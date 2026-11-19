import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { setOidcFetchForTest } from "../../src/directory/oidc.ts"
import { fakeGoogle } from "../oidc-google.ts"
import { body, workJourney, type Person } from "./workspace-journey.ts"
import { registration, softwarePasskey } from "./passkeys.ts"
import { googleFlow, linkGoogle, oidcResultOf } from "./oidc-journey.ts"
import type { WorkspaceInvocation, Invocation } from "../../src/vault/core.ts"
let google: Awaited<ReturnType<typeof fakeGoogle>>
beforeEach(async () => { google = await fakeGoogle(); setOidcFetchForTest(google.fetcher) })
afterEach(() => setOidcFetchForTest(null))
async function pendingPerson() {
  const f = await workJourney(),invite = await f.invite(f.alex,f.work,{ role: "member",email: "new@northwind.example",teams: [],shares: [],expiresAt: new Date(Date.now()+86400000).toISOString() })
  f.env.GOOGLE_SIGNIN_CLIENT_ID = "test-google-client"; f.env.GOOGLE_SIGNIN_CLIENT_SECRET = "test-only-google-secret"
  const started = await f.request("/api/auth/oidc/google/start",undefined,{ purpose: "invite",invite: invite.code }),flowCookie = started.headers.get("set-cookie")!.split(";")[0]!,{ url } = await body<{ url: string }>(started),callback = await f.request(`/auth/oidc/google/callback?${new URLSearchParams(google.authorise(url,{ sub: "new-subject",email: "new@northwind.example" }))}`,undefined,undefined,{ cookie: flowCookie })
  expect(callback.status).toBe(303)
  expect(callback.headers.get("location")).toMatch(/^\/signup#oidc=oidr_/)
  const result = oidcResultOf(callback,f.env.VAULT_ORIGIN),passkey = await softwarePasskey(),name = "New person",startedSignup = await body<{ options: { challenge: string } }>(await f.request("/api/auth/signup/options",undefined,{ invite: invite.code,name,oidcResult: result },{ cookie: flowCookie })),registered = await f.request("/api/auth/signup/verify",undefined,{ invite: invite.code,name,oidcResult: result,response: await registration(passkey,startedSignup.options.challenge) },{ cookie: flowCookie }),cookie = registered.headers.get("set-cookie")!.split(";")[0]!,created = await body<{ account: string }>(registered)
  const person: Person = { account: created.account,cookie: `${cookie}; ${flowCookie}`,passkey,counter: 0,codes: [] }
  await f.recoverySetup(person)
  return { ...f,invite,result,person }
}
function intercept(f: Awaited<ReturnType<typeof pendingPerson>>,before: (input: WorkspaceInvocation | Invocation) => Promise<void>) {
  const namespace = f.env.TENANT_VAULT
  f.env.TENANT_VAULT = new Proxy(namespace,{ get(target,key) { if (key === "getByName") return (name: string) => { const stub = target.getByName(name); return new Proxy(stub,{ get(object,prop) { if (prop === "invoke") return async (input: WorkspaceInvocation | Invocation) => { await before(input); return object.invoke(input) }; const value = Reflect.get(object,prop) as unknown; return typeof value === "function" ? value.bind(object) : value } }) }; const value = Reflect.get(target,key) as unknown; return typeof value === "function" ? value.bind(target) : value } })
  return () => { f.env.TENANT_VAULT = namespace }
}
describe("OIDC exact join reservation recovery", () => {
  it.each([false,true])("a definitive source refusal deletes only a reservation-created identity (pre-existing=%s)",async existing => {
    const f = await pendingPerson()
    if (existing) await linkGoogle(f,google,f.person,{ sub: "new-subject",email: "new@northwind.example" })
    let once = false
    const restore = intercept(f,async input => { if (input.op === "access.invites.redeem" && !once) { once = true; expect((await f.request(`/api/w/${f.work.slug}/invites/${f.invite.invite.id}/revoke`,f.alex,{})).status).toBe(200) } })
    expect((await f.request("/api/account/invites/join",f.person,{ code: f.invite.code,oidcResult: f.result })).status).toBe(404)
    restore()
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM memberships WHERE account=?").bind(f.person.account).first()).toEqual({ n: 0 })
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM oidc_identities WHERE account=?").bind(f.person.account).first()).toEqual({ n: existing ? 1 : 0 })
    expect(await f.db.prepare("SELECT state FROM oidc_results WHERE id=?").bind(f.result).first()).toEqual({ state: "consumed" })
  })
  it("lost reply retains the exact proof/link; expiry aborts the source and permits a fresh proof for the same invitation",async () => {
    const f = await pendingPerson(); f.faults.lostReply = "access.invites.redeem"
    expect((await f.request("/api/account/invites/join",f.person,{ code: f.invite.code,oidcResult: f.result })).status).toBe(500)
    expect(await f.db.prepare("SELECT state FROM memberships WHERE account=?").bind(f.person.account).first()).toEqual({ state: "joining" })
    expect(await f.db.prepare("SELECT state FROM oidc_results WHERE id=?").bind(f.result).first()).toEqual({ state: "joining" })
    await f.db.prepare("UPDATE oidc_results SET expires_at=? WHERE id=?").bind(Date.now()-1,f.result).run()
    await f.cron()
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM memberships WHERE account=?").bind(f.person.account).first()).toEqual({ n: 0 })
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM oidc_identities WHERE account=?").bind(f.person.account).first()).toEqual({ n: 0 })
    expect(await f.sql(f.work,"SELECT status FROM invites WHERE id=?",f.invite.invite.id)).toEqual([{ status: "open" }])
    const fresh = await googleFlow(f,google,f.person,{ purpose: "invite",invite: f.invite.code },{ sub: "new-subject",email: "new@northwind.example" })
    expect((await f.request("/api/account/invites/join",f.person,{ code: f.invite.code,oidcResult: fresh.id },{ cookie: `${f.person.cookie.split(";")[0]}; ${fresh.cookie}` })).status).toBe(200)
  })
  it("refreshing a reserved proof transfers only its exact identity ownership and retires the older proof",async () => {
    const f = await pendingPerson(); f.faults.lostReply = "access.invites.redeem"
    expect((await f.request("/api/account/invites/join",f.person,{ code: f.invite.code,oidcResult: f.result })).status).toBe(500)
    const old = await f.db.prepare("SELECT joining_identity FROM oidc_results WHERE id=?").bind(f.result).first<{ joining_identity: string }>()
    const fresh = await googleFlow(f,google,f.person,{ purpose: "invite",invite: f.invite.code },{ sub: "new-subject",email: "new@northwind.example" })
    f.faults.lostReply = "access.identity.install"
    expect((await f.request("/api/account/invites/join",f.person,{ code: f.invite.code,oidcResult: fresh.id },{ cookie: `${f.person.cookie.split(";")[0]}; ${fresh.cookie}` })).status).toBe(500)
    expect(await f.db.prepare("SELECT state FROM oidc_results WHERE id=?").bind(f.result).first()).toEqual({ state: "consumed" })
    expect(await f.db.prepare("SELECT state,joining_identity FROM oidc_results WHERE id=?").bind(fresh.id).first()).toEqual({ state: "joining",joining_identity: old!.joining_identity })
    await f.db.prepare("UPDATE oidc_results SET expires_at=? WHERE id=?").bind(Date.now()-1,fresh.id).run(); await f.cron()
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM oidc_identities WHERE account=?").bind(f.person.account).first()).toEqual({ n: 0 })
  })
  it("an already owner-confirmed source rolls the stale D1 join mirror forward instead of deleting it",async () => {
    const f = await pendingPerson(); f.faults.lostReply = "access.identity.install"
    expect((await f.request("/api/account/invites/join",f.person,{ code: f.invite.code,oidcResult: f.result })).status).toBe(500)
    const membership = await f.db.prepare("SELECT id FROM memberships WHERE account=?").bind(f.person.account).first<{ id: string }>()
    // Make the persisted reservation visible to the real recovery-ready owner
    // confirmation, then inject a stale directory mirror. DO authority is real.
    await f.db.prepare("UPDATE memberships SET state='member' WHERE id=?").bind(membership!.id).run()
    expect((await f.memberChange(f.alex,f.work,membership!.id,"confirm")).status).toBe(200)
    await f.db.prepare("UPDATE memberships SET state='joining' WHERE id=?").bind(membership!.id).run()
    await f.db.prepare("UPDATE oidc_results SET expires_at=? WHERE id=?").bind(Date.now()-1,f.result).run()
    await f.cron()
    expect(await f.db.prepare("SELECT state FROM memberships WHERE id=?").bind(membership!.id).first()).toEqual({ state: "member" })
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM oidc_identities WHERE account=?").bind(f.person.account).first()).toEqual({ n: 1 })
    expect(await f.sql(f.work,"SELECT status FROM members WHERE id=?",membership!.id)).toEqual([{ status: "active" }])
  })
  it("unavailable source expiry keeps the reservation, identity and proof for a later retry",async () => {
    const f = await pendingPerson(); f.faults.lostReply = "access.invites.redeem"
    expect((await f.request("/api/account/invites/join",f.person,{ code: f.invite.code,oidcResult: f.result })).status).toBe(500)
    await f.db.prepare("UPDATE oidc_results SET expires_at=? WHERE id=?").bind(Date.now()-1,f.result).run()
    const restore = intercept(f,async input => { if (input.op === "access.invites.abort") throw new Error("Injected source outage") })
    await f.cron(); restore()
    expect(await f.db.prepare("SELECT state FROM memberships WHERE account=?").bind(f.person.account).first()).toEqual({ state: "joining" })
    expect(await f.db.prepare("SELECT state FROM oidc_results WHERE id=?").bind(f.result).first()).toEqual({ state: "joining" })
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM oidc_identities WHERE account=?").bind(f.person.account).first()).toEqual({ n: 1 })
    await f.cron()
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM memberships WHERE account=?").bind(f.person.account).first()).toEqual({ n: 0 })
  })
})
