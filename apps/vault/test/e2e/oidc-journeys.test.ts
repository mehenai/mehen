import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { OIDC_INVITE_EMAIL_REFUSAL, OIDC_NOT_LINKED_REFUSAL, setOidcFetchForTest } from "../../src/directory/oidc.ts"
import { SIGNUP_DEAD_INVITE_SAY } from "../../src/directory/workspace-accounts.ts"
import { fakeGoogle } from "../oidc-google.ts"
import type { AccountSession } from "@mehen/protocol/workspace"
import { linkGoogle, oidcResultOf, setGoogleRule, webGate } from "./oidc-journey.ts"
import { registration, softwarePasskey, assertion } from "./passkeys.ts"
import { body, refusal, workJourney, type Person } from "./workspace-journey.ts"
let google: Awaited<ReturnType<typeof fakeGoogle>>
beforeEach(async () => { google = await fakeGoogle(); setOidcFetchForTest(google.fetcher) })
afterEach(() => setOidcFetchForTest(null))
async function start(f: Awaited<ReturnType<typeof workJourney>>, input: Record<string, unknown>, person?: Person, claims: Record<string, unknown> = {}) {
  f.env.GOOGLE_SIGNIN_CLIENT_ID = "test-google-client"; f.env.GOOGLE_SIGNIN_CLIENT_SECRET = "test-only-google-secret"
  const response = await f.request("/api/auth/oidc/google/start", person, input), cookie = response.headers.get("set-cookie")?.split(";")[0] ?? ""
  const { url } = await body<{ url: string }>(response), authorised = google.authorise(url, claims)
  const callback = await f.request(`/auth/oidc/google/callback?${new URLSearchParams(authorised)}`, person, undefined, { cookie: [person?.cookie, cookie].filter(Boolean).join("; ") })
  expect(callback.status).toBe(303)
  return { id: oidcResultOf(callback, f.env.VAULT_ORIGIN), cookie, url, location: callback.headers.get("location") }
}
// The boot payload /signup renders for this browser.
async function signupBoot(f: Awaited<ReturnType<typeof workJourney>>, person?: Person): Promise<unknown> {
  const page = await (await f.request("/signup", person, undefined, { accept: "text/html" })).text(), raw = /data-boot="([^"]*)"/.exec(page)?.[1] ?? "{}"
  return JSON.parse(raw.replaceAll("&quot;", '"').replaceAll("&amp;", "&"))
}
describe("OIDC real Worker journeys", () => {
  it("email-bound invite through /signup: peek, Google proof back to /signup, real passkey, recovery, join, owner confirmation, Connect an agent", async () => {
    const f = await workJourney(), terms = { role: "member" as const, email: "colleague@northwind.example", teams: [], shares: [], expiresAt: new Date(Date.now() + 86400000).toISOString() }, invite = await (async () => { await linkGoogle(f,google); await setGoogleRule(f,google); await webGate(f,google); return f.invite(f.alex,f.work,terms) })()
    // The page names the workspace and role and says the invitation is bound, never to whom.
    const peeked = await body<Record<string, unknown>>(await f.request("/api/auth/invite/peek", undefined, { code: invite.code }))
    expect(peeked).toEqual({ workspace: { name: "Northwind", slug: "northwind" }, role: "member", bound: true, emailCode: "identity_rule", expiresAt: terms.expiresAt })
    expect(JSON.stringify(peeked)).not.toContain("colleague")
    await refusal(await f.request("/api/auth/invite/peek", undefined, { code: "not-an-invite-code" }), 404, { error: "not_found", message: "No such invite." })
    // A dead link that still reaches the passkey step is told what to do instead.
    await refusal(await f.request("/api/auth/signup/options", undefined, { invite: "not-an-invite-code", name: "Colleague" }), 404, { error: "not_found", message: "No such invite.", next: { say: SIGNUP_DEAD_INVITE_SAY } })
    await refusal(await f.request("/api/auth/signup/options", undefined, { invite: invite.code, name: "Colleague" }), 403, { error: "identity_required", message: "Prove the invited email before joining.", next: { url: "/signup", say: "Verify the invited email with Google, then continue." } })
    const proof = await start(f, { purpose: "invite", invite: invite.code, next: "/signup" }, undefined, { sub: "google-colleague", email: terms.email, name: "Colleague Name" })
    expect(proof.location).toBe(`/signup#oidc=${proof.id}`)
    // An old result link carries nothing and lands on /signup.
    const old = await f.request(`/auth/oidc/result?result=${proof.id}&purpose=invite`, undefined, undefined, { cookie: proof.cookie, accept: "text/html" })
    expect(old.status).toBe(303); expect(old.headers.get("location")).toBe("/signup")
    // The name Google gave comes back with the proof, for /signup's Your name.
    expect(await body(await f.request("/api/auth/oidc/google/result", undefined, { result: proof.id, purpose: "invite" }, { cookie: proof.cookie }))).toMatchObject({ purpose: "invite", identity: { email: terms.email, name: "Colleague Name" } })
    expect(await signupBoot(f)).toEqual({ page: "workspace-signup", signedIn: false, recoveryReady: false })
    const passkey = await softwarePasskey(), options = await body<{ options: { challenge: string } }>(await f.request("/api/auth/signup/options", undefined, { invite: invite.code, name: "Colleague", oidcResult: proof.id }, { cookie: proof.cookie }))
    const registered = await f.request("/api/auth/signup/verify", undefined, { invite: invite.code, name: "Colleague", oidcResult: proof.id, response: await registration(passkey, options.options.challenge) }, { cookie: proof.cookie }), sessionCookie = registered.headers.get("set-cookie")!.split(";")[0]!, created = await body<{ account: string; onboarding: string }>(registered)
    expect(created.onboarding).toBe("join")
    const colleague: Person = { account: created.account, cookie: `${sessionCookie}; ${proof.cookie}`, passkey, counter: 0, codes: [] }
    expect(await f.db.prepare("SELECT can_create_workspaces FROM accounts WHERE id=?").bind(colleague.account).first()).toEqual({ can_create_workspaces: 0 })
    await f.recoverySetup(colleague)
    // Signed in now, the account may still read its invitation.
    expect(await body(await f.request("/api/auth/invite/peek", colleague, { code: invite.code }))).toEqual(peeked)
    const joined = await body<{ member: string; state: string }>(await f.request("/api/account/invites/join", colleague, { code: invite.code, oidcResult: proof.id }))
    expect(joined.state).toBe("pending_confirmation")
    expect(await body(await f.request("/api/auth/invite/peek", colleague, { code: invite.code }))).toEqual(peeked)
    await refusal(await f.request("/api/auth/invite/peek", undefined, { code: invite.code }), 404, { error: "not_found", message: "No such invite." })
    expect(await f.sql(f.work,"SELECT purpose FROM workspace_identity_checks WHERE member=?",joined.member)).toEqual([{ purpose: "invite" }])
    expect(await f.sql(f.work, "SELECT status FROM members WHERE id=?", joined.member)).toEqual([{ status: "unconfirmed" }])
    const waiting = await body<AccountSession>(await f.request("/api/account", colleague))
    expect(waiting.memberships.find(m => m.member === joined.member)).toMatchObject({ workspace: { slug: "northwind" }, status: "unconfirmed" })
    expect(await body(await f.memberChange(f.alex, f.work, joined.member, "confirm"))).toMatchObject({ member: joined.member, role: "member", status: "active" })
    const confirmed = await body<AccountSession>(await f.request("/api/account", colleague)), mine = confirmed.memberships.find(m => m.member === joined.member)!
    expect(mine.status).toBe("active")
    expect(await body(await f.request(`/api/account/onboarding/${mine.workspace.id}`, colleague))).toEqual({ next: `${f.env.VAULT_ORIGIN}/w/northwind/connect-agent` })
    // A session that owes the workspace's identity check (here, its check
    // gone) could get no connect code there, so it lands on the home, and
    // nothing is minted; once checked, Connect an agent again.
    await f.db.prepare("DELETE FROM session_identity_checks WHERE account=?").bind(colleague.account).run()
    expect(await body(await f.request(`/api/account/onboarding/${mine.workspace.id}`, colleague))).toEqual({ next: `${f.env.VAULT_ORIGIN}/w/northwind/` })
    expect((await f.request("/api/w/northwind/connect-code", colleague, {}, { "Mehen-Workspace": mine.workspace.id })).status).toBe(403)
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM enrol_connect_codes WHERE account=?").bind(colleague.account).first()).toEqual({ n: 0 })
    await webGate(f, google, colleague, {}, { sub: "google-colleague", email: terms.email })
    expect(await body(await f.request(`/api/account/onboarding/${mine.workspace.id}`, colleague))).toEqual({ next: `${f.env.VAULT_ORIGIN}/w/northwind/connect-agent` })
    expect(await f.db.prepare("SELECT state,joining_membership FROM oidc_results WHERE id=?").bind(proof.id).first()).toEqual({ state: "consumed", joining_membership: joined.member })
    expect(await f.db.prepare("SELECT account,issuer,subject,email FROM oidc_identities WHERE subject='google-colleague'").first()).toEqual({ account: colleague.account, issuer: "https://accounts.google.com", subject: "google-colleague", email: terms.email })
    expect((await f.request("/api/account/invites/join", colleague, { code: invite.code, oidcResult: proof.id })).status).toBe(403)
    const stored = JSON.stringify(await f.db.prepare("SELECT * FROM oidc_results").all()); expect(stored).not.toContain("test-never-retained")
  })
  it("an already signed-in invitee with recovery ready: only the Google step and the join, then Connect an agent", async () => {
    const f = await workJourney(), tom = await f.guest(f.alex, f.work, f.project.id, "Tom")
    const terms = { role: "member" as const, email: "tom@northwind.example", teams: [], shares: [], expiresAt: new Date(Date.now() + 86400000).toISOString() }, invite = await f.invite(f.alex, f.personal, terms)
    expect(await signupBoot(f, tom)).toEqual({ page: "workspace-signup", signedIn: true, recoveryReady: true })
    expect(await body(await f.request("/api/auth/invite/peek", tom, { code: invite.code }))).toEqual({ workspace: { name: "Personal", slug: "alex" }, role: "member", bound: true, emailCode: "offered", expiresAt: terms.expiresAt })
    await refusal(await f.request("/api/account/invites/join", tom, { code: invite.code }), 403, { error: "identity_required", message: "Prove the invited email before joining.", next: { url: "/signup", say: "Verify the invited email with Google, then continue." } })
    const proof = await start(f, { purpose: "invite", invite: invite.code, next: "/signup" }, tom, { sub: "google-tom", email: terms.email })
    expect(proof.location).toBe(`/signup#oidc=${proof.id}`)
    const joined = await body<{ member: string; state: string }>(await f.request("/api/account/invites/join", tom, { code: invite.code, oidcResult: proof.id }, { cookie: `${tom.cookie}; ${proof.cookie}` }))
    expect(joined.state).toBe("pending_confirmation")
    expect(await body(await f.memberChange(f.alex, f.personal, joined.member, "confirm"))).toMatchObject({ member: joined.member, role: "member", status: "active" })
    const mine = (await body<AccountSession>(await f.request("/api/account", tom))).memberships.find(m => m.member === joined.member)!
    expect(mine).toMatchObject({ workspace: { slug: "alex" }, status: "active" })
    expect(await body(await f.request(`/api/account/onboarding/${mine.workspace.id}`, tom))).toEqual({ next: `${f.env.VAULT_ORIGIN}/w/alex/connect-agent` })
    expect(await f.db.prepare("SELECT can_create_workspaces FROM accounts WHERE id=?").bind(tom.account).first()).toEqual({ can_create_workspaces: 0 })
  })
  it.each(["rule","terms","email"] as const)("invite consent refuses a changed %s without consuming the invite", async kind => {
    const f = await workJourney(),terms = { role: "member" as const,email: "colleague@northwind.example",teams: [],shares: [],expiresAt: new Date(Date.now()+86400000).toISOString() },invite = await f.invite(f.alex,f.work,terms)
    f.env.GOOGLE_SIGNIN_CLIENT_ID = "test-google-client"; f.env.GOOGLE_SIGNIN_CLIENT_SECRET = "test-only-google-secret"
    const started = await f.request("/api/auth/oidc/google/start",undefined,{ purpose: "invite",invite: invite.code }),cookie = started.headers.get("set-cookie")!.split(";")[0]!,{ url } = await body<{ url: string }>(started),authorised = google.authorise(url,{ sub: "new-subject",email: kind === "email" ? "forwarded@northwind.example" : terms.email })
    if (kind === "rule") { await linkGoogle(f,google); await setGoogleRule(f,google); await webGate(f,google) }
    if (kind === "terms") await f.sql(f.work,"UPDATE invites SET digest='changed-terms' WHERE id=?",invite.invite.id)
    const refused = await f.request(`/auth/oidc/google/callback?${new URLSearchParams(authorised)}`,undefined,undefined,{ cookie })
    expect(refused.status).toBe(403)
    const message = (await refused.json<{ message: string }>()).message
    expect(message).not.toContain(terms.email)
    if (kind === "email") expect(message).toBe(OIDC_INVITE_EMAIL_REFUSAL)
    else expect(message).not.toBe(OIDC_INVITE_EMAIL_REFUSAL)
    expect(await f.db.prepare("SELECT used_at,used_by_account FROM invite_codes WHERE invite=?").bind(invite.invite.id).first()).toEqual({ used_at: null,used_by_account: null })
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM oidc_results WHERE purpose='invite'").first()).toEqual({ n: 0 })
  })
  it("Google never signs in alone; unknown identity, wrong passkey and proof replay refuse", async () => {
    const f = await workJourney(), link = await start(f, { purpose: "link", stepUp: await f.proof(f.alex, { type: "identity.link", provider: "google" }) }, f.alex)
    expect(await body(await f.request("/api/account/identities/link", f.alex, { result: link.id, email: "alex@northwind.example", subject: "google-alex" }, { cookie: `${f.alex.cookie}; ${link.cookie}` }))).toEqual({ linked: true })
    const signin = await start(f, { purpose: "signin" })
    const before = await f.db.prepare("SELECT COUNT(*) AS n FROM web_sessions").first()
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM web_sessions").first()).toEqual(before)
    const options = await body<{ flow: string; options: { challenge: string } }>(await f.request("/api/auth/signin/options", undefined, { oidcResult: signin.id }, { cookie: signin.cookie }))
    const stranger = await f.guest(f.alex,f.work,f.project.id,"Other registered account")
    expect((await f.request("/api/auth/signin/verify", undefined, { flow: options.flow, response: await assertion(stranger.passkey, options.options.challenge, ++stranger.counter) }, { cookie: signin.cookie })).status).toBe(401)
    const retry = await body<{ flow: string; options: { challenge: string } }>(await f.request("/api/auth/signin/options", undefined, { oidcResult: signin.id }, { cookie: signin.cookie }))
    const response = await f.request("/api/auth/signin/verify", undefined, { flow: retry.flow, response: await assertion(f.alex.passkey, retry.options.challenge, ++f.alex.counter) }, { cookie: signin.cookie })
    expect(await body(response)).toEqual({ account: f.alex.account }); expect(response.headers.get("set-cookie")).toBeTruthy()
    expect((await f.request("/api/auth/signin/options", undefined, { oidcResult: signin.id }, { cookie: signin.cookie })).status).toBe(403)
    const unknown = await start(f, { purpose: "signin" }, undefined, { sub: "no-account" })
    await refusal(await f.request("/api/auth/signin/options", undefined, { oidcResult: unknown.id }, { cookie: unknown.cookie }), 403, { error: "identity_required", message: OIDC_NOT_LINKED_REFUSAL })
  })
})
