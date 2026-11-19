import { expectDirectoryRefusal } from "./directory-test-support.ts"
import { beginAccessSideEffectChecks,finishAccessSideEffectChecks } from "./access-test-support.ts"
import { afterEach,beforeEach,describe,expect,it } from "vitest"
import { WorkspaceStepUpActionSchema } from "@mehen/protocol"
import { workspacePeopleRoutes } from "../src/routes/people.ts"
import { findRoute } from "../src/router.ts"
import { responseFor } from "../src/http.ts"
import { workspaceCall } from "../src/routes/context.ts"
import { reserveInviteRouting,reconcileInviteRouting,finaliseInviteRouting } from "../src/directory/workspace-invite-routing.ts"
import { reserveWorkspaceJoin,completeWorkspaceJoin,peekWorkspaceInvite } from "../src/directory/workspace-invites.ts"
import { directoryWorkspaceClient } from "../src/directory/workspace-client.ts"
import { setPasskeyCeremonies,simpleWebAuthnCeremonies } from "../src/directory/webauthn.ts"
import { newSession,sha256Text } from "../src/directory/session.ts"
import { accountSessionStatements } from "../src/directory/account-store.ts"
import { currentAccountSession } from "../src/directory/account-session.ts"
import { assertAccountOnboarding } from "../src/directory/workspace-account-admin.ts"
import { directoryRuntimeFixture } from "./directory-runtime-fixture.ts"
import { refreshAccountRecoverySetup } from "../src/directory/account-recovery-setup.ts"
import { seedAccountRecoverySetup,directoryCeremonies,directoryRegistration } from "./directory-test-support.ts"
import { SIGNUP_DEAD_INVITE_SAY,accountSignupOptions,accountSignupVerify } from "../src/directory/workspace-accounts.ts"
import { security,principalOf } from "../src/vault/areas/workspace-runtime.ts"
import { accountAuth,inAccess,workspaceInvoke } from "./access-test-support.ts"
let f: Awaited<ReturnType<typeof directoryRuntimeFixture>>
beforeEach(async () => { beginAccessSideEffectChecks(); f = await directoryRuntimeFixture(); setPasskeyCeremonies(directoryCeremonies) })
afterEach(() => setPasskeyCeremonies(simpleWebAuthnCeremonies))
const terms = () => ({ role: "guest" as const,email: null,teams: [],shares: [{ project: "prj_a",level: "use" as const,protected: false,expiresAt: null }],expiresAt: new Date(Date.now()+600000).toISOString() })
async function call(path: string,body?: unknown) {
  const found = findRoute(workspacePeopleRoutes,body === undefined ? "GET" : "POST",path)
  if (!found || found === "method") throw new Error("Missing people route")
  try { return await found.route.handler(f.context(path,body,found.params),f.workspace) } catch (error) { return responseFor(error) }
}
async function invite() {
  const t = terms(),response = await call("/invites",{ terms: t,email: false,stepUp: await f.proof({ type: "member.invite",terms: t }) })
  expect(response.status).toBe(201)
  return await response.json() as { url: string; invite: { id: string } }
}
async function newAccount(ready: boolean) {
  const session = await newSession(),id = "acc_invitee",now = Date.now()
  await f.env.DB.batch([f.env.DB.prepare("INSERT INTO accounts(id,name,created_at,recovery_setup_at,recovery_setup_kind) VALUES (?,'Invitee',?,?,?)").bind(id,now,ready ? now : null,ready ? "codes" : null),...accountSessionStatements(f.env,session,id,now,{ kind: "web",method: "passkey",passkey: null,client: "Test",place: null })])
  if (ready) await seedAccountRecoverySetup(f.env,id,now)
  const account = await currentAccountSession(new Request(f.env.VAULT_ORIGIN,{ headers: { cookie: `__Host-mehen_session=${session.token}` } }),f.env)
  if (!account) throw new Error("Missing invitee account")
  return account
}
describe("workspace invite routing and activation",() => {
  it("requires recovery setup, preserves a preallocated join, and never activates without exact confirmation",async () => {
    const invitation = await invite(),code = invitation.url.split("#")[1] as string,account = await newAccount(false)
    await expectDirectoryRefusal(reserveWorkspaceJoin(f.env,account,code),{ error: "forbidden",message: "Set up account recovery before activation.",next: { url: `${f.env.VAULT_ORIGIN}/account`,say: "Save recovery codes or add a second passkey before activating a membership." } })
    await inAccess(f.tenant,ctx => expect(ctx.sql.exec("SELECT id FROM members WHERE account='acc_invitee'").toArray()).toEqual([]))
    await seedAccountRecoverySetup(f.env,account.account)
    const reservation = await reserveWorkspaceJoin(f.env,account,code)
    expect(await f.env.DB.prepare("SELECT state FROM memberships WHERE id=?").bind(reservation.member).first()).toEqual({ state: "joining" })
    expect(await completeWorkspaceJoin(f.env,reservation)).toEqual({ member: reservation.member,state: "pending_confirmation" })
    await expectDirectoryRefusal(assertAccountOnboarding(f.env,account,f.tenant),{ error: "forbidden",message: "An owner or admin must confirm this membership before you connect an agent." })
    await inAccess(f.tenant,ctx => expect(ctx.sql.exec("SELECT status FROM members WHERE id=?",reservation.member).toArray()).toEqual([{ status: "unconfirmed" }]))
    const prepared = await workspaceCall(f.context(""),f.workspace,"access.members.action",{ member: reservation.member,change: "confirm" }) as { action: unknown },action = WorkspaceStepUpActionSchema.parse(prepared.action)
    const confirmed = await call(`/members/${reservation.member}/confirm`,{ stepUp: await f.proof(action) })
    expect(confirmed.status).toBe(200)
    expect(await confirmed.json()).toMatchObject({ member: reservation.member,status: "active" })
    expect(await assertAccountOnboarding(f.env,account,f.tenant)).toEqual({ next: `${f.env.VAULT_ORIGIN}/w/work/connect-agent` })
  })
  it("guest teams/manage and unbound non-guest terms refuse without a routing row or member",async () => {
    for (const t of [{ ...terms(),teams: ["tm_engineering"] },{ ...terms(),shares: [{ ...terms().shares[0],level: "manage" }] },{ ...terms(),role: "owner" }]) expect((await call("/invites",{ terms: t,email: false })).status).toBe(400)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM invite_codes").first()).toEqual({ n: 0 })
    await inAccess(f.tenant,ctx => expect(ctx.sql.exec("SELECT id FROM invites").toArray()).toEqual([]))
  })
  it("revocation kills an orphaned routing row and redemption has the exact not_found",async () => {
    const invitation = await invite(),code = invitation.url.split("#")[1] as string,account = await newAccount(true)
    await workspaceCall(f.context(""),f.workspace,"access.invites.revoke",{ invite: invitation.invite.id })
    await expectDirectoryRefusal(reserveWorkspaceJoin(f.env,account,code),{ error: "not_found",message: "No such invite." })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM memberships WHERE account=?").bind(account.account).first()).toEqual({ n: 0 })
  })
  it.each(["removed","demoted","suspended"] as const)("signup without a proof refuses an open link whose inviter was %s, though its routing row stays",async (change) => {
    const t = terms(),r = await reserveInviteRouting(f.env,f.workspace.workspace,f.workspace.account,t)
    expect(await workspaceInvoke(f.tenant,"access.invites.create",{ invite: r.id,codeHash: r.codeHash,terms: t,reservation: { expiresAt: new Date(r.expiresAt).toISOString() } },accountAuth("admin",{ type: "member.invite",terms: t }))).toMatchObject({ ok: true })
    await finaliseInviteRouting(f.env,r,t.expiresAt)
    const input = { invite: r.code,name: "Stale guest" },{ options } = await accountSignupOptions(f.env,input)
    const route = change === "removed" ? "remove" : change === "demoted" ? "role" : "suspend",role = change === "demoted" ? { role: "member" as const } : {}
    const prepared = await workspaceCall(f.context(""),f.workspace,"access.members.action",{ member: "mem_admin",change: route,...role }) as { action: unknown }
    expect((await call(`/members/mem_admin/${route}`,{ ...role,stepUp: await f.proof(WorkspaceStepUpActionSchema.parse(prepared.action)) })).status).toBe(200)
    await inAccess(f.tenant,ctx => expect(ctx.sql.exec("SELECT status FROM invites WHERE id=?",r.id).toArray()).toEqual([{ status: change === "removed" ? "revoked" : "open" }]))
    expect(await f.env.DB.prepare("SELECT state,used_by_account FROM invite_codes WHERE code_hash=?").bind(r.codeHash).first()).toEqual({ state: "active",used_by_account: null })
    // A revoked invitation is dead; one whose inviter may no longer invite needs reissuing.
    const before = (await f.env.DB.prepare("SELECT id FROM accounts ORDER BY id").all()).results
    const refused = change === "removed" ? { error: "not_found" as const,message: "No such invite.",next: { say: SIGNUP_DEAD_INVITE_SAY } } : { error: "forbidden" as const,message: "This invitation needs an eligible owner or admin to reissue it." }
    await expectDirectoryRefusal(accountSignupOptions(f.env,input),refused)
    await expectDirectoryRefusal(accountSignupVerify(f.env,{ ...input,response: directoryRegistration("stale-guest",(options as { challenge: string }).challenge) }),refused)
    expect((await f.env.DB.prepare("SELECT id FROM accounts ORDER BY id").all()).results).toEqual(before)
    expect(await f.env.DB.prepare("SELECT used_by_account FROM invite_codes WHERE code_hash=?").bind(r.codeHash).first()).toEqual({ used_by_account: null })
  })
  it("reconciles both crash boundaries without ever redeeming pending routing rows",async () => {
    const t = terms(),r = await reserveInviteRouting(f.env,f.workspace.workspace,f.workspace.account,t)
    const account = await newAccount(true)
    await expectDirectoryRefusal(reserveWorkspaceJoin(f.env,account,r.code),{ error: "not_found",message: "No such invite." })
    await reconcileInviteRouting(f.env,directoryWorkspaceClient(f.env),r.expiresAt+1)
    expect(await f.env.DB.prepare("SELECT code_hash FROM invite_codes WHERE code_hash=?").bind(r.codeHash).first()).toBeNull()
    const next = await reserveInviteRouting(f.env,f.workspace.workspace,f.workspace.account,t)
    await workspaceCall(f.context(""),f.workspace,"access.invites.create",{ invite: next.id,codeHash: next.codeHash,terms: t,reservation: { expiresAt: new Date(next.expiresAt).toISOString() } },{ action: { type: "member.invite",terms: t },factor: "pk_test" })
    await reconcileInviteRouting(f.env,directoryWorkspaceClient(f.env),next.expiresAt+1)
    expect(await f.env.DB.prepare("SELECT state,expires_at FROM invite_codes WHERE code_hash=?").bind(next.codeHash).first()).toEqual({ state: "active",expires_at: Date.parse(t.expiresAt) })
    expect(await sha256Text(next.code)).toBe(next.codeHash)
  })
  it("an expired DO reservation refuses without creating an invite",async () => {
    const t = terms()
    await expectDirectoryRefusal(workspaceCall(f.context(""),f.workspace,"access.invites.create",{ invite: "inv_expired",codeHash: "hash",terms: t,reservation: { expiresAt: new Date(Date.now()-1).toISOString() } },{ action: { type: "member.invite",terms: t },factor: "pk_test" }),{ error: "conflict",message: "This invitation reservation expired." })
    await inAccess(f.tenant,ctx => expect(ctx.sql.exec("SELECT id FROM invites WHERE id='inv_expired'").toArray()).toEqual([]))
  })
})

afterEach(() => finishAccessSideEffectChecks())

describe("invite peek",() => {
  it("names the workspace, role, binding and expiry and never the email; refuses as join does",async () => {
    const t = { ...terms(),role: "member" as const,email: "invited@example.test",shares: [] },response = await call("/invites",{ terms: t,email: false,stepUp: await f.proof({ type: "member.invite",terms: t }) })
    expect(response.status).toBe(201)
    const code = (await response.json() as { url: string }).url.split("#")[1]!,peek = await peekWorkspaceInvite(f.env,code,null)
    const ref = await f.env.DB.prepare("SELECT name,slug FROM workspaces WHERE id=?").bind(f.tenant).first<{ name: string; slug: string }>()
    expect(peek).toEqual({ workspace: ref,role: "member",bound: true,emailCode: "offered",expiresAt: t.expiresAt })
    expect(JSON.stringify(peek)).not.toMatch(/invited|example\.test|\*\*\*/)
    const guest = await invite(),guestCode = guest.url.split("#")[1]!
    expect(await peekWorkspaceInvite(f.env,guestCode,null)).toMatchObject({ role: "guest",bound: false })
    const unknown = { error: "not_found" as const,message: "No such invite." }
    await expectDirectoryRefusal(peekWorkspaceInvite(f.env,"no-such-invite-code",null),unknown)
    await f.env.DB.prepare("UPDATE invite_codes SET expires_at=? WHERE code_hash=?").bind(Date.now()-1,await sha256Text(code)).run()
    await expectDirectoryRefusal(peekWorkspaceInvite(f.env,code,null),unknown)
    // A used code answers only the account that used it.
    const account = await newAccount(true)
    await f.env.DB.prepare("UPDATE invite_codes SET used_at=?,used_by_account=? WHERE code_hash=?").bind(Date.now(),account.account,await sha256Text(guestCode)).run()
    await expectDirectoryRefusal(peekWorkspaceInvite(f.env,guestCode,null),unknown)
    expect(await peekWorkspaceInvite(f.env,guestCode,account)).toMatchObject({ role: "guest" })
    const revoked = await invite(),revokedCode = revoked.url.split("#")[1]!
    expect((await call(`/invites/${revoked.invite.id}/revoke`,{})).status).toBe(200)
    await expectDirectoryRefusal(peekWorkspaceInvite(f.env,revokedCode,null),unknown)
  })
})

describe("bound-email DIRECTORY refusals",() => {
  for (const role of ["member","guest"] as const) it(`${role} email proof refuses before signup or redemption side effects`,async () => {
    const t = { ...terms(),role,email: "invited@example.test" },response = await call("/invites",{ terms: t,email: false,stepUp: await f.proof({ type: "member.invite",terms: t }) })
    expect(response.status).toBe(201)
    const invitation = await response.json() as { url: string },code = invitation.url.split("#")[1]!,account = await newAccount(true),input = { invite: code,name: "Forwarded" }
    const before = (await f.env.DB.prepare("SELECT id FROM accounts ORDER BY id").all()).results
    for (const operation of [() => accountSignupOptions(f.env,input),() => accountSignupVerify(f.env,{ ...input,response: {} }),() => reserveWorkspaceJoin(f.env,account,code)]) await expectDirectoryRefusal(operation(),{ error: "identity_required",message: "Prove the invited email before joining.",next: { url: "/signup",say: "Verify the invited email with Google, then continue." } })
    if (role === "guest") {
      await f.env.DB.prepare("UPDATE invite_codes SET email=NULL WHERE code_hash=?").bind(await sha256Text(code)).run()
      await expectDirectoryRefusal(reserveWorkspaceJoin(f.env,account,code),{ error: "identity_required",message: "Prove the invited email before joining.",next: { url: "/signup",say: "Verify the invited email with Google, then continue." } })
    }
    expect((await f.env.DB.prepare("SELECT id FROM accounts ORDER BY id").all()).results).toEqual(before)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM challenges").first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT used_by_account FROM invite_codes WHERE code_hash=?").bind(await sha256Text(code)).first()).toEqual({ used_by_account: null })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM memberships WHERE account=?").bind(account.account).first()).toEqual({ n: 0 })
    await inAccess(f.tenant,ctx => expect(ctx.sql.exec("SELECT id FROM members WHERE account=?",account.account).toArray()).toEqual([]))
  })
})
it("join installs the account's current epoch before redeeming",async () => {
  const invitation = await invite(),original = await newAccount(true)
  await f.env.DB.prepare("UPDATE accounts SET security_epoch=3 WHERE id=?").bind(original.account).run()
  const account = { ...original,securityEpoch: 3 },reservation = await reserveWorkspaceJoin(f.env,account,invitation.url.split("#")[1]!)
  await completeWorkspaceJoin(f.env,reservation)
  await inAccess(f.tenant,async ctx => {
    expect(security(ctx,account.account)?.installedEpoch).toBe(3)
    await expectDirectoryRefusal(Promise.resolve().then(() => principalOf(ctx,{ kind: "account",account: account.account,session: account.session,securityEpoch: 2,restrictedUntil: null,sessionCheck: null })),{ error: "unauthenticated",message: "This session is no longer authorised." })
  })
})

it("confirmation rechecks current recovery readiness after asynchronous passkey verification",async () => {
  const invitation = await invite(),account = await newAccount(true),reservation = await reserveWorkspaceJoin(f.env,account,invitation.url.split("#")[1]!)
  await completeWorkspaceJoin(f.env,reservation)
  const prepared = await workspaceCall(f.context(""),f.workspace,"access.members.action",{ member: reservation.member,change: "confirm" }) as { action: unknown },action = WorkspaceStepUpActionSchema.parse(prepared.action),proof = await f.proof(action)
  setPasskeyCeremonies({ ...directoryCeremonies,async verifyAuthentication(response,expected,key) {
    await f.env.DB.batch([f.env.DB.prepare("UPDATE recovery_codes SET status='used',used_at=? WHERE account=?").bind(Date.now(),account.account),refreshAccountRecoverySetup(f.env,account.account,Date.now())])
    return directoryCeremonies.verifyAuthentication(response,expected,key)
  } })
  const response = await call(`/members/${reservation.member}/confirm`,{ stepUp: proof })
  expect(response.status).toBe(403)
  expect(await response.json()).toEqual({ error: "forbidden",message: "Set up account recovery before activation.",next: { url: `${f.env.VAULT_ORIGIN}/account`,say: "Save recovery codes or add a second passkey before activating a membership." } })
  await inAccess(f.tenant,ctx => expect(ctx.sql.exec("SELECT status FROM members WHERE id=?",reservation.member).toArray()).toEqual([{ status: "unconfirmed" }]))
})
