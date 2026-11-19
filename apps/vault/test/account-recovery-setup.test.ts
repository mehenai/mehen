import { afterEach,beforeEach,describe,expect,it } from "vitest"
import { createExecutionContext } from "cloudflare:test"
import { accountRecoverySetupRequiredNow,refreshAccountRecoverySetup } from "../src/directory/account-recovery-setup.ts"
import { accountSessionStatements } from "../src/directory/account-store.ts"
import { endSuspendedAccountSessions } from "../src/directory/account-suspension.ts"
import { currentAccountSession } from "../src/directory/account-session.ts"
import { accountSessionView,assertAccountOnboarding,removeAccountPasskey } from "../src/directory/workspace-account-admin.ts"
import { accountRecoveryStatus,accountRecoverySession,accountPasskeyOptions,accountPasskeyVerify,issueAccountRecoveryCodes,confirmAccountRecoveryCodes,startAccountRecovery,resolveAccountRecovery } from "../src/directory/workspace-recovery.ts"
import { reserveWorkspaceJoin } from "../src/directory/workspace-invites.ts"
import { reserveWorkspace } from "../src/directory/workspace-index.ts"
import { newSession,sha256Text } from "../src/directory/session.ts"
import { accountRoutes } from "../src/routes/account.ts"
import { workspaceCall } from "../src/routes/context.ts"
import { setPasskeyCeremonies,simpleWebAuthnCeremonies } from "../src/directory/webauthn.ts"
import type { WorkspaceJoinClient } from "../src/directory/workspace-client.ts"
import { beginAccessSideEffectChecks,finishAccessSideEffectChecks } from "./access-test-support.ts"
import { directoryRuntimeFixture } from "./directory-runtime-fixture.ts"
import { directoryCeremonies,directoryRegistration,expectDirectoryRefusal,successfulDirectoryClient } from "./directory-test-support.ts"
let f: Awaited<ReturnType<typeof directoryRuntimeFixture>>
beforeEach(async () => { beginAccessSideEffectChecks(); f = await directoryRuntimeFixture(); await f.env.DB.prepare("UPDATE memberships SET state='left' WHERE account=? AND workspace=?").bind(f.account,f.workspaces.personal).run(); setPasskeyCeremonies(directoryCeremonies) })
afterEach(() => { setPasskeyCeremonies(simpleWebAuthnCeremonies); finishAccessSideEffectChecks() })
async function actor() {
  const session = await newSession()
  await f.env.DB.batch(accountSessionStatements(f.env,session,f.account,Date.now(),{ kind: "web",method: "passkey",passkey: "credential",client: "Browser",place: null }))
  const request = new Request(f.env.VAULT_ORIGIN,{ headers: { cookie: `__Host-mehen_session=${session.token}` } }),account = await currentAccountSession(request,f.env)
  if (!account) throw new Error("Missing surviving actor")
  return { account,request }
}
async function codes() {
  const a = await actor(),issued = await issueAccountRecoveryCodes(f.env,a.account)
  await confirmAccountRecoveryCodes(f.env,a.account,issued.batch,issued.codes[issued.confirmPosition-1]!)
  return issued
}
async function second(credential: string) {
  const a = await actor(),{ options } = await accountPasskeyOptions(f.env,a.account,"settings",Date.now(),"pk_test")
  await accountPasskeyVerify(f.env,a.account,directoryRegistration(credential,(options as { challenge: string }).challenge),"settings")
  const key = await f.env.DB.prepare("SELECT handle FROM passkeys WHERE credential_id=?").bind(credential).first<{ handle: string }>()
  if (!key) throw new Error("Missing second factor")
  return key.handle
}
async function setupFlag() { return f.env.DB.prepare("SELECT recovery_setup_at,recovery_setup_kind FROM accounts WHERE id=?").bind(f.account).first<{ recovery_setup_at: number | null; recovery_setup_kind: string | null }>() }
async function refusedNewActivation(checkCreation = true) {
  const a = await actor(),next = { url: `${f.env.VAULT_ORIGIN}/account`,say: "Save recovery codes or add a second passkey before activating a membership." },body = { error: "forbidden" as const,message: "Set up account recovery before activation.",next }
  const workspace = { id: "tn_Future123456",slug: "future",name: "Future" },code = "future-invite-code",codeHash = await sha256Text(code)
  await f.env.DB.batch([
    f.env.DB.prepare("INSERT OR IGNORE INTO workspaces(id,slug,name,status,created_by,created_at) VALUES (?,?,'Future','active','acc_admin',?)").bind(workspace.id,workspace.slug,Date.now()),
    f.env.DB.prepare("INSERT OR IGNORE INTO invite_codes(code_hash,workspace,invite,kind,expires_at) VALUES (?,?,'inv_future','join',?)").bind(codeHash,workspace.id,Date.now()+600000),
    f.env.DB.prepare("UPDATE accounts SET can_create_workspaces=1,can_create_workspaces_by='operator:test',can_create_workspaces_op=? WHERE id=?").bind(crypto.randomUUID(),f.account),
  ])
  const client: WorkspaceJoinClient = { ...successfulDirectoryClient(),async lookupInvite() { return { id: "inv_future",workspace,inviter: { name: "Inviter" },role: "guest",teams: [],shares: [],guestExpiresAt: null,boundEmail: null,digest: "digest",status: "open",expiresAt: new Date(Date.now()+600000).toISOString() } },async redeemInvite() { throw new Error("Unready account reached redemption") } }
  await expectDirectoryRefusal(reserveWorkspaceJoin(f.env,a.account,code,client),body)
  await expectDirectoryRefusal(assertAccountOnboarding(f.env,a.account,f.tenant),body)
  if (checkCreation) await expectDirectoryRefusal(reserveWorkspace(f.env,a.account,{ name: "New",slug: "new-workspace" },{ type: "workspace.create",name: "New",slug: "new-workspace" }),body)
  expect(await f.env.DB.prepare("SELECT used_by_account FROM invite_codes WHERE code_hash=?").bind(codeHash).first()).toEqual({ used_by_account: null })
  expect(await f.env.DB.prepare("SELECT id FROM memberships WHERE account=? AND workspace=?").bind(f.account,workspace.id).first()).toBeNull()
  const session = await accountSessionView(f.env,a.account)
  expect(session.recoverySetupRequired).toBe(true)
  expect(session.memberships.find(membership => membership.workspace.id === f.tenant)).toMatchObject({ role: "owner",status: "active" })
  const members = await workspaceCall({ ...f.context(""),request: a.request },{ ...f.workspace,account: a.account },"access.members.list",{}) as { account?: string; member: string; status: string }[]
  expect(members.find(member => member.member === f.workspace.membership)?.status).toBe("active")
  const route = accountRoutes.find(route => route.path === "/api/account/security-transition")!,url = new URL(`${f.env.VAULT_ORIGIN}/api/account/security-transition`)
  expect(await (await route.handler({ request: a.request,url,env: f.env,params: {},ctx: createExecutionContext() })).json()).toMatchObject({ recoverySetupRequired: true })
}
describe("current account recovery setup",() => {
  it("removing the second factor clears readiness without suspending existing memberships, and replacement restores it",async () => {
    const handle = await second("second")
    expect(await setupFlag()).toMatchObject({ recovery_setup_kind: "passkey" })
    expect(await removeAccountPasskey(f.env,(await actor()).account,handle,"pk_test",successfulDirectoryClient())).toEqual({ pending: false })
    expect(await setupFlag()).toEqual({ recovery_setup_at: null,recovery_setup_kind: null })
    await refusedNewActivation()
    await second("replacement")
    expect(await accountRecoverySetupRequiredNow(f.env,f.account)).toBe(false)
    expect((await setupFlag())?.recovery_setup_at).not.toBeNull()
    expect((await accountSessionView(f.env,(await actor()).account)).recoverySetupRequired).toBe(false)
  })
  it("using the final code clears readiness, blocks a new join, and a fresh acknowledged sheet restores it",async () => {
    const issued = await codes()
    await f.env.DB.batch([f.env.DB.prepare("UPDATE recovery_codes SET status='used',used_at=? WHERE account=? AND batch=? AND position!=1").bind(Date.now(),f.account,issued.batch),refreshAccountRecoverySetup(f.env,f.account,Date.now())])
    const client = successfulDirectoryClient(); client.install = async () => { throw new Error("unavailable") }
    const pending = await startAccountRecovery(f.env,new Request(f.env.VAULT_ORIGIN),issued.codes[0]!,client)
    expect(pending.pending).toBe(true)
    expect((await accountRecoveryStatus(f.env,f.account)).active?.left).toBe(0)
    const { retryAccountSecurity } = await import("../src/directory/account-security.ts")
    await retryAccountSecurity(f.env,pending.transition,successfulDirectoryClient())
    expect(await setupFlag()).toEqual({ recovery_setup_at: null,recovery_setup_kind: null })
    await refusedNewActivation(false)
    const notice = await f.env.DB.prepare("SELECT id FROM account_notices WHERE account=? AND kind='recovery'").bind(f.account).first<{ id: string }>()
    await resolveAccountRecovery(f.env,(await actor()).account,"pk_test",notice!.id,"keep",successfulDirectoryClient())
    await refusedNewActivation()
    await codes()
    expect(await accountRecoverySetupRequiredNow(f.env,f.account)).toBe(false)
    expect(await setupFlag()).toMatchObject({ recovery_setup_kind: "codes" })
  })
  it("removing a second factor retains setup when unused recovery codes remain",async () => {
    await codes()
    const handle = await second("second-with-codes")
    await removeAccountPasskey(f.env,(await actor()).account,handle,"pk_test",successfulDirectoryClient())
    expect(await accountRecoverySetupRequiredNow(f.env,f.account)).toBe(false)
    expect(await setupFlag()).toMatchObject({ recovery_setup_kind: "codes" })
  })
  it("cancel revokes the code sheet and recovered factor and clears the setup flag",async () => {
    const issued = await codes(),recovery = await startAccountRecovery(f.env,new Request(f.env.VAULT_ORIGIN),issued.codes[0]!,successfulDirectoryClient())
    const { options } = await accountPasskeyOptions(f.env,{ account: f.account,session: recovery.session.id },"recovery")
    await accountPasskeyVerify(f.env,{ account: f.account,session: recovery.session.id },directoryRegistration("recovered",(options as { challenge: string }).challenge),"recovery")
    const notice = await f.env.DB.prepare("SELECT id FROM account_notices WHERE account=? AND kind='recovery'").bind(f.account).first<{ id: string }>()
    await resolveAccountRecovery(f.env,(await actor()).account,"pk_test",notice!.id,"cancel",successfulDirectoryClient())
    expect(await setupFlag()).toEqual({ recovery_setup_at: null,recovery_setup_kind: null })
    expect(await f.env.DB.prepare("SELECT credential_id FROM passkeys WHERE credential_id='recovered'").first()).toBeNull()
    await refusedNewActivation()
  })
})
describe("a suspension while recovery is under way",() => {
  const suspend = () => f.env.DB.prepare("UPDATE accounts SET suspended_at=?,suspended_by='operator:acc_admin' WHERE id=?").bind(Date.now(),f.account).run()
  const ceremony = (token: string) => new Request(f.env.VAULT_ORIGIN,{ headers: { cookie: `__Host-mehen_session=${token}` } })
  it("gives no recovery session, and no passkey, to an account suspended before its recovery reached every workspace",async () => {
    const issued = await codes(),unavailable = successfulDirectoryClient()
    unavailable.install = async () => { throw new Error("unavailable") }
    const recovery = await startAccountRecovery(f.env,new Request(f.env.VAULT_ORIGIN),issued.codes[0]!,unavailable)
    expect(recovery.pending).toBe(true)
    // The suspension's own sessions.end joins the pending recovery, which
    // then commits and creates the ceremony's session.
    await suspend()
    await endSuspendedAccountSessions(f.env,f.account,Date.now(),successfulDirectoryClient())
    expect(await f.env.DB.prepare("SELECT kind FROM web_sessions WHERE id=?").bind(recovery.session.id).first()).toEqual({ kind: "recovery" })
    await expectDirectoryRefusal(accountRecoverySession(f.env,ceremony(recovery.session.token)),{ error: "unauthenticated",message: "That recovery ceremony is no longer available. Start again with another code." })
    await expect(accountPasskeyOptions(f.env,{ account: f.account,session: recovery.session.id },"recovery")).rejects.toThrow("Account state changed. Try again.")
  })
  it("refuses the passkey a suspended account's recovery session was adding",async () => {
    const issued = await codes(),recovery = await startAccountRecovery(f.env,new Request(f.env.VAULT_ORIGIN),issued.codes[0]!,successfulDirectoryClient())
    const { options } = await accountPasskeyOptions(f.env,{ account: f.account,session: recovery.session.id },"recovery")
    await suspend()
    await expect(accountPasskeyVerify(f.env,{ account: f.account,session: recovery.session.id },directoryRegistration("while-suspended",(options as { challenge: string }).challenge),"recovery")).rejects.toThrow("Account state changed. Try again.")
    expect(await f.env.DB.prepare("SELECT credential_id FROM passkeys WHERE credential_id='while-suspended'").first()).toBeNull()
  })
})
