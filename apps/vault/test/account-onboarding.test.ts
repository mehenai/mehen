import { expectDirectoryRefusal } from "./directory-test-support.ts"
import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { SIGNUP_DEAD_INVITE_SAY, accountSignupOptions, accountSignupVerify } from "../src/directory/workspace-accounts.ts"
import { accountPasskeyOptions, accountPasskeyVerify, issueAccountRecoveryCodes, confirmAccountRecoveryCodes } from "../src/directory/workspace-recovery.ts"
import { insertAccountPasskey } from "../src/directory/account-store.ts"
import { sha256Text } from "../src/directory/session.ts"
import { VaultError } from "../src/http.ts"
import { currentAccountSession } from "../src/directory/account-session.ts"
import { setPasskeyCeremonies, simpleWebAuthnCeremonies } from "../src/directory/webauthn.ts"
import { createWorkspaceFixture, type WorkspaceTestFixture } from "./workspace-fixtures.ts"
import { directoryCeremonies, directoryRegistration } from "./directory-test-support.ts"
import { accessFixture, accountAuth, workspaceInvoke } from "./access-test-support.ts"
import type { InviteTerms } from "@mehen/protocol"
let f: WorkspaceTestFixture
beforeEach(async () => { f = await createWorkspaceFixture(); setPasskeyCeremonies(directoryCeremonies) })
afterEach(() => setPasskeyCeremonies(simpleWebAuthnCeremonies))
async function emptyDirectory() {
  await f.env.DB.batch(["account_notices","account_events","web_sessions","passkeys","invite_codes","memberships","workspace_slugs","workspaces","accounts"].map(t => f.env.DB.prepare(`DELETE FROM ${t}`)))
}
// Every workspace-creation grant in the directory, however it was made.
async function grants() {
  const row = await f.env.DB.prepare("SELECT (SELECT COUNT(*) FROM accounts WHERE can_create_workspaces=1) AS accounts,(SELECT COUNT(*) FROM account_events WHERE action='operator.allow_workspaces') AS events,(SELECT COUNT(*) FROM account_notices WHERE kind='workspace') AS notices").first<{ accounts: number; events: number; notices: number }>()
  return row
}
async function account() {
  const a = await currentAccountSession(new Request("https://vault.test/api/account",{ headers: { cookie: f.cookie } }),f.env)
  if (!a) throw new Error("Missing fixture account")
  return a
}
describe("account onboarding",() => {
  it("bootstrap creates the first account only, granted workspace creation in the same batch with its operator event and notice, and no workspace",async () => {
    await emptyDirectory()
    const input = { invite: f.env.BOOTSTRAP_CODE ?? "test-bootstrap-code",name: "First account" }
    for (const bindings of [{ ...f.env,BOOTSTRAP_CODE: undefined },{ ...f.env,BOOTSTRAP_CODE: "short" },f.env]) {
      const invite = bindings === f.env ? "not-the-bootstrap-code" : input.invite
      await expectDirectoryRefusal(accountSignupOptions(bindings,{ ...input,invite }),{ error: "not_found",message: "No such invite.",next: { say: SIGNUP_DEAD_INVITE_SAY } })
    }
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM accounts").first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM challenges").first()).toEqual({ n: 0 })
    const { options } = await accountSignupOptions(f.env,input)
    const { account: id } = await accountSignupVerify(f.env,{ ...input,response: directoryRegistration("bootstrap-credential",(options as { challenge: string }).challenge) })
    const granted = await f.env.DB.prepare("SELECT can_create_workspaces,can_create_workspaces_by,can_create_workspaces_op,recovery_setup_at FROM accounts WHERE id=?").bind(id).first<{ can_create_workspaces: number; can_create_workspaces_by: string; can_create_workspaces_op: string | null; recovery_setup_at: number | null }>()
    expect(granted).toMatchObject({ can_create_workspaces: 1,can_create_workspaces_by: "operator:bootstrap",recovery_setup_at: null })
    expect(granted?.can_create_workspaces_op).toMatch(/^[0-9a-f-]{36}$/)
    expect((await f.env.DB.prepare("SELECT action,detail FROM account_events WHERE account=? AND action LIKE 'operator.%'").bind(id).all()).results).toEqual([{ action: "operator.allow_workspaces",detail: JSON.stringify({ by: "operator:bootstrap",allowed: 1 }) }])
    expect((await f.env.DB.prepare("SELECT kind,payload,resolved_at FROM account_notices WHERE account=?").bind(id).all()).results).toEqual([{ kind: "workspace",payload: JSON.stringify({ change: "workspace_creation",allowed: 1,by: "operator:bootstrap" }),resolved_at: null }])
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces").first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM memberships").first()).toEqual({ n: 0 })
    await expectDirectoryRefusal(accountSignupOptions(f.env,input),{ error: "conflict",message: "This deployment already has an account. Ask for a workspace invite." })
    await expectDirectoryRefusal(accountSignupVerify(f.env,{ ...input,response: directoryRegistration("second-bootstrap",(options as { challenge: string }).challenge) }),{ error: "conflict",message: "This deployment already has an account. Ask for a workspace invite." })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM accounts").first()).toEqual({ n: 1 })
    expect(await grants()).toEqual({ accounts: 1,events: 1,notices: 1 })
  })
  it("two simultaneous bootstrap signups make one account and one grant",async () => {
    await emptyDirectory()
    const input = { invite: f.env.BOOTSTRAP_CODE ?? "test-bootstrap-code",name: "First account" }
    const [first,second] = await Promise.all([accountSignupOptions(f.env,input),accountSignupOptions(f.env,input)])
    const outcomes = await Promise.allSettled([
      accountSignupVerify(f.env,{ ...input,response: directoryRegistration("bootstrap-one",(first.options as { challenge: string }).challenge) }),
      accountSignupVerify(f.env,{ ...input,response: directoryRegistration("bootstrap-two",(second.options as { challenge: string }).challenge) }),
    ])
    expect(outcomes.filter(o => o.status === "fulfilled")).toHaveLength(1)
    const refused = outcomes.find(o => o.status === "rejected")
    if (refused?.status !== "rejected") throw new Error("expected one refused bootstrap")
    // Refused either at the code check or by the batch's own guard: a conflict both ways.
    expect(refused.reason).toBeInstanceOf(VaultError)
    expect((refused.reason as VaultError).code).toBe("conflict")
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM accounts").first()).toEqual({ n: 1 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys").first()).toEqual({ n: 1 })
    expect(await grants()).toEqual({ accounts: 1,events: 1,notices: 1 })
  })
  it("an ordinary invitee's signup grants nothing, even while the bootstrap code is set",async () => {
    const code = "plain-guest-invite-code",before = await grants(),{ tenant } = await accessFixture(),expiresAt = Date.now()+86400000
    const terms: InviteTerms = { role: "guest",email: null,teams: [],shares: [{ project: "prj_a",level: "use",protected: false,expiresAt: null }],expiresAt: new Date(expiresAt).toISOString() }
    expect(await workspaceInvoke(tenant,"access.invites.create",{ invite: "inv_plain",codeHash: await sha256Text(code),terms,reservation: { expiresAt: new Date(Date.now()+60000).toISOString() } },accountAuth("owner",{ type: "member.invite",terms }))).toMatchObject({ ok: true })
    await f.env.DB.batch([f.env.DB.prepare("INSERT INTO workspaces(id,slug,name,status,created_by,created_at) VALUES (?,'invited','Invited','active',?,?)").bind(tenant,f.account,Date.now()),
      f.env.DB.prepare("INSERT INTO invite_codes(code_hash,kind,workspace,invite,email,expires_at) VALUES (?,'join',?,'inv_plain',NULL,?)").bind(await sha256Text(code),tenant,expiresAt)])
    const input = { invite: code,name: "Invited guest" },{ options } = await accountSignupOptions(f.env,input)
    const created = await accountSignupVerify(f.env,{ ...input,response: directoryRegistration("invitee-credential",(options as { challenge: string }).challenge) })
    expect(created.via).toBe("join")
    expect(await f.env.DB.prepare("SELECT can_create_workspaces,can_create_workspaces_by,can_create_workspaces_op FROM accounts WHERE id=?").bind(created.account).first()).toEqual({ can_create_workspaces: 0,can_create_workspaces_by: null,can_create_workspaces_op: null })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_events WHERE account=? AND action LIKE 'operator.%'").bind(created.account).first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_notices WHERE account=?").bind(created.account).first()).toEqual({ n: 0 })
    expect(await grants()).toEqual(before)
  })
  it("does not mark recovery ready until codes are acknowledged, and logs no values",async () => {
    const a = await account(),issued = await issueAccountRecoveryCodes(f.env,a)
    expect(await f.env.DB.prepare("SELECT recovery_setup_at FROM accounts WHERE id=?").bind(a.account).first()).toEqual({ recovery_setup_at: null })
    await expectDirectoryRefusal(confirmAccountRecoveryCodes(f.env,a,issued.batch,"wrong"),{ error: "bad_request",message: "That is not the code at the requested position. Check the saved sheet and try again." })
    expect(await f.env.DB.prepare("SELECT recovery_setup_at FROM accounts WHERE id=?").bind(a.account).first()).toEqual({ recovery_setup_at: null })
    await confirmAccountRecoveryCodes(f.env,a,issued.batch,issued.codes[issued.confirmPosition-1] as string)
    expect(await f.env.DB.prepare("SELECT recovery_setup_kind FROM accounts WHERE id=?").bind(a.account).first()).toEqual({ recovery_setup_kind: "codes" })
    const events = JSON.stringify((await f.env.DB.prepare("SELECT * FROM account_events").all()).results)
    for (const code of issued.codes) expect(events).not.toContain(code)
    await expectDirectoryRefusal(confirmAccountRecoveryCodes(f.env,a,issued.batch,issued.codes[0] as string),{ error: "bad_request",message: "Those codes could not be confirmed. Generate a new set." })
  })
  it("a second distinct passkey fulfils required recovery setup in the registration batch",async () => {
    const a = await account()
    await insertAccountPasskey(f.env,a.account,{ credentialId: "initial",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },Date.now()-1000,"signup","pk_initial").run()
    expect(await f.env.DB.prepare("SELECT recovery_setup_kind FROM accounts WHERE id=?").bind(a.account).first()).toEqual({ recovery_setup_kind: null })
    const { options } = await accountPasskeyOptions(f.env,a,"settings",Date.now(),"pk_initial")
    await accountPasskeyVerify(f.env,a,directoryRegistration("second",(options as { challenge: string }).challenge),"settings")
    expect(await f.env.DB.prepare("SELECT recovery_setup_kind FROM accounts WHERE id=?").bind(a.account).first()).toEqual({ recovery_setup_kind: "passkey" })
  })
  it("a factor-registration challenge cannot cross a committed epoch",async () => {
    const a = await account()
    await insertAccountPasskey(f.env,a.account,{ credentialId: "initial",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },Date.now()-1000,"signup","pk_initial").run()
    const { options } = await accountPasskeyOptions(f.env,a,"settings",Date.now(),"pk_initial")
    await f.env.DB.prepare("UPDATE accounts SET security_epoch=1 WHERE id=?").bind(a.account).run()
    await expectDirectoryRefusal(accountPasskeyVerify(f.env,a,directoryRegistration("stale",(options as { challenge: string }).challenge),"settings"),{ error: "conflict",message: "Account state changed. Try again." })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys").first()).toEqual({ n: 1 })
    expect(await f.env.DB.prepare("SELECT recovery_setup_at FROM accounts WHERE id=?").bind(a.account).first()).toEqual({ recovery_setup_at: null })
  })
  it("registration final check rejects sign-out after async verification",async () => {
    const a = await account()
    await insertAccountPasskey(f.env,a.account,{ credentialId: "initial",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },Date.now()-1000,"signup","pk_initial").run()
    const { options } = await accountPasskeyOptions(f.env,a,"settings",Date.now(),"pk_initial")
    setPasskeyCeremonies({ ...directoryCeremonies,async verifyRegistration(response,expected) { const key = await directoryCeremonies.verifyRegistration(response,expected); await f.env.DB.prepare("DELETE FROM web_sessions").run(); return key } })
    await expectDirectoryRefusal(accountPasskeyVerify(f.env,a,directoryRegistration("raced",(options as { challenge: string }).challenge),"settings"),{ error: "conflict",message: "Account state changed. Try again." })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys").first()).toEqual({ n: 1 })
    expect(await f.env.DB.prepare("SELECT recovery_setup_at FROM accounts WHERE id=?").bind(a.account).first()).toEqual({ recovery_setup_at: null })
  })
})
