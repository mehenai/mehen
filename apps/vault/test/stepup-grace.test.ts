// Passkey grace, at the verifier: after a real passkey in a
// browser session, a graceable action starts with `grace` and no passkey
// options, and its `{ nonce, grace: true }` proof runs every check of the
// passkey path but WebAuthn and the counter, for 15 minutes that do not slide.
import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { createExecutionContext } from "cloudflare:test"
import { STEP_UP_GRACE_MS, type StepUpProof, type WorkspaceStepUpAction } from "@mehen/protocol"
import { currentAccountSession } from "../src/directory/account-session.ts"
import { insertAccountPasskey } from "../src/directory/account-store.ts"
import { reserveAccountSecurity, retryAccountSecurity } from "../src/directory/account-security.ts"
import { accountBreakGlassOptions, accountBreakGlassVerify, reconcileAccountBreakGlass } from "../src/directory/account-break-glass.ts"
import { confirmAccountRecoveryCodes, issueAccountRecoveryCodes, startAccountRecovery } from "../src/directory/workspace-recovery.ts"
import { sha256Text } from "../src/directory/session.ts"
import { breakGlassStatement } from "../scripts/break-glass.ts"
import { endStepUpGrace, liveStepUpGrace, requireAppAccountStepUp, requireWorkspaceStepUp, startAccountStepUp, stepUpGraceId, type StepUpStart } from "../src/directory/workspace-stepup.ts"
import { setPasskeyCeremonies, simpleWebAuthnCeremonies, type PasskeyCeremonies } from "../src/directory/webauthn.ts"
import type { Env } from "../src/env.ts"
import { responseFor } from "../src/http.ts"
import type { RequestContext, WorkspaceRequest } from "../src/routes/context.ts"
import { createWorkspaceFixture, type WorkspaceTestFixture } from "./workspace-fixtures.ts"
import { directoryCeremonies, directoryRegistration, expectDirectoryRefusal, successfulDirectoryClient } from "./directory-test-support.ts"
import { ORIGIN } from "./helpers.ts"

const REFUSAL = { error: "forbidden",message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." } as const
// Graced: revoking a machine. Always fresh: removing a backup recipient.
const revoke: WorkspaceStepUpAction = { type: "device.revoke",device: "dev_test" }
const fresh: WorkspaceStepUpAction = { type: "backup.recipient_remove",id: "rcp_test" }
const assertion = { id: "credential",rawId: "credential",type: "public-key",response: {} }
const ceremonies: PasskeyCeremonies = { ...simpleWebAuthnCeremonies,async verifyAuthentication(_response,expected) { return expected.challenge ? { counter: 7,backedUp: true } : null } }
let f: WorkspaceTestFixture
let env: Env
let rc: RequestContext
let ws: WorkspaceRequest
beforeEach(async () => {
  f = await createWorkspaceFixture()
  env = { ...f.env,STEPUP_GRACE: "on" }
  setPasskeyCeremonies(ceremonies)
  await insertAccountPasskey(env,f.account,{ credentialId: "credential",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },Date.now(),"signup","pk_test").run()
  rc = { request: new Request(`${ORIGIN}/api/w/alex`,{ headers: { cookie: f.cookie } }),env,ctx: createExecutionContext(),url: new URL(`${ORIGIN}/api/w/alex`),params: { ws: "alex" } }
  const account = await currentAccountSession(rc.request,env)
  if (!account) throw new Error("Missing account")
  ws = { account,workspace: { id: f.workspaces.personal,slug: "alex",name: "Personal" },membership: f.personalMember }
})
afterEach(() => setPasskeyCeremonies(simpleWebAuthnCeremonies))

const start = (action: WorkspaceStepUpAction, on = env): Promise<StepUpStart> => startAccountStepUp(on,ws.account,ws.workspace.id,action)
async function passkey(action: WorkspaceStepUpAction): Promise<StepUpProof> {
  const started = await start(action)
  if (!("options" in started)) throw new Error("Expected passkey options")
  return { nonce: started.nonce,assertion }
}
async function graced(action: WorkspaceStepUpAction): Promise<StepUpProof> {
  const started = await start(action)
  if (!("grace" in started)) throw new Error("Expected a graced start")
  expect(started).not.toHaveProperty("options")
  return { nonce: started.nonce,grace: true }
}
const windowRow = () => env.DB.prepare("SELECT kind,challenge,account,workspace,security_epoch,factor,context,expires_at FROM challenges WHERE kind='stepup-grace'").all().then(r => r.results)
const passkeyState = () => env.DB.prepare("SELECT counter,backed_up,last_used_at FROM passkeys WHERE handle='pk_test'").first()
// A window row standing when a later statement runs, as a race could leave one.
async function plantWindow(): Promise<void> {
  await env.DB.prepare("INSERT INTO challenges(id,kind,challenge,account,workspace,security_epoch,factor,context,expires_at) SELECT ?,'stepup-grace',?,id,'*',security_epoch,'pk_test',?,? FROM accounts WHERE id=?")
    .bind(await stepUpGraceId(ws.account.session),String(Date.now()),ws.account.session,Date.now() + STEP_UP_GRACE_MS,f.account).run()
}
// Opens this session's window with a real passkey; answers when it was proven.
async function openWindow(): Promise<number> {
  const evidence = await requireWorkspaceStepUp(rc,ws,revoke,await passkey(revoke))
  expect(evidence.confirmation.kind).toBe("passkey")
  return evidence.confirmation.provenAt
}

describe("passkey grace",() => {
  it("a real passkey opens the window; a graced action then needs no passkey, touches no passkey state and does not extend it",async () => {
    const before = Date.now()
    const provenAt = await openWindow()
    expect(provenAt).toBeGreaterThanOrEqual(before)
    expect(await windowRow()).toEqual([{ kind: "stepup-grace",challenge: String(provenAt),account: f.account,workspace: "*",security_epoch: 0,factor: "pk_test",context: ws.account.session,expires_at: provenAt + STEP_UP_GRACE_MS }])
    const opened = await passkeyState()
    expect(opened).toMatchObject({ counter: 7,backed_up: 1 })
    const started = await start(revoke)
    expect(started).toEqual({ nonce: expect.any(String),grace: { until: new Date(provenAt + STEP_UP_GRACE_MS).toISOString() } })
    expect(await requireWorkspaceStepUp(rc,ws,revoke,{ nonce: started.nonce,grace: true })).toEqual({ action: revoke,factor: "pk_test",confirmation: { kind: "grace",provenAt } })
    expect(await passkeyState()).toEqual(opened)
    expect(await windowRow()).toEqual([expect.objectContaining({ expires_at: provenAt + STEP_UP_GRACE_MS })])
  })
  it("a graced confirmation's provenAt is the ceremony time the window stored, not one worked back from its end",async () => {
    const provenAt = await openWindow()
    await env.DB.prepare("UPDATE challenges SET expires_at=? WHERE kind='stepup-grace'").bind(provenAt + 5 * 60_000).run()
    expect((await requireWorkspaceStepUp(rc,ws,revoke,await graced(revoke))).confirmation).toEqual({ kind: "grace",provenAt })
  })
  it("ends at 15 minutes from the passkey, and only a real passkey renews it",async () => {
    await openWindow()
    await env.DB.prepare("UPDATE challenges SET expires_at=? WHERE kind='stepup-grace'").bind(Date.now() - 1).run()
    expect(await start(revoke)).toHaveProperty("options")
    const renewed = await openWindow()
    expect(await windowRow()).toEqual([expect.objectContaining({ challenge: String(renewed),expires_at: renewed + STEP_UP_GRACE_MS })])
  })
  it("an always-fresh action asks for the passkey inside the window, and a grace proof for it is refused",async () => {
    await openWindow()
    const started = await start(fresh)
    expect(started).toHaveProperty("options")
    await expectDirectoryRefusal(requireWorkspaceStepUp(rc,ws,fresh,{ nonce: started.nonce,grace: true }),REFUSAL)
  })
  it("refuses a grace proof for a challenge started without grace, and a passkey proof for a graced one",async () => {
    const plain = await passkey(revoke)
    await expectDirectoryRefusal(requireWorkspaceStepUp(rc,ws,revoke,{ nonce: plain.nonce,grace: true }),REFUSAL)
    await openWindow()
    const p = await graced(revoke)
    await expectDirectoryRefusal(requireWorkspaceStepUp(rc,ws,revoke,{ nonce: p.nonce,assertion }),REFUSAL)
  })
  it("a graced challenge is single use and bound to the exact action",async () => {
    await openWindow()
    const p = await graced(revoke)
    await expectDirectoryRefusal(requireWorkspaceStepUp(rc,ws,{ type: "device.revoke",device: "dev_other" },p),REFUSAL)
    const q = await graced(revoke)
    await requireWorkspaceStepUp(rc,ws,revoke,q)
    await expectDirectoryRefusal(requireWorkspaceStepUp(rc,ws,revoke,q),REFUSAL)
  })
  it("ends with the session: signing out, ask every time, or another session",async () => {
    await openWindow()
    expect(await liveStepUpGrace(env,{ ...ws.account,session: "ses_other" })).toBeNull()
    const p = await graced(revoke)
    await env.DB.prepare("DELETE FROM web_sessions").run()
    await expectDirectoryRefusal(requireWorkspaceStepUp(rc,ws,revoke,p),REFUSAL)
  })
  it("ask every time ends it with no passkey",async () => {
    await openWindow()
    await endStepUpGrace(env,ws.account)
    expect(await windowRow()).toEqual([])
    expect(await start(revoke)).toHaveProperty("options")
  })
  it("ends with an epoch change, the passkey's removal or its pending removal",async () => {
    await openWindow()
    const p = await graced(revoke)
    await env.DB.prepare("UPDATE accounts SET security_epoch=1 WHERE id=?").bind(f.account).run()
    expect(await liveStepUpGrace(env,{ ...ws.account,securityEpoch: 1 })).toBeNull()
    await expectDirectoryRefusal(requireWorkspaceStepUp(rc,ws,revoke,p),REFUSAL)
    await env.DB.prepare("UPDATE accounts SET security_epoch=0 WHERE id=?").bind(f.account).run()
    expect(await liveStepUpGrace(env,ws.account)).not.toBeNull()
    await env.DB.prepare("UPDATE passkeys SET handle='pk_moved' WHERE handle='pk_test'").run()
    expect(await liveStepUpGrace(env,ws.account)).toBeNull()
    await env.DB.prepare("UPDATE passkeys SET handle='pk_test' WHERE handle='pk_moved'").run()
    const q = await graced(revoke)
    await reserveAccountSecurity(env,f.account,{ effect: { kind: "factor.remove" },revokedSessionIds: [],removedFactorIds: ["pk_test"] })
    expect(await liveStepUpGrace(env,ws.account)).toBeNull()
    await expectDirectoryRefusal(requireWorkspaceStepUp(rc,ws,revoke,q),REFUSAL)
  })
  it("a security transition deletes the account's windows, so none revives when it clears without an epoch change",async () => {
    await openWindow()
    await reserveAccountSecurity(env,f.account,{ effect: { kind: "factor.remove" },revokedSessionIds: [],removedFactorIds: ["pk_other"] })
    expect(await windowRow()).toEqual([])
    await env.DB.prepare("UPDATE accounts SET security_transition=NULL WHERE id=?").bind(f.account).run()
    expect(await start(revoke)).toHaveProperty("options")
  })
  it("committing a recovery deletes the account's windows",async () => {
    await openWindow()
    const codes = await issueAccountRecoveryCodes(env,ws.account)
    await confirmAccountRecoveryCodes(env,ws.account,codes.batch,codes.codes[codes.confirmPosition - 1] as string)
    const unavailable = successfulDirectoryClient()
    unavailable.install = async () => { throw new Error("unavailable") }
    const recovery = await startAccountRecovery(env,new Request(`${ORIGIN}/api/auth/recovery`),codes.codes[0] as string,unavailable)
    await plantWindow()
    expect(await windowRow()).toHaveLength(1)
    await retryAccountSecurity(env,recovery.transition,successfulDirectoryClient())
    expect(await env.DB.prepare("SELECT security_transition FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ security_transition: null })
    expect(await windowRow()).toEqual([])
  })
  it("redeeming a break-glass link deletes the account's windows",async () => {
    const code = "offline-operator-grace-link"
    await env.DB.prepare(breakGlassStatement(f.account,"operator:test",await sha256Text(code),Date.now(),`bgi_${"a".repeat(32)}`,`ntc_${"b".repeat(32)}`)).run()
    await reconcileAccountBreakGlass(env,successfulDirectoryClient())
    await plantWindow()
    expect(await windowRow()).toHaveLength(1)
    setPasskeyCeremonies(directoryCeremonies)
    const { options } = await accountBreakGlassOptions(env,code)
    await accountBreakGlassVerify(env,code,directoryRegistration("replacement-factor",(options as { challenge: string }).challenge),{ client: "Safari on Mac",place: null })
    expect(await windowRow()).toEqual([])
  })
  it("a cooling-off refuses grace even for a narrowing action, refuses a widening one exactly as now, and a passkey then opens no window",async () => {
    await openWindow()
    const p = await graced(revoke)
    await env.DB.prepare("UPDATE accounts SET restricted_until=?,restricted_reason='recovery' WHERE id=?").bind(Date.now() + 3_600_000,f.account).run()
    expect(await liveStepUpGrace(env,ws.account)).toBeNull()
    await expectDirectoryRefusal(requireWorkspaceStepUp(rc,ws,revoke,p),REFUSAL)
    expect(await start(revoke)).toHaveProperty("options")
    await expectDirectoryRefusal(start({ type: "item.delete",item: "itm_x" }),{ error: "forbidden",message: "Your account is cooling off. You can read, narrow, deny, revoke and freeze, but cannot widen access.",next: expect.anything() })
    await env.DB.prepare("DELETE FROM challenges WHERE kind='stepup-grace'").run()
    await openWindow()
    expect(await windowRow()).toEqual([])
  })
  it("a passkey during a pending transition opens no window",async () => {
    await reserveAccountSecurity(env,f.account,{ effect: { kind: "factor.remove" },revokedSessionIds: [],removedFactorIds: ["pk_other"] })
    await openWindow()
    expect(await windowRow()).toEqual([])
  })
  it("switched off: no window is written, start never answers grace and a grace proof is refused",async () => {
    const off = { ...env,STEPUP_GRACE: "off" }
    const offRc = { ...rc,env: off }
    const started = await start(revoke,off)
    if (!("options" in started)) throw new Error("Expected passkey options")
    await requireWorkspaceStepUp(offRc,ws,revoke,{ nonce: started.nonce,assertion })
    expect(await windowRow()).toEqual([])
    await openWindow()
    expect(await start(revoke,off)).toHaveProperty("options")
    const p = await graced(revoke)
    await expectDirectoryRefusal(requireWorkspaceStepUp(offRc,ws,revoke,p),REFUSAL)
  })
  it("the app's start always answers passkey options, and an app session never rides a window",async () => {
    await openWindow()
    expect(await startAccountStepUp(env,ws.account,ws.workspace.id,revoke,{ allowGrace: false })).toHaveProperty("options")
    const p = await graced(revoke)
    let error: unknown
    try { await requireAppAccountStepUp(rc,ws.account,ws.workspace.id,revoke,p) } catch (e) { error = e }
    expect(responseFor(error).status).toBe(403)
  })
  it("the window's row id is the session's own",async () => {
    await openWindow()
    expect(await env.DB.prepare("SELECT id FROM challenges WHERE kind='stepup-grace'").first()).toEqual({ id: await stepUpGraceId(ws.account.session) })
  })
})
