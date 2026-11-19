import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { createWorkspaceFixture, type WorkspaceTestFixture } from "./workspace-fixtures.ts"
import { directoryCeremonies,directoryRegistration,expectDirectoryRefusal,successfulDirectoryClient } from "./directory-test-support.ts"
import { accountBreakGlassOptions,accountBreakGlassVerify,reconcileAccountBreakGlass } from "../src/directory/account-break-glass.ts"
import { setPasskeyCeremonies,simpleWebAuthnCeremonies } from "../src/directory/webauthn.ts"
import { insertAccountPasskey } from "../src/directory/account-store.ts"
import { SESSION_COOKIE,sha256Text } from "../src/directory/session.ts"
import { currentAccountSession } from "../src/directory/account-session.ts"
import { accountRecoverySession,confirmAccountRecoveryCodes,issueAccountRecoveryCodes,startAccountRecovery } from "../src/directory/workspace-recovery.ts"
import { PENDING_RESTRICTION_UNTIL } from "@mehen/protocol"
import { breakGlassStatement,parseArgs,runBreakGlass,type BreakGlassIo } from "../scripts/break-glass.ts"
let f: WorkspaceTestFixture
const id = `bgi_${"a".repeat(32)}`,notice = `ntc_${"b".repeat(32)}`,code = "offline-operator-test-link"
beforeEach(async () => { f = await createWorkspaceFixture(); setPasskeyCeremonies(directoryCeremonies) })
afterEach(() => setPasskeyCeremonies(simpleWebAuthnCeremonies))
async function issue(now = Date.now()) {
  await insertAccountPasskey(f.env,f.account,{ credentialId: "old-factor",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },now-1000,"signup","pk_old").run()
  await f.env.DB.prepare("INSERT INTO recovery_codes(code_hash,account,batch,position,status,created_at) VALUES ('old-code',?,'old-batch',1,'active',?)").bind(f.account,now).run()
  await f.env.DB.prepare(breakGlassStatement(f.account,"operator:test",await sha256Text(code),now,id,notice)).run()
  return now
}
it("holds the link until every target acknowledges, then revokes account factors/codes/sessions without restoring memberships",async () => {
  const now = await issue(),before = (await f.env.DB.prepare("SELECT * FROM memberships").all()).results
  const client = successfulDirectoryClient()
  client.install = async () => { throw new Error("unavailable workspace") }
  await reconcileAccountBreakGlass(f.env,client,now)
  await expectDirectoryRefusal(accountBreakGlassOptions(f.env,code),{ error: "not_found",message: "No such recovery link." })
  expect(await f.env.DB.prepare("SELECT security_epoch,security_transition FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ security_epoch: 0,security_transition: expect.any(String) })
  expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys WHERE account=?").bind(f.account).first()).toEqual({ n: 1 })
  expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM invite_codes").first()).toEqual({ n: 0 })
  await reconcileAccountBreakGlass(f.env,successfulDirectoryClient(),now+1)
  expect(await f.env.DB.prepare("SELECT security_epoch,security_transition,restricted_until,recovery_setup_at FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ security_epoch: 1,security_transition: null,restricted_until: PENDING_RESTRICTION_UNTIL,recovery_setup_at: null })
  expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys WHERE account=?").bind(f.account).first()).toEqual({ n: 0 })
  expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions WHERE account=?").bind(f.account).first()).toEqual({ n: 0 })
  expect(await f.env.DB.prepare("SELECT status FROM recovery_codes WHERE account=?").bind(f.account).first()).toEqual({ status: "revoked" })
  expect((await f.env.DB.prepare("SELECT * FROM memberships").all()).results).toEqual(before)
  const { options } = await accountBreakGlassOptions(f.env,code)
  const result = await accountBreakGlassVerify(f.env,code,directoryRegistration("replacement-factor",(options as { challenge: string }).challenge),{ client: "Safari on Mac",place: null })
  expect(result.account).toBe(f.account)
  const account = await f.env.DB.prepare("SELECT restricted_until,recovery_setup_at FROM accounts WHERE id=?").bind(f.account).first<{ restricted_until: number; recovery_setup_at: null }>()
  expect(account!.restricted_until).toBeGreaterThanOrEqual(now+86400000)
  expect(account!.restricted_until).toBeLessThan(PENDING_RESTRICTION_UNTIL)
  expect(account!.recovery_setup_at).toBeNull()
  expect(await f.env.DB.prepare("SELECT added_via FROM passkeys WHERE account=?").bind(f.account).first()).toEqual({ added_via: "break-glass" })
  await expectDirectoryRefusal(accountBreakGlassOptions(f.env,code),{ error: "not_found",message: "No such recovery link." })
  const events = JSON.stringify((await f.env.DB.prepare("SELECT action,detail FROM account_events WHERE account=?").bind(f.account).all()).results)
  expect(events).toContain("operator.break_glass")
  expect(events).toContain("account.break_glass")
  expect(events).not.toContain(code)
  expect(events).not.toContain(await sha256Text(code))
})
it("expired, wrong and pending links refuse without minting a challenge",async () => {
  const now = await issue()
  for (const input of [code,"unknown-link"]) await expectDirectoryRefusal(accountBreakGlassOptions(f.env,input),{ error: "not_found",message: "No such recovery link." })
  await reconcileAccountBreakGlass(f.env,successfulDirectoryClient(),now)
  await expectDirectoryRefusal(accountBreakGlassOptions(f.env,code,now+3600000),{ error: "not_found",message: "No such recovery link." })
  expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM challenges").first()).toEqual({ n: 0 })
})
it("the operator refuses tenant/member targets, ambiguous databases, injection and an unconfirmed account",async () => {
  for (const argv of [["--remote","--member","mem_x"],["--remote","--local","--list"],["--account",f.account],["--remote","--account",f.account,"--actor","owner:x"]]) expect(() => parseArgs(argv)).toThrow()
  expect(() => breakGlassStatement("acc_x'","operator:test","a".repeat(43),1,id,notice)).toThrow()
  const output: string[] = [],writes: string[] = []
  const io: BreakGlassIo = { async query<T>() { return [{ id: f.account,name: "Owner",status: "active" }] as T[] },async execute(_t,sql) { writes.push(sql) },async bookmark() { return "bookmark" },print: line => output.push(line),async ask() { return "wrong-account" },now: () => Date.now(),async wait() { throw new Error("must not wait") } }
  expect(await runBreakGlass(parseArgs(["--remote","--account",f.account,"--actor","operator:test"]),io)).toBe(1)
  expect(writes).toEqual([])
  expect(output.some(line => line.includes("/signup#"))).toBe(false)
})

it("--list and the plan spell an account name's control characters, so no ESC or BEL from it reaches the terminal",async () => {
  const output: string[] = []
  const io: BreakGlassIo = { async query<T>() { return [{ id: f.account,name: "Mallory\u001b[31m red\u001b[0m\u0007\u009b2J",status: "active" }] as T[] },async execute() { throw new Error("must not write") },async bookmark() { return "bookmark" },print: line => output.push(line),async ask() { return null },now: () => Date.now(),async wait() { throw new Error("must not wait") } }
  expect(await runBreakGlass(parseArgs(["--local","--list"]),io)).toBe(0)
  expect(await runBreakGlass(parseArgs(["--local","--account",f.account,"--actor","operator:test"]),io)).toBe(1)
  expect(output.filter(line => /[\u0000-\u001f\u007f-\u009f]/.test(line))).toEqual([])
  expect(output[0]).toBe(`${f.account}  Mallory\\u001B[31m red\\u001B[0m\\u0007\\u009B2J  active`)
  expect(output).toContain(`Break glass for Mallory\\u001B[31m red\\u001B[0m\\u0007\\u009B2J (${f.account}) on local database mehen-local, actor operator:test.`)
})

it("prints the private link once only after the real intent and barrier commit, never a hash or a pending link",async () => {
  const lines: string[] = []
  let now = Date.now(),waited = 0
  const io: BreakGlassIo = {
    async query<T>(_target: import("../scripts/break-glass.ts").Target,sql: string) { return (await f.env.DB.prepare(sql).all<T>()).results },
    async execute(_target,sql) { await f.env.DB.prepare(sql).run() },
    async bookmark() { return "operator-bookmark" },print: line => lines.push(line),async ask() { return f.account },now: () => now,
    async wait() { expect(lines.some(line => line.includes("/signup#"))).toBe(false); waited++; now++; await reconcileAccountBreakGlass(f.env,successfulDirectoryClient(),now) },
  }
  expect(await runBreakGlass(parseArgs(["--local","--account",f.account,"--actor","operator:test"]),io)).toBe(0)
  expect(waited).toBe(1)
  const links = lines.filter(line => line.includes("/signup#"))
  expect(links).toHaveLength(1)
  const issued = links[0]!.split("#")[1]!
  const intent = await f.env.DB.prepare("SELECT state,code_hash FROM account_break_glass_intents").first<{ state: string; code_hash: string }>()
  expect(intent).toEqual({ state: "ready",code_hash: await sha256Text(issued) })
  expect(lines.join("\n")).not.toContain(intent!.code_hash)
})
it("a failed final security commit leaves every factor and the link pending, and retries the same barrier",async () => {
  await issue()
  await f.env.DB.prepare("CREATE TRIGGER fail_break_glass_commit BEFORE DELETE ON passkeys BEGIN SELECT RAISE(ABORT,'commit-fault'); END").run()
  await reconcileAccountBreakGlass(f.env,successfulDirectoryClient())
  expect(await f.env.DB.prepare("SELECT state FROM account_break_glass_intents").first()).toEqual({ state: "pending" })
  expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys").first()).toEqual({ n: 1 })
  expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM invite_codes").first()).toEqual({ n: 0 })
  const transition = await f.env.DB.prepare("SELECT id,reserved_epoch FROM account_security_transitions").first()
  await f.env.DB.prepare("DROP TRIGGER fail_break_glass_commit").run()
  await reconcileAccountBreakGlass(f.env,successfulDirectoryClient())
  expect(await f.env.DB.prepare("SELECT id,reserved_epoch FROM account_security_transitions").first()).toEqual(transition)
  expect(await f.env.DB.prepare("SELECT state FROM account_break_glass_intents").first()).toEqual({ state: "ready" })
})

it("a replacement link cannot leave an abandoned expired intent as an endless recovery restriction",async () => {
  const start = Date.now()-3600001
  await issue(start)
  // Simulate a ready link whose operator process ended before publication.
  await reconcileAccountBreakGlass(f.env,successfulDirectoryClient(),start)
  await reconcileAccountBreakGlass(f.env,successfulDirectoryClient(),Date.now())
  expect(await f.env.DB.prepare("SELECT state FROM account_break_glass_intents").first()).toEqual({ state: "expired" })
  const replacement = "replacement-operator-link",next = Date.now()
  await f.env.DB.prepare(breakGlassStatement(f.account,"operator:replacement",await sha256Text(replacement),next,`bgi_${"c".repeat(32)}`,`ntc_${"d".repeat(32)}`)).run()
  await reconcileAccountBreakGlass(f.env,successfulDirectoryClient(),next)
  const { options } = await accountBreakGlassOptions(f.env,replacement)
  await accountBreakGlassVerify(f.env,replacement,directoryRegistration("new-factor",(options as { challenge: string }).challenge),{ client: "A browser",place: null })
  const restriction = await f.env.DB.prepare("SELECT restricted_until FROM accounts WHERE id=?").bind(f.account).first<{ restricted_until: number }>()
  expect(restriction!.restricted_until).toBeLessThan(PENDING_RESTRICTION_UNTIL)
  expect(restriction!.restricted_until).toBeGreaterThanOrEqual(next+86400000)
})

it("an explicitly cancelled pending operator notice never publishes a link or leaves a redeemable invite",async () => {
  const now = await issue()
  const { reserveAccountSecurity } = await import("../src/directory/account-security.ts")
  await reserveAccountSecurity(f.env,f.account,{ effect: { kind: "recovery.cancel",notice,factor: "pk_old" },revokedSessionIds: [],removedFactorIds: [] },now)
  await reconcileAccountBreakGlass(f.env,successfulDirectoryClient(),now+1)
  expect(await f.env.DB.prepare("SELECT state FROM account_break_glass_intents").first()).toEqual({ state: "expired" })
  expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM invite_codes WHERE kind='break-glass'").first()).toEqual({ n: 0 })
  await expectDirectoryRefusal(accountBreakGlassOptions(f.env,code),{ error: "not_found",message: "No such recovery link." })
})

it("refreshes recovery readiness in the replacement-factor batch when another recovered factor already exists",async () => {
  await issue()
  await reconcileAccountBreakGlass(f.env,successfulDirectoryClient())
  await insertAccountPasskey(f.env,f.account,{ credentialId: "overlapping-recovery-factor",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },Date.now(),"recovery","pk_overlap").run()
  const { options } = await accountBreakGlassOptions(f.env,code)
  await accountBreakGlassVerify(f.env,code,directoryRegistration("operator-recovered-factor",(options as { challenge: string }).challenge),{ client: "A browser",place: null })
  expect(await f.env.DB.prepare("SELECT recovery_setup_kind,recovery_setup_at IS NOT NULL AS ready FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ recovery_setup_kind: "passkey",ready: 1 })
})
it("a suspension landing after the link is checked refuses its redemption: no passkey, no session, the link still unused",async () => {
  const now = await issue()
  await reconcileAccountBreakGlass(f.env,successfulDirectoryClient(),now)
  const { options } = await accountBreakGlassOptions(f.env,code)
  // The operator's suspension commits between the link's check and its batch.
  const db = new Proxy(f.env.DB,{ get(target,prop) {
    if (prop === "batch") return async (statements: D1PreparedStatement[]) => {
      await target.prepare("UPDATE accounts SET suspended_at=?,suspended_by='operator:acc_admin' WHERE id=?").bind(Date.now(),f.account).run()
      return target.batch(statements)
    }
    const value = Reflect.get(target,prop) as unknown
    return typeof value === "function" ? value.bind(target) : value
  } })
  await expectDirectoryRefusal(accountBreakGlassVerify({ ...f.env,DB: db },code,directoryRegistration("while-suspended",(options as { challenge: string }).challenge),{ client: "A browser",place: null }),{ error: "conflict",message: "Account state changed. Try again." })
  expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys WHERE account=?").bind(f.account).first()).toEqual({ n: 0 })
  expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions WHERE account=?").bind(f.account).first()).toEqual({ n: 0 })
  expect(await f.env.DB.prepare("SELECT state FROM account_break_glass_intents WHERE id=?").bind(id).first()).toEqual({ state: "ready" })
})

// OPERATIONS.md, the operator barrier: break-glass ends passkeys, sessions and
// recovery codes before its link works. A recovery a code holder started in the
// same pending transition, in either order, neither stalls that barrier nor
// keeps a ceremony past it, and its notice does not outlive the redeemed link.
describe("a recovery started in the same pending transition as break-glass",() => {
  async function recoveryCodes() {
    const account = await currentAccountSession(new Request("https://vault.test",{ headers: { cookie: f.cookie } }),f.env)
    if (!account) throw new Error("Missing actor session")
    const issued = await issueAccountRecoveryCodes(f.env,account)
    await confirmAccountRecoveryCodes(f.env,account,issued.batch,issued.codes[issued.confirmPosition-1]!)
    return issued.codes
  }
  function unavailable() { const client = successfulDirectoryClient(); client.install = async () => { throw new Error("unavailable workspace") }; return client }
  async function expectBarrierHeld(token: string,transition: string) {
    expect(await f.env.DB.prepare("SELECT state FROM account_security_transitions WHERE id=?").bind(transition).first()).toEqual({ state: "committed" })
    expect(await f.env.DB.prepare("SELECT security_transition FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ security_transition: null })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions WHERE account=?").bind(f.account).first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys WHERE account=?").bind(f.account).first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM recovery_codes WHERE account=? AND status!='revoked'").bind(f.account).first()).toEqual({ n: 0 })
    const ceremony = new Request("https://vault.test",{ headers: { cookie: `${SESSION_COOKIE}=${token}` } })
    await expectDirectoryRefusal(accountRecoverySession(f.env,ceremony),{ error: "unauthenticated",message: "That recovery ceremony is no longer available. Start again with another code." })
    const { options } = await accountBreakGlassOptions(f.env,code)
    await accountBreakGlassVerify(f.env,code,directoryRegistration("operator-recovered-factor",(options as { challenge: string }).challenge),{ client: "A browser",place: null })
    const restriction = await f.env.DB.prepare("SELECT restricted_until FROM accounts WHERE id=?").bind(f.account).first<{ restricted_until: number }>()
    expect(restriction!.restricted_until).toBeLessThan(PENDING_RESTRICTION_UNTIL)
  }
  it("break-glass first, then recovery: the barrier commits and the link works",async () => {
    const codes = await recoveryCodes(),now = await issue()
    await reconcileAccountBreakGlass(f.env,unavailable(),now)
    const recovery = await startAccountRecovery(f.env,new Request("https://vault.test/api/auth/recovery"),codes[0]!,unavailable(),now+1)
    const effects = await f.env.DB.prepare("SELECT effects FROM account_security_transitions WHERE id=?").bind(recovery.transition).first<{ effects: string }>()
    expect((JSON.parse(effects!.effects) as { kind: string }[]).map(e => e.kind)).toEqual(["break-glass","recovery.start"])
    await reconcileAccountBreakGlass(f.env,successfulDirectoryClient(),now+2)
    await expectBarrierHeld(recovery.session.token,recovery.transition)
  })
  it("recovery first, then break-glass: no recovery ceremony survives the barrier",async () => {
    const codes = await recoveryCodes(),start = Date.now()
    const recovery = await startAccountRecovery(f.env,new Request("https://vault.test/api/auth/recovery"),codes[0]!,unavailable(),start)
    const now = await issue(start+1)
    await reconcileAccountBreakGlass(f.env,unavailable(),now)
    const effects = await f.env.DB.prepare("SELECT effects FROM account_security_transitions WHERE id=?").bind(recovery.transition).first<{ effects: string }>()
    expect((JSON.parse(effects!.effects) as { kind: string }[]).map(e => e.kind)).toEqual(["recovery.start","break-glass"])
    await reconcileAccountBreakGlass(f.env,successfulDirectoryClient(),now+1)
    await expectBarrierHeld(recovery.session.token,recovery.transition)
  })
})
