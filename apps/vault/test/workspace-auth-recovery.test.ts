import { expectDirectoryRefusal } from "./directory-test-support.ts"
import { beforeEach, describe, expect, it } from "vitest"
import { issueAccountRecoveryCodes,confirmAccountRecoveryCodes,startAccountRecovery,resolveAccountRecovery } from "../src/directory/workspace-recovery.ts"
import { currentAccountSession } from "../src/directory/account-session.ts"
import { accountSessionStatements,insertAccountPasskey } from "../src/directory/account-store.ts"
import { MAX_SESSIONS,newSession } from "../src/directory/session.ts"
import { reserveAccountSecurity,retryAccountSecurity } from "../src/directory/account-security.ts"
import { endOwnAccountSession } from "../src/directory/workspace-account-admin.ts"
import { createWorkspaceFixture,type WorkspaceTestFixture } from "./workspace-fixtures.ts"
import { successfulDirectoryClient } from "./directory-test-support.ts"
let f: WorkspaceTestFixture
beforeEach(async () => { f = await createWorkspaceFixture() })
async function actor() { const account = await currentAccountSession(new Request("https://vault.test",{ headers: { cookie: f.cookie } }),f.env); if (!account) throw new Error("Missing actor session"); return account }
async function setup() {
  const account = await currentAccountSession(new Request("https://vault.test",{ headers: { cookie: f.cookie } }),f.env)
  if (!account) throw new Error("Missing account")
  const codes = await issueAccountRecoveryCodes(f.env,account)
  await confirmAccountRecoveryCodes(f.env,account,codes.batch,codes.codes[codes.confirmPosition-1] as string)
  return codes
}
describe("workspace account recovery",() => {
  it("recovery merges into pending factor removal, keeps revocations and opens ceremony only after barrier",async () => {
    const codes = await setup(),client = successfulDirectoryClient()
    const id = await reserveAccountSecurity(f.env,f.account,{ effect: { kind: "factor.remove" },revokedSessionIds: ["ses_removed"],removedFactorIds: ["pk_removed"] })
    client.install = async () => { throw new Error("unavailable") }
    const recovery = await startAccountRecovery(f.env,new Request("https://vault.test/api/auth/recovery"),codes.codes[0] as string,client)
    expect(recovery).toMatchObject({ pending: true,transition: id })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions WHERE id=?").bind(recovery.session.id).first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT security_epoch,restricted_until FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ security_epoch: 0,restricted_until: null })
    const pending = await f.env.DB.prepare("SELECT reserved_epoch,revoked_sessions,removed_factors,target_restrictions FROM account_security_transitions WHERE id=?").bind(id).first<{ reserved_epoch: number; revoked_sessions: string; removed_factors: string; target_restrictions: string }>()
    expect(pending?.reserved_epoch).toBe(2)
    expect(JSON.parse(pending?.revoked_sessions ?? "[]")).toEqual([f.session,"ses_removed"].sort())
    expect(JSON.parse(pending?.removed_factors ?? "[]")).toEqual(["pk_removed"])
    await retryAccountSecurity(f.env,id,successfulDirectoryClient())
    expect(await f.env.DB.prepare("SELECT kind FROM web_sessions WHERE id=?").bind(recovery.session.id).first()).toEqual({ kind: "recovery" })
    expect(await currentAccountSession(new Request("https://vault.test",{ headers: { cookie: f.cookie } }),f.env)).toBeNull()
    const stored = JSON.stringify((await f.env.DB.prepare("SELECT * FROM account_security_transitions").all()).results)
    expect(stored).not.toContain(recovery.session.token)
    expect(stored).not.toContain(codes.codes[0])
    await expectDirectoryRefusal(startAccountRecovery(f.env,new Request("https://vault.test"),codes.codes[0] as string,successfulDirectoryClient()),{ error: "unauthenticated",message: "That code is not valid or was already used." })
  })
  it("only an older factor resolves recovery; keep is lazy and never changes the epoch",async () => {
    const now = Date.now(),notice = "ntc_test"
    await insertAccountPasskey(f.env,f.account,{ credentialId: "old",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },now-1000,"signup","pk_old").run()
    await insertAccountPasskey(f.env,f.account,{ credentialId: "new",publicKey: new Uint8Array([2]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },now+1,"recovery","pk_new").run()
    await f.env.DB.batch([f.env.DB.prepare("UPDATE accounts SET restricted_until=?,restricted_reason='recovery' WHERE id=?").bind(now+86400000,f.account),f.env.DB.prepare("INSERT INTO account_notices(id,account,kind,at,restricted_until) VALUES (?,?,'recovery',?,?)").bind(notice,f.account,now,now+86400000)])
    for (const factor of ["pk_new","pk_foreign"]) await expectDirectoryRefusal(resolveAccountRecovery(f.env,await actor(),factor,notice,"keep",successfulDirectoryClient()),{ error: "forbidden",message: "Only an older account passkey can resolve recovery." })
    expect(await f.env.DB.prepare("SELECT restricted_until FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ restricted_until: now+86400000 })
    expect(await resolveAccountRecovery(f.env,await actor(),"pk_old",notice,"keep",successfulDirectoryClient())).toEqual({ pending: false })
    expect(await f.env.DB.prepare("SELECT security_epoch,restricted_until FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ security_epoch: 0,restricted_until: null })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys").first()).toEqual({ n: 2 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_security_transitions").first()).toEqual({ n: 0 })
  })
})

describe("pending recovery timing and cancellation",() => {
  it("notifies at reservation and preserves a full 24 hours after a 30-hour barrier",async () => {
    const codes = await setup(),unavailable = successfulDirectoryClient(),now = Date.now()
    unavailable.install = async () => { throw new Error("unavailable") }
    const recovery = await startAccountRecovery(f.env,new Request("https://vault.test/api/auth/recovery"),codes.codes[0] as string,unavailable,now)
    const notice = await f.env.DB.prepare("SELECT at,restricted_until,payload FROM account_notices WHERE account=? AND kind='recovery'").bind(f.account).first<{ at: number; restricted_until: number | null; payload: string }>()
    expect(notice?.at).toBe(now)
    expect(notice?.restricted_until).toBeNull()
    expect(JSON.parse(notice?.payload ?? "{}")).toEqual({ pendingTransition: recovery.transition })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_events WHERE action='account.recovery'").first()).toEqual({ n: 1 })
    const restriction = await f.env.DB.prepare("SELECT target_restrictions FROM account_security_transitions WHERE id=?").bind(recovery.transition).first<{ target_restrictions: string }>()
    expect(JSON.parse(restriction?.target_restrictions ?? "{}").until).toBe((await import("@mehen/protocol")).PENDING_RESTRICTION_UNTIL)
    const committedAt = now+30*3600000
    await retryAccountSecurity(f.env,recovery.transition,successfulDirectoryClient(),committedAt)
    expect(await f.env.DB.prepare("SELECT restricted_until FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ restricted_until: committedAt+86400000 })
    expect(await f.env.DB.prepare("SELECT created_at,expires_at FROM web_sessions WHERE id=?").bind(recovery.session.id).first()).toEqual({ created_at: committedAt,expires_at: committedAt+900000 })
  })
  it("an older factor can cancel a pending recovery without ever minting its ceremony session",async () => {
    const codes = await setup(),unavailable = successfulDirectoryClient(),now = Date.now()
    await insertAccountPasskey(f.env,f.account,{ credentialId: "older",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },now-1000,"signup","pk_older").run()
    unavailable.install = async () => { throw new Error("unavailable") }
    const recovery = await startAccountRecovery(f.env,new Request("https://vault.test/api/auth/recovery"),codes.codes[0] as string,unavailable,now)
    const notice = await f.env.DB.prepare("SELECT id FROM account_notices WHERE account=? AND kind='recovery'").bind(f.account).first<{ id: string }>()
    if (!notice) throw new Error("Missing immediate notice")
    const session = await newSession()
    await f.env.DB.batch(accountSessionStatements(f.env,session,f.account,now+1,{ kind: "web",method: "passkey",passkey: "older",client: "Test",place: null }))
    const older = await currentAccountSession(new Request("https://vault.test",{ headers: { cookie: `__Host-mehen_session=${session.token}` } }),f.env,now+1)
    if (!older) throw new Error("Missing surviving older-factor session")
    await expectDirectoryRefusal(resolveAccountRecovery(f.env,older,"pk_older",notice.id,"keep",unavailable,now+1),{ error: "conflict",message: "Account state changed. Try again." })
    expect(await f.env.DB.prepare("SELECT outcome FROM account_notices WHERE id=?").bind(notice.id).first()).toEqual({ outcome: null })
    expect(await resolveAccountRecovery(f.env,older,"pk_older",notice.id,"cancel",unavailable,now+1)).toEqual({ pending: true })
    await expectDirectoryRefusal(startAccountRecovery(f.env,new Request("https://vault.test"),codes.codes[1] as string,unavailable,now+2),{ error: "unauthenticated",message: "That code is not valid or was already used." })
    await retryAccountSecurity(f.env,recovery.transition,successfulDirectoryClient(),now+3)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions WHERE id=?").bind(recovery.session.id).first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT security_epoch,security_transition,restricted_until FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ security_epoch: 2,security_transition: null,restricted_until: null })
    expect(await f.env.DB.prepare("SELECT outcome FROM account_notices WHERE id=?").bind(notice.id).first()).toEqual({ outcome: "cancel" })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM recovery_codes WHERE status='active'").first()).toEqual({ n: 0 })
  })
})

describe("account recovery network refusal budget",() => {
  it("counts one IPv6 /64 budget without storing addresses or changing account authority",async () => {
    const now = Date.now(),window = now-now%3600000
    for (let i=1;i<=5;i++) await expectDirectoryRefusal(startAccountRecovery(f.env,new Request("https://vault.test",{ headers: { "cf-connecting-ip": `2001:db8:abcd:1234::${i}` } }),"invalid",successfulDirectoryClient(),now),{ error: "unauthenticated",message: "That code is not valid or was already used." })
    await expectDirectoryRefusal(startAccountRecovery(f.env,new Request("https://vault.test",{ headers: { "cf-connecting-ip": "2001:db8:abcd:1234::6" } }),"invalid",successfulDirectoryClient(),now),{ error: "rate_limited",message: "Too many wrong recovery codes from this network. Wait until the next hour and try again.", retryAfter: Math.ceil((window+3600000-now)/1000) })
    const counters = (await f.env.DB.prepare("SELECT key,count FROM auth_attempts").all<{ key: string; count: number }>()).results
    expect(counters).toHaveLength(1)
    expect(counters[0]?.count).toBe(5)
    expect(JSON.stringify(counters)).not.toContain("2001:")
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_security_transitions").first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions").first()).toEqual({ n: 1 })
  })
})

describe("overlapping recovery cooling-off (reviewer stolen-sheet probe)",() => {
  async function overlapping() {
    const codes = await setup(),t0 = Date.now(),client = successfulDirectoryClient(),lifts: unknown[] = [],calls: unknown[] = []
    client.install = async (workspace,input) => { calls.push({ op: "install",workspace,input }); return { installedEpoch: input.committedEpoch } }
    client.commit = async (workspace,input) => { calls.push({ op: "commit",workspace,input }); return { installedEpoch: input.committedEpoch } }
    client.mirror = async (workspace,event) => { calls.push({ op: "mirror",workspace,event }) }
    client.restriction = async (workspace,input) => { lifts.push({ workspace,...input }); calls.push({ op: "restriction",workspace,input }) }
    await startAccountRecovery(f.env,new Request("https://vault.test/api/auth/recovery"),codes.codes[0] as string,client,t0)
    await insertAccountPasskey(f.env,f.account,{ credentialId: "attacker",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },t0+10,"recovery","pk_attacker").run()
    const t1 = t0+3600000
    await startAccountRecovery(f.env,new Request("https://vault.test/api/auth/recovery"),codes.codes[1] as string,client,t1)
    const { mirrorAccountEvents } = await import("../src/directory/account-events.ts")
    await mirrorAccountEvents(f.env,client)
    const notices = (await f.env.DB.prepare("SELECT id,at,restricted_until,resolved_at,outcome FROM account_notices WHERE account=? AND kind='recovery' ORDER BY at").bind(f.account).all<{ id: string; at: number; restricted_until: number; resolved_at: number | null; outcome: string | null }>()).results
    async function sessionFor(credential: string,at: number) {
      const session = await newSession()
      await f.env.DB.batch(accountSessionStatements(f.env,session,f.account,at,{ kind: "web",method: "passkey",passkey: credential,client: "Browser",place: null }))
      const account = await currentAccountSession(new Request("https://vault.test",{ headers: { cookie: `__Host-mehen_session=${session.token}` } }),f.env,at)
      if (!account) throw new Error("Missing surviving-factor session")
      return account
    }
    return { client,lifts,calls,t0,t1,notices,sessionFor }
  }
  for (const outcome of ["keep","cancel"] as const) it(`${outcome} cannot use a factor made after an older governing notice`,async () => {
    const p = await overlapping(),account = await p.sessionFor("attacker",p.t1+10)
    const before = await f.env.DB.prepare("SELECT * FROM accounts WHERE id=?").bind(f.account).first(),count = await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_security_transitions").first(),lifts = [...p.lifts],calls = [...p.calls]
    await expectDirectoryRefusal(resolveAccountRecovery(f.env,account,"pk_attacker",p.notices[1]!.id,outcome,p.client,p.t1+20),{ error: "forbidden",message: "Only an older account passkey can resolve recovery." })
    expect(await f.env.DB.prepare("SELECT * FROM accounts WHERE id=?").bind(f.account).first()).toEqual(before)
    expect(before).toMatchObject({ restricted_until: p.t1+86400000 })
    expect((await f.env.DB.prepare("SELECT id,at,restricted_until,resolved_at,outcome FROM account_notices WHERE account=? AND kind='recovery' ORDER BY at").bind(f.account).all()).results).toEqual(p.notices)
    expect(p.notices[0]).toMatchObject({ resolved_at: null,restricted_until: p.t0+86400000 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_security_transitions").first()).toEqual(count)
    const { mirrorAccountEvents } = await import("../src/directory/account-events.ts")
    await mirrorAccountEvents(f.env,p.client)
    expect(p.lifts).toEqual(lifts)
    expect(p.calls).toEqual(calls)
  })
  for (const outcome of ["keep","cancel"] as const) it(`${outcome} also respects an earlier pending break-glass notice`,async () => {
    const p = await overlapping(),account = await p.sessionFor("attacker",p.t1+10)
    await f.env.DB.prepare("UPDATE account_notices SET kind='break-glass',restricted_until=NULL WHERE id=?").bind(p.notices[0]!.id).run()
    const before = (await f.env.DB.prepare("SELECT * FROM account_notices ORDER BY id").all()).results,calls = [...p.calls]
    await expectDirectoryRefusal(resolveAccountRecovery(f.env,account,"pk_attacker",p.notices[1]!.id,outcome,p.client,p.t1+20),{ error: "forbidden",message: "Only an older account passkey can resolve recovery." })
    expect((await f.env.DB.prepare("SELECT * FROM account_notices ORDER BY id").all()).results).toEqual(before)
    expect(p.calls).toEqual(calls)
  })
  it("keep repeats the age guard in the transaction and preserves the exact refusal on a raced notice",async () => {
    const p = await overlapping()
    await insertAccountPasskey(f.env,f.account,{ credentialId: "owner-race",publicKey: new Uint8Array([2]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },p.t0-1000,"signup","pk_owner_race").run()
    const account = await p.sessionFor("owner-race",p.t1+10),before = await f.env.DB.prepare("SELECT * FROM accounts WHERE id=?").bind(f.account).first(),calls = [...p.calls]
    let injected = false
    const db = new Proxy(f.env.DB,{ get(target,key) {
      if (key === "batch") return async (statements: D1PreparedStatement[]) => {
        if (!injected) { injected = true; await target.prepare("INSERT INTO account_notices(id,account,kind,at,restricted_until) VALUES ('ntc_raced',?,'break-glass',?,NULL)").bind(f.account,p.t0-2000).run() }
        return target.batch(statements)
      }
      const value = Reflect.get(target,key)
      return typeof value === "function" ? value.bind(target) : value
    } })
    await expectDirectoryRefusal(resolveAccountRecovery({ ...f.env,DB: db },account,"pk_owner_race",p.notices[1]!.id,"keep",p.client,p.t1+20),{ error: "forbidden",message: "Only an older account passkey can resolve recovery." })
    expect(injected).toBe(true)
    expect(await f.env.DB.prepare("SELECT * FROM accounts WHERE id=?").bind(f.account).first()).toEqual(before)
    expect(await f.env.DB.prepare("SELECT resolved_at FROM account_notices WHERE id=?").bind(p.notices[1]!.id).first()).toEqual({ resolved_at: null })
    expect(p.calls).toEqual(calls)
  })
  it("the recovered factor may cancel the newer notice once the older cooling-off expires",async () => {
    const p = await overlapping(),now = p.t0+86400001,account = await p.sessionFor("attacker",now)
    expect(await resolveAccountRecovery(f.env,account,"pk_attacker",p.notices[1]!.id,"cancel",p.client,now)).toEqual({ pending: false })
    expect(await f.env.DB.prepare("SELECT restricted_until FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ restricted_until: null })
    expect(await f.env.DB.prepare("SELECT resolved_at FROM account_notices WHERE id=?").bind(p.notices[0]!.id).first()).toEqual({ resolved_at: null })
  })
  for (const outcome of ["keep","cancel"] as const) it(`${outcome} by the original owner preserves the strictest remaining notice`,async () => {
    const p = await overlapping()
    await insertAccountPasskey(f.env,f.account,{ credentialId: "owner",publicKey: new Uint8Array([2]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },p.t0-1000,"signup","pk_owner").run()
    const account = await p.sessionFor("owner",p.t1+10)
    expect(await resolveAccountRecovery(f.env,account,"pk_owner",p.notices[1]!.id,outcome,p.client,p.t1+20)).toEqual({ pending: false })
    expect(await f.env.DB.prepare("SELECT restricted_until FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ restricted_until: p.t0+86400000 })
  })
})

describe("ending other sign-ins during a recovery",() => {
  it("a recovered sign-in may end another only once the cooling-off has finished",async () => {
    const codes = await setup(),t0 = Date.now()
    await insertAccountPasskey(f.env,f.account,{ credentialId: "older",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },t0-1000,"signup","pk_older").run()
    expect((await startAccountRecovery(f.env,new Request("https://vault.test/api/auth/recovery"),codes.codes[0] as string,successfulDirectoryClient(),t0)).pending).toBe(false)
    await insertAccountPasskey(f.env,f.account,{ credentialId: "recovered",publicKey: new Uint8Array([2]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },t0+10,"recovery","pk_recovered").run()
    async function sessionFor(credential: string,at: number) {
      const session = await newSession()
      await f.env.DB.batch(accountSessionStatements(f.env,session,f.account,at,{ kind: "web",method: "passkey",passkey: credential,client: "Browser",place: null }))
      const account = await currentAccountSession(new Request("https://vault.test",{ headers: { cookie: `__Host-mehen_session=${session.token}` } }),f.env,at)
      if (!account) throw new Error("Missing session")
      return account
    }
    const recovered = await sessionFor("recovered",t0+20),owner = await sessionFor("older",t0+30)
    await expectDirectoryRefusal(endOwnAccountSession(f.env,recovered,owner.session,t0+40),{ error: "forbidden",message: "During a recovery, only a sign-in with a passkey from before it can end other sign-ins. Cancelling the recovery ends the new ones." })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions WHERE id=?").bind(owner.session).first()).toEqual({ n: 1 })
    await endOwnAccountSession(f.env,recovered,owner.session,t0+86400001)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions WHERE id=?").bind(owner.session).first()).toEqual({ n: 0 })
  })
  it("the batch repeats the check, so a recovery notice that lands after the first check ends nothing",async () => {
    const t0 = Date.now()
    await insertAccountPasskey(f.env,f.account,{ credentialId: "recovered",publicKey: new Uint8Array([2]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },t0+10,"recovery","pk_recovered").run()
    const sessions: Awaited<ReturnType<typeof newSession>>[] = []
    for (const at of [t0+20,t0+30]) {
      const session = await newSession()
      await f.env.DB.batch(accountSessionStatements(f.env,session,f.account,at,{ kind: "web",method: "passkey",passkey: "recovered",client: "Browser",place: null }))
      sessions.push(session)
    }
    const actor = await currentAccountSession(new Request("https://vault.test",{ headers: { cookie: `__Host-mehen_session=${sessions[1]!.token}` } }),f.env,t0+30)
    if (!actor) throw new Error("Missing session")
    let injected = false
    const db = new Proxy(f.env.DB,{ get(target,key) {
      if (key === "batch") return async (statements: D1PreparedStatement[]) => {
        if (!injected) { injected = true; await target.prepare("INSERT INTO account_notices(id,account,kind,at,restricted_until) VALUES ('ntc_raced',?,'recovery',?,?)").bind(f.account,t0,t0+86400000).run() }
        return target.batch(statements)
      }
      const value = Reflect.get(target,key)
      return typeof value === "function" ? value.bind(target) : value
    } })
    await expectDirectoryRefusal(endOwnAccountSession({ ...f.env,DB: db },actor,sessions[0]!.id,t0+40),{ error: "conflict",message: "Account state changed. Try again." })
    expect(injected).toBe(true)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions WHERE id=?").bind(sessions[0]!.id).first()).toEqual({ n: 1 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_events WHERE action='account.signout'").first()).toEqual({ n: 0 })
  })
  for (const recovery of [true,false]) it(recovery ? "the session cap keeps the older passkey's sign-in and drops the oldest recovered one" : "without a recovery the session cap drops the oldest sign-in",async () => {
    const codes = await setup(),t0 = Date.now()
    await insertAccountPasskey(f.env,f.account,{ credentialId: "older",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },t0-1000,"signup","pk_older").run()
    if (recovery) expect((await startAccountRecovery(f.env,new Request("https://vault.test/api/auth/recovery"),codes.codes[0] as string,successfulDirectoryClient(),t0)).pending).toBe(false)
    await insertAccountPasskey(f.env,f.account,{ credentialId: "recovered",publicKey: new Uint8Array([2]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },t0+10,"recovery","pk_recovered").run()
    async function signIn(credential: string,at: number) {
      const session = await newSession()
      await f.env.DB.batch(accountSessionStatements(f.env,session,f.account,at,{ kind: "web",method: "passkey",passkey: credential,client: "Browser",place: null }))
      return session.id
    }
    const owner = await signIn("older",t0+20),recovered: string[] = []
    for (let i=0;i<MAX_SESSIONS;i++) recovered.push(await signIn("recovered",t0+30+i))
    const live = (await f.env.DB.prepare("SELECT id FROM web_sessions WHERE account=? AND kind IN ('web','app')").bind(f.account).all<{ id: string }>()).results.map(row => row.id)
    expect(live).toHaveLength(MAX_SESSIONS)
    expect(live.includes(owner)).toBe(recovery)
    expect(live.includes(recovered[0]!)).toBe(!recovery)
    expect(recovered.slice(1).every(id => live.includes(id))).toBe(true)
  })
})

describe("recovery retains its ceremony response after reservation",() => {
  it("a final D1 batch failure returns the token and a later retry mints that same ceremony",async () => {
    const codes = await setup(),client = successfulDirectoryClient(),mirrored: string[] = []
    client.mirror = async (_workspace,event) => { mirrored.push(event.id) }
    await f.env.DB.prepare("INSERT INTO account_events(id,account,at,action,detail,targets) VALUES ('evt_other_account','acc_guest',0,'account.signin','{}',?)").bind(JSON.stringify([f.workspaces.work])).run()
    await f.env.DB.prepare("CREATE TRIGGER reject_recovery_commit BEFORE INSERT ON account_events WHEN NEW.action='account.security' BEGIN SELECT RAISE(ABORT,'injected recovery commit failure'); END").run()
    const result = await startAccountRecovery(f.env,new Request("https://vault.test/api/auth/recovery"),codes.codes[0]!,client)
    expect(result.pending).toBe(true)
    expect(result.session.token).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(mirrored).not.toContain("evt_other_account")
    expect(await f.env.DB.prepare("SELECT id FROM web_sessions WHERE id=?").bind(result.session.id).first()).toBeNull()
    await f.env.DB.prepare("DROP TRIGGER reject_recovery_commit").run()
    await retryAccountSecurity(f.env,result.transition,client)
    expect(await f.env.DB.prepare("SELECT token_hash FROM web_sessions WHERE id=?").bind(result.session.id).first()).toEqual({ token_hash: result.session.tokenHash })
  })
})
