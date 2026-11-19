import { expectDirectoryRefusal } from "./directory-test-support.ts"
import { beginAccessSideEffectChecks,finishAccessSideEffectChecks,inAccess,seedAccessStateForTests } from "./access-test-support.ts"
import { directoryRuntimeFixture } from "./directory-runtime-fixture.ts"
import { directoryWorkspaceClient } from "../src/directory/workspace-client.ts"
import { workspaceCall } from "../src/routes/context.ts"
import { freshTenant } from "./helpers.ts"
import { setSetting } from "../src/vault/areas/workspace-runtime.ts"
import { workspaceAccessState } from "./workspace-fixtures.ts"
import { afterEach,beforeEach, describe, expect, it, vi } from "vitest"
import { accountBatch, accountEvent } from "../src/directory/account-store.ts"
import { deliverWorkspaceNotice, drainWorkspaceNotices, writeWorkspaceNotices, mirrorAccountEvents, ownAccountEvents, ownAccountNotices } from "../src/directory/account-events.ts"
import { currentAccountSession } from "../src/directory/account-session.ts"
import type { DirectoryWorkspaceClient } from "../src/directory/workspace-client.ts"
import { createWorkspaceFixture, type WorkspaceTestFixture } from "./workspace-fixtures.ts"
import { REDELIVERY_MARGIN_MS } from "../src/directory/account-security.ts"
import { restoreIntentDigest,runVaultRestores,type VaultBackupClient } from "../src/directory/vault-backups.ts"
let f: WorkspaceTestFixture
beforeEach(async () => { beginAccessSideEffectChecks(); f = await createWorkspaceFixture() })
function client(seen: Set<string>,calls: string[]): DirectoryWorkspaceClient {
  return { async install(_w,i) { return { installedEpoch: i.committedEpoch } },async commit(_w,i) { return { installedEpoch: i.committedEpoch } },async restriction() {},async revokeSession() {},async mirror(workspace,event) { calls.push(workspace); seen.add(`${workspace}:${event.id}`) } }
}
describe("directory account event outbox",() => {
  it("snapshots targets in the event transaction, retains leavers and excludes later joiners",async () => {
    await f.env.DB.prepare("UPDATE memberships SET state='left' WHERE account=? AND workspace=?").bind(f.account,f.workspaces.work).run()
    await accountBatch(f.env,[accountEvent(f.env,f.account,"account.signin",{ method: "passkey" },Date.now(),"evt_test")])
    await f.env.DB.prepare("UPDATE memberships SET state=CASE workspace WHEN ? THEN 'left' ELSE 'member' END WHERE account=?").bind(f.workspaces.personal,f.account).run()
    const seen = new Set<string>(),calls: string[] = []
    await mirrorAccountEvents(f.env,client(seen,calls))
    expect(calls).toEqual([f.workspaces.personal])
    expect(seen.size).toBe(1)
    await mirrorAccountEvents(f.env,client(seen,calls))
    expect(calls).toHaveLength(1)
  })
  it("retains unavailable mirrors durably and retries idempotently",async () => {
    await accountBatch(f.env,[accountEvent(f.env,f.account,"account.passkey_add",{ passkey: "pk_test" },Date.now(),"evt_test")])
    const seen = new Set<string>(),calls: string[] = [],c = client(seen,calls)
    c.mirror = async workspace => { if (workspace === f.workspaces.work) throw new Error("unavailable"); seen.add(`${workspace}:evt_test`) }
    await mirrorAccountEvents(f.env,c)
    expect(await f.env.DB.prepare("SELECT mirrored_to FROM account_events WHERE id='evt_test'").first()).toEqual({ mirrored_to: JSON.stringify([f.workspaces.personal]) })
    await mirrorAccountEvents(f.env,client(seen,calls),Date.now()+60001)
    expect(calls).toEqual([f.workspaces.work])
    expect(seen.size).toBe(2)
    expect(await ownAccountEvents(f.env,"acc_guest")).toEqual([])
  })
  it("an event failure rolls back the same-batch account change",async () => {
    await f.env.DB.prepare("CREATE TRIGGER reject_event BEFORE INSERT ON account_events BEGIN SELECT RAISE(ABORT,'audit failure'); END").run()
    await expect(accountBatch(f.env,[f.env.DB.prepare("UPDATE accounts SET name='Changed' WHERE id=?").bind(f.account),accountEvent(f.env,f.account,"account.rename",{},Date.now())])).rejects.toThrow("audit failure")
    expect(await f.env.DB.prepare("SELECT name FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ name: "owner" })
    await f.env.DB.prepare("DROP TRIGGER reject_event").run()
  })
  it("delivers to source recipient snapshots once, including removed accounts, never colleagues",async () => {
    const notice = { id: "notice_one",workspace: f.workspaces.work,recipients: [f.account,"acc_admin"],payload: { kind: "owner_changed" as const,workspace: { id: f.workspaces.work,slug: "northwind",name: "Work" },member: "mem_owner",name: "Owner",change: "removed" as const,by: "mem_admin",at: new Date().toISOString() } }
    await f.env.DB.prepare("UPDATE memberships SET state='left' WHERE account=?").bind(f.account).run()
    await deliverWorkspaceNotice(f.env,notice)
    await deliverWorkspaceNotice(f.env,notice)
    expect(await ownAccountNotices(f.env,f.account)).toHaveLength(1)
    expect(await ownAccountNotices(f.env,"acc_admin")).toHaveLength(1)
    expect(await ownAccountNotices(f.env,"acc_member")).toEqual([])
    expect(await ownAccountNotices(f.env,"acc_guest")).toEqual([])
  })
  it("refuses a foreign workspace notice and invalid payload without writing anything",async () => {
    const notice = { id: "notice_bad",workspace: f.workspaces.personal,recipients: [f.account],payload: { kind: "deletion_scheduled" as const,workspace: { id: f.workspaces.work,slug: "northwind",name: "Work" },by: "mem_owner",at: new Date().toISOString(),deleteAfter: new Date().toISOString() } }
    await expect(deliverWorkspaceNotice(f.env,notice)).rejects.toThrow("Notice workspace mismatch")
    expect(await ownAccountNotices(f.env,f.account)).toEqual([])
  })
  it("alarm and cron use one idempotent writer for the same source event",async () => {
    const payload = { kind: "machine_added" as const,workspace: { id: f.workspaces.work,slug: "northwind",name: "Work" },device: "dev_new",name: "Laptop",owner: { kind: "member" as const,member: "mem_member",name: "Member" },place: null,at: new Date().toISOString() }
    const event = { id: "source_event",account: f.account,payload,at: Date.now(),url: `${f.env.VAULT_ORIGIN}/w/northwind/devices/dev_new` }
    expect(await writeWorkspaceNotices(f.env,[event])).toEqual([event.id])
    const acks: string[] = []
    await drainWorkspaceNotices(f.env,{ async drain(workspace) { return { events: workspace === f.workspaces.work ? [event] : [] } },async ack(_workspace,ids) { acks.push(...ids) } })
    expect(acks).toEqual([event.id])
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_notices WHERE account=?").bind(f.account).first()).toEqual({ n: 1 })
  })
  it("drops a notice whose recipient account no longer exists, logging that once at info without the account",async () => {
    const payload = { kind: "machine_added" as const,workspace: { id: f.workspaces.work,slug: "northwind",name: "Work" },device: "dev_new",name: "Laptop",owner: { kind: "member" as const,member: "mem_member",name: "Member" },place: null,at: new Date().toISOString() }
    const gone = { id: "notice_gone",account: "acc_gone",payload,at: Date.now(),url: `${f.env.VAULT_ORIGIN}/w/northwind/devices/dev_new` }
    const deleted = { ...gone,id: "notice_deleted",account: "acc_guest" }
    await f.env.DB.prepare("UPDATE accounts SET status='deleted',deleted_at=? WHERE id='acc_guest'").bind(Date.now()).run()
    const info = vi.spyOn(console,"info").mockImplementation(() => undefined),error = vi.spyOn(console,"error").mockImplementation(() => undefined)
    try {
      expect(await writeWorkspaceNotices(f.env,[gone,deleted])).toEqual([gone.id,deleted.id])
      expect(info.mock.calls).toEqual([[JSON.stringify({ at: "workspace.notice.recipient_gone",notice: gone.id })],[JSON.stringify({ at: "workspace.notice.recipient_gone",notice: deleted.id })]])
      expect(error).not.toHaveBeenCalled()
    } finally { info.mockRestore(); error.mockRestore() }
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_notices WHERE account IN ('acc_gone','acc_guest')").first()).toEqual({ n: 0 })
  })
  it("documents the trusted D1 writer boundary with an offline forged session",async () => {
    // Deliberately privileged fixture SQL, not an internet-facing capability.
    await f.env.DB.prepare("UPDATE web_sessions SET account='acc_guest' WHERE id=?").bind(f.session).run()
    const session = await currentAccountSession(new Request("https://app.mehen.dev/api/account",{ headers: { cookie: f.cookie } }),f.env)
    expect(session?.account).toBe("acc_guest")
  })
})

afterEach(() => finishAccessSideEffectChecks())
describe("actual DO account-event delivery",() => {
  it("mirrors a snapshotted event after the member leaves without restoring rights",async () => {
    const live = await directoryRuntimeFixture(),event = { id: "evt_leaver",account: "acc_member",at: Date.now(),action: "account.signin",detail: { client: "Browser",place: null } }
    await live.env.DB.prepare("UPDATE memberships SET state='left' WHERE account=? AND workspace=?").bind(event.account,live.workspaces.personal).run()
    await live.env.DB.batch([accountEvent(live.env,event.account,event.action,event.detail,event.at,event.id)])
    await workspaceCall(live.context(""),live.workspace,"access.members.remove",{ member: "mem_member" },{ action: { type: "member.remove",member: "mem_member" },factor: "pk_test" })
    await live.env.DB.prepare("UPDATE memberships SET state='left' WHERE account=? AND workspace=?").bind(event.account,live.tenant).run()
    await mirrorAccountEvents(live.env)
    await directoryWorkspaceClient(live.env).mirror(live.tenant,event)
    await inAccess(live.tenant,ctx => {
      expect(ctx.sql.exec("SELECT target FROM audit WHERE action='account.signin'").toArray()).toEqual([{ target: "mem_member" }])
      expect(ctx.sql.exec("SELECT status FROM members WHERE id='mem_member'").toArray()).toEqual([{ status: "removed" }])
    })
    expect(await live.env.DB.prepare("SELECT mirrored_to FROM account_events WHERE id=?").bind(event.id).first()).toEqual({ mirrored_to: JSON.stringify([live.tenant]) })
    await expectDirectoryRefusal(directoryWorkspaceClient(live.env).membership(live.tenant,event.account),{ error: "not_found",message: "No such membership." })
  })
  it("notifies only each workspace's active owners/admins, including where the subject is a guest",async () => {
    const live = await directoryRuntimeFixture(),second = freshTenant(),state = workspaceAccessState()
    state.members = state.members.map(member => ({ ...member,id: `mem_second_${member.id.slice(4)}`,standing: { ...member.standing,effectiveRole: member.account === "acc_member" ? "guest" : member.standing.effectiveRole } }))
    state.teams = []; state.shares = []; state.devices = []; state.projects = []; state.credentials = []
    await inAccess(second,ctx => { setSetting(ctx,"workspace",{ id: second,slug: "client-work",name: "Client" }); seedAccessStateForTests(ctx,state) })
    await live.env.DB.batch([
      live.env.DB.prepare("INSERT INTO workspaces(id,slug,name,status,created_by,created_at) VALUES (?,'client-work','Client','active',?,?)").bind(second,live.account,Date.now()),
      ...state.members.map(member => live.env.DB.prepare("INSERT INTO memberships(id,account,workspace,state,role_hint,updated_at) VALUES (?,?,?,'member',?,?)").bind(member.id,member.account,second,member.standing.effectiveRole,Date.now())),
    ])
    const event = { id: "evt_recovery",account: "acc_member",at: Date.now(),action: "account.recovery",detail: { client: "Browser",place: "Amsterdam, NL",restrictedUntil: null } }
    await live.env.DB.batch([accountEvent(live.env,event.account,event.action,event.detail,event.at,event.id)])
    await mirrorAccountEvents(live.env)
    await drainWorkspaceNotices(live.env)
    for (const account of ["acc_owner","acc_admin"]) {
      const notices = await live.env.DB.prepare("SELECT source_workspace,payload FROM account_notices WHERE account=? AND kind='workspace' ORDER BY source_workspace").bind(account).all<{ source_workspace: string; payload: string }>()
      expect(notices.results.map(notice => notice.source_workspace)).toEqual([live.tenant,second].sort())
      for (const notice of notices.results) expect(JSON.parse(notice.payload)).toMatchObject({ kind: "account_security",account: event.account,event: "recovery",client: "Browser",restrictedUntil: null })
    }
    expect(await ownAccountNotices(live.env,"acc_guest")).toEqual([])
    expect(await ownAccountNotices(live.env,"acc_member")).toEqual([])
    const client = directoryWorkspaceClient(live.env)
    await client.mirror(live.tenant,event); await client.mirror(second,event); await drainWorkspaceNotices(live.env)
    expect(await live.env.DB.prepare("SELECT COUNT(*) AS n FROM account_notices WHERE kind='workspace'").first()).toEqual({ n: 4 })
  })
  it("tells each workspace's active owners and admins that an operator suspended a member's account, never the account itself",async () => {
    const live = await directoryRuntimeFixture()
    const event = { id: "evt_suspend",account: "acc_member",at: Date.now(),action: "account.suspend",detail: { by: "operator:acc_x" } }
    await live.env.DB.batch([accountEvent(live.env,event.account,event.action,event.detail,event.at,event.id)])
    await mirrorAccountEvents(live.env)
    await drainWorkspaceNotices(live.env)
    for (const account of ["acc_owner","acc_admin"]) {
      const notices = await live.env.DB.prepare("SELECT payload FROM account_notices WHERE account=? AND kind='workspace'").bind(account).all<{ payload: string }>()
      expect(notices.results.map(notice => JSON.parse(notice.payload))).toEqual([expect.objectContaining({ kind: "account_suspended",account: "acc_member",name: expect.any(String),at: new Date(event.at).toISOString() })])
    }
    expect(await ownAccountNotices(live.env,"acc_member")).toEqual([])
    expect(await ownAccountNotices(live.env,"acc_guest")).toEqual([])
  })
})

describe("account-event retry fairness",() => {
  it("101 unavailable events cannot starve a new healthy event on the next pass",async () => {
    const now = Date.now(),calls: string[] = [],c = client(new Set(),[])
    c.mirror = async (workspace,event) => { if (workspace === f.workspaces.work) throw new Error("unavailable"); calls.push(event.id) }
    await f.env.DB.batch(Array.from({ length: 101 },(_,i) => f.env.DB.prepare("INSERT INTO account_events(id,account,at,action,detail,targets) VALUES (?,?,?,'account.signin','{}',?)").bind(`evt_stuck_${String(i).padStart(3,"0")}`,f.account,now-1000,JSON.stringify([f.workspaces.work]))))
    await f.env.DB.prepare("INSERT INTO account_events(id,account,at,action,detail,targets) VALUES ('evt_healthy',?,?,'account.signin','{}',?)").bind(f.account,now,JSON.stringify([f.workspaces.personal])).run()
    await mirrorAccountEvents(f.env,c,now)
    expect(calls).toEqual([])
    await mirrorAccountEvents(f.env,c,now+1)
    expect(calls).toEqual(["evt_healthy"])
    expect(await f.env.DB.prepare("SELECT attempts,next_retry_at FROM account_events WHERE id='evt_stuck_000'").first()).toEqual({ attempts: 1,next_retry_at: now+60000 })
  })
})

// A restore loses only what was delivered after its point: a year of older
// sign-outs and transitions committed before it are still in the restored
// object, so the cron delivers them no second time.
describe("a restored workspace's redelivery",() => {
  it("forgets only deliveries from the margin before the restore point on, and every pending transition",async () => {
    const now = Date.now(),target = now-3_600_000,since = target-REDELIVERY_MARGIN_MS,work = f.workspaces.work
    const signout = (id: string,at: number) => f.env.DB.prepare("INSERT INTO account_events(id,account,at,action,detail,targets,mirrored_to) VALUES (?,?,?,'account.signout',?,?,?)").bind(id,f.account,at,JSON.stringify({ session: `ses_${id}` }),JSON.stringify([work]),JSON.stringify([work]))
    const transition = (id: string,state: "pending" | "committed",at: number) => f.env.DB.prepare(`INSERT INTO account_security_transitions(id,account,reserved_epoch,kind,target_restrictions,revoked_sessions,removed_factors,targets,acknowledged,state,created_at,updated_at,committed_at,commit_delivery,next_retry_at)
      VALUES (?,?,1,'sessions.end','null','[]','[]',?,?,?,?,?,?,?,?)`).bind(id,f.account,JSON.stringify([{ workspace: work,membership: "mem_test",state: "member" }]),JSON.stringify([{ workspace: work,reservedEpoch: 1,at }]),state,at,at,state === "committed" ? at : null,state === "committed" ? JSON.stringify([work]) : "[]",at+60_000)
    await f.env.DB.batch([
      ...Array.from({ length: 365 },(_,day) => signout(`evt_old_${String(day).padStart(3,"0")}`,since-1-day*86_400_000)),
      signout("evt_margin",since),
      signout("evt_after",target+60_000),
      transition("trn_old","committed",since-1),
      transition("trn_after","committed",target+60_000),
      transition("trn_pending","pending",since-30*86_400_000),
    ])
    const fields = { id: `vri_${"b".repeat(32)}`,tenant: work,source: "pitr" as const,target: new Date(target).toISOString(),actor: "operator:test",createdAt: now-60_000 }
    await f.env.DB.prepare("INSERT INTO vault_restore_intents(id,tenant,source,target,actor,intent_hash,created_at,expires_at,state,bookmark,undo_bookmark) VALUES (?,?,?,?,?,?,?,?,'restarting','bm','bm-undo')")
      .bind(fields.id,fields.tenant,fields.source,fields.target,fields.actor,await restoreIntentDigest(fields),fields.createdAt,fields.createdAt+3_600_000).run()
    const restores: VaultBackupClient = { async dump() { throw new Error("no dump here") },async restore() { throw new Error("no restore here") },async restart() {},async restored() {} }
    await runVaultRestores(f.env,restores,now)
    expect(await f.env.DB.prepare("SELECT state FROM vault_restore_intents WHERE id=?").bind(fields.id).first()).toEqual({ state: "done" })
    const revoked: string[] = [],c = client(new Set(),[])
    c.revokeSession = async (_workspace,input) => { revoked.push(input.session) }
    await mirrorAccountEvents(f.env,c,now)
    expect(revoked.sort()).toEqual(["ses_evt_after","ses_evt_margin"])
    expect((await f.env.DB.prepare("SELECT id,commit_delivery,next_retry_at FROM account_security_transitions ORDER BY id").all()).results).toEqual([
      { id: "trn_after",commit_delivery: "[]",next_retry_at: null },
      { id: "trn_old",commit_delivery: JSON.stringify([work]),next_retry_at: since+59_999 },
      { id: "trn_pending",commit_delivery: "[]",next_retry_at: null },
    ])
    expect(await f.env.DB.prepare("SELECT acknowledged FROM account_security_transitions WHERE id='trn_pending'").first()).toEqual({ acknowledged: "[]" })
  })
})

describe("committed restriction delivery through real DOs",() => {
  async function recoveryFixture() {
    const live = await directoryRuntimeFixture(),other = freshTenant(),state = workspaceAccessState()
    state.members = [{ ...state.members[0]!,id: "mem_other" }]; state.teams = []; state.shares = []; state.devices = []; state.projects = []; state.credentials = []
    await inAccess(other,ctx => { setSetting(ctx,"workspace",{ id: other,slug: "other",name: "Other" }); seedAccessStateForTests(ctx,state) })
    await live.env.DB.batch([
      live.env.DB.prepare("INSERT INTO workspaces(id,slug,name,status,created_by,created_at) VALUES (?,'other','Other','active',?,?)").bind(other,live.account,Date.now()),
      live.env.DB.prepare("UPDATE memberships SET workspace=? WHERE account=? AND workspace=?").bind(other,live.account,live.workspaces.personal),
    ])
    const real = directoryWorkspaceClient(live.env),calls: { op: string; workspace: string; epoch: number; until: number | null; pending: string | null }[] = []
    let unavailable = true
    const recording: DirectoryWorkspaceClient = { ...real,
      async install(workspace,input) { const result = await real.install(workspace,input); calls.push({ op: "install",workspace,epoch: input.committedEpoch,until: input.pending?.restriction?.until ?? null,pending: input.pending?.transitionId ?? null }); if (unavailable) throw new Error("lost install acknowledgement"); return result },
      async commit(workspace,input) { calls.push({ op: "commit",workspace,epoch: input.committedEpoch,until: null,pending: null }); return real.commit(workspace,input) },
      async restriction(workspace,input) { const account = await live.env.DB.prepare("SELECT security_transition FROM accounts WHERE id=?").bind(live.account).first<{ security_transition: string | null }>(); calls.push({ op: "restriction",workspace,epoch: input.committedEpoch,until: input.restriction?.until ?? null,pending: account?.security_transition ?? null }); await real.restriction(workspace,input) },
    }
    const { issueAccountRecoveryCodes,confirmAccountRecoveryCodes,startAccountRecovery } = await import("../src/directory/workspace-recovery.ts")
    const codes = await issueAccountRecoveryCodes(live.env,live.workspace.account)
    await confirmAccountRecoveryCodes(live.env,live.workspace.account,codes.batch,codes.codes[codes.confirmPosition-1]!)
    const now = Date.now(),recovery = await startAccountRecovery(live.env,new Request(live.env.VAULT_ORIGIN),codes.codes[0]!,recording,now)
    const targets = [live.tenant,other]
    const { security } = await import("../src/vault/areas/workspace-runtime.ts")
    async function restrictions() { return Promise.all(targets.map(workspace => inAccess(workspace,ctx => security(ctx,live.account)))) }
    return { live,real,recording,calls,recovery,targets,now,restrictions,available(value: boolean) { unavailable = !value } }
  }
  async function oldActor(p: Awaited<ReturnType<typeof recoveryFixture>>,at: number) {
    const { newSession } = await import("../src/directory/session.ts"),{ accountSessionStatements } = await import("../src/directory/account-store.ts"),session = await newSession()
    await p.live.env.DB.batch(accountSessionStatements(p.live.env,session,p.live.account,at,{ kind: "web",method: "passkey",passkey: "credential",client: "Browser",place: null }))
    const actor = await currentAccountSession(new Request(p.live.env.VAULT_ORIGIN,{ headers: { cookie: `__Host-mehen_session=${session.token}` } }),p.live.env,at)
    if (!actor) throw new Error("Missing older-factor actor")
    return actor
  }
  for (const outcome of ["keep","cancel"] as const) it(`${outcome} lifts each real DO only after the corresponding D1 commit`,async () => {
    const p = await recoveryFixture(),{ PENDING_RESTRICTION_UNTIL } = await import("@mehen/protocol"),{ retryAccountSecurity } = await import("../src/directory/account-security.ts"),{ resolveAccountRecovery } = await import("../src/directory/workspace-recovery.ts")
    expect(p.recovery.pending).toBe(true)
    await mirrorAccountEvents(p.live.env,p.recording,p.now)
    expect(p.calls.filter(call => call.op === "restriction")).toEqual([])
    for (const state of await p.restrictions()) expect(state?.restriction?.until).toBe(PENDING_RESTRICTION_UNTIL)
    p.available(true)
    const committedAt = p.now+5000
    await retryAccountSecurity(p.live.env,p.recovery.transition,p.recording,committedAt)
    await mirrorAccountEvents(p.live.env,p.recording,committedAt)
    expect(p.calls.filter(call => call.op === "restriction").map(call => ({ workspace: call.workspace,epoch: call.epoch,until: call.until,pending: call.pending })).sort((a,b) => a.workspace.localeCompare(b.workspace))).toEqual(p.targets.map(workspace => ({ workspace,epoch: 1,until: committedAt+86400000,pending: null })).sort((a,b) => a.workspace.localeCompare(b.workspace)))
    for (const workspace of p.targets) expect(p.calls.findIndex(call => call.op === "commit" && call.workspace === workspace)).toBeLessThan(p.calls.findIndex(call => call.op === "restriction" && call.workspace === workspace))
    for (const state of await p.restrictions()) expect(state?.restriction?.until).toBe(committedAt+86400000)
    const notice = await p.live.env.DB.prepare("SELECT id FROM account_notices WHERE account=? AND kind='recovery'").bind(p.live.account).first<{ id: string }>(),actor = await oldActor(p,committedAt+1)
    if (!notice) throw new Error("Missing recovery notice")
    const liftCount = p.calls.filter(call => call.op === "restriction").length
    if (outcome === "cancel") p.available(false)
    expect(await resolveAccountRecovery(p.live.env,actor,"pk_test",notice.id,outcome,p.recording,committedAt+2)).toEqual({ pending: outcome === "cancel" })
    expect(p.calls.filter(call => call.op === "restriction")).toHaveLength(liftCount)
    if (outcome === "cancel") {
      const row = await p.live.env.DB.prepare("SELECT security_transition FROM accounts WHERE id=?").bind(p.live.account).first<{ security_transition: string }>()
      await mirrorAccountEvents(p.live.env,p.recording,committedAt+2)
      expect(p.calls.filter(call => call.op === "restriction")).toHaveLength(liftCount)
      p.available(true); await retryAccountSecurity(p.live.env,row!.security_transition,p.recording,committedAt+3)
    }
    await mirrorAccountEvents(p.live.env,p.recording,committedAt+4)
    expect(p.calls.filter(call => call.op === "restriction").slice(liftCount).map(call => ({ epoch: call.epoch,until: call.until,pending: call.pending }))).toEqual(p.targets.map(() => ({ epoch: outcome === "keep" ? 1 : 2,until: null,pending: null })))
    for (const state of await p.restrictions()) expect(state?.restriction).toBeNull()
  })
  it("a stale event below the D1 epoch cannot send a restriction",async () => {
    const p = await recoveryFixture()
    await p.live.env.DB.prepare("UPDATE accounts SET security_epoch=3 WHERE id=?").bind(p.live.account).run()
    await p.live.env.DB.batch([accountEvent(p.live.env,p.live.account,"account.recovery_keep",{ epoch: 2,restriction: null },p.now,"evt_stale")])
    await mirrorAccountEvents(p.live.env,p.recording,p.now)
    expect(p.calls.filter(call => call.op === "restriction")).toEqual([])
  })
  it("a newer pending DO refuses a committed lift and keeps the event unmirrored",async () => {
    const p = await recoveryFixture(),{ retryAccountSecurity,reserveAccountSecurity } = await import("../src/directory/account-security.ts"),{ resolveAccountRecovery } = await import("../src/directory/workspace-recovery.ts")
    p.available(true); await retryAccountSecurity(p.live.env,p.recovery.transition,p.recording,p.now+100)
    await mirrorAccountEvents(p.live.env,p.recording,p.now+100)
    const notice = await p.live.env.DB.prepare("SELECT id FROM account_notices WHERE account=? AND kind='recovery'").bind(p.live.account).first<{ id: string }>()
    await resolveAccountRecovery(p.live.env,await oldActor(p,p.now+101),"pk_test",notice!.id,"keep",p.recording,p.now+102)
    const next = await reserveAccountSecurity(p.live.env,p.live.account,{ effect: { kind: "sessions.end" },revokedSessionIds: [],removedFactorIds: [] },p.now+103)
    p.available(false); await retryAccountSecurity(p.live.env,next,p.recording,p.now+104)
    await expectDirectoryRefusal(p.real.restriction(p.targets[0]!,{ account: p.live.account,committedEpoch: 1,restriction: null }),{ error: "conflict",message: "The account security change is not committed here." })
    await mirrorAccountEvents(p.live.env,p.recording,p.now+105)
    expect(await p.live.env.DB.prepare("SELECT mirrored_to FROM account_events WHERE action='account.recovery_keep'").first()).toEqual({ mirrored_to: "[]" })
    for (const state of await p.restrictions()) expect(state).toMatchObject({ pending: { reservedEpoch: 2 },restriction: { until: p.now+100+86400000 } })
  })
})
