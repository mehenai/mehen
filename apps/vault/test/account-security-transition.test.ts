import {
  describe as describeAccessDO,
  it as itAccessDO,
  expect as expectAccessDO,
} from "vitest"
import {
  accessFixture as accessDOFixture,
  accountAuth as accessDOAuth,
  inAccess as withAccessDO,
} from "./access-test-support.ts"
import {
  authorise as authoriseAccessDO,
  installSecurity as installAccessDO,
  observeCommittedEpoch as commitAccessDO,
  principalOf as principalAccessDO,
  requireStepUp as stepUpAccessDO,
  security as securityAccessDO,
  updateRestriction as restrictionAccessDO,
} from "../src/vault/areas/workspace-runtime.ts"

describeAccessDO("T14 authoritative DO side", () => {
  itAccessDO("keeps surviving prior epochs safe-list-only until commit is observed", async () => {
    const { tenant } = await accessDOFixture()
    await withAccessDO(tenant, (ctx) => {
      installAccessDO(ctx, "acc_owner", 0, {
        transitionId: "ast_t14", reservedEpoch: 1,
        revokedSessionIds: ["ses_bad"], removedFactorIds: ["pk_bad"],
        restriction: null,
      })
      const auth = accessDOAuth("owner")
      const invocation = { auth, workspace: { id: tenant, slug: "work", name: "Work" } }
      expectAccessDO(authoriseAccessDO(ctx, invocation,
        { type: "people.read" }, {}, ctx.now()).allowed).toBe(true)
      expectAccessDO(authoriseAccessDO(ctx, invocation,
        { type: "workspace.freeze" }, {}, ctx.now()).allowed).toBe(true)
      expectAccessDO(authoriseAccessDO(ctx, invocation,
        { type: "device.revoke" }, { device: "dev_member" }, ctx.now()).allowed).toBe(true)
      expectAccessDO(() => authoriseAccessDO(ctx, invocation,
        { type: "workspace.unfreeze" }, {}, ctx.now())).toThrowError(expectAccessDO.objectContaining({ code: "account_pending", message: "You are not allowed to do that." }))
      expectAccessDO(() => principalAccessDO(ctx,
        { ...auth, session: "ses_bad" })).toThrowError(expectAccessDO.objectContaining({ code: "unauthenticated", message: "This session is no longer authorised." }))
      expectAccessDO(() => principalAccessDO(ctx,
        { ...auth, stepUpFactor: "pk_bad" })).toThrowError(expectAccessDO.objectContaining({ code: "unauthenticated", message: "This session is no longer authorised." }))
      commitAccessDO(ctx, "acc_owner", 1)
      expectAccessDO(() => principalAccessDO(ctx, auth)).toThrowError(expectAccessDO.objectContaining({ code: "unauthenticated", message: "This session is no longer authorised." }))
      expectAccessDO(principalAccessDO(ctx,
        { ...auth, securityEpoch: 1 })).toMatchObject({ securityEpoch: 1 })
    })
  })

  itAccessDO("does not clear a newer pending guard with an older commit or install", async () => {
    const { tenant } = await accessDOFixture()
    await withAccessDO(tenant, (ctx) => {
      const first = { transitionId: "ast_merge", reservedEpoch: 1,
        revokedSessionIds: ["ses_one"], removedFactorIds: ["pk_one"],
        restriction: { reason: "recovery" as const,
          until: ctx.now() + 86_400_000, notice: "ntc_recovery" } }
      installAccessDO(ctx, "acc_owner", 0, first)
      installAccessDO(ctx, "acc_owner", 0, { ...first, reservedEpoch: 2,
        revokedSessionIds: ["ses_two"], removedFactorIds: ["pk_two"],
        restriction: null })
      commitAccessDO(ctx, "acc_owner", 1)
      const before = securityAccessDO(ctx, "acc_owner")
      installAccessDO(ctx, "acc_owner", 0, first)
      expectAccessDO(securityAccessDO(ctx, "acc_owner")).toEqual(before)
      expectAccessDO(before).toMatchObject({ installedEpoch: 1,
        pending: { reservedEpoch: 2 },
        revokedSessionIds: ["ses_one", "ses_two"],
        removedFactorIds: ["pk_one", "pk_two"], restriction: first.restriction })
      expectAccessDO(() => restrictionAccessDO(ctx,
        "acc_owner", 1, null)).toThrowError(expectAccessDO.objectContaining({ code: "conflict", message: "The account security change is not committed here." }))
      commitAccessDO(ctx, "acc_owner", 2)
      expectAccessDO(restrictionAccessDO(ctx, "acc_owner", 2, null))
        .toMatchObject({ restriction: null, pending: null,
          revokedSessionIds: ["ses_one", "ses_two"],
          removedFactorIds: ["pk_one", "pk_two"] })
    })
  })

  itAccessDO("cannot spend a prepared widening after cancel installs revocation", async () => {
    const { tenant } = await accessDOFixture()
    await withAccessDO(tenant, async (ctx) => {
      const action = { type: "workspace.unfreeze" } as const
      const invocation = { auth: accessDOAuth("owner", action),
        workspace: { id: tenant, slug: "work", name: "Work" } }
      const decision = authoriseAccessDO(ctx, invocation,
        { type: "workspace.unfreeze" }, {}, ctx.now())
      let resume: () => void = () => undefined
      const barrier = new Promise<void>((resolve) => { resume = resolve })
      const waiting = (async () => {
        await barrier
        ctx.storage.transactionSync(() => {
          stepUpAccessDO(ctx, decision, action, invocation)
          ctx.sql.exec("INSERT INTO tenant_state VALUES ('t14_losing_write','true')")
        })
      })()
      installAccessDO(ctx, "acc_owner", 0, { transitionId: "ast_cancel",
        reservedEpoch: 1, revokedSessionIds: ["ses_owner"],
        removedFactorIds: ["pk_recovered"], restriction: {
          reason: "recovery", until: ctx.now() + 86_400_000, notice: "ntc_cancel" } })
      resume()
      await expectAccessDO(waiting).rejects.toMatchObject({ code: "unauthenticated", message: "This session is no longer authorised." })
      expectAccessDO(ctx.sql.exec(
        "SELECT * FROM tenant_state WHERE key='t14_losing_write'").toArray()).toEqual([])
    })
  })
})
import { expectDirectoryRefusal } from "./directory-test-support.ts"
import { beginAccessSideEffectChecks,finishAccessSideEffectChecks } from "./access-test-support.ts"
import { afterEach,beforeEach, describe, expect, it } from "vitest"
import { insertAccountPasskey } from "../src/directory/account-store.ts"
import { reserveAccountSecurity, retryAccountSecurity, accountSecurityStatus, retryDueAccountSecurity } from "../src/directory/account-security.ts"
import type { DirectoryWorkspaceClient } from "../src/directory/workspace-client.ts"
import { createWorkspaceFixture, type WorkspaceTestFixture } from "./workspace-fixtures.ts"
let f: WorkspaceTestFixture
beforeEach(async () => { beginAccessSideEffectChecks(); f = await createWorkspaceFixture() })
function client(): DirectoryWorkspaceClient & { installs: { workspace: string; input: unknown }[]; commits: string[] } {
  const installs: { workspace: string; input: unknown }[] = [],commits: string[] = []
  return { installs,commits,async install(workspace,input) { installs.push({ workspace,input }); return { installedEpoch: input.committedEpoch } },async commit(workspace,input) { commits.push(workspace); return { installedEpoch: input.committedEpoch } },async restriction() {},async revokeSession() {},async mirror() {} }
}
async function account() { return f.env.DB.prepare("SELECT security_epoch,security_transition,restricted_until FROM accounts WHERE id=?").bind(f.account).first() }
async function reserve(sessions = [f.session]) { return reserveAccountSecurity(f.env,f.account,{ effect: { kind: "sessions.end" },revokedSessionIds: sessions,removedFactorIds: [] }) }
describe("account-security-transition D1 barrier",() => {
  it("reserves without advancing committed epoch and waits for every indexed workspace",async () => {
    const id = await reserve()
    expect(await account()).toEqual({ security_epoch: 0,security_transition: id,restricted_until: null })
    const c = client()
    c.install = async (workspace,input) => { c.installs.push({ workspace,input }); if (workspace === f.workspaces.work) throw new Error("unavailable"); return { installedEpoch: 0 } }
    expect(await retryAccountSecurity(f.env,id,c)).toMatchObject({ id,reservedEpoch: 1,targets: 2,acknowledged: 1 })
    expect(await account()).toEqual({ security_epoch: 0,security_transition: id,restricted_until: null })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions WHERE id=?").bind(f.session).first()).toEqual({ n: 1 })
    expect(c.commits).toEqual([])
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_events").first()).toEqual({ n: 0 })
    await retryAccountSecurity(f.env,id,client())
    expect(await account()).toEqual({ security_epoch: 1,security_transition: null,restricted_until: null })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions").first()).toEqual({ n: 0 })
  })
  it("includes joining reservations, and retains unavailable unresolved targets",async () => {
    await f.env.DB.prepare("UPDATE memberships SET state='joining' WHERE account=? AND workspace=?").bind(f.account,f.workspaces.personal).run()
    const id = await reserve()
    await f.env.DB.prepare("UPDATE memberships SET state='left' WHERE account=? AND workspace=?").bind(f.account,f.workspaces.personal).run()
    const c = client()
    await retryAccountSecurity(f.env,id,c)
    expect(c.installs.map(x => x.workspace).sort()).toEqual([f.workspaces.personal,f.workspaces.work].sort())
  })
  it("merges tightening revocations, increments reserved version and invalidates old acknowledgements",async () => {
    const id = await reserve(["ses_old"])
    const c = client()
    let merged = false
    c.install = async (_workspace,input) => {
      if (!merged) { merged = true; expect(await reserveAccountSecurity(f.env,f.account,{ effect: { kind: "factor.remove" },revokedSessionIds: ["ses_new"],removedFactorIds: ["pk_removed"] })).toBe(id) }
      return { installedEpoch: input.committedEpoch }
    }
    expect(await retryAccountSecurity(f.env,id,c)).toMatchObject({ reservedEpoch: 2,acknowledged: 0 })
    expect(await account()).toMatchObject({ security_epoch: 0 })
    const next = client()
    await retryAccountSecurity(f.env,id,next)
    expect(next.installs[0]?.input).toMatchObject({ committedEpoch: 0,pending: { reservedEpoch: 2,revokedSessionIds: ["ses_new","ses_old",f.session].sort(),removedFactorIds: ["pk_removed"] } })
    expect(await account()).toMatchObject({ security_epoch: 2,security_transition: null })
  })
  it("final D1 failure rolls back revocations and epoch, keeps installed guards and retries",async () => {
    const id = await reserve()
    await f.env.DB.prepare("CREATE TRIGGER reject_event BEFORE INSERT ON account_events BEGIN SELECT RAISE(ABORT,'injected audit failure'); END").run()
    const c = client()
    await expect(retryAccountSecurity(f.env,id,c)).rejects.toThrow("injected audit failure")
    expect(await account()).toMatchObject({ security_epoch: 0,security_transition: id })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions").first()).toEqual({ n: 1 })
    expect(c.commits).toEqual([])
    await f.env.DB.prepare("DROP TRIGGER reject_event").run()
    await retryAccountSecurity(f.env,id,c)
    expect(await account()).toMatchObject({ security_epoch: 1,security_transition: null })
  })
  it("repairs lost commit messages, and duplicate retries do not duplicate account events",async () => {
    const id = await reserve()
    const c = client()
    c.commit = async () => { throw new Error("lost commit message") }
    await retryAccountSecurity(f.env,id,c)
    expect(await account()).toMatchObject({ security_epoch: 1 })
    const repaired = client()
    await retryDueAccountSecurity(f.env,repaired,Date.now()+60001)
    expect(repaired.commits.sort()).toEqual([f.workspaces.personal,f.workspaces.work].sort())
    await retryAccountSecurity(f.env,id,repaired)
    expect(repaired.commits).toHaveLength(2)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_events").first()).toEqual({ n: 1 })
    expect(await accountSecurityStatus(f.env,f.account)).toBeNull()
  })
  it("cancel keeps restriction until revocations commit in the same D1 transaction",async () => {
    const now = Date.now(),notice = "ntc_recovery"
    await f.env.DB.batch([
      f.env.DB.prepare("UPDATE accounts SET restricted_until=?,restricted_reason='recovery' WHERE id=?").bind(now+86400000,f.account),
      f.env.DB.prepare("INSERT INTO account_notices(id,account,kind,at,restricted_until) VALUES (?,?,'recovery',?,?)").bind(notice,f.account,now,now+86400000),
    ])
    await insertAccountPasskey(f.env,f.account,{ credentialId: "old",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },now-1000,"signup","pk_old").run()
    const id = await reserveAccountSecurity(f.env,f.account,{ effect: { kind: "recovery.cancel",notice,factor: "pk_old" },revokedSessionIds: [f.session],removedFactorIds: ["pk_recovered"] })
    const unavailable = client()
    unavailable.install = async () => { throw new Error("unavailable") }
    await retryAccountSecurity(f.env,id,unavailable)
    expect(await account()).toMatchObject({ security_epoch: 0,restricted_until: now+86400000 })
    expect(await f.env.DB.prepare("SELECT resolved_at FROM account_notices WHERE id=?").bind(notice).first()).toEqual({ resolved_at: null })
    const c = client()
    await retryAccountSecurity(f.env,id,c)
    expect(c.installs[0]?.input).toMatchObject({ pending: { restriction: { reason: "recovery",until: now+86400000,notice } } })
    expect(await account()).toMatchObject({ security_epoch: 1,restricted_until: null })
    expect(await f.env.DB.prepare("SELECT outcome FROM account_notices WHERE id=?").bind(notice).first()).toEqual({ outcome: "cancel" })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions").first()).toEqual({ n: 0 })
  })
})

describe("T14 local epoch observation through the ACCESS runtime",() => {
  it("pending admits only the surviving safe list, never widening, approval or reveal",async () => {
    const { accessFixture,inAccess,accountAuth } = await import("./access-test-support.ts")
    const { installSecurity,authorise,security } = await import("../src/vault/areas/workspace-runtime.ts")
    const { tenant } = await accessFixture()
    await inAccess(tenant,ctx => {
      const restriction = { reason: "recovery" as const,until: Date.now()+86400000,notice: "ntc_pending" }
      installSecurity(ctx,"acc_owner",0,{ transitionId: "trn_pending",reservedEpoch: 1,revokedSessionIds: ["ses_revoked"],removedFactorIds: ["pk_removed"],restriction })
      const invocation = { workspace: { id: tenant,slug: "work",name: "Work" },auth: accountAuth() }
      for (const action of [{ type: "people.read" as const },{ type: "workspace.freeze" as const },{ type: "device.revoke" as const }]) expect(authorise(ctx,invocation,action,action.type === "device.revoke" ? { device: "dev_member" } : {}).allowed).toBe(true)
      const before = security(ctx,"acc_owner"),workspace = ctx.sql.exec("SELECT value FROM tenant_state WHERE key='workspace'").toArray()
      for (const action of [{ type: "workspace.update" as const },{ type: "approval.approve" as const },{ type: "credential.reveal" as const }]) {
        let error: unknown
        try { authorise(ctx,invocation,action,{}) } catch (e) { error = e }
        expect(error).toMatchObject({ code: "account_pending" })
      }
      for (const auth of [{ ...accountAuth(),session: "ses_revoked" },{ ...accountAuth(),stepUpFactor: "pk_removed" }]) {
        expect(() => authorise(ctx,{ ...invocation,auth },{ type: "workspace.freeze" },{})).toThrow("This session is no longer authorised.")
      }
      expect(security(ctx,"acc_owner")).toEqual(before)
      expect(ctx.sql.exec("SELECT value FROM tenant_state WHERE key='workspace'").toArray()).toEqual(workspace)
    })
  })
  it("a lost commit message limits a surviving prior epoch until the first committed-epoch call",async () => {
    const { accessFixture,inAccess,accountAuth } = await import("./access-test-support.ts")
    const { installSecurity,authorise,security } = await import("../src/vault/areas/workspace-runtime.ts")
    const { tenant } = await accessFixture()
    await inAccess(tenant,ctx => {
      installSecurity(ctx,"acc_owner",0,{ transitionId: "trn_one",reservedEpoch: 1,revokedSessionIds: [],removedFactorIds: [],restriction: null })
      const invocation = { workspace: { id: tenant,slug: "work",name: "Work" },auth: accountAuth() }
      // D1 has committed 1, but this object has not observed the message yet.
      expect(authorise(ctx,invocation,{ type: "people.read" },{}).allowed).toBe(true)
      expect(() => authorise(ctx,invocation,{ type: "workspace.update" },{})).toThrow(expect.objectContaining({ code: "account_pending",status: 403,message: "You are not allowed to do that." }))
      expect(authorise(ctx,{ ...invocation,auth: { ...invocation.auth,securityEpoch: 1 } },{ type: "people.read" },{}).allowed).toBe(true)
      expect(security(ctx,"acc_owner")).toMatchObject({ installedEpoch: 1,pending: null })
      expect(() => authorise(ctx,invocation,{ type: "people.read" },{})).toThrow("This session is no longer authorised.")
    })
  })
  it("delayed N+1 commit/call cannot clear N+2, and stale/duplicate installs are idempotent",async () => {
    const { accessFixture,inAccess,accountAuth } = await import("./access-test-support.ts")
    const { installSecurity,observeCommittedEpoch,authorise,security } = await import("../src/vault/areas/workspace-runtime.ts")
    const { tenant } = await accessFixture()
    await inAccess(tenant,ctx => {
      const pending = { transitionId: "trn_newer",reservedEpoch: 2,revokedSessionIds: ["ses_bad"],removedFactorIds: ["pk_bad"],restriction: null }
      installSecurity(ctx,"acc_owner",0,pending)
      observeCommittedEpoch(ctx,"acc_owner",1)
      const invocation = { workspace: { id: tenant,slug: "work",name: "Work" },auth: { ...accountAuth(),securityEpoch: 1 } }
      expect(authorise(ctx,invocation,{ type: "people.read" },{}).allowed).toBe(true)
      expect(() => authorise(ctx,invocation,{ type: "workspace.update" },{})).toThrow(expect.objectContaining({ code: "account_pending",status: 403,message: "You are not allowed to do that." }))
      expect(() => authorise(ctx,{ ...invocation,auth: accountAuth() },{ type: "people.read" },{})).toThrow("This session is no longer authorised.")
      const before = security(ctx,"acc_owner"),audit = ctx.sql.exec("SELECT COUNT(*) AS n FROM audit").toArray()
      installSecurity(ctx,"acc_owner",0,{ ...pending,reservedEpoch: 1,revokedSessionIds: [],removedFactorIds: [] })
      observeCommittedEpoch(ctx,"acc_owner",1)
      installSecurity(ctx,"acc_owner",1,pending)
      expect(security(ctx,"acc_owner")).toEqual(before)
      expect(ctx.sql.exec("SELECT COUNT(*) AS n FROM audit").toArray()).toEqual(audit)
      observeCommittedEpoch(ctx,"acc_owner",2)
      expect(security(ctx,"acc_owner")).toMatchObject({ installedEpoch: 2,pending: null,revokedSessionIds: ["ses_bad"],removedFactorIds: ["pk_bad"] })
      expect(() => authorise(ctx,invocation,{ type: "people.read" },{})).toThrow("This session is no longer authorised.")
    })
  })
})

afterEach(() => finishAccessSideEffectChecks())

describe("T14 prepared step-up cancellation boundary",() => {
  it("cannot spend a widening prepared before cancellation installs revocation",async () => {
    const { accessFixture,inAccess,accountAuth } = await import("./access-test-support.ts")
    const { installSecurity,authorise,requireStepUp } = await import("../src/vault/areas/workspace-runtime.ts")
    const { tenant } = await accessFixture()
    await inAccess(tenant,async ctx => {
      const action = { type: "workspace.unfreeze" } as const,invocation = { auth: accountAuth("owner",action),workspace: { id: tenant,slug: "work",name: "Work" } }
      const decision = authorise(ctx,invocation,{ type: "workspace.unfreeze" },{})
      let resume: (() => void) | undefined
      const barrier = new Promise<void>(resolve => { resume = resolve })
      const waiting = (async () => {
        await barrier
        ctx.storage.transactionSync(() => {
          requireStepUp(ctx,decision,action,invocation)
          ctx.sql.exec("INSERT INTO tenant_state VALUES ('t14_losing_write','true')")
        })
      })()
      installSecurity(ctx,"acc_owner",0,{ transitionId: "trn_cancel",reservedEpoch: 1,revokedSessionIds: ["ses_owner"],removedFactorIds: ["pk_recovered"],restriction: { reason: "recovery",until: Date.now()+86400000,notice: "ntc_cancel" } })
      if (!resume) throw new Error("Missing test barrier")
      resume()
      await expectDirectoryRefusal(waiting,{ error: "unauthenticated",message: "This session is no longer authorised." })
      expect(ctx.sql.exec("SELECT * FROM tenant_state WHERE key='t14_losing_write'").toArray()).toEqual([])
    })
  })
})
