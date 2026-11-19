import { describe, expect, it, vi } from "vitest"
import { digestOf } from "../src/vault/areas/approvals.ts"
import { assertApprovedUse, consumeApprovedUse, prepareApprovedUse } from "../src/vault/areas/projects-workspace.ts"
import { approvalBatchesOn, staleWorkspaceConsent, workspaceApproval, workspaceApprovalStatus, type ApprovalAskBatch } from "../src/vault/areas/approvals-workspace.ts"
import { policyRulesOn } from "../src/vault/areas/policy-rules-workspace.ts"
import { approvalsArea } from "../src/vault/areas/approvals.ts"
import { applyMigrations } from "../src/vault/tenant-vault.ts"
import type { AccessState } from "../src/vault/access.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { VaultError } from "../src/http.ts"
import { projectFixture, projectState, inAccess, callProject } from "./projects-workspace-fixture.ts"
import { credentialsFixture, deviceInvocation, devicePrincipal, seedCredential } from "./credentials-test-support.ts"
import { authoriseWorkspaceRelay, workspaceRelayOps } from "../src/vault/areas/relay-workspace.ts"
import { setSetting } from "../src/vault/areas/workspace-runtime.ts"
import type { ApprovalBundleCreated } from "@mehen/protocol/api"
import { fixtureSql } from "./fixture-sql.ts"
const SUBJECT = { item: "key-project", method: "POST", url: "https://api.example.com/write", contentType: "application/json", contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf("{}"), constraints: { uses: 1, ttlSeconds: 600 } }
const PRESENTATION = { title: "Write a record", details: [{ label: "Action", value: "Write" }], body: "{}", headers: [] as [string, string][] }
const BATCH = { floor: [], shape: "shape-write", replaces: null }
describe("protected approval lifecycle", () => {
  it("requires, approves, checks exact bindings, consumes once, and rechecks decider and machine", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const state = projectState(ctx)
      const item = state.credentials.find((c) => c.home.kind === "project")!
      const credential = { ...item, slug: "key-project", version: 1 }
      const caller = { principal: { kind: "device" as const, deviceId: "dev_kim" }, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation: PRESENTATION, batch: BATCH }
      const context = { project: "prj_a", env: "prod" }
      const first = prepareApprovedUse(ctx, state, caller, credential, context, SUBJECT, null, ctx.now())
      expect(first.kind).toBe("required")
      const same = prepareApprovedUse(ctx, state, caller, credential, context, SUBJECT, null, ctx.now())
      expect(same.approvalId).toBe(first.approvalId)
      const row = workspaceApproval(ctx, first.approvalId)!
      const action = { type: "approval.decide" as const, approval: row.id, digest: row.digest, decision: "approve" as const, constraints: SUBJECT.constraints }
      callProject(ctx, state, "owner", "approvals.decide", { id: row.id, decision: "approve" }, action)
      const approved = prepareApprovedUse(ctx, projectState(ctx), caller, credential, context, SUBJECT, row.id, ctx.now())
      expect(approved.kind).toBe("approved")
      const changed = prepareApprovedUse(ctx, projectState(ctx), caller, credential, context, { ...SUBJECT, bodySha256: digestOf("changed") }, row.id, ctx.now())
      expect(changed.kind).toBe("required"); expect(changed.approvalId).not.toBe(row.id)
      const freshState = projectState(ctx)
      freshState.members.find((m) => m.id === "mem_owner")!.standing.effectiveRole = "member"
      expect(() => assertApprovedUse(ctx, freshState, approved.snapshot, row.id, ctx.now())).toThrow("no longer has a current approval")
      const revoked = projectState(ctx)
      revoked.devices.find((d) => d.id === "dev_kim")!.status = "revoked"
      expect(() => assertApprovedUse(ctx, revoked, approved.snapshot, row.id, ctx.now())).toThrow()
      ctx.storage.transactionSync(() => { assertApprovedUse(ctx, projectState(ctx), approved.snapshot, row.id, ctx.now()); consumeApprovedUse(ctx, approved.snapshot, row.id) })
      expect(() => assertApprovedUse(ctx, projectState(ctx), approved.snapshot, row.id, ctx.now())).toThrow("no longer has a current approval")
      const again = prepareApprovedUse(ctx, projectState(ctx), caller, credential, context, SUBJECT, row.id, ctx.now())
      expect(again.kind).toBe("required"); expect(again.approvalId).not.toBe(row.id)
      expect(JSON.stringify(workspaceApproval(ctx, row.id))).not.toContain("secret-value")
    })
  })
  it("uses the same approval authority for an unprotected policy ask without context", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "workspace")!
      const caller = { principal: { kind: "device" as const, deviceId: "dev_member" }, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation: PRESENTATION, batch: BATCH }
      const required = prepareApprovedUse(ctx, state, caller, { ...item, slug: "key-workspace", version: 1 }, null, SUBJECT, null, ctx.now())
      expect(required.kind).toBe("required"); expect(required.snapshot.reason).toBe("policy")
      const row = workspaceApproval(ctx, required.approvalId)!
      callProject(ctx, state, "member", "approvals.decide", { id: row.id, decision: "approve" }, { type: "approval.decide", approval: row.id, digest: row.digest, decision: "approve", constraints: SUBJECT.constraints })
      expect(prepareApprovedUse(ctx, projectState(ctx), caller, { ...item, slug: "key-workspace", version: 1 }, null, SUBJECT, row.id, ctx.now()).kind).toBe("approved")
    })
  })
  it("reloads authority before persisting an ask when the supplied planning state is stale", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "project")!
      fixtureSql(ctx).exec("DELETE FROM project_shares WHERE id='shr_kim'")
      const open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      try { prepareApprovedUse(ctx, state, { principal: { kind: "device", deviceId: "dev_kim" }, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation: PRESENTATION, batch: BATCH }, { ...item, slug: "key-project", version: 1 }, { project: "prj_a", env: "prod" }, SUBJECT, null, ctx.now()); throw new Error("accepted") } catch (error) { expect((error as import("../src/http.ts").VaultError).toJSON()).toEqual({ error: "not_found", message: "No such object." }) }
      expect(ctx.sql.exec("SELECT * FROM approvals").toArray()).toEqual([])
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
  it("rolls back a decision and grant when audit fails", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "project")!
      const first = prepareApprovedUse(ctx, state, { principal: { kind: "device", deviceId: "dev_kim" }, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation: PRESENTATION, batch: BATCH }, { ...item, slug: "key-project", version: 1 }, { project: "prj_a", env: "prod" }, SUBJECT, null, ctx.now())
      const row = workspaceApproval(ctx, first.approvalId)!
      const audit = vi.spyOn(ctx, "audit").mockImplementation(() => { throw new Error("audit unavailable") })
      expect(() => callProject(ctx, state, "owner", "approvals.decide", { id: row.id, decision: "approve" }, { type: "approval.decide", approval: row.id, digest: row.digest, decision: "approve", constraints: SUBJECT.constraints })).toThrow("audit unavailable")
      audit.mockRestore()
      expect(workspaceApproval(ctx, row.id)!.status).toBe("pending")
      expect(ctx.sql.exec("SELECT * FROM protected_use_grants").toArray()).toEqual([])
      expect(ctx.sql.exec("SELECT * FROM consent_lineage").toArray()).toEqual([])
    })
  })
})

it("an orphaned pending device stales its ask without blocking an owner project mutation", async () => {
  const f = await projectFixture()
  await inAccess(f.tenant, (ctx) => {
    const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "project")!
    const required = prepareApprovedUse(ctx, state, { principal: { kind: "device", deviceId: "dev_kim" }, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation: PRESENTATION, batch: BATCH }, { ...item, slug: "key-project", version: 1 }, { project: "prj_a", env: "prod" }, SUBJECT, null, ctx.now())
    ctx.sql.exec("DELETE FROM devices WHERE id='dev_kim'")
    const input = { project: "prj_a", env: "dev", name: "PLAIN", before: null, plain: "safe" }
    const action = callProject(ctx, projectState(ctx), "owner", "projects.action", { change: "variable", input }) as import("@mehen/protocol").WorkspaceStepUpAction
    const open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
    callProject(ctx, projectState(ctx), "owner", "projects.setVar", input, action)
    expect(workspaceApproval(ctx, required.approvalId)!.policy_status).toBe("stale")
    expect(ctx.sql.exec<{ plain: string }>("SELECT plain FROM vars WHERE project='prj_a' AND env='dev' AND name='PLAIN'").toArray()[0]!.plain).toBe("safe")
    expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
  })
})

// Batch approvals (APPROVAL_BATCHES, on in the test env): an ask records its
// review group, shape and floor, and the asker may replace its own open ask
// to the same place, explicitly (ruling B1).
describe("asking with batch approvals", () => {
  const ask = (ctx: VaultContext, state: AccessState, body: string, batch: Partial<ApprovalAskBatch> = {}): string => {
    const item = state.credentials.find((c) => c.home.kind === "workspace")!
    const caller = { principal: { kind: "device" as const, deviceId: "dev_member" }, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation: PRESENTATION, batch: { ...BATCH, ...batch } }
    return prepareApprovedUse(ctx, state, caller, { ...item, slug: "key-workspace", version: 1 }, null, { ...SUBJECT, item: "key-workspace", bodySha256: digestOf(body) }, null, ctx.now()).approvalId
  }
  const refusal = (fn: () => unknown) => { try { fn() } catch (error) { if (error instanceof VaultError) return error.toJSON(); throw error } throw new Error("accepted") }
  const batchColumns = (ctx: VaultContext, id: string) => ctx.sql.exec<{ review_group: string | null; shape: string | null; floor: string | null; bundle: string | null; superseded_by: string | null; policy_status: string | null }>("SELECT review_group,shape,floor,bundle,superseded_by,policy_status FROM approvals WHERE id=?", id).toArray()[0]!
  const switchedOff = (ctx: VaultContext): VaultContext => Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, APPROVAL_BATCHES: "off" } })

  it("reads APPROVAL_BATCHES with the one switch parser POLICY_RULES uses", () => {
    const here = "tn_aaaaaaaaaa"
    for (const value of ["on", "off", "", undefined, here, `${here}, tn_bbbbbbbbbb`, " tn_bbbbbbbbbb ,tn_aaaaaaaaaa ", `${here},`, "work", `on, ${here}`, "tn_bbbbbbbbbb"]) {
      expect(approvalBatchesOn({ APPROVAL_BATCHES: value }, here), String(value)).toBe(policyRulesOn({ POLICY_RULES: value }, here))
    }
    expect([approvalBatchesOn({ APPROVAL_BATCHES: "on" }, here), approvalBatchesOn({ APPROVAL_BATCHES: here }, here), approvalBatchesOn({ APPROVAL_BATCHES: `${here},` }, here), approvalBatchesOn({}, here)]).toEqual([true, true, false, false])
  })

  it("records the review group, shape and floor, and a re-ask naming the earlier one supersedes it and names the replacement", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const state = projectState(ctx)
      const first = ask(ctx, state, "first", { floor: ["send", "destructive", "send"] })
      expect(batchColumns(ctx, first)).toEqual({ review_group: expect.stringMatching(/^grp_[A-Za-z0-9_-]{22}$/), shape: "shape-write", floor: JSON.stringify(["destructive", "send"]), bundle: null, superseded_by: null, policy_status: null })
      const second = ask(ctx, projectState(ctx), "second", { replaces: first })
      expect(second).not.toBe(first)
      expect(batchColumns(ctx, first)).toMatchObject({ policy_status: "superseded", superseded_by: second })
      expect(batchColumns(ctx, second).review_group).toBe(batchColumns(ctx, first).review_group)
      expect(workspaceApprovalStatus(ctx, workspaceApproval(ctx, first)!)).toBe("superseded")
      expect(workspaceApprovalStatus(ctx, workspaceApproval(ctx, second)!)).toBe("pending")
      const view = await callProject(ctx, projectState(ctx), "member", "approvals.view", { id: first }) as import("@mehen/protocol").ApprovalViewProjection
      expect(view).toMatchObject({ view: "detail", approval: { status: "superseded", replacedBy: second } })
      const audit = ctx.sql.exec<{ actor: string; target: string; detail: string }>("SELECT actor,target,detail FROM audit WHERE action='approval.supersede'").toArray()
      expect(audit).toHaveLength(1)
      expect(audit[0]).toMatchObject({ actor: "device:dev_member", target: first })
      expect(JSON.parse(audit[0]!.detail)).toEqual({ item: "key-workspace", replacedBy: second })
      const row = workspaceApproval(ctx, first)!
      expect(() => callProject(ctx, projectState(ctx), "member", "approvals.decide", { id: first, decision: "approve" }, { type: "approval.decide", approval: first, digest: row.digest, decision: "approve", constraints: SUBJECT.constraints })).toThrow("This approval is no longer pending.")
    })
  })

  it("refuses to replace anything but the asker's own open ask to the same place, and changes nothing", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const changes: [string, string][] = [
        ["another machine", "UPDATE approvals SET device='dev_kim' WHERE id=?"],
        ["a workload", "UPDATE approvals SET workload='wkl_other' WHERE id=?"],
        ["a bundle", "UPDATE approvals SET bundle='bnd_other' WHERE id=?"],
        ["decided", "UPDATE approvals SET status='approved' WHERE id=?"],
        ["denied", "UPDATE approvals SET status='denied' WHERE id=?"],
        ["expired", `UPDATE approvals SET expires_at=${ctx.now() - 1} WHERE id=?`],
        ["already replaced", "UPDATE approvals SET policy_status='superseded' WHERE id=?"],
        ["stale", "UPDATE approvals SET policy_status='stale' WHERE id=?"],
        ["asked before batches", "UPDATE approvals SET shape=NULL WHERE id=?"],
      ]
      for (const [why, change] of changes) {
        const earlier = ask(ctx, projectState(ctx), `earlier ${why}`)
        ctx.sql.exec(change, earlier)
        const before = ctx.sql.exec("SELECT * FROM approvals ORDER BY id").toArray()
        expect(refusal(() => ask(ctx, projectState(ctx), `later ${why}`, { replaces: earlier })), why).toEqual({ error: "bad_request", message: `${earlier} is not an open ask from this machine to the same place.` })
        expect(ctx.sql.exec("SELECT * FROM approvals ORDER BY id").toArray(), why).toEqual(before)
      }
      const open = ask(ctx, projectState(ctx), "open")
      expect(refusal(() => ask(ctx, projectState(ctx), "elsewhere", { replaces: open, shape: "shape-other" }))).toEqual({ error: "bad_request", message: `${open} is not an open ask from this machine to the same place.` })
      expect(refusal(() => ask(ctx, projectState(ctx), "nothing", { replaces: "apr_nothere" }))).toEqual({ error: "bad_request", message: "apr_nothere is not an open ask from this machine to the same place." })
      expect(batchColumns(ctx, open)).toMatchObject({ policy_status: null, superseded_by: null })
      expect(ctx.sql.exec("SELECT * FROM audit WHERE action='approval.supersede'").toArray()).toEqual([])
    })
  })

  it("keeps a superseded ask superseded when access changes and the open asks go stale", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const first = ask(ctx, projectState(ctx), "first"), second = ask(ctx, projectState(ctx), "second", { replaces: first })
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      staleWorkspaceConsent(ctx, projectState(ctx))
      expect([batchColumns(ctx, first).policy_status, batchColumns(ctx, second).policy_status]).toEqual(["superseded", "stale"])
    })
  })

  it("returns an identical open ask as it is, superseding nothing", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const first = ask(ctx, projectState(ctx), "same")
      expect(ask(ctx, projectState(ctx), "same", { replaces: first })).toBe(first)
      expect(batchColumns(ctx, first)).toMatchObject({ policy_status: null, superseded_by: null })
    })
  })

  it("lets a re-ask that replaces one of 20 open asks through the cap", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const asked = Array.from({ length: 20 }, (_, n) => ask(ctx, projectState(ctx), `body ${n}`))
      expect(refusal(() => ask(ctx, projectState(ctx), "body 20"))).toEqual({ error: "rate_limited", message: "This machine already has 20 open asks. Settle one before asking again." })
      const replacement = ask(ctx, projectState(ctx), "body 20", { replaces: asked[0] })
      expect(batchColumns(ctx, asked[0]!)).toMatchObject({ policy_status: "superseded", superseded_by: replacement })
    })
  })

  it("keeps the old ask when the new one fails to be stored", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const first = ask(ctx, projectState(ctx), "first")
      const audit = ctx.audit.bind(ctx)
      const spy = vi.spyOn(ctx, "audit").mockImplementation((event) => { if (event.action === "approval.request") throw new Error("audit unavailable"); audit(event) })
      try { expect(() => ask(ctx, projectState(ctx), "second", { replaces: first })).toThrow("audit unavailable") } finally { spy.mockRestore() }
      expect(batchColumns(ctx, first)).toMatchObject({ policy_status: null, superseded_by: null })
      expect(ctx.sql.exec("SELECT id FROM approvals").toArray()).toEqual([{ id: first }])
      expect(ctx.sql.exec("SELECT * FROM audit WHERE action='approval.supersede'").toArray()).toEqual([])
    })
  })

  it("with APPROVAL_BATCHES off records none of it and refuses to replace an ask", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const off = switchedOff(ctx)
      const first = ask(off, projectState(off), "first", { floor: ["send"] })
      expect(batchColumns(ctx, first)).toEqual({ review_group: null, shape: null, floor: null, bundle: null, superseded_by: null, policy_status: null })
      expect(refusal(() => ask(off, projectState(off), "second", { replaces: first }))).toEqual({ error: "forbidden", message: "Replacing an ask is not available yet." })
      expect(ctx.sql.exec("SELECT id FROM approvals").toArray()).toEqual([{ id: first }])
      expect(workspaceApprovalStatus(ctx, workspaceApproval(ctx, first)!)).toBe("pending")
    })
  })

  it("migrates a workspace that ran the workload migration, keeping its asks", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const off = switchedOff(ctx)
      const kept = ask(off, projectState(off), "kept")
      const before = ctx.sql.exec("SELECT * FROM approvals").toArray()
      ctx.sql.exec("DROP INDEX approvals_review_group; DROP INDEX approvals_shape; DROP INDEX approvals_bundle; DROP TABLE approval_bundles")
      for (const column of ["review_group", "shape", "floor", "bundle", "superseded_by"]) ctx.sql.exec(`ALTER TABLE approvals DROP COLUMN ${column}`)
      ctx.sql.exec("UPDATE _migrations SET applied=? WHERE area='approvals'", approvalsArea.migrations.length - 1)
      applyMigrations(ctx.sql, ctx.storage, [approvalsArea])
      expect(ctx.sql.exec<{ applied: number }>("SELECT applied FROM _migrations WHERE area='approvals'").toArray()[0]!.applied).toBe(approvalsArea.migrations.length)
      expect(ctx.sql.exec("SELECT * FROM approvals").toArray()).toEqual(before)
      expect(batchColumns(ctx, kept)).toEqual({ review_group: null, shape: null, floor: null, bundle: null, superseded_by: null, policy_status: null })
      expect(ctx.sql.exec("SELECT * FROM approval_bundles").toArray()).toEqual([])
      expect(ctx.sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='approvals' AND name IN ('approvals_review_group','approvals_shape','approvals_bundle') ORDER BY name").toArray().map((r) => r.name)).toEqual(["approvals_bundle", "approvals_review_group", "approvals_shape"])
    })
  })
})

// Bundles (approvals.bundle): the room, the switch, a frozen or managed
// workspace and who may read one are all settled before a request runs.
describe("asking for a bundle", () => {
  const body = (text: string) => Buffer.from(text).toString("base64url")
  const request = (n: number) => ({ item: "plan-key", method: "POST", url: "https://api.example.com/v1/databases", headers: [], body: body(`{"n":${n}}`) })
  const op = async (ctx: VaultContext, name: string, input: unknown, device = "dev_member") => await workspaceRelayOps[name]!.handler(ctx, devicePrincipal(device), input, await deviceInvocation(ctx, device))
  const refused = async (fn: () => Promise<unknown>) => { try { await fn() } catch (error) { if (error instanceof VaultError) return error.toJSON(); throw error } throw new Error("accepted") }
  const held = async (ctx: VaultContext) => {
    await seedCredential(ctx, "plan-key")
    ctx.sql.exec("UPDATE items SET policy=? WHERE slug='plan-key'", JSON.stringify({ default: "approve", rules: [] }))
  }
  const nothingAsked = (ctx: VaultContext) => [ctx.sql.exec("SELECT * FROM approval_bundles").toArray(), ctx.sql.exec("SELECT * FROM audit WHERE action='approval.bundle'").toArray()]

  it("refuses rate_limited before creating anything when the open asks and the requests would pass 20", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await held(ctx)
      for (let n = 0; n < 18; n++) expect(await refused(async () => authoriseWorkspaceRelay(ctx, devicePrincipal(), request(100 + n), await deviceInvocation(ctx)))).toMatchObject({ error: "approval_required" })
      const before = ctx.sql.exec("SELECT * FROM approvals ORDER BY id").toArray()
      expect(await refused(() => op(ctx, "approvals.bundle", { requests: [request(1), request(2), request(3)] }))).toEqual({ error: "rate_limited", message: "This machine's open asks and these 3 requests would pass its 20. Settle some, or send fewer at once." })
      expect(ctx.sql.exec("SELECT * FROM approvals ORDER BY id").toArray()).toEqual(before)
      expect(nothingAsked(ctx)).toEqual([[], []])
      const fits = await op(ctx, "approvals.bundle", { requests: [request(1), request(2)] }) as ApprovalBundleCreated
      expect(fits.results.map((r) => r.outcome)).toEqual(["ask", "ask"])
    })
  })

  it("refuses in a frozen workspace, in a managed one and with APPROVAL_BATCHES off, creating nothing", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await held(ctx)
      const off = Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, APPROVAL_BATCHES: "off" } })
      const unavailable = { error: "forbidden", message: "Asking for several requests at once is not available yet." }
      expect(await refused(() => op(off, "approvals.bundle", { requests: [request(1)] }))).toEqual(unavailable)
      expect(await refused(() => op(off, "approvals.bundle_status", { id: "bnd_missing" }))).toEqual(unavailable)
      setSetting(ctx, "frozen", true)
      expect(await refused(() => op(ctx, "approvals.bundle", { requests: [request(1)] }))).toEqual({ error: "frozen", message: "This workspace is frozen." })
      setSetting(ctx, "frozen", false)
      setSetting(ctx, "managed", { platform: "plt_fixture", subject: "sub_fixture", member: "mem_owner", createdAt: ctx.now() })
      expect(await refused(() => op(ctx, "approvals.bundle", { requests: [request(1)] }))).toEqual(unavailable)
      expect(ctx.sql.exec("SELECT * FROM approvals").toArray()).toEqual([])
      expect(nothingAsked(ctx)).toEqual([[], []])
    })
  })

  it("lets only the machine and workload that asked read a bundle; another machine finds nothing", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await held(ctx)
      const created = await op(ctx, "approvals.bundle", { requests: [request(1)] }) as ApprovalBundleCreated
      const asked = created.results[0]!.approval!
      expect(await op(ctx, "approvals.bundle_status", { id: created.bundle })).toEqual({ bundle: created.bundle, approvals: [{ id: asked, status: "pending" }] })
      const missing = { error: "not_found", message: "No such object." }
      expect(await refused(() => op(ctx, "approvals.bundle_status", { id: created.bundle }, "dev_admin"))).toEqual(missing)
      expect(await refused(() => op(ctx, "approvals.bundle_status", { id: "bnd_missing" }))).toEqual(missing)
      ctx.sql.exec("UPDATE approval_bundles SET workload='wkl_other' WHERE id=?", created.bundle)
      expect(await refused(() => op(ctx, "approvals.bundle_status", { id: created.bundle }))).toEqual(missing)
    })
  })

  it("reads an ask the machine can no longer see as stale", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await held(ctx)
      const created = await op(ctx, "approvals.bundle", { requests: [request(1)] }) as ApprovalBundleCreated
      const asked = created.results[0]!.approval!
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.tags',json('[\"elsewhere\"]')) WHERE id='dev_member'")
      expect(await op(ctx, "approvals.bundle_status", { id: created.bundle })).toEqual({ bundle: created.bundle, approvals: [{ id: asked, status: "stale" }] })
    })
  })

  it("leaves an identical ask already in another bundle where it is", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await held(ctx)
      const first = await op(ctx, "approvals.bundle", { requests: [request(1)] }) as ApprovalBundleCreated
      const asked = first.results[0]!.approval!
      const second = await op(ctx, "approvals.bundle", { requests: [request(1)] }) as ApprovalBundleCreated
      expect(second.results).toEqual([{ index: 0, outcome: "ask", approval: asked, bindingCode: expect.any(String) }])
      expect(ctx.sql.exec("SELECT id,bundle FROM approvals").toArray()).toEqual([{ id: asked, bundle: first.bundle }])
      expect(await op(ctx, "approvals.bundle_status", { id: first.bundle })).toEqual({ bundle: first.bundle, approvals: [{ id: asked, status: "pending" }] })
      expect(await op(ctx, "approvals.bundle_status", { id: second.bundle })).toEqual({ bundle: second.bundle, approvals: [] })
    })
  })
})
