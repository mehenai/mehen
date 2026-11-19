import { describe, expect, it } from "vitest"
import { eligibility, type AccessAsk, type AccessState } from "../src/vault/access.ts"
import { consentBasis, consentIsCurrent } from "../src/vault/areas/approvals-workspace.ts"
import { workspaceAccessState } from "./workspace-fixtures.ts"
const NOW = 1_800_000_000_000
export function fourEyesState(): AccessState {
  const state = workspaceAccessState(NOW)
  for (const project of state.projects) {
    const env = project.environments.find((e) => e.name === "prod")!
    env.references = [{ variable: "TOKEN", field: "key", item: "itm_workspace", home: { kind: "workspace" }, revision: 1 }]
    env.fourEyes = true
  }
  state.shares.push({ id: "shr_manager_b", project: "prj_b", subject: { kind: "member", member: "mem_member" }, level: "manage", protected: true, expiresAt: null })
  return state
}
const ASK: AccessAsk = { device: "dev_kim", credential: "itm_workspace", credentials: ["itm_workspace"], context: { project: "prj_a", environment: "prod" } }
describe("workspace approval eligibility and immutable consent", () => {
  it("refuses the B-only manager and Kim's own project, admits a manager of both and an owner", () => {
    const state = fourEyesState()
    expect(eligibility(state, "mem_member", ASK, NOW).canApprove).toBe(false)
    expect(eligibility(state, "mem_kim", ASK, NOW).canApprove).toBe(false)
    expect(() => consentBasis(state, "mem_member", ASK, NOW, { sessionCheck: null, session: "ses_owner", account: "acc_owner", securityEpoch: 0 })).toThrow("not an eligible approver")
    state.shares.push({ id: "shr_manager_a", project: "prj_a", subject: { kind: "member", member: "mem_member" }, level: "manage", protected: true, expiresAt: null })
    for (const member of ["mem_member", "mem_owner"]) {
      const rights = eligibility(state, member, ASK, NOW)
      expect(rights.canApprove).toBe(true)
      expect(rights.canReadAskDetail).toBe(true)
    }
  })
  for (const loss of ["requester-share", "device-project", "device-protected", "decider-role", "reference", "four-eyes"] as const) {
    it(`voids consent after ${loss} changes with no mutation`, () => {
      const state = fourEyesState()
      const lineage = { id: "cns_test", decision: "apr_test", basis: consentBasis(state, "mem_owner", ASK, NOW, { sessionCheck: null, session: "ses_owner", account: "acc_owner", securityEpoch: 0 }), createdAt: NOW, expiresAt: NOW + 60_000, revokedAt: null }
      expect(consentIsCurrent(state, lineage, ASK, NOW)).toBe(true)
      if (loss === "requester-share") state.shares = state.shares.filter((s) => s.id !== "shr_kim")
      if (loss === "device-project") state.devices.find((d) => d.id === "dev_kim")!.scope.projects = ["prj_b"]
      if (loss === "device-protected") state.devices.find((d) => d.id === "dev_kim")!.scope.maxEnvironment = "unprotected"
      if (loss === "decider-role") state.members.find((m) => m.id === "mem_owner")!.standing.effectiveRole = "member"
      if (loss === "reference") state.projects[1]!.environments[1]!.revision++
      if (loss === "four-eyes") state.projects[1]!.environments[1]!.fourEyes = false
      const before = structuredClone(state)
      expect(consentIsCurrent(state, lineage, ASK, NOW)).toBe(false)
      expect(state).toEqual(before)
    })
  }
  it("lets a push's decider be only one who sees the credential carrying it, a private one only its owner", () => {
    const state = workspaceAccessState(NOW)
    state.devices.find((d) => d.id === "dev_member")!.scope.privateCredentials = true
    const push = (via: string, credential = "itm_workspace"): AccessAsk => ({ device: "dev_member", credential, credentials: [credential, via], via, context: null })
    expect(eligibility(state, "mem_member", push("itm_member"), NOW).canApprove).toBe(true)
    expect(eligibility(state, "mem_member", push("itm_workspace", "itm_member"), NOW).canApprove).toBe(true)
    // Another member's private via: their machine may not use it, and no one decides.
    expect(eligibility(state, "mem_member", push("itm_owner"), NOW).canApprove).toBe(false)
    expect(eligibility(state, "mem_owner", push("itm_owner"), NOW).canApprove).toBe(false)
    // The via must be the second credential named, never the first again.
    expect(eligibility(state, "mem_member", { ...push("itm_member"), credentials: ["itm_workspace"] }, NOW).canApprove).toBe(false)
    expect(eligibility(state, "mem_member", push("itm_workspace"), NOW).canApprove).toBe(false)
  })
  it("never lets a guest approve their machine's push of a shared credential, whatever carries it", () => {
    const state = workspaceAccessState(NOW)
    for (const project of state.projects) for (const env of project.environments) if (env.protected) env.references = []
    state.credentials.push({ id: "itm_project_github", home: { kind: "project", project: "prj_a" }, tags: [] })
    state.devices.find((d) => d.id === "dev_guest")!.scope.privateCredentials = true
    const push = (via: string): AccessAsk => ({ device: "dev_guest", credential: "itm_project", credentials: ["itm_project", via], via, context: null })
    // The guest's own private via widens nothing: the shared credential still needs a manager, and the manager may not decide over the guest's private via.
    expect(eligibility(state, "mem_guest", push("itm_guest"), NOW).canApprove).toBe(false)
    expect(eligibility(state, "mem_kim", push("itm_guest"), NOW).canApprove).toBe(false)
    // A shared via: the project's manager decides, the guest still does not.
    expect(eligibility(state, "mem_kim", push("itm_project_github"), NOW).canApprove).toBe(true)
    expect(eligibility(state, "mem_guest", push("itm_project_github"), NOW).canApprove).toBe(false)
  })
  it("retains a healthy consent independently of a spent start grant", () => {
    const state = fourEyesState()
    const lineage = { id: "cns_test", decision: "apr_test", basis: consentBasis(state, "mem_owner", ASK, NOW, { sessionCheck: null, session: "ses_owner", account: "acc_owner", securityEpoch: 0 }), createdAt: NOW, expiresAt: NOW + 60_000, revokedAt: null }
    expect(consentIsCurrent(state, lineage, ASK, NOW + 1)).toBe(true)
    expect(consentIsCurrent(state, { ...lineage, revokedAt: NOW }, ASK, NOW + 1)).toBe(false)
    expect(consentIsCurrent(state, lineage, ASK, NOW + 60_000)).toBe(false)
  })
})

import { vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { projectFixture, projectState, inAccess, callProject } from "./projects-workspace-fixture.ts"
import { prepareApprovedUse } from "../src/vault/areas/projects-workspace.ts"
import { workspaceApproval, type WorkspaceApprovalRow } from "../src/vault/areas/approvals-workspace.ts"
import { digestOf } from "../src/vault/areas/approvals.ts"
import { VaultError } from "../src/http.ts"
describe("all-applicable-project runtime approval", () => {
  it("refuses B-only and self, without writes/opens/sends, then admits both-project manager and owner", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      ctx.sql.exec("UPDATE vars SET item='key-workspace' WHERE project='prj_a' AND env='prod'")
      ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_b','prod','TOKEN','key-workspace','key','member:mem_owner',?)", ctx.now())
      ctx.sql.exec("INSERT INTO project_shares VALUES('shr_both_b','prj_b','member','mem_member',?)", canonicalJson({ id: "shr_both_b", project: "prj_b", subject: { kind: "member", member: "mem_member" }, level: "manage", protected: true, expiresAt: null }))
      const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "workspace")!, caller = { principal: { kind: "device" as const, deviceId: "dev_kim" }, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation: { title: "Protected", details: [], body: null }, batch: { floor: [], shape: "test-shape", replaces: null } }, credential = { ...item, slug: "key-workspace", version: 1 }, context = { project: "prj_a", env: "prod" }, subject = { item: "key-workspace", method: "POST", url: "https://api.example.com/", contentType: null, contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf(null), constraints: { uses: 1, ttlSeconds: 600 } }
      const required = prepareApprovedUse(ctx, state, caller, credential, context, subject, null, ctx.now()), row = workspaceApproval(ctx, required.approvalId)!, action = { type: "approval.decide" as const, approval: row.id, digest: row.digest, decision: "approve" as const, constraints: subject.constraints }
      const before = canonicalJson([ctx.sql.exec("SELECT * FROM approvals").toArray(), ctx.sql.exec("SELECT * FROM protected_use_grants").toArray(), ctx.sql.exec("SELECT * FROM consent_lineage").toArray()]), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      for (const role of ["member", "kim"]) {
        try { callProject(ctx, projectState(ctx), role, "approvals.decide", { id: row.id, decision: "approve" }, action); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON()).toEqual({ error: "forbidden", message: "You are not allowed to do that." }) }
      }
      expect(canonicalJson([ctx.sql.exec("SELECT * FROM approvals").toArray(), ctx.sql.exec("SELECT * FROM protected_use_grants").toArray(), ctx.sql.exec("SELECT * FROM consent_lineage").toArray()])).toBe(before)
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
      ctx.sql.exec("UPDATE project_shares SET value=? WHERE id='shr_direct'", canonicalJson({ id: "shr_direct", project: "prj_a", subject: { kind: "member", member: "mem_member" }, level: "manage", protected: true, expiresAt: null }))
      const view = callProject(ctx, projectState(ctx), "member", "approvals.decide", { id: row.id, decision: "approve" }, action) as import("@mehen/protocol").ApprovalViewProjection
      expect(view.view).toBe("detail")
      if (view.view === "detail") {
        expect(view.approval.eligibility).toMatchObject({ canApprove: true, canReadAskDetail: true })
        const binding = view.binding
        expect(digestOf({ subject: JSON.parse(row.subject), ...binding })).toBe(row.digest)
        expect(canonicalJson(view)).not.toContain("prj_b")
        expect(canonicalJson(view)).not.toContain("referenceRevisions")
      }
      const next = prepareApprovedUse(ctx, projectState(ctx), caller, credential, context, { ...subject, bodySha256: digestOf("second") }, null, ctx.now()), nextRow = workspaceApproval(ctx, next.approvalId)!
      expect(callProject(ctx, projectState(ctx), "owner", "approvals.decide", { id: nextRow.id, decision: "approve" }, { ...action, approval: nextRow.id, digest: nextRow.digest })).toMatchObject({ view: "detail" })
    })
  })
})

import type { ApprovalGroupRow, ApprovalViewProjection } from "@mehen/protocol"
import { batchAsk, batchActionFor, decideBatch, groupView, outcomes, projectBCredential, runAsk } from "./approvals-batch-support.ts"
// Review together (design 3.3): what each row of a group may do in a batch,
// and one passkey deciding a list, each entry on its own.
describe("a review group's rows", () => {
  const detail = (row: ApprovalGroupRow | undefined) => { if (row?.view !== "detail") throw new Error("Expected a detail row"); return row }
  it("states each row: routine, floor (named or unknown), own-page for a warning; the older of one shape names the newest", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      // Each ask a second after the last: asks made in one millisecond sort by their random id.
      const start = ctx.now(), clock = vi.spyOn(ctx, "now")
      let asked = 0
      const ask = (a: Parameters<typeof batchAsk>[1]) => { clock.mockReturnValue(start + ++asked * 1000); return batchAsk(ctx, a) }
      const older = ask({ body: "a" }), newer = ask({ body: "b" })
      const other = ask({ body: "c", shape: "shape-delete", floor: ["destructive"] })
      const unknown = ask({ body: "d", shape: "shape-run", floor: null })
      const warned = ask({ body: "e", shape: "shape-warned", title: "Write \u202Ea record" })
      expect(new Set([older, newer, other, unknown, warned].map((r) => r.review_group)).size).toBe(1)
      const view = groupView(ctx, "kim", older.review_group!)
      expect(view).toMatchObject({ group: older.review_group, kind: "machine", workspace: { id: ctx.tenant, slug: "work" }, machine: { device: "dev_kim", owner: { kind: "member", member: "mem_kim" }, workload: null }, item: { slug: "key-workspace" }, reason: null })
      expect(view.rows.map((r) => detail(r).approval.approval)).toEqual([older.id, newer.id, other.id, unknown.id, warned.id])
      expect(view.rows.map((r) => { const d = detail(r); return [d.batch, d.ownPage, d.floor, d.protected, d.newerSameShape] })).toEqual([
        ["routine", null, [], false, newer.id],
        ["routine", null, [], false, null],
        ["floor", null, ["destructive"], false, null],
        ["floor", null, [], false, null],
        ["own-page", "warning", [], false, null],
      ])
      expect(JSON.stringify(view)).not.toContain("shape-")
      // An owner may only deny what Kim's machine asks: every row but the warned one is deny-only.
      expect(groupView(ctx, "owner", older.review_group!).rows.map((r) => [r.batch, r.view === "detail" ? r.ownPage : null])).toEqual([["deny-only", null], ["deny-only", null], ["deny-only", null], ["deny-only", null], ["own-page", "warning"]])
      clock.mockRestore()
    })
  })
  it("marks a protected credential's use Protected, batchable but never ticked; a four-eyes use is own-page", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const fourEyes = batchAsk(ctx, { slug: "key-project", context: { project: "prj_a", env: "prod" } })
      expect(detail(groupView(ctx, "owner", fourEyes.review_group!).rows[0])).toMatchObject({ batch: "own-page", ownPage: "four-eyes", protected: true })
      ctx.sql.exec("UPDATE environments SET four_eyes=0 WHERE project='prj_a' AND name='prod'")
      const plain = batchAsk(ctx, { slug: "key-project", context: { project: "prj_a", env: "prod" }, body: "again" })
      const row = detail(groupView(ctx, "kim", plain.review_group!).rows.find((r) => r.view === "detail" && r.approval.approval === plain.id))
      expect(row).toMatchObject({ batch: "floor", ownPage: null, floor: [], protected: true })
    })
  })
  it("shows another member only the rows they may see, and an unseen group as one that does not exist", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const row = batchAsk(ctx)
      const refusal = (id: string) => { try { groupView(ctx, "guest", id); return null } catch (error) { return (error as VaultError).toJSON() } }
      expect(refusal(row.review_group!)).toEqual(refusal("grp_absent"))
      expect(refusal("grp_absent")).toEqual({ error: "not_found", message: "No such object." })
    })
  })
  it("keeps rows a viewer may not see, and a bundle's workload and reason when they may read no row, out of the view and its ETag", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      // The route's ETag hashes this canonical view, so an unchanged view is an unchanged ETag.
      const seen = (id: string) => canonicalJson(groupView(ctx, "kim", id))
      // One group of Member's machine on key-workspace: Kim, a manager of prj_a, sees an ask in prj_a; she may not see one with no project.
      const shown = batchAsk(ctx, { device: "dev_member", context: { project: "prj_a", env: "dev" }, body: "shown" })
      const before = seen(shown.review_group!)
      const hidden = batchAsk(ctx, { device: "dev_member", body: "sentinel-hidden-body", title: "sentinel-hidden-title" })
      expect(hidden.review_group).toBe(shown.review_group)
      expect(groupView(ctx, "member", shown.review_group!).rows).toHaveLength(2)
      expect(seen(shown.review_group!)).toBe(before)
      expect(before).not.toContain(hidden.id)
      expect(before).not.toContain("sentinel")
      // A bundle where Kim may only deny one ask and may not see the other.
      await projectBCredential(ctx, "key-b-dev", "dev")
      const denyOnly = batchAsk(ctx, { device: "dev_member", slug: "key-b-dev", context: { project: "prj_a", env: "dev" } })
      ctx.sql.exec("INSERT INTO approval_bundles(id,device,workload,reason,created_at,expires_at) VALUES('bnd_mixed','dev_member','wkl_sentinel','sentinel-reason',?,?)", ctx.now(), ctx.now() + 3_600_000)
      ctx.sql.exec("UPDATE approvals SET bundle='bnd_mixed' WHERE id=?", denyOnly.id)
      const bundled = seen("bnd_mixed")
      ctx.sql.exec("UPDATE approvals SET bundle='bnd_mixed' WHERE id=?", hidden.id)
      expect(seen("bnd_mixed")).toBe(bundled)
      expect(groupView(ctx, "kim", "bnd_mixed")).toMatchObject({ kind: "bundle", machine: { device: "dev_member", workload: null }, reason: null, rows: [{ view: "stop", batch: "deny-only" }] })
      for (const sentinel of ["sentinel", hidden.id]) expect(bundled).not.toContain(sentinel)
    })
  })
  it("gives a machine group one stored code while it has an open ask, and a new one each time it reopens", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const start = ctx.now(), clock = vi.spyOn(ctx, "now").mockReturnValue(start)
      const first = batchAsk(ctx, { body: "a" })
      const code = groupView(ctx, "kim", first.review_group!).code
      expect(code).toMatch(/^[ABCDEFGHJKMNPQRSTVWXYZ2-9]{6}$/)
      clock.mockReturnValue(start + 1_800_000)
      const second = batchAsk(ctx, { body: "b" })
      expect(second.review_group).toBe(first.review_group)
      expect(groupView(ctx, "kim", first.review_group!).code).toBe(code)
      // Past the first ask's hour the second is still open: the code stays.
      clock.mockReturnValue(start + 3_600_001)
      expect(groupView(ctx, "kim", first.review_group!).code).toBe(code)
      // Once every ask of it has run out, the group's next ask reopens it with a new code.
      clock.mockReturnValue(start + 1_800_000 + 3_600_001)
      const third = batchAsk(ctx, { body: "c" })
      expect(third.review_group).toBe(first.review_group)
      const reopened = groupView(ctx, "kim", first.review_group!).code
      expect(reopened).not.toBe(code)
      // Decided a minute later, the group closes: an ask in the same hour reopens it with a new code too.
      const entries = [{ id: third.id, decision: "approve" as const }]
      expect(outcomes(decideBatch(ctx, "kim", entries, batchActionFor(ctx, "kim", entries)))).toEqual({ [third.id]: "approved" })
      clock.mockReturnValue(start + 1_800_000 + 3_660_001)
      expect(batchAsk(ctx, { body: "d" }).review_group).toBe(first.review_group)
      const fresh = groupView(ctx, "kim", first.review_group!).code
      expect([code, reopened]).not.toContain(fresh)
      expect(ctx.sql.exec("SELECT COUNT(*) AS n FROM approval_group_codes").one().n).toBe(1)
      expect(ctx.sql.exec<{ code: string }>("SELECT code FROM approval_group_codes WHERE review_group=?", first.review_group).one().code).toBe(fresh)
      clock.mockRestore()
    })
  })
  it("approves only the asks the page showed: one that joined the group after stays pending, and the signed list cannot be stretched to it", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const a = batchAsk(ctx, { body: "a" }), b = batchAsk(ctx, { body: "b" })
      const shown = groupView(ctx, "kim", a.review_group!).rows.flatMap((r) => r.view === "detail" ? [r.approval.approval] : [])
      const entries = shown.map((id) => ({ id, decision: "approve" as const }))
      const action = batchActionFor(ctx, "kim", entries)
      const late = batchAsk(ctx, { body: "late" })
      expect(late.review_group).toBe(a.review_group)
      expect(() => decideBatch(ctx, "kim", [...entries, { id: late.id, decision: "approve" }], action)).toThrow()
      expect(workspaceApproval(ctx, late.id)!.status).toBe("pending")
      expect(outcomes(decideBatch(ctx, "kim", entries, action))).toEqual({ [a.id]: "approved", [b.id]: "approved" })
      expect(workspaceApproval(ctx, late.id)!.status).toBe("pending")
    })
  })
  it("lists an ask with no binding to check as own-page unbound, and refuses it in a batch", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const row = batchAsk(ctx)
      ctx.sql.exec("UPDATE approvals SET snapshot_digest=NULL WHERE id=?", row.id)
      expect(detail(groupView(ctx, "kim", row.review_group!).rows[0])).toMatchObject({ batch: "own-page", ownPage: "unbound" })
      expect(outcomes(decideBatch(ctx, "kim", [{ id: row.id, decision: "approve" }]))).toEqual({ [row.id]: "own_page" })
      expect(workspaceApproval(ctx, row.id)!.status).toBe("pending")
    })
  })
})

describe("deciding a batch", () => {
  it("decides each entry on its own: one approved, the rest decided, expired, superseded or for their own page", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const fresh = batchAsk(ctx, { body: "1" }), decided = batchAsk(ctx, { body: "2" }), expired = batchAsk(ctx, { body: "3" })
      const replaced = batchAsk(ctx, { body: "4", shape: "shape-replace" }), warned = batchAsk(ctx, { body: "5", title: "Write \u202Ea record" })
      const entries = [fresh, decided, expired, replaced, warned].map((r) => ({ id: r.id, decision: "approve" as const }))
      const action = batchActionFor(ctx, "kim", entries)
      callProject(ctx, projectState(ctx), "kim", "approvals.decide", { id: decided.id, decision: "deny" }, { type: "approval.decide", approval: decided.id, digest: decided.digest, decision: "deny", constraints: { uses: 1, ttlSeconds: 600 } })
      ctx.sql.exec("UPDATE approvals SET expires_at=? WHERE id=?", ctx.now() - 1, expired.id)
      batchAsk(ctx, { body: "4 again", shape: "shape-replace", replaces: replaced.id })
      const result = decideBatch(ctx, "kim", entries, action)
      expect(outcomes(result)).toEqual({ [fresh.id]: "approved", [decided.id]: "decided", [expired.id]: "expired", [replaced.id]: "superseded", [warned.id]: "own_page" })
      expect(result).toMatchObject({ batch: expect.stringMatching(/^apb_/), approved: 1, denied: 0, skipped: 4 })
      expect(result.results.map((r) => r.approval)).toEqual([...result.results.map((r) => r.approval)].sort())
      expect(ctx.sql.exec("SELECT approval,uses_left FROM protected_use_grants").toArray()).toEqual([{ approval: fresh.id, uses_left: 1 }])
      expect(ctx.sql.exec("SELECT id,status FROM approvals WHERE id IN (?,?)", warned.id, fresh.id).toArray().sort((a, b) => String(a.id).localeCompare(String(b.id)))).toEqual([{ id: fresh.id, status: "approved" }, { id: warned.id, status: "pending" }].sort((a, b) => a.id.localeCompare(b.id)))
      const audit = ctx.sql.exec<{ action: string; target: string; detail: string }>("SELECT action,target,detail FROM audit WHERE action IN ('approval.approve','approval.batch') ORDER BY seq").toArray().map((a) => ({ ...a, detail: JSON.parse(a.detail) as unknown }))
      expect(audit).toEqual([
        { action: "approval.approve", target: fresh.id, detail: { item: "key-workspace", device: "dev_kim", outcome: "approve", batch: result.batch } },
        { action: "approval.batch", target: result.batch, detail: { approved: 1, denied: 0, skipped: 4 } },
      ])
    })
  })
  it("refuses a four-eyes ask in a batch, so it is decided on its own page", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const fourEyes = batchAsk(ctx, { slug: "key-project", context: { project: "prj_a", env: "prod" } })
      for (const decision of ["approve", "deny"] as const) expect(outcomes(decideBatch(ctx, "owner", [{ id: fourEyes.id, decision }]))).toEqual({ [fourEyes.id]: "own_page" })
      expect(workspaceApproval(ctx, fourEyes.id)!.status).toBe("pending")
    })
  })
  it("lists a run and a four-eyes ask as own-page to a person who may deny them but not read them, refuses them in a batch, and still lets them deny another", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      await projectBCredential(ctx, "key-b-dev", "dev")
      await projectBCredential(ctx, "key-b-prod", "prod")
      const plain = batchAsk(ctx, { device: "dev_member", slug: "key-b-dev", context: { project: "prj_a", env: "dev" } })
      const fourEyes = batchAsk(ctx, { device: "dev_member", slug: "key-b-prod", context: { project: "prj_a", env: "prod" } })
      const run = await runAsk(ctx)
      const view = (id: string) => (callProject(ctx, projectState(ctx), "kim", "approvals.view", { id }) as ApprovalViewProjection).view
      expect([view(plain.id), view(fourEyes.id)]).toEqual(["stop", "stop"])
      const stopRow = (ask: WorkspaceApprovalRow) => { const row = groupView(ctx, "kim", ask.review_group!).rows.find((r) => r.view === "stop" && r.stop.id === ask.id); if (!row) throw new Error("Expected a stop row"); return row }
      // What the page may tick from a row: a deny-only row is denied, an own-page row is left for its page.
      const ticked = (ask: WorkspaceApprovalRow) => stopRow(ask).batch === "own-page" ? "own_page" : "denied"
      expect([stopRow(fourEyes).batch, stopRow(plain).batch]).toEqual(["own-page", "deny-only"])
      expect(stopRow(fourEyes)).toEqual({ view: "stop", stop: expect.objectContaining({ id: fourEyes.id }), batch: "own-page" })
      const denyAll = (rows: { id: string }[]) => rows.map((r) => ({ id: r.id, decision: "deny" as const }))
      const expected = { [fourEyes.id]: ticked(fourEyes), [plain.id]: ticked(plain) }
      expect(expected).toEqual({ [fourEyes.id]: "own_page", [plain.id]: "denied" })
      expect(outcomes(decideBatch(ctx, "kim", denyAll([fourEyes, plain])))).toEqual(expected)
      // Kim's share ends with the clock, not a write: she may still deny her machine's run but no longer read it.
      ctx.sql.exec("UPDATE project_shares SET value=json_set(value,'$.expiresAt',?) WHERE id='shr_kim'", new Date(ctx.now() - 1000).toISOString())
      expect(view(run.id)).toBe("stop")
      expect(stopRow(run).batch).toBe("own-page")
      expect(outcomes(decideBatch(ctx, "kim", denyAll([run])))).toEqual({ [run.id]: ticked(run) })
      expect([run, fourEyes, plain].map((r) => workspaceApproval(ctx, r.id)!.status)).toEqual(["pending", "pending", "denied"])
    })
  })
  it("records the batch with what it decided when an unexpected error stops it, keeping the entries already decided", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const rows = [batchAsk(ctx, { body: "1" }), batchAsk(ctx, { body: "2" }), batchAsk(ctx, { body: "3" })].sort((a, b) => a.id < b.id ? -1 : 1)
      const entries = rows.map((r) => ({ id: r.id, decision: "deny" as const }))
      const action = batchActionFor(ctx, "kim", entries)
      const audit = ctx.audit.bind(ctx)
      const failing = vi.spyOn(ctx, "audit").mockImplementation((event) => { if (event.target === rows[1]!.id) throw new Error("Injected failure"); audit(event) })
      expect(() => decideBatch(ctx, "kim", entries, action)).toThrow("Injected failure")
      failing.mockRestore()
      expect(rows.map((r) => workspaceApproval(ctx, r.id)!.status)).toEqual(["denied", "pending", "pending"])
      expect(ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='approval.batch'").toArray().map((a) => JSON.parse(a.detail) as unknown)).toEqual([{ approved: 0, denied: 1, skipped: 2 }])
    })
  })
  it("refuses a run's ask in a batch, so it is decided on its own page", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const run = await runAsk(ctx)
      expect(groupView(ctx, "owner", run.review_group!).rows[0]).toMatchObject({ view: "detail", batch: "own-page", ownPage: "run" })
      for (const decision of ["approve", "deny"] as const) expect(outcomes(decideBatch(ctx, "owner", [{ id: run.id, decision }]))).toEqual({ [run.id]: "own_page" })
      expect(workspaceApproval(ctx, run.id)!.status).toBe("pending")
    })
  })
  it("ends an approval stale when four-eyes or the asker's rights changed since it was asked", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const rights = batchAsk(ctx, { context: { project: "prj_a", env: "dev" }, body: "rights" })
      ctx.sql.exec("UPDATE environments SET four_eyes=0 WHERE project='prj_a' AND name='prod'")
      const fourEyes = batchAsk(ctx, { slug: "key-project", context: { project: "prj_a", env: "prod" }, body: "four-eyes" })
      ctx.sql.exec("UPDATE environments SET four_eyes=1 WHERE project='prj_a' AND name='prod'")
      expect(outcomes(decideBatch(ctx, "owner", [{ id: fourEyes.id, decision: "approve" }]))).toEqual({ [fourEyes.id]: "stale" })
      ctx.sql.exec("UPDATE project_shares SET value=json_set(value,'$.level','edit') WHERE id='shr_kim'")
      expect(outcomes(decideBatch(ctx, "kim", [{ id: rights.id, decision: "approve" }]))).toEqual({ [rights.id]: "stale" })
      expect([fourEyes, rights].map((r) => workspaceApproval(ctx, r.id)!.status)).toEqual(["pending", "pending"])
      expect(ctx.sql.exec("SELECT COUNT(*) AS n FROM protected_use_grants").toArray()).toEqual([{ n: 0 }])
    })
  })
  it("leaves an entry undecided as changed when its stored digest no longer matches the signed list", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const rows = [batchAsk(ctx, { body: "1" }), batchAsk(ctx, { body: "2" })].sort((a, b) => a.id < b.id ? -1 : 1)
      const entries = rows.map((r) => ({ id: r.id, decision: "deny" as const }))
      const action = batchActionFor(ctx, "kim", entries)
      // The second ask's digest changes in storage while the first is decided.
      const audit = ctx.audit.bind(ctx)
      const changing = vi.spyOn(ctx, "audit").mockImplementation((event) => { if (event.target === rows[0]!.id) ctx.sql.exec("UPDATE approvals SET digest='changed' WHERE id=?", rows[1]!.id); audit(event) })
      const result = decideBatch(ctx, "kim", entries, action)
      changing.mockRestore()
      expect(outcomes(result)).toEqual({ [rows[0]!.id]: "denied", [rows[1]!.id]: "changed" })
      expect(rows.map((r) => workspaceApproval(ctx, r.id)!.status)).toEqual(["denied", "pending"])
    })
  })
  it("ends every entry stale when the asking machine is revoked mid-batch", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const rows = [batchAsk(ctx, { body: "1" }), batchAsk(ctx, { body: "2" })]
      const entries = rows.map((r) => ({ id: r.id, decision: "approve" as const }))
      const action = batchActionFor(ctx, "kim", entries)
      ctx.sql.exec("UPDATE devices SET revoked_at=? WHERE id='dev_kim'", ctx.now())
      const result = decideBatch(ctx, "kim", entries, action)
      expect(outcomes(result)).toEqual(Object.fromEntries(rows.map((r) => [r.id, "stale"])))
      expect(ctx.sql.exec("SELECT COUNT(*) AS n FROM protected_use_grants").toArray()).toEqual([{ n: 0 }])
    })
  })
  it("lets a person who may only deny deny a batch, and refuses each approval", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const rows = [batchAsk(ctx, { body: "1" }), batchAsk(ctx, { body: "2" })]
      const result = decideBatch(ctx, "owner", [{ id: rows[0]!.id, decision: "deny" }, { id: rows[1]!.id, decision: "approve" }])
      expect(outcomes(result)).toEqual({ [rows[0]!.id]: "denied", [rows[1]!.id]: "forbidden" })
      expect(result).toMatchObject({ approved: 0, denied: 1, skipped: 1 })
      expect(rows.map((r) => workspaceApproval(ctx, r.id)!.status)).toEqual(["denied", "pending"])
    })
  })
  it("refuses duplicates, more than 25, a remember, and an unseen id exactly as a missing one", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const row = batchAsk(ctx)
      const refusal = (role: string, input: unknown) => { try { callProject(ctx, projectState(ctx), role, "approvals.action_many", input); return null } catch (error) { return (error as VaultError).toJSON() } }
      expect(refusal("owner", { entries: [{ id: row.id, decision: "approve" }, { id: row.id, decision: "deny" }] })).toEqual({ error: "bad_request", message: "Each ask may appear once in a batch." })
      expect(refusal("owner", { entries: Array.from({ length: 26 }, (_, i) => ({ id: `apr_${i}`, decision: "deny" })) })).toMatchObject({ error: "bad_request" })
      expect(refusal("owner", { entries: [{ id: row.id, decision: "approve", remember: { kind: "rule" } }] })).toMatchObject({ error: "bad_request" })
      expect(refusal("guest", { entries: [{ id: row.id, decision: "deny" }] })).toEqual(refusal("guest", { entries: [{ id: "apr_absent", decision: "deny" }] }))
      expect(refusal("guest", { entries: [{ id: "apr_absent", decision: "deny" }] })).toEqual({ error: "not_found", message: "No such object." })
    })
  })
})
