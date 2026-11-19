import { describe, expect, it, vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { prepareApprovedUse } from "../src/vault/areas/projects-workspace.ts"
import { storedApprovalProjection, workspaceApproval } from "../src/vault/areas/approvals-workspace.ts"
import { digestOf } from "../src/vault/areas/approvals.ts"
import { accessMember } from "./workspace-fixtures.ts"
import { projectFixture, projectState, inAccess, callProject } from "./projects-workspace-fixture.ts"
import { VaultError } from "../src/http.ts"
const FORBIDDEN_DETAIL = ["hidden-provider", "hidden-account", "private.example.com", "recipient@example.com", "hidden-field", "hidden-fingerprint", "private-request-body"]
describe("workspace private approval projection", () => {
  it("gives an owner/admin only an exact stop projection for pending and settled asks", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "member" && c.home.member === "mem_member")!
      const presentation = { title: "hidden-provider hidden-account", details: [{ label: "hidden-field", value: "hidden-fingerprint" }], body: "private-request-body", headers: [["x-recipient", "recipient@example.com"]] as [string, string][] }
      const required = prepareApprovedUse(ctx, state, { principal: { kind: "device", deviceId: "dev_member" }, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation, batch: { floor: [], shape: "test-shape", replaces: null } }, { ...item, slug: "key-member", version: 1 }, null, { item: "key-member", method: "POST", url: "https://private.example.com/write", contentType: null, contentEncoding: null, headersSha256: digestOf(presentation.headers), bodySha256: digestOf(presentation.body), constraints: { uses: 1, ttlSeconds: 600 } }, null, ctx.now())
      const row = workspaceApproval(ctx, required.approvalId)!
      for (const role of ["owner", "admin"]) {
        const view = storedApprovalProjection(ctx, state, accessMember(state, role), row)
        expect(view).toEqual({ view: "stop", id: row.id, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, machine: { device: "dev_member", name: "dev_member", owner: { kind: "member", member: "mem_member", name: "member" } }, item: { slug: "key-member" }, status: "pending", eligibility: { canApprove: false, canDeny: true, canReadAskDetail: false, deciders: [], reason: "Not an eligible approver" } })
        for (const detail of FORBIDDEN_DETAIL) expect(canonicalJson(view)).not.toContain(detail)
      }
      const own = storedApprovalProjection(ctx, state, accessMember(state, "member"), row)
      expect(own.view).toBe("detail")
      if (own.view === "detail") { expect(own.approval.eligibility.canApprove).toBe(true); expect(own.approval.eligibility.canReadAskDetail).toBe(true); expect(own.approval.request.body).toBe("private-request-body") }
      ctx.sql.exec("UPDATE approvals SET status='denied' WHERE id=?", row.id)
      const settled = storedApprovalProjection(ctx, state, accessMember(state, "admin"), workspaceApproval(ctx, row.id)!)
      expect(settled.view).toBe("stop"); expect(settled.view === "stop" && settled.status).toBe("denied")
      for (const detail of FORBIDDEN_DETAIL) expect(canonicalJson(settled)).not.toContain(detail)
      const before = canonicalJson(ctx.sql.exec("SELECT * FROM approvals").toArray())
      expect(() => storedApprovalProjection(ctx, state, accessMember(state, "guest"), row)).toThrow("No such object")
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM approvals").toArray())).toBe(before)
    })
  })
  it("denial-only approval is refused with no open, send or mutation", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "member" && c.home.member === "mem_member")!
      const required = prepareApprovedUse(ctx, state, { principal: { kind: "device", deviceId: "dev_member" }, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation: { title: "Private ask", details: [], body: null }, batch: { floor: [], shape: "test-shape", replaces: null } }, { ...item, slug: "key-member", version: 1 }, null, { item: "key-member", method: "POST", url: "https://private.example.com/", contentType: null, contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf(null), constraints: { uses: 1, ttlSeconds: 600 } }, null, ctx.now())
      const row = workspaceApproval(ctx, required.approvalId)!, open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      const before = canonicalJson(ctx.sql.exec("SELECT * FROM approvals").toArray())
      try { callProject(ctx, state, "admin", "approvals.decide", { id: row.id, decision: "approve" }, { type: "approval.decide", approval: row.id, digest: row.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 600 } }); throw new Error("accepted") } catch (error) {
        expect(error).toBeInstanceOf(VaultError)
        expect((error as VaultError).toJSON()).toEqual({ error: "forbidden", message: "You are not allowed to do that." })
      }
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM approvals").toArray())).toBe(before)
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
      const event = ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='approval.request' ORDER BY seq DESC LIMIT 1").toArray()[0]!
      expect(Object.keys(JSON.parse(event.detail)).sort()).toEqual(["action", "actor", "at", "item", "outcome", "run", "session", "slug"])
    })
  })
})

describe("replacing a private ask", () => {
  it("supersedes the earlier ask and records a private event, not a workspace line", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      const item = projectState(ctx).credentials.find((c) => c.home.kind === "member" && c.home.member === "mem_member")!
      const ask = (body: string, replaces: string | null) => prepareApprovedUse(ctx, projectState(ctx), { principal: { kind: "device", deviceId: "dev_member" }, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation: { title: "Private", details: [], body }, batch: { floor: [], shape: "private-shape", replaces } }, { ...item, slug: "key-member", version: 1 }, null, { item: "key-member", method: "POST", url: "https://private.example.com/", contentType: null, contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf(body), constraints: { uses: 1, ttlSeconds: 600 } }, null, ctx.now()).approvalId
      const first = ask("one", null), second = ask("two", first)
      expect(ctx.sql.exec("SELECT policy_status,superseded_by FROM approvals WHERE id=?", first).toArray()).toEqual([{ policy_status: "superseded", superseded_by: second }])
      const events = ctx.sql.exec<{ target: string; detail: string }>("SELECT target,detail FROM audit WHERE action='approval.supersede'").toArray()
      expect(events).toHaveLength(1)
      const detail = JSON.parse(events[0]!.detail) as Record<string, unknown>
      expect(Object.keys(detail).sort()).toEqual(["action", "actor", "at", "item", "outcome", "run", "session", "slug"])
      expect(detail).toMatchObject({ action: "approval.supersede", item: item.id, slug: "key-member", outcome: "superseded" })
      expect(canonicalJson(events)).not.toContain("private.example.com")
    })
  })
})

describe("private ask mutation visibility", () => {
  for (const decision of ["approve", "deny"] as const) it(`foreign-private ${decision} and absent approval are byte-identical not_found`, async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "member" && c.home.member === "mem_member")!
      const required = prepareApprovedUse(ctx, state, { principal: { kind: "device", deviceId: "dev_member" }, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation: { title: "Private", details: [], body: null }, batch: { floor: [], shape: "test-shape", replaces: null } }, { ...item, slug: "key-member", version: 1 }, null, { item: "key-member", method: "POST", url: "https://api.example.com/", contentType: null, contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf(null), constraints: { uses: 1, ttlSeconds: 600 } }, null, ctx.now())
      const row = workspaceApproval(ctx, required.approvalId)!, before = canonicalJson(ctx.sql.exec("SELECT * FROM approvals").toArray()), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      const failures = [row.id, "apr_absent"].map((id) => { try { callProject(ctx, state, "kim", "approvals.decide", { id, decision }, { type: "approval.decide", approval: id, digest: row.digest, decision, constraints: { uses: 1, ttlSeconds: 600 } }); return null } catch (error) { return (error as VaultError).toJSON() } })
      expect(failures).toEqual(Array(2).fill({ error: "not_found", message: "No such object." }))
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM approvals").toArray())).toBe(before)
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
})

import { batchAsk, batchActionFor, decideBatch, outcomes } from "./approvals-batch-support.ts"
describe("deciding a batch of private asks", () => {
  it("lets only the credential's owner approve, records the batch on the private event, and hides the ask from everyone else", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      const ask = (body: string) => batchAsk(ctx, { device: "dev_member", slug: "key-member", body })
      const [first, second] = [ask("one"), ask("two")]
      for (const role of ["owner", "admin"]) expect(outcomes(decideBatch(ctx, role, [{ id: first!.id, decision: "approve" }]))).toEqual({ [first!.id]: "forbidden" })
      const refusal = (id: string) => { try { batchActionFor(ctx, "kim", [{ id, decision: "deny" }]); return null } catch (error) { return (error as VaultError).toJSON() } }
      expect(refusal(first!.id)).toEqual(refusal("apr_absent"))
      expect(refusal("apr_absent")).toEqual({ error: "not_found", message: "No such object." })
      // Deciding straight away, with the list signed, says no more.
      const deciding = (id: string) => { try { decideBatch(ctx, "kim", [{ id, decision: "deny" }], { type: "approval.decide_many", entries: [{ approval: id, digest: first!.digest, decision: "deny", uses: 1, ttlSeconds: 600 }] }); return null } catch (error) { return (error as VaultError).toJSON() } }
      expect(deciding(first!.id)).toEqual(deciding("apr_absent"))
      expect(deciding(first!.id)).toEqual({ error: "not_found", message: "No such object." })
      expect(ctx.sql.exec("SELECT COUNT(*) AS n FROM audit WHERE action='approval.batch'").toArray()).toEqual([{ n: 2 }])
      const result = decideBatch(ctx, "member", [{ id: first!.id, decision: "approve" }, { id: second!.id, decision: "deny" }])
      expect(outcomes(result)).toEqual({ [first!.id]: "approved", [second!.id]: "denied" })
      const events = ctx.sql.exec<{ action: string; target: string; detail: string }>("SELECT action,target,detail FROM audit WHERE action IN ('approval.approve','approval.deny','approval.batch') ORDER BY seq").toArray()
      const decided = events.filter((e) => e.action !== "approval.batch").map((e) => JSON.parse(e.detail) as Record<string, unknown>)
      expect(decided.map((d) => [d.action, d.outcome, d.batch])).toEqual(result.results.map((r) => [r.outcome === "approved" ? "approval.approve" : "approval.deny", r.outcome === "approved" ? "approve" : "deny", result.batch]))
      for (const d of decided) expect(Object.keys(d).sort()).toEqual(["action", "actor", "at", "batch", "item", "outcome", "run", "session", "slug"])
      // The owner's and the admin's refused batches each counted one skipped.
      expect(events.filter((e) => e.action === "approval.batch").map((e) => JSON.parse(e.detail) as unknown)).toEqual([{ approved: 0, denied: 0, skipped: 1 }, { approved: 0, denied: 0, skipped: 1 }, { approved: 1, denied: 1, skipped: 0 }])
      expect(events.at(-1)?.target).toBe(result.batch)
      expect(canonicalJson(events)).not.toContain("private.example.com")
    })
  })
})
