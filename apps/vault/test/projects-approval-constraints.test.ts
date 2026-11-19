import { describe, expect, it, vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { prepareApprovedUse, assertApprovedUse, consumeApprovedUse } from "../src/vault/areas/projects-workspace.ts"
import { workspaceApproval } from "../src/vault/areas/approvals-workspace.ts"
import { digestOf } from "../src/vault/areas/approvals.ts"
import { projectFixture, projectState, inAccess, callProject } from "./projects-workspace-fixture.ts"
import { VaultError } from "../src/http.ts"
const SUBJECT = { item: "key-workspace", method: "POST", url: "https://api.example.com/", contentType: null, contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf(null), constraints: { uses: 3, ttlSeconds: 600 } }
const PRESENTATION = { title: "Write records", details: [], body: null }
describe("workspace exact approval constraints", () => {
  it("enforces fewer approved uses and a narrower TTL, then requires a new ask when spent", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "workspace")!, caller = { principal: { kind: "device" as const, deviceId: "dev_member" }, workspace: { id: ctx.tenant, slug: "work", name: "Work" }, presentation: PRESENTATION, batch: { floor: [], shape: "test-shape", replaces: null } }, checked = { ...item, slug: "key-workspace", version: 1 }
      const required = prepareApprovedUse(ctx, state, caller, checked, null, SUBJECT, null, ctx.now()), row = workspaceApproval(ctx, required.approvalId)!, constraints = { uses: 2, ttlSeconds: 120 }
      callProject(ctx, state, "member", "approvals.decide", { id: row.id, decision: "approve", constraints }, { type: "approval.decide", approval: row.id, digest: row.digest, decision: "approve", constraints })
      expect(ctx.sql.exec<{ uses_left: number; expires_at: number }>("SELECT uses_left,expires_at FROM protected_use_grants").toArray()[0]).toMatchObject({ uses_left: 2 })
      for (let i=0;i<2;i++) ctx.storage.transactionSync(() => { assertApprovedUse(ctx, projectState(ctx), required.snapshot, row.id, ctx.now()); consumeApprovedUse(ctx, required.snapshot, row.id) })
      expect(() => assertApprovedUse(ctx, projectState(ctx), required.snapshot, row.id, ctx.now())).toThrow("no longer has a current approval")
      const next = prepareApprovedUse(ctx, projectState(ctx), caller, checked, null, SUBJECT, row.id, ctx.now())
      expect(next.kind).toBe("required"); expect(next.approvalId).not.toBe(row.id)
      const nextRow = workspaceApproval(ctx, next.approvalId)!
      callProject(ctx, projectState(ctx), "member", "approvals.decide", { id: nextRow.id, decision: "approve", constraints }, { type: "approval.decide", approval: nextRow.id, digest: nextRow.digest, decision: "approve", constraints })
      const expiresAt = ctx.sql.exec<{ expires_at: number }>("SELECT expires_at FROM protected_use_grants WHERE approval=?", nextRow.id).toArray()[0]!.expires_at
      expect(expiresAt-ctx.now()).toBeLessThanOrEqual(120_000)
      expect(() => assertApprovedUse({ ...ctx, now: () => expiresAt+1 }, projectState(ctx), next.snapshot, nextRow.id, expiresAt+1)).toThrow("no longer has a current approval")
    })
  })
  it("refuses uses/TTL above the requested ceiling and refuses remember without writes, opens or sends", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "workspace")!, required = prepareApprovedUse(ctx, state, { principal: { kind: "device", deviceId: "dev_member" }, workspace: { id: ctx.tenant, slug: "work", name: "Work" }, presentation: PRESENTATION, batch: { floor: [], shape: "test-shape", replaces: null } }, { ...item, slug: "key-workspace", version: 1 }, null, SUBJECT, null, ctx.now()), row = workspaceApproval(ctx, required.approvalId)!
      const before = canonicalJson(ctx.sql.exec("SELECT * FROM approvals").toArray()), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      for (const constraints of [{ uses: 4, ttlSeconds: 600 }, { uses: null, ttlSeconds: 600 }, { uses: 1, ttlSeconds: 601 }]) {
        try { callProject(ctx, state, "member", "approvals.decide", { id: row.id, decision: "approve", constraints }, { type: "approval.decide", approval: row.id, digest: row.digest, decision: "approve", constraints }); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON()).toEqual({ error: "bad_request", message: "Approval limits cannot exceed the requested limits." }) }
      }
      try { callProject(ctx, state, "member", "approvals.decide", { id: row.id, decision: "approve", remember: { kind: "exact", selector: { device: "dev_member", session: null } } }); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON()).toEqual({ error: "forbidden", message: "Policy widening is not available yet.", next: { command: "mehen policy propose --help", say: "Read the policy proposal options and try again." } }) }
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM approvals").toArray())).toBe(before)
      expect(ctx.sql.exec("SELECT * FROM protected_use_grants").toArray()).toEqual([])
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
})
