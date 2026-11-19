import { describe, expect, it, vi } from "vitest"
import { onCredentialRemoved, prepareApprovedUse } from "../src/vault/areas/projects-workspace.ts"
import { workspaceApproval } from "../src/vault/areas/approvals-workspace.ts"
import { digestOf } from "../src/vault/areas/approvals.ts"
import { projectFixture, projectState, inAccess } from "./projects-workspace-fixture.ts"
describe("project credential removal hook", () => {
  for (const reason of ["deleted", "rehomed", "offboarded"] as const) it(`${reason} unsets references and stales pending approvals atomically`, async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "project")!
      const required = prepareApprovedUse(ctx, state, { principal: { kind: "device", deviceId: "dev_kim" }, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation: { title: "Test", details: [], body: null }, batch: { floor: [], shape: "test-shape", replaces: null } }, { ...item, slug: "key-project", version: 1 }, { project: "prj_a", env: "prod" }, { item: "key-project", method: "POST", url: "https://api.example.com/write", contentType: null, contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf(null), constraints: { uses: 1, ttlSeconds: 600 } }, null, ctx.now())
      const open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      ctx.storage.transactionSync(() => onCredentialRemoved(ctx, { ...item, slug: "key-project" }, reason, "mem_owner"))
      expect(ctx.sql.exec("SELECT * FROM vars WHERE item='key-project'").toArray()).toEqual([])
      expect(ctx.sql.exec<{ policy_status: string }>("SELECT policy_status FROM approvals WHERE id=?", required.approvalId).toArray()[0]!.policy_status).toBe("stale")
      expect(ctx.sql.exec<{ reference_rev: number; protection_rev: number }>("SELECT reference_rev,protection_rev FROM environments WHERE project='prj_a' AND name='prod'").toArray()[0]).toEqual({ reference_rev: 2, protection_rev: 2 })
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled()
      open.mockRestore(); send.mockRestore()
    })
  })
})

import { createProof } from "@mehen/protocol"
import { workspaceRunOps } from "../src/vault/areas/runs-workspace.ts"
import { VaultError } from "../src/http.ts"
it("voids a plain-only run ask that inherited the removed credential's reference graph", async () => {
  const f = await projectFixture()
  await inAccess(f.tenant, async (ctx) => {
    ctx.sql.exec("INSERT INTO vars(project,env,name,plain,updated_by,updated_at) VALUES('prj_a','prod','PLAIN','safe','member:mem_owner',?)", ctx.now())
    const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "project")!, proof = await createProof({ deviceId: "dev_kim", sign: async () => new Uint8Array(64) }, { method: "POST", url: "https://vault.test/v1/runs" }, { tenant: ctx.tenant })
    let approval: string | undefined
    try { await workspaceRunOps["runs.create"]!.handler(ctx, { kind: "device", deviceId: "dev_kim" }, { project: "prj_a", env: "prod", envSource: "flag", remote: null, worktree: "/fixture", head: null, command: "test", argv: ["test"], vars: ["PLAIN"] }, { auth: { kind: "device", proof, method: "POST", url: "https://vault.test/v1/runs", bodyHash: "" }, workspace: { id: ctx.tenant, slug: "work", name: "Work" } }) } catch (error) { if (!(error instanceof VaultError) || error.code !== "approval_required") throw error; approval = error.extra.approval }
    expect(approval).toBeDefined()
    ctx.storage.transactionSync(() => onCredentialRemoved(ctx, { ...item, slug: "key-project" }, "deleted", "mem_owner"))
    expect(ctx.sql.exec<{ policy_status: string }>("SELECT policy_status FROM approvals WHERE id=?", approval).toArray()[0]!.policy_status).toBe("stale")
  })
})

import { canonicalJson } from "@mehen/protocol"
import { approvedProjectRun, projectSecurityRows } from "./projects-workspace-fixture.ts"
describe("approved credential removal", () => {
  for (const reason of ["deleted", "rehomed", "offboarded"] as const) for (const rollback of [false, true]) {
    it(`${reason} voids approved run authority and protected-reference notices, rollback=${rollback}`, async () => {
      const f = await projectFixture()
      await inAccess(f.tenant, async (ctx) => {
        ctx.sql.exec("UPDATE vars SET item='key-workspace' WHERE project='prj_a' AND env='prod'")
        const active = await approvedProjectRun(ctx), item = projectState(ctx).credentials.find((c) => c.home.kind === "workspace")!
        const before = projectSecurityRows(ctx), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
        const remove = () => ctx.storage.transactionSync(() => {
          onCredentialRemoved(ctx, { ...item, slug: "key-workspace" }, reason, "mem_owner")
          if (rollback) throw new Error("parent transaction failed")
        })
        if (rollback) {
          expect(remove).toThrow("parent transaction failed")
          expect(projectSecurityRows(ctx)).toBe(before)
        } else {
          remove()
          expect(ctx.sql.exec("SELECT * FROM vars WHERE item='key-workspace'").toArray()).toEqual([])
          expect(workspaceApproval(ctx, active.approval)!.policy_status).toBe("stale")
          for (const table of ["protected_use_grants", "consent_lineage"]) expect(ctx.sql.exec<{ revoked_at: number | null }>(`SELECT revoked_at FROM ${table} WHERE ${table === "consent_lineage" ? "decision" : "approval"}=?`, active.approval).toArray()[0]!.revoked_at).not.toBeNull()
          expect(ctx.sql.exec<{ revoked_at: number | null }>("SELECT revoked_at FROM run_authorisations WHERE run=?", active.run).toArray()[0]!.revoked_at).not.toBeNull()
          expect(ctx.sql.exec<{ ended_at: number | null }>("SELECT ended_at FROM runs WHERE id=?", active.run).toArray()[0]!.ended_at).not.toBeNull()
          expect(ctx.sql.exec("SELECT * FROM run_placeholders WHERE run=?", active.run).toArray()).toEqual([])
          const notices = ctx.sql.exec<{ account: string; payload: string }>("SELECT account,payload FROM notice_outbox ORDER BY account").toArray()
          expect(notices.map((notice) => notice.account)).toEqual(["acc_admin", "acc_owner"])
          expect(notices.map((notice) => JSON.parse(notice.payload))).toEqual(Array(2).fill(expect.objectContaining({ kind: "protection_changed", project: { id: "prj_a", slug: "project-a" }, env: "prod", changes: ["reference_removed"] })))
          expect(canonicalJson(notices)).not.toContain("key-workspace")
        }
        expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
      })
    })
  }
})
