import { describe, expect, it, vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { onCredentialRemoved, prepareApprovedUse } from "../src/vault/areas/projects-workspace.ts"
import { workspaceApproval } from "../src/vault/areas/approvals-workspace.ts"
import { digestOf } from "../src/vault/areas/approvals.ts"
import { callProject, inAccess, projectFixture, projectState } from "./projects-workspace-fixture.ts"
import { VaultError } from "../src/http.ts"
describe("workspace project deletion dependencies", () => {
  it("refuses without listing project credentials, then cascades after the dependency is rehomed", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "project")!, action = { type: "project.delete" as const, project: "prj_a" }
      const before = canonicalJson(ctx.sql.exec("SELECT * FROM projects").toArray()), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      try { callProject(ctx, state, "owner", "projects.delete", { project: "prj_a" }, action); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON()).toEqual({ error: "conflict", message: "Delete or re-home this project's credentials before deleting the project." }) }
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM projects").toArray())).toBe(before)
      const required = prepareApprovedUse(ctx, state, { principal: { kind: "device", deviceId: "dev_kim" }, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation: { title: "Protected", details: [], body: null }, batch: { floor: [], shape: "test-shape", replaces: null } }, { ...item, slug: "key-project", version: 1 }, { project: "prj_a", env: "prod" }, { item: "key-project", method: "POST", url: "https://api.example.com/", contentType: null, contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf(null), constraints: { uses: 1, ttlSeconds: 600 } }, null, ctx.now())
      ctx.sql.exec("INSERT INTO runs(id,device,project,env,worktree,command,created_at,expires_at) VALUES('run_delete','dev_kim','prj_a','prod','/fixture','test',?,?)", ctx.now(), ctx.now()+60_000)
      ctx.storage.transactionSync(() => onCredentialRemoved(ctx, { ...item, slug: "key-project" }, "rehomed", "mem_owner"))
      f.state.credentials.find((c) => c.id === item.id)!.home = { kind: "workspace" }
      ctx.sql.exec("UPDATE access_fixture_state SET value=?", canonicalJson(f.state))
      callProject(ctx, projectState(ctx), "owner", "projects.delete", { project: "prj_a" }, action)
      for (const table of ["projects", "vars", "environments"]) expect(ctx.sql.exec(`SELECT * FROM ${table} WHERE ${table === "projects" ? "id" : "project"}='prj_a'`).toArray()).toEqual([])
      expect(workspaceApproval(ctx, required.approvalId)!.policy_status).toBe("stale")
      expect(ctx.sql.exec<{ ended_at: number | null }>("SELECT ended_at FROM runs WHERE id='run_delete'").toArray()[0]!.ended_at).not.toBeNull()
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
})
