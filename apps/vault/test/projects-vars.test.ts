import { describe, expect, it, vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import { can } from "../src/vault/access.ts"
import { workspaceVarDigest, projectWorkspaceOps } from "../src/vault/areas/projects-workspace.ts"
import { projectFixture, projectState, inAccess, callProject } from "./projects-workspace-fixture.ts"
import { fixtureSql } from "./fixture-sql.ts"
describe("workspace project variables", () => {
  it("keeps protected run and edit independent in the runtime projection", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const state = projectState(ctx)
      const project = callProject(ctx, state, "member", "projects.get", { id: "prj_a" }) as import("@mehen/protocol").WorkspaceProject
      expect(project.access).toMatchObject({ level: "edit", runProtected: true, editProtected: false })
      expect(project.access.sources.map((s) => s.kind === "share" ? [s.share.level, s.share.protected] : s.role)).toEqual([["edit", false], ["use", true]])
      const input = { project: "prj_a", env: "prod", name: "TOKEN", before: { kind: "item" as const, item: "key-project", field: "key" }, plain: "safe" }
      const before = canonicalJson(ctx.sql.exec("SELECT * FROM vars").toArray()), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      try { callProject(ctx, state, "member", "projects.setVar", input, { type: "item.update", item: "prj_a", digest: workspaceVarDigest(input) }); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON()).toEqual({ error: "forbidden", message: "You are not allowed to do that." }) }
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM vars").toArray())).toBe(before)
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
  it("refuses member-manager workspace delegation to guest/team shares, allows owner, then removes exactly that reach", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const input = { project: "prj_a", env: "dev", name: "ANOTHER", before: null, item: "key-workspace" }
      const state = projectState(ctx), before = canonicalJson(ctx.sql.exec("SELECT * FROM vars").toArray())
      expect(() => callProject(ctx, state, "kim", "projects.setVar", input, { type: "item.update", item: "prj_a", digest: workspaceVarDigest(input) })).toThrow("not allowed")
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM vars").toArray())).toBe(before)
      callProject(ctx, state, "owner", "projects.setVar", input, { type: "item.update", item: "prj_a", digest: workspaceVarDigest(input) })
      const fresh = projectState(ctx), credential = fresh.credentials.find((c) => c.home.kind === "workspace")!
      expect(can(fresh, { kind: "device", deviceId: "dev_service" }, { type: "item.use", context: { project: "prj_a", environment: "dev" } }, { credential: credential.id }, ctx.now()).allowed).toBe(true)
      ctx.sql.exec("UPDATE vars SET item=NULL,field=NULL WHERE project='prj_a' AND env='dev' AND name='TOKEN'")
      const remove = { project: "prj_a", env: "dev", name: "ANOTHER", before: { kind: "item" as const, item: "key-workspace", field: "key" } }
      callProject(ctx, projectState(ctx), "kim", "projects.setVar", remove, { type: "item.update", item: "prj_a", digest: workspaceVarDigest(remove) })
      expect(can(projectState(ctx), { kind: "device", deviceId: "dev_service" }, { type: "item.use", context: { project: "prj_a", environment: "dev" } }, { credential: credential.id }, ctx.now())).toEqual({ allowed: false, error: "not_found", message: "No such object." })
    })
  })
  it("prepared human authority is reloaded after share loss and a wrong-kind proof never writes", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const state = projectState(ctx), input = { project: "prj_a", env: "dev", name: "PLAIN", before: null, plain: "safe" }
      const action = callProject(ctx, state, "kim", "projects.action", { change: "variable", input }) as import("@mehen/protocol").WorkspaceStepUpAction
      fixtureSql(ctx).exec("DELETE FROM project_shares WHERE id='shr_kim'")
      const before = canonicalJson(ctx.sql.exec("SELECT * FROM vars").toArray())
      expect(() => callProject(ctx, state, "kim", "projects.setVar", input, action)).toThrow("No such object")
      expect(() => callProject(ctx, projectState(ctx), "owner", "projects.setVar", input, { type: "project.delete", project: "prj_a" })).toThrow("exact action")
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM vars").toArray())).toBe(before)
    })
  })
  it("hidden and absent credentials refuse identically before field validation", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const errors = ["key-owner", "absent-item"].map((item) => {
        const input = { project: "prj_a", env: "dev", name: "HIDDEN", before: null, item, field: "not_a_field" }
        try { callProject(ctx, projectState(ctx), "kim", "projects.setVar", input, { type: "item.update", item: "prj_a", digest: workspaceVarDigest(input) }); return "accepted" } catch (error) { return (error as VaultError).toJSON() }
      })
      expect(errors).toEqual([{ error: "not_found", message: "No such object." }, { error: "not_found", message: "No such object." }])
    })
  })
})
