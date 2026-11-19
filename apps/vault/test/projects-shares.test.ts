import { describe, expect, it, vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { callProject, inAccess, projectFixture, projectState } from "./projects-workspace-fixture.ts"
import { VaultError } from "../src/http.ts"
describe("workspace project shares and visibility", () => {
  it("hidden and absent project reads are uniform, with no side effects", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch"), before = canonicalJson(ctx.sql.exec("SELECT * FROM projects").toArray())
      const failures = ["prj_b", "prj_absent", "project-b"].map((id) => { try { callProject(ctx, projectState(ctx), "member", "projects.get", { id }); return null } catch (error) { return (error as VaultError).toJSON() } })
      expect(failures).toEqual(Array(3).fill({ error: "not_found", message: "No such object." }))
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM projects").toArray())).toBe(before)
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
  it("requires manage, forbids a member manager sharing with a guest, and never grants guests manage", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const input = { project: "prj_a", subject: { kind: "member" as const, member: "mem_guest" }, before: { level: "edit" as const, protected: true, expiresAt: null }, after: { level: "use" as const, protected: false, expiresAt: null } }
      const before = canonicalJson(ctx.sql.exec("SELECT * FROM project_shares").toArray())
      for (const role of ["member", "kim", "guest"]) expect(() => callProject(ctx, projectState(ctx), role, "projects.share", input, { type: "project.share", ...input })).toThrow("not allowed")
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM project_shares").toArray())).toBe(before)
      const manage = { ...input, after: { ...input.after, level: "manage" as const } }
      expect(() => callProject(ctx, projectState(ctx), "owner", "projects.share", manage, { type: "project.share", ...manage })).toThrow("guest cannot manage")
      callProject(ctx, projectState(ctx), "owner", "projects.share", input, { type: "project.share", ...input })
      const guest = callProject(ctx, projectState(ctx), "guest", "projects.get", { id: "prj_a" }) as import("@mehen/protocol").WorkspaceProject
      expect(guest.shares).toBeUndefined()
      expect(guest.access).toMatchObject({ level: "use", runProtected: false, editProtected: false })
    })
  })
  it("a member manager may remove a guest's share", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const remove = { project: "prj_a", subject: { kind: "member" as const, member: "mem_guest" }, before: { level: "edit" as const, protected: true, expiresAt: null }, after: null }
      callProject(ctx, projectState(ctx), "kim", "projects.share", remove, { type: "project.share", ...remove })
      expect(projectState(ctx).shares.some((s) => s.subject.kind === "member" && s.subject.member === "mem_guest")).toBe(false)
    })
  })
  it("unsharing a team preserves the direct source, and audit failure preserves both", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const input = { project: "prj_a", subject: { kind: "team" as const, team: "tm_engineering" }, before: { level: "use" as const, protected: true, expiresAt: null }, after: null }
      const before = canonicalJson(ctx.sql.exec("SELECT * FROM project_shares").toArray())
      const audit = vi.spyOn(ctx, "audit").mockImplementation(() => { throw new Error("audit failed") })
      expect(() => callProject(ctx, projectState(ctx), "kim", "projects.share", input, { type: "project.share", ...input })).toThrow("audit failed")
      audit.mockRestore(); expect(canonicalJson(ctx.sql.exec("SELECT * FROM project_shares").toArray())).toBe(before)
      callProject(ctx, projectState(ctx), "kim", "projects.share", input, { type: "project.share", ...input })
      const project = callProject(ctx, projectState(ctx), "member", "projects.get", { id: "prj_a" }) as import("@mehen/protocol").WorkspaceProject
      expect(project.access).toMatchObject({ level: "edit", runProtected: false, editProtected: false })
      expect(project.access.sources).toHaveLength(1)
    })
  })
  it("a member manager cannot widen a machine-holding team's share of a project using a workspace credential, but can narrow or remove it", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const before = { level: "use" as const, protected: false, expiresAt: null }
      const widen = { project: "prj_a", subject: { kind: "team" as const, team: "tm_service" }, before, after: { ...before, level: "edit" as const } }
      const rows = canonicalJson(ctx.sql.exec("SELECT * FROM project_shares").toArray())
      const refusal = (() => { try { callProject(ctx, projectState(ctx), "kim", "projects.share", widen, { type: "project.share", ...widen }); return null } catch (error) { return (error as VaultError).toJSON() } })()
      expect(refusal).toEqual({ error: "forbidden", message: "You are not allowed to do that.", next: { say: "Only an owner or admin can share project-a with a team that has a machine: it uses workspace credentials." } })
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM project_shares").toArray())).toBe(rows)
      const narrow = { ...widen, after: { ...before, expiresAt: new Date(ctx.now() + 3_600_000).toISOString() } }
      callProject(ctx, projectState(ctx), "kim", "projects.share", narrow, { type: "project.share", ...narrow })
      expect(projectState(ctx).shares.find((s) => s.subject.kind === "team" && s.subject.team === "tm_service")).toMatchObject(narrow.after)
      const remove = { ...widen, before: narrow.after, after: null }
      callProject(ctx, projectState(ctx), "kim", "projects.share", remove, { type: "project.share", ...remove })
      expect(projectState(ctx).shares.some((s) => s.subject.kind === "team" && s.subject.team === "tm_service")).toBe(false)
      const give = { ...widen, before: null, after: before }
      expect(() => callProject(ctx, projectState(ctx), "kim", "projects.share", give, { type: "project.share", ...give })).toThrow("not allowed")
      callProject(ctx, projectState(ctx), "admin", "projects.share", give, { type: "project.share", ...give })
    })
  })
})

import { projectDeviceInvocation, projectSecurityRows } from "./projects-workspace-fixture.ts"
import { projectWorkspaceOps } from "../src/vault/areas/projects-workspace.ts"
describe("project metadata boundaries", () => {
  it("does not distinguish existing and absent share subjects for guests", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const before = projectSecurityRows(ctx), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      const bodies = ["mem_member", "mem_absent"].map((member) => {
        const input = { project: "prj_a", subject: { kind: "member" as const, member }, before: null, after: { level: "use" as const, protected: false, expiresAt: null } }
        try { callProject(ctx, projectState(ctx), "guest", "projects.share", input, { type: "project.share", ...input }); return null } catch (error) { return (error as VaultError).toJSON() }
      })
      expect(bodies).toEqual(Array(2).fill({ error: "forbidden", message: "You are not allowed to do that." }))
      expect(projectSecurityRows(ctx)).toBe(before)
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
  it("does not send a managing machine the human share list", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const view = await projectWorkspaceOps["projects.get"]!.handler(ctx, { kind: "device", deviceId: "dev_kim" }, { id: "prj_a" }, await projectDeviceInvocation(ctx)) as import("@mehen/protocol").WorkspaceProject
      expect(view.access.level).toBe("manage")
      expect(view.shares).toBeUndefined()
      expect((callProject(ctx, projectState(ctx), "kim", "projects.get", { id: "prj_a" }) as import("@mehen/protocol").WorkspaceProject).shares).toBeDefined()
    })
  })
})
