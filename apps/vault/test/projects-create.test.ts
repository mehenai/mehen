import { describe, expect, it, vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { nameMiss } from "../src/vault/areas/workspace-runtime.ts"
import { accessMember } from "./workspace-fixtures.ts"
import { callProject, inAccess, projectFixture, projectState } from "./projects-workspace-fixture.ts"
import { VaultError } from "../src/http.ts"
const INPUT = { slug: "fresh-project", remote: null, defaultEnv: "dev", environments: [{ name: "dev", protected: false, fourEyes: false }] }
const ACTION = { type: "project.create" as const, slug: INPUT.slug, remote: null, environments: INPUT.environments }
describe("workspace project naming", () => {
  it("uses one account/machine miss budget for project, credential and remote namespaces", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const state = projectState(ctx), principal = accessMember(state, "member")
      // CREDENTIALS calls this exact shared service too; a machine miss also
      // charges its owning account, rather than creating a parallel bucket.
      for (let i = 0; i < 19; i++) nameMiss.record(ctx, { kind: "device", deviceId: "dev_member" }, ctx.now())
      const hidden = { ...INPUT, slug: "project-b" }
      try { callProject(ctx, state, "member", "projects.create", hidden, { ...ACTION, slug: hidden.slug }); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON()).toEqual({ error: "conflict", message: "name not available" }) }
      expect(nameMiss.check(ctx, principal, ctx.now()).ok).toBe(false)
      const before = canonicalJson(ctx.sql.exec("SELECT * FROM projects").toArray()), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      const failures = [INPUT, hidden].map((input) => { try { callProject(ctx, state, "member", "projects.create", input, { ...ACTION, slug: input.slug }); return null } catch (error) { return (error as VaultError).toJSON() } })
      expect(failures[0]).toEqual(failures[1]); expect(failures[0]).toMatchObject({ error: "rate_limited", message: "Too many unavailable names; try again later." })
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM projects").toArray())).toBe(before)
      const events = ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='name.miss_limit'").toArray()
      expect(events.length).toBeGreaterThan(0)
      for (const event of events) { expect(JSON.parse(event.detail)).toHaveProperty("count", 20); expect(event.detail).not.toContain("project-b") }
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
  it("creates normally below the limit, gives the creator manage, and rolls back on audit failure", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const created = callProject(ctx, projectState(ctx), "member", "projects.create", INPUT, ACTION) as import("@mehen/protocol").WorkspaceProject
      expect(created.access).toMatchObject({ level: "manage", runProtected: true, editProtected: true })
      const before = canonicalJson(ctx.sql.exec("SELECT * FROM projects").toArray())
      const audit = vi.spyOn(ctx, "audit").mockImplementation(() => { throw new Error("audit failed") })
      const input = { ...INPUT, slug: "another-project" }
      expect(() => callProject(ctx, projectState(ctx), "member", "projects.create", input, { ...ACTION, slug: input.slug })).toThrow("audit failed")
      audit.mockRestore(); expect(canonicalJson(ctx.sql.exec("SELECT * FROM projects").toArray())).toBe(before)
    })
  })
  it("remote collision is generic and its shared miss survives the refusal", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      ctx.sql.exec("INSERT INTO remotes(remote,project) VALUES('github.com/hidden/repo','prj_b')")
      const input = { project: "prj_a", remote: "github.com/hidden/repo", bound: true }
      const action = callProject(ctx, projectState(ctx), "kim", "projects.action", { change: "remote", input }) as import("@mehen/protocol").WorkspaceStepUpAction
      try { callProject(ctx, projectState(ctx), "kim", "projects.setRemote", input, action); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON()).toEqual({ error: "conflict", message: "name not available" }) }
      expect(ctx.sql.exec<{ count: number }>("SELECT count FROM name_miss_buckets WHERE subject='account:acc_kim'").toArray()[0]!.count).toBe(1)
      expect(ctx.sql.exec("SELECT * FROM remotes WHERE project='prj_a'").toArray()).toEqual([])
    })
  })
})
