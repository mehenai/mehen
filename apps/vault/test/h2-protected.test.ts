import { VaultError } from "../src/http.ts"
import { describe,expect,it } from "vitest"
import type { VaultContext } from "../src/vault/core.ts"
// Workspace protection runtime: every refusal is checked against actual DO
// state, not only the pure evaluator's planning result.
import { vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { projectFixture, inAccess, callProject, projectState } from "./projects-workspace-fixture.ts"
import { workspaceEnvironmentDigest, workspaceVarDigest, projectWorkspaceOps } from "../src/vault/areas/projects-workspace.ts"
function workspaceRows(ctx: VaultContext): string {
  return canonicalJson(["projects", "environments", "vars", "project_shares", "notice_outbox", "consent_lineage", "run_authorisations", "audit"].map((table) => ({ table, rows: ctx.sql.exec(`SELECT * FROM ${table}`).toArray() })))
}
describe("protected changes and freezing", () => {
  for (const change of ["unprotect", "four-eyes-off", "fence-add", "fence-remove", "mixed-fences", "reference-remove", "reference-repoint", "delete"] as const) {
    it(`member manager cannot ${change}; no state, open or send`, async () => {
      const f = await projectFixture()
      await inAccess(f.tenant, (ctx) => {
        ctx.sql.exec("UPDATE environments SET four_eyes=1,fences='[\"old.example.com\"]' WHERE project='prj_a' AND name='staging'")
        const workspaceItem = ctx.sql.exec<{ slug: string }>("SELECT slug FROM items WHERE slug='key-workspace'").toArray()[0]!.slug
        ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_a','staging','TOKEN',?,'key','member:mem_owner',?)", workspaceItem, ctx.now())
        const state = projectState(ctx), before = workspaceRows(ctx)
        const open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
        let failure: unknown
        try {
          if (change === "delete") callProject(ctx, state, "kim", "projects.delete", { project: "prj_a" }, { type: "project.delete", project: "prj_a" })
          else if (change.startsWith("reference-")) {
            const input = { project: "prj_a", env: "staging", name: "TOKEN", before: { kind: "item" as const, item: workspaceItem, field: "key" }, ...(change === "reference-repoint" ? { item: "key-project" } : {}) }
            callProject(ctx, state, "kim", "projects.setVar", input, { type: "item.update", item: "prj_a", digest: workspaceVarDigest(input) })
          } else {
            const input = { project: "prj_a", env: "staging", before: { protected: true, fences: ["old.example.com"], fourEyes: true }, protected: change !== "unprotect", fourEyes: change !== "four-eyes-off", fences: change === "fence-add" ? ["old.example.com", "new.example.com"] : change === "fence-remove" ? [] : change === "mixed-fences" ? ["new.example.com"] : ["old.example.com"] }
            callProject(ctx, state, "kim", "projects.setEnvironment", input, { type: "item.update", item: "prj_a", digest: workspaceEnvironmentDigest(input) })
          }
        } catch (error) { failure = error }
        expect(failure).toBeInstanceOf(VaultError)
        expect((failure as VaultError).status).toBe(403)
        expect((failure as VaultError).toJSON()).toEqual({ error: "forbidden", message: "You are not allowed to do that.", next: { say: change === "delete" ? "Only an owner or admin can delete project-a: a protected environment uses workspace credentials." : change === "fence-add" ? "Only an owner or admin can change fences for project-a/staging." : "Only an owner or admin can loosen project-a/staging: it uses workspace credentials." } })
        expect(workspaceRows(ctx)).toBe(before)
        expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled()
        open.mockRestore(); send.mockRestore()
      })
    })
  }
  for (const role of ["owner", "admin", "member", "guest", "kim"]) for (const env of ["prod", "production"]) {
    it(`${role} cannot unprotect ${env} before a role or step-up check`, async () => {
      const f = await projectFixture()
      await inAccess(f.tenant, (ctx) => {
        if (env === "production") ctx.sql.exec("INSERT INTO environments(project,name,protected,fences) VALUES('prj_a','production',1,'[]')")
        const input = { project: "prj_a", env, before: { protected: true, fences: [], fourEyes: env === "prod" }, protected: false, fences: [], fourEyes: false }
        const before = workspaceRows(ctx)
        try { callProject(ctx, projectState(ctx), role, "projects.setEnvironment", input); throw new Error("accepted") } catch (error) {
          expect(error).toBeInstanceOf(VaultError)
          expect((error as VaultError).toJSON()).toEqual({ error: "bad_request", message: "prod and production are always protected." })
        }
        expect(workspaceRows(ctx)).toBe(before)
      })
    })
  }
  for (const role of ["owner", "admin"]) {
    it(`${role} loosens workspace references and queues owner/admin notice atomically`, async () => {
      const f = await projectFixture()
      await inAccess(f.tenant, (ctx) => {
        ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_a','staging','TOKEN','key-workspace','key','member:mem_owner',?)", ctx.now())
        const input = { project: "prj_a", env: "staging", before: { protected: true, fences: [], fourEyes: false }, protected: false, fences: ["new.example.com"], fourEyes: true }
        callProject(ctx, projectState(ctx), role, "projects.setEnvironment", input, { type: "item.update", item: "prj_a", digest: workspaceEnvironmentDigest(input) })
        const notices = ctx.sql.exec<{ account: string; payload: string }>("SELECT account,payload FROM notice_outbox ORDER BY account").toArray()
        expect(notices.map((n) => n.account)).toEqual(["acc_admin", "acc_owner"])
        expect(JSON.parse(notices[0]!.payload)).toMatchObject({ kind: "protection_changed", env: "staging", changes: ["unprotected", "fence_added"] })
      })
    })
  }
  it("a manager may loosen project-only protection but not edit any fence", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const input = { project: "prj_a", env: "staging", before: { protected: true, fences: [], fourEyes: false }, protected: false, fences: [], fourEyes: false }
      callProject(ctx, projectState(ctx), "kim", "projects.setEnvironment", input, { type: "item.update", item: "prj_a", digest: workspaceEnvironmentDigest(input) })
      expect(ctx.sql.exec("SELECT * FROM notice_outbox").toArray()).toEqual([])
      ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_a','staging','TOKEN','key-project','key','member:mem_owner',?)", ctx.now())
      for (const change of ["add", "remove"] as const) {
        const fences = change === "remove" ? ["old.example.com"] : []
        ctx.sql.exec("UPDATE environments SET fences=? WHERE project='prj_a' AND name='staging'", JSON.stringify(fences))
        const fenced = { ...input, before: { protected: false, fences, fourEyes: false }, fences: change === "add" ? ["new.example.com"] : [] }
        const before = projectSecurityRows(ctx), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
        try { callProject(ctx, projectState(ctx), "kim", "projects.setEnvironment", fenced, { type: "item.update", item: "prj_a", digest: workspaceEnvironmentDigest(fenced) }); throw new Error("accepted") } catch (error) {
          expect((error as VaultError).toJSON()).toEqual({ error: "forbidden", message: "You are not allowed to do that.", next: { say: "Only an owner or admin can change fences for project-a/staging." } })
        }
        expect(projectSecurityRows(ctx)).toBe(before)
        expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
      }
    })
  })
  it("stale before gives conflict without echoing the live value; audit failure rolls notices and mutation back", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const stale = { project: "prj_a", env: "staging", before: { protected: false, fences: [], fourEyes: false }, protected: true, fences: [], fourEyes: true }
      const before = workspaceRows(ctx)
      try { callProject(ctx, projectState(ctx), "owner", "projects.setEnvironment", stale, { type: "item.update", item: "prj_a", digest: workspaceEnvironmentDigest(stale) }); throw new Error("accepted") } catch (error) {
        expect((error as VaultError).toJSON()).toEqual({ error: "conflict", message: "The expected state changed.", next: { say: "Reload this page and review the change again." } })
      }
      expect(workspaceRows(ctx)).toBe(before)
      const input = { ...stale, before: { protected: true, fences: [], fourEyes: false }, fences: ["example.com"] }
      const audit = vi.spyOn(ctx, "audit").mockImplementation(() => { throw new Error("audit failed") })
      expect(() => callProject(ctx, projectState(ctx), "owner", "projects.setEnvironment", input, { type: "item.update", item: "prj_a", digest: workspaceEnvironmentDigest(input) })).toThrow("audit failed")
      audit.mockRestore(); expect(workspaceRows(ctx)).toBe(before)
    })
  })
})

describe("workspace protection notice completeness", () => {
  for (const role of ["owner", "admin"]) for (const change of ["four-eyes-off", "fence-remove", "reference-remove", "reference-repoint", "delete"] as const) {
    it(`${role} ${change} queues exactly the durable owner/admin notice`, async () => {
      const f = await projectFixture()
      await inAccess(f.tenant, (ctx) => {
        const project = change === "delete" ? "prj_b" : "prj_a", env = change === "delete" ? "prod" : "staging"
        ctx.sql.exec("UPDATE environments SET four_eyes=1,fences='[\"old.example.com\"]' WHERE project=? AND name=?", project, env)
        ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES(?,?,'TOKEN','key-workspace','key','member:mem_owner',?)", project, env, ctx.now())
        if (change === "delete") callProject(ctx, projectState(ctx), role, "projects.delete", { project }, { type: "project.delete", project })
        else if (change.startsWith("reference-")) {
          const input = { project, env, name: "TOKEN", before: { kind: "item" as const, item: "key-workspace", field: "key" }, ...(change === "reference-repoint" ? { item: "key-project" } : {}) }
          callProject(ctx, projectState(ctx), role, "projects.setVar", input, { type: "item.update", item: project, digest: workspaceVarDigest(input) })
        } else {
          const input = { project, env, before: { protected: true, fences: ["old.example.com"], fourEyes: true }, protected: true, fences: change === "fence-remove" ? [] : ["old.example.com"], fourEyes: change !== "four-eyes-off" }
          callProject(ctx, projectState(ctx), role, "projects.setEnvironment", input, { type: "item.update", item: project, digest: workspaceEnvironmentDigest(input) })
        }
        const notices = ctx.sql.exec<{ account: string; payload: string }>("SELECT account,payload FROM notice_outbox ORDER BY account").toArray()
        expect(notices.map((n) => n.account)).toEqual(["acc_admin", "acc_owner"])
        const expected = change === "delete" ? "project_deleted" : change.startsWith("reference-") ? "reference_removed" : change === "fence-remove" ? "fence_removed" : "four_eyes_off"
        expect(JSON.parse(notices[0]!.payload)).toMatchObject({ kind: "protection_changed", project: { id: project }, env, changes: [expected], by: `mem_${role}` })
        expect(notices[0]!.payload).not.toContain("key-workspace")
      })
    })
  }
  it("outbox failure after audit rolls the environment and audit back too", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      withTrustedSchema(ctx, () => ctx.sql.exec("CREATE TRIGGER fail_project_notice BEFORE INSERT ON notice_outbox BEGIN SELECT RAISE(ABORT,'notice unavailable'); END"))
      const before = workspaceRows(ctx), input = { project: "prj_a", env: "staging", before: { protected: true, fences: [], fourEyes: false }, protected: true, fences: ["example.com"], fourEyes: false }
      expect(() => callProject(ctx, projectState(ctx), "owner", "projects.setEnvironment", input, { type: "item.update", item: "prj_a", digest: workspaceEnvironmentDigest(input) })).toThrow("notice unavailable")
      expect(workspaceRows(ctx)).toBe(before)
    })
  })
})

import { workspaceRunOps, workspaceRunPlaceholders } from "../src/vault/areas/runs-workspace.ts"
import { assertRunUse } from "../src/vault/areas/projects-workspace.ts"
import { projectDeviceInvocation, projectSecurityRows, PROJECT_RUN_INPUT } from "./projects-workspace-fixture.ts"
import { fixtureSql } from "./fixture-sql.ts"
import { withTrustedSchema } from "../src/vault/areas/management-guard.ts"
describe("protection closes unapproved runs", () => {
  for (const fourEyes of [false, true]) for (const delivery of ["lease", "placeholder"] as const) for (const restoreLiveRow of [false, true]) {
    it(`protecting staging closes ${delivery} use, fourEyes=${fourEyes}, missed-end fallback=${restoreLiveRow}`, async () => {
      const f = await projectFixture()
      await inAccess(f.tenant, async (ctx) => {
        ctx.sql.exec("UPDATE environments SET protected=0 WHERE project='prj_a' AND name='staging'")
        ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_a','staging','TOKEN','key-workspace','key','member:mem_owner',?)", ctx.now())
        if (delivery === "lease") fixtureSql(ctx).exec("UPDATE items SET ceiling='lease',injection=NULL WHERE slug='key-workspace'")
        const invocation = await projectDeviceInvocation(ctx), principal = { kind: "device" as const, deviceId: "dev_kim" }
        const created = await workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...PROJECT_RUN_INPUT, env: "staging" }, invocation) as import("@mehen/protocol").WorkspaceRunCreated
        expect(created.vars[0]?.delivery).toBe(delivery)
        const change = { project: "prj_a", env: "staging", before: { protected: false, fences: [], fourEyes: false }, protected: true, fences: [], fourEyes }
        callProject(ctx, projectState(ctx), "owner", "projects.setEnvironment", change, { type: "item.update", item: "prj_a", digest: workspaceEnvironmentDigest(change) })
        expect(ctx.sql.exec<{ ended_at: number | null }>("SELECT ended_at FROM runs WHERE id=?", created.run).toArray()[0]!.ended_at).not.toBeNull()
        expect(ctx.sql.exec("SELECT * FROM run_placeholders WHERE run=?", created.run).toArray()).toEqual([])
        // Model an older row missed by the transition: the shared final check
        // must still reject it, independently of the eager invalidation.
        if (restoreLiveRow) ctx.sql.exec("UPDATE runs SET ended_at=NULL WHERE id=?", created.run)
        const before = projectSecurityRows(ctx), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
        const expected = restoreLiveRow ? { error: "forbidden", message: "This run has no protected authorisation." } : { error: "not_found", message: "No live run for this machine." }
        const attempts = [
          () => workspaceRunOps["runs.renew"]!.handler(ctx, principal, { run: created.run }, invocation),
          () => workspaceRunOps["runs.lease"]!.handler(ctx, principal, { run: created.run, item: "key-workspace" }, invocation),
          () => workspaceRunPlaceholders(ctx, { kind: "device" as const, deviceId: principal.deviceId }, created.run),
          () => assertRunUse(ctx, projectState(ctx), created.run, { kind: "device" as const, deviceId: principal.deviceId }, ctx.now()),
        ]
        for (const attempt of attempts) {
          try { await attempt(); throw new Error("accepted") } catch (error) { expect(error).toBeInstanceOf(VaultError); expect((error as VaultError).toJSON()).toEqual(expected) }
        }
        expect(projectSecurityRows(ctx)).toBe(before)
        expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
      })
    })
  }
})

describe("protected workspace reference authority", () => {
  for (const caller of ["kim", "dev_kim"] as const) it(`refuses ${caller} pointing a protected environment at a workspace credential`, async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const input = { project: "prj_a", env: "staging", name: "TOKEN", before: null, item: "key-workspace" }, before = projectSecurityRows(ctx)
      const open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      try {
        if (caller === "kim") callProject(ctx, projectState(ctx), caller, "projects.setVar", input, { type: "item.update", item: "prj_a", digest: workspaceVarDigest(input) })
        else await projectWorkspaceOps["projects.setVar"]!.handler(ctx, { kind: "device", deviceId: caller }, input, await projectDeviceInvocation(ctx))
        throw new Error("accepted")
      } catch (error) { expect((error as VaultError).status).toBe(403); expect((error as VaultError).toJSON()).toEqual({ error: "forbidden", message: "You are not allowed to do that." }) }
      expect(projectSecurityRows(ctx)).toBe(before)
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
  for (const role of ["kim", "owner", "admin"]) it(`${role} protecting a live workspace reference observes owner/admin authority`, async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      ctx.sql.exec("UPDATE environments SET protected=0 WHERE project='prj_a' AND name='staging'")
      ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_a','staging','TOKEN','key-workspace','key','member:mem_owner',?)", ctx.now())
      const input = { project: "prj_a", env: "staging", before: { protected: false, fences: [], fourEyes: false }, protected: true, fences: [], fourEyes: true }, before = projectSecurityRows(ctx), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      if (role === "kim") {
        try { callProject(ctx, projectState(ctx), role, "projects.setEnvironment", input, { type: "item.update", item: "prj_a", digest: workspaceEnvironmentDigest(input) }); throw new Error("accepted") } catch (error) { expect((error as VaultError).status).toBe(403); expect((error as VaultError).toJSON()).toEqual({ error: "forbidden", message: "You are not allowed to do that.", next: { say: "Only an owner or admin can protect project-a/staging: it uses workspace credentials." } }) }
        expect(projectSecurityRows(ctx)).toBe(before)
      } else {
        callProject(ctx, projectState(ctx), role, "projects.setEnvironment", input, { type: "item.update", item: "prj_a", digest: workspaceEnvironmentDigest(input) })
        expect(ctx.sql.exec<{ protected: number; four_eyes: number }>("SELECT protected,four_eyes FROM environments WHERE project='prj_a' AND name='staging'").toArray()[0]).toEqual({ protected: 1, four_eyes: 1 })
      }
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
})

it("protection audit failure restores unapproved runs and their placeholders atomically", async () => {
  const f = await projectFixture()
  await inAccess(f.tenant, async (ctx) => {
    ctx.sql.exec("UPDATE environments SET protected=0 WHERE project='prj_a' AND name='staging'")
    ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_a','staging','TOKEN','key-workspace','key','member:mem_owner',?)", ctx.now())
    const invocation = await projectDeviceInvocation(ctx), principal = { kind: "device" as const, deviceId: "dev_kim" }
    const active = await workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...PROJECT_RUN_INPUT, env: "staging" }, invocation) as import("@mehen/protocol").WorkspaceRunCreated
    expect(workspaceRunPlaceholders(ctx, { kind: "device" as const, deviceId: principal.deviceId }, active.run)).toHaveLength(1)
    const change = { project: "prj_a", env: "staging", before: { protected: false, fences: [], fourEyes: false }, protected: true, fences: [], fourEyes: true }
    const before = projectSecurityRows(ctx), audit = vi.spyOn(ctx, "audit").mockImplementation(() => { throw new Error("protection audit failed") }), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
    expect(() => callProject(ctx, projectState(ctx), "owner", "projects.setEnvironment", change, { type: "item.update", item: "prj_a", digest: workspaceEnvironmentDigest(change) })).toThrow("protection audit failed")
    audit.mockRestore()
    expect(projectSecurityRows(ctx)).toBe(before)
    expect(workspaceRunPlaceholders(ctx, { kind: "device" as const, deviceId: principal.deviceId }, active.run)).toHaveLength(1)
    expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
  })
})
