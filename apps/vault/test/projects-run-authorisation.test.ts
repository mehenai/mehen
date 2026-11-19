import { describe, expect, it, vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { runs } from "../src/vault/areas/runs.ts"
import { workspaceRunOps } from "../src/vault/areas/runs-workspace.ts"
import { assertRunUse, workspaceEnvironmentDigest } from "../src/vault/areas/projects-workspace.ts"
import { workspaceApproval } from "../src/vault/areas/approvals-workspace.ts"
import { projectFixture, projectState, inAccess, callProject, projectDeviceInvocation } from "./projects-workspace-fixture.ts"
import { VaultError } from "../src/http.ts"
import type { VaultContext } from "../src/vault/core.ts"
const INPUT = { project: "prj_a", env: "prod", envSource: "flag", remote: null, worktree: "/test/repo", head: null, vars: ["TOKEN"], command: "bun run", argv: ["bun", "run"] }
async function protectedRun(ctx: VaultContext, input = INPUT) {
  const invocation = await projectDeviceInvocation(ctx), principal = { kind: "device" as const, deviceId: "dev_kim" }
  let approval: string | undefined
  try { await workspaceRunOps["runs.create"]!.handler(ctx, principal, input, invocation) } catch (error) { if (!(error instanceof VaultError) || error.code !== "approval_required") throw error; approval = error.extra.approval }
  expect(approval).toBeDefined()
  const row = workspaceApproval(ctx, approval!)!
  expect(() => callProject(ctx, projectState(ctx), "kim", "approvals.decide", { id: row.id, decision: "approve" }, { type: "approval.decide", approval: row.id, digest: row.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 3600 } })).toThrow("not allowed")
  callProject(ctx, projectState(ctx), "owner", "approvals.decide", { id: row.id, decision: "approve" }, { type: "approval.decide", approval: row.id, digest: row.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 3600 } })
  const result = await workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...input, approval }, invocation) as { run: string }
  return result.run
}
// A run is decided on its own page; its ask stores a NULL floor, which counts
// as floor (ruling B5), so nothing reading the floor alone can start it ticked.
it("a protected run's ask records its review group and shape, and a NULL floor", async () => {
  const f = await projectFixture()
  await inAccess(f.tenant, async (ctx) => {
    let approval: string | undefined
    try { await workspaceRunOps["runs.create"]!.handler(ctx, { kind: "device", deviceId: "dev_kim" }, INPUT, await projectDeviceInvocation(ctx)) } catch (error) { if (!(error instanceof VaultError) || error.code !== "approval_required") throw error; approval = error.extra.approval as string }
    expect(ctx.sql.exec("SELECT review_group,shape,floor FROM approvals WHERE id=?", approval!).toArray()).toEqual([{ review_group: expect.stringMatching(/^grp_/), shape: expect.any(String), floor: null }])
  })
})
describe("continuing workspace run authorisation", () => {
  it("keeps a healthy run valid for a second relay after consuming its start grant", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const run = await protectedRun(ctx)
      expect(ctx.sql.exec<{ uses_left: number }>("SELECT uses_left FROM protected_use_grants").toArray()[0]!.uses_left).toBe(0)
      const first = assertRunUse(ctx, projectState(ctx), run, { kind: "device" as const, deviceId: "dev_kim" }, ctx.now())
      expect(assertRunUse(ctx, projectState(ctx), run, { kind: "device" as const, deviceId: "dev_kim" }, ctx.now())).toEqual(first)
      expect(first.snapshot?.run?.items).toHaveLength(1)
    })
  })
  it("approves a plain-only protected run with context four-eyes and refuses self-approval", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      ctx.sql.exec("UPDATE environments SET four_eyes=1 WHERE project='prj_a' AND name='staging'")
      ctx.sql.exec("INSERT INTO vars(project,env,name,plain,updated_by,updated_at) VALUES('prj_a','staging','TOKEN','safe','member:mem_owner',?)", ctx.now())
      const run = await protectedRun(ctx, { ...INPUT, env: "staging" })
      const used = assertRunUse(ctx, projectState(ctx), run, { kind: "device" as const, deviceId: "dev_kim" }, ctx.now())
      expect(used.snapshot?.run?.items).toEqual([])
      expect(used.snapshot?.fourEyes).toEqual(["prj_a"])
    })
  })
  for (const change of ["device-revoked", "decider-role", "reference", "requester-share", "device-scope", "foreign-device"] as const) it(`refuses ${change} before release or send`, async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const run = await protectedRun(ctx)
      if (change === "device-revoked") ctx.sql.exec("UPDATE devices SET revoked_at=? WHERE id='dev_kim'", ctx.now())
      if (change === "decider-role") fixtureSql(ctx).exec("UPDATE members SET role='member' WHERE id='mem_owner'")
      if (change === "reference") ctx.sql.exec("UPDATE environments SET reference_rev=reference_rev+1 WHERE project='prj_a' AND name='prod'")
      if (change === "requester-share") fixtureSql(ctx).exec("DELETE FROM project_shares WHERE id='shr_kim'")
      if (change === "device-scope") ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.maxEnvironment','unprotected') WHERE id='dev_kim'")
      const open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      const before = canonicalJson(ctx.sql.exec("SELECT * FROM runs").toArray())
      try { assertRunUse(ctx, projectState(ctx), run, { kind: "device" as const, deviceId: change === "foreign-device" ? "dev_owner" : "dev_kim" }, ctx.now()); throw new Error("accepted") } catch (error) {
        expect(error).toBeInstanceOf(VaultError)
        if (change === "foreign-device") expect((error as VaultError).toJSON()).toEqual({ error: "not_found", message: "No live run for this machine." })
      }
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM runs").toArray())).toBe(before)
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled()
      open.mockRestore(); send.mockRestore()
    })
  })
  it("audit failure rolls run, start consumption, authorisation and placeholders back", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const invocation = await projectDeviceInvocation(ctx), principal = { kind: "device" as const, deviceId: "dev_kim" }
      let approval: string | undefined
      try { await workspaceRunOps["runs.create"]!.handler(ctx, principal, INPUT, invocation) } catch (error) { approval = (error as VaultError).extra.approval }
      const row = workspaceApproval(ctx, approval!)!
      callProject(ctx, projectState(ctx), "owner", "approvals.decide", { id: row.id, decision: "approve" }, { type: "approval.decide", approval: row.id, digest: row.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 3600 } })
      const audit = vi.spyOn(ctx, "audit").mockImplementation(() => { throw new Error("audit failed") })
      await expect(workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...INPUT, approval }, invocation)).rejects.toThrow("audit failed")
      audit.mockRestore()
      expect(ctx.sql.exec("SELECT * FROM runs").toArray()).toEqual([])
      expect(ctx.sql.exec("SELECT * FROM run_authorisations").toArray()).toEqual([])
      expect(ctx.sql.exec("SELECT * FROM run_placeholders").toArray()).toEqual([])
      expect(ctx.sql.exec<{ uses_left: number }>("SELECT uses_left FROM protected_use_grants").toArray()[0]!.uses_left).toBe(1)
    })
  })
})

describe("workspace run final-await boundaries", () => {
  it("share loss during decryption loses the race: no run, value release, exposure or upstream send", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      ctx.sql.exec("UPDATE items SET ceiling='lease',injection=NULL WHERE slug='key-workspace'")
      const invocation = await projectDeviceInvocation(ctx, "dev_member"), principal = { kind: "device" as const, deviceId: "dev_member" }
      let entered!: () => void, release!: () => void
      const opening = new Promise<void>((resolve) => { entered = resolve }), barrier = new Promise<void>((resolve) => { release = resolve })
      const original = ctx.openField.bind(ctx)
      const open = vi.spyOn(ctx, "openField").mockImplementation(async (...args) => { entered(); await barrier; return original(...args) })
      const send = vi.spyOn(globalThis, "fetch")
      const pending = workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...INPUT, env: "dev" }, invocation)
      await opening
      fixtureSql(ctx).exec("DELETE FROM project_shares WHERE subject_id IN('mem_member','tm_engineering')")
      release()
      await expect(pending).rejects.toThrow("has not been shared")
      expect(open).toHaveBeenCalled() // Prepared plaintext is not a released value.
      expect(ctx.sql.exec("SELECT * FROM runs").toArray()).toEqual([])
      expect(ctx.sql.exec("SELECT * FROM exposures").toArray()).toEqual([])
      expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
  it("a lease audit failure rolls all capability and exposure writes back", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      ctx.sql.exec("UPDATE items SET ceiling='lease',injection=NULL WHERE slug='key-workspace'")
      const invocation = await projectDeviceInvocation(ctx, "dev_member"), principal = { kind: "device" as const, deviceId: "dev_member" }
      const originalAudit = ctx.audit.bind(ctx), audit = vi.spyOn(ctx, "audit").mockImplementation((event) => { if (event.action === "run.lease") throw new Error("lease audit failed"); originalAudit(event) })
      await expect(workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...INPUT, env: "dev" }, invocation)).rejects.toThrow("lease audit failed")
      audit.mockRestore()
      expect(ctx.sql.exec("SELECT * FROM runs").toArray()).toEqual([])
      expect(ctx.sql.exec("SELECT * FROM exposures").toArray()).toEqual([])
    })
  })
})

describe("workspace consent graph provenance", () => {
  it("a new protected workspace reference synchronously stales pending asks, grants and live runs", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      ctx.sql.exec("UPDATE vars SET item='key-workspace' WHERE project='prj_a' AND env='prod'")
      const run = await protectedRun(ctx), invocation = await projectDeviceInvocation(ctx)
      let pending: string | undefined
      try { await workspaceRunOps["runs.create"]!.handler(ctx, { kind: "device", deviceId: "dev_kim" }, INPUT, invocation) } catch (error) { pending = (error as VaultError).extra.approval }
      const input = { project: "prj_b", env: "staging", name: "TOKEN", before: null, item: "key-workspace" }
      const action = callProject(ctx, projectState(ctx), "owner", "projects.action", { change: "variable", input }) as import("@mehen/protocol").WorkspaceStepUpAction
      callProject(ctx, projectState(ctx), "owner", "projects.setVar", input, action)
      expect(workspaceApproval(ctx, pending!)!.policy_status).toBe("stale")
      expect(ctx.sql.exec<{ revoked_at: number | null }>("SELECT revoked_at FROM protected_use_grants").toArray()[0]!.revoked_at).not.toBeNull()
      expect(ctx.sql.exec<{ revoked_at: number | null }>("SELECT revoked_at FROM run_authorisations").toArray()[0]!.revoked_at).not.toBeNull()
      expect(() => assertRunUse(ctx, projectState(ctx), run, { kind: "device" as const, deviceId: "dev_kim" }, ctx.now())).toThrow()
    })
  })
  it("equivalent replacement shares never revive an old run's requester basis", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const run = await protectedRun(ctx)
      const replacement = { id: "shr_new_grant", project: "prj_a", subject: { kind: "member", member: "mem_kim" }, level: "manage", protected: true, expiresAt: null }
      fixtureSql(ctx).exec("UPDATE project_shares SET id=?,value=? WHERE id='shr_kim'", replacement.id, canonicalJson(replacement))
      expect(() => assertRunUse(ctx, projectState(ctx), run, { kind: "device" as const, deviceId: "dev_kim" }, ctx.now())).toThrow("Access changed")
    })
  })
})

describe("workspace lease-only runs", () => {
  it("uses and renews a lease-only run without granting metadata or losing exposure attribution", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      ctx.sql.exec("UPDATE items SET ceiling='lease',injection=NULL WHERE slug='key-workspace'")
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.modes',json('[\"lease\"]')) WHERE id='dev_member'")
      const invocation = await projectDeviceInvocation(ctx, "dev_member"), principal = { kind: "device" as const, deviceId: "dev_member" }
      const result = await workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...INPUT, env: "dev" }, invocation) as import("@mehen/protocol").WorkspaceRunCreated
      expect(result.vars[0]).toMatchObject({ name: "TOKEN", delivery: "lease" })
      expect(assertRunUse(ctx, projectState(ctx), result.run, { kind: "device" as const, deviceId: principal.deviceId }, ctx.now()).env).toBe("dev")
      expect(await workspaceRunOps["runs.renew"]!.handler(ctx, principal, { run: result.run }, invocation)).toMatchObject({ run: result.run })
      const exposure = ctx.sql.exec<{ event: string; member: string; device: string; source: string }>("SELECT event,member,device,source FROM exposures").toArray()[0]!
      expect(exposure).toMatchObject({ member: "mem_member", device: "dev_member", source: "leased" })
      expect(exposure.event).toContain(`run:${result.run}:lease:`)
    })
  })
})

describe("protected run lifetime is separate from the start-grant window", () => {
  it("continues after its consumed start grant expires, but never past the two-hour run limit", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const run = await protectedRun(ctx), invocation = await projectDeviceInvocation(ctx), principal = { kind: "device" as const, deviceId: "dev_kim" }
      const started = ctx.sql.exec<{ created_at: number }>("SELECT created_at FROM runs WHERE id=?", run).toArray()[0]!.created_at
      const grantExpiry = ctx.sql.exec<{ expires_at: number }>("SELECT expires_at FROM protected_use_grants").toArray()[0]!.expires_at
      const clock = vi.spyOn(ctx, "now"), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      for (let minutes=5;minutes<120;minutes+=5) {
        clock.mockReturnValue(started+minutes*60_000)
        await workspaceRunOps["runs.renew"]!.handler(ctx, principal, { run }, invocation)
        if (ctx.now()>grantExpiry) expect(() => assertRunUse(ctx, projectState(ctx), run, { kind: "device" as const, deviceId: principal.deviceId }, ctx.now())).not.toThrow()
      }
      expect(ctx.sql.exec<{ expires_at: number }>("SELECT expires_at FROM runs WHERE id=?", run).toArray()[0]!.expires_at).toBe(started+2*3_600_000)
      clock.mockReturnValue(started+2*3_600_000+1)
      expect(() => assertRunUse(ctx, projectState(ctx), run, { kind: "device" as const, deviceId: principal.deviceId }, ctx.now())).toThrow("No live run")
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore(); clock.mockRestore()
    })
  })
})

import { workspaceRunPlaceholders } from "../src/vault/areas/runs-workspace.ts"
import { setSetting } from "../src/vault/areas/workspace-runtime.ts"
import { approvedProjectRun, projectSecurityRows } from "./projects-workspace-fixture.ts"
import { fixtureSql } from "./fixture-sql.ts"
describe("run-use checks", () => {
  it("refuses every use of a frozen run before opening, exposure or sending", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { run, invocation, principal } = await approvedProjectRun(ctx)
      setSetting(ctx, "frozen", true)
      const before = projectSecurityRows(ctx), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      const legacyPrincipal = { kind: "device" as const, device: principal.deviceId, name: "Kim laptop", scope: projectState(ctx).devices.find((d) => d.id === principal.deviceId)!.scope, session: null, grant: null, workload: null }
      for (const attempt of [
        () => runs.isApprovedProtectedRun(ctx, legacyPrincipal, run),
        () => runs.fencesFor(ctx, legacyPrincipal, run),
        () => runs.placeholdersFor(ctx, legacyPrincipal, run),
        () => assertRunUse(ctx, projectState(ctx), run, { kind: "device" as const, deviceId: principal.deviceId }, ctx.now()),
        () => workspaceRunPlaceholders(ctx, { kind: "device" as const, deviceId: principal.deviceId }, run),
        () => workspaceRunOps["runs.renew"]!.handler(ctx, principal, { run }, invocation),
        () => workspaceRunOps["runs.lease"]!.handler(ctx, principal, { run, item: "key-project" }, invocation),
      ]) {
        try { await attempt(); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON()).toEqual({ error: "frozen", message: "This workspace is frozen." }) }
      }
      expect(projectSecurityRows(ctx)).toBe(before)
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
  it("cannot start another run with the consumed approval of a live run", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { run, approval, invocation, principal, input } = await approvedProjectRun(ctx)
      const before = projectSecurityRows(ctx), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      try { await workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...input, approval }, invocation); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON()).toEqual({ error: "forbidden", message: "This approval is no longer usable." }) }
      expect(ctx.sql.exec<{ id: string }>("SELECT id FROM runs").toArray()).toEqual([{ id: run }])
      expect(projectSecurityRows(ctx)).toBe(before)
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
})

it("enabling four-eyes revokes approved grants and live run authorisation in the same transaction", async () => {
  const f = await projectFixture()
  await inAccess(f.tenant, async (ctx) => {
    ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_a','staging','TOKEN','key-workspace','key','member:mem_owner',?)", ctx.now())
    const active = await approvedProjectRun(ctx, { ...INPUT, env: "staging" }, "dev_kim", "kim")
    const input = { project: "prj_a", env: "staging", before: { protected: true, fences: [], fourEyes: false }, protected: true, fences: [], fourEyes: true }
    callProject(ctx, projectState(ctx), "kim", "projects.setEnvironment", input, { type: "item.update", item: "prj_a", digest: workspaceEnvironmentDigest(input) })
    for (const table of ["protected_use_grants", "consent_lineage"]) expect(ctx.sql.exec<{ revoked_at: number | null }>(`SELECT revoked_at FROM ${table} WHERE ${table === "consent_lineage" ? "decision" : "approval"}=?`, active.approval).toArray()[0]!.revoked_at).not.toBeNull()
    expect(ctx.sql.exec<{ revoked_at: number | null }>("SELECT revoked_at FROM run_authorisations WHERE run=?", active.run).toArray()[0]!.revoked_at).not.toBeNull()
    const before = projectSecurityRows(ctx), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
    for (const attempt of [() => assertRunUse(ctx, projectState(ctx), active.run, { kind: "device" as const, deviceId: active.principal.deviceId }, ctx.now()), () => workspaceRunPlaceholders(ctx, { kind: "device" as const, deviceId: active.principal.deviceId }, active.run), () => workspaceRunOps["runs.renew"]!.handler(ctx, active.principal, { run: active.run }, active.invocation)]) {
      try { await attempt(); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON()).toEqual({ error: "conflict", message: "Access changed; ask for a new approval." }) }
    }
    expect(projectSecurityRows(ctx)).toBe(before)
    expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
  })
})
