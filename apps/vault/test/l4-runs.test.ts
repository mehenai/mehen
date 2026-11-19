import { describe, expect, it, vi } from "vitest"
import { KINDS, LEASE_ONLY_HOST, canonicalJson, customItemPolicy, leaseOnlyBinding, type WorkspaceRunCreated } from "@mehen/protocol"
import { items } from "../src/vault/areas/items.ts"
import { workspaceRunOps } from "../src/vault/areas/runs-workspace.ts"
import { fetchWorker } from "./helpers.ts"
import { PROJECT_RUN_INPUT, approvedProjectRun, inAccess, projectDeviceInvocation, projectFixture } from "./projects-workspace-fixture.ts"

const HOUR = 3_600_000

describe("runs", () => {

  it("refuses run routes without a proof", async () => {
    expect((await fetchWorker("/v1/runs", { method: "POST", body: "{}" })).status).toBe(401)
    expect((await fetchWorker("/v1/runs/run_x", { method: "DELETE" })).status).toBe(401)
    expect((await fetchWorker("/v1/lease", { method: "POST", body: "{}" })).status).toBe(401)
  })

  it("names a run's hard end on create and on every renewal, and renewal never passes it", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const invocation = await projectDeviceInvocation(ctx, "dev_member"), principal = { kind: "device" as const, deviceId: "dev_member" }
      const created = await workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...PROJECT_RUN_INPUT, env: "dev" }, invocation) as WorkspaceRunCreated
      const started = ctx.sql.exec<{ created_at: number }>("SELECT created_at FROM runs WHERE id=?", created.run).toArray()[0]!.created_at
      expect(created.endsAt).toBe(new Date(started + 12 * HOUR).toISOString())
      const clock = vi.spyOn(ctx, "now")
      clock.mockReturnValue(started + 5 * 60_000)
      expect(await workspaceRunOps["runs.renew"]!.handler(ctx, principal, { run: created.run }, invocation)).toEqual({ run: created.run, expiresAt: new Date(started + 20 * 60_000).toISOString(), endsAt: created.endsAt })
      ctx.sql.exec("UPDATE runs SET expires_at=? WHERE id=?", started + 12 * HOUR, created.run)
      clock.mockReturnValue(started + 12 * HOUR - 60_000)
      expect(await workspaceRunOps["runs.renew"]!.handler(ctx, principal, { run: created.run }, invocation)).toEqual({ run: created.run, expiresAt: created.endsAt, endsAt: created.endsAt })
      clock.mockRestore()
    })
  })

  it("leases a lease-only credential into the run, never as a placeholder, though it has an injection", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      ctx.sql.exec("UPDATE items SET ceiling='lease',binding=? WHERE slug='key-workspace'", canonicalJson(leaseOnlyBinding()))
      const invocation = await projectDeviceInvocation(ctx, "dev_member"), principal = { kind: "device" as const, deviceId: "dev_member" }
      const created = await workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...PROJECT_RUN_INPUT, env: "dev" }, invocation) as WorkspaceRunCreated
      expect(created.vars).toMatchObject([{ name: "TOKEN", delivery: "lease", item: "key-workspace" }])
      expect(created.interceptHosts).not.toContain(LEASE_ONLY_HOST)
      expect(ctx.sql.exec("SELECT * FROM run_placeholders WHERE run=?", created.run).toArray()).toEqual([])
      expect(await workspaceRunOps["runs.lease"]!.handler(ctx, principal, { run: created.run, item: "key-workspace" }, invocation)).toMatchObject({ value: "test-fixture-key-not-a-live-secret" })
    })
  })

  it("leases a lease-only generic and database-url credential stored at their kind's own ceiling", async () => {
    for (const [kind, field, value] of [["generic", "value", "session-secret-not-a-live-secret"], ["database-url", "url", "postgres://app:not-live@db.internal/app"]] as const) {
      const f = await projectFixture()
      await inAccess(f.tenant, async (ctx) => {
        const old = items.getItem(ctx, "key-workspace")!
        const item = await items.putItem(ctx, { slug: `lease-${kind}`, kind, provider: null, account: null, accountVerified: false, tags: [], ceiling: KINDS[kind].defaultCeiling, binding: leaseOnlyBinding(), policy: customItemPolicy(false), injection: null, publicFields: {}, secretFields: { [field]: value }, description: null }, { kind: "system", reason: "test" })
        const state = ctx.sql.exec<{ value: string }>("SELECT value FROM access_fixture_state").one().value
        ctx.sql.exec("UPDATE access_fixture_state SET value=?", state.replaceAll(old.id, item.id))
        ctx.sql.exec("UPDATE vars SET item=?,field=? WHERE item='key-workspace'", item.slug, field)
        const invocation = await projectDeviceInvocation(ctx, "dev_member"), principal = { kind: "device" as const, deviceId: "dev_member" }
        const created = await workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...PROJECT_RUN_INPUT, env: "dev" }, invocation) as WorkspaceRunCreated
        expect(created.vars).toMatchObject([{ name: "TOKEN", delivery: "lease", item: item.slug }])
        expect(await workspaceRunOps["runs.lease"]!.handler(ctx, principal, { run: created.run, item: item.slug }, invocation)).toMatchObject({ value })
      })
    }
  })

  it("ends an approved protected run two hours after it started", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { run, result, invocation, principal } = await approvedProjectRun(ctx)
      const started = ctx.sql.exec<{ created_at: number }>("SELECT created_at FROM runs WHERE id=?", run).toArray()[0]!.created_at
      expect(result.endsAt).toBe(new Date(started + 2 * HOUR).toISOString())
      expect(await workspaceRunOps["runs.renew"]!.handler(ctx, principal, { run }, invocation)).toMatchObject({ run, endsAt: result.endsAt })
    })
  })
})
