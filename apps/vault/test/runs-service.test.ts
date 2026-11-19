import { describe, expect, it, vi } from "vitest"
import { canonicalJson, type WorkspaceRunCreated } from "@mehen/protocol"
import { workspaceRunOps } from "../src/vault/areas/runs-workspace.ts"
import { workspaceDeviceOps } from "../src/vault/areas/workspace-devices.ts"
import { runs } from "../src/vault/areas/runs.ts"
import { accessState, setSetting } from "../src/vault/areas/workspace-runtime.ts"
import type { DevicePrincipal, VaultContext } from "../src/vault/core.ts"
import type { VaultError } from "../src/http.ts"
import { PROJECT_RUN_INPUT, accountAuth, inAccess, projectDeviceInvocation, projectFixture, projectState } from "./projects-workspace-fixture.ts"
import { accessMember } from "./workspace-fixtures.ts"
import { seedCredential } from "./credentials-test-support.ts"
import { registerCredentialServices } from "../src/vault/areas/items-workspace.ts"
import { fixtureSql } from "./fixture-sql.ts"

const HOUR = 3_600_000
const DEVICE = "dev_member"
const principal = { kind: "device" as const, deviceId: DEVICE }
const SERVICE_INPUT = { ...PROJECT_RUN_INPUT, env: "dev", service: true }
const WORKSPACE = { id: "", slug: "work", name: "Work" }

function allowServiceRuns(ctx: VaultContext, allowed: boolean): void {
  const { serviceRuns: _serviceRuns, ...scope } = accessState(ctx).devices.find((d) => d.id === DEVICE)!.scope
  ctx.sql.exec("UPDATE devices SET scope=? WHERE id=?", canonicalJson(allowed ? { ...scope, serviceRuns: true } : scope), DEVICE)
}

async function refusal(attempt: () => unknown): Promise<ReturnType<VaultError["toJSON"]>> {
  try {
    await attempt()
  } catch (error) {
    return (error as VaultError).toJSON()
  }
  throw new Error("accepted")
}

async function serviceRun(ctx: VaultContext) {
  allowServiceRuns(ctx, true)
  const invocation = await projectDeviceInvocation(ctx, DEVICE)
  const created = await workspaceRunOps["runs.create"]!.handler(ctx, principal, SERVICE_INPUT, invocation) as WorkspaceRunCreated
  const renew = () => workspaceRunOps["runs.renew"]!.handler(ctx, principal, { run: created.run }, invocation)
  return { created, invocation, renew }
}

describe("service runs", () => {
  it("have no hard end and renew past twelve hours", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { created, renew } = await serviceRun(ctx)
      expect(created.endsAt).toBeNull()
      const started = ctx.sql.exec<{ created_at: number; service: number }>("SELECT created_at, service FROM runs WHERE id=?", created.run).toArray()[0]!
      expect(started.service).toBe(1)
      const clock = vi.spyOn(ctx, "now")
      for (const at of [started.created_at + 12 * HOUR - 60_000, started.created_at + 13 * HOUR, started.created_at + 100 * HOUR]) {
        ctx.sql.exec("UPDATE runs SET expires_at=? WHERE id=?", at + 60_000, created.run)
        clock.mockReturnValue(at)
        expect(await renew()).toEqual({ run: created.run, expiresAt: new Date(at + 15 * 60_000).toISOString(), endsAt: null })
      }
      clock.mockRestore()
      expect(ctx.sql.exec<{ action: string; detail: string }>("SELECT action, detail FROM audit WHERE action='run.create' AND target=?", created.run).toArray()[0]!.detail).toContain('"service":true')
    })
  })

  it("are refused to a machine whose scope does not allow them, with its page as the next step", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const invocation = await projectDeviceInvocation(ctx, DEVICE)
      expect(await refusal(() => workspaceRunOps["runs.create"]!.handler(ctx, principal, SERVICE_INPUT, invocation))).toEqual({
        error: "forbidden",
        message: "This machine may not start service runs.",
        next: { url: `https://vault.test/w/work/devices/${DEVICE}`, say: "Ask the machine's owner to tick May run services on its page under Machines and sign the change with a passkey, then run again." },
      })
      expect(ctx.sql.exec("SELECT id FROM runs").toArray()).toEqual([])
    })
  })

  it("are refused in a protected environment, before any approval is asked", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      allowServiceRuns(ctx, true)
      const invocation = await projectDeviceInvocation(ctx, DEVICE)
      expect(await refusal(() => workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...SERVICE_INPUT, env: "prod" }, invocation))).toMatchObject({ error: "environment_refused", message: "A service run cannot use a protected environment." })
      expect(ctx.sql.exec("SELECT id FROM approvals").toArray()).toEqual([])
      expect(ctx.sql.exec("SELECT id FROM runs").toArray()).toEqual([])
    })
  })

  // Each change leaves the run's credential in use by the environment, so
  // only the re-plan on renewal sees it; an ordinary run renews on. A fence
  // added to another environment is checked by the local relay from the
  // list the run started with, which only a new run refreshes.
  it.each(["rebind", "delivery", "fence"] as const)("end on the next renewal after a %s, while an ordinary run renews on", async (change) => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { created, invocation, renew } = await serviceRun(ctx)
      const ordinary = await workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...PROJECT_RUN_INPUT, env: "dev" }, invocation) as WorkspaceRunCreated
      expect(created.vars).toMatchObject([{ name: "TOKEN", delivery: "placeholder" }])
      if (change === "rebind") {
        ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_a','dev','OTHER','key-workspace','key','member:mem_owner',?)", ctx.now())
        ctx.sql.exec("UPDATE vars SET item=NULL, field=NULL, plain='plain-value' WHERE project='prj_a' AND env='dev' AND name='TOKEN'")
      } else if (change === "delivery") ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.modes',json('[\"relay\",\"sign\",\"mint\",\"lease\"]')) WHERE id=?", DEVICE)
      else ctx.sql.exec("UPDATE environments SET fences=? WHERE project='prj_a' AND name='prod'", JSON.stringify(["db.prod.example.com"]))
      expect(await workspaceRunOps["runs.renew"]!.handler(ctx, principal, { run: ordinary.run }, invocation)).toMatchObject({ run: ordinary.run })
      expect(await refusal(renew)).toEqual({ error: "conflict", message: "Run sources changed; start a new run." })
    })
  })

  function setOverride(ctx: VaultContext, source: { item: string; field: string } | { plain: string }): void {
    ctx.sql.exec("INSERT INTO overrides(member,project,env,name,item,field,plain,updated_at) VALUES('mem_member','prj_a','dev','TOKEN',?,?,?,?)", "item" in source ? source.item : null, "item" in source ? source.field : null, "plain" in source ? source.plain : null, ctx.now())
  }

  // An override to a private credential on a machine without the private
  // credentials tick makes the plan itself refuse; renewal still says
  // conflict, as for any changed source.
  it.each(["set", "cleared", "set to a private credential"] as const)("end on the next renewal after an override is %s, with conflict", async (change) => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      registerCredentialServices()
      const own = change === "set to a private credential" ? await seedCredential(ctx, "member-private", { kind: "member", member: "mem_member" }) : null
      if (change === "cleared") setOverride(ctx, { plain: "local-value" })
      const { created, renew } = await serviceRun(ctx)
      expect(created.vars[0]).toMatchObject({ name: "TOKEN", delivery: change === "cleared" ? "plain" : "placeholder" })
      if (change === "cleared") ctx.sql.exec("DELETE FROM overrides")
      else setOverride(ctx, own ? { item: own.id, field: "key" } : { plain: "local-value" })
      expect(await refusal(renew)).toEqual({ error: "conflict", message: "Run sources changed; start a new run." })
    })
  })

  it("end on the next renewal after a rotation, with conflict", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { renew } = await serviceRun(ctx)
      fixtureSql(ctx).exec("UPDATE items SET version=version+1, config_rev=config_rev+1 WHERE slug='key-workspace'")
      expect(await refusal(renew)).toMatchObject({ error: "conflict" })
    })
  })

  it("are refused once the machine's scope no longer allows them, on renewal and in the relay", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { created, renew } = await serviceRun(ctx)
      const relayPrincipal = { kind: "device", device: DEVICE } as DevicePrincipal
      expect(runs.placeholdersFor(ctx, relayPrincipal, created.run)).toHaveLength(1)
      allowServiceRuns(ctx, false)
      const unticked = { error: "forbidden", message: "This machine may no longer run services; its owner changed what it may use." }
      expect(await refusal(renew)).toEqual(unticked)
      expect(await refusal(() => runs.placeholdersFor(ctx, relayPrincipal, created.run))).toEqual(unticked)
    })
  })

  it("refuse a lease once the machine's scope no longer allows them", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      fixtureSql(ctx).exec("UPDATE items SET ceiling='lease',injection=NULL WHERE slug='key-workspace'")
      const { created, invocation } = await serviceRun(ctx)
      expect(created.vars).toMatchObject([{ name: "TOKEN", delivery: "lease" }])
      const lease = () => workspaceRunOps["runs.lease"]!.handler(ctx, principal, { run: created.run, item: "key-workspace" }, invocation)
      expect(await lease()).toMatchObject({ value: expect.any(String) })
      allowServiceRuns(ctx, false)
      expect(await refusal(lease)).toEqual({ error: "forbidden", message: "This machine may no longer run services; its owner changed what it may use." })
    })
  })

  it.each(["untick", "freeze", "revoke"] as const)("end on a %s", async (change) => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { renew } = await serviceRun(ctx)
      const before = accessState(ctx).devices.find((d) => d.id === DEVICE)!.scope, after = { ...before, serviceRuns: false }
      const workspace = { ...WORKSPACE, id: ctx.tenant }
      if (change === "untick") expect(workspaceDeviceOps["devices.rescope"]!.handler(ctx, accessMember(projectState(ctx), "member"), { device: DEVICE, before, after }, { workspace, auth: accountAuth("member", { type: "device.rescope", device: DEVICE, thumbprint: DEVICE, before, after }) })).toMatchObject({ state: "committed" })
      else if (change === "freeze") setSetting(ctx, "frozen", true)
      else workspaceDeviceOps["devices.revoke"]!.handler(ctx, accessMember(projectState(ctx), "owner"), { device: DEVICE }, { workspace, auth: accountAuth("owner", { type: "device.revoke", device: DEVICE }) })
      expect(await refusal(renew)).toMatchObject({ error: change === "freeze" ? "frozen" : "not_found" })
    })
  })
})
