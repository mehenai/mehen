import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { accessState, beforeOffboarding, recordExposure, registerAccessChangeHook, registerExposureProvider, registerOffboardingHook } from "../src/vault/areas/workspace-runtime.ts"
import { verifyAuditChain } from "../src/vault/audit.ts"
import type { AuditRow } from "../src/vault/audit.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { accessFixture, accessSnapshot, accountAuth, beginAccessSideEffectChecks, editAccessFixture, finishAccessSideEffectChecks, inAccess, registerFixtureLifecycleHooks, workspaceInvoke } from "./access-test-support.ts"
import { withTrustedSchema } from "../src/vault/areas/management-guard.ts"
beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)
async function resources(tenant: string) {
  await inAccess(tenant, (ctx) => {
    registerFixtureLifecycleHooks()
    editAccessFixture(ctx, (state) => { for (const id of ["itm_entered", "itm_relay", "itm_old"]) state.credentials.push({ id, home: { kind: "workspace" }, tags: [] }) })
    withTrustedSchema(ctx, () => ctx.sql.exec("CREATE TABLE fixture_resources(item TEXT PRIMARY KEY,version INTEGER,ceiling TEXT,private_owner TEXT,flagged INTEGER DEFAULT 0)"))
    for (const [id, version, ceiling, owner] of [["itm_workspace", 2, "lease", null], ["itm_entered", 3, "relay", null], ["itm_relay", 1, "relay", null], ["itm_old", 2, "relay", null], ["itm_member", 1, "lease", "mem_member"]] as const) ctx.sql.exec("INSERT INTO fixture_resources(item,version,ceiling,private_owner) VALUES (?,?,?,?)", id, version, ceiling, owner)
    withTrustedSchema(ctx, () => ctx.sql.exec("CREATE TABLE fixture_consents(id TEXT PRIMARY KEY,decider TEXT,device TEXT,revoked INTEGER DEFAULT 0)"))
    ctx.sql.exec("INSERT INTO fixture_consents VALUES ('other-machine','mem_member','dev_kim',0),('own-machine','mem_kim','dev_member',0),('team','mem_owner','dev_service',0)")
    registerExposureProvider((c) => c.sql.exec<{ item: string; version: number; ceiling: "lease" | "relay" }>("SELECT item,version,ceiling FROM fixture_resources").toArray())
    registerOffboardingHook("credentials", (c, snapshot) => {
      for (const exposure of snapshot.exposures) c.sql.exec("UPDATE fixture_resources SET flagged=1 WHERE item=? AND version=? AND private_owner IS NULL", exposure.item, exposure.version)
      c.sql.exec("DELETE FROM fixture_resources WHERE private_owner=?", snapshot.member)
      editAccessFixture(c, (state) => { state.credentials = state.credentials.filter((item) => !(item.home.kind === "member" && item.home.member === snapshot.member)) })
    })
    registerOffboardingHook("consent", (c, snapshot) => { c.sql.exec("UPDATE fixture_consents SET revoked=1 WHERE decider=?", snapshot.member); for (const device of snapshot.devices) c.sql.exec("UPDATE fixture_consents SET revoked=1 WHERE device=?", device) })
    registerAccessChangeHook("consent", (c, member) => c.sql.exec("UPDATE fixture_consents SET revoked=1 WHERE decider=?", member))
    recordExposure(ctx, { event: "evt_entered", member: "mem_member", device: null, item: "itm_entered", version: 3, source: "entered", at: 1 })
    recordExposure(ctx, { event: "evt_old_value", member: "mem_member", device: "dev_old", item: "itm_old", version: 1, source: "leased", at: 1 })
  })
}
describe("atomic workspace offboarding", () => {
  it("snapshots unused current lease reach before removal, keeps historical exposure and leaves team services alone", async () => {
    const { tenant } = await accessFixture()
    await resources(tenant)
    const result = await workspaceInvoke(tenant, "access.members.remove", { member: "mem_member" }, accountAuth("owner", { type: "member.remove", member: "mem_member" }))
    expect(result).toEqual({ ok: true, value: { removed: true, member: "mem_member" } })
    await inAccess(tenant, (ctx) => {
      const rows = ctx.sql.exec<{ item: string; flagged: number }>("SELECT item,flagged FROM fixture_resources ORDER BY item").toArray()
      expect(rows).toEqual([{ item: "itm_entered", flagged: 1 }, { item: "itm_old", flagged: 0 }, { item: "itm_relay", flagged: 0 }, { item: "itm_workspace", flagged: 1 }])
      const state = accessState(ctx)
      expect(state.devices.find((d) => d.id === "dev_member")?.status).toBe("revoked")
      expect(state.devices.find((d) => d.id === "dev_service")?.status).toBe("active")
      expect(state.teams.every((t) => !t.members.includes("mem_member"))).toBe(true)
      expect(state.shares.every((s) => s.subject.kind !== "member" || s.subject.member !== "mem_member")).toBe(true)
      expect(ctx.sql.exec<{ id: string; revoked: number }>("SELECT id,revoked FROM fixture_consents ORDER BY id").toArray()).toEqual([{ id: "other-machine", revoked: 1 }, { id: "own-machine", revoked: 1 }, { id: "team", revoked: 0 }])
      const snapshot = JSON.parse(ctx.sql.exec<{ snapshot: string }>("SELECT snapshot FROM removal_exposures").toArray()[0]!.snapshot)
      expect(snapshot.by).toBe("mem_owner")
      expect(snapshot.exposures).toEqual(expect.arrayContaining([expect.objectContaining({ item: "itm_workspace", source: "reachable_lease" }), expect.objectContaining({ item: "itm_entered", source: "entered" })]))
      expect(ctx.sql.exec("SELECT * FROM exposures WHERE event='evt_old_value'").toArray()).toHaveLength(1)
      expect(verifyAuditChain(ctx.sql.exec<AuditRow>("SELECT * FROM audit ORDER BY seq").toArray())).toEqual({ ok: true })
    })
  })
  it("flags a credential the leaving member's machine had typed into a web page, as one it leased", async () => {
    const { tenant } = await accessFixture()
    await resources(tenant)
    await inAccess(tenant, (ctx) => {
      editAccessFixture(ctx, (state) => { state.credentials.push({ id: "itm_filled", home: { kind: "workspace" }, tags: [] }) })
      ctx.sql.exec("INSERT INTO fixture_resources(item,version,ceiling,private_owner) VALUES ('itm_filled',4,'relay',NULL)")
      recordExposure(ctx, { event: "fill:jti_fixture", member: "mem_member", device: "dev_member", item: "itm_filled", version: 4, source: "filled", at: 1 })
    })
    expect(await workspaceInvoke(tenant, "access.members.remove", { member: "mem_member" }, accountAuth("owner", { type: "member.remove", member: "mem_member" }))).toMatchObject({ ok: true })
    await inAccess(tenant, (ctx) => {
      expect(ctx.sql.exec("SELECT flagged FROM fixture_resources WHERE item='itm_filled'").toArray()).toEqual([{ flagged: 1 }])
      const snapshot = JSON.parse(ctx.sql.exec<{ snapshot: string }>("SELECT snapshot FROM removal_exposures").toArray()[0]!.snapshot)
      expect(snapshot.exposures).toEqual(expect.arrayContaining([expect.objectContaining({ item: "itm_filled", device: "dev_member", source: "filled" })]))
    })
  })
  it("rolls exposure flags, secret deletion, devices, consent, audit and notices back together on final audit failure", async () => {
    const { tenant } = await accessFixture()
    await resources(tenant)
    const before = await accessSnapshot(tenant)
    let originalAudit: VaultContext["audit"] = () => undefined
    await inAccess(tenant, (ctx) => { originalAudit = ctx.audit; ctx.audit = (event) => { if (event.action === "member.remove") throw new Error("injected audit fault"); originalAudit(event) } })
    expect(await workspaceInvoke(tenant, "access.members.remove", { member: "mem_member" }, accountAuth("owner", { type: "member.remove", member: "mem_member" }))).toEqual({ ok: false, error: { status: 500, vaultError: { error: "internal", message: "Something went wrong inside the vault." } } })
    await inAccess(tenant, (ctx) => { ctx.audit = originalAudit })
    expect(await accessSnapshot(tenant)).toBe(before)
  })
  it("uses bounded exposure indexes, not a scan through a large audit chain", async () => {
    const { tenant } = await accessFixture()
    await resources(tenant)
    await inAccess(tenant, (ctx) => {
      for (let n = 0; n < 500; n++) ctx.audit({ actor: "system", action: "fixture.event", target: String(n) })
      const size = ctx.sql.exec("SELECT seq FROM audit").toArray().length
      const snapshot = beforeOffboarding(ctx, "mem_member")
      expect(snapshot.exposures).toHaveLength(2)
      expect(ctx.sql.exec("SELECT seq FROM audit").toArray()).toHaveLength(size)
    })
  })
})
