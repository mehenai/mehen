import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { can } from "../src/vault/access.ts"
import { accessState, authorise, principalOf, registerAccessChangeHook, newMember } from "../src/vault/areas/workspace-runtime.ts"
import { beginAccessSideEffectChecks, finishAccessSideEffectChecks, accessFixture, accessSnapshot, accountAuth, inAccess, registerFixtureLifecycleHooks, workspaceInvoke } from "./access-test-support.ts"
import { withTrustedSchema } from "../src/vault/areas/management-guard.ts"

beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)

describe("access suspension", () => {
  it("empties human and machine authority, invalidates consent, and reinstates rights only", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); withTrustedSchema(ctx, () => ctx.sql.exec("CREATE TABLE fixture_consent(revoked INTEGER NOT NULL)")); ctx.sql.exec("INSERT INTO fixture_consent VALUES (0)"); registerAccessChangeHook("consent", (c) => { c.sql.exec("UPDATE fixture_consent SET revoked=1") }) })
    expect(await workspaceInvoke(tenant, "access.members.suspend", { member: "mem_member" }, accountAuth("owner", { type: "member.suspend", member: "mem_member" }))).toMatchObject({ ok: true })
    await inAccess(tenant, (ctx) => {
      const state = accessState(ctx)
      expect(can(state, { kind: "device", deviceId: "dev_member" }, { type: "item.use", context: null }, { credential: "itm_workspace" }, ctx.now())).toEqual({ allowed: false, error: "not_found", message: "No such object." })
      expect(() => authorise(ctx, { auth: accountAuth("member"), workspace: { id: tenant, slug: "work", name: "Work" } }, { type: "people.read" }, {}, ctx.now())).toThrow("not allowed")
      expect(principalOf(ctx, accountAuth("member"))).toMatchObject({ kind: "member" })
    })
    expect(await workspaceInvoke(tenant, "access.members.reinstate", { member: "mem_member" }, accountAuth("owner", { type: "member.reinstate", member: "mem_member" }))).toMatchObject({ ok: true })
    await inAccess(tenant, (ctx) => expect(ctx.sql.exec<{ revoked: number }>("SELECT * FROM fixture_consent").toArray()[0]?.revoked).toBe(1))
  })
  it("refuses admin suspension of an owner and rolls back a failing invalidation", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, () => registerFixtureLifecycleHooks())
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.members.suspend", { member: "mem_owner" }, accountAuth("admin", { type: "member.suspend", member: "mem_owner" }))).toMatchObject({ ok: false, error: { vaultError: { error: "forbidden" } } })
    await inAccess(tenant, () => registerAccessChangeHook("projects", () => { throw new Error("hook fault") }))
    expect(await workspaceInvoke(tenant, "access.members.suspend", { member: "mem_member" }, accountAuth("owner", { type: "member.suspend", member: "mem_member" }))).toMatchObject({ ok: false, error: { vaultError: { error: "internal" } } })
    expect(await accessSnapshot(tenant)).toBe(before)
  })
  it("never activates unconfirmed people through suspend, reinstate or role changes", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); newMember(ctx, "acc_new", "New", "admin", "unconfirmed", "mem_new") })
    const before = await accessSnapshot(tenant)
    const refusal = { ok: false, error: { status: 409, vaultError: { error: "conflict", message: "This membership cannot be confirmed this way." } } }
    for (const role of ["admin", "owner"]) {
      for (const change of ["reinstate", "suspend", "reinstate"] as const) {
        expect(await workspaceInvoke(tenant, `access.members.${change}`, { member: "mem_new" }, accountAuth(role, { type: `member.${change}`, member: "mem_new" }))).toEqual(refusal)
        expect(await accessSnapshot(tenant)).toBe(before)
      }
      expect(await workspaceInvoke(tenant, "access.members.role", { member: "mem_new", role: "member" }, accountAuth(role, { type: "member.role", member: "mem_new", before: "admin", after: "member" }))).toEqual(refusal)
      expect(await accessSnapshot(tenant)).toBe(before)
    }
  })

})
