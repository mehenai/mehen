import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { accessState, authorise, setSetting, digest, newMember } from "../src/vault/areas/workspace-runtime.ts"
import { can } from "../src/vault/access.ts"
import { installTestIdentity, beginAccessSideEffectChecks, finishAccessSideEffectChecks, accessFixture, accessSnapshot, accountAuth, inAccess, registerFixtureLifecycleHooks, workspaceInvoke } from "./access-test-support.ts"
import { fixtureSql } from "./fixture-sql.ts"

beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)

describe("access first-release identity gate", () => {
  it("keeps the old effective role and exposes pendingRole for a covered promotion", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["admin"] }) })
    expect(await workspaceInvoke(tenant, "access.members.role", { member: "mem_member", role: "admin" }, accountAuth("owner", { type: "member.role", member: "mem_member", before: "member", after: "admin" }))).toMatchObject({ ok: true, value: { role: "member", pendingRole: "admin" } })
    expect(await workspaceInvoke(tenant, "access.membership", { account: "acc_member" }, { kind: "system", reason: "test" })).toMatchObject({ ok: true, value: { role: "member", pendingRole: "admin" } })
    await inAccess(tenant, (ctx) => {
      const auth = accountAuth("member")
      expect(() => authorise(ctx, { auth, workspace: { id: tenant, slug: "work", name: "Work" } }, { type: "team.update" }, {}, ctx.now())).toThrow("not allowed")
    })
  })
  it("requires identity even for the last owner and never promotes an admin or gates machines", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => { setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["owner", "admin", "member"] }); setSetting(ctx, "identity_rule_rev", 4) })
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.members.list", {}, accountAuth())).toEqual({ ok: false, error: { status: 403, vaultError: { error: "identity_required", message: "You are not allowed to do that." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
    await inAccess(tenant, (ctx) => {
      const state = accessState(ctx)
      expect(state.members.find((m) => m.id === "mem_admin")?.standing.effectiveRole).toBe("admin")
      expect(can(state, { kind: "device", deviceId: "dev_member" }, { type: "item.use", context: null }, { credential: "itm_workspace" }, ctx.now())).toEqual({ allowed: true, stepUp: null })
    })
  })
  it("admits ordinary reads without time re-gating, but refuses 12-hour-old widening", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["member"] }); setSetting(ctx, "identity_rule_rev", 4)
      const auth = accountAuth("member")
      auth.sessionCheck = { id: "chk_one", identityRuleRev: 4, gateGeneration: 0, checkSequence: 1, succeededAt: new Date(ctx.now() - 43_200_000).toISOString(), expiresAt: new Date(ctx.now() + 600_000).toISOString() }
      installTestIdentity(ctx, auth)
      const invocation = { auth, workspace: { id: tenant, slug: "work", name: "Work" } }
      expect(() => authorise(ctx, invocation, { type: "people.read" }, {}, ctx.now())).not.toThrow()
      expect(() => authorise(ctx, invocation, { type: "project.create" }, {}, ctx.now())).toThrow("not allowed")
      auth.sessionCheck.gateGeneration = 1
      expect(() => authorise(ctx, invocation, { type: "people.read" }, {}, ctx.now())).toThrow("not allowed")
    })
  })
  it("applies covered demotions immediately and clears stale pending promotions", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      registerFixtureLifecycleHooks()
      setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["owner", "admin", "member"] })
      fixtureSql(ctx).exec("UPDATE members SET pending_role='owner' WHERE id='mem_admin'")
      newMember(ctx, "acc_second", "Second owner", "owner", "active", "mem_second")
    })
    const action = { type: "member.role", member: "mem_admin", before: "admin", after: "member" } as const
    const auth = accountAuth("owner", action)
    auth.sessionCheck = { id: "chk_owner", identityRuleRev: 0, gateGeneration: 0, checkSequence: 1, succeededAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() }
    await inAccess(tenant, ctx => installTestIdentity(ctx, auth))
    auth.operationCheck = { id: "chk_operation", subjectDigest: digest(action), identityRuleRev: 0, gateGeneration: 0, succeededAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() }
    expect(await workspaceInvoke(tenant, "access.members.role", { member: "mem_admin", role: "member" }, auth)).toMatchObject({ ok: true, value: { role: "member", pendingRole: null } })
    await inAccess(tenant, (ctx) => {
      const admin = { ...accountAuth("admin"), sessionCheck: auth.sessionCheck }
      expect(() => authorise(ctx, { auth: admin, workspace: { id: tenant, slug: "work", name: "Work" } }, { type: "team.update" }, {}, ctx.now())).toThrow("not allowed")
    })
    const demoteOwner = { type: "member.role", member: "mem_second", before: "owner", after: "admin" } as const
    auth.stepUp = demoteOwner; auth.operationCheck.subjectDigest = digest(demoteOwner)
    expect(await workspaceInvoke(tenant, "access.members.role", { member: "mem_second", role: "admin" }, auth)).toMatchObject({ ok: true, value: { role: "admin", pendingRole: null } })
  })

})
