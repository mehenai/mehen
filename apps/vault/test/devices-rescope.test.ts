import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { DeviceRescopeProposalSchema, RescopeProposalViewSchema, canonicalJson } from "@mehen/protocol"
import { reach } from "../src/vault/access.ts"
import type { WorkspaceDeviceScope } from "@mehen/protocol"
import { accessState, digest, principalOf, setProjectShare } from "../src/vault/areas/workspace-runtime.ts"
import { workspaceDeviceOps } from "../src/vault/areas/workspace-devices.ts"
import { VaultError } from "../src/http.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { beginAccessSideEffectChecks, finishAccessSideEffectChecks, accessFixture, accessSnapshot, accountAuth, inAccess, registerFixtureLifecycleHooks, workspaceInvoke } from "./access-test-support.ts"
import { fixtureSql } from "./fixture-sql.ts"

async function scope(tenant: string, tags: string[] = []): Promise<WorkspaceDeviceScope> { return inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); const value = { ...accessState(ctx).devices.find((d) => d.id === "dev_member")!.scope, tags }; ctx.sql.exec("UPDATE devices SET scope=? WHERE id='dev_member'", canonicalJson(value)); return value }) }
async function propose(tenant: string, before: WorkspaceDeviceScope, after: WorkspaceDeviceScope) {
  const result = await workspaceInvoke(tenant, "devices.rescope", { device: "dev_member", before, after }, accountAuth("admin", { type: "device.rescope", device: "dev_member", thumbprint: "dev_member", before, after }))
  if (!result.ok) throw new Error(JSON.stringify(result))
  const view = RescopeProposalViewSchema.parse(result.value)
  return inAccess(tenant, (ctx) => DeviceRescopeProposalSchema.parse(JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM device_rescope_proposals WHERE id=?", view.id).toArray()[0]!.value)))
}
beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)

describe("workspace device rescope", () => {
  it.each(["last-tag", "last-project", "mixed", "private-tick", "tag-addition", "mode", "environment", "service-runs"] as const)("requires stored owner acceptance for %s widening", async (change) => {
    const { tenant } = await accessFixture()
    let before = await scope(tenant, change === "last-tag" || change === "mixed" || change === "tag-addition" ? ["ai"] : [])
    if (change === "last-project") { before = { ...before, projects: ["prj_a"] }; await inAccess(tenant, (ctx) => ctx.sql.exec("UPDATE devices SET scope=? WHERE id='dev_member'", canonicalJson(before))) }
    if (change === "mode" || change === "environment") { before = { ...before, modes: ["relay"], maxEnvironment: "unprotected" }; await inAccess(tenant, (ctx) => ctx.sql.exec("UPDATE devices SET scope=? WHERE id='dev_member'", canonicalJson(before))) }
    const after = { ...before, ...(change === "tag-addition" ? { tags: ["ai", "code"] } : change === "mode" ? { modes: ["relay", "lease"] as WorkspaceDeviceScope["modes"] } : change === "environment" ? { maxEnvironment: "protected" as const } : change === "last-tag" ? { tags: [] } : change === "last-project" ? { projects: [] } : change === "mixed" ? { tags: ["code"], maxEnvironment: "unprotected" as const } : change === "service-runs" ? { serviceRuns: true } : { privateCredentials: true }) }
    const proposal = await propose(tenant, before, after)
    expect(proposal.state).toBe("open")
    expect(proposal.requiredSigners).toEqual([{ account: "acc_member", name: "member", as: "owner_acceptance" }])
    await inAccess(tenant, (ctx) => expect(accessState(ctx).devices.find((d) => d.id === "dev_member")?.scope).toEqual(before))
    const snapshot = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: proposal.id }, accountAuth("admin", { type: "device.rescope_accept", device: "dev_member", thumbprint: "dev_member", account: "acc_member", before, after, admission: false }))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    expect(await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: proposal.id }, accountAuth("member", { type: "device.rescope_accept", device: "dev_member", thumbprint: "dev_member", account: "acc_member", before, after, admission: false }))).toMatchObject({ ok: true, value: { state: "committed" } })
    await inAccess(tenant, (ctx) => expect(accessState(ctx).devices.find((d) => d.id === "dev_member")?.scope).toEqual(after))
  })
  it("refuses a scope with fill on every rescope path while BROWSER_FILL is off, whatever the machine's mehen", async () => {
    const { tenant } = await accessFixture()
    const before = await scope(tenant)
    const after: WorkspaceDeviceScope = { ...before, modes: [...before.modes, "fill"] }
    const snapshot = await accessSnapshot(tenant)
    const refused = { error: "mode_refused", message: "Typing into web pages is not available yet." }
    await inAccess(tenant, async (ctx) => {
      ctx.sql.exec("UPDATE devices SET last_cli_version='0.3.17' WHERE id='dev_member'")
      const off = Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, BROWSER_FILL: "off" } })
      const call = async (op: string, input: unknown, auth: ReturnType<typeof accountAuth>) => {
        try { await workspaceDeviceOps[op]!.handler(off, principalOf(off, auth), input, { auth, workspace: { id: ctx.tenant, slug: "work", name: "Work" } }); return null } catch (error) { return error instanceof VaultError ? error.toJSON() : error }
      }
      for (const role of ["admin", "member"]) expect(await call("devices.rescope", { device: "dev_member", before, after }, accountAuth(role, { type: "device.rescope", device: "dev_member", thumbprint: "dev_member", before, after }))).toEqual(refused)
      for (const kind of ["rescope", "rescope_propose"]) expect(await call("access.devices.action", { device: "dev_member", change: { kind, before, after } }, accountAuth("admin"))).toEqual(refused)
      ctx.sql.exec("UPDATE devices SET last_cli_version=NULL WHERE id='dev_member'")
    })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    await inAccess(tenant, (ctx) => expect(ctx.sql.exec("SELECT id FROM device_rescope_proposals").toArray()).toEqual([]))
  })
  it("takes service runs away at once, with no proposal", async () => {
    const { tenant } = await accessFixture()
    const before = { ...await scope(tenant), serviceRuns: true }
    await inAccess(tenant, (ctx) => ctx.sql.exec("UPDATE devices SET scope=? WHERE id='dev_member'", canonicalJson(before)))
    const after = { ...before, serviceRuns: false }
    expect(await workspaceInvoke(tenant, "devices.rescope", { device: "dev_member", before, after }, accountAuth("member", { type: "device.rescope", device: "dev_member", thumbprint: "dev_member", before, after }))).toMatchObject({ ok: true, value: { state: "committed", scope: after } })
    await inAccess(tenant, (ctx) => {
      expect(accessState(ctx).devices.find((d) => d.id === "dev_member")?.scope).toEqual(after)
      expect(ctx.sql.exec("SELECT id FROM device_rescope_proposals").toArray()).toEqual([])
    })
  })
  it("narrows immediately but voids stale proposals, including changed owner/key revisions", async () => {
    const { tenant } = await accessFixture()
    const before = await scope(tenant)
    const proposal = await propose(tenant, before, { ...before, privateCredentials: true })
    const after = { ...before, tags: ["ai"] }
    expect(await workspaceInvoke(tenant, "devices.rescope", { device: "dev_member", before, after }, accountAuth("admin", { type: "device.rescope", device: "dev_member", thumbprint: "dev_member", before, after }))).toMatchObject({ ok: true, value: { state: "committed" } })
    const snapshot = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: proposal.id }, accountAuth("member", { type: "device.rescope_accept", device: "dev_member", thumbprint: "dev_member", account: "acc_member", before, after: proposal.after, admission: false }))).toMatchObject({ ok: false, error: { vaultError: { error: "conflict" } } })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    await inAccess(tenant, (ctx) => expect(JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM device_rescope_proposals WHERE id=?", proposal.id).toArray()[0]!.value).state).toBe("void"))
  })
  it.each(["expired", "owner", "key"] as const)("refuses a %s proposal without changing scope or audit", async (variant) => {
    const { tenant } = await accessFixture()
    const before = await scope(tenant)
    const after = { ...before, privateCredentials: true }
    const proposal = await propose(tenant, before, after)
    await inAccess(tenant, (ctx) => {
      if (variant === "owner") fixtureSql(ctx).exec("UPDATE members SET revision=revision+1 WHERE id='mem_member'")
      if (variant === "key") ctx.sql.exec("UPDATE devices SET thumbprint='different' WHERE id='dev_member'")
      if (variant === "expired") ctx.sql.exec("UPDATE device_rescope_proposals SET value=? WHERE id=?", canonicalJson({ ...proposal, expiresAt: new Date(ctx.now() - 1).toISOString() }), proposal.id)
    })
    const snapshot = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: proposal.id }, accountAuth("member", { type: "device.rescope_accept", device: "dev_member", thumbprint: "dev_member", account: "acc_member", before, after, admission: false }))).toEqual({ ok: false, error: { status: 409, vaultError: { error: "conflict", message: "This scope proposal expired or changed. Review a new proposal." } } })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
  })
  it("guest widening needs both independent admission and the owning account's exact acceptance", async () => {
    const { tenant } = await accessFixture()
    const before = await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); return accessState(ctx).devices.find((d) => d.id === "dev_guest")!.scope })
    const after = { ...before, privateCredentials: true }
    const proposed = await workspaceInvoke(tenant, "devices.rescope", { device: "dev_guest", before, after, project: "prj_a" }, accountAuth("admin", { type: "device.rescope", device: "dev_guest", thumbprint: "dev_guest", before, after }))
    if (!proposed.ok) throw new Error(JSON.stringify(proposed))
    const proposal = RescopeProposalViewSchema.parse(proposed.value)
    expect(proposal.requiredSigners.map((signer) => signer.as).sort()).toEqual(["admission", "owner_acceptance"])
    expect(proposal).not.toHaveProperty("signatures")
    await inAccess(tenant, (ctx) => expect(DeviceRescopeProposalSchema.parse(JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM device_rescope_proposals WHERE id=?", proposal.id).toArray()[0]!.value)).signatures).toHaveLength(1))
    await inAccess(tenant, (ctx) => expect(accessState(ctx).devices.find((d) => d.id === "dev_guest")?.scope).toEqual(before))
    const snapshot = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_admit", { proposal: proposal.id, project: "prj_a" }, accountAuth("guest", { type: "device.rescope", device: "dev_guest", thumbprint: "dev_guest", before, after }))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    expect(await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: proposal.id }, accountAuth("guest", { type: "device.rescope_accept", device: "dev_guest", thumbprint: "dev_guest", account: "acc_guest", before, after, admission: true }))).toMatchObject({ ok: true, value: { state: "committed" } })
  })

  it("plans every canonical device action without changing state and hides invisible machines", async () => {
    const { tenant } = await accessFixture()
    const before = await scope(tenant)
    const after = { ...before, privateCredentials: true }
    const memberProposal = await propose(tenant, before, after)
    const guestBefore = await inAccess(tenant, (ctx) => accessState(ctx).devices.find((d) => d.id === "dev_guest")!.scope)
    const guestAfter = { ...guestBefore, privateCredentials: true }
    const guestResult = await workspaceInvoke(tenant, "devices.rescope", { device: "dev_guest", before: guestBefore, after: guestAfter, project: "prj_a" }, accountAuth("admin", { type: "device.rescope", device: "dev_guest", thumbprint: "dev_guest", before: guestBefore, after: guestAfter }))
    if (!guestResult.ok) throw new Error(JSON.stringify(guestResult))
    const guestProposal = RescopeProposalViewSchema.parse(guestResult.value)
    const snapshot = await accessSnapshot(tenant)
    const cases = [
      { device: "dev_member", auth: accountAuth("admin"), change: { kind: "rescope", before, after: { ...before, tags: ["ai"] } }, type: "device.rescope" },
      { device: "dev_member", auth: accountAuth("admin"), change: { kind: "rescope_propose", before, after }, type: "device.rescope" },
      { device: "dev_member", auth: accountAuth("member"), change: { kind: "rescope_accept", proposal: memberProposal.id }, type: "device.rescope_accept" },
      { device: "dev_guest", auth: accountAuth("admin"), change: { kind: "rescope_admit", proposal: guestProposal.id }, type: "device.rescope" },
      { device: "dev_member", auth: accountAuth("admin"), change: { kind: "revoke" }, type: "device.revoke" },
    ]
    for (const entry of cases) {
      const planned = await workspaceInvoke(tenant, "access.devices.action", { device: entry.device, change: entry.change, project: "prj_a" }, entry.auth)
      expect(planned).toMatchObject({ ok: true, value: { action: { type: entry.type, device: entry.device } } })
      if (entry.type !== "device.revoke") expect(planned).toMatchObject({ value: { action: { thumbprint: entry.device } } })
    }
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    const hidden = await workspaceInvoke(tenant, "access.devices.action", { device: "dev_owner", change: { kind: "revoke" } }, accountAuth("member"))
    const absent = await workspaceInvoke(tenant, "access.devices.action", { device: "dev_missing", change: { kind: "revoke" } }, accountAuth("member"))
    expect(hidden).toEqual(absent)
    expect(hidden).toEqual({ ok: false, error: { status: 404, vaultError: { error: "not_found", message: "No such machine." } } })
    expect(await workspaceInvoke(tenant, "access.devices.action", { device: "dev_member", change: { kind: "rescope_accept", proposal: memberProposal.id } }, accountAuth("admin"))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
  })

  it("refuses an existing proposal that raises protected reach beyond the admitting manager's projects", async () => {
    const { tenant } = await accessFixture()
    let before: WorkspaceDeviceScope = { tags: [], projects: [], modes: ["relay"], maxEnvironment: "unprotected", privateCredentials: false }
    await inAccess(tenant, (ctx) => {
      registerFixtureLifecycleHooks()
      setProjectShare(ctx, { id: "shr_guest_b", project: "prj_b", subject: { kind: "member", member: "mem_guest" }, level: "use", protected: true, expiresAt: null }, null)
      before = { ...accessState(ctx).devices.find((d) => d.id === "dev_guest")!.scope, projects: ["prj_a", "prj_b"], maxEnvironment: "unprotected" }
      ctx.sql.exec("UPDATE devices SET scope=? WHERE id='dev_guest'", canonicalJson(before))
      const after = { ...before, maxEnvironment: "protected" as const }
      // A persisted two-party proposal must be re-evaluated after the rule fix.
      const proposal = DeviceRescopeProposalSchema.parse({ id: "rsp_review", device: "dev_guest", thumbprint: "dev_guest", before, after, beforeDigest: digest(before), afterDigest: digest(after), proposer: { member: "mem_guest", name: "guest" }, owner: { kind: "member", member: "mem_guest", name: "guest" }, requiredSigners: [{ account: "acc_guest", name: "guest", as: "owner_acceptance" }, { account: "acc_kim", name: "Kim", as: "admission" }], signedBy: ["acc_guest"], signatures: [{ account: "acc_guest", as: "owner_acceptance", digest: "owner-signed", factor: "pk_fixture", identityCheck: null, at: new Date().toISOString() }], expiresAt: new Date(ctx.now() + 600_000).toISOString(), state: "open", deviceRevision: 0, ownerRevision: 1, scopeRevision: 0 })
      ctx.sql.exec("INSERT INTO device_rescope_proposals VALUES (?,?,?)", proposal.id, proposal.device, canonicalJson(proposal))
    })
    const after = { ...before, maxEnvironment: "protected" as const }
    const snapshot = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_admit", { proposal: "rsp_review", project: "prj_a" }, accountAuth("kim", { type: "device.rescope", device: "dev_guest", thumbprint: "dev_guest", before, after }))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    await inAccess(tenant, (ctx) => {
      const state = accessState(ctx)
      const device = state.devices.find((d) => d.id === "dev_guest")!
      expect(reach(state, device, ctx.now()).projects.prj_b?.runProtected).toBe(false)
    })
  })

})

it.each(["none", "rule", "unlink"] as const)("lets a guest name a covered insider but keeps actual signing and retained evidence strict (%s)", async change => {
  const { setSetting } = await import("../src/vault/areas/workspace-runtime.ts")
  const { installTestIdentity } = await import("./access-test-support.ts")
  const { tenant } = await accessFixture()
  const before = await inAccess(tenant, ctx => { registerFixtureLifecycleHooks(); setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["owner"] }); return accessState(ctx).devices.find(d => d.id === "dev_guest")!.scope })
  const after = { ...before, privateCredentials: true }, action = { type: "device.rescope", device: "dev_guest", thumbprint: "dev_guest", before, after } as const
  const result = await workspaceInvoke(tenant, "devices.rescope", { device: "dev_guest", before, after, project: "prj_a", admissionMember: "mem_owner" }, accountAuth("guest", action))
  expect(result).toMatchObject({ ok: true, value: { state: "open" } })
  if (!result.ok) throw new Error(JSON.stringify(result))
  const proposal = RescopeProposalViewSchema.parse(result.value), owner = accountAuth("owner", action)
  const unsigned = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "devices.rescope_admit", { proposal: proposal.id, project: "prj_a" }, owner)).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
  expect(await accessSnapshot(tenant)).toBe(unsigned)
  owner.sessionCheck = { id: "chk_owner", identityRuleRev: 0, gateGeneration: 0, checkSequence: 1, succeededAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() }
  await inAccess(tenant, ctx => installTestIdentity(ctx, owner))
  const gated = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "devices.rescope_admit", { proposal: proposal.id, project: "prj_a" }, owner)).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
  expect(await accessSnapshot(tenant)).toBe(gated)
  owner.operationCheck = { id: "opc_owner", subjectDigest: digest(action), identityRuleRev: 0, gateGeneration: 0, succeededAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() }
  expect(await workspaceInvoke(tenant, "devices.rescope_admit", { proposal: proposal.id, project: "prj_a" }, owner)).toMatchObject({ ok: true, value: { state: "open" } })
  if (change === "rule") await inAccess(tenant, ctx => setSetting(ctx, "identity_rule_rev", 1))
  if (change === "unlink") expect(await workspaceInvoke(tenant, "access.identity.install", { account: owner.account, member: "mem_owner", session: owner.session, securityEpoch: 0, sessionCheck: null,invalidation: "rescope-unlink" }, { kind: "system", reason: "unlink" })).toMatchObject({ ok: true })
  const saved = await accessSnapshot(tenant)
  const accepted = await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: proposal.id }, accountAuth("guest", { type: "device.rescope_accept", device: "dev_guest", thumbprint: "dev_guest", account: "acc_guest", before, after, admission: true }))
  if (change === "none") expect(accepted).toMatchObject({ ok: true, value: { state: "committed" } })
  else { expect(accepted).toMatchObject({ ok: false, error: { vaultError: { error: "conflict" } } }); expect(await accessSnapshot(tenant)).toBe(saved) }
})

it.each(["missing", "subject", "revision", "generation", "expired", "future"] as const)("F2: a covered insider's proposal-time admission refuses %s operation evidence", async kind => {
  const { setSetting } = await import("../src/vault/areas/workspace-runtime.ts"), { installTestIdentity } = await import("./access-test-support.ts")
  const { tenant } = await accessFixture()
  const before = await inAccess(tenant, ctx => { registerFixtureLifecycleHooks(); setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["owner"] }); return accessState(ctx).devices.find(d => d.id === "dev_guest")!.scope })
  const after = { ...before, privateCredentials: true }, action = { type: "device.rescope", device: "dev_guest", thumbprint: "dev_guest", before, after } as const
  const owner = accountAuth("owner", action)
  owner.sessionCheck = { id: "chk_owner", identityRuleRev: 0, gateGeneration: 0, checkSequence: 1, succeededAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() }
  await inAccess(tenant, ctx => installTestIdentity(ctx, owner))
  const valid = { id: "opc_valid", subjectDigest: digest(action), identityRuleRev: 0, gateGeneration: 0, succeededAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() }
  owner.operationCheck = kind === "missing" ? undefined : { ...valid, ...(kind === "subject" ? { subjectDigest: "wrong" } : kind === "revision" ? { identityRuleRev: 99 } : kind === "generation" ? { gateGeneration: 99 } : kind === "expired" ? { expiresAt: new Date(Date.now() - 1).toISOString() } : { succeededAt: new Date(Date.now() + 60_000).toISOString() }) }
  const snapshot = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "devices.rescope", { device: "dev_guest", before, after, project: "prj_a" }, owner)).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
  expect(await accessSnapshot(tenant)).toBe(snapshot)
  owner.operationCheck = valid
  const proposed = await workspaceInvoke(tenant, "devices.rescope", { device: "dev_guest", before, after, project: "prj_a" }, owner)
  expect(proposed).toMatchObject({ ok: true })
  if (!proposed.ok) throw new Error(JSON.stringify(proposed))
  expect(await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: RescopeProposalViewSchema.parse(proposed.value).id }, accountAuth("guest", { type: "device.rescope_accept", device: "dev_guest", thumbprint: "dev_guest", account: "acc_guest", before, after, admission: true }))).toMatchObject({ ok: true, value: { state: "committed" } })
})

it("F3: covered team-machine widening is an exact admission, while narrowing stays immediate", async () => {
  const { setSetting } = await import("../src/vault/areas/workspace-runtime.ts"), { installTestIdentity } = await import("./access-test-support.ts")
  const { tenant } = await accessFixture()
  const before = await inAccess(tenant, ctx => { registerFixtureLifecycleHooks(); setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["owner"] }); return accessState(ctx).devices.find(d => d.id === "dev_service")!.scope })
  const narrow = { ...before, maxEnvironment: "unprotected" as const }, owner = accountAuth("owner", { type: "device.rescope", device: "dev_service", thumbprint: "dev_service", before, after: narrow })
  owner.sessionCheck = { id: "chk_owner", identityRuleRev: 0, gateGeneration: 0, checkSequence: 1, succeededAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() }
  await inAccess(tenant, ctx => installTestIdentity(ctx, owner))
  expect(await workspaceInvoke(tenant, "devices.rescope", { device: "dev_service", before, after: narrow }, owner)).toMatchObject({ ok: true, value: { state: "committed" } })
  const action = { type: "device.rescope", device: "dev_service", thumbprint: "dev_service", before: narrow, after: before } as const
  owner.stepUp = action
  const snapshot = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "devices.rescope", { device: "dev_service", before: narrow, after: before }, owner)).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
  expect(await accessSnapshot(tenant)).toBe(snapshot)
  owner.operationCheck = { id: "opc_team", subjectDigest: digest(action), identityRuleRev: 0, gateGeneration: 0, succeededAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() }
  expect(await workspaceInvoke(tenant, "devices.rescope", { device: "dev_service", before: narrow, after: before }, owner)).toMatchObject({ ok: true, value: { state: "committed" } })
})
