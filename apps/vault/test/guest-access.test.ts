import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { can, eligibility } from "../src/vault/access.ts"
import { accessState, PendingEnrolSchema } from "../src/vault/areas/workspace-runtime.ts"
import { accessFixture, accessSnapshot, accountAuth, beginAccessSideEffectChecks, finishAccessSideEffectChecks, inAccess, workspaceInvoke } from "./access-test-support.ts"
import { fixtureSql } from "./fixture-sql.ts"
beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)
describe("workspace guest boundaries", () => {
  it("refuses people, teams and freeze uniformly without side effects", async () => {
    const { tenant } = await accessFixture()
    const before = await accessSnapshot(tenant)
    for (const op of ["access.members.list", "access.teams.read", "access.freeze"]) expect(await workspaceInvoke(tenant, op, {}, accountAuth("guest"))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
  })
  it("allows only reference-derived workspace reach and owns only private asks", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      const state = accessState(ctx)
      const device = { kind: "device", deviceId: "dev_guest" } as const
      expect(can(state, device, { type: "item.use", context: null }, { credential: "itm_workspace" }, ctx.now())).toEqual({ allowed: false, error: "not_found", message: "No such object." })
      expect(can(state, device, { type: "item.use", context: { project: "prj_a", environment: "dev" } }, { credential: "itm_workspace" }, ctx.now())).toEqual({ allowed: true, stepUp: null })
      const ask = { device: "dev_guest", credential: "itm_workspace", credentials: ["itm_workspace"], context: { project: "prj_a", environment: "dev" } }
      expect(eligibility(state, "mem_guest", ask, ctx.now())).toMatchObject({ canApprove: false, deciders: [] })
      expect(eligibility(state, "mem_kim", ask, ctx.now())).toMatchObject({ canApprove: true, canReadAskDetail: true, deciders: [] })
      expect(eligibility(state, "mem_guest", { ...ask, device: "dev_member" }, ctx.now())).toMatchObject({ canApprove: false, canDeny: false, canReadAskDetail: false, deciders: [] })
      const own = state.devices.find((d) => d.id === "dev_guest")!
      ctx.sql.exec("UPDATE devices SET scope=? WHERE id='dev_guest'", JSON.stringify({ ...own.scope, privateCredentials: true }))
      const live = accessState(ctx)
      expect(eligibility(live, "mem_guest", { device: "dev_guest", credential: "itm_guest", credentials: ["itm_guest"], context: null }, ctx.now())).toMatchObject({ canApprove: true, canReadAskDetail: true, deciders: [] })
      expect(eligibility(live, "mem_owner", { device: "dev_guest", credential: "itm_guest", credentials: ["itm_guest"], context: null }, ctx.now())).toMatchObject({ canApprove: false, canDeny: true, canReadAskDetail: false })
    })
  })
  it("keeps other signers' account, factor and identity evidence out of guest machine and proposal views", async () => {
    const { tenant } = await accessFixture()
    const at = new Date().toISOString()
    const before = await inAccess(tenant, (ctx) => {
      ctx.sql.exec("UPDATE devices SET thumbprint=?,acceptance=?,admission=? WHERE id='dev_guest'", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", JSON.stringify({ account: "acc_guest", member: "mem_guest", digest: "own", ruleRevision: 0, gateGeneration: 0, identityCheck: null, at }), JSON.stringify({ account: "acc_admin", member: "mem_admin", digest: "other", ruleRevision: 0, gateGeneration: 0, identityCheck: "chk_admin", at }))
      return accessState(ctx).devices.find((d) => d.id === "dev_guest")!.scope
    })
    const listed = await workspaceInvoke(tenant, "devices.list", {}, accountAuth("guest"))
    expect(listed).toMatchObject({ ok: true, value: { devices: [{ acceptance: { account: "acc_guest" }, admission: { name: "admin", at } }] } })
    const after = { ...before, privateCredentials: true }
    const input = { device: "dev_guest", before, after, project: "prj_a" }
    const auth = accountAuth("guest", { type: "device.rescope", device: "dev_guest", thumbprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", before, after })
    const snapshot = await accessSnapshot(tenant)
    const refusal = { ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "Choose an eligible insider for this guest's shared project." } } }
    for (const admissionAccount of ["acc_unknown", "acc_member", "acc_kim"]) expect(await workspaceInvoke(tenant, "devices.rescope", { ...input, admissionAccount }, auth)).toEqual(refusal)
    for (const admissionMember of ["mem_unknown", "mem_member"]) expect(await workspaceInvoke(tenant, "devices.rescope", { ...input, admissionMember }, auth)).toEqual(refusal)
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    const proposed = await workspaceInvoke(tenant, "devices.rescope", { ...input, admissionMember: "mem_kim" }, auth)
    expect(proposed).toMatchObject({ ok: true, value: { requiredSigners: [{ account: "acc_guest", as: "owner_acceptance" }, { name: "Kim", as: "admission" }] } })
    if (!proposed.ok) throw new Error(JSON.stringify(proposed))
    const proposal = proposed.value as { id: string }
    const accepted = await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: proposal.id }, accountAuth("guest", { type: "device.rescope_accept", device: "dev_guest", thumbprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", account: "acc_guest", before, after, admission: true }))
    expect(accepted).toMatchObject({ ok: true, value: { signedBy: ["acc_guest"] } })
    for (const response of [listed, proposed, accepted]) {
      const json = JSON.stringify(response)
      expect(json).not.toContain("acc_admin")
      expect(json).not.toContain("acc_kim")
      expect(json).not.toContain("pk_fixture")
      expect(json).not.toContain("chk_admin")
      expect(json).not.toContain('"signatures"')
    }
  })
  it("projects another enrolment signer's evidence to name and time for the guest", async () => {
    const { tenant } = await accessFixture()
    const { newDeviceKey, publicJwk } = await import("./devices.ts")
    const { jwkThumbprint } = await import("@mehen/protocol")
    const jwk = await publicJwk(await newDeviceKey())
    const raw = { enrolment: "enr_guest_evidence", start: { at: new Date().toISOString(), place: null, clientLabel: "Terminal" }, thumbprint: await jwkThumbprint(jwk), requestedOwner: { kind: "self" }, claimedAccount: null, scope: { tags: [], projects: ["prj_a"], modes: ["relay"], maxEnvironment: "unprotected" }, detail: { name: "Laptop", backend: "software", host: null, jwk, codeHash: "do-not-expose-this-hash", hardExpiresAt: new Date(Date.now() + 600_000).toISOString() } }
    const registered = await workspaceInvoke(tenant, "access.enrol.register", raw, { kind: "system", reason: "test" })
    if (!registered.ok) throw new Error(JSON.stringify(registered))
    const pending = PendingEnrolSchema.parse(registered.value)
    expect(await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: pending.enrolment, privateCredentials: false }, accountAuth("guest", { type: "enrol.accept", enrolment: pending.enrolment, workspace: tenant, thumbprint: pending.thumbprint, account: "acc_guest", member: "mem_guest", scope: pending.scope, start: pending.start }))).toMatchObject({ ok: true })
    expect(await workspaceInvoke(tenant, "access.enrol.admit", { enrolment: pending.enrolment, project: "prj_a" }, accountAuth("kim", { type: "enrol.approve", enrolment: pending.enrolment, digest: pending.digest, owner: { kind: "member", member: "mem_guest", name: "guest" }, admissionRole: "member" }))).toMatchObject({ ok: true })
    const view = await workspaceInvoke(tenant, "access.enrol.view", { enrolment: pending.enrolment }, accountAuth("guest"))
    expect(view).toMatchObject({ ok: true, value: { acceptance: { account: "acc_guest" }, admission: { name: "Kim", at: expect.any(String) } } })
    const json = JSON.stringify(view)
    expect(json).not.toContain("acc_kim")
    expect(json).not.toContain("mem_kim")
    expect(json).not.toContain("do-not-expose-this-hash")
    expect(json).not.toContain("codeHash")
  })
  it("only lets an owner unfreeze, with an exact confirmation", async () => {
    const { tenant } = await accessFixture()
    expect(await workspaceInvoke(tenant, "access.freeze", {}, accountAuth("member"))).toEqual({ ok: true, value: {} })
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.unfreeze", {}, accountAuth("admin", { type: "workspace.unfreeze" }))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
    expect(await workspaceInvoke(tenant, "access.unfreeze", {}, accountAuth("owner", { type: "workspace.unfreeze" }))).toEqual({ ok: true, value: {} })
  })

})

it("hides membership status and existence before role, suspend or reinstate authority", async () => {
  const { newMember } = await import("../src/vault/areas/workspace-runtime.ts")
  const { tenant } = await accessFixture()
  await inAccess(tenant, ctx => { newMember(ctx, "acc_new", "Pending", "member", "unconfirmed", "mem_new"); fixtureSql(ctx).exec("UPDATE members SET status='suspended' WHERE id='mem_kim'") })
  const before = await accessSnapshot(tenant)
  for (const member of ["mem_new", "mem_member", "mem_kim", "mem_absent"]) {
    for (const change of ["role", "suspend", "reinstate", "confirm", "remove"] as const) {
      const input = { member, ...(change === "role" ? { role: "admin" } : {}) }
      const expected = { ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } }
      for (const role of ["guest", "member"]) {
        expect(await workspaceInvoke(tenant, `access.members.${change}`, input, accountAuth(role))).toEqual(expected)
        expect(await workspaceInvoke(tenant, "access.members.action", { ...input, change }, accountAuth(role))).toEqual(expected)
      }
    }
  }
  expect(await accessSnapshot(tenant)).toBe(before)
})
