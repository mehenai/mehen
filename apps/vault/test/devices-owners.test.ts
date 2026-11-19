import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { jwkThumbprint } from "@mehen/protocol"
import type { EnrolRequestedScope } from "@mehen/protocol"
import { PendingEnrolSchema, PendingEnrolViewSchema, newMember } from "../src/vault/areas/workspace-runtime.ts"
import type { PendingEnrolRecord as PendingEnrol } from "../src/vault/areas/workspace-runtime.ts"
import { enrolmentWording } from "../src/vault/areas/workspace-devices.ts"
import { beginAccessSideEffectChecks, finishAccessSideEffectChecks, accessFixture, accessSnapshot, accountAuth, inAccess, registerFixtureLifecycleHooks, workspaceInvoke, editAccessFixture } from "./access-test-support.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"
const system = { kind: "system", reason: "test" } as const
export async function registerEnrolment(tenant: string, account = "acc_member", kind: "self" | "team" = "self", options: { team?: string; projects?: string[]; maxEnvironment?: "protected" | "unprotected"; requested?: EnrolRequestedScope } = {}): Promise<PendingEnrol> {
  const jwk = await publicJwk(await newDeviceKey())
  const input = { enrolment: `enr_${crypto.randomUUID().replaceAll("-", "")}`, start: { at: new Date().toISOString(), place: "Amsterdam", clientLabel: "Terminal label, not verified" }, thumbprint: await jwkThumbprint(jwk), requestedOwner: kind === "self" ? { kind: "self" } : { kind: "team", team: options.team ?? "tm_service" }, claimedAccount: null, scope: { tags: [], projects: options.projects ?? (account === "acc_guest" ? ["prj_a"] : []), maxEnvironment: options.maxEnvironment ?? "unprotected", modes: ["relay"] }, detail: { name: "Laptop", backend: "software", host: "laptop.local", jwk, codeHash: "hash-only", hardExpiresAt: new Date(Date.now() + 600_000).toISOString() }, ...(options.requested ? { requested: options.requested } : {}) }
  const result = await workspaceInvoke(tenant, "access.enrol.register", input, system)
  if (!result.ok) throw new Error(JSON.stringify(result))
  return PendingEnrolSchema.parse(result.value)
}
export function acceptance(tenant: string, pending: PendingEnrol, role = "member", privateCredentials = pending.scope.privateCredentials) {
  return accountAuth(role, { type: "enrol.accept", enrolment: pending.enrolment, workspace: tenant, thumbprint: pending.thumbprint, account: `acc_${role}`, member: `mem_${role}`, scope: { ...pending.scope, privateCredentials }, start: pending.start })
}
beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)

describe("workspace machine ownership", () => {
  it("the sole owner's view planning is on; register is off", async () => {
    const { tenant } = await accessFixture()
    expect((await registerEnrolment(tenant)).scope.privateCredentials).toBe(false)
    expect((await registerEnrolment(tenant, "acc_guest")).scope.privateCredentials).toBe(false)
    expect((await registerEnrolment(tenant, "acc_owner", "team")).scope.privateCredentials).toBe(false)
    await inAccess(tenant, (ctx) => ctx.sql.exec("UPDATE members SET status='suspended' WHERE role!='owner'"))
    const sole = await registerEnrolment(tenant, "acc_owner")
    expect(sole.scope.privateCredentials).toBe(false)
    const viewed = await workspaceInvoke(tenant, "access.enrol.view", { enrolment: sole.enrolment }, accountAuth("owner"))
    expect(viewed).toMatchObject({ ok: true, value: { defaultPrivateCredentials: true, actions: ["accept", "reject"], scope: { privateCredentials: false }, planning: { scope: { privateCredentials: true } } } })
    if (viewed.ok) {
      const planning = PendingEnrolViewSchema.parse(viewed.value).planning!
      const accepted = await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: sole.enrolment, privateCredentials: planning.scope.privateCredentials }, acceptance(tenant, sole, "owner", true))
      expect(accepted).toMatchObject({ ok: true, value: { digest: planning.digest, state: "active" } })
    }
  })
  it("in a shared workspace a member's own machine views with private credentials on; a guest's, a team's and a --no-private one off", async () => {
    const { tenant } = await accessFixture()
    const view = async (pending: PendingEnrol, role: string) => {
      const viewed = await workspaceInvoke(tenant, "access.enrol.view", { enrolment: pending.enrolment }, accountAuth(role))
      if (!viewed.ok) throw new Error(JSON.stringify(viewed))
      return PendingEnrolViewSchema.parse(viewed.value)
    }
    for (const role of ["owner", "admin", "member"]) {
      const own = await registerEnrolment(tenant, `acc_${role}`)
      expect(own.scope.privateCredentials).toBe(false)
      expect(await view(own, role)).toMatchObject({ defaultPrivateCredentials: true, scope: { privateCredentials: false }, planning: { scope: { privateCredentials: true } } })
    }
    expect(await view(await registerEnrolment(tenant, "acc_guest"), "guest")).toMatchObject({ defaultPrivateCredentials: false, planning: { scope: { privateCredentials: false } } })
    expect(await view(await registerEnrolment(tenant, "acc_owner", "team"), "owner")).toMatchObject({ defaultPrivateCredentials: false, planning: null })
    const asked = await registerEnrolment(tenant, "acc_member", "self", { requested: { privateCredentials: false } })
    expect(await view(asked, "member")).toMatchObject({ defaultPrivateCredentials: false, planning: { scope: { privateCredentials: false } } })
    const member = await registerEnrolment(tenant)
    const planning = (await view(member, "member")).planning!
    expect(await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: member.enrolment, privateCredentials: true }, acceptance(tenant, member, "member", true))).toMatchObject({ ok: true, value: { digest: planning.digest, state: "active", scope: { privateCredentials: true } } })
  })
  it("never lets an admin admit on behalf of the owning account or change start context", async () => {
    const { tenant } = await accessFixture()
    const value = await registerEnrolment(tenant)
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: value.enrolment, privateCredentials: false }, accountAuth("admin", acceptance(tenant, value).stepUp))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "This needs a passkey confirmation of the exact action." } } })
    const wrong = acceptance(tenant, value)
    if (wrong.stepUp?.type === "enrol.accept") wrong.stepUp.start = { ...wrong.stepUp.start, clientLabel: "Different start" }
    expect(await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: value.enrolment, privateCredentials: false }, wrong)).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "This needs a passkey confirmation of the exact action." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
    expect(enrolmentWording("accept", "Sam").label).toBe("Accept as my own machine")
    expect(enrolmentWording("accept", "Sam").warning).toContain("If someone sent you this link, do not accept it")
    expect(enrolmentWording("admit", "Sam").label).toBe("Admit Sam's machine")
  })
  it("requires guest acceptance plus independent admission, and a tick change invalidates admission", async () => {
    const { tenant } = await accessFixture()
    const value = await registerEnrolment(tenant, "acc_guest")
    const admissionAuth = accountAuth("owner", { type: "enrol.approve", enrolment: value.enrolment, digest: value.digest, owner: { kind: "member", member: "mem_guest", name: "guest" }, admissionRole: "owner" })
    expect(await workspaceInvoke(tenant, "access.enrol.admit", { enrolment: value.enrolment }, admissionAuth)).toMatchObject({ ok: false, error: { vaultError: { error: "conflict" } } })
    expect(await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: value.enrolment, privateCredentials: false }, acceptance(tenant, value, "guest"))).toMatchObject({ ok: true, value: { state: "pending_admission" } })
    expect(await workspaceInvoke(tenant, "access.enrol.view", { enrolment: value.enrolment }, accountAuth("admin"))).toMatchObject({ ok: true, value: { planning: null } })
    // An earlier stored signature cannot survive a changed tick.
    await inAccess(tenant, (ctx) => {
      const row = ctx.sql.exec<{ value: string }>("SELECT value FROM workspace_enrolments WHERE id=?", value.enrolment).toArray()[0]!
      const stored = PendingEnrolSchema.parse(JSON.parse(row.value))
      stored.admission = { account: "acc_owner", member: "mem_owner", digest: stored.digest, ruleRevision: 0, gateGeneration: 0, identityCheck: null, at: new Date().toISOString() }
      ctx.sql.exec("UPDATE workspace_enrolments SET value=? WHERE id=?", JSON.stringify(stored), value.enrolment)
    })
    const accepted = await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: value.enrolment, privateCredentials: true }, acceptance(tenant, value, "guest", true))
    expect(accepted).toMatchObject({ ok: true, value: { state: "pending_admission", admission: null, acceptance: { account: "acc_guest" }, scope: { privateCredentials: true } } })
    if (!accepted.ok) throw new Error("accept failed")
    const current = PendingEnrolViewSchema.parse(accepted.value)
    expect(current.digest).not.toBe(value.digest)
    expect(await workspaceInvoke(tenant, "access.enrol.admit", { enrolment: value.enrolment }, admissionAuth)).toMatchObject({ ok: false, error: { vaultError: { error: "forbidden" } } })
    const active = await workspaceInvoke(tenant, "access.enrol.admit", { enrolment: value.enrolment }, accountAuth("kim", { type: "enrol.approve", enrolment: value.enrolment, digest: current.digest, owner: current.owner!, admissionRole: "member" }))
    expect(active).toMatchObject({ ok: true, value: { state: "active", device: expect.stringMatching(/^dev_/) } })
    await inAccess(tenant, (ctx) => expect(ctx.sql.exec("SELECT * FROM notice_outbox").toArray()).toHaveLength(2))
  })
  it("mirrors and discards only the exact source enrolment, once", async () => {
    const { tenant } = await accessFixture()
    const value = await registerEnrolment(tenant)
    const accepted = await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: value.enrolment, privateCredentials: false }, acceptance(tenant, value))
    if (!accepted.ok) throw new Error(JSON.stringify(accepted))
    const active = PendingEnrolViewSchema.parse(accepted.value)
    const pair = { enrolment: value.enrolment, device: active.device! }
    expect(await workspaceInvoke(tenant, "access.enrol.discard", { ...pair, enrolment: "enr_wrong" }, system)).toEqual({ ok: true, value: { discarded: false } })
    expect(await workspaceInvoke(tenant, "access.enrol.mirrored", { ...pair, enrolment: "enr_wrong" }, system)).toMatchObject({ ok: false, error: { vaultError: { error: "conflict" } } })
    expect(await workspaceInvoke(tenant, "access.enrol.mirrored", pair, system)).toEqual({ ok: true, value: { mirrored: true } })
    expect(await workspaceInvoke(tenant, "access.enrol.mirrored", pair, system)).toEqual({ ok: true, value: { mirrored: true } })
    expect(await workspaceInvoke(tenant, "access.enrol.discard", pair, system)).toEqual({ ok: true, value: { discarded: false } })
    const second = await registerEnrolment(tenant)
    const secondAccepted = await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: second.enrolment, privateCredentials: false }, acceptance(tenant, second))
    if (!secondAccepted.ok) throw new Error(JSON.stringify(secondAccepted))
    const secondPair = { enrolment: second.enrolment, device: PendingEnrolViewSchema.parse(secondAccepted.value).device! }
    expect(await workspaceInvoke(tenant, "access.enrol.discard", secondPair, system)).toEqual({ ok: true, value: { discarded: true } })
    expect(await workspaceInvoke(tenant, "access.enrol.discard", secondPair, system)).toEqual({ ok: true, value: { discarded: false } })
  })
  it("reconciles only the source enrolment without changing it, even after expiry", async () => {
    const { tenant } = await accessFixture()
    const pending = await registerEnrolment(tenant)
    expect(await workspaceInvoke(tenant, "access.enrol.reconcile", { enrolment: pending.enrolment }, system)).toEqual({ ok: true, value: { device: null, mirrored: false, state: "pending_owner_acceptance", active: null } })
    const accepted = await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: pending.enrolment, privateCredentials: false }, acceptance(tenant, pending))
    if (!accepted.ok) throw new Error(JSON.stringify(accepted))
    const acceptedView = PendingEnrolViewSchema.parse(accepted.value)
    const device = acceptedView.device!
    const active = { scope: acceptedView.scope, owner: acceptedView.owner, acceptance: acceptedView.acceptance, admission: acceptedView.admission }
    await inAccess(tenant, (ctx) => {
      const row = ctx.sql.exec<{ value: string }>("SELECT value FROM workspace_enrolments WHERE id=?", pending.enrolment).toArray()[0]!
      const value = PendingEnrolSchema.parse(JSON.parse(row.value))
      if (!value.detail) throw new Error("missing fixture details")
      value.detail.hardExpiresAt = new Date(ctx.now() - 1).toISOString()
      ctx.sql.exec("UPDATE workspace_enrolments SET value=? WHERE id=?", JSON.stringify(value), pending.enrolment)
    })
    let before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.enrol.reconcile", { enrolment: pending.enrolment }, system)).toEqual({ ok: true, value: { device, mirrored: false, state: "active", active } })
    expect(await accessSnapshot(tenant)).toBe(before)
    expect(await workspaceInvoke(tenant, "access.enrol.mirrored", { enrolment: pending.enrolment, device }, system)).toEqual({ ok: true, value: { mirrored: true } })
    before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.enrol.reconcile", { enrolment: pending.enrolment }, system)).toEqual({ ok: true, value: { device, mirrored: true, state: "active", active } })
    expect(await accessSnapshot(tenant)).toBe(before)
    await inAccess(tenant, (ctx) => ctx.sql.exec("UPDATE devices SET revoked_at=? WHERE id=?", ctx.now(), device))
    expect(await workspaceInvoke(tenant, "access.enrol.reconcile", { enrolment: pending.enrolment }, system)).toMatchObject({ ok: true, value: { active: null } })
  })

  it("stores a team intent without resolving existence and refuses an unknown team only at admission", async () => {
    const { tenant } = await accessFixture()
    const known = await registerEnrolment(tenant, "acc_owner", "team")
    const unknown = await registerEnrolment(tenant, "acc_owner", "team", { team: "tm_unknown" })
    expect(Object.keys(unknown).sort()).toEqual(Object.keys(known).sort())
    expect(unknown).toMatchObject({ state: known.state, owner: null, scope: known.scope, requestedOwner: { kind: "team", team: "tm_unknown" } })
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.enrol.admit", { enrolment: unknown.enrolment }, accountAuth("owner"))).toEqual({ ok: false, error: { status: 404, vaultError: { error: "not_found", message: "No such object." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
  })
  it("never returns the registered code hash in view, accept or admission responses", async () => {
    const { tenant } = await accessFixture()
    const pending = await registerEnrolment(tenant, "acc_guest")
    const view = await workspaceInvoke(tenant, "access.enrol.view", { enrolment: pending.enrolment }, accountAuth("guest"))
    const accepted = await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: pending.enrolment, privateCredentials: false }, acceptance(tenant, pending, "guest"))
    const admitted = await workspaceInvoke(tenant, "access.enrol.admit", { enrolment: pending.enrolment }, accountAuth("kim", { type: "enrol.approve", enrolment: pending.enrolment, digest: pending.digest, owner: { kind: "member", member: "mem_guest", name: "guest" }, admissionRole: "member" }))
    for (const response of [view, accepted, admitted]) {
      expect(response).toMatchObject({ ok: true })
      expect(JSON.stringify(response)).not.toContain("codeHash")
      expect(JSON.stringify(response)).not.toContain("hash-only")
    }
  })
  it("refuses an unrelated guest's rejection and records an authorised rejection as a member", async () => {
    const { tenant } = await accessFixture()
    const pending = await registerEnrolment(tenant, "acc_guest")
    expect(await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: pending.enrolment, privateCredentials: false }, acceptance(tenant, pending, "guest"))).toMatchObject({ ok: true })
    await inAccess(tenant, (ctx) => { newMember(ctx, "acc_guest2", "Other guest", "guest", "active", "mem_guest2") })
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.enrol.reject", { enrolment: pending.enrolment }, accountAuth("guest2"))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
    expect(await workspaceInvoke(tenant, "access.enrol.reject", { enrolment: pending.enrolment }, accountAuth("owner"))).toMatchObject({ ok: true, value: { state: "rejected" } })
    await inAccess(tenant, (ctx) => expect(ctx.sql.exec<{ actor: string }>("SELECT actor FROM audit WHERE action='device.enrol_rejected'").toArray()).toEqual([{ actor: "member:mem_owner" }]))
  })
  it("checks the entire effective guest scope when a manager admits an enrolment", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      ctx.sql.exec("INSERT INTO project_shares VALUES ('shr_guest_b','prj_b','member','mem_guest',?)", JSON.stringify({ id: "shr_guest_b", project: "prj_b", subject: { kind: "member", member: "mem_guest" }, level: "use", protected: true, expiresAt: null }))
      editAccessFixture(ctx, (state) => { state.projects.find((p) => p.id === "prj_b")!.environments[0]!.protected = true })
    })
    const pending = await registerEnrolment(tenant, "acc_guest", "self", { projects: ["prj_a", "prj_b"], maxEnvironment: "protected" })
    expect(await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: pending.enrolment, privateCredentials: false }, acceptance(tenant, pending, "guest"))).toMatchObject({ ok: true })
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.enrol.admit", { enrolment: pending.enrolment, project: "prj_a" }, accountAuth("kim", { type: "enrol.approve", enrolment: pending.enrolment, digest: pending.digest, owner: { kind: "member", member: "mem_guest", name: "guest" }, admissionRole: "member" }))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
  })

  it("re-registers immutable intent after acceptance changed the signed private tick", async () => {
    const { tenant } = await accessFixture()
    const pending = await registerEnrolment(tenant, "acc_guest")
    const accepted = await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: pending.enrolment, privateCredentials: true }, acceptance(tenant, pending, "guest", true))
    expect(accepted).toMatchObject({ ok: true, value: { state: "pending_admission", scope: { privateCredentials: true } } })
    const { privateCredentials: _tick, ...scope } = pending.scope
    const input = { enrolment: pending.enrolment, start: pending.start, thumbprint: pending.thumbprint, requestedOwner: pending.requestedOwner, claimedAccount: pending.claimedAccount, detail: pending.detail, scope }
    const before = await accessSnapshot(tenant)
    const repeated = await workspaceInvoke(tenant, "access.enrol.register", input, system)
    expect(repeated).toMatchObject({ ok: true, value: { state: "pending_admission", scope: { privateCredentials: true } } })
    if (accepted.ok && repeated.ok) expect(PendingEnrolSchema.parse(repeated.value).digest).toBe(PendingEnrolViewSchema.parse(accepted.value).digest)
    expect(await accessSnapshot(tenant)).toBe(before)
    expect(await workspaceInvoke(tenant, "access.enrol.view", { enrolment: pending.enrolment }, accountAuth("kim"))).toMatchObject({ ok: true, value: { actions: expect.arrayContaining(["admit"]) } })
    const changed = { ...input, start: { ...input.start, clientLabel: "changed" } }
    expect(await workspaceInvoke(tenant, "access.enrol.register", changed, system)).toEqual({ ok: false, error: { status: 409, vaultError: { error: "conflict", message: "This enrolment has different terms." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
    if (!accepted.ok) throw new Error(JSON.stringify(accepted))
    const view = PendingEnrolViewSchema.parse(accepted.value)
    expect(await workspaceInvoke(tenant, "access.enrol.admit", { enrolment: pending.enrolment, project: "prj_a" }, accountAuth("kim", { type: "enrol.approve", enrolment: pending.enrolment, digest: view.digest, owner: view.owner!, admissionRole: "member" }))).toMatchObject({ ok: true, value: { state: "active" } })
  })

})

it("projects the source enrolment start context only where the device is visible", async () => {
  const { tenant } = await accessFixture()
  const pending = await registerEnrolment(tenant)
  const accepted = await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: pending.enrolment, privateCredentials: false }, acceptance(tenant, pending))
  expect(accepted).toMatchObject({ ok: true, value: { state: "active" } })
  const device = await inAccess(tenant, ctx => {
    const id = ctx.sql.exec<{ id: string }>("SELECT id FROM devices WHERE enrolment=?", pending.enrolment).toArray()[0]!.id
    ctx.sql.exec("DELETE FROM devices WHERE id!=?", id)
    return id
  })
  const result = await workspaceInvoke(tenant, "devices.list", {}, accountAuth("member"))
  expect(result).toMatchObject({ ok: true, value: { devices: expect.arrayContaining([expect.objectContaining({ device, start: pending.start })]) } })
  await inAccess(tenant, ctx => ctx.sql.exec("UPDATE devices SET enrolment=NULL WHERE id=?", device))
  expect(await workspaceInvoke(tenant, "devices.list", {}, accountAuth("member"))).toMatchObject({ ok: true, value: { devices: [{ device, start: null }] } })
  const guest = await workspaceInvoke(tenant, "devices.list", {}, accountAuth("guest"))
  expect(guest.ok && JSON.stringify(guest.value)).not.toContain(pending.start.clientLabel)
})

it("a pending guest's own admission still needs a different signer after promotion to sharing manager", async () => {
  const { tenant } = await accessFixture()
  const value = await registerEnrolment(tenant, "acc_guest")
  const accepted = await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: value.enrolment, privateCredentials: false }, acceptance(tenant, value, "guest"))
  expect(accepted.ok).toBe(true)
  if (!accepted.ok) throw new Error("Guest acceptance failed")
  const current = PendingEnrolViewSchema.parse(accepted.value)
  expect(await workspaceInvoke(tenant, "access.members.role", { member: "mem_guest", role: "admin" }, accountAuth("owner", { type: "member.role", member: "mem_guest", before: "guest", after: "admin" }))).toMatchObject({ ok: true })
  const before = await accessSnapshot(tenant)
  const action = { type: "enrol.approve" as const, enrolment: value.enrolment, digest: current.digest, owner: current.owner!, admissionRole: "admin" as const }
  expect(await workspaceInvoke(tenant, "access.enrol.admit", { enrolment: value.enrolment, project: "prj_a" }, accountAuth("guest", action))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "Admission needs a different eligible insider." } } })
  expect(await accessSnapshot(tenant)).toBe(before)
})

it("completes an enrolment with a covered insider's real admitted and exact signing evidence", async () => {
  const { setSetting, digest } = await import("../src/vault/areas/workspace-runtime.ts")
  const { installTestIdentity } = await import("./access-test-support.ts")
  const { tenant } = await accessFixture()
  await inAccess(tenant, ctx => setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["owner"] }))
  const pending = await registerEnrolment(tenant, "acc_guest")
  expect(await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: pending.enrolment, privateCredentials: false }, acceptance(tenant, pending, "guest"))).toMatchObject({ ok: true })
  const action = { type: "enrol.approve", enrolment: pending.enrolment, digest: pending.digest, owner: { kind: "member", member: "mem_guest", name: "guest" }, admissionRole: "owner" } as const
  const auth = accountAuth("owner", action)
  auth.sessionCheck = { id: "chk_owner", identityRuleRev: 0, gateGeneration: 0, checkSequence: 1, succeededAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() }
  await inAccess(tenant, ctx => installTestIdentity(ctx, auth))
  const before = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "access.enrol.admit", { enrolment: pending.enrolment, project: "prj_a" }, auth)).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
  expect(await accessSnapshot(tenant)).toBe(before)
  auth.operationCheck = { id: "opc_enrol", subjectDigest: digest(action), identityRuleRev: 0, gateGeneration: 0, succeededAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() }
  expect(await workspaceInvoke(tenant, "access.enrol.admit", { enrolment: pending.enrolment, project: "prj_a" }, auth)).toMatchObject({ ok: true, value: { state: "active" } })
})

it("never accepts, admits or mirrors a past-deadline unknown-team pending source", async () => {
  const { tenant } = await accessFixture(), pending = await registerEnrolment(tenant, "acc_owner", "team", { team: "tm_unknown" })
  await inAccess(tenant, ctx => ctx.sql.exec("UPDATE workspace_enrolments SET value=? WHERE id=?", JSON.stringify({ ...pending, detail: { ...pending.detail, hardExpiresAt: new Date(ctx.now() - 1).toISOString() } }), pending.enrolment))
  const before = await accessSnapshot(tenant)
  for (const op of ["access.enrol.accept", "access.enrol.admit"]) expect(await workspaceInvoke(tenant, op, { enrolment: pending.enrolment, ...(op.endsWith("accept") ? { privateCredentials: false } : {}) }, accountAuth("owner"))).toMatchObject({ ok: false, error: { vaultError: { error: "not_found" } } })
  expect(await workspaceInvoke(tenant, "access.enrol.mirrored", { enrolment: pending.enrolment, device: "dev_absent" }, system)).toMatchObject({ ok: false, error: { vaultError: { error: "conflict" } } })
  expect(await accessSnapshot(tenant)).toBe(before)
})

it("expires only a past-deadline pending source, with idempotent audit and no active-device changes", async () => {
  const { tenant } = await accessFixture()
  const missing = { enrolment: "enr_missing" }
  expect(await workspaceInvoke(tenant, "access.enrol.expire", missing, system)).toEqual({ ok: true, value: { expired: true } })
  const pending = await registerEnrolment(tenant)
  const before = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "access.enrol.expire", { enrolment: pending.enrolment }, system)).toEqual({ ok: true, value: { expired: false } })
  expect(await accessSnapshot(tenant)).toBe(before)
  expect(await workspaceInvoke(tenant, "access.enrol.expire", { enrolment: pending.enrolment }, accountAuth("owner"))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
  await inAccess(tenant, ctx => { pending.detail!.hardExpiresAt = new Date(ctx.now() - 1).toISOString(); ctx.sql.exec("UPDATE workspace_enrolments SET value=? WHERE id=?", JSON.stringify(pending), pending.enrolment) })
  expect(await workspaceInvoke(tenant, "access.enrol.expire", { enrolment: pending.enrolment }, system)).toEqual({ ok: true, value: { expired: true } })
  const expired = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "access.enrol.expire", { enrolment: pending.enrolment }, system)).toEqual({ ok: true, value: { expired: true } })
  expect(await accessSnapshot(tenant)).toBe(expired)
  const active = await registerEnrolment(tenant)
  expect((await workspaceInvoke(tenant, "access.enrol.accept", { enrolment: active.enrolment, privateCredentials: false }, acceptance(tenant, active))).ok).toBe(true)
  const activeBefore = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "access.enrol.expire", { enrolment: active.enrolment }, system)).toEqual({ ok: true, value: { expired: false } })
  expect(await accessSnapshot(tenant)).toBe(activeBefore)
})

it("never expires rejected, device-bearing or mirrored enrolment sources, even with inconsistent pending state",async () => {
  const { tenant } = await accessFixture()
  const rejected = await registerEnrolment(tenant)
  await inAccess(tenant,ctx => {
    rejected.state = "rejected"
    rejected.detail!.hardExpiresAt = new Date(ctx.now()-1).toISOString()
    ctx.sql.exec("UPDATE workspace_enrolments SET value=? WHERE id=?",JSON.stringify(rejected),rejected.enrolment)
  })
  const beforeRejected = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant,"access.enrol.expire",{ enrolment: rejected.enrolment },system)).toEqual({ ok: true,value: { expired: false } })
  expect(await accessSnapshot(tenant)).toBe(beforeRejected)
  const device = await registerEnrolment(tenant)
  expect((await workspaceInvoke(tenant,"access.enrol.accept",{ enrolment: device.enrolment,privateCredentials: false },acceptance(tenant,device))).ok).toBe(true)
  await inAccess(tenant,ctx => {
    device.detail!.hardExpiresAt = new Date(ctx.now()-1).toISOString()
    ctx.sql.exec("UPDATE workspace_enrolments SET value=? WHERE id=?",JSON.stringify(device),device.enrolment)
  })
  const beforeDevice = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant,"access.enrol.expire",{ enrolment: device.enrolment },system)).toEqual({ ok: true,value: { expired: false } })
  expect(await accessSnapshot(tenant)).toBe(beforeDevice)
  const mirrored = await registerEnrolment(tenant)
  await inAccess(tenant,ctx => {
    mirrored.detail!.hardExpiresAt = new Date(ctx.now()-1).toISOString()
    ctx.sql.exec("UPDATE workspace_enrolments SET value=? WHERE id=?",JSON.stringify(mirrored),mirrored.enrolment)
    ctx.sql.exec("INSERT INTO workspace_enrol_mirrors VALUES (?,?)",mirrored.enrolment,"dev_recorded_mirror")
  })
  const beforeMirror = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant,"access.enrol.expire",{ enrolment: mirrored.enrolment },system)).toEqual({ ok: true,value: { expired: false } })
  expect(await accessSnapshot(tenant)).toBe(beforeMirror)
})
