// Rejecting a scope proposal: only the people who may accept or admit it, a
// passkey over the reject itself, one audit row, and the machine's scope and
// scope revision never move.
import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { RescopeProposalViewSchema, canonicalJson } from "@mehen/protocol"
import type { RescopeProposalView, Share, WorkspaceDeviceScope, WorkspaceStepUpAction } from "@mehen/protocol"
import { accessState, installSecurity, setProjectShare, updateRestriction } from "../src/vault/areas/workspace-runtime.ts"
import { accessFixture, accessSnapshot, accountAuth, beginAccessSideEffectChecks, finishAccessSideEffectChecks, inAccess, registerFixtureLifecycleHooks, workspaceInvoke } from "./access-test-support.ts"

beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)

const reject = (device: string, proposal: string): WorkspaceStepUpAction => ({ type: "device.rescope_reject", device, thumbprint: device, proposal })
async function deviceScope(tenant: string, device: string): Promise<{ scope: string; scope_rev: number }> {
  return inAccess(tenant, (ctx) => ctx.sql.exec<{ scope: string; scope_rev: number }>("SELECT scope,scope_rev FROM devices WHERE id=?", device).toArray()[0]!)
}
async function rejectedRows(tenant: string): Promise<{ actor: string; target: string; detail: unknown }[]> {
  return inAccess(tenant, (ctx) => ctx.sql.exec<{ actor: string; target: string; detail: string }>("SELECT actor,target,detail FROM audit WHERE action='device.rescope_rejected'").toArray().map((row) => ({ ...row, detail: JSON.parse(row.detail) as unknown })))
}
async function storedState(tenant: string, proposal: string): Promise<string> {
  return inAccess(tenant, (ctx) => (JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM device_rescope_proposals WHERE id=?", proposal).toArray()[0]!.value) as { state: string }).state)
}
// An owner-acceptance proposal on the member's machine, proposed by an admin.
async function memberProposal(tenant: string, after?: (before: WorkspaceDeviceScope) => WorkspaceDeviceScope): Promise<{ before: WorkspaceDeviceScope; after: WorkspaceDeviceScope; proposal: RescopeProposalView }> {
  const before = await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); return accessState(ctx).devices.find((d) => d.id === "dev_member")!.scope })
  const wider = after ? after(before) : { ...before, privateCredentials: true }
  const result = await workspaceInvoke(tenant, "devices.rescope", { device: "dev_member", before, after: wider }, accountAuth("admin", { type: "device.rescope", device: "dev_member", thumbprint: "dev_member", before, after: wider }))
  if (!result.ok) throw new Error(JSON.stringify(result))
  return { before, after: wider, proposal: RescopeProposalViewSchema.parse(result.value) }
}

describe("devices.rescope_reject", () => {
  it("ends the open proposal for its owner without changing scope or scope_rev, with one audit row", async () => {
    const { tenant } = await accessFixture()
    const { before, proposal } = await memberProposal(tenant)
    const scopeBefore = await deviceScope(tenant, "dev_member")
    const result = await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: proposal.id }, accountAuth("member", reject("dev_member", proposal.id)))
    expect(result).toMatchObject({ ok: true, value: { id: proposal.id, state: "rejected", before, signedBy: [] } })
    if (!result.ok) throw new Error(JSON.stringify(result))
    expect(RescopeProposalViewSchema.parse(result.value)).not.toHaveProperty("signatures")
    expect(await deviceScope(tenant, "dev_member")).toEqual(scopeBefore)
    expect(JSON.parse(scopeBefore.scope)).toEqual(before)
    expect(await storedState(tenant, proposal.id)).toBe("rejected")
    expect(await rejectedRows(tenant)).toEqual([{ actor: "member:mem_member", target: "dev_member", detail: { proposal: proposal.id, as: "owner_acceptance", by: { account: "acc_member", session: "ses_member" } } }])
    // The machine no longer shows a waiting proposal, and it cannot be accepted any more.
    await inAccess(tenant, (ctx) => expect(ctx.sql.exec<{ value: string }>("SELECT value FROM device_rescope_proposals WHERE device='dev_member'").toArray().map((row) => (JSON.parse(row.value) as { state: string }).state)).toEqual(["rejected"]))
    const snapshot = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: proposal.id }, accountAuth("member", { type: "device.rescope_accept", device: "dev_member", thumbprint: "dev_member", account: "acc_member", before, after: proposal.after, admission: false }))).toEqual({ ok: false, error: { status: 409, vaultError: { error: "conflict", message: "This scope proposal expired or changed. Review a new proposal." } } })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
  })

  it("answers a repeated reject with the same view and writes no second audit row", async () => {
    const { tenant } = await accessFixture()
    const { proposal } = await memberProposal(tenant)
    const auth = accountAuth("member", reject("dev_member", proposal.id))
    const first = await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: proposal.id }, auth)
    expect(first).toMatchObject({ ok: true, value: { state: "rejected" } })
    const snapshot = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: proposal.id }, auth)).toEqual(first)
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    expect(await rejectedRows(tenant)).toHaveLength(1)
    // The repeat still needs an eligible caller.
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: proposal.id }, accountAuth("admin", reject("dev_member", proposal.id)))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
  })

  it.each([
    ["an admin who is not a signer", "admin", { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } }],
    ["an unrelated member", "kim", { status: 404, vaultError: { error: "not_found", message: "No such machine." } }],
    ["a guest", "guest", { status: 404, vaultError: { error: "not_found", message: "No such machine." } }],
  ] as const)("refuses %s and changes nothing", async (_label, role, error) => {
    const { tenant } = await accessFixture()
    const { proposal } = await memberProposal(tenant)
    const scopeBefore = await deviceScope(tenant, "dev_member")
    const snapshot = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: proposal.id }, accountAuth(role, reject("dev_member", proposal.id)))).toEqual({ ok: false, error })
    expect(await workspaceInvoke(tenant, "access.devices.action", { device: "dev_member", change: { kind: "rescope_reject", proposal: proposal.id } }, accountAuth(role))).toEqual({ ok: false, error })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    expect(await deviceScope(tenant, "dev_member")).toEqual(scopeBefore)
    expect(await storedState(tenant, proposal.id)).toBe("open")
    expect(await rejectedRows(tenant)).toEqual([])
  })

  it("refuses an insider with authority who is not the proposal's admission signer", async () => {
    const { tenant } = await accessFixture()
    const before = await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); return accessState(ctx).devices.find((d) => d.id === "dev_guest")!.scope })
    const after = { ...before, privateCredentials: true }
    const proposed = await workspaceInvoke(tenant, "devices.rescope", { device: "dev_guest", before, after, project: "prj_a" }, accountAuth("admin", { type: "device.rescope", device: "dev_guest", thumbprint: "dev_guest", before, after }))
    if (!proposed.ok) throw new Error(JSON.stringify(proposed))
    const proposal = RescopeProposalViewSchema.parse(proposed.value)
    expect(proposal.requiredSigners.map((s) => s.as).sort()).toEqual(["admission", "owner_acceptance"])
    const snapshot = await accessSnapshot(tenant)
    // The owner may admit this guest's machine in general, but this proposal names the admin.
    const refusal = { ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } }
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_guest", proposal: proposal.id, project: "prj_a" }, accountAuth("owner", reject("dev_guest", proposal.id)))).toEqual(refusal)
    expect(await workspaceInvoke(tenant, "access.devices.action", { device: "dev_guest", change: { kind: "rescope_reject", proposal: proposal.id }, project: "prj_a" }, accountAuth("owner"))).toEqual(refusal)
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    // The admitting insider may reject it, recorded as the admission signer.
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_guest", proposal: proposal.id, project: "prj_a" }, accountAuth("admin", reject("dev_guest", proposal.id)))).toMatchObject({ ok: true, value: { state: "rejected" } })
    expect(await rejectedRows(tenant)).toEqual([{ actor: "member:mem_admin", target: "dev_guest", detail: { proposal: proposal.id, as: "admission", by: { account: "acc_admin", session: "ses_admin" } } }])
    await inAccess(tenant, (ctx) => expect(accessState(ctx).devices.find((d) => d.id === "dev_guest")?.scope).toEqual(before))
  })

  it("lets a guest reject a proposal for their own machine", async () => {
    const { tenant } = await accessFixture()
    const before = await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); return accessState(ctx).devices.find((d) => d.id === "dev_guest")!.scope })
    const after = { ...before, privateCredentials: true }
    const proposed = await workspaceInvoke(tenant, "devices.rescope", { device: "dev_guest", before, after, project: "prj_a" }, accountAuth("admin", { type: "device.rescope", device: "dev_guest", thumbprint: "dev_guest", before, after }))
    if (!proposed.ok) throw new Error(JSON.stringify(proposed))
    const proposal = RescopeProposalViewSchema.parse(proposed.value)
    const scopeBefore = await deviceScope(tenant, "dev_guest")
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_guest", proposal: proposal.id }, accountAuth("guest", reject("dev_guest", proposal.id)))).toMatchObject({ ok: true, value: { state: "rejected" } })
    expect(await deviceScope(tenant, "dev_guest")).toEqual(scopeBefore)
  })

  it("refuses a stale, unknown or other machine's proposal id", async () => {
    const { tenant } = await accessFixture()
    const { before, proposal: replaced } = await memberProposal(tenant)
    const { proposal: current } = await memberProposal(tenant, (scope) => ({ ...scope, privateCredentials: true, tags: ["ai"] }))
    expect(await storedState(tenant, replaced.id)).toBe("void")
    const scopeBefore = await deviceScope(tenant, "dev_member")
    const snapshot = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: replaced.id }, accountAuth("member", reject("dev_member", replaced.id)))).toEqual({ ok: false, error: { status: 409, vaultError: { error: "conflict", message: "This scope proposal expired or changed. Review a new proposal." } } })
    const noProposal = { ok: false, error: { status: 404, vaultError: { error: "not_found", message: "No such scope proposal." } } }
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: "rsp_missing" }, accountAuth("member", reject("dev_member", "rsp_missing")))).toEqual(noProposal)
    // A real proposal named under another machine the caller can see.
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_admin", proposal: current.id }, accountAuth("admin", reject("dev_admin", current.id)))).toEqual(noProposal)
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_missing", proposal: current.id }, accountAuth("member", reject("dev_missing", current.id)))).toEqual({ ok: false, error: { status: 404, vaultError: { error: "not_found", message: "No such machine." } } })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    expect(await storedState(tenant, current.id)).toBe("open")
    expect(await deviceScope(tenant, "dev_member")).toEqual(scopeBefore)
    expect(JSON.parse(scopeBefore.scope)).toEqual(before)
  })

  it("refuses a proposal that was already accepted", async () => {
    const { tenant } = await accessFixture()
    const { before, after, proposal } = await memberProposal(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: proposal.id }, accountAuth("member", { type: "device.rescope_accept", device: "dev_member", thumbprint: "dev_member", account: "acc_member", before, after, admission: false }))).toMatchObject({ ok: true, value: { state: "committed" } })
    const scopeAfter = await deviceScope(tenant, "dev_member")
    const snapshot = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: proposal.id }, accountAuth("member", reject("dev_member", proposal.id)))).toEqual({ ok: false, error: { status: 409, vaultError: { error: "conflict", message: "This scope proposal was already accepted." } } })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    expect(await deviceScope(tenant, "dev_member")).toEqual(scopeAfter)
    expect(JSON.parse(scopeAfter.scope)).toEqual(after)
    expect(await rejectedRows(tenant)).toEqual([])
  })

  it("needs a passkey over the reject itself; an acceptance proof never stands in", async () => {
    const { tenant } = await accessFixture()
    const { before, after, proposal } = await memberProposal(tenant)
    const snapshot = await accessSnapshot(tenant)
    const refusal = { ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "This needs a passkey confirmation of the exact action." } } }
    for (const stepUp of [undefined, { type: "device.rescope_accept", device: "dev_member", thumbprint: "dev_member", account: "acc_member", before, after, admission: false } as const, reject("dev_member", "rsp_other"), reject("dev_guest", proposal.id)]) {
      expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: proposal.id }, accountAuth("member", stepUp))).toEqual(refusal)
    }
    const removed = accountAuth("member", reject("dev_member", proposal.id))
    removed.stepUpFactor = "totp_fixture"
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: proposal.id }, removed)).toEqual(refusal)
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    // Planning hands the browser exactly the action to confirm.
    expect(await workspaceInvoke(tenant, "access.devices.action", { device: "dev_member", change: { kind: "rescope_reject", proposal: proposal.id } }, accountAuth("member"))).toEqual({ ok: true, value: { action: reject("dev_member", proposal.id) } })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
  })
})

// A guest machine's proposal naming Kim, a prj_a manager, as the admission signer.
async function kimProposal(tenant: string): Promise<{ before: WorkspaceDeviceScope; after: WorkspaceDeviceScope; proposal: RescopeProposalView }> {
  const before = await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); return accessState(ctx).devices.find((d) => d.id === "dev_guest")!.scope })
  const after = { ...before, privateCredentials: true }
  const result = await workspaceInvoke(tenant, "devices.rescope", { device: "dev_guest", before, after, project: "prj_a", admissionMember: "mem_kim" }, accountAuth("admin", { type: "device.rescope", device: "dev_guest", thumbprint: "dev_guest", before, after }))
  if (!result.ok) throw new Error(JSON.stringify(result))
  const proposal = RescopeProposalViewSchema.parse(result.value)
  expect(proposal.requiredSigners).toEqual([{ name: "guest", as: "owner_acceptance" }, { name: "Kim", as: "admission" }])
  return { before, after, proposal }
}
async function storedShare(tenant: string, project: string, member: string): Promise<Share> {
  return inAccess(tenant, (ctx) => JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM project_shares WHERE project=? AND subject_kind='member' AND subject_id=?", project, member).toArray()[0]!.value) as Share)
}
const hiddenMachine = { ok: false, error: { status: 404, vaultError: { error: "not_found", message: "No such machine." } } }
const noProposal = { ok: false, error: { status: 404, vaultError: { error: "not_found", message: "No such scope proposal." } } }
const stale = { ok: false, error: { status: 409, vaultError: { error: "conflict", message: "This scope proposal expired or changed. Review a new proposal." } } }
const exactPasskey = { ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "This needs a passkey confirmation of the exact action." } } }

describe("rescope reject is a narrowing action", () => {
  it.each([
    ["owner acceptance", "clear"], ["owner acceptance", "restricted"], ["owner acceptance", "pending"],
    ["admission", "clear"], ["admission", "restricted"], ["admission", "pending"],
  ] as const)("the %s signer rejects while %s; accept and admit still refuse when held back", async (as, standing) => {
    const { tenant } = await accessFixture()
    const admission = as === "admission"
    const { before, after, proposal } = admission ? await kimProposal(tenant) : await memberProposal(tenant)
    const role = admission ? "kim" : "member", device = admission ? "dev_guest" : "dev_member", project = admission ? { project: "prj_a" } : {}
    await inAccess(tenant, (ctx) => {
      if (standing === "restricted") updateRestriction(ctx, `acc_${role}`, 0, { reason: "recovery", until: ctx.now() + 600_000, notice: "ntc_rj" })
      if (standing === "pending") installSecurity(ctx, `acc_${role}`, 0, { transitionId: "trn_rj", reservedEpoch: 1, revokedSessionIds: [], removedFactorIds: [], restriction: null })
    })
    const scopeBefore = await deviceScope(tenant, device)
    const held = await accessSnapshot(tenant)
    const sign = admission
      ? await workspaceInvoke(tenant, "devices.rescope_admit", { proposal: proposal.id, ...project }, accountAuth(role, { type: "device.rescope", device, thumbprint: device, before, after }))
      : await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: proposal.id }, accountAuth(role, { type: "device.rescope_accept", device, thumbprint: device, account: "acc_member", before, after, admission: false }))
    if (standing === "clear") expect(sign).toMatchObject({ ok: true, value: { state: admission ? "open" : "committed" } })
    else {
      expect(sign).toMatchObject({ ok: false, error: standing === "pending" ? { status: 403, vaultError: { error: "account_pending" } } : { status: 403, vaultError: { error: "forbidden" } } })
      expect(await accessSnapshot(tenant)).toBe(held)
    }
    if (standing === "clear" && !admission) return
    expect(await workspaceInvoke(tenant, "access.devices.action", { device, change: { kind: "rescope_reject", proposal: proposal.id }, ...project }, accountAuth(role))).toEqual({ ok: true, value: { action: reject(device, proposal.id) } })
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device, proposal: proposal.id, ...project }, accountAuth(role, reject(device, proposal.id)))).toMatchObject({ ok: true, value: { id: proposal.id, state: "rejected" } })
    expect(await deviceScope(tenant, device)).toEqual(scopeBefore)
    expect(JSON.parse(scopeBefore.scope)).toEqual(before)
    expect(await rejectedRows(tenant)).toEqual([{ actor: `member:mem_${role}`, target: device, detail: { proposal: proposal.id, as: admission ? "admission" : "owner_acceptance", by: { account: `acc_${role}`, session: `ses_${role}` } } }])
  })
})

describe("a named project-manager admission signer", () => {
  it("passes the evaluator, plans and rejects as admission without reading the guest's machine", async () => {
    const { tenant } = await accessFixture()
    const { before, proposal } = await kimProposal(tenant)
    // Kim cannot read the guest's machine for anything else.
    expect(await workspaceInvoke(tenant, "access.devices.action", { device: "dev_guest", change: { kind: "revoke" } }, accountAuth("kim"))).toEqual(hiddenMachine)
    const scopeBefore = await deviceScope(tenant, "dev_guest")
    expect(await workspaceInvoke(tenant, "access.devices.action", { device: "dev_guest", change: { kind: "rescope_reject", proposal: proposal.id }, project: "prj_a" }, accountAuth("kim"))).toEqual({ ok: true, value: { action: reject("dev_guest", proposal.id) } })
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_guest", proposal: proposal.id, project: "prj_a" }, accountAuth("kim", reject("dev_guest", proposal.id)))).toMatchObject({ ok: true, value: { state: "rejected" } })
    expect(await rejectedRows(tenant)).toEqual([{ actor: "member:mem_kim", target: "dev_guest", detail: { proposal: proposal.id, as: "admission", by: { account: "acc_kim", session: "ses_kim" } } }])
    expect(await deviceScope(tenant, "dev_guest")).toEqual(scopeBefore)
    expect(JSON.parse(scopeBefore.scope)).toEqual(before)
  })

  it("hides the machine from a manager the proposal does not name, a manager whose authority went, and foreign or unknown ids", async () => {
    const { tenant } = await accessFixture()
    const { proposal } = await kimProposal(tenant)
    const { proposal: memberOne } = await memberProposal(tenant)
    // Make the member a prj_a manager too: eligible to admit in general, but not named.
    const direct = await storedShare(tenant, "prj_a", "mem_member")
    await inAccess(tenant, (ctx) => setProjectShare(ctx, { ...direct, level: "manage" }, direct))
    const snapshot = await accessSnapshot(tenant)
    const attempt = async (role: string, device: string, id: string) => [
      await workspaceInvoke(tenant, "access.devices.action", { device, change: { kind: "rescope_reject", proposal: id }, project: "prj_a" }, accountAuth(role)),
      await workspaceInvoke(tenant, "devices.rescope_reject", { device, proposal: id, project: "prj_a" }, accountAuth(role, reject(device, id))),
    ]
    expect(await attempt("member", "dev_guest", proposal.id)).toEqual([hiddenMachine, hiddenMachine])
    // Kim with another machine's real proposal, or an unknown id, on a machine Kim cannot read.
    expect(await attempt("kim", "dev_member", memberOne.id)).toEqual([hiddenMachine, hiddenMachine])
    expect(await attempt("kim", "dev_member", proposal.id)).toEqual([hiddenMachine, hiddenMachine])
    expect(await attempt("kim", "dev_guest", "rsp_missing")).toEqual([hiddenMachine, hiddenMachine])
    expect(await attempt("kim", "dev_missing", proposal.id)).toEqual([hiddenMachine, hiddenMachine])
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    // Kim's management share removed: the same hidden answer.
    const kim = await storedShare(tenant, "prj_a", "mem_kim")
    await inAccess(tenant, (ctx) => setProjectShare(ctx, null, kim))
    const withoutShare = await accessSnapshot(tenant)
    expect(await attempt("kim", "dev_guest", proposal.id)).toEqual([hiddenMachine, hiddenMachine])
    expect(await accessSnapshot(tenant)).toBe(withoutShare)
    expect(await storedState(tenant, proposal.id)).toBe("open")
    expect(await rejectedRows(tenant)).toEqual([])
  })

  it("hides the machine when the manager's share has expired", async () => {
    const { tenant } = await accessFixture()
    const { proposal } = await kimProposal(tenant)
    const kim = await storedShare(tenant, "prj_a", "mem_kim")
    await inAccess(tenant, (ctx) => setProjectShare(ctx, { ...kim, expiresAt: new Date(ctx.now() - 1).toISOString() }, kim))
    const snapshot = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_guest", proposal: proposal.id, project: "prj_a" }, accountAuth("kim", reject("dev_guest", proposal.id)))).toEqual(hiddenMachine)
    expect(await workspaceInvoke(tenant, "access.devices.action", { device: "dev_guest", change: { kind: "rescope_reject", proposal: proposal.id }, project: "prj_a" }, accountAuth("kim"))).toEqual(hiddenMachine)
    expect(await accessSnapshot(tenant)).toBe(snapshot)
  })
})

describe("rescope reject refusal boundaries", () => {
  it("never accepts a proof for another action, in either direction", async () => {
    const { tenant } = await accessFixture()
    const { before, after, proposal } = await kimProposal(tenant)
    const snapshot = await accessSnapshot(tenant)
    const admitProof = { type: "device.rescope", device: "dev_guest", thumbprint: "dev_guest", before, after } as const
    const acceptProof = { type: "device.rescope_accept", device: "dev_guest", thumbprint: "dev_guest", account: "acc_guest", before, after, admission: true } as const
    const rejectProof = reject("dev_guest", proposal.id)
    // Admission and acceptance proofs, from the eligible signers, at reject.
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_guest", proposal: proposal.id, project: "prj_a" }, accountAuth("kim", admitProof))).toEqual(exactPasskey)
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_guest", proposal: proposal.id }, accountAuth("guest", acceptProof))).toEqual(exactPasskey)
    // The reject proof at admit and accept.
    expect(await workspaceInvoke(tenant, "devices.rescope_admit", { proposal: proposal.id, project: "prj_a" }, accountAuth("kim", rejectProof))).toEqual(exactPasskey)
    expect(await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: proposal.id }, accountAuth("guest", rejectProof))).toEqual(exactPasskey)
    // A wrong thumbprint in the reject proof.
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_guest", proposal: proposal.id }, accountAuth("guest", { type: "device.rescope_reject", device: "dev_guest", thumbprint: "another-key", proposal: proposal.id }))).toEqual(exactPasskey)
    expect(await accessSnapshot(tenant)).toBe(snapshot)
  })

  it("refuses a removed passkey, machines and the system, and a repeat without a proof", async () => {
    const { tenant } = await accessFixture()
    const { proposal } = await memberProposal(tenant)
    const snapshot = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: proposal.id }, { kind: "system", reason: "rj" })).toMatchObject({ ok: false, error: { status: 403, vaultError: { error: "forbidden" } } })
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: proposal.id }, { kind: "device", proof: "unused", method: "POST", url: "https://app.mehen.dev/unused", bodyHash: "unused" })).toMatchObject({ ok: false, error: { status: 403, vaultError: { error: "forbidden" } } })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: proposal.id }, accountAuth("member", reject("dev_member", proposal.id)))).toMatchObject({ ok: true, value: { state: "rejected" } })
    const rejected = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: proposal.id }, accountAuth("member"))).toEqual(exactPasskey)
    expect(await accessSnapshot(tenant)).toBe(rejected)
    await inAccess(tenant, (ctx) => installSecurity(ctx, "acc_member", 0, { transitionId: "trn_rj", reservedEpoch: 1, revokedSessionIds: [], removedFactorIds: ["pk_fixture"], restriction: null }))
    const removed = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: proposal.id }, accountAuth("member", reject("dev_member", proposal.id)))).toEqual({ ok: false, error: { status: 401, vaultError: { error: "unauthenticated", message: "This session is no longer authorised." } } })
    expect(await accessSnapshot(tenant)).toBe(removed)
    expect(await rejectedRows(tenant)).toHaveLength(1)
  })

  it.each(["expired", "scope_rev", "owner", "key", "revoked"] as const)("refuses a %s proposal with the stale answer and changes nothing", async (variant) => {
    const { tenant } = await accessFixture()
    const { proposal } = await memberProposal(tenant)
    await inAccess(tenant, (ctx) => {
      const saved = JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM device_rescope_proposals WHERE id=?", proposal.id).toArray()[0]!.value) as Record<string, unknown>
      if (variant === "expired") ctx.sql.exec("UPDATE device_rescope_proposals SET value=? WHERE id=?", canonicalJson({ ...saved, expiresAt: new Date(ctx.now() - 1).toISOString() }), proposal.id)
      if (variant === "scope_rev") ctx.sql.exec("UPDATE devices SET scope_rev=scope_rev+1 WHERE id='dev_member'")
      if (variant === "owner") ctx.sql.exec("UPDATE members SET revision=revision+1 WHERE id='mem_member'")
      if (variant === "key") ctx.sql.exec("UPDATE devices SET thumbprint='different' WHERE id='dev_member'")
      if (variant === "revoked") ctx.sql.exec("UPDATE devices SET revoked_at=? WHERE id='dev_member'", ctx.now())
    })
    const scopeBefore = await deviceScope(tenant, "dev_member")
    const snapshot = await accessSnapshot(tenant)
    const thumbprint = variant === "key" ? "different" : "dev_member"
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: proposal.id }, accountAuth("member", { type: "device.rescope_reject", device: "dev_member", thumbprint, proposal: proposal.id }))).toEqual(stale)
    expect(await workspaceInvoke(tenant, "access.devices.action", { device: "dev_member", change: { kind: "rescope_reject", proposal: proposal.id } }, accountAuth("member"))).toEqual(stale)
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    expect(await deviceScope(tenant, "dev_member")).toEqual(scopeBefore)
    expect(await rejectedRows(tenant)).toEqual([])
  })

  it("answers another machine's open, accepted or rejected proposal exactly as an unknown id, and an invisible machine as an absent one", async () => {
    const { tenant } = await accessFixture()
    const { proposal: rejected } = await memberProposal(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_member", proposal: rejected.id }, accountAuth("member", reject("dev_member", rejected.id)))).toMatchObject({ ok: true, value: { state: "rejected" } })
    const { before, after, proposal: accepted } = await memberProposal(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: accepted.id }, accountAuth("member", { type: "device.rescope_accept", device: "dev_member", thumbprint: "dev_member", account: "acc_member", before, after, admission: false }))).toMatchObject({ ok: true, value: { state: "committed" } })
    const { proposal: open } = await kimProposal(tenant)
    const snapshot = await accessSnapshot(tenant)
    // The admin reads every machine, so only the proposal's own machine decides.
    for (const id of [open.id, accepted.id, rejected.id, "rsp_missing"]) {
      expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device: "dev_admin", proposal: id }, accountAuth("admin", reject("dev_admin", id)))).toEqual(noProposal)
      expect(await workspaceInvoke(tenant, "access.devices.action", { device: "dev_admin", change: { kind: "rescope_reject", proposal: id } }, accountAuth("admin"))).toEqual(noProposal)
    }
    // A machine the caller cannot read answers as one that does not exist.
    for (const device of ["dev_owner", "dev_missing"]) {
      expect(await workspaceInvoke(tenant, "devices.rescope_reject", { device, proposal: accepted.id }, accountAuth("member", reject(device, accepted.id)))).toEqual(hiddenMachine)
      expect(await workspaceInvoke(tenant, "access.devices.action", { device, change: { kind: "rescope_reject", proposal: accepted.id } }, accountAuth("member"))).toEqual(hiddenMachine)
    }
    expect(await accessSnapshot(tenant)).toBe(snapshot)
  })
})
