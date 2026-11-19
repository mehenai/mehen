import { z } from "zod"
import { DeviceRescopeProposalSchema, EnrolEvidenceSchema, WorkspaceDeviceScopeSchema, WorkspaceDeviceViewSchema, canonicalJson, fingerprintOf, fingerprintWords, scopeChangeIsNarrowing } from "@mehen/protocol"
import type { DeviceRescopeProposal, WorkspaceDeviceScope, WorkspaceMe, WorkspaceStepUpAction } from "@mehen/protocol"
import { VaultError } from "../../http.ts"
import type { Area, VaultContext } from "../core.ts"
import { one, randomId } from "../core.ts"
import type { AccessAction, AccessMember, AccessPrincipal, AccessState } from "../access.ts"
import { can, reach } from "../access.ts"
import { CAPABILITIES } from "./devices.ts"
import { refuseFillUnlessOn } from "../fill-unavailable.ts"
import { refuseFillForOldCli, refuseFillOnlyMachine, refuseFillOnlyWorkloadStatus, scopeForCli, workloadForCli } from "../fill-old-cli.ts"
import { forgetCliVersions } from "./device-cli-versions.ts"
import { workloadRevokeDecision, workloadRow, workloadScope, workloadView } from "./workloads.ts"
import { EnrolReconcileOutputSchema, PendingEnrolViewSchema, enrolRecord, readStoredEnrol, saveEnrol, storedEnrolTerms } from "./workspace-runtime.ts"
import type { PendingEnrol } from "./workspace-runtime.ts"
import { accessChanged, accessState, capabilityState, authorise, bumpAccessRevision, digest, memberRows, principalOf, security, eligibilityState, queueNotice, requireOperationIdentity, requireStepUp, setting, workspaceRef } from "./workspace-runtime.ts"
import type { AccessAllowed, WorkspaceInvocationContext } from "./workspace-runtime.ts"

type WorkspaceDeviceRow = { enrolment: string | null; id: string; name: string; backend: string; host: string | null; jwk: string; thumbprint: string; scope: string; scope_rev: number; owner_kind: "member" | "team"; owner_id: string; owner_revision: number; acceptance: string | null; admission: string | null; created_at: number; last_seen_at: number | null; last_cli_version: string | null; revoked_at: number | null }
const DeviceInput = z.strictObject({ device: z.string() })
const RescopeInput = DeviceInput.extend({ before: WorkspaceDeviceScopeSchema, after: WorkspaceDeviceScopeSchema, admissionMember: z.string().regex(/^mem_[A-Za-z0-9_-]{1,64}$/).optional(), project: z.string().optional() })
// The scope a machine is planned with before acceptance. A member's own
// machine starts with private credentials on when its acceptor is an active
// owner, admin or member; a guest's own machine starts with them off, and a
// team's machine never has them.
export function defaultWorkspaceScope(owner: "self" | "team", acceptor: AccessMember): WorkspaceDeviceScope {
  return { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay", "sign", "mint", "placeholder"], privateCredentials: owner === "self" && acceptor.status === "active" && acceptor.standing.effectiveRole !== "guest" }
}
function signerIdentityCheck(ctx: VaultContext, invocation: WorkspaceInvocationContext, member: string, expected: WorkspaceStepUpAction): string | null {
  if (!accessState(ctx).members.find(m => m.id === member)?.standing.identityGate.covered) return null
  const evidence = invocation.auth.kind === "account" ? invocation.auth.operationCheck : undefined
  requireOperationIdentity(ctx, member, expected, evidence)
  return evidence!.id
}
function recordRescopeIdentity(ctx: VaultContext, proposal: string, account: string): void {
  const member = memberRows(ctx).find(m => m.account === account && m.status !== "removed")
  if (!member) throw new VaultError("conflict", "A scope signer is no longer eligible. Review a new proposal.")
  ctx.sql.exec("INSERT INTO workspace_rescope_identity(proposal,account,rule_rev,generation) VALUES (?,?,?,?) ON CONFLICT(proposal,account) DO UPDATE SET rule_rev=excluded.rule_rev,generation=excluded.generation", proposal, account, setting(ctx, "identity_rule_rev", 0), member.gate_generation)
}
function deviceRow(ctx: VaultContext, id: string): WorkspaceDeviceRow {
  const row = one(ctx.sql.exec<WorkspaceDeviceRow>("SELECT * FROM devices WHERE id=? AND owner_kind IS NOT NULL", id))
  if (!row) throw new VaultError("not_found", "No such machine.")
  return row
}
function actor(decision: AccessAllowed): string { return decision.principal.kind === "member" ? `member:${decision.principal.memberId}` : `device:${decision.principal.deviceId}` }
function changeScope(ctx: VaultContext, row: WorkspaceDeviceRow, scope: WorkspaceDeviceScope): void {
  const narrowing = scopeChangeIsNarrowing(WorkspaceDeviceScopeSchema.parse(JSON.parse(row.scope)), scope)
  accessChanged(ctx, row.owner_kind === "member" ? row.owner_id : null, "rescope", { device: row.id, narrowing, ...(row.owner_kind === "team" ? { team: row.owner_id } : {}) })
  ctx.sql.exec("UPDATE devices SET scope=?,scope_rev=scope_rev+1 WHERE id=?", canonicalJson(scope), row.id)
  for (const proposal of proposals(ctx, row.id)) if (proposal.state === "open") saveProposal(ctx, { ...proposal, state: "void" })
}
// Fill joins a machine's scope only where BROWSER_FILL is on, and only for
// a machine whose mehen last proved 0.3.17 or later (ruling F2), and never
// as a machine's only mode.
function refuseFillChange(ctx: VaultContext, row: WorkspaceDeviceRow, after: WorkspaceDeviceScope): void {
  refuseFillUnlessOn(ctx, after.modes)
  refuseFillOnlyMachine(after.modes)
  refuseFillForOldCli({ name: row.name, lastCliVersion: row.last_cli_version }, WorkspaceDeviceScopeSchema.parse(JSON.parse(row.scope)).modes, after.modes)
}
function proposals(ctx: VaultContext, device: string): DeviceRescopeProposal[] { return ctx.sql.exec<{ value: string }>("SELECT value FROM device_rescope_proposals WHERE device=?", device).toArray().map((p) => { const proposal = DeviceRescopeProposalSchema.parse(JSON.parse(p.value)); return proposal.state === "open" && Date.parse(proposal.expiresAt) <= ctx.now() ? { ...proposal, state: "expired" as const } : proposal }) }
function saveProposal(ctx: VaultContext, proposal: DeviceRescopeProposal): void { ctx.sql.exec("INSERT INTO device_rescope_proposals(id,device,value) VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value", proposal.id, proposal.device, canonicalJson(DeviceRescopeProposalSchema.parse(proposal))) }
function publicProposal(proposal: DeviceRescopeProposal, account: string) {
  const { owner: _owner, deviceRevision: _deviceRevision, ownerRevision: _ownerRevision, scopeRevision: _scopeRevision, signatures: _signatures, ...view } = proposal
  return { ...view, requiredSigners: proposal.requiredSigners.map(({ account: signer, ...visible }) => signer === account ? { ...visible, account: signer } : visible), signedBy: proposal.signedBy.filter((signer) => signer === account) }
}
function publicEvidence(ctx: VaultContext, raw: unknown, caller: AccessMember) {
  if (raw === null) return null
  const evidence = EnrolEvidenceSchema.parse(raw)
  if (caller.standing.effectiveRole !== "guest" || evidence.account === caller.account) return evidence
  return { name: memberRows(ctx).find((m) => m.id === evidence.member)?.name ?? "A manager", at: evidence.at }
}
function callerMember(ctx: VaultContext, invocation: WorkspaceInvocationContext): AccessMember {
  const principal = principalOf(ctx, invocation.auth)
  const caller = principal.kind === "member" ? accessState(ctx).members.find((m) => m.id === principal.memberId && m.status !== "removed") : undefined
  if (!caller) throw new VaultError("forbidden", "Only people review machines.")
  return caller
}
function deviceView(ctx: VaultContext, row: WorkspaceDeviceRow, invocation: WorkspaceInvocationContext) {
  const state = accessState(ctx)
  const device = state.devices.find((d) => d.id === row.id)
  if (!device) throw new VaultError("not_found", "No such machine.")
  const caller = callerMember(ctx, invocation)
  const source = row.enrolment ? one(ctx.sql.exec<{ value: string }>("SELECT value FROM workspace_enrolments WHERE id=?", row.enrolment)) : null
  const start = source ? readStoredEnrol(source.value).start : null
  return WorkspaceDeviceViewSchema.parse({ start, device: row.id, name: row.name, backend: row.backend, host: row.host, owner: reach(state, device, ctx.now()).owner, scope: JSON.parse(row.scope), scopeRevision: row.scope_rev, acceptance: publicEvidence(ctx, row.acceptance ? JSON.parse(row.acceptance) : null, caller), admission: publicEvidence(ctx, row.admission ? JSON.parse(row.admission) : null, caller), pendingRescope: (() => { const pending = proposals(ctx, row.id).find((p) => p.state === "open"); return pending ? publicProposal(pending, caller.account) : null })(), createdAt: new Date(row.created_at).toISOString(), lastSeenAt: row.last_seen_at === null ? null : new Date(row.last_seen_at).toISOString(), lastCliVersion: row.last_cli_version, revoked: row.revoked_at !== null, ...(row.revoked_at !== null ? { revokedAt: new Date(row.revoked_at).toISOString() } : {}), fingerprintWords: fingerprintWords(row.thumbprint) })
}
function enrol(ctx: VaultContext, id: string): PendingEnrol {
  const row = one(ctx.sql.exec<{ value: string }>("SELECT value FROM workspace_enrolments WHERE id=?", id))
  if (!row) throw new VaultError("not_found", "No such enrolment.")
  const value = readStoredEnrol(row.value)
  // Only the attempt's hard cap ends it here: the renewable lease lives in D1.
  if (value.state === "expired" || value.detail && Date.parse(value.detail.hardExpiresAt) <= ctx.now()) throw new VaultError("not_found", "No such enrolment.")
  if (value.state === "rejected") throw new VaultError("conflict", "This enrolment was rejected.")
  return value
}
function enrolmentDigest(value: PendingEnrol): string { return digest(storedEnrolTerms(value)) }
function enrolEvidence(ctx: VaultContext, invocation: WorkspaceInvocationContext, subject: PendingEnrol, member: string) {
  if (invocation.auth.kind !== "account") throw new VaultError("forbidden", "Only the signing account can accept a machine.")
  return { account: invocation.auth.account, member, digest: subject.digest, ruleRevision: setting(ctx, "identity_rule_rev", 0), gateGeneration: memberRows(ctx).find((m) => m.id === member)?.gate_generation ?? 0, identityCheck: signerIdentityCheck(ctx, invocation, member, invocation.auth.stepUp!), at: new Date(ctx.now()).toISOString() }
}
function finishEnrol(ctx: VaultContext, value: PendingEnrol): void {
  if (!value.owner || value.state === "active") return
  const member = value.owner.kind === "member" ? memberRows(ctx).find((m) => m.id === (value.owner?.kind === "member" ? value.owner.member : "")) : undefined
  const ready = value.owner.kind === "team" ? !!value.admission : !!value.acceptance && (member?.role !== "guest" || !!value.admission)
  if (!ready) { value.state = value.acceptance ? "pending_admission" : "pending_owner_acceptance"; return }
  const state = accessState(ctx)
  if (value.acceptance && (value.acceptance.digest !== value.digest || value.acceptance.member !== member?.id || value.acceptance.account !== member?.account || value.acceptance.gateGeneration !== memberRows(ctx).find((m) => m.id === member?.id)?.gate_generation || value.acceptance.ruleRevision !== setting(ctx, "identity_rule_rev", 0) || state.members.find(m => m.id === member?.id)?.standing.identityGate.covered && !value.acceptance.identityCheck)) throw new VaultError("conflict", "The owning account must accept the current enrolment terms again.")
  if (value.admission) {
    const signer = state.members.find((m) => m.id === value.admission?.member)
    const target = value.owner.kind === "team" ? { team: value.owner.team } : { member: member?.id, project: value.admissionProject ?? undefined, after: value.scope }
    if (!signer || value.admission.digest !== value.digest || value.admission.ruleRevision !== setting(ctx, "identity_rule_rev", 0) || value.admission.gateGeneration !== signer.standing.gateGeneration || signer.standing.identityGate.covered && !value.admission.identityCheck || !can(capabilityState(state, signer.id), { kind: "member", account: signer.account, memberId: signer.id, session: "stored-admission", securityEpoch: 0, sessionCheck: null }, { type: "enrol.approve" }, target, ctx.now()).allowed) throw new VaultError("forbidden", "This enrolment needs a current eligible admission.")
  }
  if (!value.detail) throw new VaultError("bad_request", "The enrolment is missing its public key details.")
  if (value.owner.kind === "member" && member?.status !== "active") throw new VaultError("owner_inactive", "The owning member is not active.")
  if (one(ctx.sql.exec("SELECT id FROM devices WHERE thumbprint=? AND revoked_at IS NULL", value.thumbprint))) throw new VaultError("conflict", "This key is already enrolled. Revoke it and enrol a fresh key.")
  const device = randomId("dev")
  ctx.sql.exec("INSERT INTO devices(id,name,backend,host,jwk,thumbprint,scope,created_at,enrolment,owner_kind,owner_id,acceptance,admission) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", device, value.detail.name, value.detail.backend, value.detail.host, canonicalJson(value.detail.jwk), value.thumbprint, canonicalJson(value.scope), ctx.now(), value.enrolment, value.owner.kind, value.owner.kind === "member" ? value.owner.member : value.owner.team, value.acceptance ? canonicalJson(value.acceptance) : null, value.admission ? canonicalJson(value.admission) : null)
  value.device = device; value.state = "active"
  bumpAccessRevision(ctx)
  ctx.audit({ actor: value.acceptance ? `member:${value.acceptance.member}` : `member:${value.admission?.member}`, action: "device.enrol", target: device, detail: { owner: value.owner, start: value.start } })
  queueNotice(ctx, { kind: "machine_added", workspace: workspaceRef(ctx), device, name: value.detail.name, owner: value.owner, place: value.start.place, at: new Date(ctx.now()).toISOString() })
}
// What the caller may do to a pending enrolment, from live standing. The
// claim narrows acceptance to the claimed account; hiding a button is never
// the guard, access.enrol.accept enforces it again.
export function enrolDecisions(ctx: VaultContext, state: AccessState, principal: Extract<AccessPrincipal, { kind: "member" }>, caller: AccessMember, value: Pick<PendingEnrol, "requestedOwner" | "owner" | "scope" | "claimedAccount">): ("accept" | "admit" | "reject")[] {
  const member = value.owner?.kind === "member" ? state.members.find((m) => m.id === (value.owner?.kind === "member" ? value.owner.member : "")) : undefined
  const project = member ? state.shares.find((s) => s.subject.kind === "member" && s.subject.member === member.id && (s.expiresAt === null || Date.parse(s.expiresAt) > ctx.now()))?.project : undefined
  const target = value.requestedOwner.kind === "team" ? { team: value.requestedOwner.team } : { after: value.scope, member: member?.id ?? caller.id, owningAccount: member?.account ?? caller.account, acceptingAccount: caller.account, project }
  const actions: ("accept" | "admit" | "reject")[] = []
  if (value.requestedOwner.kind === "self" && (value.claimedAccount === null || value.claimedAccount === caller.account) && can(state, principal, { type: "enrol.accept" }, target, ctx.now()).allowed) actions.push("accept")
  if ((value.requestedOwner.kind === "team" || value.owner !== null) && can(state, principal, { type: "enrol.approve" }, target, ctx.now()).allowed && caller.id !== member?.id) actions.push("admit")
  if (can(state, principal, { type: "enrol.reject" }, target, ctx.now()).allowed) actions.push("reject")
  return actions
}
function enrolView(ctx: VaultContext, value: PendingEnrol, invocation: WorkspaceInvocationContext) {
  const principal = principalOf(ctx, invocation.auth)
  const state = eligibilityState(ctx, invocation)
  const caller = principal.kind === "member" ? state.members.find((m) => m.id === principal.memberId) : undefined
  if (principal.kind !== "member" || !caller) throw new VaultError("forbidden", "Only people review enrolments.")
  const actions = ["active", "rejected", "expired"].includes(value.state) ? [] : enrolDecisions(ctx, state, principal, caller, value)
  const defaultPrivateCredentials = value.requested?.privateCredentials !== false && defaultWorkspaceScope(value.requestedOwner.kind === "self" ? "self" : "team", caller).privateCredentials
  const scope = { ...value.scope, privateCredentials: defaultPrivateCredentials }
  const { detail: storedDetail, ...visible } = enrolRecord(value)
  const detail = storedDetail ? (({ codeHash: _codeHash, ...publicDetail }) => publicDetail)(storedDetail) : undefined
  return PendingEnrolViewSchema.parse({ ...visible, ...(detail ? { detail } : {}), acceptance: publicEvidence(ctx, value.acceptance, caller), admission: publicEvidence(ctx, value.admission, caller), actions, defaultPrivateCredentials, planning: actions.includes("accept") ? { scope, digest: enrolmentDigest({ ...value, scope }) } : null })
}
function proposalForSigning(ctx: VaultContext, id: string, device?: string) {
  const saved = one(ctx.sql.exec<{ value: string }>("SELECT value FROM device_rescope_proposals WHERE id=?", id))
  if (!saved) throw new VaultError("not_found", "No such scope proposal.")
  const proposal = DeviceRescopeProposalSchema.parse(JSON.parse(saved.value))
  const row = deviceRow(ctx, proposal.device)
  if (device && row.id !== device) throw new VaultError("not_found", "No such scope proposal.")
  const state = accessState(ctx)
  const owner = state.members.find((m) => m.id === row.owner_id)
  const ownerRevision = memberRows(ctx).find((m) => m.id === row.owner_id)?.revision ?? row.owner_revision
  if (proposal.state !== "open" || Date.parse(proposal.expiresAt) <= ctx.now() || row.revoked_at !== null || proposal.scopeRevision !== row.scope_rev || proposal.ownerRevision !== ownerRevision || proposal.thumbprint !== row.thumbprint || proposal.beforeDigest !== digest(JSON.parse(row.scope))) throw new VaultError("conflict", "This scope proposal expired or changed. Review a new proposal.")
  return { proposal, row, state, owner }
}
// The proposal a reject may end. An already rejected one comes back as it is
// (the repeat answer); an accepted one, or one that expired, was replaced or
// went stale, is refused exactly as accepting it would be.
function proposalForRejecting(ctx: VaultContext, id: string, device: string) {
  const saved = one(ctx.sql.exec<{ value: string }>("SELECT value FROM device_rescope_proposals WHERE id=?", id))
  const stored = saved ? DeviceRescopeProposalSchema.parse(JSON.parse(saved.value)) : null
  if (!stored || stored.device !== device) throw new VaultError("not_found", "No such scope proposal.")
  if (stored.state === "committed") throw new VaultError("conflict", "This scope proposal was already accepted.")
  if (stored.state !== "rejected") return proposalForSigning(ctx, id, device)
  const row = deviceRow(ctx, device)
  return { proposal: stored, row, owner: accessState(ctx).members.find((m) => m.id === row.owner_id) }
}
// Who may reject: exactly a required signer, by the evaluator's narrowing
// device.rescope_reject, which reuses that signer's accept or admit authority.
function rescopeRejectDecision(ctx: VaultContext, invocation: WorkspaceInvocationContext, proposal: DeviceRescopeProposal, row: WorkspaceDeviceRow, owner: AccessMember | undefined, project: string | undefined) {
  const signer = proposal.requiredSigners.find((s) => s.account === (invocation.auth.kind === "account" ? invocation.auth.account : ""))
  const decision = authorise(ctx, invocation, { type: "device.rescope_reject" }, { device: row.id, owningAccount: owner?.account, project, before: proposal.before, after: proposal.after, proposal: proposal.id, rescopeAs: signer?.as }, ctx.now())
  if (!signer) throw new VaultError("forbidden", "This proposal needs a different signer.")
  const expected: WorkspaceStepUpAction = { type: "device.rescope_reject", device: row.id, thumbprint: row.thumbprint, proposal: proposal.id }
  return { decision, as: signer.as, expected }
}
// Who may see a machine to reject on it: anyone who may read it, or the
// stored proposal's named admission signer who holds admission authority now
// (a guest's project manager need not read the guest's machine). Every other
// caller gets the same hidden-machine answer, before any proposal state.
function rescopeRejectVisibility(ctx: VaultContext, invocation: WorkspaceInvocationContext, row: WorkspaceDeviceRow, proposalId: string, project: string | undefined): void {
  const hidden = () => new VaultError("not_found", "No such machine.")
  const refusal = (error: unknown) => error instanceof VaultError && (error.code === "forbidden" || error.code === "not_found")
  try { authorise(ctx, invocation, { type: "devices.read" }, { device: row.id }, ctx.now()); return } catch (error) { if (!refusal(error)) throw error }
  const saved = one(ctx.sql.exec<{ value: string }>("SELECT value FROM device_rescope_proposals WHERE id=?", proposalId))
  const proposal = saved ? DeviceRescopeProposalSchema.parse(JSON.parse(saved.value)) : null
  const account = invocation.auth.kind === "account" ? invocation.auth.account : null
  if (!proposal || proposal.device !== row.id || account === null || !proposal.requiredSigners.some((s) => s.account === account && s.as === "admission")) throw hidden()
  // Authority only: the live scope as before, so a stale proposal is no oracle here.
  try { authorise(ctx, invocation, { type: "device.rescope_reject" }, { device: row.id, project, before: WorkspaceDeviceScopeSchema.parse(JSON.parse(row.scope)), after: proposal.after, proposal: proposal.id, rescopeAs: "admission" }, ctx.now()) } catch (error) { if (refusal(error)) throw hidden(); throw error }
}
// The machines this person may read, as the Machines page lists them.
export function readableDevices(ctx: VaultContext, invocation: WorkspaceInvocationContext): AccessState["devices"] {
  return accessState(ctx).devices.filter((d) => {
    try { authorise(ctx, invocation, { type: "devices.read" }, { device: d.id }, ctx.now()); return true } catch (error) { if (error instanceof VaultError && error.code === "forbidden") return false; throw error }
  })
}
export function enrolmentWording(kind: "accept" | "admit", name: string): { label: string; warning: string } {
  return kind === "accept" ? { label: "Accept as my own machine", warning: "This machine will act as you and can use your private credentials if you tick that scope. Only accept a machine you are using yourself. If someone sent you this link, do not accept it: they accept their own machine and you admit it" } : { label: `Admit ${name}'s machine`, warning: "Admission does not accept this machine as your own." }
}
export const workspaceDeviceOps: NonNullable<Area["workspaceOps"]> = {
  "access.devices.action": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const input = z.strictObject({ device: z.string(), project: z.string().optional(), change: z.discriminatedUnion("kind", [z.strictObject({ kind: z.literal("rescope"), before: WorkspaceDeviceScopeSchema, after: WorkspaceDeviceScopeSchema }), z.strictObject({ kind: z.literal("rescope_propose"), before: WorkspaceDeviceScopeSchema, after: WorkspaceDeviceScopeSchema }), z.strictObject({ kind: z.literal("rescope_accept"), proposal: z.string() }), z.strictObject({ kind: z.literal("rescope_admit"), proposal: z.string() }), z.strictObject({ kind: z.literal("rescope_reject"), proposal: z.string() }), z.strictObject({ kind: z.literal("revoke") }), z.strictObject({ kind: z.literal("workload_revoke"), workload: z.string().max(80) })]) }).parse(raw)
    const row = deviceRow(ctx, input.device)
    const change = input.change
    if (change.kind === "rescope_reject") {
      rescopeRejectVisibility(ctx, invocation, row, change.proposal, input.project)
      const { proposal, owner } = proposalForRejecting(ctx, change.proposal, row.id)
      return { action: rescopeRejectDecision(ctx, invocation, proposal, row, owner, input.project).expected }
    }
    try { authorise(ctx, invocation, { type: "devices.read" }, { device: row.id }, ctx.now()) } catch (error) { if (error instanceof VaultError && (error.code === "forbidden" || error.code === "not_found")) throw new VaultError("not_found", "No such machine."); throw error }
    if (change.kind === "revoke") { authorise(ctx, invocation, { type: "device.revoke" }, { device: row.id }, ctx.now()); return { action: { type: "device.revoke", device: row.id } } }
    if (change.kind === "workload_revoke") {
      workloadRevokeDecision(ctx, invocation, row.id)
      const workload = workloadRow(ctx, change.workload)
      if (!workload || workload.device !== row.id) throw new VaultError("not_found", "No such workload.")
      return { action: { type: "workload.revoke", device: row.id, workload: workload.id } }
    }
    if (change.kind === "rescope" || change.kind === "rescope_propose") {
      refuseFillChange(ctx, row, change.after)
      authorise(ctx, invocation, change.kind === "rescope" ? { type: "device.rescope", before: change.before, after: change.after } : { type: "device.rescope_propose" }, { device: row.id, project: input.project, before: change.before, after: change.after }, ctx.now())
      return { action: { type: "device.rescope", device: row.id, thumbprint: row.thumbprint, before: WorkspaceDeviceScopeSchema.parse(JSON.parse(row.scope)), after: change.after } }
    }
    const { proposal, owner } = proposalForSigning(ctx, change.proposal, row.id)
    refuseFillChange(ctx, row, proposal.after)
    const accept = change.kind === "rescope_accept"
    authorise(ctx, invocation, accept ? { type: "device.rescope_accept", before: proposal.before, after: proposal.after } : { type: "device.rescope_admit" }, { device: row.id, owningAccount: owner?.account, project: input.project, proposal: proposal.id, before: proposal.before, after: proposal.after }, ctx.now())
    const action: WorkspaceStepUpAction = accept ? { type: "device.rescope_accept", device: row.id, thumbprint: row.thumbprint, account: owner?.account ?? "", before: proposal.before, after: proposal.after, admission: owner?.standing.effectiveRole === "guest" } : { type: "device.rescope", device: row.id, thumbprint: row.thumbprint, before: proposal.before, after: proposal.after }
    return { action }
  } },
  "access.enrol.reconcile": { auth: ["system"], handler(ctx, _p, raw) {
    const input = z.strictObject({ enrolment: z.string() }).parse(raw)
    const saved = one(ctx.sql.exec<{ value: string }>("SELECT value FROM workspace_enrolments WHERE id=?", input.enrolment))
    if (!saved) throw new VaultError("not_found", "No such enrolment.")
    const pending = readStoredEnrol(saved.value)
    const device = one(ctx.sql.exec<{ id: string }>("SELECT id FROM devices WHERE enrolment=?", input.enrolment))?.id ?? null
    const mirrored = device !== null && one(ctx.sql.exec("SELECT device FROM workspace_enrol_mirrors WHERE enrolment=? AND device=?", input.enrolment, device)) !== null
    const row = device ? deviceRow(ctx, device) : null
    const live = device ? accessState(ctx).devices.find((d) => d.id === device) : undefined
    const active = row && row.revoked_at === null && live ? { scope: WorkspaceDeviceScopeSchema.parse(JSON.parse(row.scope)), owner: reach(accessState(ctx), live, ctx.now()).owner, acceptance: row.acceptance ? JSON.parse(row.acceptance) : null, admission: row.admission ? JSON.parse(row.admission) : null } : null
    return EnrolReconcileOutputSchema.parse({ device, mirrored, state: pending.state, active })
  } },
  "access.enrol.expire": { auth: ["system"], handler(ctx, _p, raw) {
    const { enrolment } = z.strictObject({ enrolment: z.string() }).parse(raw)
    return ctx.storage.transactionSync(() => {
      const saved = one(ctx.sql.exec<{ value: string }>("SELECT value FROM workspace_enrolments WHERE id=?", enrolment))
      if (!saved) return { expired: true }
      const value = readStoredEnrol(saved.value)
      if (value.state === "active" || one(ctx.sql.exec("SELECT id FROM devices WHERE enrolment=?", enrolment)) || one(ctx.sql.exec("SELECT device FROM workspace_enrol_mirrors WHERE enrolment=?", enrolment))) return { expired: false }
      if (value.state === "expired") return { expired: true }
      if (value.state === "rejected" || !value.detail || Date.parse(value.detail.hardExpiresAt) > ctx.now()) return { expired: false }
      saveEnrol(ctx, { ...value, state: "expired" })
      ctx.audit({ actor: "system", action: "device.enrol_expired", target: enrolment })
      return { expired: true }
    })
  } },
  "access.enrol.mirrored": { auth: ["system"], handler(ctx, _p, raw) {
    const input = z.strictObject({ enrolment: z.string(), device: z.string() }).parse(raw)
    return ctx.storage.transactionSync(() => {
      const pair = one(ctx.sql.exec<{ enrolment: string }>("SELECT enrolment FROM devices WHERE id=?", input.device))
      if (pair?.enrolment !== input.enrolment) throw new VaultError("conflict", "The enrolment and machine do not match.")
      ctx.sql.exec("INSERT OR IGNORE INTO workspace_enrol_mirrors(enrolment,device) VALUES (?,?)", input.enrolment, input.device)
      return { mirrored: true }
    })
  } },
  "access.enrol.discard": { auth: ["system"], handler(ctx, _p, raw) {
    const input = z.strictObject({ enrolment: z.string(), device: z.string() }).parse(raw)
    return ctx.storage.transactionSync(() => {
      if (one(ctx.sql.exec("SELECT device FROM workspace_enrol_mirrors WHERE enrolment=? AND device=?", input.enrolment, input.device))) return { discarded: false }
      const removed = ctx.sql.exec("DELETE FROM devices WHERE id=? AND enrolment=? AND last_seen_at IS NULL", input.device, input.enrolment)
      if (removed.rowsWritten === 0) return { discarded: false }
      const pending = one(ctx.sql.exec<{ value: string }>("SELECT value FROM workspace_enrolments WHERE id=?", input.enrolment))
      if (pending) { const value = readStoredEnrol(pending.value); value.state = "rejected"; saveEnrol(ctx, value) }
      ctx.audit({ actor: "system", action: "device.discard", target: input.device, detail: { enrolment: input.enrolment } })
      bumpAccessRevision(ctx)
      return { discarded: true }
    })
  } },
  "access.enrol.view": { auth: ["account"], handler(ctx, _p, raw, invocation) { const input = z.strictObject({ enrolment: z.string() }).parse(raw); authorise(ctx, invocation, { type: "asks.read" }, {}, ctx.now()); return enrolView(ctx, enrol(ctx, input.enrolment), invocation) } },
  "access.enrol.reject": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const input = z.strictObject({ enrolment: z.string() }).parse(raw)
    return ctx.storage.transactionSync(() => { const value = enrol(ctx, input.enrolment); if (value.state === "active") throw new VaultError("conflict", "Revoke an active machine instead."); const decision = authorise(ctx, invocation, { type: "enrol.reject" }, { member: value.owner?.kind === "member" ? value.owner.member : memberRows(ctx).find((m) => m.account === (invocation.auth.kind === "account" ? invocation.auth.account : ""))?.id, ...(value.requestedOwner.kind === "team" ? { team: value.requestedOwner.team } : {}) }, ctx.now()); value.state = "rejected"; saveEnrol(ctx, value); ctx.audit({ actor: actor(decision), action: "device.enrol_rejected", target: value.enrolment }); return enrolView(ctx, value, invocation) })
  } },
  "access.enrol.accept": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const input = z.strictObject({ enrolment: z.string(), privateCredentials: z.boolean() }).parse(raw)
    return ctx.storage.transactionSync(() => {
      const value = enrol(ctx, input.enrolment)
      if (value.requestedOwner.kind !== "self" || invocation.auth.kind !== "account") throw new VaultError("forbidden", "Team machines require admission, not personal acceptance.")
      const member = memberRows(ctx).find((m) => m.account === (invocation.auth.kind === "account" ? invocation.auth.account : "") && m.status === "active")
      if (!member) throw new VaultError("not_found", "No such workspace.")
      // A connect code's claim, immutable since start: whichever page or
      // route the acceptance came through, only that account accepts.
      if (value.claimedAccount !== null && value.claimedAccount !== member.account) throw new VaultError("forbidden", "This machine was started for another account.")
      // A machine that asked for no private credentials never gets them at acceptance.
      if (input.privateCredentials && value.requested?.privateCredentials === false) throw new VaultError("forbidden", "This machine asked not to use private credentials. Accept it without them.")
      if (value.owner?.kind === "member" && value.owner.member !== member.id) throw new VaultError("forbidden", "Only the owning account can accept this machine.")
      if (value.scope.privateCredentials !== input.privateCredentials) {
        if (value.state === "active") throw new VaultError("conflict", "Use a rescope proposal to change an active machine.")
        value.scope = { ...value.scope, privateCredentials: input.privateCredentials }
        value.digest = enrolmentDigest(value)
        value.acceptance = null; value.admission = null
      }
      const decision = authorise(ctx, invocation, { type: "enrol.accept" }, { owningAccount: member.account, acceptingAccount: member.account }, ctx.now())
      requireStepUp(ctx, decision, { type: "enrol.accept", workspace: ctx.tenant, enrolment: value.enrolment, thumbprint: value.thumbprint, account: member.account, member: member.id, scope: value.scope, start: value.start }, invocation)
      if (value.state === "active") return enrolView(ctx, value, invocation)
      value.owner = { kind: "member", member: member.id, name: member.name }
      value.acceptance = enrolEvidence(ctx, invocation, value, member.id)
      finishEnrol(ctx, value); saveEnrol(ctx, value)
      return enrolView(ctx, value, invocation)
    })
  } },
  "access.enrol.admit": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const input = z.strictObject({ enrolment: z.string(), project: z.string().optional() }).parse(raw)
    return ctx.storage.transactionSync(() => {
      const value = enrol(ctx, input.enrolment)
      const state = accessState(ctx)
      const owner = value.requestedOwner.kind === "team" ? { kind: "team" as const, team: value.requestedOwner.team, name: state.teams.find((t) => t.id === (value.requestedOwner.kind === "team" ? value.requestedOwner.team : ""))?.name ?? "" } : value.owner
      if (!owner) throw new VaultError("conflict", "The owning account must accept this machine first.")
      const member = owner.kind === "member" ? state.members.find((m) => m.id === owner.member) : undefined
      if (member && input.project && !state.shares.some((s) => s.project === input.project && s.subject.kind === "member" && s.subject.member === member.id && (s.expiresAt === null || Date.parse(s.expiresAt) > ctx.now()))) throw new VaultError("not_found", "No such admission project.")
      const decision = authorise(ctx, invocation, { type: "enrol.approve" }, { ...(owner.kind === "team" ? { team: owner.team } : {}), member: member?.id, after: value.scope, project: input.project ?? state.shares.find((s) => s.subject.kind === "member" && s.subject.member === member?.id && (s.expiresAt === null || Date.parse(s.expiresAt) > ctx.now()))?.project }, ctx.now())
      const signer = decision.principal.kind === "member" ? state.members.find((m) => m.id === (decision.principal.kind === "member" ? decision.principal.memberId : "")) : undefined
      if (!signer || signer.id === member?.id) throw new VaultError("forbidden", "Admission needs a different eligible insider.")
      requireStepUp(ctx, decision, { type: "enrol.approve", enrolment: value.enrolment, digest: value.digest, owner, admissionRole: signer.standing.effectiveRole }, invocation)
      value.owner = owner; value.admission = enrolEvidence(ctx, invocation, value, signer.id); value.admissionProject = input.project ?? state.shares.find((s) => s.subject.kind === "member" && s.subject.member === member?.id && (s.expiresAt === null || Date.parse(s.expiresAt) > ctx.now()))?.project ?? null
      finishEnrol(ctx, value); saveEnrol(ctx, value)
      return enrolView(ctx, value, invocation)
    })
  } },
  "devices.list": { auth: ["account"], handler(ctx, _p, _raw, invocation) {
    const decision = authorise(ctx, invocation, { type: "devices.read" }, {}, ctx.now())
    if (decision.principal.kind !== "member") throw new VaultError("forbidden", "Only people list machines.")
    return { devices: readableDevices(ctx, invocation).map((d) => deviceView(ctx, deviceRow(ctx, d.id), invocation)) }
  } },
  "devices.rescope": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    if (typeof raw === "object" && raw !== null && "admissionAccount" in raw) throw new VaultError("forbidden", "Choose an eligible insider for this guest's shared project.")
    const input = RescopeInput.parse(raw)
    return ctx.storage.transactionSync(() => {
      const row = deviceRow(ctx, input.device)
      if (row.revoked_at !== null) throw new VaultError("conflict", "This machine was revoked.")
      refuseFillChange(ctx, row, input.after)
      const live = WorkspaceDeviceScopeSchema.parse(JSON.parse(row.scope))
      const narrow = scopeChangeIsNarrowing(live, input.after)
      const action = (narrow ? { type: "device.rescope", before: input.before, after: input.after } : { type: "device.rescope_propose" }) as AccessAction
      const decision = authorise(ctx, invocation, action, { device: row.id, project: input.project, before: input.before, after: input.after }, ctx.now())
      const expected = { type: "device.rescope", device: row.id, thumbprint: row.thumbprint, before: live, after: input.after } as const
      requireStepUp(ctx, decision, expected, invocation)
      if (narrow) { changeScope(ctx, row, input.after); ctx.audit({ actor: actor(decision), action: "device.rescope", target: row.id, detail: { before: live, after: input.after } }); return { state: "committed", scope: input.after } }
      const state = accessState(ctx)
      const member = row.owner_kind === "member" ? state.members.find((m) => m.id === row.owner_id) : undefined
      const proposer = decision.principal.kind === "member" ? state.members.find((m) => m.id === (decision.principal.kind === "member" ? decision.principal.memberId : "")) : undefined
      if (!proposer || invocation.auth.kind !== "account") throw new VaultError("forbidden", "A person must propose widening.")
      const guest = member?.standing.effectiveRole === "guest"
      const selectedMember = guest ? input.admissionMember ?? (proposer.id !== member.id ? proposer.id : null) : row.owner_kind === "team" ? proposer.id : null
      const admissionMember = state.members.find((m) => m.id === selectedMember && m.status !== "removed")
      if (guest) {
        const principal = admissionMember ? { kind: "member" as const, memberId: admissionMember.id, account: admissionMember.account, session: "proposal-admission", securityEpoch: security(ctx, admissionMember.account)?.installedEpoch ?? 0, sessionCheck: admissionMember.account === invocation.auth.account ? invocation.auth.sessionCheck : null } : null
        const stateForSigner = admissionMember?.account === invocation.auth.account ? eligibilityState(ctx, invocation) : admissionMember ? capabilityState(state, admissionMember.id) : state
        const eligible = principal && admissionMember?.id !== member?.id && state.projects.some((project) => (input.project === undefined || input.project === project.id) && can(stateForSigner, principal, { type: "device.rescope_admit" }, { device: row.id, project: project.id, before: live, after: input.after, proposal: "new" }, ctx.now()).allowed)
        if (!eligible) throw new VaultError("forbidden", "Choose an eligible insider for this guest's shared project.")
      }
      const admissionAccount = admissionMember?.account
      const owner = reach(state, state.devices.find((d) => d.id === row.id)!, ctx.now()).owner
      const proposal: DeviceRescopeProposal = { id: randomId("rsp"), device: row.id, thumbprint: row.thumbprint, before: live, after: input.after, beforeDigest: digest(live), afterDigest: digest(input.after), proposer: { member: proposer.id, name: proposer.name }, requiredSigners: [...(member ? [{ account: member.account, name: member.name, as: "owner_acceptance" as const }] : []), ...(admissionMember ? [{ account: admissionMember.account, name: admissionMember.name, as: "admission" as const }] : [])], signedBy: [], expiresAt: new Date(ctx.now() + 900_000).toISOString(), state: "open", owner, deviceRevision: row.scope_rev, ownerRevision: memberRows(ctx).find((m) => m.id === row.owner_id)?.revision ?? row.owner_revision, scopeRevision: row.scope_rev, signatures: [] }
      if (admissionAccount === proposer.account) { proposal.signatures.push({ account: proposer.account, as: "admission", digest: digest({ before: live, after: input.after, device: row.id, thumbprint: row.thumbprint }), factor: invocation.auth.stepUpFactor!, identityCheck: signerIdentityCheck(ctx, invocation, proposer.id, expected), at: new Date(ctx.now()).toISOString() }); proposal.signedBy.push(proposer.account); recordRescopeIdentity(ctx, proposal.id, proposer.account) }
      for (const previous of proposals(ctx, row.id)) if (previous.state === "open") saveProposal(ctx, { ...previous, state: "void" })
      saveProposal(ctx, proposal)
      if (row.owner_kind === "team") { changeScope(ctx, row, proposal.after); proposal.state = "committed"; saveProposal(ctx, proposal) }
      ctx.audit({ actor: actor(decision), action: "device.rescope_proposed", target: row.id, detail: { proposal: proposal.id } })
      return publicProposal(proposal, invocation.auth.account)
    })
  } },
  ...Object.fromEntries((["accept", "admit"] as const).map((signAs) => [`devices.rescope_${signAs}`, { auth: ["account"] as ("account")[], handler(ctx: VaultContext, _p: import("./workspace-runtime.ts").WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext) {
    const input = z.strictObject({ proposal: z.string(), project: z.string().optional() }).parse(raw)
    return ctx.storage.transactionSync(() => {
      const { proposal, row, state, owner } = proposalForSigning(ctx, input.proposal)
      refuseFillChange(ctx, row, proposal.after)
      const decision = authorise(ctx, invocation, (signAs === "accept" ? { type: "device.rescope_accept", before: proposal.before, after: proposal.after } : { type: "device.rescope_admit" }), { device: row.id, owningAccount: owner?.account, project: input.project, before: proposal.before, after: proposal.after, proposal: proposal.id }, ctx.now())
      const expected: WorkspaceStepUpAction = signAs === "accept" ? { type: "device.rescope_accept", device: row.id, thumbprint: row.thumbprint, account: owner?.account ?? "", before: proposal.before, after: proposal.after, admission: owner?.standing.effectiveRole === "guest" } : { type: "device.rescope", device: row.id, thumbprint: row.thumbprint, before: proposal.before, after: proposal.after }
      requireStepUp(ctx, decision, expected, invocation)
      if (invocation.auth.kind !== "account") throw new VaultError("forbidden", "Only people sign scope proposals.")
      const as = signAs === "accept" ? "owner_acceptance" : "admission"
      const signer = proposal.requiredSigners.find((s) => s.account === (invocation.auth.kind === "account" ? invocation.auth.account : "") && s.as === as)
      if (!signer) throw new VaultError("forbidden", "This proposal needs a different signer.")
      if (!proposal.signatures.some((s) => s.account === signer.account && s.as === as)) { proposal.signatures.push({ account: signer.account, as, digest: digest({ before: proposal.before, after: proposal.after, device: row.id, thumbprint: row.thumbprint }), factor: invocation.auth.stepUpFactor!, identityCheck: signerIdentityCheck(ctx, invocation, state.members.find(m => m.account === signer.account && m.status !== "removed")!.id, expected), at: new Date(ctx.now()).toISOString() }); recordRescopeIdentity(ctx, proposal.id, signer.account) }
      proposal.signedBy = [...new Set(proposal.signatures.map((s) => s.account))]
      for (const signature of proposal.signatures) {
        const member = state.members.find((m) => m.account === signature.account && m.status !== "removed")
        const accountSecurity = security(ctx, signature.account)
        if (!member || member.status !== "active" || accountSecurity?.pending || accountSecurity?.removedFactorIds.includes(signature.factor)) throw new VaultError("conflict", "A scope signer is no longer eligible. Review a new proposal.")
        if (member.standing.identityGate.covered) {
          const installed = one(ctx.sql.exec<{ rule_rev: number; generation: number }>("SELECT rule_rev,generation FROM workspace_rescope_identity WHERE proposal=? AND account=?", proposal.id, signature.account))
          if (!signature.identityCheck || installed?.rule_rev !== member.standing.identityRuleRev || installed?.generation !== member.standing.gateGeneration) throw new VaultError("conflict", "A scope signer's identity changed. Review a new proposal.")
        }
        if (signature.as === "admission" && row.owner_kind === "member") {
          const principal = { kind: "member" as const, memberId: member.id, account: member.account, session: "stored-admission", securityEpoch: accountSecurity?.installedEpoch ?? 0, sessionCheck: null }
          if (!state.projects.some((project) => can(capabilityState(state, member.id), principal, { type: "device.rescope_admit" }, { device: row.id, project: project.id, proposal: proposal.id, before: proposal.before, after: proposal.after }, ctx.now()).allowed)) throw new VaultError("conflict", "A scope signer is no longer eligible. Review a new proposal.")
        }
      }
      if (proposal.requiredSigners.every((required) => proposal.signatures.some((s) => s.account === required.account && s.as === required.as))) { changeScope(ctx, row, proposal.after); proposal.state = "committed" }
      saveProposal(ctx, proposal)
      ctx.audit({ actor: actor(decision), action: "device.rescope_signed", target: row.id, detail: { proposal: proposal.id, as, state: proposal.state } })
      return publicProposal(proposal, invocation.auth.account)
    })
  } }])),
  "devices.rescope_reject": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const input = z.strictObject({ device: z.string(), proposal: z.string(), project: z.string().optional() }).parse(raw)
    return ctx.storage.transactionSync(() => {
      const row = deviceRow(ctx, input.device)
      rescopeRejectVisibility(ctx, invocation, row, input.proposal, input.project)
      const { proposal, owner } = proposalForRejecting(ctx, input.proposal, row.id)
      const { decision, as, expected } = rescopeRejectDecision(ctx, invocation, proposal, row, owner, input.project)
      // A passkey over the reject itself, so the proof never stands in for an acceptance.
      requireStepUp(ctx, decision, expected, invocation)
      if (invocation.auth.kind !== "account") throw new VaultError("forbidden", "Only people reject scope proposals.")
      if (proposal.state === "rejected") return publicProposal(proposal, invocation.auth.account)
      const rejected: DeviceRescopeProposal = { ...proposal, state: "rejected" }
      saveProposal(ctx, rejected)
      ctx.audit({ actor: actor(decision), action: "device.rescope_rejected", target: row.id, detail: { proposal: proposal.id, as } })
      return publicProposal(rejected, invocation.auth.account)
    })
  } },
  "devices.revoke": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const input = DeviceInput.parse(raw)
    return ctx.storage.transactionSync(() => { const row = deviceRow(ctx, input.device); const decision = authorise(ctx, invocation, { type: "device.revoke" }, { device: row.id }, ctx.now()); requireStepUp(ctx, decision, { type: "device.revoke", device: row.id }, invocation); accessChanged(ctx, row.owner_kind === "member" ? row.owner_id : null, "revoke", { device: row.id, ...(row.owner_kind === "team" ? { team: row.owner_id } : {}) }); ctx.sql.exec("UPDATE devices SET revoked_at=?,scope_rev=scope_rev+1 WHERE id=?", ctx.now(), row.id); ctx.audit({ actor: actor(decision), action: "device.revoke", target: row.id }); forgetCliVersions(ctx, [row.id]); return {} })
  } },
  "devices.self_revoke": { auth: ["device"], handler(ctx, _p, _raw, invocation) {
    return ctx.storage.transactionSync(() => { const principal = principalOf(ctx, invocation.auth); if (principal.kind !== "device") throw new VaultError("forbidden", "Only machines revoke themselves."); const decision = authorise(ctx, invocation, { type: "device.self_revoke" }, { device: principal.deviceId }, ctx.now()); const row = deviceRow(ctx, principal.deviceId); accessChanged(ctx, row.owner_kind === "member" ? row.owner_id : null, "revoke", { device: row.id, ...(row.owner_kind === "team" ? { team: row.owner_id } : {}) }); ctx.sql.exec("UPDATE devices SET revoked_at=?,scope_rev=scope_rev+1 WHERE id=?", ctx.now(), row.id); ctx.audit({ actor: actor(decision), action: "device.revoke", target: row.id }); forgetCliVersions(ctx, [row.id]); return {} })
  } },
  "devices.transfer": { auth: ["account"], handler(ctx, _p, raw, invocation) { const input = z.object({ device: z.string() }).parse(raw); authorise(ctx, invocation, { type: "device.transfer" }, { device: input.device }, ctx.now()); throw new VaultError("forbidden", "Revoke this key and enrol a fresh key for the new owner.") } },
  "devices.me": { auth: ["device"], handler(ctx, _p, _raw, invocation): WorkspaceMe {
    const principal = principalOf(ctx, invocation.auth)
    if (principal.kind !== "device") throw new VaultError("forbidden", "Only machines read their status.")
    authorise(ctx, invocation, { type: "device.read_self" }, { device: principal.deviceId }, ctx.now())
    const row = deviceRow(ctx, principal.deviceId)
    const state = accessState(ctx)
    const device = state.devices.find((d) => d.id === row.id)!
    const workload = principal.workload === undefined ? null : workloadRow(ctx, principal.workload)
    const ownerRole = device.owner.kind === "team" ? "team" : state.members.find((m) => m.id === device.owner.id)?.standing.effectiveRole
    const cli = invocation.auth.kind === "device" ? invocation.auth.cliVersion : null
    if (workload) refuseFillOnlyWorkloadStatus(workloadScope(workload), cli)
    return { tenant: ctx.tenant, device: row.id, name: row.name, scope: scopeForCli(device.scope, cli), frozen: setting(ctx, "frozen", false), fingerprint: fingerprintOf(row.thumbprint), capabilities: CAPABILITIES, ...(ownerRole ? { ownerRole } : {}), workspace: workspaceRef(ctx), owner: reach(state, device, ctx.now()).owner, displayRev: setting(ctx, "display_rev", 1), ...(workload ? { workload: workloadForCli(workloadView(workload, ctx.now()), cli) } : {}) }
  } },
}
