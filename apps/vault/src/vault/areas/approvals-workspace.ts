// Workspace consent is immutable evidence, not a cached permission decision.

import { canonicalJson, type ApprovalViewProjection, type WorkspaceRef, type WorkspaceStepUpAction } from "@mehen/protocol"
import { can, effectiveAccess, eligibility, fourEyesProjects, type AccessAsk, type AccessPrincipal, type AccessState } from "../access.ts"
import { one, randomId, type VaultContext } from "../core.ts"
import type { ConsentBasis, ConsentLineage, WorkspaceConsentService } from "../services.ts"
import { VaultError } from "../../http.ts"
import { PolicyRememberSchema } from "@mehen/protocol/policy-mode"
import { policyHelpNext } from "./policy.ts"
import type { ApprovalSubject, ApprovalView } from "@mehen/protocol/api"
import { devicePolicyState } from "./devices.ts"
import { bindingCode, digestOf } from "./approvals.ts"
import type { ApprovalPresentation } from "../services.ts"
import { accessState, eligibilityState, managedSetting, retainedGateValid, standingGateValid, authorise, requireStepUp, openAskCount, registerOpenAskCounter, registerWorkloadAskCounter, registerOffboardingHook, registerAccessChangeHook, type WorkspaceInvocationContext } from "./workspace-runtime.ts"
import { cachedManagedPlatform, managedDefaultsRevision, platformLive } from "../managed-platform.ts"
import { waitForStorageWrite } from "../storage-waits.ts"
import { askingWorkload, assertWorkloadAskRoom } from "./workloads.ts"
import { applyRemember, approvalRuleRefs, approvalRuleView, areaOffer, prepareAreaRemember, prepareRemember, ruleOffer, rulesAvailable, rulesOff, type RememberedArea, type RememberedRule } from "./policy-rules-workspace.ts"
import { z } from "zod"
import { parseOpInput } from "./approvals.ts"
import { auditPrivateEvent } from "../audit.ts"
import { createHash } from "node:crypto"
import { compareVersions } from "@mehen/protocol/version"
import type { PolicyFloorView, PolicyRemember } from "@mehen/protocol/policy-mode"
import type { Env } from "../../env.ts"
import { SUPERSEDED_CLI } from "../../cli-version.ts"
import { workspaceSwitchOn } from "../workspace-switch.ts"
import { countPostureDenied } from "./postures-workspace.ts"
import { PUSH_CONSTRAINTS, isPushSubject, pushApprovalStatus, pushApprovalView, pushSnapshotChanged, queueApprovedPush } from "./push-records.ts"

export function requesterBasis(state: AccessState, deviceId: string, projects: string[], now: number): { owner: import("../access.ts").AccessDevice["owner"]; scope: import("@mehen/protocol").WorkspaceDeviceScope; sources: import("@mehen/protocol").AccessSource[] } {
  const device = state.devices.find((d) => d.id === deviceId)
  if (!device) throw new VaultError("not_found", "No such object.")
  return { owner: structuredClone(device.owner), scope: structuredClone(device.scope), sources: [...new Set(projects)].flatMap((project) => effectiveAccess(state, { kind: device.owner.kind, id: device.owner.id }, project, now).sources) }
}

// Whether a machine still sees an ask of its own: it may read each asked
// credential, or, for a run's placeholder ask or a fill ask (with or without
// a context), still use it in that mode (a placeholder-only or fill-only
// workload holds no relay mode to read by), and it may read the ask's project.
export function deviceSeesAsk(state: AccessState, principal: Extract<AccessPrincipal, { kind: "device" }>, ask: AccessAsk, now: number): boolean {
  const sees = (credential: string) => can(state, principal, { type: "item.read" }, { credential }, now).allowed || ask.mode !== undefined && (ask.context !== null || ask.mode === "fill") && can(state, principal, { type: "item.use", context: ask.context }, { credential, mode: ask.mode }, now).allowed
  return ask.credentials.every(sees) && (!ask.context || can(state, principal, { type: "project.read" }, { project: ask.context.project }, now).allowed)
}

export function askedCredentials(state: AccessState, ask: AccessAsk): string[] {
  const context = state.projects.find((p) => p.id === ask.context?.project)?.environments.find((e) => e.name === ask.context?.environment)
  return [...new Set([...ask.credentials, ...(ask.credential === null ? context?.references.map((r) => r.item) ?? [] : [])])]
}

function consentReferences(state: AccessState, ask: AccessAsk): ConsentBasis["referenceRevisions"] {
  const ids = askedCredentials(state, ask)
  return state.projects.flatMap((p) => p.environments.filter((e) => e.references.some((r) => ids.includes(r.item)) || ask.context?.project === p.id && ask.context.environment === e.name).map((e) => ({ project: p.id, environment: e.name, revision: e.revision, protectionRevision: e.protectionRevision }))).sort((a, b) => `${a.project}/${a.environment}`.localeCompare(`${b.project}/${b.environment}`))
}

type GateEvidence = Pick<ConsentBasis, "sessionCheck" | "session" | "account" | "securityEpoch">

export function consentBasis(state: AccessState, member: string, ask: AccessAsk, now: number, evidence: GateEvidence): ConsentBasis {
  if (!eligibility(state, member, ask, now).canApprove) throw new VaultError("forbidden", "You are not an eligible approver.")
  const decider = state.members.find((m) => m.id === member)
  if (!decider) throw new VaultError("not_found", "No such object.")
  const projects = new Set(fourEyesProjects(state, ask).sort())
  if (ask.context) projects.add(ask.context.project)
  for (const credential of state.credentials.filter((c) => askedCredentials(state, ask).includes(c.id))) if (credential.home.kind === "project") projects.add(credential.home.project)
  const sources = [...projects].flatMap((project) => effectiveAccess(state, { kind: "member", id: member }, project, now).sources)
  const expiries = sources.flatMap((s) => s.kind === "share" && s.share.expiresAt !== null ? [Date.parse(s.share.expiresAt)] : [])
  return {
    ...evidence, member, role: decider.standing.effectiveRole, sources, accessRevision: state.accessRev, context: ask.context,
    referenceRevisions: consentReferences(state, ask),
    fourEyesProjects: fourEyesProjects(state, ask).sort(), expiresAt: expiries.length ? Math.min(...expiries) : null,
  }
}

export function consentIsCurrent(state: AccessState, lineage: ConsentLineage, ask: AccessAsk, now: number): boolean {
  const basis = lineage.basis
  if (lineage.revokedAt !== null || now >= lineage.expiresAt || now < lineage.createdAt || basis.expiresAt !== null && now >= basis.expiresAt) return false
  const member = state.members.find((m) => m.id === basis.member)
  if (!member || member.standing.effectiveRole !== basis.role || !eligibility(state, member.id, ask, now).canApprove) return false
  if (canonicalJson(basis.context) !== canonicalJson(ask.context) || canonicalJson(basis.fourEyesProjects) !== canonicalJson(fourEyesProjects(state, ask).sort())) return false
  for (const source of basis.sources) {
    if (source.kind === "role") { if (member.standing.effectiveRole !== source.role) return false; continue }
    const current = effectiveAccess(state, { kind: "member", id: member.id }, source.share.project, now).sources
    if (!current.some((s) => canonicalJson(s) === canonicalJson(source))) return false
  }
  return canonicalJson(consentReferences(state, ask)) === canonicalJson([...basis.referenceRevisions].sort((a, b) => `${a.project}/${a.environment}`.localeCompare(`${b.project}/${b.environment}`)))
}

export type WorkspaceApprovalRecord = {
  id: string
  ask: AccessAsk
  detail: Extract<ApprovalViewProjection, { view: "detail" }>["approval"]
  binding?: import("@mehen/protocol").WorkspaceApprovalBinding
}

// This discriminator is the only serialisation boundary. A denial right never
// gives the caller a full request to redact after it has already escaped.
export function approvalProjection(state: AccessState, principal: AccessPrincipal, record: WorkspaceApprovalRecord, workspace: WorkspaceRef, now: number): ApprovalViewProjection {
  const device = state.devices.find((d) => d.id === record.ask.device)
  if (!device) throw new VaultError("not_found", "No such object.")
  const machineOwner = device.owner.kind === "member"
    ? { kind: "member" as const, member: device.owner.id, name: state.members.find((m) => m.id === device.owner.id)?.name ?? "" }
    : { kind: "team" as const, team: device.owner.id, name: state.teams.find((t) => t.id === device.owner.id)?.name ?? "" }
  if (principal.kind !== "member") throw new VaultError("not_found", "No such object.")
  const rights = eligibility(state, principal.memberId, record.ask, now)
  if (!rights.canReadAskDetail && !rights.canDeny) throw new VaultError("not_found", "No such object.")
  if (rights.canReadAskDetail) return { view: "detail", ...(record.binding ? { binding: record.binding } : {}), approval: { ...record.detail, workspace, owner: machineOwner, eligibility: rights } }
  const credential = record.ask.credential === null ? null : { slug: record.detail.item.slug }
  const status = record.detail.status
  return { view: "stop", id: record.id, workspace, machine: { device: device.id, name: record.detail.requestedBy.deviceName, owner: machineOwner }, item: credential, status, eligibility: rights }
}

export function approvalDelivery(state: AccessState, member: string, ask: AccessAsk, visibleProject: string, now: number): { deciders: string[]; say: string } {
  const device = state.devices.find((d) => d.id === ask.device)
  const guest = device?.owner.kind === "member" && state.members.some((m) => m.id === device.owner.id && m.standing.effectiveRole === "guest")
  const deciders = guest ? [] : eligibility(state, member, ask, now).deciders
  return { deciders, say: deciders.length ? `Send this link to ${deciders.join(" or ")}.` : `Send this link to a manager of ${visibleProject}.` }
}

export const WORKSPACE_CONSENT_MIGRATION = `CREATE TABLE consent_lineage (
  id TEXT PRIMARY KEY, decision TEXT NOT NULL, member TEXT NOT NULL, ask TEXT NOT NULL,
  basis TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER
); CREATE INDEX consent_lineage_member ON consent_lineage(member);
CREATE TABLE run_authorisations (
  id TEXT PRIMARY KEY, run TEXT NOT NULL UNIQUE, lineage TEXT NOT NULL REFERENCES consent_lineage(id),
  revision INTEGER NOT NULL, valid_from INTEGER NOT NULL, valid_until INTEGER NOT NULL, revoked_at INTEGER
); CREATE INDEX run_authorisations_lineage ON run_authorisations(lineage);`

export function storeConsent(ctx: VaultContext, state: AccessState, decision: string, member: string, ask: AccessAsk, expiresAt: number, invocation: WorkspaceInvocationContext): ConsentLineage {
  if (invocation.auth.kind !== "account") throw new VaultError("forbidden", "Only a person can record consent.")
  const auth = invocation.auth
  const basis = consentBasis(state, member, ask, ctx.now(), { sessionCheck: auth.sessionCheck, session: auth.session, account: auth.account, securityEpoch: auth.securityEpoch })
  const lineage: ConsentLineage = { id: randomId("cns"), decision, basis, createdAt: ctx.now(), expiresAt: Math.min(expiresAt, basis.expiresAt ?? expiresAt), revokedAt: null }
  ctx.sql.exec("INSERT INTO consent_lineage(id,decision,member,ask,basis,created_at,expires_at) VALUES (?,?,?,?,?,?,?)", lineage.id, decision, member, JSON.stringify(ask), JSON.stringify(basis), lineage.createdAt, lineage.expiresAt)
  return lineage
}

// Consent a platform gave in its managed workspace, for its subject member:
// the same graph a person's consent binds, with the platform's attestation
// in place of a session's gate.
export type PlatformConsent = { kind: "platform"; platform: string; key: string; subject: string; member: string }
export type PlatformConsentBasis = ConsentBasis & { platform: PlatformConsent }
function platformConsentOf(basis: ConsentBasis): PlatformConsent | null {
  const platform = (basis as Partial<PlatformConsentBasis>).platform
  return platform?.kind === "platform" ? platform : null
}
export function storePlatformConsent(ctx: VaultContext, state: AccessState, decision: string, ask: AccessAsk, expiresAt: number, platform: PlatformConsent): ConsentLineage {
  const member = state.members.find((m) => m.id === platform.member)
  if (!member) throw new VaultError("not_found", "No such subject.")
  const basis: PlatformConsentBasis = { ...consentBasis(state, member.id, ask, ctx.now(), { sessionCheck: null, session: `platform:${platform.key}`, account: member.account, securityEpoch: 0 }), platform }
  const lineage: ConsentLineage = { id: randomId("cns"), decision, basis, createdAt: ctx.now(), expiresAt: Math.min(expiresAt, basis.expiresAt ?? expiresAt), revokedAt: null }
  ctx.sql.exec("INSERT INTO consent_lineage(id,decision,member,ask,basis,created_at,expires_at) VALUES (?,?,?,?,?,?,?)", lineage.id, decision, member.id, JSON.stringify(ask), JSON.stringify(basis), lineage.createdAt, lineage.expiresAt)
  return lineage
}
// Platform consent stays current while it is this workspace's platform and
// subject, the subject member is active, and the platform is live by the
// row the workspace last read.
function platformConsentLive(ctx: VaultContext, state: AccessState, platform: PlatformConsent): boolean {
  const managed = managedSetting(ctx), row = cachedManagedPlatform(ctx)
  return managed !== null && managed.platform === platform.platform && managed.subject === platform.subject && managed.member === platform.member && row !== null && platformLive(row.platform.status) && state.members.some((m) => m.id === platform.member && m.status === "active")
}

export function readConsent(ctx: VaultContext, id: string): { lineage: ConsentLineage; ask: AccessAsk } | null {
  const row = one(ctx.sql.exec<{ id: string; decision: string; ask: string; basis: string; created_at: number; expires_at: number; revoked_at: number | null }>("SELECT * FROM consent_lineage WHERE id=?", id))
  return row ? { lineage: { id: row.id, decision: row.decision, basis: JSON.parse(row.basis) as ConsentBasis, createdAt: row.created_at, expiresAt: row.expires_at, revokedAt: row.revoked_at }, ask: JSON.parse(row.ask) as AccessAsk } : null
}

export function invalidateConsent(ctx: VaultContext, member: string): void {
  ctx.sql.exec("UPDATE consent_lineage SET revoked_at=? WHERE member=? AND revoked_at IS NULL", ctx.now(), member)
  ctx.sql.exec("UPDATE run_authorisations SET revoked_at=? WHERE lineage IN (SELECT id FROM consent_lineage WHERE member=?) AND revoked_at IS NULL", ctx.now(), member)
  ctx.sql.exec("UPDATE protected_use_grants SET revoked_at=? WHERE lineage IN (SELECT id FROM consent_lineage WHERE member=?) AND revoked_at IS NULL", ctx.now(), member)
}

export function accessChangeDevices(state: AccessState, member: string | null, target: import("./workspace-runtime.ts").AccessChangeTarget): string[] {
  return state.devices.filter((device) => member !== null ? device.owner.kind === "member" && device.owner.id === member : target.device ? device.id === target.device : target.team ? device.owner.kind === "team" && device.owner.id === target.team : false).map((device) => device.id)
}
export function invalidateDeviceConsent(ctx: VaultContext, device: string): void {
  ctx.sql.exec("UPDATE consent_lineage SET revoked_at=? WHERE json_extract(ask,'$.device')=? AND revoked_at IS NULL", ctx.now(), device)
  ctx.sql.exec("UPDATE protected_use_grants SET revoked_at=? WHERE lineage IN(SELECT id FROM consent_lineage WHERE json_extract(ask,'$.device')=?) AND revoked_at IS NULL", ctx.now(), device)
  ctx.sql.exec("UPDATE run_authorisations SET revoked_at=? WHERE lineage IN(SELECT id FROM consent_lineage WHERE json_extract(ask,'$.device')=?) AND revoked_at IS NULL", ctx.now(), device)
}

export function consentService(state: (ctx: VaultContext) => AccessState): WorkspaceConsentService {
  return { current(ctx, lineage, now) { const stored = readConsent(ctx, lineage.id); return stored !== null && canonicalJson(stored.lineage) === canonicalJson(lineage) && consentCurrent(ctx, state(ctx), stored.lineage, stored.ask, now) }, invalidate: invalidateConsent, offboard(ctx, snapshot) { invalidateConsent(ctx, snapshot.member) } }
}

export function approvalDecision(state: AccessState, principal: AccessPrincipal, ask: AccessAsk, action: WorkspaceStepUpAction, now: number): void {
  if (action.type !== "approval.decide") throw new VaultError("forbidden", "This decision needs a passkey confirmation.")
  const decision = can(state, principal, { type: action.decision === "approve" ? "approval.approve" : "approval.deny" }, { ask }, now)
  if (!decision.allowed) throw new VaultError(decision.error, decision.message, decision.next ? { next: decision.next } : {})
}

export const WORKSPACE_APPROVAL_MIGRATION = `ALTER TABLE approvals ADD COLUMN ask TEXT;
ALTER TABLE approvals ADD COLUMN snapshot TEXT;
ALTER TABLE approvals ADD COLUMN binding_digest TEXT;
ALTER TABLE approvals ADD COLUMN workspace TEXT;
ALTER TABLE approvals ADD COLUMN lineage TEXT;
CREATE INDEX approvals_binding ON approvals(device,binding_digest);
${WORKSPACE_CONSENT_MIGRATION}`
export const WORKSPACE_APPROVAL_BINDING_MIGRATION = `ALTER TABLE approvals ADD COLUMN snapshot_digest TEXT;
ALTER TABLE approvals ADD COLUMN presentation_digest TEXT;
UPDATE approvals SET policy_status='stale' WHERE ask IS NOT NULL;`
// The workload that asked, when one did: only it may read, wait on or spend
// the approval; its device's own key may list it and see it ended.
export const WORKSPACE_APPROVAL_WORKLOAD_MIGRATION = `ALTER TABLE approvals ADD COLUMN workload TEXT;
CREATE INDEX approvals_workload ON approvals(workload);`
// Batch approvals: an ask's review group, shape and floor (NULL on rows asked
// before them, or with APPROVAL_BATCHES off), the bundle it was asked in,
// and the newer ask that replaced it (policy_status 'superseded').
export const WORKSPACE_APPROVAL_BATCH_MIGRATION = `ALTER TABLE approvals ADD COLUMN review_group TEXT;
ALTER TABLE approvals ADD COLUMN shape TEXT;
ALTER TABLE approvals ADD COLUMN floor TEXT;
ALTER TABLE approvals ADD COLUMN bundle TEXT;
ALTER TABLE approvals ADD COLUMN superseded_by TEXT;
CREATE INDEX approvals_review_group ON approvals(review_group, status);
CREATE INDEX approvals_shape ON approvals(device, shape);
CREATE INDEX approvals_bundle ON approvals(bundle);
CREATE TABLE approval_bundles (id TEXT PRIMARY KEY, device TEXT NOT NULL, workload TEXT,
  reason TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);`
// Group codes: one code per Review together page, which mehen prints
// with the group's link, so the person checks one code, not one per ask. A
// bundle's is made with it; a machine group's with the ask that opens it,
// kept while any ask of it may still be open (expires_at, its newest ask's
// end), and new each time the group reopens.
export const WORKSPACE_APPROVAL_GROUP_CODE_MIGRATION = `ALTER TABLE approval_bundles ADD COLUMN code TEXT;
CREATE TABLE approval_group_codes (review_group TEXT PRIMARY KEY, code TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE INDEX approval_group_codes_expiry ON approval_group_codes(expires_at);`
// Inside the caller's transaction, for an ask just stored in a machine
// group: with no other open ask of the group, the group reopens on a new code.
function keepGroupCode(ctx: VaultContext, group: string, ask: string, expiresAt: number, now: number): void {
  ctx.sql.exec("DELETE FROM approval_group_codes WHERE expires_at<=?", now)
  const others = one(ctx.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM approvals WHERE review_group=? AND bundle IS NULL AND id<>? AND ask IS NOT NULL AND status='pending' AND policy_status IS NULL AND expires_at>?", group, ask, now))?.n ?? 0
  if (others === 0) ctx.sql.exec("DELETE FROM approval_group_codes WHERE review_group=?", group)
  ctx.sql.exec("INSERT INTO approval_group_codes(review_group,code,expires_at) VALUES (?,?,?) ON CONFLICT(review_group) DO UPDATE SET expires_at=MAX(approval_group_codes.expires_at,excluded.expires_at)", group, bindingCode(), expiresAt)
}
// The code a Review together page shows: its bundle's, or its machine
// group's while one of its asks may be open; null for one made before codes.
export function reviewGroupCode(ctx: VaultContext, group: string): string | null {
  if (group.startsWith("bnd_")) return one(ctx.sql.exec<{ code: string | null }>("SELECT code FROM approval_bundles WHERE id=?", group))?.code ?? null
  return one(ctx.sql.exec<{ code: string }>("SELECT code FROM approval_group_codes WHERE review_group=? AND expires_at>?", group, ctx.now()))?.code ?? null
}

// Whether batch approvals are on for a workspace (its tn_ id). In a
// workspace's object, batchesHere also leaves out a managed workspace.
export function approvalBatchesOn(env: Pick<Env, "APPROVAL_BATCHES">, workspace: string): boolean {
  return workspaceSwitchOn(env.APPROVAL_BATCHES, workspace)
}
export function batchesHere(ctx: VaultContext): boolean {
  return approvalBatchesOn(ctx.env, ctx.tenant) && managedSetting(ctx) === null
}
export function replacingUnavailable(): VaultError {
  return new VaultError("forbidden", "Replacing an ask is not available yet.")
}

// What every caller of requestWorkspaceApproval says about its ask. floor:
// the floor reasons the request touches, worked out while its bytes are in
// hand, or null (a run, decided on its own page), stored as NULL, which
// counts as floor. shape: digestOf the credential, method, host and path (no query),
// or of a run's project, environment and command. replaces: the asker's
// own earlier open ask to the same place that this one supersedes. bundle:
// the bnd_ an agent's plan asked it in (relay plan mode), never superseded.
export type ApprovalAskBatch = { floor: PolicyFloorView["reason"][] | null; shape: string; replaces: string | null; bundle?: string }

// A machine's open asks of every kind (approvals, intakes, connects and rule
// proposals together): it bounds the noise one machine can put in front of
// people (threat model), and what one Review together page holds.
export const MACHINE_MAX_OPEN_ASKS = 20
// The refusal at that cap. It sends the person to decide what is open: the
// asker's own oldest open approval, on its Review together page when it
// shares a bundle or a group with others, else on its own page; with none
// of its own, the workspace's home, whose Needs you lists them (mehen
// accepts the home as a refusal's link, not /pending). With batch approvals
// off, Review together refuses, so the link is the ask's own page. Only ids
// the asker already knows go in.
export function machineAsksFull(ctx: VaultContext, asker: { device: string; workload?: string }, slug: string, message: string): VaultError {
  const now = ctx.now(), base = `${ctx.env.VAULT_ORIGIN}/w/${encodeURIComponent(slug)}`
  const oldest = one(ctx.sql.exec<{ id: string; review_group: string | null; bundle: string | null }>("SELECT id,review_group,bundle FROM approvals WHERE device=? AND workload IS ? AND ask IS NOT NULL AND status='pending' AND policy_status IS NULL AND expires_at>? ORDER BY created_at,id LIMIT 1", asker.device, asker.workload ?? null, now))
  const batches = batchesHere(ctx)
  const grouped = batches && oldest?.review_group != null && oldest.bundle === null && (one(ctx.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM approvals WHERE review_group=? AND bundle IS NULL AND ask IS NOT NULL AND status='pending' AND policy_status IS NULL AND expires_at>?", oldest.review_group, now))?.n ?? 0) >= 2
  const path = !oldest ? "/" : batches && oldest.bundle !== null ? `/g/${oldest.bundle}` : grouped ? `/g/${oldest.review_group}` : `/a/${oldest.id}`
  return new VaultError("rate_limited", message, { next: { url: `${base}${path}`, say: "Ask the person to decide this machine's open asks at the link, then ask for the rest." } })
}

// grp_: one machine's (and workload's) asks on one credential, or for one
// project environment's runs. Only ids the asker already knows go in.
export function approvalReviewGroup(workspace: string, ask: AccessAsk): string {
  const target = ask.credential ?? `run:${ask.context?.project ?? ""}/${ask.context?.environment ?? ""}`
  return `grp_${createHash("sha256").update(`mehen-approval-group/v1\n${workspace}\n${ask.device}\n${ask.workload ?? ""}\n${target}`).digest("base64url").slice(0, 22)}`
}
export function approvalBinding(subject: ApprovalSubject, presentation: ApprovalPresentation, snapshot: unknown): { snapshotDigest: string; presentationDigest: string; digest: string } {
  const snapshotDigest = digestOf(snapshot), presentationDigest = digestOf(presentation)
  return { snapshotDigest, presentationDigest, digest: digestOf({ subject, snapshotDigest, presentationDigest }) }
}

// decided_by_platform: in a managed workspace, the platform, key, proof id
// and the platform's own reference of the decision (areas/managed.ts).
export type WorkspaceApprovalRow = { id: string; device: string; workload: string | null; device_name: string; session: string | null; item: string; subject: string; presentation: string; digest: string; binding_code: string; status: "pending" | "approved" | "denied"; created_at: number; expires_at: number; decided_by: string | null; decided_at: number | null; ask: string; snapshot: string; binding_digest: string; workspace: string; lineage: string | null; policy_status: string | null; snapshot_digest: string | null; presentation_digest: string | null; decided_by_platform?: string | null; review_group?: string | null; shape?: string | null; floor?: string | null; bundle?: string | null; superseded_by?: string | null }
export function workspaceApproval(ctx: VaultContext, id: string): WorkspaceApprovalRow | null {
  return one(ctx.sql.exec<WorkspaceApprovalRow>("SELECT * FROM approvals WHERE id=? AND ask IS NOT NULL", id))
}
// Inside the caller's transaction: an identical open ask is returned as it
// is (a bundle takes it in when it is in none); otherwise the ask it
// replaces is superseded before the cap is counted, so a re-ask at the cap
// succeeds, and a failed insert keeps the old ask.
export function requestWorkspaceApproval(ctx: VaultContext, state: AccessState, ask: AccessAsk, workspace: WorkspaceRef, subject: ApprovalSubject, presentation: ApprovalPresentation, snapshot: unknown, now: number, batch: ApprovalAskBatch): WorkspaceApprovalRow {
  const { digest: binding, snapshotDigest, presentationDigest } = approvalBinding(subject, presentation, snapshot)
  const old = one(ctx.sql.exec<WorkspaceApprovalRow>("SELECT * FROM approvals WHERE device=? AND workload IS ? AND binding_digest=? AND status='pending' AND policy_status IS NULL AND expires_at>? ORDER BY created_at LIMIT 1", ask.device, ask.workload ?? null, binding, now))
  if (old && batch.bundle !== undefined && !old.bundle && batchesHere(ctx)) {
    ctx.sql.exec("UPDATE approvals SET bundle=? WHERE id=?", batch.bundle, old.id)
    return { ...old, bundle: batch.bundle }
  }
  if (old) return old
  const device = state.devices.find((d) => d.id === ask.device)
  if (!device) throw new VaultError("not_found", "No such object.")
  const id = randomId("apr")
  const batches = batchesHere(ctx)
  if (batch.replaces !== null) supersedeAsk(ctx, state, ask, batch.replaces, batch.shape, id, now)
  if (openAskCount(ctx, device.id, now) >= MACHINE_MAX_OPEN_ASKS) throw machineAsksFull(ctx, ask, workspace.slug, "This machine already has 20 open asks. Settle one before asking again.")
  assertWorkloadAskRoom(ctx, ask.workload, now)
  const name = devicePolicyState(ctx, device.id)?.name
  if (name === undefined) throw new VaultError("not_found", "No such object.")
  const group = batches ? approvalReviewGroup(workspace.id, ask) : null
  ctx.sql.exec("INSERT INTO approvals(id,device,device_name,session,item,digest,subject,presentation,binding_code,status,created_at,expires_at,ask,snapshot,binding_digest,workspace,snapshot_digest,presentation_digest,workload,review_group,shape,floor,bundle) VALUES(?,?,?,NULL,?,?,?,?,?,'pending',?,?,?,?,?,?,?,?,?,?,?,?,?)", id, device.id, name, subject.item, binding, JSON.stringify(subject), JSON.stringify(presentation), bindingCode(), now, now + 3_600_000, JSON.stringify(ask), canonicalJson(snapshot), binding, JSON.stringify(workspace), snapshotDigest, presentationDigest, ask.workload ?? null, group, batches ? batch.shape : null, batches && batch.floor !== null ? JSON.stringify([...new Set(batch.floor)].sort()) : null, batches ? batch.bundle ?? null : null)
  if (group !== null && batch.bundle === undefined) keepGroupCode(ctx, group, id, now + 3_600_000, now)
  const credential = state.credentials.find((c) => c.id === ask.credential)
  if (credential?.home.kind === "member") auditPrivateEvent(ctx, { action: "approval.request", at: now, actor: { kind: "device", device: device.id, owner: device.owner.kind === "member" ? { kind: "member", member: device.owner.id } : { kind: "team", team: device.owner.id } }, session: null, item: credential.id, slug: subject.item, outcome: "pending", run: null }, credential.home.member)
  else ctx.audit({ actor: `device:${device.id}`, action: "approval.request", target: id, detail: { item: subject.item, outcome: "pending" } })
  const row = workspaceApproval(ctx, id)
  if (!row) throw new Error("Approval insertion failed")
  return row
}
// Only the asker's own open ask to the same place, outside any bundle (ruling
// B1): the same device and workload, the same shape, pending and unexpired.
function supersedeAsk(ctx: VaultContext, state: AccessState, ask: AccessAsk, replaces: string, shape: string, by: string, now: number): void {
  if (!batchesHere(ctx)) throw replacingUnavailable()
  const earlier = one(ctx.sql.exec<WorkspaceApprovalRow>("SELECT * FROM approvals WHERE id=? AND ask IS NOT NULL AND device=? AND workload IS ? AND shape=? AND bundle IS NULL AND status='pending' AND policy_status IS NULL AND expires_at>?", replaces, ask.device, ask.workload ?? null, shape, now))
  if (!earlier) throw new VaultError("bad_request", `${replaces} is not an open ask from this machine to the same place.`)
  ctx.sql.exec("UPDATE approvals SET policy_status='superseded',superseded_by=? WHERE id=?", by, earlier.id)
  const device = state.devices.find((d) => d.id === ask.device)
  if (!device) throw new VaultError("not_found", "No such object.")
  const credential = state.credentials.find((c) => c.id === (JSON.parse(earlier.ask) as AccessAsk).credential)
  if (credential?.home.kind === "member") auditPrivateEvent(ctx, { action: "approval.supersede", at: now, actor: { kind: "device", device: device.id, owner: device.owner.kind === "member" ? { kind: "member", member: device.owner.id } : { kind: "team", team: device.owner.id } }, session: null, item: credential.id, slug: earlier.item, outcome: "superseded", run: null }, credential.home.member)
  else ctx.audit({ actor: `device:${device.id}`, action: "approval.supersede", target: earlier.id, detail: { item: earlier.item, replacedBy: by } })
}
// A pending run ask whose credentials' configuration changed since it was
// requested: the snapshot keeps each credential's config_rev, and any
// difference (a binding, ceiling or policy edit that leaves the item, its
// home and the references as they were) means the request is no longer the
// one shown. Only the status says so; no revision leaves the vault.
function runConfigurationChanged(ctx: VaultContext, row: WorkspaceApprovalRow): boolean {
  if (!row.snapshot) return false
  const run = (JSON.parse(row.snapshot) as import("./projects-workspace.ts").ProtectedSnapshot).run
  if (!run) return false
  return run.items.some((item) => one(ctx.sql.exec<{ config_rev: number }>("SELECT config_rev FROM items WHERE id=?", item.id))?.config_rev !== item.configRevision)
}
// In a managed workspace an approval asked under other platform defaults
// than those the workspace holds now is no longer the one asked: one still
// pending, or granted and still usable. One that was denied, used, revoked
// or has ended keeps that ending.
function platformDefaultsChanged(ctx: VaultContext, row: WorkspaceApprovalRow): boolean {
  const revision = managedDefaultsRevision(ctx)
  return revision !== null && (JSON.parse(row.snapshot) as import("./projects-workspace.ts").ProtectedSnapshot).platformDefaults !== revision
}
export function workspaceApprovalStatus(ctx: VaultContext, row: WorkspaceApprovalRow): ApprovalView["status"] {
  if (row.status === "denied") return "denied"
  if (row.policy_status === "stale") return "stale"
  if (row.policy_status === "superseded") return "superseded"
  const grant = row.status === "approved" ? one(ctx.sql.exec<{ uses_left: number | null; revoked_at: number | null; expires_at: number }>("SELECT uses_left,revoked_at,expires_at FROM protected_use_grants WHERE approval=?", row.id)) : null
  // A grant that was stopped or spent keeps saying so after the approval's own hour ends.
  if (grant && grant.revoked_at !== null) return "revoked"
  if (grant && grant.uses_left === 0) return "used"
  if (row.expires_at <= ctx.now()) return "expired"
  if (row.status === "pending" && (runConfigurationChanged(ctx, row) || platformDefaultsChanged(ctx, row) || pushSnapshotChanged(ctx, row.snapshot))) return "stale"
  if (row.status === "approved") {
    if (!grant) return "used"
    if (grant.expires_at <= ctx.now()) return "expired"
    if (platformDefaultsChanged(ctx, row)) return "stale"
    const consent = row.lineage ? readConsent(ctx, row.lineage) : null
    if (!consent || !consentCurrent(ctx, accessState(ctx), consent.lineage, consent.ask, ctx.now())) return "stale"
  }
  return row.status
}
export function storedApprovalProjection(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, row: WorkspaceApprovalRow): ApprovalViewProjection {
  const projected = approvalRowProjection(ctx, state, principal, row)
  if (projected.view === "detail" && (!row.snapshot_digest || !row.presentation_digest)) throw new VaultError("conflict", "This approval needs a fresh binding; ask for a new approval.")
  return projected
}
// storedApprovalProjection without its refusal of a row asked before
// bindings: Review together lists such a row to decide on its own page.
export function approvalRowProjection(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, row: WorkspaceApprovalRow): ApprovalViewProjection {
  const ask = JSON.parse(row.ask) as AccessAsk
  const subject = JSON.parse(row.subject) as ApprovalSubject
  const stored = JSON.parse(row.presentation) as ApprovalPresentation
  const standing = workspaceApprovalStatus(ctx, row)
  const status = standing === "expired" && row.status === "approved" ? "ended" : standing
  const presentation = status === "pending" || !stored.settled ? stored : { ...stored, ...stored.settled }
  const device = state.devices.find((d) => d.id === row.device)
  if (!device) throw new VaultError("not_found", "No such object.")
  const owner = device.owner.kind === "member" ? { kind: "member" as const, member: device.owner.id, name: state.members.find((m) => m.id === device.owner.id)?.name ?? "" } : { kind: "team" as const, team: device.owner.id, name: state.teams.find((t) => t.id === device.owner.id)?.name ?? "" }
  const eligibilityView = principal.kind === "member" ? eligibility(state, principal.memberId, ask, ctx.now()) : { canApprove: false, canDeny: false, canReadAskDetail: false, deciders: [], reason: null }
  // A guest never learns who decided: only the outcome, or that it was them.
  const guestReader = principal.kind === "member" && state.members.find((m) => m.id === principal.memberId)?.standing.effectiveRole === "guest"
  const push = pushApprovalView(ctx, row)
  const detail: Extract<ApprovalViewProjection, { view: "detail" }>["approval"] = { approval: row.id, status, decidedBy: row.decided_by ? { name: guestReader && !(principal.kind === "member" && principal.memberId === row.decided_by) ? null : state.members.find((m) => m.id === row.decided_by)?.name ?? null, self: principal.kind === "member" && principal.memberId === row.decided_by } : null, bindingCode: row.binding_code, item: { slug: row.item, account: null, provider: null }, requestedBy: { device: row.device, deviceName: row.device_name, session: row.session, ...askingWorkload(ctx, row.workload) }, title: presentation.title, details: presentation.details, warnings: presentation.warnings ?? [], email: presentation.email ?? null, request: { method: subject.method, url: subject.url, contentType: subject.contentType, contentEncoding: subject.contentEncoding, headers: presentation.headers ?? null, headersSha256: subject.headersSha256, bodySha256: subject.bodySha256, body: presentation.body }, digest: row.digest, constraints: subject.constraints, expiresAt: new Date(row.expires_at).toISOString(), workspace: JSON.parse(row.workspace) as WorkspaceRef, owner, eligibility: eligibilityView, ...(status === "superseded" && row.superseded_by ? { replacedBy: row.superseded_by } : {}), ...(push ? { push } : {}) }
  return approvalProjection(state, principal, { id: row.id, ask, detail, binding: { snapshotDigest: row.snapshot_digest ?? "", presentationDigest: row.presentation_digest ?? "" } }, detail.workspace, ctx.now())
}
const ApprovalConstraints = z.strictObject({ uses: z.number().int().min(1).max(100).nullable(), ttlSeconds: z.number().int().min(60).max(86_400) })
// `surface: "app"` is set by the app route only.
export const WorkspaceApprovalDecisionInput = z.strictObject({ id: z.string().max(64), decision: z.enum(["approve", "deny"]), constraints: ApprovalConstraints.optional(), remember: PolicyRememberSchema.optional(), surface: z.literal("app").optional() })
// The app shows no push card and sends nothing, so a push, approved or
// denied, is decided on its vault page.
function refuseAppPush(input: z.infer<typeof WorkspaceApprovalDecisionInput>, subject: ApprovalSubject): void {
  if (input.surface === "app" && isPushSubject(subject)) throw new VaultError("forbidden", "Decide this push on its vault page.")
}
function decisionConstraints(ctx: VaultContext, subject: ApprovalSubject, input: z.infer<typeof WorkspaceApprovalDecisionInput>): ApprovalSubject["constraints"] {
  // A push is one send within its ten minutes, never remembered (design 2.4).
  if (isPushSubject(subject) && (input.remember !== undefined || input.constraints !== undefined && canonicalJson(input.constraints) !== canonicalJson(PUSH_CONSTRAINTS))) throw new VaultError("bad_request", "A push is approved once, as asked, and never remembered.")
  // Only a standing rule or a task grant may be remembered
  // (policy-rules-workspace.ts), and only on an approval; exact and route
  // stay refused. While rules are unavailable every remember answers as it
  // did before them.
  if (input.remember !== undefined) {
    if (input.remember.kind !== "rule" && input.remember.kind !== "area") throw new VaultError("forbidden", "Policy widening is not available yet.", { next: policyHelpNext })
    rulesAvailable(ctx)
    if (input.decision === "deny") throw new VaultError("bad_request", "Deny cannot remember access.")
  }
  if (input.decision === "deny") return subject.constraints
  const chosen = input.constraints ?? subject.constraints
  if (chosen.ttlSeconds > subject.constraints.ttlSeconds || subject.constraints.uses !== null && (chosen.uses === null || chosen.uses > subject.constraints.uses)) throw new VaultError("bad_request", "Approval limits cannot exceed the requested limits.")
  return chosen
}

// Rebuilds the immutable graph directly before consent is recorded: the
// requester, the references and the four-eyes projects the approval was
// asked under, and in a managed workspace the platform's defaults.
export function assertApprovalGraphCurrent(ctx: VaultContext, state: AccessState, snapshot: import("./projects-workspace.ts").ProtectedSnapshot, ask: AccessAsk): void {
  const changed = () => new VaultError("conflict", "Access changed; ask for a new approval.")
  if (canonicalJson(snapshot.requester) !== canonicalJson(requesterBasis(state, snapshot.device, snapshot.requesterProjects, ctx.now()))) throw changed()
  const ids = askedCredentials(state, ask)
  const references = new Map<string, ConsentBasis["referenceRevisions"][number]>()
  for (const p of state.projects) for (const e of p.environments) if (e.references.some((r) => ids.includes(r.item)) || snapshot.run && p.id === snapshot.project && e.name === snapshot.environment) references.set(`${p.id}/${e.name}`, { project: p.id, environment: e.name, revision: e.revision, protectionRevision: e.protectionRevision })
  if (canonicalJson([...references.values()].sort((a, b) => `${a.project}/${a.environment}`.localeCompare(`${b.project}/${b.environment}`))) !== canonicalJson(snapshot.references) || canonicalJson(fourEyesProjects(state, ask).sort()) !== canonicalJson(snapshot.fourEyes)) throw changed()
  const revision = managedDefaultsRevision(ctx)
  if (revision !== null && snapshot.platformDefaults !== revision) throw changed()
}

export const workspaceApprovalOps: NonNullable<import("../core.ts").Area["workspaceOps"]> = {
  "approvals.action": { auth: ["account"], async handler(ctx, principal, raw, invocation) {
    const input = parseOpInput(WorkspaceApprovalDecisionInput, raw)
    const row = workspaceApproval(ctx, input.id)
    if (!row) throw new VaultError("not_found", "No such object.")
    const ask = JSON.parse(row.ask) as AccessAsk
    authorise(ctx, invocation, { type: input.decision === "approve" ? "approval.approve" : "approval.deny" }, { ask }, ctx.now())
    const subject = JSON.parse(row.subject) as ApprovalSubject
    refuseAppPush(input, subject)
    const constraints = decisionConstraints(ctx, subject, input)
    if (input.remember?.kind === "rule" || input.remember?.kind === "area") {
      if (principal.kind === "system") rulesOff()
      await rememberPrepared(ctx, eligibilityState(ctx, invocation), principal, row, input.remember)
      return { type: "approval.decide", approval: row.id, digest: row.digest, decision: input.decision, constraints, remember: input.remember }
    }
    return { type: "approval.decide", approval: row.id, digest: row.digest, decision: input.decision, constraints }
  } },
  "approvals.status": { auth: ["device"], async handler(ctx, principal, raw, invocation) {
    if (principal.kind !== "device") throw new VaultError("not_found", "No such object.")
    const { id, wait } = parseOpInput(z.strictObject({ id: z.string().max(64), wait: z.boolean().default(false) }), raw)
    const check = () => {
      authorise(ctx, invocation, { type: "asks.read" }, { device: principal.deviceId }, ctx.now())
      const row = workspaceApproval(ctx, id)
      if (!row || row.device !== principal.deviceId || row.workload !== (principal.workload ?? null)) throw new VaultError("not_found", "No such object.")
      const ask = JSON.parse(row.ask) as AccessAsk
      if (!deviceSeesAsk(accessState(ctx), principal, ask, ctx.now())) throw new VaultError("not_found", "No such object.")
      return row
    }
    let row = check()
    const deadline = ctx.now() + Math.min(25_000, Math.max(0, row.expires_at - ctx.now()))
    while (wait && workspaceApprovalStatus(ctx, row) === "pending" && ctx.now() < deadline) {
      await waitForStorageWrite(ctx.storage, deadline - ctx.now())
      row = check()
    }
    const approvedAt = row.status === "approved" && row.decided_at !== null ? { approvedAt: new Date(row.decided_at).toISOString() } : {}
    // A mehen before SUPERSEDED_CLI reads a superseded ask as stale, which it already stops on.
    const standing = workspaceApprovalStatus(ctx, row), version = invocation.auth.kind === "device" ? invocation.auth.cliVersion ?? null : null
    const status = standing === "superseded" && (version === null || compareVersions(version, SUPERSEDED_CLI) < 0) ? "stale" : standing
    const replaced = status === "superseded" && row.superseded_by ? { replacedBy: row.superseded_by } : {}
    const push = pushApprovalStatus(ctx, row)
    return { approval: row.id, status, ...replaced, bindingCode: row.binding_code, summary: (JSON.parse(row.presentation) as ApprovalPresentation).title, expiresAt: new Date(row.expires_at).toISOString(), ...approvedAt, ...approvalRuleRefs(ctx, invocation, row.id), ...(push ? { push } : {}) }
  } },
  "approvals.view": { auth: ["account"], handler(ctx, principal, raw, invocation) {
    if (principal.kind === "system") throw new VaultError("not_found", "No such object.")
    const { id } = parseOpInput(z.strictObject({ id: z.string().max(64) }), raw)
    const row = workspaceApproval(ctx, id)
    if (!row) throw new VaultError("not_found", "No such object.")
    authorise(ctx, invocation, { type: "asks.read" }, {}, ctx.now())
    const state = eligibilityState(ctx, invocation)
    const projected = withRuleRefs(ctx, state, principal, invocation, storedApprovalProjection(ctx, state, principal, row))
    if (projected.view !== "detail" || projected.approval.status !== "pending") return projected
    return Promise.all([ruleOffer(ctx, state, principal, row), areaOffer(ctx, state, principal, row)]).then(([rule, area]) => rule === undefined && area === undefined ? projected : { ...projected, approval: { ...projected.approval, rememberOptions: { route: null, ...(rule !== undefined ? { rule } : {}), ...(area !== undefined ? { area } : {}) } } })
  } },
  "approvals.decide": { auth: ["account"], handler(ctx, principal, raw, invocation) {
    if (principal.kind !== "member") throw new VaultError("forbidden", "Only a person can decide an approval.")
    const input = parseOpInput(WorkspaceApprovalDecisionInput, raw)
    // A remembered rule's or task grant's terms are rebuilt and their digest
    // checked first (async), once the decider and the remember are allowed;
    // a plain decision stays synchronous.
    const remember = input.remember
    if ((remember?.kind === "rule" || remember?.kind === "area") && input.decision === "approve") {
      const pending = workspaceApproval(ctx, input.id)
      if (!pending) throw new VaultError("not_found", "No such object.")
      authorise(ctx, invocation, { type: "approval.approve" }, { ask: JSON.parse(pending.ask) as AccessAsk }, ctx.now())
      const subject = JSON.parse(pending.subject) as ApprovalSubject
      refuseAppPush(input, subject)
      decisionConstraints(ctx, subject, input)
      return rememberPrepared(ctx, eligibilityState(ctx, invocation), principal, pending, remember).then((remembered) => decideApproval(ctx, principal, input, invocation, remembered))
    }
    return decideApproval(ctx, principal, input, invocation, null)
  } },
}
function rememberPrepared(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, row: WorkspaceApprovalRow, remember: Extract<PolicyRemember, { kind: "rule" | "area" }>): Promise<RememberedRule | RememberedArea> {
  return remember.kind === "area" ? prepareAreaRemember(ctx, state, principal, row, remember) : prepareRemember(ctx, state, principal, row, remember)
}

function decideApproval(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "member" }>, input: z.infer<typeof WorkspaceApprovalDecisionInput>, invocation: WorkspaceInvocationContext, remembered: RememberedRule | RememberedArea | null): ApprovalViewProjection {
  ctx.storage.transactionSync(() => {
    const row = workspaceApproval(ctx, input.id)
    if (!row) throw new VaultError("not_found", "No such object.")
    const state = eligibilityState(ctx, invocation), ask = JSON.parse(row.ask) as AccessAsk
    const decision = authorise(ctx, invocation, { type: input.decision === "approve" ? "approval.approve" : "approval.deny" }, { ask }, ctx.now())
    const subject = JSON.parse(row.subject) as ApprovalSubject
    refuseAppPush(input, subject)
    const constraints = decisionConstraints(ctx, subject, input)
    const expected: WorkspaceStepUpAction = { type: "approval.decide", approval: row.id, digest: row.digest, decision: input.decision, constraints, ...(input.remember ? { remember: input.remember } : {}) }
    requireStepUp(ctx, decision, expected, invocation)
    recordDecision(ctx, state, principal, row, input.decision, constraints, invocation, null)
    if (input.decision === "approve" && isPushSubject(subject)) queueApprovedPush(ctx, row)
    if (remembered !== null) applyRemember(ctx, eligibilityState(ctx, invocation), principal, row, remembered, invocation)
  })
  const row = workspaceApproval(ctx, input.id)
  if (!row) throw new Error("Approval disappeared")
  const state = eligibilityState(ctx, invocation)
  return withRuleRefs(ctx, state, principal, invocation, storedApprovalProjection(ctx, state, principal, row))
}
// The decision itself, inside the caller's transaction once the decider's
// rights and step-up are checked: the ask must still be pending, an approval
// must still stand on the graph it was asked under, and it is audited, with
// the approval.decide_many batch (apb_) that made it, if one did.
export function recordDecision(ctx: VaultContext, state: AccessState, principal: Extract<AccessPrincipal, { kind: "member" }>, row: WorkspaceApprovalRow, decision: "approve" | "deny", constraints: ApprovalSubject["constraints"], invocation: WorkspaceInvocationContext, batch: string | null): void {
  const ask = JSON.parse(row.ask) as AccessAsk
  if (row.status !== "pending" || row.policy_status !== null || row.expires_at <= ctx.now()) throw new VaultError("conflict", "This approval is no longer pending.")
  let lineage: ConsentLineage | null = null
  if (decision === "approve") {
    const snapshot = JSON.parse(row.snapshot) as import("./projects-workspace.ts").ProtectedSnapshot
    assertApprovalGraphCurrent(ctx, state, snapshot, ask)
    const grantExpiresAt = Math.min(row.expires_at, ctx.now() + constraints.ttlSeconds * 1000)
    lineage = storeConsent(ctx, state, row.id, principal.memberId, ask, snapshot.run ? grantExpiresAt + 2 * 3_600_000 : grantExpiresAt, invocation)
    ctx.sql.exec("INSERT INTO protected_use_grants(approval,lineage,snapshot,uses_left,expires_at) VALUES(?,?,?,?,?)", row.id, lineage.id, row.snapshot, constraints.uses, Math.min(grantExpiresAt, lineage.expiresAt))
  }
  ctx.sql.exec("UPDATE approvals SET status=?,decided_by=?,decided_at=?,lineage=? WHERE id=?", decision === "approve" ? "approved" : "denied", principal.memberId, ctx.now(), lineage?.id ?? null, row.id)
  if (decision === "deny") countPostureDenied(ctx, ask.credential, row.created_at)
  const credential = state.credentials.find((c) => c.id === ask.credential)
  const batched = batch === null ? {} : { batch }
  if (credential?.home.kind === "member") auditPrivateEvent(ctx, { action: decision === "approve" ? "approval.approve" : "approval.deny", at: ctx.now(), actor: { kind: "member", member: principal.memberId }, session: invocation.auth.kind === "account" ? invocation.auth.session : null, item: credential.id, slug: row.item, outcome: decision, run: null, ...batched }, credential.home.member)
  else ctx.audit({ actor: `member:${principal.memberId}`, action: decision === "approve" ? "approval.approve" : "approval.deny", target: row.id, detail: { item: row.item, device: row.device, outcome: decision, ...batched } })
}
// The page's detail view names what a remember made, when the viewer may read it.
function withRuleRefs(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, invocation: WorkspaceInvocationContext, projected: ApprovalViewProjection): ApprovalViewProjection {
  if (projected.view !== "detail") return projected
  const refs = approvalRuleView(ctx, state, principal, invocation, projected.approval.approval)
  return refs === null ? projected : { ...projected, approval: { ...projected.approval, ...refs } }
}

registerOpenAskCounter("approvals", (ctx, device, now) => one(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM approvals WHERE device=? AND status='pending' AND policy_status IS NULL AND expires_at>?", device, now))?.count ?? 0)
registerWorkloadAskCounter("approvals", (ctx, workload, now) => one(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM approvals WHERE workload=? AND status='pending' AND policy_status IS NULL AND expires_at>?", workload, now))?.count ?? 0)
registerOffboardingHook("consent", (ctx, snapshot) => {
  invalidateConsent(ctx, snapshot.member)
  for (const device of accessChangeDevices(accessState(ctx), snapshot.member, {})) invalidateDeviceConsent(ctx, device)
})
registerAccessChangeHook("consent", (ctx, member, _reason, target) => {
  if (member !== null) invalidateConsent(ctx, member)
  for (const device of accessChangeDevices(accessState(ctx), member, target)) invalidateDeviceConsent(ctx, device)
})

// Resource changes synchronously mark affected consent stale. Expiry is still
// checked on each use, because clocks do not bump an access revision. A
// standing rule's consent (decision "rule:...") is judged by its own rules
// (standingConsentCurrent) each time the rule is read or used.
export const STANDING_CONSENT_PREFIX = "rule:"
export function staleWorkspaceConsent(ctx: VaultContext, state: AccessState): void {
  for (const { id } of ctx.sql.exec<{ id: string }>("SELECT id FROM consent_lineage WHERE revoked_at IS NULL AND substr(decision,1,5)<>?", STANDING_CONSENT_PREFIX).toArray()) {
    const stored = readConsent(ctx, id)
    if (!stored || consentCurrent(ctx, state, stored.lineage, stored.ask, ctx.now())) continue
    ctx.sql.exec("UPDATE consent_lineage SET revoked_at=? WHERE id=?", ctx.now(), id)
    ctx.sql.exec("UPDATE protected_use_grants SET revoked_at=? WHERE lineage=?", ctx.now(), id)
    ctx.sql.exec("UPDATE run_authorisations SET revoked_at=? WHERE lineage=?", ctx.now(), id)
  }
  // A superseded ask keeps saying so.
  for (const row of ctx.sql.exec<WorkspaceApprovalRow>("SELECT * FROM approvals WHERE ask IS NOT NULL AND status='pending' AND policy_status IS NULL").toArray()) {
    const snapshot = JSON.parse(row.snapshot) as import("./projects-workspace.ts").ProtectedSnapshot
    const ask = JSON.parse(row.ask) as AccessAsk
    const invalid = !state.devices.some((device) => device.id === snapshot.device) || canonicalJson(snapshot.requester) !== canonicalJson(requesterBasis(state, snapshot.device, snapshot.requesterProjects, ctx.now())) || canonicalJson(consentReferences(state, ask)) !== canonicalJson(snapshot.references) || canonicalJson(fourEyesProjects(state, ask).sort()) !== canonicalJson(snapshot.fourEyes)
    if (invalid) ctx.sql.exec("UPDATE approvals SET policy_status='stale' WHERE id=?", row.id)
  }
}

export function consentCurrent(ctx: VaultContext, state: AccessState, lineage: ConsentLineage, ask: AccessAsk, now: number): boolean {
  const basis = lineage.basis as ConsentBasis
  const platform = platformConsentOf(basis)
  if (platform) return platformConsentLive(ctx, state, platform) && consentIsCurrent(state, lineage, ask, now)
  if (!retainedGateValid(ctx, basis, now)) return false
  const forDecider = structuredClone(state)
  const member = forDecider.members.find((m) => m.id === basis.member && m.account === basis.account)
  if (!member) return false
  if (member.standing.identityGate.covered) {
    const check = basis.sessionCheck
    if (!check || check.identityRuleRev !== member.standing.identityRuleRev || check.gateGeneration !== member.standing.gateGeneration || Date.parse(check.expiresAt) <= now) return false
    member.standing.identityGate.admitted = true
    member.standing.identityGate.checkedAt = Date.parse(check.succeededAt)
  }
  return consentIsCurrent(forDecider, lineage, ask, now)
}

// consentCurrent for a standing rule (policy-rules-workspace.ts): the
// approver's live standing (standingGateValid) in place of the session's
// identity check, so a rule in an identity-gated workspace lives to its
// own deadline. Never platform consent: rules do not exist in a managed
// workspace.
export function standingConsentCurrent(ctx: VaultContext, state: AccessState, lineage: ConsentLineage, ask: AccessAsk, now: number): boolean {
  const basis = lineage.basis as ConsentBasis
  if (platformConsentOf(basis) || !standingGateValid(ctx, basis)) return false
  const forDecider = structuredClone(state)
  const member = forDecider.members.find((m) => m.id === basis.member && m.account === basis.account)
  if (!member) return false
  if (member.standing.identityGate.covered) {
    member.standing.identityGate.admitted = true
    member.standing.identityGate.checkedAt = now
  }
  return consentIsCurrent(forDecider, lineage, ask, now)
}
