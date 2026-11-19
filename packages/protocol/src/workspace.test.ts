import { describe, expect, test } from "bun:test"
import { AccountSecurityStateSchema, AccountSecurityTransitionSchema, DeviceRescopeProposalSchema, RescopeRejectRequestSchema, EligibilitySchema, EnrolAcceptanceSubjectSchema, INVITE_TTL_MS, InviteCreateSchema, InviteEmailedSchema, InviteTermsSchema, inviteJoinsStraightAway, PrivateEventSchema, WorkspaceDeviceScopeSchema, WorkspaceSlugSchema, WorkspaceStepUpActionSchema } from "./workspace.ts"
import { AppGateCodeSchema } from "./oidc.ts"
import { ModeSchema } from "./api.ts"
import { DeviceModeSchema, EnrolRequestedScopeSchema } from "./workspace.ts"
import { WorkloadScopeSchema } from "./workload.ts"
const scope = { tags: [], projects: [], modes: ["relay"], maxEnvironment: "unprotected", privateCredentials: false } as const
const complete = { ...scope, tags: [], projects: [], modes: ["relay"] }

describe("workspace strict frozen schemas", () => {
 test("the shared invitation and pending-promotion lifetime is seven days", () => { expect(INVITE_TTL_MS).toBe(604800000) })
 test("no private tick is ever inferred; team scopes cannot imply private authority", () => {
  expect(WorkspaceDeviceScopeSchema.safeParse({ tags: [], projects: [], modes: [], maxEnvironment: "unprotected" }).success).toBe(false)
  expect(WorkspaceDeviceScopeSchema.parse(complete).privateCredentials).toBe(false)
  expect(WorkspaceDeviceScopeSchema.safeParse({ ...complete, unknown: true }).success).toBe(false)
 })
 test("device modes take fill, never reveal, and a scope holds all six", () => {
  const six = ["relay", "sign", "mint", "placeholder", "fill", "lease"]
  expect(DeviceModeSchema.options).toEqual(six as typeof DeviceModeSchema.options)
  expect(DeviceModeSchema.safeParse("reveal").success).toBe(false)
  expect(WorkspaceDeviceScopeSchema.parse({ ...complete, modes: six }).modes).toEqual(six as typeof DeviceModeSchema.options)
  expect(EnrolRequestedScopeSchema.parse({ modes: six }).modes).toEqual(six as typeof DeviceModeSchema.options)
  expect(WorkloadScopeSchema.parse({ modes: six }).modes).toEqual(six as typeof DeviceModeSchema.options)
  expect(WorkspaceDeviceScopeSchema.safeParse({ ...complete, modes: [...six, "relay"] }).success).toBe(false)
  expect(EnrolRequestedScopeSchema.safeParse({ modes: [...six, "relay"] }).success).toBe(false)
  expect(WorkloadScopeSchema.safeParse({ modes: [...six, "relay"] }).success).toBe(false)
  expect(ModeSchema.options).toEqual(["relay", "sign", "mint", "placeholder", "fill", "lease", "reveal"])
 })
 test("source union projection cannot approve blind", () => {
  expect(EligibilitySchema.safeParse({ canApprove: true, canDeny: true, canReadAskDetail: false, deciders: [], reason: null }).success).toBe(false)
 })
 test("guest terms never contain teams/manage; elevated unbound invites refuse", () => {
  const terms = { role: "guest", email: null, teams: [], shares: [{ project: "p", level: "edit", protected: false, expiresAt: null }], expiresAt: "2027-01-01T00:00:00.000Z" }
  expect(InviteTermsSchema.safeParse(terms).success).toBe(true)
  expect(InviteTermsSchema.safeParse({ ...terms, teams: ["t"] }).success).toBe(false)
  expect(InviteTermsSchema.safeParse({ ...terms, role: "member" }).success).toBe(false)
  expect(InviteTermsSchema.safeParse({ ...terms, shares: [{ ...terms.shares[0], level: "manage" }] }).success).toBe(false)
 })
 test("onJoin is signed with the terms; only an email-bound invitation below owner joins straight away, and terms without it wait", () => {
  const member = { role: "member" as const, email: "tom@example.com", teams: [], shares: [], expiresAt: "2027-01-01T00:00:00.000Z" }
  for (const onJoin of ["activate", "confirm", undefined] as const) expect(InviteTermsSchema.parse({ ...member, onJoin })).toEqual({ ...member, onJoin })
  expect(InviteTermsSchema.safeParse({ ...member, onJoin: "auto" }).success).toBe(false)
  expect(inviteJoinsStraightAway({ ...member, onJoin: "activate" })).toBe(true)
  for (const role of ["admin", "guest"] as const) expect(inviteJoinsStraightAway({ ...member, role, onJoin: "activate" })).toBe(true)
  expect(inviteJoinsStraightAway({ ...member, onJoin: "confirm" })).toBe(false)
  expect(inviteJoinsStraightAway(member)).toBe(false)
  expect(inviteJoinsStraightAway({ ...member, role: "owner", onJoin: "activate" })).toBe(false)
  expect(inviteJoinsStraightAway({ ...member, role: "guest", email: null, onJoin: "activate" })).toBe(false)
 })
 test("making an invitation says whether to email its link (not, when a page from before emails says nothing), and nothing else beside the terms", () => {
  const terms = { role: "member" as const, email: "tom@example.com", teams: [], shares: [], expiresAt: "2027-01-01T00:00:00.000Z" }
  for (const email of [true, false]) expect(InviteCreateSchema.parse({ terms, email })).toEqual({ terms, email })
  expect(InviteCreateSchema.parse({ terms })).toEqual({ terms, email: false })
  expect(InviteCreateSchema.safeParse({ terms, email: "yes" }).success).toBe(false)
  expect(InviteCreateSchema.safeParse({ terms, email: true, subject: "Hi" }).success).toBe(false)
  expect(InviteEmailedSchema.options).toEqual(["sent", "not_requested", "limited", "failed"])
 })
 test("acceptance signs start time/place/client and complete key/owner/scope", () => {
  const subject = { type: "enrol.accept", workspace: "tn_x", enrolment: "enr_x", thumbprint: "full", account: "acc_x", member: "mem_x", scope: complete, start: { at: "2026-10-27T00:00:00.000Z", place: "Amsterdam, NL", clientLabel: "CLI" } }
  expect(WorkspaceStepUpActionSchema.safeParse(subject).success).toBe(true)
  const { start, ...missing } = subject
  expect(WorkspaceStepUpActionSchema.safeParse(missing).success).toBe(false)
  expect(EnrolAcceptanceSubjectSchema.safeParse({ ...missing, type: undefined }).success).toBe(false)
  expect(WorkspaceStepUpActionSchema.safeParse({ ...subject, type: "enrol.approve" }).success).toBe(false)
 })
 test("adoption.approve signs the adoption, the batch digest and how many variables it repoints, and nothing else", () => {
  const action = { type: "adoption.approve" as const, adoption: "adp_x", digest: "d", repoints: 0 }
  expect(WorkspaceStepUpActionSchema.parse(action)).toEqual(action)
  expect(WorkspaceStepUpActionSchema.safeParse({ type: "adoption.approve", adoption: "adp_x", repoints: 0 }).success).toBe(false)
  expect(WorkspaceStepUpActionSchema.safeParse({ type: "adoption.approve", adoption: "", digest: "d", repoints: 0 }).success).toBe(false)
  expect(WorkspaceStepUpActionSchema.safeParse({ type: "adoption.approve", adoption: "adp_x", digest: "d" }).success).toBe(false)
  expect(WorkspaceStepUpActionSchema.safeParse({ ...action, repoints: -1 }).success).toBe(false)
  expect(WorkspaceStepUpActionSchema.safeParse({ ...action, items: 3 }).success).toBe(false)
 })
 test("security transition separates committed and reserved epochs", () => {
  const state = { account: "acc_a", installedEpoch: 2, restriction: null, revokedSessionIds: ["s"], removedFactorIds: ["f"], deleting: false, pending: { transitionId: "tr", reservedEpoch: 3, revokedSessionIds: ["s"], removedFactorIds: ["f"], restriction: null } }
  expect(AccountSecurityStateSchema.parse(state)).toEqual(state)
  const transition = { id: "tr", account: "acc_a", committedEpoch: 2, pending: state.pending, kind: "recovery.cancel", targets: [{ workspace: "tn_a", membership: "mem_a", state: "joining" }], acknowledged: [], state: "pending", createdAt: 1, updatedAt: 1, committedAt: null, commitDelivery: [] }
  expect(AccountSecurityTransitionSchema.safeParse(transition).success).toBe(true)
  expect(AccountSecurityTransitionSchema.safeParse({ ...transition, committedEpoch: 3 }).success).toBe(false)
 })
 test("private event schema contains only the exact stored minimal fields", () => {
  const event = { action: "relay.allow", at: 1, actor: { kind: "device" as const, device: "d", owner: { kind: "member" as const, member: "m" } }, session: null, item: "i", slug: "mine", outcome: "allowed", run: null }
  expect(PrivateEventSchema.parse(event)).toEqual(event)
  for (const forbidden of ["host", "path", "fields", "provider", "binding", "label", "fingerprint", "body", "override"]) expect(PrivateEventSchema.safeParse({ ...event, [forbidden]: "hidden" }).success).toBe(false)
 })
 test("rescope proposals bind before/after and all live authority revisions", () => {
  const proposal = { id: "r", device: "d", thumbprint: "key", before: complete, after: { ...complete, privateCredentials: true }, beforeDigest: "b", afterDigest: "a", proposer: { member: "m", name: "M" }, requiredSigners: [{ account: "acc_m", name: "M", as: "owner_acceptance" }], signedBy: [], expiresAt: "2027-01-01T00:00:00.000Z", state: "open", owner: { kind: "member", member: "m", name: "M" }, deviceRevision: 1, ownerRevision: 1, scopeRevision: 1, signatures: [] }
  expect(DeviceRescopeProposalSchema.safeParse(proposal).success).toBe(true)
  const { scopeRevision, ...incomplete } = proposal
  expect(DeviceRescopeProposalSchema.safeParse(incomplete).success).toBe(false)
  expect(DeviceRescopeProposalSchema.safeParse({ ...proposal, state: "rejected" }).success).toBe(true)
  expect(DeviceRescopeProposalSchema.safeParse({ ...proposal, state: "declined" }).success).toBe(false)
 })
 test("a rescope reject request names one proposal and nothing that could change scope", () => {
  expect(RescopeRejectRequestSchema.parse({ proposal: "rsp_x" })).toEqual({ proposal: "rsp_x" })
  expect(RescopeRejectRequestSchema.parse({ proposal: "rsp_x", project: "prj_a" })).toEqual({ proposal: "rsp_x", project: "prj_a" })
  for (const extra of [{ after: complete }, { scope: complete }, { device: "d" }]) expect(RescopeRejectRequestSchema.safeParse({ proposal: "rsp_x", ...extra }).success).toBe(false)
  expect(RescopeRejectRequestSchema.safeParse({ proposal: "" }).success).toBe(false)
 })
 test("app handoff code requires session, epoch, rule/generation, PKCE, single-use state and five minutes", () => {
  const code = { codeHash: "h", appSessionHash: "s", account: "a", securityEpoch: 3, pkceChallenge: "a".repeat(43), workspace: "w", member: "m", ruleRevision: 1, gateGeneration: 1, result: "r", createdAt: 1000, expiresAt: 301000, consumedAt: null }
  expect(AppGateCodeSchema.safeParse(code).success).toBe(true)
  expect(AppGateCodeSchema.safeParse({ ...code, expiresAt: 301001 }).success).toBe(false)
  const { appSessionHash, ...incomplete } = code
  expect(AppGateCodeSchema.safeParse(incomplete).success).toBe(false)
 })
 test("public slug grammar reserves the migration prefix", () => {
  for (const slug of ["legacy-any", "has--dash", "-bad", "Upper", "a"]) expect(WorkspaceSlugSchema.safeParse(slug).success).toBe(false)
  expect(WorkspaceSlugSchema.safeParse("northwind").success).toBe(true)
 })
})

import { MinimalStopViewSchema } from "./workspace.ts"
import { WorkspaceIntakeCreate } from "./api.ts"
test("minimal stop projection rejects all richer details, and home requests use the frozen top-level wire fields", () => {
 const stop = { view: "stop", id: "a", workspace: { id: "w", slug: "alex", name: "Personal" }, machine: { device: "d", name: "laptop", owner: { kind: "member", member: "m", name: "M" } }, item: { slug: "private" }, status: "pending", eligibility: { canApprove: false, canDeny: true, canReadAskDetail: false, deciders: [], reason: null } }
 expect(MinimalStopViewSchema.safeParse(stop).success).toBe(true)
 expect(MinimalStopViewSchema.safeParse({ ...stop, request: { url: "hidden" } }).success).toBe(false)
 const input = { kind: "api-key", slug: "my-token", reason: "Need a token", home: "project", project: "prj_a" }
 expect(WorkspaceIntakeCreate.safeParse(input).success).toBe(true)
 expect(WorkspaceIntakeCreate.safeParse({ ...input, project: undefined }).success).toBe(false)
 expect(WorkspaceIntakeCreate.safeParse({ ...input, home: "private" }).success).toBe(false)
})

import { WorkspaceApprovalStopViewSchema, WorkspacePolicyProposalStopViewSchema, WorkspaceNoticePayloadSchema, WorkspaceEnrolViewSchema, type WorkspaceNoticePayload } from "./workspace.ts"
import { apiErrorExtrasValid, type ApiError } from "./api.ts"
test("minimal stop statuses are complete and remain family-specific", () => {
 const stop = { view: "stop", id: "a", workspace: { id: "w", slug: "alex", name: "Personal" }, machine: { device: "d", name: "laptop", owner: { kind: "member", member: "m", name: "M" } }, item: null, eligibility: { canApprove: false, canDeny: true, canReadAskDetail: false, deciders: [], reason: null } }
 for (const status of ["pending", "approved", "denied", "expired", "used", "ended", "revoked", "stale"]) expect(WorkspaceApprovalStopViewSchema.safeParse({ ...stop, status }).success).toBe(true)
 for (const status of ["pending", "approved", "denied", "expired", "cancelled", "stale"]) expect(WorkspacePolicyProposalStopViewSchema.safeParse({ ...stop, status }).success).toBe(true)
 for (const status of ["ended", "cancelled"]) expect(MinimalStopViewSchema.safeParse({ ...stop, status }).success).toBe(true)
 expect(WorkspaceApprovalStopViewSchema.safeParse({ ...stop, status: "cancelled" }).success).toBe(false)
 expect(WorkspacePolicyProposalStopViewSchema.safeParse({ ...stop, status: "ended" }).success).toBe(false)
 expect(MinimalStopViewSchema.safeParse({ ...stop, status: "unknown" }).success).toBe(false)
})
test("notice kind literals include protection_changed and refuse the obsolete spelling", () => {
 const workspace = { id: "tn_a", slug: "alex", name: "Personal" }
 const at = "2027-01-01T00:00:00.000Z"
 const notices: WorkspaceNoticePayload[] = [
  { kind: "machine_added", workspace, device: "d", name: "machine", owner: { kind: "member", member: "m", name: "M" }, place: null, at },
  { kind: "protection_changed", workspace, project: { id: "p", slug: "project" }, env: "prod", changes: ["fence_added"], by: "m", at },
  { kind: "owner_changed", workspace, member: "m", name: "M", change: "promoted", by: "m", at },
  { kind: "member_joined", workspace, member: "m", name: "M", role: "member", by: "i", at },
  { kind: "deletion_scheduled", workspace, by: "m", at, deleteAfter: at },
  { kind: "rotation_required", workspace, projects: [], items: [], by: "m", at },
 ]
 for (const notice of notices) expect(WorkspaceNoticePayloadSchema.parse(notice)).toEqual(notice)
 expect(WorkspaceNoticePayloadSchema.safeParse({ ...notices[1], kind: "protection_loosened" }).success).toBe(false)
 expect(WorkspaceEnrolViewSchema).toBeDefined()
})
test("error extras are bound to their error codes", () => {
 const transition = { id: "tr", reservedEpoch: 1, targets: 1, acknowledged: 0, state: "pending" as const }
 for (const error of ["forbidden", "account_pending", "approval_required", "conflict"] as const) {
  const base: ApiError = { error, message: "refused" }
  expect(apiErrorExtrasValid(base)).toBe(true)
  expect(apiErrorExtrasValid({ ...base, deciders: [] })).toBe(error === "approval_required")
  expect(apiErrorExtrasValid({ ...base, transition })).toBe(error === "account_pending")
  expect(apiErrorExtrasValid({ ...base, refused: [{ ref: "a017", reason: "name not available" }] })).toBe(error === "conflict")
  expect(apiErrorExtrasValid({ ...base, ruleRefused: "rule.send" })).toBe(error === "forbidden")
  expect(apiErrorExtrasValid({ ...base, dialRefused: "protected" })).toBe(error === "forbidden")
  expect(apiErrorExtrasValid({ ...base, deciders: [], transition })).toBe(false)
 }
})

test("account security notices carry only this workspace and the affected account", () => {
  const event = { kind: "account_security", workspace: { id: "tn_workspace", slug: "work", name: "Work" }, account: "acc_subject", name: "Sam", event: "recovery", at: "2026-10-27T12:00:00.000Z", client: "Browser", place: "Amsterdam", restrictedUntil: "2026-10-28T12:00:00.000Z" }
  expect(WorkspaceNoticePayloadSchema.safeParse(event).success).toBe(true)
  expect(WorkspaceNoticePayloadSchema.safeParse({ ...event, event: "break-glass" }).success).toBe(true)
  expect(WorkspaceNoticePayloadSchema.safeParse({ ...event, workspaces: ["foreign"] }).success).toBe(false)
  expect(WorkspaceNoticePayloadSchema.safeParse({ ...event, event: "signin" }).success).toBe(false)
})

test("pending restrictions round-trip without being coerced into dates", async () => {
  const { PENDING_RESTRICTION_UNTIL, AccountRestrictionSchema } = await import("./workspace.ts")
  const pending = { reason: "recovery" as const, until: PENDING_RESTRICTION_UNTIL, notice: "ntc_pending" }
  expect(PENDING_RESTRICTION_UNTIL).toBe(Number.MAX_SAFE_INTEGER)
  expect(AccountRestrictionSchema.parse(JSON.parse(JSON.stringify(pending)))).toEqual(pending)
})

test("workspace approval bindings are detail-only and contain no raw snapshot", async () => {
  const { WorkspaceApprovalBindingSchema, WorkspaceApprovalStopViewSchema } = await import("./workspace.ts")
  const binding = { snapshotDigest: "snapshot-digest", presentationDigest: "presentation-digest" }
  expect(WorkspaceApprovalBindingSchema.parse(binding)).toEqual(binding)
  expect(WorkspaceApprovalBindingSchema.safeParse({ ...binding, snapshot: { private: "hidden" } }).success).toBe(false)
  const stop = { view: "stop", id: "apr_one", workspace: { id: "tn_work", slug: "work", name: "Work" }, machine: { device: "dev_one", name: "Laptop", owner: { kind: "member", member: "mem_one", name: "Sam" } }, item: null, status: "pending", eligibility: { canApprove: false, canDeny: true, canReadAskDetail: false, deciders: [], reason: null } }
  expect(WorkspaceApprovalStopViewSchema.safeParse(stop).success).toBe(true)
  expect(WorkspaceApprovalStopViewSchema.safeParse({ ...stop, binding }).success).toBe(false)
})

test("public evidence and proposal views cannot relax stored security evidence", async () => {
  const { WorkspaceEnrolEvidenceViewSchema, RescopeProposalViewSchema } = await import("./workspace.ts")
  expect(WorkspaceEnrolEvidenceViewSchema.parse({ name: "A manager", at: "2026-10-27T12:00:00.000Z" })).toEqual({ name: "A manager", at: "2026-10-27T12:00:00.000Z" })
  expect(WorkspaceEnrolEvidenceViewSchema.safeParse({ name: "A manager", at: "2026-10-27T12:00:00.000Z", account: "acc_hidden" }).success).toBe(false)
  const proposal = { id: "r", device: "d", thumbprint: "key", before: complete, after: complete, beforeDigest: "b", afterDigest: "a", proposer: { member: "m", name: "M" }, requiredSigners: [{ name: "A manager", as: "admission" }], signedBy: [], expiresAt: "2027-01-01T00:00:00.000Z", state: "open" }
  expect(RescopeProposalViewSchema.safeParse(proposal).success).toBe(true)
  expect(DeviceRescopeProposalSchema.safeParse({ ...proposal, owner: { kind: "member", member: "m", name: "M" }, deviceRevision: 1, ownerRevision: 1, scopeRevision: 1, signatures: [] }).success).toBe(false)
})

test("account sessions require an explicit current-recovery setup warning",async () => {
  const { AccountSessionSchema } = await import("./workspace.ts"),base = { canCreateWorkspaces: false,workspaceCreation: "default",account: "acc_fixture",name: "Fixture",securityEpoch: 0,pendingTransition: null,restricted: null,memberships: [] }
  expect(AccountSessionSchema.safeParse(base).success).toBe(false)
  expect(AccountSessionSchema.parse({ ...base,recoverySetupRequired: true }).recoverySetupRequired).toBe(true)
  expect(AccountSessionSchema.parse({ ...base,recoverySetupRequired: false }).recoverySetupRequired).toBe(false)
})


test("requires creator permission and where it comes from, and accepts an open-ended pending restriction", async () => {
  const { AccountSessionSchema } = await import("./workspace.ts")
  const session = { account: "acc_one", name: "One", canCreateWorkspaces: false, workspaceCreation: "operator-denied" as const, recoverySetupRequired: false, securityEpoch: 0, pendingTransition: null, restricted: { reason: "recovery" as const, until: null, notice: "ntc_one" }, memberships: [] }
  expect(AccountSessionSchema.parse(session)).toEqual(session)
  const { canCreateWorkspaces: _permission, ...missing } = session
  expect(AccountSessionSchema.safeParse(missing).success).toBe(false)
  const { workspaceCreation: _source, ...unsourced } = session
  expect(AccountSessionSchema.safeParse(unsourced).success).toBe(false)
  expect(AccountSessionSchema.safeParse({ ...session, workspaceCreation: "operator" }).success).toBe(false)
})

test("requires a nullable enrolment start context in device views", async () => {
  const { WorkspaceDeviceViewSchema } = await import("./workspace.ts")
  expect(WorkspaceDeviceViewSchema.shape.start.parse(null)).toBeNull()
  const start = { at: "2026-10-27T20:00:00.000Z", place: "Amsterdam", clientLabel: "Terminal" }
  expect(WorkspaceDeviceViewSchema.shape.start.parse(start)).toEqual(start)
  expect(WorkspaceDeviceViewSchema.shape.start.safeParse(undefined).success).toBe(false)
})

test("keeps workspace audit stored bytes, cursor and verification strict", async () => {
  const { WorkspaceAuditPageSchema, WORKSPACE_AUDIT_PATH } = await import("./workspace.ts")
  const page = { events: [{ seq: 3, at: 1, actor: "member:mem_one", action: "item.read", target: null, detail: '{"unchanged":true}', prev: "previous", hash: "original" }], head: { seq: 4, hash: "head" }, verified: true, filtered: true, next: "3" }
  expect(WORKSPACE_AUDIT_PATH).toBe("/api/w/:ws/audit")
  expect(WorkspaceAuditPageSchema.parse(page)).toEqual(page)
  expect(WorkspaceAuditPageSchema.safeParse({ ...page, next: "garbage" }).success).toBe(false)
  expect(WorkspaceAuditPageSchema.safeParse({ ...page, events: [{ ...page.events[0], detail: {} }] }).success).toBe(false)
})

import { MembershipViewSchema, WorkspaceEnrolStartSchema, WorkspaceNoticeSchema, WorkspaceSettingsViewSchema, type MembershipView, type WorkspaceDeviceScope, type WorkspaceEnrolStatus, type WorkspaceEnrolView, type WorkspaceNotice, type WorkspaceSettingsView } from "./workspace.ts"
import type { z } from "zod"
import { fingerprintWords } from "./fingerprint.ts"
describe("enrolment, membership and settings shapes after the cutover", () => {
 const at = "2027-01-01T00:00:00.000Z"
 const workspace = { id: "tn_a", slug: "alex", name: "Personal" }
 const deviceScope: WorkspaceDeviceScope = { tags: [], projects: [], modes: ["relay"], maxEnvironment: "unprotected", privateCredentials: false }
 const view: WorkspaceEnrolView = { workspace, enrolment: "enr_1", ref: "K7QX29PD", code: "K7QX29PD", name: "laptop", host: null, backend: "software", start: { at, place: null, clientLabel: "mehen 0.3.0" }, acceptorPlace: null, requestedOwner: { kind: "self" }, owner: null, scope: deviceScope, digest: "d", fingerprint: { groups: ["7KQ2", "X9PD", "M4TR"], hidden: 2, check: "c", words: fingerprintWords("A".repeat(43)) }, state: "pending_owner_acceptance", actions: ["accept", "reject"], expiresAt: at, hardExpiresAt: at, lease: "live", claimed: null, reason: null, successor: null }
 test("the enrolment view needs ref and every lease field; code is the code form's only", () => {
  expect(WorkspaceEnrolViewSchema.parse(view)).toEqual(view)
  const { code: _code, ...idForm } = { ...view, ref: "enr_1" }
  expect(WorkspaceEnrolViewSchema.parse(idForm)).toEqual(idForm)
  const { ref: _ref, ...noRef } = view
  expect(WorkspaceEnrolViewSchema.safeParse(noRef).success).toBe(false)
  // The cutover: a view without any one of the lease fields is refused.
  for (const field of ["hardExpiresAt", "lease", "claimed", "reason", "successor"] as const) {
   const { [field]: _gone, ...without } = view
   expect(WorkspaceEnrolViewSchema.safeParse(without).success).toBe(false)
  }
  const closed: WorkspaceEnrolView = { ...view, state: "expired", actions: [], hardExpiresAt: at, lease: "terminal", claimed: { account: "acc_a", name: "Alex" }, reason: "superseded", successor: { enrolment: "enr_2", expiresAt: at } }
  expect(WorkspaceEnrolViewSchema.parse(closed)).toEqual(closed)
  expect(WorkspaceEnrolViewSchema.parse({ ...closed, claimed: null, reason: null, successor: null }).reason).toBeNull()
  expect(WorkspaceEnrolViewSchema.safeParse({ ...closed, lease: "gone" }).success).toBe(false)
  expect(WorkspaceEnrolViewSchema.safeParse({ ...closed, reason: "stale" }).success).toBe(false)
  expect(WorkspaceEnrolViewSchema.safeParse({ ...closed, successor: { enrolment: "enr_2", expiresAt: at, code: "K7QX29PD" } }).success).toBe(false)
 })
 test("an enrolment start may carry a connect code; the body stays strict", () => {
  const start: z.input<typeof WorkspaceEnrolStartSchema> = { workspace: "alex", owner: { kind: "self" }, name: "laptop", backend: "software", jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" } }
  expect(WorkspaceEnrolStartSchema.parse(start)).toEqual(start)
  expect(WorkspaceEnrolStartSchema.parse({ ...start, connect: "ABCD2345" }).connect).toBe("ABCD2345")
  expect(WorkspaceEnrolStartSchema.safeParse({ ...start, extra: true }).success).toBe(false)
 })
 test("a membership carries no pending count: the field is refused", () => {
  const membership: MembershipView = { workspace, member: "mem_a", role: "owner", pendingRole: null, status: "active" }
  expect(MembershipViewSchema.parse(membership)).toEqual(membership)
  expect(MembershipViewSchema.safeParse({ ...membership, pending: 2 }).success).toBe(false)
  expect(MembershipViewSchema.safeParse({ ...membership, pending: -1 }).success).toBe(false)
 })
 test("the settings read is strict", () => {
  const settings: WorkspaceSettingsView = { frozen: false, rights: { rename: true, freeze: true, unfreeze: false }, approvals: { level: "writes", askLess: true, askMore: true } }
  expect(WorkspaceSettingsViewSchema.parse(settings)).toEqual(settings)
  expect(WorkspaceSettingsViewSchema.safeParse({ ...settings, rights: { ...settings.rights, delete: true } }).success).toBe(false)
  expect(WorkspaceSettingsViewSchema.safeParse({ ...settings, approvals: { ...settings.approvals, level: "never" } }).success).toBe(false)
  const { approvals: _dial, ...off } = settings
  expect(WorkspaceSettingsViewSchema.parse(off)).toEqual(off)
 })
 test("the notice envelope is strict and integer-timed", () => {
  const notice: WorkspaceNotice = { id: "n", account: "acc_a", payload: { kind: "deletion_scheduled", workspace, by: "m", at, deleteAfter: at }, at: 1, url: "https://app.mehen.dev/w/alex/" }
  expect(WorkspaceNoticeSchema.parse(notice)).toEqual(notice)
  expect(WorkspaceNoticeSchema.safeParse({ ...notice, at: 1.5 }).success).toBe(false)
 })
 test("a poll answer carries hardExpiresAt and reason; a terminal renew refusal carries the full poll answer", () => {
  const answers: WorkspaceEnrolStatus[] = [{ status: "pending_owner_acceptance", expiresAt: at, hardExpiresAt: at }, { status: "expired", reason: "legacy" }, { status: "rejected" }, { status: "pending_admission", expiresAt: at, hardExpiresAt: at }, { status: "expired", reason: "hard_cap" }]
  // @ts-expect-error the cutover: a pending answer names its hard limit
  const noHardLimit: WorkspaceEnrolStatus = { status: "pending_owner_acceptance", expiresAt: at }
  // @ts-expect-error the cutover: an expired answer names its reason
  const noReason: WorkspaceEnrolStatus = { status: "expired" }
  expect([noHardLimit, noReason]).toHaveLength(2)
  const active: WorkspaceEnrolStatus = { status: "active", tenant: "tn_a", workspace, device: "dev_1", scope: deviceScope, owner: { kind: "member", member: "m", name: "M" } }
  const refusal: ApiError = { error: "conflict", message: "settled", enrolment: active }
  expect(answers).toHaveLength(5)
  expect(refusal.enrolment?.status === "active" ? refusal.enrolment.device : null).toBe("dev_1")
 })
})

import { APPROVAL_BATCH_MAX, ApprovalBatchEntrySchema, ApprovalGroupStopRowSchema } from "./workspace.ts"
describe("approval.decide_many", () => {
 const entry = (n: number, decision: "approve" | "deny" = "approve") => ({ approval: `apr_${String(n).padStart(3, "0")}`, digest: "d", decision, uses: 1, ttlSeconds: 3600 })
 const many = (entries: unknown[]) => WorkspaceStepUpActionSchema.safeParse({ type: "approval.decide_many", entries })
 test("signs 1 to 25 entries, sorted by approval id, each once", () => {
  expect(APPROVAL_BATCH_MAX).toBe(25)
  expect(many([entry(1)]).success).toBe(true)
  expect(many(Array.from({ length: 25 }, (_, i) => entry(i))).success).toBe(true)
  expect(many([]).success).toBe(false)
  expect(many(Array.from({ length: 26 }, (_, i) => entry(i))).success).toBe(false)
  expect(many([entry(2), entry(1)]).success).toBe(false)
  expect(many([entry(1), entry(1, "deny")]).success).toBe(false)
  expect(many([entry(1), entry(2, "deny")]).success).toBe(true)
 })
 test("an entry is strict: no remember, no other field, and the limits approval.decide signs", () => {
  expect(ApprovalBatchEntrySchema.safeParse(entry(1)).success).toBe(true)
  expect(ApprovalBatchEntrySchema.safeParse({ ...entry(1), uses: null }).success).toBe(true)
  for (const bad of [{ remember: { kind: "rule" } }, { uses: 0 }, { uses: 101 }, { ttlSeconds: 59 }, { ttlSeconds: 86_401 }, { decision: "maybe" }]) expect(ApprovalBatchEntrySchema.safeParse({ ...entry(1), ...bad }).success).toBe(false)
 })
 test("a superseded ask has its own stop status", () => {
  const stop = { view: "stop", id: "apr_1", workspace: { id: "w", slug: "alex", name: "Personal" }, machine: { device: "d", name: "laptop", owner: { kind: "member", member: "m", name: "M" } }, item: null, status: "superseded", eligibility: { canApprove: false, canDeny: true, canReadAskDetail: false, deciders: [], reason: null } }
  expect(WorkspaceApprovalStopViewSchema.safeParse(stop).success).toBe(true)
  expect(WorkspacePolicyProposalStopViewSchema.safeParse(stop).success).toBe(false)
 })
 test("a stop row of a group is deny-only or own-page, never routine or floor", () => {
  const stop = { view: "stop", id: "apr_1", workspace: { id: "w", slug: "alex", name: "Personal" }, machine: { device: "d", name: "laptop", owner: { kind: "member", member: "m", name: "M" } }, item: null, status: "pending", eligibility: { canApprove: false, canDeny: true, canReadAskDetail: false, deciders: [], reason: null } }
  for (const batch of ["deny-only", "own-page"]) expect(ApprovalGroupStopRowSchema.safeParse({ view: "stop", stop, batch }).success).toBe(true)
  for (const batch of ["routine", "floor"]) expect(ApprovalGroupStopRowSchema.safeParse({ view: "stop", stop, batch }).success).toBe(false)
  expect(ApprovalGroupStopRowSchema.safeParse({ view: "stop", stop, batch: "own-page", ownPage: "run" }).success).toBe(false)
 })
})
