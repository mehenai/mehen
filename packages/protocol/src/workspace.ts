// Workspace contracts live beside legacy api.ts contracts until ACCESS's final
// cleanup. Workspace prefixes remain permanently, including after legacy removal.
// Views use ISO timestamps. Stored security evidence uses Unix milliseconds.
import { z } from "zod"
import { PolicyRememberSchema, PostureLevelSchema } from "./policy-mode.ts"
import { FINGERPRINT_COLOURS } from "./fingerprint-words.ts"
import { MandateClassSchema, MandateIdSchema } from "./mandate-terms.ts"

export const WorkspaceRoleSchema = z.enum(["owner", "admin", "member", "guest"])
export type WorkspaceRole = z.infer<typeof WorkspaceRoleSchema>
export const ProjectLevelSchema = z.enum(["use", "edit", "manage"])
export type ProjectLevel = z.infer<typeof ProjectLevelSchema>
export const WorkspaceSlugSchema = z.string().regex(/^[a-z][a-z0-9-]{1,38}[a-z0-9]$/).refine((s) => !s.includes("--") && !s.startsWith("legacy-"))
export const RESERVED_WORKSPACE_SLUGS = ["api", "app", "auth", "w", "workspaces", "account", "admin", "operator", "mehen", "settings", "signin", "signup", "recover", "docs", "assets", "oauth", "v1", "well-known"] as const
export function normaliseWorkspaceSlug(value: string): string { return value.trim().toLowerCase() }
const Id = z.string().min(1).max(128)
const Iso = z.iso.datetime()
const FingerprintWordSchema = z.strictObject({ word: z.string(), colour: z.strictObject({ name: z.string(), light: z.string(), dark: z.string() }).refine((v) => FINGERPRINT_COLOURS.some((c) => c.name === v.name && c.light === v.light && c.dark === v.dark)) })
const Ms = z.number().int().nonnegative()
export const WorkspaceRefSchema = z.strictObject({ id: Id, slug: WorkspaceSlugSchema, name: z.string().min(1).max(64) })
export type WorkspaceRef = z.infer<typeof WorkspaceRefSchema>
export const OwnerRefSchema = z.discriminatedUnion("kind", [z.strictObject({ kind: z.literal("member"), member: Id, name: z.string() }), z.strictObject({ kind: z.literal("team"), team: Id, name: z.string() })])
export type OwnerRef = z.infer<typeof OwnerRefSchema>
export const CredentialHomeSchema = z.discriminatedUnion("kind", [z.strictObject({ kind: z.literal("workspace") }), z.strictObject({ kind: z.literal("project"), project: Id }), z.strictObject({ kind: z.literal("member"), member: Id })])
export type CredentialHome = z.infer<typeof CredentialHomeSchema>
export const ItemUseContextSchema = z.strictObject({ project: Id, environment: z.string().min(1).max(32) })
export type ItemUseContext = z.infer<typeof ItemUseContextSchema>
export const ShareSubjectSchema = z.discriminatedUnion("kind", [z.strictObject({ kind: z.literal("member"), member: Id }), z.strictObject({ kind: z.literal("team"), team: Id })])
export type ShareSubject = z.infer<typeof ShareSubjectSchema>
export const ShareTermsSchema = z.strictObject({ level: ProjectLevelSchema, protected: z.boolean(), expiresAt: Iso.nullable() })
export const ShareSchema = ShareTermsSchema.extend({ id: Id, project: Id, subject: ShareSubjectSchema })
export type Share = z.infer<typeof ShareSchema>
export const AccessSourceSchema = z.discriminatedUnion("kind", [z.strictObject({ kind: z.literal("role"), role: WorkspaceRoleSchema }), z.strictObject({ kind: z.literal("share"), share: ShareSchema, via: ShareSubjectSchema })])
export type AccessSource = z.infer<typeof AccessSourceSchema>
// level is the unprotected projection ONLY. Never OR ticks onto a max level.
export const EffectiveAccessSchema = z.strictObject({ level: ProjectLevelSchema.nullable(), runProtected: z.boolean(), editProtected: z.boolean(), sources: z.array(AccessSourceSchema) })
export type EffectiveAccess = z.infer<typeof EffectiveAccessSchema>
// How often Mehen asks a person in a workspace (the approval dial), from
// more asks to fewer: writes (Ask on writes, the default) and work (Let it
// work). Moving to work asks less.
export const APPROVAL_DIALS = ["writes", "work"] as const
export const ApprovalDialSchema = z.enum(APPROVAL_DIALS)
export type ApprovalDial = z.infer<typeof ApprovalDialSchema>
export const DEFAULT_APPROVAL_DIAL: ApprovalDial = "writes"
export function approvalDialAsksLess(before: ApprovalDial, after: ApprovalDial): boolean {
  return APPROVAL_DIALS.indexOf(after) > APPROVAL_DIALS.indexOf(before)
}
// Why Let it work refused a held request instead of asking: a protected
// environment, a machine trust does not reach, a service nobody reviewed,
// a request trust does not cover, or the floor's own reason.
export type ApprovalDialRefusal = "protected" | "machine" | "unreviewed" | "not-covered" | import("./policy-mode.ts").PolicyRuleRefusal
export const DeviceTagSchema = z.string().regex(/^[a-z0-9][a-z0-9:_-]{0,39}$/)
export const DeviceModeSchema = z.enum(["relay", "sign", "mint", "placeholder", "fill", "lease"])
// workloads: "allowed" (also when absent, as every device before workloads)
// lets the device act with its own key and through workloads it creates;
// "required" lets its own key only read and manage workloads, so every use,
// ask and run carries a workload. "required" is the narrower of the two.
// serviceRuns: true lets the device start service runs (mehen run --service),
// which renew with no maximum life; absent means false. Only a human widens
// a scope to it.
export const DeviceWorkloadsSchema = z.enum(["allowed", "required"])
export const WorkspaceDeviceScopeSchema = z.strictObject({ tags: z.array(DeviceTagSchema).max(32), projects: z.array(z.string().min(1).max(64)).max(32), maxEnvironment: z.enum(["unprotected", "protected"]), modes: z.array(DeviceModeSchema).min(1).max(6), privateCredentials: z.boolean(), workloads: DeviceWorkloadsSchema.optional(), serviceRuns: z.boolean().optional() })
export type WorkspaceDeviceScope = z.infer<typeof WorkspaceDeviceScopeSchema>
export const IdentityRuleSchema = z.strictObject({ provider: z.literal("google"), domains: z.array(z.string().max(253).regex(/^[a-z0-9]+(?:[.-][a-z0-9]+)*\.[a-z]{2,}$/)).min(1).max(5), roles: z.array(WorkspaceRoleSchema).min(1).max(4) }).nullable()
export type IdentityRule = z.infer<typeof IdentityRuleSchema>
export const EligibilitySchema = z.strictObject({ canApprove: z.boolean(), canDeny: z.boolean(), canReadAskDetail: z.boolean(), deciders: z.array(z.string()), reason: z.string().nullable() }).refine((v) => !v.canApprove || v.canReadAskDetail, "Cannot approve blind")
export type Eligibility = z.infer<typeof EligibilitySchema>
export const MembershipViewSchema = z.strictObject({ workspace: WorkspaceRefSchema, member: Id, role: WorkspaceRoleSchema, pendingRole: WorkspaceRoleSchema.nullable(), status: z.enum(["unconfirmed", "active", "suspended"]) })
export type MembershipView = z.infer<typeof MembershipViewSchema>
export const WorkspaceMemberViewSchema = z.strictObject({ member: Id, name: z.string(), role: WorkspaceRoleSchema, pendingRole: WorkspaceRoleSchema.nullable(), status: z.enum(["unconfirmed", "active", "suspended"]), teams: z.array(Id), machines: z.number().int().nonnegative(), joinedAt: Iso })
export type WorkspaceMemberView = z.infer<typeof WorkspaceMemberViewSchema>
export const INVITE_TTL_MS = 7 * 86_400_000
// onJoin: what redeeming does. "activate" makes the member active once the
// invited email is proved; "confirm" waits for an owner or admin. Terms
// signed before onJoin existed have none and wait (inviteJoinsStraightAway).
export const InviteOnJoinSchema = z.enum(["activate", "confirm"])
export type InviteOnJoin = z.infer<typeof InviteOnJoinSchema>
export const InviteTermsSchema = z.strictObject({ role: WorkspaceRoleSchema, email: z.email().max(254).nullable(), teams: z.array(Id), shares: z.array(ShareTermsSchema.extend({ project: Id })), expiresAt: Iso, onJoin: InviteOnJoinSchema.optional() }).refine((v) => v.role === "guest" ? v.teams.length === 0 && v.shares.length > 0 && v.shares.every((s) => s.level !== "manage") : v.email !== null, "Invalid role-specific invite terms").refine((v) => v.email === null || v.email === v.email.trim().toLowerCase(), "Email must be canonical")
export type InviteTerms = z.infer<typeof InviteTermsSchema>
// POST /api/w/:ws/invites, beside its step-up. email: whether the vault
// emails the link to the invitation's own address as it makes it; an open
// link has no address, so asking for one is refused. The answer always
// carries the link, and `emailed` says what became of the email.
export const InviteCreateSchema = z.strictObject({ terms: InviteTermsSchema, email: z.boolean().default(false) })
export const InviteEmailedSchema = z.enum(["sent", "not_requested", "limited", "failed"])
export type InviteEmailed = z.infer<typeof InviteEmailedSchema>
// Only an email-bound invitation below owner may let its member in without
// a confirmation: an open link admits whoever holds it, and an owner can
// delete and export everything.
export function inviteMayActivate(terms: Pick<InviteTerms, "role" | "email">): boolean {
  return terms.role !== "owner" && terms.email !== null
}
export function inviteJoinsStraightAway(terms: Pick<InviteTerms, "role" | "email" | "onJoin">): boolean {
  return terms.onJoin === "activate" && inviteMayActivate(terms)
}
export const TeamViewSchema = z.strictObject({ id: Id, slug: z.string().regex(/^[a-z][a-z0-9-]{1,30}[a-z0-9]$/), name: z.string(), members: z.array(z.strictObject({ member: Id, name: z.string(), role: z.literal("member") })), shares: z.array(ShareSchema), machines: z.number().int().nonnegative() })
export type TeamView = z.infer<typeof TeamViewSchema>
export const AccountSecurityTransitionViewSchema = z.strictObject({ id: Id, reservedEpoch: Ms, targets: Ms, acknowledged: Ms, state: z.literal("pending") })
export type AccountSecurityTransitionView = z.infer<typeof AccountSecurityTransitionViewSchema>
/** restricted until the pending security transition commits; never render as a date */
export const PENDING_RESTRICTION_UNTIL = Number.MAX_SAFE_INTEGER
export const AccountRestrictionSchema = z.strictObject({ reason: z.enum(["recovery", "reset", "break-glass"]), until: Ms, notice: Id })
export type AccountRestriction = z.infer<typeof AccountRestrictionSchema>
export const PendingAccountSecuritySchema = z.strictObject({ transitionId: Id, reservedEpoch: Ms, revokedSessionIds: z.array(Id), removedFactorIds: z.array(Id), restriction: AccountRestrictionSchema.nullable() })
export type PendingAccountSecurity = z.infer<typeof PendingAccountSecuritySchema>
export const AccountSecurityStateSchema = z.strictObject({ account: Id, installedEpoch: Ms, restriction: AccountRestrictionSchema.nullable(), revokedSessionIds: z.array(Id), removedFactorIds: z.array(Id), deleting: z.boolean(), pending: PendingAccountSecuritySchema.nullable() })
export type AccountSecurityState = z.infer<typeof AccountSecurityStateSchema>
export const ACCOUNT_PENDING_SAFE_OPERATIONS = ["metadata.read", "narrow", "freeze", "deny", "device.revoke"] as const
export const AccountSecurityTransitionSchema = z.strictObject({ id: Id, account: Id, committedEpoch: Ms, pending: PendingAccountSecuritySchema, kind: z.enum(["factor.remove", "sessions.end", "recovery.start", "recovery.cancel", "break-glass", "account.delete", "identity.unlink"]), targets: z.array(z.strictObject({ workspace: Id, membership: Id, state: z.enum(["joining", "member"]) })), acknowledged: z.array(z.strictObject({ workspace: Id, reservedEpoch: Ms, at: Ms })), state: z.literal("pending"), createdAt: Ms, updatedAt: Ms, committedAt: Ms.nullable(), commitDelivery: z.array(z.strictObject({ workspace: Id, epoch: Ms, acknowledgedAt: Ms.nullable(), retryAt: Ms, attempts: Ms })) }).refine((v) => v.pending.transitionId === v.id && v.pending.reservedEpoch > v.committedEpoch)
/** Reserve R only on pending, never advance committed C before every indexed
 * target (including joining) acknowledges the latest R. Merge tightenings by
 * unioning revocations, strictest restriction and a newer R; invalidate old
 * acknowledgements. Install C monotonically and pending only at equal/newer R;
 * retain revoked ids forever. A commit/call E raises the installed floor and
 * clears pending only when E >= its R. Delayed commits never clear newer guards.
 * Prior epochs below the floor refuse. Until commit is observed, surviving
 * prior-epoch sessions/factors get ONLY ACCOUNT_PENDING_SAFE_OPERATIONS, never
 * secret/lease/relay/approval/widening. After observation they refuse entirely.
 * Recovery cancel installs revocations while restricted, then atomically deletes
 * recovered factors/sessions, revokes codes and clears restriction in D1; only
 * the clear propagates lazily. Keep/time expiry do not change epochs or revoke
 * evidence. Unavailable targets remain pending, with no timeout bypass. Already
 * committed operations, authorised sends and leased values cannot be recalled.
 */
export type AccountSecurityTransition = z.infer<typeof AccountSecurityTransitionSchema>
// The deployment's rule for an account the operator has not decided on
// (WORKSPACE_CREATION): "accounts" lets it create workspaces, "operator"
// needs the operator's allow-workspaces first.
export const WorkspaceCreationDefaultSchema = z.enum(["accounts", "operator"])
export type WorkspaceCreationDefault = z.infer<typeof WorkspaceCreationDefaultSchema>
// Where an account's permission to create workspaces comes from: the
// deployment default, or the operator's allow-workspaces or deny-workspaces.
export const WorkspaceCreationSourceSchema = z.enum(["default", "operator-allowed", "operator-denied"])
export type WorkspaceCreationSource = z.infer<typeof WorkspaceCreationSourceSchema>
export const AccountSessionSchema = z.strictObject({ account: Id, name: z.string(), canCreateWorkspaces: z.boolean(), workspaceCreation: WorkspaceCreationSourceSchema, recoverySetupRequired: z.boolean(), securityEpoch: Ms, pendingTransition: AccountSecurityTransitionViewSchema.nullable(), restricted: z.strictObject({ reason: z.enum(["recovery", "reset", "break-glass"]), until: Iso.nullable(), notice: Id }).nullable(), memberships: z.array(MembershipViewSchema) })
export type AccountSession = z.infer<typeof AccountSessionSchema>
export const EnrolStartContextSchema = z.strictObject({ at: Iso, place: z.string().nullable(), clientLabel: z.string().max(120) })
export type EnrolStartContext = z.infer<typeof EnrolStartContextSchema>
export const EnrolOwnerIntentSchema = z.discriminatedUnion("kind", [z.strictObject({ kind: z.literal("self") }), z.strictObject({ kind: z.literal("team"), team: Id })])
// What a machine asks for at enrolment. Every field can only narrow what an
// enrolment gets without it; the page shows the result and the acceptor's
// passkey signs it with the rest of the scope.
export const EnrolRequestedScopeSchema = z.strictObject({ tags: z.array(DeviceTagSchema).min(1).max(32).optional(), projects: z.array(z.string().min(1).max(64)).min(1).max(32).optional(), modes: z.array(DeviceModeSchema).min(1).max(6).optional(), privateCredentials: z.literal(false).optional(), workloads: DeviceWorkloadsSchema.optional() })
export type EnrolRequestedScope = z.infer<typeof EnrolRequestedScopeSchema>
export const WorkspaceEnrolStartSchema = z.strictObject({ workspace: WorkspaceSlugSchema, owner: EnrolOwnerIntentSchema, name: z.string().min(1).max(64), backend: z.enum(["secure-enclave", "software"]), jwk: z.strictObject({ kty: z.literal("EC"), crv: z.literal("P-256"), x: z.string(), y: z.string() }), host: z.string().max(253).optional(), connect: z.string().optional(), scope: EnrolRequestedScopeSchema.optional() })
export const EnrolAcceptanceSubjectSchema = z.strictObject({ workspace: Id, enrolment: Id, thumbprint: z.string(), account: Id, member: Id, scope: WorkspaceDeviceScopeSchema, start: EnrolStartContextSchema })
export type EnrolAcceptanceSubject = z.infer<typeof EnrolAcceptanceSubjectSchema>
const EnrolExpiredReasonSchema = z.enum(["hard_cap", "superseded", "discarded", "source", "legacy"])
export type EnrolExpiredReason = z.infer<typeof EnrolExpiredReasonSchema>
// ref is what the page was opened with: the code on the code form, the enr_
// id on the id form. code is present on the code form only.
export const WorkspaceEnrolViewSchema = z.strictObject({ workspace: WorkspaceRefSchema, enrolment: Id, ref: z.string(), code: z.string().optional(), name: z.string(), host: z.string().nullable(), backend: z.enum(["secure-enclave", "software"]), start: EnrolStartContextSchema, acceptorPlace: z.string().nullable(), acceptorLocal: z.literal(true).optional(), startedByAgent: z.literal(true).optional(), requestedOwner: z.discriminatedUnion("kind", [z.strictObject({ kind: z.literal("self") }), z.strictObject({ kind: z.literal("team"), team: Id, name: z.string() })]), owner: OwnerRefSchema.nullable(), scope: WorkspaceDeviceScopeSchema, digest: z.string(), fingerprint: z.strictObject({ groups: z.tuple([z.string(), z.string(), z.string()]), hidden: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]), check: z.string(), words: z.array(FingerprintWordSchema) }), state: z.enum(["pending_owner_acceptance", "pending_admission", "active", "rejected", "expired"]), actions: z.array(z.enum(["accept", "admit", "reject"])), expiresAt: Iso, hardExpiresAt: Iso, lease: z.enum(["live", "lapsed", "terminal"]), claimed: z.strictObject({ account: Id, name: z.string() }).nullable(), reason: EnrolExpiredReasonSchema.nullable(), successor: z.strictObject({ enrolment: Id, expiresAt: Iso }).nullable(), requested: EnrolRequestedScopeSchema.optional() })
export type WorkspaceEnrolView = z.infer<typeof WorkspaceEnrolViewSchema>
export const EnrolEvidenceSchema = z.strictObject({ account: Id, member: Id, digest: z.string(), ruleRevision: Ms, gateGeneration: Ms, identityCheck: Id.nullable(), at: Iso })
export const WorkspaceEnrolEvidenceViewSchema = z.union([EnrolEvidenceSchema, z.strictObject({ name: z.string(), at: Iso })])
export type WorkspaceEnrolEvidenceView = z.infer<typeof WorkspaceEnrolEvidenceViewSchema>
const RescopeRequiredSignerSchema = z.strictObject({ account: Id, name: z.string(), as: z.enum(["owner_acceptance", "admission"]) })
export const RescopeProposalViewSchema = z.strictObject({ id: Id, device: Id, thumbprint: z.string(), before: WorkspaceDeviceScopeSchema, after: WorkspaceDeviceScopeSchema, beforeDigest: z.string(), afterDigest: z.string(), proposer: z.strictObject({ member: Id, name: z.string() }), requiredSigners: z.array(RescopeRequiredSignerSchema.partial({ account: true })).min(1), signedBy: z.array(Id), expiresAt: Iso, state: z.enum(["open", "committed", "expired", "void", "rejected"]) })
export type RescopeProposalView = z.infer<typeof RescopeProposalViewSchema>
// POST /api/w/:ws/devices/:id/rescope-reject { proposal, project?, stepUp } ->
// RescopeProposalView with state "rejected". Ends an open proposal without
// touching the machine's scope; a required signer who may accept or admit it
// may reject it. Rejecting an already rejected proposal returns the same view.
export const RescopeRejectRequestSchema = z.strictObject({ proposal: Id, project: Id.optional() })
export type RescopeRejectRequest = z.infer<typeof RescopeRejectRequestSchema>
export type RescopeRejectResponse = RescopeProposalView
// Stored proposals additionally bind every authority revision and exact evidence.
export const DeviceRescopeProposalSchema = RescopeProposalViewSchema.extend({ requiredSigners: z.array(RescopeRequiredSignerSchema).min(1), owner: OwnerRefSchema, deviceRevision: Ms, ownerRevision: Ms, scopeRevision: Ms, signatures: z.array(z.strictObject({ account: Id, as: z.enum(["owner_acceptance", "admission"]), digest: z.string(), factor: Id, identityCheck: Id.nullable(), at: Iso })) })
export type DeviceRescopeProposal = z.infer<typeof DeviceRescopeProposalSchema>
// lastCliVersion: the version the machine's `mehen/<x.y.z>` User-Agent last named; null until one did.
export const WorkspaceDeviceViewSchema = z.strictObject({ start: EnrolStartContextSchema.nullable(), device: Id, name: z.string(), backend: z.string(), host: z.string().nullable(), owner: OwnerRefSchema, scope: WorkspaceDeviceScopeSchema, scopeRevision: Ms, acceptance: WorkspaceEnrolEvidenceViewSchema.nullable(), admission: WorkspaceEnrolEvidenceViewSchema.nullable(), pendingRescope: RescopeProposalViewSchema.nullable(), createdAt: Iso, lastSeenAt: Iso.nullable(), lastCliVersion: z.string().max(64).nullable(), revoked: z.boolean(), revokedAt: Iso.optional(), fingerprintWords: z.array(FingerprintWordSchema) })
export type WorkspaceDeviceView = z.infer<typeof WorkspaceDeviceViewSchema>
// A device actor names the workload when one acted (its label is the machine's words).
// batch: the apb_ id of the approval.decide_many that made this decision.
// How a step-up was confirmed: a passkey ceremony now, or a passkey grace
// window a ceremony opened at provenAt. A graced action's
// audit entries carry it, its private records included.
export const StepUpConfirmationSchema = z.strictObject({ kind: z.enum(["passkey", "grace"]), provenAt: Ms })
export type StepUpConfirmation = z.infer<typeof StepUpConfirmationSchema>
export const PrivateEventSchema = z.strictObject({ action: z.string(), at: Ms, actor: z.discriminatedUnion("kind", [z.strictObject({ kind: z.literal("member"), member: Id }), z.strictObject({ kind: z.literal("device"), device: Id, owner: ShareSubjectSchema, workload: z.strictObject({ id: Id, label: z.string().max(120) }).optional() }), z.strictObject({ kind: z.literal("enrolment"), enrolment: Id, owner: ShareSubjectSchema })]), session: Id.nullable(), item: Id, slug: z.string(), outcome: z.string(), run: Id.nullable(), batch: Id.optional(), confirmation: StepUpConfirmationSchema.optional(), browser: z.strictObject({ origin: z.string().max(300), field: z.string().regex(/^[a-z][a-z0-9_]{0,31}$/) }).optional() })
export type PrivateEvent = z.infer<typeof PrivateEventSchema>
const MinimalStopFields = z.strictObject({ view: z.literal("stop"), id: Id, workspace: WorkspaceRefSchema, machine: z.strictObject({ device: Id, name: z.string(), owner: OwnerRefSchema }), item: z.strictObject({ slug: z.string() }).nullable(), eligibility: EligibilitySchema.refine((v) => !v.canApprove && !v.canReadAskDetail) })
// superseded: a newer ask from the same machine to the same place replaced it.
export const WorkspaceApprovalStopViewSchema = MinimalStopFields.extend({ status: z.enum(["pending", "approved", "denied", "expired", "used", "ended", "revoked", "stale", "superseded"]) })
export const WorkspacePolicyProposalStopViewSchema = MinimalStopFields.extend({ status: z.enum(["pending", "approved", "denied", "expired", "cancelled", "stale"]) })
export const MinimalStopViewSchema = z.union([WorkspaceApprovalStopViewSchema, WorkspacePolicyProposalStopViewSchema])
export type MinimalStopView = z.infer<typeof MinimalStopViewSchema>
export const WorkspaceApprovalBindingSchema = z.strictObject({ snapshotDigest: z.string(), presentationDigest: z.string() })
export type WorkspaceApprovalBinding = z.infer<typeof WorkspaceApprovalBindingSchema>
export type ApprovalViewProjection = { view: "detail"; binding?: WorkspaceApprovalBinding; approval: import("./api.ts").ApprovalView & { workspace: WorkspaceRef; owner: OwnerRef; eligibility: Eligibility } } | z.infer<typeof WorkspaceApprovalStopViewSchema>
// Review together (GET /api/w/:ws/approvals/groups/:id): the pending asks of
// one review group (grp_, one machine, workload and credential) or one
// bundle (bnd_), decided under one passkey as approval.decide_many.
export type ApprovalDetail = Extract<ApprovalViewProjection, { view: "detail" }>["approval"]
export type WorkspaceApprovalStopView = z.infer<typeof WorkspaceApprovalStopViewSchema>
// routine starts ticked; floor starts unticked with its request open;
// deny-only may only be denied; own-page cannot be ticked at all.
export type ApprovalBatchState = "routine" | "floor" | "deny-only" | "own-page"
export type ApprovalOwnPageReason = "run" | "four-eyes" | "warning" | "unbound"
  // push: a push is decided on its own page, where it is sent.
  | "push"
// protected: a protected credential's relay use (ruling B2), batchable but
// state "floor" so it never starts ticked; the page marks it Protected.
// newerSameShape: the newest pending row of this view with the same stored
// shape, when that is another row (ruling B1); null on the newest and on a
// row of its own shape. Both optional for older readers; the vault sends them.
// A row the viewer may not read: own-page for a run, four-eyes or push ask,
// which a batch never decides, deny-only otherwise. It says no more than that.
export const ApprovalGroupStopRowSchema = z.strictObject({ view: z.literal("stop"), stop: WorkspaceApprovalStopViewSchema, batch: z.enum(["deny-only", "own-page"]) })
export type ApprovalGroupRow =
  | { view: "detail"; approval: ApprovalDetail; binding: WorkspaceApprovalBinding; batch: ApprovalBatchState; ownPage: ApprovalOwnPageReason | null; floor: import("./policy-mode.ts").PolicyFloorView["reason"][]; createdAt: string; replacedBy: string | null; protected?: boolean; newerSameShape?: string | null }
  | z.infer<typeof ApprovalGroupStopRowSchema>
// rows: pending oldest first, then those settled in the last hour. reason:
// a bundle's reason, the agent's words, unverified.
export type ApprovalGroupView = {
  group: string
  kind: "machine" | "bundle"
  workspace: WorkspaceRef
  machine: { device: string; name: string; owner: OwnerRef; workload: { id: string; label: string } | null }
  item: { slug: string } | null
  reason: string | null
  rows: ApprovalGroupRow[]
}
export type ApprovalBatchOutcome = "approved" | "denied" | "expired" | "decided" | "superseded" | "stale" | "own_page" | "forbidden" | "changed"
// batch: the apb_ id the audit rows of this decision share.
export type ApprovalBatchResult = { batch: string; results: { approval: string; outcome: ApprovalBatchOutcome; message: string }[]; approved: number; denied: number; skipped: number }
export type PolicyProposalViewProjection = { view: "detail"; proposal: import("./policy-mode.ts").PolicyProposalView & { workspace: WorkspaceRef; owner: OwnerRef; eligibility: Eligibility } } | z.infer<typeof WorkspacePolicyProposalStopViewSchema>
// GET /api/w/<slug>/policy/proposals/:id for a standing rule's proposal.
export type PolicyRuleProposalViewProjection = { view: "detail"; proposal: import("./policy-mode.ts").PolicyRuleProposalView & { workspace: WorkspaceRef; owner: OwnerRef; eligibility: Eligibility } } | z.infer<typeof WorkspacePolicyProposalStopViewSchema>
// The same read for a task grant's proposal waiting for its co-signer.
export type PolicyAreaProposalViewProjection = { view: "detail"; proposal: import("./policy-mode.ts").PolicyAreaProposalView & { workspace: WorkspaceRef; owner: OwnerRef; eligibility: Eligibility } }
// What that read answers for any standing rule's proposal, either kind.
export type PolicyStandingProposalViewProjection = PolicyRuleProposalViewProjection | PolicyAreaProposalViewProjection
export type WorkspaceApprovalView = ApprovalViewProjection
export type WorkspacePolicyProposalView = PolicyProposalViewProjection
export type WorkspaceMe = Omit<import("./api.ts").Me, "scope"> & { workspace: WorkspaceRef; owner: OwnerRef; displayRev: number; scope: WorkspaceDeviceScope }
export type WorkspaceItemSummary = import("./api.ts").ItemSummary & { home: CredentialHome }
// The value a rotation replaced, kept for ADOPTION_LIMITS.replacedKeptMs and
// restorable with a passkey: names only, never a value, fingerprint or
// length. replacedBy is the member's display name or the machine's name.
export type ItemPreviousVersion = { version: number; replacedAt: string; expiresAt: string; replacedBy: string; fields: string[] }
// previous, pushable and browser: on a person's description only, never a machine's.
// pushable: the item may be put into other services' secret stores.
// browser: the pages a human added for fill (items.browser), only once there are any.
// posture, on a person's description: only to someone who may set it, with
// the machines it is limited to (null: every eligible one), the catalogue
// it was signed at and whether that has grown since (current), who set it
// and the revision a change must name (0 while it was never set).
// eligible: the active machines this person may read, each with the levels
// that would cover it now; a machine no level covers is left out.
export type WorkspaceItemPosture = { level: import("./policy-mode.ts").PostureLevel; machines: { id: string; name: string }[] | null; catalogue: (import("./policy-mode.ts").PostureCatalogue & { current: number }) | null; setBy: string | null; setAt: string | null; rev: number; eligible?: PostureEligibleMachine[] }
export type PostureEligibleMachine = { device: string; name: string; levels: Exclude<import("./policy-mode.ts").PostureLevel, "ask">[] }
export type WorkspaceItemDescription = Omit<import("./api.ts").ItemDescription, "posture"> & { home: CredentialHome; previous?: ItemPreviousVersion | null; pushable?: boolean; browser?: import("./fill.ts").ItemBrowser; posture?: WorkspaceItemPosture }
export type WorkspaceProject = Omit<import("./api.ts").Project, "environments"> & { access: EffectiveAccess; shares?: Share[]; environments: { name: string; protected: boolean; fences: string[]; fourEyes: boolean }[] }
export type WorkspaceRunCreated = import("./api.ts").RunCreated & { overrides: string[]; authorisation: { id: string; context: ItemUseContext; expiresAt: string } | null }
export type WorkspacePendingAsk = { workspace: WorkspaceRef; owner: OwnerRef; view: "stop"; stop: MinimalStopView } | { workspace: WorkspaceRef; owner: OwnerRef; view: "detail"; detail: import("./api.ts").PendingAsk }
export type WorkspaceSecurityNotice = { workspace: WorkspaceRef | null; account: string; notice: string; kind: "recovery" | "reset" | "break-glass" | "identity" | "workspace"; at: string; client: string | null; place: string | null; restrictedUntil: string | null; url: string }
export const ProposedHomeSchema = z.discriminatedUnion("home", [z.strictObject({ home: z.literal("private") }), z.strictObject({ home: z.literal("workspace") }), z.strictObject({ home: z.literal("project"), project: Id })])
export type CredentialCreationContext = { home: CredentialHome; permittedHomes: CredentialHome[]; intent: "create" | "rotate"; target: { item: string; version: number; configRevision: number } | null; client: { item: string; configRevision: number } | null; dependencyRevision: number }
// Added beside legacy schemas: no legacy caller silently acquires a default home.
export type WorkspaceIntakeView = import("./api.ts").IntakeView & CredentialCreationContext
// `tags` are the stored tags the connection will carry, one of the
// connect.start terms the page compares before the passkey.
export type WorkspaceConnectView = import("./api.ts").ConnectView & CredentialCreationContext & { tags: string[] }
// approval.decide_many: each entry as approval.decide would sign it, without
// a remember, sorted by approval id, each once.
export const APPROVAL_BATCH_MAX = 25
export const ApprovalBatchEntrySchema = z.strictObject({ approval: Id, digest: z.string(), decision: z.enum(["approve", "deny"]), uses: z.number().int().min(1).max(100).nullable(), ttlSeconds: z.number().int().min(60).max(86_400) })
export type ApprovalBatchEntry = z.infer<typeof ApprovalBatchEntrySchema>
const Empty = z.strictObject({})
export const WorkspaceStepUpActionSchema = z.discriminatedUnion("type", [
  Empty.extend({ type: z.literal("workspace.unfreeze") }),
  Empty.extend({ type: z.literal("passkey.add") }),
  Empty.extend({ type: z.literal("recovery.generate") }),
  z.strictObject({ type: z.literal("workspace.create"), slug: WorkspaceSlugSchema, name: z.string().min(1).max(64) }),
  z.strictObject({ type: z.literal("workspace.update"), slug: WorkspaceSlugSchema, name: z.string().min(1).max(64) }),
  z.strictObject({ type: z.literal("workspace.identity_rule"), rule: IdentityRuleSchema }),
  z.strictObject({ type: z.literal("workspace.delete"), name: z.string() }),
  z.strictObject({ type: z.literal("workspace.delete_cancel"), name: z.string() }),
  z.strictObject({ type: z.literal("member.invite"), terms: InviteTermsSchema }),
  z.strictObject({ type: z.literal("member.confirm"), member: Id, termsDigest: z.string(), identityRuleRevision: Ms }),
  z.strictObject({ type: z.literal("member.role"), member: Id, before: WorkspaceRoleSchema, after: WorkspaceRoleSchema }),
  z.strictObject({ type: z.literal("member.suspend"), member: Id }),
  z.strictObject({ type: z.literal("member.reinstate"), member: Id }),
  z.strictObject({ type: z.literal("member.remove"), member: Id }),
  z.strictObject({ type: z.literal("member.leave"), member: Id }),
  z.strictObject({ type: z.literal("account.delete"), account: Id }),
  z.strictObject({ type: z.literal("identity.link"), provider: z.literal("google") }),
  z.strictObject({ type: z.literal("identity.unlink"), provider: z.literal("google"), identity: Id }),
  z.strictObject({ type: z.literal("team.update"), team: Id, change: z.enum(["create", "rename", "delete"]), name: z.string().nullable(), slug: z.string().nullable() }),
  z.strictObject({ type: z.literal("team.members"), team: Id, member: Id, change: z.enum(["add", "remove"]) }),
  z.strictObject({ type: z.literal("project.create"), slug: z.string(), remote: z.string().nullable(), environments: z.array(z.strictObject({ name: z.string(), protected: z.boolean(), fourEyes: z.boolean() })) }),
  z.strictObject({ type: z.literal("project.share"), project: Id, subject: ShareSubjectSchema, before: ShareTermsSchema.nullable(), after: ShareTermsSchema.nullable() }),
  z.strictObject({ type: z.literal("project.configure"), project: Id, digest: z.string() }),
  z.strictObject({ type: z.literal("project.delete"), project: Id }),
  z.strictObject({ type: z.literal("override.set"), project: Id, environment: z.string(), variable: z.string(), source: z.discriminatedUnion("kind", [z.strictObject({ kind: z.literal("plain"), value: z.string() }), z.strictObject({ kind: z.literal("item"), item: Id, field: z.string() })]).nullable() }),
  z.strictObject({ type: z.literal("item.rehome"), item: Id, before: CredentialHomeSchema, after: CredentialHomeSchema, dependencyRevision: Ms }),
  z.strictObject({ type: z.literal("connect.start"), connect: Id, provider: z.string(), slug: z.string(), home: CredentialHomeSchema, tags: z.array(z.string()), expectedAccount: z.string().nullable(), scopes: z.array(z.string()), intent: z.enum(["create", "rotate"]), target: Id.nullable(), targetRevision: Ms.nullable(), client: Id, clientRevision: Ms, dependencyRevision: Ms }),
  EnrolAcceptanceSubjectSchema.extend({ type: z.literal("enrol.accept") }),
  z.strictObject({ type: z.literal("enrol.approve"), enrolment: Id, digest: z.string(), owner: OwnerRefSchema, admissionRole: WorkspaceRoleSchema }),
  z.strictObject({ type: z.literal("device.rescope"), device: Id, thumbprint: z.string(), before: WorkspaceDeviceScopeSchema, after: WorkspaceDeviceScopeSchema }),
  z.strictObject({ type: z.literal("device.rescope_accept"), device: Id, thumbprint: z.string(), account: Id, before: WorkspaceDeviceScopeSchema, after: WorkspaceDeviceScopeSchema, admission: z.boolean() }),
  z.strictObject({ type: z.literal("device.rescope_reject"), device: Id, thumbprint: z.string(), proposal: Id }),
  z.strictObject({ type: z.literal("device.revoke"), device: Id }),
  z.strictObject({ type: z.literal("workload.revoke"), device: Id, workload: Id }),
  z.strictObject({ type: z.literal("approval.decide"), approval: Id, digest: z.string(), decision: z.enum(["approve", "deny"]), constraints: z.strictObject({ uses: z.number().int().min(1).max(100).nullable(), ttlSeconds: z.number().int().min(60).max(86_400) }), remember: PolicyRememberSchema.optional() }).refine((v) => v.decision !== "deny" || v.remember === undefined, "Deny cannot remember access"),
  z.strictObject({ type: z.literal("approval.decide_many"), entries: z.array(ApprovalBatchEntrySchema).min(1).max(APPROVAL_BATCH_MAX) }).refine((v) => v.entries.every((e, i) => i === 0 || v.entries[i - 1]!.approval < e.approval), "Sorted by approval, each once"),
  z.strictObject({ type: z.literal("policy.decide"), proposal: Id, digest: z.string(), decision: z.enum(["approve", "deny"]), effectDigest: z.string().nullable() }).refine((v) => v.decision === "deny" ? v.effectDigest === null : v.effectDigest !== null, "Only approval has an effect digest"),
  z.strictObject({ type: z.literal("item.update"), item: Id, digest: z.string() }),
  // digest: itemPostureDigest (policy-rules.ts) over the posture, its
  // catalogue and the posture revision it replaces; level in the clear so a
  // cooling-off may still sign ask.
  z.strictObject({ type: z.literal("item.posture"), item: Id, digest: z.string(), level: PostureLevelSchema }),
  z.strictObject({ type: z.literal("item.delete"), item: Id }),
  // Only a change that asks less is signed; the levels are in the clear so
  // the page shows exactly what the passkey signs.
  z.strictObject({ type: z.literal("workspace.approvals"), before: ApprovalDialSchema, after: ApprovalDialSchema }).refine((v) => approvalDialAsksLess(v.before, v.after), "Only a change that asks less is signed"),
  // digest: mandateDigest (mandates.ts) over the terms, the workspace and
  // the signer. A resume signs the mandate's digest and the revision it
  // resumes, so a mandate changed since the page read it refuses. from:
  // what it resumes from, rebuilt by the vault from live state: a pause, a
  // trip, or a signer who no longer stands behind it.
  z.strictObject({ type: z.literal("mandate.sign"), device: Id, digest: z.string() }),
  z.strictObject({ type: z.literal("mandate.resume"), mandate: MandateIdSchema, digest: z.string(), rev: z.number().int().min(1), from: z.enum(["paused", "tripped", "lapsed"]) }),
  // Push the item's current value again to places a done push put an older
  // one (push.ts): the canonical destinations, sorted, each with the via and
  // its version, as the server rebuilds them from the records the page posts.
  z.strictObject({ type: z.literal("item.push"), item: Id, field: z.string(), version: z.number().int(), pushes: z.array(z.strictObject({ destination: z.string(), via: Id, viaVersion: z.number().int() })).min(1).max(25) }).refine((v) => v.pushes.every((p, i) => i === 0 || v.pushes[i - 1]!.destination < p.destination), "Destinations are sorted, each once"),
  // digest: stepUpDigest({ item, version, previous }), the item's version and
  // its kept previous version as the page showed them.
  z.strictObject({ type: z.literal("item.restore"), item: Id, digest: z.string() }),
  z.strictObject({ type: z.literal("intake.submit"), intake: Id, digest: z.string() }),
  // digest: adoptionDigest (adopt.ts) over every reviewed row of the batch;
  // repoints: adoptionRepoints (adopt.ts), the project variables it rebinds.
  z.strictObject({ type: z.literal("adoption.approve"), adoption: Id, digest: z.string(), repoints: z.number().int().min(0) }),
  z.strictObject({ type: z.literal("passkey.remove"), passkey: Id }),
  // recipient and label as stored; scopeDigest: backupScopeDigest (backup.ts).
  z.strictObject({ type: z.literal("backup.recipient_add"), recipient: z.string(), label: z.string(), scopeDigest: z.string() }),
  z.strictObject({ type: z.literal("backup.recipient_remove"), id: Id }),
  z.strictObject({ type: z.literal("recovery.resolve"), notice: Id, outcome: z.enum(["cancel", "keep"]) }),
  // The operator console and platform admins (platform-console.ts): the
  // platform's slug and id (null only for register, whose platform has no
  // id yet), the command and the digest of the whole command.
  z.strictObject({ type: z.literal("platform.operate"), platform: z.string().min(3).max(40), platformId: Id.nullable(), command: z.string().min(1).max(32), digest: z.string().min(1).max(64) }),
  z.strictObject({ type: z.literal("platform.administer"), platform: z.string().min(3).max(40), platformId: Id, command: z.string().min(1).max(32), digest: z.string().min(1).max(64) }),
  // Two-operator proposals (operator-proposals.ts): the digest of the
  // proposal's kind, target and parameters. Proposing and approving start
  // only on the operator's step-up route; accepting the operator role on
  // the account's own, for the account the approved grant names.
  z.strictObject({ type: z.literal("operator.propose"), digest: z.string().min(1).max(64) }),
  z.strictObject({ type: z.literal("operator.approve"), proposal: Id, digest: z.string().min(1).max(64) }),
  z.strictObject({ type: z.literal("operator.accept"), proposal: Id, digest: z.string().min(1).max(64) }),
  // The proposer of an approved account break-glass taking its single-use
  // link once the account's workspaces hold the barrier (operator-accounts.ts).
  z.strictObject({ type: z.literal("operator.break_glass_link"), intent: Id }),
])
export type WorkspaceStepUpAction = z.infer<typeof WorkspaceStepUpActionSchema>
// POST /api/w/<ws>/mandates/action: the action a passkey signs, or, for a
// resume its signer may make without one, { stepUp: null }.
export const MandateActionAnswerSchema = z.union([WorkspaceStepUpActionSchema, z.strictObject({ stepUp: z.null() })])
export type MandateActionAnswer = z.infer<typeof MandateActionAnswerSchema>

// What the vault answers a poll with. A vault from before migration 0008
// omits hardExpiresAt and reason; the CLI reads a poll as unknown and
// tolerates that, so this type is the current vault's.
export type WorkspaceEnrolStatus =
  | { status: "pending_owner_acceptance" | "pending_admission"; expiresAt: string; hardExpiresAt: string }
  | { status: "expired"; reason: EnrolExpiredReason }
  | { status: "rejected" }
  | { status: "active"; tenant: string; workspace: WorkspaceRef; device: string; scope: WorkspaceDeviceScope; owner: OwnerRef }
export const SessionIdentityCheckSchema = z.strictObject({ id: Id, identityRuleRev: Ms, gateGeneration: Ms, checkSequence: Ms, succeededAt: Iso, expiresAt: Iso })
export type SessionIdentityCheck = z.infer<typeof SessionIdentityCheckSchema>
export const EnvironmentStateSchema = z.strictObject({ protected: z.boolean(), fences: z.array(z.string()), fourEyes: z.boolean() })
export type EnvironmentState = z.infer<typeof EnvironmentStateSchema>
export const EnvironmentUpdateSubjectSchema = EnvironmentStateSchema.extend({ change: z.literal("environment.update"), project: Id, env: z.string() })
export type EnvironmentUpdateSubject = z.infer<typeof EnvironmentUpdateSubjectSchema>
// Parse the exact signed input: omitting fourEyes must never reuse a signature.
export function environmentUpdateDigestInput(subject: EnvironmentUpdateSubject): EnvironmentUpdateSubject { return EnvironmentUpdateSubjectSchema.parse(subject) }
export const WorkspaceSettingsChangeSchema = z.discriminatedUnion("change", [z.strictObject({ change: z.literal("name"), name: z.string().min(1).max(64) }), z.strictObject({ change: z.literal("slug"), slug: WorkspaceSlugSchema }), z.strictObject({ change: z.literal("identity_rule"), rule: IdentityRuleSchema }), z.strictObject({ change: z.literal("delete"), name: z.string() }), z.strictObject({ change: z.literal("delete_cancel") })])
export type WorkspaceSettingsRequest = z.infer<typeof WorkspaceSettingsChangeSchema> & { stepUp: import("./api.ts").StepUpProof }
export const WorkspaceNoticePayloadSchema = z.discriminatedUnion("kind", [
 z.strictObject({ kind: z.literal("account_security"), workspace: WorkspaceRefSchema, account: Id, name: z.string(), event: z.enum(["recovery", "break-glass"]), at: Iso, client: z.string().nullable(), place: z.string().nullable(), restrictedUntil: Iso.nullable() }),
 z.strictObject({ kind: z.literal("machine_added"), workspace: WorkspaceRefSchema, device: Id, name: z.string(), owner: OwnerRefSchema, place: z.string().nullable(), at: Iso }),
 z.strictObject({ kind: z.literal("protection_changed"), workspace: WorkspaceRefSchema, project: z.strictObject({ id: Id, slug: z.string() }), env: z.string(), changes: z.array(z.enum(["unprotected", "fence_added", "fence_removed", "four_eyes_off", "reference_removed", "project_deleted"])), by: Id, at: Iso }),
 z.strictObject({ kind: z.literal("owner_changed"), workspace: WorkspaceRefSchema, member: Id, name: z.string(), change: z.enum(["added", "promoted", "reinstated", "demoted", "suspended", "removed"]), by: Id, at: Iso }),
 // To the inviter alone: someone joined straight away through their invitation.
 z.strictObject({ kind: z.literal("member_joined"), workspace: WorkspaceRefSchema, member: Id, name: z.string(), role: WorkspaceRoleSchema, by: Id, at: Iso }),
 z.strictObject({ kind: z.literal("deletion_scheduled"), workspace: WorkspaceRefSchema, by: Id, at: Iso, deleteAfter: Iso }),
 z.strictObject({ kind: z.literal("backup_recipient"), workspace: WorkspaceRefSchema, member: Id, name: z.string(), recipient: z.strictObject({ id: Id, fingerprint: z.string(), label: z.string() }), change: z.enum(["added", "active", "removed"]), activeAt: Iso, by: Id, at: Iso }),
 z.strictObject({ kind: z.literal("rotation_required"), workspace: WorkspaceRefSchema, projects: z.array(z.strictObject({ id: Id, slug: z.string() })), items: z.array(z.strictObject({ id: Id, slug: z.string() })), by: Id, at: Iso }),
 // An operator suspended a member's account: their machines keep their
 // scope until the owners revoke them.
 z.strictObject({ kind: z.literal("account_suspended"), workspace: WorkspaceRefSchema, account: Id, name: z.string(), at: Iso }),
 // A member signed a mandate for one of their machines (to the owners and
 // admins), one tripped on its rate (to its signer too), one ends within
 // MANDATE_ENDING_NOTICE_MS, or one lapsed, covering nothing until its
 // signer resumes it (both to its signer only). Never names a credential.
 z.strictObject({ kind: z.literal("mandate_signed"), workspace: WorkspaceRefSchema, mandate: MandateIdSchema, device: Id, machine: z.string(), signer: z.strictObject({ member: Id, name: z.string() }), classes: z.array(MandateClassSchema), expiresAt: Iso, at: Iso }),
 z.strictObject({ kind: z.literal("mandate_tripped"), workspace: WorkspaceRefSchema, mandate: MandateIdSchema, device: Id, machine: z.string(), signer: z.strictObject({ member: Id, name: z.string() }), classes: z.array(MandateClassSchema), expiresAt: Iso, at: Iso }),
 z.strictObject({ kind: z.literal("mandate_ending"), workspace: WorkspaceRefSchema, mandate: MandateIdSchema, device: Id, machine: z.string(), signer: z.strictObject({ member: Id, name: z.string() }), classes: z.array(MandateClassSchema), expiresAt: Iso, at: Iso }),
 z.strictObject({ kind: z.literal("mandate_lapsed"), workspace: WorkspaceRefSchema, mandate: MandateIdSchema, device: Id, machine: z.string(), signer: z.strictObject({ member: Id, name: z.string() }), classes: z.array(MandateClassSchema), expiresAt: Iso, at: Iso }),
])
export type WorkspaceNoticePayload = z.infer<typeof WorkspaceNoticePayloadSchema>
// The one notice envelope every pending and inbox route returns.
export const WorkspaceNoticeSchema = z.strictObject({ id: z.string(), account: z.string(), payload: WorkspaceNoticePayloadSchema, at: z.number().int(), url: z.string() })
export type WorkspaceNotice = z.infer<typeof WorkspaceNoticeSchema>
// approvals: the approval dial, only where it may be changed (switched on,
// and not a managed workspace; elsewhere every request asks as writes);
// askLess and askMore say whether the caller may move it either way now.
export const WorkspaceApprovalsViewSchema = z.strictObject({ level: ApprovalDialSchema, askLess: z.boolean(), askMore: z.boolean() })
export type WorkspaceApprovalsView = z.infer<typeof WorkspaceApprovalsViewSchema>
// POST /api/w/:ws/settings/approvals: the level the page showed and the one
// chosen; the vault answers the level it now holds.
export const WorkspaceApprovalsChangeSchema = z.strictObject({ before: ApprovalDialSchema, after: ApprovalDialSchema })
export const WorkspaceApprovalsChangedSchema = z.strictObject({ level: ApprovalDialSchema })
export const WorkspaceSettingsViewSchema = z.strictObject({ frozen: z.boolean(), rights: z.strictObject({ rename: z.boolean(), freeze: z.boolean(), unfreeze: z.boolean() }), approvals: WorkspaceApprovalsViewSchema.optional() })
export type WorkspaceSettingsView = z.infer<typeof WorkspaceSettingsViewSchema>
export const WORKSPACE_VERIFY_PAGE = "/w/:ws/verify"
export const OIDC_CONTINUE_PAGE = "/auth/oidc/continue"
export const NAME_UNAVAILABLE = { error: "conflict", message: "name not available" } as const
export function nameRateRefusal(retryAfter: number) { return { error: "rate_limited", message: "Too many unavailable names; try again later.", retryAfter } as const }

export type NameMissBudget = { windowStart: number; count: number }
export function exhaustedNameBudget(budgets: NameMissBudget[], now: number): ReturnType<typeof nameRateRefusal> | null {
 const end = Math.max(0, ...budgets.filter((b) => b.count >= 20 && b.windowStart <= now && now < b.windowStart + 3_600_000).map((b) => b.windowStart + 3_600_000))
 return end === 0 ? null : nameRateRefusal(Math.ceil((end - now) / 1000))
}

// Audit rows are immutable stored bytes. Visibility filters rows, never detail.
export const WORKSPACE_AUDIT_PATH = "/api/w/:ws/audit"
export const WorkspaceAuditEventSchema = z.strictObject({ seq: z.number().int().positive(), at: Ms, actor: z.string(), action: z.string(), target: z.string().nullable(), detail: z.string(), prev: z.string(), hash: z.string() })
export type WorkspaceAuditEvent = z.infer<typeof WorkspaceAuditEventSchema>
export const WorkspaceAuditPageSchema = z.strictObject({ events: z.array(WorkspaceAuditEventSchema), verified: z.boolean(), next: z.string().regex(/^[1-9][0-9]*$/).nullable(), filtered: z.boolean(), head: z.strictObject({ seq: z.number().int().positive(), hash: z.string() }).nullable() })
export type WorkspaceAuditPage = z.infer<typeof WorkspaceAuditPageSchema>
