// Several operators, and the changes that need two of them, in Mehen's own
// web app: every kind of change, the digest that binds one, and the Operators
// view's requests and answers (routes in CONSOLE_ROUTES).
//
// One operator proposes a change with a passkey; a different operator
// approves it, also with a passkey, within 24 hours; then the vault applies
// it in one guarded batch. A kind may need the account it names to accept
// with their own passkey before it applies (granting the operator role). A
// one-operator kind (resigning your own role) applies at once when proposed.
// Nobody proposes or approves a change whose target is themselves, except a
// kind whose target is always yourself.
//
// A kind is one entry in OPERATOR_PROPOSAL_KINDS (its rule and the schemas
// of its target and parameters) and one in the vault's registry (what it
// checks and applies); nothing else changes to add one.

import { z } from "zod"
import { sha256B64 } from "./bytes.ts"
import { canonicalJson } from "./canonical-json.ts"
import { DeploymentSettingKeySchema, DeploymentSettingValueSchema } from "./deployment-settings.ts"
import { WorkspaceIdSchema, WorkspaceRestoreParamsSchema } from "./operator-workspace-terms.ts"
import { AccountIdSchema, OperatorRequirementSchema } from "./platform-console.ts"
import type { WorkspaceStepUpAction } from "./workspace.ts"

const Iso = z.iso.datetime()
const Count = z.number().int().nonnegative()
const Id = z.string().min(1).max(128)
const Digest = z.string().min(1).max(64)

export const OPERATOR_PROPOSAL_TTL_MS = 24 * 60 * 60 * 1000

// Until a second operator exists, what a two-operator change says; and why
// the last operator cannot resign or be revoked. The scripts still work.
export const NEEDS_SECOND_OPERATOR_WORDS = {
  change: "Needs a second operator; use the script.",
  resign: "Mehen needs at least one operator; use the script.",
} as const
export const OPERATOR_PROPOSALS_RECENT = 20
export const OPERATOR_EVENTS_SHOWN = 50

// ---------------------------------------------------------------- kinds

// `operators`: 2 for a change a second operator approves, 1 for one that
// applies when proposed. `target`: "other" never names the proposer or the
// approver, "self" only ever the proposer. `accept`: the target accepts
// with their own passkey once approved, and only then does it apply.
// `names`: what the target is, an account, a workspace or a deployment
// setting.
export type OperatorProposalKindRule = { operators: 1 | 2; target: "self" | "other"; accept: boolean; names: "account" | "workspace" | "setting"; targetSchema: z.ZodType<string>; params: z.ZodType<Record<string, unknown>> }

// A deployment setting (deployment-settings.ts): its key is the target,
// and the value it is set to a parameter. A widening also names the value
// in force when it was proposed (`from`), so it applies only while that is
// still the value in force.
const NarrowSettingParams = z.strictObject({ value: DeploymentSettingValueSchema })
const WidenSettingParams = z.strictObject({ value: DeploymentSettingValueSchema, from: DeploymentSettingValueSchema })

// The Accounts view's kinds (operator-accounts.ts). Workspace creation for
// one account: allowed, denied, or back to the deployment's default.
export const AccountWorkspaceCreationChoiceSchema = z.enum(["allow", "deny", "default"])
export type AccountWorkspaceCreationChoice = z.infer<typeof AccountWorkspaceCreationChoiceSchema>
// Free words with no control characters and no space at either end, so
// what the passkey signs is what is kept.
const PlainWords = (max: number) => z.string().min(1).max(max).refine((value) => value.trim() === value && !/[\u0000-\u001f\u007f]/.test(value), "Use plain words with no space at either end.")
// Recovering access: how the proposer checked, out of band, that the
// person asking is the account's holder; kept in the proposal's events.
export const ACCOUNT_BREAK_GLASS_VERIFIED_MAX = 500
export const AccountBreakGlassParamsSchema = z.strictObject({ verified: PlainWords(ACCOUNT_BREAK_GLASS_VERIFIED_MAX) })
// Deleting an account: the proposer types its name back, and the proposal
// keeps only this hash of it (accountDeleteNameHash), never the name.
export const AccountDeleteParamsSchema = z.strictObject({ nameHash: z.string().regex(/^[A-Za-z0-9_-]{43}$/) })
export function accountDeleteNameHash(target: string, name: string): Promise<string> {
  return sha256B64(canonicalJson({ purpose: "mehen-account-delete-name/v1", target, name }))
}

export const OPERATOR_PROPOSAL_KINDS = {
  "operator.grant": { operators: 2, target: "other", accept: true, names: "account", targetSchema: AccountIdSchema, params: z.strictObject({}) },
  "operator.revoke": { operators: 2, target: "other", accept: false, names: "account", targetSchema: AccountIdSchema, params: z.strictObject({}) },
  "operator.resign": { operators: 1, target: "self", accept: false, names: "account", targetSchema: AccountIdSchema, params: z.strictObject({}) },
  // A workspace back to a point in time or from a day's dump: approval
  // records the restore intent the operator script records, and the cron
  // carries it out (operator-workspace-terms.ts).
  "workspace.restore": { operators: 2, target: "other", accept: false, names: "workspace", targetSchema: WorkspaceIdSchema, params: WorkspaceRestoreParamsSchema },
  // A brake: the workspace's own freeze, pulled by one operator; only its
  // owners unfreeze it.
  "workspace.freeze": { operators: 1, target: "other", accept: false, names: "workspace", targetSchema: WorkspaceIdSchema, params: z.strictObject({}) },
  "account.workspace_creation": { operators: 1, target: "other", accept: false, names: "account", targetSchema: AccountIdSchema, params: z.strictObject({ creation: AccountWorkspaceCreationChoiceSchema }) },
  "account.suspend": { operators: 1, target: "other", accept: false, names: "account", targetSchema: AccountIdSchema, params: z.strictObject({}) },
  "account.lift_suspension": { operators: 1, target: "other", accept: false, names: "account", targetSchema: AccountIdSchema, params: z.strictObject({}) },
  "account.break_glass": { operators: 2, target: "other", accept: false, names: "account", targetSchema: AccountIdSchema, params: AccountBreakGlassParamsSchema },
  "account.delete": { operators: 2, target: "other", accept: false, names: "account", targetSchema: AccountIdSchema, params: AccountDeleteParamsSchema },
  // Narrowing a deployment setting is one operator's brake; widening it,
  // never past the deploy's ceiling, needs a second.
  "settings.narrow": { operators: 1, target: "other", accept: false, names: "setting", targetSchema: DeploymentSettingKeySchema, params: NarrowSettingParams },
  "settings.widen": { operators: 2, target: "other", accept: false, names: "setting", targetSchema: DeploymentSettingKeySchema, params: WidenSettingParams },
} as const satisfies Record<string, OperatorProposalKindRule>

export type OperatorProposalKind = keyof typeof OPERATOR_PROPOSAL_KINDS
export const OperatorProposalKindSchema = z.enum(Object.keys(OPERATOR_PROPOSAL_KINDS) as [OperatorProposalKind, ...OperatorProposalKind[]])

export function operatorProposalRule(kind: OperatorProposalKind): OperatorProposalKindRule {
  return OPERATOR_PROPOSAL_KINDS[kind]
}

export type OperatorProposalTerms = { kind: OperatorProposalKind; target: string; params: Record<string, unknown> }

const TARGET_PROBLEMS: Record<OperatorProposalKindRule["names"], string> = {
  account: "That is not an account id (acc_...).",
  workspace: "That is not a workspace id (tn_...).",
  setting: "That is not a deployment setting (workspace_creation or signup_mode).",
}

// The terms as the kind's own schemas parse them, which is what the digest
// is taken over, or the first problem in plain words.
export function parseOperatorProposalTerms(input: { kind: OperatorProposalKind; target: string; params: unknown }): { ok: true; terms: OperatorProposalTerms } | { ok: false; problem: string } {
  const rule = operatorProposalRule(input.kind)
  const target = rule.targetSchema.safeParse(input.target)
  if (!target.success) return { ok: false, problem: TARGET_PROBLEMS[rule.names] }
  const params = rule.params.safeParse(input.params)
  if (!params.success) return { ok: false, problem: `Those are not the terms of ${input.kind}.` }
  return { ok: true, terms: { kind: input.kind, target: target.data, params: params.data } }
}

// The SHA-256 of the canonical JSON of the kind, the target and the
// parameters: what every passkey on a proposal confirms.
export function operatorProposalDigest(terms: OperatorProposalTerms): Promise<string> {
  return sha256B64(canonicalJson({ kind: terms.kind, target: terms.target, params: terms.params }))
}

export async function operatorProposeStepUpAction(terms: OperatorProposalTerms): Promise<WorkspaceStepUpAction> {
  return { type: "operator.propose", digest: await operatorProposalDigest(terms) }
}

export function operatorApproveStepUpAction(proposal: string, digest: string): WorkspaceStepUpAction {
  return { type: "operator.approve", proposal, digest }
}

export function operatorAcceptStepUpAction(proposal: string, digest: string): WorkspaceStepUpAction {
  return { type: "operator.accept", proposal, digest }
}

// The proposer of an approved account.break_glass taking its link, once.
export function operatorBreakGlassLinkStepUpAction(intent: string): WorkspaceStepUpAction {
  return { type: "operator.break_glass_link", intent }
}

// ---------------------------------------------------------------- requests

const StepUpSchema = z.strictObject({ nonce: z.string().min(1).max(200), assertion: z.unknown() })

export const OperatorProposeRequestSchema = z.strictObject({ kind: OperatorProposalKindSchema, target: z.string().min(1).max(128), params: z.record(z.string(), z.unknown()), stepUp: StepUpSchema.optional() })
export type OperatorProposeRequest = z.infer<typeof OperatorProposeRequestSchema>

// Approving carries the digest the approver read, refused once it is not
// the proposal's; declining (another operator) and cancelling (the
// proposer) are brakes and need no passkey.
export const OperatorProposalDecisionSchema = z.discriminatedUnion("decision", [
  z.strictObject({ decision: z.literal("approve"), digest: Digest, stepUp: StepUpSchema.optional() }),
  z.strictObject({ decision: z.literal("decline") }),
  z.strictObject({ decision: z.literal("cancel") }),
])
export type OperatorProposalDecision = z.infer<typeof OperatorProposalDecisionSchema>

export const OperatorAcceptRequestSchema = z.strictObject({ proposal: Id, digest: Digest, stepUp: StepUpSchema.optional() })
export type OperatorAcceptRequest = z.infer<typeof OperatorAcceptRequestSchema>

// An account id, or the email of the Google identity linked to an account.
export const OperatorAccountLookupQuerySchema = z.strictObject({ q: z.string().trim().min(1).max(254) })

// ---------------------------------------------------------------- answers

export const OperatorAccountRefSchema = z.strictObject({ account: AccountIdSchema, name: z.string() })
export type OperatorAccountRef = z.infer<typeof OperatorAccountRefSchema>

export const OperatorProposalStateSchema = z.enum(["open", "applied", "declined", "expired", "cancelled"])
export type OperatorProposalState = z.infer<typeof OperatorProposalStateSchema>

// `targetName` is the target account's name; `awaiting` says whose move an
// open proposal waits for, null once closed.
export const OperatorProposalViewSchema = z.strictObject({
  id: Id,
  kind: OperatorProposalKindSchema,
  target: z.string(),
  targetName: z.string().nullable(),
  params: z.record(z.string(), z.unknown()),
  digest: Digest,
  proposedBy: OperatorAccountRefSchema,
  proposedAt: Iso,
  expiresAt: Iso,
  approvedBy: OperatorAccountRefSchema.nullable(),
  approvedAt: Iso.nullable(),
  declinedBy: OperatorAccountRefSchema.nullable(),
  state: OperatorProposalStateSchema,
  closedAt: Iso.nullable(),
  awaiting: z.enum(["approval", "acceptance"]).nullable(),
})
export type OperatorProposalView = z.infer<typeof OperatorProposalViewSchema>

// One operator: `since` when the role was last granted and `grantedBy` by
// whom; passkeys as counts only; `missing` what the account lacks.
export const OperatorViewSchema = z.strictObject({
  account: AccountIdSchema,
  name: z.string(),
  since: Iso.nullable(),
  grantedBy: z.string().nullable(),
  passkeys: Count,
  securityKeys: Count,
  recoveryReady: z.boolean(),
  lastSeenAt: Iso.nullable(),
  missing: z.array(OperatorRequirementSchema),
})
export type OperatorView = z.infer<typeof OperatorViewSchema>

// One deployment_events row, newest first. `actor` is `operator:<who>` or
// `system`; `approver` the second operator of a two-operator change.
export const OperatorEventViewSchema = z.strictObject({ id: z.string(), at: Iso, kind: z.string(), actor: z.string(), approver: z.string().nullable(), target: z.string(), details: z.record(z.string(), z.unknown()) })
export type OperatorEventView = z.infer<typeof OperatorEventViewSchema>

export const OperatorsViewSchema = z.strictObject({
  you: AccountIdSchema,
  operators: z.array(OperatorViewSchema),
  open: z.array(OperatorProposalViewSchema),
  recent: z.array(OperatorProposalViewSchema).max(OPERATOR_PROPOSALS_RECENT),
  events: z.array(OperatorEventViewSchema).max(OPERATOR_EVENTS_SHOWN),
})
export type OperatorsView = z.infer<typeof OperatorsViewSchema>

// The account an operator looked up: its name and id, whether it holds the
// role, and what it lacks to be granted it. Never its email.
export const OperatorCandidateSchema = z.strictObject({ account: AccountIdSchema, name: z.string(), operator: z.boolean(), missing: z.array(OperatorRequirementSchema) })
export type OperatorCandidate = z.infer<typeof OperatorCandidateSchema>

// `proposal` is null for a one-operator kind, applied at once.
export const OperatorProposalAnswerSchema = z.strictObject({ done: z.string(), proposal: OperatorProposalViewSchema.nullable() })
export type OperatorProposalAnswer = z.infer<typeof OperatorProposalAnswerSchema>

// An approved operator role waiting for this account to accept it.
export const OperatorInvitationSchema = z.strictObject({ proposal: Id, digest: Digest, proposedBy: OperatorAccountRefSchema, approvedBy: OperatorAccountRefSchema, expiresAt: Iso, missing: z.array(OperatorRequirementSchema) })
export type OperatorInvitation = z.infer<typeof OperatorInvitationSchema>
export const OperatorInvitationReadSchema = z.strictObject({ invitation: OperatorInvitationSchema.nullable() })
export type OperatorInvitationRead = z.infer<typeof OperatorInvitationReadSchema>
export const OperatorAcceptAnswerSchema = z.strictObject({ done: z.string() })
