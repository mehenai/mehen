// The one way the workspace pages sign a change, and the approval decision
// built on it. Ask the vault for the canonical action; refuse unless it is
// the one the page rebuilt from what it showed; refuse unless the workspace
// still has the id, slug and name the page showed (and any page-specific
// check still holds); only then start the workspace-bound step-up, ask the
// passkey (not inside the session's grace window) and send. A refusal sends
// nothing further: no step-up start, no passkey, no mutation. No DOM here,
// so the tests drive this exact code with a fake passkey and fetch.

import type { ApiError } from "@mehen/protocol/api"
import type { WorkspaceRef, WorkspaceStepUpAction } from "@mehen/protocol/workspace"
import { type PublicKeyCredentialRequestOptionsJSON, startAuthentication } from "@simplewebauthn/browser"
import { VaultFailure, workspaceApi } from "./api.ts"
import { type StepUpStarted, WORKSPACE_STEP_UP_PATH, stepUpProof } from "./step-up.ts"
import type { ShellState } from "./shell-logic.ts"
import type { PolicyRememberArea, PolicyRememberRule } from "@mehen/protocol/policy-mode"
import { AREA_OFFER_MISMATCH_MESSAGE, AREA_OFFER_MISMATCH_SAY, AREA_PROPOSAL_MISMATCH_MESSAGE, AREA_PROPOSAL_MISMATCH_SAY } from "../wording.ts"
import { type AreaProposalBoot, areaOfferMatches, areaProposalDecision, areaProposalMatches, rememberArea } from "./workspace-logic.ts"
import { RULE_OFFER_MISMATCH_MESSAGE, RULE_OFFER_MISMATCH_SAY, RULE_PROPOSAL_MISMATCH_MESSAGE, RULE_PROPOSAL_MISMATCH_SAY } from "../wording.ts"
import { CHANGED_SINCE_SHOWN, type Constraints, type RuleProposalBoot, type RuleProposalEffect, type WorkspaceApprovalBoot, approvalBindingMatches, approvalDecision, chosenConstraints, identityRefusal, rememberRule, ruleOfferMatches, ruleProposalDecision, ruleProposalEffect, ruleProposalMatches, sameAction } from "./workspace-logic.ts"
import { type ReviewChoice, type ReviewRowBoot, reviewBatchBody, reviewBatchMatches, reviewBindingMismatches, reviewMayApprove, reviewMayDeny } from "./workspace-logic.ts"

export type Passkey = (options: PublicKeyCredentialRequestOptionsJSON) => Promise<unknown>

export const browserPasskey: Passkey = (options) => startAuthentication({ optionsJSON: options })

export type SignRequest = {
  prepare: { path: string; body: unknown }
  matches: (action: unknown) => boolean
  // The refusal when it does not match; CHANGED_SINCE_SHOWN unless named.
  mismatch?: ApiError
  // A further check against what the page showed, read fresh before signing.
  stillShown?: () => Promise<ApiError | null>
  mutation: { path: string; body: Record<string, unknown> }
}

function refuse(body: ApiError): never {
  throw new VaultFailure(409, body)
}

// The step-up action itself, once the vault's action has been checked.
export async function signAction<T>(shell: ShellState, action: WorkspaceStepUpAction, mutation: SignRequest["mutation"], stillShown: SignRequest["stillShown"], passkey: Passkey): Promise<T> {
  const now = await workspaceApi<WorkspaceRef>(shell, "")
  const renamed = identityRefusal(shell.identity.workspace, now)
  if (renamed !== null) refuse(renamed)
  const changed = stillShown === undefined ? null : await stillShown()
  if (changed !== null) refuse(changed)
  const stepUp = await stepUpProof(await workspaceApi<StepUpStarted>(shell, WORKSPACE_STEP_UP_PATH, { action }), passkey)
  return workspaceApi<T>(shell, mutation.path, { ...mutation.body, stepUp })
}

export async function signed<T>(shell: ShellState, request: SignRequest, passkey: Passkey = browserPasskey): Promise<T> {
  const action = await workspaceApi<WorkspaceStepUpAction>(shell, request.prepare.path, request.prepare.body)
  if (!request.matches(action)) refuse(request.mismatch ?? CHANGED_SINCE_SHOWN)
  return signAction<T>(shell, action, request.mutation, request.stillShown, passkey)
}

export const BINDING_CODE_NOT_TICKED: ApiError = { error: "bad_request", message: "Tick the box once the agent has shown you the binding code.", next: { say: "Nothing was signed." } }
export const BINDING_MISMATCH: ApiError = { error: "conflict", message: "The request shown does not match what the vault stored for this approval.", next: { say: "Nothing was signed. Deny it, or reload and check the request again." } }

export const RULE_OFFER_MISMATCH: ApiError = { error: "conflict", message: RULE_OFFER_MISMATCH_MESSAGE, next: { say: RULE_OFFER_MISMATCH_SAY } }

export const AREA_OFFER_MISMATCH: ApiError = { error: "conflict", message: AREA_OFFER_MISMATCH_MESSAGE, next: { say: AREA_OFFER_MISMATCH_SAY } }

export const AREA_PROPOSAL_MISMATCH: ApiError = { error: "conflict", message: AREA_PROPOSAL_MISMATCH_MESSAGE, next: { say: AREA_PROPOSAL_MISMATCH_SAY } }

// A task grant proposal: Approve only once the page's terms hash to the
// vault's digests (and an agent's code is ticked), signing the terms as
// they were signed before; Deny always.
export async function decideAreaProposal<T>(shell: ShellState, boot: AreaProposalBoot & { coded: boolean }, choice: { decision: "approve" | "deny"; codeTicked: boolean }, passkey: Passkey = browserPasskey): Promise<T> {
  if (choice.decision === "approve") {
    if (boot.coded && !choice.codeTicked) refuse(BINDING_CODE_NOT_TICKED)
    if (!(await areaProposalMatches(boot))) refuse(AREA_PROPOSAL_MISMATCH)
  }
  const path = `/policy/proposals/${encodeURIComponent(boot.proposal)}`
  const { body, expected } = await areaProposalDecision(boot, choice.decision)
  return signed<T>(shell, { prepare: { path: `${path}/action`, body }, matches: (a) => sameAction(expected, a), mutation: { path: `${path}/decide`, body } }, passkey)
}

// `rule`: approve and allow this from now on, with the path and duration
// chosen in the panel. `area`: approve and let the agent carry on, with the
// areas, duration and uses chosen in the task grant panel.
export type ApprovalChoice = { decision: "approve" | "deny"; codeTicked: boolean; uses: string; ttl: string; rule?: { path: string; ttl: string }; area?: { areas: string[]; ttl: string; uses: string } }

// Approve only once the binding recomputes, the code is ticked and the
// terms are within what was asked; deny always signs the asked terms. A
// rule also needs the offer's terms to hash to the vault's digest and to be
// this approval's request, and signs the digest of the terms with the
// chosen path and duration. A task grant likewise needs the offer's terms to
// hash to the vault's digest, and signs the digest of the terms with the
// areas, duration and uses chosen.
export async function decideApproval<T>(shell: ShellState, boot: WorkspaceApprovalBoot, choice: ApprovalChoice, passkey: Passkey = browserPasskey): Promise<T> {
  let constraints: Constraints = boot.subject.constraints
  let remember: PolicyRememberRule | PolicyRememberArea | undefined
  if (choice.decision === "approve") {
    if (!choice.codeTicked) refuse(BINDING_CODE_NOT_TICKED)
    if (!(await approvalBindingMatches(boot))) refuse(BINDING_MISMATCH)
    const chosen = chosenConstraints(boot.subject.constraints, choice.uses, choice.ttl)
    if (!chosen.ok) throw new VaultFailure(400, { error: "bad_request", message: chosen.problems.join(" "), next: { say: "Nothing was signed." } })
    constraints = chosen.value
    if (choice.rule !== undefined) {
      if (boot.rule === undefined || !(await ruleOfferMatches(boot.rule, boot.subject))) refuse(RULE_OFFER_MISMATCH)
      const built = await rememberRule(boot.rule, choice.rule.path, choice.rule.ttl)
      if (!built.ok) throw new VaultFailure(400, { error: "bad_request", message: built.problems.join(" "), next: { say: "Nothing was signed." } })
      remember = built.value
    }
    if (choice.area !== undefined) {
      if (choice.rule !== undefined || boot.area === undefined || !(await areaOfferMatches(boot.area, boot.subject))) refuse(AREA_OFFER_MISMATCH)
      const built = await rememberArea(boot.area, choice.area.areas, choice.area.ttl, choice.area.uses)
      if (!built.ok) throw new VaultFailure(400, { error: "bad_request", message: built.problems.join(" "), next: { say: "Nothing was signed." } })
      remember = built.value
    }
  }
  const path = `/approvals/${encodeURIComponent(boot.approval)}`
  const { body, expected } = approvalDecision(boot, choice.decision, constraints, remember)
  return signed<T>(shell, { prepare: { path: `${path}/action`, body }, matches: (a) => sameAction(expected, a), mutation: { path: `${path}/decide`, body } }, passkey)
}

// The stop view knows nothing of the request: it may only deny this
// approval, with whatever terms and digest the vault stored.
export async function denyFromStop<T>(shell: ShellState, approval: string, passkey: Passkey = browserPasskey): Promise<T> {
  const path = `/approvals/${encodeURIComponent(approval)}`
  const isDenial = (a: unknown) => typeof a === "object" && a !== null && (a as { type?: unknown }).type === "approval.decide" && (a as { approval?: unknown }).approval === approval && (a as { decision?: unknown }).decision === "deny"
  return signed<T>(shell, { prepare: { path: `${path}/action`, body: { decision: "deny" } }, matches: isDenial, mutation: { path: `${path}/decide`, body: { decision: "deny" } } }, passkey)
}

export const RULE_PROPOSAL_MISMATCH: ApiError = { error: "conflict", message: RULE_PROPOSAL_MISMATCH_MESSAGE, next: { say: RULE_PROPOSAL_MISMATCH_SAY } }

// What the person chose on the rule proposal page.
export type RuleProposalChoice = { decision: "approve" | "deny"; codeTicked: boolean; path: string; ttl: string }

// Approve only once the page's terms hash to the vault's digests, the code
// is ticked where the page shows one, and the path and duration are within
// what was proposed; it signs policy.decide with the digest of the terms
// with them. Deny signs policy.decide with no effect.
export async function decideRuleProposal<T>(shell: ShellState, boot: RuleProposalBoot & { coded: boolean }, choice: RuleProposalChoice, passkey: Passkey = browserPasskey): Promise<T> {
  let effect: RuleProposalEffect | null = null
  if (choice.decision === "approve") {
    if (boot.coded && !choice.codeTicked) refuse(BINDING_CODE_NOT_TICKED)
    if (!(await ruleProposalMatches(boot))) refuse(RULE_PROPOSAL_MISMATCH)
    const built = await ruleProposalEffect(boot, choice.path, choice.ttl)
    if (!built.ok) throw new VaultFailure(400, { error: "bad_request", message: built.problems.join(" "), next: { say: "Nothing was signed." } })
    effect = built.value
  }
  const path = `/policy/proposals/${encodeURIComponent(boot.proposal)}`
  const { body, expected } = ruleProposalDecision(boot, choice.decision, effect)
  return signed<T>(shell, { prepare: { path: `${path}/action`, body }, matches: (a) => sameAction(expected, a), mutation: { path: `${path}/decide`, body } }, passkey)
}

// ---------------------------------------------------------------- Review together

export const REVIEW_CODES_NOT_TICKED: ApiError = { error: "bad_request", message: "Tick the code box once you have checked the code against the agent's message.", next: { say: "Nothing was signed." } }
export const REVIEW_NOTHING_TICKED: ApiError = { error: "bad_request", message: "Tick the asks to decide first.", next: { say: "Nothing was signed." } }
export const REVIEW_BINDING_MISMATCH: ApiError = { error: "conflict", message: "A ticked request does not match what the vault stored for it.", next: { say: "Nothing was signed. Untick it and decide it on its own page, or reload and check the requests again." } }

// One passkey over the ticked rows of Review together. Approving needs the
// codes ticked and every approved row's request to recompute to its stored
// digest; any choice the rows shown do not allow refuses. Then the vault's
// approval.decide_many must be exactly the rows shown, entry by entry
// (reviewBatchMatches), before the passkey is asked; a mismatch signs
// nothing.
export async function decideReviewBatch<T>(shell: ShellState, rows: readonly ReviewRowBoot[], choices: readonly ReviewChoice[], codesTicked: boolean, passkey: Passkey = browserPasskey): Promise<T> {
  if (choices.length === 0) refuse(REVIEW_NOTHING_TICKED)
  const approving = choices.some((c) => c.decision === "approve")
  if (approving && !codesTicked) refuse(REVIEW_CODES_NOT_TICKED)
  const shown = (c: ReviewChoice) => rows.find((r) => r.approval === c.approval)
  if (choices.some((c) => { const row = shown(c); return row === undefined || (c.decision === "approve" ? !reviewMayApprove(row) : !reviewMayDeny(row)) })) refuse(CHANGED_SINCE_SHOWN)
  const approved = rows.filter((r) => choices.some((c) => c.decision === "approve" && c.approval === r.approval))
  if ((await reviewBindingMismatches(approved)).length > 0) refuse(REVIEW_BINDING_MISMATCH)
  const body = reviewBatchBody(choices)
  return signed<T>(shell, { prepare: { path: "/approval-batch/action", body }, matches: (a) => reviewBatchMatches(rows, choices, a), mutation: { path: "/approval-batch/decide", body } }, passkey)
}
