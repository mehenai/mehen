// Stop and Extend on a standing rule, from a credential's or a machine's
// page, with no DOM so the tests drive this exact code. Stop only narrows:
// one post, no passkey. Extend signs one passkey over the vault's
// policy.decide, and only once the action's effectDigest is the one this
// page computed itself from the rule's id and the duration chosen
// (policyRuleExtendDigest), and its digest is that of the terms the row
// shows (policyRuleTermsDigest); any other action sends nothing further.

import type { PolicyAreaGrantView } from "@mehen/protocol/policy-mode"
import { type PolicyRuleExtended, type PolicyRuleStopped, type PolicyRuleTerms, type PolicyRuleView, type RuleDuration, PolicyProposalIdSchema, PolicyRuleTermsSchema, RULE_DURATIONS } from "@mehen/protocol/policy-mode"
import { policyRuleExtendDigest, policyRuleTermsDigest } from "@mehen/protocol/policy-rules"
import { VaultFailure, workspaceApi } from "./api.ts"
import { type ShellState, workspacePath } from "./shell-logic.ts"
import { CHANGED_SINCE_SHOWN } from "./workspace-logic.ts"
import { type Passkey, browserPasskey, signed } from "./workspace-sign.ts"

// A task grant's Stop answers the grant, or only its id, status and why it
// ended.
export type RuleStopAnswer = PolicyRuleView | PolicyAreaGrantView | PolicyRuleStopped | Pick<PolicyAreaGrantView, "id" | "status" | "endedReason">

function rulePath(rule: string): string {
  return `/policy/rules/${encodeURIComponent(rule)}`
}

// A viewer who may stop the rule or grant but not read it gets only its
// id, status and why it ended: no terms, neither a rule's method nor a
// grant's areas.
export function isStoppedOnly(answer: RuleStopAnswer): answer is PolicyRuleStopped | Pick<PolicyAreaGrantView, "id" | "status" | "endedReason"> {
  return !("method" in answer) && !("areas" in answer)
}

export function stopRule(shell: ShellState, rule: string): Promise<RuleStopAnswer> {
  return workspaceApi<RuleStopAnswer>(shell, `${rulePath(rule)}/revoke`, {})
}

export function ruleDuration(value: string): RuleDuration | null {
  return RULE_DURATIONS.find((d) => String(d) === value) ?? null
}

// The terms a row shows (policy-rules-row.ts ruleTermsOf, on its Extend
// button), or null when they are not a rule's terms.
export function shownRuleTerms(raw: string | undefined): PolicyRuleTerms | null {
  if (raw === undefined) return null
  try {
    const parsed = PolicyRuleTermsSchema.safeParse(JSON.parse(raw))
    return parsed.success ? parsed.data : null
  } catch {
    return null
  }
}

// Exactly the extension of this rule the page chose: policy.decide over
// the rul_ id, approve, the digest of the terms shown and this effectDigest.
export function isRuleExtendAction(action: unknown, rule: string, effectDigest: string, termsDigest: string): boolean {
  if (typeof action !== "object" || action === null) return false
  const a = action as Record<string, unknown>
  return Object.keys(a).sort().join() === "decision,digest,effectDigest,proposal,type"
    && a.type === "policy.decide" && a.proposal === rule && a.decision === "approve" && a.effectDigest === effectDigest && a.digest === termsDigest
}

// shown: the terms the row shows; with none read, nothing is sent.
export async function extendRule(shell: ShellState, rule: string, ttlSeconds: RuleDuration, shown: PolicyRuleTerms | null, passkey: Passkey = browserPasskey): Promise<PolicyRuleExtended> {
  if (shown === null) throw new VaultFailure(409, CHANGED_SINCE_SHOWN)
  const [effectDigest, termsDigest] = await Promise.all([policyRuleExtendDigest(rule, ttlSeconds), policyRuleTermsDigest(shown)])
  const body = { ttlSeconds }
  return signed<PolicyRuleExtended>(shell, { prepare: { path: `${rulePath(rule)}/extend/action`, body }, matches: (a) => isRuleExtendAction(a, rule, effectDigest, termsDigest), mutation: { path: `${rulePath(rule)}/extend/decide`, body } }, passkey)
}

// The co-sign proposal's page, built from its checked id on this tab's
// workspace and origin; the url the vault sends is never followed. Null
// for an id that is not a proposal's.
export function coSignHref(shell: ShellState, proposal: string): string | null {
  return PolicyProposalIdSchema.safeParse(proposal).success ? `${shell.identity.origin}${workspacePath(shell.identity, `/p/${proposal}`)}` : null
}
