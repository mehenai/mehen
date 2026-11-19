// Vault answers for standing rules, each built from the protocol's shapes
// and parsed through its schemas where the protocol has one, so a fake
// cannot say what the vault never could.

import type { ApiError } from "@mehen/protocol/api"
import { PolicyAreaGrantTermsSchema, type PolicyAreaGrantTerms, type PolicyAreaGrantView, PolicyRuleIdSchema, PolicyRuleProposalStatusSchema, PolicyRuleTermsSchema, type PolicyRulePreview, type PolicyRuleProposalStatus, type PolicyRuleRefusal, type PolicyRuleTerms, type PolicyRuleView } from "@mehen/protocol/policy-mode"
import { z } from "zod"

const inAnHour = () => new Date(Date.now() + 3_600_000).toISOString()
const inAWeek = () => new Date(Date.now() + 7 * 86_400_000).toISOString()

export function ruleTerms(extra: Partial<PolicyRuleTerms> = {}): PolicyRuleTerms {
  return PolicyRuleTermsSchema.parse({ item: "example-key", itemId: "itm_example", asker: { device: "dev_test", workload: null }, method: "POST", host: "api.example.com", path: "/tasks", anchorPath: "/tasks", queryNames: [], graphql: null, ttlSeconds: 604_800, ...extra })
}

export function ruleStatus(extra: Partial<PolicyRuleProposalStatus> = {}): PolicyRuleProposalStatus {
  return PolicyRuleProposalStatusSchema.parse({ proposal: "pol_rule", item: "example-key", status: "pending", stage: "approve", bindingCode: "CODE42", summary: "POST api.example.com/tasks, from test-machine, outside any project, 7 days", expiresAt: inAnHour(), rule: null, ...extra })
}

export function ruleCreated(origin: string, extra: Partial<PolicyRuleProposalStatus> = {}) {
  const status = ruleStatus(extra)
  const url = `${origin}/w/mock-space/p/${status.proposal}`
  return { ...status, url, next: { url, command: `mehen wait ${status.proposal}`, say: "Send this link to the machine's owner; only their passkey turns the rule on." } }
}

export function rulePreview(extra: Partial<PolicyRulePreview> = {}): PolicyRulePreview {
  const terms = extra.terms === undefined ? ruleTerms() : extra.terms
  return { terms, pathChoices: terms ? ["/tasks"] : [], summary: "POST api.example.com/tasks, from test-machine, outside any project, 7 days", refused: null, ...extra }
}

// The PolicyRuleView fields the protocol has no schema for, checked here.
const ViewExtraSchema = z.strictObject({
  id: PolicyRuleIdSchema, approvedBy: z.string().nullable(), coSignedBy: z.strictObject({ name: z.string().nullable() }).nullable(),
  context: z.strictObject({ project: z.string(), environment: z.string() }).nullable(), createdAt: z.iso.datetime(), endsAt: z.iso.datetime(), uses: z.number().int().min(0), lastUsedAt: z.iso.datetime().nullable(),
  status: z.enum(["active", "ended"]), endedReason: z.enum(["expired", "revoked", "access-changed", "credential-changed"]).nullable(),
})

export function ruleView(extra: Partial<PolicyRuleView> = {}): PolicyRuleView {
  const { id = "rul_live", approvedBy = "Alex", coSignedBy = null, context = null, createdAt = new Date().toISOString(), endsAt = inAWeek(), uses = 3, lastUsedAt = null, status = "active", endedReason = null, ...terms } = extra
  const view = { ...ruleTerms(terms), ...ViewExtraSchema.parse({ id, approvedBy, coSignedBy, context, createdAt, endsAt, uses, lastUsedAt, status, endedReason }) }
  return view
}

// What every rule route but preview and proposals answers while standing
// rules are off (and what an older vault answers): today's forbidden, with
// the vault's next.
export const RULES_OFF: ApiError = { error: "forbidden", message: "Policy widening is not available yet.", next: { command: "mehen policy propose --help", say: "Read the policy proposal options and try again." } }

// What preview and proposals answer a rule's body while standing rules are
// off (and what an older vault answers): the body read as a legacy window's.
export const RULES_OFF_BODY: ApiError = { error: "bad_request", message: "Invalid request: change Invalid input: expected object, received undefined.", next: RULES_OFF.next! }

export function ruleRefusal(reason: PolicyRuleRefusal, message: string): ApiError {
  return { error: "forbidden", message, ruleRefused: reason }
}

// Task grants (standing rules of kind area), as GET /v1/policy/rules?include=grants lists them.
export function grantTerms(extra: Partial<PolicyAreaGrantTerms> = {}): PolicyAreaGrantTerms {
  return PolicyAreaGrantTermsSchema.parse({ kind: "area", item: "github-work", itemId: "itm_github", asker: { device: "dev_test", workload: null }, host: "api.github.com", catalogue: "github", catalogueVersion: 1, areas: ["issues"], ttlSeconds: 3600, maxUses: 50, ...extra })
}

const GrantExtraSchema = ViewExtraSchema.extend({
  receipt: z.array(z.strictObject({ entry: z.string(), words: z.string(), count: z.number().int().min(1) })),
  endedReason: z.enum(["expired", "revoked", "access-changed", "credential-changed", "uses-spent", "replaced"]).nullable(),
})

export function grantView(extra: Partial<PolicyAreaGrantView> = {}): PolicyAreaGrantView {
  const { id = "rul_grant", approvedBy = "Alex", coSignedBy = null, context = null, createdAt = new Date().toISOString(), endsAt = inAnHour(), uses = 2, lastUsedAt = null, status = "active", receipt = [{ entry: "github.issue-comment", words: "Comment on an issue", count: 2 }], endedReason = null, ...terms } = extra
  return { ...grantTerms(terms), ...GrantExtraSchema.parse({ id, approvedBy, coSignedBy, context, createdAt, endsAt, uses, lastUsedAt, status, receipt, endedReason }) }
}

export function grantCreated(origin: string, extra: Partial<PolicyRuleProposalStatus> = {}) {
  return ruleCreated(origin, { proposal: "pol_grant", item: "github-work", summary: "Task grant on api.github.com: Issues and comments, from test-machine, outside any project, 1 hour, up to 50 requests", ...extra })
}
