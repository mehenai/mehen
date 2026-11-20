// A policy in three plain lines (UX-VAULT-WEB 2.3d, UX-MEHEN-TOOLS 2.7): what an
// agent may do on its own, what needs the human's approval, and what is
// refused even with one. Shown above the full rule list, never instead of it,
// and `rest` says where every request no rule names goes, so the summary
// never implies an allow the policy does not grant.
//
// Rule notes are display text written by whoever wrote the policy. A
// template's notes were written by a human and reviewed; a policy an agent
// proposed (an intake with proposed_binding, verified false) could carry a
// note like "read mail" on a rule that allows sending. So notes are used
// only when the caller says they are trusted; otherwise every rule is
// described from what it actually matches.

import type { PolicyInput } from "./api.ts"

export type PolicySummary = {
  allowed: string[]
  approve: string[]
  deny: string[]
  rest: "allowed" | "approve" | "deny"
}

// "trusted": the notes came from a verified template or were written by a
// member, and may be shown. "untrusted" (the default): the notes may have
// been written by an agent and are ignored.
export type PolicySummaryOptions = { notes: "trusted" | "untrusted" }

type PolicyRule = PolicyInput["rules"][number]

const REST: Record<PolicyInput["default"], PolicySummary["rest"]> = { allow: "allowed", approve: "approve", deny: "deny" }

const BODY_WORDS: Record<NonNullable<PolicyRule["body"]>, string> = {
  "graphql-query": "GraphQL queries only",
  "graphql-mutation": "GraphQL that may change something",
  "json-remote-mcp": "requests that name a remote MCP server, or cannot be read",
  "json-webhook": "requests that name a webhook, or cannot be read",
  "json-public-url": "requests that publish their output at a public URL, or cannot be read",
}

// What a rule matches, in words: "DELETE on /v1/items/*, /v1/items",
// "GET/HEAD anywhere", "any method on /v1/status", "every request".
export function describeRuleMatchers(rule: PolicyRule): string {
  const methods = rule.methods && rule.methods.length > 0 ? rule.methods.join("/") : null
  const paths = rule.paths && rule.paths.length > 0 ? rule.paths.join(", ") : null
  let phrase: string
  if (methods && paths) phrase = `${methods} on ${paths}`
  else if (methods) phrase = `${methods} anywhere`
  else if (paths) phrase = `any method on ${paths}`
  else phrase = "every request"
  return rule.body ? `${phrase}, ${BODY_WORDS[rule.body]}` : phrase
}

export function summarisePolicy(policy: PolicyInput, options: PolicySummaryOptions = { notes: "untrusted" }): PolicySummary {
  const summary: PolicySummary = { allowed: [], approve: [], deny: [], rest: REST[policy.default] }
  for (const rule of policy.rules) {
    const list = rule.action === "allow" ? summary.allowed : rule.action === "approve" ? summary.approve : summary.deny
    const phrase = options.notes === "trusted" && rule.note ? rule.note : describeRuleMatchers(rule)
    if (!list.includes(phrase)) list.push(phrase)
  }
  return summary
}
