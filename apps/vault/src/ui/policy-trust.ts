// Whether an item's policy notes and destination are a built-in template's
// own. Server-side only: it reads the templates, which the browser bundle
// has no business carrying. The words themselves are made in wording.ts.

import type { BindingInput, PolicyInput } from "@mehen/protocol/api"
import { canonicalJson } from "@mehen/protocol/canonical-json"
import { type PolicySummary, type PolicySummaryOptions, summarisePolicy } from "@mehen/protocol/policy-summary"
import { connectionPolicy, getOAuthProvider, getTemplate } from "@mehen/protocol/templates"
import { capabilityLine } from "./wording.ts"

// What a summary needs: the template the item claims, the hosts it goes to
// and its policy. ItemSummary and ItemDescription both carry these.
export type PolicyOwner = { provider: string | null; hosts: readonly string[]; policy: PolicyInput }

function same(a: unknown, b: unknown): boolean {
  return canonicalJson(a) === canonicalJson(b)
}

// The hosts a built-in template gives, when the item names one.
export function templateHosts(provider: string | null): readonly string[] | null {
  if (provider === null) return null
  const template = getTemplate(provider)
  if (template !== null) return template.binding.hosts
  const oauth = getOAuthProvider(provider)
  return oauth !== null ? oauth.upstream.binding.hosts : null
}

function templatePolicy(provider: string): PolicyInput | null {
  const template = getTemplate(provider)
  if (template !== null) return template.policy
  const oauth = getOAuthProvider(provider)
  return oauth !== null ? connectionPolicy(oauth) : null
}

// Rule notes may be shown only when they are a built-in template's own: the
// item names the template and still carries exactly its hosts and policy.
// Anything else (an agent's proposal, a policy edited since) is described
// from what its rules match, never from their notes.
export function policyTrust(item: PolicyOwner): PolicySummaryOptions["notes"] {
  if (item.provider === null) return "untrusted"
  const hosts = templateHosts(item.provider)
  const policy = templatePolicy(item.provider)
  if (hosts === null || policy === null) return "untrusted"
  return same(hosts, item.hosts) && same(policy, item.policy) ? "trusted" : "untrusted"
}

// The three lines above the full rule list.
export function capabilitySummary(item: PolicyOwner): PolicySummary {
  return summarisePolicy(item.policy, { notes: policyTrust(item) })
}

// One line for a credential row.
export function capabilityLineFor(item: PolicyOwner): string {
  return capabilityLine(item.policy, policyTrust(item))
}

// Verified means the hosts are exactly the template's; a member may have
// narrowed paths or methods since, which only ever narrows.
export function destinationVerified(item: { provider: string | null; binding: BindingInput }): boolean {
  const hosts = templateHosts(item.provider)
  return hosts !== null && same(hosts, item.binding.hosts)
}
