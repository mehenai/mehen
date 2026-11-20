// A resolver-level check: what resolvePolicyRequest, the decision the relay
// takes, gives for a template's credential once a person has set the item's
// own policy to allow everything. Only the template's floors (its approve
// and deny rules, which policy-safety.ts holds per host) can still hold a
// request then. The template tests use it to prove a secret-bearing route
// stays held whatever the item's policy says; the vault's
// relay-template-floors.test.ts runs the relay itself for the same cases.
import { type Binding, type RuleAction, parseDestination } from "../src/binding.ts"
import { resolvePolicyRequest } from "../src/policy-safety.ts"
import type { Template } from "../src/templates.ts"

export function underBroadAllow(template: Template, method: string, url: string, body?: unknown): RuleAction {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(typeof body === "string" ? body : JSON.stringify(body))
  return resolvePolicyRequest({
    destination: parsed.destination,
    body: bytes,
    contentType: body === undefined ? null : "application/json",
    contentEncoding: null,
    policy: { default: "allow", rules: [{ action: "allow", paths: ["/**"], note: "everything" }] },
    binding: template.binding as Binding,
    policyMode: "standard",
    scope: null,
  }).action
}

// The notes of a template's allow rules that admit a read anywhere in its
// binding: no paths, or a path that is the whole API (an open binding path,
// one ending "/**"; an exact binding path names one route).
export function blanketReadAllows(template: Template): string[] {
  const whole = new Set(["/**", "/*", ...(template.binding.paths ?? []).filter((p) => p.endsWith("/**"))])
  return template.policy.rules
    .filter((r) => r.action === "allow" && (r.methods === undefined || r.methods.some((m) => ["GET", "HEAD", "*"].includes(m.toUpperCase()))))
    .filter((r) => r.paths === undefined || r.paths.length === 0 || r.paths.some((p) => whole.has(p)))
    .map((r) => r.note ?? "")
}
