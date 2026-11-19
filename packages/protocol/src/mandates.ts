// What a held request is to a mandate, and whether a mandate's terms cover
// it. The shapes are in mandate-terms.ts. Everything
// here is pure: which credentials, machines and signers a mandate reaches,
// its caps and its rate are the vault's.

import { evaluatePolicy, hostMatches, type Binding } from "./binding.ts"
import { graphqlMutationRootFields } from "./body-match.ts"
import { sha256B64 } from "./bytes.ts"
import { canonicalJson } from "./canonical-json.ts"
import { MANDATE_CLASSES, type MandateClass, type MandateSchedule, type MandateState, type MandateTerms } from "./mandate-terms.ts"
import { catalogueFloorReason } from "./policy-catalogue.ts"
import { POLICY_RULE_MAX_NESTED_FIELDS, type PolicyRuleRefusal } from "./policy-mode.ts"
import { coveredBody, fieldFloorRefusals, holdsLiveKey, isJsonType, queryNamesOf, ruleOnlyRefusals, type PolicyRuleAnchor } from "./policy-rules.ts"
import { classifyPolicyRequest, evaluatePolicyFloor, POLICY_FLOOR, policyCatalogueVerdict, policyPathFloorReasons } from "./policy-safety.ts"

// Facts that make a request never covered, whatever a mandate ticks.
export const MANDATE_NEVER_FACTS = ["method", "destination", "deny", "credential", "persistence", "sharing", "money", "generic", "unreadable", "live-key"] as const
export type MandateFact = (typeof MANDATE_NEVER_FACTS)[number] | "send" | "destructive" | "item-rule"

const WRITE_METHODS = ["POST", "PUT", "PATCH"]
const READ_METHODS = ["GET", "HEAD"]
const CLASS_METHODS = [...READ_METHODS, ...WRITE_METHODS, "DELETE"]
const DESTINATION_SAFETY = new Set(["safety.destination", "safety.encoding", "safety.destination-shape", "safety.method-override"])

// The fact a floor refusal word gives: rule.credential is credential, and
// so on; rule.destructive is destructive and rule.generic generic.
function refusalFact(refusal: PolicyRuleRefusal): MandateFact {
  switch (refusal) {
    case "rule.credential": return "credential"
    case "rule.persistence": return "persistence"
    case "rule.sharing": return "sharing"
    case "rule.money": return "money"
    case "rule.send": return "send"
    case "rule.destructive": return "destructive"
    case "rule.generic": return "generic"
    default: return "unreadable"
  }
}

// Every fact about a request, from the same pieces the standing rules'
// floor test reads, without its early return on a DELETE, which is still
// read for everything else it does. A method other than the six a class
// names (OPTIONS included) is the method fact. policyFloorRefusal is
// untouched by this.
export function mandateRequestFacts(request: PolicyRuleAnchor): ReadonlySet<MandateFact> {
  const d = request.destination
  const facts = new Set<MandateFact>()
  const input = { destination: d, body: request.body, contentType: request.contentType, contentEncoding: request.contentEncoding }
  if (d.scheme !== "https" || d.port !== 443) facts.add("destination")
  if (!CLASS_METHODS.includes(d.method)) facts.add("method")
  if (d.method === "DELETE") facts.add("destructive")
  let graphql = d.path.split("/").some((s) => s.toLowerCase() === "graphql")
  const base = evaluatePolicy(request.policy, d, request.body)
  if (base.action === "deny") facts.add("deny")
  for (const rule of base.matched) {
    if (rule.action !== "approve") continue
    if (rule.body === "graphql-mutation") graphql = true
    else facts.add("item-rule")
  }
  const floor = evaluatePolicyFloor(input)
  if (floor.action === "deny") facts.add("deny")
  for (const reason of floor.reasons) {
    const entry = POLICY_FLOOR.find((f) => f.id === reason)
    if (entry !== undefined) {
      if (entry.action === "deny") facts.add("deny")
      else if (entry.reason !== "opaque") facts.add(entry.reason)
      else if (entry.rule.body === "graphql-mutation") graphql = true
      else facts.add("unreadable")
      continue
    }
    const catalogued = catalogueFloorReason(reason)
    if (catalogued !== null) facts.add(catalogued === "opaque" ? "unreadable" : catalogued)
    else if (reason.startsWith("generic.")) facts.add("generic")
    else if (reason === "safety.graphql-proof") graphql = true
    else if (DESTINATION_SAFETY.has(reason)) facts.add("destination")
    else facts.add("unreadable")
  }
  const classification = classifyPolicyRequest(input)
  if (classification.effect === "destructive") facts.add("destructive")
  if (!facts.has("generic") && classification.routeId === null) {
    for (const reason of policyPathFloorReasons(d.path, READ_METHODS.includes(d.method))) facts.add(reason)
  }
  for (const refusal of ruleOnlyRefusals(d)) facts.add(refusalFact(refusal))
  if (graphql) {
    const proof = graphqlMutationRootFields(request.body)
    const nested = proof.ok ? new Set(proof.nestedFields).size : 0
    if (!proof.ok || d.search !== "" || !(request.body === null || isJsonType(request.contentType)) || nested > POLICY_RULE_MAX_NESTED_FIELDS) facts.add("unreadable")
    else for (const field of [...proof.fields, ...proof.nestedFields]) for (const refusal of fieldFloorRefusals(field)) facts.add(refusalFact(refusal))
  }
  if (queryNamesOf(d.search) === null) facts.add("unreadable")
  if (!graphql && request.body !== null && !isJsonType(request.contentType)) {
    const { entry } = policyCatalogueVerdict(input)
    if (entry === null || !coveredBody(entry, request)) facts.add("unreadable")
  }
  if (holdsLiveKey(request)) facts.add("live-key")
  return facts
}

// The classes a request is in, sorted, or never: send for a send,
// delete for anything destructive, change for a write or a request the
// item's own rules ask for, and read for a GET or HEAD in no other class.
export function mandateClassesOf(facts: ReadonlySet<MandateFact>, method: string): MandateClass[] | "never" {
  if (MANDATE_NEVER_FACTS.some((f) => facts.has(f))) return "never"
  const classes = new Set<MandateClass>()
  if (facts.has("send")) classes.add("send")
  if (facts.has("destructive")) classes.add("delete")
  if (WRITE_METHODS.includes(method) || facts.has("item-rule")) classes.add("change")
  if (READ_METHODS.includes(method) && classes.size === 0) classes.add("read")
  return classes.size === 0 ? "never" : MANDATE_CLASSES.filter((c) => classes.has(c))
}

// A mandate reaches a destination only on a host the credential's binding
// names exactly: a wildcard host may admit a subdomain someone else holds.
export function mandateHostNamed(binding: Binding, host: string): boolean {
  return binding.hosts.some((h) => !h.includes("*") && hostMatches(h, host))
}

const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
// The weekday (0 Sunday) and minutes past midnight of a moment in a zone.
function localTime(now: number, tz: string): { day: number; minutes: number } {
  const parts = new Intl.DateTimeFormat("en-GB", { timeZone: tz, weekday: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(new Date(now))
  const part = (type: string): string => parts.find((p) => p.type === type)?.value ?? ""
  return { day: WEEKDAYS.indexOf(part("weekday")), minutes: Number(part("hour")) * 60 + Number(part("minute")) }
}
const minutesOf = (clock: string): number => Number(clock.slice(0, 2)) * 60 + Number(clock.slice(3, 5))

// Whether a moment is inside one of the schedule's windows; always, with none.
export function mandateScheduleOpen(schedule: MandateSchedule | null, now: number): boolean {
  if (schedule === null) return true
  const { day, minutes } = localTime(now, schedule.tz)
  if (day < 0) return false
  const before = (day + 6) % 7
  return schedule.windows.some((w) => {
    const from = minutesOf(w.from), to = minutesOf(w.to)
    if (from < to) return w.days.includes(day) && minutes >= from && minutes < to
    return (w.days.includes(day) && minutes >= from) || (w.days.includes(before) && minutes < to)
  })
}

// The state the vault keeps beside the terms, as covering reads it.
export type MandateCoverView = { state: MandateState; expiresAt: number }
// Whether the terms let these classes through now: active, not expired,
// inside the schedule, and every class ticked. Caps, the credentials, the
// machine, the signer and the binding are the vault's.
export function mandateCovers(terms: Pick<MandateTerms, "classes" | "schedule">, view: MandateCoverView, classes: readonly MandateClass[], now: number): boolean {
  if (view.state !== "active" || now >= view.expiresAt || classes.length === 0) return false
  return mandateScheduleOpen(terms.schedule, now) && classes.every((c) => terms.classes.includes(c))
}

// What a passkey signs to make a mandate (mandate.sign, and mandate.resume
// beside the revision it resumes): the terms, the workspace and the signer.
export function mandateDigest(input: { terms: MandateTerms; workspace: string; signer: string }): Promise<string> {
  return sha256B64(canonicalJson({ domain: "mehen-mandate/v1", terms: input.terms, workspace: input.workspace, signer: input.signer }))
}
