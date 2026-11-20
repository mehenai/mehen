// Standing rules (rul_): a human approved one held request and chose to
// allow that request shape from now on, for one item and the key that
// asked. The vault builds the terms from the stored request (ruleTermsFrom);
// the human only picks one of the vault's path choices and a duration; the
// relay lets a later request through without asking only when the terms
// cover it (ruleCovers). A rule only ever turns an approval into an allow:
// it never touches a deny, the binding or the ceiling. The shapes are in
// policy-mode.ts, which api.ts can import without the safety catalogue.

import { checkBinding, evaluatePolicy, hostMatches, pathMatches, type Binding, type Destination, type Policy } from "./binding.ts"
import { graphqlMutationRootFields } from "./body-match.ts"
import { sha256B64 } from "./bytes.ts"
import { canonicalJson } from "./canonical-json.ts"
import {
  POLICY_RULE_ID_SEGMENT, POLICY_RULE_MAX_NESTED_FIELDS, POLICY_RULE_METHODS, POLICY_RULE_REFUSALS, PolicyAreaGrantTermsSchema, PolicyRuleQueryNameSchema, PolicyRuleTermsSchema, policyRulePathChoices, policyScopeWithinBinding, RULE_DURATIONS,
  AREA_GRANT_DEFAULT_DURATION, AREA_GRANT_DURATIONS, AREA_GRANT_USES,
  type PolicyAreaGrantTerms, type PolicyAreaRefusal, type PolicyRuleRefusal, type PolicyRuleTerms, type Posture, type PostureCatalogue, type PostureLevel, type RuleDuration,
} from "./policy-mode.ts"
import { CATALOGUE_COVERED_TEXT_READERS, catalogueFloorReason, cataloguePathMatches, POLICY_CATALOGUES, policyCatalogueFor, policyCatalogueNamed, type CatalogueEntry, type PolicyCatalogue } from "./policy-catalogue.ts"
import { classifyPolicyRequest, evaluatePolicyFloor, GENERIC_POLICY_FLOOR_WORDS, POLICY_FLOOR, POLICY_FLOOR_REASON_WORDS, policyCatalogueVerdict, policyMethodOverrideParameter, policyPathFloorReasons } from "./policy-safety.ts"
import { OAUTH_PROVIDERS, TEMPLATES } from "./templates.ts"

// A request as the relay holds it, with the item's slug, id and own policy.
export type PolicyRuleRequest = {
  item: string
  itemId: string
  asker: { device: string; workload: string | null }
  destination: Destination
  body: Uint8Array | null
  contentType: string | null
  contentEncoding: string | null
  policy: Policy
}
// The stored request a rule is made from, or a request a rule may cover,
// with what the vault knows of the item at that moment: its binding and the
// prefix of each of its secrets.
export type PolicyRuleAnchor = PolicyRuleRequest & { binding: Binding; secretPrefixes: readonly string[] }
export type PolicyRuleChoice = { path: string; ttlSeconds: number }

const LIVE_KEY_PREFIXES = ["sk_live_", "rk_live_"]
const FORBIDDEN_QUERY_NAMES = ["query", "operationname", "extensions", "documentid"]

const segmentsOf = (path: string): string[] => (path === "/" ? [] : path.slice(1).split("/"))

// The words a GraphQL field may not hold, by the refusal they give: the
// floor's path words and generic words (letters only, so "/env/" is "env"),
// what a destructive mutation is called, and words only a mutation's name
// uses for the floor's reasons.
const FIELD_ONLY_FLOOR_WORDS: Partial<Record<keyof typeof POLICY_FLOOR_REASON_WORDS, string[]>> = { credential: ["admin"], persistence: ["subscribe"], money: ["sponsor"] }
// What a destructive operation is called, in a GraphQL field here and in a
// path on a service nobody has reviewed (mandateRequestFacts).
export const POLICY_DESTRUCTIVE_WORDS = ["delete", "remove", "destroy", "archive", "purge", "revoke", "transfer", "trash", "erase", "wipe", "reset", "suspend", "force"] as const
const FIELD_FLOOR_WORDS: [PolicyRuleRefusal, string[]][] = [
  ["rule.destructive", [...POLICY_DESTRUCTIVE_WORDS]],
  ...(Object.keys(POLICY_FLOOR_REASON_WORDS) as (keyof typeof POLICY_FLOOR_REASON_WORDS)[]).map((reason): [PolicyRuleRefusal, string[]] => [
    `rule.${reason}`, [...POLICY_FLOOR_REASON_WORDS[reason].map((w) => w.replace(/[^a-z]/g, "")), ...(FIELD_ONLY_FLOOR_WORDS[reason] ?? [])],
  ]),
  ["rule.generic", [...GENERIC_POLICY_FLOOR_WORDS]],
]

// The refusals a field's name gives. The name is split at each change
// to upper case, each "_" and each run of digits, and lower-cased; a word
// counts when one part, two neighbouring parts read together, or the whole
// lower-cased name without "_" and digits hold it ("connectionUri" and
// "connectionURIs" hold "connectionuri").
export function fieldFloorRefusals(field: string): PolicyRuleRefusal[] {
  const parts = field.replace(/([a-z])([A-Z])/g, "$1_$2").replace(/([A-Z])([A-Z][a-z])/g, "$1_$2").toLowerCase().split(/[_0-9]+/).filter((p) => p !== "")
  const texts = [...parts, ...parts.slice(1).map((p, i) => `${parts[i]}${p}`), parts.join("")]
  return FIELD_FLOOR_WORDS.filter(([, words]) => words.some((w) => texts.some((t) => t.includes(w)))).map(([reason]) => reason)
}

export function policyRuleTermsDigest(terms: PolicyRuleTerms): Promise<string> {
  return sha256B64(canonicalJson({ domain: "mehen-policy-rule/v1", terms }))
}

// What the passkey signs to create a task grant (PolicyRememberAreaSchema,
// or a policy.decide's effectDigest on a task grant proposal).
export function policyAreaGrantTermsDigest(terms: PolicyAreaGrantTerms): Promise<string> {
  return sha256B64(canonicalJson({ domain: "mehen-area-grant/v1", terms }))
}

// Whether the termsDigest a passkey signed (PolicyRememberRuleSchema) is
// the digest of the terms the vault rebuilt. The vault creates a rule only
// when it is.
export async function policyRuleTermsDigestMatches(terms: PolicyRuleTerms, termsDigest: string): Promise<boolean> {
  return (await policyRuleTermsDigest(terms)) === termsDigest
}

// What the passkey signs to set a credential's posture (the item.posture
// step-up's digest): the item's id, the posture, the catalogue and version
// it covers (null for ask on a credential with no catalogue) and the
// posture revision it replaces (0 when none was ever set), so a posture
// changed since the page read it refuses.
export type ItemPostureTerms = Posture & { item: string; catalogue: string | null; catalogueVersion: number | null; before: number }
export function itemPostureDigest(terms: ItemPostureTerms): Promise<string> {
  return sha256B64(canonicalJson({ domain: "mehen-item-posture/v1", item: terms.item, level: terms.level, machines: terms.machines, catalogue: terms.catalogue, catalogueVersion: terms.catalogueVersion, before: terms.before }))
}

// What the passkey signs to extend a rule (PolicyRuleExtendSchema): the
// effectDigest of a policy.decide whose proposal is the rul_ id.
export function policyRuleExtendDigest(rule: string, ttlSeconds: RuleDuration): Promise<string> {
  return sha256B64(canonicalJson({ domain: "mehen-policy-rule-extend/v1", rule, ttlSeconds }))
}

// The sorted parameter names of a query string; null when one is not a
// plain name, is a GraphQL or method-override parameter, or repeats.
export function queryNamesOf(search: string): string[] | null {
  if (search === "") return []
  if (!search.startsWith("?") || policyMethodOverrideParameter(search) !== null) return null
  const names = search.slice(1).split(/[&;]/).map((part) => part.split("=", 1)[0] ?? "")
  if (names.some((n) => !PolicyRuleQueryNameSchema.safeParse(n).success || FORBIDDEN_QUERY_NAMES.includes(n.toLowerCase()))) return null
  return new Set(names).size === names.length ? [...names].sort() : null
}

// A rule's body is checked as JSON, so it must be sent as exactly JSON: an
// upstream that reads a form or text from the same bytes could find another
// request (or GraphQL query) in them.
export function isJsonType(contentType: string | null): boolean {
  const [media, ...parameters] = (contentType ?? "").toLowerCase().split(";").map((p) => p.trim())
  return media === "application/json" && parameters.every((p, i) => i === 0 && p === "charset=utf-8")
}

type RuleShape = { ok: true; queryNames: string[]; graphql: PolicyRuleTerms["graphql"] } | { ok: false; reason: PolicyRuleRefusal }
// What the floor test found: the most telling refusal, if any; whether the
// request is a GraphQL mutation; and, when one passes, its root fields and
// the names below them.
type FloorTest = { refusal: PolicyRuleRefusal | null; graphql: boolean; graphqlTerms: PolicyRuleTerms["graphql"] }

const catalogueHosts = (...ids: string[]): string[] => ids.flatMap((id) => {
  const hosts = TEMPLATES[id]?.binding.hosts ?? OAUTH_PROVIDERS[id]?.upstream.binding.hosts
  if (hosts === undefined) throw new Error(`No catalogue entry ${id}`)
  return hosts
})

// Catalogue writes whose paths name no floor word but that still never
// become a standing rule. They refuse rules only: whether the relay holds
// one stays with the item's policy.
type RuleOnlyRefusal = { hosts: string[]; methods: string[]; paths: string[]; reason: PolicyRuleRefusal }
const RULE_ONLY_REFUSALS: RuleOnlyRefusal[] = [
  // Creating, changing or answering an event can invite and email its attendees.
  { hosts: catalogueHosts("microsoft-graph"), methods: ["POST", "PUT", "PATCH"], paths: ["/**/events", "/**/events/**"], reason: "rule.send" },
  { hosts: catalogueHosts("google-calendar"), methods: ["POST", "PUT", "PATCH"], paths: ["/calendar/v3/calendars/*/events", "/calendar/v3/calendars/*/events/**"], reason: "rule.send" },
  // A repository's settings can make it public.
  { hosts: catalogueHosts("github-pat", "github-oauth"), methods: ["PATCH"], paths: ["/repos/*/*", "/repositories/*"], reason: "rule.sharing" },
  // An organisation's settings set its members' base permission; a team's
  // settings, repositories and projects give its members access; security
  // managers, blocks and rulesets decide who may read or push.
  {
    hosts: catalogueHosts("github-pat", "github-oauth"),
    methods: ["POST", "PUT", "PATCH"],
    paths: [
      "/orgs/*", "/organizations/*", "/orgs/*/teams/**", "/organizations/*/teams/**", "/organizations/*/team/**", "/teams/*/**",
      "/orgs/*/security-managers/**", "/organizations/*/security-managers/**", "/orgs/*/blocks/**", "/organizations/*/blocks/**", "/orgs/*/rulesets/**", "/organizations/*/rulesets/**",
    ],
    reason: "rule.sharing",
  },
  // A fork, a copy from a template or a Pages site puts a repository's
  // content where others can read it; branch protection and rulesets decide
  // who may push, and an environment's reviewers, protection rules and branch
  // policies who may deploy to it and read its secrets. A branch name may hold
  // a "/", so it spans one or more segments.
  {
    hosts: catalogueHosts("github-pat", "github-oauth"),
    methods: ["POST", "PUT", "PATCH"],
    paths: [
      "/repos/*/*/forks", "/repos/*/*/generate", "/repos/*/*/pages/**", "/repos/*/*/branches/*/**/protection/**", "/repos/*/*/rulesets/**",
      "/repos/*/*/environments/*", "/repos/*/*/environments/*/deployment_protection_rules/**", "/repos/*/*/environments/*/deployment-branch-policies/**",
    ].flatMap((p) => [p, `/repositories/*/${p.slice("/repos/*/*/".length)}`]),
    reason: "rule.sharing",
  },
  // A project's settings can make its source and deployments public or drop
  // their protection, a bypass lets anyone with it past that protection, and
  // a team's settings decide who may join it.
  { hosts: catalogueHosts("vercel"), methods: ["POST", "PUT", "PATCH"], paths: ["/projects/*", "/*/projects/*", "/*/projects/*/protection-bypass", "/teams/*", "/*/teams/*"], reason: "rule.sharing" },
]

// The RULE_ONLY_REFUSALS a request meets, its path in lower case and also
// with each key in parentheses read as a segment of its own, as Graph
// accepts it ("events('E1')" as "events/'E1'").
export function ruleOnlyRefusals(d: Destination): PolicyRuleRefusal[] {
  const path = d.path.toLowerCase()
  const keyed = path.split("/").flatMap((s) => {
    const key = /^([^()]*)\((.*)\)$/.exec(s)
    return key === null ? [s] : [key[1] ?? "", key[2] ?? ""]
  }).join("/")
  return RULE_ONLY_REFUSALS.filter((r) => r.methods.includes(d.method) && r.hosts.some((h) => hostMatches(h, d.host)) && r.paths.some((p) => pathMatches(p, path) || pathMatches(p, keyed))).map((r) => r.reason)
}

// The floor test standing rules, task grants and postures share: why a
// request asks every time, or null. It refuses a deny, a DELETE, a catalogue
// route whose effect is destructive, a method no rule takes, a destination other than HTTPS on 443, the floor (the
// templates' and the catalogue's), a generic path word, a path that names a
// floor reason's word on a route no catalogue reviewed, one of
// RULE_ONLY_REFUSALS, a body the safety checks refuse, and an item rule that
// asks for it. A GraphQL floor or body refusal is lifted only by a
// root-field proof sent as exactly JSON with no query string, naming at most
// POLICY_RULE_MAX_NESTED_FIELDS fields below the root, where no field name,
// at any depth, holds a floor word.
export function policyFloorRefusal(request: PolicyRuleRequest): PolicyRuleRefusal | null {
  return floorTest(request).refusal
}

function floorTest(request: PolicyRuleRequest): FloorTest {
  const d = request.destination
  const refusedAs = (refusal: PolicyRuleRefusal): FloorTest => ({ refusal, graphql: false, graphqlTerms: null })
  if (d.scheme !== "https" || d.port !== 443) return refusedAs("rule.destination")
  if (d.method === "DELETE") return refusedAs("rule.destructive")
  if (!(POLICY_RULE_METHODS as readonly string[]).includes(d.method)) return refusedAs("rule.method")
  const reasons = new Set<PolicyRuleRefusal>()
  let graphql = d.path.split("/").some((s) => s.toLowerCase() === "graphql")
  const base = evaluatePolicy(request.policy, d, request.body)
  if (base.action === "deny") reasons.add("rule.deny")
  for (const rule of base.matched) {
    if (rule.action !== "approve") continue
    if (rule.body === "graphql-mutation") graphql = true
    else reasons.add("rule.item-rule")
  }
  const floor = evaluatePolicyFloor({ destination: d, body: request.body, contentType: request.contentType, contentEncoding: request.contentEncoding })
  if (floor.action === "deny") reasons.add("rule.deny")
  for (const reason of floor.reasons) {
    const entry = POLICY_FLOOR.find((f) => f.id === reason)
    if (entry !== undefined) {
      if (entry.action === "deny") reasons.add("rule.deny")
      else if (entry.reason !== "opaque") reasons.add(`rule.${entry.reason}`)
      else if (entry.rule.body === "graphql-mutation") graphql = true
      else reasons.add("rule.opaque")
      continue
    }
    const catalogued = catalogueFloorReason(reason)
    if (catalogued !== null) reasons.add(`rule.${catalogued}`)
    else if (reason.startsWith("generic.")) reasons.add("rule.generic")
    else if (reason === "safety.graphql-proof") graphql = true
    else if (reason === "safety.destination" || reason === "safety.encoding" || reason === "safety.destination-shape") reasons.add("rule.destination")
    else if (reason.startsWith("safety.")) reasons.add("rule.body")
    else reasons.add("rule.opaque")
  }
  const classification = classifyPolicyRequest({ destination: d, body: request.body, contentType: request.contentType, contentEncoding: request.contentEncoding })
  if (classification.effect === "destructive") reasons.add("rule.destructive")
  // A path that names what the floor's reasons do, where no generic word
  // already refused it and it is no catalogue route (which the generic words
  // skip too, so a repository's name stays its own); for a read, only a word
  // that names an act, so GET /v1/messages stays a rule.
  const read = d.method === "GET" || d.method === "HEAD"
  if (!reasons.has("rule.generic") && classification.routeId === null) {
    for (const reason of policyPathFloorReasons(d.path, read)) reasons.add(`rule.${reason}`)
  }
  for (const reason of ruleOnlyRefusals(d)) reasons.add(reason)
  let graphqlTerms: PolicyRuleTerms["graphql"] = null
  if (graphql) {
    const proof = graphqlMutationRootFields(request.body)
    const nestedFields = proof.ok ? [...new Set(proof.nestedFields)].sort() : []
    if (!proof.ok || d.search !== "" || !sentAsJson(request) || nestedFields.length > POLICY_RULE_MAX_NESTED_FIELDS) reasons.add("rule.graphql")
    else {
      graphqlTerms = { fields: [...proof.fields].sort(), nestedFields }
      for (const field of [...proof.fields, ...proof.nestedFields]) for (const reason of fieldFloorRefusals(field)) reasons.add(reason)
    }
  }
  return { refusal: POLICY_RULE_REFUSALS.find((r) => reasons.has(r)) ?? null, graphql, graphqlTerms }
}

const sentAsJson = (request: PolicyRuleRequest): boolean => request.body === null || isJsonType(request.contentType)

// What a request is as a rule sees it, the same for the anchor and for every
// request a rule later covers: refused when the floor test refuses it, when
// its query names are not plain and unique, or when a body that is not
// GraphQL is not sent as exactly JSON; otherwise its query names and, for
// GraphQL, the mutation's root fields and the real names of the fields
// below them.
function ruleShape(request: PolicyRuleRequest): RuleShape {
  const floor = floorTest(request)
  const reasons = new Set<PolicyRuleRefusal>(floor.refusal === null ? [] : [floor.refusal])
  const queryNames = queryNamesOf(request.destination.search)
  if (queryNames === null) reasons.add("rule.query")
  if (!floor.graphql && !sentAsJson(request)) reasons.add("rule.body")
  const refused = POLICY_RULE_REFUSALS.find((r) => reasons.has(r))
  if (refused !== undefined || queryNames === null) return { ok: false, reason: refused ?? "rule.query" }
  return { ok: true, queryNames, graphql: floor.graphqlTerms }
}

export const holdsLiveKey = (item: Pick<PolicyRuleAnchor, "secretPrefixes">): boolean => item.secretPrefixes.some((p) => LIVE_KEY_PREFIXES.includes(p))

// A rule's path within the binding's paths. A pattern must also name more
// than the binding's own literal prefix, so its "*" never stands for the
// first segment the binding leaves open (policyScopeWithinBinding's
// unreviewed check); the anchor's own path is as narrow as a path gets.
function rulePathWithinBinding(rule: { host: string; method: (typeof POLICY_RULE_METHODS)[number]; path: string; anchorPath: string }, binding: Binding): boolean {
  const scope = { host: rule.host, methods: [rule.method], path: rule.path, anchorPath: rule.anchorPath, basis: rule.path === rule.anchorPath ? "reviewed" as const : "unreviewed" as const }
  return policyScopeWithinBinding(scope, binding)
}

// The terms of a rule made from a stored request and the path and duration
// the human chose among the vault's offers, or why it cannot be one.
export function ruleTermsFrom(anchor: PolicyRuleAnchor, choice: PolicyRuleChoice): { ok: true; terms: PolicyRuleTerms } | { ok: false; reason: PolicyRuleRefusal } {
  if (holdsLiveKey(anchor)) return { ok: false, reason: "rule.live-key" }
  const shape = ruleShape(anchor)
  if (!shape.ok) return shape
  const d = anchor.destination
  if (!checkBinding(anchor.binding, d).ok) return { ok: false, reason: "rule.binding" }
  if (!policyRulePathChoices(d.path).includes(choice.path)) return { ok: false, reason: "rule.path" }
  if (!(RULE_DURATIONS as readonly number[]).includes(choice.ttlSeconds)) return { ok: false, reason: "rule.duration" }
  if (!rulePathWithinBinding({ host: d.host, method: d.method as (typeof POLICY_RULE_METHODS)[number], path: choice.path, anchorPath: d.path }, anchor.binding)) return { ok: false, reason: "rule.binding" }
  const terms = PolicyRuleTermsSchema.safeParse({
    item: anchor.item, itemId: anchor.itemId, asker: anchor.asker, method: d.method, host: d.host, path: choice.path, anchorPath: d.path,
    queryNames: shape.queryNames, graphql: shape.graphql, ttlSeconds: choice.ttlSeconds as RuleDuration,
  })
  return terms.success ? { ok: true, terms: terms.data } : { ok: false, reason: "rule.terms" }
}

// True only when the rule's terms cover this request, given the item's
// binding and secret prefixes as they are now: the same item (slug and id)
// and asker, host and method, a path the pattern matches with an id segment
// in place of its "*", the same query names, and every check ruleTermsFrom
// makes (no live secret, the request's shape and body, the binding, and the
// rule's path within it); for GraphQL, one mutation whose root fields and
// set of field names below them are exactly the rule's.
// True only when the task grant's terms cover this request, given the
// item's binding and secret prefixes as they are now: the same item (slug
// and id), asker and host, a catalogue for that host that still has every
// area and is at least the version signed, no live secret, the binding, no
// floor refusal (policyFloorRefusal), and a routine catalogue entry in one
// of the areas that the catalogue had at that version, its body one
// coveredBody takes.
export function areaGrantCovers(terms: PolicyAreaGrantTerms, request: PolicyRuleAnchor, catalogue: PolicyCatalogue | null = policyCatalogueNamed(terms.catalogue)): boolean {
  return areaGrantEntry(terms, request, catalogue) !== null
}

// The catalogue entry a task grant covers this request as (areaGrantCovers),
// or null: the entry a grant's receipt counts the use under. No query
// string, whatever the floor test says of one.
export function areaGrantEntry(terms: PolicyAreaGrantTerms, request: PolicyRuleAnchor, catalogue: PolicyCatalogue | null = policyCatalogueNamed(terms.catalogue)): CatalogueEntry | null {
  if (!PolicyAreaGrantTermsSchema.safeParse(terms).success || catalogue === null || catalogue.template !== terms.catalogue) return null
  const d = request.destination
  if (request.item !== terms.item || request.itemId !== terms.itemId || request.asker.device !== terms.asker.device || request.asker.workload !== terms.asker.workload) return null
  if (d.host !== terms.host || !catalogue.hosts.includes(d.host) || catalogue.version < terms.catalogueVersion) return null
  if (!terms.areas.every((a) => catalogue.areas.some((area) => area.id === a))) return null
  const entry = routineEntry(request, catalogue)
  if (entry === null || holdsLiveKey(request) || !checkBinding(request.binding, d).ok || !terms.areas.includes(entry.area) || entry.since > terms.catalogueVersion) return null
  return entry
}

// The routine catalogue entry a request is, with no query string, no floor
// refusal, and a body coveredBody takes; or null.
function routineEntry(request: PolicyRuleAnchor, catalogue: PolicyCatalogue): CatalogueEntry | null {
  if (request.destination.search !== "" || policyFloorRefusal(request) !== null) return null
  const { entry } = policyCatalogueVerdict(request, catalogue)
  if (entry === null || entry.effect !== "routine") return null
  return coveredBody(entry, request) ? entry : null
}

// A body a task grant or posture covers on this entry: none or JSON, the
// entry's stored bytes (data), or text one of CATALOGUE_COVERED_TEXT_READERS
// has read. A mandate reads a body the same way (mandateRequestFacts).
export function coveredBody(entry: CatalogueEntry, request: PolicyRuleRequest): boolean {
  return entry.body === "data" || sentAsJson(request) || (typeof entry.body === "object" && CATALOGUE_COVERED_TEXT_READERS.has(entry.body.reader))
}

// What a person picks for a task grant: the areas, how long and how many
// requests. null: the offer's defaults, the request's own area, 1 hour and
// 50 requests.
export type AreaGrantChoice = { areas: readonly string[]; ttlSeconds: number; maxUses: number }
// The task grant a held request can start, built from the stored request,
// the key that sent it and the catalogue for its host as it is now (its
// version is the one signed): the request must be a routine entry of that
// catalogue, and every area chosen one the catalogue has. requestArea: the
// request's own area. Or why not, most telling first (POLICY_AREA_REFUSALS).
export function areaGrantTermsFrom(anchor: PolicyRuleAnchor, choice: AreaGrantChoice | null, catalogue: PolicyCatalogue | null = policyCatalogueFor(anchor.destination.host)): { ok: true; terms: PolicyAreaGrantTerms; requestArea: string } | { ok: false; reason: PolicyAreaRefusal } {
  const d = anchor.destination
  if (catalogue === null || !catalogue.hosts.includes(d.host)) return { ok: false, reason: "area.unreviewed" }
  const entry = routineEntry(anchor, catalogue)
  if (entry === null) return { ok: false, reason: "area.not-routine" }
  if (holdsLiveKey(anchor)) return { ok: false, reason: "area.live-key" }
  if (!checkBinding(anchor.binding, d).ok) return { ok: false, reason: "area.terms" }
  const chosen = choice ?? { areas: [entry.area], ttlSeconds: AREA_GRANT_DEFAULT_DURATION, maxUses: AREA_GRANT_USES.default }
  if (chosen.areas.length === 0 || !chosen.areas.every((a) => catalogue.areas.some((area) => area.id === a))) return { ok: false, reason: "area.unknown" }
  if (!(AREA_GRANT_DURATIONS as readonly number[]).includes(chosen.ttlSeconds)) return { ok: false, reason: "area.duration" }
  if (!Number.isInteger(chosen.maxUses) || chosen.maxUses < 1 || chosen.maxUses > AREA_GRANT_USES.max) return { ok: false, reason: "area.uses" }
  const terms = PolicyAreaGrantTermsSchema.safeParse({
    kind: "area", item: anchor.item, itemId: anchor.itemId, asker: anchor.asker, host: d.host, catalogue: catalogue.template, catalogueVersion: catalogue.version,
    areas: [...new Set(chosen.areas)].sort(), ttlSeconds: chosen.ttlSeconds, maxUses: chosen.maxUses,
  })
  return terms.success ? { ok: true, terms: terms.data, requestArea: entry.area } : { ok: false, reason: "area.terms" }
}

// The catalogue a credential's posture reads: the one whose hosts hold
// every host the credential's binding names, or null (a wildcard host, or
// a host nobody has reviewed), when only ask may be set.
export function postureCatalogueFor(binding: { hosts: readonly string[] }): PolicyCatalogue | null {
  const found = POLICY_CATALOGUES.filter((c) => binding.hosts.length > 0 && binding.hosts.every((h) => c.hosts.includes(h)))
  return found.length === 1 ? (found[0] as PolicyCatalogue) : null
}

// What a posture lets through without asking, given the item as it is now,
// or null when the request still asks. Never a floor refusal
// (policyFloorRefusal), a query string (which the floor test alone lets a
// method override through), a live key or a request outside the binding.
// routine: a routine entry of the catalogue signed, at most its version.
// trust: the same, or a route no catalogue reviewed that a standing rule
// could name (ruleShape: a rule method, a body sent as JSON, no floor word in
// the path). A destructive entry is never covered at any level, whatever the
// floor test says of it. Which machines a level covers is the vault's to
// decide.
export type PostureCoverage = { entry: string } | { entry: "unreviewed" }
export function postureCovers(level: PostureLevel, signed: PostureCatalogue, request: PolicyRuleAnchor, catalogue: PolicyCatalogue | null = policyCatalogueNamed(signed.template)): PostureCoverage | null {
  if (level === "ask" || catalogue === null || catalogue.template !== signed.template || catalogue.version < signed.version) return null
  const d = request.destination
  if (d.search !== "" || !catalogue.hosts.includes(d.host) || holdsLiveKey(request) || !checkBinding(request.binding, d).ok || policyFloorRefusal(request) !== null) return null
  const { entry } = policyCatalogueVerdict(request, catalogue)
  if (entry !== null) {
    if (entry.since > signed.version || !coveredBody(entry, request)) return null
    return entry.effect === "routine" ? { entry: entry.id } : null
  }
  if (level !== "trust" || catalogue.entries.some((e) => (e.methods as readonly string[]).includes(d.method) && cataloguePathMatches(e.path, d.path))) return null
  return ruleShape(request).ok ? { entry: "unreviewed" } : null
}

export function ruleCovers(terms: PolicyRuleTerms, request: PolicyRuleAnchor): boolean {
  if (!PolicyRuleTermsSchema.safeParse(terms).success) return false
  const d = request.destination
  if (request.item !== terms.item || request.itemId !== terms.itemId || request.asker.device !== terms.asker.device || request.asker.workload !== terms.asker.workload) return false
  if (d.host !== terms.host || d.method !== terms.method) return false
  // Segment by segment, so a trailing or doubled "/" (which pathMatches
  // ignores) is another path.
  const pattern = segmentsOf(terms.path)
  const segments = segmentsOf(d.path)
  if (segments.length !== pattern.length || !segments.every((s, i) => (pattern[i] === "*" ? POLICY_RULE_ID_SEGMENT.test(s) : s === pattern[i]))) return false
  if (holdsLiveKey(request)) return false
  if (!checkBinding(request.binding, d).ok || !rulePathWithinBinding(terms, request.binding)) return false
  const shape = ruleShape(request)
  if (!shape.ok || canonicalJson(shape.queryNames) !== canonicalJson(terms.queryNames)) return false
  return canonicalJson(shape.graphql) === canonicalJson(terms.graphql)
}
