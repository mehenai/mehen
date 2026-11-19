import { z } from "zod"
import type { NextStep, PolicyInput, RequestedBy, StepUpProof } from "./api.ts"
import { StepUpProofSchema } from "./step-up-proof.ts"
import { hostMatches, pathMatches, type Binding, type PolicyDecision, type RuleAction } from "./binding.ts"

export const POLICY_REQUEST_LIMIT = 32 * 1024
export const POLICY_HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] as const
export const PolicyModeSchema = z.enum(["standard", "relaxed", "yolo"])
export const PolicyWindowModeSchema = z.enum(["relaxed", "yolo"])
export const PolicyHttpMethodSchema = z.enum(POLICY_HTTP_METHODS)
export type PolicyMode = z.infer<typeof PolicyModeSchema>
export type PolicyWindowMode = z.infer<typeof PolicyWindowModeSchema>
export type PolicyHttpMethod = z.infer<typeof PolicyHttpMethodSchema>

export const PolicySlugSchema = z.string().regex(/^[a-z][a-z0-9-]{1,63}$/).refine((s) => !s.endsWith("-") && !s.includes("--"), "Invalid item slug")
export const PolicyDeviceIdSchema = z.string().regex(/^dev_[A-Za-z0-9_-]{1,60}$/)
export const PolicyProposalIdSchema = z.string().regex(/^pol_[A-Za-z0-9_-]{1,60}$/)
export const PolicyWindowIdSchema = z.string().regex(/^pov_[A-Za-z0-9_-]{1,60}$/)
export const PolicyGrantIdSchema = z.string().regex(/^gnt_[A-Za-z0-9_-]{1,60}$/)
export const PolicyReviewIdSchema = z.string().regex(/^prv_[A-Za-z0-9_-]{1,60}$/)
export const PolicyItemIdSchema = z.string().regex(/^itm_[A-Za-z0-9_-]{1,60}$/)
export const PolicyRevisionSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)
// What an asker names. Never a workload: the vault takes that from the proof.
export const PolicySelectorSchema = z.strictObject({ device: PolicyDeviceIdSchema, session: z.string().regex(/^[A-Za-z0-9_.:-]{1,120}$/).nullable() })
export const PolicyItemTargetSchema = z.strictObject({ kind: z.literal("item"), item: PolicySlugSchema })

export function isPolicyHost(host: string): boolean {
  if (host.length === 0 || host.length > 253 || host !== host.toLowerCase()) return false
  if (host.startsWith("[")) {
    try { return new URL(`https://${host}/`).hostname === host } catch { return false }
  }
  if (/^[0-9.]+$/.test(host)) {
    try { return new URL(`https://${host}/`).hostname === host } catch { return false }
  }
  return host.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
}

// Scope paths use a smaller canonical alphabet than destinations, so a signed
// pattern has one spelling and cannot change meaning after another decoding.
export function isPolicyPath(path: string, pattern = false): boolean {
  if (path.length === 0 || path.length > 256 || !path.startsWith("/")) return false
  if (path === "/") return true
  const segments = path.slice(1).split("/")
  return segments.every((segment, i) => {
    if (pattern && segment === "*") return true
    if (pattern && segment === "**") return i === segments.length - 1
    return segment !== "." && segment !== ".." && /^[A-Za-z0-9_~!$&'()+,=:@.-]+$/.test(segment)
  })
}

const segmentsOf = (path: string): string[] => path === "/" ? [] : path.slice(1).split("/")

export function policyPathSubset(candidate: string, boundary: string): boolean {
  if (!isPolicyPath(candidate, true) || !isPolicyPath(boundary, true)) return false
  const child = segmentsOf(candidate)
  const parent = segmentsOf(boundary)
  for (let i = 0; i < parent.length; i++) {
    const p = parent[i]
    const c = child[i]
    if (p === "**") return true
    if (c === undefined || c === "**") return false
    if (p !== "*" && p !== c) return false
  }
  return child.length === parent.length
}

export const PolicyRouteScopeSchema = z.strictObject({
  host: z.string().refine(isPolicyHost, "Use a canonical literal host"),
  methods: z.array(PolicyHttpMethodSchema).min(1).max(6).refine((ms) => new Set(ms).size === ms.length, "Methods must be unique")
    .transform((ms) => POLICY_HTTP_METHODS.filter((m) => ms.includes(m))),
  path: z.string().refine((p) => isPolicyPath(p, true), "Use a canonical path pattern"),
  anchorPath: z.string().refine((p) => isPolicyPath(p), "Use a literal canonical anchor path"),
  basis: z.enum(["reviewed", "unreviewed"]),
}).refine((s) => pathMatches(s.path, s.anchorPath), "The pattern must match its anchor")
export type PolicySelector = z.infer<typeof PolicySelectorSchema>
// The selector of a grant or context the vault answers: the asker's, plus the
// workload its proof named when one asked. Such a grant serves only that
// workload, never its device's own key or another workload of the device.
export type PolicyGrantSelector = PolicySelector & { workload?: string }
export type PolicyItemTarget = z.infer<typeof PolicyItemTargetSchema>
export type PolicyRouteScope = z.infer<typeof PolicyRouteScopeSchema>

export function policyLifetime(mode: PolicyWindowMode, basis: PolicyRouteScope["basis"], kind: "mode" | "allow") {
  return {
    minimumSeconds: 60,
    defaultSeconds: mode === "relaxed" && basis === "reviewed" ? 7200 : 3600,
    maximumSeconds: mode === "yolo" ? 7200 : basis === "reviewed" && kind === "mode" ? 86400 : 28800,
  }
}

const DeadlineSchema = z.iso.datetime({ offset: true }).refine((s) => Number.isFinite(Date.parse(s)))
const terms = {
  target: PolicyItemTargetSchema,
  selector: PolicySelectorSchema,
  policyMode: PolicyWindowModeSchema,
  scope: PolicyRouteScopeSchema,
  ttlSeconds: z.number().int().min(60).max(86400),
  notAfter: DeadlineSchema.nullable(),
}
const change = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("mode"), ...terms }),
  z.strictObject({ kind: z.literal("allow"), ...terms }),
]).superRefine((c, ctx) => {
  if (c.ttlSeconds > policyLifetime(c.policyMode, c.scope.basis, c.kind).maximumSeconds) {
    ctx.addIssue({ code: "custom", path: ["ttlSeconds"], message: "The duration exceeds this scope's maximum" })
  }
  if (c.policyMode === "relaxed" && c.scope.methods.includes("DELETE")) {
    ctx.addIssue({ code: "custom", path: ["scope", "methods"], message: "DELETE requires YOLO" })
  }
})

function requestLimit(value: unknown, ctx: z.RefinementCtx): void {
  try {
    if (new TextEncoder().encode(JSON.stringify(value)).length <= POLICY_REQUEST_LIMIT) return
  } catch { /* Non-JSON values are not request bodies. */ }
  ctx.addIssue({ code: "custom", message: "Policy requests must fit in 32 KiB of JSON" })
}

export const PolicyChangeSchema = change.superRefine(requestLimit)
export type PolicyChange = z.infer<typeof PolicyChangeSchema>
export type PolicyTerms = Omit<PolicyChange, "kind">
const preview = { change: PolicyChangeSchema, reason: z.string().min(1).max(500).refine((r) => r.trim().length > 0, "Give a reason") }
export const PolicyPreviewRequestSchema = z.strictObject(preview).superRefine(requestLimit)
export const PolicyProposeSchema = z.strictObject({ ...preview, baseDigest: z.string().regex(/^[A-Za-z0-9_-]{43}$/), slotRevision: PolicyRevisionSchema, fresh: z.boolean().optional() }).superRefine(requestLimit)
export const PolicyDecideSchema = z.discriminatedUnion("decision", [
  z.strictObject({ decision: z.literal("approve"), effectiveChange: PolicyChangeSchema, stepUp: StepUpProofSchema }),
  z.strictObject({ decision: z.literal("deny"), effectiveChange: z.null(), stepUp: StepUpProofSchema }),
]).superRefine(requestLimit)

// How long a standing rule lasts: one day, seven days (the default) or 30
// days (the maximum). Every rule duration is one of these.
export const RULE_DURATIONS = [86_400, 604_800, 2_592_000] as const
export type RuleDuration = (typeof RULE_DURATIONS)[number]
export const RULE_DEFAULT_DURATION: RuleDuration = RULE_DURATIONS[1]
export const RuleDurationSchema = z.literal(RULE_DURATIONS)

// A standing rule's path: literal, or with "*" for whole segments. Never
// "**": a rule covers one route shape, not a subtree.
export function isPolicyRulePath(path: string): boolean {
  return isPolicyPath(path, true) && !segmentsOf(path).includes("**")
}

// Remembering a held request as a standing rule: the human picks one of the
// vault's path choices and a duration, and the passkey signs those with
// termsDigest, the policyRuleTermsDigest of the full terms they make (the
// offer's terms with that path and duration). The vault rebuilds the terms
// from the stored request, the key that signed it, the path and the
// duration (ruleTermsFrom), and creates the rule only when their digest is
// termsDigest (policyRuleTermsDigestMatches).
export const PolicyRememberRuleSchema = z.strictObject({
  kind: z.literal("rule"),
  path: z.string().refine(isPolicyRulePath, "Use a canonical rule path"),
  ttlSeconds: RuleDurationSchema,
  termsDigest: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
})
export type PolicyRememberRule = z.infer<typeof PolicyRememberRuleSchema>

// Standing rules (rul_): what one is and how it is shown. policy-rules.ts
// builds the terms from a held request and decides what they cover.
export const POLICY_RULE_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH"] as const
export const PolicyRuleIdSchema = z.string().regex(/^rul_[A-Za-z0-9_-]{1,60}$/)
// The key that signed the request: the machine's own, or one workload's.
// The workload id is WORKLOAD_ID (workload.ts), spelt again here because
// workload.ts imports workspace.ts, which imports this module; a test holds
// the two the same.
export const POLICY_RULE_WORKLOAD_ID = /^wl_[A-Za-z0-9_-]{8,64}$/
export const PolicyRuleAskerSchema = z.strictObject({ device: PolicyDeviceIdSchema, workload: z.string().regex(POLICY_RULE_WORKLOAD_ID).nullable() })
export const PolicyRuleQueryNameSchema = z.string().regex(/^[A-Za-z0-9_.-]{1,64}$/)
const GraphqlFieldSchema = z.string().regex(/^[_A-Za-z][_0-9A-Za-z]{0,127}$/)
const sortedUnique = (values: readonly string[]): boolean => values.every((v, i) => i === 0 || (values[i - 1] as string) < v)
// The most distinct field names a GraphQL rule pins below the root fields.
export const POLICY_RULE_MAX_NESTED_FIELDS = 64

// An id segment a rule's "*" may stand for: a number or a UUID.
export const POLICY_RULE_ID_SEGMENT = /^(?:[0-9]{1,20}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})$/

// The paths a rule may name for a request to this path, narrowest first:
// the path itself, then it with "*" in place of each id segment, one at a
// time.
export function policyRulePathChoices(anchorPath: string): string[] {
  if (!isPolicyPath(anchorPath)) return []
  const segments = segmentsOf(anchorPath)
  const patterns = segments.flatMap((s, i) => (POLICY_RULE_ID_SEGMENT.test(s) ? [`/${segments.map((t, j) => (j === i ? "*" : t)).join("/")}`] : []))
  return [anchorPath, ...patterns]
}

export const PolicyRuleTermsSchema = z.strictObject({
  item: PolicySlugSchema,
  // The item's id, which the vault fills in, so an item deleted and made
  // again with the same slug never inherits the rule.
  itemId: PolicyItemIdSchema,
  asker: PolicyRuleAskerSchema,
  method: z.enum(POLICY_RULE_METHODS),
  host: z.string().refine(isPolicyHost, "Use a canonical literal host"),
  path: z.string().refine(isPolicyRulePath, "Use a canonical rule path"),
  anchorPath: z.string().refine((p) => isPolicyPath(p), "Use a literal canonical anchor path"),
  // Values are free.
  queryNames: z.array(PolicyRuleQueryNameSchema).max(32).refine(sortedUnique, "Query names are sorted and unique"),
  // The mutation's root fields, and the real names of every field below
  // them, when the anchor is GraphQL.
  graphql: z.strictObject({
    fields: z.array(GraphqlFieldSchema).min(1).max(32).refine(sortedUnique, "Root fields are sorted and unique"),
    nestedFields: z.array(GraphqlFieldSchema).max(POLICY_RULE_MAX_NESTED_FIELDS).refine(sortedUnique, "Nested fields are sorted and unique"),
  }).nullable(),
  ttlSeconds: RuleDurationSchema,
}).refine((t) => policyRulePathChoices(t.anchorPath).includes(t.path), "The path must be the anchor or it with one id segment as *")
  .refine((t) => t.graphql === null || t.queryNames.length === 0, "A GraphQL rule takes no query string")
export type PolicyRuleTerms = z.infer<typeof PolicyRuleTermsSchema>

// context: the project and environment the rule serves, or null for
// requests made outside any project. coSignedBy: the second person, when a
// manager of the credential's home co-signed (name null as for approvedBy).
export type PolicyRuleView = PolicyRuleTerms & {
  id: string
  approvedBy: string | null
  coSignedBy: { name: string | null } | null
  context: PolicyRuleContext | null
  createdAt: string
  endsAt: string
  uses: number
  lastUsedAt: string | null
  status: "active" | "ended"
  endedReason: "expired" | "revoked" | "access-changed" | "credential-changed" | null
}

// Why a request cannot become a standing rule, or be covered by one, most
// telling first. A deny, the floor reasons (credential, persistence,
// sharing, money, send), a DELETE and a destructive catalogue route ask
// every time; the rest are shapes a rule cannot pin down.
export const POLICY_RULE_REFUSALS = [
  "rule.live-key", "rule.destination", "rule.method", "rule.destructive", "rule.deny",
  "rule.credential", "rule.persistence", "rule.sharing", "rule.money", "rule.send", "rule.opaque", "rule.item-rule",
  "rule.generic", "rule.body", "rule.graphql", "rule.query", "rule.binding", "rule.path", "rule.duration", "rule.terms",
] as const
export type PolicyRuleRefusal = (typeof POLICY_RULE_REFUSALS)[number]

// ApprovalView.rememberOptions.rule: the terms at the narrowest path and the
// default duration, their digest (policyRuleTermsDigest), and every path the
// human may pick; or why the request asks every time. coSign: the viewer
// does not manage the credential's home, so approving with the rule
// approves this request once and asks a manager of the home to allow it
// from now on ("Approve once and ask a manager to allow it from now on").
export type PolicyRuleOffer =
  | { terms: PolicyRuleTerms; termsDigest: string; pathChoices: string[]; refused: null; coSign: boolean }
  | { terms: null; termsDigest: null; pathChoices: []; refused: PolicyRuleRefusal; coSign: false }

// Base64 with one spelling per body: padded to a multiple of four, and the
// bits padding leaves over are zero.
const STRICT_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$/

// The project and environment an example request is made in, as a relay
// request names them: ItemUseContextSchema (workspace.ts), spelt again here
// because workspace.ts imports this module; a test holds the two the same.
export const PolicyRuleContextSchema = z.strictObject({ project: z.string().min(1).max(128), environment: z.string().min(1).max(32) })
export type PolicyRuleContext = z.infer<typeof PolicyRuleContextSchema>

// POST /v1/policy/preview and /v1/policy/proposals: a rule from a held or
// approved request, bound to the project, environment and mode it was asked
// in, or from an example request to the item it names, bound to the context
// it names (none: the rule covers only requests made outside any project).
export const PolicyRuleProposalSchema = z.strictObject({
  from: z.union([
    z.strictObject({ approval: z.string().regex(/^apr_[A-Za-z0-9_-]{1,60}$/) }),
    z.strictObject({ item: PolicySlugSchema, method: z.enum(POLICY_RULE_METHODS), url: z.string().min(1).max(2048), bodyBase64: z.string().max(POLICY_REQUEST_LIMIT).regex(STRICT_BASE64).optional(), contentType: z.string().max(256).optional(), context: PolicyRuleContextSchema.optional() }),
  ]),
  path: z.string().refine(isPolicyRulePath, "Use a canonical rule path").optional(),
  ttlSeconds: RuleDurationSchema.optional(),
  reason: z.string().min(1).max(500).refine((r) => r.trim().length > 0, "Give a reason"),
}).superRefine(requestLimit)
export type PolicyRuleProposal = z.infer<typeof PolicyRuleProposalSchema>
export type PolicyRulePreview = { terms: PolicyRuleTerms | null; pathChoices: string[]; summary: string; refused: PolicyRuleRefusal | null }

// The rule a remembered approval made, or the proposal it opened when a
// manager of the credential's home must co-sign: ApprovalStatus.rule and
// ApprovalStatus.ruleProposal (GET /v1/approvals/:id).
export type PolicyRuleRef = { id: string; endsAt: string }
export type PolicyRuleProposalRef = { id: string; url: string; bindingCode: string; expiresAt: string }

// A rule proposal's stage: "approve" waits for the machine's owner (or, for a
// team's machine, an eligible approver); "co-sign" waits for a manager of
// the credential's home after the owner approved.
export const POLICY_RULE_PROPOSAL_STAGES = ["approve", "co-sign"] as const
export type PolicyRuleProposalStage = (typeof POLICY_RULE_PROPOSAL_STAGES)[number]

// GET /v1/policy/proposals/:id (?wait=1), POST /v1/policy/proposals/:id/cancel,
// for a rule proposal. rule: the rule its approval made.
export const PolicyRuleProposalStatusSchema = z.strictObject({
  proposal: PolicyProposalIdSchema,
  item: PolicySlugSchema,
  status: z.enum(["pending", "approved", "denied", "expired", "cancelled", "stale"]),
  stage: z.enum(POLICY_RULE_PROPOSAL_STAGES),
  bindingCode: z.string(),
  summary: z.string(),
  expiresAt: DeadlineSchema,
  rule: z.strictObject({ id: PolicyRuleIdSchema, endsAt: DeadlineSchema }).nullable(),
})
export type PolicyRuleProposalStatus = z.infer<typeof PolicyRuleProposalStatusSchema>
// POST /v1/policy/proposals with a PolicyRuleProposal: 201 when it opened a
// proposal, 200 when the same key's pending proposal for the same terms is
// answered again.
export type PolicyRuleProposalCreated = PolicyRuleProposalStatus & { url: string; next: NextStep }

// GET /v1/policy/rules: this key's rules, live first. The same rows, by item
// or by machine, for a person (policy.rules), who is listed every live rule
// and only the POLICY_RULES_ENDED_LISTED most recently ended.
export type PolicyRuleList = PolicyRuleView[]
export const POLICY_RULES_ENDED_LISTED = 20
// POST /v1/policy/rules/:id/revoke, body {}: the rule, now ended.
export type PolicyRuleRevoked = PolicyRuleView
// A person who may stop a rule but not read its ask (an admin, for a rule
// on a private credential) learns only that it ended.
export type PolicyRuleStopped = Pick<PolicyRuleView, "id" | "status" | "endedReason">

// The proposal page (/w/<slug>/p/<pol_id>), for a person who may read it:
// the terms as the vault rebuilt them, the paths they may narrow to, the
// agent's reason (untrusted text, shown quoted), who approved when it waits
// for a co-signer, and what the person may do. extends: the rule a co-sign
// proposal would give a new deadline, null for a new rule.
export type PolicyRuleProposalView = PolicyRuleProposalStatus & {
  kind: "rule"
  extends: string | null
  requestedBy: RequestedBy
  reason: string | null
  terms: PolicyRuleTerms
  termsDigest: string
  pathChoices: string[]
  digest: string
  // self: the reader is the one who approved, so may not co-sign.
  approvedBy: { name: string | null; self?: boolean } | null
  canApprove: boolean
  canDeny: boolean
}

// Task grants: standing rules of kind "area" (rul_ ids) that cover a
// catalogue's reviewed routine routes in the areas a person ticked, for one
// key and one credential, for a short time and a number of uses.
// policy-rules.ts decides what they cover (areaGrantCovers) and digests the
// terms (policyAreaGrantTermsDigest).
export const AREA_GRANT_DURATIONS = [900, 3600, 14_400] as const
export type AreaGrantDuration = (typeof AREA_GRANT_DURATIONS)[number]
export const AREA_GRANT_DEFAULT_DURATION: AreaGrantDuration = AREA_GRANT_DURATIONS[1]
export const AreaGrantDurationSchema = z.literal(AREA_GRANT_DURATIONS)
export const AREA_GRANT_USES = { default: 50, max: 200 } as const
const AreaGrantUsesSchema = z.number().int().min(1).max(AREA_GRANT_USES.max)
// An area's id within its catalogue (PolicyCatalogue.areas).
export const PolicyAreaIdSchema = z.string().regex(/^[a-z][a-z0-9-]{0,31}$/)
export const POLICY_AREA_GRANT_MAX_AREAS = 16
const PolicyAreaIdsSchema = z.array(PolicyAreaIdSchema).min(1).max(POLICY_AREA_GRANT_MAX_AREAS)
const SortedAreaIdsSchema = PolicyAreaIdsSchema.refine(sortedUnique, "Areas are sorted and unique")

// The areas are sorted and unique; whether the catalogue has them is
// checked where the terms are made and used, not here, so a reader whose
// catalogue is older than the vault's still parses a grant.
export const PolicyAreaGrantTermsSchema = z.strictObject({
  kind: z.literal("area"),
  item: PolicySlugSchema,
  itemId: PolicyItemIdSchema,
  asker: PolicyRuleAskerSchema,
  host: z.string().refine(isPolicyHost, "Use a canonical literal host"),
  // The catalogue's template (PolicyCatalogue.template) and the version the
  // person signed: entries added after it are not covered.
  catalogue: z.string().regex(/^[a-z][a-z0-9-]{0,63}$/),
  catalogueVersion: z.number().int().min(1),
  areas: SortedAreaIdsSchema,
  ttlSeconds: AreaGrantDurationSchema,
  maxUses: AreaGrantUsesSchema,
})
export type PolicyAreaGrantTerms = z.infer<typeof PolicyAreaGrantTermsSchema>

// Remembering a held request as a task grant: the passkey signs the areas,
// duration and uses with termsDigest, the policyAreaGrantTermsDigest of the
// terms the vault rebuilds from the stored request, the key that signed it,
// the catalogue's current version and these choices.
export const PolicyRememberAreaSchema = z.strictObject({
  kind: z.literal("area"),
  areas: SortedAreaIdsSchema,
  ttlSeconds: AreaGrantDurationSchema,
  maxUses: AreaGrantUsesSchema,
  termsDigest: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
})
export type PolicyRememberArea = z.infer<typeof PolicyRememberAreaSchema>

// Why a request cannot start a task grant, or the terms asked for cannot be
// granted, most telling first.
export const POLICY_AREA_REFUSALS = ["area.unreviewed", "area.unknown", "area.not-routine", "area.live-key", "area.duration", "area.uses", "area.terms"] as const
export type PolicyAreaRefusal = (typeof POLICY_AREA_REFUSALS)[number]

// ApprovalView.rememberOptions.area: the terms with the request's own area
// and the default duration and uses, their digest, and every area of the
// catalogue the person may tick (requestArea: the request's own); or why
// the request cannot start one. coSign as for PolicyRuleOffer.
export type PolicyAreaOffer =
  | { terms: PolicyAreaGrantTerms; termsDigest: string; areas: { id: string; name: string; words: string; requestArea: boolean }[]; refused: null; coSign: boolean }
  | { terms: null; termsDigest: null; areas: []; refused: PolicyAreaRefusal; coSign: false }

// POST /v1/policy/proposals: a task grant from a held (still pending) or
// approved request of this key, named as a rule proposal names one, bound to
// the mode and the project and environment (or none) that request was asked
// in. item names the request's credential, as a cross-check. The vault
// rebuilds the terms from the stored request, the key, the catalogue as it
// is now and these choices; a duration and uses not named are the defaults.
export const PolicyAreaProposalSchema = z.strictObject({
  from: z.strictObject({ approval: z.string().regex(/^apr_[A-Za-z0-9_-]{1,60}$/) }),
  area: z.strictObject({
    item: PolicySlugSchema,
    areas: PolicyAreaIdsSchema.refine((areas) => new Set(areas).size === areas.length, "Name each area once"),
    ttlSeconds: AreaGrantDurationSchema.optional(),
    maxUses: AreaGrantUsesSchema.optional(),
  }),
  reason: z.string().min(1).max(500).refine((r) => r.trim().length > 0, "Give a reason"),
})
export type PolicyAreaProposal = z.infer<typeof PolicyAreaProposalSchema>

// A decision's terms on a task grant proposal (PolicyRuleDecisionSchema).
export const PolicyAreaEffectiveSchema = z.strictObject({ areas: SortedAreaIdsSchema, ttlSeconds: AreaGrantDurationSchema, maxUses: AreaGrantUsesSchema })
export type PolicyAreaEffective = z.infer<typeof PolicyAreaEffectiveSchema>

// A task grant as a list shows it. receipt: the uses so far by catalogue
// entry, with the entry's words. endedReason adds "uses-spent" (maxUses
// reached) and "replaced" (a newer grant for the same key and credential).
export type PolicyAreaGrantView = PolicyAreaGrantTerms & {
  id: string
  approvedBy: string | null
  coSignedBy: { name: string | null } | null
  context: PolicyRuleContext | null
  createdAt: string
  endsAt: string
  uses: number
  lastUsedAt: string | null
  status: "active" | "ended"
  receipt: { entry: string; words: string; count: number }[]
  endedReason: PolicyRuleView["endedReason"] | "uses-spent" | "replaced"
}

// The proposal page for a task grant waiting for a co-signer (the one an
// approval's area remember opens when a manager of the credential's home
// must also sign): the terms as the vault rebuilt them, every area of the
// catalogue the co-signer may keep (requestArea: the held request's own),
// and what the person may do. A decision may only narrow the areas,
// duration and uses (PolicyAreaEffective). Never shown to a machine.
export type PolicyAreaProposalView = PolicyRuleProposalStatus & {
  kind: "area"
  extends: null
  requestedBy: RequestedBy
  reason: string | null
  terms: PolicyAreaGrantTerms
  termsDigest: string
  areas: { id: string; name: string; words: string; requestArea: boolean }[]
  digest: string
  approvedBy: { name: string | null; self?: boolean } | null
  canApprove: boolean
  canDeny: boolean
}

// How careful a credential is (its posture), on top of its policy: ask (no
// posture stored) holds every change its policy holds; routine lets a
// catalogue's routine entries through for members' and teams' machines;
// trust lets anything but the floor through for machines whose owner
// manages the credential's home. machines, when set, narrows either to
// those machines, sorted and each once. policy-rules.ts decides what a
// level covers (postureCovers) and digests what a person signs
// (itemPostureDigest).
export const POSTURE_LEVELS = ["ask", "routine", "trust"] as const
export const PostureLevelSchema = z.enum(POSTURE_LEVELS)
export type PostureLevel = z.infer<typeof PostureLevelSchema>
export const POSTURE_MAX_MACHINES = 32
export const PostureSchema = z.strictObject({
  level: PostureLevelSchema,
  machines: z.array(PolicyDeviceIdSchema).min(1).max(POSTURE_MAX_MACHINES).refine(sortedUnique, "Machines are sorted and unique").nullable(),
}).refine((p) => p.level !== "ask" || p.machines === null, "Ask names no machines")
export type Posture = z.infer<typeof PostureSchema>
// The catalogue a posture was signed against: its template and version.
export type PostureCatalogue = { template: string; version: number }

// The proposal page's decision on a rule proposal (POST
// /api/w/<slug>/policy/proposals/:id/action and /decide). Approve may narrow:
// a path among the terms' choices no wider than the proposed one, and a
// duration no longer. The passkey signs policy.decide with effectDigest the
// policyRuleTermsDigest of the terms with that path and duration; deny signs
// effectDigest null.
// On a task grant proposal, approve names the areas, duration and uses,
// which the vault holds to the proposed ones or fewer (PolicyAreaEffective).
export const PolicyRuleDecisionSchema = z.discriminatedUnion("decision", [
  z.strictObject({ decision: z.literal("approve"), effective: z.union([z.strictObject({ path: z.string().refine(isPolicyRulePath, "Use a canonical rule path"), ttlSeconds: RuleDurationSchema }), PolicyAreaEffectiveSchema]) }),
  z.strictObject({ decision: z.literal("deny") }),
])
export type PolicyRuleDecision = z.infer<typeof PolicyRuleDecisionSchema>
// Extending a rule (POST /api/w/<slug>/policy/rules/:id/extend): a new
// deadline ttlSeconds from the moment the vault accepts it, never more than
// 30 days away. The passkey signs policy.decide with proposal the rul_ id,
// digest the rule's termsDigest and effectDigest policyRuleExtendDigest.
export const PolicyRuleExtendSchema = z.strictObject({ ttlSeconds: RuleDurationSchema })
export type PolicyRuleExtend = z.infer<typeof PolicyRuleExtendSchema>
// The extend's answer: the rule with its new deadline, or, when a manager of
// the credential's home must co-sign, the rule as it was and the co-sign
// proposal whose approval sets the new deadline.
export type PolicyRuleExtended = { rule: PolicyRuleView; coSign: PolicyRuleProposalRef | null }

export const PolicyRememberSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("exact"), selector: PolicySelectorSchema }),
  z.strictObject({ kind: z.literal("route"), selector: PolicySelectorSchema, policyMode: PolicyWindowModeSchema, scope: PolicyRouteScopeSchema, parent: PolicyWindowIdSchema.nullable() })
    .refine((r) => r.policyMode === "yolo" || !r.scope.methods.includes("DELETE"), "DELETE requires YOLO"),
  PolicyRememberRuleSchema,
  PolicyRememberAreaSchema,
]).superRefine(requestLimit)
export type PolicyPreviewRequest = z.infer<typeof PolicyPreviewRequestSchema>
export type PolicyPropose = z.infer<typeof PolicyProposeSchema>
export type PolicyDecide = { decision: "approve" | "deny"; effectiveChange: PolicyChange | null; stepUp: StepUpProof }
export type PolicyRemember = z.infer<typeof PolicyRememberSchema>

export function policyScopeWithinBinding(scope: PolicyRouteScope, binding: Binding): boolean {
  if (!PolicyRouteScopeSchema.safeParse(scope).success) return false
  if (!binding.hosts.some((h) => hostMatches(h, scope.host))) return false
  if (binding.methods?.length && !scope.methods.every((m) => binding.methods?.some((b) => b === "*" || b.toUpperCase() === m))) return false
  const paths = binding.paths?.length ? binding.paths : ["/**"]
  if (!paths.some((p) => policyPathSubset(scope.path, p))) return false
  const matching = paths.filter((p) => pathMatches(p, scope.anchorPath))
  const prefixLength = (p: string): number => {
    const segs = segmentsOf(p)
    const wildcard = segs.findIndex((s) => s.includes("*"))
    return wildcard < 0 ? segs.length : wildcard
  }
  const boundary = Math.max(0, ...matching.map(prefixLength))
  return scope.basis !== "unreviewed" || prefixLength(scope.path) > boundary
}

export function isPolicyNarrowing(requested: PolicyChange, effective: PolicyChange): boolean {
  if (!PolicyChangeSchema.safeParse(requested).success || !PolicyChangeSchema.safeParse(effective).success) return false
  if (requested.kind !== effective.kind || requested.target.item !== effective.target.item || requested.selector.device !== effective.selector.device || requested.selector.session !== effective.selector.session) return false
  if (requested.scope.host !== effective.scope.host || requested.scope.basis !== effective.scope.basis || requested.scope.anchorPath !== effective.scope.anchorPath) return false
  if (requested.policyMode === "relaxed" && effective.policyMode !== "relaxed") return false
  if (effective.ttlSeconds > requested.ttlSeconds) return false
  if (requested.notAfter !== null && (effective.notAfter === null || Date.parse(effective.notAfter) > Date.parse(requested.notAfter))) return false
  if (!effective.scope.methods.every((m) => requested.scope.methods.includes(m))) return false
  if (!policyPathSubset(effective.scope.path, requested.scope.path)) return false
  const before = segmentsOf(requested.scope.path)
  const anchor = segmentsOf(requested.scope.anchorPath)
  return segmentsOf(effective.scope.path).every((s, i) => {
    const inTail = before.indexOf("**") >= 0 && i >= before.indexOf("**")
    return s === before[i] || ((before[i] === "*" || inTail) && (s === anchor[i] || inTail && s === "**"))
  })
}

export function policyExpiresAt(change: PolicyChange, now: number, parentExpiresAt: string | null = null): string | null {
  if (!PolicyChangeSchema.safeParse(change).success || !Number.isFinite(now)) return null
  const expires = Math.min(now + change.ttlSeconds * 1000, change.notAfter === null ? Infinity : Date.parse(change.notAfter), parentExpiresAt === null ? Infinity : Date.parse(parentExpiresAt))
  return Number.isFinite(expires) && Math.abs(expires) <= 8.64e15 && expires - now >= 60000 ? new Date(expires).toISOString() : null
}

export function resolvePolicyMode(base: PolicyDecision, mode: PolicyMode, effect: "read" | "routine" | "destructive" | "unknown", eligible: boolean): RuleAction {
  if (base.action !== "approve" || base.matched.length !== 0 || mode === "standard" || !eligible || effect === "unknown") return base.action
  return effect === "destructive" && mode !== "yolo" ? "approve" : "allow"
}

export type PolicySecuritySnapshot = { itemId: string; device: string; configRev: number; scopeRev: number; protectionRev: number; safetyDigest: string; frozen: boolean }
export type PolicyFloorView = { id: string; host: string; action: "deny" | "approve"; reason: "credential" | "persistence" | "send" | "money" | "sharing" | "destructive" | "opaque"; rule: PolicyInput["rules"][number]; ruleDigest: string }
export type PolicyWidening = { id: string; kind: "mode" | "route-grant"; item: string; selector: PolicyGrantSelector; policyMode: PolicyWindowMode; scope: PolicyRouteScope; expiresAt: string; parent: string | null; reviewUrl: string; stopUrl: string }
export type PolicyState = { widening: PolicyWidening[]; observedAt: string }
export type PolicyContext = { item: string; selector: PolicyGrantSelector; baseMode: "standard"; effectiveMode: PolicyMode; basePolicy: PolicyInput; floor: PolicyFloorView[]; snapshot: PolicySecuritySnapshot; baseDigest: string; slotRevision: number; predecessor: PolicyWidening | null; state: PolicyState }
export type PolicyDiff = { field: string; before: string; after: string; effect: "narrower" | "wider" | "unchanged" }[]
export type PolicyPreview = { change: PolicyChange; reason: string; context: PolicyContext; baseDigest: string; slotRevision: number; summary: string; diff: PolicyDiff; warnings: string[] }
const policyOutcomeSchema = z.strictObject({
  change: PolicyChangeSchema,
  override: PolicyWindowIdSchema.nullable(),
  grant: PolicyGrantIdSchema.nullable(),
  effectiveUntil: DeadlineSchema,
  active: z.boolean(),
  endedReason: z.enum(["expired", "revoked", "replaced", "stale", "exhausted"]).nullable(),
})
export type PolicyOutcome = z.infer<typeof policyOutcomeSchema>
export const PolicyProposalStatusSchema = z.strictObject({
  proposal: PolicyProposalIdSchema,
  item: PolicySlugSchema,
  status: z.enum(["pending", "approved", "denied", "expired", "cancelled", "stale"]),
  bindingCode: z.string(),
  summary: z.string(),
  expiresAt: DeadlineSchema,
  outcome: policyOutcomeSchema.nullable(),
})
export type PolicyProposalStatus = z.infer<typeof PolicyProposalStatusSchema>
export type PolicyProposalCreated = PolicyProposalStatus & { url: string; next: NextStep }
export type PolicyProposalView = PolicyProposalStatus & { requestedBy: RequestedBy; requestedByViewer: RequestedBy; requested: PolicyChange; reason: string; context: PolicyContext; baseDigest: string; digest: string; diff: PolicyDiff; warnings: string[] }
export type PolicyStopped = { id: string; stopped: string[]; status: "revoked"; effectiveAt: string }
export type PolicyGrantStatus = { id: string; uses: number | null; expiresAt: string; kind: "exact" | "route"; scope: { selector: PolicyGrantSelector; route: PolicyRouteScope | null }; parent: string | null }
export type PolicyApprovalContext = { selector: PolicyGrantSelector; guardDigest: string; reasons: string[] }
export type PolicyActivityRow = { seq: number; at: string; device: string; session: string | null; item: string; method: string; host: string; routeId: string | null; requestDigest: string; widened: boolean }
export type PolicyActivity = { source: PolicyWidening; active: boolean; authorised: number; widened: number; rows: PolicyActivityRow[]; before: string | null; review: { id: string; acknowledgedAt: string | null } | null }
