import { expect, test } from "bun:test"
import { apiErrorExtrasValid, ERROR_CODES, RULE_HEADER, StepUpAction, type ApprovalStatus, type ApprovalView, type ItemDescription, type Me, type PendingKind, type ResetLinkView } from "./api.ts"
import {
  AREA_GRANT_DEFAULT_DURATION, AREA_GRANT_DURATIONS, AREA_GRANT_USES, POLICY_AREA_REFUSALS, PolicyAreaGrantTermsSchema, PolicyAreaProposalSchema, type PolicyAreaGrantTerms, type PolicyAreaGrantView, type PolicyAreaOffer,
} from "./policy-mode.ts"
import { POLICY_REQUEST_LIMIT, POLICY_RULE_WORKLOAD_ID, PolicyRememberSchema, PolicyRuleAskerSchema, PolicyRuleContextSchema, PolicyRuleDecisionSchema, PolicyRuleExtendSchema, PolicyRuleProposalSchema, PolicyRuleProposalStatusSchema, RULE_DEFAULT_DURATION, RULE_DURATIONS, type PolicyGrantStatus, type PolicyRemember, type PolicyRuleOffer, type PolicyRuleProposalStatus } from "./policy-mode.ts"
import { sha256B64 } from "./bytes.ts"
import { canonicalJson } from "./canonical-json.ts"
import { policyAreaGrantTermsDigest, policyRuleExtendDigest } from "./policy-rules.ts"
import { WORKLOAD_ID, WorkloadIdSchema } from "./workload.ts"
import { ItemUseContextSchema, WorkspaceStepUpActionSchema } from "./workspace.ts"

const selector = { device: "dev_x", session: null }
const scope = { host: "api.example.com", methods: ["GET" as const], path: "/v1/**", anchorPath: "/v1/data", basis: "unreviewed" as const }
const approval = { type: "approval.decide" as const, approval: "apr_x", digest: "d", decision: "approve" as const, constraints: { uses: 1, ttlSeconds: 600 } }
const policy = { type: "policy.decide" as const, proposal: "pol_x", digest: "d", decision: "approve" as const, effectDigest: "e" }
const exact: PolicyRemember = { kind: "exact", selector }
const route: PolicyRemember = { kind: "route", selector, policyMode: "relaxed", scope, parent: null }
const rule: PolicyRemember = { kind: "rule", path: "/repos/alex/vault/issues/*/comments", ttlSeconds: 604_800, termsDigest: "a".repeat(43) }

test("policy.decide is strict and binds a nullable deny effect digest", () => {
  expect(StepUpAction.parse(policy)).toEqual(policy)
  expect(StepUpAction.parse({ ...policy, decision: "deny", effectDigest: null })).toMatchObject({ effectDigest: null })
  for (const extra of [{ arbitrary: true }, { floorLifts: [] }, { effectDigest: undefined }, { effectDigest: null }, { decision: "deny", effectDigest: "e" }]) {
    expect(StepUpAction.safeParse({ ...policy, ...extra }).success).toBe(false)
  }
})

test("approval.decide preserves exact-once compatibility and refuses deny with remember", () => {
  expect(StepUpAction.parse(approval)).toEqual(approval)
  expect(StepUpAction.parse({ ...approval, remember: exact })).toMatchObject({ remember: exact })
  expect(StepUpAction.parse({ ...approval, remember: route })).toMatchObject({ remember: route })
  for (const remember of [exact, route]) {
    expect(StepUpAction.safeParse({ ...approval, decision: "deny", remember }).success).toBe(false)
  }
  expect(StepUpAction.parse({ ...approval, decision: "deny" })).toMatchObject({ decision: "deny" })
  for (const extra of [{ arbitrary: true }, { remember: { ...exact, arbitrary: true } }, { remember: { ...route, scope: { ...scope, body: "*" } } }, { constraints: { ...approval.constraints, arbitrary: true } }]) {
    expect(StepUpAction.safeParse({ ...approval, ...extra }).success).toBe(false)
  }
})

test("rule durations are one day, seven days by default, and at most 30 days", () => {
  expect(RULE_DURATIONS).toEqual([86_400, 604_800, 2_592_000])
  expect(RULE_DEFAULT_DURATION).toBe(604_800)
})

test("approval.decide remembers a rule as a path, a duration and the digest of its terms only, and deny cannot", () => {
  expect(StepUpAction.parse({ ...approval, remember: rule })).toMatchObject({ remember: rule })
  expect(WorkspaceStepUpActionSchema.parse({ ...approval, remember: rule })).toMatchObject({ remember: rule })
  for (const ttlSeconds of RULE_DURATIONS) expect(PolicyRememberSchema.safeParse({ ...rule, ttlSeconds }).success).toBe(true)
  expect(StepUpAction.safeParse({ ...approval, decision: "deny", remember: rule }).success).toBe(false)
  expect(WorkspaceStepUpActionSchema.safeParse({ ...approval, decision: "deny", remember: rule }).success).toBe(false)
  for (const patch of [
    { ttlSeconds: 3600 }, { ttlSeconds: 2_592_001 }, { ttlSeconds: "604800" },
    { path: "/repos/alex/vault/issues/**" }, { path: "repos/alex" }, { path: "/repos/../x" },
    { termsDigest: "a".repeat(42) }, { termsDigest: "a".repeat(44) }, { termsDigest: `${"a".repeat(42)}=` }, { termsDigest: null },
    { selector }, { session: "s" }, { workload: "wl_task12345" }, { item: "github-work" }, { method: "POST" }, { host: "api.github.com" }, { graphql: { fields: ["x"] } },
  ]) {
    expect(StepUpAction.safeParse({ ...approval, remember: { ...rule, ...patch } }).success, JSON.stringify(patch)).toBe(false)
  }
  expect(StepUpAction.safeParse({ ...approval, remember: { kind: "rule", path: rule.path } }).success).toBe(false)
  expect(StepUpAction.safeParse({ ...approval, remember: { kind: "rule", path: rule.path, ttlSeconds: rule.ttlSeconds } }).success).toBe(false)
})

test("a rule's asker workload is spelt as WORKLOAD_ID", () => {
  expect(POLICY_RULE_WORKLOAD_ID.source).toBe(WORKLOAD_ID.source)
  expect(POLICY_RULE_WORKLOAD_ID.flags).toBe(WORKLOAD_ID.flags)
  for (const workload of ["wl_task12345", "wl_" + "a".repeat(64), "wl_short", "wl_" + "a".repeat(65), "wl_task 1234", "task12345"]) {
    expect(PolicyRuleAskerSchema.safeParse({ device: "dev_x", workload }).success, workload).toBe(WorkloadIdSchema.safeParse(workload).success)
  }
})

test("the approval page's rule offer is terms with path choices, or a refusal", () => {
  const terms = { item: "linear-work", itemId: "itm_linear01", asker: { device: "dev_x", workload: null }, method: "POST" as const, host: "api.linear.app", path: "/graphql", anchorPath: "/graphql", queryNames: [], graphql: { fields: ["commentCreate"], nestedFields: ["success"] }, ttlSeconds: RULE_DEFAULT_DURATION }
  const offered: ApprovalView["rememberOptions"] = { route: null, rule: { terms, termsDigest: "d", pathChoices: ["/graphql"], refused: null, coSign: true } }
  const refused: PolicyRuleOffer = { terms: null, termsDigest: null, pathChoices: [], refused: "rule.send", coSign: false }
  const without: ApprovalView["rememberOptions"] = { route: null }
  expect(offered?.rule?.coSign).toBe(true)
  expect(offered?.rule?.terms?.graphql).toEqual({ fields: ["commentCreate"], nestedFields: ["success"] })
  expect(refused.refused).toBe("rule.send")
  expect(without).not.toHaveProperty("rule")
  // @ts-expect-error An offer either carries terms or a refusal, never both.
  const both: PolicyRuleOffer = { terms, termsDigest: "d", pathChoices: [], refused: "rule.send", coSign: false }
  expect(both.refused).toBe("rule.send")
})

test("a rule proposal names an approval or an example request for one item, never a session or mode", () => {
  expect(PolicyRuleProposalSchema.parse({ from: { approval: "apr_x" }, reason: "Comments on Linear" })).toEqual({ from: { approval: "apr_x" }, reason: "Comments on Linear" })
  const example = { item: "linear-work", method: "POST", url: "https://api.linear.app/graphql", bodyBase64: "e30=" }
  expect(PolicyRuleProposalSchema.safeParse({ from: example, path: "/graphql", ttlSeconds: 86_400, reason: "r" }).success).toBe(true)
  for (const bodyBase64 of ["", "AAAA", "eyI6MX0=", "eyJhIjoxfQ==", "A".repeat(POLICY_REQUEST_LIMIT - 4096)]) {
    expect(PolicyRuleProposalSchema.safeParse({ from: { ...example, bodyBase64 }, reason: "r" }).success, bodyBase64.slice(0, 16)).toBe(true)
  }
  for (const input of [
    { from: { ...example, method: "DELETE" }, reason: "r" },
    { from: { method: "POST", url: "https://api.linear.app/graphql" }, reason: "r" },
    { from: { ...example, item: "Linear Work" }, reason: "r" },
    { from: { ...example, bodyBase64: "e30" }, reason: "r" },
    { from: { ...example, bodyBase64: "e30==" }, reason: "r" },
    { from: { ...example, bodyBase64: "e3=0" }, reason: "r" },
    { from: { ...example, bodyBase64: "e31=" }, reason: "r" },
    { from: { ...example, bodyBase64: "eyJ9-_==" }, reason: "r" },
    { from: { ...example, bodyBase64: "A".repeat(POLICY_REQUEST_LIMIT + 4) }, reason: "r" },
    { from: { ...example, bodyBase64: "A".repeat(POLICY_REQUEST_LIMIT - 256) }, reason: "r".repeat(500) },
    { from: { approval: "apr_x" }, ttlSeconds: 3600, reason: "r" },
    { from: { approval: "apr_x" }, reason: " " },
    { from: { approval: "apr_x" }, reason: "r", session: "s" },
    { from: { approval: "apr_x" }, reason: "r", policyMode: "yolo" },
    { from: { approval: "apr_x", context: { project: "prj_a", environment: "dev" } }, reason: "r" },
  ]) {
    expect(PolicyRuleProposalSchema.safeParse(input).success, JSON.stringify(input).slice(0, 200)).toBe(false)
  }
})

test("an example proposal may name the context it is made in, spelt as a relay request's", () => {
  const example = { item: "linear-work", method: "POST", url: "https://api.linear.app/graphql" }
  expect(PolicyRuleProposalSchema.parse({ from: { ...example, context: { project: "prj_a", environment: "dev" } }, reason: "r" }).from).toMatchObject({ context: { project: "prj_a", environment: "dev" } })
  for (const context of [{ project: "prj_a", environment: "dev" }, { project: "", environment: "dev" }, { project: "prj_a", environment: "" }, { project: "p".repeat(129), environment: "dev" }, { project: "prj_a", environment: "e".repeat(33) }, { project: "prj_a" }, { project: "prj_a", environment: "dev", run: "run_x" }]) {
    expect(PolicyRuleContextSchema.safeParse(context).success, JSON.stringify(context)).toBe(ItemUseContextSchema.safeParse(context).success)
    expect(PolicyRuleProposalSchema.safeParse({ from: { ...example, context }, reason: "r" }).success).toBe(ItemUseContextSchema.safeParse(context).success)
  }
})

test("phase 1 response contracts retain optional metadata and compatible grants", () => {
  const base: ApprovalStatus = { approval: "apr_x", status: "approved", bindingCode: "CODE", summary: "Read", expiresAt: "later", grant: { id: "gnt_x", uses: 1, expiresAt: "later", kind: "exact", scope: { selector, route: null }, parent: null } }
  const grant: PolicyGrantStatus = { id: "gnt_x", uses: null, expiresAt: "later", kind: "route", scope: { selector, route: scope }, parent: "pov_x" }
  const status: ApprovalStatus = { ...base, status: "revoked", item: "example-key", grant, policyContext: { selector, guardDigest: "g", reasons: [] }, rememberOptions: { route: { scope, policyMode: "relaxed", maxTtlSeconds: 600 } } }
  const viewOptions: ApprovalView["rememberOptions"] = { route: null }
  const closed: ApprovalView["status"][] = ["revoked", "stale"]
  const withoutFloor: Pick<ItemDescription, "policyFloor"> = {}
  const withFloor: Pick<ItemDescription, "policyFloor"> = { policyFloor: [] }
  expect(base).not.toHaveProperty("item")
  expect(status.grant).toEqual(grant)
  expect(viewOptions.route).toBeNull()
  expect(closed).toEqual(["revoked", "stale"])
  expect(withoutFloor).not.toHaveProperty("policyFloor")
  expect(withFloor.policyFloor).toEqual([])
  // @ts-expect-error Floor lifts are phase 2 only.
  const floorLifts: Pick<ItemDescription, "floorLifts"> = {}
  expect(Object.keys(floorLifts)).toEqual([])
})

test("Me has five required flags, and no ENV or phase 2 action/code leaks in", () => {
  const capabilities: Me["capabilities"] = { environmentV2: false, runBaseUrl: false, runFiles: false, sealedEnvImport: false, policyV1: false }
  expect(Object.keys(capabilities).sort()).toEqual(["environmentV2", "policyV1", "runBaseUrl", "runFiles", "sealedEnvImport"])
  // @ts-expect-error Every capability must be supplied by the server.
  const incomplete: Me["capabilities"] = { policyV1: false }
  expect(incomplete.policyV1).toBe(false)
  for (const type of ["project.configure", "environment.import.commit", "policy.control"]) expect(StepUpAction.safeParse({ type }).success).toBe(false)
  expect(ERROR_CODES).not.toContain("stale")
  expect(ERROR_CODES).not.toContain("file_conflict")
  expect(ERROR_CODES).not.toContain("manifest_mismatch")
  const kinds: PendingKind[] = ["policy", "policy-review"]
  expect(kinds).toHaveLength(2)
  // @ts-expect-error Import is phase 2 only.
  const future: PendingKind = "import"
  expect(String(future)).toBe("import")
  const reset: ResetLinkView = { member: "mem_x", memberName: "Alex", createdBy: { kind: "break-glass" }, createdAt: "now", expiresAt: "later" }
  expect(reset.createdBy.kind).toBe("break-glass")
})

test("a remembered approval's status names the rule it made, or the proposal a co-signer must approve", () => {
  const base: ApprovalStatus = { approval: "apr_x", status: "approved", bindingCode: "CODE", summary: "s", expiresAt: "2026-11-03T10:00:00.000Z" }
  const made: ApprovalStatus = { ...base, rule: { id: "rul_x", endsAt: "2026-11-10T10:00:00.000Z" } }
  const proposed: ApprovalStatus = { ...base, ruleProposal: { id: "pol_x", url: "https://vault.test/w/work/p/pol_x", bindingCode: "CODE", expiresAt: "2026-11-04T10:00:00.000Z" } }
  expect(made.rule?.id).toBe("rul_x")
  expect(proposed.ruleProposal?.id).toBe("pol_x")
  expect(RULE_HEADER).toBe("Mehen-Rule")
})

test("a rule proposal's status has a stage and the rule it made, and nothing else", () => {
  const status: PolicyRuleProposalStatus = { proposal: "pol_x", item: "linear-work", status: "pending", stage: "approve", bindingCode: "CODE", summary: "s", expiresAt: "2026-11-04T10:00:00.000Z", rule: null }
  expect(PolicyRuleProposalStatusSchema.parse(status)).toEqual(status)
  expect(PolicyRuleProposalStatusSchema.parse({ ...status, status: "approved", rule: { id: "rul_x", endsAt: "2026-11-10T10:00:00.000Z" } }).rule?.id).toBe("rul_x")
  for (const bad of [{ ...status, stage: "review" }, { ...status, rule: { id: "pov_x", endsAt: status.expiresAt } }, { ...status, outcome: null }, (({ stage: _stage, ...rest }) => rest)(status)]) expect(PolicyRuleProposalStatusSchema.safeParse(bad).success).toBe(false)
})

test("a rule decision approves with a narrowed path and a listed duration, or denies with nothing", () => {
  expect(PolicyRuleDecisionSchema.parse({ decision: "approve", effective: { path: "/graphql", ttlSeconds: 86_400 } }).decision).toBe("approve")
  expect(PolicyRuleDecisionSchema.parse({ decision: "deny" })).toEqual({ decision: "deny" })
  for (const bad of [{ decision: "approve", effective: { path: "/v1/**", ttlSeconds: 86_400 } }, { decision: "approve", effective: { path: "/graphql", ttlSeconds: 3600 } }, { decision: "deny", effective: { path: "/graphql", ttlSeconds: 86_400 } }, { decision: "approve" }]) expect(PolicyRuleDecisionSchema.safeParse(bad).success).toBe(false)
  for (const ttlSeconds of RULE_DURATIONS) expect(PolicyRuleExtendSchema.safeParse({ ttlSeconds }).success).toBe(true)
  expect(PolicyRuleExtendSchema.safeParse({ ttlSeconds: 2_592_001 }).success).toBe(false)
})

test("an extend digest binds the rule and the duration", async () => {
  const digest = await policyRuleExtendDigest("rul_x", 604_800)
  expect(digest).toMatch(/^[A-Za-z0-9_-]{43}$/)
  expect(await policyRuleExtendDigest("rul_y", 604_800)).not.toBe(digest)
  expect(await policyRuleExtendDigest("rul_x", 86_400)).not.toBe(digest)
})

// Task grants: standing rules of kind "area" over a catalogue's reviewed
// routine routes.
const areaTerms: PolicyAreaGrantTerms = { kind: "area", item: "github-work", itemId: "itm_github01", asker: { device: "dev_x", workload: null }, host: "api.github.com", catalogue: "github", catalogueVersion: 1, areas: ["issues"], ttlSeconds: AREA_GRANT_DEFAULT_DURATION, maxUses: AREA_GRANT_USES.default }
const areaRemember: PolicyRemember = { kind: "area", areas: ["issues"], ttlSeconds: 3600, maxUses: 50, termsDigest: "a".repeat(43) }

test("a task grant lasts 15 minutes, an hour by default, or 4 hours, for 50 uses by default and at most 200", () => {
  expect(AREA_GRANT_DURATIONS).toEqual([900, 3600, 14_400])
  expect(AREA_GRANT_DEFAULT_DURATION).toBe(3600)
  expect(AREA_GRANT_USES).toEqual({ default: 50, max: 200 })
})

test("task grant terms are one key, one credential, one host and sorted catalogue areas, for a listed duration and uses", () => {
  expect(PolicyAreaGrantTermsSchema.parse(areaTerms)).toEqual(areaTerms)
  expect(PolicyAreaGrantTermsSchema.safeParse({ ...areaTerms, areas: Array.from({ length: 16 }, (_, i) => `a${String(i).padStart(2, "0")}`), maxUses: 200, ttlSeconds: 14_400, asker: { device: "dev_x", workload: "wl_task12345" } }).success).toBe(true)
  for (const patch of [
    { kind: "rule" }, { areas: [] }, { areas: ["workers", "d1"] }, { areas: ["d1", "d1"] }, { areas: ["D1"] }, { areas: Array.from({ length: 17 }, (_, i) => `a${String(i).padStart(2, "0")}`) },
    { ttlSeconds: 3601 }, { ttlSeconds: 86_400 }, { maxUses: 0 }, { maxUses: 201 }, { maxUses: 1.5 }, { catalogueVersion: 0 }, { catalogue: "" }, { host: "API.github.com" }, { host: "*.github.com" },
    { asker: { device: "dev_x" } }, { itemId: "github-work" }, { path: "/repos/**" }, { method: "POST" },
  ]) {
    expect(PolicyAreaGrantTermsSchema.safeParse({ ...areaTerms, ...patch }).success, JSON.stringify(patch)).toBe(false)
  }
})

test("approval.decide remembers a task grant as areas, a duration, uses and the digest of its terms only, and deny cannot", () => {
  expect(StepUpAction.parse({ ...approval, remember: areaRemember })).toMatchObject({ remember: areaRemember })
  expect(WorkspaceStepUpActionSchema.parse({ ...approval, remember: areaRemember })).toMatchObject({ remember: areaRemember })
  for (const ttlSeconds of AREA_GRANT_DURATIONS) expect(PolicyRememberSchema.safeParse({ ...areaRemember, ttlSeconds }).success).toBe(true)
  expect(WorkspaceStepUpActionSchema.safeParse({ ...approval, decision: "deny", remember: areaRemember }).success).toBe(false)
  for (const patch of [
    { ttlSeconds: RULE_DEFAULT_DURATION }, { maxUses: 201 }, { maxUses: 0 }, { areas: [] }, { areas: ["workers", "d1"] }, { termsDigest: "a".repeat(42) },
    { path: "/repos/**" }, { catalogue: "github" }, { selector },
  ]) {
    expect(WorkspaceStepUpActionSchema.safeParse({ ...approval, remember: { ...areaRemember, ...patch } }).success, JSON.stringify(patch)).toBe(false)
  }
  expect(WorkspaceStepUpActionSchema.safeParse({ ...approval, remember: { kind: "area", areas: ["issues"], ttlSeconds: 3600, termsDigest: "a".repeat(43) } }).success).toBe(false)
})

test("the approval page's task grant offer is terms with every area to tick, or a refusal", () => {
  const offered: ApprovalView["rememberOptions"] = { route: null, area: { terms: areaTerms, termsDigest: "d", areas: [{ id: "issues", name: "Issues", words: "Opens issues", requestArea: true }], refused: null, coSign: false } }
  const refused: PolicyAreaOffer = { terms: null, termsDigest: null, areas: [], refused: "area.not-routine", coSign: false }
  expect(offered?.area?.areas[0]?.requestArea).toBe(true)
  expect(refused.refused).toBe("area.not-routine")
  // @ts-expect-error An offer either carries terms or a refusal, never both.
  const both: PolicyAreaOffer = { terms: areaTerms, termsDigest: "d", areas: [], refused: "area.unreviewed", coSign: false }
  expect(both.refused).toBe("area.unreviewed")
  expect(POLICY_AREA_REFUSALS).toEqual(["area.unreviewed", "area.unknown", "area.not-routine", "area.live-key", "area.duration", "area.uses", "area.terms"])
})

test("a task grant proposal names the held ask, the item and areas, and may name a duration and uses, never a mode or a context", () => {
  const from = { approval: "apr_x" }, area = { item: "github-work", areas: ["issues"] }
  expect(PolicyAreaProposalSchema.parse({ from, area, reason: "Triage the backlog" })).toEqual({ from, area, reason: "Triage the backlog" })
  const full = { from, area: { ...area, areas: ["issues", "pulls"], ttlSeconds: 900 as const, maxUses: 200 }, reason: "r" }
  expect(PolicyAreaProposalSchema.parse(full)).toEqual(full)
  for (const bad of [
    { area, reason: "r" }, { from: { item: "github-work", method: "POST", url: "https://api.github.com/x" }, area, reason: "r" }, { from: { approval: "pol_x" }, area, reason: "r" },
    { from, area: { ...area, mode: "relay" }, reason: "r" }, { from, area: { ...area, context: { project: "prj_a", environment: "dev" } }, reason: "r" },
    { from, area, reason: " " }, { from, area }, { from, area: { ...area, areas: [] }, reason: "r" }, { from, area: { ...area, areas: ["issues", "issues"] }, reason: "r" }, { from, area: { ...area, areas: ["github:issues"] }, reason: "r" },
    { from, area: { ...area, ttlSeconds: 86_400 }, reason: "r" }, { from, area: { ...area, maxUses: 201 }, reason: "r" }, { from, area: { ...area, maxUses: 0 }, reason: "r" }, { from, area: { ...area, path: "/x" }, reason: "r" },
  ]) {
    expect(PolicyAreaProposalSchema.safeParse(bad).success, JSON.stringify(bad)).toBe(false)
  }
  expect(PolicyRuleProposalSchema.safeParse({ from, area, reason: "r" }).success).toBe(false)
})

test("a decision on a task grant proposal approves with areas, a duration and uses, or denies with nothing", () => {
  const effective = { areas: ["issues"], ttlSeconds: 900 as const, maxUses: 25 }
  expect(PolicyRuleDecisionSchema.parse({ decision: "approve", effective })).toEqual({ decision: "approve", effective })
  for (const bad of [
    { decision: "approve", effective: { ...effective, ttlSeconds: 86_400 } }, { decision: "approve", effective: { ...effective, maxUses: 201 } }, { decision: "approve", effective: { ...effective, areas: [] } },
    { decision: "approve", effective: { areas: ["issues"], ttlSeconds: 900 } }, { decision: "approve", effective: { ...effective, path: "/graphql" } }, { decision: "deny", effective },
  ]) {
    expect(PolicyRuleDecisionSchema.safeParse(bad).success, JSON.stringify(bad)).toBe(false)
  }
})

test("a task grant's view adds its uses, receipt and how it ended", () => {
  const view: PolicyAreaGrantView = { ...areaTerms, id: "rul_x", approvedBy: "Alex", coSignedBy: null, context: null, createdAt: "2026-11-05T10:00:00.000Z", endsAt: "2026-11-05T11:00:00.000Z", uses: 6, lastUsedAt: null, status: "ended", receipt: [{ entry: "github.issue-create", words: "Opens an issue", count: 6 }], endedReason: "uses-spent" }
  const endings: PolicyAreaGrantView["endedReason"][] = ["expired", "revoked", "access-changed", "credential-changed", "uses-spent", "replaced", null]
  expect(endings).toContain(view.endedReason)
})

test("a task grant's terms digest binds every term, in its own domain", async () => {
  const digest = await policyAreaGrantTermsDigest(areaTerms)
  expect(digest).toBe(await sha256B64(canonicalJson({ domain: "mehen-area-grant/v1", terms: areaTerms })))
  for (const patch of [{ item: "github-other" }, { itemId: "itm_github02" }, { asker: { device: "dev_x", workload: "wl_task12345" } }, { host: "api.stripe.com" }, { catalogue: "stripe" }, { catalogueVersion: 2 }, { areas: ["issues", "pulls"] }, { ttlSeconds: 900 }, { maxUses: 49 }] as Partial<PolicyAreaGrantTerms>[]) {
    expect(await policyAreaGrantTermsDigest({ ...areaTerms, ...patch }), JSON.stringify(patch)).not.toBe(digest)
  }
})

test("areaRefused rides only on forbidden", () => {
  for (const error of ["forbidden", "bad_request", "conflict", "approval_required"] as const) {
    expect(apiErrorExtrasValid({ error, message: "refused", areaRefused: "area.not-routine" })).toBe(error === "forbidden")
  }
})
