// Standing rules in the vault (areas/policy-rules-workspace.ts): the offer
// on an approval, remember, the relay's use of a rule, proposals, revoke,
// extend, every way a rule ends, and the POLICY_RULES switch. Direct-area
// calls through the workspace ops, as the other relay and approval tests.
import { afterEach, describe, expect, it } from "vitest"
import { RULE_HEADER, base64UrlEncode, createProof, type CredentialHome, type WorkspaceDeviceScope, type WorkspaceRunCreated, type WorkspaceStepUpAction } from "@mehen/protocol"
import { POLICY_RULES_ENDED_LISTED, type PolicyRuleOffer, type PolicyRuleTerms, type PolicyRuleView, type RuleDuration } from "@mehen/protocol/policy-mode"
import { policyRuleExtendDigest, policyRuleTermsDigest } from "@mehen/protocol/policy-rules"
import { VaultError } from "../src/http.ts"
import type { InboxItem } from "@mehen/protocol/inbox"
import { inboxRow, inboxRowOf } from "../src/ui/inbox-row.ts"
import { auditLine, formatTime } from "../src/ui/wording.ts"
import { TEMPLATES } from "@mehen/protocol/templates"
import { ruleOfferMatches, ruleProposalDecision, ruleProposalEffect, ruleProposalMatches } from "../src/ui/client/workspace-logic.ts"
import { approvalSubjectOf } from "../src/ui/pages/workspace-asks.ts"
import type { AccessPrincipal } from "../src/vault/access.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { storedApprovalProjection, workspaceApproval, workspaceApprovalOps } from "../src/vault/areas/approvals-workspace.ts"
import { prepareCredential, storeCredential } from "../src/vault/areas/items-workspace.ts"
import { workspacePolicyOps } from "../src/vault/areas/policy-workspace.ts"
import { authoriseWorkspaceRelay } from "../src/vault/areas/relay-workspace.ts"
import { accessState, openAskCount, principalOf as invocationPrincipal, type WorkspaceInvocationContext } from "../src/vault/areas/workspace-runtime.ts"
import type { AccountInvocationAuth } from "../src/vault/core.ts"
import { forwardRelay } from "../src/relay/forward.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { installSecurity, newMember, setSetting, updateRestriction } from "../src/vault/areas/workspace-runtime.ts"
import { workspacePendingOps } from "../src/vault/areas/pending-workspace.ts"
import { workspaceDeviceOps } from "../src/vault/areas/workspace-devices.ts"
import { workspaceItemOps } from "../src/vault/areas/items-workspace.ts"
import { policyArea } from "../src/vault/areas/policy.ts"
import { RULE_ANCHOR_SWEEP_KEY, WORKSPACE_POLICY_AREA_GRANTS_MIGRATION, WORKSPACE_POLICY_RULES_MIGRATION, WORKSPACE_POLICY_RULE_ANCHORS_MIGRATION, approvalRuleView, policyRulesOn } from "../src/vault/areas/policy-rules-workspace.ts"
import { applyMigrations } from "../src/vault/tenant-vault.ts"
import { accountAuth, editAccessFixture, installTestIdentity } from "./access-test-support.ts"
import { PROJECT_RUN_INPUT, approvedProjectRun, projectFixture } from "./projects-workspace-fixture.ts"
import { seedRelayProject, seedRelayVar } from "./relay-fixtures.ts"
import { registerCredentialProvider } from "../src/vault/areas/items-workspace.ts"
import { workspaceRunOps } from "../src/vault/areas/runs-workspace.ts"
import { credentialInput, credentialsFixture, deviceInvocation, devicePrincipal, inAccess, memberInvocation, memberPrincipal } from "./credentials-test-support.ts"
import { createWorkspaceIntake } from "../src/vault/areas/intake-workspace.ts"
import { fixtureSql } from "./fixture-sql.ts"
import { withTrustedSchema } from "../src/vault/areas/management-guard.ts"

afterEach(() => setUpstreamFetch(null))

const DAY = 86_400_000
const enc = (value: unknown): Uint8Array<ArrayBuffer> => new TextEncoder().encode(JSON.stringify(value)) as Uint8Array<ArrayBuffer>
const COMMENT_CREATE = "mutation CommentCreate($input: CommentCreateInput!) { commentCreate(input: $input) { success comment { id } } }"
const comment = (body: string) => ({ query: COMMENT_CREATE, variables: { input: { issueId: "ISS-1", body } }, operationName: "CommentCreate" })
const mutation = (field: string) => ({ query: `mutation { ${field}(input: {}) { success } }` })
type Body = { bytes: Uint8Array<ArrayBuffer>; contentType: string } | null
const json = (value: unknown): Body => ({ bytes: enc(value), contentType: "application/json" })

// A Linear key: its template holds every mutation for approval.
async function seedLinear(ctx: VaultContext, home: CredentialHome = { kind: "workspace" }, slug = "linear-work", secret = "lin_api_fixture0000000000000000") {
  const creator = home.kind === "member" ? home.member.slice(4) : "owner"
  const input = { ...credentialInput(slug, home), provider: null, binding: { hosts: ["api.linear.app"], paths: ["/graphql"], methods: ["POST" as const] }, policy: { default: "approve" as const, rules: [] }, injection: { in: "header" as const, name: "Authorization", format: "{key}" }, secretFields: { key: secret } }
  const prepared = await prepareCredential(ctx, input, null)
  return ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx, creator), "item.create"))
}
// A key with no template whose policy holds every request.
async function seedTasks(ctx: VaultContext, secret = "test-secret-never-returned", slug = "tasks-key") {
  const input = { ...credentialInput(slug), policy: { default: "approve" as const, rules: [] }, secretFields: { key: secret } }
  const prepared = await prepareCredential(ctx, input, null)
  return ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
}

type Asker = { device: string; workload?: string }
const principalOf = (asker: Asker): AccessPrincipal => ({ kind: "device", deviceId: asker.device, ...(asker.workload ? { workload: asker.workload } : {}) })
async function invocationOf(ctx: VaultContext, asker: Asker): Promise<WorkspaceInvocationContext> {
  const proof = await createProof({ deviceId: asker.device, ...(asker.workload ? { workloadId: asker.workload } : {}), sign: async () => new Uint8Array(64) }, { method: "POST", url: "https://vault.test/v1/relay" }, { tenant: ctx.tenant })
  return { workspace: { id: ctx.tenant, slug: "work", name: "Work" }, auth: { kind: "device", proof, method: "POST", url: "https://vault.test/v1/relay", bodyHash: "" } }
}
// A machine that may use its owner's private credentials.
function seesPrivate(ctx: VaultContext, device: string) {
  const scope = JSON.parse(ctx.sql.exec<{ scope: string }>("SELECT scope FROM devices WHERE id=?", device).toArray()[0]!.scope) as Record<string, unknown>
  ctx.sql.exec("UPDATE devices SET scope=? WHERE id=?", JSON.stringify({ ...scope, privateCredentials: true }), device)
}
function addWorkload(ctx: VaultContext, id: string, device: string) {
  ctx.sql.exec("INSERT INTO workloads(id,device,label,jwk,thumbprint,scope,created_at,expires_at,hard_expires_at) VALUES (?,?,?,'{}',?,'{}',?,?,?)", id, device, id, `thumb-${id}`, ctx.now(), ctx.now() + 40 * DAY, ctx.now() + 40 * DAY)
}

type Sent = { item: string; url: string; body: Body; method?: string; context?: { project: string; environment: string } }
const linearCall = (body: unknown, item = "linear-work"): Sent => ({ item, url: "https://api.linear.app/graphql", body: json(body) })
const relayInput = (sent: Sent) => ({ item: sent.item, method: sent.method ?? "POST", url: sent.url, headers: sent.body ? [["content-type", sent.body.contentType] as [string, string]] : [], ...(sent.body ? { body: base64UrlEncode(sent.body.bytes) } : {}), ...(sent.context ? { context: sent.context } : {}) })

// The relay's answer: the material when allowed, or the refusal.
async function relay(ctx: VaultContext, sent: Sent, asker: Asker = { device: "dev_owner" }) {
  try { return { material: await authoriseWorkspaceRelay(ctx, principalOf(asker), relayInput(sent), await invocationOf(ctx, asker)), error: null } }
  catch (error) { if (error instanceof VaultError) return { material: null, error }; throw error }
}
async function held(ctx: VaultContext, sent: Sent, asker: Asker = { device: "dev_owner" }): Promise<string> {
  const { error } = await relay(ctx, sent, asker)
  expect(error?.code).toBe("approval_required")
  return error!.extra.approval!
}

// A machine's example request for a Linear comment, as `mehen policy propose` sends it.
const exampleComment = (item: string) => ({ item, method: "POST", url: "https://api.linear.app/graphql", bodyBase64: Buffer.from(JSON.stringify(comment("x"))).toString("base64"), contentType: "application/json" })

const ops = { ...workspaceApprovalOps, ...workspacePolicyOps, ...workspacePendingOps, ...workspaceDeviceOps }
// A person by role, a person's own account auth, or a machine key.
type Who = string | Asker | AccountInvocationAuth
async function op(ctx: VaultContext, name: string, who: Who, input: unknown, action?: WorkspaceStepUpAction): Promise<any> {
  const handler = ops[name]!.handler
  if (typeof who === "string") return handler(ctx, memberPrincipal(ctx, who), input, memberInvocation(ctx, who, action))
  if ("kind" in who) {
    const auth = { ...who, ...(action ? { stepUp: action, stepUpFactor: "pk_fixture" } : {}) }
    return handler(ctx, invocationPrincipal(ctx, auth), input, { auth, workspace: { id: ctx.tenant, slug: "work", name: "Work" } })
  }
  return handler(ctx, principalOf(who), input, await invocationOf(ctx, who))
}
async function offerOf(ctx: VaultContext, role: Who, approval: string): Promise<PolicyRuleOffer | undefined> {
  const view = await op(ctx, "approvals.view", role, { id: approval })
  return view.view === "detail" ? view.approval.rememberOptions?.rule : undefined
}
// "Approve and allow this from now on", the step-up signed as the page would.
async function remember(ctx: VaultContext, role: Who, approval: string, choice: { path?: string; ttlSeconds?: RuleDuration; termsDigest?: string } = {}) {
  const offer = await offerOf(ctx, role, approval)
  if (!offer?.terms) throw new Error(`No rule offered: ${offer?.refused}`)
  const path = choice.path ?? offer.terms.path, ttlSeconds = choice.ttlSeconds ?? offer.terms.ttlSeconds
  const input = { id: approval, decision: "approve", remember: { kind: "rule", path, ttlSeconds, termsDigest: choice.termsDigest ?? await policyRuleTermsDigest({ ...offer.terms, path, ttlSeconds }) } }
  const action = await op(ctx, "approvals.action", role, input)
  return op(ctx, "approvals.decide", role, input, action)
}
const rulesOf = (ctx: VaultContext, asker: Asker = { device: "dev_owner" }): Promise<PolicyRuleView[]> => op(ctx, "policy.rules", asker, {})
const count = (ctx: VaultContext, sql: string, ...args: unknown[]) => ctx.sql.exec<{ n: number }>(`SELECT count(*) AS n FROM ${sql}`, ...args).toArray()[0]!.n
const at = (ctx: VaultContext, ms: number): VaultContext => Object.assign(Object.create(ctx) as VaultContext, { now: () => ms })
// A deadline set during the test, read against the test's real clock.
function expectEndsIn(ctx: VaultContext, endsAt: string, ms: number) {
  const left = Date.parse(endsAt) - ctx.now()
  expect(left).toBeGreaterThan(ms - 5_000)
  expect(left).toBeLessThanOrEqual(ms)
}
const switched = (ctx: VaultContext, value: string): VaultContext => Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, POLICY_RULES: value } })
// A list naming only other workspaces: off here, exactly as "off" is.
const UNLISTED = "tn_elsewhere0001, tn_elsewhere0002"
const switchedOff = (ctx: VaultContext, value = "off"): VaultContext => switched(ctx, value)
// The test env leaves standing rules off, as production does; this file
// switches them on for each workspace it opens.
const inRules = <T>(tenant: string, fn: (ctx: VaultContext) => T | Promise<T>): Promise<T> => inAccess(tenant, (ctx) => fn(switched(ctx, "on")))
async function decide(ctx: VaultContext, who: Who, input: unknown) {
  const action = await op(ctx, "policy.action", who, input)
  return op(ctx, "policy.decide", who, input, action)
}
// A rule's stored terms carry the duration its end was last set by, under their own digest.
async function expectStoredTerms(ctx: VaultContext, id: string, ttlSeconds: RuleDuration) {
  const row = ctx.sql.exec<{ terms: string; terms_digest: string }>("SELECT terms,terms_digest FROM policy_rules WHERE id=?", id).toArray()[0]!
  const terms = JSON.parse(row.terms) as PolicyRuleTerms
  expect(terms.ttlSeconds).toBe(ttlSeconds)
  expect(row.terms_digest).toBe(await policyRuleTermsDigest(terms))
}
async function extend(ctx: VaultContext, who: Who, id: string, ttlSeconds: RuleDuration) {
  const action = await op(ctx, "policy.rules.extend-action", who, { id, ttlSeconds })
  expect(action).toMatchObject({ type: "policy.decide", proposal: id, effectDigest: await policyRuleExtendDigest(id, ttlSeconds) })
  return op(ctx, "policy.rules.extend", who, { id, ttlSeconds }, action)
}

describe("a machine at its 20 open asks", () => {
  it("is refused a rule proposal with the link to its oldest open ask, and nothing is proposed", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const oldest = await held(ctx, linearCall(comment("First")))
      const asker = devicePrincipal("dev_owner"), invocation = await deviceInvocation(ctx, "dev_owner")
      for (let n = 1; n < 20; n++) createWorkspaceIntake(ctx, asker, { kind: "api-key", slug: `asked-${n}`, reason: "test", binding: { hosts: ["api.example.com"] }, home: "project", project: "prj_a" }, invocation)
      expect(openAskCount(ctx, "dev_owner", ctx.now())).toBe(20)
      await expect(op(ctx, "policy.propose", { device: "dev_owner" }, { from: exampleComment("linear-work"), reason: "Comment on issues" })).rejects.toMatchObject({ code: "rate_limited", message: "This machine already has 20 open asks. Settle one before asking again.", extra: { next: { url: `https://vault.test/w/work/a/${oldest}`, say: "Ask the person to decide this machine's open asks at the link, then ask for the rest." } } })
      expect(count(ctx, "policy_proposals")).toBe(0)
    })
  })
})

describe("remember and cover", () => {
  it("makes a rule from the approved request; the next commentCreate passes with Mehen-Rule and counts its use", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const approval = await held(ctx, linearCall(comment("First")))
      const offer = await offerOf(ctx, "owner", approval)
      expect(offer).toMatchObject({ refused: null, coSign: false, pathChoices: ["/graphql"], terms: { method: "POST", host: "api.linear.app", path: "/graphql", graphql: { fields: ["commentCreate"] }, asker: { device: "dev_owner", workload: null }, ttlSeconds: 604_800 } })
      await remember(ctx, "owner", approval)
      const [rule] = await rulesOf(ctx)
      expect(rule).toMatchObject({ status: "active", uses: 0, approvedBy: "owner", coSignedBy: null, context: null, endedReason: null })
      expect(Date.parse(rule!.endsAt) - Date.parse(rule!.createdAt)).toBe(7 * DAY)
      // The owner's consent names the rule it made.
      expect(ctx.sql.exec<{ decision: string }>("SELECT decision FROM consent_lineage WHERE id=(SELECT lineage FROM policy_rules WHERE id=?)", rule!.id).toArray()[0]?.decision).toBe(`rule:${rule!.id}`)
      expect(await op(ctx, "approvals.status", { device: "dev_owner" }, { id: approval })).toMatchObject({ status: "approved", rule: { id: rule!.id, endsAt: rule!.endsAt } })

      let sends = 0
      setUpstreamFetch(async () => { sends++; return new Response("ok") })
      for (const text of ["Second", "Third"]) {
        const { material, error } = await relay(ctx, linearCall(comment(text)))
        expect(error).toBeNull()
        expect(material!.rules).toEqual([rule!.id])
        const response = await forwardRelay(material!, enc(comment(text)))
        expect(response.headers.get(RULE_HEADER)).toBe(rule!.id)
      }
      expect(sends).toBe(2)
      const [used] = await rulesOf(ctx)
      expect(used).toMatchObject({ uses: 2 })
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(2)
      expect(count(ctx, "audit WHERE action='rule.create'")).toBe(1)
      expect(count(ctx, "approvals")).toBe(1)
    })
  })

  it("reads the clock once, so a rule lasts exactly its duration however the clock moves while it is made", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      // Every read of this clock is a millisecond later than the one before.
      let tick = ctx.now()
      const ticking = Object.assign(Object.create(ctx) as VaultContext, { now: () => tick++ })
      await remember(ticking, "owner", await held(ctx, linearCall(comment("First"))))
      const created = await op(ctx, "policy.propose", { device: "dev_owner" }, { from: exampleComment("linear-work"), reason: "Comment on issues" })
      await decide(ticking, "owner", { id: created.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 86_400 } })
      const rules = await rulesOf(at(ctx, tick))
      expect(rules.map((r) => Date.parse(r.endsAt) - Date.parse(r.createdAt)).sort((a, b) => a - b)).toEqual([DAY, 7 * DAY])
    })
  })

  it("holds issueDelete under a commentCreate rule, and never offers one for it", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      await remember(ctx, "owner", await held(ctx, linearCall(comment("First"))))
      const again = await held(ctx, linearCall(mutation("issueDelete")))
      expect(await offerOf(ctx, "owner", again)).toEqual({ terms: null, termsDigest: null, pathChoices: [], refused: "rule.destructive", coSign: false })
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(0)
    })
  })

  it("refuses a remember whose signed digest is not the vault's terms, and stores nothing", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const approval = await held(ctx, linearCall(comment("First")))
      const offer = (await offerOf(ctx, "owner", approval))!
      const wrong = await policyRuleTermsDigest({ ...offer.terms!, graphql: { fields: ["issueDelete"], nestedFields: [] } })
      await expect(remember(ctx, "owner", approval, { termsDigest: wrong })).rejects.toMatchObject({ code: "conflict" })
      expect(count(ctx, "policy_rules")).toBe(0)
      expect(count(ctx, "approvals WHERE status='pending'")).toBe(1)
    })
  })

  it("refuses a remember on deny, and keeps exact and route refused", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const approval = await held(ctx, linearCall(comment("First")))
      const offer = (await offerOf(ctx, "owner", approval))!
      const rule = { kind: "rule", path: "/graphql", ttlSeconds: 604_800, termsDigest: offer.termsDigest }
      await expect(op(ctx, "approvals.action", "owner", { id: approval, decision: "deny", remember: rule })).rejects.toMatchObject({ code: "bad_request" })
      await expect(op(ctx, "approvals.action", "owner", { id: approval, decision: "approve", remember: { kind: "exact", selector: { device: "dev_owner", session: null } } })).rejects.toMatchObject({ code: "forbidden", message: "Policy widening is not available yet." })
    })
  })

  // Task grants parse but nothing grants one yet: an area remember
  // is refused where an exact or route one is, and an area decision on a
  // rule proposal is not a rule's.
  // Task grants themselves: test/policy-area-grants.test.ts.
  it("refuses an area remember for a service nobody reviewed on approvals.action and approvals.decide, and an area effective on a rule proposal's action, and stores nothing", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const approval = await held(ctx, linearCall(comment("First")))
      const input = { id: approval, decision: "approve", remember: { kind: "area", areas: ["issues"], ttlSeconds: 3600, maxUses: 50, termsDigest: "A".repeat(43) } }
      const unreviewed = { error: "forbidden", message: "Nobody has reviewed this service's routes, so this request cannot start a task grant.", areaRefused: "area.unreviewed" }
      for (const name of ["approvals.action", "approvals.decide"]) {
        const error = await op(ctx, name, "owner", input).then(() => null, (e: unknown) => e)
        expect(error, name).toBeInstanceOf(VaultError)
        expect((error as VaultError).toJSON(), name).toEqual(unreviewed)
      }
      expect(count(ctx, "approvals WHERE status='pending'")).toBe(1)
      const created = await op(ctx, "policy.propose", { device: "dev_owner" }, { from: exampleComment("linear-work"), reason: "Comment on issues" })
      await expect(op(ctx, "policy.action", "owner", { id: created.proposal, decision: "approve", effective: { areas: ["issues"], ttlSeconds: 3600, maxUses: 50 } })).rejects.toMatchObject({ code: "bad_request" })
      expect(count(ctx, "policy_rules")).toBe(0)
    })
  })
})

describe("the approval page after a remember", () => {
  it("names the rule, or the proposal waiting for a co-signer, to a person who may read it", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const mine = await held(ctx, linearCall(comment("First")))
      const decided = await remember(ctx, "owner", mine)
      const [rule] = await rulesOf(ctx)
      const ref = { id: rule!.id, endsAt: rule!.endsAt }
      expect(decided.approval).toMatchObject({ status: "approved", rule: ref, ruleProposal: null })
      expect((await op(ctx, "approvals.view", "owner", { id: mine })).approval).toMatchObject({ rule: ref, ruleProposal: null })

      const theirs = await held(ctx, linearCall(comment("Second")), { device: "dev_member" })
      const asked = await remember(ctx, "member", theirs)
      const proposal = (await op(ctx, "approvals.status", { device: "dev_member" }, { id: theirs })).ruleProposal
      expect(asked.approval).toMatchObject({ rule: null, ruleProposal: proposal })
      expect((await op(ctx, "approvals.view", "owner", { id: theirs })).approval).toMatchObject({ rule: null, ruleProposal: proposal })
      await decide(ctx, "owner", { id: proposal.id, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } })
      const [cosigned] = await rulesOf(ctx, { device: "dev_member" })
      expect((await op(ctx, "approvals.view", "member", { id: theirs })).approval).toMatchObject({ rule: { id: cosigned!.id, endsAt: cosigned!.endsAt }, ruleProposal: null })
      // An approval that remembered nothing names neither.
      const once = await held(ctx, linearCall(mutation("issueDelete")))
      const yes = { id: once, decision: "approve" }
      expect(await op(ctx, "approvals.decide", "owner", yes, await op(ctx, "approvals.action", "owner", yes))).not.toHaveProperty("approval.rule")
      expect(await op(ctx, "approvals.view", "owner", { id: once })).not.toHaveProperty("approval.ruleProposal")
    })
  })

  // The service team's machine asks in project B for a credential homed in
  // project A. The member manages B only, so a rule they approve for it waits
  // for Kim, who manages A; an admin manages both and needs no co-signer.
  async function serviceInProjectB(ctx: VaultContext): Promise<string> {
    await seedLinear(ctx, { kind: "project", project: "prj_a" }, "linear-project")
    const item = ctx.sql.exec<{ id: string }>("SELECT id FROM items WHERE slug='linear-project'").toArray()[0]!.id
    editAccessFixture(ctx, (state) => { state.projects[1]!.environments[0]!.references.push({ variable: "LINEAR", field: "key", item, home: { kind: "project", project: "prj_a" }, revision: 1 }) })
    for (const [id, kind, subject, level] of [["shr_service_b", "team", "tm_service", "use"], ["shr_member_b", "member", "mem_member", "manage"]] as const) {
      const share = { id, project: "prj_b", subject: kind === "team" ? { kind, team: subject } : { kind, member: subject }, level, protected: false, expiresAt: null }
      fixtureSql(ctx).exec("INSERT INTO project_shares VALUES (?,?,?,?,?)", id, "prj_b", kind, subject, JSON.stringify(share))
    }
    return held(ctx, { ...linearCall(comment("First"), "linear-project"), context: { project: "prj_b", environment: "dev" } }, { device: "dev_service" })
  }
  // The service machine's proposal from that approval, approved by the member and co-signed by Kim.
  async function coSignedProposalFrom(ctx: VaultContext, approval: string): Promise<string> {
    const created = await op(ctx, "policy.propose", { device: "dev_service" }, { from: { approval }, reason: "Comment on issues" })
    const decision = { id: created.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } }
    await decide(ctx, "member", decision)
    await decide(ctx, "kim", decision)
    const rule = ctx.sql.exec<{ id: string; source: string }>("SELECT id,source FROM policy_rules WHERE id=(SELECT outcome FROM policy_proposals WHERE id=?)", created.proposal).toArray()[0]!
    // A co-signed proposal's rule names the approval it came from as its source.
    expect(rule.source).toBe(approval)
    return rule.id
  }

  it("does not name a rule a machine's proposal from the approval made, even once it is extended directly", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      const approval = await serviceInProjectB(ctx)
      const yes = { id: approval, decision: "approve" }
      await op(ctx, "approvals.decide", "member", yes, await op(ctx, "approvals.action", "member", yes))
      const rule = await coSignedProposalFrom(ctx, approval)
      const unnamed = async () => {
        expect(await op(ctx, "approvals.view", "admin", { id: approval })).not.toHaveProperty("approval.rule")
        expect(await op(ctx, "approvals.status", { device: "dev_service" }, { id: approval })).not.toHaveProperty("rule")
      }
      await unnamed()
      expect((await extend(ctx, "admin", rule, 2_592_000)).coSign).toBeNull()
      await unnamed()
    })
  })

  it("names only the remember's rule when a machine's proposal from the same approval makes another", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      const approval = await serviceInProjectB(ctx)
      expect((await offerOf(ctx, "admin", approval))?.coSign).toBe(false)
      await remember(ctx, "admin", approval)
      const remembered = ctx.sql.exec<{ id: string }>("SELECT id FROM policy_rules").toArray()[0]!.id
      const proposed = await coSignedProposalFrom(ctx, approval)
      expect(proposed).not.toBe(remembered)
      expect((await op(ctx, "approvals.view", "admin", { id: approval })).approval.rule.id).toBe(remembered)
      expect((await op(ctx, "approvals.status", { device: "dev_service" }, { id: approval })).rule.id).toBe(remembered)
    })
  })

  it("names a directly remembered rule after an extension a second person co-signed, with its new end", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      const approval = await serviceInProjectB(ctx)
      await remember(ctx, "admin", approval)
      const remembered = ctx.sql.exec<{ id: string }>("SELECT id FROM policy_rules").toArray()[0]!.id
      // The member manages prj_b, not the credential's home, so Kim co-signs.
      const extended = await extend(ctx, "member", remembered, 2_592_000)
      expect(extended.coSign).not.toBeNull()
      await decide(ctx, "kim", { id: extended.coSign.id, decision: "approve", effective: { path: "/graphql", ttlSeconds: 2_592_000 } })
      const endsAt = ctx.sql.exec<{ expires_at: number }>("SELECT expires_at FROM policy_rules WHERE id=?", remembered).toArray()[0]!.expires_at
      const ref = { id: remembered, endsAt: new Date(endsAt).toISOString() }
      expect((await op(ctx, "approvals.view", "admin", { id: approval })).approval).toMatchObject({ rule: ref, ruleProposal: null })
      expect(await op(ctx, "approvals.status", { device: "dev_service" }, { id: approval })).toMatchObject({ rule: ref })
    })
  })

  it("names a remembered rule after it is extended, with its new end", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const approval = await held(ctx, linearCall(comment("First")))
      await remember(ctx, "owner", approval, { ttlSeconds: 86_400 })
      const [rule] = await rulesOf(ctx)
      const extended = await extend(ctx, "owner", rule!.id, 2_592_000)
      const ref = { id: rule!.id, endsAt: extended.rule.endsAt }
      expect((await op(ctx, "approvals.view", "owner", { id: approval })).approval).toMatchObject({ rule: ref, ruleProposal: null })
      expect(await op(ctx, "approvals.status", { device: "dev_owner" }, { id: approval })).toMatchObject({ rule: ref })
    })
  })

  it("names nothing to a person who may only stop the ask, and nothing at all with the switch off", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx, { kind: "member", member: "mem_member" }, "linear-mine")
      seesPrivate(ctx, "dev_member")
      const approval = await held(ctx, linearCall(comment("First"), "linear-mine"), { device: "dev_member" })
      await remember(ctx, "member", approval)
      const stop = await op(ctx, "approvals.view", "admin", { id: approval })
      expect(stop.view).toBe("stop")
      expect(JSON.stringify(stop)).not.toContain("rul_")
      // The stop view never asks for the refs, so ask the rule's own check:
      // it names the rule to whoever reads the detail, and to no one else.
      const refsFor = (role: string) => approvalRuleView(ctx, accessState(ctx), memberPrincipal(ctx, role), memberInvocation(ctx, role), approval)
      const [rule] = await rulesOf(ctx, { device: "dev_member" })
      expect(refsFor("member")).toEqual({ rule: { id: rule!.id, endsAt: rule!.endsAt }, ruleProposal: null })
      expect(refsFor("admin")).toBeNull()
      // With the switch off the page reads exactly as the stored approval's projection, as before rules.
      const off = switchedOff(ctx)
      const asBefore = JSON.stringify(storedApprovalProjection(off, accessState(off), memberPrincipal(off, "member"), workspaceApproval(off, approval)!))
      expect(JSON.stringify(await op(off, "approvals.view", "member", { id: approval }))).toBe(asBefore)
      const later = await held(off, linearCall(comment("Second"), "linear-mine"), { device: "dev_member" })
      const yes = { id: later, decision: "approve" }
      const decided = await op(off, "approvals.decide", "member", yes, await op(off, "approvals.action", "member", yes))
      expect(JSON.stringify(decided)).toBe(JSON.stringify(storedApprovalProjection(off, accessState(off), memberPrincipal(off, "member"), workspaceApproval(off, later)!)))
      expect(decided.approval).not.toHaveProperty("rule")
    })
  })
})

describe("what never becomes a rule", () => {
  const floors: [string, string][] = [["issueDelete", "rule.destructive"], ["webhookCreate", "rule.persistence"], ["organizationInviteCreate", "rule.sharing"], ["apiKeyCreate", "rule.credential"], ["emailSend", "rule.send"], ["createSponsorship", "rule.money"]]
  it("refuses each floor class at the offer, and the relay holds each under a commentCreate rule", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      await remember(ctx, "owner", await held(ctx, linearCall(comment("First"))))
      for (const [field, reason] of floors) {
        const approval = await held(ctx, linearCall(mutation(field)))
        expect((await offerOf(ctx, "owner", approval))?.refused).toBe(reason)
      }
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(0)
    })
  })

  it("holds a request a \"*\" rule's path matches when a query value holds a floor word", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedTasks(ctx)
      const task = (id: string, view: string): Sent => ({ item: "tasks-key", method: "PATCH", url: `https://api.example.com/tasks/${id}?view=${view}`, body: json({ done: true }) })
      await remember(ctx, "owner", await held(ctx, task("123", "full")), { path: "/tasks/*" })
      setUpstreamFetch(async () => new Response("ok"))
      expect((await relay(ctx, task("456", "full"))).material?.rules).toHaveLength(1)
      const again = await held(ctx, task("456", "webhook"))
      expect((await offerOf(ctx, "owner", again))?.refused).toBe("rule.generic")
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(1)
    })
  })

  it("refuses a rule for a held custom POST whose path names a send, offered or proposed, and makes none", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedTasks(ctx)
      const approval = await held(ctx, { item: "tasks-key", url: "https://api.example.com/v1/messages/send", body: json({ to: "someone@example.com", text: "hi" }) })
      expect(await offerOf(ctx, "owner", approval)).toEqual({ terms: null, termsDigest: null, pathChoices: [], refused: "rule.send", coSign: false })
      await expect(op(ctx, "policy.propose", { device: "dev_owner" }, { from: { approval }, reason: "Send messages" })).rejects.toMatchObject({ code: "forbidden", extra: { ruleRefused: "rule.send" } })
      expect(count(ctx, "policy_rules")).toBe(0)
    })
  })

  it("holds a form-encoded body and refuses it a rule", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedTasks(ctx)
      const form: Sent = { item: "tasks-key", url: "https://api.example.com/tasks", body: { bytes: enc("title=a"), contentType: "application/x-www-form-urlencoded" } }
      expect((await offerOf(ctx, "owner", await held(ctx, form)))?.refused).toBe("rule.body")
    })
  })

  it("refuses a live key", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedTasks(ctx, "sk_live_fixture000000000000000000")
      expect((await offerOf(ctx, "owner", await held(ctx, { item: "tasks-key", url: "https://api.example.com/tasks", body: json({ title: "a" }) })))?.refused).toBe("rule.live-key")
    })
  })
})

describe("who may make a rule", () => {
  it("never offers one to a guest", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx, { kind: "member", member: "mem_guest" }, "linear-guest")
      seesPrivate(ctx, "dev_guest")
      const approval = await held(ctx, linearCall(comment("First"), "linear-guest"), { device: "dev_guest" })
      const view = await op(ctx, "approvals.view", "guest", { id: approval })
      expect(view.approval.eligibility.canApprove).toBe(true)
      expect(view.approval.rememberOptions).toBeUndefined()
    })
  })

  it("lets a private credential's owner allow it from now on with one passkey, and no admin", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx, { kind: "member", member: "mem_member" }, "linear-mine")
      seesPrivate(ctx, "dev_member")
      const approval = await held(ctx, linearCall(comment("First"), "linear-mine"), { device: "dev_member" })
      // An admin may only stop it, and is offered nothing.
      expect(await op(ctx, "approvals.view", "admin", { id: approval })).toMatchObject({ view: "stop" })
      expect(await offerOf(ctx, "admin", approval)).toBeUndefined()
      expect((await offerOf(ctx, "member", approval))?.coSign).toBe(false)
      await remember(ctx, "member", approval)
      const [rule] = await rulesOf(ctx, { device: "dev_member" })
      // The admin may stop the rule, and learns only that it ended.
      expect(await op(ctx, "policy.rules.revoke", "admin", { id: rule!.id })).toEqual({ id: rule!.id, status: "ended", endedReason: "revoked" })
    })
  })

  it("never lets an admin or owner make a rule for another member's machine", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const approval = await held(ctx, linearCall(comment("First")), { device: "dev_member" })
      for (const role of ["admin", "owner"]) {
        expect(await offerOf(ctx, role, approval)).toBeUndefined()
        const input = { id: approval, decision: "approve", remember: { kind: "rule", path: "/graphql", ttlSeconds: 604_800, termsDigest: "A".repeat(43) } }
        await expect(op(ctx, "approvals.action", role, input)).rejects.toBeInstanceOf(VaultError)
      }
      expect(count(ctx, "policy_rules")).toBe(0)
    })
  })

  it("refuses a guest's machine a proposal, and a guest's approval of one made before they were a guest", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx, { kind: "member", member: "mem_guest" }, "linear-guest")
      seesPrivate(ctx, "dev_guest")
      const guest = { device: "dev_guest" }
      const from = { item: "linear-guest", method: "POST", url: "https://api.linear.app/graphql", bodyBase64: Buffer.from(JSON.stringify(comment("x"))).toString("base64"), contentType: "application/json" }
      await expect(op(ctx, "policy.propose", guest, { from, reason: "Comment on issues" })).rejects.toMatchObject({ code: "forbidden" })
      fixtureSql(ctx).exec("UPDATE members SET role='member' WHERE id='mem_guest'")
      const created = await op(ctx, "policy.propose", guest, { from, reason: "Comment on issues" })
      fixtureSql(ctx).exec("UPDATE members SET role='guest' WHERE id='mem_guest'")
      await expect(decide(ctx, "guest", { id: created.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } })).rejects.toMatchObject({ code: "forbidden" })
      expect(count(ctx, "policy_rules")).toBe(0)
    })
  })

  it("refuses an admin's approval of a proposal from a guest's machine", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx, { kind: "project", project: "prj_a" }, "linear-project")
      const guest = { device: "dev_guest" }
      const from = { item: "linear-project", method: "POST", url: "https://api.linear.app/graphql", bodyBase64: Buffer.from(JSON.stringify(comment("x"))).toString("base64"), contentType: "application/json" }
      fixtureSql(ctx).exec("UPDATE members SET role='member' WHERE id='mem_guest'")
      const created = await op(ctx, "policy.propose", guest, { from, reason: "Comment on issues" })
      fixtureSql(ctx).exec("UPDATE members SET role='guest' WHERE id='mem_guest'")
      // The admin may approve each of the guest machine's requests, never a rule.
      expect((await op(ctx, "policy.status", "admin", { id: created.proposal })).proposal.canApprove).toBe(false)
      const decision = { id: created.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } }
      await expect(op(ctx, "policy.action", "admin", decision)).rejects.toMatchObject({ code: "forbidden" })
      await expect(op(ctx, "policy.decide", "admin", decision, { type: "policy.decide", proposal: created.proposal, digest: "", decision: "approve", effectDigest: "" })).rejects.toMatchObject({ code: "forbidden" })
      expect(count(ctx, "policy_rules")).toBe(0)
    })
  })

  it("lets a manager of a team machine's project approve its proposal", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx, { kind: "project", project: "prj_a" }, "linear-project")
      const team = { device: "dev_service" }
      const from = { item: "linear-project", method: "POST", url: "https://api.linear.app/graphql", bodyBase64: Buffer.from(JSON.stringify(comment("x"))).toString("base64"), contentType: "application/json" }
      const created = await op(ctx, "policy.propose", team, { from, reason: "Comment on issues" })
      expect((await op(ctx, "policy.status", "admin", { id: created.proposal })).proposal.canApprove).toBe(true)
      await decide(ctx, "admin", { id: created.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } })
      const [rule] = await rulesOf(ctx, team)
      expect(rule).toMatchObject({ status: "active", approvedBy: "admin" })
      setUpstreamFetch(async () => new Response("ok"))
      expect((await relay(ctx, linearCall(comment("Second"), "linear-project"), team)).material?.rules).toEqual([rule!.id])
    })
  })

  it("needs a manager of the home to co-sign when the machine's owner does not manage it", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const approval = await held(ctx, linearCall(comment("First")), { device: "dev_member" })
      expect((await offerOf(ctx, "member", approval))?.coSign).toBe(true)
      await remember(ctx, "member", approval)
      // The one request is approved; the rule waits for a second person.
      const status = await op(ctx, "approvals.status", { device: "dev_member" }, { id: approval })
      expect(status).toMatchObject({ status: "approved", ruleProposal: { id: expect.stringMatching(/^pol_/) } })
      expect(count(ctx, "policy_rules")).toBe(0)
      const proposal = status.ruleProposal.id as string
      const view = await op(ctx, "policy.status", "owner", { id: proposal })
      expect(view.proposal).toMatchObject({ kind: "rule", stage: "co-sign", status: "pending", canApprove: true, approvedBy: { name: "member" } })
      // The machine's owner cannot be their own second signature.
      expect((await op(ctx, "policy.status", "member", { id: proposal })).proposal.canApprove).toBe(false)
      const decision = { id: proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } }
      const action = await op(ctx, "policy.action", "owner", decision)
      expect(action).toMatchObject({ type: "policy.decide", proposal, decision: "approve", effectDigest: view.proposal.termsDigest })
      expect((await op(ctx, "policy.decide", "owner", decision, action)).proposal).toMatchObject({ status: "approved", rule: { id: expect.stringMatching(/^rul_/) } })
      const [rule] = await rulesOf(ctx, { device: "dev_member" })
      expect(rule).toMatchObject({ status: "active", approvedBy: "member", coSignedBy: { name: "owner" }, context: null })
      setUpstreamFetch(async () => new Response("ok"))
      expect((await relay(ctx, linearCall(comment("Second")), { device: "dev_member" })).material?.rules).toEqual([rule!.id])
    })
  })
})

describe("a machine's proposal that needs a second person", () => {
  it("is refused at the co-sign once its credential backs a protected environment, writing no rule and leaving it pending", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const asker = { device: "dev_member" }
      const created = await op(ctx, "policy.propose", asker, { from: exampleComment("linear-work"), reason: "Comment on issues" })
      await decide(ctx, "member", { id: created.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } })
      const project = seedRelayProject(ctx, { slug: "platform", remote: null, defaultEnv: "prod", environments: [{ name: "prod", protected: true }] })
      seedRelayVar(ctx, { project, env: "prod", name: "LINEAR_TOKEN", item: "linear-work" })
      await expect(decide(ctx, "owner", { id: created.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } })).rejects.toMatchObject({ code: "environment_refused", message: "This credential backs a protected environment, so it asks every time." })
      expect(count(ctx, "policy_rules")).toBe(0)
      expect(await op(ctx, "policy.status", asker, { id: created.proposal })).toMatchObject({ status: "pending", stage: "co-sign" })
    })
  })

  it("answers a machine's wait on an id that names no proposal as not_found, and as switched off only with rules off", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      const asker = { device: "dev_member" }
      await expect(op(ctx, "policy.status", asker, { id: "pol_madeup123", wait: false })).rejects.toMatchObject({ code: "not_found", message: "No such policy proposal.", extra: { next: { command: "mehen pending" } } })
      await expect(op(switchedOff(ctx), "policy.status", asker, { id: "pol_madeup123", wait: false })).rejects.toMatchObject({ code: "forbidden", message: "Policy widening is not available yet." })
    })
  })

  it("moves to stage co-sign when its machine's owner approves, and becomes a rule when a manager co-signs", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const asker = { device: "dev_member" }
      const created = await op(ctx, "policy.propose", asker, { from: exampleComment("linear-work"), reason: "Comment on issues" })
      expect(created).toMatchObject({ stage: "approve" })
      await decide(ctx, "member", { id: created.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } })
      expect(count(ctx, "policy_rules")).toBe(0)
      expect(await op(ctx, "policy.status", asker, { id: created.proposal })).toMatchObject({ status: "pending", stage: "co-sign" })
      const view = (await op(ctx, "policy.status", "owner", { id: created.proposal })).proposal
      expect(view).toMatchObject({ stage: "co-sign", canApprove: true, approvedBy: { name: "member" } })
      await decide(ctx, "owner", { id: created.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } })
      const [rule] = await rulesOf(ctx, asker)
      expect(rule).toMatchObject({ status: "active", approvedBy: "member" })
      expect(await op(ctx, "policy.status", asker, { id: created.proposal })).toMatchObject({ status: "approved", rule: { id: rule!.id } })
    })
  })

  it("lets the co-signer revoke the rule, and ends it when the co-signer no longer manages the credential's project", async () => {
    for (const end of ["revoke", "lose manage"] as const) {
      const f = await credentialsFixture()
      await inRules(f.tenant, async (ctx) => {
        await seedLinear(ctx, { kind: "project", project: "prj_a" }, "linear-project")
        const asker = { device: "dev_member" }
        const approval = await held(ctx, linearCall(comment("First"), "linear-project"), asker)
        await remember(ctx, "member", approval)
        const proposal = (await op(ctx, "approvals.status", asker, { id: approval })).ruleProposal.id
        await decide(ctx, "kim", { id: proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } })
        const [rule] = await rulesOf(ctx, asker)
        expect(rule).toMatchObject({ status: "active" })
        if (end === "revoke") expect(await op(ctx, "policy.rules.revoke", "kim", { id: rule!.id })).toMatchObject({ status: "ended", endedReason: "revoked" })
        else {
          fixtureSql(ctx).exec("DELETE FROM project_shares WHERE id='shr_kim'")
          expect((await rulesOf(ctx, asker))[0]).toMatchObject({ status: "ended", endedReason: "access-changed" })
        }
        expect((await relay(ctx, linearCall(comment("Second"), "linear-project"), asker)).error?.code).toBe("approval_required")
      })
    }
  })
})

describe("the person who approved as the machine's owner", () => {
  it("cannot co-sign their own approval, even once they manage the credential's home", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx, { kind: "project", project: "prj_a" }, "linear-project")
      const asker = { device: "dev_member" }
      const approval = await held(ctx, linearCall(comment("First"), "linear-project"), asker)
      await remember(ctx, "member", approval)
      const proposal = (await op(ctx, "approvals.status", asker, { id: approval })).ruleProposal.id
      // The owner gains manage of the project through their team's share.
      const team = JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM project_shares WHERE id='shr_team'").toArray()[0]!.value) as Record<string, unknown>
      fixtureSql(ctx).exec("UPDATE project_shares SET value=? WHERE id='shr_team'", JSON.stringify({ ...team, level: "manage" }))
      const decision = { id: proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } }
      const refusal = { code: "forbidden", message: "You approved this as the machine's owner; a second person must co-sign it." }
      await expect(op(ctx, "policy.action", "member", decision)).rejects.toMatchObject(refusal)
      const action = await op(ctx, "policy.action", "kim", decision)
      await expect(op(ctx, "policy.decide", "member", decision, action)).rejects.toMatchObject(refusal)
      expect(count(ctx, "policy_rules")).toBe(0)
    })
  })
})

describe("a decision on a rule proposal", () => {
  // requireStepUp runs the stage's authorise again inside the transaction.
  it("is authorised again inside its transaction, so a co-signer who loses manage in between makes no rule", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx, { kind: "project", project: "prj_a" }, "linear-project")
      const asker = { device: "dev_member" }
      const approval = await held(ctx, linearCall(comment("First"), "linear-project"), asker)
      await remember(ctx, "member", approval)
      const proposal = (await op(ctx, "approvals.status", asker, { id: approval })).ruleProposal.id
      const decision = { id: proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } }
      const action = await op(ctx, "policy.action", "kim", decision)
      // Kim's share goes after the decision is checked and before it is written.
      const storage = Object.assign(Object.create(ctx.storage) as DurableObjectStorage, { transactionSync: <T>(fn: () => T): T => {
        fixtureSql(ctx).exec("DELETE FROM project_shares WHERE id='shr_kim'")
        return ctx.storage.transactionSync(fn)
      } })
      const racing = Object.assign(Object.create(ctx) as VaultContext, { storage })
      await expect(op(racing, "policy.decide", "kim", decision, action)).rejects.toMatchObject({ code: "not_found" })
      expect(count(ctx, "policy_rules")).toBe(0)
      expect(count(ctx, "policy_proposals WHERE id=? AND status='pending' AND stage='co-sign'", proposal)).toBe(1)
    })
  })
})

describe("a proposal waiting for its co-signer", () => {
  it("is stale once the credential is edited after the owner approved, and cannot be co-signed", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const asker = { device: "dev_member" }
      const approval = await held(ctx, linearCall(comment("First")), asker)
      await remember(ctx, "member", approval)
      const proposal = (await op(ctx, "approvals.status", asker, { id: approval })).ruleProposal.id
      const decision = { id: proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } }
      const action = await op(ctx, "policy.action", "owner", decision)
      fixtureSql(ctx).exec("UPDATE items SET config_rev=config_rev+1 WHERE slug='linear-work'")
      expect((await op(ctx, "policy.status", "owner", { id: proposal })).proposal).toMatchObject({ status: "stale", canApprove: false })
      await expect(op(ctx, "policy.decide", "owner", decision, action)).rejects.toMatchObject({ code: "conflict" })
      expect(count(ctx, "policy_rules")).toBe(0)
    })
  })

  it("tells the person who approved an agent's proposal that it was them, and nobody else", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedTasks(ctx)
      const created = await op(ctx, "policy.propose", { device: "dev_member" }, { from: { item: "tasks-key", method: "PATCH", url: "https://api.example.com/tasks/123", bodyBase64: Buffer.from(JSON.stringify({ done: true })).toString("base64"), contentType: "application/json" }, reason: "Close tasks when done" })
      const { terms } = (await op(ctx, "policy.status", "member", { id: created.proposal })).proposal
      await decide(ctx, "member", { id: created.proposal, decision: "approve", effective: { path: terms.path, ttlSeconds: 86_400 } })
      const approver = (await op(ctx, "policy.status", "member", { id: created.proposal })).proposal
      expect(approver).toMatchObject({ stage: "co-sign", requestedBy: { device: "dev_member" }, approvedBy: { self: true }, canApprove: false })
      expect((await op(ctx, "policy.status", "owner", { id: created.proposal })).proposal).toMatchObject({ approvedBy: { self: false }, canApprove: true })
    })
  })
})

describe("the request bytes the vault keeps", () => {
  const bytesOf = (ctx: VaultContext, source: string) => count(ctx, "policy_rule_anchors WHERE source=? AND (url IS NOT NULL OR body IS NOT NULL)", source)
  const due = (ctx: VaultContext) => ctx.sql.exec<{ due_at: number }>("SELECT due_at FROM schedule WHERE area='policy' AND key=?", RULE_ANCHOR_SWEEP_KEY).toArray().map((r) => r.due_at)
  const sweep = (ctx: VaultContext, ms: number) => policyArea.alarm!(at(ctx, ms), RULE_ANCHOR_SWEEP_KEY)
  const kept = (ctx: VaultContext) => ctx.sql.exec<{ source: string }>("SELECT source FROM policy_rule_anchors ORDER BY source").toArray().map((r) => r.source)
  it("keeps none for a request that can never become a rule, only why", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const approval = await held(ctx, linearCall(mutation("issueDelete")))
      expect(bytesOf(ctx, approval)).toBe(0)
      expect(await offerOf(ctx, "owner", approval)).toMatchObject({ terms: null, refused: "rule.destructive" })
      expect(await op(ctx, "policy.preview", { device: "dev_owner" }, { from: { approval }, reason: "Delete" })).toMatchObject({ terms: null, pathChoices: [], refused: "rule.destructive" })
      await expect(op(ctx, "policy.propose", { device: "dev_owner" }, { from: { approval }, reason: "Delete" })).rejects.toMatchObject({ code: "forbidden", extra: { ruleRefused: "rule.destructive" } })
    })
  })

  it("drops a held request's copy two days on from the policy alarm, with nothing else held", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const approval = await held(ctx, linearCall(comment("First")))
      const createdAt = ctx.sql.exec<{ created_at: number }>("SELECT created_at FROM policy_rule_anchors WHERE source=?", approval).toArray()[0]!.created_at
      expect(due(ctx)).toEqual([createdAt + 2 * DAY])
      await sweep(ctx, createdAt + 2 * DAY - 1)
      expect(bytesOf(ctx, approval)).toBe(1)
      await sweep(ctx, createdAt + 2 * DAY)
      expect(count(ctx, "policy_rule_anchors")).toBe(0)
      expect(due(ctx)).toEqual([])
    })
  })

  it("keeps a live rule's copy and a pending proposal's two days on, drops a lapsed proposal's, and sets the alarm for the next one due", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const t0 = ctx.now(), start = at(ctx, t0)
      const approval = await held(start, linearCall(comment("First")))
      await remember(start, "owner", approval)
      const [rule] = await rulesOf(start)
      const pending = (await op(start, "policy.propose", { device: "dev_member" }, { from: exampleComment("linear-work"), reason: "Comment on issues" })).proposal as string
      const lapsed = (await op(start, "policy.propose", { device: "dev_admin" }, { from: exampleComment("linear-work"), reason: "Comment on issues" })).proposal as string
      // Still waiting a day past the sweep; the other is still marked pending past its own time.
      ctx.sql.exec("UPDATE policy_proposals SET expires_at=? WHERE id=?", t0 + 3 * DAY, pending)
      expect(count(ctx, "policy_proposals WHERE id=? AND status='pending' AND expires_at<=?", lapsed, t0 + 2 * DAY)).toBe(1)
      expect(kept(ctx)).toEqual([approval, pending, lapsed, rule!.id].sort())
      await sweep(ctx, t0 + 2 * DAY)
      expect(kept(ctx)).toEqual([pending, rule!.id].sort())
      expect(due(ctx)).toEqual([t0 + 3 * DAY])
    })
  })

  it("drops a live rule's copy once the rule's own deadline passes, though nothing has settled it", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const t0 = ctx.now(), start = at(ctx, t0)
      const approval = await held(start, linearCall(comment("First")))
      await remember(start, "owner", approval)
      const rule = ctx.sql.exec<{ id: string; expires_at: number }>("SELECT id,expires_at FROM policy_rules").toArray()[0]!
      expect(rule.expires_at).toBe(t0 + 7 * DAY)
      expect(due(ctx)).toEqual([t0 + 2 * DAY])
      await sweep(ctx, t0 + 2 * DAY)
      expect(kept(ctx)).toEqual([rule.id])
      expect(due(ctx)).toEqual([t0 + 7 * DAY])
      await sweep(ctx, t0 + 7 * DAY - 1)
      expect(kept(ctx)).toEqual([rule.id])
      await sweep(ctx, t0 + 7 * DAY)
      expect(kept(ctx)).toEqual([])
      expect(due(ctx)).toEqual([])
      expect(count(ctx, "policy_rules WHERE ended_at IS NULL")).toBe(1)
    })
  })

  it("puts a co-signed extension's copy on the sweep when the rule's own copy was all that was left", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const t0 = ctx.now(), start = at(ctx, t0), asker = { device: "dev_member" }
      const approval = await held(start, linearCall(comment("First")), asker)
      await remember(start, "member", approval)
      const proposal = (await op(start, "approvals.status", asker, { id: approval })).ruleProposal.id
      await decide(start, "owner", { id: proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } })
      const [rule] = await rulesOf(start, asker)
      await sweep(ctx, t0 + 2 * DAY)
      expect(kept(ctx)).toEqual([rule!.id])
      const extended = await extend(at(ctx, t0 + 3 * DAY), "member", rule!.id, 604_800)
      expect(bytesOf(ctx, extended.coSign.id)).toBe(1)
      expect(due(ctx)).toEqual([t0 + 5 * DAY])
      await sweep(ctx, t0 + 5 * DAY)
      expect(kept(ctx)).toEqual([rule!.id])
    })
  })

  it("sets the alarm for a rule's new, earlier deadline when an extension shortens it, directly or co-signed", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const t0 = ctx.now(), start = at(ctx, t0)
      await remember(start, "owner", await held(start, linearCall(comment("First"))), { ttlSeconds: 2_592_000 })
      const [rule] = await rulesOf(start)
      await sweep(ctx, t0 + 2 * DAY)
      expect(due(ctx)).toEqual([t0 + 30 * DAY])
      await extend(at(ctx, t0 + 5 * DAY), "owner", rule!.id, 86_400)
      expect(due(ctx)).toEqual([t0 + 6 * DAY])
      await sweep(ctx, t0 + 6 * DAY)
      expect(kept(ctx)).toEqual([])
    })
    const g = await credentialsFixture()
    await inRules(g.tenant, async (ctx) => {
      await seedLinear(ctx)
      const t0 = ctx.now(), start = at(ctx, t0), asker = { device: "dev_member" }
      await remember(start, "member", await held(start, linearCall(comment("First")), asker), { ttlSeconds: 2_592_000 })
      const proposal = (await op(start, "approvals.status", asker, { id: ctx.sql.exec<{ id: string }>("SELECT id FROM approvals").toArray()[0]!.id })).ruleProposal.id
      await decide(start, "owner", { id: proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 2_592_000 } })
      const [rule] = await rulesOf(start, asker)
      await sweep(ctx, t0 + 2 * DAY)
      expect(kept(ctx)).toEqual([rule!.id])
      const extended = await extend(at(ctx, t0 + 5 * DAY), "member", rule!.id, 86_400)
      const cosigned = t0 + 5 * DAY + 3_600_000
      await decide(at(ctx, cosigned), "owner", { id: extended.coSign.id, decision: "approve", effective: { path: "/graphql", ttlSeconds: 86_400 } })
      expect(Date.parse((await rulesOf(at(ctx, cosigned), asker))[0]!.endsAt)).toBe(cosigned + DAY)
      expect(due(ctx)).toEqual([cosigned + DAY])
      await sweep(ctx, cosigned + DAY)
      expect(kept(ctx)).toEqual([extended.coSign.id])
    })
  })

  it("indexes held requests by age, in a migration a workspace that ran the first rules migration applies cleanly", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const approval = await held(ctx, linearCall(comment("First")))
      const first = policyArea.migrations.indexOf(WORKSPACE_POLICY_RULES_MIGRATION)
      expect(first).toBe(policyArea.migrations.indexOf(WORKSPACE_POLICY_RULE_ANCHORS_MIGRATION) - 1)
      withTrustedSchema(ctx, () => ctx.sql.exec("DROP INDEX policy_rules_kind"))
      for (const column of ["kind", "max_uses", "receipt"]) withTrustedSchema(ctx, () => ctx.sql.exec(`ALTER TABLE policy_rules DROP COLUMN ${column}`))
      withTrustedSchema(ctx, () => ctx.sql.exec("DROP INDEX policy_rule_anchors_created"))
      ctx.sql.exec("UPDATE _migrations SET applied=? WHERE area='policy'", first + 1)
      withTrustedSchema(ctx, () => applyMigrations(ctx.sql, ctx.storage, [policyArea]))
      expect(ctx.sql.exec<{ applied: number }>("SELECT applied FROM _migrations WHERE area='policy'").toArray()[0]!.applied).toBe(policyArea.migrations.length)
      expect(bytesOf(ctx, approval)).toBe(1)
      expect(withTrustedSchema(ctx, () => ctx.sql.exec<{ detail: string }>("EXPLAIN QUERY PLAN SELECT source FROM policy_rule_anchors WHERE created_at<=?", 0)).toArray().map((r) => r.detail).join(" ")).toContain("policy_rule_anchors_created")
    })
  })

  it("adds task grants' columns in a migration a workspace with rules applies cleanly, its rules kept as shape rules", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      await remember(ctx, "owner", await held(ctx, linearCall(comment("First"))))
      const grants = policyArea.migrations.indexOf(WORKSPACE_POLICY_AREA_GRANTS_MIGRATION)
      expect(grants).toBe(policyArea.migrations.length - 1)
      expect(policyArea.migrations.indexOf(WORKSPACE_POLICY_RULE_ANCHORS_MIGRATION)).toBe(grants - 1)
      // The schema as it was before task grants.
      withTrustedSchema(ctx, () => ctx.sql.exec("DROP INDEX policy_rules_kind"))
      for (const column of ["kind", "max_uses", "receipt"]) withTrustedSchema(ctx, () => ctx.sql.exec(`ALTER TABLE policy_rules DROP COLUMN ${column}`))
      ctx.sql.exec("UPDATE _migrations SET applied=? WHERE area='policy'", grants)
      withTrustedSchema(ctx, () => applyMigrations(ctx.sql, ctx.storage, [policyArea]))
      expect(ctx.sql.exec<{ applied: number }>("SELECT applied FROM _migrations WHERE area='policy'").toArray()[0]!.applied).toBe(policyArea.migrations.length)
      expect(ctx.sql.exec("SELECT kind,max_uses,receipt FROM policy_rules").toArray()).toEqual([{ kind: null, max_uses: null, receipt: null }])
      const [rule] = await rulesOf(ctx)
      expect(rule).toMatchObject({ status: "active", method: "POST" })
      expect(rule).not.toHaveProperty("kind")
      setUpstreamFetch(async () => new Response("ok"))
      expect((await relay(ctx, linearCall(comment("Second")))).material?.rules).toEqual([rule!.id])
      expect(withTrustedSchema(ctx, () => ctx.sql.exec<{ detail: string }>("EXPLAIN QUERY PLAN SELECT * FROM policy_rules WHERE item_id=? AND device=? AND kind='area' AND ended_at IS NULL", "x", "y")).toArray().map((r) => r.detail).join(" ")).toContain("policy_rules_kind")
    })
  })

  it("keeps the text of every rules migration as production ran them", async () => {
    const sha256 = async (text: string) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)))].map((b) => b.toString(16).padStart(2, "0")).join("")
    expect(await sha256(WORKSPACE_POLICY_RULES_MIGRATION)).toBe("e85fabfedc07a61163ff000ba35f116715995a592b6e313ccac5e197ba17fbbf")
    expect(await sha256(WORKSPACE_POLICY_RULE_ANCHORS_MIGRATION)).toBe("0d29b0348b1905ab9f36b0922a232cfda4e7705358b90a8eb1c0578f7d3091ad")
    expect(await sha256(WORKSPACE_POLICY_AREA_GRANTS_MIGRATION)).toBe("023de6944ada7544fd688d82d6b55859530624190d12fc262e8438b8a9bdfdb5")
  })

  it("drops a rule's copy when it ends, and every copy when the credential is deleted", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      await remember(ctx, "owner", await held(ctx, linearCall(comment("First"))))
      const [rule] = await rulesOf(ctx)
      expect(bytesOf(ctx, rule!.id)).toBe(1)
      await op(ctx, "policy.rules.revoke", "owner", { id: rule!.id })
      expect(bytesOf(ctx, rule!.id)).toBe(0)
      await held(ctx, linearCall(comment("Second")))
      expect(count(ctx, "policy_rule_anchors")).toBeGreaterThan(0)
      const item = ctx.sql.exec<{ id: string }>("SELECT id FROM items WHERE slug='linear-work'").toArray()[0]!.id
      await workspaceItemOps["items.delete"]!.handler(ctx, memberPrincipal(ctx), { slug: "linear-work" }, memberInvocation(ctx, "owner", { type: "item.delete", item }))
      expect(count(ctx, "policy_rule_anchors")).toBe(0)
    })
  })
})

describe("a rule is for the key that asked", () => {
  it("covers only its own workload, never the machine key or another workload", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      addWorkload(ctx, "wl_alphatask", "dev_owner"); addWorkload(ctx, "wl_betatask0", "dev_owner")
      const alpha = { device: "dev_owner", workload: "wl_alphatask" }
      await remember(ctx, "owner", await held(ctx, linearCall(comment("First")), alpha))
      setUpstreamFetch(async () => new Response("ok"))
      expect((await relay(ctx, linearCall(comment("Second")), alpha)).material?.rules).toHaveLength(1)
      expect((await relay(ctx, linearCall(comment("Second")), { device: "dev_owner" })).error?.code).toBe("approval_required")
      expect((await relay(ctx, linearCall(comment("Second")), { device: "dev_owner", workload: "wl_betatask0" })).error?.code).toBe("approval_required")
      expect(await rulesOf(ctx, alpha)).toHaveLength(1)
      expect(await rulesOf(ctx, { device: "dev_owner" })).toHaveLength(0)
      expect(await rulesOf(ctx, { device: "dev_owner", workload: "wl_betatask0" })).toHaveLength(0)
    })
  })

  it("ends when its workload is revoked", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      addWorkload(ctx, "wl_alphatask", "dev_owner")
      const alpha = { device: "dev_owner", workload: "wl_alphatask" }
      await remember(ctx, "owner", await held(ctx, linearCall(comment("First")), alpha))
      ctx.sql.exec("UPDATE workloads SET revoked_at=?,revoked_by='mem_owner' WHERE id='wl_alphatask'", ctx.now())
      expect((await relay(ctx, linearCall(comment("Second")), alpha)).material).toBeNull()
      expect((await op(ctx, "policy.rules", "owner", { item: "linear-work" }))[0]).toMatchObject({ status: "ended", endedReason: "access-changed" })
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(0)
    })
  })
})

describe("a person's list of rules", () => {
  it("lists every live rule and only the most recently ended ones, by credential and by machine, while the machine's own list keeps them all", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      await remember(ctx, "owner", await held(ctx, linearCall(comment("First"))))
      const [live] = await rulesOf(ctx)
      // Copies of that rule, ended a minute apart, the first most recently.
      const row = ctx.sql.exec<Record<string, SqlStorageValue>>("SELECT * FROM policy_rules WHERE id=?", live!.id).toArray()[0]!
      const columns = Object.keys(row)
      const ended = Array.from({ length: POLICY_RULES_ENDED_LISTED + 5 }, (_, i) => `rul_ended${String(i + 1).padStart(4, "0")}`)
      ended.forEach((id, i) => ctx.sql.exec(`INSERT INTO policy_rules(${columns.join(",")}) VALUES (${columns.map(() => "?").join(",")})`, ...columns.map((c) => c === "id" ? id : c === "ended_at" ? ctx.now() - (i + 1) * 60_000 : c === "ended_reason" ? "expired" : row[c]!)))
      const listed = [live!.id, ...ended.slice(0, POLICY_RULES_ENDED_LISTED)]
      for (const input of [{ item: "linear-work" }, { device: "dev_owner" }]) expect((await op(ctx, "policy.rules", "owner", input)).map((r: PolicyRuleView) => r.id)).toEqual(listed)
      expect(await rulesOf(ctx)).toHaveLength(ended.length + 1)
      // Once the live rule has run out it is the most recently ended.
      expect((await op(at(ctx, ctx.now() + 31 * DAY), "policy.rules", "owner", { item: "linear-work" })).map((r: PolicyRuleView) => [r.id, r.status])).toEqual(listed.slice(0, POLICY_RULES_ENDED_LISTED).map((id) => [id, "ended"]))
    })
  })
})

// Kim manages project A, the credential's home, but not project B, where
// the member's machine asked; Kim co-signed the member's rule there.
async function coSignedInProjectB(ctx: VaultContext, member: Who = "member", kim: Who = "kim"): Promise<PolicyRuleView> {
  await seedLinear(ctx, { kind: "project", project: "prj_a" }, "linear-project")
  const item = ctx.sql.exec<{ id: string }>("SELECT id FROM items WHERE slug='linear-project'").toArray()[0]!.id
  editAccessFixture(ctx, (state) => { state.projects[1]!.environments[0]!.references.push({ variable: "LINEAR", field: "key", item, home: { kind: "project", project: "prj_a" }, revision: 1 }) })
  const share = { id: "shr_member_b", project: "prj_b", subject: { kind: "member", member: "mem_member" }, level: "use", protected: false, expiresAt: null }
  fixtureSql(ctx).exec("INSERT INTO project_shares VALUES (?,?,?,?,?)", share.id, share.project, "member", "mem_member", JSON.stringify(share))
  const asker = { device: "dev_member" }
  const approval = await held(ctx, { ...linearCall(comment("First"), "linear-project"), context: { project: "prj_b", environment: "dev" } }, asker)
  await remember(ctx, member, approval)
  const proposal = (await op(ctx, "approvals.status", asker, { id: approval })).ruleProposal.id
  await decide(ctx, kim, { id: proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } })
  const [rule] = await rulesOf(ctx, asker)
  expect(rule).toMatchObject({ status: "active", coSignedBy: { name: "Kim" }, context: { project: "prj_b", environment: "dev" } })
  return rule!
}

describe("a person's own rules (naming neither credential nor machine)", () => {
  it("lists the live rules on their own machines and those they approved or co-signed, and nobody else's", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      // The owner's own machine, the owner approving.
      await remember(ctx, "owner", await held(ctx, linearCall(comment("First"))))
      const [own] = await rulesOf(ctx)
      // The member's machine: the member approves as its owner, the owner co-signs.
      const asker = { device: "dev_member" }
      const created = await op(ctx, "policy.propose", asker, { from: exampleComment("linear-work"), reason: "Comment on issues" })
      await decide(ctx, "member", { id: created.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } })
      await decide(ctx, "owner", { id: created.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } })
      const [cosigned] = await rulesOf(ctx, asker)
      const mine = async (who: string) => (await op(ctx, "policy.rules", who, {})).map((r: PolicyRuleView) => r.id).sort()
      expect(await mine("owner")).toEqual([own!.id, cosigned!.id].sort())
      expect(await mine("member")).toEqual([cosigned!.id])
      // An admin may read both on the credential's page, but neither is theirs.
      expect((await op(ctx, "policy.rules", "admin", { item: "linear-work" })).length).toBe(2)
      expect(await mine("admin")).toEqual([])
      // Each listed as the credential's page lists it.
      const byItem = await op(ctx, "policy.rules", "member", { item: "linear-work" })
      expect(await op(ctx, "policy.rules", "member", {})).toEqual(byItem.filter((r: PolicyRuleView) => r.id === cosigned!.id))
      // An ended rule is no longer listed.
      await op(ctx, "policy.rules.revoke", "owner", { id: own!.id })
      expect(await mine("owner")).toEqual([cosigned!.id])
      await expect(op(ctx, "policy.rules", "owner", { item: "linear-work", device: "dev_owner" })).rejects.toMatchObject({ code: "bad_request" })
      await expect(op(switchedOff(ctx), "policy.rules", "owner", {})).rejects.toMatchObject({ code: "forbidden", message: "Policy widening is not available yet." })
    })
  })

  it("lists nothing to a co-signer who has lost the credential and does not own the machine, as neither page shows it to them", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      const rule = await coSignedInProjectB(ctx)
      expect((await op(ctx, "policy.rules", "kim", {})).map((r: PolicyRuleView) => r.id)).toEqual([rule.id])
      fixtureSql(ctx).exec("DELETE FROM project_shares WHERE id='shr_kim'")
      expect(await op(ctx, "policy.rules", "kim", {})).toEqual([])
      // Left out by the access check before it is settled, not because settling ended it.
      expect(count(ctx, "policy_rules WHERE ended_at IS NULL")).toBe(1)
      await expect(op(ctx, "policy.rules", "kim", { item: "linear-project" })).rejects.toBeInstanceOf(VaultError)
      await expect(op(ctx, "policy.rules", "kim", { device: "dev_member" })).rejects.toBeInstanceOf(VaultError)
    })
  })

  it("lists nothing to a machine owner who cannot read the rule's credential, as the machine page lists nothing and the credential page refuses", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      // The member's machine reached project A's credential through project
      // B; the member then loses project A, and with it the credential.
      const rule = await coSignedInProjectB(ctx)
      expect((await op(ctx, "policy.rules", "member", {})).map((r: PolicyRuleView) => r.id)).toEqual([rule.id])
      fixtureSql(ctx).exec("DELETE FROM project_shares WHERE id IN ('shr_direct','shr_team')")
      expect(await op(ctx, "policy.rules", "member", {})).toEqual([])
      expect(await op(ctx, "policy.rules", "member", { device: "dev_member" })).toEqual([])
      await expect(op(ctx, "policy.rules", "member", { item: "linear-project" })).rejects.toBeInstanceOf(VaultError)
      // Left out by the access check before it is settled, not because settling ended it.
      expect(count(ctx, "policy_rules WHERE ended_at IS NULL")).toBe(1)
    })
  })

  it("lists nothing live to a guest on their own machine, where the machine page shows the rule their demotion ended", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      // Made while the guest was still a member.
      fixtureSql(ctx).exec("UPDATE members SET role='member' WHERE id='mem_guest'")
      await seedLinear(ctx, { kind: "member", member: "mem_guest" }, "linear-guest")
      seesPrivate(ctx, "dev_guest")
      await remember(ctx, "guest", await held(ctx, linearCall(comment("First"), "linear-guest"), { device: "dev_guest" }))
      const [rule] = await rulesOf(ctx, { device: "dev_guest" })
      expect((await op(ctx, "policy.rules", "guest", {})).map((r: PolicyRuleView) => r.id)).toEqual([rule!.id])
      fixtureSql(ctx).exec("UPDATE members SET role='guest' WHERE id='mem_guest'")
      expect(await op(ctx, "policy.rules", "guest", {})).toEqual([])
      expect((await op(ctx, "policy.rules", "guest", { device: "dev_guest" })).map((r: PolicyRuleView) => [r.id, r.status, r.endedReason])).toEqual([[rule!.id, "ended", "access-changed"]])
    })
  })

  it("refuses a suspended member, as their machine's and credential's pages do", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await coSignedInProjectB(ctx)
      fixtureSql(ctx).exec("UPDATE members SET status='suspended' WHERE id='mem_member'")
      await expect(op(ctx, "policy.rules", "member", {})).rejects.toMatchObject({ code: "owner_inactive" })
      await expect(op(ctx, "policy.rules", "member", { device: "dev_member" })).rejects.toMatchObject({ code: "owner_inactive" })
      await expect(op(ctx, "policy.rules", "member", { item: "linear-project" })).rejects.toMatchObject({ code: "not_found" })
    })
  })
})

describe("a rule ends when an exact grant would", () => {
  const endings: [string, string, (ctx: VaultContext) => void][] = [
    ["the approver is demoted", "access-changed", (ctx) => { fixtureSql(ctx).exec("UPDATE members SET role='admin' WHERE id='mem_owner'") }],
    ["the approver is removed", "access-changed", (ctx) => { fixtureSql(ctx).exec("UPDATE members SET status='removed' WHERE id='mem_owner'") }],
    ["the machine is revoked", "access-changed", (ctx) => { ctx.sql.exec("UPDATE devices SET revoked_at=? WHERE id='dev_owner'", ctx.now()) }],
    ["the machine is rescoped", "access-changed", (ctx) => {
      const scope = JSON.parse(ctx.sql.exec<{ scope: string }>("SELECT scope FROM devices WHERE id='dev_owner'").toArray()[0]!.scope) as Record<string, unknown>
      ctx.sql.exec("UPDATE devices SET scope=? WHERE id='dev_owner'", JSON.stringify({ ...scope, modes: ["relay"] }))
    }],
    ["the credential is edited", "credential-changed", (ctx) => { fixtureSql(ctx).exec("UPDATE items SET config_rev=config_rev+1 WHERE slug='linear-work'") }],
    ["a protected reference is added", "access-changed", (ctx) => {
      const id = ctx.sql.exec<{ id: string }>("SELECT id FROM items WHERE slug='linear-work'").toArray()[0]!.id
      editAccessFixture(ctx, (state) => { state.projects[0]!.environments[1]!.references.push({ variable: "LINEAR", field: "key", item: id, home: { kind: "workspace" }, revision: 1 }) })
    }],
  ]
  for (const [name, reason, change] of endings) it(`when ${name}`, async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      // A second owner keeps the workspace owned when the first steps down.
      fixtureSql(ctx).exec("UPDATE members SET role='owner' WHERE id='mem_admin'")
      await remember(ctx, "owner", await held(ctx, linearCall(comment("First"))))
      change(ctx)
      setUpstreamFetch(async () => new Response("ok"))
      expect((await relay(ctx, linearCall(comment("Second")))).material).toBeNull()
      // A person's list settles it, whichever check refused the relay first.
      expect((await op(ctx, "policy.rules", "admin", { item: "linear-work" }))[0]).toMatchObject({ status: "ended", endedReason: reason })
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(0)
    })
  })

  it("when its time runs out", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      await remember(ctx, "owner", await held(ctx, linearCall(comment("First"))), { ttlSeconds: 86_400 })
      const later = at(ctx, ctx.now() + DAY)
      expect((await relay(later, linearCall(comment("Second")))).error?.code).toBe("approval_required")
      expect((await rulesOf(later))[0]).toMatchObject({ status: "ended", endedReason: "expired" })
    })
  })
})

describe("a rule that ends during a request", () => {
  it("refuses the request at the relay's last check, sends nothing and counts no use", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      await remember(ctx, "owner", await held(ctx, linearCall(comment("First"))))
      const [rule] = await rulesOf(ctx)
      let sends = 0, opens = 0
      setUpstreamFetch(async () => { sends++; return new Response("ok") })
      // The secret is opened after the rule matched and before the last check.
      const racing = Object.assign(Object.create(ctx) as VaultContext, { async openField(ref: Parameters<VaultContext["openField"]>[0], sealed: Parameters<VaultContext["openField"]>[1]) {
        const value = await ctx.openField(ref, sealed)
        opens++
        await op(ctx, "policy.rules.revoke", { device: "dev_owner" }, { id: rule!.id })
        return value
      } })
      const { error } = await relay(racing, linearCall(comment("Second")))
      expect(error).toMatchObject({ code: "conflict", message: "The rule that allowed this request has ended; send it again to ask for approval." })
      expect(opens).toBe(1)
      expect(sends).toBe(0)
      expect((await rulesOf(ctx))[0]).toMatchObject({ status: "ended", endedReason: "revoked", uses: 0 })
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(0)
    })
  })
})

describe("runs, placeholders and protected credentials", () => {
  // projectFixture's key-workspace: a workspace key every request of which
  // its policy holds, the TOKEN of each project's unprotected dev.
  const byItem = (title: string): Sent => ({ item: "key-workspace", url: "https://api.example.com/tasks", body: json({ title }) })
  async function devRun(ctx: VaultContext) {
    const created = await workspaceRunOps["runs.create"]!.handler(ctx, principalOf({ device: "dev_owner" }), { ...PROJECT_RUN_INPUT, env: "dev" }, await invocationOf(ctx, { device: "dev_owner" })) as WorkspaceRunCreated
    return { run: created.run, placeholder: created.vars.find((v) => v.delivery === "placeholder")!.value }
  }
  async function viaRun(ctx: VaultContext, run: { run: string; placeholder: string }, title: string) {
    const input = { run: run.run, method: "POST", url: "https://api.example.com/tasks", headers: [["Authorization", `Bearer ${run.placeholder}`], ["content-type", "application/json"]], body: base64UrlEncode(enc({ title })) }
    try { return { material: await authoriseWorkspaceRelay(ctx, principalOf({ device: "dev_owner" }), input, await invocationOf(ctx, { device: "dev_owner" })), error: null } }
    catch (error) { if (error instanceof VaultError) return { material: null, error }; throw error }
  }
  async function projectRules() {
    const f = await projectFixture()
    await inAccess(f.tenant, () => registerCredentialProvider())
    return f
  }

  it("covers a request in the project and environment its approval named, and holds one in another", async () => {
    const f = await projectRules()
    await inRules(f.tenant, async (ctx) => {
      setUpstreamFetch(async () => new Response("ok"))
      const dev = { project: "prj_a", environment: "dev" }
      await remember(ctx, "owner", await held(ctx, { ...byItem("a"), context: dev }))
      const [rule] = await rulesOf(ctx)
      expect(rule).toMatchObject({ context: dev, coSignedBy: null })
      // The rule's snapshot is bound to that context and the relay mode.
      const snapshot = JSON.parse(ctx.sql.exec<{ snapshot: string }>("SELECT snapshot FROM policy_rules WHERE id=?", rule!.id).toArray()[0]!.snapshot) as { project: string; environment: string; mode?: string }
      expect([snapshot.project, snapshot.environment, snapshot.mode]).toEqual(["prj_a", "dev", undefined])
      expect((await relay(ctx, { ...byItem("b"), context: dev })).material?.rules).toEqual([rule!.id])
      for (const context of [undefined, { project: "prj_b", environment: "dev" }]) expect((await relay(ctx, { ...byItem("c"), ...(context ? { context } : {}) })).error?.code).toBe("approval_required")
      expect((await rulesOf(ctx))[0]).toMatchObject({ status: "active", uses: 1 })
    })
  })

  // The rescope goes through devices.rescope, so through accessChanged's
  // hooks as in production.
  const contextChanges: [string, (ctx: VaultContext) => unknown][] = [
    ["prj_a/dev no longer references the credential", (ctx) => { ctx.sql.exec("DELETE FROM vars WHERE project='prj_a' AND env='dev' AND item='key-workspace'") }],
    ["the machine is rescoped off prj_a", (ctx) => {
      const row = ctx.sql.exec<{ scope: string; thumbprint: string }>("SELECT scope,thumbprint FROM devices WHERE id='dev_owner'").toArray()[0]!
      const before = JSON.parse(row.scope) as WorkspaceDeviceScope, after = { ...before, projects: ["prj_b"] }
      return op(ctx, "devices.rescope", "owner", { device: "dev_owner", before, after }, { type: "device.rescope", device: "dev_owner", thumbprint: row.thumbprint, before, after })
    }],
  ]
  for (const [name, change] of contextChanges) it(`ends a rule bound to prj_a/dev as access-changed when ${name}`, async () => {
    const f = await projectRules()
    await inRules(f.tenant, async (ctx) => {
      setUpstreamFetch(async () => new Response("ok"))
      const dev = { project: "prj_a", environment: "dev" }
      await remember(ctx, "owner", await held(ctx, { ...byItem("a"), context: dev }))
      const [rule] = await rulesOf(ctx)
      expect((await relay(ctx, { ...byItem("b"), context: dev })).material?.rules).toEqual([rule!.id])
      await change(ctx)
      expect((await relay(ctx, { ...byItem("c"), context: dev })).material).toBeNull()
      // The machine's own list settles it, whichever check refused the relay first.
      expect(await rulesOf(ctx)).toMatchObject([{ id: rule!.id, status: "ended", endedReason: "access-changed", uses: 1 }])
    })
  })

  it("lets a rule serve only the mode it was asked in: by item, or a run's placeholder", async () => {
    const f = await projectRules()
    await inRules(f.tenant, async (ctx) => {
      setUpstreamFetch(async () => new Response("ok"))
      await remember(ctx, "owner", await held(ctx, byItem("a")))
      const [relayRule] = await rulesOf(ctx)
      const run = await devRun(ctx)
      const asked = await viaRun(ctx, run, "b")
      expect(asked.error?.code).toBe("approval_required")
      await remember(ctx, "owner", asked.error!.extra.approval!)
      const placeholderRule = (await rulesOf(ctx)).find((r) => r.id !== relayRule!.id)!
      const modeOf = (id: string) => (JSON.parse(ctx.sql.exec<{ snapshot: string }>("SELECT snapshot FROM policy_rules WHERE id=?", id).toArray()[0]!.snapshot) as { mode?: string }).mode
      expect([modeOf(relayRule!.id), modeOf(placeholderRule.id)]).toEqual([undefined, "placeholder"])
      expect((await viaRun(ctx, run, "c")).material?.rules).toEqual([placeholderRule.id])
      expect((await relay(ctx, byItem("d"))).material?.rules).toEqual([relayRule!.id])
      await op(ctx, "policy.rules.revoke", "owner", { id: relayRule!.id })
      expect((await relay(ctx, byItem("e"))).error?.code).toBe("approval_required")
      expect(count(ctx, "policy_rules WHERE id=? AND uses=1", placeholderRule.id)).toBe(1)
    })
  })

  it("lets a team machine remember a workspace credential it reaches only through prj_a/dev, and covers its next request there", async () => {
    const f = await projectRules()
    await inRules(f.tenant, async (ctx) => {
      setUpstreamFetch(async () => new Response("ok"))
      const team = { device: "dev_service" }, dev = { project: "prj_a", environment: "dev" }
      await remember(ctx, "admin", await held(ctx, { ...byItem("a"), context: dev }, team))
      const [rule] = await rulesOf(ctx, team)
      expect(rule).toMatchObject({ status: "active" })
      expect((await relay(ctx, { ...byItem("b"), context: dev }, team)).material?.rules).toEqual([rule!.id])
      expect((await rulesOf(ctx, team))[0]).toMatchObject({ status: "active", uses: 1 })
    })
  })

  it("makes a proposal from a run's placeholder approval cover the run's next request, and not one by item", async () => {
    const f = await projectRules()
    await inRules(f.tenant, async (ctx) => {
      setUpstreamFetch(async () => new Response("ok"))
      const run = await devRun(ctx)
      const approval = (await viaRun(ctx, run, "a")).error!.extra.approval!
      const created = await op(ctx, "policy.propose", { device: "dev_owner" }, { from: { approval }, reason: "Create tasks" })
      expect(created.summary).toContain("from dev_owner, in project-a / dev, from `mehen run`, 7 days")
      await decide(ctx, "owner", { id: created.proposal, decision: "approve", effective: { path: "/tasks", ttlSeconds: 604_800 } })
      const [rule] = await rulesOf(ctx)
      expect((await viaRun(ctx, run, "b")).material?.rules).toEqual([rule!.id])
      expect((await relay(ctx, { ...byItem("c"), context: { project: "prj_a", environment: "dev" } })).error?.code).toBe("approval_required")
    })
  })

  it("makes a proposal from a request asked in prj_a/dev cover the next request there, and not one outside it", async () => {
    const f = await projectRules()
    await inRules(f.tenant, async (ctx) => {
      setUpstreamFetch(async () => new Response("ok"))
      const dev = { project: "prj_a", environment: "dev" }
      const approval = await held(ctx, { ...byItem("a"), context: dev })
      const created = await op(ctx, "policy.propose", { device: "dev_owner" }, { from: { approval }, reason: "Create tasks" })
      expect(created.summary).toContain("in project-a / dev, 7 days")
      await decide(ctx, "owner", { id: created.proposal, decision: "approve", effective: { path: "/tasks", ttlSeconds: 604_800 } })
      const [rule] = await rulesOf(ctx)
      expect((await relay(ctx, { ...byItem("b"), context: dev })).material?.rules).toEqual([rule!.id])
      for (const context of [undefined, { project: "prj_b", environment: "dev" }]) expect((await relay(ctx, { ...byItem("c"), ...(context ? { context } : {}) })).error?.code).toBe("approval_required")
    })
  })

  it("checks an example's context as the relay would: refused where the machine cannot use the credential, bound where it can", async () => {
    const f = await projectRules()
    await inRules(f.tenant, async (ctx) => {
      setUpstreamFetch(async () => new Response("ok"))
      const team = { device: "dev_service" }, reason = "Create tasks"
      const example = (context?: { project: string; environment: string }) => ({ item: "key-workspace", method: "POST", url: "https://api.example.com/tasks", bodyBase64: Buffer.from(JSON.stringify({ title: "x" })).toString("base64"), contentType: "application/json", ...(context ? { context } : {}) })
      for (const context of [undefined, { project: "prj_b", environment: "dev" }, { project: "prj_a", environment: "qa" }]) {
        const refusal = (await relay(ctx, { ...byItem("a"), ...(context ? { context } : {}) }, team)).error
        expect(refusal).toBeInstanceOf(VaultError)
        for (const name of ["policy.preview", "policy.propose"]) await expect(op(ctx, name, team, { from: example(context), reason })).rejects.toMatchObject({ code: refusal!.code, message: refusal!.message })
      }
      expect(count(ctx, "policy_proposals")).toBe(0)
      const dev = { project: "prj_a", environment: "dev" }
      expect((await op(ctx, "policy.preview", team, { from: example(dev), reason })).summary).toContain("in project-a / dev")
      const created = await op(ctx, "policy.propose", team, { from: example(dev), reason })
      await decide(ctx, "admin", { id: created.proposal, decision: "approve", effective: { path: "/tasks", ttlSeconds: 604_800 } })
      const [rule] = await rulesOf(ctx, team)
      expect((await relay(ctx, { ...byItem("b"), context: dev }, team)).material?.rules).toEqual([rule!.id])
    })
  })

  it("never looks a rule up for a protected credential, by item or in a protected run", async () => {
    const f = await projectRules()
    await inRules(f.tenant, async (ctx) => {
      setUpstreamFetch(async () => new Response("ok"))
      await remember(ctx, "owner", await held(ctx, byItem("a")))
      const asked = await viaRun(ctx, await devRun(ctx), "b")
      await remember(ctx, "owner", asked.error!.extra.approval!)
      expect(count(ctx, "policy_rules WHERE ended_at IS NULL")).toBe(2)
      // key-workspace backs the protected staging from now on.
      ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_a','staging','TOKEN','key-workspace','key','member:mem_owner',?)", ctx.now())
      expect((await relay(ctx, byItem("c"))).error?.code).toBe("environment_refused")
      const run = await approvedProjectRun(ctx, { ...PROJECT_RUN_INPUT, env: "staging" }, "dev_owner", "owner")
      const through = await viaRun(ctx, { run: run.run, placeholder: run.result.vars.find((v) => v.delivery === "placeholder")!.value }, "d")
      expect(through.error).toBeNull()
      expect(through.material?.rules).toBeUndefined()
      // A rule the relay had looked up would have been settled as ended.
      expect(count(ctx, "policy_rules WHERE ended_at IS NULL AND uses=0")).toBe(2)
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(0)
    })
  })
})

describe("in an identity-gated workspace", () => {
  it("a rule outlives the 12-hour session check, and ends when the gate moves", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const approval = await held(ctx, linearCall(comment("First")))
      setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["owner", "admin", "member"] }); setSetting(ctx, "identity_rule_rev", 4)
      const owner = accessState(ctx).members.find((m) => m.id === "mem_owner")!
      const auth = accountAuth("owner")
      auth.sessionCheck = { id: "chk_owner", identityRuleRev: 4, gateGeneration: owner.standing.gateGeneration, checkSequence: 1, succeededAt: new Date(ctx.now()).toISOString(), expiresAt: new Date(ctx.now() + 600_000).toISOString() }
      installTestIdentity(ctx, auth)
      await remember(ctx, auth, approval)
      setUpstreamFetch(async () => new Response("ok"))
      const later = at(ctx, ctx.now() + 13 * 3_600_000)
      expect((await relay(later, linearCall(comment("Second")))).material?.rules).toHaveLength(1)
      setSetting(ctx, "identity_rule_rev", 5)
      expect((await relay(later, linearCall(comment("Third")))).error?.code).toBe("approval_required")
      expect(ctx.sql.exec<{ ended_reason: string }>("SELECT ended_reason FROM policy_rules").toArray()[0]?.ended_reason).toBe("access-changed")
    })
  })
})

describe("ending a rule", () => {
  it("lets the machine, an admin or the approver revoke it, and no one else", async () => {
    for (const who of [{ device: "dev_owner" }, "admin", "owner"] as Who[]) {
      const f = await credentialsFixture()
      await inRules(f.tenant, async (ctx) => {
        await seedLinear(ctx)
        await remember(ctx, "owner", await held(ctx, linearCall(comment("First"))))
        const [rule] = await rulesOf(ctx)
        await expect(op(ctx, "policy.rules.revoke", "guest", { id: rule!.id })).rejects.toMatchObject({ code: "not_found" })
        await expect(op(ctx, "policy.rules.revoke", { device: "dev_member" }, { id: rule!.id })).rejects.toMatchObject({ code: "not_found" })
        expect(await op(ctx, "policy.rules.revoke", who, { id: rule!.id })).toMatchObject({ status: "ended", endedReason: "revoked" })
        expect((await relay(ctx, linearCall(comment("Second")))).error?.code).toBe("approval_required")
        expect(count(ctx, "audit WHERE action='rule.end'")).toBe(1)
        // Revoking again answers the ended rule and writes nothing.
        expect(await op(ctx, "policy.rules.revoke", who, { id: rule!.id })).toMatchObject({ status: "ended" })
        expect(count(ctx, "audit WHERE action='rule.end'")).toBe(1)
      })
    }
  })
})

describe("ending a team machine's rule", () => {
  it("lets a member of the machine's team who did not approve it revoke it", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx, { kind: "project", project: "prj_a" }, "linear-project")
      fixtureSql(ctx).exec("INSERT INTO team_members(team,member) VALUES ('tm_service','mem_member')")
      const team = { device: "dev_service" }
      const created = await op(ctx, "policy.propose", team, { from: exampleComment("linear-project"), reason: "Comment on issues" })
      await decide(ctx, "admin", { id: created.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } })
      const [rule] = await rulesOf(ctx, team)
      await expect(op(ctx, "policy.rules.revoke", "guest", { id: rule!.id })).rejects.toBeInstanceOf(VaultError)
      expect(await op(ctx, "policy.rules.revoke", "member", { id: rule!.id })).toMatchObject({ status: "ended", endedReason: "revoked" })
    })
  })

  it("refuses a guest on the machine's team, and a team member whose identity check has lapsed", async () => {
    for (const [role, member] of [["guest", "mem_guest"], ["member", "mem_member"]] as const) {
      const f = await credentialsFixture()
      await inRules(f.tenant, async (ctx) => {
        await seedLinear(ctx, { kind: "project", project: "prj_a" }, "linear-project")
        fixtureSql(ctx).exec("INSERT INTO team_members(team,member) VALUES ('tm_service',?)", member)
        const team = { device: "dev_service" }
        const created = await op(ctx, "policy.propose", team, { from: exampleComment("linear-project"), reason: "Comment on issues" })
        await decide(ctx, "admin", { id: created.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } })
        const [rule] = await rulesOf(ctx, team)
        // The workspace now admits members only after an identity check this one has not passed.
        if (role === "member") { setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["member"] }); setSetting(ctx, "identity_rule_rev", 4) }
        await expect(op(ctx, "policy.rules.revoke", role, { id: rule!.id })).rejects.toBeInstanceOf(VaultError)
        expect(count(ctx, "policy_rules WHERE ended_at IS NULL")).toBe(1)
      })
    }
  })
})

describe("ending a co-signed rule", () => {
  it("lets a co-signer who manages the credential's home but not the ask's project revoke it", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      const rule = await coSignedInProjectB(ctx)
      expect(await op(ctx, "policy.rules.revoke", "kim", { id: rule.id })).toMatchObject({ id: rule.id, status: "ended", endedReason: "revoked" })
    })
  })

  // Lee manages project A too, so may end the rule only as a manager of the
  // credential's home (policy.cosigner_revoke). Ending a rule only narrows,
  // so Lee may still do it where a denial is allowed: under a recovery
  // restriction, while a security transition is pending, and 12 hours
  // after an identity check that still stands.
  it("lets another manager of the credential's home revoke it while their account may only narrow, as a denial may", async () => {
    const checked = (ctx: VaultContext, who: string, at: number): AccountInvocationAuth => {
      const member = accessState(ctx).members.find((m) => m.id === `mem_${who}`)!
      const auth = accountAuth(who)
      auth.sessionCheck = { id: `chk_${who}`, identityRuleRev: 4, gateGeneration: member.standing.gateGeneration, checkSequence: 1, succeededAt: new Date(at).toISOString(), expiresAt: new Date(at + DAY).toISOString() }
      installTestIdentity(ctx, auth)
      return auth
    }
    const cases: Array<{ before?: (ctx: VaultContext) => { member: Who; kim: Who; lee: Who }; after?: (ctx: VaultContext) => void; later?: number }> = [
      { after: (ctx) => { updateRestriction(ctx, "acc_lee", 0, { reason: "recovery", until: ctx.now() + DAY, notice: "ntc_lee" }) } },
      { after: (ctx) => { installSecurity(ctx, "acc_lee", 0, { transitionId: "trn_lee", reservedEpoch: 1, revokedSessionIds: [], removedFactorIds: [], restriction: null }) } },
      {
        before: (ctx) => {
          setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["member"] }); setSetting(ctx, "identity_rule_rev", 4)
          return { member: checked(ctx, "member", ctx.now()), kim: checked(ctx, "kim", ctx.now()), lee: checked(ctx, "lee", ctx.now()) }
        },
        later: 13 * 3_600_000,
      },
    ]
    for (const { before, after, later = 0 } of cases) {
      const f = await credentialsFixture()
      await inRules(f.tenant, async (ctx) => {
        newMember(ctx, "acc_lee", "Lee", "member", "active", "mem_lee")
        const share = { id: "shr_lee", project: "prj_a", subject: { kind: "member", member: "mem_lee" }, level: "manage", protected: false, expiresAt: null }
        fixtureSql(ctx).exec("INSERT INTO project_shares VALUES (?,?,?,?,?)", share.id, share.project, "member", "mem_lee", JSON.stringify(share))
        const who = before?.(ctx) ?? { member: "member", kim: "kim", lee: "lee" }
        const rule = await coSignedInProjectB(ctx, who.member, who.kim)
        after?.(ctx)
        expect(await op(at(ctx, ctx.now() + later), "policy.rules.revoke", who.lee, { id: rule.id })).toMatchObject({ id: rule.id, status: "ended", endedReason: "revoked" })
      })
    }
  })

  it("refuses that co-signer once they are a guest, or their identity check has lapsed", async () => {
    for (const change of [
      (ctx: VaultContext) => { fixtureSql(ctx).exec("UPDATE members SET role='guest' WHERE id='mem_kim'") },
      (ctx: VaultContext) => { setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["member"] }); setSetting(ctx, "identity_rule_rev", 4) },
    ]) {
      const f = await credentialsFixture()
      await inRules(f.tenant, async (ctx) => {
        const rule = await coSignedInProjectB(ctx)
        change(ctx)
        await expect(op(ctx, "policy.rules.revoke", "kim", { id: rule.id })).rejects.toBeInstanceOf(VaultError)
        expect(count(ctx, "policy_rules WHERE ended_at IS NULL")).toBe(1)
      })
    }
  })
})

describe("extending a rule", () => {
  it("moves the end with the approver's passkey", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      await remember(ctx, "owner", await held(ctx, linearCall(comment("First"))), { ttlSeconds: 86_400 })
      const [rule] = await rulesOf(ctx)
      const extended = await extend(ctx, "owner", rule!.id, 2_592_000)
      expect(extended.coSign).toBeNull()
      expectEndsIn(ctx, extended.rule.endsAt, 30 * DAY)
      expect(extended.rule.ttlSeconds).toBe(2_592_000)
      await expectStoredTerms(ctx, rule!.id, 2_592_000)
      setUpstreamFetch(async () => new Response("ok"))
      expect((await relay(at(ctx, ctx.now() + 2 * DAY), linearCall(comment("Second")))).material?.rules).toEqual([rule!.id])
      await expect(extend(ctx, "admin", rule!.id, 2_592_000)).rejects.toMatchObject({ code: "forbidden" })
      // At most 30 days from now: no other duration is accepted.
      for (const ttlSeconds of [2_592_001, 5_184_000, 3_600]) await expect(op(ctx, "policy.rules.extend-action", "owner", { id: rule!.id, ttlSeconds })).rejects.toMatchObject({ code: "bad_request" })
    })
  })

  it("needs the co-signer again when the machine's owner does not manage the home, with the request the proposal kept", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const approval = await held(ctx, linearCall(comment("First")), { device: "dev_member" })
      await remember(ctx, "member", approval, { ttlSeconds: 86_400 })
      const proposal = (await op(ctx, "approvals.status", { device: "dev_member" }, { id: approval })).ruleProposal.id
      // The approval's own copy of the request is swept, as after two days;
      // the proposal's copy is the one the rule keeps.
      ctx.sql.exec("DELETE FROM policy_rule_anchors WHERE source=?", approval)
      await decide(ctx, "owner", { id: proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 86_400 } })
      const [rule] = await rulesOf(ctx, { device: "dev_member" })
      const extended = await extend(ctx, "member", rule!.id, 604_800)
      expect(extended.rule.endsAt).toBe(rule!.endsAt)
      expect(extended.coSign).toMatchObject({ id: expect.stringMatching(/^pol_/) })
      await expect(extend(ctx, "member", rule!.id, 604_800)).rejects.toMatchObject({ code: "conflict" })
      await decide(ctx, "owner", { id: extended.coSign.id, decision: "approve", effective: { path: "/graphql", ttlSeconds: 604_800 } })
      const [after] = await rulesOf(ctx, { device: "dev_member" })
      expectEndsIn(ctx, after!.endsAt, 7 * DAY)
      expect(after!.id).toBe(rule!.id)
      expect(after!.ttlSeconds).toBe(604_800)
      await expectStoredTerms(ctx, rule!.id, 604_800)
    })
  })
})

describe("the approval page's rule offer against the vault", () => {
  // The page offers Allow only when the offer's terms are the approval's
  // request as the page reads it, so the vault's anchor and the page's
  // subject must agree, a query string and a GraphQL body included.
  it("matches the approval's own subject for a URL with a query string and for a GraphQL request", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedTasks(ctx)
      await seedLinear(ctx)
      const cases: [Sent, Partial<PolicyRuleTerms>][] = [
        [{ item: "tasks-key", method: "PATCH", url: "https://api.example.com/tasks/123?view=full&lang=en", body: json({ done: true }) }, { anchorPath: "/tasks/123", queryNames: ["lang", "view"] }],
        [linearCall(comment("First")), { anchorPath: "/graphql", graphql: expect.objectContaining({ fields: ["commentCreate"] }) }],
      ]
      for (const [sent, shape] of cases) {
        const view = (await op(ctx, "approvals.view", "owner", { id: await held(ctx, sent) })).approval
        const offer = view.rememberOptions?.rule
        expect(offer?.refused ?? null, sent.url).toBeNull()
        expect(offer.terms, sent.url).toMatchObject(shape)
        expect(await ruleOfferMatches({ terms: offer.terms, termsDigest: offer.termsDigest, pathChoices: offer.pathChoices, coSign: offer.coSign }, approvalSubjectOf(view)), sent.url).toBe(true)
      }
    })
  })
})

describe("the rule proposal page against the vault", () => {
  // The page enables Approve only when what it shows hashes to the vault's
  // digests, and signs the effect digest the vault's action names.
  it("rebuilds each proposal's digest (with a reason, without one, an extension) and the effect the vault signs", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedTasks(ctx)
      const asker = { device: "dev_member" }
      const shown = async (id: string) => {
        const view = (await op(ctx, "policy.status", "owner", { id })).proposal
        expect(await ruleProposalMatches(view), id).toBe(true)
        expect(await ruleProposalMatches({ ...view, reason: view.reason === null ? "" : null }), id).toBe(view.reason === null)
        return view
      }
      const created = await op(ctx, "policy.propose", asker, { from: { item: "tasks-key", method: "PATCH", url: "https://api.example.com/tasks/123", bodyBase64: Buffer.from(JSON.stringify({ done: true })).toString("base64"), contentType: "application/json" }, reason: "Close tasks when done" })
      const machine = await shown(created.proposal)
      expect(machine.reason).toBe("Close tasks when done")
      const approval = await held(ctx, { item: "tasks-key", method: "PATCH", url: "https://api.example.com/tasks/124", body: json({ done: true }) }, asker)
      await remember(ctx, "member", approval, { path: "/tasks/*", ttlSeconds: 86_400 })
      const cosign = await shown((await op(ctx, "approvals.status", asker, { id: approval })).ruleProposal.id)
      expect(cosign.reason).toBeNull()
      const narrowed = await ruleProposalEffect(cosign, "/tasks/*", "86400")
      if (!narrowed.ok) throw new Error(narrowed.problems.join(" "))
      expect(await op(ctx, "policy.action", "owner", { id: cosign.proposal, ...ruleProposalDecision(cosign, "approve", narrowed.value).body })).toEqual(ruleProposalDecision(cosign, "approve", narrowed.value).expected)
      await decide(ctx, "owner", { id: cosign.proposal, decision: "approve", effective: { path: "/tasks/*", ttlSeconds: 86_400 } })
      const [rule] = await rulesOf(ctx, asker)
      const extension = await shown((await extend(ctx, "member", rule!.id, 604_800)).coSign.id)
      expect(extension.extends).toBe(rule!.id)
      const built = await ruleProposalEffect(extension, "/tasks/*", "604800")
      if (!built.ok) throw new Error(built.problems.join(" "))
      expect(await op(ctx, "policy.action", "owner", { id: extension.proposal, ...ruleProposalDecision(extension, "approve", built.value).body })).toEqual(ruleProposalDecision(extension, "approve", built.value).expected)
    })
  })
})

describe("a rule proposal in Needs you", () => {
  it("reads Allow from now on: the credential, who asked and the code, and opens the proposal page", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedTasks(ctx)
      const created = await op(ctx, "policy.propose", { device: "dev_member" }, { from: { item: "tasks-key", method: "PATCH", url: "https://api.example.com/tasks/123", bodyBase64: Buffer.from(JSON.stringify({ done: true })).toString("base64"), contentType: "application/json" }, reason: "Close tasks when done" })
      const inbox = await op(ctx, "pending.inbox", "owner", { enrolments: [] })
      const item = inbox.items.find((i: InboxItem) => i.kind === "ask" && i.ask.view === "detail" && i.ask.detail.id === created.proposal)
      const href = `/w/${item.workspace.slug}/p/${created.proposal}`
      expect(item).toMatchObject({ href, action: "review" })
      const row = inboxRow(inboxRowOf(item, { workspace: item.workspace, role: "owner", state: "ok", reason: null, count: 1, truncated: false }), { now: ctx.now(), showWorkspace: false }).value
      expect(row).toContain(`<a class="row-main" href="${href}">`)
      expect(row).toContain("Allow from now on: tasks-key")
      expect(row).toContain(`<a class="btn primary sm" href="${href}">Review</a>`)
      expect(row).toContain(`Code <code class="code-inline">${item.ask.detail.bindingCode}</code>`)
      expect(row).toMatch(/An agent on [^<]+/)

      // A co-sign shows no code to tick on its page, so its row names none;
      // an extension reads as one, of the rule it would move.
      const rowFor = async (id: string) => {
        const found = (await op(ctx, "pending.inbox", "owner", { enrolments: [] })).items.find((i: InboxItem) => i.kind === "ask" && i.ask.view === "detail" && i.ask.detail.id === id)
        return { found, html: inboxRow(inboxRowOf(found, { workspace: found.workspace, role: "owner", state: "ok", reason: null, count: 1, truncated: false }), { now: ctx.now(), showWorkspace: false }).value }
      }
      const asker = { device: "dev_member" }
      const approval = await held(ctx, { item: "tasks-key", method: "PATCH", url: "https://api.example.com/tasks/124", body: json({ done: true }) }, asker)
      await remember(ctx, "member", approval, { path: "/tasks/*", ttlSeconds: 86_400 })
      const cosign = (await op(ctx, "approvals.status", asker, { id: approval })).ruleProposal.id
      const co = await rowFor(cosign)
      expect(co.found.ask.detail).not.toHaveProperty("bindingCode")
      expect(co.html).toContain("Co-sign: allow from now on: tasks-key")
      expect(co.html).not.toContain('data-check="code"')
      await decide(ctx, "owner", { id: cosign, decision: "approve", effective: { path: "/tasks/*", ttlSeconds: 86_400 } })
      const [rule] = await rulesOf(ctx, asker)
      const extension = await rowFor((await extend(ctx, "member", rule!.id, 604_800)).coSign.id)
      expect(extension.found.ask.detail).not.toHaveProperty("bindingCode")
      expect(extension.html).toContain(`Extend ${rule!.id}: tasks-key`)
      expect(extension.html).not.toContain("Allow from now on")
      expect(extension.html).not.toContain('data-check="code"')
    })
  })
})

describe("co-signing an extension", () => {
  it("shows the extended terms' own digest, offers only the rule's path, and refuses a narrower one", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedTasks(ctx)
      const asker = { device: "dev_member" }
      const approval = await held(ctx, { item: "tasks-key", method: "PATCH", url: "https://api.example.com/tasks/123", body: json({ done: true }) }, asker)
      expect((await offerOf(ctx, "member", approval))?.pathChoices).toEqual(["/tasks/123", "/tasks/*"])
      await remember(ctx, "member", approval, { path: "/tasks/*", ttlSeconds: 86_400 })
      const proposal = (await op(ctx, "approvals.status", asker, { id: approval })).ruleProposal.id
      await decide(ctx, "owner", { id: proposal, decision: "approve", effective: { path: "/tasks/*", ttlSeconds: 86_400 } })
      const [rule] = await rulesOf(ctx, asker)
      expect(rule).toMatchObject({ path: "/tasks/*" })
      const extended = await extend(ctx, "member", rule!.id, 604_800)
      const view = (await op(ctx, "policy.status", "owner", { id: extended.coSign.id })).proposal
      expect(view).toMatchObject({ extends: rule!.id, terms: { path: "/tasks/*", ttlSeconds: 604_800 }, pathChoices: ["/tasks/*"] })
      expect(view.termsDigest).toBe(await policyRuleTermsDigest(view.terms))
      const narrower = { id: extended.coSign.id, decision: "approve", effective: { path: "/tasks/123", ttlSeconds: 604_800 } }
      await expect(op(ctx, "policy.action", "owner", narrower)).rejects.toMatchObject({ code: "bad_request" })
      await expect(op(ctx, "policy.decide", "owner", narrower, { type: "policy.decide", proposal: extended.coSign.id, digest: view.digest, decision: "approve", effectDigest: "" })).rejects.toMatchObject({ code: "bad_request" })
      await decide(ctx, "owner", { id: extended.coSign.id, decision: "approve", effective: { path: "/tasks/*", ttlSeconds: 604_800 } })
      const [after] = await rulesOf(ctx, asker)
      expect(after).toMatchObject({ id: rule!.id, path: "/tasks/*", ttlSeconds: 604_800 })
      await expectStoredTerms(ctx, rule!.id, 604_800)
      expectEndsIn(ctx, after!.endsAt, 7 * DAY)
    })
  })
})

describe("the activity lines of rule events", () => {
  // Every rule event the vault writes, as the activity page words it.
  const lines = (ctx: VaultContext) => ctx.sql.exec<{ actor: string; action: string; target: string | null; detail: string }>("SELECT actor,action,target,detail FROM audit WHERE action LIKE 'rule.%' OR action IN ('policy.deny','policy.cancel') ORDER BY seq").toArray()
    .map((event) => ({ action: event.action, text: (({ actor, pieces }) => actor + pieces.map((p) => p.text).join(""))(auditLine(event, { self: null, devices: new Map([["dev_member", "Member's laptop"], ["dev_owner", "Owner's laptop"]]), members: new Map([["mem_member", "member"], ["mem_owner", "owner"]]) })) }))
  const extensionOf = (rule: string) => `the extension of rule ${rule}`

  it("names an extension's request, co-sign and denial as the extension of its rule, never as allowing it from now on, and every rule action has its line", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      setUpstreamFetch(async () => new Response("ok"))
      await seedTasks(ctx)
      const asker = { device: "dev_member" }
      const task = (n: number): Sent => ({ item: "tasks-key", method: "PATCH", url: "https://api.example.com/tasks/123", body: json({ n }) })
      const approval = await held(ctx, task(1), asker)
      await remember(ctx, "member", approval, { path: "/tasks/*", ttlSeconds: 86_400 })
      const proposal = (await op(ctx, "approvals.status", asker, { id: approval })).ruleProposal.id
      await decide(ctx, "owner", { id: proposal, decision: "approve", effective: { path: "/tasks/*", ttlSeconds: 86_400 } })
      const [rule] = await rulesOf(ctx, asker)
      expect((await relay(ctx, task(2), asker)).material?.rules).toEqual([rule!.id])
      const before = lines(ctx).length
      // The member asks, the owner denies; the member asks again, the owner co-signs.
      const denied = (await extend(ctx, "member", rule!.id, 604_800)).coSign.id
      await decide(ctx, "owner", { id: denied, decision: "deny" })
      const signed = (await extend(ctx, "member", rule!.id, 2_592_000)).coSign.id
      await decide(ctx, "owner", { id: signed, decision: "approve", effective: { path: "/tasks/*", ttlSeconds: 2_592_000 } })
      const [extended] = await rulesOf(ctx, asker)
      const extension = lines(ctx).slice(before)
      expect(extension).toEqual([
        { action: "rule.propose", text: `member asked a second person to co-sign ${extensionOf(rule!.id)} with tasks-key for up to 7 days` },
        { action: "policy.deny", text: `owner denied ${extensionOf(rule!.id)} with tasks-key for up to 7 days` },
        { action: "rule.propose", text: `member asked a second person to co-sign ${extensionOf(rule!.id)} with tasks-key for up to 30 days` },
        { action: "rule.extend", text: `owner co-signed ${extensionOf(rule!.id)} with tasks-key to ${formatTime(extended!.endsAt)}` },
      ])
      // The member's machine asks for a rule and withdraws it, then the rule is stopped.
      const proposed = await op(ctx, "policy.propose", asker, { from: { item: "tasks-key", method: "POST", url: "https://api.example.com/tasks", bodyBase64: Buffer.from("{}").toString("base64"), contentType: "application/json" }, reason: "Create tasks" })
      await op(ctx, "policy.cancel", asker, { id: proposed.proposal })
      await op(ctx, "policy.rules.revoke", "member", { id: rule!.id })
      const all = lines(ctx)
      expect(new Set(all.map((l) => l.action))).toEqual(new Set(["rule.propose", "rule.create", "rule.use", "rule.extend", "policy.deny", "policy.cancel", "rule.end"]))
      for (const l of all) expect(l.text.includes("from now on"), l.text).toBe(l.action === "rule.create" || l.action === "rule.propose" && !l.text.includes("extension"))
      expect(all.filter((l) => l.text.includes("extension")).map((l) => l.action)).toEqual(["rule.propose", "policy.deny", "rule.propose", "rule.extend"])
    })
  })

  it("names an extension made directly as extending its rule to its new end", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      await remember(ctx, "owner", await held(ctx, linearCall(comment("First"))), { ttlSeconds: 86_400 })
      const [rule] = await rulesOf(ctx)
      const extended = await extend(ctx, "owner", rule!.id, 604_800)
      expect(lines(ctx).filter((l) => l.action === "rule.extend")).toEqual([{ action: "rule.extend", text: `owner extended rule ${rule!.id} with linear-work to ${formatTime(extended.rule.endsAt)}` }])
    })
  })
})

describe("a machine asks for a rule", () => {
  it("previews, proposes, lists, narrows on decide, and reuses an identical pending ask", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const approval = await held(ctx, linearCall(comment("First")))
      const asker = { device: "dev_owner" }
      const preview = await op(ctx, "policy.preview", asker, { from: { approval }, reason: "Comment on issues" })
      expect(preview).toMatchObject({ refused: null, pathChoices: ["/graphql"], terms: { path: "/graphql", graphql: { fields: ["commentCreate"] } } })
      // Asked outside any project, the rule covers only requests made outside one.
      expect(preview.summary).toBe("POST api.linear.app/graphql, commentCreate, from dev_owner, outside any project, 7 days")
      const input = { from: { approval }, ttlSeconds: 604_800, reason: "Comment on issues" }
      const created = await op(ctx, "policy.propose", asker, input)
      expect(created).toMatchObject({ proposal: expect.stringMatching(/^pol_/), stage: "approve", status: "pending", rule: null })
      expect(await op(ctx, "policy.propose", asker, input)).toMatchObject({ proposal: created.proposal, reused: true })
      await expect(op(ctx, "policy.propose", asker, { ...input, reason: "Something else" })).rejects.toMatchObject({ code: "conflict", message: expect.stringContaining(created.proposal) })
      expect(await op(ctx, "policy.status", asker, { id: created.proposal })).toMatchObject({ proposal: created.proposal, status: "pending" })
      expect((await op(ctx, "pending.list", asker, {})).pending.map((p: any) => p.detail?.id)).toContain(created.proposal)
      expect((await op(ctx, "pending.list", "owner", {})).pending.map((p: any) => p.detail?.id)).toContain(created.proposal)
      // A decision may narrow, never widen.
      await expect(decide(ctx, "owner", { id: created.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 2_592_000 } })).rejects.toMatchObject({ code: "bad_request" })
      await decide(ctx, "owner", { id: created.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 86_400 } })
      expect(await op(ctx, "policy.status", asker, { id: created.proposal })).toMatchObject({ status: "approved", rule: { id: expect.stringMatching(/^rul_/) } })
      const [rule] = await rulesOf(ctx)
      expectEndsIn(ctx, rule!.endsAt, DAY)
    })
  })

  it("proposes from a held or approved request only, never a denied or expired one", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const asker = { device: "dev_owner" }
      const refusal = { code: "conflict", message: "That request was denied or has expired; propose from an example request instead." }
      const denied = await held(ctx, linearCall(comment("Denied")))
      const no = { id: denied, decision: "deny" }
      await op(ctx, "approvals.decide", "owner", no, await op(ctx, "approvals.action", "owner", no))
      await expect(op(ctx, "policy.preview", asker, { from: { approval: denied }, reason: "Comment on issues" })).rejects.toMatchObject(refusal)
      const lapsed = await held(ctx, linearCall(comment("Lapsed")))
      const expiresAt = ctx.sql.exec<{ expires_at: number }>("SELECT expires_at FROM approvals WHERE id=?", lapsed).toArray()[0]!.expires_at
      await expect(op(at(ctx, expiresAt), "policy.propose", asker, { from: { approval: lapsed }, reason: "Comment on issues" })).rejects.toMatchObject(refusal)
      const approved = await held(ctx, linearCall(comment("Approved")))
      const yes = { id: approved, decision: "approve" }
      await op(ctx, "approvals.decide", "owner", yes, await op(ctx, "approvals.action", "owner", yes))
      expect(await op(ctx, "policy.propose", asker, { from: { approval: approved }, reason: "Comment on issues" })).toMatchObject({ status: "pending" })
    })
  })

  it("proposes from a described request, and cancels its own ask", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const asker = { device: "dev_owner" }
      const from = { item: "linear-work", method: "POST", url: "https://api.linear.app/graphql", bodyBase64: Buffer.from(JSON.stringify(comment("x"))).toString("base64"), contentType: "application/json" }
      const created = await op(ctx, "policy.propose", asker, { from, reason: "Comment on issues" })
      await expect(op(ctx, "policy.cancel", { device: "dev_member" }, { id: created.proposal })).rejects.toMatchObject({ code: "not_found" })
      expect(await op(ctx, "policy.cancel", asker, { id: created.proposal })).toMatchObject({ status: "cancelled" })
      await expect(op(ctx, "policy.propose", asker, { from: { ...from, bodyBase64: Buffer.from(JSON.stringify(mutation("issueDelete"))).toString("base64") }, reason: "Delete" })).rejects.toMatchObject({ code: "forbidden", extra: { ruleRefused: "rule.destructive" } })
    })
  })
})

describe("the POLICY_RULES switch and managed workspaces", () => {
  for (const value of ["off", UNLISTED]) it(`refuses every rule op with the switch ${JSON.stringify(value)}, offers nothing, and stops covering`, async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const first = await held(ctx, linearCall(comment("First")))
      await remember(ctx, "owner", first)
      const [rule] = await rulesOf(ctx)
      const off = switchedOff(ctx, value)
      // The approval's status is as before rules: no rule named.
      expect(await op(off, "approvals.status", { device: "dev_owner" }, { id: first })).not.toHaveProperty("rule")
      const approval = await held(off, linearCall(comment("Second")))
      expect(await offerOf(off, "owner", approval)).toBeUndefined()
      await expect(remember(off, "owner", approval)).rejects.toThrow("No rule offered")
      const forbidden = { code: "forbidden", message: "Policy widening is not available yet." }
      await expect(op(off, "approvals.action", "owner", { id: approval, decision: "approve", remember: { kind: "rule", path: "/graphql", ttlSeconds: 604_800, termsDigest: "A".repeat(43) } })).rejects.toMatchObject(forbidden)
      await expect(rulesOf(off)).rejects.toMatchObject(forbidden)
      await expect(op(off, "policy.rules.revoke", "owner", { id: rule!.id })).rejects.toMatchObject(forbidden)
      await expect(op(off, "policy.rules.extend-action", "owner", { id: rule!.id, ttlSeconds: 86_400 })).rejects.toMatchObject(forbidden)
      await expect(op(off, "policy.propose", { device: "dev_owner" }, { from: { approval }, reason: "x" })).rejects.toMatchObject(forbidden)
      await expect(op(off, "policy.preview", { device: "dev_owner" }, { from: { approval }, reason: "x" })).rejects.toMatchObject(forbidden)
    })
  })

  for (const value of ["off", UNLISTED]) it(`refuses a rule proposal's status, cancel, action and decide, an extend, and lists no proposal, with the switch ${JSON.stringify(value)}`, async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const asker = { device: "dev_owner" }
      await remember(ctx, "owner", await held(ctx, linearCall(comment("First"))))
      const [rule] = await rulesOf(ctx)
      const created = await op(ctx, "policy.propose", { device: "dev_member" }, { from: exampleComment("linear-work"), reason: "Comment on issues" })
      const off = switchedOff(ctx, value)
      const notYet = { code: "forbidden", message: "Policy widening is not available yet." }
      const decision = { id: created.proposal, decision: "deny" }
      for (const call of [
        () => op(off, "policy.status", { device: "dev_member" }, { id: created.proposal }),
        () => op(off, "policy.status", "owner", { id: created.proposal }),
        () => op(off, "policy.cancel", { device: "dev_member" }, { id: created.proposal }),
        () => op(off, "policy.action", "owner", decision),
        () => op(off, "policy.decide", "owner", decision, { type: "policy.decide", proposal: created.proposal, digest: "", decision: "deny", effectDigest: null }),
        () => op(off, "policy.rules.extend", "owner", { id: rule!.id, ttlSeconds: 86_400 }, { type: "policy.decide", proposal: rule!.id, digest: "", decision: "approve", effectDigest: "" }),
      ]) await expect(call()).rejects.toMatchObject(notYet)
      for (const who of [{ device: "dev_member" }, "owner"] as Who[]) expect((await op(off, "pending.list", who, {})).pending.map((p: any) => p.detail?.id ?? p.stop?.id)).not.toContain(created.proposal)
      expect(await op(ctx, "policy.status", asker, { id: created.proposal }).catch((error: VaultError) => error.code)).toBe("not_found")
    })
  })

  for (const value of ["off", UNLISTED]) it(`answers a remember with the switch ${JSON.stringify(value)} as before rules: the switch before deny and limits, the decider's refusal before the switch`, async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const off = switchedOff(ctx, value)
      const approval = await held(off, linearCall(comment("First")), { device: "dev_member" })
      const remembered = { kind: "rule", path: "/graphql", ttlSeconds: 604_800, termsDigest: "A".repeat(43) }
      const notYet = { code: "forbidden", message: "Policy widening is not available yet." }
      await expect(op(off, "approvals.action", "member", { id: approval, decision: "deny", remember: remembered })).rejects.toMatchObject(notYet)
      await expect(op(off, "approvals.action", "member", { id: approval, decision: "approve", constraints: { uses: null, ttlSeconds: 86_400 }, remember: remembered })).rejects.toMatchObject(notYet)
      await expect(op(off, "approvals.decide", "member", { id: approval, decision: "deny", remember: remembered }, { type: "approval.decide", approval, digest: "", decision: "deny", constraints: { uses: 1, ttlSeconds: 900 } })).rejects.toMatchObject(notYet)
      // Someone who may not approve this machine's ask is refused as they were.
      const plain = await op(off, "approvals.decide", "admin", { id: approval, decision: "approve" }).catch((error: VaultError) => error)
      expect(plain).toBeInstanceOf(VaultError)
      await expect(op(off, "approvals.decide", "admin", { id: approval, decision: "approve", remember: remembered })).rejects.toMatchObject({ code: plain.code, message: plain.message })
      expect(count(ctx, "approvals WHERE status='pending'")).toBe(1)
    })
  })

  it("reads an approval's rule, a machine's rules and a co-sign's proposal by index", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, (ctx) => {
      const plan = (sql: string) => withTrustedSchema(ctx, () => ctx.sql.exec<{ detail: string }>(`EXPLAIN QUERY PLAN ${sql}`, "x")).toArray().map((r) => r.detail).join(" ")
      expect(plan("SELECT * FROM policy_rules WHERE source=?")).toContain("policy_rules_source")
      expect(plan("SELECT * FROM policy_rules WHERE device=?")).toContain("policy_rules_device")
      expect(plan("SELECT * FROM policy_proposals WHERE requester=?")).toContain("policy_proposals_requester")
    })
  })

  it("reads POLICY_RULES as on, off, or a list of workspace ids, and anything else as off for every workspace", () => {
    const here = "tn_listed0000001"
    const on = (value: string | undefined) => policyRulesOn({ POLICY_RULES: value }, here)
    for (const value of ["on", " on ", here, `tn_elsewhere0001,${here}`, ` tn_elsewhere0001 , ${here} `]) expect(on(value), value).toBe(true)
    for (const value of [undefined, "", "off", UNLISTED, "ON", "yes", "true", `on,${here}`, `${here},`, `${here},,tn_elsewhere0001`, `${here};tn_elsewhere0001`, `${here} tn_elsewhere0001`, `${here},work`, "work", "tn_short"]) expect(on(value), String(value)).toBe(false)
  })

  it("serves rules in a listed workspace, and in one the list leaves out stores no copy and matches no rule", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const listed = switched(ctx, `tn_elsewhere0001, ${ctx.tenant}`)
      await remember(listed, "owner", await held(listed, linearCall(comment("First"))))
      const [rule] = await rulesOf(listed)
      expect((await relay(listed, linearCall(comment("Second")))).material?.rules).toEqual([rule!.id])
      const unlisted = switched(ctx, UNLISTED)
      const copies = count(ctx, "policy_rule_anchors")
      const { error } = await relay(unlisted, linearCall(comment("Third")))
      expect(error?.code).toBe("approval_required")
      expect(count(ctx, "policy_rule_anchors")).toBe(copies)
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(1)
    })
  })

  it("sweeps a copy at its bound once the list leaves its workspace out, and sets no more work once none is left", async () => {
    const due = (ctx: VaultContext) => ctx.sql.exec<{ due_at: number }>("SELECT due_at FROM schedule WHERE area='policy' AND key=?", RULE_ANCHOR_SWEEP_KEY).toArray().map((r) => r.due_at)
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      const t0 = ctx.now()
      const approval = await held(switched(at(ctx, t0), ctx.tenant), linearCall(comment("First")))
      expect(count(ctx, "policy_rule_anchors WHERE source=?", approval)).toBe(1)
      const unlisted = (ms: number) => switched(at(ctx, ms), UNLISTED)
      await policyArea.alarm!(unlisted(t0 + 2 * DAY - 1), RULE_ANCHOR_SWEEP_KEY)
      expect(count(ctx, "policy_rule_anchors")).toBe(1)
      expect(due(ctx)).toEqual([t0 + 2 * DAY])
      await policyArea.alarm!(unlisted(t0 + 2 * DAY), RULE_ANCHOR_SWEEP_KEY)
      expect(count(ctx, "policy_rule_anchors")).toBe(0)
      expect(due(ctx)).toEqual([])
      // Unlisted from here on: a held request leaves no copy, so the sweep has nothing to do.
      await held(unlisted(t0 + 3 * DAY), linearCall(comment("Second")))
      await policyArea.alarm!(unlisted(t0 + 5 * DAY), RULE_ANCHOR_SWEEP_KEY)
      expect(count(ctx, "policy_rule_anchors")).toBe(0)
      expect(due(ctx)).toEqual([])
    })
  })

  it("refuses in a managed workspace", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedLinear(ctx)
      await remember(ctx, "owner", await held(ctx, linearCall(comment("First"))))
      setSetting(ctx, "managed", { platform: "plt_x", subject: "s", member: "mem_owner" })
      await expect(op(ctx, "policy.rules", { device: "dev_owner" }, {})).rejects.toMatchObject({ code: "forbidden", message: "Policy widening is not available yet." })
      expect(ctx.sql.exec<{ ended_reason: string | null }>("SELECT ended_reason FROM policy_rules").toArray()[0]?.ended_reason ?? null).toBeNull()
      const { material, error } = await relay(ctx, linearCall(comment("Second")))
      // The platform decides it; the rule is neither used nor settled, and the held bytes are not kept.
      expect(material).toBeNull()
      expect(error).toMatchObject({ code: "approval_required", extra: { next: { say: "The platform decides this request." } } })
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(0)
      expect(count(ctx, "policy_rules WHERE uses=0 AND ended_at IS NULL")).toBe(1)
      expect(count(ctx, "policy_rule_anchors WHERE source=?", error!.extra.approval)).toBe(0)
    })
  })
})

// Alex's case: an agent comments on Linear issues through the relay with the
// linear template's credential, and asks for that from now on.
describe("an agent's Linear comments, end to end", () => {
  it("proposes a rule from a held commentCreate, is approved for a day, then comments without asking until Stop, and nothing else passes", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      const linear = TEMPLATES.linear!
      const input = { ...credentialInput("linear-work"), provider: linear.id, kind: linear.kind, ceiling: linear.ceiling, binding: linear.binding, policy: linear.policy, injection: linear.injection, secretFields: { key: "lin_api_synthetic0000000000000000" } }
      const prepared = await prepareCredential(ctx, input, null)
      ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
      const sent: { url: string; authorization: string | null; body: string }[] = []
      setUpstreamFetch(async (request) => { sent.push({ url: request.url, authorization: request.headers.get("authorization"), body: await request.text() }); return new Response(JSON.stringify({ data: { commentCreate: { success: true } } }), { headers: { "content-type": "application/json" } }) })
      const agent = { device: "dev_owner" }
      // A read-only query passes on the template's own rule; the comment is held.
      expect((await relay(ctx, linearCall({ query: "query { viewer { id } }" }), agent)).error).toBeNull()
      const approval = await held(ctx, linearCall(comment("First")), agent)

      const proposed = await op(ctx, "policy.propose", agent, { from: { approval }, reason: "Comment on the issues I work on" })
      const view = (await op(ctx, "policy.status", "owner", { id: proposed.proposal })).proposal
      expect(view).toMatchObject({ terms: { method: "POST", host: "api.linear.app", path: "/graphql", graphql: { fields: ["commentCreate"] }, asker: { device: "dev_owner", workload: null } } })
      await decide(ctx, "owner", { id: proposed.proposal, decision: "approve", effective: { path: "/graphql", ttlSeconds: 86_400 } })
      expect(await op(ctx, "policy.status", agent, { id: proposed.proposal })).toMatchObject({ status: "approved" })
      const [rule] = await rulesOf(ctx, agent)
      expect(rule).toMatchObject({ status: "active", ttlSeconds: 86_400, graphql: { fields: ["commentCreate"] } })
      expectEndsIn(ctx, rule!.endsAt, DAY)

      // Another comment, with another body, goes without asking.
      const other = comment("A different comment, on another day")
      const { material, error } = await relay(ctx, linearCall(other), agent)
      expect(error).toBeNull()
      expect(material!.rules).toEqual([rule!.id])
      const response = await forwardRelay(material!, enc(other))
      expect(response.headers.get(RULE_HEADER)).toBe(rule!.id)
      expect(sent.at(-1)).toEqual({ url: "https://api.linear.app/graphql", authorization: "lin_api_synthetic0000000000000000", body: JSON.stringify(other) })

      // Deleting an issue with the same credential still asks.
      expect((await relay(ctx, linearCall(mutation("issueDelete")), agent)).error?.code).toBe("approval_required")
      // So does the same comment from another machine's key, or a workload's on this machine.
      addWorkload(ctx, "wl_othertask", "dev_owner")
      for (const asker of [{ device: "dev_member" }, { device: "dev_owner", workload: "wl_othertask" }]) expect((await relay(ctx, linearCall(comment("Third")), asker)).error?.code).toBe("approval_required")

      // After Stop, a comment asks again.
      expect(await op(ctx, "policy.rules.revoke", "owner", { id: rule!.id })).toMatchObject({ status: "ended", endedReason: "revoked" })
      expect((await relay(ctx, linearCall(comment("Fourth")), agent)).error?.code).toBe("approval_required")
      expect(await rulesOf(ctx, agent)).toMatchObject([{ id: rule!.id, status: "ended", uses: 1 }])

      // The owner approves a held comment and allows it for a day from the approval page.
      await remember(ctx, "owner", await held(ctx, linearCall(comment("Again")), agent), { ttlSeconds: 86_400 })
      const remembered = (await rulesOf(ctx, agent)).find((r) => r.status === "active")!
      expect(remembered).toMatchObject({ ttlSeconds: 86_400, graphql: { fields: ["commentCreate"] } })
      expectEndsIn(ctx, remembered.endsAt, DAY)
      const next = comment("Yet another comment, with its own body")
      const allowed = await relay(ctx, linearCall(next), agent)
      expect(allowed.error).toBeNull()
      expect(allowed.material!.rules).toEqual([remembered.id])
      expect((await forwardRelay(allowed.material!, enc(next))).headers.get(RULE_HEADER)).toBe(remembered.id)
      expect(sent.at(-1)).toEqual({ url: "https://api.linear.app/graphql", authorization: "lin_api_synthetic0000000000000000", body: JSON.stringify(next) })
      expect((await relay(ctx, linearCall(mutation("issueDelete")), agent)).error?.code).toBe("approval_required")
    })
  })
})
