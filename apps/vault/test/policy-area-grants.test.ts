// Task grants in the vault (areas/policy-rules-workspace.ts, kind "area"):
// the offer on an approval, the area remember rebuilt and its digest
// compared, the relay's use of a grant after any shape rule, the asks a new
// grant closes, every way a grant ends, the co-sign it waits on, and what a
// machine of each version may read. GitHub's catalogue, and a test-only one
// on api.example.com with two areas and an entry that takes stored bytes.
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest"
import { RULE_HEADER, base64UrlEncode, canonicalJson, createProof, leaseOnlyBinding, type CredentialHome, type WorkspaceStepUpAction } from "@mehen/protocol"
import { POLICY_CATALOGUES, type PolicyCatalogue } from "@mehen/protocol/policy-catalogue"
import type { AreaGrantDuration, PolicyAreaGrantTerms, PolicyAreaGrantView, PolicyAreaOffer } from "@mehen/protocol/policy-mode"
import { policyAreaGrantTermsDigest, policyRuleTermsDigest } from "@mehen/protocol/policy-rules"
import { VaultError } from "../src/http.ts"
import { forwardRelay } from "../src/relay/forward.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { auditLine } from "../src/ui/wording.ts"
import { workspaceProposalPage } from "../src/ui/pages/workspace-asks.ts"
import { GALLERY_WORKSPACE, VIEWERS, galleryShell } from "../src/ui/workspace-projects-gallery.ts"
import type { PolicyAreaProposalViewProjection } from "@mehen/protocol/workspace"
import type { AccessPrincipal } from "../src/vault/access.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { workspaceApprovalOps } from "../src/vault/areas/approvals-workspace.ts"
import { prepareCredential, storeCredential } from "../src/vault/areas/items-workspace.ts"
import { policyArea } from "../src/vault/areas/policy.ts"
import { RULE_ANCHOR_SWEEP_KEY } from "../src/vault/areas/policy-rules-workspace.ts"
import { workspacePolicyOps } from "../src/vault/areas/policy-workspace.ts"
import { authoriseWorkspaceRelay } from "../src/vault/areas/relay-workspace.ts"
import { setSetting, updateRestriction, type WorkspaceInvocationContext } from "../src/vault/areas/workspace-runtime.ts"
import { workspacePendingOps } from "../src/vault/areas/pending-workspace.ts"
import { credentialInput, credentialsFixture, inAccess, memberInvocation, memberPrincipal } from "./credentials-test-support.ts"
import { PROJECT_RUN_INPUT, approvedProjectRun, projectFixture } from "./projects-workspace-fixture.ts"
import { seedRelayProject, seedRelayVar } from "./relay-fixtures.ts"
import { registerCredentialProvider } from "../src/vault/areas/items-workspace.ts"
import { workspaceRunOps } from "../src/vault/areas/runs-workspace.ts"
import type { WorkspaceRunCreated } from "@mehen/protocol"
import { setPosture } from "./postures-test-support.ts"
import { fixtureSql } from "./fixture-sql.ts"

// A reviewed catalogue for the test's own host: tasks sent as JSON, and
// uploads whose bytes are the file, which no shape rule takes.
const EXAMPLE_CATALOGUE: PolicyCatalogue = {
  template: "example",
  version: 1,
  hosts: ["api.example.com"],
  areas: [{ id: "tasks", name: "Tasks", words: "Creates tasks" }, { id: "uploads", name: "Uploads", words: "Uploads files" }],
  entries: [
    { id: "example.task-create", area: "tasks", effect: "routine", methods: ["POST"], path: "/tasks", body: "json", words: "Creates a task", since: 1, additionalPermission: false },
    { id: "example.upload", area: "uploads", effect: "routine", methods: ["POST"], path: "/uploads", body: "data", words: "Uploads a file", since: 1, additionalPermission: false },
  ],
  floor: [],
}
beforeAll(() => { (POLICY_CATALOGUES as PolicyCatalogue[]).push(EXAMPLE_CATALOGUE) })
afterAll(() => { (POLICY_CATALOGUES as PolicyCatalogue[]).splice(POLICY_CATALOGUES.indexOf(EXAMPLE_CATALOGUE), 1) })
afterEach(() => { setUpstreamFetch(null); vi.restoreAllMocks() })

const DAY = 86_400_000
const enc = (value: unknown): Uint8Array<ArrayBuffer> => new TextEncoder().encode(JSON.stringify(value)) as Uint8Array<ArrayBuffer>
type Body = { bytes: Uint8Array<ArrayBuffer>; contentType: string } | null
const json = (value: unknown): Body => ({ bytes: enc(value), contentType: "application/json" })

// A key whose policy holds every request, on GitHub or the test's host.
async function seedKey(ctx: VaultContext, slug: string, host: string, home: CredentialHome = { kind: "workspace" }, secret = "ghp_fixture000000000000000000000000000") {
  const input = { ...credentialInput(slug, home), binding: { hosts: [host] }, policy: { default: "approve" as const, rules: [] }, secretFields: { key: secret } }
  const prepared = await prepareCredential(ctx, input, null)
  return ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
}
const seedGithub = (ctx: VaultContext, home?: CredentialHome) => seedKey(ctx, "github-work", "api.github.com", home)
const seedExample = (ctx: VaultContext, secret?: string) => seedKey(ctx, "example-key", "api.example.com", undefined, secret)

type Sent = { item: string; url: string; body: Body; method?: string; context?: { project: string; environment: string } }
const github = (path: string, body: unknown, method = "POST"): Sent => ({ item: "github-work", method, url: `https://api.github.com${path}`, body: body === null ? null : json(body) })
const commentOn = (issue: number, text: string) => github(`/repos/northwind/platform/issues/${issue}/comments`, { body: text })
const deleteComment = (id: number) => github(`/repos/northwind/platform/issues/comments/${id}`, null, "DELETE")
const openPull = () => github("/repos/northwind/platform/pulls", { title: "x", head: "a", base: "main" })
const task = (title: string): Sent => ({ item: "example-key", url: "https://api.example.com/tasks", body: json({ title }) })
const upload = (text: string): Sent => ({ item: "example-key", url: "https://api.example.com/uploads", body: { bytes: new TextEncoder().encode(text) as Uint8Array<ArrayBuffer>, contentType: "application/octet-stream" } })
const relayInput = (sent: Sent) => ({ item: sent.item, method: sent.method ?? "POST", url: sent.url, headers: sent.body ? [["content-type", sent.body.contentType] as [string, string]] : [], ...(sent.body ? { body: base64UrlEncode(sent.body.bytes) } : {}), ...(sent.context ? { context: sent.context } : {}) })

// A machine key, with the mehen version its User-Agent names (none: unknown).
type Asker = { device: string; workload?: string; cli?: string }
const OWNER: Asker = { device: "dev_owner" }
const principalOf = (asker: Asker): AccessPrincipal => ({ kind: "device", deviceId: asker.device, ...(asker.workload ? { workload: asker.workload } : {}) })
async function invocationOf(ctx: VaultContext, asker: Asker): Promise<WorkspaceInvocationContext> {
  const proof = await createProof({ deviceId: asker.device, sign: async () => new Uint8Array(64) }, { method: "POST", url: "https://vault.test/v1/relay" }, { tenant: ctx.tenant })
  return { workspace: { id: ctx.tenant, slug: "work", name: "Work" }, auth: { kind: "device", proof, method: "POST", url: "https://vault.test/v1/relay", bodyHash: "", ...(asker.cli ? { cliVersion: asker.cli } : {}) } }
}
// A relay from mehen 0.3.17, which reads grants, unless the test names another.
async function relay(ctx: VaultContext, sent: Sent, asker: Asker = { ...OWNER, cli: "0.3.17" }) {
  try { return { material: await authoriseWorkspaceRelay(ctx, principalOf(asker), relayInput(sent), await invocationOf(ctx, asker)), error: null } }
  catch (error) { if (error instanceof VaultError) return { material: null, error }; throw error }
}
async function held(ctx: VaultContext, sent: Sent, asker: Asker = OWNER): Promise<string> {
  const { error } = await relay(ctx, sent, asker)
  expect(error?.code).toBe("approval_required")
  return error!.extra.approval!
}

const ops = { ...workspaceApprovalOps, ...workspacePolicyOps, ...workspacePendingOps }
type Who = string | Asker
async function op(ctx: VaultContext, name: string, who: Who, input: unknown, action?: WorkspaceStepUpAction): Promise<any> {
  const handler = ops[name]!.handler
  if (typeof who === "string") return handler(ctx, memberPrincipal(ctx, who), input, memberInvocation(ctx, who, action))
  return handler(ctx, principalOf(who), input, await invocationOf(ctx, who))
}
async function areaOfferOf(ctx: VaultContext, role: string, approval: string): Promise<PolicyAreaOffer | undefined> {
  const view = await op(ctx, "approvals.view", role, { id: approval })
  return view.view === "detail" ? view.approval.rememberOptions?.area : undefined
}
type Choice = { areas?: string[]; ttlSeconds?: AreaGrantDuration; maxUses?: number; termsDigest?: string }
async function areaRemember(ctx: VaultContext, role: string, approval: string, choice: Choice = {}) {
  const offer = await areaOfferOf(ctx, role, approval)
  if (!offer?.terms) throw new Error(`No task grant offered: ${offer?.refused}`)
  const areas = choice.areas ?? offer.terms.areas, ttlSeconds = choice.ttlSeconds ?? offer.terms.ttlSeconds, maxUses = choice.maxUses ?? offer.terms.maxUses
  const input = { id: approval, decision: "approve", remember: { kind: "area", areas, ttlSeconds, maxUses, termsDigest: choice.termsDigest ?? await policyAreaGrantTermsDigest({ ...offer.terms, areas, ttlSeconds, maxUses }) } }
  const action = await op(ctx, "approvals.action", role, input)
  return op(ctx, "approvals.decide", role, input, action)
}
const NEW_CLI: Asker = { ...OWNER, cli: "0.3.17" }
const grantsOf = (ctx: VaultContext, asker: Asker = NEW_CLI): Promise<PolicyAreaGrantView[]> => op(ctx, "policy.rules", asker, { include: "grants" })
const count = (ctx: VaultContext, sql: string, ...args: unknown[]) => ctx.sql.exec<{ n: number }>(`SELECT count(*) AS n FROM ${sql}`, ...args).toArray()[0]!.n
const at = (ctx: VaultContext, ms: number): VaultContext => Object.assign(Object.create(ctx) as VaultContext, { now: () => ms })
const switched = (ctx: VaultContext, value: string): VaultContext => Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, POLICY_RULES: value } })
const inRules = <T>(tenant: string, fn: (ctx: VaultContext) => T | Promise<T>): Promise<T> => inAccess(tenant, (ctx) => fn(switched(ctx, "on")))
// Every task grant event the vault writes, as the activity page words it.
const lines = (ctx: VaultContext) => ctx.sql.exec<{ actor: string; action: string; target: string | null; detail: string }>("SELECT actor,action,target,detail FROM audit WHERE action LIKE 'rule.%' OR action='approval.supersede' ORDER BY seq").toArray()
  .map((event) => ({ action: event.action, text: (({ actor, pieces }) => actor + pieces.map((p) => p.text).join(""))(auditLine(event, { self: null, devices: new Map([["dev_owner", "Owner's laptop"]]), members: new Map([["mem_owner", "owner"]]) })) }))
const pendingIds = (ctx: VaultContext) => ctx.sql.exec<{ id: string }>("SELECT id FROM approvals WHERE status='pending' AND policy_status IS NULL ORDER BY id").toArray().map((r) => r.id)

describe("the task grant an approval offers", () => {
  it("offers a routine GitHub comment the request's own area, 1 hour and 50 requests", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const offer = await areaOfferOf(ctx, "owner", await held(ctx, commentOn(1, "First")))
      expect(offer).toMatchObject({ refused: null, coSign: false, areas: [{ id: "issues", name: "Issues and comments", requestArea: true }], terms: { kind: "area", item: "github-work", host: "api.github.com", catalogue: "github", catalogueVersion: 1, areas: ["issues"], ttlSeconds: 3600, maxUses: 50, asker: { device: "dev_owner", workload: null } } })
      expect(offer!.termsDigest).toBe(await policyAreaGrantTermsDigest(offer!.terms!))
    })
  })

  it("refuses a service nobody reviewed, a request that is not routine, a floor request and a live key", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await seedKey(ctx, "linear-work", "api.linear.app")
      await seedExample(ctx, "sk_live_fixture000000000000000000")
      const refused = async (sent: Sent) => (await areaOfferOf(ctx, "owner", await held(ctx, sent)))?.refused
      expect(await refused({ item: "linear-work", url: "https://api.linear.app/v1/things", body: json({ a: 1 }) })).toBe("area.unreviewed")
      expect(await refused(openPull())).toBe("area.not-routine")
      expect(await refused(deleteComment(5))).toBe("area.not-routine")
      expect(await refused(task("a"))).toBe("area.live-key")
    })
  })

  it("offers nothing to someone who may only stop the ask, on a protected credential, in a managed workspace or with the switch off", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const approval = await held(ctx, commentOn(1, "First"), { device: "dev_owner" })
      expect(await areaOfferOf(ctx, "admin", approval)).toBeUndefined()
      expect(await areaOfferOf(switched(ctx, "off"), "owner", approval)).toBeUndefined()
      expect((await areaOfferOf(ctx, "owner", approval))?.refused).toBeNull()
      setSetting(ctx, "managed", { platform: "plt_x", subject: "s", member: "mem_owner" })
      expect(await areaOfferOf(ctx, "owner", approval)).toBeUndefined()
    })
  })

  it("offers a grant that needs a manager of the credential's home to co-sign as one, as the rule offer does", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const approval = await held(ctx, commentOn(1, "First"), { device: "dev_member" })
      const view = await op(ctx, "approvals.view", "member", { id: approval })
      expect(view.approval.rememberOptions.rule.coSign).toBe(true)
      expect(view.approval.rememberOptions.area).toMatchObject({ refused: null, coSign: true, terms: { areas: ["issues"], asker: { device: "dev_member", workload: null } } })
    })
  })
})

describe("who may let an agent carry on", () => {
  // An area remember the page never offered, refused before its terms are
  // rebuilt, at the step-up's action and at the decision itself.
  async function refusedArea(ctx: VaultContext, role: string, approval: string) {
    const row = ctx.sql.exec<{ digest: string; subject: string }>("SELECT digest,subject FROM approvals WHERE id=?", approval).toArray()[0]!
    const input = { id: approval, decision: "approve", remember: { kind: "area", areas: ["tasks"], ttlSeconds: 3600, maxUses: 50, termsDigest: "A".repeat(43) } }
    const action = { type: "approval.decide", approval, digest: row.digest, decision: "approve", constraints: JSON.parse(row.subject).constraints, remember: input.remember } as WorkspaceStepUpAction
    await expect(op(ctx, "approvals.action", role, input), role).rejects.toMatchObject({ code: "forbidden" })
    await expect(op(ctx, "approvals.decide", role, input, action), role).rejects.toMatchObject({ code: "forbidden" })
  }

  it("offers none on a guest machine's ask on a shared credential, on a member's private credential to anyone but its owner, or on a four-eyes project's ask, and refuses each an area remember, writing no rule", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, () => registerCredentialProvider())
    await inRules(f.tenant, async (ctx) => {
      // prj_a's credential, shared with the guest: the guest reads their machine's ask, and an admin may approve it once.
      await seedKey(ctx, "shared-key", "api.example.com", { kind: "project", project: "prj_a" })
      const guestAsk = await held(ctx, { ...task("a"), item: "shared-key" }, { device: "dev_guest" })
      expect(await op(ctx, "approvals.view", "guest", { id: guestAsk })).toMatchObject({ view: "detail" })
      expect((await op(ctx, "approvals.view", "admin", { id: guestAsk })).approval.eligibility.canApprove).toBe(true)
      for (const role of ["guest", "admin"]) {
        expect(await areaOfferOf(ctx, role, guestAsk), role).toBeUndefined()
        await refusedArea(ctx, role, guestAsk)
      }

      // The member's own private credential: an admin may only stop the ask; another member never sees it.
      await seedKey(ctx, "member-key", "api.example.com", { kind: "member", member: "mem_member" })
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      const privateAsk = await held(ctx, { ...task("b"), item: "member-key" }, { device: "dev_member" })
      expect(await op(ctx, "approvals.view", "admin", { id: privateAsk })).toMatchObject({ view: "stop" })
      expect(await areaOfferOf(ctx, "admin", privateAsk)).toBeUndefined()
      await refusedArea(ctx, "admin", privateAsk)
      await expect(op(ctx, "approvals.view", "kim", { id: privateAsk })).rejects.toMatchObject({ code: "not_found" })
      expect((await areaOfferOf(ctx, "member", privateAsk))?.refused).toBeNull()

      // A run in prj_a's prod, which needs a second person: the owner may approve it once.
      let runAsk = ""
      try { await workspaceRunOps["runs.create"]!.handler(ctx, principalOf({ device: "dev_kim" }), PROJECT_RUN_INPUT, await invocationOf(ctx, { device: "dev_kim" })) }
      catch (error) { if (!(error instanceof VaultError) || error.code !== "approval_required") throw error; runAsk = error.extra.approval! }
      expect((await op(ctx, "approvals.view", "owner", { id: runAsk })).approval.eligibility.canApprove).toBe(true)
      expect(await areaOfferOf(ctx, "owner", runAsk)).toBeUndefined()
      await refusedArea(ctx, "owner", runAsk)

      expect(count(ctx, "policy_rules")).toBe(0)
      expect(count(ctx, "policy_proposals")).toBe(0)
      expect(pendingIds(ctx)).toEqual([guestAsk, privateAsk, runAsk].sort())
    })
  })
})

describe("an area remember", () => {
  it("approves the request once and makes a grant that lets the next routine comment and issue through with Mehen-Rule, counting each by entry", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const approval = await held(ctx, commentOn(1, "First"))
      await areaRemember(ctx, "owner", approval, { ttlSeconds: 900, maxUses: 10 })
      const [grant] = await grantsOf(ctx)
      expect(grant).toMatchObject({ kind: "area", status: "active", uses: 0, maxUses: 10, areas: ["issues"], approvedBy: "owner", coSignedBy: null, endedReason: null, receipt: [] })
      expect(Date.parse(grant!.endsAt) - Date.parse(grant!.createdAt)).toBe(900_000)
      // The approval is approved once and names no rule: a grant is not a shape rule.
      const status = await op(ctx, "approvals.status", NEW_CLI, { id: approval })
      expect(status).toMatchObject({ status: "approved" })
      expect(status).not.toHaveProperty("rule")
      expect(status).not.toHaveProperty("ruleProposal")

      let sends = 0
      setUpstreamFetch(async () => { sends++; return new Response("ok") })
      for (const sent of [commentOn(2, "Second"), github("/repos/northwind/platform/issues", { title: "Bug" }), commentOn(3, "Third")]) {
        const { material, error } = await relay(ctx, sent)
        expect(error).toBeNull()
        expect(material!.rules).toEqual([grant!.id])
        const response = await forwardRelay(material!, sent.body!.bytes)
        expect(response.headers.get(RULE_HEADER)).toBe(grant!.id)
      }
      expect(sends).toBe(3)
      expect((await grantsOf(ctx))[0]).toMatchObject({ uses: 3, receipt: [{ entry: "github.comment-create", words: "Comments on an issue", count: 2 }, { entry: "github.issue-create", words: "Opens an issue", count: 1 }] })
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(3)
      // The grant keeps no copy of the request.
      expect(count(ctx, "policy_rule_anchors WHERE source=?", grant!.id)).toBe(0)
      // A destructive request and one outside the catalogue still ask; one with a query is never covered.
      expect((await relay(ctx, deleteComment(9))).error?.code).toBe("approval_required")
      expect((await relay(ctx, openPull())).error?.code).toBe("approval_required")
      for (const query of ["?_method=DELETE", "?x=1"]) {
        const { material, error } = await relay(ctx, { ...commentOn(4, "query"), url: `https://api.github.com/repos/northwind/platform/issues/4/comments${query}` })
        expect(material, query).toBeNull()
        expect(error, query).not.toBeNull()
      }
      expect(sends).toBe(3)
      expect((await grantsOf(ctx))[0]!.uses).toBe(3)
    })
  })

  it("refuses a digest that is not the vault's terms, an area the catalogue lacks, and a duration or count out of range, storing nothing", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const approval = await held(ctx, commentOn(1, "First"))
      const offer = (await areaOfferOf(ctx, "owner", approval))!
      await expect(areaRemember(ctx, "owner", approval, { termsDigest: await policyAreaGrantTermsDigest({ ...offer.terms!, maxUses: 51 }) })).rejects.toMatchObject({ code: "conflict" })
      await expect(areaRemember(ctx, "owner", approval, { areas: ["pulls"] })).rejects.toMatchObject({ code: "forbidden", extra: { areaRefused: "area.unknown" } })
      for (const remember of [{ ttlSeconds: 600 }, { maxUses: 201 }, { maxUses: 0 }]) {
        const input = { id: approval, decision: "approve", remember: { kind: "area", areas: ["issues"], ttlSeconds: 3600, maxUses: 50, termsDigest: offer.termsDigest, ...remember } }
        await expect(op(ctx, "approvals.action", "owner", input)).rejects.toMatchObject({ code: "bad_request" })
      }
      expect(count(ctx, "policy_rules")).toBe(0)
      expect(pendingIds(ctx)).toEqual([approval])
    })
  })

  it("is refused while the person cools off, as any approval is", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const approval = await held(ctx, commentOn(1, "First"))
      const offer = (await areaOfferOf(ctx, "owner", approval))!
      const input = { id: approval, decision: "approve", remember: { kind: "area", areas: offer.terms!.areas, ttlSeconds: offer.terms!.ttlSeconds, maxUses: offer.terms!.maxUses, termsDigest: offer.termsDigest } }
      const action = await op(ctx, "approvals.action", "owner", input)
      updateRestriction(ctx, "acc_owner", 0, { reason: "recovery", until: ctx.now() + DAY, notice: "ntc_owner" })
      await expect(op(ctx, "approvals.decide", "owner", input, action)).rejects.toBeInstanceOf(VaultError)
      expect(count(ctx, "policy_rules")).toBe(0)
      expect(pendingIds(ctx)).toEqual([approval])
    })
  })

  it("uses a shape rule that covers the request before a task grant", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await areaRemember(ctx, "owner", await held(ctx, commentOn(1, "First")))
      const [grant] = await grantsOf(ctx)
      // A machine's own rule for comments on issue 2, approved by its owner.
      const created = await op(ctx, "policy.propose", OWNER, { from: { item: "github-work", method: "POST", url: "https://api.github.com/repos/northwind/platform/issues/2/comments", bodyBase64: Buffer.from(JSON.stringify({ body: "x" })).toString("base64"), contentType: "application/json" }, reason: "Comment" })
      const decision = { id: created.proposal, decision: "approve", effective: { path: "/repos/northwind/platform/issues/2/comments", ttlSeconds: 86_400 } }
      await op(ctx, "policy.decide", "owner", decision, await op(ctx, "policy.action", "owner", decision))
      const rule = (await op(ctx, "policy.rules", OWNER, {}))[0]
      setUpstreamFetch(async () => new Response("ok"))
      expect((await relay(ctx, commentOn(2, "Second"))).material?.rules).toEqual([rule.id])
      expect((await relay(ctx, commentOn(3, "Third"))).material?.rules).toEqual([grant!.id])
    })
  })
})

describe("the asks a new task grant covers", () => {
  it("closes each pending ask from the key on the credential the grant covers, with no replacement, and leaves a floor ask and one it does not cover pending", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await seedKey(ctx, "github-other", "api.github.com")
      const first = await held(ctx, commentOn(1, "First"))
      const covered = await held(ctx, commentOn(2, "Second"))
      const floor = await held(ctx, deleteComment(5))
      const outside = await held(ctx, openPull())
      const otherKey = await held(ctx, commentOn(3, "Mine"), { device: "dev_member" })
      const otherCredential = await held(ctx, { ...commentOn(4, "Other"), item: "github-other" })
      await areaRemember(ctx, "owner", first)
      const [grant] = await grantsOf(ctx)
      expect(ctx.sql.exec("SELECT policy_status,superseded_by FROM approvals WHERE id=?", covered).toArray()).toEqual([{ policy_status: "superseded", superseded_by: null }])
      expect(pendingIds(ctx)).toEqual([floor, outside, otherKey, otherCredential].sort())
      // A mehen that reads superseded learns it, with nothing to wait on; an older one reads stale.
      const read = await op(ctx, "approvals.status", NEW_CLI, { id: covered })
      expect(read.status).toBe("superseded")
      expect(read).not.toHaveProperty("replacedBy")
      for (const cli of [undefined, "0.3.16"]) expect((await op(ctx, "approvals.status", { ...OWNER, ...(cli ? { cli } : {}) }, { id: covered })).status, String(cli)).toBe("stale")
      const audit = ctx.sql.exec<{ actor: string; target: string; detail: string }>("SELECT actor,target,detail FROM audit WHERE action='approval.supersede'").toArray()
      expect(audit.map((a) => ({ ...a, detail: JSON.parse(a.detail) }))).toEqual([{ actor: "member:mem_owner", target: covered, detail: { item: "github-work", grant: grant!.id } }])
      // Sent again, the grant lets it through.
      setUpstreamFetch(async () => new Response("ok"))
      expect((await relay(ctx, commentOn(2, "Second"))).material?.rules).toEqual([grant!.id])
    })
  })

})

describe("the activity lines of task grant events", () => {

  it("says a person let the agent carry on, the agent used the task grant, the asks it closed, and why it ended", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      setUpstreamFetch(async () => new Response("ok"))
      const first = await held(ctx, commentOn(1, "First"))
      const covered = await held(ctx, commentOn(2, "Second"))
      await areaRemember(ctx, "owner", first, { maxUses: 1 })
      const [grant] = await grantsOf(ctx)
      await relay(ctx, commentOn(3, "Third"))
      await areaRemember(ctx, "owner", await held(ctx, commentOn(4, "Fourth")))
      const [next] = await grantsOf(ctx)
      await op(ctx, "policy.rules.revoke", "owner", { id: next!.id })
      expect(lines(ctx)).toEqual([
        { action: "rule.create", text: `owner let an agent carry on with routine work on api.github.com with github-work as task grant ${grant!.id}` },
        { action: "approval.supersede", text: `owner closed an ask to use github-work that task grant ${grant!.id} now allows` },
        { action: "rule.use", text: `An agent on Owner's laptop used github-work under task grant ${grant!.id}, use 1` },
        { action: "rule.end", text: `The vault ended task grant ${grant!.id} with github-work because it was used as many times as it allows` },
        { action: "rule.create", text: `owner let an agent carry on with routine work on api.github.com with github-work as task grant ${next!.id}` },
        { action: "rule.end", text: `owner stopped task grant ${next!.id} with github-work` },
      ])
      expect(ctx.sql.exec("SELECT target FROM audit WHERE action='approval.supersede'").toArray()).toEqual([{ target: covered }])
    })
  })

  it("says the owner of a private credential closed an ask a task grant now allows, naming no grant, and a machine's newer ask still replaces one", () => {
    const minimal = (actor: string, kind: "member" | "device", outcome: string) => ({ actor, action: "approval.supersede", target: "github-mine", detail: JSON.stringify({ action: "approval.supersede", at: 0, actor: kind === "member" ? { kind, member: "mem_member" } : { kind, device: "dev_member", owner: { kind: "member", member: "mem_member" } }, session: null, item: "itm_githubmine", slug: "github-mine", outcome, run: null }) })
    const words = { self: null, devices: new Map([["dev_member", "Member's laptop"]]), members: new Map([["mem_member", "member"]]) }
    const text = (event: ReturnType<typeof minimal>) => (({ actor, pieces }) => actor + pieces.map((p) => p.text).join(""))(auditLine(event, words))
    expect(text(minimal("member:mem_member", "member", "grant"))).toBe("member closed an ask to use github-mine that a task grant now allows")
    expect(text(minimal("device:dev_member", "device", "superseded"))).toMatch(/^An agent on Member's laptop replaced an ask to use \S+ with a newer one to the same place$/)
  })
})

describe("a task grant on a member's private credential", () => {
  it("keeps its making, its uses, the ask it closes and its ending in the owner's private audit, never the workspace's", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx, { kind: "member", member: "mem_member" })
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      const item = ctx.sql.exec<{ id: string }>("SELECT id FROM items WHERE slug='github-work'").toArray()[0]!.id
      const mine: Asker = { device: "dev_member", cli: "0.3.17" }
      const first = await held(ctx, commentOn(1, "First"), mine)
      const covered = await held(ctx, commentOn(2, "Second"), mine)
      expect((await areaOfferOf(ctx, "member", first))?.refused).toBeNull()
      await areaRemember(ctx, "member", first, { maxUses: 2 })
      const [grant] = await grantsOf(ctx, mine)
      expect(ctx.sql.exec("SELECT policy_status FROM approvals WHERE id=?", covered).toArray()).toEqual([{ policy_status: "superseded" }])
      setUpstreamFetch(async () => new Response("ok"))
      for (const n of [3, 4]) expect((await relay(ctx, commentOn(n, "x"), mine)).error).toBeNull()
      expect((await grantsOf(ctx, mine))[0]).toMatchObject({ status: "ended", endedReason: "uses-spent", uses: 2 })
      const rows = ctx.sql.exec<{ action: string; target: string | null; detail: string; member: string | null }>("SELECT a.action,a.target,a.detail,p.member FROM audit a LEFT JOIN audit_private_owners p ON p.seq=a.seq ORDER BY a.seq").toArray()
      const workspace = JSON.stringify(rows.filter((r) => r.member === null))
      for (const named of [item, "github-work", grant!.id]) expect(workspace, named).not.toContain(named)
      const owned = rows.filter((r) => r.member === "mem_member" && (r.action.startsWith("rule.") || r.action === "approval.supersede"))
      expect(owned.map((r) => [r.action, JSON.parse(r.detail).outcome])).toEqual([["rule.create", "created"], ["approval.supersede", "grant"], ["rule.use", "allowed"], ["rule.use", "allowed"], ["rule.end", "uses_spent"]])
    })
  })
})

describe("one live task grant per key and credential", () => {
  it("ends the earlier grant as replaced when a new one is made", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedExample(ctx)
      await areaRemember(ctx, "owner", await held(ctx, task("a")))
      const [tasks] = await grantsOf(ctx)
      await areaRemember(ctx, "owner", await held(ctx, upload("file")))
      const grants = await grantsOf(ctx)
      expect(grants.map((g) => [g.areas, g.status, g.endedReason])).toEqual([[["uploads"], "active", null], [["tasks"], "ended", "replaced"]])
      expect(grants[1]!.id).toBe(tasks!.id)
      expect(lines(ctx).filter((l) => l.action === "rule.end")).toEqual([{ action: "rule.end", text: `owner ended task grant ${tasks!.id} with example-key because a newer one replaced it` }])
      expect((await relay(ctx, task("b"))).error?.code).toBe("approval_required")
    })
  })
})

describe("a task grant ends", () => {
  it("as uses-spent with the use that reaches its most, and the next request asks", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await areaRemember(ctx, "owner", await held(ctx, commentOn(1, "First")), { maxUses: 2 })
      setUpstreamFetch(async () => new Response("ok"))
      for (const n of [2, 3]) expect((await relay(ctx, commentOn(n, "x"))).error).toBeNull()
      expect((await grantsOf(ctx))[0]).toMatchObject({ status: "ended", endedReason: "uses-spent", uses: 2 })
      expect((await relay(ctx, commentOn(4, "x"))).error?.code).toBe("approval_required")
      expect(count(ctx, "audit WHERE action='rule.end' AND detail LIKE '%uses-spent%'")).toBe(1)
    })
  })

  it("gives the second of two requests racing for its last use a conflict, sending nothing for it", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await areaRemember(ctx, "owner", await held(ctx, commentOn(1, "First")), { maxUses: 1 })
      let sends = 0, raced = false
      setUpstreamFetch(async () => { sends++; return new Response("ok") })
      // The other request takes the last use after this one matched the grant and before its last check.
      const racing = Object.assign(Object.create(ctx) as VaultContext, { async openField(ref: Parameters<VaultContext["openField"]>[0], sealed: Parameters<VaultContext["openField"]>[1]) {
        const value = await ctx.openField(ref, sealed)
        if (!raced) { raced = true; expect((await relay(ctx, commentOn(3, "winner"))).error).toBeNull() }
        return value
      } })
      const { error } = await relay(racing, commentOn(2, "loser"))
      expect(error).toMatchObject({ code: "conflict", message: "The rule that allowed this request has ended; send it again to ask for approval." })
      expect((await grantsOf(ctx))[0]).toMatchObject({ status: "ended", endedReason: "uses-spent", uses: 1 })
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(1)
    })
  })

  it("when its time runs out, when the credential is edited, and when it is stopped from the web; rotation and restore keep it", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      setUpstreamFetch(async () => new Response("ok"))
      await areaRemember(ctx, "owner", await held(ctx, commentOn(1, "First")), { ttlSeconds: 900 })
      expect((await relay(at(ctx, ctx.now() + 900_000), commentOn(2, "late"))).error?.code).toBe("approval_required")
      expect((await grantsOf(at(ctx, ctx.now() + 900_000)))[0]).toMatchObject({ status: "ended", endedReason: "expired" })

      await areaRemember(ctx, "owner", await held(ctx, commentOn(3, "Again")))
      // A rotation and a restore move the version and keep the config.
      fixtureSql(ctx).exec("UPDATE items SET version=version+1 WHERE slug='github-work'")
      expect((await relay(ctx, commentOn(4, "rotated"))).error).toBeNull()
      fixtureSql(ctx).exec("UPDATE items SET config_rev=config_rev+1 WHERE slug='github-work'")
      expect((await relay(ctx, commentOn(5, "edited"))).material).toBeNull()
      expect((await op(ctx, "policy.rules", "owner", { item: "github-work", include: "grants" }))[0]).toMatchObject({ status: "ended", endedReason: "credential-changed" })

      await areaRemember(ctx, "owner", await held(ctx, commentOn(6, "Third")))
      const live = (await op(ctx, "policy.rules", "owner", { include: "grants" }))[0]
      expect(await op(ctx, "policy.rules.revoke", "owner", { id: live.id })).toMatchObject({ id: live.id, kind: "area", status: "ended", endedReason: "revoked" })
      expect((await relay(ctx, commentOn(7, "stopped"))).error?.code).toBe("approval_required")
    })
  })

  it("cannot be extended", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await areaRemember(ctx, "owner", await held(ctx, commentOn(1, "First")))
      const [grant] = await grantsOf(ctx)
      await expect(op(ctx, "policy.rules.extend-action", "owner", { id: grant!.id, ttlSeconds: 86_400 })).rejects.toMatchObject({ code: "bad_request" })
    })
  })
})

describe("a task grant that needs a second person", () => {
  // The member signs the offered grant: the request is approved once, and a
  // proposal at stage co-sign holds the grant's terms, writing no grant.
  async function areaCoSign(ctx: VaultContext): Promise<{ approval: string; proposal: string }> {
    const approval = await held(ctx, commentOn(1, "First"), { device: "dev_member" })
    await areaRemember(ctx, "member", approval)
    const proposal = ctx.sql.exec<{ id: string }>("SELECT id FROM policy_proposals").toArray()[0]!.id
    // The machine's approval names the co-sign it waits on, as for a rule.
    expect(await op(ctx, "approvals.status", { device: "dev_member", cli: "0.3.17" }, { id: approval })).toMatchObject({ status: "approved", ruleProposal: { id: proposal } })
    expect(count(ctx, "policy_rules")).toBe(0)
    return { approval, proposal }
  }

  it("approves the request once and waits for a manager, who sees the member's terms and may co-sign them; the grant then lets the next comment through", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { proposal } = await areaCoSign(ctx)
      const view = await op(ctx, "policy.status", "owner", { id: proposal })
      expect(view.proposal).toMatchObject({ kind: "area", stage: "co-sign", status: "pending", canApprove: true, canDeny: true, terms: { areas: ["issues"], ttlSeconds: 3600, maxUses: 50 }, areas: [{ id: "issues", requestArea: true }], approvedBy: { name: "member" } })
      // It waits in the manager's Needs you, and never in the machine's own list.
      expect(JSON.stringify(await op(ctx, "pending.list", "owner", {}))).toContain(`"title":"Co-sign: let an agent carry on: github-work"`)
      expect(JSON.stringify(await op(ctx, "pending.list", { device: "dev_member", cli: "0.3.17" }, {}))).not.toContain(proposal)
      // The member who signed may not co-sign their own.
      expect((await op(ctx, "policy.status", "member", { id: proposal })).proposal).toMatchObject({ canApprove: false, approvedBy: { self: true } })
      const decision = { id: proposal, decision: "approve", effective: { areas: view.proposal.terms.areas, ttlSeconds: view.proposal.terms.ttlSeconds, maxUses: view.proposal.terms.maxUses } }
      const action = await op(ctx, "policy.action", "owner", decision)
      expect(action.effectDigest).toBe(view.proposal.termsDigest)
      expect((await op(ctx, "policy.decide", "owner", decision, action)).proposal).toMatchObject({ status: "approved" })
      const [grant] = await grantsOf(ctx, { device: "dev_member", cli: "0.3.17" })
      expect(grant).toMatchObject({ kind: "area", status: "active", areas: ["issues"], maxUses: 50, approvedBy: "member", coSignedBy: { name: "owner" } })
      setUpstreamFetch(async () => new Response("ok"))
      expect((await relay(ctx, commentOn(2, "x"), { device: "dev_member", cli: "0.3.17" })).material?.rules).toEqual([grant!.id])
      expect(lines(ctx).find((l) => l.action === "rule.propose")?.text).toMatch(/ asked a second person to let an agent carry on with routine work on api\.github\.com with github-work$/)
    })
  })

  it("refuses the co-sign of a credential protected since the member signed, writing no grant and leaving the proposal pending", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { proposal } = await areaCoSign(ctx)
      const project = seedRelayProject(ctx, { slug: "platform", remote: null, defaultEnv: "prod", environments: [{ name: "prod", protected: true }] })
      seedRelayVar(ctx, { project, env: "prod", name: "GITHUB_TOKEN", item: "github-work" })
      const decision = { id: proposal, decision: "approve", effective: { areas: ["issues"], ttlSeconds: 3600, maxUses: 50 } }
      await expect(op(ctx, "policy.decide", "owner", decision, await op(ctx, "policy.action", "owner", decision))).rejects.toMatchObject({ code: "environment_refused", message: "This credential backs a protected environment, so it asks every time." })
      expect(count(ctx, "policy_rules")).toBe(0)
      expect((await op(ctx, "policy.status", "owner", { id: proposal })).proposal).toMatchObject({ status: "pending", stage: "co-sign" })
    })
  })

  it("makes no grant when the manager declines", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { proposal } = await areaCoSign(ctx)
      const decision = { id: proposal, decision: "deny" }
      expect((await op(ctx, "policy.decide", "owner", decision, await op(ctx, "policy.action", "owner", decision))).proposal).toMatchObject({ status: "denied" })
      expect(count(ctx, "policy_rules")).toBe(0)
      expect(await grantsOf(ctx, { device: "dev_member", cli: "0.3.17" })).toEqual([])
      expect((await relay(ctx, commentOn(2, "x"), { device: "dev_member", cli: "0.3.17" })).error?.code).toBe("approval_required")
      // The activity page says what was declined: a task grant, not wider access.
      const [denied] = ctx.sql.exec<{ actor: string; action: string; target: string | null; detail: string }>("SELECT actor,action,target,detail FROM audit WHERE action='policy.deny'").toArray()
      const line = auditLine(denied!, { self: null, devices: new Map(), members: new Map([["mem_owner", "owner"]]) })
      expect(line.actor + line.pieces.map((p) => p.text).join("")).toBe("owner declined to let an agent carry on with routine work on api.github.com with github-work")
    })
  })

  it("is co-signed through policy.action and policy.decide, narrowing only, and the grant's clock starts at the co-sign", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { proposal } = await areaCoSign(ctx)
      const view = await op(ctx, "policy.status", "owner", { id: proposal })
      expect(view.proposal).toMatchObject({ kind: "area", stage: "co-sign", canApprove: true, areas: [{ id: "issues", requestArea: true }], approvedBy: { name: "member" } })
      expect(view.proposal.summary).toContain("Task grant on api.github.com: Issues and comments")
      // A machine never reads it.
      await expect(op(ctx, "policy.status", { device: "dev_member", cli: "0.3.17" }, { id: proposal })).rejects.toMatchObject({ code: "not_found" })
      for (const effective of [{ areas: ["issues"], ttlSeconds: 14_400, maxUses: 50 }, { areas: ["issues"], ttlSeconds: 3600, maxUses: 51 }, { areas: ["pulls"], ttlSeconds: 3600, maxUses: 50 }]) {
        await expect(op(ctx, "policy.action", "owner", { id: proposal, decision: "approve", effective })).rejects.toMatchObject({ code: "bad_request" })
      }
      const coSignedAt = ctx.now() + 60_000, later = at(ctx, coSignedAt)
      const decision = { id: proposal, decision: "approve", effective: { areas: ["issues"], ttlSeconds: 900, maxUses: 5 } }
      const action = await op(later, "policy.action", "owner", decision)
      expect(action.effectDigest).toBe(await policyAreaGrantTermsDigest({ ...view.proposal.terms, ttlSeconds: 900, maxUses: 5 }))
      expect((await op(later, "policy.decide", "owner", decision, action)).proposal).toMatchObject({ status: "approved" })
      const [grant] = await grantsOf(later, { device: "dev_member", cli: "0.3.17" })
      expect(grant).toMatchObject({ kind: "area", maxUses: 5, ttlSeconds: 900, approvedBy: "member", coSignedBy: { name: "owner" } })
      expect(Date.parse(grant!.createdAt)).toBe(coSignedAt)
      expect(Date.parse(grant!.endsAt)).toBe(coSignedAt + 900_000)
      setUpstreamFetch(async () => new Response("ok"))
      expect((await relay(later, commentOn(2, "x"), { device: "dev_member", cli: "0.3.17" })).material?.rules).toEqual([grant!.id])
    })
  })

  it("shows on its own co-sign page, with the areas as signed", () => {
    const terms: PolicyAreaGrantTerms = { kind: "area", item: "github-kim", itemId: "itm_github01", asker: { device: "dev_kimlaptop1", workload: null }, host: "api.github.com", catalogue: "github", catalogueVersion: 1, areas: ["issues"], ttlSeconds: 3600, maxUses: 50 }
    const view: PolicyAreaProposalViewProjection = { view: "detail", proposal: { proposal: "pol_area0000001", item: "github-kim", status: "pending", stage: "co-sign", bindingCode: "ABCD-1234", summary: "Task grant on api.github.com: Issues and comments", expiresAt: "2026-11-06T12:00:00.000Z", rule: null, kind: "area", extends: null, requestedBy: { member: "mem_kim00001", self: false }, reason: null, terms, termsDigest: "A".repeat(43), areas: [{ id: "issues", name: "Issues and comments", words: "Opens and comments on issues", requestArea: true }], digest: "B".repeat(43), approvedBy: { name: "Kim" }, canApprove: true, canDeny: true, workspace: GALLERY_WORKSPACE, owner: { kind: "member", member: "mem_kim00001", name: "Kim" }, eligibility: { canApprove: true, canDeny: true, canReadAskDetail: true, deciders: [], reason: null } } }
    const page = workspaceProposalPage(galleryShell(VIEWERS.owner), view, null)
    expect(page.boot).toMatchObject({ page: "ws-area-proposal", proposal: "pol_area0000001", terms })
    expect(page.body.value).toContain("github-kim")
    expect(page.body.value).toContain("Issues and comments")
  })
})

// A machine proposes a task grant from one of its held or approved asks
// (POST /v1/policy/proposals with an area body), and the machine's owner
// decides it with policy.decide, as a rule proposal is decided.
describe("a task grant a machine proposes", () => {
  type AreaChoice = { item?: string; areas?: string[]; ttlSeconds?: number; maxUses?: number }
  const propose = (ctx: VaultContext, approval: string, area: AreaChoice = {}, asker: Asker = NEW_CLI) =>
    op(ctx, "policy.propose", asker, { from: { approval }, area: { item: "github-work", areas: ["issues"], ...area }, reason: "Triage the backlog" })
  const answer = (promise: Promise<unknown>) => promise.then(() => null, (error: VaultError) => ({ code: error.code, message: error.message, extra: error.extra }))
  const decide = async (ctx: VaultContext, role: string, decision: Record<string, unknown>) => op(ctx, "policy.decide", role, decision, await op(ctx, "policy.action", role, decision))

  it("opens a proposal from a held ask that the machine's owner approves with a passkey, narrowing only, making a grant that lets the next routine comment through", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const approval = await held(ctx, commentOn(1, "First"))
      const created = await propose(ctx, approval, { ttlSeconds: 900, maxUses: 10 })
      expect(created).toMatchObject({ item: "github-work", status: "pending", stage: "approve", rule: null, url: `https://vault.test/w/work/p/${created.proposal}`, next: { command: `mehen wait ${created.proposal}`, say: "Send this link to the machine's owner; only their passkey lets the agent carry on." } })
      expect(created.summary).toMatch(/^Task grant on api\.github\.com: Issues and comments, from .*, outside any project, 15 minutes, up to 10 requests$/)
      // The proposal keeps its own copy of the held request, so it outlives the ask.
      expect(count(ctx, "policy_rule_anchors WHERE source=? AND body IS NOT NULL", created.proposal)).toBe(1)
      // The same proposal again is the same proposal; another while it waits is a conflict.
      expect((await propose(ctx, approval, { ttlSeconds: 900, maxUses: 10 })).proposal).toBe(created.proposal)
      expect(await answer(propose(ctx, approval, { ttlSeconds: 900, maxUses: 11 }))).toMatchObject({ code: "conflict" })
      // The machine reads where it stands, and finds it in mehen pending.
      expect(await op(ctx, "policy.status", NEW_CLI, { id: created.proposal })).toMatchObject({ proposal: created.proposal, status: "pending", stage: "approve" })
      const listed = (await op(ctx, "pending.list", NEW_CLI, {})).pending.map((p: { detail?: { id: string; title: string } }) => p.detail)
      expect(listed).toContainEqual(expect.objectContaining({ id: created.proposal, title: "Task grant: github-work" }))

      const view = await op(ctx, "policy.status", "owner", { id: created.proposal })
      expect(view.proposal).toMatchObject({ kind: "area", stage: "approve", canApprove: true, reason: "Triage the backlog", approvedBy: null, areas: [{ id: "issues", requestArea: true }], terms: { kind: "area", areas: ["issues"], ttlSeconds: 900, maxUses: 10, catalogue: "github", asker: { device: "dev_owner", workload: null } } })
      for (const effective of [{ areas: ["issues"], ttlSeconds: 3600, maxUses: 10 }, { areas: ["issues"], ttlSeconds: 900, maxUses: 11 }, { areas: ["pulls"], ttlSeconds: 900, maxUses: 10 }]) {
        await expect(op(ctx, "policy.action", "owner", { id: created.proposal, decision: "approve", effective }), JSON.stringify(effective)).rejects.toMatchObject({ code: "bad_request" })
      }
      const decision = { id: created.proposal, decision: "approve", effective: { areas: ["issues"], ttlSeconds: 900, maxUses: 5 } }
      const action = await op(ctx, "policy.action", "owner", decision)
      expect(action.effectDigest).toBe(await policyAreaGrantTermsDigest({ ...view.proposal.terms, maxUses: 5 }))
      expect((await op(ctx, "policy.decide", "owner", decision, action)).proposal).toMatchObject({ status: "approved" })

      const [grant] = await grantsOf(ctx)
      expect(grant).toMatchObject({ kind: "area", status: "active", areas: ["issues"], ttlSeconds: 900, maxUses: 5, uses: 0, approvedBy: "owner", coSignedBy: null })
      expect(Date.parse(grant!.endsAt) - Date.parse(grant!.createdAt)).toBe(900_000)
      expect(await op(ctx, "policy.status", NEW_CLI, { id: created.proposal })).toMatchObject({ status: "approved", rule: { id: grant!.id, endsAt: grant!.endsAt } })
      // The held ask the grant covers is closed; sent again, the grant lets it through.
      expect(ctx.sql.exec("SELECT policy_status FROM approvals WHERE id=?", approval).toArray()).toEqual([{ policy_status: "superseded" }])
      setUpstreamFetch(async () => new Response("ok"))
      expect((await relay(ctx, commentOn(2, "Second"))).material?.rules).toEqual([grant!.id])
      expect(lines(ctx).filter((l) => l.action !== "rule.use")).toEqual([
        { action: "rule.propose", text: "An agent on Owner's laptop proposed letting an agent carry on with routine work on api.github.com with github-work" },
        { action: "rule.create", text: `owner let an agent carry on with routine work on api.github.com with github-work as task grant ${grant!.id}` },
        { action: "approval.supersede", text: `owner closed an ask to use github-work that task grant ${grant!.id} now allows` },
      ])
    })
  })

  it("opens one from an approved ask, with the areas named in order, and a person may deny it", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedExample(ctx)
      const approval = await held(ctx, task("a"))
      const once = { id: approval, decision: "approve" }
      await op(ctx, "approvals.decide", "owner", once, await op(ctx, "approvals.action", "owner", once))
      const created = await propose(ctx, approval, { item: "example-key", areas: ["uploads", "tasks"] })
      expect(created).toMatchObject({ status: "pending", stage: "approve" })
      expect((await op(ctx, "policy.status", "owner", { id: created.proposal })).proposal.terms).toMatchObject({ areas: ["tasks", "uploads"], ttlSeconds: 3600, maxUses: 50 })
      expect((await decide(ctx, "owner", { id: created.proposal, decision: "deny" })).proposal).toMatchObject({ status: "denied" })
      expect(count(ctx, "policy_rules")).toBe(0)
    })
  })

  it("answers another machine's ask, one on another credential and one it does not know alike, and refuses a denied or expired ask and a request that cannot start a task grant, writing nothing", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await seedKey(ctx, "linear-work", "api.linear.app")
      await seedExample(ctx, "sk_live_fixture000000000000000000")
      const mine = await held(ctx, commentOn(1, "First"))
      const theirs = await held(ctx, commentOn(2, "Theirs"), { device: "dev_member" })
      const floor = await held(ctx, deleteComment(5)), outside = await held(ctx, openPull())
      const unreviewed = await held(ctx, { item: "linear-work", url: "https://api.linear.app/v1/things", body: json({ a: 1 }) })
      const liveKey = await held(ctx, task("a"))
      const denied = await held(ctx, commentOn(3, "Denied"))
      const no = { id: denied, decision: "deny" }
      await op(ctx, "approvals.decide", "owner", no, await op(ctx, "approvals.action", "owner", no))
      const audits = count(ctx, "audit")

      const missing = await answer(propose(ctx, "apr_nothing00000000"))
      expect(missing).toEqual({ code: "not_found", message: "No such approval.", extra: {} })
      expect(await answer(propose(ctx, theirs))).toEqual(missing)
      expect(await answer(propose(ctx, mine, { item: "linear-work" }))).toEqual(missing)
      const gone = { code: "conflict", message: "That request was denied or has expired; send the request again and propose from its new ask.", extra: {} }
      expect(await answer(propose(ctx, denied))).toEqual(gone)
      expect(await answer(propose(at(ctx, ctx.now() + DAY), mine))).toEqual(gone)
      const refusedAs = async (approval: string, area: AreaChoice) => (await answer(propose(ctx, approval, area)) as { extra: { areaRefused?: string } } | null)?.extra.areaRefused
      expect(await refusedAs(floor, {})).toBe("area.not-routine")
      expect(await refusedAs(outside, {})).toBe("area.not-routine")
      expect(await refusedAs(unreviewed, { item: "linear-work" })).toBe("area.unreviewed")
      expect(await refusedAs(liveKey, { item: "example-key", areas: ["tasks"] })).toBe("area.live-key")
      expect(await refusedAs(mine, { areas: ["pulls"] })).toBe("area.unknown")
      expect(await answer(propose(ctx, floor))).toMatchObject({ code: "forbidden", message: "This request is not routine building, so it cannot start a task grant." })
      expect(count(ctx, "policy_proposals")).toBe(0)
      expect(count(ctx, "audit")).toBe(audits)
    })
  })

  it("answers a mehen older than 0.3.17 or of unknown version as before task grants, and refuses with the switch off, in a managed workspace and from a guest's machine", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, () => registerCredentialProvider())
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const approval = await held(ctx, commentOn(1, "First"))
      for (const asker of [OWNER, { ...OWNER, cli: "0.3.16" }]) {
        expect(await answer(propose(ctx, approval, {}, asker)), String(asker.cli)).toEqual({ code: "bad_request", message: "Invalid request: body Unrecognized key: \"area\".", extra: { next: { command: "mehen policy propose --help", say: "Read the policy proposal options and try again." } } })
      }
      const off = { code: "forbidden", message: "Policy widening is not available yet." }
      expect(await answer(propose(switched(ctx, "off"), approval))).toMatchObject(off)
      await seedKey(ctx, "shared-key", "api.example.com", { kind: "project", project: "prj_a" })
      const guestAsk = await held(ctx, { ...task("a"), item: "shared-key" }, { device: "dev_guest" })
      expect(await answer(propose(ctx, guestAsk, { item: "shared-key", areas: ["tasks"] }, { device: "dev_guest", cli: "0.3.17" }))).toMatchObject({ code: "forbidden", message: "A guest's machine cannot ask for a task grant; it asks for each request instead." })
      setSetting(ctx, "managed", { platform: "plt_x", subject: "s", member: "mem_owner" })
      expect(await answer(propose(ctx, approval))).toMatchObject(off)
      expect(count(ctx, "policy_proposals")).toBe(0)
    })
  })

  it("refuses a held ask on a credential that backs a protected environment as environment_refused, writing nothing", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, () => registerCredentialProvider())
    await inRules(f.tenant, async (ctx) => {
      // projectFixture's key-workspace, held on the unprotected dev.
      const approval = await held(ctx, { item: "key-workspace", url: "https://api.example.com/tasks", body: json({ title: "a" }) })
      // key-workspace backs the protected staging from now on.
      ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_a','staging','TOKEN','key-workspace','key','member:mem_owner',?)", ctx.now())
      const audits = count(ctx, "audit")
      // The ask's own use of the credential is authorised again first, and refused there.
      expect(await answer(propose(ctx, approval, { item: "key-workspace", areas: ["tasks"] }))).toEqual({ code: "environment_refused", message: "This credential needs an authorised protected context.", extra: { next: { command: "mehen run --env <environment> -- <command>", say: "Run with a literal --env in an authorised protected environment and approve that run." } } })
      expect(count(ctx, "policy_proposals")).toBe(0)
      expect(count(ctx, "audit")).toBe(audits)
    })
  })

  it("is not found, cannot be cancelled and is left out of mehen pending for a mehen older than 0.3.17 or of unknown version", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { proposal } = await propose(ctx, await held(ctx, commentOn(1, "First")))
      for (const asker of [OWNER, { ...OWNER, cli: "0.3.16" }]) {
        expect(await answer(op(ctx, "policy.status", asker, { id: proposal })), String(asker.cli)).toEqual({ code: "not_found", message: "No such object.", extra: {} })
        expect(await answer(op(ctx, "policy.cancel", asker, { id: proposal })), String(asker.cli)).toEqual({ code: "not_found", message: "No such object.", extra: {} })
        expect((await op(ctx, "pending.list", asker, {})).pending.map((p: { detail?: { id: string } }) => p.detail?.id), String(asker.cli)).not.toContain(proposal)
      }
      expect(await op(ctx, "policy.cancel", NEW_CLI, { id: proposal })).toMatchObject({ proposal, status: "cancelled" })
    })
  })

  it("moves to stage co-sign, writing no grant, when the person approving needs a manager of the credential's home to co-sign", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const machine: Asker = { device: "dev_member", cli: "0.3.17" }
      const { proposal } = await propose(ctx, await held(ctx, commentOn(1, "First"), machine), {}, machine)
      const consents = count(ctx, "consent_lineage")
      const decision = { id: proposal, decision: "approve", effective: { areas: ["issues"], ttlSeconds: 3600, maxUses: 50 } }
      expect((await decide(ctx, "member", decision)).proposal).toMatchObject({ status: "pending", stage: "co-sign" })
      expect(count(ctx, "policy_rules")).toBe(0)
      expect(count(ctx, "consent_lineage")).toBe(consents + 1)
      expect(await op(ctx, "policy.status", machine, { id: proposal })).toMatchObject({ status: "pending", stage: "co-sign" })
    })
  })

  it("becomes a live grant when a manager co-signs with a passkey, from the terms and the request's own area the proposal stored", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const machine: Asker = { device: "dev_member", cli: "0.3.17" }
      const { proposal } = await propose(ctx, await held(ctx, commentOn(1, "First"), machine), { ttlSeconds: 900, maxUses: 10 }, machine)
      await decide(ctx, "member", { id: proposal, decision: "approve", effective: { areas: ["issues"], ttlSeconds: 900, maxUses: 10 } })
      // The stored proposal keeps the member's terms and the request's own area.
      const stored = ctx.sql.exec<{ stage: string; rule_terms: string }>("SELECT stage,rule_terms FROM policy_proposals WHERE id=?", proposal).toArray()[0]!
      expect(stored.stage).toBe("co-sign")
      expect(JSON.parse(stored.rule_terms)).toMatchObject({ requestArea: "issues", terms: { kind: "area", areas: ["issues"], ttlSeconds: 900, maxUses: 10 } })
      // The manager reads it back and co-signs exactly what the vault stored.
      const view = await op(ctx, "policy.status", "owner", { id: proposal })
      expect(view.proposal).toMatchObject({ kind: "area", stage: "co-sign", canApprove: true, areas: [{ id: "issues", requestArea: true }], approvedBy: { name: "member" } })
      expect(JSON.stringify(await op(ctx, "pending.list", "owner", {}))).toContain(`"title":"Co-sign: let an agent carry on: github-work"`)
      expect((await op(ctx, "policy.status", "member", { id: proposal })).proposal.canApprove).toBe(false)
      const decision = { id: proposal, decision: "approve", effective: { areas: view.proposal.terms.areas, ttlSeconds: view.proposal.terms.ttlSeconds, maxUses: view.proposal.terms.maxUses } }
      const action = await op(ctx, "policy.action", "owner", decision)
      expect(action.effectDigest).toBe(view.proposal.termsDigest)
      expect((await op(ctx, "policy.decide", "owner", decision, action)).proposal).toMatchObject({ status: "approved" })
      const [grant] = await grantsOf(ctx, machine)
      expect(grant).toMatchObject({ kind: "area", status: "active", areas: ["issues"], ttlSeconds: 900, maxUses: 10, approvedBy: "member", coSignedBy: { name: "owner" } })
      expect(await op(ctx, "policy.status", machine, { id: proposal })).toMatchObject({ status: "approved", rule: { id: grant!.id } })
      setUpstreamFetch(async () => new Response("ok"))
      expect((await relay(ctx, commentOn(2, "Second"), machine)).material?.rules).toEqual([grant!.id])
      // Both rule.propose rows say the grant's shape, its duration included.
      const proposed = ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='rule.propose' ORDER BY seq").toArray().map((r) => JSON.parse(r.detail))
      expect(proposed).toEqual([
        { stage: "approve", kind: "area", host: "api.github.com", catalogue: "github", areas: ["issues"], maxUses: 10, ttlSeconds: 900, item: "github-work", device: "dev_member" },
        { stage: "co-sign", kind: "area", host: "api.github.com", catalogue: "github", areas: ["issues"], maxUses: 10, ttlSeconds: 900, item: "github-work", device: "dev_member" },
      ])
    })
  })
})

describe("what a machine of each version reads of a task grant", () => {
  it("lists grants only when asked, and only to mehen 0.3.17 or later; to an older or unknown one a grant's id is not found and is never revoked", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await areaRemember(ctx, "owner", await held(ctx, commentOn(1, "First")))
      const id = ctx.sql.exec<{ id: string }>("SELECT id FROM policy_rules WHERE kind='area'").toArray()[0]!.id
      const old = [OWNER, { ...OWNER, cli: "0.3.16" }]
      for (const asker of [...old, NEW_CLI]) expect(await op(ctx, "policy.rules", asker, {}), String(asker.cli)).toEqual([])
      for (const asker of old) expect(await op(ctx, "policy.rules", asker, { include: "grants" }), String(asker.cli)).toEqual([])
      expect((await grantsOf(ctx)).map((g) => g.id)).toEqual([id])
      // To an old or unknown mehen, the grant's id answers exactly as an id that names nothing, with nothing written.
      const answer = (asker: Asker, rule: string) => op(ctx, "policy.rules.revoke", asker, { id: rule }).then(() => null, (error: VaultError) => ({ code: error.code, message: error.message, extra: error.extra }))
      const audits = count(ctx, "audit")
      for (const asker of old) {
        const missing = await answer(asker, "rul_nothing000000")
        expect(missing, String(asker.cli)).toEqual({ code: "not_found", message: "No such object.", extra: {} })
        expect(await answer(asker, id), String(asker.cli)).toEqual(missing)
      }
      expect(count(ctx, "policy_rules WHERE ended_at IS NULL")).toBe(1)
      expect(count(ctx, "audit")).toBe(audits)
      expect(await answer(NEW_CLI, "rul_nothing000000")).toEqual({ code: "not_found", message: "No such object.", extra: {} })
      expect(await op(ctx, "policy.rules.revoke", NEW_CLI, { id })).toMatchObject({ id, kind: "area", status: "ended", endedReason: "revoked" })
    })
  })

  it("names a grant in Mehen-Rule only to mehen 0.3.17 or later, and a shape rule to every version; the use counts whichever asked", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await areaRemember(ctx, "owner", await held(ctx, commentOn(1, "First")))
      const [grant] = await grantsOf(ctx)
      setUpstreamFetch(async () => new Response("ok"))
      const headerOf = async (asker: Asker, sent: Sent) => {
        const { material, error } = await relay(ctx, sent, asker)
        expect(error).toBeNull()
        return { rules: material!.rules, header: (await forwardRelay(material!, sent.body!.bytes)).headers.get(RULE_HEADER) }
      }
      for (const asker of [OWNER, { ...OWNER, cli: "0.3.16" }]) expect(await headerOf(asker, commentOn(2, "x")), String(asker.cli)).toEqual({ rules: undefined, header: null })
      expect(await headerOf(NEW_CLI, commentOn(3, "x"))).toEqual({ rules: [grant!.id], header: grant!.id })
      expect((await grantsOf(ctx))[0]).toMatchObject({ uses: 3 })
      expect(ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='rule.use' ORDER BY seq").toArray().map((r) => JSON.parse(r.detail).uses)).toEqual([1, 2, 3])
      // A shape rule for issue 9's comments, approved by the owner.
      const created = await op(ctx, "policy.propose", OWNER, { from: { item: "github-work", method: "POST", url: "https://api.github.com/repos/northwind/platform/issues/9/comments", bodyBase64: Buffer.from(JSON.stringify({ body: "x" })).toString("base64"), contentType: "application/json" }, reason: "Comment" })
      const decision = { id: created.proposal, decision: "approve", effective: { path: "/repos/northwind/platform/issues/9/comments", ttlSeconds: 86_400 } }
      await op(ctx, "policy.decide", "owner", decision, await op(ctx, "policy.action", "owner", decision))
      const rule = (await op(ctx, "policy.rules", OWNER, {}))[0]
      for (const asker of [OWNER, { ...OWNER, cli: "0.3.16" }, NEW_CLI]) expect(await headerOf(asker, commentOn(9, "y")), String(asker.cli)).toEqual({ rules: [rule.id], header: rule.id })
    })
  })

  it("lists grants to a person only when asked, beside the rules", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await areaRemember(ctx, "owner", await held(ctx, commentOn(1, "First")))
      for (const input of [{}, { item: "github-work" }, { device: "dev_owner" }]) {
        expect(await op(ctx, "policy.rules", "owner", input)).toEqual([])
        expect((await op(ctx, "policy.rules", "owner", { ...input, include: "grants" })).map((g: PolicyAreaGrantView) => g.kind)).toEqual(["area"])
      }
    })
  })
})

describe("a task grant and a posture that both cover a request", () => {
  it("uses the grant, names it in Mehen-Rule to mehen 0.3.17 or later and gives no posture, which covers the request only once the grant has ended", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await areaRemember(ctx, "owner", await held(ctx, commentOn(1, "First")))
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: null })
      const [grant] = await grantsOf(ctx)
      const ruleUses = count(ctx, "audit WHERE action='rule.use'")
      const covered = await relay(ctx, commentOn(2, "x"))
      expect(covered.error).toBeNull()
      expect(covered.material).toMatchObject({ rules: [grant!.id] })
      expect(covered.material).not.toHaveProperty("postures")
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(ruleUses + 1)
      expect((await grantsOf(ctx))[0]).toMatchObject({ uses: grant!.uses + 1 })
      expect(count(ctx, "audit WHERE action='posture.use'")).toBe(0)
      await op(ctx, "policy.rules.revoke", NEW_CLI, { id: grant!.id })
      const postured = await relay(ctx, commentOn(3, "x"))
      expect(postured.material).toMatchObject({ postures: ["routine"] })
      expect(postured.material).not.toHaveProperty("rules")
      expect(count(ctx, "audit WHERE action='posture.use'")).toBe(1)
    })
  })
})

describe("the bytes a task grant's offer keeps", () => {
  it("keeps an upload no rule takes for its grant, never shows them to a machine, an audit row or a log, and drops them when a held request's copy is dropped", async () => {
    const SENTINEL = "SENTINEL-c0ffee-upload-bytes"
    const logged: string[] = []
    for (const level of ["log", "info", "warn", "error", "debug"] as const) vi.spyOn(console, level).mockImplementation((...args: unknown[]) => { logged.push(args.map(String).join(" ")) })
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedExample(ctx)
      const t0 = ctx.now()
      const { error } = await relay(at(ctx, t0), upload(SENTINEL))
      const approval = error!.extra.approval!
      expect(count(ctx, "policy_rule_anchors WHERE source=? AND refused IS NULL", approval)).toBe(1)
      const view = await op(ctx, "approvals.view", "owner", { id: approval })
      expect(view.approval.rememberOptions.rule.refused).toBe("rule.body")
      expect(view.approval.rememberOptions.area.refused).toBeNull()
      const answers: unknown[] = [error!.extra, await op(ctx, "approvals.status", NEW_CLI, { id: approval }), await op(ctx, "pending.list", NEW_CLI, {})]
      await areaRemember(ctx, "owner", approval)
      setUpstreamFetch(async () => new Response("ok"))
      const used = await relay(ctx, upload(`${SENTINEL}-2`))
      expect(used.error).toBeNull()
      answers.push(await grantsOf(ctx), await op(ctx, "approvals.status", NEW_CLI, { id: approval }))
      const encoded = [SENTINEL, Buffer.from(SENTINEL).toString("base64"), Buffer.from(SENTINEL).toString("base64url")]
      const seen = JSON.stringify([answers, ctx.sql.exec("SELECT * FROM audit").toArray(), logged])
      for (const text of encoded) expect(seen).not.toContain(text)
      // Dropped two days on, as every held request's copy is.
      await policyArea.alarm!(switched(at(ctx, t0 + 2 * DAY - 1), "on"), RULE_ANCHOR_SWEEP_KEY)
      expect(count(ctx, "policy_rule_anchors WHERE source=?", approval)).toBe(1)
      await policyArea.alarm!(switched(at(ctx, t0 + 2 * DAY), "on"), RULE_ANCHOR_SWEEP_KEY)
      expect(count(ctx, "policy_rule_anchors WHERE source=?", approval)).toBe(0)
    })
  })
})

describe("managed workspaces", () => {
  it("never use a task grant made before the workspace was managed, and offer none", async () => {
    const f = await credentialsFixture()
    await inRules(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await areaRemember(ctx, "owner", await held(ctx, commentOn(1, "First")))
      setSetting(ctx, "managed", { platform: "plt_x", subject: "s", member: "mem_owner" })
      const { material, error } = await relay(ctx, commentOn(2, "Second"))
      expect(material).toBeNull()
      expect(error).toMatchObject({ code: "approval_required", extra: { next: { say: "The platform decides this request." } } })
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(0)
      expect(count(ctx, "policy_rules WHERE uses=0 AND ended_at IS NULL")).toBe(1)
      expect(await areaOfferOf(ctx, "owner", error!.extra.approval!)).toBeUndefined()
    })
  })
})

describe("runs, placeholders and protected credentials", () => {
  // projectFixture's key-workspace, on the test catalogue's host: the TOKEN
  // of each project's unprotected dev, every request of which its policy holds.
  const byItem = (title: string, context?: { project: string; environment: string }): Sent => ({ item: "key-workspace", url: "https://api.example.com/tasks", body: json({ title }), ...(context ? { context } : {}) })
  const DEV = { project: "prj_a", environment: "dev" }
  async function devRun(ctx: VaultContext) {
    const created = await workspaceRunOps["runs.create"]!.handler(ctx, principalOf(OWNER), { ...PROJECT_RUN_INPUT, env: "dev" }, await invocationOf(ctx, OWNER)) as WorkspaceRunCreated
    return { run: created.run, placeholder: created.vars.find((v) => v.delivery === "placeholder")!.value }
  }
  async function viaRun(ctx: VaultContext, run: { run: string; placeholder: string }, title: string) {
    const input = { run: run.run, method: "POST", url: "https://api.example.com/tasks", headers: [["Authorization", `Bearer ${run.placeholder}`], ["content-type", "application/json"]] as [string, string][], body: base64UrlEncode(enc({ title })) }
    try { return { material: await authoriseWorkspaceRelay(ctx, principalOf(NEW_CLI), input, await invocationOf(ctx, NEW_CLI)), error: null } }
    catch (error) { if (error instanceof VaultError) return { material: null, error }; throw error }
  }
  async function projectGrants() {
    const f = await projectFixture()
    await inAccess(f.tenant, () => registerCredentialProvider())
    return f
  }

  it("lets a grant serve only the mode and the project and environment it was asked in, and never a lease", async () => {
    const f = await projectGrants()
    await inRules(f.tenant, async (ctx) => {
      setUpstreamFetch(async () => new Response("ok"))
      const run = await devRun(ctx)
      const asked = await viaRun(ctx, run, "a")
      expect(asked.error?.code).toBe("approval_required")
      await areaRemember(ctx, "owner", asked.error!.extra.approval!)
      const [grant] = await grantsOf(ctx)
      expect(grant).toMatchObject({ context: DEV, areas: ["tasks"] })
      expect((await viaRun(ctx, run, "b")).material?.rules).toEqual([grant!.id])
      for (const context of [undefined, DEV]) expect((await relay(ctx, byItem("c", context))).error?.code, JSON.stringify(context)).toBe("approval_required")
      expect((await grantsOf(ctx))[0]).toMatchObject({ uses: 1, status: "active" })
      // A lease hands the run the value with no request to cover: it never
      // reaches the relay hook, so it neither uses nor counts the grant.
      fixtureSql(ctx).exec("UPDATE items SET ceiling='lease',binding=? WHERE slug='key-workspace'", canonicalJson(leaseOnlyBinding()))
      const leasing = await workspaceRunOps["runs.create"]!.handler(ctx, principalOf(OWNER), { ...PROJECT_RUN_INPUT, env: "dev" }, await invocationOf(ctx, OWNER)) as WorkspaceRunCreated
      expect(leasing.vars).toMatchObject([{ name: "TOKEN", delivery: "lease", item: "key-workspace" }])
      expect(await workspaceRunOps["runs.lease"]!.handler(ctx, principalOf(OWNER), { run: leasing.run, item: "key-workspace" }, await invocationOf(ctx, OWNER))).toMatchObject({ value: expect.any(String) })
      expect((await grantsOf(ctx))[0]).toMatchObject({ id: grant!.id, uses: 1, status: "active" })
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(1)
    })
  })

  it("never looks a grant up for a protected credential, by item or in a protected run, and offers none", async () => {
    const f = await projectGrants()
    await inRules(f.tenant, async (ctx) => {
      setUpstreamFetch(async () => new Response("ok"))
      await areaRemember(ctx, "owner", await held(ctx, byItem("a")))
      // An upload the tasks grant does not cover, still pending.
      const pending = await held(ctx, { ...upload("file"), item: "key-workspace" })
      expect((await areaOfferOf(ctx, "owner", pending))?.refused).toBeNull()
      // key-workspace backs the protected staging from now on.
      ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_a','staging','TOKEN','key-workspace','key','member:mem_owner',?)", ctx.now())
      expect(await areaOfferOf(ctx, "owner", pending)).toBeUndefined()
      expect((await relay(ctx, byItem("c"))).error?.code).toBe("environment_refused")
      const run = await approvedProjectRun(ctx, { ...PROJECT_RUN_INPUT, env: "staging" }, "dev_owner", "owner")
      const through = await viaRun(ctx, { run: run.run, placeholder: run.result.vars.find((v) => v.delivery === "placeholder")!.value }, "d")
      expect(through.error).toBeNull()
      expect(through.material?.rules).toBeUndefined()
      expect(count(ctx, "policy_rules WHERE ended_at IS NULL AND uses=0")).toBe(1)
      expect(count(ctx, "audit WHERE action='rule.use'")).toBe(0)
    })
  })
})
