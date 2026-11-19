// The production browser signing path (workspace-sign.ts), driven
// with a fake fetch and a fake passkey: every refusal before the passkey
// sends no step-up start, asks no passkey and sends no mutation. These run
// the same functions the pages call, not a copy of them.

import { type Mock, afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import type { ApprovalSubject } from "@mehen/protocol/api"
import { VaultFailure } from "./api.ts"
import { ShellState } from "./shell-logic.ts"
import { digestOf } from "./logic.ts"
import { PolicyRememberRuleSchema, type PolicyRuleTerms } from "@mehen/protocol/policy-mode"
import { type PolicyAreaGrantTerms, PolicyRememberSchema } from "@mehen/protocol/policy-mode"
import { policyAreaGrantTermsDigest } from "@mehen/protocol/policy-rules"
import { areaOfferMatches } from "./workspace-logic.ts"
import { AREA_OFFER_MISMATCH, AREA_PROPOSAL_MISMATCH, decideAreaProposal } from "./workspace-sign.ts"
import { AREA_AREAS_PROBLEM, AREA_DURATION_PROBLEM, AREA_USES_PROBLEM } from "../wording.ts"
import { policyRuleTermsDigest } from "@mehen/protocol/policy-rules"
import { CHANGED_SINCE_SHOWN, type ReviewRowBoot, type WorkspaceApprovalBoot, approvalDecision, itemChangedRefusal, itemDeleteAction, ruleOfferMatches, ruleProposalDigest, ruleProposalMatches, sameAction } from "./workspace-logic.ts"
import { BINDING_CODE_NOT_TICKED, BINDING_MISMATCH, type Passkey, REVIEW_BINDING_MISMATCH, REVIEW_CODES_NOT_TICKED, REVIEW_NOTHING_TICKED, RULE_OFFER_MISMATCH, RULE_PROPOSAL_MISMATCH, decideApproval, decideReviewBatch, decideRuleProposal, denyFromStop, signed } from "./workspace-sign.ts"
import { RULE_PATH_PROBLEM, RULE_PROPOSAL_DURATION_PROBLEM } from "../wording.ts"

const WORKSPACE = { id: "tn_work", slug: "northwind", name: "Northwind" }

type Call = { path: string; body: unknown }

// Answers by path; records every call the page sends.
function vault(answers: Record<string, unknown>): { calls: Call[]; paths: () => string[] } {
  const calls: Call[] = []
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const path = String(input)
    calls.push({ path, body: init?.body === undefined ? undefined : JSON.parse(String(init.body)) })
    const answer = answers[path]
    if (answer === undefined) return new Response(JSON.stringify({ error: "not_found", message: "No such route." }), { status: 404 })
    return new Response(JSON.stringify(typeof answer === "function" ? (answer as () => unknown)() : answer), { status: 200, headers: { "content-type": "application/json" } })
  })
  return { calls, paths: () => calls.map((c) => c.path) }
}

function shell(): ShellState {
  return new ShellState({ origin: "https://vault.test", account: "acc_alex", workspace: WORKSPACE, pages: [], reads: [] })
}

const STEPUP = { nonce: "n", options: { challenge: "c", allowCredentials: [] } }
let passkey: Mock<Passkey>

beforeEach(() => {
  passkey = vi.fn<Passkey>(async () => ({ signed: true }))
})
afterEach(() => vi.restoreAllMocks())

async function refusedWith(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise
  } catch (error) {
    if (error instanceof VaultFailure) return error.body
    throw error
  }
  throw new Error("Expected a refusal")
}

describe("signed: the one way the pages sign", () => {
  const expected = itemDeleteAction({ id: "itm_shown" })
  const request = (stillShown?: () => Promise<ReturnType<typeof itemChangedRefusal>>) => ({ prepare: { path: "/items/key/action", body: { action: "delete" } }, matches: (a: unknown) => sameAction(expected, a), stillShown, mutation: { path: "/items/key/delete", body: {} } })

  it("a stale action (a replacement credential under the same name) refuses with nothing signed", async () => {
    const v = vault({ "/api/w/northwind/items/key/action": { type: "item.delete", item: "itm_REPLACEMENT" } })
    expect(await refusedWith(signed(shell(), request(), passkey))).toEqual(CHANGED_SINCE_SHOWN)
    expect(v.paths()).toEqual(["/api/w/northwind/items/key/action"])
    expect(passkey).not.toHaveBeenCalled()
  })

  it("a renamed workspace refuses before the step-up starts", async () => {
    const v = vault({ "/api/w/northwind/items/key/action": expected, "/api/w/northwind": { ...WORKSPACE, name: "Northwind Labs" } })
    expect(await refusedWith(signed(shell(), request(), passkey))).toMatchObject({ error: "conflict", message: "This workspace was renamed to Northwind Labs (northwind) since the page loaded." })
    expect(v.paths()).not.toContain("/api/w/northwind/stepup/start")
    expect(passkey).not.toHaveBeenCalled()
  })

  it("a credential changed since the page showed it refuses before the step-up starts", async () => {
    const shown = { id: "itm_shown", version: 3, configRevision: 2, dependencyRevision: 1 }
    const v = vault({ "/api/w/northwind/items/key/action": expected, "/api/w/northwind": WORKSPACE, "/api/w/northwind/items/key": { ...shown, configRevision: 3 } })
    const still = async () => itemChangedRefusal(shown, (await (await fetch("/api/w/northwind/items/key")).json()) as typeof shown)
    expect(await refusedWith(signed(shell(), request(still), passkey))).toEqual(CHANGED_SINCE_SHOWN)
    expect(v.paths()).not.toContain("/api/w/northwind/stepup/start")
    expect(v.paths()).not.toContain("/api/w/northwind/items/key/delete")
    expect(passkey).not.toHaveBeenCalled()
  })

  it("only an unchanged, matching action reaches the passkey and the mutation", async () => {
    const v = vault({ "/api/w/northwind/items/key/action": expected, "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": STEPUP, "/api/w/northwind/items/key/delete": {} })
    expect(await signed(shell(), request(), passkey)).toEqual({})
    expect(v.paths()).toEqual(["/api/w/northwind/items/key/action", "/api/w/northwind", "/api/w/northwind/stepup/start", "/api/w/northwind/items/key/delete"])
    expect(v.calls[2]?.body).toEqual({ action: expected })
    expect(passkey).toHaveBeenCalledTimes(1)
  })

  it("inside the session's passkey grace window, sends a grace proof and never opens the passkey prompt", async () => {
    const v = vault({ "/api/w/northwind/items/key/action": expected, "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": { nonce: "g", grace: { until: "2026-11-08T17:30:00.000Z" } }, "/api/w/northwind/items/key/delete": {} })
    expect(await signed(shell(), request(), passkey)).toEqual({})
    expect(v.calls.at(-1)).toEqual({ path: "/api/w/northwind/items/key/delete", body: { stepUp: { nonce: "g", grace: true } } })
    expect(passkey).not.toHaveBeenCalled()
  })
})

describe("decideApproval: the approval page's decision", () => {
  const subject: ApprovalSubject = { item: "platform", method: "RUN", url: "https://vault.test/w/northwind/projects/prj_a", contentType: null, contentEncoding: null, headersSha256: "h", bodySha256: "b", constraints: { uses: 1, ttlSeconds: 3600 } }
  // The composite the vault stores (workspace-logic.test.ts checks this
  // against the vault's own approvalBinding).
  const binding = { snapshotDigest: "snap", presentationDigest: "pres", digest: "" }
  let boot: WorkspaceApprovalBoot
  beforeEach(async () => {
    binding.digest = await digestOf({ subject, snapshotDigest: binding.snapshotDigest, presentationDigest: binding.presentationDigest })
    boot = { approval: "apr_1", digest: binding.digest, subject, binding: { snapshotDigest: binding.snapshotDigest, presentationDigest: binding.presentationDigest }, headers: null }
  })
  const ok = { decision: "approve" as const, codeTicked: true, uses: "1", ttl: "600" }

  it("refuses an unticked binding code with nothing sent", async () => {
    const v = vault({})
    expect(await refusedWith(decideApproval(shell(), boot, { ...ok, codeTicked: false }, passkey))).toEqual(BINDING_CODE_NOT_TICKED)
    expect(v.calls).toEqual([])
    expect(passkey).not.toHaveBeenCalled()
  })

  it("refuses when the shown request does not recompute to the stored digest", async () => {
    const v = vault({})
    expect(await refusedWith(decideApproval(shell(), { ...boot, binding: { ...boot.binding!, snapshotDigest: "tampered" } }, ok, passkey))).toEqual(BINDING_MISMATCH)
    expect(await refusedWith(decideApproval(shell(), { ...boot, subject: { ...subject, url: "https://vault.test/w/northwind/projects/prj_b" } }, ok, passkey))).toEqual(BINDING_MISMATCH)
    expect(v.calls).toEqual([])
    expect(passkey).not.toHaveBeenCalled()
  })

  it("refuses more uses or time than the agent asked for", async () => {
    const v = vault({})
    expect(await refusedWith(decideApproval(shell(), boot, { ...ok, uses: "2" }, passkey))).toMatchObject({ error: "bad_request" })
    expect(await refusedWith(decideApproval(shell(), boot, { ...ok, ttl: "7200" }, passkey))).toMatchObject({ error: "bad_request" })
    expect(v.calls).toEqual([])
    expect(passkey).not.toHaveBeenCalled()
  })

  it("refuses a vault action with other terms than the page chose", async () => {
    const v = vault({ "/api/w/northwind/approvals/apr_1/action": { type: "approval.decide", approval: "apr_1", digest: binding.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 3600 } } })
    expect(await refusedWith(decideApproval(shell(), boot, ok, passkey))).toEqual(CHANGED_SINCE_SHOWN)
    expect(v.paths()).toEqual(["/api/w/northwind/approvals/apr_1/action"])
    expect(passkey).not.toHaveBeenCalled()
  })

  it("signs exactly the chosen, bounded terms once everything holds", async () => {
    const action = { type: "approval.decide", approval: "apr_1", digest: binding.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 600 } }
    const v = vault({ "/api/w/northwind/approvals/apr_1/action": action, "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": STEPUP, "/api/w/northwind/approvals/apr_1/decide": { status: "approved" } })
    expect(await decideApproval(shell(), boot, ok, passkey)).toEqual({ status: "approved" })
    expect(v.calls[0]?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 600 } })
    expect(v.calls[3]?.body).toMatchObject({ decision: "approve", constraints: { uses: 1, ttlSeconds: 600 }, stepUp: { nonce: "n" } })
    expect(passkey).toHaveBeenCalledTimes(1)
  })

  describe("with a standing rule", () => {
    const terms: PolicyRuleTerms = { item: "github-alex", itemId: "itm_github01", asker: { device: "dev_macmini1", workload: null }, method: "POST", host: "api.github.com", path: "/repos/a/b/issues/12/comments", anchorPath: "/repos/a/b/issues/12/comments", queryNames: [], graphql: null, ttlSeconds: 604_800 }
    const pathChoices = ["/repos/a/b/issues/12/comments", "/repos/a/b/issues/*/comments"]
    // The approval the rule is offered beside: the same credential, method,
    // host and path as its terms.
    const asked: ApprovalSubject = { ...subject, item: "github-alex", method: "POST", url: "https://api.github.com/repos/a/b/issues/12/comments?per_page=1" }
    let ruled: WorkspaceApprovalBoot
    beforeEach(async () => {
      binding.digest = await digestOf({ subject: asked, snapshotDigest: binding.snapshotDigest, presentationDigest: binding.presentationDigest })
      ruled = { ...boot, digest: binding.digest, subject: asked, rule: { terms, termsDigest: await policyRuleTermsDigest(terms), pathChoices, coSign: false } }
    })
    const allow = { ...ok, rule: { path: "/repos/a/b/issues/*/comments", ttl: "2592000" } }

    it("refuses before the binding code is ticked, with nothing sent", async () => {
      const v = vault({})
      expect(await refusedWith(decideApproval(shell(), ruled, { ...allow, codeTicked: false }, passkey))).toEqual(BINDING_CODE_NOT_TICKED)
      expect(await refusedWith(decideApproval(shell(), { ...ruled, digest: "tampered" }, allow, passkey))).toEqual(BINDING_MISMATCH)
      expect(v.calls).toEqual([])
      expect(passkey).not.toHaveBeenCalled()
    })

    it("refuses while the offer's terms do not hash to the vault's digest, or with no offer at all", async () => {
      const v = vault({})
      expect(await refusedWith(decideApproval(shell(), { ...ruled, rule: { ...ruled.rule!, termsDigest: "x".repeat(43) } }, allow, passkey))).toEqual(RULE_OFFER_MISMATCH)
      expect(await refusedWith(decideApproval(shell(), { ...ruled, rule: { ...ruled.rule!, terms: { ...terms, host: "api.github.example" } } }, allow, passkey))).toEqual(RULE_OFFER_MISMATCH)
      expect(await refusedWith(decideApproval(shell(), { ...ruled, rule: undefined }, allow, passkey))).toEqual(RULE_OFFER_MISMATCH)
      expect(v.calls).toEqual([])
      expect(passkey).not.toHaveBeenCalled()
    })

    it("refuses terms that hash right but are not this approval's credential, method, host or path", async () => {
      const v = vault({})
      for (const other of [{ ...terms, item: "github-kim" }, { ...terms, method: "PUT" as const }, { ...terms, host: "uploads.github.com" }, { ...terms, path: "/repos/a/b/issues/13/comments", anchorPath: "/repos/a/b/issues/13/comments" }]) {
        const offer = { terms: other, termsDigest: await policyRuleTermsDigest(other), pathChoices: [other.path], coSign: false }
        expect(await ruleOfferMatches(offer, asked), JSON.stringify(other)).toBe(false)
        expect(await refusedWith(decideApproval(shell(), { ...ruled, rule: offer }, { ...allow, rule: { path: other.path, ttl: "604800" } }, passkey))).toEqual(RULE_OFFER_MISMATCH)
      }
      expect(await ruleOfferMatches(ruled.rule!, asked)).toBe(true)
      expect(await ruleOfferMatches(ruled.rule!, { ...asked, url: "not a url" })).toBe(false)
      expect(v.calls).toEqual([])
      expect(passkey).not.toHaveBeenCalled()
    })

    it("refuses a path or a duration the vault did not offer", async () => {
      const v = vault({})
      expect(await refusedWith(decideApproval(shell(), ruled, { ...allow, rule: { path: "/repos/a/*/issues/12/comments", ttl: "604800" } }, passkey))).toMatchObject({ error: "bad_request" })
      expect(await refusedWith(decideApproval(shell(), ruled, { ...allow, rule: { path: pathChoices[0]!, ttl: "3600" } }, passkey))).toMatchObject({ error: "bad_request" })
      expect(v.calls).toEqual([])
      expect(passkey).not.toHaveBeenCalled()
    })

    it("signs one approval.decide whose remember is the chosen path, duration and the digest of those terms", async () => {
      const remember = { kind: "rule", path: "/repos/a/b/issues/*/comments", ttlSeconds: 2_592_000, termsDigest: await policyRuleTermsDigest({ ...terms, path: "/repos/a/b/issues/*/comments", ttlSeconds: 2_592_000 }) }
      expect(PolicyRememberRuleSchema.parse(remember)).toEqual(remember)
      const action = { type: "approval.decide", approval: "apr_1", digest: binding.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 600 }, remember }
      const v = vault({ "/api/w/northwind/approvals/apr_1/action": action, "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": STEPUP, "/api/w/northwind/approvals/apr_1/decide": { status: "approved" } })
      expect(await decideApproval(shell(), ruled, allow, passkey)).toEqual({ status: "approved" })
      expect(v.paths()).toEqual(["/api/w/northwind/approvals/apr_1/action", "/api/w/northwind", "/api/w/northwind/stepup/start", "/api/w/northwind/approvals/apr_1/decide"])
      expect(v.calls[0]?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 600 }, remember })
      expect(v.calls[2]?.body).toEqual({ action })
      expect(v.calls[3]?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 600 }, remember, stepUp: { nonce: "n", assertion: { signed: true } } })
      expect(passkey).toHaveBeenCalledTimes(1)
    })

    it("refuses a vault action that remembers other terms than the page chose", async () => {
      const other = { kind: "rule", path: "/repos/a/b/issues/*/comments", ttlSeconds: 2_592_000, termsDigest: await policyRuleTermsDigest({ ...terms, path: "/repos/a/b/issues/*/comments", ttlSeconds: 604_800 }) }
      const v = vault({ "/api/w/northwind/approvals/apr_1/action": { type: "approval.decide", approval: "apr_1", digest: binding.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 600 }, remember: other } })
      expect(await refusedWith(decideApproval(shell(), ruled, allow, passkey))).toEqual(CHANGED_SINCE_SHOWN)
      expect(v.paths()).toEqual(["/api/w/northwind/approvals/apr_1/action"])
      expect(passkey).not.toHaveBeenCalled()
    })

    it("a plain approve or a decline on the same page remembers nothing", async () => {
      const v = vault({ "/api/w/northwind/approvals/apr_1/action": { type: "approval.decide", approval: "apr_1", digest: binding.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 600 } }, "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": STEPUP, "/api/w/northwind/approvals/apr_1/decide": { status: "approved" } })
      await decideApproval(shell(), ruled, ok, passkey)
      expect(v.calls[0]?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 600 } })
      expect(approvalDecision(ruled, "deny", subject.constraints, { kind: "rule", path: pathChoices[0]!, ttlSeconds: 604_800, termsDigest: ruled.rule!.termsDigest }).body).toEqual({ decision: "deny", constraints: subject.constraints })
    })
  })

  describe("with a task grant", () => {
    // A held D1 database create on Cloudflare: the vault offers D1 databases
    // (the request's own area) for 1 hour and 50 requests, and KV to tick.
    const terms: PolicyAreaGrantTerms = { kind: "area", item: "cf-token", itemId: "itm_cf01", asker: { device: "dev_macmini1", workload: null }, host: "api.cloudflare.com", catalogue: "cloudflare-api-token", catalogueVersion: 1, areas: ["d1"], ttlSeconds: 3600, maxUses: 50 }
    const areas = [{ id: "d1", name: "D1 databases", words: "Creates and changes D1 databases", requestArea: true }, { id: "kv", name: "KV namespaces and values", words: "Writes KV values", requestArea: false }]
    const asked: ApprovalSubject = { ...subject, item: "cf-token", method: "POST", url: "https://api.cloudflare.com/client/v4/accounts/abc/d1/database" }
    let granted: WorkspaceApprovalBoot
    beforeEach(async () => {
      binding.digest = await digestOf({ subject: asked, snapshotDigest: binding.snapshotDigest, presentationDigest: binding.presentationDigest })
      granted = { ...boot, digest: binding.digest, subject: asked, area: { terms, termsDigest: await policyAreaGrantTermsDigest(terms), areas, coSign: false } }
    })
    const carry = { ...ok, area: { areas: ["kv", "d1"], ttl: "900", uses: "25" } }

    it("refuses while the offer's terms do not hash to the vault's digest, are not this approval's, or do not tick the request's own area", async () => {
      const v = vault({})
      expect(await areaOfferMatches(granted.area!, asked)).toBe(true)
      expect(await refusedWith(decideApproval(shell(), { ...granted, area: { ...granted.area!, termsDigest: "x".repeat(43) } }, carry, passkey))).toEqual(AREA_OFFER_MISMATCH)
      expect(await refusedWith(decideApproval(shell(), { ...granted, area: undefined }, carry, passkey))).toEqual(AREA_OFFER_MISMATCH)
      for (const other of [{ ...terms, item: "cf-other" }, { ...terms, host: "api.cloudflare.example" }, { ...terms, areas: ["kv"] }]) {
        const offer = { terms: other, termsDigest: await policyAreaGrantTermsDigest(other), areas, coSign: false }
        expect(await refusedWith(decideApproval(shell(), { ...granted, area: offer }, carry, passkey)), JSON.stringify(other)).toEqual(AREA_OFFER_MISMATCH)
      }
      // Both a rule and a task grant at once is refused, whichever check sees it first.
      expect(await refusedWith(decideApproval(shell(), granted, { ...carry, rule: { path: "/", ttl: "86400" } }, passkey))).toMatchObject({ error: "conflict" })
      expect(v.calls).toEqual([])
      expect(passkey).not.toHaveBeenCalled()
    })

    it("refuses no area, an area, duration or uses the vault did not offer", async () => {
      const v = vault({})
      expect(await refusedWith(decideApproval(shell(), granted, { ...carry, area: { ...carry.area, areas: [] } }, passkey))).toMatchObject({ error: "bad_request", message: AREA_AREAS_PROBLEM })
      expect(await refusedWith(decideApproval(shell(), granted, { ...carry, area: { ...carry.area, areas: ["dns"] } }, passkey))).toMatchObject({ error: "bad_request", message: AREA_AREAS_PROBLEM })
      expect(await refusedWith(decideApproval(shell(), granted, { ...carry, area: { ...carry.area, ttl: "86400" } }, passkey))).toMatchObject({ error: "bad_request", message: AREA_DURATION_PROBLEM })
      expect(await refusedWith(decideApproval(shell(), granted, { ...carry, area: { ...carry.area, uses: "500" } }, passkey))).toMatchObject({ error: "bad_request", message: AREA_USES_PROBLEM })
      expect(v.calls).toEqual([])
      expect(passkey).not.toHaveBeenCalled()
    })

    it("signs one approval.decide whose remember is the areas, duration and uses chosen and the digest of those terms", async () => {
      const remember = { kind: "area", areas: ["d1", "kv"], ttlSeconds: 900, maxUses: 25, termsDigest: await policyAreaGrantTermsDigest({ ...terms, areas: ["d1", "kv"], ttlSeconds: 900, maxUses: 25 }) }
      expect(PolicyRememberSchema.parse(remember)).toEqual(remember)
      const action = { type: "approval.decide", approval: "apr_1", digest: binding.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 600 }, remember }
      const v = vault({ "/api/w/northwind/approvals/apr_1/action": action, "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": STEPUP, "/api/w/northwind/approvals/apr_1/decide": { status: "approved" } })
      expect(await decideApproval(shell(), granted, carry, passkey)).toEqual({ status: "approved" })
      expect(v.calls[0]?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 600 }, remember })
      expect(v.calls[3]?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 600 }, remember, stepUp: { nonce: "n", assertion: { signed: true } } })
      expect(passkey).toHaveBeenCalledTimes(1)
    })

    it("refuses a vault action that grants other terms than the page chose", async () => {
      const other = { kind: "area", areas: ["d1", "kv"], ttlSeconds: 3600, maxUses: 25, termsDigest: await policyAreaGrantTermsDigest({ ...terms, areas: ["d1", "kv"], ttlSeconds: 3600, maxUses: 25 }) }
      const v = vault({ "/api/w/northwind/approvals/apr_1/action": { type: "approval.decide", approval: "apr_1", digest: binding.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 600 }, remember: other } })
      expect(await refusedWith(decideApproval(shell(), granted, carry, passkey))).toEqual(CHANGED_SINCE_SHOWN)
      expect(passkey).not.toHaveBeenCalled()
    })
  })

  it("the stop view signs only a denial of this approval", async () => {
    const v = vault({ "/api/w/northwind/approvals/apr_1/action": { type: "approval.decide", approval: "apr_1", digest: "d", decision: "approve", constraints: { uses: 1, ttlSeconds: 60 } } })
    expect(await refusedWith(denyFromStop(shell(), "apr_1", passkey))).toEqual(CHANGED_SINCE_SHOWN)
    expect(v.paths()).toEqual(["/api/w/northwind/approvals/apr_1/action"])
    expect(passkey).not.toHaveBeenCalled()
  })
})

describe("decideRuleProposal: the rule proposal page's one signed decision", () => {
  // A machine's proposal for a GitHub comment, the issue number as *, for
  // 30 days, with the vault's digests (the rule proposal page's gallery entry).
  const terms: PolicyRuleTerms = { item: "github-alex", itemId: "itm_github01", asker: { device: "dev_macmini1", workload: null }, method: "POST", host: "api.github.com", path: "/repos/northwind/platform/issues/*/comments", anchorPath: "/repos/northwind/platform/issues/12/comments", queryNames: [], graphql: null, ttlSeconds: 2_592_000 }
  const proposal = { proposal: "pol_7rk2mq9vx4", item: terms.item, digest: "X0Zz4RoXjjKkKlwfYGRroM7zgAvvMGh3MrcFoI-5rcU", stage: "approve" as const, extends: null, reason: "Post the deploy status on each issue it closes", terms, termsDigest: "BEajoDA9bGWZw8EVt5Au3kkmkFFgXKvAdsBRv2yfTys", pathChoices: [terms.anchorPath, terms.path] }
  const boot = { ...proposal, coded: true }
  const API = `/api/w/northwind/policy/proposals/${proposal.proposal}`
  const EXACT = proposal.terms.anchorPath
  const choice = { decision: "approve" as const, codeTicked: true, path: EXACT, ttl: "604800" }
  const approved = async (path = EXACT, ttlSeconds = 604_800) => ({ type: "policy.decide", proposal: proposal.proposal, digest: proposal.digest, decision: "approve", effectDigest: await policyRuleTermsDigest({ ...proposal.terms, path, ttlSeconds: ttlSeconds as 604_800 }) })

  it("holds the fixture to its digests", async () => {
    expect(await ruleProposalMatches(boot)).toBe(true)
  })

  it("approve signs one policy.decide whose effect is the digest of the terms with the chosen path and duration", async () => {
    const action = await approved()
    const v = vault({ [`${API}/action`]: action, "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": STEPUP, [`${API}/decide`]: { view: "detail", proposal: { status: "approved" } } })
    await decideRuleProposal(shell(), boot, choice, passkey)
    const body = { decision: "approve", effective: { path: EXACT, ttlSeconds: 604_800 } }
    expect(v.calls).toEqual([{ path: `${API}/action`, body }, { path: "/api/w/northwind", body: undefined }, { path: "/api/w/northwind/stepup/start", body: { action } }, { path: `${API}/decide`, body: { ...body, stepUp: { nonce: "n", assertion: { signed: true } } } }])
    expect(passkey).toHaveBeenCalledTimes(1)
  })

  it("deny signs policy.decide with no effect, and needs no tick", async () => {
    const action = { type: "policy.decide", proposal: proposal.proposal, digest: proposal.digest, decision: "deny", effectDigest: null }
    const v = vault({ [`${API}/action`]: action, "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": STEPUP, [`${API}/decide`]: {} })
    await decideRuleProposal(shell(), boot, { ...choice, decision: "deny", codeTicked: false }, passkey)
    expect(v.calls[0]).toEqual({ path: `${API}/action`, body: { decision: "deny" } })
    expect(v.calls[3]).toEqual({ path: `${API}/decide`, body: { decision: "deny", stepUp: { nonce: "n", assertion: { signed: true } } } })
  })

  it("refuses a prepared action that differs in any field, with nothing signed", async () => {
    const action = await approved()
    for (const differs of [{ proposal: "pol_other" }, { digest: "x".repeat(43) }, { decision: "deny" }, { effectDigest: await (await approved(EXACT, 86_400)).effectDigest }, { effectDigest: null }, { type: "approval.decide" }, { extra: 1 }]) {
      const v = vault({ [`${API}/action`]: { ...action, ...differs } })
      expect(await refusedWith(decideRuleProposal(shell(), boot, choice, passkey)), JSON.stringify(differs)).toEqual(CHANGED_SINCE_SHOWN)
      expect(v.paths()).toEqual([`${API}/action`])
      vi.restoreAllMocks()
    }
    expect(passkey).not.toHaveBeenCalled()
  })

  it("refuses before asking the vault: no tick, terms or reason the vault's digests do not cover, a credential not the terms', a wider path or a longer duration", async () => {
    const v = vault({})
    expect(await refusedWith(decideRuleProposal(shell(), boot, { ...choice, codeTicked: false }, passkey))).toEqual(BINDING_CODE_NOT_TICKED)
    expect(await refusedWith(decideRuleProposal(shell(), { ...boot, reason: "Something else" }, choice, passkey))).toEqual(RULE_PROPOSAL_MISMATCH)
    expect(await refusedWith(decideRuleProposal(shell(), { ...boot, terms: { ...boot.terms, host: "uploads.github.com" } }, choice, passkey))).toEqual(RULE_PROPOSAL_MISMATCH)
    expect(await refusedWith(decideRuleProposal(shell(), { ...boot, stage: "co-sign" }, choice, passkey))).toEqual(RULE_PROPOSAL_MISMATCH)
    expect(await refusedWith(decideRuleProposal(shell(), { ...boot, item: "github-other" }, choice, passkey))).toEqual(RULE_PROPOSAL_MISMATCH)
    expect(await refusedWith(decideRuleProposal(shell(), boot, { ...choice, path: "/repos/northwind/*/issues/*/comments" }, passkey))).toMatchObject({ error: "bad_request", message: RULE_PATH_PROBLEM })
    const terms = { ...boot.terms, ttlSeconds: 604_800 as const }
    const termsDigest = await policyRuleTermsDigest(terms)
    const shorter = { ...boot, terms, termsDigest, digest: await ruleProposalDigest({ ...boot, termsDigest }) }
    expect(await ruleProposalMatches(shorter)).toBe(true)
    expect(await refusedWith(decideRuleProposal(shell(), shorter, { ...choice, ttl: "2592000" }, passkey))).toMatchObject({ error: "bad_request", message: RULE_PROPOSAL_DURATION_PROBLEM })
    expect(v.calls).toEqual([])
    expect(passkey).not.toHaveBeenCalled()
  })
})

describe("decideAreaProposal: the task grant proposal page's one signed decision", () => {
  // A task grant Kim signed, D1 and KV for 1 hour and up to 50 requests,
  // waiting for a co-signer (the task grant proposal page's gallery entry).
  const terms: PolicyAreaGrantTerms = { kind: "area", item: "cloudflare-api-token-local-secrets-2", itemId: "itm_cloudflare1", asker: { device: "dev_kimlaptop1", workload: null }, host: "api.cloudflare.com", catalogue: "cloudflare-api-token", catalogueVersion: 1, areas: ["d1", "kv"], ttlSeconds: 3600, maxUses: 50 }
  const boot = { proposal: "pol_6ag3kq8mw2", item: terms.item, digest: "0iP7gye9vFlrigrsEN3pyCq3TeoG8N-t7m7Zb-RssAY", stage: "co-sign" as const, reason: null, terms, termsDigest: "N0xgvgVfDd644wxJ2615hsUta2sc6TjqEt1gZwNWdTg", coded: false }
  const API = `/api/w/northwind/policy/proposals/${boot.proposal}`
  const approve = { decision: "approve" as const, codeTicked: false }

  it("approve signs one policy.decide whose effect is the digest of the terms as signed", async () => {
    const action = { type: "policy.decide", proposal: boot.proposal, digest: boot.digest, decision: "approve", effectDigest: boot.termsDigest }
    const v = vault({ [`${API}/action`]: action, "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": STEPUP, [`${API}/decide`]: { view: "detail", proposal: { status: "approved" } } })
    await decideAreaProposal(shell(), boot, approve, passkey)
    const body = { decision: "approve", effective: { areas: ["d1", "kv"], ttlSeconds: 3600, maxUses: 50 } }
    expect(v.calls).toEqual([{ path: `${API}/action`, body }, { path: "/api/w/northwind", body: undefined }, { path: "/api/w/northwind/stepup/start", body: { action } }, { path: `${API}/decide`, body: { ...body, stepUp: { nonce: "n", assertion: { signed: true } } } }])
    expect(passkey).toHaveBeenCalledTimes(1)
  })

  it("deny signs policy.decide with no effect", async () => {
    const action = { type: "policy.decide", proposal: boot.proposal, digest: boot.digest, decision: "deny", effectDigest: null }
    const v = vault({ [`${API}/action`]: action, "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": STEPUP, [`${API}/decide`]: {} })
    await decideAreaProposal(shell(), { ...boot, termsDigest: "x".repeat(43) }, { decision: "deny", codeTicked: false }, passkey)
    expect(v.calls[0]).toEqual({ path: `${API}/action`, body: { decision: "deny" } })
  })

  it("refuses before asking the vault: terms the vault's digests do not cover, a credential not the terms', or an agent's code unticked", async () => {
    const v = vault({})
    expect(await refusedWith(decideAreaProposal(shell(), { ...boot, terms: { ...terms, maxUses: 100 } }, approve, passkey))).toEqual(AREA_PROPOSAL_MISMATCH)
    expect(await refusedWith(decideAreaProposal(shell(), { ...boot, stage: "approve" }, approve, passkey))).toEqual(AREA_PROPOSAL_MISMATCH)
    expect(await refusedWith(decideAreaProposal(shell(), { ...boot, item: "github-alex" }, approve, passkey))).toEqual(AREA_PROPOSAL_MISMATCH)
    expect(await refusedWith(decideAreaProposal(shell(), { ...boot, coded: true }, approve, passkey))).toEqual(BINDING_CODE_NOT_TICKED)
    expect(v.calls).toEqual([])
    expect(passkey).not.toHaveBeenCalled()
  })

  it("refuses a prepared action that grants anything else, with nothing signed", async () => {
    const wider = await policyAreaGrantTermsDigest({ ...terms, areas: ["d1", "dns", "kv"] })
    const v = vault({ [`${API}/action`]: { type: "policy.decide", proposal: boot.proposal, digest: boot.digest, decision: "approve", effectDigest: wider } })
    expect(await refusedWith(decideAreaProposal(shell(), boot, approve, passkey))).toEqual(CHANGED_SINCE_SHOWN)
    expect(v.paths()).toEqual([`${API}/action`])
    expect(passkey).not.toHaveBeenCalled()
  })
})

describe("decideReviewBatch: Review together's one passkey", () => {
  const subject = (path: string): ApprovalSubject => ({ item: "cloudflare", method: "POST", url: `https://api.cloudflare.com${path}`, contentType: null, contentEncoding: null, headersSha256: "h", bodySha256: "b", constraints: { uses: 1, ttlSeconds: 600 } })
  let rows: ReviewRowBoot[]
  beforeEach(async () => {
    const detail = async (approval: string, section: ReviewRowBoot["section"]): Promise<ReviewRowBoot> => {
      const asked = subject(`/v1/${approval}`)
      return { approval, view: "detail", section, pending: true, newer: false, digest: await digestOf({ subject: asked, snapshotDigest: "snap", presentationDigest: approval }), subject: asked, binding: { snapshotDigest: "snap", presentationDigest: approval }, headers: null }
    }
    rows = [await detail("apr_b", "routine"), await detail("apr_a", "floor"), await detail("apr_c", "deny-only"), await detail("apr_d", "own-page")]
  })
  const entry = (r: ReviewRowBoot, decision: "approve" | "deny") => r.view === "detail" ? { approval: r.approval, digest: r.digest, decision, uses: 1, ttlSeconds: 600 } : null
  const approveBoth = [{ approval: "apr_a", decision: "approve" as const }, { approval: "apr_b", decision: "approve" as const }]
  const action = () => ({ type: "approval.decide_many", entries: [entry(rows[1]!, "approve"), entry(rows[0]!, "approve")] })
  const RESULT = { batch: "apb_1", results: [], approved: 2, denied: 0, skipped: 0 }

  it("refuses with nothing sent: nothing ticked, the codes unticked, a row the page does not let a batch decide, a request that does not recompute", async () => {
    const v = vault({})
    expect(await refusedWith(decideReviewBatch(shell(), rows, [], true, passkey))).toEqual(REVIEW_NOTHING_TICKED)
    expect(await refusedWith(decideReviewBatch(shell(), rows, approveBoth, false, passkey))).toEqual(REVIEW_CODES_NOT_TICKED)
    expect(await refusedWith(decideReviewBatch(shell(), rows, [{ approval: "apr_c", decision: "approve" }], true, passkey))).toEqual(CHANGED_SINCE_SHOWN)
    expect(await refusedWith(decideReviewBatch(shell(), rows, [{ approval: "apr_d", decision: "deny" }], true, passkey))).toEqual(CHANGED_SINCE_SHOWN)
    expect(await refusedWith(decideReviewBatch(shell(), rows, [{ approval: "apr_x", decision: "deny" }], true, passkey))).toEqual(CHANGED_SINCE_SHOWN)
    const tampered = rows.map((r) => r.approval === "apr_b" && r.view === "detail" ? { ...r, subject: subject("/v1/elsewhere") } : r)
    expect(await refusedWith(decideReviewBatch(shell(), tampered, approveBoth, true, passkey))).toEqual(REVIEW_BINDING_MISMATCH)
    expect(v.calls).toEqual([])
    expect(passkey).not.toHaveBeenCalled()
  })

  it("refuses a vault action that differs from the rows shown in any entry, with nothing signed", async () => {
    for (const changed of [{ ...action(), entries: [{ ...action().entries[0]!, digest: "other" }, action().entries[1]] }, { ...action(), entries: [action().entries[0]] }, { ...action(), entries: [action().entries[1], action().entries[0]] }]) {
      passkey.mockClear()
      const v = vault({ "/api/w/northwind/approval-batch/action": changed })
      expect(await refusedWith(decideReviewBatch(shell(), rows, approveBoth, true, passkey))).toEqual(CHANGED_SINCE_SHOWN)
      expect(v.paths()).toEqual(["/api/w/northwind/approval-batch/action"])
      expect(passkey).not.toHaveBeenCalled()
      vi.restoreAllMocks()
    }
  })

  it("signs only the matching action, once, and sends the same entries to decide", async () => {
    const v = vault({ "/api/w/northwind/approval-batch/action": action(), "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": STEPUP, "/api/w/northwind/approval-batch/decide": RESULT })
    expect(await decideReviewBatch(shell(), rows, approveBoth, true, passkey)).toEqual(RESULT)
    expect(v.paths()).toEqual(["/api/w/northwind/approval-batch/action", "/api/w/northwind", "/api/w/northwind/stepup/start", "/api/w/northwind/approval-batch/decide"])
    expect(v.calls[0]?.body).toEqual({ entries: [{ id: "apr_a", decision: "approve" }, { id: "apr_b", decision: "approve" }] })
    expect(v.calls[2]?.body).toEqual({ action: action() })
    expect(v.calls[3]?.body).toMatchObject({ entries: [{ id: "apr_a", decision: "approve" }, { id: "apr_b", decision: "approve" }], stepUp: { nonce: "n" } })
    expect(passkey).toHaveBeenCalledTimes(1)
  })

  it("denies a deny-only row with the codes unticked", async () => {
    const denial = { type: "approval.decide_many", entries: [entry(rows[2]!, "deny")] }
    const v = vault({ "/api/w/northwind/approval-batch/action": denial, "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": STEPUP, "/api/w/northwind/approval-batch/decide": { ...RESULT, approved: 0, denied: 1 } })
    await decideReviewBatch(shell(), rows, [{ approval: "apr_c", decision: "deny" }], false, passkey)
    expect(v.paths()).toContain("/api/w/northwind/approval-batch/decide")
    expect(passkey).toHaveBeenCalledTimes(1)
  })
})
