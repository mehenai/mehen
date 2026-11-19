// Stop and Extend on a standing rule (policy-rules-sign.ts), driven with a
// fake fetch and a fake passkey: Stop is one post and no passkey; Extend
// signs only when the vault's action carries the effectDigest this code
// computed from the rule's id and the chosen duration, and otherwise sends
// no step-up start, asks no passkey and sends no decide.

import { type Mock, afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import type { PolicyRuleTerms } from "@mehen/protocol/policy-mode"
import { policyRuleExtendDigest, policyRuleTermsDigest } from "@mehen/protocol/policy-rules"
import { VaultFailure } from "./api.ts"
import { coSignHref, extendRule, isRuleExtendAction, isStoppedOnly, ruleDuration, shownRuleTerms, stopRule } from "./policy-rules-sign.ts"
import { ShellState } from "./shell-logic.ts"
import { CHANGED_SINCE_SHOWN } from "./workspace-logic.ts"
import type { Passkey } from "./workspace-sign.ts"

const WORKSPACE = { id: "tn_work", slug: "northwind", name: "Northwind" }
const RULE = "rul_chat0001"
// The terms the rule's row shows, as the vault lists them.
const TERMS: PolicyRuleTerms = { item: "openai-shared", itemId: "itm_openaishared", asker: { device: "dev_tomlaptop01", workload: null }, method: "POST", host: "api.openai.com", path: "/v1/chat/completions", anchorPath: "/v1/chat/completions", queryNames: [], graphql: null, ttlSeconds: 604_800 }
const BASE = `/api/w/northwind/policy/rules/${RULE}`
const STEPUP = { nonce: "n", options: { challenge: "c", allowCredentials: [] } }

type Call = { path: string; body: unknown }

function vault(answers: Record<string, unknown>): { calls: Call[]; paths: () => string[] } {
  const calls: Call[] = []
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const path = String(input)
    calls.push({ path, body: init?.body === undefined ? undefined : JSON.parse(String(init.body)) })
    const answer = answers[path]
    if (answer === undefined) return new Response(JSON.stringify({ error: "not_found", message: "No such route." }), { status: 404 })
    return new Response(JSON.stringify(answer), { status: 200, headers: { "content-type": "application/json" } })
  })
  return { calls, paths: () => calls.map((c) => c.path) }
}

function shell(): ShellState {
  return new ShellState({ origin: "https://vault.test", account: "acc_alex", workspace: WORKSPACE, pages: [], reads: [] })
}

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

const ended = { id: RULE, status: "ended", endedReason: "revoked" }

describe("Stop", () => {
  it("posts revoke with an empty body and no passkey, and tells a full answer from a stopped-only one", async () => {
    const v = vault({ [`${BASE}/revoke`]: ended })
    const answer = await stopRule(shell(), RULE)
    expect(v.calls).toEqual([{ path: `${BASE}/revoke`, body: {} }])
    expect(passkey).not.toHaveBeenCalled()
    expect(isStoppedOnly(answer)).toBe(true)
    expect(isStoppedOnly({ ...ended, method: "POST" } as never)).toBe(false)
    // A task grant's full answer names its areas, not a method.
    expect(isStoppedOnly({ ...ended, kind: "area", areas: ["d1"] } as never)).toBe(false)
    expect(isStoppedOnly({ ...ended, endedReason: "uses-spent" } as never)).toBe(true)
  })
})

describe("Extend", () => {
  const action = async (ttlSeconds: 86_400 | 604_800 | 2_592_000, terms: PolicyRuleTerms = TERMS) => ({ type: "policy.decide", proposal: RULE, digest: await policyRuleTermsDigest(terms), decision: "approve", effectDigest: await policyRuleExtendDigest(RULE, ttlSeconds) })

  it("signs one passkey over the vault's action when its effectDigest is the one computed here, then decides with the same duration", async () => {
    const extended = { rule: { id: RULE, endsAt: "2026-11-10T12:00:00.000Z" }, coSign: null }
    const v = vault({ [`${BASE}/extend/action`]: await action(604_800), "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": STEPUP, [`${BASE}/extend/decide`]: extended })
    expect(await extendRule(shell(), RULE, 604_800, TERMS, passkey)).toEqual(extended)
    expect(v.paths()).toEqual([`${BASE}/extend/action`, "/api/w/northwind", "/api/w/northwind/stepup/start", `${BASE}/extend/decide`])
    expect(v.calls[0]!.body).toEqual({ ttlSeconds: 604_800 })
    expect(v.calls[2]!.body).toEqual({ action: await action(604_800) })
    expect(v.calls[3]!.body).toEqual({ ttlSeconds: 604_800, stepUp: { nonce: "n", assertion: { signed: true } } })
    expect(passkey).toHaveBeenCalledTimes(1)
  })

  it("refuses with nothing signed when the action's effectDigest is for another duration, another rule, or missing, or its digest is not of the terms shown", async () => {
    // The terms digest follows an extension (ttlSeconds), so a page showing
    // the rule before its last extension is refused too.
    const extendedSince = await action(604_800, { ...TERMS, ttlSeconds: 2_592_000 })
    for (const wrong of [await action(2_592_000), { ...(await action(604_800)), proposal: "rul_other0001" }, { ...(await action(604_800)), effectDigest: null }, { ...(await action(604_800)), extra: true }, extendedSince, await action(604_800, { ...TERMS, path: "/v1/embeddings", anchorPath: "/v1/embeddings" })]) {
      vi.restoreAllMocks()
      const v = vault({ [`${BASE}/extend/action`]: wrong, "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": STEPUP })
      expect(await refusedWith(extendRule(shell(), RULE, 604_800, TERMS, passkey))).toEqual(CHANGED_SINCE_SHOWN)
      expect(v.paths()).toEqual([`${BASE}/extend/action`])
    }
    expect(passkey).not.toHaveBeenCalled()
  })

  it("refuses before sending anything when the row's terms cannot be read", async () => {
    const v = vault({ [`${BASE}/extend/action`]: await action(604_800) })
    expect(await refusedWith(extendRule(shell(), RULE, 604_800, null, passkey))).toEqual(CHANGED_SINCE_SHOWN)
    expect(v.paths()).toEqual([])
    expect(passkey).not.toHaveBeenCalled()
    expect(shownRuleTerms(JSON.stringify(TERMS))).toEqual(TERMS)
    for (const raw of [undefined, "", "{", JSON.stringify({ ...TERMS, extra: 1 }), JSON.stringify({ ...TERMS, ttlSeconds: 3600 })]) expect(shownRuleTerms(raw), String(raw)).toBeNull()
  })

  it("passes on the co-sign answer: the rule as it was and the proposal a manager of the credential's home must approve", async () => {
    const coSign = { id: "pol_extend0001", url: "https://vault.test/w/northwind/p/pol_extend0001", bindingCode: "7XK2M9QP", expiresAt: "2026-11-05T12:00:00.000Z" }
    vault({ [`${BASE}/extend/action`]: await action(86_400), "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": STEPUP, [`${BASE}/extend/decide`]: { rule: { id: RULE }, coSign } })
    expect((await extendRule(shell(), RULE, 86_400, TERMS, passkey)).coSign).toEqual(coSign)
    expect(coSignHref(shell(), coSign.id)).toBe(coSign.url)
    expect(coSignHref(shell(), "https://evil.test/")).toBeNull()
  })

  it("reads only the three durations, and an action is exactly the extension of this rule", async () => {
    expect(["86400", "604800", "2592000", "3600", "", "604800.0"].map(ruleDuration)).toEqual([86_400, 604_800, 2_592_000, null, null, null])
    const digest = await policyRuleExtendDigest(RULE, 604_800)
    const termsDigest = await policyRuleTermsDigest(TERMS)
    expect(isRuleExtendAction(await action(604_800), RULE, digest, termsDigest)).toBe(true)
    expect(isRuleExtendAction({ ...(await action(604_800)), decision: "deny" }, RULE, digest, termsDigest)).toBe(false)
    expect(isRuleExtendAction({ ...(await action(604_800)), digest: "short" }, RULE, digest, termsDigest)).toBe(false)
    expect(isRuleExtendAction(null, RULE, digest, termsDigest)).toBe(false)
  })
})
