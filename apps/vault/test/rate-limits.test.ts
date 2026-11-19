// Which limits a request meets (src/rate-limits.ts): signed traffic by the
// identity its proof claims behind a higher limit per address, everything
// else as before, and a limiter left unbound refuses rather than allows.

import { describe, expect, it, vi } from "vitest"
import { createProof, parseProof, webCryptoSigner } from "@mehen/protocol"
import type { Env } from "../src/env.ts"
import { type RateLimiterBinding, rateLimitSteps } from "../src/rate-limits.ts"
import { ORIGIN } from "./helpers.ts"
import { answerOf, fetchPlatformRequest, platformEnv, registerPlatform, signedRequest } from "./platform-fixtures.ts"

type Counted = { name: string; key: string }

function countingLimiters(refuse: (name: string, key: string) => boolean = () => false): { limiters: Partial<Env>; counted: Counted[] } {
  const counted: Counted[] = []
  const limiter = (name: string) => ({ limit: async ({ key }: { key: string }) => { counted.push({ name, key }); return { success: !refuse(name, key) } } }) as unknown as RateLimit
  return { counted, limiters: { RATE_LIMITER: limiter("RATE_LIMITER"), AUTH_RATE_LIMITER: limiter("AUTH_RATE_LIMITER"), PLATFORM_IP_RATE_LIMITER: limiter("PLATFORM_IP_RATE_LIMITER"), DEVICE_IP_RATE_LIMITER: limiter("DEVICE_IP_RATE_LIMITER"), DEVICE_RATE_LIMITER: limiter("DEVICE_RATE_LIMITER") } }
}

async function deviceProof(path: string, options: { tenant?: string; device?: string; workload?: string; method?: string } = {}): Promise<string> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
  return createProof(webCryptoSigner(options.device ?? "dev_one", pair.privateKey, options.workload), { method: options.method ?? "GET", url: `${ORIGIN}${path}` }, { tenant: options.tenant ?? "tn_Alpha123456" })
}

function without(env: Env, binding: RateLimiterBinding): Env {
  const copy = { ...env }
  delete copy[binding]
  return copy
}

const RATE_LIMITED = { status: 429, body: { error: "rate_limited", message: "Too many requests; slow down." } }

function steps(env: Env, path: string, headers: Record<string, string> = {}): { name: string; key: string }[] {
  const named = new Map<RateLimit | undefined, string>(Object.entries(env).filter(([name]) => name.endsWith("RATE_LIMITER")).map(([name, value]) => [value as RateLimit, name]))
  const request = new Request(`${ORIGIN}${path}`, { headers: { "cf-connecting-ip": "203.0.113.7", ...headers } })
  return rateLimitSteps(request, new URL(request.url), env).map((step) => ({ name: named.get(step.limiter) ?? "none", key: step.key }))
}

describe("rate limits", () => {
  it("key device and workload calls by the workspace and device their proof claims, behind the per-address limit", async () => {
    const { env } = await platformEnv()
    const { limiters } = countingLimiters()
    const bound = { ...env, ...limiters }
    expect(steps(bound, "/v1/me", { "Mehen-Proof": await deviceProof("/v1/me") })).toEqual([{ name: "DEVICE_IP_RATE_LIMITER", key: "203.0.113.7" }, { name: "DEVICE_RATE_LIMITER", key: "tn_Alpha123456:dev_one" }])
    expect(steps(bound, "/v1/relay", { "Mehen-Proof": await deviceProof("/v1/relay", { workload: "wl_abcdefgh" }) })).toEqual([{ name: "DEVICE_IP_RATE_LIMITER", key: "203.0.113.7" }, { name: "DEVICE_RATE_LIMITER", key: "tn_Alpha123456:dev_one" }])
    // Fill's own hourly buckets (areas/browser-workspace.ts) come after these.
    expect(steps(bound, "/v1/fill", { "Mehen-Proof": await deviceProof("/v1/fill", { method: "POST", workload: "wl_abcdefgh" }) })).toEqual([{ name: "DEVICE_IP_RATE_LIMITER", key: "203.0.113.7" }, { name: "DEVICE_RATE_LIMITER", key: "tn_Alpha123456:dev_one" }])
  })

  it("keep today's limits for sign-in, enrolment, the seal key, unauthenticated routes and proofs that do not parse", async () => {
    const { env } = await platformEnv()
    const { limiters } = countingLimiters()
    const bound = { ...env, ...limiters }
    const proof = await deviceProof("/v1/enrol")
    const enrolling = await deviceProof("/v1/enrol", { tenant: "enrol" })
    const address = (name: string) => [{ name, key: "203.0.113.7" }]
    expect(steps(bound, "/api/auth/signin", { "Mehen-Proof": proof })).toEqual(address("AUTH_RATE_LIMITER"))
    expect(steps(bound, "/app/v1/session")).toEqual(address("AUTH_RATE_LIMITER"))
    expect(steps(bound, "/v1/enrol", { "Mehen-Proof": proof })).toEqual(address("RATE_LIMITER"))
    expect(steps(bound, "/v1/enrol/enr_x", { "Mehen-Proof": proof })).toEqual(address("RATE_LIMITER"))
    expect(steps(bound, "/v1/seal-key", { "Mehen-Proof": proof })).toEqual(address("RATE_LIMITER"))
    expect(steps(bound, "/v1/me", { "Mehen-Proof": enrolling })).toEqual(address("RATE_LIMITER"))
    expect(steps(bound, "/v1/me", { "Mehen-Proof": "not.a.proof" })).toEqual(address("RATE_LIMITER"))
    expect(steps(bound, "/v1/me")).toEqual(address("RATE_LIMITER"))
    expect(steps(bound, "/healthz")).toEqual(address("RATE_LIMITER"))
    expect(steps(bound, "/api/w/alex/items", { "Mehen-Proof": proof })).toEqual(address("RATE_LIMITER"))
  })

  it("limit platform calls only by a generous per-address limit before their proof is checked", async () => {
    const { env } = await platformEnv()
    const { limiters } = countingLimiters()
    expect(steps({ ...env, ...limiters }, "/v1/platform/subjects/subject-aaaa")).toEqual([{ name: "PLATFORM_IP_RATE_LIMITER", key: "203.0.113.7" }])
  })

  it("throttle one device without throttling another behind the same address, through the Worker", async () => {
    const { env } = await platformEnv()
    const { limiters, counted } = countingLimiters((name, key) => name === "DEVICE_RATE_LIMITER" && key.endsWith(":dev_busy"))
    const bound = { ...env, ...limiters }
    const request = async (device: string) => new Request(`${ORIGIN}/v1/me`, { headers: { "cf-connecting-ip": "203.0.113.7", "Mehen-Proof": await deviceProof("/v1/me", { device }) } })
    const busy = await answerOf(await fetchPlatformRequest(bound, await request("dev_busy")))
    expect(busy).toEqual({ status: 429, body: { error: "rate_limited", message: "Too many requests; slow down." } })
    const quiet = await fetchPlatformRequest(bound, await request("dev_quiet"))
    expect(quiet.status).not.toBe(429)
    expect(counted.map((c) => c.name)).not.toContain("RATE_LIMITER")
  })

  it("refuse an address sending unsigned or forged device proofs after 120 a minute, while a genuine device behind it keeps its own limits", async () => {
    // The workspace stands in for the proof check: dev_genuine verifies,
    // dev_forged's signature does not, and any other device is unknown.
    const { env } = await platformEnv((call) => {
      const device = parseProof(String(call.auth.proof)).claims.dev
      if (device === "dev_genuine") return { ok: true, value: { device } }
      const refusal = device === "dev_forged" ? { error: "proof_invalid" as const, message: "The Mehen-Proof does not verify." } : { error: "unauthenticated" as const, message: "Unknown device." }
      return { ok: false, error: { vaultError: refusal, status: 401 } }
    })
    const spent = new Map<string, number>()
    const { limiters, counted } = countingLimiters((name, key) => {
      if (name !== "RATE_LIMITER") return false
      spent.set(key, (spent.get(key) ?? 0) + 1)
      return (spent.get(key) ?? 0) > 120
    })
    const bound = { ...env, ...limiters }
    const call = async (device: string) => answerOf(await fetchPlatformRequest(bound, new Request(`${ORIGIN}/v1/me`, { headers: { "cf-connecting-ip": "203.0.113.7", "Mehen-Proof": await deviceProof("/v1/me", { device }) } })))
    for (let i = 0; i < 60; i++) expect((await call("dev_forged")).status).toBe(401)
    for (let i = 0; i < 60; i++) expect((await call(`dev_random${i}`)).status).toBe(401)
    expect(spent.get("203.0.113.7")).toBe(120)
    expect(await call("dev_forged")).toEqual({ status: 429, body: { error: "rate_limited", message: "Too many requests; slow down." } })
    expect(await call("dev_random_after")).toEqual({ status: 429, body: { error: "rate_limited", message: "Too many requests; slow down." } })
    for (let i = 0; i < 200; i++) expect(await call("dev_genuine")).toEqual({ status: 200, body: { device: "dev_genuine" } })
    expect(spent.get("203.0.113.7")).toBe(122)
    expect(counted.filter((c) => c.name === "DEVICE_RATE_LIMITER" && c.key === "tn_Alpha123456:dev_genuine")).toHaveLength(200)
  })

  it("charge a call with no proof once, up front, a genuine call never, and a refused proof after the fact", async () => {
    const { env } = await platformEnv((call) => (parseProof(String(call.auth.proof)).claims.dev === "dev_genuine" ? { ok: true, value: {} } : { ok: false, error: { vaultError: { error: "proof_invalid", message: "The Mehen-Proof does not verify." }, status: 401 } }))
    const { limiters, counted } = countingLimiters()
    const bound = { ...env, ...limiters }
    const charged = () => counted.filter((c) => c.name === "RATE_LIMITER").length
    const unsigned = await answerOf(await fetchPlatformRequest(bound, new Request(`${ORIGIN}/v1/me`, { headers: { "cf-connecting-ip": "203.0.113.7" } })))
    expect(unsigned.status).toBe(401)
    expect(charged()).toBe(1)
    await fetchPlatformRequest(bound, new Request(`${ORIGIN}/v1/me`, { headers: { "cf-connecting-ip": "203.0.113.7", "Mehen-Proof": await deviceProof("/v1/me", { device: "dev_genuine" }) } }))
    expect(charged()).toBe(1)
    await fetchPlatformRequest(bound, new Request(`${ORIGIN}/v1/me`, { headers: { "cf-connecting-ip": "203.0.113.7", "Mehen-Proof": await deviceProof("/v1/me", { device: "dev_forged" }) } }))
    expect(charged()).toBe(2)
  })

  it("throttle a platform's calls by address only before verification, then by its own limits", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env)
    const { limiters, counted } = countingLimiters((name) => name === "PLATFORM_IP_RATE_LIMITER" && counted.filter((c) => c.name === name).length > 1)
    const bound = { ...env, ...limiters }
    expect((await fetchPlatformRequest(bound, await signedRequest(platform, { method: "GET", path: "/v1/platform" }))).status).toBe(200)
    const limited = await answerOf(await fetchPlatformRequest(bound, await signedRequest(platform, { method: "GET", path: "/v1/platform" })))
    expect(limited).toEqual({ status: 429, body: { error: "rate_limited", message: "Too many requests; slow down." } })
    expect(counted.map((c) => c.name)).toEqual(["PLATFORM_IP_RATE_LIMITER", "PLATFORM_IP_RATE_LIMITER"])
  })

  it("refuse what a missing limiter would have counted, and only that, through the Worker", async () => {
    const { env } = await platformEnv()
    const { limiters } = countingLimiters()
    const bound = { ...env, ...limiters }
    const signed = async (): Promise<Record<string, string>> => ({ "Mehen-Proof": await deviceProof("/v1/me") })
    const cases: [RateLimiterBinding, string, () => Promise<Record<string, string>>][] = [
      ["RATE_LIMITER", "/healthz", async () => ({})],
      ["AUTH_RATE_LIMITER", "/api/auth/signin", async () => ({})],
      ["PLATFORM_IP_RATE_LIMITER", "/v1/platform", async () => ({})],
      ["DEVICE_IP_RATE_LIMITER", "/v1/me", signed],
      ["DEVICE_RATE_LIMITER", "/v1/me", signed],
    ]
    const errors = vi.spyOn(console, "error").mockImplementation(() => {})
    try {
      for (const [binding, path, headers] of cases) {
        const request = async () => new Request(`${ORIGIN}${path}`, { headers: { "cf-connecting-ip": "203.0.113.7", ...(await headers()) } })
        errors.mockClear()
        expect(await answerOf(await fetchPlatformRequest(without(bound, binding), await request())), binding).toEqual(RATE_LIMITED)
        expect(errors).toHaveBeenCalledWith(JSON.stringify({ at: "rate_limit", error: "limiter_unbound", binding }))
        expect((await fetchPlatformRequest(bound, await request())).status, binding).not.toBe(429)
      }
      // A missing device limiter leaves unsigned traffic, which never meets it, alone.
      const healthz = new Request(`${ORIGIN}/healthz`, { headers: { "cf-connecting-ip": "203.0.113.7" } })
      expect((await fetchPlatformRequest(without(bound, "DEVICE_RATE_LIMITER"), healthz)).status).toBe(200)
    } finally {
      errors.mockRestore()
    }
  })

  it("answer a refused device proof rate_limited when RATE_LIMITER is missing, while a genuine device keeps its own limits", async () => {
    const { env } = await platformEnv((call) => (parseProof(String(call.auth.proof)).claims.dev === "dev_genuine" ? { ok: true, value: { device: "dev_genuine" } } : { ok: false, error: { vaultError: { error: "proof_invalid", message: "The Mehen-Proof does not verify." }, status: 401 } }))
    const { limiters, counted } = countingLimiters()
    const unbound = without({ ...env, ...limiters }, "RATE_LIMITER")
    const call = async (device: string) => answerOf(await fetchPlatformRequest(unbound, new Request(`${ORIGIN}/v1/me`, { headers: { "cf-connecting-ip": "203.0.113.7", "Mehen-Proof": await deviceProof("/v1/me", { device }) } })))
    const errors = vi.spyOn(console, "error").mockImplementation(() => {})
    try {
      expect(await call("dev_forged")).toEqual(RATE_LIMITED)
      expect(errors).toHaveBeenCalledWith(JSON.stringify({ at: "rate_limit", error: "limiter_unbound", binding: "RATE_LIMITER" }))
      errors.mockClear()
      expect(await call("dev_genuine")).toEqual({ status: 200, body: { device: "dev_genuine" } })
      expect(errors).not.toHaveBeenCalled()
    } finally {
      errors.mockRestore()
    }
    expect(counted.map((c) => c.name)).toEqual(["DEVICE_IP_RATE_LIMITER", "DEVICE_RATE_LIMITER", "DEVICE_IP_RATE_LIMITER", "DEVICE_RATE_LIMITER"])
  })
})
