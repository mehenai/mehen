// The recommended version in Mehen-Cli follows the published release: the
// higher of CLI_RECOMMENDED_VERSION (the floor) and the version of
// https://mehen.dev/dl/latest.json, read through the mehen-web service
// binding, advertised only when a trusted release key signed it, refreshed
// off the request path at most every five minutes, kept an hour after the
// last good read. The minimum stays the hand-set var. The logic is tested
// with a release key made here and manifests it signs; the real published
// manifests only show that real releases verify against the compiled list.

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test"
import { env as baseEnv } from "cloudflare:workers"
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"
import { base64UrlEncode } from "@mehen/protocol/bytes"
import { RELEASE_KEYS } from "@mehen/protocol/release-keys"
import { type ReleaseKey, type ReleaseManifest, manifestSigningBytes, verifyManifestSignatures } from "@mehen/protocol/release-manifest"
import { RELEASE_KEYS as CLI_RELEASE_KEYS } from "../../cli/src/release-keys.ts"
import { cliAdvice, recommendedCliVersion } from "../src/cli-version.ts"
import type { Env } from "../src/env.ts"
import { PUBLISHED_RELEASE_MAX_BYTES, PUBLISHED_RELEASE_TIMEOUT_MS, PUBLISHED_RELEASE_URL, refreshPublishedRelease, resetPublishedReleaseForTest } from "../src/published-release.ts"
import { ORIGIN } from "./helpers.ts"
import { PUBLISHED_0_3_8, PUBLISHED_0_3_9 } from "./published-release-fixtures.ts"

const T0 = Date.parse("2026-11-03T12:00:00.000Z")
const MINUTE = 60_000

// A release key made for these tests, never a real one, and the
// manifests it signed, as latest.json would carry them.
let testKeys: ReleaseKey[]
let RELEASE_0_3_8: string
let RELEASE_0_3_9: string
beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey
  testKeys = [{ id: "rk-test-advice", alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y! }, presence: "none", created: "2026-11-03T12:00:00.000Z" }]
  const signed = async (version: string) => {
    const manifest: ReleaseManifest = {
      version,
      commit: "a53a3de",
      builtAt: "2026-11-03T10:00:00.000Z",
      files: [{ name: "mehen-linux-x64", os: "linux", arch: "x64", url: `https://mehen.dev/dl/v${version}/mehen-linux-x64.gz`, sha256: "a".repeat(64), size: 1, gzSha256: "b".repeat(64), gzSize: 1 }],
    }
    const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, manifestSigningBytes(manifest))
    return `${JSON.stringify({ ...manifest, signatures: [{ keyId: "rk-test-advice", alg: "ES256", signature: base64UrlEncode(new Uint8Array(signature)) }] }, null, 2)}\n`
  }
  RELEASE_0_3_8 = await signed("0.3.8")
  RELEASE_0_3_9 = await signed("0.3.9")
})

type Served = () => Response | Promise<Response>

// The mehen-web Worker as the service binding reaches it, serving whatever
// `served` answers and counting the reads.
function releasesWeb(initial: Served) {
  const binding = { served: initial, reads: [] as string[] }
  const fetcher = {
    fetch: async (input: RequestInfo | URL) => {
      binding.reads.push(input instanceof Request ? input.url : String(input))
      return binding.served()
    },
  }
  return { binding, fetcher: fetcher as unknown as Fetcher }
}

const json = (text: string, headers: Record<string, string> = {}) => () => new Response(text, { headers: { "content-type": "application/json", ...headers } })
const edited = (text: string, edit: (manifest: Record<string, unknown>) => void) => {
  const manifest = JSON.parse(text) as Record<string, unknown>
  edit(manifest)
  return JSON.stringify(manifest)
}

function vaultEnv(vars: { floor?: string | undefined; web?: Fetcher | undefined }): Env {
  return { ...(baseEnv as Env), CLI_MINIMUM_VERSION: "0.3.0", CLI_RECOMMENDED_VERSION: vars.floor, RELEASES_WEB: vars.web }
}

let errors: ReturnType<typeof vi.spyOn>
beforeEach(() => {
  resetPublishedReleaseForTest()
  errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
})
afterEach(() => {
  errors.mockRestore()
  vi.useRealTimers()
})

const logged = () => errors.mock.calls.map((call: unknown[]) => String(call[0]))

describe("the vault and the CLI trust the same release keys", () => {
  it("is one list, and both published fixtures verify against it", async () => {
    expect(CLI_RELEASE_KEYS).toBe(RELEASE_KEYS)
    expect(RELEASE_KEYS.length).toBeGreaterThan(0)
    for (const text of [PUBLISHED_0_3_8, PUBLISHED_0_3_9]) expect(await verifyManifestSignatures(JSON.parse(text), RELEASE_KEYS)).toMatchObject({ ok: true })
  })
})

describe("Mehen-Cli through the Worker", () => {
  async function send(env: Env, path = "/v1/me") {
    const worker = (await import("../src/index.ts")).default
    const ctx = createExecutionContext()
    const response = await worker.fetch(new Request(`${ORIGIN}${path}`, { headers: { "user-agent": "mehen/0.3.1 (linux-x64; release)" } }), env, ctx)
    return { response, ctx }
  }

  it("starts the read from a /v1 request, off the request path, and verifies it against the compiled release keys", async () => {
    const { binding, fetcher } = releasesWeb(json(RELEASE_0_3_9))
    const env = vaultEnv({ floor: "0.3.1", web: fetcher })
    const first = await send(env)
    expect(binding.reads).toEqual([PUBLISHED_RELEASE_URL])
    await waitOnExecutionContext(first.ctx)
    expect(logged()).toEqual([JSON.stringify({ at: "published_release", reason: "unknown_key" })])
    expect((await send(env)).response.headers.get("Mehen-Cli")).toBe("minimum=0.3.0; recommended=0.3.1")
    expect(binding.reads).toHaveLength(1)
  })

  it("advertises a verified newer release on /v1 responses and on the Machines page's advice", async () => {
    const { binding, fetcher } = releasesWeb(json(RELEASE_0_3_9))
    const env = vaultEnv({ floor: "0.3.1", web: fetcher })
    await refreshPublishedRelease(env, Date.now(), testKeys)
    const sent = await send(env)
    expect(sent.response.headers.get("Mehen-Cli")).toBe("minimum=0.3.0; recommended=0.3.9")
    await waitOnExecutionContext(sent.ctx)
    expect(binding.reads).toHaveLength(1)
    expect(cliAdvice(env)).toEqual({ minimum: "0.3.0", recommended: "0.3.9" })
    expect(logged()).toEqual([])
  })

  it("refuses no client for being below the published release: mehen/0.3.1 reaches the route (401 without a proof), never cli_outdated", async () => {
    const env = vaultEnv({ floor: "0.3.1", web: releasesWeb(json(RELEASE_0_3_9)).fetcher })
    await refreshPublishedRelease(env, Date.now(), testKeys)
    const sent = await send(env)
    expect(sent.response.status).toBe(401)
    expect(((await sent.response.json()) as { error: string }).error).not.toBe("cli_outdated")
    expect(sent.response.headers.get("Mehen-Cli")).toBe("minimum=0.3.0; recommended=0.3.9")
    await waitOnExecutionContext(sent.ctx)
  })

  it("never makes a request wait for the read, and starts no second read while one is in flight", async () => {
    let release: (response: Response) => void = () => undefined
    const gate = new Promise<Response>((resolve) => { release = resolve })
    const { binding, fetcher } = releasesWeb(() => gate)
    const env = vaultEnv({ floor: "0.3.1", web: fetcher })
    const first = await send(env)
    expect(first.response.status).toBe(401)
    expect(first.response.headers.get("Mehen-Cli")).toBe("minimum=0.3.0; recommended=0.3.1")
    const second = await send(env)
    expect(second.response.headers.get("Mehen-Cli")).toBe("minimum=0.3.0; recommended=0.3.1")
    expect(binding.reads).toHaveLength(1)
    release(json(RELEASE_0_3_9)())
    await waitOnExecutionContext(first.ctx)
    await waitOnExecutionContext(second.ctx)
    expect(binding.reads).toHaveLength(1)
  })

  it("reads nothing for a page, the browser API or the app API", async () => {
    const { binding, fetcher } = releasesWeb(json(RELEASE_0_3_9))
    const env = vaultEnv({ floor: "0.3.1", web: fetcher })
    for (const path of ["/signin", "/api/needs-you", "/app/v1/pending"]) await waitOnExecutionContext((await send(env, path)).ctx)
    expect(binding.reads).toEqual([])
  })

  it("advertises the floor when no binding is configured, as in local and test", async () => {
    const env = vaultEnv({ floor: "0.3.1", web: undefined })
    const first = await send(env)
    await waitOnExecutionContext(first.ctx)
    expect((await send(env)).response.headers.get("Mehen-Cli")).toBe("minimum=0.3.0; recommended=0.3.1")
    expect(refreshPublishedRelease(env, T0)).toBeNull()
  })
})

describe("the recommended version", () => {
  async function readAt(env: Env, now: number) {
    const refresh = refreshPublishedRelease(env, now, testKeys)
    if (refresh !== null) await refresh
    return refresh !== null
  }

  it("is the published release when it verifies and is above the floor, the floor when the release is not above it, and the release when no floor is set", async () => {
    for (const [floor, expected] of [["0.3.1", "0.3.9"], ["0.3.9", "0.3.9"], ["0.4.0", "0.4.0"], [undefined, "0.3.9"], ["latest", "0.3.9"]] as const) {
      resetPublishedReleaseForTest()
      const env = vaultEnv({ floor, web: releasesWeb(json(RELEASE_0_3_9)).fetcher })
      expect(recommendedCliVersion(env, T0), `${floor} before the read`).toBe(floor === "latest" ? null : (floor ?? null))
      await readAt(env, T0)
      expect(recommendedCliVersion(env, T0), String(floor)).toBe(expected)
    }
    expect(logged()).toEqual([])
  })

  it("is the floor for an unsigned manifest, an unknown key, a bad signature, a malformed or oversized body, a version that is not x.y.z, a refusal and an unreachable Worker; each read logs its reason once and never the body", async () => {
    const padded = RELEASE_0_3_9.replace(/\n}\s*$/, `${" ".repeat(PUBLISHED_RELEASE_MAX_BYTES)}\n}\n`)
    const cases: [string, Served][] = [
      ["unsigned", json(edited(RELEASE_0_3_9, (m) => { m.signatures = [] }))],
      ["unsigned", json(edited(RELEASE_0_3_9, (m) => { delete m.signatures }))],
      ["unknown_key", json(edited(RELEASE_0_3_9, (m) => { m.signatures = (m.signatures as { keyId: string }[]).map((s) => ({ ...s, keyId: "rk-someone-else" })) }))],
      ["bad_signature", json(edited(RELEASE_0_3_9, (m) => { m.commit = "0000000" }))],
      ["bad_signature", json(edited(RELEASE_0_3_9, (m) => { m.version = "0.4.0" }))],
      ["version", json(edited(RELEASE_0_3_9, (m) => { m.version = "0.4.0-rc.1" }))],
      ["version", json(edited(RELEASE_0_3_9, (m) => { m.version = "0.4" }))],
      ["version", json("[]")],
      ["malformed", json(JSON.stringify({ version: "0.4.0" }))],
      ["not_json", json("not json")],
      ["not_json", json("")],
      ["too_large", json(padded)],
      ["too_large", json(RELEASE_0_3_9, { "content-length": String(PUBLISHED_RELEASE_MAX_BYTES + 1) })],
      ["status", () => new Response(RELEASE_0_3_9, { status: 404 })],
      ["unreachable", () => Promise.reject(new Error("internal error; reference = abc"))],
    ]
    for (const [reason, served] of cases) {
      resetPublishedReleaseForTest()
      errors.mockClear()
      const { binding, fetcher } = releasesWeb(served)
      const env = vaultEnv({ floor: "0.3.1", web: fetcher })
      await readAt(env, T0)
      expect(recommendedCliVersion(env, T0), reason).toBe("0.3.1")
      expect(binding.reads).toHaveLength(1)
      expect(logged(), reason).toEqual([JSON.stringify({ at: "published_release", reason })])
    }
  })

  it("starts no second read while one is in flight, even once five minutes have passed", async () => {
    let release: (response: Response) => void = () => undefined
    const gate = new Promise<Response>((resolve) => { release = resolve })
    const { binding, fetcher } = releasesWeb(() => gate)
    const env = vaultEnv({ floor: "0.3.1", web: fetcher })
    const first = refreshPublishedRelease(env, T0, testKeys)
    expect(first).not.toBeNull()
    expect(refreshPublishedRelease(env, T0 + 5 * MINUTE, testKeys)).toBeNull()
    expect(refreshPublishedRelease(env, T0 + 30 * MINUTE, testKeys)).toBeNull()
    expect(binding.reads).toHaveLength(1)
    release(json(RELEASE_0_3_9)())
    await first
    expect(recommendedCliVersion(env, T0 + 30 * MINUTE)).toBe("0.3.9")
    binding.served = json(RELEASE_0_3_8)
    expect(await readAt(env, T0 + 30 * MINUTE)).toBe(true)
    expect(binding.reads).toHaveLength(2)
  })

  it("gives up on a read that outlasts its timeout, and logs it once", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] })
    const { fetcher } = releasesWeb(() => new Promise<Response>(() => undefined))
    const env = vaultEnv({ floor: "0.3.1", web: fetcher })
    const refresh = refreshPublishedRelease(env, T0, testKeys)
    expect(refresh).not.toBeNull()
    await vi.advanceTimersByTimeAsync(PUBLISHED_RELEASE_TIMEOUT_MS)
    await refresh
    expect(recommendedCliVersion(env, T0)).toBe("0.3.1")
    expect(logged()).toEqual([JSON.stringify({ at: "published_release", reason: "timeout" })])
  })

  it("is read at most every five minutes, keeps the last good release for an hour of failed reads, then falls back to the floor", async () => {
    const { binding, fetcher } = releasesWeb(json(RELEASE_0_3_9))
    const env = vaultEnv({ floor: "0.3.1", web: fetcher })
    expect(await readAt(env, T0)).toBe(true)
    expect(recommendedCliVersion(env, T0)).toBe("0.3.9")
    binding.served = () => new Response("unavailable", { status: 503 })
    expect(await readAt(env, T0 + 5 * MINUTE - 1)).toBe(false)
    for (let minutes = 5; minutes < 60; minutes += 5) {
      expect(await readAt(env, T0 + minutes * MINUTE)).toBe(true)
      expect(recommendedCliVersion(env, T0 + minutes * MINUTE), `${minutes} min`).toBe("0.3.9")
    }
    expect(binding.reads).toHaveLength(12)
    expect(logged()).toHaveLength(11)
    expect(recommendedCliVersion(env, T0 + 60 * MINUTE - 1)).toBe("0.3.9")
    expect(recommendedCliVersion(env, T0 + 60 * MINUTE)).toBe("0.3.1")
    binding.served = json(RELEASE_0_3_9)
    await readAt(env, T0 + 60 * MINUTE)
    expect(recommendedCliVersion(env, T0 + 60 * MINUTE)).toBe("0.3.9")
  })

  it("goes down within one refresh when a pause repoints latest.json at the previous signed release, never below the floor", async () => {
    for (const [floor, paused] of [["0.3.1", "0.3.8"], ["0.3.9", "0.3.9"]] as const) {
      resetPublishedReleaseForTest()
      const { binding, fetcher } = releasesWeb(json(RELEASE_0_3_9))
      const env = vaultEnv({ floor, web: fetcher })
      await readAt(env, T0)
      expect(recommendedCliVersion(env, T0)).toBe("0.3.9")
      binding.served = json(RELEASE_0_3_8)
      await readAt(env, T0 + MINUTE)
      expect(recommendedCliVersion(env, T0 + MINUTE)).toBe("0.3.9")
      await readAt(env, T0 + 5 * MINUTE)
      expect(recommendedCliVersion(env, T0 + 5 * MINUTE), floor).toBe(paused)
    }
    expect(logged()).toEqual([])
  })
})

describe("the deploy's configuration", () => {
  it("binds the mehen-web Worker in production only, and no release bucket", () => {
    const config = Object.values(import.meta.glob<string>("../wrangler.jsonc", { query: "?raw", import: "default", eager: true }))[0]!
    expect(config.match(/"services": .*/g)).toEqual(['"services": [{ "binding": "RELEASES_WEB", "service": "mehen-web" }],'])
    expect(config.indexOf('"services"')).toBeLessThan(config.indexOf('"env"'))
    expect(config).not.toContain("mehen-releases")
    expect(baseEnv.RELEASES_WEB).toBeUndefined()
  })
})
