// The push adapters against a fake provider behind setUpstreamFetch: the
// exact URLs, headers and bodies each provider's reference gives, the
// mapping of each answer to a vault error (push-providers design 2.6), the
// one retry when GitHub's key changes, and no value or token in any error.

import { afterEach, describe, expect, it } from "vitest"
import { x25519 } from "@noble/curves/ed25519.js"
import { type PushDestination, parsePushDestination } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { type PushCall, type PushValue, type PushVia, pushCalls, pushPreview, pushWrite } from "../src/push/adapters.ts"
import { MAX_PROVIDER_MESSAGE, MAX_PUSH_ANSWER_BYTES } from "../src/push/common.ts"
import { base64Decode, base64Encode } from "../src/push/sealed-box.ts"
import { sealOpen } from "./sealed-box-open.ts"

const VALUE: PushValue = { label: "openai-prod", value: "sk-proj-SECRETVALUE-0123456789abcdef" }
const TOKEN = "ghp_TOKENVALUE0123456789abcdefABCDEF"
const VIA: PushVia = { slug: "github-pat-ci", headers: [["authorization", `Bearer ${TOKEN}`]], scrub: [{ label: "github-pat-ci", value: TOKEN }] }
const ALLOW_ALL = () => true

type Seen = { method: string; url: string; headers: Record<string, string>; redirect: string; body: string | null }
// `raw` is sent as it is, in place of `body` as JSON.
type Reply = { status: number; body?: unknown; raw?: string; headers?: Record<string, string> } | "network"

// A provider that answers each request with the next reply, recording what
// it was sent.
function provider(...replies: Reply[]): Seen[] {
  const seen: Seen[] = []
  setUpstreamFetch(async (request) => {
    seen.push({ method: request.method, url: request.url, headers: Object.fromEntries(request.headers), redirect: request.redirect, body: request.body === null ? null : await request.text() })
    const reply = replies.shift()
    if (reply === undefined) throw new Error(`unexpected request ${request.method} ${request.url}`)
    if (reply === "network") throw new TypeError("network down")
    const body = reply.raw ?? (reply.body === undefined || reply.status === 204 ? null : JSON.stringify(reply.body))
    return new Response(body, { status: reply.status, headers: { "content-type": "application/json", ...reply.headers } })
  })
  return seen
}

afterEach(() => setUpstreamFetch(null))

function destination(text: string): PushDestination {
  const d = parsePushDestination(text)
  if (d === null) throw new Error(`bad destination ${text}`)
  return d
}

async function refusal(promise: Promise<unknown>): Promise<VaultError> {
  try {
    await promise
  } catch (error) {
    if (error instanceof VaultError) return error
    throw error
  }
  throw new Error("expected a vault error")
}

const b64 = (text: string) => btoa(text)
const b64url = (text: string) => btoa(text).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "")

// No value or token in any form the scrubber knows, anywhere in the error.
function expectClean(error: VaultError): void {
  const text = JSON.stringify(error.toJSON())
  for (const secret of [VALUE.value, TOKEN]) for (const form of [secret, b64(secret).replace(/=+$/, ""), b64url(secret)]) expect(text).not.toContain(form)
}

function gitHubKey() {
  const secretKey = x25519.utils.randomSecretKey()
  const publicKey = x25519.getPublicKey(secretKey)
  return { secretKey, publicKey, base64: base64Encode(publicKey) }
}

function opened(body: string | null, key: { secretKey: Uint8Array; publicKey: Uint8Array }): string {
  const sealed = base64Decode((JSON.parse(body!) as { encrypted_value: string }).encrypted_value)!
  return new TextDecoder().decode(sealOpen(sealed, key.publicKey, key.secretKey))
}

const GITHUB_HEADERS = { accept: "application/vnd.github+json", "x-github-api-version": "2026-03-10", authorization: `Bearer ${TOKEN}` }

describe("pushCalls: every URL a push may call, from the canonical destination only", () => {
  it("names each provider's preview reads and writes exactly", () => {
    const urls = (calls: PushCall[]) => calls.map((c) => `${c.method} ${c.url}`)
    const github = pushCalls(destination("github:Example/Mehen/openai_api_key"))
    expect(urls(github.preview)).toEqual(["GET https://api.github.com/repos/example/mehen", "GET https://api.github.com/repos/example/mehen/actions/secrets/OPENAI_API_KEY"])
    expect(urls(github.write)).toEqual(["GET https://api.github.com/repos/example/mehen/actions/secrets/public-key", "PUT https://api.github.com/repos/example/mehen/actions/secrets/OPENAI_API_KEY"])
    const environment = pushCalls(destination("github:o/r/env/Production.EU/KEY"))
    expect(urls(environment.preview)).toEqual(["GET https://api.github.com/repos/o/r", "GET https://api.github.com/repos/o/r/environments/production.eu", "GET https://api.github.com/repos/o/r/environments/production.eu/secrets/KEY"])
    expect(urls(environment.write)).toEqual(["GET https://api.github.com/repos/o/r/environments/production.eu/secrets/public-key", "PUT https://api.github.com/repos/o/r/environments/production.eu/secrets/KEY"])
    const dependabot = pushCalls(destination("github:o/r/dependabot/NPM_TOKEN"))
    expect(urls(dependabot.write)).toEqual(["GET https://api.github.com/repos/o/r/dependabot/secrets/public-key", "PUT https://api.github.com/repos/o/r/dependabot/secrets/NPM_TOKEN"])
    expect(urls(dependabot.preview)).toContain("GET https://api.github.com/repos/o/r/dependabot/secrets/NPM_TOKEN")

    expect(urls(pushCalls(destination("vercel:web/production/KEY")).preview)).toEqual(["GET https://api.vercel.com/v9/projects/web"])
    expect(urls(pushCalls(destination("vercel:web/production/KEY")).write)).toEqual(["POST https://api.vercel.com/v10/projects/web/env?upsert=true"])
    expect(urls(pushCalls(destination("vercel:prj_AbC123@team_XyZ789/preview/KEY")).preview)).toEqual(["GET https://api.vercel.com/v9/projects/prj_AbC123?teamId=team_XyZ789"])
    expect(urls(pushCalls(destination("vercel:web@acme/preview/KEY")).write)).toEqual(["POST https://api.vercel.com/v10/projects/web/env?upsert=true&slug=acme"])

    const account = "0123456789abcdef0123456789abcdef"
    const cloudflare = pushCalls(destination(`cloudflare:${account}/my-worker/KEY`))
    expect(urls(cloudflare.preview)).toEqual([`GET https://api.cloudflare.com/client/v4/accounts/${account}`, `GET https://api.cloudflare.com/client/v4/accounts/${account}/workers/scripts/my-worker/secrets`])
    expect(urls(cloudflare.write)).toEqual([`PUT https://api.cloudflare.com/client/v4/accounts/${account}/workers/scripts/my-worker/secrets`])

    const fly = pushCalls(destination("fly:my-app/DATABASE_URL"))
    expect(urls(fly.preview)).toEqual(["GET https://api.machines.dev/v1/apps/my-app", "GET https://api.machines.dev/v1/apps/my-app/secrets"])
    expect(urls(fly.write)).toEqual(["POST https://api.machines.dev/v1/apps/my-app/secrets/DATABASE_URL"])
  })
})

describe("GitHub", () => {
  it("seals the value to the store's public key and puts it with the key id: 201 is created, 204 replaced", async () => {
    const key = gitHubKey()
    const seen = provider({ status: 200, body: { key_id: "kid-1", key: key.base64 } }, { status: 201, body: {} })
    expect(await pushWrite(destination("github:o/r/KEY"), VALUE, VIA)).toEqual({ outcome: "created", providerStatus: 201 })
    expect(seen.map((s) => `${s.method} ${s.url}`)).toEqual(["GET https://api.github.com/repos/o/r/actions/secrets/public-key", "PUT https://api.github.com/repos/o/r/actions/secrets/KEY"])
    for (const s of seen) {
      expect(s.headers).toMatchObject(GITHUB_HEADERS)
      expect(s.redirect).toBe("manual")
    }
    expect(seen[0]!.body).toBeNull()
    expect(seen[1]!.headers["content-type"]).toBe("application/json")
    expect(Object.keys(JSON.parse(seen[1]!.body!) as object).sort()).toEqual(["encrypted_value", "key_id"])
    expect((JSON.parse(seen[1]!.body!) as { key_id: string }).key_id).toBe("kid-1")
    expect(seen[1]!.body).not.toContain(VALUE.value)
    expect(opened(seen[1]!.body, key)).toBe(VALUE.value)

    provider({ status: 200, body: { key_id: "kid-1", key: key.base64 } }, { status: 204 })
    expect(await pushWrite(destination("github:o/r/dependabot/KEY"), VALUE, VIA)).toEqual({ outcome: "replaced", providerStatus: 204 })
  })

  it("re-seals and retries once when the key changed between the read and the put", async () => {
    const first = gitHubKey()
    const second = gitHubKey()
    const seen = provider({ status: 200, body: { key_id: "kid-1", key: first.base64 } }, { status: 422, body: { message: "Bad key" } }, { status: 200, body: { key_id: "kid-2", key: second.base64 } }, { status: 204 })
    expect(await pushWrite(destination("github:o/r/env/prod/KEY"), VALUE, VIA)).toEqual({ outcome: "replaced", providerStatus: 204 })
    expect(seen.map((s) => s.method)).toEqual(["GET", "PUT", "GET", "PUT"])
    expect((JSON.parse(seen[3]!.body!) as { key_id: string }).key_id).toBe("kid-2")
    expect(opened(seen[3]!.body, second)).toBe(VALUE.value)

    // A second 422 after the retry is a refusal, with no third put.
    const again = provider({ status: 200, body: { key_id: "kid-1", key: first.base64 } }, { status: 422, body: { message: "Bad key" } }, { status: 200, body: { key_id: "kid-2", key: second.base64 } }, { status: 422, body: { message: "Still bad" } })
    const error = await refusal(pushWrite(destination("github:o/r/KEY"), VALUE, VIA))
    expect(error.toJSON()).toEqual({ error: "provider_refused", message: "GitHub refused it (422): Still bad", providerStatus: 422 })
    expect(again).toHaveLength(4)

    // The same key after a 422 is no key change: no retry.
    const same = provider({ status: 200, body: { key_id: "kid-1", key: first.base64 } }, { status: 422, body: { message: "Name is reserved" } }, { status: 200, body: { key_id: "kid-1", key: first.base64 } })
    expect((await refusal(pushWrite(destination("github:o/r/KEY"), VALUE, VIA))).toJSON()).toMatchObject({ error: "provider_refused", providerStatus: 422 })
    expect(same.map((s) => s.method)).toEqual(["GET", "PUT", "GET"])
  })

  it("maps each answer to the vault's refusal, on the key read and on the put", async () => {
    const key = gitHubKey()
    const cases: { reply: Reply; json: Record<string, unknown> }[] = [
      { reply: { status: 401, body: { message: "Bad credentials" } }, json: { error: "provider_refused", message: "GitHub refused github-pat-ci: the token is invalid or expired.", providerStatus: 401 } },
      { reply: { status: 403, body: { message: "Resource not accessible" } }, json: { error: "provider_refused", message: "github-pat-ci may not write secrets in o/r.", providerStatus: 403 } },
      { reply: { status: 403, body: { message: "API rate limit exceeded" }, headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": String(Math.floor(Date.now() / 1000) + 120) } }, json: { error: "rate_limited" } },
      { reply: { status: 403, body: { message: "secondary rate limit" }, headers: { "retry-after": "45" } }, json: { error: "rate_limited", message: "GitHub is limiting requests; ask again after 45 seconds.", retryAfter: 45 } },
      { reply: { status: 429, body: {}, headers: { "retry-after": "30" } }, json: { error: "rate_limited", retryAfter: 30 } },
      { reply: { status: 404, body: { message: "Not Found" } }, json: { error: "provider_refused", message: "GitHub says o/r does not exist, or github-pat-ci cannot see it.", providerStatus: 404 } },
      { reply: { status: 301, body: {}, headers: { location: "https://api.github.com/repositories/1" } }, json: { error: "provider_refused", providerStatus: 301 } },
      { reply: { status: 502, body: {} }, json: { error: "upstream_failed", message: "GitHub did not answer (502); nothing is known to have been written." } },
      { reply: "network", json: { error: "upstream_failed", message: "GitHub did not answer; nothing is known to have been written." } },
    ]
    for (const { reply, json } of cases) {
      provider(reply)
      const onKey = await refusal(pushWrite(destination("github:o/r/KEY"), VALUE, VIA))
      expect(onKey.toJSON(), `key read ${JSON.stringify(reply)}`).toMatchObject(json)
      provider({ status: 200, body: { key_id: "kid", key: key.base64 } }, reply)
      const onPut = await refusal(pushWrite(destination("github:o/r/KEY"), VALUE, VIA))
      expect(onPut.toJSON(), `put ${JSON.stringify(reply)}`).toMatchObject(json)
      expect(onPut.status).toBe({ provider_refused: 502, rate_limited: 429, upstream_failed: 502 }[json.error as string])
    }
    const limited = provider({ status: 403, body: {}, headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": String(Math.floor(Date.now() / 1000) + 120) } })
    const wait = (await refusal(pushWrite(destination("github:o/r/KEY"), VALUE, VIA))).toJSON().retryAfter!
    expect(wait).toBeGreaterThan(100)
    expect(wait).toBeLessThanOrEqual(120)
    expect(limited).toHaveLength(1)
  })

  it("refuses a key GitHub gives that is not a usable 32-byte key, before any put", async () => {
    for (const bad of [base64Encode(new Uint8Array(31)), base64Encode(new Uint8Array(32))]) {
      const seen = provider({ status: 200, body: { key_id: "kid", key: bad } })
      expect((await refusal(pushWrite(destination("github:o/r/KEY"), VALUE, VIA))).toJSON(), bad).toMatchObject({ error: "upstream_failed", message: "GitHub did not give a usable public key; nothing was written." })
      expect(seen).toHaveLength(1)
    }
    provider({ status: 200, body: { key: gitHubKey().base64 } })
    expect((await refusal(pushWrite(destination("github:o/r/KEY"), VALUE, VIA))).code).toBe("upstream_failed")
  })

  it("keeps GitHub's own words only for a 422, scrubbed of the value and the token and cut short", async () => {
    const key = gitHubKey()
    const echo = `Value ${VALUE.value} as ${b64(VALUE.value)} and ${b64url(VALUE.value)} with ${TOKEN} is refused`
    provider({ status: 200, body: { key_id: "kid", key: key.base64 } }, { status: 422, body: { message: echo } }, { status: 200, body: { key_id: "kid", key: key.base64 } })
    const error = await refusal(pushWrite(destination("github:o/r/KEY"), VALUE, VIA))
    expectClean(error)
    expect(error.message).toContain("[redacted:openai-prod]")
    expect(error.message).toContain("[redacted:github-pat-ci]")

    provider({ status: 200, body: { key_id: "kid", key: key.base64 } }, { status: 422, body: { message: "x".repeat(1000) } }, { status: 200, body: { key_id: "kid", key: key.base64 } })
    const long = await refusal(pushWrite(destination("github:o/r/KEY"), VALUE, VIA))
    expect(long.message.length).toBeLessThanOrEqual("GitHub refused it (422): ".length + MAX_PROVIDER_MESSAGE)

    // A value too short for the scrubber: none of GitHub's words are kept.
    const short: PushValue = { label: "pin", value: "w9Zq" }
    provider({ status: 200, body: { key_id: "kid", key: key.base64 } }, { status: 422, body: { message: `Value w9Zq is refused` } }, { status: 200, body: { key_id: "kid", key: key.base64 } })
    expect((await refusal(pushWrite(destination("github:o/r/KEY"), short, VIA))).toJSON()).toEqual({ error: "provider_refused", message: "GitHub refused it (422).", providerStatus: 422 })

    // Fixed words for a 401, 403 and 404: nothing of the body is kept.
    provider({ status: 403, body: { message: echo } })
    expectClean(await refusal(pushWrite(destination("github:o/r/KEY"), VALUE, VIA)))
  })

  it("previews the repository, the environment and the secret from the named fields only", async () => {
    const seen = provider(
      { status: 200, body: { full_name: "o/r", owner: { login: "Evil-Org", type: "Organization", id: 1 }, private: false, fork: true, parent: { full_name: "example/mehen", owner: { login: "example" } } } },
      { status: 200, body: { name: "prod" } },
      { status: 200, body: { name: "KEY", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-10-01T00:00:00Z" } },
    )
    expect(await pushPreview(destination("github:o/r/env/prod/KEY"), VIA, ALLOW_ALL)).toEqual({ provider: "github", owner: "Evil-Org", ownerType: "Organization", private: false, fork: true, parent: "example/mehen", exists: true, updatedAt: "2026-10-01T00:00:00Z" })
    expect(seen.map((s) => s.url)).toEqual(["https://api.github.com/repos/o/r", "https://api.github.com/repos/o/r/environments/prod", "https://api.github.com/repos/o/r/environments/prod/secrets/KEY"])
    for (const s of seen) {
      expect(s.headers).toMatchObject(GITHUB_HEADERS)
      expect(s.redirect).toBe("manual")
    }

    provider({ status: 200, body: { owner: { login: "o", type: "User" }, private: true, fork: false, parent: { full_name: "ignored/when-not-a-fork" } } }, { status: 404, body: { message: "Not Found" } })
    expect(await pushPreview(destination("github:o/r/KEY"), VIA, ALLOW_ALL)).toMatchObject({ owner: "o", ownerType: "User", private: true, fork: false, parent: null, exists: false, updatedAt: null })
  })

  it("makes only the reads the via's policy allows, and a read that fails leaves its fields unknown", async () => {
    const seen = provider({ status: 403, body: { message: "Forbidden" } })
    const onlyRepo = (call: PushCall) => call.url.endsWith("/repos/o/r")
    expect(await pushPreview(destination("github:o/r/KEY"), VIA, onlyRepo)).toEqual({ provider: "github", owner: null, ownerType: null, private: null, fork: null, parent: null, exists: null, updatedAt: null })
    expect(seen).toHaveLength(1)

    provider("network", { status: 500, body: {} })
    expect(await pushPreview(destination("github:o/r/KEY"), VIA, ALLOW_ALL)).toMatchObject({ owner: null, exists: null })

    const none = provider()
    expect(await pushPreview(destination("github:o/r/KEY"), VIA, () => false)).toMatchObject({ owner: null, exists: null })
    expect(none).toHaveLength(0)
  })

  it("refuses at preview when the repository or environment is missing, the token is refused, or GitHub is limiting", async () => {
    provider({ status: 404, body: { message: "Not Found" } })
    expect((await refusal(pushPreview(destination("github:o/r/KEY"), VIA, ALLOW_ALL))).toJSON()).toEqual({ error: "provider_refused", message: "GitHub says o/r does not exist, or github-pat-ci cannot see it.", providerStatus: 404 })
    provider({ status: 200, body: {} }, { status: 404, body: {} })
    expect((await refusal(pushPreview(destination("github:o/r/env/prod/KEY"), VIA, ALLOW_ALL))).toJSON()).toMatchObject({ error: "provider_refused", message: "GitHub says o/r environment prod does not exist, or github-pat-ci cannot see it.", providerStatus: 404 })
    provider({ status: 401, body: { message: "Bad credentials" } })
    expect((await refusal(pushPreview(destination("github:o/r/KEY"), VIA, ALLOW_ALL))).toJSON()).toMatchObject({ error: "provider_refused", providerStatus: 401 })
    provider({ status: 429, body: {}, headers: { "retry-after": "12" } })
    expect((await refusal(pushPreview(destination("github:o/r/KEY"), VIA, ALLOW_ALL))).toJSON()).toMatchObject({ error: "rate_limited", retryAfter: 12 })
  })
})

describe("Vercel", () => {
  const vercelVia: PushVia = { slug: "vercel-ci", headers: [["authorization", `Bearer ${TOKEN}`]], scrub: [{ label: "vercel-ci", value: TOKEN }] }

  it("upserts one sensitive variable for one target, scoped to the team", async () => {
    for (const target of ["production", "preview", "development"] as const) {
      const seen = provider({ status: 201, body: { created: { key: "KEY", value: VALUE.value }, failed: [] } })
      expect(await pushWrite(destination(`vercel:web@team_ABC123/${target}/KEY`), VALUE, vercelVia)).toEqual({ outcome: "set", providerStatus: 201 })
      expect(seen).toHaveLength(1)
      expect(seen[0]).toMatchObject({ method: "POST", url: "https://api.vercel.com/v10/projects/web/env?upsert=true&teamId=team_ABC123", redirect: "manual" })
      expect(seen[0]!.headers).toMatchObject({ authorization: `Bearer ${TOKEN}`, "content-type": "application/json" })
      expect(JSON.parse(seen[0]!.body!)).toEqual({ key: "KEY", value: VALUE.value, type: "sensitive", target: [target] })
    }
  })

  it("refuses a 201 that lists the variable under failed, and maps refusals, without the value", async () => {
    provider({ status: 201, body: { created: [], failed: [{ error: { code: "ENV_CONFLICT", message: `A variable with value ${VALUE.value} exists`, value: VALUE.value } }] } })
    const failed = await refusal(pushWrite(destination("vercel:web/production/KEY"), VALUE, vercelVia))
    expect(failed.toJSON()).toEqual({ error: "provider_refused", message: "Vercel did not write KEY: A variable with value [redacted:openai-prod] exists", providerStatus: 201 })
    expectClean(failed)

    provider({ status: 400, body: { error: { code: "bad_request", message: `Invalid request: ${TOKEN}` } } })
    const bad = await refusal(pushWrite(destination("vercel:web/production/KEY"), VALUE, vercelVia))
    expect(bad.toJSON()).toEqual({ error: "provider_refused", message: "Vercel refused it (400): Invalid request: [redacted:vercel-ci]", providerStatus: 400 })
    provider({ status: 403, body: { error: { message: "Not authorized" } } })
    expect((await refusal(pushWrite(destination("vercel:web/production/KEY"), VALUE, vercelVia))).toJSON()).toEqual({ error: "provider_refused", message: "vercel-ci may not write environment variables in project web.", providerStatus: 403 })
    provider({ status: 429, body: {}, headers: { "x-ratelimit-reset": String(Math.floor(Date.now() / 1000) + 30) } })
    expect((await refusal(pushWrite(destination("vercel:web/production/KEY"), VALUE, vercelVia))).code).toBe("rate_limited")
    provider({ status: 500, body: {} })
    expect((await refusal(pushWrite(destination("vercel:web/production/KEY"), VALUE, vercelVia))).code).toBe("upstream_failed")
  })

  it("calls a success whose answer cannot be read upstream_failed, since the variable may have been written", async () => {
    for (const reply of [{ status: 201, raw: "<html>ok</html>" }, { status: 201, raw: "x".repeat(MAX_PUSH_ANSWER_BYTES + 1) }, { status: 201 }, { status: 201, body: "ok" }] satisfies Reply[]) {
      provider(reply)
      const error = await refusal(pushWrite(destination("vercel:web/production/KEY"), VALUE, vercelVia))
      expect(error.toJSON(), JSON.stringify(reply).slice(0, 80)).toEqual({ error: "upstream_failed", message: "Vercel answered but Mehen could not read the answer; the variable may have been written. Check Vercel." })
    }
  })

  it("previews the project's id, name, account and linked repository, and refuses a missing project", async () => {
    const seen = provider({ status: 200, body: { id: "prj_1", name: "web", accountId: "team_ABC123", link: { type: "github", org: "example", repo: "mehen", repoOwnerId: 7 }, env: [{ key: "KEY", value: VALUE.value }] } })
    expect(await pushPreview(destination("vercel:web@acme/preview/KEY"), vercelVia, ALLOW_ALL)).toEqual({ provider: "vercel", projectId: "prj_1", projectName: "web", accountId: "team_ABC123", repo: "example/mehen", exists: null, updatedAt: null })
    expect(seen[0]).toMatchObject({ method: "GET", url: "https://api.vercel.com/v9/projects/web?slug=acme", redirect: "manual" })
    provider({ status: 404, body: { error: { code: "not_found", message: "Project not found" } } })
    expect((await refusal(pushPreview(destination("vercel:web/preview/KEY"), vercelVia, ALLOW_ALL))).toJSON()).toEqual({ error: "provider_refused", message: "Vercel says project web does not exist, or vercel-ci cannot see it.", providerStatus: 404 })
  })
})

describe("Cloudflare", () => {
  const account = "0123456789abcdef0123456789abcdef"
  const cloudflareVia: PushVia = { slug: "cf-workers", headers: [["authorization", `Bearer ${TOKEN}`]], scrub: [{ label: "cf-workers", value: TOKEN }] }

  it("puts the secret as secret_text on the Worker", async () => {
    const seen = provider({ status: 200, body: { success: true, errors: [], messages: [], result: { name: "KEY", type: "secret_text" } } })
    expect(await pushWrite(destination(`cloudflare:${account}/my-worker/KEY`), VALUE, cloudflareVia)).toEqual({ outcome: "set", providerStatus: 200 })
    expect(seen[0]).toMatchObject({ method: "PUT", url: `https://api.cloudflare.com/client/v4/accounts/${account}/workers/scripts/my-worker/secrets`, redirect: "manual" })
    expect(seen[0]!.headers).toMatchObject({ authorization: `Bearer ${TOKEN}`, "content-type": "application/json" })
    expect(JSON.parse(seen[0]!.body!)).toEqual({ name: "KEY", text: VALUE.value, type: "secret_text" })
  })

  it("refuses an answer that is not a success, and keeps Cloudflare's first error scrubbed", async () => {
    provider({ status: 200, body: { success: false, errors: [{ code: 10021, message: `bad ${VALUE.value}` }] } })
    const unsuccessful = await refusal(pushWrite(destination(`cloudflare:${account}/my-worker/KEY`), VALUE, cloudflareVia))
    expect(unsuccessful.toJSON()).toEqual({ error: "provider_refused", message: "Cloudflare did not write KEY: bad [redacted:openai-prod]", providerStatus: 200 })
    provider({ status: 400, body: { success: false, errors: [{ code: 10007, message: "workers.api.error.script_not_found" }] } })
    expect((await refusal(pushWrite(destination(`cloudflare:${account}/my-worker/KEY`), VALUE, cloudflareVia))).toJSON()).toEqual({ error: "provider_refused", message: "Cloudflare refused it (400): workers.api.error.script_not_found", providerStatus: 400 })
    provider({ status: 403, body: { success: false, errors: [{ code: 10000, message: "Authentication error" }] } })
    expect((await refusal(pushWrite(destination(`cloudflare:${account}/my-worker/KEY`), VALUE, cloudflareVia))).toJSON()).toEqual({ error: "provider_refused", message: "cf-workers may not write secrets in Worker my-worker.", providerStatus: 403 })
    provider({ status: 429, body: { success: false, errors: [] }, headers: { "retry-after": "5" } })
    expect((await refusal(pushWrite(destination(`cloudflare:${account}/my-worker/KEY`), VALUE, cloudflareVia))).toJSON()).toMatchObject({ error: "rate_limited", retryAfter: 5 })
  })

  it("calls a success whose answer cannot be read upstream_failed, since the secret may have been written", async () => {
    for (const reply of [{ status: 200, raw: "<html>ok</html>" }, { status: 200, raw: "x".repeat(MAX_PUSH_ANSWER_BYTES + 1) }, { status: 200 }, { status: 200, body: "ok" }] satisfies Reply[]) {
      provider(reply)
      const error = await refusal(pushWrite(destination(`cloudflare:${account}/my-worker/KEY`), VALUE, cloudflareVia))
      expect(error.toJSON(), JSON.stringify(reply).slice(0, 80)).toEqual({ error: "upstream_failed", message: "Cloudflare answered but Mehen could not read the answer; the secret may have been written. Check Cloudflare." })
    }
  })

  it("previews the account name and whether the secret exists; a token that cannot read the account refuses nothing", async () => {
    provider({ status: 200, body: { success: true, result: { id: account, name: "Acme" } } }, { status: 200, body: { success: true, result: [{ name: "OTHER", type: "secret_text" }, { name: "KEY", type: "secret_text" }] } })
    expect(await pushPreview(destination(`cloudflare:${account}/my-worker/KEY`), cloudflareVia, ALLOW_ALL)).toEqual({ provider: "cloudflare", accountName: "Acme", exists: true, updatedAt: null })
    provider({ status: 403, body: { success: false } }, { status: 200, body: { success: true, result: [] } })
    expect(await pushPreview(destination(`cloudflare:${account}/my-worker/KEY`), cloudflareVia, ALLOW_ALL)).toEqual({ provider: "cloudflare", accountName: null, exists: false, updatedAt: null })
    provider({ status: 404, body: { success: false } }, { status: 404, body: { success: false, errors: [{ code: 10007, message: "script not found" }] } })
    expect((await refusal(pushPreview(destination(`cloudflare:${account}/my-worker/KEY`), cloudflareVia, ALLOW_ALL))).toJSON()).toEqual({ error: "provider_refused", message: "Cloudflare says Worker my-worker does not exist, or cf-workers cannot see it.", providerStatus: 404 })
  })
})

describe("Fly", () => {
  const flyVia: PushVia = { slug: "fly-deploy", headers: [["authorization", `Bearer ${TOKEN}`]], scrub: [{ label: "fly-deploy", value: TOKEN }] }

  it("posts the value to the app's secret by name", async () => {
    const seen = provider({ status: 201, body: { name: "DATABASE_URL", value: VALUE.value, version: 4, digest: "d" } })
    expect(await pushWrite(destination("fly:my-app/DATABASE_URL"), VALUE, flyVia)).toEqual({ outcome: "set", providerStatus: 201 })
    expect(seen[0]).toMatchObject({ method: "POST", url: "https://api.machines.dev/v1/apps/my-app/secrets/DATABASE_URL", redirect: "manual" })
    expect(seen[0]!.headers).toMatchObject({ authorization: `Bearer ${TOKEN}`, "content-type": "application/json" })
    expect(JSON.parse(seen[0]!.body!)).toEqual({ value: VALUE.value })
  })

  it("maps refusals and scrubs Fly's error text, with no control or bidi character kept", async () => {
    provider({ status: 400, body: { error: `invalid secret ${VALUE.value}`, status: "unknown" } })
    const bad = await refusal(pushWrite(destination("fly:my-app/KEY"), VALUE, flyVia))
    expect(bad.toJSON()).toEqual({ error: "provider_refused", message: "Fly refused it (400): invalid secret [redacted:openai-prod]", providerStatus: 400 })
    provider({ status: 400, body: { error: "bad\u001b[31m name\u202eeman\u2066 \u0000x\ty\r\nz\u007f\u2069" } })
    expect((await refusal(pushWrite(destination("fly:my-app/KEY"), VALUE, flyVia))).message).toBe("Fly refused it (400): bad [31m nameeman x y z")
    provider({ status: 404, body: { error: "app not found" } })
    expect((await refusal(pushWrite(destination("fly:my-app/KEY"), VALUE, flyVia))).toJSON()).toEqual({ error: "provider_refused", message: "Fly says app my-app does not exist, or fly-deploy cannot see it.", providerStatus: 404 })
    provider({ status: 401, body: { error: "unauthorized" } })
    expect((await refusal(pushWrite(destination("fly:my-app/KEY"), VALUE, flyVia))).toJSON()).toEqual({ error: "provider_refused", message: "Fly refused fly-deploy: the token is invalid or expired.", providerStatus: 401 })
  })

  it("previews the organisation and whether the secret exists, reading names only", async () => {
    const seen = provider({ status: 200, body: { name: "my-app", organization: { slug: "acme", name: "Acme" } } }, { status: 200, body: { secrets: [{ name: "DATABASE_URL", value: VALUE.value, digest: "d" }] } })
    const preview = await pushPreview(destination("fly:my-app/DATABASE_URL"), flyVia, ALLOW_ALL)
    expect(preview).toEqual({ provider: "fly", organization: "acme", exists: true, updatedAt: null })
    expect(JSON.stringify(preview)).not.toContain(VALUE.value)
    expect(seen.map((s) => s.url)).toEqual(["https://api.machines.dev/v1/apps/my-app", "https://api.machines.dev/v1/apps/my-app/secrets"])
    provider({ status: 404, body: { error: "not found" } })
    expect((await refusal(pushPreview(destination("fly:my-app/KEY"), flyVia, ALLOW_ALL))).code).toBe("provider_refused")
  })
})
