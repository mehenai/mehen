import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test"
import { ERROR_HEADER, FORWARDED_HEADER, UPSTREAM_HEADER } from "@mehen/protocol/api"
import { type ProofSigner, parseProof } from "@mehen/protocol/proof"
import { readConfig } from "./config.ts"
import { DEFAULT_NEXT, OUTCOME_UNKNOWN_SAY, errorBody, toCliError } from "./errors.ts"
import { loadDeviceKey } from "./device-key.ts"
import { HttpVaultApi } from "./http-client.ts"
import { MOCK_TENANT, MockVault, vaultError } from "./testing/mock-vault.ts"
import { tempDir } from "./testing/run-mehen.ts"
import { RelayOutcomeUnknownError, RelayUnmarkedAnswerError, VaultApiError, VaultNetworkError } from "./vault-api.ts"

let vault: MockVault
let dir: { path: string; remove(): Promise<void> }

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
afterEach(async () => {
  vault.overrides.clear()
  await dir?.remove()
})

async function enrolledSigner(): Promise<ProofSigner> {
  dir = await tempDir()
  const device = await vault.enrolSoftware(dir.path)
  const slot = vault.slotDir(dir.path)
  const config = await readConfig(slot)
  const key = await loadDeviceKey(slot, config?.backend ?? "software", {})
  return key.signer(device)
}

async function client(options: { fetch?: (request: Request) => Promise<Response>; session?: string } = {}): Promise<HttpVaultApi> {
  return new HttpVaultApi({ vaultUrl: vault.url, tenant: MOCK_TENANT, signer: await enrolledSigner(), ...options })
}

describe("HttpVaultApi signing", () => {
  test("signs every request so the vault's proof check passes, with the session label", async () => {
    const api = await client({ session: "agent-1" })
    const me = await api.request<{ device: string }>("GET", "/v1/me")
    expect(me.device).toStartWith("dev_")
    await api.request("POST", "/v1/intakes", { kind: "api-key", slug: "new-key", reason: "testing" })
    const last = vault.seen.at(-1)
    expect(last?.claims.ten).toBe(MOCK_TENANT)
    expect(last?.claims.sid).toBe("agent-1")
    expect(last?.claims.htm).toBe("POST")
  })

  // mehen fill opens a box sealed under the jti of the proof its answer
  // came back to; send makes exactly one proof per call and never retries.
  test("onProof hands the caller the jti of the one proof each request carried", async () => {
    const api = await client()
    const jtis: string[] = []
    await api.request("GET", "/v1/me", undefined, { onProof: (jti) => jtis.push(jti) })
    expect(jtis).toEqual([vault.seen.at(-1)?.claims.jti as string])
    let sent = 0
    const failing = await client({ fetch: async () => { sent += 1; throw new Error("connection reset") } })
    const failed: string[] = []
    await expect(failing.request("POST", "/v1/fill", { item: "x" }, { onProof: (jti) => failed.push(jti) })).rejects.toBeInstanceOf(VaultNetworkError)
    expect({ sent, proofs: failed.length }).toEqual({ sent: 1, proofs: 1 })
  })

  test("a body changed after signing is refused", async () => {
    const api = await client({
      fetch: async (request) => {
        const headers = new Headers(request.headers)
        return fetch(new Request(request.url, { method: request.method, headers, body: '{"kind":"api-key","slug":"other","reason":"x"}' }))
      },
    })
    const error = await api.request("POST", "/v1/intakes", { kind: "api-key", slug: "new-key", reason: "testing" }).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(VaultApiError)
    expect((error as VaultApiError).body.error).toBe("proof_invalid")
    expect((error as VaultApiError).message).toContain("body")
  })

  test("a URL changed after signing is refused", async () => {
    const api = await client({
      fetch: async (request) => fetch(new Request(request.url.replace("/v1/items", "/v1/items?tag=ai"), { method: request.method, headers: request.headers })),
    })
    const error = await api.request("GET", "/v1/items").catch((e: unknown) => e)
    expect((error as VaultApiError).body.error).toBe("proof_invalid")
    expect((error as VaultApiError).message).toContain("url")
  })

  test("a replayed proof is refused", async () => {
    let captured: Request | null = null
    const api = await client({
      fetch: async (request) => {
        captured = request.clone()
        return fetch(request)
      },
    })
    await api.request("GET", "/v1/me")
    const replay = await fetch(captured as unknown as Request)
    expect(replay.status).toBe(401)
    expect(((await replay.json()) as { error: string }).error).toBe("proof_invalid")
  })

  test("the proof carries the method, the full URL and the body hash", async () => {
    let proof = ""
    const api = await client({
      fetch: async (request) => {
        proof = request.headers.get("Mehen-Proof") ?? ""
        return fetch(request)
      },
    })
    await api.request("GET", "/v1/items?kind=api-key")
    const { claims } = parseProof(proof)
    expect(claims.htu).toBe(`${vault.url}/v1/items?kind=api-key`)
    expect(claims.htm).toBe("GET")
  })
})

describe("HttpVaultApi errors", () => {
  test("a Mehen-Error body becomes VaultApiError with next", async () => {
    const api = await client()
    const error = await api.request("GET", "/v1/items/missing-item").catch((e: unknown) => e)
    expect(error).toBeInstanceOf(VaultApiError)
    const body = (error as VaultApiError).body
    expect(body).toEqual({ error: "not_found", message: "No item missing-item.", next: { command: "mehen ls", say: "List the items." } })
    expect((error as VaultApiError).status).toBe(404)
  })

  test("a string expiresAt on an error is kept, so an ask synthesised from it carries the expiry; other shapes are dropped", async () => {
    const api = await client()
    vault.overrides.set("GET /v1/me", () =>
      vaultError("approval_required", "Needs approval.", { next: { url: "https://vault.example/a/apr_1", say: "x" }, approval: "apr_1", bindingCode: "K7", ...({ expiresAt: "2026-10-24T17:00:00.000Z" } as object) }),
    )
    const kept = (await api.request("GET", "/v1/me").catch((e: unknown) => e)) as VaultApiError
    expect(kept.body).toEqual({
      error: "approval_required",
      message: "Needs approval.",
      next: { url: "https://vault.example/a/apr_1", say: "x" },
      approval: "apr_1",
      bindingCode: "K7",
      expiresAt: "2026-10-24T17:00:00.000Z",
    } as typeof kept.body)
    vault.overrides.set("GET /v1/me", () => vaultError("approval_required", "Needs approval.", { approval: "apr_1", ...({ expiresAt: 12345 } as object) }))
    const dropped = (await api.request("GET", "/v1/me").catch((e: unknown) => e)) as VaultApiError
    expect(dropped.body).not.toHaveProperty("expiresAt")
  })

  test("approval_required keeps deciders, a list of names, through to the CLI error; other shapes and codes drop it", async () => {
    const api = await client()
    vault.overrides.set("GET /v1/me", () => vaultError("approval_required", "Needs approval.", { approval: "apr_1", deciders: ["Alex", "Sam"] }))
    const kept = (await api.request("GET", "/v1/me").catch((e: unknown) => e)) as VaultApiError
    expect(kept.body.deciders).toEqual(["Alex", "Sam"])
    expect(errorBody(toCliError(kept))).toMatchObject({ error: "approval_required", deciders: ["Alex", "Sam"] })
    for (const [code, deciders] of [["approval_required", [1]], ["approval_required", "Alex"], ["forbidden", ["Alex"]]] as const) {
      vault.overrides.set("GET /v1/me", () => vaultError(code, "No.", { deciders } as unknown as object))
      const dropped = (await api.request("GET", "/v1/me").catch((e: unknown) => e)) as VaultApiError
      expect(dropped.body).not.toHaveProperty("deciders")
      expect(errorBody(toCliError(dropped))).not.toHaveProperty("deciders")
    }
  })

  test("a terminal renew refusal keeps its settled enrolment, the full active answer included; malformed ones are dropped", async () => {
    const api = await client()
    const workspace = { id: "tn_work0001", slug: "northwind", name: "Northwind" }
    const active = { status: "active" as const, tenant: workspace.id, workspace, device: "dev_new0001", scope: { tags: [], projects: [], maxEnvironment: "unprotected" as const, modes: ["relay" as const], privateCredentials: false }, owner: { kind: "member" as const, member: "mem_alex01", name: "Alex" } }
    const conflict = (extra: object) => Response.json({ error: "conflict", message: "This enrolment is settled.", ...extra }, { status: 409, headers: { [ERROR_HEADER]: "1" } })
    // `expired` without a reason is a pre-0008 vault's answer, kept for the
    // poll reader's tolerance.
    const settled: unknown[] = [active, { status: "expired" as const, reason: "superseded" as const }, { status: "expired" as const }, { status: "rejected" as const }, { status: "pending_admission" as const, expiresAt: "2026-10-24T17:00:00.000Z", hardExpiresAt: "2026-10-25T16:00:00.000Z" }]
    for (const enrolment of settled) {
      vault.overrides.set("GET /v1/me", () => conflict({ enrolment }))
      const kept = (await api.request("GET", "/v1/me").catch((e: unknown) => e)) as VaultApiError
      expect(kept.status).toBe(409)
      expect(kept.body as unknown).toEqual({ error: "conflict", message: "This enrolment is settled.", enrolment })
    }
    const malformed: unknown[] = ["active", { status: "done" }, { status: "expired", reason: "stale" }, { status: "active", tenant: workspace.id }, { status: "pending_owner_acceptance" }, { ...active, device: 7 }]
    for (const enrolment of malformed) {
      vault.overrides.set("GET /v1/me", () => conflict({ enrolment }))
      const dropped = (await api.request("GET", "/v1/me").catch((e: unknown) => e)) as VaultApiError
      expect(dropped.body).not.toHaveProperty("enrolment")
    }
    vault.overrides.set("GET /v1/me", () => Response.json({ error: "conflict", message: "Renewed a moment ago.", retryAfter: 60 }, { status: 409, headers: { [ERROR_HEADER]: "1" } }))
    const early = (await api.request("GET", "/v1/me").catch((e: unknown) => e)) as VaultApiError
    expect(early.body).toEqual({ error: "conflict", message: "Renewed a moment ago.", retryAfter: 60 })
  })

  test("an unknown error code or a non-JSON error is reported as internal", async () => {
    const api = await client()
    vault.overrides.set("GET /v1/me", () => new Response("<html>bad gateway</html>", { status: 502 }))
    const error = (await api.request("GET", "/v1/me").catch((e: unknown) => e)) as VaultApiError
    expect(error.body.error).toBe("internal")
    expect(error.status).toBe(502)
  })

  test("an unreachable vault is a VaultNetworkError", async () => {
    const offline = new HttpVaultApi({ vaultUrl: "http://127.0.0.1:1", tenant: MOCK_TENANT, signer: await enrolledSigner() })
    const error = await offline.request("GET", "/v1/me").catch((e: unknown) => e)
    expect(error).toBeInstanceOf(VaultNetworkError)
  })

  test("aborting a request rejects with the abort, not a network error", async () => {
    const api = await client()
    vault.overrides.set("GET /v1/me", () => new Promise<Response>((resolve) => setTimeout(() => resolve(Response.json({})), 2000)))
    const error = await api.request("GET", "/v1/me", undefined, { signal: AbortSignal.timeout(50) }).catch((e: unknown) => e)
    expect(error).not.toBeInstanceOf(VaultNetworkError)
    expect((error as Error).name).toBe("TimeoutError")
  })
})

describe("HttpVaultApi relay", () => {
  // A write relayed over a connection that broke may have gone upstream; a
  // read, or a connection never made, did not do anything twice.
  test("a broken connection is RelayOutcomeUnknownError for a write only, and never when nothing connected", async () => {
    const reset = Object.assign(new Error("The socket connection was closed unexpectedly"), { code: "ECONNRESET" })
    const refused = Object.assign(new Error("Unable to connect"), { code: "ConnectionRefused" })
    const signer = await enrolledSigner()
    const relay = (failure: Error, method: string) => new HttpVaultApi({ vaultUrl: vault.url, tenant: MOCK_TENANT, signer, fetch: async () => { throw failure } }).relay({ item: "gmail", method, url: "https://gmail.googleapis.com/x", headers: [] }).catch((e: unknown) => e)
    for (const method of ["POST", "PATCH", "PUT", "DELETE"]) expect(await relay(reset, method)).toBeInstanceOf(RelayOutcomeUnknownError)
    for (const method of ["GET", "HEAD"]) {
      const error = await relay(reset, method)
      expect(error).toBeInstanceOf(VaultNetworkError)
      expect(error).not.toBeInstanceOf(RelayOutcomeUnknownError)
    }
    expect(await relay(refused, "POST")).not.toBeInstanceOf(RelayOutcomeUnknownError)
  })

  test("upstream_failed keeps retry later for a read, and says to check before sending again for a write", async () => {
    const api = await client()
    vault.overrides.set("POST /v1/relay", () => vaultError("upstream_failed", "Could not get an answer from gmail.googleapis.com."))
    const failed = async (method: string) => errorBody(toCliError(await api.relay({ item: "gmail", method, url: "https://gmail.googleapis.com/x", headers: [] }).catch((e: unknown) => e)))
    const read = await failed("GET")
    expect(read.error).toBe("upstream_failed")
    expect(read.next?.say).toContain("retry later")
    const write = await failed("POST")
    expect(write.error).toBe("outcome_unknown")
    expect(write.message).toBe("Could not get an answer from gmail.googleapis.com.")
    expect(write.next?.say).toBe(OUTCOME_UNKNOWN_SAY)
  })

  test("a write is safe to send again only after a readable refusal marked as made before forwarding, and not the vault's own failure", async () => {
    const api = await client()
    const write = async () => toCliError(await api.relay({ item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x", headers: [] }).catch((e: unknown) => e))
    const answer = (status: number, headers: Record<string, string>, text: string) => vault.overrides.set("POST /v1/relay", () => new Response(text, { status, headers }))
    const refusal = JSON.stringify({ error: "approval_required", message: "Needs a human.", approval: "apr_1", next: { url: `${vault.url}/w/mock-space/a/apr_1`, say: "Ask." } })
    // Marked no and readable: the vault's own answer, which may be resent.
    answer(409, { [ERROR_HEADER]: "1", [FORWARDED_HEADER]: "no" }, refusal)
    expect((await write()).code).toBe("approval_required")
    const unknown: [string, number, Record<string, string>, string][] = [
      ["a refusal from a vault that does not mark them", 409, { [ERROR_HEADER]: "1" }, refusal],
      ["a refusal marked as after forwarding", 413, { [ERROR_HEADER]: "1", [FORWARDED_HEADER]: "yes" }, JSON.stringify({ error: "too_large", message: "The answer was too large." })],
      ["a marked refusal whose body cannot be read", 409, { [ERROR_HEADER]: "1", [FORWARDED_HEADER]: "no" }, "<html>"],
      ["a marked refusal with an unknown code", 409, { [ERROR_HEADER]: "1", [FORWARDED_HEADER]: "no" }, JSON.stringify({ error: "brand_new", message: "x" })],
      ["the vault's own failure, even marked", 500, { [ERROR_HEADER]: "1", [FORWARDED_HEADER]: "no" }, JSON.stringify({ error: "internal", message: "It broke." })],
      ...[408, 429, 499, 200].map((status): [string, number, Record<string, string>, string] => [`an unmarked ${status}`, status, {}, "from a proxy"]),
    ]
    for (const [name, status, headers, text] of unknown) {
      answer(status, headers, text)
      vault.relayForwarded = null
      const failed = await write().finally(() => { vault.relayForwarded = "no" })
      expect([failed.code, failed.next?.say], name).toEqual(["outcome_unknown", OUTCOME_UNKNOWN_SAY])
      expect(failed.extras, name).not.toHaveProperty("retryAfter")
    }
    // A read is judged as before: an unmarked answer is retryable.
    answer(429, {}, "from a proxy")
    const read = toCliError(await api.relay({ item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/x", headers: [] }).catch((e: unknown) => e))
    expect(read.code).toBe("internal")
  })

  test("a write's upstream_failed loses any retryAfter the vault sent, as its next says to check first", async () => {
    const api = await client()
    vault.overrides.set("POST /v1/relay", () => Response.json({ error: "upstream_failed", message: "Could not get an answer.", retryAfter: 5 }, { status: 502, headers: { [ERROR_HEADER]: "1" } }))
    const failed = async (method: string) => toCliError(await api.relay({ item: "gmail", method, url: "https://gmail.googleapis.com/x", headers: [] }).catch((e: unknown) => e))
    expect((await failed("POST")).extras.retryAfter).toBeUndefined()
    expect((await failed("GET")).extras.retryAfter).toBe(5)
  })

  test("returns the streamed upstream response", async () => {
    const api = await client()
    const response = await api.relay({ item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/models", headers: [] })
    expect(response.headers.get(UPSTREAM_HEADER)).toBe("1")
    expect(JSON.parse(await response.text())).toMatchObject({ method: "GET", url: "https://api.openai.com/v1/models" })
  })

  test("a body fetch already decoded loses Content-Encoding and Content-Length, so it is passed on as is", async () => {
    const api = await client()
    const plain = "hello world ".repeat(200)
    vault.overrides.set("POST /v1/relay", () =>
      new Response(Bun.gzipSync(new TextEncoder().encode(plain)), { headers: { [UPSTREAM_HEADER]: "1", "content-encoding": "gzip", "x-kept": "yes" } }),
    )
    const response = await api.relay({ item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/models", headers: [] })
    expect(response.headers.get("content-encoding")).toBeNull()
    expect(response.headers.get("content-length")).toBeNull()
    expect(response.headers.get("x-kept")).toBe("yes")
    expect(await response.text()).toBe(plain)
  })

  test("resolves while the upstream is still sending: the body streams", async () => {
    const api = await client()
    let finish: () => void = () => {}
    vault.overrides.set("POST /v1/relay", () => {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode("first"))
          finish = () => {
            controller.enqueue(new TextEncoder().encode(" second"))
            controller.close()
          }
        },
      })
      return new Response(stream, { headers: { [UPSTREAM_HEADER]: "1" } })
    })
    const response = await api.relay({ item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/models", headers: [] })
    const reader = (response.body as ReadableStream<Uint8Array>).getReader()
    const first = await reader.read()
    expect(new TextDecoder().decode(first.value)).toBe("first")
    finish()
    let rest = ""
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      rest += new TextDecoder().decode(value)
    }
    expect(rest).toBe(" second")
  })

  test("a Mehen-Error answer is a refusal even with a 2xx-looking shape", async () => {
    const api = await client()
    vault.overrides.set("POST /v1/relay", () =>
      Response.json({ error: "binding_refused", message: "evil.example is not in the binding." }, { status: 403, headers: { [ERROR_HEADER]: "1" } }),
    )
    const error = (await api.relay({ item: "openai-personal", method: "GET", url: "https://evil.example/", headers: [] }).catch((e: unknown) => e)) as VaultApiError
    expect(error.body.error).toBe("binding_refused")
  })

  test("an answer with neither Mehen-Upstream nor Mehen-Error is not passed off as the upstream's, and is RelayUnmarkedAnswerError with its status", async () => {
    const api = await client()
    vault.overrides.set("POST /v1/relay", () => new Response("hello", { status: 200 }))
    const error = (await api.relay({ item: "openai-personal", method: "GET", url: "https://api.openai.com/", headers: [] }).catch((e: unknown) => e)) as VaultApiError
    expect(error).toBeInstanceOf(VaultApiError)
    expect(error.body.error).toBe("internal")
    vault.overrides.set("POST /v1/relay", () => new Response("Bad Gateway", { status: 502 }))
    const proxied = await api.relay({ item: "openai-personal", method: "GET", url: "https://api.openai.com/", headers: [] }).catch((e: unknown) => e)
    expect(proxied).toBeInstanceOf(RelayUnmarkedAnswerError)
    expect((proxied as RelayUnmarkedAnswerError).status).toBe(502)
  })

  test("an unmarked 502 or 504 after a write is outcome unknown, never internal with retry advice; after a read it stays retryable", async () => {
    const api = await client()
    for (const status of [502, 504]) {
      vault.overrides.set("POST /v1/relay", () => new Response("Gateway", { status }))
      const write = await api.relay({ item: "openai-personal", method: "POST", url: "https://api.openai.com/", headers: [] }).catch((e: unknown) => e)
      expect(write).toBeInstanceOf(RelayOutcomeUnknownError)
      const cli = toCliError(write)
      expect([cli.code, cli.next?.say]).toEqual(["outcome_unknown", OUTCOME_UNKNOWN_SAY])
      const read = toCliError(await api.relay({ item: "openai-personal", method: "GET", url: "https://api.openai.com/", headers: [] }).catch((e: unknown) => e))
      expect([read.code, read.next?.say]).toEqual(["internal", DEFAULT_NEXT.internal.say])
    }
  })
})

// The version seam's client half.
describe("the CLI's version and the vault's advice", () => {
  test("every /v1 request names mehen and its version in the User-Agent", async () => {
    const { USER_AGENT } = await import("./http-client.ts")
    const { VERSION } = await import("./version.ts")
    expect(USER_AGENT).toBe(`mehen/${VERSION} (${process.platform}-${process.arch}; source)`)
    const api = await client()
    const before = vault.userAgents.length
    await api.request("GET", "/v1/me")
    await api.request("GET", "/v1/items").catch(() => {})
    expect(vault.userAgents.slice(before)).toEqual([USER_AGENT, USER_AGENT])
  })

  test("Mehen-Cli is parsed strictly and reported once per distinct advice and origin, refusals included", async () => {
    const { flushCliAdvice, parseCliAdvice, setCliAdviceSink } = await import("./http-client.ts")
    expect(parseCliAdvice("minimum=0.2.0; recommended=0.3.0")).toEqual({ minimum: "0.2.0", recommended: "0.3.0" })
    expect(parseCliAdvice("minimum=0.2.0")).toEqual({ minimum: "0.2.0", recommended: null })
    for (const bad of [null, "", "recommended=0.3.0", "minimum=latest", "minimum=0.2.0; recommended=<b>", "minimum=0.2"]) expect(parseCliAdvice(bad)).toBeNull()
    const seen: [string, unknown][] = []
    setCliAdviceSink((origin, advice) => { seen.push([origin, advice]) })
    try {
      const api = await client()
      vault.cliAdvice = "minimum=0.2.0; recommended=0.3.0"
      await api.request("GET", "/v1/me")
      await api.request("GET", "/v1/me")
      vault.cliAdvice = "minimum=0.3.0; recommended=0.3.0"
      vault.cliMinimum = "9.0.0"
      await expect(api.request("GET", "/v1/me")).rejects.toMatchObject({ status: 426, body: { error: "cli_outdated", next: { command: "mehen update --json" } } })
      await flushCliAdvice()
      expect(seen).toEqual([[vault.url, { minimum: "0.2.0", recommended: "0.3.0" }], [vault.url, { minimum: "0.3.0", recommended: "0.3.0" }]])
      expect(vault.outdated).toContain("GET /v1/me")
    } finally {
      setCliAdviceSink(null)
      vault.cliAdvice = null
      vault.cliMinimum = null
    }
  })
})
