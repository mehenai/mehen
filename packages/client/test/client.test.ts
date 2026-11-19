import { describe, expect, it } from "bun:test"
import { base64UrlDecode } from "@mehen/protocol/bytes"
import { ERROR_HEADER, RelayRequest, RunCreate } from "@mehen/protocol/api"
import { WorkloadCreateSchema } from "@mehen/protocol/workload"
import { type Fetcher, MehenRefusal, MehenTransport, type RelayInput, createClient, deviceSigner, generateKey, workloadSigner } from "../src/index.ts"
import { DEVICE, FakeVault, ORIGIN, TENANT, WORKLOAD, json, refuse, upstream } from "./fake-vault.ts"
import { PROJECT, RUN, meAnswer, projectAnswer, runCreated, workloadView } from "./fixtures.ts"

async function setup() {
  const vault = new FakeVault()
  const device = await generateKey()
  vault.devices.set(DEVICE, device.jwk)
  const client = createClient({ vaultUrl: ORIGIN, tenant: TENANT, signer: deviceSigner(DEVICE, device.privateKey), fetch: vault.fetch, session: "task-runner", userAgent: "example-host/2" })
  return { vault, device, client }
}

async function caught(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection")
    },
    (error: unknown) => error,
  )
}

const BINARY = new Uint8Array([0, 1, 2, 253, 254, 255, 0x89, 0x50, 0x4e, 0x47])

// A fetch as a runtime's: it reads the request and, as the Fetch standard's
// abort steps do, keeps the Request reachable from its signal for as long as
// that signal lives. The upstream's answer is `answer`, made elsewhere so no
// closure of its own reaches the request. Only WeakRefs record the requests.
function runtimeFetch(answer: ReadableStream<Uint8Array>): { fetch: Fetcher; requests: WeakRef<Request>[] } {
  const requests: WeakRef<Request>[] = []
  const fetch = async (request: Request): Promise<Response> => {
    requests.push(new WeakRef(request))
    await request.arrayBuffer()
    request.signal.addEventListener("abort", () => request.signal.reason, { once: true })
    return upstream(200, answer as unknown as Uint8Array<ArrayBuffer>)
  }
  return { fetch, requests }
}

// An 8 MiB body that only the relay and a WeakRef reach once this returns.
function withLargeBody<T>(relay: (input: RelayInput) => T): { body: WeakRef<Uint8Array>; answer: T } {
  const body = new Uint8Array(8 * 1024 * 1024).fill(0x2a)
  return { body: new WeakRef(body), answer: relay({ run: RUN, method: "POST", url: "https://api.openai.com/v1/files", body }) }
}

// A WeakRef's target lives to the end of the job that made or read it, so
// collect across a few turns of the event loop.
async function collectGarbage(): Promise<void> {
  for (let turn = 0; turn < 3; turn += 1) {
    Bun.gc(true)
    await Bun.sleep(1)
  }
}

describe("createClient", () => {
  it("reads me signed by the device key, with the client's user agent", async () => {
    const { vault, client } = await setup()
    vault.on("GET /v1/me", () => json(meAnswer({ added: "a field this client does not know" })))
    const me = await client.me()
    expect(me.device).toBe(DEVICE)
    expect(me.workspace.slug).toBe("acme")
    expect("added" in me).toBe(false)
    expect(vault.last.signedBy).toBe("device")
    expect(vault.last.claims).toMatchObject({ ten: TENANT, dev: DEVICE, sid: "task-runner" })
    expect(vault.last.claims.wkl).toBeUndefined()
    expect(vault.last.headers.get("user-agent")).toMatch(/^mehen-client\/\d+\.\d+\.\d+ example-host\/2$/)
    expect(vault.last.headers.get("accept")).toBe("application/json")
  })

  it("refuses a vault URL that is not https, has a path or carries userinfo", async () => {
    const signer = deviceSigner(DEVICE, (await generateKey()).privateKey)
    for (const vaultUrl of ["http://vault.example", "https://vault.example/v1", "https://a:b@vault.example", "not a url"]) {
      expect(() => createClient({ vaultUrl, tenant: TENANT, signer })).toThrow(TypeError)
    }
    expect(() => createClient({ vaultUrl: "http://localhost:8787", tenant: TENANT, signer })).not.toThrow()
    expect(() => createClient({ vaultUrl: ORIGIN, tenant: TENANT, signer, userAgent: "bad\nagent" })).toThrow(TypeError)
  })
})

describe("relay", () => {
  it("sends a binary body as base64url and answers the upstream's binary body intact", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/relay", (seen) => {
      const request = RelayRequest.parse(seen.json)
      expect(base64UrlDecode(request.body ?? "")).toEqual(BINARY)
      return upstream(200, BINARY, { "content-type": "image/png" })
    })
    const answer = await client.relay({ item: "openai", method: "post", url: "https://api.openai.com/v1/files", headers: [["content-type", "image/png"]], body: BINARY, context: { project: "prj_test0001", environment: "dev" } })
    expect(answer.kind).toBe("response")
    expect(answer.status).toBe(200)
    expect(answer.body).toEqual(BINARY)
    expect(answer.headers.get("content-type")).toBe("image/png")
    expect(answer.item).toBe("openai (alex@example.com)")
    expect(RelayRequest.parse(vault.last.json)).toEqual({ item: "openai", method: "POST", url: "https://api.openai.com/v1/files", headers: [["content-type", "image/png"]], body: expect.any(String), context: { project: "prj_test0001", environment: "dev" }, session: "task-runner" })
  })

  it("answers an upstream 500 as a response, not a refusal", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/relay", () => upstream(500, '{"error":"upstream broke"}', { "content-type": "application/json" }))
    const answer = await client.relay({ item: "openai", method: "GET", url: "https://api.openai.com/v1/models" })
    expect(answer.status).toBe(500)
    expect(new TextDecoder().decode(answer.body)).toBe('{"error":"upstream broke"}')
    expect(vault.last.json).not.toHaveProperty("body")
  })

  it("throws approval_required with the approval id, binding code, expiry, link and deciders", async () => {
    const { vault, client } = await setup()
    const link = `${ORIGIN}/w/acme/a/apr_approval0001`
    vault.on("POST /v1/relay", () => refuse("approval_required", "A person must approve this request.", { approval: "apr_approval0001", bindingCode: "RX-42", expiresAt: "2026-10-29T10:10:00.000Z", next: { url: link, command: "mehen wait apr_approval0001", say: "Ask Alex to approve it." }, deciders: ["Alex"] }))
    const error = await caught(client.relay({ item: "gmail", method: "POST", url: "https://gmail.googleapis.com/gmail/v1/users/me/messages/send", body: "{}" }))
    expect(error).toBeInstanceOf(MehenRefusal)
    const refusal = error as MehenRefusal
    expect(refusal.code).toBe("approval_required")
    expect(refusal.status).toBe(409)
    expect(refusal.approval).toBe("apr_approval0001")
    expect(refusal.bindingCode).toBe("RX-42")
    expect(refusal.expiresAt).toBe("2026-10-29T10:10:00.000Z")
    expect(refusal.link).toBe(link)
    expect(refusal.next?.say).toBe("Ask Alex to approve it.")
    expect(refusal.deciders).toEqual(["Alex"])
    expect(refusal.message).toBe("A person must approve this request.")
  })

  it("retries with the approval id once approved", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/relay", () => upstream(200, "sent"))
    await client.relay({ item: "gmail", method: "POST", url: "https://gmail.googleapis.com/send", approval: "apr_approval0001" })
    expect(vault.last.json).toMatchObject({ approval: "apr_approval0001" })
  })

  it("is a transport failure when the answer carries neither Mehen-Upstream nor Mehen-Error", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/relay", () => new Response("<html>Bad gateway</html>", { status: 502 }))
    const error = await caught(client.relay({ item: "openai", method: "GET", url: "https://api.openai.com/v1/models" }))
    expect(error).toBeInstanceOf(MehenTransport)
    expect((error as MehenTransport).reason).toBe("unexpected")
    expect((error as MehenTransport).status).toBe(502)
  })

  it("is a transport failure when the refusal links off the vault's origin", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/relay", () => refuse("approval_required", "Approve it.", { approval: "apr_approval0001", next: { url: "https://evil.example/a/apr_approval0001", say: "Open it." } }))
    expect(await caught(client.relay({ item: "openai", method: "GET", url: "https://api.openai.com/v1/models" }))).toBeInstanceOf(MehenTransport)
  })

  it("resolves a refusal's relative link against the vault's origin and hands it over absolute", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/intakes", () => refuse("forbidden", "Your sign-in was recovered.", { next: { url: "/account", say: "Use an older account passkey to resolve recovery, or wait for cooling-off to finish." } }))
    const error = await caught(client.intake({ kind: "api-key", slug: "stripe-task", provider: "stripe", reason: "payments", home: "workspace" }))
    expect(error).toBeInstanceOf(MehenRefusal)
    const refusal = error as MehenRefusal
    expect(refusal.code).toBe("forbidden")
    expect(refusal.link).toBe(`${ORIGIN}/account`)
    expect(refusal.next).toEqual({ url: `${ORIGIN}/account`, say: "Use an older account passkey to resolve recovery, or wait for cooling-off to finish." })
    for (const url of ["//evil.example/account", "https://evil.example/account"]) {
      vault.on("POST /v1/intakes", () => refuse("forbidden", "Your sign-in was recovered.", { next: { url } }))
      expect(await caught(client.intake({ kind: "api-key", slug: "stripe-task", provider: "stripe", reason: "payments", home: "workspace" }))).toBeInstanceOf(MehenTransport)
    }
  })

  it("keeps the vault's own code as rawCode when this client does not know it", async () => {
    const { vault, client } = await setup()
    // A code from a vault newer than this client's protocol.
    vault.on("POST /v1/relay", () => new Response(JSON.stringify({ error: "budget_exhausted", message: "This task has spent its budget." }), { status: 403, headers: { "content-type": "application/json", [ERROR_HEADER]: "1" } }))
    const unknown = (await caught(client.relay({ item: "openai", method: "GET", url: "https://api.openai.com/v1/models" }))) as MehenRefusal
    expect(unknown).toBeInstanceOf(MehenRefusal)
    expect({ code: unknown.code, rawCode: unknown.rawCode, message: unknown.message }).toEqual({ code: "internal", rawCode: "budget_exhausted", message: "This task has spent its budget." })
    vault.on("POST /v1/relay", () => refuse("forbidden", "No."))
    const known = (await caught(client.relay({ item: "openai", method: "GET", url: "https://api.openai.com/v1/models" }))) as MehenRefusal
    expect({ code: known.code, rawCode: known.rawCode }).toEqual({ code: "forbidden", rawCode: undefined })
  })

  it("is a network failure when fetch throws, and a timeout when no answer arrives in time", async () => {
    const device = await generateKey()
    const signer = deviceSigner(DEVICE, device.privateKey)
    const down = createClient({ vaultUrl: ORIGIN, tenant: TENANT, signer, fetch: () => Promise.reject(new TypeError("connection refused")) })
    const network = await caught(down.relay({ item: "openai", method: "POST", url: "https://api.openai.com/v1/responses", body: "{}" }))
    expect(network).toBeInstanceOf(MehenTransport)
    expect((network as MehenTransport).reason).toBe("network")
    expect((network as MehenTransport).message).toContain("connection refused")
    const hanging = createClient({
      vaultUrl: ORIGIN,
      tenant: TENANT,
      signer,
      timeoutMs: 30,
      fetch: (request) => new Promise((_, reject) => request.signal.addEventListener("abort", () => reject(request.signal.reason), { once: true })),
    })
    const timeout = await caught(hanging.relay({ item: "openai", method: "POST", url: "https://api.openai.com/v1/responses", body: "{}" }))
    expect(timeout).toBeInstanceOf(MehenTransport)
    expect((timeout as MehenTransport).reason).toBe("timeout")
  })

  it("sends an item relay's request exactly as before: context, item, method, url, headers, body, session, approval", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/relay", () => upstream(200, "ok"))
    await client.relay({ approval: "apr_approval0001", body: "hi", headers: [["accept", "text/plain"]], url: "https://api.openai.com/v1/models", method: "post", context: { environment: "dev", project: "prj_test0001" }, item: "openai" })
    expect(new TextDecoder().decode(vault.last.body)).toBe('{"context":{"project":"prj_test0001","environment":"dev"},"item":"openai","method":"POST","url":"https://api.openai.com/v1/models","headers":[["accept","text/plain"]],"body":"aGk","session":"task-runner","approval":"apr_approval0001"}')
  })

  it("sends a run relay's request exactly as before, from relay and relayStream alike", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/relay", () => upstream(200, "ok"))
    const input = { approval: "apr_approval0001", body: BINARY, headers: [["authorization", "Bearer sk-proj-mehen-placeholder-0001"]] as [string, string][], url: "https://api.openai.com/v1/files", method: "post", run: RUN }
    const expected = '{"run":"run_run0001","method":"POST","url":"https://api.openai.com/v1/files","headers":[["authorization","Bearer sk-proj-mehen-placeholder-0001"]],"body":"AAEC_f7_iVBORw","session":"task-runner","approval":"apr_approval0001"}'
    await client.relay(input)
    expect(new TextDecoder().decode(vault.last.body)).toBe(expected)
    await (await client.relayStream(input)).body?.cancel()
    expect(new TextDecoder().decode(vault.last.body)).toBe(expected)
    expect(vault.last.headers.get("content-type")).toBe("application/json")
  })

  it("no longer holds the request body or the request once the answer's headers arrive, while it reads the answer", async () => {
    const fed = fedBody()
    const runtime = runtimeFetch(fed.stream)
    const client = createClient({ vaultUrl: ORIGIN, tenant: TENANT, signer: deviceSigner(DEVICE, (await generateKey()).privateKey), fetch: runtime.fetch })
    const { body, answer } = withLargeBody((input) => client.relay(input))
    while (fed.counts.pulls === 0) await Bun.sleep(1)
    await collectGarbage()
    expect(body.deref()).toBeUndefined()
    expect(runtime.requests).toHaveLength(1)
    expect(runtime.requests[0]?.deref()).toBeUndefined()
    fed.push("done")
    fed.close()
    expect(new TextDecoder().decode((await answer).body)).toBe("done")
  })

  it("times out an answer that stalls mid-body, for relay and the JSON routes alike, cancelling the vault's body", async () => {
    const vault = new FakeVault()
    const device = await generateKey()
    vault.devices.set(DEVICE, device.jwk)
    const client = createClient({ vaultUrl: ORIGIN, tenant: TENANT, signer: deviceSigner(DEVICE, device.privateKey), fetch: vault.fetch, timeoutMs: 60 })
    const relayed = fedBody()
    vault.on("POST /v1/relay", () => upstream(200, relayed.stream as unknown as Uint8Array<ArrayBuffer>))
    relayed.push("partial")
    const relay = await caught(client.relay({ item: "openai", method: "GET", url: "https://api.openai.com/v1/models" }))
    expect((relay as MehenTransport).reason).toBe("timeout")
    expect(relayed.counts.cancelled).toBe(true)
    const answered = fedBody()
    vault.on("GET /v1/me", () => new Response(answered.stream, { status: 200, headers: { "content-type": "application/json" } }))
    answered.push('{"tenant"')
    const me = await caught(client.me())
    expect((me as MehenTransport).reason).toBe("timeout")
    expect(answered.counts.cancelled).toBe(true)
  })

  it("through a run sends the run and no item", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/relay", () => upstream(200, "ok"))
    const answer = await client.relay({ run: RUN, method: "GET", url: "https://api.openai.com/v1/models", headers: [["authorization", "Bearer sk-proj-mehen-placeholder-0001"]] })
    expect(new TextDecoder().decode(answer.body)).toBe("ok")
    expect(vault.last.json).toEqual({ run: RUN, method: "GET", url: "https://api.openai.com/v1/models", headers: [["authorization", "Bearer sk-proj-mehen-placeholder-0001"]], session: "task-runner" })
    expect(vault.last.json).not.toHaveProperty("item")
  })

  it("refuses both or neither of item and run, and a malformed run id, before any request", async () => {
    const { vault, client } = await setup()
    const request = { method: "GET", url: "https://api.openai.com/v1/models" }
    const both = { ...request, item: "openai", run: RUN } as unknown as Parameters<typeof client.relay>[0]
    const neither = request as unknown as Parameters<typeof client.relay>[0]
    for (const input of [both, neither, { ...request, run: "../me" }, { ...request, run: "apr_approval0001" }]) {
      await expect(client.relay(input)).rejects.toBeInstanceOf(TypeError)
      await expect(client.relayStream(input)).rejects.toBeInstanceOf(TypeError)
    }
    expect(vault.seen).toHaveLength(0)
  })

  it("refuses an invalid relay before anything is sent", async () => {
    const { vault, client } = await setup()
    await expect(client.relay({ item: "Not A Slug", method: "GET", url: "https://api.openai.com/" })).rejects.toBeInstanceOf(TypeError)
    await expect(client.relay({ item: "openai", method: "GET", url: "not a url" })).rejects.toBeInstanceOf(TypeError)
    expect(vault.seen).toHaveLength(0)
  })
})

// A body the test feeds by hand, counting how often anything pulled from it.
function fedBody() {
  let feed: ReadableStreamDefaultController<Uint8Array> | null = null
  const counts = { pulls: 0, cancelled: false }
  const stream = new ReadableStream<Uint8Array>(
    {
      start(controller) {
        feed = controller
      },
      pull() {
        counts.pulls += 1
      },
      cancel() {
        counts.cancelled = true
      },
    },
    { highWaterMark: 0 },
  )
  const push = (text: string) => feed?.enqueue(new TextEncoder().encode(text))
  const close = () => feed?.close()
  return { stream, counts, push, close }
}

describe("relayStream", () => {
  it("hands over the upstream's status, headers and body unread, and the caller reads it chunk by chunk", async () => {
    const { vault, client } = await setup()
    const fed = fedBody()
    vault.on("POST /v1/relay", () => upstream(201, fed.stream as unknown as Uint8Array<ArrayBuffer>, { "content-type": "text/event-stream" }))
    const answer = await client.relayStream({ run: RUN, method: "POST", url: "https://api.openai.com/v1/responses", body: "{}" })
    expect({ kind: answer.kind, status: answer.status, type: answer.headers.get("content-type"), item: answer.item }).toEqual({ kind: "stream", status: 201, type: "text/event-stream", item: "openai (alex@example.com)" })
    expect(vault.last.json).toMatchObject({ run: RUN, method: "POST", session: "task-runner" })
    expect(fed.counts.pulls).toBe(0)
    const reader = answer.body!.getReader()
    const first = reader.read()
    fed.push("data: one\n\n")
    expect(new TextDecoder().decode((await first).value)).toBe("data: one\n\n")
    fed.push("data: two\n\n")
    fed.close()
    expect(new TextDecoder().decode((await reader.read()).value)).toBe("data: two\n\n")
    expect((await reader.read()).done).toBe(true)
  })

  it("releases the request body and the request once the answer's headers arrive, the answer still open and unread", async () => {
    const signer = deviceSigner(DEVICE, (await generateKey()).privateKey)
    // The caller's signal too: it outlives the request, combined with the timeout.
    const caller = new AbortController()
    for (const options of [{}, { signal: caller.signal }]) {
      const fed = fedBody()
      const runtime = runtimeFetch(fed.stream)
      const client = createClient({ vaultUrl: ORIGIN, tenant: TENANT, signer, fetch: runtime.fetch })
      const sending = withLargeBody((input) => client.relayStream(input, options))
      const answer = await sending.answer
      await collectGarbage()
      expect(sending.body.deref()).toBeUndefined()
      expect(runtime.requests).toHaveLength(1)
      expect(runtime.requests[0]?.deref()).toBeUndefined()
      expect(fed.counts).toEqual({ pulls: 0, cancelled: false })
      const reader = answer.body!.getReader()
      const read = reader.read()
      fed.push("data: still open\n\n")
      expect(new TextDecoder().decode((await read).value)).toBe("data: still open\n\n")
      await reader.cancel()
    }
  })

  it("cancelling the body cancels the vault's", async () => {
    const { vault, client } = await setup()
    const fed = fedBody()
    vault.on("POST /v1/relay", () => upstream(200, fed.stream as unknown as Uint8Array<ArrayBuffer>))
    const answer = await client.relayStream({ item: "openai", method: "GET", url: "https://api.openai.com/v1/models" })
    await answer.body!.cancel()
    expect(fed.counts.cancelled).toBe(true)
  })

  it("throws MehenRefusal on Mehen-Error and MehenTransport without Mehen-Upstream, cancelling that body", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/relay", () => refuse("surface_refused", "A placeholder was found outside the surfaces its item allows."))
    const refusal = (await caught(client.relayStream({ run: RUN, method: "GET", url: "https://api.openai.com/v1/models" }))) as MehenRefusal
    expect(refusal).toBeInstanceOf(MehenRefusal)
    expect({ code: refusal.code, status: refusal.status }).toEqual({ code: "surface_refused", status: 403 })
    const fed = fedBody()
    vault.on("POST /v1/relay", () => new Response(fed.stream, { status: 502 }))
    const error = await caught(client.relayStream({ run: RUN, method: "GET", url: "https://api.openai.com/v1/models" }))
    expect(error).toBeInstanceOf(MehenTransport)
    expect({ reason: (error as MehenTransport).reason, status: (error as MehenTransport).status }).toEqual({ reason: "unexpected", status: 502 })
    expect(fed.counts.cancelled).toBe(true)
  })

  it("times out a stalled body mid-stream, the timeout covering the whole exchange", async () => {
    const { vault, client } = await setup()
    const fed = fedBody()
    vault.on("POST /v1/relay", () => upstream(200, fed.stream as unknown as Uint8Array<ArrayBuffer>))
    const answer = await client.relayStream({ run: RUN, method: "GET", url: "https://api.openai.com/v1/models" }, { timeoutMs: 60 })
    const reader = answer.body!.getReader()
    const first = reader.read()
    fed.push("partial")
    expect(new TextDecoder().decode((await first).value)).toBe("partial")
    const stalled = await caught(reader.read())
    expect(stalled).toBeInstanceOf(MehenTransport)
    expect((stalled as MehenTransport).reason).toBe("timeout")
    expect(fed.counts.cancelled).toBe(true)
  })

  it("times out when no answer arrives, and rejects with the caller's own reason when it aborts", async () => {
    const device = await generateKey()
    const signer = deviceSigner(DEVICE, device.privateKey)
    let fetched = () => undefined as unknown
    const hanging = createClient({
      vaultUrl: ORIGIN,
      tenant: TENANT,
      signer,
      fetch: (request) =>
        new Promise((_, reject) => {
          request.signal.addEventListener("abort", () => reject(request.signal.reason), { once: true })
          fetched()
        }),
    })
    const timeout = await caught(hanging.relayStream({ run: RUN, method: "GET", url: "https://api.openai.com/v1/models" }, { timeoutMs: 30 }))
    expect((timeout as MehenTransport).reason).toBe("timeout")
    const reason = new Error("the task was stopped")
    const controller = new AbortController()
    const started = new Promise((resolve) => (fetched = resolve as () => unknown))
    const pending = caught(hanging.relayStream({ run: RUN, method: "GET", url: "https://api.openai.com/v1/models" }, { signal: controller.signal }))
    await started
    controller.abort(reason)
    expect(await pending).toBe(reason)
    const before = new AbortController()
    before.abort(reason)
    expect(await caught(hanging.relayStream({ run: RUN, method: "GET", url: "https://api.openai.com/v1/models" }, { signal: before.signal }))).toBe(reason)
    await expect(hanging.relayStream({ run: RUN, method: "GET", url: "https://api.openai.com/v1/models" }, { timeoutMs: 0 })).rejects.toBeInstanceOf(TypeError)
  })

  it("errors the body with the caller's reason when it aborts mid-stream", async () => {
    const { vault, client } = await setup()
    const fed = fedBody()
    vault.on("POST /v1/relay", () => upstream(200, fed.stream as unknown as Uint8Array<ArrayBuffer>))
    const controller = new AbortController()
    const answer = await client.relayStream({ run: RUN, method: "GET", url: "https://api.openai.com/v1/models" }, { signal: controller.signal })
    const reader = answer.body!.getReader()
    const read = caught(reader.read())
    const reason = new Error("the task was stopped")
    controller.abort(reason)
    expect(await read).toBe(reason)
    expect(fed.counts.cancelled).toBe(true)
  })
})

describe("runs", () => {
  it("creates a run with the client's session and parses every delivery", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/runs", () => json(runCreated({ added: "a field this client does not know" }), 201))
    const input = { project: PROJECT, env: "dev", envSource: "flag" as const, remote: null, worktree: "/workspace", head: null, vars: ["DATABASE_HOST", "OPENAI_API_KEY", "OPENAI_BASE_URL", "PGPASSWORD", "SENTRY_DSN"], command: "globex computer" }
    const run = await client.runs.create(input)
    expect(RunCreate.parse(vault.last.json)).toEqual({ ...input, session: "task-runner" })
    expect(vault.last.claims.sid).toBe("task-runner")
    expect(run).toEqual(runCreated() as typeof run)
    expect("added" in run).toBe(false)
    expect(run.vars.map((v) => v.delivery)).toEqual(["plain", "placeholder", "base-url", "lease", "missing"])
  })

  it("is a transport failure when a variable's delivery is one this client does not know", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/runs", () => json(runCreated({ vars: [{ name: "X", delivery: "sealed-file", value: "x" }] }), 201))
    const error = await caught(client.runs.create({ project: PROJECT, env: "dev", envSource: "flag", remote: null, worktree: "/workspace", head: null, vars: ["X"], command: "globex computer" }))
    expect(error).toBeInstanceOf(MehenTransport)
    expect((error as MehenTransport).reason).toBe("unexpected")
    expect((error as MehenTransport).message).toContain("vars")
  })

  it("renews and ends a run by id", async () => {
    const { vault, client } = await setup()
    vault.on(`POST /v1/runs/${RUN}/renew`, () => json({ run: RUN, expiresAt: "2026-10-29T10:30:00.000Z" }))
    vault.on(`DELETE /v1/runs/${RUN}`, () => json({ run: RUN, ended: true }))
    expect(await client.runs.renew(RUN)).toEqual({ run: RUN, expiresAt: "2026-10-29T10:30:00.000Z" })
    expect(vault.last.json).toEqual({})
    expect(await client.runs.end(RUN)).toEqual({ run: RUN, ended: true })
    expect(vault.last.method).toBe("DELETE")
    expect(vault.last.body).toHaveLength(0)
  })

  it("refuses a malformed run or project id before anything is sent", async () => {
    const { vault, client } = await setup()
    for (const id of ["../me", "apr_approval0001", "run_", "run_a/b"]) {
      await expect(client.runs.renew(id)).rejects.toBeInstanceOf(TypeError)
      await expect(client.runs.end(id)).rejects.toBeInstanceOf(TypeError)
    }
    await expect(client.runs.create({ project: "acme-app", env: "dev", envSource: "flag", remote: null, worktree: "/workspace", head: null, vars: [], command: "globex computer" })).rejects.toBeInstanceOf(TypeError)
    await expect(client.runs.create({ project: PROJECT, env: "Not An Env", envSource: "flag", remote: null, worktree: "/workspace", head: null, vars: [], command: "globex computer" })).rejects.toBeInstanceOf(TypeError)
    await expect(client.project("acme-app")).rejects.toBeInstanceOf(TypeError)
    expect(vault.seen).toHaveLength(0)
  })
})

describe("project", () => {
  it("reads a project's remotes, environments and variables, and drops what a machine does not need", async () => {
    const { vault, client } = await setup()
    vault.on(`GET /v1/projects/${PROJECT}`, () => json(projectAnswer()))
    const project = await client.project(PROJECT)
    const { access: _, ...expected } = projectAnswer()
    expect(project).toEqual(expected as typeof project)
    expect("access" in project).toBe(false)
    vault.on(`GET /v1/projects/${PROJECT}`, () => json(projectAnswer({ environments: [{ name: "dev", protected: "no" }] })))
    expect(await caught(client.project(PROJECT))).toBeInstanceOf(MehenTransport)
  })
})

describe("answers that do not parse", () => {
  it("are transport failures, never crashes or untyped values", async () => {
    const { vault, client } = await setup()
    vault.on("GET /v1/me", () => json({ tenant: TENANT, device: 42 }))
    const malformed = await caught(client.me())
    expect(malformed).toBeInstanceOf(MehenTransport)
    expect((malformed as MehenTransport).message).toContain("device")
    vault.on("GET /v1/me", () => new Response("not json", { status: 200 }))
    expect(await caught(client.me())).toBeInstanceOf(MehenTransport)
    vault.on("GET /v1/me", () => new Response("<html>oops</html>", { status: 500 }))
    expect(await caught(client.me())).toBeInstanceOf(MehenTransport)
    vault.on("GET /v1/me", () => new Response("not json", { status: 403, headers: { "Mehen-Error": "1" } }))
    expect(await caught(client.me())).toBeInstanceOf(MehenTransport)
  })

  it("include an intake link off the vault's origin", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/intakes", () => json({ intake: "int_intake0001", url: "https://evil.example/w/acme/i/int_intake0001", expiresAt: "2026-10-29T11:00:00.000Z" }, 201))
    expect(await caught(client.intake({ kind: "api-key", slug: "openai", reason: "The task calls OpenAI.", home: "private" }))).toBeInstanceOf(MehenTransport)
  })
})

describe("asks", () => {
  it("polls an approval, long-polling with wait", async () => {
    const { vault, client } = await setup()
    vault.on("GET /v1/approvals/apr_approval0001", () => json({ approval: "apr_approval0001", status: "approved", bindingCode: "RX-42", summary: "Send an email", expiresAt: "2026-10-29T10:10:00.000Z" }))
    expect(await client.approval("apr_approval0001", { wait: true })).toEqual({ approval: "apr_approval0001", status: "approved", bindingCode: "RX-42", summary: "Send an email", expiresAt: "2026-10-29T10:10:00.000Z" })
    expect(vault.last.search).toBe("?wait=1")
    expect(vault.last.claims.htu).toBe(`${ORIGIN}/v1/approvals/apr_approval0001?wait=1`)
    await client.approval("apr_approval0001")
    expect(vault.last.search).toBe("")
    await expect(client.approval("../me")).rejects.toBeInstanceOf(TypeError)
  })

  it("creates, polls and cancels an intake with the client's session", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/intakes", () => json({ intake: "int_intake0001", url: `${ORIGIN}/w/acme/i/int_intake0001`, expiresAt: "2026-10-29T11:00:00.000Z" }, 201))
    vault.on("GET /v1/intakes/int_intake0001", () => json({ intake: "int_intake0001", status: "open", expiresAt: "2026-10-29T11:00:00.000Z" }))
    vault.on("POST /v1/intakes/int_intake0001/cancel", () => json({}))
    expect((await client.intake({ kind: "api-key", slug: "openai", provider: "openai", reason: "The task calls OpenAI.", home: "private" })).url).toBe(`${ORIGIN}/w/acme/i/int_intake0001`)
    expect(vault.seen[0]?.json).toEqual({ kind: "api-key", slug: "openai", provider: "openai", reason: "The task calls OpenAI.", home: "private", session: "task-runner" })
    expect((await client.intakeStatus("int_intake0001", { wait: true })).status).toBe("open")
    expect(vault.last.search).toBe("?wait=1")
    await client.cancelIntake("int_intake0001")
    expect(vault.last.json).toEqual({})
  })

  it("creates, polls and cancels a connection", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/connect", () => json({ connect: "con_connect0001", url: `${ORIGIN}/w/acme/c/con_connect0001`, expiresAt: "2026-10-29T11:00:00.000Z" }))
    vault.on("GET /v1/connect/con_connect0001", () => json({ connect: "con_connect0001", status: "completed", account: "alex@example.com", expiresAt: "2026-10-29T11:00:00.000Z" }))
    vault.on("POST /v1/connect/con_connect0001/cancel", () => json({}))
    expect((await client.connect({ provider: "google-gmail", client: "google-client", slug: "gmail-alex", reason: "Send the weekly report.", home: "private" })).connect).toBe("con_connect0001")
    expect((await client.connectStatus("con_connect0001")).account).toBe("alex@example.com")
    await client.cancelConnect("con_connect0001")
  })

  it("reads an intake and a connection with no link, as a managed workspace answers them", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/intakes", () => json({ intake: "int_intake0001", expiresAt: "2026-10-29T11:00:00.000Z" }, 201))
    vault.on("POST /v1/connect", () => json({ connect: "con_connect0001", expiresAt: "2026-10-29T11:00:00.000Z", intake: { intake: "int_intake0001", expiresAt: "2026-10-29T11:00:00.000Z" } }))
    const intake = await client.intake({ kind: "api-key", slug: "openai", provider: "openai", reason: "The task calls OpenAI.", home: "private" })
    expect(intake).toEqual({ intake: "int_intake0001", expiresAt: "2026-10-29T11:00:00.000Z" })
    expect("url" in intake).toBe(false)
    const connect = await client.connect({ provider: "google-gmail", client: "google-client", slug: "gmail-alex", reason: "Send the weekly report.", home: "private" })
    expect(connect.url).toBeUndefined()
    expect(connect.intake?.url).toBeUndefined()
  })

  it("lists pending asks and keeps only notices it knows on the vault's origin", async () => {
    const { vault, client } = await setup()
    const ask = { workspace: { id: TENANT, slug: "acme", name: "Acme" }, owner: { kind: "member", member: "mem_alex0001", name: "Alex" }, view: "detail", detail: { kind: "approval", id: "apr_approval0001", title: "Send an email", url: `${ORIGIN}/w/acme/a/apr_approval0001`, expiresAt: "2026-10-29T10:10:00.000Z", requestedBy: { device: DEVICE, deviceName: "globex-broker", session: "task-runner" }, item: "gmail", bindingCode: "RX-42" } }
    const notice = { id: "ntc_notice0001", account: "acc_alex", payload: { kind: "machine_added", workspace: { id: TENANT, slug: "acme", name: "Acme" }, device: DEVICE, name: "globex-broker", owner: { kind: "member", member: "mem_alex0001", name: "Alex" }, place: null, at: "2026-10-29T10:00:00.000Z" }, at: 1_793_000_000_000, url: `${ORIGIN}/w/acme/devices/${DEVICE}` }
    vault.on("GET /v1/pending", () => json({ pending: [ask], notices: [notice, { ...notice, url: "https://evil.example/" }, { ...notice, payload: { kind: "from_the_future" } }] }))
    const pending = await client.pending()
    expect(pending.pending).toEqual([ask] as typeof pending.pending)
    expect(pending.notices).toEqual([notice] as typeof pending.notices)
  })

  it("revokes itself and freezes the workspace", async () => {
    const { vault, client } = await setup()
    vault.on("POST /v1/devices/self/revoke", () => json({}))
    vault.on("POST /v1/freeze", () => json({}))
    await client.revokeSelf()
    expect(vault.last.path).toBe("/v1/devices/self/revoke")
    await client.freeze()
    expect(vault.last.path).toBe("/v1/freeze")
  })
})

describe("items", () => {
  it("lists with filters and describes one item", async () => {
    const { vault, client } = await setup()
    const summary = { slug: "openai", kind: "api-key", provider: "openai", account: null, accountVerified: false, tags: ["globex"], ceiling: "relay", hosts: ["api.openai.com"], status: "active", updatedAt: "2026-10-29T10:00:00.000Z", lastUsedAt: null, home: { kind: "workspace" } }
    vault.on("GET /v1/items", () => json({ items: [summary] }))
    vault.on("GET /v1/items/openai", () => json({ ...summary, description: null, publicFields: {}, secretFields: [{ name: "key", set: true, length: 51, prefix: "sk-proj-", fingerprint: "abcdefabcdef" }], binding: { hosts: ["api.openai.com"] }, policy: { default: "allow", rules: [] }, injection: { in: "header", name: "Authorization", format: "Bearer {key}" }, version: 1, rotatedAt: null }))
    expect(await client.items({ tag: "globex" })).toEqual([summary] as Awaited<ReturnType<typeof client.items>>)
    expect(vault.last.search).toBe("?tag=globex")
    expect((await client.item("openai")).injection).toEqual({ in: "header", name: "Authorization", format: "Bearer {key}" })
  })
})

describe("workloads", () => {
  it("creates, lists, gets, renews and revokes with the device key", async () => {
    const { vault, client } = await setup()
    const task = await generateKey()
    const scope = { items: ["openai"], modes: ["relay" as const] }
    const view = await workloadView(WORKLOAD, task.jwk, scope)
    vault.on("POST /v1/workloads", () => json(view, 201))
    vault.on("GET /v1/workloads", () => json({ workloads: [view] }))
    vault.on(`GET /v1/workloads/${WORKLOAD}`, () => json(view))
    vault.on(`POST /v1/workloads/${WORKLOAD}/renew`, () => json({ ...view, expiresAt: "2026-10-29T12:00:00.000Z" }))
    vault.on(`DELETE /v1/workloads/${WORKLOAD}`, () => json({ ...view, state: "revoked", revokedAt: "2026-10-29T10:30:00.000Z", revokedBy: "device" }))
    expect(await client.workloads.create({ jwk: task.jwk, label: "task:42", ttlSeconds: 3600, scope })).toEqual(view)
    expect(WorkloadCreateSchema.parse(vault.last.json)).toEqual({ jwk: task.jwk, label: "task:42", ttlSeconds: 3600, scope })
    expect(vault.last.signedBy).toBe("device")
    expect(await client.workloads.list()).toEqual([view])
    expect(await client.workloads.get(WORKLOAD)).toEqual(view)
    expect((await client.workloads.renew(WORKLOAD, { ttlSeconds: 7200 })).expiresAt).toBe("2026-10-29T12:00:00.000Z")
    expect(vault.last.json).toEqual({ ttlSeconds: 7200 })
    const revoked = await client.workloads.revoke(WORKLOAD)
    expect(revoked.state).toBe("revoked")
    expect(vault.last.method).toBe("DELETE")
    expect(vault.last.body).toHaveLength(0)
  })

  it("is a transport failure when the vault's new workload holds another key", async () => {
    const { vault, client } = await setup()
    const task = await generateKey()
    vault.on("POST /v1/workloads", async () => json(await workloadView(WORKLOAD, (await generateKey()).jwk, {}), 201))
    expect(await caught(client.workloads.create({ jwk: task.jwk, label: "task:42", scope: {} }))).toBeInstanceOf(MehenTransport)
  })

  it("refuses an invalid workload before anything is sent", async () => {
    const { vault, client } = await setup()
    const task = await generateKey()
    await expect(client.workloads.create({ jwk: task.jwk, label: "has spaces", scope: {} })).rejects.toBeInstanceOf(TypeError)
    await expect(client.workloads.create({ jwk: task.jwk, label: "task", ttlSeconds: 10, scope: {} })).rejects.toBeInstanceOf(TypeError)
    await expect(client.workloads.get("dev_notaworkload")).rejects.toBeInstanceOf(TypeError)
    expect(vault.seen).toHaveLength(0)
  })

  it("a workload client relays signed by the workload key, as the workload of its device", async () => {
    const { vault } = await setup()
    const task = await generateKey()
    vault.workloads.set(WORKLOAD, { device: DEVICE, jwk: task.jwk })
    vault.on("POST /v1/relay", (seen) => (seen.signedBy === "workload" ? upstream(200, "ok") : refuse("workload_required", "This machine acts only through workloads.")))
    vault.on("GET /v1/me", async () => json(meAnswer({ workload: await workloadView(WORKLOAD, task.jwk, { items: ["openai"] }) })))
    const workload = createClient({ vaultUrl: ORIGIN, tenant: TENANT, signer: workloadSigner(DEVICE, WORKLOAD, task.privateKey), fetch: vault.fetch })
    const answer = await workload.relay({ item: "openai", method: "GET", url: "https://api.openai.com/v1/models" })
    expect(new TextDecoder().decode(answer.body)).toBe("ok")
    expect(vault.last.signedBy).toBe("workload")
    expect(vault.last.claims).toMatchObject({ ten: TENANT, dev: DEVICE, wkl: WORKLOAD })
    expect((await workload.me()).workload?.workload).toBe(WORKLOAD)
  })

  it("the fake vault refuses a workload proof signed with another key, and a replayed proof", async () => {
    const { vault } = await setup()
    vault.workloads.set(WORKLOAD, { device: DEVICE, jwk: (await generateKey()).jwk })
    vault.on("POST /v1/relay", () => upstream(200, "ok"))
    const impostor = createClient({ vaultUrl: ORIGIN, tenant: TENANT, signer: workloadSigner(DEVICE, WORKLOAD, (await generateKey()).privateKey), fetch: vault.fetch })
    const error = await caught(impostor.relay({ item: "openai", method: "GET", url: "https://api.openai.com/v1/models" }))
    expect((error as MehenRefusal).code).toBe("proof_invalid")
    const task = await generateKey()
    vault.workloads.set(WORKLOAD, { device: DEVICE, jwk: task.jwk })
    let replayed: Response | null = null
    const replaying = createClient({
      vaultUrl: ORIGIN,
      tenant: TENANT,
      signer: workloadSigner(DEVICE, WORKLOAD, task.privateKey),
      fetch: async (request) => {
        const copy = request.clone()
        const first = await vault.fetch(request)
        replayed = await vault.fetch(copy)
        return first
      },
    })
    await replaying.relay({ item: "openai", method: "GET", url: "https://api.openai.com/v1/models" })
    expect(replayed).not.toBeNull()
    expect(((await (replayed as unknown as Response).json()) as { error: string }).error).toBe("proof_invalid")
  })

  it("surfaces workload_ended and workload_required as typed refusals", async () => {
    const { vault, client } = await setup()
    const task = await generateKey()
    vault.workloads.set(WORKLOAD, { device: DEVICE, jwk: task.jwk })
    vault.on("POST /v1/relay", (seen) => (seen.signedBy === "workload" ? refuse("workload_ended", "This workload has ended. Create a new one from its device.") : refuse("workload_required", "This machine acts only through workloads.")))
    const workload = createClient({ vaultUrl: ORIGIN, tenant: TENANT, signer: workloadSigner(DEVICE, WORKLOAD, task.privateKey), fetch: vault.fetch })
    const ended = (await caught(workload.relay({ item: "openai", method: "GET", url: "https://api.openai.com/v1/models" }))) as MehenRefusal
    expect(ended).toBeInstanceOf(MehenRefusal)
    expect(ended.code).toBe("workload_ended")
    expect(ended.status).toBe(403)
    expect(ended.message).toBe("This workload has ended. Create a new one from its device.")
    const required = (await caught(client.relay({ item: "openai", method: "GET", url: "https://api.openai.com/v1/models" }))) as MehenRefusal
    expect(required).toBeInstanceOf(MehenRefusal)
    expect(required.code).toBe("workload_required")
    expect(required.status).toBe(403)
  })
})
