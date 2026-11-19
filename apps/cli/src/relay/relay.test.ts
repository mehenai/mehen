import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { writeFileSync } from "node:fs"
import net from "node:net"
import tls from "node:tls"
import { join } from "node:path"
import { newPlaceholder } from "@mehen/protocol"
import { RelayOutcomeUnknownError, RelayUnmarkedAnswerError, VaultApiError } from "../vault-api.ts"
import { FakeVaultApi, removeDir, spawnText, tempDir, withTimeout } from "../run/fake-vault-api.ts"
import { createRunCa, type RunCa } from "./ca.ts"
import { type LocalRelay, startLocalRelay } from "./relay.ts"

const INTERCEPT = "api.mehen.test"
const FENCED = "db.prod.mehen.test"
const placeholder = newPlaceholder("sk-proj-realvalue")

let api: FakeVaultApi
let ca: RunCa
let relay: LocalRelay
let dir: string
let caFile: string
let fixtureCaFile: string
let fixture: tls.Server
let fixturePort: number
let echo: net.Server
let echoPort: number

function listenPort(server: net.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", () => {
      const address = server.address()
      if (address === null || typeof address === "string") reject(new Error("no port"))
      else resolve(address.port)
    })
  })
}

function closeServer(server: net.Server | undefined): Promise<void> {
  return new Promise((resolve) => (server === undefined ? resolve() : server.close(() => resolve())))
}

// Sends raw bytes to the relay and collects everything until it closes.
async function rawExchange(request: string): Promise<string> {
  return withTimeout(
    new Promise<string>((resolve, reject) => {
      const socket = net.connect({ host: "127.0.0.1", port: relay.port }, () => socket.write(request))
      let text = ""
      socket.on("data", (chunk) => {
        text += chunk.toString("latin1")
      })
      socket.on("close", () => resolve(text))
      socket.on("error", reject)
    }),
    5000,
    "raw exchange with the relay",
  )
}

function proxyAuth(url = relay.proxyUrl): string {
  const parsed = new URL(url)
  return `Basic ${Buffer.from(`${parsed.username}:${parsed.password}`).toString("base64")}`
}

function header(headers: [string, string][] | undefined, name: string): string | undefined {
  return headers?.find(([key]) => key.toLowerCase() === name)?.[1]
}

function runSecretPath(item: string): string {
  return new URL(relay.baseUrl(item)).pathname
}

beforeAll(async () => {
  dir = tempDir("mehen-relay-test-")
  api = new FakeVaultApi()
  ca = await createRunCa([INTERCEPT])
  caFile = join(dir, "run-ca.pem")
  writeFileSync(caFile, ca.certPem)
  relay = await startLocalRelay({
    api,
    run: "run_test1",
    env: "dev",
    interceptHosts: [INTERCEPT],
    fencedHosts: [FENCED, "*.prod.example"],
    baseUrls: [{ item: "openai-personal", upstream: "https://api.openai.com/v1" }],
    ca,
  })
  // A real HTTPS server the relay must not touch, with its own CA.
  const fixtureCa = await createRunCa(["127.0.0.1"])
  fixtureCaFile = join(dir, "fixture-ca.pem")
  writeFileSync(fixtureCaFile, fixtureCa.certPem)
  const leaf = await fixtureCa.issueLeaf("127.0.0.1")
  fixture = tls.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (socket) => {
    socket.once("data", () => socket.end("HTTP/1.1 200 OK\r\ncontent-length: 10\r\nconnection: close\r\n\r\nfixture ok"))
  })
  fixturePort = await listenPort(fixture)
  echo = net.createServer((socket) => socket.pipe(socket))
  echoPort = await listenPort(echo)
})

afterAll(async () => {
  await relay?.close()
  await closeServer(fixture)
  await closeServer(echo)
  if (dir !== undefined) removeDir(dir)
})

describe("intercepted hosts", () => {
  test("curl: forwarded to the vault relay with the placeholder intact, nothing swapped locally", async () => {
    api.relayCalls.length = 0
    const result = await spawnText([
      "curl", "-sS", "--max-time", "10", "-x", relay.proxyUrl, "--cacert", caFile,
      "-H", `Authorization: Bearer ${placeholder}`, "-H", "X-Trace: 1", "--data-binary", "hello body",
      `https://${INTERCEPT}/v1/things?x=1`,
    ])
    expect(result.stderr).toBe("")
    expect(result.code).toBe(0)
    expect(api.relayCalls).toHaveLength(1)
    const call = api.relayCalls[0]
    expect(call?.run).toBe("run_test1")
    expect(call?.item).toBeUndefined()
    expect(call?.method).toBe("POST")
    expect(call?.url).toBe(`https://${INTERCEPT}/v1/things?x=1`)
    expect(call?.headers).toContainEqual(["Authorization", `Bearer ${placeholder}`])
    expect(call?.headers).toContainEqual(["X-Trace", "1"])
    expect(call?.headers.some(([name]) => ["host", "content-length", "proxy-authorization"].includes(name.toLowerCase()))).toBe(false)
    expect(Buffer.from(call?.body ?? "", "base64url").toString()).toBe("hello body")
    expect(JSON.parse(result.stdout).echoed.headers).toContainEqual(["Authorization", `Bearer ${placeholder}`])
  })

  test("bun fetch through HTTPS_PROXY and NODE_EXTRA_CA_CERTS: forwarded with the placeholder intact", async () => {
    api.relayCalls.length = 0
    const script = `const r = await fetch("https://${INTERCEPT}/v1/models", { headers: { authorization: "Bearer " + process.env.KEY } }); console.log(r.status, r.headers.get("mehen-upstream"))`
    const result = await spawnText([process.execPath, "-e", script], {
      env: { HTTPS_PROXY: relay.proxyUrl, NODE_EXTRA_CA_CERTS: caFile, NO_PROXY: "", KEY: placeholder },
    })
    expect(result.stderr).toBe("")
    expect(result.stdout.trim()).toBe("200 1")
    expect(api.relayCalls).toHaveLength(1)
    expect(api.relayCalls[0]?.method).toBe("GET")
    expect(api.relayCalls[0]?.url).toBe(`https://${INTERCEPT}/v1/models`)
    expect(header(api.relayCalls[0]?.headers, "authorization")).toBe(`Bearer ${placeholder}`)
    expect(api.relayCalls[0]?.body).toBeUndefined()
  })

  test("the upstream response is streamed back, not buffered", async () => {
    let release = () => {}
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    api.relayHandler = () =>
      new Response(
        new ReadableStream<Uint8Array>({
          async start(controller) {
            controller.enqueue(new TextEncoder().encode("first;"))
            await gate
            controller.enqueue(new TextEncoder().encode("second"))
            controller.close()
          },
        }),
        { status: 200, headers: { "content-type": "text/event-stream" } },
      )
    try {
      const response = await withTimeout(fetch(`https://${INTERCEPT}/stream`, { proxy: relay.proxyUrl, tls: { ca: ca.certPem } }), 5000, "streamed response head")
      const reader = response.body?.getReader()
      if (reader === undefined) throw new Error("no body")
      const first = await withTimeout(reader.read(), 5000, "first chunk before the upstream finished")
      expect(new TextDecoder().decode(first.value)).toBe("first;")
      release()
      let rest = ""
      for (let chunk = await reader.read(); !chunk.done; chunk = await reader.read()) rest += new TextDecoder().decode(chunk.value)
      expect(rest).toBe("second")
    } finally {
      release()
      api.relayHandler = (request) => Response.json({ echoed: request }, { headers: { "Mehen-Upstream": "1" } })
    }
  })

  test("a vault refusal reaches the client as JSON with Mehen-Error and the next step", async () => {
    api.relayHandler = () => {
      throw new VaultApiError(409, { error: "approval_required", message: "Sending needs an approval.", approval: "apr_1", next: { say: "Ask Alex to approve.", url: "https://vault.test/a/apr_1" } })
    }
    try {
      const response = await withTimeout(fetch(`https://${INTERCEPT}/send`, { method: "POST", body: "x", proxy: relay.proxyUrl, tls: { ca: ca.certPem } }), 5000, "refusal")
      expect(response.status).toBe(409)
      expect(response.headers.get("mehen-error")).toBe("1")
      const body = (await response.json()) as { error: string; next: { url: string } }
      expect(body.error).toBe("approval_required")
      expect(body.next.url).toBe("https://vault.test/a/apr_1")
    } finally {
      api.relayHandler = (request) => Response.json({ echoed: request }, { headers: { "Mehen-Upstream": "1" } })
    }
  })

  test("a write whose outcome is unknown is a 424 outcome_unknown that tells SDKs not to retry", async () => {
    api.relayHandler = () => {
      throw new RelayOutcomeUnknownError("The connection to the vault failed after the request may have reached it: reset")
    }
    try {
      const response = await withTimeout(fetch(`https://${INTERCEPT}/send`, { method: "POST", body: "x", proxy: relay.proxyUrl, tls: { ca: ca.certPem } }), 5000, "outcome unknown")
      expect(response.status).toBe(424)
      expect(response.headers.get("mehen-error")).toBe("1")
      expect(response.headers.get("x-should-retry")).toBe("false")
      expect(response.headers.get("stripe-should-retry")).toBe("false")
      const body = (await response.json()) as { error: string; message: string; next: { say: string } }
      expect(body.error).toBe("outcome_unknown")
      expect(body.next.say).toContain("Do not send it again until you have checked")
      expect(`${body.message} ${body.next.say}`).not.toMatch(/try again/i)
    } finally {
      api.relayHandler = (request) => Response.json({ echoed: request }, { headers: { "Mehen-Upstream": "1" } })
    }
  })

  async function relayedFailure(method: string, failure: Error): Promise<Response> {
    api.relayHandler = () => {
      throw failure
    }
    try {
      return await withTimeout(fetch(`https://${INTERCEPT}/send`, { method, ...(method === "GET" ? {} : { body: "x" }), proxy: relay.proxyUrl, tls: { ca: ca.certPem } }), 5000, `${method} failure`)
    } finally {
      api.relayHandler = (request) => Response.json({ echoed: request }, { headers: { "Mehen-Upstream": "1" } })
    }
  }

  async function expectOutcomeUnknown(response: Response, message: string): Promise<void> {
    expect(response.status).toBe(424)
    expect(response.headers.get("x-should-retry")).toBe("false")
    expect(response.headers.get("stripe-should-retry")).toBe("false")
    const body = (await response.json()) as { error: string; message: string; next: { say: string }; retryAfter?: number }
    expect(body.error).toBe("outcome_unknown")
    expect(body.message).toBe(message)
    expect(body.next.say).toContain("Do not send it again until you have checked")
    expect(body.retryAfter).toBeUndefined()
  }

  test("a write the vault answers upstream_failed is a 424 outcome_unknown, not a 502", async () => {
    const message = "Could not get an answer from api.mehen.test. The request may have reached it: check whether it took effect before sending it again."
    await expectOutcomeUnknown(await relayedFailure("POST", new VaultApiError(502, { error: "upstream_failed", message, retryAfter: 5 })), message)
  })

  test("a write the upstream answered in a compression the vault cannot check is a 424 outcome_unknown", async () => {
    const message = "api.mehen.test answered with a body in a compression the vault cannot check for leaked credentials, so it was not passed on. The request itself was sent; check its effect before retrying."
    await expectOutcomeUnknown(await relayedFailure("POST", new VaultApiError(502, { error: "upstream_failed", message })), message)
  })

  test("a write answered with a 5xx that carries neither Mehen-Upstream nor mehen-error is a 424 outcome_unknown", async () => {
    const message = "The vault answered the relay with HTTP 504 but neither Mehen-Upstream nor Mehen-Error, so mehen will not treat it as the upstream's answer."
    await expectOutcomeUnknown(await relayedFailure("POST", new RelayUnmarkedAnswerError(504, { error: "internal", message })), message)
  })

  test("a write answered with any unmarked status, a 429 or a 200 from something in front of the vault, is a 424 outcome_unknown", async () => {
    for (const status of [408, 429, 200]) {
      const message = `The vault answered the relay with HTTP ${status} but neither Mehen-Upstream nor Mehen-Error, so mehen will not treat it as the upstream's answer.`
      await expectOutcomeUnknown(await relayedFailure("POST", new RelayUnmarkedAnswerError(status, { error: "internal", message })), message)
    }
  })

  test("a streamed answer that breaks after its first chunk reaches the program as an incomplete body, never a clean end, and is not buffered", async () => {
    for (const method of ["POST", "GET"]) {
      let pulled = 0, release = () => {}
      const held = new Promise<void>((resolve) => { release = resolve })
      api.relayHandler = () => new Response(new ReadableStream<Uint8Array>({
        async pull(controller) {
          pulled++
          if (pulled === 1) return controller.enqueue(new TextEncoder().encode("data: first\n\n"))
          await held
          controller.error(new Error("stream reset"))
        },
      }), { headers: { "Mehen-Upstream": "1", "content-type": "text/event-stream" } })
      try {
        // The headers and the first chunk arrive while the rest is held back:
        // the relay streams the answer, it does not buffer it.
        const response = await withTimeout(fetch(`https://${INTERCEPT}/stream`, { method, ...(method === "GET" ? {} : { body: "x" }), proxy: relay.proxyUrl, tls: { ca: ca.certPem } }), 5000, `${method} stream`)
        expect(response.status, method).toBe(200)
        const reader = response.body!.getReader()
        const first = await withTimeout(reader.read(), 5000, `${method} first chunk`)
        expect(new TextDecoder().decode(first.value), method).toBe("data: first\n\n")
        release()
        await expect((async () => { for (;;) if ((await reader.read()).done) return "clean end" })(), method).rejects.toBeDefined()
      } finally {
        api.relayHandler = (request) => Response.json({ echoed: request }, { headers: { "Mehen-Upstream": "1" } })
      }
    }
  })

  test("a read the vault answers upstream_failed keeps its retryable 502", async () => {
    const response = await relayedFailure("GET", new VaultApiError(502, { error: "upstream_failed", message: "Could not reach api.mehen.test. Nothing was changed by the vault; retry later.", retryAfter: 5 }))
    expect(response.status).toBe(502)
    expect(response.headers.get("x-should-retry")).toBeNull()
    const body = (await response.json()) as { error: string; retryAfter?: number }
    expect(body.error).toBe("upstream_failed")
    expect(body.retryAfter).toBe(5)
  })
})

describe("everything else", () => {
  test("a non-intercepted host is tunnelled byte for byte", async () => {
    const payload = Buffer.from(crypto.getRandomValues(new Uint8Array(64 * 1024)))
    const received = await withTimeout(
      new Promise<Buffer>((resolve, reject) => {
        const socket = net.connect({ host: "127.0.0.1", port: relay.port }, () => {
          socket.write(`CONNECT 127.0.0.1:${echoPort} HTTP/1.1\r\nHost: 127.0.0.1:${echoPort}\r\nProxy-Authorization: ${proxyAuth()}\r\n\r\n`)
        })
        let head = ""
        let body = Buffer.alloc(0)
        let tunnelled = false
        socket.on("data", (chunk: Buffer) => {
          if (!tunnelled) {
            head += chunk.toString("latin1")
            const end = head.indexOf("\r\n\r\n")
            if (end === -1) return
            expect(head.startsWith("HTTP/1.1 200")).toBe(true)
            tunnelled = true
            body = Buffer.from(head.slice(end + 4), "latin1")
            socket.write(payload)
            return
          }
          body = Buffer.concat([body, chunk])
          if (body.length >= payload.length) {
            socket.destroy()
            resolve(body)
          }
        })
        socket.on("error", reject)
      }),
      5000,
      "tunnel echo",
    )
    expect(received.equals(payload)).toBe(true)
  })

  test("curl reaches a non-intercepted HTTPS server with its own certificate, and the vault is never called", async () => {
    api.relayCalls.length = 0
    const result = await spawnText(["curl", "-sS", "--max-time", "10", "-x", relay.proxyUrl, "--cacert", fixtureCaFile, `https://127.0.0.1:${fixturePort}/`])
    expect(result.stderr).toBe("")
    expect(result.stdout).toBe("fixture ok")
    expect(api.relayCalls).toHaveLength(0)
  })

  test("a fenced host is refused with a 403 that says why", async () => {
    const response = await rawExchange(`CONNECT ${FENCED}:5432 HTTP/1.1\r\nProxy-Authorization: ${proxyAuth()}\r\n\r\n`)
    expect(response).toStartWith("HTTP/1.1 403")
    expect(response).toContain("Mehen-Error: 1")
    expect(response).toContain(`mehen refused a connection to ${FENCED}: that host is fenced to another environment and this run is env=dev`)
    const wildcard = await rawExchange(`CONNECT api.prod.example:443 HTTP/1.1\r\nProxy-Authorization: ${proxyAuth()}\r\n\r\n`)
    expect(wildcard).toStartWith("HTTP/1.1 403")
    const plain = await rawExchange(`GET http://${FENCED}/ HTTP/1.1\r\nHost: ${FENCED}\r\nProxy-Authorization: ${proxyAuth()}\r\n\r\n`)
    expect(plain).toStartWith("HTTP/1.1 403")
    const viaCurl = await spawnText(["curl", "-sS", "--max-time", "10", "-x", relay.proxyUrl, `https://${FENCED}/`])
    expect(viaCurl.code).not.toBe(0)
    expect(viaCurl.stderr).toContain("403")
  })

  test("the proxy password is required", async () => {
    api.relayCalls.length = 0
    const missing = await rawExchange(`CONNECT ${INTERCEPT}:443 HTTP/1.1\r\n\r\n`)
    expect(missing).toStartWith("HTTP/1.1 407")
    expect(missing).toContain("the proxy password is missing or wrong")
    const wrongUrl = new URL(relay.proxyUrl)
    wrongUrl.password = "not-the-password"
    const wrong = await rawExchange(`CONNECT 127.0.0.1:${echoPort} HTTP/1.1\r\nProxy-Authorization: ${proxyAuth(wrongUrl.href)}\r\n\r\n`)
    expect(wrong).toStartWith("HTTP/1.1 407")
    const plain = await rawExchange(`GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n`)
    expect(plain).toStartWith("HTTP/1.1 407")
    const curl = await spawnText(["curl", "-sS", "--max-time", "10", "-x", `http://127.0.0.1:${relay.port}`, "--cacert", caFile, `https://${INTERCEPT}/`])
    expect(curl.code).not.toBe(0)
    expect(curl.stderr).toContain("407")
    expect(api.relayCalls).toHaveLength(0)
  })

  test("a placeholder over plain HTTP to a non-intercepted host is refused, not sent", async () => {
    const response = await rawExchange(`GET http://127.0.0.1:${echoPort}/ HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${placeholder}\r\nProxy-Authorization: ${proxyAuth()}\r\n\r\n`)
    expect(response).toStartWith("HTTP/1.1 403")
    expect(response).toContain("surface_refused")
  })
})

// Resolves with what the relay first sends back, then hangs up.
async function firstReply(port: number, request: string): Promise<string> {
  return withTimeout(
    new Promise<string>((resolve, reject) => {
      const socket = net.connect({ host: "127.0.0.1", port }, () => socket.write(request))
      socket.once("data", (chunk: Buffer) => {
        socket.destroy()
        resolve(chunk.toString("latin1"))
      })
      socket.on("error", reject)
    }),
    5000,
    "first reply from the relay",
  )
}

describe("IP addresses", () => {
  test("a CONNECT to an IP address, in any spelling, is refused while the run has fenced or intercepted hosts", async () => {
    api.relayCalls.length = 0
    // 167772161 and 0xa.1 are 10.0.0.1; 0.0.0.0 reaches this machine on most systems.
    for (const target of ["10.0.0.1:443", "167772161:443", "0xa.1:443", "[2001:db8::1]:443", "[::ffff:10.0.0.1]:443", `0.0.0.0:${echoPort}`]) {
      const response = await rawExchange(`CONNECT ${target} HTTP/1.1\r\nProxy-Authorization: ${proxyAuth()}\r\n\r\n`)
      expect(response).toStartWith("HTTP/1.1 403")
      expect(response).toContain("environment_refused")
      expect(response).toContain("Connect by host name instead")
    }
    expect(api.relayCalls).toHaveLength(0)
  })

  test("a plain-HTTP proxy request to an IP address is refused the same way", async () => {
    for (const url of ["http://10.0.0.1/", "http://167772161/", "http://[2001:db8::1]/"]) {
      const response = await rawExchange(`GET ${url} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: ${proxyAuth()}\r\n\r\n`)
      expect(response).toStartWith("HTTP/1.1 403")
      expect(response).toContain("environment_refused")
    }
  })

  test("loopback addresses stay reachable", async () => {
    for (const target of [`127.0.0.1:${echoPort}`, `127.1:${echoPort}`, `2130706433:${echoPort}`]) {
      expect(await firstReply(relay.port, `CONNECT ${target} HTTP/1.1\r\nProxy-Authorization: ${proxyAuth()}\r\n\r\n`)).toStartWith("HTTP/1.1 200")
    }
    // The echo server listens on IPv4, so [::1] may get only as far as a failed connect: never the address refusal.
    for (const target of [`[::1]:${echoPort}`, `[::ffff:127.0.0.1]:${echoPort}`]) {
      expect(await firstReply(relay.port, `CONNECT ${target} HTTP/1.1\r\nProxy-Authorization: ${proxyAuth()}\r\n\r\n`)).not.toContain("403")
    }
    // The echo server sends the forwarded request straight back.
    const plain = await firstReply(relay.port, `GET http://127.0.0.1:${echoPort}/ HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: ${proxyAuth()}\r\n\r\n`)
    expect(plain).toStartWith("GET / HTTP/1.1")
  })

  test("an intercepted address is intercepted as written, and refused in any other spelling", async () => {
    const boundCa = await createRunCa(["10.1.2.3"])
    const bound = await startLocalRelay({ api, run: "run_test2", env: "dev", interceptHosts: ["10.1.2.3"], fencedHosts: [], baseUrls: [], ca: boundCa })
    try {
      const auth = proxyAuth(bound.proxyUrl)
      expect(await firstReply(bound.port, `CONNECT 10.1.2.3:443 HTTP/1.1\r\nProxy-Authorization: ${auth}\r\n\r\n`)).toStartWith("HTTP/1.1 200")
      expect(await firstReply(bound.port, `CONNECT 167838211:443 HTTP/1.1\r\nProxy-Authorization: ${auth}\r\n\r\n`)).toStartWith("HTTP/1.1 403")
      expect(await firstReply(bound.port, `CONNECT 10.9.9.9:443 HTTP/1.1\r\nProxy-Authorization: ${auth}\r\n\r\n`)).toStartWith("HTTP/1.1 403")
    } finally {
      await bound.close()
    }
  })

  test("with no fenced or intercepted hosts, addresses are tunnelled as before", async () => {
    const open = await startLocalRelay({ api, run: "run_test3", env: "dev", interceptHosts: [], fencedHosts: [], baseUrls: [], ca: null })
    try {
      expect(await firstReply(open.port, `CONNECT 0.0.0.0:${echoPort} HTTP/1.1\r\nProxy-Authorization: ${proxyAuth(open.proxyUrl)}\r\n\r\n`)).toStartWith("HTTP/1.1 200")
    } finally {
      await open.close()
    }
  })
})

describe("base-URL path", () => {
  test("forwards bound to the run, never item mode, with the upstream URL rebuilt and no Authorization or Host", async () => {
    api.relayCalls.length = 0
    const base = relay.baseUrl("openai-personal")
    expect(base).toMatch(new RegExp(`^http://127\\.0\\.0\\.1:${relay.port}/r/[A-Za-z0-9_-]+/openai-personal/v1$`))
    const response = await withTimeout(
      fetch(`${base}/chat/completions?stream=true`, { method: "POST", headers: { authorization: `Bearer ${placeholder}`, "content-type": "application/json" }, body: '{"model":"x"}' }),
      5000,
      "base-URL request",
    )
    expect(response.status).toBe(200)
    expect(api.relayCalls).toHaveLength(1)
    const call = api.relayCalls[0]
    expect(call?.run).toBe("run_test1")
    expect(call?.item).toBeUndefined()
    expect(call?.url).toBe("https://api.openai.com/v1/chat/completions?stream=true")
    expect(call?.headers.some(([name]) => ["authorization", "host"].includes(name.toLowerCase()))).toBe(false)
    expect(header(call?.headers, "content-type")).toBe("application/json")
    expect(Buffer.from(call?.body ?? "", "base64url").toString()).toBe('{"model":"x"}')
  })

  test("also works through the proxy, as clients with NO_PROXY empty send it", async () => {
    api.relayCalls.length = 0
    const result = await spawnText(["curl", "-sS", "--max-time", "10", "-x", relay.proxyUrl, `${relay.baseUrl("openai-personal")}/models`])
    expect(result.code).toBe(0)
    expect(api.relayCalls[0]?.url).toBe("https://api.openai.com/v1/models")
    expect(api.relayCalls[0]?.run).toBe("run_test1")
    expect(api.relayCalls[0]?.item).toBeUndefined()
  })

  test("a server refusal of base-URL delivery is returned without falling back to item mode", async () => {
    api.relayCalls.length = 0
    api.relayHandler = () => {
      throw new VaultApiError(400, { error: "bad_request", message: "No run placeholder.", next: { say: "Use the placeholder key instead." } })
    }
    try {
      const response = await withTimeout(fetch(`${relay.baseUrl("openai-personal")}/models`), 5000, "base-URL refusal")
      expect(response.status).toBe(400)
      expect(response.headers.get("mehen-error")).toBe("1")
      expect(await response.json()).toMatchObject({ next: { say: "Use the placeholder key instead." } })
      expect(api.relayCalls).toHaveLength(1)
      expect(api.relayCalls[0]?.run).toBe("run_test1")
      expect(api.relayCalls[0]?.item).toBeUndefined()
    } finally {
      api.relayHandler = (request) => Response.json({ echoed: request }, { headers: { "Mehen-Upstream": "1" } })
    }
  })

  test("a wrong run secret, an unknown item and an escaping path are refused", async () => {
    api.relayCalls.length = 0
    const good = runSecretPath("openai-personal")
    const wrongSecret = good.replace(/\/r\/[^/]+\//, "/r/wrong-secret/")
    expect((await rawExchange(`GET ${wrongSecret}/models HTTP/1.1\r\nHost: x\r\n\r\n`))).toStartWith("HTTP/1.1 403")
    expect((await rawExchange(`GET ${good.replace("openai-personal", "other-item")}/models HTTP/1.1\r\nHost: x\r\n\r\n`))).toStartWith("HTTP/1.1 404")
    for (const escape of ["/../../other-item/v1", "/%2e%2e/x", "/a%2fb", "//admin", "/a\\b"]) {
      const response = await rawExchange(`GET ${good}${escape} HTTP/1.1\r\nHost: x\r\n\r\n`)
      expect(response).toStartWith("HTTP/1.1 400")
    }
    expect((await rawExchange("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))).toStartWith("HTTP/1.1 404")
    expect(api.relayCalls).toHaveLength(0)
  })

  test("a path with an encoded ? or # is forwarded as sent, for the vault's rules to meet it cut there", async () => {
    const good = runSecretPath("openai-personal")
    for (const path of ["/repos/o/r/git/refs/heads/fix%23123", "/files/user%231", "/keys%3Fx", "/delete%3F/send"]) {
      api.relayCalls.length = 0
      expect(await rawExchange(`GET ${good}${path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`), path).toStartWith("HTTP/1.1 200")
      expect(api.relayCalls.map((call) => call.url)).toEqual([`https://api.openai.com/v1${path}`])
    }
  })
})
