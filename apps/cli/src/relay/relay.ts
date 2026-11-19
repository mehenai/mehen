// The local relay for one `mehen run`: an authenticated forward proxy on
// 127.0.0.1 plus the base-URL endpoint.
//
//   CONNECT to an intercept host: TLS terminated with a leaf from the run CA,
//     every request forwarded to the vault relay (POST /v1/relay with `run`)
//     with its placeholders intact. The vault swaps them, or refuses.
//   CONNECT to a fenced host: refused with a 403 that says why.
//   CONNECT to an IP address, while the run has fenced or intercepted
//     hosts: refused unless that address is itself intercepted, since an
//     address can belong to a fenced host. Loopback is exempt.
//   CONNECT to anything else: an opaque tunnel, byte for byte.
//   /r/<run-secret>/<item>/...: the base-URL path, forwarded to the vault
//     relay bound to `run` and no CA at all. Base-URL delivery stays
//     unavailable until the vault can authorise its item within the run.
//
// This process never holds a secret value and never swaps a placeholder.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto"
import net from "node:net"
import tls from "node:tls"
import type { Duplex } from "node:stream"
import { ERROR_HEADER, containsPlaceholder, hostMatches, parseDestination } from "@mehen/protocol"
import type { ErrorCode, RelayRequestInput } from "@mehen/protocol/api"
import { errorBody, outcomeUnknown } from "../errors.ts"
import { RelayOutcomeUnknownError, RelayUnmarkedAnswerError, VaultApiError, type VaultApi, retrySafeMethod } from "../vault-api.ts"
import type { RunCa } from "./ca.ts"
import {
  type HttpHead,
  HttpFramingError,
  SocketReader,
  hasToken,
  headerValues,
  parseHead,
  readBody,
  removeHeader,
  requestFraming,
  serialiseRequestHead,
  writeWithBackpressure,
} from "./http1.ts"

// 10 MiB of body is just under the vault relay's 14 MB base64url limit.
const MAX_RELAY_BODY = 10 * 1024 * 1024
const PROXY_USER = "mehen"

export type BaseUrlRoute = {
  item: string
  // The upstream base URL the vault delivered, e.g. "https://api.openai.com/v1".
  upstream: string
}

export type LocalRelayOptions = {
  api: VaultApi
  run: string
  env: string
  interceptHosts: readonly string[]
  fencedHosts: readonly string[]
  baseUrls: readonly BaseUrlRoute[]
  // Null when nothing is intercepted: every CONNECT is then tunnelled or fenced.
  ca: RunCa | null
}

export type LocalRelay = {
  port: number
  // http://mehen:<proxy password>@127.0.0.1:<port>
  proxyUrl: string
  // http://127.0.0.1:<port>/r/<run secret>/<item><upstream path>
  baseUrl(item: string): string
  close(): Promise<void>
}

type Authority = { host: string; port: number }

type Refusal = { status: number; error: ErrorCode; message: string }

type Routed = { relay: Omit<RelayRequestInput, "body"> } | { refuse: Refusal }

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-connection",
  "proxy-authorization",
  "proxy-authenticate",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "expect",
])

const RESPONSE_DROP = new Set(["connection", "keep-alive", "transfer-encoding", "content-length", "trailer", "upgrade", "proxy-authenticate"])

function digest(text: string): Buffer {
  return createHash("sha256").update(text).digest()
}

function sameSecret(presented: string, expected: string): boolean {
  return timingSafeEqual(digest(presented), digest(expected))
}

function refusalBody(refusal: Refusal): string {
  return JSON.stringify({ error: refusal.error, message: refusal.message })
}

function rawRefusal(refusal: Refusal, extraHeaders = ""): string {
  const body = refusalBody(refusal)
  const reason = refusal.status === 407 ? "Proxy Authentication Required" : "Refused"
  return (
    `HTTP/1.1 ${refusal.status} ${reason}\r\n${extraHeaders}content-type: application/json\r\n${ERROR_HEADER}: 1\r\n` +
    `content-length: ${Buffer.byteLength(body)}\r\nconnection: close\r\n\r\n${body}`
  )
}

function parseAuthority(target: string): Authority | null {
  const match = target.match(/^(\[[0-9a-fA-F:.]+\]|[^:[\]/]+):(\d{1,5})$/)
  if (!match?.[1] || !match[2]) return null
  const port = Number(match[2])
  if (port < 1 || port > 65535) return null
  return { host: match[1].replace(/^\[|\]$/g, "").toLowerCase().replace(/\.$/, ""), port }
}

function urlHost(host: string): string {
  return net.isIPv6(host) ? `[${host}]` : host
}

// The address a host names when it is an IP literal in any spelling the
// resolver accepts ("2130706433", "0x7f.1", "[::ffff:127.0.0.1]"), else null.
function ipLiteral(host: string): string | null {
  let canonical: string
  try {
    canonical = new URL(`http://${urlHost(host)}/`).hostname.replace(/^\[|\]$/g, "")
  } catch {
    return net.isIP(host) === 0 ? null : host
  }
  return net.isIP(canonical) === 0 ? null : canonical
}

// 127.0.0.0/8 and ::1, plain or IPv4-mapped, from ipLiteral's canonical form.
function isLoopback(address: string): boolean {
  if (net.isIPv4(address)) return address.startsWith("127.")
  return address === "::1" || /^::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}$/.test(address)
}

// Headers the vault may forward upstream: hop-by-hop headers, Host and the
// framing headers go; so does anything the Connection header names.
function forwardableHeaders(head: HttpHead, drop: readonly string[] = []): [string, string][] {
  const named = new Set(
    headerValues(head, "connection")
      .flatMap((value) => value.split(","))
      .map((name) => name.trim().toLowerCase()),
  )
  return head.headers.filter(([name]) => {
    const lower = name.toLowerCase()
    return !HOP_BY_HOP.has(lower) && !named.has(lower) && !drop.includes(lower)
  })
}

function errorResponse(refusal: Refusal): Response {
  return new Response(refusalBody(refusal), {
    status: refusal.status,
    headers: { "content-type": "application/json", [ERROR_HEADER]: "1" },
  })
}

// A failed write that may still have reached the upstream: anything but a
// readable refusal the vault made before forwarding (HttpVaultApi.relay),
// whatever its status, and any answer something in front of the vault sent.
function writeOutcomeUnknown(error: unknown): error is Error {
  if (error instanceof RelayOutcomeUnknownError) return true
  if (error instanceof RelayUnmarkedAnswerError) return true
  return error instanceof VaultApiError && error.body.error === "upstream_failed"
}

async function writeResponse(socket: Duplex, method: string, response: Response, close: boolean): Promise<void> {
  let head = `HTTP/1.1 ${response.status} ${response.statusText || "Status"}\r\n`
  response.headers.forEach((value, name) => {
    if (RESPONSE_DROP.has(name) || name === "set-cookie") return
    head += `${name}: ${value}\r\n`
  })
  for (const cookie of response.headers.getSetCookie()) head += `set-cookie: ${cookie}\r\n`
  const bodiless = method === "HEAD" || response.status === 204 || response.status === 304 || response.status < 200
  if (!bodiless) head += "transfer-encoding: chunked\r\n"
  if (close) head += "connection: close\r\n"
  await writeWithBackpressure(socket, Buffer.from(`${head}\r\n`, "latin1"))
  if (bodiless) {
    await response.body?.cancel()
    return
  }
  if (response.body !== null) {
    const reader = response.body.getReader()
    try {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        if (value.length === 0) continue
        await writeWithBackpressure(socket, Buffer.concat([Buffer.from(`${value.length.toString(16)}\r\n`), value, Buffer.from("\r\n")]))
      }
    } catch (error) {
      // The answer broke after its head went out: never the last chunk, so
      // the program reads an incomplete body, as a write that may have
      // landed must be read, and not a clean end.
      await reader.cancel().catch(() => {})
      socket.destroy()
      throw error
    }
  }
  await writeWithBackpressure(socket, "0\r\n\r\n")
}

export async function startLocalRelay(options: LocalRelayOptions): Promise<LocalRelay> {
  const proxyPassword = randomBytes(24).toString("base64url")
  const runSecret = randomBytes(24).toString("base64url")
  const expectedProxyAuth = `Basic ${Buffer.from(`${PROXY_USER}:${proxyPassword}`).toString("base64")}`
  const contexts = new Map<string, Promise<tls.SecureContext>>()
  const sockets = new Set<net.Socket | tls.TLSSocket>()
  const ca = options.ca
  let port = 0

  const isFenced = (host: string) => options.fencedHosts.some((pattern) => hostMatches(pattern, host))
  const isIntercepted = (host: string) => ca !== null && options.interceptHosts.some((pattern) => hostMatches(pattern, host))
  const guardsHosts = options.fencedHosts.length > 0 || options.interceptHosts.length > 0
  const isRefusedAddress = (host: string) => {
    const address = guardsHosts ? ipLiteral(host) : null
    return address !== null && !isLoopback(address) && !isIntercepted(host)
  }
  const addressRefusal = (host: string): Refusal => ({
    status: 403,
    error: "environment_refused",
    message:
      `mehen refused a connection to the address ${host}: this run has fenced or intercepted hosts, and an address could belong to one of them. ` +
      `Nothing was sent. Connect by host name instead, or ask a human to bind that address in the vault.`,
  })
  const fencedRefusal = (host: string): Refusal => ({
    status: 403,
    error: "environment_refused",
    message:
      `mehen refused a connection to ${host}: that host is fenced to another environment and this run is env=${options.env}. ` +
      `Nothing was sent. Run with the environment that host belongs to (mehen run --env <env>), or ask a human to change the fence in the vault.`,
  })

  function secureContextFor(host: string): Promise<tls.SecureContext> {
    let pending = contexts.get(host)
    if (pending === undefined) {
      if (ca === null) throw new Error("no run CA")
      pending = ca.issueLeaf(host).then((leaf) => tls.createSecureContext({ cert: leaf.certPem, key: leaf.keyPem }))
      contexts.set(host, pending)
    }
    return pending
  }

  function routeBaseUrl(head: HttpHead): Routed {
    const [path = "", ...queryParts] = head.target.split("?")
    const query = queryParts.length > 0 ? `?${queryParts.join("?")}` : ""
    const segments = path.split("/")
    const [, prefix, secret, item] = segments
    if (prefix !== "r" || secret === undefined || item === undefined) {
      return {
        refuse: {
          status: 404,
          error: "not_found",
          message: "This is the mehen local relay. Base URLs look like /r/<run-secret>/<item>/...; use the one mehen run put in your environment.",
        },
      }
    }
    if (!sameSecret(secret, runSecret)) {
      return { refuse: { status: 403, error: "forbidden", message: "The run secret in this URL is wrong. Use the base URL mehen run put in your environment; it is valid for this run only." } }
    }
    const route = options.baseUrls.find((candidate) => candidate.item === item)
    if (route === undefined) {
      return { refuse: { status: 404, error: "not_found", message: `This run has no base URL for the item ${item}.` } }
    }
    const rest = `/${segments.slice(4).join("/")}`
    const url = `${new URL(route.upstream).origin}${rest}${query}`
    // Dot segments, empty segments and encoded slashes could step outside the
    // item prefix or be read differently upstream: refuse them as written and as built.
    if (!parseDestination(head.method, `http://127.0.0.1${head.target}`).ok || !parseDestination(head.method, url).ok) {
      return {
        refuse: {
          status: 400,
          error: "bad_request",
          message: "mehen refused this path: dot segments, empty segments, backslashes and encoded slashes or dots are not allowed.",
        },
      }
    }
    return { relay: { run: options.run, method: head.method, url, headers: forwardableHeaders(head, ["authorization"]) } }
  }

  function routeIntercepted(head: HttpHead, authority: Authority): Routed {
    let pathAndQuery = head.target
    if (!pathAndQuery.startsWith("/")) {
      try {
        const parsed = new URL(pathAndQuery)
        pathAndQuery = `${parsed.pathname}${parsed.search}`
      } catch {
        return { refuse: { status: 400, error: "bad_request", message: "mehen could not read the request target." } }
      }
    }
    // The URL comes from the CONNECT authority, never from a Host header.
    const origin = `https://${urlHost(authority.host)}${authority.port === 443 ? "" : `:${authority.port}`}`
    return { relay: { run: options.run, method: head.method, url: `${origin}${pathAndQuery}`, headers: forwardableHeaders(head) } }
  }

  async function callVault(relay: Omit<RelayRequestInput, "body">, body: Buffer): Promise<Response> {
    try {
      return await options.api.relay({ ...relay, ...(body.length > 0 ? { body: body.toString("base64url") } : {}) })
    } catch (error) {
      // 424, not a 5xx, and both should-retry headers: SDKs retry a 5xx on
      // their own, and repeating this write could do it twice.
      if (!retrySafeMethod(relay.method) && writeOutcomeUnknown(error)) {
        return new Response(JSON.stringify(errorBody(outcomeUnknown(error.message))), {
          status: 424,
          headers: { "content-type": "application/json", [ERROR_HEADER]: "1", "x-should-retry": "false", "stripe-should-retry": "false" },
        })
      }
      if (error instanceof VaultApiError) {
        return new Response(JSON.stringify(error.body), { status: error.status, headers: { "content-type": "application/json", [ERROR_HEADER]: "1" } })
      }
      const message = error instanceof Error ? error.message : String(error)
      return errorResponse({ status: 502, error: "upstream_failed", message: `mehen could not reach the vault: ${message}. Check the network and try again.` })
    }
  }

  async function serveRequests(socket: Duplex, reader: SocketReader, first: HttpHead | null, route: (head: HttpHead) => Routed, oneRequest: boolean): Promise<void> {
    let head = first
    try {
      for (;;) {
        if (head === null) {
          const raw = await reader.readHead()
          if (raw === null) break
          head = parseHead(raw)
        }
        if (headerValues(head, "upgrade").length > 0) {
          const refusal: Refusal = { status: 501, error: "bad_request", message: "The mehen local relay does not carry WebSocket or other protocol upgrades to intercepted hosts." }
          await writeWithBackpressure(socket, rawRefusal(refusal))
          break
        }
        const routed = route(head)
        if ("refuse" in routed) {
          await writeWithBackpressure(socket, rawRefusal(routed.refuse))
          break
        }
        const framing = requestFraming(head)
        if (framing.kind !== "none" && hasToken(head, "expect", "100-continue")) await writeWithBackpressure(socket, "HTTP/1.1 100 Continue\r\n\r\n")
        const body = await readBody(reader, framing, MAX_RELAY_BODY)
        const response = await callVault(routed.relay, body)
        const close = oneRequest || head.version === "HTTP/1.0" || hasToken(head, "connection", "close")
        await writeResponse(socket, head.method, response, close)
        if (close) break
        head = null
      }
    } catch (error) {
      if (error instanceof HttpFramingError && !socket.destroyed) {
        const refusal: Refusal = { status: error.status, error: error.status === 413 ? "too_large" : "bad_request", message: `mehen local relay: ${error.message}.` }
        await writeWithBackpressure(socket, rawRefusal(refusal)).catch(() => {})
      }
    }
    socket.end()
  }

  function tunnel(client: net.Socket, authority: Authority, leftover: Buffer): void {
    const upstream = net.connect({ host: authority.host, port: authority.port })
    sockets.add(upstream)
    upstream.once("connect", () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n")
      if (leftover.length > 0) upstream.write(leftover)
      client.pipe(upstream)
      upstream.pipe(client)
      client.resume()
    })
    upstream.on("error", () => {
      if (!client.writableEnded) client.end(`HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n`)
    })
    client.on("error", () => upstream.destroy())
    client.on("close", () => upstream.destroy())
    upstream.on("close", () => {
      sockets.delete(upstream)
      client.destroy()
    })
  }

  async function intercept(raw: net.Socket, authority: Authority, leftover: Buffer): Promise<void> {
    // The leaf is ready before the 200 goes out, so the TLS wrap happens before
    // the ClientHello can arrive: unread bytes on an unwrapped socket are lost.
    const context = await secureContextFor(authority.host)
    raw.write("HTTP/1.1 200 Connection Established\r\n\r\n")
    raw.unshift(leftover)
    const client = new tls.TLSSocket(raw, {
      isServer: true,
      secureContext: context,
      ALPNProtocols: ["http/1.1"],
      // SNI, when present, must name the CONNECT host: no domain fronting.
      SNICallback: (servername, callback) => {
        if (servername.toLowerCase() !== authority.host) callback(new Error(`SNI ${servername} does not match CONNECT ${authority.host}`), undefined)
        else callback(null, context)
      },
    })
    sockets.add(client)
    client.on("close", () => sockets.delete(client))
    client.on("error", () => {})
    const secured = await new Promise<boolean>((resolve) => {
      client.once("secure", () => resolve(true))
      client.once("error", () => resolve(false))
      client.once("close", () => resolve(false))
    })
    if (!secured) {
      client.destroy()
      return
    }
    await serveRequests(client, new SocketReader(client), null, (head) => routeIntercepted(head, authority), false)
  }

  async function forwardPlainHttp(client: net.Socket, reader: SocketReader, head: HttpHead): Promise<void> {
    let url: URL
    try {
      url = new URL(head.target)
    } catch {
      client.end(rawRefusal({ status: 400, error: "bad_request", message: "mehen local relay: the proxy request target is not a URL." }))
      return
    }
    if (url.protocol !== "http:") {
      client.end(rawRefusal({ status: 400, error: "bad_request", message: "mehen local relay: only http:// URLs go through as proxy requests; HTTPS uses CONNECT." }))
      return
    }
    const authority: Authority = { host: url.hostname.replace(/^\[|\]$/g, "").toLowerCase(), port: url.port === "" ? 80 : Number(url.port) }
    const originForm: HttpHead = { ...head, target: `${url.pathname}${url.search}` }
    if ((authority.host === "127.0.0.1" || authority.host === "localhost") && authority.port === port) {
      await serveRequests(client, reader, originForm, routeBaseUrl, true)
      return
    }
    if (isFenced(authority.host)) {
      client.end(rawRefusal(fencedRefusal(authority.host)))
      return
    }
    if (isRefusedAddress(authority.host)) {
      client.end(rawRefusal(addressRefusal(authority.host)))
      return
    }
    if (isIntercepted(authority.host)) {
      // The vault decides what a placeholder may do over plain HTTP.
      const route = (h: HttpHead): Routed => ({ relay: { run: options.run, method: h.method, url: url.href, headers: forwardableHeaders(h) } })
      await serveRequests(client, reader, head, route, true)
      return
    }
    if (containsPlaceholder(head.target) || head.headers.some(([, value]) => containsPlaceholder(value))) {
      client.end(
        rawRefusal({
          status: 403,
          error: "surface_refused",
          message: `mehen refused to send a credential placeholder over plain HTTP to ${authority.host}. Placeholders only work over HTTPS to the hosts the vault bound them to. Nothing was sent.`,
        }),
      )
      return
    }
    removeHeader(originForm, "proxy-authorization")
    removeHeader(originForm, "proxy-connection")
    removeHeader(originForm, "connection")
    originForm.headers.push(["Connection", "close"])
    const leftover = reader.detach()
    const upstream = net.connect({ host: authority.host, port: authority.port }, () => {
      upstream.write(serialiseRequestHead(originForm))
      if (leftover.length > 0) upstream.write(leftover)
      client.pipe(upstream)
      upstream.pipe(client)
      client.resume()
    })
    sockets.add(upstream)
    upstream.on("error", () => client.destroy())
    upstream.on("close", () => sockets.delete(upstream))
    client.on("close", () => upstream.destroy())
  }

  async function handleClient(socket: net.Socket): Promise<void> {
    const reader = new SocketReader(socket)
    let head: HttpHead
    try {
      const raw = await reader.readHead()
      if (raw === null) {
        socket.destroy()
        return
      }
      head = parseHead(raw)
    } catch (error) {
      const status = error instanceof HttpFramingError ? error.status : 400
      socket.end(rawRefusal({ status, error: "bad_request", message: "mehen local relay: malformed request." }))
      return
    }
    if (head.target.startsWith("/")) {
      await serveRequests(socket, reader, head, routeBaseUrl, false)
      return
    }
    if (!sameSecret(headerValues(head, "proxy-authorization")[0] ?? "", expectedProxyAuth)) {
      socket.end(
        rawRefusal(
          {
            status: 407,
            error: "unauthenticated",
            message: "mehen local relay: the proxy password is missing or wrong. Use the HTTPS_PROXY mehen run set; it is valid for this run only.",
          },
          'proxy-authenticate: Basic realm="mehen"\r\n',
        ),
      )
      return
    }
    if (head.method !== "CONNECT") {
      await forwardPlainHttp(socket, reader, head)
      return
    }
    const authority = parseAuthority(head.target)
    if (authority === null) {
      socket.end(rawRefusal({ status: 400, error: "bad_request", message: "mehen local relay: CONNECT needs host:port." }))
      return
    }
    if (isFenced(authority.host)) {
      socket.end(rawRefusal(fencedRefusal(authority.host)))
      return
    }
    if (isRefusedAddress(authority.host)) {
      socket.end(rawRefusal(addressRefusal(authority.host)))
      return
    }
    const leftover = reader.detach()
    if (isIntercepted(authority.host)) await intercept(socket, authority, leftover)
    else tunnel(socket, authority, leftover)
  }

  const server = net.createServer((socket) => {
    sockets.add(socket)
    socket.on("close", () => sockets.delete(socket))
    socket.on("error", () => {})
    handleClient(socket).catch(() => socket.destroy())
  })
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", resolve)
  })
  const address = server.address()
  if (address === null || typeof address === "string") throw new Error("the local relay did not get a port")
  port = address.port
  const routes = new Map(options.baseUrls.map((route) => [route.item, route]))

  return {
    port,
    proxyUrl: `http://${PROXY_USER}:${proxyPassword}@127.0.0.1:${port}`,
    baseUrl(item) {
      const route = routes.get(item)
      if (route === undefined) throw new Error(`no base URL route for ${item}`)
      const path = new URL(route.upstream).pathname.replace(/\/+$/, "")
      return `http://127.0.0.1:${port}/r/${runSecret}/${item}${path}`
    },
    close: () =>
      new Promise<void>((resolve) => {
        for (const socket of sockets) socket.destroy()
        server.close(() => resolve())
      }),
  }
}
