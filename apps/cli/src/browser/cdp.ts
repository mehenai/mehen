// mehen fill's Chrome DevTools Protocol client, over the runtime's own
// WebSocket. Only a browser-level endpoint is accepted: it is the one that
// sees every page and out-of-process frame (Target.setAutoAttach); a page
// endpoint sees one process's frames only. Sessions are flattened: every
// message names its sessionId on the one connection.

import { constants } from "node:fs"
import { type FileHandle, lstat, open } from "node:fs/promises"
import { join } from "node:path"
import { CliError } from "../errors.ts"

export const CDP_TIMEOUT_MS = 10_000

// Where the browser is: a URL (--cdp) or a Chrome profile directory whose
// DevToolsActivePort names it (--user-data-dir).
export type CdpSource = { cdp: string } | { userDataDir: string }

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "localhost"])
const BROWSER_PATH = /^\/devtools\/browser\/[A-Za-z0-9._-]{1,128}$/
const PAGE_PATH = /^\/devtools\/page\//

export function cdpRefused(message: string): CliError {
  return new CliError("cdp_refused", message, {
    command: "mehen fill --help",
    say: "Give the browser's own endpoint: ws://127.0.0.1:<port>/devtools/browser/<id>, http://127.0.0.1:<port>, a wss:// URL from a cloud browser, or --user-data-dir <profile>.",
  })
}

export function cdpUnreachable(message: string): CliError {
  return new CliError("cdp_unreachable", message, {
    say: "Check that the browser is running with remote debugging on and that the endpoint is current (it changes each time Chrome starts), then retry.",
  })
}

// A loopback browser-level ws:// URL, as Chrome prints it; anything else is
// refused. `from` names where the URL came from, for the message.
function loopbackBrowserUrl(url: URL, from: string): string {
  if (!LOOPBACK_HOSTS.has(url.hostname)) throw cdpRefused(`${from} is a ws:// endpoint on another host. Only a browser on this machine (127.0.0.1, [::1] or localhost) is reached over plain ws://; a remote browser needs wss://.`)
  if (PAGE_PATH.test(url.pathname)) throw cdpRefused(`${from} is a page's endpoint (/devtools/page/...). mehen needs the browser's own endpoint (/devtools/browser/...), which sees every frame of the page.`)
  if (url.port === "" || url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "" || !BROWSER_PATH.test(url.pathname)) throw cdpRefused(`${from} is not a browser endpoint of the form ws://127.0.0.1:<port>/devtools/browser/<id>.`)
  return url.href
}

// The browser-level WebSocket URL for a source. Chrome's /json/version and
// DevToolsActivePort answers are held to the same rules as a URL given
// directly. A message never repeats a wss:// URL, whose query may carry a
// cloud browser's key.
export async function cdpEndpoint(source: CdpSource, options: { timeoutMs?: number } = {}): Promise<string> {
  const timeoutMs = options.timeoutMs ?? CDP_TIMEOUT_MS
  if ("userDataDir" in source) return endpointFromProfile(source.userDataDir)
  let url: URL
  try {
    url = new URL(source.cdp)
  } catch {
    throw cdpRefused("--cdp is not a URL.")
  }
  if (url.protocol === "ws:") return loopbackBrowserUrl(url, "--cdp")
  if (url.protocol === "wss:") {
    if (PAGE_PATH.test(url.pathname)) throw cdpRefused(`--cdp names a page's endpoint on ${url.host} (/devtools/page/...). mehen needs the browser's own endpoint.`)
    return url.href
  }
  if (url.protocol === "http:") {
    if (url.hostname !== "127.0.0.1" || url.port === "" || url.username !== "" || url.password !== "" || (url.pathname !== "/" && url.pathname !== "") || url.search !== "" || url.hash !== "") {
      throw cdpRefused("An http:// endpoint must be exactly http://127.0.0.1:<port>, Chrome's remote debugging port on this machine.")
    }
    return endpointFromVersion(url.origin, timeoutMs)
  }
  throw cdpRefused(`--cdp must be a ws://, wss:// or http:// endpoint, not ${url.protocol}`)
}

async function endpointFromVersion(origin: string, timeoutMs: number): Promise<string> {
  let answer: unknown
  try {
    const response = await fetch(`${origin}/json/version`, { signal: AbortSignal.timeout(timeoutMs), redirect: "manual" })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    answer = await response.json()
  } catch (error) {
    throw cdpUnreachable(`No browser answered at ${origin}/json/version: ${(error as Error).message}.`)
  }
  const ws = typeof answer === "object" && answer !== null ? (answer as { webSocketDebuggerUrl?: unknown }).webSocketDebuggerUrl : undefined
  if (typeof ws !== "string") throw cdpUnreachable(`${origin}/json/version named no webSocketDebuggerUrl, so it is not a Chrome remote debugging port.`)
  let url: URL
  try {
    url = new URL(ws)
  } catch {
    throw cdpUnreachable(`${origin}/json/version named a webSocketDebuggerUrl that is not a URL.`)
  }
  if (url.protocol !== "ws:") throw cdpRefused(`${origin}/json/version named a ${url.protocol} endpoint; only ws:// on this machine is accepted from it.`)
  return loopbackBrowserUrl(url, `The endpoint ${origin}/json/version named`)
}

const MAX_ACTIVE_PORT_BYTES = 256

// DevToolsActivePort as Chrome writes it: a regular file of a few bytes. A
// symbolic link is refused (lstat, then O_NOFOLLOW for the race), and so is
// a FIFO or device, which could block the read; O_NONBLOCK covers the race.
async function readActivePort(file: string): Promise<string> {
  const refuse = (why: string) => cdpUnreachable(`mehen will not read ${file}: ${why}.`)
  try {
    const info = await lstat(file)
    if (info.isSymbolicLink()) throw refuse("it is a symbolic link, not the file Chrome writes")
    if (!info.isFile()) throw refuse("it is not a regular file")
  } catch (error) {
    if (error instanceof CliError) throw error
    if ((error as { code?: string }).code === "ENOENT") throw cdpUnreachable(`${file} does not exist: no Chrome is running with remote debugging on for that profile.`)
    throw cdpUnreachable(`Cannot read ${file}: ${(error as Error).message}`)
  }
  let handle: FileHandle
  try {
    handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0))
  } catch (error) {
    if ((error as { code?: string }).code === "ELOOP") throw refuse("it is a symbolic link, not the file Chrome writes")
    throw cdpUnreachable(`Cannot read ${file}: ${(error as Error).message}`)
  }
  try {
    if (!(await handle.stat()).isFile()) throw refuse("it is not a regular file")
    const buffer = new Uint8Array(MAX_ACTIVE_PORT_BYTES + 1)
    let length = 0
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null)
      if (bytesRead === 0) break
      length += bytesRead
    }
    if (length > MAX_ACTIVE_PORT_BYTES) throw refuse(`it is larger than ${MAX_ACTIVE_PORT_BYTES} bytes, which no DevToolsActivePort is`)
    return new TextDecoder().decode(buffer.subarray(0, length))
  } finally {
    await handle.close()
  }
}

// DevToolsActivePort: the port on the first line, the browser's path on the
// second. Chrome writes it when started with --remote-debugging-port.
async function endpointFromProfile(dir: string): Promise<string> {
  const file = join(dir, "DevToolsActivePort")
  const text = await readActivePort(file)
  const [port = "", path = ""] = text.split(/\r?\n/)
  const number = /^\d{1,5}$/.test(port) ? Number(port) : 0
  if (number < 1 || number > 65535 || !BROWSER_PATH.test(path)) throw cdpUnreachable(`${file} does not name a port and a browser endpoint.`)
  return `ws://127.0.0.1:${number}${path}`
}

export type CdpEvent = { method: string; params: Record<string, unknown>; sessionId: string | null }

// A protocol error Chrome answered for one call. Its text is Chrome's,
// never the call's parameters.
export class CdpCallError extends Error {
  readonly method: string
  constructor(method: string, message: string) {
    super(`${method}: ${message}`)
    this.method = method
    this.name = "CdpCallError"
  }
}

type Pending = { method: string; resolve(value: unknown): void; reject(error: Error): void; timer: ReturnType<typeof setTimeout> }

export class CdpConnection {
  private readonly socket: WebSocket
  private readonly pending = new Map<number, Pending>()
  private readonly listeners = new Set<(event: CdpEvent) => void>()
  private nextId = 1
  private closedWith: CliError | null = null

  private constructor(socket: WebSocket) {
    this.socket = socket
    socket.addEventListener("message", (event) => this.receive(event.data))
    socket.addEventListener("close", () => this.fail(cdpUnreachable("The browser closed the DevTools connection.")))
  }

  static async open(url: string, timeoutMs = CDP_TIMEOUT_MS): Promise<CdpConnection> {
    const where = new URL(url).host
    let socket: WebSocket
    try {
      socket = new WebSocket(url)
    } catch (error) {
      throw cdpUnreachable(`Could not connect to the browser at ${where}: ${(error as Error).message}`)
    }
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        socket.close()
        reject(cdpUnreachable(`The browser at ${where} did not accept a DevTools connection within ${Math.round(timeoutMs / 1000)} s.`))
      }, timeoutMs)
      socket.addEventListener("open", () => {
        clearTimeout(timer)
        resolve()
      })
      socket.addEventListener("error", () => {
        clearTimeout(timer)
        reject(cdpUnreachable(`Could not connect to the browser at ${where}.`))
      })
      socket.addEventListener("close", () => {
        clearTimeout(timer)
        reject(cdpUnreachable(`The browser at ${where} closed the DevTools connection before it opened.`))
      })
    })
    return new CdpConnection(socket)
  }

  // One call. A timeout or a closed connection is cdp_unreachable; Chrome's
  // own refusal is a CdpCallError for the caller to read.
  send<T = Record<string, unknown>>(method: string, params: Record<string, unknown> = {}, options: { sessionId?: string; timeoutMs?: number } = {}): Promise<T> {
    if (this.closedWith) return Promise.reject(this.closedWith)
    const id = this.nextId++
    const timeoutMs = options.timeoutMs ?? CDP_TIMEOUT_MS
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(cdpUnreachable(`The browser did not answer ${method} within ${Math.round(timeoutMs / 1000)} s.`))
      }, timeoutMs)
      this.pending.set(id, { method, resolve: resolve as (value: unknown) => void, reject, timer })
      this.socket.send(JSON.stringify({ id, method, params, ...(options.sessionId ? { sessionId: options.sessionId } : {}) }))
    })
  }

  onEvent(listener: (event: CdpEvent) => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  close(): void {
    this.fail(cdpUnreachable("The DevTools connection was closed."))
    try {
      this.socket.close()
    } catch {
      // already closed
    }
  }

  private receive(data: unknown): void {
    let message: { id?: unknown; result?: unknown; error?: { message?: unknown }; method?: unknown; params?: unknown; sessionId?: unknown }
    try {
      message = JSON.parse(typeof data === "string" ? data : new TextDecoder().decode(data as ArrayBuffer))
    } catch {
      return
    }
    if (typeof message.id === "number") {
      const pending = this.pending.get(message.id)
      if (!pending) return
      this.pending.delete(message.id)
      clearTimeout(pending.timer)
      if (message.error) pending.reject(new CdpCallError(pending.method, typeof message.error.message === "string" ? message.error.message : "refused"))
      else pending.resolve(message.result ?? {})
      return
    }
    if (typeof message.method !== "string") return
    const event: CdpEvent = { method: message.method, params: (typeof message.params === "object" && message.params !== null ? message.params : {}) as Record<string, unknown>, sessionId: typeof message.sessionId === "string" ? message.sessionId : null }
    for (const listener of this.listeners) listener(event)
  }

  private fail(error: CliError): void {
    if (this.closedWith) return
    this.closedWith = error
    for (const [id, pending] of this.pending) {
      clearTimeout(pending.timer)
      pending.reject(error)
      this.pending.delete(id)
    }
  }
}

export type PageTarget = { targetId: string; url: string }

type TargetInfo = { targetId: string; type: string; url: string; title?: string }

// The page to fill: the one named by --target, or the browser's only page.
export async function choosePage(connection: CdpConnection, target: string | null): Promise<PageTarget> {
  const { targetInfos } = await connection.send<{ targetInfos: TargetInfo[] }>("Target.getTargets")
  const pages = targetInfos.filter((info) => info.type === "page")
  if (target !== null) {
    const page = pages.find((info) => info.targetId === target)
    if (!page) throw new CliError("target_ambiguous", `The browser has no page with target id ${target}.`, { say: "Give --target the id of one of the browser's pages (Target.getTargetInfo of the page the agent drives), or leave it out when the browser has one page." })
    return { targetId: page.targetId, url: page.url }
  }
  if (pages.length === 1) return { targetId: (pages[0] as TargetInfo).targetId, url: (pages[0] as TargetInfo).url }
  throw new CliError("target_ambiguous", pages.length === 0 ? "The browser has no open page." : `The browser has ${pages.length} pages, so mehen will not guess which one to type into.`, {
    say: "Give --target the id of the page to fill (Target.getTargetInfo of the page the agent drives).",
  })
}

// A flattened session on the page.
export async function attachPage(connection: CdpConnection, targetId: string): Promise<string> {
  const { sessionId } = await connection.send<{ sessionId: string }>("Target.attachToTarget", { targetId, flatten: true })
  return sessionId
}

// The page's top-level URL now, as the browser reports it.
export async function pageUrl(connection: CdpConnection, targetId: string): Promise<string> {
  const { targetInfo } = await connection.send<{ targetInfo: TargetInfo }>("Target.getTargetInfo", { targetId })
  return targetInfo.url
}
