// Minimal HTTP/1.1 framing for the local relay: request heads, Content-Length
// and chunked request bodies, and writes with socket backpressure. Ambiguous
// framing is refused rather than guessed at.

import type { Duplex } from "node:stream"

const READER_HIGH_WATER = 1024 * 1024
export const MAX_HEAD_BYTES = 64 * 1024

export class HttpFramingError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

// Pull-style reader over a push-style socket, so the framing code reads sequentially.
export class SocketReader {
  private chunks: Buffer[] = []
  private buffered = 0
  private ended = false
  private failure: Error | undefined
  private wake: (() => void) | undefined
  private readonly onData = (chunk: Buffer) => {
    this.chunks.push(chunk)
    this.buffered += chunk.length
    if (this.buffered > READER_HIGH_WATER) this.socket.pause()
    this.notify()
  }
  private readonly onEnd = () => {
    this.ended = true
    this.notify()
  }
  private readonly onError = (error: Error) => {
    this.failure = error
    this.notify()
  }

  constructor(private readonly socket: Duplex) {
    socket.on("data", this.onData)
    socket.on("end", this.onEnd)
    socket.on("close", this.onEnd)
    socket.on("error", this.onError)
  }

  private notify(): void {
    const wake = this.wake
    this.wake = undefined
    wake?.()
  }

  private async waitForData(): Promise<void> {
    if (this.buffered > 0 || this.ended || this.failure) return
    this.socket.resume()
    await new Promise<void>((resolve) => {
      this.wake = resolve
    })
  }

  // The next chunk of at most `max` bytes, or null at the end of the stream.
  async read(max = Number.POSITIVE_INFINITY): Promise<Buffer | null> {
    await this.waitForData()
    const first = this.chunks.shift()
    if (first === undefined) {
      if (this.failure) throw this.failure
      return null
    }
    let chunk = first
    if (chunk.length > max) {
      this.chunks.unshift(chunk.subarray(max))
      chunk = chunk.subarray(0, max)
    }
    this.buffered -= chunk.length
    if (this.buffered < READER_HIGH_WATER / 2) this.socket.resume()
    return chunk
  }

  unshift(chunk: Buffer): void {
    if (chunk.length === 0) return
    this.chunks.unshift(chunk)
    this.buffered += chunk.length
  }

  // Reads up to and including the next CRLF CRLF. Null on a clean end before any byte.
  async readHead(limit = MAX_HEAD_BYTES): Promise<Buffer | null> {
    let collected: Buffer = Buffer.alloc(0)
    for (;;) {
      const end = collected.indexOf("\r\n\r\n")
      if (end !== -1) {
        this.unshift(collected.subarray(end + 4))
        return collected.subarray(0, end + 4)
      }
      if (collected.length > limit) throw new HttpFramingError(431, "request head too large")
      const chunk = await this.read()
      if (chunk === null) {
        if (collected.length === 0) return null
        throw new HttpFramingError(400, "connection closed in the middle of a request head")
      }
      collected = collected.length === 0 ? chunk : Buffer.concat([collected, chunk])
    }
  }

  async readLine(limit = 8 * 1024): Promise<string> {
    let collected: Buffer = Buffer.alloc(0)
    for (;;) {
      const end = collected.indexOf("\r\n")
      if (end !== -1) {
        this.unshift(collected.subarray(end + 2))
        return collected.subarray(0, end).toString("latin1")
      }
      if (collected.length > limit) throw new HttpFramingError(400, "line too long")
      const chunk = await this.read()
      if (chunk === null) throw new HttpFramingError(400, "connection closed in the middle of a line")
      collected = Buffer.concat([collected, chunk])
    }
  }

  // Stops reading and hands back anything buffered, for a socket hand-off (TLS wrap, tunnel).
  detach(): Buffer {
    this.socket.off("data", this.onData)
    this.socket.off("end", this.onEnd)
    this.socket.off("close", this.onEnd)
    this.socket.off("error", this.onError)
    this.socket.pause()
    const rest = Buffer.concat(this.chunks)
    this.chunks = []
    this.buffered = 0
    return rest
  }
}

export type HttpHead = { method: string; target: string; version: string; headers: [name: string, value: string][] }

export function parseHead(raw: Buffer): HttpHead {
  const lines = raw.toString("latin1").slice(0, -4).split("\r\n")
  const [method = "", target = "", version = "", ...extra] = (lines.shift() ?? "").split(" ")
  if (method === "" || target === "" || !version.startsWith("HTTP/1.") || extra.length > 0) {
    throw new HttpFramingError(400, "malformed request line")
  }
  const headers: [string, string][] = []
  for (const line of lines) {
    if (line.startsWith(" ") || line.startsWith("\t")) throw new HttpFramingError(400, "obsolete header folding")
    const colon = line.indexOf(":")
    if (colon <= 0) throw new HttpFramingError(400, "malformed header line")
    headers.push([line.slice(0, colon), line.slice(colon + 1).trim()])
  }
  return { method, target, version, headers }
}

export function serialiseRequestHead(head: HttpHead): Buffer {
  let text = `${head.method} ${head.target} ${head.version}\r\n`
  for (const [name, value] of head.headers) text += `${name}: ${value}\r\n`
  return Buffer.from(`${text}\r\n`, "latin1")
}

export function headerValues(head: HttpHead, name: string): string[] {
  const lower = name.toLowerCase()
  return head.headers.filter(([key]) => key.toLowerCase() === lower).map(([, value]) => value)
}

export function removeHeader(head: HttpHead, name: string): void {
  const lower = name.toLowerCase()
  head.headers = head.headers.filter(([key]) => key.toLowerCase() !== lower)
}

export function hasToken(head: HttpHead, name: string, token: string): boolean {
  return headerValues(head, name).some((value) =>
    value
      .toLowerCase()
      .split(",")
      .some((part) => part.trim() === token),
  )
}

export type BodyFraming = { kind: "none" } | { kind: "length"; length: number } | { kind: "chunked" }

// Request smuggling defence: both framings at once, or anything but chunked
// last, is refused.
export function requestFraming(head: HttpHead): BodyFraming {
  const transferEncoding = headerValues(head, "transfer-encoding")
  const contentLength = headerValues(head, "content-length")
  if (transferEncoding.length > 0) {
    if (contentLength.length > 0) throw new HttpFramingError(400, "both Transfer-Encoding and Content-Length")
    const codings = transferEncoding.join(",").toLowerCase().split(",").map((part) => part.trim())
    if (codings.length !== 1 || codings[0] !== "chunked") throw new HttpFramingError(400, "unsupported Transfer-Encoding")
    return { kind: "chunked" }
  }
  if (contentLength.length === 0) return { kind: "none" }
  const unique = new Set(contentLength.flatMap((value) => value.split(",").map((part) => part.trim())))
  const [only] = unique
  if (unique.size !== 1 || only === undefined || !/^\d+$/.test(only)) throw new HttpFramingError(400, "invalid Content-Length")
  return { kind: "length", length: Number(only) }
}

// Reads a whole request body. Refuses one larger than `limit` with a 413.
export async function readBody(reader: SocketReader, framing: BodyFraming, limit: number): Promise<Buffer> {
  const parts: Buffer[] = []
  let total = 0
  const take = (chunk: Buffer) => {
    total += chunk.length
    if (total > limit) throw new HttpFramingError(413, `request body larger than ${limit} bytes`)
    parts.push(chunk)
  }
  switch (framing.kind) {
    case "none":
      return Buffer.alloc(0)
    case "length": {
      if (framing.length > limit) throw new HttpFramingError(413, `request body larger than ${limit} bytes`)
      for (let remaining = framing.length; remaining > 0; ) {
        const chunk = await reader.read(remaining)
        if (chunk === null) throw new HttpFramingError(400, "body shorter than Content-Length")
        remaining -= chunk.length
        take(chunk)
      }
      return Buffer.concat(parts)
    }
    case "chunked": {
      for (;;) {
        const size = Number.parseInt((await reader.readLine()).split(";")[0]?.trim() ?? "", 16)
        if (!Number.isFinite(size) || size < 0) throw new HttpFramingError(400, "bad chunk size")
        if (size === 0) break
        for (let remaining = size; remaining > 0; ) {
          const chunk = await reader.read(remaining)
          if (chunk === null) throw new HttpFramingError(400, "connection closed in the middle of a chunk")
          remaining -= chunk.length
          take(chunk)
        }
        if ((await reader.readLine()) !== "") throw new HttpFramingError(400, "missing CRLF after a chunk")
      }
      while ((await reader.readLine()) !== "") {
        // Trailers are dropped: the relay request carries headers only.
      }
      return Buffer.concat(parts)
    }
  }
}

export function writeWithBackpressure(socket: Duplex, chunk: Buffer | string): Promise<void> {
  if (socket.destroyed) return Promise.reject(new Error("socket closed"))
  if (socket.write(chunk)) return Promise.resolve()
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      socket.off("drain", onDrain)
      socket.off("close", onClose)
    }
    const onDrain = () => {
      cleanup()
      resolve()
    }
    const onClose = () => {
      cleanup()
      reject(new Error("socket closed while writing"))
    }
    socket.on("drain", onDrain)
    socket.on("close", onClose)
  })
}
