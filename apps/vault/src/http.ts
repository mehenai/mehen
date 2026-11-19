// HTTP helpers shared by every route. Every vault refusal is JSON shaped as
// ApiError with `Mehen-Error: 1`, so an agent can always tell a vault refusal
// from an upstream response, and always gets a `next` step when one exists.

import { type ApiError, ERROR_HEADER, HTTP_STATUS_FOR_ERROR, type ErrorCode, type NextStep } from "@mehen/protocol/api"
import type { z } from "zod"



export class VaultError extends Error {
  readonly code: ErrorCode
  readonly status: number
  readonly extra: Omit<ApiError, "error" | "message">

  constructor(code: ErrorCode, message: string, extra: Omit<ApiError, "error" | "message"> = {}) {
    super(message)
    this.code = code
    this.status = HTTP_STATUS_FOR_ERROR[code]
    this.extra = extra
  }

  toJSON(): ApiError {
    return { error: this.code, message: this.message, ...this.extra }
  }
}

export function fail(code: ErrorCode, message: string, next?: NextStep): never {
  throw new VaultError(code, message, next ? { next } : {})
}

// Errors cross the Durable Object RPC boundary as plain objects. A thrown
// Error keeps its name, message and own fields such as code and status, but
// loses its prototype, so instanceof VaultError fails on the far side and
// toWireError and responseFor would answer a refusal with a 500.
export type WireError = { vaultError: ApiError; status: number }

export function toWireError(error: unknown): WireError {
  if (error instanceof VaultError) return { vaultError: error.toJSON(), status: error.status }
  return { vaultError: { error: "internal", message: "Something went wrong inside the vault." }, status: 500 }
}

export function isWireError(value: unknown): value is WireError {
  return typeof value === "object" && value !== null && "vaultError" in value && "status" in value
}

const SECURITY_HEADERS: Record<string, string> = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
}

export function withSecurityHeaders(response: Response): Response {
  const out = new Response(response.body, response)
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) if (!out.headers.has(k)) out.headers.set(k, v)
  return out
}

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
  })
}

export function errorResponse(error: ApiError, status: number): Response {
  return json(error, status, { [ERROR_HEADER]: "1" })
}

export function responseFor(error: unknown): Response {
  if (isWireError(error)) return errorResponse(error.vaultError, error.status)
  const wire = toWireError(error)
  return errorResponse(wire.vaultError, wire.status)
}

export const MAX_JSON_BYTES = 1_000_000

export async function readBody(request: Request, limit = MAX_JSON_BYTES): Promise<Uint8Array<ArrayBuffer>> {
  const declared = Number(request.headers.get("content-length") ?? "0")
  if (declared > limit) fail("too_large", "That request is too large.")
  // content-length can be absent or wrong, so count the bytes as they arrive
  // and stop reading the moment there are too many.
  const chunks: Uint8Array[] = []
  let total = 0
  if (request.body !== null) {
    const reader = request.body.getReader()
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > limit) {
        await reader.cancel().catch(() => {})
        fail("too_large", "That request is too large.")
      }
      chunks.push(value)
    }
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return bytes
}

// Far deeper than any request the vault takes. A body nested past it is
// refused before it reaches a schema or a workspace: the structured clone
// that carries input to a Durable Object overflows on a few thousand levels.
export const MAX_JSON_DEPTH = 64

function nestedWithin(value: unknown, limit: number): boolean {
  const stack: { value: unknown; depth: number }[] = [{ value, depth: 1 }]
  for (let next = stack.pop(); next !== undefined; next = stack.pop()) {
    if (typeof next.value !== "object" || next.value === null) continue
    if (next.depth > limit) return false
    for (const child of Object.values(next.value)) stack.push({ value: child, depth: next.depth + 1 })
  }
  return true
}

export function parseJson<T extends z.ZodType>(schema: T, bytes: Uint8Array): z.infer<T> {
  let value: unknown
  try {
    value = bytes.length === 0 ? {} : JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes))
  } catch {
    fail("bad_request", "The body must be JSON.")
  }
  if (!nestedWithin(value, MAX_JSON_DEPTH)) fail("bad_request", `The body must be JSON nested at most ${MAX_JSON_DEPTH} levels deep.`)
  const result = schema.safeParse(value)
  if (!result.success) {
    const issue = result.error.issues[0]
    fail("bad_request", `Invalid request: ${issue ? `${issue.path.join(".") || "body"} ${issue.message}` : "bad shape"}.`)
  }
  return result.data
}
