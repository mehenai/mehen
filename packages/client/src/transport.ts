// One signed request to the vault and the reading of its answer. Every /v1
// request carries a fresh Mehen-Proof over its method, full URL and exact
// body bytes, exactly as the mehen CLI signs it.

import { z } from "zod"
import { ERROR_CODES, ERROR_HEADER, type ErrorCode } from "@mehen/protocol/api"
import { PROOF_HEADER, type ProofRequest, type ProofSigner, createProof } from "@mehen/protocol/proof"
import { MehenRefusal, MehenTransport, type RefusalFields } from "./errors.ts"
import { vaultLink } from "./origin.ts"
import { EnrolStatusSchema, NextStepSchema } from "./responses.ts"
import { CLIENT_PRODUCT } from "./version.ts"

export type Fetcher = (request: Request) => Promise<Response>

export const DEFAULT_TIMEOUT_MS = 60_000
// A long poll (?wait=1) holds the answer for up to 25 s at the vault.
export const LONG_POLL_TIMEOUT_MS = 35_000

export type Transport = {
  origin: string
  fetch: Fetcher
  userAgent: string
  timeoutMs: number
}

export type Credentials = {
  tenant: string
  signer: ProofSigner
  session?: string
}

export type TransportOptions = { fetch?: Fetcher; userAgent?: string; timeoutMs?: number }

const PRODUCT_TOKENS = /^[\x21-\x7e]+(?: [\x21-\x7e]+)*$/

export function transportFor(origin: string, options: TransportOptions): Transport {
  const extra = options.userAgent?.trim()
  if (extra !== undefined && extra !== "" && (!PRODUCT_TOKENS.test(extra) || extra.length > 200)) throw new TypeError("userAgent must be printable ASCII product tokens, at most 200 characters.")
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new TypeError("timeoutMs must be a positive number of milliseconds.")
  return {
    origin,
    fetch: options.fetch ?? ((request) => fetch(request)),
    userAgent: extra ? `${CLIENT_PRODUCT} ${extra}` : CLIENT_PRODUCT,
    timeoutMs,
  }
}

export type Method = "GET" | "PUT" | "POST" | "DELETE"

// The header that carries one request's proof, and the proof itself: a
// device's Mehen-Proof, or a platform's Mehen-Platform-Proof.
export type RequestProver = (request: ProofRequest) => Promise<{ header: string; proof: string }>

// signal: the timeout's alone or combined with the caller's; the request's
// own follows it until the answer's headers arrive. caller: the caller's
// signal, when it gave one: its abort is the caller's decision, answered
// with its own reason, never as a timeout.
type Deadline = { signal: AbortSignal; caller?: AbortSignal; timeoutMs: number }

export type Sent = Deadline & { response: Response; path: string }

export function failure(transport: Transport, deadline: Deadline, error: unknown, what: string): unknown {
  if (deadline.caller?.aborted) return deadline.caller.reason
  if (deadline.signal.aborted) return new MehenTransport("timeout", `The vault at ${transport.origin} did not answer ${what} within ${deadline.timeoutMs} ms.`)
  const detail = error instanceof Error ? error.message : String(error)
  return new MehenTransport("network", `Could not reach the vault at ${transport.origin} for ${what}: ${detail}`)
}

export type SendOptions = { timeoutMs?: number; signal?: AbortSignal }

export function send(transport: Transport, credentials: Credentials, method: Method, path: string, body: string | null, options: SendOptions = {}): Promise<Sent> {
  const prove: RequestProver = async (request) => ({ header: PROOF_HEADER, proof: await createProof(credentials.signer, request, { tenant: credentials.tenant, ...(credentials.session ? { session: credentials.session } : {}) }) })
  return sendProved(transport, prove, method, path, body, options)
}

export async function sendProved(transport: Transport, prove: RequestProver, method: Method, path: string, body: string | null, options: SendOptions = {}): Promise<Sent> {
  const url = `${transport.origin}${path}`
  const { header, proof } = await prove({ method, url, body })
  const headers = new Headers({ [header]: proof, accept: "application/json", "user-agent": transport.userAgent })
  if (body !== null) headers.set("content-type", "application/json")
  const timeoutMs = options.timeoutMs ?? transport.timeoutMs
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new TypeError("timeoutMs must be a positive number of milliseconds.")
  const timeout = AbortSignal.timeout(timeoutMs)
  const signal = options.signal ? AbortSignal.any([timeout, options.signal]) : timeout
  // The request has a signal of its own, aborted with the deadline's only
  // until the vault's headers arrive. fetch keeps the Request, body and all,
  // reachable from its signal, and the deadline lives on while a relay
  // stream's body is read: sharing one signal would keep the body as long.
  const sending = new AbortController()
  const abortSending = () => sending.abort(signal.reason)
  const request = new Request(url, { method, headers, body, redirect: "manual", signal: sending.signal })
  const deadline: Deadline = { signal, timeoutMs, ...(options.signal ? { caller: options.signal } : {}) }
  // Aborted while the proof was signed: nothing is sent.
  if (options.signal?.aborted) throw options.signal.reason
  signal.addEventListener("abort", abortSending, { once: true })
  try {
    return { ...deadline, response: await transport.fetch(request), path }
  } catch (error) {
    throw failure(transport, deadline, error, `${method} ${path}`)
  } finally {
    signal.removeEventListener("abort", abortSending)
  }
}

// The answer's body, read only as the caller reads it (no chunk ahead),
// under the deadline that covered the request: when it fires mid-body the
// stream errors with the timeout (or the caller's abort reason) and the
// vault's body is cancelled. The request's own signal no longer follows the
// deadline once the headers have arrived, so every body is read this way.
export function deadlineBody(transport: Transport, sent: Sent): ReadableStream<Uint8Array> | null {
  const source = sent.response.body
  if (source === null) return null
  const reader = source.getReader()
  const what = `the answer to ${sent.path}`
  let settled = false
  let stop: () => void = () => undefined
  const settle = () => {
    settled = true
    sent.signal.removeEventListener("abort", stop)
  }
  return new ReadableStream<Uint8Array>(
    {
      start(controller) {
        stop = () => {
          if (settled) return
          settle()
          controller.error(failure(transport, sent, null, what))
          reader.cancel().catch(() => undefined)
        }
        if (sent.signal.aborted) stop()
        else sent.signal.addEventListener("abort", stop, { once: true })
      },
      async pull(controller) {
        try {
          const chunk = await reader.read()
          if (settled) return
          if (chunk.done) {
            settle()
            controller.close()
          } else controller.enqueue(chunk.value)
        } catch (error) {
          if (settled) return
          settle()
          controller.error(failure(transport, sent, error, what))
        }
      },
      cancel(reason) {
        settle()
        return reader.cancel(reason)
      },
    },
    { highWaterMark: 0 },
  )
}

// Rejects as deadlineBody errors: a MehenTransport, or the caller's reason.
export async function readBytes(transport: Transport, sent: Sent): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await new Response(deadlineBody(transport, sent)).arrayBuffer())
}

async function readText(transport: Transport, sent: Sent): Promise<string> {
  return new Response(deadlineBody(transport, sent)).text()
}

const ApiErrorBodySchema = z.object({
  error: z.string(),
  message: z.string().min(1),
  next: NextStepSchema.optional(),
  approval: z.string().max(128).optional(),
  bindingCode: z.string().max(64).optional(),
  choices: z.array(z.object({ slug: z.string(), account: z.string().nullable() })).optional(),
  retryAfter: z.number().nonnegative().optional(),
  expiresAt: z.iso.datetime().optional(),
  deciders: z.array(z.string()).optional(),
  enrolment: EnrolStatusSchema.optional(),
})

function knownCode(value: string): value is ErrorCode {
  return (ERROR_CODES as readonly string[]).includes(value)
}

// A response carrying Mehen-Error: 1 is the vault's own refusal; its body
// must be the ApiError shape, else nothing about it can be trusted.
export async function refusalOf(transport: Transport, sent: Sent): Promise<MehenRefusal | MehenTransport> {
  const status = sent.response.status
  const text = await readText(transport, sent)
  let raw: unknown
  try {
    raw = JSON.parse(text)
  } catch {
    return new MehenTransport("unexpected", `The vault refused ${sent.path} with HTTP ${status} but its error body is not JSON.`, status)
  }
  const parsed = ApiErrorBodySchema.safeParse(raw)
  if (!parsed.success) return new MehenTransport("unexpected", `The vault refused ${sent.path} with HTTP ${status} but its error body is not a Mehen error.`, status)
  const body = parsed.data
  const fields: RefusalFields = knownCode(body.error) ? { code: body.error, status, message: body.message } : { code: "internal", rawCode: body.error, status, message: body.message }
  if (body.next) {
    if (body.next.url === undefined) fields.next = body.next
    else {
      const link = vaultLink(transport.origin, body.next.url)
      if (link === null) return new MehenTransport("unexpected", `The vault's refusal of ${sent.path} links off the vault's origin.`, status)
      fields.next = { ...body.next, url: link }
      fields.link = link
    }
  }
  if (body.approval !== undefined) fields.approval = body.approval
  if (body.bindingCode !== undefined) fields.bindingCode = body.bindingCode
  if (body.expiresAt !== undefined) fields.expiresAt = body.expiresAt
  if (body.retryAfter !== undefined) fields.retryAfter = body.retryAfter
  if (body.deciders !== undefined) fields.deciders = body.deciders
  if (body.choices !== undefined) fields.choices = body.choices
  if (body.enrolment !== undefined) fields.enrolment = body.enrolment
  return new MehenRefusal(fields)
}

// The JSON answer of a non-relay route, parsed with `schema`. A refusal
// throws MehenRefusal; anything that is not the vault's answer throws
// MehenTransport.
export async function readAnswer<T>(transport: Transport, sent: Sent, schema: z.ZodType<T>): Promise<T> {
  const { response, path } = sent
  if (response.headers.has(ERROR_HEADER)) throw await refusalOf(transport, sent)
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined)
    throw new MehenTransport("unexpected", `The vault answered ${path} with HTTP ${response.status} and no Mehen error.`, response.status)
  }
  const text = await readText(transport, sent)
  let raw: unknown = {}
  try {
    if (text.length > 0) raw = JSON.parse(text)
  } catch {
    throw new MehenTransport("unexpected", `The vault answered ${path} with something that is not JSON.`, response.status)
  }
  const parsed = schema.safeParse(raw)
  if (!parsed.success) {
    const issue = parsed.error.issues[0]
    const where = issue && issue.path.length > 0 ? ` (at ${issue.path.join(".")})` : ""
    throw new MehenTransport("unexpected", `The vault's answer to ${path} is not the shape this client knows${where}.`, response.status)
  }
  return parsed.data
}
