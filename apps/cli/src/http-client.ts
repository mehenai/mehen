// VaultApi over HTTP. Every /v1 request carries a fresh Mehen-Proof over its
// method, full URL and exact body bytes; there is no bearer token.

import {
  type ApiError,
  ERROR_CODES,
  ERROR_HEADER,
  FORWARDED_HEADER,
  type ErrorCode,
  type NextStep,
  type RelayRequestInput,
  UPSTREAM_HEADER,
} from "@mehen/protocol/api"
import { MandateClassSchema, MandateIdSchema } from "@mehen/protocol/mandate-terms"
import { POLICY_AREA_REFUSALS, POLICY_RULE_REFUSALS, type PolicyAreaRefusal, type PolicyRuleRefusal } from "@mehen/protocol/policy-mode"
import { PROOF_HEADER, type ProofSigner, createProof, parseProof } from "@mehen/protocol/proof"
import type { WorkspaceEnrolStatus } from "@mehen/protocol/workspace"
import { z } from "zod"
import { readMandateCover } from "./mandate-cover.ts"
import { type CallContext, RelayOutcomeUnknownError, RelayUnmarkedAnswerError, type VaultApi, VaultApiError, VaultNetworkError, type VaultRequestOptions, retrySafeMethod } from "./vault-api.ts"
import { BUILD_KIND, VERSION } from "./version.ts"

// What every /v1 request says it is: the vault's version seam
// reads the version, and labels sessions and enrolments with it.
export const USER_AGENT = `mehen/${VERSION} (${process.platform}-${process.arch}; ${BUILD_KIND ?? "source"})`

// The vault's advice from `Mehen-Cli: minimum=<v>; recommended=<v>`, on
// every /v1 response.
export type CliAdvice = { minimum: string; recommended: string | null }
export type CliAdviceSink = (origin: string, advice: CliAdvice) => void | Promise<void>
const ADVICE_VERSION = /^\d{1,6}\.\d{1,6}\.\d{1,6}$/

export function parseCliAdvice(header: string | null): CliAdvice | null {
  if (!header || header.length > 200) return null
  const fields = new Map<string, string>()
  for (const part of header.split(";")) {
    const [key, value] = part.trim().split("=")
    if (key && value !== undefined) fields.set(key.trim(), value.trim())
  }
  const minimum = fields.get("minimum")
  const recommended = fields.get("recommended") ?? null
  if (!minimum || !ADVICE_VERSION.test(minimum) || (recommended !== null && !ADVICE_VERSION.test(recommended))) return null
  return { minimum, recommended }
}

// One sink per process (cli.ts sets it to record the advice next to the
// binary); each distinct advice of each origin is reported once, and
// flushCliAdvice waits for the writes before the process exits.
let adviceSink: CliAdviceSink | null = null
const reported = new Set<string>()
const writes = new Set<Promise<void>>()

export function setCliAdviceSink(sink: CliAdviceSink | null): void {
  adviceSink = sink
  reported.clear()
}

export async function flushCliAdvice(): Promise<void> {
  await Promise.allSettled([...writes])
}

function noteAdvice(vaultUrl: string, response: Response): void {
  if (adviceSink === null) return
  const advice = parseCliAdvice(response.headers.get("mehen-cli"))
  if (advice === null) return
  let origin: string
  try {
    origin = new URL(vaultUrl).origin
  } catch {
    return
  }
  const key = `${origin} ${advice.minimum} ${advice.recommended ?? ""}`
  if (reported.has(key)) return
  reported.add(key)
  const write = Promise.resolve()
    .then(() => adviceSink?.(origin, advice))
    .catch(() => {})
  writes.add(write)
  void write.finally(() => writes.delete(write))
}

export type Fetcher = (request: Request) => Promise<Response>

export type HttpVaultApiOptions = {
  vaultUrl: string // no trailing slash
  tenant: string // proof `ten`: the tenant id, or "enrol" while enrolling
  signer: ProofSigner
  session?: string // proof `sid`, from MEHEN_SESSION
  fetch?: Fetcher
  // The call's own provenance, attached to every refusal this client raises.
  context?: CallContext
}

type Method = "GET" | "POST" | "PUT" | "DELETE"

// Failures before a connection was made, so the request never left this
// machine: a refused connection or a name that does not resolve.
const NEVER_SENT_CODES: ReadonlySet<unknown> = new Set(["ConnectionRefused", "ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "FailedToOpenSocket", "ENETUNREACH", "EHOSTUNREACH"])

function isNextStep(value: unknown): value is NextStep {
  if (typeof value !== "object" || value === null) return false
  const n = value as Record<string, unknown>
  return typeof n.say === "string" && (n.url === undefined || typeof n.url === "string") && (n.command === undefined || typeof n.command === "string")
}

const ENROL_EXPIRED_REASONS: readonly unknown[] = ["hard_cap", "superseded", "discarded", "source", "legacy"]

// The settled enrolment a terminal renew refusal carries: the same answer a
// poll gives, checked field by field before the reader keeps it.
function isEnrolStatus(value: unknown): value is WorkspaceEnrolStatus {
  if (typeof value !== "object" || value === null) return false
  const v = value as Record<string, unknown>
  const isObject = (field: unknown) => typeof field === "object" && field !== null
  switch (v.status) {
    case "pending_owner_acceptance":
    case "pending_admission":
      return typeof v.expiresAt === "string" && (v.hardExpiresAt === undefined || typeof v.hardExpiresAt === "string")
    case "expired":
      return v.reason === undefined || ENROL_EXPIRED_REASONS.includes(v.reason)
    case "rejected":
      return true
    case "active":
      return typeof v.tenant === "string" && typeof v.device === "string" && isObject(v.workspace) && isObject(v.scope) && isObject(v.owner)
    default:
      return false
  }
}

// `expiresAt` on an error is read here ahead of the type so that an ask synthesised from the error carries the expiry.
type ApiErrorWithExpiry = ApiError & { expiresAt?: string }

// The mandate a cap kept from covering a held request; dropped unless well formed.
const CappedMandateSchema = z.object({ id: MandateIdSchema, capped: z.array(MandateClassSchema).min(1) })

// Whether a Mehen-Error body is one mehen can read: a known code and a message.
// A vault from before Mehen-Forwarded (0.4.0 and earlier) marks its own
// refusals with Mehen-Error and nothing else. There, after the upstream
// fetch, the relay route raises only upstream_failed and too_large (a
// response too large, relay/forward.ts), and anything unexpected became
// internal; every other code it can send on /v1/relay comes from a check
// before forwarding: the Worker's rate limits and version gate, the device
// request's proof and body, the relay route's own input checks and the
// workspace's authorisation of the request (relay.authorise). Read from
// the vault's relay code at 124e548a; relay-codes.test.ts pins both lists
// against the current vault's relay path.
export const RELAY_PRE_FORWARD_CODES: ReadonlySet<ErrorCode> = new Set<ErrorCode>([
  "bad_request", "unauthenticated", "proof_invalid", "device_pending", "device_revoked", "forbidden", "not_found", "conflict", "ambiguous",
  "binding_refused", "policy_denied", "approval_required", "mode_refused", "environment_refused", "remote_mismatch", "needs_reauth",
  "refresh_retrying", "frozen", "rate_limited", "account_pending", "owner_inactive", "identity_required", "project_unshared", "cli_outdated",
  "workload_ended", "workload_required", "platform_suspended", "quota_exceeded", "origin_mismatch", "totp_unreadable", "provider_refused",
])
// What such a vault may send after the request went upstream (upstream_failed,
// a response too_large, internal), and codes its relay never raised, which
// are not trusted from an unmarked answer either.
export const RELAY_MAY_HAVE_BEEN_SENT_CODES: ReadonlySet<ErrorCode> = new Set<ErrorCode>(["upstream_failed", "too_large", "internal", "surface_refused", "intake_required"])

function readableError(text: string): boolean {
  try {
    const body = JSON.parse(text) as unknown
    return typeof body === "object" && body !== null && (ERROR_CODES as readonly unknown[]).includes((body as { error?: unknown }).error) && typeof (body as { message?: unknown }).message === "string"
  } catch {
    return false
  }
}

// Reads a Mehen-Error body, keeping only the documented fields. relayedItem:
// the item a relay sent, which mandateCover then names (MandateCover).
export async function readApiError(response: Response, context: CallContext | null = null, relayedItem: string | null = null): Promise<VaultApiError> {
  let raw: unknown = null
  try {
    raw = await response.json()
  } catch {
    raw = null
  }
  const body = typeof raw === "object" && raw !== null ? (raw as Record<string, unknown>) : {}
  const code = typeof body.error === "string" && (ERROR_CODES as readonly string[]).includes(body.error) ? (body.error as ErrorCode) : "internal"
  const message =
    typeof body.message === "string" && body.message.length > 0
      ? body.message
      : `The vault answered HTTP ${response.status} without a readable error.`
  const error: ApiErrorWithExpiry = { error: code, message }
  if (isNextStep(body.next)) error.next = body.next
  if (typeof body.approval === "string") error.approval = body.approval
  if (typeof body.bindingCode === "string") error.bindingCode = body.bindingCode
  if (typeof body.retryAfter === "number") error.retryAfter = body.retryAfter
  if (typeof body.expiresAt === "string") error.expiresAt = body.expiresAt
  // Kept as sent; askGroup checks it before it reaches an ask.
  if (code === "approval_required" && body.group !== undefined) error.group = body.group as ApiError["group"]
  if (code === "approval_required") {
    const mandate = CappedMandateSchema.safeParse(body.mandate)
    if (mandate.success) error.mandate = mandate.data
    const cover = readMandateCover(body.mandateCover, relayedItem)
    if (cover) error.mandateCover = cover
    // Who may decide it, by name, as the vault's next.say names them.
    if (Array.isArray(body.deciders) && body.deciders.every((d) => typeof d === "string")) error.deciders = body.deciders as string[]
  }
  if (isEnrolStatus(body.enrolment)) error.enrolment = body.enrolment
  if (code === "forbidden" && (POLICY_RULE_REFUSALS as readonly unknown[]).includes(body.ruleRefused)) error.ruleRefused = body.ruleRefused as PolicyRuleRefusal
  if (code === "provider_refused" && Number.isInteger(body.providerStatus) && (body.providerStatus as number) >= 100 && (body.providerStatus as number) <= 599) error.providerStatus = body.providerStatus as number
  if (code === "forbidden" && (POLICY_AREA_REFUSALS as readonly unknown[]).includes(body.areaRefused)) error.areaRefused = body.areaRefused as PolicyAreaRefusal
  if (Array.isArray(body.choices)) {
    error.choices = body.choices
      .filter((c): c is { slug: string; account: unknown } => typeof c === "object" && c !== null && typeof (c as { slug?: unknown }).slug === "string")
      .map((c) => ({ slug: c.slug, account: typeof c.account === "string" ? c.account : null }))
  }
  return new VaultApiError(response.status, error, context)
}

export class HttpVaultApi implements VaultApi {
  private readonly options: HttpVaultApiOptions
  private readonly fetcher: Fetcher

  constructor(options: HttpVaultApiOptions) {
    this.options = options
    this.fetcher = options.fetch ?? ((request) => fetch(request))
  }

  // write: the relayed request is not retry safe, so a connection that
  // failed once it may have reached the vault is RelayOutcomeUnknownError.
  private async send(method: Method, path: string, body: string | null, options?: VaultRequestOptions, write = false): Promise<Response> {
    if (!path.startsWith("/v1/")) throw new Error(`vault paths start with /v1/, got ${path}`)
    const signal = options?.signal
    const url = `${this.options.vaultUrl}${path}`
    const proof = await createProof(this.options.signer, { method, url, body }, {
      tenant: this.options.tenant,
      ...(this.options.session ? { session: this.options.session } : {}),
    })
    if (options?.onProof) options.onProof(parseProof(proof).claims.jti)
    const headers = new Headers({ [PROOF_HEADER]: proof, accept: "application/json", "user-agent": USER_AGENT })
    if (body !== null) headers.set("content-type", "application/json")
    const request = new Request(url, { method, headers, body, redirect: "manual", ...(signal ? { signal } : {}) })
    try {
      const response = await this.fetcher(request)
      noteAdvice(this.options.vaultUrl, response)
      return response
    } catch (error) {
      if (signal?.aborted) throw signal.reason
      const detail = error instanceof Error ? error.message : String(error)
      if (write && !NEVER_SENT_CODES.has((error as { code?: unknown } | null)?.code)) {
        throw new RelayOutcomeUnknownError(`The connection to the vault at ${this.options.vaultUrl} failed after the request may have reached it: ${detail}`)
      }
      throw new VaultNetworkError(`Could not reach the vault at ${this.options.vaultUrl}: ${detail}`)
    }
  }

  async request<T>(method: Method, path: string, body?: unknown, options?: VaultRequestOptions): Promise<T> {
    const text = body === undefined ? null : JSON.stringify(body)
    const response = await this.send(method, path, text, options)
    if (!response.ok || response.headers.has(ERROR_HEADER)) throw await readApiError(response, this.options.context ?? null)
    const payload = await response.text()
    if (payload.length === 0) return {} as T
    try {
      return JSON.parse(payload) as T
    } catch {
      throw new VaultApiError(response.status, { error: "internal", message: `The vault answered ${path} with something that is not JSON.` })
    }
  }

  // A write's answer is safe to send again only when the vault says, in a
  // refusal it can be read from, that it refused before forwarding anything
  // (Mehen-Forwarded: no), and that refusal is not its own failure; or, from
  // a vault that sends no Mehen-Forwarded, a readable refusal whose code it
  // only ever raised before forwarding (RELAY_PRE_FORWARD_CODES). Every
  // other answer to a write that is not the upstream's own may have come
  // after it took effect: RelayOutcomeUnknownError.
  async relay(request: RelayRequestInput, options?: VaultRequestOptions): Promise<Response> {
    const write = !retrySafeMethod(request.method)
    const response = await this.send("POST", "/v1/relay", JSON.stringify(request), options, write)
    if (response.headers.has(UPSTREAM_HEADER) && !response.headers.has(ERROR_HEADER)) return withDecodedHeaders(response)
    if (response.headers.has(ERROR_HEADER)) {
      if (!write) throw await readApiError(response, this.options.context ?? null, request.item ?? null)
      const text = await response.text().catch(() => null)
      const error = await readApiError(new Response(text, response), this.options.context ?? null, request.item ?? null)
      const readable = text !== null && readableError(text)
      const forwarded = response.headers.get(FORWARDED_HEADER)?.trim().toLowerCase()
      const beforeForwarding = forwarded === "no" || (forwarded === undefined && RELAY_PRE_FORWARD_CODES.has(error.body.error))
      if (readable && beforeForwarding && !(error.body.error === "internal" && response.status >= 500)) throw error
      throw new RelayOutcomeUnknownError(readable ? error.body.message : `The vault answered the write with HTTP ${response.status} and an error mehen cannot read.`)
    }
    await response.body?.cancel()
    const message = `The vault answered the relay with HTTP ${response.status} but neither ${UPSTREAM_HEADER} nor ${ERROR_HEADER}, so mehen will not treat it as the upstream's answer.`
    // Something in front of the vault, such as a proxy, may have answered
    // after the vault sent the write upstream.
    if (write) throw new RelayOutcomeUnknownError(message)
    throw new RelayUnmarkedAnswerError(response.status, { error: "internal", message })
  }
}

// Encodings Bun's fetch decodes on its own. It keeps Content-Encoding and
// Content-Length all the same, which would make anyone passing the response
// on (the local relay) decode twice or cut the body short.
const DECODED_BY_FETCH = new Set(["gzip", "x-gzip", "deflate", "br", "zstd"])

function withDecodedHeaders(response: Response): Response {
  const encoding = response.headers.get("content-encoding")?.trim().toLowerCase()
  if (!encoding || !DECODED_BY_FETCH.has(encoding)) return response
  const headers = new Headers(response.headers)
  headers.delete("content-encoding")
  headers.delete("content-length")
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers })
}
