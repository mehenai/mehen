// What every push adapter shares: the calls go only to URLs built from a
// canonical destination, through upstreamFetch, with no redirects followed
// and a deadline; only named fields are read from an answer; any provider
// text kept for a message is scrubbed with the relay's scrubber, needles
// for the value (and its base64 forms) and the via's token, and cut short.
// A provider's answer becomes a vault error as push-providers design 2.6
// says.

import { MIN_SECRET_LENGTH, type PushDestination, type PushOutcome, type RedactionSecret, buildNeedles, redactText } from "@mehen/protocol"
import { VaultError } from "../http.ts"
import { upstreamFetch } from "../relay/upstream.ts"

export type PushCall = { method: "GET" | "PUT" | "POST"; url: string }

// Every request a push to one destination may make, for the via's binding
// and policy check before anyone is asked: the preview reads, then the
// write (GitHub's public key read is part of its write).
export type PushCalls = { preview: PushCall[]; write: PushCall[] }

// The credential that carries the push: its slug for messages, its headers
// with the token injected, and its values to scrub.
export type PushVia = { slug: string; headers: [string, string][]; scrub: RedactionSecret[] }

// The value pushed, labelled with the item's slug for redaction.
export type PushValue = RedactionSecret

export type PushWritten = { outcome: PushOutcome; providerStatus: number }

// Whether the via's policy lets the vault make this preview read without
// asking; a read it does not allow is not made.
export type PreviewAllowed = (call: PushCall) => boolean

export const PUSH_TIMEOUT_MS = 10_000
// The most of any answer read; the fields named are small.
export const MAX_PUSH_ANSWER_BYTES = 64 * 1024
// The most of a provider's own message kept, after scrubbing.
export const MAX_PROVIDER_MESSAGE = 200
const PUSH_USER_AGENT = "mehen-push"

// How a provider's refusal is worded. `place` names the destination's
// container ("example/mehen"), `store` what is written ("secrets").
export type ProviderWords = { provider: string; place: string; store: string }

export function encodeSegment(segment: string): string {
  return encodeURIComponent(segment)
}

export type Answer = { status: number; headers: Headers; body: unknown }

// One call to the provider. Network failure or a timeout is upstream_failed
// with nothing known to have been written.
export async function pushFetch(call: PushCall, via: PushVia, words: ProviderWords, extraHeaders: [string, string][], body: unknown = null): Promise<Answer> {
  const headers = new Headers(via.headers)
  for (const [name, value] of extraHeaders) headers.set(name, value)
  if (!headers.has("user-agent")) headers.set("user-agent", PUSH_USER_AGENT)
  if (body !== null) headers.set("content-type", "application/json")
  let response: Response
  try {
    response = await upstreamFetch(new Request(call.url, { method: call.method, headers, body: body === null ? null : JSON.stringify(body), redirect: "manual", signal: AbortSignal.timeout(PUSH_TIMEOUT_MS) }))
  } catch {
    throw new VaultError("upstream_failed", `${words.provider} did not answer; nothing is known to have been written.`, { retryAfter: 5 })
  }
  return { status: response.status, headers: response.headers, body: await readJson(response) }
}

// The answer's JSON, or null for an empty, oversized or non-JSON body.
async function readJson(response: Response): Promise<unknown> {
  if (response.body === null) return null
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.length
      if (size > MAX_PUSH_ANSWER_BYTES) {
        await reader.cancel()
        return null
      }
      chunks.push(value)
    }
  } catch {
    return null
  }
  const bytes = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.length
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes)) as unknown
  } catch {
    return null
  }
}

export function field(value: unknown, key: string): unknown {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>)[key] : undefined
}

export function stringField(value: unknown, key: string): string | null {
  const found = field(value, key)
  return typeof found === "string" ? found : null
}

export function booleanField(value: unknown, key: string): boolean | null {
  const found = field(value, key)
  return typeof found === "boolean" ? found : null
}

// The seconds to wait when the answer says the provider is limiting
// requests: 429, or 403 with retry-after or no requests remaining.
export function rateLimitWait(answer: Answer, now = Date.now()): number | null {
  const retryAfter = answer.headers.get("retry-after")
  const remaining = answer.headers.get("x-ratelimit-remaining")
  const limited = answer.status === 429 || (answer.status === 403 && (retryAfter !== null || remaining?.trim() === "0"))
  if (!limited) return null
  if (retryAfter !== null && /^\d+$/.test(retryAfter.trim())) return Math.max(1, Number(retryAfter.trim()))
  const reset = answer.headers.get("x-ratelimit-reset")
  if (reset !== null && /^\d+$/.test(reset.trim())) return Math.max(1, Number(reset.trim()) - Math.floor(now / 1000))
  return 60
}

// The provider's own message, scrubbed of the value and the via's token,
// with no control or bidi character (a control character becomes a space,
// so words stay apart), on one line and cut to MAX_PROVIDER_MESSAGE
// characters. None of it is kept for a value too short for the scrubber to
// find.
export function scrubbedMessage(message: string | null, value: PushValue, via: PushVia): string | null {
  if (message === null || value.value.length < MIN_SECRET_LENGTH) return null
  const scrubbed = redactText(message, buildNeedles([value, ...via.scrub]))
  const clean = scrubbed.replace(/[\u202a-\u202e\u2066-\u2069]/g, "").replace(/[\x00-\x1f\x7f]/g, " ").replace(/\s+/g, " ").trim()
  if (clean === "") return null
  return clean.length > MAX_PROVIDER_MESSAGE ? `${clean.slice(0, MAX_PROVIDER_MESSAGE - 3)}...` : clean
}

export function providerRefused(status: number, message: string): VaultError {
  return new VaultError("provider_refused", message, { providerStatus: status })
}

// A provider's refusal as a vault error, per design 2.6. `message` is the
// provider's own text, already scrubbed, kept only for a refusal without
// fixed words (a 422 and the other 4xx).
export function answerError(answer: Answer, via: PushVia, words: ProviderWords, message: string | null): VaultError {
  const wait = rateLimitWait(answer)
  if (wait !== null) return new VaultError("rate_limited", `${words.provider} is limiting requests; ask again after ${wait} seconds.`, { retryAfter: wait })
  const { status } = answer
  if (status >= 500) return new VaultError("upstream_failed", `${words.provider} did not answer (${status}); nothing is known to have been written.`, { retryAfter: 5 })
  if (status === 401) return providerRefused(status, `${words.provider} refused ${via.slug}: the token is invalid or expired.`)
  if (status === 403) return providerRefused(status, `${via.slug} may not write ${words.store} in ${words.place}.`)
  if (status === 404) return providerRefused(status, `${words.provider} says ${words.place} does not exist, or ${via.slug} cannot see it.`)
  if (status >= 300 && status < 400) return providerRefused(status, `${words.provider} answered with a redirect, which Mehen does not follow: ${words.place} may have been renamed or moved.`)
  return providerRefused(status, `${words.provider} refused it (${status})${message === null ? "." : `: ${message}`}`)
}

// A 2xx whose answer could not be read (empty, oversized, cut off or not
// the provider's shape): the provider took the request, so the value may
// have been written.
export function unreadableAnswer(words: ProviderWords, thing: string): VaultError {
  return new VaultError("upstream_failed", `${words.provider} answered but Mehen could not read the answer; the ${thing} may have been written. Check ${words.provider}.`)
}

// A preview read: the answer when it is a 2xx or a 404 (a secret not there
// yet); a refusal thrown when the read shows the push cannot work (a 401
// anywhere, a 404 on the destination's container when `refuseMissing`, or
// a rate limit); null for any other answer or no answer, which leaves the
// preview's fields unknown.
export async function previewRead(call: PushCall, via: PushVia, words: ProviderWords, extraHeaders: [string, string][], refuseMissing: boolean): Promise<Answer | null> {
  let answer: Answer
  try {
    answer = await pushFetch(call, via, words, extraHeaders)
  } catch {
    return null
  }
  if (rateLimitWait(answer) !== null || answer.status === 401 || (answer.status === 404 && refuseMissing)) throw answerError(answer, via, words, null)
  return (answer.status >= 200 && answer.status < 300) || answer.status === 404 ? answer : null
}

export function ok(answer: Answer): boolean {
  return answer.status >= 200 && answer.status < 300
}

// A preview read that the provider answered with a 2xx.
export function readOk(answer: Answer | null): answer is Answer {
  return answer !== null && ok(answer)
}

// The destinations each adapter takes.
export type GitHubDestination = Extract<PushDestination, { provider: "github" }>
export type VercelDestination = Extract<PushDestination, { provider: "vercel" }>
export type CloudflareDestination = Extract<PushDestination, { provider: "cloudflare" }>
export type FlyDestination = Extract<PushDestination, { provider: "fly" }>
