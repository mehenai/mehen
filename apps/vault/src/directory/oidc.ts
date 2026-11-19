import { base64UrlDecode, checkOidcClaims, OIDC_LIMITS, OIDC_PROVIDERS, type OidcClaimRefusal, type OidcClaims } from "@mehen/protocol"
import { z } from "zod"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"

export type OidcFetch = (url: string, init: RequestInit) => Promise<Response>
let providerFetch: OidcFetch = (url, init) => fetch(url, init)
let cached: { keys: z.infer<typeof Key>[]; freshUntil: number; staleUntil: number } | null = null
/** Test-only transport seam. Production endpoints and signature checks stay pinned. */
export function setOidcFetchForTest(value: OidcFetch | null): void { providerFetch = value ?? ((url, init) => fetch(url, init)); cached = null }
const Key = z.object({ kty: z.literal("RSA"), kid: z.string().min(1).max(255), n: z.string().min(342).max(1400), e: z.literal("AQAB"), alg: z.literal("RS256").optional(), use: z.literal("sig").optional() })
const Keys = z.object({ keys: z.array(z.unknown()).max(32) })
const Header = z.object({ alg: z.literal("RS256"), kid: z.string().min(1).max(255), typ: z.literal("JWT").optional() })
export const OidcPurpose = z.enum(["signin", "invite", "link", "gate"])
// One code per distinct cause a Google step is refused, logged so an operator
// can say why a sign-in failed without the log holding anything personal.
export type OidcRefusalReason = "not_configured" | "request_invalid" | "state_unknown" | "cookie_missing" | "cookie_mismatch" | "result_cookie_missing" | "flow_consumed" | "flow_expired" | "provider_error" | "code_missing" | "session_ended" | "account_restricted" | "epoch_changed" | "token_exchange_failed" | "jwks_unavailable" | "id_token_invalid" | "audience_mismatch" | "nonce_mismatch" | "email_unverified" | "invite_inactive" | "invite_email_mismatch" | "invite_context_missing" | "invite_changed" | "already_linked_elsewhere" | "domain_rule" | "result_unavailable" | "account_mismatch" | "confirmation_mismatch" | "member_inactive" | "gate_changed" | "no_linked_identity"
const GOOGLE_ERRORS = ["access_denied", "admin_policy_enforced", "org_internal", "invalid_scope", "unauthorized_client", "invalid_request", "unsupported_response_type", "server_error", "temporarily_unavailable"] as const
export type GoogleError = typeof GOOGLE_ERRORS[number] | "other"
export function googleError(value: string | null): GoogleError { return GOOGLE_ERRORS.find(known => known === value) ?? "other" }
export const OIDC_REFUSAL = "Google verification could not be completed. Start the Google step again from the page that asked for it."
export const OIDC_INVITE_EMAIL_REFUSAL = "This invitation is for a different email address. Choose the Google account for the address the invitation was sent to, or ask whoever invited you to invite this one."
export const OIDC_NOT_LINKED_REFUSAL = "This Google account is not linked to a Mehen account yet. Sign in with your passkey and link Google from your account page, or use your invitation link."
// A flow's lifetime comes from its own row: ten minutes on the web, five for an app's identity check.
export function oidcFlowEnded(purpose: z.infer<typeof OidcPurpose> | null, minutes: number | undefined): string { return `This sign-in link has expired or was already used. Start again from ${purpose === "invite" ? "the invitation" : "the page that sent you to Google"} and finish within ${minutes === undefined ? "a few" : minutes} minutes without refreshing.` }
export const OIDC_OTHER_BROWSER = "Finish in the same browser you started in. Links opened inside a mail or chat app open their own browser; copy the link into your usual browser."
export const OIDC_TOO_LONG_OR_OTHER_BROWSER = "This Google step took too long or was finished in another browser. Start it again here."
export const OIDC_NEWER_START = "This browser started another sign-in after this one; finish the most recent one, or start again here."
export const OIDC_GOOGLE_CANCELLED = "You cancelled at Google, or Google refused the request. Start again when you are ready."
export const OIDC_GOOGLE_BLOCKED = "Google did not let you sign in. Your Google admin, or this app's Google settings, do not allow this Google account here. Ask your Google admin, or whoever runs Mehen for you, to allow it."
export const OIDC_GOOGLE_REFUSED = "Google did not let you sign in. Start again from the page that sent you to Google."
export const OIDC_INVITE_INACTIVE = "This invitation is no longer active. Ask whoever invited you to send a new one."
export const OIDC_LINKED_ELSEWHERE = "This Google account is linked to another Mehen account. Sign in with that account to accept, or use a different Google account."
// What the person can do about a refusal; a cause they cannot act on keeps
// the general message.
function oidcRefusalMessage(reason: OidcRefusalReason, purpose: z.infer<typeof OidcPurpose> | null, google?: GoogleError, flowMinutes?: number): string {
  switch (reason) {
    case "flow_expired": case "flow_consumed": return oidcFlowEnded(purpose, flowMinutes)
    case "cookie_missing": return OIDC_OTHER_BROWSER
    case "cookie_mismatch": return OIDC_NEWER_START
    case "result_cookie_missing": return OIDC_TOO_LONG_OR_OTHER_BROWSER
    case "provider_error": return google === "access_denied" ? OIDC_GOOGLE_CANCELLED : google === "admin_policy_enforced" || google === "org_internal" ? OIDC_GOOGLE_BLOCKED : OIDC_GOOGLE_REFUSED
    case "invite_inactive": return OIDC_INVITE_INACTIVE
    case "invite_email_mismatch": return OIDC_INVITE_EMAIL_REFUSAL
    case "already_linked_elsewhere": return OIDC_LINKED_ELSEWHERE
    case "no_linked_identity": return purpose === "signin" ? OIDC_NOT_LINKED_REFUSAL : OIDC_REFUSAL
    default: return OIDC_REFUSAL
  }
}
function logOidcRefusal(reason: OidcRefusalReason, purpose: z.infer<typeof OidcPurpose> | null, google?: GoogleError): void {
  console.warn(JSON.stringify({ at: "oidc.refused", reason, purpose, provider: "google", ...(google ? { googleError: google } : {}) }))
}
export function oidcRefusal(reason: OidcRefusalReason, purpose: z.infer<typeof OidcPurpose> | null, google?: GoogleError, flowMinutes?: number): VaultError {
  logOidcRefusal(reason, purpose, google)
  return new VaultError("identity_required", oidcRefusalMessage(reason, purpose, google, flowMinutes))
}
// A Google step that finds its invitation no longer active keeps the
// not_found answer the invitation pages already handle.
export function oidcInviteNotFound(purpose: z.infer<typeof OidcPurpose>): VaultError {
  logOidcRefusal("invite_inactive", purpose)
  return new VaultError("not_found", "No such invite.", { reason: "invite_inactive" })
}
export function oidcConfigured(env: Env): boolean { return Boolean(env.GOOGLE_SIGNIN_CLIENT_ID && env.GOOGLE_SIGNIN_CLIENT_SECRET) }
// A refusal inside Google's token check, turned into a logged refusal once,
// at the boundary that knows the purpose.
class GoogleTokenRefused extends Error { constructor(readonly reason: OidcRefusalReason) { super(reason) } }
async function boundedJson(response: Response, limit: number): Promise<unknown> {
  if (!response.ok || Number(response.headers.get("content-length")) > limit || !response.body) throw new Error("Unusable Google response")
  const reader = response.body.getReader(), chunks: Uint8Array[] = []
  let size = 0
  try {
    for (;;) { const chunk = await reader.read(); if (chunk.done) break; size += chunk.value.length; if (size > limit) throw new Error("Oversized Google response"); chunks.push(chunk.value) }
    const bytes = new Uint8Array(size); let offset = 0
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes)) as unknown
  } finally { await reader.cancel().catch(() => undefined) }
}
async function requestJson(url: string, init: RequestInit, limit: number): Promise<{ value: unknown; response: Response }> {
  const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), OIDC_LIMITS.fetchTimeoutMs)
  try {
    // Workers refuses redirect "error"; "manual" leaves a redirect as a 3xx,
    // which boundedJson refuses like any other status that is not ok.
    const response = await providerFetch(url, { ...init, redirect: "manual", signal: controller.signal })
    return { value: await boundedJson(response, limit), response }
  } finally { clearTimeout(timeout) }
}
async function keys(now: number, refresh: boolean): Promise<z.infer<typeof Key>[]> {
  if (!refresh && cached && cached.freshUntil > now) return cached.keys
  try {
    const { value, response } = await requestJson(OIDC_PROVIDERS.google.jwks, {}, OIDC_LIMITS.jwksBytes)
    const usable = Keys.parse(value).keys.flatMap(value => { const parsed = Key.safeParse(value); return parsed.success ? [parsed.data] : [] })
    if (!usable.length || new Set(usable.map(key => key.kid)).size !== usable.length) throw new Error("No usable Google signing key")
    const maxAge = Math.min(86400, Number(response.headers.get("cache-control")?.match(/(?:^|,)\s*max-age=(\d+)/)?.[1] ?? 0)) * 1000
    cached = { keys: usable, freshUntil: now + maxAge, staleUntil: now + maxAge + 86400000 }
    return usable
  } catch { if (!refresh && cached && cached.staleUntil > now) return cached.keys; throw new GoogleTokenRefused("jwks_unavailable") }
}
function claimRefusal(reason: OidcClaimRefusal, claims: unknown): OidcRefusalReason {
  if (reason === "audience_invalid") return "audience_mismatch"
  if (reason === "nonce_invalid") return "nonce_mismatch"
  if (reason === "claims_invalid" && !z.object({ email_verified: z.literal(true) }).safeParse(claims).success) return "email_unverified"
  return "id_token_invalid"
}
export async function verifyGoogleToken(token: string, expected: { clientId: string; nonce: string; now: number }, purpose: z.infer<typeof OidcPurpose> | null = null): Promise<OidcClaims> {
  try {
    if (new TextEncoder().encode(token).length > OIDC_LIMITS.tokenBytes) throw new GoogleTokenRefused("id_token_invalid")
    const parts = token.split(".")
    if (parts.length !== 3 || parts.some(part => !/^[A-Za-z0-9_-]+$/.test(part))) throw new GoogleTokenRefused("id_token_invalid")
    const header = Header.parse(JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0]!))))
    let candidates = await keys(expected.now, false), jwk = candidates.find(key => key.kid === header.kid)
    if (!jwk) { candidates = await keys(expected.now, true); jwk = candidates.find(key => key.kid === header.kid) }
    if (!jwk) throw new GoogleTokenRefused("id_token_invalid")
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"])
    if (!await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, base64UrlDecode(parts[2]!), new TextEncoder().encode(`${parts[0]}.${parts[1]}`))) throw new GoogleTokenRefused("id_token_invalid")
    const claims: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(base64UrlDecode(parts[1]!))), result = checkOidcClaims(claims, expected)
    if (!result.ok) throw new GoogleTokenRefused(claimRefusal(result.reason, claims))
    return result.claims
  } catch (error) { throw oidcRefusal(error instanceof GoogleTokenRefused ? error.reason : "id_token_invalid", purpose) }
}
export async function exchangeGoogleCode(env: Env, code: string, verifier: string, nonce: string, purpose: z.infer<typeof OidcPurpose>, now = Date.now()): Promise<OidcClaims> {
  if (!oidcConfigured(env)) throw oidcRefusal("not_configured", purpose)
  let token: string
  try {
    const { value } = await requestJson(OIDC_PROVIDERS.google.token, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: `${env.VAULT_ORIGIN}/auth/oidc/google/callback`, client_id: env.GOOGLE_SIGNIN_CLIENT_ID!, client_secret: env.GOOGLE_SIGNIN_CLIENT_SECRET!, code_verifier: verifier }) }, OIDC_LIMITS.tokenBytes * 2)
    token = z.object({ id_token: z.string().max(OIDC_LIMITS.tokenBytes) }).parse(value).id_token
  } catch { throw oidcRefusal("token_exchange_failed", purpose) }
  return verifyGoogleToken(token, { clientId: env.GOOGLE_SIGNIN_CLIENT_ID!, nonce, now }, purpose)
}
