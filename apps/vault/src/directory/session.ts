// Web sessions for the browser: an opaque random token in a __Host- cookie,
// stored hashed in D1. Seven days idle, thirty days at most; a recovery
// session lives fifteen minutes and can do nothing but register a passkey.
//
// Each session row also says how it was opened and from where, in words a
// member can recognise: a client label from a closed vocabulary (never the
// raw User-Agent) and Cloudflare's city and country (never an IP).

import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"

export const SESSION_COOKIE = "__Host-mehen_session"
export const IDLE_MS = 7 * 86_400_000
const ABSOLUTE_MS = 30 * 86_400_000
export const RECOVERY_SESSION_MS = 15 * 60_000
export const MAX_SESSIONS = 20

export type RestrictionReason = "recovery" | "reset" | "break-glass"

export type Member = {
  member: string
  tenant: string
  role: "owner" | "member"
  name: string
  session: string // ses_ id of the session in use
  passkey: string | null // credential id that opened it
  // Set while a cooling-off runs; null once it has ended.
  restrictedUntil: number | null
  restrictedReason: RestrictionReason | null
}

export type SessionKind = "web" | "recovery" | "app"
export type SessionMethod = "signup" | "passkey" | "recovery" | "reset"
export type SessionMeta = { kind: SessionKind; method: SessionMethod; passkey: string | null; client: string; place: string | null }

export async function sha256Text(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))
  let bin = ""
  for (const b of new Uint8Array(digest)) bin += String.fromCharCode(b)
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "")
}

export function randomToken(bytes = 32): string {
  let bin = ""
  for (const b of crypto.getRandomValues(new Uint8Array(bytes))) bin += String.fromCharCode(b)
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "")
}

// Public handles in the directory: "pk_", "ses_" or "ntc_" and 20 lower-case
// hex digits, the same shape migration 0004 gave the rows it backfilled.
export function directoryId(prefix: "pk" | "ses" | "ntc"): string {
  let hex = ""
  for (const b of crypto.getRandomValues(new Uint8Array(10))) hex += b.toString(16).padStart(2, "0")
  return `${prefix}_${hex}`
}

export type NewSession = { token: string; tokenHash: string; id: string }

export async function newSession(): Promise<NewSession> {
  const token = randomToken()
  return { token, tokenHash: await sha256Text(token), id: directoryId("ses") }
}

// Always Secure: a browser refuses a __Host- cookie without it, and it
// treats http://localhost as secure, so local dev keeps its session too.
export function sessionCookie(token: string): string {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${ABSOLUTE_MS / 1000}; Secure`
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure`
}

export function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("cookie")
  if (!header) return null
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=")
    if (k === name) return v.join("=")
  }
  return null
}

const BROWSERS: [RegExp, string][] = [
  [/\bEdg(e|A|iOS)?\//, "Edge"],
  [/\b(Firefox|FxiOS)\//, "Firefox"],
  [/\b(Chrome|CriOS|Chromium)\//, "Chrome"],
  [/\bVersion\/[\d.]+.*\bSafari\//, "Safari"],
]

const PLATFORMS: [RegExp, string][] = [
  [/\biPhone\b/, "iPhone"],
  [/\biPad\b/, "iPad"],
  [/\bAndroid\b/, "Android"],
  [/\bWindows\b/, "Windows"],
  [/\bCrOS\b/, "ChromeOS"],
  [/\bMacintosh\b/, "Mac"],
  [/\bLinux\b/, "Linux"],
]

// The mehen CLI identifies itself as `mehen/<x.y.z> (<os>-<arch>; <build>)`.
const MEHEN_AGENT = /^mehen\/(\d{1,6}\.\d{1,6}\.\d{1,6})(?![\d.])(?: \((darwin|linux)-)?/

// The client library (@mehen/client) identifies itself as
// `mehen-client/<x.y.z>`, optionally followed by the host's own product
// token, `name/version`. Never `mehen/`: the CLI version gate ignores it.
const MEHEN_CLIENT_AGENT = /^mehen-client\/(\d{1,6}\.\d{1,6}\.\d{1,6})(?![\d.])(?: +(\S+))?/
const PRODUCT_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._+-]*$/
const PRODUCT_MAX = 40
// The host's product token as shown: only a plain `name/version`, cut to
// PRODUCT_MAX characters; anything else is left out.
function productToken(raw: string | undefined): string | null {
  if (raw === undefined || !PRODUCT_TOKEN.test(raw)) return null
  return raw.slice(0, PRODUCT_MAX)
}

// "Safari on Mac", "Chrome on Windows", "A browser on Linux", "A browser",
// "mehen 0.3.0 on macOS", "mehen-client 0.1.0 (globex/2.4.1)": built from fixed
// words, bounded digits and a bounded plain token only, so nothing else a
// client sends reaches a page.
export function clientLabel(userAgent: string | null): string {
  const ua = (userAgent ?? "").slice(0, 512)
  const mehen = MEHEN_AGENT.exec(ua)
  if (mehen) return `mehen ${mehen[1]}${mehen[2] === "darwin" ? " on macOS" : mehen[2] === "linux" ? " on Linux" : ""}`
  const library = MEHEN_CLIENT_AGENT.exec(ua)
  if (library) {
    const product = productToken(library[2])
    return `mehen-client ${library[1]}${product !== null ? ` (${product})` : ""}`
  }
  const browser = BROWSERS.find(([pattern]) => pattern.test(ua))?.[1] ?? null
  const platform = PLATFORMS.find(([pattern]) => pattern.test(ua))?.[1] ?? null
  if (platform === null) return browser ?? "A browser"
  return `${browser ?? "A browser"} on ${platform}`
}

const PLACE_MAX = 64
const COUNTRY = /^[A-Z][A-Z0-9]$/

function cleanCity(value: unknown): string | null {
  if (typeof value !== "string") return null
  const city = Array.from(
    value
      .normalize("NFC")
      .replace(/\p{C}/gu, "")
      .replace(/\s+/g, " ")
      .trim(),
  )
    .slice(0, PLACE_MAX - 4)
    .join("")
    .trim()
  return city === "" ? null : city
}

// Whether the connection came from this machine: a local vault (apps/local)
// puts the peer's address in cf-connecting-ip, which Cloudflare sets for
// itself and which is never loopback there. Only that one answer is read
// from the address; nothing keeps or shows it.
export function loopbackPeer(request: Request): boolean {
  const ip = request.headers.get("cf-connecting-ip") ?? ""
  return /^(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1|::ffff:127\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.test(ip)
}

// "Amsterdam, NL" from Cloudflare's view of the connection; null when it
// says nothing. The address itself is never read.
export function placeOf(request: Request): string | null {
  const cf: unknown = request.cf
  if (typeof cf !== "object" || cf === null) return null
  const { city, country } = cf as { city?: unknown; country?: unknown }
  const cc = typeof country === "string" && COUNTRY.test(country) ? country : null
  const town = cleanCity(city)
  if (town !== null && cc !== null) return `${town}, ${cc}`
  return town ?? cc
}

export function live(row: { expires_at: number; last_seen_at: number; kind: SessionKind }, now: number): boolean {
  if (row.expires_at <= now) return false
  return row.kind === "recovery" || row.last_seen_at + IDLE_MS > now
}

// State-changing browser requests must come from our own pages.
export function assertSameOrigin(request: Request, env: Env): void {
  const origin = request.headers.get("origin")
  const site = request.headers.get("sec-fetch-site")
  if (origin !== env.VAULT_ORIGIN || (site !== null && site !== "same-origin")) {
    throw new VaultError("forbidden", "Cross-site request refused.")
  }
}
