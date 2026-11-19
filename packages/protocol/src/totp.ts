// One-time codes (RFC 6238) computed by the vault from a stored seed, so
// the asking machine's clock never matters. WebCrypto HMAC only: it runs in
// workerd, Bun and browsers alike.
import type { Bytes } from "./bytes.ts"

export type TotpAlgorithm = "SHA-1" | "SHA-256" | "SHA-512"
export type Totp = { secret: Bytes; algorithm: TotpAlgorithm; digits: number; period: number }
export type TotpParse = { ok: true; totp: Totp } | { ok: false; reason: string }

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
const MAX_SEED_LENGTH = 1024
const MIN_SECRET_BYTES = 10 // 80 bits, RFC 4226's floor
const NOT_READABLE = "This is not a base32 secret or an otpauth://totp link."

// RFC 4648 base32. Authenticator apps show secrets in lower case, grouped
// with spaces and without padding, so those read too; a length no encoder
// produces does not.
export function base32Decode(text: string): Bytes | null {
  const body = text.replace(/\s/g, "").toUpperCase().replace(/=+$/, "")
  if (![0, 2, 4, 5, 7].includes(body.length % 8)) return null
  const out = new Uint8Array(Math.floor((body.length * 5) / 8))
  let bits = 0, value = 0, at = 0
  for (const char of body) {
    const index = ALPHABET.indexOf(char)
    if (index < 0) return null
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out[at++] = (value >> bits) & 0xff
    }
  }
  return out
}

const ALGORITHMS: Record<string, TotpAlgorithm> = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" }

function intIn(text: string | null, fallback: number, min: number, max: number): number | null {
  if (text === null) return fallback
  if (!/^[0-9]{1,4}$/.test(text)) return null
  const n = Number(text)
  return n >= min && n <= max ? n : null
}

// A bare base32 secret (SHA-1, 6 digits, 30 seconds), or an otpauth://totp
// link naming its algorithm, digits and period. Counter-based codes, Steam's
// own alphabet and secrets under 80 bits are refused. The reasons never
// repeat any of the seed.
export function parseTotp(seed: string): TotpParse {
  const text = seed.trim()
  if (text.length > MAX_SEED_LENGTH) return { ok: false, reason: "The secret is too long." }
  if (!/^otpauth:\/\//i.test(text)) return secretOf(base32Decode(text), { algorithm: "SHA-1", digits: 6, period: 30 })
  let url: URL
  try { url = new URL(text) } catch { return { ok: false, reason: NOT_READABLE } }
  const type = url.host.toLowerCase()
  if (type === "hotp") return { ok: false, reason: "This is a counter-based (HOTP) code; only time-based (TOTP) codes are supported." }
  if (type !== "totp") return { ok: false, reason: NOT_READABLE }
  const params = url.searchParams
  for (const key of ["secret", "algorithm", "digits", "period", "encoder"]) if (params.getAll(key).length > 1) return { ok: false, reason: `The link names ${key} twice.` }
  if (params.get("encoder")?.toLowerCase() === "steam") return { ok: false, reason: "Steam Guard codes are not supported." }
  const secret = params.get("secret")
  if (secret === null) return { ok: false, reason: "The link has no secret." }
  const algorithm = ALGORITHMS[(params.get("algorithm") ?? "SHA1").toUpperCase()]
  if (algorithm === undefined) return { ok: false, reason: "The algorithm must be SHA1, SHA256 or SHA512." }
  const digits = intIn(params.get("digits"), 6, 6, 8)
  if (digits === null) return { ok: false, reason: "The number of digits must be 6, 7 or 8." }
  const period = intIn(params.get("period"), 30, 15, 120)
  if (period === null) return { ok: false, reason: "The period must be 15 to 120 seconds." }
  return secretOf(base32Decode(secret), { algorithm, digits, period })
}

function secretOf(secret: Bytes | null, terms: Omit<Totp, "secret">): TotpParse {
  if (secret === null || secret.length === 0) return { ok: false, reason: NOT_READABLE }
  if (secret.length < MIN_SECRET_BYTES) return { ok: false, reason: "The secret is shorter than 80 bits." }
  return { ok: true, totp: { secret, ...terms } }
}

// The code for the step holding nowMs, and when that step ends. Callers pass
// the vault's clock.
export async function totpCode(totp: Totp, nowMs: number): Promise<{ code: string; step: number; validUntilMs: number }> {
  if (!Number.isFinite(nowMs) || nowMs < 0) throw new RangeError("nowMs must be a time")
  const step = Math.floor(nowMs / 1000 / totp.period)
  const counter = new DataView(new ArrayBuffer(8))
  counter.setUint32(0, Math.floor(step / 2 ** 32))
  counter.setUint32(4, step >>> 0)
  const key = await crypto.subtle.importKey("raw", totp.secret, { name: "HMAC", hash: totp.algorithm }, false, ["sign"])
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter.buffer))
  const offset = mac[mac.length - 1]! & 0x0f
  const binary = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!
  const code = String(binary % 10 ** totp.digits).padStart(totp.digits, "0")
  return { code, step, validUntilMs: (step + 1) * totp.period * 1000 }
}
