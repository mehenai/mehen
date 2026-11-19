// A platform's P-256 key, in the browser: a pasted public JWK checked as
// scripts/platform.ts checks a key file (no private part, only kty, crv,
// x and y kept, the point on the curve), or a key pair made here with
// WebCrypto. A made key's private half is exported once as PKCS8 in
// base64url, for the operator to copy into the platform's secret store;
// only the public JWK is ever sent to the vault.

import { base64UrlEncode } from "@mehen/protocol/bytes"
import { PlatformJwkSchema } from "@mehen/protocol/platform"
import { type DeviceJwk, importDeviceKey, jwkThumbprint } from "@mehen/protocol/proof"

// PlatformJwkSchema's shape: a P-256 public key, as a device's is.
export type PlatformPublicJwk = DeviceJwk

export type PastedPlatformKey = { ok: true; jwk: PlatformPublicJwk; thumbprint: string } | { ok: false; problem: string }

// The largest paste looked at: a JWK is a few hundred characters.
export const PASTED_KEY_MAX = 4096

export const PASTED_KEY_PROBLEMS = {
  empty: "Paste the platform's public key first.",
  long: "That is far longer than a public key. Paste only the public JWK.",
  json: "That is not JSON. Paste the public key as the JWK the platform sent.",
  object: "That is not a JWK. Paste one JSON object with kty, crv, x and y.",
  private: "That holds a private key. Never paste a platform's private key here; ask the platform for the public half only.",
  shape: "That is not a P-256 public key. It needs kty EC, crv P-256 and its x and y.",
  curve: "That key's point is not on P-256. Ask the platform to send its public key again.",
} as const

// A private key in a form that is not a JWK: a PEM private key, or PKCS8 or
// SEC1 DER in base64 (a key made here is PKCS8 in base64url, MIGH...).
const NON_JWK_PRIVATE_KEY = /PRIVATE KEY|^MI[GH]|^MHcC/

export async function readPastedPlatformKey(text: string): Promise<PastedPlatformKey> {
  const trimmed = text.trim()
  if (trimmed === "") return { ok: false, problem: PASTED_KEY_PROBLEMS.empty }
  if (NON_JWK_PRIVATE_KEY.test(trimmed)) return { ok: false, problem: PASTED_KEY_PROBLEMS.private }
  if (trimmed.length > PASTED_KEY_MAX) return { ok: false, problem: PASTED_KEY_PROBLEMS.long }
  let raw: unknown
  try {
    raw = JSON.parse(trimmed)
  } catch {
    return { ok: false, problem: PASTED_KEY_PROBLEMS.json }
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return { ok: false, problem: PASTED_KEY_PROBLEMS.object }
  if ("d" in raw) return { ok: false, problem: PASTED_KEY_PROBLEMS.private }
  const { kty, crv, x, y } = raw as Record<string, unknown>
  const parsed = PlatformJwkSchema.safeParse({ kty, crv, x, y })
  if (!parsed.success) return { ok: false, problem: PASTED_KEY_PROBLEMS.shape }
  try {
    await importDeviceKey(parsed.data)
  } catch {
    return { ok: false, problem: PASTED_KEY_PROBLEMS.curve }
  }
  return { ok: true, jwk: parsed.data, thumbprint: await jwkThumbprint(parsed.data) }
}

// A key pair made in this browser. `privatePkcs8` is the only copy of the
// private half: the caller shows it once and lets it go.
export type MadePlatformKey = { jwk: PlatformPublicJwk; thumbprint: string; privatePkcs8: string }

const P256 = { name: "ECDSA", namedCurve: "P-256" } as const

export async function makePlatformKey(subtle: SubtleCrypto = crypto.subtle): Promise<MadePlatformKey> {
  // The Workers and DOM libraries type these calls differently; both
  // answer a key pair, a JWK and the PKCS8 bytes for these arguments.
  const pair = (await subtle.generateKey(P256, true, ["sign", "verify"])) as CryptoKeyPair
  const exported = (await subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey
  const jwk = PlatformJwkSchema.parse({ kty: exported.kty, crv: exported.crv, x: exported.x, y: exported.y })
  const pkcs8 = new Uint8Array((await subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer)
  const privatePkcs8 = base64UrlEncode(pkcs8)
  // The exported bytes are not kept past the text the operator copies.
  pkcs8.fill(0)
  return { jwk, thumbprint: await jwkThumbprint(jwk), privatePkcs8 }
}

// What the platform's server runs to load the key it was given, shown
// beside the private key so the format is never guessed.
export const PKCS8_IMPORT_LINE = 'crypto.subtle.importKey("pkcs8", base64url-decoded bytes, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])'

// The public JWK as the platform and the operator compare it: kty, crv, x
// and y, nothing else.
export function publicJwkText(jwk: PlatformPublicJwk): string {
  return JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y })
}
