// The release manifest and its signatures. A release lists its files with
// both checksums; the release tool signs the canonical JSON of the manifest
// without `signatures` with a P-256 key held in the release Mac's Secure
// Enclave, and an installed CLI installs only a manifest signed by a key
// compiled into it (release-keys.ts).
//
//   { version, commit, builtAt, files, signatures: [{ keyId, alg: "ES256", signature }] }
//
// `latest.json` is a byte copy of the version's manifest, so the signature
// covers what a client is told is latest. A key's `presence` records whether
// the enclave asks for Touch ID or the password per signature; the verifier
// cannot see it (a signature is a signature), the release tool refuses to
// sign when the key's sidecar and the compiled set disagree about it.

import { type Bytes, base64UrlDecode, utf8 } from "./bytes.ts"
import { canonicalJson } from "./canonical-json.ts"
import { importDeviceKey, isDeviceJwk } from "./proof.ts"

export type ReleaseFile = { name: string; os: string; arch: string; url: string; sha256: string; size: number; gzSha256: string; gzSize: number }
export type ReleaseManifest = { version: string; commit: string; builtAt: string; files: ReleaseFile[] }
export type ReleaseSignature = { keyId: string; alg: "ES256"; signature: string } // base64url of 64 bytes r||s
export type SignedManifest = ReleaseManifest & { signatures: ReleaseSignature[] }
export type ReleaseKeyPresence = "required" | "none"
export type ReleaseKey = { id: string; alg: "ES256"; jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }; presence: ReleaseKeyPresence; created: string }

export type ManifestVerification = { ok: true; keyId: string; manifest: SignedManifest } | { ok: false; reason: "unsigned" | "unknown_key" | "bad_signature" | "malformed" }

// More signatures than a release could need is malformed, so a hostile
// manifest cannot make a client run thousands of verifications.
const MAX_SIGNATURES = 16
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/

type Fields = Record<string, unknown>

function record(value: unknown): value is Fields {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function exactKeys(value: Fields, keys: readonly string[]): boolean {
  const present = Object.keys(value)
  return present.length === keys.length && keys.every((key) => Object.hasOwn(value, key))
}

function isReleaseFile(value: unknown): value is ReleaseFile {
  if (!record(value)) return false
  return ["name", "os", "arch", "url", "sha256", "gzSha256"].every((key) => typeof value[key] === "string") && typeof value.size === "number" && typeof value.gzSize === "number"
}

function isReleaseManifest(value: Fields): boolean {
  return typeof value.version === "string" && typeof value.commit === "string" && typeof value.builtAt === "string" && Array.isArray(value.files) && value.files.every(isReleaseFile)
}

function isSignature(value: unknown): value is ReleaseSignature {
  if (!record(value) || !exactKeys(value, ["keyId", "alg", "signature"])) return false
  if (typeof value.keyId !== "string" || !KEY_ID.test(value.keyId) || value.alg !== "ES256" || typeof value.signature !== "string") return false
  try {
    return base64UrlDecode(value.signature).length === 64
  } catch {
    return false
  }
}

// A release key as the compiled set, a sidecar or MEHEN_RELEASE_KEYS holds
// it: exactly these fields, and a public JWK with nothing but kty, crv, x and
// y, so private key material can never ride along in a trusted set.
export function isReleaseKey(value: unknown): value is ReleaseKey {
  if (!record(value) || !exactKeys(value, ["id", "alg", "jwk", "presence", "created"])) return false
  return (
    typeof value.id === "string" &&
    KEY_ID.test(value.id) &&
    value.alg === "ES256" &&
    record(value.jwk) &&
    exactKeys(value.jwk, ["kty", "crv", "x", "y"]) &&
    isDeviceJwk(value.jwk) &&
    (value.presence === "required" || value.presence === "none") &&
    typeof value.created === "string" &&
    !Number.isNaN(Date.parse(value.created))
  )
}

// The bytes a release signature covers: the canonical JSON of the manifest
// without `signatures` (every other field, known or not, is covered).
export function manifestSigningBytes(manifest: ReleaseManifest): Bytes {
  const { signatures: _signatures, ...unsigned } = manifest as ReleaseManifest & { signatures?: unknown }
  return utf8(canonicalJson(unsigned))
}

async function verifiesWith(key: ReleaseKey, signature: ReleaseSignature, data: Bytes): Promise<boolean> {
  try {
    const publicKey = await importDeviceKey(key.jwk)
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, base64UrlDecode(signature.signature), data)
  } catch {
    return false
  }
}

// One valid signature by a key in `keys` is enough. A manifest whose
// signatures name only keys outside the set is `unknown_key`; one whose
// trusted signatures all fail is `bad_signature`.
export async function verifyManifestSignatures(manifest: unknown, keys: readonly ReleaseKey[]): Promise<ManifestVerification> {
  if (!record(manifest) || !isReleaseManifest(manifest)) return { ok: false, reason: "malformed" }
  const signatures = manifest.signatures
  if (signatures === undefined || (Array.isArray(signatures) && signatures.length === 0)) return { ok: false, reason: "unsigned" }
  if (!Array.isArray(signatures) || signatures.length > MAX_SIGNATURES || !signatures.every(isSignature)) return { ok: false, reason: "malformed" }
  const data = manifestSigningBytes(manifest as ReleaseManifest)
  let trusted = false
  for (const signature of signatures) {
    const key = keys.find((k) => k.id === signature.keyId)
    if (!key) continue
    trusted = true
    if (await verifiesWith(key, signature, data)) return { ok: true, keyId: key.id, manifest: manifest as SignedManifest }
  }
  return { ok: false, reason: trusted ? "bad_signature" : "unknown_key" }
}
