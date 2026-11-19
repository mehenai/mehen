// Device proofs: every API request from a machine carries a signature by
// that machine's device key over exactly what it asks for. There is no
// bearer token anywhere, so nothing on disk or in a log can be replayed.
//
// The proof is a compact JWS (ES256, P-256) in the `Mehen-Proof` header:
//
//   header  { alg: "ES256", typ: "mehen-proof+jwt", kid: <device id, or workload id> }
//   payload { ten, dev, wkl?, sid?, gnt?, htm, htu, bh, iat, jti }
//
// A workload (a child key a device created, see workload.ts) signs with its
// own key: `kid` and `wkl` are the workload id and `dev` its parent device.
// A vault that predates workloads refuses such a proof, since `kid` is not
// `dev`, so a workload never runs with its parent's wider reach.
//
// `htu` is the full request URL without fragment, `bh` the base64url
// SHA-256 of the exact body bytes (of the empty string for no body). The
// server rebuilds both from the request it received, checks `iat` within
// the skew window and refuses a `jti` it has already seen.

import { type Bytes, base64UrlDecode, base64UrlEncode, fromUtf8, randomId, sha256B64, utf8 } from "./bytes.ts"

export const PROOF_HEADER = "Mehen-Proof"
export const PROOF_TYPE = "mehen-proof+jwt"
export const PROOF_MAX_SKEW_SECONDS = 60

export type ProofClaims = {
  ten: string // tenant id
  dev: string // device id (the parent device, for a workload)
  wkl?: string // workload id, when a workload signed
  sid?: string // agent session label (audit only)
  gnt?: string // grant id the request acts under, when attenuated
  htm: string // HTTP method, upper case
  htu: string // request URL, no fragment
  bh: string // base64url SHA-256 of the body
  iat: number // seconds since the epoch
  jti: string // unique per request
}

// Anything that can produce a raw r||s ES256 signature: a Secure Enclave
// helper, a WebCrypto key, a TPM.
export type ProofSigner = {
  deviceId: string
  // Set when the key is a workload's: the proof is then the workload's.
  workloadId?: string
  sign(data: Bytes): Promise<Bytes>
}

export type ProofRequest = {
  method: string
  url: string
  body?: Bytes | string | null
}

export function normaliseUrl(url: string): string {
  const parsed = new URL(url)
  parsed.hash = ""
  return parsed.toString()
}

export async function bodyHash(body: Bytes | string | null | undefined): Promise<string> {
  return sha256B64(body ?? new Uint8Array())
}

export async function createProof(
  signer: ProofSigner,
  request: ProofRequest,
  context: { tenant: string; session?: string; grant?: string; now?: number },
): Promise<string> {
  const claims: ProofClaims = {
    ten: context.tenant,
    dev: signer.deviceId,
    ...(signer.workloadId ? { wkl: signer.workloadId } : {}),
    ...(context.session ? { sid: context.session } : {}),
    ...(context.grant ? { gnt: context.grant } : {}),
    htm: request.method.toUpperCase(),
    htu: normaliseUrl(request.url),
    bh: await bodyHash(request.body),
    iat: Math.floor((context.now ?? Date.now()) / 1000),
    jti: randomId("jti", 12),
  }
  const header = { alg: "ES256", typ: PROOF_TYPE, kid: signer.workloadId ?? signer.deviceId }
  return signCompactJws(header, claims, (data) => signer.sign(data), "device")
}

// ---------------------------------------------------------------- shared with platform proofs (platform.ts)

// Signs header and claims as a compact JWS, serialised in the order given.
// `who` names the signer in the error a wrong-sized signature raises.
export async function signCompactJws(header: object, claims: object, sign: (data: Bytes) => Promise<Bytes>, who: string): Promise<string> {
  const signingInput = `${base64UrlEncode(utf8(JSON.stringify(header)))}.${base64UrlEncode(utf8(JSON.stringify(claims)))}`
  const signature = await sign(utf8(signingInput))
  if (signature.length !== 64) throw new Error(`${who} signer must return a 64-byte r||s signature`)
  return `${signingInput}.${base64UrlEncode(signature)}`
}

// A compact JWS split into its parts, with only the header decoded; the
// payload and signature segments are left for the caller to decode after
// it has checked the header.
export type CompactJws = { header: Record<string, unknown>; payload: string; signature: string; signingInput: Bytes }

export function splitCompactJws(token: string): CompactJws {
  if (token.length > 8192) throw new Error("proof too large")
  const parts = token.split(".")
  if (parts.length !== 3) throw new Error("malformed proof")
  const [h, p, s] = parts as [string, string, string]
  const header: unknown = JSON.parse(fromUtf8(base64UrlDecode(h)))
  if (typeof header !== "object" || header === null) throw new Error("malformed proof header")
  return { header: header as Record<string, unknown>, payload: p, signature: s, signingInput: utf8(`${h}.${p}`) }
}

export function decodeJwsSegment(segment: string): unknown {
  return JSON.parse(fromUtf8(base64UrlDecode(segment)))
}

// The claims that bind a proof to one request: htm, htu, bh, iat and jti.
export type RequestClaims = { htm: string; htu: string; bh: string; iat: number; jti: string }

export const SAFE_PROOF_ID = /^[A-Za-z0-9_.:-]{1,128}$/

export function hasRequestClaims(c: Record<string, unknown>): boolean {
  return (
    typeof c.htm === "string" && /^[A-Z]{3,7}$/.test(c.htm) &&
    typeof c.htu === "string" && c.htu.length <= 4096 &&
    typeof c.bh === "string" && /^[A-Za-z0-9_-]{43}$/.test(c.bh) &&
    typeof c.iat === "number" && Number.isInteger(c.iat) &&
    typeof c.jti === "string" && SAFE_PROOF_ID.test(c.jti)
  )
}

export type RequestProofFailure = "signature" | "method" | "url" | "body" | "expired" | "future"

// The signature, then the request the proof names against the one received,
// then the skew window. Null when all hold. Replay is the caller's.
export async function checkRequestProof(
  proof: { signingInput: Bytes; signature: Bytes; claims: RequestClaims },
  publicKey: CryptoKey,
  received: { method: string; url: string; bodyHash: string; now?: number },
): Promise<RequestProofFailure | null> {
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    proof.signature,
    proof.signingInput,
  )
  if (!valid) return "signature"
  const { claims } = proof
  if (claims.htm !== received.method.toUpperCase()) return "method"
  if (claims.htu !== normaliseUrl(received.url)) return "url"
  if (claims.bh !== received.bodyHash) return "body"
  const now = Math.floor((received.now ?? Date.now()) / 1000)
  if (claims.iat < now - PROOF_MAX_SKEW_SECONDS) return "expired"
  if (claims.iat > now + PROOF_MAX_SKEW_SECONDS) return "future"
  return null
}

export type ParsedProof = {
  claims: ProofClaims
  signingInput: Bytes
  signature: Bytes
}

function isClaims(value: unknown): value is ProofClaims {
  if (typeof value !== "object" || value === null) return false
  const c = value as Record<string, unknown>
  const optional = (v: unknown) => v === undefined || (typeof v === "string" && SAFE_PROOF_ID.test(v))
  return (
    typeof c.ten === "string" && SAFE_PROOF_ID.test(c.ten) &&
    typeof c.dev === "string" && SAFE_PROOF_ID.test(c.dev) &&
    optional(c.wkl) && optional(c.sid) && optional(c.gnt) &&
    hasRequestClaims(c)
  )
}

// Parses without verifying, so the server can route to the tenant and find
// the device's key. Nothing in the result is trusted until verifyProof.
export function parseProof(token: string): ParsedProof {
  const jws = splitCompactJws(token)
  const hdr = jws.header
  if (hdr.alg !== "ES256" || hdr.typ !== PROOF_TYPE) throw new Error("unsupported proof type")
  const claims = decodeJwsSegment(jws.payload)
  if (!isClaims(claims)) throw new Error("malformed proof claims")
  if (hdr.kid !== (claims.wkl ?? claims.dev)) throw new Error("proof key id does not match device")
  return { claims, signingInput: jws.signingInput, signature: base64UrlDecode(jws.signature) }
}

export type ProofCheck =
  | { ok: true; claims: ProofClaims }
  | { ok: false; reason: RequestProofFailure }

// Verifies a parsed proof against the request as the server received it.
// Replay (jti) is checked by the caller, which owns the nonce store.
export async function verifyProof(
  proof: ParsedProof,
  publicKey: CryptoKey,
  received: { method: string; url: string; bodyHash: string; now?: number },
): Promise<ProofCheck> {
  const failure = await checkRequestProof(proof, publicKey, received)
  if (failure !== null) return { ok: false, reason: failure }
  return { ok: true, claims: proof.claims }
}

export type DeviceJwk = { kty: "EC"; crv: "P-256"; x: string; y: string }

export function isDeviceJwk(value: unknown): value is DeviceJwk {
  if (typeof value !== "object" || value === null) return false
  const k = value as Record<string, unknown>
  return k.kty === "EC" && k.crv === "P-256" &&
    typeof k.x === "string" && /^[A-Za-z0-9_-]{43}$/.test(k.x) &&
    typeof k.y === "string" && /^[A-Za-z0-9_-]{43}$/.test(k.y)
}

export async function importDeviceKey(jwk: DeviceJwk): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, ext: true },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  )
}

// RFC 7638 thumbprint, used as a stable fingerprint shown to the human when
// they approve an enrolment, so they can match it to what the CLI printed.
export async function jwkThumbprint(jwk: DeviceJwk): Promise<string> {
  return sha256B64(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`)
}

// A software signer over a WebCrypto key: Linux hosts, tests, CI.
export function webCryptoSigner(deviceId: string, privateKey: CryptoKey, workloadId?: string): ProofSigner {
  return {
    deviceId,
    ...(workloadId ? { workloadId } : {}),
    async sign(data) {
      return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, data))
    },
  }
}
