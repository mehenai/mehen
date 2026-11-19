// P-256 ECDSA keys over WebCrypto: a device's or a workload's. A host that
// must keep the key across restarts exports it as PKCS #8 and wraps it
// itself; this library never stores a key.

import type { Bytes } from "@mehen/protocol/bytes"
import { type FingerprintGroups, type FingerprintWord, fingerprintGroups, fingerprintOf, fingerprintWords } from "@mehen/protocol/fingerprint"
import { PolicyDeviceIdSchema } from "@mehen/protocol/policy-mode"
import { type DeviceJwk, type ProofSigner, isDeviceJwk, jwkThumbprint, webCryptoSigner } from "@mehen/protocol/proof"
import { WorkloadIdSchema } from "@mehen/protocol/workload"

const EC_P256 = { name: "ECDSA", namedCurve: "P-256" } as const

export type KeyPair = { privateKey: CryptoKey; publicKey: CryptoKey; jwk: DeviceJwk }
export type PrivateKey = { privateKey: CryptoKey; jwk: DeviceJwk }

function publicPart(jwk: JsonWebKey): DeviceJwk {
  const candidate = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }
  if (!isDeviceJwk(candidate)) throw new TypeError("The key is not a P-256 key.")
  return candidate
}

// The casts below name what each WebCrypto call answers for these arguments:
// the Workers types declare the union over every algorithm and format, as
// @mehen/protocol's seal.ts also narrows it.

// Extractable, so a host can export and wrap it. The private key signs; the
// JWK is what enrolment or a workload registers.
export async function generateKey(): Promise<KeyPair> {
  const pair = (await crypto.subtle.generateKey(EC_P256, true, ["sign", "verify"])) as CryptoKeyPair
  const jwk = publicPart((await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey)
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, jwk }
}

export async function exportPrivateKey(privateKey: CryptoKey): Promise<Bytes> {
  if (!privateKey.extractable) throw new TypeError("This private key was imported or made non-extractable, so it cannot be exported.")
  return new Uint8Array((await crypto.subtle.exportKey("pkcs8", privateKey)) as ArrayBuffer)
}

// The public JWK is read from the key itself, so a host stores the PKCS #8
// bytes alone. With extractable false the returned key can sign but never
// leave WebCrypto again.
export async function importPrivateKey(pkcs8: Bytes, options: { extractable: boolean }): Promise<PrivateKey> {
  const readable = await crypto.subtle.importKey("pkcs8", pkcs8, EC_P256, true, ["sign"])
  const jwk = publicPart((await crypto.subtle.exportKey("jwk", readable)) as JsonWebKey)
  if (options.extractable) return { privateKey: readable, jwk }
  const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, EC_P256, false, ["sign"])
  return { privateKey, jwk }
}

// What the mehen CLI prints when it enrols a key: the person types the
// group the enrol page hides, and the words are a quick visual match.
export type KeyFingerprint = {
  thumbprint: string
  fingerprint: string
  groups: FingerprintGroups
  words: FingerprintWord[]
}

export async function fingerprint(jwk: DeviceJwk): Promise<KeyFingerprint> {
  if (!isDeviceJwk(jwk)) throw new TypeError("The key is not a P-256 public JWK.")
  const thumbprint = await jwkThumbprint(jwk)
  const text = fingerprintOf(thumbprint)
  return { thumbprint, fingerprint: text, groups: fingerprintGroups(text), words: fingerprintWords(thumbprint) }
}

export function deviceSigner(deviceId: string, privateKey: CryptoKey): ProofSigner {
  if (!PolicyDeviceIdSchema.safeParse(deviceId).success) throw new TypeError(`${JSON.stringify(deviceId)} is not a device id (dev_...).`)
  return webCryptoSigner(deviceId, privateKey)
}

// A workload signs its own proofs: kid and wkl are the workload, dev its
// parent device.
export function workloadSigner(deviceId: string, workloadId: string, privateKey: CryptoKey): ProofSigner {
  if (!PolicyDeviceIdSchema.safeParse(deviceId).success) throw new TypeError(`${JSON.stringify(deviceId)} is not a device id (dev_...).`)
  if (!WorkloadIdSchema.safeParse(workloadId).success) throw new TypeError(`${JSON.stringify(workloadId)} is not a workload id (wl_...).`)
  return webCryptoSigner(deviceId, privateKey, workloadId)
}
