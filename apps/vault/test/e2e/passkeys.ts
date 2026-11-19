// Software WebAuthn responses from test/l1-auth.test.ts, verified by the real
// @simplewebauthn/server ceremonies. No verifier or step-up seam is replaced.
import { type Bytes, base64UrlEncode } from "@mehen/protocol"
import { isoCBOR } from "@simplewebauthn/server/helpers"
import { ORIGIN } from "../helpers.ts"
function clientData(type: string, challenge: string): string {
  return base64UrlEncode(new Uint8Array(new TextEncoder().encode(JSON.stringify({ type, challenge, origin: ORIGIN, crossOrigin: false }))))
}
export type SoftwarePasskey = { credentialId: Bytes; keys: CryptoKeyPair; cose: Bytes }

function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

function uint(value: number, bytes: 2 | 4): Uint8Array {
  const out = new Uint8Array(bytes)
  const view = new DataView(out.buffer)
  if (bytes === 2) view.setUint16(0, value)
  else view.setUint32(0, value)
  return out
}

function derInteger(value: Uint8Array): Uint8Array {
  let start = 0
  while (start < value.length - 1 && value[start] === 0) start++
  const trimmed = value.slice(start)
  const padded = (trimmed[0] ?? 0) & 0x80 ? concat(new Uint8Array([0]), trimmed) : trimmed
  return concat(new Uint8Array([0x02, padded.length]), padded)
}

function derSignature(raw: Uint8Array): Uint8Array {
  const body = concat(derInteger(raw.slice(0, 32)), derInteger(raw.slice(32)))
  return concat(new Uint8Array([0x30, body.length]), body)
}

async function authData(userVerified: boolean, extraFlags: number, rest: Uint8Array): Promise<Bytes> {
  const rpHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("vault.test")))
  return concat(rpHash, new Uint8Array([0x01 | (userVerified ? 0x04 : 0) | extraFlags]), rest)
}

export async function softwarePasskey(): Promise<SoftwarePasskey> {
  const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", keys.publicKey)) as ArrayBuffer)
  const cose = isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, raw.slice(1, 33)], [-3, raw.slice(33, 65)]]))
  return { credentialId: crypto.getRandomValues(new Uint8Array(16)), keys, cose: new Uint8Array(cose) }
}

// The backup flags the authenticator reports: none (this device only), BE
// alone (could sync, is not backed up now), or BE and BS (synced).
export type PasskeyBackup = "device" | "eligible" | "synced"
const BACKUP_FLAGS: Record<PasskeyBackup, number> = { device: 0, eligible: 0x08, synced: 0x18 }

export async function registration(passkey: SoftwarePasskey, challenge: string, userVerified = true, backup: PasskeyBackup = "device"): Promise<Record<string, unknown>> {
  const data = await authData(userVerified, 0x40 | BACKUP_FLAGS[backup], concat(uint(0, 4), new Uint8Array(16), uint(passkey.credentialId.length, 2), passkey.credentialId, passkey.cose))
  const attestation = isoCBOR.encode(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", data]]) as Map<string, string>)
  const id = base64UrlEncode(passkey.credentialId)
  return {
    id,
    rawId: id,
    type: "public-key",
    response: { clientDataJSON: clientData("webauthn.create", challenge), attestationObject: base64UrlEncode(new Uint8Array(attestation)), transports: ["internal"] },
    clientExtensionResults: {},
  }
}

export async function assertion(passkey: SoftwarePasskey, challenge: string, counter: number, userVerified = true, backup: PasskeyBackup = "device"): Promise<Record<string, unknown>> {
  const data = await authData(userVerified, BACKUP_FLAGS[backup], uint(counter, 4))
  const client = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge, origin: ORIGIN, crossOrigin: false }))
  const signed = concat(data, new Uint8Array(await crypto.subtle.digest("SHA-256", client)))
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, passkey.keys.privateKey, signed))
  const id = base64UrlEncode(passkey.credentialId)
  return {
    id,
    rawId: id,
    type: "public-key",
    response: { clientDataJSON: base64UrlEncode(new Uint8Array(client)), authenticatorData: base64UrlEncode(data), signature: base64UrlEncode(new Uint8Array(derSignature(raw))) },
    clientExtensionResults: {},
  }
}
