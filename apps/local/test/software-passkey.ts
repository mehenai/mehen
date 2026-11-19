// A software passkey for tests against a vault at any origin: the same
// ceremonies Touch ID answers, verified by the vault's real WebAuthn code.

import { base64UrlEncode } from "@mehen/protocol"
import { isoCBOR } from "@simplewebauthn/server/helpers"

type Bytes = Uint8Array<ArrayBuffer>

const encode = (text: string): Bytes => new TextEncoder().encode(text) as Bytes

function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

function uint(value: number, bytes: 2 | 4): Bytes {
  const out = new Uint8Array(bytes)
  const view = new DataView(out.buffer)
  if (bytes === 2) view.setUint16(0, value)
  else view.setUint32(0, value)
  return out
}

function derInteger(value: Uint8Array): Bytes {
  let start = 0
  while (start < value.length - 1 && value[start] === 0) start++
  const trimmed = value.slice(start)
  const padded = (trimmed[0] ?? 0) & 0x80 ? concat(new Uint8Array([0]), trimmed) : trimmed
  return concat(new Uint8Array([0x02, padded.length]), padded)
}

function derSignature(raw: Uint8Array): Bytes {
  const body = concat(derInteger(raw.slice(0, 32)), derInteger(raw.slice(32)))
  return concat(new Uint8Array([0x30, body.length]), body)
}

export type SoftwarePasskey = {
  registration(challenge: string): Promise<Record<string, unknown>>
  assertion(challenge: string): Promise<Record<string, unknown>>
}

export async function softwarePasskey(origin: string): Promise<SoftwarePasskey> {
  const rpId = new URL(origin).hostname
  const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", keys.publicKey)) as ArrayBuffer)
  const cose = new Uint8Array(isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, raw.slice(1, 33)], [-3, raw.slice(33, 65)]])))
  const credentialId = crypto.getRandomValues(new Uint8Array(16))
  const id = base64UrlEncode(credentialId)
  let counter = 0
  const authData = async (flags: number, rest: Uint8Array) => concat(new Uint8Array(await crypto.subtle.digest("SHA-256", encode(rpId))), new Uint8Array([0x01 | 0x04 | flags]), rest)
  return {
    async registration(challenge) {
      const data = await authData(0x40, concat(uint(0, 4), new Uint8Array(16), uint(credentialId.length, 2), credentialId, cose))
      const attestation = isoCBOR.encode(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", data]]) as Map<string, string>)
      const clientDataJSON = base64UrlEncode(encode(JSON.stringify({ type: "webauthn.create", challenge, origin, crossOrigin: false })))
      return { id, rawId: id, type: "public-key", response: { clientDataJSON, attestationObject: base64UrlEncode(new Uint8Array(attestation)), transports: ["internal"] }, clientExtensionResults: {} }
    },
    async assertion(challenge) {
      const data = await authData(0, uint(++counter, 4))
      const client = encode(JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false }))
      const signed = concat(data, new Uint8Array(await crypto.subtle.digest("SHA-256", client)))
      const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, signed))
      return { id, rawId: id, type: "public-key", response: { clientDataJSON: base64UrlEncode(client), authenticatorData: base64UrlEncode(data), signature: base64UrlEncode(derSignature(signature)) }, clientExtensionResults: {} }
    },
  }
}
