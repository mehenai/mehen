// Sealing a secret to the vault in the browser (or the CLI) before it is
// sent: ECDH P-256 with an ephemeral key, HKDF-SHA256, AES-256-GCM. The
// HPKE base-mode shape in plain WebCrypto, so it runs in every browser,
// Bun and workerd without a library.
//
// TLS already protects the hop. Sealing additionally keeps plaintext out of
// request logs, tail sessions, error reports and anything else between the
// edge and the one Durable Object call that opens it. The context string is
// bound into both the key derivation and the AAD, so a sealed box made for
// one intake request cannot be replayed into another.

import { type Bytes, base64UrlDecode, base64UrlEncode, fromUtf8, randomBytes, utf8 } from "./bytes.ts"

export type SealedBox = {
  v: 1
  epk: { kty: "EC"; crv: "P-256"; x: string; y: string }
  iv: string
  ct: string
}

const ECDH = { name: "ECDH", namedCurve: "P-256" } as const

// workers-types names the peer key `$public`; every runtime reads `public`.
function ecdhPeer(peer: CryptoKey): Parameters<SubtleCrypto["deriveBits"]>[0] {
  return { name: "ECDH", public: peer } as unknown as Parameters<SubtleCrypto["deriveBits"]>[0]
}

async function exportRaw(key: CryptoKey): Promise<Bytes> {
  return new Uint8Array((await crypto.subtle.exportKey("raw", key)) as ArrayBuffer)
}

async function deriveBoxKey(shared: ArrayBuffer, epkRaw: Bytes, context: string, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"])
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: epkRaw, info: utf8(`mehen/seal/v1/${context}`) },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  )
}

export async function generateSealKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH, true, ["deriveBits"]) as Promise<CryptoKeyPair>
}

export async function importSealPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  const { x, y } = jwk
  if (typeof x !== "string" || typeof y !== "string") throw new TypeError("The seal key is not a P-256 public JWK.")
  return crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x, y }, ECDH, false, [])
}

export async function importSealPrivateKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk, ECDH, false, ["deriveBits"])
}

export async function seal(recipient: CryptoKey, plaintext: Bytes | string, context: string): Promise<SealedBox> {
  const ephemeral = (await crypto.subtle.generateKey(ECDH, true, ["deriveBits"])) as CryptoKeyPair
  const shared = await crypto.subtle.deriveBits(ecdhPeer(recipient), ephemeral.privateKey, 256)
  const epkRaw = await exportRaw(ephemeral.publicKey)
  const key = await deriveBoxKey(shared, epkRaw, context, "encrypt")
  const iv = randomBytes(12)
  const data = typeof plaintext === "string" ? utf8(plaintext) : plaintext
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(context) }, key, data),
  )
  const epk = (await crypto.subtle.exportKey("jwk", ephemeral.publicKey)) as JsonWebKey
  return {
    v: 1,
    epk: { kty: "EC", crv: "P-256", x: String(epk.x), y: String(epk.y) },
    iv: base64UrlEncode(iv),
    ct: base64UrlEncode(ct),
  }
}

export function isSealedBox(value: unknown): value is SealedBox {
  if (typeof value !== "object" || value === null) return false
  const b = value as Record<string, unknown>
  const epk = b.epk as Record<string, unknown> | undefined
  return b.v === 1 && typeof b.iv === "string" && typeof b.ct === "string" && b.ct.length < 2_000_000 &&
    typeof epk === "object" && epk !== null && epk.kty === "EC" && epk.crv === "P-256" &&
    typeof epk.x === "string" && typeof epk.y === "string"
}

export async function open(recipientPrivate: CryptoKey, box: SealedBox, context: string): Promise<Bytes> {
  const epk = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: box.epk.x, y: box.epk.y }, ECDH, true, [])
  const epkRaw = await exportRaw(epk)
  const shared = await crypto.subtle.deriveBits(ecdhPeer(epk), recipientPrivate, 256)
  const key = await deriveBoxKey(shared, epkRaw, context, "decrypt")
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: base64UrlDecode(box.iv), additionalData: utf8(context) },
        key,
        base64UrlDecode(box.ct),
      ),
    )
  } catch {
    throw new Error("sealed box failed authentication")
  }
}

export async function openText(recipientPrivate: CryptoKey, box: SealedBox, context: string): Promise<string> {
  return fromUtf8(await open(recipientPrivate, box, context))
}

