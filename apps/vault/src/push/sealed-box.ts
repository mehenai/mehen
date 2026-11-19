// libsodium's crypto_box_seal, which GitHub requires for every secret it
// stores: the value is sealed to the repository's (or environment's) public
// key, so only GitHub can open it. Built from the audited noble primitives:
//
//   crypto_box(m, n, pk, sk) = XSalsa20-Poly1305(HSalsa20(X25519(sk, pk), 0^16), n, m)
//   crypto_box_seal(m, pk)   = epk || crypto_box(m, BLAKE2b-192(epk || pk), pk, esk)
//
// with a fresh ephemeral key pair (esk, epk) for every seal. Output is
// libsodium's: the 16-byte tag, then the ciphertext.

import { x25519 } from "@noble/curves/ed25519.js"
import { hsalsa, xsalsa20poly1305 } from "@noble/ciphers/salsa.js"
import { blake2b } from "@noble/hashes/blake2.js"

export const SEAL_KEY_BYTES = 32

// "expand 32-byte k" as little-endian words.
const SIGMA = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574])

function words(bytes: Uint8Array): Uint32Array {
  const copy = new Uint8Array(bytes)
  return new Uint32Array(copy.buffer, 0, copy.length / 4)
}

// crypto_box_beforenm: the XSalsa20-Poly1305 key two parties share.
function boxKey(publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array {
  const shared = x25519.getSharedSecret(secretKey, publicKey)
  const out = new Uint32Array(8)
  hsalsa(SIGMA, words(shared), new Uint32Array(4), out)
  return new Uint8Array(out.buffer)
}

// NaCl's crypto_box in libsodium's easy form (tag, then ciphertext).
export function cryptoBox(message: Uint8Array, nonce: Uint8Array, publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return xsalsa20poly1305(boxKey(publicKey, secretKey), nonce).encrypt(message)
}

export function sealNonce(ephemeralPublicKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const input = new Uint8Array(2 * SEAL_KEY_BYTES)
  input.set(ephemeralPublicKey, 0)
  input.set(publicKey, SEAL_KEY_BYTES)
  return blake2b(input, { dkLen: 24 })
}

// The ephemeral secret key is fresh and random unless a test passes one.
export function sealedBox(message: Uint8Array, publicKey: Uint8Array, ephemeralSecretKey: Uint8Array = x25519.utils.randomSecretKey()): Uint8Array {
  if (publicKey.length !== SEAL_KEY_BYTES) throw new Error("a sealed box needs a 32-byte public key")
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralSecretKey)
  const box = cryptoBox(message, sealNonce(ephemeralPublicKey, publicKey), publicKey, ephemeralSecretKey)
  const out = new Uint8Array(SEAL_KEY_BYTES + box.length)
  out.set(ephemeralPublicKey, 0)
  out.set(box, SEAL_KEY_BYTES)
  return out
}

export function base64Encode(bytes: Uint8Array): string {
  let binary = ""
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(binary)
}

// Standard base64 with its padding, as GitHub gives a public key; null for
// anything else.
export function base64Decode(text: string): Uint8Array | null {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) return null
  const binary = atob(text)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

// A value sealed as GitHub's secrets endpoints take it: the base64 public
// key in, the base64 sealed box out. Null when the key is not a base64
// 32-byte key, or is one X25519 refuses (a low-order point such as all
// zeros).
export function sealForGitHub(value: string, publicKeyBase64: string): string | null {
  const publicKey = base64Decode(publicKeyBase64)
  if (publicKey === null || publicKey.length !== SEAL_KEY_BYTES) return null
  try {
    return base64Encode(sealedBox(new TextEncoder().encode(value), publicKey))
  } catch {
    return null
  }
}
