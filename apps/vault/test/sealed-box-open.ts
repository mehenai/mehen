// crypto_box_seal_open, for tests only: the vault never opens a sealed box.

import { x25519 } from "@noble/curves/ed25519.js"
import { hsalsa, xsalsa20poly1305 } from "@noble/ciphers/salsa.js"
import { blake2b } from "@noble/hashes/blake2.js"

export function sealOpen(sealed: Uint8Array, publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array {
  const ephemeralPublicKey = sealed.subarray(0, 32)
  const nonce = blake2b(new Uint8Array([...ephemeralPublicKey, ...publicKey]), { dkLen: 24 })
  const shared = new Uint8Array(x25519.getSharedSecret(secretKey, ephemeralPublicKey))
  const key = new Uint32Array(8)
  hsalsa(new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]), new Uint32Array(shared.buffer), new Uint32Array(4), key)
  return xsalsa20poly1305(new Uint8Array(key.buffer), nonce).decrypt(sealed.subarray(32))
}
