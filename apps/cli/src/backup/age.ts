// The one place mehen calls age-encryption (typage): X25519 only, whole
// files in memory, binary (not armoured) output, as `age -d` reads it.

import { Decrypter, Encrypter, generateX25519Identity, identityToRecipient } from "age-encryption"

export async function ageEncrypt(plaintext: Uint8Array, recipients: readonly string[]): Promise<Uint8Array> {
  const encrypter = new Encrypter()
  for (const recipient of recipients) encrypter.addRecipient(recipient)
  return await encrypter.encrypt(plaintext)
}

// Throws when no identity opens the file, or the file is damaged.
export async function ageDecrypt(ciphertext: Uint8Array, identities: readonly (string | CryptoKey)[]): Promise<Uint8Array> {
  const decrypter = new Decrypter()
  for (const identity of identities) decrypter.addIdentity(identity)
  return await decrypter.decrypt(ciphertext)
}

// A key that lives only in this process: WebCrypto X25519, not extractable,
// so nothing can write its private half anywhere.
export async function ephemeralAgeIdentity(): Promise<{ key: CryptoKey; recipient: string }> {
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])) as CryptoKeyPair
  return { key: pair.privateKey, recipient: await identityToRecipient(pair.privateKey) }
}

// A backup identity (`AGE-SECRET-KEY-1...`) and its recipient.
export async function newAgeIdentity(): Promise<{ identity: string; recipient: string }> {
  const identity = await generateX25519Identity()
  return { identity, recipient: await identityToRecipient(identity) }
}
