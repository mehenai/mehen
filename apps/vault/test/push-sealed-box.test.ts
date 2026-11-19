// GitHub's sealed box against known answers, with no network: the NaCl box
// vector proves the X25519, HSalsa20 and XSalsa20-Poly1305 composition; a
// box sealed once by libsodium, which the test-only open below must open,
// proves the BLAKE2b nonce derivation interoperates; a box this module
// sealed with a fixed ephemeral key, which libsodium opened, proves the
// other direction.

import { describe, expect, it } from "vitest"
import { x25519 } from "@noble/curves/ed25519.js"
import { base64Decode, base64Encode, cryptoBox, sealForGitHub, sealedBox } from "../src/push/sealed-box.ts"
import { sealOpen } from "./sealed-box-open.ts"

const hex = (text: string) => Uint8Array.from(text.match(/../g)!.map((b) => parseInt(b, 16)))
const toHex = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")

// Bernstein, "Cryptography in NaCl", section 10, as libsodium's
// test/default/box.c and box.exp give it (the message without its 32 zero
// bytes, the box as tag then ciphertext).
const NACL = {
  aliceSecretKey: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  bobPublicKey: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  nonce: "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37",
  message: "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705",
  box: "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5",
}

// Made once with libsodium 1.0.22 (Homebrew): crypto_box_seed_keypair with
// the seed 01 02 ... 20, then crypto_box_seal of the message to its public key.
const LIBSODIUM = {
  version: "1.0.22",
  secretKey: "77788f1a0cea001a2631dae5d05dbd062008d5b30f50b9e29beb2a7822289004",
  publicKey: "4a3807d064d077181cc070989e76891d20dca5559548dc2c77c1a50273882b38",
  message: "sk-proj-mehen-sealed-box-fixture",
  sealed: "b912d76969f2d0753e66035c96c13232b0bb6d289f1174d4c826b9a17235975fae85455bce8f5ad5a075c8874ba9f8b7a253c5d75fd790f89cb75a5a11c875291b04701f71b85ff5bbbbbc595dfd4d8d",
  // sealedBox(message, publicKey, the ephemeral key 40 41 ... 5f), which
  // libsodium 1.0.22's crypto_box_seal_open opened to the message.
  ephemeralSecretKey: "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
  sealedHere: "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a1c64e3b22ecc9d6c79b8660613572450f6c446dec626b4ba5bddf3a912893c847fd7d20eb9bf4320262fda088dc00fb3",
}

describe("the sealed box GitHub takes", () => {
  it("composes crypto_box exactly as NaCl's box vector says", () => {
    expect(toHex(cryptoBox(hex(NACL.message), hex(NACL.nonce), hex(NACL.bobPublicKey), hex(NACL.aliceSecretKey)))).toBe(NACL.box)
  })

  it(`opens, with the test-only open, a box libsodium ${LIBSODIUM.version} sealed`, () => {
    expect(toHex(x25519.getPublicKey(hex(LIBSODIUM.secretKey)))).toBe(LIBSODIUM.publicKey)
    expect(new TextDecoder().decode(sealOpen(hex(LIBSODIUM.sealed), hex(LIBSODIUM.publicKey), hex(LIBSODIUM.secretKey)))).toBe(LIBSODIUM.message)
    const tampered = hex(LIBSODIUM.sealed)
    tampered[tampered.length - 1]! ^= 1
    expect(() => sealOpen(tampered, hex(LIBSODIUM.publicKey), hex(LIBSODIUM.secretKey))).toThrow()
  })

  it("seals with an injected ephemeral key exactly the box libsodium opened, every time", () => {
    const seal = () => toHex(sealedBox(new TextEncoder().encode(LIBSODIUM.message), hex(LIBSODIUM.publicKey), hex(LIBSODIUM.ephemeralSecretKey)))
    expect(seal()).toBe(LIBSODIUM.sealedHere)
    expect(seal()).toBe(seal())
  })

  it("round trips, with a fresh ephemeral key for every seal", () => {
    const secretKey = x25519.utils.randomSecretKey()
    const publicKey = x25519.getPublicKey(secretKey)
    const message = new TextEncoder().encode("ghp_" + "x".repeat(36) + " é ✓")
    const first = sealedBox(message, publicKey)
    const second = sealedBox(message, publicKey)
    expect(first.length).toBe(32 + 16 + message.length)
    expect(toHex(first)).not.toBe(toHex(second))
    expect(sealOpen(first, publicKey, secretKey)).toEqual(message)
    expect(sealOpen(second, publicKey, secretKey)).toEqual(message)
    expect(toHex(first)).not.toContain(toHex(message))
  })

  it("takes GitHub's base64 public key and gives base64 under a fresh ephemeral key, and refuses a key that is not 32 bytes of base64 or is not a usable X25519 key", () => {
    const secretKey = x25519.utils.randomSecretKey()
    const publicKey = x25519.getPublicKey(secretKey)
    const sealed = sealForGitHub("sk-proj-value", base64Encode(publicKey))
    expect(sealed).not.toBeNull()
    expect(new TextDecoder().decode(sealOpen(base64Decode(sealed!)!, publicKey, secretKey))).toBe("sk-proj-value")
    expect(sealForGitHub("v", base64Encode(publicKey))).not.toBe(sealForGitHub("v", base64Encode(publicKey)))
    // @ts-expect-error only sealedBox takes an ephemeral key, for its tests.
    sealForGitHub("v", base64Encode(publicKey), hex(LIBSODIUM.ephemeralSecretKey))
    for (const bad of [base64Encode(publicKey.subarray(0, 31)), base64Encode(new Uint8Array(33)), base64Encode(new Uint8Array(32)), "not base64!", base64Encode(publicKey).replace(/=+$/, "") + "@", ""]) expect(sealForGitHub("v", bad), bad).toBeNull()
  })
})
