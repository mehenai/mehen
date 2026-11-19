import { describe, expect, test } from "bun:test"
import { base64UrlDecode, base64UrlEncode, randomBytes, utf8 } from "./bytes.ts"
import {
  type SealedBox,
  generateSealKeyPair,
  importSealPrivateKey,
  importSealPublicKey,
  isSealedBox,
  open,
  openText,
  seal,
} from "./seal.ts"

const CONTEXT = "intake/int_abc123"
const SECRET = "sk-live-sealed-secret-value"

const recipient = await generateSealKeyPair()

function flipChar(text: string, index: number): string {
  const bytes = base64UrlDecode(text)
  bytes[index] = (bytes[index] ?? 0) ^ 0x01
  return base64UrlEncode(bytes)
}

describe("seal and open", () => {
  test("round trip of a string", async () => {
    const box = await seal(recipient.publicKey, SECRET, CONTEXT)
    expect(await openText(recipient.privateKey, box, CONTEXT)).toBe(SECRET)
  })

  test("round trip of bytes, empty and multibyte text", async () => {
    const bytes = randomBytes(1000)
    expect(await open(recipient.privateKey, await seal(recipient.publicKey, bytes, CONTEXT), CONTEXT)).toEqual(bytes)
    expect((await open(recipient.privateKey, await seal(recipient.publicKey, "", CONTEXT), CONTEXT)).length).toBe(0)
    const text = "naïve café ✓ 🔐"
    expect(await openText(recipient.privateKey, await seal(recipient.publicKey, text, CONTEXT), CONTEXT)).toBe(text)
  })

  test("round trip through exported and imported JWKs", async () => {
    const publicJwk = await crypto.subtle.exportKey("jwk", recipient.publicKey)
    const privateJwk = await crypto.subtle.exportKey("jwk", recipient.privateKey)
    const box = await seal(await importSealPublicKey(publicJwk), SECRET, CONTEXT)
    expect(await openText(await importSealPrivateKey(privateJwk), box, CONTEXT)).toBe(SECRET)
  })

  test("importSealPublicKey refuses a JWK with no x or y", async () => {
    const { x, y } = await crypto.subtle.exportKey("jwk", recipient.publicKey)
    await expect(importSealPublicKey({ kty: "EC", crv: "P-256", y })).rejects.toThrow(new TypeError("The seal key is not a P-256 public JWK."))
    await expect(importSealPublicKey({ kty: "EC", crv: "P-256", x })).rejects.toThrow(TypeError)
  })

  test("produces a well-formed box with a fresh ephemeral key and IV each time", async () => {
    const a = await seal(recipient.publicKey, SECRET, CONTEXT)
    const b = await seal(recipient.publicKey, SECRET, CONTEXT)
    expect(isSealedBox(a)).toBe(true)
    expect(a.v).toBe(1)
    expect(a.epk.kty).toBe("EC")
    expect(a.epk.crv).toBe("P-256")
    expect(base64UrlDecode(a.iv).length).toBe(12)
    expect(base64UrlDecode(a.ct).length).toBe(utf8(SECRET).length + 16)
    expect(a.epk.x).not.toBe(b.epk.x)
    expect(a.iv).not.toBe(b.iv)
    expect(a.ct).not.toBe(b.ct)
    expect(JSON.stringify(a)).not.toContain(SECRET)
  })

  test("survives a JSON round trip", async () => {
    const box = await seal(recipient.publicKey, SECRET, CONTEXT)
    const parsed: unknown = JSON.parse(JSON.stringify(box))
    expect(isSealedBox(parsed)).toBe(true)
    if (isSealedBox(parsed)) expect(await openText(recipient.privateKey, parsed, CONTEXT)).toBe(SECRET)
  })

  test("fails under another context", async () => {
    const box = await seal(recipient.publicKey, SECRET, CONTEXT)
    for (const context of ["intake/int_abc124", "", `${CONTEXT} `, "INTAKE/int_abc123"]) {
      await expect(open(recipient.privateKey, box, context)).rejects.toThrow("sealed box failed authentication")
    }
  })

  test("fails for another recipient", async () => {
    const other = await generateSealKeyPair()
    const box = await seal(recipient.publicKey, SECRET, CONTEXT)
    await expect(open(other.privateKey, box, CONTEXT)).rejects.toThrow("sealed box failed authentication")
  })

  test("fails when any byte of the ciphertext or tag is flipped", async () => {
    const box = await seal(recipient.publicKey, SECRET, CONTEXT)
    const length = base64UrlDecode(box.ct).length
    for (let i = 0; i < length; i++) {
      await expect(open(recipient.privateKey, { ...box, ct: flipChar(box.ct, i) }, CONTEXT)).rejects.toThrow(
        "sealed box failed authentication",
      )
    }
  })

  test("fails with a truncated ciphertext or a tampered IV", async () => {
    const box = await seal(recipient.publicKey, SECRET, CONTEXT)
    const ct = base64UrlDecode(box.ct)
    const truncated = base64UrlEncode(ct.slice(0, ct.length - 1))
    await expect(open(recipient.privateKey, { ...box, ct: truncated }, CONTEXT)).rejects.toThrow()
    await expect(open(recipient.privateKey, { ...box, iv: flipChar(box.iv, 0) }, CONTEXT)).rejects.toThrow(
      "sealed box failed authentication",
    )
  })

  test("fails when the ephemeral key is swapped for another box's", async () => {
    const a = await seal(recipient.publicKey, SECRET, CONTEXT)
    const b = await seal(recipient.publicKey, SECRET, CONTEXT)
    await expect(open(recipient.privateKey, { ...a, epk: b.epk }, CONTEXT)).rejects.toThrow(
      "sealed box failed authentication",
    )
  })

  test("fails when the ephemeral key is not a point on the curve", async () => {
    const box = await seal(recipient.publicKey, SECRET, CONTEXT)
    const epk = { ...box.epk, y: box.epk.x }
    await expect(open(recipient.privateKey, { ...box, epk }, CONTEXT)).rejects.toThrow()
  })

  test("openText refuses a plaintext that is not valid UTF-8", async () => {
    const box = await seal(recipient.publicKey, Uint8Array.of(0xff, 0xfe), CONTEXT)
    await expect(openText(recipient.privateKey, box, CONTEXT)).rejects.toThrow()
  })
})

describe("isSealedBox", () => {
  const valid: SealedBox = { v: 1, epk: { kty: "EC", crv: "P-256", x: "xx", y: "yy" }, iv: "iv", ct: "ct" }

  test("accepts the expected shape", () => {
    expect(isSealedBox(valid)).toBe(true)
  })

  test("rejects non-objects", () => {
    for (const value of [null, undefined, 1, "box", true, [] as unknown[]]) expect(isSealedBox(value)).toBe(false)
  })

  test("rejects a wrong version, missing fields or wrong types", () => {
    const cases: unknown[] = [
      { ...valid, v: 2 },
      { ...valid, v: "1" },
      { ...valid, iv: undefined },
      { ...valid, iv: 12 },
      { ...valid, ct: undefined },
      { ...valid, ct: ["ct"] },
      { ...valid, epk: undefined },
      { ...valid, epk: null },
      { ...valid, epk: "epk" },
      { ...valid, epk: { ...valid.epk, kty: "OKP" } },
      { ...valid, epk: { ...valid.epk, crv: "P-384" } },
      { ...valid, epk: { ...valid.epk, x: 1 } },
      { ...valid, epk: { ...valid.epk, y: undefined } },
    ]
    for (const value of cases) expect(isSealedBox(value)).toBe(false)
  })

  test("rejects an oversized ciphertext", () => {
    expect(isSealedBox({ ...valid, ct: "A".repeat(1_999_999) })).toBe(true)
    expect(isSealedBox({ ...valid, ct: "A".repeat(2_000_000) })).toBe(false)
  })
})
