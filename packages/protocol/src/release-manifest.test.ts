import { beforeAll, describe, expect, test } from "bun:test"
import { base64UrlEncode, utf8 } from "./bytes.ts"
import { canonicalJson } from "./canonical-json.ts"
import { type ReleaseKey, type ReleaseManifest, type SignedManifest, isReleaseKey, manifestSigningBytes, verifyManifestSignatures } from "./release-manifest.ts"

// Test keys only: generated here, never a release key.
type TestKey = { key: ReleaseKey; privateKey: CryptoKey }

async function testKey(id: string, presence: ReleaseKey["presence"] = "none"): Promise<TestKey> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey)
  return { key: { id, alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y! }, presence, created: "2026-10-28T12:00:00.000Z" }, privateKey: pair.privateKey }
}

async function sign(manifest: ReleaseManifest, signer: TestKey, keyId = signer.key.id): Promise<SignedManifest> {
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signer.privateKey, manifestSigningBytes(manifest))
  return { ...manifest, signatures: [{ keyId, alg: "ES256", signature: base64UrlEncode(signature) }] }
}

const file = { name: "mehen-linux-x64", os: "linux", arch: "x64", url: "https://mehen.dev/dl/v0.3.0/mehen-linux-x64.gz", sha256: "a".repeat(64), size: 100, gzSha256: "b".repeat(64), gzSize: 50 }
const manifest = (): ReleaseManifest => ({ version: "0.3.0", commit: "1a2b3c4", builtAt: "2026-10-28T12:00:00.000Z", files: [{ ...file }] })

let office: TestKey
let second: TestKey
let stranger: TestKey
beforeAll(async () => {
  office = await testKey("rk-test-release", "required")
  second = await testKey("rk-test-second")
  stranger = await testKey("rk-test-stranger")
})

describe("manifestSigningBytes", () => {
  test("is the canonical JSON of the manifest without signatures", async () => {
    const unsigned = manifest()
    const bytes = manifestSigningBytes(unsigned)
    expect(new TextDecoder().decode(bytes)).toBe(canonicalJson(unsigned))
    expect(new TextDecoder().decode(bytes)).toBe('{"builtAt":"2026-10-28T12:00:00.000Z","commit":"1a2b3c4","files":[{"arch":"x64","gzSha256":"' + "b".repeat(64) + '","gzSize":50,"name":"mehen-linux-x64","os":"linux","sha256":"' + "a".repeat(64) + '","size":100,"url":"https://mehen.dev/dl/v0.3.0/mehen-linux-x64.gz"}],"version":"0.3.0"}')
    const signed = await sign(unsigned, office)
    expect(manifestSigningBytes(signed)).toEqual(bytes)
    // Key order and whitespace in the file do not matter; the bytes are canonical.
    const reordered = JSON.parse(JSON.stringify({ files: unsigned.files, version: "0.3.0", builtAt: unsigned.builtAt, commit: unsigned.commit })) as ReleaseManifest
    expect(manifestSigningBytes(reordered)).toEqual(bytes)
  })
})

describe("verifyManifestSignatures", () => {
  test("a valid ES256 signature by a trusted key verifies, after a JSON round trip", async () => {
    const signed = JSON.parse(JSON.stringify(await sign(manifest(), office), null, 2)) as unknown
    const result = await verifyManifestSignatures(signed, [office.key])
    expect(result).toEqual({ ok: true, keyId: "rk-test-release", manifest: signed as SignedManifest })
  })

  test("a two-key set accepts either key; a key removed from the set is refused", async () => {
    const byOffice = await sign(manifest(), office)
    const bySecond = await sign(manifest(), second)
    expect(await verifyManifestSignatures(byOffice, [office.key, second.key])).toMatchObject({ ok: true, keyId: "rk-test-release" })
    expect(await verifyManifestSignatures(bySecond, [office.key, second.key])).toMatchObject({ ok: true, keyId: "rk-test-second" })
    expect(await verifyManifestSignatures(bySecond, [office.key])).toEqual({ ok: false, reason: "unknown_key" })
  })

  test("an empty trusted set verifies nothing", async () => {
    expect(await verifyManifestSignatures(await sign(manifest(), office), [])).toEqual({ ok: false, reason: "unknown_key" })
  })

  test("tampering with any signed field is a bad signature", async () => {
    const signed = await sign(manifest(), office)
    const tampered: unknown[] = [
      { ...signed, version: "0.3.1" },
      { ...signed, files: [{ ...file, sha256: "c".repeat(64) }] },
      { ...signed, files: [{ ...file, url: "https://elsewhere.example/mehen.gz" }] },
      { ...signed, builtAt: "2026-10-29T12:00:00.000Z" },
      { ...signed, extra: "an unknown field is covered too" },
    ]
    for (const value of tampered) expect(await verifyManifestSignatures(value, [office.key])).toEqual({ ok: false, reason: "bad_signature" })
  })

  test("a signature by another key under a trusted key id is a bad signature", async () => {
    expect(await verifyManifestSignatures(await sign(manifest(), stranger, "rk-test-release"), [office.key])).toEqual({ ok: false, reason: "bad_signature" })
  })

  test("one good trusted signature among others is enough", async () => {
    const good = await sign(manifest(), office)
    const other = await sign(manifest(), stranger)
    const forged = await sign({ ...manifest(), version: "9.9.9" }, second)
    const mixed = { ...good, signatures: [other.signatures[0]!, { ...forged.signatures[0]!, keyId: "rk-test-release" }, good.signatures[0]!] }
    expect(await verifyManifestSignatures(mixed, [office.key])).toMatchObject({ ok: true, keyId: "rk-test-release" })
  })

  test("missing or empty signatures are unsigned", async () => {
    expect(await verifyManifestSignatures(manifest(), [office.key])).toEqual({ ok: false, reason: "unsigned" })
    expect(await verifyManifestSignatures({ ...manifest(), signatures: [] }, [office.key])).toEqual({ ok: false, reason: "unsigned" })
  })

  test("malformed manifests and signatures are refused as malformed", async () => {
    const signed = await sign(manifest(), office)
    const sig = signed.signatures[0]!
    const malformed: unknown[] = [
      null,
      "manifest",
      [],
      { ...signed, version: 3 },
      { ...signed, files: "none" },
      { ...signed, files: [{ ...file, size: "100" }] },
      { ...signed, signatures: "sig" },
      { ...signed, signatures: [null] },
      { ...signed, signatures: [{ ...sig, alg: "ES384" }] },
      { ...signed, signatures: [{ ...sig, signature: "not base64url!" }] },
      { ...signed, signatures: [{ ...sig, signature: base64UrlEncode(new Uint8Array(70)) }] },
      { ...signed, signatures: [{ ...sig, keyId: "../key" }] },
      { ...signed, signatures: [{ ...sig, extra: true }] },
      { ...signed, signatures: Array.from({ length: 17 }, () => sig) },
    ]
    for (const value of malformed) expect(await verifyManifestSignatures(value, [office.key])).toEqual({ ok: false, reason: "malformed" })
  })
})

describe("isReleaseKey", () => {
  test("carries presence and accepts exactly the public key fields", () => {
    expect(isReleaseKey(office.key)).toBe(true)
    expect(office.key.presence).toBe("required")
    expect(isReleaseKey(second.key)).toBe(true)
    expect(second.key.presence).toBe("none")
    for (const bad of [
      { ...office.key, presence: "sometimes" },
      { ...office.key, presence: undefined },
      { ...office.key, alg: "EdDSA" },
      { ...office.key, id: "" },
      { ...office.key, created: "yesterday" },
      { ...office.key, extra: 1 },
      { ...office.key, jwk: { ...office.key.jwk, d: "A".repeat(43) } },
      { ...office.key, jwk: { ...office.key.jwk, crv: "P-384" } },
      null,
      [office.key],
    ]) expect(isReleaseKey(bad)).toBe(false)
  })

  test("utf8 of the signing bytes is what a signer signs", async () => {
    const bytes = manifestSigningBytes(manifest())
    expect(bytes).toEqual(utf8(canonicalJson(manifest())))
  })
})
