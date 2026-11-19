import { beforeAll, describe, expect, test } from "bun:test"
import { base64UrlEncode } from "@mehen/protocol/bytes"
import { type ReleaseKey, manifestSigningBytes } from "@mehen/protocol/release-manifest"
import { compareVersions as protocolCompareVersions } from "@mehen/protocol/version"
import { RELEASE_KEYS } from "./release-keys.ts"
import { compareVersions, downloadBase, latestRelease, parseManifest, releaseBytes, releaseTrust, sha256, verifiedBinary, verifiedManifest, type ReleaseManifest } from "./release-client.ts"

// Test release keys, generated here; never a real release key.
type TestKey = { key: ReleaseKey; privateKey: CryptoKey }
async function testKey(id: string): Promise<TestKey> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey)
  return { key: { id, alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y! }, presence: "none", created: "2026-10-28T12:00:00.000Z" }, privateKey: pair.privateKey }
}
async function sign(manifest: ReleaseManifest, signer: TestKey) {
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signer.privateKey, manifestSigningBytes(manifest))
  return { ...manifest, signatures: [{ keyId: signer.key.id, alg: "ES256" as const, signature: base64UrlEncode(signature) }] }
}

const file = { name: "mehen-linux-x64", os: "linux", arch: "x64", url: "https://mehen.dev/dl/v1.2.3/mehen-linux-x64.gz", sha256: "0".repeat(64), size: 100, gzSha256: "1".repeat(64), gzSize: 50 }
const release = (): ReleaseManifest => ({ version: "1.2.3", commit: "1234567", builtAt: "2026-10-28T12:00:00Z", files: [{ ...file }] })

let trusted: TestKey
let other: TestKey
beforeAll(async () => {
  trusted = await testKey("rk-test-trusted")
  other = await testKey("rk-test-other")
})

test("compareVersions is protocol's, re-exported", () => {
  expect(compareVersions).toBe(protocolCompareVersions)
  expect(compareVersions("0.10.0", "0.9.9")).toBe(1)
  expect(() => compareVersions("../bad", "1.2.3")).toThrow("Invalid release version")
})
test("release URLs refuse insecure, credentialed or ambiguous origins", () => {
  for (const base of ["http://example.test/dl", "file:///tmp", "https://user:pass@example.test", "https://example.test/dl?q=1", "https://example.test/dl#fragment", "not a URL"]) expect(() => downloadBase({ MEHEN_DL_BASE: base })).toThrow()
  expect(downloadBase({ MEHEN_DL_BASE: "http://127.0.0.1:1234/dl/" })).toBe("http://127.0.0.1:1234/dl")
})
test("manifest refuses malformed JSON, traversal, duplicate files and bad hashes", async () => {
  await expect(latestRelease("https://example.test", [trusted.key], async () => new Response("broken"))).rejects.toThrow("manifest JSON")
  for (const manifest of [{}, { version: "../path", commit: "1234567", builtAt: "today", files: [] }, { version: "1.2.3", commit: "1234567", builtAt: "today", files: [{ name: "../mehen" }] }]) expect(() => parseManifest(manifest)).toThrow("release")
})
test("download size and HTTP failures are refusals, redirects are disabled", async () => {
  await expect(releaseBytes("https://example.test", 1, async (_url, init) => { expect(init?.redirect).toBe("error"); return new Response("too much") })).rejects.toThrow("declared size")
  await expect(releaseBytes("https://example.test", 1, async () => new Response(null, { status: 404 }))).rejects.toThrow("HTTP 404")
})

test("duplicate files, invalid hashes, unsafe sizes and invalid gzip are refused", async () => {
  const compressed = new TextEncoder().encode("not gzip")
  const file = { name: "mehen-linux-x64", os: "linux", arch: "x64", url: "https://example.test/mehen.gz", sha256: "0".repeat(64), size: 100, gzSha256: sha256(compressed), gzSize: compressed.length }
  const manifest = { version: "1.2.3", commit: "1234567", builtAt: "today", files: [file] }
  expect(() => parseManifest({ ...manifest, files: [file, file] })).toThrow("duplicate")
  for (const change of [{ sha256: "bad" }, { gzSha256: "bad" }, { size: -1 }, { gzSize: 1e12 }]) expect(() => parseManifest({ ...manifest, files: [{ ...file, ...change }] })).toThrow("release file")
  await expect(verifiedBinary("https://example.test", manifest, file.name, async () => new Response(compressed))).rejects.toThrow("unpack release")
})

describe("signed manifests", () => {
  test("latestRelease returns a manifest signed by a trusted key", async () => {
    const signed = await sign(release(), trusted)
    const manifest = await latestRelease("https://example.test", [trusted.key], async url => { expect(url).toBe("https://example.test/latest.json"); return Response.json(signed) })
    expect(manifest).toEqual(signed)
  })

  test("unsigned, untrusted, tampered and malformed manifests are refused", async () => {
    const signed = await sign(release(), trusted)
    const serve = (value: unknown) => async () => Response.json(value)
    await expect(latestRelease("https://example.test", [trusted.key], serve(release()))).rejects.toThrow("not signed")
    await expect(latestRelease("https://example.test", [trusted.key], serve({ ...release(), signatures: [] }))).rejects.toThrow("not signed")
    await expect(latestRelease("https://example.test", [trusted.key], serve(await sign(release(), other)))).rejects.toThrow("a key this build does not trust")
    await expect(latestRelease("https://example.test", [trusted.key], serve({ ...signed, version: "9.9.9" }))).rejects.toThrow("signature does not verify")
    await expect(latestRelease("https://example.test", [trusted.key], serve({ ...signed, files: [{ ...file, sha256: "2".repeat(64) }] }))).rejects.toThrow("signature does not verify")
    await expect(latestRelease("https://example.test", [trusted.key], serve({ ...signed, signatures: [{ keyId: "rk-test-trusted", alg: "ES256", signature: "short" }] }))).rejects.toThrow("malformed")
    await expect(verifiedManifest({ ...signed, files: [{ ...file, name: "../mehen" }] }, [trusted.key])).rejects.toThrow("release file")
  })
})

describe("releaseTrust", () => {
  const keys = () => JSON.stringify([trusted.key])
  const loopback = "http://127.0.0.1:8787/dl"
  const publicBase = "https://mehen.dev/dl"

  test("the compiled set is the one unattended Office key, trusted without an override", () => {
    expect(RELEASE_KEYS.map((key) => [key.id, key.presence])).toEqual([["rk-studio-2026-auto", "none"]])
    for (const build of ["release", "dev", null] as const) {
      expect(releaseTrust({}, publicBase, build)).toEqual(RELEASE_KEYS)
      expect(releaseTrust({}, loopback, build)).toEqual(RELEASE_KEYS)
    }
  })

  test("an empty compiled set fails closed", () => {
    for (const build of ["release", "dev", null] as const) {
      expect(() => releaseTrust({}, publicBase, build, [])).toThrow("No trusted release key is compiled into this build")
      expect(() => releaseTrust({}, loopback, build, [])).toThrow("No trusted release key is compiled into this build")
      expect(() => releaseTrust({ MEHEN_RELEASE_KEYS: keys() }, publicBase, "release", [])).toThrow("No trusted release key is compiled into this build")
    }
  })

  test("MEHEN_RELEASE_KEYS is honoured for a loopback http base, even in a release build", () => {
    expect(releaseTrust({ MEHEN_RELEASE_KEYS: keys() }, loopback, "release")).toEqual([trusted.key])
    expect(releaseTrust({ MEHEN_RELEASE_KEYS: keys() }, "http://localhost:9/dl", "release")).toEqual([trusted.key])
  })

  test("MEHEN_RELEASE_KEYS is honoured for a build that is not a release build", () => {
    expect(releaseTrust({ MEHEN_RELEASE_KEYS: keys() }, publicBase, "dev")).toEqual([trusted.key])
    expect(releaseTrust({ MEHEN_RELEASE_KEYS: keys() }, publicBase, null)).toEqual([trusted.key])
  })

  test("a release build against a non-loopback base ignores MEHEN_RELEASE_KEYS and trusts only the compiled set", () => {
    for (const base of [publicBase, "https://mirror.example/dl", "https://127.0.0.1:8443/dl"]) {
      expect(releaseTrust({ MEHEN_RELEASE_KEYS: keys() }, base, "release")).toEqual(RELEASE_KEYS)
      expect(releaseTrust({ MEHEN_RELEASE_KEYS: keys() }, base, "release")).not.toContainEqual(trusted.key)
    }
  })

  test("a malformed or empty MEHEN_RELEASE_KEYS is a usage error, never an empty trust set", () => {
    for (const value of ["not json", "[]", "{}", JSON.stringify([{ ...trusted.key, presence: "maybe" }]), JSON.stringify([{ ...trusted.key, jwk: { ...trusted.key.jwk, d: "A".repeat(43) } }])]) {
      expect(() => releaseTrust({ MEHEN_RELEASE_KEYS: value }, loopback, "dev")).toThrow("MEHEN_RELEASE_KEYS must be a JSON array")
    }
  })
})
