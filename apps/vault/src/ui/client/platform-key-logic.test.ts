// The register and add-key forms' key handling: a pasted public JWK is
// refused for every reason scripts/platform.ts refuses a key file, and a
// key made here signs what its public half verifies, with the private
// half only as PKCS8 text.
import { describe, expect, it } from "vitest"
import { base64UrlDecode } from "@mehen/protocol/bytes"
import { jwkThumbprint } from "@mehen/protocol/proof"
import { PASTED_KEY_MAX, PASTED_KEY_PROBLEMS, makePlatformKey, publicJwkText, readPastedPlatformKey } from "./platform-key-logic.ts"

const P256 = { name: "ECDSA", namedCurve: "P-256" } as const

async function publicJwk(): Promise<JsonWebKey> {
  const pair = await crypto.subtle.generateKey(P256, true, ["sign", "verify"])
  return crypto.subtle.exportKey("jwk", pair.publicKey)
}

describe("readPastedPlatformKey", () => {
  it("takes a public JWK, keeps only kty, crv, x and y, and gives its thumbprint", async () => {
    const jwk = await publicJwk()
    const read = await readPastedPlatformKey(`  ${JSON.stringify({ ...jwk, alg: "ES256", use: "sig" })}\n`)
    if (!read.ok) throw new Error(read.problem)
    expect(Object.keys(read.jwk).sort()).toEqual(["crv", "kty", "x", "y"])
    expect(read.thumbprint).toBe(await jwkThumbprint(read.jwk))
  })

  it("refuses a private key, whatever else it holds", async () => {
    const pair = await crypto.subtle.generateKey(P256, true, ["sign", "verify"])
    const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey)
    expect(await readPastedPlatformKey(JSON.stringify(privateJwk))).toEqual({ ok: false, problem: PASTED_KEY_PROBLEMS.private })
  })

  it("refuses a private key that is not a JWK: PEM, or PKCS8 or SEC1 in base64, a made key's own text among them", async () => {
    const made = await makePlatformKey()
    for (const text of [made.privatePkcs8, `-----BEGIN PRIVATE KEY-----\n${made.privatePkcs8}\n-----END PRIVATE KEY-----`, "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY-----", "MHcCAQEEIBx"]) {
      expect(await readPastedPlatformKey(text), text.slice(0, 20)).toEqual({ ok: false, problem: PASTED_KEY_PROBLEMS.private })
    }
    // A public key in PEM is not a JWK either, but no private key.
    expect(await readPastedPlatformKey("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----")).toEqual({ ok: false, problem: PASTED_KEY_PROBLEMS.json })
  })

  it.each([
    ["", PASTED_KEY_PROBLEMS.empty],
    ["   ", PASTED_KEY_PROBLEMS.empty],
    ["{not json", PASTED_KEY_PROBLEMS.json],
    ["[1,2]", PASTED_KEY_PROBLEMS.object],
    ["null", PASTED_KEY_PROBLEMS.object],
    ['"a string"', PASTED_KEY_PROBLEMS.object],
    ['{"kty":"RSA","n":"x","e":"AQAB"}', PASTED_KEY_PROBLEMS.shape],
    ['{"kty":"EC","crv":"P-384","x":"a","y":"b"}', PASTED_KEY_PROBLEMS.shape],
    [" ".repeat(10) + "x".repeat(PASTED_KEY_MAX + 1), PASTED_KEY_PROBLEMS.long],
  ])("refuses %j", async (text, problem) => {
    expect(await readPastedPlatformKey(text)).toEqual({ ok: false, problem })
  })

  it("refuses a point that is not on P-256", async () => {
    const jwk = await publicJwk()
    const off = { ...jwk, y: jwk.x }
    expect(await readPastedPlatformKey(JSON.stringify(off))).toEqual({ ok: false, problem: PASTED_KEY_PROBLEMS.curve })
  })
})

describe("makePlatformKey", () => {
  it("makes a pair whose PKCS8 text signs what its public JWK verifies", async () => {
    const made = await makePlatformKey()
    expect(made.privatePkcs8).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(made.thumbprint).toBe(await jwkThumbprint(made.jwk))
    const read = await readPastedPlatformKey(publicJwkText(made.jwk))
    expect(read).toEqual({ ok: true, jwk: made.jwk, thumbprint: made.thumbprint })
    const signing = await crypto.subtle.importKey("pkcs8", base64UrlDecode(made.privatePkcs8), P256, false, ["sign"])
    const verifying = await crypto.subtle.importKey("jwk", { ...made.jwk, ext: true }, P256, false, ["verify"])
    const data = new TextEncoder().encode("mehen platform key")
    const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signing, data)
    expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, verifying, signature, data)).toBe(true)
  })

  it("never puts the private half in the public JWK", async () => {
    const made = await makePlatformKey()
    expect(publicJwkText(made.jwk)).not.toContain('"d"')
    expect(made.jwk).not.toHaveProperty("d")
  })
})
