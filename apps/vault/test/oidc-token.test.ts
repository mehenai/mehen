import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { OIDC_LIMITS, OIDC_PROVIDERS } from "@mehen/protocol"
import { setOidcFetchForTest, verifyGoogleToken } from "../src/directory/oidc.ts"
import { fakeGoogle } from "./oidc-google.ts"

let google: Awaited<ReturnType<typeof fakeGoogle>>
let network: ReturnType<typeof vi.spyOn<typeof globalThis, "fetch">>
beforeEach(async () => { google = await fakeGoogle(); setOidcFetchForTest(google.fetcher); network = vi.spyOn(globalThis, "fetch").mockImplementation(async () => { throw new Error("No live network") }) })
afterEach(() => { expect(network).not.toHaveBeenCalled(); network.mockRestore(); setOidcFetchForTest(null) })
const expected = () => ({ clientId: "test-google-client", nonce: "test-nonce", now: Date.now() })
async function refuses(claims: Record<string, unknown>, header?: Record<string, unknown>) { await expect(verifyGoogleToken(await google.sign(claims, header), expected())).rejects.toMatchObject({ code: "identity_required" }) }
describe("oidc-token pinned Google verification", () => {
  it("verifies RSA signatures and canonicalises both issuer spellings", async () => {
    for (const iss of OIDC_PROVIDERS.google.issuers) expect(await verifyGoogleToken(await google.sign({ ...google.claims(), iss }), expected())).toMatchObject({ issuer: OIDC_PROVIDERS.google.issuer, subject: "google-alex", emailVerified: true })
    expect(google.calls).toEqual([OIDC_PROVIDERS.google.jwks])
  })
  it.each([
    ["aud", "other-client"], ["aud", ["test-google-client"]], ["iss", "https://attacker.test"], ["azp", "other-client"], ["nonce", "other-nonce"], ["exp", 1], ["iat", Math.floor(Date.now() / 1000) + 3600], ["iat", Math.floor(Date.now() / 1000) - 301], ["sub", ""], ["sub", 42], ["email_verified", false], ["email_verified", "true"], ["email", false], ["hd", 42], ["name", "a".repeat(4097)],
  ])("refuses invalid %s claim %j", async (name, value) => { await refuses({ ...google.claims(), [name]: value }) })
  it.each(["iss", "aud", "sub", "exp", "iat", "nonce", "email", "email_verified"])("refuses missing %s", async name => { const claims = google.claims(); delete claims[name]; await refuses(claims) })
  it.each(["none", "HS256", "ES256"])("refuses %s algorithm confusion", async alg => { await refuses(google.claims(), { alg, kid: google.jwk.kid }); expect(google.calls).toEqual([]) })
  it("refuses signature tampering and malformed/oversized tokens", async () => {
    const token = await google.sign(google.claims())
    for (const bad of [token.replace(".ey", ".ez"), `${token}x`, "not-a-jwt", "a".repeat(OIDC_LIMITS.tokenBytes + 1)]) await expect(verifyGoogleToken(bad, expected())).rejects.toMatchObject({ code: "identity_required" })
  })
  it("bounds unknown key refresh to one and refuses even during outage", async () => {
    await refuses(google.claims(), { alg: "RS256", kid: "unknown" })
    expect(google.calls).toEqual([OIDC_PROVIDERS.google.jwks, OIDC_PROVIDERS.google.jwks])
    google.faults.unavailable = true
    await refuses(google.claims(), { alg: "RS256", kid: "unknown" })
  })
  it("refuses oversized JWKS and duplicate kids", async () => {
    google.faults.jwks = { keys: [google.jwk], padding: "x".repeat(OIDC_LIMITS.jwksBytes) }
    await refuses(google.claims())
    google.faults.jwks = { keys: [google.jwk, google.jwk] }
    await refuses(google.claims())
  })
  it("skips unexpected JWKS key types, algorithms and uses but requires a usable pinned RSA key", async () => {
    const token = await google.sign(google.claims())
    const unexpected = [{ kty: "EC",kid: "ec-key",alg: "ES256",use: "sig" },{ ...google.jwk,kid: "rsa-other-alg",alg: "PS256" },{ ...google.jwk,kid: "rsa-encryption",use: "enc" }]
    google.faults.jwks = { keys: [...unexpected,google.jwk] }
    expect(await verifyGoogleToken(token,expected())).toMatchObject({ subject: "google-alex" })
    setOidcFetchForTest(google.fetcher)
    google.faults.jwks = { keys: unexpected }
    await expect(verifyGoogleToken(token,expected())).rejects.toMatchObject({ code: "identity_required" })
  })
  it("after max-age a provider outage uses a cached key for at most twenty-four hours", async () => {
    const started = Date.now(),maxAge = 3600000,staleUntil = started+maxAge+86400000
    async function tokenAt(now: number) { return google.sign({ ...google.claims(),iat: Math.floor(now/1000),exp: Math.floor(now/1000)+3600 }) }
    await verifyGoogleToken(await tokenAt(started),{ ...expected(),now: started })
    google.faults.unavailable = true
    for (const now of [started+maxAge+1,staleUntil-1]) expect(await verifyGoogleToken(await tokenAt(now),{ ...expected(),now })).toMatchObject({ subject: "google-alex" })
    await expect(verifyGoogleToken(await tokenAt(staleUntil),{ ...expected(),now: staleUntil })).rejects.toMatchObject({ code: "identity_required" })
  })
  it("does not require hd for an email proof but never invents a hosted domain", async () => { const claims = google.claims(); delete claims.hd; expect(await verifyGoogleToken(await google.sign(claims), expected())).toMatchObject({ domain: null }) })
  it("asks for redirects to be left alone, which Workers allows, and refuses one from Google", async () => {
    const token = await google.sign(google.claims()), seen: unknown[] = []
    setOidcFetchForTest(async (url, init) => { new Request(url, init); seen.push(init.redirect); return new Response(null, { status: 302, headers: { location: "https://attacker.test/certs" } }) })
    await refuses(google.claims())
    expect(seen).toEqual(["manual"])
    setOidcFetchForTest(google.fetcher)
    expect(await verifyGoogleToken(token, expected())).toMatchObject({ subject: "google-alex" })
  })
})
