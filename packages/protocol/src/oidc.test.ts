import { expect, test } from "bun:test"
import { checkOidcClaims, OIDC_PROVIDERS, satisfiesRule } from "./oidc.ts"
const now = 1_800_000_000_000
const expected = { clientId: "client", nonce: "nonce", now }
const claims = { iss: "accounts.google.com", sub: "subject", aud: "client", exp: now / 1000 + 300, iat: now / 1000, nonce: "nonce", email: "Tom@NORTHWIND.EXAMPLE", email_verified: true, hd: "NORTHWIND.EXAMPLE" }
test("both exact issuer spellings canonicalise before identity lookup", () => {
 for (const iss of OIDC_PROVIDERS.google.issuers) {
  const result = checkOidcClaims({ ...claims, iss }, expected)
  expect(result).toEqual({ ok: true, claims: { issuer: "https://accounts.google.com", subject: "subject", email: "tom@northwind.example", emailVerified: true, domain: "northwind.example", name: null, issuedAt: now / 1000, expiresAt: now / 1000 + 300 } })
  if (result.ok) {
   expect(satisfiesRule(result.claims, { provider: "google", domains: ["northwind.example"], roles: ["member"] }, "member")).toBe(true)
   expect(satisfiesRule({ ...result.claims, domain: null }, { provider: "google", domains: ["northwind.example"], roles: ["member"] }, "member")).toBe(false)
   expect(satisfiesRule({ ...result.claims, email: "tom@other.ai" }, { provider: "google", domains: ["northwind.example"], roles: ["member"] }, "member")).toBe(false)
  }
 }
})
test("malformed/incorrect typed claims refuse without throwing or echoing input", () => {
 for (const patch of [{ iss: "https://evil.test" }, { sub: 7 }, { sub: "" }, { aud: ["client"] }, { aud: "wrong" }, { azp: "wrong" }, { nonce: "other" }, { email_verified: "true" }, { email_verified: false }, { email: 4 }, { hd: 7 }, { iat: now / 1000 + 31 }, { iat: now / 1000 - 301 }, { exp: now / 1000 - 31 }, { sub: "x".repeat(5000) }]) {
  expect(checkOidcClaims({ ...claims, ...patch }, expected).ok).toBe(false)
 }
 for (const input of [null, [], 1, "token", undefined]) expect(checkOidcClaims(input, expected).ok).toBe(false)
})

test("oversized and non-serialisable claims refuse without throwing", () => {
 expect(checkOidcClaims({ ...claims, extra: "x".repeat(20_000) }, expected)).toEqual({ ok: false, reason: "claims_invalid" })
 const cycle: { cycle?: unknown } = {}; cycle.cycle = cycle
 expect(checkOidcClaims(cycle, expected)).toEqual({ ok: false, reason: "claims_invalid" })
})


test("satisfiesRule matches the domain exactly, never a suffix or subdomain", () => {
 const rule = { provider: "google" as const,domains: ["example.com"],roles: ["member" as const] }
 for (const [email,hd] of [["a@evilexample.com","evilexample.com"],["a@example.com.evil","example.com.evil"],["a@sub.example.com","sub.example.com"],["a@sub.example.com","example.com"],["a@example.com",undefined],["a@example.com","evilexample.com"],["a@evilexample.com","example.com"]] as const) {
  const result = checkOidcClaims({ ...claims,email,hd },expected)
  expect(result.ok).toBe(true)
  if (result.ok) expect(satisfiesRule(result.claims,rule,"member")).toBe(false)
 }
 const mixed = checkOidcClaims({ ...claims,email: "a@EXAMPLE.COM",hd: "Example.Com" },expected)
 expect(mixed.ok).toBe(true)
 if (mixed.ok) expect(satisfiesRule(mixed.claims,rule,"member")).toBe(true)
})
