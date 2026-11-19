import { base64UrlEncode, OIDC_PROVIDERS, utf8 } from "@mehen/protocol"
import type { OidcFetch } from "../src/directory/oidc.ts"

export async function fakeGoogle() {
  const pair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]) as CryptoKeyPair
  const jwk = { ...await crypto.subtle.exportKey("jwk", pair.publicKey), kid: "test-google-key", alg: "RS256", use: "sig" }
  const calls: string[] = [], authorisations = new Map<string, { nonce: string; challenge: string; claims: Record<string, unknown> }>()
  const faults = { unavailable: false, jwks: null as unknown, token: null as string | null }
  async function sign(claims: Record<string, unknown>, header: Record<string, unknown> = { alg: "RS256", kid: jwk.kid }) {
    const body = `${base64UrlEncode(utf8(JSON.stringify(header)))}.${base64UrlEncode(utf8(JSON.stringify(claims)))}`
    return `${body}.${base64UrlEncode(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, utf8(body)))}`
  }
  function claims(nonce = "test-nonce"): Record<string, unknown> {
    const now = Math.floor(Date.now() / 1000)
    return { iss: OIDC_PROVIDERS.google.issuer, sub: "google-alex", aud: "test-google-client", nonce, email: "alex@northwind.example", email_verified: true, hd: "northwind.example", name: "Alex", iat: now, exp: now + 3600 }
  }
  const fetcher: OidcFetch = async (url, init) => {
    // The runtime's own check of the request options: workerd refuses some
    // that other runtimes accept, such as redirect "error".
    new Request(url, init)
    calls.push(url)
    if (faults.unavailable) throw new Error("Fake provider outage")
    if (url === OIDC_PROVIDERS.google.jwks) return Response.json(faults.jwks ?? { keys: [jwk] }, { headers: { "cache-control": "public,max-age=3600" } })
    if (url !== OIDC_PROVIDERS.google.token) throw new Error("Unpinned provider endpoint")
    const form = new URLSearchParams(String(init.body)), stored = authorisations.get(form.get("code") ?? "")
    authorisations.delete(form.get("code") ?? "")
    if (!stored || form.get("grant_type") !== "authorization_code" || form.get("client_id") !== "test-google-client" || form.get("client_secret") !== "test-only-google-secret" || base64UrlEncode(await crypto.subtle.digest("SHA-256", utf8(form.get("code_verifier") ?? ""))) !== stored.challenge) return Response.json({ error: "invalid_grant" }, { status: 400 })
    return Response.json({ id_token: faults.token ?? await sign(stored.claims), access_token: "test-never-retained", refresh_token: "test-never-retained" })
  }
  function authorise(url: string, override: Record<string, unknown> = {}) {
    const parsed = new URL(url), code = crypto.randomUUID(), nonce = parsed.searchParams.get("nonce")!, challenge = parsed.searchParams.get("code_challenge")!
    if (parsed.origin + parsed.pathname !== OIDC_PROVIDERS.google.authorise || parsed.searchParams.get("scope") !== "openid email profile" || parsed.searchParams.has("access_type")) throw new Error("Unexpected authorisation")
    authorisations.set(code, { nonce, challenge, claims: { ...claims(nonce), ...override } })
    return { code, state: parsed.searchParams.get("state")! }
  }
  return { jwk, sign, claims, calls, faults, fetcher, authorise }
}
