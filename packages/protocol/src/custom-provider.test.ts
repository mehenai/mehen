import { describe, expect, test } from "bun:test"
import { checkBinding, parseDestination } from "./binding.ts"
import { CUSTOM_PROVIDER_DEFAULT_INJECTION, type CustomOAuthProvider, CustomOAuthProviderSchema, PublicHttpsUrlSchema, customClientBinding, customOAuthExchange, customProviderInjection, isPublicHostName } from "./custom-provider.ts"
import { CUSTOM_OAUTH_PROVIDER_ID, OAUTH_PROVIDERS, TEMPLATES, normaliseScope } from "./templates.ts"

const yahoo: CustomOAuthProvider = {
  name: "Yahoo Mail",
  authorizeUrl: "https://api.login.yahoo.com/oauth2/request_auth",
  tokenUrl: "https://api.login.yahoo.com/oauth2/get_token",
  scopes: ["mail-r", "openid"],
  pkce: "S256",
  clientAuth: "client_secret_basic",
  hosts: ["api.mail.yahoo.com"],
}

describe("isPublicHostName", () => {
  test("accepts public names", () => {
    for (const host of ["api.mail.yahoo.com", "example.com", "a-b.example.co.uk", "xn--bcher-kva.example"]) expect(isPublicHostName(host)).toBe(true)
  })

  test("refuses addresses, private and reserved names, and anything not canonical", () => {
    for (const host of ["10.0.0.1", "127.0.0.1", "169.254.169.254", "[::1]", "localhost", "api.localhost", "printer.local", "db.internal", "nas.lan", "box.home.arpa", "1.0.0.10.in-addr.arpa", "x.test", "x.invalid", "x.onion", "intranet", "API.example.com", "example.com.", "*.example.com", "example.123", ""]) {
      expect(isPublicHostName(host)).toBe(false)
    }
  })
})

test("PublicHttpsUrlSchema takes https on a public name only, with no user info or fragment", () => {
  expect(PublicHttpsUrlSchema.safeParse("https://app.globex.ai/oauth/callback").success).toBe(true)
  expect(PublicHttpsUrlSchema.safeParse("https://api.example.com:8443/token?x=1").success).toBe(true)
  for (const url of ["http://app.globex.ai/cb", "https://user:pw@app.globex.ai/cb", "https://app.globex.ai/cb#x", "https://10.0.0.1/token", "https://localhost/cb", "https://[::1]/cb", "ftp://example.com/x", "not a url"]) {
    expect(PublicHttpsUrlSchema.safeParse(url).success).toBe(false)
  }
})

describe("CustomOAuthProviderSchema", () => {
  test("accepts a confidential client, a public client with PKCE, and every optional member", () => {
    expect(CustomOAuthProviderSchema.parse(yahoo)).toEqual(yahoo)
    expect(CustomOAuthProviderSchema.safeParse({ ...yahoo, clientAuth: "none", pkce: "S256" }).success).toBe(true)
    expect(CustomOAuthProviderSchema.safeParse({ ...yahoo, pkce: "none", clientAuth: "client_secret_post" }).success).toBe(true)
    const full: CustomOAuthProvider = { ...yahoo, scopeSeparator: ",", authorizeParams: { access_type: "offline", prompt: "consent" }, injection: { in: "header", name: "X-Access-Token", format: "{access_token}" } }
    expect(CustomOAuthProviderSchema.parse(full)).toEqual(full)
    expect(CustomOAuthProviderSchema.safeParse({ ...yahoo, injection: { in: "query", name: "token", field: "access_token" } }).success).toBe(true)
  })

  test("refuses unsafe URLs and hosts, a public client without PKCE, reserved parameters and headers, and extra members", () => {
    for (const bad of [
      { ...yahoo, authorizeUrl: "http://api.login.yahoo.com/oauth2/request_auth" },
      { ...yahoo, tokenUrl: "https://169.254.169.254/token" },
      { ...yahoo, tokenUrl: "https://user:pw@api.login.yahoo.com/token" },
      { ...yahoo, hosts: [] },
      { ...yahoo, hosts: ["10.1.2.3"] },
      { ...yahoo, hosts: ["db.internal"] },
      { ...yahoo, hosts: ["api.mail.yahoo.com", "api.mail.yahoo.com"] },
      { ...yahoo, hosts: Array.from({ length: 17 }, (_, i) => `h${i}.example.com`) },
      { ...yahoo, clientAuth: "none", pkce: "none" },
      { ...yahoo, pkce: "plain" },
      { ...yahoo, clientAuth: "private_key_jwt" },
      { ...yahoo, scopes: ["mail r"] },
      { ...yahoo, scopes: ["a,b"] },
      { ...yahoo, scopes: ["mail-r", "mail-r"] },
      { ...yahoo, scopeSeparator: ";" },
      { ...yahoo, authorizeParams: { redirect_uri: "https://evil.example.com" } },
      { ...yahoo, authorizeParams: { State: "x" } },
      { ...yahoo, authorizeParams: Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`p${i}`, "v"])) },
      { ...yahoo, injection: { in: "header", name: "Cookie", format: "{access_token}" } },
      { ...yahoo, injection: { in: "header", name: "Authorization", format: "Bearer {key}" } },
      { ...yahoo, injection: { in: "query", name: "token", field: "refresh_token" } },
      { ...yahoo, injection: { in: "basic", username: "a", password: "b" } },
      { ...yahoo, name: "" },
      { ...yahoo, clientSecret: "shh" },
    ]) {
      expect(CustomOAuthProviderSchema.safeParse(bad).success).toBe(false)
    }
  })

  test("injects a bearer Authorization header unless it says otherwise", () => {
    expect(customProviderInjection(CustomOAuthProviderSchema.parse(yahoo))).toEqual(CUSTOM_PROVIDER_DEFAULT_INJECTION)
    expect(CUSTOM_PROVIDER_DEFAULT_INJECTION).toEqual({ in: "header", name: "Authorization", format: "Bearer {access_token}" })
    const query = CustomOAuthProviderSchema.parse({ ...yahoo, injection: { in: "query", name: "token", field: "access_token" } })
    expect(customProviderInjection(query)).toEqual({ in: "query", name: "token", field: "access_token" })
  })
})

describe("customOAuthExchange", () => {
  test("runs the flow at the definition's own URLs, with its client authentication, scopes and parameters", () => {
    const exchange = customOAuthExchange({ ...yahoo, scopeSeparator: ",", authorizeParams: { prompt: "consent" } })
    expect(exchange.id).toBe(CUSTOM_OAUTH_PROVIDER_ID)
    expect(exchange.displayName).toBe("Yahoo Mail")
    expect(exchange.identity).toBeNull()
    expect(exchange.auth).toMatchObject({ authorizeUrl: yahoo.authorizeUrl, tokenUrl: yahoo.tokenUrl, pkce: "S256", clientAuth: "client_secret_basic", tokenRequestFormat: "form", authorizeParams: { prompt: "consent" } })
    expect(exchange.auth.scopes).toMatchObject({ separator: ",", param: "scope", identity: [], identityScopes: [], defaults: ["mail-r", "openid"], allowed: ["mail-r", "openid"] })
    expect(normaliseScope(exchange, "mail-r")).toBe("mail-r")
    expect(normaliseScope(exchange, "mail-w")).toBeNull()
    expect(customOAuthExchange({ ...yahoo, pkce: "none" }).auth.pkce).toBe("unsupported")
    expect(customOAuthExchange({ ...yahoo, clientAuth: "none" }).auth.clientAuth).toBe("none")
  })

  test("binds the token to the definition's hosts, injected as it says", () => {
    expect(customOAuthExchange(yahoo).upstream).toEqual({ baseUrl: "https://api.mail.yahoo.com", binding: { hosts: ["api.mail.yahoo.com"] }, injection: CUSTOM_PROVIDER_DEFAULT_INJECTION })
    const header = { in: "header" as const, name: "X-Access-Token", format: "{access_token}" }
    expect(customOAuthExchange({ ...yahoo, injection: header }).upstream.injection).toEqual(header)
  })

  test("is never mistaken for a catalogue provider or template", () => {
    expect(Object.hasOwn(OAUTH_PROVIDERS, CUSTOM_OAUTH_PROVIDER_ID)).toBe(false)
    expect(Object.hasOwn(TEMPLATES, CUSTOM_OAUTH_PROVIDER_ID)).toBe(false)
  })
})

test("customClientBinding lets the client secret go only to the token URL, by POST", () => {
  const binding = customClientBinding({ ...yahoo, tokenUrl: "https://api.login.yahoo.com/oauth2/get_token?realm=x" })
  expect(binding).toEqual({ hosts: ["api.login.yahoo.com"], paths: ["/oauth2/get_token"], methods: ["POST"] })
  const at = (method: string, url: string) => {
    const dest = parseDestination(method, url)
    return dest.ok && checkBinding(binding, dest.destination).ok
  }
  expect(at("POST", yahoo.tokenUrl)).toBe(true)
  expect(at("GET", yahoo.tokenUrl)).toBe(false)
  expect(at("POST", "https://api.login.yahoo.com/oauth2/request_auth")).toBe(false)
  expect(at("POST", "https://evil.example.com/oauth2/get_token")).toBe(false)
})
