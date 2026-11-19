// Custom OAuth providers: connect to any OAuth 2 service, not only the
// catalogue's. An oauth-client item may carry its own provider definition
// instead of naming a catalogue provider. The definition is fixed when the
// item is created; a change is a new item. A connection made with it is an
// item with no template, so its policy fails closed (customItemPolicy in
// binding.ts): every request is held unless reads were let through.
//
// The token request is a standard OAuth 2 authorisation code exchange
// (form body; access_token, refresh_token, expires_in in the JSON answer)
// at the definition's token URL, which refresh uses too. The token goes
// only to the definition's API hosts, injected as it says (a bearer
// Authorization header by default). The audit names those hosts, never a
// token.
//
// These are checks on the names a caller sends, with no DNS resolution:
// the vault's fetch runs in a Cloudflare Worker, which cannot reach a
// private network, so a public-looking name that resolves to a private
// address reaches nothing. The vault checks the definition again at every
// connect and refresh (apps/vault areas/oauth-workspace.ts).

import { z } from "zod"
import type { BindingInput, Injection } from "./api.ts"
import { isReservedHeader } from "./headers.ts"
import { isPolicyHost } from "./policy-mode.ts"
import { CUSTOM_OAUTH_PROVIDER_ID, type OAuthExchange } from "./templates.ts"

// Names that never reach the public internet.
const PRIVATE_SUFFIXES = ["localhost", "local", "internal", "intranet", "lan", "home", "corp", "home.arpa", "arpa", "test", "invalid", "onion"]

// A canonical literal host name on the public internet: lower case, at
// least two labels, not an IP address, not a private or reserved name.
export function isPublicHostName(host: string): boolean {
  if (!isPolicyHost(host) || host.startsWith("[") || /^[0-9.]+$/.test(host)) return false
  const labels = host.split(".")
  if (labels.length < 2 || /^[0-9]+$/.test(labels.at(-1) ?? "")) return false
  return !PRIVATE_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`))
}

// https on a public host name, with no user info and no fragment.
export const PublicHttpsUrlSchema = z
  .url({ protocol: /^https$/ })
  .max(2048)
  .refine((value) => {
    if (!URL.canParse(value)) return false
    const url = new URL(value)
    return url.protocol === "https:" && url.username === "" && url.password === "" && url.hash === "" && isPublicHostName(url.hostname)
  }, "Use an https URL on a public host name, with no user name, password or fragment.")

export const PublicHostSchema = z.string().refine(isPublicHostName, "Use a public host name, not an IP address or a private name.")

// The parameters Mehen sets itself on the authorisation URL.
export const RESERVED_AUTHORIZE_PARAMS = ["client_id", "client_secret", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method", "nonce"] as const

export const CUSTOM_PROVIDER_LIMITS = { scopes: 50, authorizeParams: 8, hosts: 16 } as const

export const CUSTOM_PROVIDER_DEFAULT_INJECTION: Injection = { in: "header", name: "Authorization", format: "Bearer {access_token}" }

const ScopeToken = z.string().regex(/^[\x21\x23-\x2B\x2D-\x5B\x5D-\x7E]{1,200}$/, "A scope is printable characters with no space, comma, quote or backslash.")

const CustomInjectionSchema = z.union([
  z.strictObject({
    in: z.literal("header"),
    name: z.string().regex(/^[A-Za-z0-9-]{1,64}$/).refine((name) => !isReservedHeader(name), "That header is reserved."),
    format: z.string().min(1).max(200).refine((format) => format.includes("{access_token}"), "The format must hold {access_token}."),
  }),
  z.strictObject({ in: z.literal("query"), name: z.string().regex(/^[A-Za-z0-9_.-]{1,64}$/), field: z.literal("access_token") }),
])

export const CustomOAuthProviderSchema = z
  .strictObject({
    // What the person calls the service, shown on cards and in the audit.
    name: z.string().min(1).max(64),
    authorizeUrl: PublicHttpsUrlSchema,
    tokenUrl: PublicHttpsUrlSchema,
    // Every scope a connection may ask for; a connect asks for all of them
    // unless it names fewer.
    scopes: z.array(ScopeToken).max(CUSTOM_PROVIDER_LIMITS.scopes),
    // Absent: a space.
    scopeSeparator: z.enum([" ", ","]).optional(),
    pkce: z.enum(["S256", "none"]),
    // "none" is a public client, with no secret: it needs PKCE.
    clientAuth: z.enum(["client_secret_post", "client_secret_basic", "none"]),
    authorizeParams: z.record(z.string().regex(/^[A-Za-z0-9_.-]{1,64}$/), z.string().max(200)).optional(),
    // The API hosts the access token may be sent to: the connection's binding.
    hosts: z.array(PublicHostSchema).min(1).max(CUSTOM_PROVIDER_LIMITS.hosts),
    // Absent: CUSTOM_PROVIDER_DEFAULT_INJECTION.
    injection: CustomInjectionSchema.optional(),
  })
  .superRefine((provider, ctx) => {
    const issue = (path: (string | number)[], message: string) => ctx.addIssue({ code: "custom", path, message })
    if (provider.clientAuth === "none" && provider.pkce !== "S256") issue(["pkce"], "A public client, with no secret, needs PKCE (S256).")
    if (new Set(provider.scopes).size !== provider.scopes.length) issue(["scopes"], "Each scope may appear once.")
    if (new Set(provider.hosts).size !== provider.hosts.length) issue(["hosts"], "Each host may appear once.")
    const params = Object.keys(provider.authorizeParams ?? {})
    if (params.length > CUSTOM_PROVIDER_LIMITS.authorizeParams) issue(["authorizeParams"], `At most ${CUSTOM_PROVIDER_LIMITS.authorizeParams} extra parameters.`)
    for (const name of params) {
      if ((RESERVED_AUTHORIZE_PARAMS as readonly string[]).includes(name.toLowerCase())) issue(["authorizeParams", name], `Mehen sets ${name} itself.`)
    }
  })
export type CustomOAuthProvider = z.infer<typeof CustomOAuthProviderSchema>

export function customProviderInjection(provider: CustomOAuthProvider): Injection {
  return provider.injection ?? CUSTOM_PROVIDER_DEFAULT_INJECTION
}

// Errors a token URL answers that end a sign-in, and that reject the client.
const CUSTOM_TERMINAL_ERRORS = ["invalid_grant"]
const CUSTOM_CLIENT_ERRORS = ["invalid_client", "unauthorized_client"]

// The definition in the shape the vault runs every OAuth flow and refresh
// with. A connect asks for every scope unless it names fewer, and a grant
// beyond the scopes asked for is refused, as for a catalogue provider.
export function customOAuthExchange(provider: CustomOAuthProvider): OAuthExchange {
  return {
    id: CUSTOM_OAUTH_PROVIDER_ID,
    displayName: provider.name,
    auth: {
      kind: "oauth2",
      authorizeUrl: provider.authorizeUrl,
      tokenUrl: provider.tokenUrl,
      pkce: provider.pkce === "S256" ? "S256" : "unsupported",
      clientAuth: provider.clientAuth,
      tokenRequestFormat: "form",
      scopes: { separator: provider.scopeSeparator ?? " ", param: "scope", identity: [], identityScopes: [], defaults: [...provider.scopes], allowed: [...provider.scopes] },
      ...(provider.authorizeParams ? { authorizeParams: { ...provider.authorizeParams } } : {}),
      tokenResponse: { accessToken: "access_token", refreshToken: "refresh_token", expiresIn: "expires_in", grantedScopes: "scope" },
    },
    identity: null,
    upstream: { baseUrl: `https://${provider.hosts[0] ?? ""}`, binding: { hosts: [...provider.hosts] }, injection: customProviderInjection(provider) },
    refresh: { mode: "refresh_token", rotation: "lenient", marginSeconds: 60, terminalErrors: CUSTOM_TERMINAL_ERRORS, clientErrors: CUSTOM_CLIENT_ERRORS },
  }
}

// The binding of an oauth-client item carrying this definition: its secret
// may go only to the token URL, by POST.
export function customClientBinding(provider: CustomOAuthProvider): BindingInput {
  const url = new URL(provider.tokenUrl)
  return { hosts: [url.hostname], paths: [url.pathname], methods: ["POST"] }
}
