// Provider templates: data, never code. A template fixes where a credential
// may go (binding), how it is put into a request (injection), the default
// policy with its sensitive endpoints, and hints for the intake form. A
// human picks a template; an agent can only name one.
//
// Each template and OAuth provider is one file in templates/, named by its
// id and exporting one object, registered below; the helpers they share
// are in templates/shared.ts. The order of TEMPLATES and OAUTH_PROVIDERS
// is the order `mehen templates` and the docs list them in.
//
// Policies are fail-closed. For an API that can write, the default is
// "approve": reads (GET, HEAD) are allowed where the provider's reads are
// safe, a few explicit allow rules name the everyday writes an agent may
// make without a human, and deny rules keep the routes no human should
// approve casually. A write route nobody thought of therefore needs an
// approval instead of slipping through. Approve rules that repeat the
// default pin the sends and money movements, so a broad allow rule added
// later cannot open them (approve beats allow).
//
// OAuth providers (OAUTH_PROVIDERS, below): every URL the vault sends a
// client secret, a code or a token to is fixed here, never by a request.

import type { BindingInput, Injection, PolicyInput } from "./api.ts"
import type { BodyMatcher } from "./body-match.ts"
import type { ItemKind, Mode } from "./kinds.ts"
import { anthropic } from "./templates/anthropic.ts"
import { betterstackUptime } from "./templates/betterstack-uptime.ts"
import { braveSearch } from "./templates/brave-search.ts"
import { browserbase } from "./templates/browserbase.ts"
import { cloudflareApiToken } from "./templates/cloudflare-api-token.ts"
import { elevenlabs } from "./templates/elevenlabs.ts"
import { fathom } from "./templates/fathom.ts"
import { firecrawl } from "./templates/firecrawl.ts"
import { fly } from "./templates/fly.ts"
import { gitbook } from "./templates/gitbook.ts"
import { githubOauth } from "./templates/github-oauth.ts"
import { githubOauthClient } from "./templates/github-oauth-client.ts"
import { githubPat } from "./templates/github-pat.ts"
import { googleCalendar } from "./templates/google-calendar.ts"
import { googleDrive } from "./templates/google-drive.ts"
import { googleGemini } from "./templates/google-gemini.ts"
import { googleGmail } from "./templates/google-gmail.ts"
import { googleOauthClient } from "./templates/google-oauth-client.ts"
import { groq } from "./templates/groq.ts"
import { hetznerCloud } from "./templates/hetzner-cloud.ts"
import { heygen } from "./templates/heygen.ts"
import { hubspotPrivateApp } from "./templates/hubspot-private-app.ts"
import { intercom } from "./templates/intercom.ts"
import { linear } from "./templates/linear.ts"
import { loops } from "./templates/loops.ts"
import { microsoftGraph } from "./templates/microsoft-graph.ts"
import { microsoftOauthClient } from "./templates/microsoft-oauth-client.ts"
import { mistral } from "./templates/mistral.ts"
import { neon } from "./templates/neon.ts"
import { notion } from "./templates/notion.ts"
import { npm } from "./templates/npm.ts"
import { ollamaCloud } from "./templates/ollama-cloud.ts"
import { openai } from "./templates/openai.ts"
import { openrouter } from "./templates/openrouter.ts"
import { posthog } from "./templates/posthog.ts"
import { postmarkServer } from "./templates/postmark-server.ts"
import { resend } from "./templates/resend.ts"
import { scaleway } from "./templates/scaleway.ts"
import { semrush } from "./templates/semrush.ts"
import { sentry } from "./templates/sentry.ts"
import { serpapi } from "./templates/serpapi.ts"
import { slackBot } from "./templates/slack-bot.ts"
import { snyk } from "./templates/snyk.ts"
import { stripe } from "./templates/stripe.ts"
import { together } from "./templates/together.ts"
import { vercel } from "./templates/vercel.ts"

export { CLIENT_SETUP_CALLBACK } from "./templates/shared.ts"

export type FieldHint = { label?: string; hint?: string; pattern?: string; multiline?: boolean }

// One step of a guided setup on the intake page. Text only: the page adds
// the template's docsUrl as a link where `docs` is set, the vault's own
// redirect URI in a copy box where `redirectUri` is set, and marks the
// step and every one before it done once the named `field` is filled in.
export type SetupStep = {
  title: string
  body: string
  warn?: string
  docs?: true
  redirectUri?: true
  field?: string
}

// `title` heads the steps ("In Google Cloud"); `redirectUri` is the path
// on the vault the provider must be given, which the server joins to
// VAULT_ORIGIN.
export type Setup = { title: string; steps: SetupStep[]; redirectUri?: string }

// How a person creates their own OAuth app at a provider, for a platform's
// page to show beside the client id and secret form (platform.ts). Trusted
// data: a short title, one or two sentences, and the console page to open
// where there is one. CLIENT_SETUP_CALLBACK (templates/shared.ts) stands
// for the platform's own callback URL, which the page puts in before
// showing the step.
export type ClientSetupStep = { title: string; body: string; consoleUrl?: string }

// Where a template or OAuth provider is listed: the sections of Connect a
// service and of `mehen templates`, in this order.
export type TemplateCategory = "mail" | "ai" | "code" | "productivity" | "observability" | "infrastructure" | "customers" | "search" | "clients"

export const TEMPLATE_CATEGORIES: readonly { id: TemplateCategory; title: string }[] = [
  { id: "mail", title: "Mail, calendar and files" },
  { id: "ai", title: "AI models" },
  { id: "code", title: "Code and deploy" },
  { id: "productivity", title: "Productivity and chat" },
  { id: "observability", title: "Observability" },
  { id: "infrastructure", title: "Infrastructure and data" },
  { id: "customers", title: "Payments, CRM and email" },
  { id: "search", title: "Search, web and media" },
  { id: "clients", title: "OAuth clients" },
]

export type Template = {
  id: string
  displayName: string
  kind: ItemKind
  category: TemplateCategory
  docsUrl: string | null
  binding: BindingInput
  injection: Injection | null
  policy: PolicyInput
  ceiling: Mode
  fields: Record<string, FieldHint>
  // Well-known value prefixes; the intake form warns when a value lacks one.
  prefixes?: string[]
  // A cheap read-only call that proves an item works (`mehen adopt verify`),
  // sent through relay to the binding's first host; never a write.
  check?: TemplateCheck
  // A guided setup the intake page renders as numbered steps.
  setup?: Setup
  // OAuth client templates only: the steps for a platform's page.
  clientSetup?: ClientSetupStep[]
}

export type TemplateCheck = { method: "GET" | "HEAD"; path: string; headers?: [string, string][] }

export const TEMPLATES: Record<string, Template> = {
  openai,
  anthropic,
  "github-pat": githubPat,
  "cloudflare-api-token": cloudflareApiToken,
  linear,
  stripe,
  "slack-bot": slackBot,
  "google-gemini": googleGemini,
  mistral,
  groq,
  openrouter,
  together,
  "ollama-cloud": ollamaCloud,
  snyk,
  vercel,
  fly,
  npm,
  notion,
  gitbook,
  fathom,
  sentry,
  posthog,
  "betterstack-uptime": betterstackUptime,
  "hetzner-cloud": hetznerCloud,
  scaleway,
  neon,
  "hubspot-private-app": hubspotPrivateApp,
  intercom,
  resend,
  "postmark-server": postmarkServer,
  loops,
  "brave-search": braveSearch,
  serpapi,
  semrush,
  firecrawl,
  browserbase,
  elevenlabs,
  heygen,
  "google-oauth-client": googleOauthClient,
  "github-oauth-client": githubOauthClient,
  "microsoft-oauth-client": microsoftOauthClient,
}

export function getTemplate(id: string): Template | null {
  return Object.hasOwn(TEMPLATES, id) ? (TEMPLATES[id] as Template) : null
}

// ---------------------------------------------------------------- OAuth providers

// A dotted path into a JSON object: "authed_user.access_token".
export type JsonPath = string

export type OAuth2Auth = {
  kind: "oauth2"
  authorizeUrl: string
  // Checked against the client item's binding before the secret is sent.
  tokenUrl: string
  revokeUrl?: string
  pkce: "S256" | "unsupported"
  // "none" is a public client, which sends its client id and no secret
  // (custom providers only, always with PKCE).
  clientAuth: "client_secret_basic" | "client_secret_post" | "none"
  tokenRequestFormat: "form" | "json"
  scopes: {
    separator: " " | ","
    param: "scope"
    // Always requested, so the identity probe works.
    identity: string[]
    // Asks for a refresh token where the provider wants a scope for it.
    offline?: string
    // Every scope the provider may report back for signing in and staying
    // signed in: the identity scopes, the offline scope, and the long forms
    // the provider substitutes for them. A granted scope that is neither in
    // this list nor an allowed scope that was asked for is a wider grant,
    // which the vault refuses to store (server, oauth.ts grantedBeyond).
    identityScopes: string[]
    // What a connect asks for when it names no scopes: enough for an agent
    // to do its job, because the policy, not the scope, holds the writes.
    defaults: string[]
    // The only scopes a connect request may ask for.
    allowed: string[]
    // Lets "gmail.modify" stand for "https://www.googleapis.com/auth/gmail.modify".
    shortPrefix?: string
  }
  authorizeParams?: Record<string, string>
  accountHint?: { param: string }
  tokenResponse: {
    okFlag?: { path: JsonPath; equals: boolean }
    accessToken: JsonPath
    refreshToken?: JsonPath
    expiresIn?: JsonPath
    refreshTokenExpiresIn?: JsonPath
    grantedScopes?: JsonPath
    idToken?: JsonPath
  }
}

export type IdentityProbe = {
  // id_token: read from the token response, which came straight from the
  // token endpoint over TLS (OpenID Connect Core 3.1.3.7).
  from: "id_token" | "request"
  request?: { method: "GET"; url: string; headers?: Record<string, string> }
  subject: JsonPath // stable id, never an email
  tenant?: JsonPath
  label: JsonPath // email or login, for humans
}

export type Upstream = {
  baseUrl: string
  binding: BindingInput // nothing else is ever reachable
  injection: Injection
}

export type RefreshPolicy = {
  mode: "refresh_token" | "never_expires"
  rotation: "none" | "lenient" | "strict" | "grace"
  replayGraceSeconds?: number
  marginSeconds: number
  terminalErrors: string[]
  clientErrors: string[]
}

export type Lifetimes = {
  accessTokenSeconds?: number
  refreshTokenIdleSeconds?: number
  refreshTokenAbsoluteSeconds?: number
  liveRefreshTokensPerClient?: number
  testingModeRefreshSeconds?: number
}

export type SensitiveEndpoint = { action: "approve" | "deny"; methods?: string[]; paths: string[]; body?: BodyMatcher; why: string }

export type OAuthProviderTemplate = {
  id: string
  family: string // "google": shares an OAuth client and an identity probe
  displayName: string
  category: TemplateCategory
  docsUrl: string
  // The template id the oauth-client item must have been created from.
  clientTemplate: string
  auth: OAuth2Auth
  identity: IdentityProbe
  upstream: Upstream
  refresh: RefreshPolicy
  lifetimes: Lifetimes
  defaultPolicy: PolicyInput
  sensitiveEndpoints: SensitiveEndpoint[]
}

export const OAUTH_PROVIDERS: Record<string, OAuthProviderTemplate> = {
  "google-gmail": googleGmail,
  "google-calendar": googleCalendar,
  "google-drive": googleDrive,
  "github-oauth": githubOauth,
  "microsoft-graph": microsoftGraph,
}

export function getOAuthProvider(id: string): OAuthProviderTemplate | null {
  return Object.hasOwn(OAUTH_PROVIDERS, id) ? (OAUTH_PROVIDERS[id] as OAuthProviderTemplate) : null
}

// The policy a new connection gets: the default rules plus every sensitive
// endpoint, combined deny over approve over allow by evaluatePolicy.
export function connectionPolicy(provider: OAuthProviderTemplate): PolicyInput {
  return {
    default: provider.defaultPolicy.default,
    rules: [
      ...provider.defaultPolicy.rules,
      ...provider.sensitiveEndpoints.map((e) => ({ action: e.action, paths: e.paths, ...(e.methods ? { methods: e.methods } : {}), ...(e.body ? { body: e.body } : {}), note: e.why })),
    ],
  }
}

// "gmail.modify" or the full URL; null when the scope is not allowed.
export function normaliseScope(provider: Pick<OAuthProviderTemplate, "auth">, scope: string): string | null {
  const { allowed, shortPrefix } = provider.auth.scopes
  if (allowed.includes(scope)) return scope
  if (shortPrefix !== undefined && allowed.includes(shortPrefix + scope)) return shortPrefix + scope
  return null
}

// ---------------------------------------------------------------- custom providers

// The provider a connection made with a custom provider's definition is
// recorded under in a connect flow. Never a catalogue id.
export const CUSTOM_OAUTH_PROVIDER_ID = "custom"

// What the vault needs to run an OAuth flow and refresh it: a catalogue
// provider, or a custom provider's definition in the same shape
// (custom-provider.ts customOAuthExchange). A custom provider has no
// identity probe, so its connections name no provider account.
export type OAuthExchange = Pick<OAuthProviderTemplate, "id" | "displayName" | "auth" | "upstream" | "refresh"> & { identity: IdentityProbe | null }
