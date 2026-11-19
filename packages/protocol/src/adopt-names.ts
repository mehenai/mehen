// What `mehen adopt` proposes for a variable by its name alone: the template
// and field for a provider's conventional name, else a kind from the name's
// shape. A name only proposes; the plan and the person reviewing the batch
// decide.

import type { ItemKind } from "./kinds.ts"

export type EnvNameTemplate = { template: string; kind: ItemKind; field: string }

const key = (template: string): EnvNameTemplate => ({ template, kind: "api-key", field: "key" })
const basic = (template: string, field: "username" | "password"): EnvNameTemplate => ({ template, kind: "basic-auth", field })
const oauthClient = (template: string, field: "client_id" | "client_secret"): EnvNameTemplate => ({ template, kind: "oauth-client", field })

// Exact variable names, as the provider's own docs and SDKs spell them.
export const ENV_NAME_TEMPLATES: Readonly<Record<string, EnvNameTemplate>> = {
  OPENAI_API_KEY: key("openai"),
  ANTHROPIC_API_KEY: key("anthropic"),
  GITHUB_TOKEN: key("github-pat"),
  GH_TOKEN: key("github-pat"),
  GITHUB_PAT: key("github-pat"),
  GITHUB_PERSONAL_ACCESS_TOKEN: key("github-pat"),
  CLOUDFLARE_API_TOKEN: key("cloudflare-api-token"),
  CF_API_TOKEN: key("cloudflare-api-token"),
  LINEAR_API_KEY: key("linear"),
  STRIPE_SECRET_KEY: key("stripe"),
  STRIPE_API_KEY: key("stripe"),
  SLACK_BOT_TOKEN: key("slack-bot"),
  GEMINI_API_KEY: key("google-gemini"),
  GOOGLE_GENERATIVE_AI_API_KEY: key("google-gemini"),
  MISTRAL_API_KEY: key("mistral"),
  GROQ_API_KEY: key("groq"),
  OPENROUTER_API_KEY: key("openrouter"),
  TOGETHER_API_KEY: key("together"),
  DEEPSEEK_API_KEY: key("deepseek"),
  XAI_API_KEY: key("xai"),
  HF_TOKEN: key("huggingface"),
  HUGGING_FACE_HUB_TOKEN: key("huggingface"),
  REPLICATE_API_TOKEN: key("replicate"),
  OLLAMA_API_KEY: key("ollama-cloud"),
  SNYK_TOKEN: key("snyk"),
  VERCEL_TOKEN: key("vercel"),
  FLY_API_TOKEN: key("fly"),
  RAILWAY_API_TOKEN: key("railway"),
  RENDER_API_KEY: key("render"),
  NPM_TOKEN: key("npm"),
  NOTION_API_KEY: key("notion"),
  NOTION_TOKEN: key("notion"),
  GITBOOK_API_TOKEN: key("gitbook"),
  GITBOOK_TOKEN: key("gitbook"),
  FATHOM_API_KEY: key("fathom"),
  SENTRY_AUTH_TOKEN: key("sentry"),
  POSTHOG_PERSONAL_API_KEY: key("posthog"),
  BETTERSTACK_API_TOKEN: key("betterstack-uptime"),
  BETTERUPTIME_API_TOKEN: key("betterstack-uptime"),
  HCLOUD_TOKEN: key("hetzner-cloud"),
  SCW_SECRET_KEY: key("scaleway"),
  NEON_API_KEY: key("neon"),
  SUPABASE_ACCESS_TOKEN: key("supabase"),
  PLANETSCALE_SERVICE_TOKEN: basic("planetscale", "password"),
  PLANETSCALE_SERVICE_TOKEN_ID: basic("planetscale", "username"),
  UPSTASH_API_KEY: basic("upstash", "password"),
  UPSTASH_EMAIL: basic("upstash", "username"),
  DIGITALOCEAN_ACCESS_TOKEN: key("digitalocean"),
  HUBSPOT_ACCESS_TOKEN: key("hubspot-private-app"),
  INTERCOM_ACCESS_TOKEN: key("intercom"),
  RESEND_API_KEY: key("resend"),
  POSTMARK_SERVER_TOKEN: key("postmark-server"),
  LOOPS_API_KEY: key("loops"),
  BRAVE_API_KEY: key("brave-search"),
  BRAVE_SEARCH_API_KEY: key("brave-search"),
  SERPAPI_API_KEY: key("serpapi"),
  SERPAPI_KEY: key("serpapi"),
  SEMRUSH_API_KEY: key("semrush"),
  FIRECRAWL_API_KEY: key("firecrawl"),
  BROWSERBASE_API_KEY: key("browserbase"),
  ELEVENLABS_API_KEY: key("elevenlabs"),
  HEYGEN_API_KEY: key("heygen"),
  GOOGLE_CLIENT_ID: oauthClient("google-oauth-client", "client_id"),
  GOOGLE_CLIENT_SECRET: oauthClient("google-oauth-client", "client_secret"),
  GITHUB_CLIENT_ID: oauthClient("github-oauth-client", "client_id"),
  GITHUB_CLIENT_SECRET: oauthClient("github-oauth-client", "client_secret"),
  AZURE_CLIENT_ID: oauthClient("microsoft-oauth-client", "client_id"),
  AZURE_CLIENT_SECRET: oauthClient("microsoft-oauth-client", "client_secret"),
}

// A kind for a name with no template; the first matching rule wins, so the
// specific shapes come before the broad ones.
export type EnvNameKindRule = { pattern: RegExp; kind: ItemKind; field: string; rule: string }

export const ENV_NAME_KIND_RULES: readonly EnvNameKindRule[] = [
  { pattern: /(^|_)(DATABASE|DB|POSTGRES|POSTGRESQL|PG|MYSQL|MARIADB|MONGO|MONGODB|REDIS|VALKEY|AMQP|RABBITMQ)(_[A-Z0-9]+)*_URL$/, kind: "database-url", field: "url", rule: "a database or queue URL" },
  { pattern: /^(DATABASE|POSTGRES|MYSQL|MONGO|MONGODB|REDIS)_URI$/, kind: "database-url", field: "url", rule: "a database URI" },
  { pattern: /^(?!(NEXT_PUBLIC_)?SENTRY_)\w*_DSN$/, kind: "database-url", field: "url", rule: "a DSN" },
  { pattern: /(^|_)SECRET_ACCESS_KEY$/, kind: "cloud-access-key", field: "secret_access_key", rule: "a cloud secret access key" },
  { pattern: /(^|_)ACCESS_KEY_ID$/, kind: "cloud-access-key", field: "access_key_id", rule: "a cloud access key id" },
  { pattern: /(^|_)(WEBHOOK|SIGNING)_SECRET$/, kind: "hmac-key", field: "key", rule: "a webhook or signing secret" },
  { pattern: /^(SMTP|IMAP|MAIL|EMAIL|EMAIL_HOST)_(PASSWORD|PASS)$/, kind: "smtp-imap", field: "password", rule: "a mail server password" },
  { pattern: /^(SMTP|IMAP|MAIL|EMAIL)_(USER|USERNAME)$/, kind: "smtp-imap", field: "username", rule: "a mail server user" },
  { pattern: /^(SMTP|IMAP|MAIL|EMAIL)_HOST$/, kind: "smtp-imap", field: "host", rule: "a mail server host" },
  { pattern: /(^|_)SSH_(PRIVATE_)?KEY$/, kind: "ssh-key", field: "private_key", rule: "an SSH private key" },
  { pattern: /(^|_)SERVICE_ACCOUNT(_KEY)?_JSON$|(^|_)SERVICE_ACCOUNT_KEY$|^GOOGLE_APPLICATION_CREDENTIALS_JSON$/, kind: "google-service-account", field: "key_json", rule: "a Google service account key" },
  { pattern: /(^|_)PRIVATE_KEY$/, kind: "file", field: "content", rule: "a private key" },
  { pattern: /^(SESSION_SECRET|NEXTAUTH_SECRET|AUTH_SECRET|JWT_SECRET|SECRET_KEY_BASE|SECRET_KEY|APP_KEY|APP_SECRET)$|(^|_)(ENCRYPTION|CRYPTO|COOKIE)_(KEY|SECRET)$/, kind: "generic", field: "value", rule: "an application secret" },
  { pattern: /(^|_)(PASSWORD|PASSWD|PASS)$/, kind: "generic", field: "value", rule: "a password" },
  { pattern: /(^|_)(API_KEY|APIKEY|API_TOKEN|ACCESS_TOKEN|AUTH_TOKEN|TOKEN)$/, kind: "api-key", field: "key", rule: "an API key or token without a template" },
  { pattern: /(^|_)(SECRET|KEY)$/, kind: "generic", field: "value", rule: "a secret without a known shape" },
]

// Names that are public by convention: bundled into a browser build, or the
// public half of a key pair. Their values are config, not secrets.
const PUBLIC_NAME = /^(NEXT_PUBLIC|VITE|PUBLIC)_|(^|_)(PUBLIC|PUBLISHABLE)_KEY$/

export type EnvNameProposal = { template: string | null; kind: ItemKind; field: string; rule: string }

export function envNameProposal(name: string): EnvNameProposal | null {
  if (PUBLIC_NAME.test(name)) return null
  const known = Object.hasOwn(ENV_NAME_TEMPLATES, name) ? ENV_NAME_TEMPLATES[name] : undefined
  if (known) return { ...known, rule: `the ${known.template} variable name` }
  const rule = ENV_NAME_KIND_RULES.find((r) => r.pattern.test(name))
  return rule ? { template: null, kind: rule.kind, field: rule.field, rule: rule.rule } : null
}
