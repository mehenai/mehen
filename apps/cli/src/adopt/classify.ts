// What a value read by adopt is, decided in memory from its name and the
// value itself: a secret (with the kind, template and field it would fill),
// plain config, or unknown. The result names the rule that decided it and
// never carries the value or anything derived from it but a well-known
// prefix and whether the value is a live (production) key.

import { envNameProposal } from "@mehen/protocol/adopt-names"
import { type ItemKind, KINDS } from "@mehen/protocol/kinds"
import { secretPrefix } from "@mehen/protocol/placeholder"
import { secretLikeness } from "@mehen/protocol/secret-likeness"
import { TEMPLATES, getTemplate } from "@mehen/protocol/templates"
import { dockerRegistry } from "./parse.ts"
import type { SourceType } from "./sources.ts"

export type SourceClass = "secret" | "config" | "unknown"
// new: proposed for adoption. unsupported: cannot be adopted, with why.
// dynamic: a line that computes its value; never read. skipped: left
// alone by rule (decision 8, an empty value). connector: an OAuth login or
// token, never uploaded: a connection made once with mehen connect takes
// its place, its provider the template it uses (null when none fits).
export type SourceStatus = "new" | "unsupported" | "dynamic" | "skipped" | "connector"

export type Classification = {
  class: SourceClass
  kind: ItemKind | null
  provider: string | null
  field: string | null
  reason: string
  status: SourceStatus
  // Why a status other than new, or why an item is stored only.
  why: string | null
  storeOnly: string | null
  // A secret whose shape marks it as a production key.
  liveKey: boolean
}

type Decision = Omit<Classification, "liveKey">

// path: the file read; a key read whole from .local-secrets is named by it.
export type ClassifyInput = { type: SourceType; variable: string | null; pointer: string | null; value: string | null; path?: string }

const TEMPLATE_BY_PREFIX: [string, string][] = Object.values(TEMPLATES)
  .flatMap((t) => (t.prefixes ?? []).map((p): [string, string] => [p, t.id]))
  .sort((a, b) => b[0].length - a[0].length)

// Prefixes other services use too: Stripe's sk_live_ and sk_test_ are
// WorkOS's and Clerk's, and OpenAI's sk- is LiteLLM's and many gateways'.
// One names its template only when the variable name names no service, or
// that one.
const SHARED_PREFIXES = new Set(["sk-", "sk_live_", "sk_test_", "rk_live_", "rk_test_"])
const KEY_SUFFIX = /(^|_)(SECRET_KEY|API_KEY|APIKEY|API_TOKEN|ACCESS_TOKEN|AUTH_TOKEN|TOKEN|SECRET|KEY)$/

function nameAgrees(upper: string | null, template: string): boolean {
  if (upper === null) return true
  const word = (template.split("-")[0] ?? template).toUpperCase()
  return upper.split("_").includes(word) || upper.replace(KEY_SUFFIX, "") === ""
}

const STORE_ONLY: Partial<Record<ItemKind, string>> = {
  "hmac-key": "signing is not built; stored only until a human raises it to lease",
  "ssh-key": "SSH signing is not built; stored only",
  "google-service-account": "token minting is not built; stored only",
}

function secret(kind: ItemKind, field: string, reason: string, provider: string | null = null): Decision {
  return { class: "secret", kind, provider, field, reason, status: "new", why: null, storeOnly: STORE_ONLY[kind] ?? null }
}

function other(cls: SourceClass, reason: string, status: SourceStatus = "new", why: string | null = null): Decision {
  return { class: cls, kind: null, provider: null, field: null, reason, status, why, storeOnly: null }
}

// `oauth`: an OAuth token a connection replaces (kind oauth-connection),
// even when no provider fits; a CLI login with no connection is not one.
function connector(provider: string | null, reason: string, why: string, oauth = true): Decision {
  return { class: "secret", kind: oauth ? "oauth-connection" : null, provider, field: null, reason, status: "connector", why, storeOnly: null }
}

// A Google OAuth token: a refresh token (1//) or an access token (ya29.),
// or a refresh token by its name. The service its name says is its
// provider; a name that says none gets no provider, never a guess.
const GOOGLE_TOKEN_PREFIXES = ["1//", "ya29."]
const GOOGLE_NAME = /(^|_)(GOOGLE|GMAIL|GCAL|GDRIVE)(_|$)/
const GOOGLE_SERVICES: [RegExp, string][] = [
  [/(^|_)GMAIL(_|$)/, "google-gmail"],
  [/(^|_)(CALENDAR|GCAL)(_|$)/, "google-calendar"],
  [/(^|_)(DRIVE|GDRIVE)(_|$)/, "google-drive"],
]

// `names`: the name as written and in snake case (gmailRefreshToken).
function googleToken(names: readonly string[], value: string): Decision | null {
  const shaped = GOOGLE_TOKEN_PREFIXES.some((p) => value.startsWith(p) && value.length > p.length + 16)
  const named = names.some((n) => /(^|_)REFRESH_TOKEN$/.test(n) && GOOGLE_NAME.test(n))
  if (!shaped && !named) return null
  const provider = GOOGLE_SERVICES.find(([pattern]) => names.some((n) => pattern.test(n)))?.[1] ?? null
  return connector(provider, "a Google OAuth token", provider === null ? "a Google OAuth token for a service its name does not say: connect the Google service it uses; the vault never imports a token" : `a Google OAuth token: connect ${provider} once instead; the vault never imports a token`)
}

function templateSecret(template: string, reason: string): Decision {
  const t = getTemplate(template)
  const kind = (t?.kind ?? "api-key") as ItemKind
  const field = KINDS[kind].primary ?? KINDS[kind].fields.find((f) => f.secret)?.name ?? "value"
  return secret(kind, field, reason, template)
}

function urlWithPassword(value: string): boolean {
  try {
    const url = new URL(value)
    return url.password !== ""
  } catch {
    return false
  }
}

function isServiceAccount(value: string): boolean {
  try {
    return (JSON.parse(value) as { type?: unknown }).type === "service_account"
  } catch {
    return false
  }
}

const PUBLIC_NAME = /^(NEXT_PUBLIC|VITE|PUBLIC|EXPO_PUBLIC|REACT_APP)_|(^|_)(PUBLIC|PUBLISHABLE)_KEY$/
const CONFIG_NAME = /(_URL|_URI|_HOST|_HOSTNAME|_PORT|_REGION|_ENV|_MODE|_LEVEL|_NAME|_PATH|_DIR|_FILE|_ID|_VERSION|_DOMAIN|_BUCKET|_EMAIL|_PROJECT|_TEAM|_ORG|_USER|_IP|_IPS|_IPV6|_CIDR|_CIDRS|_SUBNET|_ENDPOINT|_ENDPOINTS|_BRANCH|_AUDIENCE|_AUDIENCES|_KEYRING|_BACKEND)$|^(LOG_LEVEL|NODE_ENV|PORT|HOST|TZ|DEBUG|ENVIRONMENT|APP_ENV|PATH|HOME|SHELL|USER|LANG|TMPDIR|DOMAIN|PROVIDER|REGION|VERSION)$/

// Ids, orderings and model names: long and random-looking, but config,
// unless a secret's name rule also matches (LLM_MODEL_PASSWORD is a
// password). CLIENT_ID is not one: it is half of an OAuth client.
const CONFIG_ID_NAME = /(_PRICE_ID|_TEMPLATE_ID|_ORG_ID|(^|_)ORGANI[SZ]ATION_ID|_PROJECT_ID|_MODEL|_ORDERING|_ORDER)$|_MODEL_/
// A reCAPTCHA site key is public, though its name ends in _KEY.
const SITE_KEY_NAME = /_SITE_KEY(_V2)?$/
// A Firebase web app's API key ships in every page that uses it: public by
// Firebase's design, and only when the name says Firebase. A bare
// GOOGLE_API_KEY of the same shape may unlock a paid API. Its AIza shape
// looks like a secret, so the vault refuses it as a plain value: it is a
// generic secret, not a Gemini item, which mehen run delivers.
const FIREBASE_WEB_KEY_NAME = /^FIREBASE_WEB_API_KEY$|_FIREBASE_API_KEY$|^NEXT_PUBLIC_FIREBASE_/
const GOOGLE_API_KEY_SHAPE = /^AIza[0-9A-Za-z_-]{35}$/
// A Cloud KMS key's resource name, not the key.
const KMS_KEY_NAME = /^projects\/\S+\/keyRings\/[^/\s]+\/cryptoKeys\/\S+$/

// Prefixes a provider documents for its live keys only. Stripe: secret
// keys are sk_live_ or sk_test_, restricted keys rk_live_ or rk_test_
// (https://docs.stripe.com/keys). A webhook secret's whsec_ says nothing
// about the mode, so it is not one. No other template's format tells live
// from test.
const LIVE_KEY_PREFIXES = ["sk_live_", "rk_live_"]

function liveKeyShaped(value: string): boolean {
  return LIVE_KEY_PREFIXES.some((p) => value.startsWith(p) && value.length > p.length + 8)
}

// A value whose own shape is a secret's, whatever its name.
function secretShaped(value: string): boolean {
  if (TEMPLATE_BY_PREFIX.some(([p]) => value.startsWith(p) && value.length > p.length + 8)) return true
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(value) || isServiceAccount(value) || urlWithPassword(value)) return true
  const known = secretPrefix(value)
  return Boolean(known) && value.length > known.length + 8
}

// A value no secret looks like: a flag, a number, a version, an email
// address, an IP address or range. Checked only after every secret signal.
function configShaped(value: string): boolean {
  return /^(true|false|yes|no|on|off|0|1)$/i.test(value) || /^-?\d{1,6}$/.test(value) || /^v?\d+\.\d+(\.\d+)?(-[0-9A-Za-z.]+)?$/.test(value) || /^[^@\s:/]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(value) || /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?(,(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?)*$/.test(value)
}

// A settings key as a variable name: tokenEnvFile is TOKEN_ENV_FILE.
function snakeName(name: string): string {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toUpperCase()
}

function nameOf(input: ClassifyInput): string | null {
  if (input.variable) return input.variable
  const last = input.pointer?.split("/").at(-1)
  if (last) return last.replaceAll("~1", "/").replaceAll("~0", "~")
  if (input.type === "secrets-file" && input.path) return fileStemName(input.path)
  return null
}

// istor-github-app.private-key.pem names ISTOR_GITHUB_APP_PRIVATE_KEY.
export function fileStemName(path: string): string {
  const name = path.split(/[\\/]/).at(-1) ?? ""
  const stem = name.includes(".") && !name.startsWith(".") ? name.slice(0, name.lastIndexOf(".")) : name
  return stem.replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "").toUpperCase()
}

export function classify(input: ClassifyInput): Classification {
  const c = decide(input)
  return { ...c, liveKey: c.class === "secret" && c.status === "new" && input.value !== null && liveKeyShaped(input.value) }
}

function decide(input: ClassifyInput): Decision {
  const { type, value } = input
  if (value === null) return other("unknown", "a line that computes its value", "dynamic", "dynamic: never read; move it by hand")
  if (type === "gcloud-adc") return connector(null, "gcloud application default credentials", "gcloud ADC is skipped (decision 8); it needs a re-auth anyway", false)
  if (type === "wrangler") return connector(null, "wrangler OAuth login", "wrangler OAuth tokens rotate (decision 8); adopt a cloudflare-api-token instead", false)
  if (type === "kubeconfig" || type === "talosconfig") {
    return { ...secret("file", "content", type === "kubeconfig" ? "a kubeconfig" : "a talosconfig"), storeOnly: `${type} uses client certificates; mTLS and file delivery are not built, so the file stays` }
  }
  if (type === "gh-hosts") return connector("github-oauth", "the gh login token", "the gh login stays in place; connect github-oauth once for the vault to use GitHub")
  if (type === "docker") {
    const registry = input.pointer ? dockerRegistry(input.pointer) : null
    if (!registry) return other("unknown", "a docker auth without a registry host", "unsupported", "the registry is not a host")
    return secret("basic-auth", input.pointer?.endsWith("/username") ? "username" : "password", `docker login for ${registry}`)
  }
  if (value === "") return other("unknown", "an empty value", "skipped", "empty")
  const name = nameOf(input)
  const upper = name && /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) ? name.toUpperCase() : null
  const google = googleToken(upper ? [upper, snakeName(name as string)] : [], value)
  if (google) return google
  const proposal = upper ? envNameProposal(upper) : null
  // Only the generic API key name rule gives way: a private key or a password stays a secret.
  const firebaseWebKey = upper !== null && FIREBASE_WEB_KEY_NAME.test(upper) && GOOGLE_API_KEY_SHAPE.test(value)
  if (firebaseWebKey && (proposal === null || (proposal.template === null && proposal.kind === "api-key"))) return secret("generic", "value", "a Firebase web key is public by design, stored as a generic secret so mehen run delivers it")
  if (upper && PUBLIC_NAME.test(upper)) return other("config", "a public name")
  if (proposal?.template) return secret(proposal.kind, proposal.field, proposal.rule, proposal.template)
  if (!secretShaped(value)) {
    if (upper) {
      const names = [upper, snakeName(name as string)]
      const secretName = proposal !== null || names.some((n) => envNameProposal(n) !== null)
      if (names.some((n) => SITE_KEY_NAME.test(n) || (!secretName && CONFIG_ID_NAME.test(n)))) return other("config", "an id, site key or model name")
    }
    if (KMS_KEY_NAME.test(value)) return other("config", "a KMS key name")
  }
  const prefix = TEMPLATE_BY_PREFIX.find(([p]) => value.startsWith(p) && value.length > p.length + 8)
  if (prefix && (!SHARED_PREFIXES.has(prefix[0]) || nameAgrees(upper, prefix[1]))) return templateSecret(prefix[1], `"${prefix[0]}" prefix`)
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(value)) {
    return /OPENSSH|SSH/.test(value) || (upper ?? "").includes("SSH") ? secret("ssh-key", "private_key", "PEM block") : secret("file", "content", "PEM block")
  }
  if (isServiceAccount(value)) return secret("google-service-account", "key_json", "service account JSON")
  if (proposal) return secret(proposal.kind, proposal.field, proposal.rule)
  if (urlWithPassword(value)) return secret("database-url", "url", "URL with a password")
  const known = secretPrefix(value)
  if (known && value.length > known.length + 8) return secret("api-key", "key", `"${known}" prefix`)
  const likeness = secretLikeness(value)
  if (likeness) return secret("generic", "value", likeness.replace(/^it /, "the value "))
  if (upper && (CONFIG_NAME.test(upper) || CONFIG_NAME.test(snakeName(name as string)))) return other("config", "a config name")
  if (configShaped(value)) return other("config", "a flag or a number")
  return other("unknown", "no secret signal and not a known config name")
}

// Whether a field of a kind is public (an access key id, a user name).
export function isPublicField(kind: ItemKind, field: string): boolean {
  return KINDS[kind].fields.some((f) => f.name === field && !f.secret)
}
