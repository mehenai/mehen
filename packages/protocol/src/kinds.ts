// The closed list of credential kinds. Each kind fixes its fields, which of
// them are secret, and the highest rung of the exposure ladder it may ever
// reach. New kinds arrive by code review, never from an agent or a request.

export type Mode = "relay" | "sign" | "mint" | "placeholder" | "fill" | "lease" | "reveal"

// Lowest exposure first. A ceiling of "placeholder" allows relay, sign,
// mint and placeholder, never fill, lease or reveal to a device.
export const MODES: readonly Mode[] = ["relay", "sign", "mint", "placeholder", "fill", "lease", "reveal"]

export function modeRank(mode: Mode): number {
  return MODES.indexOf(mode)
}

export function modeAllowed(ceiling: Mode, wanted: Mode): boolean {
  return modeRank(wanted) <= modeRank(ceiling)
}

// What a device may get under an item's ceiling. Reveal is for humans only,
// so a reveal ceiling (raised to let a human view a password or a note)
// never widens what a device gets: a device fills only under a ceiling of
// exactly "fill" or "lease", leases only under exactly "lease", and never
// gets reveal.
export function deviceModeAllowed(ceiling: Mode, wanted: Mode): boolean {
  if (wanted === "reveal") return false
  if (wanted === "lease") return ceiling === "lease"
  if (wanted === "fill") return ceiling === "fill" || ceiling === "lease"
  return modeAllowed(ceiling, wanted)
}

export type FieldSpec = {
  name: string
  secret: boolean
  required: boolean
  label: string
  multiline?: boolean
}

// A value fill may type into a web page: `name` is what a fill asks for,
// `source` the stored field it comes from (a one-time code is computed from
// its seed), `input` the kind of page field it may go into. Sign-in fields
// go only to the item's sign-in pages; the others only to pages a human
// listed for typing into another service.
export type FillInput = "username" | "password" | "one-time-code" | "secret"
export type FillFieldSpec = { name: string; source: string; input: FillInput; signIn: boolean }

export type KindSpec = {
  kind: ItemKind
  label: string
  fields: FieldSpec[]
  // The field placeholders and leases deliver by default.
  primary: string | null
  defaultCeiling: Mode
  maxCeiling: Mode
  // What fill may type; empty for a kind that is never typed into a page.
  fill: FillFieldSpec[]
}

export type ItemKind =
  | "api-key"
  | "bearer-token"
  | "basic-auth"
  | "custom-headers"
  | "oauth-client"
  | "oauth-connection"
  | "google-service-account"
  | "github-app"
  | "hmac-key"
  | "ssh-key"
  | "password-login"
  | "totp"
  | "database-url"
  | "smtp-imap"
  | "cloud-access-key"
  | "file"
  | "note"
  | "generic"

const f = (name: string, label: string, secret: boolean, required = true, multiline = false): FieldSpec => ({
  name,
  label,
  secret,
  required,
  ...(multiline ? { multiline } : {}),
})

// A kind's primary value typed into another service's page, never a sign-in.
const other = (name: string): FillFieldSpec[] => [{ name, source: name, input: "secret", signIn: false }]

export const KINDS: Record<ItemKind, KindSpec> = {
  "api-key": { kind: "api-key", label: "API key", fields: [f("key", "Key", true)], primary: "key", defaultCeiling: "placeholder", maxCeiling: "lease", fill: other("key") },
  "bearer-token": {
    kind: "bearer-token",
    label: "Bearer token",
    fields: [f("token", "Token", true), f("expires_at", "Expires at (ISO date)", false, false)],
    primary: "token",
    defaultCeiling: "placeholder",
    maxCeiling: "lease",
    fill: other("token"),
  },
  "basic-auth": {
    kind: "basic-auth",
    label: "Username and password (HTTP Basic)",
    fields: [f("username", "Username", false), f("password", "Password", true)],
    primary: "password",
    defaultCeiling: "relay",
    maxCeiling: "lease",
    fill: [],
  },
  "custom-headers": {
    kind: "custom-headers",
    label: "Several secret headers",
    fields: [f("headers", "Headers as JSON, name to value", true, true, true)],
    primary: null,
    defaultCeiling: "relay",
    maxCeiling: "relay",
    fill: [],
  },
  "oauth-client": {
    kind: "oauth-client",
    label: "OAuth client",
    fields: [f("client_id", "Client ID", false), f("client_secret", "Client secret", true)],
    primary: null,
    defaultCeiling: "relay",
    maxCeiling: "relay",
    fill: [],
  },
  "oauth-connection": {
    kind: "oauth-connection",
    label: "OAuth connection",
    fields: [f("access_token", "Access token", true), f("refresh_token", "Refresh token", true, false)],
    primary: "access_token",
    defaultCeiling: "relay",
    maxCeiling: "mint",
    fill: [],
  },
  "google-service-account": {
    kind: "google-service-account",
    label: "Google service account key",
    fields: [f("key_json", "Key JSON", true, true, true)],
    primary: null,
    defaultCeiling: "mint",
    maxCeiling: "mint",
    fill: [],
  },
  "github-app": {
    kind: "github-app",
    label: "GitHub App",
    fields: [f("app_id", "App ID", false), f("private_key", "Private key (PEM)", true, true, true)],
    primary: null,
    defaultCeiling: "mint",
    maxCeiling: "mint",
    fill: [],
  },
  "hmac-key": { kind: "hmac-key", label: "Signing secret (HMAC)", fields: [f("key", "Secret", true)], primary: "key", defaultCeiling: "sign", maxCeiling: "lease", fill: [] },
  "ssh-key": {
    kind: "ssh-key",
    label: "SSH private key",
    fields: [f("private_key", "Private key", true, true, true), f("public_key", "Public key", false, false)],
    primary: null,
    defaultCeiling: "sign",
    maxCeiling: "sign",
    fill: [],
  },
  "password-login": {
    kind: "password-login",
    label: "Website or app login",
    fields: [f("url", "Sign-in address", false), f("username", "Username", false), f("password", "Password", true), f("totp_seed", "One-time code secret", true, false)],
    primary: "password",
    defaultCeiling: "relay",
    maxCeiling: "reveal",
    fill: [
      { name: "username", source: "username", input: "username", signIn: true },
      { name: "password", source: "password", input: "password", signIn: true },
      { name: "totp", source: "totp_seed", input: "one-time-code", signIn: true },
    ],
  },
  totp: {
    kind: "totp",
    label: "One-time code secret (TOTP)",
    fields: [f("seed", "Secret or otpauth:// link", true)],
    primary: null,
    defaultCeiling: "relay",
    maxCeiling: "reveal",
    fill: [{ name: "code", source: "seed", input: "one-time-code", signIn: true }],
  },
  "database-url": { kind: "database-url", label: "Database connection string", fields: [f("url", "Connection string", true)], primary: "url", defaultCeiling: "lease", maxCeiling: "lease", fill: [] },
  "smtp-imap": {
    kind: "smtp-imap",
    label: "Mail server login",
    fields: [f("host", "Host", false), f("username", "Username", false), f("password", "Password", true)],
    primary: "password",
    defaultCeiling: "lease",
    maxCeiling: "lease",
    fill: [],
  },
  "cloud-access-key": {
    kind: "cloud-access-key",
    label: "Cloud access key (AWS, R2, S3)",
    fields: [f("access_key_id", "Access key ID", false), f("secret_access_key", "Secret access key", true)],
    primary: "secret_access_key",
    defaultCeiling: "lease",
    maxCeiling: "lease",
    fill: [],
  },
  file: { kind: "file", label: "Secret file", fields: [f("filename", "File name", false), f("content", "Contents", true, true, true)], primary: "content", defaultCeiling: "lease", maxCeiling: "lease", fill: [] },
  note: { kind: "note", label: "Secure note", fields: [f("text", "Note", true, true, true)], primary: null, defaultCeiling: "reveal", maxCeiling: "reveal", fill: [] },
  generic: { kind: "generic", label: "Other", fields: [f("value", "Value", true)], primary: "value", defaultCeiling: "lease", maxCeiling: "lease", fill: other("value") },
}

export function isItemKind(value: string): value is ItemKind {
  return Object.hasOwn(KINDS, value)
}

// Slugs name items, projects and connections: lower case, digits, dashes,
// 2 to 64 characters, starting with a letter.
export const SLUG = /^[a-z][a-z0-9-]{1,63}$/

export function isSlug(value: string): boolean {
  return SLUG.test(value) && !value.endsWith("-") && !value.includes("--")
}

// A reference names an item and optionally a field: mehen://openai-personal#key
export type Reference = { item: string; field: string | null }

export function parseReference(text: string): Reference | null {
  const match = /^mehen:\/\/([a-z][a-z0-9-]{1,63})(?:#([a-z][a-z0-9_]{0,63}))?$/.exec(text)
  if (!match || !isSlug(match[1] as string)) return null
  return { item: match[1] as string, field: match[2] ?? null }
}

export function formatReference(ref: Reference): string {
  return ref.field === null ? `mehen://${ref.item}` : `mehen://${ref.item}#${ref.field}`
}
