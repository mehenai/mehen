// OAuth connections. A device asks for a connect link; a
// signed-in member opens it, starts the flow (state in D1, PKCE verifier
// sealed here) and comes back through /oauth/callback; this area then
// exchanges the code with the client secret, only at the template's token
// URL and only if the client item's binding allows it, verifies who signed
// in, and stores the tokens as an oauth-connection item.
//
// Refresh is single-flight per connection: an in-memory promise per item,
// never blockConcurrencyWhile. The attempt is written ahead, so a crash
// mid-refresh leaves an explicit "uncertain" state, and new tokens are
// committed through items.replaceSecrets before any caller sees them.

import { z } from "zod"
import { ConnectCreate, type ConnectCreated, type ConnectStatus, type ConnectView, type IntakeCreated, type NextStep, Slug, Tag, canonicalJson } from "@mehen/protocol/api"
import {
  KINDS,
  type OAuthExchange,
  type OAuthProviderTemplate,
  base64UrlDecode,
  base64UrlEncode,
  checkBinding,
  connectionPolicy,
  getOAuthProvider,
  normaliseScope,
  OAUTH_PROVIDERS,
  parseDestination,
  sha256,
} from "@mehen/protocol"
import { randomToken, sha256Text } from "../../directory/session.ts"
import { VaultError } from "../../http.ts"
import { upstreamFetch } from "../../relay/upstream.ts"
import { type Area, type DevicePrincipal, type MemberPrincipal, type Principal, type Requester, type SystemPrincipal, type VaultContext, actorOf, blob, one, randomId } from "../core.ts"
import type { IntakeOutcome, ItemRecord, OAuthService } from "../services.ts"
import { checkedCredential, credentialOps } from "./items-workspace.ts"
import { platformOAuthOps, workspaceAccessToken, workspaceOAuthClientRejectionMigration, workspaceOAuthMigration, workspaceOAuthOps } from "./oauth-workspace.ts"
import { deviceCovers } from "./devices.ts"
import { managedWorkWaits } from "../managed-platform.ts"
import { MEMBER_REASON, intakes, requestedByOf, requesterOf } from "./intake.ts"
import { items } from "./items.ts"

const CONNECT_TTL_MS = 15 * 60_000
// An open connect with less than this left is not handed out again.
const REUSE_MARGIN_MS = 60_000
const SUPERSEDED_MESSAGE = "This link was replaced by a newer one asked for by the same machine. Ask the agent for its current link."
// A finish claimed this long ago with no outcome written is resolved from
// what was stored (the isolate died mid-finish).
export const SAVING_STALE_MS = 60_000
const INTERRUPTED_MESSAGE = "The sign-in was interrupted before the connection was stored."
const UPSTREAM_TIMEOUT_MS = 15_000
const FAILING_DAYS_LIMIT = 4
const BACKOFF_MIN_MS = 30_000
const BACKOFF_MAX_MS = 3_600_000
const USER_AGENT = "mehen"
const REFRESHER: SystemPrincipal = { kind: "system", reason: "oauth refresh" }
// How long a managed workspace's scheduled refresh waits before it looks at
// its platform's status again.
const SUSPENDED_REFRESH_WAIT_MS = 5 * 60_000

export type ConnectionState = "active" | "refreshing" | "degraded" | "stale" | "uncertain" | "needs_reauth" | "client_broken" | "revoked"

export const oauthMigrations = [
  `CREATE TABLE oauth_connects (
     id TEXT PRIMARY KEY,
     provider TEXT NOT NULL,
     client TEXT NOT NULL,
     slug TEXT NOT NULL,
     scopes TEXT NOT NULL,
     expect TEXT,
     expect_subject TEXT,
     expect_tenant TEXT,
     reason TEXT NOT NULL,
     device TEXT NOT NULL,
     device_name TEXT NOT NULL,
     session TEXT,
     status TEXT NOT NULL,
     member TEXT,
     state_hash TEXT,
     state_expires_at INTEGER,
     verifier_root INTEGER,
     verifier_dek BLOB,
     verifier_ct BLOB,
     account TEXT,
     granted_scopes TEXT,
     message TEXT,
     created_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     completed_at INTEGER
   );
   CREATE INDEX oauth_connects_slug ON oauth_connects (slug, status);
   CREATE TABLE oauth_connections (
     item TEXT PRIMARY KEY,
     slug TEXT NOT NULL UNIQUE,
     provider TEXT NOT NULL,
     client TEXT NOT NULL,
     subject TEXT NOT NULL,
     provider_tenant TEXT,
     label TEXT NOT NULL,
     state TEXT NOT NULL,
     reason TEXT,
     scopes TEXT NOT NULL,
     access_expires_at INTEGER,
     refresh_expires_at INTEGER,
     connected_at INTEGER NOT NULL,
     last_refresh_at INTEGER NOT NULL,
     last_access_at INTEGER,
     attempt_id TEXT,
     attempt_started_at INTEGER,
     attempt_rt TEXT,
     failures INTEGER NOT NULL DEFAULT 0,
     failure_days INTEGER NOT NULL DEFAULT 0,
     failure_day TEXT,
     retry_at INTEGER,
     device TEXT NOT NULL,
     device_name TEXT NOT NULL
   );
   CREATE TABLE oauth_clients (
     slug TEXT PRIMARY KEY,
     broken_version INTEGER NOT NULL,
     reason TEXT NOT NULL,
     at INTEGER NOT NULL
   );`,
  `ALTER TABLE oauth_connects ADD COLUMN intake TEXT;`,
  `ALTER TABLE oauth_connects ADD COLUMN claimed_at INTEGER;`,
]

type ConnectRow = {
  id: string
  provider: string
  client: string
  slug: string
  scopes: string
  expect: string | null
  expect_subject: string | null
  expect_tenant: string | null
  reason: string
  device: string
  device_name: string
  session: string | null
  // `saving`: claimed by a finish in progress; reads as open.
  status: ConnectStatus["status"] | "saving"
  member: string | null
  state_hash: string | null
  state_expires_at: number | null
  verifier_root: number | null
  verifier_dek: ArrayBuffer | null
  verifier_ct: ArrayBuffer | null
  account: string | null
  granted_scopes: string | null
  message: string | null
  created_at: number
  expires_at: number
  completed_at: number | null
  // The client intake this connect waits for, when it was asked for along with it.
  intake: string | null
  claimed_at: number | null
}

export type ConnectionRow = {
  item: string
  slug: string
  provider: string
  client: string
  subject: string
  provider_tenant: string | null
  label: string
  state: ConnectionState
  reason: string | null
  scopes: string
  access_expires_at: number | null
  refresh_expires_at: number | null
  connected_at: number
  last_refresh_at: number
  last_access_at: number | null
  attempt_id: string | null
  attempt_started_at: number | null
  attempt_rt: string | null
  failures: number
  failure_days: number
  failure_day: string | null
  retry_at: number | null
  device: string
  device_name: string
}

// ---------------------------------------------------------------- small helpers

function savingKey(id: string): string {
  return `connect:${id}`
}

// True when the connection this claim was storing is there: a connection
// row for the slug made since the claim, backed by its item.
function connectedSince(ctx: VaultContext, row: ConnectRow, claimedAt: number): ConnectionRow | null {
  const conn = one(ctx.sql.exec<ConnectionRow>("SELECT * FROM oauth_connections WHERE slug = ?", row.slug))
  if (!conn || conn.connected_at < claimedAt || conn.client !== row.client) return null
  const item = items.getItem(ctx, row.slug)
  return item && item.id === conn.item && item.kind === "oauth-connection" ? conn : null
}

// A claim with no outcome after SAVING_STALE_MS belongs to a finish that
// died with its isolate. What it stored decides the row: a connection in
// place completes it; otherwise the row is handed back to be started
// again, or fails if its time is up. Rows resolve on read and from the
// alarm the claim scheduled.
function resolveStale(ctx: VaultContext, row: ConnectRow): ConnectRow {
  if (row.status !== "saving" || row.claimed_at === null || ctx.now() < row.claimed_at + SAVING_STALE_MS) return row
  const conn = connectedSince(ctx, row, row.claimed_at)
  const provider = getOAuthProvider(row.provider)
  if (conn) {
    ctx.sql.exec(
      "UPDATE oauth_connects SET status = 'completed', message = ?, account = ?, granted_scopes = ?, completed_at = ?, claimed_at = NULL WHERE id = ? AND status = 'saving'",
      `Connected ${provider?.displayName ?? row.provider} for ${conn.label} as "${row.slug}".`,
      conn.label,
      conn.scopes,
      ctx.now(),
      row.id,
    )
  } else if (ctx.now() < row.expires_at) {
    ctx.sql.exec("UPDATE oauth_connects SET status = 'open', message = ?, account = NULL, granted_scopes = NULL, claimed_at = NULL WHERE id = ? AND status = 'saving'", `${INTERRUPTED_MESSAGE} Start it again.`, row.id)
  } else {
    ctx.sql.exec("UPDATE oauth_connects SET status = 'failed', message = ?, account = NULL, granted_scopes = NULL, completed_at = ?, claimed_at = NULL WHERE id = ? AND status = 'saving'", `${INTERRUPTED_MESSAGE} Ask the agent for a new link.`, ctx.now(), row.id)
  }
  ctx.unschedule("oauth", savingKey(row.id))
  ctx.audit({ actor: "system", action: "oauth.connect_recover", target: row.slug, detail: { connect: row.id, stored: conn !== null } })
  return one(ctx.sql.exec<ConnectRow>("SELECT * FROM oauth_connects WHERE id = ?", row.id)) ?? row
}

function getConnect(ctx: VaultContext, id: string): ConnectRow | null {
  const row = one(ctx.sql.exec<ConnectRow>("SELECT * FROM oauth_connects WHERE id = ?", id))
  return row ? resolveStale(ctx, row) : null
}

export function getConnection(ctx: VaultContext, itemId: string): ConnectionRow | null {
  return one(ctx.sql.exec<ConnectionRow>("SELECT * FROM oauth_connections WHERE item = ?", itemId))
}

// A connect's status and expiry as they stand now. A chained connect lives
// as long as the client intake it waits for, then for CONNECT_TTL_MS from
// the moment the client was saved; its intake being cancelled fails it and
// expiring expires it. Starting the flow keeps any connect alive for the
// state's own lifetime.
type Resolved = { status: ConnectStatus["status"]; expiresAt: number; chain: IntakeOutcome | null; message: string | null }

function resolve(ctx: VaultContext, row: ConnectRow): Resolved {
  const chain = row.intake === null ? null : intakes.outcome(ctx, row.intake)
  let expiresAt = row.expires_at
  if (chain?.status === "completed" && chain.completedAt !== null) expiresAt = Math.min(expiresAt, chain.completedAt + CONNECT_TTL_MS)
  expiresAt = Math.max(expiresAt, row.state_expires_at ?? 0)
  // A finish in progress is still open to everyone outside it.
  if (row.status === "saving") return { status: "open", expiresAt, chain, message: null }
  if (row.status !== "open") return { status: row.status, expiresAt, chain, message: row.message }
  if (row.intake !== null && (chain === null || chain.status === "cancelled")) {
    return { status: "failed", expiresAt, chain, message: `The request for the OAuth client "${row.client}" was cancelled, so this connection cannot be made. Ask the agent for a new link.` }
  }
  if (chain?.status === "expired") return { status: "expired", expiresAt: chain.expiresAt, chain, message: row.message }
  return { status: ctx.now() >= expiresAt ? "expired" : "open", expiresAt, chain, message: row.message }
}

function effectiveStatus(ctx: VaultContext, row: ConnectRow): ConnectStatus["status"] {
  return resolve(ctx, row).status
}

// A connect's standing for a list that did not read the row itself (the
// pending area): any stale finish claim is settled first, exactly as the
// status route does, so the answer is the one the row's own page would give.
// Carries nothing from the row but what resolving needs to say.
export type ConnectStanding = { status: ConnectStatus["status"]; expiresAt: number; chain: IntakeOutcome | null }

export function connectStanding(ctx: VaultContext, id: string): ConnectStanding | null {
  const row = getConnect(ctx, id)
  if (!row) return null
  const { status, expiresAt, chain } = resolve(ctx, row)
  return { status, expiresAt, chain }
}

function providerOf(id: string): OAuthProviderTemplate {
  const provider = getOAuthProvider(id)
  if (!provider) throw new VaultError("internal", `Unknown OAuth provider "${id}".`)
  return provider
}

function connectUrl(ctx: VaultContext, id: string): string {
  return `${ctx.env.VAULT_ORIGIN}/c/${id}`
}

function at(value: unknown, path: string | undefined): unknown {
  if (path === undefined) return undefined
  let cur: unknown = value
  for (const key of path.split(".")) {
    if (typeof cur !== "object" || cur === null || !Object.hasOwn(cur, key)) return undefined
    cur = (cur as Record<string, unknown>)[key]
  }
  return cur
}

function textAt(value: unknown, path: string | undefined): string | null {
  const v = at(value, path)
  if (typeof v === "string" && v !== "") return v
  if (typeof v === "number" && Number.isFinite(v)) return String(v)
  return null
}

function secondsAt(value: unknown, path: string | undefined): number | null {
  const v = at(value, path)
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : Number.NaN
  return Number.isFinite(n) && n > 0 ? n : null
}

async function fingerprintOf(value: string): Promise<string> {
  return base64UrlEncode(await sha256(`mehen/oauth-rt/v1\n${value}`)).slice(0, 16)
}

function verifierRef(connect: string) {
  return { type: "oauth-pkce", id: connect }
}

function parseInput<T extends z.ZodType>(schema: T, input: unknown): z.infer<T> {
  const parsed = schema.safeParse(input)
  if (!parsed.success) {
    const issue = parsed.error.issues[0]
    throw new VaultError("bad_request", `Invalid request: ${issue ? `${issue.path.join(".") || "body"} ${issue.message}` : "bad shape"}.`)
  }
  return parsed.data
}

function requireDevice(principal: Principal): DevicePrincipal {
  if (principal.kind !== "device") throw new VaultError("forbidden", "Only an enrolled device can do that.")
  return principal
}

function requireMember(principal: Principal): MemberPrincipal {
  if (principal.kind !== "member") throw new VaultError("forbidden", "Only a signed-in member can do that.")
  return principal
}

// ---------------------------------------------------------------- talking to the provider

type TokenResult =
  | { kind: "ok"; accessToken: string; refreshToken: string | null; expiresIn: number | null; refreshExpiresIn: number | null; scopes: string[] | null; body: unknown }
  | { kind: "oauth_error"; code: string; status: number }
  | { kind: "transient"; status: number; retryAfter: number | null; mayHaveIssued: boolean }

function clientSecretBinding(client: ItemRecord, url: string): void {
  const dest = parseDestination("POST", url)
  if (!dest.ok || !checkBinding(client.binding, dest.destination).ok) {
    throw new VaultError("internal", `The token URL for "${client.slug}" is outside its binding, so its secret was not sent.`)
  }
}

async function readBodyLoose(response: Response): Promise<unknown> {
  const text = await response.text()
  try {
    return JSON.parse(text)
  } catch {
    return Object.fromEntries(new URLSearchParams(text))
  }
}

// A public client (clientAuth "none", custom providers only) sends its
// client id and no secret; PKCE stands in for the secret.
export async function tokenRequest(provider: Pick<OAuthExchange, "auth">, client: ItemRecord, clientSecret: string, params: Record<string, string>, now = Date.now()): Promise<TokenResult> {
  const auth = provider.auth
  clientSecretBinding(client, auth.tokenUrl)
  const clientId = client.publicFields.client_id ?? ""
  const fields: Record<string, string> = { ...params }
  const headers: Record<string, string> = { accept: "application/json", "user-agent": USER_AGENT }
  if (auth.clientAuth === "none") {
    fields.client_id = clientId
  } else if (auth.clientAuth === "client_secret_post") {
    fields.client_id = clientId
    fields.client_secret = clientSecret
  } else {
    headers.authorization = `Basic ${btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`)}`
  }
  let body: string
  if (auth.tokenRequestFormat === "json") {
    headers["content-type"] = "application/json"
    body = JSON.stringify(fields)
  } else {
    headers["content-type"] = "application/x-www-form-urlencoded"
    body = new URLSearchParams(fields).toString()
  }
  let response: Response
  try {
    response = await upstreamFetch(new Request(auth.tokenUrl, { method: "POST", headers, body, redirect: "manual", signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) }))
  } catch {
    return { kind: "transient", status: 0, retryAfter: null, mayHaveIssued: true }
  }
  const parsed = await readBodyLoose(response).catch(() => ({}))
  const retryAfterSeconds = retryAfterOf(response.headers.get("retry-after"), now)
  // Throttling and a provider's own failure are retried, whatever error
  // code the body carries: neither says the grant or the client is wrong.
  if (response.status === 429 || response.status >= 500 && response.status <= 599) {
    return { kind: "transient", status: response.status, retryAfter: retryAfterSeconds, mayHaveIssued: textAt(parsed, auth.tokenResponse.accessToken) !== null || textAt(parsed, auth.tokenResponse.refreshToken) !== null }
  }
  const code = textAt(parsed, "error")
  if (code !== null) return { kind: "oauth_error", code, status: response.status }
  const okFlag = auth.tokenResponse.okFlag
  const flagged = okFlag === undefined || at(parsed, okFlag.path) === okFlag.equals
  const accessToken = textAt(parsed, auth.tokenResponse.accessToken)
  if (response.ok && flagged && accessToken !== null) {
    const granted = textAt(parsed, auth.tokenResponse.grantedScopes)
    return {
      kind: "ok",
      accessToken,
      refreshToken: textAt(parsed, auth.tokenResponse.refreshToken),
      expiresIn: secondsAt(parsed, auth.tokenResponse.expiresIn),
      refreshExpiresIn: secondsAt(parsed, auth.tokenResponse.refreshTokenExpiresIn),
      scopes: granted === null ? null : granted.split(/[ ,]+/).filter((s) => s !== ""),
      body: parsed,
    }
  }
  return { kind: "transient", status: response.status, retryAfter: retryAfterSeconds, mayHaveIssued: response.ok || accessToken !== null || textAt(parsed, auth.tokenResponse.refreshToken) !== null }
}

// Retry-After in seconds from now, given as seconds or as an HTTP date, at
// most a day: a longer one waits a day and tries again, so its failures
// still count towards FAILING_DAYS_LIMIT. Null when absent, unreadable or
// already past.
const RETRY_AFTER_MAX_SECONDS = 86_400
function retryAfterOf(header: string | null, now: number): number | null {
  if (header === null || header.trim() === "") return null
  const seconds = Number(header)
  if (Number.isFinite(seconds)) return seconds > 0 ? Math.min(seconds, RETRY_AFTER_MAX_SECONDS) : null
  const until = Date.parse(header)
  return Number.isFinite(until) && until > now ? Math.min(Math.ceil((until - now) / 1000), RETRY_AFTER_MAX_SECONDS) : null
}

type Identity = { subject: string; tenant: string | null; label: string }

function decodeJwtPayload(token: string): unknown {
  const part = token.split(".")[1]
  if (part === undefined) return null
  try {
    return JSON.parse(new TextDecoder().decode(base64UrlDecode(part)))
  } catch {
    return null
  }
}

export async function probeIdentity(provider: OAuthProviderTemplate, accessToken: string, tokenBody: unknown): Promise<Identity | "unauthorised" | "failed"> {
  const probe = provider.identity
  let source: unknown
  if (probe.from === "id_token") {
    const idToken = textAt(tokenBody, provider.auth.tokenResponse.idToken)
    source = idToken === null ? null : decodeJwtPayload(idToken)
  } else {
    const request = probe.request
    if (!request) return "failed"
    let response: Response
    try {
      response = await upstreamFetch(
        new Request(request.url, {
          method: request.method,
          headers: { authorization: `Bearer ${accessToken}`, accept: "application/json", "user-agent": USER_AGENT, ...(request.headers ?? {}) },
          redirect: "manual",
          signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
        }),
      )
    } catch {
      return "failed"
    }
    if (response.status === 401) return "unauthorised"
    if (!response.ok) return "failed"
    source = await response.json().catch(() => null)
  }
  const subject = textAt(source, probe.subject)
  const label = textAt(source, probe.label)
  if (subject === null || label === null) return "failed"
  return { subject, tenant: textAt(source, probe.tenant), label }
}

// ---------------------------------------------------------------- client health

function clientBroken(ctx: VaultContext, client: ItemRecord): boolean {
  const row = one(ctx.sql.exec<{ broken_version: number }>("SELECT broken_version FROM oauth_clients WHERE slug = ?", client.slug))
  if (!row) return false
  if (client.version > row.broken_version) {
    ctx.sql.exec("DELETE FROM oauth_clients WHERE slug = ?", client.slug)
    return false
  }
  return true
}

function markClientBroken(ctx: VaultContext, client: ItemRecord, provider: OAuthProviderTemplate): void {
  const existing = one(ctx.sql.exec<{ broken_version: number }>("SELECT broken_version FROM oauth_clients WHERE slug = ?", client.slug))
  if (existing && existing.broken_version >= client.version) return
  ctx.sql.exec(
    "INSERT INTO oauth_clients (slug, broken_version, reason, at) VALUES (?, ?, ?, ?) ON CONFLICT (slug) DO UPDATE SET broken_version = excluded.broken_version, reason = excluded.reason, at = excluded.at",
    client.slug,
    client.version,
    `${provider.displayName} rejected the client secret`,
    ctx.now(),
  )
  ctx.audit({ actor: actorOf(REFRESHER), action: "oauth.client_broken", target: client.slug, detail: { provider: provider.id } })
}

function clientBrokenError(ctx: VaultContext, clientSlug: string, provider: OAuthProviderTemplate): VaultError {
  return new VaultError("needs_reauth", `${provider.displayName} rejected the OAuth client "${clientSlug}" (its secret is wrong, expired or deleted). Every connection that uses it is paused until a human replaces the secret.`, {
    next: { url: `${ctx.env.VAULT_ORIGIN}/items/${clientSlug}`, say: `The OAuth client "${clientSlug}" was rejected by ${provider.displayName}; a human must replace its client secret in the vault.` },
  })
}

// ---------------------------------------------------------------- connect records

type NewConnect = {
  provider: OAuthProviderTemplate
  client: string
  slug: string
  scopes: string[]
  expect: string | null
  expectSubject: string | null
  expectTenant: string | null
  reason: string
  device: string
  deviceName: string
  session: string | null
  // Set for a connect chained to a client intake: its id, and the intake's
  // expiry as the row's own.
  chain?: { id: string; intake: string; expiresAt: number }
}

function insertConnect(ctx: VaultContext, c: NewConnect): { id: string; expiresAt: number } {
  const id = c.chain?.id ?? randomId("con")
  const now = ctx.now()
  const expiresAt = c.chain?.expiresAt ?? now + CONNECT_TTL_MS
  ctx.sql.exec(
    `INSERT INTO oauth_connects (id, provider, client, slug, scopes, expect, expect_subject, expect_tenant, reason, device, device_name, session, status, created_at, expires_at, intake)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)`,
    id,
    c.provider.id,
    c.client,
    c.slug,
    JSON.stringify(c.scopes),
    c.expect,
    c.expectSubject,
    c.expectTenant,
    c.reason,
    c.device,
    c.deviceName,
    c.session,
    now,
    expiresAt,
    c.chain?.intake ?? null,
  )
  return { id, expiresAt }
}

// The scopes a connection holds that a connect may ask for again: the
// stored grant without the identity and offline scopes the start adds on
// its own, and without anything outside the provider's allowed set.
// Read defensively: a stored grant the vault cannot read is an empty one
// (so a reconnect asks for nothing it cannot vouch for) and is audited,
// never thrown, since a reconnect and the connect page both read it.
export function connectionScopes(ctx: VaultContext, provider: OAuthProviderTemplate, conn: ConnectionRow): string[] {
  let parsed: unknown
  try {
    parsed = JSON.parse(conn.scopes)
  } catch {
    parsed = null
  }
  const stored = Array.isArray(parsed) ? parsed.filter((s): s is string => typeof s === "string") : null
  if (stored === null || stored.length !== (parsed as unknown[]).length) {
    ctx.audit({ actor: "system", action: "oauth.scopes_unreadable", target: conn.slug, detail: { item: conn.item } })
  }
  const out: string[] = []
  for (const s of stored ?? []) {
    const scope = normaliseScope(provider, s)
    if (scope !== null && !out.includes(scope)) out.push(scope)
  }
  return out
}

// The scopes a token response grants beyond what the connect asked for. A
// granted scope is acceptable only when it is an allowed scope that was
// asked for, or one of the template's identityScopes (sign-in, staying
// signed in, and the long forms the provider substitutes). Anything else
// is wider, a scope the vault offers (gmail.modify on a readonly connect)
// and one it never offers (https://mail.google.com/) alike. An absent
// response (`granted` null) grants exactly what was asked.
export function grantedBeyond(provider: Pick<OAuthExchange, "auth">, asked: readonly string[], granted: readonly string[] | null): string[] {
  if (granted === null) return []
  const askedSet = new Set(asked.map((s) => normaliseScope(provider, s) ?? s))
  const identity = new Set(provider.auth.scopes.identityScopes)
  const wider: string[] = []
  for (const s of granted) {
    if (identity.has(s)) continue
    const scope = normaliseScope(provider, s) ?? s
    if (!askedSet.has(scope) && !wider.includes(scope)) wider.push(scope)
  }
  return wider
}

// Best effort: a token the vault will not keep is handed back to the
// provider where the template names a revocation endpoint (Google does;
// GitHub and Microsoft do not). Nothing depends on the answer.
export async function revokeToken(provider: Pick<OAuthExchange, "auth">, token: string): Promise<boolean> {
  const url = provider.auth.revokeUrl
  if (url === undefined) return false
  try {
    const response = await upstreamFetch(
      new Request(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", "user-agent": USER_AGENT },
        body: new URLSearchParams({ token }).toString(),
        redirect: "manual",
        signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
      }),
    )
    return response.ok
  } catch {
    return false
  }
}

// A reconnect link pinned to the connection's provider subject. Reuses an
// open one so a busy agent does not mint a link per failing call.
function reconnectNext(ctx: VaultContext, conn: ConnectionRow): { next: NextStep; expiresAt: number } {
  const now = ctx.now()
  const open = one(
    ctx.sql.exec<{ id: string; expires_at: number }>(
      "SELECT id, expires_at FROM oauth_connects WHERE slug = ? AND status = 'open' AND expect_subject = ? AND state_hash IS NULL AND intake IS NULL AND expires_at > ? ORDER BY created_at DESC LIMIT 1",
      conn.slug,
      conn.subject,
      now + REUSE_MARGIN_MS,
    ),
  )
  const provider = providerOf(conn.provider)
  const { id, expiresAt } =
    open === null
      ? insertConnect(ctx, {
          provider,
          client: conn.client,
          slug: conn.slug,
          scopes: JSON.parse(conn.scopes) as string[],
          expect: conn.label,
          expectSubject: conn.subject,
          expectTenant: conn.provider_tenant,
          reason: `Reconnect ${conn.slug}: ${conn.reason ?? "the sign-in stopped working"}`,
          device: conn.device,
          deviceName: conn.device_name,
          session: null,
        })
      : { id: open.id, expiresAt: open.expires_at }
  return {
    next: {
      url: connectUrl(ctx, id),
      command: `mehen wait ${id}`,
      say: `${provider.displayName} for ${conn.label} must be reconnected. Open this link, sign in to the vault, then sign in to ${provider.displayName} as ${conn.label}.`,
    },
    expiresAt,
  }
}

function reauthError(ctx: VaultContext, conn: ConnectionRow): VaultError {
  const { next, expiresAt } = reconnectNext(ctx, conn)
  return new VaultError("needs_reauth", `"${conn.slug}" must be reconnected: ${conn.reason ?? "the provider no longer accepts the sign-in"}.`, { next, expiresAt: new Date(expiresAt).toISOString() })
}

// Quotes one word for a POSIX shell, so a printed command runs as printed.
export function shellQuote(word: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(word) ? word : `'${word.replaceAll("'", `'\\''`)}'`
}

function clientMissing(ctx: VaultContext, clientSlug: string, provider: OAuthProviderTemplate, reason: string): VaultError {
  const template = provider.clientTemplate
  return new VaultError("bad_request", `"${clientSlug}" must be an OAuth client item made from the ${template} template.`, {
    next: {
      command: `mehen request oauth-client --name ${shellQuote(clientSlug)} --provider ${shellQuote(template)} --reason ${shellQuote(reason)}`,
      say: `Ask a human for the ${provider.displayName} OAuth client first, or repeat the connect with requestClient: true to ask for both at once. The redirect URI they will need is ${ctx.env.VAULT_ORIGIN}/oauth/callback.`,
    },
  })
}

// ---------------------------------------------------------------- refresh

type Inflight = Map<string, Promise<string>>
const inflight: Inflight = new Map()

function inflightKey(ctx: VaultContext, itemId: string): string {
  return `${ctx.tenant}/${itemId}`
}

function nextDue(conn: ConnectionRow, provider: OAuthProviderTemplate): number | null {
  if (conn.state === "needs_reauth" || conn.state === "revoked" || conn.state === "client_broken") return null
  const due: number[] = []
  if (conn.retry_at !== null) due.push(conn.retry_at)
  // Refresh ahead of expiry only while the connection is in use; idle ones
  // just get their keepalive.
  if (conn.access_expires_at !== null && conn.last_access_at !== null && conn.last_access_at >= conn.last_refresh_at) {
    due.push(conn.access_expires_at - provider.refresh.marginSeconds * 1000)
  }
  const idle = provider.lifetimes.refreshTokenIdleSeconds
  if (idle !== undefined) due.push(conn.last_refresh_at + (idle * 1000) / 2)
  return due.length === 0 ? null : Math.min(...due)
}

function reschedule(ctx: VaultContext, itemId: string): void {
  const conn = getConnection(ctx, itemId)
  if (!conn) return
  const due = nextDue(conn, providerOf(conn.provider))
  if (due === null) ctx.unschedule("oauth", `refresh:${itemId}`)
  else ctx.schedule("oauth", `refresh:${itemId}`, due)
}

function reauthReason(ctx: VaultContext, conn: ConnectionRow, provider: OAuthProviderTemplate, wasUncertain: boolean): string {
  return reauthReasonAt(provider, provider.displayName, { connectedAt: conn.connected_at, refreshedAt: conn.last_refresh_at }, ctx.now(), wasUncertain && provider.refresh.rotation === "strict")
}

// Why a provider stopped accepting a sign-in, from when it was made and
// last renewed (null where unknown); provider is null for a custom one.
// lostRotation: a refresh of a strictly rotating token was interrupted. The
// refusal cannot say whether that refresh replaced the token or the grant
// was revoked or expired, so a time limit that was met still wins.
export function reauthReasonAt(provider: OAuthProviderTemplate | null, displayName: string, times: { connectedAt: number | null; refreshedAt: number | null }, now: number, lostRotation: boolean): string {
  // Testing ends a grant at its lifetime, so only a grant whose age fits it
  // (from a day short of it to twice it, room for a run of failing days)
  // and that never renewed past it is put down to Testing.
  const testing = provider?.lifetimes.testingModeRefreshSeconds
  const age = times.connectedAt === null ? null : now - times.connectedAt
  const renewedPast = times.connectedAt !== null && times.refreshedAt !== null && testing !== undefined && times.refreshedAt > times.connectedAt + testing * 1000
  if (testing !== undefined && age !== null && age >= testing * 1000 - 86_400_000 && age <= testing * 2000 && !renewedPast) {
    const days = Math.round(age / 86_400_000)
    return `${displayName} stopped accepting the sign-in about ${days} days after it was made, which is what happens when the OAuth app is in Testing. Set the app to "In production" on its consent screen, then reconnect`
  }
  const idle = provider?.lifetimes.refreshTokenIdleSeconds
  if (idle !== undefined && times.refreshedAt !== null && now - times.refreshedAt >= idle * 900) return `the sign-in was unused for too long and ${displayName} expired it`
  if (lostRotation) return `${displayName} no longer accepts the sign-in, most likely because an interrupted refresh had already replaced the token`
  if (provider?.family === "google") {
    return "Google revoked the sign-in: the password was changed, access was removed in the Google account's security settings, or the account signed in to this app too many times (Google keeps 100)"
  }
  return `${displayName} no longer accepts the sign-in (it was revoked, the password changed, or it expired)`
}

function markNeedsReauth(ctx: VaultContext, item: ItemRecord, reason: string, state: ConnectionState = "needs_reauth"): VaultError {
  ctx.sql.exec(
    "UPDATE oauth_connections SET state = ?, reason = ?, attempt_id = NULL, attempt_started_at = NULL, attempt_rt = NULL, retry_at = NULL WHERE item = ?",
    state,
    reason,
    item.id,
  )
  items.setStatus(ctx, item.slug, "needs_reauth", reason)
  ctx.unschedule("oauth", `refresh:${item.id}`)
  ctx.audit({ actor: actorOf(REFRESHER), action: "oauth.needs_reauth", target: item.slug, detail: { state } })
  return reauthError(ctx, getConnection(ctx, item.id) as ConnectionRow)
}

async function refreshConnection(ctx: VaultContext, item: ItemRecord): Promise<string> {
  const conn = getConnection(ctx, item.id)
  if (!conn) throw new VaultError("internal", `"${item.slug}" has no connection record.`)
  const provider = providerOf(conn.provider)
  const wasUncertain = conn.state === "uncertain"
  const client = items.getItem(ctx, conn.client)
  if (!client || client.kind !== "oauth-client") throw markNeedsReauth(ctx, item, `its OAuth client "${conn.client}" no longer exists`)
  if (clientBroken(ctx, client)) throw clientBrokenError(ctx, client.slug, provider)
  const secrets = await items.openSecrets(ctx, item)
  const refreshToken = secrets.refresh_token
  const stillValid = conn.access_expires_at === null || ctx.now() < conn.access_expires_at
  if (refreshToken === undefined) {
    if (stillValid && secrets.access_token) return secrets.access_token
    throw markNeedsReauth(ctx, item, `${provider.displayName} gave no refresh token, so the expired sign-in cannot be renewed`)
  }
  const clientSecret = (await items.openSecrets(ctx, client)).client_secret ?? ""

  const attempt = async (rt: string, retried: boolean): Promise<string> => {
    const now = ctx.now()
    ctx.sql.exec(
      "UPDATE oauth_connections SET state = 'refreshing', attempt_id = ?, attempt_started_at = ?, attempt_rt = ? WHERE item = ?",
      randomId("rfa"),
      now,
      await fingerprintOf(rt),
      item.id,
    )
    const result = await tokenRequest(provider, client, clientSecret, { grant_type: "refresh_token", refresh_token: rt }, ctx.now())
    if (result.kind === "ok") {
      const rotated: Record<string, string> = { access_token: result.accessToken }
      // Google sends a refresh token only on first consent: keep the old one.
      if (result.refreshToken !== null) rotated.refresh_token = result.refreshToken
      await items.replaceSecrets(ctx, item.slug, rotated, REFRESHER)
      const done = ctx.now()
      ctx.sql.exec(
        `UPDATE oauth_connections SET state = 'active', reason = NULL, access_expires_at = ?, refresh_expires_at = COALESCE(?, refresh_expires_at), scopes = COALESCE(?, scopes),
           last_refresh_at = ?, attempt_id = NULL, attempt_started_at = NULL, attempt_rt = NULL, failures = 0, failure_days = 0, failure_day = NULL, retry_at = NULL WHERE item = ?`,
        result.expiresIn === null ? null : done + result.expiresIn * 1000,
        result.refreshExpiresIn === null ? null : done + result.refreshExpiresIn * 1000,
        result.scopes === null ? null : JSON.stringify(result.scopes),
        done,
        item.id,
      )
      if (items.getItem(ctx, item.slug)?.status !== "active") items.setStatus(ctx, item.slug, "active", null)
      reschedule(ctx, item.id)
      ctx.audit({ actor: actorOf(REFRESHER), action: "oauth.refresh", target: item.slug, detail: { provider: provider.id } })
      return result.accessToken
    }
    if (result.kind === "oauth_error" && provider.refresh.clientErrors.includes(result.code)) {
      markClientBroken(ctx, client, provider)
      ctx.sql.exec("UPDATE oauth_connections SET state = 'client_broken', reason = ?, attempt_id = NULL, attempt_started_at = NULL, attempt_rt = NULL WHERE item = ?", `${provider.displayName} rejected the OAuth client "${client.slug}"`, item.id)
      items.setStatus(ctx, item.slug, "needs_reauth", `OAuth client "${client.slug}" rejected`)
      throw clientBrokenError(ctx, client.slug, provider)
    }
    if (result.kind === "oauth_error" && provider.refresh.terminalErrors.includes(result.code)) {
      // Someone may have rotated the token meanwhile (a reconnect): retry once with it.
      if (!retried) {
        const current = (await items.openSecrets(ctx, item)).refresh_token
        if (current !== undefined && current !== rt) return attempt(current, true)
      }
      throw markNeedsReauth(ctx, item, reauthReason(ctx, conn, provider, wasUncertain))
    }
    return transientFailure(ctx, item, provider, result.kind === "transient" ? result.retryAfter : null, secrets.access_token ?? null)
  }
  return attempt(refreshToken, false)
}

function transientFailure(ctx: VaultContext, item: ItemRecord, provider: OAuthProviderTemplate, retryAfter: number | null, oldToken: string | null): string {
  const conn = getConnection(ctx, item.id) as ConnectionRow
  const now = ctx.now()
  const day = new Date(now).toISOString().slice(0, 10)
  const failureDays = conn.failure_day === day ? conn.failure_days : conn.failure_days + 1
  const failures = conn.failures + 1
  if (failureDays >= FAILING_DAYS_LIMIT) throw markNeedsReauth(ctx, item, `refreshing with ${provider.displayName} has failed on ${failureDays} different days`)
  const wait = refreshRetryWaitMs(failures, retryAfter)
  const valid = oldToken !== null && (conn.access_expires_at === null || now < conn.access_expires_at)
  ctx.sql.exec(
    "UPDATE oauth_connections SET state = ?, failures = ?, failure_days = ?, failure_day = ?, retry_at = ?, attempt_id = NULL, attempt_started_at = NULL, attempt_rt = NULL WHERE item = ?",
    valid ? "degraded" : "stale",
    failures,
    failureDays,
    day,
    now + Math.round(wait),
    item.id,
  )
  if (!valid) items.setStatus(ctx, item.slug, "refresh_retrying", `${provider.displayName} did not answer a refresh`)
  reschedule(ctx, item.id)
  if (valid) return oldToken
  throw retryingError(item, provider, Math.ceil(wait / 1000))
}

// How long to wait after the nth refresh failure in a row: doubling from
// 30 s to an hour, with 20% jitter either way, or longer if the provider
// asked (Retry-After, in seconds or as a date, up to a day).
export function refreshRetryWaitMs(failures: number, retryAfter: number | null): number {
  const backoff = Math.min(BACKOFF_MIN_MS * 2 ** (failures - 1), BACKOFF_MAX_MS) * (0.8 + Math.random() * 0.4)
  return Math.max(backoff, (retryAfter ?? 0) * 1000)
}

function retryingError(item: ItemRecord, provider: OAuthProviderTemplate, seconds: number): VaultError {
  return new VaultError("refresh_retrying", `${provider.displayName} did not answer the token refresh for "${item.slug}". Try again in ${seconds} seconds.`, {
    retryAfter: seconds,
    next: { say: `${provider.displayName} is not answering right now; the vault will keep retrying. Try again in ${seconds} seconds.` },
  })
}

function singleFlight(ctx: VaultContext, item: ItemRecord): Promise<string> {
  const key = inflightKey(ctx, item.id)
  const running = inflight.get(key)
  if (running) return running
  const promise = refreshConnection(ctx, item)
  inflight.set(key, promise)
  const clear = () => {
    if (inflight.get(key) === promise) inflight.delete(key)
  }
  promise.then(clear, clear)
  return promise
}

export const oauth: OAuthService = {
  // Everything up to joining or starting the single flight is synchronous,
  // so concurrent callers always find the first caller's promise.
  async accessToken(ctx, item) {
    if (item.kind !== "oauth-connection") throw new VaultError("bad_request", `"${item.slug}" is not an OAuth connection.`)
    const conn = getConnection(ctx, item.id)
    if (!conn) {
      throw new VaultError("needs_reauth", `"${item.slug}" was never connected.`, {
        next: {
          command: `mehen connect ${item.provider ?? "<provider>"} --client <oauth-client-item> --name ${item.slug} --reason "<why you need it>"`,
          say: `Connect "${item.slug}" first with \`mehen connect\`, naming the OAuth client item to use.`,
        },
      })
    }
    if (conn.state === "needs_reauth" || conn.state === "revoked") throw reauthError(ctx, conn)
    const provider = providerOf(conn.provider)
    const key = inflightKey(ctx, item.id)
    const running = inflight.get(key)
    if (running) return running
    if (conn.state === "refreshing") {
      // Written ahead, but nothing in this process is running it: the DO
      // restarted mid-refresh.
      ctx.sql.exec("UPDATE oauth_connections SET state = 'uncertain' WHERE item = ?", item.id)
      return singleFlight(ctx, item)
    }
    const now = ctx.now()
    if (conn.state === "client_broken") {
      const client = items.getItem(ctx, conn.client)
      if (client && clientBroken(ctx, client)) throw clientBrokenError(ctx, conn.client, provider)
      return singleFlight(ctx, item)
    }
    const fresh = conn.access_expires_at === null || now < conn.access_expires_at - provider.refresh.marginSeconds * 1000
    const coolingDown = (conn.state === "stale" || conn.state === "degraded") && conn.retry_at !== null && now < conn.retry_at
    if (conn.state === "uncertain" || (!fresh && !coolingDown)) return singleFlight(ctx, item)
    if (coolingDown && (conn.access_expires_at === null || now >= conn.access_expires_at)) throw retryingError(item, provider, Math.ceil(((conn.retry_at as number) - now) / 1000))
    const firstUseSinceRefresh = conn.last_access_at === null || conn.last_access_at < conn.last_refresh_at
    ctx.sql.exec("UPDATE oauth_connections SET last_access_at = ? WHERE item = ?", now, item.id)
    if (firstUseSinceRefresh) reschedule(ctx, item.id)
    const token = (await items.openSecrets(ctx, item)).access_token
    if (!token) throw markNeedsReauth(ctx, item, "the stored access token is missing")
    return token
  },
}

// GitHub OAuth app tokens never expire but die after a year unused: an
// identity probe counts as use.
async function keepAlive(ctx: VaultContext, item: ItemRecord, conn: ConnectionRow, provider: OAuthProviderTemplate): Promise<void> {
  const token = (await items.openSecrets(ctx, item)).access_token
  if (!token) return
  const probe = await probeIdentity(provider, token, null)
  if (probe === "unauthorised") {
    markNeedsReauth(ctx, item, `${provider.displayName} revoked the sign-in`, "revoked")
    return
  }
  if (probe === "failed") throw new Error("keepalive probe failed")
  ctx.sql.exec("UPDATE oauth_connections SET last_refresh_at = ? WHERE item = ?", ctx.now(), conn.item)
  reschedule(ctx, item.id)
}

// ---------------------------------------------------------------- ops

const ConnectIdInput = z.object({ connect: z.string().max(64) })
const ConnectStartInput = z.object({ connect: z.string().max(64), state: z.string().min(32).max(128) })
const ConnectFinishInput = z.object({
  connect: z.string().max(64),
  state: z.string().min(1).max(128),
  code: z.string().max(4096).nullable(),
  error: z.string().max(200).nullable(),
})

function connectStatusOf(ctx: VaultContext, row: ConnectRow): ConnectStatus {
  const { status, expiresAt, message } = resolve(ctx, row)
  const item = status === "completed" ? items.getItem(ctx, row.slug) : null
  const out: ConnectStatus = { connect: row.id, status, expiresAt: new Date(expiresAt).toISOString() }
  if (item) out.item = items.summarise(item)
  if (row.account !== null) out.account = row.account
  if (row.granted_scopes !== null) out.grantedScopes = JSON.parse(row.granted_scopes) as string[]
  if (message !== null) out.message = message
  return out
}

function chainedIntakeOf(ctx: VaultContext, row: ConnectRow): IntakeCreated | undefined {
  const chain = row.intake === null ? null : intakes.outcome(ctx, row.intake)
  return row.intake !== null && chain ? { intake: row.intake, url: chain.url, expiresAt: new Date(chain.expiresAt).toISOString() } : undefined
}

function createdOf(ctx: VaultContext, row: ConnectRow): ConnectCreated {
  const intake = chainedIntakeOf(ctx, row)
  return { connect: row.id, url: connectUrl(ctx, row.id), expiresAt: new Date(resolve(ctx, row).expiresAt).toISOString(), ...(intake ? { intake } : {}) }
}

// What a connect row holds apart from who asked and why: the values a second
// request must repeat to get the same link back.
// For a chained connect, `clientTags` is the client intake's tag set.
type ConnectShape = { provider: string; client: string; scopes: string[]; expect: string | null; expectSubject: string | null; expectTenant: string | null; chained: boolean; clientTags: string[] }

function tagSet(tags: string[]): string[] {
  return [...new Set(tags)].sort()
}

function shapeOf(row: ConnectRow, chain: IntakeOutcome | null): ConnectShape {
  return {
    provider: row.provider,
    client: row.client,
    scopes: (JSON.parse(row.scopes) as string[]).sort(),
    expect: row.expect,
    expectSubject: row.expect_subject,
    expectTenant: row.expect_tenant,
    chained: row.intake !== null,
    clientTags: row.intake !== null && chain ? tagSet(chain.tags) : [],
  }
}

function finishingNow(open: ConnectRow): VaultError {
  return new VaultError("conflict", `A human is finishing the sign-in for "${open.slug}" right now (request ${open.id}). Wait for it instead of asking again.`, {
    next: { command: `mehen wait ${open.id}`, say: `Your sign-in for "${open.slug}" is being completed; the agent is waiting for it.` },
  })
}

// This requester's open connect for the slug, if it has time left. Only the
// asker's own rows are considered, so a link never travels to another
// machine or member.
function openConnectFor(ctx: VaultContext, requester: Requester, slug: string): ConnectRow | null {
  const rows = ctx.sql.exec<ConnectRow>("SELECT * FROM oauth_connects WHERE device = ? AND slug = ? AND status = 'open' ORDER BY created_at DESC", requester.key, slug).toArray()
  const now = ctx.now()
  return rows.find((row) => {
    const { status, expiresAt } = resolve(ctx, row)
    return status === "open" && expiresAt > now + REUSE_MARGIN_MS
  }) ?? null
}

// This requester's connect for the slug that a human is finishing right now, if any.
function finishingFor(ctx: VaultContext, requester: Requester, slug: string): ConnectRow | null {
  const rows = ctx.sql.exec<ConnectRow>("SELECT * FROM oauth_connects WHERE device = ? AND slug = ? AND status = 'saving'", requester.key, slug).toArray()
  return rows.map((row) => resolveStale(ctx, row)).find((row) => row.status === "saving") ?? null
}

// Closes every other open connect this requester has for the slug, so one
// link is live per requester and slug. A row a human is finishing right now
// is not open, so it is left alone: its claim decides it.
function supersedeOthers(ctx: VaultContext, requester: Requester, slug: string, keep: string): void {
  const rows = ctx.sql.exec<ConnectRow>("SELECT * FROM oauth_connects WHERE device = ? AND slug = ? AND status = 'open' AND id != ?", requester.key, slug, keep).toArray()
  for (const old of rows) {
    const written = ctx.sql.exec(
      "UPDATE oauth_connects SET status = 'failed', message = ?, state_hash = NULL, verifier_root = NULL, verifier_dek = NULL, verifier_ct = NULL, completed_at = ? WHERE id = ? AND status = 'open' AND device = ?",
      SUPERSEDED_MESSAGE,
      ctx.now(),
      old.id,
      requester.key,
    ).rowsWritten
    if (written === 0) continue
    ctx.audit({ actor: actorOf(requester.principal), action: "oauth.connect_supersede", target: old.slug, detail: { connect: old.id, by: keep } })
  }
}

// A device may only use items its scope covers; a member sees them all.
function covers(requester: Requester, item: ItemRecord): boolean {
  return requester.principal.kind === "member" || deviceCovers(requester.principal, item, "relay")
}

type ConnectRequest = z.infer<typeof ConnectCreate>

function createConnect(ctx: VaultContext, requester: Requester, req: ConnectRequest): ConnectCreated {
  const principal = requester.principal
  const provider = getOAuthProvider(req.provider)
  if (!provider) throw new VaultError("bad_request", `Unknown provider "${req.provider}". Known: ${Object.keys(OAUTH_PROVIDERS).join(", ")}.`)
  const clientSlug = req.client ?? (req.requestClient ? provider.clientTemplate : null)
  if (clientSlug === null) {
    throw new VaultError("bad_request", "Name the OAuth client item (mehen connect --client), or set requestClient: true (mehen connect --request-client) to ask a human for one along with this connection.", {
      next: { say: `Ask a human for the ${provider.displayName} OAuth client, or ask for it together with the connection.` },
    })
  }
  const client = items.getItem(ctx, clientSlug)
  // The chain: no item of that name yet, and the device asked for one.
  const chained = client === null && req.requestClient === true
  if (!chained) {
    if (!client || client.kind !== "oauth-client" || client.provider !== provider.clientTemplate) throw clientMissing(ctx, clientSlug, provider, req.reason)
    if (client.status !== "active") throw new VaultError("forbidden", `The OAuth client "${client.slug}" is not usable (${client.status}).`)
    if (!covers(requester, client)) throw new VaultError("forbidden", `This machine's scope does not cover the OAuth client "${client.slug}".`)
  } else if (principal.kind === "device" && principal.scope.tags.length > 0 && !(req.clientTags ?? []).some((tag) => principal.scope.tags.includes(tag))) {
    // The connection will carry the client's tags, so a client this machine
    // cannot use would make a connection it cannot use either.
    throw new VaultError("bad_request", `This machine's scope covers only items tagged ${principal.scope.tags.join(", ")}; give the OAuth client one of those tags (clientTags) so this machine can use it.`)
  }
  let expectSubject: string | null = null
  let expectTenant: string | null = null
  let expect = req.expect ?? null
  let conn: ConnectionRow | null = null
  const existing = items.getItem(ctx, req.slug)
  if (existing) {
    if (existing.kind !== "oauth-connection" || existing.provider !== provider.id) {
      throw new VaultError("conflict", `An item called "${req.slug}" already exists and is not a ${provider.displayName} connection. Pick another name.`)
    }
    if (!covers(requester, existing)) throw new VaultError("forbidden", `This machine's scope does not cover "${existing.slug}".`)
    conn = getConnection(ctx, existing.id)
    if (conn) {
      expectSubject = conn.subject
      expectTenant = conn.provider_tenant
      expect = conn.label
    }
  }
  // A reconnect that names no scopes asks for what the connection already
  // has, never the provider's defaults: a reconnect must not widen a grant
  // nobody asked to widen. Explicit scopes go through the same check as a
  // first connect, and the page shows where they differ.
  const scopes: string[] = []
  for (const s of req.scopes ?? (conn ? connectionScopes(ctx, provider, conn) : provider.auth.scopes.defaults)) {
    const scope = normaliseScope(provider, s)
    if (scope === null) {
      const short = provider.auth.scopes.allowed.map((a) => (provider.auth.scopes.shortPrefix ? a.replace(provider.auth.scopes.shortPrefix, "") : a))
      throw new VaultError("bad_request", `"${s}" is not a scope ${provider.displayName} connections may ask for. Allowed: ${short.join(", ")}.`)
    }
    if (!scopes.includes(scope)) scopes.push(scope)
  }
  const shape: ConnectShape = { provider: provider.id, client: clientSlug, scopes: [...scopes].sort(), expect, expectSubject, expectTenant, chained, clientTags: chained ? tagSet(req.clientTags ?? []) : [] }
  const open = openConnectFor(ctx, requester, req.slug)
  if (open && !req.fresh) {
    if (canonicalJson(shapeOf(open, resolve(ctx, open).chain)) !== canonicalJson(shape)) {
      const url = connectUrl(ctx, open.id)
      const expiresAt = new Date(resolve(ctx, open).expiresAt).toISOString()
      if (principal.kind === "member") {
        throw new VaultError("conflict", `You already asked to connect "${req.slug}" with other details (request ${open.id}, open until ${expiresAt}).`, {
          next: { url, say: "Open that request to finish it, or let it run out and start again here." },
          expiresAt,
        })
      }
      throw new VaultError("conflict", `This machine already asked to connect "${req.slug}" with other details (request ${open.id}, open until ${expiresAt}). Wait for that one, or repeat this request with fresh: true (mehen connect --new) to replace it.`, {
        next: { url, command: `mehen wait ${open.id}`, say: `A request to connect "${req.slug}" is already waiting for you at ${url}. If the agent needs something different it will ask again with a new link.` },
        expiresAt,
      })
    }
    ctx.audit({ actor: actorOf(principal), action: "oauth.connect_reuse", target: req.slug, detail: { connect: open.id } })
    supersedeOthers(ctx, requester, req.slug, open.id)
    return createdOf(ctx, open)
  }
  // Superseding or adding a link: refused while a human is finishing one.
  const busy = finishingFor(ctx, requester, req.slug)
  if (busy) throw finishingNow(busy)
  const id = randomId("con")
  let chain: NewConnect["chain"]
  if (chained) {
    const intake = intakes.createForConnect(ctx, requester, {
      slug: clientSlug,
      provider: provider.clientTemplate,
      reason:
        principal.kind === "device"
          ? `An OAuth client so the agent can connect ${provider.displayName}${expect ? ` as ${expect}` : ""} ("${req.slug}"): ${req.reason}`
          : `An OAuth client so the vault can connect ${provider.displayName}${expect ? ` as ${expect}` : ""} ("${req.slug}"). ${req.reason}`,
      tags: req.clientTags ?? [],
      connect: id,
      fresh: req.fresh === true,
    })
    chain = { id, intake: intake.intake, expiresAt: Date.parse(intake.expiresAt) }
  }
  const created = insertConnect(ctx, {
    provider,
    client: clientSlug,
    slug: req.slug,
    scopes,
    expect,
    expectSubject,
    expectTenant,
    reason: req.reason,
    device: requester.key,
    deviceName: requester.name,
    session: requester.session,
    ...(chain ? { chain } : {}),
  })
  // Last, so a refusal above leaves the older links untouched.
  supersedeOthers(ctx, requester, req.slug, created.id)
  ctx.audit({
    actor: actorOf(principal),
    action: "oauth.connect_create",
    target: req.slug,
    detail: { connect: created.id, provider: provider.id, reconnect: expectSubject !== null, ...(chain ? { intake: chain.intake } : {}) },
  })
  return createdOf(ctx, getConnect(ctx, created.id) as ConnectRow)
}

// A chained connect may only start once its own intake has saved the client
// it was created against: the same slug, through that intake and no other.
function requireChainComplete(ctx: VaultContext, row: ConnectRow, resolved: Resolved, provider: OAuthProviderTemplate): void {
  if (row.intake === null) return
  const chain = resolved.chain
  const again = { say: `Ask the agent to request the ${provider.displayName} connection "${row.slug}" again.` }
  if (chain === null || chain.status === "cancelled") {
    throw new VaultError("conflict", `The request for the OAuth client "${row.client}" was cancelled, so this connection cannot be made. Ask the agent for a new link.`, { next: again })
  }
  if (chain.status === "expired") {
    throw new VaultError("conflict", `The request for the OAuth client "${row.client}" expired before it was filled in, so this connection cannot be made. Ask the agent for a new link.`, { next: again })
  }
  if (chain.status === "open") {
    throw new VaultError("conflict", `The OAuth client "${row.client}" has not been added yet. Fill in the credential request first; it leads straight back here.`, {
      next: { url: chain.url, say: `Add the ${provider.displayName} OAuth client at ${chain.url} first, then this connection can start.` },
      expiresAt: new Date(chain.expiresAt).toISOString(),
    })
  }
  if (chain.item !== row.client) {
    throw new VaultError("conflict", `The credential request this connection waits for saved a different item, so this connection cannot be made. Ask the agent for a new link.`, { next: again })
  }
}

async function startConnect(ctx: VaultContext, principal: MemberPrincipal, input: unknown) {
  const req = parseInput(ConnectStartInput, input)
  const row = getConnect(ctx, req.connect)
  if (!row) throw new VaultError("not_found", "No such connect link.")
  const provider = providerOf(row.provider)
  const resolved = resolve(ctx, row)
  requireChainComplete(ctx, row, resolved, provider)
  if (resolved.status !== "open") throw new VaultError("conflict", `This connect link is ${resolved.status}. Ask the agent for a new one.`)
  const client = items.getItem(ctx, row.client)
  if (!client || client.kind !== "oauth-client" || client.provider !== provider.clientTemplate) throw new VaultError("conflict", `The OAuth client "${row.client}" no longer exists.`)
  if (client.status !== "active") throw new VaultError("conflict", `The OAuth client "${row.client}" is not usable (${client.status}).`)
  if (clientBroken(ctx, client)) throw clientBrokenError(ctx, client.slug, provider)
  const clientId = client.publicFields.client_id
  if (!clientId) throw new VaultError("conflict", `The OAuth client "${row.client}" has no client ID.`)

  const verifier = randomToken(32)
  const challenge = base64UrlEncode(await sha256(verifier))
  const sealed = await ctx.sealField(verifierRef(row.id), new Uint8Array(new TextEncoder().encode(verifier)))
  const stateHash = await sha256Text(req.state)
  const now = ctx.now()
  const stateExpiresAt = now + CONNECT_TTL_MS
  const started = ctx.sql.exec(
    "UPDATE oauth_connects SET member = ?, state_hash = ?, state_expires_at = ?, verifier_root = ?, verifier_dek = ?, verifier_ct = ? WHERE id = ? AND status = 'open'",
    principal.member,
    stateHash,
    stateExpiresAt,
    sealed.rootVersion,
    sealed.wrappedDek,
    sealed.ciphertext,
    row.id,
  ).rowsWritten
  if (started === 0) throw new VaultError("conflict", "This connect link is no longer open. Ask the agent for a new one.")
  const scopes = provider.auth.scopes
  const requested = [...new Set([...scopes.identity, ...(JSON.parse(row.scopes) as string[]), ...(scopes.offline ? [scopes.offline] : [])])]
  const url = new URL(provider.auth.authorizeUrl)
  url.searchParams.set("response_type", "code")
  url.searchParams.set("client_id", clientId)
  url.searchParams.set("redirect_uri", `${ctx.env.VAULT_ORIGIN}/oauth/callback`)
  url.searchParams.set(scopes.param, requested.join(scopes.separator))
  url.searchParams.set("state", req.state)
  if (provider.auth.pkce === "S256") {
    url.searchParams.set("code_challenge", challenge)
    url.searchParams.set("code_challenge_method", "S256")
  }
  for (const [k, v] of Object.entries(provider.auth.authorizeParams ?? {})) url.searchParams.set(k, v)
  if (provider.auth.accountHint && row.expect) url.searchParams.set(provider.auth.accountHint.param, row.expect)
  ctx.audit({ actor: actorOf(principal), action: "oauth.connect_start", target: row.slug, detail: { connect: row.id } })
  return { authorizeUrl: url.href, stateExpiresAt }
}

// Settles an open connect. False when the row was no longer open, so the
// caller decides whether that is a conflict (a completion) or old news (a
// failure written for a row something else already closed).
// Settles the finish that holds the claim. False when the row is no longer
// `saving`: recovery resolved it meanwhile, and its outcome stands. A
// completion also settles a row recovery handed back open, since what it
// was waiting for is now stored.
function finishWith(ctx: VaultContext, id: string, status: ConnectStatus["status"], message: string, extra: { account?: string; scopes?: string[] } = {}): boolean {
  const written = ctx.sql.exec(
    `UPDATE oauth_connects SET status = ?, message = ?, account = COALESCE(?, account), granted_scopes = COALESCE(?, granted_scopes), completed_at = ?, claimed_at = NULL
     WHERE id = ? AND (status = 'saving' OR (status = 'open' AND ? = 'completed'))`,
    status,
    message,
    extra.account ?? null,
    extra.scopes ? JSON.stringify(extra.scopes) : null,
    ctx.now(),
    id,
    status,
  ).rowsWritten
  ctx.unschedule("oauth", savingKey(id))
  // Index writes count too, so anything above zero is the row.
  return written > 0
}

// Hands a claimed row back open: the sign-in itself went fine but the
// connection could not be stored, so the human starts it again.
function handBack(ctx: VaultContext, id: string, message: string): void {
  ctx.sql.exec("UPDATE oauth_connects SET status = 'open', message = ?, account = NULL, granted_scopes = NULL, claimed_at = NULL WHERE id = ? AND status = 'saving'", message, id)
  ctx.unschedule("oauth", savingKey(id))
}

// Thrown after a store failure: the finish reports it without failing the row.
class StoreFailed extends Error {
  constructor(readonly reason: unknown) {
    super("connection not stored")
  }
}

async function finishConnect(ctx: VaultContext, principal: MemberPrincipal, input: unknown): Promise<ConnectStatus> {
  const req = parseInput(ConnectFinishInput, input)
  const row = getConnect(ctx, req.connect)
  if (!row) throw new VaultError("not_found", "No such connect link.")
  if (row.member !== principal.member) throw new VaultError("forbidden", "This sign-in was started by someone else. Open the connect link and start again yourself.")
  if (row.state_hash === null || row.state_hash !== (await sha256Text(req.state))) {
    throw new VaultError("forbidden", "This sign-in does not match the connect link. Open the connect link and start again.")
  }
  if (row.status === "saving") throw new VaultError("conflict", "This sign-in is already being finished.")
  const status = effectiveStatus(ctx, row)
  if (status !== "open") throw new VaultError("conflict", `This connect link is ${status}. Ask the agent for a new one.`)
  // The claim, in the same synchronous step as the check above, and single
  // use: the state and the verifier are gone before any network call. While
  // `saving` the row reads as open to everyone else and nobody may close
  // it; the outcome is written only once known, a store failure hands the
  // row back, and a claim left behind by a dead isolate is resolved from
  // what was stored (resolveStale, also from the alarm).
  const claimedAt = ctx.now()
  const claimed = ctx.sql.exec(
    "UPDATE oauth_connects SET status = 'saving', claimed_at = ?, state_hash = NULL, verifier_root = NULL, verifier_dek = NULL, verifier_ct = NULL WHERE id = ? AND status = 'open'",
    claimedAt,
    row.id,
  ).rowsWritten
  if (claimed === 0) throw new VaultError("conflict", "This connect link is no longer open; nothing was stored. Ask the agent for its current link.")
  ctx.schedule("oauth", savingKey(row.id), claimedAt + SAVING_STALE_MS)
  const provider = providerOf(row.provider)
  if (req.error !== null || req.code === null) {
    finishWith(ctx, row.id, "failed", `The sign-in at ${provider.displayName} was cancelled or refused. Ask the agent for a new link to try again.`)
    return connectStatusOf(ctx, getConnect(ctx, row.id) as ConnectRow)
  }
  try {
    await completeConnect(ctx, principal, row, provider, req.code)
  } catch (error) {
    if (error instanceof StoreFailed) {
      if (!(error.reason instanceof VaultError)) console.error(JSON.stringify({ at: "oauth.store", provider: provider.id, error: error.reason instanceof Error ? error.reason.name : "unknown" }))
      handBack(ctx, row.id, `${INTERRUPTED_MESSAGE} Start it again.`)
    } else {
      const message = error instanceof VaultError ? error.message : "Something went wrong while finishing the connection. Ask the agent for a new link."
      if (!(error instanceof VaultError)) console.error(JSON.stringify({ at: "oauth.finish", provider: provider.id, error: error instanceof Error ? error.name : "unknown" }))
      finishWith(ctx, row.id, "failed", message)
    }
  }
  return connectStatusOf(ctx, getConnect(ctx, row.id) as ConnectRow)
}

async function completeConnect(ctx: VaultContext, principal: MemberPrincipal, row: ConnectRow, provider: OAuthProviderTemplate, code: string): Promise<void> {
  if (row.verifier_root === null || row.verifier_dek === null || row.verifier_ct === null) throw new VaultError("conflict", "This sign-in was never started from the connect page.")
  const verifier = new TextDecoder().decode(
    await ctx.openField(verifierRef(row.id), { rootVersion: row.verifier_root, wrappedDek: blob(row.verifier_dek), ciphertext: blob(row.verifier_ct) }),
  )
  const client = items.getItem(ctx, row.client)
  if (!client || client.kind !== "oauth-client" || client.provider !== provider.clientTemplate) throw new VaultError("conflict", `The OAuth client "${row.client}" no longer exists.`)
  const clientSecret = (await items.openSecrets(ctx, client)).client_secret ?? ""
  const params: Record<string, string> = { grant_type: "authorization_code", code, redirect_uri: `${ctx.env.VAULT_ORIGIN}/oauth/callback` }
  if (provider.auth.pkce === "S256") params.code_verifier = verifier
  const tokens = await tokenRequest(provider, client, clientSecret, params)
  if (tokens.kind === "oauth_error" && provider.refresh.clientErrors.includes(tokens.code)) {
    markClientBroken(ctx, client, provider)
    throw clientBrokenError(ctx, client.slug, provider)
  }
  if (tokens.kind !== "ok") throw new VaultError("upstream_failed", `${provider.displayName} did not accept the sign-in. Ask the agent for a new link and try again.`)

  // A grant wider than the ask is not kept: nothing is probed, stored or
  // touched, the token goes back where it came from if it can, and the
  // link fails with the reason. The existing item and connection stand.
  const asked = JSON.parse(row.scopes) as string[]
  const wider = grantedBeyond(provider, asked, tokens.scopes)
  if (wider.length > 0) {
    const revoked = await revokeToken(provider, tokens.accessToken)
    const short = provider.auth.scopes.shortPrefix
    const names = wider.map((s) => (short !== undefined ? s.replace(short, "") : s))
    ctx.audit({ actor: actorOf(principal), action: "oauth.connect_wider", target: row.slug, detail: { connect: row.id, provider: provider.id, wider: names, revoked } })
    throw new VaultError("forbidden", `${provider.displayName} granted more access than this connection asked for (${names.join(", ")}), so nothing was saved and nothing was changed. Try again; if it happens again, remove this app's access in your ${provider.displayName} account first.`)
  }

  const identity = await probeIdentity(provider, tokens.accessToken, tokens.body)
  if (typeof identity === "string") throw new VaultError("upstream_failed", `${provider.displayName} did not say which account signed in, so nothing was stored. Try again.`)
  const pinned = row.expect_subject !== null
  const subjectMismatch = pinned && (identity.subject !== row.expect_subject || (row.expect_tenant ?? null) !== (identity.tenant ?? null))
  const labelMismatch = !pinned && row.expect !== null && row.expect.toLowerCase() !== identity.label.toLowerCase()
  if (subjectMismatch || labelMismatch) {
    finishWith(ctx, row.id, "mismatch", `You signed in to ${provider.displayName} as ${identity.label}, but this link was for ${row.expect ?? "another account"}. Nothing was stored or changed. Sign in as ${row.expect ?? "the expected account"} and ask the agent for a new link, or ask it to connect ${identity.label} under a new name.`, { account: identity.label })
    ctx.audit({ actor: actorOf(principal), action: "oauth.connect_mismatch", target: row.slug, detail: { connect: row.id, provider: provider.id } })
    return
  }

  const existing = items.getItem(ctx, row.slug)
  if (existing && (existing.kind !== "oauth-connection" || existing.provider !== provider.id)) throw new VaultError("conflict", `"${row.slug}" is now a different kind of item; nothing was stored.`)
  const priorConn = existing ? getConnection(ctx, existing.id) : null
  if (existing && priorConn && !pinned) throw new VaultError("conflict", `"${row.slug}" was connected meanwhile; ask the agent for a reconnect link.`)
  let refreshToken = tokens.refreshToken
  if (refreshToken === null && existing) refreshToken = (await items.openSecrets(ctx, existing)).refresh_token ?? null
  const secretFields: Record<string, string> = { access_token: tokens.accessToken }
  if (refreshToken !== null) secretFields.refresh_token = refreshToken
  const granted = tokens.scopes ?? (JSON.parse(row.scopes) as string[])
  // The store, under the claim. The item lands first (its own transaction,
  // after sealing); the connection row is then written with it in one
  // transaction, and if that fails a new item is removed again so nothing
  // half-stored stays behind. Completion is written last.
  let stored: ItemRecord
  try {
    stored = await items.putItem(
      ctx,
      {
        slug: row.slug,
        kind: "oauth-connection",
        provider: provider.id,
        account: identity.label,
        accountVerified: true,
        tags: existing?.tags ?? client.tags,
        ceiling: existing?.ceiling ?? KINDS["oauth-connection"].defaultCeiling,
        binding: existing?.binding ?? provider.upstream.binding,
        policy: existing?.policy ?? connectionPolicy(provider),
        injection: existing?.injection ?? provider.upstream.injection,
        publicFields: {},
        secretFields,
        description: existing?.description ?? `${provider.displayName} for ${identity.label}`,
      },
      principal,
      { replace: existing !== null },
    )
  } catch (error) {
    throw new StoreFailed(error)
  }
  const now = ctx.now()
  try {
    ctx.storage.transactionSync(() => {
      // A connection row left by an item of this slug that is gone (deleted
      // before deletes cleaned up) would clash on the slug: it is stale.
      for (const stale of ctx.sql.exec<{ item: string }>("SELECT item FROM oauth_connections WHERE slug = ? AND item != ?", stored.slug, stored.id).toArray()) {
        ctx.sql.exec("DELETE FROM oauth_connections WHERE item = ?", stale.item)
        ctx.unschedule("oauth", `refresh:${stale.item}`)
      }
      ctx.sql.exec(
        `INSERT INTO oauth_connections (item, slug, provider, client, subject, provider_tenant, label, state, reason, scopes, access_expires_at, refresh_expires_at,
           connected_at, last_refresh_at, last_access_at, failures, failure_days, device, device_name)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'active', NULL, ?, ?, ?, ?, ?, NULL, 0, 0, ?, ?)
         ON CONFLICT (item) DO UPDATE SET slug = excluded.slug, provider = excluded.provider, client = excluded.client, subject = excluded.subject, provider_tenant = excluded.provider_tenant,
           label = excluded.label, state = 'active', reason = NULL, scopes = excluded.scopes, access_expires_at = excluded.access_expires_at,
           refresh_expires_at = excluded.refresh_expires_at, connected_at = excluded.connected_at, last_refresh_at = excluded.last_refresh_at, last_access_at = NULL,
           attempt_id = NULL, attempt_started_at = NULL, attempt_rt = NULL, failures = 0, failure_days = 0, failure_day = NULL, retry_at = NULL`,
        stored.id,
        stored.slug,
        provider.id,
        client.slug,
        identity.subject,
        identity.tenant,
        identity.label,
        JSON.stringify(granted),
        tokens.expiresIn === null ? null : now + tokens.expiresIn * 1000,
        tokens.refreshExpiresIn === null ? null : now + tokens.refreshExpiresIn * 1000,
        now,
        now,
        row.device,
        row.device_name,
      )
      reschedule(ctx, stored.id)
      if (!finishWith(ctx, row.id, "completed", `Connected ${provider.displayName} for ${identity.label} as "${stored.slug}".`, { account: identity.label, scopes: granted })) {
        // The finish outlived its claim and the row was closed for good
        // meanwhile; the connection is in place either way.
        ctx.audit({ actor: actorOf(principal), action: "oauth.connect_late", target: stored.slug, detail: { connect: row.id } })
      }
    })
  } catch (error) {
    if (!existing) items.deleteItem(ctx, stored, principal)
    throw new StoreFailed(error)
  }
  ctx.audit({ actor: actorOf(principal), action: pinned ? "oauth.reconnect" : "oauth.connect", target: stored.slug, detail: { connect: row.id, provider: provider.id } })
}

// Called when an oauth-connection item is deleted: its connection row and
// refresh schedule go with it, so a later connect under the slug starts clean.
export function forgetConnection(ctx: VaultContext, item: ItemRecord): void {
  ctx.sql.exec("DELETE FROM oauth_connections WHERE item = ? OR slug = ?", item.id, item.slug)
  ctx.unschedule("oauth", `refresh:${item.id}`)
}

// POST /api/connect: a member connects an account from Connect a service,
// or reconnects one from its item page. Only a built-in provider, by id:
// the hosts, policy and injection are the provider's. Scopes, when named,
// are the ones the member ticked on the start sheet for a new connection
// and pass the same allowed-set check as a device's; left out, it asks for
// the provider's defaults. A reconnect from here never names scopes: it
// asks for what the connection holds, so it cannot widen the grant.
// Strict, so a body that tries to name a reason or a session is refused
// rather than ignored.
export const MemberConnectCreate = z.strictObject({
  provider: z.string().max(64),
  slug: Slug,
  client: Slug.optional(),
  scopes: z.array(z.string().max(200)).min(1).max(50).optional(),
  expect: z.string().max(320).optional(),
  requestClient: z.boolean().optional(),
  clientTags: z.array(Tag).max(16).optional(),
  fresh: z.boolean().optional(),
})

// The same principal rule as the connect page: any signed-in member of the
// tenant (connectView, connectStart and connectFinish are auth member). No
// step-up: nothing is approved or stored here; the connect page signs in.
function createConnectByMember(ctx: VaultContext, principal: MemberPrincipal, input: unknown): ConnectCreated {
  const req = parseInput(MemberConnectCreate, input)
  if (!getOAuthProvider(req.provider)) {
    throw new VaultError("bad_request", `"${req.provider}" is not a built-in OAuth provider. Known: ${Object.keys(OAUTH_PROVIDERS).join(", ")}.`)
  }
  const existing = items.getItem(ctx, req.slug)
  const reconnect = existing !== null && existing.kind === "oauth-connection" && existing.provider === req.provider ? existing : null
  if (reconnect !== null && req.scopes !== undefined) {
    throw new VaultError("bad_request", `"${req.slug}" is already connected, and reconnecting it keeps the permissions it has. Leave the scopes out to reconnect it, or connect under a new name.`)
  }
  // A reconnect that names no client signs in through the connection's own.
  const client = req.client ?? (req.requestClient || reconnect === null ? undefined : getConnection(ctx, reconnect.id)?.client)
  return createConnect(ctx, requesterOf(principal), {
    provider: req.provider,
    slug: req.slug,
    reason: MEMBER_REASON,
    ...(client !== undefined ? { client } : {}),
    ...(req.scopes !== undefined ? { scopes: req.scopes } : {}),
    ...(req.expect !== undefined && req.expect !== "" ? { expect: req.expect } : {}),
    ...(req.requestClient !== undefined ? { requestClient: req.requestClient } : {}),
    ...(req.clientTags !== undefined ? { clientTags: req.clientTags } : {}),
    ...(req.fresh !== undefined ? { fresh: req.fresh } : {}),
  })
}

function viewConnect(ctx: VaultContext, principal: Principal, input: unknown): ConnectView {
  const req = parseInput(ConnectIdInput, input)
  const row = getConnect(ctx, req.connect)
  if (!row) throw new VaultError("not_found", "No such connect link.")
  const provider = providerOf(row.provider)
  const { status, expiresAt, chain, message } = resolve(ctx, row)
  // A reconnect is pinned to the connection's subject; the connection it
  // would replace is read now, so the page compares against what is held.
  const reconnect = row.expect_subject !== null
  const existing = reconnect ? items.getItem(ctx, row.slug) : null
  const current = existing && existing.kind === "oauth-connection" ? getConnection(ctx, existing.id) : null
  return {
    connect: row.id,
    status,
    provider: provider.id,
    providerName: provider.displayName,
    slug: row.slug,
    scopes: JSON.parse(row.scopes) as string[],
    expect: row.expect,
    reason: row.reason,
    requestedBy: requestedByOf(row, principal),
    reconnect,
    currentScopes: current ? connectionScopes(ctx, provider, current) : null,
    account: row.account,
    message,
    expiresAt: new Date(expiresAt).toISOString(),
    ...(row.intake !== null && chain ? { awaiting: { intake: row.intake, url: chain.url, status: chain.status } } : {}),
  }
}

export const oauthArea: Area = {
  name: "oauth",
  get migrations() { return [...oauthMigrations,workspaceOAuthMigration,workspaceOAuthClientRejectionMigration] },
  get workspaceOps() { return { ...credentialOps(workspaceOAuthOps), ...platformOAuthOps } },
  async alarm(ctx, key) {
    if(key.startsWith("workspace-refresh:")){
      // A managed workspace's scheduled refreshes wait while its platform
      // is suspended, or cannot be read (D0 1.5).
      if (await managedWorkWaits(ctx)) {
        ctx.schedule("oauth", key, ctx.now() + SUSPENDED_REFRESH_WAIT_MS)
        return
      }
      const id=key.slice("workspace-refresh:".length)
      const slug=one(ctx.sql.exec<{slug:string}>("SELECT slug FROM items WHERE id=?",id))?.slug
      const item=slug?checkedCredential(ctx,slug):null
      // A connection that needs a person, or waits to retry (it has
      // rescheduled itself), is done here; any other refusal (an edit racing
      // the refresh) is retried by the scheduler's back-off. A wait for an
      // attempt still in flight (one an edit raced) schedules nothing
      // itself, so it is scheduled here for when that attempt has ended.
      if(item&&item.status!=="disabled"&&item.status!=="needs_reauth")await workspaceAccessToken(ctx,item).catch((error:unknown)=>{
        if(!(error instanceof VaultError)||(error.code!=="needs_reauth"&&error.code!=="refresh_retrying"))throw error
        const retryAfter=error.extra.retryAfter
        if(error.code==="refresh_retrying"&&retryAfter!==undefined&&!one(ctx.sql.exec("SELECT 1 FROM schedule WHERE area='oauth' AND key=?",key)))ctx.schedule("oauth",key,ctx.now()+retryAfter*1000)
      })
      return
    }
    // `connect:<id>`: resolves a claim its finish never settled.
    if (key.startsWith("connect:")) {
      const row = getConnect(ctx, key.slice("connect:".length))
      if (row?.status === "saving" && row.claimed_at !== null) ctx.schedule("oauth", key, row.claimed_at + SAVING_STALE_MS)
      return
    }
    if (!key.startsWith("refresh:")) return
    const conn = getConnection(ctx, key.slice("refresh:".length))
    if (!conn) return
    const item = items.getItem(ctx, conn.slug)
    if (!item || item.id !== conn.item) return
    const provider = providerOf(conn.provider)
    const due = nextDue(conn, provider)
    if (due === null) return
    if (due > ctx.now()) {
      reschedule(ctx, item.id)
      return
    }
    const hasRefresh = (await items.openSecrets(ctx, item)).refresh_token !== undefined
    try {
      if (hasRefresh) await singleFlight(ctx, item)
      else await keepAlive(ctx, item, conn, provider)
    } catch (error) {
      // Refusals are recorded on the connection and rescheduled as needed.
      if (!(error instanceof VaultError)) throw error
    }
  },
}
