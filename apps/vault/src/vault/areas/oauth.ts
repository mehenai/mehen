// Talking to an OAuth provider for the workspace connections
// (oauth-workspace.ts): the token request, the identity probe, the scope
// check and best-effort revocation. Its area carries the workspace
// connections' migration and their scheduled refreshes.

import { type OAuthExchange, type OAuthProviderTemplate, base64UrlDecode, checkBinding, normaliseScope, parseDestination } from "@mehen/protocol"
import { VaultError } from "../../http.ts"
import { upstreamFetch } from "../../relay/upstream.ts"
import { type Area, one } from "../core.ts"
import type { ItemRecord } from "../services.ts"
import { checkedCredential, credentialOps } from "./items-workspace.ts"
import { platformOAuthOps, workspaceAccessToken, workspaceOAuthClientRejectionMigration, workspaceOAuthMigration, workspaceOAuthOps } from "./oauth-workspace.ts"
import { managedWorkWaits } from "../managed-platform.ts"

const UPSTREAM_TIMEOUT_MS = 15_000
const USER_AGENT = "mehen"
const BACKOFF_MIN_MS = 30_000
const BACKOFF_MAX_MS = 3_600_000
// How long a managed workspace's scheduled refresh waits before it looks at
// its platform's status again.
const SUSPENDED_REFRESH_WAIT_MS = 5 * 60_000

// The first three made the tables of single-tenant connections, which no
// workspace ever wrote; they stay so every workspace's migration count
// holds, and a later one (DROP_SINGLE_TENANT_TABLES) drops those tables.

const oauthMigrations = [
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

const DROP_SINGLE_TENANT_TABLES = `DROP TABLE IF EXISTS oauth_connects;
DROP TABLE IF EXISTS oauth_connections;
DROP TABLE IF EXISTS oauth_clients;`

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
// still count towards the four failing days that put a connection in front
// of a person. Null when absent, unreadable or already past.
const RETRY_AFTER_MAX_SECONDS = 86_400
function retryAfterOf(header: string | null, now: number): number | null {
  if (header === null || header.trim() === "") return null
  const seconds = Number(header)
  if (Number.isFinite(seconds)) return seconds > 0 ? Math.min(seconds, RETRY_AFTER_MAX_SECONDS) : null
  const until = Date.parse(header)
  return Number.isFinite(until) && until > now ? Math.min(Math.ceil((until - now) / 1000), RETRY_AFTER_MAX_SECONDS) : null
}

// How long to wait after the nth refresh failure in a row: doubling from
// 30 s to an hour, with 20% jitter either way, or longer if the provider
// asked (Retry-After, in seconds or as a date, up to a day).
export function refreshRetryWaitMs(failures: number, retryAfter: number | null): number {
  const backoff = Math.min(BACKOFF_MIN_MS * 2 ** (failures - 1), BACKOFF_MAX_MS) * (0.8 + Math.random() * 0.4)
  return Math.max(backoff, (retryAfter ?? 0) * 1000)
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

// Quotes one word for a POSIX shell, so a printed command runs as printed.
export function shellQuote(word: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(word) ? word : `'${word.replaceAll("'", `'\\''`)}'`
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

export const oauthArea: Area = {
  name: "oauth",
  get migrations() { return [...oauthMigrations, workspaceOAuthMigration, DROP_SINGLE_TENANT_TABLES, workspaceOAuthClientRejectionMigration] },
  get workspaceOps() { return { ...credentialOps(workspaceOAuthOps), ...platformOAuthOps } },
  async alarm(ctx, key) {
    if (!key.startsWith("workspace-refresh:")) return
    // A managed workspace's scheduled refreshes wait while its platform
    // is suspended, or cannot be read.
    if (await managedWorkWaits(ctx)) {
      ctx.schedule("oauth", key, ctx.now() + SUSPENDED_REFRESH_WAIT_MS)
      return
    }
    const id = key.slice("workspace-refresh:".length)
    const slug = one(ctx.sql.exec<{ slug: string }>("SELECT slug FROM items WHERE id=?", id))?.slug
    const item = slug ? checkedCredential(ctx, slug) : null
    // A connection that needs a person, or waits to retry (it has
    // rescheduled itself), is done here; any other refusal (an edit racing
    // the refresh) is retried by the scheduler's back-off. A wait for an
    // attempt still in flight (one an edit raced) schedules nothing itself,
    // so it is scheduled here for when that attempt has ended.
    if (item && item.status !== "disabled" && item.status !== "needs_reauth") await workspaceAccessToken(ctx, item).catch((error: unknown) => {
      if (!(error instanceof VaultError) || (error.code !== "needs_reauth" && error.code !== "refresh_retrying")) throw error
      const retryAfter = error.extra.retryAfter
      if (error.code === "refresh_retrying" && retryAfter !== undefined && !one(ctx.sql.exec("SELECT 1 FROM schedule WHERE area='oauth' AND key=?", key))) ctx.schedule("oauth", key, ctx.now() + retryAfter * 1000)
    })
  },
}
