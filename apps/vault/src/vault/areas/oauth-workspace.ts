import { z } from "zod"
import { askingWorkload, assertWorkloadMayConnect, assertWorkloadMayFollow } from "./workloads.ts"
import { CUSTOM_OAUTH_PROVIDER_ID, CredentialHomeSchema, CustomOAuthProviderSchema, KINDS, PLATFORM_CONNECT_TTL_SECONDS, PlatformConnectFinishSchema, PlatformConnectStartSchema, base64UrlDecode, base64UrlEncode, canonicalJson, connectionPolicy, customItemPolicy, customOAuthExchange, getOAuthProvider, normaliseScope, sha256, type CredentialHome, type CustomOAuthProvider, type OAuthExchange, type OAuthProviderTemplate, type PlatformConnectFinished, type PlatformConnectStarted, type WorkspaceStepUpAction, type WorkspaceConnectView } from "@mehen/protocol"
import { WorkspaceConnectCreate, WorkspaceMemberConnectCreate, type ConnectCreated, type ConnectStatus } from "@mehen/protocol/api"
import { VaultError } from "../../http.ts"
import { randomToken, sha256Text } from "../../directory/session.ts"
import { can, type AccessPrincipal } from "../access.ts"
import { blob, one, randomId, type Area, type VaultContext } from "../core.ts"
import { items, parseOpInput } from "./items.ts"
import { tokenRequest, probeIdentity, grantedBeyond, reauthReasonAt, refreshRetryWaitMs, revokeToken } from "./oauth.ts"
import { cancelCredentialRequest, RequestWait, waitForCredentialRequest, createCredentialRequest, createWorkspaceIntake, requestAuthority, requestHome, requestOpen, requestRow, requestAudit, type CredentialRequest } from "./intake-workspace.ts"
import { assertCredentialCurrent, assertCredentialReservation, assertNameBudget, assertItemRight, checkedCredential, creationHome, credentialAccessState, credentialAudit, credentialCreationContext, describeCredential, openCredentialSecrets, prepareCredential, storeCredential, unavailableName, visibleCredential, type CheckedCredential, type PreparedCredential } from "./items-workspace.ts"
import { devicePolicyState } from "./devices.ts"
import { assertManagedConnectRoom, managedItemsFull, overLimit, subjectWrite } from "./managed.ts"
import { heldManagedPlatform, managedPolicyView } from "../managed-platform.ts"
import { managedSetting, nameMiss, queueNotice, recordExposure, requireStepUp, workspaceRef, type WorkspaceInvocationContext, type WorkspaceRuntimePrincipal } from "./workspace-runtime.ts"
type Flow = {
  requestItemId?: string
  fresh?: boolean
  reason: string
  session: string | null
  provider: string
  clientSlug: string
  client: CheckedCredential | null
  target: CheckedCredential | null
  scopes: string[]
  expect: string | null
  pinnedIdentity?:{subject:string;tenant:string|null}
  tags: string[]
  intake: string | null
  // Set on a connect the platform started (route 16): its own callback,
  // and the state's hash and sealed verifier from the same call.
  platform?: { redirectUri: string }
  platformStarted?: {
    stateHash: string
    pkce: boolean
    verifier: { root: number; dek: string; ct: string }
  }
  started?: {
    account: string
    session: string
    epoch: number
    member: string
    stateHash: string
    verifier: {
      root: number
      dek: string
      ct: string
    }
  }
}
type Connection = {
  item: string
  client: string
  member: string
  intent: "create" | "rotate"
  payload: string
  expires_at: number | null
}

export const workspaceOAuthMigration = `CREATE TABLE workspace_oauth_connections(item TEXT PRIMARY KEY,client TEXT NOT NULL,member TEXT NOT NULL,intent TEXT NOT NULL,payload TEXT NOT NULL,expires_at INTEGER);`

function providerOf(id: string): OAuthProviderTemplate { const p = getOAuthProvider(id); if (!p)
  throw new VaultError("bad_request", "Unknown OAuth provider."); return p; }

// The client's own provider definition (items.custom_provider, written by
// the platform's intake when the client is added and never changed), or
// null when it names a catalogue provider. Checked again at every connect
// and refresh, so a definition the current rules refuse is never used. The
// hosts are checked by name only, with no DNS resolution: this fetch runs
// in a Cloudflare Worker, which cannot reach a private network, so a
// public-looking name that resolves to a private address reaches nothing.
export function customProviderOf(ctx: VaultContext, client: string): CustomOAuthProvider | null {
  const stored = one(ctx.sql.exec<{ custom_provider: string | null }>("SELECT custom_provider FROM items WHERE id=?", client))?.custom_provider ?? null
  if (stored === null)
    return null
  const parsed = CustomOAuthProviderSchema.safeParse(JSON.parse(stored))
  if (!parsed.success)
    throw new VaultError("forbidden", "This OAuth client's provider definition is no longer accepted; add a new client.")
  return parsed.data
}

// The exchange a flow or a connection runs with: its catalogue provider, or
// its client's own definition.
function exchangeFor(ctx: VaultContext, provider: string, client: CheckedCredential): OAuthExchange {
  if (provider !== CUSTOM_OAUTH_PROVIDER_ID)
    return providerOf(provider)
  const definition = customProviderOf(ctx, client.id)
  if (!definition)
    throw new VaultError("not_found", "No usable OAuth client.")
  return customOAuthExchange(definition)
}

// The client template a flow's client must have been made from; null for a
// client carrying its own provider definition.
function clientTemplateOf(provider: string): string | null { return provider === CUSTOM_OAUTH_PROVIDER_ID ? null : providerOf(provider).clientTemplate; }

// What an audit row says about a custom provider: the token URL's host,
// never a token. A catalogue provider's rows are unchanged.
function exchangeAuditDetail(exchange: OAuthExchange): Record<string, string> {
  return exchange.id === CUSTOM_OAUTH_PROVIDER_ID ? { provider: CUSTOM_OAUTH_PROVIDER_ID, host: new URL(exchange.auth.tokenUrl).hostname } : {}
}

export function compatibleClientHome(client: CredentialHome, connection: CredentialHome): boolean { return client.kind === "workspace" || client.kind === "member" && connection.kind === "member" && client.member === connection.member || client.kind === "project" && connection.kind === "project" && client.project === connection.project; }

function clientFor(ctx: VaultContext, p: AccessPrincipal, slug: string, home: CredentialHome, clientTemplate: string | null, invocation: WorkspaceInvocationContext): CheckedCredential {
  const client = visibleCredential(ctx, p, slug, undefined, invocation)
  const kindMatches = clientTemplate === null ? client.provider === null && customProviderOf(ctx, client.id) !== null : client.provider === clientTemplate
  if (client.kind !== "oauth-client" || !kindMatches || client.status !== "active" || !compatibleClientHome(client.home, home))
    throw new VaultError("not_found", "No usable OAuth client.")
  return client
}

function flowOf(row: CredentialRequest): Flow { return JSON.parse(row.payload) as Flow; }

// A connect by id; an intake id answers as an absent request.
function connectRow(ctx: VaultContext, id: string): CredentialRequest {
  const row = requestRow(ctx, id)
  if (row.kind !== "connect") throw new VaultError("not_found", "No such credential request.")
  return row
}

function flowAuthority(ctx: VaultContext, p: AccessPrincipal, row: CredentialRequest, flow: Flow, i: WorkspaceInvocationContext, home = requestHome(row)) {
  // Visibility first: a hidden request in any state answers as an absent one.
  requestAuthority(ctx, p, row, i)
  requestOpen(ctx, row)
  if (flow.target && canonicalJson(home) !== canonicalJson(flow.target.home))
    throw new VaultError("bad_request", "Reconnection keeps the credential home.")
  const client = clientFor(ctx, p, flow.clientSlug, home, clientTemplateOf(flow.provider), i)
  if (flow.client)
    assertCredentialCurrent(ctx, flow.client)
  const decision = assertItemRight(ctx, i, flow.target ? { type: "credential.reconnect" } : { type: "credential.connect" }, flow.target ? { credential: flow.target.id, client: client.id } : { destinationHome: home, client: client.id })
  if (flow.target)
    assertCredentialCurrent(ctx, flow.target)
  return { client, decision }
}

export function connectStartAction(row: CredentialRequest, flow: Flow, client: CheckedCredential, home = requestHome(row)): WorkspaceStepUpAction {
  return { type: "connect.start", connect: row.id, provider: flow.provider, slug: row.slug, home, tags: flow.tags, expectedAccount: flow.expect, scopes: flow.scopes, intent: flow.target ? "rotate" : "create", target: flow.target?.id ?? null, targetRevision: flow.target?.configRev ?? null, client: client.id, clientRevision: client.configRev, dependencyRevision: flow.target?.dependencyRevision ?? 0 }
}

function createConnectRequest(ctx: VaultContext, p: AccessPrincipal, input: unknown, i: WorkspaceInvocationContext): ConnectCreated {
  const req = p.kind === "device" ? parseOpInput(WorkspaceConnectCreate, input) : parseOpInput(WorkspaceMemberConnectCreate, input)
  const provider = providerOf(req.provider)
  const clientSlug = req.client ?? provider.clientTemplate
  const home = creationHome(ctx, p, req.home, req.project)
  assertWorkloadMayConnect(ctx, p, req.slug, clientSlug, home)
  if (home.kind === "member")
    assertItemRight(ctx, i, { type: "credential.create" }, { destinationHome: home })
  assertNameBudget(ctx, p)
  let target: CheckedCredential | null = null
  if (checkedCredential(ctx, req.slug)) {
    try {
      target = visibleCredential(ctx, p, req.slug, undefined, i)
    }
    catch (e) {
      if (e instanceof VaultError && e.code === "not_found") {
        assertItemRight(ctx,i,{type:"credential.create"},{destinationHome:home})
        unavailableName(ctx, p)
      }
      throw e
    }
  }
  assertItemRight(ctx,i,target?{type:"credential.rotate"}:{type:"credential.create"},target?{credential:target.id}:{destinationHome:home})
  if (target && (target.kind !== "oauth-connection" || target.provider !== provider.id || canonicalJson(target.home) !== canonicalJson(home)))
    unavailableName(ctx, p)
  // The connection and (with requestClient) its client intake carry these tags.
  const tags = target?.tags ?? req.clientTags ?? []
  assertWorkloadMayFollow(ctx, p, { slug: req.slug, tags, home })
  let client: CheckedCredential | null = null
  let intake: Awaited<ReturnType<typeof createWorkspaceIntake>> | undefined
  if (req.requestClient && !checkedCredential(ctx, clientSlug))
    intake = createWorkspaceIntake(ctx, p, { ...(p.kind === "device" ? { kind: "oauth-client", reason: "OAuth client for this connection." } : {}), slug: clientSlug, provider: provider.clientTemplate, tags: req.clientTags ?? [], fresh: req.fresh, home: req.home, ...(req.project ? { project: req.project } : {}) }, i)
  else {
    try { client = clientFor(ctx, p, clientSlug, home, provider.clientTemplate, i) }
    catch (error) {
      if (req.requestClient && error instanceof VaultError && error.code === "not_found") unavailableName(ctx, p)
      throw error
    }
  }
  const previousIdentity=target?one(ctx.sql.exec<{payload:string}>("SELECT payload FROM workspace_oauth_connections WHERE item=?",target.id)):null
  const pin=previousIdentity?JSON.parse(previousIdentity.payload) as {subject:string;tenant:string|null;scopes?:string[]}:null
  // A reconnect keeps every scope the connection holds and adds those asked
  // for: it never drops one.
  const held = pin?.scopes?.length ? pin.scopes : null
  const asked = (req.scopes ?? (held ? [] : provider.auth.scopes.defaults)).map(s => { const normal = normaliseScope(provider, s); if (!normal)
    throw new VaultError("bad_request", "Unsupported scope."); return normal; })
  const allowed = new Set([...provider.auth.scopes.allowed, ...provider.auth.scopes.identity].map(s => normaliseScope(provider, s)))
  if (asked.some(s => !allowed.has(s)))
    throw new VaultError("bad_request", "A scope is outside this provider's allowed set.")
  const scopes = [...new Set([...(held ?? []).map(s => normaliseScope(provider, s)).filter((s): s is string => s !== null && allowed.has(s)), ...asked])]
  const flow: Flow = { reason: "reason" in req && typeof req.reason === "string" ? req.reason : "Started from Connect a service in the vault.", session: "session" in req && typeof req.session === "string" ? req.session : null, provider: provider.id, clientSlug, client, target, scopes, expect: target?.account??req.expect??null, tags, intake: intake?.intake ?? null,...(pin?{pinnedIdentity:{subject:pin.subject,tenant:pin.tenant}}:{}) }
  const row = createCredentialRequest(ctx, p, { kind: "connect", slug: req.slug, home, tags, payload: { ...flow, fresh: req.fresh }, target, ...(client ? { client } : {}), ttl: intake ? 86400000 : 900000 }, i)
  if (intake) {
    const child = requestRow(ctx, intake.intake)
    ctx.sql.exec("UPDATE workspace_credential_requests SET payload=? WHERE id=?", JSON.stringify({ ...JSON.parse(child.payload) as Record<string, unknown>, connect: row.id }), child.id)
  }
  return { connect: row.id, url: `${ctx.env.VAULT_ORIGIN}/w/${i.workspace.slug}/c/${row.id}`, expiresAt: new Date(row.expires_at).toISOString(), ...(intake ? { intake } : {}) }
}

export function createWorkspaceConnect(ctx: VaultContext, p: AccessPrincipal, input: unknown, i: WorkspaceInvocationContext): ConnectCreated {
  // One OAuth path in a managed workspace: the platform's (route 16).
  if (managedSetting(ctx))
    throw new VaultError("forbidden", "In a managed workspace the platform starts connections.")
  // A liveness gate before any namespace probe.
  assertItemRight(ctx, i, p.kind === "device" ? { type: "device.read_self" } : { type: "asks.read" }, p.kind === "device" ? { device: p.deviceId } : {})
  try {
    return ctx.storage.transactionSync(() => createConnectRequest(ctx, p, input, i))
  }
  catch (e) {
    if (e instanceof VaultError && e.code === "conflict" && e.message === "name not available")
      nameMiss.record(ctx, p, ctx.now())
    throw e
  }
}

export async function startWorkspaceConnect(ctx: VaultContext, p: AccessPrincipal, input: unknown, i: WorkspaceInvocationContext) {
  const req = parseOpInput(z.object({ connect: z.string(), state: z.string().min(16).max(128), home: CredentialHomeSchema.optional() }), input)
  if (i.auth.kind !== "account" || p.kind !== "member")
    throw new VaultError("forbidden", "Only a signed-in account can connect.")
  const row = connectRow(ctx, req.connect), flow = flowOf(row), provider = providerOf(flow.provider)
  requestAuthority(ctx, p, row, i)
  if (flow.intake && requestRow(ctx, flow.intake).status !== "completed")
    throw new VaultError("conflict", "Fill in the OAuth client first.")
  const home = req.home ?? requestHome(row)
  const { client, decision } = flowAuthority(ctx, p, row, flow, i, home)
  // Create authority does not waive the distinct passkey action for consent.
  requireStepUp(ctx, decision, connectStartAction(row, flow, client, home), i)
  const verifier = randomToken(32), challenge = base64UrlEncode(await sha256(verifier))
  const sealed = await ctx.sealField({ type: "workspace-oauth-verifier", id: row.id }, new Uint8Array(new TextEncoder().encode(verifier)))
  const stateHash = await sha256Text(req.state)
  const account = i.auth
  ctx.storage.transactionSync(() => {
    const current = requestRow(ctx, row.id), latest = flowOf(current)
    const final = flowAuthority(ctx, p, current, latest, i, home)
    requireStepUp(ctx, final.decision, connectStartAction(current, latest, final.client, home), i)
    const started = { account: account.account, session: account.session, epoch: account.securityEpoch, member: p.memberId, stateHash, verifier: { root: sealed.rootVersion, dek: base64UrlEncode(sealed.wrappedDek), ct: base64UrlEncode(sealed.ciphertext) } }
    ctx.sql.exec("UPDATE workspace_credential_requests SET payload=?,client_id=?,home=? WHERE id=?", JSON.stringify({ ...latest, client: final.client, started }), final.client.id, JSON.stringify(home), row.id)
    requestAudit(ctx, p, current, "oauth.connect_start", i)
  })
  const url = new URL(provider.auth.authorizeUrl), scopes = provider.auth.scopes
  url.searchParams.set("response_type", "code")
  url.searchParams.set("client_id", client.publicFields.client_id ?? "")
  url.searchParams.set("redirect_uri", `${ctx.env.VAULT_ORIGIN}/oauth/callback`)
  url.searchParams.set(scopes.param, [...new Set([...scopes.identity, ...flow.scopes, ...(scopes.offline ? [scopes.offline] : [])])].join(scopes.separator))
  url.searchParams.set("state", req.state)
  if (provider.auth.pkce === "S256") {
    url.searchParams.set("code_challenge", challenge)
    url.searchParams.set("code_challenge_method", "S256")
  }
  for (const [k, v] of Object.entries(provider.auth.authorizeParams ?? {}))
    url.searchParams.set(k, v)
  return { authorizeUrl: url.href, stateExpiresAt: row.expires_at, action: connectStartAction(row, flow, client, home) }
}

function checkInitiator(flow: Flow, i: WorkspaceInvocationContext): void {
  if (i.auth.kind !== "account" || !flow.started || i.auth.account !== flow.started.account || i.auth.session !== flow.started.session || i.auth.securityEpoch !== flow.started.epoch)
    throw new VaultError("forbidden", "This connection belongs to another sign-in.")
}

export async function finishWorkspaceConnect(ctx: VaultContext, p: AccessPrincipal, input: unknown, i: WorkspaceInvocationContext) {
  const req = parseOpInput(z.object({ connect: z.string(), state: z.string(), code: z.string().max(4096).nullable(), error: z.string().nullable() }), input)
  const row = requestRow(ctx, req.connect), flow = flowOf(row)
  checkInitiator(flow, i)
  const stateHash = await sha256Text(req.state)
  if (stateHash !== flow.started?.stateHash)
    throw new VaultError("forbidden", "This sign-in has different state.")
  const { client } = flowAuthority(ctx, p, row, flow, i)
  const provider = providerOf(flow.provider)
  if (req.error || !req.code)
    throw new VaultError("bad_request", "The provider did not complete sign-in.")
  const { base64UrlDecode } = await import("@mehen/protocol")
  const seal = flow.started?.verifier
  if (!seal)
    throw new VaultError("conflict", "Start the connection first.")
  const verifier = new TextDecoder().decode(await ctx.openField({ type: "workspace-oauth-verifier", id: row.id }, { rootVersion: seal.root, wrappedDek: base64UrlDecode(seal.dek), ciphertext: base64UrlDecode(seal.ct) }))
  const secret = (await openCredentialSecrets(ctx, client)).client_secret ?? ""
  flowAuthority(ctx, p, requestRow(ctx, row.id), flow, i)
  const tokens = await tokenRequest(provider, client, secret, { grant_type: "authorization_code", code: req.code, redirect_uri: `${ctx.env.VAULT_ORIGIN}/oauth/callback`, ...(provider.auth.pkce === "S256" ? { code_verifier: verifier } : {}) })
  if (tokens.kind !== "ok")
    throw new VaultError("upstream_failed", "The provider refused sign-in.")
  if (grantedBeyond(provider, flow.scopes, tokens.scopes).length) {
    await revokeToken(provider, tokens.accessToken)
    throw new VaultError("forbidden", "The provider granted more access than requested.")
  }
  flowAuthority(ctx, p, requestRow(ctx, row.id), flow, i)
  const identity = await probeIdentity(provider, tokens.accessToken, tokens.body)
  if (typeof identity === "string")
    throw new VaultError("upstream_failed", "The provider did not identify the account.")
  if(flow.pinnedIdentity?(flow.pinnedIdentity.subject!==identity.subject||flow.pinnedIdentity.tenant!==identity.tenant):flow.expect!==null&&flow.expect.toLowerCase()!==identity.label.toLowerCase())
    throw new VaultError("forbidden", "The provider account does not match this connection.")
  const previous = flow.target
  const secretFields: Record<string, string> = { access_token: tokens.accessToken }
  if (tokens.refreshToken)
    secretFields.refresh_token = tokens.refreshToken
  const prepared = await prepareCredential(ctx, { slug: row.slug, kind: "oauth-connection", provider: provider.id, account: identity.label, accountVerified: true, tags: flow.tags, home: requestHome(row), ceiling: previous?.ceiling ?? KINDS["oauth-connection"].defaultCeiling, binding: previous?.binding ?? provider.upstream.binding, policy: previous?.policy ?? connectionPolicy(provider), injection: previous?.injection ?? provider.upstream.injection, publicFields: {}, secretFields, description: previous?.description ?? null }, previous, flow.requestItemId)
  return ctx.storage.transactionSync(() => {
    const live = requestRow(ctx, row.id), latest = flowOf(live)
    checkInitiator(latest, i)
    flowAuthority(ctx, p, live, latest, i)
    if (canonicalJson(flow) !== canonicalJson(latest))
      throw new VaultError("conflict", "The connection changed during sign-in.")
    const stored = commitConnection(ctx, p, { row, flow, client, previous, prepared, identity, tokens, session: i.auth.kind === "account" ? i.auth.session : null })
    return { connect: row.id, status: "completed", item: describeCredential(ctx, stored) }
  })
}

type ConnectionCommit = {
  row: CredentialRequest
  flow: Flow
  client: CheckedCredential
  previous: CheckedCredential | null
  prepared: PreparedCredential
  // null for a custom provider, which has no identity probe.
  identity: { subject: string; tenant: string | null } | null
  tokens: { scopes: string[] | null; expiresIn: number | null }
  session: string | null
}

// Stores a finished connection, its dependency on its client and its refresh
// schedule, and completes the request. Called inside the finishing
// transaction, after the caller has checked the request and its authority again.
function commitConnection(ctx: VaultContext, p: AccessPrincipal, c: ConnectionCommit): CheckedCredential {
  const { row, flow, client, previous, prepared, identity, tokens } = c
  if (!previous)
    assertCredentialReservation(ctx, row.slug, row.id)
  const earlier = previous ? one(ctx.sql.exec<{ payload: string }>("SELECT payload FROM workspace_oauth_connections WHERE item=?", previous.id)) : null
  const stored = storeCredential(ctx, prepared, p, previous ? "oauth.reconnect" : "oauth.connect", c.session)
  const connectionPayload: ConnectionBasis = { clientRevision: client.configRev, credentialRevision: stored.configRev, home: stored.home, subject: identity?.subject ?? null, tenant: identity?.tenant ?? null, scopes: tokens.scopes ?? flow.scopes, connectedAt: ctx.now(), refreshedAt: ctx.now() }
  // The reason it had to be reconnected, or kept failing, no longer stands.
  const earlierBasis = earlier ? JSON.parse(earlier.payload) as ConnectionBasis : null
  if (previous)
    for (const reason of [earlierBasis?.lost?.reason, earlierBasis?.failingReason])
      if (reason !== undefined)
        ctx.sql.exec("UPDATE items SET review_reason=NULL,review_at=NULL WHERE id=? AND review_reason=?", stored.id, reason)
  const oldClient = one(ctx.sql.exec<{
    client: string
  }>("SELECT client FROM credential_dependencies WHERE connection=?", stored.id))?.client
  ctx.sql.exec("INSERT INTO credential_dependencies VALUES (?,?,?,?) ON CONFLICT(connection) DO UPDATE SET client=excluded.client,client_revision=excluded.client_revision,revision=credential_dependencies.revision+1", stored.id, client.id, client.configRev, 1)
  for (const id of new Set([client.id, ...(oldClient ? [oldClient] : [])]))
    ctx.sql.exec("UPDATE items SET dependency_revision=dependency_revision+1 WHERE id=?", id)
  ctx.sql.exec("UPDATE items SET dependency_revision=dependency_revision+1 WHERE id=?", stored.id)
  if (p.kind !== "member")
    throw new VaultError("forbidden", "Only a human can connect.")
  ctx.sql.exec("INSERT INTO workspace_oauth_connections VALUES (?,?,?,?,?,?) ON CONFLICT(item) DO UPDATE SET client=excluded.client,member=excluded.member,intent=excluded.intent,payload=excluded.payload,expires_at=excluded.expires_at", stored.id, client.id, p.memberId, previous ? "rotate" : "create", JSON.stringify(connectionPayload), tokens.expiresIn === null ? null : ctx.now() + tokens.expiresIn * 1000)
  ctx.sql.exec("UPDATE workspace_credential_requests SET status='completed' WHERE id=?", row.id)
  if (tokens.expiresIn !== null)
    ctx.schedule("oauth", `workspace-refresh:${stored.id}`, Math.max(ctx.now() + 30000, ctx.now() + tokens.expiresIn * 1000 - 60000))
  return stored
}
// Refresh maintains retained consent, not a current browser session. Cooling-off
// and pending account epochs do not revoke an already authorised provider grant.

type ConnectionBasis = {
  clientRevision: number
  credentialRevision: number
  home: CredentialHome
  // null for a custom provider's connection: it has no identity probe.
  subject: string | null
  tenant: string | null
  scopes: string[]
  // When the grant was made and last renewed; absent on a connection made
  // before they were kept. The reason a lost grant gives depends on them.
  connectedAt?: number
  refreshedAt?: number
  retryAt?: number
  // Refreshes that failed since the last one that worked, and on how many
  // different days (the day of the last one, as YYYY-MM-DD).
  failures?: number
  failureDays?: number
  failureDay?: string
  // When this run of failed refreshes began, and once it has failed on
  // FAILING_DAYS_LIMIT days, the review reason that says so.
  failingSince?: number
  failingReason?: string
  refreshAttempt?: {
    id: string
    startedAt: number
  }
  // The provider rejected the OAuth client at this revision: the
  // connection waits for the client without sending its token again.
  clientRejected?: { clientRevision: number; at: number }
  // Why it must be reconnected, from the moment it had to be.
  lost?: { reason: string; at: number }
}

// A connection that cannot work until a person signs in again, and why.
class ConnectionLost extends VaultError {
  readonly reason: string
  constructor(reason: string) {
    super("needs_reauth", `Reconnect this credential: ${reason}.`)
    this.reason = reason
  }
}

// The provider refused the OAuth client itself (its secret is wrong,
// expired or deleted): reconnecting cannot help until the client's secret
// is replaced. A refresh has no asker, so the error names no client and
// sends to the connection's page; connectionNeedsReauth names the client
// to an asker who may see it.
class ClientRejected extends VaultError {
  readonly client: { id: string; slug: string; configRev: number }
  readonly providerName: string
  constructor(ctx: VaultContext, connectionSlug: string, client: { id: string; slug: string; configRev: number }, providerName: string) {
    super("needs_reauth", clientRejectedMessage(null, providerName), { next: clientRejectedNext(ctx, { connection: connectionSlug }, providerName) })
    this.client = client
    this.providerName = providerName
  }
}

function clientRejectedMessage(clientSlug: string | null, providerName: string): string {
  return `${providerName} rejected ${clientSlug === null ? "the OAuth client this connection uses" : `the OAuth client "${clientSlug}"`} (its secret is wrong, expired or deleted). Every connection that uses it is paused until a human replaces the client secret and then reconnects them.`
}

// The rejected client's own review reason, until its secret is replaced
// (a rotation or a restore).
const CLIENT_REJECTED_REASON = " rejected this OAuth client (its secret is wrong, expired or deleted), so the connections that use it are paused: replace its secret, then reconnect them"
function clientRejectedReason(providerName: string): string {
  return `${providerName}${CLIENT_REJECTED_REASON}`
}
export function isClientRejectedReason(reason: string): boolean { return reason.endsWith(CLIENT_REJECTED_REASON) }

// The client's page for a reader who may see it, else the connection's.
function clientRejectedNext(ctx: VaultContext, page: { client: string } | { connection: string }, providerName: string) {
  const slug = "client" in page ? page.client : page.connection
  const named = "client" in page ? `the OAuth client "${page.client}"` : "the OAuth client this connection uses"
  return { url: `${ctx.env.VAULT_ORIGIN}/w/${workspaceRef(ctx).slug}/items/${slug}`, say: `${providerName} rejected ${named}. A human must replace its client secret in the vault, then reconnect the connections that use it; reconnecting first will not work.` }
}

function lost(reason: string): never { throw new ConnectionLost(reason) }

// Whether the provider has rejected this client at its current revision,
// as any of its connections found: all of them wait for it.
function clientRejectedNow(ctx: VaultContext, client: { id: string; configRev: number }): boolean {
  return one(ctx.sql.exec("SELECT 1 FROM workspace_oauth_connections WHERE client=? AND json_extract(payload,'$.clientRejected.clientRevision')=?", client.id, client.configRev)) !== null
}

// Every connection waiting for a client the provider rejected at its
// current revision, by connection item id, with that client's item id.
export function connectionsPausedByClient(ctx: VaultContext): Map<string, string> {
  return new Map(ctx.sql.exec<{ item: string; client: string }>("SELECT c.item AS item,c.client AS client FROM workspace_oauth_connections c JOIN items i ON i.id=c.client WHERE c.client IN (SELECT client FROM workspace_oauth_connections WHERE json_extract(payload,'$.clientRejected.clientRevision')=i.config_rev)").toArray().map((r) => [r.item, r.client]))
}

function refreshBasis(ctx: VaultContext, item: CheckedCredential) {
  const conn = one(ctx.sql.exec<Connection>("SELECT * FROM workspace_oauth_connections WHERE item=?", item.id))
  if (!conn)
    return lost("it was never connected here")
  const basis = JSON.parse(conn.payload) as ConnectionBasis
  const state = credentialAccessState(ctx), member = state.members.find(m => m.id === conn.member)
  const clientSlug = one(ctx.sql.exec<{
    slug: string
  }>("SELECT slug FROM items WHERE id=?", conn.client))?.slug
  const client = clientSlug ? checkedCredential(ctx, clientSlug) : null
  if (!member || member.status !== "active")
    return lost("the person who connected it is no longer an active member")
  if (!client)
    return lost("its OAuth client was removed")
  if (client.configRev !== basis.clientRevision)
    return lost("its OAuth client was replaced or changed since it was connected")
  if (item.configRev !== basis.credentialRevision || !compatibleClientHome(client.home, item.home) || canonicalJson(item.home) !== canonicalJson(basis.home))
    return lost("it or its OAuth client was moved since it was connected")
  const standing = { ...member.standing, restriction: null, transitionPending: false, identityGate: { covered: false, admitted: true, checkedAt: null } }
  const clean = { ...state, members: state.members.map(m => m.id === member.id ? { ...m, standing } : m) }
  const principal: AccessPrincipal = { kind: "member", memberId: member.id, account: member.account, session: "ses_retained", securityEpoch: 0, sessionCheck: null }
  if (!can(clean, principal, conn.intent === "rotate" ? { type: "credential.rotate" } : { type: "credential.create" }, conn.intent === "rotate" ? { credential: item.id } : { destinationHome: item.home }, ctx.now()).allowed || !can(clean, principal, { type: "item.read" }, { credential: client.id }, ctx.now()).allowed)
    return lost("the person who connected it may no longer maintain it")
  return { conn, basis, client, principal }
}

const REFRESH_UNCERTAINTY_MS = 120000
// A refresh that keeps failing on this many different days is put in front
// of a person; the vault keeps retrying, as only the provider can say the
// grant is gone.
const FAILING_DAYS_LIMIT = 4
class RefreshInFlight extends VaultError {
}

type TokenRead = { accessToken: string; item: CheckedCredential }

// Only a strictly rotating refresh token (GitHub's) may be spent by an
// exchange whose answer was lost, so only then is an interrupted refresh
// sent again no sooner than it could still be answered. A custom provider's
// rotation is not known, so it is treated so too.
function strictRotation(exchange: OAuthExchange): boolean {
  return exchange.id === CUSTOM_OAUTH_PROVIDER_ID || exchange.refresh.rotation === "strict"
}

// Why the provider ended the grant, in words, from what the vault knows of it.
function grantEndedReason(ctx: VaultContext, exchange: OAuthExchange, item: string, basis: ConnectionBasis, lostRotation: boolean): string {
  const catalogue = exchange.id === CUSTOM_OAUTH_PROVIDER_ID ? null : providerOf(exchange.id)
  const connectedAt = connectedAtOf(ctx, item, basis)
  return reauthReasonAt(catalogue, exchange.displayName, { connectedAt, refreshedAt: basis.refreshedAt ?? connectedAt }, ctx.now(), lostRotation)
}

async function refreshOrAccessToken(ctx: VaultContext, item: CheckedCredential): Promise<TokenRead> {
  const before = refreshBasis(ctx, item)
  // An authorised metadata edit may race maintenance. Preserve its new
  // constraints; never rebase across a rotation, rehome or dependency change.
  const currentValue = () => {
    const current = checkedCredential(ctx, item.slug)
    if (!current || current.id !== item.id || current.version !== item.version || current.kind !== item.kind || current.provider !== item.provider || current.dependencyRevision !== item.dependencyRevision || canonicalJson(current.home) !== canonicalJson(item.home))
      throw new VaultError("conflict", "The credential changed; review and try again.")
    return current
  }
  // A catalogue connection refreshes with its provider; one made with a
  // custom provider at its client's definition's token URL.
  const exchange = exchangeFor(ctx, item.provider ?? CUSTOM_OAUTH_PROVIDER_ID, before.client)
  if (clientRejectedNow(ctx, before.client))
    throw new ClientRejected(ctx, item.slug, before.client, exchange.displayName)
  if (before.basis.refreshAttempt) {
    const remaining = before.basis.refreshAttempt.startedAt + REFRESH_UNCERTAINTY_MS - ctx.now()
    if (remaining >= 0)
      throw new RefreshInFlight("refresh_retrying", "A credential refresh is already in progress.", { retryAfter: Math.max(1, Math.ceil(remaining / 1000)) })
  }
  // An interrupted refresh is sent again. A strictly rotating token the lost
  // exchange spent is refused with a terminal error, which then says so.
  const resent = before.basis.refreshAttempt !== undefined && strictRotation(exchange)
  const expired = before.conn.expires_at !== null && before.conn.expires_at <= ctx.now()
  const waiting = before.basis.retryAt !== undefined && before.basis.retryAt > ctx.now()
  if (waiting && expired)
    throw new VaultError("refresh_retrying", "The provider refresh is waiting to retry.", { retryAfter: Math.ceil((before.basis.retryAt! - ctx.now()) / 1000) })
  const secrets = await openCredentialSecrets(ctx, item)
  // While a failed refresh waits to retry, the old token is used until it expires.
  if (before.conn.expires_at === null || before.conn.expires_at > ctx.now() + 60000 || waiting) {
    refreshBasis(ctx, currentValue())
    return { accessToken: secrets.access_token ?? "", item: currentValue() }
  }
  const clientSecret = (await openCredentialSecrets(ctx, before.client)).client_secret ?? ""
  refreshBasis(ctx, currentValue())
  if (!secrets.refresh_token)
    lost(`${exchange.displayName} gave no refresh token, so the expired sign-in cannot be renewed`)
  const attempt = { id: randomId("rfa"), startedAt: ctx.now() }
  ctx.storage.transactionSync(() => {
    refreshBasis(ctx, currentValue())
    assertCredentialCurrent(ctx, before.client)
    ctx.sql.exec("UPDATE workspace_oauth_connections SET payload=? WHERE item=?", JSON.stringify({ ...before.basis, refreshAttempt: attempt }), item.id)
    credentialAudit(ctx, before.principal, item, "oauth.refresh_attempt", "started", exchangeAuditDetail(exchange))
  })
  const tokens = await tokenRequest(exchange, before.client, clientSecret, { grant_type: "refresh_token", refresh_token: secrets.refresh_token }, ctx.now())
  refreshBasis(ctx, currentValue())
  if (tokens.kind === "oauth_error" && exchange.refresh.clientErrors.includes(tokens.code)) {
    ctx.storage.transactionSync(() => {
      const latest = refreshBasis(ctx, currentValue())
      ctx.sql.exec("UPDATE workspace_oauth_connections SET payload=? WHERE item=?", JSON.stringify({ ...latest.basis, refreshAttempt: undefined, retryAt: undefined, clientRejected: { clientRevision: latest.client.configRev, at: ctx.now() } }), item.id)
      ctx.sql.exec("UPDATE items SET status='needs_reauth',review_reason=?,review_at=? WHERE id=? AND config_rev=?", clientRejectedReason(exchange.displayName), ctx.now(), latest.client.id, latest.client.configRev)
    })
    throw new ClientRejected(ctx, item.slug, before.client, exchange.displayName)
  }
  if (tokens.kind === "oauth_error" && exchange.refresh.terminalErrors.includes(tokens.code))
    lost(grantEndedReason(ctx, exchange, item.id, before.basis, resent))
  if (tokens.kind !== "ok") {
    // A network error, a timeout, throttling, the provider's own failure or
    // an OAuth error that says neither the grant nor the client is gone:
    // retried after a wait. A strictly rotating token whose exchange may
    // have gone through keeps its attempt, so it is sent again only once
    // that exchange can no longer be in flight.
    const keepAttempt = tokens.kind === "transient" && tokens.mayHaveIssued && strictRotation(exchange)
    const failures = (before.basis.failures ?? 0) + 1
    const wait = Math.round(Math.max(refreshRetryWaitMs(failures, tokens.kind === "transient" ? tokens.retryAfter : null), keepAttempt ? REFRESH_UNCERTAINTY_MS + 1000 : 0))
    const retryAfter = Math.ceil(wait / 1000), retryAt = ctx.now() + wait
    const day = new Date(ctx.now()).toISOString().slice(0, 10)
    const failureDays = before.basis.failureDay === day ? before.basis.failureDays ?? 1 : (before.basis.failureDays ?? 0) + 1
    const failingSince = before.basis.failingSince ?? ctx.now()
    // However long it lasts, a failure that does not say the grant is gone
    // never needs a reconnect: past the limit a person is told it keeps failing.
    const failingReason = failureDays >= FAILING_DAYS_LIMIT ? `Mehen has not been able to renew the sign-in with ${exchange.displayName} since ${new Date(failingSince).toISOString().slice(0, 10)} (last error: ${failureClass(tokens)}); it keeps trying` : undefined
    const stillValid = before.conn.expires_at !== null && before.conn.expires_at > ctx.now() && secrets.access_token !== undefined
    ctx.storage.transactionSync(() => {
      const latest = refreshBasis(ctx, currentValue())
      ctx.sql.exec("UPDATE workspace_oauth_connections SET payload=? WHERE item=?", JSON.stringify({ ...latest.basis, retryAt, failures, failureDays, failureDay: day, failingSince, failingReason, refreshAttempt: keepAttempt ? attempt : undefined }), item.id)
      if (!stillValid)
        ctx.sql.exec("UPDATE items SET status='refresh_retrying' WHERE id=?", item.id)
      if (failingReason !== undefined)
        markConnectionFailing(ctx, item, exchange.displayName, failingSince, failingReason, latest.basis.failingReason)
      ctx.schedule("oauth", `workspace-refresh:${item.id}`, retryAt)
    })
    if (stillValid)
      return { accessToken: secrets.access_token ?? "", item: currentValue() }
    throw new VaultError("refresh_retrying", `${exchange.displayName} did not renew the sign-in; the vault retries in ${retryAfter} seconds.`, { retryAfter })
  }
  if (grantedBeyond(exchange, before.basis.scopes, tokens.scopes).length)
    lost(`${exchange.displayName} changed the access it grants`)
  const latest = currentValue()
  const prepared = await prepareCredential(ctx, { ...latest, secretFields: { access_token: tokens.accessToken, refresh_token: tokens.refreshToken ?? secrets.refresh_token } }, latest)
  return ctx.storage.transactionSync(() => {
    const current = currentValue(), final = refreshBasis(ctx, current)
    assertCredentialCurrent(ctx, before.client)
    const currentAttempt = one(ctx.sql.exec<{
      payload: string
    }>("SELECT payload FROM workspace_oauth_connections WHERE item=?", item.id))
    if (!currentAttempt || (JSON.parse(currentAttempt.payload) as {
      refreshAttempt?: {
        id: string
      }
    }).refreshAttempt?.id !== attempt.id)
      throw new VaultError("conflict", "The credential refresh changed.")
    const stored = storeCredential(ctx, { ...prepared, input: { ...prepared.input, ...current }, expected: current }, before.principal, "oauth.refresh", null, false)
    recordExposure(ctx, { item: stored.id, version: stored.version, member: before.conn.member, device: null, event: "oauth.authorisation_retained", source: "entered", at: ctx.now() })
    ctx.sql.exec("UPDATE workspace_oauth_connections SET payload=?,expires_at=? WHERE item=?", JSON.stringify({ ...final.basis, refreshedAt: ctx.now(), retryAt: undefined, refreshAttempt: undefined, failures: undefined, failureDays: undefined, failureDay: undefined, failingSince: undefined, failingReason: undefined }), tokens.expiresIn === null ? null : ctx.now() + tokens.expiresIn * 1000, item.id)
    if (final.basis.failingReason !== undefined)
      ctx.sql.exec("UPDATE items SET review_reason=NULL,review_at=NULL WHERE id=? AND review_reason=?", item.id, final.basis.failingReason)
    if (tokens.expiresIn !== null)
      ctx.schedule("oauth", `workspace-refresh:${item.id}`, Math.max(ctx.now() + 30000, ctx.now() + tokens.expiresIn * 1000 - 60000))
    return { accessToken: tokens.accessToken, item: stored }
  })
}
const refreshing = new Map<string, Promise<TokenRead>>()

// What went wrong with a refresh that is retried, in words.
function failureClass(tokens: { kind: "transient"; status: number } | { kind: "oauth_error"; code: string }): string {
  if (tokens.kind === "oauth_error")
    return `the provider answered ${tokens.code}`
  if (tokens.status === 0)
    return "no answer (a network error or timeout)"
  if (tokens.status === 429)
    return "throttled (429)"
  return tokens.status >= 500 && tokens.status <= 599 ? `the provider failed (${tokens.status})` : `an answer it could not read (${tokens.status})`
}

// A connection whose refreshes have failed on FAILING_DAYS_LIMIT days: the
// reason goes on the item (its page and a Review row in Needs you, which
// offers Reconnect without needing it), never over another review reason,
// and whoever may reconnect it is told once per run of failures, when it
// first crosses the limit. A refresh that works, or a reconnect, clears it.
function markConnectionFailing(ctx: VaultContext, item: CheckedCredential, providerName: string, since: number, reason: string, previous: string | undefined): void {
  ctx.sql.exec("UPDATE items SET review_reason=?,review_at=COALESCE(CASE WHEN review_reason=? THEN review_at END,?) WHERE id=? AND (review_reason IS NULL OR review_reason=?)", reason, previous ?? "", ctx.now(), item.id, previous ?? "")
  if (previous !== undefined)
    return
  const row = one(ctx.sql.exec<{ account: string | null; provider: string | null }>("SELECT account,provider FROM items WHERE id=?", item.id))
  if (!row)
    return
  queueNotice(ctx, { kind: "connection_failing", workspace: workspaceRef(ctx), item: { id: item.id, slug: item.slug }, provider: { id: row.provider, name: providerName }, account: row.account, since: new Date(since).toISOString(), reason, at: new Date(ctx.now()).toISOString() }, `${item.id}:${since}`, reconnectors(ctx, item.id))
}

// The connection stops until a person acts: needs_reauth, with the reason
// on the item (as its review reason, so its page, Needs you and the agent
// all say it), no refresh scheduled, and on the change into needs_reauth
// one notice to whoever may reconnect it. A rejected client is noticed once
// for the client instead, by the first of its connections to find it.
function markConnectionLost(ctx: VaultContext, item: CheckedCredential, error: VaultError): void {
  const row = one(ctx.sql.exec<{ status: string; account: string | null; provider: string | null }>("SELECT status,account,provider FROM items WHERE id=?", item.id))
  const conn = one(ctx.sql.exec<{ client: string; payload: string }>("SELECT client,payload FROM workspace_oauth_connections WHERE item=?", item.id))
  if (!row)
    return
  const now = ctx.now()
  ctx.unschedule("oauth", `workspace-refresh:${item.id}`)
  const reason = error instanceof ClientRejected ? `its OAuth client was rejected by ${error.providerName}: replace the client's secret, then reconnect` : error instanceof ConnectionLost ? error.reason : "the provider no longer accepts the sign-in"
  const already = row.status === "needs_reauth"
  ctx.sql.exec("UPDATE items SET status='needs_reauth',review_reason=?,review_at=? WHERE id=?", reason, now, item.id)
  if (!conn)
    return
  const basis = JSON.parse(conn.payload) as ConnectionBasis
  ctx.sql.exec("UPDATE workspace_oauth_connections SET payload=? WHERE item=?", JSON.stringify({ ...basis, refreshAttempt: undefined, lost: { reason, at: already && basis.lost ? basis.lost.at : now } }), item.id)
  if (already)
    return
  // The outbox keeps one per client revision, and one per grant (each
  // connect or reconnect makes a new one).
  if (error instanceof ClientRejected) {
    queueNotice(ctx, { kind: "oauth_client_rejected", workspace: workspaceRef(ctx), item: { id: error.client.id, slug: error.client.slug }, clientRevision: error.client.configRev, provider: error.providerName, at: new Date(now).toISOString() }, `${error.client.id}:${error.client.configRev}`, reconnectors(ctx, error.client.id))
    return
  }
  const provider = row.provider === null ? null : getOAuthProvider(row.provider)
  queueNotice(ctx, { kind: "connection_lost", workspace: workspaceRef(ctx), item: { id: item.id, slug: item.slug }, provider: { id: row.provider, name: provider?.displayName ?? customProviderOf(ctx, conn.client)?.name ?? "The provider" }, account: row.account, reason, at: new Date(now).toISOString() }, `${item.id}:${connectedAtOf(ctx, item.id, basis) ?? 0}`, reconnectors(ctx, item.id))
}

// When the connection's grant was made: kept on it since connectedAt was
// recorded, and before that the time of its last connect or reconnect.
function connectedAtOf(ctx: VaultContext, item: string, basis: ConnectionBasis): number | null {
  return basis.connectedAt ?? one(ctx.sql.exec<{ at: number | null }>("SELECT MAX(at) AS at FROM exposures WHERE item=? AND event IN ('oauth.connect','oauth.reconnect')", item))?.at ?? null
}

// The accounts that may start a reconnect of this credential (or replace
// this client): whoever manages where it belongs, the same people its Needs
// you row is listed to (credentials-pending.ts).
function reconnectors(ctx: VaultContext, credential: string): string[] {
  const state = credentialAccessState(ctx)
  return state.members.filter(m => m.status === "active" && m.standing.effectiveRole !== "guest" && can(state, { kind: "member", memberId: m.id, account: m.account, session: "ses_notice", securityEpoch: 0, sessionCheck: null }, { type: "credential.rotate" }, { credential }, ctx.now()).allowed).map(m => m.account)
}

// What an agent is told about a connection that already needs a person:
// when the provider rejected the OAuth client (reconnecting first cannot
// work), sent to the client if the asker may see it, else to the
// connection's page, without naming the client; else, for a machine that may rotate it, a reconnect link
// pinned to the account it holds, the same open one each time, to wait on;
// else the connection's page. Each says why it stopped.
export function connectionNeedsReauth(ctx: VaultContext, item: { id: string; slug: string; provider: string | null; review: { reason: string } | null }, asker?: { principal: AccessPrincipal; invocation: WorkspaceInvocationContext }): VaultError {
  const conn = one(ctx.sql.exec<{ client: string }>("SELECT client FROM workspace_oauth_connections WHERE item=?", item.id))
  const client = conn ? one(ctx.sql.exec<{ slug: string; config_rev: number }>("SELECT slug,config_rev FROM items WHERE id=?", conn.client)) : null
  const name = (item.provider === null ? null : getOAuthProvider(item.provider)?.displayName) ?? (conn ? customProviderOf(ctx, conn.client)?.name : null) ?? "The provider"
  if (conn && client && clientRejectedNow(ctx, { id: conn.client, configRev: client.config_rev })) {
    const seesClient = asker !== undefined && can(credentialAccessState(ctx, asker.invocation), asker.principal, { type: "item.read" }, { credential: conn.client }, ctx.now()).allowed
    return new VaultError("needs_reauth", clientRejectedMessage(seesClient ? client.slug : null, name), { next: clientRejectedNext(ctx, seesClient ? { client: client.slug } : { connection: item.slug }, name) })
  }
  const why = item.review?.reason ?? "the provider no longer accepts the sign-in"
  const pinned = conn && client && asker ? reconnectLink(ctx, item, client.slug, why, asker) : null
  if (pinned) {
    const account = checkedCredential(ctx, item.slug)?.account ?? null
    const as = account ? ` as ${account}` : ""
    return new VaultError("needs_reauth", `"${item.slug}" must be reconnected: ${why}.`, { next: { url: pinned.url, command: `mehen wait ${pinned.connect} --timeout 60 --json`, say: `${name}${account ? ` for ${account}` : ""} must be reconnected. Open this link, sign in to the vault, then sign in to ${name}${as}.` }, expiresAt: pinned.expiresAt })
  }
  return new VaultError("needs_reauth", item.review ? `"${item.slug}" needs to be connected again: ${item.review.reason}.` : `"${item.slug}" needs to be connected again.`, { next: { url: `${ctx.env.VAULT_ORIGIN}/w/${workspaceRef(ctx).slug}/items/${item.slug}`, say: "Reconnect this credential in the workspace." } })
}

// The machine's reconnect of this connection: its open one, or a new one
// keeping the connection's scopes and pinned to its account; null when the
// machine may not start one (no rotate right, a full ask list, another open
// connect for the name), which leaves the connection's page.
function reconnectLink(ctx: VaultContext, item: { slug: string; provider: string | null }, clientSlug: string, why: string, asker: { principal: AccessPrincipal; invocation: WorkspaceInvocationContext }): ConnectCreated | null {
  const current = checkedCredential(ctx, item.slug)
  if (!current || asker.principal.kind !== "device" || item.provider === null)
    return null
  const home = current.home.kind === "project" ? { home: "project" as const, project: current.home.project } : { home: current.home.kind === "member" ? "private" as const : "workspace" as const }
  try {
    return createWorkspaceConnect(ctx, asker.principal, { provider: item.provider, client: clientSlug, slug: item.slug, reason: `Reconnect ${item.slug}: ${why}`, ...home }, asker.invocation)
  }
  catch (error) {
    if (error instanceof VaultError)
      return null
    throw error
  }
}

export function workspaceTokenRead(ctx: VaultContext, item: CheckedCredential): Promise<TokenRead> {
  const key = `${ctx.tenant}:${item.id}`, active = refreshing.get(key)
  if (active)
    return active
  const connector = one(ctx.sql.exec<{
    member: string
  }>("SELECT member FROM workspace_oauth_connections WHERE item=?", item.id))?.member
  const promise = refreshOrAccessToken(ctx, item).catch(error => {
    if (error instanceof RefreshInFlight)
      throw error
    if (error instanceof VaultError) {
      const conn = one(ctx.sql.exec<{
        member: string
      }>("SELECT member FROM workspace_oauth_connections WHERE item=?", item.id))
      const member = credentialAccessState(ctx).members.find(m => m.id === (conn?.member ?? connector))
      ctx.storage.transactionSync(() => {
        if (error.code === "needs_reauth")
          markConnectionLost(ctx, item, error)
        if (member)
          credentialAudit(ctx, { kind: "member", memberId: member.id, account: member.account, session: "ses_retained", securityEpoch: 0, sessionCheck: null }, item, "oauth.refresh", `refused:${error.code}`)
      })
    }
    throw error
  }).finally(() => { if (refreshing.get(key) === promise)
    refreshing.delete(key); })
  refreshing.set(key, promise)
  return promise
}

export async function workspaceAccessToken(ctx: VaultContext, item: CheckedCredential): Promise<string> {
  return (await workspaceTokenRead(ctx, item)).accessToken
}

// ---------------------------------------------------------------- the platform's connects (routes 16 to 19)

// P1's routes/platform.ts sends each route here as `platform.<route name>`,
// with { params (without the subject), query, body } parsed by the route's
// schemas, null for a part the route has none of; parsed again here, at the
// object's own boundary. Each answers the route's answer, as every platform
// operation does (areas/managed.ts).
const PlatformConnectStartInput = z.object({ body: PlatformConnectStartSchema })
const PlatformConnectFinishInput = z.object({ body: PlatformConnectFinishSchema })
const PlatformConnectInput = z.object({ params: z.object({ connect: z.string().min(1).max(64) }) })
const PLATFORM_CONNECT_REASON = "Started by the platform."

type PlatformConnectFailure = Extract<PlatformConnectFinished, { status: "failed" }>["reason"]
type PlatformConnectState = { state_hash: string; connect: string; expires_at: number }
type SubjectMember = Extract<AccessPrincipal, { kind: "member" }>

// The platform acts as the subject member, and only through these operations.
function platformMember(i: WorkspaceInvocationContext, p: WorkspaceRuntimePrincipal): SubjectMember {
  if (i.auth.kind !== "platform" || p.kind !== "member")
    throw new VaultError("forbidden", "Only the platform can do that.")
  return p
}

// A public client has no secret, so only PKCE keeps its code useless to
// anyone but the vault.
function assertPublicClientPkce(exchange: OAuthExchange): void {
  if (exchange.auth.clientAuth === "none" && exchange.auth.pkce !== "S256")
    throw new VaultError("bad_request", "A public client, with no secret, needs PKCE.")
}

function connectScopes(exchange: OAuthExchange, asked: readonly string[]): string[] {
  const scopes: string[] = []
  for (const s of asked) {
    const scope = normaliseScope(exchange, s)
    if (scope === null)
      throw new VaultError("bad_request", `"${s}" is not a scope ${exchange.displayName} allows.`)
    if (!scopes.includes(scope))
      scopes.push(scope)
  }
  return scopes
}

function platformConnectAudit(ctx: VaultContext, p: SubjectMember, row: CredentialRequest, action: string, exchange: OAuthExchange, detail: Record<string, string> = {}): void {
  ctx.audit({ actor: `member:${p.memberId}`, action, target: row.id, detail: { slug: row.slug, provider: exchange.id, ...exchangeAuditDetail(exchange), outcome: row.status, ...detail } })
}

// Route 16: a connection with the subject's own OAuth client, named by the
// catalogue provider or by the client carrying its own definition. Answers
// the provider's authorisation URL with the client's id, the platform's
// callback, the vault's state and, whenever the provider supports it, a
// PKCE S256 challenge. Starting again for the same name replaces the open one.
async function startPlatformConnect(ctx: VaultContext, p: WorkspaceRuntimePrincipal, input: unknown, i: WorkspaceInvocationContext): Promise<PlatformConnectStarted> {
  const member = platformMember(i, p)
  const { body } = parseOpInput(PlatformConnectStartInput, input)
  const { defaults } = heldManagedPlatform(ctx).platform
  const home: CredentialHome = { kind: "workspace" }
  const catalogue = body.provider === undefined ? null : providerOf(body.provider)
  if (catalogue && defaults.providers !== undefined && !defaults.providers.includes(catalogue.id))
    throw new VaultError("bad_request", `This platform does not offer ${catalogue.displayName}.`)
  const provider = catalogue?.id ?? CUSTOM_OAUTH_PROVIDER_ID
  const clientSlug = body.client ?? catalogue?.clientTemplate
  if (clientSlug === undefined)
    throw new VaultError("bad_request", "Name a catalogue provider, or the client whose own provider definition to use.")
  const created = subjectWrite(ctx, () => {
    const client = clientFor(ctx, member, clientSlug, home, clientTemplateOf(provider), i)
    const exchange = exchangeFor(ctx, provider, client)
    assertPublicClientPkce(exchange)
    if (!client.publicFields.client_id)
      throw new VaultError("conflict", `The OAuth client "${client.slug}" has no client ID.`)
    // An existing name is a reconnect: of the same provider and, for a custom
    // provider, through the same client, whose definition made it.
    const target = checkedCredential(ctx, body.slug) ? visibleCredential(ctx, member, body.slug, undefined, i) : null
    const connection = target ? one(ctx.sql.exec<{ client: string; payload: string }>("SELECT client,payload FROM workspace_oauth_connections WHERE item=?", target.id)) : null
    if (target && (target.kind !== "oauth-connection" || (target.provider ?? CUSTOM_OAUTH_PROVIDER_ID) !== provider || (provider === CUSTOM_OAUTH_PROVIDER_ID && connection?.client !== client.id) || canonicalJson(target.home) !== canonicalJson(home)))
      throw new VaultError("conflict", `An item called "${body.slug}" already exists and is not this connection. Pick another name.`)
    assertManagedConnectRoom(ctx, member.memberId, body.slug, target === null)
    const pin = connection ? JSON.parse(connection.payload) as { subject: string | null; tenant: string | null } : null
    const scopes = connectScopes(exchange, body.scopes ?? (catalogue ? defaults.scopes[catalogue.id] : undefined) ?? exchange.auth.scopes.defaults)
    const tags = target?.tags ?? [...new Set([...(body.tags ?? []), ...defaults.tags])].sort()
    const flow: Flow = { reason: PLATFORM_CONNECT_REASON, session: null, provider, clientSlug, client, target, scopes, expect: target?.account ?? body.expect ?? null, tags, intake: null, ...(pin?.subject ? { pinnedIdentity: { subject: pin.subject, tenant: pin.tenant } } : {}), platform: { redirectUri: body.redirectUri } }
    const row = createCredentialRequest(ctx, member, { kind: "connect", slug: body.slug, home, tags, payload: { ...flow, fresh: true }, target, client, ttl: PLATFORM_CONNECT_TTL_SECONDS * 1000 }, i)
    const stored = flowOf(row)
    requireStepUp(ctx, flowAuthority(ctx, member, row, stored, i).decision, connectStartAction(row, stored, client), i)
    return { row, flow: stored, client, exchange }
  })
  const { row, flow, client, exchange } = created
  const pkce = exchange.auth.pkce === "S256"
  const state = randomToken(32), verifier = randomToken(32), challenge = base64UrlEncode(await sha256(verifier))
  const sealed = await ctx.sealField({ type: "workspace-oauth-verifier", id: row.id }, new Uint8Array(new TextEncoder().encode(verifier)))
  const stateHash = await sha256Text(state)
  subjectWrite(ctx, () => {
    const current = requestRow(ctx, row.id), latest = flowOf(current)
    if (canonicalJson(latest) !== canonicalJson(flow))
      throw new VaultError("conflict", "The connection changed; start it again.")
    const final = flowAuthority(ctx, member, current, latest, i)
    requireStepUp(ctx, final.decision, connectStartAction(current, latest, final.client), i)
    const platformStarted = { stateHash, pkce, verifier: { root: sealed.rootVersion, dek: base64UrlEncode(sealed.wrappedDek), ct: base64UrlEncode(sealed.ciphertext) } }
    ctx.sql.exec("UPDATE workspace_credential_requests SET payload=?,client_id=? WHERE id=?", JSON.stringify({ ...latest, client: final.client, platformStarted }), final.client.id, row.id)
    ctx.sql.exec("DELETE FROM platform_connect_states WHERE expires_at<=?", ctx.now())
    ctx.sql.exec("DELETE FROM platform_connect_states WHERE connect IN (SELECT id FROM workspace_credential_requests WHERE kind='connect' AND status!='open')")
    ctx.sql.exec("INSERT INTO platform_connect_states(state_hash,connect,expires_at) VALUES (?,?,?)", stateHash, row.id, row.expires_at)
    platformConnectAudit(ctx, member, current, "oauth.connect_start", exchange)
  })
  const scopes = exchange.auth.scopes
  const url = new URL(exchange.auth.authorizeUrl)
  for (const [k, v] of Object.entries(exchange.auth.authorizeParams ?? {}))
    url.searchParams.set(k, v)
  url.searchParams.set("response_type", "code")
  url.searchParams.set("client_id", client.publicFields.client_id ?? "")
  url.searchParams.set("redirect_uri", flow.platform?.redirectUri ?? "")
  const requested = [...new Set([...scopes.identity, ...flow.scopes, ...(scopes.offline ? [scopes.offline] : [])])]
  if (requested.length > 0)
    url.searchParams.set(scopes.param, requested.join(scopes.separator))
  url.searchParams.set("state", state)
  if (pkce) {
    url.searchParams.set("code_challenge", challenge)
    url.searchParams.set("code_challenge_method", "S256")
  }
  if (catalogue?.auth.accountHint && flow.expect)
    url.searchParams.set(catalogue.auth.accountHint.param, flow.expect)
  return { connect: row.id, authorizeUrl: url.href, expiresAt: new Date(row.expires_at).toISOString() }
}

// Route 17: what the platform's callback received. The state is found only
// in this subject's workspace and spent before any network call. The code
// is exchanged with the client secret, opened here, and the PKCE verifier
// when a challenge was sent.
async function finishPlatformConnect(ctx: VaultContext, p: WorkspaceRuntimePrincipal, input: unknown, i: WorkspaceInvocationContext): Promise<PlatformConnectFinished> {
  const member = platformMember(i, p)
  const { body } = parseOpInput(PlatformConnectFinishInput, input)
  const stateHash = await sha256Text(body.state)
  // The claim deletes the state row, so the state is used once; a state
  // already spent is still found through its connect, and is a conflict.
  const { row, flow, client } = subjectWrite(ctx, () => {
    const state = one(ctx.sql.exec<PlatformConnectState>("SELECT * FROM platform_connect_states WHERE state_hash=?", stateHash))
    if (!state) {
      const spent = one(ctx.sql.exec<{ id: string }>("SELECT id FROM workspace_credential_requests WHERE kind='connect' AND json_extract(payload,'$.platformStarted.stateHash')=?", stateHash))
      throw spent ? new VaultError("conflict", "This sign-in has already been used.") : new VaultError("not_found", "No such connection.")
    }
    ctx.sql.exec("DELETE FROM platform_connect_states WHERE state_hash=?", stateHash)
    if (state.expires_at <= ctx.now())
      return null
    const row = connectRow(ctx, state.connect), flow = flowOf(row)
    if (flow.platformStarted?.stateHash !== stateHash)
      throw new VaultError("not_found", "No such connection.")
    const { client } = flowAuthority(ctx, member, row, flow, i)
    return { row, flow, client }
  }) ?? expiredConnect()
  const exchange = exchangeFor(ctx, flow.provider, client)
  const settle = (status: "failed" | "mismatch", reason: PlatformConnectFailure): PlatformConnectFinished => {
    subjectWrite(ctx, () => {
      ctx.sql.exec("UPDATE workspace_credential_requests SET status=? WHERE id=? AND status='open'", status, row.id)
      platformConnectAudit(ctx, member, { ...row, status }, "oauth.connect_finish", exchange, { reason })
    })
    return { connect: row.id, status: "failed", reason }
  }
  if (body.error !== undefined || body.code === undefined)
    return settle("failed", "denied")
  const started = flow.platformStarted, redirectUri = flow.platform?.redirectUri
  if (!started || !redirectUri)
    throw new VaultError("conflict", "Start the connection first.")
  assertPublicClientPkce(exchange)
  const verifier = new TextDecoder().decode(await ctx.openField({ type: "workspace-oauth-verifier", id: row.id }, { rootVersion: started.verifier.root, wrappedDek: base64UrlDecode(started.verifier.dek), ciphertext: base64UrlDecode(started.verifier.ct) }))
  const secret = exchange.auth.clientAuth === "none" ? "" : (await openCredentialSecrets(ctx, client)).client_secret ?? ""
  flowAuthority(ctx, member, requestRow(ctx, row.id), flow, i)
  const tokens = await tokenRequest(exchange, client, secret, { grant_type: "authorization_code", code: body.code, redirect_uri: redirectUri, ...(started.pkce ? { code_verifier: verifier } : {}) })
  if (tokens.kind === "transient") {
    settle("failed", "provider")
    throw new VaultError("upstream_failed", `${exchange.displayName} did not answer; start the connection again.`)
  }
  if (tokens.kind !== "ok")
    return settle("failed", "provider")
  if (grantedBeyond(exchange, flow.scopes, tokens.scopes).length) {
    await revokeToken(exchange, tokens.accessToken)
    return settle("failed", "wider")
  }
  const catalogue = flow.provider === CUSTOM_OAUTH_PROVIDER_ID ? null : providerOf(flow.provider)
  let identity: { subject: string; tenant: string | null } | null = null
  let account: string | null = null
  if (catalogue) {
    const probed = await probeIdentity(catalogue, tokens.accessToken, tokens.body)
    if (typeof probed === "string")
      return settle("failed", "provider")
    const pinned = flow.pinnedIdentity
    if (pinned ? pinned.subject !== probed.subject || pinned.tenant !== probed.tenant : flow.expect !== null && flow.expect.toLowerCase() !== probed.label.toLowerCase())
      return settle("mismatch", "mismatch")
    identity = { subject: probed.subject, tenant: probed.tenant }
    account = probed.label
  }
  const previous = flow.target
  const secretFields: Record<string, string> = { access_token: tokens.accessToken }
  if (tokens.refreshToken)
    secretFields.refresh_token = tokens.refreshToken
  // A connection's binding and injection come from its provider when it is
  // made and never change after; a custom provider's connection has no
  // template, so its policy holds every request (customItemPolicy).
  const prepared = await prepareCredential(ctx, { slug: row.slug, kind: "oauth-connection", provider: catalogue?.id ?? null, account, accountVerified: identity !== null, tags: flow.tags, home: requestHome(row), ceiling: previous?.ceiling ?? KINDS["oauth-connection"].defaultCeiling, binding: previous?.binding ?? exchange.upstream.binding, policy: previous?.policy ?? (catalogue ? connectionPolicy(catalogue) : customItemPolicy(false)), injection: previous?.injection ?? exchange.upstream.injection, publicFields: {}, secretFields, description: previous?.description ?? (catalogue ? null : exchange.displayName) }, previous, flow.requestItemId)
  const stored = subjectWrite(ctx, () => {
    const live = requestRow(ctx, row.id), latest = flowOf(live)
    flowAuthority(ctx, member, live, latest, i)
    if (canonicalJson(flow) !== canonicalJson(latest))
      throw new VaultError("conflict", "The connection changed during sign-in.")
    // The item limit again, for a new item: intakes and connects counted
    // at their start may have filled it since this one began.
    if (previous === null && managedItemsFull(ctx)) {
      ctx.sql.exec("UPDATE workspace_credential_requests SET status='failed' WHERE id=? AND status='open'", row.id)
      platformConnectAudit(ctx, member, { ...live, status: "failed" }, "oauth.connect_finish", exchange, { reason: "quota" })
      return null
    }
    const stored = commitConnection(ctx, member, { row, flow, client, previous, prepared, identity, tokens, session: null })
    platformConnectAudit(ctx, member, { ...live, status: "completed" }, "oauth.connect_finish", exchange)
    return stored
  })
  // Refused at the limit: the grant is handed back to the provider, best
  // effort, and nothing is kept.
  if (stored === null) {
    await revokeToken(exchange, tokens.refreshToken ?? tokens.accessToken)
    throw overLimit()
  }
  return { connect: row.id, status: "completed", item: items.summarise(managedPolicyView(ctx, stored)) }
}

// A state past its time is spent with the claim that found it.
function expiredConnect(): never {
  throw new VaultError("conflict", "This connection has expired; start it again.")
}

function platformConnectStatus(ctx: VaultContext, row: CredentialRequest): ConnectStatus["status"] {
  return row.status === "cancelled" ? "failed" : row.status === "open" && row.expires_at <= ctx.now() ? "expired" : row.status as ConnectStatus["status"]
}

// Route 18.
function getPlatformConnect(ctx: VaultContext, p: WorkspaceRuntimePrincipal, input: unknown, i: WorkspaceInvocationContext): ConnectStatus {
  const member = platformMember(i, p)
  const { params } = parseOpInput(PlatformConnectInput, input)
  const row = connectRow(ctx, params.connect)
  requestAuthority(ctx, member, row, i)
  const status = platformConnectStatus(ctx, row)
  const item = status === "completed" ? checkedCredential(ctx, row.slug) : null
  const connection = item ? one(ctx.sql.exec<{ payload: string }>("SELECT payload FROM workspace_oauth_connections WHERE item=?", item.id)) : null
  const grantedScopes = connection ? (JSON.parse(connection.payload) as { scopes: string[] }).scopes : null
  return { connect: row.id, status, expiresAt: new Date(row.expires_at).toISOString(), ...(item ? { item: items.summarise(managedPolicyView(ctx, item)) } : {}), ...(item?.account ? { account: item.account } : {}), ...(grantedScopes ? { grantedScopes } : {}) }
}

// Route 19: its state is spent with it, so a late callback finds it used.
function cancelPlatformConnect(ctx: VaultContext, p: WorkspaceRuntimePrincipal, input: unknown, i: WorkspaceInvocationContext): Record<string, never> {
  const member = platformMember(i, p)
  const { params } = parseOpInput(PlatformConnectInput, input)
  connectRow(ctx, params.connect)
  return subjectWrite(ctx, () => {
    const cancelled = cancelCredentialRequest(ctx, member, params.connect, "connect", i)
    ctx.sql.exec("DELETE FROM platform_connect_states WHERE connect=?", params.connect)
    return cancelled
  })
}

export const workspaceOAuthOps = {
  "oauth.connect_action": { auth: ["account"] as const, handler(ctx: VaultContext, p: AccessPrincipal, input: unknown, i: WorkspaceInvocationContext) { const { connect, home } = parseOpInput(z.object({ connect: z.string(), home: CredentialHomeSchema.optional() }), input); const row = connectRow(ctx, connect), flow = flowOf(row); const { client } = flowAuthority(ctx, p, row, flow, i, home); return connectStartAction(row, flow, client, home); } },
  "oauth.connectCreate": { auth: ["device"] as const, handler: createWorkspaceConnect },
  "oauth.connectCreateByMember": { auth: ["account"] as const, handler: createWorkspaceConnect },
  "oauth.connectStart": { auth: ["account"] as const, handler: startWorkspaceConnect },
  "oauth.connectFinish": { auth: ["account"] as const, handler: finishWorkspaceConnect },
  "oauth.connectView": { auth: ["account"] as const, handler(ctx: VaultContext, p: AccessPrincipal, input: unknown, i: WorkspaceInvocationContext): WorkspaceConnectView {
      const { connect } = parseOpInput(z.object({ connect: z.string() }), input), row = requestRow(ctx, connect)
      requestAuthority(ctx, p, row, i)
      const f = flowOf(row), provider = providerOf(f.provider), item = row.status === "completed" ? checkedCredential(ctx, row.slug) : null
      let clientView:CheckedCredential|null=null
    // The client start would sign with (connect_action reads it by slug), so
    // the page can compare it before the passkey; absent while it is not yet
    // added or not visible to this reader.
    try{clientView=visibleCredential(ctx,p,f.client?.slug ?? f.clientSlug,undefined,i)}catch(error){if(!(error instanceof VaultError)||error.code!=="not_found")throw error}
    const previous=f.target?one(ctx.sql.exec<{payload:string}>("SELECT payload FROM workspace_oauth_connections WHERE item=?",f.target.id)):null
    const currentScopes=previous?(JSON.parse(previous.payload) as {scopes:string[]}).scopes:null
    const status: ConnectStatus["status"] = row.status === "cancelled" ? "failed" : row.status === "open" && row.expires_at <= ctx.now() ? "expired" : row.status as ConnectStatus["status"]
      return { connect: row.id, status, provider: provider.id, providerName: provider.displayName, slug: row.slug, scopes: f.scopes, tags: f.tags, expect: f.expect, reason: f.reason, requestedBy: row.requester_device ? { device: row.requester_device, deviceName: devicePolicyState(ctx, row.requester_device)?.name ?? row.requester_device, session: f.session, ...askingWorkload(ctx, row.requester_workload) } : { member: row.requester_member ?? "", self: p.kind === "member" && p.memberId === row.requester_member }, reconnect: f.target !== null, currentScopes, account: item?.account ?? null, message: row.status === "cancelled" ? "This connection was cancelled." : null, expiresAt: new Date(row.expires_at).toISOString(), ...credentialCreationContext(ctx, p, requestHome(row), f.target, clientView, i), ...(f.intake ? { awaiting: { intake: f.intake, url: `${ctx.env.VAULT_ORIGIN}/w/${i.workspace.slug}/i/${f.intake}`, status: requestRow(ctx, f.intake).status as import("@mehen/protocol/api").IntakeStatus["status"] } } : {}) }
    } },
  "oauth.connectStatus": { auth: ["device"] as const, async handler(ctx: VaultContext, p: AccessPrincipal, input: unknown, i: WorkspaceInvocationContext): Promise<ConnectStatus> {
      const { connect, wait, waitMs } = parseOpInput(z.object({ connect: z.string(), ...RequestWait }), input)
      const row = await waitForCredentialRequest(ctx, p, connect, i, waitMs ?? (wait ? 30000 : 0))
      return { connect: row.id, status: row.status === "cancelled" ? "failed" : row.status === "open" && row.expires_at <= ctx.now() ? "expired" : row.status as ConnectStatus["status"], expiresAt: new Date(row.expires_at).toISOString(), ...(row.status === "completed" ? { item: describeCredential(ctx, visibleCredential(ctx, p, row.slug, undefined, i), { principal: p, invocation: i }) } : {}) }
    } },
  "oauth.connectCancel": { auth: ["account", "device"] as const, handler(ctx: VaultContext, p: AccessPrincipal, input: unknown, i: WorkspaceInvocationContext) { const { connect } = parseOpInput(z.object({ connect: z.string() }), input); return cancelCredentialRequest(ctx, p, connect, "connect", i); } },
}

// Routes 16 to 19, admitted to platform auth alone (routes/platform-oauth.ts).
export const platformOAuthOps = {
  "platform.connects.start": { auth: ["platform"], handler: startPlatformConnect },
  "platform.connects.finish": { auth: ["platform"], handler: finishPlatformConnect },
  "platform.connects.get": { auth: ["platform"], handler: getPlatformConnect },
  "platform.connects.cancel": { auth: ["platform"], handler: cancelPlatformConnect },
} satisfies NonNullable<Area["workspaceOps"]>