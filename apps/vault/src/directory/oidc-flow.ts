import { canonicalJson, satisfiesRule, WorkspaceRoleSchema, WorkspaceStepUpActionSchema, type WorkspaceStepUpAction, type IdentityRule, type SessionIdentityCheck, IdentityRuleSchema, OIDC_PROVIDERS, type OidcClaims } from "@mehen/protocol"
import { z } from "zod"
import type { Env } from "../env.ts"
import { invokeVault } from "../vault/client.ts"
import type { OperationCheck } from "../vault/core.ts"
import { randomId } from "../vault/core.ts"
import { VaultError } from "../http.ts"
import type { AccountWebSession } from "./account-session.ts"
import { accountBatch, accountEvent, accountGuard } from "./account-store.ts"
import { exchangeGoogleCode, googleError, oidcConfigured, oidcInviteNotFound, OidcPurpose, oidcRefusal } from "./oidc.ts"
import { randomToken, readCookie, sha256Text } from "./session.ts"

export const OIDC_COOKIE = "__Host-mehen_oidc"
export const OidcCheckContext = z.strictObject({ member: z.string().nullable(), inviteTermsDigest: z.string().optional(),inviteRole: WorkspaceRoleSchema.optional(), rule: IdentityRuleSchema, ruleRevision: z.number().int().nonnegative(), gateGeneration: z.number().int().nonnegative(), sequence: z.number().int().nonnegative(), startedAt: z.number().int().nonnegative(), purpose: z.enum(["session", "enrolment", "acceptance", "rescope", "activation", "promotion", "rule"]), subjectDigest: z.string().nullable() })
export type OidcContext = z.infer<typeof OidcCheckContext>
export type OidcBinding = { purpose: z.infer<typeof OidcPurpose>; account?: AccountWebSession; inviteHash?: string; workspace?: string; context?: OidcContext; app?: { sessionHash: string; challenge: string }; next?: string }
export type OidcResult = { id: string; cookie_hash: string; purpose: z.infer<typeof OidcPurpose>; issuer: "https://accounts.google.com"; subject: string; email: string; domain: string | null; name: string | null; account: string | null; session: string | null; security_epoch: number | null; invite_hash: string | null; workspace: string | null; rule_revision: number | null; gate_generation: number | null; created_at: number; expires_at: number; app_session_hash: string | null; app_pkce_challenge: string | null; state: "unused" | "joining" | "consumed"; joining_membership: string | null; joining_identity: string | null; check_context: string | null; next?: string | null }
type Flow = Omit<OidcResult, "id" | "issuer" | "subject" | "email" | "domain" | "name" | "state" | "joining_membership"> & { nonce: string; pkce_verifier: string; next_path: string | null }
export function oidcNext(value: string | undefined | null): string | null { return value && value.startsWith("/") && !value.startsWith("//") && !/[\\\u0000-\u001f\u007f#]/.test(value) ? value : null }
export function oidcCookie(token: string, maxAgeSeconds = 600): string { return `${OIDC_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}` }
function oidcCookieValue(request: Request): string | null { const token = readCookie(request, OIDC_COOKIE); return token && /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null }
// The callback sets the cookie again to last as long as the result, so a
// result used without it either ran out of time or is in another browser.
export function oidcCookieToken(request: Request, purpose: z.infer<typeof OidcPurpose>): string { const token = oidcCookieValue(request); if (!token) throw oidcRefusal("result_cookie_missing", purpose); return token }
export async function assertOidcSession(env: Env, account: string, session: string, epoch: number, kind: "web" | "app", purpose: z.infer<typeof OidcPurpose>, now = Date.now()): Promise<void> {
  if (await env.DB.prepare(`SELECT s.id FROM web_sessions s JOIN accounts a ON a.id=s.account WHERE s.id=? AND a.id=? AND s.kind=? AND a.status='active' AND a.security_epoch=? AND a.security_transition IS NULL AND (a.restricted_until IS NULL OR a.restricted_until<=?) AND s.expires_at>? AND s.last_seen_at>?`).bind(session, account, kind, epoch, now, now, now - 7 * 86400000).first()) return
  const row = await env.DB.prepare("SELECT status,security_epoch,security_transition,restricted_until FROM accounts WHERE id=?").bind(account).first<{ status: string; security_epoch: number; security_transition: string | null; restricted_until: number | null }>()
  if (row?.status === "active" && (row.security_epoch !== epoch || row.security_transition !== null)) throw oidcRefusal("epoch_changed", purpose)
  if (row?.status === "active" && row.restricted_until !== null && row.restricted_until > now) throw oidcRefusal("account_restricted", purpose)
  throw oidcRefusal("session_ended", purpose)
}
// Says which check a flow the callback could not consume failed; the
// consuming update itself stays one atomic statement.
async function oidcFlowRefusal(env: Env, stateHash: string, cookie: string | null, now: number, app = false): Promise<VaultError> {
  const flow = await env.DB.prepare("SELECT purpose,cookie_hash,consumed_at,created_at,expires_at,app_session_hash,app_launched_at FROM oidc_flows WHERE state_hash=?").bind(stateHash).first<{ purpose: z.infer<typeof OidcPurpose>; cookie_hash: string; consumed_at: number | null; created_at: number; expires_at: number; app_session_hash: string | null; app_launched_at: number | null }>()
  if (!flow || app && (flow.purpose !== "gate" || flow.app_session_hash === null)) return oidcRefusal("state_unknown", app ? "gate" : null)
  // Expiry first: the browser drops the flow cookie when the flow expires.
  const minutes = Math.round((flow.expires_at - flow.created_at) / 60000)
  if (flow.consumed_at === null && !(app && flow.app_launched_at !== null) && flow.expires_at <= now) return oidcRefusal("flow_expired", flow.purpose, undefined, minutes)
  if (!cookie) return oidcRefusal("cookie_missing", flow.purpose)
  if (flow.cookie_hash !== await sha256Text(cookie)) return oidcRefusal("cookie_mismatch", flow.purpose)
  return oidcRefusal("flow_consumed", flow.purpose, undefined, minutes)
}
export async function startOidcFlow(env: Env, binding: OidcBinding, now = Date.now()): Promise<{ url: string; cookie: string }> {
  if (!oidcConfigured(env)) throw oidcRefusal("not_configured", binding.purpose)
  if (binding.account) await assertOidcSession(env, binding.account.account, binding.account.session, binding.account.securityEpoch, binding.app ? "app" : "web", binding.purpose, now)
  const state = randomToken(), cookie = randomToken(), nonce = randomToken(), verifier = randomToken()
  const context = binding.context ? OidcCheckContext.parse(binding.context) : null
  const next = oidcNext(binding.next)
  // Only an invitation's own step carries one: a stale page's invitation on a sign-in or link is ignored, not refused.
  const inviteHash = binding.purpose === "invite" ? binding.inviteHash : undefined
  await env.DB.prepare(`INSERT INTO oidc_flows(state_hash,cookie_hash,provider,purpose,account,session,security_epoch,invite_hash,workspace,rule_revision,gate_generation,nonce,pkce_verifier,next_path,created_at,expires_at,app_session_hash,app_pkce_challenge,check_context) VALUES (?,?,'google',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(await sha256Text(state), await sha256Text(cookie), binding.purpose, binding.account?.account ?? null, binding.account?.session ?? null, binding.account?.securityEpoch ?? null, inviteHash ?? null, binding.workspace ?? null, context?.ruleRevision ?? null, context?.gateGeneration ?? null, nonce, verifier, next, now, now + (binding.app ? 300000 : 600000), binding.app?.sessionHash ?? null, binding.app?.challenge ?? null, context ? JSON.stringify(context) : null).run()
  const url = googleAuthoriseUrl(env,state,nonce,await sha256Text(verifier),context)
  if (inviteHash) {
    const invite = await env.DB.prepare("SELECT email FROM invite_codes WHERE code_hash=? AND kind='join' AND state='active' AND expires_at>?").bind(inviteHash, now).first<{ email: string | null }>()
    if (!invite) throw oidcInviteNotFound("invite")
    if (invite.email) url.searchParams.set("login_hint", invite.email)
  }
  if (binding.app) return { url: `${env.VAULT_ORIGIN}/auth/oidc/google/app/start#${new URLSearchParams({ state,flow: cookie })}`,cookie: oidcCookie(cookie) }
  return { url: url.toString(), cookie: oidcCookie(cookie) }
}
function googleAuthoriseUrl(env: Env,state: string,nonce: string,verifier: string,context: OidcContext | null): URL {
  const url = new URL(OIDC_PROVIDERS.google.authorise)
  for (const [key,value] of Object.entries({ client_id: env.GOOGLE_SIGNIN_CLIENT_ID!,redirect_uri: `${env.VAULT_ORIGIN}/auth/oidc/google/callback`,response_type: "code",scope: OIDC_PROVIDERS.google.scopes.join(" "),state,nonce,code_challenge: verifier,code_challenge_method: "S256",prompt: "select_account" })) url.searchParams.set(key,value)
  if (context?.rule?.domains[0]) url.searchParams.set("hd",context.rule.domains[0])
  return url
}
export async function bootstrapAppOidc(env: Env,state: string,flowToken: string,now = Date.now()): Promise<{ url: string; cookie: string }> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(state)) throw oidcRefusal("state_unknown","gate")
  if (!/^[A-Za-z0-9_-]{43}$/.test(flowToken)) throw oidcRefusal("cookie_missing","gate")
  const stateHash = await sha256Text(state),flow = await env.DB.prepare("UPDATE oidc_flows SET app_launched_at=? WHERE state_hash=? AND cookie_hash=? AND purpose='gate' AND app_session_hash IS NOT NULL AND app_launched_at IS NULL AND consumed_at IS NULL AND expires_at>? RETURNING *").bind(now,stateHash,await sha256Text(flowToken),now).first<Flow>()
  if (!flow) throw await oidcFlowRefusal(env,stateHash,flowToken,now,true)
  await assertOidcSession(env,flow.account!,flow.session!,flow.security_epoch!,"app","gate",now)
  const url = googleAuthoriseUrl(env,state,flow.nonce,await sha256Text(flow.pkce_verifier),flow.check_context ? OidcCheckContext.parse(JSON.parse(flow.check_context)) : null)
  return { url: url.toString(),cookie: oidcCookie(flowToken) }
}

// resultCookie sets the flow cookie again to last as long as the result, so
// the browser that finished the step can still use it.
export async function callbackOidcFlow(env: Env, request: Request, now = Date.now()): Promise<OidcResult & { resultCookie: string }> {
  const url = new URL(request.url), state = url.searchParams.get("state"), code = url.searchParams.get("code")
  if (!state || state.length > 256) throw oidcRefusal("state_unknown", null)
  const stateHash = await sha256Text(state), cookie = oidcCookieValue(request)
  const flow = cookie ? await env.DB.prepare("UPDATE oidc_flows SET consumed_at=? WHERE state_hash=? AND cookie_hash=? AND consumed_at IS NULL AND expires_at>? RETURNING *").bind(now, stateHash, await sha256Text(cookie), now).first<Flow>() : null
  if (!flow) throw await oidcFlowRefusal(env, stateHash, cookie, now)
  if (url.searchParams.has("error")) throw oidcRefusal("provider_error", flow.purpose, googleError(url.searchParams.get("error")))
  if (!code || code.length > 4096) throw oidcRefusal("code_missing", flow.purpose)
  if (flow.account) await assertOidcSession(env, flow.account, flow.session!, flow.security_epoch!, flow.app_session_hash ? "app" : "web", flow.purpose, now)
  const claims = await exchangeGoogleCode(env, code, flow.pkce_verifier, flow.nonce, flow.purpose, now)
  if (flow.account) await assertOidcSession(env, flow.account, flow.session!, flow.security_epoch!, flow.app_session_hash ? "app" : "web", flow.purpose)
  if (flow.invite_hash) {
    const invite = await env.DB.prepare("SELECT email FROM invite_codes WHERE code_hash=? AND kind='join' AND state='active' AND expires_at>?").bind(flow.invite_hash, now).first<{ email: string | null }>()
    if (!invite) throw oidcRefusal("invite_inactive", flow.purpose)
    if (invite.email !== null && invite.email !== claims.email) throw oidcRefusal("invite_email_mismatch", flow.purpose)
    if (!flow.check_context) throw oidcRefusal("invite_context_missing", flow.purpose)
    const saved = OidcCheckContext.parse(JSON.parse(flow.check_context)),current = await inviteIdentityContext(env,flow.invite_hash,flow.purpose)
    if (saved.inviteTermsDigest !== current.termsDigest || saved.ruleRevision !== current.identityRuleRev || canonicalJson(saved.rule) !== canonicalJson(current.identityRule) || !saved.inviteRole) throw oidcRefusal("invite_changed", flow.purpose)
    if (!satisfiesRule(claims,saved.rule,saved.inviteRole)) throw oidcRefusal("domain_rule", flow.purpose)
  }
  const id = randomId("oidr")
  await env.DB.prepare(`INSERT INTO oidc_results(id,cookie_hash,provider,issuer,subject,email,domain,name,email_verified,purpose,account,session,security_epoch,invite_hash,workspace,rule_revision,gate_generation,created_at,expires_at,app_session_hash,app_pkce_challenge,check_context) VALUES (?,?,'google',?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id, flow.cookie_hash, claims.issuer, claims.subject, claims.email, claims.domain, claims.name, flow.purpose, flow.account, flow.session, flow.security_epoch, flow.invite_hash, flow.workspace, flow.rule_revision, flow.gate_generation, now, now + 600000, flow.app_session_hash, flow.app_pkce_challenge, flow.check_context).run()
  const row = (await env.DB.prepare("SELECT * FROM oidc_results WHERE id=?").bind(id).first<OidcResult>())!
  return { ...row,next: flow.next_path,resultCookie: oidcCookie(cookie!,Math.ceil((row.expires_at - now) / 1000)) }
}
export async function readOidcResult(env: Env, id: string, cookie: string, purpose: z.infer<typeof OidcPurpose>, now = Date.now()): Promise<OidcResult> {
  if (id.length > 128) throw oidcRefusal("result_unavailable", purpose)
  const row = await env.DB.prepare("SELECT * FROM oidc_results WHERE id=? AND cookie_hash=? AND purpose=? AND expires_at>? AND consumed_at IS NULL AND state IN ('unused','joining')").bind(id, await sha256Text(cookie), purpose, now).first<OidcResult>()
  if (!row) throw oidcRefusal("result_unavailable", purpose)
  if (row.check_context) OidcCheckContext.parse(JSON.parse(row.check_context))
  return row
}
export function resultClaims(result: OidcResult): OidcClaims { return { issuer: result.issuer, subject: result.subject, email: result.email, emailVerified: true, domain: result.domain, name: result.name, issuedAt: Math.floor(result.created_at / 1000), expiresAt: Math.floor(result.expires_at / 1000) } }
export function oidcResultGuard(env: Env, result: OidcResult, now: number): D1PreparedStatement { return accountGuard(env, "EXISTS (SELECT 1 FROM oidc_results WHERE id=? AND cookie_hash=? AND purpose=? AND expires_at>? AND consumed_at IS NULL AND state=? AND account IS ? AND joining_membership IS ?)", [result.id, result.cookie_hash, result.purpose, now, result.state, result.account, result.joining_membership]) }
export function consumeOidcResult(env: Env, result: OidcResult, now: number): D1PreparedStatement { return env.DB.prepare("UPDATE oidc_results SET state='consumed',consumed_at=? WHERE id=?").bind(now, result.id) }
export async function identityForResult(env: Env, result: OidcResult): Promise<{ id: string; account: string } | null> { return env.DB.prepare("SELECT id,account FROM oidc_identities WHERE issuer=? AND subject=?").bind(result.issuer, result.subject).first() }
export function linkIdentityStatements(env: Env, result: OidcResult, account: string, now: number,identityId = randomId("oid")): D1PreparedStatement[] {
  return [accountGuard(env, "NOT EXISTS (SELECT 1 FROM oidc_identities WHERE issuer=? AND subject=? AND account!=?)", [result.issuer, result.subject, account]), env.DB.prepare(`INSERT INTO oidc_identities(id,account,provider,issuer,subject,email,domain,name,email_verified,linked_at,last_verified_at) VALUES (?,?,'google',?,?,?,?,?,1,?,?) ON CONFLICT(issuer,subject) DO UPDATE SET email=excluded.email,domain=excluded.domain,name=excluded.name,last_verified_at=excluded.last_verified_at WHERE oidc_identities.account=excluded.account`).bind(identityId, account, result.issuer, result.subject, result.email, result.domain, result.name, now, now)]
}
export async function finishOidcLink(env: Env, account: AccountWebSession, result: OidcResult, confirmed: { email: string; subject: string }, now = Date.now()): Promise<void> {
  if (result.purpose !== "link" || result.state !== "unused") throw oidcRefusal("result_unavailable", "link")
  if (result.account !== account.account || result.session !== account.session || result.security_epoch !== account.securityEpoch) throw oidcRefusal("account_mismatch", "link")
  if (confirmed.email !== result.email || confirmed.subject !== result.subject) throw oidcRefusal("confirmation_mismatch", "link")
  await assertOidcSession(env, account.account, account.session, account.securityEpoch, "web", "link", now)
  await accountBatch(env, [oidcResultGuard(env, result, now), accountGuard(env, "EXISTS (SELECT 1 FROM web_sessions s JOIN accounts a ON a.id=s.account WHERE s.id=? AND a.id=? AND a.security_epoch=? AND a.security_transition IS NULL AND (a.restricted_until IS NULL OR a.restricted_until<=?) AND s.kind='web' AND s.expires_at>? AND s.last_seen_at>?)", [account.session, account.account, account.securityEpoch, now, now, now - 7 * 86400000]), ...linkIdentityStatements(env, result, account.account, now), consumeOidcResult(env, result, now), accountEvent(env, account.account, "account.identity_link", { provider: "google" }, now)])
}

// The system projection is available even while the member needs a gate. It
// supplies facts only; the install and protected mutation recheck authority.
export const OidcIdentityContext = z.strictObject({ member: z.string(),role: WorkspaceRoleSchema,pendingRole: WorkspaceRoleSchema.nullable(),pendingAction: WorkspaceStepUpActionSchema.nullable(),identityRule: IdentityRuleSchema,identityRuleRev: z.number().int().nonnegative(),gateGeneration: z.number().int().nonnegative(),checkSequence: z.number().int().nonnegative(),status: z.enum(["unconfirmed","active","suspended","removed"]) })
export async function oidcIdentityContext(env: Env,workspace: string,account: string) { return OidcIdentityContext.parse(await invokeVault(env,workspace,{ op: "access.identity.context",input: { account },auth: { kind: "system",reason: "OIDC identity context" } })) }
export async function startWorkspaceGate(env: Env,account: AccountWebSession,workspace: string,input: { action?: WorkspaceStepUpAction; rule?: IdentityRule; app?: { sessionHash: string; challenge: string }; next?: string },now = Date.now()) {
  const context = await oidcIdentityContext(env,workspace,account.account)
  if (context.status !== "active" && context.status !== "unconfirmed") throw oidcRefusal("member_inactive","gate")
  let purpose: OidcContext["purpose"] = "session",action = input.action,rule = context.identityRule
  if (input.rule !== undefined) {
    if (context.role !== "owner") throw new VaultError("forbidden","Only an owner can change the identity rule.")
    rule = input.rule; action = { type: "workspace.identity_rule",rule }; purpose = "rule"
  } else if (context.pendingRole && context.pendingAction) { action = context.pendingAction; purpose = "promotion" }
  else if (action) {
    if (action.type === "enrol.accept") purpose = "acceptance"
    else if (action.type === "enrol.approve") purpose = "enrolment"
    else if (action.type === "device.rescope_accept" || action.type === "device.rescope") purpose = "rescope"
    else throw new VaultError("bad_request","This action does not use an exact identity check.")
  }
  const checkContext: OidcContext = { member: context.member,rule,ruleRevision: context.identityRuleRev,gateGeneration: context.gateGeneration,sequence: context.checkSequence+1,startedAt: now,purpose,subjectDigest: action ? await sha256Text(canonicalJson(action)) : null }
  return startOidcFlow(env,{ purpose: "gate",account,workspace,context: checkContext,app: input.app,next: input.next },now)
}
async function validateGateResult(env: Env,result: OidcResult,account: AccountWebSession,kind: "web" | "app",now: number) {
  if (result.purpose !== "gate" || (result.app_session_hash !== null) !== (kind === "app") || !result.workspace || !result.check_context || result.state !== "unused") throw oidcRefusal("result_unavailable","gate")
  if (result.account !== account.account || result.session !== account.session || result.security_epoch !== account.securityEpoch) throw oidcRefusal("account_mismatch","gate")
  await assertOidcSession(env,account.account,account.session,account.securityEpoch,kind,"gate",now)
  const saved = OidcCheckContext.parse(JSON.parse(result.check_context)),current = await oidcIdentityContext(env,result.workspace,account.account),identity = await identityForResult(env,result)
  if (!identity || identity.account !== account.account) throw oidcRefusal("no_linked_identity","gate")
  if (current.status !== "active") throw oidcRefusal("member_inactive","gate")
  if (current.member !== saved.member || current.identityRuleRev !== saved.ruleRevision || current.gateGeneration !== saved.gateGeneration || current.checkSequence >= saved.sequence) throw oidcRefusal("gate_changed","gate")
  const role = saved.purpose === "promotion" ? current.pendingRole : current.role
  if (!role || saved.purpose !== "rule" && canonicalJson(saved.rule) !== canonicalJson(current.identityRule)) throw oidcRefusal("gate_changed","gate")
  if (!satisfiesRule(resultClaims(result),saved.rule,role)) throw oidcRefusal("domain_rule","gate")
  if (saved.purpose === "promotion" && (!current.pendingAction || await sha256Text(canonicalJson(current.pendingAction)) !== saved.subjectDigest)) throw oidcRefusal("gate_changed","gate")
  const session = await env.DB.prepare("SELECT expires_at FROM web_sessions WHERE id=? AND kind=? AND account=?").bind(account.session,kind,account.account).first<{ expires_at: number }>()
  if (!session) throw oidcRefusal("session_ended","gate")
  return { saved,current,identity,expiresAt: session.expires_at }
}
export async function finishWorkspaceGate(env: Env,account: AccountWebSession,result: OidcResult,kind: "web" | "app" = "web",now = Date.now(),codeHash?: string): Promise<void> {
  const { saved,current,identity,expiresAt } = await validateGateResult(env,result,account,kind,now)
  const id = randomId("chk"),sessionCheck: SessionIdentityCheck = { id,identityRuleRev: saved.ruleRevision,gateGeneration: saved.gateGeneration,checkSequence: saved.sequence,succeededAt: new Date(now).toISOString(),expiresAt: new Date(expiresAt).toISOString() }
  const operationCheck: OperationCheck | undefined = saved.subjectDigest ? { id,subjectDigest: saved.subjectDigest,identityRuleRev: saved.ruleRevision,gateGeneration: saved.gateGeneration,succeededAt: new Date(now).toISOString(),expiresAt: new Date(Math.min(expiresAt,now+600000)).toISOString() } : undefined
  await accountBatch(env,[oidcResultGuard(env,result,now),
    accountGuard(env,"EXISTS (SELECT 1 FROM accounts a JOIN web_sessions s ON s.account=a.id WHERE a.id=? AND s.id=? AND s.kind=? AND a.security_epoch=? AND a.security_transition IS NULL AND (a.restricted_until IS NULL OR a.restricted_until<=?) AND s.expires_at>? AND s.last_seen_at>?)",[account.account,account.session,kind,account.securityEpoch,now,now,now-7*86400000]),
    ...(codeHash ? [accountGuard(env,"EXISTS (SELECT 1 FROM app_gate_codes WHERE code_hash=? AND result=? AND consumed_at IS NULL AND expires_at>?)",[codeHash,result.id,now]),env.DB.prepare("UPDATE app_gate_codes SET consumed_at=? WHERE code_hash=?").bind(now,codeHash)] : []),consumeOidcResult(env,result,now)])
  // Consume before the RPC. A failed or lost install never leaves reusable proof.
  // An install with no D1 projection grants no request authority.
  if (saved.purpose !== "rule") await invokeVault(env,result.workspace!,{ op: "access.identity.install",input: { account: account.account,member: saved.member,session: account.session,securityEpoch: account.securityEpoch,sessionCheck,...(saved.purpose === "promotion" ? { pendingRole: current.pendingRole,operationCheck } : {}) },auth: { kind: "system",reason: "verified interactive OIDC" } })
  await assertOidcSession(env,account.account,account.session,account.securityEpoch,kind,"gate")
  const claims = JSON.stringify({ issuer: result.issuer,subject: result.subject,email: result.email,domain: result.domain,name: result.name })
  await accountBatch(env,[accountGuard(env,"EXISTS (SELECT 1 FROM oidc_identities WHERE id=? AND account=? AND issuer=? AND subject=?)",[identity.id,account.account,result.issuer,result.subject]),
    ...(saved.purpose !== "rule" ? [env.DB.prepare(`INSERT INTO session_identity_checks(id,session,workspace,member,identity,account,session_kind,security_epoch,claims,rule_revision,gate_generation,sequence,started_at,succeeded_at,purpose,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'session',?) ON CONFLICT(session,workspace) DO UPDATE SET id=excluded.id,member=excluded.member,identity=excluded.identity,security_epoch=excluded.security_epoch,claims=excluded.claims,rule_revision=excluded.rule_revision,gate_generation=excluded.gate_generation,sequence=excluded.sequence,started_at=excluded.started_at,succeeded_at=excluded.succeeded_at,expires_at=excluded.expires_at WHERE excluded.member!=session_identity_checks.member OR excluded.sequence>session_identity_checks.sequence`).bind(id,account.session,result.workspace,saved.member,identity.id,account.account,kind,account.securityEpoch,claims,saved.ruleRevision,saved.gateGeneration,saved.sequence,saved.startedAt,now,expiresAt)] : []),
    ...(operationCheck ? [env.DB.prepare("INSERT INTO operation_identity_checks(id,session,workspace,member,identity,account,session_kind,security_epoch,claims,rule_revision,gate_generation,sequence,started_at,succeeded_at,purpose,subject_digest,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(id,account.session,result.workspace,saved.member,identity.id,account.account,kind,account.securityEpoch,claims,saved.ruleRevision,saved.gateGeneration,saved.sequence,saved.startedAt,now,saved.purpose,saved.subjectDigest,Math.min(expiresAt,now+600000))] : []),
    env.DB.prepare("UPDATE oidc_identities SET last_verified_at=?,email=?,domain=?,name=? WHERE id=?").bind(now,result.email,result.domain,result.name,identity.id)])
}
export async function createAppGateCode(env: Env,result: OidcResult,now = Date.now()): Promise<string> {
  if (!result.account || !result.session || result.security_epoch === null || !result.app_session_hash || !result.app_pkce_challenge) throw oidcRefusal("result_unavailable","gate")
  const account: AccountWebSession = { account: result.account,session: result.session,securityEpoch: result.security_epoch,name: "",restrictedUntil: null,transition: null }
  const { saved } = await validateGateResult(env,result,account,"app",now),code = randomToken()
  await env.DB.prepare("INSERT INTO app_gate_codes(code_hash,app_session_hash,account,security_epoch,app_pkce_challenge,workspace,member,rule_revision,gate_generation,result,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)").bind(await sha256Text(code),result.app_session_hash,account.account,account.securityEpoch,result.app_pkce_challenge,result.workspace,saved.member,saved.ruleRevision,saved.gateGeneration,result.id,now,now+300000).run()
  return `${env.VAULT_ORIGIN}/app/v1/gate/callback#code=${encodeURIComponent(code)}`
}
export async function redeemAppGateCode(env: Env,account: AccountWebSession,sessionHash: string,code: string,verifier: string,now = Date.now()): Promise<void> {
  const codeHash = await sha256Text(code),row = await env.DB.prepare("SELECT c.result,c.app_pkce_challenge FROM app_gate_codes c WHERE c.code_hash=? AND c.account=? AND c.app_session_hash=? AND c.security_epoch=? AND c.consumed_at IS NULL AND c.expires_at>?").bind(codeHash,account.account,sessionHash,account.securityEpoch,now).first<{ result: string; app_pkce_challenge: string }>()
  if (!row || await sha256Text(verifier) !== row.app_pkce_challenge) throw oidcRefusal("result_unavailable","gate")
  const result = await env.DB.prepare("SELECT * FROM oidc_results WHERE id=? AND state='unused' AND consumed_at IS NULL AND expires_at>?").bind(row.result,now).first<OidcResult>()
  if (!result || result.app_session_hash !== sessionHash) throw oidcRefusal("result_unavailable","gate")
  await finishWorkspaceGate(env,account,result,"app",now,codeHash)
}
export async function operationIdentityCheck(env: Env,account: AccountWebSession,workspace: string,kind: "web" | "app",action: WorkspaceStepUpAction,now = Date.now()): Promise<OperationCheck | undefined> {
  const subjectDigest = await sha256Text(canonicalJson(action))
  const row = await env.DB.prepare("UPDATE operation_identity_checks SET consumed_at=? WHERE id=(SELECT id FROM operation_identity_checks WHERE account=? AND session=? AND workspace=? AND session_kind=? AND security_epoch=? AND subject_digest=? AND consumed_at IS NULL AND expires_at>? ORDER BY succeeded_at DESC,id DESC LIMIT 1) AND consumed_at IS NULL RETURNING id,rule_revision,gate_generation,succeeded_at,expires_at").bind(now,account.account,account.session,workspace,kind,account.securityEpoch,subjectDigest,now).first<{ id: string; rule_revision: number; gate_generation: number; succeeded_at: number; expires_at: number }>()
  return row ? { id: row.id,subjectDigest,identityRuleRev: row.rule_revision,gateGeneration: row.gate_generation,succeededAt: new Date(row.succeeded_at).toISOString(),expiresAt: new Date(row.expires_at).toISOString() } : undefined
}

export async function assertWorkspaceSessionGate(env: Env,account: AccountWebSession,workspace: { id: string; slug: string },kind: "web" | "app",now = Date.now(),fresh = false): Promise<void> {
  const context = await oidcIdentityContext(env,workspace.id,account.account)
  if (!context.identityRule?.roles.includes(context.role)) return
  const check = await env.DB.prepare("SELECT c.id,c.succeeded_at FROM session_identity_checks c JOIN oidc_identities i ON i.id=c.identity WHERE c.account=? AND c.session=? AND c.session_kind=? AND c.workspace=? AND c.security_epoch=? AND c.rule_revision=? AND c.gate_generation=? AND c.member=? AND c.expires_at>?").bind(account.account,account.session,kind,workspace.id,account.securityEpoch,context.identityRuleRev,context.gateGeneration,context.member,now).first<{ id: string; succeeded_at: number }>()
  if (!check || check.succeeded_at>now || fresh && now-check.succeeded_at>=43200000) throw new VaultError("identity_required","Verify your workspace identity with Google.",{ next: { url: `${env.VAULT_ORIGIN}/auth/oidc/verify?purpose=gate&workspace=${encodeURIComponent(workspace.slug)}&next=${encodeURIComponent(`/w/${workspace.slug}/`)}`,say: "Verify with Google, then confirm any change with your passkey." } })
}

export const InviteIdentityContext = z.strictObject({ termsDigest: z.string(),role: WorkspaceRoleSchema,identityRule: IdentityRuleSchema,identityRuleRev: z.number().int().nonnegative() })
// A Google step names its purpose, so an invitation it finds no longer active is logged as its refusal.
export async function inviteIdentityContext(env: Env,codeHash: string,googleStep?: z.infer<typeof OidcPurpose>) { const row = await env.DB.prepare("SELECT workspace FROM invite_codes WHERE code_hash=? AND kind='join' AND state='active' AND expires_at>?").bind(codeHash,Date.now()).first<{ workspace: string }>(); if (!row) throw googleStep ? oidcInviteNotFound(googleStep) : new VaultError("not_found","No such invite."); return { ...InviteIdentityContext.parse(await invokeVault(env,row.workspace,{ op: "access.invites.identity_context",input: { codeHash },auth: { kind: "system",reason: "OIDC invite snapshot" } })),workspace: row.workspace } }
export async function startInviteOidc(env: Env,codeHash: string,account: AccountWebSession | null,next?: string,now = Date.now()) {
  const invitation = await inviteIdentityContext(env,codeHash,"invite")
  const membership = account ? await env.DB.prepare("SELECT id FROM memberships WHERE account=? AND workspace=? AND state IN ('joining','member')").bind(account.account,invitation.workspace).first<{ id: string }>() : null
  const member = membership && account ? await oidcIdentityContext(env,invitation.workspace,account.account) : null
  if (member && member.status !== "unconfirmed") throw new VaultError("conflict","This account already belongs to the workspace.")
  const context: OidcContext = { member: member?.member ?? null,inviteTermsDigest: invitation.termsDigest,inviteRole: invitation.role,rule: invitation.identityRule,ruleRevision: invitation.identityRuleRev,gateGeneration: member?.gateGeneration ?? 0,sequence: (member?.checkSequence ?? 0)+1,startedAt: now,purpose: "activation",subjectDigest: null }
  return startOidcFlow(env,{ purpose: "invite",inviteHash: codeHash,...(account ? { account } : {}),workspace: invitation.workspace,context,next },now)
}
export async function assertInviteResultCurrent(env: Env,result: OidcResult): Promise<OidcContext> {
  if (!result.invite_hash || !result.check_context) throw oidcRefusal("invite_context_missing","invite")
  const saved = OidcCheckContext.parse(JSON.parse(result.check_context)),current = await inviteIdentityContext(env,result.invite_hash,"invite")
  if (saved.inviteTermsDigest !== current.termsDigest || saved.ruleRevision !== current.identityRuleRev || canonicalJson(saved.rule) !== canonicalJson(current.identityRule) || !saved.inviteRole) throw oidcRefusal("invite_changed","invite")
  if (!satisfiesRule(resultClaims(result),saved.rule,saved.inviteRole)) throw oidcRefusal("domain_rule","invite")
  return saved
}
