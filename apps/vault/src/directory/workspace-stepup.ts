// v2 commits to both the canonical server action and its workspace. Account
// actions use the literal "-". Legacy v1 remains only until the cutover.
import { PENDING_RESTRICTION_UNTIL, base64UrlEncode, canonicalJson, sha256, timingSafeEqualText, workspaceAllowedWhileRestricted, workspaceStepUpGraced, STEP_UP_GRACE_MS, type StepUpConfirmation, type WorkspaceStepUpAction } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import type { RequestContext, WorkspaceRequest } from "../routes/context.ts"
import { currentAccountSession, type AccountWebSession } from "./account-session.ts"
import { refreshAccountRecoverySetup } from "./account-recovery-setup.ts"
import { accountBatch, accountGuard, findAccountPasskey } from "./account-store.ts"
import { accountSuspendedError } from "./account-suspension.ts"
import { randomToken, sha256Text } from "./session.ts"
import type { StepUpProof } from "@mehen/protocol/step-up-proof"
import { assertWorkspaceSessionGate, operationIdentityCheck } from "./oidc-flow.ts"
import { credentialId, passkeyCeremonies } from "./webauthn.ts"

const REFUSAL = "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again."
const ACCOUNT_ACTIONS = new Set<WorkspaceStepUpAction["type"]>(["workspace.create", "account.delete", "identity.link", "identity.unlink", "passkey.add", "passkey.remove", "recovery.generate", "recovery.resolve", "platform.operate", "platform.administer", "operator.propose", "operator.approve", "operator.accept", "operator.break_glass_link"])
export function stepUpGraceOn(env: Pick<Env, "STEPUP_GRACE">): boolean {
  return (env.STEPUP_GRACE ?? "").trim() === "on"
}
export function workspaceStepUpChallenge(nonce: string, scope: string, action: WorkspaceStepUpAction): Promise<string> {
  return sha256(`mehen-stepup/v2\n${nonce}\n${scope}\n${canonicalJson(action)}`).then(base64UrlEncode)
}
function checkScope(scope: string, action: WorkspaceStepUpAction): void {
  if ((scope === "-") !== ACCOUNT_ACTIONS.has(action.type)) throw new VaultError("bad_request", "That action does not belong to this scope.")
}
// Cancelling recovery is the tightening cure; keeping it is a loosening.
function allowedDuringPending(action: WorkspaceStepUpAction): boolean {
  return workspaceAllowedWhileRestricted(action) && (action.type !== "recovery.resolve" || action.outcome === "cancel")
}
export async function assertAccountStepUpAllowed(env: Env, account: string, action: WorkspaceStepUpAction, now = Date.now()): Promise<void> {
  const row = await env.DB.prepare("SELECT status,suspended_at,restricted_until,security_transition FROM accounts WHERE id=?").bind(account).first<{ status: string; suspended_at: number | null; restricted_until: number | null; security_transition: string | null }>()
  if (!row || row.status !== "active") throw new VaultError("unauthenticated", "Sign in with your passkey to continue.")
  if (row.suspended_at !== null) throw accountSuspendedError()
  const safe = workspaceAllowedWhileRestricted(action)
  if (row.security_transition && !allowedDuringPending(action)) {
    const pending = await env.DB.prepare("SELECT id,reserved_epoch,json_array_length(targets) AS targets,json_array_length(acknowledged) AS acknowledged FROM account_security_transitions WHERE id=? AND state='pending'").bind(row.security_transition).first<{ id: string; reserved_epoch: number; targets: number; acknowledged: number }>()
    if (!pending) throw new VaultError("account_pending", "Account security changes are still pending.", { next: { url: `${env.VAULT_ORIGIN}/account`, say: "Wait for the account security change to complete." } })
    throw new VaultError("account_pending", "Account security changes are still pending.", { transition: { id: pending.id,reservedEpoch: pending.reserved_epoch,targets: pending.targets,acknowledged: pending.acknowledged,state: "pending" },next: { url: `${env.VAULT_ORIGIN}/account`,say: "Wait for the account security change to complete." } })
  }
  if (row.restricted_until !== null && row.restricted_until > now && !safe) throw new VaultError("forbidden", "Your account is cooling off. You can read, narrow, deny, revoke and freeze, but cannot widen access.", { next: { url: `${env.VAULT_ORIGIN}/account`, say: coolingOffSay(row.restricted_until) } })
}
// When the cooling-off ends, in the words the account page uses for it: a
// recovery still committing has no end date yet (PENDING_RESTRICTION_UNTIL).
export function coolingOffSay(until: number): string {
  const ends = until >= PENDING_RESTRICTION_UNTIL ? "It ends once your recovery completes" : `It ends ${new Date(until).toISOString().slice(0, 16).replace("T", " ")} UTC`
  return `${ends}; until then, ask another owner or admin if this cannot wait.`
}
// A browser session's passkey grace window: one challenges
// row per session, opened or renewed only in a passkey ceremony's own
// success batch, never by a confirmation that rode it. Its factor is the
// passkey that signed and its challenge the ceremony time, kept so a graced
// confirmation's provenAt does not depend on STEP_UP_GRACE_MS staying the
// same. App sessions never get one.
export function stepUpGraceId(session: string): Promise<string> {
  return sha256Text(`stepup-grace\n${session}`)
}
const FACTOR_NOT_PENDING_REMOVAL = "NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.removed_factors) f WHERE t.account=p.account AND t.state='pending' AND f.value=p.handle)"
// Grace's own eligibility, whatever the action: no pending security
// transition and no cooling-off. The passkey paths that may narrow during
// either are unchanged; a window is neither opened nor used then.
const GRACE_ELIGIBLE = "a.status='active' AND a.suspended_at IS NULL AND a.security_transition IS NULL AND (a.restricted_until IS NULL OR a.restricted_until<=?)"
// Opens or renews a browser session's window in a passkey ceremony's own
// success batch: a step-up's, or a sign-in's for the session it creates. A
// ceremony while restricted or pending opens none. Without securityEpoch (a
// new sign-in) the window takes the account's current epoch.
export async function openStepUpGrace(env: Env, { session, account, factor, provenAt, securityEpoch = null }: { session: string; account: string; factor: string; provenAt: number; securityEpoch?: number | null }): Promise<D1PreparedStatement> {
  return env.DB.prepare(`INSERT INTO challenges(id,kind,challenge,account,workspace,security_epoch,factor,context,expires_at)
    SELECT ?,'stepup-grace',?,a.id,'*',a.security_epoch,?,?,? FROM accounts a WHERE a.id=? AND a.security_epoch=COALESCE(?,a.security_epoch) AND ${GRACE_ELIGIBLE}
    ON CONFLICT(id) DO UPDATE SET challenge=excluded.challenge,account=excluded.account,security_epoch=excluded.security_epoch,factor=excluded.factor,context=excluded.context,expires_at=excluded.expires_at WHERE challenges.kind='stepup-grace'`)
    .bind(await stepUpGraceId(session),String(provenAt),factor,session,provenAt+STEP_UP_GRACE_MS,account,securityEpoch,provenAt)
}
export async function liveStepUpGrace(env: Env, account: AccountWebSession, now = Date.now()): Promise<{ factor: string; until: number; provenAt: number } | null> {
  if (!stepUpGraceOn(env)) return null
  const row = await env.DB.prepare(`SELECT c.factor,c.challenge,c.expires_at FROM challenges c JOIN passkeys p ON p.account=c.account AND p.handle=c.factor JOIN accounts a ON a.id=c.account AND a.security_epoch=c.security_epoch
    WHERE c.id=? AND c.kind='stepup-grace' AND c.account=? AND c.context=? AND c.security_epoch=? AND c.expires_at>? AND ${GRACE_ELIGIBLE} AND ${FACTOR_NOT_PENDING_REMOVAL}`)
    .bind(await stepUpGraceId(account.session),account.account,account.session,account.securityEpoch,now,now).first<{ factor: string; challenge: string; expires_at: number }>()
  return row ? { factor: row.factor,until: row.expires_at,provenAt: Number(row.challenge) } : null
}
export async function endStepUpGrace(env: Env, account: AccountWebSession): Promise<void> {
  await env.DB.prepare("DELETE FROM challenges WHERE id=? AND kind='stepup-grace' AND account=?").bind(await stepUpGraceId(account.session),account.account).run()
}
// `grace`: the session's window covers this action, so no passkey is asked;
// the challenge still commits to the nonce and the exact action.
export type StepUpStart = { nonce: string; options: unknown } | { nonce: string; grace: { until: string } }
// confirmation.provenAt is when the passkey ceremony happened: now, or when
// the window this proof rode was opened.
export type StepUpEvidence = { action: WorkspaceStepUpAction; factor: string; confirmation: StepUpConfirmation; operationCheck?: import("../vault/core.ts").OperationCheck }
// allowGrace false: the app's /app/v1/stepup, whose answer always carries
// passkey options until the app understands `grace`.
export async function startAccountStepUp(env: Env, account: AccountWebSession, scope: string, action: WorkspaceStepUpAction, { allowGrace = true, now = Date.now() }: { allowGrace?: boolean; now?: number } = {}): Promise<StepUpStart> {
  checkScope(scope,action)
  await assertAccountStepUpAllowed(env,account.account,action,now)
  if (scope !== "-" && !workspaceAllowedWhileRestricted(action)) {
    const workspace = await env.DB.prepare("SELECT id,slug FROM workspaces WHERE id=? AND status='active'").bind(scope).first<{ id: string; slug: string }>()
    const kind = await env.DB.prepare("SELECT kind FROM web_sessions WHERE id=? AND account=?").bind(account.session,account.account).first<{ kind: "web" | "app" }>()
    if (workspace && kind) await assertWorkspaceSessionGate(env,account,workspace,kind.kind,now,true)
  }
  const grace = allowGrace && workspaceStepUpGraced(action) ? await liveStepUpGrace(env,account,now) : null
  const nonce = randomToken()
  const challenge = await workspaceStepUpChallenge(nonce,scope,action)
  let options: unknown = null
  if (!grace) {
    const keys = await env.DB.prepare(`SELECT credential_id,transports FROM passkeys p WHERE account=? AND ${FACTOR_NOT_PENDING_REMOVAL}`).bind(account.account).all<{ credential_id: string; transports: string | null }>()
    if (!keys.results.length) throw new VaultError("forbidden", REFUSAL)
    options = await passkeyCeremonies().authenticationOptions({ rpId: env.RP_ID,challenge: Uint8Array.from(atob(challenge.replaceAll("-","+").replaceAll("_","/")),c => c.charCodeAt(0)),allow: keys.results.map(k => ({ id: k.credential_id,transports: JSON.parse(k.transports ?? "[]") as string[] })) })
  }
  await accountBatch(env,[
    accountGuard(env,"EXISTS (SELECT 1 FROM web_sessions s JOIN accounts a ON a.id=s.account WHERE s.id=? AND s.account=? AND a.security_epoch=? AND a.status='active' AND a.suspended_at IS NULL AND s.expires_at>? AND s.last_seen_at>? AND s.kind IN ('web','app') AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.revoked_sessions) r WHERE t.account=a.id AND t.state='pending' AND r.value=s.id) AND (?=1 OR a.security_transition IS NULL) AND (?=1 OR a.restricted_until IS NULL OR a.restricted_until<=?))",[account.session,account.account,account.securityEpoch,now,now-7*86400000,allowedDuringPending(action) ? 1 : 0,workspaceAllowedWhileRestricted(action) ? 1 : 0,now]),
    env.DB.prepare("INSERT INTO challenges(id,kind,challenge,account,workspace,security_epoch,factor,context,expires_at) VALUES (?,'stepup-v2',?,?,?,?,?,?,?)").bind(await sha256Text(nonce),challenge,account.account,scope,account.securityEpoch,grace?.factor ?? null,account.session,now+300000),
  ])
  return grace ? { nonce,grace: { until: new Date(grace.until).toISOString() } } : { nonce,options }
}
// A proof that rides a window runs every check of the passkey path but the
// WebAuthn verification and the counter: its challenge must have been
// started with grace (and a passkey proof's without), and the final guard
// also needs this session's live window with the challenge's factor.
async function verifyScopedAccountStepUp(rc: RequestContext, account: AccountWebSession, scope: string, action: WorkspaceStepUpAction, proof: StepUpProof | undefined,kind: "web" | "app"): Promise<StepUpEvidence> {
  checkScope(scope,action)
  const now = Date.now()
  await assertAccountStepUpAllowed(rc.env,account.account,action,now)
  if (!proof) throw new VaultError("forbidden",REFUSAL)
  if (proof.grace === true && (!stepUpGraceOn(rc.env) || kind !== "web" || !workspaceStepUpGraced(action))) throw new VaultError("forbidden",REFUSAL)
  const current = kind === "web" ? await currentAccountSession(rc.request,rc.env,now) : await (await import("./workspace-app-session.ts")).currentAccountAppSession(rc.request,rc.env,now)
  if (!current || current.account !== account.account || current.session !== account.session) throw new VaultError("forbidden",REFUSAL)
  const stored = await rc.env.DB.prepare("DELETE FROM challenges WHERE id=? AND kind='stepup-v2' RETURNING account,workspace,security_epoch,factor,context,challenge,expires_at").bind(await sha256Text(proof.nonce)).first<{ account: string; workspace: string; security_epoch: number; factor: string | null; context: string; challenge: string; expires_at: number }>()
  const expected = await workspaceStepUpChallenge(proof.nonce,scope,action)
  if (!stored || stored.account !== current.account || stored.workspace !== scope || stored.context !== current.session || stored.security_epoch !== current.securityEpoch || stored.expires_at <= now || !timingSafeEqualText(stored.challenge,expected)) throw new VaultError("forbidden",REFUSAL)
  if ((stored.factor !== null) !== (proof.grace === true)) throw new VaultError("forbidden",REFUSAL)
  let factor: string
  let verified: { counter: number; backedUp: boolean } | null = null
  let window: { until: number; provenAt: number } | null = null
  if (proof.grace === true) {
    const live = await liveStepUpGrace(rc.env,current,now)
    if (!live || live.factor !== stored.factor) throw new VaultError("forbidden",REFUSAL)
    factor = live.factor
    window = { until: live.until,provenAt: live.provenAt }
  } else {
    let id: string
    try { id = credentialId(proof.assertion) } catch { throw new VaultError("forbidden",REFUSAL) }
    const key = await findAccountPasskey(rc.env,id)
    if (!key || key.account !== current.account) throw new VaultError("forbidden",REFUSAL)
    verified = await passkeyCeremonies().verifyAuthentication(proof.assertion as Record<string,unknown>,{ challenge: expected,origin: rc.env.VAULT_ORIGIN,rpId: rc.env.RP_ID },key.record)
    if (verified === null) throw new VaultError("forbidden",REFUSAL)
    factor = key.handle
  }
  await assertAccountStepUpAllowed(rc.env,current.account,action)
  const provenAt = Date.now()
  if (stored.expires_at<=provenAt) throw new VaultError("forbidden",REFUSAL)
  // The window this proof rode, exactly as read, and grace's own eligibility.
  const windowHeld = window ? ` AND EXISTS (SELECT 1 FROM challenges g WHERE g.id=? AND g.kind='stepup-grace' AND g.account=a.id AND g.context=s.id AND g.security_epoch=a.security_epoch AND g.factor=p.handle AND g.expires_at=? AND g.expires_at>?) AND ${GRACE_ELIGIBLE}` : ""
  await accountBatch(rc.env,[
    accountGuard(rc.env,`EXISTS (SELECT 1 FROM web_sessions s JOIN accounts a ON a.id=s.account JOIN passkeys p ON p.account=a.id
      WHERE s.id=? AND a.id=? AND a.security_epoch=? AND a.status='active' AND a.suspended_at IS NULL AND s.expires_at>? AND s.last_seen_at>? AND s.kind=?
      AND p.handle=? AND (?=1 OR a.security_transition IS NULL) AND (?=1 OR a.restricted_until IS NULL OR a.restricted_until<=?) AND ${FACTOR_NOT_PENDING_REMOVAL}
      AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.revoked_sessions) r WHERE t.account=a.id AND t.state='pending' AND r.value=s.id)${windowHeld})`,[current.session,current.account,current.securityEpoch,Date.now(),Date.now()-7*86400000,kind,factor,allowedDuringPending(action) ? 1 : 0,workspaceAllowedWhileRestricted(action) ? 1 : 0,Date.now(),...(window ? [await stepUpGraceId(current.session),window.until,Date.now(),Date.now()] : [])]),
    ...(verified === null ? [] : [
      rc.env.DB.prepare("UPDATE passkeys SET counter=MAX(counter,?),backed_up=?,last_used_at=? WHERE handle=? AND account=?").bind(verified.counter,Number(verified.backedUp),provenAt,factor,current.account),
      refreshAccountRecoverySetup(rc.env,current.account,Date.now()),
      // A ceremony while restricted or pending opens no window.
      ...(stepUpGraceOn(rc.env) && kind === "web" ? [await openStepUpGrace(rc.env,{ session: current.session,account: current.account,factor,provenAt,securityEpoch: current.securityEpoch })] : []),
    ]),
  ])
  const confirmation: StepUpConfirmation = window ? { kind: "grace",provenAt: window.provenAt } : { kind: "passkey",provenAt }
  return { action,factor,confirmation,...(scope !== "-" ? { operationCheck: await operationIdentityCheck(rc.env,current,scope,kind,action) } : {}) }
}
export function requireAccountStepUp(rc: RequestContext, account: AccountWebSession, scope: string, action: WorkspaceStepUpAction, proof: StepUpProof | undefined): Promise<StepUpEvidence> {
  return verifyScopedAccountStepUp(rc,account,scope,action,proof,"web")
}
export function requireAppAccountStepUp(rc: RequestContext, account: AccountWebSession, scope: string, action: WorkspaceStepUpAction, proof: StepUpProof | undefined): Promise<StepUpEvidence> {
  return verifyScopedAccountStepUp(rc,account,scope,action,proof,"app")
}
export function requireWorkspaceStepUp(rc: RequestContext, ws: WorkspaceRequest, expectedAction: WorkspaceStepUpAction, proof: StepUpProof | undefined): Promise<StepUpEvidence> {
  return verifyScopedAccountStepUp(rc,ws.account,ws.workspace.id,expectedAction,proof,ws.sessionKind ?? "web")
}
