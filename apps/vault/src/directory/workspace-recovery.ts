import { PENDING_RESTRICTION_UNTIL,timingSafeEqualText, utf8 } from "@mehen/protocol"
import { RECOVERY_CODE_COUNT,generateRecoveryCode,normaliseRecoveryCode,recoveryCodeHashInput } from "@mehen/protocol/recovery-code"
import { PasskeyName,suggestedName } from "./passkey-admin.ts"
import type { RecoveryStatus } from "@mehen/protocol/api"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { refreshAccountRecoverySetup } from "./account-recovery-setup.ts"
import { accountBatch, accountEvent, accountGuard, accountSessionStatements, insertAccountPasskey } from "./account-store.ts"
import { reserveAccountSecurity, retryAccountSecurity,updateAccountRestriction,snapshotAccountRestriction } from "./account-security.ts"
import { mirrorAccountEvents } from "./account-events.ts"
import { refuseSuspendedAccount } from "./account-suspension.ts"
import type { DirectoryWorkspaceClient } from "./workspace-client.ts"
import { accountRegistrationChallenge } from "./workspace-accounts.ts"
import { clientLabel, directoryId, live, newSession, placeOf, randomToken, readCookie, SESSION_COOKIE, sha256Text } from "./session.ts"
import { passkeyCeremonies } from "./webauthn.ts"
import type { AccountWebSession } from "./account-session.ts"

const DEAD = "That recovery ceremony is no longer available. Start again with another code."
export function accountRecoverySetupRequired(env: Env): VaultError {
  return new VaultError("forbidden","Set up account recovery before activation.",{ next: { url: `${env.VAULT_ORIGIN}/account`,say: "Save recovery codes or add a second passkey before activating a membership." } })
}
// An account's first recovery codes, asked for within 15 minutes of the
// sign-up that made it and from that sign-up's own session, need no step-up:
// there are no earlier codes for a stolen session to replace, and the passkey
// registered moments before is the stronger proof. Any later set does. So
// does an account with a synced passkey: /signup never shows it the recovery
// step, so for it the exemption would only serve a stolen cookie.
export const FIRST_CODES_AFTER_SIGNUP_MS = 15*60_000
const FIRST_CODES_AFTER_SIGNUP = "EXISTS (SELECT 1 FROM web_sessions s WHERE s.id=? AND s.account=? AND s.kind='web' AND s.method='signup' AND s.created_at>?) AND NOT EXISTS (SELECT 1 FROM recovery_codes c WHERE c.account=?) AND NOT EXISTS (SELECT 1 FROM passkeys p WHERE p.account=? AND p.backed_up=1)"
function firstCodesAfterSignupValues(account: AccountWebSession,now: number): (string | number)[] {
  return [account.session,account.account,now-FIRST_CODES_AFTER_SIGNUP_MS,account.account,account.account]
}
export async function firstRecoveryCodesAfterSignup(env: Env,account: AccountWebSession,now = Date.now()): Promise<boolean> {
  return (await env.DB.prepare(`SELECT 1 AS first WHERE ${FIRST_CODES_AFTER_SIGNUP}`).bind(...firstCodesAfterSignupValues(account,now)).first()) !== null
}
// `afterSignup`: made without a step-up, so the batch holds only while that
// is still true.
export async function issueAccountRecoveryCodes(env: Env,account: AccountWebSession,now = Date.now(),afterSignup = false): Promise<{ batch: string; codes: string[]; confirmPosition: number; expiresAt: string }> {
  const codes = Array.from({ length: RECOVERY_CODE_COUNT },generateRecoveryCode),hashes = await Promise.all(codes.map(code => { const parsed = normaliseRecoveryCode(code); if (!parsed.ok) throw new Error("Generated invalid recovery code"); return sha256Text(recoveryCodeHashInput(parsed.code)) }))
  const batch = `rcb_${randomToken(18)}`
  let choice: number
  do { choice = crypto.getRandomValues(new Uint8Array(1))[0] as number } while (choice >= 250)
  const confirmPosition = choice%RECOVERY_CODE_COUNT+1
  await accountBatch(env,[
    accountGuard(env,"EXISTS (SELECT 1 FROM accounts a JOIN web_sessions s ON s.account=a.id WHERE a.id=? AND a.status='active' AND a.security_epoch=? AND a.security_transition IS NULL AND (a.restricted_until IS NULL OR a.restricted_until<=?) AND s.id=? AND s.kind='web' AND s.expires_at>?)",[account.account,account.securityEpoch,now,account.session,now]),
    ...(afterSignup ? [accountGuard(env,FIRST_CODES_AFTER_SIGNUP,firstCodesAfterSignupValues(account,now))] : []),
    env.DB.prepare("INSERT INTO recovery_batches(batch,account,confirm_position,expires_at) VALUES (?,?,?,?)").bind(batch,account.account,confirmPosition,now+900000),
    ...hashes.map((hash,i) => env.DB.prepare("INSERT INTO recovery_codes(code_hash,account,batch,position,status,created_at) VALUES (?,?,?,?,'pending',?)").bind(hash,account.account,batch,i+1,now)),
    accountEvent(env,account.account,"account.recovery_generate",{ count: codes.length,stepUp: !afterSignup },now),
  ])
  return { batch,codes,confirmPosition,expiresAt: new Date(now+900000).toISOString() }
}
export async function confirmAccountRecoveryCodes(env: Env,account: AccountWebSession,batch: string,code: string,now = Date.now()): Promise<void> {
  const row = await env.DB.prepare("SELECT c.code_hash FROM recovery_batches b JOIN recovery_codes c ON c.batch=b.batch AND c.position=b.confirm_position WHERE b.batch=? AND b.account=? AND b.expires_at>? AND b.tries<5 AND c.status='pending'").bind(batch,account.account,now).first<{ code_hash: string }>()
  if (!row) throw new VaultError("bad_request","Those codes could not be confirmed. Generate a new set.")
  const normalised = normaliseRecoveryCode(code),hash = normalised.ok ? await sha256Text(recoveryCodeHashInput(normalised.code)) : ""
  if (!timingSafeEqualText(hash,row.code_hash)) {
    await env.DB.prepare("UPDATE recovery_batches SET tries=tries+1 WHERE batch=? AND account=? AND tries<5").bind(batch,account.account).run()
    throw new VaultError("bad_request","That is not the code at the requested position. Check the saved sheet and try again.")
  }
  await accountBatch(env,[
    accountGuard(env,"EXISTS (SELECT 1 FROM accounts a JOIN web_sessions s ON s.account=a.id WHERE a.id=? AND a.status='active' AND a.security_epoch=? AND a.security_transition IS NULL AND s.id=? AND s.kind='web' AND s.expires_at>? AND (a.restricted_until IS NULL OR a.restricted_until<=?))",[account.account,account.securityEpoch,account.session,now,now]),
    accountGuard(env,"EXISTS (SELECT 1 FROM recovery_batches WHERE batch=? AND account=? AND expires_at>? AND tries<5)",[batch,account.account,now]),
    env.DB.prepare("UPDATE recovery_codes SET status='revoked' WHERE account=? AND status='active'").bind(account.account),
    env.DB.prepare("UPDATE recovery_codes SET status='active' WHERE batch=? AND account=? AND status='pending'").bind(batch,account.account),
    env.DB.prepare("DELETE FROM recovery_batches WHERE batch=? AND account=?").bind(batch,account.account),
    refreshAccountRecoverySetup(env,account.account,now),
    accountEvent(env,account.account,"account.recovery_confirm",{ count: RECOVERY_CODE_COUNT },now),
  ])
}
async function recoveryNetworkKey(request: Request): Promise<string> {
  const ip = request.headers.get("cf-connecting-ip") ?? "local"
  let network = ip
  if (ip.includes(":")) {
    try {
      const host = new URL(`http://[${ip}]/`).hostname.slice(1,-1),[left = "",right = ""] = host.split("::")
      const start = left === "" ? [] : left.split(":"),end = right === "" ? [] : right.split(":")
      const groups = host.includes("::") ? [...start,...Array<string>(8-start.length-end.length).fill("0"),...end] : start
      network = `${groups.slice(0,4).map(group => Number.parseInt(group,16).toString(16)).join(":")}::/64`
    } catch { network = "unknown" }
  }
  return `account-recovery:${await sha256Text(network)}`
}
export async function startAccountRecovery(env: Env,request: Request,input: string,client?: DirectoryWorkspaceClient,now = Date.now()): Promise<{ session: Awaited<ReturnType<typeof newSession>>; pending: boolean; transition: string }> {
  const key = await recoveryNetworkKey(request),window = now-now%3600000
  const count = await env.DB.prepare("SELECT count FROM auth_attempts WHERE key=? AND window_start=?").bind(key,window).first<{ count: number }>()
  if ((count?.count ?? 0) >= 5) throw new VaultError("rate_limited","Too many wrong recovery codes from this network. Wait until the next hour and try again.",{ retryAfter: Math.ceil((window+3600000-now)/1000) })
  const normalised = normaliseRecoveryCode(input),hash = normalised.ok ? await sha256Text(recoveryCodeHashInput(normalised.code)) : ""
  const row = await env.DB.prepare("SELECT c.account FROM recovery_codes c JOIN accounts a ON a.id=c.account WHERE code_hash=? AND c.status='active' AND c.used_by_session IS NULL AND a.status='active' AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.effects) e WHERE t.account=a.id AND t.state='pending' AND json_extract(e.value,'$.kind')='recovery.cancel')").bind(hash).first<{ account: string }>()
  if (!row) {
    await env.DB.prepare("INSERT INTO auth_attempts(key,window_start,count) VALUES (?,?,1) ON CONFLICT(key,window_start) DO UPDATE SET count=count+1").bind(key,window).run()
    throw new VaultError("unauthenticated","That code is not valid or was already used.")
  }
  await refuseSuspendedAccount(env,row.account)
  const [sessions,session] = await Promise.all([env.DB.prepare("SELECT id FROM web_sessions WHERE account=?").bind(row.account).all<{ id: string }>(),newSession()])
  const notice = directoryId("ntc"),restriction = { reason: "recovery" as const,until: PENDING_RESTRICTION_UNTIL,notice }
  const transition = await reserveAccountSecurity(env,row.account,{ effect: { kind: "recovery.start",codeHash: hash,notice,ceremony: { tokenHash: session.tokenHash,id: session.id,kind: "recovery",method: "recovery",client: clientLabel(request.headers.get("user-agent")),place: placeOf(request) } },revokedSessionIds: sessions.results.map(s => s.id),removedFactorIds: [],restriction },now)
  try { await mirrorAccountEvents(env,client,now,`${transition}:recovery:${notice}`) } catch { console.error(JSON.stringify({ at: "account.recovery.notice_pending",transition })) }
  try { return { session,pending: await retryAccountSecurity(env,transition,client,now) !== null,transition } }
  catch { console.error(JSON.stringify({ at: "account.recovery.commit_pending",transition })); return { session,pending: true,transition } }
}
export async function accountRecoverySession(env: Env,request: Request,now = Date.now()): Promise<{ account: string; session: string }> {
  const token = readCookie(request,SESSION_COOKIE)
  if (!token) throw new VaultError("unauthenticated",DEAD)
  const row = await env.DB.prepare("SELECT s.account,s.id,s.kind,s.expires_at,s.last_seen_at FROM web_sessions s JOIN accounts a ON a.id=s.account WHERE token_hash=? AND a.status='active' AND a.suspended_at IS NULL AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.revoked_sessions) r WHERE t.account=a.id AND t.state='pending' AND r.value=s.id)").bind(await sha256Text(token)).first<{ account: string; id: string; kind: "recovery" | "web" | "app"; expires_at: number; last_seen_at: number }>()
  if (!row || row.kind !== "recovery" || !live(row,now)) throw new VaultError("unauthenticated",DEAD)
  return { account: row.account,session: row.id }
}
// Where a recovery ceremony stands, from its own cookie: "live" once its
// transition committed and the ceremony session exists; "pending" while the
// recovery that reserved this exact token is still reaching the account's
// workspaces (no session exists yet, so this grants nothing); "ended" for
// anything else, expired, cancelled or unknown. The pending transition is
// returned so the caller can schedule its due retry.
export async function accountRecoveryCeremony(env: Env,request: Request,now = Date.now()): Promise<{ state: "live" | "pending" | "ended"; transition: string | null }> {
  const token = readCookie(request,SESSION_COOKIE)
  if (!token) return { state: "ended",transition: null }
  const ready = await accountRecoverySession(env,request,now).then(() => true,() => false)
  if (ready) return { state: "live",transition: null }
  // The start must belong to its active account's current pending
  // transition and must not have been cancelled: a recovery.cancel for the
  // same notice means its ceremony is never created, so it has ended. Other
  // starts in the same transition are untouched. Nothing here clears the
  // cancellation or creates a session.
  const pending = await env.DB.prepare(`SELECT t.id FROM account_security_transitions t JOIN accounts a ON a.id=t.account AND a.status='active' AND a.security_transition=t.id,json_each(t.effects) e
    WHERE t.state='pending' AND json_extract(e.value,'$.kind')='recovery.start' AND json_extract(e.value,'$.ceremony.tokenHash')=?
    AND NOT EXISTS (SELECT 1 FROM json_each(t.effects) c WHERE json_extract(c.value,'$.kind')='recovery.cancel' AND json_extract(c.value,'$.notice')=json_extract(e.value,'$.notice'))`).bind(await sha256Text(token)).first<{ id: string }>()
  return pending ? { state: "pending",transition: pending.id } : { state: "ended",transition: null }
}
export async function accountPasskeyOptions(env: Env,account: { account: string; session: string },via: "settings" | "recovery",now = Date.now(),factor?: string,kind: "device" | "security-key" = "device"): Promise<{ options: unknown }> {
  const row = await env.DB.prepare("SELECT name,security_epoch FROM accounts WHERE id=? AND status='active'").bind(account.account).first<{ name: string; security_epoch: number }>()
  if (!row) throw new VaultError("unauthenticated",DEAD)
  if (via === "settings" && (!factor || !(await env.DB.prepare("SELECT handle FROM passkeys WHERE account=? AND handle=?").bind(account.account,factor).first()))) throw new VaultError("forbidden","This needs a current account passkey confirmation.")
  const keys = await env.DB.prepare("SELECT credential_id FROM passkeys WHERE account=?").bind(account.account).all<{ credential_id: string }>()
  const options = await passkeyCeremonies().registrationOptions({ rpId: env.RP_ID,userId: utf8(account.account),name: row.name,prefer: kind === "device" ? "localDevice" : "securityKey",exclude: keys.results.map(k => ({ id: k.credential_id,transports: [] })) })
  await accountBatch(env,[
    accountGuard(env,"EXISTS (SELECT 1 FROM accounts a JOIN web_sessions s ON s.account=a.id WHERE a.id=? AND a.security_epoch=? AND a.status='active' AND a.suspended_at IS NULL AND s.id=? AND s.kind=? AND s.expires_at>? AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.revoked_sessions) r WHERE t.account=a.id AND t.state='pending' AND r.value=s.id) AND (?='recovery' OR a.security_transition IS NULL AND (a.restricted_until IS NULL OR a.restricted_until<=?) AND EXISTS (SELECT 1 FROM passkeys p WHERE p.account=a.id AND p.handle=?)))",[account.account,row.security_epoch,account.session,via === "recovery" ? "recovery" : "web",now,via,now,factor ?? null]),
    env.DB.prepare("INSERT INTO challenges(id,kind,challenge,account,context,expires_at,security_epoch,factor) VALUES (?,?,?,?,?,?,?,?)").bind(await sha256Text(options.challenge),`account-register-${via}`,options.challenge,account.account,account.session,now+300000,row.security_epoch,factor ?? null),
  ])
  return { options }
}
export async function accountPasskeyVerify(env: Env,account: { account: string; session: string },response: Record<string,unknown>,via: "settings" | "recovery",now = Date.now(),name?: string): Promise<Awaited<ReturnType<typeof newSession>> | null> {
  const challenge = accountRegistrationChallenge(response)
  const stored = await env.DB.prepare("DELETE FROM challenges WHERE id=? AND kind=? RETURNING account,context,challenge,expires_at,security_epoch,factor").bind(await sha256Text(challenge),`account-register-${via}`).first<{ account: string; context: string; challenge: string; expires_at: number; security_epoch: number; factor: string | null }>()
  if (!stored || stored.account !== account.account || stored.context !== account.session || stored.expires_at <= now) throw new VaultError("unauthenticated",DEAD)
  const passkey = await passkeyCeremonies().verifyRegistration(response,{ challenge: stored.challenge,origin: env.VAULT_ORIGIN,rpId: env.RP_ID })
  if (!passkey) throw new VaultError("bad_request","That passkey could not be verified. Try again.")
  const session = via === "recovery" ? await newSession() : null
  const handle = directoryId("pk"),displayName = name === undefined ? suggestedName(passkey) : PasskeyName.parse(name)
  const finalNow = Math.max(now,Date.now())
  if (stored.expires_at<=finalNow) throw new VaultError("unauthenticated",DEAD)
  await accountBatch(env,[
    accountGuard(env,`EXISTS (SELECT 1 FROM accounts a JOIN web_sessions s ON s.account=a.id WHERE a.id=? AND a.status='active' AND a.suspended_at IS NULL AND a.security_epoch=? AND s.id=? AND s.kind=? AND s.expires_at>?
      AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.revoked_sessions) r WHERE t.account=a.id AND t.state='pending' AND r.value=s.id)
      AND (?='recovery' OR s.last_seen_at>?)
      AND (?='recovery' OR EXISTS (SELECT 1 FROM passkeys p WHERE p.account=a.id AND p.handle=?))
      AND (a.security_transition IS NULL OR (?='recovery' AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.effects) e WHERE t.account=a.id AND t.state='pending' AND json_extract(e.value,'$.kind')='recovery.cancel')))
      AND (?='recovery' OR a.restricted_until IS NULL OR a.restricted_until<=?))`,[account.account,stored.security_epoch,account.session,via === "recovery" ? "recovery" : "web",finalNow,via,finalNow-7*86400000,via,stored.factor,via,via,finalNow]),
    insertAccountPasskey(env,account.account,passkey,finalNow,via,handle),
    env.DB.prepare("UPDATE passkeys SET name=? WHERE handle=? AND account=?").bind(displayName,handle,account.account),
    refreshAccountRecoverySetup(env,account.account,finalNow),
    ...(session ? [env.DB.prepare("DELETE FROM web_sessions WHERE id=? AND account=?").bind(account.session,account.account),...accountSessionStatements(env,session,account.account,finalNow,{ kind: "web",method: "recovery",passkey: passkey.credentialId,client: "A browser",place: null })] : []),
    accountEvent(env,account.account,"account.passkey_add",{ via },finalNow),
  ])
  return session
}
export async function resolveAccountRecovery(env: Env,actor: AccountWebSession,factor: string,notice: string,outcome: "cancel" | "keep",client?: DirectoryWorkspaceClient,now = Date.now()): Promise<{ pending: boolean }> {
  const account = actor.account
  const eligibility = env.DB.prepare("SELECT n.at,n.restricted_until,p.created_at,a.security_epoch FROM account_notices n JOIN passkeys p ON p.account=n.account JOIN accounts a ON a.id=n.account WHERE n.id=? AND n.account=? AND n.kind IN ('recovery','break-glass') AND n.resolved_at IS NULL AND p.handle=? AND NOT EXISTS (SELECT 1 FROM account_notices o WHERE o.account=a.id AND o.kind IN ('recovery','break-glass') AND o.resolved_at IS NULL AND (o.restricted_until IS NULL OR o.restricted_until>?) AND o.at<=p.created_at)").bind(notice,account,factor,now)
  const row = await eligibility.first<{ at: number; restricted_until: number | null; created_at: number; security_epoch: number }>()
  if (!row || row.created_at >= row.at) throw new VaultError("forbidden","Only an older account passkey can resolve recovery.")
  if (outcome === "keep") {
    const event = `evt_${crypto.randomUUID()}`
    try { await accountBatch(env,[
      accountGuard(env,"EXISTS (SELECT 1 FROM accounts a JOIN web_sessions s ON s.account=a.id WHERE a.id=? AND a.security_epoch=? AND s.id=? AND s.kind='web' AND s.expires_at>? AND s.last_seen_at>?)",[account,actor.securityEpoch,actor.session,now,now-7*86400000]),
      accountGuard(env,"EXISTS (SELECT 1 FROM accounts a JOIN passkeys p ON p.account=a.id JOIN account_notices n ON n.account=a.id WHERE a.id=? AND a.security_transition IS NULL AND p.handle=? AND p.created_at<n.at AND n.id=? AND n.resolved_at IS NULL AND NOT EXISTS (SELECT 1 FROM account_notices o WHERE o.account=a.id AND o.kind IN ('recovery','break-glass') AND o.resolved_at IS NULL AND (o.restricted_until IS NULL OR o.restricted_until>?) AND o.at<=p.created_at))",[account,factor,notice,now]),
      env.DB.prepare("UPDATE account_notices SET resolved_at=?,resolved_by=?,outcome='keep' WHERE id=? AND account=?").bind(now,account,notice,account),
      updateAccountRestriction(env,account,now),
      accountEvent(env,account,"account.recovery_keep",{ notice,epoch: row.security_epoch },now,event),
      snapshotAccountRestriction(env,event,account,now),
    ]) } catch (error) {
      if (error instanceof VaultError && error.code === "conflict" && !(await eligibility.first())) throw new VaultError("forbidden","Only an older account passkey can resolve recovery.")
      throw error
    }
    return { pending: false }
  }
  const [sessions,factors] = await Promise.all([
    env.DB.prepare("SELECT id FROM web_sessions WHERE account=? AND created_at>=?").bind(account,row.at).all<{ id: string }>(),
    env.DB.prepare("SELECT handle FROM passkeys WHERE account=? AND created_at>=?").bind(account,row.at).all<{ handle: string }>(),
  ])
  const transition = await reserveAccountSecurity(env,account,{ effect: { kind: "recovery.cancel",notice,factor },revokedSessionIds: sessions.results.map(s => s.id),removedFactorIds: factors.results.map(p => p.handle),session: { id: actor.session,epoch: actor.securityEpoch },authorisingFactor: factor },now)
  return { pending: await retryAccountSecurity(env,transition,client,now) !== null }
}

export async function accountRecoveryStatus(env: Env,account: string): Promise<RecoveryStatus> {
  const row = await env.DB.prepare(`SELECT MIN(created_at) AS generated_at,COUNT(*) AS total,SUM(status='active' AND used_by_session IS NULL) AS remaining FROM recovery_codes WHERE account=? GROUP BY batch
    HAVING SUM(status='revoked')=0 AND SUM(status IN ('active','used'))>0 ORDER BY generated_at DESC LIMIT 1`).bind(account).first<{ generated_at: number; total: number; remaining: number }>()
  return { active: row ? { generatedAt: new Date(row.generated_at).toISOString(),total: row.total,left: row.remaining } : null }
}
