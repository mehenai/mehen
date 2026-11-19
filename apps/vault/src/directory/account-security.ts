import { AccountRestrictionSchema, PENDING_RESTRICTION_UNTIL, type AccountRestriction, type AccountSecurityTransitionView, type PendingAccountSecurity } from "@mehen/protocol"
import { z } from "zod"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { invokeVault } from "../vault/client.ts"
import { oidcIdentityContext } from "./oidc-flow.ts"
import { refreshAccountRecoverySetup } from "./account-recovery-setup.ts"
import { accountBatch, accountEvent, accountGuard } from "./account-store.ts"
import { directoryWorkspaceClient, type DirectoryWorkspaceClient } from "./workspace-client.ts"

const Ids = z.array(z.string().min(1))
const Ceremony = z.strictObject({ tokenHash: z.string(),id: z.string(),kind: z.literal("recovery"),method: z.literal("recovery"),client: z.string(),place: z.string().nullable() })
export const SecurityEffectSchema = z.discriminatedUnion("kind",[
  z.strictObject({ kind: z.literal("break-glass"),intent: z.string(),notice: z.string() }),
  z.strictObject({ kind: z.literal("factor.remove") }),
  z.strictObject({ kind: z.literal("sessions.end") }),
  z.strictObject({ kind: z.literal("identity.unlink"),identity: z.string(),session: z.string(),invalidation: z.string().min(1) }),
  z.strictObject({ kind: z.literal("recovery.start"),notice: z.string(),codeHash: z.string(),ceremony: Ceremony }),
  z.strictObject({ kind: z.literal("recovery.cancel"),notice: z.string(),factor: z.string() }),
])
export type SecurityEffect = z.infer<typeof SecurityEffectSchema>
const Effects = z.array(SecurityEffectSchema)
const Targets = z.array(z.strictObject({ workspace: z.string(),membership: z.string(),state: z.enum(["joining","member"]) }))
const Acknowledged = z.array(z.strictObject({ workspace: z.string(),reservedEpoch: z.number().int(),at: z.number().int() }))
type TransitionRow = { id: string; account: string; reserved_epoch: number; kind: string; target_restrictions: string; effects: string; commit_restriction: string | null; revoked_sessions: string; removed_factors: string; targets: string; acknowledged: string; state: "pending" | "committed"; created_at: number; updated_at: number; committed_at: number | null; commit_delivery: string; attempts: number; next_retry_at: number | null }
type Transition = { row: TransitionRow; restriction: AccountRestriction | null; commitRestriction: AccountRestriction | null; effects: SecurityEffect[]; sessions: string[]; factors: string[]; targets: z.infer<typeof Targets>; acknowledged: z.infer<typeof Acknowledged> }
function decode(row: TransitionRow): Transition {
  return { row,restriction: AccountRestrictionSchema.nullable().parse(JSON.parse(row.target_restrictions)),commitRestriction: AccountRestrictionSchema.nullable().parse(row.commit_restriction === null ? null : JSON.parse(row.commit_restriction)),effects: Effects.parse(JSON.parse(row.effects)),sessions: Ids.parse(JSON.parse(row.revoked_sessions)),factors: Ids.parse(JSON.parse(row.removed_factors)),targets: Targets.parse(JSON.parse(row.targets)),acknowledged: Acknowledged.parse(JSON.parse(row.acknowledged)) }
}
async function load(env: Env, id: string): Promise<Transition | null> {
  const row = await env.DB.prepare("SELECT * FROM account_security_transitions WHERE id=?").bind(id).first<TransitionRow>()
  return row ? decode(row) : null
}
const union = (a: string[],b: string[]) => [...new Set([...a,...b])].sort()
function strictest(a: AccountRestriction | null,b: AccountRestriction | null): AccountRestriction | null { return a === null ? b : b === null || a.until > b.until ? a : b }
const governingRestrictionSql = `SELECT json_object('reason',kind,'notice',id,'until',COALESCE(restricted_until,${PENDING_RESTRICTION_UNTIL})) AS value FROM account_notices
  WHERE account=? AND kind IN ('recovery','break-glass') AND resolved_at IS NULL AND (restricted_until IS NULL OR restricted_until>?)
  ORDER BY COALESCE(restricted_until,${PENDING_RESTRICTION_UNTIL}) DESC,at DESC,id DESC LIMIT 1`
// Derive loosening and its event snapshot inside the same transaction as notice
// resolution, so an overlapping notice cannot be lost between read and commit.
export function updateAccountRestriction(env: Env,account: string,now: number): D1PreparedStatement {
  return env.DB.prepare(`WITH restriction AS (${governingRestrictionSql}) UPDATE accounts SET restricted_until=(SELECT json_extract(value,'$.until') FROM restriction),restricted_reason=(SELECT json_extract(value,'$.reason') FROM restriction) WHERE id=?`).bind(account,now,account)
}
// Every passkey grace window of the account (workspace-stepup.ts), deleted in
// the batch that starts a security transition or a cooling-off, so none
// revives when the restriction clears without an epoch change.
export function endAccountStepUpGraceWindows(env: Env,account: string): D1PreparedStatement {
  return env.DB.prepare("DELETE FROM challenges WHERE account=? AND kind='stepup-grace'").bind(account)
}
export function snapshotAccountRestriction(env: Env,event: string,account: string,now: number): D1PreparedStatement {
  return env.DB.prepare(`WITH restriction AS (${governingRestrictionSql}) UPDATE account_events SET detail=json_set(detail,'$.restriction',json((SELECT value FROM restriction))) WHERE id=?`).bind(account,now,event)
}
function pending(t: Transition): PendingAccountSecurity { return { transitionId: t.row.id,reservedEpoch: t.row.reserved_epoch,revokedSessionIds: t.sessions,removedFactorIds: t.factors,restriction: t.restriction } }
function view(t: Transition): AccountSecurityTransitionView { return { id: t.row.id,reservedEpoch: t.row.reserved_epoch,targets: new Set(t.targets.map(x => x.workspace)).size,acknowledged: new Set(t.acknowledged.filter(a => a.reservedEpoch === t.row.reserved_epoch).map(a => a.workspace)).size,state: "pending" } }
export async function accountSecurityStatus(env: Env, account: string): Promise<AccountSecurityTransitionView | null> {
  const row = await env.DB.prepare("SELECT t.* FROM account_security_transitions t JOIN accounts a ON a.security_transition=t.id WHERE a.id=? AND t.state='pending'").bind(account).first<TransitionRow>()
  return row ? view(decode(row)) : null
}
// Reservation and target enumeration share a conditional D1 transaction with
// joins/creation. The reserved epoch never changes the account's committed one.
export async function reserveAccountSecurity(env: Env, account: string, input: { effect: SecurityEffect; revokedSessionIds: string[]; removedFactorIds: string[]; restriction?: AccountRestriction | null; session?: { id: string; epoch: number }; authorisingFactor?: string }, now = Date.now()): Promise<string> {
  const effect = SecurityEffectSchema.parse(input.effect)
  const sessions = Ids.parse(input.revokedSessionIds)
  const factors = Ids.parse(input.removedFactorIds)
  const requested = effect.kind === "break-glass" ? { reason: "break-glass" as const,until: PENDING_RESTRICTION_UNTIL,notice: effect.notice } : effect.kind === "recovery.start" ? { reason: "recovery" as const,until: PENDING_RESTRICTION_UNTIL,notice: effect.notice } : AccountRestrictionSchema.nullable().parse(input.restriction ?? null)
  for (let attempt = 0; attempt < 5; attempt++) {
    const a = await env.DB.prepare("SELECT security_epoch,security_transition,status,restricted_until,restricted_reason FROM accounts WHERE id=?").bind(account).first<{ security_epoch: number; security_transition: string | null; status: string; restricted_until: number | null; restricted_reason: string | null }>()
    if (!a || a.status !== "active") throw new VaultError("unauthenticated","Sign in with your passkey to continue.")
    const old = a.security_transition ? await load(env,a.security_transition) : null
    if (a.security_transition && (!old || old.row.state !== "pending")) throw new VaultError("account_pending","Account security changes are still pending.")
    const id = old?.row.id ?? `trn_${crypto.randomUUID()}`
    const epoch = Math.max(a.security_epoch,old?.row.reserved_epoch ?? 0)+1
    const currentNotice = await env.DB.prepare("SELECT id FROM account_notices WHERE account=? AND resolved_at IS NULL AND restricted_until=? ORDER BY at DESC LIMIT 1").bind(account,a.restricted_until).first<{ id: string }>()
    const currentRestriction = a.restricted_until !== null && a.restricted_reason !== null ? AccountRestrictionSchema.parse({ reason: a.restricted_reason,until: a.restricted_until,notice: currentNotice?.id ?? "pending" }) : null
    const restriction = strictest(strictest(old?.restriction ?? null,currentRestriction),requested)
    const commitRestriction = strictest(old ? old.commitRestriction : currentRestriction,requested)
    const effects = old ? [...old.effects] : []
    if (!effects.some(e => JSON.stringify(e) === JSON.stringify(effect))) effects.push(effect)
    const statements = [accountGuard(env,"EXISTS (SELECT 1 FROM accounts WHERE id=? AND status='active' AND security_epoch=? AND security_transition IS ?)",[account,a.security_epoch,a.security_transition])]
    if (old) statements.push(accountGuard(env,"EXISTS (SELECT 1 FROM account_security_transitions WHERE id=? AND reserved_epoch=? AND state='pending')",[id,old.row.reserved_epoch]))
    if (input.session) statements.push(accountGuard(env,"EXISTS (SELECT 1 FROM accounts a JOIN web_sessions s ON s.account=a.id WHERE a.id=? AND a.security_epoch=? AND s.id=? AND s.kind='web' AND s.expires_at>? AND s.last_seen_at>? AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.revoked_sessions) r WHERE t.account=a.id AND t.state='pending' AND r.value=s.id))",[account,input.session.epoch,input.session.id,now,now-7*86400000]))
    if (input.authorisingFactor) statements.push(accountGuard(env,"EXISTS (SELECT 1 FROM passkeys p WHERE p.account=? AND p.handle=? AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.removed_factors) f WHERE t.account=p.account AND t.state='pending' AND f.value=p.handle))",[account,input.authorisingFactor]))
    if (effect.kind === "factor.remove" && input.session) statements.push(accountGuard(env,"EXISTS (SELECT 1 FROM passkeys WHERE account=? AND handle NOT IN (SELECT value FROM json_each(?)))",[account,JSON.stringify(union(old?.factors ?? [],factors))]))
    if (effect.kind === "recovery.cancel") {
      const eligible = await env.DB.prepare("SELECT p.handle FROM passkeys p JOIN accounts a ON a.id=p.account JOIN account_notices n ON n.account=a.id WHERE n.id=? AND a.id=? AND p.handle=? AND n.resolved_at IS NULL AND p.created_at<n.at AND NOT EXISTS (SELECT 1 FROM account_notices o WHERE o.account=a.id AND o.kind IN ('recovery','break-glass') AND o.resolved_at IS NULL AND (o.restricted_until IS NULL OR o.restricted_until>?) AND o.at<=p.created_at)").bind(effect.notice,account,effect.factor,now).first()
      if (!eligible) throw new VaultError("forbidden","Only an older account passkey can resolve recovery.")
      statements.push(accountGuard(env,"EXISTS (SELECT 1 FROM account_notices n JOIN passkeys p ON p.account=n.account JOIN accounts a ON a.id=n.account WHERE n.id=? AND n.account=? AND n.resolved_at IS NULL AND p.handle=? AND p.created_at<n.at AND NOT EXISTS (SELECT 1 FROM account_notices o WHERE o.account=a.id AND o.kind IN ('recovery','break-glass') AND o.resolved_at IS NULL AND (o.restricted_until IS NULL OR o.restricted_until>?) AND o.at<=p.created_at) AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.removed_factors) f WHERE t.account=n.account AND t.state='pending' AND f.value=p.handle))",[effect.notice,account,effect.factor,now]))
    }

    if (effect.kind === "break-glass") statements.push(
      accountGuard(env,"EXISTS (SELECT 1 FROM account_break_glass_intents WHERE id=? AND account=? AND notice=? AND state='pending' AND expires_at>? AND EXISTS (SELECT 1 FROM account_notices n WHERE n.id=notice AND n.account=account_break_glass_intents.account AND n.resolved_at IS NULL))",[effect.intent,account,effect.notice,now]),
      env.DB.prepare("UPDATE account_break_glass_intents SET transition_id=? WHERE id=? AND account=?").bind(id,effect.intent,account),
    )
    if (effect.kind === "identity.unlink") statements.push(accountGuard(env,"EXISTS (SELECT 1 FROM oidc_identities WHERE id=? AND account=?)",[effect.identity,account]))
    if (effect.kind === "recovery.start") statements.push(
      accountGuard(env,"EXISTS (SELECT 1 FROM recovery_codes WHERE code_hash=? AND account=? AND status='active' AND used_by_session IS NULL) AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.effects) e WHERE t.account=? AND t.state='pending' AND json_extract(e.value,'$.kind')='recovery.cancel')",[effect.codeHash,account,account]),
      env.DB.prepare("UPDATE recovery_codes SET used_by_session=? WHERE code_hash=?").bind(effect.ceremony.id,effect.codeHash),
    )
    // Keep every unresolved prior target, even if its routing row became left.
    const targetSql = `(SELECT COALESCE(json_group_array(json_object('workspace',workspace,'membership',id,'state',state)),'[]') FROM
      (SELECT workspace,id,state FROM memberships WHERE account=? AND state IN ('joining','member')
       UNION SELECT json_extract(value,'$.workspace'),json_extract(value,'$.membership'),json_extract(value,'$.state') FROM json_each(?)))`
    if (old) statements.push(env.DB.prepare(`UPDATE account_security_transitions SET reserved_epoch=?,kind=?,target_restrictions=?,commit_restriction=?,effects=?,revoked_sessions=?,removed_factors=?,targets=${targetSql},acknowledged='[]',updated_at=?,next_retry_at=? WHERE id=?`)
      .bind(epoch,effect.kind,JSON.stringify(restriction),commitRestriction ? JSON.stringify(commitRestriction) : null,JSON.stringify(effects),JSON.stringify(union(old.sessions,sessions)),JSON.stringify(union(old.factors,factors)),account,JSON.stringify(old.targets),now,now,id))
    else statements.push(env.DB.prepare(`INSERT INTO account_security_transitions(id,account,reserved_epoch,kind,target_restrictions,commit_restriction,effects,revoked_sessions,removed_factors,targets,acknowledged,state,created_at,updated_at,next_retry_at)
      VALUES (?,?,?,?,?,?,?,?,?,${targetSql},'[]','pending',?,?,?)`)
      .bind(id,account,epoch,effect.kind,JSON.stringify(restriction),commitRestriction ? JSON.stringify(commitRestriction) : null,JSON.stringify(effects),JSON.stringify(sessions),JSON.stringify(factors),account,"[]",now,now,now))
    if (effect.kind === "break-glass" || effect.kind === "recovery.start" || effect.kind === "sessions.end" || effect.kind === "recovery.cancel" || effect.kind === "factor.remove") {
      const sessionPredicate = effect.kind === "break-glass" || effect.kind === "recovery.start" || effect.kind === "sessions.end" ? "1" : effect.kind === "recovery.cancel" ? "s.created_at >= (SELECT at FROM account_notices WHERE id=?) OR json_extract(s.lineage,'$.kind') IN ('ceremony','code')" : "s.passkey IN (SELECT credential_id FROM passkeys WHERE handle IN (SELECT value FROM json_each((SELECT removed_factors FROM account_security_transitions WHERE id=?))))"
      const values = effect.kind === "break-glass" || effect.kind === "recovery.start" || effect.kind === "sessions.end" ? [] : [effect.kind === "recovery.cancel" ? effect.notice : id]
      statements.push(env.DB.prepare(`UPDATE account_security_transitions SET revoked_sessions=(SELECT COALESCE(json_group_array(value),'[]') FROM
        (SELECT value FROM json_each(revoked_sessions) UNION SELECT s.id AS value FROM web_sessions s WHERE s.account=? AND (${sessionPredicate}))) WHERE id=?`).bind(account,...values,id))
    }
    if (effect.kind === "recovery.cancel") statements.push(env.DB.prepare(`UPDATE account_security_transitions SET removed_factors=(SELECT COALESCE(json_group_array(value),'[]') FROM
      (SELECT value FROM json_each(removed_factors) UNION SELECT handle AS value FROM passkeys WHERE account=? AND created_at >= (SELECT at FROM account_notices WHERE id=?))) WHERE id=?`).bind(account,effect.notice,id))
    if (effect.kind === "break-glass") statements.push(env.DB.prepare(`UPDATE account_security_transitions SET removed_factors=(SELECT COALESCE(json_group_array(value),'[]') FROM
      (SELECT value FROM json_each(removed_factors) UNION SELECT handle AS value FROM passkeys WHERE account=?)) WHERE id=?`).bind(account,id))
    statements.push(env.DB.prepare("UPDATE accounts SET security_transition=? WHERE id=?").bind(id,account),refreshAccountRecoverySetup(env,account,now),endAccountStepUpGraceWindows(env,account))
    if (effect.kind === "break-glass") statements.push(accountEvent(env,account,"account.break_glass",{ client: "Independent operator",place: null,restrictedUntil: null },now,`${id}:break_glass:${effect.notice}`))
    if (effect.kind === "recovery.start") statements.push(
      env.DB.prepare("INSERT INTO account_notices(id,account,kind,payload,at,client,place,restricted_until) VALUES (?,?,'recovery',?,?,?,?,NULL)").bind(effect.notice,account,JSON.stringify({ pendingTransition: id }),now,effect.ceremony.client,effect.ceremony.place),
      accountEvent(env,account,"account.recovery",{ client: effect.ceremony.client,place: effect.ceremony.place,restrictedUntil: null },now,`${id}:recovery:${effect.notice}`),
    )
    try { await accountBatch(env,statements); return id } catch (error) { if (!(error instanceof VaultError) || error.code !== "conflict" || attempt === 4) throw error }
  }
  throw new VaultError("conflict","Account state changed. Try again.")
}
function commitStatements(env: Env,t: Transition,now: number): D1PreparedStatement[] {
  const { row } = t
  const cancelled = new Set(t.effects.flatMap(effect => effect.kind === "recovery.cancel" ? [effect.notice] : []))
  // Break-glass ends every session, factor and code, so a recovery started
  // in the same transition, before or after it, opens no ceremony.
  const breakGlass = t.effects.some(effect => effect.kind === "break-glass")
  const statements = [
    accountGuard(env,`EXISTS (SELECT 1 FROM accounts a JOIN account_security_transitions t ON t.id=a.security_transition
      WHERE a.id=? AND t.id=? AND t.state='pending' AND t.reserved_epoch=? AND NOT EXISTS
      (SELECT 1 FROM json_each(t.targets) target WHERE NOT EXISTS (SELECT 1 FROM json_each(t.acknowledged) ack WHERE json_extract(ack.value,'$.workspace')=json_extract(target.value,'$.workspace') AND json_extract(ack.value,'$.reservedEpoch')=t.reserved_epoch)))`,[row.account,row.id,row.reserved_epoch]),
    env.DB.prepare("DELETE FROM web_sessions WHERE account=? AND id IN (SELECT value FROM json_each(?))").bind(row.account,JSON.stringify(t.sessions)),
    env.DB.prepare("DELETE FROM passkeys WHERE account=? AND handle IN (SELECT value FROM json_each(?))").bind(row.account,JSON.stringify(t.factors)),
  ]
  for (const effect of t.effects) {
    if (effect.kind === "break-glass") statements.push(
      // Only another independently authorised, committed barrier supersedes
      // an abandoned link. Timeout alone never lifts an account restriction.
      env.DB.prepare(`UPDATE account_notices SET resolved_at=?,resolved_by='operator',outcome='removed' WHERE account=? AND resolved_at IS NULL AND id IN
        (SELECT notice FROM account_break_glass_intents WHERE account=? AND state='expired' AND id!=?)`).bind(now,row.account,row.account,effect.intent),
      env.DB.prepare("UPDATE recovery_codes SET status='revoked' WHERE account=?").bind(row.account),
      env.DB.prepare("DELETE FROM recovery_batches WHERE account=?").bind(row.account),
      env.DB.prepare("DELETE FROM challenges WHERE account=?").bind(row.account),
      env.DB.prepare("DELETE FROM invite_codes WHERE account=? AND kind='break-glass'").bind(row.account),
      env.DB.prepare(`INSERT INTO invite_codes(code_hash,kind,account,expires_at)
        SELECT code_hash,'break-glass',account,expires_at FROM account_break_glass_intents WHERE id=? AND account=? AND state='pending' AND expires_at>? AND ?=0`).bind(effect.intent,row.account,now,cancelled.has(effect.notice) ? 1 : 0),
      env.DB.prepare("UPDATE account_break_glass_intents SET state=CASE WHEN expires_at>? AND ?=0 THEN 'ready' ELSE 'expired' END WHERE id=? AND account=? AND state='pending'").bind(now,cancelled.has(effect.notice) ? 1 : 0,effect.intent,row.account),
    )
    if (effect.kind === "identity.unlink") statements.push(
      env.DB.prepare("DELETE FROM session_identity_checks WHERE identity=? AND account=?").bind(effect.identity,row.account),
      env.DB.prepare("DELETE FROM operation_identity_checks WHERE identity=? AND account=?").bind(effect.identity,row.account),
      env.DB.prepare("DELETE FROM oidc_identities WHERE id=? AND account=?").bind(effect.identity,row.account),
      accountEvent(env,row.account,"account.identity_unlink",{ provider: "google" },now,`${row.id}:unlink:${effect.identity}`),
    )
    if (effect.kind === "recovery.start" && !cancelled.has(effect.notice) && breakGlass) statements.push(
      env.DB.prepare("UPDATE account_notices SET resolved_at=?,resolved_by='operator',outcome='removed' WHERE id=? AND account=? AND resolved_at IS NULL").bind(now,effect.notice,row.account),
    )
    if (effect.kind === "recovery.start" && !cancelled.has(effect.notice) && !breakGlass) statements.push(
      accountGuard(env,"EXISTS (SELECT 1 FROM recovery_codes WHERE code_hash=? AND account=? AND status='active' AND used_by_session=?)",[effect.codeHash,row.account,effect.ceremony.id]),
      env.DB.prepare("UPDATE recovery_codes SET status='used',used_at=? WHERE code_hash=?").bind(now,effect.codeHash),
      env.DB.prepare("UPDATE account_notices SET restricted_until=?,payload='{}' WHERE id=? AND account=? AND resolved_at IS NULL").bind(now+86400000,effect.notice,row.account),
      env.DB.prepare("INSERT INTO web_sessions(token_hash,id,account,created_at,expires_at,last_seen_at,kind,method,client,place,lineage) VALUES (?,?,?,?,?,?,'recovery','recovery',?,?,?)").bind(effect.ceremony.tokenHash,effect.ceremony.id,row.account,now,now+900000,now,effect.ceremony.client,effect.ceremony.place,JSON.stringify({ kind: "ceremony",notice: effect.notice })),
    )
    if (effect.kind === "recovery.cancel") statements.push(
      env.DB.prepare("UPDATE recovery_codes SET status='revoked' WHERE account=?").bind(row.account),
      env.DB.prepare("UPDATE account_notices SET resolved_at=?,resolved_by=?,outcome='cancel' WHERE id=? AND account=? AND resolved_at IS NULL").bind(now,row.account,effect.notice,row.account),
    )
  }
  statements.push(
    refreshAccountRecoverySetup(env,row.account,now),
    updateAccountRestriction(env,row.account,now),
    endAccountStepUpGraceWindows(env,row.account),
    env.DB.prepare("UPDATE accounts SET security_epoch=?,security_transition=NULL WHERE id=?").bind(row.reserved_epoch,row.account),
    accountEvent(env,row.account,"account.security",{ transition: row.id,epoch: row.reserved_epoch,kinds: t.effects.map(e => e.kind) },now,`${row.id}:${row.reserved_epoch}`),
    snapshotAccountRestriction(env,`${row.id}:${row.reserved_epoch}`,row.account,now),
    env.DB.prepare("UPDATE account_security_transitions SET state='committed',committed_at=?,updated_at=?,next_retry_at=?,commit_restriction=(SELECT json_extract(detail,'$.restriction') FROM account_events WHERE id=?) WHERE id=?").bind(now,now,now,`${row.id}:${row.reserved_epoch}`,row.id),
  )
  return statements
}
async function retryAccountSecurityAttempt(env: Env,id: string,client: DirectoryWorkspaceClient,now: number,onlyWhenDue: boolean): Promise<AccountSecurityTransitionView | null> {
  let t = await load(env,id)
  if (!t) return null
  const claimed = await env.DB.prepare("UPDATE account_security_transitions SET attempts=attempts+1,last_retry_at=?,next_retry_at=? WHERE id=? AND reserved_epoch=? AND (?=0 OR next_retry_at IS NULL OR next_retry_at<=?)").bind(now,now+60000,id,t.row.reserved_epoch,onlyWhenDue ? 1 : 0,now).run()
  if (claimed.meta.changes !== 1) return t.row.state === "pending" ? view(t) : null
  if (t.row.state === "pending") {
    const a = await env.DB.prepare("SELECT security_epoch FROM accounts WHERE id=?").bind(t.row.account).first<{ security_epoch: number }>()
    if (!a) return view(t)
    for (const workspace of new Set(t.targets.map(x => x.workspace))) {
      if (t.acknowledged.some(x => x.workspace === workspace && x.reservedEpoch === t?.row.reserved_epoch)) continue
      try {
        await client.install(workspace,{ account: t.row.account,committedEpoch: a.security_epoch,pending: pending(t) })
        for (const effect of t.effects) if (effect.kind === "identity.unlink") {
          try {
            const context = await oidcIdentityContext(env,workspace,t.row.account)
            if (context.status === "active" || context.status === "unconfirmed") await invokeVault(env,workspace,{ op: "access.identity.install",input: { account: t.row.account,member: context.member,session: effect.session,securityEpoch: a.security_epoch,sessionCheck: null,invalidation: effect.invalidation },auth: { kind: "system",reason: "identity unlink security transition" } })
          } catch (error) { if (!(error instanceof VaultError) || error.code !== "not_found") throw error }
        }
        await env.DB.prepare(`UPDATE account_security_transitions SET acknowledged=json_insert(acknowledged,'$[#]',json(?)) WHERE id=? AND state='pending' AND reserved_epoch=?
          AND NOT EXISTS (SELECT 1 FROM json_each(acknowledged) WHERE json_extract(value,'$.workspace')=? AND json_extract(value,'$.reservedEpoch')=?)`)
          .bind(JSON.stringify({ workspace,reservedEpoch: t.row.reserved_epoch,at: now }),id,t.row.reserved_epoch,workspace,t.row.reserved_epoch).run()
      } catch { console.error(JSON.stringify({ at: "account.security.pending",transition: id,workspace,reservedEpoch: t.row.reserved_epoch,age: now-t.row.created_at })) }
    }
    const current = await load(env,id)
    if (!current) return null
    if (current.row.reserved_epoch !== t.row.reserved_epoch) return view(current)
    t = current
    if (view(t).acknowledged !== view(t).targets) return view(t)
    try { await accountBatch(env,commitStatements(env,t,now)) } catch (error) {
      console.error(JSON.stringify({ at: "account.security.commit_pending",transition: id }))
      if (!(error instanceof VaultError) || error.code !== "conflict") throw error
      const latest = await load(env,id)
      return latest?.row.state === "pending" ? view(latest) : null
    }
    t = await load(env,id)
    if (!t) return null
  }
  const delivered = Ids.parse(JSON.parse(t.row.commit_delivery))
  for (const workspace of new Set(t.targets.map(x => x.workspace))) {
    if (delivered.includes(workspace)) continue
    try {
      await client.commit(workspace,{ account: t.row.account,committedEpoch: t.row.reserved_epoch })
      await env.DB.prepare(`UPDATE account_security_transitions SET commit_delivery=json_insert(commit_delivery,'$[#]',?) WHERE id=? AND NOT EXISTS (SELECT 1 FROM json_each(commit_delivery) WHERE value=?)`).bind(workspace,id,workspace).run()
    } catch { console.error(JSON.stringify({ at: "account.security.commit_delivery",transition: id,workspace,epoch: t.row.reserved_epoch })) }
  }
  return null
}
export function retryAccountSecurity(env: Env,id: string,client: DirectoryWorkspaceClient = directoryWorkspaceClient(env),now = Date.now()): Promise<AccountSecurityTransitionView | null> {
  return retryAccountSecurityAttempt(env,id,client,now,false)
}
export function retryAccountSecurityIfDue(env: Env,id: string,client: DirectoryWorkspaceClient = directoryWorkspaceClient(env),now = Date.now()): Promise<AccountSecurityTransitionView | null> {
  return retryAccountSecurityAttempt(env,id,client,now,true)
}
// A commit's or event's delivery records no time, only its own committed_at
// or at: one made this long before the restore point is taken as delivered by
// then. Both queues retry a failed delivery a minute later, on a cron that
// runs every 15 minutes: a day is many times that, covers a workspace
// unreachable for up to a day, and keeps a replay to a day's deliveries.
export const REDELIVERY_MARGIN_MS = 86_400_000
// A restored workspace object holds its accounts' security as it was at the
// restore point, while the directory still records it as delivered there.
// Forgetting the deliveries the restore lost (every pending transition, and
// commits and events from the margin before the point on) makes the due
// retries install those transitions, cooling-off and ended sessions in that
// object again.
export function redeliverAccountSecurity(env: Env,workspace: string,restorePoint: number): D1PreparedStatement[] {
  const since = restorePoint-REDELIVERY_MARGIN_MS
  return [
    env.DB.prepare(`UPDATE account_security_transitions SET next_retry_at=NULL,
      acknowledged=(SELECT COALESCE(json_group_array(json(value)),'[]') FROM json_each(acknowledged) WHERE json_extract(value,'$.workspace')!=?1),
      commit_delivery=(SELECT COALESCE(json_group_array(value),'[]') FROM json_each(commit_delivery) WHERE value!=?1)
      WHERE (state='pending' OR committed_at>=?2) AND EXISTS (SELECT 1 FROM json_each(targets) WHERE json_extract(value,'$.workspace')=?1)`).bind(workspace,since),
    env.DB.prepare(`UPDATE account_events SET next_retry_at=NULL,mirrored_to=(SELECT COALESCE(json_group_array(value),'[]') FROM json_each(mirrored_to) WHERE value!=?1)
      WHERE action IN ('account.signout','account.security','account.recovery_keep') AND at>=?2 AND EXISTS (SELECT 1 FROM json_each(targets) WHERE value=?1)`).bind(workspace,since),
  ]
}
export async function retryDueAccountSecurity(env: Env,client: DirectoryWorkspaceClient = directoryWorkspaceClient(env),now = Date.now()): Promise<void> {
  const rows = await env.DB.prepare(`SELECT id FROM account_security_transitions WHERE (next_retry_at IS NULL OR next_retry_at<=?) AND
    (state='pending' OR EXISTS (SELECT 1 FROM json_each(targets) target WHERE NOT EXISTS (SELECT 1 FROM json_each(commit_delivery) done WHERE done.value=json_extract(target.value,'$.workspace')))) ORDER BY created_at LIMIT 100`).bind(now).all<{ id: string }>()
  for (const row of rows.results) { try { await retryAccountSecurityIfDue(env,row.id,client,now) } catch { console.error(JSON.stringify({ at: "account.security.retry",transition: row.id })) } }
}
