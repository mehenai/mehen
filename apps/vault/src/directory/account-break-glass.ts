import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { accountBatch, accountEvent, accountGuard, accountSessionStatements, insertAccountPasskey } from "./account-store.ts"
import { refreshAccountRecoverySetup } from "./account-recovery-setup.ts"
import { refuseSuspendedAccount } from "./account-suspension.ts"
import { endAccountStepUpGraceWindows, reserveAccountSecurity, retryAccountSecurity, snapshotAccountRestriction, updateAccountRestriction } from "./account-security.ts"
import { accountRegistrationChallenge } from "./workspace-accounts.ts"
import { passkeyCeremonies } from "./webauthn.ts"
import { directoryId, newSession, sha256Text } from "./session.ts"
import type { DirectoryWorkspaceClient } from "./workspace-client.ts"
import { utf8 } from "@mehen/protocol"

export async function reconcileAccountBreakGlass(env: Env, client?: DirectoryWorkspaceClient, now = Date.now()): Promise<void> {
  await env.DB.prepare("UPDATE account_break_glass_intents SET state='expired' WHERE (state='ready' OR state='pending' AND transition_id IS NULL) AND expires_at<=?").bind(now).run()
  const rows = await env.DB.prepare("SELECT id,account,notice,transition_id FROM account_break_glass_intents WHERE state='pending' ORDER BY created_at LIMIT 100").all<{ id: string; account: string; notice: string; transition_id: string | null }>()
  for (const row of rows.results) {
    try {
      const id = row.transition_id ?? await reserveAccountSecurity(env,row.account,{ effect: { kind: "break-glass",intent: row.id,notice: row.notice },revokedSessionIds: [],removedFactorIds: [] },now)
      await retryAccountSecurity(env,id,client,now)
    } catch { console.error(JSON.stringify({ at: "account.break_glass.pending",intent: row.id })) }
  }
}
async function ready(env: Env, code: string, now: number) {
  const row = await env.DB.prepare(`SELECT i.id,i.account,i.notice,a.name,a.security_epoch FROM account_break_glass_intents i JOIN invite_codes c ON c.code_hash=i.code_hash
    JOIN accounts a ON a.id=i.account JOIN account_security_transitions t ON t.id=i.transition_id
    WHERE i.code_hash=? AND i.state='ready' AND i.expires_at>? AND c.kind='break-glass' AND c.state='active' AND c.used_at IS NULL AND c.expires_at>?
    AND EXISTS (SELECT 1 FROM account_notices n WHERE n.id=i.notice AND n.account=i.account AND n.resolved_at IS NULL) AND a.status='active' AND a.security_transition IS NULL AND t.state='committed' AND a.security_epoch=t.reserved_epoch`).bind(await sha256Text(code),now,now).first<{ id: string; account: string; notice: string; name: string; security_epoch: number }>()
  if (!row) throw new VaultError("not_found","No such recovery link.")
  await refuseSuspendedAccount(env,row.account)
  return row
}
export async function accountBreakGlassOptions(env: Env, code: string, now = Date.now()): Promise<{ options: unknown }> {
  const intent = await ready(env,code,now)
  const options = await passkeyCeremonies().registrationOptions({ rpId: env.RP_ID,userId: utf8(intent.account),name: intent.name })
  await accountBatch(env,[
    accountGuard(env,"EXISTS (SELECT 1 FROM accounts WHERE id=? AND status='active' AND security_transition IS NULL AND security_epoch=?)",[intent.account,intent.security_epoch]),
    env.DB.prepare("INSERT INTO challenges(id,kind,challenge,account,context,expires_at,security_epoch) VALUES (?,'account-break-glass',?,?,?,?,?)").bind(await sha256Text(options.challenge),options.challenge,intent.account,intent.id,now+300000,intent.security_epoch),
  ])
  return { options }
}
export async function accountBreakGlassVerify(env: Env, code: string, response: Record<string,unknown>, from: { client: string; place: string | null }, now = Date.now()) {
  const intent = await ready(env,code,now),challenge = accountRegistrationChallenge(response)
  const stored = await env.DB.prepare("DELETE FROM challenges WHERE id=? AND kind='account-break-glass' RETURNING challenge,account,context,expires_at,security_epoch").bind(await sha256Text(challenge)).first<{ challenge: string; account: string; context: string; expires_at: number; security_epoch: number }>()
  if (!stored || stored.account !== intent.account || stored.context !== intent.id || stored.security_epoch !== intent.security_epoch || stored.expires_at<=now) throw new VaultError("unauthenticated","That recovery ceremony is no longer available.")
  const passkey = await passkeyCeremonies().verifyRegistration(response,{ challenge: stored.challenge,origin: env.VAULT_ORIGIN,rpId: env.RP_ID })
  if (!passkey) throw new VaultError("bad_request","That passkey could not be verified. Try again.")
  const finalNow = Math.max(now,Date.now()),session = await newSession()
  const event = `evt_${crypto.randomUUID()}`
  await accountBatch(env,[
    accountGuard(env,"EXISTS (SELECT 1 FROM account_break_glass_intents i JOIN accounts a ON a.id=i.account JOIN invite_codes c ON c.code_hash=i.code_hash WHERE i.id=? AND i.state='ready' AND i.expires_at>? AND c.used_at IS NULL AND c.expires_at>? AND a.status='active' AND a.suspended_at IS NULL AND a.security_transition IS NULL AND a.security_epoch=?) AND ? > ?",[intent.id,finalNow,finalNow,intent.security_epoch,stored.expires_at,finalNow]),
    env.DB.prepare("UPDATE invite_codes SET used_at=?,used_by_account=? WHERE code_hash=?").bind(finalNow,intent.account,await sha256Text(code)),
    env.DB.prepare("UPDATE account_break_glass_intents SET state='redeemed' WHERE id=?").bind(intent.id),
    insertAccountPasskey(env,intent.account,passkey,finalNow,"break-glass",directoryId("pk")),
    refreshAccountRecoverySetup(env,intent.account,finalNow),
    env.DB.prepare("UPDATE account_notices SET restricted_until=?,client=?,place=? WHERE id=? AND account=? AND resolved_at IS NULL").bind(finalNow+86400000,from.client,from.place,intent.notice,intent.account),
    updateAccountRestriction(env,intent.account,finalNow),
    endAccountStepUpGraceWindows(env,intent.account),
    ...accountSessionStatements(env,session,intent.account,finalNow,{ kind: "web",method: "recovery",passkey: passkey.credentialId,...from }),
    // A replacement factor is recovered lineage, never an older-factor escape.
    env.DB.prepare("UPDATE web_sessions SET lineage=json_object('kind','ceremony','notice',?) WHERE id=? AND account=?").bind(intent.notice,session.id,intent.account),
    accountEvent(env,intent.account,"account.security",{ epoch: intent.security_epoch,kinds: ["break-glass.redeem"] },finalNow,event),
    snapshotAccountRestriction(env,event,intent.account,finalNow),
    accountEvent(env,intent.account,"account.break_glass",{ ...from,restrictedUntil: new Date(finalNow+86400000).toISOString() },finalNow),
  ])
  return { account: intent.account,session }
}
