import type { Env } from "../env.ts"

// Only source-owned SQL column references enter this expression. Claimed codes
// and factors already pending removal are not available recovery paths. A
// passkey whose authenticator last said it is backed up (synced through a
// password manager) survives losing the device, so one is enough.
export function accountRecoveryReadySql(account: string): string {
  const available = `NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.removed_factors) f WHERE t.account=p.account AND t.state='pending' AND f.value=p.handle)`
  return `(EXISTS (SELECT 1 FROM recovery_codes c WHERE c.account=${account} AND c.status='active' AND c.used_by_session IS NULL)
    OR (SELECT COUNT(*) FROM passkeys p WHERE p.account=${account} AND ${available})>=2
    OR EXISTS (SELECT 1 FROM passkeys p WHERE p.account=${account} AND p.backed_up=1 AND ${available}))`
}
export function refreshAccountRecoverySetup(env: Env,account: string,now: number): D1PreparedStatement {
  return env.DB.prepare(`UPDATE accounts SET recovery_setup_at=CASE WHEN ${accountRecoveryReadySql("accounts.id")} THEN COALESCE(recovery_setup_at,?) ELSE NULL END,
    recovery_setup_kind=CASE WHEN EXISTS (SELECT 1 FROM recovery_codes c WHERE c.account=accounts.id AND c.status='active' AND c.used_by_session IS NULL) THEN 'codes'
    WHEN ${accountRecoveryReadySql("accounts.id")} THEN 'passkey' ELSE NULL END WHERE id=?`).bind(now,account)
}
export async function accountRecoverySetupRequiredNow(env: Env,account: string): Promise<boolean> {
  const row = await env.DB.prepare(`SELECT ${accountRecoveryReadySql("a.id")} AS ready FROM accounts a WHERE a.id=? AND a.status='active'`).bind(account).first<{ ready: number }>()
  return row?.ready !== 1
}
