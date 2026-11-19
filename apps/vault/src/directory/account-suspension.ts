// An operator's suspension of an account (accounts.suspended_at, migration
// 0017; set and lifted only by the Accounts view's proposals,
// operator-account-kinds.ts). While it holds, the account cannot sign in by
// passkey or recovery code, redeem a recovery link, step up or use a
// session; it is told so in these words once it has proved who it is.

import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { reserveAccountSecurity, retryAccountSecurity } from "./account-security.ts"
import type { DirectoryWorkspaceClient } from "./workspace-client.ts"

export const ACCOUNT_SUSPENDED = "An operator of this deployment has suspended your account, so you cannot sign in. Ask them to lift the suspension."

export function accountSuspendedError(): VaultError {
  return new VaultError("forbidden", ACCOUNT_SUSPENDED)
}

export async function refuseSuspendedAccount(env: Env, account: string): Promise<void> {
  const row = await env.DB.prepare("SELECT suspended_at FROM accounts WHERE id=?").bind(account).first<{ suspended_at: number | null }>()
  if (row && row.suspended_at !== null) throw accountSuspendedError()
}

// The suspend batch deletes the account's sessions itself. This raises the
// account's security epoch in every workspace (a sessions.end transition),
// so nothing a workspace kept from those sessions outlives them.
export async function endSuspendedAccountSessions(env: Env, account: string, now: number, client?: DirectoryWorkspaceClient): Promise<void> {
  const transition = await reserveAccountSecurity(env, account, { effect: { kind: "sessions.end" }, revokedSessionIds: [], removedFactorIds: [] }, now)
  await retryAccountSecurity(env, transition, client, now)
}

// The cron's: a suspended account with no sessions.end transition reserved
// since its suspension (the one right after the batch failed) gets one. A
// reserved transition is then retried with every other. Each account is
// read again just before, so a suspension lifted since never signs its
// person out of the sessions they started after.
export async function reconcileSuspendedAccounts(env: Env, client?: DirectoryWorkspaceClient, now = Date.now()): Promise<void> {
  const rows = await env.DB.prepare(`SELECT a.id FROM accounts a WHERE a.status='active' AND a.suspended_at IS NOT NULL AND NOT EXISTS
    (SELECT 1 FROM account_security_transitions t,json_each(t.effects) e WHERE t.account=a.id AND t.updated_at>=a.suspended_at AND json_extract(e.value,'$.kind')='sessions.end') ORDER BY a.suspended_at LIMIT 100`).all<{ id: string }>()
  for (const row of rows.results) {
    try {
      if (!(await env.DB.prepare("SELECT 1 FROM accounts WHERE id=? AND status='active' AND suspended_at IS NOT NULL").bind(row.id).first())) continue
      await endSuspendedAccountSessions(env, row.id, now, client)
    } catch {
      console.error(JSON.stringify({ at: "account.suspend.sessions_pending", account: row.id }))
    }
  }
}
