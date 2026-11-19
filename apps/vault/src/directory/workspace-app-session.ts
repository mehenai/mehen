import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import type { AccountWebSession } from "./account-session.ts"
import { live,sha256Text } from "./session.ts"
export async function currentAccountAppSession(request: Request,env: Env,now = Date.now()): Promise<AccountWebSession | null> {
  const token = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(request.headers.get("authorization") ?? "")?.[1]
  if (!token) return null
  const row = await env.DB.prepare(`SELECT s.id,s.account,s.expires_at,s.last_seen_at,s.kind,a.name,a.security_epoch,a.security_transition,a.restricted_until FROM web_sessions s JOIN accounts a ON a.id=s.account
    WHERE s.token_hash=? AND s.kind='app' AND a.status='active' AND a.suspended_at IS NULL AND EXISTS (SELECT 1 FROM passkeys p WHERE p.account=a.id AND p.credential_id=s.passkey)
    AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.revoked_sessions) r WHERE t.account=a.id AND t.state='pending' AND r.value=s.id)`)
    .bind(await sha256Text(token)).first<{ id: string; account: string; name: string; security_epoch: number; security_transition: string | null; restricted_until: number | null; expires_at: number; last_seen_at: number; kind: "app" }>()
  if (!row || !live(row,now) || !Number.isSafeInteger(row.security_epoch) || row.security_epoch < 0) return null
  if (now-row.last_seen_at>3600000) await env.DB.prepare("UPDATE web_sessions SET last_seen_at=? WHERE id=? AND account=?").bind(now,row.id,row.account).run()
  return { account: row.account,name: row.name,session: row.id,securityEpoch: row.security_epoch,transition: row.security_transition,restrictedUntil: row.restricted_until !== null && row.restricted_until > now ? row.restricted_until : null }
}
export async function requireAccountAppSession(request: Request,env: Env): Promise<AccountWebSession> {
  const account = await currentAccountAppSession(request,env)
  if (!account) throw new VaultError("unauthenticated","Sign in to the vault again in the app.")
  return account
}
