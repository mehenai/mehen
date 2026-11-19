// Account-keyed browser sessions, independent of workspace memberships.
import type { Env } from "../env.ts"
import { pageRead } from "../page-reads.ts"
import { timed } from "../server-timing.ts"
import { SESSION_COOKIE, live, readCookie, sha256Text } from "./session.ts"
export type AccountWebSession = { account: string; name: string; session: string; securityEpoch: number; transition: string | null; restrictedUntil: number | null }
type Row = { account: string; name: string; id: string; security_epoch: number; security_transition: string | null; status: string; suspended_at: number | null; restricted_until: number | null; kind: "web" | "app" | "recovery"; expires_at: number; last_seen_at: number }
export function currentAccountSession(request: Request, env: Env, now = Date.now()): Promise<AccountWebSession | null> {
  return timed("session", () => readAccountSession(request, env, now))
}
async function readAccountSession(request: Request, env: Env, now: number): Promise<AccountWebSession | null> {
  const token = readCookie(request, SESSION_COOKIE)
  if (!token || token.length > 100) return null
  const hash = await sha256Text(token)
  return pageRead(request, `session:${hash}`, () => sessionOf(env, hash, now))
}
async function sessionOf(env: Env, hash: string, now: number): Promise<AccountWebSession | null> {
  const row = await env.DB.prepare(`SELECT s.account,s.id,s.kind,s.expires_at,s.last_seen_at,a.name,a.status,a.suspended_at,a.security_epoch,a.security_transition,a.restricted_until FROM web_sessions s JOIN accounts a ON a.id=s.account WHERE s.token_hash=? AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.revoked_sessions) r WHERE t.account=a.id AND t.state='pending' AND r.value=s.id)`).bind(hash).first<Row>()
  if (!row || row.kind !== "web" || row.status !== "active" || row.suspended_at !== null || !live(row, now) || !Number.isSafeInteger(row.security_epoch) || row.security_epoch < 0) return null
  if (now - row.last_seen_at > 3600_000) await env.DB.prepare("UPDATE web_sessions SET last_seen_at=? WHERE token_hash=?").bind(now, hash).run()
  return { account: row.account, name: row.name, session: row.id, securityEpoch: row.security_epoch, transition: row.security_transition, restrictedUntil: row.restricted_until !== null && row.restricted_until > now ? row.restricted_until : null }
}
