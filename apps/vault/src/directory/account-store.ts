import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { blobBytes } from "./passkeys.ts"
import { directoryId, type NewSession, type SessionMeta, MAX_SESSIONS, RECOVERY_SESSION_MS } from "./session.ts"
import type { PasskeyRecord, RegisteredPasskey } from "./webauthn.ts"

// A failed conditional write must abort its whole D1 batch, not just skip one
// statement. Only internal SQL predicates enter this helper.
export function accountGuard(env: Env, predicate: string, values: (string | number | null)[] = []): D1PreparedStatement {
  return env.DB.prepare(`SELECT CASE WHEN (${predicate}) THEN 1 ELSE json('account-write-refused') END`).bind(...values)
}
export async function accountBatch(env: Env, statements: D1PreparedStatement[]): Promise<D1Result[]> {
  try { return await env.DB.batch(statements) } catch (error) {
    if (error instanceof Error && error.message.includes("malformed JSON")) throw new VaultError("conflict", "Account state changed. Try again.")
    throw error
  }
}
export function accountEvent(env: Env, account: string, action: string, detail: Record<string, unknown>, now: number, id = `evt_${crypto.randomUUID()}`): D1PreparedStatement {
  return env.DB.prepare(`INSERT INTO account_events(id,account,at,action,detail,targets) VALUES (?,?,?,?,?,
    (SELECT COALESCE(json_group_array(DISTINCT workspace),'[]') FROM memberships WHERE account=? AND state IN ('joining','member')))`)
    .bind(id, account, now, action, JSON.stringify(detail), account)
}
// While a recovery cools off, a sign-in counts as the owner's only if its
// passkey is older than every such notice, the same age rule that lets a
// factor cancel: otherwise the recovered sign-in could end the older
// passkey's fresh one, or push it past the session cap, before it cancels.
// Break-glass leaves no older passkey, so it is not counted. Binds the
// account, then now.
export function olderFactorOrNoRecoverySql(sessionId: string): string {
  return `NOT EXISTS (SELECT 1 FROM account_notices n WHERE n.account=? AND n.kind='recovery' AND n.resolved_at IS NULL AND (n.restricted_until IS NULL OR n.restricted_until>?)
  AND NOT EXISTS (SELECT 1 FROM web_sessions s JOIN passkeys p ON p.credential_id=s.passkey AND p.account=s.account WHERE s.id=${sessionId} AND s.account=n.account AND p.created_at<n.at))`
}
export function accountSessionStatements(env: Env, session: NewSession, account: string, now: number, meta: SessionMeta): D1PreparedStatement[] {
  return [
    env.DB.prepare(`INSERT INTO web_sessions(token_hash,id,account,created_at,expires_at,last_seen_at,kind,method,passkey,client,place,lineage)
      SELECT ?,?,?,?,?,?,?,?,?,?,?,json_object('kind','factor','factor',(SELECT handle FROM passkeys WHERE credential_id=? AND account=?)) WHERE EXISTS (SELECT 1 FROM accounts a WHERE a.id=? AND a.status='active' AND a.suspended_at IS NULL
        AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.removed_factors) f JOIN passkeys p ON p.handle=f.value WHERE t.account=a.id AND t.state='pending' AND p.credential_id=?))`)
      .bind(session.tokenHash,session.id,account,now,now+(meta.kind === "recovery" ? RECOVERY_SESSION_MS : 30*86400000),now,meta.kind,meta.method,meta.passkey,meta.client,meta.place,meta.passkey,account,account,meta.passkey),
    env.DB.prepare(`DELETE FROM web_sessions WHERE account=? AND kind IN ('web','app') AND token_hash NOT IN
      (SELECT c.token_hash FROM web_sessions c WHERE c.account=? AND c.kind IN ('web','app') ORDER BY ${olderFactorOrNoRecoverySql("c.id")} DESC,c.created_at DESC,c.token_hash DESC LIMIT ?)`)
      .bind(account,account,account,now,MAX_SESSIONS),
  ]
}
export function insertAccountPasskey(env: Env, account: string, passkey: RegisteredPasskey, now: number, via: "signup" | "settings" | "recovery" | "break-glass", handle = directoryId("pk")): D1PreparedStatement {
  return env.DB.prepare(`INSERT INTO passkeys(credential_id,account,public_key,counter,transports,created_at,last_used_at,handle,aaguid,device_type,backed_up,added_via)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).bind(passkey.credentialId,account,passkey.publicKey.slice().buffer,passkey.counter,JSON.stringify(passkey.transports),now,now,handle,passkey.aaguid,passkey.deviceType,passkey.backedUp === null ? null : Number(passkey.backedUp),via)
}
export async function findAccountPasskey(env: Env, credential: string): Promise<{ account: string; handle: string; createdAt: number; record: PasskeyRecord } | null> {
  const row = await env.DB.prepare("SELECT account,handle,created_at,public_key,counter,transports FROM passkeys WHERE credential_id=?").bind(credential)
    .first<{ account: string; handle: string; created_at: number; public_key: unknown; counter: number; transports: string | null }>()
  if (!row) return null
  const transports: unknown = JSON.parse(row.transports ?? "[]")
  return { account: row.account,handle: row.handle,createdAt: row.created_at,record: { credentialId: credential,publicKey: blobBytes(row.public_key),counter: row.counter,transports: Array.isArray(transports) ? transports.filter((v): v is string => typeof v === "string") : [] } }
}
