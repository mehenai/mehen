// Connect codes: minted on the Connect an agent page for one account in one
// workspace, they route an enrolment to that account's inbox and claim it,
// so only that account can accept the machine. Routing and binding, never
// authority: acceptance still needs the claimed account's passkey and the
// typed hidden group, and admission is unchanged. Stored hashed only.
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { enrolmentCode,normaliseCode } from "./enrolment.ts"
import { directoryWorkspaceClient } from "./workspace-client.ts"
import { sha256Text } from "./session.ts"

export const CONNECT_CODE_TTL_MS = 86_400_000

// One message, one body, for every refusal: an unknown, expired, malformed
// or other-workspace code, a removed account or membership, a suspended
// member. Nothing tells them apart.
export function connectCodeRefusal(): VaultError {
  return new VaultError("forbidden","The connect code is not valid for this workspace.")
}

// Reissuing for the same account and workspace replaces the old code.
export async function issueConnectCode(env: Env,account: string,workspace: string,now = Date.now()): Promise<{ code: string; expiresAt: string }> {
  const code = enrolmentCode(),expiresAt = now+CONNECT_CODE_TTL_MS
  await env.DB.batch([
    env.DB.prepare("DELETE FROM enrol_connect_codes WHERE account=? AND workspace=?").bind(account,workspace),
    env.DB.prepare("INSERT INTO enrol_connect_codes(code_hash,account,workspace,created_at,expires_at) VALUES (?,?,?,?,?)").bind(await sha256Text(code),account,workspace,now,expiresAt),
  ])
  return { code,expiresAt: new Date(expiresAt).toISOString() }
}

// The account a start's connect code claims the attempt for, or the one
// refusal. The per-address limiter is spent first, so guessing is bounded
// however many keys the guesser makes.
export async function connectCodeClaim(env: Env,request: Request,input: string,workspaceSlug: string,now = Date.now()): Promise<string> {
  const limited = await env.AUTH_RATE_LIMITER?.limit({ key: `enrol-connect:${request.headers.get("cf-connecting-ip") ?? "local"}` })
  if (!limited?.success) throw new VaultError("rate_limited","Too many connect code attempts. Try again shortly.",{ retryAfter: 60 })
  const code = normaliseCode(input)
  if (!code) throw connectCodeRefusal()
  const row = await env.DB.prepare(`SELECT c.account,c.workspace FROM enrol_connect_codes c JOIN workspaces w ON w.id=c.workspace JOIN accounts a ON a.id=c.account
    JOIN memberships m ON m.account=c.account AND m.workspace=c.workspace AND m.state='member'
    WHERE c.code_hash=? AND c.expires_at>? AND w.status='active' AND a.status='active'
      AND (w.slug=? OR EXISTS (SELECT 1 FROM workspace_slugs s WHERE s.workspace=w.id AND s.slug=?))`).bind(await sha256Text(code),now,workspaceSlug,workspaceSlug).first<{ account: string; workspace: string }>()
  if (!row) throw connectCodeRefusal()
  // Suspension lives in the workspace, not the directory.
  let status: string
  try { status = (await directoryWorkspaceClient(env).membership(row.workspace,row.account)).status } catch (error) {
    if (error instanceof VaultError && error.code === "not_found") throw connectCodeRefusal()
    throw error
  }
  if (status !== "active") throw connectCodeRefusal()
  return row.account
}

// Housekeeping for the cron's expiry batch: expired codes, and codes whose
// account is no longer active or whose membership has ended.
export function connectCodeSweep(env: Env,now: number): D1PreparedStatement {
  return env.DB.prepare(`DELETE FROM enrol_connect_codes WHERE expires_at<=?
    OR NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id=enrol_connect_codes.account AND a.status='active')
    OR NOT EXISTS (SELECT 1 FROM memberships m WHERE m.account=enrol_connect_codes.account AND m.workspace=enrol_connect_codes.workspace AND m.state='member')`).bind(now)
}
