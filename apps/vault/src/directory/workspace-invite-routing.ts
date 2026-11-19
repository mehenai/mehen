import type { InviteTerms,WorkspaceRef } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { randomId } from "../vault/core.ts"
import { accountBatch,accountGuard } from "./account-store.ts"
import type { AccountWebSession } from "./account-session.ts"
import { randomToken,sha256Text } from "./session.ts"
import { directoryWorkspaceClient,type WorkspaceJoinClient } from "./workspace-client.ts"
export type InviteRoutingReservation = { id: string; code: string; codeHash: string; workspace: string; expiresAt: number }
export async function reserveInviteRouting(env: Env,workspace: WorkspaceRef,account: AccountWebSession,terms: InviteTerms,now = Date.now()): Promise<InviteRoutingReservation> {
  const code = randomToken(24),id = randomId("inv"),codeHash = await sha256Text(code),expiresAt = now+300000
  await accountBatch(env,[
    accountGuard(env,"EXISTS (SELECT 1 FROM accounts a JOIN web_sessions s ON s.account=a.id JOIN memberships m ON m.account=a.id WHERE a.id=? AND a.status='active' AND a.security_epoch=? AND a.security_transition IS NULL AND s.id=? AND s.kind='web' AND s.expires_at>? AND m.workspace=? AND m.state='member')",[account.account,account.securityEpoch,account.session,now,workspace.id]),
    env.DB.prepare("INSERT INTO invite_codes(code_hash,kind,workspace,invite,email,expires_at,state,reservation_expires_at) VALUES (?,'join',?,?,?,?,'pending',?)").bind(codeHash,workspace.id,id,terms.email,expiresAt,expiresAt),
  ])
  return { id,code,codeHash,workspace: workspace.id,expiresAt }
}
export async function finaliseInviteRouting(env: Env,reservation: Pick<InviteRoutingReservation,"id" | "codeHash" | "workspace">,expiresAt: string): Promise<void> {
  await accountBatch(env,[
    accountGuard(env,"EXISTS (SELECT 1 FROM invite_codes WHERE code_hash=? AND invite=? AND workspace=? AND state IN ('pending','active'))",[reservation.codeHash,reservation.id,reservation.workspace]),
    env.DB.prepare("UPDATE invite_codes SET state='active',expires_at=?,reservation_expires_at=NULL WHERE code_hash=? AND invite=? AND workspace=?").bind(Date.parse(expiresAt),reservation.codeHash,reservation.id,reservation.workspace),
  ])
}
export async function reconcileInviteRouting(env: Env,client: WorkspaceJoinClient = directoryWorkspaceClient(env),now = Date.now()): Promise<void> {
  const rows = await env.DB.prepare("SELECT code_hash,workspace,invite FROM invite_codes WHERE state='pending' AND reservation_expires_at<=? ORDER BY reservation_expires_at LIMIT 100").bind(now).all<{ code_hash: string; workspace: string; invite: string }>()
  for (const row of rows.results) {
    try {
      const invite = await client.lookupInvite(row.workspace,row.code_hash)
      if (invite.id !== row.invite || invite.workspace.id !== row.workspace) throw new Error("Invite reservation changed")
      await finaliseInviteRouting(env,{ id: row.invite,codeHash: row.code_hash,workspace: row.workspace },invite.expiresAt)
    } catch (error) {
      if (error instanceof VaultError && error.code === "not_found") await env.DB.prepare("DELETE FROM invite_codes WHERE code_hash=? AND state='pending' AND reservation_expires_at<=?").bind(row.code_hash,now).run()
      else console.error(JSON.stringify({ at: "workspace.invite.pending",workspace: row.workspace,invite: row.invite }))
    }
  }
}
