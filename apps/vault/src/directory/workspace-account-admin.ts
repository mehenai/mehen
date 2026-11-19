import type { PasskeyView,SessionView } from "@mehen/protocol/api"
import { authenticatorWords,PasskeyName } from "./passkey-admin.ts"
import { PENDING_RESTRICTION_UNTIL } from "@mehen/protocol"
import type { AccountSession } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { accountRecoveryReadySql } from "./account-recovery-setup.ts"
import { accountRecoverySetupRequired } from "./workspace-recovery.ts"
import { workspaceCreationAllowed,workspaceCreationDefault,workspaceCreationSource } from "./workspace-creation.ts"
import { accountSecurityStatus,reserveAccountSecurity,retryAccountSecurity } from "./account-security.ts"
import type { AccountWebSession } from "./account-session.ts"
import { accountBatch,accountEvent,accountGuard,olderFactorOrNoRecoverySql } from "./account-store.ts"
import { assertWorkspaceSessionGate } from "./oidc-flow.ts"
import { directoryWorkspaceClient,type DirectoryWorkspaceClient,type WorkspaceMetadataClient } from "./workspace-client.ts"
export async function accountSessionView(env: Env,account: AccountWebSession,client: WorkspaceMetadataClient = directoryWorkspaceClient(env)): Promise<AccountSession> {
  const [row,notice,index,rule] = await Promise.all([
    env.DB.prepare(`SELECT can_create_workspaces,can_create_workspaces_by,restricted_reason,restricted_until,${accountRecoveryReadySql("accounts.id")} AS recovery_ready FROM accounts WHERE id=?`).bind(account.account).first<{ can_create_workspaces: number; can_create_workspaces_by: string | null; restricted_reason: "recovery" | "reset" | "break-glass" | null; restricted_until: number | null; recovery_ready: number }>(),
    env.DB.prepare("SELECT id FROM account_notices WHERE account=? AND resolved_at IS NULL AND kind IN ('recovery','break-glass') ORDER BY at DESC LIMIT 1").bind(account.account).first<{ id: string }>(),
    env.DB.prepare("SELECT w.id,w.slug,w.name FROM workspaces w JOIN memberships m ON m.workspace=w.id WHERE m.account=? AND m.state='member' AND w.status='active' ORDER BY w.name,w.id").bind(account.account).all<{ id: string; slug: string; name: string }>(),
    workspaceCreationDefault(env),
  ])
  const memberships: AccountSession["memberships"] = []
  for (const workspace of index.results) {
    try {
      const member = await client.membership(workspace.id,account.account)
      memberships.push({ workspace,member: member.member,role: member.role,pendingRole: member.pendingRole,status: member.status })
    } catch (error) {
      if (error instanceof VaultError && error.code === "not_found") continue
      console.error(JSON.stringify({ at: "account.membership.unavailable",workspace: workspace.id }))
      throw new VaultError("upstream_failed","Workspace security metadata is temporarily unavailable.",{ retryAfter: 60,next: { url: `${env.VAULT_ORIGIN}/api/account/security-transition`,say: "Check the pending account security transition and retry the workspace list." } })
    }
  }
  return { account: account.account,name: account.name,canCreateWorkspaces: row ? workspaceCreationAllowed(rule,row) : false,workspaceCreation: row ? workspaceCreationSource(row) : "default",recoverySetupRequired: row?.recovery_ready !== 1,securityEpoch: account.securityEpoch,pendingTransition: await accountSecurityStatus(env,account.account),restricted: row?.restricted_reason && row.restricted_until && row.restricted_until > Date.now() ? { reason: row.restricted_reason,until: row.restricted_until >= PENDING_RESTRICTION_UNTIL ? null : new Date(row.restricted_until).toISOString(),notice: notice?.id ?? "" } : null,memberships }
}
export async function accountPasskeys(env: Env,actor: AccountWebSession): Promise<PasskeyView[]> {
  const rows = await env.DB.prepare(`SELECT p.credential_id,p.handle,p.name,p.transports,p.backed_up,p.added_via,p.created_at,p.last_used_at,p.last_used_client,p.last_used_place,
    (SELECT passkey FROM web_sessions WHERE id=? AND account=p.account) AS current_passkey FROM passkeys p WHERE p.account=? ORDER BY p.created_at,p.handle`)
    .bind(actor.session,actor.account).all<{ credential_id: string; handle: string; name: string | null; transports: string | null; backed_up: number | null; added_via: PasskeyView["addedVia"]; created_at: number; last_used_at: number | null; last_used_client: string | null; last_used_place: string | null; current_passkey: string | null }>()
  return rows.results.map(row => {
    const transports: unknown = JSON.parse(row.transports ?? "[]")
    return { passkey: row.handle,name: row.name,authenticator: authenticatorWords(Array.isArray(transports) ? transports.filter((value): value is string => typeof value === "string") : []),synced: row.backed_up === null ? null : row.backed_up === 1,addedVia: row.added_via,createdAt: new Date(row.created_at).toISOString(),lastUsedAt: row.last_used_at === null ? null : new Date(row.last_used_at).toISOString(),lastUsedClient: row.last_used_client,lastUsedPlace: row.last_used_place,current: row.current_passkey !== null && row.current_passkey === row.credential_id }
  })
}
export async function accountSessions(env: Env,actor: AccountWebSession,now = Date.now()): Promise<SessionView[]> {
  const rows = await env.DB.prepare(`SELECT s.id,s.kind,s.method,s.client,s.place,p.name AS passkey_name,s.created_at,s.last_seen_at FROM web_sessions s
    LEFT JOIN passkeys p ON p.credential_id=s.passkey AND p.account=s.account WHERE s.account=? AND s.kind IN ('web','app') AND s.expires_at>? AND s.last_seen_at>? AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.revoked_sessions) r WHERE t.account=s.account AND t.state='pending' AND r.value=s.id) ORDER BY s.last_seen_at DESC,s.id`)
    .bind(actor.account,now,now-7*86400000).all<{ id: string; kind: SessionView["kind"]; method: SessionView["method"]; client: string; place: string | null; passkey_name: string | null; created_at: number; last_seen_at: number }>()
  return rows.results.map(row => ({ session: row.id,kind: row.kind,method: row.method,client: row.client,place: row.place,passkeyName: row.passkey_name,createdAt: new Date(row.created_at).toISOString(),lastSeenAt: new Date(row.last_seen_at).toISOString(),current: row.id === actor.session }))
}
export async function renameAccountPasskey(env: Env,actor: AccountWebSession,passkey: string,input: string,now = Date.now()): Promise<PasskeyView> {
  const name = PasskeyName.parse(input)
  if (!(await env.DB.prepare("SELECT handle FROM passkeys WHERE account=? AND handle=?").bind(actor.account,passkey).first())) throw new VaultError("not_found","You have no passkey with that id.")
  await accountBatch(env,[
    accountGuard(env,"EXISTS (SELECT 1 FROM accounts a JOIN web_sessions s ON s.account=a.id WHERE a.id=? AND a.status='active' AND a.security_epoch=? AND a.security_transition IS NULL AND s.id=? AND s.kind='web' AND s.expires_at>? AND s.last_seen_at>?)",[actor.account,actor.securityEpoch,actor.session,now,now-7*86400000]),
    accountGuard(env,"EXISTS (SELECT 1 FROM passkeys WHERE account=? AND handle=?)",[actor.account,passkey]),
    env.DB.prepare("UPDATE passkeys SET name=? WHERE account=? AND handle=?").bind(name,actor.account,passkey),
    accountEvent(env,actor.account,"account.passkey_rename",{ passkey },now),
  ])
  const view = (await accountPasskeys(env,actor)).find(value => value.passkey === passkey)
  if (!view) throw new VaultError("not_found","You have no passkey with that id.")
  return view
}
export async function removeAccountPasskey(env: Env,account: AccountWebSession,passkey: string,factor: string,client: DirectoryWorkspaceClient = directoryWorkspaceClient(env)): Promise<{ pending: boolean }> {
  const key = await env.DB.prepare("SELECT handle FROM passkeys WHERE account=? AND handle=?").bind(account.account,passkey).first<{ handle: string }>()
  if (!key) throw new VaultError("not_found","No such passkey.")
  const keys = await env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys WHERE account=?").bind(account.account).first<{ n: number }>()
  if (!keys || keys.n < 2) throw new VaultError("conflict","Keep at least one account passkey.")
  const transition = await reserveAccountSecurity(env,account.account,{ effect: { kind: "factor.remove" },revokedSessionIds: [],removedFactorIds: [passkey],authorisingFactor: factor,session: { id: account.session,epoch: account.securityEpoch } })
  return { pending: await retryAccountSecurity(env,transition,client) !== null }
}
const RECOVERY_SESSION_END_REFUSED = "During a recovery, only a sign-in with a passkey from before it can end other sign-ins. Cancelling the recovery ends the new ones."
const OLDER_FACTOR_OR_NO_RECOVERY = olderFactorOrNoRecoverySql("?")
export async function mayEndOtherAccountSessions(env: Env,account: AccountWebSession,now = Date.now()): Promise<boolean> {
  return (await env.DB.prepare(`SELECT 1 AS allowed WHERE ${OLDER_FACTOR_OR_NO_RECOVERY}`).bind(account.account,now,account.session).first()) !== null
}
async function assertMayEndOtherSessions(env: Env,account: AccountWebSession,now: number): Promise<void> {
  if (!(await mayEndOtherAccountSessions(env,account,now))) throw new VaultError("forbidden",RECOVERY_SESSION_END_REFUSED)
}
export async function endAllAccountSessions(env: Env,account: AccountWebSession,client: DirectoryWorkspaceClient = directoryWorkspaceClient(env)): Promise<{ pending: boolean }> {
  await assertMayEndOtherSessions(env,account,Date.now())
  const sessions = await env.DB.prepare("SELECT id FROM web_sessions WHERE account=?").bind(account.account).all<{ id: string }>()
  const id = await reserveAccountSecurity(env,account.account,{ effect: { kind: "sessions.end" },revokedSessionIds: sessions.results.map(s => s.id),removedFactorIds: [],session: { id: account.session,epoch: account.securityEpoch } })
  return { pending: await retryAccountSecurity(env,id,client) !== null }
}
export async function endOwnAccountSession(env: Env,account: AccountWebSession,session: string,now = Date.now()): Promise<void> {
  if (session !== account.session) await assertMayEndOtherSessions(env,account,now)
  await accountBatch(env,[
    accountGuard(env,"EXISTS (SELECT 1 FROM web_sessions WHERE account=? AND id=?)",[account.account,session]),
    accountGuard(env,`?=? OR ${OLDER_FACTOR_OR_NO_RECOVERY}`,[session,account.session,account.account,now,account.session]),
    accountGuard(env,"EXISTS (SELECT 1 FROM web_sessions s JOIN accounts a ON a.id=s.account WHERE a.id=? AND s.id=? AND s.expires_at>? AND s.last_seen_at>? AND a.status='active')",[account.account,account.session,now,now-7*86400000]),
    env.DB.prepare("DELETE FROM web_sessions WHERE account=? AND id=?").bind(account.account,session),
    accountEvent(env,account.account,"account.signout",{ session },now),
  ])
}
// Where a membership just confirmed goes first: Connect an agent, at the
// canonical slug so no redirect comes between. While this session still owes
// the workspace's identity check, the connect-code issuer would refuse, so
// the home, where that check returns to.
export async function assertAccountOnboarding(env: Env,account: AccountWebSession,workspace: string,client: WorkspaceMetadataClient = directoryWorkspaceClient(env)): Promise<{ next: string }> {
  const row = await env.DB.prepare(`SELECT ${accountRecoveryReadySql("accounts.id")} AS ready FROM accounts WHERE id=? AND status='active'`).bind(account.account).first<{ ready: number }>()
  if (!row || row.ready !== 1) throw accountRecoverySetupRequired(env)
  const indexed = await env.DB.prepare("SELECT w.id FROM workspaces w JOIN memberships m ON m.workspace=w.id WHERE w.id=? AND w.status='active' AND m.account=? AND m.state='member'").bind(workspace,account.account).first()
  if (!indexed) throw new VaultError("not_found","No such workspace.")
  const member = await client.membership(workspace,account.account)
  if (member.status !== "active") throw new VaultError("forbidden","An owner or admin must confirm this membership before you connect an agent.")
  const ref = await client.metadata(workspace)
  try {
    await assertWorkspaceSessionGate(env,account,ref.workspace,"web")
  } catch (error) {
    if (error instanceof VaultError && error.code === "identity_required") return { next: `${env.VAULT_ORIGIN}/w/${ref.workspace.slug}/` }
    throw error
  }
  return { next: `${env.VAULT_ORIGIN}/w/${ref.workspace.slug}/connect-agent` }
}
