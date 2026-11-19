import { normaliseWorkspaceSlug, type WorkspaceRef } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { can, stepUpSatisfies, type AccessMember, type AccessState } from "../vault/access.ts"
import { randomId } from "../vault/core.ts"
import type { AccountWebSession } from "./account-session.ts"
import { accountBatch, accountEvent, accountGuard } from "./account-store.ts"
import { assertWorkspaceNameBudget,checkWorkspaceName } from "./workspace-names.ts"
import type { StepUpConfirmation, WorkspaceStepUpAction } from "@mehen/protocol"
import { accountRecoveryReadySql } from "./account-recovery-setup.ts"
import { accountRecoverySetupRequired } from "./workspace-recovery.ts"
import { directoryWorkspaceClient, type WorkspaceInitialisationClient } from "./workspace-client.ts"
import { workspaceCreationAllowed, workspaceCreationAllowedSql, workspaceCreationCeilingParam, workspaceCreationDefault } from "./workspace-creation.ts"

export async function accountWorkspaceCreation(env: Env,account: AccountWebSession,action: WorkspaceStepUpAction,now = Date.now()): Promise<void> {
  const row = await env.DB.prepare(`SELECT name,can_create_workspaces,can_create_workspaces_by,restricted_until,restricted_reason,security_transition,${accountRecoveryReadySql("accounts.id")} AS recovery_ready FROM accounts WHERE id=? AND status='active'`).bind(account.account).first<{ name: string; can_create_workspaces: number; can_create_workspaces_by: string | null; restricted_until: number | null; restricted_reason: "recovery" | "reset" | "break-glass" | null; security_transition: string | null; recovery_ready: number }>()
  if (!row) throw new VaultError("unauthenticated","Sign in with your passkey to continue.")
  const member: AccessMember = { id: account.account,account: account.account,name: row.name,status: "active",canCreateWorkspaces: workspaceCreationAllowed(await workspaceCreationDefault(env),row),standing: { identityRule: null,checkSequence: 0,effectiveRole: "member",pendingRole: null,restriction: row.restricted_until !== null && row.restricted_reason !== null ? { reason: row.restricted_reason,until: row.restricted_until,notice: "account" } : null,identityRuleRev: 0,gateGeneration: 0,transitionPending: row.security_transition !== null,identityGate: { covered: false,admitted: true,checkedAt: null } } }
  const state: AccessState = { accessRev: 0,members: [member],teams: [],shares: [],projects: [],credentials: [],devices: [] }
  const decision = can(state,{ kind: "member",account: account.account,memberId: member.id,session: account.session,securityEpoch: account.securityEpoch,sessionCheck: null },{ type: "workspace.create" },{},now)
  if (!decision.allowed) throw new VaultError(decision.error,decision.message,decision.next ? { next: decision.next } : {})
  if (row.recovery_ready !== 1) throw accountRecoverySetupRequired(env)
  if (!stepUpSatisfies(decision,action)) throw new VaultError("forbidden","This needs a passkey confirmation of the exact action.")
}
async function namespace(env: Env) {
  const [canonical,aliases] = await Promise.all([env.DB.prepare("SELECT slug FROM workspaces UNION SELECT new_slug AS slug FROM workspace_slug_reservations").all<{ slug: string }>(),env.DB.prepare("SELECT slug,workspace FROM workspace_slugs").all<{ slug: string; workspace: string }>()])
  return { canonical: canonical.results.map(x => x.slug),aliases: aliases.results }
}
export type WorkspaceReservation = { workspace: WorkspaceRef; member: string; account: string; name: string }
// confirmation: how the step-up was proven; a graced one is kept on the account event.
export async function reserveWorkspace(env: Env,account: AccountWebSession,input: { name: string; slug: string },action: WorkspaceStepUpAction,{ confirmation,now = Date.now() }: { confirmation?: StepUpConfirmation; now?: number } = {}): Promise<WorkspaceReservation> {
  const slug = normaliseWorkspaceSlug(input.slug),name = input.name.trim()
  if (!name || name.length > 64 || action.type !== "workspace.create" || action.name !== name || action.slug !== slug) throw new VaultError("bad_request","Workspace details do not match the confirmation.")
  await accountWorkspaceCreation(env,account,action,now)
  await assertWorkspaceNameBudget(env,account.account,now)
  await checkWorkspaceName(env,account.account,slug,await namespace(env),undefined,now)
  const workspace = { id: randomId("tn"),slug,name },member = randomId("mem")
  try {
    await accountBatch(env,[
      accountGuard(env,`EXISTS (SELECT 1 FROM accounts a JOIN web_sessions s ON s.account=a.id WHERE a.id=? AND a.status='active' AND a.security_transition IS NULL AND a.security_epoch=? AND ${workspaceCreationAllowedSql("a")} AND ${accountRecoveryReadySql("a.id")}
        AND (a.restricted_until IS NULL OR a.restricted_until<=?) AND s.id=? AND s.kind='web' AND s.expires_at>? AND s.last_seen_at>?)`,[account.account,account.securityEpoch,workspaceCreationCeilingParam(env),now,account.session,now,now-7*86400000]),
      accountGuard(env,"NOT EXISTS (SELECT 1 FROM workspaces WHERE slug=?) AND NOT EXISTS (SELECT 1 FROM workspace_slugs WHERE slug=?) AND NOT EXISTS (SELECT 1 FROM workspace_slug_reservations WHERE new_slug=?)",[slug,slug,slug]),
      env.DB.prepare("INSERT INTO workspaces(id,slug,name,status,created_by,created_at) VALUES (?,?,?,'creating',?,?)").bind(workspace.id,slug,name,account.account,now),
      env.DB.prepare("INSERT INTO memberships(id,account,workspace,state,role_hint,updated_at) VALUES (?,?,?,'joining','owner',?)").bind(member,account.account,workspace.id,now),
      accountEvent(env,account.account,"account.workspace_create",{ workspace: workspace.id,...(confirmation?.kind === "grace" ? { confirmation } : {}) },now),
    ])
  } catch (error) {
    if (error instanceof Error && (error.message.includes("UNIQUE") || error instanceof VaultError && error.code === "conflict")) {
      await checkWorkspaceName(env,account.account,slug,await namespace(env),undefined,now)
    }
    throw error
  }
  return { workspace,member,account: account.account,name: account.name }
}
export async function initialiseWorkspace(env: Env,reservation: WorkspaceReservation,client: WorkspaceInitialisationClient = directoryWorkspaceClient(env),now = Date.now()): Promise<WorkspaceRef> {
  const index = await env.DB.prepare(`SELECT a.security_epoch,a.security_transition,${accountRecoveryReadySql("a.id")} AS recovery_ready,a.status,w.status AS workspace_status,m.state FROM accounts a JOIN memberships m ON m.account=a.id JOIN workspaces w ON w.id=m.workspace WHERE a.id=? AND w.id=? AND m.id=?`).bind(reservation.account,reservation.workspace.id,reservation.member).first<{ security_epoch: number; security_transition: string | null; recovery_ready: number; status: string; workspace_status: string; state: string }>()
  if (!index || index.status !== "active" || index.state === "left") throw new VaultError("not_found","No such workspace.")
  if (index.recovery_ready !== 1) throw accountRecoverySetupRequired(env)
  if (index.security_transition) throw new VaultError("account_pending","Account security changes are still pending.")
  await client.install(reservation.workspace.id,{ account: reservation.account,committedEpoch: index.security_epoch,pending: null })
  const result = await client.init(reservation.workspace.id,{ workspace: reservation.workspace.id,slug: reservation.workspace.slug,name: reservation.workspace.name,owner: { account: reservation.account,name: reservation.name },member: reservation.member })
  if (result.member !== reservation.member) throw new Error("Workspace initialisation changed the reserved member")
  await accountBatch(env,[
    accountGuard(env,`EXISTS (SELECT 1 FROM accounts WHERE id=? AND status='active' AND security_transition IS NULL AND security_epoch=? AND ${accountRecoveryReadySql("accounts.id")})`,[reservation.account,index.security_epoch]),
    env.DB.prepare("UPDATE workspaces SET status='active' WHERE id=? AND status='creating'").bind(reservation.workspace.id),
    env.DB.prepare("UPDATE memberships SET state='member',updated_at=? WHERE id=? AND account=? AND state='joining'").bind(now,reservation.member,reservation.account),
  ])
  return reservation.workspace
}
export async function reconcileCreatingWorkspaces(env: Env,client: WorkspaceInitialisationClient = directoryWorkspaceClient(env)): Promise<void> {
  const rows = await env.DB.prepare("SELECT w.id,w.slug,w.name,m.id AS member,a.id AS account,a.name AS account_name FROM workspaces w JOIN memberships m ON m.workspace=w.id JOIN accounts a ON a.id=m.account WHERE w.status='creating' AND m.state='joining' ORDER BY w.created_at LIMIT 100").all<{ id: string; slug: string; name: string; member: string; account: string; account_name: string }>()
  for (const row of rows.results) { try { await initialiseWorkspace(env,{ workspace: { id: row.id,slug: row.slug,name: row.name },member: row.member,account: row.account,name: row.account_name },client) } catch { console.error(JSON.stringify({ at: "workspace.create.pending",workspace: row.id })) } }
}
