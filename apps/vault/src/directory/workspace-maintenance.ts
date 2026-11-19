import { reconcileAccountBreakGlass } from "./account-break-glass.ts"
import type { Env } from "../env.ts"
import { retryDueAccountSecurity } from "./account-security.ts"
import { reconcileSuspendedAccounts } from "./account-suspension.ts"
import { drainWorkspaceNotices,mirrorAccountEvents } from "./account-events.ts"
import { reconcileCreatingWorkspaces } from "./workspace-index.ts"
import { expireEmailJoins, expireOidcJoins, reconcileWorkspaceJoins } from "./workspace-invites.ts"
import { emailProofSweep } from "./email-proof.ts"
import { inviteEmailSweep } from "./invite-email.ts"
import { reconcileInviteRouting } from "./workspace-invite-routing.ts"
import { reconcileWorkspaceMetadata } from "./workspace-aliases.ts"
import { reconcileEnrolmentMirrors } from "./workspace-enrolment.ts"
import { directoryWorkspaceClient } from "./workspace-client.ts"
import { connectCodeSweep } from "./connect-code.ts"
import { ENROLMENT_PRUNE_BATCHES,ENROLMENT_PRUNE_LIMIT,ENROLMENT_SETTLED_KEEP_MS,UNREACHED_ENROLMENT } from "./enrolment.ts"
import { maintainPlatforms } from "../platform/sweeps.ts"
import { backUpWorkspaceVaults, runVaultRestores } from "./vault-backups.ts"
import { expireOperatorProposals } from "./operator-proposals.ts"
// One prune statement repeated in bounded batches, stopping at a short one.
async function pruneEnrolments(statement: () => D1PreparedStatement): Promise<void> {
  for (let batch = 0; batch < ENROLMENT_PRUNE_BATCHES; batch++) {
    if ((await statement().run()).meta.changes < ENROLMENT_PRUNE_LIMIT) return
  }
}
// Registered by the Worker after its fresh-start schema/binding guard.
export async function maintainWorkspaceDirectory(env: Env,now = Date.now()): Promise<void> {
  const tasks: [string,() => Promise<void>][] = [
    ["expiry",async () => { await env.DB.batch([
      env.DB.prepare("DELETE FROM challenges WHERE expires_at<=?").bind(now),
      env.DB.prepare("DELETE FROM web_sessions WHERE expires_at<=? OR (kind!='recovery' AND last_seen_at<=?)").bind(now,now-7*86400000),
      env.DB.prepare("DELETE FROM oauth_states WHERE expires_at<=?").bind(now),
      // Only the hard cap ends an attempt: a lapsed lease stays renewable.
      env.DB.prepare("UPDATE enrolments SET status='expired',pending_state=NULL,expired_reason='hard_cap' WHERE status='pending' AND hard_expires_at<=?").bind(now),
      env.DB.prepare("DELETE FROM enrol_nonces WHERE expires_at<=?").bind(now),
      connectCodeSweep(env,now),
      env.DB.prepare("DELETE FROM auth_attempts WHERE window_start<?").bind(now-3600000),
      env.DB.prepare("DELETE FROM recovery_codes WHERE status='pending' AND batch IN (SELECT batch FROM recovery_batches WHERE expires_at<=?)").bind(now),
      env.DB.prepare("DELETE FROM recovery_batches WHERE expires_at<=?").bind(now),
      env.DB.prepare("DELETE FROM oidc_flows WHERE expires_at<=?").bind(now),
      env.DB.prepare("DELETE FROM app_gate_codes WHERE expires_at<=?").bind(now),
      env.DB.prepare("DELETE FROM oidc_results WHERE expires_at<=? AND NOT (state='joining' AND joining_membership IS NOT NULL)").bind(now),
      emailProofSweep(env,now),
      inviteEmailSweep(env,now),
      env.DB.prepare("DELETE FROM operation_identity_checks WHERE expires_at<=?").bind(now),
      env.DB.prepare("DELETE FROM session_identity_checks WHERE expires_at<=?").bind(now),
    ]) }],
    // Its own bounded step, so a backlog never rolls back the expiry batch.
    // An attempt that never reached a workspace goes at its hard cap with no
    // retention: superseded or run out, claimed and accepted by no account,
    // and no tenant, which its page records once it has registered the
    // workspace's copy, even when the attempt changed meanwhile
    // (routes/enrolments.ts). A copy whose register reply was lost is dead
    // past the hard cap anyway (vault/areas/workspace-devices.ts, enrol).
    ["enrolment-prune-unreached",() => pruneEnrolments(() => env.DB.prepare(`DELETE FROM enrolments WHERE id IN (SELECT e.id FROM enrolments e WHERE ${UNREACHED_ENROLMENT}
      AND COALESCE(e.hard_expires_at,e.expires_at)<=? ORDER BY e.created_at LIMIT ?)`).bind(now,ENROLMENT_PRUNE_LIMIT))],
    // A settled attempt its workspace has still to hear of (reconcileEnrolmentMirrors) stays until it has.
    ["enrolment-prune",() => pruneEnrolments(() => env.DB.prepare(`DELETE FROM enrolments WHERE id IN (SELECT e.id FROM enrolments e WHERE e.status IN ('expired','rejected') AND e.discard_pending=0 AND COALESCE(e.hard_expires_at,e.expires_at)<=?
      AND (e.reconciled_at IS NOT NULL OR NOT EXISTS (SELECT 1 FROM workspaces w WHERE e.tenant=w.id OR e.tenant IS NULL AND (e.workspace_intent=w.slug OR EXISTS (SELECT 1 FROM workspace_slugs s WHERE s.workspace=w.id AND s.slug=e.workspace_intent))))
      ORDER BY e.created_at LIMIT ?)`).bind(now-ENROLMENT_SETTLED_KEEP_MS,ENROLMENT_PRUNE_LIMIT))],
    // Recorded restores before security and events, so the run that records
    // one done delivers again what it lost (directory/vault-backups.ts).
    ["vault-restores",() => runVaultRestores(env,undefined,now)],
    ["security",() => retryDueAccountSecurity(env,undefined,now)],
    ["break-glass",() => reconcileAccountBreakGlass(env,undefined,now)],
    ["suspensions",() => reconcileSuspendedAccounts(env,undefined,now)],
    ["creating",() => reconcileCreatingWorkspaces(env)],
    ["oidc-joins",() => expireOidcJoins(env,now)],
    ["email-joins",() => expireEmailJoins(env,now)],
    ["joining",() => reconcileWorkspaceJoins(env)],
    ["aliases",() => reconcileWorkspaceMetadata(env,undefined,now)],
    ["invites",() => reconcileInviteRouting(env,undefined,now)],
    ["enrolments",() => reconcileEnrolmentMirrors(env,directoryWorkspaceClient(env),now)],
    ["events",() => mirrorAccountEvents(env)],
    ["notices",() => drainWorkspaceNotices(env,undefined,now)],
    // Platform mode: retiring, creating, deleting, purging and activity (platform/sweeps.ts).
    ["platforms",() => maintainPlatforms(env,now)],
    // Two-operator proposals past their 24 hours (directory/operator-proposals.ts).
    ["operator-proposals",() => expireOperatorProposals(env,now)],
    // The operator's backup: each workspace's daily dump (directory/vault-backups.ts).
    ["vault-backups",() => backUpWorkspaceVaults(env,undefined,now)],
  ]
  for (const [task,run] of tasks) { try { await run() } catch { console.error(JSON.stringify({ at: "directory.maintenance.pending",task })) } }
}
