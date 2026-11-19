import { type WorkspaceRef } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { assertWorkspaceNameBudget,checkWorkspaceName } from "./workspace-names.ts"
import { accountBatch, accountGuard } from "./account-store.ts"
import { directoryWorkspaceClient, type WorkspaceMetadataClient } from "./workspace-client.ts"
export type WorkspaceSlugReservation = { id: string; workspace: string; newSlug: string; oldSlug: string; expiresAt: number }
async function namespace(env: Env) {
  const [canonical,aliases] = await Promise.all([env.DB.prepare("SELECT slug FROM workspaces UNION SELECT new_slug AS slug FROM workspace_slug_reservations").all<{ slug: string }>(),env.DB.prepare("SELECT slug,workspace FROM workspace_slugs").all<{ slug: string; workspace: string }>()])
  return { canonical: canonical.results.map(row => row.slug),aliases: aliases.results }
}
export async function reserveWorkspaceSlug(env: Env,account: string,workspace: WorkspaceRef,newSlug: string,now = Date.now()): Promise<WorkspaceSlugReservation> {
  await assertWorkspaceNameBudget(env,account,now)
  await checkWorkspaceName(env,account,newSlug,await namespace(env),workspace.id,now)
  const reservation = { id: `wrs_${crypto.randomUUID()}`,workspace: workspace.id,newSlug,oldSlug: workspace.slug,expiresAt: now+300000 }
  try {
    await accountBatch(env,[
      accountGuard(env,"EXISTS (SELECT 1 FROM workspaces WHERE id=? AND slug=? AND status='active')",[workspace.id,workspace.slug]),
      accountGuard(env,"(SELECT COUNT(*) FROM workspace_slugs WHERE workspace=?)<5",[workspace.id]),
      accountGuard(env,"NOT EXISTS (SELECT 1 FROM workspace_slug_reservations WHERE workspace=?)",[workspace.id]),
      accountGuard(env,"NOT EXISTS (SELECT 1 FROM workspaces WHERE slug=?) AND NOT EXISTS (SELECT 1 FROM workspace_slugs WHERE slug=?) AND NOT EXISTS (SELECT 1 FROM workspace_slug_reservations WHERE new_slug=?)",[newSlug,newSlug,newSlug]),
      env.DB.prepare("INSERT INTO workspace_slug_reservations(id,workspace,new_slug,old_slug,expires_at) VALUES (?,?,?,?,?)").bind(reservation.id,workspace.id,newSlug,workspace.slug,reservation.expiresAt),
    ])
  } catch (error) {
    if (error instanceof Error && (error.message.includes("UNIQUE") || error instanceof VaultError && error.code === "conflict")) {
      if (await env.DB.prepare("SELECT id FROM workspace_slug_reservations WHERE workspace=?").bind(workspace.id).first()) throw new VaultError("conflict","A workspace rename is still in progress.")
      await checkWorkspaceName(env,account,newSlug,await namespace(env),workspace.id,now)
    }
    throw error
  }
  return reservation
}
export async function finaliseWorkspaceSlug(env: Env,reservation: WorkspaceSlugReservation,metadata: Awaited<ReturnType<WorkspaceMetadataClient["metadata"]>>,now = Date.now()): Promise<void> {
  if (metadata.workspace.id !== reservation.workspace || metadata.workspace.slug !== reservation.newSlug || !metadata.appliedReservations.includes(reservation.id)) throw new VaultError("conflict","Workspace metadata changed. Try again.")
  await accountBatch(env,[
    accountGuard(env,"EXISTS (SELECT 1 FROM workspace_slug_reservations r JOIN workspaces w ON w.id=r.workspace WHERE r.id=? AND r.workspace=? AND r.new_slug=? AND r.old_slug=? AND w.slug=r.old_slug)",[reservation.id,reservation.workspace,reservation.newSlug,reservation.oldSlug]),
    accountGuard(env,"(SELECT COUNT(*) FROM workspace_slugs WHERE workspace=?)<5",[reservation.workspace]),
    env.DB.prepare("UPDATE workspaces SET slug=?,name=CASE WHEN display_rev<=? THEN ? ELSE name END,display_rev=MAX(display_rev,?) WHERE id=?").bind(reservation.newSlug,metadata.displayRev,metadata.workspace.name,metadata.displayRev,reservation.workspace),
    env.DB.prepare("INSERT INTO workspace_slugs(slug,workspace,retired_at) VALUES (?,?,?)").bind(reservation.oldSlug,reservation.workspace,now),
    env.DB.prepare("DELETE FROM workspace_slug_reservations WHERE id=?").bind(reservation.id),
  ])
}
export async function reconcileWorkspaceMetadata(env: Env,client: WorkspaceMetadataClient = directoryWorkspaceClient(env),now = Date.now()): Promise<void> {
  const pending = await env.DB.prepare("SELECT id,workspace,new_slug,old_slug,expires_at FROM workspace_slug_reservations WHERE expires_at<=? ORDER BY expires_at LIMIT 100").bind(now).all<{ id: string; workspace: string; new_slug: string; old_slug: string; expires_at: number }>()
  for (const row of pending.results) {
    try {
      const metadata = await client.metadata(row.workspace)
      if (metadata.appliedReservations.includes(row.id)) await finaliseWorkspaceSlug(env,{ id: row.id,workspace: row.workspace,newSlug: row.new_slug,oldSlug: row.old_slug,expiresAt: row.expires_at },metadata,now)
      else await env.DB.prepare("DELETE FROM workspace_slug_reservations WHERE id=? AND expires_at<=?").bind(row.id,now).run()
    } catch { console.error(JSON.stringify({ at: "workspace.slug.pending",workspace: row.workspace,reservation: row.id })) }
  }
  // Names are cosmetic; only a strictly newer DO revision may replace one.
  const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces WHERE status='active'").first<{ n: number }>()
  const offset = (Math.floor(now / 900000) % Math.max(1, Math.ceil((count?.n ?? 0) / 100))) * 100
  const workspaces = await env.DB.prepare("SELECT id FROM workspaces WHERE status='active' ORDER BY id LIMIT 100 OFFSET ?").bind(offset).all<{ id: string }>()
  for (const workspace of workspaces.results) {
    try {
      const metadata = await client.metadata(workspace.id)
      await env.DB.prepare("UPDATE workspaces SET name=?,display_rev=? WHERE id=? AND display_rev<?").bind(metadata.workspace.name,metadata.displayRev,workspace.id,metadata.displayRev).run()
    } catch { console.error(JSON.stringify({ at: "workspace.metadata.pending",workspace: workspace.id })) }
  }
}
