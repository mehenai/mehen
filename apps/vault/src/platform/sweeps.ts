// The cron's platform work, each part bounded and idempotent, so an
// interrupted run is finished by the next one:
// - retiring: a platform past its retirement date has every live subject
//   marked deleting; once none is left its PlatformVault is erased, its
//   keys revoked and it is marked retired;
// - creating: a subject whose creation was interrupted is removed through
//   deletion, never left half made;
// - deleting: subjects marked deleting (by route 7 interrupted, route 31,
//   delete-subjects or retirement) are deleted, PLATFORM_DELETE_BATCH a run,
//   those tried least recently first;
// - purging: a deleted subject past its purge date has its last audit head
//   kept in D1 and its workspace erased; the subject's name goes, its hash
//   stays as the tombstone;
// - activity: each platform's last day of calls, by route and outcome, is
//   copied to D1 for the operator's `show`;
// - removing: a platform the operator removed (retired at once, its live
//   subjects marked deleting) has its deleted subjects purged without
//   waiting for the audit retention, which no one can read once its keys
//   are revoked; once it is retired and every subject purged, its slug is
//   renamed to a reserved, unguessable form, freeing it, and the old slug
//   is kept beside it with the row, its keys, its events and its subjects'
//   tombstones.

import { PLATFORM_DELETE_BATCH, REMOVED_PLATFORM_SLUG_PREFIX } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { randomId } from "../vault/core.ts"
import { PLATFORM_SYSTEM_AUTH, purgeSubjectWorkspace, removeSubjectWorkspace } from "./workspace-calls.ts"

export const PLATFORM_CREATING_GRACE_MS = 10 * 60_000
const DAY_MS = 86_400_000

// The fixed id of a platform's rolling activity row in platform_events.
export function activityEventId(platform: string): string {
  return `pev_activity_${platform}`
}

// The operator's and an admin's reading of that row: the last day's devices
// made, items added and deleted, decisions, and refusals of any kind.
export function activityCounts(activity: unknown): { devices: number; added: number; deleted: number; decisions: number; refusals: number } {
  const routes = typeof activity === "object" && activity !== null ? (activity as Record<string, Record<string, number>>) : {}
  const ok = (route: string) => routes[route]?.ok ?? 0
  const refusals = Object.values(routes).reduce((sum, outcomes) => sum + Object.entries(outcomes).reduce((n, [outcome, count]) => n + (outcome === "ok" ? 0 : count), 0), 0)
  return { devices: ok("devices.create"), added: ok("intakes.submit") + ok("connects.finish"), deleted: ok("items.remove"), decisions: ok("approvals.decide"), refusals }
}

function logFailure(at: string, target: string): void {
  console.error(JSON.stringify({ at, target }))
}

export async function sweepRetiringPlatforms(env: Env, now: number): Promise<void> {
  const due = await env.DB.prepare("SELECT id FROM platforms WHERE status='retiring' AND retire_after<=?").bind(now).all<{ id: string }>()
  for (const { id } of due.results) {
    try {
      const [, live] = await env.DB.batch<{ n: number }>([
        env.DB.prepare("UPDATE managed_workspaces SET status='deleting' WHERE platform=? AND status IN ('creating','active')").bind(id),
        env.DB.prepare("SELECT COUNT(*) AS n FROM managed_workspaces WHERE platform=? AND status IN ('creating','active','deleting')").bind(id),
      ])
      if ((live?.results[0]?.n ?? 1) > 0) continue
      await env.PLATFORM_VAULT.getByName(id).erase()
      await env.DB.batch([
        env.DB.prepare("UPDATE platform_keys SET revoked_at=?,revoked_by='system' WHERE platform=? AND revoked_at IS NULL").bind(now, id),
        env.DB.prepare("UPDATE platforms SET status='retired',retire_after=NULL,status_at=?,status_by='system' WHERE id=? AND status='retiring'").bind(now, id),
        env.DB.prepare("INSERT INTO platform_events (id,platform,at,actor,action,detail) VALUES (?,?,?,'system','platform.retired','{}')").bind(randomId("pev"), id, now),
      ])
    } catch {
      logFailure("platform.sweep.retire", id)
    }
  }
}

export async function sweepCreatingSubjects(env: Env, now: number): Promise<void> {
  await env.DB.prepare("UPDATE managed_workspaces SET status='deleting' WHERE status='creating' AND created_at<=?").bind(now - PLATFORM_CREATING_GRACE_MS).run()
}

// The batch is the subjects tried least recently, never tried first (SQLite
// sorts NULL first), each marked tried as it is taken, so subjects that keep
// failing go to the back of the queue and never block the rest.
export async function sweepDeletingSubjects(env: Env, now: number): Promise<void> {
  const due = await env.DB.prepare("UPDATE managed_workspaces SET delete_attempted_at=? WHERE tenant IN (SELECT tenant FROM managed_workspaces WHERE status='deleting' ORDER BY delete_attempted_at,created_at,tenant LIMIT ?) RETURNING tenant").bind(now, PLATFORM_DELETE_BATCH).all<{ tenant: string }>()
  for (const { tenant } of due.results) {
    try {
      const { purgeAfter } = await removeSubjectWorkspace(env, tenant, PLATFORM_SYSTEM_AUTH)
      await env.DB.prepare("UPDATE managed_workspaces SET status='deleted',deleted_at=?,purge_after=? WHERE tenant=? AND status='deleting'").bind(now, purgeAfter, tenant).run()
    } catch {
      logFailure("platform.sweep.delete", tenant)
    }
  }
}

// A subject of a platform being removed is purged early: its object keeps
// its own purge date, so it is told, and checks with the directory itself.
export async function sweepDueSubjectPurges(env: Env, now: number): Promise<void> {
  const due = await env.DB.prepare("SELECT w.tenant,p.removing_at IS NOT NULL AS removing FROM managed_workspaces w JOIN platforms p ON p.id=w.platform WHERE w.status='deleted' AND w.purge_after<=? ORDER BY w.purge_after,w.tenant LIMIT ?").bind(now, PLATFORM_DELETE_BATCH).all<{ tenant: string; removing: number }>()
  for (const { tenant, removing } of due.results) {
    try {
      // The object has already recorded the head; this marks a row whose
      // object was erased before that, which answers null.
      const { auditHead } = await purgeSubjectWorkspace(env, tenant, removing === 1)
      await env.DB.prepare("UPDATE managed_workspaces SET status='purged',subject=NULL,final_audit_head=COALESCE(?,final_audit_head) WHERE tenant=? AND status='deleted'").bind(auditHead, tenant).run()
    } catch {
      logFailure("platform.sweep.purge", tenant)
    }
  }
}

// Brings forward the purge of every deleted subject of a platform being
// removed, so the purge sweep after it takes them now.
export async function expediteRemovedPurges(env: Env, now: number): Promise<void> {
  await env.DB.prepare("UPDATE managed_workspaces SET purge_after=? WHERE status='deleted' AND (purge_after IS NULL OR purge_after>?) AND platform IN (SELECT id FROM platforms WHERE removing_at IS NOT NULL AND removed_at IS NULL)").bind(now, now).run()
}

const REMOVED_SLUG_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"

// `removed-` and 24 characters of 5 random bits each: 120 bits, within the
// slug's rules (40 characters at most, a letter first, no double hyphen).
export function removedPlatformSlug(): string {
  return REMOVED_PLATFORM_SLUG_PREFIX + Array.from(crypto.getRandomValues(new Uint8Array(24)), (byte) => REMOVED_SLUG_ALPHABET[byte & 31]).join("")
}

export async function freeRemovedSlugs(env: Env, now: number): Promise<void> {
  const due = await env.DB.prepare("SELECT p.id FROM platforms p WHERE p.removing_at IS NOT NULL AND p.removed_at IS NULL AND p.status='retired' AND NOT EXISTS (SELECT 1 FROM managed_workspaces w WHERE w.platform=p.id AND w.status!='purged')").all<{ id: string }>()
  for (const { id } of due.results) {
    try {
      await env.DB.batch([
        env.DB.prepare("UPDATE platforms SET removed_slug=slug,slug=?,removed_at=? WHERE id=? AND removed_at IS NULL AND status='retired' AND NOT EXISTS (SELECT 1 FROM managed_workspaces w WHERE w.platform=platforms.id AND w.status!='purged')").bind(removedPlatformSlug(), now, id),
        env.DB.prepare("INSERT INTO platform_events (id,platform,at,actor,action,detail) SELECT ?,id,?,'system','platform.removed',json_object('slug',removed_slug) FROM platforms WHERE id=? AND changes()>0").bind(randomId("pev"), now, id),
      ])
    } catch {
      logFailure("platform.sweep.remove", id)
    }
  }
}

export async function rollUpPlatformActivity(env: Env, now: number): Promise<void> {
  const platforms = await env.DB.prepare("SELECT id FROM platforms WHERE status!='retired'").all<{ id: string }>()
  for (const { id } of platforms.results) {
    try {
      const activity = await env.PLATFORM_VAULT.getByName(id).activity(now - DAY_MS)
      await env.DB.prepare("INSERT INTO platform_events (id,platform,at,actor,action,detail) VALUES (?,?,?,'system','platform.activity',?) ON CONFLICT (id) DO UPDATE SET at=excluded.at,detail=excluded.detail")
        .bind(activityEventId(id), id, now, JSON.stringify(activity.routes))
        .run()
    } catch {
      logFailure("platform.sweep.activity", id)
    }
  }
}

export async function maintainPlatforms(env: Env, now = Date.now()): Promise<void> {
  const tasks: [string, () => Promise<void>][] = [
    ["retiring", () => sweepRetiringPlatforms(env, now)],
    ["creating", () => sweepCreatingSubjects(env, now)],
    ["deleting", () => sweepDeletingSubjects(env, now)],
    ["removing", () => expediteRemovedPurges(env, now)],
    ["purging", () => sweepDueSubjectPurges(env, now)],
    ["removed", () => freeRemovedSlugs(env, now)],
    ["activity", () => rollUpPlatformActivity(env, now)],
  ]
  for (const [task, run] of tasks) {
    try {
      await run()
    } catch {
      console.error(JSON.stringify({ at: "platform.maintenance", task }))
    }
  }
}
