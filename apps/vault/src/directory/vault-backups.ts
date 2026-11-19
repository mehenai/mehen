// The cron's side of the operator's backup (vault/areas/vault-backup.ts,
// docs/OPERATIONS.md, Backup and recovery), each part bounded and idempotent:
// - restores: each intent the operator script recorded is checked against
//   its digest in every state, staged in its workspace object, kept with
//   its bookmarks, and the object restarted; once it is back, the object
//   audits the restore;
// - backups: once a UTC day every active workspace dumps itself to
//   VAULT_BACKUPS, VAULT_BACKUP_BATCH a run, those not yet tried that day
//   first and, among them, those whose last good dump is oldest; each
//   outcome is kept in vault_backup_runs, one failure never stops the rest,
//   and a failed workspace is tried again on the next run, except one
//   refused as too_large, which waits for the next UTC day.

import { z } from "zod"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { invokeVault } from "../vault/client.ts"
import { PITR_WINDOW_MS, RestoreStagedSchema, utcDate, type DumpRefused, type DumpResult, type RestoreStaged } from "../vault/areas/vault-backup.ts"
import { redeliverAccountSecurity } from "./account-security.ts"
import { sha256Text } from "./session.ts"

// 96 runs a day: up to 4,800 workspaces dumped daily.
export const VAULT_BACKUP_BATCH = 50
const RESTORE_BATCH = 10
// An intent the object has not confirmed within this long stops blocking the
// workspace's next restore (one live intent a workspace).
export const RESTART_TIMEOUT_MS = 6 * 3_600_000

export type RestoreRequest = { intent: string; source: "dump"; date: string } | { intent: string; source: "pitr"; at: string }
export type RestoreRecord = { intent: string; source: "dump" | "pitr"; target: string; bookmark: string | null; undoBookmark: string | null; actor: string }
export type VaultBackupClient = {
  dump(tenant: string, date: string): Promise<DumpResult | DumpRefused>
  restore(tenant: string, input: RestoreRequest): Promise<RestoreStaged>
  restart(tenant: string, intent: string): Promise<void>
  restored(tenant: string, input: RestoreRecord): Promise<void>
}

const DumpResultSchema = z.union([
  z.strictObject({ date: z.string(), key: z.string(), bytes: z.number().int().positive(), sha256: z.string().regex(/^[0-9a-f]{64}$/), rootVersion: z.number().int().positive() }),
  z.strictObject({ date: z.string(), key: z.string(), refused: z.literal("backup_corrupt"), message: z.string().max(200) }),
])

export function vaultBackupClient(env: Env): VaultBackupClient {
  const system = (tenant: string, op: string, input: unknown) => invokeVault(env, tenant, { op, input, auth: { kind: "system", reason: "vault backup" } })
  return {
    dump: async (tenant, date) => DumpResultSchema.parse(await system(tenant, "vaultbackup.dump", { date })),
    restore: async (tenant, input) => RestoreStagedSchema.parse(await system(tenant, "vaultbackup.restore", input)),
    // The object's reset ends this call with an error; the next call reaches the restarted object.
    restart: async (tenant, intent) => { await system(tenant, "vaultbackup.restart", { intent }).catch(() => undefined) },
    restored: async (tenant, input) => { z.strictObject({ recorded: z.literal(true) }).parse(await system(tenant, "vaultbackup.restored", input)) },
  }
}

export type RestoreIntentFields = { id: string; tenant: string; source: "pitr" | "dump"; target: string; actor: string; createdAt: number }
// Every field the script wrote, as one unkeyed digest, checked in every
// state: an intent edited after it was recorded (a mistaken UPDATE, a
// half-applied statement) is refused. It is not a confirmation: anyone with
// D1 write access can compute it and record a valid restore of any
// workspace, so D1 write access is as powerful as the operator script.
export function restoreIntentDigest(intent: RestoreIntentFields): Promise<string> {
  return sha256Text(["mehen-restore/v1", intent.id, intent.tenant, intent.source, intent.target, intent.actor, String(intent.createdAt)].join("|"))
}

// The one row a restore records, built the same way by the operator script
// and by an approved workspace.restore proposal (operator-proposal-kinds.ts):
// a fresh id, created now, living an hour, every value checked so the
// script's SQL text (wrangler d1 execute takes no bound parameters) can
// carry nothing else.
export const RESTORE_INTENT_TTL_MS = 3_600_000
const RESTORE_INTENT_ID = /^vri_[a-f0-9]{32}$/
const RESTORE_TENANT = /^tn_[A-Za-z0-9]{8,40}$/
const RESTORE_ACTOR = /^operator:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/
const RESTORE_POINT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

function calendarDate(text: string): boolean {
  return /^\d{4}-\d{2}-\d{2}$/.test(text) && !Number.isNaN(Date.parse(`${text}T00:00:00Z`)) && new Date(`${text}T00:00:00Z`).toISOString().startsWith(text)
}

export function newRestoreIntent(fields: Omit<RestoreIntentFields, "id" | "createdAt">, now: number): RestoreIntentFields {
  return { id: `vri_${crypto.randomUUID().replaceAll("-", "")}`, tenant: fields.tenant, source: fields.source, target: fields.target, actor: fields.actor, createdAt: now }
}

export function assertRestoreIntent(intent: RestoreIntentFields, hash: string): void {
  const targetOk = intent.source === "dump" ? calendarDate(intent.target) : RESTORE_POINT.test(intent.target)
  if (!RESTORE_INTENT_ID.test(intent.id) || !RESTORE_TENANT.test(intent.tenant) || !RESTORE_ACTOR.test(intent.actor) || !targetOk || !/^[A-Za-z0-9_-]{43}$/.test(hash) || !Number.isSafeInteger(intent.createdAt) || intent.createdAt < 0) throw new Error("Invalid restore intent")
}

export function restoreIntentValues(intent: RestoreIntentFields, hash: string): [string, string, string, string, string, string, number, number] {
  assertRestoreIntent(intent, hash)
  return [intent.id, intent.tenant, intent.source, intent.target, intent.actor, hash, intent.createdAt, intent.createdAt + RESTORE_INTENT_TTL_MS]
}

export const RESTORE_INTENT_COLUMNS = "id,tenant,source,target,actor,intent_hash,created_at,expires_at"

export function restoreIntentInsert(env: Env, intent: RestoreIntentFields, hash: string): D1PreparedStatement {
  return env.DB.prepare(`INSERT INTO vault_restore_intents(${RESTORE_INTENT_COLUMNS}) VALUES (?,?,?,?,?,?,?,?)`).bind(...restoreIntentValues(intent, hash))
}

// A point in time a restore may reach: within the last 30 days, not ahead.
export function restorePointInWindow(target: string, now: number): boolean {
  const at = Date.parse(target)
  return at < now && at >= now - PITR_WINDOW_MS
}

function failure(error: unknown): string {
  return error instanceof VaultError ? `${error.code}: ${error.message}` : "error"
}

export async function backUpWorkspaceVaults(env: Env, client: VaultBackupClient = vaultBackupClient(env), now = Date.now()): Promise<void> {
  const date = utcDate(now)
  const due = await env.DB.prepare(`SELECT w.id FROM workspaces w LEFT JOIN vault_backup_runs r ON r.tenant=w.id AND r.date=?
    WHERE w.status='active' AND (r.outcome IS NULL OR (r.outcome='failed' AND r.error NOT LIKE 'too_large:%')) ORDER BY r.attempted_at IS NOT NULL, (SELECT MAX(o.date) FROM vault_backup_runs o WHERE o.tenant=w.id AND o.outcome='ok'), r.attempted_at, w.id LIMIT ?`).bind(date, VAULT_BACKUP_BATCH).all<{ id: string }>()
  for (const { id } of due.results) {
    const failed = (error: string) => env.DB.prepare(`INSERT INTO vault_backup_runs(tenant,date,outcome,error,attempts,attempted_at) VALUES (?,?,'failed',?,1,?)
      ON CONFLICT(tenant,date) DO UPDATE SET error=excluded.error,attempts=attempts+1,attempted_at=excluded.attempted_at WHERE outcome!='ok'`)
      .bind(id, date, error, now).run().catch(() => undefined)
    try {
      const result = await client.dump(id, date)
      if (result.date !== date) throw new Error("dump for another date")
      if ("refused" in result) {
        console.error(JSON.stringify({ at: "vault.backup.failed", tenant: id, error: result.refused }))
        await failed(`${result.refused}: ${result.message}`)
        continue
      }
      await env.DB.prepare(`INSERT INTO vault_backup_runs(tenant,date,outcome,bytes,sha256,root_version,error,attempts,attempted_at) VALUES (?,?,'ok',?,?,?,NULL,1,?)
        ON CONFLICT(tenant,date) DO UPDATE SET outcome='ok',bytes=excluded.bytes,sha256=excluded.sha256,root_version=excluded.root_version,error=NULL,attempts=attempts+1,attempted_at=excluded.attempted_at WHERE outcome!='ok'`)
        .bind(id, date, result.bytes, result.sha256, result.rootVersion, now).run()
    } catch (error) {
      console.error(JSON.stringify({ at: "vault.backup.failed", tenant: id, error: error instanceof VaultError ? error.code : "error" }))
      await failed(failure(error))
    }
  }
}

type IntentRow = { id: string; tenant: string; source: "pitr" | "dump"; target: string; actor: string; intent_hash: string; created_at: number; state: "pending" | "restarting"; bookmark: string | null; undo_bookmark: string | null }

export async function runVaultRestores(env: Env, client: VaultBackupClient = vaultBackupClient(env), now = Date.now()): Promise<void> {
  await env.DB.prepare("UPDATE vault_restore_intents SET state='expired' WHERE state='pending' AND expires_at<=?").bind(now).run()
  await env.DB.prepare("UPDATE vault_restore_intents SET state='failed',error='restart_timeout: the workspace did not confirm the restore within 6 hours; check it and its audit before recording another.',completed_at=? WHERE state='restarting' AND created_at<=?").bind(now, now - RESTART_TIMEOUT_MS).run()
  const intents = await env.DB.prepare("SELECT id,tenant,source,target,actor,intent_hash,created_at,state,bookmark,undo_bookmark FROM vault_restore_intents WHERE state IN ('pending','restarting') ORDER BY created_at LIMIT ?").bind(RESTORE_BATCH).all<IntentRow>()
  for (const intent of intents.results) {
    try { await advanceRestore(env, client, intent, now) } catch { console.error(JSON.stringify({ at: "vault.restore.pending", intent: intent.id })) }
  }
}

async function advanceRestore(env: Env, client: VaultBackupClient, intent: IntentRow, now: number): Promise<void> {
  const fail = (error: string) => env.DB.prepare("UPDATE vault_restore_intents SET state='failed',error=?,completed_at=? WHERE id=? AND state=?").bind(error, now, intent.id, intent.state).run()
  let { bookmark, undo_bookmark: undoBookmark } = intent
  const digest = await restoreIntentDigest({ id: intent.id, tenant: intent.tenant, source: intent.source, target: intent.target, actor: intent.actor, createdAt: intent.created_at })
  if (digest !== intent.intent_hash) { await fail("intent_changed: the intent no longer matches what was recorded."); return }
  if (intent.state === "pending") {
    let staged: RestoreStaged
    try {
      staged = await client.restore(intent.tenant, intent.source === "dump" ? { intent: intent.id, source: "dump", date: intent.target } : { intent: intent.id, source: "pitr", at: intent.target })
    } catch (error) {
      if (error instanceof VaultError) { await fail(failure(error)); return }
      throw error
    }
    bookmark = staged.source === "pitr" ? staged.bookmark : null
    undoBookmark = staged.source === "pitr" ? staged.undoBookmark : null
    await env.DB.prepare("UPDATE vault_restore_intents SET state='restarting',bookmark=?,undo_bookmark=? WHERE id=? AND state='pending'").bind(bookmark, undoBookmark, intent.id).run()
    await client.restart(intent.tenant, intent.id)
  }
  try {
    await client.restored(intent.tenant, { intent: intent.id, source: intent.source, target: intent.target, bookmark, undoBookmark, actor: intent.actor })
  } catch (error) {
    // Not restarted yet: ask again, and record it on a later run.
    if (error instanceof VaultError && error.code === "conflict") { await client.restart(intent.tenant, intent.id); return }
    throw error
  }
  await env.DB.batch([
    env.DB.prepare("UPDATE vault_restore_intents SET state='done',completed_at=? WHERE id=? AND state='restarting'").bind(now, intent.id),
    // A dump holds the object as it was some time on its UTC day: from that day's start.
    ...redeliverAccountSecurity(env, intent.tenant, Date.parse(intent.source === "dump" ? `${intent.target}T00:00:00.000Z` : intent.target)),
  ])
}
