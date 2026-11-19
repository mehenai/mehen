// The operator's backup of this workspace object (docs/OPERATIONS.md, Backup
// and recovery). System calls only: the directory's cron dumps every table
// to VAULT_BACKUPS once a day and carries out the restores the operator
// script records (directory/vault-backups.ts). No member, device or platform
// reaches these ops.
//
// A dump is every table in sqlite_master but Cloudflare's own (_migrations
// and the generation marker included) as NDJSON, BLOBs in base64, gzipped,
// then sealed under the tenant's backup key for the current root version.
// Slugs, members and the audit are stored in the clear in the object, so the
// whole dump is encrypted, not only the already sealed secret fields.

import { z } from "zod"
import { backupAad, concatBytes, deriveBackupKey, fromUtf8, openBackup, sealBackup, utf8 } from "@mehen/protocol"
import { VaultError } from "../../http.ts"
import { WORKSPACE_GENERATION } from "../../directory/workspace-cutover.ts"
import type { Area, VaultContext } from "../core.ts"
import { parseRootKeys } from "../keys.ts"
import { setSetting, setting } from "./workspace-runtime.ts"
import { GUARD_PREFIX, withTrustedSchema } from "./management-guard.ts"

const OBJECT_FORMAT = "mehen-vault-backup/v1"
const DUMP_FORMAT = "mehen-vault-dump/v1"
// A dump is built whole in this object's memory (128 MB) several times over,
// so a workspace whose storage is larger is refused rather than reset.
export const MAX_DUMP_DATABASE_BYTES = 32 * 1024 * 1024
// A sealed dump is gzipped NDJSON: an object at a dump's key larger than
// twice the storage limit cannot be one, and is not read.
const MAX_STORED_DUMP_BYTES = 2 * MAX_DUMP_DATABASE_BYTES
// Cloudflare's DO point-in-time recovery reaches back 30 days.
export const PITR_WINDOW_MS = 30 * 86_400_000

export const BackupDateSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}$/).refine((date) => !Number.isNaN(Date.parse(`${date}T00:00:00Z`)) && new Date(`${date}T00:00:00Z`).toISOString().startsWith(date), "Not a calendar date.")
export const RestoreIntentIdSchema = z.string().regex(/^vri_[a-f0-9]{32}$/)

export function utcDate(at: number): string {
  return new Date(at).toISOString().slice(0, 10)
}
export function backupObjectKey(tenant: string, date: string): string {
  return `ws/${tenant}/${date}.bin`
}
// The first of each month is kept a year under its own prefix; the daily
// keys expire after 35 days (the bucket's lifecycle rules).
export function monthlyObjectKey(tenant: string, date: string): string {
  return `monthly/ws/${tenant}/${date.slice(0, 7)}.bin`
}

export async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (b) => b.toString(16).padStart(2, "0")).join("")
}

const ObjectHeaderSchema = z.strictObject({ format: z.literal(OBJECT_FORMAT), tenant: z.string().min(1), date: BackupDateSchema, rootVersion: z.number().int().positive() })
type ObjectHeader = z.infer<typeof ObjectHeaderSchema>

// The R2 object: one cleartext JSON line naming what opens it, then the sealed dump.
export function parseBackupObject(bytes: Uint8Array<ArrayBuffer>): { header: ObjectHeader; sealed: Uint8Array<ArrayBuffer> } {
  const end = bytes.subarray(0, 512).indexOf(0x0a)
  const header = end < 0 ? null : ObjectHeaderSchema.safeParse((() => { try { return JSON.parse(fromUtf8(bytes.slice(0, end))) as unknown } catch { return null } })())
  if (!header?.success) throw new VaultError("conflict", "That backup is not a Mehen vault backup.")
  return { header: header.data, sealed: bytes.slice(end + 1) }
}

const ValueSchema = z.union([z.string(), z.number(), z.null(), z.strictObject({ b64: z.string() })])
const SchemaEntrySchema = z.strictObject({ type: z.enum(["table", "index", "trigger", "view"]), name: z.string(), tbl_name: z.string(), sql: z.string() })
const DumpHeaderSchema = z.strictObject({ format: z.literal(DUMP_FORMAT), tenant: z.string(), date: BackupDateSchema, createdAt: z.number() })
const DumpLineSchema = z.union([z.strictObject({ schema: SchemaEntrySchema }), z.strictObject({ table: z.string(), columns: z.array(z.string()) }), z.strictObject({ row: z.array(ValueSchema) })])
type SchemaEntry = z.infer<typeof SchemaEntrySchema>
type DumpTable = { name: string; columns: string[]; rows: z.infer<typeof ValueSchema>[][] }
export type VaultDump = { header: z.infer<typeof DumpHeaderSchema>; schema: SchemaEntry[]; tables: DumpTable[] }

const NAME = /^[A-Za-z_][A-Za-z0-9_]*$/
function quoted(name: string): string {
  if (!NAME.test(name)) throw new Error("unexpected table or column name")
  return `"${name}"`
}

function base64(bytes: Uint8Array): string {
  let text = ""
  for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(text)
}
function unbase64(text: string): ArrayBuffer {
  const raw = atob(text)
  const out = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i)
  return out.buffer
}

// Application schema in creation order: tables, then their indexes and
// triggers as the migrations made them. Never SQLite's or Cloudflare's own,
// nor the management guard's tables and triggers, which every start puts
// back and a restore installs after its rows (management-guard.ts).
const OWN_SCHEMA = (entry: SchemaEntry): boolean => entry.name.startsWith(GUARD_PREFIX) || entry.tbl_name.startsWith(GUARD_PREFIX)
function schemaEntries(sql: SqlStorage): SchemaEntry[] {
  return sql.exec<SchemaEntry>("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*' AND tbl_name NOT GLOB '_cf_*' ORDER BY rowid").toArray().filter((entry) => !OWN_SCHEMA(entry))
}

// Synchronous from the first read to the last, so no other call interleaves
// and the dump is one consistent state of the object.
export function serialiseVault(ctx: VaultContext, date: string): Uint8Array<ArrayBuffer> {
  const schema = schemaEntries(ctx.sql)
  const lines = [JSON.stringify({ format: DUMP_FORMAT, tenant: ctx.tenant, date, createdAt: ctx.now() })]
  for (const entry of schema) lines.push(JSON.stringify({ schema: entry }))
  for (const table of schema.filter((entry) => entry.type === "table")) {
    const cursor = ctx.sql.exec(`SELECT * FROM ${quoted(table.name)}`)
    lines.push(JSON.stringify({ table: table.name, columns: cursor.columnNames }))
    for (const row of cursor.raw()) lines.push(JSON.stringify({ row: row.map((value) => value instanceof ArrayBuffer ? { b64: base64(new Uint8Array(value)) } : value) }))
  }
  return utf8(`${lines.join("\n")}\n`)
}

export function parseVaultDump(text: string): VaultDump {
  const [first, ...rest] = text.split("\n").filter((line) => line.length > 0)
  const header = DumpHeaderSchema.parse(JSON.parse(first ?? "null"))
  const schema: SchemaEntry[] = [], tables: DumpTable[] = []
  for (const line of rest) {
    const parsed = DumpLineSchema.parse(JSON.parse(line))
    if ("schema" in parsed) schema.push(parsed.schema)
    else if ("table" in parsed) tables.push({ name: parsed.table, columns: parsed.columns, rows: [] })
    else {
      const table = tables.at(-1)
      if (!table || parsed.row.length !== table.columns.length) throw new Error("row outside its table")
      table.rows.push(parsed.row)
    }
  }
  return { header, schema, tables }
}

async function through(bytes: Uint8Array<ArrayBuffer>, stream: CompressionStream | DecompressionStream): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(stream)).arrayBuffer())
}

async function backupKey(ctx: VaultContext, version: number): Promise<CryptoKey> {
  const root = parseRootKeys(ctx.env.ROOT_KEYS).versions.get(version)
  if (!root) throw new VaultError("conflict", `That backup needs root key version ${version}, which this deploy does not have.`)
  return deriveBackupKey(await root, ctx.tenant)
}

export async function sealVaultDump(ctx: VaultContext, date: string, plaintext: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const rootVersion = parseRootKeys(ctx.env.ROOT_KEYS).current
  const sealed = await sealBackup(await backupKey(ctx, rootVersion), backupAad(ctx.tenant, date, rootVersion), await through(plaintext, new CompressionStream("gzip")))
  return concatBytes(utf8(`${JSON.stringify({ format: OBJECT_FORMAT, tenant: ctx.tenant, date, rootVersion })}\n`), sealed)
}

// Opens a dump with this object's own root keys: the operator never handles
// plaintext. Another tenant's dump fails here even with a forged header,
// because the key and the AAD both name the tenant.
export async function openVaultDump(ctx: VaultContext, date: string, bytes: Uint8Array<ArrayBuffer>): Promise<VaultDump> {
  const { header, sealed } = parseBackupObject(bytes)
  if (header.tenant !== ctx.tenant) throw new VaultError("conflict", "That backup is another workspace's.")
  if (header.date !== date) throw new VaultError("conflict", "That backup is from another date.")
  const key = await backupKey(ctx, header.rootVersion)
  let compressed: Uint8Array<ArrayBuffer>
  try {
    compressed = await openBackup(key, backupAad(ctx.tenant, date, header.rootVersion), sealed)
  } catch {
    throw new VaultError("conflict", "That backup does not open as this workspace's.")
  }
  const dump = parseVaultDump(fromUtf8(await through(compressed, new DecompressionStream("gzip"))))
  if (dump.header.tenant !== ctx.tenant || dump.header.date !== date) throw new VaultError("conflict", "That backup is another workspace's.")
  return dump
}

// Writes the bytes at a key that has none, or answers whether what is there
// is the same bytes. The bucket lock refuses an overwrite.
async function storedAs(bucket: R2Bucket, key: string, bytes: Uint8Array<ArrayBuffer>, sha256: string): Promise<boolean> {
  const existing = await bucket.get(key)
  if (!existing) { await bucket.put(key, bytes, { customMetadata: { sha256 } }); return true }
  if (existing.size !== bytes.length) { await existing.body.cancel(); return false }
  return await sha256Hex(new Uint8Array(await existing.arrayBuffer())) === sha256
}

export type DumpResult = { date: string; key: string; bytes: number; sha256: string; rootVersion: number }
// Something not a backup already holds the key: the lock keeps it there, so
// the run is recorded failed and the operator looks (docs/OPERATIONS.md).
export type DumpRefused = { date: string; key: string; refused: "backup_corrupt"; message: string }

// Today's UTC date only, and idempotent: an object already at today's key is
// answered as it is if it opens as this workspace's dump of today, so a
// retry after a lost reply never writes another, and a planted or damaged
// object is never recorded as a backup. An empty object is refused rather
// than dumped: a workspace the directory lists whose object has lost its
// data is an incident for the operator, and its earlier dumps are what a
// restore needs.
export async function dumpVault(ctx: VaultContext, date: string): Promise<DumpResult | DumpRefused> {
  if (date !== utcDate(ctx.now())) throw new VaultError("bad_request", "A dump is written only for today's UTC date.")
  const bucket = ctx.env.VAULT_BACKUPS
  const key = backupObjectKey(ctx.tenant, date)
  const existing = await bucket.get(key)
  let bytes: Uint8Array<ArrayBuffer>
  if (existing) {
    const corrupt: DumpRefused = { date, key, refused: "backup_corrupt", message: "The object already at today's key does not open as this workspace's dump of today; it is not a backup." }
    if (existing.size > MAX_STORED_DUMP_BYTES) { await existing.body.cancel(); return corrupt }
    bytes = new Uint8Array(await existing.arrayBuffer())
    try { await openVaultDump(ctx, date, bytes) } catch { return corrupt }
  } else {
    const size = ctx.sql.databaseSize
    if (size > MAX_DUMP_DATABASE_BYTES) throw new VaultError("too_large", `This workspace's storage is ${size} bytes, above the ${MAX_DUMP_DATABASE_BYTES}-byte limit for a dump; nothing was dumped.`)
    if (isEmpty(ctx)) throw new VaultError("conflict", "This workspace object is empty; nothing was dumped.")
    const plaintext = serialiseVault(ctx, date)
    try { bytes = await sealVaultDump(ctx, date, plaintext) } finally { plaintext.fill(0) }
  }
  const sha256 = await sha256Hex(bytes)
  if (!existing) await bucket.put(key, bytes, { customMetadata: { sha256 } })
  if (date.endsWith("-01") && !await storedAs(bucket, monthlyObjectKey(ctx.tenant, date), bytes, sha256)) {
    return { date, key: monthlyObjectKey(ctx.tenant, date), refused: "backup_corrupt", message: "The object already at this month's key is not this workspace's dump of the first; it is not a backup." }
  }
  return { date, key, bytes: bytes.length, sha256, rootVersion: parseBackupObject(bytes).header.rootVersion }
}

function applicationTables(ctx: VaultContext): string[] {
  return schemaEntries(ctx.sql).filter((entry) => entry.type === "table").map((entry) => entry.name)
}

// Empty apart from what every fresh object has: its migrations and its
// generation marker. Anything else is live data a dump would overwrite.
function isEmpty(ctx: VaultContext): boolean {
  return applicationTables(ctx).every((name) => name === "_migrations" || name === "_workspace_generation" || ctx.sql.exec(`SELECT 1 FROM ${quoted(name)} LIMIT 1`).toArray().length === 0)
}
function assertEmpty(ctx: VaultContext): void {
  if (!isEmpty(ctx)) throw new VaultError("conflict", "This workspace is not empty. A dump restores only into an empty object; restore to a point in time instead.")
}

function tableRows(dump: VaultDump, name: string): z.infer<typeof ValueSchema>[][] | null {
  return dump.tables.find((table) => table.name === name)?.rows ?? null
}

// The dump's generation must be this deploy's, and no area in it may be
// further on than this object's code: older areas are migrated forward when
// the object restarts.
function assertCompatible(ctx: VaultContext, dump: VaultDump): void {
  const generation = tableRows(dump, "_workspace_generation")
  if (generation?.length !== 1 || generation[0]?.[0] !== WORKSPACE_GENERATION) throw new VaultError("conflict", "That backup is from another workspace storage generation.")
  const current = new Map(ctx.sql.exec<{ area: string; applied: number }>("SELECT area, applied FROM _migrations").toArray().map((row) => [row.area, row.applied]))
  const migrations = dump.tables.find((table) => table.name === "_migrations")
  if (!migrations) throw new VaultError("conflict", "That backup has no migration record.")
  const area = migrations.columns.indexOf("area"), applied = migrations.columns.indexOf("applied")
  for (const row of migrations.rows) {
    const known = current.get(String(row[area]))
    if (known === undefined || typeof row[applied] !== "number" || row[applied] > known) throw new VaultError("conflict", "That backup was written by newer vault code than this deploy runs.")
  }
}

// Set once a restore is staged, until this object restarts: the restore takes
// effect only in the next session, and the audit is written there.
const awaitingRestart = new WeakSet<DurableObjectStorage>()
// Until then the object answers only vaultbackup.* (tenant-vault.ts): a
// write now would be lost to a point-in-time restore, or land on the restored
// tables before their migrations have run.
export function restoreAwaitingRestart(storage: DurableObjectStorage): boolean {
  return awaitingRestart.has(storage)
}

export const RestoreStagedSchema = z.discriminatedUnion("source", [
  z.strictObject({ source: z.literal("dump"), date: z.string(), tables: z.number().int(), rows: z.number().int() }),
  z.strictObject({ source: z.literal("pitr"), at: z.string(), bookmark: z.string(), undoBookmark: z.string() }),
])
export type RestoreStaged = z.infer<typeof RestoreStagedSchema>

// The intent this object last staged and what it answered, written with the
// stage itself, so the cron asking again after a lost reply gets the same
// answer: a dump restore is not refused as "not empty", and a point-in-time
// one never takes a second undo bookmark (of the state already being left).
// A point-in-time restore rolls this record back with everything else, so
// the undo bookmark is also logged when it is taken.
const STAGED_KEY = "vault_restore_staged"
const StagedRecordSchema = z.strictObject({ intent: RestoreIntentIdSchema, staged: RestoreStagedSchema })
function stagedBefore(ctx: VaultContext, intent: string): RestoreStaged | null {
  const record = StagedRecordSchema.safeParse(setting<unknown>(ctx, STAGED_KEY, null))
  if (!record.success || record.data.intent !== intent) return null
  awaitingRestart.add(ctx.storage)
  return record.data.staged
}

export async function stageDumpRestore(ctx: VaultContext, intent: string, date: string): Promise<RestoreStaged> {
  const before = stagedBefore(ctx, intent)
  if (before) return before
  assertEmpty(ctx)
  const bucket = ctx.env.VAULT_BACKUPS
  const object = await bucket.get(backupObjectKey(ctx.tenant, date)) ?? (date.endsWith("-01") ? await bucket.get(monthlyObjectKey(ctx.tenant, date)) : null)
  if (!object) throw new VaultError("not_found", "There is no backup of this workspace for that date.")
  const dump = await openVaultDump(ctx, date, new Uint8Array(await object.arrayBuffer()))
  assertCompatible(ctx, dump)
  let rows = 0
  // The trusted sequence: in one transaction that may change the schema and
  // holds the management guard's marker, drop the tables, make the dump's
  // schema, write its rows, then install the guard's triggers and check
  // them; the marker goes as the transaction commits, and the next start
  // checks the triggers, recursive_triggers and an empty marker again.
  const staged = withTrustedSchema(ctx, (): RestoreStaged => {
    // Checked again: another call may have written while the dump was fetched.
    assertEmpty(ctx)
    ctx.sql.exec("PRAGMA defer_foreign_keys = ON")
    for (const name of applicationTables(ctx)) ctx.sql.exec(`DROP TABLE ${quoted(name)}`)
    for (const entry of dump.schema) if (!OWN_SCHEMA(entry)) ctx.sql.exec(entry.sql)
    // Tables in the order the migrations created them.
    for (const table of dump.tables) {
      const insert = `INSERT INTO ${quoted(table.name)} (${table.columns.map(quoted).join(", ")}) VALUES (${table.columns.map(() => "?").join(", ")})`
      for (const row of table.rows) {
        ctx.sql.exec(insert, ...row.map((value) => value !== null && typeof value === "object" ? unbase64(value.b64) : value))
        rows++
      }
    }
    const done: RestoreStaged = { source: "dump", date, tables: dump.tables.length, rows }
    setSetting(ctx, STAGED_KEY, { intent, staged: done })
    return done
  })
  const due = ctx.sql.exec<{ due: number | null }>("SELECT MIN(due_at) AS due FROM schedule").toArray()[0]?.due
  if (due !== null && due !== undefined) await ctx.storage.setAlarm(due)
  awaitingRestart.add(ctx.storage)
  return staged
}

export async function stagePointInTimeRestore(ctx: VaultContext, intent: string, at: string): Promise<RestoreStaged> {
  const before = stagedBefore(ctx, intent)
  if (before) return before
  const time = Date.parse(at), now = ctx.now()
  if (!(time < now && time >= now - PITR_WINDOW_MS)) throw new VaultError("bad_request", "A point-in-time restore reaches back at most 30 days, and not into the future.")
  const bookmark = await ctx.storage.getBookmarkForTime(time)
  const undoBookmark = await ctx.storage.onNextSessionRestoreBookmark(bookmark)
  console.log(JSON.stringify({ at: "vault.restore.staged", tenant: ctx.tenant, intent, bookmark, undoBookmark }))
  const staged: RestoreStaged = { source: "pitr", at, bookmark, undoBookmark }
  setSetting(ctx, STAGED_KEY, { intent, staged })
  awaitingRestart.add(ctx.storage)
  return staged
}

const RestoreInput = z.discriminatedUnion("source", [
  z.strictObject({ intent: RestoreIntentIdSchema, source: z.literal("dump"), date: BackupDateSchema }),
  z.strictObject({ intent: RestoreIntentIdSchema, source: z.literal("pitr"), at: z.iso.datetime({ offset: true }) }),
])
// The operator who recorded the intent, as scripts/vault-backup.ts names them.
const RestoreActorSchema = z.string().regex(/^operator:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/)
const RestoredInput = z.strictObject({ intent: RestoreIntentIdSchema, source: z.enum(["dump", "pitr"]), target: z.string().min(1).max(64), bookmark: z.string().max(512).nullable(), undoBookmark: z.string().max(512).nullable(), actor: RestoreActorSchema })

// After the restart: the restored object records where it came from on its
// own audit chain, once per intent, as the operator who asked for it.
export function recordRestore(ctx: VaultContext, input: z.infer<typeof RestoredInput>): { recorded: true } {
  if (awaitingRestart.has(ctx.storage)) throw new VaultError("conflict", "This workspace has not restarted since the restore was staged.")
  const done = ctx.sql.exec("SELECT 1 FROM audit WHERE action = 'system.restore' AND json_extract(detail, '$.intent') = ? LIMIT 1", input.intent).toArray().length > 0
  if (!done) ctx.audit({ actor: input.actor, action: "system.restore", target: null, detail: { intent: input.intent, source: input.source, target: input.target, bookmark: input.bookmark, undoBookmark: input.undoBookmark } })
  return { recorded: true }
}

export const vaultBackupOps: NonNullable<Area["workspaceOps"]> = {
  "vaultbackup.dump": { auth: ["system"], handler(ctx, _p, raw) {
    return dumpVault(ctx, z.strictObject({ date: BackupDateSchema }).parse(raw).date)
  } },
  "vaultbackup.restore": { auth: ["system"], handler(ctx, _p, raw) {
    const input = RestoreInput.parse(raw)
    return input.source === "dump" ? stageDumpRestore(ctx, input.intent, input.date) : stagePointInTimeRestore(ctx, input.intent, input.at)
  } },
  "vaultbackup.restart": { auth: ["system"], handler(ctx, _p, raw) {
    RestoreIntentIdSchema.parse(z.strictObject({ intent: z.string() }).parse(raw).intent)
    ctx.restart("vault restore")
    return { restarting: true }
  } },
  "vaultbackup.restored": { auth: ["system"], handler(ctx, _p, raw) {
    return recordRestore(ctx, RestoredInput.parse(raw))
  } },
}

export const vaultBackupArea: Area = { name: "vault-backup", migrations: [], workspaceOps: vaultBackupOps }
