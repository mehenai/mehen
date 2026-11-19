// The management guard: what must run before any write that can change who
// manages a credential's home (team membership, shares, a member made or
// their role, status or account changed, a credential made, deleted, moved
// or renamed, a team or project made, deleted, renamed or given another id):
// mandates lapse what expired shares took (settleShareExpiries) while access
// is still as it was.
//
// SQLite enforces it, not this code's reading of the SQL: triggers on the
// six graph tables abort an insert, a delete, or an update that changes a
// management column (MANAGEMENT_COLUMNS) unless the guard's marker row is in
// _mehen_guard. beforeManagementChange writes that row, only inside a
// synchronous transaction and only once the guards have run; the
// transaction wrapper (tenant-vault.ts) deletes it before the outermost
// transaction commits, and a rollback removes it with everything else.
// recursive_triggers is on, so rows a REPLACE deletes fire their triggers
// too. What triggers cannot stop (DROP TABLE, DROP TRIGGER and other schema
// statements, PRAGMA, EXPLAIN, transaction control) the SQL wrapper refuses
// outside migrations and restores (assertPlainStatement), and the triggers are checked, and put back, every
// time the object starts (installGuardTriggers). docs/OPERATIONS.md, The
// management guard.

import { VaultError } from "../../http.ts"
import type { VaultContext } from "../core.ts"

type ManagementGuard = (ctx: VaultContext) => void
const managementGuards = new Map<string, ManagementGuard>()
export function registerManagementGuard(name: string, guard: ManagementGuard): void { managementGuards.set(name, guard) }
// Test support only: clears the guards and hands back a restore.
export function isolateManagementGuardsForTests(): () => void {
  const saved = new Map(managementGuards)
  managementGuards.clear()
  return () => { managementGuards.clear(); for (const [name, guard] of saved) managementGuards.set(name, guard) }
}

export const GUARD_TABLE = "_mehen_guard"
export const REVISION_TABLE = "_mehen_revision"
// The guard's own tables and triggers: never dumped, restored or counted as
// data (vault-backup.ts).
export const GUARD_PREFIX = "_mehen_"
export const MANAGEMENT_GUARD_ERROR = "management_guard"

export const GRAPH_TABLES = ["items", "team_members", "project_shares", "members", "teams", "projects"] as const
export type GraphTable = (typeof GRAPH_TABLES)[number]
// The columns whose change is a change to who manages what: an update that
// changes any of them takes the guard. Ids and slugs among them, since a
// REPLACE on a unique one deletes another row. Every column of
// team_members and project_shares.
export const MANAGEMENT_COLUMNS: Readonly<Record<GraphTable, readonly string[]>> = {
  items: ["id", "slug", "home_kind", "home_id"],
  team_members: ["team", "member", "role"],
  project_shares: ["id", "project", "subject_kind", "subject_id", "value"],
  members: ["id", "account", "role", "status"],
  teams: ["id", "slug"],
  projects: ["id", "slug"],
}
// Every other column: none decides who manages a credential's home
// (effectiveAccess, managesHome). The two lists together are exactly the
// columns the migrations make, which management-guard.test.ts checks.
export const NEUTRAL_COLUMNS: Readonly<Record<GraphTable, readonly string[]>> = {
  items: ["kind", "provider", "account", "account_verified", "tags", "ceiling", "binding", "policy", "injection", "public_fields", "status", "status_reason", "version", "description", "created_at", "updated_at", "rotated_at", "last_used_at", "review_reason", "review_at", "config_rev", "dependency_revision", "browser", "pushable", "custom_provider"],
  team_members: [],
  project_shares: [],
  members: ["name", "pending_role", "pending_since", "gate_generation", "joined_at", "revision", "invite", "check_sequence", "pending_action", "pending_by"],
  teams: ["name", "created_by", "created_at"],
  projects: ["default_env", "created_by", "created_at", "updated_at", "revision"],
}

// One object's synchronous transactions, keyed by its storage, which every
// context of the object shares: how deep the current one is, whether the
// schema may change (migrations, restores), and whether the guard's tables
// are there (a deleteAll removes them until the object starts again).
type Scope = { depth: number; trusted: number; ready: boolean }
const scopes = new WeakMap<object, Scope>()
// The guard's own SQL for each object, unchecked: the storage wrapper
// (tenant-vault.ts) hands it over and nothing else may reach it. The checked
// SQL refuses any statement that names the guard's tables.
const guardSqls = new WeakMap<object, SqlStorage>()
export function registerGuardSql(storage: object, sql: SqlStorage): void {
  if (guardSqls.has(storage)) throw new Error("The management guard's SQL is registered once per object.")
  guardSqls.set(storage, sql)
}
function guardSql(storage: object): SqlStorage {
  const sql = guardSqls.get(storage)
  if (!sql) throw new VaultError("internal", "The management guard has no SQL for this object.")
  return sql
}
export function managementScope(storage: object): Scope {
  let scope = scopes.get(storage)
  if (!scope) scopes.set(storage, (scope = { depth: 0, trusted: 0, ready: false }))
  return scope
}

// Runs every guard, then writes the marker the triggers look for, inside the
// current synchronous transaction, which removes it before it commits.
export function beforeManagementChange(ctx: VaultContext): void {
  const scope = managementScope(ctx.storage)
  if (scope.depth === 0) throw new VaultError("internal", "The management guard runs only inside a synchronous transaction.")
  for (const guard of managementGuards.values()) guard(ctx)
  guardSql(ctx.storage).exec(`INSERT OR IGNORE INTO ${GUARD_TABLE}(id) VALUES (1)`)
}

// What the vault's checked SQL runs, statement by statement: only reads and
// row changes. Everything else (schema statements, PRAGMA and EXPLAIN, which
// applies a flag pragma while it is prepared, transaction control, ATTACH,
// VACUUM, ANALYZE, a statement with no readable first keyword) runs only in
// a migration, a restore or the guard's own start, and transaction control
// only inside the storage implementation.
const PLAIN_KEYWORDS: ReadonlySet<string> = new Set(["select", "insert", "update", "delete", "replace", "with"])
// The first keyword of each statement in a query: comments become space,
// string literals and quoted names a placeholder that is no keyword.
export function firstKeywords(query: string): string[] {
  const blanked = query.replace(/--[^\n]*|\/\*[\s\S]*?(?:\*\/|$)|'(?:[^']|'')*'|"(?:[^"]|"")*"|`[^`]*`|\[[^\]]*\]/g, (match) => (match.startsWith("--") || match.startsWith("/*") ? " " : " ? "))
  return blanked.split(";").filter((statement) => statement.trim() !== "").map((statement) => /^\s*([A-Za-z]+)/.exec(statement)?.[1]?.toLowerCase() ?? "?")
}
// Refuses, failing closed: a statement that names the guard's own tables,
// anywhere in its text and whatever the scope; and, outside a migration or
// restore, a statement that is not a plain read or row change.
export function assertPlainStatement(storage: object, query: string): void {
  if (query.toLowerCase().includes(GUARD_PREFIX)) throw new VaultError("internal", "The management guard's own tables are reached only through the guard.")
  if (managementScope(storage).trusted > 0) return
  const word = firstKeywords(query).find((keyword) => !PLAIN_KEYWORDS.has(keyword))
  if (word !== undefined) throw new VaultError("internal", `A ${word === "?" ? "statement without a readable keyword" : `${word.toUpperCase()} statement`} runs only in a migration or a restore.`)
}
// Runs a restore's own statements with schema changes allowed, inside a
// transaction, with the guard's marker held for the rows it writes, and
// puts the guard's triggers back on whatever schema it leaves.
export function withTrustedSchema<T>(ctx: VaultContext, run: () => T): T {
  const scope = managementScope(ctx.storage)
  scope.trusted++
  try {
    return ctx.storage.transactionSync(() => {
      const own = guardSql(ctx.storage)
      own.exec(`INSERT OR IGNORE INTO ${GUARD_TABLE}(id) VALUES (1)`)
      // A trigger naming a column keeps that column from being dropped.
      for (const { name } of own.exec<{ name: string }>(`SELECT name FROM sqlite_master WHERE type='trigger' AND name GLOB '${GUARD_PREFIX}*'`).toArray()) own.exec(`DROP TRIGGER ${quote(name)}`)
      const result = run()
      installGuardTriggers(own)
      return result
    })
  } finally {
    scope.trusted--
  }
}

const quote = (name: string): string => `"${name.replaceAll('"', '""')}"`
const UNGUARDED = `NOT EXISTS (SELECT 1 FROM ${GUARD_TABLE})`
const ABORT = `BEGIN SELECT RAISE(ABORT, '${MANAGEMENT_GUARD_ERROR}'); END`
// Every trigger the guard expects, by name, for the tables there are: the
// guard's on the graph tables, and the revision's on every table, which the
// access-state memo is stamped with (workspace-runtime.ts accessState).
export function expectedGuardTriggers(tables: readonly string[]): Map<string, string> {
  const triggers = new Map<string, string>()
  for (const table of GRAPH_TABLES) {
    if (!tables.includes(table)) continue
    const changed = MANAGEMENT_COLUMNS[table].map((column) => `OLD.${quote(column)} IS NOT NEW.${quote(column)}`).join(" OR ")
    triggers.set(`${GUARD_PREFIX}guard_${table}_insert`, `CREATE TRIGGER ${GUARD_PREFIX}guard_${table}_insert BEFORE INSERT ON ${quote(table)} WHEN ${UNGUARDED} ${ABORT}`)
    triggers.set(`${GUARD_PREFIX}guard_${table}_delete`, `CREATE TRIGGER ${GUARD_PREFIX}guard_${table}_delete BEFORE DELETE ON ${quote(table)} WHEN ${UNGUARDED} ${ABORT}`)
    triggers.set(`${GUARD_PREFIX}guard_${table}_update`, `CREATE TRIGGER ${GUARD_PREFIX}guard_${table}_update BEFORE UPDATE ON ${quote(table)} WHEN (${changed}) AND ${UNGUARDED} ${ABORT}`)
  }
  for (const table of tables) {
    for (const op of ["insert", "update", "delete"]) {
      const name = `${GUARD_PREFIX}revision_${table}_${op}`
      triggers.set(name, `CREATE TRIGGER ${quote(name)} AFTER ${op.toUpperCase()} ON ${quote(table)} BEGIN UPDATE ${REVISION_TABLE} SET n=n+1 WHERE id=1; END`)
    }
  }
  return triggers
}
// The tables triggers go on: every application table, never SQLite's,
// Cloudflare's or the guard's own.
function guardedTables(sql: SqlStorage): string[] {
  return sql.exec<{ name: string }>(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*' AND name NOT GLOB '${GUARD_PREFIX}*'`).toArray().map((row) => row.name)
}

// The guard's tables, made once and kept.
export function installGuardTables(sql: SqlStorage): void {
  sql.exec(`CREATE TABLE IF NOT EXISTS ${GUARD_TABLE}(id INTEGER PRIMARY KEY CHECK (id = 1))`)
  sql.exec(`CREATE TABLE IF NOT EXISTS ${REVISION_TABLE}(id INTEGER PRIMARY KEY CHECK (id = 1), n INTEGER NOT NULL)`)
  sql.exec(`INSERT OR IGNORE INTO ${REVISION_TABLE}(id, n) VALUES (1, 0)`)
}
// recursive_triggers on and read back: without it a row a REPLACE deletes
// would not fire its delete trigger.
export function enableRecursiveTriggers(sql: SqlStorage): void {
  sql.exec("PRAGMA recursive_triggers = ON")
  const on = sql.exec<{ recursive_triggers: number }>("PRAGMA recursive_triggers").toArray()[0]?.recursive_triggers
  if (on !== 1) throw new Error("recursive_triggers did not turn on")
}
// The expected triggers that are missing or not as expected, on an object.
export function missingGuardTriggers(ctx: Pick<VaultContext, "storage">): string[] {
  return missingTriggers(guardSql(ctx.storage))
}
function missingTriggers(sql: SqlStorage): string[] {
  const expected = expectedGuardTriggers(guardedTables(sql))
  const present = new Map(sql.exec<{ name: string; sql: string }>(`SELECT name, sql FROM sqlite_master WHERE type='trigger' AND name GLOB '${GUARD_PREFIX}*'`).toArray().map((row) => [row.name, row.sql]))
  return [...expected].filter(([name, text]) => present.get(name) !== text).map(([name]) => name)
}
// Puts back every guard trigger that is missing or changed, drops ones for
// tables or columns that are gone, and checks the result. Run at start-up
// after the migrations, and by a restore after its rows.
export function installGuardTriggers(sql: SqlStorage): void {
  const expected = expectedGuardTriggers(guardedTables(sql))
  const present = new Map(sql.exec<{ name: string; sql: string }>(`SELECT name, sql FROM sqlite_master WHERE type='trigger' AND name GLOB '${GUARD_PREFIX}*'`).toArray().map((row) => [row.name, row.sql]))
  for (const [name, text] of present) if (expected.get(name) !== text) sql.exec(`DROP TRIGGER IF EXISTS ${quote(name)}`)
  for (const [name, text] of expected) if (present.get(name) !== text) sql.exec(text)
  const missing = missingTriggers(sql)
  if (missing.length > 0) throw new Error(`The management guard's triggers did not install: ${missing.join(", ")}`)
}

// A marker left behind, which no transaction should ever do: removed, and
// written to the audit. Checked at start-up and at every request outside a
// transaction. True when one was found.
export function clearLeftoverMarker(ctx: VaultContext): boolean {
  const scope = managementScope(ctx.storage)
  if (!scope.ready || scope.depth > 0) return false
  const own = guardSql(ctx.storage)
  if (own.exec(`SELECT 1 FROM ${GUARD_TABLE} LIMIT 1`).toArray().length === 0) return false
  own.exec(`DELETE FROM ${GUARD_TABLE}`)
  console.error(JSON.stringify({ at: "management_guard", error: "leftover_marker" }))
  ctx.audit({ actor: "system", action: "management_guard.leftover", target: ctx.tenant })
  return true
}
// The access revision the revision triggers keep (VaultContext.accessRevision).
export function accessRevisionOf(storage: object): number {
  return guardSql(storage).exec<{ n: number }>(`SELECT n FROM ${REVISION_TABLE} WHERE id=1`).toArray()[0]?.n ?? 0
}
// Test support only, through the guard's own SQL: the marker rows there are,
// and one planted where no transaction holds it.
export function guardMarkersForTests(ctx: Pick<VaultContext, "storage">): number {
  return guardSql(ctx.storage).exec(`SELECT 1 FROM ${GUARD_TABLE}`).toArray().length
}
export function plantGuardMarkerForTests(ctx: Pick<VaultContext, "storage">): void {
  guardSql(ctx.storage).exec(`INSERT OR IGNORE INTO ${GUARD_TABLE}(id) VALUES (1)`)
}
export function dropGuardTriggerForTests(ctx: Pick<VaultContext, "storage">, name: string): void {
  guardSql(ctx.storage).exec(`DROP TRIGGER ${quote(name)}`)
}
