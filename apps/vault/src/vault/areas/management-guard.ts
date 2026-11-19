// What must run before any write that can change who manages a credential's
// home (team membership, shares, a member made or their role or status, a
// credential made, deleted or moved, a team or project deleted): mandates
// lapse what expired shares took (settleShareExpiries) while access is
// still as it was. Its own module, with no imports but types and the error,
// so any area may call it without an import cycle.
//
// The guarantee is the vault's SQL itself: the workspace vault's `sql.exec`
// (tenant-vault.ts, which the Worker and the local edition both run) hands
// every statement to assertManagementWrite, which throws for a statement
// that writes the management graph unless beforeManagementChange marked the
// synchronous transaction it runs in. The mark lasts until that transaction
// ends, by returning or throwing, and a graph write outside a transaction
// is refused. Nothing switches it off.

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

// One object's synchronous transactions: how deep the current one is
// nested, and whether the guards ran in it. Keyed by the object's storage,
// which every context of the object shares.
type Scope = { depth: number; settled: boolean }
const scopes = new WeakMap<object, Scope>()
const scopeOf = (storage: object): Scope => {
  let scope = scopes.get(storage)
  if (!scope) scopes.set(storage, (scope = { depth: 0, settled: false }))
  return scope
}
// Runs a synchronous transaction as the management scope: entered before it
// starts, the mark cleared when the outermost one ends, and on any throw,
// since a nested one that threw rolled back what the guards wrote in it.
export function inManagementScope<T>(storage: object, run: () => T): T {
  const scope = scopeOf(storage)
  scope.depth++
  try {
    return run()
  } catch (error) {
    scope.settled = false
    throw error
  } finally {
    scope.depth--
    if (scope.depth === 0) scope.settled = false
  }
}

// Runs every guard and marks the current transaction as settled.
export function beforeManagementChange(ctx: VaultContext): void {
  for (const guard of managementGuards.values()) guard(ctx)
  const scope = scopeOf(ctx.storage)
  if (scope.depth > 0) scope.settled = true
}

const GRAPH_TABLES = ["items", "team_members", "project_shares", "members", "teams", "projects"] as const
type GraphTable = (typeof GRAPH_TABLES)[number]
// Rows made or deleted here change who manages what; teams and projects
// are made empty, so only their deletion counts.
const INSERTED: ReadonlySet<string> = new Set<GraphTable>(["items", "team_members", "project_shares", "members"])
const DELETED: ReadonlySet<string> = new Set<GraphTable>(GRAPH_TABLES)
// The columns an update may set without being a graph write: none of them
// decides who manages a credential's home (effectiveAccess, managesHome).
// Every other column of these tables, and every column of team_members and
// project_shares, is a graph write.
export const MANAGEMENT_NEUTRAL_COLUMNS: Readonly<Record<GraphTable, readonly string[]>> = {
  items: ["kind", "provider", "account", "account_verified", "tags", "ceiling", "binding", "policy", "injection", "public_fields", "description", "status", "status_reason", "version", "config_rev", "dependency_revision", "updated_at", "rotated_at", "last_used_at", "review_reason", "review_at", "custom_provider", "browser", "pushable"],
  members: ["name", "revision", "check_sequence", "gate_generation", "invite", "pending_role", "pending_since", "pending_action", "pending_by"],
  teams: ["name", "slug"],
  projects: ["slug", "default_env", "revision", "updated_at"],
  team_members: [],
  project_shares: [],
}

// The statements in a query as SQLite reads them for this purpose: comments
// and string literals blanked, identifier quotes dropped, a schema prefix
// dropped, case folded, whitespace collapsed, split at semicolons.
function statementsOf(query: string): string[] {
  const blanked = query
    .replace(/--[^\n]*|\/\*[\s\S]*?\*\//g, " ")
    .replace(/'(?:[^']|'')*'/g, "?")
    .replace(/["`[\]]/g, "")
    .toLowerCase()
    .replace(/\b(main|temp)\./g, "")
    .replace(/\s+/g, " ")
  return blanked.split(";").map((s) => s.trim()).filter((s) => s !== "")
}
// The columns a SET clause assigns, tuple assignments `(a,b)=(?,?)`
// included, a column qualified by its table counted by its own name.
function assignedColumns(set: string): string[] {
  const parts: string[] = []
  let depth = 0, start = 0
  for (let i = 0; i < set.length; i++) {
    const c = set[i]
    if (c === "(") depth++
    else if (c === ")") depth--
    else if (c === "," && depth === 0) { parts.push(set.slice(start, i)); start = i + 1 }
  }
  parts.push(set.slice(start))
  return parts.flatMap((part) => {
    const lhs = part.split("=")[0]?.trim() ?? ""
    return lhs.replace(/^\(|\)$/g, "").split(",").map((column) => column.trim().split(".").at(-1) ?? "")
  })
}
const TABLE = String.raw`(${GRAPH_TABLES.join("|")})\b`
const INSERT_INTO = new RegExp(String.raw`\b(?:insert(?: or \w+)?|replace) into ${TABLE}`, "g")
const DELETE_FROM = new RegExp(String.raw`\bdelete from ${TABLE}`, "g")
const UPDATE_SET = new RegExp(String.raw`\bupdate(?: or \w+)? ${TABLE}(?: as \w+)? set (.*?)(?= where | returning | from |$)`, "g")

// Why a query writes the management graph, or null when it does not.
export function managementWrite(query: string): string | null {
  for (const statement of statementsOf(query)) {
    for (const [, table] of statement.matchAll(INSERT_INTO)) if (table && INSERTED.has(table)) return `insert into ${table}`
    for (const [, table] of statement.matchAll(DELETE_FROM)) if (table && DELETED.has(table)) return `delete from ${table}`
    for (const [, table, set] of statement.matchAll(UPDATE_SET)) {
      const neutral = MANAGEMENT_NEUTRAL_COLUMNS[table as GraphTable]
      const columns = assignedColumns(set ?? "")
      const moving = columns.filter((column) => !neutral.includes(column))
      if (moving.length > 0 || columns.length === 0) return `update of ${table} (${moving.join(", ") || "unreadable"})`
    }
  }
  return null
}

// Throws for a statement that writes the management graph outside a
// transaction the guards marked.
export function assertManagementWrite(storage: object, query: string): void {
  const write = managementWrite(query)
  if (write === null) return
  const scope = scopes.get(storage)
  if (scope && scope.depth > 0 && scope.settled) return
  throw new VaultError("internal", `A ${write} ran without the management guard (beforeManagementChange) in its transaction.`)
}
