// D1 on bun:sqlite: prepare, bind, first, all, run, raw and batch, with D1's
// result shapes, and the migrations directory applied in order at start.

import { Database, type SQLQueryBindings } from "bun:sqlite"

type Meta = { changes: number; last_row_id: number; duration: number; rows_read: number; rows_written: number; changed_db: boolean; size_after: number }
type Result<T> = { results: T[]; success: true; meta: Meta }

function binding(value: unknown): SQLQueryBindings {
  if (value instanceof ArrayBuffer) return new Uint8Array(value)
  if (value === undefined) throw new Error("D1_TYPE_ERROR: Type 'undefined' not supported for value 'undefined'")
  if (typeof value === "boolean") return value ? 1 : 0
  return value as SQLQueryBindings
}

function column(value: unknown): unknown {
  if (value instanceof Uint8Array) return Array.from(value)
  return value
}

export class LocalD1Statement {
  private readonly db: Database
  readonly query: string
  private readonly values: SQLQueryBindings[]

  constructor(db: Database, query: string, values: SQLQueryBindings[] = []) {
    this.db = db
    this.query = query
    this.values = values
  }

  bind(...values: unknown[]): LocalD1Statement {
    return new LocalD1Statement(this.db, this.query, values.map(binding))
  }

  private rows(): { rows: Record<string, unknown>[]; columns: string[]; changes: number; lastId: number } {
    const before = (this.db.query("SELECT total_changes() AS n").get() as { n: number }).n
    const statement = this.db.prepare(this.query)
    try {
      const columns = statement.columnNames
      const rows = columns.length > 0 ? (statement.all(...this.values) as Record<string, unknown>[]) : (statement.run(...this.values), [])
      const after = (this.db.query("SELECT total_changes() AS n, last_insert_rowid() AS id").get() as { n: number; id: number })
      const shaped = rows.map((row) => Object.fromEntries(Object.entries(row).map(([k, v]) => [k, column(v)])))
      return { rows: shaped, columns, changes: after.n - before, lastId: after.id }
    } finally {
      statement.finalize()
    }
  }

  private meta(changes: number, lastId: number, read: number): Meta {
    return { changes, last_row_id: lastId, duration: 0, rows_read: read, rows_written: changes, changed_db: changes > 0, size_after: 0 }
  }

  async first<T = Record<string, unknown>>(columnName?: string): Promise<T | null> {
    const { rows } = this.rows()
    const row = rows[0]
    if (row === undefined) return null
    if (columnName !== undefined) {
      if (!(columnName in row)) throw new Error(`D1_COLUMN_NOTFOUND: Column not found (${columnName})`)
      return row[columnName] as T
    }
    return row as T
  }

  async all<T = Record<string, unknown>>(): Promise<Result<T>> {
    return this.allSync<T>()
  }

  allSync<T>(): Result<T> {
    const { rows, changes, lastId } = this.rows()
    return { results: rows as T[], success: true, meta: this.meta(changes, lastId, rows.length) }
  }

  async run<T = Record<string, unknown>>(): Promise<Result<T>> {
    return this.allSync<T>()
  }

  async raw<T = unknown[]>(options?: { columnNames?: boolean }): Promise<T[]> {
    const { rows, columns } = this.rows()
    const values = rows.map((row) => columns.map((name) => row[name])) as T[]
    return options?.columnNames ? [columns as T, ...values] : values
  }
}

export class LocalD1 {
  readonly db: Database

  constructor(path: string) {
    this.db = new Database(path, { create: true, strict: false })
    this.db.run("PRAGMA journal_mode = WAL")
    this.db.run("PRAGMA foreign_keys = ON")
  }

  prepare(query: string): LocalD1Statement {
    return new LocalD1Statement(this.db, query)
  }

  async batch<T = Record<string, unknown>>(statements: LocalD1Statement[]): Promise<Result<T>[]> {
    return this.db.transaction(() => statements.map((s) => s.allSync<T>()))()
  }

  async exec(query: string): Promise<{ count: number; duration: number }> {
    this.db.run(query)
    return { count: 1, duration: 0 }
  }

  migrate(migrations: { name: string; sql: string }[]): string[] {
    this.db.run("CREATE TABLE IF NOT EXISTS d1_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
    const done = new Set((this.db.query("SELECT name FROM d1_migrations").all() as { name: string }[]).map((r) => r.name))
    const applied: string[] = []
    for (const { name, sql } of migrations) {
      if (done.has(name)) continue
      this.db.transaction(() => {
        this.db.run(sql)
        this.db.run("INSERT INTO d1_migrations (name) VALUES (?)", [name])
      })()
      applied.push(name)
    }
    return applied
  }
}
