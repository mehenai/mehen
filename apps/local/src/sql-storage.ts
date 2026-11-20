// A Durable Object's SqlStorage on bun:sqlite: the same synchronous API,
// the same value types (BLOBs as ArrayBuffer), multi-statement migrations
// and rowsWritten, so the vault's areas run unchanged. A cursor is read
// once, as values in column order, so toArray, one and raw share one
// position and duplicate column names keep their own values in raw.

import { Database, type SQLQueryBindings } from "bun:sqlite"

type Value = ArrayBuffer | string | number | null
type Row = Record<string, Value>

const READS = /^\s*(SELECT|WITH|PRAGMA|EXPLAIN)\b/i

function toBinding(value: unknown): SQLQueryBindings {
  if (value instanceof ArrayBuffer) return new Uint8Array(value)
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  if (value === undefined) throw new TypeError("SQL binding is undefined")
  return value as SQLQueryBindings
}

function fromColumn(value: unknown): Value {
  if (value instanceof Uint8Array) return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer
  if (typeof value === "bigint") return Number(value)
  return value as Value
}

// How many statements a query holds, counting semicolons outside quotes,
// comments and CREATE TRIGGER bodies.
export function statementCount(query: string): number {
  let count = 0
  let pending = false
  let depth = 0
  const text = query
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string
    if (ch === "'" || ch === '"' || ch === "`") {
      const end = text.indexOf(ch, i + 1)
      i = end === -1 ? text.length : end
      pending = true
      continue
    }
    if (ch === "[") {
      const end = text.indexOf("]", i + 1)
      i = end === -1 ? text.length : end
      pending = true
      continue
    }
    if (ch === "-" && text[i + 1] === "-") {
      const end = text.indexOf("\n", i)
      i = end === -1 ? text.length : end
      continue
    }
    if (ch === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2)
      i = end === -1 ? text.length : end + 1
      continue
    }
    if (/\s/.test(ch)) continue
    const word = /^[A-Za-z]+/.exec(text.slice(i))?.[0]?.toUpperCase()
    if (word === "BEGIN" && /\bTRIGGER\b/i.test(text.slice(0, i).split(";").at(-1) ?? "")) depth++
    if (word === "END" && depth > 0) depth--
    if (word) {
      i += word.length - 1
      pending = true
      continue
    }
    if (ch === ";" && depth === 0) {
      if (pending) count++
      pending = false
      continue
    }
    pending = true
  }
  return pending ? count + 1 : count
}

export class LocalCursor<T extends Row = Row> implements Iterable<T> {
  readonly columnNames: string[]
  readonly rowsRead: number
  readonly rowsWritten: number
  private readonly values: Value[][]
  private index = 0

  constructor(values: Value[][], columnNames: string[], rowsWritten: number) {
    this.values = values
    this.columnNames = columnNames
    this.rowsRead = values.length
    this.rowsWritten = rowsWritten
  }

  private row(values: Value[]): T {
    const out: Row = {}
    this.columnNames.forEach((name, i) => {
      out[name] = values[i] as Value
    })
    return out as T
  }

  next(): IteratorResult<T> {
    if (this.index < this.values.length) return { done: false, value: this.row(this.values[this.index++] as Value[]) }
    return { done: true, value: undefined }
  }

  toArray(): T[] {
    const rest = this.values.slice(this.index).map((v) => this.row(v))
    this.index = this.values.length
    return rest
  }

  one(): T {
    const rest = this.toArray()
    if (rest.length !== 1) throw new Error(`Expected exactly one result from SQL query, but got ${rest.length === 0 ? "no" : "multiple"} results.`)
    return rest[0] as T
  }

  raw<R extends Value[] = Value[]>(): IterableIterator<R> {
    const cursor = this
    return {
      next(): IteratorResult<R> {
        if (cursor.index < cursor.values.length) return { done: false, value: [...(cursor.values[cursor.index++] as Value[])] as R }
        return { done: true, value: undefined }
      },
      toArray(): R[] {
        const rest = cursor.values.slice(cursor.index).map((v) => [...v] as R)
        cursor.index = cursor.values.length
        return rest
      },
      [Symbol.iterator]() {
        return this
      },
    } as IterableIterator<R>
  }

  [Symbol.iterator](): Iterator<T> {
    return { next: () => this.next() }
  }
}

export class LocalSqlStorage {
  readonly #db: Database

  constructor(db: Database) {
    this.#db = db
  }

  private totalChanges(): number {
    return (this.#db.query("SELECT total_changes() AS n").get() as { n: number }).n
  }

  exec<T extends Row = Row>(query: string, ...bindings: unknown[]): LocalCursor<T> {
    const before = this.totalChanges()
    const statements = statementCount(query)
    // A migration is several statements with no bindings and no rows.
    if (bindings.length === 0 && !READS.test(query) && !/\bRETURNING\b/i.test(query)) {
      this.#db.run(query)
      return new LocalCursor<T>([], [], this.totalChanges() - before)
    }
    // Cloudflare runs every statement and binds the last; nothing in the
    // vault needs that, so it is refused here rather than run differently.
    if (statements > 1) throw new Error("A local vault runs one statement at a time when it reads rows or takes bindings; split the query.")
    const statement = this.#db.prepare(query)
    try {
      const args = bindings.map(toBinding)
      if (statement.columnNames.length === 0) {
        statement.run(...args)
        return new LocalCursor<T>([], [], this.totalChanges() - before)
      }
      const values = (statement.values(...args) as unknown[][]).map((row) => row.map(fromColumn))
      return new LocalCursor<T>(values, statement.columnNames, this.totalChanges() - before)
    } finally {
      statement.finalize()
    }
  }

  get databaseSize(): number {
    const pages = this.#db.query("PRAGMA page_count").get() as { page_count: number }
    const size = this.#db.query("PRAGMA page_size").get() as { page_size: number }
    return pages.page_count * size.page_size
  }

  get Cursor(): typeof LocalCursor {
    return LocalCursor
  }

  get Statement(): undefined {
    return undefined
  }
}

let savepoints = 0

// transactionSync: a savepoint per call, so nested calls roll back only
// their own work, as in a Durable Object.
export function transactionSync<T>(db: Database, closure: () => T): T {
  const name = `mehen_tx_${++savepoints}`
  db.run(`SAVEPOINT ${name}`)
  try {
    const result = closure()
    db.run(`RELEASE ${name}`)
    return result
  } catch (error) {
    db.run(`ROLLBACK TO ${name}`)
    db.run(`RELEASE ${name}`)
    throw error
  }
}
