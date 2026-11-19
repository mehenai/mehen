// Durable Objects on one machine: one SQLite file per object, its alarm kept
// beside it so it survives a restart, and stubs whose calls cross a
// structured clone as Workers RPC does, so an error keeps its message and
// fields and loses its prototype.

import { Database } from "bun:sqlite"
import { createHash } from "node:crypto"
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { LocalSqlStorage, transactionSync } from "./sql-storage.ts"

type ObjectClass<E> = new (state: LocalObjectState, env: E) => object

// Cloudflare retries a failed alarm handler with backoff, up to six times.
export const ALARM_RETRIES = 6
const ALARM_FIRST_RETRY_MS = 2_000
const ALARM_FILE = ".alarm"

export class LocalObjectId {
  readonly name: string
  constructor(name: string) {
    this.name = name
  }
  toString(): string {
    return createHash("sha256").update(this.name).digest("hex")
  }
  equals(other: LocalObjectId): boolean {
    return other.name === this.name
  }
}

// An object's alarm: a timestamp in a file beside its database, so a restart
// finds it again. Writing it is a rename, so a crash leaves the old one or
// the new one.
class AlarmFile {
  private readonly path: string
  constructor(path: string) {
    this.path = path
  }
  read(): number | null {
    if (!existsSync(this.path)) return null
    const at = Number(readFileSync(this.path, "utf8").trim())
    return Number.isFinite(at) ? at : null
  }
  write(at: number): void {
    const temporary = `${this.path}.${process.pid}.tmp`
    writeFileSync(temporary, String(at), { mode: 0o600 })
    renameSync(temporary, this.path)
  }
  clear(): void {
    rmSync(this.path, { force: true })
  }
}

export class LocalStorage {
  readonly sql: LocalSqlStorage
  private timer: ReturnType<typeof setTimeout> | null = null
  readonly #db: Database
  private readonly alarmFile: AlarmFile
  private readonly fire: () => void

  constructor(db: Database, alarmFile: AlarmFile, fire: () => void) {
    this.#db = db
    this.sql = new LocalSqlStorage(db)
    this.alarmFile = alarmFile
    this.fire = fire
  }

  transactionSync<T>(closure: () => T): T {
    return transactionSync(this.#db, closure)
  }

  // Whether SQLite has a transaction open on this object's database: the
  // vault's management guard checks it rather than its own count, since a
  // statement can end a transaction under it.
  nativeTransaction(): boolean {
    return this.#db.inTransaction
  }

  // Everything at once, as Cloudflare's deleteAll is: every table, index,
  // view and trigger in one transaction, with foreign keys off so the order
  // never matters, and the alarm cleared only once the drop committed.
  async deleteAll(): Promise<void> {
    const objects = this.#db.query("SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'view', 'trigger')").all() as { type: string; name: string }[]
    this.#db.run("PRAGMA foreign_keys = OFF")
    try {
      this.#db.transaction(() => {
        for (const { type, name } of objects.filter((o) => o.type !== "table")) this.#db.run(`DROP ${type.toUpperCase()} IF EXISTS "${name.replaceAll('"', '""')}"`)
        for (const { name } of objects.filter((o) => o.type === "table")) this.#db.run(`DROP TABLE IF EXISTS "${name.replaceAll('"', '""')}"`)
      })()
    } finally {
      this.#db.run("PRAGMA foreign_keys = ON")
    }
    await this.deleteAlarm()
  }

  async getAlarm(): Promise<number | null> {
    return this.alarmFile.read()
  }

  async setAlarm(at: number | Date): Promise<void> {
    const when = typeof at === "number" ? at : at.getTime()
    this.alarmFile.write(when)
    this.arm(when)
  }

  async deleteAlarm(): Promise<void> {
    this.alarmFile.clear()
    this.disarm()
  }

  // The alarm is spent the moment its handler starts, as in a Durable
  // Object: the handler sees no alarm unless it sets a new one.
  consumeAlarm(): void {
    this.alarmFile.clear()
  }

  arm(when: number): void {
    this.disarm()
    this.timer = setTimeout(() => {
      this.timer = null
      this.fire()
    }, Math.max(0, when - Date.now()))
  }

  disarm(): void {
    if (this.timer) clearTimeout(this.timer)
    this.timer = null
  }

  async getBookmarkForTime(): Promise<string> {
    throw new Error("Point-in-time recovery is not available in a local vault; restore from a local backup instead.")
  }

  async onNextSessionRestoreBookmark(): Promise<string> {
    throw new Error("Point-in-time recovery is not available in a local vault; restore from a local backup instead.")
  }

  close(): void {
    this.disarm()
    this.#db.close()
  }
}

export class LocalObjectState {
  readonly id: LocalObjectId
  readonly storage: LocalStorage
  private readonly pending = new Set<Promise<unknown>>()
  private readonly aborted: (reason: unknown) => void

  constructor(id: LocalObjectId, storage: LocalStorage, aborted: (reason: unknown) => void) {
    this.id = id
    this.storage = storage
    this.aborted = aborted
  }

  waitUntil(promise: Promise<unknown>): void {
    this.pending.add(promise)
    void promise.catch(() => undefined).finally(() => this.pending.delete(promise))
  }

  async blockConcurrencyWhile<T>(closure: () => Promise<T>): Promise<T> {
    return closure()
  }

  abort(reason?: unknown): never {
    this.aborted(reason)
    throw new Error(`Durable Object reset: ${String(reason ?? "aborted")}`)
  }
}

function cloneAcross<T>(value: T): T {
  return value === undefined ? value : structuredClone(value)
}

function plainError(error: unknown): Error {
  if (!(error instanceof Error)) return new Error(String(error))
  const plain = new Error(error.message)
  plain.name = error.name
  for (const key of Object.keys(error)) (plain as unknown as Record<string, unknown>)[key] = cloneAcross((error as unknown as Record<string, unknown>)[key])
  return plain
}

type Live<C> = { instance: C; storage: LocalStorage; alarm: { running: boolean; again: boolean; attempts: number } }

export class LocalNamespace<E, C extends object> {
  private readonly live = new Map<string, Live<C>>()
  private readonly dir: string
  private readonly cls: ObjectClass<E>
  private env: E | null = null
  private closed = false

  constructor(dataDir: string, className: string, cls: ObjectClass<E>) {
    this.dir = join(dataDir, "objects", className)
    mkdirSync(this.dir, { recursive: true, mode: 0o700 })
    this.cls = cls
  }

  bind(env: E): void {
    this.env = env
  }

  // Every alarm left by an earlier run, armed again: an object whose alarm
  // is due is opened when it fires, as Cloudflare wakes it.
  resumeAlarms(): number {
    let armed = 0
    for (const file of readdirSync(this.dir).filter((f) => f.endsWith(`.sqlite${ALARM_FILE}`))) {
      const key = file.slice(0, -`.sqlite${ALARM_FILE}`.length)
      const nameFile = join(this.dir, `${key}.name`)
      if (!existsSync(nameFile)) continue
      const at = new AlarmFile(join(this.dir, file)).read()
      if (at === null) continue
      const id = new LocalObjectId(readFileSync(nameFile, "utf8"))
      if (id.toString() !== key) continue
      this.open(id).storage.arm(at)
      armed++
    }
    return armed
  }

  idFromName(name: string): LocalObjectId {
    return new LocalObjectId(name)
  }

  private open(id: LocalObjectId): Live<C> {
    const key = id.toString()
    const found = this.live.get(key)
    if (found) return found
    if (!this.env) throw new Error("namespace used before its env was bound")
    if (this.closed) throw new Error("the local vault is shutting down")
    const path = join(this.dir, `${key}.sqlite`)
    const nameFile = join(this.dir, `${key}.name`)
    if (!existsSync(nameFile)) writeFileSync(nameFile, id.name, { mode: 0o600 })
    const db = new Database(path, { create: true, strict: false })
    let entry: Live<C> | null = null
    const storage = new LocalStorage(db, new AlarmFile(`${path}${ALARM_FILE}`), () => void this.runAlarm(key))
    const state = new LocalObjectState(id, storage, () => {
      storage.close()
      this.live.delete(key)
    })
    try {
      db.run("PRAGMA journal_mode = WAL")
      db.run("PRAGMA foreign_keys = ON")
      // Rows a REPLACE deletes fire their delete triggers, the vault's
      // management guard's among them, as the Worker's object sets it too.
      db.run("PRAGMA recursive_triggers = ON")
      if ((db.query("PRAGMA recursive_triggers").get() as { recursive_triggers: number } | null)?.recursive_triggers !== 1) throw new Error("recursive_triggers did not turn on")
      // A new object's first writes (its migrations, its generation marker)
      // are one transaction, as Cloudflare commits a turn's writes together:
      // a crash part-way leaves the object as it was.
      db.run("BEGIN IMMEDIATE")
      const instance = new this.cls(state, this.env) as C
      db.run("COMMIT")
      entry = { instance, storage, alarm: { running: false, again: false, attempts: 0 } }
    } catch (error) {
      if (db.inTransaction) db.run("ROLLBACK")
      storage.close()
      throw error
    }
    this.live.set(key, entry)
    return entry
  }

  // One alarm at a time per object. A failure is retried with backoff, six
  // times, then given up as Cloudflare does; the alarm file stays until the
  // handler succeeds, so a restart tries again too.
  private async runAlarm(key: string): Promise<void> {
    const entry = this.live.get(key)
    if (!entry) return
    if (entry.alarm.running) {
      entry.alarm.again = true
      return
    }
    entry.alarm.running = true
    const target = entry.instance as { alarm?: () => Promise<void> }
    try {
      const due = await entry.storage.getAlarm()
      if (due !== null && due > Date.now()) {
        entry.storage.arm(due)
        return
      }
      entry.storage.consumeAlarm()
      await target.alarm?.()
      entry.alarm.attempts = 0
    } catch (error) {
      entry.alarm.attempts++
      console.error(JSON.stringify({ at: "local.alarm", attempt: entry.alarm.attempts, error: error instanceof Error ? error.message : String(error) }))
      if (entry.alarm.attempts <= ALARM_RETRIES && !this.closed) {
        const retry = Date.now() + ALARM_FIRST_RETRY_MS * 2 ** (entry.alarm.attempts - 1)
        await entry.storage.setAlarm(retry)
      } else entry.alarm.attempts = 0
    } finally {
      entry.alarm.running = false
      if (entry.alarm.again) {
        entry.alarm.again = false
        void this.runAlarm(key)
      }
    }
  }

  get(id: LocalObjectId): C {
    return new Proxy({} as C, {
      get: (_target, prop) => {
        if (prop === "then") return undefined
        if (prop === "id") return id
        return async (...args: unknown[]) => {
          const target = this.open(id).instance as Record<PropertyKey, unknown>
          const method = target[prop]
          if (typeof method !== "function") throw new Error(`The object has no method ${String(prop)}`)
          try {
            return cloneAcross(await (method as (...a: unknown[]) => unknown).apply(target, args.map(cloneAcross)))
          } catch (error) {
            throw plainError(error)
          }
        }
      },
    })
  }

  getByName(name: string): C {
    return this.get(this.idFromName(name))
  }

  close(): void {
    this.closed = true
    for (const { storage } of this.live.values()) storage.close()
    this.live.clear()
  }
}
