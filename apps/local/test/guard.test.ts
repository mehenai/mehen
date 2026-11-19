// The vault's management guard on the local edition's storage (bun:sqlite):
// what a statement through the vault's own SQL may do. The guard itself is
// apps/vault/src/vault/areas/management-guard.ts; these drive a real
// WorkspaceVault object, as `mehen serve` runs it.

import { afterEach, describe, expect, test } from "bun:test"
import { mkdtempSync, readFileSync, rmSync } from "node:fs"
import { homedir, tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { WorkspaceVault } from "mehen-local:vault"
import { Database } from "bun:sqlite"
import { LocalObjectId, LocalObjectState, LocalStorage } from "../src/durable-objects.ts"

type Cursor = { toArray(): Record<string, unknown>[] }
type Sql = { exec(query: string, ...bindings: unknown[]): Cursor }
type Context = { sql: Sql; storage: { transactionSync<T>(run: () => T): T } }
type Guard = { beforeManagementChange(ctx: Context): void }

// The guard module the vault's own bundle loads, by path, so it is the same
// module instance and this package's typecheck never enters the vault's.
const GUARD = resolve(import.meta.dir, "../../vault/src/vault/areas/management-guard.ts")
const guard = (await import(GUARD)) as Guard

const base = process.env.TMPDIR && process.env.TMPDIR !== "/tmp" ? tmpdir() : join(homedir(), ".cache")
const made: string[] = []
const dbs: Database[] = []
const latest = (): Database => dbs.at(-1) as Database
afterEach(() => {
  for (const db of dbs.splice(0)) db.close()
  for (const dir of made.splice(0)) rmSync(dir, { recursive: true, force: true })
})

// A workspace object with one project share in it, made under the guard,
// opened on the local edition's storage as LocalNamespace opens one.
function workspace(): Context {
  const dir = mkdtempSync(join(base, "mehen-guard-"))
  made.push(dir)
  const db = new Database(join(dir, "object.sqlite"), { create: true, strict: false })
  dbs.push(db)
  db.run("PRAGMA foreign_keys = ON")
  db.run("PRAGMA recursive_triggers = ON")
  const alarms = { read: () => null, write: () => undefined, clear: () => undefined }
  const storage = new LocalStorage(db, alarms as never, () => undefined)
  const state = new LocalObjectState(new LocalObjectId("tn_guardtest0001"), storage, () => undefined)
  const ctx = (new WorkspaceVault(state, {}) as unknown as { context: Context }).context
  ctx.storage.transactionSync(() => {
    guard.beforeManagementChange(ctx)
    ctx.sql.exec("INSERT INTO project_shares(id,project,subject_kind,subject_id,value) VALUES ('shr_1','prj_1','member','mem_1','{}')")
  })
  return ctx
}
const refusal = (run: () => unknown): string | null => {
  try { run(); return null } catch (error) { return error instanceof Error ? error.message : String(error) }
}
const unmarkedWrite = (ctx: Context) => refusal(() => ctx.storage.transactionSync(() => ctx.sql.exec("UPDATE project_shares SET value='{\"changed\":true}' WHERE id='shr_1'")))
const value = (ctx: Context) => ctx.sql.exec("SELECT value FROM project_shares WHERE id='shr_1'").toArray()[0]?.value

describe("the management guard on the local edition", () => {
  test("refuses an unmarked graph write", () => {
    const ctx = workspace()
    expect(unmarkedWrite(ctx)).toContain("management_guard")
    expect(value(ctx)).toBe("{}")
  })

  // The sixth review's first repro: a flag pragma under EXPLAIN is applied
  // while the statement is prepared. This SQLite refuses writable_schema in
  // any form, but recursive_triggers goes off.
  test("refuses EXPLAIN PRAGMA, so no flag pragma changes and the triggers stay", () => {
    const ctx = workspace()
    for (const query of ["EXPLAIN PRAGMA recursive_triggers = OFF", "EXPLAIN PRAGMA writable_schema = ON"]) expect([query, refusal(() => ctx.sql.exec(query).toArray())]).toEqual([query, expect.stringMatching(/runs only in a migration or a restore/)])
    expect(latest().query("PRAGMA recursive_triggers").get()).toEqual({ recursive_triggers: 1 })
    refusal(() => ctx.sql.exec("DELETE FROM sqlite_master WHERE type='trigger' AND name GLOB '_mehen_*'"))
    refusal(() => ctx.sql.exec("EXPLAIN PRAGMA writable_schema = RESET"))
    expect(unmarkedWrite(ctx)).toContain("management_guard")
    expect(value(ctx)).toBe("{}")
  })

  // The second: COMMIT inside the callback ends the savepoint and keeps the
  // marker the guard took.
  test("refuses COMMIT inside a transaction, so the guard's marker never outlives it", () => {
    const ctx = workspace()
    const failed = refusal(() => ctx.storage.transactionSync(() => {
      guard.beforeManagementChange(ctx)
      ctx.sql.exec("COMMIT")
      throw new Error("after commit")
    }))
    expect(failed).toMatch(/runs only in a migration or a restore/)
    expect(unmarkedWrite(ctx)).toContain("management_guard")
    expect(value(ctx)).toBe("{}")
  })

  test.each([
    "EXPLAIN QUERY PLAN SELECT * FROM project_shares",
    "EXPLAIN SELECT 1",
    "BEGIN",
    "BEGIN IMMEDIATE",
    "COMMIT",
    "END",
    "ROLLBACK",
    "SAVEPOINT sneaky",
    "RELEASE sneaky",
    "ROLLBACK TO sneaky",
    "PRAGMA recursive_triggers = OFF",
    "ANALYZE",
    "SELECT 1; COMMIT",
  ])("refuses %s through the vault's SQL", (query) => {
    const ctx = workspace()
    expect(refusal(() => ctx.sql.exec(query))).toMatch(/runs only in a migration or a restore/)
    expect(unmarkedWrite(ctx)).toContain("management_guard")
  })

  test("a nested transaction that fails and is caught, and an outer callback that fails, leave no marker behind", () => {
    const ctx = workspace()
    ctx.storage.transactionSync(() => {
      guard.beforeManagementChange(ctx)
      expect(refusal(() => ctx.storage.transactionSync(() => { throw new Error("inner") }))).toBe("inner")
      ctx.sql.exec("UPDATE project_shares SET value='{\"marked\":true}' WHERE id='shr_1'")
    })
    expect(value(ctx)).toBe('{"marked":true}')
    expect(unmarkedWrite(ctx)).toContain("management_guard")
    expect(refusal(() => ctx.storage.transactionSync(() => { guard.beforeManagementChange(ctx); throw new Error("outer") }))).toBe("outer")
    expect(unmarkedWrite(ctx)).toContain("management_guard")
    expect(value(ctx)).toBe('{"marked":true}')
  })

  test("refuses any statement that names the guard's own tables", () => {
    const ctx = workspace()
    for (const query of ["INSERT INTO _mehen_guard(id) VALUES (1)", "UPDATE _mehen_revision SET n=0", "SELECT * FROM _MEHEN_GUARD", "DELETE FROM _mehen_guard"]) {
      expect([query, refusal(() => ctx.sql.exec(query))]).toEqual([query, expect.stringContaining("guard's own")])
    }
    expect(unmarkedWrite(ctx)).toContain("management_guard")
  })

  // The seventh review: a statement whose conflict algorithm is ROLLBACK
  // ends the native transaction while the guard's scope is still open.
  const ROLLBACKS = [
    "INSERT OR ROLLBACK INTO tenant_state(key,value) VALUES ('guard_rollback_probe','1'),('guard_rollback_probe','2')",
    "WITH v(k) AS (VALUES ('guard_rollback_probe')) INSERT OR ROLLBACK INTO tenant_state(key,value) SELECT k,'1' FROM v UNION ALL SELECT k,'2' FROM v",
    "UPDATE OR ROLLBACK tenant_state SET key='guard_probe_a' WHERE key IN ('guard_probe_a','guard_probe_b')",
    "insert /* a comment */ or\n  rollback into tenant_state(key,value) values ('x','1')",
  ]
  test.each(ROLLBACKS)("refuses %s, and no marker outlives the transaction", (query) => {
    const ctx = workspace()
    ctx.storage.transactionSync(() => {
      guard.beforeManagementChange(ctx)
      ctx.sql.exec("INSERT INTO tenant_state(key,value) VALUES ('guard_probe_a','1'),('guard_probe_b','2')")
    })
    const failed = refusal(() => ctx.storage.transactionSync(() => {
      guard.beforeManagementChange(ctx)
      try { ctx.sql.exec(query) } catch { /* caught, as a handler might */ }
      guard.beforeManagementChange(ctx)
      throw new Error("after rollback")
    }))
    expect(failed).toBe("after rollback")
    expect(refusal(() => ctx.sql.exec(query))).toMatch(/OR ROLLBACK/)
    expect(unmarkedWrite(ctx)).toContain("management_guard")
    expect(value(ctx)).toBe("{}")
  })

  test("leaves the vault's own literals and names that spell rollback alone", () => {
    const ctx = workspace()
    ctx.storage.transactionSync(() => {
      guard.beforeManagementChange(ctx)
      ctx.sql.exec("INSERT INTO tenant_state(key,value) VALUES ('or rollback', 'insert or rollback into') -- or rollback")
    })
    expect(ctx.sql.exec("SELECT value FROM tenant_state WHERE key='or rollback'").toArray()).toEqual([{ value: "insert or rollback into" }])
  })

  // The class, whatever ends the native transaction: here the test ends it
  // under the vault, as an engine error that rolls back would.
  test("a transaction that ended under the guard breaks its scope: no further statement or guard call, and no marker after it", () => {
    const ctx = workspace()
    const db = latest()
    const failed = refusal(() => ctx.storage.transactionSync(() => {
      guard.beforeManagementChange(ctx)
      db.run("ROLLBACK")
      expect(refusal(() => guard.beforeManagementChange(ctx))).toMatch(/transaction ended/)
      expect(refusal(() => ctx.sql.exec("SELECT 1"))).toMatch(/transaction ended/)
      expect(refusal(() => ctx.sql.exec("UPDATE project_shares SET value='{\"broken\":true}' WHERE id='shr_1'"))).toMatch(/transaction ended/)
    }))
    expect(failed).toMatch(/transaction ended/)
    expect(unmarkedWrite(ctx)).toContain("management_guard")
    expect(value(ctx)).toBe("{}")
  })

  test("a caught constraint failure leaves the transaction and the guard whole", () => {
    const ctx = workspace()
    ctx.storage.transactionSync(() => {
      guard.beforeManagementChange(ctx)
      expect(refusal(() => ctx.sql.exec("INSERT INTO tenant_state(key,value) VALUES ('dup','1'),('dup','2')"))).toMatch(/UNIQUE constraint failed/)
      guard.beforeManagementChange(ctx)
      ctx.sql.exec("UPDATE project_shares SET value='{\"after\":true}' WHERE id='shr_1'")
    })
    expect(value(ctx)).toBe('{"after":true}')
    expect(unmarkedWrite(ctx)).toContain("management_guard")
  })

  test("refuses load_extension", () => {
    const ctx = workspace()
    for (const query of ["SELECT load_extension('x')", "select LOAD_EXTENSION ('x', 'entry')"]) expect([query, refusal(() => ctx.sql.exec(query).toArray())]).toEqual([query, expect.stringContaining("load_extension")])
    // A quoted name is still the function. Bun's SQLite refuses it too, as
    // "not authorized" on Linux and "no such function" on macOS, where it is
    // built without it; the guard refuses it before SQLite sees it.
    for (const query of [`SELECT "load_extension"('x')`, "SELECT [load_extension]('x')", "SELECT `load_extension`('x')", `SELECT "LOAD_Extension"('x')`, "SELECT [Load_Extension] /* c */ ('x')", `SELECT "load_extension" -- c\n('x')`]) {
      expect([query, refusal(() => ctx.sql.exec(query).toArray())]).toEqual([query, "load_extension is never run."])
      expect([query, refusal(() => latest().query(query).all())]).toEqual([query, expect.stringMatching(/^(not authorized|no such function: load_extension)$/i)])
    }
    expect(ctx.sql.exec(`SELECT "upper"('x') AS v, 'load_extension(' AS w`).toArray()).toEqual([{ v: "X", w: "load_extension(" }])
  })

  // The raw database handle is a private field of the storage
  // implementation; nothing else names a storage's database.
  test("keeps the raw database handle inside the storage implementation", () => {
    const storage = new LocalStorage(new Database(":memory:"), { read: () => null, write: () => undefined, clear: () => undefined } as never, () => undefined)
    expect(Object.keys(storage)).not.toContain("db")
    expect((storage as unknown as Record<string, unknown>).db).toBeUndefined()
    const sources = [...new Bun.Glob("**/*.ts").scanSync(resolve(import.meta.dir, "../src"))].map((path) => `local/src/${path}`)
      .concat([...new Bun.Glob("**/*.ts").scanSync(resolve(import.meta.dir, "../../vault/src"))].map((path) => `vault/src/${path}`))
    const naming = sources.filter((path) => !path.endsWith(".test.ts") && /storage\??\.db\b|storage\[\s*["'`]db["'`]\s*\]/.test(readFileSync(resolve(import.meta.dir, "../..", path), "utf8")))
    expect(naming).toEqual([])
  })
})
