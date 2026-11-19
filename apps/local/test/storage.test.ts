// The stand-ins hold to what the vault relies on from Cloudflare: deleteAll
// is all or nothing, an alarm survives a restart and is retried, a failed
// first open leaves nothing behind, and cursors read as SqlStorage's do.

import { afterEach, describe, expect, test } from "bun:test"
import { Database } from "bun:sqlite"
import { existsSync, mkdtempSync, rmSync } from "node:fs"
import { homedir, tmpdir } from "node:os"
import { join } from "node:path"
import { LocalNamespace, type LocalObjectState } from "../src/durable-objects.ts"
import { LocalSqlStorage, statementCount } from "../src/sql-storage.ts"

const base = process.env.TMPDIR && process.env.TMPDIR !== "/tmp" ? tmpdir() : join(homedir(), ".cache")
const made: string[] = []
const namespaces: LocalNamespace<object, object>[] = []
function scratch(): string {
  const dir = mkdtempSync(join(base, "mehen-storage-"))
  made.push(dir)
  return dir
}
afterEach(() => {
  for (const ns of namespaces.splice(0)) ns.close()
  for (const dir of made.splice(0)) rmSync(dir, { recursive: true, force: true })
})

class Counter {
  static fires: string[] = []
  static failFirst = 0
  readonly state: LocalObjectState
  constructor(state: LocalObjectState) {
    this.state = state
    state.storage.sql.exec("CREATE TABLE IF NOT EXISTS n (v INTEGER)")
  }
  async arm(at: number): Promise<void> {
    await this.state.storage.setAlarm(at)
  }
  async next(): Promise<number | null> {
    return this.state.storage.getAlarm()
  }
  async alarm(): Promise<void> {
    if (Counter.failFirst > 0) {
      Counter.failFirst--
      throw new Error("not yet")
    }
    Counter.fires.push(this.state.id.name)
  }
}

function namespace(dir: string, cls: new (state: LocalObjectState) => object = Counter): LocalNamespace<object, object> {
  const ns = new LocalNamespace<object, object>(dir, "Test", cls as never)
  ns.bind({})
  namespaces.push(ns)
  return ns
}

describe("alarms", () => {
  test("an alarm set before a restart fires after it", async () => {
    Counter.fires = []
    const dir = scratch()
    const first = namespace(dir)
    await (first.getByName("a") as unknown as Counter).arm(Date.now() + 150)
    first.close()
    const second = namespace(dir)
    expect(second.resumeAlarms()).toBe(1)
    await Bun.sleep(400)
    expect(Counter.fires).toEqual(["a"])
    expect(await (second.getByName("a") as unknown as Counter).next()).toBeNull()
  })

  test("a failing handler is retried, and the alarm is spent once it succeeds", async () => {
    Counter.fires = []
    Counter.failFirst = 1
    const ns = namespace(scratch())
    await (ns.getByName("b") as unknown as Counter).arm(Date.now())
    await Bun.sleep(150)
    expect(Counter.fires).toEqual([])
    expect(await (ns.getByName("b") as unknown as Counter).next()).not.toBeNull()
    await Bun.sleep(2300)
    expect(Counter.fires).toEqual(["b"])
    expect(await (ns.getByName("b") as unknown as Counter).next()).toBeNull()
  }, 10_000)
})

describe("deleteAll", () => {
  test("drops every table at once, references or not, and clears the alarm", async () => {
    class Linked {
      readonly state: LocalObjectState
      constructor(state: LocalObjectState) {
        this.state = state
        state.storage.sql.exec("CREATE TABLE IF NOT EXISTS early (v TEXT); CREATE TABLE IF NOT EXISTS parent (id TEXT PRIMARY KEY); CREATE TABLE IF NOT EXISTS child (p TEXT REFERENCES parent(id)); CREATE INDEX IF NOT EXISTS child_p ON child (p)")
      }
      async fill(): Promise<void> {
        this.state.storage.sql.exec("INSERT INTO early VALUES ('x')")
        this.state.storage.sql.exec("INSERT INTO parent VALUES ('p1')")
        this.state.storage.sql.exec("INSERT INTO child VALUES ('p1')")
        await this.state.storage.setAlarm(Date.now() + 60_000)
      }
      async wipe(): Promise<void> {
        await this.state.storage.deleteAll()
      }
      async tables(): Promise<string[]> {
        return this.state.storage.sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").toArray().map((r) => r.name)
      }
      async alarmAt(): Promise<number | null> {
        return this.state.storage.getAlarm()
      }
    }
    const ns = namespace(scratch(), Linked as never)
    const object = ns.getByName("linked") as unknown as Linked
    await object.fill()
    await object.wipe()
    expect(await object.tables()).toEqual([])
    expect(await object.alarmAt()).toBeNull()
  })
})

describe("the first open", () => {
  test("a constructor that throws leaves no half-made object, and the next open starts clean", async () => {
    let fail = true
    class Fragile {
      constructor(state: LocalObjectState) {
        state.storage.sql.exec("CREATE TABLE marker (v INTEGER)")
        if (fail) throw new Error("migration failed")
        state.storage.sql.exec("INSERT INTO marker VALUES (1)")
      }
      async count(): Promise<number> {
        return 0
      }
    }
    const dir = scratch()
    const ns = namespace(dir, Fragile as never)
    await expect((ns.getByName("f") as unknown as Fragile).count()).rejects.toThrow("migration failed")
    fail = false
    expect(await (ns.getByName("f") as unknown as Fragile).count()).toBe(0)
  })
})

describe("cursors", () => {
  const sql = () => {
    const db = new Database(":memory:")
    db.run("CREATE TABLE t (a INTEGER, b TEXT); INSERT INTO t VALUES (1, 'x'), (2, 'y'), (3, 'z')")
    return new LocalSqlStorage(db)
  }

  test("raw and toArray share one position", () => {
    const cursor = sql().exec<{ a: number; b: string }>("SELECT a, b FROM t ORDER BY a")
    expect(cursor.raw().next().value).toEqual([1, "x"])
    expect(cursor.toArray()).toEqual([{ a: 2, b: "y" }, { a: 3, b: "z" }])
  })

  test("raw keeps duplicate column names apart", () => {
    expect([...sql().exec("SELECT 1 AS x, 2 AS x").raw()]).toEqual([[1, 2]])
  })

  test("several statements with bindings are refused rather than run differently", () => {
    expect(() => sql().exec("INSERT INTO t VALUES (?, 'q'); SELECT * FROM t", 4)).toThrow(/one statement at a time/)
    expect(statementCount("CREATE TRIGGER tr AFTER INSERT ON t BEGIN UPDATE t SET b = 'a;b'; DELETE FROM t WHERE a = 0; END; SELECT 1")).toBe(2)
    expect(statementCount("SELECT ';' -- a; comment\n")).toBe(1)
  })
})

test("an object's database files stay where the namespace keeps them", () => {
  const dir = scratch()
  const ns = namespace(dir)
  void ns.getByName("files")
  expect(existsSync(join(dir, "objects", "Test"))).toBe(true)
})
