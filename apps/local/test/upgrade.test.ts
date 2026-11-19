// A local vault made by an earlier mehen opens under this one: the mandates
// area's newer migrations run on its existing database, and what a machine
// asked for starts from the held asks it already keeps.

import { afterEach, expect, test } from "bun:test"
import { Database } from "bun:sqlite"
import { mkdtempSync, rmSync } from "node:fs"
import { homedir, tmpdir } from "node:os"
import { join } from "node:path"
import { LocalSqlStorage, transactionSync } from "../src/sql-storage.ts"

// The engine's own migrations, loaded as the local host loads them (its
// entry first, for its module order), by path so the vault's Cloudflare
// types stay out of this package's typecheck.
type Area = { name: string; migrations: string[] }
type Sql = { exec(query: string, ...bindings: unknown[]): unknown }
const engine = (path: string) => new URL(`../../vault/src/${path}`, import.meta.url).pathname
await import(engine("index.ts"))
const { applyMigrations } = await import(engine("vault/tenant-vault.ts")) as { applyMigrations(sql: Sql, storage: { transactionSync<T>(fn: () => T): T }, areas: Area[]): void }
const { AREAS } = await import(engine("vault/registry.ts")) as { AREAS: Area[] }

const base = process.env.TMPDIR && process.env.TMPDIR !== "/tmp" ? tmpdir() : join(homedir(), ".cache")
const made: string[] = []
afterEach(() => { for (const dir of made.splice(0)) rmSync(dir, { recursive: true, force: true }) })

test("a workspace database from before the mandate asked table gains it, filled from the held asks it kept, and its proposals gain item_ids", () => {
  const dir = mkdtempSync(join(base, "mehen-upgrade-"))
  made.push(dir)
  const db = new Database(join(dir, "workspace.sqlite"))
  const sql = new LocalSqlStorage(db)
  const storage = { transactionSync: <T>(fn: () => T): T => transactionSync(db, fn) }
  // As an earlier mehen left it: every migration but this change's two.
  const mandatesArea = AREAS.find((area) => area.name === "mandates")
  expect(mandatesArea).toBeDefined()
  const before = AREAS.map((area) => (area === mandatesArea ? { ...area, migrations: area.migrations.slice(0, -2) } : area))
  applyMigrations(sql, storage, before)
  expect(db.query("SELECT name FROM sqlite_master WHERE name='mandate_asked'").all()).toEqual([])
  const now = Date.now()
  const approval = (id: string, status: string, decidedBy: string | null) => db.run(
    "INSERT INTO approvals(id,device,device_name,item,digest,subject,presentation,binding_code,status,created_at,expires_at,decided_by,ask) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
    [id, "dev_box", "box", "github-work", "d", "{}", "{}", "K7Q2", status, now, now + 3_600_000, decidedBy, JSON.stringify({ device: "dev_box", credential: "itm_github", credentials: ["itm_github"], context: null })],
  )
  approval("apr_open", "pending", null)
  approval("apr_denied", "denied", "mem_owner")
  db.run("INSERT INTO mandate_cover_asks(approval,device,classes,at) VALUES (?,?,?,?)", ["apr_open", "dev_box", JSON.stringify(["change", "send"]), now])
  db.run("INSERT INTO mandate_cover_asks(approval,device,classes,at) VALUES (?,?,?,?)", ["apr_denied", "dev_box", JSON.stringify(["delete"]), now])
  db.run("INSERT INTO mandate_proposals(id,device,terms,reason,created_at,expires_at) VALUES (?,?,?,?,?,?)", ["mdp_old", "dev_box", "{}", "Old", now, now + 1])
  applyMigrations(sql, storage, AREAS)
  // Each kept ask, by approval; a rejected one is copied too and left out
  // when the vault reads what the machine asked for.
  expect(db.query("SELECT approval,device,item_id,cls,at FROM mandate_asked ORDER BY approval,cls").all()).toEqual([
    { approval: "apr_denied", device: "dev_box", item_id: "itm_github", cls: "delete", at: now },
    { approval: "apr_open", device: "dev_box", item_id: "itm_github", cls: "change", at: now },
    { approval: "apr_open", device: "dev_box", item_id: "itm_github", cls: "send", at: now },
  ])
  expect(db.query("SELECT id,item_ids FROM mandate_proposals").all()).toEqual([{ id: "mdp_old", item_ids: null }])
  // Opening again changes nothing.
  applyMigrations(sql, storage, AREAS)
  expect(db.query("SELECT COUNT(*) AS n FROM mandate_asked").get()).toEqual({ n: 3 })
  db.close()
})
