// Migration 0017 is additive: a fresh replay is idempotent, a populated 0015
// store keeps every account as it was, not suspended, and suspended_by
// names an operator or nothing, whatever writes the row.
import { env } from "cloudflare:workers"
import { applyD1Migrations } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import { resetWorkspaceDatabase } from "./workspace-fixtures.ts"

const upTo15 = () => env.TEST_MIGRATIONS.filter((migration) => Number(migration.name.slice(0, 4)) <= 15)
const now = 1_800_000_000_000

async function columns(db: D1Database): Promise<string[]> {
  return (await db.prepare("PRAGMA table_info(accounts)").all<{ name: string }>()).results.map((c) => c.name)
}

describe("migration 0017", () => {
  it("replays fresh twice and adds suspended_at and suspended_by to accounts", async () => {
    const db = env.MIGRATION_DB
    await resetWorkspaceDatabase(db)
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    expect((await columns(db)).slice(-2)).toEqual(["suspended_at", "suspended_by"])
  })

  it("keeps a populated 0015 store's accounts, none of them suspended", async () => {
    const db = env.MIGRATION_DB
    await resetWorkspaceDatabase(db)
    await applyD1Migrations(db, upTo15())
    await db.batch(["acc_alex", "acc_kim"].map((id) => db.prepare("INSERT INTO accounts(id,name,status,created_at) VALUES (?,?,'active',?)").bind(id, id.slice(4), now)))
    const before = (await db.prepare("SELECT * FROM accounts ORDER BY id").all()).results
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    expect((await db.prepare("SELECT * FROM accounts ORDER BY id").all()).results).toEqual(before.map((row) => ({ ...row, suspended_at: null, suspended_by: null })))
  })

  it("refuses a suspension by anything but an operator", async () => {
    const db = env.MIGRATION_DB
    await resetWorkspaceDatabase(db)
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    await db.prepare("INSERT INTO accounts(id,name,status,created_at) VALUES ('acc_kim','Kim','active',?)").bind(now).run()
    for (const by of ["admin:acc_x", "operator:", "system"]) await expect(db.prepare("UPDATE accounts SET suspended_at=?,suspended_by=? WHERE id='acc_kim'").bind(now, by).run()).rejects.toThrow(/CHECK/)
    await db.prepare("UPDATE accounts SET suspended_at=?,suspended_by='operator:acc_alex' WHERE id='acc_kim'").bind(now).run()
    expect(await db.prepare("SELECT suspended_at,suspended_by FROM accounts WHERE id='acc_kim'").first()).toEqual({ suspended_at: now, suspended_by: "operator:acc_alex" })
  })
})
