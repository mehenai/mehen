// Migration 0018 is additive: a fresh replay is idempotent, a populated 0017
// store keeps every account and event, the settings table refuses a change
// with no operator named, and the Audit view's reads use their indexes.
import { env } from "cloudflare:workers"
import { applyD1Migrations } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import { resetWorkspaceDatabase } from "./workspace-fixtures.ts"

const upTo17 = () => env.TEST_MIGRATIONS.filter((migration) => Number(migration.name.slice(0, 4)) <= 17)
const now = 1_800_000_000_000

async function columns(db: D1Database, table: string): Promise<string[]> {
  return (await db.prepare(`PRAGMA table_info(${table})`).all<{ name: string }>()).results.map((c) => c.name)
}

describe("migration 0018", () => {
  it("replays fresh twice and adds the deployment settings", async () => {
    const db = env.MIGRATION_DB
    await resetWorkspaceDatabase(db)
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    expect(await columns(db, "deployment_settings")).toEqual(["key", "value", "updated_at", "updated_by"])
  })

  it("keeps a populated 0017 store's accounts and events", async () => {
    const db = env.MIGRATION_DB
    await resetWorkspaceDatabase(db)
    await applyD1Migrations(db, upTo17())
    await db.batch([
      db.prepare("INSERT INTO accounts(id,name,status,created_at) VALUES ('acc_alex','alex','active',?)").bind(now),
      db.prepare("INSERT INTO account_events(id,account,at,action,detail) VALUES ('evt_1','acc_alex',?,'operator.grant_operator','{}')").bind(now),
      db.prepare("INSERT INTO deployment_events(id,at,kind,actor,target) VALUES ('dpe_1',?,'operator.grant','operator:alex','acc_alex')").bind(now),
    ])
    const before = await Promise.all(["accounts", "account_events", "deployment_events"].map(async (table) => (await db.prepare(`SELECT * FROM ${table} ORDER BY id`).all()).results))
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    expect(await Promise.all(["accounts", "account_events", "deployment_events"].map(async (table) => (await db.prepare(`SELECT * FROM ${table} ORDER BY id`).all()).results))).toEqual(before)
  })

  it("refuses a setting with no operator named, and keeps one row per key", async () => {
    const db = env.MIGRATION_DB
    await resetWorkspaceDatabase(db)
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    await expect(db.prepare("INSERT INTO deployment_settings(key,value,updated_at,updated_by) VALUES ('signup_mode','invite',?,'alex')").bind(now).run()).rejects.toThrow("CHECK constraint failed")
    await db.prepare("INSERT INTO deployment_settings(key,value,updated_at,updated_by) VALUES ('signup_mode','invite',?,'operator:alex')").bind(now).run()
    await expect(db.prepare("INSERT INTO deployment_settings(key,value,updated_at,updated_by) VALUES ('signup_mode','open',?,'operator:alex')").bind(now).run()).rejects.toThrow("UNIQUE constraint failed")
  })

  it("indexes platform events and the operator rows of account events by time", async () => {
    const db = env.MIGRATION_DB
    await resetWorkspaceDatabase(db)
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    const plan = async (sql: string) => JSON.stringify((await db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all()).results)
    expect(await plan("SELECT id FROM platform_events ORDER BY at DESC,id DESC LIMIT 51")).toContain("platform_events_at")
    expect(await plan("SELECT id FROM account_events WHERE action GLOB 'operator.*' ORDER BY at DESC,id DESC LIMIT 51")).toContain("account_events_operator")
  })
})
