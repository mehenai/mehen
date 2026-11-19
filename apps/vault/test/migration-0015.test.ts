// Migration 0015 is additive: a fresh replay is idempotent, a populated 0014
// store keeps every account, and its CHECKs refuse an approval by the
// proposer and a proposal naming the proposer or the approver as its
// target, whatever writes the row, with one open proposal per kind and target.
import { env } from "cloudflare:workers"
import { applyD1Migrations } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import { resetWorkspaceDatabase } from "./workspace-fixtures.ts"

const upTo = (last: number) => env.TEST_MIGRATIONS.filter((migration) => Number(migration.name.slice(0, 4)) <= last)
const upTo14 = () => upTo(14)
const now = 1_800_000_000_000

async function columns(db: D1Database, table: string): Promise<string[]> {
  return (await db.prepare(`PRAGMA table_info(${table})`).all<{ name: string }>()).results.map((c) => c.name)
}

async function accounts(db: D1Database): Promise<void> {
  await db.batch(["acc_alex", "acc_tom", "acc_kim"].map((id) => db.prepare("INSERT INTO accounts(id,name,status,created_at) VALUES (?,?,'active',?)").bind(id, id.slice(4), now)))
}

function proposal(db: D1Database, row: { id: string; target: string; proposed_by: string; approved_by?: string; state?: string; kind?: string }): D1PreparedStatement {
  const approved = row.approved_by ?? null
  const state = row.state ?? "open"
  return db.prepare("INSERT INTO operator_proposals(id,kind,target,params,digest,proposed_by,proposed_at,expires_at,approved_by,approved_at,state,closed_at) VALUES (?,?,?,'{}','d',?,?,?,?,?,?,?)")
    .bind(row.id, row.kind ?? "operator.grant", row.target, row.proposed_by, now, now + 86_400_000, approved, approved === null ? null : now, state, state === "open" ? null : now)
}

describe("migration 0015", () => {
  it("replays fresh twice and adds the proposals and the deployment events", async () => {
    const db = env.MIGRATION_DB
    await resetWorkspaceDatabase(db)
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    expect(await columns(db, "operator_proposals")).toEqual(["id", "kind", "target", "params", "digest", "proposed_by", "proposed_at", "expires_at", "approved_by", "approved_at", "declined_by", "state", "closed_at"])
    expect(await columns(db, "deployment_events")).toEqual(["id", "at", "kind", "actor", "approver", "target", "details"])
  })

  it("keeps a populated 0014 store's accounts", async () => {
    const db = env.MIGRATION_DB
    await resetWorkspaceDatabase(db)
    await applyD1Migrations(db, upTo14())
    await accounts(db)
    const before = (await db.prepare("SELECT * FROM accounts ORDER BY id").all()).results
    await applyD1Migrations(db, upTo(15))
    expect((await db.prepare("SELECT * FROM accounts ORDER BY id").all()).results).toEqual(before)
  })

  it("refuses an approval by the proposer, a target that is the proposer or the approver, and a second open proposal of one kind and target", async () => {
    const db = env.MIGRATION_DB
    await resetWorkspaceDatabase(db)
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    await accounts(db)
    await expect(proposal(db, { id: "opp_self", target: "acc_kim", proposed_by: "acc_alex", approved_by: "acc_alex" }).run()).rejects.toThrow("CHECK constraint failed")
    await expect(proposal(db, { id: "opp_mine", target: "acc_alex", proposed_by: "acc_alex" }).run()).rejects.toThrow("CHECK constraint failed")
    await expect(proposal(db, { id: "opp_approver", target: "acc_tom", proposed_by: "acc_alex", approved_by: "acc_tom" }).run()).rejects.toThrow("CHECK constraint failed")
    await expect(proposal(db, { id: "opp_unapproved", target: "acc_kim", proposed_by: "acc_alex", state: "applied" }).run()).rejects.toThrow("CHECK constraint failed")
    await proposal(db, { id: "opp_one", target: "acc_kim", proposed_by: "acc_alex" }).run()
    await expect(proposal(db, { id: "opp_two", target: "acc_kim", proposed_by: "acc_tom" }).run()).rejects.toThrow("UNIQUE constraint failed")
    await expect(db.prepare("UPDATE operator_proposals SET approved_by='acc_alex',approved_at=? WHERE id='opp_one'").bind(now).run()).rejects.toThrow("CHECK constraint failed")
    await proposal(db, { id: "opp_revoke", kind: "operator.revoke", target: "acc_kim", proposed_by: "acc_tom" }).run()
    await proposal(db, { id: "opp_old", target: "acc_kim", proposed_by: "acc_tom", state: "expired" }).run()
    await expect(db.prepare("INSERT INTO deployment_events(id,at,kind,actor,target) VALUES ('dpe_x',?,'operator.grant','alex','acc_kim')").bind(now).run()).rejects.toThrow("CHECK constraint failed")
  })
})
