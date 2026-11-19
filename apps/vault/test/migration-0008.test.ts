// Migration 0008 is additive: a fresh replay is idempotent, and a populated
// 0007 store keeps every row, with each pre-lease attempt's expiry as its
// hard cap, so no terminal time moves and nothing old becomes renewable.
import { env } from "cloudflare:workers"
import { applyD1Migrations } from "cloudflare:test"
import { createProof, jwkThumbprint, webCryptoSigner, type WorkspaceEnrolStatus } from "@mehen/protocol"
import { describe, expect, it } from "vitest"
import type { Env } from "../src/env.ts"
import { VaultError } from "../src/http.ts"
import { enrolmentLease } from "../src/directory/enrolment.ts"
import { renewWorkspaceEnrolment, workspaceEnrolmentStatus, type WorkspaceEnrolmentRow } from "../src/directory/workspace-enrolment.ts"
import { resetWorkspaceDatabase } from "./workspace-fixtures.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"

const upTo7 = () => env.TEST_MIGRATIONS.filter(migration => Number(migration.name.slice(0, 4)) <= 7)
const origin = "https://vault.test"
type Row = Record<string, string | number | null>
async function insert(db: D1Database, table: string, row: Row) { await db.prepare(`INSERT INTO ${table}(${Object.keys(row).join(",")}) VALUES (${Object.keys(row).map(() => "?").join(",")})`).bind(...Object.values(row)).run() }
async function columns(db: D1Database, table: string) { return (await db.prepare(`PRAGMA table_info(${table})`).all<{ name: string }>()).results.map(c => c.name) }
async function indexes(db: D1Database) { return (await db.prepare("SELECT name FROM sqlite_master WHERE type='index'").all<{ name: string }>()).results.map(i => i.name) }
async function pendingEnrolment(id: string, workspace: string, status: string, expiresAt: number, extra: Row = {}) {
  const keys = await newDeviceKey(), jwk = await publicJwk(keys)
  const row: Row = { id, code_hash: `hash-${id}`, jwk: JSON.stringify(jwk), thumbprint: await jwkThumbprint(jwk), name: id, backend: "software", status, created_at: expiresAt - 900_000, expires_at: expiresAt, workspace_intent: workspace, owner_intent: '{"kind":"self"}', start_at: expiresAt - 900_000, start_client_label: "Bun/1.4.2", pending_state: status === "pending" ? "pending_owner_acceptance" : null, ...extra }
  return { keys, row }
}
async function proofFor(keys: CryptoKeyPair, id: string, method: "GET" | "POST", path: string) {
  const url = `${origin}${path}`
  return new Request(url, { method, headers: { "Mehen-Proof": await createProof(webCryptoSigner(id, keys.privateKey), { method, url, body: null }, { tenant: "enrol" }) } })
}

describe("migration 0008", () => {
  it("replays fresh twice and adds exactly the lease columns, the connect codes and the inbox indexes", async () => {
    const db = env.MIGRATION_DB
    await resetWorkspaceDatabase(db)
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    expect(await columns(db, "enrolments")).toEqual(expect.arrayContaining(["hard_expires_at", "renewed_at", "renewals", "expired_reason", "hidden_group", "start_session", "claimed_account"]))
    expect(await columns(db, "enrol_connect_codes")).toEqual(["code_hash", "account", "workspace", "created_at", "expires_at"])
    expect(await indexes(db)).toEqual(expect.arrayContaining(["enrolments_intent", "enrolments_tenant", "enrol_connect_codes_live"]))
  })

  it("upgrades a populated 0007 store, the Office's rows included, without moving any terminal time", async () => {
    const db = env.MIGRATION_DB, now = Date.now()
    await resetWorkspaceDatabase(db)
    await applyD1Migrations(db, upTo7())
    await insert(db, "accounts", { id: "acc_alex", name: "Alex", created_at: 1 })
    await insert(db, "workspaces", { id: "tn_Nw4dQ2m8xPLsJyKb3Rtvz", slug: "northwind", name: "Northwind", status: "active", created_at: 1 })
    await insert(db, "workspaces", { id: "tn_Ex7mR4pLq9WzTnVc2Hdyk", slug: "example", name: "Personal", status: "active", created_at: 1 })
    const pending = await pendingEnrolment("enr_pending0007", "northwind", "pending", now + 600_000)
    const expired = await pendingEnrolment("enr_expired0007", "northwind", "expired", now - 3_600_000)
    const active = await pendingEnrolment("enr_active0007", "northwind", "active", now - 86_400_000, { tenant: "tn_Nw4dQ2m8xPLsJyKb3Rtvz", device: "dev_office", scope: JSON.stringify({ tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay"], privateCredentials: true }), resolved_owner: JSON.stringify({ kind: "member", member: "mem_alex", name: "Alex" }) })
    // The Office's Personal attempt: started, never accepted, long expired.
    const office = await pendingEnrolment("enr_f1xtR3cP4y5KIRtrusg", "example", "expired", Date.parse("2026-10-28T10:15:00Z"))
    for (const fixture of [pending, expired, active, office]) await insert(db, "enrolments", fixture.row)
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    const rows = (await db.prepare("SELECT id,expires_at,hard_expires_at,renewals,renewed_at,hidden_group,expired_reason,start_session,claimed_account FROM enrolments ORDER BY id").all<Row>()).results
    expect(rows).toHaveLength(4)
    for (const row of rows) expect(row).toEqual({ id: row.id, expires_at: row.expires_at, hard_expires_at: row.expires_at, renewals: 0, renewed_at: null, hidden_group: null, expired_reason: null, start_session: null, claimed_account: null })
    expect(await indexes(db)).toEqual(expect.arrayContaining(["enrolments_intent", "enrolments_tenant", "enrol_connect_codes_live"]))
    const dbEnv = { ...env, DB: db } as Env
    const stored = (id: string) => db.prepare("SELECT * FROM enrolments WHERE id=?").bind(id).first<WorkspaceEnrolmentRow>()
    // The Office's long-expired attempt answers expired, the reason unknown.
    expect(await workspaceEnrolmentStatus(dbEnv, await proofFor(office.keys, office.row.id as string, "GET", `/v1/enrol/${office.row.id}`), office.row.id as string, now)).toEqual({ status: "expired", reason: "legacy" })
    expect(await workspaceEnrolmentStatus(dbEnv, await proofFor(active.keys, active.row.id as string, "GET", `/v1/enrol/${active.row.id}`), active.row.id as string, now)).toMatchObject({ status: "active", tenant: "tn_Nw4dQ2m8xPLsJyKb3Rtvz", device: "dev_office" })
    // The legacy pending row keeps its 15 minute life: live until then,
    // terminal after, never lapsed, and never extended by renewal.
    const legacy = (await stored(pending.row.id as string))!
    expect(enrolmentLease(legacy, now)).toBe("live")
    expect(enrolmentLease(legacy, legacy.expires_at)).toBe("terminal")
    const renewed = await renewWorkspaceEnrolment(dbEnv, await proofFor(pending.keys, pending.row.id as string, "POST", `/v1/enrol/${pending.row.id}/renew`), pending.row.id as string, now)
    expect(renewed).toEqual({ enrolment: pending.row.id, expiresAt: new Date(legacy.expires_at).toISOString(), hardExpiresAt: new Date(legacy.expires_at).toISOString() })
    let refusal: unknown
    // Its life ends: the same row, its 0007 expiry (and so its hard cap) passed.
    await db.prepare("UPDATE enrolments SET expires_at=?,hard_expires_at=?,renewed_at=NULL WHERE id=?").bind(now - 1, now - 1, pending.row.id).run()
    try { await renewWorkspaceEnrolment(dbEnv, await proofFor(pending.keys, pending.row.id as string, "POST", `/v1/enrol/${pending.row.id}/renew`), pending.row.id as string, now) } catch (error) { refusal = error }
    expect(refusal).toBeInstanceOf(VaultError)
    expect((refusal as VaultError).toJSON()).toEqual({ error: "conflict", message: "This enrolment can no longer be renewed.", enrolment: { status: "expired", reason: "hard_cap" } satisfies WorkspaceEnrolStatus })
    // A new row carries every new column.
    const fresh = await pendingEnrolment("enr_fresh0008", "northwind", "pending", now + 3_600_000, { hard_expires_at: now + 86_400_000, renewed_at: now, renewals: 1, expired_reason: null, hidden_group: 2, start_session: "native-app:fa987f", claimed_account: "acc_alex" })
    await insert(db, "enrolments", fresh.row)
    expect(await db.prepare("SELECT hard_expires_at,renewals,hidden_group,start_session,claimed_account FROM enrolments WHERE id='enr_fresh0008'").first()).toEqual({ hard_expires_at: now + 86_400_000, renewals: 1, hidden_group: 2, start_session: "native-app:fa987f", claimed_account: "acc_alex" })
  })

  it("refuses an illegal reason, a fifth hidden group, a wrong connect code life and a second live code", async () => {
    const db = env.MIGRATION_DB
    await resetWorkspaceDatabase(db)
    await applyD1Migrations(db, env.TEST_MIGRATIONS)
    await insert(db, "accounts", { id: "acc_alex", name: "Alex", created_at: 1 })
    await insert(db, "workspaces", { id: "tn_seed", slug: "seed", name: "Seed", status: "active", created_at: 1 })
    const base = (await pendingEnrolment("enr_checks", "seed", "pending", 2)).row
    await expect(insert(db, "enrolments", { ...base, expired_reason: "legacy" })).rejects.toThrow()
    await expect(insert(db, "enrolments", { ...base, hidden_group: 4 })).rejects.toThrow()
    await expect(insert(db, "enrol_connect_codes", { code_hash: "c1", account: "acc_alex", workspace: "tn_seed", created_at: 1, expires_at: 2 })).rejects.toThrow()
    await insert(db, "enrol_connect_codes", { code_hash: "c1", account: "acc_alex", workspace: "tn_seed", created_at: 1, expires_at: 86_400_001 })
    await expect(insert(db, "enrol_connect_codes", { code_hash: "c2", account: "acc_alex", workspace: "tn_seed", created_at: 2, expires_at: 86_400_002 })).rejects.toThrow()
    for (const reason of ["hard_cap", "superseded", "discarded", "source"]) await insert(db, "enrolments", { ...base, id: `enr_${reason}`, code_hash: `hash-${reason}`, status: "expired", pending_state: null, expired_reason: reason })
  })
})
