// The management guard (areas/management-guard.ts): SQLite's triggers refuse
// a write to the management graph unless the guard's marker is held in the
// same synchronous transaction; the SQL wrapper refuses schema statements
// outside migrations and restores; the triggers are put back at every
// start; the access-state memo follows the access revision.
import { env } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import type { VaultContext } from "../src/vault/core.ts"
import { GRAPH_TABLES, GUARD_TABLE, MANAGEMENT_COLUMNS, NEUTRAL_COLUMNS, REVISION_TABLE, beforeManagementChange, managementScope, missingGuardTriggers, withTrustedSchema, type GraphTable } from "../src/vault/areas/management-guard.ts"
import { accessState } from "../src/vault/areas/workspace-runtime.ts"
import { applyMigrations, invocationContext } from "../src/vault/tenant-vault.ts"
import { projectWorkspaceOps } from "../src/vault/areas/projects-workspace.ts"
import { workspaceMemberOps } from "../src/vault/areas/workspace-members.ts"
import { inAccess } from "./access-test-support.ts"
import { memberInvocation, memberPrincipal } from "./credentials-test-support.ts"
import { fixtureSql } from "./fixture-sql.ts"
import { projectFixture } from "./projects-workspace-fixture.ts"

const fixture = async () => (await projectFixture()).tenant
const refusal = (run: () => unknown): string | null => {
  try { run(); return null } catch (error) { return error instanceof Error ? error.message : String(error) }
}
const GUARDED = "management_guard"
// Runs a change and rolls it back, answering why it was refused or null.
function tried(ctx: VaultContext, marked: boolean, change: () => void): string | null {
  return refusal(() => ctx.storage.transactionSync(() => {
    if (marked) beforeManagementChange(ctx)
    change()
    throw new Error("rolled back")
  }))?.replace(/^rolled back$/, "") || null
}
const columnsOf = (ctx: VaultContext, table: string): string[] => ctx.sql.exec<{ name: string }>("SELECT name FROM pragma_table_info(?)", table).toArray().map((row) => row.name)
const oneRow = (ctx: VaultContext, table: GraphTable): Record<string, SqlStorageValue> => ctx.sql.exec<Record<string, SqlStorageValue>>(`SELECT rowid AS _rowid, * FROM ${table} LIMIT 1`).toArray()[0] as Record<string, SqlStorageValue>
const changed = (value: SqlStorageValue): SqlStorageValue => typeof value === "number" ? value + 1 : value === null ? "x" : `${String(value)}_changed`
// A connection setting, read as only the guard's own start may.
function pragma(ctx: VaultContext, name: string): unknown {
  const scope = managementScope(ctx.storage)
  scope.trusted++
  try { return ctx.sql.exec(`PRAGMA ${name}`).toArray()[0]?.[name] } finally { scope.trusted-- }
}
const revision = (ctx: VaultContext): number => ctx.sql.exec<{ n: number }>(`SELECT n FROM ${REVISION_TABLE}`).toArray()[0]!.n

describe("the management guard's columns", () => {
  it("classifies every column the migrations make, each once, as management or neutral", async () => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      for (const table of GRAPH_TABLES) {
        const management = MANAGEMENT_COLUMNS[table], neutral = NEUTRAL_COLUMNS[table]
        expect([table, management.filter((column) => neutral.includes(column))]).toEqual([table, []])
        expect([table, [...management, ...neutral].sort()]).toEqual([table, columnsOf(ctx, table).sort()])
      }
    })
  })

  it("refuses a real change of every management column unmarked and lets it through marked, and never refuses a neutral one", async () => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      for (const table of GRAPH_TABLES) {
        const row = oneRow(ctx, table)
        const update = (column: string) => () => ctx.sql.exec(`UPDATE ${table} SET "${column}"=? WHERE rowid=?`, changed(row[column] ?? null), row._rowid as number)
        for (const column of MANAGEMENT_COLUMNS[table]) {
          expect([table, column, tried(ctx, false, update(column))]).toEqual([table, column, expect.stringContaining(GUARDED)])
          expect([table, column, tried(ctx, true, update(column)) ?? ""]).toEqual([table, column, expect.not.stringContaining(GUARDED)])
        }
        for (const column of NEUTRAL_COLUMNS[table]) expect([table, column, tried(ctx, false, update(column)) ?? ""]).toEqual([table, column, expect.not.stringContaining(GUARDED)])
      }
    })
  })

  it("refuses an insert and a delete on every graph table unmarked and lets them through marked", async () => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      for (const table of GRAPH_TABLES) {
        const row = oneRow(ctx, table)
        const remove = () => ctx.sql.exec(`DELETE FROM ${table} WHERE rowid=?`, row._rowid as number)
        const insert = () => ctx.sql.exec(`INSERT INTO ${table} SELECT * FROM ${table} WHERE rowid=?`, row._rowid as number)
        expect([table, tried(ctx, false, remove), tried(ctx, true, remove)]).toEqual([table, expect.stringContaining(GUARDED), null])
        expect([table, tried(ctx, false, insert), tried(ctx, true, insert) ?? ""]).toEqual([table, expect.stringContaining(GUARDED), expect.not.stringContaining(GUARDED)])
      }
    })
  })
})

describe("REPLACE and recursive triggers", () => {
  it("has recursive_triggers on, so the row a REPLACE deletes fires its own triggers", async () => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      expect(pragma(ctx, "recursive_triggers")).toBe(1)
      // A REPLACE that displaces one team: its delete and its insert both
      // count, which they do only with recursive_triggers on.
      ctx.storage.transactionSync(() => {
        beforeManagementChange(ctx)
        const before = revision(ctx)
        ctx.sql.exec("INSERT OR REPLACE INTO teams(id,slug,name,created_by,created_at) VALUES ('tm_service','tm-service','Service','mem_owner',1)")
        expect(revision(ctx) - before).toBe(2)
      })
    })
  })

  it.each(["teams", "projects"] as const)("refuses a REPLACE on %s unmarked, a slug change that would displace another row included", async (table) => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      fixtureSql(ctx).exec(table === "teams" ? "INSERT INTO teams VALUES ('tm_other','other','Other','mem_owner',1)" : "INSERT INTO projects(id,slug,default_env,created_by,created_at,updated_at) VALUES ('prj_other','other','dev','member:mem_owner',1,1)")
      const [first] = ctx.sql.exec<{ id: string; slug: string }>(`SELECT id, slug FROM ${table} WHERE id NOT IN ('tm_other','prj_other') LIMIT 1`).toArray()
      const count = () => ctx.sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM ${table}`).toArray()[0]!.n
      const before = count()
      const replaceInsert = () => ctx.sql.exec(table === "teams" ? "INSERT OR REPLACE INTO teams VALUES ('tm_new','other','New','mem_owner',1)" : "INSERT OR REPLACE INTO projects(id,slug,default_env,created_by,created_at,updated_at) VALUES ('prj_new','other','dev','member:mem_owner',1,1)")
      const neutralLooking = () => ctx.sql.exec(table === "teams" ? "UPDATE OR REPLACE teams SET name='Renamed', slug='other' WHERE id=?" : "UPDATE OR REPLACE projects SET updated_at=updated_at+1, slug='other' WHERE id=?", first!.id)
      for (const replace of [replaceInsert, neutralLooking]) expect(refusal(() => ctx.storage.transactionSync(replace))).toContain(GUARDED)
      expect(count()).toBe(before)
    })
  })
})

describe("the guard's marker", () => {
  it("is taken only inside a synchronous transaction, held for the whole outermost one, and gone when it ends, by commit or by throw", async () => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      const marker = () => ctx.sql.exec(`SELECT COUNT(*) AS n FROM ${GUARD_TABLE}`).toArray()[0]!.n
      let n = 0
      const write = () => ctx.sql.exec("INSERT INTO team_members(team,member) VALUES ('tm_service',?)", ["mem_owner", "mem_admin", "mem_kim", "mem_guest"][n++] as string)
      expect(refusal(() => beforeManagementChange(ctx))).toBe("The management guard runs only inside a synchronous transaction.")
      ctx.storage.transactionSync(() => {
        beforeManagementChange(ctx)
        expect(marker()).toBe(1)
        // A nested transaction that succeeds keeps the outer one's marker.
        ctx.storage.transactionSync(() => undefined)
        expect(marker()).toBe(1)
        write()
      })
      expect(marker()).toBe(0)
      expect(refusal(() => ctx.storage.transactionSync(write))).toContain(GUARDED)
      expect(refusal(() => ctx.storage.transactionSync(() => { beforeManagementChange(ctx); throw new Error("rolled back") }))).toBe("rolled back")
      expect(marker()).toBe(0)
      expect(refusal(() => ctx.storage.transactionSync(() => Promise.resolve()))).toBe("A synchronous transaction's callback returned a promise.")
      expect(managementScope(ctx.storage).depth).toBe(0)
    })
  })

  it("is never left behind by the vault's own changes, and one found at a request is removed and audited", async () => {
    const tenant = await fixture()
    const share = { project: "prj_a", subject: { kind: "member", member: "mem_kim" }, before: { level: "manage", protected: false, expiresAt: null }, after: { level: "use", protected: false, expiresAt: null } } as const
    const team = { team: "tm_engineering", member: "mem_kim", change: "add" } as const
    const markers = (ctx: VaultContext) => ctx.sql.exec(`SELECT * FROM ${GUARD_TABLE}`).toArray().length
    const leftovers = (ctx: VaultContext) => ctx.sql.exec("SELECT 1 FROM audit WHERE action='management_guard.leftover'").toArray().length
    await inAccess(tenant, async (ctx) => {
      await projectWorkspaceOps["projects.share"]!.handler(ctx, memberPrincipal(ctx, "owner"), share, memberInvocation(ctx, "owner", { type: "project.share", ...share }))
      await workspaceMemberOps["access.team.members"]!.handler(ctx, memberPrincipal(ctx, "owner"), team, memberInvocation(ctx, "owner", { type: "team.members", ...team }))
      const rename = { team: "tm_engineering", change: "rename", name: "Platform", slug: "platform" } as const
      await workspaceMemberOps["access.team.update"]!.handler(ctx, memberPrincipal(ctx, "owner"), rename, memberInvocation(ctx, "owner", { type: "team.update", ...rename }))
      expect([markers(ctx), leftovers(ctx)]).toEqual([0, 0])
      ctx.sql.exec(`INSERT INTO ${GUARD_TABLE}(id) VALUES (1)`)
    })
    await env.TENANT_VAULT.getByName(tenant).invoke({ op: "access.teams.read", input: {}, auth: { kind: "system", reason: "test" } })
    await inAccess(tenant, (ctx) => expect([markers(ctx), leftovers(ctx)]).toEqual([0, 1]))
  })
})

describe("schema statements and the raw handle", () => {
  it.each([
    "DROP TABLE team_members",
    "DROP TRIGGER _mehen_guard_items_delete",
    "ALTER TABLE project_shares RENAME TO shares_old",
    "CREATE TABLE sneaky(x)",
    "PRAGMA recursive_triggers = OFF",
    "ATTACH DATABASE ':memory:' AS other",
    "DETACH DATABASE other",
    "VACUUM",
    "REINDEX",
    "  /* a comment */ -- another\n drop table teams",
    "SELECT 1; DROP TABLE members",
    "SELECT ';'; DROP TABLE members",
    "SELECT 1; 'x' DROP TABLE members",
  ])("refuses %s through ctx.sql and storage.sql alike", async (query) => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      expect(refusal(() => ctx.sql.exec(query))).toMatch(/runs only in a migration or a restore/)
      expect(refusal(() => ctx.storage.sql.exec(query))).toMatch(/runs only in a migration or a restore/)
      expect(missingGuardTriggers(ctx.sql)).toEqual([])
    })
  })

  it("lets a restore change the schema and puts every guard trigger back on what it leaves", async () => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      withTrustedSchema(ctx, () => ctx.sql.exec("CREATE TABLE trusted_probe(x)"))
      expect(missingGuardTriggers(ctx.sql)).toEqual([])
      expect(ctx.sql.exec("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='trusted_probe'").toArray().length).toBe(3)
    })
  })

  it("puts back a guard trigger that is missing when the object starts", async () => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      const scope = managementScope(ctx.storage)
      scope.trusted++
      try { ctx.sql.exec("DROP TRIGGER _mehen_guard_project_shares_insert") } finally { scope.trusted-- }
      expect(missingGuardTriggers(ctx.sql)).toEqual(["_mehen_guard_project_shares_insert"])
      ctx.restart("guard test")
    }).catch((error: Error) => expect(error.message).toBe("guard test"))
    await inAccess(tenant, (ctx) => {
      expect(missingGuardTriggers(ctx.sql)).toEqual([])
      expect(pragma(ctx, "recursive_triggers")).toBe(1)
      expect(ctx.sql.exec(`SELECT * FROM ${GUARD_TABLE}`).toArray()).toEqual([])
    })
  })

  it("runs a migration that moves graph rows on a database whose triggers are in place, and guards the table it makes from the next start", async () => {
    const tenant = await fixture()
    const area = { name: "guard_probe", migrations: ["CREATE TABLE guard_probe(x)", "INSERT INTO team_members(team,member) VALUES ('tm_service','mem_kim')"] }
    await inAccess(tenant, (ctx) => {
      const scope = managementScope(ctx.storage)
      scope.trusted++
      try {
        // As the start runs it (guarded); without the marker the graph write is refused.
        expect(refusal(() => applyMigrations(ctx.sql, ctx.storage, [area]))).toContain(GUARDED)
        applyMigrations(ctx.sql, ctx.storage, [area], true)
      } finally { scope.trusted-- }
      expect(ctx.sql.exec("SELECT member FROM team_members WHERE team='tm_service'").toArray()).toEqual([{ member: "mem_kim" }])
      expect(missingGuardTriggers(ctx.sql)).toEqual(["_mehen_revision_guard_probe_insert", "_mehen_revision_guard_probe_update", "_mehen_revision_guard_probe_delete"])
      ctx.restart("guard test")
    }).catch((error: Error) => expect(error.message).toBe("guard test"))
    await inAccess(tenant, (ctx) => expect(missingGuardTriggers(ctx.sql)).toEqual([]))
  })

  // Only the storage wrapper holds the raw SQL handle; the platform vault is
  // its own object with no management graph.
  it("is reached only by the storage wrapper", () => {
    const sources = import.meta.glob<string>("../src/**/*.ts", { query: "?raw", import: "default", eager: true })
    const reaching = Object.entries(sources).filter(([path, text]) => !path.endsWith(".test.ts") && /storage\s*\.\s*sql\b|storage\[\s*["'`]sql["'`]\s*\]/.test(text)).map(([path]) => path.replace("../src/", "")).sort()
    expect(reaching).toEqual(["platform/platform-vault.ts", "vault/tenant-vault.ts"])
  })
})

describe("the access-state memo", () => {
  it("is rebuilt after a change by any route, and kept after one that rolled back", async () => {
    const tenant = await fixture()
    await inAccess(tenant, (base) => {
      const ctx = invocationContext(base)
      const teamOf = (c: VaultContext) => accessState(c).teams.find((t) => t.id === "tm_engineering")?.members ?? []
      expect(teamOf(ctx)).toEqual(["mem_member"])
      fixtureSql(base).exec("INSERT INTO team_members(team,member) VALUES ('tm_engineering','mem_kim')")
      expect([...teamOf(ctx)].sort()).toEqual(["mem_kim", "mem_member"])
      base.storage.transactionSync(() => { beforeManagementChange(base); base.storage.sql.exec("DELETE FROM team_members WHERE member='mem_kim'") })
      expect(teamOf(ctx)).toEqual(["mem_member"])
      const kept = accessState(ctx)
      refusal(() => base.storage.transactionSync(() => { beforeManagementChange(base); base.sql.exec("DELETE FROM team_members"); throw new Error("rolled back") }))
      expect(accessState(ctx)).toEqual(kept)
      expect(teamOf(ctx)).toEqual(["mem_member"])
    })
  })
})
