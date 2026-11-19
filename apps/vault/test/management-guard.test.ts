// The management guard (areas/management-guard.ts): SQLite's triggers refuse
// a write to the management graph unless the guard's marker is held in the
// same synchronous transaction; the SQL wrapper refuses schema statements
// outside migrations and restores; the triggers are put back at every
// start; the access-state memo follows the access revision.
import { env } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import type { VaultContext } from "../src/vault/core.ts"
import { GRAPH_TABLES, MANAGEMENT_COLUMNS, NEUTRAL_COLUMNS, beforeManagementChange, dropGuardTriggerForTests, guardMarkersForTests, managementScope, missingGuardTriggers, plantGuardMarkerForTests, runUncheckedForTests, withTrustedSchema, type GraphTable } from "../src/vault/areas/management-guard.ts"
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
const revision = (ctx: VaultContext): number => Number(ctx.accessRevision().split(":")[0])
// A valid new row for each graph table: a copy of an existing one with
// these columns given fresh values, so no key is taken and nothing refers to
// it.
const FRESH: Readonly<Record<GraphTable, Record<string, string>>> = {
  items: { id: "itm_fresh", slug: "fresh-key" },
  team_members: { team: "tm_service", member: "mem_kim" },
  project_shares: { id: "shr_fresh", subject_id: "mem_fresh_subject" },
  members: { id: "mem_fresh", account: "acc_fresh" },
  teams: { id: "tm_fresh", slug: "fresh-team" },
  projects: { id: "prj_fresh", slug: "fresh-project" },
}
// A valid new value for every management column of that fresh row, or the
// constraint that refuses every other value.
const CHANGES: Readonly<Record<GraphTable, Record<string, string | { refused: RegExp }>>> = {
  items: { id: "itm_fresh2", slug: "fresh-key-2", home_kind: "member", home_id: "mem_kim" },
  team_members: { team: "tm_engineering", member: "mem_owner", role: { refused: /CHECK constraint failed/ } },
  project_shares: { id: "shr_fresh2", project: "prj_b", subject_kind: "team", subject_id: "mem_fresh_subject2", value: '{"fresh":true}' },
  members: { id: "mem_fresh2", account: "acc_fresh2", role: "guest", status: "suspended" },
  teams: { id: "tm_fresh2", slug: "fresh-team-2" },
  projects: { id: "prj_fresh2", slug: "fresh-project-2" },
}
function insertFresh(ctx: VaultContext, table: GraphTable): void {
  const fresh = FRESH[table], columns = columnsOf(ctx, table)
  const source = oneRow(ctx, table)
  ctx.sql.exec(`INSERT INTO ${table}(${columns.map((c) => `"${c}"`).join(",")}) SELECT ${columns.map((c) => (c in fresh ? "?" : `"${c}"`)).join(",")} FROM ${table} WHERE rowid=?`, ...columns.filter((c) => c in fresh).map((c) => fresh[c] as string), source._rowid as number)
}
const freshWhere = (table: GraphTable): string => Object.keys(FRESH[table]).map((c) => `"${c}"=?`).join(" AND ")
const freshKey = (table: GraphTable): string[] => Object.values(FRESH[table])

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

  it("refuses a real change of every management column unmarked, and makes it, read back, marked", async () => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      for (const table of GRAPH_TABLES) {
        const row = oneRow(ctx, table)
        for (const [column, change] of Object.entries(CHANGES[table])) {
          const value = typeof change === "string" ? change : changed(row[column] ?? null)
          // Unmarked, on an existing row, to a value it does not have: the
          // trigger refuses it first.
          const other = value === row[column] ? changed(value) : value
          expect([table, column, tried(ctx, false, () => ctx.sql.exec(`UPDATE ${table} SET "${column}"=? WHERE rowid=?`, other, row._rowid as number))]).toEqual([table, column, expect.stringContaining(GUARDED)])
          // Marked, on a fresh row nothing refers to: made and read back, or
          // refused by the one constraint that allows no other value.
          const outcome = tried(ctx, true, () => {
            insertFresh(ctx, table)
            const [rowid] = ctx.sql.exec<{ rowid: number }>(`SELECT rowid FROM ${table} WHERE ${freshWhere(table)}`, ...freshKey(table)).toArray().map((r) => r.rowid)
            ctx.sql.exec(`UPDATE ${table} SET "${column}"=? WHERE rowid=?`, value, rowid as number)
            expect(ctx.sql.exec(`SELECT "${column}" AS v FROM ${table} WHERE rowid=?`, rowid as number).toArray()).toEqual([{ v: value }])
          })
          if (typeof change === "string") expect([table, column, outcome]).toEqual([table, column, null])
          else expect([table, column, outcome]).toEqual([table, column, expect.stringMatching(change.refused)])
        }
        expect(Object.keys(CHANGES[table]).sort()).toEqual([...MANAGEMENT_COLUMNS[table]].sort())
      }
    })
  })

  it("never refuses a change of a neutral column, made and read back unmarked", async () => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      for (const table of GRAPH_TABLES) {
        const row = oneRow(ctx, table)
        for (const column of NEUTRAL_COLUMNS[table]) {
          const value = changed(row[column] ?? null)
          expect([table, column, tried(ctx, false, () => {
            ctx.sql.exec(`UPDATE ${table} SET "${column}"=? WHERE rowid=?`, value, row._rowid as number)
            expect(ctx.sql.exec(`SELECT "${column}" AS v FROM ${table} WHERE rowid=?`, row._rowid as number).toArray()).toEqual([{ v: value }])
          })]).toEqual([table, column, null])
        }
      }
    })
  })

  it("refuses an insert and a delete on every graph table unmarked, and makes them, read back, marked", async () => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      for (const table of GRAPH_TABLES) {
        const row = oneRow(ctx, table)
        const count = (where: string, ...bindings: SqlStorageValue[]) => ctx.sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM ${table} WHERE ${where}`, ...bindings).toArray()[0]!.n
        expect([table, tried(ctx, false, () => insertFresh(ctx, table))]).toEqual([table, expect.stringContaining(GUARDED)])
        expect([table, tried(ctx, true, () => { insertFresh(ctx, table); expect(count(freshWhere(table), ...freshKey(table))).toBe(1) })]).toEqual([table, null])
        const remove = () => ctx.sql.exec(`DELETE FROM ${table} WHERE rowid=?`, row._rowid as number)
        expect([table, tried(ctx, false, remove)]).toEqual([table, expect.stringContaining(GUARDED)])
        expect([table, tried(ctx, true, () => { remove(); expect(count("rowid=?", row._rowid as number)).toBe(0) })]).toEqual([table, null])
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
      const marker = () => guardMarkersForTests(ctx)
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
    const markers = (ctx: VaultContext) => guardMarkersForTests(ctx)
    const leftovers = (ctx: VaultContext) => ctx.sql.exec("SELECT 1 FROM audit WHERE action='management_guard.leftover'").toArray().length
    await inAccess(tenant, async (ctx) => {
      await projectWorkspaceOps["projects.share"]!.handler(ctx, memberPrincipal(ctx, "owner"), share, memberInvocation(ctx, "owner", { type: "project.share", ...share }))
      await workspaceMemberOps["access.team.members"]!.handler(ctx, memberPrincipal(ctx, "owner"), team, memberInvocation(ctx, "owner", { type: "team.members", ...team }))
      const rename = { team: "tm_engineering", change: "rename", name: "Platform", slug: "platform" } as const
      await workspaceMemberOps["access.team.update"]!.handler(ctx, memberPrincipal(ctx, "owner"), rename, memberInvocation(ctx, "owner", { type: "team.update", ...rename }))
      expect([markers(ctx), leftovers(ctx)]).toEqual([0, 0])
      plantGuardMarkerForTests(ctx)
    })
    await env.TENANT_VAULT.getByName(tenant).invoke({ op: "access.teams.read", input: {}, auth: { kind: "system", reason: "test" } })
    await inAccess(tenant, (ctx) => expect([markers(ctx), leftovers(ctx)]).toEqual([0, 1]))
  })
})

describe("schema statements and the raw handle", () => {
  it.each([
    "DROP TABLE team_members",
    "DROP TRIGGER any_trigger",
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
    "EXPLAIN PRAGMA recursive_triggers = OFF",
    "EXPLAIN QUERY PLAN SELECT * FROM items",
    "BEGIN",
    "COMMIT",
    "END",
    "ROLLBACK",
    "SAVEPOINT s1",
    "RELEASE s1",
    "ANALYZE",
  ])("refuses %s through ctx.sql and storage.sql alike", async (query) => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      expect(refusal(() => ctx.sql.exec(query))).toMatch(/runs only in a migration or a restore/)
      expect(refusal(() => ctx.storage.sql.exec(query))).toMatch(/runs only in a migration or a restore/)
      expect(missingGuardTriggers(ctx)).toEqual([])
    })
  })

  it("lets a restore change the schema and puts every guard trigger back on what it leaves", async () => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      withTrustedSchema(ctx, () => ctx.sql.exec("CREATE TABLE trusted_probe(x)"))
      expect(missingGuardTriggers(ctx)).toEqual([])
      expect(ctx.sql.exec("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='trusted_probe'").toArray().length).toBe(3)
    })
  })

  it("puts back a guard trigger that is missing when the object starts", async () => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      const scope = managementScope(ctx.storage)
      scope.trusted++
      try { dropGuardTriggerForTests(ctx, "_mehen_guard_project_shares_insert") } finally { scope.trusted-- }
      expect(missingGuardTriggers(ctx)).toEqual(["_mehen_guard_project_shares_insert"])
      ctx.restart("guard test")
    }).catch((error: Error) => expect(error.message).toBe("guard test"))
    await inAccess(tenant, (ctx) => {
      expect(missingGuardTriggers(ctx)).toEqual([])
      expect(pragma(ctx, "recursive_triggers")).toBe(1)
      expect(guardMarkersForTests(ctx)).toBe(0)
    })
  })

  it("runs a migration that moves graph rows on a database whose triggers are in place, and guards the table it makes from the next start", async () => {
    const tenant = await fixture()
    const area = { name: "guard_probe", migrations: ["CREATE TABLE guard_probe(x)", "INSERT INTO team_members(team,member) VALUES ('tm_service','mem_kim')"] }
    await inAccess(tenant, (ctx) => {
      const scope = managementScope(ctx.storage)
      scope.trusted++
      try {
        // Without the marker the graph write is refused; holding it, as the
        // start does for each migration, it runs.
        expect(refusal(() => applyMigrations(ctx.sql, ctx.storage, [area]))).toContain(GUARDED)
        ctx.storage.transactionSync(() => { beforeManagementChange(ctx); applyMigrations(ctx.sql, ctx.storage, [area]) })
      } finally { scope.trusted-- }
      expect(ctx.sql.exec("SELECT member FROM team_members WHERE team='tm_service'").toArray()).toEqual([{ member: "mem_kim" }])
      expect(missingGuardTriggers(ctx)).toEqual(["_mehen_revision_guard_probe_insert", "_mehen_revision_guard_probe_update", "_mehen_revision_guard_probe_delete"])
      ctx.restart("guard test")
    }).catch((error: Error) => expect(error.message).toBe("guard test"))
    await inAccess(tenant, (ctx) => expect(missingGuardTriggers(ctx)).toEqual([]))
  })

  // Only the storage wrapper holds the raw SQL handle; the platform vault is
  // its own object with no management graph.
  it("is reached only by the storage wrapper", () => {
    const sources = import.meta.glob<string>("../src/**/*.ts", { query: "?raw", import: "default", eager: true })
    const reaching = Object.entries(sources).filter(([path, text]) => !path.endsWith(".test.ts") && /storage\s*\.\s*sql\b|storage\[\s*["'`]sql["'`]\s*\]/.test(text)).map(([path]) => path.replace("../src/", "")).sort()
    expect(reaching).toEqual(["platform/platform-vault.ts", "vault/tenant-vault.ts"])
    // The guard's own SQL is handed over once, by the wrapper, and its test
    // helpers are for tests alone.
    const naming = (pattern: RegExp) => Object.entries(sources).filter(([path, text]) => !path.endsWith(".test.ts") && pattern.test(text)).map(([path]) => path.replace("../src/", "")).sort()
    expect(naming(/registerGuardSql\(/)).toEqual(["vault/areas/management-guard.ts", "vault/tenant-vault.ts"])
    expect(naming(/\w+ForTests\b/).filter((path) => /GuardMarker|GuardTrigger|UncheckedForTests/.test(sources[`../src/${path}`] ?? ""))).toEqual(["vault/areas/management-guard.ts"])
  })
})

describe("statements that would end the transaction under the guard", () => {
  const ROLLBACKS = [
    "INSERT OR ROLLBACK INTO tenant_state(key,value) VALUES ('guard_rollback_probe','1'),('guard_rollback_probe','2')",
    "WITH v(k) AS (VALUES ('guard_rollback_probe')) INSERT OR ROLLBACK INTO tenant_state(key,value) SELECT k,'1' FROM v UNION ALL SELECT k,'2' FROM v",
    "UPDATE OR ROLLBACK tenant_state SET key='a' WHERE key IN ('a','b')",
    "insert /* a comment */ or\n rollback into tenant_state(key,value) values ('x','1')",
  ]
  it.each(ROLLBACKS)("refuses %s in the vault's SQL", async (query) => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => expect(refusal(() => ctx.sql.exec(query))).toMatch(/OR ROLLBACK/))
  })

  it("refuses load_extension, and leaves literals and comments that spell either alone", async () => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      expect(refusal(() => ctx.sql.exec("SELECT load_extension('x')"))).toMatch(/load_extension/)
      fixtureSql(ctx).exec("INSERT INTO tenant_state(key,value) VALUES ('or rollback', 'load_extension(x)') -- or rollback")
      expect(ctx.sql.exec("SELECT value FROM tenant_state WHERE key='or rollback'").toArray()).toEqual([{ value: "load_extension(x)" }])
    })
  })

  // What the refusal above keeps out, done under the vault: SQLite ends the
  // transaction, and the guard must notice rather than trust its count.
  it("breaks the scope when SQLite's transaction ends under it: no guard call or statement after, and no marker after the transaction", async () => {
    const tenant = await fixture()
    const seen: (string | null)[] = []
    // The Worker's SQLite rolls the transaction back without a thrown error
    // (bun:sqlite throws UNIQUE), and the Worker then fails the whole event:
    // what the scope said is kept here, and the state after it read anew.
    await inAccess(tenant, (ctx) => {
      seen.push(refusal(() => ctx.storage.transactionSync(() => {
        beforeManagementChange(ctx)
        refusal(() => runUncheckedForTests(ctx, "INSERT OR ROLLBACK INTO tenant_state(key,value) VALUES ('p','1'),('p','2')"))
        seen.push(refusal(() => beforeManagementChange(ctx)), refusal(() => ctx.sql.exec("SELECT 1")))
        throw new Error("after rollback")
      })))
    }).catch(() => {})
    expect(seen).toEqual([expect.stringMatching(/transaction ended/), expect.stringMatching(/transaction ended/), expect.stringMatching(/transaction ended/)])
    await inAccess(tenant, (ctx) => {
      expect(guardMarkersForTests(ctx)).toBe(0)
      expect(refusal(() => ctx.storage.transactionSync(() => ctx.sql.exec("DELETE FROM team_members")))).toContain(GUARDED)
    })
  })

  it("keeps the scope whole after a caught constraint failure, and the guard taken again", async () => {
    const tenant = await fixture()
    await inAccess(tenant, (ctx) => {
      ctx.storage.transactionSync(() => {
        beforeManagementChange(ctx)
        expect(refusal(() => ctx.sql.exec("INSERT INTO tenant_state(key,value) VALUES ('dup','1'),('dup','2')"))).toMatch(/UNIQUE/)
        beforeManagementChange(ctx)
        ctx.sql.exec("INSERT INTO team_members(team,member) VALUES ('tm_service','mem_kim')")
      })
      expect(ctx.sql.exec("SELECT member FROM team_members WHERE team='tm_service'").toArray()).toEqual([{ member: "mem_kim" }])
      expect(guardMarkersForTests(ctx)).toBe(0)
      expect(refusal(() => ctx.storage.transactionSync(() => ctx.sql.exec("DELETE FROM team_members")))).toContain(GUARDED)
    })
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
