// The management guard at run time (areas/management-guard.ts): the
// workspace vault's SQL refuses a write to the management graph unless the
// guard ran in the transaction it is part of, and lets every update of a
// column that cannot change management through.
import { describe, expect, it } from "vitest"
import type { VaultContext } from "../src/vault/core.ts"
import { MANAGEMENT_NEUTRAL_COLUMNS, beforeManagementChange, managementWrite } from "../src/vault/areas/management-guard.ts"
import { credentialsFixture, inAccess } from "./credentials-test-support.ts"

// Each writes nothing (WHERE 0), so only the guard decides whether it runs.
const GRAPH_WRITES = [
  "INSERT INTO items SELECT * FROM items WHERE 0",
  "INSERT OR IGNORE INTO team_members SELECT * FROM team_members WHERE 0",
  "REPLACE INTO project_shares SELECT * FROM project_shares WHERE 0",
  "insert or replace into Members select * from members where 0",
  "DELETE FROM items WHERE 0",
  "DELETE FROM team_members WHERE 0",
  "DELETE FROM project_shares WHERE 0",
  "DELETE FROM members WHERE 0",
  "DELETE FROM teams WHERE 0",
  "DELETE FROM projects WHERE 0",
  "UPDATE items SET home_kind=home_kind WHERE 0",
  "UPDATE items SET home_id=home_id WHERE 0",
  "UPDATE items SET policy=policy, home_id=home_id WHERE 0",
  `UPDATE "items" SET "home_id"=home_id WHERE 0`,
  "UPDATE `items` SET [home_id]=home_id WHERE 0",
  "update Items set Home_Id = home_id where 0",
  "UPDATE main.items SET home_id=home_id WHERE 0",
  "/* a comment */ UPDATE items SET -- another\n home_id=home_id WHERE 0",
  "UPDATE items AS i SET home_id=i.home_id WHERE 0",
  "UPDATE OR IGNORE members SET role=role WHERE 0",
  "UPDATE members SET status=status WHERE 0",
  "UPDATE members SET (name, role) = (name, role) WHERE 0",
  "UPDATE members SET revision=revision+1, status=status WHERE 0",
  "UPDATE members SET account=account WHERE 0",
  "UPDATE team_members SET member=member WHERE 0",
  "UPDATE project_shares SET value=value WHERE 0",
  "UPDATE teams SET id=id WHERE 0",
  "UPDATE projects SET id=id WHERE 0",
  "SELECT 1; DELETE FROM project_shares WHERE 0",
]
const refused = (run: () => unknown): string | null => {
  try { run(); return null } catch (error) { return error instanceof Error ? error.message : String(error) }
}

describe("the management guard at run time", () => {
  it.each(GRAPH_WRITES)("refuses %s outside a transaction, and in one the guard did not run in", async (query) => {
    expect(managementWrite(query)).not.toBeNull()
    const f = await credentialsFixture()
    await inAccess(f.tenant, (ctx) => {
      expect(refused(() => ctx.sql.exec(query))).toContain("without the management guard")
      expect(refused(() => ctx.storage.transactionSync(() => ctx.sql.exec(query)))).toContain("without the management guard")
      expect(refused(() => ctx.storage.transactionSync(() => { beforeManagementChange(ctx); ctx.sql.exec(query) }))).toBeNull()
    })
  })

  it("lets every update of a column that cannot change management through, outside any transaction", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, (ctx) => {
      for (const [table, columns] of Object.entries(MANAGEMENT_NEUTRAL_COLUMNS)) {
        for (const column of columns) {
          const query = `UPDATE ${table} SET ${column}=${column} WHERE 0`
          expect([query, managementWrite(query), refused(() => ctx.sql.exec(query))]).toEqual([query, null, null])
        }
      }
      for (const query of ["INSERT INTO teams SELECT * FROM teams WHERE 0", "INSERT INTO projects SELECT * FROM projects WHERE 0", "UPDATE items SET policy=policy, config_rev=config_rev+1 WHERE 0", "SELECT home_id FROM items WHERE 0"]) {
        expect([query, refused(() => ctx.sql.exec(query))]).toEqual([query, null])
      }
    })
  })

  it("marks one transaction only: the next one without the guard is refused, and so is the rest of one whose nested transaction threw", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, (ctx: VaultContext) => {
      const write = () => ctx.sql.exec("DELETE FROM team_members WHERE 0")
      ctx.storage.transactionSync(() => { beforeManagementChange(ctx); write() })
      expect(refused(() => ctx.storage.transactionSync(write))).toContain("without the management guard")
      expect(refused(() => ctx.storage.transactionSync(() => { beforeManagementChange(ctx); throw new Error("rolled back") }))).toBe("rolled back")
      expect(refused(() => ctx.storage.transactionSync(write))).toContain("without the management guard")
      // A nested transaction shares its outer one's mark until one throws.
      expect(refused(() => ctx.storage.transactionSync(() => {
        beforeManagementChange(ctx)
        ctx.storage.transactionSync(write)
        try { ctx.storage.transactionSync(() => { throw new Error("inner") }) } catch { /* the savepoint rolled back */ }
        write()
      }))).toContain("without the management guard")
      expect(refused(write)).toContain("without the management guard")
    })
  })
})
