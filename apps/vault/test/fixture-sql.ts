// A test's own writes that arrange the management graph (team membership,
// shares, members, teams, projects, credentials): each runs in a fixture
// transaction of its own that takes the management guard, as the vault's
// own writes must (areas/management-guard.ts). Only for setting state up,
// never around a handler under test.
import type { VaultContext } from "../src/vault/core.ts"
import { beforeManagementChange } from "../src/vault/areas/management-guard.ts"

export function fixtureSql(ctx: VaultContext): Pick<SqlStorage, "exec"> {
  return {
    exec<T extends Record<string, SqlStorageValue>>(query: string, ...bindings: unknown[]): SqlStorageCursor<T> {
      return ctx.storage.transactionSync(() => {
        beforeManagementChange(ctx)
        return ctx.sql.exec<T>(query, ...bindings)
      })
    },
  }
}
