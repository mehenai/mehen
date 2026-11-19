// A test's own writes to the management graph (team membership, shares,
// members, credentials), which arrange a state rather than act: each runs
// in a transaction of its own after the management guard, as the vault's
// own writes must (areas/management-guard.ts). Any other statement runs as
// it is.
import type { VaultContext } from "../src/vault/core.ts"
import { beforeManagementChange, managementWrite } from "../src/vault/areas/management-guard.ts"

export function fixtureSql(ctx: VaultContext): Pick<SqlStorage, "exec"> {
  return {
    exec<T extends Record<string, SqlStorageValue>>(query: string, ...bindings: unknown[]): SqlStorageCursor<T> {
      if (managementWrite(query) === null) return ctx.sql.exec<T>(query, ...bindings)
      return ctx.storage.transactionSync(() => {
        beforeManagementChange(ctx)
        return ctx.sql.exec<T>(query, ...bindings)
      })
    },
  }
}
