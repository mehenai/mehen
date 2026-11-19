import type { Env } from "../env.ts"
import { WORKSPACE_GENERATION } from "../directory/workspace-cutover.ts"
import { TenantVault } from "./tenant-vault.ts"

// A new class namespace deletes, rather than renames or adopts, old storage.
// Refuse an accidentally reused legacy object before running any migrations.
export function initialiseWorkspaceGeneration(sql: SqlStorage): void {
  const marker = sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table' AND name='_workspace_generation'").toArray()[0]
  if (marker) {
    if (sql.exec<{ generation: string }>("SELECT generation FROM _workspace_generation").toArray()[0]?.generation !== WORKSPACE_GENERATION) throw new Error("Wrong workspace storage generation")
    return
  }
  if (sql.exec("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('_migrations','tenant_state','devices','items','audit','runs','projects','enrolments','approvals','grants','oauth_connections','policy_windows') LIMIT 1").toArray().length) throw new Error("Legacy vault storage cannot serve workspaces")
  sql.exec("CREATE TABLE _workspace_generation(generation TEXT NOT NULL)")
  sql.exec("INSERT INTO _workspace_generation VALUES (?)", WORKSPACE_GENERATION)
}

export class WorkspaceVault extends TenantVault {
  constructor(ctx: DurableObjectState, env: Env) {
    initialiseWorkspaceGeneration(ctx.storage.sql)
    super(ctx, env)
  }

  cutoverGeneration(): string { return WORKSPACE_GENERATION }
}
