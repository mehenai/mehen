import type { WorkspaceCreationDefault, WorkspaceCreationSource } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { deploymentCeiling, deploymentSetting } from "./deployment-settings.ts"

// Whether an account may create workspaces. An operator's decision for the
// account, once made (operator.ts allow-workspaces or deny-workspaces, or
// the bootstrap account's grant), is the flag; can_create_workspaces_by
// stays NULL until then, and until then the deployment default decides:
// the operators' workspace_creation setting (deployment-settings.ts)
// capped by the deploy's ceiling, WORKSPACE_CREATION, which is also the
// default while no operator has set it.

// The deploy's ceiling: "accounts" only when WORKSPACE_CREATION says so
// exactly.
export function workspaceCreationCeiling(env: Env): WorkspaceCreationDefault {
  return deploymentCeiling(env, "workspace_creation") as WorkspaceCreationDefault
}

export async function workspaceCreationDefault(env: Env): Promise<WorkspaceCreationDefault> {
  return (await deploymentSetting(env, "workspace_creation")) as WorkspaceCreationDefault
}

export type WorkspaceCreationRow = { can_create_workspaces: number; can_create_workspaces_by: string | null }

export function workspaceCreationSource(row: WorkspaceCreationRow): WorkspaceCreationSource {
  if (row.can_create_workspaces_by === null) return "default"
  return row.can_create_workspaces === 1 ? "operator-allowed" : "operator-denied"
}

// `rule` is the deployment default (workspaceCreationDefault).
export function workspaceCreationAllowed(rule: WorkspaceCreationDefault, row: WorkspaceCreationRow): boolean {
  const source = workspaceCreationSource(row)
  return source === "default" ? rule === "accounts" : source === "operator-allowed"
}

// The same rule in SQL for the account row `account` names, reading the
// stored setting in the statement itself, with one parameter:
// workspaceCreationCeilingParam(env).
export function workspaceCreationAllowedSql(account: string): string {
  return `(CASE WHEN ${account}.can_create_workspaces_by IS NULL THEN ?=1 AND COALESCE((SELECT value FROM deployment_settings WHERE key='workspace_creation'),'accounts')='accounts' ELSE ${account}.can_create_workspaces=1 END)`
}
export function workspaceCreationCeilingParam(env: Env): number {
  return workspaceCreationCeiling(env) === "accounts" ? 1 : 0
}
