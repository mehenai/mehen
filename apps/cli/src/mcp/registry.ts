import { TOOLSETS, type Toolset } from "./toolsets.ts"
import { vaultStatus } from "./vault-status.ts"
import { vaultDoctor } from "./vault-doctor.ts"
import { vaultTemplates } from "./vault-templates.ts"
import { vaultList } from "./vault-list.ts"
import { vaultShow } from "./vault-show.ts"
import { vaultCheck } from "./vault-check.ts"
import { vaultRequest } from "./vault-request.ts"
import { vaultConnect } from "./vault-connect.ts"
import { vaultFetch } from "./vault-fetch.ts"
import { vaultPlan } from "./vault-plan.ts"
import { vaultFill } from "./vault-fill.ts"
import { vaultPush } from "./vault-push.ts"
import { vaultEnv } from "./vault-env.ts"
import { vaultWait } from "./vault-wait.ts"
import { vaultPending } from "./vault-pending.ts"
import { vaultPolicy } from "./vault-policy.ts"
import { vaultMandate } from "./vault-mandate.ts"
import { vaultAdoptScan } from "./vault-adopt-scan.ts"
import { vaultAdoptStatus } from "./vault-adopt-status.ts"
import { vaultAskState } from "./vault-ask-state.ts"

export const TOOLS = [
  vaultStatus,
  vaultDoctor,
  vaultTemplates,
  vaultList,
  vaultShow,
  vaultCheck,
  vaultRequest,
  vaultConnect,
  vaultFetch,
  vaultPlan,
  vaultFill,
  vaultPush,
  vaultEnv,
  vaultWait,
  vaultPending,
  vaultPolicy,
  vaultMandate,
  vaultAdoptScan,
  vaultAdoptStatus,
]

// The tools only a card calls (MCP Apps visibility ["app"]): listed only to
// a host that negotiated MCP Apps, callable by any.
export const APP_TOOLS = [vaultAskState]

export { CORE_TOOLS, TOOLSETS, TOOLSETS_ENV, TOOLSET_NAMES, type Toolset, parseToolsets, resolveToolsets, toolsetOf, toolsetsValue } from "./toolsets.ts"

// The mehen command that does the work of each tool outside the core, for
// the refusal of a tool this server does not serve.
export const TOOL_COMMAND: Readonly<Record<string, string>> = {
  vault_doctor: "mehen doctor",
  vault_templates: "mehen templates",
  vault_show: "mehen show <item>",
  vault_check: "mehen check <item> <METHOD> <url>",
  vault_pending: "mehen pending",
  vault_connect: "mehen connect <provider> --name <slug> --reason <why>",
  vault_plan: "mehen plan submit <plan.json>",
  vault_fill: "mehen fill <item>#<field> --cdp <url> --selector <css>",
  vault_push: "mehen push <item> --to <destination> --reason <why>",
  vault_policy: "mehen policy ls",
  vault_mandate: "mehen mandate ls",
  vault_adopt_scan: "mehen adopt scan",
  vault_adopt_status: "mehen adopt status <adp_id>",
}

export function servedTools(toolsets: readonly Toolset[]): typeof TOOLS {
  const served = new Set<string>(toolsets.flatMap((name) => TOOLSETS[name]))
  return TOOLS.filter((t) => served.has(t.name))
}
