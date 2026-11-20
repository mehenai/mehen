import type { Env } from "../config.ts"
import { CliError } from "../errors.ts"
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

// What a server lists. The core is always served, so an agent sees six
// tools unless the harness asks for more; each other tool is in one
// toolset, and `all` is every one. Listed in TOOLS order whatever is asked.
export const TOOLSETS = {
  core: ["vault_status", "vault_list", "vault_request", "vault_fetch", "vault_env", "vault_wait"],
  inspect: ["vault_doctor", "vault_templates", "vault_show", "vault_check", "vault_pending"],
  connect: ["vault_connect"],
  writes: ["vault_plan", "vault_fill", "vault_push"],
  policy: ["vault_policy", "vault_mandate"],
  adopt: ["vault_adopt_scan", "vault_adopt_status"],
} as const satisfies Record<string, readonly string[]>

export type Toolset = keyof typeof TOOLSETS
export const TOOLSET_NAMES = Object.keys(TOOLSETS) as Toolset[]
export const CORE_TOOLS: readonly string[] = TOOLSETS.core
export const TOOLSETS_ENV = "MEHEN_MCP_TOOLSETS"

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

const isToolset = (name: string): name is Toolset => Object.hasOwn(TOOLSETS, name)

export function toolsetOf(tool: string): Toolset | null {
  return TOOLSET_NAMES.find((name) => (TOOLSETS[name] as readonly string[]).includes(tool)) ?? null
}

// A comma-separated list as --toolsets or MEHEN_MCP_TOOLSETS gives it: the
// core first, then each named toolset once, in the order named.
export function parseToolsets(text: string, source: string): Toolset[] {
  const names = text.split(",").map((name) => name.trim()).filter((name) => name !== "")
  const unknown = names.filter((name) => name !== "all" && !isToolset(name))
  if (names.length === 0 || unknown.length > 0) {
    const what = names.length === 0 ? "names no toolset" : `names ${unknown.map((name) => JSON.stringify(name)).join(", ")}, which ${unknown.length === 1 ? "is not a toolset" : "are not toolsets"}`
    throw new CliError("usage", `${source} ${what}. The toolsets are ${[...TOOLSET_NAMES, "all"].join(", ")}.`, { say: "Give a comma-separated list of toolsets, such as `mehen mcp --toolsets inspect,connect`, or all for every tool.", command: "mehen mcp --help" })
  }
  if (names.includes("all")) return [...TOOLSET_NAMES]
  return [...new Set<Toolset>(["core", ...names.filter(isToolset)])]
}

// The flag, else the environment, else the core alone.
export function resolveToolsets(flag: string | null, env: Env): Toolset[] {
  if (flag !== null) return parseToolsets(flag, "--toolsets")
  const set = env[TOOLSETS_ENV]
  return set === undefined ? ["core"] : parseToolsets(set, TOOLSETS_ENV)
}

export function servedTools(toolsets: readonly Toolset[]): typeof TOOLS {
  const served = new Set<string>(toolsets.flatMap((name) => TOOLSETS[name]))
  return TOOLS.filter((t) => served.has(t.name))
}
