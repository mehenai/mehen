import type { Env } from "../config.ts"
import { CliError } from "../errors.ts"

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

// Whether a server with these toolsets serves a tool.
export function serves(toolsets: readonly Toolset[], tool: string): boolean {
  return toolsets.some((name) => (TOOLSETS[name] as readonly string[]).includes(tool))
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

// What an agent entry's MEHEN_MCP_TOOLSETS says for these toolsets: `all`
// for every one, else the toolsets beyond the core (which it implies); null
// for the core alone, which needs no variable.
export function toolsetsValue(toolsets: readonly Toolset[]): string | null {
  const extra = TOOLSET_NAMES.filter((name) => name !== "core" && toolsets.includes(name))
  if (extra.length === TOOLSET_NAMES.length - 1) return "all"
  return extra.length === 0 ? null : extra.join(",")
}

