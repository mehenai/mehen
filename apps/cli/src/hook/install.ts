// Puts the guard hooks into the agents that can run them, and takes them
// out again. Only the entries mehen wrote are ever touched: a hook group is
// mehen's when its one command is `<mehen> hook <harness>`, and a sandbox
// path is mehen's when it is one of the vault's data folders. The file is
// backed up once, the first time mehen changes it, and written atomically.

import { rmSync } from "node:fs"
import { rm } from "node:fs/promises"
import { join } from "node:path"
import { PI_EXTENSION_FILE, PI_MARKER, piExtension } from "./pi.ts"
import { atomicText, info, textFile } from "../setup/files.ts"
import { shellWord } from "../shell-word.ts"
import { object, parseJson } from "../setup/formats.ts"

export type GuardStatus = "added" | "updated" | "unchanged" | "removed" | "skipped"
export type GuardResult = { agent: "claude-code" | "pi"; status: GuardStatus; file: string; sandbox?: "protected" | "off" | "unchanged"; reason?: string }

// Claude Code's tools the guard looks at; the rest never reach it.
export const CLAUDE_TOOLS = "Read|Grep|Glob|Bash|Write|Edit|MultiEdit|NotebookEdit"
const HOOK_TIMEOUT_SECONDS = 10


export function claudeHookCommand(binary: string): string {
  return `${shellWord(binary)} hook claude-code`
}

const OURS = /(^|[/'])mehen'? hook claude-code$/

type Group = { matcher?: unknown; hooks?: unknown }

function ours(group: unknown): boolean {
  if (!object(group) || !Array.isArray(group.hooks) || group.hooks.length !== 1) return false
  const hook = group.hooks[0] as unknown
  return object(hook) && hook.type === "command" && typeof hook.command === "string" && OURS.test(hook.command)
}

function withGroup(list: unknown, group: Group | null): unknown[] {
  const kept = (Array.isArray(list) ? list : []).filter((g) => !ours(g))
  return group ? [...kept, group] : kept
}

// The sandbox paths mehen added, per list, so removal takes out only those
// and never a path the person had there before.
export type SandboxOwned = { denyRead: string[]; denyWrite: string[] }
const NONE: SandboxOwned = { denyRead: [], denyWrite: [] }

function strings(list: unknown): string[] {
  return (Array.isArray(list) ? list : []).filter((p): p is string => typeof p === "string")
}

// The settings with mehen's entries put in (or, with remove, taken out), and
// which sandbox paths mehen now owns. Pure: the caller reads and writes the
// file and the ownership record.
export function claudeSettings(settings: Record<string, unknown>, binary: string, vaultDirs: string[], remove: boolean, owned: SandboxOwned = NONE): { settings: Record<string, unknown>; sandbox: GuardResult["sandbox"]; owned: SandboxOwned } {
  const next: Record<string, unknown> = structuredClone(settings)
  const hooks = object(next.hooks) ? next.hooks : {}
  const command = { type: "command", command: claudeHookCommand(binary), timeout: HOOK_TIMEOUT_SECONDS }
  hooks.PreToolUse = withGroup(hooks.PreToolUse, remove ? null : { matcher: CLAUDE_TOOLS, hooks: [command] })
  hooks.SessionStart = withGroup(hooks.SessionStart, remove ? null : { hooks: [command] })
  for (const event of ["PreToolUse", "SessionStart"]) if ((hooks[event] as unknown[]).length === 0) delete hooks[event]
  if (Object.keys(hooks).length) next.hooks = hooks
  else delete next.hooks
  // Claude Code's sandbox keeps the agent's shell out of these folders; its
  // MCP servers and hooks run outside it, so mehen mcp and mehen hook still
  // reach the vault. Paths are added only to a sandbox the person turned on.
  let sandbox: GuardResult["sandbox"] = "off"
  const nowOwned: SandboxOwned = { denyRead: [], denyWrite: [] }
  if (object(next.sandbox)) {
    const enabled = next.sandbox.enabled === true
    const filesystem = object(next.sandbox.filesystem) ? next.sandbox.filesystem : {}
    for (const key of ["denyRead", "denyWrite"] as const) {
      const before = strings(filesystem[key])
      // Ours from before that are not wanted now (a moved data folder, or all
      // of them on removal) go; the person's stay.
      const wanted = remove || !enabled ? [] : vaultDirs
      let list = before.filter((p) => !owned[key].includes(p) || wanted.includes(p))
      for (const dir of wanted) {
        if (!list.includes(dir)) {
          list = [...list, dir]
          nowOwned[key].push(dir)
        } else if (owned[key].includes(dir)) nowOwned[key].push(dir)
      }
      if (list.length) filesystem[key] = list
      else delete filesystem[key]
    }
    if (Object.keys(filesystem).length) next.sandbox.filesystem = filesystem
    else delete next.sandbox.filesystem
    if (enabled && !remove) sandbox = "protected"
  }
  return { settings: next, sandbox, owned: nowOwned }
}

function readOwned(text: string | null): SandboxOwned {
  if (text === null) return NONE
  try {
    const value = JSON.parse(text) as { claude?: Partial<SandboxOwned> }
    return { denyRead: strings(value.claude?.denyRead), denyWrite: strings(value.claude?.denyWrite) }
  } catch {
    return NONE
  }
}

export async function installClaudeGuard(options: { home: string; binary: string; vaultDirs: string[]; remove: boolean; dryRun: boolean; ownedFile?: string }): Promise<GuardResult> {
  const file = join(options.home, ".claude", "settings.json")
  const result: GuardResult = { agent: "claude-code", status: "skipped", file, sandbox: "unchanged" }
  if (!options.remove && !(await info(join(options.home, ".claude")))) return { ...result, reason: "Claude Code is not set up for this user (no ~/.claude folder)." }
  let text: string | null
  let settings: Record<string, unknown>
  try {
    text = await textFile(options.home, file)
    settings = text === null ? {} : parseJson(text)
  } catch (error) {
    return { ...result, status: "skipped", reason: `${file}: ${error instanceof Error ? error.message : String(error)}` }
  }
  const ownedText = options.ownedFile ? await Bun.file(options.ownedFile).text().catch(() => null) : null
  const owned = readOwned(ownedText)
  const { settings: next, sandbox, owned: nowOwned } = claudeSettings(settings, options.binary, options.vaultDirs, options.remove, owned)
  const same = JSON.stringify(next) === JSON.stringify(settings)
  if (same) return { ...result, status: "unchanged", sandbox: sandbox === "off" ? "off" : "unchanged" }
  const before = JSON.stringify(claudeSettings(settings, options.binary, options.vaultDirs, true, owned).settings) === JSON.stringify(settings)
  const status: GuardStatus = options.remove ? "removed" : before ? "added" : "updated"
  if (!options.dryRun) {
    if (text !== null && !(await info(`${file}.mehen-backup`))) await atomicText(options.home, `${file}.mehen-backup`, text)
    await atomicText(options.home, file, `${JSON.stringify(next, null, 2)}\n`, text)
    if (options.ownedFile) {
      if (nowOwned.denyRead.length || nowOwned.denyWrite.length) await Bun.write(options.ownedFile, `${JSON.stringify({ claude: nowOwned })}\n`, { mode: 0o600 })
      else rmSync(options.ownedFile, { force: true })
    }
  }
  return { ...result, status, sandbox }
}

// pi loads every file in ~/.pi/agent/extensions, so the guard is one file
// there that mehen owns while its first line is the marker.
export async function installPiGuard(options: { home: string; binary: string; remove: boolean; dryRun: boolean }): Promise<GuardResult> {
  const file = join(options.home, ".pi", "agent", "extensions", PI_EXTENSION_FILE)
  const result: GuardResult = { agent: "pi", status: "skipped", file }
  if (!(await info(join(options.home, ".pi")))) return { ...result, reason: options.remove ? undefined : "pi is not set up for this user (no ~/.pi folder)." }
  const current = await textFile(options.home, file)
  if (current !== null && !current.startsWith(PI_MARKER)) return { ...result, reason: `${file} is not mehen's, so it was left alone.` }
  if (options.remove) {
    if (current === null) return { ...result, status: "unchanged" }
    if (!options.dryRun) await rm(file)
    return { ...result, status: "removed" }
  }
  const wanted = piExtension(options.binary)
  if (current === wanted) return { ...result, status: "unchanged" }
  if (!options.dryRun) await atomicText(options.home, file, wanted, current)
  return { ...result, status: current === null ? "added" : "updated" }
}
