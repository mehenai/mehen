// Puts the guard hooks into the agents that can run them, and takes them
// out again. Only the entries mehen wrote are ever touched: a hook group is
// mehen's when its one command is `<mehen> hook <harness>`, and a sandbox
// path is mehen's when it is one of the vault's data folders. The file is
// backed up once, the first time mehen changes it, and written atomically.

import { rmSync } from "node:fs"
import { rm } from "node:fs/promises"
import { isAbsolute, join, relative, resolve, sep } from "node:path"
import { PI_EXTENSION_FILE, PI_MARKER, piExtension } from "./pi.ts"
import { atomicText, info, textFile } from "../setup/files.ts"
import { shellWord } from "../shell-word.ts"
import { object, parseJson } from "../setup/formats.ts"

export type GuardStatus = "added" | "updated" | "unchanged" | "removed" | "skipped"
export type GuardAgent = "claude-code" | "pi" | "cursor" | "codex"
export type GuardResult = { agent: GuardAgent; status: GuardStatus; file: string; sandbox?: "protected" | "off" | "unchanged"; reason?: string; next?: string; absent?: true }

// Claude Code's tools the guard looks at; the rest never reach it.
export const CLAUDE_TOOLS = "Read|Grep|Glob|Bash|Write|Edit|MultiEdit|NotebookEdit"
const HOOK_TIMEOUT_SECONDS = 10


export function claudeHookCommand(binary: string): string {
  return `${shellWord(binary)} hook claude-code`
}

function oursPattern(harness: "claude-code" | "cursor" | "codex"): RegExp {
  return new RegExp(`(^|[/'])mehen'? hook ${harness}$`)
}
const OURS = oursPattern("claude-code")

type Group = { matcher?: unknown; hooks?: unknown }

function ours(group: unknown, pattern = OURS): boolean {
  if (!object(group) || !Array.isArray(group.hooks) || group.hooks.length !== 1) return false
  const hook = group.hooks[0] as unknown
  return object(hook) && hook.type === "command" && typeof hook.command === "string" && pattern.test(hook.command)
}

// Mehen's entry in a hook list: put where mehen's first one was (so a second
// install changes nothing), else at the end; any others of mehen's go.
function placed(list: unknown, entry: unknown, mine: (item: unknown) => boolean): unknown[] {
  const items = Array.isArray(list) ? (list as unknown[]) : []
  const at = items.findIndex(mine)
  const kept = items.filter((item) => !mine(item))
  if (entry === null) return kept
  if (at === -1) return [...kept, entry]
  return [...kept.slice(0, at), entry, ...kept.slice(at)]
}

function withGroup(list: unknown, group: Group | null, pattern = OURS): unknown[] {
  return placed(list, group, (g) => ours(g, pattern))
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
  if (!options.remove && !(await info(join(options.home, ".claude")))) return { ...result, absent: true, reason: "Claude Code is not set up for this user (no ~/.claude folder)." }
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
  if (!(await info(join(options.home, ".pi")))) return { ...result, absent: true, reason: options.remove ? undefined : "pi is not set up for this user (no ~/.pi folder)." }
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

// ---- Cursor and Codex: one hooks.json each ---------------------------------

type HooksFile = {
  agent: GuardAgent
  // The folder every read and write of the file is contained in.
  base: string
  file: string
  present: boolean
  missing: string
  edit: (config: Record<string, unknown>, remove: boolean) => Record<string, unknown>
  remove: boolean
  dryRun: boolean
}

function emptied(config: Record<string, unknown>): boolean {
  return Object.keys(config).every((key) => key === "version")
}

// Reads the file, puts mehen's entries in or takes them out, and writes it
// back only when that changes it. A file mehen made is deleted once nothing
// of the person's is in it; a file the person had (the backup says so) is
// kept, with only mehen's entries gone.
async function installHooksFile(options: HooksFile): Promise<GuardResult> {
  const result: GuardResult = { agent: options.agent, status: "skipped", file: options.file }
  if (!options.present) return { ...result, absent: true, reason: options.remove ? undefined : options.missing }
  let text: string | null
  let config: Record<string, unknown>
  try {
    text = await textFile(options.base, options.file)
    config = text === null ? {} : parseJson(text)
  } catch (error) {
    return { ...result, reason: `${options.file}: ${error instanceof Error ? error.message : String(error)}` }
  }
  if (options.remove && text === null) return { ...result, status: "unchanged" }
  const next = options.edit(config, options.remove)
  if (JSON.stringify(next) === JSON.stringify(config)) return { ...result, status: "unchanged" }
  const before = JSON.stringify(options.edit(config, true)) === JSON.stringify(config)
  const status: GuardStatus = options.remove ? "removed" : before ? "added" : "updated"
  if (!options.dryRun) {
    const backup = `${options.file}.mehen-backup`
    const backedUp = (await info(backup)) !== null
    if (text !== null && !backedUp) await atomicText(options.base, backup, text)
    if (options.remove && emptied(next) && !backedUp) await rm(options.file, { force: true })
    else await atomicText(options.base, options.file, `${JSON.stringify(next, null, 2)}\n`, text)
  }
  return { ...result, status }
}

function hooksObject(config: Record<string, unknown>): Record<string, unknown> {
  return object(config.hooks) ? config.hooks : {}
}

// Mehen's events left with no hook go, and the hooks object with them once
// it is empty; anything else of the person's stays as it was.
function settle(next: Record<string, unknown>, hooks: Record<string, unknown>, events: readonly string[]): Record<string, unknown> {
  for (const event of events) if (Array.isArray(hooks[event]) && (hooks[event] as unknown[]).length === 0) delete hooks[event]
  if (Object.keys(hooks).length) next.hooks = hooks
  else delete next.hooks
  return next
}

// Cursor: ~/.cursor/hooks.json, { version: 1, hooks: { <event>: [{ command,
// matcher?, timeout?, failClosed? }] } }. The shell, read and write hooks
// fail closed, so a guard that cannot answer (or a mehen that is gone)
// blocks the call rather than let it through unseen.
export const CURSOR_EVENTS = ["beforeShellExecution", "beforeReadFile", "preToolUse", "sessionStart"] as const
export const CURSOR_WRITE_MATCHER = "Write"
const CURSOR_OURS = oursPattern("cursor")

export function cursorHookCommand(binary: string): string {
  return `${shellWord(binary)} hook cursor`
}

function cursorOurs(entry: unknown): boolean {
  return object(entry) && (entry.type === undefined || entry.type === "command") && typeof entry.command === "string" && CURSOR_OURS.test(entry.command)
}

export function cursorHooks(config: Record<string, unknown>, binary: string, remove: boolean): Record<string, unknown> {
  const next: Record<string, unknown> = remove || config.version !== undefined ? structuredClone(config) : { version: 1, ...structuredClone(config) }
  const hooks = hooksObject(next)
  const command = cursorHookCommand(binary)
  const permission = { command, timeout: HOOK_TIMEOUT_SECONDS, failClosed: true }
  const wanted: Record<(typeof CURSOR_EVENTS)[number], Record<string, unknown>> = {
    beforeShellExecution: permission,
    beforeReadFile: permission,
    preToolUse: { ...permission, matcher: CURSOR_WRITE_MATCHER },
    sessionStart: { command, timeout: HOOK_TIMEOUT_SECONDS },
  }
  for (const event of CURSOR_EVENTS) {
    hooks[event] = placed(hooks[event], remove ? null : wanted[event], cursorOurs)
  }
  return settle(next, hooks, CURSOR_EVENTS)
}

export async function installCursorGuard(options: { home: string; binary: string; remove: boolean; dryRun: boolean }): Promise<GuardResult> {
  const dir = join(options.home, ".cursor")
  return installHooksFile({
    agent: "cursor",
    base: options.home,
    file: join(dir, "hooks.json"),
    present: (await info(dir)) !== null,
    missing: "Cursor is not set up for this user (no ~/.cursor folder).",
    edit: (config, remove) => cursorHooks(config, options.binary, remove),
    remove: options.remove,
    dryRun: options.dryRun,
  })
}

// Codex: $CODEX_HOME/hooks.json (~/.codex by default), the same event,
// matcher group and handler shape as Claude Code's settings. Codex runs a
// new or changed hook only once the person trusts it in /hooks.
export const CODEX_TOOLS = "Bash|apply_patch"
const CODEX_OURS = oursPattern("codex")
export const CODEX_TRUST = "Open /hooks in Codex and trust mehen's hooks: Codex skips a new or changed hook until you do."

export function codexHookCommand(binary: string): string {
  return `${shellWord(binary)} hook codex`
}

export function codexHooks(config: Record<string, unknown>, binary: string, remove: boolean): Record<string, unknown> {
  const next: Record<string, unknown> = structuredClone(config)
  const hooks = hooksObject(next)
  const command = { type: "command", command: codexHookCommand(binary), timeout: HOOK_TIMEOUT_SECONDS }
  hooks.PreToolUse = withGroup(hooks.PreToolUse, remove ? null : { matcher: CODEX_TOOLS, hooks: [command] }, CODEX_OURS)
  hooks.SessionStart = withGroup(hooks.SessionStart, remove ? null : { hooks: [command] }, CODEX_OURS)
  return settle(next, hooks, ["PreToolUse", "SessionStart"])
}

export function codexDir(home: string, codexHome: string | undefined): string {
  return codexHome ? resolve(home, codexHome) : join(home, ".codex")
}

const INLINE_HOOKS = /^\s*\[\[?\s*hooks[.\]\s]/m

export async function installCodexGuard(options: { home: string; binary: string; remove: boolean; dryRun: boolean; codexHome?: string }): Promise<GuardResult> {
  const dir = codexDir(options.home, options.codexHome)
  const rel = relative(options.home, dir)
  const inHome = rel !== "" && rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel)
  const result = await installHooksFile({
    agent: "codex",
    base: inHome ? options.home : dir,
    file: join(dir, "hooks.json"),
    present: (await info(dir)) !== null,
    missing: `Codex is not set up for this user (no ${options.codexHome ? "CODEX_HOME folder" : "~/.codex folder"}).`,
    edit: (config, remove) => codexHooks(config, options.binary, remove),
    remove: options.remove,
    dryRun: options.dryRun,
  })
  if (options.remove || (result.status !== "added" && result.status !== "updated")) return result
  const toml = await Bun.file(join(dir, "config.toml")).text().catch(() => "")
  const inline = INLINE_HOOKS.test(toml) ? `${join(dir, "config.toml")} also declares hooks; Codex loads both files and warns at startup.` : undefined
  return { ...result, next: CODEX_TRUST, ...(inline ? { reason: inline } : {}) }
}

// Every agent the guard knows, in the order mehen guard reports them.
export type GuardOptions = { home: string; binary: string; vaultDirs: string[]; ownedFile?: string; codexHome?: string; remove: boolean; dryRun: boolean }

export async function installGuards(options: GuardOptions): Promise<GuardResult[]> {
  return [
    await installClaudeGuard(options),
    await installPiGuard(options),
    await installCursorGuard(options),
    await installCodexGuard(options),
  ]
}
