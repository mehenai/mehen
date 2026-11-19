// Puts the guard hooks into the agents that can run them, and takes them
// out again. Only the entries mehen wrote are ever touched: a hook is
// mehen's when its one command is exactly the `<mehen> hook <harness>` this
// file writes, and a sandbox path is mehen's when it is one of the vault's
// data folders. The file is backed up once, the first time mehen changes
// it, and written atomically.

import { realpathSync, rmSync } from "node:fs"
import { rm } from "node:fs/promises"
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path"
import { PI_EXTENSION_FILE, PI_MARKER, piExtension } from "./pi.ts"
import { checkUnique, hasComments, insertItem, patchItem, removeItem } from "./jsonc.ts"
import { FileChanged, atomicText, info, safePath, textFile, unchanged } from "../setup/files.ts"
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

export type HookHarness = "claude-code" | "cursor" | "codex"

// What shellWord makes of an argument, read back: the plain word, or the
// single-quoted one with its escaped quotes; null for anything else.
function unquoted(word: string): string | null {
  if (/^[A-Za-z0-9_./:@,=+%-]+$/.test(word)) return word
  if (word.length < 2 || !word.startsWith("'") || !word.endsWith("'")) return null
  return word.slice(1, -1).replaceAll("'\\''", "'")
}

// Whether a hook's command is one this file writes: an absolute path to a
// binary called mehen, quoted exactly as shellWord quotes it, then
// ` hook <harness>` and nothing else. A prefix, a wrapper, an extra
// argument or a shell operator makes it the person's.
export function ownsCommand(command: string, harness: HookHarness): boolean {
  const suffix = ` hook ${harness}`
  if (!command.endsWith(suffix)) return false
  const word = command.slice(0, -suffix.length)
  const binary = unquoted(word)
  return binary !== null && shellWord(binary) === word && isAbsolute(binary) && basename(binary) === "mehen"
}

type Group = { matcher?: unknown; hooks?: unknown }

function ours(group: unknown, harness: HookHarness = "claude-code"): boolean {
  if (!object(group) || !Array.isArray(group.hooks) || group.hooks.length !== 1) return false
  const hook = group.hooks[0] as unknown
  return object(hook) && hook.type === "command" && typeof hook.command === "string" && ownsCommand(hook.command, harness)
}

// Mehen's entry in a hook list: put where mehen's first one was (so a second
// install changes nothing), else at the end; any others of mehen's go.
function placed(list: unknown, entry: unknown, mine: (item: unknown) => boolean): unknown[] {
  if (list !== undefined && !Array.isArray(list)) throw new Error("placed() takes a list; check the shape first")
  const items = (list ?? []) as unknown[]
  const at = items.findIndex(mine)
  const kept = items.filter((item) => !mine(item))
  if (entry === null) return kept
  if (at === -1) return [...kept, entry]
  return [...kept.slice(0, at), entry, ...kept.slice(at)]
}

function withGroup(list: unknown, group: Group | null): unknown[] {
  return placed(list, group, (g) => ours(g))
}

// Why the containers mehen edits are not the shape it can edit, or null:
// hooks an object, each of mehen's events a list, Cursor's version a
// positive integer. Anything else is skipped with the file untouched.
export function shapeProblem(config: Record<string, unknown>, events: readonly string[], cursor = false): string | null {
  if (config.hooks !== undefined && !object(config.hooks)) return "hooks must be an object"
  const hooks = object(config.hooks) ? config.hooks : {}
  for (const event of events) if (hooks[event] !== undefined && !Array.isArray(hooks[event])) return `hooks.${event} must be a list`
  if (cursor && config.version !== undefined && !(typeof config.version === "number" && Number.isInteger(config.version) && config.version > 0)) return "version must be a positive integer"
  return null
}

function shapeReason(file: string, problem: string): string {
  return `${file}: ${problem}, so mehen changed nothing; fix the file, then run mehen guard again.`
}

const CHANGED = (file: string) => `${file} changed while mehen guard ran, so mehen left it as it is; run mehen guard again.`

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
  const problem = shapeProblem(settings, ["PreToolUse", "SessionStart"])
  if (problem) return { ...result, reason: shapeReason(file, problem) }
  const ownedText = options.ownedFile ? await Bun.file(options.ownedFile).text().catch(() => null) : null
  const owned = readOwned(ownedText)
  const { settings: next, sandbox, owned: nowOwned } = claudeSettings(settings, options.binary, options.vaultDirs, options.remove, owned)
  const same = JSON.stringify(next) === JSON.stringify(settings)
  if (same) return { ...result, status: "unchanged", sandbox: sandbox === "off" ? "off" : "unchanged" }
  const before = JSON.stringify(claudeSettings(settings, options.binary, options.vaultDirs, true, owned).settings) === JSON.stringify(settings)
  const status: GuardStatus = options.remove ? "removed" : before ? "added" : "updated"
  if (!options.dryRun) {
    if (text !== null && !(await info(`${file}.mehen-backup`))) await atomicText(options.home, `${file}.mehen-backup`, text)
    try {
      await atomicText(options.home, file, `${JSON.stringify(next, null, 2)}\n`, text)
    } catch (error) {
      if (error instanceof FileChanged) return { ...result, reason: CHANGED(file) }
      throw error
    }
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

// One of mehen's events in a hooks.json: the entry it wants there (null to
// take it out) and how to tell its own entries from the person's.
type EventEdit = { event: string; entry: unknown; mine: (item: unknown) => boolean }

type HooksFile = {
  agent: GuardAgent
  // The folder every read and write of the file is contained in.
  base: string
  file: string
  present: boolean
  missing: string
  // What a file mehen makes starts as.
  empty: string
  events: (remove: boolean) => EventEdit[]
  cursor: boolean
  remove: boolean
  dryRun: boolean
  // Runs just before the file is replaced or deleted; tests change the
  // file here to prove a concurrent edit is never lost.
  beforeWrite?: () => Promise<void>
}

// Puts mehen's entry for one event in place, or takes it out, editing the
// text so everything else in it, comments included, stays as it was. The
// entry goes where mehen's first one was, so a second install changes
// nothing, and an event or hooks object mehen emptied goes too.
function editEvent(text: string, edit: EventEdit): string {
  const data = parseJson(text)
  const hooks = object(data.hooks) ? data.hooks : undefined
  const list = hooks && Array.isArray(hooks[edit.event]) ? (hooks[edit.event] as unknown[]) : undefined
  const at = (list ?? []).flatMap((item, i) => (edit.mine(item) ? [i] : []))
  if (edit.entry === null) {
    if (!hooks || !list || at.length === 0) return text
    if (at.length === list.length) {
      const without = removeItem(text, ["hooks"], edit.event)
      return Object.keys(hooks).length === 1 ? removeItem(without, [], "hooks") : without
    }
    return at.reverse().reduce((t, i) => removeItem(t, ["hooks", edit.event], i), text)
  }
  if (!hooks) return insertItem(text, [], "hooks", { [edit.event]: [edit.entry] })
  if (!list) return insertItem(text, ["hooks"], edit.event, [edit.entry])
  const [first, ...rest] = at
  if (first === undefined) return insertItem(text, ["hooks", edit.event], undefined, edit.entry)
  const trimmed = rest.reverse().reduce((t, i) => removeItem(t, ["hooks", edit.event], i), text)
  return patchItem(trimmed, ["hooks", edit.event, first], list[first], edit.entry)
}

function editHooks(text: string, events: EventEdit[], cursor: boolean, remove: boolean): string {
  let next = events.reduce(editEvent, text)
  if (cursor && !remove && parseJson(next).version === undefined) next = insertItem(next, [], "version", 1)
  return next
}

function hasOurs(config: Record<string, unknown>, events: EventEdit[]): boolean {
  const hooks = object(config.hooks) ? config.hooks : {}
  return events.some((edit) => Array.isArray(hooks[edit.event]) && (hooks[edit.event] as unknown[]).some(edit.mine))
}

// Reads the file, puts mehen's entries in or takes them out, and writes it
// back only when that changes it. A file mehen made is recorded beside it
// (`.mehen-created`), and only that record lets removal delete it, once
// nothing of the person's is left; a file the person had is backed up
// once and never deleted.
async function installHooksFile(options: HooksFile): Promise<GuardResult> {
  const result: GuardResult = { agent: options.agent, status: "skipped", file: options.file }
  if (!options.present) return { ...result, absent: true, reason: options.remove ? undefined : options.missing }
  const events = options.events(options.remove)
  let text: string | null
  let next: string
  let hadOurs: boolean
  try {
    text = await textFile(options.base, options.file)
    const config = text === null ? {} : parseJson(text)
    const problem = shapeProblem(config, events.map((e) => e.event), options.cursor)
    if (problem) return { ...result, reason: shapeReason(options.file, problem) }
    for (const edit of events) checkUnique(text ?? "{}", ["hooks", edit.event])
    if (options.cursor) checkUnique(text ?? "{}", ["version"])
    if (options.remove && text === null) return { ...result, status: "unchanged" }
    hadOurs = hasOurs(config, events)
    next = editHooks(text ?? options.empty, events, options.cursor, options.remove)
    parseJson(next)
  } catch (error) {
    return { ...result, reason: `${options.file}: ${error instanceof Error ? error.message : String(error)}` }
  }
  if (next === text) return { ...result, status: "unchanged" }
  const status: GuardStatus = options.remove ? "removed" : hadOurs ? "updated" : "added"
  if (options.dryRun) return { ...result, status }
  const backup = `${options.file}.mehen-backup`
  const created = `${options.file}.mehen-created`
  const made = (await info(created)) !== null
  try {
    if (text !== null && !made && !(await info(backup))) await atomicText(options.base, backup, text)
    const left = parseJson(next)
    if (options.remove && made && Object.keys(left).every((key) => key === "version") && !hasComments(next)) {
      await options.beforeWrite?.()
      await unchanged(options.base, options.file, text)
      await safePath(options.base, options.file)
      await rm(options.file)
    } else await atomicText(options.base, options.file, next, text, options.beforeWrite)
  } catch (error) {
    if (error instanceof FileChanged) return { ...result, reason: CHANGED(options.file) }
    throw error
  }
  if (options.remove) await rm(created, { force: true })
  else if (text === null) await atomicText(options.base, created, "Written by mehen guard install: mehen made the file beside this one, so mehen guard remove may delete it once nothing else is in it.\n")
  return { ...result, status }
}

function eventEdits(wanted: Record<string, unknown>, remove: boolean, mine: (item: unknown) => boolean): EventEdit[] {
  return Object.entries(wanted).map(([event, entry]) => ({ event, entry: remove ? null : entry, mine }))
}

// Cursor: ~/.cursor/hooks.json, { version: 1, hooks: { <event>: [{ command,
// matcher?, timeout?, failClosed? }] } }. The shell, read and write hooks
// fail closed, so a guard that cannot answer (or a mehen that is gone)
// blocks the call rather than let it through unseen.
export const CURSOR_EVENTS = ["beforeShellExecution", "beforeReadFile", "preToolUse", "sessionStart"] as const
export const CURSOR_WRITE_MATCHER = "Write"

export function cursorHookCommand(binary: string): string {
  return `${shellWord(binary)} hook cursor`
}

function cursorOurs(entry: unknown): boolean {
  return object(entry) && (entry.type === undefined || entry.type === "command") && typeof entry.command === "string" && ownsCommand(entry.command, "cursor")
}

function cursorEvents(binary: string, remove: boolean): EventEdit[] {
  const command = cursorHookCommand(binary)
  const permission = { command, timeout: HOOK_TIMEOUT_SECONDS, failClosed: true }
  const wanted: Record<(typeof CURSOR_EVENTS)[number], Record<string, unknown>> = {
    beforeShellExecution: permission,
    beforeReadFile: permission,
    preToolUse: { ...permission, matcher: CURSOR_WRITE_MATCHER },
    sessionStart: { command, timeout: HOOK_TIMEOUT_SECONDS },
  }
  return eventEdits(wanted, remove, cursorOurs)
}

const CURSOR_EMPTY = '{\n  "version": 1\n}\n'

// The same edit on a parsed object, for callers and tests that hold one.
export function cursorHooks(config: Record<string, unknown>, binary: string, remove: boolean): Record<string, unknown> {
  return parseJson(editHooks(JSON.stringify(config, null, 2), cursorEvents(binary, remove), true, remove))
}

export async function installCursorGuard(options: { home: string; binary: string; remove: boolean; dryRun: boolean; beforeWrite?: () => Promise<void> }): Promise<GuardResult> {
  const dir = join(options.home, ".cursor")
  return installHooksFile({
    agent: "cursor",
    base: options.home,
    file: join(dir, "hooks.json"),
    present: (await info(dir)) !== null,
    missing: "Cursor is not set up for this user (no ~/.cursor folder).",
    empty: CURSOR_EMPTY,
    events: (remove) => cursorEvents(options.binary, remove),
    cursor: true,
    remove: options.remove,
    dryRun: options.dryRun,
    beforeWrite: options.beforeWrite,
  })
}

// Codex: $CODEX_HOME/hooks.json (~/.codex by default), the same event,
// matcher group and handler shape as Claude Code's settings. Codex runs a
// new or changed hook only once the person trusts it in /hooks.
export const CODEX_TOOLS = "Bash|apply_patch"
export const CODEX_TRUST = "Open /hooks in Codex and trust mehen's hooks: Codex skips a new or changed hook until you do."

export function codexHookCommand(binary: string): string {
  return `${shellWord(binary)} hook codex`
}

function codexEvents(binary: string, remove: boolean): EventEdit[] {
  const command = { type: "command", command: codexHookCommand(binary), timeout: HOOK_TIMEOUT_SECONDS }
  return eventEdits({ PreToolUse: { matcher: CODEX_TOOLS, hooks: [command] }, SessionStart: { hooks: [command] } }, remove, (g) => ours(g, "codex"))
}

export function codexHooks(config: Record<string, unknown>, binary: string, remove: boolean): Record<string, unknown> {
  return parseJson(editHooks(JSON.stringify(config, null, 2), codexEvents(binary, remove), false, remove))
}

// Where Codex keeps its files: CODEX_HOME as Codex reads it (a relative one
// against the working directory, then its real path), else ~/.codex.
export function codexDir(home: string, codexHome: string | undefined, cwd = process.cwd()): string {
  if (!codexHome) return join(home, ".codex")
  const dir = resolve(cwd, codexHome)
  try {
    return realpathSync(dir)
  } catch {
    return dir
  }
}

const INLINE_HOOKS = /^\s*\[\[?\s*hooks[.\]\s]/m

export async function installCodexGuard(options: { home: string; binary: string; remove: boolean; dryRun: boolean; codexHome?: string; cwd?: string; beforeWrite?: () => Promise<void> }): Promise<GuardResult> {
  const dir = codexDir(options.home, options.codexHome, options.cwd)
  const rel = relative(options.home, dir)
  const inHome = rel !== "" && rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel)
  const result = await installHooksFile({
    agent: "codex",
    base: inHome ? options.home : dir,
    file: join(dir, "hooks.json"),
    present: (await info(dir)) !== null,
    missing: `Codex is not set up for this user (no ${options.codexHome ? `CODEX_HOME folder at ${dir}` : "~/.codex folder"}).`,
    empty: "{}\n",
    events: (remove) => codexEvents(options.binary, remove),
    cursor: false,
    remove: options.remove,
    dryRun: options.dryRun,
    beforeWrite: options.beforeWrite,
  })
  if (options.remove || (result.status !== "added" && result.status !== "updated")) return result
  const toml = await Bun.file(join(dir, "config.toml")).text().catch(() => "")
  const inline = INLINE_HOOKS.test(toml) ? `${join(dir, "config.toml")} also declares hooks; Codex loads both files and warns at startup.` : undefined
  return { ...result, next: CODEX_TRUST, ...(inline ? { reason: inline } : {}) }
}

// Every agent the guard knows, in the order mehen guard reports them.
export type GuardOptions = { home: string; binary: string; vaultDirs: string[]; ownedFile?: string; codexHome?: string; cwd?: string; remove: boolean; dryRun: boolean }

export async function installGuards(options: GuardOptions): Promise<GuardResult[]> {
  return [
    await installClaudeGuard(options),
    await installPiGuard(options),
    await installCursorGuard(options),
    await installCodexGuard(options),
  ]
}
