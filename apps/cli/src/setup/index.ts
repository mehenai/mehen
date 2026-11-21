import { createHash } from "node:crypto"
import { homedir } from "node:os"
import { isAbsolute, join, resolve } from "node:path"
import { readdir, rm } from "node:fs/promises"
import { EXIT } from "@mehen/protocol/api"
import type { VaultFileOptions } from "../agent-profiles.ts"
import type { ParsedArgs } from "../args.ts"
import type { Command } from "../command.ts"
import type { Env } from "../config.ts"
import { installedBinaryRequired, usageError } from "../errors.ts"
import { printBlock, printJson, printLine } from "../output.ts"
import { launchPath } from "../homebrew.ts"
import { isCompiledBinary } from "../version.ts"
import { TOOLSETS_ENV, type Toolset, parseToolsets, toolsetsValue } from "../mcp/registry.ts"
import { type Agent, MCP_FILE, type PinnedBase, agents, assertPinnedBase, envField, legacyServerKey, mcpFileAgent, pinMcpFileBase, recordedMcpFile, serverEntry } from "./agents.ts"
import { type SetupCeiling, printCeiling, resolveSetupCeiling } from "./ceiling.ts"
import { atomicText, FileChanged, info, textFile, unchanged } from "./files.ts"
import { DEFAULT_SERVER, editJson, editJsonText, editToml, jsonEntry, jsonEntryText, object, parseJson, tomlEntry, tomlRange, tomlTable } from "./formats.ts"
import { SKILL_BASES, SKILL_HASH, type SkillReport, type SkillStatus, installSkills, keptSkills, skillPath } from "./skills.ts"
import type { OwnedFile, State } from "./state.ts"

export type { SkillReport, SkillStatus } from "./skills.ts"

// The published shapes. AgentResult.mcp: `skipped` is a
// policy skip with its reason (a foreign or edited entry, an unowned
// backup, a retired variable, another root, a wider preserved ceiling);
// `failed` means the agent file could not be read, parsed or written, and
// setup exits 1. AgentResult.skill is null when the harness reads no
// skills folder.
export type AgentResult = { name: string; detected: boolean; mcp: "added" | "updated" | "unchanged" | "skipped" | "failed"; skill: SkillStatus | null; skillReason?: string; files: string[]; restart: string; server: "mehen"; reason?: string }
// `removed`: the retired `mehen-<slug>` entries this run took out, as
// `<file>#<server>`; `allowed` and `home`: the MEHEN_WORKSPACES and
// MEHEN_HOME a new entry gets (null: left out); `unenrolled`: allowed
// workspaces with no active slot yet; `files`: every file this run wrote
// or removed (with dryRun, would have).
export type SetupReport = { agents: AgentResult[]; skills: SkillReport[]; removed: string[]; unenrolled: string[]; allowed: string[] | null; home: string | null; files: string[]; next: string; dryRun?: true }
// `entry`: the JSON entry object, or the TOML table as text.
export type PrintResult = { printed: true; format: "json" | "toml"; server: "mehen"; entry: unknown; text: string; allowed: string[] | null; home: string | null }

// `toolsets`, when given, sets the entry's MEHEN_MCP_TOOLSETS (the core
// alone takes it out); absent, the entry keeps whatever it has.
export type SetupOptions = { home: string; binary: string; names?: string[]; mcpFile?: string; workspaces?: string | null; toolsets?: readonly Toolset[] | null; dryRun?: boolean; remove?: boolean; force?: boolean; resetEnv?: boolean; env?: Env; platform?: NodeJS.Platform; skillsOnly?: boolean; files?: VaultFileOptions; beforeWrite?: (path: string, attempt: number) => Promise<void> }

type PlanStatus = "added" | "updated" | "unchanged" | "skipped"

const NO_AGENT_NEXT = "No agent found on this machine, so no MCP entry was written. Install one and run mehen setup --json again, or name the agent you use with --agent <name> (--mcp-file <path> for another JSON MCP client)."

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical)
  if (object(value)) return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]))
  return value
}
const digest = (entry: unknown) => createHash("sha256").update(JSON.stringify(canonical(entry)) ?? "null").digest("hex")
function readState(text: string | null): State {
  if (text === null) return {}
  const value = parseJson(text)
  for (const v of Object.values(value)) if (!object(v) || typeof v.hash !== "string" || typeof v.existed !== "boolean" || (v.prefix !== undefined && typeof v.prefix !== "string") || (v.backup !== undefined && typeof v.backup !== "string") || (v.createdDirs !== undefined && (!Array.isArray(v.createdDirs) || !v.createdDirs.every(p => typeof p === "string")))) throw usageError("Invalid setup ownership file; fix or move it before running mehen setup --json again.")
  return value as State
}
function entry(agent: Agent, text: string, server: string): unknown { return agent.toml ? tomlEntry(text, server) : jsonEntry(text, agent.section, server) }
function tomlEnv(env: unknown): string {
  return object(env) ? `env = { ${Object.entries(env).map(([k, v]) => `${JSON.stringify(k)} = ${JSON.stringify(v)}`).join(", ")} }\n` : ""
}
function render(agent: Agent, text: string, expected: Record<string, unknown>, server: string): string {
  if (!agent.toml) {
    const rendered = editJson(text, agent.section, expected, false, server).text
    if (digest(jsonEntry(rendered, agent.section, server)) !== digest(expected)) throw usageError(`Unsupported ${server} JSON entry spelling; no settings were changed.`)
    return rendered
  }
  const args = Array.isArray(expected.args) ? expected.args : ["mcp"]
  const timeout = typeof expected.tool_timeout_sec === "number" ? `tool_timeout_sec = ${expected.tool_timeout_sec}\n` : ""
  const rendered = editToml(text, `[mcp_servers.${server}]\ncommand = ${JSON.stringify(expected.command)}\nargs = ${JSON.stringify(args)}\n${timeout}${tomlEnv(expected.env)}`, server)
  if (digest(tomlEntry(rendered, server)) !== digest(expected)) throw usageError(`Unsupported ${server} TOML table spelling; no settings were changed.`)
  return rendered
}
// The ownership key: the file alone for the `mehen` entry, the file and
// server for a retired `mehen-<slug>` registration.
function stateKey(agent: Agent, server: string): string {
  return server === DEFAULT_SERVER ? agent.key : `${agent.key}#${server}`
}
// The managed server entries this file has, by their ownership keys: the
// file's one backup belongs to all of them together.
// An --mcp-file has only its own key: it never had a retired server.
function siblingKeys(agent: Agent, state: State): string[] {
  return Object.keys(state).filter((key) => key === agent.key || (agent.name !== MCP_FILE && key.startsWith(`${agent.key}#${DEFAULT_SERVER}-`)))
}
// The retired per-workspace servers (`file#mehen-<slug>`, design 15.7)
// a known agent's file still has: the first new setup takes them out.
function retiredServers(agent: Agent, state: State): string[] {
  if (agent.name === MCP_FILE) return []
  return Object.keys(state).filter((key) => key.startsWith(`${agent.key}#${DEFAULT_SERVER}-`)).map((key) => key.slice(agent.key.length + 1))
}
// The MCP entries setup manages, every harness and file together: the
// skills stay while any remains.
function managedEntries(state: State): number {
  return Object.values(state).filter((owned) => owned.hash !== SKILL_HASH).length
}
// Removes one server's table from a TOML file together with the separator
// setup inserted before it, when that separator is still there.
function withoutTomlTable(text: string, server: string, owned: OwnedFile): string {
  const range = tomlRange(text, server)
  if (!range) return text
  const start = owned.prefix && text.slice(range.start - owned.prefix.length, range.start) === owned.prefix ? range.start - owned.prefix.length : range.start
  return text.slice(0, start) + text.slice(range.end)
}

// The env of the entry setup writes. A new entry, or one
// rebuilt by --reset-env, gets the effective ceiling and root of the
// process running setup and nothing else, so a restricted process never
// writes an entry wider than itself; an unrestricted one drops a stale
// restriction. An existing entry otherwise keeps its env key by key,
// except that a retired variable, a wider MEHEN_WORKSPACES, or a
// MEHEN_HOME or HOME that would make the launched server open another
// root than the one the ceiling was checked against skips the
// agent and writes nothing, and a missing ceiling or root is added.
function entryEnv(agent: Agent, current: unknown, ceiling: SetupCeiling, resetEnv: boolean, home: string): { env: Record<string, unknown> } | { skip: string } {
  const written: Record<string, string> = {}
  if (ceiling.allowed !== null) written.MEHEN_WORKSPACES = ceiling.allowed.join(",")
  if (ceiling.home !== null) written.MEHEN_HOME = ceiling.home
  const field = envField(agent)
  const preserved = object(current) && object(current[field]) ? current[field] : null
  if (resetEnv || preserved === null) return { env: written }
  for (const retired of ["MEHEN_CONFIG_DIR", "MEHEN_MANAGED_CONTEXT"]) {
    if (retired in preserved) return { skip: `The existing ${DEFAULT_SERVER} entry sets ${retired}, a retired variable; rerun with --reset-env.` }
  }
  const workspaces = preserved.MEHEN_WORKSPACES
  if (workspaces !== undefined) {
    const wider = typeof workspaces === "string" ? ceiling.wider(workspaces) : "its MEHEN_WORKSPACES is not a string"
    if (wider) return { skip: `workspace_not_allowed: the existing ${DEFAULT_SERVER} entry is wider than this setup may write: ${wider}. The harness widens MEHEN_WORKSPACES, nothing here can; rerun with --reset-env to narrow the entry.` }
  }
  const added: Record<string, string> = {}
  if (workspaces === undefined && written.MEHEN_WORKSPACES !== undefined) added.MEHEN_WORKSPACES = written.MEHEN_WORKSPACES
  if (preserved.MEHEN_HOME === undefined && written.MEHEN_HOME !== undefined) added.MEHEN_HOME = written.MEHEN_HOME
  const env = { ...preserved, ...added }
  const root = launchRoot(home, env)
  if (root !== ceiling.root) {
    const named = ["MEHEN_HOME", "HOME"].filter((name) => preserved[name] !== undefined).map((name) => `${name}=${JSON.stringify(preserved[name])}`).join(" and ")
    return { skip: `The existing ${DEFAULT_SERVER} entry sets ${named}, so the launched server would open ${root === null ? "a config root that cannot be verified" : `another config root (${root})`}, not ${ceiling.root}; run setup with that root, or rerun with --reset-env to point it at this root.` }
  }
  return { env }
}

// Claude Desktop runs no shell, so a next step that names a mehen command
// is one it cannot take: its entry serves the tools that do those steps
// unless --toolsets or the entry itself says otherwise.
export const AGENT_TOOLSETS: Partial<Record<Agent["name"], readonly Toolset[]>> = { "claude-desktop": ["core", "inspect", "connect"] }

// The toolsets an entry is written with: --toolsets when given, else the
// agent's own default for a new entry or one --reset-env clears, else null
// to keep what the entry has (--toolsets core taking it out included).
function entryToolsets(agent: Agent, fresh: boolean, toolsets: readonly Toolset[] | null): readonly Toolset[] | null {
  if (toolsets !== null || !fresh) return toolsets
  return AGENT_TOOLSETS[agent.name] ?? null
}

// The entry's env with MEHEN_MCP_TOOLSETS as --toolsets asked: written,
// taken out for the core alone, or left as it was without the flag.
function withToolsets(result: { env: Record<string, unknown> } | { skip: string }, toolsets: readonly Toolset[] | null): { env: Record<string, unknown> } | { skip: string } {
  if ("skip" in result || toolsets === null) return result
  const { [TOOLSETS_ENV]: _old, ...env } = result.env
  const value = toolsetsValue(toolsets)
  return { env: value === null ? env : { ...env, [TOOLSETS_ENV]: value } }
}

// The config root a launched entry opens: its
// MEHEN_HOME, else the default root of its HOME, which is the harness's own
// HOME unless the entry sets one. Null for a path that is not an absolute,
// non-empty string: no root can be verified for it.
function launchRoot(home: string, env: Record<string, unknown>): string | null {
  const path = (name: string): string | null | undefined => {
    const value = env[name]
    if (value === undefined) return undefined
    return typeof value === "string" && value.startsWith("/") && !value.includes("\0") ? resolve(value) : null
  }
  const explicit = path("MEHEN_HOME")
  if (explicit !== undefined) return explicit
  const own = path("HOME")
  if (own === null) return null
  return resolve(join(own ?? home, ".config", "mehen"))
}

// `retireBackup`: this removal takes the file's last managed entry, so the
// backup is restored or retired with it.
// handEdited: the entry setup wrote was since edited or removed by hand; the
// human's choice, so it needs no fixing.
type Plan = { before: string | null; after: string | null; status: PlanStatus; owned?: OwnedFile; reason?: string; retireBackup?: boolean; handEdited?: true }
// `backupGone`: a dry run has already planned the removal that retires
// this file's backup, so the next plan must not take it for a foreign one.
// `pin`: the identity of an external --mcp-file directory.
// `restoreCeiling`: the caller's ceiling a restored original entry is
// checked against: the resolved one when registering, resolved
// on first need when removing, or why it cannot be resolved.
type PlanContext = { home: string; binary: string; force: boolean; resetEnv: boolean; toolsets: readonly Toolset[] | null; ceiling: SetupCeiling | null; backupGone: boolean; pin: PinnedBase | null; restoreCeiling: () => Promise<SetupCeiling | { unverifiable: string }> }

// Why restoring the backup's original entry for a server would write an
// entry wider than the caller may, or null when it may come
// back. Removing an entry narrows nothing; bringing an original back adds
// a server, so it is held to what setup itself may write: no retired
// variable, the caller's root, and inside the caller's ceiling (a missing
// MEHEN_WORKSPACES is every workspace).
async function restorationRefused(context: PlanContext, agent: Agent, server: string, restored: unknown): Promise<string | null> {
  const left = `Removing setup's ${server} entry would bring back the original from ${agent.file}.mehen-backup`
  const keep = "left in place with its backup and ownership record; remove it from a process allowed that much, or edit the file by hand."
  const ceiling = await context.restoreCeiling()
  if ("unverifiable" in ceiling) return `${left}, and this process cannot check it against its own ceiling (${ceiling.unverifiable}); ${keep}`
  const field = envField(agent)
  const env = object(restored) && object(restored[field]) ? restored[field] : object(restored) && restored[field] === undefined ? {} : null
  if (env === null) return `${left}, whose env cannot be read; ${keep}`
  for (const retired of ["MEHEN_CONFIG_DIR", "MEHEN_MANAGED_CONTEXT"]) if (retired in env) return `${left}, which sets the retired variable ${retired}; ${keep}`
  const root = launchRoot(context.home, env)
  if (root !== ceiling.root) return `${left}, which would open ${root ?? "a config root that cannot be verified"}, not ${ceiling.root}; ${keep}`
  if (ceiling.allowed !== null) {
    const workspaces = env.MEHEN_WORKSPACES
    const wider = workspaces === undefined ? "it has no MEHEN_WORKSPACES, so it allows every workspace" : typeof workspaces === "string" ? ceiling.wider(workspaces) : "its MEHEN_WORKSPACES is not a string"
    if (wider) return `workspace_not_allowed: ${left}, which is wider than this process may write: ${wider}; ${keep}`
  }
  return null
}
async function planAgent(context: PlanContext, agent: Agent, server: string, remove: boolean, owned: OwnedFile | undefined, siblings: OwnedFile[]): Promise<Plan> {
  const { binary, force, resetEnv, ceiling } = context
  const base = agent.base
  await assertPinnedBase(context.pin)
  // An empty JSON settings file (VS Code creates mcp.json with no bytes)
  // holds nothing, so it reads as an empty object; its bytes are what a
  // removal restores.
  const settings = (raw: string) => !agent.toml && raw.trim() === "" ? "{}\n" : raw
  const before = await textFile(base, agent.file)
  const text = before === null ? (agent.toml ? "" : "{}\n") : settings(before)
  const current = entry(agent, text, server)
  if (agent.toml) tomlRange(text, server)
  if (remove) {
    if (!owned) return { before, after: before, status: "unchanged" }
    if (digest(current) !== owned.hash) return { before, after: before, status: "skipped", owned, reason: `The ${server} entry changed after setup; left alone. Restore it or remove it by hand, then run mehen setup --json again.` }
    // A file setup created has no backup: its original is the empty file.
    const saved = (await textFile(base, `${agent.file}.mehen-backup`)) ?? (owned.existed ? null : agent.toml ? "" : "{}\n")
    if (saved === null) throw usageError(`Missing setup backup for ${agent.file}; restore it before removing.`)
    const backup = settings(saved)
    const original = agent.toml ? tomlTable(backup, server) : null
    const restored = agent.toml ? tomlEntry(backup, server) : jsonEntry(backup, agent.section, server)
    if (restored !== undefined) {
      const refused = await restorationRefused(context, agent, server, restored)
      if (refused) return { before, after: before, status: "skipped", owned, reason: refused }
    }
    if (siblings.length > 0) {
      // Other managed servers stay in this file with its backup. This
      // server goes back to what the backup held for it (a forced original
      // entry is restored); one the backup never had goes, with the
      // separator written before it.
      const after = agent.toml
        ? original === null ? withoutTomlTable(text, server, owned) : editToml(text, original, server)
        : editJsonText(text, agent.section, jsonEntryText(backup, agent.section, server), true, server)
      return { before, after, status: "updated" }
    }
    // The last managed entry: back to the original bytes, or the original
    // absence, when nothing else changed since the backup; else just this
    // entry out, and an empty file we created goes.
    let after: string | null = agent.toml ? (original === null ? withoutTomlTable(text, server, owned) : editToml(text, original, server)) : editJsonText(text, agent.section, jsonEntryText(backup, agent.section, server), object(parseJson(backup)[agent.section]), server)
    if (object(current) && text === render(agent, backup, current, server)) after = owned.existed ? saved : null
    else if (!owned.existed && (agent.toml ? after.trim() === "" : Object.keys(parseJson(after)).length === 0)) after = null
    return { before, after, status: "updated", retireBackup: true }
  }
  if (current !== undefined && !owned && !force) return { before, after: before, status: "skipped", reason: `An existing ${server} entry was not written by setup; rerun with --force to replace it.` }
  // An entry setup wrote that was since edited or deleted by hand is the
  // human's now: left alone, ownership kept so removal refuses it too.
  if (owned && digest(current) !== owned.hash && !force) {
    return { before, after: before, status: "skipped", owned, handEdited: true, reason: current === undefined ? `The ${server} entry setup wrote was removed by hand since, so setup left it out; --force registers it again.` : `The ${server} entry changed after setup, by hand, so setup left it as it is; --force replaces it with setup's entry.` }
  }
  if (ceiling === null) throw new Error("setup registers an entry only with a resolved ceiling")
  const env = withToolsets(entryEnv(agent, current, ceiling, resetEnv, context.home), entryToolsets(agent, current === undefined || resetEnv, context.toolsets))
  if ("skip" in env) return { before, after: before, status: "skipped", ...(owned ? { owned } : {}), reason: env.skip }
  const expected = serverEntry(agent, binary, env.env)
  if (owned && digest(current) === digest(expected)) return { before, after: before, status: "unchanged", owned }
  // A backup is foreign only when no managed entry of this file owns it.
  if (!owned && siblings.length === 0 && !context.backupGone && await textFile(base, `${agent.file}.mehen-backup`) !== null) return { before, after: before, status: "skipped", reason: `An unowned setup backup already exists for ${agent.file}. Move it aside before setup; it was not overwritten.` }
  const after = render(agent, text, expected, server)
  const prefix = agent.toml && current === undefined ? after.slice(text.length, tomlRange(after, server)!.start) : owned?.prefix
  // Whether the file existed before setup touched it is what the first
  // managed entry recorded; a later entry inherits it.
  const existed = owned?.existed ?? siblings[0]?.existed ?? before !== null
  return { before, after, status: current === undefined ? "added" : "updated", owned: { hash: digest(expected), existed, ...(prefix ? { prefix } : {}) } }
}

// Plans and writes one server of one agent file, replanning once when the
// file changes under it, and records the ownership in `state`.
async function applyPlan(options: SetupOptions, context: PlanContext, agent: Agent, server: string, remove: boolean, state: State): Promise<Plan> {
  const key = stateKey(agent, server)
  for (let attempt = 0; ; attempt++) {
    const plan = await planAgent(context, agent, server, remove, state[key], siblingKeys(agent, state).filter((k) => k !== key).map((k) => state[k] as OwnedFile))
    let madeBackup = false
    try {
      if (!options.dryRun && plan.status !== "unchanged" && plan.status !== "skipped") {
        const backup = `${agent.file}.mehen-backup`
        const guard = async () => { await options.beforeWrite?.(agent.file, attempt); await assertPinnedBase(context.pin); await unchanged(agent.base, agent.file, plan.before) }
        const pinned = () => assertPinnedBase(context.pin)
        // One backup per file, taken at the first owned write of any server,
        // and only of a file that existed before setup first wrote it.
        if (!remove && plan.owned?.existed && plan.before !== null && await textFile(agent.base, backup) === null) {
          await atomicText(agent.base, backup, plan.before, undefined, pinned)
          madeBackup = true
        }
        if (plan.after === null) { await guard(); await rm(agent.file, { force: true }) }
        else await atomicText(agent.base, agent.file, plan.after, plan.before, guard)
        if (remove && plan.retireBackup) { await pinned(); await rm(backup, { force: true }) }
      }
      if (plan.owned) state[key] = plan.owned
      else delete state[key]
      return plan
    } catch (error) {
      if (madeBackup) await rm(`${agent.file}.mehen-backup`, { force: true })
      if (error instanceof FileChanged && attempt === 0) continue
      throw error
    }
  }
}

// Whether a harness is installed: its folder, its file or its binary. A
// folder holding nothing but setup's own (or a linked) skill is not one.
async function detect(agent: Agent, env: Env, home: string): Promise<boolean> {
  if (agent.dir === null || agent.binary === null) return true
  const fileExists = Boolean(await info(agent.file))
  let directoryExists = Boolean(await info(agent.dir))
  if (directoryExists && !fileExists && agent.name === "claude-code") {
    const contents = await readdir(agent.dir)
    if (contents.length === 1 && contents[0] === "skills") {
      const skillsDir = join(agent.dir, "skills")
      const skillNames = await readdir(skillsDir)
      const linked = (await info(skillsDir))?.isSymbolicLink() || (await info(join(skillsDir, "mehen")))?.isSymbolicLink() || (await info(join(skillsDir, "mehen/SKILL.md")))?.isSymbolicLink()
      const ownSkill = linked ? null : await textFile(home, join(skillsDir, "mehen/SKILL.md"))
      if (skillNames.length === 1 && skillNames[0] === "mehen" && (linked || ownSkill?.includes("\n  mehen-version:"))) directoryExists = false
    }
  }
  return directoryExists || fileExists || Boolean(Bun.which(agent.binary, { PATH: env.PATH ?? "" }))
}

// An --mcp-file is a generic JSON client's file: one whose top level has
// another client's server section and no mcpServers is that client's. A
// file that cannot be read or parsed is the agent loop's `failed`.
// Returns the directory pin the rest of the run keeps.
async function assertMcpFileShape(agent: Agent, home: string): Promise<PinnedBase | null> {
  const pin = await pinMcpFileBase(agent, home)
  let data: Record<string, unknown>
  try {
    const text = await textFile(agent.base, agent.file)
    if (text === null) return pin
    data = parseJson(text)
  } catch {
    return pin
  }
  if (data.mcpServers === undefined && (data.servers !== undefined || data.mcp !== undefined)) {
    const vscode = data.servers !== undefined
    throw usageError(`${agent.file} keeps its servers under ${vscode ? "servers" : "mcp"}, not mcpServers: it is another client's file, so register it with --agent ${vscode ? "vscode" : "opencode"} instead.`, "mehen setup --help")
  }
  return pin
}

export async function setup(options: SetupOptions): Promise<SetupReport> {
  const { home, binary, names = [], dryRun, remove = false, env = {}, skillsOnly } = options
  if (!isAbsolute(home) || !isAbsolute(binary)) throw usageError("Setup requires an absolute HOME and executable path.")
  const definitions = agents(home, options.platform)
  for (const name of names) if (!definitions.some(a => a.name === name)) throw usageError(`Unknown agent ${name}. Choose ${definitions.map(a => a.name).join(", ")}.`)
  const fileAgent = options.mcpFile === undefined || skillsOnly ? null : mcpFileAgent(home, options.mcpFile)
  // Both platforms' files: a state file may come from either.
  const known = [...agents(home, "darwin"), ...agents(home, "linux")]
  if (fileAgent && legacyServerKey(fileAgent.key, known)) throw usageError(`${fileAgent.file} would be recorded as ${fileAgent.key}, which reads as a retired server of another agent's file; name the file differently.`, "mehen setup --help")
  const filePin = fileAgent && !remove ? await assertMcpFileShape(fileAgent, home) : null
  // Registering needs the ceiling; removing and refreshing skills widen
  // nothing and run from any process.
  const ceiling = remove || skillsOnly ? null : await resolveSetupCeiling(env, home, options.workspaces ?? null, options.files)
  const statePath = join(home, ".config/mehen/setup-state.json")
  let originalState: string | null = null, state: State = {}, stateError: string | undefined
  try { originalState = await textFile(home, statePath); state = readState(originalState) }
  catch (error) { stateError = `${statePath}: ${error instanceof Error ? error.message : String(error)}` }
  const explicit = names.length > 0 || fileAgent !== null
  const targets: Agent[] = skillsOnly ? [] : [
    ...definitions.filter((agent) => !explicit || names.includes(agent.name)),
    ...(fileAgent ? [fileAgent] : []),
    // A whole removal takes every --mcp-file entry setup wrote too.
    ...(remove && !explicit ? Object.keys(state).filter((key) => state[key]?.hash !== SKILL_HASH).flatMap((key) => recordedMcpFile(home, key, known) ?? []) : []),
  ]
  let resolvedForRestore: Promise<SetupCeiling | { unverifiable: string }> | null = null
  const restoreCeiling = () => resolvedForRestore ??= ceiling !== null ? Promise.resolve(ceiling) : resolveSetupCeiling(env, home, null, options.files).catch((error: unknown) => ({ unverifiable: error instanceof Error ? error.message : String(error) }))
  const context: PlanContext = { home, binary, force: Boolean(options.force), resetEnv: Boolean(options.resetEnv), toolsets: options.toolsets ?? null, ceiling, backupGone: false, pin: null, restoreCeiling }
  const results: { agent: Agent; result: AgentResult }[] = []
  const handEdited = new Set<AgentResult>()
  const removed: string[] = []
  for (const agent of targets) {
    let detected = false
    const result: AgentResult = { name: agent.name, detected, mcp: "skipped", skill: null, files: [agent.file], restart: agent.restart, server: DEFAULT_SERVER }
    try {
      detected = agent.name === MCP_FILE || await detect(agent, env, home)
      result.detected = detected
      const retired = stateError ? [] : retiredServers(agent, state)
      if (!explicit && !detected && !(remove && state[agent.key]) && retired.length === 0) continue
      if (stateError) throw usageError(stateError)
      const notes: string[] = []
      // Every --mcp-file target, a removal or a recorded one included, has
      // its external directory pinned before anything is read.
      const agentContext = { ...context, pin: agent === fileAgent && filePin !== null ? filePin : await pinMcpFileBase(agent, home) }
      // The retired `mehen-<slug>` servers go first, through the sibling
      // removal path: one server serves every workspace now.
      for (const server of retired) {
        const plan = await applyPlan(options, agentContext, agent, server, true, state)
        if (plan.status === "updated") {
          removed.push(`${agent.file}#${server}`)
          if (dryRun && plan.retireBackup) agentContext.backupGone = true
        } else if (plan.reason) notes.push(plan.reason)
      }
      const plan = await applyPlan(options, agentContext, agent, DEFAULT_SERVER, remove, state)
      result.mcp = plan.status
      if (plan.handEdited && notes.length === 0) handEdited.add(result)
      if (plan.reason) notes.unshift(plan.reason)
      if (notes.length) result.reason = notes.join(" ")
    } catch (error) {
      if (!explicit && !detected) continue
      const message = error instanceof Error ? error.message : String(error)
      result.mcp = "failed"
      result.reason = `${agent.file}: ${message}${message.includes("mehen setup --json again") ? "" : " Fix or move this file, then run mehen setup --json again."}`
    }
    results.push({ agent, result })
  }
  // A removal keeps the skills while any managed entry still reads them;
  // they go with the last one, or with the whole installation.
  let skills: SkillReport[]
  if (stateError) skills = SKILL_BASES.map((base) => ({ path: skillPath(home, base), status: "failed", reason: stateError }))
  else if (remove && managedEntries(state) > 0) skills = keptSkills(home, managedEntries(state))
  else skills = await installSkills({ home, bases: results.flatMap(({ agent }) => agent.skills ?? []), dryRun, remove, force: options.force, skillsOnly, state })
  let stateWritten = false
  if (!dryRun && !stateError) {
    if (!Object.keys(state).length) { if (originalState !== null) { await rm(statePath); stateWritten = true } }
    else {
      const nextState = `${JSON.stringify(state, null, 2)}\n`
      if (nextState !== originalState) { await atomicText(home, statePath, nextState); stateWritten = true }
    }
  }
  for (const { agent, result } of results) {
    if (agent.skills === null) {
      result.skillReason = agent.name === "claude-desktop" ? "Claude Desktop does not read Agent Skills folders" : "mehen does not know which skills folder this client reads"
      continue
    }
    const skill = skills.find(s => s.path === skillPath(home, agent.skills as NonNullable<Agent["skills"]>))
    result.skill = skill?.status ?? null
    if (skill?.reason) result.skillReason = skill.reason
    if (skill) result.files.push(skill.path)
  }
  const agentResults = results.map(({ result }) => result)
  const wrote = (status: string) => status === "added" || status === "updated" || status === "removed"
  const files = [...new Set([...results.filter(({ result }) => wrote(result.mcp)).map(({ agent }) => agent.file), ...removed.map((entry) => entry.slice(0, entry.lastIndexOf("#"))), ...skills.filter((s) => wrote(s.status)).map((s) => s.path), ...(stateWritten ? [statePath] : [])])]
  const attention = agentResults.some((r) => (r.mcp === "skipped" && !handEdited.has(r)) || r.mcp === "failed") || skills.some((s) => s.status === "failed")
  const noAgent = !skillsOnly && !remove && agentResults.length === 0
  return {
    agents: agentResults,
    skills,
    removed,
    unenrolled: ceiling?.unenrolled ?? [],
    allowed: ceiling?.allowed ?? null,
    home: ceiling?.home ?? null,
    files,
    next: stateError ? `${stateError} Fix or move the ownership file, then run mehen setup --json again.` : attention ? "Fix what each skipped or failed entry's reason names, then run mehen setup --json again." : noAgent ? NO_AGENT_NEXT : ceiling?.enrolled ? "mehen status --json" : "mehen enrol --workspace <slug> --json",
    ...(dryRun ? { dryRun: true as const } : {}),
  }
}

// Exit codes: 1 when a skill or an agent's MCP entry
// failed; 2 when every agent was skipped and nothing was written; else 0.
// Skills-only setup has no agents, so it exits 1 only on a failed skill.
export function setupExitCode(report: SetupReport): number {
  if (report.agents.some((a) => a.mcp === "failed") || report.skills.some((s) => s.status === "failed")) return EXIT.error
  const nothing = report.removed.length === 0 && !report.skills.some((s) => s.status === "added" || s.status === "updated" || s.status === "removed")
  if (report.agents.length > 0 && report.agents.every((a) => a.mcp === "skipped") && nothing) return EXIT.usage
  return EXIT.ok
}

// `mehen setup --print`: the entry rendered from the environment
// alone. It reads the managed-host marker and nothing else, and writes
// nothing.
export function printSetup(options: { home: string; binary: string; env: Env; workspaces: string | null; format: "json" | "toml"; toolsets?: readonly Toolset[] | null; files?: VaultFileOptions }): PrintResult {
  if (!isAbsolute(options.home) || !isAbsolute(options.binary)) throw usageError("Setup requires an absolute HOME and executable path.")
  const { home, allowed } = printCeiling(options.env, options.home, options.workspaces, options.files)
  const env: Record<string, string> = {}
  if (allowed !== null) env.MEHEN_WORKSPACES = allowed.join(",")
  if (home !== null) env.MEHEN_HOME = home
  const toolsets = options.toolsets ? toolsetsValue(options.toolsets) : null
  if (toolsets !== null) env[TOOLSETS_ENV] = toolsets
  const json = { command: options.binary, args: ["mcp"], ...(Object.keys(env).length ? { env } : {}) }
  if (options.format === "json") return { printed: true, format: "json", server: DEFAULT_SERVER, entry: json, text: JSON.stringify({ mcpServers: { [DEFAULT_SERVER]: json } }, null, 2), allowed, home }
  const table = `[mcp_servers.${DEFAULT_SERVER}]\ncommand = ${JSON.stringify(options.binary)}\nargs = ["mcp"]\n${Object.keys(env).length ? tomlEnv(env) : ""}`
  return { printed: true, format: "toml", server: DEFAULT_SERVER, entry: table, text: table, allowed, home }
}

// The human report. A dry run says first that nothing was written, so its
// statuses read as what setup would do.
export function setupLines(report: SetupReport): string[] {
  const lines = report.dryRun ? ["Dry run: nothing was written. Without --dry-run, mehen setup would do this:"] : []
  for (const agent of report.agents) lines.push(`${agent.name.padEnd(16)} MCP ${agent.mcp.padEnd(9)} skill ${agent.skill ?? "none"}. ${agent.restart}${agent.reason ? ` ${agent.reason}` : ""}${agent.skillReason ? ` ${agent.skillReason}` : ""}`)
  for (const skill of report.skills) lines.push(`skill ${skill.status}: ${skill.path}${skill.reason ? ` (${skill.reason})` : ""}`)
  for (const entry of report.removed) lines.push(`removed the retired server ${entry}`)
  if (report.allowed !== null) lines.push(`MEHEN_WORKSPACES in each entry: ${report.allowed.join(",") || "(nothing)"}`)
  if (report.home !== null) lines.push(`MEHEN_HOME in each entry: ${report.home}`)
  lines.push(`next: ${report.next}`)
  return lines
}

export type SetupRequest = { print: { workspaces: string | null; format: "json" | "toml" } | null; names: string[]; mcpFile: string | null; workspaces: string | null; toolsets: Toolset[] | null; dryRun: boolean; remove: boolean; force: boolean; resetEnv: boolean }

// --toolsets as given: null without the flag. An empty value is refused
// rather than read as the core, which is spelled out to take the variable out.
function requestedToolsets(value: string | null): Toolset[] | null {
  if (value === null) return null
  if (value.trim() === "") throw usageError("--toolsets needs a toolset: --toolsets core takes MEHEN_MCP_TOOLSETS out of the entry, and --toolsets all serves every tool.", "mehen setup --help")
  return parseToolsets(value, "--toolsets")
}

// The flags, with every usage refusal decided before anything is read.
export function setupRequest(args: ParsedArgs): SetupRequest {
  if (args.string("workspace") !== null) throw usageError("mehen setup --workspace was removed: one mehen server serves every workspace this machine may use. Narrow the entry with --workspaces <a,b> instead.", "mehen setup --help")
  const format = args.string("format")
  const workspaces = args.string("workspaces")
  const request: SetupRequest = { print: null, names: args.list("agent"), mcpFile: args.string("mcp-file"), workspaces, toolsets: requestedToolsets(args.string("toolsets")), dryRun: args.bool("dry-run"), remove: args.bool("remove"), force: args.bool("force"), resetEnv: args.bool("reset-env") }
  if (!args.bool("print")) {
    if (format !== null) throw usageError("--format goes with --print.", "mehen setup --help")
    return request
  }
  const flags: [string, boolean][] = [["--remove", request.remove], ["--dry-run", request.dryRun], ["--force", request.force], ["--reset-env", request.resetEnv], ["--agent", request.names.length > 0], ["--mcp-file", request.mcpFile !== null]]
  const conflicts = flags.filter(([, set]) => set).map(([flag]) => flag)
  if (conflicts.length) throw usageError(`--print only renders the entry; it cannot be combined with ${conflicts.join(", ")}.`, "mehen setup --help")
  if (format !== null && format !== "json" && format !== "toml") throw usageError("--format is json or toml.", "mehen setup --help")
  return { ...request, print: { workspaces, format: format ?? "json" } }
}

// The mehen an agent's entry runs: this binary, or for a Homebrew keg the
// link brew keeps pointing at the current version, since brew deletes the
// keg itself on the next upgrade.
export function setupBinary(env: Env, binary: string = process.execPath): string {
  return launchPath(binary, env)
}

export const setupCommand: Command = {
  summary: "register the Mehen MCP server and skills in your installed agents, at user level",
  spec: {
    usage: "mehen setup [--agent <name>]... [--workspaces <a,b>] [--toolsets <names>] [--mcp-file <path>] [--remove] [--dry-run] [--force] [--reset-env] [--print [--format json|toml]]",
    flags: { agent: { type: "list" }, workspaces: { type: "string" }, toolsets: { type: "string" }, "mcp-file": { type: "string" }, "dry-run": { type: "boolean" }, remove: { type: "boolean" }, force: { type: "boolean" }, "reset-env": { type: "boolean" }, print: { type: "boolean" }, format: { type: "string" } },
    positionals: { min: 0, max: 0 },
  },
  examples: [["setup", "--json"], ["setup", "--agent", "codex", "--dry-run"], ["setup", "--workspaces", "acme", "--agent", "claude-code"], ["setup", "--toolsets", "all"], ["setup", "--mcp-file", "/path/to/mcp.json"], ["setup", "--print", "--format", "toml"], ["setup", "--remove"]],
  notes: [
    "Agents: claude-code, codex, cursor, pi, gemini, opencode, vscode, claude-desktop. Reload or restart afterwards.",
    "One `mehen` server per agent, always `mehen mcp`, serving every workspace this machine may use. The entry carries MEHEN_WORKSPACES when this shell is restricted or --workspaces narrows it (never wider than this shell), and MEHEN_HOME for a root other than ~/.config/mehen.",
    "--toolsets <names> writes MEHEN_MCP_TOOLSETS into each entry, so its server lists those MCP toolsets beside the core (inspect, connect, writes, policy, adopt, or all); --toolsets core takes it out. Without the flag an entry keeps the MEHEN_MCP_TOOLSETS it has; --reset-env alone drops it.",
    "--mcp-file writes mcpServers.mehen into any JSON MCP client's file. --print renders the entry and writes nothing.",
    "Symlinked and foreign skills and entries are left alone unless --force, which needs the human's agreement and still refuses unsafe files; read every entry's status and reason. Settings are backed up once; --remove only undoes entries still owned by setup, and the skills stay while another entry remains.",
    "Exit 1 when a skill or an agent file failed; 2 when every agent was skipped.",
  ],
  async run({ args, json, env }) {
    const request = setupRequest(args)
    const home = resolve(env.HOME ?? homedir())
    if (request.print) {
      // Rendered (and refused) from the environment first, then shown only
      // from an installed binary, whose path the entry names.
      const printed = printSetup({ home, binary: setupBinary(env), env, workspaces: request.print.workspaces, format: request.print.format, toolsets: request.toolsets })
      if (!isCompiledBinary()) throw installedBinaryRequired("setup")
      if (json) printJson(printed)
      else printBlock(printed.text)
      return EXIT.ok
    }
    if (!isCompiledBinary()) throw installedBinaryRequired("setup")
    const report = await setup({ home, binary: setupBinary(env), names: request.names, ...(request.mcpFile !== null ? { mcpFile: request.mcpFile } : {}), workspaces: request.workspaces, toolsets: request.toolsets, dryRun: request.dryRun, remove: request.remove, force: request.force, resetEnv: request.resetEnv, env, skillsOnly: env.MEHEN_SETUP_SKILLS_ONLY === "1" })
    if (json) printJson(report)
    else for (const line of setupLines(report)) printLine(line)
    return setupExitCode(report)
  },
}
