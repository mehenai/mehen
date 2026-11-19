// mehen hook: the guard an agent harness runs before each tool call. It
// reads the harness's hook JSON on stdin and answers in that harness's
// shape: deny (with the reason the model reads and a card the person
// sees), warn (the card only), or nothing. The guard level comes from
// MEHEN_GUARD, else <MEHEN_HOME>/guard.json, else block. A hook is never
// the security boundary (the vault's bindings are); it keeps the agent
// from reading or writing keys by accident or because a page told it to.

import { EXIT } from "@mehen/protocol/api"
import { existsSync, readFileSync, writeFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import { defaultDataDir } from "../../../local/src/config.ts"
import type { Command } from "../command.ts"
import { usageError } from "../errors.ts"
import { ensureSafeRoot, resolveHome } from "../home.ts"
import { printJson, printLine } from "../output.ts"
import { selfExecutable } from "../install-state.ts"
import { codexAnswer } from "./codex.ts"
import { cursorAnswer, cursorFailure } from "./cursor.ts"
import { type GuardResult, installGuards } from "./install.ts"
import { type Finding, commandFindings, secretFile, secretInText } from "./rules.ts"

export const GUARD_LEVELS = ["block", "warn", "off"] as const
export type GuardLevel = (typeof GUARD_LEVELS)[number]
export type ToolCall = { tool: "read" | "write" | "shell" | "other"; path?: string; content?: string; command?: string; cwd: string }
export type Verdict = { decision: "deny" | "warn" | "allow"; findings: Finding[]; reason: string | null; card: string | null }
type Env = Record<string, string | undefined>

const FIX = {
  "secret-file": "Use the keys through Mehen instead: `mehen ls` lists them, `mehen fetch <item> <METHOD> <url>` (or the vault_fetch tool) makes the call, and `mehen run -- <command>` gives a program its variables without them reaching you. To move this file's keys into the vault, ask the person to run `mehen adopt scan`.",
  "secret-in-command": "Put the key in the vault (`mehen request api-key --provider <id>`, a person fills it in) and make the call through `mehen fetch` or `mehen run`, so the value never appears in a command.",
  "secret-in-write": "Store the key in the vault (`mehen request api-key --provider <id>`) and write a reference to it instead (`mehen://<item>#key`).",
} as const

export function guardLevel(env: Env): GuardLevel {
  const fromEnv = env.MEHEN_GUARD
  if (fromEnv && (GUARD_LEVELS as readonly string[]).includes(fromEnv)) return fromEnv as GuardLevel
  try {
    const path = join(resolveHome(env).root, "guard.json")
    if (existsSync(path)) {
      const level = (JSON.parse(readFileSync(path, "utf8")) as { level?: unknown }).level
      if (typeof level === "string" && (GUARD_LEVELS as readonly string[]).includes(level)) return level as GuardLevel
    }
  } catch {
    return "block"
  }
  return "block"
}

// The folders the guard keeps the agent out of beyond the fixed ones: the
// local vault's data (the one mehen up recorded, and the default) and
// Mehen's own home, wherever MEHEN_HOME puts it.
export function vaultDirs(env: Env): string[] {
  const dirs = [defaultDataDir(env)]
  try {
    dirs.push(resolveHome(env).root)
  } catch {
    // A home that cannot be resolved has nothing in it to guard.
  }
  try {
    const record = join(resolveHome(env).root, "local-vault.json")
    if (existsSync(record)) {
      const data = (JSON.parse(readFileSync(record, "utf8")) as { data?: unknown }).data
      if (typeof data === "string") dirs.push(data)
    }
  } catch {
    // An unreadable record changes nothing: the default is still guarded.
  }
  return dirs
}

export function judge(call: ToolCall, level: GuardLevel, env: Env): Verdict {
  if (level === "off" || call.tool === "other") return { decision: "allow", findings: [], reason: null, card: null }
  const home = env.HOME || homedir()
  const dirs = vaultDirs(env)
  const findings: Finding[] = []
  if (call.tool === "read" && call.path) {
    const why = secretFile(call.path, call.cwd, home, dirs)
    if (why) findings.push({ rule: "secret-file", reason: `reading ${call.path} would show you its contents: ${why}`, path: call.path })
  }
  if (call.tool === "shell" && call.command) findings.push(...commandFindings(call.command, call.cwd, home, dirs))
  if (call.tool === "write" && call.content) {
    const inText = secretInText(call.content)
    if (inText) findings.push({ rule: "secret-in-write", reason: `the write to ${call.path ?? "the file"} carries ${inText}`, path: call.path })
  }
  if (findings.length === 0) return { decision: "allow", findings, reason: null, card: null }
  const first = findings[0] as Finding
  const reason = `Mehen ${level === "block" ? "blocked this" : "noticed this"}: ${first.reason}. ${FIX[first.rule]}`
  const card = level === "block" ? `Mehen blocked a tool call: ${first.reason}.` : `Mehen: ${first.reason}. Set the guard to block with \`mehen guard block\`.`
  return { decision: level === "block" ? "deny" : "warn", findings, reason, card }
}

// ---- Claude Code ------------------------------------------------------------

type ClaudeInput = { hook_event_name?: string; cwd?: string; tool_name?: string; tool_input?: Record<string, unknown> }

const str = (value: unknown): string | undefined => (typeof value === "string" ? value : undefined)

export function claudeToolCall(input: ClaudeInput): ToolCall {
  const cwd = str(input.cwd) ?? process.cwd()
  const args = input.tool_input ?? {}
  switch (input.tool_name) {
    case "Read":
      return { tool: "read", path: str(args.file_path), cwd }
    case "Grep":
    case "Glob":
      return str(args.path) ? { tool: "read", path: str(args.path), cwd } : { tool: "other", cwd }
    case "Bash":
      return { tool: "shell", command: str(args.command), cwd }
    case "Write":
      return { tool: "write", path: str(args.file_path), content: str(args.content), cwd }
    case "Edit":
      return { tool: "write", path: str(args.file_path), content: str(args.new_string), cwd }
    case "MultiEdit": {
      const edits = Array.isArray(args.edits) ? (args.edits as { new_string?: unknown }[]) : []
      return { tool: "write", path: str(args.file_path), content: edits.map((e) => str(e.new_string) ?? "").join("\n"), cwd }
    }
    case "NotebookEdit":
      return { tool: "write", path: str(args.notebook_path), content: str(args.new_source), cwd }
    default:
      return { tool: "other", cwd }
  }
}

export const SESSION_CONTEXT = "Mehen is on this machine. Keys stay in its vault and are never shown to you. To call an API with one, use the vault_fetch tool or `mehen fetch <item> <METHOD> <url>`; to run a program that needs its variables, `mehen run -- <command>`; `mehen ls` lists the keys you may use. Do not read .env files or other key files, and never paste a key into a command or a file: ask the person to add it with `mehen request`."

export function claudeAnswer(input: ClaudeInput, env: Env): Record<string, unknown> | null {
  if (input.hook_event_name === "SessionStart") return { hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: SESSION_CONTEXT } }
  if (input.hook_event_name !== "PreToolUse") return null
  const verdict = judge(claudeToolCall(input), guardLevel(env), env)
  if (verdict.decision === "deny") return { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: verdict.reason }, systemMessage: verdict.card }
  if (verdict.decision === "warn") return { systemMessage: verdict.card }
  return null
}

// ---- the neutral shape, for the pi extension and anything else -------------

type NeutralInput = { tool?: unknown; path?: unknown; content?: unknown; command?: unknown; cwd?: unknown }

export function neutralAnswer(input: NeutralInput, env: Env): Verdict {
  const tool = input.tool === "read" || input.tool === "write" || input.tool === "shell" ? input.tool : "other"
  return judge({ tool, path: str(input.path), content: str(input.content), command: str(input.command), cwd: str(input.cwd) ?? process.cwd() }, guardLevel(env), env)
}

export const HARNESSES = ["claude-code", "cursor", "codex", "check"] as const
type Harness = (typeof HARNESSES)[number]

// Cursor and Codex let a tool call through when a hook fails, unless it
// answers a denial (Cursor) or exits 2 with the reason on stderr (Codex):
// so whatever goes wrong here, those two are told to block.
const BLOCK = EXIT.usage

async function readInput(): Promise<Record<string, unknown>> {
  let input: unknown
  try {
    input = JSON.parse(await Bun.stdin.text())
  } catch {
    throw usageError("mehen hook reads one JSON object on stdin.", "mehen hook --help")
  }
  if (typeof input !== "object" || input === null || Array.isArray(input)) throw usageError("mehen hook reads one JSON object on stdin.", "mehen hook --help")
  return input as Record<string, unknown>
}

function answerFor(harness: Harness, input: Record<string, unknown>, env: Env): unknown {
  switch (harness) {
    case "check":
      return neutralAnswer(input, env)
    case "claude-code":
      return claudeAnswer(input as ClaudeInput, env)
    case "cursor":
      return cursorAnswer(input, env)
    case "codex":
      return codexAnswer(input, env)
  }
}

export const hookCommand: Command = {
  summary: "the guard an agent harness runs before each tool call: reads its hook JSON on stdin, answers deny, warn or nothing (mehen hook claude-code|cursor|codex|check)",
  spec: { usage: "mehen hook <claude-code|cursor|codex|check>", flags: {}, positionals: { min: 1, max: 1 } },
  examples: [["hook", "claude-code"], ["hook", "cursor"], ["hook", "codex"], ["hook", "check"]],
  notes: [
    "claude-code answers PreToolUse with permissionDecision deny and a systemMessage card, and SessionStart with a short note on using the vault.",
    "cursor answers beforeShellExecution, beforeReadFile and preToolUse (Write) with { permission, user_message, agent_message }, and sessionStart with additional_context; it answers a denial when it cannot check the call.",
    "codex answers PreToolUse (Bash, apply_patch) and SessionStart in Claude Code's shape; when it cannot check the call it exits 2 with the reason on stderr, which Codex reads as a block.",
    "check takes { tool: read|write|shell, path?, content?, command?, cwd } and prints { decision, reason, card, findings }, for any other harness.",
    "The level is MEHEN_GUARD, else guard.json in the mehen home, else block; warn shows the card without blocking, off says nothing.",
  ],
  async run({ args, env }) {
    const wanted = args.positionals[0]
    if (!(HARNESSES as readonly unknown[]).includes(wanted)) throw usageError(`mehen hook knows ${HARNESSES.join(", ")}, not ${JSON.stringify(wanted)}.`, "mehen hook --help")
    const harness = wanted as Harness
    if (harness === "claude-code" || harness === "check") {
      const answer = answerFor(harness, await readInput(), env)
      if (answer !== null) process.stdout.write(`${JSON.stringify(answer)}\n`)
      return EXIT.ok
    }
    let answer: unknown
    try {
      answer = answerFor(harness, await readInput(), env)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      if (harness === "cursor") {
        process.stdout.write(`${JSON.stringify(cursorFailure(message))}\n`)
        return EXIT.ok
      }
      process.stderr.write(`The Mehen guard could not check this call (${message}); run \`mehen doctor\` to see why.\n`)
      return BLOCK
    }
    if (answer !== null) process.stdout.write(`${JSON.stringify(answer)}\n`)
    return EXIT.ok
  },
}

const RESTART: Record<GuardResult["agent"], string> = {
  "claude-code": "restart Claude Code to pick it up",
  pi: "restart pi (or /reload) to pick it up",
  cursor: "Cursor reloads hooks.json by itself; restart it if the hooks do not show in its Hooks settings",
  codex: "restart Codex to pick it up",
}

export const guardCommand: Command = {
  summary: "the guard hooks: put them into your agents or take them out (install, remove), or set what they do (block, warn, off)",
  spec: { usage: "mehen guard [install|remove|block|warn|off] [--dry-run]", flags: { "dry-run": { type: "boolean" } }, positionals: { min: 0, max: 1 } },
  examples: [["guard"], ["guard", "install", "--json"], ["guard", "warn"], ["guard", "remove", "--dry-run"]],
  notes: [
    "install adds mehen's PreToolUse and SessionStart hooks to ~/.claude/settings.json (and, when Claude Code's sandbox is on, keeps the agent's shell out of the vault's data folder), a guard extension to ~/.pi/agent/extensions, mehen's hooks to ~/.cursor/hooks.json, and its PreToolUse and SessionStart hooks to ~/.codex/hooks.json ($CODEX_HOME when set), which Codex runs once you trust them in /hooks. remove takes out only what mehen wrote.",
    "The level is kept in guard.json in the mehen home; MEHEN_GUARD overrides it for one process.",
  ],
  async run({ args, json, env }) {
    const wanted = args.positionals[0]
    if (wanted === "install" || wanted === "remove") {
      const binary = selfExecutable(env)
      if (binary === null) throw usageError("The guard hooks name the installed mehen, and this one runs from source. Install mehen with `curl -fsSL https://mehen.dev/install | sh`, then run `mehen guard install`.", "mehen guard --help")
      const options = { home: env.HOME || homedir(), binary, remove: wanted === "remove", dryRun: args.bool("dry-run") }
      const { root } = resolveHome(env)
      ensureSafeRoot(root)
      const results = await installGuards({ ...options, vaultDirs: vaultDirs(env), ownedFile: join(root, "guard-installed.json"), codexHome: env.CODEX_HOME || undefined })
      if (json) printJson({ agents: results, ...(options.dryRun ? { dryRun: true } : {}) })
      else for (const result of results) {
        printLine(`${result.agent.padEnd(16)} guard ${result.status}${result.reason ? `: ${result.reason}` : ""}`)
        if (result.sandbox === "protected") printLine("                 the sandbox keeps the agent's shell out of the vault's data folder")
        if (result.sandbox === "off" && wanted === "install") printLine("                 turn Claude Code's sandbox on (/sandbox) and run `mehen guard install` again to keep the agent's shell out of the vault's files too")
        if (result.status === "added" || result.status === "updated" || result.status === "removed") printLine(`                 ${RESTART[result.agent]}`)
        if (result.next) printLine(`                 ${result.next}`)
      }
      return EXIT.ok
    }
    if (wanted !== undefined) {
      if (!(GUARD_LEVELS as readonly string[]).includes(wanted)) throw usageError(`mehen guard takes install, remove, block, warn or off, not ${JSON.stringify(wanted)}.`, "mehen guard --help")
      const { root } = resolveHome(env)
      ensureSafeRoot(root)
      writeFileSync(join(root, "guard.json"), `${JSON.stringify({ level: wanted })}\n`, { mode: 0o600 })
    }
    const level = guardLevel(env)
    if (json) printJson({ level, source: env.MEHEN_GUARD ? "MEHEN_GUARD" : "guard.json" })
    else printLine(`Guard: ${level}${env.MEHEN_GUARD ? " (from MEHEN_GUARD)" : ""}`)
    return EXIT.ok
  },
}
