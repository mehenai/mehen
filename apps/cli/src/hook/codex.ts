// mehen hook codex: the guard in Codex's hooks ($CODEX_HOME/hooks.json).
// Codex has no file-read tool of its own: the agent reads files through
// its shell, so PreToolUse on Bash (shell commands and exec_command, both
// with tool_input.command) covers reads, and on apply_patch (the patch in
// tool_input.command) covers writes. The answer is Claude Code's shape,
// which Codex reads: hookSpecificOutput.permissionDecision deny with a
// reason, and systemMessage for the card.

import { type ToolCall, SESSION_CONTEXT, guardLevel, judge } from "./index.ts"

type Env = Record<string, string | undefined>
export type CodexInput = { hook_event_name?: unknown; cwd?: unknown; tool_name?: unknown; tool_input?: unknown }

const str = (value: unknown): string | undefined => (typeof value === "string" ? value : undefined)

// What a patch adds, file by file: the lines it writes, without the ones it
// keeps or takes out, so removing a key from a file is never mistaken for
// adding one. A moved file is named by where it goes; a deleted one adds
// nothing.
export type PatchWrite = { path: string; content: string }

export function patchWrites(patch: string): PatchWrite[] {
  const files: { path: string; lines: string[] }[] = []
  for (const line of patch.split("\n")) {
    const header = /^\*\*\* (Add|Update|Delete) File: (.+)$/.exec(line)
    if (header) {
      files.push({ path: (header[2] as string).trim(), lines: [] })
      continue
    }
    const current = files.at(-1)
    if (!current) continue
    const moved = /^\*\*\* Move to: (.+)$/.exec(line)
    if (moved) current.path = (moved[1] as string).trim()
    else if (line.startsWith("+")) current.lines.push(line.slice(1))
  }
  return files.filter((file) => file.lines.length > 0).map((file) => ({ path: file.path, content: file.lines.join("\n") }))
}

// The calls one Codex tool call makes, for the guard: one shell command, or
// one write per file a patch adds to.
export function codexToolCall(input: CodexInput): ToolCall[] {
  const cwd = str(input.cwd) ?? process.cwd()
  const args = typeof input.tool_input === "object" && input.tool_input !== null ? (input.tool_input as Record<string, unknown>) : {}
  const command = str(args.command)
  if (input.tool_name === "Bash") return [{ tool: "shell", command, cwd }]
  if (input.tool_name === "apply_patch" && command !== undefined) return patchWrites(command).map((write): ToolCall => ({ tool: "write", ...write, cwd }))
  return [{ tool: "other", cwd }]
}

export function codexAnswer(input: CodexInput, env: Env): Record<string, unknown> | null {
  if (input.hook_event_name === "SessionStart") return { hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: SESSION_CONTEXT } }
  if (input.hook_event_name !== "PreToolUse") return null
  const level = guardLevel(env)
  const verdict = codexToolCall(input).map((call) => judge(call, level, env)).find((v) => v.decision !== "allow")
  if (verdict === undefined) return null
  if (verdict.decision === "deny") return { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: verdict.reason }, systemMessage: verdict.card }
  if (verdict.decision === "warn") return { systemMessage: verdict.card }
  return null
}
