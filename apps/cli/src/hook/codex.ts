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

// What a patch adds: the lines it writes, without the ones it keeps or
// takes out, so removing a key from a file is never mistaken for adding
// one. The path is the first file the patch adds or changes.
export function patchWrites(patch: string): { path?: string; content: string } {
  const lines = patch.split("\n")
  const path = lines.map((line) => /^\*\*\* (?:Add|Update) File: (.+)$/.exec(line)?.[1]).find((p) => p !== undefined)
  const content = lines.filter((line) => line.startsWith("+")).map((line) => line.slice(1)).join("\n")
  return { ...(path ? { path: path.trim() } : {}), content }
}

export function codexToolCall(input: CodexInput): ToolCall {
  const cwd = str(input.cwd) ?? process.cwd()
  const args = typeof input.tool_input === "object" && input.tool_input !== null ? (input.tool_input as Record<string, unknown>) : {}
  const command = str(args.command)
  if (input.tool_name === "Bash") return { tool: "shell", command, cwd }
  if (input.tool_name === "apply_patch" && command !== undefined) return { tool: "write", ...patchWrites(command), cwd }
  return { tool: "other", cwd }
}

export function codexAnswer(input: CodexInput, env: Env): Record<string, unknown> | null {
  if (input.hook_event_name === "SessionStart") return { hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: SESSION_CONTEXT } }
  if (input.hook_event_name !== "PreToolUse") return null
  const verdict = judge(codexToolCall(input), guardLevel(env), env)
  if (verdict.decision === "deny") return { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: verdict.reason }, systemMessage: verdict.card }
  if (verdict.decision === "warn") return { systemMessage: verdict.card }
  return null
}
