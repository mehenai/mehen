// mehen hook cursor: the guard in Cursor's agent hooks (~/.cursor/hooks.json).
// Cursor sends one JSON object per hook on stdin and reads a flat answer:
// { permission: "allow" | "deny", user_message, agent_message }. The guard
// runs on beforeShellExecution (the command), beforeReadFile (the file the
// agent is about to read), preToolUse for the Write tool (what it would
// write) and sessionStart (the note on using the vault). A permission hook
// must always answer with valid JSON, since Cursor blocks on anything else.

import { type ToolCall, type Verdict, SESSION_CONTEXT, guardLevel, judge } from "./index.ts"

type Env = Record<string, string | undefined>
export type CursorInput = { hook_event_name?: unknown; command?: unknown; cwd?: unknown; file_path?: unknown; tool_name?: unknown; tool_input?: unknown; workspace_roots?: unknown }
export type CursorAnswer = { permission: "allow" | "deny"; user_message?: string; agent_message?: string } | { additional_context: string }

const str = (value: unknown): string | undefined => (typeof value === "string" ? value : undefined)

// Every string in a value, depth first: the Write tool's input fields are
// not documented, so a key is looked for in all of them.
function strings(value: unknown): string[] {
  if (typeof value === "string") return [value]
  if (Array.isArray(value)) return value.flatMap(strings)
  if (typeof value === "object" && value !== null) return Object.values(value).flatMap(strings)
  return []
}

function cwdOf(input: CursorInput): string {
  const roots = Array.isArray(input.workspace_roots) ? input.workspace_roots : []
  return str(input.cwd) ?? str(roots[0]) ?? process.cwd()
}

export function cursorToolCall(input: CursorInput): ToolCall {
  const cwd = cwdOf(input)
  switch (input.hook_event_name) {
    case "beforeShellExecution":
      return { tool: "shell", command: str(input.command), cwd }
    case "beforeReadFile":
      return { tool: "read", path: str(input.file_path), cwd }
    case "preToolUse":
      return input.tool_name === "Write" ? { tool: "write", content: strings(input.tool_input).join("\n"), cwd } : { tool: "other", cwd }
    default:
      return { tool: "other", cwd }
  }
}

// beforeReadFile's answer has permission and user_message only; the shell
// and tool hooks also take agent_message, the reason the model reads.
function permission(event: unknown, verdict: Verdict): CursorAnswer {
  if (verdict.decision === "allow" || verdict.card === null) return { permission: "allow" }
  if (verdict.decision === "warn") return { permission: "allow", user_message: verdict.card }
  if (event === "beforeReadFile") return { permission: "deny", user_message: verdict.card }
  return { permission: "deny", user_message: verdict.card, ...(verdict.reason ? { agent_message: verdict.reason } : {}) }
}

export const CURSOR_PERMISSION_EVENTS = ["beforeShellExecution", "beforeReadFile", "preToolUse"] as const

export function cursorAnswer(input: CursorInput, env: Env): CursorAnswer | null {
  if (input.hook_event_name === "sessionStart") return { additional_context: SESSION_CONTEXT }
  if (!(CURSOR_PERMISSION_EVENTS as readonly unknown[]).includes(input.hook_event_name)) return null
  return permission(input.hook_event_name, judge(cursorToolCall(input), guardLevel(env), env))
}

// What a permission hook answers when the guard itself fails: a denial, so
// nothing passes unchecked.
export function cursorFailure(message: string): CursorAnswer {
  return { permission: "deny", user_message: `The Mehen guard could not check this call (${message}); run \`mehen doctor\` to see why.` }
}
