// The guard for pi: an extension file mehen writes to ~/.pi/agent/extensions,
// which pi loads by itself. On each tool call it asks `mehen hook check` and
// blocks what the guard denies, with a notice for the person. The file
// names the installed mehen, so it is rewritten when that path changes, and
// it is mehen's only while its first line is the marker below.

export const PI_MARKER = "// Written by mehen guard install. mehen guard remove takes it out; edits are lost on the next install."
export const PI_EXTENSION_FILE = "mehen-guard.ts"

export function piExtension(binary: string): string {
  return `${PI_MARKER}
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent"
import { spawnSync } from "node:child_process"

const MEHEN = ${JSON.stringify(binary)}

type Verdict = { decision: "deny" | "warn" | "allow"; reason: string | null; card: string | null }

function text(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined
}

// What pi's built-in tools carry, in the guard's neutral shape.
function call(toolName: string, input: Record<string, unknown>, cwd: string) {
  if (toolName === "bash") return { tool: "shell", command: text(input.command), cwd }
  if (toolName === "read" || toolName === "grep" || toolName === "find" || toolName === "ls") return { tool: "read", path: text(input.path), cwd }
  if (toolName === "write") return { tool: "write", path: text(input.path), content: text(input.content), cwd }
  if (toolName === "edit") {
    const edits = Array.isArray(input.edits) ? (input.edits as Record<string, unknown>[]) : [input]
    return { tool: "write", path: text(input.path), content: edits.map((e) => text(e.newText) ?? text(e.new_string) ?? "").join("\\n"), cwd }
  }
  return null
}

export default function (pi: ExtensionAPI) {
  let warned = false
  pi.on("tool_call", async (event, ctx) => {
    const neutral = call(event.toolName, event.input as Record<string, unknown>, ctx.cwd)
    if (neutral === null) return
    const run = spawnSync(MEHEN, ["hook", "check"], { input: JSON.stringify(neutral), encoding: "utf8", timeout: 10_000 })
    // mehen gone altogether: say so once and get out of the way.
    if ((run.error as { code?: string } | undefined)?.code === "ENOENT") {
      if (!warned && ctx.hasUI) ctx.ui.notify(\`Mehen is not installed at \${MEHEN} any more, so its guard is off. Remove ~/.pi/agent/extensions/mehen-guard.ts, or reinstall mehen.\`, "warning")
      warned = true
      return
    }
    // A guard that cannot answer blocks: it never lets a call through unseen.
    if (run.status !== 0) return { block: true, reason: "The Mehen guard could not check this call (mehen hook check failed); run \`mehen doctor\` to see why." }
    const verdict = JSON.parse(run.stdout) as Verdict
    if (verdict.card && ctx.hasUI) ctx.ui.notify(verdict.card, verdict.decision === "deny" ? "error" : "warning")
    if (verdict.decision === "deny") return { block: true, reason: verdict.reason ?? "Blocked by the Mehen guard." }
  })
}
`
}
