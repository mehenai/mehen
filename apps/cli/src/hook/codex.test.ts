import { describe, expect, test } from "bun:test"
import { runJv, tempDir } from "../testing/run-mehen.ts"
import { codexAnswer, codexToolCall, patchWrites } from "./codex.ts"
import { SESSION_CONTEXT } from "./index.ts"

const HOME = "/home/a"
const CWD = "/home/a/code/app"
const block = { HOME, MEHEN_GUARD: "block" }
const warn = { HOME, MEHEN_GUARD: "warn" }
const off = { HOME, MEHEN_GUARD: "off" }
const KEY = "sk_live_51Hab12CDef34GHij56KLmn"

const pre = (tool_name: string, tool_input: unknown) => ({ session_id: "s", transcript_path: null, cwd: CWD, hook_event_name: "PreToolUse", model: "m", permission_mode: "default", turn_id: "t", tool_name, tool_use_id: "c1", tool_input })
const patch = (lines: string[]) => ["*** Begin Patch", ...lines, "*** End Patch"].join("\n")

describe("Codex's payloads", () => {
  test("Bash is a shell command and apply_patch a write of the lines it adds; other tools are not the guard's", () => {
    expect(codexToolCall(pre("Bash", { command: "cat .env" }))).toEqual([{ tool: "shell", command: "cat .env", cwd: CWD }])
    expect(codexToolCall(pre("apply_patch", { command: patch(["*** Add File: src/key.ts", `+export const key = '${KEY}'`]) }))).toEqual([{ tool: "write", path: "src/key.ts", content: `export const key = '${KEY}'`, cwd: CWD }])
    expect(codexToolCall(pre("mcp__fs__read", { path: ".env" }))).toEqual([{ tool: "other", cwd: CWD }])
    expect(codexToolCall(pre("update_plan", {}))).toEqual([{ tool: "other", cwd: CWD }])
  })

  test("a patch that takes a key out, or only keeps one as context, writes none", () => {
    expect(patchWrites(patch(["*** Update File: .env.example", "@@", ` OLD=1`, `-KEY=${KEY}`, "+KEY=mehen://stripe#key"]))).toEqual([{ path: ".env.example", content: "KEY=mehen://stripe#key" }])
    expect(codexAnswer(pre("apply_patch", { command: patch(["*** Update File: a.ts", "@@", `-const key = '${KEY}'`, "+const key = process.env.KEY"]) }), block)).toBeNull()
  })

  test("block: denied in the hook-specific shape, with the card as systemMessage", () => {
    expect(codexAnswer(pre("Bash", { command: "cat .env" }), block)).toEqual({
      hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: expect.stringContaining("Mehen blocked this") },
      systemMessage: expect.stringContaining("Mehen blocked a tool call"),
    })
    expect(codexAnswer(pre("Bash", { command: "printenv" }), block)).toMatchObject({ hookSpecificOutput: { permissionDecision: "deny" } })
    expect(codexAnswer(pre("apply_patch", { command: patch(["*** Add File: k.ts", `+const k = '${KEY}'`]) }), block)).toMatchObject({ hookSpecificOutput: { permissionDecisionReason: expect.stringContaining("k.ts") } })
  })

  test("warn: the card only; off and harmless calls: nothing", () => {
    expect(codexAnswer(pre("Bash", { command: "cat .env" }), warn)).toEqual({ systemMessage: expect.stringContaining("mehen guard block") })
    expect(codexAnswer(pre("Bash", { command: "cat .env" }), off)).toBeNull()
    expect(codexAnswer(pre("Bash", { command: "npm test" }), block)).toBeNull()
    expect(codexAnswer(pre("Bash", {}), block)).toBeNull()
  })

  test("SessionStart gets the note; any other event nothing", () => {
    expect(codexAnswer({ hook_event_name: "SessionStart", cwd: CWD }, block)).toEqual({ hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: SESSION_CONTEXT } })
    expect(codexAnswer({ hook_event_name: "Stop" }, block)).toBeNull()
  })
})

describe("mehen hook codex, as a process", () => {
  test("answers on stdout and exits 0; input it cannot read exits 2 with the reason on stderr, which Codex reads as a block", async () => {
    const home = await tempDir()
    const env = { HOME: home.path, MEHEN_HOME: `${home.path}/mehen` }
    try {
      const denied = await runJv(["hook", "codex"], env, JSON.stringify(pre("Bash", { command: "cat .env" })))
      expect(denied.code).toBe(0)
      expect(JSON.parse(denied.stdout).hookSpecificOutput.permissionDecision).toBe("deny")
      const allowed = await runJv(["hook", "codex"], env, JSON.stringify(pre("Bash", { command: "ls" })))
      expect(allowed).toMatchObject({ code: 0, stdout: "" })
      const broken = await runJv(["hook", "codex"], env, "[1, 2]")
      expect(broken.code).toBe(2)
      expect(broken.stdout).toBe("")
      expect(broken.stderr).toContain("could not check this call")
    } finally {
      await home.remove()
    }
  })
})

describe("review fixes: patches that touch several files", () => {
  test("each file's additions are judged on their own, and the file that carries the key is the one named", () => {
    const multi = patch(["*** Add File: src/clean.ts", "+export const a = 1", "*** Update File: src/config.ts", "@@", "-const key = process.env.KEY", `+const key = '${KEY}'`, "*** Delete File: old.ts"])
    const answer = codexAnswer(pre("apply_patch", { command: multi }), block) as { hookSpecificOutput: { permissionDecisionReason: string } }
    expect(answer.hookSpecificOutput.permissionDecisionReason).toContain("src/config.ts")
    expect(answer.hookSpecificOutput.permissionDecisionReason).not.toContain("src/clean.ts")
    expect(patchWrites(multi)).toEqual([{ path: "src/clean.ts", content: "export const a = 1" }, { path: "src/config.ts", content: `const key = '${KEY}'` }])
  })

  test("a moved file is named by where it goes", () => {
    const moved = patch(["*** Update File: a.ts", "*** Move to: b.ts", "@@", `+const k = '${KEY}'`])
    expect(patchWrites(moved)).toEqual([{ path: "b.ts", content: `const k = '${KEY}'` }])
    expect((codexAnswer(pre("apply_patch", { command: moved }), block) as { hookSpecificOutput: { permissionDecisionReason: string } }).hookSpecificOutput.permissionDecisionReason).toContain("b.ts")
  })
})
