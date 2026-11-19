import { describe, expect, test } from "bun:test"
import { runJv, tempDir } from "../testing/run-mehen.ts"
import { cursorAnswer, cursorToolCall } from "./cursor.ts"
import { SESSION_CONTEXT } from "./index.ts"

const HOME = "/home/a"
const CWD = "/home/a/code/app"
const block = { HOME, MEHEN_GUARD: "block" }
const warn = { HOME, MEHEN_GUARD: "warn" }
const off = { HOME, MEHEN_GUARD: "off" }
const KEY = "sk_live_51Hab12CDef34GHij56KLmn"

const shell = (command: string) => ({ hook_event_name: "beforeShellExecution", command, cwd: CWD, sandbox: false, workspace_roots: [CWD] })
const read = (file_path: string) => ({ hook_event_name: "beforeReadFile", file_path, content: "", attachments: [], workspace_roots: [CWD] })
const tool = (tool_name: string, tool_input: unknown) => ({ hook_event_name: "preToolUse", tool_name, tool_input, tool_use_id: "t1", cwd: CWD, workspace_roots: [CWD] })

describe("Cursor's payloads", () => {
  test("the shell, read and Write hooks map onto the guard's calls; other tools are not its business", () => {
    expect(cursorToolCall(shell("cat .env"))).toEqual({ tool: "shell", command: "cat .env", cwd: CWD })
    expect(cursorToolCall(read(`${CWD}/.env`))).toEqual({ tool: "read", path: `${CWD}/.env`, cwd: CWD })
    expect(cursorToolCall(tool("Write", { path: "src/a.ts", contents: { text: KEY } }))).toEqual({ tool: "write", content: `src/a.ts\n${KEY}`, cwd: CWD })
    expect(cursorToolCall(tool("Shell", { command: "cat .env" }))).toEqual({ tool: "other", cwd: CWD })
    expect(cursorToolCall({ hook_event_name: "beforeReadFile", file_path: "/x/.env" })).toMatchObject({ tool: "read", path: "/x/.env" })
  })

  test("block: a denial with the card for the person and the reason for the agent", () => {
    expect(cursorAnswer(shell("cat .env"), block)).toEqual({ permission: "deny", user_message: expect.stringContaining("Mehen blocked a tool call"), agent_message: expect.stringContaining("mehen fetch") })
    expect(cursorAnswer(tool("Write", { contents: `const key = '${KEY}'` }), block)).toMatchObject({ permission: "deny", agent_message: expect.stringContaining("mehen request") })
  })

  test("beforeReadFile answers only the fields its schema has", () => {
    const denied = cursorAnswer(read(`${CWD}/.env`), block)
    expect(denied).toEqual({ permission: "deny", user_message: expect.stringContaining(".env") })
    expect(Object.keys(denied ?? {}).sort()).toEqual(["permission", "user_message"])
  })

  test("warn: allowed, with the card; off and harmless calls: a plain allow, never silence", () => {
    expect(cursorAnswer(shell("cat .env"), warn)).toEqual({ permission: "allow", user_message: expect.stringContaining("mehen guard block") })
    expect(cursorAnswer(read(`${CWD}/.env`), off)).toEqual({ permission: "allow" })
    expect(cursorAnswer(shell("npm test"), block)).toEqual({ permission: "allow" })
    expect(cursorAnswer(read(`${CWD}/README.md`), block)).toEqual({ permission: "allow" })
    expect(cursorAnswer(tool("Write", { contents: "const x = 1" }), block)).toEqual({ permission: "allow" })
    expect(cursorAnswer(tool("Delete", { path: ".env" }), block)).toEqual({ permission: "allow" })
  })

  test("sessionStart gets the note; any other event gets nothing", () => {
    const start = { hook_event_name: "sessionStart", session_id: "s", is_background_agent: false, composer_mode: "agent" }
    expect(cursorAnswer(start, block)).toEqual({ additional_context: SESSION_CONTEXT })
    expect(cursorAnswer({ hook_event_name: "stop" }, block)).toBeNull()
  })
})

describe("mehen hook cursor, as a process", () => {
  test("answers on stdout and exits 0; input it cannot read is a denial, not a pass", async () => {
    const home = await tempDir()
    const env = { HOME: home.path, MEHEN_HOME: `${home.path}/mehen` }
    try {
      const denied = await runJv(["hook", "cursor"], env, JSON.stringify(shell("cat .env")))
      expect(denied.code).toBe(0)
      expect(JSON.parse(denied.stdout)).toMatchObject({ permission: "deny" })
      const allowed = await runJv(["hook", "cursor"], env, JSON.stringify(shell("ls")))
      expect(JSON.parse(allowed.stdout)).toEqual({ permission: "allow" })
      const broken = await runJv(["hook", "cursor"], env, "not json")
      expect(broken.code).toBe(0)
      expect(JSON.parse(broken.stdout)).toMatchObject({ permission: "deny", user_message: expect.stringContaining("could not check") })
    } finally {
      await home.remove()
    }
  })
})
