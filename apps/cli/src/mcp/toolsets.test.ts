import { afterEach, beforeEach, expect, test } from "bun:test"
import { CliError } from "../errors.ts"
import { runJv, tempDir } from "../testing/run-mehen.ts"
import { CORE_TOOLS, TOOLS, TOOLSETS, TOOLSET_NAMES, TOOL_COMMAND, parseToolsets, resolveToolsets, servedTools, toolsetOf } from "./registry.ts"

let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path }
})
afterEach(() => dir.remove())

const names = (tools: readonly { name: string }[]) => tools.map((t) => t.name)

async function listed(args: string[], extra: Record<string, string> = {}): Promise<string[]> {
  const result = await runJv(["mcp", ...args], { ...env, ...extra }, '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
  expect(result.code).toBe(0)
  return (JSON.parse(result.stdout) as { result: { tools: { name: string }[] } }).result.tools.map((t) => t.name)
}

test("the core is the six tools, and every other tool is in exactly one toolset", () => {
  expect([...CORE_TOOLS].sort()).toEqual(["vault_env", "vault_fetch", "vault_list", "vault_request", "vault_status", "vault_wait"])
  expect<readonly string[]>(TOOLSETS.core).toEqual(CORE_TOOLS)
  const all: string[] = Object.values(TOOLSETS).flat()
  expect(new Set(all).size).toBe(all.length)
  expect([...all].sort()).toEqual(names(TOOLS).sort())
  expect(toolsetOf("vault_doctor")).toBe("inspect")
  expect(toolsetOf("vault_adopt_scan")).toBe("adopt")
  expect(toolsetOf("vault_nothing")).toBeNull()
  // Each tool outside the core names the mehen command that does its work.
  expect(Object.keys(TOOL_COMMAND).sort()).toEqual(all.filter((name) => !CORE_TOOLS.includes(name)).sort())
  for (const command of Object.values(TOOL_COMMAND)) expect(command).toStartWith("mehen ")
})

test("a toolset list always has the core, `all` is every toolset, and an unknown name is refused naming the real ones", () => {
  expect(parseToolsets("inspect", "--toolsets")).toEqual(["core", "inspect"])
  expect(parseToolsets(" policy , adopt,policy ", "--toolsets")).toEqual(["core", "policy", "adopt"])
  expect(parseToolsets("all", "--toolsets")).toEqual([...TOOLSET_NAMES])
  for (const bad of ["", "inspect,nope", " , "]) {
    let thrown: unknown = null
    try {
      parseToolsets(bad, "MEHEN_MCP_TOOLSETS")
    } catch (error) {
      thrown = error
    }
    expect(thrown).toBeInstanceOf(CliError)
    expect((thrown as CliError).code).toBe("usage")
    expect((thrown as CliError).message).toContain("MEHEN_MCP_TOOLSETS")
    expect((thrown as CliError).message).toContain("core, inspect, connect, writes, policy, adopt, all")
  }
  expect(resolveToolsets(null, {})).toEqual(["core"])
  expect(resolveToolsets(null, { MEHEN_MCP_TOOLSETS: "connect" })).toEqual(["core", "connect"])
  expect(resolveToolsets("writes", { MEHEN_MCP_TOOLSETS: "connect" })).toEqual(["core", "writes"])
  expect(names(servedTools(["core", "adopt"]))).toEqual(names(TOOLS).filter((n) => CORE_TOOLS.includes(n) || n.startsWith("vault_adopt")))
})

test("tools/list serves the core by default, a toolset when asked, and every tool with all", async () => {
  expect((await listed([])).sort()).toEqual([...CORE_TOOLS].sort())
  expect(await listed(["--toolsets", "inspect"])).toEqual(names(servedTools(["core", "inspect"])))
  expect(await listed(["--toolsets=connect,adopt"])).toEqual(names(servedTools(["core", "connect", "adopt"])))
  expect(await listed([], { MEHEN_MCP_TOOLSETS: "all" })).toEqual(names(TOOLS))
  // The flag decides when both are set.
  expect(await listed(["--toolsets", "policy"], { MEHEN_MCP_TOOLSETS: "all" })).toEqual(names(servedTools(["core", "policy"])))
})

test("a call to a tool outside the served toolsets is refused tool_not_served, naming its toolset and the way to get it", async () => {
  const call = (name: string, id: number) => JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: {} } })
  const result = await runJv(["mcp"], env, `${call("vault_doctor", 1)}\n${call("vault_adopt_scan", 2)}\n`)
  expect(result.code).toBe(0)
  const replies = result.stdout.trim().split("\n").map((line) => JSON.parse(line) as { id: number; result: { isError: boolean; content: { text: string }[]; structuredContent: { error: string; message: string; next: { say: string; tool?: string; command?: string } } } })
  const doctor = replies.find((r) => r.id === 1)?.result
  expect(doctor?.isError).toBe(true)
  expect(doctor?.structuredContent.error).toBe("tool_not_served")
  expect(doctor?.structuredContent.message).toBe("vault_doctor is in the inspect toolset, which this server does not serve (it serves core).")
  expect(doctor?.structuredContent.next.say).toContain("--toolsets inspect")
  expect(doctor?.structuredContent.next.say).toContain("MEHEN_MCP_TOOLSETS")
  expect(doctor?.structuredContent.next.command).toBe("mehen doctor --json")
  expect(doctor?.structuredContent.next.tool).toBeUndefined()
  expect(doctor?.content[0]?.text).toStartWith("tool_not_served: vault_doctor is in the inspect toolset")
  const scan = replies.find((r) => r.id === 2)?.result
  expect(scan?.structuredContent.message).toContain("in the adopt toolset")
  expect(scan?.structuredContent.next.command).toBe("mehen adopt scan --json")
  // A tool no toolset has is still the JSON-RPC unknown tool.
  const unknown = await runJv(["mcp", "--toolsets", "all"], env, `${call("vault_nothing", 3)}\n`)
  expect((JSON.parse(unknown.stdout) as { error: { message: string } }).error.message).toMatch(/unknown tool/i)
})

test("an unknown toolset stops the server before it reads anything, naming the toolsets there are", async () => {
  for (const [args, extra] of [[["--toolsets", "nope"], {}], [[], { MEHEN_MCP_TOOLSETS: "core,nope" }]] as const) {
    const result = await runJv(["mcp", ...args], { ...env, ...extra }, '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
    expect(result.code).toBe(2)
    expect(result.stdout).toBe("")
    expect(result.stderr).toContain("core, inspect, connect, writes, policy, adopt, all")
  }
})

test("the instructions name only the tools served, and say how to get the rest", async () => {
  const instructions = async (args: string[]) => {
    const result = await runJv(["mcp", ...args], env, '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')
    return (JSON.parse(result.stdout) as { result: { instructions: string } }).result.instructions
  }
  const core = await instructions([])
  for (const name of CORE_TOOLS) expect(core).toContain(name)
  for (const hidden of names(TOOLS).filter((n) => !CORE_TOOLS.includes(n))) expect(core).not.toContain(hidden)
  expect(core).toContain("--toolsets")
  expect(core).toContain("tool_not_served")
  const all = await instructions(["--toolsets", "all"])
  expect(all).toContain("vault_doctor")
  expect(all).toContain("vault_connect")
  expect(all).toContain("vault_check is local base-policy advice only, not permission to send")
})
