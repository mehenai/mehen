import { afterEach, beforeEach, expect, test } from "bun:test"
import { readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"
import toolsList from "./mcp/fixtures/tools-list.json"
import allToolsList from "./mcp/fixtures/tools-list-all.json"
import { CORE_TOOLS, TOOLSETS } from "./mcp/registry.ts"
import { runJv, tempDir } from "./testing/run-mehen.ts"

// An empty context directory: the server binds it (not enrolled) and reads
// nothing of this user's own configuration.
let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path }
})
afterEach(() => dir.remove())

// Captured through mehen mcp tools/list: the default list (the core
// toolset) and the list with --toolsets all. MEHEN_REGENERATE_TOOLS_LIST=1
// rewrites both fixtures from the server's own answers first; review the
// diff (it changes only by the optional argument and the descriptions).
const LISTS = [
  { file: "tools-list.json", args: [] as string[], fixture: toolsList },
  { file: "tools-list-all.json", args: ["--toolsets", "all"], fixture: allToolsList },
]

for (const { file, args, fixture } of LISTS) {
  test(`tools/list ${args.join(" ") || "by default"} preserves the captured names, descriptions, schemas and order byte for byte`, async () => {
    const result = await runJv(["mcp", ...args], env, '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
    expect(result.code).toBe(0)
    if (process.env.MEHEN_REGENERATE_TOOLS_LIST === "1") {
      const path = join(import.meta.dir, "mcp", "fixtures", file)
      await writeFile(path, `${JSON.stringify((JSON.parse(result.stdout) as { result: unknown }).result, null, 2)}\n`)
      expect(JSON.parse(await readFile(path, "utf8"))).toEqual(JSON.parse(result.stdout).result)
      return
    }
    expect(result.stderr).toBe("")
    expect(result.stdout).toBe(`${JSON.stringify({ jsonrpc: "2.0", id: 1, result: fixture })}\n`)
  })
}

test("the default list is the core toolset, and the full list is every toolset's tools", () => {
  expect(toolsList.tools.map((tool) => tool.name).sort()).toEqual([...CORE_TOOLS].sort())
  expect(allToolsList.tools.map((tool) => tool.name).sort()).toEqual(Object.values(TOOLSETS).flat().sort())
})

// What a host puts in front of the model for every conversation: the list
// as the server sends it, kept under a budget so descriptions do not creep.
// The default is the six core tools; the rest are opt-in.
test("the default tools/list result stays under 9,200 bytes", () => {
  expect(Buffer.byteLength(JSON.stringify(toolsList))).toBeLessThan(9_200)
})

test("the --toolsets all result stays under 32,500 bytes", () => {
  expect(Buffer.byteLength(JSON.stringify(allToolsList))).toBeLessThan(32_500)
})

test("vault_fill follows vault_fetch and vault_plan, with the design's arguments and no value in its result", () => {
  const names = allToolsList.tools.map((tool) => tool.name)
  const fetch = names.indexOf("vault_fetch")
  expect(names.slice(fetch, fetch + 3)).toEqual(["vault_fetch", "vault_plan", "vault_fill"])
  const fill = allToolsList.tools.find((tool) => tool.name === "vault_fill") as { inputSchema: { properties: Record<string, unknown>; required: string[] }; description: string }
  expect(Object.keys(fill.inputSchema.properties)).toEqual(["item", "field", "cdp", "target", "selector", "submit", "context", "approval", "workspace"])
  expect(fill.inputSchema.required).toEqual(["item", "field", "cdp", "selector"])
  expect(fill.description).toContain("never returns the value")
})

type ListedTool = { name: string; title?: string; annotations?: Record<string, unknown>; outputSchema?: { type: string; properties: Record<string, unknown>; required?: unknown; additionalProperties?: unknown } }

// The MCP spec: destructiveHint and idempotentHint apply only when
// readOnlyHint is false, so a read-only tool may leave them out.
test("every tool has a title and its annotations, and only the tools that change nothing are read-only", () => {
  const tools = allToolsList.tools as ListedTool[]
  for (const tool of tools) {
    expect(tool.title).toEqual(expect.any(String))
    const hints = tool.annotations?.readOnlyHint === true ? ["openWorldHint", "readOnlyHint"] : ["destructiveHint", "idempotentHint", "openWorldHint", "readOnlyHint"]
    expect(Object.keys(tool.annotations ?? {}).sort()).toEqual(hints)
  }
  const where = (hint: string) => tools.filter((t) => t.annotations?.[hint] === true).map((t) => t.name)
  expect(where("readOnlyHint")).toEqual(["vault_status", "vault_doctor", "vault_templates", "vault_list", "vault_show", "vault_check", "vault_env", "vault_pending", "vault_adopt_status"])
  expect(where("openWorldHint")).toEqual(["vault_fetch", "vault_fill", "vault_push", "vault_wait"])
  // vault_wait with execute can send a write.
  expect(where("destructiveHint")).toEqual(["vault_fetch", "vault_fill", "vault_push", "vault_wait", "vault_policy", "vault_mandate"])
  // vault_request and vault_connect with `new` make a new link on every call.
  expect(where("idempotentHint")).toEqual(["vault_adopt_scan"])
})

// The keys an error's structuredContent may carry (errors.ts errorBody and
// ErrorExtras): an outputSchema that typed one of them could refuse an error.
const ERROR_BODY_KEYS = ["error", "message", "next", "ask", "mandateCover", "approval", "bindingCode", "choices", "retryAfter", "providerStatus", "mandate", "expiresAt", "request", "setup", "ruleRefused", "areaRefused", "bundle", "approvals", "cleared", "kind", "id", "status", "replacedBy", "summary", "item", "policyContext", "rememberOptions", "grant", "rule", "ruleProposal", "approvedAt", "push", "proposal", "outcome", "replay"]

test("an outputSchema requires nothing and names no field an error carries, so an error result meets it too", () => {
  const withOutput = (allToolsList.tools as ListedTool[]).filter((t) => t.outputSchema)
  expect(withOutput.map((t) => t.name)).toEqual(["vault_templates", "vault_list", "vault_check", "vault_fetch", "vault_env", "vault_pending"])
  for (const { outputSchema } of withOutput) {
    expect(outputSchema?.type).toBe("object")
    expect(outputSchema?.required).toBeUndefined()
    expect(outputSchema?.additionalProperties).toBeUndefined()
    for (const key of Object.keys(outputSchema?.properties ?? {})) expect(ERROR_BODY_KEYS).not.toContain(key)
  }
})

// A client checks a wrong injection shape before the round trip.
test("vault_request advertises injection's exact shapes, one per way it goes in", () => {
  const request = toolsList.tools.find((tool) => tool.name === "vault_request") as { inputSchema: { properties: { injection: { oneOf?: { properties: { in: { const: string } }; required: string[] }[] } } } }
  const shapes = request.inputSchema.properties.injection.oneOf ?? []
  expect(shapes.map((shape) => shape.properties.in.const)).toEqual(["header", "query", "basic", "headers"])
  expect(shapes.map((shape) => shape.required)).toEqual([["in", "name", "format"], ["in", "name", "field"], ["in", "username", "password"], ["in", "field"]])
})

test("vault_policy's captured model schema has a closed object root, not a union root", () => {
  const policy = allToolsList.tools.find((tool) => tool.name === "vault_policy")
  expect(policy).toBeDefined()
  const schema = policy!.inputSchema
  expect(schema.type).toBe("object")
  expect(schema.properties).toBeDefined()
  expect(schema.additionalProperties).toBe(false)
  for (const key of ["oneOf", "anyOf", "allOf"]) expect(schema).not.toHaveProperty(key)
})


test("mehen mcp --help names the core tools and each toolset with its tools, in the server's order", async () => {
  const result = await runJv(["mcp", "--help"], env)
  expect(result.code).toBe(0)
  expect(allToolsList.tools).toHaveLength(19)
  const order = allToolsList.tools.map((tool) => tool.name)
  const inOrder = (names: readonly string[]) => [...names].sort((a, b) => order.indexOf(a) - order.indexOf(b)).join(", ")
  expect(result.stdout).toContain(`Core tools, always served: ${inOrder(CORE_TOOLS)}.`)
  for (const [name, tools] of Object.entries(TOOLSETS)) if (name !== "core") expect(result.stdout).toContain(`${name} (${inOrder(tools)})`)
  expect(result.stdout).toContain("--toolsets all")
  expect(result.stdout).toContain("MEHEN_MCP_TOOLSETS")
})

test("MCP instructions describe check as advice, not approval prediction", async () => {
  const result = await runJv(["mcp", "--toolsets", "inspect"], env, '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')
  expect(result.code).toBe(0)
  const { instructions } = JSON.parse(result.stdout).result as { instructions: string }
  expect(instructions).toContain("vault_check is local base-policy advice only, not permission to send")
  expect(instructions).not.toContain("Before a write, vault_check tells you whether it will need approval.")
})
