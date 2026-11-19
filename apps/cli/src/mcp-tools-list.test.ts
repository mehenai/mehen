import { afterEach, beforeEach, expect, test } from "bun:test"
import { readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"
import toolsList from "./mcp/fixtures/tools-list.json"
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

// Captured through mehen mcp tools/list from the integrated policy head.
// MEHEN_REGENERATE_TOOLS_LIST=1 rewrites the fixture from the server's own
// answer first; review the diff (it changes only by the optional argument
// and the descriptions).
test("tools/list preserves the captured names, descriptions, schemas and order byte for byte", async () => {
  const result = await runJv(["mcp"], env, '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
  expect(result.code).toBe(0)
  if (process.env.MEHEN_REGENERATE_TOOLS_LIST === "1") {
    const fixture = join(import.meta.dir, "mcp", "fixtures", "tools-list.json")
    await writeFile(fixture, `${JSON.stringify((JSON.parse(result.stdout) as { result: unknown }).result, null, 2)}\n`)
    expect(JSON.parse(await readFile(fixture, "utf8"))).toEqual(JSON.parse(result.stdout).result)
    return
  }
  expect(result.stderr).toBe("")
  expect(result.stdout).toBe(`${JSON.stringify({ jsonrpc: "2.0", id: 1, result: toolsList })}\n`)
})


// What a host puts in front of the model for every conversation: the list
// as the server sends it, kept under a budget so descriptions do not creep.
test("the tools/list result stays under 34,100 bytes", () => {
  expect(Buffer.byteLength(JSON.stringify(toolsList))).toBeLessThan(34_100)
})

test("vault_fill follows vault_fetch and vault_plan, with the design's arguments and no value in its result", () => {
  const names = toolsList.tools.map((tool) => tool.name)
  const fetch = names.indexOf("vault_fetch")
  expect(names.slice(fetch, fetch + 3)).toEqual(["vault_fetch", "vault_plan", "vault_fill"])
  const fill = toolsList.tools.find((tool) => tool.name === "vault_fill") as { inputSchema: { properties: Record<string, unknown>; required: string[] }; description: string }
  expect(Object.keys(fill.inputSchema.properties)).toEqual(["item", "field", "cdp", "target", "selector", "submit", "context", "approval", "workspace"])
  expect(fill.inputSchema.required).toEqual(["item", "field", "cdp", "selector"])
  expect(fill.description).toContain("never returns the value")
})

type ListedTool = { name: string; title?: string; annotations?: Record<string, unknown>; outputSchema?: { type: string; properties: Record<string, unknown>; required?: unknown; additionalProperties?: unknown } }

// The MCP spec: destructiveHint and idempotentHint apply only when
// readOnlyHint is false, so a read-only tool may leave them out.
test("every tool has a title and its annotations, and only the tools that change nothing are read-only", () => {
  const tools = toolsList.tools as ListedTool[]
  for (const tool of tools) {
    expect(tool.title).toEqual(expect.any(String))
    const hints = tool.annotations?.readOnlyHint === true ? ["openWorldHint", "readOnlyHint"] : ["destructiveHint", "idempotentHint", "openWorldHint", "readOnlyHint"]
    expect(Object.keys(tool.annotations ?? {}).sort()).toEqual(hints)
  }
  const where = (hint: string) => tools.filter((t) => t.annotations?.[hint] === true).map((t) => t.name)
  expect(where("readOnlyHint")).toEqual(["vault_status", "vault_doctor", "vault_templates", "vault_list", "vault_show", "vault_check", "vault_env", "vault_pending", "vault_adopt_status"])
  expect(where("openWorldHint")).toEqual(["vault_fetch", "vault_fill", "vault_push"])
  expect(where("destructiveHint")).toEqual(["vault_fetch", "vault_fill", "vault_push", "vault_policy", "vault_mandate"])
  // vault_request and vault_connect with `new` make a new link on every call.
  expect(where("idempotentHint")).toEqual(["vault_wait", "vault_adopt_scan"])
})

// The keys an error's structuredContent may carry (errors.ts errorBody and
// ErrorExtras): an outputSchema that typed one of them could refuse an error.
const ERROR_BODY_KEYS = ["error", "message", "next", "ask", "mandateCover", "approval", "bindingCode", "choices", "retryAfter", "providerStatus", "mandate", "expiresAt", "request", "setup", "ruleRefused", "areaRefused", "bundle", "approvals", "cleared", "kind", "id", "status", "replacedBy", "summary", "item", "policyContext", "rememberOptions", "grant", "rule", "ruleProposal", "approvedAt", "push", "proposal", "outcome"]

test("an outputSchema requires nothing and names no field an error carries, so an error result meets it too", () => {
  const withOutput = (toolsList.tools as ListedTool[]).filter((t) => t.outputSchema)
  expect(withOutput.map((t) => t.name)).toEqual(["vault_templates", "vault_list", "vault_check", "vault_fetch", "vault_env", "vault_pending"])
  for (const { outputSchema } of withOutput) {
    expect(outputSchema?.type).toBe("object")
    expect(outputSchema?.required).toBeUndefined()
    expect(outputSchema?.additionalProperties).toBeUndefined()
    for (const key of Object.keys(outputSchema?.properties ?? {})) expect(ERROR_BODY_KEYS).not.toContain(key)
  }
})

test("vault_policy's captured model schema has a closed object root, not a union root", () => {
  const policy = toolsList.tools.find((tool) => tool.name === "vault_policy")
  expect(policy).toBeDefined()
  const schema = policy!.inputSchema
  expect(schema.type).toBe("object")
  expect(schema.properties).toBeDefined()
  expect(schema.additionalProperties).toBe(false)
  for (const key of ["oneOf", "anyOf", "allOf"]) expect(schema).not.toHaveProperty(key)
})


test("mehen mcp --help names every tool the server lists, in its order", async () => {
  const result = await runJv(["mcp", "--help"], env)
  expect(result.code).toBe(0)
  const names = toolsList.tools.map((tool) => tool.name)
  expect(names).toHaveLength(19)
  expect(result.stdout).toContain(`Tools: ${names.join(", ")}.`)
})

test("MCP instructions describe check as advice, not approval prediction", async () => {
  const result = await runJv(["mcp"], env, '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')
  expect(result.code).toBe(0)
  const { instructions } = JSON.parse(result.stdout).result as { instructions: string }
  expect(instructions).toContain("vault_check is local base-policy advice only, not permission to send")
  expect(instructions).not.toContain("Before a write, vault_check tells you whether it will need approval.")
})
