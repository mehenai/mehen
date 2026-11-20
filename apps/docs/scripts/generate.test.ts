import { expect, test } from "bun:test"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { ERROR_CODES } from "@mehen/protocol/api"
import { parseArgs } from "../../cli/src/args.ts"
import { COMMANDS, shellWord } from "../../cli/src/cli.ts"
import { LOCAL_EXIT, exitCodeFor } from "../../cli/src/errors.ts"
import { DEFAULT_PLATFORM_LIMITS, PLATFORM_COMMON_REFUSALS, PLATFORM_ROUTES } from "@mehen/protocol/platform"
import { ERRORS_SOURCE, GENERATED_DIR, REPO_ROOT, TOOLS_FIXTURE, cliReference, errorEntries, fieldType, generate, platformReference, schemaFields, usageFlags } from "./generate.ts"

const errorsSource = () => readFile(path.join(REPO_ROOT, ERRORS_SOURCE), "utf8")

test("cli.json has every command mehen --help lists, in its order", () => {
  const cli = cliReference()
  expect(cli.commands.map((c) => c.name)).toEqual([...Object.keys(COMMANDS), "run", "env", "init", "workspace", "mcp"])
  expect(cli.globalFlags).toEqual(["--json", "--help", "--no-qr", "--workspace"])
})

test("every example in cli.json is the command's own and parses against its spec", () => {
  const cli = cliReference()
  for (const [name, command] of Object.entries(COMMANDS)) {
    const entry = cli.commands.find((c) => c.name === name)
    expect(entry?.examples).toEqual(command.examples.map((args) => `mehen ${args.map(shellWord).join(" ")}`))
    for (const args of command.examples) expect(() => parseArgs(args.slice(1), command.spec)).not.toThrow()
    expect(entry?.flags.map((f) => f.name)).toEqual(Object.keys(command.spec.flags))
  }
})

test("the flags of a command with its own parser are the --names in its usage", () => {
  expect(usageFlags("mehen run [--env <env>] [--approval <id>] [--] <command> [args...]").map((f) => f.name)).toEqual(["env", "approval"])
  const workspace = cliReference().commands.find((c) => c.name === "workspace")
  expect(workspace?.examples).toContain("mehen workspace list --json")
  expect(workspace?.flags.map((f) => f.name)).toEqual(["check", "slot"])
})

test("errors.json has every vault and local code with the exit mehen gives it", async () => {
  const errors = errorEntries(await errorsSource())
  expect(errors.filter((e) => e.origin === "vault").map((e) => e.code)).toEqual([...ERROR_CODES])
  expect(errors.filter((e) => e.origin === "mehen").map((e) => e.code)).toEqual(Object.keys(LOCAL_EXIT))
  for (const entry of errors) {
    expect(entry.exit).toBe(exitCodeFor(entry.code as Parameters<typeof exitCodeFor>[0]))
    expect(entry.means.length).toBeGreaterThan(0)
    expect(entry.do.length).toBeGreaterThan(0)
  }
  expect(errors.find((e) => e.code === "approval_required")).toMatchObject({ http: 409, exit: 3, origin: "vault" })
  expect(errors.find((e) => e.code === "proof_invalid")?.next?.command).toBe("mehen doctor")
})

test("a code without prose, or prose for no code, fails the generation", async () => {
  const source = await errorsSource()
  const without = source.replace(/### `frozen`\n[\s\S]*?(?=\n### )/, "")
  expect(() => errorEntries(without)).toThrow("frozen has no")
  expect(() => errorEntries(`${source}\n### \`frozen_solid\`\n\n**What it means.** x\n\n**What you do.** y\n`)).toThrow("frozen_solid is not an error code")
})

test("mcp.json is the server's full tool list, each tool with its toolset", async () => {
  const fixture = JSON.parse(await readFile(path.join(REPO_ROOT, TOOLS_FIXTURE), "utf8")) as { tools: { name: string }[] }
  const mcp = (await generate(await errorsSource())).mcp
  expect(mcp.tools.map(({ toolset: _toolset, ...tool }) => tool) as unknown).toEqual(fixture.tools)
  expect(mcp.tools.filter((tool) => tool.toolset === "core").map((tool) => tool.name)).toEqual(["vault_status", "vault_list", "vault_request", "vault_fetch", "vault_env", "vault_wait"])
  expect(mcp.tools.find((tool) => tool.name === "vault_doctor")?.toolset).toBe("inspect")
})

test("providers.json is what mehen templates --json prints", async () => {
  // A private home: mehen refuses one below a world-writable directory.
  const home = await mkdtemp(path.join(tmpdir(), "mehen-docs-"))
  try {
    const env: Record<string, string> = { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? home, MEHEN_HOME: path.join(home, "mehen"), MEHEN_NO_AUTO_UPDATE: "1" }
    const proc = Bun.spawn(["bun", path.join(REPO_ROOT, "apps/cli/src/main.ts"), "templates", "--json"], { env, stdout: "pipe", stderr: "pipe" })
    const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited])
    expect({ code, err }).toEqual({ code: 0, err: "" })
    const printed = JSON.parse(out) as Record<string, unknown>
    const generated = (await generate(await errorsSource())).providers
    expect(generated.templates).toEqual(printed.templates)
    expect(generated.oauthProviders).toEqual(printed.oauthProviders)
    expect(generated.redirectUri).toBe(printed.redirectUri)
  } finally {
    await rm(home, { recursive: true, force: true })
  }
})

test("platform.json has every route of the protocol's table, in its order, with its prose", () => {
  const platform = platformReference()
  expect(platform.routes.map((r) => r.name)).toEqual(PLATFORM_ROUTES.map((r) => r.name))
  for (const [i, route] of PLATFORM_ROUTES.entries()) {
    const entry = platform.routes[i]
    expect(entry).toMatchObject({ method: route.method, path: route.path, prose: route.prose, status: [...route.status], refusals: [...route.refusals] })
    expect(entry?.params.map((p) => p.field)).toEqual(Object.keys(route.params))
    expect(entry?.body === null).toBe(route.body === null)
  }
  expect(platform.commonRefusals).toEqual([...PLATFORM_COMMON_REFUSALS])
  expect(platform.limits.map((l) => l.name)).toEqual(Object.keys(DEFAULT_PLATFORM_LIMITS))
})

test("a platform route without prose fails the generation", () => {
  const route = PLATFORM_ROUTES[0]
  expect(() => platformReference([{ ...route, prose: "" }])).toThrow("platform.view (GET /v1/platform) has no prose")
  expect(() => platformReference([{ ...route, prose: "Reads the platform" }])).toThrow("has no prose")
})

test("the platform reference regenerates with no diff", async () => {
  const fresh = `${JSON.stringify(platformReference(), null, 2)}\n`
  expect(`${JSON.stringify(platformReference(), null, 2)}\n`).toBe(fresh)
  expect(await readFile(path.join(GENERATED_DIR, "platform.json"), "utf8")).toBe(fresh)
  // The copy the docs site serves, too.
  expect(await readFile(path.join(REPO_ROOT, "apps/docs/public/reference/platform.json"), "utf8")).toBe(fresh)
})

test("a platform field's type and requirement come from its schema", () => {
  const decide = platformReference().routes.find((r) => r.name === "approvals.decide")
  expect(decide?.body).toEqual([
    { field: "decision", type: "one of `approve`, `deny`", required: "yes" },
    { field: "digest", type: "string matching `^[A-Za-z0-9_-]{43}$`", required: "yes" },
    { field: "ttlSeconds", type: "integer, 60 to 900", required: "no" },
    { field: "ref", type: "string matching `^[A-Za-z0-9_.:-]{1,64}$`", required: "no" },
  ])
  const finish = platformReference().routes.find((r) => r.name === "connects.finish")
  expect(finish?.answer.find((f) => f.field === "status")).toEqual({ field: "status", type: "`completed` or `failed`", required: "yes" })
  expect(finish?.answer.find((f) => f.field === "reason")?.required).toBe("in its shape")
  expect(fieldType({ type: ["integer", "null"], minimum: 1 })).toBe("integer, at least 1, or null")
  expect(fieldType({ type: "object", additionalProperties: { type: "string" }, propertyNames: { type: "string", maxLength: 8 } })).toBe("map of keys (string, at most 8 characters) to values (string)")
  expect(schemaFields({ type: "object", properties: { a: { type: "array", items: { type: "object", properties: { b: { type: "boolean" } }, required: ["b"] } } } })).toEqual([
    { field: "a", type: "array of object", required: "no" },
    { field: "a[].b", type: "boolean", required: "yes" },
  ])
})
