import { afterEach, beforeEach, expect, test } from "bun:test"
import { z } from "zod"
import { GLOBAL_FLAGS } from "./args.ts"
import { COMMANDS } from "./cli.ts"
import type { AskKind } from "./ask.ts"
import { GUIDE_TOPICS } from "./commands/info.ts"
import { CORE_TOOLS, TOOLS } from "./mcp/registry.ts"
import { WAIT_ID_PREFIXES } from "./operations.ts"
import { runJv, tempDir } from "./testing/run-mehen.ts"

let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path }
})
afterEach(() => dir.remove())

// `--reset-env` (mehen setup) resets an MCP registration's env block,
// not an account: it is the one spelling of "reset" allowed on the surface.
const forbidden = /(?:^|[^a-z])(?:recovery|recover|reset(?!-env)|passkeys?|web[-_ ]sessions?)(?:[^a-z]|$)/i
const words = (text: string): string => text.replace(/([a-z])([A-Z])/g, "$1 $2")

test("no command, flag or MCP tool mentions recovery, reset, passkeys or web sessions", async () => {
  expect(Object.keys(COMMANDS)).toEqual(["up", "setup", "update", "enrol", "status", "whoami", "doctor", "ls", "show", "templates", "check", "request", "connect", "wait", "pending", "policy", "mandate", "fetch", "plan", "fill", "push", "adopt", "workload", "backup", "serve", "hook", "guard", "revoke", "freeze", "guide", "version"])
  for (const [name, command] of Object.entries(COMMANDS)) {
    expect(words(name)).not.toMatch(forbidden)
    expect(command.spec.usage).not.toMatch(forbidden)
    for (const flag of Object.keys({ ...GLOBAL_FLAGS, ...command.spec.flags })) expect(words(flag)).not.toMatch(forbidden)
  }
  for (const tool of TOOLS) {
    expect(words(tool.name)).not.toMatch(forbidden)
    expect(words(JSON.stringify(z.toJSONSchema(tool.input, { io: "input" })))).not.toMatch(forbidden)
  }
  for (const command of ["recover", "recovery", "reset", "passkey", "passkeys", "sessions"]) {
    const result = await runJv([command, "--json"], env)
    expect(result.code).toBe(2)
    expect(JSON.parse(result.stdout)).toMatchObject({ error: "usage" })
  }
  for (const command of ["run", "env", "init"]) {
    const help = await runJv([command, "--help"], env)
    expect(help.code).toBe(0)
    expect(help.stdout).not.toMatch(forbidden)
  }
  const result = await runJv(["mcp"], env, ["vault_recovery", "vault_reset", "vault_passkeys", "vault_sessions"].map((name, id) => JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: {} } })).join("\n") + "\n")
  expect(result.code).toBe(0)
  const replies = result.stdout.trim().split("\n").map((line) => JSON.parse(line) as { error?: { message: string } })
  expect(replies).toHaveLength(4)
  for (const reply of replies) expect(reply.error?.message).toMatch(/unknown tool/i)
})

// A guest's or a team's machine, or a member's whose tick was cleared, has
// no private credentials, and request and connect default to the private
// home: every place an agent reads about --home names that case and the way
// round it.
test("mehen request and connect help, the guide, the skill and the MCP home arguments name a machine without private credentials", async () => {
  for (const name of ["request", "connect"]) {
    const notes = COMMANDS[name]?.notes?.join("\n") ?? ""
    expect(notes).toContain("scope.privateCredentials false")
    expect(notes).toContain("--home project")
  }
  const guide = await Bun.file(new URL("./guide.md", import.meta.url)).text()
  expect(guide).toContain("`scope.privateCredentials: false`, ask with `--home project --project <prj_id>`")
  const skill = await Bun.file(new URL("../../../skills/mehen/SKILL.md", import.meta.url)).text()
  expect(skill).toContain("When `scope.privateCredentials` is false, never rely on the private default")
  for (const name of ["vault_request", "vault_connect"]) {
    const tool = TOOLS.find((t) => t.name === name)
    const schema = JSON.stringify(tool ? z.toJSONSchema(tool.input, { io: "input" }) : null)
    expect(schema).toContain("scope.privateCredentials false")
  }
})

// mehen guide is the agent's full guide: it names every command mehen --help
// lists, every MCP tool, every ask kind and every id mehen wait follows.
test("the guide names every command, MCP tool, ask kind and wait id prefix", async () => {
  const guide = await Bun.file(new URL("./guide.md", import.meta.url)).text()
  const help = JSON.parse((await runJv(["--help", "--json"], {})).stdout) as { commands: { name: string }[] }
  expect(help.commands.length).toBeGreaterThan(30)
  expect(help.commands.map((c) => c.name).filter((name) => !guide.includes(`\`mehen ${name}`))).toEqual([])
  expect(TOOLS.map((t) => t.name).filter((name) => !guide.includes(`\`${name}\``))).toEqual([])
  const kinds: Record<AskKind, true> = { enrol: true, intake: true, connect: true, reconnect: true, approval: true, policy: true, adoption: true, bundle: true, unfreeze: true, mandate: true }
  const listed = guide.match(/`ask` has `kind` \(([^)]*)\)/)?.[1]?.split(", ") ?? []
  expect(listed.sort()).toEqual(Object.keys(kinds).sort())
  expect(WAIT_ID_PREFIXES.length).toBe(8)
  expect(WAIT_ID_PREFIXES.filter((prefix) => !guide.includes(`(\`${prefix}_\`)`))).toEqual([])
})

// The skill is a core sheet of about 1,500 tokens: an agent loads it for
// every task that touches a credential. Move detail to a guide topic
// (`mehen guide <topic>`) rather than raise this.
test("the skill is a core sheet under 6,500 bytes", async () => {
  const skill = await Bun.file(new URL("../../../skills/mehen/SKILL.md", import.meta.url)).bytes()
  expect(skill.length).toBeLessThan(6_500)
})

test("the skill covers the six core tools, the ask-and-wait loop, exit 7's outcome_unknown and where the rest is", async () => {
  const skill = await Bun.file(new URL("../../../skills/mehen/SKILL.md", import.meta.url)).text()
  for (const name of CORE_TOOLS) expect(skill).toContain(`\`${name}\``)
  expect(skill).toContain("**Needs you in the vault:**")
  expect(skill).toMatch(/\| 7 \|[^\n]*`outcome_unknown`[^\n]*check/)
  expect(skill).toContain("mehen guide <topic>")
  expect(skill).toContain("--toolsets")
  expect(skill).toContain("https://docs.mehen.dev/guide.md")
  for (const [, topic] of skill.matchAll(/`mehen guide ([a-z-]+)`/g)) expect(Object.keys(GUIDE_TOPICS)).toContain(topic ?? "")
})

// 0.3.2's skill carried "Bringing existing credentials in" twice, from two
// branches merging; an agent read both and the skill grew by 1.7 KB.
test("the skill has each section once", async () => {
  const skill = await Bun.file(new URL("../../../skills/mehen/SKILL.md", import.meta.url)).text()
  const headings = skill.split("\n").filter((line) => line.startsWith("## "))
  expect(headings.filter((h, i) => headings.indexOf(h) !== i)).toEqual([])
})
