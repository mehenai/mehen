import { afterEach, beforeEach, expect, test } from "bun:test"
import { z } from "zod"
import { GLOBAL_FLAGS } from "./args.ts"
import { COMMANDS } from "./cli.ts"
import { TOOLS } from "./mcp/registry.ts"
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

// Claude Code attaches only the first 5,000 tokens of a skill again after
// compaction; 18 KB of this skill is about 4,400. Move detail to
// docs/site/reference/agent-reference.md rather than raise this.
test("the skill stays under 18 KB, so an agent keeps all of it after compaction", async () => {
  const skill = await Bun.file(new URL("../../../skills/mehen/SKILL.md", import.meta.url)).bytes()
  expect(skill.length).toBeLessThan(18 * 1024)
})

// 0.3.2's skill carried "Bringing existing credentials in" twice, from two
// branches merging; an agent read both and the skill grew by 1.7 KB.
test("the skill has each section once", async () => {
  const skill = await Bun.file(new URL("../../../skills/mehen/SKILL.md", import.meta.url)).text()
  const headings = skill.split("\n").filter((line) => line.startsWith("## "))
  expect(headings.filter((h, i) => headings.indexOf(h) !== i)).toEqual([])
})
