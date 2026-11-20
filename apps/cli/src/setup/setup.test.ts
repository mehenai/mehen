import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { createHash } from "node:crypto"
import { dirname, join, relative } from "node:path"
import { parseArgs } from "../args.ts"
import { type Config, writeConfig } from "../config.ts"
import { createDeviceKey } from "../device-key.ts"
import { writeEnrolmentRecord } from "../enrolment-record.ts"
import { CliError } from "../errors.ts"
import { activeSlotPath, pendingSlotPath } from "../home.ts"
import { pendingLockPath, withSlotLocks } from "../slot-lock.ts"
import { runJv } from "../testing/run-mehen.ts"
import { VERSION } from "../version.ts"
import { printSetup, setup, setupCommand, setupExitCode, setupLines, setupRequest } from "./index.ts"
import { type Agent, agents, serverEntry } from "./agents.ts"
import { editJson, editToml, jsonEntry, tomlEntry, tomlRange } from "./formats.ts"
import { RELEASED_SKILL_SHA256, skillSha256, stampedSkill } from "./skills.ts"
import publishedSkill from "../../../../skills/mehen/SKILL.md" with { type: "text" }

let home: string
// Where the managed-host marker is looked for: a temporary owner home of
// its own, never this user's real one and never the test HOME.
let owner: string
beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "mehen-setup-"))
  owner = await mkdtemp(join(tmpdir(), "mehen-owner-"))
})
afterEach(async () => {
  await rm(home, { recursive: true, force: true })
  await rm(owner, { recursive: true, force: true })
})
const run = (names?: string[], extra: Partial<Parameters<typeof setup>[0]> = {}) => setup({ home, binary: join(home, "bin/mehen"), env: { PATH: "" }, names, files: { ownerRoot: owner }, ...extra })
async function put(path: string, text: string) { await mkdir(dirname(path), { recursive: true }); await writeFile(path, text) }

for (const definition of agents("/unused", "darwin")) describe(definition.name, () => {
  const agent = () => agents(home, "darwin").find(a => a.name === definition.name)!
  const read = (text: string) => agent().toml ? tomlEntry(text) : jsonEntry(text, agent().section)
  const fresh = () => agent().toml ? '# Keep my settings\nmodel = "other-model"\n\n[mcp_servers.other]\ncommand = "other"\n' : JSON.stringify({ preference: "kept", [agent().section]: { other: { command: "other" } } }, null, 4) + "\n"
  test("fresh file, unrelated servers, indentation, backup and idempotency", async () => {
    const first = await run([definition.name], { platform: "darwin" })
    expect(first.agents[0]?.mcp).toBe("added")
    expect(read(await readFile(agent().file, "utf8"))).toEqual(serverEntry(agent(), join(home, "bin/mehen")))
    // A file that did not exist has nothing to back up.
    expect(await Bun.file(`${agent().file}.mehen-backup`).exists()).toBe(false)
    expect((await run([definition.name], { platform: "darwin" })).agents[0]?.mcp).toBe("unchanged")
    expect((await run([definition.name], { platform: "darwin" })).skills.every(s => s.status === "unchanged")).toBe(true)
    await run([definition.name], { platform: "darwin", remove: true })
    expect(await Bun.file(agent().file).exists()).toBe(false)
    await put(agent().file, fresh())
    await run([definition.name], { platform: "darwin" })
    const text = await readFile(agent().file, "utf8")
    if (agent().toml) expect(text.startsWith(fresh())).toBe(true)
    else expect(text).toContain('\n    "preference"')
    expect(await readFile(`${agent().file}.mehen-backup`, "utf8")).toBe(fresh())
    await run([definition.name], { platform: "darwin", remove: true })
    expect(await readFile(agent().file, "utf8")).toBe(fresh())
  })
  test("updates stale mehen entry, removes only ours while preserving later edits", async () => {
    const before = agent().toml ? fresh() + '\n[mcp_servers.mehen]\ncommand = "/old/mehen"\nargs = ["mcp"]\n' : JSON.stringify({ [agent().section]: { other: { command: "other" }, mehen: { command: "/old/mehen", args: ["mcp"] } } }, null, 2) + "\n"
    await put(agent().file, before)
    expect((await run([definition.name], { platform: "darwin", force: true })).agents[0]?.mcp).toBe("updated")
    const configured = await readFile(agent().file, "utf8")
    await writeFile(agent().file, agent().toml ? configured + '\n[mcp_servers.later]\ncommand = "later"\n' : configured.replace('"other"\n', '"later"\n'))
    await run([definition.name], { platform: "darwin", remove: true })
    const removed = await readFile(agent().file, "utf8")
    expect(removed).toContain("later")
    expect(read(removed)).toEqual(agent().toml ? { command: "/old/mehen", args: ["mcp"] } : { command: "/old/mehen", args: ["mcp"] })
    expect(await Bun.file(`${agent().file}.mehen-backup`).exists()).toBe(false)
  })
  test("malformed config refuses without overwriting or backing it up", async () => {
    await put(agent().file, "{broken = [")
    const result = await run([definition.name], { platform: "darwin" })
    expect(result.agents[0]?.mcp).toBe("failed")
    expect(setupExitCode(result)).toBe(1)
    expect(result.agents[0]?.reason).toContain(agent().file)
    expect(result.agents[0]?.reason).toContain("Malformed")
    expect(await readFile(agent().file, "utf8")).toBe("{broken = [")
    expect(await Bun.file(`${agent().file}.mehen-backup`).exists()).toBe(false)
  })
  // The agent may read either of two entries with one name; setup would
  // check one, edit the first and record its own as written.
  test.skipIf(Boolean(definition.toml))("a duplicate section or server name refuses without writing; a duplicate elsewhere does not", async () => {
    const section = JSON.stringify(agent().section)
    const ours = '{"command":"/x/mehen","args":["mcp"],"env":{"MEHEN_WORKSPACES":"tn_work00000001"}}'
    const cases: [string, string][] = [
      [`{${section}:{"mehen":${ours}},${section}:{"mehen":{"command":"/x/mehen","args":["mcp"]}}}\n`, `${section} more than once`],
      [`{${section}:{"mehen":${ours},"mehen":{"command":"/x/mehen","args":["mcp"]}}}\n`, `"mehen" more than once in ${section}`],
    ]
    for (const [text, named] of cases) {
      await put(agent().file, text)
      for (const remove of [false, true]) {
        const result = await run([definition.name], { platform: "darwin", force: true, resetEnv: true, remove })
        expect(result.agents[0]?.mcp).toBe("failed")
        expect(result.agents[0]?.reason).toContain(agent().file)
        expect(result.agents[0]?.reason).toContain(named)
        expect(await readFile(agent().file, "utf8")).toBe(text)
        expect(await Bun.file(`${agent().file}.mehen-backup`).exists()).toBe(false)
      }
    }
    const elsewhere = `{"other":1,"other":2,${section}:{"other":{"command":"a"},"other":{"command":"b"}}}\n`
    await put(agent().file, elsewhere)
    expect((await run([definition.name], { platform: "darwin" })).agents[0]?.mcp).toBe("added")
    expect(read(await readFile(agent().file, "utf8"))).toEqual(serverEntry(agent(), join(home, "bin/mehen")))
  })
  test("dry run changes nothing, remove leaves foreign entries alone", async () => {
    expect((await run([definition.name], { platform: "darwin", dryRun: true })).agents[0]?.mcp).toBe("added")
    expect(await readdir(home)).toEqual([])
    await put(agent().file, fresh())
    await run([definition.name], { platform: "darwin", remove: true })
    expect(await readFile(agent().file, "utf8")).toBe(fresh())
  })
})

test("detects only installed agents and returns next without contacting the vault", async () => {
  await mkdir(join(home, ".codex"))
  const result = await run()
  expect(result.agents.map(a => a.name)).toEqual(["codex"])
  expect(result.agents[0]?.detected).toBe(true)
  expect(result.next).toBe("mehen enrol --workspace <slug> --json")
  expect((await run()).agents.map(a => [a.name, a.mcp])).toEqual([["codex", "unchanged"]])
  await writeConfig(activeSlotPath(join(home, ".config/mehen"), "https://vault.example", "tn_example"), { vault: "https://vault.example", tenant: "tn_example", device: "dev_example", backend: "software" })
  expect((await run()).next).toBe("mehen status --json")
})
// With no agent found, setup reported only its skills.
test("with no agent found, the JSON and the human report say so and name the next step", async () => {
  const report = await run()
  expect(report.agents).toEqual([])
  expect(report.next).toBe("No agent found on this machine, so no MCP entry was written. Install one and run mehen setup --json again, or name the agent you use with --agent <name> (--mcp-file <path> for another JSON MCP client).")
  expect(setupLines(report).at(-1)).toBe(`next: ${report.next}`)
  expect(setupExitCode(report)).toBe(0)
})
test("the human report of a dry run says first that nothing was written; a real run does not", async () => {
  await mkdir(join(home, ".codex"))
  const dry = setupLines(await run([], { dryRun: true }))
  expect(dry[0]).toBe("Dry run: nothing was written. Without --dry-run, mehen setup would do this:")
  expect(dry[1]).toStartWith("codex            MCP added")
  expect(await readdir(join(home, ".codex"))).toEqual([])
  const real = setupLines(await run())
  expect(real[0]).toStartWith("codex            MCP added")
  expect(real.some((line) => line.startsWith("Dry run"))).toBe(false)
})
// Gemini CLI turns user-level servers off in an untrusted folder.
test("Gemini CLI's restart step says to trust the working folder", async () => {
  const report = await run(["gemini"])
  expect(report.agents[0]?.restart).toBe("Restart Gemini CLI and trust the folder you work in; user-level servers are off in untrusted folders.")
})
// Cursor, OpenCode and VS Code read ~/.agents/skills, as
// Codex and pi do; only Claude Code reads ~/.claude/skills.
test("each agent's skill is the copy in the folder that harness reads", async () => {
  const report = await run(["claude-code", "codex", "cursor", "pi", "opencode", "vscode"], { platform: "darwin" })
  const skillFile = (name: string) => report.agents.find((a) => a.name === name)?.files.find((f) => f.endsWith("SKILL.md"))
  expect(skillFile("claude-code")).toBe(join(home, ".claude/skills/mehen/SKILL.md"))
  for (const name of ["codex", "cursor", "pi", "opencode", "vscode"]) expect(skillFile(name)).toBe(join(home, ".agents/skills/mehen/SKILL.md"))
})
test("setup adds the skill only in the folders the detected or named agents read, and still refreshes a managed copy elsewhere", async () => {
  const claude = join(home, ".claude/skills/mehen/SKILL.md"), shared = join(home, ".agents/skills/mehen/SKILL.md")
  const none = await run()
  expect(none.skills).toEqual([claude, shared].map((path) => ({ path, status: "unchanged", reason: "No agent setup found reads this folder, so the skill was not added here." })))
  expect(none.files).toEqual([])
  expect(await readdir(home)).toEqual([])
  expect((await run(["claude-code"])).skills.map((s) => s.status)).toEqual(["added", "unchanged"])
  expect(await Bun.file(shared).exists()).toBe(false)
  await run([], { remove: true })
  // A stale managed copy Claude Code no longer reads, with only Codex here.
  await put(claude, stampedSkill("0.0.1"))
  await mkdir(join(home, ".codex"))
  const codex = await run()
  expect(codex.agents.map((a) => a.name)).toEqual(["codex"])
  expect(codex.skills.map((s) => s.status)).toEqual(["updated", "added"])
  expect(await readFile(claude, "utf8")).toBe(stampedSkill())
})
test("refuses unknown agents and paths outside HOME", async () => {
  await expect(run(["unknown"])).rejects.toThrow("Unknown agent")
  await symlink(tmpdir(), join(home, ".cursor"))
  expect((await run(["cursor"])).agents[0]?.reason).toContain("symbolic link")
})
test("managed skills carry embedded source with metadata and remove idempotently", async () => {
  await run(["claude-code", "codex"])
  for (const base of [".claude", ".agents"]) expect(await readFile(join(home, base, "skills/mehen/SKILL.md"), "utf8")).toBe(stampedSkill())
  expect(stampedSkill()).toContain(`metadata:\n  mehen-version: "${VERSION}"`)
  await run([], { remove: true })
  expect((await run([], { remove: true })).skills.every(s => s.status === "unchanged")).toBe(true)
})
test("foreign skills and links stay untouched, force preserves and restores original", async () => {
  const foreign = join(home, "foreign")
  await put(join(foreign, "SKILL.md"), "foreign skill")
  await mkdir(join(home, ".claude/skills"), { recursive: true })
  await symlink(foreign, join(home, ".claude/skills/mehen"))
  await put(join(home, ".agents/skills/mehen/SKILL.md"), "another foreign skill")
  const result = await run(["claude-code", "codex"])
  expect(result.skills.map(s => s.status)).toEqual(["external", "external"])
  expect(await readFile(join(foreign, "SKILL.md"), "utf8")).toBe("foreign skill")
  expect((await run(["claude-code", "codex"], { force: true })).skills.map(s => s.status)).toEqual(["updated", "updated"])
  expect(await readFile(join(foreign, "SKILL.md"), "utf8")).toBe("foreign skill")
  await run([], { remove: true })
  expect(await readFile(join(home, ".claude/skills/mehen/SKILL.md"), "utf8")).toBe("foreign skill")
  expect(await readFile(join(home, ".agents/skills/mehen/SKILL.md"), "utf8")).toBe("another foreign skill")
})
test("remove will not delete an entry edited after setup", async () => {
  await run(["cursor"])
  const path = join(home, ".cursor/mcp.json")
  await writeFile(path, JSON.stringify({ mcpServers: { mehen: { command: "different" } } }))
  expect((await run(["cursor"], { remove: true })).agents[0]?.mcp).toBe("skipped")
  expect(await readFile(path, "utf8")).toContain("different")
})
// A managed entry replaced by hand was overwritten by the next
// plain setup because only the ownership record's presence was checked.
describe("a managed entry edited or deleted by hand after setup", () => {
  for (const name of ["cursor", "codex", "opencode"] as const) test(`${name}: plain setup leaves it alone, --force replaces it, and a forced takeover still refuses an unsafe env`, async () => {
    const agent = agents(home, "darwin").find((a) => a.name === name)!
    const read = (text: string) => agent.toml ? tomlEntry(text) : jsonEntry(text, agent.section)
    const manual = (env?: Record<string, string>) => {
      const field = name === "opencode" ? "environment" : "env"
      if (agent.toml) return `[mcp_servers.mehen]\ncommand = "/my/manual/server"\nargs = ["custom"]\n${env ? `env = { ${Object.entries(env).map(([k, v]) => `${JSON.stringify(k)} = ${JSON.stringify(v)}`).join(", ")} }\n` : ""}`
      return JSON.stringify({ [agent.section]: { mehen: name === "opencode" ? { type: "local", command: ["/my/manual/server", "custom"], enabled: true, ...(env ? { [field]: env } : {}) } : { command: "/my/manual/server", args: ["custom"], ...(env ? { [field]: env } : {}) } } })
    }
    expect((await run([name])).agents[0]?.mcp).toBe("added")
    const backup = await readFile(`${agent.file}.mehen-backup`, "utf8").catch(() => null)
    const ownership = await readFile(statePath(), "utf8")
    await writeFile(agent.file, manual())
    // Before the fix: "updated", the manual command replaced by setup's binary.
    const plain = await run([name])
    expect(plain.agents[0]?.mcp).toBe("skipped")
    expect(plain.agents[0]?.reason).toContain("changed after setup")
    // The human's edit needs no fixing: next is not "fix what each skipped entry names".
    expect(plain.next).toBe("mehen enrol --workspace <slug> --json")
    expect(await readFile(agent.file, "utf8")).toBe(manual())
    expect(await readFile(`${agent.file}.mehen-backup`, "utf8").catch(() => null)).toBe(backup)
    expect(await readFile(statePath(), "utf8")).toBe(ownership)
    expect((await run([name], { remove: true })).agents[0]?.mcp).toBe("skipped")
    // A forced takeover still applies every env check.
    await writeFile(agent.file, manual({ MEHEN_CONFIG_DIR: "/Users/someone/.config/mehen" }))
    const unsafe = await run([name], { force: true })
    expect(unsafe.agents[0]?.reason).toContain("retired variable")
    expect(await readFile(agent.file, "utf8")).toBe(manual({ MEHEN_CONFIG_DIR: "/Users/someone/.config/mehen" }))
    await writeFile(agent.file, manual())
    expect((await run([name], { force: true })).agents[0]?.mcp).toBe("updated")
    expect(read(await readFile(agent.file, "utf8"))).toEqual(serverEntry(agent, join(home, "bin/mehen")))
    // Deleted by hand: not brought back without --force.
    await writeFile(agent.file, agent.toml ? "" : "{}")
    const deleted = await run([name])
    expect(deleted.agents[0]?.mcp).toBe("skipped")
    expect(deleted.agents[0]?.reason).toContain("removed by hand")
    expect(deleted.next).toBe("mehen enrol --workspace <slug> --json")
    expect(await readFile(agent.file, "utf8")).toBe(agent.toml ? "" : "{}")
    expect((await run([name], { force: true })).agents[0]?.mcp).toBe("added")
  })
})

// A harness's default tool limit (Codex 60 s, OpenCode
// 30 s) stopped vault_wait before Mehen answered.
describe("harness tool timeouts", () => {
  const expected: Record<string, Record<string, number>> = { codex: { tool_timeout_sec: 660 }, opencode: { timeout: 660_000 }, gemini: { timeout: 660_000 } }
  for (const [name, timeout] of Object.entries(expected)) test(`${name}: a new entry carries the tool timeout, and one setup wrote before it gets it on the next run`, async () => {
    const agent = agents(home, "darwin").find((a) => a.name === name)!
    const read = async () => { const text = await readFile(agent.file, "utf8"); return agent.toml ? tomlEntry(text) : jsonEntry(text, agent.section) }
    expect((await run([name])).agents[0]?.mcp).toBe("added")
    expect(await read()).toMatchObject(timeout)
    // What an earlier setup wrote and recorded: the same entry without the timeout.
    const earlier = entryWithoutToolTimeout(agent)
    await writeFile(agent.file, agent.toml ? editToml("", `[mcp_servers.mehen]\ncommand = ${JSON.stringify(earlier.command)}\nargs = ["mcp"]\n`) : editJson("{}\n", agent.section, earlier, false).text)
    const state = JSON.parse(await readFile(statePath(), "utf8")) as Record<string, { hash: string }>
    await writeFile(statePath(), JSON.stringify({ ...state, [agent.key]: { ...state[agent.key], hash: digest(earlier) } }))
    expect((await run([name])).agents[0]?.mcp).toBe("updated")
    expect(await read()).toEqual(serverEntry(agent, join(home, "bin/mehen")))
    expect(await read()).toMatchObject(timeout)
  })
})

test("TOML refuses ambiguous inline and nested tables rather than rewriting unrelated data", async () => {
  const path = join(home, ".codex/config.toml")
  for (const text of ['[mcp_servers]\nmehen = { command = "old" }\n', '[mcp_servers.mehen]\ncommand = "old"\n[mcp_servers.mehen.env]\nother = "setting"\n']) {
    await put(path, text)
    expect((await run(["codex"])).agents[0]?.reason).toContain("table")
    expect(await readFile(path, "utf8")).toBe(text)
  }
})
test("JSONC settings preserve indentation and unrelated data", async () => {
  const path = join(home, ".cursor/mcp.json")
  await put(path, '{\n\t// user comment\n\t"mcpServers": { "other": { "command": "https://example.test/*not a comment*/", }, },\n}\n')
  await run(["cursor"])
  const text = await readFile(path, "utf8")
  expect(text).toContain("https://example.test/*not a comment*/")
  expect(text).toContain('\n\t"mcpServers"')
})

test("a new setup lifecycle takes a fresh backup rather than restoring stale settings", async () => {
  await run(["cursor"])
  await run(["cursor"], { remove: true })
  const path = join(home, ".cursor/mcp.json")
  const later = '{"mcpServers":{"mehen":{"command":"my-own-command"},"other":{"command":"other"}}}\n'
  await put(path, later)
  await run(["cursor"], { force: true })
  expect(await readFile(`${path}.mehen-backup`, "utf8")).toBe(later)
  await run(["cursor"], { remove: true })
  expect(await readFile(path, "utf8")).toBe(later)
})
test("unowned backups and missing owned backups refuse without losing settings", async () => {
  const path = join(home, ".cursor/mcp.json")
  await put(`${path}.mehen-backup`, "old backup")
  expect((await run(["cursor"])).agents[0]?.reason).toContain("unowned setup backup")
  expect(await readFile(`${path}.mehen-backup`, "utf8")).toBe("old backup")
  await rm(`${path}.mehen-backup`)
  await put(path, '{"mcpServers":{"other":{"command":"other"}}}\n')
  await run(["cursor"])
  const configured = await readFile(path, "utf8")
  await rm(`${path}.mehen-backup`)
  expect((await run(["cursor"], { remove: true })).agents[0]?.reason).toContain("Missing setup backup")
  expect(await readFile(path, "utf8")).toBe(configured)
})
test("malformed ownership, non-object JSON sections and symlinked configs refuse", async () => {
  const state = join(home, ".config/mehen/setup-state.json")
  await put(state, '{"cursor":{"existed":true}}')
  expect((await run(["cursor"])).agents[0]?.reason).toContain("ownership")
  await rm(state)
  const path = join(home, ".cursor/mcp.json")
  await put(path, '{"mcpServers":[]}')
  expect((await run(["cursor"])).agents[0]?.reason).toContain("must be an object")
  await rm(path); await symlink(join(home, "elsewhere"), path)
  expect((await run(["cursor"])).agents[0]?.reason).toContain("symbolic link")
  await expect(run([], { home: "relative" })).rejects.toThrow("absolute HOME")
})
test("dry removal preserves owned config, skills and backup", async () => {
  const path = join(home, ".codex/config.toml")
  await put(path, 'model = "other-model"\n')
  await run(["codex"])
  const before = await readFile(path, "utf8")
  expect((await run(["codex"], { remove: true, dryRun: true })).agents[0]?.mcp).toBe("updated")
  expect(await readFile(path, "utf8")).toBe(before)
  expect(await Bun.file(`${path}.mehen-backup`).exists()).toBe(true)
  expect(await readFile(join(home, ".agents/skills/mehen/SKILL.md"), "utf8")).toBe(stampedSkill())
})
test("a version-like field outside metadata is not a managed skill", async () => {
  // The current version string in the wrong place: still foreign.
  await put(join(home, ".agents/skills/mehen/SKILL.md"), `---\nmetadata:\n  author: another\nforeign:\n  mehen-version: "${VERSION}"\n---\nForeign skill\n`)
  expect((await run([])).skills[1]?.status).toBe("external")
})
// Docs.mehen.dev/skill.md publishes the unstamped skill.
test("a published copy of the skill, unstamped, is managed and refreshed; a symlink to it stays external", async () => {
  await put(join(home, ".agents/skills/mehen/SKILL.md"), publishedSkill)
  const first = await run([], { skillsOnly: true })
  expect(first.skills[1]).toEqual({ path: join(home, ".agents/skills/mehen/SKILL.md"), status: "updated" })
  expect(await readFile(join(home, ".agents/skills/mehen/SKILL.md"), "utf8")).toBe(stampedSkill())
  await put(join(home, "published/SKILL.md"), publishedSkill)
  await mkdir(join(home, ".claude/skills"), { recursive: true })
  await symlink(join(home, "published"), join(home, ".claude/skills/mehen"))
  expect((await run(["claude-code"])).skills[0]?.status).toBe("external")
  expect(await readFile(join(home, "published/SKILL.md"), "utf8")).toBe(publishedSkill)
})
// The release hashes are the raw bytes' SHA-256, as `shasum -a 256` gives.
test("the embedded skill hashes as its file's bytes do", async () => {
  const bytes = await readFile(join(import.meta.dir, "../../../../skills/mehen/SKILL.md"))
  expect(skillSha256(publishedSkill)).toBe(createHash("sha256").update(bytes).digest("hex"))
})
const RELEASE_COMMITS: Record<string, string> = { "0.1.0": "ecc074a", "0.2.0": "dc95a2c", "0.3.0": "f077c6c", "0.3.1": "4dd712b", "0.3.2": "bdf35ef", "0.3.3": "4fdea51", "0.3.4": "e22bf5e", "0.3.5": "cbfab8f", "0.3.6": "d34bc2e", "0.3.7": "3d2ad4c", "0.3.8": "dbe7449", "0.3.9": "958d563", "0.3.10": "d2e291a", "0.3.11": "9bba5b7", "0.3.12": "4fea471", "0.3.13": "b63ec88", "0.3.14": "8cc94de", "0.3.15": "dec7a26", "0.3.16": "d43cf71", "0.3.17": "b956b66", "0.3.18": "59845d9", "0.3.19": "97e8ade", "0.4.0": "f52635f", "0.4.1": "a49c8aa" }
const releasedSkill = (commit: string) => Bun.spawnSync(["git", "show", `${commit}:skills/mehen/SKILL.md`], { cwd: import.meta.dir, stderr: "ignore" })
// A shallow or partial clone (CI) lacks some release commits; only a clone
// with every one of them checks them.
test.skipIf(!Object.values(RELEASE_COMMITS).every((commit) => releasedSkill(commit).success))("each release's skill hashes to its entry and a saved copy of it is managed", async () => {
  expect(Object.keys(RELEASED_SKILL_SHA256)).toEqual(Object.keys(RELEASE_COMMITS))
  for (const [version, commit] of Object.entries(RELEASE_COMMITS)) {
    const text = releasedSkill(commit).stdout.toString()
    expect(skillSha256(text)).toBe(RELEASED_SKILL_SHA256[version]!)
    await put(join(home, ".agents/skills/mehen/SKILL.md"), text)
    expect((await run([], { skillsOnly: true })).skills[1]?.status).toBe(text === stampedSkill() ? "unchanged" : "updated")
  }
})
// 0.5's skill is a short sheet unlike any release's: a saved copy of the
// last release's long one is still Mehen's own, and setup replaces it.
test.skipIf(!releasedSkill(RELEASE_COMMITS["0.4.1"]!).success)("the released 0.4.1 skill, saved unstamped, is Mehen's own and is replaced by this one", async () => {
  const text = releasedSkill(RELEASE_COMMITS["0.4.1"]!).stdout.toString()
  expect(skillSha256(text)).toBe(RELEASED_SKILL_SHA256["0.4.1"]!)
  expect(text).not.toBe(publishedSkill)
  await put(join(home, ".agents/skills/mehen/SKILL.md"), text)
  expect((await run([], { skillsOnly: true })).skills[1]).toEqual({ path: join(home, ".agents/skills/mehen/SKILL.md"), status: "updated" })
  expect(await readFile(join(home, ".agents/skills/mehen/SKILL.md"), "utf8")).toBe(stampedSkill())
})
test("force never overwrites an existing skill backup, even in dry run", async () => {
  const path = join(home, ".agents/skills/mehen/SKILL.md")
  await put(path, "foreign skill")
  await run([], { force: true })
  await writeFile(path, "another foreign skill")
  expect((await run([], { force: true, dryRun: true })).skills[1]?.status).toBe("external")
  expect((await run([], { force: true })).skills[1]?.status).toBe("external")
  expect(await readFile(path, "utf8")).toBe("another foreign skill")
})
test("JSONC trailing commas followed by comments and CRLF preserve data and indentation", async () => {
  const path = join(home, ".cursor/mcp.json")
  await put(path, '{\r\n\t"mcpServers": {"other":{"command":"other"}, /* keep other */ }, // trailing\r\n}\r\n')
  await run(["cursor"])
  const text = await readFile(path, "utf8")
  expect(text).toContain('\r\n\t"mcpServers"')
  expect(jsonEntry(text, "mcpServers")).toEqual({ command: join(home, "bin/mehen"), args: ["mcp"] })
  expect(text).toContain("/* keep other */")
})

test("one linked agent outside HOME fails while a normal agent is added", async () => {
  await mkdir(join(home, ".config"))
  await symlink(tmpdir(), join(home, ".config/opencode"))
  await put(join(home, ".codex/config.toml"), 'model = "x"\n')
  const result = await run(["opencode", "codex"])
  expect(result.agents.map(a => [a.name, a.mcp])).toEqual([["codex", "added"], ["opencode", "failed"]])
  expect(result.agents[1]?.reason).toContain("outside HOME")
  expect(result.agents[1]?.reason?.split("mehen setup --json again").length).toBe(2)
  expect(result.agents[1]?.files).toContain(join(home, ".config/opencode/opencode.json"))
  expect(result.next).toContain("setup --json")
})
test("in-HOME .config and mehen symlinks work, as do linked agent files", async () => {
  await mkdir(join(home, "actual-mehen"), { recursive: true })
  await symlink(join(home, "dotfiles"), join(home, ".config"))
  await mkdir(join(home, "dotfiles"))
  await symlink(join(home, "actual-mehen"), join(home, ".config/mehen"))
  await put(join(home, "cursor.json"), '{}')
  await mkdir(join(home, ".cursor"))
  await symlink(join(home, "cursor.json"), join(home, ".cursor/mcp.json"))
  expect((await run(["cursor", "codex"])).agents.map(a => [a.mcp, a.reason])).toEqual([["added", undefined], ["added", undefined]])
  expect((await lstat(join(home, ".cursor/mcp.json"))).isSymbolicLink()).toBe(true)
  expect(jsonEntry(await readFile(join(home, "cursor.json"), "utf8"), "mcpServers")).toBeDefined()
})
test("malformed opencode does not block cursor or gemini", async () => {
  await put(join(home, ".config/opencode/opencode.json"), '{bad')
  const result = await run(["opencode", "cursor", "gemini"])
  expect(result.agents.map(a => a.mcp)).toEqual(["added", "added", "failed"])
  expect(result.agents[2]?.reason).toContain(join(home, ".config/opencode/opencode.json"))
})
test("an out-of-HOME state link refuses each selected agent with a recovery step", async () => {
  await symlink(tmpdir(), join(home, ".config"))
  const result = await run(["codex"])
  expect(result.agents[0]?.mcp).toBe("failed")
  expect(result.skills.map((s) => s.status)).toEqual(["failed", "failed"])
  expect(result.next).toContain("ownership file")
  expect(await Bun.file(join(home, ".codex/config.toml")).exists()).toBe(false)
})
test("JSONC splices preserve comments, compact layout and missing final newline after unrelated edits", async () => {
  const path = join(home, ".cursor/mcp.json")
  const before = '{\n  // My servers\n  "mcpServers": {"other":{"args":["a","b"]}, /* trailing */},\n  "settings":{"x":true}\n}'
  await put(path, before)
  await run(["cursor"])
  const added = await readFile(path, "utf8")
  expect(added.replace(/,\n    "mehen": \{"command":"[^"]+","args":\["mcp"\]\}/, "")).toBe(before)
  expect(added.endsWith("\n")).toBe(false)
  await writeFile(path, added.replace('"x":true', '"x":false /* human edit */'))
  await run(["cursor"], { remove: true })
  expect(await readFile(path, "utf8")).toBe(before.replace('"x":true', '"x":false /* human edit */'))
})
test("foreign MCP entries need force and retain env unless reset explicitly", async () => {
  const path = join(home, ".gemini/settings.json")
  const foreign = { command: "/opt/mehen", args: ["mcp"], env: { MEHEN_SESSION: "gemini-main", MEHEN_VAULT_URL: "https://vault.example" } }
  const before = JSON.stringify({ mcpServers: { mehen: foreign } })
  await put(path, before)
  expect((await run(["gemini"])).agents[0]?.mcp).toBe("skipped")
  expect(await readFile(path, "utf8")).toBe(before)
  await run(["gemini"], { force: true })
  expect(jsonEntry(await readFile(path, "utf8"), "mcpServers")).toEqual({ ...foreign, command: join(home, "bin/mehen"), timeout: 660_000 })
  await run(["gemini"], { force: true, resetEnv: true })
  expect(jsonEntry(await readFile(path, "utf8"), "mcpServers")).toEqual({ command: join(home, "bin/mehen"), args: ["mcp"], timeout: 660_000 })
})
test("TOML inserts one blank line and remove keeps later comments byte for byte", async () => {
  const path = join(home, ".codex/config.toml")
  const before = 'model = "x"\n'
  const later = '\n# Notes about docs, keep\n[mcp_servers.docs]\ncommand = "docs-mcp"\n'
  await put(path, before)
  await run(["codex"])
  const added = await readFile(path, "utf8")
  expect(added).toContain('model = "x"\n\n[mcp_servers.mehen]')
  await writeFile(path, added + later)
  await run(["codex"], { remove: true })
  expect(await readFile(path, "utf8")).toBe(before + later)
})
test("writes retain config modes and remove tidies managed skill parents and state", async () => {
  const path = join(home, ".cursor/mcp.json")
  await put(path, '{}')
  await chmod(path, 0o640)
  await run(["cursor"])
  expect((await lstat(path)).mode & 0o777).toBe(0o640)
  await run(["cursor"], { remove: true })
  expect((await lstat(path)).mode & 0o777).toBe(0o640)
  expect(await Bun.file(join(home, ".config/mehen/setup-state.json")).exists()).toBe(false)
  expect(await readdir(home)).not.toContain(".agents")
})
test("forced skill backups live outside scanned folders and restore on remove", async () => {
  await put(join(home, ".agents/skills/mehen/SKILL.md"), "foreign")
  await run(["codex"], { force: true })
  expect(await readdir(join(home, ".agents/skills"))).toEqual(["mehen"])
  expect(await readFile(join(home, ".config/mehen/backups/skills/agents/mehen/SKILL.md"), "utf8")).toBe("foreign")
  const state = await readFile(join(home, ".config/mehen/setup-state.json"), "utf8")
  expect(state).toContain("backups/skills/agents/mehen")
  await run([], { remove: true })
  expect(await readFile(join(home, ".agents/skills/mehen/SKILL.md"), "utf8")).toBe("foreign")
})
test("skill reports use each agent's location and desktop explains the absence", async () => {
  await put(join(home, ".claude/skills/mehen/SKILL.md"), "foreign")
  const result = await run(["claude-code", "codex", "pi", "claude-desktop"])
  expect(result.agents.map(a => a.skill)).toEqual(["external", "added", "added", null])
  expect(result.agents[3]?.skillReason).toContain("does not read Agent Skills")
})
test("update skills-only refreshes managed locations but never adds removed skills", async () => {
  await put(join(home, ".agents/skills/mehen/SKILL.md"), stampedSkill("0.0.1"))
  await run([], { skillsOnly: true })
  expect(await readFile(join(home, ".agents/skills/mehen/SKILL.md"), "utf8")).toBe(stampedSkill())
  expect(await Bun.file(join(home, ".claude/skills/mehen/SKILL.md")).exists()).toBe(false)
  await run([], { remove: true })
  await run([], { skillsOnly: true })
  expect(await Bun.file(join(home, ".agents/skills/mehen/SKILL.md")).exists()).toBe(false)
})
test("a symlinked skill alone does not detect Claude Code", async () => {
  await mkdir(join(home, ".claude/skills"), { recursive: true })
  await symlink(join(home, "foreign"), join(home, ".claude/skills/mehen"))
  expect((await run([], { dryRun: true })).agents).toEqual([])
})
test("a concurrent edit is replanned once and kept; a second edit fails", async () => {
  const path = join(home, ".cursor/mcp.json")
  await put(path, '{}')
  const once = await run(["cursor"], { beforeWrite: async (file, attempt) => { if (attempt === 0) await writeFile(file, '{"human":true}') } })
  expect(once.agents[0]?.mcp).toBe("added")
  expect(await readFile(path, "utf8")).toContain('"human":true')
  await run(["cursor"], { remove: true })
  const twice = await run(["cursor"], { beforeWrite: async (file, attempt) => { await writeFile(file, `{"human":${attempt}}`) } })
  expect(twice.agents[0]?.mcp).toBe("failed")
  expect(twice.agents[0]?.reason).toContain("changed while setup ran")
  expect(await readFile(path, "utf8")).toBe('{"human":1}')
  expect(await Bun.file(`${path}.mehen-backup`).exists()).toBe(false)
})

test("an out-of-HOME agent file fails without blocking a normal file", async () => {
  await mkdir(join(home, ".cursor"))
  await symlink(join(tmpdir(), "outside-config.json"), join(home, ".cursor/mcp.json"))
  const result = await run(["cursor", "gemini"])
  expect(result.agents.map(a => a.mcp)).toEqual(["failed", "added"])
  expect(result.agents[0]?.reason).toContain("symbolic link outside HOME")
})
test("an empty JSON settings file (VS Code's mcp.json with no bytes) is registered in, and removal gives back the empty file", async () => {
  for (const original of ["", "\n  \n"]) {
    const agent = agents(home, "darwin").find(a => a.name === "vscode")!
    await put(agent.file, original)
    const result = await run(["vscode"], { platform: "darwin" })
    expect(result.agents[0]?.mcp).toBe("added")
    expect(jsonEntry(await readFile(agent.file, "utf8"), agent.section)).toEqual(serverEntry(agent, join(home, "bin/mehen")))
    expect(await readFile(`${agent.file}.mehen-backup`, "utf8")).toBe(original)
    expect((await run(["vscode"], { platform: "darwin" })).agents[0]?.mcp).toBe("unchanged")
    await run(["vscode"], { platform: "darwin", remove: true })
    expect(await readFile(agent.file, "utf8")).toBe(original)
    expect(await Bun.file(`${agent.file}.mehen-backup`).exists()).toBe(false)
  }
  const toml = agents(home, "darwin").find(a => a.name === "codex")!
  await put(toml.file, "")
  expect((await run(["codex"], { platform: "darwin" })).agents[0]?.mcp).toBe("added")
})
test("removal after an unrelated edit keeps an originally empty JSONC section", async () => {
  const path = join(home, ".cursor/mcp.json")
  const before = '{"mcpServers":{/* keep */},"setting":true}'
  await put(path, before)
  await run(["cursor"])
  const added = await readFile(path, "utf8")
  await writeFile(path, added.replace('"setting":true', '"setting":false /* changed */'))
  await run(["cursor"], { remove: true })
  expect(await readFile(path, "utf8")).toBe(before.replace('"setting":true', '"setting":false /* changed */'))
})
test("even a matching unowned MCP entry remains foreign", async () => {
  const agent = agents(home).find(a => a.name === "cursor")!
  const before = JSON.stringify({ mcpServers: { mehen: serverEntry(agent, join(home, "bin/mehen")) } })
  await put(agent.file, before)
  expect((await run(["cursor"])).agents[0]?.mcp).toBe("skipped")
  expect(await readFile(agent.file, "utf8")).toBe(before)
  expect((await run(["cursor"], { force: true })).agents[0]?.mcp).toBe("updated")
  expect((await run(["cursor"])).agents[0]?.mcp).toBe("unchanged")
  await run(["cursor"], { remove: true })
  expect(await readFile(agent.file, "utf8")).toBe(before)
})


// What a 0.2.0 `mehen setup --workspace <slug>` left behind (design 15.7):
// a `mehen-<slug>` entry beside or instead of `mehen`, the file's one
// backup when it had none, and the `file#mehen-<slug>` ownership record.
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical)
  if (typeof value === "object" && value !== null) return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical((value as Record<string, unknown>)[key])]))
  return value
}
const digest = (entry: unknown) => createHash("sha256").update(JSON.stringify(canonical(entry))).digest("hex")
const statePath = () => join(home, ".config/mehen/setup-state.json")
// The entry setup wrote before it set harness tool timeouts.
function entryWithoutToolTimeout(agent: Agent): Record<string, unknown> {
  return Object.fromEntries(Object.entries(serverEntry(agent, join(home, "bin/mehen"))).filter(([key]) => key !== "timeout" && key !== "tool_timeout_sec"))
}
async function legacyRegistration(agent: Agent, server: string, id: string): Promise<void> {
  const before = await readFile(agent.file, "utf8").catch(() => null)
  const text = before ?? (agent.toml ? "" : "{}\n")
  const entry: Record<string, unknown> = { ...entryWithoutToolTimeout(agent), args: ["mcp", "--workspace", id] }
  let after: string
  let prefix: string | undefined
  if (agent.toml) {
    const existing = tomlRange(text, server)
    after = editToml(text, `[mcp_servers.${server}]\ncommand = ${JSON.stringify(entry.command)}\nargs = ${JSON.stringify(entry.args)}\n`, server)
    if (existing === null) prefix = after.slice(text.length, tomlRange(after, server)!.start)
  } else after = editJson(text, agent.section, entry, false, server).text
  if (!(await Bun.file(`${agent.file}.mehen-backup`).exists())) await put(`${agent.file}.mehen-backup`, text)
  const state = await readFile(statePath(), "utf8").then((t) => JSON.parse(t) as Record<string, { existed: boolean }>, () => ({}) as Record<string, { existed: boolean }>)
  const key = relative(home, agent.file)
  await put(agent.file, after)
  await put(statePath(), `${JSON.stringify({ ...state, [`${key}#${server}`]: { hash: digest(entry), existed: state[key]?.existed ?? before !== null, ...(prefix ? { prefix } : {}) } }, null, 2)}\n`)
}

// With the retired servers: one backup per settings file, owned
// by every managed entry in it together. The first new setup takes each
// `mehen-<slug>` entry out through the sibling removal path; the
// last removal restores the original bytes or absence and retires the
// backup.
describe("retired mehen-<slug> servers and the shared backup", () => {
  const WORK = "tn_work00000001"
  const OTHER = "tn_other0000001"
  const binary = () => join(home, "bin/mehen")
  for (const definition of agents("/unused", "darwin").filter((a) => ["claude-code", "codex", "cursor"].includes(a.name))) describe(definition.name, () => {
    const agent = () => agents(home, "darwin").find((a) => a.name === definition.name)!
    const go = (extra: Partial<Parameters<typeof setup>[0]> = {}) => run([definition.name], { platform: "darwin", ...extra })
    const read = (text: string, server?: string) => agent().toml ? tomlEntry(text, server) : jsonEntry(text, agent().section, server)
    const backupPath = () => `${agent().file}.mehen-backup`
    const keys = async () => Object.keys(JSON.parse(await readFile(statePath(), "utf8")) as object)
    const present = () => (definition.toml ? '# Keep my settings\nmodel = "other-model"\n\n[mcp_servers.other]\ncommand = "other"\n' : JSON.stringify({ preference: "kept", [definition.section]: { other: { command: "other" } } }, null, 2) + "\n")
    const originals: [string, () => string | null][] = [
      ["absent", () => null],
      ["present", present],
      ["empty section", () => (definition.toml ? "" : JSON.stringify({ preference: "kept", [definition.section]: {} }, null, 2) + "\n")],
    ]
    for (const [label, make] of originals) {
      test(`a retired server alone: the next setup takes it out and registers mehen; removal restores the original ${label} and retires the backup`, async () => {
        const original = make()
        if (original !== null) await put(agent().file, original)
        await legacyRegistration(agent(), "mehen-work", WORK)
        const empty = agent().toml ? "" : "{}\n"
        expect(await readFile(backupPath(), "utf8")).toBe(original ?? empty)
        const result = await go()
        expect(result.agents[0]?.mcp).toBe("added")
        expect(result.removed).toEqual([`${agent().file}#mehen-work`])
        const after = await readFile(agent().file, "utf8")
        expect(read(after, "mehen-work")).toBeUndefined()
        expect(read(after)).toEqual(serverEntry(agent(), binary()))
        if (original) expect(after).toContain(agent().toml ? 'model = "other-model"' : '"preference"')
        // An absent original needs no backup once the retired entry has gone.
        if (original === null) expect(await Bun.file(backupPath()).exists()).toBe(false)
        else expect(await readFile(backupPath(), "utf8")).toBe(original)
        expect((await keys()).filter((k) => k.includes("#"))).toEqual([])
        expect((await go()).removed).toEqual([])
        await go({ remove: true })
        if (original === null) expect(await Bun.file(agent().file).exists()).toBe(false)
        else expect(await readFile(agent().file, "utf8")).toBe(original)
        expect(await Bun.file(backupPath()).exists()).toBe(false)
      })
    }
    test("a retired server beside mehen goes through the sibling path: mehen and its backup stay; the last removal restores", async () => {
      const original = present()
      await put(agent().file, original)
      expect((await go()).agents[0]?.mcp).toBe("added")
      await legacyRegistration(agent(), "mehen-work", WORK)
      const result = await go()
      expect(result.agents[0]?.mcp).toBe("unchanged")
      expect(result.removed).toEqual([`${agent().file}#mehen-work`])
      const left = await readFile(agent().file, "utf8")
      expect(read(left, "mehen-work")).toBeUndefined()
      expect(read(left)).toEqual(serverEntry(agent(), binary()))
      expect(await readFile(backupPath(), "utf8")).toBe(original)
      await go({ remove: true })
      expect(await readFile(agent().file, "utf8")).toBe(original)
      expect(await Bun.file(backupPath()).exists()).toBe(false)
    })
    test.skipIf(Boolean(definition.toml))("a duplicate mehen refuses before the retired server is taken out: nothing is written or removed", async () => {
      await put(agent().file, present())
      await legacyRegistration(agent(), "mehen-work", WORK)
      const registered = await readFile(agent().file, "utf8")
      const text = registered.replace(new RegExp(`${JSON.stringify(definition.section)}\\s*:\\s*\\{`), (open) => `${open}"mehen":{"command":"a"},"mehen":{"command":"b"},`)
      expect(text).not.toBe(registered)
      await put(agent().file, text)
      const record = async () => (JSON.parse(await readFile(statePath(), "utf8")) as Record<string, unknown>)[`${relative(home, agent().file)}#mehen-work`]
      const retired = await record()
      const backup = await readFile(backupPath(), "utf8")
      for (const remove of [false, true]) {
        const result = await go({ remove })
        expect(result.agents[0]?.mcp).toBe("failed")
        expect(result.agents[0]?.reason).toContain(`"mehen" more than once in ${JSON.stringify(definition.section)}`)
        expect(result.removed).toEqual([])
        expect(await readFile(agent().file, "utf8")).toBe(text)
        expect(await readFile(backupPath(), "utf8")).toBe(backup)
        expect(await record()).toEqual(retired)
      }
    })
    test("two retired servers both go, a dry run reports them and writes nothing", async () => {
      const original = present()
      await put(agent().file, original)
      await legacyRegistration(agent(), "mehen-work", WORK)
      await legacyRegistration(agent(), "mehen-other", OTHER)
      const before = await readFile(agent().file, "utf8")
      const dry = await go({ dryRun: true })
      expect(dry.removed).toEqual([`${agent().file}#mehen-work`, `${agent().file}#mehen-other`])
      expect(dry.agents[0]?.mcp).toBe("added")
      expect(await readFile(agent().file, "utf8")).toBe(before)
      const result = await go()
      expect(result.removed).toEqual([`${agent().file}#mehen-work`, `${agent().file}#mehen-other`])
      const left = await readFile(agent().file, "utf8")
      expect(read(left, "mehen-work")).toBeUndefined()
      expect(read(left, "mehen-other")).toBeUndefined()
      await go({ remove: true })
      expect(await readFile(agent().file, "utf8")).toBe(original)
      expect(await Bun.file(backupPath()).exists()).toBe(false)
    })
    test("a later unrelated edit survives the retirement, and a genuinely foreign backup still refuses", async () => {
      const original = present()
      await put(agent().file, original)
      await legacyRegistration(agent(), "mehen-work", WORK)
      const configured = await readFile(agent().file, "utf8")
      const later = agent().toml ? '\n[mcp_servers.later]\ncommand = "later"\n' : ""
      if (agent().toml) await writeFile(agent().file, configured + later)
      else await writeFile(agent().file, configured.replace('"other"', '"later"'))
      const removal = await go({ remove: true })
      expect(removal.removed).toEqual([`${agent().file}#mehen-work`])
      const removed = await readFile(agent().file, "utf8")
      expect(removed).toContain("later")
      expect(read(removed, "mehen-work")).toBeUndefined()
      expect(await Bun.file(backupPath()).exists()).toBe(false)
      // Nobody's backup: refused, file untouched.
      await put(backupPath(), "stray")
      const stray = await go()
      expect(stray.agents[0]?.mcp).toBe("skipped")
      expect(stray.agents[0]?.reason).toContain("unowned setup backup")
      expect(await readFile(agent().file, "utf8")).toBe(removed)
      expect(await readFile(backupPath(), "utf8")).toBe("stray")
    })
    // A forced original entry comes back when its registration is
    // removed, whether or not another managed server remains.
    test("forced originals come back: a hand-made mehen-work returns when its retired registration goes, a hand-made mehen on the last removal", async () => {
      const originalEntry = (name: string) => (definition.toml ? `[mcp_servers.${name}]\ncommand = "/my/own/${name}"\nargs = ["mcp", "--legacy"]\n` : `"${name}": {"command": "/my/own/${name}", "args": ["mcp", "--legacy"]}`)
      const fileWith = (names: string[]) => (definition.toml ? `# Keep my settings\nmodel = "other-model"\n\n${names.map(originalEntry).join("\n")}` : `{\n  "preference": "kept",\n  "${definition.section}": {\n    ${names.map(originalEntry).join(",\n    ")}\n  }\n}\n`)
      const own = (name: string) => ({ command: `/my/own/${name}`, args: ["mcp", "--legacy"] })
      // One forced original: the plain mehen entry is hand-made; a retired mehen-work was added beside it.
      const one = fileWith(["mehen"])
      await put(agent().file, one)
      expect((await go()).agents[0]?.mcp).toBe("skipped")
      expect((await go({ force: true })).agents[0]?.mcp).toBe("updated")
      await legacyRegistration(agent(), "mehen-work", WORK)
      const removal = await go({ remove: true })
      expect(removal.removed).toEqual([`${agent().file}#mehen-work`])
      expect(removal.agents[0]?.mcp).toBe("updated")
      expect(await readFile(agent().file, "utf8")).toBe(one)
      expect(await Bun.file(backupPath()).exists()).toBe(false)
      expect((await go()).agents[0]?.mcp).toBe("skipped")
      // Two forced originals: both hand-made, both replaced by 0.2.0.
      await rm(statePath(), { force: true })
      const two = fileWith(["mehen", "mehen-work"])
      await put(agent().file, two)
      expect((await go({ force: true })).agents[0]?.mcp).toBe("updated")
      await legacyRegistration(agent(), "mehen-work", WORK)
      expect(read(await readFile(agent().file, "utf8"), "mehen-work")).toEqual({ ...entryWithoutToolTimeout(agent()), args: ["mcp", "--workspace", WORK] })
      // The retirement puts the hand-made mehen-work back; mehen stays managed.
      const retired = await go()
      expect(retired.removed).toEqual([`${agent().file}#mehen-work`])
      const after = await readFile(agent().file, "utf8")
      expect(read(after, "mehen-work")).toEqual(own("mehen-work"))
      expect(read(after)).toEqual(serverEntry(agent(), binary()))
      await go({ remove: true })
      expect(await readFile(agent().file, "utf8")).toBe(two)
      expect(await Bun.file(backupPath()).exists()).toBe(false)
    })
    test("modes are preserved through a retirement and removal", async () => {
      await put(agent().file, present())
      await chmod(agent().file, 0o640)
      await legacyRegistration(agent(), "mehen-work", WORK)
      await chmod(agent().file, 0o640)
      await go()
      expect((await lstat(agent().file)).mode & 0o777).toBe(0o640)
      await go({ remove: true })
      expect((await lstat(agent().file)).mode & 0o777).toBe(0o640)
    })
  })
})

// ---- the ceiling and the root in the entry ----

const ORIGIN = "https://vault.example"
const SECOND_ORIGIN = "https://second.example"
const NORTHWIND: Config = { vault: ORIGIN, tenant: "tn_work00000001", device: "dev_work00000001", backend: "software", workspaceSlug: "northwind", workspaceName: "Northwind" }
const root = () => join(home, ".config/mehen")
async function activeSlot(config: Config, at = root()): Promise<string> {
  const dir = activeSlotPath(at, config.vault, config.tenant)
  await writeConfig(dir, config)
  await createDeviceKey(dir, "software", {}, { vault: config.vault, tenant: config.tenant })
  return dir
}
async function pendingSlot(slug: string, origin = ORIGIN): Promise<string> {
  const dir = pendingSlotPath(root(), origin, slug)
  const { jwk } = await createDeviceKey(dir, "software", {}, { vault: origin, tenant: null })
  await writeEnrolmentRecord(dir, { v: 1, state: "pending", id: "enr_f1xtR3cP4y5KIRtrusg", code: "ABCD2345", url: `${origin}/w/${slug}/e/ABCD2345`, origin, intent: { workspace: slug, team: null }, name: "office", backend: "software", jwk, session: null, startedAt: "2026-10-28T12:00:00.000Z", expiresAt: "2026-10-28T12:15:00.000Z", hardExpiresAt: null, renewals: 0, legacy: false, claimed: false })
  return dir
}
const claude = () => agents(home, "darwin").find((a) => a.name === "claude-code")!
const claudeEntry = async () => jsonEntry(await readFile(claude().file, "utf8"), "mcpServers") as ({ env?: Record<string, string> } & Record<string, unknown>) | undefined
async function refusal(promise: Promise<unknown>): Promise<CliError> {
  try {
    await promise
  } catch (error) {
    if (error instanceof CliError) return error
    throw error
  }
  throw new Error("expected a CliError")
}

describe("ceiling propagation", () => {
  test("an unrestricted default shell writes no env; the inherited ceiling is written on plain setup, as ids for active slots and the given slug for an absent workspace", async () => {
    await activeSlot(NORTHWIND)
    const plain = await run(["claude-code", "codex", "opencode"])
    expect(plain).toMatchObject({ allowed: null, home: null, unenrolled: [] })
    expect((await claudeEntry())?.env).toBeUndefined()
    await run([], { remove: true })
    const env = { PATH: "", MEHEN_WORKSPACES: "northwind, example" }
    const report = await run(["claude-code", "codex", "opencode"], { env })
    expect(report).toMatchObject({ allowed: ["tn_work00000001", "example"], home: null, unenrolled: ["example"], next: "mehen status --json" })
    expect(report.agents.map((a) => a.mcp)).toEqual(["added", "added", "added"])
    expect(await claudeEntry()).toEqual({ type: "stdio", command: join(home, "bin/mehen"), args: ["mcp"], env: { MEHEN_WORKSPACES: "tn_work00000001,example" } })
    const codex = await readFile(join(home, ".codex/config.toml"), "utf8")
    expect(codex).toContain('env = { "MEHEN_WORKSPACES" = "tn_work00000001,example" }\n')
    expect(tomlEntry(codex)).toEqual({ command: join(home, "bin/mehen"), args: ["mcp"], tool_timeout_sec: 660, env: { MEHEN_WORKSPACES: "tn_work00000001,example" } })
    expect(jsonEntry(await readFile(join(home, ".config/opencode/opencode.json"), "utf8"), "mcp")).toEqual({ type: "local", command: [join(home, "bin/mehen"), "mcp"], enabled: true, timeout: 660_000, environment: { MEHEN_WORKSPACES: "tn_work00000001,example" } })
    expect((await run(["claude-code", "codex", "opencode"], { env })).agents.map((a) => a.mcp)).toEqual(["unchanged", "unchanged", "unchanged"])
  })

  test("with two origins in the root the ids are origin-prefixed, and a pending workspace is written as its slug at its origin", async () => {
    await activeSlot(NORTHWIND)
    await activeSlot({ ...NORTHWIND, vault: SECOND_ORIGIN, tenant: "tn_dev000000001", workspaceSlug: "dev-space" })
    await pendingSlot("example")
    const report = await run(["claude-code"], { workspaces: "northwind,example" })
    expect(report).toMatchObject({ allowed: ["vault.example/tn_work00000001", "vault.example/example"], unenrolled: ["example"] })
    expect((await claudeEntry())?.env).toEqual({ MEHEN_WORKSPACES: "vault.example/tn_work00000001,vault.example/example" })
  })

  test("--workspaces narrows the entry and outside the inherited ceiling refuses and writes nothing", async () => {
    await activeSlot(NORTHWIND)
    const narrowed = { PATH: "", MEHEN_WORKSPACES: "northwind" }
    for (const workspaces of ["example", "northwind,example", "*"]) {
      const refused = await refusal(run(["claude-code"], { env: narrowed, workspaces }))
      expect(refused.code).toBe("workspace_not_allowed")
      expect(refused.next?.say).toContain("Only the human can widen MEHEN_WORKSPACES, in the harness that sets it; nothing here can.")
    }
    // A bare slug is wider than an origin-prefixed inherited one; the prefixed spelling is inside it.
    expect((await refusal(run(["claude-code"], { env: { PATH: "", MEHEN_WORKSPACES: "vault.example/example" }, workspaces: "example" }))).code).toBe("workspace_not_allowed")
    // An empty inherited ceiling allows nothing to be named.
    expect((await refusal(run(["claude-code"], { env: { PATH: "", MEHEN_WORKSPACES: "" }, workspaces: "northwind" }))).code).toBe("workspace_not_allowed")
    expect(await Bun.file(claude().file).exists()).toBe(false)
    expect(await Bun.file(statePath()).exists()).toBe(false)
    expect(await Bun.file(join(home, ".claude/skills/mehen/SKILL.md")).exists()).toBe(false)
    // Narrowing inside the ceiling: the id of the inherited slug, and a prefixed absent workspace as typed.
    expect((await run(["claude-code"], { env: narrowed, workspaces: "tn_work00000001" })).allowed).toEqual(["tn_work00000001"])
    expect((await run(["claude-code"], { env: { PATH: "", MEHEN_WORKSPACES: "vault.example/example" }, workspaces: "vault.example/example" })).allowed).toEqual(["vault.example/example"])
    // No inherited ceiling: --workspaces is the ceiling.
    await run(["claude-code"], { remove: true })
    expect((await run(["claude-code"], { workspaces: "northwind" })).allowed).toEqual(["tn_work00000001"])
    expect((await claudeEntry())?.env).toEqual({ MEHEN_WORKSPACES: "tn_work00000001" })
  })

  test("an empty inherited ceiling is written as the empty list, never left out", async () => {
    const report = await run(["claude-code"], { env: { PATH: "", MEHEN_WORKSPACES: "" } })
    expect(report.allowed).toEqual([])
    expect((await claudeEntry())?.env).toEqual({ MEHEN_WORKSPACES: "" })
  })

  // A narrowed process now
  // writes its narrowing into the entry instead of refusing to write one.
  test("a process narrowed by MEHEN_WORKSPACES or another root writes that narrowing; a root naming a slot still refuses", async () => {
    const other = join(home, "agent-root")
    await activeSlot(NORTHWIND, other)
    await activeSlot({ ...NORTHWIND, tenant: "tn_home00000001", workspaceSlug: "example", device: "dev_home00000001" }, other)
    for (const env of [{ PATH: "", MEHEN_HOME: other, MEHEN_WORKSPACES: "northwind" }, { PATH: "", MEHEN_CONFIG_DIR: other, MEHEN_WORKSPACES: "northwind" }]) {
      const report = await run(["claude-code"], { env })
      expect(report).toMatchObject({ allowed: ["tn_work00000001"], home: other })
      expect((await claudeEntry())?.env).toEqual({ MEHEN_WORKSPACES: "tn_work00000001", MEHEN_HOME: other })
      // The written env, launched on its own, sees exactly that one workspace in that root.
      const listed = await runJv(["workspace", "list", "--json"], { HOME: home, ...(await claudeEntry())?.env })
      expect(listed.code).toBe(0)
      const list = JSON.parse(listed.stdout) as { home: string; workspaces: { state: string; workspace?: { id: string } }[] }
      expect(list.home).toBe(other)
      expect(list.workspaces.map((w) => w.workspace?.id)).toEqual(["tn_work00000001"])
      await run(["claude-code"], { remove: true })
    }
    // The default root named explicitly and an unrestricted `*` are the plain process.
    expect(await run(["claude-code"], { env: { PATH: "", MEHEN_WORKSPACES: "*", MEHEN_HOME: root() } })).toMatchObject({ allowed: null, home: null })
    expect((await claudeEntry())?.env).toBeUndefined()
    await run(["claude-code"], { remove: true })
    // MEHEN_CONFIG_DIR naming a slot is retired: refused before anything is written.
    const slot = activeSlotPath(other, ORIGIN, NORTHWIND.tenant)
    expect((await refusal(run(["claude-code"], { env: { PATH: "", MEHEN_CONFIG_DIR: slot } }))).code).toBe("config_dir_retired")
    expect(await Bun.file(claude().file).exists()).toBe(false)
    // Removing narrows nothing and runs from any process.
    await run(["claude-code"])
    await run(["claude-code"], { env: { PATH: "", MEHEN_WORKSPACES: "" }, remove: true })
    expect(await Bun.file(claude().file).exists()).toBe(false)
  })

  test("--reset-env rebuilds the env from the process running setup: a restricted process never writes wider than itself, an unrestricted one drops a stale restriction", async () => {
    await activeSlot(NORTHWIND)
    await activeSlot({ ...NORTHWIND, tenant: "tn_home00000001", workspaceSlug: "example", device: "dev_home00000001" })
    const path = claude().file
    const forced = (env: Record<string, string>) => put(path, JSON.stringify({ mcpServers: { mehen: { command: "/opt/mehen", args: ["mcp"], env } } }))
    // An entry that had a,b reset from a process with MEHEN_WORKSPACES=a writes a.
    await forced({ MEHEN_WORKSPACES: "northwind,example", MEHEN_SESSION: "x" })
    const restricted = { PATH: "", MEHEN_WORKSPACES: "northwind" }
    expect((await run(["claude-code"], { env: restricted, force: true, resetEnv: true })).agents[0]?.mcp).toBe("updated")
    expect((await claudeEntry())?.env).toEqual({ MEHEN_WORKSPACES: "tn_work00000001" })
    // An unrestricted process may drop a stale restriction.
    expect((await run(["claude-code"], { resetEnv: true })).agents[0]?.mcp).toBe("updated")
    expect((await claudeEntry())?.env).toBeUndefined()
  })

  // Root A holds a.example/acme, root B the same id at b.example.
  // A preserved HOME must not let the launched entry open root B.
  test("a preserved HOME that would move the launched entry to another root is skipped; a MEHEN_HOME pinning it back, or --reset-env, launches in the checked root", async () => {
    const otherHome = await mkdtemp(join(tmpdir(), "mehen-other-home-"))
    try {
      const tenant = "tn_shared0000001"
      const shared = (vault: string): Config => ({ vault, tenant, device: "dev_example00001", backend: "software", workspaceSlug: "acme" })
      await activeSlot(shared("https://a.example"))
      await activeSlot(shared("https://b.example"), join(otherHome, ".config/mehen"))
      const env = { PATH: "", MEHEN_WORKSPACES: "a.example/acme" }
      const launched = async (entryEnv: Record<string, string> | undefined) => {
        const child = await runJv(["workspace", "list", "--json"], { HOME: home, ...entryEnv })
        expect(child.code).toBe(0)
        const list = JSON.parse(child.stdout) as { home: string; workspaces: { origin: string }[] }
        return { home: list.home, origins: list.workspaces.map((w) => w.origin) }
      }
      // Before the fix: written as { HOME: B, MEHEN_WORKSPACES: tn_shared0000001 }, launching in root B at b.example.
      for (const [label, path, agentNames, mcpFile] of [["claude-code", claude().file, ["claude-code"], undefined], ["--mcp-file", join(home, ".config/client/mcp.json"), [], join(home, ".config/client/mcp.json")]] as const) {
        for (const preserved of [{ HOME: otherHome }, { HOME: "" }, { HOME: "relative/home" }, { MEHEN_HOME: join(otherHome, ".config/mehen") }]) {
          const before = JSON.stringify({ mcpServers: { mehen: { command: "/old/mehen", args: ["mcp"], env: preserved } } })
          await put(path, before)
          const result = await run([...agentNames], { env, force: true, ...(mcpFile ? { mcpFile } : {}) })
          expect([label, result.agents[0]?.mcp]).toEqual([label, "skipped"])
          expect(result.agents[0]?.reason).toContain("config root")
          expect(await readFile(path, "utf8")).toBe(before)
          expect(await Bun.file(`${path}.mehen-backup`).exists()).toBe(false)
        }
        await rm(path)
      }
      // An explicit MEHEN_HOME that pins the merged env back to root A is kept with the foreign HOME.
      const rootA = join(home, ".config/mehen")
      await put(claude().file, JSON.stringify({ mcpServers: { mehen: { command: "/old/mehen", args: ["mcp"], env: { HOME: otherHome, MEHEN_HOME: rootA } } } }))
      expect((await run(["claude-code"], { env, force: true })).agents[0]?.mcp).toBe("updated")
      expect((await claudeEntry())?.env).toEqual({ HOME: otherHome, MEHEN_HOME: rootA, MEHEN_WORKSPACES: tenant })
      expect(await launched((await claudeEntry())?.env)).toEqual({ home: rootA, origins: ["https://a.example"] })
      // --reset-env drops the foreign HOME and rebuilds from the caller.
      await run(["claude-code"], { remove: true })
      await put(claude().file, JSON.stringify({ mcpServers: { mehen: { command: "/old/mehen", args: ["mcp"], env: { HOME: otherHome } } } }))
      expect((await run(["claude-code"], { env, force: true, resetEnv: true })).agents[0]?.mcp).toBe("updated")
      expect((await claudeEntry())?.env).toEqual({ MEHEN_WORKSPACES: tenant })
      expect(await launched((await claudeEntry())?.env)).toEqual({ home: rootA, origins: ["https://a.example"] })
    } finally {
      await rm(otherHome, { recursive: true, force: true })
    }
  })

  test("a preserved env is kept key by key; a retired variable, another root or a wider ceiling skips the agent and writes nothing", async () => {
    await activeSlot(NORTHWIND)
    const path = claude().file
    const restricted = { PATH: "", MEHEN_WORKSPACES: "northwind" }
    const cases: [Record<string, string>, Record<string, string>, string][] = [
      [{ MEHEN_CONFIG_DIR: "/Users/someone/.config/mehen" }, {}, "retired variable; rerun with --reset-env"],
      [{ MEHEN_MANAGED_CONTEXT: "work" }, {}, "retired variable; rerun with --reset-env"],
      [{ MEHEN_HOME: "/elsewhere/root" }, {}, "another config root"],
      [{ MEHEN_WORKSPACES: "northwind,example" }, restricted, "workspace_not_allowed"],
      [{ MEHEN_WORKSPACES: "*" }, restricted, "workspace_not_allowed"],
    ]
    for (const [preserved, env, reason] of cases) {
      await rm(statePath(), { force: true })
      await rm(`${path}.mehen-backup`, { force: true })
      const before = JSON.stringify({ mcpServers: { mehen: { command: "/opt/mehen", args: ["mcp"], env: preserved } } })
      await put(path, before)
      const result = await run(["claude-code"], { env: { PATH: "", ...env }, force: true })
      expect(result.agents[0]?.mcp).toBe("skipped")
      expect(result.agents[0]?.reason).toContain(reason)
      expect(await readFile(path, "utf8")).toBe(before)
      expect(await Bun.file(`${path}.mehen-backup`).exists()).toBe(false)
    }
    // Every agent skipped and nothing written: exit 2.
    expect(setupExitCode(await run(["claude-code"], { env: restricted, force: true }))).toBe(2)
    // A narrower preserved ceiling and other variables stay; a missing ceiling is added.
    await rm(statePath(), { force: true })
    await put(path, JSON.stringify({ mcpServers: { mehen: { command: "/opt/mehen", args: ["mcp"], env: { MEHEN_WORKSPACES: "northwind", MEHEN_SESSION: "x" } } } }))
    await run(["claude-code"], { force: true })
    expect((await claudeEntry())?.env).toEqual({ MEHEN_WORKSPACES: "northwind", MEHEN_SESSION: "x" })
    await run(["claude-code"], { remove: true })
    await put(path, JSON.stringify({ mcpServers: { mehen: { command: "/opt/mehen", args: ["mcp"], env: { MEHEN_SESSION: "x" } } } }))
    await run(["claude-code"], { env: restricted, force: true })
    expect((await claudeEntry())?.env).toEqual({ MEHEN_SESSION: "x", MEHEN_WORKSPACES: "tn_work00000001" })
  })

  test("setup --workspace (singular) is gone; MEHEN_WORKSPACE is never propagated", async () => {
    expect(() => setupRequest(parseArgs(["--workspace", "northwind"], setupCommand.spec))).toThrow("--workspaces")
    await activeSlot(NORTHWIND)
    await run(["claude-code"], { env: { PATH: "", MEHEN_WORKSPACE: "northwind" } })
    expect((await claudeEntry())?.env).toBeUndefined()
  })
})

// G0 F-1: setup may be the first command on a new machine. Its state file
// makes ~/.config and the root private, and the first enrol's lock then
// takes the root as it is.
describe("setup on a fresh HOME", () => {
  test("a HOME with nothing: setup creates ~/.config and the root 0700 for its state, and a slot lock under that root then works", async () => {
    await run(["claude-code"])
    const root = join(home, ".config/mehen")
    for (const dir of [join(home, ".config"), root]) expect((await lstat(dir)).mode & 0o777).toBe(0o700)
    expect(await Bun.file(join(root, "setup-state.json")).exists()).toBe(true)
    await withSlotLocks([pendingLockPath(root, "https://app.mehen.dev", "acme")], async () => undefined)
    expect((await lstat(join(root, "locks"))).mode & 0o777).toBe(0o700)
  })
})

describe("managed hosts", () => {
  test("plain setup and --print refuse workspace_mismatch on a managed host and write nothing; removal still runs", async () => {
    await run(["claude-code"])
    const before = await readFile(claude().file, "utf8")
    await mkdir(join(owner, ".config/mehen"), { recursive: true, mode: 0o700 })
    await writeFile(join(owner, ".config/mehen/managed-agents"), "", { mode: 0o600 })
    expect((await refusal(run(["claude-code"], { force: true, resetEnv: true }))).code).toBe("workspace_mismatch")
    expect(await readFile(claude().file, "utf8")).toBe(before)
    expect(() => printSetup({ home, binary: join(home, "bin/mehen"), env: { MEHEN_WORKSPACES: "northwind" }, workspaces: null, format: "json", files: { ownerRoot: owner } })).toThrow("managed")
    expect((await run(["claude-code"], { remove: true })).agents[0]?.mcp).toBe("updated")
  })
})

// A hand-made original replaced from a restricted process came
// back unrestricted when that process removed setup's entry.
describe("restored originals stay inside the caller's ceiling", () => {
  const original = (env?: Record<string, string>) => JSON.stringify({ mcpServers: { mehen: { type: "stdio", command: join(home, "bin/mehen"), args: ["mcp"], ...(env ? { env } : {}) } } })
  const state = async () => readFile(statePath(), "utf8")
  test("removal from a restricted process never restores a wider, retired-variable or foreign-root original; entry, backup and ownership survive", async () => {
    const otherHome = await mkdtemp(join(tmpdir(), "mehen-other-home-"))
    try {
      const cases: [string, Record<string, string>, Record<string, string> | undefined][] = [
        ["acme", { MEHEN_WORKSPACES: "acme" }, undefined],
        ["acme", { MEHEN_WORKSPACES: "acme" }, { MEHEN_WORKSPACES: "*" }],
        ["acme", { MEHEN_WORKSPACES: "acme" }, { MEHEN_WORKSPACES: "acme,other" }],
        ["acme", { MEHEN_WORKSPACES: "acme" }, { MEHEN_WORKSPACES: "acme", MEHEN_HOME: "/elsewhere/root" }],
        ["acme", { MEHEN_WORKSPACES: "acme" }, { MEHEN_WORKSPACES: "acme", HOME: otherHome }],
        ["acme", { MEHEN_WORKSPACES: "acme" }, { MEHEN_WORKSPACES: "acme", MEHEN_CONFIG_DIR: "/Users/someone/.config/mehen" }],
        ["empty", { MEHEN_WORKSPACES: "" }, { MEHEN_WORKSPACES: "acme" }],
        ["empty", { MEHEN_WORKSPACES: "" }, undefined],
      ]
      for (const [label, ceiling, originalEnv] of cases) {
        await rm(statePath(), { force: true })
        await rm(`${claude().file}.mehen-backup`, { force: true })
        await put(claude().file, original(originalEnv))
        const env = { PATH: "", ...ceiling }
        expect((await run(["claude-code"], { env, force: true, resetEnv: true })).agents[0]?.mcp).toBe("updated")
        const managed = await readFile(claude().file, "utf8")
        const ownership = await state()
        const removal = await run(["claude-code"], { env, remove: true })
        expect([label, originalEnv, removal.agents[0]?.mcp]).toEqual([label, originalEnv, "skipped"])
        expect(removal.agents[0]?.reason).toContain("left in place with its backup and ownership record")
        expect(await readFile(claude().file, "utf8")).toBe(managed)
        expect(await readFile(`${claude().file}.mehen-backup`, "utf8")).toBe(original(originalEnv))
        expect(await state()).toBe(ownership)
        expect(removal.skills.map((s) => s.status)).toEqual(["unchanged", "unchanged"])
      }
      // Inside the ceiling the original comes back byte for byte, from the same restricted process.
      await rm(statePath(), { force: true })
      await rm(`${claude().file}.mehen-backup`, { force: true })
      await put(claude().file, original({ MEHEN_WORKSPACES: "acme" }))
      const restricted = { PATH: "", MEHEN_WORKSPACES: "acme" }
      await run(["claude-code"], { env: restricted, force: true, resetEnv: true })
      expect((await run(["claude-code"], { env: restricted, remove: true })).agents[0]?.mcp).toBe("updated")
      expect(await readFile(claude().file, "utf8")).toBe(original({ MEHEN_WORKSPACES: "acme" }))
      // An unrestricted process restores an unrestricted original.
      await rm(statePath(), { force: true })
      await put(claude().file, original())
      await run(["claude-code"], { force: true })
      expect((await run(["claude-code"], { remove: true })).agents[0]?.mcp).toBe("updated")
      expect(await readFile(claude().file, "utf8")).toBe(original())
      // Deletion-only removal still runs from a restricted process.
      await rm(claude().file)
      await run(["claude-code"], { env: restricted })
      expect((await run(["claude-code"], { env: { PATH: "", MEHEN_WORKSPACES: "" }, remove: true })).agents[0]?.mcp).toBe("updated")
      expect(await Bun.file(claude().file).exists()).toBe(false)
    } finally {
      await rm(otherHome, { recursive: true, force: true })
    }
  })

  test("retiring a mehen-<slug> registration from a restricted plain setup keeps a wider hand-made original out, --force or not", async () => {
    const agent = claude()
    const handMade = JSON.stringify({ mcpServers: { "mehen-work": { command: "/my/own/mehen", args: ["mcp"] } } }, null, 2) + "\n"
    await put(agent.file, handMade)
    await legacyRegistration(agent, "mehen-work", "tn_work00000001")
    const registered = await readFile(agent.file, "utf8")
    for (const force of [false, true]) {
      const result = await run(["claude-code"], { env: { PATH: "", MEHEN_WORKSPACES: "acme" }, force })
      expect(result.removed).toEqual([])
      expect(result.agents[0]?.reason).toContain("wider than this process may write")
      const after = await readFile(agent.file, "utf8")
      expect(jsonEntry(after, "mcpServers", "mehen-work")).toEqual(jsonEntry(registered, "mcpServers", "mehen-work"))
      expect(await readFile(`${agent.file}.mehen-backup`, "utf8")).toBe(handMade)
      expect(Object.keys(JSON.parse(await state()) as object)).toContain(".claude.json#mehen-work")
    }
    // The unrestricted owner's plain setup retires it and the hand-made original comes back.
    const retired = await run(["claude-code"])
    expect(retired.removed).toEqual([`${agent.file}#mehen-work`])
    expect(jsonEntry(await readFile(agent.file, "utf8"), "mcpServers", "mehen-work")).toEqual({ command: "/my/own/mehen", args: ["mcp"] })
  })
})

// ---- the shared skill and its consumers ----

describe("--remove scopes", () => {
  test("--remove --agent X keeps the skills while another managed entry remains, in either order, and they go with the last one", async () => {
    for (const [first, second] of [["codex", "claude-code"], ["claude-code", "codex"]] as const) {
      await run(["claude-code", "codex"])
      const partial = await run([first], { remove: true })
      expect(partial.agents.map((a) => [a.name, a.mcp])).toEqual([[first, "updated"]])
      expect(partial.skills.map((s) => s.status)).toEqual(["unchanged", "unchanged"])
      expect(partial.skills[0]?.reason).toContain("Kept: 1 managed MCP entry")
      for (const base of [".claude", ".agents"]) expect(await readFile(join(home, base, "skills/mehen/SKILL.md"), "utf8")).toBe(stampedSkill())
      const remaining = agents(home, "darwin").find((a) => a.name === second)!
      expect(await Bun.file(remaining.file).exists()).toBe(true)
      const last = await run([second], { remove: true })
      expect(last.skills.map((s) => s.status)).toEqual(["removed", "removed"])
      for (const base of [".claude", ".agents"]) expect(await Bun.file(join(home, base, "skills/mehen/SKILL.md")).exists()).toBe(false)
    }
  })

  test("--remove without --agent takes every managed entry, --mcp-file ones included, and the skills", async () => {
    const outside = await mkdtemp(join(tmpdir(), "mehen-client-"))
    try {
      await run(["claude-code"])
      await run([], { mcpFile: join(home, ".config/agent-app/mcp.json") })
      await run([], { mcpFile: join(outside, "mcp.json") })
      const removal = await run([], { remove: true })
      expect(removal.agents.filter((a) => a.mcp === "updated").map((a) => a.name)).toEqual(["claude-code", "mcp-file", "mcp-file"])
      expect(removal.skills.map((s) => s.status)).toEqual(["removed", "unchanged"])
      expect(await Bun.file(claude().file).exists()).toBe(false)
      expect(await Bun.file(join(home, ".config/agent-app/mcp.json")).exists()).toBe(false)
      expect(await Bun.file(join(outside, "mcp.json")).exists()).toBe(false)
      expect(await Bun.file(statePath()).exists()).toBe(false)
    } finally {
      await rm(outside, { recursive: true, force: true })
    }
  })
})

// Whole removal skipped every state key containing `#`, so an
// --mcp-file named client#one.json stayed registered with its backup.
test("--mcp-file names containing # are whole file paths: whole removal takes them, a #mehen- spelling is never another file's server, and the skills go with the last entry", async () => {
  const outside = await mkdtemp(join(tmpdir(), "mehen-client-"))
  try {
    const files = [join(home, "clients/client#one.json"), join(home, "clients/a.json"), join(home, "clients/a.json#mehen-b"), join(outside, "x#mehen-y.json")]
    for (const file of files) expect((await run([], { mcpFile: file })).agents[0]?.mcp).toBe("added")
    await run(["claude-code"])
    // Removing one leaves the other: a.json#mehen-b is not a server of a.json.
    expect((await run([], { mcpFile: join(home, "clients/a.json"), remove: true })).agents[0]?.mcp).toBe("updated")
    expect(jsonEntry(await readFile(join(home, "clients/a.json#mehen-b"), "utf8"), "mcpServers")).toBeDefined()
    const keys = Object.keys(JSON.parse(await readFile(statePath(), "utf8")) as object)
    expect(keys).toContain("clients/a.json#mehen-b")
    expect(keys).not.toContain("clients/a.json")
    // claude-code goes; the skills stay with the --mcp-file entries.
    expect((await run(["claude-code"], { remove: true })).skills.map((s) => s.status)).toEqual(["unchanged", "unchanged"])
    const removal = await run([], { remove: true })
    expect(removal.agents.map((a) => [a.name, a.mcp, a.files[0]])).toEqual([files[0], files[2], files[3]].map((file) => ["mcp-file", "updated", file]))
    expect(removal.skills.map((s) => s.status)).toEqual(["removed", "unchanged"])
    for (const file of files) {
      expect(await Bun.file(file).exists()).toBe(false)
      expect(await Bun.file(`${file}.mehen-backup`).exists()).toBe(false)
    }
    expect(await Bun.file(statePath()).exists()).toBe(false)
    // The one spelling that would read as a retired server of a known agent's file is refused.
    const legacy = await refusal(run([], { mcpFile: join(home, ".claude.json#mehen-work") }))
    expect(legacy.code).toBe("usage")
    expect(await Bun.file(join(home, ".claude.json#mehen-work")).exists()).toBe(false)
  } finally {
    await rm(outside, { recursive: true, force: true })
  }
})

// ---- --mcp-file: any JSON MCP client ----

describe("--mcp-file", () => {
  const appFile = () => join(home, ".config/agent-app/mcp.json")
  test("writes mcpServers.mehen into the named file only, owned by its path relative to HOME, with no skill folder", async () => {
    await mkdir(join(home, ".codex"))
    const report = await run([], { mcpFile: appFile(), env: { PATH: "", MEHEN_WORKSPACES: "northwind" } })
    expect(report.agents).toEqual([{ name: "mcp-file", detected: true, mcp: "added", skill: null, skillReason: "mehen does not know which skills folder this client reads", files: [appFile()], restart: `Restart the client that reads ${appFile()}.`, server: "mehen" }])
    expect(JSON.parse(await readFile(appFile(), "utf8"))).toEqual({ mcpServers: { mehen: { command: join(home, "bin/mehen"), args: ["mcp"], env: { MEHEN_WORKSPACES: "northwind" } } } })
    expect(Object.keys(JSON.parse(await readFile(statePath(), "utf8")) as object)).toContain(".config/agent-app/mcp.json")
    expect(await Bun.file(join(home, ".codex/config.toml")).exists()).toBe(false)
    expect((await run([], { mcpFile: appFile(), env: { PATH: "", MEHEN_WORKSPACES: "northwind" } })).agents[0]?.mcp).toBe("unchanged")
    await run([], { mcpFile: appFile(), remove: true })
    expect(await Bun.file(appFile()).exists()).toBe(false)
  })

  test("a hand-made mehen entry stays foreign until --force; one carrying MEHEN_CONFIG_DIR needs --reset-env too (a native app's file)", async () => {
    const before = JSON.stringify({ mcpServers: { other: { command: "other" }, mehen: { command: "/Users/sam/.local/bin/mehen", args: ["mcp"], env: { MEHEN_CONFIG_DIR: "/Users/sam/.config/mehen" } } } }, null, 2)
    await put(appFile(), before)
    expect((await run([], { mcpFile: appFile() })).agents[0]?.mcp).toBe("skipped")
    expect((await run([], { mcpFile: appFile(), force: true })).agents[0]?.reason).toContain("retired variable; rerun with --reset-env")
    expect(await readFile(appFile(), "utf8")).toBe(before)
    const env = { PATH: "", MEHEN_HOME: root(), MEHEN_WORKSPACES: "example,northwind" }
    expect((await run([], { mcpFile: appFile(), force: true, resetEnv: true, env })).agents[0]?.mcp).toBe("updated")
    expect(JSON.parse(await readFile(appFile(), "utf8"))).toEqual({ mcpServers: { other: { command: "other" }, mehen: { command: join(home, "bin/mehen"), args: ["mcp"], env: { MEHEN_WORKSPACES: "example,northwind" } } } })
    // Removal would bring back the original with its retired MEHEN_CONFIG_DIR: refused, nothing changes.
    const managed = await readFile(appFile(), "utf8")
    const removal = await run([], { mcpFile: appFile(), remove: true })
    expect(removal.agents[0]?.mcp).toBe("skipped")
    expect(removal.agents[0]?.reason).toContain("retired variable MEHEN_CONFIG_DIR")
    expect(await readFile(appFile(), "utf8")).toBe(managed)
    expect(await readFile(`${appFile()}.mehen-backup`, "utf8")).toBe(before)
  })

  test("another client's file (servers or mcp at the top) refuses usage naming --agent, and nothing is written", async () => {
    for (const [top, agent] of [["servers", "vscode"], ["mcp", "opencode"]] as const) {
      const text = JSON.stringify({ [top]: {} })
      await put(appFile(), text)
      const refused = await refusal(run([], { mcpFile: appFile() }))
      expect(refused.code).toBe("usage")
      expect(refused.message).toContain(`--agent ${agent}`)
      expect(await readFile(appFile(), "utf8")).toBe(text)
      expect(await Bun.file(`${appFile()}.mehen-backup`).exists()).toBe(false)
    }
  })

  test("a file outside HOME is written in its own existing directory and owned by its absolute path; a missing directory refuses", async () => {
    const outside = await mkdtemp(join(tmpdir(), "mehen-client-"))
    try {
      const file = join(outside, "mcp.json")
      expect((await run([], { mcpFile: file })).agents[0]?.mcp).toBe("added")
      expect(Object.keys(JSON.parse(await readFile(statePath(), "utf8")) as object)).toContain(file)
      expect(jsonEntry(await readFile(file, "utf8"), "mcpServers")).toEqual({ command: join(home, "bin/mehen"), args: ["mcp"] })
      await run([], { mcpFile: file, remove: true })
      expect(await Bun.file(file).exists()).toBe(false)
      expect((await refusal(run([], { mcpFile: join(outside, "missing/mcp.json") }))).code).toBe("usage")
      // A link in that directory pointing elsewhere is refused, like a link out of HOME.
      await symlink(join(tmpdir(), "elsewhere.json"), file)
      const linked = await run([], { mcpFile: file })
      expect(linked.agents[0]?.mcp).toBe("failed")
      expect(linked.agents[0]?.reason).toContain("symbolic link")
    } finally {
      await rm(outside, { recursive: true, force: true })
    }
  })
})

// An outside-HOME file's directory is moved aside and replaced by
// a link to another directory holding the same managed entry and backup.
describe("an --mcp-file directory replaced by a link", () => {
  type Fixture = { parent: string; base: string; saved: string; escaped: string; file: string }
  async function fixture(test: (f: Fixture) => Promise<void>): Promise<void> {
    const parent = await mkdtemp(join(tmpdir(), "mehen-client-"))
    const f = { parent, base: join(parent, "client"), saved: join(parent, "saved-client"), escaped: join(parent, "elsewhere"), file: join(parent, "client/mcp.json") }
    try {
      await mkdir(f.base, { mode: 0o700 })
      await mkdir(f.escaped, { mode: 0o700 })
      await writeFile(f.file, '{"setting":"original"}\n')
      expect((await run([], { mcpFile: f.file })).agents[0]?.mcp).toBe("added")
      await writeFile(join(f.escaped, "mcp.json"), await readFile(f.file, "utf8"))
      await writeFile(join(f.escaped, "mcp.json.mehen-backup"), await readFile(`${f.file}.mehen-backup`, "utf8"))
      await test(f)
    } finally {
      await rm(parent, { recursive: true, force: true })
    }
  }
  const bytes = async (dir: string) => [await readFile(join(dir, "mcp.json"), "utf8"), await readFile(join(dir, "mcp.json.mehen-backup"), "utf8")]
  const recorded = async (file: string) => Object.keys(JSON.parse(await readFile(statePath(), "utf8")) as object).includes(file)

  test("explicit, whole and dry-run removal refuse the link, touch neither directory and keep the ownership record", () => fixture(async (f) => {
    const original = await bytes(f.base)
    const escaped = await bytes(f.escaped)
    await rename(f.base, f.saved)
    await symlink(f.escaped, f.base)
    for (const extra of [{ mcpFile: f.file, remove: true }, { remove: true }, { mcpFile: f.file, remove: true, dryRun: true }]) {
      const result = await run([], extra)
      const entry = result.agents.find((a) => a.name === "mcp-file")
      expect(entry?.mcp).toBe("failed")
      expect(entry?.reason).toContain("never through a symbolic link")
      expect(await bytes(f.escaped)).toEqual(escaped)
      expect(await bytes(f.saved)).toEqual(original)
      expect(await recorded(f.file)).toBe(true)
      // The skills stay with the entry that could not be removed.
      if (!("dryRun" in extra)) expect(result.skills.map((s) => s.status)).toEqual(["unchanged", "unchanged"])
    }
    // A registration through the link is refused too.
    expect((await refusal(run([], { mcpFile: f.file }))).code).toBe("usage")
    expect(await bytes(f.escaped)).toEqual(escaped)
  }))

  test("a directory swapped for a link at the write guard is refused before the rename; neither directory's files change", () => fixture(async (f) => {
    const original = await bytes(f.base)
    const escaped = await bytes(f.escaped)
    const result = await run([], { mcpFile: f.file, remove: true, beforeWrite: async () => { await rename(f.base, f.saved); await symlink(f.escaped, f.base) } })
    expect(result.agents[0]?.mcp).toBe("failed")
    expect(result.agents[0]?.reason).toContain("no longer the directory setup checked")
    expect(await bytes(f.escaped)).toEqual(escaped)
    expect(await bytes(f.saved)).toEqual(original)
    expect(await recorded(f.file)).toBe(true)
  }))
})

// ---- --print: a pure render ----

describe("--print", () => {
  const binary = () => join(home, "bin/mehen")
  const print = (env: Record<string, string>, workspaces: string | null = null, format: "json" | "toml" = "json") => printSetup({ home, binary: binary(), env, workspaces, format, files: { ownerRoot: owner } })
  test("renders the entry as typed: the inherited ceiling, MEHEN_HOME when not default, nothing when unrestricted", () => {
    const json = print({ MEHEN_WORKSPACES: " northwind , example " })
    expect(json).toEqual({ printed: true, format: "json", server: "mehen", entry: { command: binary(), args: ["mcp"], env: { MEHEN_WORKSPACES: "northwind,example" } }, text: JSON.stringify({ mcpServers: { mehen: { command: binary(), args: ["mcp"], env: { MEHEN_WORKSPACES: "northwind,example" } } } }, null, 2), allowed: ["northwind", "example"], home: null })
    expect(print({})).toMatchObject({ entry: { command: binary(), args: ["mcp"] }, allowed: null, home: null })
    expect(print({ MEHEN_WORKSPACES: "*", MEHEN_HOME: root() })).toMatchObject({ entry: { command: binary(), args: ["mcp"] }, allowed: null, home: null })
    expect(print({ MEHEN_WORKSPACES: "" }).entry).toEqual({ command: binary(), args: ["mcp"], env: { MEHEN_WORKSPACES: "" } })
    const toml = print({ MEHEN_HOME: "/agents/root" }, "northwind", "toml")
    expect(toml.text).toBe(`[mcp_servers.mehen]\ncommand = ${JSON.stringify(binary())}\nargs = ["mcp"]\nenv = { "MEHEN_WORKSPACES" = "northwind", "MEHEN_HOME" = "/agents/root" }\n`)
    expect(toml).toMatchObject({ format: "toml", entry: toml.text, allowed: ["northwind"], home: "/agents/root" })
    expect(Bun.TOML.parse(toml.text)).toEqual({ mcp_servers: { mehen: { command: binary(), args: ["mcp"], env: { MEHEN_WORKSPACES: "northwind", MEHEN_HOME: "/agents/root" } } } })
  })

  test("--workspaces narrows textually: each entry must equal an inherited one, else workspace_not_allowed; with no inherited list it passes through", () => {
    expect(print({ MEHEN_WORKSPACES: "northwind,example" }, "example").allowed).toEqual(["example"])
    for (const workspaces of ["other", "northwind,other", "*", "tn_work00000001"]) expect(() => print({ MEHEN_WORKSPACES: "northwind" }, workspaces)).toThrow("outside MEHEN_WORKSPACES")
    expect(print({}, "tn_work00000001, vault.example/example").allowed).toEqual(["tn_work00000001", "vault.example/example"])
    expect(() => print({}, "not a slug!")).toThrow("not a workspace slug")
    expect(() => print({ MEHEN_CONFIG_DIR: join(root(), "workspaces/vault.example/tn_work00000001") })).toThrow("names a slot")
  })

  test("reads no slot and writes nothing: a read-only HOME with a ceiling every other command refuses as ambiguous", async () => {
    await activeSlot(NORTHWIND)
    await activeSlot({ ...NORTHWIND, vault: SECOND_ORIGIN, tenant: "tn_dev000000001" })
    const env = { PATH: "", MEHEN_WORKSPACES: "northwind" }
    expect((await refusal(run(["claude-code"], { env }))).code).toBe("context_ambiguous")
    const listing = async () => (await readdir(home, { recursive: true })).sort()
    const before = await listing()
    await chmod(home, 0o500)
    try {
      expect(print(env)).toMatchObject({ entry: { env: { MEHEN_WORKSPACES: "northwind" } }, allowed: ["northwind"] })
    } finally {
      await chmod(home, 0o700)
    }
    expect(await listing()).toEqual(before)
  })

  // The CLI's error renderer selected a slot (reading its
  // config.json) to decorate a refused print. A child process runs the real
  // main() with every file-system call that names a path under HOME
  // recorded, for each way --print is refused.
  test("a refused --print reads and writes nothing under HOME through the whole CLI, error rendering included", async () => {
    const probeDir = await mkdtemp(join(tmpdir(), "mehen-print-probe-"))
    try {
      await activeSlot(NORTHWIND)
      await run(["claude-code"])
      const probe = join(probeDir, "probe.ts")
      const cli = join(import.meta.dir, "../cli.ts")
      await writeFile(probe, `import { mock } from "bun:test"
import * as fsp from "node:fs/promises"
import * as fs from "node:fs"
// Copies first: mock.module replaces these namespaces in place.
const realFsp = { ...fsp }
const realFs = { ...fs }
const home = process.env.HOME
const touched = []
const note = (name, path) => { const text = String(path); if (text.startsWith(home)) touched.push(name + " " + text.slice(home.length)) }
const wrap = (module, names) => Object.fromEntries(names.filter((n) => typeof module[n] === "function").map((n) => [n, (...args) => { note(n, args[0]); if (n === "rename" || n === "renameSync") note(n, args[1]); return module[n](...args) }]))
mock.module("node:fs/promises", () => ({ ...realFsp, ...wrap(realFsp, ["readFile", "readdir", "lstat", "stat", "open", "writeFile", "mkdir", "rename", "rm", "realpath", "access", "chmod", "copyFile"]) }))
mock.module("node:fs", () => ({ ...realFs, ...wrap(realFs, ["readFileSync", "readdirSync", "lstatSync", "statSync", "openSync", "writeFileSync", "mkdirSync", "existsSync", "renameSync", "rmSync"]) }))
const { main } = await import(${JSON.stringify(cli)})
const code = await main(JSON.parse(process.argv[2]), process.env)
console.log("PROBE " + JSON.stringify({ code, touched }))
`)
      const cases: [string[], Record<string, string>, number, string][] = [
        [["setup", "--print", "--remove", "--json"], {}, 2, "usage"],
        [["setup", "--print", "--format", "yaml", "--json"], {}, 2, "usage"],
        [["setup", "--print", "--json"], { MEHEN_WORKSPACES: "not a slug!" }, 2, "usage"],
        [["setup", "--print", "--workspaces", "other", "--json"], { MEHEN_WORKSPACES: "northwind" }, 2, "workspace_not_allowed"],
        [["setup", "--print", "--json"], { MEHEN_MANAGED_CONTEXT: "work" }, 2, "workspace_mismatch"],
        [["setup", "--print", "--json"], { MEHEN_CONFIG_DIR: activeSlotPath(root(), ORIGIN, NORTHWIND.tenant) }, 2, "config_dir_retired"],
        // A valid render: from source it is refused only after rendering, for not being the installed binary.
        [["setup", "--print", "--format", "toml", "--json"], { MEHEN_WORKSPACES: "northwind" }, 2, "usage"],
      ]
      for (const [argv, extra, code, error] of cases) {
        const proc = Bun.spawn([process.execPath, probe, JSON.stringify(argv)], { env: { PATH: process.env.PATH ?? "", HOME: home, ...extra }, stdout: "pipe", stderr: "pipe", timeout: 8000 })
        const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
        await proc.exited
        const line = stdout.split("\n").find((l) => l.startsWith("PROBE "))
        if (line === undefined) throw new Error(`the probe printed nothing for ${JSON.stringify(argv)}: ${stderr}`)
        const result = JSON.parse(line.slice(6)) as { code: number; touched: string[] }
        const body = JSON.parse(stdout.split("\n")[0] as string) as { error: string }
        expect([argv, extra, result.code, body.error, result.touched]).toEqual([argv, extra, code, error, []])
      }
    } finally {
      await rm(probeDir, { recursive: true, force: true })
    }
  }, 60_000)

  test("--print conflicts with every writing flag, --format needs --print, at the command line too", async () => {
    const request = (...argv: string[]) => setupRequest(parseArgs(argv, setupCommand.spec))
    for (const flag of [["--remove"], ["--dry-run"], ["--force"], ["--reset-env"], ["--agent", "codex"], ["--mcp-file", "/tmp/x.json"]]) {
      expect(() => request("--print", ...flag)).toThrow(`cannot be combined with ${flag[0]}`)
    }
    expect(() => request("--format", "toml")).toThrow("--format goes with --print")
    expect(() => request("--print", "--format", "yaml")).toThrow("json or toml")
    expect(request("--print", "--workspaces", "a")).toMatchObject({ print: { workspaces: "a", format: "json" } })
    const result = await runJv(["setup", "--print", "--remove", "--json"], { HOME: home })
    expect(result.code).toBe(2)
    expect(JSON.parse(result.stdout)).toMatchObject({ error: "usage", message: expect.stringContaining("--print only renders the entry") })
  })
})

// ---- the skills report ----

describe("the skills report", () => {
  test("a refused skill write is failed with its reason and exit 1; symlinked and foreign skills are external, never failed", async () => {
    await mkdir(join(home, ".agents/skills/mehen"), { recursive: true })
    await chmod(join(home, ".agents/skills/mehen"), 0o500)
    try {
      const result = await run(["claude-code", "codex"])
      expect(result.skills.map((s) => s.status)).toEqual(["added", "failed"])
      expect(result.skills[1]?.reason).toContain(join(home, ".agents/skills/mehen/SKILL.md"))
      expect(setupExitCode(result)).toBe(1)
    } finally {
      await chmod(join(home, ".agents/skills/mehen"), 0o700)
    }
    await rm(join(home, ".agents/skills/mehen"), { recursive: true })
    await symlink(join(home, "elsewhere"), join(home, ".agents/skills/mehen"))
    const external = await run(["claude-code", "codex"])
    expect(external.skills.map((s) => [s.status, s.reason])).toEqual([["unchanged", undefined], ["external", "Symlinked skill left alone."]])
    expect(setupExitCode(external)).toBe(0)
  })

  test("skills-only setup (the updater's refresh) exits 1 only on a failed skill; external is policy", async () => {
    await put(join(home, ".agents/skills/mehen/SKILL.md"), stampedSkill("0.0.1"))
    await put(join(home, ".claude/skills/mehen/SKILL.md"), "a foreign skill")
    const refreshed = await run([], { skillsOnly: true })
    expect(refreshed.agents).toEqual([])
    expect(refreshed.skills.map((s) => s.status)).toEqual(["external", "updated"])
    expect(setupExitCode(refreshed)).toBe(0)
    await writeFile(join(home, ".agents/skills/mehen/SKILL.md"), stampedSkill("0.0.1"))
    await chmod(join(home, ".agents/skills/mehen"), 0o500)
    try {
      const failed = await run([], { skillsOnly: true })
      expect(failed.skills.map((s) => s.status)).toEqual(["external", "failed"])
      expect(failed.skills[1]?.reason).toBeDefined()
      expect(setupExitCode(failed)).toBe(1)
    } finally {
      await chmod(join(home, ".agents/skills/mehen"), 0o700)
    }
  })

  test("an agent file that cannot be written is mcp failed with its reason and exit 1", async () => {
    await put(join(home, ".cursor/mcp.json"), "{}")
    await chmod(join(home, ".cursor"), 0o500)
    try {
      const result = await run(["cursor"])
      expect(result.agents[0]).toMatchObject({ mcp: "failed", reason: expect.stringContaining(join(home, ".cursor/mcp.json")) })
      expect(setupExitCode(result)).toBe(1)
      expect(await readFile(join(home, ".cursor/mcp.json"), "utf8")).toBe("{}")
    } finally {
      await chmod(join(home, ".cursor"), 0o700)
    }
  })
})
