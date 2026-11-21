import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runJv } from "../testing/run-mehen.ts"
import { brewPrefix } from "../testing/brew-prefix.ts"
import { CLAUDE_TOOLS, CODEX_TOOLS, CODEX_TRUST, CURSOR_WRITE_MATCHER, claudeHookCommand, claudeSettings, codexHooks, cursorHooks, installClaudeGuard, installCodexGuard, installCursorGuard, installPiGuard, ownsCommand } from "./install.ts"
import { piExtension } from "./pi.ts"
import { parseJson } from "../setup/formats.ts"

const BIN = "/Users/a/.local/bin/mehen"
const VAULT = "/Users/a/Library/Application Support/Mehen/vault"
const command = { type: "command", command: `${BIN} hook claude-code`, timeout: 10 }

describe("the settings", () => {
  test("mehen's hooks join what is there, and their own entries are replaced, never doubled", () => {
    const theirs = { matcher: "Bash", hooks: [{ type: "command", command: "my-linter" }] }
    const first = claudeSettings({ model: "opus", hooks: { PreToolUse: [theirs] } }, BIN, [VAULT], false).settings
    expect(first).toEqual({ model: "opus", hooks: { PreToolUse: [theirs, { matcher: CLAUDE_TOOLS, hooks: [command] }], SessionStart: [{ hooks: [command] }] } })
    expect(claudeSettings(first, BIN, [VAULT], false).settings).toEqual(first)
    const moved = claudeSettings(first, "/opt/mehen/bin/mehen", [VAULT], false).settings as { hooks: { PreToolUse: unknown[] } }
    expect(moved.hooks.PreToolUse).toHaveLength(2)
  })

  test("removal takes out only mehen's hooks and leaves the person's", () => {
    const theirs = { matcher: "Bash", hooks: [{ type: "command", command: "my-linter" }] }
    const installed = claudeSettings({ hooks: { PreToolUse: [theirs] } }, BIN, [VAULT], false).settings
    expect(claudeSettings(installed, BIN, [VAULT], true).settings).toEqual({ hooks: { PreToolUse: [theirs] } })
    expect(claudeSettings(claudeSettings({}, BIN, [VAULT], false).settings, BIN, [VAULT], true).settings).toEqual({})
  })

  test("a sandbox the person turned on keeps the shell out of the vault's folder; an off one is left alone", () => {
    const on = claudeSettings({ sandbox: { enabled: true, filesystem: { denyRead: ["~/secrets"] } } }, BIN, [VAULT], false)
    expect(on.sandbox).toBe("protected")
    expect(on.settings.sandbox).toEqual({ enabled: true, filesystem: { denyRead: ["~/secrets", VAULT], denyWrite: [VAULT] } })
    expect(on.owned).toEqual({ denyRead: [VAULT], denyWrite: [VAULT] })
    expect(claudeSettings(on.settings, BIN, [VAULT], true, on.owned).settings.sandbox).toEqual({ enabled: true, filesystem: { denyRead: ["~/secrets"] } })
    const off = claudeSettings({ sandbox: { enabled: false } }, BIN, [VAULT], false)
    expect(off).toMatchObject({ sandbox: "off", settings: { sandbox: { enabled: false } } })
  })

  test("a path the person had in the sandbox before is theirs: never recorded as mehen's, never removed", () => {
    const theirs = { sandbox: { enabled: true, filesystem: { denyRead: [VAULT] } } }
    const on = claudeSettings(theirs, BIN, [VAULT], false)
    expect(on.owned).toEqual({ denyRead: [], denyWrite: [VAULT] })
    expect(claudeSettings(on.settings, BIN, [VAULT], true, on.owned).settings.sandbox).toEqual({ enabled: true, filesystem: { denyRead: [VAULT] } })
  })

  test("a moved data folder: mehen's old path goes, the new one comes", () => {
    const on = claudeSettings({ sandbox: { enabled: true } }, BIN, ["/old"], false)
    const moved = claudeSettings(on.settings, BIN, ["/new"], false, on.owned)
    expect(moved.settings.sandbox).toEqual({ enabled: true, filesystem: { denyRead: ["/new"], denyWrite: ["/new"] } })
    expect(moved.owned).toEqual({ denyRead: ["/new"], denyWrite: ["/new"] })
  })

  test("a path with spaces or quotes is quoted for the shell", () => {
    expect(claudeHookCommand("/Users/a b/bin/mehen")).toBe("'/Users/a b/bin/mehen' hook claude-code")
    expect(claudeHookCommand("/x/it's/mehen")).toBe("'/x/it'\\''s/mehen' hook claude-code")
  })
})

describe("the file", () => {
  let home: string
  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "mehen-guard-"))
  })
  afterEach(async () => {
    await rm(home, { recursive: true, force: true })
  })
  const file = () => join(home, ".claude", "settings.json")

  test("no ~/.claude folder: skipped, nothing written", async () => {
    expect(await installClaudeGuard({ home, binary: BIN, vaultDirs: [VAULT], remove: false, dryRun: false })).toMatchObject({ status: "skipped", reason: expect.stringContaining("no ~/.claude folder") })
  })

  test("added once with a backup of the original, unchanged the second time, removed cleanly", async () => {
    await mkdir(join(home, ".claude"))
    await writeFile(file(), '{\n  // mine\n  "model": "opus",\n}\n')
    expect(await installClaudeGuard({ home, binary: BIN, vaultDirs: [VAULT], remove: false, dryRun: false })).toMatchObject({ status: "added", sandbox: "off" })
    expect(await readFile(`${file()}.mehen-backup`, "utf8")).toBe('{\n  // mine\n  "model": "opus",\n}\n')
    expect(JSON.parse(await readFile(file(), "utf8"))).toMatchObject({ model: "opus", hooks: { PreToolUse: [{ matcher: CLAUDE_TOOLS }] } })
    expect(await installClaudeGuard({ home, binary: BIN, vaultDirs: [VAULT], remove: false, dryRun: false })).toMatchObject({ status: "unchanged" })
    expect(await installClaudeGuard({ home, binary: BIN, vaultDirs: [VAULT], remove: true, dryRun: false })).toMatchObject({ status: "removed" })
    expect(JSON.parse(await readFile(file(), "utf8"))).toEqual({ model: "opus" })
  })

  test("a dry run says what it would do and writes nothing", async () => {
    await mkdir(join(home, ".claude"))
    expect(await installClaudeGuard({ home, binary: BIN, vaultDirs: [VAULT], remove: false, dryRun: true })).toMatchObject({ status: "added" })
    expect(await Bun.file(file()).exists()).toBe(false)
  })

  test("a malformed file is skipped and left as it was", async () => {
    await mkdir(join(home, ".claude"))
    await writeFile(file(), "{ not json")
    expect(await installClaudeGuard({ home, binary: BIN, vaultDirs: [VAULT], remove: false, dryRun: false })).toMatchObject({ status: "skipped", reason: expect.stringContaining("Malformed") })
    expect(await readFile(file(), "utf8")).toBe("{ not json")
  })

  test("mehen guard install needs an installed mehen", async () => {
    const result = await runJv(["guard", "install", "--json"], { HOME: home })
    expect(result.code).toBe(2)
    expect(JSON.parse(result.stdout)).toMatchObject({ error: "usage" })
  })

  test("mehen guard install from an installed mehen writes the hooks", async () => {
    await mkdir(join(home, ".claude"))
    const result = await runJv(["guard", "install", "--json"], { HOME: home, MEHEN_SELF_EXECUTABLE: BIN })
    expect(result.code).toBe(0)
    expect(JSON.parse(result.stdout)).toMatchObject({ agents: [{ agent: "claude-code", status: "added" }, { agent: "pi", status: "skipped" }, { agent: "cursor", status: "skipped", absent: true }, { agent: "codex", status: "skipped", absent: true }] })
    expect(JSON.parse(await readFile(file(), "utf8")).hooks.SessionStart[0].hooks[0].command).toBe(`${BIN} hook claude-code`)
  })
})

describe("a mehen Homebrew installed", () => {
  let home: string
  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "mehen-guard-brew-"))
  })
  afterEach(async () => {
    await rm(home, { recursive: true, force: true })
  })

  test("guard install names brew's opt/mehen link, which outlives brew upgrade, never the keg", async () => {
    const brew = await brewPrefix(await import("node:fs").then((fs) => fs.realpathSync(home)))
    for (const agent of [".claude", ".pi", ".cursor", ".codex"]) await mkdir(join(home, agent))
    const result = await runJv(["guard", "install", "--json"], { HOME: home, MEHEN_SELF_EXECUTABLE: brew.bin })
    expect(result.code).toBe(0)
    expect(JSON.parse(await readFile(join(home, ".claude", "settings.json"), "utf8")).hooks.SessionStart[0].hooks[0].command).toBe(`${brew.opt} hook claude-code`)
    expect(await readFile(join(home, ".pi", "agent", "extensions", "mehen-guard.ts"), "utf8")).toContain(JSON.stringify(brew.opt))
    for (const file of [join(home, ".cursor", "hooks.json"), join(home, ".codex", "hooks.json")]) {
      const text = await readFile(file, "utf8")
      expect(text).toContain(brew.opt)
      expect(text).not.toContain("Cellar")
    }
  })
})

describe("pi", () => {
  let home: string
  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "mehen-guard-pi-"))
  })
  afterEach(async () => {
    await rm(home, { recursive: true, force: true })
  })
  const file = () => join(home, ".pi", "agent", "extensions", "mehen-guard.ts")

  test("the extension is written once, rewritten when mehen moves, and removed; another file of that name is left alone", async () => {
    expect(await installPiGuard({ home, binary: BIN, remove: false, dryRun: false })).toMatchObject({ status: "skipped", reason: expect.stringContaining("no ~/.pi folder") })
    await mkdir(join(home, ".pi"))
    expect(await installPiGuard({ home, binary: BIN, remove: false, dryRun: false })).toMatchObject({ status: "added" })
    expect(await installPiGuard({ home, binary: BIN, remove: false, dryRun: false })).toMatchObject({ status: "unchanged" })
    expect(await installPiGuard({ home, binary: "/opt/mehen", remove: false, dryRun: false })).toMatchObject({ status: "updated" })
    expect(await readFile(file(), "utf8")).toContain('const MEHEN = "/opt/mehen"')
    expect(await installPiGuard({ home, binary: BIN, remove: true, dryRun: false })).toMatchObject({ status: "removed" })
    expect(await Bun.file(file()).exists()).toBe(false)
    await writeFile(file(), "// my own guard\n")
    expect(await installPiGuard({ home, binary: BIN, remove: false, dryRun: false })).toMatchObject({ status: "skipped", reason: expect.stringContaining("not mehen's") })
    expect(await installPiGuard({ home, binary: BIN, remove: true, dryRun: false })).toMatchObject({ status: "skipped" })
    expect(await readFile(file(), "utf8")).toBe("// my own guard\n")
  })

  test("in pi, the extension blocks what mehen hook check denies, notifies, and fails closed", async () => {
    const fake = join(home, "fake-mehen")
    const verdicts = join(home, "verdict.json")
    await writeFile(fake, `#!/bin/sh\ncat > /dev/null\ncat ${JSON.stringify(verdicts)}\n`, { mode: 0o755 })
    const extension = join(home, "ext.ts")
    await writeFile(extension, piExtension(fake))
    const handlers: Record<string, (event: unknown, ctx: unknown) => Promise<unknown>> = {}
    const notes: string[] = []
    const { default: load } = (await import(extension)) as { default: (pi: unknown) => void }
    load({ on: (name: string, handler: (event: unknown, ctx: unknown) => Promise<unknown>) => { handlers[name] = handler } })
    const ctx = { cwd: home, hasUI: true, ui: { notify: (text: string) => notes.push(text) } }
    await writeFile(verdicts, JSON.stringify({ decision: "deny", reason: "Mehen blocked this: reading .env", card: "Mehen blocked a tool call" }))
    expect(await handlers.tool_call!({ toolName: "read", input: { path: ".env" } }, ctx)).toEqual({ block: true, reason: "Mehen blocked this: reading .env" })
    expect(notes).toEqual(["Mehen blocked a tool call"])
    await writeFile(verdicts, JSON.stringify({ decision: "allow", reason: null, card: null }))
    expect(await handlers.tool_call!({ toolName: "bash", input: { command: "ls" } }, ctx)).toBeUndefined()
    expect(await handlers.tool_call!({ toolName: "web_search", input: {} }, ctx)).toBeUndefined()
    await writeFile(fake, "#!/bin/sh\nexit 3\n", { mode: 0o755 })
    expect(await handlers.tool_call!({ toolName: "read", input: { path: "a.ts" } }, ctx)).toMatchObject({ block: true })
    await rm(fake)
    expect(await handlers.tool_call!({ toolName: "read", input: { path: "a.ts" } }, ctx)).toBeUndefined()
    expect(notes.at(-1)).toContain("not installed")
  })
})

describe("Cursor's hooks.json", () => {
  const cmd = `${BIN} hook cursor`
  const permission = { command: cmd, timeout: 10, failClosed: true }
  const theirs = { command: "./hooks/audit.sh" }

  test("mehen's four hooks join the person's, fail closed where Cursor allows it, and a second install changes nothing", () => {
    const first = cursorHooks({ version: 1, hooks: { beforeShellExecution: [theirs], afterFileEdit: [theirs] } }, BIN, false)
    expect(first).toEqual({
      version: 1,
      hooks: {
        beforeShellExecution: [theirs, permission],
        afterFileEdit: [theirs],
        beforeReadFile: [permission],
        preToolUse: [{ ...permission, matcher: CURSOR_WRITE_MATCHER }],
        sessionStart: [{ command: cmd, timeout: 10 }],
      },
    })
    expect(cursorHooks(first, BIN, false)).toEqual(first)
    expect(cursorHooks({}, BIN, false)).toMatchObject({ version: 1 })
  })

  test("a moved mehen replaces its own entries where they were; removal leaves only the person's", () => {
    const installed = cursorHooks({ version: 1, hooks: { beforeShellExecution: [theirs] } }, BIN, false)
    const later = { ...installed, hooks: { ...(installed.hooks as Record<string, unknown[]>), beforeShellExecution: [theirs, permission, { command: "./hooks/after.sh" }] } }
    const moved = cursorHooks(later, "/opt/mehen", false) as { hooks: Record<string, { command: string }[]> }
    expect(moved.hooks.beforeShellExecution?.map((e) => e.command)).toEqual(["./hooks/audit.sh", "/opt/mehen hook cursor", "./hooks/after.sh"])
    expect(cursorHooks(installed, BIN, true)).toEqual({ version: 1, hooks: { beforeShellExecution: [theirs] } })
  })

  test("an entry the person changed to run something else is theirs, and stays, as do their other events, empty or not", () => {
    const edited = { version: 1, hooks: { beforeReadFile: [{ command: `${BIN} hook cursor | tee /tmp/log` }], stop: [] } }
    expect(cursorHooks(edited, BIN, true)).toEqual(edited)
    expect(cursorHooks(cursorHooks(edited, BIN, false), BIN, true)).toEqual(edited)
  })
})

describe("Codex's hooks.json", () => {
  const command = { type: "command", command: `${BIN} hook codex`, timeout: 10 }
  const theirs = { matcher: "Bash", hooks: [{ type: "command", command: "python3 ~/.codex/hooks/policy.py" }] }

  test("PreToolUse on Bash and apply_patch and a SessionStart note join the person's, once", () => {
    const first = codexHooks({ description: "mine", hooks: { PreToolUse: [theirs] } }, BIN, false)
    expect(first).toEqual({ description: "mine", hooks: { PreToolUse: [theirs, { matcher: CODEX_TOOLS, hooks: [command] }], SessionStart: [{ hooks: [command] }] } })
    expect(codexHooks(first, BIN, false)).toEqual(first)
    expect(codexHooks(first, BIN, true)).toEqual({ description: "mine", hooks: { PreToolUse: [theirs] } })
    expect(codexHooks(codexHooks({}, BIN, false), BIN, true)).toEqual({})
  })
})

describe("the Cursor and Codex files", () => {
  let home: string
  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "mehen-guard-cc-"))
  })
  afterEach(async () => {
    await rm(home, { recursive: true, force: true })
  })
  const cursor = (remove = false, dryRun = false) => installCursorGuard({ home, binary: BIN, remove, dryRun })
  const codex = (remove = false, dryRun = false, codexHome?: string) => installCodexGuard({ home, binary: BIN, remove, dryRun, codexHome })

  test("no ~/.cursor or ~/.codex folder: skipped, nothing written", async () => {
    expect(await cursor()).toMatchObject({ status: "skipped", absent: true, reason: expect.stringContaining("no ~/.cursor folder") })
    expect(await codex()).toMatchObject({ status: "skipped", absent: true, reason: expect.stringContaining("no ~/.codex folder") })
    expect(await cursor(true)).toMatchObject({ status: "skipped", absent: true })
    expect(await Bun.file(join(home, ".cursor")).exists()).toBe(false)
  })

  test("a file mehen made: added, unchanged the second time, and deleted on removal", async () => {
    await mkdir(join(home, ".cursor"))
    const file = join(home, ".cursor", "hooks.json")
    expect(await cursor(false, true)).toMatchObject({ status: "added" })
    expect(await Bun.file(file).exists()).toBe(false)
    expect(await cursor()).toMatchObject({ status: "added" })
    expect(JSON.parse(await readFile(file, "utf8"))).toMatchObject({ version: 1, hooks: { beforeReadFile: [{ command: `${BIN} hook cursor`, failClosed: true }] } })
    expect(await Bun.file(`${file}.mehen-backup`).exists()).toBe(false)
    expect(await cursor()).toMatchObject({ status: "unchanged" })
    expect(await cursor(true, true)).toMatchObject({ status: "removed" })
    expect(await Bun.file(file).exists()).toBe(true)
    expect(await cursor(true)).toMatchObject({ status: "removed" })
    expect(await Bun.file(file).exists()).toBe(false)
    expect(await cursor(true)).toMatchObject({ status: "unchanged" })
  })

  test("a hand-edited file: backed up once, the person's hooks and comments kept in the backup, and kept on removal", async () => {
    await mkdir(join(home, ".codex"))
    const file = join(home, ".codex", "hooks.json")
    const mine = '{\n  // my policy\n  "hooks": { "Stop": [{ "hooks": [{ "type": "command", "command": "./stop.sh" }] }] },\n}\n'
    await writeFile(file, mine)
    expect(await codex(false, true)).toMatchObject({ status: "added", next: CODEX_TRUST })
    expect(await readFile(file, "utf8")).toBe(mine)
    expect(await codex()).toMatchObject({ status: "added", next: CODEX_TRUST })
    expect(await readFile(`${file}.mehen-backup`, "utf8")).toBe(mine)
    expect(parseJson(await readFile(file, "utf8")).hooks).toMatchObject({ Stop: [{ hooks: [{ type: "command", command: "./stop.sh" }] }] })
    expect(await readFile(file, "utf8")).toContain("// my policy")
    expect(await codex()).toMatchObject({ status: "unchanged" })
    expect(await codex(false, false)).not.toHaveProperty("next")
    expect(await installCodexGuard({ home, binary: "/opt/mehen", remove: false, dryRun: false })).toMatchObject({ status: "updated", next: CODEX_TRUST })
    expect(await readFile(`${file}.mehen-backup`, "utf8")).toBe(mine)
    expect(await codex(true)).toMatchObject({ status: "removed" })
    expect(parseJson(await readFile(file, "utf8"))).toEqual({ hooks: { Stop: [{ hooks: [{ type: "command", command: "./stop.sh" }] }] } })
    expect(await readFile(file, "utf8")).toContain("// my policy")
  })

  test("a malformed file is skipped and left as it was", async () => {
    await mkdir(join(home, ".cursor"))
    const file = join(home, ".cursor", "hooks.json")
    await writeFile(file, "{ not json")
    expect(await cursor()).toMatchObject({ status: "skipped", reason: expect.stringContaining("Malformed") })
    expect(await cursor(true)).toMatchObject({ status: "skipped" })
    expect(await readFile(file, "utf8")).toBe("{ not json")
  })

  test("CODEX_HOME moves Codex's file, and hooks declared in its config.toml are pointed out", async () => {
    const codexHome = join(home, "codex-home")
    await mkdir(codexHome)
    await writeFile(join(codexHome, "config.toml"), 'model = "x"\n\n[[hooks.PreToolUse]]\nmatcher = "^Bash$"\n')
    expect(await codex(false, false, codexHome)).toMatchObject({ status: "added", file: join(codexHome, "hooks.json"), reason: expect.stringContaining("config.toml also declares hooks") })
    expect(JSON.parse(await readFile(join(codexHome, "hooks.json"), "utf8")).hooks.PreToolUse[0].matcher).toBe(CODEX_TOOLS)
  })

  test("mehen guard install and remove wire both, and --dry-run writes neither", async () => {
    await mkdir(join(home, ".cursor"))
    await mkdir(join(home, ".codex"))
    const env = { HOME: home, MEHEN_SELF_EXECUTABLE: BIN }
    const dry = await runJv(["guard", "install", "--dry-run", "--json"], env)
    expect(JSON.parse(dry.stdout)).toMatchObject({ dryRun: true, agents: [{ agent: "claude-code" }, { agent: "pi" }, { agent: "cursor", status: "added" }, { agent: "codex", status: "added" }] })
    expect(await Bun.file(join(home, ".cursor", "hooks.json")).exists()).toBe(false)
    const human = await runJv(["guard", "install"], env)
    expect(human.stdout).toContain("cursor           guard added")
    expect(human.stdout).toContain("Open /hooks in Codex")
    expect(JSON.parse(await readFile(join(home, ".codex", "hooks.json"), "utf8")).hooks.SessionStart[0].hooks[0].command).toBe(`${BIN} hook codex`)
    const again = await runJv(["guard", "install", "--json"], env)
    expect(JSON.parse(again.stdout).agents.slice(2).map((a: { status: string }) => a.status)).toEqual(["unchanged", "unchanged"])
    const removed = await runJv(["guard", "remove", "--json"], env)
    expect(JSON.parse(removed.stdout).agents.slice(2).map((a: { status: string }) => a.status)).toEqual(["removed", "removed"])
    expect(await Bun.file(join(home, ".codex", "hooks.json")).exists()).toBe(false)
  })
})

describe("review fixes: what counts as mehen's", () => {
  const foreign = (harness: string) => [
    `/bin/echo ${BIN} hook ${harness}`,
    `env ${BIN} hook ${harness}`,
    `sudo ${BIN} hook ${harness}`,
    `${BIN} hook ${harness} --verbose`,
    `${BIN} hook ${harness}; rm -rf ~`,
    `${BIN} hook ${harness} | tee /tmp/log`,
    `${BIN} hook ${harness} && true`,
    `sh -c '${BIN} hook ${harness}'`,
    `"${BIN}" hook ${harness}`,
    `/opt/not-mehen hook ${harness}`,
    `mehen hook ${harness}`,
    `${BIN}  hook ${harness}`,
    `'/Users/a b/bin/mehen hook ${harness}'`,
  ]

  test("only the complete generated invocation is mehen's, shell quoting included", () => {
    for (const harness of ["claude-code", "cursor", "codex"] as const) {
      expect(ownsCommand(`${BIN} hook ${harness}`, harness)).toBe(true)
      expect(ownsCommand(`'/Users/a b/bin/mehen' hook ${harness}`, harness)).toBe(true)
      expect(ownsCommand("'/x/it'\\''s/mehen' hook " + harness, harness)).toBe(true)
      for (const command of foreign(harness)) expect({ command, ours: ownsCommand(command, harness) }).toEqual({ command, ours: false })
    }
    expect(ownsCommand(`${BIN} hook cursor`, "codex")).toBe(false)
  })

  test("a foreign command that ends like mehen's is kept on remove and install, in all three files", () => {
    for (const command of foreign("cursor")) {
      const config = { version: 1, hooks: { beforeReadFile: [{ command }] } }
      expect(cursorHooks(config, BIN, true)).toEqual(config)
      expect((cursorHooks(config, BIN, false) as { hooks: { beforeReadFile: unknown[] } }).hooks.beforeReadFile).toEqual([{ command }, { command: `${BIN} hook cursor`, timeout: 10, failClosed: true }])
    }
    for (const command of foreign("codex")) {
      const config = { hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command }] }] } }
      expect(codexHooks(config, BIN, true)).toEqual(config)
    }
    for (const command of foreign("claude-code")) {
      const config = { hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command }] }] } }
      expect(claudeSettings(config, BIN, [VAULT], true).settings).toEqual(config)
    }
  })
})

describe("review fixes: the files", () => {
  let home: string
  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "mehen-guard-fix-"))
  })
  afterEach(async () => {
    await rm(home, { recursive: true, force: true })
  })
  const cursorFile = () => join(home, ".cursor", "hooks.json")
  const codexFile = () => join(home, ".codex", "hooks.json")

  test("a file edited while remove runs is not deleted: the live file is checked right before the unlink", async () => {
    await mkdir(join(home, ".cursor"))
    expect(await installCursorGuard({ home, binary: BIN, remove: false, dryRun: false })).toMatchObject({ status: "added" })
    const edited = '{ "version": 1, "hooks": { "stop": [{ "command": "./mine.sh" }] } }\n'
    const result = await installCursorGuard({ home, binary: BIN, remove: true, dryRun: false, beforeWrite: async () => { await writeFile(cursorFile(), edited) } })
    expect(result).toMatchObject({ status: "skipped", reason: expect.stringContaining("changed while") })
    expect(await readFile(cursorFile(), "utf8")).toBe(edited)
  })

  test("a file edited while install rewrites it is left as the person wrote it", async () => {
    await mkdir(join(home, ".codex"))
    await writeFile(codexFile(), "{}\n")
    const edited = '{ "hooks": {} }\n'
    const result = await installCodexGuard({ home, binary: BIN, remove: false, dryRun: false, beforeWrite: async () => { await writeFile(codexFile(), edited) } })
    expect(result).toMatchObject({ status: "skipped", reason: expect.stringContaining("changed while") })
    expect(await readFile(codexFile(), "utf8")).toBe(edited)
  })

  test("two guard installs at once are serialised: one adds, the other finds it unchanged", async () => {
    await mkdir(join(home, ".cursor"))
    await mkdir(join(home, ".codex"))
    const env = { HOME: home, MEHEN_SELF_EXECUTABLE: BIN }
    const [a, b] = await Promise.all([runJv(["guard", "install", "--json"], env), runJv(["guard", "install", "--json"], env)])
    const statuses = [a, b].map((r) => (JSON.parse(r.stdout) as { agents: { agent: string; status: string }[] }).agents.find((x) => x.agent === "cursor")?.status).sort()
    expect(statuses).toEqual(["added", "unchanged"])
    expect(JSON.parse(await readFile(cursorFile(), "utf8")).hooks.beforeReadFile).toHaveLength(1)
  })

  test("hooks that are not an object, an event that is not a list, or a Cursor version that is not a positive integer: skipped, bytes untouched", async () => {
    await mkdir(join(home, ".cursor"))
    await mkdir(join(home, ".codex"))
    await mkdir(join(home, ".claude"))
    const cases: [string, string, string, () => Promise<unknown>, () => Promise<unknown>][] = [
      [cursorFile(), '{ "version": 1, "hooks": [] }', "hooks must be an object", () => installCursorGuard({ home, binary: BIN, remove: false, dryRun: false }), () => installCursorGuard({ home, binary: BIN, remove: true, dryRun: false })],
      [cursorFile(), '{ "version": 1, "hooks": { "beforeReadFile": { "command": "x" } } }', "hooks.beforeReadFile must be a list", () => installCursorGuard({ home, binary: BIN, remove: false, dryRun: false }), () => installCursorGuard({ home, binary: BIN, remove: true, dryRun: false })],
      [cursorFile(), '{ "version": "1", "hooks": {} }', "version must be a positive integer", () => installCursorGuard({ home, binary: BIN, remove: false, dryRun: false }), () => installCursorGuard({ home, binary: BIN, remove: true, dryRun: false })],
      [cursorFile(), '{ "version": 0 }', "version must be a positive integer", () => installCursorGuard({ home, binary: BIN, remove: false, dryRun: false }), () => installCursorGuard({ home, binary: BIN, remove: true, dryRun: false })],
      [cursorFile(), '{ "version": 1.5 }', "version must be a positive integer", () => installCursorGuard({ home, binary: BIN, remove: false, dryRun: false }), () => installCursorGuard({ home, binary: BIN, remove: true, dryRun: false })],
      [codexFile(), '{ "hooks": { "PreToolUse": "Bash" } }', "hooks.PreToolUse must be a list", () => installCodexGuard({ home, binary: BIN, remove: false, dryRun: false }), () => installCodexGuard({ home, binary: BIN, remove: true, dryRun: false })],
      [codexFile(), '{ "hooks": "none" }', "hooks must be an object", () => installCodexGuard({ home, binary: BIN, remove: false, dryRun: false }), () => installCodexGuard({ home, binary: BIN, remove: true, dryRun: false })],
      [join(home, ".claude", "settings.json"), '{ "hooks": { "SessionStart": {} } }', "hooks.SessionStart must be a list", () => installClaudeGuard({ home, binary: BIN, vaultDirs: [VAULT], remove: false, dryRun: false }), () => installClaudeGuard({ home, binary: BIN, vaultDirs: [VAULT], remove: true, dryRun: false })],
    ]
    for (const [file, text, reason, install, remove] of cases) {
      await writeFile(file, text)
      expect({ text, result: await install() }).toMatchObject({ text, result: { status: "skipped", reason: expect.stringContaining(reason) } })
      expect({ text, result: await remove() }).toMatchObject({ text, result: { status: "skipped", reason: expect.stringContaining(reason) } })
      expect(await readFile(file, "utf8")).toBe(text)
      await rm(file)
    }
  })

  test("a relative CODEX_HOME is resolved against the working directory, as Codex does, not HOME", async () => {
    const work = join(home, "work")
    await mkdir(join(work, "codex-rel"), { recursive: true })
    expect(await installCodexGuard({ home, binary: BIN, remove: false, dryRun: false, codexHome: "codex-rel", cwd: work })).toMatchObject({ status: "added", file: join(work, "codex-rel", "hooks.json") })
    expect(await Bun.file(join(home, "codex-rel", "hooks.json")).exists()).toBe(false)
    const elsewhere = join(home, "elsewhere")
    await mkdir(join(elsewhere, "codex-rel"), { recursive: true })
    const result = await runJv(["guard", "install", "--json"], { HOME: home, MEHEN_SELF_EXECUTABLE: BIN, CODEX_HOME: "codex-rel" }, undefined, elsewhere)
    expect(JSON.parse(result.stdout).agents.find((a: { agent: string }) => a.agent === "codex")).toMatchObject({ status: "added", file: join(elsewhere, "codex-rel", "hooks.json") })
  })

  test("a file mehen made, reinstalled after mehen moved, is deleted on removal: the record of making it, not a backup, is the evidence", async () => {
    await mkdir(join(home, ".cursor"))
    expect(await installCursorGuard({ home, binary: BIN, remove: false, dryRun: false })).toMatchObject({ status: "added" })
    expect(await installCursorGuard({ home, binary: "/opt/mehen", remove: false, dryRun: false })).toMatchObject({ status: "updated" })
    expect(await installCursorGuard({ home, binary: BIN, remove: true, dryRun: false })).toMatchObject({ status: "removed" })
    expect(await Bun.file(cursorFile()).exists()).toBe(false)
    expect((await readdir(join(home, ".cursor"))).sort()).toEqual([])
  })

  test("a person's own empty file, with no mehen hook in it, is never removed or rewritten", async () => {
    await mkdir(join(home, ".cursor"))
    await mkdir(join(home, ".codex"))
    const cursorText = '{ "version": 1, "hooks": {} }\n'
    const codexText = '{ "hooks": {} }'
    await writeFile(cursorFile(), cursorText)
    await writeFile(codexFile(), codexText)
    expect(await installCursorGuard({ home, binary: BIN, remove: true, dryRun: false })).toMatchObject({ status: "unchanged" })
    expect(await installCodexGuard({ home, binary: BIN, remove: true, dryRun: false })).toMatchObject({ status: "unchanged" })
    expect(await readFile(cursorFile(), "utf8")).toBe(cursorText)
    expect(await readFile(codexFile(), "utf8")).toBe(codexText)
  })

  test("comments survive: the person's, added after install, through a reinstall and a remove", async () => {
    await mkdir(join(home, ".codex"))
    expect(await installCodexGuard({ home, binary: BIN, remove: false, dryRun: false })).toMatchObject({ status: "added" })
    const installed = await readFile(codexFile(), "utf8")
    const commented = installed.replace('"hooks": {', '// my notes on these hooks\n  "hooks": {\n    /* my stop hook */ "Stop": [{ "hooks": [{ "type": "command", "command": "./stop.sh" }] }],')
    await writeFile(codexFile(), commented)
    expect(await installCodexGuard({ home, binary: "/opt/mehen", remove: false, dryRun: false })).toMatchObject({ status: "updated" })
    const moved = await readFile(codexFile(), "utf8")
    expect(moved).toContain("// my notes on these hooks")
    expect(moved).toContain("/* my stop hook */")
    expect(moved).toContain("/opt/mehen hook codex")
    expect(await installCodexGuard({ home, binary: "/opt/mehen", remove: false, dryRun: false })).toMatchObject({ status: "unchanged" })
    expect(await installCodexGuard({ home, binary: BIN, remove: true, dryRun: false })).toMatchObject({ status: "removed" })
    const removed = await readFile(codexFile(), "utf8")
    expect(removed).toContain("// my notes on these hooks")
    expect(removed).toContain("/* my stop hook */")
    expect(removed).not.toContain("hook codex")
    expect(JSON.parse(removed.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, ""))).toEqual({ hooks: { Stop: [{ hooks: [{ type: "command", command: "./stop.sh" }] }] } })
  })
})

describe("second review: the files", () => {
  let home: string
  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "mehen-guard-r2-"))
  })
  afterEach(async () => {
    await rm(home, { recursive: true, force: true })
  })
  const cursorFile = () => join(home, ".cursor", "hooks.json")

  test("a comment right after a number, a boolean or a string is a comment, in objects and lists", async () => {
    await mkdir(join(home, ".cursor"))
    const tight = '{"version":1/* x */}'
    await writeFile(cursorFile(), tight)
    expect(await installCursorGuard({ home, binary: BIN, remove: false, dryRun: false })).toMatchObject({ status: "added" })
    const installed = await readFile(cursorFile(), "utf8")
    expect(installed).toContain("/* x */")
    expect(parseJson(installed)).toMatchObject({ version: 1, hooks: { beforeReadFile: [{ command: `${BIN} hook cursor` }] } })
    expect(await installCursorGuard({ home, binary: BIN, remove: true, dryRun: false })).toMatchObject({ status: "removed" })
    expect(parseJson(await readFile(cursorFile(), "utf8"))).toEqual({ version: 1 })
    const mixed = '{"version":1,"x":true// t\n,"y":[1/*a*/,false//b\n,"s"/*c*/,null],"hooks":{"stop":[{"command":"./s.sh"}/*d*/]}}\n'
    await writeFile(cursorFile(), mixed)
    expect(await installCursorGuard({ home, binary: BIN, remove: false, dryRun: false })).toMatchObject({ status: "added" })
    expect(parseJson(await readFile(cursorFile(), "utf8"))).toMatchObject({ version: 1, x: true, y: [1, false, "s", null], hooks: { stop: [{ command: "./s.sh" }] } })
    expect(await installCursorGuard({ home, binary: BIN, remove: true, dryRun: false })).toMatchObject({ status: "removed" })
    expect(await readFile(cursorFile(), "utf8")).toBe(mixed)
  })

  test("a moved mehen changes only the fields mehen writes: a comment inside its entry stays", async () => {
    await mkdir(join(home, ".cursor"))
    expect(await installCursorGuard({ home, binary: BIN, remove: false, dryRun: false })).toMatchObject({ status: "added" })
    const text = await readFile(cursorFile(), "utf8")
    const commented = text.replace(`"command": "${BIN} hook cursor",`, `/* mine: keep this */ "command": "${BIN} hook cursor",`)
    expect(commented).not.toBe(text)
    await writeFile(cursorFile(), commented)
    expect(await installCursorGuard({ home, binary: "/opt/mehen", remove: false, dryRun: false })).toMatchObject({ status: "updated" })
    const moved = await readFile(cursorFile(), "utf8")
    expect(moved).toContain("/* mine: keep this */")
    expect(moved).toContain('"/opt/mehen hook cursor"')
    expect(moved).not.toContain(`${BIN} hook cursor`)
    expect(await installCursorGuard({ home, binary: "/opt/mehen", remove: false, dryRun: false })).toMatchObject({ status: "unchanged" })
  })

  test("--dry-run writes nothing: no Mehen home, no locks folder", async () => {
    await mkdir(join(home, ".cursor"))
    await mkdir(join(home, ".codex"))
    const result = await runJv(["guard", "install", "--dry-run", "--json"], { HOME: home, MEHEN_SELF_EXECUTABLE: BIN })
    expect(result.code).toBe(0)
    expect(JSON.parse(result.stdout)).toMatchObject({ dryRun: true, agents: expect.arrayContaining([expect.objectContaining({ agent: "cursor", status: "added" })]) })
    // The bun runtime keeps its own cache in HOME; nothing else may appear.
    const mine = async () => (await readdir(home)).filter((name) => name !== ".bun").sort()
    expect(await mine()).toEqual([".codex", ".cursor"])
    expect(await readdir(join(home, ".cursor"))).toEqual([])
    expect(await readdir(join(home, ".codex"))).toEqual([])
    const removal = await runJv(["guard", "remove", "--dry-run", "--json"], { HOME: home, MEHEN_SELF_EXECUTABLE: BIN })
    expect(removal.code).toBe(0)
    expect(await mine()).toEqual([".codex", ".cursor"])
  })
})
