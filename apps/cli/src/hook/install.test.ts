import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runJv } from "../testing/run-mehen.ts"
import { CLAUDE_TOOLS, CODEX_TOOLS, CODEX_TRUST, CURSOR_WRITE_MATCHER, claudeHookCommand, claudeSettings, codexHooks, cursorHooks, installClaudeGuard, installCodexGuard, installCursorGuard, installPiGuard } from "./install.ts"
import { piExtension } from "./pi.ts"

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
    expect(JSON.parse(await readFile(file, "utf8")).hooks.Stop).toEqual([{ hooks: [{ type: "command", command: "./stop.sh" }] }])
    expect(await codex()).toMatchObject({ status: "unchanged" })
    expect(await codex(false, false)).not.toHaveProperty("next")
    expect(await installCodexGuard({ home, binary: "/opt/mehen", remove: false, dryRun: false })).toMatchObject({ status: "updated", next: CODEX_TRUST })
    expect(await readFile(`${file}.mehen-backup`, "utf8")).toBe(mine)
    expect(await codex(true)).toMatchObject({ status: "removed" })
    expect(JSON.parse(await readFile(file, "utf8"))).toEqual({ hooks: { Stop: [{ hooks: [{ type: "command", command: "./stop.sh" }] }] } })
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
