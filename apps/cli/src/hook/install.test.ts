import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runJv } from "../testing/run-mehen.ts"
import { CLAUDE_TOOLS, claudeHookCommand, claudeSettings, installClaudeGuard, installPiGuard } from "./install.ts"
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
    expect(JSON.parse(result.stdout)).toMatchObject({ agents: [{ agent: "claude-code", status: "added" }, { agent: "pi", status: "skipped" }] })
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
