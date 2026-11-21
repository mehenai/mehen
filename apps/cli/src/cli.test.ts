import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { EXIT } from "@mehen/protocol/api"
import { parseArgs } from "./args.ts"
import { COMMANDS } from "./cli.ts"
import { requestCommand } from "./commands/intake.ts"
import type { CliError } from "./errors.ts"
import { MockVault } from "./testing/mock-vault.ts"
import { VERSION } from "./version.ts"
import { type JvResult, runJv, tempDir } from "./testing/run-mehen.ts"
import { RUN_USAGE } from "./run/index.ts"

let vault: MockVault
let dir: { path: string; remove(): Promise<void> }
let env: Record<string, string>

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url }
  vault.overrides.clear()
  vault.sequences.clear()
  vault.enrolOutcome = { pendingPolls: 2, result: "active" }
})
afterEach(async () => dir.remove())

function json(result: JvResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>
}

async function enrolled(): Promise<string> {
  return vault.enrolSoftware(dir.path)
}

describe("local commands", () => {
  test("guide prints the embedded guide; version prints the version", async () => {
    const guide = await runJv(["guide"], env)
    expect(guide.code).toBe(EXIT.ok)
    expect(guide.stdout).toContain("References, not values")
    expect(guide.stdout).toContain("Exit codes")
    expect(guide.stdout).toContain("`mehen push <item>[#<field>] --to <destination>")
    const version = await runJv(["version", "--json"], env)
    expect(json(version).version).toMatch(/^\d+\.\d+\.\d+$/)
    // The version is apps/cli/package.json's; a run from source has no build commit, no build kind and no embedded helper.
    expect(json(version)).toEqual({ version: (await Bun.file(new URL("../package.json", import.meta.url)).json()).version, commit: null, build: null, helper: "none" })
    // The release this source is: bump here and in package.json together (apps/cli/CHANGELOG.md).
    expect(json(version).version).toBe(VERSION)
  })

  test("usage errors exit 2", async () => {
    expect((await runJv([], env)).code).toBe(EXIT.usage)
    expect((await runJv(["frobnicate"], env)).code).toBe(EXIT.usage)
    expect((await runJv(["ls", "--bogus"], env)).code).toBe(EXIT.usage)
    expect((await runJv(["show"], env)).code).toBe(EXIT.usage)
    const bad = await runJv(["show", "--json"], env)
    expect(json(bad)).toMatchObject({ error: "usage" })
  })

  test("mcp --help prints help and exits 0; other options are still a usage error", async () => {
    const help = await runJv(["mcp", "--help"], env)
    expect(help.code).toBe(EXIT.ok)
    expect(help.stdout).toContain("usage: mehen mcp")
    expect(help.stdout).toContain("serve the vault tools over MCP on stdio")
    // Every registered tool is named, and the one the server refuses says so.
    expect(help.stdout).toContain("vault_policy proposes standing rules and task grants, which the person approves with their passkey; vault_mandate proposes a mandate, which the person signs with their passkey, and lists, follows and pauses it.")
    expect(help.stdout).toContain("Enrol this machine first with mehen enrol --workspace <slug>")
    expect(help.stderr).toBe("")
    const bogus = await runJv(["mcp", "--bogus"], env)
    expect(bogus.code).toBe(EXIT.usage)
    expect(bogus.stderr).toContain("mehen mcp --help")
  })

  test("--no-qr is accepted by every command and changes nothing off a TTY", async () => {
    expect((await runJv(["templates", "--no-qr"], env)).code).toBe(EXIT.ok)
    expect((await runJv(["version", "--no-qr"], env)).stdout).toBe((await runJv(["version"], env)).stdout)
  })

  test("run, env and init --help print usage and exit 0, enrolled or not", async () => {
    for (const [argv, usage] of [
      [["run", "--help"], "usage: mehen run [--env <env>]"],
      [["run", "--env", "prod", "-h"], "usage: mehen run [--env <env>]"],
      [["env", "--help"], "usage: mehen env ls [--env <env>] [--json]"],
      [["env", "check", "--help"], "usage: mehen env ls"],
      [["init", "--help"], "usage: mehen init [--slug <slug>]"],
    ] as const) {
      const result = await runJv([...argv], env, undefined, dir.path)
      expect(result.code).toBe(EXIT.ok)
      expect(result.stdout).toContain(usage)
    }
  })

  test("run, env and init are wired to src/run and get the session", async () => {
    expect((await runJv(["env", "ls"], env, undefined, dir.path)).code).toBe(EXIT.identity)
    await enrolled()
    const result = await runJv(["env", "ls"], env, undefined, dir.path)
    expect(result.code).toBe(EXIT.error)
    expect(result.stderr).toContain("no mehen.toml")
    expect(result.stderr).toContain("mehen init")
  })
})

describe("help", () => {
  test("every command's examples parse against its own flags, with its positionals in range", () => {
    for (const [name, command] of Object.entries(COMMANDS)) {
      expect(command.examples.length).toBeGreaterThan(0)
      for (const example of command.examples) {
        expect(example[0]).toBe(name)
        expect(() => parseArgs(example.slice(1), command.spec)).not.toThrow()
      }
    }
  })

  test("mehen <command> --help prints usage, summary, examples a shell reads back, and notes", async () => {
    const help = await runJv(["fetch", "--help"], env)
    expect(help.code).toBe(EXIT.ok)
    expect(help.stdout).toStartWith(`usage: ${COMMANDS.fetch?.spec.usage}\n  ${COMMANDS.fetch?.summary}\n\nexamples:\n`)
    expect(help.stdout).toContain("  mehen fetch openai-personal POST https://api.openai.com/v1/responses -H 'Content-Type: application/json' -d @body.json\n")
    expect(help.stdout).toContain("Any upstream status exits 0 unless --fail.")
    expect((await runJv(["request", "--help"], env)).stdout).toContain("--format 'token {key}' --reason 'scan this repo'\\''s dependencies'")
  })

  test("mehen --json and mehen --help --json give the command list as JSON, from the same table as the text help", async () => {
    const bare = await runJv(["--json"], env)
    expect(bare.code).toBe(EXIT.usage)
    expect(bare.stderr).toBe("")
    const out = json(bare) as { version: string; commands: { name: string; summary: string }[]; next: unknown }
    expect(out.version).toBe(VERSION)
    expect(out.commands.map((c) => c.name)).toEqual([...Object.keys(COMMANDS), "run", "env", "init", "workspace", "mcp"])
    expect(out.commands.find((c) => c.name === "fetch")?.summary).toBe(COMMANDS.fetch?.summary as string)
    expect(out.next).toEqual({ say: "Run mehen <command> --help for a command's flags." })
    const text = (await runJv(["--help"], env)).stdout
    for (const { name, summary } of out.commands) expect(text).toMatch(new RegExp(`^  ${name} +${summary.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"))
    for (const argv of [["--help", "--json"], ["help", "--json"]]) {
      const help = await runJv(argv, env)
      expect(help.code).toBe(EXIT.ok)
      expect(json(help)).toEqual(out)
    }
    expect((await runJv([], env)).stderr).toStartWith(`mehen ${VERSION}, the Mehen command line.`)
  })

  test("mehen help <command> is mehen <command> --help; mehen help alone is the command list", async () => {
    expect((await runJv(["help", "check"], env)).stdout).toBe((await runJv(["check", "--help"], env)).stdout)
    expect((await runJv(["help", "mcp"], env)).stdout).toContain("vault_doctor")
    expect((await runJv(["help", "run"], env)).stdout).toContain("usage: mehen run")
    const list = await runJv(["help"], env)
    expect(list.code).toBe(EXIT.ok)
    expect(list.stdout).toContain("mehen help <command>")
    expect((await runJv(["help", "frobnicate"], env)).code).toBe(EXIT.usage)
  })

  test("an unknown --kind names every kind and points at mehen ls --help, before anything is sent", async () => {
    await enrolled()
    const before = vault.seen.length
    const result = await runJv(["ls", "--kind", "apikey", "--json"], env)
    expect(result.code).toBe(EXIT.usage)
    expect(json(result)).toMatchObject({ error: "usage", next: { command: "mehen ls --help" } })
    expect(String(json(result).message)).toContain("The kinds are api-key, bearer-token,")
    expect(vault.seen.length).toBe(before)
  })

  test("a flag missing its value, or a switch given one, points at the command's own help", () => {
    const refusal = (argv: string[]) => {
      try {
        parseArgs(argv, requestCommand.spec)
      } catch (error) {
        return error as CliError
      }
      throw new Error("parseArgs accepted the line")
    }
    for (const argv of [["api-key", "--name", "x", "--reason"], ["api-key", "--wait=yes"]]) {
      const refused = refusal(argv)
      expect(refused.code).toBe("usage")
      expect(refused.next).toEqual({ command: "mehen request --help", say: "Check the usage with `mehen request --help`." })
    }
  })

  test("a flag that takes a value never swallows the next option; --flag=value passes a value starting with --", async () => {
    const refused = await runJv(["request", "api-key", "--name", "--reason", "x", "--json"], env)
    expect(refused.code).toBe(EXIT.usage)
    expect(json(refused)).toMatchObject({ error: "usage", next: { command: "mehen request --help" } })
    expect(String(json(refused).message)).toStartWith("--name needs a value, but the next argument is the option --reason.")
    expect(() => parseArgs(["api-key", "--name", "--"], requestCommand.spec)).toThrow("--name needs a value, but the next argument is the option --.")
    expect(parseArgs(["api-key", "--name=--odd", "--reason", "-x"], requestCommand.spec).string("name")).toBe("--odd")
    expect(parseArgs(["api-key", "--name=--odd", "--reason", "-x"], requestCommand.spec).string("reason")).toBe("-x")
  })

  test("--json and --no-qr may come before the command", async () => {
    const leading = await runJv(["--json", "version"], env)
    expect(leading.code).toBe(EXIT.ok)
    expect(json(leading)).toEqual(json(await runJv(["version", "--json"], env)))
    const error = await runJv(["--json", "--no-qr", "ls"], env)
    expect(error.code).toBe(EXIT.identity)
    expect(json(error)).toMatchObject({ error: "unauthenticated" })
  })
})


test("policy is registered with local help and refuses an agent approval before enrolment", async () => {
  const help = await runJv(["policy", "--help"], env)
  expect(help.code).toBe(EXIT.ok)
  expect(help.stdout).toContain("mehen policy show <item>")
  expect(help.stdout).toContain("No access changes before a human's passkey decision. The person approves each proposal on the vault page.")
  expect(help.stdout).toContain("A standing rule allows one kind of request from now on, for 1, 7 or 30 days, without asking each time.")
  expect(help.stdout).toContain("Rules never cover requests that send messages, move money, share or publish, change credentials or access, set up something that keeps running, or delete or remove something, nor protected environments or credentials holding a live key.")
  const refused = await runJv(["policy", "approve", "pol_example", "--json"], env)
  expect(refused.code).toBe(EXIT.usage)
  expect(json(refused)).toMatchObject({ error: "usage", message: expect.stringContaining("Agents cannot approve"), next: { command: "mehen policy --help" } })
})

test("run, env and init refuse a bad line as a usage error with next before opening a session, enrolled or not", async () => {
  const cases: [string[], string, string][] = [
    [["run"], `Name the command to run. Usage: ${RUN_USAGE}`, "mehen run --help"],
    [["run", "--bogus", "x"], `Unknown option --bogus for \`${RUN_USAGE}\`.`, "mehen run --help"],
    [["env"], "mehen env needs a subcommand: ls, check or set.", "mehen env --help"],
    [["env", "bogus"], "Unknown subcommand bogus; use ls, check or set.", "mehen env --help"],
    [["env", "set", "DATABASE_URL", "--env", "dev", "--item", "db", "--plain", "x"], "Pass --item or --plain, not both.", "mehen env --help"],
    [["init", "stray"], "Unexpected argument stray. Usage: mehen init [--slug <slug>] [--env <name>]... [--local] [--json]", "mehen init --help"],
    [["init", "--slug", "Bad Slug"], "Bad Slug is not a valid slug; pass --slug <lower-case-name>.", "mehen init --help"],
  ]
  for (const state of ["unenrolled", "enrolled"]) {
    if (state === "enrolled") await enrolled()
    const before = vault.seen.length
    for (const [argv, message, help] of cases) {
      const human = await runJv(argv, env)
      expect(human.code).toBe(EXIT.usage)
      expect(human.stdout).toBe("")
      expect(human.stderr).toBe(`mehen: ${message}\nnext: Check the usage with \`${help}\`.\n  run:  ${help}\n`)
    }
    const machine = await runJv(["env", "ls", "stray", "--json"], env)
    expect(machine.code).toBe(EXIT.usage)
    expect(json(machine)).toMatchObject({ error: "usage", message: "Unexpected argument stray.", next: { command: "mehen env --help", say: "Check the usage with `mehen env --help`." } })
    expect(vault.seen.length).toBe(before)
  }
  const noSource = await runJv(["env", "set", "DATABASE_URL", "--env", "dev"], env)
  expect(noSource.code).toBe(EXIT.usage)
  expect(noSource.stderr).toContain("mehen: DATABASE_URL needs a source: --item <slug> for a credential in the vault, or --plain <value> for non-secret config.")
  expect(noSource.stderr).toContain("run:  mehen env set DATABASE_URL --env dev --item <slug>")
}, 30_000)

test("source runs refuse setup and in-place update instead of registering or replacing Bun", async () => {
  for (const name of ["setup", "update"]) {
    const result = await runJv([name, "--json"], { ...env, HOME: dir.path })
    expect(result.code).toBe(EXIT.usage)
    expect(json(result)).toMatchObject({ error: "usage" })
    expect(String(json(result).message)).toContain("standalone mehen binary")
  }
})

describe("the config root", () => {
  test("MEHEN_CONFIG_DIR naming a slot refuses config_dir_retired before anything is read, with the root's MEHEN_HOME in next", async () => {
    await enrolled()
    const slot = vault.slotDir(dir.path)
    const before = vault.seen.length
    const result = await runJv(["status", "--json"], { ...env, MEHEN_CONFIG_DIR: slot })
    expect(result.code).toBe(EXIT.usage)
    expect(json(result)).toMatchObject({ error: "config_dir_retired", next: { say: expect.stringContaining(`MEHEN_HOME=${dir.path}`) } })
    const disagree = await runJv(["status", "--json"], { ...env, MEHEN_HOME: `${dir.path}-other` })
    expect(json(disagree)).toMatchObject({ error: "config_dir_retired" })
    expect(vault.seen.length).toBe(before)
    // The commands that read no slot never resolve the root at all.
    for (const args of [["version", "--json"], ["guide"], ["status", "--help"]]) expect((await runJv(args, { ...env, MEHEN_CONFIG_DIR: slot })).code).toBe(EXIT.ok)
  })

  test("doctor never migrates: a legacy root is reported, not moved; the next command migrates it", async () => {
    const { writeConfig } = await import("./config.ts")
    await writeConfig(dir.path, { vault: vault.url, tenant: "tn_legacy00000001", device: "dev_legacy0000001", backend: "software" })
    const { readdirSync } = await import("node:fs")
    const doctor = await runJv(["doctor", "--json"], env)
    expect(json(doctor)).toMatchObject({ migration: null, workspaces: [], origins: [] })
    expect((json(doctor).machine as { check: string; status: string }[]).find((c) => c.check === "migration")).toMatchObject({ status: "warn" })
    // doctor wrote nothing at all.
    expect(readdirSync(dir.path)).toEqual(["config.json"])
    // status only observes too: it refuses and names the command that migrates.
    const status = await runJv(["status", "--json"], env)
    expect(status.code).toBe(EXIT.error)
    expect(json(status)).toMatchObject({ error: "failed", next: { command: "mehen workspace list" } })
    expect(readdirSync(dir.path)).toEqual(["config.json"])
    const list = await runJv(["workspace", "list", "--json"], env)
    expect(list.stderr).toContain("\"migrated\"")
    expect(readdirSync(dir.path).sort()).toEqual(["locks", "mehen.json", "workspaces"])
  })
})

// A root below a component that is not a directory, or cannot be
// examined, is the named refusal at command and MCP startup, never internal.
describe("an unusable root ancestor", () => {
  test("ENOTDIR and EACCES below the root are key_insecure naming the path, for a command and for mehen mcp", async () => {
    const { chmodSync, mkdirSync, writeFileSync } = await import("node:fs")
    const { join } = await import("node:path")
    const blocker = join(dir.path, "not-a-directory")
    writeFileSync(blocker, "x", { mode: 0o600 })
    const locked = join(dir.path, "locked")
    mkdirSync(locked, { mode: 0o700 })
    chmodSync(locked, 0o000)
    try {
      for (const [path, unsafe] of [[join(blocker, "child"), blocker], [join(locked, "child"), join(locked, "child")]] as const) {
        const status = await runJv(["status", "--json"], { MEHEN_HOME: path, MEHEN_VAULT_URL: vault.url })
        expect(status.code).toBe(EXIT.identity)
        const body = JSON.parse(status.stdout) as { error: string; message: string }
        expect(body.error).toBe("key_insecure")
        expect(body.message).toContain(unsafe)
        const mcp = await runJv(["mcp"], { MEHEN_HOME: path, MEHEN_VAULT_URL: vault.url }, '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
        expect(mcp.code).toBe(EXIT.identity)
        expect(mcp.stdout).toBe("")
        expect(mcp.stderr).toContain(unsafe)
        expect(mcp.stderr).not.toContain("Unexpected failure")
        const doctor = JSON.parse((await runJv(["doctor", "--json"], { MEHEN_HOME: path, MEHEN_VAULT_URL: vault.url })).stdout) as { machine: { check: string; error?: string }[] }
        expect(doctor.machine.find((c) => c.check === "migration")).toMatchObject({ check: "migration", error: "key_insecure" })
      }
    } finally {
      chmodSync(locked, 0o700)
    }
  })
})

// The heal. A source run stands in for an
// installed release through MEHEN_SELF_EXECUTABLE (a script that runs this
// CLI); the signed release it heals to is a script that records how it was
// run. Every path is under a private temporary directory.
describe("healing an outdated CLI", () => {
  const { base64UrlEncode } = require("@mehen/protocol/bytes") as typeof import("@mehen/protocol/bytes")
  const { manifestSigningBytes } = require("@mehen/protocol/release-manifest") as typeof import("@mehen/protocol/release-manifest")
  const { createHash } = require("node:crypto") as typeof import("node:crypto")
  const { join } = require("node:path") as typeof import("node:path")
  const { realpathSync } = require("node:fs") as typeof import("node:fs")
  const { mkdtemp, readFile, rm, writeFile } = require("node:fs/promises") as typeof import("node:fs/promises")
  const { tmpdir } = require("node:os") as typeof import("node:os")
  const { MAIN } = require("./testing/run-mehen.ts") as typeof import("./testing/run-mehen.ts")
  const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex")
  let bin: string
  let releases: ReturnType<typeof Bun.serve>
  let key: { id: string; alg: "ES256"; jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }; presence: "none"; created: string }
  let signer: CryptoKey

  beforeEach(async () => {
    bin = realpathSync(await mkdtemp(join(tmpdir(), "mehen-heal-")))
    const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey)
    key = { id: "rk-test-heal", alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y! }, presence: "none", created: "2026-10-28T12:00:00.000Z" }
    signer = pair.privateKey
    const info = JSON.stringify({ version: "9.0.0", commit: "abc1234", build: "release", helper: process.platform === "darwin" ? "embedded" : "none" })
    const healed = new TextEncoder().encode(`#!/bin/sh\nif [ "$1 $2" = "version --json" ]; then printf '%s\\n' '${info}'; exit 0; fi\nif [ "$1 $2" = "setup --json" ]; then printf '{"skills":[]}\\n'; exit 0; fi\nprintf '%s|%s\\n' "$*" "$MEHEN_UPDATE_RETRIED" >> '${bin}/ran'\nprintf '{"healed":true}\\n'\n`)
    const gz = Bun.gzipSync(healed)
    const files = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"].map((t) => ({ name: `mehen-${t}`, os: t.split("-")[0]!, arch: t.split("-")[1]!, url: `https://mehen.dev/dl/v9.0.0/mehen-${t}.gz`, sha256: sha(healed), size: healed.length, gzSha256: sha(gz), gzSize: gz.length }))
    const manifest = { version: "9.0.0", commit: "abc1234", builtAt: "2026-10-28T12:00:00Z", files }
    const signature = base64UrlEncode(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signer, manifestSigningBytes(manifest)))
    releases = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: (req) => (new URL(req.url).pathname.endsWith(".json") ? Response.json({ ...manifest, signatures: [{ keyId: key.id, alg: "ES256", signature }] }) : new Response(gz)) })
    await writeFile(join(bin, "mehen"), `#!/bin/sh\nexec '${process.execPath}' '${MAIN}' "$@"\n`, { mode: 0o755 })
  })
  afterEach(async () => {
    releases.stop(true)
    vault.cliAdvice = null
    vault.cliMinimum = null
    vault.outdatedFrom = null
    await rm(bin, { recursive: true, force: true })
  })
  const installed = () => ({ ...env, MEHEN_SELF_EXECUTABLE: join(bin, "mehen"), MEHEN_DL_BASE: `http://127.0.0.1:${releases.port}/dl`, MEHEN_RELEASE_KEYS: JSON.stringify([key]), CI: "" })
  const ran = () => readFile(join(bin, "ran"), "utf8").catch(() => null)

  test("pre-dispatch: a recorded minimum above this version heals and re-executes the same argv as the new binary, having sent nothing", async () => {
    const { freshInstallState, installation, readInstallState, writeInstallState } = await import("./install-state.ts")
    const state = freshInstallState()
    state.vault[vault.url] = { minimum: "9.0.0", recommended: null, seenAt: "2026-10-28T12:00:00.000Z" }
    await writeInstallState(installation(join(bin, "mehen")), state)
    await enrolled()
    const before = vault.userAgents.length
    const result = await runJv(["status", "--json"], installed())
    expect(result.stdout.trim()).toBe('{"healed":true}')
    expect(await ran()).toBe("status --json|1\n")
    expect(vault.userAgents.length).toBe(before)
    expect((await readInstallState(installation(join(bin, "mehen"))))?.installed).toMatchObject({ version: "9.0.0", by: "heal", keyId: key.id })
  })

  test("pre-dispatch: backup export and status heal first; backup restore, which never talks to the vault, runs as it is", async () => {
    const { freshInstallState, installation, writeInstallState } = await import("./install-state.ts")
    const state = freshInstallState()
    state.vault[vault.url] = { minimum: "9.0.0", recommended: null, seenAt: "2026-10-28T12:00:00.000Z" }
    await writeInstallState(installation(join(bin, "mehen")), state)
    await enrolled()
    const result = await runJv(["backup", "status", "--json"], installed())
    expect(result.stdout.trim()).toBe('{"healed":true}')
    expect(await ran()).toBe("backup status --json|1\n")
    const offline = await runJv(["backup", "restore", "missing.age", "--identity", "-", "--verify-only"], installed(), "")
    expect(offline.stdout).not.toContain("healed")
    expect(await ran()).toBe("backup status --json|1\n")
  })

  test("pre-dispatch: backup snapshot heals first only when it asks the vault for keys, with no --recipient and no MEHEN_BACKUP_RECIPIENTS", async () => {
    const { freshInstallState, installation, writeInstallState } = await import("./install-state.ts")
    const state = freshInstallState()
    state.vault[vault.url] = { minimum: "9.0.0", recommended: null, seenAt: "2026-10-28T12:00:00.000Z" }
    await writeInstallState(installation(join(bin, "mehen")), state)
    await enrolled()
    const key = `age1${"q".repeat(58)}`
    for (const [argv, extra] of [[["backup", "snapshot", "--plan", "missing.json", "--to", "out", "--recipient", key], {}], [["backup", "snapshot", "--plan", "missing.json", "--to", "out", `--recipient=${key}`], {}], [["backup", "snapshot", "--plan", "missing.json", "--to", "out"], { MEHEN_BACKUP_RECIPIENTS: key }]] as const) {
      const named = await runJv([...argv], { ...installed(), ...extra })
      expect(named.stdout).not.toContain("healed")
    }
    expect(await ran()).toBeNull()
    const asks = await runJv(["backup", "snapshot", "--plan", "missing.json", "--to", "out", "--json"], installed())
    expect(asks.stdout.trim()).toBe('{"healed":true}')
    expect(await ran()).toBe("backup snapshot --plan missing.json --to out --json|1\n")
  })

  test("mid-command: a refusal after a local write heals and renders once, with the original command to run again, and never re-executes", async () => {
    vault.cliMinimum = "9.0.0"
    vault.cliAdvice = "minimum=9.0.0"
    const before = vault.outdated.length
    const result = await runJv(["enrol", "--workspace", "mock-space", "--json"], installed())
    expect(result.code).toBe(EXIT.error)
    expect(json(result)).toMatchObject({ error: "cli_outdated", next: { command: "mehen enrol --workspace mock-space --json", say: `mehen updated itself from ${VERSION} to 9.0.0; run the command again.` } })
    expect(vault.outdated.slice(before)).toEqual(["POST /v1/enrol"])
    // The new binary never ran the command (a background check may run).
    expect(await ran() ?? "").not.toContain("enrol")
    const { installation, readInstallState } = await import("./install-state.ts")
    const state = await readInstallState(installation(join(bin, "mehen")))
    expect(state?.vault[vault.url]).toMatchObject({ minimum: "9.0.0", recommended: null })
    expect(state?.installed).toMatchObject({ version: "9.0.0", by: "heal" })
  })

  // `setup --print` in an installed release spawned
  // an updater and created the log. Previews and every help form do no
  // installation work; an ordinary command still schedules.
  test("previews and help forms never schedule the updater or touch the installation; an ordinary command does", async () => {
    const { readdir } = await import("node:fs/promises")
    await writeFile(join(bin, "mehen"), `#!/bin/sh\nprintf '%s\\n' "$*" >> '${bin}/spawned'\n`, { mode: 0o755 })
    const recorder = { ...env, MEHEN_SELF_EXECUTABLE: join(bin, "mehen"), CI: "" }
    for (const argv of [["setup", "--print", "--json"], ["setup", "--print"], ["status", "--help"], ["status", "-h"], ["help", "status"], ["help"], ["--help"], ["run", "--help"], ["workspace", "--help"]]) {
      await runJv(argv, recorder)
      await Bun.sleep(50)
      expect(await readdir(bin), argv.join(" ")).toEqual(["mehen"])
    }
    await runJv(["templates", "--json"], recorder)
    let spawned: string | null = null
    for (let i = 0; i < 100 && spawned === null; i++) {
      spawned = await readFile(join(bin, "spawned"), "utf8").catch(() => null)
      if (spawned === null) await Bun.sleep(20)
    }
    expect(spawned).toBe("update --background\n")
  })

  test("a Homebrew keg below the vault's minimum is never healed or re-executed: the refusal says brew upgrade mehen", async () => {
    const { brewPrefix } = await import("./testing/brew-prefix.ts")
    const { freshInstallState, installation, writeInstallState } = await import("./install-state.ts")
    const brew = await brewPrefix(bin)
    const script = `#!/bin/sh\nexec '${process.execPath}' '${MAIN}' "$@"\n`
    await writeFile(brew.keg, script, { mode: 0o755 })
    const state = freshInstallState()
    state.vault[vault.url] = { minimum: "9.0.0", recommended: null, seenAt: "2026-10-28T12:00:00.000Z" }
    await writeInstallState(installation(brew.keg), state)
    vault.cliMinimum = "9.0.0"
    vault.cliAdvice = "minimum=9.0.0"
    const result = await runJv(["enrol", "--workspace", "mock-space", "--json"], { ...installed(), MEHEN_SELF_EXECUTABLE: brew.bin })
    expect(result.code).toBe(EXIT.error)
    expect(json(result)).toMatchObject({ error: "cli_outdated", next: { command: "brew upgrade mehen", say: expect.stringContaining("Homebrew installed this mehen") } })
    expect(await readFile(brew.keg, "utf8")).toBe(script)
    expect(await ran()).toBeNull()
  })

  test("a refusal on the third request of a command renders once with the vault's next and is never retried", async () => {
    vault.enrolOutcome = { pendingPolls: 50, result: "active" }
    const started = await runJv(["enrol", "--workspace", "mock-space", "--json"], env)
    expect(started.code).toBe(EXIT.ok)
    const id = String(json(started).enrolment)
    const before = vault.v1Count
    const refusedBefore = vault.outdated.length
    vault.outdatedFrom = before + 3
    const result = await runJv(["wait", id, "--json"], env)
    expect(result.code).toBe(EXIT.error)
    expect(json(result)).toMatchObject({ error: "cli_outdated", next: { command: "mehen update --json" } })
    expect(vault.v1Count).toBe(before + 3)
    expect(vault.outdated.slice(refusedBefore)).toHaveLength(1)
  })
})
