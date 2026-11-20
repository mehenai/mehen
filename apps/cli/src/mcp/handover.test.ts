// The transparent handover: on by default for a server
// with automatic updates on, off with `"mcpHandover": false` in its
// settings.json. The one-process run of every case switches it off that way.
//
// Every spawned case runs its script twice, each on its own installation:
// once switching, and once against one process that never switches. The
// host must read exactly the same messages from both. Ordering comes from
// the server's stages (written to stderr and held by the test on request),
// never from sleeps.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { appendFileSync, closeSync, existsSync, openSync, realpathSync, utimesSync, writeSync } from "node:fs"
import { type FileHandle, chmod, mkdir, mkdtemp, open, readFile, readdir, rename, rm, stat, utimes, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { base64UrlEncode } from "@mehen/protocol/bytes"
import { canonicalJson } from "@mehen/protocol/canonical-json"
import { type ReleaseKey, type SignedManifest, manifestSigningBytes } from "@mehen/protocol/release-manifest"
import { askUrlFor, policyAsk } from "../ask.ts"
import { type InstalledRecord, cliState, freshInstallState, installation, writeInstallState } from "../install-state.ts"
import { addLedgerEntry } from "../ledger.ts"
import { migrationJournalPath } from "../migration.ts"
import { sha256 } from "../release-client.ts"
import { MOCK_WORKSPACE, MockVault } from "../testing/mock-vault.ts"
import { MAIN } from "../testing/run-mehen.ts"
import { ASK_CARD_URI, CARD_MIME_TYPE, MCP_APPS_EXTENSION } from "./ui/cards.ts"
import { VERSION } from "../version.ts"
import { mcpDeps } from "../mcp.ts"
import { latchState, startServer } from "./binding.ts"
import { ACCEPT_STDERR_MAX_BYTES, RESUME_MAX_BYTES, type McpResumePayload, acceptResume, acceptanceRefusal, assertStillVerified, encodeResume, parseResume, prepareHandover, readResumeLine, resumeInto, takeResume } from "./handover.ts"
import { PrivateExecutables } from "./self-watch.ts"

const SRC = join(import.meta.dir, "..")
// The version the image a switch replaces runs as, and its replacement's:
// the source both run is this build, so the replacement is VERSION.
const OLD = "0.3.0"
const UPDATE = VERSION

let releaseKey: ReleaseKey
let signer: CryptoKey
let vault: MockVault
beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey)
  releaseKey = { id: "rk-test-handover", alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y! }, presence: "none", created: "2026-10-28T12:00:00.000Z" }
  signer = pair.privateKey
  vault = new MockVault()
})
afterAll(() => vault.stop())

async function signedManifest(version: string, bytes: Uint8Array): Promise<SignedManifest> {
  const gz = Bun.gzipSync(new Uint8Array(bytes))
  const files = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"].map((t) => ({ name: `mehen-${t}`, os: t.split("-")[0]!, arch: t.split("-")[1]!, url: `https://mehen.dev/dl/v${version}/mehen-${t}.gz`, sha256: sha256(bytes), size: bytes.length, gzSha256: sha256(gz), gzSize: gz.length }))
  const manifest = { version, commit: "abc1234", builtAt: "2026-10-28T12:00:00Z", files }
  const signature = base64UrlEncode(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signer, manifestSigningBytes(manifest)))
  return { ...manifest, signatures: [{ keyId: releaseKey.id, alg: "ES256", signature }] }
}

// One test installation, all private: the binary with its install state
// and receipt beside it, a config root, a HOME, a TMPDIR, and the test
// entry every image runs.
type Fixture = { dir: string; binary: string; config: string; home: string; tmp: string }

const fixtures: Fixture[] = []
afterEach(async () => {
  vault.overrides.clear()
  vault.workspace = { ...MOCK_WORKSPACE }
  for (const f of fixtures.splice(0)) await rm(f.dir, { recursive: true, force: true })
})

async function makeFixture(): Promise<Fixture> {
  const root = realpathSync(await mkdtemp(join(tmpdir(), "mehen-handover-")))
  await chmod(root, 0o700)
  const f: Fixture = { dir: root, binary: join(root, "mehen"), config: join(root, "config"), home: join(root, "home"), tmp: join(root, "tmp") }
  fixtures.push(f)
  await mkdir(f.home, { mode: 0o700 })
  await mkdir(f.tmp, { mode: 0o700 })
  // The test entry: the server, each stage written to stderr as `stage
  // <name>` and held until SIGWINCH when the `hold` file names it (a signal
  // nothing else sends, ignored by default, and one Bun delivers to a
  // listener on macOS and Linux); and the acceptance check, through the
  // command line.
  await writeFile(
    join(root, "entry.ts"),
    [
      `import { existsSync, readFileSync, readdirSync, realpathSync, renameSync, unlinkSync, writeFileSync } from "node:fs"`,
      `import { setPasswdHomeLookupForTests } from ${JSON.stringify(join(SRC, "agent-profiles.ts"))}`,
      `import { enterRoot } from ${JSON.stringify(join(SRC, "migration.ts"))}`,
      `import { serveMcp, setServeSeamsForTests } from ${JSON.stringify(join(SRC, "mcp.ts"))}`,
      `import { main } from ${JSON.stringify(join(SRC, "cli.ts"))}`,
      `setPasswdHomeLookupForTests(() => ({ kind: "found", home: realpathSync(process.env.HOME ?? "") }))`,
      `const args = process.argv.slice(2)`,
      `if (args[0] === "mcp" && args[1] === "--accept-resume") process.exit(await main(args, process.env))`,
      `const running = process.env.HANDOVER_TEST_RUNNING`,
      `const hold = ${JSON.stringify(join(root, "hold"))}`,
      `const stage = async (name: string) => {`,
      `  let held = false`,
      `  try { held = readFileSync(hold, "utf8") === name } catch {}`,
      `  if (held) unlinkSync(hold)`,
      `  const released = held ? new Promise((resolve) => process.once("SIGWINCH", resolve)) : null`,
      `  process.stderr.write(\`stage \${name}\\n\`)`,
      `  await released`,
      `}`,
      // Once the last hash is done, the private directories still marked
      // under TMPDIR are counted into "hashed", and a file the test left as
      // "swap" is renamed into place.
      `const hashed = () => {`,
      `  const tmp = process.env.TMPDIR ?? ""`,
      `  const marked = readdirSync(tmp).filter((name) => name.startsWith("mehen-mcp-") && existsSync(\`\${tmp}/\${name}/owner.json\`)).length`,
      `  writeFileSync(${JSON.stringify(join(root, "hashed"))}, \`\${marked} marked\`)`,
      `  try { renameSync(${JSON.stringify(join(root, "swap"))}, ${JSON.stringify(f.binary)}) } catch {}`,
      `}`,
      // HANDOVER_TEST_ENTRY=main: the server as the command line starts it.
      `if (process.env.HANDOVER_TEST_ENTRY === "main") {`,
      `  setServeSeamsForTests({ stage, hashed, running })`,
      `  process.stderr.write("stage serving\\n")`,
      `  process.exitCode = await main(args, process.env)`,
      `} else {`,
      `  await enterRoot(process.env)`,
      `  process.stderr.write("stage serving\\n")`,
      `  process.exitCode = await serveMcp(process.env, { args: args.slice(1), stage, hashed, running })`,
      `}`,
    ].join("\n"),
  )
  await writeFile(f.binary, imageFor(f, "old", OLD), { mode: 0o755 })
  return f
}

// An image: answers `version --json` itself, logs every other run to
// `images`, then runs the test entry as `version` (the source it runs is
// this build's: a replacement is this VERSION, and the image it replaces
// says it runs OLD). `accept` replaces the acceptance check's answer.
function imageFor(f: Fixture, mark: string, version: string, options: { accept?: string } = {}): Uint8Array {
  const info = JSON.stringify({ version, commit: "abc1234", build: "release", helper: process.platform === "darwin" ? "embedded" : "none" })
  const accept = options.accept ? `if [ "$1 $2" = "mcp --accept-resume" ]; then printf '%s %s\\n' '${mark}' "$*" >> '${f.dir}/images'; ${options.accept}; fi\n` : ""
  return new TextEncoder().encode(`#!/bin/sh\n# ${mark}\nif [ "$1 $2" = "version --json" ]; then printf '%s\\n' '${info}'; exit 0; fi\n${accept}printf '%s %s\\n' '${mark}' "$*" >> '${f.dir}/images'\nexport HANDOVER_TEST_RUNNING='${version}'\nexec '${process.execPath}' '${join(f.dir, "entry.ts")}' "$@"\n`)
}

// Bytes at the binary's path by rename, as the updater lands them.
async function land(f: Fixture, bytes: Uint8Array): Promise<void> {
  await writeFile(`${f.binary}.new`, bytes, { mode: 0o755 })
  await rename(`${f.binary}.new`, f.binary)
}

// A signed update: the bytes landed, then recorded with a key id and the
// retained signed manifest, and the receipt written.
async function updateIn(f: Fixture, bytes: Uint8Array, version = UPDATE): Promise<InstalledRecord> {
  await land(f, bytes)
  const manifest = await signedManifest(version, bytes)
  const installed: InstalledRecord = { version, commit: "abc1234", sha256: sha256(bytes), size: bytes.length, at: "2026-10-28T12:00:00.000Z", by: "auto", keyId: releaseKey.id, manifestSha256: sha256(new TextEncoder().encode(canonicalJson(manifest))), manifest }
  const state = freshInstallState()
  state.installed = installed
  await writeInstallState(installation(f.binary), state)
  await writeFile(join(f.dir, ".mehen.sha256"), `${installed.sha256}\n`)
  return installed
}

const envFor = (f: Fixture, extra: Record<string, string> = {}) => ({ PATH: process.env.PATH ?? "", HOME: f.home, TMPDIR: f.tmp, MEHEN_CONFIG_DIR: f.config, MEHEN_VAULT_URL: vault.url, MEHEN_SELF_EXECUTABLE: f.binary, MEHEN_DL_BASE: "http://127.0.0.1:9/dl", MEHEN_RELEASE_KEYS: JSON.stringify([releaseKey]), MEHEN_POLL_INTERVAL_MS: "20", MEHEN_MCP_TOOLSETS: "all", CI: "", ...extra })
// settings.json under the installation's config root.
const handoverSetting = async (f: Fixture, on: boolean) => {
  await mkdir(f.config, { recursive: true, mode: 0o700 })
  await writeFile(join(f.config, "settings.json"), `${JSON.stringify({ mcpHandover: on })}\n`)
}
const checkoutOf = (f: Fixture) => join(f.dir, "checkout")
const imagesOf = async (f: Fixture) => (await readFile(join(f.dir, "images"), "utf8").catch(() => "")).split("\n").filter(Boolean)

type Content = { type: string; text?: string }
type Message = { jsonrpc: "2.0"; id?: number | null; method?: string; params?: unknown; result?: Record<string, unknown> & { content?: Content[] }; error?: { code: number; message: string } }

// The host: writes to the server's stdin, and reads its stdout through a
// FIFO it owns, so it can stop reading and the server's writes back up (a
// Bun pipe would be drained into memory whatever the test did). It keeps
// the server's stderr, where the test entry reports each stage.
class Host {
  readonly received: Message[] = []
  stderr = ""
  private readonly listeners = new Set<() => void>()
  private ended = false
  private gate: { promise: Promise<void>; open: () => void } | null = null

  private constructor(
    readonly proc: ReturnType<typeof Bun.spawn<"pipe", number, "pipe">>,
    out: FileHandle,
  ) {
    void this.read(out)
    void this.readStderr()
  }

  static async start(f: Fixture, hostEnv: Record<string, string>, options: { cwd?: string; args?: string[] } = {}): Promise<Host> {
    const fifo = join(f.dir, "stdout")
    if (Bun.spawnSync(["mkfifo", "-m", "600", fifo]).exitCode !== 0) throw new Error("mkfifo failed")
    // Opening a FIFO blocks until both ends are open: the read end opens
    // off the main thread while this one opens the write end.
    const reading = open(fifo, "r")
    const writeEnd = openSync(fifo, "w")
    const out = await reading
    try {
      return new Host(Bun.spawn([f.binary, "mcp", ...(options.args ?? [])], { env: hostEnv, ...(options.cwd ? { cwd: options.cwd } : {}), stdin: "pipe", stdout: writeEnd, stderr: "pipe", timeout: 60_000 }), out)
    } finally {
      closeSync(writeEnd)
    }
  }

  private changed(): void {
    for (const listener of [...this.listeners]) listener()
  }

  private async read(out: FileHandle): Promise<void> {
    const chunk = new Uint8Array(64 * 1024)
    const decoder = new TextDecoder()
    let buffer = ""
    try {
      for (;;) {
        if (this.gate) await this.gate.promise
        const { bytesRead } = await out.read(chunk, 0, chunk.length, null)
        if (bytesRead === 0) return
        buffer += decoder.decode(chunk.subarray(0, bytesRead), { stream: true })
        let newline = buffer.indexOf("\n")
        while (newline !== -1) {
          this.received.push(JSON.parse(buffer.slice(0, newline)) as Message)
          buffer = buffer.slice(newline + 1)
          newline = buffer.indexOf("\n")
        }
        this.changed()
      }
    } finally {
      await out.close()
      this.ended = true
      this.changed()
    }
  }

  private async readStderr(): Promise<void> {
    const decoder = new TextDecoder()
    const reader = this.proc.stderr.getReader()
    for (;;) {
      const { done, value } = await reader.read()
      if (done) return
      this.stderr += decoder.decode(value, { stream: true })
      this.changed()
    }
  }

  // Stops reading stdout once the read in progress returns, until resume().
  pause(): void {
    let open = () => {}
    const promise = new Promise<void>((resolve) => {
      open = resolve
    })
    this.gate = { promise, open }
  }

  resume(): void {
    const gate = this.gate
    this.gate = null
    gate?.open()
  }

  // Resolves once `done` holds, looked at again whenever the server writes;
  // refused when its stdout ended first.
  until<T>(done: () => T | undefined | false, what: string): Promise<T> {
    return new Promise((resolve, reject) => {
      const look = () => {
        const value = done()
        if (value !== undefined && value !== false) {
          this.listeners.delete(look)
          resolve(value)
        } else if (this.ended) {
          this.listeners.delete(look)
          reject(new Error(`the server ended before ${what}; stderr:\n${this.stderr}`))
        }
      }
      this.listeners.add(look)
      look()
    })
  }

  reply(id: number): Promise<Message> {
    return this.until(() => this.received.find((m) => m.id === id), `answering ${id}`)
  }

  stage(name: string, count = 1): Promise<void> {
    return this.until(() => this.stderr.split("\n").filter((l) => l === `stage ${name}`).length >= count, `stage ${name} #${count}`).then(() => {})
  }

  logged(text: string): Promise<void> {
    return this.until(() => this.stderr.includes(text), JSON.stringify(text)).then(() => {})
  }

  write(bytes: string | Uint8Array): void {
    this.proc.stdin.write(bytes)
    this.proc.stdin.flush()
  }

  async close(): Promise<number> {
    this.resume()
    this.proc.stdin.end()
    const code = await this.proc.exited
    await this.until(() => this.ended, "its stdout closed").catch(() => {})
    return code
  }
}

// What one process would have answered: one that saw no update at all
// (`plain`), or one that saw the same changes on disk and, with the
// handover off, keeps serving and asks for a restart (`restart`).
type Reference = "plain" | "restart"

// One run of a case's script. The switching run has the handover on; the
// reference is one process given the same writes and, as `Reference` says,
// the same changes on disk. A step only a switch has (waiting for one of
// its stages, holding or releasing one) is nothing in the reference.
class Session {
  constructor(
    readonly fixture: Fixture,
    readonly host: Host,
    readonly switching: boolean,
    readonly device: string | null,
    private readonly reference: Reference,
  ) {}

  send(bytes: string | Uint8Array): void {
    this.host.write(bytes)
  }

  reply(id: number): Promise<Message> {
    return this.host.reply(id)
  }

  // The look after the `count`th tool call, in every run.
  checked(count: number): Promise<void> {
    return this.host.stage("checked", count)
  }

  async stage(name: string, count = 1): Promise<void> {
    if (this.switching) await this.host.stage(name, count)
  }

  async logged(text: string): Promise<void> {
    if (this.switching) await this.host.logged(text)
  }

  async hold(name: string): Promise<void> {
    if (this.switching) await writeFile(join(this.fixture.dir, "hold"), name)
  }

  release(): void {
    if (this.switching) this.host.proc.kill("SIGWINCH")
  }

  image(mark: string, version: string, options: { accept?: string } = {}): Uint8Array {
    return imageFor(this.fixture, mark, version, options)
  }

  // A signed update, in every run but a plain reference.
  async update(bytes: Uint8Array, version = UPDATE): Promise<void> {
    if (this.switching || this.reference === "restart") await updateIn(this.fixture, bytes, version)
  }
}

type Run = { fixture: Fixture; host: Host; device: string | null; code: number }

// Runs `script` switching, then against one process, each on its own
// installation, and asserts the host read exactly the same messages from
// both and saw both end the same way. Returns the switching run. With
// `checkout`, the server starts in a checkout whose mehen.toml says that;
// `args` follow `mcp`.
async function againstOneProcess(reference: Reference, script: (s: Session) => Promise<void>, options: { env?: Record<string, string>; enrolled?: boolean; checkout?: string; args?: string[] } = {}): Promise<Run> {
  const runs: Run[] = []
  for (const switching of [true, false]) {
    const f = await makeFixture()
    const device = options.enrolled === false ? null : await vault.enrolSoftware(f.config)
    if (!switching) await handoverSetting(f, false)
    if (options.checkout !== undefined) {
      await mkdir(checkoutOf(f), { mode: 0o700 })
      await writeFile(join(checkoutOf(f), "mehen.toml"), options.checkout)
    }
    const host = await Host.start(f, envFor(f, options.env), { ...(options.checkout === undefined ? {} : { cwd: checkoutOf(f) }), ...(options.args ? { args: options.args } : {}) })
    try {
      await host.stage("serving")
      await script(new Session(f, host, switching, device, reference))
    } catch (error) {
      host.proc.kill()
      throw new Error(`${switching ? "switching" : "one process"}: ${error instanceof Error ? error.message : String(error)}\nstderr:\n${host.stderr}`)
    }
    runs.push({ fixture: f, host, device, code: await host.close() })
  }
  const [switched, single] = runs as [Run, Run]
  expect(sameAs(switched)).toEqual(sameAs(single))
  expect(switched.code).toBe(single.code)
  return switched
}

// The messages as a host compares them across two installations: each
// installation's directory, and the mock's generated ids and each device
// key's fingerprint named by first appearance, and `cli` (this build's own installation state, which the
// two runs differ in by construction) left out.
function sameAs(run: Run): unknown[] {
  const ids = new Map<string, string>()
  const text = JSON.stringify(run.host.received)
    .replaceAll(run.fixture.dir, "<installation>")
    .replace(/\b[a-z]+_[A-Za-z]*mock\d+\b|\b[A-Z0-9]{4}(?: [A-Z0-9]{4}){3}\b/g, (id) => {
      if (!ids.has(id)) ids.set(id, `<id ${ids.size + 1}>`)
      return ids.get(id)!
    })
  return (JSON.parse(text) as Message[]).map(withoutCli).map(withoutListChanged)
}

// The one difference the handover makes to what a host reads: `initialize`
// says the tool list may change. Asserted on its own.
function withoutListChanged(m: Message): Message {
  const capabilities = m.result?.capabilities as { tools?: { listChanged?: boolean } } | undefined
  if (capabilities?.tools?.listChanged === undefined) return m
  return { ...m, result: { ...m.result, capabilities: { ...capabilities, tools: { ...capabilities.tools, listChanged: "<handover on or off>" } } } }
}

function withoutCli(m: Message): Message {
  const structured = m.result?.structuredContent as Record<string, unknown> | undefined
  if (!m.result || !structured || !("cli" in structured)) return m
  const { cli: _cli, ...rest } = structured
  const content = (m.result.content ?? []).map((c) => {
    if (c.type !== "text" || c.text === undefined) return c
    try {
      const { cli: _shown, ...shown } = JSON.parse(c.text) as Record<string, unknown>
      return { ...c, text: JSON.stringify(shown) }
    } catch {
      return c
    }
  })
  return { ...m, result: { ...m.result, structuredContent: rest, content } }
}

const restartNotices = (m: Message) => (m.result?.content ?? []).filter((c) => c.type === "text" && c.text?.includes("Restart the agent")).map((c) => c.text)
const RESTART_TEXT = `mehen ${UPDATE} is installed on this machine; this server still runs ${OLD}. Restart the agent to use the new version.`

const line = (id: number, method: string, params?: unknown) => `${JSON.stringify({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) })}\n`
const call = (id: number, name: string, args: Record<string, unknown> = {}) => line(id, "tools/call", { name, arguments: args })
const initialize = (id: number) => line(id, "initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "handover-test", version: "1" } })

// The opening every switching case shares: initialize, a call, an update
// on disk, and a call whose look verifies it.
async function verifiedUpdate(s: Session, options: { accept?: string } = {}): Promise<void> {
  s.send(initialize(1))
  await s.reply(1)
  s.send(call(2, "vault_status"))
  await s.reply(2)
  await s.checked(1)
  await s.update(s.image("new", UPDATE, options))
  s.send(call(3, "vault_templates"))
  await s.reply(3)
  await s.checked(2)
}

// Whether the image that answered a vault_status still knew of a verified
// replacement (`cli.mcp`): the old image does, the new one is it.
const knewReplacement = (m: Message) => (m.result?.structuredContent as { cli?: { mcp?: unknown } } | undefined)?.cli?.mcp !== undefined

// A policy proposal this machine recorded, pending at the vault until a
// test settles it, for a vault_wait that stays in flight.
const POLICY_EXPIRES = "2099-01-01T00:00:00.000Z"
const proposal = (status: string, outcome: unknown = null) => ({ proposal: "pol_x", item: "example-key", status, bindingCode: "CODE", summary: "Relax a route", expiresAt: POLICY_EXPIRES, outcome })
const APPROVED = { change: { kind: "mode", policyMode: "relaxed", ttlSeconds: 60 }, override: "pov_narrowed", grant: null, effectiveUntil: POLICY_EXPIRES, active: false, endedReason: "revoked" }
async function pendingProposal(s: Session): Promise<void> {
  const link = askUrlFor(vault.askVault(), "policy", "pol_x")!
  await addLedgerEntry(vault.slotDir(s.fixture.config), vault.ledgerScope(), { ask: policyAsk({ id: "pol_x", url: link.url, summary: "Relax a route", bindingCode: "CODE", expiresAt: POLICY_EXPIRES, requestedBy: { device: "test-machine", session: null } }) })
  vault.overrides.set("GET /v1/policy/proposals/pol_x", () => Response.json(proposal("pending")))
}
const cancelled = (requestId: number) => `${JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId } })}\n`

// The fixture the payload tests use; the spawned cases make their own.
let fixture: Fixture
let dir: string
let binary: string
let config: string
beforeEach(async () => {
  fixture = await makeFixture()
  ;({ dir, binary, config } = fixture)
})
const env = (extra: Record<string, string> = {}) => envFor(fixture, extra)
const image = (mark: string, version: string, options: { accept?: string } = {}) => imageFor(fixture, mark, version, options)
const replaceWith = (bytes: Uint8Array, version = UPDATE) => updateIn(fixture, bytes, version)
const images = () => readFile(join(dir, "images"), "utf8").catch(() => "")
// The replacement as the self-watch verified it: the record and the file at the path now.
const verifiedNow = async (record: InstalledRecord) => {
  const info = await stat(binary)
  return { identity: { dev: info.dev, ino: info.ino, size: info.size, mtimeMs: info.mtimeMs }, record }
}

describe("the handover, on by default and off through settings.json", () => {
  test("a server with the handover off drops MEHEN_MCP_RESUME, still reads a payload it is handed (the old image decided), ends before serving on one it cannot take, and does not announce tool list changes", async () => {
    const taken = takeResume({ MEHEN_MCP_RESUME: "{}", HOME: "/h" })
    expect(taken).toEqual({ env: { HOME: "/h" }, payload: "{}" })
    const serve = async (extra: Record<string, string>) => {
      const proc = Bun.spawn([process.execPath, MAIN, "mcp"], { env: { ...env(), MEHEN_SELF_EXECUTABLE: "", ...extra }, stdin: "pipe", stdout: "pipe", stderr: "pipe", timeout: 30_000 })
      proc.stdin.write(initialize(1))
      proc.stdin.end()
      const [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
      return { code: await proc.exited, out, err }
    }
    // A development run: its own handover is off.
    const garbage = await serve({ MEHEN_MCP_RESUME: "not a payload" })
    expect(garbage.code).not.toBe(0)
    expect(garbage.out).toBe("")
    expect(garbage.err).toContain("the resume payload is not JSON")
    const plain = await serve({})
    expect(plain.code).toBe(0)
    const init = JSON.parse(plain.out.split("\n")[0]!) as Message
    expect(init.result).toMatchObject({ capabilities: { tools: { listChanged: false } } })
  })

  test("a new image takes a committed payload over whatever settings.json says by then: turned off after the acceptance, the switch still happens and the latch is carried", async () => {
    const run = await againstOneProcess("plain", async (s) => {
      await verifiedUpdate(s)
      await s.hold("accepted")
      s.send(line(4, "ping"))
      await s.stage("accepted")
      // After the old image's last look at the setting: it has committed.
      if (s.switching) await handoverSetting(s.fixture, false)
      // Another device in the latched slot: only a carried latch refuses it.
      await vault.enrolSoftware(s.fixture.config)
      s.release()
      await s.reply(4)
      await s.stage("serving", 2)
      s.send(call(5, "vault_templates"))
      await s.reply(5)
      s.send(call(6, "vault_status"))
      await s.reply(6)
    })
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
    const status = run.host.received.find((m) => m.id === 6)!.result!.structuredContent as { workspaces: { check: unknown }[]; cli: { mcpHandover: unknown } }
    expect(status.workspaces[0]!.check).toMatchObject({ ok: false, error: "workspace_mismatch" })
    // The new image's own decision governs only the switches it would start.
    expect(status.cli.mcpHandover).toEqual({ handover: "off", reason: "mcpHandover is false in settings.json" })
  }, 60_000)

  test("a verified replacement is switched to in place: the host reads what one process would have, the process never exits, the latch is carried and no initialize is needed", async () => {
    const run = await againstOneProcess("plain", async (s) => {
      await verifiedUpdate(s)
      // A request split inside a multibyte character inside a JSON string:
      // while its first part is held the switch waits, then the old image
      // answers it and switches at the quiet point after.
      const split = new TextEncoder().encode(call(4, "vault_check", { url: "https://api.example.com/é", method: "GET" }))
      const cut = split.indexOf(0xc3) + 1
      s.send(split.slice(0, cut))
      await s.stage("partial")
      s.send(split.slice(cut))
      await s.reply(4)
      await s.stage("serving", 2)
      // Several requests in one write, read by the new image, which never
      // saw an initialize.
      s.send(line(5, "ping") + line(6, "tools/list") + "{not json\n" + line(7, "no/such/method"))
      await Promise.all([s.reply(5), s.reply(6), s.reply(7)])
      // The new image serves the slot the old one latched, as that identity.
      s.send(call(8, "vault_status"))
      await s.reply(8)
    })
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
    // The old image's private directory went with it (it launched no
    // updater): same pid, so nothing else would ever sweep it.
    expect((await readdir(run.fixture.tmp)).filter((name) => name.startsWith("mehen-mcp-"))).toEqual([])
    const status = run.host.received.find((m) => m.id === 8)!.result!.structuredContent as { workspaces: { device: string; check: { ok: boolean } }[] }
    expect(status.workspaces[0]).toMatchObject({ device: run.device!, check: { ok: true } })
    // The same tool list: no list_changed. A pending switch is not announced.
    expect(run.host.received.filter((m) => m.method === "notifications/tools/list_changed")).toEqual([])
    expect(run.host.received.flatMap(restartNotices)).toEqual([])
    // execve kept the process: the host saw it end only when stdin closed.
    expect(run.code).toBe(0)
  }, 60_000)

  test("a new image that refuses the payload means no switch: the old image keeps serving and asks for a restart, as one process does", async () => {
    const run = await againstOneProcess("restart", async (s) => {
      await verifiedUpdate(s, { accept: "exit 1" })
      s.send(line(4, "ping"))
      await s.reply(4)
      await s.logged("mcp handover cancelled")
      s.send(call(5, "vault_templates"))
      await s.reply(5)
    })
    expect(run.host.stderr).toContain("the new image refused the resume payload (exit 1)")
    expect(run.host.received.flatMap(restartNotices)).toEqual([RESTART_TEXT])
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume"])
  }, 60_000)

  test("a server with the handover on says the tool list may change, reports its decision in cli.mcpHandover with no cli.mcp until a replacement is verified, and cli.mcp says switch until it has", async () => {
    const cliOf = (m: Message) => (m.result?.structuredContent as { cli: Record<string, unknown> }).cli
    const run = await againstOneProcess("plain", async (s) => {
      await verifiedUpdate(s)
      s.send(call(4, "vault_status"))
      await s.reply(4)
      await s.stage("serving", 2)
      s.send(call(5, "vault_status"))
      await s.reply(5)
    })
    const reply = (id: number) => run.host.received.find((m) => m.id === id)!
    expect(reply(1).result).toMatchObject({ capabilities: { tools: { listChanged: true } } })
    expect(cliOf(reply(2)).mcpHandover).toEqual({ handover: "on" })
    expect(Object.hasOwn(cliOf(reply(2)), "mcp")).toBe(false)
    // Answered by the old image while the switch waited for it.
    expect(cliOf(reply(4))).toMatchObject({ mcpHandover: { handover: "on" }, mcp: { running: OLD, installed: UPDATE, action: "switch" } })
    expect(Object.hasOwn(cliOf(reply(4)).mcp as object, "reason")).toBe(false)
    // The new image is the replacement: nothing newer on disk.
    expect(Object.hasOwn(cliOf(reply(5)), "mcp")).toBe(false)
    expect(cliOf(reply(5)).mcpHandover).toEqual({ handover: "on" })
    expect(run.host.received.flatMap(restartNotices)).toEqual([])
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
  }, 60_000)

  test("a server reports the decision it started with when settings.json changes, and cli.mcp says why there is no switch once one is refused; a shell reports what a server started now would decide", async () => {
    const cliOf = (m: Message) => (m.result?.structuredContent as { cli: Record<string, unknown> }).cli
    const run = await againstOneProcess("restart", async (s) => {
      s.send(initialize(1))
      await s.reply(1)
      // Switched off once the server has decided (it answers initialize only
      // after): the running server still reports its start, and its look
      // at the setting before the switch stops it.
      if (s.switching) await handoverSetting(s.fixture, false)
      s.send(call(2, "vault_status"))
      await s.reply(2)
      await s.checked(1)
      await s.update(s.image("new", UPDATE))
      s.send(call(3, "vault_templates"))
      await s.reply(3)
      await s.checked(2)
      s.send(line(4, "ping"))
      await s.reply(4)
      await s.logged("mcp handover cancelled")
      s.send(call(5, "vault_status"))
      await s.reply(5)
    })
    expect(run.host.stderr).toContain("the handover was turned off: mcpHandover is false in settings.json")
    const status = cliOf(run.host.received.find((m) => m.id === 5)!)
    expect(status.mcpHandover).toEqual({ handover: "on" })
    expect(status.mcp).toEqual({ running: OLD, installed: UPDATE, action: "restart", reason: `the switch to ${UPDATE} was refused` })
    expect(run.host.received.flatMap(restartNotices)).toEqual([RESTART_TEXT])
    expect(await imagesOf(run.fixture)).toEqual(["old mcp"])
    const shell = envFor(run.fixture)
    expect((await cliState(shell)).mcpHandover).toEqual({ handover: "off", reason: "mcpHandover is false in settings.json" })
    await handoverSetting(run.fixture, true)
    const on = await cliState(shell)
    expect(on.mcpHandover).toEqual({ handover: "on" })
    expect(Object.hasOwn(on, "mcp")).toBe(false)
  }, 60_000)

  test("a running server whose settings.json turns the handover off before it commits does not switch: it reads the setting again before the acceptance check, and asks for a restart as one process does", async () => {
    const run = await againstOneProcess("restart", async (s) => {
      // An acceptance check that takes anything: only the old image's own look stops the switch.
      await verifiedUpdate(s, { accept: "exit 0" })
      await s.hold("holdoff")
      s.send(line(4, "ping"))
      await s.stage("holdoff")
      if (s.switching) await handoverSetting(s.fixture, false)
      s.release()
      await s.reply(4)
      await s.logged("mcp handover cancelled")
      s.send(call(5, "vault_templates"))
      await s.reply(5)
    })
    expect(run.host.stderr).toContain("the handover was turned off: mcpHandover is false in settings.json")
    expect(run.host.received.flatMap(restartNotices)).toEqual([RESTART_TEXT])
    expect(await imagesOf(run.fixture)).toEqual(["old mcp"])
  }, 60_000)

  test("a new image whose own acceptance check refuses a payload of this v means no switch", async () => {
    const run = await againstOneProcess("restart", async (s) => {
      // The new image's real acceptance check, handed the payload as a
      // build that only takes another v would read it.
      await verifiedUpdate(s, { accept: `sed 's/^{"v":1,/{"v":2,/' | '${process.execPath}' '${join(s.fixture.dir, "entry.ts")}' mcp --accept-resume; exit $?` })
      s.send(line(4, "ping"))
      await s.reply(4)
      await s.logged("mcp handover cancelled")
      s.send(call(5, "vault_templates"))
      await s.reply(5)
    })
    expect(run.host.stderr).toContain("the new image refused the resume payload (exit 1): the resume payload is not one this build accepts")
    expect(run.host.received.flatMap(restartNotices)).toEqual([RESTART_TEXT])
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume"])
  }, 60_000)

  test("MEHEN_NO_AUTO_UPDATE=1 switches the handover off on a running server: no hold-off, no switch, the restart notice as one process gives it", async () => {
    const run = await againstOneProcess(
      "restart",
      async (s) => {
        await verifiedUpdate(s)
        s.send(line(4, "ping"))
        await s.reply(4)
        s.send(call(5, "vault_templates"))
        await s.reply(5)
      },
      { env: { MEHEN_NO_AUTO_UPDATE: "1" } },
    )
    expect(run.host.stderr).not.toContain("stage holdoff")
    expect(run.host.received.flatMap(restartNotices)).toEqual([RESTART_TEXT])
    expect(await imagesOf(run.fixture)).toEqual(["old mcp"])
  }, 60_000)

  test("a new image whose tool list differs from the old one's says so first, then answers tools/list without an initialize", async () => {
    const f = await makeFixture()
    await vault.enrolSoftware(f.config)
    const e = envFor(f)
    const server = await startServer(e, process.cwd())
    const payload: McpResumePayload = { v: 1, protocolVersion: "2025-11-25", clientInfo: { name: "handover-test", version: "1" }, initialized: true, startedAt: "2026-10-28T12:00:00.000Z", toolsHash: "another tool list", latch: latchState(server), manifest: await signedManifest(UPDATE, new Uint8Array([1])) }
    const host = await Host.start(f, { ...e, MEHEN_MCP_RESUME: encodeResume(payload) })
    await host.stage("serving")
    host.write(line(1, "tools/list"))
    await host.reply(1)
    expect(await host.close()).toBe(0)
    expect(host.received.map((m) => m.method ?? m.id)).toEqual(["notifications/tools/list_changed", 1])
    expect((host.received[1]!.result!.tools as unknown[]).length).toBeGreaterThan(5)
  }, 60_000)

  test("a payload over its bound means no switch: the old image keeps serving and asks for a restart, as one process does", async () => {
    const run = await againstOneProcess("restart", async (s) => {
      s.send(line(1, "initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x".repeat(RESUME_MAX_BYTES), version: "1" } }))
      await s.reply(1)
      await s.update(s.image("new", UPDATE, { accept: "exit 0" }))
      s.send(call(2, "vault_templates"))
      await s.reply(2)
      await s.checked(1)
      s.send(line(3, "ping"))
      await s.reply(3)
      await s.logged("mcp handover cancelled")
      s.send(call(4, "vault_templates"))
      await s.reply(4)
    })
    expect(run.host.stderr).toContain(`the resume payload is over ${RESUME_MAX_BYTES} bytes`)
    expect(run.host.received.flatMap(restartNotices)).toEqual([RESTART_TEXT])
    expect(await imagesOf(run.fixture)).toEqual(["old mcp"])
  }, 60_000)

  test("a second replacement before the acceptance cancels the switch, and nothing at the path runs", async () => {
    const run = await againstOneProcess("restart", async (s) => {
      await verifiedUpdate(s, { accept: "exit 0" })
      // Another binary lands while the switch waits for its quiet point.
      await s.hold("holdoff")
      s.send(line(4, "ping"))
      await s.stage("holdoff")
      await land(s.fixture, s.image("third", "99.0.1", { accept: "exit 0" }))
      s.release()
      await s.reply(4)
      await s.logged("mcp handover cancelled")
      s.send(call(5, "vault_templates"))
      await s.reply(5)
    })
    expect(run.host.stderr).toContain("the executable changed after it was verified")
    expect(await imagesOf(run.fixture)).toEqual(["old mcp"])
  }, 60_000)

  test("a second replacement after the acceptance, just before the exec, cancels the switch: the identity is read again as the last step before execve", async () => {
    const run = await againstOneProcess("restart", async (s) => {
      await verifiedUpdate(s, { accept: "exit 0" })
      await s.hold("accepted")
      s.send(line(4, "ping"))
      await s.stage("accepted")
      await land(s.fixture, s.image("third", "99.0.1", { accept: "exit 0" }))
      s.release()
      await s.reply(4)
      await s.logged("mcp handover cancelled")
      s.send(call(5, "vault_templates"))
      await s.reply(5)
    })
    expect(run.host.stderr).toContain("the executable changed after it was verified")
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume"])
  }, 60_000)

  test("a replacement renamed into place after the last hash, just before the exec, cancels the switch: the path must still name the file that was hashed, and the private directory was released before that last look", async () => {
    const run = await againstOneProcess("restart", async (s) => {
      await verifiedUpdate(s, { accept: "exit 0" })
      const third = s.image("third", "99.0.1", { accept: "exit 0" })
      // The test entry renames it into place once the last hash is done.
      if (s.switching) await writeFile(join(s.fixture.dir, "swap"), third, { mode: 0o755 })
      else await land(s.fixture, third)
      s.send(line(4, "ping"))
      await s.reply(4)
      await s.logged("mcp handover cancelled")
      s.send(call(5, "vault_templates"))
      await s.reply(5)
    })
    expect(existsSync(join(run.fixture.dir, "swap"))).toBe(false)
    expect(await readFile(join(run.fixture.dir, "hashed"), "utf8")).toBe("0 marked")
    expect(run.host.stderr).toContain("the executable changed after it was verified")
    expect(run.host.received.flatMap(restartNotices)).toEqual([RESTART_TEXT])
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume"])
  }, 60_000)

  test("requests arriving while the replacement is verified are answered by the old image, and the switch follows", async () => {
    const run = await againstOneProcess("plain", async (s) => {
      s.send(initialize(1))
      await s.reply(1)
      s.send(call(2, "vault_status"))
      await s.reply(2)
      await s.checked(1)
      await s.hold("verifying")
      await s.update(s.image("new", UPDATE))
      s.send(call(3, "vault_templates"))
      await s.reply(3)
      // The look after call 3 has read the replacement and is held there.
      await s.stage("verifying")
      s.send(line(4, "ping") + line(5, "tools/list"))
      await Promise.all([s.reply(4), s.reply(5)])
      s.send(call(6, "vault_status"))
      await s.reply(6)
      s.release()
      await s.checked(3)
      s.send(line(7, "ping"))
      await s.reply(7)
      await s.stage("serving", 2)
      s.send(call(8, "vault_status"))
      await s.reply(8)
    })
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
  }, 60_000)

  test("requests arriving during the hold-off stay in the pipe and are answered by the new image", async () => {
    const run = await againstOneProcess("plain", async (s) => {
      await verifiedUpdate(s)
      await s.hold("holdoff")
      s.send(line(4, "ping"))
      await s.stage("holdoff")
      s.send(line(5, "ping") + line(6, "tools/list") + call(7, "vault_status"))
      s.release()
      await Promise.all([s.reply(4), s.reply(5), s.reply(6), s.reply(7)])
    })
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
    expect(knewReplacement(run.host.received.find((m) => m.id === 7)!)).toBe(false)
  }, 60_000)

  test("a notifications/cancelled sent during the hold-off is read once the hold-off gives up, cancels the call, and the switch follows", async () => {
    const run = await againstOneProcess("plain", async (s) => {
      await verifiedUpdate(s)
      await pendingProposal(s)
      s.send(call(4, "vault_wait", { id: "pol_x", timeoutSeconds: 60 }))
      // The loop came round with the wait in flight: the hold-off starts.
      await s.stage("holdoff")
      s.send(cancelled(4))
      // The cancel waits in the pipe for at most the hold-off.
      await s.stage("holdoff-expired")
      s.send(line(5, "ping"))
      await s.reply(5)
      await s.stage("serving", 2)
      s.send(call(6, "vault_status"))
      await s.reply(6)
    })
    expect(run.host.received.some((m) => m.id === 4)).toBe(false)
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
    expect(knewReplacement(run.host.received.find((m) => m.id === 6)!)).toBe(false)
  }, 60_000)

  test("while the calls a hold-off gave up on are still in flight, later reads are not held off again; once they end, the switch follows", async () => {
    const run = await againstOneProcess("plain", async (s) => {
      await verifiedUpdate(s)
      await pendingProposal(s)
      s.send(call(4, "vault_wait", { id: "pol_x", timeoutSeconds: 60 }))
      await s.stage("holdoff")
      await s.stage("holdoff-expired")
      s.send(line(5, "ping"))
      await s.reply(5)
      if (s.switching) expect(await Promise.race([s.host.stage("holdoff-skipped").then(() => "not held off"), s.host.stage("holdoff", 2).then(() => "held off again")])).toBe("not held off")
      vault.overrides.set("GET /v1/policy/proposals/pol_x", () => Response.json(proposal("approved", APPROVED)))
      await s.reply(4)
      s.send(line(6, "ping"))
      await s.reply(6)
      await s.stage("serving", 2)
      s.send(call(7, "vault_status"))
      await s.reply(7)
    })
    expect(run.host.stderr.split("\n").filter((l) => l === "stage holdoff")).toHaveLength(2)
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
    expect(knewReplacement(run.host.received.find((m) => m.id === 7)!)).toBe(false)
  }, 60_000)

  test("a cancel of a call the hold-off gave up on, read in one write with another request, is held off for again: the switch follows without another read", async () => {
    const run = await againstOneProcess("plain", async (s) => {
      await verifiedUpdate(s)
      await pendingProposal(s)
      s.send(call(4, "vault_wait", { id: "pol_x", timeoutSeconds: 60 }))
      await s.stage("holdoff")
      await s.stage("holdoff-expired")
      s.send(cancelled(4) + line(5, "ping"))
      await s.reply(5)
      await s.stage("serving", 2)
      s.send(call(6, "vault_status"))
      await s.reply(6)
    })
    expect(run.host.received.some((m) => m.id === 4)).toBe(false)
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
    expect(knewReplacement(run.host.received.find((m) => m.id === 6)!)).toBe(false)
  }, 60_000)

  test("a vault_wait in flight when the replacement is ready is completed by the old image, then the switch follows", async () => {
    const run = await againstOneProcess("plain", async (s) => {
      await verifiedUpdate(s)
      await pendingProposal(s)
      s.send(call(4, "vault_wait", { id: "pol_x", timeoutSeconds: 60 }))
      await s.stage("holdoff")
      vault.overrides.set("GET /v1/policy/proposals/pol_x", () => Response.json(proposal("approved", APPROVED)))
      await s.reply(4)
      s.send(line(5, "ping"))
      await s.reply(5)
      await s.stage("serving", 2)
      s.send(call(6, "vault_status"))
      await s.reply(6)
    })
    expect(run.host.received.find((m) => m.id === 4)!.result).toMatchObject({ isError: false, structuredContent: { id: "pol_x", status: "approved", outcome: APPROVED } })
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
    expect(knewReplacement(run.host.received.find((m) => m.id === 6)!)).toBe(false)
  }, 60_000)

  test("a host that stops reading stdout and resumes loses and reorders nothing: requests arriving during the drain are answered, then the switch follows", async () => {
    const flood = Array.from({ length: 64 }, (_, i) => 100 + i)
    const run = await againstOneProcess("plain", async (s) => {
      await verifiedUpdate(s)
      s.host.pause()
      s.send(flood.map((id) => line(id, "tools/list")).join(""))
      // More than the pipe holds: the old image cannot hand every response
      // to the kernel, so the hold-off gives up.
      await s.stage("holdoff-expired")
      s.send(line(4, "ping") + call(5, "vault_status"))
      s.host.resume()
      await Promise.all([...flood, 4, 5].map((id) => s.reply(id)))
      await s.stage("serving", 2)
      s.send(call(6, "vault_status"))
      await s.reply(6)
    })
    const answers = run.host.received.filter((m) => typeof m.id === "number" && m.id >= 100)
    expect(answers.map((m) => m.id)).toEqual(flood)
    expect(JSON.stringify(answers).length).toBeGreaterThan(1_000_000)
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
    expect(knewReplacement(run.host.received.find((m) => m.id === 6)!)).toBe(false)
  }, 60_000)

  test("a slot refused for a replaced device before the switch is still refused after it, in the same words", async () => {
    const run = await againstOneProcess("plain", async (s) => {
      s.send(initialize(1))
      await s.reply(1)
      s.send(call(2, "vault_status"))
      await s.reply(2)
      await s.checked(1)
      // Another device enrolled in the latched slot: refused from now on.
      await vault.enrolSoftware(s.fixture.config)
      s.send(call(3, "vault_templates"))
      await s.reply(3)
      await s.checked(2)
      await s.update(s.image("new", UPDATE))
      s.send(call(4, "vault_status"))
      await s.reply(4)
      await s.checked(3)
      s.send(line(5, "ping"))
      await s.reply(5)
      await s.stage("serving", 2)
      s.send(call(6, "vault_templates"))
      await s.reply(6)
      s.send(call(7, "vault_status"))
      await s.reply(7)
    })
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
  }, 60_000)

  test("a slot enrolled after the switch is latched by the new image", async () => {
    const run = await againstOneProcess(
      "plain",
      async (s) => {
        await verifiedUpdate(s)
        s.send(line(4, "ping"))
        await s.reply(4)
        await s.stage("serving", 2)
        await vault.enrolSoftware(s.fixture.config)
        s.send(call(5, "vault_status"))
        await s.reply(5)
        // A replacement after the latch is refused: the new image latched it.
        await vault.enrolSoftware(s.fixture.config)
        s.send(call(6, "vault_status"))
        await s.reply(6)
      },
      { enrolled: false },
    )
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
  }, 60_000)

  test("a slot re-enrolled between the acceptance and the exec is refused by the new image, in the words one process uses", async () => {
    const run = await againstOneProcess("plain", async (s) => {
      await verifiedUpdate(s)
      await s.hold("accepted")
      s.send(line(4, "ping"))
      await s.stage("accepted")
      await vault.enrolSoftware(s.fixture.config)
      s.release()
      await s.reply(4)
      await s.stage("serving", 2)
      s.send(call(5, "vault_templates"))
      await s.reply(5)
      s.send(call(6, "vault_status"))
      await s.reply(6)
    })
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
  }, 60_000)

  test("a workspace renamed and recorded by another process between the acceptance and the exec is served by the new image under its new name, as one process serves it", async () => {
    const run = await againstOneProcess("plain", async (s) => {
      await verifiedUpdate(s)
      await s.hold("accepted")
      s.send(line(4, "ping"))
      await s.stage("accepted")
      vault.workspace = { ...MOCK_WORKSPACE, slug: "renamed-space", name: "Renamed Space" }
      // Async: the mock vault answers from this process.
      const recorder = Bun.spawn([process.execPath, MAIN, "workspace", "list", "--check", "--json"], { env: envFor(s.fixture, { MEHEN_SELF_EXECUTABLE: "" }), stdout: "pipe", stderr: "pipe", timeout: 30_000 })
      expect(await recorder.exited).toBe(0)
      s.release()
      await s.reply(4)
      await s.stage("serving", 2)
      s.send(call(5, "vault_status"))
      await s.reply(5)
      vault.workspace = { ...MOCK_WORKSPACE }
    })
    const status = run.host.received.find((m) => m.id === 5)!.result!.structuredContent as { workspaces: { state: string; workspace: { slug: string } }[] }
    expect(status.workspaces).toMatchObject([{ state: "active", workspace: { slug: "renamed-space" } }])
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
  }, 60_000)

  test("a pinned server keeps its pin across the switch: the new image serves the pinned workspace, as one process does", async () => {
    const run = await againstOneProcess(
      "plain",
      async (s) => {
        await verifiedUpdate(s)
        s.send(line(4, "ping"))
        await s.reply(4)
        await s.stage("serving", 2)
        s.send(call(5, "vault_status"))
        await s.reply(5)
        s.send(call(6, "vault_status", { workspace: "another-space" }))
        await s.reply(6)
      },
      { env: { MEHEN_WORKSPACE: "mock-space" } },
    )
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
    expect(run.host.received.find((m) => m.id === 6)!.result).toMatchObject({ isError: true, structuredContent: { error: "workspace_mismatch" } })
  }, 60_000)

  test("mehen mcp --workspace started through the command line switches with its arguments: the new image runs mcp --workspace again and keeps the pin, as one process does", async () => {
    const run = await againstOneProcess(
      "plain",
      async (s) => {
        await verifiedUpdate(s)
        s.send(line(4, "ping"))
        await s.reply(4)
        await s.stage("serving", 2)
        s.send(call(5, "vault_status"))
        await s.reply(5)
        s.send(call(6, "vault_status", { workspace: "another-space" }))
        await s.reply(6)
      },
      { args: ["--workspace", "mock-space"], env: { HANDOVER_TEST_ENTRY: "main" } },
    )
    expect(await imagesOf(run.fixture)).toEqual(["old mcp --workspace mock-space", "new mcp --accept-resume", "new mcp --workspace mock-space"])
    expect(run.host.received.find((m) => m.id === 6)!.result).toMatchObject({ isError: true, structuredContent: { error: "workspace_mismatch" } })
  }, 60_000)

  test("a host that negotiated MCP Apps keeps that negotiation across the switch: the new image lists the cards' tools and resources, as one process does", async () => {
    const apps = { protocolVersion: "2025-11-25", capabilities: { extensions: { [MCP_APPS_EXTENSION]: { mimeTypes: [CARD_MIME_TYPE] } } }, clientInfo: { name: "handover-test", version: "1" } }
    const run = await againstOneProcess("plain", async (s) => {
      s.send(line(1, "initialize", apps))
      await s.reply(1)
      s.send(call(2, "vault_status"))
      await s.reply(2)
      await s.checked(1)
      await s.update(s.image("new", UPDATE))
      s.send(call(3, "vault_templates"))
      await s.reply(3)
      await s.checked(2)
      s.send(line(4, "ping"))
      await s.reply(4)
      await s.stage("serving", 2)
      s.send(line(5, "tools/list") + line(6, "resources/list") + line(7, "resources/read", { uri: ASK_CARD_URI }))
      await Promise.all([s.reply(5), s.reply(6), s.reply(7)])
    })
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
    const reply = (id: number) => run.host.received.find((m) => m.id === id)!
    expect((reply(5).result!.tools as { _meta?: unknown }[]).some((t) => t._meta !== undefined)).toBe(true)
    expect(reply(6).result!.resources).toEqual(expect.arrayContaining([expect.objectContaining({ uri: ASK_CARD_URI })]))
    expect(reply(7).error).toBeUndefined()
  }, 60_000)

  test("a pin's slug reused by another workspace before the switch means no switch: the old image keeps its pin and asks for a restart, as one process does", async () => {
    const run = await againstOneProcess(
      "restart",
      async (s) => {
        s.send(initialize(1))
        await s.reply(1)
        s.send(call(2, "vault_status"))
        await s.reply(2)
        await s.checked(1)
        // The pinned workspace renamed, as a status run records it, and
        // another workspace enrolled under the slug it had.
        const slot = join(vault.slotDir(s.fixture.config), "config.json")
        const pinned = JSON.parse(await readFile(slot, "utf8")) as Record<string, unknown>
        await writeFile(slot, JSON.stringify({ ...pinned, workspaceSlug: "renamed-space", workspaceName: "Renamed Space" }), { mode: 0o600 })
        await vault.enrolSoftware(s.fixture.config, { config: { tenant: "tn_reusedslug01", workspaceSlug: "mock-space", workspaceName: "Reused Space" } })
        await s.update(s.image("new", UPDATE))
        s.send(call(3, "vault_templates"))
        await s.reply(3)
        await s.checked(2)
        s.send(line(4, "ping"))
        await s.reply(4)
        await s.logged("mcp handover cancelled")
        s.send(call(5, "vault_status"))
        await s.reply(5)
      },
      { env: { MEHEN_WORKSPACE: "mock-space" } },
    )
    expect(run.host.received.flatMap(restartNotices)).toEqual([RESTART_TEXT])
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume"])
    const status = run.host.received.find((m) => m.id === 5)!.result!.structuredContent as { workspaces: { workspace: { id: string } }[] }
    expect(status.workspaces.map((w) => w.workspace.id)).toEqual([MOCK_WORKSPACE.id])
  }, 60_000)

  test("a checkout manifest changed before the switch means no switch: the old image keeps its startup manifest and asks for a restart, as one process does", async () => {
    const run = await againstOneProcess(
      "restart",
      async (s) => {
        await verifiedUpdate(s)
        await s.hold("holdoff")
        s.send(line(4, "ping"))
        await s.stage("holdoff")
        await writeFile(join(checkoutOf(s.fixture), "mehen.toml"), `project = "prj_handover"\n`)
        s.release()
        await s.reply(4)
        await s.logged("mcp handover cancelled")
        s.send(call(5, "vault_templates"))
        await s.reply(5)
      },
      { checkout: `project = "prj_handover"\nworkspace = "${MOCK_WORKSPACE.id}"\n` },
    )
    expect(run.host.received.flatMap(restartNotices)).toEqual([RESTART_TEXT])
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume"])
  }, 60_000)

  test("a slot moved away between the acceptance and the exec is refused by the new image, in the words one process uses", async () => {
    const run = await againstOneProcess("plain", async (s) => {
      await verifiedUpdate(s)
      await s.hold("accepted")
      s.send(line(4, "ping"))
      await s.stage("accepted")
      const slot = vault.slotDir(s.fixture.config)
      await rename(slot, `${slot}-moved`)
      s.release()
      await s.reply(4)
      await s.stage("serving", 2)
      s.send(call(5, "vault_templates"))
      await s.reply(5)
      s.send(call(6, "vault_status"))
      await s.reply(6)
    })
    expect(await imagesOf(run.fixture)).toEqual(["old mcp", "new mcp --accept-resume", "new mcp"])
  }, 60_000)
})

describe("the resume payload", () => {
  const handshake = { protocolVersion: "2025-11-25", clientInfo: { name: "t", version: "1" } }

  async function payloadFor(serverEnv: Record<string, string>): Promise<McpResumePayload> {
    const server = await startServer(serverEnv, dir)
    return { v: 1, ...handshake, initialized: true, startedAt: "2026-10-28T12:00:00.000Z", toolsHash: "x", latch: latchState(server), manifest: await signedManifest(UPDATE, new Uint8Array([1])) }
  }

  test("round-trips, refuses another v, and is bounded; an image whose own handover is off accepts none", async () => {
    await vault.enrolSoftware(config)
    const e = env()
    const payload = await payloadFor(e)
    expect(parseResume(encodeResume(payload))).toEqual(payload)
    expect(() => parseResume(JSON.stringify({ ...payload, v: 2 }))).toThrow("not one this build accepts")
    await handoverSetting(fixture, false)
    expect(await acceptResume(e, dir, encodeResume(payload))).toBe(1)
    await handoverSetting(fixture, true)
    expect(await acceptResume({ ...e, MEHEN_NO_AUTO_UPDATE: "1" }, dir, encodeResume(payload))).toBe(1)
    expect(await acceptResume(e, dir, JSON.stringify({ ...payload, v: 2 }))).toBe(1)
    expect(await acceptResume(e, dir, encodeResume(payload))).toBe(0)
    const slots = Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`/s/${i}`, { refused: { reason: "r", since: "t" } }]))
    expect(() => encodeResume({ ...payload, latch: { ...payload.latch, slots } })).toThrow()
    expect(() => parseResume("x".repeat(RESUME_MAX_BYTES + 1))).toThrow(`over ${RESUME_MAX_BYTES} bytes`)
  })

  test("the acceptance check reads at most one byte past the payload's bound from stdin, so one over it is refused without reading the rest", async () => {
    const chunk = new Uint8Array(16 * 1024).fill(0x78)
    let offered = 0
    const stdin = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (offered >= 100 * chunk.length) return controller.close()
        offered += chunk.length
        controller.enqueue(chunk)
      },
    })
    const line = await readResumeLine(stdin)
    expect(line.length).toBe(RESUME_MAX_BYTES + 1)
    expect(offered).toBeLessThanOrEqual(RESUME_MAX_BYTES + 1 + 2 * chunk.length)
    expect(() => parseResume(line)).toThrow(`over ${RESUME_MAX_BYTES} bytes`)
    const payload = `${JSON.stringify({ v: 1 })}\n`
    expect(await readResumeLine(new Response(payload).body!)).toBe(payload)
  })

  test("mehen mcp --accept-resume refuses a payload over its bound while its stdin is still open: the command reads no further than one byte past the bound", async () => {
    const proc = Bun.spawn([process.execPath, MAIN, "mcp", "--accept-resume"], { cwd: dir, env: env(), stdin: "pipe", stdout: "ignore", stderr: "pipe" })
    proc.stdin.write(new Uint8Array(RESUME_MAX_BYTES + 2).fill(0x78))
    await proc.stdin.flush()
    const [code, stderr] = await Promise.all([proc.exited, new Response(proc.stderr).text()])
    proc.stdin.end()
    expect(code).toBe(1)
    expect(stderr).toContain("over 65536 bytes")
  }, 60_000)

  test("the acceptance check does not judge the install directory: it runs from a private copy, and the old image judged the real one", async () => {
    await vault.enrolSoftware(config)
    const payload = await payloadFor(env())
    await chmod(dir, 0o500)
    try {
      expect(await acceptResume(env(), dir, encodeResume(payload))).toBe(0)
    } finally {
      await chmod(dir, 0o700)
    }
  })

  test("carries whether the host negotiated MCP Apps, and a payload from before the cards still parses", async () => {
    await vault.enrolSoftware(config)
    const payload = await payloadFor(env())
    expect(parseResume(encodeResume({ ...payload, apps: true })).apps).toBe(true)
    expect(parseResume(encodeResume(payload))).toEqual(payload)
    expect("apps" in parseResume(encodeResume(payload))).toBe(false)
    expect(() => parseResume(JSON.stringify({ ...payload, apps: "yes" }))).toThrow("not one this build accepts")
  })

  test("a slot re-enrolled under the same slug between preflight and exec is refused by the new image; a refused slot stays refused", async () => {
    const before = await vault.enrolSoftware(config)
    const e = env()
    const payload = await payloadFor(e)
    const slot = Object.keys(payload.latch.slots)[0]!
    expect(payload.latch.slots[slot]).toEqual({ latched: { vault: vault.url, tenant: expect.any(String), device: before } })
    // Re-enrolled in the same slot: another device.
    const after = await vault.enrolSoftware(config)
    expect(after).not.toBe(before)
    const server = await startServer(e, dir)
    await resumeInto(server, encodeResume(payload))
    expect(latchState(server).slots[slot]).toMatchObject({ refused: { reason: expect.stringContaining(`changed to ${after}`) } })
    const refused = { ...payload, latch: { ...payload.latch, slots: { [slot]: { refused: { reason: "earlier", since: "2026-10-28T12:00:00.000Z" } } } } }
    const again = await startServer(e, dir)
    await resumeInto(again, encodeResume(refused))
    expect(latchState(again).slots[slot]).toEqual({ refused: { reason: "earlier", since: "2026-10-28T12:00:00.000Z" } })
  })

  test("`seen` names slots and authorises nothing: one that disagrees with its latch, sits in another directory, names no latched slot or carries more than a config's fields is refused, and a refused slot stays refused whatever it claims", async () => {
    await vault.enrolSoftware(config)
    const e = env()
    const payload = await payloadFor(e)
    const slot = Object.keys(payload.latch.slots)[0]!
    const shown = payload.latch.seen![slot]!
    const other = { ...shown, config: { ...shown.config, device: "dev_other0000001" } }
    const withSeen = (seen: unknown, slots: unknown = payload.latch.slots) => JSON.stringify({ ...payload, latch: { ...payload.latch, slots, seen } })
    const refusal = (why: string) => `The latch state handed to this server does not match what it resolves itself: ${why}.`
    const cases: [unknown, string][] = [
      [{ [slot]: other }, refusal("what it saw in a slot is not the enrolment it latched")],
      [{ [slot]: { ...shown, dir: join(dir, "elsewhere") } }, refusal("what it saw for a slot is in another directory")],
      [{ [`${slot}-x`]: shown }, refusal("it names a slot without a latch for it")],
      [{ [slot]: { ...shown, state: "active" } }, "the resume payload is not one this build accepts"],
      [{ [slot]: { ...shown, config: { ...shown.config, key: "not carried" } } }, refusal("it is not a latch state")],
    ]
    for (const [seen, reason] of cases) expect(await acceptanceRefusal(e, dir, withSeen(seen))).toBe(reason)
    const refused = { [slot]: { refused: { reason: "earlier", since: "2026-10-28T12:00:00.000Z" } } }
    const server = await startServer(e, dir)
    await resumeInto(server, withSeen({ [slot]: other }, refused))
    expect(latchState(server).slots).toEqual(refused)
    await expect(mcpDeps(e, server, () => {}).session()).rejects.toMatchObject({ code: "workspace_mismatch" })
  })

  test("a payload from before `seen` still parses and restores; `seen` carries only a config's identity and display fields", async () => {
    const device = await vault.enrolSoftware(config)
    const e = env()
    const payload = await payloadFor(e)
    const { seen, ...before } = payload.latch
    const server = await startServer(e, dir)
    await resumeInto(server, encodeResume({ ...payload, latch: before }))
    expect(latchState(server).slots).toEqual(payload.latch.slots)
    expect((await mcpDeps(e, server, () => {}).session()).config.device).toBe(device)
    // A field a config file holds beyond those stays behind.
    const slot = Object.keys(payload.latch.slots)[0]!
    const onDisk = JSON.parse(await readFile(join(slot, "config.json"), "utf8")) as Record<string, unknown>
    await writeFile(join(slot, "config.json"), JSON.stringify({ ...onDisk, extra: "stays behind" }), { mode: 0o600 })
    const carried = (await payloadFor(e)).latch.seen![slot]!.config
    expect(carried).toEqual(seen![slot]!.config)
    expect(Object.keys(carried).every((k) => ["vault", "tenant", "device", "backend", "fingerprint", "name", "workspaceSlug", "workspaceName", "owner"].includes(k))).toBe(true)
  })

  test("the acceptance check gives each refusal as a reason that names no path and carries nothing of the payload, and refuses a payload built for another release", async () => {
    await vault.enrolSoftware(config)
    const e = env()
    const payload = await payloadFor(e)
    const refusal = (why: string) => `The latch state handed to this server does not match what it resolves itself: ${why}.`
    await handoverSetting(fixture, false)
    expect(await acceptanceRefusal(e, dir, encodeResume(payload))).toBe("the new image does not take handovers: mcpHandover is false in settings.json")
    await handoverSetting(fixture, true)
    const reasons = [
      await acceptanceRefusal(e, dir, encodeResume({ ...payload, latch: { ...payload.latch, home: "/elsewhere" } })),
      await acceptanceRefusal({ ...e, MEHEN_WORKSPACE: "mock-space" }, dir, encodeResume(payload)),
      await acceptanceRefusal({ ...e, MEHEN_WORKSPACES: "no-such-space" }, dir, encodeResume(payload)),
      await acceptanceRefusal({ ...e, MEHEN_WORKSPACES: "" }, dir, encodeResume(payload)),
      await acceptanceRefusal(e, dir, "not a payload"),
      await acceptanceRefusal(e, dir, encodeResume({ ...payload, manifest: await signedManifest("99.0.0", new Uint8Array([1])) })),
    ]
    expect(reasons).toEqual([
      refusal("it names another root"),
      refusal("its pin resolved to another workspace"),
      refusal("its MEHEN_WORKSPACES entries resolved to other vaults or workspaces"),
      "the new image would not start a server here (workspace_not_allowed)",
      "the resume payload is not JSON",
      `the payload was built for another release than this image, ${VERSION}`,
    ])
    for (const reason of reasons) expect(reason).not.toContain(dir)
    expect(await acceptanceRefusal(e, dir, encodeResume(payload))).toBeNull()
  })

  test("the acceptance check refuses when this image would migrate the root first: the image after the exec would enter it before serving", async () => {
    await vault.enrolSoftware(config)
    const payload = await payloadFor(env())
    await writeFile(migrationJournalPath(config), "{}", { mode: 0o600 })
    expect(await acceptanceRefusal(env(), dir, encodeResume(payload))).toBe("this image would migrate the root before serving")
    await rm(migrationJournalPath(config))
    expect(await acceptanceRefusal(env(), dir, encodeResume(payload))).toBeNull()
  })

  test("the old image logs the acceptance check's reason, read from a bounded stderr, and nothing else it wrote", async () => {
    await vault.enrolSoftware(config)
    const e = env()
    const server = await startServer(e, dir)
    const executables = new PrivateExecutables(fixture.tmp)
    const attempt = async (accept: string) => {
      const record = await replaceWith(image("new", UPDATE, { accept }))
      return prepareHandover({ env: e, server, replacement: await verifiedNow(record), binary, executables, args: [], handshake, startedAt: "t", toolsHash: "x" }).then(() => "accepted", (error: Error) => error.message)
    }
    const line = JSON.stringify({ msg: "mcp resume refused", reason: "a reason" })
    expect(await attempt(`echo 'noise' >&2; echo '${line}' >&2; exit 1`)).toBe("the new image refused the resume payload (exit 1): a reason")
    // Past the bound the reason is not read; the rest is drained, so the check still ends.
    expect(await attempt(`head -c ${ACCEPT_STDERR_MAX_BYTES * 64} /dev/zero | tr '\\0' x >&2; echo '${line}' >&2; exit 1`)).toBe("the new image refused the resume payload (exit 1)")
    executables.clear()
  })

  test("prepareHandover checks the bytes before anything runs: another binary at the path, or the same bytes in another file, cancels the switch and never runs", async () => {
    await vault.enrolSoftware(config)
    const e = env()
    const bytes = image("new", UPDATE, { accept: "exit 0" })
    const record = await replaceWith(bytes)
    const replacement = await verifiedNow(record)
    const server = await startServer(e, dir)
    const executables = new PrivateExecutables(fixture.tmp)
    // Another binary lands after the verification, then the verified bytes
    // again as another file. Linux may give that file the freed inode
    // number, so each landed file is set to another mtime than the verified
    // one, never left to the timestamp granularity to tell apart.
    for (const landed of [image("other", "99.0.1", { accept: "exit 0" }), bytes]) {
      await land(fixture, landed)
      const earlier = (replacement.identity.mtimeMs - 60_000) / 1000
      await utimes(binary, earlier, earlier)
      await expect(prepareHandover({ env: e, server, replacement, binary, executables, args: [], handshake, startedAt: "t", toolsHash: "x" })).rejects.toThrow("the executable changed after it was verified")
    }
    expect(await images()).toBe("")
    executables.clear()
  })

  test("the last look before the exec refuses a write in place after the hash: the path's file must keep the held file's size and mtime, not only its device and inode", async () => {
    const bytes = image("new", UPDATE, { accept: "exit 0" })
    // Each is given the verified mtime, so the second sets another one whatever the timestamp granularity.
    const writes: ((verifiedMtimeMs: number) => void)[] = [
      () => appendFileSync(binary, "\n"),
      (verifiedMtimeMs) => {
        const fd = openSync(binary, "r+")
        writeSync(fd, new TextEncoder().encode("#"), 0, 1, bytes.length - 1)
        closeSync(fd)
        const earlier = (verifiedMtimeMs - 60_000) / 1000
        utimesSync(binary, earlier, earlier)
      },
    ]
    for (const write of writes) {
      const replacement = await verifiedNow(await replaceWith(bytes))
      expect(() => assertStillVerified(binary, replacement, () => write(replacement.identity.mtimeMs))).toThrow("the executable changed after it was verified")
    }
    const replacement = await verifiedNow(await replaceWith(bytes))
    expect(() => assertStillVerified(binary, replacement)).not.toThrow()
  })

  test("prepareHandover runs the acceptance from a private copy of the verified bytes, never the installation path, and removes the copy", async () => {
    await vault.enrolSoftware(config)
    const e = env()
    const accepted = join(dir, "accepted")
    const record = await replaceWith(image("new", UPDATE, { accept: `printf '%s\\n' "$0" >> '${accepted}'; exit 0` }))
    const server = await startServer(e, dir)
    const temp = fixture.tmp
    const executables = new PrivateExecutables(temp)
    const exec = await prepareHandover({ env: e, server, replacement: await verifiedNow(record), binary, executables, args: ["--workspace", "x"], handshake, startedAt: "t", toolsHash: "x" })
    const ran = (await readFile(accepted, "utf8")).trim()
    expect(ran).not.toBe(binary)
    expect(ran.startsWith(`${temp}/mehen-mcp-`)).toBe(true)
    expect(existsSync(ran)).toBe(false)
    expect(await images()).toBe("new mcp --accept-resume\n")
    expect(exec).toMatchObject({ file: binary, argv: [binary, "mcp", "--workspace", "x"] })
    executables.clear()
  })

  test("prepareHandover hands the new image the resolved admitted set, the latch table and the retained signed manifest, and the exec the same line", async () => {
    const device = await vault.enrolSoftware(config)
    const e = env({ MEHEN_WORKSPACES: "mock-space" })
    const handed = join(dir, "handed")
    const record = await replaceWith(image("new", UPDATE, { accept: `cat > '${handed}'; exit 0` }))
    const server = await startServer(e, dir)
    const executables = new PrivateExecutables(fixture.tmp)
    const exec = await prepareHandover({ env: e, server, replacement: await verifiedNow(record), binary, executables, args: [], handshake, startedAt: "t", toolsHash: "x" })
    const sent = (await readFile(handed, "utf8")).trim()
    const payload = parseResume(sent)
    expect(payload.manifest).toEqual(record.manifest!)
    expect(payload.latch).toEqual(latchState(server))
    expect(payload.latch.allowed).toEqual([{ entry: "mock-space", origin: vault.url, workspace: expect.any(String) }])
    expect(Object.values(payload.latch.slots)).toEqual([{ latched: { vault: vault.url, tenant: payload.latch.allowed![0]!.workspace!, device } }])
    expect(exec.env.MEHEN_MCP_RESUME).toBe(sent)
    executables.clear()
  })
})
