import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { chmod, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, utimes, writeFile } from "node:fs/promises"
import { chmodSync, existsSync, mkdtempSync, realpathSync, statSync } from "node:fs"
import { tmpdir } from "node:os"
import { basename, dirname, join } from "node:path"
import { base64UrlEncode } from "@mehen/protocol/bytes"
import { canonicalJson } from "@mehen/protocol/canonical-json"
import { type ReleaseKey, type SignedManifest, manifestSigningBytes } from "@mehen/protocol/release-manifest"
import { type InstalledRecord, type McpHandover, bootId, freshInstallState, installation, writeInstallState } from "../install-state.ts"
import { sha256 } from "../release-client.ts"
import { scheduleBackgroundUpdate, updateTarget } from "../update.ts"
import { MockVault } from "../testing/mock-vault.ts"
import { MAIN } from "../testing/run-mehen.ts"
import { VERSION } from "../version.ts"
import { IGNORE_MS, NOTICE_INTERVAL_MS, PrivateExecutables, SelfWatch, type VerifyHooks, probeVersion, restartText, sweepPrivateLeftovers } from "./self-watch.ts"

// A test release key, trusted through MEHEN_RELEASE_KEYS over a loopback
// download base; never a real release key.
let releaseKey: ReleaseKey
let signer: CryptoKey
beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey)
  releaseKey = { id: "rk-test-selfwatch", alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y! }, presence: "none", created: "2026-10-28T12:00:00.000Z" }
  signer = pair.privateKey
})

async function signedManifest(version: string, bytes: Uint8Array, key: CryptoKey = signer): Promise<SignedManifest> {
  const gz = Bun.gzipSync(new Uint8Array(bytes))
  const files = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"].map((t) => ({ name: `mehen-${t}`, os: t.split("-")[0]!, arch: t.split("-")[1]!, url: `https://mehen.dev/dl/v${version}/mehen-${t}.gz`, sha256: sha256(bytes), size: bytes.length, gzSha256: sha256(gz), gzSize: gz.length }))
  const manifest = { version, commit: "abc1234", builtAt: "2026-10-28T12:00:00Z", files }
  const signature = base64UrlEncode(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, manifestSigningBytes(manifest)))
  return { ...manifest, signatures: [{ keyId: releaseKey.id, alg: "ES256", signature }] }
}

// A replacement binary: a shell script that appends to `ran` whenever it is
// executed at all, then answers `version --json` as a release would.
function script(dir: string, version: string, build = "release"): Uint8Array<ArrayBuffer> {
  const info = JSON.stringify({ version, commit: "abc1234", build, helper: process.platform === "darwin" ? "embedded" : "none" })
  return new TextEncoder().encode(`#!/bin/sh\nprintf '%s\\n' "$*" >> '${dir}/ran'\nif [ "$1 $2" = "version --json" ]; then printf '%s\\n' '${info}'; exit 0; fi\nexit 2\n`)
}

let dir: string
let binary: string
let logs: string[]
let probes: string[]

beforeEach(async () => {
  dir = realpathSync(await mkdtemp(join(tmpdir(), "mehen-selfwatch-")))
  await chmod(dir, 0o700)
  binary = join(dir, "mehen")
  await writeFile(binary, "#!/bin/sh\n# the running image\nexit 0\n", { mode: 0o755 })
  logs = []
  probes = []
})
afterEach(async () => {
  await rm(dir, { recursive: true, force: true })
})

const env = (extra: Record<string, string> = {}) => ({ HOME: dir, PATH: process.env.PATH ?? "", MEHEN_HOME: join(dir, "home"), MEHEN_SELF_EXECUTABLE: binary, MEHEN_DL_BASE: "http://127.0.0.1:9/dl", MEHEN_RELEASE_KEYS: JSON.stringify([releaseKey]), CI: "", ...extra })
// What a spawned server runs with: its root is MEHEN_CONFIG_DIR, so no MEHEN_HOME.
const serverHomes: string[] = []
const serverBase = (extra: Record<string, string> = {}) => {
  const { MEHEN_HOME: _home, ...rest } = env()
  const home = privateDir("mehen-selfwatch-home-")
  serverHomes.push(home)
  return { ...rest, HOME: home, MEHEN_MCP_TOOLSETS: "all", ...extra }
}
afterAll(async () => {
  for (const home of serverHomes.splice(0)) await rm(home, { recursive: true, force: true })
})
function privateDir(prefix: string): string {
  const path = realpathSync(mkdtempSync(join(tmpdir(), prefix)))
  chmodSync(path, 0o700)
  return path
}
const ran = () => readFile(join(dir, "ran"), "utf8").catch(() => null)
// settings.json under `root` switching the handover off, for the restart path.
async function handoverOff(root: string): Promise<void> {
  await mkdir(root, { recursive: true, mode: 0o700 })
  await writeFile(join(root, "settings.json"), '{ "mcpHandover": false }\n')
}

// Replaces the binary by rename (a new inode), as the updater does.
async function replaceWith(bytes: Uint8Array): Promise<void> {
  await writeFile(`${binary}.new`, bytes, { mode: 0o755 })
  await rename(`${binary}.new`, binary)
}

async function record(bytes: Uint8Array, overrides: Partial<InstalledRecord> = {}, options: { receipt?: boolean; pending?: boolean } = {}): Promise<InstalledRecord> {
  const version = overrides.version ?? "99.0.0"
  const manifest = overrides.manifest === undefined ? await signedManifest(version, bytes) : overrides.manifest
  const installed: InstalledRecord = { version, commit: "abc1234", sha256: sha256(bytes), size: bytes.length, at: "2026-10-28T12:00:00.000Z", by: "auto", keyId: releaseKey.id, manifestSha256: manifest ? sha256(new TextEncoder().encode(canonicalJson(manifest))) : null, manifest, ...overrides }
  const state = freshInstallState()
  state.installed = installed
  if (options.pending) state.pending = { target: installed, previousSha256: null, steps: ["receipt", "skills"], since: "2026-10-28T12:00:00.000Z" }
  await writeInstallState(installation(binary), state)
  if (options.receipt !== false) await writeFile(join(dir, ".mehen.sha256"), `${installed.sha256}\n`)
  return installed
}

// Every probe runs a private copy, never the installation path: a file of
// mode 0500 in a directory of mode 0700, gone once the probe returns.
let snapshots: { path: string; mode: number; dirMode: number }[] = []
const watches: SelfWatch[] = []
afterEach(() => {
  for (const w of watches.splice(0)) w.stop()
  snapshots = []
})

async function watch(options: { now?: () => number; extra?: Record<string, string>; schedule?: () => Promise<unknown>; busy?: () => boolean; beforeProbe?: (path: string) => Promise<void>; hooks?: VerifyHooks; probeLimits?: { timeoutMs: number; maxBytes: number }; handover?: McpHandover } = {}): Promise<SelfWatch> {
  const e = env(options.extra)
  const real = probeVersion(e, options.probeLimits)
  const w = await SelfWatch.create({
    env: e,
    binary,
    now: options.now,
    log: (line) => logs.push(line),
    probe: async (path) => {
      probes.push(path)
      snapshots.push({ path, mode: statSync(path).mode & 0o777, dirMode: statSync(dirname(path)).mode & 0o777 })
      await options.beforeProbe?.(path)
      return real(path)
    },
    ...(options.schedule ? { schedule: options.schedule } : {}),
    ...(options.busy ? { busy: options.busy } : {}),
    ...(options.hooks ? { hooks: options.hooks } : {}),
    ...(options.handover ? { handover: options.handover } : {}),
  })
  watches.push(w)
  return w
}

async function expectOnePrivateProbe(): Promise<void> {
  expect(probes).toHaveLength(1)
  expect(probes[0]).not.toBe(binary)
  expect(snapshots[0]).toMatchObject({ mode: 0o500, dirMode: 0o700 })
  expect(existsSync(probes[0]!)).toBe(false)
}

describe("the self-watch's verification", () => {
  test("with the handover on a verified replacement is to be switched to, not announced; once that switch is refused it is a restart with why", async () => {
    const w = await watch({ handover: { handover: "on" } })
    const bytes = script(dir, "99.0.0")
    await replaceWith(bytes)
    await record(bytes)
    await w.check()
    const verified = w.verified()!
    expect(w.cliMcp()).toEqual({ running: VERSION, installed: "99.0.0", action: "switch" })
    expect(w.switchable()).toBe(verified)
    expect(w.notice()).toBeNull()
    w.switchRefused(verified)
    expect(w.cliMcp()).toEqual({ running: VERSION, installed: "99.0.0", action: "restart", reason: "the switch to 99.0.0 was refused" })
    expect(w.switchable()).toBeNull()
    expect(w.notice()).toBe(`mehen 99.0.0 is installed on this machine; this server still runs ${VERSION}. Restart the agent to use the new version.`)
  })

  test("by default the handover is on; settings.json with mcpHandover false switches it off, and a verified replacement is then a restart naming that setting", async () => {
    expect((await watch()).handover).toEqual({ handover: "on" })
    await handoverOff(join(dir, "home"))
    const w = await watch()
    expect(w.handover).toEqual({ handover: "off", reason: "mcpHandover is false in settings.json" })
    const bytes = script(dir, "99.0.0")
    await replaceWith(bytes)
    await record(bytes)
    await w.check()
    expect(w.cliMcp()).toEqual({ running: VERSION, installed: "99.0.0", action: "restart", reason: "mcpHandover is false in settings.json" })
    expect(w.switchable()).toBeNull()
  })

  test("an unchanged binary is nothing to report and nothing is read or run", async () => {
    const w = await watch()
    await w.check()
    expect(w.cliMcp()).toBeNull()
    expect(w.notice()).toBeNull()
    expect(probes).toEqual([])
    expect(logs).toEqual([])
  })

  test("a hand copy no record describes is ignored with one stderr line and never executed", async () => {
    let now = 1_000_000
    const w = await watch({ now: () => now })
    await replaceWith(script(dir, "99.0.0"))
    await w.check()
    expect(w.cliMcp()).toBeNull()
    expect(probes).toEqual([])
    expect(await ran()).toBeNull()
    expect(logs).toHaveLength(1)
    expect(JSON.parse(logs[0]!)).toMatchObject({ msg: "mcp self-watch ignored a replaced binary", path: binary, reason: "no update record describes it" })
    // Ignored for an hour, then looked at again, and logged once only.
    await w.check()
    now += IGNORE_MS
    await w.check()
    expect(logs).toHaveLength(1)
    expect(probes).toEqual([])
    expect(await ran()).toBeNull()
  })

  for (const [name, overrides] of [
    ["a by: \"install\" record (reconcile after a hand copy or the shell installer)", { by: "install" as const, keyId: null, manifest: null, manifestSha256: null }],
    ["a keyId: null record", { keyId: null }],
    ["a by: \"install\" record that still names a key", { by: "install" as const }],
  ] as const) {
    test(`${name} is ignored with one stderr line and spawns nothing`, async () => {
      const w = await watch()
      const bytes = script(dir, "99.0.0")
      await replaceWith(bytes)
      await record(bytes, overrides)
      await w.check()
      expect(w.cliMcp()).toBeNull()
      expect(probes).toEqual([])
      expect(await ran()).toBeNull()
      expect(logs.map((l) => JSON.parse(l).reason)).toEqual(["its record was not written by the signed updater (a hand copy or the shell installer)"])
    })
  }

  test("bytes the signed record does not name are ignored before any probe", async () => {
    const w = await watch()
    await record(script(dir, "99.0.0"))
    await replaceWith(script(dir, "99.0.1"))
    await w.check()
    expect(w.cliMcp()).toBeNull()
    expect(probes).toEqual([])
    expect(logs.map((l) => JSON.parse(l).reason)).toEqual(["its bytes are not the ones the signed update record names"])
  })

  test("a manifest signed by an untrusted key is ignored before any probe", async () => {
    const other = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
    const w = await watch()
    const bytes = script(dir, "99.0.0")
    await replaceWith(bytes)
    await record(bytes, { manifest: await signedManifest("99.0.0", bytes, other.privateKey) })
    await w.check()
    expect(w.cliMcp()).toBeNull()
    expect(probes).toEqual([])
    expect(JSON.parse(logs[0]!).reason).toMatch(/^its retained release manifest does not verify/)
  })

  test("a lower or equal version and a missing receipt are ignored before any probe", async () => {
    const w = await watch()
    const bytes = script(dir, VERSION)
    await replaceWith(bytes)
    await record(bytes, { version: VERSION })
    await w.check()
    expect(JSON.parse(logs[0]!).reason).toBe(`${VERSION} is not newer than ${VERSION}`)
    const next = script(dir, "99.0.0")
    await replaceWith(next)
    await record(next, {}, { receipt: false })
    await w.check()
    expect(JSON.parse(logs[1]!).reason).toBe("its receipt does not match it")
    expect(probes).toEqual([])
    expect(await ran()).toBeNull()
  })

  test("verified bytes are probed once; a dev build or another version is then ignored", async () => {
    const w = await watch()
    const dev = script(dir, "99.0.0", "dev")
    await replaceWith(dev)
    await record(dev)
    await w.check()
    await expectOnePrivateProbe()
    expect(w.cliMcp()).toBeNull()
    expect(JSON.parse(logs[0]!).reason).toBe("it is not a release build")
    const liar = script(dir, "98.0.0")
    await replaceWith(liar)
    await record(liar, { version: "99.0.0", manifest: await signedManifest("99.0.0", liar) })
    await w.check()
    expect(JSON.parse(logs[1]!).reason).toBe("it reports 98.0.0, not the recorded 99.0.0")
  })

  test("an update between its rename and its record is looked at again, not ignored", async () => {
    const w = await watch()
    const bytes = script(dir, "99.0.0")
    await replaceWith(bytes)
    // The journal names the target; the record and receipt are not written yet.
    const state = freshInstallState()
    const target = { ...(await record(bytes)) }
    state.pending = { target, previousSha256: null, steps: ["record", "receipt"], since: "2026-10-28T12:00:00.000Z" }
    await writeInstallState(installation(binary), state)
    await rm(join(dir, ".mehen.sha256"))
    await w.check()
    expect(w.cliMcp()).toBeNull()
    expect(logs).toEqual([])
    await record(bytes)
    await w.check()
    expect(w.cliMcp()).toEqual({ running: VERSION, installed: "99.0.0", action: "switch" })
  })

  test("a verified newer binary: cli.mcp, and the restart text once then hourly", async () => {
    let now = 5_000_000
    await handoverOff(join(dir, "home"))
    const w = await watch({ now: () => now })
    const bytes = script(dir, "99.0.0")
    await replaceWith(bytes)
    await record(bytes)
    await w.check()
    await expectOnePrivateProbe()
    expect(await ran()).toBe("version --json\n")
    expect(logs).toEqual([])
    expect(w.cliMcp()).toEqual({ running: VERSION, installed: "99.0.0", action: "restart", reason: "mcpHandover is false in settings.json" })
    const text = `mehen 99.0.0 is installed on this machine; this server still runs ${VERSION}. Restart the agent to use the new version.`
    expect(restartText({ running: VERSION, installed: "99.0.0" })).toBe(text)
    expect(w.notice()).toBe(text)
    expect(w.notice()).toBeNull()
    now += NOTICE_INTERVAL_MS - 1
    expect(w.notice()).toBeNull()
    now += 1
    expect(w.notice()).toBe(text)
    // Looking again at the same file neither probes nor re-announces.
    await w.check()
    expect(probes).toHaveLength(1)
    expect(w.notice()).toBeNull()
  })

  for (const [name, setup, reason] of [
    ["MEHEN_NO_AUTO_UPDATE=1", async () => ({ MEHEN_NO_AUTO_UPDATE: "1" }), "MEHEN_NO_AUTO_UPDATE is set"],
    ["settings.autoUpdate false", async () => {
      await mkdir(join(dir, "home"), { recursive: true, mode: 0o700 })
      await writeFile(join(dir, "home", "settings.json"), '{ "autoUpdate": false, "mcpHandover": true }\n')
      return {}
    }, "autoUpdate is false in settings.json"],
  ] as const) {
    test(`${name} keeps the restart text once then hourly and cli.mcp, and switches off the handover and the idle launch`, async () => {
      let now = 7_000_000
      const extra: Record<string, string> = await setup()
      const w = await watch({ extra, now: () => now })
      const bytes = script(dir, "99.0.0")
      await replaceWith(bytes)
      await record(bytes)
      await w.check()
      expect(w.cliMcp()).toEqual({ running: VERSION, installed: "99.0.0", action: "restart", reason })
      const text = `mehen 99.0.0 is installed on this machine; this server still runs ${VERSION}. Restart the agent to use the new version.`
      expect(w.notice()).toBe(text)
      expect(w.notice()).toBeNull()
      now += NOTICE_INTERVAL_MS
      expect(w.notice()).toBe(text)
      expect(w.switchable()).toBeNull()
      // The real idle schedule follows U2's opt-out: nothing launches.
      await w.tick()
      await Bun.sleep(CHILD_SETTLE_MS)
      expect((await ran()) ?? "").not.toContain("update --background")
      const quietWatch = await watch({ extra })
      await replaceWith(script(dir, "99.0.2"))
      await quietWatch.check()
      expect(logs).toHaveLength(1)
    })
  }
})

describe("only authenticated bytes ever run", () => {
  // An unsigned script that leaves a marker if it is ever executed.
  const unsigned = () => new TextEncoder().encode(`#!/bin/sh\nprintf '%s\\n' "$*" >> '${dir}/unsigned'\nprintf '%s\\n' '{"version":"99.0.0","build":"release"}'\n`)
  const unsignedRan = () => readFile(join(dir, "unsigned"), "utf8").catch(() => null)

  test("a swap at the pre-spawn seam never runs the substitute: the authenticated copy runs, and the changed path is not admitted", async () => {
    const bytes = script(dir, "99.0.0")
    const w = await watch({
      beforeProbe: async () => {
        await writeFile(`${binary}.x`, unsigned(), { mode: 0o755 })
        await rename(`${binary}.x`, binary)
      },
    })
    await replaceWith(bytes)
    await record(bytes)
    await w.check()
    expect(await unsignedRan()).toBeNull()
    expect(await ran()).toBe("version --json\n")
    expect(w.cliMcp()).toBeNull()
  })

  test("swap and restore of the original inode inside the probe seam: the substitute never runs and the restored file is admitted", async () => {
    const bytes = script(dir, "99.0.0")
    const w = await watch({
      beforeProbe: async (path) => {
        await rename(binary, `${binary}.signed`)
        await writeFile(binary, unsigned(), { mode: 0o755 })
        // Whatever runs now runs before the restore.
        await probeVersion(env())(path)
        await rename(`${binary}.signed`, binary)
      },
    })
    await replaceWith(bytes)
    await record(bytes)
    await w.check()
    expect(await unsignedRan()).toBeNull()
    expect(w.cliMcp()).toEqual({ running: VERSION, installed: "99.0.0", action: "switch" })
  })

  test("the path replaced while the signature is still being verified: the authenticated copy runs, the substitute never does, and the stale result is not admitted", async () => {
    const bytes = script(dir, "99.0.0")
    const w = await watch({
      hooks: {
        afterRead: async () => {
          await writeFile(`${binary}.x`, unsigned(), { mode: 0o755 })
          await rename(`${binary}.x`, binary)
        },
      },
    })
    await replaceWith(bytes)
    await record(bytes)
    await w.check()
    expect(await unsignedRan()).toBeNull()
    expect(w.cliMcp()).toBeNull()
  })

  test("the source altered in place after it was read: the substitute never runs and nothing is admitted", async () => {
    const bytes = script(dir, "99.0.0")
    const w = await watch({
      hooks: {
        afterRead: async () => {
          await writeFile(binary, unsigned())
        },
      },
    })
    await replaceWith(bytes)
    await record(bytes)
    await w.check()
    expect(await unsignedRan()).toBeNull()
    expect(w.cliMcp()).toBeNull()
  })
})

describe("one deadline over the whole probe", () => {
  const info = JSON.stringify({ version: "99.0.0", commit: "abc1234", build: "release" })
  const cases: [string, string][] = [
    ["never exits", `exec sleep 30`],
    ["leaves a descendant holding stdout after it exits", `(sleep 5) &\nprintf '%s\\n' '${info}'\nexit 0`],
    ["floods stdout", `exec yes '${info}'`],
  ]
  for (const [name, body] of cases) {
    test(`a version command that ${name} settles within the budget, admits nothing, and leaves the watch usable`, async () => {
      const w = await watch({ probeLimits: { timeoutMs: 500, maxBytes: 4096 } })
      const bad = new TextEncoder().encode(`#!/bin/sh\nif [ "$1 $2" = "version --json" ]; then\n${body}\nfi\nexit 2\n`)
      await replaceWith(bad)
      await record(bad)
      const started = Date.now()
      await w.check()
      expect(Date.now() - started).toBeLessThan(2_000)
      expect(w.cliMcp()).toBeNull()
      expect(JSON.parse(logs[0]!).reason).toMatch(/^its version --json did not answer/)
      // A later replacement is still looked at and admitted.
      const good = script(dir, "99.0.1")
      await replaceWith(good)
      await record(good, { version: "99.0.1" })
      await w.check()
      expect(w.cliMcp()).toMatchObject({ installed: "99.0.1" })
    })
  }
})

// Directories older servers left in the temporary directory: removed only
// when they are clearly a mehen mcp private directory and clearly dead.
describe("leftover private directories", () => {
  let parent: string
  beforeEach(() => {
    parent = privateDir("mehen-selfwatch-tmp-")
  })
  afterEach(async () => {
    await rm(parent, { recursive: true, force: true })
  })
  const hoursAgo = (hours: number) => new Date(Date.now() - hours * 3_600_000)
  const deadPid = async () => {
    const proc = Bun.spawn(["true"])
    await proc.exited
    return proc.pid
  }
  async function leftover(name: string, options: { owner?: { pid: number; boot: string }; extra?: string; age?: number } = {}): Promise<string> {
    const path = join(parent, name)
    await mkdir(path, { mode: 0o700 })
    await chmod(path, 0o700)
    const files = [`exec-${"ab".repeat(8)}`, ...(options.extra ? [options.extra] : []), ...(options.owner ? ["owner.json"] : [])]
    for (const file of files) await writeFile(join(path, file), file === "owner.json" ? JSON.stringify(options.owner) : "#!/bin/sh\nexit 0\n", { mode: 0o500 })
    if (options.age !== undefined) for (const file of [...files.map((f) => join(path, f)), path]) await utimes(file, hoursAgo(options.age), hoursAgo(options.age))
    return path
  }
  const left = async () => (await readdir(parent)).sort()

  test("a marked directory whose owner is gone and an unmarked one untouched for two hours are removed", async () => {
    await leftover("mehen-mcp-Dead01", { owner: { pid: await deadPid(), boot: bootId() } })
    await leftover("mehen-mcp-Old001", { age: 3 })
    expect((await sweepPrivateLeftovers(parent, null)).map((p) => basename(p)).sort()).toEqual(["mehen-mcp-Dead01", "mehen-mcp-Old001"])
    expect(await left()).toEqual([])
  })

  test("a mehen-mcp-home- directory, one with another file, a symlink, a live owner, a recent unmarked one, a loose mode and the caller's own are all left alone", async () => {
    await leftover("mehen-mcp-home-Abc123", { age: 3 })
    await leftover("mehen-mcp-Other1", { age: 3, extra: "notes.txt" })
    const target = await leftover("elsewhere", { age: 3 })
    await symlink(target, join(parent, "mehen-mcp-Link01"))
    await leftover("mehen-mcp-Live01", { owner: { pid: process.pid, boot: bootId() }, age: 3 })
    await leftover("mehen-mcp-New001")
    const loose = await leftover("mehen-mcp-Loose1", { age: 3 })
    await chmod(loose, 0o755)
    await utimes(loose, hoursAgo(3), hoursAgo(3))
    const own = await leftover("mehen-mcp-Own001", { age: 3 })
    const before = await left()
    expect(await sweepPrivateLeftovers(parent, own)).toEqual([])
    expect(await left()).toEqual(before)
    expect(await readdir(target)).toEqual([`exec-${"ab".repeat(8)}`])
  })

  // Liveness is the pid alone: a boot id that reads differently must never
  // remove a live server's directory. A reused pid keeps one, the safe way.
  test("a live owner whose marker names another boot keeps its directory", async () => {
    await leftover("mehen-mcp-Boot01", { owner: { pid: process.pid, boot: `not-${bootId()}` }, age: 3 })
    expect(await sweepPrivateLeftovers(parent, null)).toEqual([])
    expect(await left()).toEqual(["mehen-mcp-Boot01"])
  })

  test("a marker that is corrupt, unreadable, not an object or names no pid keeps its directory, however old", async () => {
    const markers: Record<string, string> = { "mehen-mcp-Bad001": "{not json", "mehen-mcp-Bad002": "", "mehen-mcp-Bad003": "42", "mehen-mcp-Bad004": JSON.stringify({ boot: bootId() }) }
    for (const [name, text] of Object.entries(markers)) {
      const path = await leftover(name, { owner: { pid: 1, boot: "" } })
      await rm(join(path, "owner.json"))
      await writeFile(join(path, "owner.json"), text, { mode: 0o600 })
    }
    const unreadable = await leftover("mehen-mcp-Bad005", { owner: { pid: await deadPid(), boot: bootId() } })
    await chmod(join(unreadable, "owner.json"), 0o000)
    for (const name of [...Object.keys(markers), "mehen-mcp-Bad005"]) {
      const path = join(parent, name)
      for (const file of await readdir(path)) await utimes(join(path, file), hoursAgo(3), hoursAgo(3))
      await utimes(path, hoursAgo(3), hoursAgo(3))
    }
    const before = await left()
    expect(await sweepPrivateLeftovers(parent, null)).toEqual([])
    expect(await left()).toEqual(before)
  })

  test("a dead owner's directory is removed whatever boot its marker names", async () => {
    await leftover("mehen-mcp-Dead02", { owner: { pid: await deadPid(), boot: `not-${bootId()}` } })
    expect((await sweepPrivateLeftovers(parent, null)).map((p) => basename(p))).toEqual(["mehen-mcp-Dead02"])
    expect(await left()).toEqual([])
  })

  test("an exec- entry that is a symlink keeps its directory, and its target is never touched", async () => {
    const target = join(parent, "target")
    await writeFile(target, "#!/bin/sh\nexit 0\n", { mode: 0o500 })
    const path = await leftover("mehen-mcp-Sym001", { owner: { pid: await deadPid(), boot: bootId() } })
    await symlink(target, join(path, `exec-${"cd".repeat(8)}`))
    expect(await sweepPrivateLeftovers(parent, null)).toEqual([])
    expect(await left()).toEqual(["mehen-mcp-Sym001", "target"])
    expect(await readdir(path)).toContain(`exec-${"cd".repeat(8)}`)
    expect(await readFile(target, "utf8")).toBe("#!/bin/sh\nexit 0\n")
  })

  test("one sweep removes at most 200 directories", async () => {
    for (let i = 0; i < 205; i++) await leftover(`mehen-mcp-B${String(i).padStart(5, "0")}`, { age: 3 })
    expect(await sweepPrivateLeftovers(parent, null)).toHaveLength(200)
    expect(await left()).toHaveLength(5)
  })

  test("making a private directory marks it with its owner and sweeps dead siblings", async () => {
    await leftover("mehen-mcp-Old001", { age: 3 })
    const executables = new PrivateExecutables(parent)
    try {
      const path = await executables.create(new TextEncoder().encode("#!/bin/sh\nexit 0\n"))
      expect(await left()).toEqual([basename(dirname(path))])
      expect(JSON.parse(await readFile(join(dirname(path), "owner.json"), "utf8"))).toEqual({ pid: process.pid, boot: bootId() })
    } finally {
      executables.clear()
    }
  })

  test("a private directory another server swept is made again on the next launch", async () => {
    const executables = new PrivateExecutables(parent)
    const bytes = new TextEncoder().encode("#!/bin/sh\nexit 0\n")
    try {
      const first = await executables.create(bytes)
      await rm(dirname(first), { recursive: true, force: true })
      const second = await executables.create(bytes)
      expect(await readFile(second)).toEqual(Buffer.from(bytes))
      expect(statSync(dirname(second)).mode & 0o777).toBe(0o700)
      expect(JSON.parse(await readFile(join(dirname(second), "owner.json"), "utf8"))).toEqual({ pid: process.pid, boot: bootId() })
      expect(await left()).toEqual([basename(dirname(second))])
    } finally {
      executables.clear()
    }
  })
})

describe("the idle timer and update scheduling", () => {
  test("a busy server neither looks nor schedules; an idle one does both", async () => {
    let busy = true
    let scheduled = 0
    const w = await watch({ busy: () => busy, schedule: async () => void scheduled++ })
    const bytes = script(dir, "99.0.0")
    await replaceWith(bytes)
    await record(bytes)
    await w.tick()
    expect(scheduled).toBe(0)
    expect(w.cliMcp()).toBeNull()
    busy = false
    await w.tick()
    expect(scheduled).toBe(1)
    expect(w.cliMcp()).toMatchObject({ installed: "99.0.0" })
  })

  test("the idle schedule spawns a private copy of the server's own bytes as the updater when due, with the real target and an allowlisted environment; main's finally for mcp never does", async () => {
    await writeFile(binary, `#!/bin/sh\nprintf '%s|%s|%s|%s\\n' "$*" "$MEHEN_UPDATE_TARGET" "$MEHEN_UPDATE_CHILD" "$UNRELATED_CANARY" >> '${dir}/spawned'\nprintf '%s\\n' "$0" >> '${dir}/spawnedFrom'\n`, { mode: 0o755 })
    expect(await scheduleBackgroundUpdate(env(), "mcp")).toBe("skipped")
    const w = await watch({ extra: { UNRELATED_CANARY: "leaked" } })
    await w.tick()
    const spawned = await eventually(() => readFile(join(dir, "spawned"), "utf8").catch(() => null))
    expect(spawned).toBe(`update --background|${binary}|1|\n`)
    const from = (await eventually(() => readFile(join(dir, "spawnedFrom"), "utf8").catch(() => null)))?.trim() ?? ""
    expect(from).not.toBe("")
    expect(from).not.toBe(binary)
    expect(dirname(from)).not.toBe(dir)
  })

  test("the idle schedule respects the updater's rules: nothing when automatic updates are off", async () => {
    await writeFile(binary, `#!/bin/sh\nprintf '%s\\n' "$*" >> '${dir}/spawned'\n`, { mode: 0o755 })
    const launch = { executable: async () => binary, env: {}, isIdle: () => true }
    expect(await scheduleBackgroundUpdate(env({ MEHEN_NO_AUTO_UPDATE: "1" }), "mcp", { idleMcp: launch })).toBe("skipped")
    expect(await scheduleBackgroundUpdate(env({ MEHEN_UPDATE_CHILD: "1" }), "mcp", { idleMcp: launch })).toBe("skipped")
    await Bun.sleep(100)
    expect((await readdir(dir)).includes("spawned")).toBe(false)
  })
})

// A file the child appends to exists, empty, before its line is written, so
// an empty read is not an answer yet.
async function eventually<T>(read: () => Promise<T | null>, tries = 150): Promise<T | null> {
  for (let i = 0; i < tries; i++) {
    const value = await read()
    if (value !== null && value !== "") return value
    await Bun.sleep(20)
  }
  return null
}

// The child a launch would start writes `ran` within this long; a negative
// check waits at least this.
const CHILD_SETTLE_MS = 1_000

describe("the idle updater runs only admitted bytes", () => {
  const other = async () => ((await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair).privateKey
  const refusedCases: [string, (bytes: Uint8Array) => Promise<void>][] = [
    ["a hand copy with no record", async () => {}],
    ["a by: \"install\" record", async (bytes) => void (await record(bytes, { by: "install", keyId: null, manifest: null, manifestSha256: null }))],
    ["a keyId: null record", async (bytes) => void (await record(bytes, { keyId: null }))],
    ["a record whose manifest has a bad signature", async (bytes) => void (await record(bytes, { manifest: await signedManifest("99.0.0", bytes, await other()) }))],
    ["a record naming other bytes", async () => void (await record(script(dir, "99.0.1")))],
    ["an unsettled journal", async (bytes) => {
      const state = freshInstallState()
      state.pending = { target: { version: "99.0.0", commit: "abc1234", sha256: sha256(bytes), size: bytes.length, at: "2026-10-28T12:00:00.000Z", by: "auto", keyId: releaseKey.id, manifestSha256: null, manifest: await signedManifest("99.0.0", bytes) }, previousSha256: null, steps: ["record", "receipt"], since: "2026-10-28T12:00:00.000Z" }
      await writeInstallState(installation(binary), state)
    }],
  ]
  for (const [name, admit] of refusedCases) {
    test(`a due idle tick after ${name} runs nothing from that file: no version --json, no update --background`, async () => {
      const w = await watch()
      const bytes = script(dir, "99.0.0")
      await replaceWith(bytes)
      await admit(bytes)
      await w.tick()
      await Bun.sleep(CHILD_SETTLE_MS)
      expect(w.cliMcp()).toBeNull()
      expect(await ran()).toBeNull()
    })
  }

  test("two launches of the same admitted bytes share one private copy; a copy whose bytes changed is replaced, never run", async () => {
    const w = await watch()
    const first = await w.launchable(installation(binary))
    const second = await w.launchable(installation(binary))
    expect(first).not.toBeNull()
    expect(second).toBe(first)
    expect((await readdir(dirname(first!))).filter((n) => n.startsWith("exec-"))).toEqual([basename(first!)])
    await chmod(first!, 0o700)
    await writeFile(first!, "#!/bin/sh\nexit 9\n")
    const third = await w.launchable(installation(binary))
    expect(third).not.toBe(first)
    expect(await readFile(third!)).toEqual(await readFile(binary))
    expect((await readdir(dirname(third!))).filter((n) => n.startsWith("exec-"))).toEqual([basename(third!)])
  })

  test("an exec keeps the copies the idle updater launched within the hour and removes everything else, owner marker included, so the directory is a dead one's once it sits unchanged", async () => {
    let at = Date.now()
    const w = await watch({ now: () => at })
    const launched = (await w.launchable(installation(binary)))!
    const other = await w.executables.create(new TextEncoder().encode("#!/bin/sh\nexit 0\n"))
    at += 30 * 60_000
    w.releaseForExec()
    expect(existsSync(launched)).toBe(true)
    expect(await readdir(dirname(launched))).toEqual([basename(launched)])
    expect(existsSync(other)).toBe(false)
    // Without a launch in the last hour nothing is kept.
    const later = await watch({ now: () => at })
    const old = (await later.launchable(installation(binary)))!
    at += 61 * 60_000
    later.releaseForExec()
    expect(existsSync(dirname(old))).toBe(false)
    await rm(dirname(launched), { recursive: true, force: true })
  })

  test("MEHEN_UPDATE_TARGET is honoured only inside an updater child, and only for a binary named mehen", () => {
    expect(updateTarget({ MEHEN_UPDATE_TARGET: binary })).toBeNull()
    expect(updateTarget({ MEHEN_UPDATE_TARGET: binary, MEHEN_UPDATE_CHILD: "1" })).toBe(binary)
    expect(() => updateTarget({ MEHEN_UPDATE_TARGET: join(dir, "git"), MEHEN_UPDATE_CHILD: "1" })).toThrow("must name an installed mehen binary")
    expect(() => updateTarget({ MEHEN_UPDATE_TARGET: "mehen", MEHEN_UPDATE_CHILD: "1" })).toThrow("must name an installed mehen binary")
  })

  test("a file swapped in between admission and the updater launch is never run", async () => {
    const unsigned = `#!/bin/sh\nprintf '%s\\n' "$*" >> '${dir}/unsigned'\n`
    const w = await watch({
      hooks: {
        beforeLaunch: async () => {
          await writeFile(`${binary}.x`, unsigned, { mode: 0o755 })
          await rename(`${binary}.x`, binary)
        },
      },
    })
    const bytes = script(dir, "99.0.0")
    await replaceWith(bytes)
    await record(bytes)
    await w.tick()
    expect(w.cliMcp()).toMatchObject({ installed: "99.0.0" })
    await Bun.sleep(CHILD_SETTLE_MS)
    expect(await readFile(join(dir, "unsigned"), "utf8").catch(() => null)).toBeNull()
    expect(await ran()).toBe("version --json\n")
  })

  test("an admitted launch updates the real installation under U2's lock, and an unrelated variable never reaches the updater", async () => {
    // The release: answers the smoke test and writes the environment its
    // skills refresh sees, which is the updater's own plus its additions.
    const info = JSON.stringify({ version: "9.0.0", commit: "abc1234", build: "release", helper: process.platform === "darwin" ? "embedded" : "none" })
    const release = new TextEncoder().encode(`#!/bin/sh\nif [ "$1 $2" = "version --json" ]; then printf '%s\\n' '${info}'; exit 0; fi\nif [ "$1 $2" = "setup --json" ]; then env > '${dir}/updater-env'; printf '{"skills":[]}\\n'; exit 0; fi\nexit 2\n`)
    const manifest = await signedManifest("9.0.0", release)
    const gz = Bun.gzipSync(new Uint8Array(release))
    const releases = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: (req) => (new URL(req.url).pathname.endsWith(".json") ? Response.json(manifest) : new Response(gz)) })
    try {
      await writeFile(binary, `#!/bin/sh\nexec '${process.execPath}' '${MAIN}' "$@"\n`, { mode: 0o755 })
      const w = await watch({ extra: { MEHEN_DL_BASE: `http://127.0.0.1:${releases.port}/dl`, UNRELATED_CANARY: "leaked" } })
      await w.tick()
      const state = await eventually(async () => {
        const text = await readFile(join(dir, ".mehen.update.json"), "utf8").catch(() => null)
        const value = text === null ? null : (JSON.parse(text) as { installed?: { version?: string }; pending?: unknown })
        return value !== null && value.installed?.version === "9.0.0" && value.pending === null ? value : null
      }, 500)
      expect(state?.installed).toMatchObject({ version: "9.0.0", by: "auto", keyId: releaseKey.id })
      expect(new Uint8Array(await readFile(binary))).toEqual(release)
      // The updater records the install before it refreshes skills and
      // appends its log line, so both trail the state file.
      const log = await eventually(async () => {
        const text = await readFile(join(dir, ".mehen.update.log"), "utf8").catch(() => null)
        return text?.includes('"result":"updated"') ? text : null
      }, 500)
      expect(log).toContain('"result":"updated"')
      const seen = (await eventually(() => readFile(join(dir, "updater-env"), "utf8").catch(() => null), 500)) ?? ""
      expect(seen).not.toContain("UNRELATED_CANARY")
      expect(seen).toContain("MEHEN_UPDATE_CHILD=1")
    } finally {
      releases.stop(true)
    }
  }, 30_000)
})

describe("idle means idle at the spawn", () => {
  const recorder = () => writeFile(binary, `#!/bin/sh\nprintf '%s\\n' "$*" >> '${dir}/spawned'\n`, { mode: 0o755 })
  const spawned = () => readFile(join(dir, "spawned"), "utf8").catch(() => null)

  test("a call that arrives while the launch is being prepared stops it; a later idle tick schedules", async () => {
    await recorder()
    let busy = false
    const w = await watch({ busy: () => busy, hooks: { beforeLaunch: async () => void (busy = true) } })
    await w.tick()
    await Bun.sleep(CHILD_SETTLE_MS)
    expect(await spawned()).toBeNull()
    // The call finished: the next idle tick launches.
    const later = await watch({ busy: () => false })
    await later.tick()
    expect(await eventually(spawned)).toBe("update --background\n")
  })

  test("overlapping idle ticks prepare one launch", async () => {
    await recorder()
    let release: () => void = () => {}
    const held = new Promise<void>((resolve) => (release = resolve))
    const w = await watch({ hooks: { beforeLaunch: () => held } })
    const ticks = [w.tick(), w.tick(), w.tick()]
    await Bun.sleep(50)
    release()
    await Promise.all(ticks)
    await Bun.sleep(CHILD_SETTLE_MS)
    expect(await spawned()).toBe("update --background\n")
  })

  test("a live U2 lock is never taken: nothing launches and the state is not written", async () => {
    await recorder()
    const install = installation(binary)
    await mkdir(install.files.lock, { mode: 0o700 })
    const owner = JSON.stringify({ pid: process.pid, boot: bootId(), at: new Date().toISOString(), by: "manual", nonce: "held" })
    await writeFile(join(install.files.lock, "owner.json"), owner)
    const w = await watch()
    await w.tick()
    await Bun.sleep(CHILD_SETTLE_MS)
    expect(await spawned()).toBeNull()
    expect(await readFile(join(install.files.lock, "owner.json"), "utf8")).toBe(owner)
    expect(existsSync(install.files.state)).toBe(false)
  })
})

// The server as an agent's host runs it: `mehen mcp` standing in for an
// installed binary (MEHEN_SELF_EXECUTABLE), its executable replaced under it.
type Message = { jsonrpc: "2.0"; id?: number; method?: string; result?: Record<string, unknown>; error?: { code: number; message: string } }
type Content = { type: string; text?: string }

class Server {
  private readonly proc: ReturnType<typeof Bun.spawn<"pipe", "pipe", "pipe">>
  private readonly waiting = new Map<number, (m: Message) => void>()
  private nextId = 1
  stderr = ""

  constructor(serverEnv: Record<string, string>) {
    this.proc = Bun.spawn([process.execPath, MAIN, "mcp"], { env: serverEnv, stdin: "pipe", stdout: "pipe", stderr: "pipe", timeout: 60_000 })
    void this.read()
    void lines(this.proc.stderr, (text) => {
      this.stderr += text
    })
  }

  private async read(): Promise<void> {
    let buffer = ""
    await lines(this.proc.stdout, (text) => {
      buffer += text
      let newline = buffer.indexOf("\n")
      while (newline !== -1) {
        const message = JSON.parse(buffer.slice(0, newline)) as Message
        buffer = buffer.slice(newline + 1)
        newline = buffer.indexOf("\n")
        if (message.id !== undefined) this.waiting.get(message.id)?.(message)
      }
    })
  }

  async call(name: string, args: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    const id = this.nextId++
    const reply = new Promise<Message>((resolve) => this.waiting.set(id, resolve))
    this.proc.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } })}\n`)
    this.proc.stdin.flush()
    const message = await reply
    expect(message.error).toBeUndefined()
    return message.result as Record<string, unknown>
  }

  async close(): Promise<void> {
    this.proc.stdin.end()
    await this.proc.exited
  }

  async kill(signal: NodeJS.Signals): Promise<{ code: number | null; signal: string | null }> {
    this.proc.kill(signal)
    await this.proc.exited
    return { code: this.proc.exitCode, signal: this.proc.signalCode }
  }
}

// Every chunk of a child's stream as text, in order.
async function lines(stream: ReadableStream<Uint8Array>, onText: (text: string) => void): Promise<void> {
  const decoder = new TextDecoder()
  const reader = stream.getReader()
  for (;;) {
    const { done, value } = await reader.read()
    if (done) return
    onText(decoder.decode(value, { stream: true }))
  }
}

const notices = (result: Record<string, unknown>) => (result.content as Content[]).filter((c) => c.type === "text" && c.text?.startsWith("mehen ") && c.text.includes("Restart the agent"))

describe("restart-required in a running server", () => {
  let server: Server | null = null
  afterEach(async () => {
    await server?.close()
    server = null
  })
  const serverEnv = () => serverBase({ MEHEN_CONFIG_DIR: join(dir, "config") })
  beforeEach(() => handoverOff(join(dir, "config")))

  test("a verified replacement is noticed after a call: the next result carries the text once, vault_status and vault_doctor carry cli.mcp, and the old image keeps serving", async () => {
    server = new Server(serverEnv())
    const before = await server.call("vault_status")
    expect(notices(before)).toEqual([])
    expect((before.structuredContent as { cli: Record<string, unknown> }).cli.mcp).toBeUndefined()
    expect((before.structuredContent as { cli: Record<string, unknown> }).cli.mcpHandover).toEqual({ handover: "off", reason: "mcpHandover is false in settings.json" })
    const bytes = script(dir, "99.0.0")
    await replaceWith(bytes)
    await record(bytes)
    // This call's completion triggers the look; a later result reports it.
    const seen: Record<string, unknown>[] = [await server.call("vault_templates")]
    // The look runs the replacement's `version --json`; on a loaded runner that alone can take seconds.
    for (const deadline = Date.now() + 45_000; Date.now() < deadline; ) {
      const status = await server.call("vault_status")
      seen.push(status)
      if ((status.structuredContent as { cli: Record<string, unknown> }).cli.mcp) break
      await Bun.sleep(20)
    }
    const status = seen.at(-1)!
    expect((status.structuredContent as { cli: Record<string, unknown> }).cli.mcp).toEqual({ running: VERSION, installed: "99.0.0", action: "restart", reason: "mcpHandover is false in settings.json" })
    seen.push(await server.call("vault_templates"), await server.call("vault_templates"))
    const doctor = await server.call("vault_doctor")
    seen.push(doctor)
    expect((doctor.structuredContent as { cli: Record<string, unknown> }).cli.mcp).toEqual({ running: VERSION, installed: "99.0.0", action: "restart", reason: "mcpHandover is false in settings.json" })
    const all = seen.flatMap(notices)
    expect(all).toEqual([{ type: "text", text: `mehen 99.0.0 is installed on this machine; this server still runs ${VERSION}. Restart the agent to use the new version.` }])
    // The text is an extra block; structuredContent is the tool's own.
    expect(server.stderr).not.toContain("ignored a replaced binary")
    expect(await ran()).toBe("version --json\n")
  }, 60_000)

  test("a hand-copied binary is ignored with one stderr line, never run, and no cli.mcp appears", async () => {
    server = new Server(serverEnv())
    await server.call("vault_templates")
    await replaceWith(script(dir, "99.0.0"))
    await server.call("vault_templates")
    for (const deadline = Date.now() + 45_000; Date.now() < deadline && !server.stderr.includes("ignored a replaced binary"); ) await Bun.sleep(20)
    const results = [await server.call("vault_status"), await server.call("vault_templates")]
    expect(results.flatMap(notices)).toEqual([])
    expect((results[0]!.structuredContent as { cli: Record<string, unknown> }).cli.mcp).toBeUndefined()
    expect(server.stderr.split("\n").filter((l) => l.includes("ignored a replaced binary"))).toHaveLength(1)
    expect(await ran()).toBeNull()
  }, 60_000)
})

// A server's private directory goes with it however it ends: a signal left
// every copy it had made in the temporary directory.
describe("the private directory on a signal", () => {
  for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
    test(`${signal} removes the server's private directory and still ends the server by ${signal}`, async () => {
      const temp = privateDir("mehen-selfwatch-tmp-")
      const own = async () => (await readdir(temp)).filter((n) => n.startsWith("mehen-mcp-"))
      try {
        const server = new Server(serverBase({ MEHEN_CONFIG_DIR: join(dir, "config"), TMPDIR: temp }))
        await server.call("vault_templates")
        const bytes = script(dir, "99.0.0")
        await replaceWith(bytes)
        await record(bytes)
        await server.call("vault_templates")
        for (const deadline = Date.now() + 45_000; Date.now() < deadline; ) {
          const status = await server.call("vault_status")
          if ((status.structuredContent as { cli: Record<string, unknown> }).cli.mcp) break
          await Bun.sleep(20)
        }
        expect(await own()).toHaveLength(1)
        expect(await server.kill(signal)).toEqual({ code: null, signal })
        expect(await own()).toEqual([])
      } finally {
        await rm(temp, { recursive: true, force: true })
      }
    }, 60_000)
  }
})

describe("cli_outdated inside a call", () => {
  let vault: MockVault
  let releases: ReturnType<typeof Bun.serve>
  let server: Server | null = null
  beforeAll(() => {
    vault = new MockVault()
  })
  afterAll(() => vault.stop())
  afterEach(async () => {
    await server?.close()
    server = null
    releases?.stop(true)
    vault.cliMinimum = null
    vault.cliAdvice = null
  })

  test("heals inside the call, returns the restart next, and the next result carries the restart text", async () => {
    const healed = script(dir, "9.0.0")
    const manifest = await signedManifest("9.0.0", healed)
    const gz = Bun.gzipSync(new Uint8Array(healed))
    releases = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: (req) => (new URL(req.url).pathname.endsWith(".json") ? Response.json(manifest) : new Response(gz)) })
    const config = join(dir, "config")
    await vault.enrolSoftware(config)
    vault.cliMinimum = "9.0.0"
    vault.cliAdvice = "minimum=9.0.0"
    await handoverOff(config)
    server = new Server(serverBase({ MEHEN_CONFIG_DIR: config, MEHEN_VAULT_URL: vault.url, MEHEN_DL_BASE: `http://127.0.0.1:${releases.port}/dl` }))
    const refused = await server.call("vault_list")
    expect(refused.isError).toBe(true)
    expect(refused.structuredContent).toMatchObject({ error: "cli_outdated", next: { say: "mehen updated itself to 9.0.0 on disk; restart the agent to load it, then retry" } })
    expect(new Uint8Array(await readFile(binary))).toEqual(healed)
    let noticed: Content[] = []
    for (let i = 0; i < 100 && noticed.length === 0; i++) {
      noticed = notices(await server.call("vault_templates"))
      if (noticed.length === 0) await Bun.sleep(20)
    }
    expect(noticed).toEqual([{ type: "text", text: `mehen 9.0.0 is installed on this machine; this server still runs ${VERSION}. Restart the agent to use the new version.` }])
  })

  test("with automatic updates off the refusal keeps the vault's next and nothing is installed", async () => {
    const config = join(dir, "config")
    await vault.enrolSoftware(config)
    vault.cliMinimum = "9.0.0"
    releases = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response("never", { status: 500 }) })
    server = new Server(serverBase({ MEHEN_CONFIG_DIR: config, MEHEN_VAULT_URL: vault.url, MEHEN_NO_AUTO_UPDATE: "1" }))
    const refused = await server.call("vault_list")
    expect(refused.structuredContent).toMatchObject({ error: "cli_outdated", next: { command: "mehen update --json", say: "Update mehen on this machine, then run the command again." } })
    expect(await readFile(binary, "utf8")).toContain("the running image")
  })
})
