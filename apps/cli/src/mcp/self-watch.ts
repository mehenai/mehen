// mehen mcp watching its own executable. A server
// records its binary's identity at start; after every tools/call and on an
// idle timer it looks again. A replacement is believed only when the signed
// updater verified and recorded exactly those bytes: the record names a key
// (never `by: "install"`), its retained manifest verifies against the
// trusted release keys and names the same hash and size, the receipt
// agrees and the version is above this one. Only then is the file run at
// all (`version --json`, under MEHEN_UPDATE_CHILD=1); a hand copy, a
// shell-installer binary or bytes no record describes are never executed.
// With the handover off, a verified replacement is
// restart-required: the server keeps serving this image and says so. With
// it on, the server switches to it in place, and says so
// only when that switch is refused or fails.

import { randomBytes, randomInt } from "node:crypto"
import { readdirSync, rmSync } from "node:fs"
import { chmod, lstat, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { canonicalJson } from "@mehen/protocol/canonical-json"
import type { Env } from "../config.ts"
import { type CliMcp, type InstalledRecord, type Installation, type McpHandover, bootId, installation, mcpHandoverNow, pidAlive, readInstallState, selfBuild } from "../install-state.ts"
import { compareVersions, downloadBase, releaseTrust, sha256, verifiedRelease } from "../release-client.ts"
import { scheduleBackgroundUpdate } from "../update.ts"
import { VERSION } from "../version.ts"

export const IDLE_INTERVAL_MS = 60_000
// A replacement that failed verification is not looked at again for an hour.
export const IGNORE_MS = 3_600_000
// The restart-required text: in the next tool result, then at most hourly.
export const NOTICE_INTERVAL_MS = 3_600_000
const PROBE_TIMEOUT_MS = 10_000
const LAUNCH_KEEP_MS = 3_600_000

// What the updater child an idle server launches may see of the server's
// environment: the home, the release and update controls and
// what its skills refresh reads, nothing else.
const UPDATER_ENV = ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "MEHEN_HOME", "MEHEN_CONFIG_DIR", "MEHEN_MANAGED_CONTEXT", "MEHEN_DL_BASE", "MEHEN_RELEASE_KEYS", "MEHEN_NO_AUTO_UPDATE", "CI", "MEHEN_SELF_EXECUTABLE"] as const

export function updaterEnv(env: Env): Record<string, string> {
  const out: Record<string, string> = {}
  for (const key of UPDATER_ENV) {
    const value = env[key]
    if (value !== undefined) out[key] = value
  }
  return out
}

// What identifies the file at the binary's path: a rename gives a new inode.
export type FileIdentity = { dev: number; ino: number; size: number; mtimeMs: number }

// A replacement the signed updater verified and recorded, and the version
// it printed when probed after that.
export type VerifiedReplacement = { identity: FileIdentity; record: InstalledRecord }

export type Verification = { ok: true; replacement: VerifiedReplacement } | { ok: false; reason: string; unsettled: boolean }

// Runs `<binary> version --json` and returns what it printed.
export type Probe = (binary: string) => Promise<unknown>

export type SelfWatchOptions = {
  env: Env
  // The real path of the executable this process stands for.
  binary: string
  running?: string
  now?: () => number
  probe?: Probe
  log?: (line: string) => void
  // The idle timer's background check; the default is the updater's own
  // scheduling with its due rules.
  schedule?: () => Promise<unknown>
  // True while a tools/call is in flight: the idle timer does nothing then.
  busy?: () => boolean
  hooks?: VerifyHooks
  // The server's handover decision at its start; by default what one
  // started now with `env` would decide.
  handover?: McpHandover
}

export function restartText(cli: Pick<CliMcp, "running" | "installed">): string {
  return `mehen ${cli.installed} is installed on this machine; this server still runs ${cli.running}. Restart the agent to use the new version.`
}

async function identityOf(path: string): Promise<FileIdentity | null> {
  try {
    const info = await lstat(path)
    if (!info.isFile()) return null
    return { dev: info.dev, ino: info.ino, size: info.size, mtimeMs: info.mtimeMs }
  } catch {
    return null
  }
}

function sameIdentity(a: FileIdentity | null, b: FileIdentity | null): boolean {
  return a !== null && b !== null && a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeMs === b.mtimeMs
}

// `version --json` of the replacement with nothing of this process's
// environment but PATH and HOME, as the updater's smoke test runs it. One
// deadline covers the whole probe, reading and exit alike, so a child
// that never exits, or a descendant that keeps its stdout open, cannot
// hold the watch; output past a small bound is refused.
export const PROBE_MAX_BYTES = 64 * 1024

export function probeVersion(env: Env, limits: { timeoutMs?: number; maxBytes?: number } = {}): Probe {
  const timeoutMs = limits.timeoutMs ?? PROBE_TIMEOUT_MS
  const maxBytes = limits.maxBytes ?? PROBE_MAX_BYTES
  return async (binary) => {
    const proc = Bun.spawn([binary, "version", "--json"], { env: { PATH: env.PATH ?? process.env.PATH ?? "", HOME: env.HOME ?? "", MEHEN_UPDATE_CHILD: "1" }, stdin: "ignore", stdout: "pipe", stderr: "ignore" })
    const reader = proc.stdout.getReader()
    let timer: ReturnType<typeof setTimeout> | null = null
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`no answer within ${timeoutMs} ms`)), timeoutMs)
    })
    const answer = (async () => {
      const chunks: Uint8Array[] = []
      let size = 0
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        size += value.length
        if (size > maxBytes) throw new Error(`more than ${maxBytes} bytes of output`)
        chunks.push(value)
      }
      return { code: await proc.exited, out: new TextDecoder().decode(Buffer.concat(chunks)) }
    })()
    answer.catch(() => {})
    try {
      const { code, out } = await Promise.race([answer, deadline])
      if (code !== 0) throw new Error(`exit ${code}`)
      return JSON.parse(out) as unknown
    } finally {
      if (timer !== null) clearTimeout(timer)
      if (proc.exitCode === null && proc.signalCode === null) proc.kill("SIGKILL")
      await reader.cancel().catch(() => {})
    }
  }
}

function above(version: string, running: string): boolean {
  try {
    return compareVersions(version, running) > 0
  } catch {
    return false
  }
}

const refused = (reason: string, unsettled = false): Verification => ({ ok: false, reason, unsettled })

const PRIVATE_PREFIX = "mehen-mcp-"
// What mkdtemp makes of the prefix: six more characters, never a dash, so
// `mehen-mcp-home-*` and the like are never taken for one.
const PRIVATE_DIR_NAME = /^mehen-mcp-[A-Za-z0-9]{6}$/
const PRIVATE_EXEC_NAME = /^exec-[0-9a-f]{16}$/
const OWNER_MARKER = "owner.json"
const OWNER_MARKER_MAX_BYTES = 4096
// A directory with no owner marker (made before there was one) is dead once
// nothing in it changed for this long.
const UNMARKED_IDLE_MS = 2 * 3_600_000
const SWEEP_LIMIT = 200

// Removes private directories other mehen mcp servers left in `parent`
// (a crash, a signal, a version that never removed them), at most
// SWEEP_LIMIT of them looked at, from a random place in the listing so
// that ones left alone never hold back the rest on the next start. A
// directory is removed only when it is clearly one:
// named `mehen-mcp-` and a mkdtemp suffix, a real directory of this uid
// with mode 0700, holding nothing but `exec-<16 hex>` files of this uid
// and the owner marker; and clearly dead: its marker names a process gone,
// or, with no marker, nothing in it changed for two hours. The boot id is
// not trusted to override a live pid; a reused pid keeps a directory. Symlinks are never followed; anything else is left alone. Returns
// the paths removed.
export async function sweepPrivateLeftovers(parent: string, own: string | null): Promise<string[]> {
  const uid = process.getuid?.() ?? -1
  const now = Date.now()
  const names = (await readdir(parent)).filter((name) => PRIVATE_DIR_NAME.test(name) && join(parent, name) !== own)
  const start = names.length === 0 ? 0 : randomInt(names.length)
  const removed: string[] = []
  for (let i = 0; i < Math.min(names.length, SWEEP_LIMIT); i++) {
    const path = join(parent, names[(start + i) % names.length]!)
    if (await deadLeftover(path, uid, now)) {
      await rm(path, { recursive: true, force: true })
      removed.push(path)
    }
  }
  return removed
}

async function deadLeftover(path: string, uid: number, now: number): Promise<boolean> {
  try {
    const info = await lstat(path)
    if (!info.isDirectory() || info.uid !== uid || (info.mode & 0o777) !== 0o700) return false
    let changed = info.mtimeMs
    let marker: string | null = null
    for (const entry of await readdir(path)) {
      if (entry !== OWNER_MARKER && !PRIVATE_EXEC_NAME.test(entry)) return false
      const file = await lstat(join(path, entry))
      if (!file.isFile() || file.uid !== uid) return false
      changed = Math.max(changed, file.mtimeMs)
      if (entry === OWNER_MARKER) {
        if (file.size > OWNER_MARKER_MAX_BYTES) return false
        marker = await readFile(join(path, entry), "utf8")
      }
    }
    if (marker === null) return now - changed >= UNMARKED_IDLE_MS
    const owner: unknown = JSON.parse(marker)
    if (typeof owner !== "object" || owner === null) return false
    const { pid, boot } = owner as { pid?: unknown; boot?: unknown }
    if (typeof pid !== "number" || !Number.isSafeInteger(pid) || pid <= 0 || typeof boot !== "string") return false
    return !pidAlive(pid)
  } catch {
    return false
  }
}

// Executables this server owns: copies of bytes it has authenticated, in
// a private directory (mode 0700) under the temporary directory, each made
// with `wx` and mode 0500. Nothing here is ever the installation path, a
// path from a tool argument or a path the updater replaces, so what runs is
// exactly what was checked. The directory carries an owner
// marker, so a later server can tell it is dead if this one never removes
// it; making it sweeps what dead servers left. A directory that has gone
// (another server's sweep, a cleaner of the temporary directory) is made
// again, so this server still verifies and launches.
export class PrivateExecutables {
  private dir: string | null = null
  private readonly parent: string

  constructor(parent = tmpdir()) {
    this.parent = parent
  }

  async create(bytes: Uint8Array): Promise<string> {
    try {
      return await this.write(await this.directory(), bytes)
    } catch (error) {
      if ((error as { code?: string }).code !== "ENOENT") throw error
      this.dir = null
      return this.write(await this.directory(), bytes)
    }
  }

  private async directory(): Promise<string> {
    if (this.dir !== null) return this.dir
    const dir = await mkdtemp(join(this.parent, PRIVATE_PREFIX))
    try {
      await chmod(dir, 0o700)
      await writeFile(join(dir, OWNER_MARKER), JSON.stringify({ pid: process.pid, boot: bootId() }), { mode: 0o600, flag: "wx" })
    } catch (error) {
      await rm(dir, { recursive: true, force: true }).catch(() => {})
      throw error
    }
    this.dir = dir
    await sweepPrivateLeftovers(this.parent, dir).catch(() => [])
    return dir
  }

  private async write(dir: string, bytes: Uint8Array): Promise<string> {
    const path = join(dir, `exec-${randomBytes(8).toString("hex")}`)
    await writeFile(path, bytes, { mode: 0o500, flag: "wx" })
    await chmod(path, 0o500)
    return path
  }

  async remove(path: string): Promise<void> {
    await rm(path, { force: true }).catch(() => {})
  }

  // Removes the directory and everything in it.
  clear(): void {
    if (this.dir !== null) rmSync(this.dir, { recursive: true, force: true })
    this.dir = null
  }

  // Lets the directory go at an exec, which keeps the pid: the copies in
  // `keep` stay, everything else goes, the owner marker with it, so the
  // directory is an unmarked one that sweepPrivateLeftovers removes once
  // nothing in it changed for UNMARKED_IDLE_MS. With nothing to keep, it
  // goes now. Synchronous: it runs just before the last check and the exec.
  release(keep: string[]): void {
    const dir = this.dir
    this.dir = null
    if (dir === null) return
    const kept = new Set(keep.filter((path) => path.startsWith(`${dir}/`)).map((path) => path.slice(dir.length + 1)))
    if (kept.size === 0) return void rmSync(dir, { recursive: true, force: true })
    for (const entry of readdirSync(dir)) if (!kept.has(entry)) rmSync(join(dir, entry), { recursive: true, force: true })
  }
}

// Test seams: awaited after the replacement's bytes were read, while the
// rest of its verification is still to come.
export type VerifyHooks = { afterRead?: () => Promise<void>; beforeLaunch?: () => Promise<void> }

// Whether the file now at `binary` is a newer release the signed updater
// verified and recorded. Its bytes are read once; every check is on that
// buffer, and only a private copy of it is ever executed. The
// installation path is never run.
export async function verifyReplacement(options: { env: Env; binary: string; running: string; identity: FileIdentity; probe: Probe; executables: PrivateExecutables; hooks?: VerifyHooks }): Promise<Verification> {
  const { env, binary, running, identity } = options
  const install = installation(binary)
  let state
  try {
    state = await readInstallState(install)
  } catch (error) {
    return refused(`the installation state cannot be read (${error instanceof Error ? error.message : String(error)})`)
  }
  // An update between its rename and its record: look again next time.
  const unsettled = state?.pending !== null && state?.pending !== undefined
  const record = state?.installed ?? null
  if (record === null) return refused("no update record describes it", unsettled)
  if (record.by === "install" || record.keyId === null || record.manifest === null) return refused("its record was not written by the signed updater (a hand copy or the shell installer)", unsettled)
  let bytes: Uint8Array
  try {
    bytes = new Uint8Array(await readFile(binary))
  } catch {
    return refused("it cannot be read", true)
  }
  await options.hooks?.afterRead?.()
  if (bytes.length !== record.size || sha256(bytes) !== record.sha256) return refused("its bytes are not the ones the signed update record names", unsettled)
  const verified = await verifiedRelease(record.manifest, releaseTrust(env, downloadBase(env), selfBuild(env))).catch((error: unknown) => error instanceof Error ? error : new Error(String(error)))
  if (verified instanceof Error) return refused(`its retained release manifest does not verify (${verified.message})`)
  const manifest = verified.manifest
  const file = manifest.files.find((f) => f.name.startsWith(`mehen-${process.platform}-`) && f.sha256 === record.sha256 && f.size === record.size)
  if (manifest.version !== record.version || file === undefined) return refused("its signed manifest does not name these bytes")
  if (record.manifestSha256 !== null && record.manifestSha256 !== sha256(new TextEncoder().encode(canonicalJson(manifest)))) return refused("its record's manifest digest does not match the manifest")
  if (!above(record.version, running)) return refused(`${record.version} is not newer than ${running}`)
  const receipt = await readFile(install.files.receipt, "utf8").then((t) => t.trim(), () => null)
  if (receipt !== record.sha256) return refused("its receipt does not match it", unsettled)
  // Authenticated bytes: a private copy of exactly them runs, never the path.
  let info: unknown
  let snapshot: string | null = null
  try {
    snapshot = await options.executables.create(bytes)
    info = await options.probe(snapshot)
  } catch (error) {
    return refused(`its version --json did not answer (${error instanceof Error ? error.message : String(error)})`)
  } finally {
    if (snapshot !== null) await options.executables.remove(snapshot)
  }
  const v = typeof info === "object" && info !== null ? (info as Record<string, unknown>) : {}
  if (v.build !== "release") return refused("it is not a release build")
  if (v.version !== record.version) return refused(`it reports ${String(v.version)}, not the recorded ${record.version}`)
  // What is installed now is still what was verified: anything else is
  // stale, and looked at again.
  const now = await readFile(binary).then((b) => new Uint8Array(b), () => null)
  if (!sameIdentity(await identityOf(binary), identity) || now === null || now.length !== record.size || sha256(now) !== record.sha256) return refused("it changed while it was verified", true)
  return { ok: true, replacement: { identity, record } }
}

export class SelfWatch {
  readonly binary: string
  private readonly env: Env
  private readonly running: string
  private readonly now: () => number
  private readonly probe: Probe
  private readonly log: (line: string) => void
  private readonly schedule: () => Promise<unknown>
  private readonly busy: () => boolean
  private start: FileIdentity | null = null
  // The bytes this server started from, as they were read at start.
  private startBytes: { sha256: string; size: number } | null = null
  // Private copies launched as the updater, one per distinct set of bytes:
  // kept an hour after their last launch, so a child is never left without
  // its executable while it starts.
  private launched: { path: string; at: number; sha256: string; size: number }[] = []
  private replacement: VerifiedReplacement | null = null
  private ignored: { identity: FileIdentity; until: number } | null = null
  private noticed: { version: string; at: number } | null = null
  // The replacement a switch to was refused or failed for.
  private refused: VerifiedReplacement | null = null
  private checking: Promise<void> | null = null
  private scheduling: Promise<unknown> | null = null
  private timer: ReturnType<typeof setInterval> | null = null
  // The private directory every copy this server runs is made in: the
  // probe's, the idle updater's and the handover's acceptance check's.
  readonly executables = new PrivateExecutables()
  private readonly hooks: VerifyHooks

  private constructor(
    options: SelfWatchOptions,
    readonly handover: McpHandover,
  ) {
    this.env = options.env
    this.binary = options.binary
    this.running = options.running ?? VERSION
    this.now = options.now ?? Date.now
    this.probe = options.probe ?? probeVersion(options.env)
    this.log = options.log ?? ((line) => process.stderr.write(`${line}\n`))
    this.schedule = options.schedule ?? (() => scheduleBackgroundUpdate(options.env, "mcp", { idleMcp: { executable: (install) => this.launchable(install), env: updaterEnv(options.env), isIdle: () => !this.busy() } }))
    this.busy = options.busy ?? (() => false)
    this.hooks = options.hooks ?? {}
  }

  // The watch over `binary` as it is now.
  static async create(options: SelfWatchOptions): Promise<SelfWatch> {
    // Automatic updates switched off switch off the handover and the idle
    // launch, never the restart notice: a human may update by
    // hand, and the agent still has to be told.
    const watch = new SelfWatch(options, options.handover ?? (await mcpHandoverNow(options.env)))
    watch.start = await identityOf(watch.binary)
    const bytes = await readFile(watch.binary).then((b) => new Uint8Array(b), () => null)
    if (bytes !== null && sameIdentity(await identityOf(watch.binary), watch.start)) watch.startBytes = { sha256: sha256(bytes), size: bytes.length }
    return watch
  }

  // The verified newer binary on disk, for `cli.mcp` in vault_status and
  // vault_doctor; null when there is none.
  cliMcp(): CliMcp | null {
    const replacement = this.replacement
    if (replacement === null) return null
    const versions = { running: this.running, installed: replacement.record.version }
    if (this.handover.handover === "off") return { ...versions, action: "restart", reason: this.handover.reason }
    if (replacement === this.refused) return { ...versions, action: "restart", reason: `the switch to ${replacement.record.version} was refused` }
    return { ...versions, action: "switch" }
  }

  verified(): VerifiedReplacement | null {
    return this.replacement
  }

  // The verified replacement to switch to in place: none with the handover
  // off, or once a switch to it was refused or failed.
  switchable(): VerifiedReplacement | null {
    return this.cliMcp()?.action === "switch" ? this.replacement : null
  }

  switchRefused(replacement: VerifiedReplacement): void {
    this.refused = replacement
  }

  // The restart-required text for the next tool result: the first time a
  // replacement is known with no switch to it, then at most hourly,
  // whatever the auto-update setting.
  notice(): string | null {
    const cli = this.cliMcp()
    if (cli === null || cli.action === "switch") return null
    const at = this.now()
    if (this.noticed && this.noticed.version === cli.installed && at - this.noticed.at < NOTICE_INTERVAL_MS) return null
    this.noticed = { version: cli.installed, at }
    return restartText(cli)
  }

  // Looks at the binary again, off the request path; one look at a time.
  check(): Promise<void> {
    this.checking ??= this.look().finally(() => {
      this.checking = null
    })
    return this.checking
  }

  private async look(): Promise<void> {
    const identity = await identityOf(this.binary)
    if (identity === null || sameIdentity(identity, this.start)) {
      this.replacement = null
      return
    }
    if (this.replacement && sameIdentity(this.replacement.identity, identity)) return
    this.replacement = null
    const ignored = this.ignored
    if (ignored && sameIdentity(ignored.identity, identity) && this.now() < ignored.until) return
    const result = await verifyReplacement({ env: this.env, binary: this.binary, running: this.running, identity, probe: this.probe, executables: this.executables, hooks: this.hooks }).catch((error: unknown) => refused(error instanceof Error ? error.message : String(error)))
    if (result.ok) {
      this.replacement = result.replacement
      this.ignored = null
      return
    }
    if (result.unsettled) return
    // Logged once per file, with the reason; ignored for an hour.
    if (!ignored || !sameIdentity(ignored.identity, identity)) this.log(JSON.stringify({ msg: "mcp self-watch ignored a replaced binary", path: this.binary, reason: result.reason }))
    this.ignored = { identity, until: this.now() + IGNORE_MS }
  }

  // The updater an idle server may launch: a private copy of the
  // installation's bytes, only when they are the bytes this server started
  // from or a replacement its self-watch admitted. A refused, unsettled or
  // unknown file is never run, and there is no fallback to the path.
  async launchable(install: Installation): Promise<string | null> {
    const at = this.now()
    for (const old of this.launched.filter((l) => at - l.at >= LAUNCH_KEEP_MS)) await this.executables.remove(old.path)
    this.launched = this.launched.filter((l) => at - l.at < LAUNCH_KEEP_MS)
    if (install.binary !== this.binary) return null
    await this.hooks.beforeLaunch?.()
    const bytes = await readFile(install.binary).then((b) => new Uint8Array(b), () => null)
    if (bytes === null) return null
    const hash = sha256(bytes)
    const admitted = [this.startBytes, this.replacement ? { sha256: this.replacement.record.sha256, size: this.replacement.record.size } : null]
    if (!admitted.some((a) => a !== null && a.sha256 === hash && a.size === bytes.length)) return null
    const kept = this.launched.find((l) => l.sha256 === hash && l.size === bytes.length)
    if (kept !== undefined) {
      const copy = await readFile(kept.path).then((b) => new Uint8Array(b), () => null)
      if (copy !== null && copy.length === kept.size && sha256(copy) === kept.sha256) {
        kept.at = at
        return kept.path
      }
      await this.executables.remove(kept.path)
      this.launched = this.launched.filter((l) => l !== kept)
    }
    const path = await this.executables.create(bytes)
    this.launched.push({ path, at, sha256: hash, size: bytes.length })
    return path
  }

  // One idle tick: nothing while a call is in flight; otherwise look at the
  // binary, then let the updater's own rules decide whether a background
  // check is due. Never from a busy call: idleness is asked again at the
  // spawn itself, and one scheduling attempt runs at a time.
  async tick(): Promise<void> {
    if (this.busy() || this.scheduling !== null) return
    await this.check()
    if (this.busy() || this.scheduling !== null) return
    this.scheduling = this.schedule().catch(() => {})
    try {
      await this.scheduling
    } finally {
      this.scheduling = null
    }
  }

  startTimer(intervalMs = IDLE_INTERVAL_MS): void {
    if (this.timer) return
    this.timer = setInterval(() => void this.tick(), intervalMs)
    this.timer.unref?.()
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer)
    this.timer = null
    this.executables.clear()
  }

  // Before an exec: the copies launched as the updater within the last
  // LAUNCH_KEEP_MS stay, since a child may still be starting from one;
  // the rest of the private directory goes (PrivateExecutables.release).
  releaseForExec(): void {
    const at = this.now()
    const kept = this.launched.filter((l) => at - l.at < LAUNCH_KEEP_MS).map((l) => l.path)
    this.launched = []
    this.executables.release(kept)
  }
}
