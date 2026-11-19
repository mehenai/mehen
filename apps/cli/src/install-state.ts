// The installation state: everything about
// the executable lives next to it, in the directory of the binary's
// realpath, with the `.mehen.` prefix. Two homes that share one binary share
// one lock and one record; two install directories have two of each; the
// shell installer finds the lock without knowing any home.
//
// There is no writer outside the lock: every write of
// `.mehen.update.json` happens inside withInstallLock, and the vault's
// advice is a zero-wait best-effort write under it.

import { spawnSync } from "node:child_process"
import { accessSync, constants, lstatSync, openSync, readFileSync, realpathSync } from "node:fs"
import { appendFile, chmod, lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises"
import { randomBytes } from "node:crypto"
import { dirname, join, resolve } from "node:path"
import type { SignedManifest } from "@mehen/protocol/release-manifest"
import { compareVersions } from "@mehen/protocol/version"
import type { DoctorCheck } from "./commands/doctor.ts"
import type { Env } from "./config.ts"
import { CliError } from "./errors.ts"
import { resolveHome } from "./home.ts"
// The skills report, as the updater stores it in `lastUpdate`.
import type { SkillReport } from "./setup/skills.ts"
import { BUILD_COMMIT, BUILD_KIND, type BuildKind, VERSION, isCompiledBinary } from "./version.ts"

// `manifest`: the exact signed manifest the bytes were verified against;
// null for by "install" (never verified by this binary).
// The repair advice for a refused journal or signature check: for the human
// only, never an instruction to bypass the check.
export const HUMAN_REPAIR = "Stop and ask the human to repair this installation out of band; an agent must not rerun the installer or add --force to get past a signature or journal check."

export type InstalledRecord = { version: string; commit: string | null; sha256: string; size: number; at: string; by: "auto" | "manual" | "heal" | "rollback" | "install"; keyId: string | null; manifestSha256: string | null; manifest: SignedManifest | null }
export type JournalStep = "record" | "receipt" | "retire-helper" | "skills"
// The complete verified record of what is about to be renamed in, written
// before the rename.
export type PendingJournal = { target: InstalledRecord; previousSha256: string | null; steps: JournalStep[]; since: string }
export type VaultAdvice = { minimum: string; recommended: string | null; seenAt: string }
export type InstallState = {
  v: 1
  installed: InstalledRecord | null
  previous: InstalledRecord | null
  highestSeen: string | null
  holdBelow: string | null
  pending: PendingJournal | null
  // `highestAnswered`: the highest version any vault advised (minimum or
  // recommended) when this check or an earlier one ran; advice at or below
  // it is not new (answeredAdvice in update.ts).
  check: { at: string; nextAt: string; base: string; latest: string | null; error: string | null; highestAnswered: string | null } | null
  vault: Record<string, VaultAdvice>
  lastUpdate: { at: string; from: string; to: string; result: "ok" | "ok_skills_failed" | "failed"; reason: string | null; skills: SkillReport[] } | null
}

export type AutoUpdateMode = "on" | "off" | "ci" | "dev" | "read-only"

// Whether `mehen mcp` switches to a verified update in place; when off,
// `reason` names the setting or variable that keeps it off, never a path
// or a value.
export type McpHandover = { handover: "on" } | { handover: "off"; reason: string }

// A verified newer binary on disk, as a running server reports it:
// "switch" while it will switch to it in place, else "restart" with why.
export type CliMcp = { running: string; installed: string; action: "switch" } | { running: string; installed: string; action: "restart"; reason: string }

// What status and doctor embed. `mcpHandover` is what a server
// started now would decide, or inside a server its own decision at start;
// `mcp` appears only inside a server with a verified newer binary on disk.
//
export type CliState = { version: string; commit: string | null; build: "release" | "dev" | null; path: string; autoUpdate: AutoUpdateMode; mcpHandover: McpHandover } & Omit<InstallState, "v"> & { mcp?: CliMcp }

// What cliState embeds when no state file exists; `vault` is `{}`, never
// null.
export const FRESH_INSTALL_STATE: Omit<InstallState, "v"> = { installed: null, previous: null, highestSeen: null, holdBelow: null, pending: null, check: null, vault: {}, lastUpdate: null }

export function freshInstallState(): InstallState {
  return { v: 1, ...structuredClone(FRESH_INSTALL_STATE) }
}

export type Installation = { binary: string; dir: string; files: { receipt: string; previous: string; previousMeta: string; state: string; lock: string; log: string; env: string } }

// The installation of `binary` (default: this process's executable),
// identified by realpath so a symlinked `~/.local/bin/mehen` names its
// target's directory; the path as given when it cannot be resolved.
export function installation(binary: string = process.execPath): Installation {
  let real: string
  try {
    real = realpathSync(binary)
  } catch {
    real = resolve(binary)
  }
  const dir = dirname(real)
  return {
    binary: real,
    dir,
    files: {
      receipt: join(dir, ".mehen.sha256"),
      previous: join(dir, ".mehen.previous"),
      previousMeta: join(dir, ".mehen.previous.json"),
      state: join(dir, ".mehen.update.json"),
      lock: join(dir, ".mehen.update.lock"),
      log: join(dir, ".mehen.update.log"),
      env: join(dir, ".mehen.env"),
    },
  }
}

// The executable this process stands for. A run from source is Bun itself,
// whose directory is no installation of mehen; MEHEN_SELF_EXECUTABLE names
// a stand-in script there (tests), and is never honoured by a compiled
// binary.
export function selfExecutable(env: Env): string | null {
  if (isCompiledBinary()) return process.execPath
  return env.MEHEN_SELF_EXECUTABLE ? resolve(env.MEHEN_SELF_EXECUTABLE) : null
}

// The build this process acts as for updating: a compiled binary's own
// stamp; a source run standing in for an installed release through
// MEHEN_SELF_EXECUTABLE acts as one, so the updater's tests run the real
// path; any other source run is no installation at all.
export function selfBuild(env: Env): BuildKind {
  if (isCompiledBinary()) return BUILD_KIND
  return env.MEHEN_SELF_EXECUTABLE ? "release" : null
}

export async function installDirWritable(install: Installation): Promise<boolean> {
  try {
    accessSync(install.dir, constants.W_OK)
    return true
  } catch {
    return false
  }
}

// --- the state file -------------------------------------------------------

const isString = (value: unknown): value is string => typeof value === "string"
const isNullableString = (value: unknown): value is string | null => value === null || typeof value === "string"
const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value)
function isReleaseVersion(value: unknown): value is string {
  try {
    return isString(value) && compareVersions(value, value) === 0
  } catch {
    return false
  }
}
const BY = new Set(["auto", "manual", "heal", "rollback", "install"])
const STEPS = new Set(["record", "receipt", "retire-helper", "skills"])
const HASH = /^[0-9a-f]{64}$/

function isInstalledRecord(value: unknown): value is InstalledRecord {
  if (!isObject(value)) return false
  return isString(value.version) && isNullableString(value.commit) && isString(value.sha256) && HASH.test(value.sha256) && typeof value.size === "number" && Number.isSafeInteger(value.size) && isString(value.at) && BY.has(value.by as string) && isNullableString(value.keyId) && isNullableString(value.manifestSha256) && (value.manifest === null || isObject(value.manifest))
}

function isPendingJournal(value: unknown): value is PendingJournal {
  if (!isObject(value)) return false
  return isInstalledRecord(value.target) && (value.previousSha256 === null || (isString(value.previousSha256) && HASH.test(value.previousSha256))) && Array.isArray(value.steps) && value.steps.every((step) => STEPS.has(step as string)) && isString(value.since)
}

function isAdvice(value: unknown): value is VaultAdvice {
  return isObject(value) && isString(value.minimum) && isNullableString(value.recommended) && isString(value.seenAt)
}

// The state as written, field by field; a field that does not hold its
// documented shape reads as its fresh value, except a malformed journal,
// which refuses: dropping it could record a half-finished update as a hand
// copy.
function parseInstallState(value: unknown): InstallState | null {
  if (!isObject(value) || value.v !== 1) return null
  if (value.pending !== null && value.pending !== undefined && !isPendingJournal(value.pending)) {
    throw new CliError("failed", "The installation state's update journal is malformed, so mehen cannot tell which binary it describes.", { command: "mehen doctor --json", say: `Run mehen doctor --json to see it, then stop. ${HUMAN_REPAIR}` })
  }
  const check = isObject(value.check) && isString(value.check.at) && isString(value.check.nextAt) && isString(value.check.base) && isNullableString(value.check.latest) && isNullableString(value.check.error) ? { at: value.check.at, nextAt: value.check.nextAt, base: value.check.base, latest: value.check.latest, error: value.check.error, highestAnswered: isReleaseVersion(value.check.highestAnswered) ? value.check.highestAnswered : null } : null
  const vault: Record<string, VaultAdvice> = {}
  if (isObject(value.vault)) for (const [origin, advice] of Object.entries(value.vault)) if (isAdvice(advice)) vault[origin] = { minimum: advice.minimum, recommended: advice.recommended, seenAt: advice.seenAt }
  const last = value.lastUpdate
  const lastUpdate = isObject(last) && isString(last.at) && isString(last.from) && isString(last.to) && ["ok", "ok_skills_failed", "failed"].includes(last.result as string) && isNullableString(last.reason) && Array.isArray(last.skills) ? (last as InstallState["lastUpdate"]) : null
  return {
    v: 1,
    installed: isInstalledRecord(value.installed) ? value.installed : null,
    previous: isInstalledRecord(value.previous) ? value.previous : null,
    highestSeen: isString(value.highestSeen) ? value.highestSeen : null,
    holdBelow: isString(value.holdBelow) ? value.holdBelow : null,
    pending: isPendingJournal(value.pending) ? value.pending : null,
    check,
    vault,
    lastUpdate,
  }
}

// null when there is no state file (or it is not a plain file: a link is
// never followed). A malformed journal refuses (parseInstallState).
export async function readInstallState(install: Installation): Promise<InstallState | null> {
  let text: string
  try {
    const info = await lstat(install.files.state)
    if (!info.isFile()) return null
    text = await readFile(install.files.state, "utf8")
  } catch {
    return null
  }
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    return null
  }
  return parseInstallState(value)
}

// Temp file then rename, 0600. Every caller holds the lock.
export async function writeInstallState(install: Installation, state: InstallState): Promise<void> {
  await writePrivateAtomic(install.files.state, `${JSON.stringify(state, null, 2)}\n`)
}

export async function writePrivateAtomic(path: string, text: string, mode = 0o600): Promise<void> {
  const temp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`
  try {
    await writeFile(temp, text, { mode, flag: "wx" })
    await chmod(temp, mode)
    await rename(temp, path)
  } catch (error) {
    await rm(temp, { force: true })
    throw error
  }
}

// --- the lock -------------------------------------------------------------

export type LockHolder = { pid: number; boot: string; at: string; by: string; live: boolean }
export type LockBy = "auto" | "manual" | "heal" | "rollback" | "advice"

const LOCK_WAIT_MS = 10_000
// A real holder writes its owner within milliseconds of mkdir; a lock with no
// parseable owner for this long was left by a process killed in between.
export const OWNERLESS_GRACE_MS = 10 * 60_000
const OWNER_FILE = "owner.json"

let cachedBoot: string | null = null

// This boot's identity, in the form the installer writes too:
// `linux:<boot_id>` or `darwin:<kern.boottime seconds>`; "" when unknown,
// and an unknown boot on either side never makes a lock stale.
export function bootId(): string {
  if (cachedBoot !== null) return cachedBoot
  let boot = ""
  try {
    if (process.platform === "linux") boot = `linux:${readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim()}`
    else if (process.platform === "darwin") {
      const out = spawnSync("/usr/sbin/sysctl", ["-n", "kern.boottime"], { encoding: "utf8" }).stdout ?? ""
      const sec = /sec = (\d+)/.exec(out)?.[1]
      if (sec) boot = `darwin:${sec}`
    }
  } catch {
    boot = ""
  }
  cachedBoot = boot
  return boot
}

export function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    // EPERM: the process exists and belongs to someone else.
    return (error as { code?: string }).code !== "ESRCH"
  }
}

// A holder is stale only when its pid is gone or it was written on another
// boot; never by age. An owner file that cannot be read (being written, or
// left by a crash between mkdir and write) reads as pid 0, live: whether the
// grace period has passed is ownerlessPastGrace's to say.
function holderFrom(text: string | null): LockHolder {
  let value: unknown = null
  try {
    value = text === null ? null : JSON.parse(text)
  } catch {
    value = null
  }
  if (!isObject(value) || typeof value.pid !== "number" || !Number.isSafeInteger(value.pid) || value.pid <= 0) return { pid: 0, boot: "", at: "", by: "unknown", live: true }
  const boot = isString(value.boot) ? value.boot : ""
  const mine = bootId()
  const otherBoot = boot !== "" && mine !== "" && boot !== mine
  return { pid: value.pid, boot, at: isString(value.at) ? value.at : "", by: isString(value.by) ? value.by : "unknown", live: !otherBoot && pidAlive(value.pid) }
}

async function readOwner(lock: string): Promise<string | null> {
  try {
    return await readFile(join(lock, OWNER_FILE), "utf8")
  } catch {
    return null
  }
}

function notALock(install: Installation): CliError {
  return new CliError("failed", `${install.files.lock} is not a lock directory mehen made, so the installation cannot be locked.`, { say: `Move ${install.files.lock} aside, then run the command again.` })
}

// The lock as one contender saw it: the owner text, and the directory's
// identity and mtime at that moment.
export type LockObservation = { text: string | null; dev: number; ino: number; mtimeMs: number }

export async function observeLock(install: Installation): Promise<LockObservation | null> {
  const info = await lstat(install.files.lock).catch(() => null)
  if (info === null) return null
  if (!info.isDirectory()) throw notALock(install)
  return { text: await readOwner(install.files.lock), dev: info.dev, ino: info.ino, mtimeMs: info.mtimeMs }
}

// Age is by mtime only, never ctime or birthtime; an mtime in the future is
// not past grace.
function pastGrace(mtimeMs: number, now: number): boolean {
  return now - mtimeMs > OWNERLESS_GRACE_MS
}

// An owner file that is missing, or was last written over the grace period ago.
async function ownerFilePastGrace(lock: string, now: number): Promise<boolean> {
  try {
    return pastGrace((await lstat(join(lock, OWNER_FILE))).mtimeMs, now)
  } catch (error) {
    return (error as { code?: string }).code === "ENOENT"
  }
}

// A lock with no parseable owner is stale once the younger of its directory
// and its owner file is past the grace period, so any recent write counts.
async function observedHolder(install: Installation, observed: LockObservation): Promise<LockHolder> {
  const holder = holderFrom(observed.text)
  if (holder.pid !== 0) return holder
  const now = Date.now()
  return { ...holder, live: !(pastGrace(observed.mtimeMs, now) && (await ownerFilePastGrace(install.files.lock, now))) }
}

export async function lockHolder(install: Installation): Promise<LockHolder | null> {
  const observed = await observeLock(install)
  if (observed === null) return null
  const holder = await observedHolder(install, observed)
  // A reclamation in progress, or one abandoned mid-way, is held.
  return (await lockGuardPresent(install)) ? { ...holder, live: true } : holder
}

// The reclamation guard (shared with tools/release/install.sh): a stale lock
// is never moved or emptied. A contender that judged it stale makes
// `.mehen.update.lock/reap/` with mkdir; only that winner re-reads the owner
// and, when it is still the stale record it saw in the same directory,
// replaces owner.json in place by rename, so the lock path is never free
// between two holders. A guard that already exists (another reclaimer, or
// one that died mid-way) means held: it is never removed by age, only by a
// human.
export const RECLAIM_GUARD = "reap"

// An ownerless observation is reclaimable only past the grace period. Under
// the guard the directory's own mtime is not read again, as making the guard
// set it; the same directory and an owner file still past grace stand for it.
export async function reclaimStale(install: Installation, observed: LockObservation, by: LockBy, nonce: string): Promise<boolean> {
  const ownerless = holderFrom(observed.text).pid === 0
  if (ownerless && !pastGrace(observed.mtimeMs, Date.now())) return false
  const guard = join(install.files.lock, RECLAIM_GUARD)
  try {
    await mkdir(guard, { mode: 0o700 })
  } catch {
    return false
  }
  try {
    const current = await readOwner(install.files.lock)
    if (current !== observed.text) return false
    const info = await lstat(install.files.lock).catch(() => null)
    if (info === null || info.dev !== observed.dev || info.ino !== observed.ino) return false
    if (ownerless ? !(await ownerFilePastGrace(install.files.lock, Date.now())) : holderFrom(current).live) return false
    const temp = join(install.files.lock, `${OWNER_FILE}.${process.pid}.${randomBytes(4).toString("hex")}`)
    const owner = { pid: process.pid, boot: bootId(), at: new Date().toISOString(), by, nonce }
    await writeFile(temp, `${JSON.stringify(owner)}\n`, { mode: 0o600, flag: "wx" })
    await rename(temp, join(install.files.lock, OWNER_FILE))
    return true
  } finally {
    // The guard goes only after the owner is ours (or nothing changed), so a
    // contender with an old observation finds either the guard or a live owner.
    await rm(guard, { recursive: true, force: true }).catch(() => {})
  }
}

export async function lockGuardPresent(install: Installation): Promise<boolean> {
  return lstat(join(install.files.lock, RECLAIM_GUARD)).then(() => true, () => false)
}

async function tryAcquire(install: Installation, by: LockBy, nonce: string): Promise<{ ok: true } | { ok: false; holder: LockHolder }> {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      await mkdir(install.files.lock, { mode: 0o700 })
    } catch (error) {
      if ((error as { code?: string }).code !== "EEXIST") throw error
      const observed = await observeLock(install)
      if (observed === null) continue
      const holder = await observedHolder(install, observed)
      if (holder.live || (await lockGuardPresent(install))) return { ok: false, holder: { ...holder, live: true } }
      if (await reclaimStale(install, observed, by, nonce)) {
        if (holder.pid === 0) await appendUpdateLog(install, { event: "lock", result: "reclaimed", reason: "ownerless" })
        return { ok: true }
      }
      // Lost the reclamation: whoever won holds it now, or it went away.
      if ((await lstat(install.files.lock).catch(() => null)) === null) continue
      return { ok: false, holder: { ...holderFrom(await readOwner(install.files.lock)), live: true } }
    }
    const owner = { pid: process.pid, boot: bootId(), at: new Date().toISOString(), by, nonce }
    await writeFile(join(install.files.lock, OWNER_FILE), `${JSON.stringify(owner)}\n`, { mode: 0o600, flag: "wx" })
    return { ok: true }
  }
  const holder = await lockHolder(install)
  return { ok: false, holder: holder ?? { pid: 0, boot: "", at: "", by: "unknown", live: true } }
}

async function releaseLock(install: Installation, nonce: string): Promise<void> {
  const text = await readOwner(install.files.lock)
  try {
    if (text === null || (JSON.parse(text) as { nonce?: unknown }).nonce !== nonce) return
  } catch {
    return
  }
  await rm(join(install.files.lock, OWNER_FILE), { force: true })
  await rm(install.files.lock, { recursive: true, force: true })
}

// The one lock of an installation: `mkdir` of `.mehen.update.lock/` with
// `owner.json` { pid, boot, at, by }. Waits up to 10 s for a live holder,
// or not at all with { wait: false }; a stale holder is reaped.
export async function withInstallLock<T>(install: Installation, by: LockBy, fn: () => Promise<T>, options?: { wait: false } | { signal: AbortSignal }): Promise<{ ok: true; value: T } | { ok: false; holder: LockHolder }> {
  const nonce = randomBytes(8).toString("hex")
  const deadline = options && "wait" in options ? 0 : Date.now() + LOCK_WAIT_MS
  const signal = options && "signal" in options ? options.signal : undefined
  while (true) {
    const got = await tryAcquire(install, by, nonce)
    if (got.ok) break
    if (Date.now() >= deadline || signal?.aborted) return got
    await Bun.sleep(200)
  }
  try {
    return { ok: true, value: await fn() }
  } finally {
    await releaseLock(install, nonce)
  }
}

// --- the vault's advice ---------------------------------------------------

// Under the lock with zero wait: held means skipped, and the advice is
// re-sent on the next response. It re-reads the state under the lock and
// rewrites only `vault`, so a stale snapshot never erases the journal.
export async function recordVaultAdvice(install: Installation, origin: string, advice: { minimum: string; recommended: string | null }): Promise<void> {
  await withInstallLock(install, "advice", async () => {
    const state = (await readInstallState(install)) ?? freshInstallState()
    const known = state.vault[origin]
    if (known && known.minimum === advice.minimum && known.recommended === advice.recommended) return
    state.vault[origin] = { minimum: advice.minimum, recommended: advice.recommended, seenAt: new Date().toISOString() }
    await writeInstallState(install, state)
  }, { wait: false }).catch(() => {})
}

// True when a recorded minimum (or, with `recommended`, a recommended
// version) from any vault is above `version`.
export function vaultAhead(state: Pick<InstallState, "vault">, version: string, field: "minimum" | "recommended"): boolean {
  return vaultAdviceAbove(state, version, field) !== null
}

// The highest minimum (or recommended version) any vault advertised above
// `version`, with the vault that did; null when none is above it.
export function vaultAdviceAbove(state: Pick<InstallState, "vault">, version: string, field: "minimum" | "recommended"): { origin: string; version: string } | null {
  let best: { origin: string; version: string } | null = null
  for (const [origin, advice] of Object.entries(state.vault)) {
    const wanted = field === "minimum" ? advice.minimum : advice.recommended
    try {
      if (wanted !== null && compareVersions(wanted, version) > 0 && (best === null || compareVersions(wanted, best.version) > 0)) best = { origin, version: wanted }
    } catch {
      // A version this build cannot compare is no advice.
    }
  }
  return best
}

// --- the log --------------------------------------------------------------

const LOG_LIMIT = 64 * 1024

// One JSON line per event, 0600; past 64 KB the file keeps its last 200
// lines. No secret, no slot path is ever logged.
export async function appendUpdateLog(install: Installation, event: Record<string, unknown>): Promise<void> {
  try {
    await trimUpdateLog(install)
    await appendFile(install.files.log, `${JSON.stringify({ at: new Date().toISOString(), pid: process.pid, ...event })}\n`, { mode: 0o600 })
  } catch {
    // The log is best effort; it never fails an update.
  }
}

export async function trimUpdateLog(install: Installation): Promise<void> {
  const info = await lstat(install.files.log).catch(() => null)
  if (info === null || !info.isFile() || info.size <= LOG_LIMIT) return
  const lines = (await readFile(install.files.log, "utf8")).split("\n").filter(Boolean).slice(-200)
  await writePrivateAtomic(install.files.log, `${lines.join("\n")}\n`)
}

// The log opened for append, for the background child's stdout and stderr.
export async function openUpdateLog(install: Installation): Promise<number> {
  await trimUpdateLog(install).catch(() => {})
  return openSync(install.files.log, "a", 0o600)
}

// --- settings, mode and the doctor rows -----------------------------------

export type Settings = { autoUpdate: boolean; mcpHandover: boolean }

const DEFAULT_SETTINGS: Settings = { autoUpdate: true, mcpHandover: true }

// <root>/settings.json, human-written; only an explicit `"autoUpdate":
// false` switches updating off, only an explicit `"mcpHandover": false`
// switches the MCP handover off, and anything unreadable is the default.
export async function readSettings(env: Env): Promise<Settings> {
  try {
    const path = join(resolveHome(env).root, "settings.json")
    if (!lstatSync(path).isFile()) return DEFAULT_SETTINGS
    const value: unknown = JSON.parse(await readFile(path, "utf8"))
    if (!isObject(value)) return DEFAULT_SETTINGS
    return { autoUpdate: value.autoUpdate !== false, mcpHandover: value.mcpHandover !== false }
  } catch {
    return DEFAULT_SETTINGS
  }
}

export function autoUpdateMode(env: Env, writable: boolean, settings: { autoUpdate: boolean }, build: BuildKind = BUILD_KIND): AutoUpdateMode {
  if (env.MEHEN_NO_AUTO_UPDATE === "1" || !settings.autoUpdate) return "off"
  if (env.CI) return "ci"
  if (build !== "release") return "dev"
  if (!writable) return "read-only"
  return "on"
}

// The MCP handover is on by default and needs automatic updates on and a
// runtime with execve: anything else, or `"mcpHandover": false`, keeps it
// off, with the first reason that does.
export function mcpHandoverDecision(env: Env, mode: AutoUpdateMode, settings: Settings, canExec: boolean = typeof process.execve === "function"): McpHandover {
  if (mode === "off") return { handover: "off", reason: env.MEHEN_NO_AUTO_UPDATE === "1" ? "MEHEN_NO_AUTO_UPDATE is set" : "autoUpdate is false in settings.json" }
  if (mode === "ci") return { handover: "off", reason: "CI is set" }
  if (mode === "dev") return { handover: "off", reason: "a development build" }
  if (mode === "read-only") return { handover: "off", reason: "the install directory is not writable" }
  if (!canExec) return { handover: "off", reason: "this runtime cannot switch in place" }
  if (!settings.mcpHandover) return { handover: "off", reason: "mcpHandover is false in settings.json" }
  return { handover: "on" }
}

// What a `mehen mcp` started now with `env` would decide. `installDir:
// false` leaves the install directory out: the handover's acceptance check
// runs from a private copy, whose directory says nothing of the
// installation, and the old image judged the real one itself.
export async function mcpHandoverNow(env: Env, options: { installDir?: boolean } = {}): Promise<McpHandover> {
  const install = installation(selfExecutable(env) ?? process.execPath)
  const settings = await readSettings(env)
  const writable = options.installDir === false || (await installDirWritable(install))
  return mcpHandoverDecision(env, autoUpdateMode(env, writable, settings, selfBuild(env)), settings)
}

export function onPathCheck(install: Installation, env: Env): DoctorCheck {
  const entries = (env.PATH ?? "").split(":").filter(Boolean)
  const on = entries.some((entry) => {
    if (resolve(entry) === install.dir) return true
    try {
      return realpathSync(entry) === install.dir
    } catch {
      return false
    }
  })
  if (on) return { check: "on_path", status: "ok", detail: `${install.dir} is on PATH.` }
  return {
    check: "on_path",
    status: "warn",
    detail: `${install.dir} is not on this shell's PATH; ${install.binary} runs mehen by its absolute path.`,
    next: { say: `Use ${install.binary} by its absolute path in this session, or open a new login shell after the installer's PATH line.` },
  }
}

// What status and doctor embed: this build, the installation it runs
// from and that installation's state, or the fresh state when none exists.
export async function cliState(env: Env): Promise<CliState> {
  const self = selfExecutable(env)
  const install = installation(self ?? process.execPath)
  let state: InstallState | null = null
  try {
    state = self === null ? null : await readInstallState(install)
  } catch {
    state = null
  }
  const writable = await installDirWritable(install)
  const settings = await readSettings(env)
  const mode = autoUpdateMode(env, writable, settings, selfBuild(env))
  const { v: _v, ...rest } = state ?? freshInstallState()
  return { version: VERSION, commit: BUILD_COMMIT, build: BUILD_KIND, path: install.binary, autoUpdate: mode, mcpHandover: mcpHandoverDecision(env, mode, settings), ...rest }
}

const LONG_HOLD_MS = 3_600_000

// Doctor's `update` row from the state cliState embeds and the lock's
// holder: below a vault's minimum fails, as that vault refuses this
// version; an interrupted or refused journal, a failed update, skills that
// could not be refreshed, a failed check, a lock held for over an hour and
// a version below a vault's recommended one are warnings; a long-held lock
// is reported, never taken.
// What doctor could not read: the state file (a malformed journal), the lock
// path, and a reclamation guard left in the lock. Each is
// reported, never repaired by doctor: no guard or lock path is removed, no
// journal deleted. A lock with no readable owner is reported only for its
// grace period, after which the next mehen to need the lock takes it over.
export type InstallProblems = { state?: string; stateError?: string | null; lockError?: string | null; guard?: boolean }

export function updateDoctorCheck(cli: CliState, holder: LockHolder | null, lock: string, now = Date.now(), problems: InstallProblems = {}): DoctorCheck {
  const inspect = { say: `Ask the human to inspect ${lock}; mehen does not take it over or remove it.` }
  const graceMinutes = OWNERLESS_GRACE_MS / 60_000
  const minimum = vaultAdviceAbove(cli, cli.version, "minimum")
  if (minimum) return { check: "update", status: "fail", detail: `${minimum.origin} refuses mehen ${cli.version}: its minimum is ${minimum.version}.`, error: "cli_outdated", next: { command: "mehen update --json", say: `Run mehen update --json to install the latest release; ${minimum.origin} refuses mehen below ${minimum.version}.` } }
  if (problems.lockError) return { check: "update", status: "warn", detail: problems.lockError, next: inspect }
  if (problems.stateError) return { check: "update", status: "warn", detail: `The installation state${problems.state ? ` ${problems.state}` : ""} cannot be read: ${problems.stateError}`, next: { say: HUMAN_REPAIR } }
  if (problems.guard) return { check: "update", status: "warn", detail: `A reclamation of the installation lock ${lock} did not finish; the lock is held until a human inspects it.`, next: inspect }
  if (holder?.live && holder.pid === 0) return { check: "update", status: "warn", detail: `The installation lock ${lock} has no readable owner; mehen takes it over once it has stayed so for ${graceMinutes} minutes.`, next: { say: `Leave ${lock} alone; mehen takes it over itself once it has had no readable owner for ${graceMinutes} minutes.` } }
  if (holder?.live && holder.at && now - Date.parse(holder.at) > LONG_HOLD_MS) {
    return { check: "update", status: "warn", detail: `An update has been running since ${holder.at} (pid ${holder.pid}).`, next: { say: `Leave it to finish; if pid ${holder.pid} is gone, remove ${lock}.` } }
  }
  const last = cli.lastUpdate
  if (cli.pending) {
    const refused = last?.result === "failed" && last.reason ? ` The last run stopped: ${last.reason}.` : ""
    return { check: "update", status: "warn", detail: `An update to ${cli.pending.target.version} is unfinished; the next update run finishes or undoes it.${refused}`, next: refused ? { say: HUMAN_REPAIR } : { command: "mehen update --json", say: "Run mehen update --json to finish it now." } }
  }
  if (last?.result === "failed") return { check: "update", status: "warn", detail: `The last update to ${last.to} failed: ${last.reason ?? "no reason recorded"}.`, next: { command: "mehen update --json", say: "Run mehen update --json to try again and see why." } }
  if (last?.result === "ok_skills_failed") {
    const failed = last.skills.filter((s) => s.status === "failed").map((s) => `${s.path}${s.reason ? ` (${s.reason})` : ""}`)
    return { check: "update", status: "warn", detail: `mehen ${last.to} is installed, but ${failed.length} skill${failed.length === 1 ? "" : "s"} could not be refreshed: ${failed.join("; ")}.`, next: { command: "mehen setup --json", say: "Run mehen setup --json and fix what it reports as failed." } }
  }
  if (cli.check?.error) return { check: "update", status: "warn", detail: `The last release check failed (${cli.check.error}); the next is due after ${cli.check.nextAt}.` }
  const recommended = vaultAdviceAbove(cli, cli.version, "recommended")
  if (recommended) return { check: "update", status: "warn", detail: `Update available: ${recommended.origin} recommends mehen ${recommended.version} or later; this is ${cli.version}.`, next: { command: "mehen update --json", say: "Run mehen update --json to install the latest release." } }
  const checked = cli.check ? `; last checked ${cli.check.at}, latest ${cli.check.latest ?? "unknown"}` : "; not checked yet"
  return { check: "update", status: "ok", detail: `mehen ${cli.version}, automatic updates ${cli.autoUpdate}${checked}.` }
}
