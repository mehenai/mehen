// mehen update and the background updater. One path for both: lock; recover or reconcile; fetch and verify
// the signed manifest; download and verify both hashes; smoke-test the
// staged binary; keep the previous binary with its signed metadata; write
// the journal; one rename; complete the journal. A kill at any point leaves
// the old bytes or the new ones, and a state that says which.

import { spawn, spawnSync } from "node:child_process"
import { closeSync } from "node:fs"
import { copyFile, lstat, mkdtemp, readFile, readdir, rename, rm, writeFile } from "node:fs/promises"
import { basename, isAbsolute, join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { canonicalJson } from "@mehen/protocol/canonical-json"
import type { SignedManifest } from "@mehen/protocol/release-manifest"
import type { Command } from "./command.ts"
import type { Env } from "./config.ts"
import { CliError, installedBinaryRequired, toCliError, usageError } from "./errors.ts"
import {
  type InstallState,
  type InstalledRecord,
  type Installation,
  HUMAN_REPAIR,
  type JournalStep,
  type LockHolder,
  type PendingJournal,
  appendUpdateLog,
  autoUpdateMode,
  freshInstallState,
  installDirWritable,
  installation,
  lockHolder,
  openUpdateLog,
  readInstallState,
  readSettings,
  selfBuild,
  selfExecutable,
  vaultAhead,
  withInstallLock,
  writeInstallState,
  writePrivateAtomic,
} from "./install-state.ts"
import { printJson, printLine } from "./output.ts"
import { compareVersions, downloadBase, releaseBytes, releaseTrust, sha256, verifiedBinary, verifiedRelease, type ReleaseFetch } from "./release-client.ts"
import type { SkillReport } from "./setup/skills.ts"
import { BUILD_COMMIT, BUILD_LIBC, type BuildKind, type Libc, VERSION } from "./version.ts"

export type UpdateReport = { current: string; latest: string | null; available: boolean; updated: boolean; path: string; result: "updated" | "current" | "locked" | "held" | "rolled_back"; holder?: LockHolder; from?: string; to?: string; skills?: SkillReport[] }
export type UpdateCheck = { current: string; latest: string | null; available: boolean; path: string; installed: InstalledRecord | null; pending: PendingJournal | null }

// The points a kill can land between, in order (src/update.test.ts kills
// the updater at each one).
export type UpdateStep = "locked" | "recovered" | "fetched" | "staged" | "smoked" | "previous" | "journal" | "renamed" | JournalStep | "done"

export type UpdateOptions = {
  env: Env
  install: Installation
  by: "auto" | "manual" | "heal"
  // The running release; the build kind this process acts as.
  current?: string
  commit?: string | null
  build?: BuildKind
  check?: boolean
  force?: boolean
  version?: string | null
  rollback?: boolean
  // false: a live holder means `locked` at once (the background child).
  wait?: boolean
  platform?: NodeJS.Platform
  arch?: string
  // The libc of the binary to fetch on Linux: this build's own by default.
  libc?: Libc
  fetch?: ReleaseFetch
  now?: () => number
  smoke?: (path: string) => Promise<unknown>
  refreshSkills?: (binary: string) => Promise<SkillReport[]>
  onStep?: (step: UpdateStep) => void | Promise<void>
  // A total deadline (the foreground heal's 90 s): every wait, download and
  // child stops at it; before the rename nothing has changed, after it the
  // journal keeps the steps left for the next run.
  signal?: AbortSignal
}

function stopped(): CliError {
  return new CliError("failed", "The update stopped at its time limit; the next update run finishes or undoes what it started.")
}

function guard(options: { signal?: AbortSignal }): void {
  if (options.signal?.aborted) throw stopped()
}

// A child under a timeout and the update's deadline: killed at either, and
// never waited on past the deadline, even when a grandchild holds its pipe.
async function runChild(argv: string[], env: Record<string, string | undefined>, timeoutMs: number, signal?: AbortSignal): Promise<{ code: number; out: string }> {
  if (signal?.aborted) throw stopped()
  const proc = Bun.spawn(argv, { env, stdin: "ignore", stdout: "pipe", stderr: "ignore", timeout: timeoutMs })
  let stop: (() => void) | null = null
  const aborted = new Promise<never>((_, reject) => {
    stop = () => {
      proc.kill("SIGKILL")
      reject(stopped())
    }
    signal?.addEventListener("abort", stop, { once: true })
  })
  aborted.catch(() => {})
  try {
    const out = await Promise.race([new Response(proc.stdout).text(), aborted])
    const code = await Promise.race([proc.exited, aborted])
    return { code, out }
  } finally {
    if (stop) signal?.removeEventListener("abort", stop)
  }
}

// The release fetcher bound to the update's deadline.
function boundFetch(options: UpdateOptions): ReleaseFetch {
  const fetcher = options.fetch ?? fetch
  const signal = options.signal
  if (!signal) return fetcher
  return (url, init) => fetcher(url, { ...init, signal: init?.signal ? AbortSignal.any([init.signal, signal]) : signal })
}

const CHECK_INTERVAL_MS = 3_600_000
const RETRY_INTERVAL_MS = 15 * 60_000
const SPREAD_MS = 5 * 60_000
const SMOKE_TIMEOUT_MS = 10_000
const SKILLS_TIMEOUT_MS = 60_000
const MAX_SKILLS = 32
const STAGING_PREFIX = ".mehen-update."
const JOURNAL_STEPS: JournalStep[] = ["record", "receipt", "retire-helper", "skills"]
const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?$/

const notChanged = "The installed binary was not changed."

async function hashFile(path: string): Promise<{ sha256: string; size: number }> {
  const bytes = await readFile(path)
  return { sha256: sha256(bytes), size: bytes.length }
}

async function exists(path: string): Promise<boolean> {
  return lstat(path).then(() => true, () => false)
}

function platformBinary(options: UpdateOptions): { platform: "darwin" | "linux"; binary: string } {
  const platform = options.platform ?? process.platform
  const requested = options.arch ?? process.arch
  // Rosetta: an x64 process on Apple silicon installs the arm64 binary.
  const arch = options.arch === undefined && platform === "darwin" && requested === "x64" && spawnSync("/usr/sbin/sysctl", ["-n", "hw.optional.arm64"], { encoding: "utf8" }).stdout?.trim() === "1" ? "arm64" : requested
  if (platform !== "darwin" && platform !== "linux") throw usageError("Updates support macOS and Linux only.")
  if (arch !== "arm64" && arch !== "x64") throw usageError("Updates support arm64 and x64 only.")
  const musl = platform === "linux" && (options.libc ?? BUILD_LIBC) === "musl"
  return { platform, binary: `mehen-${platform}-${arch}${musl ? "-musl" : ""}` }
}

// `<staged> version --json` under MEHEN_UPDATE_CHILD=1 with a 10 s budget.
async function smokeRun(path: string, env: Env, signal?: AbortSignal): Promise<unknown> {
  const { code, out } = await runChild([path, "version", "--json"], { PATH: env.PATH ?? process.env.PATH ?? "", HOME: env.HOME ?? "", MEHEN_UPDATE_CHILD: "1" }, SMOKE_TIMEOUT_MS, signal)
  if (code !== 0) throw new Error(`exit ${code}`)
  return JSON.parse(out) as unknown
}

async function smokeTest(options: UpdateOptions, path: string, want: { version: string; commit: string | null }, platform: "darwin" | "linux"): Promise<void> {
  let info: unknown
  try {
    info = await (options.smoke ?? ((p: string) => smokeRun(p, options.env, options.signal)))(path)
  } catch (error) {
    if (options.signal?.aborted) throw stopped()
    throw new CliError("failed", `The new mehen did not run its smoke test (${error instanceof Error ? error.message : String(error)}). ${notChanged}`)
  }
  const helper = platform === "darwin" ? "embedded" : "none"
  const v = typeof info === "object" && info !== null ? (info as Record<string, unknown>) : {}
  if (v.version !== want.version || (want.commit !== null && v.commit !== want.commit) || v.build !== "release" || v.helper !== helper) {
    throw new CliError("failed", `The new mehen's version --json does not match the signed release ${want.version} for this platform. ${notChanged}`)
  }
}

// The default skills step: the new binary's own skills-only setup, its
// structured report kept verbatim.
async function refreshSkillsWith(binary: string, env: Env, signal?: AbortSignal): Promise<SkillReport[]> {
  try {
    const { out } = await runChild([binary, "setup", "--json"], { ...env, MEHEN_SETUP_SKILLS_ONLY: "1", MEHEN_UPDATE_CHILD: "1" }, SKILLS_TIMEOUT_MS, signal)
    const report = JSON.parse(out) as { skills?: unknown }
    if (!Array.isArray(report.skills)) throw new Error("no skills report")
    return report.skills.filter((s): s is SkillReport => typeof s === "object" && s !== null && typeof (s as SkillReport).path === "string" && typeof (s as SkillReport).status === "string")
  } catch (error) {
    // Stopped at the deadline: the skills step stays in the journal.
    if (signal?.aborted) throw stopped()
    return [{ path: binary, status: "failed", reason: `the new mehen's skills refresh did not report (${error instanceof Error ? error.message : String(error)}); run mehen setup --json` }]
  }
}

function stripQuarantine(path: string): void {
  if (process.platform !== "darwin") return
  spawnSync("/usr/bin/xattr", ["-d", "com.apple.quarantine", path], { stdio: "ignore" })
}

async function holdsStaging(install: Installation): Promise<boolean> {
  return (await readdir(install.dir).catch(() => [] as string[])).some((name) => name.startsWith(STAGING_PREFIX))
}

async function removeStaging(install: Installation): Promise<void> {
  for (const name of await readdir(install.dir).catch(() => [] as string[])) {
    if (name.startsWith(STAGING_PREFIX)) await rm(join(install.dir, name), { recursive: true, force: true })
  }
}

function manifestDigest(manifest: SignedManifest): string {
  return sha256(new TextEncoder().encode(canonicalJson(manifest)))
}

// What a check now answers: the highest version any recorded vault advice
// names, minimum or recommended, or what an earlier check answered when that
// is higher. Advice that went down and came back is not new advice. A
// version this build cannot compare, stored or advised, counts as none.
function highestAdvice(state: InstallState): string | null {
  let highest: string | null = null
  const versions = [state.check?.highestAnswered ?? null, ...Object.values(state.vault).flatMap((advice) => [advice.minimum, advice.recommended])]
  for (const version of versions) {
    try {
      if (version !== null && compareVersions(version, highest ?? version) >= 0) highest = version
    } catch {}
  }
  return highest
}

function maxVersion(a: string | null, b: string): string {
  if (a === null) return b
  try {
    return compareVersions(a, b) >= 0 ? a : b
  } catch {
    return b
  }
}

// Completes the journal's remaining steps, each removed as it finishes, so
// a kill resumes at the next one. Returns the skills report, when the
// skills step ran.
async function completeJournal(options: UpdateOptions, state: InstallState): Promise<SkillReport[] | null> {
  const { install } = options
  const pending = state.pending
  if (pending === null) return null
  let skills: SkillReport[] | null = null
  const now = options.now ?? Date.now
  for (const step of [...pending.steps]) {
    guard(options)
    if (step === "record") {
      state.installed = { ...pending.target, at: new Date(now()).toISOString() }
      state.highestSeen = maxVersion(state.highestSeen, pending.target.version)
    } else if (step === "receipt") {
      await writePrivateAtomic(install.files.receipt, `${pending.target.sha256}\n`, 0o644)
    } else if (step === "retire-helper") {
      await retireHelper(install)
    } else if (step === "skills") {
      skills = (await (options.refreshSkills ?? ((b: string) => refreshSkillsWith(b, options.env, options.signal)))(install.binary)).slice(0, MAX_SKILLS)
      guard(options)
      const failed = skills.filter((s) => s.status === "failed")
      state.lastUpdate = {
        at: new Date(now()).toISOString(),
        from: state.previous?.version ?? options.current ?? VERSION,
        to: pending.target.version,
        result: failed.length ? "ok_skills_failed" : "ok",
        reason: failed.length ? `${failed.length} skill${failed.length === 1 ? "" : "s"} could not be refreshed` : null,
        skills,
      }
    }
    pending.steps = pending.steps.filter((s) => s !== step)
    if (pending.steps.length === 0) state.pending = null
    await writeInstallState(install, state)
    await options.onStep?.(step)
  }
  return skills
}

// The standalone helper 0.2.0 installed beside the binary: removed only
// when it and its receipt are plain files of this user and agree.
async function retireHelper(install: Installation): Promise<void> {
  const helper = join(install.dir, "mehen-se")
  const receipt = join(install.dir, ".mehen-se.sha256")
  const uid = process.getuid?.() ?? -1
  const [h, r] = await Promise.all([lstat(helper).catch(() => null), lstat(receipt).catch(() => null)])
  if (!h || !r || !h.isFile() || !r.isFile() || h.uid !== uid || r.uid !== uid) return
  const recorded = (await readFile(receipt, "utf8")).trim()
  if ((await hashFile(helper)).sha256 !== recorded) return
  await rm(helper, { force: true })
  await rm(receipt, { force: true })
}

// Under the lock, before anything else: a journal is
// finished or undone by the binary's hash; anything else is `unknown` and
// refuses. With no journal, a binary the state does not describe (the
// installer, a hand copy) is recorded as by "install" with no key.
async function recoverOrReconcile(options: UpdateOptions, state: InstallState): Promise<"finished" | "aborted" | "reconciled" | "none"> {
  const { install } = options
  const now = options.now ?? Date.now
  if (state.pending) {
    const disk = await hashFile(install.binary)
    if (disk.sha256 === state.pending.target.sha256) {
      await completeJournal(options, state)
      await removeStaging(install)
      return "finished"
    }
    if (disk.sha256 === state.pending.previousSha256 || disk.sha256 === state.installed?.sha256) {
      state.pending = null
      await removeStaging(install)
      await writeInstallState(install, state)
      return "aborted"
    }
    const reason = "the binary on disk is neither the previous nor the pending release"
    state.lastUpdate = { at: new Date(now()).toISOString(), from: state.installed?.version ?? options.current ?? VERSION, to: state.pending.target.version, result: "failed", reason, skills: [] }
    await writeInstallState(install, state)
    throw new CliError("failed", `The update cannot continue: ${reason}. Nothing was changed.`, { command: "mehen doctor --json", say: `Run mehen doctor --json to see it, then stop. ${HUMAN_REPAIR}` })
  }
  await removeStaging(install)
  if ((options.build ?? null) !== "release") return "none"
  const disk = await hashFile(install.binary)
  if (state.installed?.sha256 === disk.sha256) return "none"
  const old = state.installed
  if (old && (await exists(install.files.previous)) && (await hashFile(install.files.previous)).sha256 === old.sha256) {
    await writePrivateAtomic(install.files.previousMeta, `${JSON.stringify(old, null, 2)}\n`)
    state.previous = old
  }
  state.installed = { version: options.current ?? VERSION, commit: options.commit ?? BUILD_COMMIT, sha256: disk.sha256, size: disk.size, at: new Date(now()).toISOString(), by: "install", keyId: null, manifestSha256: null, manifest: null }
  const receipt = await readFile(install.files.receipt, "utf8").then((t) => t.trim(), () => null)
  if (receipt !== disk.sha256) await writePrivateAtomic(install.files.receipt, `${disk.sha256}\n`, 0o644)
  await writeInstallState(install, state)
  return "reconciled"
}

// The signed manifest and the key whose signature verified it.
async function fetchManifest(options: UpdateOptions, base: string): Promise<{ manifest: SignedManifest; keyId: string }> {
  const fetcher = boundFetch(options)
  const keys = releaseTrust(options.env, base, options.build ?? null)
  const bytes = await releaseBytes(options.version ? `${base}/v${options.version}/manifest.json` : `${base}/latest.json`, 1024 * 1024, fetcher)
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    throw new CliError("failed", "Invalid release manifest JSON.")
  }
  const verified = await verifiedRelease(value, keys)
  if (options.version && verified.manifest.version !== options.version) throw new CliError("failed", `The signed manifest names ${verified.manifest.version}, not the ${options.version} asked for. ${notChanged}`)
  return verified
}

// Keeps the binary being replaced as `.mehen.previous` with its record, by
// copy then one rename; the record has null key fields when it was never
// recorded as signed.
async function keepPrevious(install: Installation, record: InstalledRecord): Promise<void> {
  const temp = `${install.files.previous}.tmp-${process.pid}`
  await copyFile(install.binary, temp)
  await rename(temp, install.files.previous)
  await writePrivateAtomic(install.files.previousMeta, `${JSON.stringify(record, null, 2)}\n`)
}

// What recovery did with an interrupted update, for the refusal that may
// follow it (an offline check must not hide that the journal was settled);
// null when nothing was interrupted.
function recoveryNote(recovered: "finished" | "aborted" | "reconciled" | "none", interrupted: string | null, staged: boolean, state: InstallState, running: string): string | null {
  const installed = state.installed?.version ?? running
  if (recovered === "finished") return `The interrupted update to ${interrupted ?? installed} was finished first: mehen ${installed} is installed.`
  if (recovered === "aborted") return `The interrupted update${interrupted ? ` to ${interrupted}` : ""} was undone first: mehen ${installed} stays installed.`
  // No journal: the update stopped before it, or after completing it.
  if (recovered === "none" && staged) return `An interrupted update was cleaned up first (its staged download removed): mehen ${installed} is installed.`
  return null
}

// Stages, journals and renames `staged` in as `target`: the one operation
// that changes what `mehen` is.
async function swapIn(options: UpdateOptions, state: InstallState, staged: string, stage: string, target: InstalledRecord, current: InstalledRecord, step: (s: UpdateStep) => Promise<void>): Promise<SkillReport[] | null> {
  const { install } = options
  await keepPrevious(install, current)
  state.previous = current
  await step("previous")
  state.pending = { target, previousSha256: current.sha256, steps: [...JOURNAL_STEPS], since: new Date((options.now ?? Date.now)()).toISOString() }
  await writeInstallState(install, state)
  await step("journal")
  guard(options)
  try {
    await rename(staged, install.binary)
  } catch (error) {
    // The rename is atomic: the old binary is still in place, so the journal
    // describes nothing and the failure is recorded like any other.
    state.pending = null
    throw error
  }
  await step("renamed")
  await rm(stage, { recursive: true, force: true })
  return completeJournal(options, state)
}

// The binary on disk as a record: the state's when it describes these bytes,
// else what this process knows of itself.
async function currentRecord(options: UpdateOptions, state: InstallState): Promise<InstalledRecord> {
  const disk = await hashFile(options.install.binary)
  if (state.installed?.sha256 === disk.sha256) return state.installed
  return { version: options.current ?? VERSION, commit: options.commit ?? BUILD_COMMIT, sha256: disk.sha256, size: disk.size, at: new Date((options.now ?? Date.now)()).toISOString(), by: "install", keyId: null, manifestSha256: null, manifest: null }
}

async function rollback(options: UpdateOptions, state: InstallState, step: (s: UpdateStep) => Promise<void>, platform: "darwin" | "linux", binary: string): Promise<UpdateReport> {
  const { install } = options
  const refuse = () => new CliError("failed", "The previous binary cannot be verified, so it is not rolled back to; `mehen update --force --version <v> --json` installs a signed release, and anything else is the human's to repair.", { command: "mehen update --force --version <v> --json", say: `The previous binary has no signed record. A signed release may be installed with that command; otherwise ${HUMAN_REPAIR.charAt(0).toLowerCase()}${HUMAN_REPAIR.slice(1)}` })
  let record: unknown
  try {
    record = JSON.parse(await readFile(install.files.previousMeta, "utf8"))
  } catch {
    throw refuse()
  }
  const r = record as InstalledRecord
  if (typeof r !== "object" || r === null || typeof r.version !== "string" || typeof r.sha256 !== "string" || typeof r.size !== "number" || r.keyId === null || r.manifest === null || typeof r.manifest !== "object") throw refuse()
  const base = downloadBase(options.env)
  const keys = releaseTrust(options.env, base, options.build ?? null)
  let manifest: SignedManifest
  let keyId: string
  try {
    ;({ manifest, keyId } = await verifiedRelease(r.manifest, keys))
  } catch {
    throw refuse()
  }
  const file = manifest.files.find((f) => f.name === binary)
  if (manifest.version !== r.version || !file || file.sha256 !== r.sha256 || file.size !== r.size) throw refuse()
  const current = await currentRecord(options, state)
  const stage = await mkdtemp(join(install.dir, STAGING_PREFIX))
  try {
    const staged = join(stage, "mehen")
    await copyFile(install.files.previous, staged)
    const bytes = await hashFile(staged)
    if (bytes.sha256 !== r.sha256 || bytes.size !== r.size) throw refuse()
    await step("staged")
    await smokeTest(options, staged, { version: r.version, commit: manifest.commit }, platform)
    await step("smoked")
    const target: InstalledRecord = { ...r, keyId, manifestSha256: manifestDigest(manifest), manifest, at: new Date((options.now ?? Date.now)()).toISOString(), by: "rollback" }
    state.holdBelow = current.version
    const skills = await swapIn(options, state, staged, stage, target, current, step)
    return { current: current.version, latest: r.version, available: false, updated: true, path: install.binary, result: "rolled_back", from: current.version, to: r.version, ...(skills ? { skills } : {}) }
  } finally {
    await rm(stage, { recursive: true, force: true })
  }
}

async function underLock(options: UpdateOptions, platform: "darwin" | "linux", binary: string): Promise<UpdateReport> {
  const { install } = options
  const now = options.now ?? Date.now
  const step = async (s: UpdateStep) => {
    guard(options)
    await options.onStep?.(s)
  }
  await step("locked")
  const info = await lstat(install.binary).catch(() => null)
  if (!info || !info.isFile()) throw usageError("Refusing to replace a symlink or non-file executable.")
  const receipt = await lstat(install.files.receipt).catch(() => null)
  if (receipt && !receipt.isFile()) throw usageError("Refusing a symlink or non-file install receipt.")
  const state = (await readInstallState(install)) ?? freshInstallState()
  const interrupted = state.pending?.target.version ?? null
  const staged = await holdsStaging(install)
  const recovered = recoveryNote(await recoverOrReconcile(options, state), interrupted, staged, state, options.current ?? VERSION)
  await step("recovered")
  if (options.rollback) return rollback(options, state, step, platform, binary)

  const base = downloadBase(options.env)
  let manifest: SignedManifest
  let verifiedKey: string
  try {
    ;({ manifest, keyId: verifiedKey } = await fetchManifest(options, base))
  } catch (error) {
    const at = now()
    state.check = { at: new Date(at).toISOString(), nextAt: new Date(at + RETRY_INTERVAL_MS).toISOString(), base, latest: state.check?.latest ?? null, error: error instanceof Error ? error.message : String(error), highestAnswered: highestAdvice(state) }
    await writeInstallState(install, state)
    if (recovered === null) throw error
    // The same code (and exit), with what recovery already did said first.
    const failure = toCliError(error)
    throw new CliError(failure.code, `${recovered} ${failure.message}`, failure.next, failure.extras)
  }
  const seenBefore = state.highestSeen
  const at = now()
  state.check = { at: new Date(at).toISOString(), nextAt: new Date(at + CHECK_INTERVAL_MS + Math.floor(Math.random() * SPREAD_MS)).toISOString(), base, latest: manifest.version, error: null, highestAnswered: highestAdvice(state) }
  state.highestSeen = maxVersion(state.highestSeen, manifest.version)
  await writeInstallState(install, state)
  // From here a failure is recorded, so a release this machine cannot
  // install waits for the retry interval; before the download the phase is
  // the installation's own (its record, its directory).
  let from = options.current ?? VERSION
  let phase: "download" | "smoke" | "install" = "install"
  let stage: string | null = null
  try {
    await step("fetched")
    const current = await currentRecord(options, state)
    from = current.version
    const comparison = compareVersions(manifest.version, current.version)
    const report = { current: current.version, latest: manifest.version, available: comparison > 0, updated: false, path: install.binary }
    const file = manifest.files.find((f) => f.name === binary)
    // The running version is a floor of its own, never inferred from the
    // record of the bytes on disk: an older matching record must
    // not let an ordinary update go below the process doing it.
    const running = options.current ?? VERSION
    const aboveRunning = compareVersions(manifest.version, running)
    // Nothing to install: an earlier failed attempt no longer stands.
    const isCurrent = async (): Promise<UpdateReport> => {
      if (state.lastUpdate?.result === "failed") {
        state.lastUpdate = null
        await writeInstallState(install, state)
      }
      return { ...report, result: "current" }
    }
    if (!options.force) {
      if (comparison < 0 || aboveRunning < 0) {
        if (options.by === "manual") throw new CliError("denied", `Refusing to downgrade mehen from ${aboveRunning < 0 ? running : current.version} to ${manifest.version}. Use --force only if you intend to go back to that signed release.`)
        return isCurrent()
      }
      if (comparison === 0 || aboveRunning === 0) return isCurrent()
      if ((seenBefore !== null && compareVersions(manifest.version, seenBefore) < 0) || (state.holdBelow !== null && compareVersions(manifest.version, state.holdBelow) <= 0)) return { ...report, result: "held" }
    } else if (file && file.sha256 === current.sha256) {
      return isCurrent()
    }

    stage = await mkdtemp(join(install.dir, STAGING_PREFIX))
    phase = "download"
    const bytes = await verifiedBinary(base, manifest, binary, boundFetch(options))
    const staged = join(stage, "mehen")
    await writeFile(staged, bytes, { mode: 0o755 })
    stripQuarantine(staged)
    await step("staged")
    phase = "smoke"
    await smokeTest(options, staged, { version: manifest.version, commit: manifest.commit }, platform)
    await step("smoked")
    phase = "install"
    if (options.force && (comparison < 0 || aboveRunning < 0)) state.holdBelow = maxVersion(current.version, running)
    const target: InstalledRecord = { version: manifest.version, commit: manifest.commit, sha256: sha256(bytes), size: bytes.length, at: new Date(now()).toISOString(), by: options.by, keyId: verifiedKey, manifestSha256: manifestDigest(manifest), manifest }
    const skills = await swapIn(options, state, staged, stage, target, current, step)
    await step("done")
    return { ...report, updated: true, result: "updated", from: current.version, to: manifest.version, ...(skills ? { skills } : {}) }
  } catch (error) {
    // A failure before the journal, or a failed rename, leaves the old
    // binary; doctor shows it until a later run succeeds. A journal is the
    // next run's to settle, and neither a stop at the deadline nor a refused
    // downgrade is a failure of the release.
    const refused = error instanceof CliError && error.code === "denied"
    if (state.pending === null && !options.signal?.aborted && !refused) {
      state.lastUpdate = { at: new Date(now()).toISOString(), from, to: manifest.version, result: "failed", reason: failureCode(phase, error), skills: [] }
      await writeInstallState(install, state).catch(() => {})
    }
    throw error
  } finally {
    if (stage !== null) await rm(stage, { recursive: true, force: true })
  }
}

// The short reason a failed update records in `lastUpdate`: never the
// error's text, which can name paths or a server's answer.
function failureCode(phase: "download" | "smoke" | "install", error: unknown): string {
  if (phase === "smoke") return "smoke_failed"
  if (phase === "install") return "install_failed"
  const code = toCliError(error).code
  return code === "network" ? "download_failed" : code === "not_available" ? "no_binary_for_platform" : "verify_failed"
}

// `--check`: what is installed and what is latest, without the lock and
// without writing anything.
async function checkOnly(options: UpdateOptions): Promise<UpdateCheck> {
  const base = downloadBase(options.env)
  const { manifest } = await fetchManifest(options, base)
  const state = await readInstallState(options.install).catch(() => null)
  const current = options.current ?? VERSION
  return { current, latest: manifest.version, available: compareVersions(manifest.version, current) > 0, path: options.install.binary, installed: state?.installed ?? null, pending: state?.pending ?? null }
}

export async function update(options: UpdateOptions & { check: true }): Promise<UpdateCheck>
export async function update(options: UpdateOptions): Promise<UpdateReport>
export async function update(options: UpdateOptions): Promise<UpdateReport | UpdateCheck> {
  if (options.version !== undefined && options.version !== null && !VERSION_PATTERN.test(options.version)) throw usageError("--version needs a release version such as 0.3.0.")
  if (options.check) return checkOnly(options)
  const { platform, binary } = platformBinary(options)
  if (!(await installDirWritable(options.install))) throw new CliError("failed", `${options.install.dir} is not writable, so mehen cannot update itself there. ${notChanged}`, { say: "Update with the account that owns the install directory; mehen never uses sudo." })
  const locked = await withInstallLock(options.install, options.rollback ? "rollback" : options.by, () => underLock(options, platform, binary), options.wait === false ? { wait: false } : options.signal ? { signal: options.signal } : undefined)
  if (!locked.ok) return { current: options.current ?? VERSION, latest: null, available: false, updated: false, path: options.install.binary, result: "locked", holder: locked.holder }
  return locked.value
}

function skillLines(skills: SkillReport[] | undefined): string[] {
  if (!skills) return []
  const counts = new Map<string, number>()
  for (const s of skills) counts.set(s.status, (counts.get(s.status) ?? 0) + 1)
  const summary = [...counts].map(([status, n]) => `${n} ${status}`).join(", ")
  const lines = [`Skills: ${summary || "none managed"}.`]
  for (const s of skills) if (!["added", "updated", "unchanged"].includes(s.status)) lines.push(`  skill ${s.status}: ${s.path}${s.reason ? ` (${s.reason})` : ""}`)
  return lines
}

function reportLines(report: UpdateReport): string[] {
  switch (report.result) {
    case "updated":
      return [`Updated mehen ${report.from} to ${report.to} at ${report.path}. Restart agents that run mehen mcp to load it.`, ...skillLines(report.skills)]
    case "rolled_back":
      return [`Rolled mehen back from ${report.from} to ${report.to} at ${report.path}; automatic updates wait for a release above ${report.from}.`, ...skillLines(report.skills)]
    case "locked":
      return [`Another mehen update is running (pid ${report.holder?.pid ?? "unknown"}${report.holder?.at ? `, since ${report.holder.at}` : ""}); nothing was changed.`]
    case "held":
      return [`mehen ${report.latest} is not installed: it is not above a release this machine already saw or was rolled back from. mehen update --force --json installs it anyway.`]
    case "current":
      return [`mehen ${report.current} is current (latest ${report.latest}).`]
  }
}

export const updateCommand: Command = {
  summary: "check for or install a signed Mehen release and refresh managed skills",
  spec: {
    usage: "mehen update [--check] [--force] [--version <v>] [--rollback]",
    flags: { check: { type: "boolean" }, force: { type: "boolean" }, version: { type: "string" }, rollback: { type: "boolean" }, background: { type: "boolean" } },
    positionals: { min: 0, max: 0 },
  },
  examples: [["update", "--check", "--json"], ["update", "--json"], ["update", "--rollback", "--json"]],
  notes: [
    "Installs only a release signed by a key this build trusts, newer than the one running, after a smoke test of the new binary; the previous binary is kept for --rollback.",
    "--check only reports. --force installs the signed release named even when it is not newer. No sudo; the installed binary's directory must be writable. Exit 0 also when another update holds the lock.",
  ],
  async run({ args, json, env }) {
    const check = args.bool("check")
    const background = args.bool("background")
    const self = (background ? updateTarget(env) : null) ?? selfExecutable(env)
    if (!check && self === null) throw installedBinaryRequired("update")
    if (args.bool("rollback") && (args.bool("force") || args.string("version") !== null)) throw usageError("--rollback takes no --force or --version.")
    const install = installation(self ?? process.execPath)
    const options: UpdateOptions = { env, install, by: background ? "auto" : "manual", build: selfBuild(env), force: args.bool("force"), version: args.string("version"), rollback: args.bool("rollback"), ...(background ? { wait: false } : {}) }
    if (check) {
      const result = await update({ ...options, check: true })
      if (json) printJson(result)
      else printLine(`mehen ${result.current}; latest ${result.latest}${result.available ? ". Run mehen update." : "."}`)
      return EXIT.ok
    }
    if (background) {
      try {
        const report = await update(options)
        await appendUpdateLog(install, { event: "update", result: report.result, from: report.from ?? report.current, to: report.to ?? null, latest: report.latest })
      } catch (error) {
        await appendUpdateLog(install, { event: "update", result: "failed", reason: error instanceof Error ? error.message : String(error) })
      }
      return EXIT.ok
    }
    const report = await update(options)
    await appendUpdateLog(install, { event: "update", by: "manual", result: report.result, from: report.from ?? report.current, to: report.to ?? null })
    if (json) printJson(report)
    else for (const line of reportLines(report)) printLine(line)
    return EXIT.ok
  },
}

// --- scheduling and the heal ------------------

// hook runs before every tool call an agent makes: it never spawns the updater.
const NOT_SCHEDULED = new Set(["update", "help", "--help", "-h", "version", "--version", "guide", "mcp", "backup", "hook"])
const HEAL_BUDGET_MS = 90_000

// The installation this process may update, when automatic updating is on
// for it: a release build (or its test stand-in), not an updater child or a
// re-executed heal, auto-update on, the directory writable.
async function autoInstallation(env: Env): Promise<{ install: Installation; build: BuildKind } | null> {
  if (env.MEHEN_UPDATE_CHILD === "1") return null
  const self = selfExecutable(env)
  const build = selfBuild(env)
  if (self === null || build !== "release") return null
  const install = installation(self)
  const mode = autoUpdateMode(env, await installDirWritable(install), await readSettings(env), build)
  return mode === "on" ? { install, build } : null
}

// How an idle `mehen mcp` server launches the updater: never by re-resolving the installation path. `executable` is a
// private copy of bytes the server authenticated (its own image, or a
// replacement its self-watch admitted), or null to skip; the child gets the
// allowlisted `env` and the real installation as MEHEN_UPDATE_TARGET;
// `isIdle` is asked again after the last await, immediately before the
// child is created. The child still takes U2's lock itself.
export type McpIdleLaunch = {
  executable: (install: Installation) => Promise<string | null>
  env: Record<string, string>
  isIdle: () => boolean
}

// After a command, in `main`'s finally: spawns the detached background
// updater when a check is due. Due 1 hour after the last check, with up to
// 5 minutes of spread (15 minutes after a failure; both written by the
// updater), or at once when a journal is pending, when a vault advertised a
// minimum or recommended version above the installed one that no check since
// has answered, or after a cli_outdated (no back-off on these). A check that found only releases a rollback holds back
// answers the advice until the schedule; a check that failed, or a failed
// install of the release it found, answers it for a while (answeredAdvice),
// so a machine that cannot install the recommended release does not launch
// the updater on every command. `mehen mcp` never schedules from main's
// finally; its idle timer calls this with `idleMcp`.
export async function scheduleBackgroundUpdate(env: Env, command: string | undefined, options: { outdated?: boolean; now?: number; idleMcp?: McpIdleLaunch } = {}): Promise<"spawned" | "skipped"> {
  const idle = command === "mcp" ? (options.idleMcp ?? null) : null
  if (env.MEHEN_UPDATE_RETRIED === "1" || command === undefined || (NOT_SCHEDULED.has(command) && idle === null)) return "skipped"
  if (command === "setup" && env.MEHEN_SETUP_SKILLS_ONLY === "1") return "skipped"
  const auto = await autoInstallation(env)
  if (auto === null) return "skipped"
  const { install } = auto
  const now = options.now ?? Date.now()
  // A malformed journal refuses every updater run until a human repairs it,
  // which doctor reports.
  const state = await readInstallState(install).then((read) => read ?? freshInstallState(), () => null)
  if (state === null) return "skipped"
  const scheduled = state.check === null || !(now < Date.parse(state.check.nextAt))
  const current = idle !== null ? versionForAdvice(state) : VERSION
  const urgent = options.outdated === true || state.pending !== null || ((vaultAhead(state, current, "minimum") || vaultAhead(state, current, "recommended")) && !answeredAdvice(state, current, idle !== null, now))
  if (!scheduled && !urgent) return "skipped"
  const holder = await lockHolder(install).catch(() => null)
  if (holder?.live) return "skipped"
  const executable = idle ? await idle.executable(install) : install.binary
  if (executable === null) return "skipped"
  const fd = await openUpdateLog(install)
  try {
    // No await from here to the spawn: a call that arrived meanwhile wins.
    if (idle && !idle.isIdle()) return "skipped"
    const childEnv = idle ? { ...idle.env, MEHEN_UPDATE_CHILD: "1", [UPDATE_TARGET]: install.binary } : { ...env, MEHEN_UPDATE_CHILD: "1" }
    const child = spawn(executable, ["update", "--background"], { env: childEnv, detached: true, stdio: ["ignore", fd, fd] })
    child.on("error", () => {})
    child.unref()
  } finally {
    closeSync(fd)
  }
  return "spawned"
}

// The version the vault's advice is judged against by an idle `mehen mcp`:
// the recorded installed version when it is above this one, as for a
// long-lived server that started before an update. Its installation already
// meets what it meets; the restart notice, not the updater, closes the rest.
// Every other command judges against the running version, since the record
// is not checked against the bytes on disk.
function versionForAdvice(state: InstallState): string {
  const recorded = state.installed?.version
  if (recorded === undefined) return VERSION
  try {
    return compareVersions(recorded, VERSION) > 0 ? recorded : VERSION
  } catch {
    return VERSION
  }
}

// The vault's advice is urgent until a check after it found nothing newer
// than `current`, found only releases the updater holds back (at or below a
// rollback's `holdBelow`, or below a release seen before), failed, or was
// followed by a failed install of that release; from then it waits for the
// next scheduled check (15 minutes after a failed one), for the retry
// interval after the failed install (an idle `mehen mcp` waits for the
// schedule), or for advice above the highest a check answered: a vault whose
// isolates advise the floor and the release by turns gives no new advice.
// Below a vault's minimum a command run by hand still retries a failure at
// once: that path updates in the foreground within its own budget
// (healInForeground).
function answeredAdvice(state: InstallState, current: string, idleMcp: boolean, now: number): boolean {
  const check = state.check
  if (check === null) return false
  const answered = check.highestAnswered
  if (answered === null || vaultAhead(state, answered, "minimum") || vaultAhead(state, answered, "recommended")) return false
  const checkedAt = Date.parse(check.at)
  const backOff = idleMcp || !vaultAhead(state, current, "minimum")
  if (check.error !== null) return backOff
  if (check.latest === null) return false
  try {
    if (compareVersions(check.latest, current) <= 0) return true
    // Held: at or below a rollback's hold, or below a release seen before
    // (a manifest that went backwards); the updater would only hold again.
    if (state.holdBelow !== null && compareVersions(state.holdBelow, check.latest) >= 0) return true
    if (state.highestSeen !== null && compareVersions(check.latest, state.highestSeen) < 0) return true
    // An install of that release that failed after the check is not tried
    // again on every command, nor every idle minute.
    const last = state.lastUpdate
    if (!backOff || last === null || last.result !== "failed" || last.to !== check.latest || Date.parse(last.at) < checkedAt) return false
    return idleMcp || now < Date.parse(last.at) + RETRY_INTERVAL_MS
  } catch {
    return false
  }
}

// The installation an updater child launched by an idle MCP server updates:
// that server's real installation, since the child itself runs from a
// private copy. Honoured only for `update --background` under
// MEHEN_UPDATE_CHILD=1, and only for an absolute path to a plain file named
// `mehen`.
export const UPDATE_TARGET = "MEHEN_UPDATE_TARGET"

export function updateTarget(env: Env): string | null {
  const target = env[UPDATE_TARGET]
  if (env.MEHEN_UPDATE_CHILD !== "1" || !target) return null
  const real = installation(target).binary
  if (!isAbsolute(target) || basename(real) !== "mehen") throw usageError(`${UPDATE_TARGET} must name an installed mehen binary.`)
  return real
}

// The foreground heal: the same updater, by "heal", within one total budget
// (90 s), silent. At the deadline the updater is stopped, not abandoned: the
// heal returns only once it has settled, so no work outlives it. Resolves with the version now on disk when it is newer than this one.
export async function healInForeground(env: Env, options: { budgetMs?: number } = {}): Promise<{ from: string; to: string } | null> {
  const auto = await autoInstallation(env)
  if (auto === null) return null
  const { install, build } = auto
  const deadline = new AbortController()
  const timer = setTimeout(() => deadline.abort(), options.budgetMs ?? HEAL_BUDGET_MS)
  try {
    const report = await update({ env, install, by: "heal", build, signal: deadline.signal })
    await appendUpdateLog(install, { event: "heal", result: report.result, from: report.from ?? report.current, to: report.to ?? null })
    if (deadline.signal.aborted) return null
    const onDisk = report.result === "updated" ? report.to : report.current
    return onDisk && compareVersions(onDisk, VERSION) > 0 ? { from: VERSION, to: onDisk } : null
  } catch (error) {
    await appendUpdateLog(install, { event: "heal", result: deadline.signal.aborted ? "stopped" : "failed", reason: error instanceof Error ? error.message : String(error) })
    return null
  } finally {
    clearTimeout(timer)
  }
}

// Before a vault-talking command has done anything: when a
// recorded minimum is above this version, heal and re-execute the same
// argv as the new binary with MEHEN_UPDATE_RETRIED=1. Nothing has been sent
// or written yet, so the re-execution repeats nothing. Returns only when
// there is nothing to heal or the heal did not produce a newer binary.
export async function preDispatchHeal(env: Env, argv: string[]): Promise<void> {
  if (env.MEHEN_UPDATE_RETRIED === "1") return
  const auto = await autoInstallation(env)
  if (auto === null) return
  const state = await readInstallState(auto.install).catch(() => null)
  if (state === null || !vaultAhead(state, VERSION, "minimum")) return
  const healed = await healInForeground(env)
  if (healed === null || typeof process.execve !== "function") return
  const next: Record<string, string> = {}
  for (const [key, value] of Object.entries(env)) if (value !== undefined) next[key] = value
  next.MEHEN_UPDATE_RETRIED = "1"
  process.execve(auto.install.binary, [auto.install.binary, ...argv], next)
}
