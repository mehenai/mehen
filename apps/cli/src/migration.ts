// The migration from the contexts layout to layout 2 (// 10.3). It runs at the start of every command not on the skip list, before
// slot discovery or the ceiling, under locks/root.lock, touches only the
// root, never talks to the vault and never deletes a key, a stray or
// anything it does not recognise.
//
// Entry sequence (enterRoot): resolve the root; a layout-2 marker and no
// journal is done (on a managed host too: an owner-provisioned layout-2
// root runs under unchanged rule 0); any other state on a managed host
// refuses workspace_mismatch before touching the root; otherwise take the
// root lock, resume a journal (or inventory and write one), run the steps,
// finalise (mehen.json first, then the journal's deletion: the marker is
// the commit), release the lock.
//
// Journal first: the inventory is written to migration.json before any
// move, and every step records its state, so a kill anywhere resumes to the
// same result. A step whose resume fails its identity check is stuck: the
// command refuses `failed` with next `mehen doctor --json`, and doctor,
// which never migrates, reads the journal without the lock (migrationState).

import { constants, lstatSync, statSync } from "node:fs"
import { lstat, open, readdir, readFile, rename, rm, rmdir, unlink } from "node:fs/promises"
import { userInfo } from "node:os"
import { dirname, isAbsolute, join, normalize, sep } from "node:path"
import type { VaultFileOptions } from "./agent-profiles.ts"
import { BACKENDS, type Backend, type Config, type Env, canonicalOrigin, readConfig, writePrivateFile } from "./config.ts"
import { ENCLAVE_KEY_FILE, ENCLAVE_KEY_SCOPE_FILE, ENCLAVE_PUBLIC_KEY_FILE, SOFTWARE_KEY_FILE, SOFTWARE_KEY_SCOPE_FILE } from "./device-key.ts"
import { type EnrolmentRecord, enrolmentRecordPath, parseEnrolmentRecord, readEnrolmentRecord, recordFromLegacyEntry, writeEnrolmentRecord } from "./enrolment-record.ts"
import { CliError } from "./errors.ts"
import { LOCKS_DIR, MIGRATION_JOURNAL_FILE, PENDING_DIR, ROOT_MARKER_FILE, SAFE_COMPONENT, WORKSPACES_DIR, assertPrivateDirs, assertSafeRoot, managedHost, mkdirPrivate, originKey, resolveHome } from "./home.ts"
import { LEDGER_FILE, ledgerOrigins, ledgerPath, readLegacyEnrolments } from "./ledger.ts"
import { rootLockPath, withSlotLocks } from "./slot-lock.ts"

export { assertSafeRoot }

export type RootMarker = { layout: 2; migratedAt: string; from: "contexts-v1" | null }

export type MigrationIdentity = { origin: string; tenant: string; device: string; backend: Backend }
export type MigrationStep =
  | { id: number; kind: "slot"; source: string; move: "rename" | "files"; files: string[]; identity: MigrationIdentity; target: string; state: "planned" | "moving" | "done" }
  | { id: number; kind: "pending"; source: string; files: string[]; record: EnrolmentRecord; target: string; state: "planned" | "moving" | "done" }
  | { id: number; kind: "delete"; source: string; state: "planned" | "done" }
  | { id: number; kind: "leave"; source: string; detail: string }
export type MigrationJournal = { v: 1; from: "contexts-v1"; startedAt: string; pid: number; steps: MigrationStep[] }

// What doctor reports, read without the lock.
export type MigrationState = { state: "none" | "journal" | "stuck" | "corrupt"; root: string; layout: 2 | null; steps?: MigrationStep[]; stuck?: { step: number; detail: string } }

// A kill-point seam for the tests: called after every durable write.
export type MigrationHooks = { at?: (point: string) => void }

export type EnterOptions = { files?: VaultFileOptions; hooks?: MigrationHooks }

export type EnterResult = { root: string; migrated: MigrationJournal | null }

// Files a legacy context directory holds that a slot step moves, in the
// order they move: key, enclave sidecar, scope, ledger, then config last.
const SLOT_FILES = [SOFTWARE_KEY_FILE, ENCLAVE_KEY_FILE, ENCLAVE_PUBLIC_KEY_FILE, SOFTWARE_KEY_SCOPE_FILE, ENCLAVE_KEY_SCOPE_FILE, LEDGER_FILE, "config.json"]
const KEY_FILES = [SOFTWARE_KEY_FILE, ENCLAVE_KEY_FILE, ENCLAVE_PUBLIC_KEY_FILE, SOFTWARE_KEY_SCOPE_FILE, ENCLAVE_KEY_SCOPE_FILE]
// Names at the root that belong to layout 2, to setup and the updater, or
// to mehen up and the guard: never in the journal, never strays.
export const ROOT_OWN: ReadonlySet<string> = new Set([ROOT_MARKER_FILE, MIGRATION_JOURNAL_FILE, LOCKS_DIR, WORKSPACES_DIR, PENDING_DIR, "setup-state.json", "backups", "settings.json", "bin", "local-vault.json", "guard.json", "guard-installed.json"])
// Legacy files the migration deletes where it finds them.
const DELETED = new Set(["default-context", "update-check.json"])

function errorCode(error: unknown): string | undefined {
  return (error as { code?: string }).code
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path)
    return true
  } catch (error) {
    if (errorCode(error) === "ENOENT") return false
    throw error
  }
}

function doctorNext(): { command: string; say: string } {
  return { command: "mehen doctor --json", say: "Run `mehen doctor --json`: it prints the unfinished migration and the step that cannot continue, without changing anything." }
}

function failed(message: string): CliError {
  return new CliError("failed", message, doctorNext())
}

// ---- the marker and the journal -----------------------------------------

export function rootMarkerPath(root: string): string {
  return join(root, ROOT_MARKER_FILE)
}

export function migrationJournalPath(root: string): string {
  return join(root, MIGRATION_JOURNAL_FILE)
}

export async function readRootMarker(root: string): Promise<RootMarker | null> {
  try {
    const parsed: unknown = JSON.parse(await readFile(rootMarkerPath(root), "utf8"))
    const m = parsed as Record<string, unknown>
    if (typeof parsed === "object" && parsed !== null && m.layout === 2 && typeof m.migratedAt === "string" && (m.from === null || m.from === "contexts-v1")) return { layout: 2, migratedAt: m.migratedAt, from: m.from }
    return null
  } catch {
    return null
  }
}

function isIdentity(value: unknown): value is MigrationIdentity {
  const v = value as Record<string, unknown>
  return typeof value === "object" && value !== null && typeof v.origin === "string" && typeof v.tenant === "string" && typeof v.device === "string" && (BACKENDS as readonly string[]).includes(v.backend as string)
}

function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === "string" && v.length > 0 && !v.includes("/") && v !== "." && v !== "..")
}

function isStep(value: unknown, index: number): value is MigrationStep {
  if (typeof value !== "object" || value === null) return false
  const s = value as Record<string, unknown>
  if (s.id !== index || typeof s.source !== "string" || !s.source.startsWith("/")) return false
  const moving = s.state === "planned" || s.state === "moving" || s.state === "done"
  switch (s.kind) {
    case "slot":
      return (s.move === "rename" || s.move === "files") && isStringList(s.files) && isIdentity(s.identity) && typeof s.target === "string" && moving
    case "pending":
      return isStringList(s.files) && parseEnrolmentRecord(s.record) !== null && typeof s.target === "string" && moving
    case "delete":
      return s.state === "planned" || s.state === "done"
    case "leave":
      return typeof s.detail === "string"
    default:
      return false
  }
}

export function parseMigrationJournal(value: unknown): MigrationJournal | null {
  if (typeof value !== "object" || value === null) return null
  const j = value as Record<string, unknown>
  if (j.v !== 1 || j.from !== "contexts-v1" || typeof j.startedAt !== "string" || typeof j.pid !== "number" || !Array.isArray(j.steps)) return null
  if (!j.steps.every((step, i) => isStep(step, i))) return null
  return value as MigrationJournal
}

export type JournalRead = { journal: MigrationJournal } | { corrupt: string } | null

function canonicalPath(path: string): boolean {
  return isAbsolute(path) && !path.includes("\0") && normalize(path) === path && !path.endsWith(sep)
}

function placedOrigin(origin: string): string | null {
  try {
    return canonicalOrigin(origin) === origin ? originKey(origin) : null
  } catch {
    return null
  }
}

// `path` is <root>/<one>/<two>/... with every listed component a safe name.
function under(root: string, path: string, components: number): string[] | null {
  if (!canonicalPath(path) || !path.startsWith(root + sep)) return null
  const parts = path.slice(root.length + 1).split(sep)
  return parts.length === components && parts.every((part) => SAFE_COMPONENT.test(part)) ? parts : null
}

// Why a step is not one this root's migration could have written, or null.
// Every path must be the exact shape the inventory produces under `root`,
// so a journal can never move, delete or read anything outside it.
function stepOutsideRoot(root: string, step: MigrationStep): string | null {
  const bad = (what: string) => `step ${step.id} ${what}`
  const contextSource = (path: string) => under(root, path, 2)?.[0] === "contexts"
  if (step.kind === "leave") return canonicalPath(step.source) && step.source.startsWith(root + sep) ? null : bad("names a path outside the root")
  if (step.kind === "delete") {
    const parts = under(root, step.source, step.source.split(sep).length - root.split(sep).length)
    if (!parts) return bad("deletes a path outside the root")
    const [first, , third, fourth] = parts
    const shapes = (parts.length === 1 && (first === "default-context" || first === "update-check.json" || first === "contexts")) || (parts.length === 2 && first === "contexts") || (parts.length === 3 && first === "contexts" && third === "update-check.json") || (parts.length === 4 && first === WORKSPACES_DIR && fourth === "update-check.json")
    return shapes ? null : bad("deletes something a migration never deletes")
  }
  if (step.kind === "slot") {
    if (!step.files.every((file) => SLOT_FILES.includes(file))) return bad("moves a file a slot does not hold")
    const origin = placedOrigin(step.identity.origin)
    if (origin === null || !SAFE_COMPONENT.test(step.identity.tenant) || !SAFE_COMPONENT.test(step.identity.device)) return bad("names a workspace, device or vault that cannot be placed")
    const target = join(root, WORKSPACES_DIR, origin, step.identity.tenant)
    if (step.target !== target && step.target !== `${target}.duplicate-${step.identity.device}`) return bad("moves to another place than its identity's slot")
    return (step.move === "files" ? step.source === root : contextSource(step.source)) ? null : bad("moves from a place a slot is never moved from")
  }
  if (!step.files.every((file) => KEY_FILES.includes(file))) return bad("moves a file a pending slot does not hold")
  const origin = placedOrigin(step.record.origin)
  if (origin === null || step.target !== join(root, PENDING_DIR, origin, step.record.intent.workspace)) return bad("moves to another place than its enrolment's pending slot")
  return step.source === root || contextSource(step.source) ? null : bad("moves from a place an enrolment is never moved from")
}

export function journalOutsideRoot(root: string, journal: MigrationJournal): string | null {
  for (const step of journal.steps) {
    const why = stepOutsideRoot(root, step)
    if (why) return why
  }
  return null
}

// The journal, without the root lock: null when there is none. It is read
// only as a private regular file of this user, opened without following a
// link and checked to be the file that was examined, and every step must
// stay inside the root; anything else is corrupt and nothing is done.
export async function readMigrationJournal(root: string): Promise<JournalRead> {
  const path = migrationJournalPath(root)
  let text: string
  try {
    const info = await lstat(path)
    if (info.isSymbolicLink()) return { corrupt: `${path} is a symbolic link.` }
    if (!info.isFile()) return { corrupt: `${path} is not a regular file.` }
    if (info.uid !== userInfo().uid) return { corrupt: `${path} is owned by another user (uid ${info.uid}).` }
    if ((info.mode & 0o077) !== 0) return { corrupt: `${path} can be read or written by other users.` }
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
    try {
      const opened = await handle.stat()
      if (opened.dev !== info.dev || opened.ino !== info.ino) return { corrupt: `${path} changed while it was read.` }
      text = await handle.readFile("utf8")
    } finally {
      await handle.close()
    }
  } catch (error) {
    if (errorCode(error) === "ENOENT") return null
    return { corrupt: `${path} cannot be read: ${error instanceof Error ? error.message : String(error)}` }
  }
  let journal: MigrationJournal | null
  try {
    journal = parseMigrationJournal(JSON.parse(text))
  } catch {
    return { corrupt: `${path} is not JSON.` }
  }
  if (!journal) return { corrupt: `${path} is not a migration journal mehen recognises.` }
  const outside = journalOutsideRoot(root, journal)
  return outside ? { corrupt: `${path}: ${outside}.` } : { journal }
}

async function writeJournal(root: string, journal: MigrationJournal, hooks: MigrationHooks, point: string): Promise<void> {
  await writePrivateFile(migrationJournalPath(root), `${JSON.stringify(journal, null, 2)}\n`)
  hooks.at?.(point)
}

// ---- the inventory -----------------------------------------------------

// A file the journal moves: this user's, a plain file, not a link, closed
// to group and others. A directory it renames: the same, as a directory.
async function assertMovable(path: string, kind: "file" | "directory"): Promise<void> {
  const info = await lstat(path)
  const uid = userInfo().uid
  const ok = !info.isSymbolicLink() && (kind === "file" ? info.isFile() : info.isDirectory()) && info.uid === uid && (info.mode & 0o077) === 0
  if (!ok) throw new CliError("failed", `The migration stopped before changing anything: ${path} is not a private ${kind} this user owns (a link, another user's, or readable by others).`, { say: `Make ${path} this user's and private (chmod ${kind === "file" ? "600" : "700"}), or move it out of the config root, then run the command again.` })
}

async function ownedPrivateDirectory(path: string): Promise<boolean> {
  try {
    const info = await lstat(path)
    return !info.isSymbolicLink() && info.isDirectory() && info.uid === userInfo().uid && (info.mode & 0o077) === 0
  } catch {
    return false
  }
}

async function presentFiles(dir: string, names: string[]): Promise<string[]> {
  const present: string[] = []
  for (const name of names) if (await exists(join(dir, name))) present.push(name)
  return present
}

// A step before its id is given, per kind.
type PlannedStep = MigrationStep extends infer S ? (S extends MigrationStep ? Omit<S, "id"> : never) : never
type Plan = { steps: PlannedStep[]; slotTargets: Set<string>; pendingTargets: Set<string> }

function identityOf(config: Config): MigrationIdentity {
  return { origin: config.vault, tenant: config.tenant, device: config.device, backend: config.backend }
}

// A config whose vault, workspace or device cannot name a directory under
// the root is never placed: its identity would make the target path.
function placeable(config: Config): boolean {
  return placedOrigin(config.vault) !== null && SAFE_COMPONENT.test(config.tenant) && SAFE_COMPONENT.test(config.device)
}

async function planSlot(root: string, plan: Plan, source: string, config: Config, move: "rename" | "files", files: string[]): Promise<string> {
  const base = join(root, WORKSPACES_DIR, originKey(config.vault))
  let target = join(base, config.tenant)
  if (plan.slotTargets.has(target) || (await exists(target))) target = join(base, `${config.tenant}.duplicate-${config.device}`)
  plan.slotTargets.add(target)
  plan.steps.push({ kind: "slot", source, move, files, identity: identityOf(config), target, state: "planned" })
  return target
}

// A legacy ledger with enrol entries and no config: one pending step for
// the newest entry whose key is on disk, a leave step for every other.
async function planPending(root: string, plan: Plan, source: string): Promise<boolean> {
  const entries: Awaited<ReturnType<typeof readLegacyEnrolments>> = []
  for (const origin of await ledgerOrigins(source)) if (placedOrigin(origin) !== null) entries.push(...(await readLegacyEnrolments(source, origin)))
  if (entries.length === 0) return false
  entries.sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt))
  const newest = entries.at(-1) as (typeof entries)[number]
  for (const older of entries.slice(0, -1)) plan.steps.push({ kind: "leave", source, detail: `enrolment ${older.ask.id} is superseded by ${newest.ask.id}; the vault has already expired it` })
  const key = newest.enrol.backend === "software" ? SOFTWARE_KEY_FILE : ENCLAVE_KEY_FILE
  if (!(await exists(join(source, key)))) {
    plan.steps.push({ kind: "leave", source, detail: `enrolment ${newest.ask.id} has no key on disk` })
    return true
  }
  const record = recordFromLegacyEntry(newest)
  const target = join(root, PENDING_DIR, originKey(record.origin), record.intent.workspace)
  if (plan.pendingTargets.has(target) || (await exists(target))) {
    plan.steps.push({ kind: "leave", source, detail: `another pending enrolment for ${record.intent.workspace} is already kept at ${target}` })
    return true
  }
  plan.pendingTargets.add(target)
  const files = await presentFiles(source, KEY_FILES)
  for (const file of files) await assertMovable(join(source, file), "file")
  plan.steps.push({ kind: "pending", source, files, record, target, state: "planned" })
  return true
}

async function configOrNull(dir: string): Promise<Config | null | "invalid"> {
  try {
    return await readConfig(dir)
  } catch {
    return "invalid"
  }
}

// Every legacy item under the root, validated before anything is written.
async function inventory(root: string): Promise<MigrationJournal> {
  const plan: Plan = { steps: [], slotTargets: new Set(), pendingTargets: new Set() }
  const deletes: string[] = []
  const directories: string[] = []
  const names = (await readdir(root)).sort()
  // The legacy root context (the old default directory): its files move
  // into a slot, or its ledger's newest enrolment into a pending slot.
  const movedFromRoot = new Set<string>()
  const rootConfig = await configOrNull(root)
  if (rootConfig === "invalid" || (rootConfig && !placeable(rootConfig))) throw new CliError("failed", `The migration stopped before changing anything: ${join(root, "config.json")} is not a valid mehen config.`, { say: `Move ${join(root, "config.json")} aside, then run the command again.` })
  if (rootConfig) {
    const files = await presentFiles(root, SLOT_FILES)
    for (const file of files) await assertMovable(join(root, file), "file")
    await planSlot(root, plan, root, rootConfig, "files", files)
    for (const file of files) movedFromRoot.add(file)
  } else if (await exists(ledgerPath(root))) {
    await assertMovable(ledgerPath(root), "file")
    if (await planPending(root, plan, root)) {
      const last = plan.steps.at(-1)
      if (last?.kind === "pending") for (const file of last.files) movedFromRoot.add(file)
    } else plan.steps.push({ kind: "leave", source: ledgerPath(root), detail: "a ledger with no enrolment in it; mehen no longer reads it here" })
    movedFromRoot.add(LEDGER_FILE)
  }
  for (const name of names) {
    const path = join(root, name)
    if (ROOT_OWN.has(name) || name === "contexts" || movedFromRoot.has(name)) continue
    if (DELETED.has(name)) deletes.push(path)
    else plan.steps.push({ kind: "leave", source: path, detail: "not a slot; mehen does not read or delete it; remove it yourself if you know what it is" })
  }
  // contexts/<name>/: a slot each, renamed whole, or a pending enrolment.
  const contexts = join(root, "contexts")
  if (await exists(contexts)) {
    if (!(await ownedPrivateDirectory(contexts))) plan.steps.push({ kind: "leave", source: contexts, detail: "not a private directory this user owns; mehen did not read it" })
    else {
      let emptied = true
      for (const name of (await readdir(contexts)).sort()) {
        const dir = join(contexts, name)
        if (!SAFE_COMPONENT.test(name) || !(await ownedPrivateDirectory(dir))) {
          plan.steps.push({ kind: "leave", source: dir, detail: "not a private directory this user owns; mehen did not read it" })
          emptied = false
          continue
        }
        const config = await configOrNull(dir)
        if (config === "invalid" || (config && !placeable(config))) {
          plan.steps.push({ kind: "leave", source: dir, detail: "its config.json is not a valid mehen config; mehen does not read or delete it" })
          emptied = false
        } else if (config) {
          await assertMovable(dir, "directory")
          const files = await presentFiles(dir, SLOT_FILES)
          for (const file of files) await assertMovable(join(dir, file), "file")
          const target = await planSlot(root, plan, dir, config, "rename", files)
          if (await exists(join(dir, "update-check.json"))) deletes.push(join(target, "update-check.json"))
        } else if (await exists(ledgerPath(dir))) {
          await assertMovable(ledgerPath(dir), "file")
          const planned = await planPending(root, plan, dir)
          const pendingMoved = plan.steps.at(-1)?.kind === "pending" && plan.steps.at(-1)?.source === dir
          if (await exists(join(dir, "update-check.json"))) deletes.push(join(dir, "update-check.json"))
          if (!planned) plan.steps.push({ kind: "leave", source: dir, detail: "a ledger with no enrolment in it; mehen no longer reads it here" })
          if (pendingMoved) directories.push(dir)
          else emptied = false
        } else {
          plan.steps.push({ kind: "leave", source: dir, detail: "not a slot; mehen does not read or delete it; remove it yourself if you know what it is" })
          emptied = false
        }
      }
      if (emptied) directories.push(contexts)
    }
  }
  const steps: MigrationStep[] = [...plan.steps.filter((s) => s.kind === "slot" || s.kind === "pending"), ...deletes.map((source) => ({ kind: "delete" as const, source, state: "planned" as const })), ...directories.map((source) => ({ kind: "delete" as const, source, state: "planned" as const })), ...plan.steps.filter((s) => s.kind === "leave")].map((step, id) => ({ ...step, id }) as MigrationStep)
  return { v: 1, from: "contexts-v1", startedAt: new Date().toISOString(), pid: process.pid, steps }
}

// ---- running and resuming steps -------------------------------------------

type Classified = "done" | "ready" | { stuck: string }

async function identityAt(dir: string): Promise<MigrationIdentity | null> {
  try {
    const config = await readConfig(dir)
    return config ? identityOf(config) : null
  } catch {
    return null
  }
}

function sameIdentity(a: MigrationIdentity | null, b: MigrationIdentity): boolean {
  return a !== null && a.origin === b.origin && a.tenant === b.tenant && a.device === b.device && a.backend === b.backend
}

async function recordAt(dir: string): Promise<EnrolmentRecord | null> {
  const read = await readEnrolmentRecord(dir)
  return read && "record" in read ? read.record : null
}

// What resuming a step would do, decided from the journal and the disk
// alone (never re-derived from a half-moved directory). Read-only.
export async function classifyStep(step: MigrationStep): Promise<Classified> {
  if (step.kind === "leave") return "done"
  if (step.state === "done") return "done"
  if (step.kind === "delete") return "ready"
  if (step.kind === "slot" && step.move === "rename") {
    const [source, target] = [await exists(step.source), await exists(step.target)]
    if (source && !target) return "ready"
    if (!source && target) return sameIdentity(await identityAt(step.target), step.identity) ? "ready" : { stuck: `${step.target} does not hold the enrolment the journal moved there (${step.identity.device} in ${step.identity.tenant})` }
    return { stuck: source ? `both ${step.source} and ${step.target} exist` : `neither ${step.source} nor ${step.target} exists` }
  }
  for (const file of step.files) {
    const [source, target] = [await exists(join(step.source, file)), await exists(join(step.target, file))]
    if (source && target) return { stuck: `${file} exists both in ${step.source} and in ${step.target}` }
    if (!source && !target) return { stuck: `${file} is in neither ${step.source} nor ${step.target}` }
  }
  return "ready"
}

async function moveFiles(root: string, source: string, target: string, files: string[], hooks: MigrationHooks, step: number): Promise<void> {
  mkdirPrivate(root, target)
  for (const file of files) {
    if (await exists(join(target, file))) continue
    await rename(join(source, file), join(target, file))
    hooks.at?.(`step ${step}: moved ${file}`)
  }
}

// The enrol entry the record came from, removed from the source ledger (the
// ledger itself when nothing else is left in it).
async function dropLegacyEntry(source: string, id: string, hooks: MigrationHooks, step: number): Promise<void> {
  const path = ledgerPath(source)
  let parsed: unknown
  try {
    parsed = JSON.parse(await readFile(path, "utf8"))
  } catch (error) {
    if (errorCode(error) === "ENOENT") return
    throw error
  }
  const list = Array.isArray(parsed) ? parsed : typeof parsed === "object" && parsed !== null && Array.isArray((parsed as { entries?: unknown }).entries) ? (parsed as { entries: unknown[] }).entries : []
  const kept = list.filter((e) => !(typeof e === "object" && e !== null && (e as { ask?: { id?: unknown } }).ask?.id === id))
  if (kept.length === list.length) return
  if (kept.length === 0) await unlink(path)
  else await writePrivateFile(path, `${JSON.stringify({ entries: kept }, null, 2)}\n`)
  hooks.at?.(`step ${step}: ledger entry ${id} removed`)
}

// Every existing directory a step reads from or writes into, below the
// root, is a private directory of this user and no link: a moved key never
// leaves the root through a linked, foreign or loose directory.
function assertStepPaths(root: string, step: MigrationStep): void {
  if (step.kind === "leave") return
  if (step.source !== root) assertPrivateDirs(root, step.kind === "slot" && step.move === "rename" ? step.source : dirname(step.source))
  if (step.kind === "delete") return
  assertPrivateDirs(root, dirname(step.target))
  assertPrivateDirs(root, step.target)
}

async function runStep(root: string, journal: MigrationJournal, step: MigrationStep, hooks: MigrationHooks): Promise<void> {
  if (step.kind === "leave") return
  assertStepPaths(root, step)
  const verdict = await classifyStep(step)
  if (verdict === "done") return
  if (typeof verdict === "object") throw failed(`The migration of ${root} cannot continue: step ${step.id} is stuck (${verdict.stuck}). Nothing was deleted.`)
  if (step.kind === "delete") {
    try {
      const info = await lstat(step.source)
      if (info.isDirectory()) await rmdir(step.source)
      else await rm(step.source, { force: true })
    } catch (error) {
      // Gone already, or a directory something else was put in: kept.
      if (errorCode(error) !== "ENOENT" && errorCode(error) !== "ENOTEMPTY" && errorCode(error) !== "EEXIST") throw error
    }
    step.state = "done"
    await writeJournal(root, journal, hooks, `step ${step.id}: done`)
    return
  }
  if (step.state === "planned") {
    step.state = "moving"
    await writeJournal(root, journal, hooks, `step ${step.id}: moving`)
  }
  if (step.kind === "slot" && step.move === "rename") {
    if (await exists(step.source)) {
      mkdirPrivate(root, dirname(step.target))
      await rename(step.source, step.target)
      hooks.at?.(`step ${step.id}: renamed`)
    }
  } else if (step.kind === "slot") {
    await moveFiles(root, step.source, step.target, step.files, hooks, step.id)
  } else {
    await moveFiles(root, step.source, step.target, step.files, hooks, step.id)
    const written = await recordAt(step.target)
    if (!written || written.id !== step.record.id) {
      await writeEnrolmentRecord(step.target, step.record)
      hooks.at?.(`step ${step.id}: record written`)
    }
    await dropLegacyEntry(step.source, step.record.id as string, hooks, step.id)
  }
  // The identity at the target is the journal's before the step is done.
  if (step.kind === "slot" && !sameIdentity(await identityAt(step.target), step.identity)) throw failed(`The migration of ${root} cannot continue: ${step.target} does not hold ${step.identity.device} in ${step.identity.tenant} after the move. Nothing was deleted.`)
  if (step.kind === "pending" && (await recordAt(step.target))?.id !== step.record.id) throw failed(`The migration of ${root} cannot continue: ${enrolmentRecordPath(step.target)} is not enrolment ${step.record.id}. Nothing was deleted.`)
  step.state = "done"
  await writeJournal(root, journal, hooks, `step ${step.id}: done`)
}

async function finalise(root: string, journal: MigrationJournal, hooks: MigrationHooks): Promise<void> {
  const marker: RootMarker = { layout: 2, migratedAt: new Date().toISOString(), from: journal.steps.length > 0 ? "contexts-v1" : null }
  await writePrivateFile(rootMarkerPath(root), `${JSON.stringify(marker)}\n`)
  hooks.at?.("marker written")
  await rm(migrationJournalPath(root), { force: true })
  hooks.at?.("journal deleted")
}

async function migrateLocked(root: string, hooks: MigrationHooks): Promise<MigrationJournal | null> {
  const read = await readMigrationJournal(root)
  if (read && "corrupt" in read) throw failed(`The migration of ${root} cannot continue: ${read.corrupt}`)
  let journal: MigrationJournal
  if (read) journal = read.journal
  else {
    if (await readRootMarker(root)) return null
    journal = await inventory(root)
    const outside = journalOutsideRoot(root, journal)
    if (outside) throw new CliError("failed", `The migration stopped before changing anything: ${outside}.`, doctorNext())
  }
  // Every directory the steps touch is checked before the journal is
  // committed, and again before a resumed journal moves anything.
  for (const step of journal.steps) assertStepPaths(root, step)
  if (!read) await writeJournal(root, journal, hooks, "journal written")
  for (const step of journal.steps) await runStep(root, journal, step, hooks)
  await finalise(root, journal, hooks)
  return journal
}

function managedRefusal(root: string): CliError {
  return new CliError("workspace_mismatch", `This host is managed: ${root} is not a layout-2 root, and mehen never migrates a managed host's layout.`, {
    say: "The owner migrates the layout and rewrites the pin (this host's launcher keeps refusing until then); nothing here changes it.",
  })
}

// The entry sequence. Returns the journal it ran, when it
// ran one with anything in it, for the caller's one `migrated` line.
export async function enterRoot(env: Env, options: EnterOptions = {}): Promise<EnterResult> {
  const { root } = resolveHome(env, { files: options.files ?? {} })
  // The root and the ancestors that exist are checked before anything under
  // them is read (a component that is not a directory or cannot be examined
  // is the named refusal) and before the root exists: the first write would
  // create it under them. Read-only, so a managed host is not touched.
  assertSafeRoot(root)
  const marker = await readRootMarker(root)
  const journalPresent = await exists(migrationJournalPath(root))
  if (marker && !journalPresent) return { root, migrated: null }
  if (managedHost(options.files ?? {})) throw managedRefusal(root)
  if (!(await exists(root))) return { root, migrated: null }
  // Nothing of the old layout here (an empty or layout-2 root without its
  // marker): nothing to journal, and nothing is created by looking.
  if (!journalPresent && !(await holdsLegacy(root))) return { root, migrated: null }
  const migrated = await withSlotLocks([rootLockPath(root)], () => migrateLocked(root, options.hooks ?? {}))
  return { root, migrated: migrated && migrated.steps.length > 0 ? migrated : null }
}

// Whether enterRoot would migrate the root, or refuse to on a managed
// host, read without the lock and without changing anything: the MCP
// handover's acceptance check asks, since the image after the exec enters
// the root before it serves.
export async function enterRootMigrates(env: Env, options: Pick<EnterOptions, "files"> = {}): Promise<boolean> {
  const { root } = resolveHome(env, { files: options.files ?? {} })
  assertSafeRoot(root)
  const journalPresent = await exists(migrationJournalPath(root))
  if ((await readRootMarker(root)) && !journalPresent) return false
  if (managedHost(options.files ?? {})) return true
  if (!(await exists(root))) return false
  return journalPresent || (await holdsLegacy(root))
}

// What doctor reports, read without the lock and without changing anything.
export async function migrationState(root: string): Promise<MigrationState> {
  const layout = (await readRootMarker(root)) ? 2 : null
  const read = await readMigrationJournal(root)
  if (read === null) return { state: "none", root, layout }
  if ("corrupt" in read) return { state: "corrupt", root, layout, stuck: { step: -1, detail: read.corrupt } }
  for (const step of read.journal.steps) {
    const verdict = await classifyStep(step)
    if (typeof verdict === "object") return { state: "stuck", root, layout, steps: read.journal.steps, stuck: { step: step.id, detail: verdict.stuck } }
  }
  return { state: "journal", root, layout, steps: read.journal.steps }
}

async function holdsLegacy(root: string): Promise<boolean> {
  try {
    return (await readdir(root)).some((name) => !ROOT_OWN.has(name))
  } catch {
    return false
  }
}

// Does the root hold anything a migration would move or name (not just a
// legacy file it deletes): a legacy layout that the next command migrates.
export async function legacyLayout(root: string): Promise<boolean> {
  if (await readRootMarker(root)) return false
  try {
    return (await readdir(root)).some((name) => !ROOT_OWN.has(name) && !DELETED.has(name))
  } catch {
    return false
  }
}

// The `migrated` line's facts.
export function migrationSummary(journal: MigrationJournal): { slots: number; pending: number; deleted: number; left: string[] } {
  return {
    slots: journal.steps.filter((s) => s.kind === "slot").length,
    pending: journal.steps.filter((s) => s.kind === "pending").length,
    deleted: journal.steps.filter((s) => s.kind === "delete").length,
    left: journal.steps.filter((s): s is Extract<MigrationStep, { kind: "leave" }> => s.kind === "leave").map((s) => s.source),
  }
}
