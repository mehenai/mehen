// mehen adopt retire and unretire: take a source file out of play once the
// vault copy is proven, and put it back. A human's step, never an agent's
// own idea: without --yes retire only says which files are ready and why
// the others are held.
//
// A file is ready only when all of these hold (design section 16.3, backup
// decision 12):
//   1. it is a dotenv file, or NAME=value lines kept in .local-secrets;
//   2. it is a regular file with one name that git does not track,
//      unchanged since the newest snapshot holding it (mtime and ctime, as
//      the submit gate checks);
//   3. `adopt verify` covers every name in it, with no gap and nothing
//      skipped, its env check passes and every item behind it has a live
//      check of ok or none;
//   4. a program gets these values from Mehen: its repo or service ran
//      cleanly under `mehen run` often enough, over enough days, since the
//      batch was applied, and its newest run was clean: exit 0, or a
//      SIGINT or SIGTERM passed on from outside (unless --path says
//      nothing reads the file any more);
//   5. a `mehen backup compare --json` of that snapshot against an export
//      taken after the batch was applied reports every variable matching.
//
// Ready files move to <adopt dir>/quarantine/<date>/<path hash>/<name>,
// never deleted, with an index line unretire reads to put each back.

import { constants } from "node:fs"
import { chmod, link, lstat, mkdir, open, rename, unlink } from "node:fs/promises"
import type { Stats } from "node:fs"
import { basename, dirname, join } from "node:path"
import { sha256Hex } from "@mehen/protocol/backup"
import { randomId, utf8 } from "@mehen/protocol/bytes"
import { z } from "zod"
import { changedSince, snapshotCommand } from "../backup/guard.ts"
import { readRegularFile, writeNewFile } from "../backup/files.ts"
import type { SnapshotRecord } from "../backup/state.ts"
import { MANIFEST_FILE } from "../run/manifest.ts"
import { type RunLogEntry, cleanRun } from "../run/run-log.ts"
import { type ApplyContext, type StoredItems, mappedItem, tracked } from "./apply.ts"
import type { OutputGuard } from "./output-guard.ts"
import type { AdoptPlan, PlanItem } from "./plan.ts"
import { MAX_SOURCE_BYTES, type SourceType } from "./sources.ts"
import { type CoverageRow, type VerifyReport, namesIn, verifyPlan } from "./verify.ts"

export const QUARANTINE_DIR = "quarantine"
export const QUARANTINE_INDEX = "index.jsonl"
// Note prefixes: a moved file unretire may not find, and an original a
// failed move could not put back.
export const NOT_INDEXED = "its line in the quarantine index could not be written, or not saved to disk"
export const LEFT_ASIDE = "the original is left aside at "
const DAY_MS = 86_400_000

const ComparedSource = z.looseObject({ path: z.string(), variable: z.string().nullable(), pointer: z.string().nullable() })
// What retire reads from `mehen backup compare --json`: names, never a value.
export const ComparedSchema = z.looseObject({
  snapshot: z.string(),
  export: z.string(),
  exportedAt: z.iso.datetime().optional(),
  matching: z.array(ComparedSource).optional(),
  different: z.array(ComparedSource),
  missing: z.array(ComparedSource.extend({ why: z.string() })),
})
export type Compared = z.infer<typeof ComparedSchema>

// An approved batch of this machine's, by the plan refs it created, with
// when `adopt apply` first applied it (null before that was recorded).
export type AppliedBatch = { adoption: string; planRefs: ReadonlySet<string>; appliedAt: string | null }

export type RetireInputs = {
  plan: AdoptPlan
  planPath: string
  stored: StoredItems
  batches: readonly AppliedBatch[]
  snapshots: readonly SnapshotRecord[]
  runs: readonly RunLogEntry[]
  compared: { path: string; result: Compared } | null
}

export type RetireOptions = {
  // --repo roots and --path files; both empty means every file.
  repos: readonly string[]
  paths: readonly string[]
  minRuns: number
  minDays: number
  now: Date
  session: string | null
}

export type RetireFileState = "ready" | "held" | "moved" | "failed"
// `reasons`: why a file is held or failed; `notes`: what a ready or moved
// file was not checked for, and where it went.
export type RetireFile = { path: string; state: RetireFileState; reasons: string[]; notes: string[] }
// A move a crash or kill cut short: its line in the quarantine index has
// nothing ending it. `note` says where the file is and what to do.
export type UnfinishedMove = { path: string; at: string; aside: string; quarantined: string; note: string }
export type RetireReport = { files: RetireFile[]; moved: number; held: number; unfinished: UnfinishedMove[] }

// What retire found about a ready file, compared again right before it moves.
type Checked = RetireFile & { info: Stats | null; snapshot: SnapshotRecord | null; adoption: string | null; refs: string[] }

const MOVABLE: ReadonlySet<SourceType> = new Set(["dotenv", "secrets-file"])

function byHand(type: SourceType | null): string {
  if (type === "envrc") return "edit by hand: a .envrc is a script direnv runs; take the exports out of it yourself"
  if (type === "json") return "edit by hand: a settings file its program reads and writes; take the keys out of it yourself"
  if (type === "plist" || type === "systemd") return "edit by hand: a service unit; make the change `mehen adopt apply` printed for it"
  if (type === "kubeconfig") return "edit by hand: a kubeconfig; take the credentials out of it with kubectl or by hand"
  if (type === null) return "edit by hand: not a file adopt reads"
  return "edit by hand: login state its own tool keeps; sign out with that tool when you are sure"
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`
}

// Every file the plan names, sorted, once.
export function planFiles(plan: AdoptPlan): string[] {
  const files = new Set(Object.values(plan.sources).map((s) => s.path))
  for (const repo of plan.repos) for (const f of repo.files) files.add(join(repo.root, f.path))
  return [...files].sort()
}

function selected(path: string, plan: AdoptPlan, options: RetireOptions): boolean {
  if (options.repos.length === 0 && options.paths.length === 0) return true
  if (options.paths.includes(path)) return true
  return plan.repos.some((r) => options.repos.includes(r.root) && r.files.some((f) => join(r.root, f.path) === path))
}

// The repo root or service folder whose mehen.toml a program reading this
// file runs with, or null when no target in the plan reads it.
function targetRoot(plan: AdoptPlan, path: string): string | null {
  const repo = plan.repos.find((r) => r.files.some((f) => join(r.root, f.path) === path))
  if (repo) return repo.root
  return plan.services.find((s) => s.envFile === path)?.dir ?? null
}

function sourceIds(plan: AdoptPlan, path: string): string[] {
  return Object.entries(plan.sources).flatMap(([id, s]) => (s.path === path ? [id] : []))
}

function takes(item: PlanItem, ids: readonly string[]): boolean {
  return Object.values(item.fields).some((f) => f.from.some((id) => ids.includes(id))) || Object.values(item.publicFields).some((p) => typeof p !== "string" && ids.includes(p.from))
}

// Coverage for a file no repo or service reads, such as one in
// .local-secrets: each name is covered when a credential the vault stored
// holds it.
async function ownCoverage(plan: AdoptPlan, stored: StoredItems, path: string, ctx: ApplyContext): Promise<CoverageRow[]> {
  const { names, errors, why } = await namesIn(plan, path, ctx.home, ctx.guard)
  const rows: CoverageRow[] = []
  const row = { file: path, env: "" }
  if (why !== null) rows.push({ ...row, variable: "*", state: "gap", why: `the file ${why}` })
  for (const e of errors) rows.push({ ...row, variable: `line ${e.line}`, state: "gap", why: e.why })
  for (const variable of names) {
    const ids = Object.entries(plan.sources).flatMap(([id, s]) => (s.path === path && s.variable === variable ? [id] : []))
    const item = plan.items.find((i) => takes(i, ids))
    if (ids.length === 0) rows.push({ ...row, variable, state: "gap", why: "not in the plan" })
    else if (item === undefined) rows.push({ ...row, variable, state: "skipped", why: "no credential in the plan holds it" })
    else {
      const mapped = mappedItem(plan, stored, item.ref)
      rows.push("why" in mapped ? { ...row, variable, state: "skipped", why: mapped.why } : { ...row, variable, state: "covered", why: null })
    }
  }
  return rows
}

function newestHolding(snapshots: readonly SnapshotRecord[], path: string): SnapshotRecord | null {
  const holding = snapshots.filter((s) => s.selfCheck === "passed" && s.paths.includes(path))
  holding.sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0))
  return holding[0] ?? null
}

// Rule 2's file checks; also run again right before a move.
async function fileReasons(path: string, snapshot: SnapshotRecord | null, planPath: string): Promise<{ reasons: string[]; info: Stats | null }> {
  const info = await lstat(path).catch(() => null)
  if (info === null) return { reasons: ["it is not there any more"], info }
  if (info.isSymbolicLink()) return { reasons: ["it is a symbolic link; retire moves only a regular file"], info }
  if (!info.isFile()) return { reasons: ["it is not a regular file"], info }
  const reasons: string[] = []
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) reasons.push("it is owned by another user")
  if (info.nlink > 1) reasons.push(`it has other names (${plural(info.nlink - 1, "more hard link", "more hard links")}); retire moves only a file with one, since the others would share the quarantined copy`)
  if (info.size > MAX_SOURCE_BYTES) reasons.push("it is over 1 MiB, so adopt never read it")
  if (tracked(dirname(path), basename(path))) reasons.push("this file is committed; rotate these values instead")
  const take = `take a new snapshot: ${snapshotCommand(planPath)}`
  if (snapshot === null) reasons.push(`no snapshot on this machine holds it; ${take}`)
  else if ((await changedSince([path], snapshot.createdAt)) !== null) reasons.push(`it changed after snapshot ${snapshot.id} was taken; ${take}, then export and compare again`)
  return { reasons, info }
}

function describeRows(rows: readonly CoverageRow[]): string {
  return rows.map((r) => (r.why ? `${r.variable} (${r.why})` : r.variable)).join(", ")
}

function newest(times: readonly string[]): string | null {
  return times.reduce<string | null>((a, b) => (a === null || Date.parse(b) > Date.parse(a) ? b : a), null)
}

function compareCommands(snapshot: SnapshotRecord | null, adoption: string | null): string {
  const archive = snapshot ? snapshot.archive : "<snp_id>.age"
  return `take an export with mehen backup export --to <dir>, save mehen adopt status ${adoption ?? "<adp_id>"} --json > adoption.json, then on the key machine run mehen backup compare ${archive} <export>.age --identity - --map adoption.json --json > compare.json and give it with --compared compare.json`
}

export async function assessRetire(inputs: RetireInputs, ctx: ApplyContext, options: RetireOptions): Promise<{ files: Checked[]; verify: VerifyReport }> {
  const { plan, stored } = inputs
  const verify = await verifyPlan(plan, stored, ctx, { repos: options.paths.length === 0 && options.repos.length > 0 ? [...options.repos] : null, session: options.session, now: options.now })
  const files: Checked[] = []
  for (const path of planFiles(plan)) {
    if (!selected(path, plan, options)) continue
    const ids = sourceIds(plan, path)
    const sources = ids.map((id) => plan.sources[id]).filter((s) => s !== undefined)
    const type = sources[0]?.type ?? null
    const behind = plan.items.filter((i) => (i.include || i.exists) && takes(i, ids))
    const refs = behind.map((i) => i.ref)
    const named = options.paths.includes(path)
    const checked: Checked = { path, state: "held", reasons: [], notes: [], info: null, snapshot: null, adoption: null, refs }
    files.push(checked)
    const reasons = checked.reasons

    // 1. What kind of file it is.
    if (type === null || !MOVABLE.has(type)) reasons.push(byHand(type))
    else if (type === "secrets-file" && sources.some((s) => s.variable === null)) reasons.push("edit by hand: a key or certificate kept whole in a file, which a program may read by its path")
    if (reasons.length) continue

    // 2. The file itself.
    checked.snapshot = newestHolding(inputs.snapshots, path)
    const file = await fileReasons(path, checked.snapshot, inputs.planPath)
    checked.info = file.info
    reasons.push(...file.reasons)

    // 3. Coverage, the env check and the live checks.
    const target = verify.targets.find((t) => t.coverage.some((c) => c.file === path))
    const rows = target ? target.coverage.filter((c) => c.file === path) : await ownCoverage(plan, stored, path, ctx)
    const gaps = rows.filter((r) => r.state === "gap")
    const skipped = rows.filter((r) => r.state === "skipped")
    if (rows.length === 0) reasons.push("adopt found no name in it; move it by hand if nothing needs it")
    if (gaps.length) reasons.push(`${plural(gaps.length, "name")} would be lost: ${describeRows(gaps)}`)
    if (skipped.length) reasons.push(`${plural(skipped.length, "name is", "names are")} not in Mehen: ${describeRows(skipped)}`)
    for (const env of new Set(rows.map((r) => r.env))) {
      const check = target?.checks.find((c) => c.env === env)
      if (check && !check.ok) reasons.push(`mehen env check --env ${env} does not pass in ${targetRoot(plan, path) ?? dirname(path)}: ${check.why ?? `${check.unresolved.join(", ")} do not resolve`}`)
    }
    for (const ref of refs) {
      const live = verify.items.find((i) => i.ref === ref)
      if (live && live.check !== "ok" && live.check !== "none") reasons.push(`the live check of ${live.slug} ${live.check}${live.why ? `: ${live.why}` : ""}`)
    }

    // The batches that stored what this file holds; every approved one
    // when none did (its items were already in the vault).
    const holding = inputs.batches.filter((b) => refs.some((r) => b.planRefs.has(r)))
    const batches = holding.length ? holding : inputs.batches
    const unrecorded = batches.filter((b) => b.appliedAt === null).map((b) => b.adoption)
    const appliedAt = unrecorded.length ? null : newest(batches.map((b) => b.appliedAt as string))
    const adoption = [...batches].sort((a, b) => ((a.appliedAt ?? "") < (b.appliedAt ?? "") ? 1 : -1))[0]?.adoption ?? null
    checked.adoption = adoption
    if (unrecorded.length) reasons.push(`this machine has no record of when ${unrecorded.join(", ")} ${unrecorded.length === 1 ? "was" : "were"} applied; run mehen adopt apply again (it changes nothing already set)`)

    // 4. A program gets these values from Mehen.
    const root = targetRoot(plan, path)
    if (named) checked.notes.push("named with --path: not checked for runs under mehen run, since you say nothing reads it any more")
    else if (root === null) reasons.push(`nothing runs these under mehen run yet; switch the program that reads ${path} to mehen run first`)
    else if ((await lstat(join(root, MANIFEST_FILE)).catch(() => null)) === null) reasons.push(`${root} has no ${MANIFEST_FILE}; run mehen adopt apply first`)
    else if (appliedAt !== null) {
      const inRoot = inputs.runs.filter((r) => r.root === root).sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0))
      const clean = inRoot.filter((r) => Date.parse(r.at) >= Date.parse(appliedAt) && cleanRun(r))
      const last = inRoot.at(-1)
      if (clean.length < options.minRuns) reasons.push(`${plural(clean.length, "clean run")} under mehen run in ${root} since ${adoption} was applied; ${options.minRuns} needed`)
      else {
        const span = Date.parse((clean.at(-1) as RunLogEntry).at) - Date.parse((clean[0] as RunLogEntry).at)
        if (span < options.minDays * DAY_MS) reasons.push(`the clean runs in ${root} since ${adoption} was applied span ${(span / DAY_MS).toFixed(1)} days; ${plural(options.minDays, "day")} needed between the first and the last`)
      }
      if (last && !cleanRun(last)) reasons.push(`the newest run in ${root}, at ${last.at}, exited ${last.exit}`)
    }

    // 5. The backup compare.
    const compared = inputs.compared
    if (compared === null) reasons.push(`no backup compare: ${compareCommands(checked.snapshot, adoption)}`)
    else {
      const c = compared.result
      if (c.exportedAt === undefined || c.matching === undefined) reasons.push(`${compared.path} is from an older mehen; run mehen backup compare --json again with this one`)
      else {
        if (checked.snapshot !== null && c.snapshot !== checked.snapshot.id) reasons.push(`the compare used snapshot ${c.snapshot}, not ${checked.snapshot.id}, the newest snapshot holding this file; compare again with ${checked.snapshot.archive}`)
        if (appliedAt !== null && Date.parse(c.exportedAt) <= Date.parse(appliedAt)) reasons.push(`export ${c.export} was taken at ${c.exportedAt}, before ${adoption} was applied at ${appliedAt}; take a new export and compare again`)
        const key = (s: { variable: string | null; pointer: string | null }) => `${s.variable ?? ""}\u0000${s.pointer ?? ""}`
        const here = <T extends { path: string }>(list: readonly T[]) => list.filter((s) => s.path === path)
        const different = new Set(here(c.different).map(key))
        const missing = new Map(here(c.missing).map((s) => [key(s), s.why]))
        const matching = new Set(here(c.matching).map(key))
        const secretIds = ids.filter((id) => behind.some((i) => Object.values(i.fields).some((f) => f.from.includes(id))))
        for (const id of secretIds) {
          const source = plan.sources[id]
          if (source === undefined) continue
          const name = source.variable ?? source.pointer ?? "the file"
          const k = key(source)
          if (different.has(k)) reasons.push(`${name} differs from Mehen in export ${c.export}`)
          else if (missing.has(k)) reasons.push(`the compare could not check ${name}: ${missing.get(k)}`)
          else if (!matching.has(k)) reasons.push(`the compare did not check ${name}; compare with the map of the batch that holds it`)
        }
      }
    }
    if (reasons.length === 0) checked.state = "ready"
  }
  return { files, verify }
}

// ---------------------------------------------------------------- moving

export type MoveFs = { link: (from: string, to: string) => Promise<void>; writeNewFile?: typeof writeNewFile }
const NODE_FS: MoveFs = { link, writeNewFile }

async function privateDirs(base: string, parts: readonly string[]): Promise<string> {
  let dir = base
  for (const part of parts) {
    dir = join(dir, part)
    await mkdir(dir, { mode: 0o700 }).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "EEXIST") throw error
    })
    const info = await lstat(dir)
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`${dir} is not a directory`)
    if ((info.mode & 0o077) !== 0) await chmod(dir, 0o700)
  }
  return dir
}

async function fileSha256(path: string): Promise<string> {
  const read = await readRegularFile(path, { maxBytes: MAX_SOURCE_BYTES, ownOnly: true })
  if (read === null) throw new Error(`${path} is not there any more`)
  return await sha256Hex(read.bytes)
}

function errorCode(error: unknown): string {
  return (error as NodeJS.ErrnoException).code ?? (error instanceof Error ? error.message : String(error))
}

// A move that failed after the original was renamed aside and could not be
// put back: `note` says where it is.
class LeftAside extends Error {
  constructor(
    message: string,
    readonly note: string,
  ) {
    super(message)
  }
}

// `aside` back to `from`, never over a file that appeared there since.
async function putBack(aside: string, from: string): Promise<string | null> {
  try {
    await link(aside, from)
    await unlink(aside)
    return null
  } catch (error) {
    return `${LEFT_ASIDE}${aside} (${errorCode(error)} putting it back); compare it with ${from} by hand`
  }
}

function linkTo(fs: MoveFs, from: string, to: string): Promise<boolean> {
  return fs.link(from, to).then(
    () => true,
    (error: NodeJS.ErrnoException) => {
      if (error.code === "EEXIST") throw new Error(`something is already at ${to}`)
      if (error.code !== "EXDEV") throw error
      return false
    },
  )
}

// The same file, as far as a rename leaves it: a rename changes the ctime.
function sameUnchanged(a: Stats, b: Stats): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeMs === b.mtimeMs
}

function asidePath(from: string): string {
  return join(dirname(from), `.${basename(from)}.${randomId("retiring", 6)}`)
}

// `aside`, the file at `from` renamed aside in its own folder, to `to`,
// once it is still the file `expected` describes: a hard link at `to`
// when both are on one volume, otherwise a copy written with
// O_EXCL and O_NOFOLLOW, flushed, read back and compared; only then is
// `aside` unlinked. A file saved at `from` from the rename on is never
// touched. If a step fails the file goes back to `from`, never over a
// file that appeared there. The bytes are compared in memory only: no hash
// of them is ever written. Throws when nothing moved; once the file is at
// `to`, returns what went wrong after that.
async function placeFromAside(from: string, aside: string, to: string, mode: number, expected: Stats, fs: MoveFs): Promise<string[]> {
  let placed = false
  let linked = false
  let sha256 = ""
  try {
    const held = await readRegularFile(aside, { maxBytes: MAX_SOURCE_BYTES, ownOnly: true })
    if (held === null || !sameUnchanged(held.info, expected)) throw new Error(`${from} changed while it was being moved`)
    sha256 = await sha256Hex(held.bytes)
    linked = await linkTo(fs, aside, to)
    if (linked) {
      const at = await lstat(to).catch(() => null)
      if (at === null || at.dev !== held.info.dev || at.ino !== held.info.ino) throw new Error(`something other than ${from} appeared at ${to}`)
      placed = true
    } else {
      await (fs.writeNewFile ?? writeNewFile)(to, held.bytes, { mode })
      placed = true
      if ((await fileSha256(to).catch(() => null)) !== sha256) throw new Error(`${from} did not copy to ${to} intact`)
    }
    await unlink(aside)
  } catch (error) {
    if (placed) await unlink(to).catch(() => undefined)
    const why = error instanceof Error ? error.message : String(error)
    const stuck = await putBack(aside, from)
    throw stuck === null ? new Error(why) : new LeftAside(why, stuck)
  }
  const problems: string[] = []
  if (linked) {
    await chmod(to, mode).catch((error: unknown) => problems.push(`${to} could not be given mode ${mode.toString(8)} (${errorCode(error)})`))
    if ((await fileSha256(to).catch(() => null)) !== sha256) problems.push(`${from} changed as it moved; compare ${to} with what you expect by hand`)
  }
  return problems
}

// Retire's move of an original to `to` in quarantine, which must not
// exist, only while it is still the file retire checked (`expected`). The
// original is renamed to `aside` first, on every volume, so nothing saved
// at its path as it moves can be deleted.
export async function retireFile(from: string, aside: string, to: string, expected: Stats, fs: MoveFs = NODE_FS): Promise<string[]> {
  if ((await lstat(to).catch(() => null)) !== null) throw new Error(`something is already at ${to}`)
  await rename(from, aside).catch((error: unknown) => {
    throw new Error(errorCode(error) === "ENOENT" ? `${from} is not there any more` : `${from} could not be moved (${errorCode(error)})`)
  })
  return await placeFromAside(from, aside, to, 0o600, expected, fs)
}

// Unretire's move of a quarantined copy back to `to`, which must not
// exist: on one volume a hard link at `to`, which refuses anything that
// appeared there, then the quarantined copy, which only mehen writes,
// unlinked. Across volumes, a copy written with O_EXCL and read back,
// then recorded with `recordCopy`, a new file unretire can know again as
// the one it put back; the quarantined copy stays where the index says
// until then, so a crash never leaves it under another name. Nothing at
// `to` that is not the file mehen put there is ever unlinked. A copy that
// cannot be known as the quarantined one refuses, so the index keeps
// naming the quarantined copy; once `to` is placed and known, anything
// wrong is a note and the quarantined copy stays.
async function restoreFile(from: string, to: string, mode: number, fs: MoveFs, recordCopy: (copy: Stats) => Promise<void>): Promise<string[]> {
  if ((await lstat(to).catch(() => null)) !== null) throw new Error(`something is already at ${to}`)
  const read = await readRegularFile(from, { maxBytes: MAX_SOURCE_BYTES, ownOnly: true })
  if (read === null) throw new Error(`${from} is not there any more`)
  const sha256 = await sha256Hex(read.bytes)
  const stillThere = (error: unknown) => [`${from} could not be unlinked (${errorCode(error)}), so the copy is still in quarantine too; delete it once ${to} is right`]
  if (!(await linkTo(fs, from, to))) {
    await (fs.writeNewFile ?? writeNewFile)(to, read.bytes, { mode })
    const copy = await readRegularFile(to, { maxBytes: MAX_SOURCE_BYTES, ownOnly: true }).catch(() => null)
    if (copy === null || (await sha256Hex(copy.bytes)) !== sha256) throw new Error(`${to} does not read back as ${from} was, so ${from} is kept in quarantine; compare them by hand`)
    const now = await lstat(from).catch(() => null)
    if (now === null || !sameFile(now, read.info)) throw new Error(`${from} changed as it was copied to ${to}, so it is kept in quarantine; compare them by hand`)
    const unrecorded = await recordCopy(copy.info).then(
      () => null,
      (error: unknown) => errorCode(error),
    )
    if (unrecorded !== null) return [`the quarantine index could not record the copy at ${to} (${unrecorded}), so ${from} is still in quarantine too; delete it once ${to} is right`]
    return await unlink(from).then((): string[] => [], stillThere)
  }
  const at = await lstat(to).catch(() => null)
  if (at === null || at.dev !== read.info.dev || at.ino !== read.info.ino) throw new Error(`something other than ${from} appeared at ${to} as it was put back; ${to} is left as it is and the copy is kept in quarantine, but unretire will not put it back now: once ${to} is sorted, move ${from} there by hand`)
  const problems = await unlink(from).then((): string[] => [], stillThere)
  await chmod(to, mode).catch((error: unknown) => problems.push(`${to} could not be given mode ${mode.toString(8)} (${errorCode(error)})`))
  if ((await fileSha256(to).catch(() => null)) !== sha256) problems.push(`${from} changed as it moved; compare ${to} with what you expect by hand`)
  return problems
}

// Written before a move's first step: where the original is renamed aside
// and where it goes. A crash before the move ends leaves it with no line
// ending it, which retire and unretire report.
const MovingLine = z.strictObject({
  moving: z.string(),
  path: z.string(),
  aside: z.string(),
  quarantined: z.string(),
  at: z.iso.datetime(),
})
type MovingLine = z.infer<typeof MovingLine>

// Ends a move that failed with the original back at its path.
const MoveEndedLine = z.strictObject({ ended: z.string(), at: z.iso.datetime() })
type MoveEndedLine = z.infer<typeof MoveEndedLine>

// One line per quarantined file, ending its move. `dev`, `ino`, `mtimeMs`
// and `ctimeMs` are the quarantined copy's once it is in place, which
// unretire requires unchanged; never its size or a hash of its bytes.
// `dev` is missing from lines an older retire wrote. `restored` is only in
// an index an older unretire rewrote.
const IndexLine = z.strictObject({
  path: z.string(),
  quarantined: z.string(),
  dev: z.number().int().optional(),
  ino: z.number().int(),
  mtimeMs: z.number(),
  ctimeMs: z.number(),
  mode: z.number().int(),
  at: z.iso.datetime(),
  adoption: z.string().nullable(),
  refs: z.array(z.string()),
  ended: z.string().optional(),
  restored: z.iso.datetime().optional(),
})
type IndexLine = z.infer<typeof IndexLine>

// Added by unretire once it has put a file back: the newest line before it
// for that path and quarantined copy is restored. Retire and unretire only
// ever add lines, so neither can lose one the other adds.
const RestoredLine = z.strictObject({ restored: z.iso.datetime(), path: z.string(), quarantined: z.string() })
type RestoredLine = z.infer<typeof RestoredLine>

// Added by unretire across volumes before it unlinks the quarantined copy:
// the new file it copied to the path, which a later unretire takes as put
// back, like the quarantined copy itself, should the restored line be missing.
const CopiedLine = z.strictObject({ copied: z.iso.datetime(), path: z.string(), quarantined: z.string(), dev: z.number().int(), ino: z.number().int(), mtimeMs: z.number() })
type CopiedLine = z.infer<typeof CopiedLine>

// A line appended to the index that could not be flushed to disk: its
// message is the error code.
class IndexNotSaved extends Error {}

async function appendIndex(path: string, line: IndexLine | MovingLine | MoveEndedLine | RestoredLine | CopiedLine, guard: OutputGuard): Promise<void> {
  const text = `${JSON.stringify(line)}\n`
  guard.assertClean(text)
  const handle = await open(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o600)
  try {
    if (!(await handle.stat()).isFile()) throw new Error(`${path} is not a regular file`)
    await handle.write(text)
    await handle.sync().catch((error: unknown) => {
      throw new IndexNotSaved(errorCode(error))
    })
  } finally {
    await handle.close()
  }
}

function sameFile(a: Stats, b: Stats): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs
}

export type QuarantineOptions = { adoptDir: string; planPath: string; now: Date; guard: OutputGuard; fs?: MoveFs }

// Moves every ready file; one failing never stops the others.
export async function quarantine(files: Checked[], options: QuarantineOptions): Promise<void> {
  const fs = options.fs ?? NODE_FS
  const base = join(options.adoptDir, QUARANTINE_DIR)
  const day = options.now.toISOString().slice(0, 10)
  const indexPath = join(base, QUARANTINE_INDEX)
  for (const file of files) {
    if (file.state !== "ready") continue
    let to: string
    let problems: string[]
    let mode: number
    let move: MovingLine | undefined
    try {
      // Rules 1 and 2 again, at the moment of the move, on the very file
      // retire looked at.
      const again = await fileReasons(file.path, file.snapshot, options.planPath)
      if (again.reasons.length) throw new Error(again.reasons.join("; "))
      if (file.info === null || again.info === null || !sameFile(file.info, again.info)) throw new Error("it changed while retire ran; run retire again")
      const hash = (await sha256Hex(utf8(file.path))).slice(0, 16)
      await mkdir(options.adoptDir, { recursive: true, mode: 0o700 })
      const dir = await privateDirs(options.adoptDir, [QUARANTINE_DIR, day, hash])
      to = join(dir, basename(file.path))
      mode = again.info.mode & 0o777
      // Set first, so a line written but not saved to disk is still ended.
      move = { moving: randomId("mv", 8), path: file.path, aside: asidePath(file.path), quarantined: to, at: options.now.toISOString() }
      await appendIndex(indexPath, move, options.guard).catch((error: unknown) => {
        throw new Error(`the quarantine index could not record the move (${errorCode(error)})`)
      })
      problems = await retireFile(file.path, move.aside, to, again.info, fs)
    } catch (error) {
      file.state = "failed"
      file.reasons.push(error instanceof Error ? error.message : String(error))
      // Left aside, its move stays open in the index, so later runs name it.
      if (error instanceof LeftAside) file.notes.push(error.note)
      else if (move !== undefined) await appendIndex(indexPath, { ended: move.moving, at: options.now.toISOString() }, options.guard).catch(() => undefined)
      continue
    }
    // Moved: from here on the file is reported moved, whatever else fails.
    file.state = "moved"
    file.notes.push(`moved to ${to}`, ...problems)
    try {
      const held = await lstat(to)
      await appendIndex(indexPath, { path: file.path, quarantined: to, dev: held.dev, ino: held.ino, mtimeMs: held.mtimeMs, ctimeMs: held.ctimeMs, mode, at: options.now.toISOString(), adoption: file.adoption, refs: file.refs, ended: move.moving }, options.guard)
    } catch (error) {
      file.notes.push(`${NOT_INDEXED} (${errorCode(error)}); if mehen adopt unretire ${file.path} does not put it back, move ${to} to ${file.path} by hand`)
    }
  }
}

export function retireReport(files: readonly Checked[], unfinished: UnfinishedMove[]): RetireReport {
  return {
    files: files.map(({ path, state, reasons, notes }) => ({ path, state, reasons, notes })),
    moved: files.filter((f) => f.state === "moved").length,
    held: files.filter((f) => f.state === "held").length,
    unfinished,
  }
}

// Retire exits with an error when a ready file did not move, or moved with
// no index line, so unretire cannot put it back.
export function retireFailed(report: RetireReport): boolean {
  return report.files.some((f) => f.state === "failed" || f.notes.some((n) => n.startsWith(NOT_INDEXED)))
}

// ---------------------------------------------------------------- unretire

// `reasons`: why a file was refused, or what was not right once a restored
// file was back.
export type UnretireFile = { path: string; state: "restored" | "refused"; reasons: string[]; quarantined: string | null }
export type UnretireReport = { files: UnretireFile[]; restored: number; refused: number; unfinished: UnfinishedMove[] }

// The index read in order, its restored and copied lines folded into the
// lines they mark; a line this mehen cannot read, such as one from a newer
// mehen, is passed over.
type QuarantinedFile = { line: IndexLine; restored: string | null; copy: CopiedLine | null }
type QuarantineIndex = { files: QuarantinedFile[]; moving: MovingLine[]; ended: Set<string> }

async function readIndex(path: string): Promise<QuarantineIndex> {
  const index: QuarantineIndex = { files: [], moving: [], ended: new Set() }
  const read = await readRegularFile(path, { maxBytes: 16 * 1024 * 1024, ownOnly: true })
  if (read === null) return index
  for (const raw of Buffer.from(read.bytes).toString("utf8").split("\n")) {
    if (raw === "") continue
    let parsed: unknown = null
    try {
      parsed = JSON.parse(raw)
    } catch {
      parsed = null
    }
    const line = IndexLine.safeParse(parsed)
    const restored = RestoredLine.safeParse(parsed)
    const copied = CopiedLine.safeParse(parsed)
    const moving = MovingLine.safeParse(parsed)
    const ended = MoveEndedLine.safeParse(parsed)
    const open = (original: string, quarantined: string) => index.files.filter((f) => f.restored === null && f.line.path === original && f.line.quarantined === quarantined).at(-1)
    if (line.success) {
      index.files.push({ line: line.data, restored: line.data.restored ?? null, copy: null })
      if (line.data.ended !== undefined) index.ended.add(line.data.ended)
    } else if (restored.success) {
      const marked = open(restored.data.path, restored.data.quarantined)
      if (marked !== undefined) marked.restored = restored.data.restored
    } else if (copied.success) {
      const marked = open(copied.data.path, copied.data.quarantined)
      if (marked !== undefined) marked.copy = copied.data
    } else if (moving.success) index.moving.push(moving.data)
    else if (ended.success) index.ended.add(ended.data.ended)
  }
  return index
}

async function unfinishedNote(move: MovingLine, indexPath: string): Promise<string> {
  const there = async (path: string) => (await lstat(path).catch(() => null)) !== null
  const begun = `a move of ${move.path} begun at ${move.at} never finished`
  const then = `then delete the line with "moving":"${move.moving}" from ${indexPath}`
  const taken = await there(move.path)
  if (await there(move.aside)) return `${begun}: the original is at ${move.aside}; ${taken ? `compare it with ${move.path}` : `move it back to ${move.path}`} by hand, ${then}`
  if (await there(move.quarantined)) return `${begun}: it is at ${move.quarantined}, which unretire cannot put back; ${taken ? `compare it with ${move.path}` : `move it to ${move.path}`} by hand, ${then}`
  if (taken) return `${begun}: it looks never to have moved, since ${move.path} is there and neither ${move.aside} nor ${move.quarantined} is; make sure ${move.path} is the file you expect, ${then}`
  return `${begun}: neither ${move.aside} nor ${move.quarantined} is there; check ${move.path} by hand, ${then}`
}

async function unfinishedIn(index: QuarantineIndex, indexPath: string): Promise<UnfinishedMove[]> {
  const open = index.moving.filter((m) => !index.ended.has(m.moving))
  return await Promise.all(open.map(async (m) => ({ path: m.path, at: m.at, aside: m.aside, quarantined: m.quarantined, note: await unfinishedNote(m, indexPath) })))
}

// Every move in the adopt dir's quarantine index that never finished.
export async function unfinishedMoves(adoptDir: string): Promise<UnfinishedMove[]> {
  const indexPath = join(adoptDir, QUARANTINE_DIR, QUARANTINE_INDEX)
  return await unfinishedIn(await readIndex(indexPath), indexPath)
}

// The file an index line records, by its device when the line has one.
function sameRecorded(info: Stats, recorded: { dev?: number; ino: number; mtimeMs: number }): boolean {
  return (recorded.dev === undefined || info.dev === recorded.dev) && info.ino === recorded.ino && info.mtimeMs === recorded.mtimeMs
}

export type UnretireOptions = { adoptDir: string; paths: readonly string[] | null; now: Date; guard: OutputGuard; fs?: MoveFs }

// Puts quarantined files back where they were, with their recorded mode,
// and adds a restored line to the index for each. Refuses, per file, when
// anything is at the original path now.
export async function unretire(options: UnretireOptions): Promise<UnretireReport> {
  const fs = options.fs ?? NODE_FS
  const indexPath = join(options.adoptDir, QUARANTINE_DIR, QUARANTINE_INDEX)
  const index = await readIndex(indexPath)
  const waiting = index.files.filter((f) => f.restored === null)
  const wanted = options.paths ?? [...new Set(waiting.map((f) => f.line.path))]
  const files: UnretireFile[] = []
  for (const path of wanted) {
    const entry = waiting.filter((f) => f.line.path === path).at(-1)
    if (entry === undefined) {
      files.push({ path, state: "refused", reasons: ["it is not in quarantine"], quarantined: null })
      continue
    }
    const { line, copy } = entry
    const file: UnretireFile = { path, state: "refused", reasons: [], quarantined: line.quarantined }
    files.push(file)
    try {
      const at = await lstat(path).catch(() => null)
      const held = await lstat(line.quarantined).catch(() => null)
      // An unretire that put it back and stopped before its index line.
      if (at !== null && held === null && (sameRecorded(at, line) || (copy !== null && sameRecorded(at, copy)))) {
        file.reasons.push("it was already back; an earlier unretire put it back but could not mark it restored")
        // One that stopped before it set the mode left the quarantined copy's.
        if ((at.mode & 0o777) !== line.mode) await chmod(path, line.mode).catch((error: unknown) => file.reasons.push(`${path} could not be given mode ${line.mode.toString(8)} (${errorCode(error)})`))
      } else {
        if (at !== null) throw new Error(`${path} exists; compare it with ${line.quarantined} by hand`)
        const parent = await lstat(dirname(path)).catch(() => null)
        if (parent === null || !parent.isDirectory()) throw new Error(`${dirname(path)} is not there any more; make it, then run unretire again`)
        if (held === null || !held.isFile() || held.isSymbolicLink()) throw new Error(`${line.quarantined} is not there any more`)
        if (!sameRecorded(held, line) || held.ctimeMs !== line.ctimeMs) throw new Error(`${line.quarantined} changed in quarantine; compare it with what you expect by hand`)
        const recordCopy = (made: Stats) => appendIndex(indexPath, { copied: options.now.toISOString(), path, quarantined: line.quarantined, dev: made.dev, ino: made.ino, mtimeMs: made.mtimeMs }, options.guard)
        file.reasons.push(...(await restoreFile(line.quarantined, path, line.mode, fs, recordCopy)))
      }
      file.state = "restored"
    } catch (error) {
      file.reasons.push(error instanceof Error ? error.message : String(error))
      continue
    }
    await appendIndex(indexPath, { restored: options.now.toISOString(), path, quarantined: line.quarantined }, options.guard).catch((error: unknown) => {
      file.reasons.push(error instanceof IndexNotSaved ? `${path} is back; the quarantine index line marking it restored was written but could not be saved to disk (${error.message})` : `${path} is back, but the quarantine index could not mark it restored (${errorCode(error)}), so unretire still lists it`)
    })
  }
  return { files, restored: files.filter((f) => f.state === "restored").length, refused: files.filter((f) => f.state === "refused").length, unfinished: await unfinishedIn(index, indexPath) }
}
