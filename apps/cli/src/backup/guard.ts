// The gate before `adopt submit`: nothing is adopted until a passed
// snapshot holds every file the plan names. There is no bypass.

import { lstat } from "node:fs/promises"
import type { Env } from "../config.ts"
import { checkSnapshot } from "./check.ts"
import { backupFailure } from "./files.ts"
import { namedPaths, readPlan } from "./snapshot.ts"
import { type SnapshotRecord, readSnapshotRecords } from "./state.ts"

export type RequireSnapshotOptions = { planPath: string; snapshot?: string; env?: Env }

export function snapshotCommand(planPath: string): string {
  return `mehen backup snapshot --plan ${planPath} --to <dir outside your repos> --recipient <age1...>`
}

// The first of `paths` changed after `createdAt`, or null. A path that is
// not there has not changed. ctime as well as mtime: anyone who owns a file
// can put its mtime back (touch -r, cp -p, rsync -t), but not its ctime.
export async function changedSince(paths: readonly string[], createdAt: string): Promise<string | null> {
  const at = Date.parse(createdAt)
  for (const path of paths) {
    const info = await lstat(path).catch(() => null)
    if (info && (info.mtimeMs > at || info.ctimeMs > at)) return path
  }
  return null
}

// The newest recorded snapshot with a passed self-check that lists every
// path the plan names, none of which has changed since, whose archive is
// still where it was written and passes `mehen backup check`. An archive
// moved off this machine passes only when --snapshot names it; one that is
// there but damaged never does. Throws the refusal otherwise, naming the
// first path, or the archive, that falls short.
export async function requireSnapshot(options: RequireSnapshotOptions): Promise<{ id: string; path: string }> {
  const env = options.env ?? process.env
  const read = await readPlan(options.planPath)
  const paths = await namedPaths(read)
  const command = snapshotCommand(read.path)
  let records = (await readSnapshotRecords(env)).filter((r) => r.selfCheck === "passed")
  if (options.snapshot !== undefined) {
    records = records.filter((r) => r.id === options.snapshot)
    if (records.length === 0) throw backupFailure(`No passed snapshot ${options.snapshot} is recorded on this machine.`, "Take a snapshot of this plan first; adopt submit is refused until one holds every file the plan names.", command)
  }
  records.sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0))
  let refusal: { record: SnapshotRecord; path: string; why: "missing" | "changed" | "gone" | "damaged"; detail?: string } | null = null
  for (const record of records) {
    const covered = new Set(record.paths)
    const missing = paths.find((p) => !covered.has(p))
    if (missing !== undefined) {
      refusal ??= { record, path: missing, why: "missing" }
      continue
    }
    const newer = await changedSince(paths, record.createdAt)
    if (newer !== null) {
      refusal ??= { record, path: newer, why: "changed" }
      continue
    }
    if ((await lstat(record.archive).catch(() => null)) === null) {
      if (options.snapshot === record.id) return { id: record.id, path: record.archive }
      refusal ??= { record, path: record.archive, why: "gone" }
      continue
    }
    try {
      await checkSnapshot(record.archive)
    } catch (error) {
      refusal ??= { record, path: record.archive, why: "damaged", detail: (error as Error).message }
      continue
    }
    return { id: record.id, path: record.archive }
  }
  if (refusal === null) throw backupFailure(`No passed snapshot of ${read.path} is recorded on this machine, so nothing is adopted yet.`, "Take a snapshot of this plan first; adopt submit is refused until one holds every file the plan names.", command)
  const which = `snapshot ${refusal.record.id}`
  if (refusal.why === "missing") throw backupFailure(`The plan names ${refusal.path}, which ${which} does not hold, so nothing is adopted yet.`, "Take a new snapshot of this plan; adopt submit is refused until one holds every file the plan names.", command)
  if (refusal.why === "gone") throw backupFailure(`The archive of ${which}, ${refusal.path}, is not there, so nothing is adopted yet.`, `If you moved it off this machine, name it with --snapshot ${refusal.record.id}; otherwise take a new snapshot of this plan.`, command)
  if (refusal.why === "damaged") throw backupFailure(`The archive of ${which} fails its check, so nothing is adopted yet: ${refusal.detail}`, "Take a new snapshot of this plan while the sources are still in place.", command)
  throw backupFailure(`${refusal.path} changed after ${which} was taken, so nothing is adopted yet.`, "Take a new snapshot of this plan so it holds the files as they are now.", command)
}
