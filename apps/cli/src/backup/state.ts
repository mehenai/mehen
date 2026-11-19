// The snapshots this machine has taken, under MEHEN_HOME at
// backups/snapshots.json (mode 0600): ids, paths, digests and times, never
// a value. `requireSnapshot` (guard.ts) reads it before `adopt submit`.

import { join } from "node:path"
import { SnapshotIdSchema, SnapshotPathSchema, Sha256HexSchema } from "@mehen/protocol/backup"
import { fromUtf8 } from "@mehen/protocol/bytes"
import { z } from "zod"
import { type Env, writePrivateFile } from "../config.ts"
import { ensureSafeRoot, mkdirPrivate, resolveHome } from "../home.ts"
import { CliError } from "../errors.ts"
import { readRegularFile } from "./files.ts"

export const BACKUP_STATE_DIR = "backups"
export const BACKUP_STATE_FILE = "snapshots.json"

export const SnapshotRecordSchema = z.strictObject({
  id: SnapshotIdSchema,
  // The archive as it was written; it may since have been copied elsewhere.
  archive: z.string().min(1),
  planPath: z.string().min(1),
  planDigest: Sha256HexSchema,
  // What the plan named, the plan file itself not included.
  paths: z.array(SnapshotPathSchema),
  createdAt: z.iso.datetime(),
  selfCheck: z.literal("passed"),
  // The archive's length and SHA-256 as written, as in its sidecar: only
  // that archive restores in place. Older records hold none.
  ciphertext: z.strictObject({ bytes: z.number().int().positive(), sha256: Sha256HexSchema }).optional(),
})
export type SnapshotRecord = z.infer<typeof SnapshotRecordSchema>

const BackupStateSchema = z.strictObject({ version: z.literal(1), snapshots: z.array(SnapshotRecordSchema) })

export function backupStatePath(env: Env): string {
  return join(resolveHome(env).root, BACKUP_STATE_DIR, BACKUP_STATE_FILE)
}

function corrupt(path: string, why: string): CliError {
  return new CliError("failed", `The backup state ${path} ${why}.`, { say: `Move ${path} aside and take a new snapshot with \`mehen backup snapshot\`.` })
}

export async function readSnapshotRecords(env: Env): Promise<SnapshotRecord[]> {
  const path = backupStatePath(env)
  const read = await readRegularFile(path, { maxBytes: 16 * 1_048_576, ownOnly: true })
  if (read === null) return []
  if ((read.info.mode & 0o077) !== 0) throw corrupt(path, "can be read or written by other users")
  let parsed: unknown
  try {
    parsed = JSON.parse(fromUtf8(new Uint8Array(read.bytes)))
  } catch {
    throw corrupt(path, "is not JSON")
  }
  const state = BackupStateSchema.safeParse(parsed)
  if (!state.success) throw corrupt(path, "is not a backup state mehen recognises")
  return state.data.snapshots
}

// Makes the state's directory and reads what is there, so a root or a
// state file mehen would refuse fails before any snapshot work starts.
export async function prepareBackupState(env: Env): Promise<void> {
  const { root } = resolveHome(env)
  ensureSafeRoot(root)
  mkdirPrivate(root, join(root, BACKUP_STATE_DIR))
  await readSnapshotRecords(env)
}

export async function recordSnapshot(env: Env, record: SnapshotRecord): Promise<void> {
  const { root } = resolveHome(env)
  ensureSafeRoot(root)
  mkdirPrivate(root, join(root, BACKUP_STATE_DIR))
  const snapshots = [...(await readSnapshotRecords(env)), record]
  await writePrivateFile(backupStatePath(env), `${JSON.stringify({ version: 1, snapshots }, null, 2)}\n`)
}
