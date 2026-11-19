// mehen backup snapshot: before `adopt submit`, every file the adopt plan
// names, byte for byte with its mode, owner and mtime, in one archive
// encrypted with age to backup recipients whose private half is on no
// enrolled machine. Beside it, a cleartext sidecar with no value, length or
// content hash.
//
// The archive proves itself before the command succeeds: an ephemeral
// X25519 key, made in this process and never written, is one more
// recipient. Once the archive is on disk it is read back, opened with that
// key and compared with what was read, and every source is read again and
// compared. Any difference deletes what was written and fails. The key goes
// with the process, so its stanza opens to nothing afterwards.
//
// The plan is read with its own minimal schema, the fields adopt-design
// section 3 promises (machine, source paths, service units and env files,
// repo roots), so the adopt CLI's plan schema can grow without breaking it.

import { lstat, mkdir, unlink } from "node:fs/promises"
import { userInfo } from "node:os"
import { join, resolve } from "node:path"
import {
  BACKUP_LIMITS,
  SNAPSHOT_FORMAT,
  SNAPSHOT_SIDECAR_FORMAT,
  type Snapshot,
  type SnapshotFile,
  SnapshotPathSchema,
  SnapshotSchema,
  type SnapshotSidecar,
  ageRecipientFingerprint,
  parseAgeRecipient,
  sha256Hex,
  snapshotPlaintext,
} from "@mehen/protocol/backup"
import { fromUtf8, randomId, utf8 } from "@mehen/protocol/bytes"
import { z } from "zod"
import type { Env } from "../config.ts"
import { usageError } from "../errors.ts"
import { ageDecrypt, ageEncrypt, ephemeralAgeIdentity } from "./age.ts"
import { backupFailure, base64, gitWorkTreeAbove, groupName, insideDir, readRegularFile, realTarget, writeNewFile } from "./files.ts"
import { prepareBackupState, recordSnapshot } from "./state.ts"

export const RECIPIENTS_ENV = "MEHEN_BACKUP_RECIPIENTS"
export const MANIFEST_FILE = "mehen.toml"

const PathText = z.string().min(1).max(4096)
const PlanSource = z.looseObject({ path: PathText })
const PlanSources = z.union([z.record(z.string(), PlanSource), z.array(PlanSource)])

export const SnapshotPlanSchema = z.looseObject({
  machine: z.string().min(1).max(256),
  sources: PlanSources.optional(),
  items: z.array(z.looseObject({ sources: PlanSources.optional() })).optional(),
  services: z.array(z.looseObject({ unit: PathText.optional(), envFile: PathText.nullable().optional() })).optional(),
  repos: z.array(z.looseObject({ root: PathText })).optional(),
})
export type SnapshotPlan = z.infer<typeof SnapshotPlanSchema>

export type ReadPlan = { path: string; bytes: Uint8Array; digest: string; plan: SnapshotPlan }

const planTooLarge = `Scan fewer folders with \`mehen adopt scan --root <folder>\` and plan again; mehen reads a plan up to ${BACKUP_LIMITS.maxPlanBytes} bytes.`

export async function readPlan(planPath: string): Promise<ReadPlan> {
  const path = resolve(planPath)
  const read = await readRegularFile(path, { maxBytes: BACKUP_LIMITS.maxPlanBytes, ownOnly: true, tooLarge: planTooLarge })
  if (read === null) throw backupFailure(`There is no plan at ${path}.`, "Name the plan `mehen adopt plan` wrote with --plan <path>.")
  let json: unknown
  try {
    json = JSON.parse(fromUtf8(new Uint8Array(read.bytes)))
  } catch {
    throw backupFailure(`The plan ${path} is not JSON.`, "Name the plan `mehen adopt plan` wrote with --plan <path>.")
  }
  const plan = SnapshotPlanSchema.safeParse(json)
  if (!plan.success) throw backupFailure(`The plan ${path} has no machine, or a source, service or repo entry without its path.`, "Check the plan with `mehen adopt plan --check`, then run the command again.")
  for (const repo of plan.data.repos ?? []) requireAbsolute(path, repo.root)
  return { path, bytes: read.bytes, digest: await sha256Hex(read.bytes), plan: plan.data }
}

// Every path a plan names is absolute, so the snapshot and the guard read
// the same files whatever directory each runs in.
function requireAbsolute(planPath: string, path: string): void {
  if (!SnapshotPathSchema.safeParse(path).success) throw backupFailure(`The plan ${planPath} names ${JSON.stringify(path)}, which is not an absolute path.`, "Give every path in the plan as the absolute path `mehen adopt scan` reported.")
}

function sourcePaths(sources: z.infer<typeof PlanSources> | undefined): string[] {
  if (sources === undefined) return []
  return (Array.isArray(sources) ? sources : Object.values(sources)).map((s) => s.path)
}

export function repoRoots(plan: SnapshotPlan): string[] {
  return (plan.repos ?? []).map((r) => r.root)
}

// Every path the plan names, sorted, once: each source, each service's unit
// and env file, and the mehen.toml of each repo root that has one. The plan
// file itself is not included.
export async function namedPaths(read: ReadPlan): Promise<string[]> {
  const { plan } = read
  const named = [
    ...sourcePaths(plan.sources),
    ...(plan.items ?? []).flatMap((item) => sourcePaths(item.sources)),
    ...(plan.services ?? []).flatMap((s) => [s.unit, s.envFile].filter((p): p is string => typeof p === "string")),
  ]
  for (const root of repoRoots(plan)) {
    const manifest = join(root, MANIFEST_FILE)
    if (await lstat(manifest).catch(() => null)) named.push(manifest)
  }
  for (const path of named) requireAbsolute(read.path, path)
  return [...new Set(named)].sort()
}

// --recipient flags when there are any, otherwise MEHEN_BACKUP_RECIPIENTS
// (comma-separated). X25519 only.
// The recipients named by --recipient, or else MEHEN_BACKUP_RECIPIENTS, or
// else the caller's own active backup keys (`registered`, asked of the
// vault only when neither is given).
export function namedRecipients(flags: readonly string[], env: Env): string[] {
  return flags.length ? [...flags] : (env[RECIPIENTS_ENV] ?? "").split(",").filter((r) => r.trim() !== "")
}

export function backupRecipients(flags: readonly string[], env: Env, registered: readonly string[] = [], unreachable: string | null = null): string[] {
  const named = namedRecipients(flags, env)
  const given = named.length ? named : [...registered]
  if (given.length === 0) throw usageError(`Name the backup recipient with --recipient age1... (or set ${RECIPIENTS_ENV}), or, as an owner, add a backup key of your own on the workspace's Settings page${unreachable ? ` (the vault could not be asked for one: ${unreachable})` : ""}; \`mehen backup keygen\` or \`age-keygen\` makes one on a machine no agent uses.`, "mehen backup --help")
  const recipients: string[] = []
  for (const text of given) {
    const parsed = parseAgeRecipient(text)
    if (!parsed.ok) throw usageError(`The recipient ${JSON.stringify(text.trim())} cannot be used: ${parsed.reason}.`, "mehen backup --help")
    if (!recipients.includes(parsed.recipient)) recipients.push(parsed.recipient)
  }
  if (recipients.length > BACKUP_LIMITS.maxRecipients) throw usageError(`At most ${BACKUP_LIMITS.maxRecipients} recipients.`, "mehen backup --help")
  return recipients
}

// The directory the pair goes in: refused inside a repo root the plan names
// or inside any git work tree, so it is never committed or scanned; made
// 0700 when it does not exist.
async function outputDir(to: string, read: ReadPlan): Promise<string> {
  const target = realTarget(to)
  for (const root of repoRoots(read.plan)) {
    if (insideDir(target, realTarget(root))) throw backupFailure(`Refusing to write the snapshot to ${target}: it is inside ${root}, a repo the plan adopts.`, "Choose a directory outside every scanned root, such as ~/Backups/mehen; a synced folder is fine.")
  }
  const tree = gitWorkTreeAbove(target)
  if (tree !== null) throw backupFailure(`Refusing to write the snapshot to ${target}: it is inside the git work tree ${tree}.`, "Choose a directory outside every git work tree, such as ~/Backups/mehen; a synced folder is fine.")
  await mkdir(target, { recursive: true, mode: 0o700 })
  const info = await lstat(target)
  if (!info.isDirectory()) throw backupFailure(`Refusing to write the snapshot to ${target}: it is not a directory.`, "Name a directory with --to.")
  return target
}

type Captured = { file: SnapshotFile; mode: number; uid: number; gid: number }

// The plan is read with its own cap; every source with a source's.
async function capture(path: string, planPath: string): Promise<Captured> {
  const rules = path === planPath ? { maxBytes: BACKUP_LIMITS.maxPlanBytes, tooLarge: planTooLarge } : { maxBytes: BACKUP_LIMITS.maxFileBytes }
  const read = await readRegularFile(path, { ...rules, ownOnly: true })
  if (read === null) throw backupFailure(`The plan names ${path}, but nothing is there.`, "Run `mehen adopt scan` and `mehen adopt plan` again so the plan matches this machine.")
  const { bytes, info } = read
  const file: SnapshotFile = {
    path,
    mode: info.mode & 0o7777,
    uid: info.uid,
    gid: info.gid,
    user: userInfo().username,
    group: groupName(info.gid),
    mtimeMs: info.mtimeMs,
    size: bytes.length,
    sha256: await sha256Hex(bytes),
    content: base64(bytes),
  }
  return { file, mode: file.mode, uid: file.uid, gid: file.gid }
}

export type SnapshotOptions = {
  planPath: string
  to: string
  recipients: readonly string[]
  env: Env
  now?: () => Date
  // Runs after the archive is written and before it is checked.
  beforeSelfCheck?: () => Promise<void>
}

export type SnapshotResult = {
  id: string
  archive: string
  sidecar: string
  machine: string
  createdAt: string
  files: number
  paths: string[]
  recipients: { recipient: string; fingerprint: string }[]
  ciphertext: { bytes: number; sha256: string }
  selfCheck: "passed"
}

function changed(path: string): Error {
  return backupFailure(`The self-check failed: ${path} changed while the snapshot was taken, so nothing was kept.`, "Run `mehen backup snapshot` again once nothing is writing to the plan's files.")
}

async function selfCheck(archive: string, ciphertext: Uint8Array, key: CryptoKey, expected: string, captured: Captured[], planPath: string): Promise<void> {
  const reread = await readRegularFile(archive, { maxBytes: ciphertext.length, ownOnly: true })
  if (reread === null || (await sha256Hex(reread.bytes)) !== (await sha256Hex(ciphertext))) throw backupFailure(`The self-check failed: ${archive} on disk is not what was written, so nothing was kept.`, "Check the disk holding --to, then run the command again.")
  let opened: Snapshot
  try {
    opened = SnapshotSchema.parse(JSON.parse(fromUtf8(new Uint8Array(await ageDecrypt(reread.bytes, [key])))))
  } catch {
    throw backupFailure(`The self-check failed: ${archive} does not open to the snapshot that was written, so nothing was kept.`, "Run the command again; if it fails again, tell the human.")
  }
  if (snapshotPlaintext(opened) !== expected) throw backupFailure(`The self-check failed: ${archive} opens to something other than what was read, so nothing was kept.`, "Run the command again; if it fails again, tell the human.")
  for (const before of captured) {
    const again = await capture(before.file.path, planPath).catch(() => null)
    if (again === null || again.file.sha256 !== before.file.sha256 || again.mode !== before.mode || again.uid !== before.uid || again.gid !== before.gid) throw changed(before.file.path)
  }
}

export async function takeSnapshot(options: SnapshotOptions): Promise<SnapshotResult> {
  const recipients = [...options.recipients]
  await prepareBackupState(options.env)
  const read = await readPlan(options.planPath)
  const named = await namedPaths(read)
  const paths = [...new Set([...named, read.path])].sort()
  if (paths.length > BACKUP_LIMITS.maxFiles) throw backupFailure(`The plan names ${paths.length} files; a snapshot holds at most ${BACKUP_LIMITS.maxFiles}.`, "Split the plan, then snapshot and submit each part.")
  const dir = await outputDir(options.to, read)

  const captured: Captured[] = []
  let total = 0
  for (const path of paths) {
    const one = await capture(path, read.path)
    total += one.file.size
    if (total > BACKUP_LIMITS.maxSnapshotBytes) throw backupFailure(`The plan's files come to more than ${BACKUP_LIMITS.maxSnapshotBytes} bytes, more than one snapshot holds.`, "Split the plan, then snapshot and submit each part.")
    captured.push(one)
  }

  const snapshot: Snapshot = {
    format: SNAPSHOT_FORMAT,
    id: randomId("snp"),
    machine: read.plan.machine,
    createdAt: (options.now?.() ?? new Date()).toISOString(),
    planDigest: read.digest,
    files: captured.map((c) => c.file),
  }
  const expected = snapshotPlaintext(snapshot)
  const plaintext = utf8(expected)
  const ephemeral = await ephemeralAgeIdentity()
  const ciphertext = await ageEncrypt(plaintext, [...recipients, ephemeral.recipient])
  plaintext.fill(0)

  const archive = join(dir, `${snapshot.id}.age`)
  const sidecarPath = join(dir, `${snapshot.id}.json`)
  const sidecar: SnapshotSidecar = {
    format: SNAPSHOT_SIDECAR_FORMAT,
    id: snapshot.id,
    machine: snapshot.machine,
    createdAt: snapshot.createdAt,
    planDigest: snapshot.planDigest,
    recipients: recipients.map((recipient) => ({ recipient, fingerprint: ageRecipientFingerprint(recipient) })),
    files: captured.length,
    paths,
    ciphertext: { bytes: ciphertext.length, sha256: await sha256Hex(ciphertext) },
    selfCheck: "passed",
  }
  // Only what this run wrote is removed: a file already at the archive's
  // path refuses in writeNewFile and is left alone.
  let written = false
  try {
    await writeNewFile(archive, ciphertext)
    written = true
    await options.beforeSelfCheck?.()
    await selfCheck(archive, ciphertext, ephemeral.key, expected, captured, read.path)
    await writeNewFile(sidecarPath, utf8(`${JSON.stringify(sidecar, null, 2)}\n`))
  } catch (error) {
    if (written) await unlink(archive).catch(() => undefined)
    throw error
  }
  await recordSnapshot(options.env, { id: snapshot.id, archive, planPath: read.path, planDigest: read.digest, paths: named, createdAt: snapshot.createdAt, selfCheck: "passed", ciphertext: sidecar.ciphertext })
  return { id: snapshot.id, archive, sidecar: sidecarPath, machine: snapshot.machine, createdAt: snapshot.createdAt, files: captured.length, paths, recipients: sidecar.recipients, ciphertext: sidecar.ciphertext, selfCheck: "passed" }
}
