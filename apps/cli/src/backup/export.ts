// mehen backup export --to <dir> [--recipient <bkr_id>]... and mehen backup
// status: the vault encrypts an export to a backup key an owner registered
// with a passkey, and this machine only ever receives the ciphertext. Each
// file is checked against the SHA-256 and length the vault reported and
// must be an age file with exactly one X25519 stanza before it is written,
// as <dir>/mehen-<workspace>-<date>-<bkx>.age (0600, never over a file)
// beside a sidecar that holds no slug and no value.

import { lstat, mkdir, unlink } from "node:fs/promises"
import { join } from "node:path"
import {
  BACKUP_SIDECAR_FORMAT,
  type BackupExportMeta,
  BackupExportResponseSchema,
  type BackupRecipientView,
  BackupRecipientViewSchema,
  type BackupSidecar,
  type BackupStatus,
  BackupStatusSchema,
  backupExportFileName,
  sha256Hex,
} from "@mehen/protocol/backup"
import { utf8 } from "@mehen/protocol/bytes"
import { z } from "zod"
import { CliError } from "../errors.ts"
import type { VaultApi } from "../vault-api.ts"
import { parseAgeHeader, sidecarPathFor } from "./check.ts"
import { backupFailure, fromBase64, gitWorkTreeAbove, realTarget, writeNewFile } from "./files.ts"

// The caller's own active backup keys, for a snapshot given no
// --recipient. Another person's key is never used: a snapshot holds this
// machine's own files, and only its owner should open them. A key still in
// its day of cooling-off is left out: a snapshot to it would skip the wait
// every other owner and admin was promised.
export async function ownRecipients(api: VaultApi): Promise<string[]> {
  const parsed = z.strictObject({ recipients: z.array(BackupRecipientViewSchema) }).safeParse(await api.request<unknown>("GET", "/v1/backup/recipients"))
  if (!parsed.success) throw backupFailure("The vault answered /v1/backup/recipients with something mehen does not recognise.", "Update mehen with `mehen update`, or name the key with --recipient age1....")
  return parsed.data.recipients.filter((r) => r.mine && r.status === "active").map((r) => r.recipient)
}

export async function readBackupStatus(api: VaultApi): Promise<BackupStatus> {
  const parsed = BackupStatusSchema.safeParse(await api.request<unknown>("GET", "/v1/backup/status"))
  if (!parsed.success) throw backupFailure("The vault answered /v1/backup/status with something mehen does not recognise.", "Update mehen with `mehen update`, then run the command again.")
  return parsed.data
}

// The recipients to export to: those named, or else every one this machine
// may export to now. None is a refusal that says why: a key still in its
// day of cooling-off, or no key at all.
export function exportTargets(status: BackupStatus, named: readonly string[]): string[] {
  if (named.length > 0) return [...new Set(named)]
  const ready = status.recipients.filter((r) => r.rights.export).map((r) => r.id)
  if (ready.length > 0) return ready
  const waiting = status.recipients.find((r) => r.mine && r.status === "pending")
  if (waiting) return refuse(`Your backup key ${waiting.label} (${waiting.fingerprint}) can receive exports from ${waiting.activeAt}, a day after it was added.`, "Wait until then; every owner and admin was told it was added.")
  return refuse("There is no backup key this machine may export to: only an owner exports, to a key they added themselves, a day after adding it.", "Add one on the workspace's Settings page with your passkey; `mehen backup keygen` makes the key on a machine no agent uses.")
}

function refuse(message: string, say: string): never {
  throw new CliError("conflict", message, { say })
}

// The directory the exports go in: never inside a git work tree, where it
// could be committed or scanned; made 0700 when it does not exist.
export async function exportDir(to: string): Promise<string> {
  const target = realTarget(to)
  const tree = gitWorkTreeAbove(target)
  if (tree !== null) throw backupFailure(`Refusing to write the export to ${target}: it is inside the git work tree ${tree}.`, "Choose a directory outside every git work tree, such as ~/Backups/mehen; a synced folder is fine.")
  await mkdir(target, { recursive: true, mode: 0o700 })
  if (!(await lstat(target)).isDirectory()) throw backupFailure(`Refusing to write the export to ${target}: it is not a directory.`, "Name a directory with --to.")
  return target
}

export type ExportWritten = BackupExportMeta & { archive: string; sidecar: string }

// Asks for one export, checks it and writes the pair. A failed write
// leaves neither file behind.
export async function exportTo(api: VaultApi, dir: string, recipient: string): Promise<ExportWritten> {
  const parsed = BackupExportResponseSchema.safeParse(await api.request<unknown>("POST", "/v1/backup/exports", { recipient }))
  if (!parsed.success) throw backupFailure("The vault answered /v1/backup/exports with something mehen does not recognise.", "Update mehen with `mehen update`, then run the command again.")
  const meta = parsed.data.export
  const ciphertext = fromBase64(parsed.data.ciphertext)
  const damaged = (why: string) => backupFailure(`The export ${meta.id} arrived damaged: ${why}. Nothing was written.`, "Run the command again in ten minutes.")
  if (ciphertext.length !== meta.ciphertext.bytes) throw damaged(`it is ${ciphertext.length} bytes, not ${meta.ciphertext.bytes}`)
  if ((await sha256Hex(ciphertext)) !== meta.ciphertext.sha256) throw damaged("its SHA-256 differs from the one the vault reported")
  const header = parseAgeHeader(ciphertext)
  if (typeof header === "string") throw damaged(header)
  if (header.stanzas.length !== 1 || header.stanzas[0]?.args[0] !== "X25519") throw damaged("it is not encrypted to exactly one X25519 key")
  const archive = join(dir, backupExportFileName(meta))
  const sidecar = sidecarPathFor(archive)
  const record: BackupSidecar = { format: BACKUP_SIDECAR_FORMAT, ...meta }
  await writeNewFile(archive, ciphertext)
  try {
    await writeNewFile(sidecar, utf8(`${JSON.stringify(record, null, 2)}\n`))
  } catch (error) {
    await unlink(archive).catch(() => undefined)
    throw error
  }
  return { ...meta, archive, sidecar }
}

// `mehen backup status` lines: each key, whose it is and when it works,
// and for your own the last export and what changed since.
export function statusLines(status: BackupStatus, ago: (iso: string) => string): string[] {
  if (status.recipients.length === 0) return ["no backup key: an owner adds one on the workspace's Settings page with a passkey"]
  const lines: string[] = []
  for (const r of status.recipients) {
    const state = r.status === "active" ? "active" : `waiting until ${r.activeAt}`
    lines.push(`${r.id}  ${r.label}  ${r.fingerprint}  ${state}  added by ${r.mine ? "you" : r.registrant.name}`)
    if (r.mine) lines.push(`  ${exportLine(r, ago)}`)
  }
  return lines
}

function exportLine(r: BackupRecipientView, ago: (iso: string) => string): string {
  const changed = r.changedSince ?? 0
  const things = `${changed} item${changed === 1 ? "" : "s"}`
  if (r.lastExport === null) return r.status === "active" ? `stale: no export yet, ${things} to export; run mehen backup export --to <dir>` : "no export yet"
  const last = `${r.lastExport.id} (${ago(r.lastExport.at)})`
  if (changed > 0) return `stale: ${things} changed since ${last}; run mehen backup export --to <dir>`
  return `up to date: ${last}, ${r.lastExport.items} credential${r.lastExport.items === 1 ? "" : "s"}`
}
