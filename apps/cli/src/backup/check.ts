// mehen backup check <snp_id>.age: whether an archive is still the file the
// snapshot wrote, with no key. The archive's byte length and SHA-256 must
// match its sidecar, and its age header must be whole: the version line,
// one X25519 stanza per sidecar recipient plus the self-check's, and a MAC.
// That catches truncation, bit rot and a swapped file. It cannot prove
// which key a stanza is for (age hides that by design); only a restore
// with the identity can.
//
// An export from the vault (mehen-<workspace>-<date>-<bkx>.age) is checked
// the same way against its own sidecar: one X25519 stanza, the backup key
// the vault encrypted it to.

import { basename, dirname, join } from "node:path"
import { BACKUP_EXPORT_LIMITS, BACKUP_LIMITS, type BackupSidecar, BackupSidecarSchema, SnapshotSidecarSchema, type SnapshotSidecar, backupExportFileName, sha256Hex } from "@mehen/protocol/backup"
import { fromUtf8 } from "@mehen/protocol/bytes"
import { backupFailure, readRegularFile } from "./files.ts"

const AGE_VERSION_LINE = "age-encryption.org/v1"
// A header is a few hundred bytes per stanza; this is generous.
const MAX_HEADER_BYTES = 65_536
// The payload's 16-byte nonce and at least one 17-byte sealed chunk.
const MIN_PAYLOAD_BYTES = 33
const BASE64_NOPAD = /^[A-Za-z0-9+/]*$/
// Base64 of the largest snapshot, with room for the JSON around it.
export const MAX_ARCHIVE_BYTES = 2 * BACKUP_LIMITS.maxSnapshotBytes
// The largest export, with room for its age framing.
export const MAX_EXPORT_BYTES = 2 * BACKUP_EXPORT_LIMITS.maxBytes

export type AgeHeader = { stanzas: { args: string[]; body: Uint8Array }[]; mac: Uint8Array; payloadBytes: number }

function decodeNoPad(text: string): Uint8Array | null {
  if (!BASE64_NOPAD.test(text) || text.length % 4 === 1) return null
  const bytes = new Uint8Array(Buffer.from(text, "base64"))
  return Buffer.from(bytes).toString("base64").replace(/=+$/, "") === text ? bytes : null
}

// The header of an age v1 file, or the reason it is not one.
export function parseAgeHeader(bytes: Uint8Array): AgeHeader | string {
  let offset = 0
  const line = (): string | null => {
    const end = bytes.indexOf(0x0a, offset)
    if (end === -1 || end > MAX_HEADER_BYTES) return null
    const text = Buffer.from(bytes.subarray(offset, end)).toString("latin1")
    offset = end + 1
    return text
  }
  if (line() !== AGE_VERSION_LINE) return "it does not start with the age v1 version line"
  const stanzas: AgeHeader["stanzas"] = []
  for (;;) {
    const next = line()
    if (next === null) return "its header has no end"
    if (next.startsWith("--- ")) {
      const mac = decodeNoPad(next.slice(4))
      if (mac === null || mac.length !== 32) return "its header MAC is malformed"
      const payloadBytes = bytes.length - offset
      if (payloadBytes < MIN_PAYLOAD_BYTES) return "its payload is missing or truncated"
      return { stanzas, mac, payloadBytes }
    }
    if (!next.startsWith("-> ")) return "its header has a line that is neither a stanza nor the MAC"
    const args = next.slice(3).split(" ")
    if (args.some((a) => a === "")) return "a stanza in its header is malformed"
    const body: Uint8Array[] = []
    for (;;) {
      const text = line()
      const chunk = text === null ? null : decodeNoPad(text)
      if (chunk === null || chunk.length > 48) return "a stanza body in its header is malformed"
      body.push(chunk)
      if (chunk.length < 48) break
    }
    stanzas.push({ args, body: new Uint8Array(Buffer.concat(body)) })
  }
}

function x25519Stanza(stanza: AgeHeader["stanzas"][number]): boolean {
  const share = stanza.args[1] === undefined ? null : decodeNoPad(stanza.args[1])
  return stanza.args.length === 2 && stanza.args[0] === "X25519" && share?.length === 32 && stanza.body.length === 32
}

export type CheckResult = {
  id: string
  archive: string
  sidecar: string
  machine: string
  createdAt: string
  files: number
  recipients: SnapshotSidecar["recipients"]
  ciphertext: SnapshotSidecar["ciphertext"]
  stanzas: number
}

export function sidecarPathFor(archive: string): string {
  return join(dirname(archive), `${basename(archive, ".age")}.json`)
}

async function readSidecar(archivePath: string, sidecarPath: string, what: string): Promise<unknown> {
  const sidecarRead = await readRegularFile(sidecarPath, { maxBytes: 4 * 1_048_576, ownOnly: false })
  if (sidecarRead === null) throw backupFailure(`There is no sidecar ${sidecarPath} beside ${archivePath}.`, "Copy the archive and its sidecar together; the sidecar says what the archive should be.")
  try {
    return JSON.parse(fromUtf8(new Uint8Array(sidecarRead.bytes)))
  } catch {
    throw backupFailure(`The sidecar ${sidecarPath} is not JSON.`, `Copy the sidecar again from where the ${what} was written.`)
  }
}

export async function checkSnapshot(archivePath: string): Promise<CheckResult> {
  if (!archivePath.endsWith(".age")) throw backupFailure(`${archivePath} is not a snapshot archive (<snp_id>.age).`, "Name the .age file `mehen backup snapshot` wrote; its sidecar <snp_id>.json must be beside it.")
  const sidecarPath = sidecarPathFor(archivePath)
  const sidecarJson = await readSidecar(archivePath, sidecarPath, "snapshot")
  const parsed = SnapshotSidecarSchema.safeParse(sidecarJson)
  if (!parsed.success) throw backupFailure(`The sidecar ${sidecarPath} is not a snapshot sidecar mehen recognises.`, "Copy the sidecar again from where the snapshot was written.")
  const sidecar = parsed.data
  if (`${sidecar.id}.age` !== basename(archivePath)) throw backupFailure(`The sidecar ${sidecarPath} is for ${sidecar.id}, not ${basename(archivePath)}.`, "Keep each archive with its own sidecar.")
  const damaged = (why: string) => backupFailure(`${archivePath} is damaged or not the archive its sidecar describes: ${why}.`, "Use another copy of this snapshot, or take a new one with `mehen backup snapshot` while the sources are still in place.")
  const archive = await readRegularFile(archivePath, { maxBytes: MAX_ARCHIVE_BYTES, ownOnly: false })
  if (archive === null) throw backupFailure(`There is no archive at ${archivePath}.`, "Name the .age file `mehen backup snapshot` wrote.")
  if (archive.bytes.length !== sidecar.ciphertext.bytes) throw damaged(`it is ${archive.bytes.length} bytes, not ${sidecar.ciphertext.bytes}`)
  if ((await sha256Hex(archive.bytes)) !== sidecar.ciphertext.sha256) throw damaged("its SHA-256 differs")
  const header = parseAgeHeader(archive.bytes)
  if (typeof header === "string") throw damaged(header)
  if (header.stanzas.length !== sidecar.recipients.length + 1) throw damaged(`its header has ${header.stanzas.length} stanzas, not ${sidecar.recipients.length + 1}`)
  if (!header.stanzas.every(x25519Stanza)) throw damaged("a stanza in its header is not X25519")
  return {
    id: sidecar.id,
    archive: archivePath,
    sidecar: sidecarPath,
    machine: sidecar.machine,
    createdAt: sidecar.createdAt,
    files: sidecar.files,
    recipients: sidecar.recipients,
    ciphertext: sidecar.ciphertext,
    stanzas: header.stanzas.length,
  }
}

// Whether a name is a snapshot's (<snp_id>.age) rather than an export's.
export function isSnapshotName(archivePath: string): boolean {
  return basename(archivePath).startsWith("snp_")
}

export type ExportCheckResult = { id: string; archive: string; sidecar: string; workspace: BackupSidecar["workspace"]; exportedAt: string; recipient: BackupSidecar["recipient"]; items: number; projects: number; excluded: number; ciphertext: BackupSidecar["ciphertext"] }

export async function checkExport(archivePath: string): Promise<ExportCheckResult> {
  if (!archivePath.endsWith(".age")) throw backupFailure(`${archivePath} is not an export (mehen-<workspace>-<date>-<bkx_id>.age).`, "Name the .age file `mehen backup export` or the Settings page wrote; its sidecar .json must be beside it.")
  const sidecarPath = sidecarPathFor(archivePath)
  const parsed = BackupSidecarSchema.safeParse(await readSidecar(archivePath, sidecarPath, "export"))
  if (!parsed.success) throw backupFailure(`The sidecar ${sidecarPath} is not an export sidecar mehen recognises.`, "Copy the sidecar again from where the export was written.")
  const sidecar = parsed.data
  if (backupExportFileName(sidecar) !== basename(archivePath)) throw backupFailure(`The sidecar ${sidecarPath} is for ${backupExportFileName(sidecar)}, not ${basename(archivePath)}.`, "Keep each export with its own sidecar.")
  const damaged = (why: string) => backupFailure(`${archivePath} is damaged or not the export its sidecar describes: ${why}.`, "Use another copy of this export, or make a new one with `mehen backup export`.")
  const archive = await readRegularFile(archivePath, { maxBytes: MAX_EXPORT_BYTES, ownOnly: false })
  if (archive === null) throw backupFailure(`There is no export at ${archivePath}.`, "Name the .age file `mehen backup export` wrote.")
  if (archive.bytes.length !== sidecar.ciphertext.bytes) throw damaged(`it is ${archive.bytes.length} bytes, not ${sidecar.ciphertext.bytes}`)
  if ((await sha256Hex(archive.bytes)) !== sidecar.ciphertext.sha256) throw damaged("its SHA-256 differs")
  const header = parseAgeHeader(archive.bytes)
  if (typeof header === "string") throw damaged(header)
  if (header.stanzas.length !== 1) throw damaged(`its header has ${header.stanzas.length} stanzas, not 1`)
  if (!header.stanzas.every(x25519Stanza)) throw damaged("its stanza is not X25519")
  const { format: _format, ...meta } = sidecar
  return { ...meta, archive: archivePath, sidecar: sidecarPath }
}
