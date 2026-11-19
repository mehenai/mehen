// Backups, layer 1 (`mehen backup snapshot`): before `adopt submit`, a
// machine copies every file its adopt plan names into one archive encrypted
// with age to backup recipients whose private half lives off every enrolled
// machine. Stock `age -d` opens it, so Mehen is never the only copy:
//
//   age -d -i key.txt snp_x.age | jq -r '.files[0].content' | base64 -d
//
// The archive's plaintext is canonical JSON, `mehen-snapshot/v1`. The
// sidecar beside it (`<id>.json`) is cleartext and says what the archive is
// and how to check it, with no value, no length and no hash of any content.
//
// v1 accepts native X25519 recipients only (`age1` and 58 bech32
// characters): post-quantum `age1pq1...`, tag and plugin recipients
// (`age1<name>1...`) and SSH keys are refused.

import { z } from "zod"
import { type Bytes, base64UrlEncode, sha256B64 } from "./bytes.ts"
import { canonicalJson } from "./canonical-json.ts"
import { RESTRICTION_MS } from "./step-up-rules.ts"
import { CredentialHomeSchema, WorkspaceRefSchema } from "./workspace.ts"

export const SNAPSHOT_FORMAT = "mehen-snapshot/v1"
export const SNAPSHOT_SIDECAR_FORMAT = "mehen-snapshot-sidecar/v1"

export const SNAPSHOT_ID = /^snp_[A-Za-z0-9_-]{1,60}$/
export const SnapshotIdSchema = z.string().regex(SNAPSHOT_ID)

export const BACKUP_LIMITS = {
  // One captured file, as adopt reads them.
  maxFileBytes: 1_048_576,
  // The adopt plan itself, as adopt reads its own files: a machine's plan
  // names thousands of sources and outgrows one source's cap.
  maxPlanBytes: 16 * 1_048_576,
  maxFiles: 2_000,
  // Every captured file together, before base64.
  maxSnapshotBytes: 64 * 1_048_576,
  maxRecipients: 16,
} as const

// ---- age recipients -------------------------------------------------------

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
export const AGE_X25519_RECIPIENT = /^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$/

function bech32Polymod(values: number[]): number {
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  let chk = 1
  for (const value of values) {
    const top = chk >>> 25
    chk = ((chk & 0x1ffffff) << 5) ^ value
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= generators[i] as number
  }
  return chk
}

function hrpExpand(hrp: string): number[] {
  const codes = [...hrp].map((c) => c.charCodeAt(0))
  return [...codes.map((c) => c >>> 5), 0, ...codes.map((c) => c & 31)]
}

// The 32-byte X25519 public key in a well-formed recipient, or null when
// the checksum fails or the padding bits are not zero.
function x25519RecipientKey(recipient: string): Uint8Array | null {
  const data = [...recipient.slice(4)].map((c) => BECH32_CHARSET.indexOf(c))
  if (bech32Polymod([...hrpExpand("age"), ...data]) !== 1) return null
  const words = data.slice(0, -6)
  const out: number[] = []
  let buffer = 0
  let bits = 0
  for (const word of words) {
    buffer = (buffer << 5) | word
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((buffer >>> bits) & 0xff)
    }
  }
  if (bits >= 5 || (buffer & ((1 << bits) - 1)) !== 0 || out.length !== 32) return null
  return new Uint8Array(out)
}

export type AgeRecipientParse = { ok: true; recipient: string } | { ok: false; reason: string }

export function parseAgeRecipient(text: string): AgeRecipientParse {
  const value = text.trim()
  if (value.startsWith("ssh-") || value.startsWith("ecdsa-")) return { ok: false, reason: "SSH recipients are not supported; use an X25519 recipient (age1...) from `age-keygen` or `mehen backup keygen`" }
  if (value.startsWith("age1pq1")) return { ok: false, reason: "post-quantum recipients (age1pq1...) are not supported yet; use an X25519 recipient (age1...)" }
  if (value.startsWith("age1") && value.slice(4).includes("1")) return { ok: false, reason: "plugin and tag recipients (age1<name>1...) are not supported; use an X25519 recipient (age1...)" }
  if (!AGE_X25519_RECIPIENT.test(value)) return { ok: false, reason: "not an age X25519 recipient (age1 followed by 58 lower-case bech32 characters)" }
  if (x25519RecipientKey(value) === null) return { ok: false, reason: "its checksum does not match, so a character is wrong" }
  return { ok: true, recipient: value }
}

export const AgeRecipientSchema = z.string().refine((s) => {
  const parsed = parseAgeRecipient(s)
  return parsed.ok && parsed.recipient === s
}, "an age X25519 recipient (age1...)")

// What a person compares against the `# public key:` line age-keygen wrote:
// the recipient's first 12 and last 8 characters.
export function ageRecipientFingerprint(recipient: string): string {
  return `${recipient.slice(0, 12)}...${recipient.slice(-8)}`
}

// ---- the archive's plaintext ----------------------------------------------

export const Sha256HexSchema = z.string().regex(/^[0-9a-f]{64}$/)

export async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(data)))
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("")
}

// An absolute path a restore can put below a staging directory: no NUL, no
// empty, `.` or `..` component.
export const SnapshotPathSchema = z
  .string()
  .min(2)
  .max(4096)
  .refine((p) => p.startsWith("/") && !p.includes("\0") && p.slice(1).split("/").every((c) => c !== "" && c !== "." && c !== ".."), "an absolute path without empty, . or .. components")

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/

export const SnapshotFileSchema = z.strictObject({
  path: SnapshotPathSchema,
  // Permission bits, setuid, setgid and sticky included; never the type.
  mode: z.number().int().min(0).max(0o7777),
  uid: z.number().int().min(0),
  gid: z.number().int().min(0),
  user: z.string().min(1).max(256),
  group: z.string().min(1).max(256).nullable(),
  mtimeMs: z.number().nonnegative(),
  // Up to maxPlanBytes for the plan; SnapshotSchema holds every other file
  // to maxFileBytes.
  size: z.number().int().min(0).max(BACKUP_LIMITS.maxPlanBytes),
  sha256: Sha256HexSchema,
  // Standard base64 with padding, as `base64 -d` reads it.
  content: z.string().regex(BASE64),
})
export type SnapshotFile = z.infer<typeof SnapshotFileSchema>

export const SnapshotSchema = z.strictObject({
  format: z.literal(SNAPSHOT_FORMAT),
  id: SnapshotIdSchema,
  machine: z.string().min(1).max(256),
  createdAt: z.iso.datetime(),
  // SHA-256 of the plan file's bytes, hex.
  planDigest: Sha256HexSchema,
  files: z.array(SnapshotFileSchema).max(BACKUP_LIMITS.maxFiles),
}).superRefine((snapshot, ctx) => {
  snapshot.files.forEach((file, i) => {
    if (file.size > snapshotFileLimit(snapshot, file)) ctx.addIssue({ code: "custom", path: ["files", i, "size"], message: `only the plan may be larger than ${BACKUP_LIMITS.maxFileBytes} bytes` })
  })
})
export type Snapshot = z.infer<typeof SnapshotSchema>

// The plan is the file whose bytes the snapshot's planDigest names.
export function snapshotFileLimit(snapshot: Pick<Snapshot, "planDigest">, file: Pick<SnapshotFile, "sha256">): number {
  return file.sha256 === snapshot.planDigest ? BACKUP_LIMITS.maxPlanBytes : BACKUP_LIMITS.maxFileBytes
}

export function snapshotPlaintext(snapshot: Snapshot): string {
  return canonicalJson(snapshot)
}

// ---- the sidecar ----------------------------------------------------------

export const SnapshotRecipientSchema = z.strictObject({
  recipient: AgeRecipientSchema,
  fingerprint: z.string().min(1).max(64),
})

// Cleartext beside the archive. Paths and counts only: never a value, a
// length or a hash of anything inside the archive. `ciphertext` is the
// archive file itself, which `mehen backup check` compares without a key.
export const SnapshotSidecarSchema = z.strictObject({
  format: z.literal(SNAPSHOT_SIDECAR_FORMAT),
  id: SnapshotIdSchema,
  machine: z.string().min(1).max(256),
  createdAt: z.iso.datetime(),
  planDigest: Sha256HexSchema,
  recipients: z.array(SnapshotRecipientSchema).min(1).max(BACKUP_LIMITS.maxRecipients),
  files: z.number().int().min(0).max(BACKUP_LIMITS.maxFiles),
  paths: z.array(SnapshotPathSchema).max(BACKUP_LIMITS.maxFiles),
  ciphertext: z.strictObject({ bytes: z.number().int().positive(), sha256: Sha256HexSchema }),
  selfCheck: z.literal("passed"),
})
export type SnapshotSidecar = z.infer<typeof SnapshotSidecarSchema>

// ---- layer 2: exports from Mehen (`mehen backup export`) ------------------
//
// An owner registers an age recipient with a passkey. It becomes active a
// day later, and every owner and admin, and the owner, is told when it is
// added, becomes active and is removed. The vault itself opens each
// credential in the owner's scope, writes one `mehen-backup/v1` bundle and
// encrypts it with age to that recipient, so whoever asks, a machine
// included, only ever receives ciphertext:
//
//   age -d -i key.txt mehen-work-2026-11-01-bkx_x.age | jq '.items[].slug'

export const BACKUP_FORMAT = "mehen-backup/v1"
export const BACKUP_SIDECAR_FORMAT = "mehen-backup-sidecar/v1"

export const BACKUP_EXPORT_ID = /^bkx_[A-Za-z0-9_-]{1,60}$/
export const BACKUP_RECIPIENT_ID = /^bkr_[A-Za-z0-9_-]{1,60}$/
export const BackupExportIdSchema = z.string().regex(BACKUP_EXPORT_ID)
export const BackupRecipientIdSchema = z.string().regex(BACKUP_RECIPIENT_ID)

// A new recipient works only after the same cooling-off as a recovery.
export const BACKUP_RECIPIENT_DELAY_MS = RESTRICTION_MS

export const BACKUP_EXPORT_LIMITS = {
  maxItems: 2_000,
  // The bundle's plaintext.
  maxBytes: 16 * 1_048_576,
  // One export per recipient in this window.
  intervalMs: 10 * 60_000,
  // The settings page warns once the last export is older than this and
  // something in scope has changed since.
  staleAfterMs: 7 * 24 * 3_600_000,
  maxLabel: 64,
} as const

// What an export may hold, as the passkey that registers a recipient signs
// it (`scopeDigest`): a recipient registered under one scope never
// receives a wider one without being registered again.
export const BACKUP_EXPORT_SCOPE = {
  format: BACKUP_FORMAT,
  roles: ["owner"],
  homes: ["workspace", "project", "own-private"],
  excluded: ["other-members-private", "four-eyes", "oauth-connection-values"],
} as const

export function backupScopeDigest(): Promise<string> {
  return sha256B64(canonicalJson(BACKUP_EXPORT_SCOPE))
}

export const BackupRecipientLabelSchema = z.string().trim().min(1).max(BACKUP_EXPORT_LIMITS.maxLabel).refine((s) => !/[\u0000-\u001f\u007f]/.test(s), "no control characters")
export const BackupRecipientAddSchema = z.strictObject({ recipient: AgeRecipientSchema, label: BackupRecipientLabelSchema })
export type BackupRecipientAdd = z.infer<typeof BackupRecipientAddSchema>

// The exact `backup.recipient_add` step-up the browser signs and the vault
// rebuilds: the recipient and label as stored, and the scope digest.
export async function backupRecipientAddAction(input: BackupRecipientAdd): Promise<{ type: "backup.recipient_add"; recipient: string; label: string; scopeDigest: string }> {
  return { type: "backup.recipient_add", recipient: input.recipient, label: input.label, scopeDigest: await backupScopeDigest() }
}

const BackupIso = z.iso.datetime()

export const BackupExportSummarySchema = z.strictObject({ id: BackupExportIdSchema, at: BackupIso, items: z.number().int().min(0) })
export type BackupExportSummary = z.infer<typeof BackupExportSummarySchema>

// One registered recipient as a non-guest sees it. `lastExport` and
// `changedSince` (in-scope credentials and variables changed after it, or
// everything in scope when there is no export yet) are filled only for
// the person who registered it, or one of their machines.
export const BackupRecipientViewSchema = z.strictObject({
  id: BackupRecipientIdSchema,
  recipient: AgeRecipientSchema,
  fingerprint: z.string(),
  label: z.string(),
  status: z.enum(["pending", "active"]),
  registrant: z.strictObject({ member: z.string(), name: z.string() }),
  mine: z.boolean(),
  registeredAt: BackupIso,
  activeAt: BackupIso,
  lastExport: BackupExportSummarySchema.nullable(),
  changedSince: z.number().int().min(0).nullable(),
  rights: z.strictObject({ export: z.boolean(), remove: z.boolean() }),
})
export type BackupRecipientView = z.infer<typeof BackupRecipientViewSchema>

export const BackupStatusSchema = z.strictObject({
  recipients: z.array(BackupRecipientViewSchema),
  rights: z.strictObject({ add: z.boolean() }),
  now: BackupIso,
})
export type BackupStatus = z.infer<typeof BackupStatusSchema>

export function backupIsStale(recipient: Pick<BackupRecipientView, "status" | "lastExport" | "changedSince">, now: number): boolean {
  if (recipient.status !== "active" || recipient.changedSince === null || recipient.changedSince === 0) return false
  return recipient.lastExport === null || now - Date.parse(recipient.lastExport.at) > BACKUP_EXPORT_LIMITS.staleAfterMs
}

// ---- the bundle's plaintext -----------------------------------------------

export const BackupItemSchema = z.strictObject({
  id: z.string(),
  slug: z.string(),
  kind: z.string(),
  provider: z.string().nullable(),
  account: z.string().nullable(),
  home: CredentialHomeSchema,
  tags: z.array(z.string()),
  binding: z.unknown(),
  policy: z.unknown(),
  ceiling: z.string(),
  injection: z.unknown(),
  description: z.string().nullable(),
  publicFields: z.record(z.string(), z.string()),
  secretFields: z.record(z.string(), z.string()),
  version: z.number().int(),
  rotatedAt: BackupIso.nullable(),
})
export type BackupItem = z.infer<typeof BackupItemSchema>

// What a reference names in place of a credential the registrant may not
// see, such as another member's private one: never its slug or id. No slug
// can be written this way.
export const BACKUP_HIDDEN_ITEM = "(outside your reach)"

export const BackupVariableSchema = z.union([
  z.strictObject({ item: z.string(), field: z.string() }),
  z.strictObject({ item: z.string(), field: z.string(), notExported: z.literal(true) }),
  z.strictObject({ plain: z.string() }),
])
export type BackupVariable = z.infer<typeof BackupVariableSchema>

export const BackupProjectSchema = z.strictObject({
  id: z.string(),
  slug: z.string(),
  remotes: z.array(z.string()),
  defaultEnv: z.string().nullable(),
  environments: z.array(z.strictObject({ name: z.string(), protected: z.boolean(), fences: z.array(z.string()), fourEyes: z.boolean(), vars: z.record(z.string(), BackupVariableSchema) })),
})
export type BackupProject = z.infer<typeof BackupProjectSchema>

export const BackupOverrideSchema = z.strictObject({
  project: z.string(),
  environment: z.string(),
  variable: z.string(),
  source: z.discriminatedUnion("kind", [z.strictObject({ kind: z.literal("plain"), value: z.string() }), z.strictObject({ kind: z.literal("item"), item: z.string(), field: z.string() })]),
})

export const BACKUP_EXCLUSION_REASONS = {
  fourEyes: "four-eyes: a protected environment needs a second person to use it, so it is never exported",
  oauthConnection: "oauth-connection: tokens rotate, so its values are not exported; reconnect it after a restore",
} as const

export const BackupBundleSchema = z.strictObject({
  format: z.literal(BACKUP_FORMAT),
  id: BackupExportIdSchema,
  // The origin a restored mehen.toml names.
  vault: z.string(),
  workspace: WorkspaceRefSchema,
  exportedAt: BackupIso,
  registrant: z.strictObject({ member: z.string(), name: z.string() }),
  recipient: z.strictObject({ id: BackupRecipientIdSchema, fingerprint: z.string() }),
  // The newest audit entry before this export: a head kept outside the vault.
  auditHead: z.strictObject({ seq: z.number().int(), hash: z.string() }).nullable(),
  items: z.array(BackupItemSchema).max(BACKUP_EXPORT_LIMITS.maxItems),
  projects: z.array(BackupProjectSchema),
  overrides: z.array(BackupOverrideSchema),
  excluded: z.array(z.strictObject({ slug: z.string(), reason: z.string() })),
})
export type BackupBundle = z.infer<typeof BackupBundleSchema>

export function backupPlaintext(bundle: BackupBundle): string {
  return canonicalJson(bundle)
}

// What the vault says about an export, beside the ciphertext.
export const BackupExportMetaSchema = z.strictObject({
  id: BackupExportIdSchema,
  workspace: WorkspaceRefSchema,
  recipient: z.strictObject({ id: BackupRecipientIdSchema, fingerprint: z.string() }),
  exportedAt: BackupIso,
  items: z.number().int().min(0),
  projects: z.number().int().min(0),
  excluded: z.number().int().min(0),
  ciphertext: z.strictObject({ bytes: z.number().int().positive(), sha256: Sha256HexSchema }),
})
export type BackupExportMeta = z.infer<typeof BackupExportMetaSchema>

// POST /v1/backup/exports answers JSON: the meta and the age file in
// standard base64. The browser route answers the file itself, with the
// SHA-256 in BACKUP_SHA256_HEADER.
export const BackupExportResponseSchema = z.strictObject({ export: BackupExportMetaSchema, ciphertext: z.string().regex(BASE64) })
export type BackupExportResponse = z.infer<typeof BackupExportResponseSchema>
export const BACKUP_SHA256_HEADER = "Mehen-Backup-Sha256"

export function backupCiphertextBase64(ciphertext: Bytes): string {
  const url = base64UrlEncode(ciphertext)
  return url.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (url.length % 4)) % 4)
}

// `mehen-<workspace>-<yyyy-mm-dd>-<bkx>.age`, from the browser or the CLI.
export function backupExportFileName(meta: Pick<BackupExportMeta, "workspace" | "exportedAt" | "id">): string {
  return `mehen-${meta.workspace.slug}-${meta.exportedAt.slice(0, 10)}-${meta.id}.age`
}

// Cleartext beside an export file: what it is and how to check it, never a
// slug, a value or a length of anything inside.
export const BackupSidecarSchema = BackupExportMetaSchema.extend({ format: z.literal(BACKUP_SIDECAR_FORMAT) })
export type BackupSidecar = z.infer<typeof BackupSidecarSchema>
