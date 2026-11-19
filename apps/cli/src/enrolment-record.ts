// The enrolment record: pending/<originKey>/<slug>/
// enrolment.json, the only resumption record of an enrolment attempt. The
// reader validates every field, refuses a link, a foreign or loose file,
// and never prunes by expiry: a record leaves the disk only when the
// lifecycle (or `mehen workspace forget`) removes it. A tampered url drops
// the record.
//
// Every write that follows an await goes through mutateAttempt: under the pending lock it re-reads the record and changes it only
// while it is still the attempt the caller holds, so a late answer about an
// older attempt never touches a newer one. The ledger never reads or writes
// the record.

import { lstat, readFile, rm } from "node:fs/promises"
import { join } from "node:path"
import { fingerprintOf } from "@mehen/protocol/fingerprint"
import { type DeviceJwk, jwkThumbprint } from "@mehen/protocol/proof"
import { type EnrolRequestedScope, EnrolRequestedScopeSchema, WorkspaceSlugSchema } from "@mehen/protocol/workspace"
import { type Ask, askUrl, enrolAsk, isAskId, isWaitId, withContext } from "./ask.ts"
import { BACKENDS, type Backend, canonicalOrigin, writePrivateFile } from "./config.ts"
import { CliError } from "./errors.ts"
import { ENROLMENT_RECORD_FILE } from "./home.ts"
import type { LedgerEnrolment, LedgerEntry } from "./ledger.ts"
import { slotLockPath, withSlotLocks } from "./slot-lock.ts"

export type WorkspaceIntent = { workspace: string; team: string | null }

export type EnrolmentRecord = {
  v: 1
  state: "issuing" | "pending"
  id: string | null
  code: string | null
  url: string | null
  origin: string
  intent: WorkspaceIntent
  name: string
  backend: Backend
  jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }
  session: string | null
  startedAt: string
  expiresAt: string | null
  hardExpiresAt: string | null
  renewals: number
  legacy: boolean
  claimed: boolean
  // The narrower scope this attempt asked for (mehen enrol --tag, --project,
  // --mode, --no-private, --workloads-only); absent when it asked for none.
  // An attempt is resumed only with the same requested scope.
  scope?: EnrolRequestedScope
}

export function enrolmentRecordPath(dir: string): string {
  return join(dir, ENROLMENT_RECORD_FILE)
}

const TEAM = /^[a-z][a-z0-9-]{0,31}$/
const SESSION = /^[A-Za-z0-9_.:-]{1,120}$/

function str(value: unknown): value is string {
  return typeof value === "string"
}

function nullableStr(value: unknown): value is string | null {
  return value === null || typeof value === "string"
}

function isTime(value: unknown): value is string {
  return str(value) && Number.isFinite(Date.parse(value))
}

function nullableTime(value: unknown): value is string | null {
  return value === null || isTime(value)
}

function pickJwk(value: unknown): EnrolmentRecord["jwk"] | null {
  if (typeof value !== "object" || value === null) return null
  const k = value as Record<string, unknown>
  if (k.kty !== "EC" || k.crv !== "P-256" || !str(k.x) || !str(k.y) || "d" in k) return null
  return { kty: "EC", crv: "P-256", x: k.x, y: k.y }
}

function pickIntent(value: unknown): WorkspaceIntent | null {
  if (typeof value !== "object" || value === null) return null
  const i = value as Record<string, unknown>
  if (!str(i.workspace) || !WorkspaceSlugSchema.safeParse(i.workspace).success) return null
  if (!(i.team === null || (str(i.team) && TEAM.test(i.team)))) return null
  return { workspace: i.workspace, team: i.team }
}

function canonical(origin: unknown): string | null {
  if (!str(origin)) return null
  try {
    return canonicalOrigin(origin) === origin ? origin : null
  } catch {
    return null
  }
}

// The record, copied field by field, or null when any field is not what a
// record may hold. The link must be this origin's own enrolment page under
// the intended workspace for the record's code; anything else drops it.
export function parseEnrolmentRecord(value: unknown): EnrolmentRecord | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null
  const r = value as Record<string, unknown>
  const origin = canonical(r.origin)
  const intent = pickIntent(r.intent)
  const jwk = pickJwk(r.jwk)
  if (r.v !== 1 || (r.state !== "issuing" && r.state !== "pending") || origin === null || intent === null || jwk === null) return null
  if (!str(r.name) || r.name.length < 1 || r.name.length > 64 || !(BACKENDS as readonly string[]).includes(r.backend as string)) return null
  if (!(r.session === null || (str(r.session) && SESSION.test(r.session))) || !isTime(r.startedAt) || !nullableTime(r.expiresAt) || !nullableTime(r.hardExpiresAt)) return null
  if (typeof r.renewals !== "number" || !Number.isSafeInteger(r.renewals) || r.renewals < 0 || typeof r.legacy !== "boolean" || typeof r.claimed !== "boolean") return null
  if (!nullableStr(r.id) || !nullableStr(r.code) || !nullableStr(r.url)) return null
  const scope = r.scope === undefined ? null : EnrolRequestedScopeSchema.safeParse(r.scope)
  if (scope !== null && !scope.success) return null
  if (r.state === "pending") {
    if (!isWaitId("enrol", r.id) || !isAskId("enrol", r.code) || r.url === null || r.expiresAt === null) return null
    const link = askUrl(r.url, { vaultUrl: origin, workspaceSlug: intent.workspace })
    if (!link || link.route === null || link.route.prefix !== "e" || link.route.id !== r.code) return null
  } else if (r.id !== null && !isWaitId("enrol", r.id)) return null
  return {
    v: 1,
    state: r.state,
    id: r.id,
    code: r.code,
    url: r.url,
    origin,
    intent,
    name: r.name,
    backend: r.backend as Backend,
    jwk,
    session: r.session,
    startedAt: r.startedAt,
    expiresAt: r.expiresAt,
    hardExpiresAt: r.hardExpiresAt,
    renewals: r.renewals,
    legacy: r.legacy,
    claimed: r.claimed,
    ...(scope !== null ? { scope: scope.data } : {}),
  }
}

export type RecordRead = { record: EnrolmentRecord } | { refused: string } | null

// The record in a pending slot: null when there is none, `refused` with a
// reason when the file is a link, not a plain file, not this user's, open
// to others or not a valid record. Never pruned by expiry.
export async function readEnrolmentRecord(dir: string): Promise<RecordRead> {
  const path = enrolmentRecordPath(dir)
  let text: string
  try {
    const info = await lstat(path)
    if (info.isSymbolicLink()) return { refused: `${path} is a symbolic link` }
    if (!info.isFile()) return { refused: `${path} is not a regular file` }
    if (info.uid !== process.getuid?.()) return { refused: `${path} is owned by another user (uid ${info.uid})` }
    if ((info.mode & 0o077) !== 0) return { refused: `${path} is readable or writable by other users` }
    text = await readFile(path, "utf8")
  } catch (error) {
    if ((error as { code?: string }).code === "ENOENT") return null
    return { refused: `${path} cannot be read: ${error instanceof Error ? error.message : String(error)}` }
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return { refused: `${path} is not JSON` }
  }
  const record = parseEnrolmentRecord(parsed)
  return record ? { record } : { refused: `${path} is not a valid enrolment record` }
}

export async function writeEnrolmentRecord(dir: string, record: EnrolmentRecord): Promise<void> {
  const clean = parseEnrolmentRecord(record)
  if (!clean) throw new Error("An enrolment record must be complete and its link on its own origin.")
  await writePrivateFile(enrolmentRecordPath(dir), `${JSON.stringify(clean, null, 2)}\n`)
}

export async function removeEnrolmentRecord(dir: string): Promise<void> {
  await rm(enrolmentRecordPath(dir), { force: true })
}

export type MutateResult = "applied" | "superseded" | "gone"

// The compare-and-mutate step for a caller that already holds the pending
// slot's lock (the finish step takes the whole ordered set itself).
export async function mutateAttemptLocked(slot: string, expected: { id: string; jwk: Pick<DeviceJwk, "x" | "y"> }, fn: (record: EnrolmentRecord) => EnrolmentRecord | null): Promise<MutateResult> {
  const read = await readEnrolmentRecord(slot)
  if (read === null) return "gone"
  if ("refused" in read) return "superseded"
  const record = read.record
  if (record.id !== expected.id || record.jwk.x !== expected.jwk.x || record.jwk.y !== expected.jwk.y) return "superseded"
  const next = fn(record)
  if (next === null) await removeEnrolmentRecord(slot)
  else await writeEnrolmentRecord(slot, next)
  return "applied"
}

// Under the pending lock, re-read enrolment.json and apply
// `fn` (null removes the record) only while the record's id and key are
// the ones the caller holds; `superseded` when another attempt replaced it,
// `gone` when there is no record any more. Nothing is written otherwise.
export async function mutateAttempt(slot: string, expected: { id: string; jwk: Pick<DeviceJwk, "x" | "y"> }, fn: (record: EnrolmentRecord) => EnrolmentRecord | null): Promise<MutateResult> {
  const lock = slotLockPath(slot)
  if (lock === null) throw new CliError("internal", `${slot} is not a pending slot under a config root.`)
  return withSlotLocks([lock], () => mutateAttemptLocked(slot, expected, fn))
}

// A legacy ledger enrol entry as a record, field by field. It has no
// server lease: never renewed, never claimed.
export function recordFromLegacyEntry(entry: LedgerEntry & { enrol: LedgerEnrolment }): EnrolmentRecord {
  return {
    v: 1,
    state: "pending",
    id: entry.ask.id,
    code: entry.enrol.code,
    url: entry.ask.url,
    origin: entry.origin,
    intent: { workspace: entry.enrol.workspace, team: entry.enrol.team },
    name: entry.enrol.name,
    backend: entry.enrol.backend,
    jwk: { kty: "EC", crv: "P-256", x: entry.enrol.jwk.x, y: entry.enrol.jwk.y },
    session: entry.ask.requestedBy.session,
    startedAt: entry.createdAt,
    expiresAt: entry.ask.expiresAt,
    hardExpiresAt: null,
    renewals: 0,
    legacy: true,
    claimed: false,
  }
}

export async function recordFingerprint(record: Pick<EnrolmentRecord, "jwk">): Promise<string> {
  return fingerprintOf(await jwkThumbprint(record.jwk as DeviceJwk))
}

// The enrol ask a pending record stands for, rebuilt from the record alone;
// null when its link is not this origin's enrolment page for its workspace.
export async function recordAsk(record: EnrolmentRecord, device: string): Promise<Ask | null> {
  if (!isPendingRecord(record)) return null
  const link = askUrl(record.url, { vaultUrl: record.origin, workspaceSlug: record.intent.workspace })
  if (!link) return null
  const ask = enrolAsk({ id: record.id, url: link.url, name: record.name, backend: record.backend, fingerprint: await recordFingerprint(record), expiresAt: record.expiresAt, requestedBy: { device, session: record.session }, intent: record.intent, claimed: record.claimed })
  return withContext(ask, { origin: record.origin, workspace: null, device: null })
}

export function isPendingRecord(record: EnrolmentRecord): record is EnrolmentRecord & { state: "pending"; id: string; code: string; url: string; expiresAt: string } {
  return record.state === "pending" && record.id !== null && record.code !== null && record.url !== null && record.expiresAt !== null
}

