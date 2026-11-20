// The ledger of open asks this machine created (UX-MEHEN-TOOLS 2.4):
// ~/.config/mehen/ledger.json, 0600, written atomically. It holds links, ids,
// expiries and, for an enrolment, the public JWK: never a secret, a token or
// a nonce. A link does nothing without a passkey session in the browser.
//
// Entries are pruned as they expire, and dropped when mehen wait settles them.
// Every link read back goes through askUrl against the vault this machine
// uses, so a hand-edited or stale ledger cannot hand a human a foreign link.
// Every entry records the identity it was written under (origin, workspace
// id, device), and a read drops any entry whose identity is not the reading
// context's (design 15.6): one context's asks never surface in another.

import { lstat, readFile } from "node:fs/promises"
import { join } from "node:path"
import type { DeviceJwk } from "@mehen/protocol/proof"
import { WorkspaceSlugSchema } from "@mehen/protocol/workspace"
import { type Ask, type AskCheckLabel, type AskContext, type AskKind, type AskLink, type AskVault, ROUTE_PREFIX, askUrl, isAskId, isWaitId } from "./ask.ts"
import { type Backend, BACKENDS, ensureConfigDir, writePrivateFile } from "./config.ts"
import { acquireLockFile, releaseLockFile } from "./slot-lock.ts"
import { terminalText } from "./tty.ts"

export const LEDGER_FILE = "ledger.json"

// An enrolment's key material that is safe to keep: the public JWK, so an
// enclave key (which mehen-se cannot export) can be re-enrolled, and the code
// that is already in the link.
// `workspace` and `team` are the intent the enrolment was started with
// (design 9.2), so a later wait can check the vault's answer against it.
export type LedgerEnrolment = { code: string; name: string; backend: Backend; jwk: DeviceJwk; workspace: string; team: string | null }

// The identity a ledger is read and written under. While enrolling there is
// no workspace or device yet: both null, and only the origin is compared.
export type LedgerScope = { vaultUrl: string; workspace: string | null; device: string | null; workspaceSlug?: string | null }

export type LedgerEntry = {
  ask: Ask
  createdAt: string
  origin: string
  workspace: string | null
  device: string | null
  // The item the ask creates (an intake or connect slug), for lookup by slug
  // and for the re-issue check. Null for approvals and enrolments.
  slug: string | null
  // The command that created the ask, so an expired one can be re-issued
  // exactly. Null when the caller did not record one.
  command: string | null
  enrol?: LedgerEnrolment
}

// How long an entry without an expiry is kept, per kind.
const KEEP_WITHOUT_EXPIRY_MS: Record<AskKind, number> = {
  enrol: 15 * 60_000,
  intake: 24 * 3_600_000,
  connect: 15 * 60_000,
  reconnect: 15 * 60_000,
  approval: 60 * 60_000,
  policy: 60 * 60_000,
  adoption: 24 * 3_600_000,
  bundle: 60 * 60_000,
  unfreeze: 0,
  mandate: 0,
}

// An intake or connect for the same slug is re-issued (not re-created) while
// its link has at least this long left.
export const REISSUE_MIN_REMAINING_MS = 2 * 60_000

export function ledgerPath(dir: string): string {
  return join(dir, LEDGER_FILE)
}

// A mandate proposal is kept only so mehen wait and vault_wait find its
// workspace: mehen mandate ls lists proposals, so no pending list or count
// shows it (isListedAsk).
const ASK_KINDS: readonly AskKind[] = ["enrol", "intake", "connect", "reconnect", "approval", "policy", "adoption", "bundle", "unfreeze", "mandate"]
const CHECK_LABELS: readonly AskCheckLabel[] = ["fingerprint", "code", "account", "asked by", "codes"]

function isString(value: unknown): value is string {
  return typeof value === "string"
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string"
}

// Copies the known fields of an ask one by one, so nothing else ever lands
// in the file, and refuses a shape that is not an ask or whose link is not
// on this vault.
// The ask's provenance, copied field by field. Supplied provenance must be
// the reading scope's own origin, workspace and device, and name the slug
// the accepted link is under; any disagreement refuses the whole entry
// rather than keeping or stripping conflicting evidence.
type Provenance = { context?: AskContext } | "refused"
function pickContext(value: unknown, scope: LedgerScope, linkSlug: string | null): Provenance {
  if (value === undefined) return {}
  if (typeof value !== "object" || value === null) return "refused"
  const c = value as Record<string, unknown>
  const w = c.workspace as Record<string, unknown> | null | undefined
  if (c.origin !== scope.vaultUrl || !isNullableString(c.device) || c.device !== scope.device) return "refused"
  if (w === null || w === undefined) {
    if (scope.workspace !== null) return "refused"
    return { context: { origin: scope.vaultUrl, workspace: null, device: c.device } }
  }
  if (typeof w !== "object" || !isString(w.id) || !isString(w.slug) || !isString(w.name)) return "refused"
  if (w.id !== scope.workspace || (linkSlug !== null && w.slug !== linkSlug) || (scope.workspaceSlug && w.slug !== scope.workspaceSlug)) return "refused"
  return { context: { origin: scope.vaultUrl, workspace: { id: w.id, slug: w.slug, name: w.name }, device: c.device } }
}

// The route a link of each kind must be on: the ask's own id, or for an
// enrolment its code; the unfreeze link is the workspace root. A reconnect
// may also point at the credential's own page.
function routeMatches(kind: AskKind, id: string, link: AskLink): boolean {
  const route = link.route
  if (kind === "unfreeze") return route === null && id === ""
  if (route === null) return false
  if (kind === "mandate") return route.prefix === "sign-mandate" && route.id === id
  if (kind === "enrol") return route.prefix === "e" && isAskId("enrol", route.id)
  if (kind === "reconnect" && route.prefix === "items") return id === ""
  if ((kind === "policy" || kind === "adoption" || kind === "bundle") && id === "") return false
  if (route.prefix !== ROUTE_PREFIX[kind]) return false
  return id === "" ? isWaitId(kind, route.id) : route.id === id
}

function pickAsk(value: unknown, scope: LedgerScope): Ask | null {
  if (typeof value !== "object" || value === null) return null
  const a = value as Record<string, unknown>
  const by = a.requestedBy as Record<string, unknown> | undefined
  const check = a.check as Record<string, unknown> | null | undefined
  if (!ASK_KINDS.includes(a.kind as AskKind) || !isString(a.id) || !isString(a.title) || !isString(a.what)) return null
  const kind = a.kind as AskKind
  const vaultUrl: AskVault = scope
  const link = askUrl(a.url, vaultUrl)
  if (link === null) return null
  if (kind !== "unfreeze" && kind !== "mandate" && a.id !== "" && !isWaitId(kind, a.id)) return null
  if (!routeMatches(kind, a.id, link)) return null
  const provenance = pickContext(a.context, scope, link.workspace)
  if (provenance === "refused") return null
  if (!isNullableString(a.expiresAt) || !isNullableString(a.account) || !isNullableString(a.wait)) return null
  if (typeof by !== "object" || by === null || !isString(by.device) || !isNullableString(by.session)) return null
  if (check !== null && (typeof check !== "object" || !isString(check?.value) || !CHECK_LABELS.includes(check?.label as AskCheckLabel))) return null
  return {
    kind: a.kind as AskKind,
    id: a.id,
    url: link.url,
    title: a.title,
    what: a.what,
    check: check ? { label: check.label as AskCheckLabel, value: check.value as string } : null,
    expiresAt: a.expiresAt,
    account: a.account,
    requestedBy: { device: by.device, session: by.session },
    wait: a.wait,
    ...provenance,
    ...(kind === "enrol" && typeof a.claimed === "boolean" ? { claimed: a.claimed } : {}),
  }
}

function isJwk(value: unknown): value is DeviceJwk {
  if (typeof value !== "object" || value === null) return false
  const k = value as Record<string, unknown>
  return k.kty === "EC" && k.crv === "P-256" && isString(k.x) && isString(k.y) && !("d" in k)
}

function pickEnrolment(value: unknown): LedgerEnrolment | null {
  if (typeof value !== "object" || value === null) return null
  const e = value as Record<string, unknown>
  if (!isString(e.code) || !isString(e.name) || !(BACKENDS as readonly string[]).includes(e.backend as string) || !isJwk(e.jwk)) return null
  if (!isString(e.workspace) || !WorkspaceSlugSchema.safeParse(e.workspace).success || !isNullableString(e.team)) return null
  return { code: e.code, name: e.name, backend: e.backend as Backend, jwk: { kty: "EC", crv: "P-256", x: e.jwk.x, y: e.jwk.y }, workspace: e.workspace, team: e.team }
}

export function pickLedgerEntry(value: unknown, scope: LedgerScope): LedgerEntry | null {
  if (typeof value !== "object" || value === null) return null
  const e = value as Record<string, unknown>
  if (e.origin !== scope.vaultUrl || !isNullableString(e.workspace) || !isNullableString(e.device)) return null
  if (e.workspace !== scope.workspace || e.device !== scope.device) return null
  const enrol = e.enrol === undefined ? undefined : pickEnrolment(e.enrol)
  if (enrol === null) return null
  // An enrolment's link is under the workspace it was started for: its
  // validated intent is the slug an enrol-scoped read accepts when the
  // reader did not name one.
  const askScope: LedgerScope = enrol && scope.workspace === null && !scope.workspaceSlug ? { ...scope, workspaceSlug: enrol.workspace } : scope
  const picked = pickAsk(e.ask, askScope)
  if (!picked || !isString(e.createdAt)) return null
  if (enrol && picked.kind !== "enrol") return null
  // An enrol ask carries its intent: the validated intent
  // the entry was started with; a legacy entry was never claimed.
  const ask: Ask = enrol ? { ...picked, intent: { workspace: enrol.workspace, team: enrol.team }, claimed: picked.claimed === true } : picked
  const slug = isNullableString(e.slug) ? e.slug : null
  const command = isNullableString(e.command) ? e.command : null
  return { ask, createdAt: e.createdAt, origin: scope.vaultUrl, workspace: scope.workspace, device: scope.device, slug, command, ...(enrol ? { enrol } : {}) }
}

// Milliseconds the entry's link is still good for; negative when it is gone.
export function remainingMs(entry: LedgerEntry, now: Date): number {
  if (entry.ask.expiresAt) {
    const at = Date.parse(entry.ask.expiresAt)
    if (Number.isFinite(at)) return at - now.getTime()
  }
  const created = Date.parse(entry.createdAt)
  const since = Number.isFinite(created) ? created : now.getTime()
  return since + KEEP_WITHOUT_EXPIRY_MS[entry.ask.kind] - now.getTime()
}

export function pruneLedger(entries: LedgerEntry[], now: Date): LedgerEntry[] {
  return entries.filter((entry) => remainingMs(entry, now) > 0)
}

// The raw entry list of a ledger file, or null when there is none to read.
// A link or non-file in its place is ignored (with a warning when `warn`).
async function readEntryList(dir: string, warn: boolean): Promise<unknown[] | null> {
  const path = ledgerPath(dir)
  let text: string
  try {
    const info = await lstat(path)
    if (info.isSymbolicLink() || !info.isFile()) {
      if (warn) process.stderr.write(`${terminalText(`mehen: warning: ${path} is ${info.isSymbolicLink() ? "a symbolic link" : "not a regular file"}; mehen is ignoring it and will replace it.`)}\n`)
      return null
    }
    text = await readFile(path, "utf8")
  } catch (error) {
    if (!warn || (error as { code?: string }).code === "ENOENT") return null
    throw error
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return null
  }
  return Array.isArray(parsed) ? parsed : typeof parsed === "object" && parsed !== null && Array.isArray((parsed as { entries?: unknown }).entries) ? (parsed as { entries: unknown[] }).entries : []
}

// The entries on disk, pruned. A missing or unreadable file is an empty
// ledger; entries that are not asks, whose link is not on the scope's
// origin, or whose recorded identity is not the scope's, are dropped rather
// than trusted. The file is looked at without following links: a symbolic
// link in its place is refused with a warning and read as empty (the next
// write replaces the link with a real 0600 file). A pending slot's
// enrolment.json is never read here: the enrol lifecycle, discovery and
// `mehen pending` read the record itself (enrolment-record.ts).
export async function readLedger(dir: string, scope: LedgerScope, now = new Date()): Promise<LedgerEntry[]> {
  const list = (await readEntryList(dir, true)) ?? []
  return pruneLedger(list.map((e) => pickLedgerEntry(e, scope)).filter((e): e is LedgerEntry => e !== null), now)
}

// The legacy reader: every enrol entry of a ledger under the enrol
// scope of `origin`, validated like any read but never pruned by expiry,
// oldest first. For the migration and discovery, never for handing a link
// to a human without the record's own checks.
export async function readLegacyEnrolments(dir: string, origin: string): Promise<(LedgerEntry & { enrol: LedgerEnrolment })[]> {
  const list = (await readEntryList(dir, false)) ?? []
  const scope: LedgerScope = { vaultUrl: origin, workspace: null, device: null }
  return list
    .map((e) => pickLedgerEntry(e, scope))
    .filter((e): e is LedgerEntry & { enrol: LedgerEnrolment } => e !== null && e.enrol !== undefined)
    .sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt))
}

// Every origin a ledger's entries were written under, for the migration's
// inventory of a directory with a ledger and no config.
export async function ledgerOrigins(dir: string): Promise<string[]> {
  const list = (await readEntryList(dir, false)) ?? []
  const origins = new Set<string>()
  for (const e of list) if (typeof e === "object" && e !== null && typeof (e as { origin?: unknown }).origin === "string") origins.add((e as { origin: string }).origin)
  return [...origins].sort()
}

// Every entry on disk that is a well-formed ask on this origin, whatever
// identity it was written under, for a write that must keep other contexts'
// entries in the same file. Not for handing anything to a human.
async function readAllEntries(dir: string, now: Date): Promise<unknown[]> {
  const list = (await readEntryList(dir, false)) ?? []
  // Kept by shape and expiry only: another identity's link is checked by
  // that identity when it reads, never trusted or dropped here.
  return list.filter((e) => {
    if (typeof e !== "object" || e === null) return false
    const entry = e as Record<string, unknown>
    const ask = entry.ask as Record<string, unknown> | undefined
    if (!isString(entry.origin) || !isNullableString(entry.workspace) || !isNullableString(entry.device) || !isString(entry.createdAt)) return false
    if (typeof ask !== "object" || ask === null || !ASK_KINDS.includes(ask.kind as AskKind) || !isString(ask.id) || !isString(ask.url) || !isNullableString(ask.expiresAt)) return false
    return remainingMs({ ask: { kind: ask.kind as AskKind, expiresAt: ask.expiresAt } as Ask, createdAt: entry.createdAt } as LedgerEntry, now) > 0
  })
}

export const LOCK_WAIT_MS = 2_000
const LOCK_WARNING = "mehen: warning: ledger.json is busy or unavailable; the command succeeded without updating the local ask ledger.\n"

// The ledger's own lock stays best effort (R2 response): its
// authoritative record is the vault's, so a busy lock costs a convenience
// and a warning, never the command. The lock file mechanics are slot-lock.ts's.
// No command sets `lockWaitMs`: only a test that queues more writes than
// the default wait can serve on a loaded machine.
export type LedgerLockOptions = { lockWaitMs?: number }

async function withLedgerLock(dir: string, update: () => Promise<void>, options: LedgerLockOptions = {}): Promise<void> {
  const path = `${ledgerPath(dir)}.lock`
  let held: Awaited<ReturnType<typeof acquireLockFile>> = null
  try {
    await ensureConfigDir(dir)
    held = await acquireLockFile(path, { waitMs: options.lockWaitMs ?? LOCK_WAIT_MS })
  } catch {
    // Local bookkeeping must not fail a command that succeeded at the vault.
  }
  if (!held) {
    process.stderr.write(LOCK_WARNING)
    return
  }
  try {
    await update()
  } finally {
    await releaseLockFile(held)
  }
}

// Writes this scope's entries, keeping the file's entries of other
// identities (an enrolment's entries beside the enrolled context's, in the
// same directory) untouched. A pending slot's enrolment.json is never
// written or removed here.
async function writeLedgerUnlocked(dir: string, scope: LedgerScope, entries: LedgerEntry[], now: Date): Promise<void> {
  const clean = entries.map((e) => pickLedgerEntry(e, scope)).filter((e): e is LedgerEntry => e !== null)
  const foreign = (await readAllEntries(dir, now)).filter((e) => pickLedgerEntry(e, scope) === null)
  await writePrivateFile(ledgerPath(dir), `${JSON.stringify({ entries: [...foreign, ...clean] }, null, 2)}\n`)
}

// Replacing a snapshot is locked too; read-modify-write callers must use the
// add/remove helpers so the read belongs to the same critical section.
export async function writeLedger(dir: string, scope: LedgerScope, entries: LedgerEntry[], now = new Date()): Promise<void> {
  await withLedgerLock(dir, () => writeLedgerUnlocked(dir, scope, entries, now))
}

export type LedgerEntryInput = { ask: Ask; slug?: string | null; command?: string | null; enrol?: LedgerEnrolment; now?: Date } & LedgerLockOptions

// Records an ask under the scope's identity, replacing an earlier entry
// with the same id, and prunes.
export async function addLedgerEntry(dir: string, scope: LedgerScope, input: LedgerEntryInput): Promise<LedgerEntry> {
  const now = input.now ?? new Date()
  const entry: LedgerEntry = { ask: input.ask, createdAt: now.toISOString(), origin: scope.vaultUrl, workspace: scope.workspace, device: scope.device, slug: input.slug ?? null, command: input.command ?? null, ...(input.enrol ? { enrol: input.enrol } : {}) }
  const picked = pickLedgerEntry(entry, scope)
  if (!picked) throw new Error("A ledger entry needs a complete ask whose link is on the vault.")
  await withLedgerLock(dir, async () => {
    const others = (await readLedger(dir, scope, now)).filter((e) => e.ask.id !== input.ask.id || input.ask.id === "")
    await writeLedgerUnlocked(dir, scope, [...others, picked], now)
  }, input)
  return picked
}

export async function removeLedgerEntry(dir: string, scope: LedgerScope, id: string, now = new Date(), options: LedgerLockOptions = {}): Promise<void> {
  await removeLedgerEntries(dir, scope, (entry) => entry.ask.id === id, now, options)
}

export async function removeLedgerEntries(dir: string, scope: LedgerScope, matches: (entry: LedgerEntry) => boolean, now = new Date(), options: LedgerLockOptions = {}): Promise<void> {
  await withLedgerLock(dir, async () => {
    const entries = await readLedger(dir, scope, now)
    const kept = entries.filter((entry) => !matches(entry))
    if (kept.length !== entries.length) await writeLedgerUnlocked(dir, scope, kept, now)
  }, options)
}

// Whether a pending list or count shows the entry: every ask but a mandate
// proposal.
export function isListedAsk(entry: LedgerEntry): boolean {
  return entry.ask.kind !== "mandate"
}

// By id (exact) or by the slug the ask creates; the newest wins for a slug.
export function findLedgerEntry(entries: LedgerEntry[], idOrSlug: string): LedgerEntry | null {
  const byId = entries.find((e) => e.ask.id === idOrSlug)
  if (byId) return byId
  const bySlug = entries.filter((e) => e.slug === idOrSlug)
  return bySlug.at(-1) ?? null
}

// The open intake or connect for a slug that still has long enough to live
// to be handed over again instead of creating a second link.
export function reissuableEntry(entries: LedgerEntry[], kind: "intake" | "connect", slug: string, now: Date): LedgerEntry | null {
  const candidates = entries.filter((e) => e.ask.kind === kind && e.slug === slug && remainingMs(e, now) > REISSUE_MIN_REMAINING_MS)
  return candidates.at(-1) ?? null
}
