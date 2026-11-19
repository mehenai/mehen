// Slots: one directory per
// (origin, workspace) under the root.
//
//   workspaces/<originKey>/<tn_id>/   an active slot: config.json, the key, ledger.json
//   pending/<originKey>/<slug>/       a pending slot: the provisional key and
//                                     enrolment.json (or a legacy enrol entry
//                                     in ledger.json an older mehen wrote); the
//                                     finish step renames it into workspaces/
//
// Discovery reports a slot it cannot read as corrupt and skips it; it never
// throws for one slot and never deletes. MEHEN_WORKSPACES is a ceiling that
// only narrows (the allowed set A); selection runs in a fixed order
// (selectSlot, below) before any key is read, and every refusal is local, exit 2. The managed
// host's rule 0 (the marker and the version-3 pin, agent-profiles.ts) runs
// first and unchanged.

import { lstat, readdir } from "node:fs/promises"
import { userInfo } from "node:os"
import { basename, join } from "node:path"
import { type OwnerRef, WorkspaceSlugSchema, normaliseWorkspaceSlug } from "@mehen/protocol/workspace"
import type { NextStep } from "@mehen/protocol/api"
import { type VaultFileOptions, assertLocalVaultIdentity, assertManagedVaultSelection, readVaultContextsFile } from "./agent-profiles.ts"
import type { Ask } from "./ask.ts"
import { BACKENDS, type Backend, type Config, DEFAULT_VAULT_URL, type Env, assertPrivateFile, canonicalOrigin, defaultConfigDir, readConfig, resolveVaultUrl, workspaceLabel } from "./config.ts"
import { keyPath, readKeyScope } from "./device-key.ts"
import { type EnrolmentRecord, type WorkspaceIntent, isPendingRecord, readEnrolmentRecord, recordAsk, recordFingerprint, recordFromLegacyEntry } from "./enrolment-record.ts"
import { CliError, usageError } from "./errors.ts"
import { PENDING_DIR, WORKSPACES_DIR, managedHost, originKey, resolveHome, rootAboveSlot } from "./home.ts"
import { type LedgerScope, ledgerOrigins, readLedger, readLegacyEnrolments } from "./ledger.ts"
import type { ManifestWorkspace } from "./run/manifest.ts"

export type { WorkspaceIntent } from "./enrolment-record.ts"

// The published shapes.
export type ActiveSlot = { state: "active"; slot: string; origin: string; workspace: { id: string; slug: string | null; name: string | null }; device: string; backend: Backend; owner: OwnerRef | null; fingerprint: string | null }
export type PendingSlot = { state: "pending"; slot: string; origin: string; intent: WorkspaceIntent; enrolment: string; backend: Backend; fingerprint: string; startedAt: string; expiresAt: string; hardExpiresAt: string | null; renewals: number; claimed: boolean; legacy: boolean; ask: Ask }
export type CorruptReason = "config_invalid" | "key_missing" | "key_insecure" | "scope_mismatch" | "duplicate_device" | "not_a_slot"
export type CorruptSlot = { state: "corrupt"; slot: string; reason: CorruptReason; detail: string; next: NextStep }
// A pending slot whose attempt ended for good (expired or replaced): the
// record is gone and the key is kept, so the next enrol for the slug reuses
// it and the fingerprint stays the same. Never a reason to forget the slot.
export type EndedSlot = { state: "ended"; slot: string; slug: string; detail: string; next: NextStep }
export type AbsentEntry = { state: "absent"; entry: string; next: NextStep }
export type Slot = ActiveSlot | PendingSlot | CorruptSlot | EndedSlot

// What discovery found, with what the callers need to act on it.
export type FoundActive = { state: "active"; dir: string; config: Config }
export type FoundPending = { state: "pending"; dir: string; slug: string; record: EnrolmentRecord & { state: "pending"; id: string; code: string; url: string; expiresAt: string }; legacyLedger: boolean }
// Discovery keeps an ended attempt with the slots it cannot use (never
// selected, never admitted); only its published view is EndedSlot.
export type FoundCorrupt = { state: "corrupt"; dir: string; reason: CorruptReason | "attempt_ended"; detail: string }
export type FoundSlot = FoundActive | FoundPending | FoundCorrupt

// The old `LocalContext` name: an active slot's directory and config.
export type LocalContext = { dir: string; config: Config }

export type SelectionReason = "workspace" | "manifest" | "only" | "ledger" | "managed" | "none"

export type SelectedContext = {
  dir: string
  // Null when nothing active is selected (no slot, or only a pending one).
  config: Config | null
  reason: SelectionReason
  // Active slots in the allowed set (plus a pinned directory outside them):
  // the count that decides whether a manifest without a workspace is unbound.
  known: number
}

export type SelectionOptions = {
  // The cwd's manifest, when the caller has one; absent means none was looked for.
  manifest?: ManifestWorkspace | null
  // `mehen wait <id>`: the ask id, for the one-slot-records-it stage (rule 4).
  waitId?: string
  // Verification seams for the managed-host marker and pin map (tests only).
  files?: VaultFileOptions
}

const WORKSPACE_ID = /^tn_[A-Za-z0-9]{8,40}$/
const ORIGIN_KEY = /^[A-Za-z0-9._-]{1,253}$/
const DUPLICATE = /\.duplicate-(dev_[A-Za-z0-9]{8,40})$/

// ---- refusals ---------------------------------------------------------

export function workspaceUnknown(selector: string, pending?: FoundPending): CliError {
  const slug = WorkspaceSlugSchema.safeParse(selector).success ? selector : "<slug>"
  if (pending) {
    return new CliError("workspace_unknown", `This machine's enrolment in workspace ${selector} is not approved yet (${pending.record.id}).`, {
      command: `mehen wait ${pending.record.id}`,
      say: `Relay the enrolment link to the human and run \`mehen wait ${pending.record.id}\` until it is approved.`,
    })
  }
  return new CliError("workspace_unknown", `No enrolment on this machine is in workspace ${selector}.`, {
    command: `mehen enrol --workspace ${slug}`,
    say: `Enrol this machine in that workspace with \`mehen enrol --workspace ${slug}\` (the slug is on the workspace's Connect an agent page), or run \`mehen workspace list\` to see which workspaces this machine is in.`,
  })
}

function contextLabel(c: LocalContext): string {
  return `${workspaceLabel(c.config)} at ${c.config.vault} as ${c.config.device} (${c.dir})`
}

export function contextAmbiguous(selector: string, matches: LocalContext[]): CliError {
  const choices = [...new Set(matches.map((c) => c.config.workspaceSlug ?? c.config.tenant))].map((s) => `--workspace ${s}`).join(", ")
  return new CliError("context_ambiguous", `${selector} matches ${matches.length} enrolments on this machine: ${matches.map(contextLabel).join("; ")}.`, {
    command: "mehen workspace list",
    say: `Name one (${choices}), or bind the checkout with \`mehen workspace bind\`; \`mehen workspace list\` shows them.`,
  })
}

// Rule 6: several active slots and nothing that selects one.
export function noneSelected(matches: LocalContext[]): CliError {
  const choices = [...new Set(matches.map((c) => c.config.workspaceSlug ?? c.config.tenant))].map((s) => `--workspace ${s}`).join(", ")
  return new CliError("context_ambiguous", `This machine is enrolled in ${matches.length} workspaces and nothing selects one: ${matches.map(contextLabel).join("; ")}.`, {
    command: "mehen workspace list",
    say: `Name one (${choices}), set MEHEN_WORKSPACE for this shell, or bind the checkout with \`mehen workspace bind\`.`,
  })
}

export function workspaceMismatch(message: string, next?: { command?: string; say: string }): CliError {
  return new CliError("workspace_mismatch", message, next ?? { command: "mehen workspace show", say: "Make the selection agree: `mehen workspace show` says which workspace the current directory picks and why." })
}

export function workspaceUnbound(manifestPath: string): CliError {
  return new CliError("workspace_unbound", `${manifestPath} does not say which workspace it belongs to, and this machine is enrolled in more than one.`, {
    command: "mehen workspace bind",
    say: "Run `mehen workspace bind` in the checkout to record the workspace and vault in mehen.toml.",
  })
}

export function workspaceNotAllowed(what: string, ceiling: CeilingEntry[]): CliError {
  const list = ceiling.length === 0 ? "nothing (MEHEN_WORKSPACES is empty)" : ceiling.map((e) => e.text).join(", ")
  return new CliError("workspace_not_allowed", `${what} is outside MEHEN_WORKSPACES.`, {
    say: `This agent may use only ${list}. Only the human can widen MEHEN_WORKSPACES, in the harness that sets it; nothing here can.`,
  })
}

// ---- selectors ----------------------------------------------------------

// The selector to honour: --workspace folded into MEHEN_WORKSPACE by cli.ts.
export function workspaceSelector(env: Env): string | null {
  const value = env.MEHEN_WORKSPACE
  if (!value) return null
  const trimmed = value.trim()
  if (!WORKSPACE_ID.test(trimmed) && !WorkspaceSlugSchema.safeParse(normaliseWorkspaceSlug(trimmed)).success) {
    throw new CliError("workspace_unknown", `${JSON.stringify(value)} is not a workspace slug or id.`, { command: "mehen workspace list", say: "Give the workspace slug (as on its Connect an agent page) or its tn_ id." })
  }
  return WORKSPACE_ID.test(trimmed) ? trimmed : normaliseWorkspaceSlug(trimmed)
}

// Does an active slot answer to a selector: its workspace id, or its recorded slug.
export function contextMatches(context: LocalContext, selector: string): boolean {
  if (WORKSPACE_ID.test(selector)) return context.config.tenant === selector
  return context.config.workspaceSlug !== undefined && context.config.workspaceSlug === normaliseWorkspaceSlug(selector)
}

function sameWorkspace(config: Config, origin: string, workspace: string): boolean {
  return config.vault === origin && config.tenant === workspace
}

// The manifest's (origin, workspace) against a selected slot. A manifest
// with a workspace that is not this slot's refuses before signing; one
// without a workspace is fine for one slot and workspace_unbound for more.
export function assertManifestAgrees(selected: { dir: string; config: Config | null }, manifest: ManifestWorkspace | null | undefined, contexts: number): void {
  if (!manifest) return
  if (manifest.workspace === null) {
    if (contexts > 1) throw workspaceUnbound(manifest.path)
    return
  }
  if (!selected.config) return
  const origin = manifest.vault ?? selected.config.vault
  if (!sameWorkspace(selected.config, origin, manifest.workspace)) {
    throw workspaceMismatch(`${manifest.path} belongs to workspace ${manifest.workspace} at ${origin}, but the selected context in ${selected.dir} is ${workspaceLabel(selected.config)} at ${selected.config.vault}.`, {
      command: `mehen --workspace ${manifest.workspace}`,
      say: "Select the manifest's workspace (--workspace or MEHEN_WORKSPACE), unset the conflicting selection, or run `mehen workspace bind` to rebind the checkout.",
    })
  }
}

// A MEHEN_VAULT_URL that names another origin than the selected slot's.
export function assertVaultUrlAgrees(env: Env, config: Config | null): void {
  if (!config || !env.MEHEN_VAULT_URL) return
  const requested = canonicalOrigin(env.MEHEN_VAULT_URL)
  if (requested !== config.vault) {
    throw workspaceMismatch(`MEHEN_VAULT_URL is ${requested}, but this context is enrolled with ${config.vault}.`, {
      say: `Unset MEHEN_VAULT_URL, or set it to ${config.vault}; a context never talks to another vault than the one it enrolled with.`,
    })
  }
}

// ---- discovery ----------------------------------------------------------

// A directory this user owns, looked at without following links, closed to
// group and others. Discovery never tightens a mode or creates anything.
async function ownedDirectory(path: string, uid: number): Promise<boolean> {
  try {
    const info = await lstat(path)
    return !info.isSymbolicLink() && info.isDirectory() && info.uid === uid && (info.mode & 0o077) === 0
  } catch {
    return false
  }
}

// The owner-only directories under `path`, or the reason it cannot be
// listed: a subtree that cannot be read is reported, never thrown, so it
// cannot hide its healthy siblings.
async function ownedEntries(path: string, uid: number): Promise<string[] | { unreadable: string }> {
  if (!(await ownedDirectory(path, uid))) return []
  let names: string[]
  try {
    names = (await readdir(path)).sort()
  } catch (error) {
    return { unreadable: `${path} cannot be listed: ${error instanceof Error ? error.message : String(error)}` }
  }
  const owned: string[] = []
  for (const name of names) if (await ownedDirectory(join(path, name), uid)) owned.push(name)
  return owned
}

// A config and its canonical origin key, or why it cannot be one: a config
// whose vault is not a vault origin is as corrupt as one that is not JSON.
async function configOf(dir: string): Promise<{ config: Config | null; origin: string | null } | { invalid: string }> {
  try {
    const config = await readConfig(dir)
    return { config, origin: config ? originKey(config.vault) : null }
  } catch (error) {
    return { invalid: error instanceof Error ? error.message : String(error) }
  }
}

function recordOrigin(origin: string): string | null {
  try {
    return originKey(origin)
  } catch {
    return null
  }
}

async function activeAt(dir: string, origin: string, tenant: string): Promise<FoundSlot> {
  const duplicate = DUPLICATE.exec(tenant)
  if (duplicate) return { state: "corrupt", dir, reason: "duplicate_device", detail: `A second device (${duplicate[1]}) in one workspace, kept aside by the migration; keep one.` }
  const read = await configOf(dir)
  if ("invalid" in read) return { state: "corrupt", dir, reason: "config_invalid", detail: read.invalid }
  if (!read.config) return { state: "corrupt", dir, reason: "not_a_slot", detail: `${dir} holds no config.json.` }
  if (read.origin !== origin || read.config.tenant !== tenant) {
    return { state: "corrupt", dir, reason: "scope_mismatch", detail: `${dir} holds an enrolment in ${read.config.tenant} at ${read.config.vault}, not this directory's.` }
  }
  return { state: "active", dir, config: read.config }
}

async function pendingAt(dir: string, origin: string, slug: string): Promise<FoundSlot> {
  // A pending record decides first: the finish step writes config.json into
  // the pending slot just before the rename that commits it, so a crash
  // between the two leaves a resumable pending slot, not an active one.
  const record = await readEnrolmentRecord(dir)
  const read = record !== null && "record" in record && isPendingRecord(record.record) ? { config: null, origin: null } : await configOf(dir)
  if ("invalid" in read) return { state: "corrupt", dir, reason: "config_invalid", detail: read.invalid }
  // The interim form of L-A's activation, config.json beside the pending
  // key with no record: read as active, as before.
  if (read.config) return read.origin === origin ? { state: "active", dir, config: read.config } : { state: "corrupt", dir, reason: "scope_mismatch", detail: `${dir} holds an enrolment at ${read.config.vault}, not this directory's origin.` }
  if (record && "refused" in record) return { state: "corrupt", dir, reason: "config_invalid", detail: record.refused }
  if (record) {
    if (!isPendingRecord(record.record)) return { state: "corrupt", dir, reason: "config_invalid", detail: `The enrolment in ${dir} was being issued when mehen stopped; \`mehen enrol --workspace ${slug}\` resumes or replaces it.` }
    if (recordOrigin(record.record.origin) !== origin || record.record.intent.workspace !== slug) return { state: "corrupt", dir, reason: "scope_mismatch", detail: `${dir} holds an enrolment for ${record.record.intent.workspace} at ${record.record.origin}, not this directory's.` }
    return { state: "pending", dir, slug, record: record.record, legacyLedger: false }
  }
  // A legacy enrol entry in this slot's own ledger (today's enrol writes one).
  for (const o of await ledgerOrigins(dir)) {
    if (recordOrigin(o) !== origin) continue
    const entry = (await readLegacyEnrolments(dir, o)).filter((e) => e.enrol.workspace === slug).at(-1)
    if (entry) {
      const legacy = recordFromLegacyEntry(entry)
      if (isPendingRecord(legacy)) return { state: "pending", dir, slug, record: legacy, legacyLedger: true }
    }
  }
  // The attempt ended for good: `mehen wait` removed the record and kept the key.
  if (await holdsDeviceKey(dir)) return { state: "corrupt", dir, reason: "attempt_ended", detail: `The last enrolment attempt for ${slug} ended without being accepted; the key in ${dir} is kept.` }
  return { state: "corrupt", dir, reason: "not_a_slot", detail: `${dir} holds neither a config nor an enrolment record.` }
}

async function holdsDeviceKey(dir: string): Promise<boolean> {
  for (const backend of BACKENDS) {
    try {
      if ((await lstat(keyPath(dir, backend))).isFile()) return true
    } catch {
      // absent: look for the other backend's key
    }
  }
  return false
}

// The next step for an ended attempt: enrol the slug again, with the same key.
export function endedNext(slug: string): NextStep {
  return { command: `mehen enrol --workspace ${slug}`, say: `The last enrolment attempt for ${slug} ended without being accepted; the key is kept, so \`mehen enrol --workspace ${slug}\` starts a new attempt with the same fingerprint.` }
}

// One slot, read without letting anything about it escape as an error.
async function slotAt(read: () => Promise<FoundSlot>, dir: string): Promise<FoundSlot> {
  try {
    return await read()
  } catch (error) {
    return { state: "corrupt", dir, reason: "config_invalid", detail: `${dir} cannot be read: ${error instanceof Error ? error.message : String(error)}` }
  }
}

// Every slot under the root: active ones, then pending ones, each sorted by
// path. A slot or a subtree that cannot be read is `corrupt`, never thrown.
export async function listSlots(root: string): Promise<FoundSlot[]> {
  const uid = userInfo().uid
  const found: FoundSlot[] = []
  for (const [kind, read] of [[WORKSPACES_DIR, activeAt], [PENDING_DIR, pendingAt]] as const) {
    const base = join(root, kind)
    const origins = await ownedEntries(base, uid)
    if (!Array.isArray(origins)) {
      found.push({ state: "corrupt", dir: base, reason: "not_a_slot", detail: origins.unreadable })
      continue
    }
    for (const origin of origins) {
      const names = await ownedEntries(join(base, origin), uid)
      if (!Array.isArray(names)) {
        found.push({ state: "corrupt", dir: join(base, origin), reason: "not_a_slot", detail: names.unreadable })
        continue
      }
      for (const name of names) found.push(await slotAt(() => read(join(base, origin, name), origin, name), join(base, origin, name)))
    }
  }
  return found
}

function corruptNext(dir: string): NextStep {
  return { command: `mehen workspace forget --slot ${dir}`, say: `mehen does not use ${dir}; retire it with \`mehen workspace forget --slot ${dir}\`, or ask the owner if you are not sure what it is.` }
}

// The key checks a published view adds to an active slot: the key file is
// present and private, and its scope names this slot's origin and workspace.
async function keyHealth(found: FoundActive): Promise<FoundCorrupt | null> {
  const path = keyPath(found.dir, found.config.backend)
  try {
    await assertPrivateFile(path)
  } catch (error) {
    if ((error as { code?: string }).code === "ENOENT") return { state: "corrupt", dir: found.dir, reason: "key_missing", detail: `${path} is missing.` }
    return { state: "corrupt", dir: found.dir, reason: "key_insecure", detail: error instanceof Error ? error.message : String(error) }
  }
  const scope = await readKeyScope(found.dir, found.config.backend)
  if (scope && (scope.vault !== found.config.vault || (scope.tenant !== null && scope.tenant !== found.config.tenant))) {
    return { state: "corrupt", dir: found.dir, reason: "scope_mismatch", detail: `The key in ${found.dir} was made for ${scope.tenant ?? "an enrolment"} at ${scope.vault}.` }
  }
  return null
}

// The published view of a slot.
export async function slotView(found: FoundSlot, device: string): Promise<Slot> {
  if (found.state === "corrupt") {
    if (found.reason === "attempt_ended") {
      const slug = basename(found.dir)
      return { state: "ended", slot: found.dir, slug, detail: found.detail, next: endedNext(slug) }
    }
    return { state: "corrupt", slot: found.dir, reason: found.reason, detail: found.detail, next: corruptNext(found.dir) }
  }
  if (found.state === "active") {
    const unhealthy = await keyHealth(found)
    if (unhealthy) return slotView(unhealthy, device)
    const c = found.config
    return { state: "active", slot: found.dir, origin: c.vault, workspace: { id: c.tenant, slug: c.workspaceSlug ?? null, name: c.workspaceName ?? null }, device: c.device, backend: c.backend, owner: c.owner ?? null, fingerprint: c.fingerprint ?? null }
  }
  const r = found.record
  const ask = await recordAsk(r, device)
  if (!ask) return { state: "corrupt", slot: found.dir, reason: "config_invalid", detail: `The enrolment link in ${found.dir} is not on ${r.origin}.`, next: corruptNext(found.dir) }
  return { state: "pending", slot: found.dir, origin: r.origin, intent: r.intent, enrolment: r.id, backend: r.backend, fingerprint: await recordFingerprint(r), startedAt: r.startedAt, expiresAt: r.expiresAt, hardExpiresAt: r.hardExpiresAt, renewals: r.renewals, claimed: r.claimed, legacy: r.legacy, ask }
}

// ---- the ceiling (MEHEN_WORKSPACES) -------------------------------------

// One entry as written: a slug, a tn_ id, or <originKey>/<slug or id>.
export type CeilingEntry = { text: string; origin: string | null; selector: string }

// The ceiling, or null when it is unrestricted (unset or `*`). Set and empty
// is the empty list: nothing is allowed. A spelling that is none of the
// three is `usage`.
export function readCeiling(env: Env): CeilingEntry[] | null {
  const raw = env.MEHEN_WORKSPACES
  if (raw === undefined) return null
  const trimmed = raw.trim()
  if (trimmed === "*") return null
  if (trimmed === "") return []
  const entries: CeilingEntry[] = []
  for (const piece of trimmed.split(",")) {
    const text = piece.trim()
    if (text === "") continue
    const slash = text.indexOf("/")
    const origin = slash === -1 ? null : text.slice(0, slash)
    const rest = slash === -1 ? text : text.slice(slash + 1)
    const selector = WORKSPACE_ID.test(rest) ? rest : normaliseWorkspaceSlug(rest)
    if ((origin !== null && !ORIGIN_KEY.test(origin)) || (!WORKSPACE_ID.test(selector) && !WorkspaceSlugSchema.safeParse(selector).success)) {
      throw usageError(`MEHEN_WORKSPACES entry ${JSON.stringify(text)} is not a workspace slug, a tn_ id or <origin key>/<slug or id>.`)
    }
    entries.push({ text, origin, selector })
  }
  return entries
}

function slotOrigin(found: FoundActive | FoundPending): string {
  return found.state === "active" ? found.config.vault : found.record.origin
}

function slotAnswers(found: FoundActive | FoundPending, selector: string): boolean {
  if (found.state === "active") return contextMatches(found, selector)
  return !WORKSPACE_ID.test(selector) && found.record.intent.workspace === normaliseWorkspaceSlug(selector)
}

function entryMatches(entry: CeilingEntry, found: FoundActive | FoundPending): boolean {
  if (entry.origin !== null && originKey(slotOrigin(found)) !== entry.origin) return false
  return slotAnswers(found, entry.selector)
}

export type Allowed = {
  // The entries as written, or null when unrestricted.
  ceiling: CeilingEntry[] | null
  // The active and pending slots in A, in discovery order.
  slots: (FoundActive | FoundPending)[]
  // Every corrupt slot: reported, never selected.
  corrupt: FoundCorrupt[]
  // Ceiling entries that match no slot: allowed, not enrolled.
  absent: CeilingEntry[]
}

// A, resolved once per process against the slots on disk. A bare entry that
// matches slots at more than one origin refuses context_ambiguous: nothing
// is silently admitted at two origins.
export function resolveAllowed(found: FoundSlot[], ceiling: CeilingEntry[] | null): Allowed {
  const usable = found.filter((f): f is FoundActive | FoundPending => f.state !== "corrupt")
  const corrupt = found.filter((f): f is FoundCorrupt => f.state === "corrupt")
  if (ceiling === null) return { ceiling, slots: usable, corrupt, absent: [] }
  const admitted = new Set<string>()
  const absent: CeilingEntry[] = []
  for (const entry of ceiling) {
    const matches = usable.filter((f) => entryMatches(entry, f))
    const origins = new Set(matches.map(slotOrigin))
    if (entry.origin === null && origins.size > 1) {
      throw new CliError("context_ambiguous", `MEHEN_WORKSPACES entry ${entry.text} matches workspaces at ${origins.size} vaults: ${[...origins].join(", ")}.`, {
        say: `Name the vault in the entry: ${[...origins].map((o) => `${originKey(o)}/${entry.selector}`).join(" or ")}.`,
      })
    }
    if (matches.length === 0) absent.push(entry)
    for (const m of matches) admitted.add(m.dir)
  }
  return { ceiling, slots: usable.filter((f) => admitted.has(f.dir)), corrupt, absent }
}

// Is a selector (and, for a manifest, its origin) inside A?
export function insideCeiling(allowed: Allowed, selector: string, origin: string | null): boolean {
  if (allowed.ceiling === null) return true
  if (allowed.slots.some((f) => slotAnswers(f, selector) && (origin === null || slotOrigin(f) === origin))) return true
  return allowed.absent.some((e) => e.selector === selector && (origin === null || e.origin === null || e.origin === originKey(origin)))
}

export function activeIn(allowed: Allowed): FoundActive[] {
  return allowed.slots.filter((f): f is FoundActive => f.state === "active")
}

export function pendingIn(allowed: Allowed): FoundPending[] {
  return allowed.slots.filter((f): f is FoundPending => f.state === "pending")
}

// The root, its slots and A for this process.
export async function allowedSlots(env: Env, files: VaultFileOptions = {}): Promise<Allowed & { root: string }> {
  const { root } = resolveHome(env, { files })
  const found = await listSlots(root)
  return { root, ...resolveAllowed(found, readCeiling(env)) }
}

// ---- selection -----------------------------------------------------------

// A corrupt slot whose directory name is the selector (a tn_ id under
// workspaces/, a slug under pending/), for a refusal that names its path.
function corruptNamed(corrupt: FoundCorrupt[], selector: string): FoundCorrupt | undefined {
  const wanted = WORKSPACE_ID.test(selector) ? selector : normaliseWorkspaceSlug(selector)
  return corrupt.find((c) => basename(c.dir) === wanted)
}

function exactlyOne(selector: string, matches: FoundActive[], pending: FoundPending[], corrupt: FoundCorrupt[] = []): FoundActive {
  if (matches.length === 1) return matches[0] as FoundActive
  if (matches.length > 1) throw contextAmbiguous(selector, matches)
  const named = corruptNamed(corrupt, selector)
  if (named) {
    throw new CliError("workspace_unknown", `Workspace ${selector} on this machine is in ${named.dir}, which mehen cannot use: ${named.detail}`, {
      command: `mehen workspace forget --slot ${named.dir}`,
      say: `Run \`mehen doctor\` to see what is wrong with ${named.dir}; retire it with \`mehen workspace forget --slot ${named.dir}\` and enrol again, or ask the owner.`,
    })
  }
  throw workspaceUnknown(selector, pending.find((p) => p.record.intent.workspace === normaliseWorkspaceSlug(selector)))
}

// Rule 4 with no slot in A recording the id, and not exactly one active slot
// to ask: nothing is signed.
function waitNotFound(env: Env, id: string): CliError {
  if (id.startsWith("enr_")) {
    let vaultUrl = DEFAULT_VAULT_URL
    try {
      vaultUrl = canonicalOrigin(env.MEHEN_VAULT_URL || DEFAULT_VAULT_URL)
    } catch {
      // The message keeps the default; the bad URL is refused where it is used.
    }
    return new CliError("not_found", `No open enrolment ${id} is recorded on this machine for ${vaultUrl}.`, {
      command: "mehen enrol --workspace <slug>",
      say: "Only the machine that started an enrolment can wait on it, and only while its link lasts; run `mehen enrol --workspace <slug>` to start again.",
    })
  }
  return new CliError("not_found", `${id} is not recorded in any workspace this machine may use.`, {
    command: "mehen pending",
    say: "Run `mehen pending` to see what this machine has open, or name the workspace with --workspace <slug>.",
  })
}

// Managed host (rule 0): the launcher's explicit pinned directory, verified
// against the pin in that directory's own contexts.json (WORKLOAD 2.2), as
// before. No discovery, no manifest or selector may pick another; a
// ceiling, when set, must contain the pin.
async function managedSelection(env: Env, options: SelectionOptions): Promise<SelectedContext> {
  const dir = env.MEHEN_CONFIG_DIR
  const key = env.MEHEN_MANAGED_CONTEXT
  const refused = (why: string) =>
    new CliError("workspace_mismatch", `This host is managed: ${why}`, { say: "Start mehen through the agent's launcher, which sets MEHEN_CONFIG_DIR and MEHEN_MANAGED_CONTEXT from the owner's pin; nothing else selects a context here." })
  if (!dir || !key) throw refused("MEHEN_CONFIG_DIR and MEHEN_MANAGED_CONTEXT must both be set by the launcher.")
  if (dir === defaultConfigDir(env)) throw refused("the default directory is never a managed context.")
  // The pin helpers refuse with a plain error (agent-profiles.ts, frozen for
  // the launcher's parity); here that is the local mismatch code.
  const verified = (run: () => void): void => {
    try {
      run()
    } catch (error) {
      if (error instanceof CliError) throw error
      throw refused(error instanceof Error ? error.message : String(error))
    }
  }
  let pin!: ReturnType<typeof assertManagedVaultSelection>
  verified(() => {
    const map = readVaultContextsFile(join(dir, "contexts.json"), options.files ?? {})
    pin = assertManagedVaultSelection(map, key, env, defaultConfigDir(env))
  })
  const config = await readConfig(dir)
  if (!config) throw refused(`${dir} holds no enrolment.`)
  verified(() => assertLocalVaultIdentity(pin, config))
  const selector = workspaceSelector(env)
  if (selector !== null && !contextMatches({ dir, config }, selector)) throw refused(`--workspace ${selector} is not the pinned workspace.`)
  const ceiling = readCeiling(env)
  if (ceiling !== null && !ceiling.some((e) => (e.origin === null || e.origin === originKey(config.vault)) && contextMatches({ dir, config }, e.selector))) {
    throw workspaceNotAllowed(`The pinned workspace ${workspaceLabel(config)}`, ceiling)
  }
  assertVaultUrlAgrees(env, config)
  // A pin does not excuse an unbound multi-slot manifest (design 15.6).
  const above = rootAboveSlot(dir)
  const others = above && above.kind === "workspaces" ? (await listSlots(above.root)).filter((f): f is FoundActive => f.state === "active" && f.dir !== dir).length : 0
  const known = others + 1
  assertManifestAgrees({ dir, config }, options.manifest, known)
  return { dir, config, reason: "managed", known }
}

// Rule 4: the one slot in A that records the id: an active slot's ledger,
// or a pending slot's enrolment. Several refuse; none falls through.
async function recordedIn(allowed: Allowed, id: string): Promise<(FoundActive | FoundPending)[]> {
  const hits: (FoundActive | FoundPending)[] = []
  for (const slot of allowed.slots) {
    if (slot.state === "pending") {
      if (slot.record.id === id) hits.push(slot)
      continue
    }
    const c = slot.config
    const scope: LedgerScope = { vaultUrl: c.vault, workspace: c.tenant, device: c.device, workspaceSlug: c.workspaceSlug ?? null }
    if ((await readLedger(slot.dir, scope)).some((e) => e.ask.id === id)) hits.push(slot)
  }
  return hits
}

// The slot the environment, flags, manifest and wait id select, in that
// order. Every refusal happens here, before any key is read.
// Nothing selected is `config: null` with reason `none`: the only pending
// slot's directory when A holds exactly one, else the root.
export async function selectSlot(env: Env, options: SelectionOptions = {}): Promise<SelectedContext> {
  if (managedHost(options.files ?? {})) return managedSelection(env, options)
  const allowed = await allowedSlots(env, options.files ?? {})
  const ceiling = allowed.ceiling ?? []
  const active = activeIn(allowed)
  const pending = pendingIn(allowed)
  const manifest = options.manifest ?? null
  const known = active.length
  // Set and empty: nothing is allowed, and a command that needs a workspace
  // says so rather than that nothing is enrolled.
  if (allowed.ceiling !== null && allowed.ceiling.length === 0) throw workspaceNotAllowed("Every workspace", ceiling)
  // 1: an unbound manifest under several slots, before every shortcut.
  if (manifest && manifest.workspace === null && known > 1) throw workspaceUnbound(manifest.path)
  const selector = workspaceSelector(env)
  // 2 and 3, outside A first: a selector, then the manifest's workspace,
  // before any comparison of the two.
  if (selector !== null && !insideCeiling(allowed, selector, null)) throw workspaceNotAllowed(`Workspace ${selector}`, ceiling)
  if (manifest?.workspace && !insideCeiling(allowed, manifest.workspace, manifest.vault)) throw workspaceNotAllowed(`${manifest.path} names workspace ${manifest.workspace}, which`, ceiling)
  let selected: SelectedContext | null = null
  if (selector !== null) {
    const match = exactlyOne(selector, active.filter((c) => contextMatches(c, selector)), pending, allowed.corrupt)
    selected = { dir: match.dir, config: match.config, reason: "workspace", known }
  } else if (manifest?.workspace) {
    const origin = manifest.vault
    const match = exactlyOne(manifest.workspace, active.filter((c) => c.config.tenant === manifest.workspace && (origin === null || c.config.vault === origin)), [], allowed.corrupt)
    selected = { dir: match.dir, config: match.config, reason: "manifest", known }
  } else if (options.waitId !== undefined) {
    const hits = await recordedIn(allowed, options.waitId)
    if (hits.length > 1) {
      const names = hits.map((h) => (h.state === "active" ? `${workspaceLabel(h.config)} at ${h.config.vault} (${h.dir})` : `pending enrolment (${h.dir})`)).join("; ")
      throw new CliError("context_ambiguous", `${options.waitId} is recorded in ${hits.length} workspaces on this machine: ${names}.`, {
        command: "mehen workspace list",
        say: "Name one with --workspace <slug>; `mehen workspace list` shows them.",
      })
    }
    const hit = hits[0]
    if (hit) selected = { dir: hit.dir, config: hit.state === "active" ? hit.config : null, reason: "ledger", known }
    // No hit: the one active slot in A is asked (the vault answers, as
    // today); with none or several, not_found before anything is signed.
    else if (active.length !== 1) throw waitNotFound(env, options.waitId)
  }
  if (selected === null) {
    if (active.length === 1) {
      const only = active[0] as FoundActive
      selected = { dir: only.dir, config: only.config, reason: "only", known }
    } else if (active.length > 1) {
      throw noneSelected(active)
    } else {
      const only = pending.length === 1 ? (pending[0] as FoundPending) : null
      selected = { dir: only?.dir ?? allowed.root, config: null, reason: "none", known }
    }
  }
  assertVaultUrlAgrees(env, selected.config)
  assertManifestAgrees(selected, manifest, known)
  return selected
}

// Every active slot in A, as the old `LocalContext` list.
export async function listActive(env: Env, files: VaultFileOptions = {}): Promise<LocalContext[]> {
  if (managedHost(files)) {
    const selected = await selectSlot(env, { manifest: null, files })
    return selected.config ? [{ dir: selected.dir, config: selected.config }] : []
  }
  return activeIn(await allowedSlots(env, files)).map((f) => ({ dir: f.dir, config: f.config }))
}

// The vault this machine would use, with the selected slot's canonical
// workspace slug when it has one, or null when it cannot be known. For the
// error renderer, which must never throw: it checks every link the vault
// hands back against this.
export async function knownVault(env: Env): Promise<{ vaultUrl: string; workspaceSlug: string | null } | null> {
  let config: SelectedContext["config"] = null
  try {
    config = (await selectSlot(env)).config
  } catch {
    config = null
  }
  try {
    return { vaultUrl: resolveVaultUrl(env, config), workspaceSlug: config?.workspaceSlug ?? null }
  } catch {
    return null
  }
}
