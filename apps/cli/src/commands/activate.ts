// The enrolment lifecycle after a link is issued, shared by mehen enrol, mehen wait and vault_wait, so any
// process can follow an attempt and finish it:
//
//   followAttempt  polls the attempt (never holding a lock), renews it in
//                  place through POST /v1/enrol/:id/renew while it is
//                  renewable, and settles it: rejected, expired for good,
//                  or active, which goes to the finish step.
//   finishAttempt  the finish step: under the active then pending lock,
//                  taken fresh, it checks that the attempt is still this
//                  observer's (record id, key and the key on disk), that the
//                  vault's answer matches the intent, and commits by renaming
//                  the pending slot to workspaces/<originKey>/<tn_id>/. A slot
//                  that already holds the device this observer activated is
//                  success; another device there is already_enrolled, and
//                  nothing is revoked or deleted.
//   mutateSlot     the compare-and-mutate step on an active slot (repair,
//                  replace, display refresh): it changes the slot only while
//                  it still holds the device and key the caller saw.
//
// Every write after an await goes through mutateAttempt or mutateSlot: a
// late answer about an older attempt or device never touches a newer one.
// A mismatched or unrecordable active answer self-revokes the new device
// with the identity the vault returned and deletes this attempt's key.

import { lstat, readFile, readdir, rename, rm } from "node:fs/promises"
import { dirname, join } from "node:path"
import { fingerprintOf } from "@mehen/protocol/fingerprint"
import { type DeviceJwk, jwkThumbprint } from "@mehen/protocol/proof"
import { type EnrolExpiredReason, OwnerRefSchema, WorkspaceDeviceScopeSchema, WorkspaceRefSchema, WorkspaceSlugSchema } from "@mehen/protocol/workspace"
import { z } from "zod"
import { type Backend, type Config, type Env, assertPrivateFile, readConfig, removeConfig, workspaceLabel, writeConfig } from "../config.ts"
import { type DeviceKey, ENCLAVE_PUBLIC_KEY_FILE, SOFTWARE_KEY_FILE, enclavePublicKeyPath, keyPath, loadDeviceKey, removeDeviceKey, writeKeyScope } from "../device-key.ts"
import { type EnrolmentRecord, type MutateResult, mutateAttempt, readEnrolmentRecord, removeEnrolmentRecord } from "../enrolment-record.ts"
import { CliError } from "../errors.ts"
import { WORKSPACES_DIR, activeSlotPath, mkdirPrivate, originKey } from "../home.ts"
import { HttpVaultApi } from "../http-client.ts"
import { LEDGER_FILE } from "../ledger.ts"
import { activeLockPath, pendingLockPath, slotLockPath, withSlotLocks } from "../slot-lock.ts"
import { VaultApiError } from "../vault-api.ts"

// What `mehen enrol --workspace <slug> [--team <slug>]` asked for, kept in
// the enrolment record so any later observer can check the answer.
export type EnrolIntent = { workspace: string; team: string | null }

const WORKSPACE_ID = /^tn_[A-Za-z0-9]{8,40}$/
const DEVICE_ID = /^dev_[A-Za-z0-9]{8,40}$/

const WorkspaceEnrolActive = z.object({
  status: z.literal("active"),
  tenant: z.string().min(1),
  workspace: WorkspaceRefSchema,
  device: z.string().regex(DEVICE_ID),
  scope: WorkspaceDeviceScopeSchema,
  owner: OwnerRefSchema,
})

export type VerifiedEnrolment = z.infer<typeof WorkspaceEnrolActive>

// The identity an active answer gives the new device, read even from an
// answer that fails the full check, so the device can be revoked.
const ActivatedIdentity = z.object({ tenant: z.string().min(1), device: z.string().regex(DEVICE_ID) })
type ActivatedIdentity = z.infer<typeof ActivatedIdentity>

export function isWorkspaceSlug(value: string): boolean {
  return WorkspaceSlugSchema.safeParse(value).success
}

// Why an active answer does not match the intent, or null when it does.
export function enrolmentMismatch(intent: EnrolIntent, answer: unknown): { verified: VerifiedEnrolment | null; identity: ActivatedIdentity | null; why: string | null } {
  const identity = ActivatedIdentity.safeParse(answer)
  const parsed = WorkspaceEnrolActive.safeParse(answer)
  if (!parsed.success) {
    const raw = (typeof answer === "object" && answer !== null ? answer : {}) as { workspace?: unknown; owner?: unknown; scope?: { privateCredentials?: unknown } }
    const why = raw.workspace === undefined || raw.owner === undefined ? "it names no workspace or owner" : raw.scope?.privateCredentials === undefined ? "its scope has no privateCredentials" : "it is not a complete workspace enrolment"
    return { verified: null, identity: identity.success ? identity.data : null, why }
  }
  const v = parsed.data
  const found = { verified: v, identity: { tenant: v.tenant, device: v.device } }
  if (v.workspace.id !== v.tenant) return { ...found, why: `its workspace id ${v.workspace.id} is not its tenant ${v.tenant}` }
  if (!WORKSPACE_ID.test(v.tenant)) return { ...found, why: `its tenant ${v.tenant} is not a workspace id` }
  if (v.workspace.slug !== intent.workspace) return { ...found, why: `it is for workspace ${v.workspace.slug}, not ${intent.workspace}` }
  if (intent.team === null && v.owner.kind !== "member") return { ...found, why: `its owner is team ${v.owner.name}, but this machine was to be your own` }
  if (intent.team !== null && v.owner.kind !== "team") return { ...found, why: `its owner is ${v.owner.name}, but this machine was to belong to team ${intent.team}` }
  return { ...found, why: null }
}

// ---- keys on disk -------------------------------------------------------

// The public half of the key in `dir`: the software key file's x and y, or
// the enclave key's sidecar. Null when there is none to read.
export async function publicKeyOnDisk(dir: string, backend: Backend): Promise<DeviceJwk | null> {
  const path = join(dir, backend === "software" ? SOFTWARE_KEY_FILE : ENCLAVE_PUBLIC_KEY_FILE)
  try {
    const info = await lstat(path)
    if (info.isSymbolicLink() || !info.isFile()) return null
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"))
    if (typeof parsed !== "object" || parsed === null) return null
    const k = parsed as Record<string, unknown>
    return typeof k.x === "string" && typeof k.y === "string" ? { kty: "EC", crv: "P-256", x: k.x, y: k.y } : null
  } catch {
    return null
  }
}

// Is the key in `dir` the one with this public half? The key itself must be
// there first: the software key file, or for an enclave key both the blob
// and its sidecar, each a private regular file of this user (never a link).
// A sidecar that outlived its blob (a replacement stopped between the two
// removals) is not the key, so no finish step commits a slot without it.
export async function sameKeyOnDisk(dir: string, backend: Backend, jwk: Pick<DeviceJwk, "x" | "y">): Promise<boolean> {
  try {
    await assertPrivateFile(keyPath(dir, backend))
    if (backend === "secure-enclave") await assertPrivateFile(enclavePublicKeyPath(dir))
  } catch {
    return false
  }
  const onDisk = await publicKeyOnDisk(dir, backend)
  return onDisk !== null && onDisk.x === jwk.x && onDisk.y === jwk.y
}

// ---- the active slot ------------------------------------------------------

// Removes an active slot: its key, scope, config and ledger, then the
// directory itself when it is a slot under the root. Best effort past the
// first failure is not wanted here: a slot half removed is reported.
async function removeSlot(slot: string, backend: Backend): Promise<void> {
  await removeDeviceKey(slot, backend)
  await removeConfig(slot)
  await rm(join(slot, LEDGER_FILE), { force: true })
  if (slotLockPath(slot) !== null) await rm(slot, { recursive: true, force: true })
}

// A compare-and-mutate on an active slot: under its lock, re-read config.json and
// apply `fn` (null removes the slot) only while it still holds `expected`'s
// device and key. `superseded` when another device or key replaced it,
// `gone` when it holds no enrolment. `fn` may throw to abort with nothing
// written, or return the config it was given to write nothing.
export async function mutateSlot(slot: string, expected: { device: string; jwk: Pick<DeviceJwk, "x" | "y"> | null }, fn: (config: Config) => Promise<Config | null> | Config | null): Promise<MutateResult> {
  // A managed host's legacy pinned context is not a slot under a root: it
  // has no lock of its own, and the comparison alone guards it.
  const lock = slotLockPath(slot)
  const run = async (): Promise<MutateResult> => {
    let config: Config | null
    try {
      config = await readConfig(slot)
    } catch {
      return "superseded"
    }
    if (!config) return "gone"
    if (config.device !== expected.device) return "superseded"
    if (expected.jwk !== null && !(await sameKeyOnDisk(slot, config.backend, expected.jwk))) return "superseded"
    const next = await fn(config)
    if (next === null) await removeSlot(slot, config.backend)
    else if (next !== config) await writeConfig(slot, next)
    return "applied"
  }
  return lock ? withSlotLocks([lock], run) : run()
}

// ---- an attempt -----------------------------------------------------------

export type PendingRecord = EnrolmentRecord & { state: "pending"; id: string; code: string; url: string; expiresAt: string }

// One enrolment attempt as an observer holds it: the pending slot, the
// record as last seen (id, key, intent, lease), and the key that signs its
// polls (a software key in memory, or an enclave signer bound to the blob's
// path).
export type Attempt = { root: string; slot: string; record: PendingRecord; key: DeviceKey; env: Env; session: string | null }

export type Finished = { config: Config; verified: VerifiedEnrolment; slot: string; already: boolean }

function attemptApi(a: Attempt, key: DeviceKey = a.key): HttpVaultApi {
  return new HttpVaultApi({ vaultUrl: a.record.origin, tenant: "enrol", signer: key.signer(a.record.id), ...(a.session ? { session: a.session } : {}), context: { origin: a.record.origin, workspace: null, device: null } })
}

function slugOf(a: Attempt): string {
  return a.record.intent.workspace
}

function enrolAgain(a: Attempt): string {
  return `mehen enrol --workspace ${slugOf(a)}${a.record.intent.team ? ` --team ${a.record.intent.team}` : ""}`
}

// Where the attempt is now, as this observer sees it: still its own (the
// record and the key on disk are the ones it holds), moved (the pending
// directory or its record is gone: another observer committed, settled or
// forgot it), or replaced by a newer attempt (--fresh-key, another name, a
// connect code).
type AttemptState = { state: "ours" } | { state: "moved" } | { state: "replaced"; by: string | null }

// The observer reads outside the slot's lock, so another observer's commit
// can rename the slot away between two of its reads: a record read before
// the rename and a key looked for after it. A slot that left, or that is
// no longer the directory first seen, is looked at again, never taken for
// a replacement.
export async function attemptState(a: Attempt, keyCheck: typeof sameKeyOnDisk = sameKeyOnDisk): Promise<AttemptState> {
  for (let look = 0; ; look += 1) {
    const before = await lstat(a.slot).catch(() => null)
    if (before === null) return { state: "moved" }
    const state = await slotState(a, keyCheck)
    if (state.state !== "replaced") return state
    const after = await lstat(a.slot).catch(() => null)
    if (after === null) return { state: "moved" }
    if ((after.dev === before.dev && after.ino === before.ino) || look >= 2) return state
  }
}

async function slotState(a: Attempt, keyCheck: typeof sameKeyOnDisk): Promise<AttemptState> {
  const read = await readEnrolmentRecord(a.slot)
  if (read === null) return { state: "moved" }
  const record = "record" in read ? read.record : null
  const by = record && record.id !== a.record.id ? record.id : null
  if (!record || record.id !== a.record.id || record.jwk.x !== a.record.jwk.x || record.jwk.y !== a.record.jwk.y) return { state: "replaced", by }
  if (!(await keyCheck(a.slot, a.record.backend, a.record.jwk))) return { state: "replaced", by: null }
  return { state: "ours" }
}

// The active slot at this origin that holds this attempt's key, when an
// earlier observer committed it: the key decides, it is unique.
async function committedElsewhere(a: Attempt): Promise<{ dir: string; config: Config } | null> {
  const base = join(a.root, WORKSPACES_DIR, originKey(a.record.origin))
  let names: string[]
  try {
    names = await readdir(base)
  } catch {
    return null
  }
  for (const name of names.sort()) {
    if (!WORKSPACE_ID.test(name)) continue
    const dir = join(base, name)
    const config = await readConfig(dir).catch(() => null)
    if (config && config.vault === a.record.origin && config.tenant === name && config.backend === a.record.backend && (await sameKeyOnDisk(dir, config.backend, a.record.jwk))) return { dir, config }
  }
  return null
}

function replacedError(a: Attempt, by: string | null, device: string | null, revoked: "revoked" | "unrevoked" | "unattempted"): CliError {
  const newer = by ? `a newer attempt (${by})` : "a newer attempt"
  const outcome =
    device === null
      ? `If a human approves the link of ${a.record.id} anyway, revoke that machine on the Machines page.`
      : revoked === "revoked"
        ? `The device ${device} the vault activated for it was revoked.`
        : `The vault activated device ${device} for it, which this machine cannot use: revoke it on the Machines page.`
  return new CliError("failed", `Enrolment ${a.record.id} was replaced on this machine by ${newer} while this observer waited; nothing on this machine was changed. ${outcome}`, {
    ...(by ? { command: `mehen wait ${by}` } : { command: "mehen pending" }),
    say: device !== null && revoked !== "revoked" ? `Device ${device} is active in the vault but no key on this machine signs for it: revoke it on the Machines page, then follow the newer attempt.` : "Follow the newer attempt instead; this one is no longer this machine's.",
  })
}

function recordGone(a: Attempt, device: string | null): CliError {
  return new CliError("failed", `The local record of enrolment ${a.record.id} is gone${device ? `; device ${device} is active in the vault` : ""}.`, {
    command: enrolAgain(a),
    say: `${device ? `An owner revokes device ${device} on the Machines page, or run` : "Run"} \`${enrolAgain(a)}\` again on this machine.`,
  })
}

// The superseded observer: the newer attempt is never
// touched. The device the vault just activated for this one is revoked only
// when this observer can still sign as it: a software key held in memory
// can; an enclave signer is bound to a blob path the newer attempt replaced
// or renamed, so it cannot, and that is said, never a cleanup claimed.
async function superseded(a: Attempt, by: string | null, identity: ActivatedIdentity | null): Promise<never> {
  if (!identity) throw replacedError(a, by, null, "unattempted")
  if (a.key.backend !== "software") throw replacedError(a, by, identity.device, "unattempted")
  const api = new HttpVaultApi({ vaultUrl: a.record.origin, tenant: identity.tenant, signer: a.key.signer(identity.device), ...(a.session ? { session: a.session } : {}) })
  let revoked: "revoked" | "unrevoked" = "unrevoked"
  try {
    await api.request<unknown>("POST", "/v1/devices/self/revoke", {})
    revoked = "revoked"
  } catch {
    revoked = "unrevoked"
  }
  throw replacedError(a, by, identity.device, revoked)
}

// On a mismatch or a failed commit: revoke with the returned identity (the
// key signs as that device in that tenant), then delete this attempt's key,
// scope, config and record from its pending slot. The error names the
// device when the vault did not accept the revocation.
async function selfRevoke(a: Attempt, identity: ActivatedIdentity | null, why: string, code: "workspace_mismatch" | "failed"): Promise<never> {
  let revoked: "revoked" | "unrevoked" | "unknown" = "unknown"
  if (identity) {
    const api = new HttpVaultApi({ vaultUrl: a.record.origin, tenant: identity.tenant, signer: a.key.signer(identity.device), ...(a.session ? { session: a.session } : {}) })
    try {
      await api.request<unknown>("POST", "/v1/devices/self/revoke", {})
      revoked = "revoked"
    } catch {
      revoked = "unrevoked"
    }
  }
  // Best effort: a path that cannot be removed (a directory planted where a
  // file goes) must not hide the refusal itself.
  const cleanup: string[] = []
  for (const [what, remove] of [["key", () => removeDeviceKey(a.slot, a.record.backend)], ["config", () => removeConfig(a.slot)], ["record", () => removeEnrolmentRecord(a.slot)]] as const) {
    try {
      await remove()
    } catch (error) {
      cleanup.push(`the ${what} could not be removed: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  const device = identity?.device ?? null
  const outcome = revoked === "revoked" ? `The device ${device} was revoked and this machine's key deleted.` : revoked === "unrevoked" ? `This machine's key was deleted, but the vault did not accept the revocation of device ${device}: an owner must revoke it on the Machines page.` : "This machine's key was deleted."
  throw new CliError(code, `The vault activated this enrolment, but ${why}. ${outcome}${cleanup.length ? ` ${cleanup.join("; ")}.` : ""}`, {
    command: `${enrolAgain(a)} --fresh-key`,
    say: `Nothing was written. Check which workspace the link was accepted in, ${device ? `make sure device ${device} is revoked there, ` : ""}then enrol again.`,
  })
}

function alreadyEnrolled(a: Attempt, existing: Config, verified: VerifiedEnrolment): CliError {
  const slug = existing.workspaceSlug ?? verified.workspace.slug
  return new CliError("already_enrolled", `This machine already holds device ${existing.device} in ${workspaceLabel(existing)}; the vault now also has device ${verified.device} active there (enrolment ${a.record.id}). Nothing was revoked or deleted.`, {
    command: `mehen revoke --workspace ${slug}`,
    say: `This machine already holds device ${existing.device} in ${workspaceLabel(existing)}; the vault now also has device ${verified.device} active; keep one: \`mehen revoke --workspace ${slug}\` revokes ${existing.device}, or revoke ${verified.device} on the Machines page.`,
  })
}

// The finish step. The observer holds no lock on entry; it takes
// active (the answer's tenant) then pending, one fresh ordered set.
export async function finishAttempt(a: Attempt, answer: unknown): Promise<Finished> {
  const { verified, identity, why } = enrolmentMismatch(a.record.intent, answer)
  const tenant = identity && WORKSPACE_ID.test(identity.tenant) ? identity.tenant : null
  const locks = [pendingLockPath(a.root, a.record.origin, slugOf(a)), ...(tenant ? [activeLockPath(a.root, a.record.origin, tenant)] : [])]
  return withSlotLocks(locks, async () => {
    const where = await attemptState(a)
    if (where.state !== "ours") {
      // Step 0: an earlier observer may have committed this very approval.
      const active = tenant ? activeSlotPath(a.root, a.record.origin, tenant) : null
      const existing = active ? await readConfig(active).catch(() => null) : null
      if (active && existing && verified && identity && existing.vault === a.record.origin && existing.tenant === tenant && existing.device === identity.device && (await sameKeyOnDisk(active, existing.backend, a.record.jwk))) {
        return { config: existing, verified, slot: active, already: true }
      }
      if (where.state === "moved") throw recordGone(a, identity?.device ?? null)
      return superseded(a, where.by, identity)
    }
    // Step 2: the answer must be what this machine asked for.
    if (why !== null || verified === null || tenant === null) return selfRevoke(a, identity, why ?? "it is not a complete workspace enrolment", "workspace_mismatch")
    // Step 3: commit.
    const active = activeSlotPath(a.root, a.record.origin, tenant)
    let existing: Config | null
    try {
      existing = await readConfig(active)
    } catch (error) {
      throw new CliError("already_enrolled", `${active} holds something mehen cannot read (${error instanceof Error ? error.message : String(error)}); the vault has device ${verified.device} active for enrolment ${a.record.id}. Nothing was revoked or deleted.`, {
        command: `mehen workspace forget --slot ${active}`,
        say: `Look at ${active}: retire it with \`mehen workspace forget --slot ${active}\` and run \`mehen wait ${a.record.id}\` again, or revoke ${verified.device} on the Machines page.`,
      })
    }
    if (existing) {
      if (existing.vault === a.record.origin && existing.device === verified.device && (await sameKeyOnDisk(active, existing.backend, a.record.jwk))) {
        await rm(a.slot, { recursive: true, force: true })
        return { config: existing, verified, slot: active, already: true }
      }
      throw alreadyEnrolled(a, existing, verified)
    }
    const config: Config = {
      vault: a.record.origin,
      tenant,
      device: verified.device,
      backend: a.record.backend,
      fingerprint: fingerprintOf(await jwkThumbprint(a.record.jwk as DeviceJwk)),
      name: a.record.name,
      workspaceSlug: verified.workspace.slug,
      workspaceName: verified.workspace.name,
      owner: verified.owner,
    }
    try {
      await writeKeyScope(a.slot, a.record.backend, { vault: a.record.origin, tenant })
      await writeConfig(a.slot, config)
      mkdirPrivate(a.root, dirname(active))
      // The rename is the commit: before it a resumable pending slot, after
      // it an active slot.
      await rename(a.slot, active)
    } catch (error) {
      return selfRevoke(a, identity, `this machine could not record it (${error instanceof Error ? error.message : String(error)})`, "failed")
    }
    await removeEnrolmentRecord(active).catch(() => undefined)
    return { config, verified, slot: active, already: false }
  })
}

// ---- polling and renewal ------------------------------------------------------

export type Polled =
  | { status: "pending"; expiresAt: string | null; hardExpiresAt: string | null }
  | { status: "active"; answer: unknown }
  | { status: "rejected" }
  | { status: "expired"; reason: EnrolExpiredReason }

const EXPIRED_REASONS: readonly string[] = ["hard_cap", "superseded", "discarded", "source", "legacy"]

// A poll or a settled renew refusal, read with the old vault's tolerance:
// a missing hardExpiresAt is null, `expired` without a reason legacy.
function polledOf(a: Attempt, value: unknown): Polled {
  const v = (typeof value === "object" && value !== null ? value : {}) as Record<string, unknown>
  if (v.status === "active") return { status: "active", answer: value }
  if (v.status === "rejected") return { status: "rejected" }
  if (v.status === "expired") return { status: "expired", reason: typeof v.reason === "string" && EXPIRED_REASONS.includes(v.reason) ? (v.reason as EnrolExpiredReason) : "legacy" }
  if (v.status === "pending" || v.status === "pending_owner_acceptance" || v.status === "pending_admission") {
    const time = (field: unknown) => (typeof field === "string" && Number.isFinite(Date.parse(field)) ? field : null)
    return { status: "pending", expiresAt: time(v.expiresAt), hardExpiresAt: time(v.hardExpiresAt) }
  }
  throw new CliError("internal", `The vault returned an unknown status ${JSON.stringify(v.status)} for enrolment ${a.record.id}.`)
}

export async function pollAttempt(a: Attempt, signal?: AbortSignal): Promise<Polled> {
  return polledOf(a, await attemptApi(a).request<unknown>("GET", `/v1/enrol/${encodeURIComponent(a.record.id)}`, undefined, signal ? { signal } : {}))
}

export type Renewed =
  | { kind: "renewed"; expiresAt: string; hardExpiresAt: string | null }
  | { kind: "later"; retryAfter: number }
  | { kind: "settled"; polled: Polled }
  | { kind: "poll" }
  | { kind: "terminal" }

// POST /v1/enrol/:id/renew: the same id, code and
// link with a fresh lease; a 409 with retryAfter means keep waiting; a 409
// carrying the enrolment is the settled answer, exactly as a poll; a 404 is
// terminal; a 409 with neither is an old vault: poll once, then settle.
export async function renewAttempt(a: Attempt, signal?: AbortSignal): Promise<Renewed> {
  try {
    const renewed = await attemptApi(a).request<{ enrolment?: unknown; expiresAt?: unknown; hardExpiresAt?: unknown }>("POST", `/v1/enrol/${encodeURIComponent(a.record.id)}/renew`, undefined, signal ? { signal } : {})
    if (renewed.enrolment !== a.record.id || typeof renewed.expiresAt !== "string" || !Number.isFinite(Date.parse(renewed.expiresAt))) {
      throw new CliError("internal", `The vault's renewal of enrolment ${a.record.id} did not name it or its new expiry.`)
    }
    const hard = typeof renewed.hardExpiresAt === "string" && Number.isFinite(Date.parse(renewed.hardExpiresAt)) ? renewed.hardExpiresAt : null
    return { kind: "renewed", expiresAt: renewed.expiresAt, hardExpiresAt: hard }
  } catch (error) {
    if (!(error instanceof VaultApiError)) throw error
    if (error.status === 404 || error.body.error === "not_found") return { kind: "terminal" }
    if (error.body.error === "conflict") {
      if (error.body.enrolment) return { kind: "settled", polled: polledOf(a, error.body.enrolment) }
      if (typeof error.body.retryAfter === "number") return { kind: "later", retryAfter: error.body.retryAfter }
      return { kind: "poll" }
    }
    throw error
  }
}

export type FollowOptions = {
  // When this observer stops waiting (0 for one look).
  deadline: number
  intervalMs: number
  // False for --no-renew: the attempt is never renewed and ends at its expiry.
  renew: boolean
  signal?: AbortSignal
  onPending?: (a: Attempt, polled: Extract<Polled, { status: "pending" }>) => void
  onRenewed?: (a: Attempt) => void
}

export type Followed = { kind: "finished"; finished: Finished } | { kind: "waiting" }

const RENEW_WITHIN_MS = 5 * 60_000
const SHORT_LEASE_MS = 10 * 60_000

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve()
    const timer = setTimeout(done, ms)
    function done(): void {
      clearTimeout(timer)
      signal?.removeEventListener("abort", done)
      resolve()
    }
    signal?.addEventListener("abort", done, { once: true })
  })
}

function expiredError(a: Attempt, reason: EnrolExpiredReason | null): CliError {
  const why = reason === "superseded" ? " (a newer attempt replaced it)" : reason === "hard_cap" ? " (it reached its hard limit)" : ""
  return new CliError("expired", `The enrolment link for ${a.record.id} expired before anyone accepted it${why}.`, {
    command: enrolAgain(a),
    say: "the link ran out for good; enrol again; the key is kept, so the fingerprint stays the same",
  })
}

function rejectedError(a: Attempt): CliError {
  return new CliError("rejected", `The enrolment ${a.record.id} was rejected in the vault.`, { say: "A human rejected this machine; ask them before enrolling it again." })
}

// A settled attempt leaves the disk only through mutateAttempt: a late
// answer about an attempt that was replaced removes nothing and says so.
async function settleRemoved(a: Attempt, outcome: CliError): Promise<never> {
  const result = await mutateAttempt(a.slot, a.record, () => null)
  if (result === "superseded") {
    const read = await readEnrolmentRecord(a.slot)
    throw replacedError(a, read && "record" in read ? read.record.id : null, null, "unattempted")
  }
  throw outcome
}

// Follows one attempt until it settles or the deadline passes:
// polls never hold a lock; a live lease is renewed when under five minutes
// remain (or under half a lease shorter than ten minutes); after a local
// lapse the terminal state is polled first, so an approval that landed in
// time is finished; a terminal answer removes the record and
// is `expired` (enrol again); a legacy record or one without a hard limit
// is never renewed and ends at its own expiry. Never mints a new attempt.
export async function followAttempt(a: Attempt, options: FollowOptions): Promise<Followed> {
  let renewable = options.renew
  let notBefore = 0
  // The lease this observer last saw issued, to decide when to renew.
  let leaseMs = a.record.renewals === 0 ? Math.max(0, Date.parse(a.record.expiresAt) - Date.parse(a.record.startedAt)) : SHORT_LEASE_MS
  const canRenew = (now: number) => renewable && !a.record.legacy && a.record.hardExpiresAt !== null && Date.parse(a.record.hardExpiresAt) > now
  const endsAt = (now: number) => (canRenew(now) ? Date.parse(a.record.hardExpiresAt as string) : Date.parse(a.record.expiresAt))

  // One renewal: settled, "again" to keep waiting, "repoll" to poll once
  // more at once (an old vault's bare 409), or "terminal".
  const renew = async (): Promise<Followed | "again" | "repoll" | "terminal"> => {
    const result = await renewAttempt(a, options.signal)
    if (result.kind === "renewed") {
      const applied = await mutateAttempt(a.slot, a.record, (r) => ({ ...r, expiresAt: result.expiresAt, hardExpiresAt: result.hardExpiresAt ?? r.hardExpiresAt, renewals: r.renewals + 1 }))
      if (applied === "superseded") {
        const read = await readEnrolmentRecord(a.slot)
        throw replacedError(a, read && "record" in read ? read.record.id : null, null, "unattempted")
      }
      if (applied === "applied") {
        a.record = { ...a.record, expiresAt: result.expiresAt, hardExpiresAt: result.hardExpiresAt ?? a.record.hardExpiresAt, renewals: a.record.renewals + 1 }
        leaseMs = Date.parse(result.expiresAt) - Date.now()
        options.onRenewed?.(a)
      }
      return "again"
    }
    if (result.kind === "later") {
      notBefore = Date.now() + result.retryAfter * 1000
      return "again"
    }
    if (result.kind === "poll") {
      renewable = false
      return "repoll"
    }
    if (result.kind === "terminal") return "terminal"
    const settled = result.polled
    if (settled.status === "active") return { kind: "finished", finished: await finishAttempt(a, settled.answer) }
    if (settled.status === "rejected") return settleRemoved(a, rejectedError(a))
    if (settled.status === "expired") return settleRemoved(a, expiredError(a, settled.reason))
    // A pending answer to a renew is not a renewal: keep waiting.
    return "again"
  }

  for (;;) {
    options.signal?.throwIfAborted()
    const where = await attemptState(a)
    if (where.state === "replaced") throw replacedError(a, where.by, null, "unattempted")
    if (where.state === "moved") {
      // Another observer committed or forgot it: never sign
      // through the old path. The key itself moved with a commit.
      const committed = await committedElsewhere(a)
      if (!committed) throw recordGone(a, null)
      const key = a.key.backend === "software" ? a.key : await loadDeviceKey(committed.dir, a.record.backend, a.env)
      const polled = polledOf(a, await attemptApi(a, key).request<unknown>("GET", `/v1/enrol/${encodeURIComponent(a.record.id)}`, undefined, options.signal ? { signal: options.signal } : {}))
      if (polled.status !== "active") throw recordGone(a, null)
      return { kind: "finished", finished: await finishAttempt({ ...a, key }, polled.answer) }
    }
    let polled: Polled
    try {
      polled = await pollAttempt(a, options.signal)
    } catch (error) {
      // An enclave blob renamed or replaced between the check and the
      // signature: look again, never sign through the old path twice.
      if (a.key.backend !== "software" && error instanceof CliError && error.code === "helper_failed" && (await attemptState(a)).state !== "ours") continue
      // A vault that pruned the attempt and answers 404, as renewAttempt reads it: terminal.
      if (error instanceof VaultApiError && (error.status === 404 || error.body.error === "not_found")) return settleRemoved(a, expiredError(a, null))
      throw error
    }
    if (polled.status === "active") return { kind: "finished", finished: await finishAttempt(a, polled.answer) }
    if (polled.status === "rejected") return settleRemoved(a, rejectedError(a))
    const now = Date.now()
    let step: Followed | "again" | "repoll" | "terminal" | null = null
    if (polled.status === "expired") {
      if (canRenew(now) && now < notBefore) step = "again"
      else step = canRenew(now) ? await renew() : "terminal"
      if (step === "terminal") return settleRemoved(a, expiredError(a, polled.reason))
    } else {
      // A lease another observer renewed shows here first; the record on
      // disk was updated by that observer.
      if (polled.expiresAt && Date.parse(polled.expiresAt) > Date.parse(a.record.expiresAt)) a.record = { ...a.record, expiresAt: polled.expiresAt, ...(polled.hardExpiresAt ? { hardExpiresAt: polled.hardExpiresAt } : {}) }
      const remaining = Date.parse(a.record.expiresAt) - now
      const threshold = leaseMs >= SHORT_LEASE_MS ? RENEW_WITHIN_MS : leaseMs / 2
      if (remaining <= 0 && !canRenew(now)) {
        if (now >= endsAt(now)) return settleRemoved(a, expiredError(a, null))
      } else if (canRenew(now) && (remaining <= 0 || remaining < threshold) && now >= notBefore) {
        step = await renew()
        if (step === "terminal") return settleRemoved(a, expiredError(a, null))
      }
      if (step === null || step === "again") options.onPending?.(a, polled)
    }
    if (step === "repoll") continue
    if (step !== null && step !== "again") return step
    if (Date.now() >= options.deadline) return { kind: "waiting" }
    const pause = Math.min(options.intervalMs, Math.max(options.deadline - Date.now(), 0))
    if (pause > 0) await sleep(pause, options.signal)
    options.signal?.throwIfAborted()
  }
}

// Opens an attempt from its pending slot: the record, which must still be
// the pending record of `id`, and the key, which must still be the record's.
export async function openAttempt(env: Env, root: string, slot: string, id: string, session: string | null): Promise<Attempt> {
  const read = await readEnrolmentRecord(slot)
  const record = read && "record" in read ? read.record : null
  if (!record || record.state !== "pending" || record.id !== id || record.code === null || record.url === null || record.expiresAt === null) {
    throw new CliError("not_found", `No open enrolment ${id} is recorded on this machine${record ? "" : ` in ${slot}`}.`, {
      command: "mehen enrol --workspace <slug>",
      say: "Only the machine that started an enrolment can wait on it; run `mehen enrol --workspace <slug>` to start again.",
    })
  }
  if (!(await sameKeyOnDisk(slot, record.backend, record.jwk))) {
    throw new CliError("failed", `The key in ${slot} is not the one enrolment ${id} was started with, so it cannot be finished here.`, {
      command: `mehen enrol --workspace ${record.intent.workspace}`,
      say: `Run \`mehen enrol --workspace ${record.intent.workspace}\` again; it resumes or replaces what this machine holds.`,
    })
  }
  const key = await loadDeviceKey(slot, record.backend, env)
  return { root, slot, record: record as PendingRecord, key, env, session }
}

