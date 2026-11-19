// Opens the vault as this enrolled machine: the selected context, its device
// key and an HTTP client. Before any signature the active origin and key
// scope are checked across config, key scope, manifest, flags and
// environment (design 15.6): a disagreement is a local refusal, never a
// request to the wrong vault or workspace.

import type { DeviceJwk } from "@mehen/protocol/proof"
import { type Ask, requestedBy } from "./ask.ts"
import { type Attempt, type Finished, enrolmentMismatch, openAttempt } from "./commands/activate.ts"
import { type Config, type Env, canonicalOrigin, configWorkspace, readConfig, resolveVaultUrl, workspaceLabel } from "./config.ts"
import { type KeyLoadOptions, loadDeviceKey, loadSigningKey, readKeyScope } from "./device-key.ts"
import { readEnrolmentRecord, recordAsk, recordFromLegacyEntry, writeEnrolmentRecord } from "./enrolment-record.ts"
import { CliError, usageError } from "./errors.ts"
import { HttpVaultApi } from "./http-client.ts"
import { rootAboveSlot } from "./home.ts"
import { type LedgerScope, ledgerOrigins, readLegacyEnrolments, removeLedgerEntries } from "./ledger.ts"
import { manifestWorkspace } from "./run/manifest.ts"
import { slotLockPath, withSlotLocks } from "./slot-lock.ts"
import { type SelectedContext, type SelectionOptions, assertVaultUrlAgrees, selectSlot } from "./slots.ts"
import { type VaultApi, VaultApiError } from "./vault-api.ts"
import { isCompiledBinary } from "./version.ts"

// `ledger` is the identity every ledger read and write of this session is
// scoped to; `context` is the own-call provenance an ask carries.
// A context named by a caller that already selected or listed it; `known` is
// only carried when selection counted the machine's contexts.
export type NamedContext = Pick<SelectedContext, "dir" | "reason"> & { config: Config; known?: number }

// `signedWith` is the public half of the key this session signs with, as
// loaded (null when it cannot be known): what a write after an answer must
// still find in the slot.
export type VaultSession = { api: VaultApi; config: Config; vaultUrl: string; configDir: string; selection: NamedContext; ledger: LedgerScope; context: SessionContext; signedWith?: DeviceJwk | null }

export type SessionContext = { origin: string; workspace: { id: string; slug: string; name: string } | null; device: string | null }

// A pending enrolment this machine started, reopened from its pending
// slot's enrolment record: the same key signs the polls (ten "enrol", dev =
// the enrolment id), so `mehen wait enr_...` and vault_wait can follow and
// finish what `mehen enrol` began, from any process.
export type EnrolmentSession = { attempt: Attempt; ask: Ask; vaultUrl: string; configDir: string }

export const ENROL_TENANT = "enrol"

const SESSION_LABEL = /^[A-Za-z0-9_.:-]{1,120}$/

// MEHEN_SESSION labels the agent session in proofs and audit; never a secret.
export function sessionLabel(env: Env): string | null {
  const label = env.MEHEN_SESSION
  if (!label) return null
  if (!SESSION_LABEL.test(label)) throw usageError("MEHEN_SESSION must be 1 to 120 characters of letters, digits, dot, colon, underscore or dash.")
  return label
}

export function pollIntervalMs(env: Env): number {
  const value = Number(env.MEHEN_POLL_INTERVAL_MS)
  return Number.isFinite(value) && value >= 0 && env.MEHEN_POLL_INTERVAL_MS ? value : 2000
}

function shellWord(path: string): string {
  return /^[\w./-]+$/.test(path) ? path : `'${path.replaceAll("'", "'\\''")}'`
}

// The enrol step names this binary by its absolute path: the agent's shell
// may not have it on PATH, and an MCP client with no shell hands the
// command to a human. A run from source is Bun itself, so it names mehen.
export function notEnrolled(vaultUrl?: string, self: string | null = isCompiledBinary() ? process.execPath : null): CliError {
  const command = `${self ? shellWord(self) : "mehen"} enrol --workspace <slug> --json`
  return new CliError("unauthenticated", `This machine is not enrolled with the vault${vaultUrl ? ` at ${vaultUrl}` : ""} yet.`, {
    command,
    say: `Run \`${command}\` on this machine (the slug is on the workspace's Connect an agent page) and accept it in the browser with your passkey. If you cannot run commands, ask the human to run this in a terminal and open the link it prints.`,
  })
}

// The ledger scope while enrolling: this origin, no workspace or device
// yet; the slug is the enrolment's intent, under which its link may be.
export function enrolLedgerScope(vaultUrl: string, workspaceSlug: string | null = null): LedgerScope {
  return { vaultUrl, workspace: null, device: null, workspaceSlug }
}

export type OpenOptions = SelectionOptions & {
  // Where to look for a manifest; process.cwd() when absent. `manifest`
  // in SelectionOptions wins when given.
  cwd?: string
  // An already bound context (the MCP server's): no selection runs at all,
  // and only this directory is read (design 15.7).
  bound?: { dir: string; config: Config | null }
  // An observing command (status, doctor): the key is loaded without
  // preparing anything on disk (KeyLoadOptions).
  observe?: boolean
}

function selectionOptions(options: OpenOptions): SelectionOptions {
  const manifest = options.manifest !== undefined ? options.manifest : manifestWorkspace(options.cwd ?? process.cwd())
  return { manifest, ...(options.waitId !== undefined ? { waitId: options.waitId } : {}), ...(options.files ? { files: options.files } : {}) }
}

// A pending enrolment can only be resumed from a directory that holds no
// enrolment: the directory is read now, never trusted from a snapshot, so
// an enrolment that landed meanwhile (another attempt in the same
// directory) refuses rather than being polled and overwritten.
export function alreadyEnrolled(dir: string, config: Config, enrolment: string): CliError {
  return new CliError("workspace_mismatch", `${dir} is already enrolled in ${workspaceLabel(config)} as ${config.device}; enrolment ${enrolment} cannot be finished there.`, {
    say: "A context serves one workspace. Resume the enrolment from the directory it was started in, or start it again elsewhere.",
  })
}

// The one exception is the finish step's own half-done commit: a pending
// slot whose record is still this attempt and whose config.json the finish
// step wrote just before the rename that a crash interrupted.
async function enrolmentDirectory(selected: { dir: string }, enrolment: string): Promise<string> {
  const current = await readConfig(selected.dir)
  if (current) {
    const read = await readEnrolmentRecord(selected.dir)
    const ours = read && "record" in read && read.record.state === "pending" && read.record.id === enrolment && read.record.origin === current.vault
    if (!ours) throw alreadyEnrolled(selected.dir, current, enrolment)
  }
  return selected.dir
}

function noOpenEnrolment(enrolment: string, vaultUrl: string): CliError {
  return new CliError("not_found", `No open enrolment ${enrolment} is recorded on this machine for ${vaultUrl}.`, {
    command: "mehen enrol --workspace <slug>",
    say: "Only the machine that started an enrolment can wait on it; run `mehen enrol --workspace <slug>` to start again.",
  })
}

// A pending slot that still holds the legacy enrol ledger entry an older
// mehen wrote (no enrolment.json): its newest entry for `enrolment` becomes
// the slot's record (legacy, never renewed, never claimed), and leaves the
// ledger, under the pending lock, so every later write is the record's.
async function adoptLegacyEnrolment(slot: string, enrolment: string): Promise<void> {
  const lock = slotLockPath(slot)
  if (lock === null) return
  await withSlotLocks([lock], async () => {
    if ((await readEnrolmentRecord(slot)) !== null) return
    for (const origin of await ledgerOrigins(slot)) {
      const entry = (await readLegacyEnrolments(slot, origin)).filter((e) => e.ask.id === enrolment).at(-1)
      if (!entry) continue
      await writeEnrolmentRecord(slot, recordFromLegacyEntry(entry))
      await removeLedgerEntries(slot, enrolLedgerScope(origin), (e) => e.ask.kind === "enrol" && e.ask.id === enrolment)
      return
    }
  })
}

// The enrolment `enrolment` in the slot selection finds for it (rule 4: the
// one slot in the allowed set whose record holds the id), or in an MCP
// server's bound directory and nowhere else. A directory that holds an
// enrolment already refuses: it is never polled or overwritten.
export async function openEnrolmentSession(env: Env, enrolment: string, options: OpenOptions = {}): Promise<EnrolmentSession> {
  const selected = options.bound ?? (await selectSlot(env, selectionOptions(options)))
  const dir = await enrolmentDirectory(selected, enrolment)
  const above = rootAboveSlot(dir)
  if (!above || above.kind !== "pending") throw noOpenEnrolment(enrolment, resolveVaultUrl(env, null))
  await adoptLegacyEnrolment(dir, enrolment)
  const read = await readEnrolmentRecord(dir)
  const record = read && "record" in read ? read.record : null
  if (!record || record.id !== enrolment) throw noOpenEnrolment(enrolment, record?.origin ?? resolveVaultUrl(env, null))
  if (env.MEHEN_VAULT_URL && canonicalOrigin(env.MEHEN_VAULT_URL) !== record.origin) {
    throw new CliError("workspace_mismatch", `MEHEN_VAULT_URL is ${canonicalOrigin(env.MEHEN_VAULT_URL)}, but enrolment ${enrolment} was started with ${record.origin}.`, {
      say: `Unset MEHEN_VAULT_URL, or set it to ${record.origin}; an enrolment is only ever finished with the vault it was started with.`,
    })
  }
  const attempt = await openAttempt(env, above.root, dir, enrolment, sessionLabel(env))
  const ask = await recordAsk(attempt.record, requestedBy(env).device)
  if (!ask) throw noOpenEnrolment(enrolment, record.origin)
  return { attempt, ask, vaultUrl: record.origin, configDir: dir }
}

// A wait for an attempt another observer already committed (// reached by a wait that starts after the commit): selection found no slot
// recording the id and fell back to the one active slot in the allowed set
// (the wait id rule), whose key is the attempt's key when
// this is that enrolment. The vault is asked with that key (ten "enrol",
// dev = the id); an active answer naming this slot's device is success, with
// nothing written. Any other answer, or a key the vault does not accept for
// the id, is null: the caller says not_found. The origin and key-scope
// guards of every active session run first: a key whose recorded
// scope names another vault or workspace is the local workspace_mismatch,
// before the key is loaded or anything is signed.
export async function committedEnrolment(env: Env, enrolment: string, selected: { dir: string; config: Config | null; reason: string }): Promise<Finished | null> {
  const config = selected.config
  if (!config || selected.reason !== "only") return null
  assertVaultUrlAgrees(env, config)
  await assertKeyScopeAgrees(selected.dir, config)
  const key = await loadDeviceKey(selected.dir, config.backend, env)
  const session = sessionLabel(env)
  const api = new HttpVaultApi({ vaultUrl: config.vault, tenant: ENROL_TENANT, signer: key.signer(enrolment), ...(session ? { session } : {}), context: { origin: config.vault, workspace: null, device: null } })
  let answer: unknown
  try {
    answer = await api.request<unknown>("GET", `/v1/enrol/${encodeURIComponent(enrolment)}`)
  } catch (error) {
    if (error instanceof VaultApiError) return null
    throw error
  }
  const intent = { workspace: config.workspaceSlug ?? "", team: config.owner?.kind === "team" ? config.owner.name : null }
  const { verified } = enrolmentMismatch(intent, answer)
  if (!verified || verified.device !== config.device || verified.tenant !== config.tenant) return null
  return { config, verified, slot: selected.dir, already: true }
}

// The key scope recorded beside the key must name this context's origin and
// workspace (design 9.5): a key is never reused across either.
export async function assertKeyScopeAgrees(dir: string, config: Config): Promise<void> {
  const scope = await readKeyScope(dir, config.backend)
  if (!scope) return
  if (scope.vault !== config.vault || (scope.tenant !== null && scope.tenant !== config.tenant)) {
    throw new CliError("workspace_mismatch", `The device key in ${dir} was made for ${scope.tenant ? `workspace ${scope.tenant} at ` : ""}${scope.vault}, but this context is enrolled in ${config.tenant} at ${config.vault}.`, {
      command: "mehen enrol --workspace <slug> --fresh-key",
      say: "A key is never reused across vaults or workspaces. Revoke this context and enrol again with --fresh-key, or restore the key and scope files that belong to it.",
    })
  }
}

export function sessionContext(config: Config): SessionContext {
  return { origin: config.vault, workspace: configWorkspace(config), device: config.device }
}

// A session on one named context, already selected or listed: the origin
// and key-scope checks still run before the key signs anything.
export async function openContext(env: Env, selected: NamedContext, options: KeyLoadOptions = {}): Promise<VaultSession> {
  const { dir, config } = selected
  assertVaultUrlAgrees(env, config)
  const vaultUrl = config.vault
  await assertKeyScopeAgrees(dir, config)
  const { key, jwk: signedWith } = await loadSigningKey(dir, config.backend, env, options)
  const session = sessionLabel(env)
  const context = sessionContext(config)
  const api = new HttpVaultApi({
    vaultUrl,
    tenant: config.tenant,
    signer: key.signer(config.device),
    ...(session ? { session } : {}),
    context,
  })
  return { api, config, vaultUrl, configDir: dir, selection: selected, ledger: { vaultUrl, workspace: config.tenant, device: config.device, workspaceSlug: config.workspaceSlug ?? null }, context, signedWith }
}

export async function openSession(env: Env, options: OpenOptions = {}): Promise<VaultSession> {
  const selected = options.bound ? { ...options.bound, reason: "workspace" as const } : await selectSlot(env, selectionOptions(options))
  if (!selected.config) throw notEnrolled(resolveVaultUrl(env, null))
  return openContext(env, { ...selected, config: selected.config }, options.observe ? { observe: true } : {})
}

// The enrolled config of the context the environment selects, without
// opening a session: for the not-enrolled branches of status and doctor.
export async function selectedConfig(env: Env, options: OpenOptions = {}): Promise<{ dir: string; config: Config | null }> {
  const selected = await selectSlot(env, selectionOptions(options))
  return { dir: selected.dir, config: selected.config }
}
