// mehen doctor: one call that tells an agent whether this machine can use the
// vault, and if not, the one thing to do next. Every check runs locally or
// against the vault's own endpoints (GET /healthz, unauthenticated, and
// GET /v1/me, signed). Nothing is created, written or deleted and no secret
// is read.
//
// `doctorAll` is `mehen doctor`: the machine checks
// once, each origin's reachability and clock once, the session label, then
// every slot in the allowed set, the strays under the root and an
// unfinished migration journal. It never migrates: on a legacy or stuck
// root it reports and skips the slots. `doctor` is the MCP server's one
// bound context, in the shape vault_doctor publishes until it spans too.

import { existsSync } from "node:fs"
import { lstat, readdir, readFile } from "node:fs/promises"
import { homedir, userInfo } from "node:os"
import { basename, join, resolve } from "node:path"
import { EXIT, type ExitCode, type Me, type NextStep } from "@mehen/protocol/api"
import { PROOF_MAX_SKEW_SECONDS } from "@mehen/protocol/proof"
import type { WorkspaceRef } from "@mehen/protocol/workspace"
import type { Command } from "../command.ts"
import { type Backend, type Env, configWorkspace, resolveVaultUrl, workspaceLabel } from "../config.ts"
import { manifestWorkspace } from "../run/manifest.ts"
import { loadDeviceKey } from "../device-key.ts"
import { type CliError, type CliErrorCode, exitCodeFor, toCliError } from "../errors.ts"
import { PENDING_DIR, WORKSPACES_DIR, managedHost, resolveHome } from "../home.ts"
import { HttpVaultApi } from "../http-client.ts"
import { type CliState, type LockHolder, cliState, installation, lockGuardPresent, lockHolder, onPathCheck, readInstallState, selfExecutable, updateDoctorCheck } from "../install-state.ts"
import { isListedAsk, readLedger } from "../ledger.ts"
import { type KeyringHost, LOCAL_VAULT_RECORD, defaultVault, keyringAdvice, keyringHost } from "../local-vault.ts"
import { type MigrationJournal, type MigrationStep, ROOT_OWN, assertSafeRoot, legacyLayout, migrationState, readMigrationJournal } from "../migration.ts"
import { printJson, printLine } from "../output.ts"
import { assertKeyScopeAgrees, notEnrolled, sessionLabel } from "../session.ts"
import { type FoundActive, type FoundCorrupt, type FoundPending, type FoundSlot, type Slot, allowedSlots, assertVaultUrlAgrees, endedNext, selectSlot, workspaceSelector } from "../slots.ts"
import { type Segment, colourEnabled, segments, styler } from "../tty.ts"
import { type SkillCopy, skillCopies } from "../setup/skills.ts"
import { VERSION } from "../version.ts"

export type DoctorCheckName = "home" | "migration" | "vault_url" | "on_path" | "update" | "skill" | "reachable" | "clock" | "session" | "enrolled" | "key" | "identity" | "frozen" | "pending" | "local_vault"
export type DoctorStatus = "ok" | "warn" | "fail" | "skipped"

export type DoctorCheck = {
  check: DoctorCheckName
  status: DoctorStatus
  detail: string
  // The error code a command would fail with, for a failed check.
  error?: CliErrorCode
  next?: NextStep
}

// The config root's migration, read without the root lock
// and without migrating; null when the root itself cannot be resolved.
export type DoctorMigration = { state: "none" | "journal" | "stuck" | "corrupt"; root: string; steps?: DoctorJournalStep[] }

// What doctor publishes of an unfinished migration journal: an
// allowlisted projection, built field by field from the validated journal,
// never the object read from disk. Every recovery fact stays (each step's
// id, kind, state, source, target and file names, a slot's identity, a
// pending step's attempt id and intent); an enrolment record's code, link
// and key and anything the journal carries beyond these fields are left
// out. The journal on disk is never changed.
export type DoctorJournalStep =
  | { id: number; kind: "slot"; source: string; move: "rename" | "files"; files: string[]; identity: { origin: string; tenant: string; device: string; backend: Backend }; target: string; state: "planned" | "moving" | "done" }
  | { id: number; kind: "pending"; source: string; files: string[]; enrolment: { id: string | null; origin: string; intent: { workspace: string; team: string | null } }; target: string; state: "planned" | "moving" | "done" }
  | { id: number; kind: "delete"; source: string; state: "planned" | "done" }
  | { id: number; kind: "leave"; source: string; detail: string }
// `omitted` counts the steps past DOCTOR_JOURNAL_STEPS that are not shown.
export type DoctorJournal = { v: 1; from: "contexts-v1"; startedAt: string; pid: number; steps: DoctorJournalStep[]; omitted: number }

export const DOCTOR_JOURNAL_STEPS = 256
const DETAIL_CHARS = 300

function journalStep(step: MigrationStep): DoctorJournalStep {
  switch (step.kind) {
    case "slot":
      return { id: step.id, kind: "slot", source: step.source, move: step.move, files: [...step.files], identity: { origin: step.identity.origin, tenant: step.identity.tenant, device: step.identity.device, backend: step.identity.backend }, target: step.target, state: step.state }
    case "pending":
      return { id: step.id, kind: "pending", source: step.source, files: [...step.files], enrolment: { id: step.record.id, origin: step.record.origin, intent: { workspace: step.record.intent.workspace, team: step.record.intent.team } }, target: step.target, state: step.state }
    case "delete":
      return { id: step.id, kind: "delete", source: step.source, state: step.state }
    case "leave":
      return { id: step.id, kind: "leave", source: step.source, detail: step.detail.slice(0, DETAIL_CHARS) }
  }
}

export function doctorJournal(journal: MigrationJournal): DoctorJournal {
  return { v: 1, from: "contexts-v1", startedAt: journal.startedAt.slice(0, 64), pid: journal.pid, steps: journal.steps.slice(0, DOCTOR_JOURNAL_STEPS).map(journalStep), omitted: Math.max(0, journal.steps.length - DOCTOR_JOURNAL_STEPS) }
}

// Past this the clock is worth a warning; past PROOF_MAX_SKEW_SECONDS every
// signed request is refused (proof_invalid).
export const CLOCK_WARN_SECONDS = 30
const REQUEST_TIMEOUT_MS = 10_000

function fromError(check: DoctorCheckName, error: CliError): DoctorCheck {
  return { check, status: "fail", detail: error.message, error: error.code, ...(error.next ? { next: error.next } : {}) }
}

function skipped(check: DoctorCheckName, why: string): DoctorCheck {
  return { check, status: "skipped", detail: why }
}

// The local vault `mehen up` set up (<root>/local-vault.json): what keeps its
// root key, as the vault itself reports it at /local/v1/state, believed only
// when it answers with the instance token in its own data directory. Read
// only, and only on loopback; null when this machine runs no such vault.
const LOOPBACK_ORIGIN = /^http:\/\/localhost:\d{1,5}$/

const CUSTODY_MEANS: Record<string, { status: DoctorStatus; detail: (origin: string) => string }> = {
  "secure-enclave": {
    status: "ok",
    detail: (origin) => `The local vault at ${origin} keeps its key sealed by this Mac's Secure Enclave: a copy of its data directory opens on no other machine, though a program running as you can still have the enclave open it.`,
  },
  keyring: {
    status: "ok",
    detail: (origin) => `The local vault at ${origin} keeps its key in your login keyring, encrypted and out of its data directory, though any program in your session can read it while the keyring is unlocked.`,
  },
  file: {
    status: "warn",
    detail: (origin) =>
      `The local vault at ${origin} keeps its key in keys.json, a file only you can read: any program running as you, or a copy of the data directory, can open the vault. A Mac with the Secure Enclave helper (a released mehen), a Linux desktop with a login keyring and secret-tool, or a vault on another machine keeps it better.`,
  },
}

export async function localVaultCheck(root: string, fetcher: (request: Request) => Promise<Response>, host: KeyringHost | null = null): Promise<DoctorCheck | null> {
  const path = join(root, LOCAL_VAULT_RECORD)
  if (!existsSync(path)) return null
  let record: { origin: string; data: string; service: string | null }
  try {
    const value = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>
    if (typeof value.origin !== "string" || typeof value.data !== "string") throw new Error("missing origin or data")
    record = { origin: value.origin, data: value.data, service: typeof value.service === "string" ? value.service : null }
  } catch (error) {
    return { check: "local_vault", status: "warn", detail: `${path} cannot be read (${error instanceof Error ? error.message : String(error)}).`, next: { command: "mehen up", say: "Run `mehen up` to set the local vault up again; its data stays." } }
  }
  if (!LOOPBACK_ORIGIN.test(record.origin)) return skipped("local_vault", `${path} names ${record.origin}, which is not this machine's loopback, so it was not asked.`)
  let state: Record<string, unknown>
  try {
    const response = await fetcher(new Request(`${record.origin}/local/v1/state`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) }))
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    state = (await response.json()) as Record<string, unknown>
  } catch (error) {
    return { check: "local_vault", status: "warn", detail: `The local vault at ${record.origin} did not answer (${error instanceof Error ? error.message : String(error)}).`, next: { command: "mehen up", say: "Run `mehen up` to start the local vault again." } }
  }
  const token = await readFile(join(record.data, "instance"), "utf8").then((text) => text.trim(), () => null)
  if (token === null || state.instance !== token) return { check: "local_vault", status: "warn", detail: `What answers at ${record.origin} is not the vault in ${record.data}, so what it says about its key is not believed.` }
  const means = typeof state.custody === "string" && Object.hasOwn(CUSTODY_MEANS, state.custody) ? CUSTODY_MEANS[state.custody] : undefined
  if (!means) return skipped("local_vault", `The local vault at ${record.origin} does not say what keeps its key; it is older than this mehen.`)
  const advice = state.custody === "file" && host !== null ? keyringAdvice(host, record.service) : null
  return { check: "local_vault", status: means.status, detail: advice === null ? means.detail(record.origin) : `${means.detail(record.origin)} ${advice}` }
}

// The vault's clock from its Date header, against this machine's at the
// midpoint of the request, to the second.
function clockCheck(dateHeader: string | null, sentAt: number, receivedAt: number): DoctorCheck {
  const vaultTime = dateHeader ? Date.parse(dateHeader) : Number.NaN
  if (!Number.isFinite(vaultTime)) return skipped("clock", "The vault's answer carried no Date header to compare with.")
  const skew = Math.round(((sentAt + receivedAt) / 2 - vaultTime) / 1000)
  const off = Math.abs(skew)
  const words = off <= 1 ? "within a second of the vault" : `${off} s ${skew > 0 ? "ahead of" : "behind"} the vault`
  if (off > PROOF_MAX_SKEW_SECONDS) {
    return {
      check: "clock",
      status: "fail",
      detail: `This machine's clock is ${words}; the vault refuses proofs more than ${PROOF_MAX_SKEW_SECONDS} s off.`,
      error: "proof_invalid",
      next: { say: "Set this machine's clock (turn on network time), then run `mehen doctor` again." },
    }
  }
  if (off > CLOCK_WARN_SECONDS) {
    return { check: "clock", status: "warn", detail: `This machine's clock is ${words}.`, next: { say: "Turn on network time on this machine before the clock drifts past 60 s." } }
  }
  return { check: "clock", status: "ok", detail: `This machine's clock is ${words}.` }
}

function withTimeout(): AbortSignal {
  return AbortSignal.timeout(REQUEST_TIMEOUT_MS)
}

function unreachable(vaultUrl: string, detail: string): DoctorCheck {
  return {
    check: "reachable",
    status: "fail",
    detail: `Could not reach the vault at ${vaultUrl}: ${detail}`,
    error: "network",
    next: { say: "Check the network connection and the vault URL (MEHEN_VAULT_URL), then run `mehen doctor` again." },
  }
}

// The migration row: ok on a layout-2 root, warn on a legacy root the next
// command migrates, fail naming the step when a journal cannot continue.
// `ready` is false when slot discovery would read a root that is not
// layout 2 yet, so the per-slot checks are skipped rather than misread.
// `journal` is the projection of a journal that could be read, from a root
// that passed the safety check; nothing under a refused root is read.
async function migrationCheck(env: Env): Promise<{ check: DoctorCheck | null; migration: DoctorMigration | null; ready: boolean; journal: DoctorJournal | null }> {
  let root: string
  try {
    root = resolveHome(env).root
  } catch {
    return { check: null, migration: null, ready: true, journal: null }
  }
  // An unsafe root or ancestor is reported by name before anything under it is read.
  try {
    assertSafeRoot(root)
  } catch (error) {
    return { check: fromError("migration", toCliError(error)), migration: null, ready: false, journal: null }
  }
  const state = await migrationState(root)
  const read = state.state === "none" || state.state === "corrupt" ? null : await readMigrationJournal(root).catch(() => null)
  const journal = read && "journal" in read ? doctorJournal(read.journal) : null
  const migration: DoctorMigration = { state: state.state, root, ...(journal ? { steps: journal.steps } : {}) }
  const next = (say: string): NextStep => ({ say })
  if (state.state === "stuck" || state.state === "corrupt") {
    const what = state.state === "corrupt" ? `the journal ${root}/migration.json cannot be read (${state.stuck?.detail})` : `step ${state.stuck?.step} cannot continue: ${state.stuck?.detail}`
    return { check: { check: "migration", status: "fail", detail: `The migration of ${root} is unfinished and ${what}. Nothing was deleted.`, error: "failed", next: next("Put the named paths back where the journal (`migration` in this report) records them, then run any mehen command to resume; ask for help if you are not sure.") }, migration, ready: false, journal }
  }
  if (state.state === "journal") return { check: { check: "migration", status: "warn", detail: `The migration of ${root} is unfinished; the next command resumes it.`, next: { command: "mehen workspace list", say: "Run `mehen workspace list` (nothing is sent to a vault) to finish the migration; status and doctor only read." } }, migration, ready: false, journal }
  if (await legacyLayout(root)) return { check: { check: "migration", status: "warn", detail: `${root} is not migrated yet; the next command migrates it.`, next: { command: "mehen workspace list", say: "Run `mehen workspace list` (nothing is sent to a vault) to migrate the config root; status and doctor only read." } }, migration, ready: false, journal }
  return { check: { check: "migration", status: "ok", detail: state.layout === 2 ? `${root} uses the workspaces layout.` : existsSync(root) ? `${root} holds nothing to migrate.` : `${root} does not exist yet; the first \`mehen enrol\` creates it.` }, migration, ready: true, journal }
}

// One row per skill folder (~/.claude and ~/.agents): mehen's copy current
// or stale, a symlinked or foreign copy against this build's text, or
// none where an installed agent reads the folder.
function skillCheck(copy: SkillCopy): DoctorCheck {
  const { path } = copy
  switch (copy.state) {
    case "current":
      return { check: "skill", status: "ok", detail: `${path}: mehen ${VERSION}'s skill${copy.version === null ? " (unstamped; mehen setup stamps it)" : ""}.` }
    case "stale":
      return { check: "skill", status: "warn", detail: `${path}: mehen's skill from ${copy.version ?? "an earlier release"}; this CLI is ${VERSION}.`, next: { command: "mehen setup --json", say: `Run \`mehen setup --json\` to refresh the skill at ${path}, then restart the agent so it loads the new text.` } }
    case "external": {
      const what = copy.link ? `a symlink to ${copy.link}` : "a copy mehen does not manage"
      if (copy.same) return { check: "skill", status: "ok", detail: `${path}: ${what}, the same text as mehen ${VERSION}'s skill.` }
      return { check: "skill", status: "warn", detail: `${path}: ${what}, different from mehen ${VERSION}'s skill.`, next: { say: `The skill at ${path}${copy.link ? ` (a symlink to ${copy.link})` : ""} is not managed by mehen and differs from mehen ${VERSION}'s skill; its owner should refresh ${copy.link ?? "it"}.` } }
    }
    case "missing":
      if (copy.readers.length === 0) return { check: "skill", status: "ok", detail: `${path}: none, and no agent found here reads this folder.` }
      return { check: "skill", status: "warn", detail: `${path}: none, but ${copy.readers.join(", ")} ${copy.readers.length === 1 ? "reads" : "read"} this folder.`, next: { command: "mehen setup --json", say: `Run \`mehen setup --json\` to add mehen's skill for ${copy.readers.join(", ")}.` } }
    case "unreadable":
      return { check: "skill", status: "warn", detail: `${path}: cannot be read (${copy.reason}).`, next: { say: `Check ${path} and its folder: mehen cannot read the skill there.` } }
  }
}

// ---- mehen doctor across the allowed set -----------

export type DoctorWorkspace = { slot: string; state: Slot["state"]; workspace: WorkspaceRef | null; checks: DoctorCheck[] }
export type DoctorOrigin = { origin: string; checks: DoctorCheck[] }
export type DoctorStray = { path: string; detail: string }
// `cli` is the same CliState as StatusAll.cli; `migration` is the
// projection of the unfinished journal when one exists (DoctorJournal).
export type DoctorReport = {
  ok: boolean
  cli: CliState
  machine: DoctorCheck[]
  origins: DoctorOrigin[]
  session: DoctorCheck
  workspaces: DoctorWorkspace[]
  strays: DoctorStray[]
  migration: DoctorJournal | null
  // The first failed check's next step, else the first warning's; null when all is well.
  next: NextStep | null
  // The exit code mehen doctor exits with: 0, or the first failure's.
  exitCode: ExitCode
}

// `span` is the MCP server's own view (vault_doctor): the slots it may use,
// and its latch check for an active slot, run before that slot's key is
// read. A refusal is the slot's `enrolled` check and nothing is signed for
// it; the server, not the environment, has already chosen what it spans.
export type DoctorSpan = { slots: FoundSlot[]; refusal: CliError | null; guard(slot: FoundActive): Promise<CliError | null> }
export type DoctorAllOptions = { fetch?: (request: Request) => Promise<Response>; now?: () => number; cwd?: string; span?: DoctorSpan; keyring?: KeyringHost }

const STRAY_DETAIL = "not a slot; mehen does not read or delete it; remove it yourself if you know what it is"
const UNREAD_DETAIL = "not a directory private to this user, so mehen does not read it as a slot and does not delete it; fix its owner and mode (chmod 700) or remove it yourself if you know what it is"

async function privateDirectory(path: string, uid: number): Promise<boolean> {
  try {
    const info = await lstat(path)
    return !info.isSymbolicLink() && info.isDirectory() && info.uid === uid && (info.mode & 0o077) === 0
  } catch {
    return false
  }
}

async function names(dir: string): Promise<string[]> {
  try {
    return (await readdir(dir)).sort()
  } catch {
    return []
  }
}

// What sits under the root that is not layout 2's (a hand-made
// `revoked-*` directory, an unknown file), and what under workspaces/ and
// pending/ discovery passes over because it is not a private directory.
// Named, never deleted.
async function strayEntries(root: string): Promise<DoctorStray[]> {
  const uid = userInfo().uid
  const strays: DoctorStray[] = []
  for (const name of await names(root)) if (!ROOT_OWN.has(name)) strays.push({ path: join(root, name), detail: STRAY_DETAIL })
  for (const kind of [WORKSPACES_DIR, PENDING_DIR]) {
    const base = join(root, kind)
    if ((await names(root)).includes(kind) && !(await privateDirectory(base, uid))) {
      strays.push({ path: base, detail: UNREAD_DETAIL })
      continue
    }
    for (const origin of await names(base)) {
      const path = join(base, origin)
      if (!(await privateDirectory(path, uid))) {
        strays.push({ path, detail: UNREAD_DETAIL })
        continue
      }
      for (const name of await names(path)) if (!(await privateDirectory(join(path, name), uid))) strays.push({ path: join(path, name), detail: UNREAD_DETAIL })
    }
  }
  return strays
}

// GET /healthz on one origin: reachable, and the clock against its Date.
async function probeOrigin(origin: string, fetcher: (request: Request) => Promise<Response>, now: () => number): Promise<{ checks: DoctorCheck[]; reachable: boolean }> {
  const sentAt = now()
  try {
    const response = await fetcher(new Request(`${origin}/healthz`, { redirect: "manual", signal: withTimeout() }))
    const receivedAt = now()
    await response.body?.cancel()
    const reachable = response.status === 200
    return { reachable, checks: [reachable ? { check: "reachable", status: "ok", detail: `${origin} answers (${Math.max(0, receivedAt - sentAt)} ms).` } : unreachable(origin, `GET /healthz answered HTTP ${response.status}`), clockCheck(response.headers.get("date"), sentAt, receivedAt)] }
  } catch (error) {
    return { reachable: false, checks: [unreachable(origin, error instanceof Error ? error.message : String(error)), skipped("clock", "The vault did not answer.")] }
  }
}

// One active slot's local checks: the origin agrees with MEHEN_VAULT_URL,
// and the key scope names this slot's origin and workspace before the key
// is read (design 9.5). `signable` is false after any local refusal: the
// slot is then neither probed nor signed for.
async function activeLocal(env: Env, found: FoundActive): Promise<{ checks: DoctorCheck[]; signable: boolean }> {
  const { dir, config } = found
  try {
    assertVaultUrlAgrees(env, config)
  } catch (error) {
    return { checks: [fromError("enrolled", toCliError(error)), skipped("key", "Not read: the slot's origin disagrees with MEHEN_VAULT_URL.")], signable: false }
  }
  const enrolled: DoctorCheck = { check: "enrolled", status: "ok", detail: `${config.device} in ${workspaceLabel(config)} (${config.backend} key)` }
  try {
    await assertKeyScopeAgrees(dir, config)
    await loadDeviceKey(dir, config.backend, env, { observe: true })
    return { checks: [enrolled, { check: "key", status: "ok", detail: `${config.backend === "software" ? "Software" : "Secure Enclave"} key in ${dir}, readable only by this user.` }], signable: true }
  } catch (error) {
    return { checks: [enrolled, fromError("key", toCliError(error))], signable: false }
  }
}

// The signed checks of one active slot whose local checks passed and whose
// origin answered: identity (GET /v1/me), frozen, and the open asks.
async function activeSigned(env: Env, found: FoundActive, session: string | null, fetcher: (request: Request) => Promise<Response>, ready: boolean): Promise<DoctorCheck[]> {
  const { dir, config } = found
  const checks: DoctorCheck[] = []
  let me: Me | null = null
  if (!ready) checks.push(skipped("identity", "Needs a usable key and a vault that answers."))
  else {
    try {
      const key = await loadDeviceKey(dir, config.backend, env, { observe: true })
      const api = new HttpVaultApi({ vaultUrl: config.vault, tenant: config.tenant, signer: key.signer(config.device), ...(session ? { session } : {}), fetch: fetcher })
      me = await api.request<Me>("GET", "/v1/me", undefined, { signal: withTimeout() })
      checks.push({ check: "identity", status: "ok", detail: `The vault accepts this machine as ${me.name} (${me.device}).` })
    } catch (error) {
      checks.push(error instanceof DOMException ? unreachable(config.vault, "no answer to GET /v1/me within 10 s") : fromError("identity", toCliError(error)))
    }
  }
  if (me === null) checks.push(skipped("frozen", "Needs the vault to accept this machine."))
  else if (me.frozen) {
    checks.push({ check: "frozen", status: "fail", detail: "The workspace is frozen: every use is refused until a human unfreezes it.", error: "frozen", next: { say: "The vault is frozen. Tell the human; they review the audit log and unfreeze it in the vault with their passkey." } })
  } else checks.push({ check: "frozen", status: "ok", detail: "Not frozen." })
  const pending = (await readLedger(dir, { vaultUrl: config.vault, workspace: config.tenant, device: config.device, workspaceSlug: config.workspaceSlug ?? null }).catch(() => [])).filter(isListedAsk).length
  checks.push(
    pending === 0
      ? { check: "pending", status: "ok", detail: "Nothing waiting for a human." }
      : { check: "pending", status: "warn", detail: `${pending} ask${pending === 1 ? "" : "s"} waiting for a human.`, next: { command: "mehen pending", say: "Some links this machine handed out are still open; `mehen pending` shows them so you can relay them again." } },
  )
  return checks
}

function pendingCheck(found: FoundPending): DoctorCheck {
  const r = found.record
  return {
    check: "enrolled",
    status: "warn",
    detail: `Enrolment ${r.id} in ${r.intent.workspace} at ${r.origin} waits for approval (link valid until ${r.expiresAt}${r.legacy ? "; from before this version, never renewed" : ""}).`,
    next: { command: `mehen wait ${r.id}`, say: `Relay the enrolment link (${r.url}) to the human and run \`mehen wait ${r.id}\` until it is approved.` },
  }
}

function corruptCheck(found: FoundCorrupt): DoctorCheck {
  if (found.reason === "attempt_ended") return { check: "enrolled", status: "warn", detail: found.detail, next: endedNext(basename(found.dir)) }
  return { check: "enrolled", status: "warn", detail: `mehen cannot use this slot (${found.reason}): ${found.detail}`, next: { command: `mehen workspace forget --slot ${found.dir}`, say: `mehen does not use ${found.dir}; retire it with \`mehen workspace forget --slot ${found.dir}\`, or ask the owner if you are not sure what it is.` } }
}

// No active slot in the allowed set: selection rule 7's answer.
function nothingActive(pending: FoundPending[], ended: FoundCorrupt[], vaultUrl: string | null): DoctorCheck {
  const only = pending.length === 1 ? pending[0] : undefined
  if (only) return { check: "enrolled", status: "fail", detail: `No workspace is active on this machine yet; enrolment ${only.record.id} in ${only.record.intent.workspace} waits for approval.`, error: "unauthenticated", next: { command: `mehen wait ${only.record.id}`, say: `Relay the enrolment link (${only.record.url}) to the human and run \`mehen wait ${only.record.id}\` until it is approved.` } }
  if (pending.length > 1) return { check: "enrolled", status: "fail", detail: `No workspace is active on this machine yet; ${pending.length} enrolments wait for approval.`, error: "unauthenticated", next: { command: "mehen pending", say: "Several enrolments wait for approval; `mehen pending` lists their links and the `mehen wait` for each." } }
  const last = ended.length === 1 ? ended[0] : undefined
  if (last) return { check: "enrolled", status: "fail", detail: `No workspace is active on this machine yet; ${last.detail}`, error: "unauthenticated", next: endedNext(basename(last.dir)) }
  return fromError("enrolled", notEnrolled(vaultUrl ?? undefined))
}

// The slots doctor looks at: the allowed set's (and every corrupt one), or
// on a managed host the pinned slot alone.
async function doctorSlots(env: Env): Promise<{ slots: FoundSlot[]; refusal: CliError | null }> {
  try {
    if (managedHost()) {
      const selected = await selectSlot(env, { manifest: null })
      return { slots: selected.config ? [{ state: "active", dir: selected.dir, config: selected.config }] : [], refusal: null }
    }
    const allowed = await allowedSlots(env)
    return { slots: [...allowed.slots, ...allowed.corrupt], refusal: null }
  } catch (error) {
    return { slots: [], refusal: toCliError(error) }
  }
}

export async function doctorAll(env: Env, options: DoctorAllOptions = {}): Promise<DoctorReport> {
  const fetcher = options.fetch ?? ((request: Request) => fetch(request))
  const now = options.now ?? Date.now
  const machine: DoctorCheck[] = []
  const origins: DoctorOrigin[] = []
  const workspaces: DoctorWorkspace[] = []
  let strays: DoctorStray[] = []
  let journal: DoctorJournal | null = null

  // Machine: the root, its migration (read, never run) and the vault URL a
  // new enrolment would use.
  let root: string | null = null
  try {
    const home = resolveHome(env)
    root = home.root
    machine.push({ check: "home", status: "ok", detail: `${home.root} (${home.source === "default" ? "the default" : home.source})` })
  } catch (error) {
    machine.push(fromError("home", toCliError(error)))
  }
  let ready = false
  if (root !== null) {
    const migration = await migrationCheck(env)
    if (migration.check) machine.push(migration.check)
    ready = migration.ready
    journal = migration.journal
    if (ready) strays = await strayEntries(root)
  }
  let vaultUrl: string | null = null
  try {
    vaultUrl = resolveVaultUrl(env, null)
    const source = env.MEHEN_VAULT_URL ? "MEHEN_VAULT_URL" : defaultVault(env).source === "local" ? "the local vault `mehen up` set up" : "the default"
    machine.push({ check: "vault_url", status: "ok", detail: `${vaultUrl} for a new enrolment (${source})` })
  } catch (error) {
    machine.push(fromError("vault_url", toCliError(error)))
  }
  // The installation this command runs from: its PATH row and its update
  // row, from the state next to the binary.
  const cli = await cliState(env)
  const self = selfExecutable(env)
  if (self === null) {
    machine.push(skipped("on_path", "mehen runs from source; nothing is installed."))
    machine.push(skipped("update", "mehen runs from source; nothing is installed to update."))
  } else {
    const install = installation(self)
    machine.push(onPathCheck(install, env))
    const reason = (error: unknown) => (error instanceof Error ? error.message : String(error))
    const stateError = await readInstallState(install).then(() => null, reason)
    let holder: LockHolder | null = null
    let lockError: string | null = null
    try {
      holder = await lockHolder(install)
    } catch (error) {
      lockError = reason(error)
    }
    machine.push(updateDoctorCheck(cli, holder, install.files.lock, Date.now(), { state: install.files.state, stateError, lockError, guard: lockError === null && (await lockGuardPresent(install)) }))
  }
  machine.push(...(await skillCopies(resolve(env.HOME || homedir()), env.PATH ?? "")).map(skillCheck))
  const local = root !== null && ready ? await localVaultCheck(root, fetcher, options.keyring ?? keyringHost(env)) : null
  if (local) machine.push(local)

  let session: DoctorCheck
  let label: string | null = null
  try {
    label = sessionLabel(env)
    session = label
      ? { check: "session", status: "ok", detail: `${label} (MEHEN_SESSION)` }
      : { check: "session", status: "warn", detail: "MEHEN_SESSION is not set.", next: { say: "Set MEHEN_SESSION to a short label for this session (letters, digits, . : _ -) so the human can tell this agent's asks apart." } }
  } catch (error) {
    session = fromError("session", toCliError(error))
  }

  // A root not ready, a refused ceiling, or a selection the environment or
  // checkout makes that refuses: reported, and nothing is probed or signed
  // anywhere.
  let refused = root === null || !ready
  if (!refused && root !== null) {
    const found = options.span ?? (await doctorSlots(env))
    if (found.refusal) {
      refused = true
      machine.push(fromError("enrolled", found.refusal))
    }
    if (!refused && !options.span) {
      try {
        const manifest = manifestWorkspace(options.cwd ?? process.cwd())
        if (workspaceSelector(env) !== null || manifest !== null) await selectSlot(env, { manifest })
      } catch (error) {
        refused = true
        machine.push(fromError("enrolled", toCliError(error)))
      }
    }
    const active = found.slots.filter((f): f is FoundActive => f.state === "active")
    const pending = found.slots.filter((f): f is FoundPending => f.state === "pending")
    if (!refused && active.length === 0) machine.push(nothingActive(pending, found.slots.filter((f): f is FoundCorrupt => f.state === "corrupt" && f.reason === "attempt_ended"), vaultUrl))

    const local = new Map<string, { checks: DoctorCheck[]; signable: boolean }>()
    for (const slot of active) {
      const latch = options.span ? await options.span.guard(slot) : null
      local.set(slot.dir, latch ? { checks: [fromError("enrolled", latch), skipped("key", "Not read: this server refuses the slot.")], signable: false } : await activeLocal(env, slot))
    }
    // Each origin once: those an active slot will sign for, those a pending
    // slot waits on, or before any enrolment the vault URL a new one uses.
    const wanted = new Set<string>()
    if (!refused) {
      for (const slot of active) if (local.get(slot.dir)?.signable) wanted.add(slot.config.vault)
      for (const slot of pending) wanted.add(slot.record.origin)
      if (found.slots.length === 0 && vaultUrl !== null) wanted.add(vaultUrl)
    }
    const answered = new Set<string>()
    for (const origin of wanted) {
      const probe = await probeOrigin(origin, fetcher, now)
      if (probe.reachable) answered.add(origin)
      origins.push({ origin, checks: probe.checks })
    }
    for (const slot of found.slots) {
      if (slot.state === "active") {
        const pre = local.get(slot.dir) ?? { checks: [], signable: false }
        const signed = refused ? [skipped("identity", "Not signed: the selection or ceiling on this machine refused first."), skipped("frozen", "Needs the vault to accept this machine.")] : await activeSigned(env, slot, label, fetcher, pre.signable && answered.has(slot.config.vault))
        workspaces.push({ slot: slot.dir, state: "active", workspace: configWorkspace(slot.config), checks: [...pre.checks, ...signed] })
      } else if (slot.state === "pending") workspaces.push({ slot: slot.dir, state: "pending", workspace: null, checks: [pendingCheck(slot)] })
      else workspaces.push({ slot: slot.dir, state: slot.reason === "attempt_ended" ? "ended" : "corrupt", workspace: null, checks: [corruptCheck(slot)] })
    }
  }

  // The first failure decides, in the order a reader meets them.
  const all = [...machine, session, ...origins.flatMap((o) => o.checks), ...workspaces.flatMap((w) => w.checks)]
  const failed = all.find((c) => c.status === "fail")
  const warned = all.find((c) => c.status === "warn" && c.next)
  return { ok: failed === undefined, cli, machine, origins, session, workspaces, strays, migration: journal, next: failed?.next ?? warned?.next ?? null, exitCode: failed ? exitCodeFor(failed.error ?? "internal") : EXIT.ok }
}

const STATUS_WORD: Record<DoctorStatus, string> = { ok: "ok", warn: "warn", fail: "FAIL", skipped: "skip" }

function workspaceHeading(w: DoctorWorkspace): string {
  if (w.workspace) return `${w.workspace.name} (${w.workspace.slug}): ${w.slot}`
  return `${w.state} slot: ${w.slot}`
}

export function doctorLines(report: DoctorReport, colour = styler(false)): Segment[][] {
  const groups: [string | null, DoctorCheck[]][] = [[null, [...report.machine, report.session]], ...report.origins.map((o): [string, DoctorCheck[]] => [`vault ${o.origin}`, o.checks]), ...report.workspaces.map((w): [string, DoctorCheck[]] => [workspaceHeading(w), w.checks])]
  const every = groups.flatMap(([, checks]) => checks)
  const width = Math.max(...every.map((c) => c.check.length))
  const counts = { ok: 0, warn: 0, fail: 0, skipped: 0 }
  for (const c of every) counts[c.status] += 1
  const summary = report.ok
    ? `mehen doctor: this machine can use the vault${counts.warn ? ` (${counts.warn} warning${counts.warn === 1 ? "" : "s"})` : ""}`
    : `mehen doctor: ${counts.fail} check${counts.fail === 1 ? "" : "s"} failed`
  const lines: Segment[][] = [segments(summary)]
  for (const [heading, checks] of groups) {
    if (heading) lines.push(segments(heading))
    for (const c of checks) {
      const word = STATUS_WORD[c.status].padEnd(4)
      const styled = c.status === "fail" ? colour.danger(word) : c.status === "warn" ? colour.warn(word) : c.status === "skipped" ? colour.dim(word) : colour.ok(word)
      lines.push(segments("  ", styled, `  ${c.check.padEnd(width)}  ${c.detail}`))
    }
  }
  for (const stray of report.strays) lines.push(segments(`stray: ${stray.path}: ${stray.detail}`))
  if (report.migration) lines.push(segments(`migration: an unfinished journal from ${report.migration.startedAt} (pid ${report.migration.pid}) with ${report.migration.steps.length} step${report.migration.steps.length === 1 ? "" : "s"}; mehen doctor --json prints it`))
  lines.push(segments(`cli: mehen ${report.cli.version}${report.cli.commit ? ` (${report.cli.commit})` : ""} at ${report.cli.path}`))
  if (report.next) {
    lines.push(segments(`next: ${report.next.say}`))
    if (report.next.url) lines.push(segments(`  open: ${report.next.url}`))
    if (report.next.command) lines.push(segments(`  run:  ${report.next.command}`))
  }
  return lines
}

export const doctorCommand: Command = {
  summary: "check in one go: every workspace on this machine, its key, the vaults, the clock, identity, session label, frozen, and what to do next",
  spec: { usage: "mehen doctor", flags: {}, positionals: { min: 0, max: 0 } },
  examples: [["doctor"], ["doctor", "--json"]],
  notes: ["Exits 0 when no check failed, else with the exit code of the first failure. Works before enrolment. The checks never migrate, write or delete anything: strays under the config root are named, not removed. As after any command, the background updater may run afterwards when a check for a new release is due."],
  async run({ json, env }) {
    const report = await doctorAll(env)
    if (json) printJson(report)
    else for (const line of doctorLines(report, styler(colourEnabled(process.stdout, env)))) printLine(line)
    return report.exitCode
  },
}
