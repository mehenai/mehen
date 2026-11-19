// mehen enrol --workspace <slug>: this
// machine's device key, an enrolment attempt the vault issues a link for in
// the named workspace, and the ask to hand to a human. It prints the ask and
// exits 0; `mehen wait <id>` (or vault_wait) follows the attempt from any
// process, and --wait follows it here.
//
// The key is the identity; the link is only a way to approve it. So the key
// is kept across attempts, a pending attempt is resumed from its record
// (pending/<originKey>/<slug>/enrolment.json, never pruned by expiry), and
// a link is renewed in place: the same id, code and URL. When an attempt
// ends for good the next mehen enrol starts a new one with the same key.
//
// The order is fixed: --fresh-key on an active slot replaces it before the
// idempotent-success check; an active slot whose signed check succeeds is
// success with nothing written; only a definitive device_revoked repairs a
// slot. Locks: the pending slot's lock around key creation, the record and
// the start; never across a poll. --connect goes in the start body only.
//
// Proofs while enrolling: POST /v1/enrol is signed with ten "enrol" and dev
// "new" and verified against the JWK in its body; the polls and renewals
// with ten "enrol" and dev = the enrolment id.

import { existsSync } from "node:fs"
import { rm } from "node:fs/promises"
import { hostname } from "node:os"
import { EXIT, type EnrolStartResponse } from "@mehen/protocol/api"
import { type FingerprintGroupIndex, fingerprintGroupIndex, fingerprintGroups, fingerprintOf, fingerprintWords } from "@mehen/protocol/fingerprint"
import { type DeviceJwk, jwkThumbprint } from "@mehen/protocol/proof"
import { canonicalJson } from "@mehen/protocol/canonical-json"
import { DeviceTagSchema, type EnrolRequestedScope, EnrolRequestedScopeSchema, type OwnerRef, OwnerRefSchema, type WorkspaceDeviceScope, WorkspaceDeviceScopeSchema, WorkspaceEnrolStartSchema, type WorkspaceRef, WorkspaceRefSchema, normaliseWorkspaceSlug } from "@mehen/protocol/workspace"
import type { ParsedArgs } from "../args.ts"
import { type Ask, askUrl, askUrlFor, enrolAsk, refusedLinkWarning, requestedBy, withContext } from "../ask.ts"
import type { Command } from "../command.ts"
import { BACKENDS, type Backend, type Config, type Env, canonicalOrigin, resolveVaultUrl, workspaceLabel } from "../config.ts"
import { type DeviceKey, chooseBackend, createDeviceKey, loadOrCreateDeviceKey } from "../device-key.ts"
import { type EnrolmentRecord, readEnrolmentRecord, recordFromLegacyEntry, removeEnrolmentRecord, writeEnrolmentRecord } from "../enrolment-record.ts"
import { CliError, toCliError, usageError } from "../errors.ts"
import { managedHost, mkdirPrivate, pendingSlotPath, resolveHome } from "../home.ts"
import { HttpVaultApi } from "../http-client.ts"
import { readLegacyEnrolments, removeLedgerEntries } from "../ledger.ts"
import { durationText } from "../operations.ts"
import { note, printAsk, printJson, printLine } from "../output.ts"
import { ENROL_TENANT, enrolLedgerScope, openContext, pollIntervalMs, sessionLabel } from "../session.ts"
import { type FoundActive, activeIn, allowedSlots, contextMatches, insideCeiling, selectSlot, workspaceNotAllowed } from "../slots.ts"
import { pendingLockPath, withSlotLocks } from "../slot-lock.ts"
import { type Segment, type Styler, colourEnabled, segments, styler } from "../tty.ts"
import { VaultApiError } from "../vault-api.ts"
import { type Attempt, type EnrolIntent, type Finished, type PendingRecord, followAttempt, isWorkspaceSlug, mutateSlot, publicKeyOnDisk } from "./activate.ts"
import { WaitMonitor, timeoutSeconds } from "./intake.ts"

export const ENROL_NEW_DEVICE = "new"

const GROUP_WORDS: Record<FingerprintGroupIndex, string> = { 0: "first", 1: "second", 2: "third", 3: "fourth" }
const LABEL_WIDTH = 8
const WORKSPACE_ID = /^tn_[A-Za-z0-9]{8,40}$/

// The same Crockford groups the approval page shows, all four: the terminal
// is the trusted side the hidden group is typed from.
export async function keyFingerprint(jwk: DeviceJwk): Promise<string> {
  return fingerprintOf(await jwkThumbprint(jwk))
}

function defaultName(): string {
  const short = hostname().split(".")[0] ?? "machine"
  return short.slice(0, 64) || "machine"
}

function sameJwk(a: Pick<DeviceJwk, "x" | "y">, b: Pick<DeviceJwk, "x" | "y">): boolean {
  return a.x === b.x && a.y === b.y
}

// The lines under the ask block that only the terminal can show: the four
// words with their colour named in text, and which group the page withholds
// (fingerprintGroupIndex of the link's code, exactly as the server picks it)
// so the human knows what to type. Every value is this machine's own.
export async function fingerprintLines(input: { thumbprint: string; code: string }, s: Styler = styler(false)): Promise<Segment[][]> {
  const fingerprint = fingerprintOf(input.thumbprint)
  const hidden = await fingerprintGroupIndex(input.code)
  const group = fingerprintGroups(fingerprint)[hidden]
  const words = fingerprintWords(input.thumbprint).map((w) => `${w.word} (${w.colour.name})`)
  const label = (name: string) => s.dim(`${name}:`.padEnd(LABEL_WIDTH))
  return [
    segments("  ", label("words"), ` ${words.join("  ")}`),
    segments("  ", label("hidden"), ` the page hides the ${GROUP_WORDS[hidden]} group, `, s.bold(group), ": type it on the page"),
  ]
}

// The published shapes.
export type EnrolPending = {
  status: "pending"
  enrolment: string
  url: string
  code: string
  fingerprint: string
  backend: Backend
  expiresAt: string
  hardExpiresAt: string | null
  renewals: number
  claimed: boolean
  slot: string
  ask: Ask
  // The narrower scope this attempt asked for, when it asked for one.
  requestedScope?: EnrolRequestedScope
  warning?: string
  superseded?: string
}
export type EnrolActive = {
  status: "active"
  alreadyEnrolled?: true
  repaired?: { device: string; reason: "device_revoked" }
  replaced?: { device: string }
  tenant: string
  workspace: WorkspaceRef
  owner: OwnerRef
  device: string
  backend: Backend
  scope: WorkspaceDeviceScope
  slot: string
}

// The workspace an enrolment is for: a slug, or a
// tn_ id only for an active slot in the allowed set.
function workspaceSelector(args: { string(name: string): string | null }): { selector: string; team: string | null } {
  const raw = args.string("workspace")
  if (raw === null) {
    throw new CliError("usage", "mehen enrol needs --workspace <slug>: the workspace this machine joins.", {
      command: "mehen enrol --workspace <slug>",
      say: "Run `mehen enrol --workspace <slug>`; the slug is on the workspace's Connect an agent page.",
    })
  }
  const trimmed = raw.trim()
  const selector = WORKSPACE_ID.test(trimmed) ? trimmed : normaliseWorkspaceSlug(raw)
  if (!WORKSPACE_ID.test(selector) && !isWorkspaceSlug(selector)) throw usageError(`--workspace ${JSON.stringify(raw)} is not a workspace slug (lower-case letters, digits and single dashes).`, "mehen enrol --help")
  const teamRaw = args.string("team")
  const team = teamRaw === null ? null : teamRaw.trim().toLowerCase()
  if (team !== null && !(/^[a-z][a-z0-9-]{0,31}$/.test(team) && !team.endsWith("-") && !team.includes("--"))) throw usageError(`--team ${JSON.stringify(teamRaw)} is not a team slug.`, "mehen enrol --help")
  return { selector, team }
}

// The modes an enrolment may ask for: the vault intersects them with the
// workspace's default modes, which never include lease.
export const ENROL_MODES = ["relay", "sign", "mint", "placeholder"] as const
const ENROL_LIST_MAX = 32

// The narrower scope the flags ask for (EnrolRequestedScope), checked flag
// by flag before any key is made or anything is signed; null when no scope
// flag was given, so the start body is exactly what it was before.
export function requestedScope(args: ParsedArgs): EnrolRequestedScope | null {
  const tags = args.list("tag")
  const projects = args.list("project")
  const modes = args.list("mode")
  for (const tag of tags) if (!DeviceTagSchema.safeParse(tag).success) throw usageError(`--tag ${JSON.stringify(tag)} is not a machine tag: lower-case letters, digits, ':', '_' or '-', starting with a letter or digit, at most 40.`, "mehen enrol --help")
  for (const project of projects) if (project.length < 1 || project.length > 64) throw usageError(`--project ${JSON.stringify(project)} must be a project id of 1 to 64 characters.`, "mehen enrol --help")
  for (const mode of modes) if (!(ENROL_MODES as readonly string[]).includes(mode)) throw usageError(`--mode ${JSON.stringify(mode)} is not one of ${ENROL_MODES.join(", ")}.`, "mehen enrol --help")
  if (tags.length > ENROL_LIST_MAX) throw usageError(`--tag may be given at most ${ENROL_LIST_MAX} times.`, "mehen enrol --help")
  if (projects.length > ENROL_LIST_MAX) throw usageError(`--project may be given at most ${ENROL_LIST_MAX} times.`, "mehen enrol --help")
  if (new Set(modes).size !== modes.length) throw usageError("Give each --mode once.", "mehen enrol --help")
  const scope = {
    ...(tags.length ? { tags } : {}),
    ...(projects.length ? { projects } : {}),
    ...(modes.length ? { modes } : {}),
    ...(args.bool("no-private") ? { privateCredentials: false } : {}),
    ...(args.bool("workloads-only") ? { workloads: "required" } : {}),
  }
  if (Object.keys(scope).length === 0) return null
  const parsed = EnrolRequestedScopeSchema.safeParse(scope)
  if (!parsed.success) throw usageError("--tag, --project, --mode, --no-private and --workloads-only do not make a scope the vault accepts.", "mehen enrol --help")
  return parsed.data
}

// The requested scope in words, for the line under the ask.
export function requestedScopeWords(scope: EnrolRequestedScope): string {
  const parts = [
    ...(scope.tags ? [`items tagged ${scope.tags.join(", ")}`] : []),
    ...(scope.projects ? [`projects ${scope.projects.join(", ")}`] : []),
    ...(scope.modes ? [`modes ${scope.modes.join(", ")}`] : []),
    ...(scope.privateCredentials === false ? ["no private credentials"] : []),
    ...(scope.workloads === "required" ? ["acts only through workloads"] : []),
  ]
  return parts.join("; ")
}

function sameRequestedScope(a: EnrolRequestedScope | undefined, b: EnrolRequestedScope | null): boolean {
  return canonicalJson(a ?? null) === canonicalJson(b)
}

function forgetSay(slot: string): string {
  return `To retire this slot anyway, \`mehen workspace forget --slot ${slot}\`.`
}

// Any answer to the signed check of an existing slot but success or a
// definitive device_revoked: the error itself, with the way to retire the
// slot by hand. Nothing is touched. When the answer's next step is to enrol
// again (the vault does not know the device, or its key file is gone), that
// is the command that just refused, so the next step is the forget that
// lets the following enrol start a new attempt. A managed host's pin is
// its owner's to provision again.
function leaveSlot(error: unknown, slot: string, slug: string, managed: boolean): CliError {
  const e = toCliError(error)
  if (e.next?.command?.startsWith("mehen enrol") && managed) {
    return new CliError(e.code, e.message, { say: "This host is managed: ask the host's owner to provision the pinned workspace again; nothing here replaces or repairs a managed pin." }, e.extras)
  }
  if (e.next?.command?.startsWith("mehen enrol")) {
    return new CliError(
      e.code,
      e.message,
      {
        command: `mehen workspace forget --slot ${slot}`,
        say: `mehen enrol keeps an active slot on this answer rather than replace it. Retire the slot with \`mehen workspace forget --slot ${slot}\`, then run \`mehen enrol --workspace ${slug}\` and have the human approve the new link.`,
      },
      e.extras,
    )
  }
  return new CliError(e.code, e.message, { ...(e.next?.command ? { command: e.next.command } : {}), say: `${e.next?.say ? `${e.next.say} ` : ""}${forgetSay(slot)}` }, e.extras)
}

function slotReplaced(slot: string, device: string, result: "superseded" | "gone"): CliError {
  return new CliError("failed", `The slot ${slot} no longer holds device ${device}${result === "superseded" ? ": another mehen process replaced it meanwhile" : ""}; nothing was changed.`, {
    command: "mehen workspace list",
    say: "Another mehen process changed this workspace's slot while this one ran; check `mehen workspace list`, then run the command again.",
  })
}

export type Step2 = { done: EnrolActive } | { repaired?: EnrolActive["repaired"]; replaced?: EnrolActive["replaced"]; slug: string }

function managedRefusal(why: string): CliError {
  return new CliError("workspace_mismatch", `This host is managed: ${why}`, { say: "Ask the host's owner to provision the pinned workspace again; nothing here replaces or repairs a managed pin." })
}

// The check for an active slot of the workspace at this origin. On a
// managed host the pinned slot is confirmed and never replaced or repaired:
// only its owner provisions it.
export async function activeStep(env: Env, found: FoundActive, freshKey: boolean, slug: string, managed = false): Promise<Step2> {
  const { dir: slot, config } = found
  const jwk = await publicKeyOnDisk(slot, config.backend)
  if (managed && freshKey) throw managedRefusal("--fresh-key would replace the owner's pinned enrolment.")
  // 2a, --fresh-key first: revoke under the active lock, then retire the slot.
  if (freshKey) {
    let session: Awaited<ReturnType<typeof openContext>>
    try {
      session = await openContext(env, { dir: slot, config, reason: "workspace", known: 1 })
    } catch (error) {
      throw leaveSlot(error, slot, slug, managed)
    }
    const result = await mutateSlot(slot, { device: config.device, jwk }, async () => {
      try {
        await session.api.request<unknown>("POST", "/v1/devices/self/revoke", {})
      } catch (error) {
        if (!(error instanceof VaultApiError && error.body.error === "device_revoked")) throw leaveSlot(error, slot, slug, managed)
      }
      return null
    })
    if (result !== "applied") throw slotReplaced(slot, config.device, result)
    return { replaced: { device: config.device }, slug }
  }
  // 2b, the signed check: success is success, with nothing written.
  let me: Record<string, unknown>
  try {
    const session = await openContext(env, { dir: slot, config, reason: "workspace", known: 1 })
    me = await session.api.request<Record<string, unknown>>("GET", "/v1/me")
  } catch (error) {
    // 2c, repair only on a definitive device_revoked from that signed call.
    if (!(error instanceof VaultApiError && error.body.error === "device_revoked")) throw leaveSlot(error, slot, slug, managed)
    if (managed) throw managedRefusal(`the pinned device ${config.device} was revoked in the vault; its slot is left for the owner.`)
    const result = await mutateSlot(slot, { device: config.device, jwk }, () => null)
    if (result !== "applied") throw slotReplaced(slot, config.device, result)
    return { repaired: { device: config.device, reason: "device_revoked" }, slug }
  }
  const named = WorkspaceRefSchema.safeParse(me.workspace)
  const workspace: WorkspaceRef = named.success && named.data.id === config.tenant ? named.data : { id: config.tenant, slug: config.workspaceSlug ?? slug, name: config.workspaceName ?? slug }
  const owned = OwnerRefSchema.safeParse(me.owner)
  const owner = owned.success ? owned.data : (config.owner ?? null)
  const scope = WorkspaceDeviceScopeSchema.safeParse(me.scope)
  if (owner === null || !scope.success) throw new CliError("internal", `The vault's status for device ${config.device} names no owner or no complete workspace scope.`, { command: "mehen status", say: "Run `mehen status` to see what the vault says about this machine." })
  return { done: { status: "active", alreadyEnrolled: true, tenant: config.tenant, workspace, owner, device: config.device, backend: config.backend, scope: scope.data, slot } }
}

// What step 3 left to do: follow a resumed attempt, or print one just
// issued; or go back to step 2, because another observer committed this
// workspace's slot while this one waited for the pending lock.
type Prepared = { attempt: Attempt; resumed: boolean; warning: string | null; superseded: string | null; key: DeviceKey } | { enrolled: FoundActive }

function enrolApi(origin: string, key: DeviceKey, device: string, session: string | null): HttpVaultApi {
  return new HttpVaultApi({ vaultUrl: origin, tenant: ENROL_TENANT, signer: key.signer(device), ...(session ? { session } : {}) })
}

function recordFailed(slot: string, slug: string, cause: unknown, started: boolean): CliError {
  const detail = cause instanceof Error ? cause.message : String(cause)
  return new CliError("failed", `The enrolment record in ${slot} could not be written (${detail}); ${started ? "no ask is printed." : "nothing was sent."}`, {
    command: `mehen enrol --workspace ${slug}`,
    say: started
      ? `The vault may hold a link for this key that this machine cannot follow; fix ${slot} and run \`mehen enrol --workspace ${slug}\` again, which issues a new link and expires the old one at the vault.`
      : `Fix ${slot} (a private directory of this user) and run \`mehen enrol --workspace ${slug}\` again.`,
  })
}

type Step3Input = { env: Env; root: string; slot: string; origin: string; intent: EnrolIntent; name: string; backend: Backend; freshKey: boolean; connect: string | null; session: string | null; scope: EnrolRequestedScope | null }

// Under the pending lock: the record read through the
// validated reader, the key loaded or made, and either a resumable attempt
// or a new one issued (3c). The lock is released before any poll.
async function prepareAttempt(input: Step3Input): Promise<Prepared> {
  const { env, root, slot, origin, intent, name, backend, session, scope } = input
  return withSlotLocks([pendingLockPath(root, origin, intent.workspace)], async (): Promise<Prepared> => {
    // The finish step renames this slot into workspaces/ while it holds this
    // lock: an attempt committed meanwhile is enrolled, not started again.
    const committed = managedHost() ? undefined : activeIn(await allowedSlots(env)).find((f) => f.config.vault === origin && contextMatches(f, intent.workspace))
    if (committed) return { enrolled: committed }
    // A slot this run makes, whose key this run makes, has never been sent
    // to the vault before this start: if the start is refused it is
    // discarded, so nothing is left to look like an attempt that ended.
    const newSlot = !existsSync(slot)
    mkdirPrivate(root, slot)
    let read = await readEnrolmentRecord(slot)
    if (read && "refused" in read) {
      throw new CliError("failed", `The enrolment record in ${slot} cannot be used: ${read.refused}.`, { command: `mehen workspace forget --slot ${slot}`, say: `Retire it with \`mehen workspace forget --slot ${slot}\`, then enrol again.` })
    }
    // A legacy enrol entry an older mehen left in this slot's ledger becomes
    // the record, so the attempt it stands for can be resumed.
    if (read === null) {
      const legacy = (await readLegacyEnrolments(slot, origin)).filter((e) => e.enrol.workspace === intent.workspace).at(-1)
      if (legacy) {
        await writeEnrolmentRecord(slot, recordFromLegacyEntry(legacy))
        await removeLedgerEntries(slot, enrolLedgerScope(origin), (e) => e.ask.kind === "enrol")
        read = await readEnrolmentRecord(slot)
      }
    }
    let record: EnrolmentRecord | null = read && "record" in read ? read.record : null
    // A crash between the two writes of 3c: nothing to resume.
    if (record?.state === "issuing") {
      await removeEnrolmentRecord(slot)
      record = null
    }
    const loaded = input.freshKey ? { ...(await createDeviceKey(slot, backend, env, { vault: origin, tenant: null })), created: true } : await loadOrCreateDeviceKey(slot, backend, env, origin)
    const discardUnsent = async () => {
      if (newSlot && loaded.created) await rm(slot, { recursive: true, force: true }).catch(() => undefined)
    }
    const resumable =
      record !== null && record.state === "pending" && !loaded.created && sameJwk(record.jwk, loaded.jwk) && record.name === name && record.backend === backend && record.intent.workspace === intent.workspace && record.intent.team === intent.team && record.origin === origin && sameRequestedScope(record.scope, scope)
        ? (record as PendingRecord)
        : null
    // The claim is immutable: a connect code on an unclaimed attempt starts a
    // new one with the same key (the vault marks the old one superseded); on
    // a claimed one it is not sent again.
    const supersede = resumable && input.connect !== null && !resumable.claimed ? resumable.id : null
    if (resumable && supersede === null) {
      if (input.connect !== null) note(`mehen: enrolment ${resumable.id} is already claimed; the connect code was not sent again.`)
      return { attempt: { root, slot, record: resumable, key: loaded.key, env, session }, resumed: true, warning: null, superseded: null, key: loaded.key }
    }
    // 3c: the record first (issuing), then the start, then the record again.
    const startedAt = new Date().toISOString()
    const issuing: EnrolmentRecord = { v: 1, state: "issuing", id: null, code: null, url: null, origin, intent, name, backend, jwk: { kty: "EC", crv: "P-256", x: loaded.jwk.x, y: loaded.jwk.y }, session, startedAt, expiresAt: null, hardExpiresAt: null, renewals: 0, legacy: false, claimed: false, ...(scope !== null ? { scope } : {}) }
    try {
      await writeEnrolmentRecord(slot, issuing)
    } catch (error) {
      throw recordFailed(slot, intent.workspace, error, false)
    }
    const owner = intent.team === null ? { kind: "self" as const } : { kind: "team" as const, team: intent.team }
    const start = WorkspaceEnrolStartSchema.safeParse({ workspace: intent.workspace, owner, name, backend, jwk: loaded.jwk, host: hostname().slice(0, 253), ...(input.connect !== null ? { connect: input.connect } : {}), ...(scope !== null ? { scope } : {}) })
    if (!start.success) {
      await removeEnrolmentRecord(slot)
      await discardUnsent()
      throw usageError("--name must be 1 to 64 characters, --workspace a workspace slug and --connect a connect code.", "mehen enrol --help")
    }
    let started: EnrolStartResponse
    try {
      started = await enrolApi(origin, loaded.key, ENROL_NEW_DEVICE, session).request<EnrolStartResponse>("POST", "/v1/enrol", start.data)
    } catch (error) {
      await removeEnrolmentRecord(slot).catch(() => undefined)
      // Only the vault's own refusal (4xx) proves no attempt was made; a 5xx
      // or a lost answer may have left one holding this key, so it is kept.
      if (error instanceof VaultApiError && error.status < 500) await discardUnsent()
      const e = toCliError(error)
      if (input.connect !== null && e.code === "forbidden") throw new CliError("forbidden", e.message, { say: "The connect code was refused; open Connect an agent for a fresh one." })
      throw e
    }
    // The vault's link is handed over only when askUrl accepts it under the
    // intended workspace; otherwise it is rebuilt from the code on this
    // vault, with a warning, and never taken from the answer.
    const vault = { vaultUrl: origin, workspaceSlug: intent.workspace }
    const given = askUrl(started.url, vault)
    const link = given?.route?.prefix === "e" && given.route.id === started.code ? given : askUrlFor(vault, "enrol", started.code)
    if (!link || typeof started.enrolment !== "string" || typeof started.expiresAt !== "string") {
      await removeEnrolmentRecord(slot).catch(() => undefined)
      throw new CliError("internal", "The vault returned an enrolment code mehen does not recognise, so there is no link to hand over.", {
        say: "The vault's answer did not look like one mehen knows; check the vault URL and try again.",
      })
    }
    const pending: EnrolmentRecord = {
      ...issuing,
      state: "pending",
      id: started.enrolment,
      code: started.code,
      url: link.url,
      expiresAt: started.expiresAt,
      hardExpiresAt: typeof started.hardExpiresAt === "string" && Number.isFinite(Date.parse(started.hardExpiresAt)) ? started.hardExpiresAt : null,
      claimed: input.connect !== null,
    }
    try {
      await writeEnrolmentRecord(slot, pending)
    } catch (error) {
      throw recordFailed(slot, intent.workspace, error, true)
    }
    return { attempt: { root, slot, record: pending as PendingRecord, key: loaded.key, env, session }, resumed: false, warning: given === link ? null : refusedLinkWarning(origin), superseded: supersede, key: loaded.key }
  })
}

async function attemptAsk(a: Attempt, env: Env): Promise<Ask> {
  const r = a.record
  const link = askUrl(r.url, { vaultUrl: r.origin, workspaceSlug: r.intent.workspace })
  if (!link) throw new CliError("internal", `The enrolment record for ${r.id} has no link on ${r.origin}.`, { command: `mehen enrol --workspace ${r.intent.workspace} --fresh-key`, say: "The recorded enrolment cannot be resumed; start again with a fresh key." })
  const ask = enrolAsk({ id: r.id, url: link.url, name: r.name, backend: r.backend, fingerprint: fingerprintOf(await jwkThumbprint(r.jwk as DeviceJwk)), expiresAt: r.expiresAt, requestedBy: requestedBy(env), intent: r.intent, claimed: r.claimed })
  return withContext(ask, { origin: r.origin, workspace: null, device: null })
}

function minutesAgo(iso: string, now: Date): string {
  const at = Date.parse(iso)
  const minutes = Number.isFinite(at) ? Math.round((now.getTime() - at) / 60_000) : 0
  return minutes < 1 ? "a moment ago" : `${minutes} min ago`
}

function pendingOutput(a: Attempt, ask: Ask, fingerprint: string, extra: { warning: string | null; superseded: string | null }): EnrolPending {
  const r = a.record
  return {
    status: "pending",
    enrolment: r.id,
    url: ask.url,
    code: r.code,
    fingerprint,
    backend: r.backend,
    expiresAt: r.expiresAt,
    hardExpiresAt: r.hardExpiresAt,
    renewals: r.renewals,
    claimed: r.claimed,
    slot: a.slot,
    ask,
    ...(r.scope ? { requestedScope: r.scope } : {}),
    ...(extra.warning ? { warning: extra.warning } : {}),
    ...(extra.superseded ? { superseded: extra.superseded } : {}),
  }
}

function activeOutput(finished: Finished, extra: Pick<EnrolActive, "repaired" | "replaced">): EnrolActive {
  const v = finished.verified
  return { status: "active", ...(extra.repaired ? { repaired: extra.repaired } : {}), ...(extra.replaced ? { replaced: extra.replaced } : {}), tenant: v.tenant, workspace: v.workspace, owner: v.owner, device: v.device, backend: finished.config.backend, scope: v.scope, slot: finished.slot }
}

function printActive(out: EnrolActive, config: Pick<Config, "tenant" | "workspaceSlug" | "workspaceName">, origin: string, json: boolean): void {
  if (json) return printJson(out)
  if (out.alreadyEnrolled) {
    printLine(segments(`This machine is already enrolled as ${out.device} in ${workspaceLabel(config)} at ${origin}; nothing to do. Try \`mehen status\`.`))
    return
  }
  printLine(segments(`Enrolled as ${out.device} in ${workspaceLabel(config)} at ${origin}, owned by ${out.owner.name}${out.owner.kind === "team" ? " (team)" : ""}. Try \`mehen status\` and \`mehen guide\`.`))
}

export const enrolCommand: Command = {
  summary: "enrol this machine in a workspace: prints the link a human accepts in the browser, then mehen wait finishes it; the key is kept across attempts",
  spec: {
    usage: "mehen enrol --workspace <slug> [--name <machine-name>] [--team <team-slug>] [--backend secure-enclave|software] [--fresh-key] [--wait [--timeout <duration>]] [--no-renew] [--connect <code>] [--tag <tag>]... [--project <id>]... [--mode relay|sign|mint|placeholder]... [--no-private] [--workloads-only]",
    flags: {
      name: { type: "string" },
      team: { type: "string" },
      backend: { type: "string" },
      "fresh-key": { type: "boolean" },
      wait: { type: "boolean" },
      timeout: { type: "string" },
      "no-renew": { type: "boolean" },
      connect: { type: "string" },
      tag: { type: "list" },
      project: { type: "list" },
      mode: { type: "list" },
      "no-private": { type: "boolean" },
      "workloads-only": { type: "boolean" },
    },
    positionals: { min: 0, max: 0 },
  },
  examples: [
    ["enrol", "--workspace", "acme", "--name", "my-laptop"],
    ["enrol", "--workspace", "acme", "--name", "ci-runner", "--team", "ci", "--backend", "software", "--json"],
    ["enrol", "--workspace", "acme", "--name", "agent-host", "--tag", "agents", "--mode", "relay", "--no-private", "--workloads-only"],
  ],
  notes: [
    "The slug is on the workspace's Connect an agent page. Your own machine: you accept it yourself with your passkey. --team: an owner or admin admits it as the team's machine.",
    "Prints the link and exits 0: relay it, then run `mehen wait enr_...` until it is accepted; it keeps the link alive while it waits. --wait waits here instead, for --timeout (10 min unless given).",
    "Each workspace gets its own slot under the config root (MEHEN_HOME, default ~/.config/mehen); running it again resumes the same attempt with the same key.",
    "--tag, --project and --mode (each repeatable), --no-private and --workloads-only ask for less than the workspace's default scope; the page shows the result and the person's passkey signs it. Without them nothing is asked for. A different requested scope starts a new attempt with the same key.",
  ],
  async run({ args, json, env }) {
    const { selector, team } = workspaceSelector(args)
    const requested = args.string("backend")
    if (requested !== null && !(BACKENDS as readonly string[]).includes(requested)) throw usageError(`--backend must be one of ${BACKENDS.join(", ")}.`, "mehen enrol --help")
    const scope = requestedScope(args)
    const freshKey = args.bool("fresh-key")
    const wait = args.bool("wait")
    if (args.string("timeout") !== null && !wait) throw usageError("--timeout goes with --wait: it is how long mehen enrol waits here for a human.", "mehen enrol --help")
    const timeout = timeoutSeconds(args.string("timeout"), "mehen enrol --help")
    const noRenew = args.bool("no-renew")
    const noQr = args.bool("no-qr")
    const connect = args.string("connect")
    const origin = canonicalOrigin(resolveVaultUrl(env, null))
    const session = sessionLabel(env)

    // Step 1 and 2: the ceiling at this origin, then an active slot of the workspace.
    let found: FoundActive | undefined
    let root: string
    const managed = managedHost()
    if (managed) {
      // A managed host serves only its pinned slot: enrol confirms it, and
      // the owner provisions anything else.
      const pinned = await selectSlot(env, { manifest: null })
      if (!pinned.config || !contextMatches({ dir: pinned.dir, config: pinned.config }, selector) || pinned.config.vault !== origin) {
        throw new CliError("workspace_mismatch", `This host is managed: it serves only its pinned workspace, not ${selector} at ${origin}.`, { say: "Ask the host's owner to provision another pin for that workspace; nothing here enrols it." })
      }
      found = { state: "active", dir: pinned.dir, config: pinned.config }
      root = resolveHome(env).root
    } else {
      const allowed = await allowedSlots(env)
      root = allowed.root
      found = activeIn(allowed).find((f) => f.config.vault === origin && contextMatches(f, selector))
      if (!insideCeiling(allowed, selector, origin) && !found) throw workspaceNotAllowed(`Workspace ${selector} at ${origin}`, allowed.ceiling ?? [])
    }
    if (!found && WORKSPACE_ID.test(selector)) throw usageError("an enrolment starts with the workspace slug from the Connect an agent page; a tn_ id names only a workspace this machine is already in.", "mehen enrol --help")
    let slug = selector
    let fix: Pick<EnrolActive, "repaired" | "replaced"> = {}
    if (found) {
      slug = found.config.workspaceSlug ?? selector
      if (!isWorkspaceSlug(slug)) throw usageError(`The slot for ${selector} records no workspace slug to enrol it again with; use the slug from the Connect an agent page.`, "mehen enrol --help")
      const step = await activeStep(env, found, freshKey, slug, managed)
      if ("done" in step) {
        if (scope !== null) note(`mehen: this machine is already enrolled, so the requested scope (${requestedScopeWords(scope)}) was not sent; a person narrows an enrolled machine on its page.`)
        printActive(step.done, found.config, origin, json)
        return EXIT.ok
      }
      fix = { ...(step.repaired ? { repaired: step.repaired } : {}), ...(step.replaced ? { replaced: step.replaced } : {}) }
      if (fix.repaired) note(`mehen: device ${fix.repaired.device} was revoked in the vault; its slot was cleared and this machine enrols again.`)
      if (fix.replaced) note(`mehen: device ${fix.replaced.device} was revoked and its slot cleared; enrolling again with a new key.`)
    }
    const intent: EnrolIntent = { workspace: slug, team }
    const backend = await chooseBackend(requested as Backend | null, env)
    const name = args.string("name") ?? defaultName()
    const slot = pendingSlotPath(root, origin, slug)
    const step3 = { env, root, slot, origin, intent, name, backend, freshKey: freshKey || fix.replaced !== undefined, connect, session, scope }
    // Step 3, going back to step 2 at most once when the slot was committed
    // by another observer meanwhile (it is then this machine's enrolment).
    const prepare = async (): Promise<Exclude<Prepared, { enrolled: FoundActive }> | EnrolActive> => {
      const first = await prepareAttempt(step3)
      if (!("enrolled" in first)) return first
      const step = await activeStep(env, first.enrolled, false, slug)
      if ("done" in step) return step.done
      const again = await prepareAttempt(step3)
      if ("enrolled" in again) throw slotReplaced(again.enrolled.dir, again.enrolled.config.device, "superseded")
      return again
    }
    const ready = await prepare()
    if ("status" in ready) {
      printActive(ready, { tenant: ready.tenant, workspaceSlug: ready.workspace.slug, workspaceName: ready.workspace.name }, origin, json)
      return EXIT.ok
    }
    let prepared = ready
    const now = new Date()
    const thumbprint = await jwkThumbprint(prepared.attempt.record.jwk as DeviceJwk)
    const fingerprint = fingerprintOf(thumbprint)
    const intervalMs = pollIntervalMs(env)

    // A resumed attempt is looked at once, outside the lock: active
    // finishes, rejected ends, a lapsed renewable lease is renewed in place,
    // and a terminal one gives way to a new attempt with the same key.
    if (prepared.resumed) {
      if (!json) printLine(`Resuming the enrolment this machine started ${minutesAgo(prepared.attempt.record.startedAt, now)}: same key, same link.`)
      let looked: Awaited<ReturnType<typeof followAttempt>> | null = null
      try {
        looked = await followAttempt(prepared.attempt, { deadline: 0, intervalMs, renew: !noRenew })
      } catch (error) {
        if (!(error instanceof CliError && error.code === "expired")) throw error
        const next = await prepare()
        if ("status" in next) {
          printActive(next, { tenant: next.tenant, workspaceSlug: next.workspace.slug, workspaceName: next.workspace.name }, origin, json)
          return EXIT.ok
        }
        prepared = next
      }
      if (looked?.kind === "finished") {
        printActive(activeOutput(looked.finished, fix), looked.finished.config, origin, json)
        return EXIT.ok
      }
    }
    const a = prepared.attempt
    const ask = await attemptAsk(a, env)
    if (json) printJson(pendingOutput(a, ask, fingerprint, prepared))
    else {
      if (prepared.warning) note(`mehen: warning: ${prepared.warning}`)
      if (prepared.superseded) note(`mehen: the unclaimed attempt ${prepared.superseded} was replaced by this one, claimed with the connect code.`)
      printAsk(ask, { env, noQr, then: wait ? `mehen keeps waiting (Ctrl-C is safe: mehen wait ${a.record.id} resumes)` : `mehen wait ${a.record.id}`, expiresNote: noRenew ? "it is not renewed (--no-renew)" : wait ? "mehen keeps it alive while it waits" : `mehen wait ${a.record.id} keeps it alive` })
      for (const line of await fingerprintLines({ thumbprint, code: a.record.code }, styler(colourEnabled(process.stdout, env)))) printLine(line)
      if (a.record.scope) printLine(segments("  ", styler(colourEnabled(process.stdout, env)).dim("scope:".padEnd(LABEL_WIDTH)), ` asks for less than usual: ${requestedScopeWords(a.record.scope)}`))
    }
    if (!wait) return EXIT.ok

    // --wait: follow the attempt from here; the wait's own timeout is exit 4, and
    // mehen wait carries on with the same attempt.
    const deadline = Date.now() + timeout * 1000
    const monitor = new WaitMonitor({ kind: "enrol", id: a.record.id }, { stderr: process.stderr, env, events: false, deadline, expiresAt: a.record.expiresAt, ask, emit: () => undefined })
    monitor.start()
    let followed: Awaited<ReturnType<typeof followAttempt>>
    try {
      followed = await followAttempt(a, { deadline, intervalMs, renew: !noRenew, onPending: (attempt) => monitor.pending(attempt.record.expiresAt, null) })
    } finally {
      monitor.stop()
    }
    if (followed.kind === "waiting") {
      const live = await attemptAsk(a, env)
      throw new CliError("timeout", `Enrolment ${a.record.id} is still waiting for a human${timeout > 0 ? ` after ${durationText(timeout)}` : ""}.`, { command: `mehen wait ${a.record.id} --timeout 60 --json`, say: "A human has not accepted it yet; relay the link again and run `mehen wait` until they do." }, { ask: live })
    }
    printActive(activeOutput(followed.finished, fix), followed.finished.config, origin, json)
    return EXIT.ok
  },
}
