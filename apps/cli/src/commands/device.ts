// mehen status, mehen revoke and mehen freeze: this machine's identity and the two
// panic buttons a device may press.
//
// `mehen status` spans the allowed set: every active,
// pending and corrupt slot and every absent ceiling entry, each active one
// with its own signed check, which reports and never deletes. With
// --workspace (or MEHEN_WORKSPACE) it is one slot's StatusResult, as
// before. `status(env)` keeps today's shape for the MCP server.
//
// `mehen revoke` retires the selected slot only on a definitive answer: the
// vault revoked the device, or says it was revoked already. Everything else
// leaves the slot and names `mehen workspace forget --slot`.

import { EXIT, type Me, type NextStep } from "@mehen/protocol/api"
import type { PolicyState } from "@mehen/protocol/policy-mode"
import { type OwnerRef, OwnerRefSchema, type WorkspaceRef, WorkspaceRefSchema } from "@mehen/protocol/workspace"
import { requestedBy } from "../ask.ts"
import type { Command } from "../command.ts"
import { isFingerprint } from "@mehen/protocol/fingerprint"
import type { DeviceJwk } from "@mehen/protocol/proof"
import { type Backend, type Config, type Env, configWorkspace, isMachineName, resolveVaultUrl } from "../config.ts"
import { CliError, type CliErrorCode, exitCodeFor, toCliError } from "../errors.ts"
import { managedHost, resolveHome } from "../home.ts"
import { assertSafeRoot, enterRoot, legacyLayout, migrationState } from "../migration.ts"
import { type StatusCli, cliState, statusCli } from "../install-state.ts"
import { isListedAsk, readLedger } from "../ledger.ts"
import { type MandateStatus, mandateProposalsText, mandateStatusText, readMandateStatus } from "../mandate-operations.ts"
import { readPolicyState, policyStateLines } from "../policy-operations.ts"
import { printJson, printLine } from "../output.ts"
import { type ManifestWorkspace, manifestWorkspace } from "../run/manifest.ts"
import { type VaultSession, notEnrolled, openContext, openSession, sessionLabel } from "../session.ts"
import { type AbsentEntry, type ActiveSlot, type CorruptSlot, type EndedSlot, type FoundSlot, type LocalContext, type PendingSlot, allowedSlots, selectSlot, slotView, workspaceSelector } from "../slots.ts"
import { mutateSlot, publicKeyOnDisk } from "./activate.ts"
import { type Segment, colourEnabled, segments, styler } from "../tty.ts"
import { VaultApiError } from "../vault-api.ts"

const BACKEND_LABEL: Record<Backend, string> = { "secure-enclave": "Secure Enclave", software: "software" }

export type StatusResult = {
  vault: string
  tenant: string
  // The workspace and owner as authenticated status names them (design
  // 15.5); null from a vault that does not say yet. The context directory
  // is where this enrolment lives.
  workspace: WorkspaceRef | null
  owner: OwnerRef | null
  context: string
  device: string
  name: string
  backend: Backend
  // The key fingerprint mehen computed from the key at enrolment, else the one
  // the vault holds for this device (GET /v1/me, for a config written
  // before mehen recorded it); null when neither says. `fingerprintFrom` says
  // which: only "enrolment" was computed on this machine.
  fingerprint: string | null
  fingerprintFrom: "enrolment" | "vault" | null
  session: string | null
  frozen: boolean
  scope: Me["scope"]
  // Asks this machine created that are still waiting for a human.
  pending: number
  policyState: PolicyState | null
  // This machine's live mandate (null for none) and how many of its
  // proposals wait for a signer; both absent when the vault would not say.
  mandate?: MandateStatus | null
  mandateProposals?: number
}

// A vault from before /v1/me carried the fingerprint sends none; anything
// that is not four groups of four is ignored rather than printed.
function vaultFingerprint(me: Me): string | null {
  const value: unknown = (me as { fingerprint?: unknown }).fingerprint
  return typeof value === "string" && isFingerprint(value) ? value : null
}

function fingerprintOfStatus(recorded: string | null, fromVault: string | null): Pick<StatusResult, "fingerprint" | "fingerprintFrom"> {
  if (recorded !== null) return { fingerprint: recorded, fingerprintFrom: "enrolment" }
  if (fromVault !== null) return { fingerprint: fromVault, fingerprintFrom: "vault" }
  return { fingerprint: null, fingerprintFrom: null }
}

// The workspace and owner /v1/me carries once the vault speaks workspaces:
// both read defensively, and the workspace only when its id is this
// context's own, so a label never changes or stands in for the stored id
// (design 15.5). Anything else leaves the recorded display fields alone.
function meWorkspace(me: Me, config: Config): { workspace: WorkspaceRef | null; owner: OwnerRef | null } {
  const raw = me as { workspace?: unknown; owner?: unknown }
  const workspace = WorkspaceRefSchema.safeParse(raw.workspace)
  const owner = OwnerRefSchema.safeParse(raw.owner)
  if (!workspace.success || workspace.data.id !== config.tenant || me.tenant !== config.tenant) return { workspace: null, owner: null }
  return { workspace: workspace.data, owner: owner.success ? owner.data : null }
}

// Every status call refreshes the recorded slug, name, owner and machine
// name from authenticated status, so a rename does not strand local
// selection or the name an ask says it was asked by. The
// write goes through mutateSlot: only while the slot still
// holds the device and the key the status call signed with (the session's
// own, never one read after the answer), so a stale answer about a replaced
// device never rewrites the newer one's config. Without that key, nothing.
async function refreshDisplay(dir: string, config: Config, signedWith: DeviceJwk | null, workspace: WorkspaceRef | null, owner: OwnerRef | null, machineName: string | null): Promise<void> {
  if (!workspace || !signedWith) return
  await mutateSlot(dir, { device: config.device, jwk: signedWith }, (current) => {
    const next: Config = { ...current, ...(machineName ? { name: machineName } : {}), workspaceSlug: workspace.slug, workspaceName: workspace.name, ...(owner ? { owner } : {}) }
    return JSON.stringify(next) !== JSON.stringify(current) ? next : current
  })
}

// `mehen workspace list --check`, the command line's refresh of a renamed
// workspace: the authenticated slug and name, and this machine's name,
// replace the recorded ones and nothing else changes. The answer must be for the slot's workspace at its
// origin, and under the slot lock the slot must still hold the device, the
// key the session signed with (as loaded, never one read after the answer),
// and the origin, workspace and backend the session opened; a slot whose
// identity changed meanwhile is workspace_mismatch, a replaced device or
// key or an unknown signing key writes nothing. A vault that
// names no workspace leaves the slot alone.
function namesMismatch(dir: string, answered: string, vaultUrl: string, slot: Pick<Config, "tenant" | "vault">): CliError {
  return new CliError("workspace_mismatch", `The vault at ${vaultUrl} answered for workspace ${answered}, but the slot ${dir} holds ${slot.tenant} at ${slot.vault}; nothing was changed.`, {
    command: "mehen doctor --json",
    say: "This slot's enrolment does not match what the vault says; mehen changed nothing. Run `mehen doctor --json` and tell the human.",
  })
}

async function refreshNames(dir: string, config: Config, vaultUrl: string, me: Me, signedWith: DeviceJwk | null): Promise<void> {
  const named = WorkspaceRefSchema.safeParse((me as { workspace?: unknown }).workspace)
  const answered = named.success ? named.data.id : me.tenant
  if (vaultUrl !== config.vault || me.tenant !== config.tenant || answered !== config.tenant) throw namesMismatch(dir, answered, vaultUrl, config)
  const machineName = isMachineName(me.name) ? me.name : null
  if (!named.success || (named.data.slug === config.workspaceSlug && named.data.name === config.workspaceName && (machineName === null || machineName === config.name))) return
  if (!signedWith) return
  const workspace = named.data
  await mutateSlot(dir, { device: config.device, jwk: signedWith }, (current) => {
    if (current.vault !== config.vault || current.tenant !== config.tenant || current.backend !== config.backend) throw namesMismatch(dir, answered, vaultUrl, current)
    return { ...current, ...(machineName ? { name: machineName } : {}), workspaceSlug: workspace.slug, workspaceName: workspace.name }
  })
}

// `persist: false` is the observational form (mehen status, whoami and
// the spanning checks): the authenticated slug, name and owner are
// shown and nothing is written or locked. The default keeps the refresh
// for the MCP server's vault_status, whose latch follows a rename.
// `refreshNames` (with `persist: false`) is `mehen workspace list --check`'s.
export type StatusOptions = { persist?: boolean; refreshNames?: boolean }

export async function status(env: Record<string, string | undefined>, opened?: VaultSession, options: StatusOptions = {}): Promise<StatusResult> {
  const session = opened ?? (await openSession(env))
  const { api, config, vaultUrl, configDir, ledger: scope, signedWith } = session
  const me = await api.request<Me>("GET", "/v1/me")
  if (options.refreshNames) await refreshNames(configDir, config, vaultUrl, me, signedWith ?? null)
  const { workspace, owner } = meWorkspace(me, config)
  if (options.persist !== false) await refreshDisplay(configDir, config, signedWith ?? null, workspace, owner, isMachineName(me.name) ? me.name : null)
  const ledger = (await readLedger(configDir, scope)).filter(isListedAsk)
  const [policyState, mandate] = await Promise.all([readPolicyState(api, vaultUrl, me), readMandateStatus(session)])
  return {
    vault: vaultUrl,
    tenant: me.tenant,
    workspace: workspace ?? configWorkspace(config),
    owner: owner ?? config.owner ?? null,
    context: configDir,
    device: me.device,
    name: me.name,
    backend: config.backend,
    ...fingerprintOfStatus(config.fingerprint ?? null, vaultFingerprint(me)),
    session: sessionLabel(env),
    frozen: me.frozen,
    scope: me.scope,
    pending: ledger.length,
    policyState,
    ...mandate,
  }
}

// Every value here came from the vault or the config file. Each line is one
// list of segments, so the terminal boundary spells every value out and a
// newline inside one cannot start a line of its own.
// `place` names the directory line: "context" for the MCP server's shape,
// "slot" for the published one.
export function statusLines(result: StatusResult, colour = styler(false), place: "context" | "slot" = "context"): Segment[][] {
  const { scope } = result
  const { privateCredentials } = scope as { privateCredentials?: unknown }
  const where = result.workspace ? `${result.workspace.name} (${result.workspace.slug})` : `workspace ${result.tenant}`
  const owned = result.owner ? `, owned by ${result.owner.name}${result.owner.kind === "team" ? " (team)" : ""}` : ""
  const lines = [
    segments(`${result.name} (${result.device}, ${BACKEND_LABEL[result.backend]} key) in ${where} at ${result.vault}${owned}`),
    segments(`  workspace id:    ${result.tenant}`),
    segments(`  ${`${place}:`.padEnd(17)}${result.context}`),
    segments(
      "  key fingerprint: ",
      ...(result.fingerprint
        ? [colour.bold(result.fingerprint), result.fingerprintFrom === "vault" ? " (as the vault holds it; this enrolment did not record it)" : ""]
        : ["unknown (the vault did not say and this enrolment did not record it; compare the words on the Machines page)"]),
    ),
    segments(`  session:         ${result.session ? `${result.session} (MEHEN_SESSION)` : "none (set MEHEN_SESSION so the human can tell this agent's asks apart)"}`),
    segments(`  items:           ${scope.tags.length ? `tagged ${scope.tags.join(", ")}` : "all"}`),
    segments(`  projects:        ${scope.projects.length ? scope.projects.join(", ") : "all"}`),
    segments(`  environments:    ${String(scope.maxEnvironment)}`),
    segments(`  modes:           ${scope.modes.join(", ")}`),
    ...(typeof privateCredentials === "boolean" ? [segments(`  private:         ${privateCredentials ? "yes" : "no (ask with --home project or workspace)"}`)] : []),
    segments(`  pending:         ${result.pending === 0 ? "nothing waiting for a human" : `${result.pending} ask${result.pending === 1 ? "" : "s"} waiting for a human (mehen pending)`}`),
  ]
  // Policy windows were replaced by standing rules (mehen policy ls); a vault
  // that does not report them prints no line rather than "unavailable".
  if (result.policyState) for (const line of policyStateLines(result.policyState)) lines.push(segments(`  ${line}`))
  if (result.mandate !== undefined) lines.push(segments(`  mandate:         ${result.mandate ? mandateStatusText(result.mandate) : "none"}`))
  if (result.mandateProposals) lines.push(segments(`  proposals:       ${mandateProposalsText(result.mandateProposals)}`))
  if (result.frozen) lines.push(segments("  The workspace is ", colour.danger("FROZEN"), ": every use is refused until a human unfreezes it in the vault."))
  return lines
}

// ---- across the allowed set ------------------------------

// One slot's StatusResult as it is published: `context` is `slot`.
export type SlotStatus = Omit<StatusResult, "context"> & { slot: string }
// Nothing in a check is ever deleted: a failing check is reported only.
export type VaultCheck = { ok: true; status: SlotStatus } | { ok: false; error: CliErrorCode; message: string; next: NextStep | null }
export type StatusEntry = (ActiveSlot & { check: VaultCheck }) | PendingSlot | CorruptSlot | EndedSlot | AbsentEntry
export type StatusAll = { home: string; allowed: string[] | null; workspaces: StatusEntry[]; selected: string | null; next: NextStep | null; cli: StatusCli }

export function slotStatus(result: StatusResult): SlotStatus {
  const { context: slot, ...rest } = result
  return { ...rest, slot }
}

// The signed GET /v1/me of one active slot, with the origin and key-scope
// checks of every session first; any refusal is the check's answer.
export async function slotCheck(env: Env, context: LocalContext, options: { refreshNames?: boolean } = {}): Promise<VaultCheck> {
  try {
    const session = await openContext(env, { ...context, reason: "workspace" }, { observe: true })
    return { ok: true, status: slotStatus(await status(env, session, { persist: false, ...(options.refreshNames ? { refreshNames: true } : {}) })) }
  } catch (error) {
    const failure = toCliError(error)
    return { ok: false, error: failure.code, message: failure.message, next: failure.next }
  }
}

export function absentEntry(text: string, selector: string): AbsentEntry {
  const slug = selector.startsWith("tn_") ? "<slug>" : selector
  return { state: "absent", entry: text, next: { command: `mehen enrol --workspace ${slug}`, say: `MEHEN_WORKSPACES allows ${text}, but this machine is not enrolled in it; \`mehen enrol --workspace ${slug}\` starts the enrolment.` } }
}

// The slot that commands needing one workspace would use here, or null
// when nothing (or nothing unambiguous) is selected.
async function selectedSlot(env: Env, manifest: ManifestWorkspace | null): Promise<string | null> {
  try {
    const selected = await selectSlot(env, { manifest })
    return selected.config ? selected.dir : null
  } catch {
    return null
  }
}

// The first active workspace's failed check when no active workspace's
// check passed: nothing this machine is in can be used now.
export function allChecksFailed(entries: StatusEntry[]): Extract<VaultCheck, { ok: false }> | null {
  const active = entries.filter((e): e is ActiveSlot & { check: VaultCheck } => e.state === "active")
  if (active.length === 0 || active.some((e) => e.check.ok)) return null
  const first = active[0]?.check
  return first && !first.ok ? first : null
}

// What to do when no slot is active: wait on the one pending enrolment, or
// enrol (again, with the kept key, for the one attempt that ended).
export function statusNext(entries: StatusEntry[], vaultUrl: string): NextStep | null {
  const failed = allChecksFailed(entries)
  if (failed) return failed.next ?? { command: "mehen doctor --json", say: "No workspace this machine is in answered; `mehen doctor --json` names the fix." }
  if (entries.some((e) => e.state === "active")) return null
  const pending = entries.filter((e): e is PendingSlot => e.state === "pending")
  const first = pending[0]
  if (pending.length === 1 && first) return { command: `mehen wait ${first.enrolment}`, say: `Relay the enrolment link (${first.ask.url}) to the human and run \`mehen wait ${first.enrolment}\` until it is approved.` }
  if (first) return { command: "mehen pending", say: "Several enrolments wait for approval; `mehen pending` lists their links and the `mehen wait` for each." }
  const ended = entries.filter((e): e is EndedSlot => e.state === "ended")
  if (ended.length === 1 && ended[0]) return ended[0].next
  return notEnrolled(vaultUrl).next
}

// status and whoami never migrate (cli.ts exempts them): they read
// the root as it is. The same safety refusal as the entry sequence comes
// first; a root that is not on the workspaces layout yet, or holds an
// unfinished or stuck journal, is refused with the command that finishes
// it, and nothing under it is read as slots or written. On a managed host
// the entry sequence itself only reads and refuses, so it is run as is.
export async function assertRootObservable(env: Env): Promise<void> {
  if (managedHost()) {
    await enterRoot(env)
    return
  }
  const { root } = resolveHome(env)
  assertSafeRoot(root)
  const state = await migrationState(root)
  if (state.state === "stuck") throw new CliError("failed", `The migration of ${root} cannot continue: step ${state.stuck?.step} is stuck (${state.stuck?.detail}). Nothing was deleted.`, { command: "mehen doctor --json", say: "Run `mehen doctor --json`: it prints the unfinished migration and the step that cannot continue, without changing anything." })
  if (state.state === "corrupt") throw new CliError("failed", `The migration journal of ${root} cannot be read (${state.stuck?.detail}). Nothing was deleted.`, { command: "mehen doctor --json", say: "Run `mehen doctor --json`: it prints the unfinished migration without changing anything." })
  const move = { command: "mehen workspace list", say: "Run `mehen workspace list`: it moves the config root to the workspaces layout (nothing is sent to a vault), then run `mehen status` again." }
  if (state.state === "journal") throw new CliError("failed", `The migration of ${root} is unfinished; mehen status does not change it.`, move)
  if (await legacyLayout(root)) throw new CliError("failed", `${root} is not on the workspaces layout yet; mehen status does not migrate it.`, move)
}

export async function statusAll(env: Env): Promise<StatusAll> {
  await assertRootObservable(env)
  // A malformed session label or a malformed manifest in the cwd is the
  // process's refusal, not one slot's: nothing is read or sent.
  sessionLabel(env)
  const manifest = manifestWorkspace(process.cwd())
  const device = requestedBy(env).device
  const workspaces: StatusEntry[] = []
  let home: string
  let allowed: string[] | null
  if (managedHost()) {
    // The pinned slot alone, as every other command sees this host.
    const selected = await selectSlot(env, { manifest: null })
    home = resolveHome(env).root
    allowed = null
    if (selected.config) workspaces.push(await entryOf(env, { state: "active", dir: selected.dir, config: selected.config }, device))
  } else {
    const found = await allowedSlots(env)
    home = found.root
    allowed = found.ceiling ? found.ceiling.map((e) => e.text) : null
    for (const slot of [...found.slots, ...found.corrupt] as FoundSlot[]) workspaces.push(await entryOf(env, slot, device))
    for (const entry of found.absent) workspaces.push(absentEntry(entry.text, entry.selector))
  }
  return { home, allowed, workspaces, selected: await selectedSlot(env, manifest), next: statusNext(workspaces, resolveVaultUrl(env, null)), cli: statusCli(await cliState(env)) }
}

async function entryOf(env: Env, found: FoundSlot, device: string): Promise<StatusEntry> {
  const view = await slotView(found, device)
  if (view.state !== "active") return view
  // slotView reports active only for an active slot.
  if (found.state !== "active") throw new CliError("internal", `${found.dir} read as active without a config.`)
  return { ...view, check: await slotCheck(env, { dir: found.dir, config: found.config }) }
}

function slotLabel(workspace: ActiveSlot["workspace"]): string {
  return workspace.slug && workspace.name ? `${workspace.name} (${workspace.slug})` : `workspace ${workspace.id}`
}

// One block per entry, then the CLI itself.
export function statusAllLines(result: StatusAll, vaultUrl: string, colour = styler(false)): Segment[][] {
  const lines: Segment[][] = []
  for (const entry of result.workspaces) {
    if (lines.length) lines.push(segments(""))
    switch (entry.state) {
      case "active":
        if (entry.check.ok) lines.push(...statusLines({ ...entry.check.status, context: entry.check.status.slot }, colour, "slot"))
        else {
          lines.push(segments(`${slotLabel(entry.workspace)} at ${entry.origin} as ${entry.device}: `, colour.danger(entry.check.error), `: ${entry.check.message}`))
          lines.push(segments(`  slot:            ${entry.slot}`))
          if (entry.check.next) lines.push(segments(`  next:            ${entry.check.next.say}`))
        }
        break
      case "pending":
        lines.push(segments(`${entry.intent.workspace} at ${entry.origin}: enrolment ${entry.enrolment} waiting for approval${entry.legacy ? " (from before this version; never renewed)" : ""}`))
        lines.push(segments(`  slot:            ${entry.slot}`))
        lines.push(segments(`  open:            ${entry.ask.url}`))
        lines.push(segments(`  key fingerprint: ${entry.fingerprint}`))
        lines.push(segments(`  then:            mehen wait ${entry.enrolment}`))
        break
      case "corrupt":
        lines.push(segments(`corrupt slot (${entry.reason}): ${entry.detail}`))
        lines.push(segments(`  slot:            ${entry.slot}`))
        lines.push(segments(`  next:            ${entry.next.say}`))
        break
      case "ended":
        lines.push(segments(`${entry.slug}: the enrolment attempt ended; the key is kept`))
        lines.push(segments(`  slot:            ${entry.slot}`))
        lines.push(segments(`  next:            ${entry.next.say}`))
        break
      case "absent":
        lines.push(segments(`${entry.entry}: allowed by MEHEN_WORKSPACES, not enrolled`))
        lines.push(segments(`  next:            ${entry.next.say}`))
        break
    }
  }
  if (result.workspaces.length === 0) lines.push(segments(notEnrolled(vaultUrl).message))
  if (result.next && result.workspaces.length > 0) lines.push(segments(""), segments(`next: ${result.next.say}`))
  else if (result.next) lines.push(segments(`next: ${result.next.say}`))
  lines.push(segments(""), segments(`cli: mehen ${result.cli.version}${result.cli.commit ? ` (${result.cli.commit})` : ""} at ${result.cli.path}`))
  return lines
}

export const statusCommand: Command = {
  summary: "show every workspace this machine is in, or one with --workspace",
  spec: { usage: "mehen status [--workspace <slug or id>]", flags: {}, positionals: { min: 0, max: 0 } },
  examples: [["status"], ["status", "--json"], ["status", "--workspace", "acme"]],
  notes: [
    "Lists every workspace slot this machine may use (active, pending, ended with the key kept, corrupt, and MEHEN_WORKSPACES entries not enrolled yet), each active one checked with the vault; a failing check is reported, never deleted. A workspace is usable when its state is active and check.ok is true. Exit 0, unless every active workspace's check failed: then the first failure's exit code (7 for network), and its error, message and next at the top level.",
    "With --workspace (or MEHEN_WORKSPACE): that one workspace's status; a workspace this machine is not enrolled in is exit 2 (workspace_unknown) with next.command mehen enrol --workspace <slug>, and a revoked or unrecognised machine is exit 6. When something else is wrong, mehen doctor checks everything at once.",
  ],
  async run({ json, env }) {
    if (workspaceSelector(env) !== null) {
      await assertRootObservable(env)
      const result = slotStatus(await status(env, await openSession(env, { observe: true }), { persist: false }))
      if (json) printJson(result)
      else for (const line of statusLines({ ...result, context: result.slot }, styler(colourEnabled(process.stdout, env)), "slot")) printLine(line)
      return EXIT.ok
    }
    const result = await statusAll(env)
    const failed = allChecksFailed(result.workspaces)
    // A non-zero exit carries its failure on top, as every other --json error does.
    if (json) printJson(failed ? { error: failed.error, message: failed.message, ...result } : result)
    else for (const line of statusAllLines(result, resolveVaultUrl(env, null), styler(colourEnabled(process.stdout, env)))) printLine(line)
    return failed ? exitCodeFor(failed.error) : EXIT.ok
  },
}

export const whoamiCommand: Command = {
  ...statusCommand,
  summary: "same as mehen status",
  spec: { ...statusCommand.spec, usage: "mehen whoami" },
  examples: [["whoami", "--json"]],
}

// ---- revoke -------------------------------------------------------

export type RevokeResult = { revoked: string | null; alreadyRevoked: boolean; workspace: WorkspaceRef | null; slot: string; note?: string }

function retireAnyway(error: unknown, slot: string): CliError {
  const e = toCliError(error)
  const say = `To retire this slot anyway, \`mehen workspace forget --slot ${slot}\`; the device then stays on the workspace's Machines page until an owner revokes it.`
  return new CliError(e.code, e.message, { ...(e.next?.command ? { command: e.next.command } : {}), ...(e.next?.url ? { url: e.next.url } : {}), say: `${e.next?.say ? `${e.next.say} ` : ""}${say}` }, e.extras)
}

// POST /v1/devices/self/revoke with the slot's own key, under its lock and
// only while it still holds the device and key the session opened: success
// or a definitive device_revoked from that signed call removes key, config
// and ledger. Every other answer (unauthenticated, proof_invalid, network,
// 5xx, a local refusal) leaves the slot. A crash between the vault's revoke
// and the removal is finished by the next run's device_revoked.
export async function revokeSlot(env: Env): Promise<RevokeResult> {
  const { api, config, configDir } = await openSession(env)
  const jwk = await publicKeyOnDisk(configDir, config.backend)
  let alreadyRevoked = false
  let result: Awaited<ReturnType<typeof mutateSlot>>
  try {
    result = await mutateSlot(configDir, { device: config.device, jwk }, async () => {
      try {
        await api.request<unknown>("POST", "/v1/devices/self/revoke", {})
      } catch (error) {
        if (!(error instanceof VaultApiError && error.body.error === "device_revoked")) throw retireAnyway(error, configDir)
        alreadyRevoked = true
      }
      return null
    })
  } catch (error) {
    throw error instanceof CliError ? error : retireAnyway(error, configDir)
  }
  if (result !== "applied") {
    throw new CliError("failed", `The slot ${configDir} no longer holds device ${config.device}${result === "superseded" ? ": another mehen process replaced it meanwhile" : ""}; nothing was sent and nothing was changed.`, {
      command: "mehen workspace list",
      say: "Another mehen process changed this workspace's slot while this one ran; check `mehen workspace list`, then run the command again.",
    })
  }
  const workspace = configWorkspace(config)
  return alreadyRevoked
    ? { revoked: null, alreadyRevoked: true, workspace, slot: configDir, note: `The vault had already revoked ${config.device}; its key, config and ledger were removed from this machine.` }
    : { revoked: config.device, alreadyRevoked: false, workspace, slot: configDir }
}

export const revokeCommand: Command = {
  summary: "revoke this workspace's device key and forget it locally",
  spec: { usage: "mehen revoke [--workspace <slug or id>]", flags: {}, positionals: { min: 0, max: 0 } },
  examples: [["revoke"], ["revoke", "--workspace", "acme"]],
  notes: [
    "Irreversible for this key: a human must accept a new enrolment before this machine can use the workspace again. Only the selected workspace is revoked; other workspaces' keys stay.",
    "The slot is removed when the vault revokes the device or says it was revoked already; any other answer leaves it, and `mehen workspace forget --slot <path>` retires it without the vault.",
  ],
  async run({ json, env }) {
    const result = await revokeSlot(env)
    const where = result.workspace ? result.workspace.slug : "this workspace"
    if (json) printJson(result)
    else if (result.alreadyRevoked) printLine(`${result.note} Run \`mehen enrol --workspace ${result.workspace?.slug ?? "<slug>"}\` to enrol it again.`)
    else printLine(`Revoked ${result.revoked} in ${where} and removed its key from ${result.slot}. Run \`mehen enrol --workspace ${result.workspace?.slug ?? "<slug>"}\` to enrol it again.`)
    return EXIT.ok
  },
}

export const freezeCommand: Command = {
  summary: "freeze the whole workspace: every use is refused until a human unfreezes it",
  spec: { usage: "mehen freeze", flags: {}, positionals: { min: 0, max: 0 } },
  examples: [["freeze"]],
  notes: ["For an emergency, such as a leaked key or an agent acting strangely. Only a human with a passkey can unfreeze."],
  async run({ json, env }) {
    const { api } = await openSession(env)
    await api.request<unknown>("POST", "/v1/freeze", {})
    if (json) printJson({ frozen: true })
    else printLine("The workspace is frozen. A human must unfreeze it in the vault with their passkey.")
    return EXIT.ok
  },
}
