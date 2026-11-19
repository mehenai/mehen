// The MCP server's per-slot latch table and the
// one place a call's slot is chosen and checked against the disk. A server
// spans every slot the ceiling admitted at start; each slot is latched on
// its first successful validation (or by the enrolment vault_wait finished)
// and refused for the rest of the process once its enrolment changed device
// or vanished, while the other slots keep serving. A slot that appears later
// is served only when the admission resolved at start admits it: an entry
// that resolved to an origin and workspace id admits nothing else, so the
// ceiling never widens inside a running server. Every path that
// can sign, cache, diagnose or finish runs through validateSlot or
// latchActivated first. Nothing here loads a key.

import { realpathSync } from "node:fs"
import { join, relative } from "node:path"
import { OwnerRefSchema, normaliseWorkspaceSlug } from "@mehen/protocol/workspace"
import { z } from "zod"
import { BACKENDS, type Config, type Env, isConfig, readConfig, workspaceLabel } from "../config.ts"
import type { VaultFileOptions } from "../agent-profiles.ts"
import { CliError } from "../errors.ts"
import { managedHost, originKey, resolveHome, rootAboveSlot } from "../home.ts"
import { type ManifestWorkspace, manifestWorkspace } from "../run/manifest.ts"
import { assertKeyScopeAgrees, notEnrolled } from "../session.ts"
import {
  type Allowed,
  type FoundActive,
  type FoundCorrupt,
  type FoundPending,
  type FoundSlot,
  allowedSlots,
  assertVaultUrlAgrees,
  contextAmbiguous,
  contextMatches,
  listSlots,
  selectSlot,
  workspaceMismatch,
  workspaceNotAllowed,
  workspaceSelector,
  workspaceUnbound,
  workspaceUnknown,
} from "../slots.ts"
import type { Admission, CallSelection, Latched, McpLatchState, McpPin, McpServer, SeenSlot, SlotBinding, Span, SpanSlot } from "./shared.ts"

const WORKSPACE_ID = /^tn_[A-Za-z0-9]{8,40}$/

// ---- start ------------------------------------------------------------

function slotOrigin(found: FoundActive | FoundPending): string {
  return found.state === "active" ? found.config.vault : found.record.origin
}

// Does a slot answer to a slug or id: an active slot by its id or recorded
// slug, a pending one by the slug it enrols in.
function answers(found: FoundActive | FoundPending, selector: string): boolean {
  if (found.state === "active") return contextMatches(found, selector)
  return !WORKSPACE_ID.test(selector) && found.record.intent.workspace === normaliseWorkspaceSlug(selector)
}

// The admitted set: each ceiling entry with the origin and workspace id it
// resolved to now. A pending slot resolves the origin only.
function admissions(allowed: Allowed): Admission[] | null {
  if (allowed.ceiling === null) return null
  return allowed.ceiling.map((entry) => {
    const matches = allowed.slots.filter((f) => (entry.origin === null || originKey(slotOrigin(f)) === entry.origin) && answers(f, entry.selector))
    const origin = matches[0] ? slotOrigin(matches[0]) : null
    const ids = new Set(matches.filter((f): f is FoundActive => f.state === "active").map((f) => f.config.tenant))
    const workspace = ids.size === 1 ? ([...ids][0] as string) : null
    return { entry: entry.text, origin, workspace, prefix: entry.origin, selector: entry.selector }
  })
}

function realRootOf(root: string): string {
  try {
    return realpathSync(root)
  } catch {
    return root
  }
}

// The server's root, ceiling, pin and startup manifest, resolved once. The
// refusals a command makes with the same environment and cwd happen here,
// before stdin is read: an empty ceiling, a bare entry at two vaults, a pin
// or a manifest outside the ceiling, unknown or disagreeing, an unbound
// manifest under several slots. A server with neither a pin nor a manifest
// starts with any number of slots and chooses per call. `files` is the
// managed-host verification seam (tests only), as for selectSlot.
export async function startServer(env: Env, cwd: string, files: VaultFileOptions = {}): Promise<McpServer> {
  const manifest = manifestWorkspace(cwd)
  const selector = workspaceSelector(env)
  // The pin is the workspace its selector resolved to now, by origin and
  // id: a later rename or a reused slug never moves it.
  const pinOf = (config: Config | null): McpPin | null => (selector !== null && config ? { text: selector, vault: config.vault, tenant: config.tenant } : null)
  const fresh = (home: string, pin: McpPin | null, extra: Pick<McpServer, "managed" | "ceiling" | "allowed">): McpServer => ({ home, pin, manifest, slots: new Map(), seen: new Map(), realRoot: realRootOf(home), ...extra })
  if (managedHost(files)) {
    const selected = await selectSlot(env, { manifest, files })
    const server = fresh(resolveHome(env, { files }).root, pinOf(selected.config), { managed: selected.dir, ceiling: null, allowed: null })
    if (selected.config) latchAtStart(server, selected.dir, selected.config)
    return server
  }
  const allowed = await allowedSlots(env)
  if (allowed.ceiling !== null && allowed.ceiling.length === 0) throw workspaceNotAllowed("Every workspace", allowed.ceiling)
  const selected = selector !== null || manifest !== null ? await selectSlot(env, { manifest }) : null
  const server = fresh(allowed.root, pinOf(selected?.config ?? null), { managed: null, ceiling: allowed.ceiling, allowed: admissions(allowed) })
  // Every active slot the server read at start is latched as it read it: a
  // replacement before its first use is refused like one after it.
  for (const found of allowed.slots) if (found.state === "active") latchAtStart(server, found.dir, found.config)
  return server
}

function latchAtStart(server: McpServer, dir: string, config: Config): void {
  const key = slotKey(server, dir)
  server.slots.set(key, { latched: { vault: config.vault, tenant: config.tenant, device: config.device } })
  server.seen.set(key, { dir, config })
}

// ---- admission ----------------------------------------------------------

// Is a slot inside what the server admitted at start? An entry that
// resolved to a workspace id admits that id at that origin (and a pending
// re-enrolment there); one that resolved to a pending slot admits that
// slug at that origin; an absent entry admits what it names as written.
function admits(server: McpServer, found: FoundActive | FoundPending): boolean {
  return server.allowed === null || server.allowed.some((a) => admitsBy(a, found))
}

function admitsBy(a: Admission, found: FoundActive | FoundPending): boolean {
  if (a.origin === null) return (a.prefix === null || originKey(slotOrigin(found)) === a.prefix) && answers(found, a.selector)
  if (slotOrigin(found) !== a.origin) return false
  if (a.workspace !== null && found.state === "active") return found.config.tenant === a.workspace
  return answers(found, a.selector)
}

export function slotKey(server: McpServer, dir: string): string {
  const rel = relative(server.home, dir)
  return rel.startsWith("..") ? dir : join(server.realRoot, rel)
}

// The slots on disk now that the server admits, plus every latched slot
// that is no longer readable as the active slot it was.
export async function spanSlots(server: McpServer): Promise<Span> {
  const bound = (keys: Set<string>): SpanSlot[] => {
    const extra: SpanSlot[] = []
    for (const key of server.slots.keys()) {
      const seen = server.seen.get(key)
      if (seen && !keys.has(key)) extra.push({ dir: seen.dir, config: seen.config, onDisk: false })
    }
    return extra
  }
  if (server.managed !== null) {
    const dir = server.managed
    const config = await readConfig(dir).catch(() => null)
    const active: SpanSlot[] = config ? [{ dir, config, onDisk: true }] : []
    return { active: [...active, ...bound(new Set(active.map((s) => slotKey(server, s.dir))))], pending: [], corrupt: [], absent: [] }
  }
  const found: FoundSlot[] = await listSlots(server.home)
  const usable = found.filter((f): f is FoundActive | FoundPending => f.state !== "corrupt" && admits(server, f))
  // An absent bare entry now matching slots at two vaults admits neither.
  for (const a of server.allowed ?? []) {
    if (a.origin !== null || a.prefix !== null) continue
    const origins = new Set(usable.filter((f) => answers(f, a.selector)).map(slotOrigin))
    if (origins.size > 1) {
      throw new CliError("context_ambiguous", `MEHEN_WORKSPACES entry ${a.entry} matches workspaces at ${origins.size} vaults: ${[...origins].join(", ")}.`, {
        say: `Name the vault in the entry: ${[...origins].map((o) => `${originKey(o)}/${a.selector}`).join(" or ")}, and restart the agent.`,
      })
    }
  }
  const active: SpanSlot[] = usable.filter((f): f is FoundActive => f.state === "active").map((f) => ({ dir: f.dir, config: f.config, onDisk: true }))
  const keys = new Set(active.map((s) => slotKey(server, s.dir)))
  // A latched slot's directory read as pending again is that slot's tombstone, not a new enrolment.
  const pending = usable.filter((f): f is FoundPending => f.state === "pending" && !server.slots.has(slotKey(server, f.dir)))
  const corrupt = found.filter((f): f is FoundCorrupt => f.state === "corrupt" && !server.slots.has(slotKey(server, f.dir)))
  const absent = (server.allowed ?? []).filter((a) => !usable.some((f) => admitsBy(a, f)))
  return { active: [...active, ...bound(keys)], pending, corrupt, absent }
}

// ---- choosing a call's slot ---------------------------------------------

// A `workspace` argument, spelled as MEHEN_WORKSPACE is.
export function workspaceArgument(value: string): string {
  return workspaceSelector({ MEHEN_WORKSPACE: value }) as string
}

function spanAnswers(slot: SpanSlot, selector: string): boolean {
  return contextMatches(slot, selector)
}

// Is a selector inside the ceiling: an admitted slot answers it, or an
// admitted entry names it.
function selectorAllowed(server: McpServer, span: Span, selector: string): boolean {
  if (server.allowed === null) return true
  if (span.active.some((s) => spanAnswers(s, selector)) || span.pending.some((p) => answers(p, selector))) return true
  return server.allowed.some((a) => a.selector === selector || a.workspace === selector)
}

function manifestAllowed(server: McpServer, span: Span, manifest: ManifestWorkspace & { workspace: string }): boolean {
  if (server.allowed === null) return true
  if (span.active.some((s) => s.config.tenant === manifest.workspace && (manifest.vault === null || s.config.vault === manifest.vault))) return true
  return server.allowed.some((a) => (a.workspace === manifest.workspace || a.selector === manifest.workspace) && (manifest.vault === null || a.origin === null || a.origin === manifest.vault))
}

function exactlyOne(selector: string, matches: SpanSlot[], span: Span): SpanSlot {
  if (matches.length === 1) return matches[0] as SpanSlot
  if (matches.length > 1) throw contextAmbiguous(selector, matches)
  throw workspaceUnknown(selector, span.pending.find((p) => answers(p, selector)))
}

function slotLabel(slot: SpanSlot): string {
  return `${workspaceLabel(slot.config)} at ${slot.config.vault}`
}

// Several active slots and nothing in the call selects one (rule 6).
function callAmbiguous(active: SpanSlot[]): CliError {
  const choices = [...new Set(active.map((s) => s.config.workspaceSlug ?? s.config.tenant))].map((s) => `workspace: "${s}"`).join(", ")
  return new CliError("context_ambiguous", `This server may use ${active.length} workspaces and nothing in this call selects one: ${active.map(slotLabel).join("; ")}.`, {
    say: `Pass workspace in the call (${choices}); vault_status lists them. A checkout bound with \`mehen workspace bind\` selects its own.`,
  })
}

// No active slot (rule 7): the one pending enrolment's wait, or enrol.
function nothingActive(span: Span): CliError {
  const only = span.pending.length === 1 ? span.pending[0] : undefined
  if (only) {
    return new CliError("unauthenticated", `No workspace is active for this server yet; enrolment ${only.record.id} in ${only.record.intent.workspace} waits for approval.`, {
      command: `mehen wait ${only.record.id}`,
      say: `Relay the enrolment link to the human, then call vault_wait with id ${only.record.id} until it is approved.`,
    })
  }
  return notEnrolled()
}

// The slot one call uses: the argument; else the server's
// pin; else the manifest (the startup cwd's, or vault_env's own); else the
// only active slot; else context_ambiguous. An unbound manifest under
// several slots refuses first, as in the CLI.
export async function resolveSlot(server: McpServer, workspace: string | null | undefined, selection: CallSelection = {}): Promise<SpanSlot> {
  const span = await spanSlots(server)
  const manifest = selection.manifest !== undefined ? selection.manifest : server.manifest
  const active = span.active
  if (manifest && manifest.workspace === null && active.length > 1) throw workspaceUnbound(manifest.path)
  const argument = workspace ? workspaceArgument(workspace) : null
  let chosen: SpanSlot
  const pin = server.pin
  if (pin !== null) {
    // The pinned identity alone; an argument must name it.
    const mine = active.filter((s) => isPinned(server, s))
    if (argument !== null) {
      if (!selectorAllowed(server, span, argument)) throw workspaceNotAllowed(`Workspace ${argument}`, server.ceiling ?? [])
      if (!mine.some((s) => spanAnswers(s, argument))) throw pinMismatch(pin, argument)
    }
    if (mine.length > 1) throw contextAmbiguous(pin.text, mine)
    const only = mine[0]
    if (!only) throw workspaceUnknown(pin.text)
    chosen = only
  } else if (argument !== null) {
    if (!selectorAllowed(server, span, argument)) throw workspaceNotAllowed(`Workspace ${argument}`, server.ceiling ?? [])
    if (server.managed !== null && !active.some((s) => spanAnswers(s, argument))) {
      throw workspaceMismatch(`This host is managed: workspace ${argument} is not the pinned workspace.`, { say: "Leave workspace out of the call; a managed agent uses its pinned workspace only." })
    }
    chosen = exactlyOne(argument, active.filter((s) => spanAnswers(s, argument)), span)
  } else if (manifest?.workspace) {
    const bound = { ...manifest, workspace: manifest.workspace }
    if (!manifestAllowed(server, span, bound)) throw workspaceNotAllowed(`${manifest.path} names workspace ${manifest.workspace}, which`, server.ceiling ?? [])
    chosen = exactlyOne(manifest.workspace, active.filter((s) => s.config.tenant === bound.workspace && (bound.vault === null || s.config.vault === bound.vault)), { ...span, pending: [] })
  } else if (active.length === 1) {
    chosen = active[0] as SpanSlot
  } else if (active.length > 1) {
    throw callAmbiguous(active)
  } else {
    throw nothingActive(span)
  }
  if (selection.strict && manifest?.workspace) {
    const origin = manifest.vault ?? chosen.config.vault
    if (chosen.config.tenant !== manifest.workspace || chosen.config.vault !== origin) {
      throw workspaceMismatch(`${manifest.path} belongs to workspace ${manifest.workspace}${manifest.vault ? ` at ${manifest.vault}` : ""}, but this call uses ${slotLabel(chosen)}.`, {
        say: `Leave workspace out of the call so the checkout's own workspace is used, or call from a checkout of ${workspaceLabel(chosen.config)}.`,
      })
    }
  }
  return chosen
}

// What a spanning tool covers: with a workspace argument, that workspace's
// slots; with a pin, the pinned workspace's; else the whole span.
export async function narrowedSpan(server: McpServer, workspace: string | null | undefined): Promise<Span> {
  const span = await spanSlots(server)
  const argument = workspace ? workspaceArgument(workspace) : null
  const narrow = (from: Span, selector: string): Span => ({
    active: from.active.filter((s) => spanAnswers(s, selector)),
    pending: from.pending.filter((p) => answers(p, selector)),
    corrupt: [],
    absent: from.absent.filter((a) => a.selector === selector),
  })
  // A pinned server spans its pinned identity alone: no pending slot,
  // absent entry or other slot answering the pin's text is its workspace.
  const pin = server.pin
  const pinned = (): Span => ({ active: span.active.filter((s) => isPinned(server, s)), pending: [], corrupt: [], absent: [] })
  if (argument === null) return pin === null ? span : pinned()
  if (!selectorAllowed(server, span, argument)) throw workspaceNotAllowed(`Workspace ${argument}`, server.ceiling ?? [])
  if (pin !== null) {
    const mine = pinned()
    if (!mine.active.some((s) => spanAnswers(s, argument))) throw pinMismatch(pin, argument)
    return mine
  }
  const named = narrow(span, argument)
  if (named.active.length + named.pending.length + named.absent.length === 0) await resolveSlot(server, workspace)
  return named
}

// Is a slot the pinned workspace: its origin and id, never its slug.
export function isPinned(server: McpServer, slot: SpanSlot): boolean {
  return server.pin !== null && slot.config.vault === server.pin.vault && slot.config.tenant === server.pin.tenant
}

export function pinMismatch(pin: McpPin, named: string): CliError {
  return workspaceMismatch(`Workspace ${named} is not the workspace this server is pinned to (MEHEN_WORKSPACE=${pin.text}: ${pin.tenant} at ${pin.vault}).`, {
    say: "Leave workspace out of the call, or have the harness start the server without MEHEN_WORKSPACE (or `mehen mcp --workspace`) to use several workspaces.",
  })
}

// ---- the latch ---------------------------------------------------------

function same(a: Latched, b: Pick<Config, "vault" | "tenant" | "device">): boolean {
  return a.vault === b.vault && a.tenant === b.tenant && a.device === b.device
}

function refusedError(server: McpServer, key: string, refused: { reason: string; since: string }): CliError {
  const seen = server.seen.get(key)
  const what = seen ? `${workspaceLabel(seen.config)} at ${seen.config.vault} as ${seen.config.device} in ${seen.dir}` : key
  return new CliError("workspace_mismatch", `This server latched ${what}; ${refused.reason}.`, {
    say: "Restart the agent to use what is on disk now: a running server never changes the identity it serves for a workspace. Every other workspace keeps working.",
  })
}

// A latched slot's refusal reasons, in the same words whichever image
// found them.
const goneFrom = (dir: string) => `the enrolment in ${dir} is gone`
const changedIn = (dir: string, c: Config) => `the enrolment in ${dir} changed to ${c.device} in ${c.tenant} at ${c.vault}`

// Refuses the slot for the life of the process.
function tombstone(server: McpServer, key: string, reason: string): CliError {
  const refused = { reason, since: new Date().toISOString() }
  server.slots.set(key, { refused })
  return refusedError(server, key, refused)
}

function identity(config: Pick<Config, "vault" | "tenant" | "device">): Latched {
  return { vault: config.vault, tenant: config.tenant, device: config.device }
}

// Does a config belong where it was found: a workspaces/<origin>/<id> slot
// holds that origin and id, a pending/<origin>/<slug> slot that origin; a
// managed host's pinned directory was verified by rule 0 at start.
function slotHolds(server: McpServer, dir: string, config: Config): boolean {
  if (server.managed !== null && dir === server.managed) return true
  const above = rootAboveSlot(dir)
  let origin: string
  try {
    origin = originKey(config.vault)
  } catch {
    return false
  }
  if (above?.kind === "workspaces") return above.parts[0] === origin && above.parts[1] === config.tenant
  if (above?.kind === "pending") return above.parts[0] === origin
  return false
}

// The one guarded commit of a slot's latch, made synchronously against the
// table as it is now (never a snapshot taken before an await): a tombstone
// stays, a different latch is never overwritten (the slot is refused
// instead), and an empty entry takes this identity.
function commitLatch(server: McpServer, key: string, dir: string, config: Config, differs: string): void {
  const current = server.slots.get(key)
  if (current && "refused" in current) throw refusedError(server, key, current.refused)
  if (current && !same(current.latched, config)) throw tombstone(server, key, differs)
  if (!current) server.slots.set(key, { latched: identity(config) })
  server.seen.set(key, { dir, config })
}

// The slot's enrolment as it is now, latched on first use. Throws
// workspace_mismatch for a tombstoned slot, and tombstones a latched slot
// whose enrolment is gone or replaced. The enrolment read now must still be
// the one the call selected (`slot.config`), belong in its directory and be
// inside the admission frozen at start: an outside identity is
// workspace_not_allowed and a drifted one workspace_mismatch, and neither
// is latched or opened. The origin and key-scope guards run on every call;
// their refusal leaves the latch as it is.
export async function validateSlot(env: Env, server: McpServer, slot: SpanSlot): Promise<Config> {
  const key = slotKey(server, slot.dir)
  const binding: SlotBinding | undefined = server.slots.get(key)
  if (binding && "refused" in binding) throw refusedError(server, key, binding.refused)
  let config: Config | null
  try {
    config = await readConfig(slot.dir)
  } catch {
    config = null
  }
  const changed = (c: Config) => changedIn(slot.dir, c)
  if (binding) {
    if (!config) throw tombstone(server, key, goneFrom(slot.dir))
    if (!same(binding.latched, config)) throw tombstone(server, key, changed(config))
  } else if (!config) {
    throw notEnrolled()
  }
  if (!admits(server, { state: "active", dir: slot.dir, config })) throw workspaceNotAllowed(`Workspace ${workspaceLabel(config)} at ${config.vault}`, server.ceiling ?? [])
  if (!same(identity(slot.config), config)) {
    throw workspaceMismatch(`The enrolment in ${slot.dir} changed between this call's choice of ${workspaceLabel(slot.config)} at ${slot.config.vault} and its use: it is now ${config.device} in ${config.tenant} at ${config.vault}.`, {
      say: "Call again; vault_status shows what this server may use now.",
    })
  }
  if (!slotHolds(server, slot.dir, config)) throw workspaceMismatch(`${slot.dir} holds an enrolment in ${config.tenant} at ${config.vault}, which does not belong in that directory.`)
  assertVaultUrlAgrees(env, config)
  await assertKeyScopeAgrees(slot.dir, config)
  // Same identity: display fields follow the disk (a rename refreshed by status).
  commitLatch(server, key, slot.dir, config, changed(config))
  return config
}

// Commits the identity vault_wait just activated in `dir`: the
// latch takes exactly that identity, never whatever is on disk after an
// await. A different latch there refuses, and a different enrolment that
// landed after the commit tombstones the slot, so neither is served.
export async function latchActivated(env: Env, server: McpServer, dir: string, activated: Config): Promise<Config> {
  const key = slotKey(server, dir)
  if (!slotHolds(server, dir, activated)) throw workspaceMismatch(`${dir} is not the slot for ${activated.tenant} at ${activated.vault}.`)
  if (!admits(server, { state: "active", dir, config: activated })) throw workspaceNotAllowed(`Workspace ${workspaceLabel(activated)} at ${activated.vault}`, server.ceiling ?? [])
  const notOurs = `the enrolment ${activated.device} finished in ${dir} is not the one this server serves`
  commitLatch(server, key, dir, activated, notOurs)
  const onDisk = await readConfig(dir).catch(() => null)
  if (!onDisk) throw tombstone(server, key, goneFrom(dir))
  if (!same(identity(activated), onDisk)) throw tombstone(server, key, `another enrolment (${onDisk.device}) landed in ${dir} after this one was recorded`)
  assertVaultUrlAgrees(env, onDisk)
  await assertKeyScopeAgrees(dir, onDisk)
  commitLatch(server, key, dir, onDisk, notOurs)
  return onDisk
}

// Whether two configs of the same identity differ only in what they display.
export function displayChanged(cached: Config, current: Config): boolean {
  return cached.workspaceSlug !== current.workspaceSlug || cached.workspaceName !== current.workspaceName || JSON.stringify(cached.owner ?? null) !== JSON.stringify(current.owner ?? null)
}

// ---- McpLatchState --------------------------------------------------------

const LatchedSchema = z.strictObject({ vault: z.string(), tenant: z.string(), device: z.string() })
// A slot's enrolment as the old image last saw it: identity and display
// fields only, each as a config on disk may hold it.
const SeenConfigSchema = z
  .strictObject({ vault: z.string(), tenant: z.string(), device: z.string(), backend: z.enum(BACKENDS), fingerprint: z.string().optional(), name: z.string().optional(), workspaceSlug: z.string().optional(), workspaceName: z.string().optional(), owner: OwnerRefSchema.optional() })
  .refine(isConfig)
const McpLatchStateSchema = z.strictObject({
  v: z.literal(1),
  home: z.string(),
  allowed: z.array(z.strictObject({ entry: z.string(), origin: z.string().nullable(), workspace: z.string().nullable() })).nullable(),
  pin: z.strictObject({ text: z.string(), vault: z.string(), tenant: z.string() }).nullable(),
  manifest: z.strictObject({ path: z.string(), workspace: z.string().nullable(), vault: z.string().nullable() }).nullable(),
  slots: z.record(z.string(), z.union([z.strictObject({ latched: LatchedSchema }), z.strictObject({ refused: z.strictObject({ reason: z.string(), since: z.string() }) })])),
  seen: z.record(z.string(), z.strictObject({ dir: z.string(), config: SeenConfigSchema })).optional(),
})

// The fields of a config `seen` carries; anything else a config file holds
// stays behind.
function seenConfig(config: Config): Config {
  const { vault, tenant, device, backend, fingerprint, name, workspaceSlug, workspaceName, owner } = config
  return { vault, tenant, device, backend, ...(fingerprint === undefined ? {} : { fingerprint }), ...(name === undefined ? {} : { name }), ...(workspaceSlug === undefined ? {} : { workspaceSlug }), ...(workspaceName === undefined ? {} : { workspaceName }), ...(owner === undefined ? {} : { owner }) }
}

function admitted(server: McpServer): McpLatchState["allowed"] {
  return server.allowed?.map(({ entry, origin, workspace }) => ({ entry, origin, workspace })) ?? null
}

function pinOf(server: McpServer): McpLatchState["pin"] {
  return server.pin ? { text: server.pin.text, vault: server.pin.vault, tenant: server.pin.tenant } : null
}

function manifestOf(server: McpServer): McpLatchState["manifest"] {
  return server.manifest ? { path: server.manifest.path, workspace: server.manifest.workspace, vault: server.manifest.vault } : null
}

export function latchState(server: McpServer): McpLatchState {
  const seen: Record<string, SeenSlot> = {}
  for (const [key, slot] of server.seen) if (server.slots.has(key)) seen[key] = { dir: slot.dir, config: seenConfig(slot.config) }
  return { v: 1, home: server.home, allowed: admitted(server), pin: pinOf(server), manifest: manifestOf(server), slots: Object.fromEntries(server.slots), seen }
}

function stateRefused(why: string): CliError {
  return workspaceMismatch(`The latch state handed to this server does not match what it resolves itself: ${why}.`, { say: "Restart the agent: the new server starts with its own latch table." })
}

// Takes over a previous server's latch table: refused when
// its root, its resolved admitted set (each entry's origin and workspace
// id, not just the strings), its pin (origin and id: a slug reused since
// never moves it) or its startup manifest differ from this server's.
// Every refused slot stays refused; every latched slot is checked against
// the disk now, and one whose enrolment changed or vanished becomes a
// tombstone, in the words a call would have used. `seen` only names
// slots: it must belong to a slot in the table, in that slot's directory,
// and agree with its latch, or the whole state is refused (and with it the
// switch). A refusal names no path: the acceptance check's reason reaches
// the old image's log.
export async function restoreLatchState(server: McpServer, value: unknown): Promise<void> {
  const parsed = McpLatchStateSchema.safeParse(value)
  if (!parsed.success) throw stateRefused("it is not a latch state")
  const state = parsed.data
  if (state.home !== server.home) throw stateRefused("it names another root")
  if (JSON.stringify(state.allowed) !== JSON.stringify(admitted(server))) throw stateRefused("its MEHEN_WORKSPACES entries resolved to other vaults or workspaces")
  if (JSON.stringify(state.pin) !== JSON.stringify(pinOf(server))) throw stateRefused("its pin resolved to another workspace")
  if (JSON.stringify(state.manifest) !== JSON.stringify(manifestOf(server))) throw stateRefused("its startup manifest is not this server's")
  const seen = state.seen ?? {}
  for (const [key, shown] of Object.entries(seen)) {
    const binding = state.slots[key]
    if (!binding) throw stateRefused("it names a slot without a latch for it")
    if (slotKey(server, shown.dir) !== key) throw stateRefused("what it saw for a slot is in another directory")
    if ("latched" in binding && !same(binding.latched, shown.config)) throw stateRefused("what it saw in a slot is not the enrolment it latched")
  }
  for (const [key, binding] of Object.entries(state.slots)) {
    const shown = seen[key]
    server.slots.set(key, binding)
    if (shown) server.seen.set(key, shown)
    if ("refused" in binding) continue
    const dir = shown?.dir ?? key
    const config = await readConfig(key).catch(() => null)
    if (config && !shown) server.seen.set(key, { dir: key, config })
    if (!config) tombstone(server, key, goneFrom(dir))
    else if (!same(binding.latched, config)) tombstone(server, key, changedIn(dir, config))
  }
}

