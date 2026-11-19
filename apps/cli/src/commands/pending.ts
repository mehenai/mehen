// mehen pending: the asks still waiting for a human, listed or re-shown (with
// the QR on a TTY), across every workspace this machine may use. For each
// active slot the vault's GET /v1/pending (V-7) lists that device's open
// intakes, connects and approvals and the slot's ledger fills in what this
// machine asked for; against a vault without the route (a 404) the ledger
// is the whole answer. Every pending slot adds its enrolment's ask.

import { PENDING_RESTRICTION_UNTIL } from "@mehen/protocol"
export { PENDING_RESTRICTION_UNTIL } from "@mehen/protocol"
import { EXIT, type SecurityNotice } from "@mehen/protocol/api"
import { z } from "zod"
import { type Ask, type AskUrl, type AskVault, ROUTE_PREFIX, adoptionAsk, approvalAsk, askGroup, askNext, askUrl, askUrlFor, connectAsk, expiryText, intakeAsk, isWaitId, policyAsk, refusedLinkWarning, requestedBy, withContext } from "../ask.ts"
import type { Command } from "../command.ts"
import { type Env, resolveVaultUrl } from "../config.ts"
import { CliError, type CliErrorCode, toCliError } from "../errors.ts"
import { managedHost } from "../home.ts"
import { type LedgerEntry, findLedgerEntry, readLedger } from "../ledger.ts"
import { normaliseWorkspacePending, workspaceMachineNotices, type MachineAddedNotice } from "../pending-workspace.ts"
import { note, printAsk, printJson, printLine, table } from "../output.ts"
import { type SessionContext, type VaultSession, openContext, sessionContext } from "../session.ts"
import { type FoundPending, type LocalContext, allowedSlots, listActive, pendingIn, slotView } from "../slots.ts"
import { VaultApiError } from "../vault-api.ts"
import { type Text, colourEnabled, styler, visibleText } from "../tty.ts"

// What GET /v1/pending carries per entry (protocol PendingAsk, the four
// kinds a device receives); every field but the kind and id is read
// defensively, since the vault may be older or newer than this mehen.
export type ServerPendingEntry = {
  kind: "intake" | "connect" | "approval" | "policy" | "adoption"
  id: string
  url?: string
  // One sentence, stored text as the agent sent it.
  title?: string | null
  expiresAt?: string | null
  // The machine and agent session that asked, as recorded when the ask was made.
  requestedBy?: { device?: unknown; deviceName?: unknown; session?: unknown } | null
  // The item the ask concerns; null for a run approval.
  item?: string | null
  provider?: string | null
  kindRequested?: string | null
  account?: string | null
  bindingCode?: string | null
  // Adoptions: how many credentials the batch holds.
  items?: number | null
}

export type ServerPending = { pending: unknown[]; notices?: unknown[]; groups?: unknown[] }

// A review group or bundle holding two or more of this machine's open
// approvals (protocol PendingGroup), its link checked against this vault.
export type PendingGroupView = { id: string; url: string; approvals: string[]; bundle: boolean }

// GET /v1/pending's top-level `groups`: a group is kept only when its id is a
// group's or a bundle's, its approvals are approval ids and its link is this
// vault's /g/ page for that id (askGroup); a link that is not is counted.
function serverGroups(raw: unknown, vault: AskVault): { groups: PendingGroupView[]; refusedLinks: number } {
  const groups: PendingGroupView[] = []
  let refusedLinks = 0
  if (!Array.isArray(raw)) return { groups, refusedLinks }
  for (const value of raw) {
    if (typeof value !== "object" || value === null) continue
    const { id, url, approvals, bundle } = value as Record<string, unknown>
    if (!Array.isArray(approvals) || !approvals.every((approval) => isWaitId("approval", approval))) continue
    const checked = askGroup({ id, url, open: approvals.length }, vault)
    if (checked.refusedLink) refusedLinks += 1
    if (checked.group) groups.push({ id: checked.group.id, url: checked.group.url, approvals: [...approvals], bundle: bundle === true })
  }
  return { groups, refusedLinks }
}

// "3 asks from sam-mac-mini: review together at <url>", named for the
// machine that asked the group's first listed ask.
export function pendingGroupText(group: PendingGroupView, asks: readonly Ask[]): string {
  const first = asks.find((ask) => ask.kind === "approval" && group.approvals.includes(ask.id))
  const machine = first?.requestedBy.device ?? "this machine"
  return visibleText(`${group.approvals.length} asks from ${machine}: review together at ${group.url}`)
}

// `restrictedUntil` is an ISO time, the pending sentinel (as the vault sends
// it, a number or its decimal string), or null.
export type DeviceSecurityNotice = Omit<SecurityNotice, "kind" | "canResolve" | "restrictedUntil"> & { kind: "recovery" | "reset" | "break-glass"; restrictedUntil: string | number | null }

// "until recovery completes" for the pending sentinel, "until HH:MM UTC on
// date" for a time, null when there is no restriction.
export function restrictionText(until: string | number | null): string | null {
  if (until === null) return null
  if (until === PENDING_RESTRICTION_UNTIL || until === String(PENDING_RESTRICTION_UNTIL)) return "until recovery completes"
  return `until ${String(until).slice(11, 16)} UTC on ${String(until).slice(0, 10)}`
}

const noticeSchema = z.object({
  notice: z.string().regex(/^ntc_[A-Za-z0-9_-]{1,60}$/),
  kind: z.enum(["recovery", "reset", "break-glass"]),
  member: z.string().regex(/^mem_[A-Za-z0-9_-]{1,60}$/),
  memberName: z.string().transform((text) => text.slice(0, 64)),
  at: z.string().datetime(),
  client: z.string().transform((text) => text.slice(0, 64)).nullable(),
  place: z.string().transform((text) => text.slice(0, 64)).nullable(),
  restrictedUntil: z.union([z.string().datetime(), z.literal(PENDING_RESTRICTION_UNTIL), z.literal(String(PENDING_RESTRICTION_UNTIL))]).nullable(),
  url: z.unknown(),
})

function deviceNotices(raw: unknown, vaultUrl: string): { notices: DeviceSecurityNotice[]; refusedLinks: number } {
  const notices: DeviceSecurityNotice[] = []
  let refusedLinks = 0
  if (!Array.isArray(raw)) return { notices, refusedLinks }
  const fallback = askUrl(`${vaultUrl}/settings#security`, vaultUrl, { purpose: "security-notice" })
  for (const value of raw) {
    const parsed = noticeSchema.safeParse(value)
    if (!parsed.success) continue
    const { url, ...notice } = parsed.data
    const checked = askUrl(url, vaultUrl, { purpose: "security-notice" })
    if (!checked) refusedLinks += 1
    const link = checked ?? fallback
    if (link) notices.push({ ...notice, url: link.url })
  }
  return { notices, refusedLinks }
}

export function securityNoticeText(notice: DeviceSecurityNotice): string {
  const method = notice.kind === "recovery" ? "a recovery code" : notice.kind === "reset" ? "a reset link" : "a break-glass reset link"
  const time = `${notice.at.slice(11, 16)} UTC on ${notice.at.slice(0, 10)}`
  const client = notice.client ? ` using ${notice.client}` : ""
  const place = notice.place ? ` from ${notice.place}` : ""
  const restriction = restrictionText(notice.restrictedUntil)
  const restricted = restriction ? ` Wider actions stay restricted ${restriction}.` : ""
  return visibleText(`Security: ${notice.memberName}'s sign-in was recovered with ${method} at ${time}${client}${place}.${restricted} Not expected? Open ${notice.url} with an older passkey.`)
}

export function pendingNoticeText(notice: DeviceSecurityNotice | MachineAddedNotice): string {
  if (!("payload" in notice)) return securityNoticeText(notice)
  const { payload } = notice
  const origin = new URL(notice.url).origin
  return visibleText(`Machine added: ${payload.name} (${payload.device}) in ${payload.workspace.name} (${payload.workspace.slug}) at ${origin}. Open ${notice.url} to review this machine.`)
}

// An entry mehen can use: a known kind and an id with that kind's prefix and
// alphabet. Anything else is counted and left out.
function isServerEntry(value: unknown): value is ServerPendingEntry {
  if (typeof value !== "object" || value === null) return false
  const e = value as Record<string, unknown>
  return (e.kind === "intake" || e.kind === "connect" || e.kind === "approval" || e.kind === "policy" || e.kind === "adoption") && isWaitId(e.kind, e.id)
}

// Who asked, as the vault recorded it when the ask was made (the session
// label is the one in force then, not now); the caller's own name when the
// entry has none.
function entryRequestedBy(entry: ServerPendingEntry, fallback: Ask["requestedBy"]): Ask["requestedBy"] {
  const by = entry.requestedBy
  if (!by || typeof by.deviceName !== "string") return fallback
  return { device: by.deviceName, session: typeof by.session === "string" ? by.session : null }
}

// The vault's entry as an Ask; the ledger's version wins where it has one,
// since it knows what the command asked and why. The entry's url is taken
// only when askUrl accepts it against this vault; otherwise the link is
// built from the id, and `refusedLink` tells the caller to warn. An id the
// link cannot be built from yields no ask.
export function askFromServerEntry(entry: ServerPendingEntry, vaultUrl: AskVault, by: Ask["requestedBy"], ledger: LedgerEntry | null): { ask: Ask | null; refusedLink: boolean } {
  // The entry's link counts only when its route is this entry's id.
  const given = askUrl(entry.url, vaultUrl)
  const matching = given && given.route && given.route.prefix === ROUTE_PREFIX[entry.kind] && given.route.id === entry.id ? given : null
  const refusedLink = entry.url !== undefined && matching === null
  const link = matching ?? askUrlFor(vaultUrl, entry.kind, entry.id)
  if (!link) return { ask: null, refusedLink }
  const url = link.url
  const expiresAt = typeof entry.expiresAt === "string" ? entry.expiresAt : (ledger?.ask.expiresAt ?? null)
  if (ledger) return { ask: { ...ledger.ask, url, expiresAt }, refusedLink }
  return { ask: buildFromServerEntry(entry, url, expiresAt, entryRequestedBy(entry, by)), refusedLink }
}

function buildFromServerEntry(entry: ServerPendingEntry, url: AskUrl, expiresAt: string | null, by: Ask["requestedBy"]): Ask {
  if (entry.kind === "policy") {
    return policyAsk({ id: entry.id, url, summary: entry.title ?? "Allow from now on", bindingCode: entry.bindingCode ?? null, expiresAt, requestedBy: by })
  }
  if (entry.kind === "adoption") {
    const items = typeof entry.items === "number" && Number.isInteger(entry.items) && entry.items >= 0 ? entry.items : 0
    return adoptionAsk({ id: entry.id, url, items, machine: by.device, expiresAt, requestedBy: by })
  }
  if (entry.kind === "approval") {
    return approvalAsk({ id: entry.id, url, summary: entry.title ?? "Approve a request", bindingCode: entry.bindingCode ?? null, item: entry.item ?? null, account: entry.account ?? null, expiresAt, requestedBy: by })
  }
  if (entry.kind === "connect") {
    return connectAsk({ id: entry.id, url, name: entry.item ?? "the connection", provider: entry.provider ?? "an account", account: entry.account ?? null, reason: null, expiresAt, requestedBy: by })
  }
  return intakeAsk({ id: entry.id, url, name: entry.item ?? "the credential", kind: entry.kindRequested ?? "credential", provider: entry.provider ?? null, reason: null, expiresAt, requestedBy: by })
}

// An open ask and the item slug it creates, when known, for lookup by slug.
export type PendingItem = { ask: Ask; slug: string | null }

// `refusedLinks` counts server entries whose url was not on this vault;
// `unavailable` names each workspace whose vault could not be asked (its
// own ledger stands in for it).
// `groups`: the review groups and bundles of the vault's list, each of whose
// asks carries the group on `ask.group`.
export type PendingList = { items: PendingItem[]; notices: (DeviceSecurityNotice | MachineAddedNotice)[]; groups: PendingGroupView[]; source: "vault" | "ledger"; vaultUrl: string; refusedLinks: number; unavailable: { slot: string; error: CliErrorCode; message: string }[] }

type SlotPending = Omit<PendingList, "vaultUrl" | "unavailable">

// One active slot: the vault's list merged with the slot's ledger when the
// route exists, the ledger alone when it does not (404). Every ask carries
// the slot's context.
async function slotPending(env: Env, slot: LocalContext, now: Date, open: PendingSpan["open"]): Promise<SlotPending> {
  const { api, ledger: scope, context, vaultUrl } = await open(slot)
  const ledger = await readLedger(slot.dir, scope, now)
  let server: ServerPending
  try {
    server = await api.request<ServerPending>("GET", "/v1/pending")
  } catch (error) {
    if (error instanceof VaultApiError && error.status === 404) return { items: fromLedger(ledger, context), notices: [], groups: [], source: "ledger", refusedLinks: 0 }
    throw error
  }
  const by = requestedBy(env, slot.config.name ?? null)
  const listed = Array.isArray(server.pending) ? server.pending : []
  const normalised = normaliseWorkspacePending(listed, context)
  const entries = normalised.filter(isServerEntry)
  const items: PendingItem[] = []
  let refusedLinks = normalised.length - entries.length
  for (const entry of entries) {
    const known = findLedgerEntry(ledger, entry.id)
    const { ask, refusedLink } = askFromServerEntry(entry, scope, by, known)
    if (refusedLink) refusedLinks += 1
    if (ask) items.push({ ask: withContext(ask, context), slug: typeof entry.item === "string" ? entry.item : (known?.slug ?? null) })
  }
  const seen = new Set(items.map((i) => i.ask.id))
  for (const entry of ledger) if (!seen.has(entry.ask.id)) items.push({ ask: withContext(entry.ask, context), slug: entry.slug })
  const groupList = serverGroups(server.groups, scope)
  const grouped = items.map((item) => {
    const group = item.ask.kind === "approval" ? groupList.groups.find((g) => g.approvals.includes(item.ask.id)) : undefined
    return group ? { ...item, ask: { ...item.ask, group: { id: group.id, url: group.url, open: group.approvals.length } } } : item
  })
  const noticeList = deviceNotices(server.notices, vaultUrl)
  const machineList = workspaceMachineNotices(server.notices, context)
  return { items: grouped, notices: [...noticeList.notices, ...machineList.notices], groups: groupList.groups, source: "vault", refusedLinks: refusedLinks + groupList.refusedLinks + noticeList.refusedLinks + machineList.refusedLinks }
}

function fromLedger(entries: LedgerEntry[], context: SessionContext): PendingItem[] {
  return entries.map((e) => ({ ask: withContext(e.ask, context), slug: e.slug }))
}

// Everything open across the allowed set: every active
// slot's asks, then every pending slot's enrol ask with its intent. A
// workspace whose vault cannot be asked is listed from its ledger and named
// in `unavailable`; when every active slot's vault fails and no pending slot
// has an enrolment to show, the first failure is the answer, as it was with
// one workspace.
//
// `span` is the MCP server's own view (vault_pending): the slots it may use
// and its latched session opener, used instead of the environment's.
export type PendingSpan = { active: LocalContext[]; pending: FoundPending[]; open(slot: LocalContext): Promise<VaultSession> }

export async function listPending(env: Env, now = new Date(), span?: PendingSpan): Promise<PendingList> {
  const active = span ? span.active : await listActive(env)
  const pendingSlots = span ? span.pending : managedHost() ? [] : pendingIn(await allowedSlots(env))
  const open = span ? span.open : (slot: LocalContext) => openContext(env, { ...slot, reason: "workspace" })
  const items: PendingItem[] = []
  const notices: PendingList["notices"] = []
  const groups: PendingGroupView[] = []
  const unavailable: PendingList["unavailable"] = []
  let refusedLinks = 0
  let source: PendingList["source"] = "ledger"
  let firstFailure: unknown = null
  for (const slot of active) {
    let found: SlotPending
    try {
      found = await slotPending(env, slot, now, open)
    } catch (error) {
      firstFailure ??= error
      const failure = toCliError(error)
      unavailable.push({ slot: slot.dir, error: failure.code, message: failure.message })
      const context = sessionContext(slot.config)
      const scope = { vaultUrl: slot.config.vault, workspace: slot.config.tenant, device: slot.config.device, workspaceSlug: slot.config.workspaceSlug ?? null }
      found = { items: fromLedger(await readLedger(slot.dir, scope, now).catch(() => []), context), notices: [], groups: [], source: "ledger", refusedLinks: 0 }
    }
    items.push(...found.items)
    notices.push(...found.notices)
    groups.push(...found.groups)
    refusedLinks += found.refusedLinks
    if (found.source === "vault") source = "vault"
  }
  // Every pending slot's enrolment is read locally and asks no vault, so a
  // refusing vault elsewhere never hides it.
  const device = requestedBy(env).device
  const enrolments: PendingItem[] = []
  for (const slot of pendingSlots) {
    const view = await slotView(slot, device)
    if (view.state === "pending") enrolments.push({ ask: view.ask, slug: null })
  }
  // Only when no active vault answered and nothing else can be returned is
  // the first refusal the answer.
  if (active.length > 0 && unavailable.length === active.length && enrolments.length === 0) throw firstFailure
  items.push(...enrolments)
  const vaultUrl = active[0]?.config.vault ?? pendingSlots[0]?.record.origin ?? resolveVaultUrl(env, null)
  return { items, notices, groups, source, vaultUrl, refusedLinks, unavailable }
}

function shortWhat(ask: Ask): string {
  const what = ask.what.replace(/ so the agent can .*$/, "").replace(/ and choose what it may use$/, "")
  return what.charAt(0).toLowerCase() + what.slice(1)
}

export const pendingCommand: Command = {
  summary: "list the asks still waiting for a human, or show one again (mehen pending [<id>|<slug>])",
  spec: { usage: "mehen pending [<id>|<slug>]", flags: {}, positionals: { min: 0, max: 1 } },
  examples: [["pending"], ["pending", "apr_7Hq2", "--json"]],
  async run({ args, json, env }) {
    const now = new Date()
    const { items, notices, groups, vaultUrl, refusedLinks, unavailable } = await listPending(env, now)
    for (const gone of unavailable) note(`mehen: warning: the vault for ${gone.slot} could not be asked (${gone.error}: ${gone.message}); its asks are listed from this machine's record.`)
    if (refusedLinks > 0) note(`mehen: warning: ${refusedLinks === 1 ? "one pending entry" : `${refusedLinks} pending entries`} came with a link not on the vault or an id mehen does not know; ${refusedLinkWarning(vaultUrl)}`)
    const asks = items.map((i) => i.ask)
    const wanted = args.positionals[0]
    if (wanted !== undefined) {
      const ask = asks.find((a) => a.id === wanted) ?? items.filter((i) => i.slug === wanted).at(-1)?.ask
      if (!ask) {
        throw new CliError("not_found", `Nothing is pending for ${JSON.stringify(wanted)}.`, { command: "mehen pending", say: "List what is still waiting for a human with `mehen pending`." })
      }
      if (json) printJson({ ask, next: askNext(ask, { now }), ...(notices.length ? { notices } : {}) })
      else {
        for (const notice of notices) printLine(pendingNoticeText(notice))
        printAsk(ask, { env, noQr: args.bool("no-qr"), now })
      }
      return EXIT.ok
    }
    if (json) {
      printJson({ pending: asks, ...(groups.length ? { groups } : {}), ...(notices.length ? { notices } : {}) })
      return EXIT.ok
    }
    for (const notice of notices) printLine(pendingNoticeText(notice))
    if (asks.length === 0) {
      if (notices.length === 0) printLine("Nothing is waiting for a human.")
      return EXIT.ok
    }
    const s = styler(colourEnabled(process.stdout, env))
    const rows: Text[][] = [["KIND", "ID", "WHAT", "EXPIRES", "THEN"]]
    for (const ask of asks) {
      const expiry = expiryText(ask, { now })
      rows.push([ask.kind, ask.id || "-", shortWhat(ask), expiry === "expired" ? s.danger(expiry) : expiry, ask.wait ?? "-"])
    }
    for (const line of table(rows)) printLine(line)
    for (const group of groups) printLine(pendingGroupText(group, asks))
    return EXIT.ok
  },
}
