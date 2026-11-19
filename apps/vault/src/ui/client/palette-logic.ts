// The command palette's contents and search, with no DOM, so the server
// tests can check the order and the matching. Entries are built from the
// lists a member already reads (/api/pending, /api/items, /api/devices,
// /api/projects, or the same under /api/w/<slug> on a workspace page) plus
// fixed actions for the lists and pages, and on a workspace page "Freeze
// <workspace>" for whoever the settings read says may; every link is a vault path built
// from an id or slug, never from a url a list carries. On a workspace page
// every link is under /w/<slug> and only to a page the server serves.

import type { DeviceView, ItemSummary, PendingAsk, Project } from "@mehen/protocol/api"
import type { WorkspacePendingAsk, WorkspaceSettingsView } from "@mehen/protocol/workspace"
import { isLeaseOnly } from "@mehen/protocol/binding"
import { KINDS } from "@mehen/protocol/kinds"
import { type CardTextSegment, spellCardSegments } from "../../relay/spelling.ts"
import { isVaultPath } from "../html.ts"
import type { BrandSlug, IconName } from "../icons.ts"
import { brandFor, brandTitle, kindIcon, machineIcon } from "../tile-names.ts"
import { PENDING_BUTTON, adoptionCount, askerName, relativeAgo } from "../wording.ts"
import { ringText } from "./countdown.ts"

export type PaletteGroup = "needs" | "credentials" | "machines" | "projects" | "actions"

export const GROUP_ORDER: readonly PaletteGroup[] = ["needs", "credentials", "machines", "projects", "actions"]

export const GROUP_WORDS: Record<PaletteGroup, string> = {
  needs: "Needs you",
  credentials: "Credentials",
  machines: "Machines",
  projects: "Projects",
  actions: "Actions",
}

export type PaletteTile = { kind: "brand"; slug: BrandSlug } | { kind: "icon"; name: IconName } | { kind: "letter"; letter: string }

export type PaletteEntry = {
  group: PaletteGroup
  title: string
  sub: string
  href: string
  tile: PaletteTile
  // Words matched but never shown (the service name, an account, tags).
  keywords: string
  // Needs-you only: when the ask stops working, for the time left.
  expiresAt: string | null
  // The button word on the right, for a needs-you row.
  action: string | null
}

export type PaletteSources = {
  pending: readonly PendingAsk[] | null
  items: readonly ItemSummary[] | null
  devices: readonly DeviceView[] | null
  projects: readonly Project[] | null
  // The workspace settings read (GET /api/w/<slug>/settings): Freeze is
  // offered only when it says this member may and the workspace is not
  // frozen already. Absent or null on the legacy vault, or when unread.
  settings?: WorkspaceSettingsView | null
}

// The workspace reads the palette lists, relative to /api/w/<slug>. The
// server puts the served ones in the boot payload; the rest are left out.
export const PALETTE_READS = ["/pending", "/items", "/devices", "/projects", "/settings"] as const

// A workspace's /pending lists each ask wrapped with its workspace and
// owner, as a detail view or a stop view. The palette lists the detail
// views' asks; a stop view stays on Needs you, where it can be stopped.
export function workspacePaletteAsks(pending: readonly WorkspacePendingAsk[]): PendingAsk[] {
  return pending.flatMap((ask) => (ask.view === "detail" ? [ask.detail] : []))
}

// Where the palette is: the legacy vault (no prefix), or one workspace with
// the pages and reads its server serves.
export type PaletteScope = { kind: "vault" } | { kind: "workspace"; slug: string; name: string; pages: readonly string[]; reads: readonly string[] }

export const VAULT_SCOPE: PaletteScope = { kind: "vault" }

// `page` is the workspace page an action opens (shell.ts WorkspacePageKey);
// null for the docs, which belong to the account and stay unprefixed (/docs
// redirects to the docs site; the palette only links within the vault).
// `href` null is a workspace page the legacy vault has not got; `title`
// there is the rail's word for the page where it differs.
const ACTIONS: readonly { title: string; sub: string; href: string | null; workspace: { page: string; path: string; title?: string } | null; icon: IconName; keywords: string }[] = [
  { title: "Credentials", sub: "Every credential, with search and filters", href: "/credentials", workspace: { page: "credentials", path: "/credentials" }, icon: "key", keywords: "items secrets keys connections list" },
  { title: "Machines", sub: "Every enrolled machine, with its key and scope", href: "/devices", workspace: { page: "machines", path: "/devices" }, icon: "desktop", keywords: "devices enrolled revoke list" },
  { title: "Projects", sub: "Repositories and their environments' variables", href: "/projects", workspace: { page: "projects", path: "/projects" }, icon: "braces", keywords: "environments variables repositories list" },
  { title: "Connect a service", sub: "The catalogue: Gmail, GitHub, OpenAI and more", href: "/connect", workspace: { page: "connect", path: "/connect" }, icon: "grid", keywords: "catalogue add new credential" },
  { title: "Settings", sub: "The name, the short name, the workspace id, freeze", href: "/settings", workspace: { page: "settings", path: "/settings" }, icon: "sliders", keywords: "preferences rename slug short name freeze unfreeze" },
  { title: "People", sub: "Members, invitations and teams", href: null, workspace: { page: "people", path: "/people" }, icon: "users", keywords: "members invite invitations teams roles colleagues" },
  { title: "Connect an agent", sub: "The line to paste into your agent", href: null, workspace: { page: "connect-agent", path: "/connect-agent" }, icon: "terminal", keywords: "enrol machine new agent setup install" },
  { title: "Audit", sub: "Every use, approval and change, as sentences", href: "/audit", workspace: { page: "audit", path: "/audit", title: "Activity" }, icon: "list", keywords: "log history audit activity" },
  { title: "Docs", sub: "The docs site: guides, concepts, reference and security", href: "/docs", workspace: null, icon: "book", keywords: "documentation help guide manual readme" },
]

// Each group's links and the workspace page they open.
const GROUP_PAGE: Record<Exclude<PaletteGroup, "actions">, string> = { needs: "asks", credentials: "credentials", machines: "machines", projects: "projects" }

// A legacy link as its workspace address: the same path under /w/<slug>.
function scoped(scope: Extract<PaletteScope, { kind: "workspace" }>, href: string): string {
  return `/w/${encodeURIComponent(scope.slug)}${href}`
}

// The page an ask opens, from its kind and id only (the same rule as home).
export function askHref(ask: Pick<PendingAsk, "kind" | "id">): string {
  const id = encodeURIComponent(ask.id)
  switch (ask.kind) {
    case "policy":
      return `/p/${id}`
    case "policy-review":
      return `/policy/${ask.id.startsWith("pov_") ? "overrides" : "grants"}/${id}`
    case "approval":
      return `/a/${id}`
    case "intake":
      return `/i/${id}`
    case "connect":
      return `/c/${id}`
    case "adoption":
      return `/b/${id}`
    case "reconnect":
    case "review":
      return `/items/${id}`
  }
}

function serviceTile(item: { provider: string | null; slug: string }): PaletteTile {
  const slug = item.provider === null ? null : brandFor(item.provider)
  if (slug !== null) return { kind: "brand", slug }
  return { kind: "letter", letter: (Array.from(item.slug)[0] ?? "?").toUpperCase() }
}

function askTile(ask: PendingAsk, items: readonly ItemSummary[]): PaletteTile {
  if (ask.provider !== undefined && ask.provider !== null) return serviceTile({ provider: ask.provider, slug: ask.item ?? ask.id })
  const item = ask.item !== null ? items.find((i) => i.slug === ask.item) : undefined
  if (item !== undefined) return serviceTile(item)
  if (ask.kind === "intake") return { kind: "icon", name: kindIcon(ask.kindRequested ?? "api-key") }
  return { kind: "icon", name: "bell" }
}

function askSub(ask: PendingAsk): string {
  const who = ask.requestedBy !== null ? askerName(ask.requestedBy) : "The vault"
  switch (ask.kind) {
    case "policy":
    case "approval":
      return [who, ask.item, ask.bindingCode !== undefined ? `code ${ask.bindingCode}` : null].filter((p): p is string => typeof p === "string" && p !== "").join(" · ")
    case "intake":
      return ask.item !== null ? `${who} · saves as ${ask.item}` : who
    case "adoption":
      return `${who} · ${adoptionCount(ask.items ?? 0)}`
    case "connect":
      return who
    case "reconnect":
      return "The provider stopped accepting its token"
    case "policy-review":
    case "review":
      return ask.reason ?? "The vault flagged it for a look"
  }
}

// The brand's name when a template or provider is known, else the kind.
function serviceName(item: ItemSummary): string {
  const slug = item.provider === null ? null : brandFor(item.provider)
  if (slug !== null) return brandTitle(slug)
  return KINDS[item.kind]?.label ?? item.kind
}

// The address an entry opens in this scope, or null when that workspace page
// is not served, so the palette never offers a link that would not open.
function linkTo(scope: PaletteScope, href: string, page: string | null): string | null {
  if (scope.kind === "vault" || page === null) return href
  return scope.pages.includes(page) ? scoped(scope, href) : null
}

export function buildEntries(sources: PaletteSources, now: number, scope: PaletteScope = VAULT_SCOPE): PaletteEntry[] {
  const items = sources.items ?? []
  const entries: PaletteEntry[] = []
  const add = (entry: PaletteEntry, page: string | null) => {
    const href = linkTo(scope, entry.href, page)
    if (href !== null) entries.push({ ...entry, href })
  }
  for (const ask of sources.pending ?? []) {
    add({
      group: "needs",
      title: ask.title,
      sub: askSub(ask),
      href: askHref(ask),
      tile: askTile(ask, items),
      keywords: [ask.kind, ask.item ?? "", ask.bindingCode ?? ""].join(" "),
      expiresAt: ask.expiresAt,
      action: PENDING_BUTTON[ask.kind],
    }, ask.kind === "reconnect" || ask.kind === "review" ? GROUP_PAGE.credentials : GROUP_PAGE.needs)
  }
  for (const item of items) {
    const used = item.lastUsedAt ? `used ${relativeAgo(item.lastUsedAt, now) ?? item.lastUsedAt}` : "never used"
    const what = item.account !== null ? `${serviceName(item)} as ${item.account}` : serviceName(item)
    add({
      group: "credentials",
      title: item.slug,
      sub: `${what} · ${used}`,
      href: `/items/${encodeURIComponent(item.slug)}`,
      tile: serviceTile(item),
      keywords: [item.provider ?? "", item.kind, ...item.tags, ...(isLeaseOnly(item) ? [] : item.hosts)].join(" "),
      expiresAt: null,
      action: null,
    }, GROUP_PAGE.credentials)
  }
  for (const device of sources.devices ?? []) {
    if (device.revoked) continue
    const seen = device.lastSeenAt !== null ? `seen ${relativeAgo(device.lastSeenAt, now) ?? device.lastSeenAt}` : "never seen"
    add({
      group: "machines",
      title: device.name,
      sub: `${device.backend === "secure-enclave" ? "Secure Enclave" : "Software key"} · ${seen}`,
      // A workspace has a page per machine; the legacy vault only the list.
      href: scope.kind === "workspace" ? `/devices/${encodeURIComponent(device.device)}` : "/devices",
      tile: { kind: "icon", name: machineIcon(device.backend, device.name) },
      keywords: `machine device ${device.host ?? ""}`,
      expiresAt: null,
      action: null,
    }, GROUP_PAGE.machines)
  }
  for (const project of sources.projects ?? []) {
    add({
      group: "projects",
      title: project.slug,
      sub: project.environments.map((e) => e.name).join(", "),
      href: `/projects/${encodeURIComponent(project.id)}`,
      tile: { kind: "icon", name: "braces" },
      keywords: "project environment",
      expiresAt: null,
      action: null,
    }, GROUP_PAGE.projects)
  }
  // The brake first among the actions: it opens the settings page's
  // confirm step, which still asks before anything is sent.
  if (scope.kind === "workspace" && sources.settings?.rights.freeze === true && !sources.settings.frozen) {
    add({ group: "actions", title: `Freeze ${scope.name}`, sub: "Refuse every machine use here until an owner unfreezes it", href: "/settings#freeze", tile: { kind: "icon", name: "snowflake" }, keywords: "freeze stop brake panic halt emergency", expiresAt: null, action: null }, "settings")
  }
  for (const action of ACTIONS) {
    const here = scope.kind === "workspace" ? action.workspace : null
    const href = here !== null ? here.path : action.href
    if (href === null) continue
    add({ group: "actions", title: here?.title ?? action.title, sub: action.sub, href, tile: { kind: "icon", name: action.icon }, keywords: action.keywords, expiresAt: null, action: null }, action.workspace?.page ?? null)
  }
  return entries.filter((e) => isVaultPath(e.href))
}

// [start, end) ranges of `title` to mark, in order and never overlapping.
export type MatchRange = [number, number]

export type PaletteMatch = { entry: PaletteEntry; ranges: MatchRange[] }

function words(query: string): string[] {
  return query.toLowerCase().split(/\s+/).filter((w) => w !== "")
}

// Where each query word sits in the title, case-insensitively, merged.
export function titleRanges(title: string, query: string): MatchRange[] {
  const lower = title.toLowerCase()
  const found: MatchRange[] = []
  for (const word of words(query)) {
    let from = 0
    for (;;) {
      const at = lower.indexOf(word, from)
      if (at < 0) break
      found.push([at, at + word.length])
      from = at + 1
    }
  }
  found.sort((a, b) => a[0] - b[0] || a[1] - b[1])
  const merged: MatchRange[] = []
  for (const range of found) {
    const last = merged[merged.length - 1]
    if (last !== undefined && range[0] <= last[1]) last[1] = Math.max(last[1], range[1])
    else merged.push([range[0], range[1]])
  }
  return merged
}

// 3 when every word is in the title, 2 when one is, 1 when they are all
// found somewhere in the title, sub or keywords, 0 for no match.
function score(entry: PaletteEntry, query: string): number {
  const list = words(query)
  if (list.length === 0) return 1
  const title = entry.title.toLowerCase()
  const everywhere = `${title} ${entry.sub} ${entry.keywords}`.toLowerCase()
  if (!list.every((w) => everywhere.includes(w))) return 0
  const inTitle = list.filter((w) => title.includes(w)).length
  if (inTitle === list.length) return 3
  return inTitle > 0 ? 2 : 1
}

// Matching entries in group order (needs you first, actions last), and
// inside a group by how well the title matches, then as listed.
export function filterEntries(entries: readonly PaletteEntry[], query: string): PaletteMatch[] {
  const scored = entries.map((entry, index) => ({ entry, index, score: score(entry, query) })).filter((s) => s.score > 0)
  scored.sort((a, b) => GROUP_ORDER.indexOf(a.entry.group) - GROUP_ORDER.indexOf(b.entry.group) || b.score - a.score || a.index - b.index)
  return scored.map((s) => ({ entry: s.entry, ranges: titleRanges(s.entry.title, query) }))
}

// A title spelled for a human (the vault's markers for hidden characters,
// controls as \u00XX) with the search's matched ranges laid over it.
// Matching ran on the raw text; here the raw ranges are cut at code point
// boundaries and each slice is spelled, with what to mark decided on the
// whole title, so a marker is never split or highlighted, a highlight never
// marks a selector the title leaves alone, and text someone typed to look
// like a marker is plain text that may be highlighted like any other.
export type TitlePiece = { kind: "text" | "match" | "marker"; text: string }

function snap(title: string, index: number): number {
  const before = title.charCodeAt(index - 1)
  const here = title.charCodeAt(index)
  return before >= 0xd800 && before <= 0xdbff && here >= 0xdc00 && here <= 0xdfff ? index - 1 : index
}

export function titlePieces(title: string, ranges: readonly MatchRange[]): TitlePiece[] {
  const out: TitlePiece[] = []
  const push = (segments: CardTextSegment[], highlighted: boolean) => {
    for (const segment of segments) {
      const kind: TitlePiece["kind"] = segment.kind === "marker" ? "marker" : highlighted ? "match" : "text"
      const last = out[out.length - 1]
      if (last !== undefined && last.kind === kind && kind !== "marker") last.text += segment.text
      else out.push({ kind, text: segment.text })
    }
  }
  let at = 0
  for (const [rawStart, rawEnd] of ranges) {
    const start = Math.max(at, snap(title, rawStart))
    const end = Math.max(start, snap(title, rawEnd))
    push(spellCardSegments(title, at, start), false)
    push(spellCardSegments(title, start, end), true)
    at = end
  }
  push(spellCardSegments(title, at), false)
  return out
}

// "9 min left", or "ran out"; null when the ask has no expiry.
export function timeLeftWords(entry: PaletteEntry, now: number): string | null {
  if (entry.expiresAt === null) return null
  const at = Date.parse(entry.expiresAt)
  if (Number.isNaN(at)) return null
  const left = Math.max(0, Math.ceil((at - now) / 1000))
  return left === 0 ? "ran out" : `${ringText(left)} left`
}
