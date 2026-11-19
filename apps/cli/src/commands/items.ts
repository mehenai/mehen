// mehen ls and mehen show: what the vault holds, as references and public metadata.
// `ls` spans every workspace this machine may use, each item
// with the workspace it is in; `show` needs one.
//
// Everything an item carries (slug, account, description, hosts, rule paths)
// was written by a human, an agent or an upstream and is untrusted: every
// line leaves through printLine, which spells out hidden and control
// characters, and the policy summary is derived from the rules' matchers,
// never their notes, because nothing in an ItemDescription proves the policy
// is a verified template binding.

import { EXIT, type ItemDescription, type ItemSummary } from "@mehen/protocol/api"
import { checkBinding, isLeaseOnly, leaseOnlyDelivery, leaseOnlyWords, parseDestination } from "@mehen/protocol/binding"
import { type PolicySummary, summarisePolicy } from "@mehen/protocol/policy-summary"
import type { PushRecordView } from "@mehen/protocol/push"
import { getOAuthProvider, getTemplate } from "@mehen/protocol/templates"
import type { Command } from "../command.ts"
import { type Env, resolveVaultUrl } from "../config.ts"
import { type CliErrorCode, toCliError } from "../errors.ts"
import { type ItemFilters, listItems, reviewNote, showItem } from "../operations.ts"
import { note, printJson, printLine, table } from "../output.ts"
import { notEnrolled, openContext, openSession } from "../session.ts"
import { type LocalContext, listActive, workspaceSelector } from "../slots.ts"
import { type Segment, type Styler, type Text, colourEnabled, segments, styler } from "../tty.ts"
import { policySummaryLines } from "./templates.ts"

const STATUS_WORDS: Record<ItemSummary["status"], string> = {
  active: "active",
  needs_reauth: "needs reauth",
  refresh_retrying: "refresh retrying",
  disabled: "disabled",
}

// "needs reauth" for needs_reauth, in the status tone (UX-MEHEN-TOOLS 2.7).
export function statusWord(status: ItemSummary["status"], colour: Styler): Segment {
  return colour.status(STATUS_WORDS[status] ?? status)
}

function accountCell(item: ItemSummary, colour: Styler): Text {
  if (!item.account) return "-"
  return item.accountVerified ? item.account : segments(item.account, " ", colour.danger("(unverified)"))
}

// The workspace an item listed by `ls` is in, as its slot names it.
export type ItemWorkspace = { id: string; slug: string | null; name: string | null }
export type ListedItem = ItemSummary & { workspace: ItemWorkspace }

// ITEM, KIND, PROVIDER, ACCOUNT, STATUS, HOSTS, with a WORKSPACE column only
// when the items span more than one workspace and a REVIEW column ("!")
// only when an item needs one; the reason lines follow the table.
export function lsLines(items: (ItemSummary & { workspace?: ItemWorkspace })[], colour: Styler): Text[] {
  const anyReview = items.some((item) => item.review !== undefined)
  const spans = new Set(items.map((item) => item.workspace?.id ?? null)).size > 1
  const rows: Text[][] = [["ITEM", ...(spans ? ["WORKSPACE"] : []), "KIND", "PROVIDER", "ACCOUNT", "STATUS", ...(anyReview ? ["REVIEW"] : []), "HOSTS"]]
  for (const item of items) {
    rows.push([
      item.slug,
      ...(spans ? [item.workspace ? (item.workspace.slug ?? item.workspace.id) : "-"] : []),
      item.kind,
      item.provider ?? "-",
      accountCell(item, colour),
      statusWord(item.status, colour),
      ...(anyReview ? [item.review ? colour.danger("!") : ""] : []),
      isLeaseOnly(item) ? "no host" : item.hosts.join(", ") || "-",
    ])
  }
  const lines: Text[] = table(rows)
  for (const item of items) {
    const review = reviewNote(item)
    if (review) lines.push(segments(`${item.slug} `, colour.danger("needs review"), review.slice("needs review".length)))
  }
  return lines
}

// Every active slot in the allowed set, or with --workspace (or
// MEHEN_WORKSPACE) the one it selects. A workspace whose vault cannot be
// asked is left out and named in `unavailable`; when every one fails, the
// first failure is the answer, as it was with one workspace.
export async function listAllItems(env: Env, filters: ItemFilters): Promise<{ list: { items: ListedItem[] }; unavailable: { slot: string; error: CliErrorCode; message: string }[] }> {
  const slots: LocalContext[] = workspaceSelector(env) !== null ? [(await openSession(env)).selection] : await listActive(env)
  if (slots.length === 0) throw notEnrolled(resolveVaultUrl(env, null))
  const items: ListedItem[] = []
  const unavailable: { slot: string; error: CliErrorCode; message: string }[] = []
  let firstFailure: unknown = null
  for (const slot of slots) {
    try {
      const { api } = await openContext(env, { ...slot, reason: "workspace" })
      const workspace: ItemWorkspace = { id: slot.config.tenant, slug: slot.config.workspaceSlug ?? null, name: slot.config.workspaceName ?? null }
      for (const item of (await listItems(api, filters)).items) items.push({ ...item, workspace })
    } catch (error) {
      firstFailure ??= error
      const failure = toCliError(error)
      unavailable.push({ slot: slot.dir, error: failure.code, message: failure.message })
    }
  }
  if (unavailable.length === slots.length) throw firstFailure
  return { list: { items }, unavailable }
}

// `mehen ls --json` leaves out an item's null and false fields (no
// provider, account unverified, never used): a missing field reads as null
// or false. `workspace` is always the whole object.
export function compactListedItem(item: ListedItem): Record<string, unknown> {
  return Object.fromEntries(Object.entries(item).filter(([key, value]) => key === "workspace" || (value !== null && value !== false && value !== undefined)))
}

export const lsCommand: Command = {
  summary: "list the items this machine may use",
  spec: {
    usage: "mehen ls [--tag <tag>] [--kind <kind>] [--provider <provider>]",
    flags: { tag: { type: "string" }, kind: { type: "string" }, provider: { type: "string" } },
    positionals: { min: 0, max: 0 },
  },
  examples: [["ls"], ["ls", "--kind", "api-key", "--json"], ["ls", "--provider", "openai"]],
  async run({ args, json, env }) {
    const { list, unavailable } = await listAllItems(env, { tag: args.string("tag"), kind: args.string("kind"), provider: args.string("provider") })
    for (const gone of unavailable) note(`mehen: warning: the vault for ${gone.slot} could not be asked (${gone.error}: ${gone.message}); its items are not listed.`)
    if (json) {
      printJson({ items: list.items.map(compactListedItem) })
      return EXIT.ok
    }
    if (list.items.length === 0) {
      printLine("No items. Ask a human for a credential with `mehen request <kind> --name <slug> --reason <why>`.")
      return EXIT.ok
    }
    for (const line of lsLines(list.items, styler(colourEnabled(process.stdout, env)))) printLine(line)
    return EXIT.ok
  },
}

// ---------------------------------------------------------------- mehen show

const MINUTE = 60_000
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR

// "just now", "3 min ago", "2 h ago", "3 days ago"; null for a time that is
// not one.
export function relativeAgo(iso: string, now: Date): string | null {
  const at = Date.parse(iso)
  if (!Number.isFinite(at)) return null
  const since = now.getTime() - at
  if (since < MINUTE) return "just now"
  if (since < HOUR) return `${Math.floor(since / MINUTE)} min ago`
  if (since < 2 * DAY) return `${Math.round(since / HOUR)} h ago`
  return `${Math.round(since / DAY)} days ago`
}

// "2026-10-24 17:06" in local time (or the given zone).
export function localStamp(iso: string, timeZone?: string): string | null {
  const at = Date.parse(iso)
  if (!Number.isFinite(at)) return null
  const parts = new Intl.DateTimeFormat("en-GB", {
    ...(timeZone ? { timeZone } : {}),
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).formatToParts(new Date(at))
  const part = (type: Intl.DateTimeFormatPartTypes) => parts.find((p) => p.type === type)?.value ?? ""
  return `${part("year")}-${part("month")}-${part("day")} ${part("hour")}:${part("minute")}`
}

// "2026-10-24 17:06 (3 min ago)", "never", or the value as sent when it is
// not a time mehen can read.
export function lastUsedText(lastUsedAt: string | null, now: Date, timeZone?: string): string {
  if (lastUsedAt === null) return "never"
  const stamp = localStamp(lastUsedAt, timeZone)
  const relative = relativeAgo(lastUsedAt, now)
  return stamp && relative ? `${stamp} (${relative})` : lastUsedAt
}

// Phrases shown per summary line before "(n more)". The full rule list is one
// --json away and the policy: line says so.
const SUMMARY_PHRASES = 3

function capped(list: string[]): string[] {
  if (list.length <= SUMMARY_PHRASES) return list
  return [...list.slice(0, SUMMARY_PHRASES), `(${list.length - SUMMARY_PHRASES} more)`]
}

export type ItemPolicyLines = { heading: string; allowed: string; approve: string; deny: string }

// The policy: heading and the three lines under it, from the matchers of an
// item's rules (untrusted notes: an agent may have written them). "anything
// else" always lands on the default's line, so an approve or deny default is
// spelled out even when every named rule is cut by the cap.
export function itemPolicyLines(item: Pick<ItemDescription, "slug" | "policy">): ItemPolicyLines {
  const count = item.policy.rules.length
  const full: PolicySummary = summarisePolicy(item.policy)
  const lines = policySummaryLines({ ...full, allowed: capped(full.allowed), approve: capped(full.approve), deny: capped(full.deny) })
  const rules = count === 0 ? "no rules" : count === 1 ? `1 rule; mehen show ${item.slug} --json for it` : `${count} rules; mehen show ${item.slug} --json for all of them`
  return { heading: `${item.policy.default} by default (${rules})`, ...lines }
}

// A lease-only credential's line where its hosts would go: "no host: only
// delivered into a process with mehen run", or what else its ceiling allows.
export function noHostText(item: Pick<ItemSummary, "kind" | "ceiling">): string {
  const words = leaseOnlyWords(leaseOnlyDelivery(item.kind, item.ceiling))
  return `${words.charAt(0).toLowerCase()}${words.slice(1, -1)}`
}

// "gmail.googleapis.com /gmail/v1/**, /upload/gmail/v1/**", with the methods
// before the paths when the binding names any.
export function goesToText(binding: ItemDescription["binding"]): string {
  const methods = binding.methods?.length ? ` ${binding.methods.join("/")}` : ""
  const paths = binding.paths?.length ? ` ${binding.paths.join(", ")}` : ""
  return `${binding.hosts.join(", ")}${methods}${paths}`
}

const PLAIN_URL = /^[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+$/
const SHELL_UNSAFE = /[\s"'`$;&|<>()\\]/

// A path the binding's first pattern admits: "**" matches no segments and
// is dropped, "*" is one segment and becomes "example" (the protocol's
// pathMatches). "/gmail/v1/**" gives "/gmail/v1".
function examplePath(pattern: string | undefined): string {
  if (!pattern) return "/"
  const parts = pattern
    .split("/")
    .filter((s, i) => i === 0 || s !== "")
    .filter((s) => s !== "**")
    .map((s) => (s === "*" ? "example" : s))
  return parts.join("/") || "/"
}

// A command a human can run from the show page that sends nothing: a mehen
// check of a request the binding admits, proven with the protocol's own
// matcher before it is printed. Null when no plain example can be built (a
// wildcard host, a method or path mehen would not put in a command line).
export function tryCommand(slug: string, binding: ItemDescription["binding"]): string | null {
  const host = binding.hosts.find((h) => !h.startsWith("*."))
  if (!host) return null
  const scheme = (binding.schemes ?? ["https"]).find((s) => s === "https" || s === "http")
  if (!scheme) return null
  const method = (binding.methods?.length ? (binding.methods.includes("GET") ? "GET" : (binding.methods[0] as string)) : "GET").toUpperCase()
  if (!/^[A-Z]{1,16}$/.test(method)) return null
  const url = `${scheme}://${host}${examplePath(binding.paths?.[0])}`
  if (!PLAIN_URL.test(url) || SHELL_UNSAFE.test(url)) return null
  const parsed = parseDestination(method, url)
  if (!parsed.ok || !checkBinding(binding, parsed.destination).ok) return null
  return `mehen check ${slug} ${method} ${url}`
}

const LABEL = 10
const SUMMARY_LABEL = 18

function field(label: string, value: Text): Segment[] {
  return segments(`  ${`${label}:`.padEnd(LABEL)} `, value)
}

function providerText(provider: string | null): string {
  if (!provider) return ""
  const name = getTemplate(provider)?.displayName ?? getOAuthProvider(provider)?.displayName ?? null
  return `, provider ${provider}${name ? ` (${name})` : ""}`
}

// How careful the credential is for this machine (ItemDescription.posture),
// never which other machines it lets through; null from a vault without
// postures. A level this mehen does not know reads as asking.
export function postureText(posture: ItemDescription["posture"]): string | null {
  if (posture === undefined) return null
  if (posture.coversThisKey && posture.level === "routine") return "routine building allowed for this machine"
  if (posture.coversThisKey && posture.level === "trust") return "this machine is trusted: changes go through except those that always ask"
  return "asks for every change"
}

export type ShowOptions = { now?: Date; timeZone?: string }

const PUSH_STATE_WORDS: Record<Exclude<PushRecordView["state"], "done">, string> = { failed: "failed", unknown: "unconfirmed", not_sent: "not sent" }

// One destination the item was put into (design push-providers 3.3 point
// 5): where, which version and when. Never the via, who pushed or anything
// the provider said beyond its HTTP status.
export function pushLine(push: PushRecordView, timeZone?: string): string {
  const at = localStamp(push.at, timeZone) ?? push.at
  if (push.state === "done") return `  pushed to ${push.words} (version ${push.version}${push.current ? "" : ", older than current"}) ${at}`
  const said = push.state === "failed" && push.providerStatus !== null ? `, provider said ${push.providerStatus}` : ""
  return `  push to ${push.words} ${PUSH_STATE_WORDS[push.state] ?? push.state} (version ${push.version}${said}) ${at}`
}

// The show page (UX-MEHEN-TOOLS 2.7): every line it had, the policy count
// followed by the three summary lines, a relative last used, and a try: line.
export function showLines(item: ItemDescription, slug: string, colour: Styler, options: ShowOptions = {}): Text[] {
  const now = options.now ?? new Date()
  const lines: Text[] = [`${item.slug}  (mehen://${item.slug})`]
  lines.push(field("kind", `${item.kind}${providerText(item.provider)}`))
  if (item.account) lines.push(field("account", segments(item.account, " ", item.accountVerified ? colour.ok("(verified)") : colour.danger("(unverified)"))))
  if (item.description) lines.push(field("about", item.description))
  lines.push(field("status", segments(statusWord(item.status, colour), `, ceiling ${item.ceiling}, version ${item.version}`)))
  const review = reviewNote(item)
  if (review) lines.push(field("review", segments(colour.danger("needs review"), review.slice("needs review".length), ` (since ${item.review?.since ?? "unknown"})`)))
  lines.push(field("goes to", isLeaseOnly(item.binding) ? noHostText(item) : goesToText(item.binding)))
  const policy = itemPolicyLines(item)
  lines.push(field("Base policy", policy.heading))
  lines.push(`    ${"without a human:".padEnd(SUMMARY_LABEL)}${policy.allowed}`)
  lines.push(`    ${"needs approval:".padEnd(SUMMARY_LABEL)}${policy.approve}`)
  lines.push(`    ${"refused:".padEnd(SUMMARY_LABEL)}${policy.deny}`)
  lines.push(field("Effective floors", item.policyFloor === undefined ? "unavailable from this vault" : item.policyFloor.length ? "Stronger than a saved base allow:" : "none reported"))
  for (const floor of item.policyFloor ?? []) lines.push(segments(`    ${floor.action}: ${floor.host} ${JSON.stringify(floor.rule)} (${floor.reason}; ${floor.id})`))
  lines.push(segments(`  Read mehen policy show ${item.slug} for current policy state. A saved base allow does not remove a floor.`))
  const careful = postureText(item.posture)
  if (careful !== null) lines.push(`  How careful: ${careful}`)
  if (item.tags.length) lines.push(field("tags", item.tags.join(", ")))
  for (const [name, value] of Object.entries(item.publicFields)) lines.push(field(name, value))
  const secretLabel = Math.max(0, ...item.secretFields.map((f) => `secret ${f.name}:`.length))
  for (const f of item.secretFields) {
    const state = f.set ? `set, ${f.length} chars${f.prefix ? `, starts ${f.prefix}` : ""}, fingerprint ${f.fingerprint}` : "not set"
    lines.push(`  ${`secret ${f.name}:`.padEnd(secretLabel)} ${state}`)
  }
  lines.push(field("last used", lastUsedText(item.lastUsedAt, now, options.timeZone)))
  for (const push of item.pushes ?? []) lines.push(pushLine(push, options.timeZone))
  const example = tryCommand(slug, item.binding)
  if (example) lines.push(field("try", example))
  return lines
}

export const showCommand: Command = {
  summary: "show an item's public metadata (never its value)",
  spec: { usage: "mehen show <item>", flags: {}, positionals: { min: 1, max: 1 } },
  examples: [["show", "openai-personal"], ["show", "gmail-personal", "--json"]],
  notes: ["Never the value: for each secret field, whether it is set, its length, a well-known prefix and a fingerprint."],
  async run({ args, json, env }) {
    const { api } = await openSession(env)
    const slug = args.positionals[0] as string
    const item = await showItem(api, slug)
    if (json) {
      printJson(item)
      return EXIT.ok
    }
    for (const line of showLines(item, slug, styler(colourEnabled(process.stdout, env)))) printLine(line)
    return EXIT.ok
  },
}
