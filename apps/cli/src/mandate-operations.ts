// Mandates as this machine sees them: it proposes one,
// reads its own, follows what went through on trust and pauses itself. It
// never signs, resumes or stops one: those are a person's, on the vault's
// pages. Every answer is read through a schema that keeps only the fields a
// machine's view carries, so nothing else (signerCurrent among them) is
// ever printed.

import { type Me, MANDATE_HEADER, type NextStep } from "@mehen/protocol/api"
import { MANDATE_CAP_MAX, MANDATE_CLASSES, MANDATE_LIVE_STATES, MANDATE_PROPOSAL_CAP_DEFAULTS, MANDATE_PROPOSAL_DEFAULT_TTL_DAYS, type MandateAsked, MANDATE_RATE_LIMIT, MANDATE_STATES, MANDATE_TTL_DAYS, type MandateCaps, type MandateClass, MandateClassSchema, MandateIdSchema, type MandateOpenProposal, MandateProposalIdSchema, type MandatePropose, MandateProposeSchema, type MandateReceiptView, type MandateSchedule, MandateScheduleSchema, type MandateView, isMandateTimeZone, mandateReceiptsCursor } from "@mehen/protocol/mandate-terms"
import { PolicySlugSchema } from "@mehen/protocol/policy-mode"
import { z } from "zod"
import { type Ask, type AskUrl, askSay, askUrl, clockText, mandateAsk, mandatePageUrlFor, mandateProposalUrlFor, refusedLinkWarning, withContext } from "./ask.ts"
import { type Env, configWorkspace } from "./config.ts"
import { CliError, toCliError, usageError } from "./errors.ts"
import { type VaultSession, sessionLabel } from "./session.ts"
import { type VaultApi, VaultApiError } from "./vault-api.ts"

export type MandateSession = Pick<VaultSession, "api" | "vaultUrl" | "config">
// Where a refusal names the term: --items on the command line, items in vault_mandate.
export type MandateSurface = "cli" | "mcp"

const timestamp = z.iso.datetime({ offset: true })
const count = z.number().int().min(0)
const countsSchema = z.object({ read: count, change: count, send: count, delete: count })
// proposal: the mdp_ id it was signed from, null for one signed without; a
// vault from before it was named sends none, and one that is not an id is
// read as none.
export type MachineMandateView = Omit<MandateView, "signerCurrent" | "proposal"> & { proposal?: string | null }
export const mandateViewSchema = z.object({
  id: MandateIdSchema,
  device: z.object({ id: z.string(), name: z.string() }),
  signer: z.object({ name: z.string() }),
  state: z.enum(MANDATE_STATES),
  rev: z.number().int().min(1),
  items: z.union([z.literal("all"), z.array(z.string())]),
  hiddenItems: count,
  classes: z.array(MandateClassSchema),
  caps: countsSchema,
  today: countsSchema,
  ttlDays: z.literal(MANDATE_TTL_DAYS),
  schedule: MandateScheduleSchema.nullable(),
  note: z.string(),
  createdAt: timestamp,
  expiresAt: timestamp,
  endedReason: z.enum(["stopped", "expired", "replaced"]).nullable(),
  proposal: MandateProposalIdSchema.nullable().optional().catch(undefined),
}) satisfies z.ZodType<MachineMandateView>
const receiptSchema = z.object({
  id: z.string(),
  at: timestamp,
  classes: z.array(MandateClassSchema),
  method: z.string(),
  credential: z.object({ slug: z.string(), host: z.string(), entry: z.string(), run: z.string().nullable() }).nullable(),
}) satisfies z.ZodType<MandateReceiptView>
const receiptsPageSchema = z.object({ receipts: z.array(receiptSchema), next: z.string().nullable() })
const openProposalSchema = z.object({
  id: MandateProposalIdSchema,
  url: z.string(),
  expiresAt: timestamp,
  createdAt: timestamp,
  device: z.object({ id: z.string(), name: z.string() }),
  classes: z.array(MandateClassSchema),
  items: z.union([z.literal("all"), z.array(z.string())]),
  hiddenItems: count,
  reason: z.string(),
}) satisfies z.ZodType<MandateOpenProposal>
// A vault from before open proposals were listed sends none.
const listSchema = z.object({ mandates: z.array(mandateViewSchema), proposals: z.array(openProposalSchema).default([]) })
const changedSchema = z.object({ mandate: mandateViewSchema })
const createdSchema = z.object({ id: MandateProposalIdSchema, url: z.string(), expiresAt: timestamp, existing: z.boolean().optional() })

function response<S extends z.ZodType>(schema: S, value: unknown): z.infer<S> {
  const parsed = schema.safeParse(value)
  if (!parsed.success) throw new CliError("internal", "The vault returned an invalid mandate response.")
  return parsed.data
}

// What a mandate never covers, in words: these ask every time, whatever a mandate says.
export const MANDATE_NEVER_COVERS = "minting or reading credentials, webhooks, forwarding, inbox rules, SSO, members, invites, permissions, sharing, publishing, money, a live key, a request Mehen cannot read, a host only a wildcard in the binding admits, a protected credential, environment or run, a workload's request, or anything in a managed or frozen workspace"

// With MANDATES off, every mandate route answers as an unknown route does,
// and so does a vault from before mandates.
export const MANDATES_OFF_LINE = "This workspace has no mandates: they are not switched on here, or this vault is older than them."
const MANDATES_OFF_NEXT = { say: "Carry on asking for each request as before; do not propose a mandate again." }

async function mandateCall<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call()
  } catch (error) {
    if (error instanceof VaultApiError && error.body.error === "not_found" && error.body.message === "No such route.") throw new CliError("not_found", MANDATES_OFF_LINE, MANDATES_OFF_NEXT)
    throw error
  }
}

// ---------------------------------------------------------------- words

const DISPLAY_ORDER: readonly MandateClass[] = ["read", "change", "send", "delete"]
const PLURAL: Record<MandateClass, string> = { read: "reads", change: "changes", send: "sends", delete: "deletes" }

function listText(words: readonly string[]): string {
  return words.length <= 1 ? (words[0] ?? "") : `${words.slice(0, -1).join(", ")} and ${words.at(-1)}`
}
function ordered(classes: readonly MandateClass[]): MandateClass[] {
  return DISPLAY_ORDER.filter((c) => classes.includes(c))
}
// "read, change and send"
export function classesText(classes: readonly MandateClass[]): string {
  return listText(ordered(classes))
}
// "5000 reads, 50 sends and 20 deletes"
function capsText(classes: readonly MandateClass[], caps: MandateCaps): string {
  return listText(ordered(classes).map((c) => `${caps[c]} ${PLURAL[c]}`))
}
// "send 3 of 50, delete 0 of 20"
export function todayText(view: Pick<MachineMandateView, "classes" | "caps" | "today">): string {
  return ordered(view.classes).map((c) => `${c} ${view.today[c]} of ${view.caps[c]}`).join(", ")
}
const SHOWN_SLUGS = 5
function itemsText(items: "all" | readonly string[], hidden = 0): string {
  if (items === "all") return "every credential it can use"
  const parts = items.slice(0, SHOWN_SLUGS)
  if (items.length > SHOWN_SLUGS) parts.push(`${items.length - SHOWN_SLUGS} more`)
  if (hidden > 0) parts.push(`${hidden} credential${hidden === 1 ? "" : "s"} you cannot see`)
  return listText(parts)
}

// The plain words of a mandate this machine proposes, for the ask.
export function proposalText(machine: string, proposal: MandatePropose): string {
  const t = proposal.terms
  const hours = t.schedule === null ? "" : `, only ${scheduleText(t.schedule)}`
  return `Let ${machine} ${classesText(t.classes)} with ${itemsText(t.items)} without asking you, for ${t.ttlDays} day${t.ttlDays === 1 ? "" : "s"}, at most ${capsText(t.classes, t.caps)} a day${hours}: ${t.note}`
}

// One mandate's page, where its signer resumes, stops or signs it again;
// null when this context has no workspace slug to build it under.
export function mandatePageLink(session: MandateSession, id: string): AskUrl | null {
  return mandatePageUrlFor(sessionVault(session), id)?.url ?? null
}

// Who can resume a paused or tripped mandate, in words: this machine never can.
function resumeWords(url: AskUrl | null): string {
  return `the person who signed it can resume it ${url ? `at ${url}` : "from the mandate page"}`
}
type StateOptions = { now?: Date; url?: AskUrl | null }
export function stateText(view: Pick<MachineMandateView, "state" | "endedReason" | "expiresAt">, options: StateOptions = {}): string {
  const url = options.url ?? null
  const again = url ? ` Its signer can sign it again at ${url}, or this machine can propose a new one.` : ""
  if (view.state === "active") return "Active: covers what it names while the person who signed it still stands behind it."
  if (view.state === "paused") return `Paused: nothing goes through on trust; ${resumeWords(url)}.`
  if (view.state === "tripped") return `Tripped: more than ${MANDATE_RATE_LIMIT} requests beyond reading in a minute, so nothing goes through on trust; ${resumeWords(url)}, with their passkey.`
  if (view.state === "expired") return `Ended ${clockText(view.expiresAt, options) ?? view.expiresAt}: it covers nothing.${again}`
  return view.endedReason === "replaced" ? `Replaced by a newer mandate: it covers nothing.${url ? ` Its page: ${url}` : ""}` : `Stopped by a person: it covers nothing.${again}`
}

// The step for a mandate that covers nothing now: its page, for the person
// who signed it. Null for an active one, or with no page to link.
export function mandateNext(view: Pick<MachineMandateView, "id" | "state" | "endedReason">, url: AskUrl | null): NextStep | null {
  if (view.state === "active" || url === null) return null
  if (view.state === "paused" || view.state === "tripped") return { url, say: `Mandate ${view.id} is ${view.state}: pass ${url} to the person who signed it, who can resume it there${view.state === "tripped" ? " with their passkey" : ""}. Until then, ask for each request as usual.` }
  if (view.endedReason === "replaced") return { url, command: "mehen mandate ls", say: `Mandate ${view.id} was replaced by a newer one; mehen mandate ls shows it.` }
  return { url, say: `Mandate ${view.id} has ended: pass ${url} to the person who signed it to sign it again, or propose a new one. Until then, ask for each request as usual.` }
}

// The mandate ls points at: this machine's live one when it covers nothing
// now, else, with none live, the newest when it has ended.
export function listedMandateNeedingSigner(views: readonly MachineMandateView[]): MachineMandateView | null {
  const live = views.find((v) => v.state === "active" || v.state === "paused" || v.state === "tripped")
  if (live) return live.state === "active" ? null : live
  const newest = views[0]
  return newest && newest.endedReason !== "replaced" ? newest : null
}

export function mandateLines(view: MachineMandateView, options: StateOptions = {}): string[] {
  const ends = clockText(view.expiresAt, options) ?? view.expiresAt
  return [
    `${view.id}: for ${view.device.name}, signed by ${view.signer.name}`,
    ...(view.proposal ? [`Signed from proposal ${view.proposal}`] : []),
    stateText(view, options),
    `For: ${view.note}`,
    `May ${classesText(view.classes)} without asking, with ${itemsText(view.items, view.hiddenItems)}.`,
    `Today (UTC): ${todayText(view)}`,
    `Hours: ${view.schedule === null ? "at any time" : scheduleText(view.schedule)}`,
    view.state === "stopped" || view.state === "expired" ? `Signed for ${view.ttlDays} days on ${clockText(view.createdAt, options) ?? view.createdAt}.` : `Ends: ${ends}`,
  ]
}

export function mandateTableRows(views: readonly MachineMandateView[], options: { now?: Date } = {}): string[][] {
  return [
    ["ID", "STATE", "MAY", "TODAY (UTC)", "ENDS", "FOR"],
    ...views.map((v) => [v.id, v.state, classesText(v.classes), todayText(v), clockText(v.expiresAt, options) ?? v.expiresAt, v.note]),
  ]
}

export function receiptTableRows(receipts: readonly MandateReceiptView[], options: { now?: Date } = {}): string[][] {
  return [
    ["WHEN", "CREDENTIAL", "CLASSES", "METHOD", "HOST", "ENTRY", "RUN"],
    ...receipts.map((r) => [clockText(r.at, options) ?? r.at, r.credential?.slug ?? "a credential you cannot see", classesText(r.classes), r.method, r.credential?.host ?? "", r.credential?.entry ?? "", r.credential?.run ?? ""]),
  ]
}

// ---------------------------------------------------------------- schedule

// "Europe/Paris mon-fri 08:00-19:00; sat 10:00-14:00": the time zone once,
// then windows separated by ";", each days and from-to. Days are daily, or
// day names and forward ranges separated by commas (mon,wed-fri). A to
// earlier than from crosses midnight, counted on the day it started.
const DAY_NAMES = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"] as const
const WEEK = [1, 2, 3, 4, 5, 6, 0] as const
const SPAN = /^([0-9]{2}:[0-9]{2})-([0-9]{2}:[0-9]{2})$/
export const SCHEDULE_EXAMPLE = "Europe/Paris mon-fri 08:00-19:00; sat 10:00-14:00"

function dayIndex(name: string): number {
  return DAY_NAMES.indexOf(name as (typeof DAY_NAMES)[number])
}
function daysOf(text: string): number[] | null {
  if (text === "daily") return [0, 1, 2, 3, 4, 5, 6]
  const days = new Set<number>()
  for (const part of text.split(",")) {
    const [from, to, extra] = part.split("-")
    if (from === undefined || extra !== undefined) return null
    const start = WEEK.indexOf(dayIndex(from) as (typeof WEEK)[number])
    const end = to === undefined ? start : WEEK.indexOf(dayIndex(to) as (typeof WEEK)[number])
    if (start === -1 || end === -1 || end < start) return null
    for (let i = start; i <= end; i++) days.add(WEEK[i] as number)
  }
  return [...days].sort((a, b) => a - b)
}

export function parseMandateSchedule(text: string, flag: string, help: string): MandateSchedule {
  const shape = usageError(`${flag} takes a time zone, then windows separated by ";", each days and hours: "${SCHEDULE_EXAMPLE}". Days are daily, or mon to sun with forward ranges (mon-fri) and commas.`, help)
  const segments = text.split(";").map((s) => s.trim().split(/\s+/))
  const first = segments[0] ?? []
  const tz = first.length === 3 ? (first.shift() as string) : null
  if (tz === null) throw shape
  if (!isMandateTimeZone(tz)) throw usageError(`${flag}: ${tz} is not a time zone mehen knows; use an IANA name such as Europe/Paris.`, help)
  const windows = segments.map((words) => {
    const span = words.length === 2 ? SPAN.exec(words[1] as string) : null
    const days = words.length === 2 ? daysOf((words[0] as string).toLowerCase()) : null
    if (span === null || days === null) throw shape
    return { days, from: span[1] as string, to: span[2] as string }
  })
  const parsed = MandateScheduleSchema.safeParse({ tz, windows })
  if (!parsed.success) throw usageError(`${flag}: ${parsed.error.issues.map((i) => i.message).join("; ")}. Hours are 00:00 to 23:59, a window starts and ends at different times, and there are at most 7 windows.`, help)
  return parsed.data
}

function daysText(days: readonly number[]): string {
  if (days.length === 7) return "daily"
  const runs: number[][] = []
  for (const day of WEEK) {
    if (!days.includes(day)) continue
    const last = runs.at(-1)
    if (last && WEEK.indexOf(last.at(-1) as (typeof WEEK)[number]) === WEEK.indexOf(day) - 1) last.push(day)
    else runs.push([day])
  }
  return runs.map((run) => (run.length >= 3 ? `${DAY_NAMES[run[0] as number]}-${DAY_NAMES[run.at(-1) as number]}` : run.map((d) => DAY_NAMES[d]).join(","))).join(",")
}
export function scheduleText(schedule: MandateSchedule): string {
  return `${schedule.tz} ${schedule.windows.map((w) => `${daysText(w.days)} ${w.from}-${w.to}`).join("; ")}`
}

// ---------------------------------------------------------------- proposing

// What a machine asks for; null is the default: the credentials and classes
// it asked for in the last 30 days (MandateAsked), read always, 30 days, the
// protocol's low caps, at any time. The vault refuses a credential or class
// it did not ask for, and every credential; a person widens on the sign page.
export type MandateRequest = {
  items: "all" | readonly string[] | null
  classes: readonly string[] | null
  days: number | null
  caps: Readonly<Record<string, number>>
  schedule: string | null
  note: string
  reason: string | null
}

// Whether the proposal's defaults need what this machine asked for.
export const proposalNeedsAsked = (input: MandateRequest): boolean => input.items === null || input.classes === null
// Stands in for what was asked for while the flags are checked, before any
// call to the vault.
const ASKED_ANYTHING: MandateAsked = { items: ["asked"], classes: ["change", "delete", "send"] }

// Checks the flags before any call to the vault: the proposal itself when no
// default needs what this machine asked for, else null, and mandateProposal
// with askedForMandate's answer builds it.
export function checkMandateRequest(input: MandateRequest, surface: MandateSurface, help: string): MandatePropose | null {
  if (!proposalNeedsAsked(input)) return mandateProposal(input, surface, help, null)
  mandateProposal(input, surface, help, ASKED_ANYTHING)
  return null
}

// asked: GET /v1/mandates/asked, or null when the vault does not say.
export function mandateProposal(input: MandateRequest, surface: MandateSurface, help: string, asked: MandateAsked | null): MandatePropose {
  const flag = (name: string) => (surface === "cli" ? `--${name}` : name)
  if (proposalNeedsAsked(input)) {
    if (asked === null) throw usageError(`This vault does not say what this machine has asked for, so there is no default: name ${flag("items")} and ${flag("classes")}.`, help)
    if (asked.items.length === 0 && input.items === null) throw new CliError("forbidden", "This machine asked for nothing a mandate could cover in the last 30 days, so there is nothing to propose.", { say: "Ask for each request as usual; propose a mandate once more asks like them will follow." }, { mandateRefused: "item_unasked" })
  }
  let items: "all" | string[] = input.items === null ? [...(asked?.items ?? [])].sort() : "all"
  if (input.items !== null && input.items !== "all") {
    if (input.items.length === 0 || !input.items.every((slug) => slug !== "all" && PolicySlugSchema.safeParse(slug).success)) throw usageError(`${flag("items")} takes credential slugs separated by commas.`, help)
    items = [...new Set(input.items)].sort()
  }
  const unknown = (input.classes ?? []).find((c) => !(MANDATE_CLASSES as readonly string[]).includes(c))
  if (unknown !== undefined) throw usageError(`${flag("classes")} takes read, change, send and delete; ${JSON.stringify(unknown)} is none of them.`, help)
  const wanted: readonly string[] = input.classes ?? asked?.classes ?? []
  const classes = MANDATE_CLASSES.filter((c) => c === "read" || wanted.includes(c))
  const days = input.days ?? MANDATE_PROPOSAL_DEFAULT_TTL_DAYS
  if (!(MANDATE_TTL_DAYS as readonly number[]).includes(days)) throw usageError(`${flag("days")} takes 1, 7, 30 or 90.`, help)
  const caps = { read: 0, change: 0, send: 0, delete: 0 }
  for (const [name, value] of Object.entries(input.caps)) {
    const cls = MandateClassSchema.safeParse(name)
    if (!cls.success) throw usageError(`${flag("caps")} names read, change, send or delete; ${JSON.stringify(name)} is none of them.`, help)
    if (!classes.includes(cls.data)) throw usageError(`A cap on ${name} needs ${name} in ${flag("classes")}.`, help)
    if (!Number.isInteger(value) || value < 1 || value > MANDATE_CAP_MAX[cls.data]) throw usageError(`${flag("caps")} ${name} takes a whole number from 1 to ${MANDATE_CAP_MAX[cls.data]} requests a day.`, help)
  }
  for (const c of classes) caps[c] = input.caps[c] ?? MANDATE_PROPOSAL_CAP_DEFAULTS[c]
  const note = input.note.trim()
  if (note === "") throw usageError(`Give ${flag("note")}: what the mandate is for. The person signing reads it.`, help)
  const reason = input.reason?.trim() || note
  const schedule = input.schedule === null ? null : parseMandateSchedule(input.schedule, flag("schedule"), help)
  const parsed = MandateProposeSchema.safeParse({ terms: { items, classes, caps, ttlDays: days, schedule, note }, reason })
  if (!parsed.success) throw usageError(`Invalid mandate proposal: ${parsed.error.issues.map((i) => `${i.path.join(".") || "proposal"}: ${i.message}`).join("; ")}.`, help)
  return parsed.data
}

// --caps send=50,delete=20 as a record; each class once.
export function parseCapsFlag(text: string | null, help: string): Record<string, number> {
  if (text === null) return {}
  const caps: Record<string, number> = {}
  for (const part of text.split(",")) {
    const match = /^([a-z]+)=([0-9]{1,6})$/.exec(part.trim())
    if (!match || Object.hasOwn(caps, match[1] as string)) throw usageError("--caps takes class=number pairs separated by commas, each class once: send=50,delete=20.", help)
    caps[match[1] as string] = Number(match[2])
  }
  return caps
}

export function splitFlag(text: string | null): string[] | null {
  return text === null ? null : text.split(",").map((s) => s.trim())
}

// existing: these very terms were already waiting for the signer, and this
// is that proposal again; nothing new was made.
export type MandateProposalResult = { proposal: string; url: AskUrl; expiresAt: string; existing?: true; ask: Ask; next: NextStep; warning: string | null }

function sessionVault(session: MandateSession): { vaultUrl: string; workspaceSlug: string | null } {
  return { vaultUrl: session.vaultUrl, workspaceSlug: session.config.workspaceSlug ?? null }
}

// A proposal's sign page: the vault's link when it is this vault's for that
// proposal, else the one built from its id, with a warning; null when this
// context has no workspace slug to build it under.
function proposalLink(session: MandateSession, id: string, url: unknown): { link: AskUrl | null; warning: string | null } {
  const vault = sessionVault(session)
  const given = askUrl(url, vault)
  const matching = given?.route?.prefix === "sign-mandate" && given.route.id === id ? given : null
  const link = matching ?? mandateProposalUrlFor(vault, id)
  return { link: link?.url ?? null, warning: matching ? null : refusedLinkWarning(session.vaultUrl) }
}

// The refusal at MANDATE_PROPOSALS_OPEN_MAX open proposals, with the newest
// one's sign page when it is this vault's, else the refused-link warning.
function openProposalsRefused(session: MandateSession, error: unknown, surface: MandateSurface): unknown {
  if (!(error instanceof VaultApiError) || error.body.error !== "conflict") return error
  const given = askUrl(error.body.next?.url, sessionVault(session))
  const link = given?.route?.prefix === "sign-mandate" ? given.url : null
  const refused = link === null && error.body.next?.url !== undefined ? ` ${refusedLinkWarning(session.vaultUrl)}` : ""
  const lists = surface === "cli" ? "`mehen mandate ls`" : 'vault_mandate { "action": "list" }'
  const say = `This machine's proposals are still waiting for its signer; ${lists} lists every open one${link ? `, and the newest is at ${link}` : ""}. Hand a link to the person rather than proposing again.${refused}`
  return new CliError("conflict", error.body.message, { ...(link ? { url: link } : {}), ...(surface === "cli" ? { command: "mehen mandate ls" } : {}), say }, error.context ? { context: error.context } : {})
}

// POST /v1/mandates/proposals: the sign page a person opens. Nothing is
// covered until they sign it with their passkey, with these terms or theirs.
// /v1/me is read first, so a failure there leaves no proposal without a link.
// What this machine asked for lately, which the vault lets it propose; null
// from a vault that does not say (an older one, or mandates off there).
export async function askedForMandate(session: MandateSession): Promise<MandateAsked | null> {
  try {
    return response(askedSchema, await session.api.request<unknown>("GET", "/v1/mandates/asked"))
  } catch (error) {
    if (error instanceof VaultApiError && error.body.error === "not_found" && error.body.message === "No such route.") return null
    throw error
  }
}
const askedSchema = z.object({ items: z.array(PolicySlugSchema), classes: z.array(MandateClassSchema) }) satisfies z.ZodType<MandateAsked>

export async function proposeMandate(session: MandateSession, proposal: MandatePropose, env: Env, surface: MandateSurface): Promise<MandateProposalResult> {
  const label = sessionLabel(env)
  const me = await session.api.request<Me>("GET", "/v1/me")
  let answer: unknown
  try {
    answer = await mandateCall(() => session.api.request<unknown>("POST", "/v1/mandates/proposals", proposal))
  } catch (error) {
    throw openProposalsRefused(session, error, surface)
  }
  const created = response(createdSchema, answer)
  const { link, warning } = proposalLink(session, created.id, created.url)
  if (!link) throw new CliError("internal", "The vault returned no usable mandate proposal link.")
  const ask = withContext(mandateAsk({ id: created.id, url: link, what: proposalText(me.name, proposal), expiresAt: created.expiresAt, requestedBy: { device: me.name, session: label } }), { origin: session.vaultUrl, workspace: configWorkspace(session.config), device: session.config.device })
  const existing = created.existing === true
  const say = existing ? `These terms are already waiting for the person to sign. ${askSay(ask)}` : askSay(ask)
  return { proposal: created.id, url: link, expiresAt: created.expiresAt, ...(existing ? { existing: true as const } : {}), ask, next: { url: ask.url, command: "mehen mandate ls", say }, warning }
}

// ---------------------------------------------------------------- reading and pausing

function mandateId(id: string, help: string): string {
  if (!MandateIdSchema.safeParse(id).success) throw usageError("Give a mandate id (mdt_...); mehen mandate ls lists this machine's.", help)
  return id
}

// An open proposal of this machine's, its link checked as propose's is.
export type MachineOpenProposal = Omit<MandateOpenProposal, "url"> & { url: AskUrl }
export type MachineMandateList = { mandates: MachineMandateView[]; proposals: MachineOpenProposal[]; warning: string | null }

// GET /v1/mandates: this machine's mandates and its open proposals, newest
// first. A proposal with no link to hand over is left out, with the warning.
export async function listMandates(session: MandateSession, signal?: AbortSignal): Promise<MachineMandateList> {
  const list = response(listSchema, await mandateCall(() => session.api.request<unknown>("GET", "/v1/mandates", undefined, signal ? { signal } : {})))
  let warning: string | null = null
  const proposals = list.proposals.flatMap((p) => {
    const checked = proposalLink(session, p.id, p.url)
    warning ??= checked.warning
    return checked.link ? [{ ...p, url: checked.link }] : []
  })
  return { mandates: list.mandates, proposals, warning }
}

// "Waiting for its signer: <url>, proposed 8 Nov 09:00, expires 15 Nov 09:00: <reason>"
export function openProposalLine(proposal: MachineOpenProposal, options: { now?: Date } = {}): string {
  return `Waiting for its signer: ${proposal.url}, proposed ${clockText(proposal.createdAt, options) ?? proposal.createdAt}, expires ${clockText(proposal.expiresAt, options) ?? proposal.expiresAt}: ${proposal.reason}`
}

export async function showMandate(session: MandateSession, id: string, help: string): Promise<MachineMandateView> {
  mandateId(id, help)
  const view = response(mandateViewSchema, await mandateCall(() => session.api.request<unknown>("GET", `/v1/mandates/${id}`)))
  if (view.id !== id) throw new CliError("internal", "The vault returned a different mandate.")
  return view
}

// "2026-11-08T09:00:00Z", or 30m, 12h or 7d before now.
export function parseSince(text: string, flag: string, help: string, now = Date.now()): number {
  const relative = /^([1-9][0-9]{0,4})(m|h|d)$/.exec(text.trim())
  if (relative) return now - Number(relative[1]) * { m: 60_000, h: 3_600_000, d: 86_400_000 }[relative[2] as "m" | "h" | "d"]
  if (timestamp.safeParse(text).success) return Date.parse(text)
  throw usageError(`${flag} takes a time with its offset (2026-11-08T09:00:00Z) or a span back from now: 30m, 12h or 7d.`, help)
}

export type MandateUsesRequest = { since: number | null; before: string | null; limit: number | null }
// next is the cursor to carry on from when it stopped at the limit.
export type MandateUses = { receipts: MandateReceiptView[]; next: string | null }

// GET /v1/mandates/:id/uses, page after page, newest first, from before
// until a receipt older than since, the last page or limit receipts.
export async function mandateUses(session: MandateSession, id: string, request: MandateUsesRequest, help: string): Promise<MandateUses> {
  mandateId(id, help)
  const { since, limit } = request
  const receipts: MandateReceiptView[] = []
  const cursors = new Set<string>()
  let before = request.before
  for (;;) {
    const path: string = `/v1/mandates/${id}/uses${before === null ? "" : `?before=${encodeURIComponent(before)}`}`
    const page = response(receiptsPageSchema, await mandateCall(() => session.api.request<unknown>("GET", path)))
    for (const receipt of page.receipts) {
      if (since !== null && Date.parse(receipt.at) < since) return { receipts, next: null }
      const last = receipts.at(-1)
      if (limit !== null && receipts.length >= limit && last) return { receipts, next: mandateReceiptsCursor(Date.parse(last.at), last.id) }
      receipts.push(receipt)
    }
    if (page.next === null || cursors.has(page.next)) return { receipts, next: null }
    cursors.add(page.next)
    before = page.next
  }
}

export type MandatePaused = { mandate: MachineMandateView; was: MachineMandateView["state"]; said: string; next: NextStep | null }

// POST /v1/mandates/:id/pause at the revision just read: this machine
// pausing itself. A paused or tripped one covers nothing already, so it is
// left as it is and nothing is sent.
export async function pauseMandate(session: MandateSession, id: string, help: string): Promise<MandatePaused> {
  const current = await showMandate(session, id, help)
  const url = mandatePageLink(session, id)
  if (current.state === "stopped" || current.state === "expired") throw new CliError("conflict", `Mandate ${id} has ended (${current.state}); there is nothing to pause.`, { ...(url ? { url } : {}), command: `mehen mandate show ${id}`, say: `It covers nothing already; carry on asking for each request.${url ? ` Its signer can sign it again at ${url}.` : ""}` })
  if (current.state !== "active") return { mandate: current, was: current.state, said: pausedText(current.state, current, url), next: mandateNext(current, url) }
  let changed: z.infer<typeof changedSchema>
  try {
    changed = response(changedSchema, await mandateCall(() => session.api.request<unknown>("POST", `/v1/mandates/${id}/pause`, { rev: current.rev })))
  } catch (error) {
    if (error instanceof VaultApiError && error.body.error === "conflict") throw new CliError("conflict", error.body.message, { command: `mehen mandate pause ${id}`, say: "The mandate changed while pausing it; run the same command once more." })
    throw error
  }
  return { mandate: changed.mandate, was: current.state, said: pausedText(current.state, changed.mandate, url), next: mandateNext(changed.mandate, url) }
}

// mehen mandate pause with no id: this machine's one live mandate in this
// workspace, refused when there is none or, which the vault never allows,
// more than one.
export async function pauseLiveMandate(session: MandateSession, surface: MandateSurface, help: string): Promise<MandatePaused> {
  const { mandates } = await listMandates(session)
  const live = mandates.filter((m) => MANDATE_LIVE_STATES.includes(m.state))
  if (live.length === 0) {
    const lists = surface === "cli" ? "`mehen mandate ls`" : 'vault_mandate { "action": "list" }'
    throw new CliError("not_found", "This machine has no live mandate in this workspace; there is nothing to pause.", { ...(surface === "cli" ? { command: "mehen mandate ls" } : {}), say: `Nothing goes through on trust here already; carry on asking for each request. ${lists} lists this machine's mandates and open proposals.` })
  }
  if (live.length > 1) {
    const first = (live[0] as MachineMandateView).id
    const message = `This machine has ${live.length} live mandates in this workspace (${live.map((m) => m.id).join(", ")}); name the one to pause.`
    if (surface === "mcp") throw new CliError("conflict", message, { say: `Pause each with vault_mandate { "action": "pause", "id": "<mdt_id>" }, such as ${first}.` })
    throw new CliError("conflict", message, { command: `mehen mandate pause ${first}`, say: "Pause each with `mehen mandate pause <mdt_id>`." })
  }
  return pauseMandate(session, (live[0] as MachineMandateView).id, help)
}

function pausedText(was: MachineMandateView["state"], now: MachineMandateView, url: AskUrl | null): string {
  if (was !== "active") return `Mandate ${now.id} was already ${was}; nothing changed. ${stateText(now, { url })}`
  const words = resumeWords(url)
  return `Paused mandate ${now.id}: nothing goes through on trust now. ${words.charAt(0).toUpperCase()}${words.slice(1)}; as this machine paused it, they need no passkey unless their own access has changed since they signed.`
}

// ---------------------------------------------------------------- status

// This machine's live mandate in a workspace, for mehen status and
// vault_status; null when it has none live.
export type MandateStatus = Pick<MachineMandateView, "id" | "state" | "classes" | "today" | "caps" | "expiresAt">
export type MandateStatusRead = { mandate: MandateStatus | null; mandateProposals: number }

// Best effort: a refusal, mandates switched off, a vault from before them,
// a network failure or no answer within MANDATE_STATUS_TIMEOUT_MS is null,
// and status says nothing about mandates.
const MANDATE_STATUS_TIMEOUT_MS = 2000
export async function readMandateStatus(session: MandateSession): Promise<MandateStatusRead | null> {
  try {
    const { mandates, proposals } = await listMandates(session, AbortSignal.timeout(MANDATE_STATUS_TIMEOUT_MS))
    const live = mandates.find((m) => MANDATE_LIVE_STATES.includes(m.state))
    return { mandate: live ? { id: live.id, state: live.state, classes: live.classes, today: live.today, caps: live.caps, expiresAt: live.expiresAt } : null, mandateProposals: proposals.length }
  } catch {
    return null
  }
}

// "mdt_live: active, change 3/200, send 1/50, delete 0/20, ends 6 Feb": the
// ticked classes but read, which has no cap worth counting against.
export function mandateStatusText(mandate: MandateStatus, timeZone?: string): string {
  const counts = ordered(mandate.classes).filter((c) => c !== "read").map((c) => `${c} ${mandate.today[c]}/${mandate.caps[c]}`)
  const ends = new Intl.DateTimeFormat("en-GB", { ...(timeZone ? { timeZone } : {}), day: "numeric", month: "short" }).format(new Date(mandate.expiresAt))
  return [`${mandate.id}: ${mandate.state}`, ...counts, `ends ${ends}`].join(", ")
}

export function mandateProposalsText(count: number): string {
  return `${count} proposal${count === 1 ? "" : "s"} waiting for its signer (mehen mandate ls)`
}

// ---------------------------------------------------------------- relay

// Mehen-Mandate on a relayed response: the mandate that let it through
// without asking, read only when it is one well-formed id.
export function mandateAllowed(response: Response): string | null {
  const id = response.headers.get(MANDATE_HEADER)
  return id !== null && MandateIdSchema.safeParse(id).success ? id : null
}
export function mandateAllowedText(id: string): string {
  return `allowed without asking by this machine's mandate ${id}`
}

// The caps a held request reached, said in words: the number from the
// mandate's own caps when this machine could read them, else without.
export function cappedText(capped: readonly MandateClass[], caps: MandateCaps | null): string {
  return `This machine's mandate has used today's ${listText(ordered(capped).map((c) => (caps ? `${caps[c]} ${PLURAL[c]}` : PLURAL[c])))}.`
}

// A held request a mandate would have let through but for a cap: the
// refusal says which caps in words, with their numbers when this machine
// can read its mandate, and only then carries mandate.
export async function mandateCapped(api: VaultApi, error: unknown, signal?: AbortSignal): Promise<unknown> {
  if (!(error instanceof VaultApiError) || error.body.error !== "approval_required" || error.body.mandate === undefined) return error
  const { id, capped } = error.body.mandate
  let caps: MandateCaps | null = null
  try {
    caps = mandateViewSchema.parse(await api.request<unknown>("GET", `/v1/mandates/${id}`, undefined, signal ? { signal } : {})).caps
  } catch {
    caps = null
  }
  const failure = toCliError(error)
  return new CliError(failure.code, `${failure.message} ${cappedText(capped, caps)}`, failure.next, { ...failure.extras, mandate: error.body.mandate })
}
