// Mandates (mdt_): a person signs once, with a passkey, that one of their
// own machines may send certain kinds of held request with certain
// credentials without asking, until a date, within daily caps and,
// optionally, only in certain hours. The shapes, limits and views are here,
// which workspace.ts and the pages can import without the safety catalogue;
// mandates.ts decides what a request is and whether a mandate covers it.

import { z } from "zod"
import { PolicyDeviceIdSchema, PolicyItemIdSchema, PolicySlugSchema } from "./policy-mode.ts"

export const MANDATE_CLASSES = ["change", "delete", "read", "send"] as const
export const MandateClassSchema = z.enum(MANDATE_CLASSES)
export type MandateClass = z.infer<typeof MandateClassSchema>
export type MandateCaps = Record<MandateClass, number>

// Requests per UTC day, for a ticked class, by default and at most.
export const MANDATE_CAP_DEFAULTS: Readonly<MandateCaps> = { read: 5000, change: 2000, send: 50, delete: 20 }
export const MANDATE_CAP_MAX: Readonly<MandateCaps> = { read: 50_000, change: 10_000, send: 500, delete: 200 }
export const MANDATE_TTL_DAYS = [1, 7, 30, 90] as const
export type MandateTtlDays = (typeof MANDATE_TTL_DAYS)[number]
export const MANDATE_DEFAULT_TTL_DAYS: MandateTtlDays = 90
// Its signer hears this long before a live mandate ends, or at signing when
// it is shorter; renewing it is signing again.
export const MANDATE_ENDING_NOTICE_MS = 3 * 86_400_000
// More than this many covered requests of a class other than read in any
// rolling MANDATE_RATE_WINDOW_MS trips the whole mandate: request 121 is not
// let through.
export const MANDATE_RATE_LIMIT = 120
export const MANDATE_RATE_WINDOW_MS = 60_000
export const MANDATE_PROPOSAL_TTL_MS = 7 * 86_400_000
export const MANDATE_RECEIPT_KEEP_MS = 30 * 86_400_000
// A machine may propose a mandate only for the credentials and classes it
// asked for (a held request a mandate could cover) or used under its own
// mandate in this window; read is always allowed. A person widens terms on
// the sign page.
export const MANDATE_ASKED_WINDOW_MS = 30 * 86_400_000
// What mehen mandate propose and vault_mandate propose by default, and the
// most a machine may propose: the person signing may raise them.
export const MANDATE_PROPOSAL_DEFAULT_TTL_DAYS: MandateTtlDays = 30
export const MANDATE_PROPOSAL_CAP_DEFAULTS: Readonly<MandateCaps> = { read: 500, change: 100, send: 10, delete: 5 }
// Why the vault refused a machine's proposal (forbidden, mandateRefused):
// it named every credential, a credential or a class it did not ask for,
// more days than MANDATE_PROPOSAL_DEFAULT_TTL_DAYS or a cap above
// MANDATE_PROPOSAL_CAP_DEFAULTS.
export const MANDATE_PROPOSAL_REFUSALS = ["items_all", "item_unasked", "class_unasked", "term_too_long", "caps_too_high"] as const
export type MandateProposalRefusal = (typeof MANDATE_PROPOSAL_REFUSALS)[number]
export const MANDATE_MAX_ITEMS = 200
export const MANDATE_NOTE_MAX = 200
export const MANDATE_MAX_WINDOWS = 7
// A machine's open proposals at once, and its proposals in a UTC day.
export const MANDATE_PROPOSALS_OPEN_MAX = 3
export const MANDATE_PROPOSALS_DAY_MAX = 10
export const MANDATE_LIST_MAX = 20
export const MANDATE_USES_PAGE = 100

export const MandateIdSchema = z.string().regex(/^mdt_[A-Za-z0-9_-]{1,60}$/)
export const MandateProposalIdSchema = z.string().regex(/^mdp_[A-Za-z0-9_-]{1,60}$/)
export const MANDATE_STATES = ["active", "paused", "tripped", "stopped", "expired"] as const
export const MandateStateSchema = z.enum(MANDATE_STATES)
export type MandateState = z.infer<typeof MandateStateSchema>
// A machine has at most one mandate in one of these at a time.
export const MANDATE_LIVE_STATES: readonly MandateState[] = ["active", "paused", "tripped"]

const sortedUnique = <T extends string | number>(values: readonly T[]): boolean => values.every((v, i) => i === 0 || (values[i - 1] as T) < v)

// Whether Intl knows this time zone.
export function isMandateTimeZone(tz: string): boolean {
  if (tz.length === 0 || tz.length > 64) return false
  try {
    new Intl.DateTimeFormat("en-GB", { timeZone: tz })
    return true
  } catch {
    return false
  }
}

const ClockSchema = z.string().regex(/^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/)
// days: 0 Sunday to 6 Saturday. A to earlier than from crosses midnight,
// and the day is the day it started; from and to are never the same.
export const MandateWindowSchema = z.strictObject({
  days: z.array(z.number().int().min(0).max(6)).min(1).max(7).refine(sortedUnique, "Days are sorted and unique"),
  from: ClockSchema,
  to: ClockSchema,
}).refine((w) => w.from !== w.to, "A window starts and ends at different times")
export type MandateWindow = z.infer<typeof MandateWindowSchema>
export const MandateScheduleSchema = z.strictObject({
  tz: z.string().refine(isMandateTimeZone, "Use an IANA time zone"),
  windows: z.array(MandateWindowSchema).min(1).max(MANDATE_MAX_WINDOWS),
})
export type MandateSchedule = z.infer<typeof MandateScheduleSchema>
// A schedule as mehen mandate propose --schedule takes it:
// "Europe/Paris mon-fri 08:00-19:00; sat 10:00-14:00".
const SCHEDULE_DAY_NAMES = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"] as const
const SCHEDULE_WEEK = [1, 2, 3, 4, 5, 6, 0] as const
function scheduleDaysText(days: readonly number[]): string {
  if (days.length === 7) return "daily"
  const runs: number[][] = []
  for (const day of SCHEDULE_WEEK) {
    if (!days.includes(day)) continue
    const last = runs.at(-1)
    if (last && SCHEDULE_WEEK.indexOf(last.at(-1) as (typeof SCHEDULE_WEEK)[number]) === SCHEDULE_WEEK.indexOf(day) - 1) last.push(day)
    else runs.push([day])
  }
  return runs.map((run) => (run.length >= 3 ? `${SCHEDULE_DAY_NAMES[run[0] as number]}-${SCHEDULE_DAY_NAMES[run.at(-1) as number]}` : run.map((d) => SCHEDULE_DAY_NAMES[d]).join(","))).join(",")
}
export function mandateScheduleText(schedule: MandateSchedule): string {
  return `${schedule.tz} ${schedule.windows.map((w) => `${scheduleDaysText(w.days)} ${w.from}-${w.to}`).join("; ")}`
}

const CapSchema = z.number().int().min(0).max(Math.max(...Object.values(MANDATE_CAP_MAX)))
const MandateCapsSchema = z.strictObject({ read: CapSchema, change: CapSchema, send: CapSchema, delete: CapSchema })
const MandateClassesSchema = z.array(MandateClassSchema).min(1).max(MANDATE_CLASSES.length)
  .refine(sortedUnique, "Classes are sorted and unique")
  .refine((classes) => classes.includes("read"), "Read is always included")
const NoteSchema = z.string().min(1).max(MANDATE_NOTE_MAX).refine((n) => n.trim() === n && n !== "", "A note has no leading or trailing spaces")
const TtlDaysSchema = z.literal(MANDATE_TTL_DAYS)

// Each ticked class a cap between 1 and its most, each other class 0.
export function mandateCapsFit(classes: readonly MandateClass[], caps: MandateCaps): boolean {
  return MANDATE_CLASSES.every((c) => (classes.includes(c) ? caps[c] >= 1 && caps[c] <= MANDATE_CAP_MAX[c] : caps[c] === 0))
}

const termsFields = {
  classes: MandateClassesSchema,
  caps: MandateCapsSchema,
  ttlDays: TtlDaysSchema,
  schedule: MandateScheduleSchema.nullable(),
  note: NoteSchema,
}
// items: credential ids, sorted and each once, or "all": every credential
// the machine reaches at the time of use while the signer manages its home.
export const MandateTermsSchema = z.strictObject({
  device: PolicyDeviceIdSchema,
  items: z.union([z.literal("all"), z.array(PolicyItemIdSchema).min(1).max(MANDATE_MAX_ITEMS).refine(sortedUnique, "Credentials are sorted and unique")]),
  ...termsFields,
}).refine((t) => mandateCapsFit(t.classes, t.caps), "Each ticked class has a cap within its bounds, and each other class 0")
export type MandateTerms = z.infer<typeof MandateTermsSchema>

// What a machine proposes (POST /v1/mandates/proposals): the terms without
// the device, which is itself, naming credentials by slug, as it knows them.
export const MandateProposedTermsSchema = z.strictObject({
  items: z.union([z.literal("all"), z.array(PolicySlugSchema).min(1).max(MANDATE_MAX_ITEMS).refine(sortedUnique, "Credentials are sorted and unique")]),
  ...termsFields,
}).refine((t) => mandateCapsFit(t.classes, t.caps), "Each ticked class has a cap within its bounds, and each other class 0")
export type MandateProposedTerms = z.infer<typeof MandateProposedTermsSchema>
export const MandateProposeSchema = z.strictObject({ terms: MandateProposedTermsSchema, reason: z.string().min(1).max(MANDATE_NOTE_MAX) })
export type MandatePropose = z.infer<typeof MandateProposeSchema>
// existing: an open proposal of this machine with the same terms and reason,
// handed back instead of a new one.
export type MandateProposalCreated = { id: string; url: string; expiresAt: string; existing?: true }

// The workspace's step-up planning (POST /api/w/<ws>/mandates/action): the
// action to sign for a signature or a resume, rebuilt from live state.
export const MandateActionRequestSchema = z.discriminatedUnion("op", [
  z.strictObject({ op: z.literal("sign"), terms: MandateTermsSchema, proposal: MandateProposalIdSchema.optional() }),
  z.strictObject({ op: z.literal("resume"), id: MandateIdSchema, rev: z.number().int().min(1) }),
])
export type MandateActionRequest = z.infer<typeof MandateActionRequestSchema>
// POST /api/w/<ws>/mandates, beside its step-up.
export const MandateSignSchema = z.strictObject({ terms: MandateTermsSchema, proposal: MandateProposalIdSchema.optional() })
// POST /api/w/<ws>/mandates/:id/resume, beside its step-up when
// /mandates/action names one; pause and stop name the revision the page
// showed and need none.
export const MandateRevSchema = z.strictObject({ rev: z.number().int().min(1) })

// ---------------------------------------------------------------- views

// What every reader sees, computed at read time from their access now:
// the device, the signer, or an owner or admin who
// may read the machine. Raw terms and receipt rows never leave the vault.
export type MandateCounts = Record<MandateClass, number>
// items: the slug of each credential the reader may see now, or "all";
// hiddenItems: how many others it names (0 for "all"); signerCurrent, for
// a person reading a live mandate only (never the machine): whether the
// person who signed still stands behind it (their account, role and
// identity check as they signed, the machine still theirs, and no lapse),
// for any credential: an active mandate whose signer does not covers
// nothing until they resume it with a passkey. signer.self, for a person
// only: whether the reader signed it. proposal: the mdp_ id it was signed
// from, null when signed without one; the vault always sends it, to every
// reader.
export type MandateView = {
  id: string
  device: { id: string; name: string }
  signer: { name: string; self?: boolean }
  state: MandateState
  rev: number
  signerCurrent?: boolean
  items: "all" | string[]
  hiddenItems: number
  classes: MandateClass[]
  caps: MandateCaps
  today: MandateCounts
  ttlDays: MandateTtlDays
  schedule: MandateSchedule | null
  note: string
  createdAt: string
  expiresAt: string
  endedReason: "stopped" | "expired" | "replaced" | null
  proposal?: string | null
}
// One request a mandate let through. credential: null for one the reader
// may not see now, a deleted one included: then only when, the classes and
// the method.
export type MandateReceiptView = {
  id: string
  at: string
  classes: MandateClass[]
  method: string
  credential: { slug: string; host: string; entry: string; run: string | null } | null
}
// Newest first; next: the before= cursor of the next page, or null.
export type MandateReceiptsPage = { receipts: MandateReceiptView[]; next: string | null }
// An open proposal in a list: the machine's own, for the machine; for a
// person, those of machines they may sign for. items: slugs the reader may see.
export type MandateOpenProposal = { id: string; url: string; expiresAt: string; createdAt: string; device: { id: string; name: string }; classes: MandateClass[]; items: "all" | string[]; hiddenItems: number; reason: string }
export type MandateList = { mandates: MandateView[]; proposals: MandateOpenProposal[] }
// On approval_required to the machine itself: a mandate could let requests
// like this one through, and why this one asked. url: the machine's mandate
// page, null for none.
export type MandateCoverState = "none" | "paused" | "tripped" | "ended" | "outside_schedule" | "unticked" | "not_covering"
export type MandateCoverHint = { classes: MandateClass[]; state: MandateCoverState; mandate: string | null; url: string | null }
// What every mutation (sign, pause, resume, stop) answers.
export type MandateChanged = { mandate: MandateView }
// A credential a proposal names, for its machine's owner, who signs terms
// that name it by id.
export type MandateItemRef = { id: string; slug: string }
// GET /api/w/<ws>/mandate-candidates?device=: the credentials the sign page
// may offer for the reader's own machine, each one it reaches now and whose
// home the reader manages, by slug.
export type MandateCandidates = { items: MandateItemRef[] }
// GET /api/w/<ws>/mandate-asks/:approval: an ask the machine's mandate
// would have let through but for these classes' caps for the day.
export type MandateCappedAsk = { mandate: string; capped: { class: MandateClass; cap: number }[] }
// GET /api/w/<ws>/mandate-covers/:approval, for the person who may sign for
// the machine: a mandate could let asks like this one through. state: the
// machine's live mandate paused or tripped (mandate names it), or "sign"
// for anything else, a mandate to sign covering these classes.
export type MandateCoverAsk = { device: { id: string; name: string }; classes: MandateClass[]; state: "sign" | "paused" | "tripped"; mandate: string | null }
// GET /v1/mandates/asked: what this machine may propose a mandate for, the
// credentials by slug and the classes besides read it asked for or used in
// the last MANDATE_ASKED_WINDOW_MS, sorted.
export type MandateAsked = { items: string[]; classes: MandateClass[] }
// mandate: for a signed one, the mandate signed from it; for an expired
// one, the mandate signed for its machine since that closed it, if any.
export type MandateProposalView = {
  id: string
  device: { id: string; name: string }
  items: "all" | MandateItemRef[]
  hiddenItems: number
  classes: MandateClass[]
  caps: MandateCaps
  ttlDays: MandateTtlDays
  schedule: MandateSchedule | null
  note: string
  reason: string
  state: "open" | "signed" | "expired"
  mandate: string | null
  createdAt: string
  expiresAt: string
}

// The before= cursor of a receipts page: the last receipt's time and id.
export function mandateReceiptsCursor(at: number, id: string): string {
  return `${at}.${id}`
}
export function parseMandateReceiptsCursor(cursor: string): { at: number; id: string } | null {
  const match = /^([0-9]{1,16})\.(mdu_[A-Za-z0-9_-]{1,60})$/.exec(cursor)
  return match ? { at: Number(match[1]), id: match[2] as string } : null
}
