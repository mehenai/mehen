// Review together's rules with no DOM, so the page, its script and the
// tests share them: which section a row is listed under and whether it
// starts ticked, the marks and reasons in words, the bar's labels, the
// empty group, and what a batch decision did, from the vault's answer.

import type { PolicyFloorView } from "@mehen/protocol/policy-mode"
import type { ApprovalBatchOutcome, ApprovalBatchResult, ApprovalBatchState, ApprovalGroupRow, ApprovalOwnPageReason } from "@mehen/protocol/workspace"
import type { ReviewRowBoot } from "../workspace-logic.ts"

// The page polls the group every 20 s while the tab is visible, as Needs you does.
export const REVIEW_POLL_MS = 20_000

export const REVIEW_SECTION_ORDER: readonly ApprovalBatchState[] = ["routine", "floor", "own-page", "deny-only"]
export const REVIEW_SECTION_TITLES: Readonly<Record<ApprovalBatchState, string>> = {
  routine: "Ready",
  floor: "Look at these first",
  "own-page": "Decide on its own page",
  "deny-only": "You can only deny these",
}
export const FLOOR_MARK_WORDS: Readonly<Record<PolicyFloorView["reason"], string>> = {
  send: "Sends email",
  money: "Moves money",
  sharing: "Shares access",
  destructive: "Deletes",
  credential: "Changes a credential",
  persistence: "Sets up something that keeps running",
  opaque: "Cannot be read for safety",
}
// A floor row with no named reason: an older ask, stored before the floor was.
export const FLOOR_UNNAMED_WORDS = "Cannot be read for safety"
// Partial: a reason added to the vault later reads as OWN_PAGE_OTHER_WORDS
// until it has words here.
export const OWN_PAGE_REASON_WORDS: Readonly<Partial<Record<ApprovalOwnPageReason, string>>> = {
  run: "A protected run",
  "four-eyes": "Needs a second person",
  warning: "Carries a warning",
  unbound: "Needs a fresh look",
}
// A row decided on its own page for a reason this page has no words for
// (a push, say, which is sent from there).
export const OWN_PAGE_OTHER_WORDS = "Decide it on its own page"
export const REVIEW_PROTECTED_WORDS = "Protected"
export const REVIEW_NEWER_WORDS = "A newer ask to the same place is further down."
export const REVIEW_DENY_ONLY_WORDS = "Deny only"
export const REVIEW_NEW_WORDS = "New"
export const REVIEW_MISMATCH_WORDS = "This page's copy of the request does not match what the vault stored. Decide it on its own page."
export const REVIEW_FOOTNOTE = "To shorten a grant or allow it from now on, open its own page."
export const REVIEW_NEXT_WORDS = "Approving lets each ticked request through as it was asked; denying tells the agent no. Your passkey confirms every ticked row at once, each exactly as this page shows it. Unticked rows stay waiting."
export const REVIEW_STOP_WORDS = "A private request: you may stop it, but not read it."

export function reviewPending(row: ApprovalGroupRow): boolean {
  return (row.view === "detail" ? row.approval.status : row.stop.status) === "pending"
}

export function reviewRowId(row: ApprovalGroupRow): string {
  return row.view === "detail" ? row.approval.approval : row.stop.id
}

// A still-pending row a poll found changed: the vault now lists it in
// another section, or a newer ask of its shape now follows it or no longer
// does. Its drawn element is replaced by the server's (moved to its new
// section when it has one), unticked, the page holds the fresh row, and a
// detail row's binding is checked again.
export type ReviewRowRedraw = { row: ReviewRowBoot; moved: boolean; untick: true; check: boolean }

// The poll's plan for the rows still pending both on the page and in the
// fresh group. Every other still-pending row keeps its element and its
// tick; rows that left pending and new arrivals are handled apart.
export function reviewRedraw(held: readonly ReviewRowBoot[], fresh: readonly ReviewRowBoot[]): ReviewRowRedraw[] {
  const newer = (row: ReviewRowBoot) => row.view === "detail" && row.newer
  return fresh.flatMap((row) => {
    const was = held.find((h) => h.approval === row.approval)
    if (was === undefined || !was.pending || !row.pending || (was.section === row.section && newer(was) === newer(row))) return []
    return [{ row, moved: was.section !== row.section, untick: true as const, check: row.view === "detail" }]
  })
}

// Whether a row the poll brings needs a button the page was drawn without
// (no bar at all, or no Approve when only deny-only rows waited): such a
// row cannot be decided here, so the page is drawn again.
export function reviewLacksButtonFor(section: ApprovalBatchState, buttons: { approve: boolean; deny: boolean }): boolean {
  if (section === "own-page") return false
  return section === "deny-only" ? !buttons.deny : !buttons.approve
}

// A page drawn with no sections (a group with nothing this viewer could
// see) has nowhere to put an ask that arrives: it is drawn again instead.
export function reviewReloadsForArrivals(drewSections: boolean, fresh: readonly ReviewRowBoot[]): boolean {
  return !drewSections && fresh.some((row) => row.pending)
}

// Only a pending row listed under routine starts ticked (section: where
// the page lists it, approvalGroupSection): never a floor, deny-only or
// own-page row, a push, a protected credential's use (ruling B2), or a row
// a newer ask of the same shape follows (ruling B1).
export function reviewTickedAtStart(row: ApprovalGroupRow, section: ApprovalBatchState): boolean {
  if (!reviewPending(row) || section !== "routine" || row.view !== "detail") return false
  return row.protected !== true && (row.newerSameShape ?? null) === null
}

// Why a row is decided on its own page, in words; a reason the page has
// no words for reads as the plain instruction.
export function reviewOwnPageWords(row: ApprovalGroupRow): string {
  if (row.view !== "detail" || row.ownPage === null) return OWN_PAGE_OTHER_WORDS
  return OWN_PAGE_REASON_WORDS[row.ownPage] ?? OWN_PAGE_OTHER_WORDS
}

// The floor marks of a row, each once; a floor row with none named reads
// as one that cannot be read.
export function reviewFloorMarks(row: ApprovalGroupRow): string[] {
  if (row.view !== "detail" || row.batch !== "floor" || row.protected === true && row.floor.length === 0) return []
  if (row.floor.length === 0) return [FLOOR_UNNAMED_WORDS]
  return [...new Set(row.floor.map((reason) => FLOOR_MARK_WORDS[reason] ?? FLOOR_UNNAMED_WORDS))]
}

// The group code tick: the one code mehen prints with the group's link.
export function reviewGroupCodeWords(code: string): string {
  return `The agent showed me the code ${code}`
}
// The other tick, for an agent that showed each ask's code instead (a mehen
// before group codes, or a group made before them): every ticked row checked.
export function reviewCodesWords(ticked: number): string {
  return `The agent showed separate codes, and I checked them against the rows (${ticked} ticked)`
}
// Asks that joined the group after the page was drawn: the code ticks are
// cleared, so nothing is approved before the person has seen them.
export function reviewChangedWords(arrived: number): string {
  return `${arrived === 1 ? "An ask" : `${arrived} asks`} joined this group since the page loaded, marked New and not ticked. Check ${arrived === 1 ? "it" : "them"}, then tick the code again.`
}

// approve: the ticked rows Approve decides. denyOnly: the ticked rows it
// leaves for Deny ticked.
export function reviewApproveLabel(approve: number, denyOnly: number): string {
  return `Approve ${approve} with passkey${denyOnly > 0 ? ` (${denyOnly} can only be denied)` : ""}`
}

export function reviewEmptyWords(settled: number): string {
  return settled > 0 ? `Nothing waiting here. ${settled} decided in the last hour.` : "Nothing waiting here."
}

// How many asks or requests a group holds, for its title.
export function reviewCountWords(n: number, kind: "machine" | "bundle"): string {
  return kind === "bundle" ? `${n} ${n === 1 ? "request" : "requests"} to approve together` : `${n} ${n === 1 ? "ask" : "asks"}`
}

const SKIPPED_WORDS: Readonly<Record<Exclude<ApprovalBatchOutcome, "approved" | "denied">, readonly [string, string]>> = {
  expired: ["had expired", "had expired"],
  decided: ["was already decided", "were already decided"],
  superseded: ["was replaced by a newer ask", "were replaced by newer asks"],
  stale: ["no longer applies", "no longer apply"],
  forbidden: ["is no longer yours to decide", "are no longer yours to decide"],
  changed: ["changed since the page loaded", "changed since the page loaded"],
  own_page: ["must be decided on its own page", "must be decided on their own pages"],
}

// What a batch did, from the vault's answer, never from what was ticked:
// "11 approved. 1 had expired."
export function reviewOutcomeWords(result: ApprovalBatchResult): string {
  const counts = new Map<ApprovalBatchOutcome, number>()
  for (const r of result.results) counts.set(r.outcome, (counts.get(r.outcome) ?? 0) + 1)
  const parts: string[] = []
  for (const decided of ["approved", "denied"] as const) if ((counts.get(decided) ?? 0) > 0) parts.push(`${counts.get(decided)} ${decided}.`)
  for (const [outcome, [one, many]] of Object.entries(SKIPPED_WORDS) as [keyof typeof SKIPPED_WORDS, readonly [string, string]][]) {
    const n = counts.get(outcome) ?? 0
    if (n > 0) parts.push(`${n} ${n === 1 ? one : many}.`)
  }
  return parts.length === 0 ? "Nothing was decided." : parts.join(" ")
}
