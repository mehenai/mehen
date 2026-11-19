// The account inbox's rules with no DOM, so the server tests can check them
// and the pages render them the same way on both sides: how the inbox is
// grouped, what an empty or partial inbox says, the count in words for the
// badge and the tab title, and the poller's validator and sequence numbers.
//
// A count is shown only when the vault gave one: never zero by default and
// never the one-workspace count where the account-wide one belongs. A
// response that arrives after a newer one was applied is dropped, a 304
// keeps what is shown, and a 401 ends the poll and clears every row.

import type { InboxItem, InboxResponse, InboxWorkspace, InboxWorkspaceState } from "@mehen/protocol/inbox"

export const NEEDS_YOU_PATH = "/needs-you"
export const NEEDS_YOU_API = "/api/needs-you"

// The inbox page polls every 20 s while visible; the badge on every other
// page every 60 s. Neither polls while the tab is hidden.
export const NEEDS_YOU_POLL_MS = 20_000
export const BADGE_POLL_MS = 60_000
// A refresh still in flight after this long says "Checking...".
export const CHECKING_AFTER_MS = 2_000

export const SESSION_ENDED_WORDS = "Your session has ended."
export const RETRYING_WORDS = "Could not check just now; retrying."

// ---------------------------------------------------------------- counts

// The badge's text: null (hidden) while unknown or zero; "3" when every
// workspace answered, "3+" when some did not, so the number is a floor.
export function countWords(count: number | null, complete: boolean): string | null {
  if (count === null || count <= 0) return null
  return complete ? String(count) : `${count}+`
}

// The document title on /needs-you: "(2) Needs you" while anything waits.
export function needsYouTitle(count: number | null, complete: boolean): string {
  const words = countWords(count, complete)
  return words === null ? "Needs you" : `(${words}) Needs you`
}

// The other workspaces' share of the account count, for "n more in other
// workspaces" on a workspace's own pages. `partial` when one of them did
// not answer or was cut, so the number is a floor.
export function elsewhere(inbox: Pick<InboxResponse, "workspaces">, workspaceId: string): { count: number; partial: boolean } {
  let count = 0
  let partial = false
  for (const w of inbox.workspaces) {
    if (w.workspace.id === workspaceId) continue
    if (w.state === "ok" && w.count !== null) count += w.count
    if (w.state === "gated" || w.state === "unavailable" || w.truncated) partial = true
  }
  return { count, partial }
}

export function elsewhereWords(count: number, partial: boolean): string | null {
  if (count <= 0) return null
  const n = partial ? `${count}+` : String(count)
  return count === 1 && !partial ? "1 more in another workspace" : `${n} more in other workspaces`
}

// ---------------------------------------------------------------- rows

// A row's DOM key (inbox-row.ts data-key): the ask or the enrolment id,
// which a renewal keeps.
export function inboxItemKey(item: InboxItem): string {
  switch (item.kind) {
    case "ask":
      return item.ask.view === "stop" ? item.ask.stop.id : item.ask.detail.id
    case "enrol":
      return item.enrol.enrolment
    case "confirm":
      return `confirm:${item.confirm.member}`
    case "rescope":
      return item.rescope.proposal
    case "group":
      return item.group.group
  }
}

// A review group's second line: the asks that need a closer look, those
// decided on their own page and those the viewer may only deny, each left
// out at 0, "All routine." when all are.
export function reviewGroupWords(floor: number, ownPage: number, denyOnly = 0): string {
  const parts = [
    ...(floor > 0 ? [`${floor} ${floor === 1 ? "needs" : "need"} a closer look.`] : []),
    ...(ownPage > 0 ? [`${ownPage} ${ownPage === 1 ? "decides on its" : "decide on their"} own page.`] : []),
    ...(denyOnly > 0 ? [`${denyOnly} can only be denied.`] : []),
  ]
  return parts.length === 0 ? "All routine." : parts.join(" ")
}

// What becomes of a row on screen once a newer answer arrives, before the
// list is redrawn: kept while the answer still lists it; kept greyed only
// while its workspace could not be read; dropped at once otherwise (the
// workspace is gated, inactive or gone, or the request was withdrawn).
export function rowFate(inbox: Pick<InboxResponse, "workspaces" | "items">, workspaceId: string, key: string): "keep" | "stale" | "drop" {
  const w = inbox.workspaces.find((x) => x.workspace.id === workspaceId)
  if (w === undefined || w.state === "gated" || w.state === "inactive") return "drop"
  if (w.state === "unavailable") return "stale"
  return inbox.items.some((item) => item.workspace.id === workspaceId && inboxItemKey(item) === key) ? "keep" : "drop"
}

// ---------------------------------------------------------------- the home card

// The rows the home's Needs you card shows before "See all".
export const HOME_NEEDS_ROWS = 5

// What a row shows that can change under the same key (a renewal, an
// enrolment accepted and now waiting to be admitted): its key, expiry,
// action and state word, "-" for none. Ids, times and state words only,
// never text anyone wrote.
export function inboxItemSign(item: InboxItem): string {
  const state = item.kind === "enrol" ? item.enrol.state : item.kind === "rescope" ? item.rescope.as : item.kind === "ask" ? item.ask.view : "-"
  return [inboxItemKey(item), item.expiresAt ?? "-", item.action, state].join(" ")
}

// What a workspace home's Needs you card shows (workspaces.ts, needsCard):
// its workspace's state as that page read it, null when the read failed
// outright; how many requests the read listed, rows past the first few
// included; whether that list was partial; and its rows' signatures, in
// order.
export type HomeNeedsShown = { state: InboxWorkspaceState | null; count: number; truncated: boolean; signs: readonly string[] }

function isWorkspaceState(value: string | undefined): value is InboxWorkspaceState {
  return value === "ok" || value === "gated" || value === "inactive" || value === "unavailable"
}

// From the card's data-state, data-count and data-truncated and its rows'
// data-sign.
export function homeNeedsShown(card: { state?: string; count?: string; truncated?: string }, signs: readonly string[]): HomeNeedsShown {
  const n = Number(card.count ?? "0")
  return { state: isWorkspaceState(card.state) ? card.state : null, count: Number.isInteger(n) && n >= 0 ? n : 0, truncated: card.truncated === "true", signs }
}

// Whether an answer knows more about this workspace than the card shows:
// another state, count or partial flag, or other first rows than the
// card's, in order. An answer that could not read the workspace either,
// or no longer lists it, knows nothing newer to draw.
function homeNeedsBehind(inbox: Pick<InboxResponse, "workspaces" | "items">, workspaceId: string, shown: HomeNeedsShown): boolean {
  const w = inbox.workspaces.find((x) => x.workspace.id === workspaceId)
  if (w === undefined || w.state === "unavailable") return false
  if (w.state !== shown.state) return true
  if (w.state !== "ok") return false
  const items = inbox.items.filter((item) => item.workspace.id === workspaceId)
  if (items.length !== shown.count || w.truncated !== shown.truncated) return true
  const signs = items.slice(0, HOME_NEEDS_ROWS).map(inboxItemSign)
  return signs.length !== shown.signs.length || signs.some((sign, i) => sign !== shown.signs[i])
}

// Where the card's poll is: whether the tab is visible; the time now and
// of the last re-read, null before the first; and whether the one re-read
// this page view allows for an answer that can never speak for the
// workspace was spent.
export type HomeNeedsTurn = { visible: boolean; now: number; rereadAt: number | null; spent: boolean }

export type HomeNeedsStep = { prune: boolean; reread: boolean; once: boolean; commit: boolean }

// What a changed answer does to the card. `prune`: its withdrawn rows leave
// at once (rowFate), unless the answer could not read the workspace, as
// the home's own read may have, or no longer lists it. `reread`: the page
// is read again only when the card is behind the answer, never while the
// tab is hidden, and at most once per BADGE_POLL_MS whatever asked (focus,
// a return to the tab); a skipped re-read commits nothing, so a later poll
// asks again. An answer that can never speak for the workspace leaves the
// card as it is: one that no longer lists it, or that says "limit" for a
// card that could not read it either (past the account inbox's limit, it
// always will). The card is then read again once per page view (`once`)
// and whatever comes back is committed. `commit`: the answer's validator
// is adopted at once only when the card already shows it; otherwise only
// once a re-read drew it (homeNeedsRedraw), so the badge's commit never
// swallows a change the card has not shown.
export function homeNeedsStep(inbox: Pick<InboxResponse, "workspaces" | "items">, workspaceId: string, shown: HomeNeedsShown, turn: HomeNeedsTurn): HomeNeedsStep {
  const w = inbox.workspaces.find((x) => x.workspace.id === workspaceId)
  const prune = w !== undefined && w.state !== "unavailable"
  const silent = w === undefined || (w.state === "unavailable" && w.reason === "limit" && shown.state === "unavailable")
  const wanted = silent ? !turn.spent : homeNeedsBehind(inbox, workspaceId, shown)
  if (!wanted) return { prune, reread: false, once: false, commit: true }
  const reread = turn.visible && (turn.rereadAt === null || turn.now - turn.rereadAt >= BADGE_POLL_MS)
  return { prune, reread, once: reread && silent, commit: false }
}

export type HomeNeedsRedraw = { swap: boolean; keepRows: boolean; commit: boolean }

// What the re-read card does; `fresh` is null when the page could not be
// read. A failed read, or a page whose own inbox read failed outright,
// leaves the card as it is and commits nothing, so the next poll brings
// the change again. A card that could not read the workspace replaces this
// one with the last good rows kept, greyed, and commits only when the
// answer could not read it either. `stopping`: a Stop on the card is in
// flight; a fresh card would offer it again, enabled, so the card stays
// and nothing is committed until a later poll.
export function homeNeedsRedraw(inbox: Pick<InboxResponse, "workspaces" | "items">, workspaceId: string, fresh: HomeNeedsShown | null, stopping: boolean): HomeNeedsRedraw {
  if (stopping || fresh === null || fresh.state === null) return { swap: false, keepRows: false, commit: false }
  if (fresh.state === "unavailable") return { swap: true, keepRows: true, commit: !homeNeedsBehind(inbox, workspaceId, fresh) }
  return { swap: true, keepRows: false, commit: true }
}

// ---------------------------------------------------------------- groups

export type InboxGroup = { workspace: InboxWorkspace; items: InboxItem[] }

// The vault sends items grouped and ordered (soonest expiry first, then the
// workspace's name); the groups follow the items' order. A workspace that
// is gated, could not be read, was over the limit or was cut with no row
// left keeps a group of its own after them, with no rows; an inactive one,
// or one proven to have nothing waiting, has none.
export function inboxGroups(inbox: Pick<InboxResponse, "workspaces" | "items">): InboxGroup[] {
  const byId = new Map(inbox.workspaces.map((w) => [w.workspace.id, w]))
  const groups: InboxGroup[] = []
  const seen = new Map<string, InboxGroup>()
  for (const item of inbox.items) {
    let group = seen.get(item.workspace.id)
    if (group === undefined) {
      const workspace = byId.get(item.workspace.id) ?? { workspace: item.workspace, role: null, state: "ok", reason: null, count: null, truncated: false }
      group = { workspace, items: [] }
      seen.set(item.workspace.id, group)
      groups.push(group)
    }
    group.items.push(item)
  }
  for (const w of inbox.workspaces) {
    if (seen.has(w.workspace.id)) continue
    if (w.state === "gated" || w.state === "unavailable" || (w.state === "ok" && w.truncated)) groups.push({ workspace: w, items: [] })
  }
  return groups
}

// "Personal", "Personal and Northwind", "A, B and C".
export function joinNames(names: readonly string[]): string {
  if (names.length <= 1) return names[0] ?? ""
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`
}

export type EmptyWords = { tone: "empty" | "partial" | "failed"; title: string; sentence: string }

export const NOTHING_NEEDS_YOU = "Nothing needs you"
export const NOTHING_SENTENCE = "When an agent asks for something you may decide, in any of your workspaces, it appears here with a countdown. A new machine is listed for owners and admins, and for you when its agent used your connect code; otherwise open the link the agent gives you."
export const LOAD_FAILED_TITLE = "Could not load what is waiting for you"
export const LOAD_FAILED_SENTENCE = "Reload the page to try again; until then, open the links your agents send you directly."

// What an inbox with no rows says, or null when it has rows. The plain
// "Nothing needs you" only when every workspace answered in full; never
// while one is gated, could not be read or was cut.
export function emptyWords(inbox: Pick<InboxResponse, "workspaces" | "items">): EmptyWords | null {
  if (inbox.items.length > 0) return null
  const ws = inbox.workspaces
  if (ws.length === 0) return { tone: "empty", title: "You are not in a workspace yet", sentence: "What waits for you in your workspaces appears here. Your workspaces says how to join or create one." }
  // Only a workspace that answered in full is proven to have nothing.
  const empty = ws.filter((w) => w.state === "ok" && !w.truncated).map((w) => w.workspace.name)
  const unread = ws.filter((w) => w.state === "unavailable").map((w) => w.workspace.name)
  const gated = ws.filter((w) => w.state === "gated").map((w) => w.workspace.name)
  const cut = ws.filter((w) => w.state === "ok" && w.truncated).map((w) => w.workspace.name)
  const others = [
    unread.length > 0 ? `${joinNames(unread)} could not be read just now; retrying.` : "",
    gated.length > 0 ? `${joinNames(gated)} ${gated.length === 1 ? "needs" : "need"} you to verify your identity first.` : "",
    cut.length > 0 ? `Some requests in ${joinNames(cut)} could not be checked.` : "",
  ].filter((s) => s !== "")
  const lead = empty.length > 0 ? `Nothing is waiting in ${joinNames(empty)}. ` : ""
  if (empty.length === 0 && cut.length === 0) {
    if (unread.length > 0) return { tone: "failed", title: LOAD_FAILED_TITLE, sentence: `${others.join(" ")} ${LOAD_FAILED_SENTENCE}` }
    if (gated.length > 0) return { tone: "partial", title: "Verify your identity to see what needs you", sentence: others.join(" ") }
    return { tone: "empty", title: "Nothing needs you yet", sentence: "None of your workspaces is open to you yet; Your workspaces says why." }
  }
  if (others.length === 0) return { tone: "empty", title: NOTHING_NEEDS_YOU, sentence: NOTHING_SENTENCE }
  const title = gated.length > 0 ? "Verify your identity to finish checking" : empty.length > 0 ? "Nothing needs you in the workspaces that answered" : "Some requests could not be checked"
  return { tone: "partial", title, sentence: `${lead}${others.join(" ")}` }
}

// ---------------------------------------------------------------- the poll

// "Updated just now", "Updated 12 s ago", "Updated 3 min ago".
export function updatedWords(at: number, now: number): string {
  const s = Math.max(0, Math.round((now - at) / 1000))
  if (s < 5) return "Updated just now"
  if (s < 60) return `Updated ${s} s ago`
  return `Updated ${Math.floor(s / 60)} min ago`
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null
}

// The response's outline, checked before anything is drawn from it.
export function isInboxResponse(value: unknown): value is InboxResponse {
  if (!isRecord(value)) return false
  return Array.isArray(value.workspaces) && Array.isArray(value.items) && Array.isArray(value.notices) && typeof value.count === "number" && typeof value.complete === "boolean"
}

export type PollAnswer = { status: number; etag: string | null; body: unknown }

export type PollOutcome =
  | { kind: "changed"; inbox: InboxResponse; etag: string | null }
  | { kind: "unchanged" }
  | { kind: "ended" }
  | { kind: "failed" }

// One inbox poll's state: the validator to send, the sequence numbers that
// keep an old answer from overwriting a newer one, and whether the session
// ended. Nothing here touches the network or a timer.
export class InboxPoll {
  private next = 0
  private applied = 0
  private validator: string | null = null
  private over = false
  lastInbox: InboxResponse | null = null
  lastOkAt: number | null = null

  get ended(): boolean {
    return this.over
  }

  // The validator of the list the server already drew, so the first poll
  // asks only whether it changed.
  prime(validator: string | null): void {
    if (!this.over) this.validator = validator
  }

  // What is now on screen: the validator of exactly that snapshot. Until
  // a changed answer is shown, the next poll keeps asking with the old one
  // and so gets the change again, never a 304 for rows it did not draw.
  commit(validator: string | null): void {
    if (!this.over) this.validator = validator
  }

  get shown(): string | null {
    return this.validator
  }

  // A call's sequence number and its If-None-Match, when there is a
  // validator to send.
  begin(): { seq: number; headers: Record<string, string> } {
    this.next += 1
    return { seq: this.next, headers: this.validator !== null ? { "if-none-match": this.validator } : {} }
  }

  // The answer to call `seq`: null when a newer answer was already applied
  // (dropped), or what the page should do with it.
  settle(seq: number, answer: PollAnswer | null, now: number): PollOutcome | null {
    if (this.over || seq <= this.applied) return null
    this.applied = seq
    if (answer === null) return { kind: "failed" }
    if (answer.status === 401) {
      this.end()
      return { kind: "ended" }
    }
    if (answer.status === 304 && this.validator !== null) {
      this.lastOkAt = now
      return { kind: "unchanged" }
    }
    if (answer.status === 200 && isInboxResponse(answer.body)) {
      // The validator is not adopted here: it names this answer, and only
      // what is on screen may be revalidated (commit).
      this.lastInbox = answer.body
      this.lastOkAt = now
      return { kind: "changed", inbox: answer.body, etag: answer.etag }
    }
    return { kind: "failed" }
  }

  // Another tab signed out or in as someone else, or the vault said 401:
  // nothing more is asked and nothing old is kept.
  end(): void {
    this.over = true
    this.validator = null
    this.lastInbox = null
  }
}

// When to ask again: never once ended or while hidden (visibility brings
// it back at once); otherwise after the interval.
export function nextPollIn(poll: Pick<InboxPoll, "ended">, visible: boolean, intervalMs: number): number | null {
  if (poll.ended || !visible) return null
  return intervalMs
}
