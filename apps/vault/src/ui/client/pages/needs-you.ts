// The account inbox in the browser. On /needs-you: GET /api/needs-you every
// 20 s while the tab is visible, at once when it comes back or takes focus,
// with the validator of the list on screen, so an unchanged inbox is a 304.
// A changed one redraws the list in place from the page as the server
// renders it now: the same rows, links and escaping as the first paint,
// parsed from this vault's own page (scripts never run in a parsed
// document) and only its list region taken. A workspace that could not be
// read this time keeps its last good rows, greyed. A 401, a sign-out in
// another tab or another account signing in clears every row and stops.
//
// Everywhere else (the workspace shells and the account pages) the same
// read every 60 s fills the hidden Needs you count, and on a workspace's
// own pages the "n more in other workspaces" line. A count is shown only
// once the vault gave one, never zero; once the tab is stale it stops.
// On a workspace's home the read comes every 20 s, as on /needs-you, and
// an answer that knows more than its Needs you card shows redraws the
// card the same way, from the home page as the server renders it now.
//
// The rules (counts, groups, validator, sequence numbers) are in
// needs-you-logic.ts.

import { api } from "../api.ts"
import type { InboxResponse } from "@mehen/protocol/inbox"
import { type Boot, all, find, must, showError } from "../dom.ts"
import { SHELL_CHANNEL, type ShellIdentity, type ShellState, parseShellMessage, readShellIdentity } from "../shell-logic.ts"
import { wireRings, wireTimes } from "../wires.ts"
import { CHECKING_AFTER_MS, badgePollMs, type HomeNeedsShown, InboxPoll, rowFate, NEEDS_YOU_API, NEEDS_YOU_POLL_MS, type PollAnswer, type PollOutcome, countWords, elsewhere, elsewhereWords, homeNeedsRedraw, homeNeedsShown, homeNeedsStep, needsYouTitle, nextPollIn, updatedWords } from "./needs-you-logic.ts"

async function fetchInbox(headers: Record<string, string>): Promise<PollAnswer | null> {
  try {
    const response = await fetch(NEEDS_YOU_API, { credentials: "same-origin", cache: "no-store", headers: { accept: "application/json", ...headers } })
    let body: unknown = null
    if (response.status === 200) {
      try {
        body = await response.json()
      } catch {
        body = null
      }
    }
    return { status: response.status, etag: response.headers.get("etag"), body }
  } catch {
    return null
  }
}

// `refresh` asks now; `later` waits out one interval first.
type Poller = { refresh(): void; later(): void; stop(): void }

// One poll loop: never while hidden, never two calls at once, a "checking"
// signal for a call still out after two seconds. `blocked` stops it for a
// tab that went stale.
function startPoller(poll: InboxPoll, intervalMs: number, onOutcome: (outcome: PollOutcome) => Promise<void> | void, onChecking: (on: boolean) => void = () => undefined, blocked: () => boolean = () => false): Poller {
  let timer: ReturnType<typeof setTimeout> | undefined
  let busy = false
  let stopped = false
  const visible = () => document.visibilityState === "visible"
  const schedule = () => {
    clearTimeout(timer)
    const wait = stopped ? null : nextPollIn(poll, visible(), intervalMs)
    if (wait !== null) timer = setTimeout(() => void run(), wait)
  }
  const run = async (): Promise<void> => {
    clearTimeout(timer)
    if (stopped || busy || poll.ended || !visible()) return
    if (blocked()) {
      stopped = true
      return
    }
    busy = true
    const { seq, headers } = poll.begin()
    const checking = setTimeout(() => onChecking(true), CHECKING_AFTER_MS)
    const answer = await fetchInbox(headers)
    const outcome = poll.settle(seq, answer, Date.now())
    // In flight, and checking, until the outcome is on screen.
    if (outcome !== null) await onOutcome(outcome)
    clearTimeout(checking)
    onChecking(false)
    busy = false
    schedule()
  }
  document.addEventListener("visibilitychange", () => (visible() ? void run() : clearTimeout(timer)))
  window.addEventListener("focus", () => void run())
  return {
    refresh: () => void run(),
    later: schedule,
    stop: () => {
      stopped = true
      clearTimeout(timer)
    },
  }
}

// The hidden Needs you counts in the shell: shown only with a count above
// zero, as "3" or, when a workspace did not answer, "3+".
function fillCounts(count: number | null, complete: boolean): void {
  const words = countWords(count, complete)
  for (const node of all('[data-region="pending-count"][data-fill]')) {
    node.textContent = words ?? ""
    node.hidden = words === null
    if (words !== null) node.setAttribute("aria-label", `${words} waiting`)
    else node.removeAttribute("aria-label")
  }
}

// "2 more in other workspaces" on a workspace's own pages.
function fillElsewhere(outcome: PollOutcome, workspaceId: string | null): void {
  const line = find('[data-region="needs-elsewhere"]')
  const link = line ? find('[data-fill="needs-elsewhere"]', line) : null
  if (!line || !link || workspaceId === null) return
  if (outcome.kind !== "changed") {
    if (outcome.kind === "ended") line.hidden = true
    return
  }
  const other = elsewhere(outcome.inbox, workspaceId)
  const words = elsewhereWords(other.count, other.partial)
  link.textContent = words ?? ""
  line.hidden = words === null
}

// Another tab signed out or signed in as someone else.
function onAccountChange(account: string, changed: () => void): void {
  if (typeof BroadcastChannel !== "function") return
  const channel = new BroadcastChannel(SHELL_CHANNEL)
  channel.addEventListener("message", (event) => {
    const message = parseShellMessage(event.data)
    if (message === null || message.origin !== location.origin) return
    if (message.kind === "signed-out" || message.account !== account) changed()
  })
}

function bootAccount(boot: Boot, shell: ShellState | null): string | null {
  if (shell !== null) return shell.identity.account
  const signedIn = boot.signedIn as { account?: unknown } | undefined
  return typeof signedIn?.account === "string" ? signedIn.account : null
}

// Every page but /needs-you itself: the badge, the elsewhere line, and on
// a workspace's home its Needs you card.
export function initNeedsBadge(boot: Boot, shell: ShellState | null): void {
  if (all('[data-region="pending-count"][data-fill]').length === 0 && find('[data-region="needs-elsewhere"]') === null && find(HOME_NEEDS) === null) return
  const account = bootAccount(boot, shell)
  if (account === null) return
  const poll = new InboxPoll()
  const workspaceId = shell?.identity.workspace.id ?? null
  const interval = badgePollMs(shell !== null && find(HOME_NEEDS) !== null)
  const homeNeeds = shell !== null && find(HOME_NEEDS) !== null ? homeNeedsRedrawer(shell, () => poll.ended, interval) : null
  const poller = startPoller(
    poll,
    interval,
    async (outcome) => {
      if (outcome.kind === "changed") {
        fillCounts(outcome.inbox.count, outcome.inbox.complete)
        // Committed only once the card shows the answer too, so the next
        // poll brings a change the card has not drawn yet again.
        if (homeNeeds === null || (await homeNeeds(outcome.inbox))) poll.commit(outcome.etag)
        // Signed out or switched account during the re-read: that cleared
        // the line, and this answer is the old account's.
        if (poll.ended) return
      }
      if (outcome.kind === "ended") fillCounts(null, false)
      fillElsewhere(outcome, workspaceId)
    },
    undefined,
    () => (shell?.stale ?? null) !== null,
  )
  onAccountChange(account, () => {
    poll.end()
    poller.stop()
    fillCounts(null, false)
    fillElsewhere({ kind: "ended" }, workspaceId)
  })
  poller.refresh()
}

export const REDRAW_TIMEOUT_MS = 10_000

type FreshPage = { doc: Document; boot: Record<string, unknown> }

// This page as the server renders it now, from its own address, with its
// boot payload; null when it could not be read in time. Scripts never run
// in a parsed document.
async function freshPage(): Promise<FreshPage | null> {
  const abort = new AbortController()
  const timer = setTimeout(() => abort.abort(), REDRAW_TIMEOUT_MS)
  try {
    const response = await fetch(location.pathname, { credentials: "same-origin", cache: "no-store", headers: { accept: "text/html" }, signal: abort.signal })
    if (!response.ok || !(response.headers.get("content-type") ?? "").startsWith("text/html")) return null
    const doc = new DOMParser().parseFromString(await response.text(), "text/html")
    const boot = JSON.parse(doc.getElementById("app")?.dataset.boot ?? "") as unknown
    return typeof boot === "object" && boot !== null ? { doc, boot: boot as Record<string, unknown> } : null
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}

export type FreshList = { list: HTMLElement; etag: string | null; count: number; complete: boolean }

// The list the server renders now, with the validator of exactly that list
// (its boot etag) and its count; null when it could not be read in time or
// is not the same account's.
async function freshList(account: string): Promise<FreshList | null> {
  const fresh = await freshPage()
  if (fresh === null) return null
  const { doc, boot } = fresh
  if (boot.page !== "needs-you" || boot.account !== account || typeof boot.etag !== "string") return null
  const list = doc.querySelector<HTMLElement>('[data-region="needs-list"]')
  if (list === null || list.dataset.count === undefined) return null
  return { list: document.importNode(list, true) as HTMLElement, etag: boot.etag, count: Number(list.dataset.count), complete: list.dataset.complete === "true" }
}

const HOME_NEEDS = '[data-region="home-needs"]'

// The home's Needs you card the server renders now; null when it could not
// be read in time or is not the same workspace's home for the same account
// on this origin.
async function freshHomeCard(identity: ShellIdentity): Promise<HTMLElement | null> {
  const fresh = await freshPage()
  if (fresh === null || fresh.boot.page !== "workspace-home") return null
  const shell = readShellIdentity(fresh.boot.shell, location.origin)
  if (shell === null || shell.account !== identity.account || shell.workspace.id !== identity.workspace.id) return null
  const card = fresh.doc.querySelector<HTMLElement>(HOME_NEEDS)
  return card === null ? null : (document.importNode(card, true) as HTMLElement)
}

function shownOn(card: HTMLElement): HomeNeedsShown {
  return homeNeedsShown(card.dataset, all<HTMLElement>("li.inbox-row", card).map((row) => row.dataset.sign ?? ""))
}

// The home's Needs you card against a changed answer: its withdrawn rows
// leave at once, and when the answer knows more than it shows it is
// redrawn from the page as the server renders it now, with focus kept as
// on /needs-you. Resolves whether the answer's validator may be committed.
function homeNeedsRedrawer(shell: ShellState, ended: () => boolean, gapMs: number): (inbox: InboxResponse) => Promise<boolean> {
  const id = shell.identity.workspace.id
  let spent = false
  let rereadAt: number | null = null
  return async (inbox) => {
    const card = find(HOME_NEEDS)
    if (card === null) return true
    const now = Date.now()
    const step = homeNeedsStep(inbox, id, shownOn(card), { visible: document.visibilityState === "visible", now, rereadAt, spent, gapMs })
    if (step.prune) pruneRows(card, inbox)
    if (!step.reread) return step.commit
    rereadAt = now
    if (step.once) spent = true
    const fresh = await freshHomeCard(shell.identity)
    const old = find(HOME_NEEDS)
    if (ended() || shell.stale !== null || old === null) return false
    const stopping = find('button[data-action="cancel-ask"][aria-busy="true"]', old) !== null
    const redraw = homeNeedsRedraw(inbox, id, fresh === null ? null : shownOn(fresh), stopping)
    if (!redraw.swap || fresh === null) return redraw.commit
    const mark = focusMark(old)
    if (redraw.keepRows) keepGroupRows(fresh, old)
    old.replaceWith(fresh)
    wireRings(Date.now, fresh)
    wireTimes(fresh)
    restoreFocus(mark, fresh)
    return redraw.commit
  }
}

const FOCUSABLE = "a[href], button:not([disabled])"

// Where keyboard focus is inside the list, by the row's workspace and key
// and the control's place in the row; null when focus is elsewhere.
type FocusMark = { workspace: string; key: string; index: number; group: string }

function focusMark(list: HTMLElement): FocusMark | null {
  const active = document.activeElement
  if (!(active instanceof HTMLElement) || !list.contains(active)) return null
  const row = active.closest<HTMLElement>("li.inbox-row")
  const group = active.closest<HTMLElement>('[data-region="needs-group"]')
  if (row === null) return { workspace: "", key: "", index: -1, group: group?.dataset.workspace ?? "" }
  return { workspace: row.dataset.workspace ?? "", key: row.dataset.key ?? "", index: all(FOCUSABLE, row).indexOf(active), group: row.dataset.workspace ?? "" }
}

// Focus back on the same control of the same request when it is still
// listed; else the first request of its workspace, else the first in the
// list, else the page's heading. Never scrolls; nothing moves when focus
// was outside the list.
function restoreFocus(mark: FocusMark | null, list: HTMLElement): void {
  if (mark === null) return
  const rows = all<HTMLElement>("li.inbox-row", list)
  const same = rows.find((r) => r.dataset.workspace === mark.workspace && r.dataset.key === mark.key)
  const target =
    (same !== undefined ? all<HTMLElement>(FOCUSABLE, same)[Math.max(0, mark.index)] : undefined) ??
    rows.filter((r) => r.dataset.workspace === mark.group).flatMap((r) => all<HTMLElement>(FOCUSABLE, r))[0] ??
    all<HTMLElement>(FOCUSABLE, list)[0] ??
    find<HTMLElement>("main h1")
  if (target === null || target === undefined) return
  if (target.tagName === "H1") target.tabIndex = -1
  target.focus({ preventScroll: true })
}

// Before the redraw: the answer's own workspaces and rows decide what may
// stay on screen at once, so a gated, inactive or withdrawn row never
// outlives the answer that withdrew it, whatever the redraw does.
function pruneRows(list: HTMLElement, inbox: Parameters<typeof rowFate>[0]): void {
  const mark = focusMark(list)
  for (const row of all<HTMLElement>("li.inbox-row", list)) {
    const fate = rowFate(inbox, row.dataset.workspace ?? "", row.dataset.key ?? "")
    if (fate === "drop") row.remove()
    else row.classList.toggle("stale", fate === "stale")
  }
  for (const group of all<HTMLElement>('[data-region="needs-group"]', list)) {
    const w = inbox.workspaces.find((x) => x.workspace.id === group.dataset.workspace)
    if (w === undefined || w.state === "gated" || w.state === "inactive") group.remove()
  }
  if (mark !== null && !list.contains(document.activeElement)) restoreFocus(mark, list)
}

// A workspace that could not be read keeps its last good rows, greyed.
function keepStaleRows(fresh: HTMLElement, old: HTMLElement): void {
  for (const group of all('[data-region="needs-group"][data-state="unavailable"]', fresh)) {
    const id = group.dataset.workspace ?? ""
    keepGroupRows(group, all<HTMLElement>('[data-region="needs-group"]', old).find((g) => g.dataset.workspace === id))
  }
}

// One workspace's group (or the home's card) that could not be read: the
// rows it had before, greyed, when it has none of its own.
function keepGroupRows(group: HTMLElement, before: HTMLElement | undefined): void {
  const rows = before ? all<HTMLElement>("li.inbox-row", before) : []
  const into = find('[data-region="needs-rows"]', group)
  if (!into || rows.length === 0 || into.children.length > 0) return
  for (const row of rows) {
    row.classList.add("stale")
    into.append(row)
  }
}

function wireCancel(root: ParentNode, refresh: () => void): void {
  root.addEventListener("click", (event) => {
    const button = (event.target as Element | null)?.closest<HTMLButtonElement>('button[data-action="cancel-ask"]')
    const row = button?.closest<HTMLElement>("li.inbox-row")
    if (!button || !row) return
    const kind = button.dataset.kind === "connect" ? "connect" : "intakes"
    const slug = row.dataset.slug ?? ""
    const id = button.dataset.id ?? ""
    button.disabled = true
    button.textContent = "Stopping..."
    void api(`/api/w/${encodeURIComponent(slug)}/${kind}/${encodeURIComponent(id)}/cancel`, {}, { "Mehen-Workspace": row.dataset.workspace ?? "" })
      .then(() => refresh())
      .catch((error: unknown) => {
        button.disabled = false
        button.textContent = "Stop"
        showError(error)
      })
  })
}

export function initNeedsYou(boot: Boot): void {
  const account = typeof boot.account === "string" ? boot.account : null
  if (account === null) return
  const poll = new InboxPoll()
  poll.prime(typeof boot.etag === "string" ? boot.etag : null)
  const updated = must('[data-region="needs-updated"]')
  const checking = must('[data-region="needs-checking"]')
  const retrying = must('[data-region="needs-retrying"]')
  const ended = must('[data-region="needs-ended"]')
  let shownAt = Date.now()
  let generation = 0
  const list = () => must('[data-region="needs-list"]')
  const initial = list()
  fillCounts(Number(initial.dataset.count ?? "0"), initial.dataset.complete === "true")

  const end = () => {
    poll.end()
    generation += 1
    list().replaceChildren()
    ended.hidden = false
    retrying.hidden = true
    document.title = `${needsYouTitle(null, true)} · Mehen`
    fillCounts(null, false)
  }

  const announce = must('[data-region="needs-announce"]')
  let announced = Number(initial.dataset.count ?? "0")
  const show = (count: number, complete: boolean) => {
    document.title = `${needsYouTitle(count, complete)} · Mehen`
    fillCounts(count, complete)
    if (count !== announced) {
      announced = count
      announce.textContent = `${countWords(count, complete) ?? "Nothing"} waiting`
    }
  }

  const apply = async (outcome: PollOutcome): Promise<void> => {
    if (outcome.kind === "ended") return end()
    if (outcome.kind === "failed") {
      retrying.hidden = false
      return
    }
    if (outcome.kind === "unchanged") {
      retrying.hidden = true
      shownAt = poll.lastOkAt ?? Date.now()
      updated.textContent = updatedWords(shownAt, Date.now())
      return
    }
    // Withdrawn, gated and inactive rows leave now; the count is the answer's.
    pruneRows(list(), outcome.inbox)
    show(outcome.inbox.count, outcome.inbox.complete)
    // No new page read while the tab is hidden: the validator still names
    // the list on screen, so the next visible poll brings the change again.
    if (document.visibilityState !== "visible") return
    const mine = ++generation
    const fresh = await freshList(account)
    if (mine !== generation || poll.ended) return
    if (fresh === null) {
      retrying.hidden = false
      return
    }
    const old = list()
    const mark = focusMark(old)
    keepStaleRows(fresh.list, old)
    old.replaceWith(fresh.list)
    wireRings(Date.now, fresh.list)
    wireTimes(fresh.list)
    restoreFocus(mark, fresh.list)
    // What is on screen now, and the validator that names it.
    poll.commit(fresh.etag)
    show(fresh.count, fresh.complete)
    retrying.hidden = true
    shownAt = Date.now()
    updated.textContent = updatedWords(shownAt, shownAt)
  }

  const poller = startPoller(poll, NEEDS_YOU_POLL_MS, apply, (on) => {
    checking.hidden = !on
  })
  setInterval(() => {
    if (!poll.ended) updated.textContent = updatedWords(shownAt, Date.now())
  }, 5_000)
  wireCancel(must("main"), () => poller.refresh())
  onAccountChange(account, () => {
    poller.stop()
    end()
  })
  // The list on screen is the one just read: the first poll waits.
  poller.later()
}
