// The account inbox's rules: the badge and title never show a zero or an
// unknown as a number, groups follow the vault's order and keep the
// workspaces that did not answer, no unqualified "Nothing needs you" while
// one is gated, unread or cut, and the poll drops answers older than the
// one it applied, keeps what it shows on a 304 and ends on a 401.

import { describe, expect, it } from "vitest"
import type { InboxItem, InboxResponse, InboxWorkspace } from "@mehen/protocol/inbox"
import type { WorkspaceRef } from "@mehen/protocol/workspace"
import { BADGE_POLL_MS, HOME_NEEDS_ROWS, NEEDS_YOU_POLL_MS, badgePollMs, InboxPoll, NOTHING_NEEDS_YOU, countWords, homeNeedsRedraw, homeNeedsShown, homeNeedsStep, type HomeNeedsTurn, inboxItemKey, inboxItemSign, rowFate, elsewhere, elsewhereWords, emptyWords, inboxGroups, isInboxResponse, joinNames, needsYouTitle, nextPollIn, reviewGroupWords, updatedWords } from "./needs-you-logic.ts"

const A: WorkspaceRef = { id: "tn_A", slug: "a", name: "Alpha" }
const B: WorkspaceRef = { id: "tn_B", slug: "b", name: "Beta" }
const NOW = Date.parse("2026-11-03T12:00:00.000Z")
const C: WorkspaceRef = { id: "tn_C", slug: "c", name: "Gamma" }

function ws(workspace: WorkspaceRef, state: InboxWorkspace["state"] = "ok", count: number | null = 0, truncated = false): InboxWorkspace {
  return { workspace, role: "owner", state, reason: state === "unavailable" ? "timeout" : null, count: state === "ok" ? count : null, truncated }
}

function confirm(workspace: WorkspaceRef, member: string): InboxItem {
  return { kind: "confirm", workspace, href: `/w/${workspace.slug}/people#confirm-${member}`, action: "confirm", createdAt: null, expiresAt: null, confirm: { member, name: member, role: "member", invite: "inv_1", termsDigest: "d", boundEmail: null, joinedAt: "2026-10-27T18:00:00.000Z" } }
}

// An enrolment waiting for its owner; the name is what a person typed.
function enrol(workspace: WorkspaceRef, enrolment: string, expiresAt: string): Extract<InboxItem, { kind: "enrol" }> {
  return {
    kind: "enrol",
    workspace,
    href: `/w/${workspace.slug}/e/${enrolment}`,
    action: "accept",
    createdAt: null,
    expiresAt,
    enrol: { enrolment, name: "tom-laptop", host: null, backend: "software", start: { at: "2026-11-03T09:00:00.000Z", place: null, clientLabel: "mehen" }, session: null, requestedOwner: { kind: "self" }, owner: null, claimed: null, state: "pending_owner_acceptance", fingerprint: { groups: ["a", "b", null, "d"], words: [] }, actions: ["accept", "reject"], hardExpiresAt: expiresAt },
  }
}

function inbox(workspaces: InboxWorkspace[], items: InboxItem[] = []): InboxResponse {
  return { workspaces, items, notices: [], count: workspaces.reduce((n, w) => n + (w.state === "ok" ? (w.count ?? 0) : 0), 0), complete: workspaces.every((w) => w.state !== "gated" && w.state !== "unavailable" && !w.truncated) }
}

describe("counts", () => {
  it("never shows zero or an unknown count, and marks a floor", () => {
    expect(countWords(null, true)).toBeNull()
    expect(countWords(0, true)).toBeNull()
    expect(countWords(0, false)).toBeNull()
    expect(countWords(3, true)).toBe("3")
    expect(countWords(3, false)).toBe("3+")
    expect(needsYouTitle(2, true)).toBe("(2) Needs you")
    expect(needsYouTitle(2, false)).toBe("(2+) Needs you")
    expect(needsYouTitle(0, true)).toBe("Needs you")
  })

  it("counts the other workspaces only, as a floor when one of them did not answer", () => {
    const read = inbox([ws(A, "ok", 2), ws(B, "ok", 3), ws(C, "unavailable")])
    expect(elsewhere(read, A.id)).toEqual({ count: 3, partial: true })
    expect(elsewhere(inbox([ws(A, "ok", 2), ws(B, "ok", 3)]), A.id)).toEqual({ count: 3, partial: false })
    expect(elsewhere(inbox([ws(A, "ok", 2), ws(B, "ok", 1, true)]), A.id)).toEqual({ count: 1, partial: true })
    expect(elsewhereWords(0, true)).toBeNull()
    expect(elsewhereWords(1, false)).toBe("1 more in another workspace")
    expect(elsewhereWords(1, true)).toBe("1+ more in other workspaces")
    expect(elsewhereWords(4, false)).toBe("4 more in other workspaces")
  })
})

describe("groups", () => {
  it("follow the items' order, then keep a gated or unread workspace, and drop inactive and empty ones", () => {
    const read = inbox([ws(A, "ok", 1), ws(B, "ok", 2), ws(C, "gated"), { ...ws({ id: "tn_D", slug: "d", name: "Delta" }), state: "inactive", count: null }, ws({ id: "tn_E", slug: "e", name: "Epsilon" }, "ok", 0)], [confirm(B, "m1"), confirm(B, "m2"), confirm(A, "m3")])
    const groups = inboxGroups(read)
    expect(groups.map((g) => [g.workspace.workspace.slug, g.items.length])).toEqual([["b", 2], ["a", 1], ["c", 0]])
  })

  it("joins names in plain English", () => {
    expect(joinNames(["A"])).toBe("A")
    expect(joinNames(["A", "B"])).toBe("A and B")
    expect(joinNames(["A", "B", "C"])).toBe("A, B and C")
  })
})

describe("empty and partial", () => {
  it("says Nothing needs you only when every workspace answered in full", () => {
    expect(emptyWords(inbox([ws(A), ws(B)]))).toMatchObject({ tone: "empty", title: NOTHING_NEEDS_YOU })
    expect(emptyWords(inbox([ws(A)], [confirm(A, "m")]))).toBeNull()
    for (const partial of [inbox([ws(A), ws(B, "unavailable")]), inbox([ws(A), ws(B, "gated")]), inbox([ws(A, "ok", 25, true)])]) {
      const words = emptyWords(partial)
      expect(words?.title).not.toBe(NOTHING_NEEDS_YOU)
      expect(words?.tone).toBe("partial")
    }
    expect(emptyWords(inbox([ws(A), ws(B, "unavailable")]))?.sentence).toBe("Nothing is waiting in Alpha. Beta could not be read just now; retrying.")
    expect(emptyWords(inbox([ws(A), ws(B, "gated")]))?.sentence).toBe("Nothing is waiting in Alpha. Beta needs you to verify your identity first.")
  })

  it("says it could not load when no workspace answered, and how to join with no workspace", () => {
    expect(emptyWords(inbox([ws(A, "unavailable"), ws(B, "unavailable")]))).toMatchObject({ tone: "failed", title: "Could not load what is waiting for you" })
    expect(emptyWords(inbox([ws(A, "gated")]))).toMatchObject({ tone: "partial", title: "Verify your identity to see what needs you" })
    expect(emptyWords(inbox([]))).toMatchObject({ tone: "empty", title: "You are not in a workspace yet" })
  })
})

describe("the poll", () => {
  const ok = (count: number) => ({ status: 200, etag: `W/"${count}"`, body: inbox([ws(A, "ok", count)]) })

  it("sends the validator it holds and keeps what is shown on a 304", () => {
    const poll = new InboxPoll()
    const first = poll.begin()
    expect(first.headers).toEqual({})
    expect(poll.settle(first.seq, ok(1), 1000)).toMatchObject({ kind: "changed", etag: 'W/"1"' })
    poll.commit('W/"1"')
    const second = poll.begin()
    expect(second.headers).toEqual({ "if-none-match": 'W/"1"' })
    expect(poll.settle(second.seq, { status: 304, etag: 'W/"1"', body: null }, 2000)).toEqual({ kind: "unchanged" })
    expect(poll.lastOkAt).toBe(2000)
  })

  it("asks only whether the list the server drew changed", () => {
    const poll = new InboxPoll()
    poll.prime('W/"drawn"')
    const call = poll.begin()
    expect(call.headers).toEqual({ "if-none-match": 'W/"drawn"' })
    expect(poll.settle(call.seq, { status: 304, etag: 'W/"drawn"', body: null }, 1)).toEqual({ kind: "unchanged" })
  })

  it("drops an answer older than the one it applied", () => {
    const poll = new InboxPoll()
    const older = poll.begin()
    const newer = poll.begin()
    expect(poll.settle(newer.seq, ok(2), 1)).toMatchObject({ kind: "changed" })
    expect(poll.settle(older.seq, ok(1), 2)).toBeNull()
    expect(poll.lastInbox?.count).toBe(2)
  })

  it("ends on a 401, forgets the list and never asks again", () => {
    const poll = new InboxPoll()
    const one = poll.begin()
    poll.settle(one.seq, ok(1), 1)
    const two = poll.begin()
    expect(poll.settle(two.seq, { status: 401, etag: null, body: null }, 2)).toEqual({ kind: "ended" })
    expect(poll.ended).toBe(true)
    expect(poll.lastInbox).toBeNull()
    expect(nextPollIn(poll, true, 20_000)).toBeNull()
    const late = poll.begin()
    expect(poll.settle(late.seq, ok(5), 3)).toBeNull()
  })

  it("treats a malformed answer, a network failure or a stray status as a failed check", () => {
    const poll = new InboxPoll()
    for (const answer of [null, { status: 200, etag: null, body: { items: "x" } }, { status: 500, etag: null, body: null }, { status: 304, etag: null, body: null }]) {
      const call = poll.begin()
      expect(poll.settle(call.seq, answer, 1)).toEqual({ kind: "failed" })
    }
    expect(isInboxResponse(inbox([ws(A)]))).toBe(true)
  })

  it("never polls while hidden", () => {
    const poll = new InboxPoll()
    expect(nextPollIn(poll, false, 20_000)).toBeNull()
    expect(nextPollIn(poll, true, 20_000)).toBe(20_000)
  })

  it("words how long ago it last checked", () => {
    expect(updatedWords(0, 2_000)).toBe("Updated just now")
    expect(updatedWords(0, 12_000)).toBe("Updated 12 s ago")
    expect(updatedWords(0, 185_000)).toBe("Updated 3 min ago")
  })
})

describe("what stays on screen", () => {
  it("never revalidates a changed answer it has not shown: the old validator is asked again until the list is drawn", () => {
    const poll = new InboxPoll()
    poll.prime('W/"shown"')
    const call = poll.begin()
    const gated = { status: 200, etag: 'W/"gated"', body: inbox([ws(A, "gated")]) }
    expect(poll.settle(call.seq, gated, 1)).toMatchObject({ kind: "changed", etag: 'W/"gated"' })
    // The redraw failed: nothing committed, so no 304 can call the old rows fresh.
    expect(poll.begin().headers).toEqual({ "if-none-match": 'W/"shown"' })
    expect(poll.shown).toBe('W/"shown"')
    poll.commit('W/"drawn"')
    expect(poll.begin().headers).toEqual({ "if-none-match": 'W/"drawn"' })
  })

  it("drops a row at once when its workspace is gated, inactive or gone, or the request was withdrawn; greys it only while unread", () => {
    const row = confirm(A, "m1")
    const key = inboxItemKey(row)
    expect(key).toBe("confirm:m1")
    expect(rowFate(inbox([ws(A, "ok", 1)], [row]), A.id, key)).toBe("keep")
    expect(rowFate(inbox([ws(A, "ok", 0)], []), A.id, key)).toBe("drop")
    expect(rowFate(inbox([ws(A, "gated")]), A.id, key)).toBe("drop")
    expect(rowFate(inbox([{ ...ws(A), state: "inactive", count: null }]), A.id, key)).toBe("drop")
    expect(rowFate(inbox([ws(B)]), A.id, key)).toBe("drop")
    expect(rowFate(inbox([ws(A, "unavailable")]), A.id, key)).toBe("stale")
  })
})

describe("the workspace home's Needs you card", () => {
  const one = confirm(A, "m1")
  const two = confirm(A, "m2")
  // What the server draws for a home read: its state, count and partial flag, and its first rows' signatures.
  const card = (state: string | undefined, items: InboxItem[] = [], truncated = false) => homeNeedsShown({ state, count: String(items.length), truncated: String(truncated) }, items.slice(0, HOME_NEEDS_ROWS).map(inboxItemSign))
  const unread = card("unavailable")
  const drawn = card("ok", [one])
  const at = (turn: Partial<HomeNeedsTurn> = {}): HomeNeedsTurn => ({ visible: true, spent: false, now: NOW, rereadAt: null, ...turn })

  it("reads what the card shows from its attributes and rows, and a read that failed outright as no state", () => {
    expect(unread).toEqual({ state: "unavailable", count: 0, truncated: false, signs: [] })
    expect(drawn).toEqual({ state: "ok", count: 1, truncated: false, signs: ["confirm:m1 - confirm -"] })
    expect(card("ok", [], true).truncated).toBe(true)
    expect(homeNeedsShown({}, [])).toEqual({ state: null, count: 0, truncated: false, signs: [] })
    expect(homeNeedsShown({ state: "bogus", count: "x", truncated: "yes" }, [])).toEqual({ state: null, count: 0, truncated: false, signs: [] })
  })

  it("signs a row with its key, expiry, action and state words only, never text anyone wrote", () => {
    const item = enrol(A, "enr_1", "2026-11-03T10:00:00.000Z")
    expect(inboxItemSign(item)).toBe("enr_1 2026-11-03T10:00:00.000Z accept pending_owner_acceptance")
    expect(inboxItemSign(item)).not.toContain("tom-laptop")
  })

  it("re-reads a card that could not read its workspace once the answer could, and never while the tab is hidden", () => {
    const answered = inbox([ws(A, "ok", 1), ws(B, "ok", 0)], [one])
    expect(homeNeedsStep(answered, A.id, unread, at())).toEqual({ prune: true, reread: true, once: false, commit: false })
    // Hidden: no page read, and the validator stays, so the next poll brings the change again.
    expect(homeNeedsStep(answered, A.id, unread, at({ visible: false }))).toEqual({ prune: true, reread: false, once: false, commit: false })
    // The empty state too: an answer with nothing waiting here.
    expect(homeNeedsStep(inbox([ws(A, "ok", 0)]), A.id, unread, at())).toMatchObject({ reread: true, commit: false })
  })

  it("re-reads a card whose own read failed outright once the answer read the workspace", () => {
    const failed = card(undefined)
    expect(homeNeedsStep(inbox([ws(A, "ok", 1)], [one]), A.id, failed, at())).toEqual({ prune: true, reread: true, once: false, commit: false })
    expect(homeNeedsStep(inbox([ws(A, "ok", 0)]), A.id, failed, at())).toEqual({ prune: true, reread: true, once: false, commit: false })
    expect(homeNeedsStep(inbox([ws(A, "ok", 1)], [one]), A.id, failed, at({ visible: false }))).toEqual({ prune: true, reread: false, once: false, commit: false })
  })

  it("commits at once, with no page read, when the card already shows the answer", () => {
    expect(homeNeedsStep(inbox([ws(A, "ok", 1), ws(B, "ok", 4)], [one]), A.id, drawn, at())).toEqual({ prune: true, reread: false, once: false, commit: true })
    const many = [one, two, confirm(A, "m3"), confirm(A, "m4"), confirm(A, "m5"), confirm(A, "m6")]
    expect(homeNeedsStep(inbox([ws(A, "ok", 6)], many), A.id, card("ok", many), at())).toMatchObject({ reread: false, commit: true })
    // An answer that could not read the workspace either knows nothing newer, and greys nothing it could not check.
    expect(homeNeedsStep(inbox([ws(A, "unavailable")]), A.id, drawn, at())).toEqual({ prune: false, reread: false, once: false, commit: true })
    expect(homeNeedsStep(inbox([ws(A, "unavailable")]), A.id, unread, at())).toEqual({ prune: false, reread: false, once: false, commit: true })
  })

  it("re-reads when a request arrived, went, or the workspace was gated", () => {
    expect(homeNeedsStep(inbox([ws(A, "ok", 2)], [one, two]), A.id, drawn, at())).toMatchObject({ reread: true, commit: false })
    expect(homeNeedsStep(inbox([ws(A, "ok", 1)], [two]), A.id, drawn, at())).toMatchObject({ reread: true, commit: false })
    expect(homeNeedsStep(inbox([ws(A, "ok", 0)]), A.id, drawn, at())).toMatchObject({ prune: true, reread: true, once: false, commit: false })
    expect(homeNeedsStep(inbox([ws(A, "gated")]), A.id, drawn, at())).toMatchObject({ prune: true, reread: true, once: false, commit: false })
  })

  it("re-reads, and commits nothing, for a change under the same key and count the card has not drawn", () => {
    const asked = enrol(A, "enr_1", "2026-11-03T10:00:00.000Z")
    const shown = card("ok", [asked])
    // Renewed in place: a new expiry under the same key.
    const renewed = { ...asked, expiresAt: "2026-11-03T11:00:00.000Z" }
    expect(homeNeedsStep(inbox([ws(A, "ok", 1)], [renewed]), A.id, shown, at())).toEqual({ prune: true, reread: true, once: false, commit: false })
    // Accepted by its owner, now waiting to be admitted.
    const admitted = { ...asked, action: "admit" as const, enrol: { ...asked.enrol, state: "pending_admission" as const, actions: ["admit" as const, "reject" as const] } }
    expect(homeNeedsStep(inbox([ws(A, "ok", 1)], [admitted]), A.id, shown, at())).toEqual({ prune: true, reread: true, once: false, commit: false })
    // Past the first rows: one request came and another went among the first five, with the count unchanged.
    const before = [one, two, confirm(A, "m3"), confirm(A, "m4"), confirm(A, "m5"), confirm(A, "m6")]
    const after = [one, two, confirm(A, "m3"), confirm(A, "m4"), confirm(A, "m7"), confirm(A, "m5")]
    expect(homeNeedsStep(inbox([ws(A, "ok", 6)], after), A.id, card("ok", before), at())).toEqual({ prune: true, reread: true, once: false, commit: false })
    // The list became partial, or whole again.
    expect(homeNeedsStep(inbox([ws(A, "ok", 1, true)], [one]), A.id, drawn, at())).toEqual({ prune: true, reread: true, once: false, commit: false })
    expect(homeNeedsStep(inbox([ws(A, "ok", 1)], [one]), A.id, card("ok", [one], true), at())).toEqual({ prune: true, reread: true, once: false, commit: false })
  })

  it("re-reads a card that could not read a workspace past the account's limit once per page view, then commits what comes back", () => {
    const limit = inbox([{ ...ws(A, "unavailable"), reason: "limit" }])
    expect(homeNeedsStep(limit, A.id, unread, at())).toEqual({ prune: false, reread: true, once: true, commit: false })
    expect(homeNeedsStep(limit, A.id, unread, at({ visible: false }))).toEqual({ prune: false, reread: false, once: false, commit: false })
    // Spent: the answer can never say more, so it is committed.
    expect(homeNeedsStep(limit, A.id, unread, at({ spent: true }))).toEqual({ prune: false, reread: false, once: false, commit: true })
    // A card that did read it has nothing to learn from an answer that did not.
    expect(homeNeedsStep(limit, A.id, drawn, at())).toEqual({ prune: false, reread: false, once: false, commit: true })
    // Whatever the re-read draws is committed, still unreadable or not.
    expect(homeNeedsRedraw(limit, A.id, unread, false)).toEqual({ swap: true, keepRows: true, commit: true })
    expect(homeNeedsRedraw(limit, A.id, drawn, false)).toEqual({ swap: true, keepRows: false, commit: true })
  })

  it("re-reads once per page view, pruning nothing, an answer that no longer lists the workspace", () => {
    const gone = inbox([ws(B)])
    expect(homeNeedsStep(gone, A.id, drawn, at())).toEqual({ prune: false, reread: true, once: true, commit: false })
    expect(homeNeedsStep(gone, A.id, unread, at())).toEqual({ prune: false, reread: true, once: true, commit: false })
    expect(homeNeedsStep(gone, A.id, drawn, at({ rereadAt: NOW - 1_000 }))).toEqual({ prune: false, reread: false, once: false, commit: false })
    // Spent: the card stays as the re-read left it, and the answer is committed.
    expect(homeNeedsStep(gone, A.id, drawn, at({ spent: true }))).toEqual({ prune: false, reread: false, once: false, commit: true })
    expect(homeNeedsRedraw(gone, A.id, drawn, false)).toEqual({ swap: true, keepRows: false, commit: true })
    expect(homeNeedsRedraw(gone, A.id, unread, false)).toEqual({ swap: true, keepRows: true, commit: true })
  })

  it("a workspace's home asks as often as /needs-you, and may re-read its card that often", () => {
    expect(badgePollMs(true)).toBe(NEEDS_YOU_POLL_MS)
    expect(badgePollMs(false)).toBe(BADGE_POLL_MS)
    const answered = inbox([ws(A, "ok", 1)], [one])
    expect(homeNeedsStep(answered, A.id, unread, at({ rereadAt: NOW - NEEDS_YOU_POLL_MS, gapMs: NEEDS_YOU_POLL_MS }))).toMatchObject({ reread: true, commit: false })
    expect(homeNeedsStep(answered, A.id, unread, at({ rereadAt: NOW - NEEDS_YOU_POLL_MS + 1, gapMs: NEEDS_YOU_POLL_MS }))).toMatchObject({ reread: false, commit: false })
  })

  it("re-reads at most once per badge interval, whatever asked, and commits nothing it skipped", () => {
    const answered = inbox([ws(A, "ok", 1)], [one])
    // Focus or a return to the tab moments after the last re-read: skipped, and the validator stays.
    expect(homeNeedsStep(answered, A.id, unread, at({ rereadAt: NOW - 1_000 }))).toEqual({ prune: true, reread: false, once: false, commit: false })
    expect(homeNeedsStep(answered, A.id, unread, at({ rereadAt: NOW - BADGE_POLL_MS + 1 }))).toMatchObject({ reread: false, commit: false })
    expect(homeNeedsStep(answered, A.id, unread, at({ rereadAt: NOW - BADGE_POLL_MS }))).toMatchObject({ reread: true, commit: false })
    // The once-per-page re-read past the limit waits too, and is not spent by the wait.
    const limit = inbox([{ ...ws(A, "unavailable"), reason: "limit" }])
    expect(homeNeedsStep(limit, A.id, unread, at({ rereadAt: NOW - 1_000 }))).toEqual({ prune: false, reread: false, once: false, commit: false })
    // A card that already shows the answer commits whenever.
    expect(homeNeedsStep(answered, A.id, drawn, at({ rereadAt: NOW - 1_000 }))).toMatchObject({ reread: false, commit: true })
  })

  it("keeps the card and the validator when the re-read fails, so the next poll brings the change again", () => {
    const answered = inbox([ws(A, "ok", 1)], [one])
    expect(homeNeedsRedraw(answered, A.id, null, false)).toEqual({ swap: false, keepRows: false, commit: false })
    // The page came back but its own inbox read failed outright.
    expect(homeNeedsRedraw(answered, A.id, card(undefined), false)).toEqual({ swap: false, keepRows: false, commit: false })
  })

  it("leaves the card, and commits nothing, while one of its Stop buttons is in flight, so the next poll redraws it", () => {
    const answered = inbox([ws(A, "ok", 1)], [one])
    expect(homeNeedsRedraw(answered, A.id, drawn, true)).toEqual({ swap: false, keepRows: false, commit: false })
    expect(homeNeedsRedraw(inbox([ws(A, "unavailable")]), A.id, unread, true)).toEqual({ swap: false, keepRows: false, commit: false })
  })

  it("draws the fresh card, and commits once it shows what the answer says", () => {
    const answered = inbox([ws(A, "ok", 1)], [one])
    expect(homeNeedsRedraw(answered, A.id, drawn, false)).toEqual({ swap: true, keepRows: false, commit: true })
    expect(homeNeedsRedraw(inbox([ws(A, "ok", 0)]), A.id, card("ok"), false)).toEqual({ swap: true, keepRows: false, commit: true })
    // Still unreadable to the page while the answer read it: drawn with the last good rows greyed, nothing committed.
    expect(homeNeedsRedraw(answered, A.id, unread, false)).toEqual({ swap: true, keepRows: true, commit: false })
    // Unreadable to both: drawn and committed; the answer that reads it will differ.
    expect(homeNeedsRedraw(inbox([ws(A, "unavailable")]), A.id, unread, false)).toEqual({ swap: true, keepRows: true, commit: true })
  })
})

describe("a workspace cut with no row left", () => {
  it("keeps its group, and never counts it among the empty ones", () => {
    const cut = ws(A, "ok", 0, true)
    expect(inboxGroups(inbox([cut])).map((g) => g.workspace.workspace.slug)).toEqual(["a"])
    const alone = emptyWords(inbox([cut]))
    expect(alone).toMatchObject({ tone: "partial", title: "Some requests could not be checked", sentence: "Some requests in Alpha could not be checked." })
    const beside = emptyWords(inbox([cut, ws(B)]))
    expect(beside?.sentence).toBe("Nothing is waiting in Beta. Some requests in Alpha could not be checked.")
    expect(beside?.sentence).not.toMatch(/waiting in [^.]*Alpha/)
    // Beside a workspace with rows: no empty words, but the cut group stays.
    const rows = inbox([cut, ws(B, "ok", 1)], [confirm(B, "m")])
    expect(emptyWords(rows)).toBeNull()
    expect(inboxGroups(rows).map((g) => [g.workspace.workspace.slug, g.items.length])).toEqual([["b", 1], ["a", 0]])
  })

  it("leads with the identity check when a gated workspace remains", () => {
    expect(emptyWords(inbox([ws(A), ws(B, "gated")]))?.title).toBe("Verify your identity to finish checking")
  })
})


describe("a review group's second line", () => {
  it("counts the asks that need a closer look and those decided on their own page, singular and plural", () => {
    expect(reviewGroupWords(1, 1)).toBe("1 needs a closer look. 1 decides on its own page.")
    expect(reviewGroupWords(3, 2)).toBe("3 need a closer look. 2 decide on their own page.")
  })

  it("leaves out a part whose count is 0, and reads All routine. when both are", () => {
    expect(reviewGroupWords(0, 1)).toBe("1 decides on its own page.")
    expect(reviewGroupWords(2, 0)).toBe("2 need a closer look.")
    expect(reviewGroupWords(0, 0)).toBe("All routine.")
  })

  it("counts the asks the viewer may only deny, and never reads All routine. while one waits", () => {
    expect(reviewGroupWords(0, 0, 1)).toBe("1 can only be denied.")
    expect(reviewGroupWords(1, 2, 3)).toBe("1 needs a closer look. 2 decide on their own page. 3 can only be denied.")
    expect(reviewGroupWords(0, 0, 0)).toBe("All routine.")
  })
})
