// Review together's words and start ticks: the bar's labels, the empty
// group, and what a batch did, read only from the vault's answer.

import { describe, expect, expectTypeOf, it } from "vitest"
import type { ApprovalBatchResult, ApprovalGroupRow, ApprovalOwnPageReason } from "@mehen/protocol/workspace"
import type { ReviewRowBoot } from "../workspace-logic.ts"
import { OWN_PAGE_OTHER_WORDS, OWN_PAGE_REASON_WORDS, reviewApproveLabel, reviewChangedWords, reviewCodesWords, reviewGroupCodeWords, reviewCountWords, reviewEmptyWords, reviewOutcomeWords, reviewLacksButtonFor, reviewOwnPageWords, reviewRedraw, reviewReloadsForArrivals } from "./workspace-review-logic.ts"

describe("Review together's words", () => {
  const result = (outcomes: ApprovalBatchResult["results"][number]["outcome"][]): ApprovalBatchResult => ({ batch: "apb_1", results: outcomes.map((outcome, i) => ({ approval: `apr_${i}`, outcome, message: "" })), approved: 0, denied: 0, skipped: 0 })

  it("says what a batch did from each entry's outcome, singular and plural", () => {
    expect(reviewOutcomeWords(result([...Array<"approved">(11).fill("approved"), "expired"]))).toBe("11 approved. 1 had expired.")
    expect(reviewOutcomeWords(result(["denied", "denied", "decided"]))).toBe("2 denied. 1 was already decided.")
    expect(reviewOutcomeWords(result(["approved", "superseded", "superseded", "own_page", "changed", "stale", "forbidden"]))).toBe("1 approved. 2 were replaced by newer asks. 1 no longer applies. 1 is no longer yours to decide. 1 changed since the page loaded. 1 must be decided on its own page.")
    expect(reviewOutcomeWords(result([]))).toBe("Nothing was decided.")
  })

  it("counts the bar's ticks and Approve, naming the ticked rows it can only deny", () => {
    expect(reviewCodesWords(11)).toBe("The agent showed separate codes, and I checked them against the rows (11 ticked)")
    expect(reviewGroupCodeWords("K7QM3P")).toBe("The agent showed me the code K7QM3P")
    expect(reviewChangedWords(1)).toBe("An ask joined this group since the page loaded, marked New and not ticked. Check it, then tick the code again.")
    expect(reviewChangedWords(3)).toBe("3 asks joined this group since the page loaded, marked New and not ticked. Check them, then tick the code again.")
    expect(reviewApproveLabel(11, 0)).toBe("Approve 11 with passkey")
    expect(reviewApproveLabel(10, 1)).toBe("Approve 10 with passkey (1 can only be denied)")
  })

  it("says nothing waits, with how many were decided in the last hour, and counts asks and requests", () => {
    expect(reviewEmptyWords(12)).toBe("Nothing waiting here. 12 decided in the last hour.")
    expect(reviewEmptyWords(0)).toBe("Nothing waiting here.")
    expect(reviewCountWords(1, "machine")).toBe("1 ask")
    expect(reviewCountWords(12, "machine")).toBe("12 asks")
    expect(reviewCountWords(12, "bundle")).toBe("12 requests to approve together")
  })

  it("needs no words for every own-page reason, and reads one it has none for as the plain instruction", () => {
    // The vault may name a reason added after this page (a push, say): the build must not break.
    expectTypeOf(OWN_PAGE_REASON_WORDS).toEqualTypeOf<Readonly<Partial<Record<ApprovalOwnPageReason, string>>>>()
    const unknown = { view: "detail", ownPage: "push" } as unknown as ApprovalGroupRow
    expect(reviewOwnPageWords(unknown)).toBe(OWN_PAGE_OTHER_WORDS)
    expect(reviewOwnPageWords({ view: "detail", ownPage: "four-eyes" } as unknown as ApprovalGroupRow)).toBe("Needs a second person")
  })
})

describe("Review together's poll", () => {
  const detail = (approval: string, section: ReviewRowBoot["section"], newer = false, pending = true): ReviewRowBoot => ({ approval, view: "detail", section, pending, newer, digest: `digest-${approval}`, subject: { item: "cloudflare", method: "POST", url: `https://api.example.com/${approval}`, contentType: null, contentEncoding: null, headersSha256: "h", bodySha256: "b", constraints: { uses: 1, ttlSeconds: 600 } }, binding: { snapshotDigest: "s", presentationDigest: "p" }, headers: null })
  const held = [detail("apr_a", "routine"), detail("apr_b", "routine"), detail("apr_c", "floor")]

  it("unticks a routine row that became deny-only, moves it, holds the fresh row and checks it again", () => {
    const fresh = [detail("apr_a", "deny-only"), detail("apr_b", "routine"), detail("apr_c", "floor")]
    expect(reviewRedraw(held, fresh)).toEqual([{ row: fresh[0], moved: true, untick: true, check: true }])
  })

  it("unticks a row a newer ask of the same shape now follows, redrawn in place with its note, and checks it again", () => {
    const fresh = [detail("apr_a", "routine"), detail("apr_b", "routine", true), detail("apr_c", "floor"), detail("apr_d", "routine")]
    expect(reviewRedraw(held, fresh)).toEqual([{ row: fresh[1], moved: false, untick: true, check: true }])
  })

  it("leaves an unchanged row, and its tick, alone, as it does rows that left pending and new arrivals", () => {
    expect(reviewRedraw(held, held)).toEqual([])
    expect(reviewRedraw(held, [detail("apr_a", "routine"), detail("apr_b", "deny-only", false, false), detail("apr_e", "floor")])).toEqual([])
    const stop: ReviewRowBoot = { approval: "apr_s", view: "stop", section: "deny-only", pending: true }
    expect(reviewRedraw([...held, stop], [...held, stop])).toEqual([])
  })

  it("draws the page again for a row it has no button for: any but own-page with no bar, a routine or floor row with no Approve", () => {
    const noBar = { approve: false, deny: false }, denyOnly = { approve: false, deny: true }, full = { approve: true, deny: true }
    expect(["routine", "floor", "deny-only", "own-page"].map((s) => reviewLacksButtonFor(s as ReviewRowBoot["section"], noBar))).toEqual([true, true, true, false])
    expect(["routine", "floor", "deny-only", "own-page"].map((s) => reviewLacksButtonFor(s as ReviewRowBoot["section"], denyOnly))).toEqual([true, true, false, false])
    expect(["routine", "floor", "deny-only", "own-page"].map((s) => reviewLacksButtonFor(s as ReviewRowBoot["section"], full))).toEqual([false, false, false, false])
  })

  it("draws an empty page again once a pending ask arrives, since it has no section to put it in", () => {
    expect(reviewReloadsForArrivals(false, [detail("apr_a", "routine")])).toBe(true)
    expect(reviewReloadsForArrivals(false, [{ approval: "apr_s", view: "stop", section: "deny-only", pending: true }])).toBe(true)
    expect(reviewReloadsForArrivals(false, [detail("apr_a", "routine", false, false)])).toBe(false)
    expect(reviewReloadsForArrivals(false, [])).toBe(false)
    expect(reviewReloadsForArrivals(true, [detail("apr_a", "routine")])).toBe(false)
  })
})
