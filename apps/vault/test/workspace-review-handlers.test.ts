// Review together's script (initWorkspaceReview) on the page as the server
// draws it: the group code tick, and asks that join the group while the
// page is open clearing it.
import { afterEach, describe, expect, it } from "vitest"
import type { ApprovalGroupRow, ApprovalGroupView } from "@mehen/protocol/workspace"
import { renderDocument } from "../src/ui/layout.ts"
import { workspaceReviewPage } from "../src/ui/pages/workspace-review.ts"
import { GALLERY_REVIEW_GROUP } from "../src/ui/workspace-asks-gallery.ts"
import { galleryShell } from "../src/ui/workspace-projects-gallery.ts"
import { ShellState } from "../src/ui/client/shell-logic.ts"
import { initWorkspaceReview } from "../src/ui/client/pages/workspace-review.ts"
import { reviewChangedWords } from "../src/ui/client/pages/workspace-review-logic.ts"
import { type MiniBrowser, type MiniElement, MiniEvent, installPage, settle } from "./mini-dom.ts"

const NOW = Date.parse("2026-10-27T18:30:00Z")
const VIEWER = { role: "admin" as const, member: "mem_tom00001" }
const PATH = `/w/northwind/g/${GALLERY_REVIEW_GROUP.group}`

let browser: MiniBrowser | null = null
afterEach(() => {
  browser?.restore()
  browser = null
})

function drawn(view: ApprovalGroupView): string {
  return renderDocument(workspaceReviewPage(galleryShell(VIEWER), { viewer: VIEWER, group: view.group, view, now: NOW })).value
}
function bootOf(markup: string): Record<string, unknown> {
  const raw = /data-boot="([^"]+)"/.exec(markup)?.[1] ?? "{}"
  return JSON.parse(raw.replaceAll("&quot;", '"').replaceAll("&#39;", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&amp;", "&")) as Record<string, unknown>
}
function shell(): ShellState {
  return new ShellState({ origin: "https://vault.test", account: "acc_4Hq9Tz2Lm7Vb1Nc8", workspace: { id: "tn_8kQw2Lm4Zp7Rt5Vx", slug: "northwind", name: "Northwind" }, pages: [], reads: [] })
}
const $ = (selector: string): MiniElement => {
  const found = browser!.document.querySelector(selector)
  if (!found) throw new Error(`no ${selector}`)
  return found
}

// Two routine asks, as the page was drawn; then a third of the same group.
const routine = GALLERY_REVIEW_GROUP.rows[1]! as Extract<ApprovalGroupRow, { view: "detail" }>
const arrival: ApprovalGroupRow = { ...routine, approval: { ...routine.approval, approval: "apr_kvnew0011" } }
const BEFORE: ApprovalGroupView = { ...GALLERY_REVIEW_GROUP, rows: [GALLERY_REVIEW_GROUP.rows[1]!, GALLERY_REVIEW_GROUP.rows[2]!] }
const AFTER: ApprovalGroupView = { ...BEFORE, rows: [...BEFORE.rows, arrival] }

describe("Review together's code tick", () => {
  it("clears the code tick and says so when an ask joins the group after the page loaded, the new ask unticked", async () => {
    const first = drawn(BEFORE), next = drawn(AFTER)
    let changed = false
    browser = installPage(first, (path) => {
      // Unchanged reads as anything but a 200, which the script leaves alone.
      if (path.includes("/approvals/groups/")) return changed ? { status: 200, body: {} } : { status: 404, body: {} }
      if (path === PATH) return { status: 200, body: next }
      return { status: 404, body: {} }
    }, `https://vault.test${PATH}`)
    initWorkspaceReview(bootOf(first) as never, shell())
    await settle()
    const tick = $('[data-input="group-code-checked"]')
    expect($('[data-region="group-code-tick"]').textContent).toContain("The agent showed me the code K7QM3P")
    tick.click()
    expect(tick.checked).toBe(true)
    expect($('[data-region="review-changed"]').hidden).toBe(true)
    // The next poll finds the group changed: the server's page now lists the third ask.
    changed = true
    Object.assign(browser.document, { visibilityState: "visible" })
    browser.document.dispatchEvent(new MiniEvent("visibilitychange"))
    await settle(60)
    expect(browser.calls.map((c) => c.path)).toContain(PATH)
    const row = browser.document.querySelector('[data-approval="apr_kvnew0011"]')
    expect(row).not.toBeNull()
    expect(row!.querySelector('[data-input="pick"]')?.checked).toBe(false)
    expect(row!.textContent).toContain("New")
    expect(tick.checked).toBe(false)
    expect($('[data-input="codes-checked"]').checked).toBe(false)
    const note = $('[data-region="review-changed"]')
    expect(note.hidden).toBe(false)
    expect(note.textContent).toBe(reviewChangedWords(1))
    expect($('[data-action="approve-ticked"]').disabled).toBe(true)
    // Ticking the code again, once the new row is seen, puts the note away.
    tick.click()
    expect(note.hidden).toBe(true)
  })

  // The poll finds the group changed and the server's page is `next`.
  async function polledTo(first: string, next: string) {
    let changed = false
    browser = installPage(first, (path) => {
      if (path.includes("/approvals/groups/")) return changed ? { status: 200, body: {} } : { status: 404, body: {} }
      if (path === PATH) return { status: 200, body: next }
      return { status: 404, body: {} }
    }, `https://vault.test${PATH}`)
    initWorkspaceReview(bootOf(first) as never, shell())
    await settle()
    const tick = $('[data-input="group-code-checked"]')
    tick.click()
    expect(tick.checked).toBe(true)
    changed = true
    Object.assign(browser.document, { visibilityState: "visible" })
    browser.document.dispatchEvent(new MiniEvent("visibilitychange"))
    await settle(60)
    expect(browser.calls.map((c) => c.path)).toContain(PATH)
    return tick
  }

  it("draws the page again, the code untick and Approve off, when the group's code changed with its rows", async () => {
    const tick = await polledTo(drawn(BEFORE), drawn({ ...AFTER, code: "M3R8TW" }))
    expect(browser!.reloaded).toBe(1)
    expect(tick.checked).toBe(false)
    expect($('[data-action="approve-ticked"]').disabled).toBe(true)
    // The old page is never extended with the new code's rows.
    expect(browser!.document.querySelector('[data-approval="apr_kvnew0011"]')).toBeNull()
    expect($('[data-region="group-code-tick"]').textContent).toContain("K7QM3P")
  })

  it("draws the page again when the group closed and reopened on a new code: every shown ask settled, a new one waiting", async () => {
    const settled = BEFORE.rows.map((r) => r.view === "detail" ? { ...r, approval: { ...r.approval, status: "expired" as const } } : r)
    const tick = await polledTo(drawn(BEFORE), drawn({ ...BEFORE, code: "M3R8TW", rows: [...settled, arrival] }))
    expect(browser!.reloaded).toBe(1)
    expect(tick.checked).toBe(false)
    expect($('[data-action="approve-ticked"]').disabled).toBe(true)
    expect(browser!.document.querySelector('[data-approval="apr_kvnew0011"]')).toBeNull()
  })

  it("keeps the page, with no reload, when an ask joins under the same code", async () => {
    await polledTo(drawn(BEFORE), drawn(AFTER))
    expect(browser!.reloaded).toBe(0)
    expect(browser!.document.querySelector('[data-approval="apr_kvnew0011"]')).not.toBeNull()
  })
})
