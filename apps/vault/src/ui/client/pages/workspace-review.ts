// Review together's script: the row ticks, the code tick (the group's code,
// or the rows' separate codes), and one passkey over the ticked rows
// (decideReviewBatch). Each shown request is hashed against the vault's
// digest first; a row that does not match is unticked for good and decided
// on its own page. Approve stays off until a code tick is ticked and every
// row it would approve matched. Asks that join while the page is open clear
// the code ticks, so they are ticked again after the new rows are seen. The group
// is polled every 20 s while the tab is visible, with If-None-Match; a
// changed group redraws from the page as the server draws it: rows that
// left pending grey out and untick, new rows arrive marked New and never
// ticked, a row the vault now lists elsewhere or a newer ask of its shape
// now follows is drawn again unticked (reviewRedraw), and every other row
// keeps its tick.

import type { ApprovalBatchResult } from "@mehen/protocol/workspace"
import { type Boot, all, find } from "../dom.ts"
import type { ShellState } from "../shell-logic.ts"
import { type ReviewRowBoot, reviewBindingMismatches, reviewChoices } from "../workspace-logic.ts"
import { decideReviewBatch } from "../workspace-sign.ts"
import { gate } from "./workspace-asks.ts"
import { REVIEW_NEW_WORDS, REVIEW_POLL_MS, reviewApproveLabel, reviewChangedWords, reviewCodesWords, reviewOutcomeWords, reviewLacksButtonFor, reviewRedraw, reviewReloadsForArrivals } from "./workspace-review-logic.ts"
import { needShell } from "./workspace.ts"

type ReviewBoot = { group: string; rows: ReviewRowBoot[] }

function rowEl(id: string, root: ParentNode = document): HTMLElement | null {
  return all<HTMLElement>("[data-row]", root).find((r) => r.dataset.approval === id) ?? null
}

function pickOf(row: HTMLElement): HTMLInputElement | null {
  return find<HTMLInputElement>('[data-input="pick"]', row)
}

// A row that may no longer be decided here: unticked, its tick off.
function retire(row: HTMLElement): void {
  const pick = pickOf(row)
  if (pick) {
    pick.checked = false
    pick.disabled = true
  }
}

function bootOf(doc: Document): ReviewBoot | null {
  try {
    const boot = JSON.parse(doc.getElementById("app")?.dataset.boot ?? "") as Partial<ReviewBoot> & Boot
    return boot.page === "ws-review" && Array.isArray(boot.rows) && typeof boot.group === "string" ? { group: boot.group, rows: boot.rows } : null
  } catch {
    return null
  }
}

export function initWorkspaceReview(raw: Boot, maybe: ShellState | null): void {
  const shell = needShell(maybe)
  const boot = raw as unknown as ReviewBoot & Boot
  find<HTMLFormElement>("#decide")?.addEventListener("submit", (event) => event.preventDefault())
  const rows = new Map(boot.rows.map((r) => [r.approval, r]))
  // Detail rows whose request hashed to the vault's digest on this page.
  const matched = new Set<string>()
  const approve = find<HTMLButtonElement>('[data-action="approve-ticked"]')
  const deny = find<HTMLButtonElement>('[data-action="deny-ticked"]')
  const buttons = { approve: approve !== null, deny: deny !== null }
  const codeTicks = [find<HTMLInputElement>('[data-input="group-code-checked"]'), find<HTMLInputElement>('[data-input="codes-checked"]')].filter((tick) => tick !== null)
  const codesChecked = () => codeTicks.some((tick) => tick.checked)
  const codesLabel = find('[data-region="codes-label"]')
  const changedNote = find('[data-region="review-changed"]')
  const approveLabel = find('[data-region="approve-label"]')
  const outcome = find('[data-region="review-outcome"]')
  const list = () => [...rows.values()]
  const ticked = () => new Set(all<HTMLElement>("[data-row]").filter((r) => pickOf(r)?.checked === true && pickOf(r)?.disabled !== true).map((r) => r.dataset.approval ?? ""))
  const approving = () => reviewChoices(list(), ticked(), "approve")
  const g = gate([deny, approve], (b) => {
    if (b === deny) return reviewChoices(list(), ticked(), "deny").length > 0
    const choices = approving()
    return codesChecked() && choices.length > 0 && choices.every((c) => matched.has(c.approval))
  }, () => {
    const picked = ticked()
    const approves = approving().length
    const denyOnly = list().filter((r) => picked.has(r.approval) && r.pending && r.section === "deny-only").length
    if (codesLabel) codesLabel.textContent = reviewCodesWords(picked.size)
    if (approveLabel) approveLabel.textContent = reviewApproveLabel(approves, denyOnly)
  })
  find("#decide")?.addEventListener("change", g.refresh)
  for (const tick of codeTicks) tick.addEventListener("change", () => {
    if (tick.checked && changedNote) changedNote.hidden = true
    g.refresh()
  })

  // A row whose shown request does not hash to the stored digest is
  // decided on its own page, whatever the vault placed it under.
  const check = async (checked: readonly ReviewRowBoot[]) => {
    const failed = new Set(await reviewBindingMismatches(checked))
    for (const row of checked) {
      if (row.view !== "detail") continue
      if (!failed.has(row.approval)) {
        matched.add(row.approval)
        continue
      }
      rows.set(row.approval, { ...row, section: "own-page" })
      const el = rowEl(row.approval)
      if (el === null) continue
      retire(el)
      const line = find('[data-region="row-mismatch"]', el)
      if (line) line.hidden = false
    }
    g.refresh()
  }

  // The group as the server now draws it.
  const redraw = async () => {
    const response = await fetch(location.pathname, { credentials: "same-origin", cache: "no-store", headers: { accept: "text/html" } })
    if (response.status !== 200) return
    const doc = new DOMParser().parseFromString(await response.text(), "text/html")
    const next = bootOf(doc)
    if (next === null || next.group !== boot.group) return
    if (reviewReloadsForArrivals(find('[data-region="review-section"]') !== null, next.rows)) return location.reload()
    const fresh = new Map(next.rows.map((r) => [r.approval, r]))
    const changed = reviewRedraw(list(), next.rows)
    const arrived: ReviewRowBoot[] = [], redrawn: ReviewRowBoot[] = []
    for (const [id, row] of rows) {
      const now = fresh.get(id)
      const el = rowEl(id)
      if (!row.pending || (now !== undefined && now.pending)) continue
      // Left pending, or no longer shown to this viewer: greyed and unticked in place.
      rows.set(id, { ...row, pending: false })
      const drawn = now !== undefined ? rowEl(id, doc) : null
      if (el !== null && drawn !== null) el.replaceWith(document.importNode(drawn, true))
      else if (el !== null) {
        retire(el)
        el.classList.add("settled")
      }
    }
    // Still pending but placed or followed differently: drawn again, unticked, and checked again.
    for (const step of changed) {
      const { row, moved } = step
      if (reviewLacksButtonFor(row.section, buttons)) return location.reload()
      const el = rowEl(row.approval), drawn = rowEl(row.approval, doc)
      matched.delete(row.approval)
      rows.set(row.approval, row)
      if (step.check) redrawn.push(row)
      if (el === null || drawn === null) {
        if (el !== null) retire(el)
        continue
      }
      const replacement = document.importNode(drawn, true)
      const pick = pickOf(replacement)
      if (pick) pick.checked = false
      const from = el.closest<HTMLElement>('[data-region="review-section"]')
      const to = moved ? find<HTMLElement>(`[data-region="review-section"][data-section="${drawn.dataset.section ?? ""}"]`) : null
      if (to === null) el.replaceWith(replacement)
      else {
        el.remove()
        find("ul", to)?.append(replacement)
        to.hidden = false
        if (from !== null && find("[data-row]", from) === null) from.hidden = true
      }
    }
    for (const row of next.rows) {
      if (rows.has(row.approval) || !row.pending) continue
      const drawn = rowEl(row.approval, doc)
      const section = find<HTMLElement>(`[data-region="review-section"][data-section="${drawn?.dataset.section ?? ""}"]`)
      if (drawn === null || section === null) continue
      // A row the page has no button for cannot be decided here: draw the page again.
      if (reviewLacksButtonFor(row.section, buttons)) return location.reload()
      const el = document.importNode(drawn, true)
      const pick = pickOf(el)
      if (pick) pick.checked = false
      const marks = find('[data-region="row-marks"]', el)
      if (marks) {
        const mark = document.createElement("span")
        mark.className = "pill accent dot"
        mark.textContent = REVIEW_NEW_WORDS
        marks.prepend(mark)
        marks.hidden = false
      }
      find("ul", section)?.append(el)
      section.hidden = false
      rows.set(row.approval, row)
      arrived.push(row)
    }
    // With nothing left pending, the head says so, as the server draws it.
    if (!list().some((r) => r.pending)) {
      const head = find('[data-region="review-head"]'), drawnHead = find('[data-region="review-head"]', doc)
      if (head && drawnHead) head.replaceWith(document.importNode(drawnHead, true))
    }
    if (arrived.length > 0) {
      for (const tick of codeTicks) tick.checked = false
      if (changedNote) {
        changedNote.textContent = reviewChangedWords(arrived.length)
        changedNote.hidden = false
      }
    }
    g.refresh()
    if (redrawn.length + arrived.length > 0) await check([...redrawn, ...arrived])
  }

  // The group as the page was drawn: the first poll redraws only if it changed since.
  let etag: string | null = typeof raw.etag === "string" ? raw.etag : null
  let ended = false
  const poll = async () => {
    if (g.busy()) return
    const response = await fetch(shell.apiPath(`/approvals/groups/${encodeURIComponent(boot.group)}`), { credentials: "same-origin", cache: "no-store", headers: { accept: "application/json", ...(etag !== null ? { "if-none-match": etag } : {}) } })
    if (response.status === 401) {
      ended = true
      return
    }
    if (response.status !== 200) return
    // A 200 is a group changed since the last answer, or since the page
    // was drawn for the first one.
    etag = response.headers.get("etag")
    await redraw()
  }
  let timer: ReturnType<typeof setTimeout> | undefined
  const visible = () => document.visibilityState === "visible"
  const schedule = () => {
    clearTimeout(timer)
    if (!ended && visible()) timer = setTimeout(() => void poll().catch(() => undefined).finally(schedule), REVIEW_POLL_MS)
  }
  document.addEventListener("visibilitychange", () => (visible() ? void poll().catch(() => undefined).finally(schedule) : clearTimeout(timer)))
  void poll().catch(() => undefined).finally(schedule)

  const decide = (button: HTMLButtonElement, decision: "approve" | "deny") => g.run(button, "Waiting for your passkey...", async () => {
    const choices = reviewChoices(list(), ticked(), decision)
    const result = await decideReviewBatch<ApprovalBatchResult>(shell, list(), choices, codesChecked())
    if (outcome) {
      outcome.textContent = reviewOutcomeWords(result)
      outcome.hidden = false
    }
    for (const tick of codeTicks) tick.checked = false
    await redraw()
  })
  if (approve) approve.addEventListener("click", () => decide(approve, "approve"))
  if (deny) deny.addEventListener("click", () => decide(deny, "deny"))
  g.refresh()
  void check(list().filter((r) => r.pending))
}
