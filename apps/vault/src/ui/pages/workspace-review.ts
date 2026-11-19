// Review together (/w/<slug>/g/<id>): one review group's asks (one machine,
// task and credential) or one bundle's, to decide with one passkey as
// approval.decide_many (design batch-approvals 3.3 and 4). The vault places
// each row (approvalGroupRow): Ready rows start ticked; Look at these first
// rows start unticked with the request open and their floor marks; Decide
// on its own page rows link there and cannot be ticked; You can only deny
// these start unticked. A protected credential's use (ruling B2) and a row
// a newer ask of the same shape follows (ruling B1) never start ticked.
// One code tick in the bar, as on the adoption batch page (/b/<id>), the
// precedent for ticking rows under one passkey. The boot data carries what
// each row's digest recomputes from, so the script approves only rows
// whose request this page shows.

import type { ApprovalBatchState, ApprovalGroupRow, ApprovalGroupView } from "@mehen/protocol/workspace"
import { APPROVAL_TTL_MS } from "../../vault/areas/approvals.ts"
import { approvalGroupSection } from "../../vault/areas/approvals-batch-workspace.ts"
import { askPlace, decisionBar, warningCard } from "../ask-evidence.ts"
import { askWarnings, stopTexts } from "../ask-safety.ts"
import type { ReviewRowBoot } from "../client/workspace-logic.ts"
import { REVIEW_DENY_ONLY_WORDS, REVIEW_FOOTNOTE, REVIEW_NEWER_WORDS, REVIEW_NEXT_WORDS, REVIEW_PROTECTED_WORDS, REVIEW_MISMATCH_WORDS, REVIEW_SECTION_ORDER, REVIEW_SECTION_TITLES, REVIEW_STOP_WORDS, reviewApproveLabel, reviewCodesWords, reviewCountWords, reviewEmptyWords, reviewFloorMarks, reviewOwnPageWords, reviewPending, reviewRowId, reviewTickedAtStart } from "../client/pages/workspace-review-logic.ts"
import { cardText, countdownTimer, notice, pill } from "../components.ts"
import { type Html, html } from "../html.ts"
import { kindTile } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import { type WorkspaceShell, workspaceHref } from "../shell.ts"
import { PASSKEY_CONFIRMS_WORDS, REQUEST_BODY_HEADING, TASK_LABEL_WORDS, detailLabelWords } from "../wording.ts"
import type { Viewer } from "../workspace-rights.ts"
import { SETTLED_APPROVAL_WORDS, approvalSubjectOf, heldNotice, settledBy } from "./workspace-asks.ts"

type DetailRow = Extract<ApprovalGroupRow, { view: "detail" }>

export const REVIEW_TITLE = "Review together"
export const REVIEW_AGENT_WORDS = "the agent's words, not verified"

// Where a row sits on the page: its section while pending, the settled
// list once decided.
function placeOf(row: ApprovalGroupRow): ApprovalBatchState | "settled" {
  return reviewPending(row) ? approvalGroupSection(row) : "settled"
}

// A row may be ticked while pending in any section but own-page.
function tickable(row: ApprovalGroupRow): boolean {
  return reviewPending(row) && approvalGroupSection(row) !== "own-page"
}

// What the script needs to approve or deny a row exactly as shown.
export function reviewRowBoot(row: ApprovalGroupRow): ReviewRowBoot {
  if (row.view === "stop") return { approval: row.stop.id, view: "stop", section: row.batch, pending: reviewPending(row) }
  const a = row.approval
  return { approval: a.approval, view: "detail", section: approvalGroupSection(row), pending: reviewPending(row), newer: (row.newerSameShape ?? null) !== null, digest: a.digest, subject: approvalSubjectOf(a), binding: row.binding, headers: a.request.headers }
}

// The request line: the method, then the host and path apart, as the
// agent asked; a URL that does not parse is shown whole.
function requestLine(method: string, url: string): Html {
  let where: Html
  try {
    const u = new URL(url)
    where = html`<code class="url">${cardText(u.host)}</code> <code class="url">${cardText(`${u.pathname}${u.search}`)}</code>`
  } catch {
    where = html`<code class="url">${cardText(url)}</code>`
  }
  return html`<p class="request-line" data-region="request-line"><span class="method">${cardText(method)}</span> ${where}</p>`
}

// The single page's request block, folded under Show request: open on a
// row to look at first.
function requestBlock(row: DetailRow, open: boolean): Html {
  const r = row.approval.request
  return html`<details class="review-request" data-region="review-request"${open ? html` open` : ""}><summary>Show request</summary>
    <p class="request-line"><span class="method">${cardText(r.method)}</span> <code class="url">${cardText(r.url)}</code></p>
    <dl class="kv small"><dt>Content type</dt><dd>${r.contentType !== null ? html`<code>${cardText(r.contentType)}</code>` : html`<span class="muted">none</span>`}</dd></dl>
    <p class="small muted">${REQUEST_BODY_HEADING}</p>
    ${r.body !== null ? html`<pre class="request-body" tabindex="0">${cardText(r.body)}</pre>` : html`<p class="muted small">No body.</p>`}
    ${r.headers !== null && r.headers.length > 0 ? html`<dl class="kv small">${r.headers.map(([name, value]) => html`<dt><code>${cardText(name)}</code></dt><dd>${value !== "" ? html`<code>${cardText(value)}</code>` : html`<span class="muted">empty</span>`}</dd>`)}</dl>` : ""}
  </details>`
}

function ownPageLink(slug: string, id: string, label: string, primary = false): Html {
  return html`<a class="btn ${primary ? "primary" : "secondary"} sm" href="${workspaceHref(slug, `/a/${encodeURIComponent(id)}`)}">${label}</a>`
}

function marks(row: ApprovalGroupRow, place: ApprovalBatchState | "settled"): Html {
  const shown = [
    ...reviewFloorMarks(row).map((m) => pill(m, "warn")),
    ...(row.view === "detail" && row.protected === true ? [pill(REVIEW_PROTECTED_WORDS, "warn")] : []),
    ...(place === "deny-only" ? [pill(REVIEW_DENY_ONLY_WORDS, "muted")] : []),
  ]
  return html`<p class="review-marks" data-region="row-marks"${shown.length === 0 ? html` hidden` : ""}>${shown}</p>`
}

function settledLine(row: ApprovalGroupRow, viewer: Viewer): Html {
  if (row.view === "stop") return html`<p class="strip" data-region="settled">${pill(row.stop.status, "muted")}</p>`
  const a = row.approval
  const words = a.status === "pending" ? "" : SETTLED_APPROVAL_WORDS[a.status]
  return html`<p class="strip" data-region="settled">${pill(a.status, a.status === "approved" ? "ok" : "muted")} ${settledBy(a.decidedBy, viewer)}</p>${words !== "" ? html`<p class="small muted">${words}</p>` : ""}`
}

function tick(row: ApprovalGroupRow, code: Html | string): Html {
  return html`<label class="tick"><input type="checkbox" form="decide" data-input="pick"${reviewTickedAtStart(row, approvalGroupSection(row)) ? html` checked` : ""}><span>${code}</span></label>`
}

function detailRow(row: DetailRow, slug: string, viewer: Viewer): Html {
  const a = row.approval
  const place = placeOf(row)
  const code = html`<code class="code-inline" data-region="row-code">${a.bindingCode}</code>`
  const line = a.details.find((d) => d.value !== a.title)
  return html`<li class="review-row${place === "settled" ? " settled" : ""}" data-row data-approval="${a.approval}" data-section="${place}">
    <div class="review-row-head">${tickable(row) ? tick(row, code) : code}${requestLine(a.request.method, a.request.url)}</div>
    <p class="review-title">${cardText(a.title)}</p>
    ${line !== undefined ? html`<p class="small muted">${cardText(detailLabelWords(line.label))}: ${cardText(line.value)}</p>` : ""}
    ${marks(row, place)}
    ${place !== "settled" && (row.newerSameShape ?? null) !== null ? html`<p class="small" data-region="newer-same-shape">${REVIEW_NEWER_WORDS}</p>` : ""}
    ${place === "own-page" ? html`<p class="small" data-region="own-page-reason">${reviewOwnPageWords(row)}</p>` : ""}
    <p class="small refused" data-region="row-mismatch" hidden>${REVIEW_MISMATCH_WORDS}</p>
    ${place === "settled" ? settledLine(row, viewer) : ""}
    ${place !== "own-page" ? requestBlock(row, place === "floor") : ""}
    <p class="review-open">${ownPageLink(slug, a.approval, place === "own-page" ? "Open its own page" : "Its own page", place === "own-page")}</p>
  </li>`
}

function stopRow(row: Extract<ApprovalGroupRow, { view: "stop" }>, slug: string, viewer: Viewer): Html {
  const s = row.stop
  const place = placeOf(row)
  return html`<li class="review-row${place === "settled" ? " settled" : ""}" data-row data-approval="${s.id}" data-section="${place}">
    <div class="review-row-head">${tickable(row) ? tick(row, html`<span class="muted">${REVIEW_STOP_WORDS}</span>`) : html`<span class="muted">${REVIEW_STOP_WORDS}</span>`}</div>
    <p class="review-title">${cardText(s.machine.name)}${s.item !== null ? html`, for <code>${cardText(s.item.slug)}</code>` : ""}</p>
    ${marks(row, place)}
    ${place === "own-page" ? html`<p class="small" data-region="own-page-reason">${reviewOwnPageWords(row)}</p>` : ""}
    ${place === "settled" ? settledLine(row, viewer) : ""}
    <p class="review-open">${ownPageLink(slug, s.id, place === "own-page" ? "Open its own page" : "Its own page", place === "own-page")}</p>
  </li>`
}

function rowHtml(row: ApprovalGroupRow, slug: string, viewer: Viewer): Html {
  return row.view === "detail" ? detailRow(row, slug, viewer) : stopRow(row, slug, viewer)
}

// Every section is drawn, an empty one hidden, so a row the poll brings
// has somewhere to go.
function sections(view: ApprovalGroupView, slug: string, viewer: Viewer): Html {
  const places: readonly (ApprovalBatchState | "settled")[] = [...REVIEW_SECTION_ORDER, "settled"]
  return html`${places.map((place) => {
    const rows = view.rows.filter((r) => placeOf(r) === place)
    const title = place === "settled" ? "Decided in the last hour" : REVIEW_SECTION_TITLES[place]
    return html`<section class="card review-section" data-region="review-section" data-section="${place}" aria-label="${title}"${rows.length === 0 ? html` hidden` : ""}><h2>${title}</h2><ul class="review-rows">${rows.map((r) => rowHtml(r, slug, viewer))}</ul></section>`
  })}`
}

// Every string the page shows that came from a machine or an agent: the
// group's head, each detail row's title, and all a stop row shows, as the
// single stop view warns on it (stopTexts).
function headTexts(view: ApprovalGroupView): string[] {
  const rows = view.rows.flatMap((r) => (r.view === "detail" ? [r.approval.title] : stopTexts(r.stop)))
  return [view.workspace.name, view.workspace.slug, view.machine.name, view.machine.owner.name, view.machine.workload?.label ?? "", view.item?.slug ?? "", view.reason ?? "", ...rows]
}

// etag: the group read's validator for this view, which the script's first
// poll sends as If-None-Match.
export type ReviewPageData = { viewer: Viewer; group: string; view: ApprovalGroupView | null; etag?: string | null; now?: number }

// The page for a group with nothing this viewer may see: what it would say
// once everything in it is decided.
function emptyPage(shell: WorkspaceShell, group: string): PageInput {
  const slug = shell.identity.workspace.slug
  return {
    title: REVIEW_TITLE,
    viewer: null,
    workspace: shell,
    boot: { page: "ws-review", group, etag: null, rows: [] },
    body: html`<section class="card decision" data-region="review-head"><p class="eyebrow">${REVIEW_TITLE}</p><h1>${reviewEmptyWords(0)}</h1><p><a class="btn secondary sm" href="${workspaceHref(slug, "/pending")}">Needs you in this workspace</a></p></section>`,
  }
}

export function workspaceReviewPage(shell: WorkspaceShell, data: ReviewPageData): PageInput {
  const view = data.view
  if (view === null) return emptyPage(shell, data.group)
  const slug = shell.identity.workspace.slug
  const now = data.now ?? Date.now()
  const pending = view.rows.filter(reviewPending)
  const settled = view.rows.length - pending.length
  const open = pending.filter(tickable)
  const ticked = open.filter((r) => reviewTickedAtStart(r, approvalGroupSection(r)))
  const mayApprove = open.some((r) => { const s = approvalGroupSection(r); return s === "routine" || s === "floor" })
  const warnings = askWarnings(headTexts(view))
  const warned = warnings.length > 0
  const soonest = pending.flatMap((r) => (r.view === "detail" ? [r.approval.expiresAt] : [])).sort()[0]
  const m = view.machine
  const owner = m.owner.kind === "member" ? m.owner.name : `the team ${m.owner.name}`
  const title = html`${cardText(m.name)}: ${reviewCountWords(pending.length, view.kind)}${view.kind === "machine" && view.item !== null ? html` on <code>${cardText(view.item.slug)}</code>` : ""}`
  const head = html`<section class="card decision${warned ? " warned" : ""}" data-region="review-head">
    <div class="decision-head">${kindTile("machine", undefined, "lg", m.name)}<div><p class="eyebrow">${REVIEW_TITLE}</p><h1>${title}</h1></div></div>
    <p class="who ask-context">${askPlace(shell.identity.origin, view.workspace)} · an agent on <b>${cardText(m.name)}</b>, owned by ${cardText(owner)}.</p>
    ${m.workload !== null ? html`<p class="small muted" data-region="ask-task">Task: <b>${cardText(m.workload.label)}</b>, ${TASK_LABEL_WORDS}</p>` : ""}
    ${view.reason !== null ? html`<blockquote class="reason" data-region="bundle-reason">${cardText(view.reason)}</blockquote><p class="small muted">${REVIEW_AGENT_WORDS}</p>` : ""}
    ${soonest !== undefined ? html`<p class="meta"><span class="timer-line">${countdownTimer(soonest, APPROVAL_TTL_MS / 1000, now)} <span class="muted">until the first runs out</span></span></p>` : ""}
    ${pending.length === 0 ? html`<p data-region="review-empty">${reviewEmptyWords(settled)}</p><p><a class="btn secondary sm" href="${workspaceHref(slug, "/pending")}">Needs you in this workspace</a></p>` : ""}
  </section>`
  const outcome = html`<div data-region="review-outcome" role="status" aria-live="polite" hidden></div>`
  const bar = open.length > 0
  const codes = html`<label class="tick" data-region="codes-tick"><input type="checkbox" form="decide" data-input="codes-checked"><span data-region="codes-label">${reviewCodesWords(ticked.length)}</span></label>`
  const denyOnly = ticked.filter((r) => approvalGroupSection(r) === "deny-only").length
  return {
    title: `${REVIEW_TITLE}: ${m.name}`,
    viewer: null,
    workspace: shell,
    bar,
    wide: true,
    boot: { page: "ws-review", group: view.group, etag: data.etag ?? null, rows: view.rows.map(reviewRowBoot) },
    body: html`${mayApprove ? heldNotice(shell, "approval") : ""}${warningCard(warnings)}<form class="stack" id="decide" data-form="review" novalidate>${head}${outcome}${sections(view, slug, data.viewer)}</form>
      ${bar ? html`<div class="ask-next">${notice("info", "What happens next", REVIEW_NEXT_WORDS)}</div>` : ""}
      <p class="small muted" data-region="review-footnote">${REVIEW_FOOTNOTE}</p>
      ${bar
        ? decisionBar({
            warned,
            form: "decide",
            terms: codes,
            caption: PASSKEY_CONFIRMS_WORDS,
            decline: { action: "deny-ticked", label: "Deny ticked", disabled: ticked.length === 0 },
            // Nothing this viewer may approve waits: no Approve, as on the single page.
            accept: mayApprove ? { action: "approve-ticked", label: html`<span data-region="approve-label">${reviewApproveLabel(ticked.length - denyOnly, denyOnly)}</span>`, passkey: true, disabled: true } : null,
          })
        : ""}`,
  }
}
