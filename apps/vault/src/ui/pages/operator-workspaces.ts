// The Workspaces view, in the Operator area: every workspace on this vault,
// searched and filtered a page at a time (/operator/workspaces), and one
// workspace (/operator/workspaces/:id) with its people counted, its backups
// and restores, and the operator events that name it. Restoring it (two
// operators) and freezing it (one, as a brake) are the only changes, each
// signed with a passkey; the restore form shows the runbook's checklist
// first, since the console cannot do those steps for the owners. Only an
// operator reaches it; anyone else gets the plain not-found page.
//
// Nothing here opens a credential or reads inside a workspace: owners are
// named, everyone else is counted.

import { NEEDS_SECOND_OPERATOR_WORDS, type OperatorEventView } from "@mehen/protocol/operator-proposals"
import type { OperatorManagedWorkspaceRow, OperatorRestoreView, OperatorWorkspaceDetail, OperatorWorkspaceFilter, OperatorWorkspaceList, OperatorWorkspaceRow, OperatorWorkspaceStatus } from "@mehen/protocol/operator-workspaces"
import { cardText, emptyState, kv, notice, pageHead, pill, type PillTone, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon, iconTile } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import type { AccountShell } from "../shell.ts"
import { OPERATOR_PATH, operatorPlatformPath, operatorRequirementsNotice } from "./operator.ts"
import { actorText, readFailed } from "./platform-console.ts"

export const OPERATOR_WORKSPACES_PATH = "/operator/workspaces"

export function operatorWorkspacePath(id: string): string {
  return `${OPERATOR_WORKSPACES_PATH}/${encodeURIComponent(id)}`
}

const NEVER_INSIDE = "Nothing here opens a credential or reads inside a workspace: owners are named, everyone else is counted."

const STATUS_TONES: Readonly<Record<OperatorWorkspaceStatus | OperatorManagedWorkspaceRow["status"], PillTone>> = { creating: "accent", active: "ok", deleting: "warn", deleted: "muted", purged: "muted" }

function statusPill(status: OperatorWorkspaceStatus | OperatorManagedWorkspaceRow["status"]): Html {
  return pill(status, STATUS_TONES[status])
}

function names(refs: readonly { name: string }[]): Html {
  return html`${refs.map((r, i) => html`${i > 0 ? ", " : ""}${cardText(r.name)}`)}`
}

function count(n: number, one: string, many: string): string {
  return n === 1 ? `1 ${one}` : `${n} ${many}`
}

// The restore a proposal's terms name, in words.
export function restoreTermsText(params: Record<string, unknown>): string {
  if (params.source === "dump" && typeof params.target === "string") return `from the dump of ${params.target}`
  if (params.source === "pitr" && typeof params.target === "string") return `to ${params.target}`
  return ""
}

// ---------------------------------------------------------------- the list

const FILTERS: readonly { filter: OperatorWorkspaceFilter; label: string }[] = [
  { filter: "all", label: "All" },
  { filter: "active", label: "Active" },
  { filter: "creating", label: "Creating" },
  { filter: "deleting", label: "Deleting" },
  { filter: "managed", label: "Platform-managed" },
]

function listAddress(filter: OperatorWorkspaceFilter, q: string, before?: string): string {
  const params = new URLSearchParams()
  if (q !== "") params.set("q", q)
  if (filter !== "all") params.set("filter", filter)
  if (before !== undefined) params.set("before", before)
  const query = params.toString()
  return query === "" ? OPERATOR_WORKSPACES_PATH : `${OPERATOR_WORKSPACES_PATH}?${query}`
}

function workspaceRow(w: OperatorWorkspaceRow): Html {
  const owners = w.owners === null ? "owners not read" : w.owners.length === 0 ? "no owner" : html`owners: ${names(w.owners)}`
  return html`<li class="row" data-workspace="${w.id}">${iconTile("folder")}<a class="row-main" href="${operatorWorkspacePath(w.id)}"><span class="row-title">${cardText(w.name)} <code>${w.slug}</code></span>
    <span class="row-sub"><code>${w.id}</code> · ${owners} · ${count(w.members, "member", "members")}</span>
    <span class="row-sub">Created ${w.createdBy !== null ? html`by ${cardText(w.createdBy.name)} ` : ""}${timeTag(w.createdAt)}</span></a><span class="row-side">${statusPill(w.status)}</span></li>`
}

function managedRow(w: OperatorManagedWorkspaceRow): Html {
  return html`<li class="row" data-workspace="${w.id}">${iconTile("globe")}<a class="row-main" href="${operatorPlatformPath(w.platform.slug)}"><span class="row-title"><code>${w.id}</code></span>
    <span class="row-sub">Managed by ${cardText(w.platform.name)} <code>${w.platform.slug}</code> · created ${timeTag(w.createdAt)}</span></a><span class="row-side">${statusPill(w.status)}</span></li>`
}

// `list` is null when it could not be read.
export function operatorWorkspacesPage(account: AccountShell, list: OperatorWorkspaceList | null): PageInput {
  const head = pageHead({ eyebrow: html`<a href="${OPERATOR_PATH}">Operator</a>`, title: "Workspaces", lead: `Every workspace on this vault, newest first. ${NEVER_INSIDE}` })
  if (list === null) return { title: "Workspaces", viewer: null, account, current: "operator", boot: { page: "operator-workspaces" }, body: html`${head}<section class="card">${readFailed("The workspaces")}</section>` }
  const filters = html`<nav class="chips" data-region="filters" aria-label="Filter the workspaces">${FILTERS.map((f) => html`<a class="chip" href="${listAddress(f.filter, list.q)}"${f.filter === list.filter ? html` aria-current="page"` : ""}>${f.label}</a>`)}</nav>`
  const search = html`<form class="toolbar" method="get" action="${OPERATOR_WORKSPACES_PATH}" role="search" data-form="workspace-search">
      <label class="search">${icon("search")}<input type="search" name="q" value="${list.q}" maxlength="80" placeholder="Search name, slug or tn_ id" aria-label="Search name, slug or tn_ id" autocomplete="off" autocapitalize="off" spellcheck="false"></label>
      ${list.filter !== "all" ? html`<input type="hidden" name="filter" value="${list.filter}">` : ""}
      <button type="submit" class="btn secondary">Search</button>
    </form>`
  const rows = list.workspaces.length === 0
    ? emptyState("folder", list.q !== "" ? "Nothing matches" : "No workspaces here", list.q !== "" ? "Search by part of a name or slug, or a whole workspace id." : "A workspace appears here once someone creates one.")
    : html`<ul class="rows" data-region="workspaces">${list.workspaces.map((w) => (w.kind === "managed" ? managedRow(w) : workspaceRow(w)))}</ul>`
  const older = list.next !== null ? html`<p class="small"><a href="${listAddress(list.filter, list.q, list.next)}" data-region="older">Older workspaces</a></p>` : ""
  return {
    title: "Workspaces",
    viewer: null,
    account,
    current: "operator",
    boot: { page: "operator-workspaces" },
    body: html`${head}<section class="card">${search}${filters}${rows}${older}</section>
      ${list.filter === "managed" ? html`<p class="small muted">A platform's workspaces are its own: each opens its platform. They are not dumped and rely on point-in-time recovery.</p>` : ""}`,
  }
}

// ---------------------------------------------------------------- one workspace

function workspaceCard(d: OperatorWorkspaceDetail): Html {
  const w = d.workspace
  const frozen = w.frozen === null ? "could not be read" : w.frozen ? "frozen: credential use and widening are refused until an owner unfreezes it" : "not frozen"
  return html`<section class="card" data-region="workspace"><h2>The workspace</h2>${kv([
    ["Status", html`${statusPill(w.status)}${w.deleteAfter !== null ? html` deleted after ${timeTag(w.deleteAfter)}` : ""}`],
    ["Freeze", html`<span data-region="frozen">${frozen}</span>`],
    ["Id", html`<code>${w.id}</code>`],
    ["Slug", html`<code>${w.slug}</code>`],
    ["Created", html`${timeTag(w.createdAt)}${w.createdBy !== null ? html` by ${cardText(w.createdBy.name)} <code>${w.createdBy.account}</code>` : ""}`],
    ["Earlier slugs", w.slugs.length === 0 ? "none" : html`${w.slugs.map((s, i) => html`${i > 0 ? ", " : ""}<code>${s.slug}</code> until ${timeTag(s.retiredAt)}`)}`],
    ["Display revision", String(w.displayRevision)],
  ], "facts")}</section>`
}

function peopleCard(d: OperatorWorkspaceDetail): Html {
  const p = d.people
  const owners = p.owners === null ? html`<span class="muted">could not be read</span>` : p.owners.length === 0 ? "none" : html`${p.owners.map((o, i) => html`${i > 0 ? ", " : ""}${cardText(o.name)} <code>${o.account}</code>`)}`
  return html`<section class="card" data-region="people"><h2>People</h2>${kv([
    ["Owners", owners],
    ["By role", `${count(p.roles.owner, "owner", "owners")}, ${count(p.roles.admin, "admin", "admins")}, ${count(p.roles.member, "member", "members")}, ${count(p.roles.guest, "guest", "guests")}`],
    ["Joining", String(p.joining)],
    ["Unconfirmed", p.unconfirmed === null ? html`<span class="muted">could not be read</span>` : String(p.unconfirmed)],
  ], "facts")}
    <p class="small muted">Roles are the directory's hints, as each person joined; the workspace itself is the authority. Its owners and admins manage its people.</p></section>`
}

const RESTORE_STATE_TONES: Readonly<Record<OperatorRestoreView["state"], PillTone>> = { pending: "accent", restarting: "accent", done: "ok", failed: "danger", expired: "muted" }

function restoreRow(r: OperatorRestoreView): Html {
  return html`<li class="row" data-restore="${r.id}"><span class="row-main"><span class="row-title">${r.source === "dump" ? `From the dump of ${r.target}` : html`To ${timeTag(r.target)}`} ${pill(r.state, RESTORE_STATE_TONES[r.state])}</span>
    <span class="row-sub">Recorded ${timeTag(r.createdAt)} by ${actorText(r.actor)}${r.completedAt !== null ? html` · finished ${timeTag(r.completedAt)}` : ""}</span>
    ${r.error !== null ? html`<span class="row-sub">${cardText(r.error)}</span>` : ""}</span></li>`
}

function backupsCard(d: OperatorWorkspaceDetail): Html {
  const b = d.backups
  const last = b.lastDump === null ? "No dump yet." : html`The last dump is of ${b.lastDump.date}, ${b.lastDump.bytes.toLocaleString("en-GB")} bytes under root key version ${b.lastDump.rootVersion}, written ${timeTag(b.lastDump.at)}.`
  const failed = b.lastFailure !== null ? html`<div data-region="backup-failure">${notice("warn", `The dump of ${b.lastFailure.date} failed after ${count(b.lastFailure.attempts, "attempt", "attempts")}.`, cardText(b.lastFailure.error))}</div>` : ""
  return html`<section class="card" data-region="backups"><h2>Backups</h2>
    <p data-region="last-dump">${last}</p>${failed}
    <p class="small muted">Cloudflare keeps every moment of the last 30 days. The weekly pull runs from an operator's machine, off Cloudflare, and leaves no record here: its record is the operator's log.</p>
    <h3>Recent restores</h3>${b.restores.length === 0 ? html`<p class="muted" data-region="no-restores">None.</p>` : html`<ul class="rows" data-region="restores">${b.restores.map(restoreRow)}</ul>`}</section>`
}

const EVENT_WORDS: Readonly<Record<string, string>> = {
  "workspace.restore": "Restore approved and recorded for the cron",
  "workspace.freeze": "Froze it",
  "proposal.open": "Proposed a change",
  "proposal.decline": "Declined a change",
  "proposal.cancel": "Cancelled their proposal",
  "proposal.expire": "A proposal expired after 24 hours",
}

function eventRow(e: OperatorEventView): Html {
  const words = Object.hasOwn(EVENT_WORDS, e.kind) ? EVENT_WORDS[e.kind] : undefined
  const kind = typeof e.details.kind === "string" ? html` <code>${cardText(e.details.kind)}</code>` : ""
  return html`<li class="row"><span class="row-main"><span class="row-title">${words ?? html`<code>${cardText(e.kind)}</code>`}${kind}</span>
    <span class="row-sub">${timeTag(e.at)} · ${actorText(e.actor)}${e.approver !== null ? html`, approved by ${actorText(e.approver)}` : ""}</span></span></li>`
}

function eventsCard(d: OperatorWorkspaceDetail): Html {
  return html`<section class="card" data-region="events"><h2>Operator events</h2>${d.events.length === 0 ? emptyState("list", "No events yet", "Every operator change to this workspace, and every proposal for one, is recorded here.") : html`<ul class="rows">${d.events.map(eventRow)}</ul>`}</section>`
}

// The runbook's steps around a restore (docs/OPERATIONS.md, Restoring a
// workspace): the console cannot do them for the owners.
function restoreChecklist(d: OperatorWorkspaceDetail): Html {
  return html`<ol class="small" data-region="restore-checklist">
    <li><strong>Freeze it first</strong>${d.workspace.frozen === true ? " (it is frozen)" : " (Freeze below)"}, so nothing widens between the saved tail and the restore.</li>
    <li><strong>Its owners save the audit tail</strong> past the restore point: page <code>GET /api/w/${d.workspace.slug}/audit</code> back with <code>before</code> and keep the JSON. A restore rolls back revocations, removals, suspensions, freezes, approvals and rotations made since; the tail is the record of what was undone.</li>
    <li><strong>Afterwards its owners re-apply</strong> what it undid, revocations first: revoke those machines and workloads again, remove or suspend those people again, deny or revoke those approvals, and rotate again at the provider every credential rotated since. Freeze again first if the restore went back before the freeze; unfreeze once the tail is re-applied.</li>
  </ol>`
}

function restoreFolds(d: OperatorWorkspaceDetail): Html {
  const alone = d.operators < 2
  const disabled = alone ? html` disabled title="${NEEDS_SECOND_OPERATOR_WORDS.change}"` : ""
  const confirmField = html`<label class="field"><span class="label">Type <code>${d.workspace.id}</code> to confirm</span><input type="text" class="mono" data-input="confirm" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" maxlength="64" required${alone ? " disabled" : ""}></label>`
  const pitr = html`<details class="fold" data-region="restore-pitr"><summary>${icon("chevronRight")}<span>Restore to a point in time</span></summary>
      <form class="stack" data-form="restore-pitr" novalidate>
        <label class="field"><span class="label">The moment to go back to</span><input type="text" class="mono" data-input="point" maxlength="40" required autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="2026-10-31T08:15:00Z"${alone ? " disabled" : ""}><span class="hint">With Z or an offset such as +01:00, within the last 30 days. Everything after it is undone.</span></label>
        ${confirmField}
        <div class="actions"><button type="submit" class="btn danger"${disabled}>${icon("passkey")}<span>Propose with passkey</span></button></div>
      </form></details>`
  const dump = html`<details class="fold" data-region="restore-dump"><summary>${icon("chevronRight")}<span>Restore from a dump</span></summary>
      ${d.backups.dumps.length === 0
        ? html`<p class="small muted" data-region="no-dumps">No dump to restore from.</p>`
        : html`<form class="stack" data-form="restore-dump" novalidate>
        <p class="small">Only into an empty workspace object, which is what a lost workspace is; the cron refuses any other.</p>
        <label class="field"><span class="label">The day's dump</span><select data-input="date"${alone ? " disabled" : ""}>${d.backups.dumps.map((date) => html`<option value="${date}">${date}</option>`)}</select></label>
        ${confirmField}
        <div class="actions"><button type="submit" class="btn danger"${disabled}>${icon("passkey")}<span>Propose with passkey</span></button></div>
      </form>`}</details>`
  return html`${pitr}${dump}`
}

function restoreCard(d: OperatorWorkspaceDetail): Html {
  const open = d.restore
  const body = open !== null
    ? html`<div data-region="restore-open">${notice("info", html`A restore ${restoreTermsText(open.params)} waits for ${open.awaiting === "approval" ? "a second operator" : "its last step"}.`, html`Proposed ${timeTag(open.proposedAt)} by ${cardText(open.proposedBy.name)}; it expires ${timeTag(open.expiresAt)}. ${open.proposedBy.account === d.you ? "Another operator approves it, or you cancel it," : "Approve or decline it"} on <a href="/operator/operators">Operators</a>.`)}</div>`
    : d.workspace.status !== "active"
      ? html`<p class="muted">Only an active workspace is restored: one being created has nothing to restore, and a restore does not stop a deletion.</p>`
      : html`${d.operators < 2 ? html`<p class="small muted" data-region="needs-second">${NEEDS_SECOND_OPERATOR_WORDS.change} <code>bun scripts/vault-backup.ts --remote restore</code></p>` : ""}${restoreFolds(d)}`
  return html`<section class="card danger-zone" data-region="restore"><h2>Restore</h2>
    <p class="small">One operator proposes and another approves, each with a passkey. Approval records the restore, and the cron carries it out within the hour. Every operator and its owners are told.</p>
    <p class="small"><strong>Before proposing:</strong></p>${restoreChecklist(d)}
    ${body}</section>`
}

function freezeCard(d: OperatorWorkspaceDetail): Html {
  const w = d.workspace
  const body = w.status !== "active"
    ? html`<p class="muted">Only an active workspace freezes.</p>`
    : w.frozen === true
      ? html`<p data-region="frozen-already">Frozen. Only its owners unfreeze it, from its home page with a passkey.</p>`
      : w.frozen === null
        ? html`<p class="muted">Whether it is frozen could not be read just now. Reload the page to try again.</p>`
        : html`<form class="actions" data-form="freeze"><button type="submit" class="btn danger">${icon("passkey")}<span>Freeze with passkey</span></button></form>`
  return html`<section class="card danger-zone" data-region="freeze"><h2>Freeze</h2>
    <p class="small">A brake, for one operator: its own freeze, which refuses every credential use and everything that widens, while reads and narrowing carry on. Its audit records it as yours, and its owners, its admins and every operator are told. Only an owner unfreezes it; this console never does.</p>${body}</section>`
}

export function operatorWorkspacePage(account: AccountShell, d: OperatorWorkspaceDetail): PageInput {
  const w = d.workspace
  return {
    title: w.name,
    viewer: null,
    account,
    current: "operator",
    wide: true,
    boot: { page: "operator-workspace", workspace: w.id },
    body: html`${pageHead({ eyebrow: html`<a href="${OPERATOR_PATH}">Operator</a> › <a href="${OPERATOR_WORKSPACES_PATH}">Workspaces</a>`, title: cardText(w.name), lead: html`<code>${w.slug}</code> ${statusPill(w.status)}${w.frozen === true ? html` ${pill("frozen", "warn")}` : ""} ${NEVER_INSIDE}` })}
      ${operatorRequirementsNotice(d.missing)}
      <div class="two-col">
        <div class="col-main">
          ${workspaceCard(d)}
          ${peopleCard(d)}
          ${backupsCard(d)}
          ${eventsCard(d)}
        </div>
        <div class="col-side">
          ${freezeCard(d)}
          ${restoreCard(d)}
        </div>
      </div>`,
  }
}
