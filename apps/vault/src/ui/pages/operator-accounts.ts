// The Accounts view, in the Operator area: every account at this deployment,
// searched by name, id or linked Google email and filtered, a page at a
// time (/operator/accounts); and one account (/operator/accounts/:id) with
// its workspaces (the role only a hint), its passkeys and sessions as
// metadata, its events, and what an operator may do to it. Workspace
// creation and suspension are one operator's, with a passkey; recovering
// access and deleting need a second operator to approve, and until there
// is one they say so and send nothing. Only an operator reaches it; anyone
// else gets the plain not-found page.

import { ACCOUNT_BREAK_GLASS_VERIFIED_MAX, DELETED_ACCOUNT_NAME, NEEDS_SECOND_OPERATOR_WORDS, OPERATOR_ACCOUNT_FILTERS, type OperatorAccountDetail, type OperatorAccountFilter, type OperatorAccountList, type OperatorAccountSummary, type OperatorProposalView } from "@mehen/protocol"
import type { WorkspaceCreationDefault, WorkspaceCreationSource } from "@mehen/protocol/workspace"
import { cardText, emptyState, kv, notice, pageHead, pill, responsiveTable, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon, iconTile } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import type { AccountShell } from "../shell.ts"
import { OPERATOR_PATH, operatorRequirementsNotice } from "./operator.ts"
import { PROPOSAL_KIND_WORDS } from "./operator-operators.ts"
import { actorText, readFailed } from "./platform-console.ts"

export const ACCOUNTS_PATH = "/operator/accounts"

export function operatorAccountPath(account: string): string {
  return `${ACCOUNTS_PATH}/${encodeURIComponent(account)}`
}

const FILTER_WORDS: Readonly<Record<OperatorAccountFilter, string>> = { all: "All", suspended: "Suspended", "cooling-off": "Cooling off", "no-recovery": "No recovery", "no-workspace": "No workspace", operators: "Operators" }

const CREATION_WORDS: Readonly<Record<WorkspaceCreationSource, string>> = { default: "default", "operator-allowed": "allowed", "operator-denied": "denied" }

function defaultWords(rule: WorkspaceCreationDefault): string {
  return rule === "accounts" ? "every account may create workspaces" : "only accounts an operator allows may create workspaces"
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`
}

// The pills a row and the page head show: operator, deleted, suspended,
// cooling off, transition pending, no recovery.
function accountPills(a: OperatorAccountSummary): Html {
  return html`${a.operator ? pill("operator", "accent") : ""}${a.status !== "active" ? pill(a.status, "muted") : ""}${a.suspendedAt !== null ? pill("suspended", "danger") : ""}${a.coolingOff !== null ? pill(a.coolingOff.until !== null ? `cooling off until ${a.coolingOff.until.slice(11, 16)} UTC` : "cooling off", "warn") : ""}${a.transitionPending ? pill("transition pending", "warn") : ""}${a.status === "active" && a.recovery === null ? pill("no recovery", "warn") : ""}`
}

function passkeyWords(p: OperatorAccountSummary["passkeys"]): string {
  const extras = [p.synced > 0 ? `${p.synced} synced` : "", p.securityKeys > 0 ? plural(p.securityKeys, "security key", "security keys") : ""].filter((x) => x !== "")
  return `${plural(p.count, "passkey", "passkeys")}${extras.length > 0 ? ` (${extras.join(", ")})` : ""}`
}

function summaryLine(a: OperatorAccountSummary): Html {
  return html`${plural(a.workspaces, "workspace", "workspaces")} · ${passkeyWords(a.passkeys)} · recovery: ${a.recovery ?? "none"} · creates: ${CREATION_WORDS[a.workspaceCreation]}`
}

function accountRow(a: OperatorAccountSummary): Html {
  return html`<li class="row" data-account="${a.account}">${iconTile("users")}<a class="row-main" href="${operatorAccountPath(a.account)}">
      <span class="row-title">${cardText(a.name)} <code>${a.account}</code> ${accountPills(a)}</span>
      <span class="row-sub">${a.email !== null ? html`${cardText(a.email)} · ` : ""}${summaryLine(a)}</span>
    </a><span class="row-data small muted"><span>${a.lastSeenAt !== null ? html`last seen ${timeTag(a.lastSeenAt)}` : "not seen"}</span></span></li>`
}

function listHref(q: string, filter: OperatorAccountFilter, before?: string): string {
  const params = new URLSearchParams()
  if (q !== "") params.set("q", q)
  if (filter !== "all") params.set("filter", filter)
  if (before !== undefined) params.set("before", before)
  const query = params.toString()
  return query === "" ? ACCOUNTS_PATH : `${ACCOUNTS_PATH}?${query}`
}

export type OperatorAccountsPageData = { list: OperatorAccountList | null; q: string; filter: OperatorAccountFilter }

export function operatorAccountsPage(account: AccountShell, data: OperatorAccountsPageData): PageInput {
  const { list, q, filter } = data
  const head = pageHead({ eyebrow: html`<a href="${OPERATOR_PATH}">Operator</a>`, title: "Accounts", lead: "Every account at this vault. Open one to see its workspaces, passkeys, sessions and events, and to change its workspace creation, suspend it, recover its access or delete it. Nothing here opens a workspace." })
  const search = html`<form class="stack" method="get" action="${ACCOUNTS_PATH}" data-form="account-search" role="search">
      <label class="field"><span class="label">Search name, email or acc_ id</span><input type="search" name="q" value="${q}" maxlength="254" autocomplete="off" autocapitalize="off" spellcheck="false"></label>
      ${filter !== "all" ? html`<input type="hidden" name="filter" value="${filter}">` : ""}
      <div class="actions"><button type="submit" class="btn secondary">${icon("search")}<span>Search</span></button></div>
    </form>
    <nav class="chips" data-region="filters" aria-label="Filter the accounts">${OPERATOR_ACCOUNT_FILTERS.map((f) => html`<a class="chip" href="${listHref(q, f)}"${f === filter ? html` aria-current="page"` : ""}>${FILTER_WORDS[f]}</a>`)}</nav>`
  const body = list === null
    ? readFailed("The accounts")
    : list.accounts.length === 0
      ? emptyState("users", "No accounts match", q !== "" || filter !== "all" ? "Try another search or filter." : "Accounts appear here once people sign up.")
      : html`<ul class="rows" data-region="accounts">${list.accounts.map(accountRow)}</ul>${list.next !== null ? html`<p class="small"><a href="${listHref(q, filter, list.next)}" data-region="next-page">Older accounts</a></p>` : ""}`
  return {
    title: "Accounts",
    viewer: null,
    account,
    current: "operator",
    wide: true,
    boot: { page: "operator-accounts" },
    body: html`${head}
      ${list !== null ? operatorRequirementsNotice(list.missing) : ""}
      <section class="card" data-region="account-search-card">${search}</section>
      <section class="card">${body}</section>
      ${list !== null ? html`<p class="small muted" data-region="workspace-creation">The deployment default: ${defaultWords(list.workspaceCreation)}.</p>` : ""}`,
  }
}

// ---------------------------------------------------------------- one account

function accountCard(d: OperatorAccountDetail): Html {
  const a = d.account
  const rows: [Html | string, Html | string][] = [
    ["Account id", html`<code>${a.account}</code>`],
    ["Status", d.deletedAt !== null ? html`deleted ${timeTag(d.deletedAt)}` : a.status],
    ["Google sign-in", d.emails.length === 0 ? "none linked" : html`${d.emails.map((e, i) => html`${i > 0 ? ", " : ""}${cardText(e)}`)}`],
    ["Created", timeTag(a.createdAt)],
    ["Last seen", a.lastSeenAt !== null ? timeTag(a.lastSeenAt) : "never"],
    ["Recovery", a.recovery === null ? "not set up" : a.recovery === "codes" ? "recovery codes" : "a second passkey"],
  ]
  if (a.suspendedAt !== null) rows.push(["Suspended", timeTag(a.suspendedAt)])
  if (a.coolingOff !== null) rows.push(["Cooling off", a.coolingOff.until !== null ? html`after ${a.coolingOff.reason}, until ${timeTag(a.coolingOff.until)}` : html`after ${a.coolingOff.reason}, until it completes`])
  if (a.transitionPending) rows.push(["Security change", "still reaching their workspaces"])
  return html`<section class="card" data-region="account"><h2>The account</h2>${kv(rows, "facts")}</section>`
}

function workspacesCard(d: OperatorAccountDetail): Html {
  const body = d.workspaces.length === 0
    ? html`<p class="muted">In no workspace.</p>`
    : responsiveTable(["Workspace", "Role (a hint)", "State", "Since"], d.workspaces.map((w) => [html`${cardText(w.name)} <code>${w.slug}</code>`, w.roleHint, w.state, timeTag(w.since)]))
  return html`<section class="card" data-region="workspaces"><h2>Workspaces</h2><p class="small muted">The role is the directory's hint; each workspace holds its members' roles itself.</p>${body}</section>`
}

function passkeysCard(d: OperatorAccountDetail): Html {
  const body = d.passkeys.length === 0
    ? html`<p class="muted">No passkeys.</p>`
    : responsiveTable(["Name", "Kind", "Synced", "Added", "Last used"], d.passkeys.map((p) => [p.name !== null ? cardText(p.name) : html`<span class="muted">unnamed</span>`, p.authenticator, p.synced === null ? "unknown" : p.synced ? "yes" : "no", html`${timeTag(p.createdAt)} (${p.addedVia})`, p.lastUsedAt !== null ? timeTag(p.lastUsedAt) : "never"]))
  return html`<section class="card" data-region="passkeys"><h2>Passkeys</h2>${body}</section>`
}

function sessionsCard(d: OperatorAccountDetail): Html {
  const s = d.sessions
  return html`<section class="card" data-region="sessions"><h2>Sessions</h2>${kv([["In a browser", String(s.web)], ["In the app", String(s.app)], ["Recovering", String(s.recovery)], ["Last seen", s.lastSeenAt !== null ? timeTag(s.lastSeenAt) : "never"]], "small")}
    <p class="small muted">Sessions and passkeys belong to the account: an operator cannot end one. Suspending ends them all.</p></section>`
}

function accountEventsCard(d: OperatorAccountDetail): Html {
  const body = d.events.length === 0
    ? emptyState("list", "No events yet", "What the account and the operators do to it is recorded here.")
    : html`<ul class="rows" data-region="account-events">${d.events.map((e) => html`<li class="row"><span class="row-main"><span class="row-title"><code>${cardText(e.action)}</code></span><span class="row-sub">${timeTag(e.at)}${typeof e.detail.by === "string" ? html` · ${actorText(e.detail.by)}` : ""}</span></span></li>`)}</ul>`
  return html`<section class="card" data-region="events-card"><h2>Events</h2>${body}</section>`
}

function self(d: OperatorAccountDetail): boolean {
  return d.account.account === d.you
}

// Why no operator may change this account here, or null when one may.
function closedReason(d: OperatorAccountDetail): string | null {
  if (d.account.status !== "active") return "This account is deleted; nothing more can change."
  if (self(d)) return "This is your own account; another operator changes it."
  return null
}

function proposeButton(kind: string, label: string, opts: { creation?: string; disabled?: string; tone?: string }): Html {
  return html`<button type="button" class="btn ${opts.tone ?? "secondary"} sm" data-action="account-propose" data-kind="${kind}"${opts.creation !== undefined ? html` data-creation="${opts.creation}"` : ""}${opts.disabled !== undefined ? html` disabled title="${opts.disabled}"` : ""}>${icon("passkey")}<span>${label}</span></button>`
}

function creationCard(d: OperatorAccountDetail, closed: string | null): Html {
  const source = d.account.workspaceCreation
  const current = { allow: "operator-allowed", deny: "operator-denied", default: "default" } as const
  const buttons = closed !== null
    ? html`<p class="small muted">${closed}</p>`
    : html`<div class="actions">${proposeButton("account.workspace_creation", "Allow", { creation: "allow", ...(source === current.allow ? { disabled: "Allowed already." } : {}) })}${proposeButton("account.workspace_creation", "Deny", { creation: "deny", ...(source === current.deny ? { disabled: "Denied already." } : {}) })}${proposeButton("account.workspace_creation", "Back to default", { creation: "default", ...(source === current.default ? { disabled: "It follows the default already." } : {}) })}</div>`
  return html`<section class="card" data-region="workspace-creation"><h2>Workspace creation</h2>
    <p>${source === "default" ? html`The deployment default: ${defaultWords(d.workspaceCreationDefault)}.` : source === "operator-allowed" ? "Allowed by an operator." : "Denied by an operator."}</p>
    ${buttons}<p class="small muted">One operator, with a passkey. The account is told.</p></section>`
}

function suspensionCard(d: OperatorAccountDetail, closed: string | null): Html {
  const a = d.account
  const why = closed ?? (a.operator && a.suspendedAt === null ? "An operator is never suspended; end their operator role on Operators first." : null)
  const control = why !== null
    ? html`<p class="small muted">${why}</p>`
    : a.suspendedAt !== null
      ? html`<p>Suspended ${timeTag(a.suspendedAt)}. They cannot sign in until it is lifted.</p><div class="actions">${proposeButton("account.lift_suspension", "Lift with passkey", {})}</div>`
      : html`<p class="small">Ends every session at once and stops sign-in. Their machines keep their scope in each workspace, whose owners and admins are told so they can revoke them.</p><div class="actions">${proposeButton("account.suspend", "Suspend with passkey", { tone: "danger" })}</div>`
  return html`<section class="card" data-region="suspension"><h2>Suspension</h2>${control}<p class="small muted">One operator, with a passkey. Every operator and the account are told.</p></section>`
}

function breakGlassState(d: OperatorAccountDetail): Html {
  const b = d.breakGlass
  if (b === null) return html``
  if (b.state === "pending") return html`<div data-region="break-glass-state">${notice("info", "Recovering access is under way", html`Every workspace is ending their old sessions and passkeys. The link is ready within minutes and expires ${timeTag(b.expiresAt)}.`)}</div>`
  if (!b.yours) return html`<div data-region="break-glass-state">${notice("info", "The recovery link is ready", html`Only ${actorText(b.proposedBy)}, who checked who the person is, takes it. It expires ${timeTag(b.expiresAt)}.`)}</div>`
  if (b.linkTaken) return html`<div data-region="break-glass-state">${notice("info", "You took the recovery link", html`It is not shown again. It works once, until ${timeTag(b.expiresAt)}.`)}</div>`
  return html`<div data-region="break-glass-state">${notice("ok", "The recovery link is ready", html`Shown once, to you only. Give it privately to the person you verified; it works once, until ${timeTag(b.expiresAt)}.`, html`<button type="button" class="btn primary sm" data-action="break-glass-link" data-intent="${b.intent}">${icon("passkey")}<span>Show the link with passkey</span></button>`)}</div>
    <section class="card" data-region="break-glass-link" hidden><h2>The recovery link</h2><p class="small">Copy it now: it is not shown again.</p><div class="copybox"><code data-region="link"></code><button type="button" class="btn secondary sm" data-copy>${icon("copy")}<span>Copy</span></button></div></section>`
}

function dangerZone(d: OperatorAccountDetail, closed: string | null): Html {
  const a = d.account
  const alone = d.operators < 2
  const twoOps = alone ? html`<p class="small muted" data-region="needs-second">${NEEDS_SECOND_OPERATOR_WORDS.change}</p>` : ""
  const disabled = alone ? html` disabled title="${NEEDS_SECOND_OPERATOR_WORDS.change}"` : ""
  if (closed !== null) return html`<section class="card danger-zone" data-region="danger-zone"><h2>Danger zone</h2><p class="small muted">${closed}</p></section>`
  const recoverWhy = a.operator
    ? "An operator's access is never recovered here. End their operator role first, or use the script."
    : a.suspendedAt !== null
      ? "Lift the suspension before recovering their access."
      : d.breakGlass !== null ? "A recovery link is already on its way." : null
  const recover = recoverWhy !== null
    ? html`<p class="small muted">${recoverWhy}</p>`
    : html`<form class="stack" data-form="break-glass" novalidate>
          <p class="small">For someone who has lost every passkey and recovery code. Their sessions, passkeys and codes end; you then take a single-use link, once, and give it to them. They add a new passkey and cool off for 24 hours. Another operator approves first.</p>
          <label class="field"><span class="label">How you checked, out of band, that the person asking holds this account</span><textarea data-input="verified" rows="3" maxlength="${ACCOUNT_BREAK_GLASS_VERIFIED_MAX}" required${alone ? " disabled" : ""}></textarea><span class="hint">Kept in the proposal's events, for every operator to read.</span></label>
          ${twoOps}
          <div class="actions"><button type="submit" class="btn danger"${disabled}>${icon("passkey")}<span>Propose with passkey</span></button></div>
        </form>`
  const live = d.workspaces.filter((w) => w.state !== "left")
  const remove = a.operator
    ? html`<p class="small muted">An operator's account is never deleted; end their operator role first.</p>`
    : live.length > 0
      ? html`<div data-region="delete-blocked"><p class="small">Only an account in no workspace is deleted. Each of these workspaces' owners removes them first:</p><ul class="small">${live.map((w) => html`<li>${cardText(w.name)} <code>${w.slug}</code></li>`)}</ul></div>`
      : html`<form class="stack" data-form="delete-account" novalidate>
          <p class="small">Its name becomes "${DELETED_ACCOUNT_NAME}", and its passkeys, sessions, recovery codes and linked Google sign-ins are deleted. Its events stay. It cannot be undone. Another operator approves first.</p>
          <label class="field"><span class="label">Type <strong>${cardText(a.name)}</strong> to confirm</span><input type="text" data-input="confirm-name" maxlength="64" required autocomplete="off"${alone ? " disabled" : ""}></label>
          ${twoOps}
          <div class="actions"><button type="submit" class="btn danger"${disabled}>${icon("passkey")}<span>Propose deleting with passkey</span></button></div>
        </form>`
  return html`<section class="card danger-zone" data-region="danger-zone"><h2>Danger zone</h2>
    <details class="fold" data-region="recover"><summary>${icon("chevronRight")}<span>Recover access</span></summary>${recover}</details>
    <details class="fold" data-region="delete"><summary>${icon("chevronRight")}<span>Delete account</span></summary>${remove}</details></section>`
}

function openProposals(d: OperatorAccountDetail): Html {
  if (d.open.length === 0) return html``
  return html`<section class="card" data-region="open-proposals"><h2>Waiting for a second operator</h2><ul class="rows">${d.open.map((p: OperatorProposalView) => html`<li class="row" data-proposal="${p.id}"><span class="row-main"><span class="row-title">${PROPOSAL_KIND_WORDS[p.kind]}</span><span class="row-sub">Proposed ${timeTag(p.proposedAt)} by ${cardText(p.proposedBy.name)} · expires ${timeTag(p.expiresAt)}</span></span></li>`)}</ul>
    <p class="small"><a href="/operator/operators">Approve, decline or cancel it on Operators</a></p></section>`
}

// `detail` is null when it could not be read.
export function operatorAccountPage(account: AccountShell, detail: OperatorAccountDetail | null): PageInput {
  const eyebrow = html`<a href="${OPERATOR_PATH}">Operator</a> › <a href="${ACCOUNTS_PATH}">Accounts</a>`
  if (detail === null) return { title: "Account", viewer: null, account, current: "operator", boot: { page: "operator-account" }, body: html`${pageHead({ eyebrow, title: "Account" })}<section class="card">${readFailed("The account")}</section>` }
  const a = detail.account
  const closed = closedReason(detail)
  return {
    title: a.name,
    viewer: null,
    account,
    current: "operator",
    wide: true,
    boot: { page: "operator-account", account: a.account, name: a.name },
    body: html`${pageHead({ eyebrow, title: cardText(a.name), lead: html`<code>${a.account}</code> ${accountPills(a)}` })}
      ${operatorRequirementsNotice(detail.missing)}
      ${breakGlassState(detail)}
      <div class="two-col">
        <div class="col-main">
          ${accountCard(detail)}
          ${workspacesCard(detail)}
          ${passkeysCard(detail)}
          ${sessionsCard(detail)}
          ${accountEventsCard(detail)}
        </div>
        <div class="col-side">
          ${openProposals(detail)}
          ${creationCard(detail, closed)}
          ${suspensionCard(detail, closed)}
          ${dangerZone(detail, closed)}
        </div>
      </div>`,
  }
}
