// The Operators view (/operator/operators), in the Operator area: every
// operator with their passkeys, recovery and last sign-in; the open
// proposals, with Approve and Decline for the other operators and Cancel
// for the one who proposed; granting the role to an account found by its
// id or a Google sign-in email; revoking another operator's role;
// resigning your own; the recent proposals and the operator events. A
// change to the role needs a second operator (Resigning needs only you),
// and until there are two the forms say so and send nothing. Only an
// operator reaches it; anyone else gets the plain not-found page.

import { NEEDS_SECOND_OPERATOR_WORDS, type OperatorEventView, type OperatorProposalKind, type OperatorProposalView, type OperatorView, type OperatorsView } from "@mehen/protocol/operator-proposals"
import { operatorRequirementsRefusal } from "@mehen/protocol/platform-console"
import { cardText, emptyState, notice, pageHead, pill, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon, iconTile } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import type { AccountShell } from "../shell.ts"
import { operatorRequirementsNotice } from "./operator.ts"
import { operatorWorkspacePath, restoreTermsText } from "./operator-workspaces.ts"
import { actorText, readFailed } from "./platform-console.ts"

export const OPERATORS_PATH = "/operator/operators"

export const PROPOSAL_KIND_WORDS: Readonly<Record<OperatorProposalKind, string>> = {
  "operator.grant": "Make an operator",
  "operator.revoke": "End an operator's role",
  "operator.resign": "Resign as an operator",
  "workspace.restore": "Restore a workspace",
  "workspace.freeze": "Freeze a workspace",
  "account.workspace_creation": "Set workspace creation",
  "account.suspend": "Suspend an account",
  "account.lift_suspension": "Lift a suspension",
  "account.break_glass": "Recover access to an account",
  "account.delete": "Delete an account",
  "settings.narrow": "Narrow a setting",
  "settings.widen": "Widen a setting",
}

const EVENT_WORDS: Readonly<Record<string, string>> = {
  "operator.grant": "Made an operator",
  "operator.revoke": "Ended an operator's role",
  "operator.resign": "Resigned as an operator",
  "workspace.restore": "Approved a workspace restore",
  "workspace.freeze": "Froze a workspace",
  "account.workspace_creation": "Set an account's workspace creation",
  "account.suspend": "Suspended an account",
  "account.lift_suspension": "Lifted an account's suspension",
  "account.break_glass": "Began recovering access to an account",
  "account.break_glass_link": "Took an account's recovery link",
  "account.delete": "Deleted an account",
  "settings.narrow": "Narrowed a setting",
  "settings.widen": "Widened a setting",
  "settings.set": "Set a setting with the script",
  "proposal.open": "Proposed a change",
  "proposal.approve": "Approved a change, waiting for its target to accept",
  "proposal.decline": "Declined a change",
  "proposal.cancel": "Cancelled their proposal",
  "proposal.expire": "A proposal expired after 24 hours",
}

function needsTwo(view: OperatorsView): boolean {
  return view.operators.length < 2
}

function passkeyWords(o: OperatorView): string {
  const keys = o.securityKeys === 1 ? "1 security key" : `${o.securityKeys} security keys`
  return `${o.passkeys === 1 ? "1 passkey" : `${o.passkeys} passkeys`}, ${keys}`
}

function operatorRow(view: OperatorsView, o: OperatorView): Html {
  const you = o.account === view.you
  const alone = needsTwo(view)
  const side = you
    ? html`<button type="button" class="btn danger-quiet sm" data-action="propose" data-kind="operator.resign" data-target="${o.account}" data-name="${o.name}"${alone ? html` disabled title="${NEEDS_SECOND_OPERATOR_WORDS.resign}"` : ""}>${icon("passkey")}<span>Resign</span></button>`
    : html`<button type="button" class="btn danger-quiet sm" data-action="propose" data-kind="operator.revoke" data-target="${o.account}" data-name="${o.name}"${alone ? html` disabled title="${NEEDS_SECOND_OPERATOR_WORDS.change}"` : ""}>${icon("passkey")}<span>Revoke</span></button>`
  return html`<li class="row" data-operator="${o.account}">${iconTile("shield")}<span class="row-main">
      <span class="row-title">${cardText(o.name)}${you ? " (you)" : ""} ${o.missing.length === 0 ? pill("ready", "ok") : pill("missing something", "warn")}</span>
      <span class="row-sub"><code>${o.account}</code>${o.since !== null ? html` · operator since ${timeTag(o.since)}` : ""}${o.grantedBy !== null ? html` by ${actorText(o.grantedBy)}` : ""}</span>
      <span class="row-sub">${passkeyWords(o)} · recovery ${o.recoveryReady ? "ready" : "not set up"} · ${o.lastSeenAt !== null ? html`last seen ${timeTag(o.lastSeenAt)}` : "not seen yet"}</span>
      ${o.missing.length > 0 ? html`<span class="row-sub" data-region="missing">${operatorRequirementsRefusal(o.missing, you ? "Your account" : `${o.name}'s account`)}</span>` : ""}
    </span><span class="row-side">${side}</span></li>`
}

function accountRef(ref: { account: string; name: string }): Html {
  return html`${cardText(ref.name)} <code>${ref.account}</code>`
}

function proposalTitle(p: OperatorProposalView): Html {
  const target = html`${p.targetName !== null ? cardText(p.targetName) : ""} <code>${p.target}</code>`
  return html`${PROPOSAL_KIND_WORDS[p.kind]}: ${p.kind.startsWith("workspace.") ? html`<a href="${operatorWorkspacePath(p.target)}">${target}</a> ${restoreTermsText(p.params)}` : target}`
}

// What the reader can do with an open proposal, or whose move it waits for.
function proposalActions(view: OperatorsView, p: OperatorProposalView): Html {
  const yours = p.proposedBy.account === view.you
  const aboutYou = p.target === view.you
  const decline = html`<button type="button" class="btn secondary sm" data-action="decline" data-proposal="${p.id}">${icon("x")}<span>Decline</span></button>`
  if (yours) return html`<span class="small muted">${p.awaiting === "acceptance" ? "Approved; waits for its target to accept." : "Waits for another operator."}</span><button type="button" class="btn secondary sm" data-action="cancel" data-proposal="${p.id}">${icon("x")}<span>Cancel</span></button>`
  if (aboutYou) return html`<span class="small muted">About you, so another operator decides.</span>${decline}`
  if (p.awaiting === "acceptance") return html`<span class="small muted">Approved by ${accountRef(p.approvedBy ?? { account: "", name: "" })}; waits for ${p.targetName !== null ? cardText(p.targetName) : "its target"} to accept with their own passkey.</span>${decline}`
  return html`<button type="button" class="btn primary sm" data-action="approve" data-proposal="${p.id}" data-digest="${p.digest}">${icon("passkey")}<span>Approve with passkey</span></button>${decline}`
}

function openRow(view: OperatorsView, p: OperatorProposalView): Html {
  return html`<li class="row" data-proposal="${p.id}"><span class="row-main">
      <span class="row-title">${proposalTitle(p)}</span>
      <span class="row-sub">Proposed ${timeTag(p.proposedAt)} by ${accountRef(p.proposedBy)} · expires ${timeTag(p.expiresAt)}</span>
      <span class="row-sub small muted">Digest <code>${p.digest}</code></span>
    </span><span class="row-side actions">${proposalActions(view, p)}</span></li>`
}

const STATE_WORDS: Readonly<Record<OperatorProposalView["state"], string>> = { open: "open", applied: "applied", declined: "declined", expired: "expired", cancelled: "cancelled" }

function recentRow(p: OperatorProposalView): Html {
  const by = p.state === "declined" && p.declinedBy !== null ? html` by ${accountRef(p.declinedBy)}` : p.state === "applied" && p.approvedBy !== null ? html`, approved by ${accountRef(p.approvedBy)}` : ""
  return html`<li class="row" data-proposal="${p.id}"><span class="row-main"><span class="row-title">${proposalTitle(p)} ${pill(STATE_WORDS[p.state], p.state === "applied" ? "ok" : "muted")}</span>
    <span class="row-sub">Proposed ${timeTag(p.proposedAt)} by ${accountRef(p.proposedBy)}${p.closedAt !== null ? html` · ${STATE_WORDS[p.state]} ${timeTag(p.closedAt)}` : ""}${by}</span></span></li>`
}

function eventRow(e: OperatorEventView): Html {
  const words = Object.hasOwn(EVENT_WORDS, e.kind) ? EVENT_WORDS[e.kind] : undefined
  return html`<li class="row"><span class="row-main"><span class="row-title">${words ?? html`<code>${cardText(e.kind)}</code>`} <code>${cardText(e.target)}</code></span>
    <span class="row-sub">${timeTag(e.at)} · ${actorText(e.actor)}${e.approver !== null ? html`, approved by ${actorText(e.approver)}` : ""}</span></span></li>`
}

function grantCard(view: OperatorsView): Html {
  const alone = needsTwo(view)
  return html`<section class="card" data-region="grant"><h2>Make an operator</h2>
    <p class="small">You propose; another operator approves within 24 hours; then they accept on Your account with their own passkey. Until they accept they are not an operator.</p>
    ${alone ? html`<p class="small muted" data-region="needs-second">${NEEDS_SECOND_OPERATOR_WORDS.change}</p>` : ""}
    <form class="stack" data-form="grant" novalidate>
      <label class="field"><span class="label">Their account id or Google sign-in email</span><input type="text" class="mono" data-input="account" maxlength="254" required autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="acc_... or name@example.com"${alone ? " disabled" : ""}><span class="hint">They find their account id on Your account. Their account needs recovery set up and two passkeys, one of them a security key.</span></label>
      <div class="actions"><button type="submit" class="btn secondary"${alone ? html` disabled title="${NEEDS_SECOND_OPERATOR_WORDS.change}"` : ""}>${icon("passkey")}<span>Propose with passkey</span></button></div>
    </form></section>`
}

// `view` is null when it could not be read.
export function operatorsPage(account: AccountShell, view: OperatorsView | null): PageInput {
  const head = pageHead({ eyebrow: html`<a href="/operator">Operator</a>`, title: "Operators", lead: "Who can run this vault, and every change to that. A change to the operator role needs a second operator to approve it, and every one is recorded below." })
  if (view === null) return { title: "Operators", viewer: null, account, current: "operator", boot: { page: "operator-operators" }, body: html`${head}<section class="card">${readFailed("The operators")}</section>` }
  const you = view.operators.find((o) => o.account === view.you)
  return {
    title: "Operators",
    viewer: null,
    account,
    current: "operator",
    wide: true,
    boot: { page: "operator-operators" },
    body: html`${head}
      ${you !== undefined ? operatorRequirementsNotice(you.missing) : ""}
      ${needsTwo(view) ? html`<div data-region="needs-second-operator">${notice("info", "You are the only operator", html`${NEEDS_SECOND_OPERATOR_WORDS.change} Add the first extra operators with <code>scripts/operator.ts grant-operator</code>; after that, everything happens here.`)}</div>` : ""}
      <div class="two-col">
        <div class="col-main">
          <section class="card" data-region="operators"><h2>Operators</h2><ul class="rows">${view.operators.map((o) => operatorRow(view, o))}</ul></section>
          <section class="card" data-region="open-proposals"><h2>Open proposals</h2>${view.open.length === 0 ? emptyState("users", "Nothing waiting", "A proposal waits here for a second operator for 24 hours, then expires.") : html`<ul class="rows">${view.open.map((p) => openRow(view, p))}</ul>`}</section>
          <section class="card" data-region="operator-events"><h2>Operator events</h2>${view.events.length === 0 ? emptyState("list", "No events yet", "Every change to the operator role, here or by the scripts, is recorded here.") : html`<ul class="rows">${view.events.map(eventRow)}</ul>`}</section>
        </div>
        <div class="col-side">
          ${grantCard(view)}
          <section class="card" data-region="recent-proposals"><h2>Recent proposals</h2>${view.recent.length === 0 ? html`<p class="muted">None yet.</p>` : html`<ul class="rows">${view.recent.map(recentRow)}</ul>`}</section>
          <p class="small muted">The scripts (<code>scripts/operator.ts</code>) are the break-glass for when the app is down or every operator is locked out. Whoever can write the database or deploy the Worker can bypass all of this.</p>
        </div>
      </div>`,
  }
}
