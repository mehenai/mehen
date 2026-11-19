// The Audit view (/operator/audit), in the Operator area: one read-only
// list, newest first, of every operator and deployment change the database
// records (deployment_events, platform_events and the operator.* rows of
// account_events), with filters on actor, action, target and a range of
// days, a page at a time. A proposal's row says its outcome and who
// proposed, approved or declined it. The page says plainly that this is a
// D1 record, not a hash chain. The filters are a plain GET form: the page
// needs no script. Only an operator reaches it; anyone else gets the plain
// not-found page.

import { OPERATOR_AUDIT_FILTER_MAX, OPERATOR_AUDIT_RECORD_WORDS, type OperatorAuditEvent, type OperatorAuditPage, type OperatorAuditProposal, type OperatorAuditQuery, type OperatorAuditSource, operatorAuditSearch } from "@mehen/protocol/operator-audit"
import { cardText, emptyState, notice, pageHead, pill, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import type { AccountShell } from "../shell.ts"
import { OPERATOR_PATH } from "./operator.ts"
import { actorText, detailFacts, readFailed } from "./platform-console.ts"

export const AUDIT_PATH = "/operator/audit"

const SOURCE_WORDS: Readonly<Record<OperatorAuditSource, string>> = { deployment: "deployment", platform: "platform", account: "account" }

const STATE_TONE: Readonly<Record<OperatorAuditProposal["state"], "ok" | "warn" | "muted">> = { open: "warn", applied: "ok", declined: "muted", expired: "muted", cancelled: "muted" }

function named(actor: string, name: string | null): Html {
  return html`${name !== null ? html`${cardText(name)} ` : ""}${actorText(actor)}`
}

function proposalLine(p: OperatorAuditProposal): Html {
  const by = (ref: { account: string; name: string }) => html`${cardText(ref.name)} <code>${ref.account}</code>`
  return html`<span class="row-sub" data-region="proposal">Proposal <code>${p.id}</code> (<code>${cardText(p.kind)}</code>) ${pill(p.state, STATE_TONE[p.state])} proposed by ${by(p.proposedBy)}${p.approvedBy !== null ? html`, approved by ${by(p.approvedBy)}` : ""}${p.declinedBy !== null ? html`, declined by ${by(p.declinedBy)}` : ""}</span>`
}

// The detail's plain fields, without what the row already says.
function rowDetails(e: OperatorAuditEvent): Html {
  const params = e.details.params
  const value = typeof params === "object" && params !== null ? (params as Record<string, unknown>).value : undefined
  const rest = Object.fromEntries(Object.entries(e.details).filter(([key]) => key !== "proposal" && key !== "kind" && key !== "params"))
  return detailFacts(value !== undefined ? { ...rest, value } : rest)
}

function eventRow(e: OperatorAuditEvent): Html {
  return html`<li class="row" data-event="${e.id}"><span class="row-main">
      <span class="row-title"><code>${cardText(e.action)}</code> ${e.targetName !== null ? html`${cardText(e.targetName)} ` : ""}<code>${cardText(e.target)}</code> ${pill(SOURCE_WORDS[e.source], "muted", false)}</span>
      <span class="row-sub">${timeTag(e.at)} · ${named(e.actor, e.actorName)}${e.approver !== null ? html`, approved by ${named(e.approver, e.approverName)}` : ""}</span>
      ${e.proposal !== null ? proposalLine(e.proposal) : ""}
      ${rowDetails(e)}
    </span></li>`
}

function filterField(name: "actor" | "action" | "target", label: string, hint: string, value: string | undefined): Html {
  return html`<label class="field"><span class="label">${label}</span><input type="text" name="${name}" class="mono" maxlength="${OPERATOR_AUDIT_FILTER_MAX}" value="${value ?? ""}" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="${hint}"></label>`
}

function filters(query: OperatorAuditQuery): Html {
  return html`<section class="card" data-region="audit-filters"><h2>Filters</h2>
    <form class="stack" method="get" action="${AUDIT_PATH}" data-form="audit-filters">
      ${filterField("actor", "Actor", "operator:acc_... or a part of one", query.actor)}
      ${filterField("action", "Action", "platform.suspend, proposal. ...", query.action)}
      ${filterField("target", "Target", "acc_..., a platform slug or a setting", query.target)}
      <label class="field"><span class="label">From (UTC day)</span><input type="date" name="from" value="${query.from ?? ""}"></label>
      <label class="field"><span class="label">To (UTC day, included)</span><input type="date" name="to" value="${query.to ?? ""}"></label>
      <div class="actions"><button type="submit" class="btn primary">${icon("search")}<span>Filter</span></button><a class="btn secondary" href="${AUDIT_PATH}">Clear</a></div>
    </form></section>`
}

// `page` is null when it could not be read, and `query` null when the
// address's filters are not the view's (then nothing is read).
export function operatorAuditPage(account: AccountShell, input: { page: OperatorAuditPage | null; query: OperatorAuditQuery | null }): PageInput {
  const query = input.query ?? {}
  const older = input.page !== null && input.page.next !== null ? `${AUDIT_PATH}${operatorAuditSearch(query, input.page.next)}` : null
  const list = input.query === null
    ? notice("warn", "Those filters are not ones this view takes.", "Actor, action and target are up to 128 characters; from and to are days. Clear them and try again.")
    : input.page === null
      ? readFailed("The audit list")
      : input.page.events.length === 0
        ? emptyState("list", "Nothing recorded matches", "Every operator change, proposal, platform change and operator script flag is recorded here.")
        : html`<ul class="rows" data-region="audit-events">${input.page.events.map(eventRow)}</ul>`
  return {
    title: "Audit",
    viewer: null,
    account,
    current: "operator",
    wide: true,
    boot: { page: "operator-audit" },
    body: html`${pageHead({ eyebrow: html`<a href="${OPERATOR_PATH}">Operator</a>`, title: "Audit", lead: "Every operator change, proposal and platform change, and the operator script's flags on accounts, newest first. Read only." })}
      <div data-region="audit-record">${notice("info", "A database record, not a hash chain", OPERATOR_AUDIT_RECORD_WORDS)}</div>
      <div class="two-col">
        <div class="col-main"><section class="card" data-region="audit-list"><h2>Events</h2>${list}${older !== null ? html`<p class="small"><a href="${older}" data-region="older">Older events</a></p>` : ""}</section></div>
        <div class="col-side">${filters(query)}</div>
      </div>`,
  }
}
