// The "Allowed without asking" card on a credential's page and a machine's
// page, shown only with POLICY_RULES on and only when the vault lists a
// live rule (GET /policy/rules?item= or ?device=): each standing rule as
// the vault returns it, with Stop (no passkey: it only narrows) and Extend
// (one passkey), which client/pages/policy-rules.ts wires. A rule the viewer
// may stop but not read (PolicyRuleStopped, from a revoke) is drawn by
// policy-rules-row.ts stoppedOnlyRow: its id and status, never a term, as
// the page draws it in place. Also the compact line
// those pages show while rules let the viewer's own machines' requests
// through without asking.

import { POLICY_RULES_ENDED_LISTED, RULE_DEFAULT_DURATION, RULE_DURATIONS, type PolicyAreaGrantView, type PolicyRuleView } from "@mehen/protocol/policy-mode"
import { policyCatalogueNamed } from "@mehen/protocol/policy-catalogue"
import type { OwnerRef, WorkspaceProject } from "@mehen/protocol/workspace"
import { cardText, emptyState, timeTag } from "./components.ts"
import { type Html, html } from "./html.ts"
import { icon } from "./icons.ts"
import type { PolicyRulesLine } from "./policy-indicator.ts"
import { outcomeRegion, ruleStatusPill, ruleTermsOf } from "./policy-rules-row.ts"
import { workspaceHref } from "./shell.ts"
import {
  RULE_APPROVER_HIDDEN_WORDS, RULE_COSIGNED_BY_WORDS, RULE_COSIGNER_HIDDEN_WORDS, RULE_EXTEND_BUTTON, RULE_EXTEND_FOR_LABEL, RULE_EXTEND_LABEL, RULE_ID_LABEL, RULE_OUTSIDE_PROJECT_WORDS, RULE_STOP_BUTTON, RULE_STOP_LABEL, RULE_STOP_WORDS,
  GRANT_RECEIPT_LABEL, GRANT_RECEIPT_NONE_WORDS, GRANT_STOP_BUTTON, GRANT_STOP_WORDS, grantReceiptLine, grantTitleWords, grantUsesWords,
  MY_RULES_EMPTY_TITLE, MY_RULES_EMPTY_WORDS, RULE_TASK_WORDS, RULE_TERM_LABELS, RULES_CARD_LEAD, RULES_CARD_TITLE, RULES_ENDED_HEADING, TASK_LABEL_WORDS, formatDuration, ruleContextWords, ruleEndedWords, ruleUsesWords, rulesEndedMoreWords,
} from "./wording.ts"

// Who the page shows the card to; held: the account may only narrow, so
// Extend is not offered.
export type RulesViewer = { member: string; role: string; held: boolean }
export type RuleMachine = { name: string; owner: OwnerRef }

// What GET /policy/rules?include=grants lists: standing rules and task
// grants (kind "area").
export type ListedRule = PolicyRuleView | PolicyAreaGrantView
export type ListedRules = readonly ListedRule[]
export function isGrant(rule: ListedRule): rule is PolicyAreaGrantView {
  return "kind" in rule && rule.kind === "area"
}

// The card's inputs: the rules and task grants, the machines and tasks
// they name by id as far as the page could read them, and whether each row
// names its credential (the machine page) or not (the credential's own
// page).
export type PolicyRulesCardData = {
  rules: ListedRules
  machines: ReadonlyMap<string, RuleMachine>
  tasks: ReadonlyMap<string, string>
  viewer: RulesViewer | null
  showCredential: boolean
}

export const RULES_CARD_ID = "policy-rules"

// The projects the page read, to name a rule's project by its slug; one
// it could not read is named by its id, as the vault names it.
export type RuleProjects = readonly Pick<WorkspaceProject, "id" | "slug">[] | null

function ownMachine(viewer: RulesViewer | null, machine: RuleMachine | undefined): boolean {
  return viewer !== null && machine?.owner.kind === "member" && machine.owner.member === viewer.member
}

// The vault lets the machine's owner extend, or for a team's machine an
// approver of its asks; the page offers Extend where that may be so, and
// the vault decides.
function mayExtend(viewer: RulesViewer | null, machine: RuleMachine | undefined): boolean {
  if (viewer === null || viewer.held || viewer.role === "guest") return false
  return ownMachine(viewer, machine) || machine?.owner.kind === "team"
}

export function rulePattern(rule: Pick<PolicyRuleView, "method" | "host" | "path">): string {
  return `${rule.method} ${rule.host}${rule.path}`
}

function who(rule: ListedRule, data: PolicyRulesCardData): Html {
  const machine = cardText(data.machines.get(rule.asker.device)?.name ?? rule.asker.device)
  if (rule.asker.workload === null) return machine
  const label = data.tasks.get(rule.asker.workload)
  return html`${RULE_TASK_WORDS} <code>${cardText(label ?? rule.asker.workload)}</code>${label !== undefined ? html` <span class="muted small">(${TASK_LABEL_WORDS})</span>` : ""} on ${machine}`
}

// Where the rule applies, in the approval panel's words, its project by
// slug as the page read it.
function context(rule: ListedRule, projects: RuleProjects): Html {
  const bound = rule.context
  const project = bound === null ? null : (projects?.find((p) => p.id === bound.project)?.slug ?? bound.project)
  return cardText(ruleContextWords(project, bound?.environment ?? null) ?? RULE_OUTSIDE_PROJECT_WORDS)
}

function approvers(rule: ListedRule): Html {
  const approver = rule.approvedBy !== null ? cardText(rule.approvedBy) : html`<span class="muted">${RULE_APPROVER_HIDDEN_WORDS}</span>`
  if (rule.coSignedBy === null) return approver
  return html`${approver}, ${RULE_COSIGNED_BY_WORDS} ${rule.coSignedBy.name !== null ? cardText(rule.coSignedBy.name) : RULE_COSIGNER_HIDDEN_WORDS}`
}

function stopFold(id: string, words = { lead: RULE_STOP_WORDS, button: RULE_STOP_BUTTON }): Html {
  return html`<details class="fold" data-region="rule-stop"><summary>${icon("chevronRight")}<span>${RULE_STOP_LABEL}</span></summary>
        <p class="small muted">${words.lead}</p>
        <div class="actions"><button type="button" class="btn danger-quiet" data-action="rule-stop" data-rule="${id}">${words.button}</button></div>
      </details>`
}

// data-rule-terms: the terms the row shows, whose digest the vault's
// action must carry before the page signs it.
function extendFold(rule: PolicyRuleView): Html {
  const id = rule.id
  return html`<details class="fold" data-region="rule-extend"><summary>${icon("chevronRight")}<span>${RULE_EXTEND_LABEL}</span></summary>
        <fieldset class="field"><legend class="label">${RULE_EXTEND_FOR_LABEL}</legend>${RULE_DURATIONS.map((d) => html`<label class="tick"><input type="radio" name="rule-ttl-${id}" data-input="rule-ttl" value="${String(d)}"${d === RULE_DEFAULT_DURATION ? html` checked` : ""}><span>${formatDuration(d)}</span></label>`)}</fieldset>
        <div class="actions"><button type="button" class="btn secondary" data-action="rule-extend" data-rule="${id}" data-rule-terms="${JSON.stringify(ruleTermsOf(rule))}">${icon("passkey")}<span>${RULE_EXTEND_BUTTON}</span></button></div>
      </details>`
}

function ruleRow(ws: string, rule: PolicyRuleView, data: PolicyRulesCardData, projects: RuleProjects): Html {
  const active = rule.status === "active"
  const machine = data.machines.get(rule.asker.device)
  const fields = rule.graphql?.fields ?? []
  return html`<li class="row" data-region="rule" data-rule="${rule.id}" data-rule-state="${rule.status}"${ownMachine(data.viewer, machine) ? html` data-rule-own` : ""}>
    <div class="row-main">
      <span class="row-title"><code>${cardText(rulePattern(rule))}</code></span>
      <dl class="kv small facts" data-region="rule-terms">
        ${data.showCredential ? html`<dt>${RULE_TERM_LABELS.credential}</dt><dd><a href="${workspaceHref(ws, `/items/${encodeURIComponent(rule.item)}`)}"><code>${cardText(rule.item)}</code></a></dd>` : ""}
        <dt>${RULE_TERM_LABELS.who}</dt><dd>${who(rule, data)}</dd>
        ${fields.length > 0 ? html`<dt>${RULE_TERM_LABELS.graphql}</dt><dd>${fields.map((f, i) => html`${i > 0 ? ", " : ""}<code>${f}</code>`)}</dd>` : ""}
        <dt>${RULE_TERM_LABELS.context}</dt><dd>${context(rule, projects)}</dd>
        <dt>${RULE_TERM_LABELS.approvedBy}</dt><dd>${approvers(rule)}</dd>
        <dt>${RULE_TERM_LABELS.used}</dt><dd>${ruleUsesWords(rule.uses, rule.lastUsedAt !== null)}${rule.uses > 0 && rule.lastUsedAt !== null ? html` ${timeTag(rule.lastUsedAt)}` : ""}</dd>
        <dt data-region="rule-ends-label">${active ? RULE_TERM_LABELS.ends : RULE_TERM_LABELS.ended}</dt><dd data-region="rule-ends">${timeTag(rule.endsAt)}</dd>
      </dl>
      <p class="small muted" data-region="rule-ended"${active ? html` hidden` : ""}>${active ? "" : ruleEndedWords(rule.endedReason)}</p>
      ${active ? stopFold(rule.id) : ""}
      ${active && mayExtend(data.viewer, machine) ? extendFold(rule) : ""}
      ${outcomeRegion("")}
      <p class="small muted">${RULE_ID_LABEL} <code>${rule.id}</code></p>
    </div>
    <span class="row-side" data-region="rule-status">${ruleStatusPill(rule)}</span>
  </li>`
}

// A task grant's row: the areas it covers by their catalogue names, its
// credential and host, who, where, who approved, how many of its requests
// are used and when it ends; Stop while it is live (a grant is never
// extended), and once it has ended why, and its receipt of what it did.
function grantRow(ws: string, grant: PolicyAreaGrantView, data: PolicyRulesCardData, projects: RuleProjects): Html {
  const active = grant.status === "active"
  const machine = data.machines.get(grant.asker.device)
  const catalogue = policyCatalogueNamed(grant.catalogue)?.areas ?? []
  const names = grant.areas.map((id) => catalogue.find((a) => a.id === id)?.name ?? id)
  return html`<li class="row" data-region="rule" data-rule="${grant.id}" data-rule-kind="area" data-rule-state="${grant.status}"${ownMachine(data.viewer, machine) ? html` data-rule-own` : ""}>
    <div class="row-main">
      <span class="row-title">${cardText(grantTitleWords(names))}</span>
      <dl class="kv small facts" data-region="rule-terms">
        <dt>${RULE_TERM_LABELS.credential}</dt><dd>${data.showCredential ? html`<a href="${workspaceHref(ws, `/items/${encodeURIComponent(grant.item)}`)}"><code>${cardText(grant.item)}</code></a>` : html`<code>${cardText(grant.item)}</code>`} <span class="muted small">on <code>${cardText(grant.host)}</code></span></dd>
        <dt>${RULE_TERM_LABELS.who}</dt><dd>${who(grant, data)}</dd>
        <dt>${RULE_TERM_LABELS.context}</dt><dd>${context(grant, projects)}</dd>
        <dt>${RULE_TERM_LABELS.approvedBy}</dt><dd>${approvers(grant)}</dd>
        <dt>${RULE_TERM_LABELS.used}</dt><dd data-region="grant-uses">${grantUsesWords(grant.uses, grant.maxUses)}</dd>
        <dt data-region="rule-ends-label">${active ? RULE_TERM_LABELS.ends : RULE_TERM_LABELS.ended}</dt><dd data-region="rule-ends">${timeTag(grant.endsAt)}</dd>
        ${active ? "" : html`<dt>${GRANT_RECEIPT_LABEL}</dt><dd><ul class="plain" data-region="grant-receipt">${grant.receipt.length === 0 ? html`<li>${GRANT_RECEIPT_NONE_WORDS}</li>` : grant.receipt.map((r) => html`<li>${cardText(grantReceiptLine(r.count, r.words))}</li>`)}</ul></dd>`}
      </dl>
      <p class="small muted" data-region="rule-ended"${active ? html` hidden` : ""}>${active ? "" : ruleEndedWords(grant.endedReason)}</p>
      ${active ? stopFold(grant.id, { lead: GRANT_STOP_WORDS, button: GRANT_STOP_BUTTON }) : ""}
      ${outcomeRegion("")}
      <p class="small muted">${RULE_ID_LABEL} <code>${grant.id}</code></p>
    </div>
    <span class="row-side" data-region="rule-status">${ruleStatusPill(grant)}</span>
  </li>`
}

function listedRow(ws: string, rule: ListedRule, data: PolicyRulesCardData, projects: RuleProjects): Html {
  return isGrant(rule) ? grantRow(ws, rule, data, projects) : ruleRow(ws, rule, data, projects)
}

// The card, and the credential page's read of its machines to name them,
// are only for a list with a live rule in it.
export function hasActiveRule(rules: readonly Pick<PolicyRuleView, "status">[]): boolean {
  return rules.some((r) => r.status === "active")
}

// How many ended rules the card lists, most recently ended first.
export const RULES_ENDED_SHOWN = 5

// Nothing at all, not an empty card, when no rule is active. Of the ended
// rules the vault lists (at most POLICY_RULES_ENDED_LISTED, the most
// recently ended) only the latest few are drawn, with a count of the rest,
// a lower bound when the vault's list is full.
export function policyRulesCard(ws: string, data: PolicyRulesCardData | undefined, projects: RuleProjects = null): Html {
  if (data === undefined || !hasActiveRule(data.rules)) return html``
  const ended = data.rules.filter((r) => r.status === "ended").sort((a, b) => Date.parse(b.endsAt) - Date.parse(a.endsAt))
  const older = ended.length - RULES_ENDED_SHOWN
  return html`<section class="card" id="${RULES_CARD_ID}" data-region="policy-rules">
    <h2>${RULES_CARD_TITLE}</h2>
    <p class="small muted">${RULES_CARD_LEAD}</p>
    <ul class="rows">${data.rules.filter((r) => r.status === "active").map((r) => listedRow(ws, r, data, projects))}</ul>
    ${ended.length > 0 ? html`<h3>${RULES_ENDED_HEADING}</h3>
    <ul class="rows" data-region="rules-ended">${ended.slice(0, RULES_ENDED_SHOWN).map((r) => listedRow(ws, r, data, projects))}</ul>
    ${older > 0 ? html`<p class="small muted" data-region="rules-ended-more">${rulesEndedMoreWords(older, ended.length >= POLICY_RULES_ENDED_LISTED)}</p>` : ""}` : ""}
  </section>`
}

// The My rules page's list (pages/my-rules.ts): every live rule the vault
// lists as the person's own, each row as the credential and machine cards
// draw it, naming its credential, with the same Stop and Extend; an empty
// state when there is none.
export function myRulesList(ws: string, data: PolicyRulesCardData, projects: RuleProjects = null): Html {
  const live = data.rules.filter((r) => r.status === "active")
  return html`<section class="card" id="${RULES_CARD_ID}" data-region="policy-rules">${live.length === 0 ? emptyState("shield", MY_RULES_EMPTY_TITLE, MY_RULES_EMPTY_WORDS) : html`<ul class="rows">${live.map((r) => listedRow(ws, r, data, projects))}</ul>`}</section>`
}

// The compact lines count requests rules let through, so not task grants.
function activeOwn(data: PolicyRulesCardData | undefined): PolicyRuleView[] {
  return data === undefined ? [] : data.rules.filter((r): r is PolicyRuleView => !isGrant(r) && r.status === "active" && ownMachine(data.viewer, data.machines.get(r.asker.device)))
}

// The compact line on a credential's page: the viewer's own machines' live
// rules on it, linking to that machine's page, or to the machines when
// several.
export function credentialRulesLine(ws: string, data: PolicyRulesCardData | undefined): PolicyRulesLine | undefined {
  const own = activeOwn(data)
  if (own.length === 0) return undefined
  const devices = [...new Set(own.map((r) => r.asker.device))]
  return { count: own.length, href: workspaceHref(ws, devices.length === 1 ? `/devices/${encodeURIComponent(devices[0] as string)}` : "/devices") }
}

// The compact line on the viewer's own machine's page: its live rules,
// linking to their credential's page, or to this page's card when several.
export function machineRulesLine(ws: string, data: PolicyRulesCardData | undefined): PolicyRulesLine | undefined {
  const own = activeOwn(data)
  if (own.length === 0) return undefined
  const items = [...new Set(own.map((r) => r.item))]
  return { count: own.length, href: items.length === 1 ? workspaceHref(ws, `/items/${encodeURIComponent(items[0] as string)}`) : `#${RULES_CARD_ID}` }
}
