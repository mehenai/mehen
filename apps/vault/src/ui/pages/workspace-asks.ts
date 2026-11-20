// The ask pages inside a workspace: an approval (the readable detail view,
// or the minimal stop view for someone who may only stop it), the intake
// and connect pages a credential is created through, and a policy
// proposal. Every one takes the one decision layout: the
// warning card first when warned, the decision card (what is asked, the
// workspace once, the facts that decide it, the check), what happens next,
// the whole truth unfolded with only the digests in a fold, and the
// decision bar fixed to the foot, its buttons tied to the card's form.
// Each names its workspace by name, slug and origin, the machine and whose
// it is, and marks the agent's session label as not verified. A guest
// never sees who else could decide. Needs you is workspace-pending.ts; the
// enrolment page is workspace-enrol.ts.

import type { ApprovalView } from "@mehen/protocol/api"
import type { MandateCappedAsk, MandateCoverAsk } from "@mehen/protocol/mandate-terms"
import type { PolicyAreaProposalViewProjection } from "@mehen/protocol/workspace"
import type { CredentialHome, PolicyRuleProposalViewProjection, PolicyStandingProposalViewProjection, WorkspaceApprovalView, WorkspaceConnectView, WorkspaceIntakeView, WorkspaceItemSummary, WorkspaceProject } from "@mehen/protocol/workspace"
import { spellCardText } from "../../relay/presentation.ts"
import { APPROVAL_TTL_MS } from "../../vault/areas/approvals.ts"
import { askPlace, decisionBar, emailBlocks, headersBlock, technicalFold, warningCard } from "../ask-evidence.ts"
import { type PushedValueFacts, approvalPush, pushOutcome, pushReason, pushRequestCard, pushSummary } from "../push-evidence.ts"
import { PUSH_NEXT_WORDS } from "../push-wording.ts"
import { approvalTexts, askWarnings, connectTexts, intakeTexts, mergedWarnings, stopTexts } from "../ask-safety.ts"
import { cardText, countdownTimer, notice, pill, taskLine } from "../components.ts"
import { Html, html } from "../html.ts"
import { icon, kindTile, serviceTile } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import { type WorkspaceShell, workspaceHref } from "../shell.ts"
import type { ConnectTerms } from "../client/ask-logic.ts"
import { type RuleProposalBoot, ruleProposalDurations, ruleProposalPaths } from "../client/workspace-logic.ts"
import type { AreaProposalBoot } from "../client/workspace-logic.ts"
import { NEEDS_YOU_PATH } from "../client/pages/needs-you-logic.ts"
import { homeKey } from "../home-key.ts"
import { type PolicyRuleTerms, RULE_DEFAULT_DURATION, RULE_DURATIONS } from "@mehen/protocol/policy-mode"
import { AREA_GRANT_DURATIONS } from "@mehen/protocol/policy-mode"
import { APPROVE_AND_ASK_MANAGER_AREA_LABEL, AREA_COSIGN_WORDS, AREA_ENDS_SOONER_WORDS, AREA_MISMATCH_WORDS, AREA_PANEL_LABELS, AREA_PANEL_TITLE, AREA_REFUSAL_WORDS, AREA_STILL_ASKS_WORDS, AREA_USES_CHOICES, areaApproveLabel, areaUsesWords } from "../wording.ts"
import { AREA_COSIGN_EYEBROW, AREA_COSIGN_NEXT_WORDS, AREA_PROPOSAL_NEXT_WORDS, AREA_PROPOSAL_SETTLED_WORDS, AREA_PROPOSAL_SIGNED_WORDS, AREA_PROPOSAL_TITLE, RULE_PROPOSAL_PAGE_MISMATCH_WORDS, areaProposalAllowedWords, areaTermsWords } from "../wording.ts"
import { APPROVAL_NEXT_WORDS, APPROVE_AND_ALLOW_LABEL, CHECKING_PAGE_WORDS, RULE_COSIGN_EYEBROW, RULE_COSIGN_NEXT_WORDS, RULE_EXTEND_EYEBROW, RULE_PROPOSAL_MISMATCH_WORDS, RULE_PROPOSAL_NEXT_WORDS, RULE_PROPOSAL_OWNER_ONLY_WORDS, RULE_PROPOSAL_OWN_APPROVAL_WORDS, RULE_PROPOSAL_READ_ONLY_WORDS, RULE_PROPOSAL_SECOND_PERSON_WORDS, RULE_PROPOSAL_SETTLED_WORDS, RULE_PROPOSAL_TITLE, RULE_PROPOSAL_TTL_SECONDS, RULE_AGENT_PROPOSED_LABEL, RULE_PROPOSED_LABEL, ruleAllowedWords, ruleChosenTermsWords, ruleApprovedByWords, ruleExtendTitle, ruleProposalExtendedWords, APPROVE_AND_ASK_MANAGER_LABEL, APPROVE_ONCE_LABEL, CHANGED_SINCE_REQUESTED, FOUR_EYES_EXPLAINED, FOUR_EYES_TITLE, PASSKEY_CONFIRMS_WORDS, REQUEST_BODY_HEADING, REQUEST_BODY_NOTE, RULE_ACTING_AS_WORDS, RULE_COSIGN_WORDS, RULE_ENDS_SOONER_WORDS, RULE_GRAPHQL_WORDS, RULE_MISMATCH_WORDS, RULE_PANEL_LABELS, RULE_PANEL_TITLE, RULE_PATH_EXACT_WORDS, RULE_PATH_PATTERN_WORDS, RULE_QUERY_VALUES_WORDS, RULE_QUERY_WORDS, RULE_REASON_LABEL, RULE_REASON_WORDS, RULE_REFUSAL_WORDS, RULE_STILL_ASKS_WORDS, RUN_NEXT_WORDS, SESSION_LABEL_WORDS, STOP_VIEW_WORDS, TASK_LABEL_WORDS, TICK_CODE_WORDS, allowWords, detailLabelWords, formatDuration, formatUses, joinWords, ruleAskerWords, ruleContextWords } from "../wording.ts"
import { MANDATE_COVER_HELD_WORDS, MANDATE_OPEN_LINK, mandateCappedWords, mandateCoverWords } from "../wording.ts"
import { type Viewer, belongsToWords } from "../workspace-rights.ts"
import { connectPage } from "./connect.ts"
import { intakePage } from "./intake.ts"

type ApprovalDetail = Extract<WorkspaceApprovalView, { view: "detail" }>
type ApprovalStop = Exclude<WorkspaceApprovalView, { view: "detail" }>

// The legacy request pages print unprefixed links; inside a workspace each
// one goes under /w/<slug>, except the old home's Needs you anchor, which
// becomes the account's one inbox. Only attribute values the page itself
// wrote start with href="/ (a quote in stored text is escaped), so this
// rewrites links and nothing else.
const PREFIXED: readonly [string, string][] = [
  ['href="/items/', "/items/"],
  ['href="/i/', "/i/"],
  ['href="/c/', "/c/"],
  ['href="/connect"', "/credentials"],
]

export function workspaceLinks(body: Html, slug: string): Html {
  let out = body.value
  for (const [from, path] of PREFIXED) {
    const closed = from.endsWith('"')
    out = out.split(from).join(`href="${workspaceHref(slug, path)}${closed ? '"' : ""}`)
  }
  out = out.split('href="/#needs-you"').join(`href="${NEEDS_YOU_PATH}"`)
  return new Html(out)
}

// ---------------------------------------------------------------- approvals

function ownerWords(owner: ApprovalDetail["approval"]["owner"]): string {
  return owner.kind === "member" ? owner.name : `the team ${owner.name}`
}

// The subject the vault's binding digest commits to, rebuilt from what the
// detail view shows. The client recomputes the digest from this and the
// binding before Approve is offered.
export function approvalSubjectOf(approval: ApprovalView): import("@mehen/protocol/api").ApprovalSubject {
  return { item: approval.item.slug, method: approval.request.method, url: approval.request.url, contentType: approval.request.contentType, contentEncoding: approval.request.contentEncoding, headersSha256: approval.request.headersSha256, bodySha256: approval.request.bodySha256, constraints: approval.constraints }
}

// A run approval names its project by id in its URL and its environment in
// its details; the credentials the run's variables point at come from the
// project's own view, each with where it belongs.
export type RunCredential = { variable: string; slug: string | null; home: CredentialHome | null }

export function runCredentials(approval: ApprovalView, project: WorkspaceProject | null, items: readonly WorkspaceItemSummary[]): { project: WorkspaceProject; env: string; credentials: RunCredential[] } | null {
  if (approval.request.method !== "RUN" || project === null) return null
  const env = approval.details.find((d) => d.label === "Environment")?.value
  const vars = approval.details.find((d) => d.label === "Variables")?.value.split(", ").filter((v) => v !== "") ?? []
  if (env === undefined) return null
  const homes = new Map(items.map((i) => [i.slug, i.home]))
  const credentials = vars.flatMap((name): RunCredential[] => {
    const v = project.vars.find((x) => x.env === env && x.name === name)
    if (v === undefined || v.source === "plain" || v.source === "unset") return []
    return [{ variable: name, slug: v.item, home: v.item === null ? null : homes.get(v.item) ?? null }]
  })
  return { project, env, credentials }
}

function constraintChoices(asked: ApprovalView["constraints"]): { uses: { value: string; label: string }[]; ttl: { value: number; label: string }[] } {
  const usesSteps = [1, 5, 10, 25, 50, 100].filter((n) => asked.uses === null || n <= asked.uses)
  const uses = [...usesSteps.map((n) => ({ value: String(n), label: formatUses(n) })), ...(asked.uses === null ? [{ value: "unlimited", label: formatUses(null) }] : asked.uses !== null && !usesSteps.includes(asked.uses) ? [{ value: String(asked.uses), label: formatUses(asked.uses) }] : [])]
  const ttlSteps = [60, 600, 3600, 4 * 3600, 86_400].filter((s) => s <= asked.ttlSeconds)
  const ttl = [...ttlSteps, ...(ttlSteps.includes(asked.ttlSeconds) ? [] : [asked.ttlSeconds])].map((s) => ({ value: s, label: formatDuration(s) }))
  return { uses, ttl }
}

// The terms the page starts on: the first choice of each, the least the
// agent's ask allows; a person may choose more, up to it.
// A fill ask starts at what it asked, never more, so the terms line agrees
// with its card ("up to 6 fields in all, for the next 10 minutes"); a
// person may still choose less.
export function defaultTerms(choices: ReturnType<typeof constraintChoices>, asked: Pick<ApprovalView, "constraints" | "request">): { uses: string; ttl: number } {
  const fill = asked.request.method === "FILL" && asked.constraints.uses !== null
  const uses = fill ? choices.uses.find((c) => c.value === String(asked.constraints.uses)) : undefined
  const ttl = fill ? choices.ttl.find((c) => c.value === asked.constraints.ttlSeconds) : undefined
  return { uses: uses?.value ?? choices.uses[0]?.value ?? "1", ttl: ttl?.value ?? choices.ttl[0]?.value ?? 60 }
}

function usesNumber(value: string): number | null {
  return value === "unlimited" ? null : Number(value)
}

// The run's credential list is read from the project as it is now; the
// approval's digest does not bind it. When a run ask moved on while the page
// was being built, or is stale (the vault says so when a credential's
// configuration changed since the request), the page says so and offers no
// decision.
function changedNotice(approval: ApprovalView, changed: boolean): Html | string {
  // An ask settled in between is simply shown settled.
  if (approval.request.method !== "RUN" || !(approval.status === "stale" || (changed && approval.status === "pending"))) return ""
  return html`<div data-region="changed-since-requested">${notice("warn", "This request changed", CHANGED_SINCE_REQUESTED)}</div>`
}

function sessionWords(by: ApprovalView["requestedBy"]): Html | string {
  return by.session !== null ? html`, session ${cardText(by.session)} <span class="muted">(${SESSION_LABEL_WORDS})</span>` : ""
}

function detailOf(a: ApprovalView, label: string): string | null {
  return a.details.find((d) => d.label === label)?.value ?? null
}

// The facts that decide it: the run's or the request's own detail lines,
// or for an email who it goes to and its subject.
function approvalSummary(a: ApprovalView): Html | string {
  if (a.email !== null) {
    const email = a.email
    const outside = email.accountDomain === null ? "external" : html`outside ${cardText(email.accountDomain)}`
    const to = email.recipients.filter((r) => r.header === "To")
    const subject = email.headers.find((h) => h.name.toLowerCase() === "subject")?.value ?? null
    return html`<dl class="summary"><dt>To</dt><dd class="big">${to.length > 0 ? html`${to.map((r, i) => html`${i > 0 ? ", " : ""}<span class="addr">${cardText(r.address)}</span>${r.external ? html` <span class="pill danger">${outside}</span>` : ""}`)}` : html`<span class="muted">nobody</span>`}</dd>${email.recipients.length > to.length ? html`<dt>Also</dt><dd>${email.recipients.length - to.length} more in Cc or Bcc, listed below</dd>` : ""}<dt>Subject</dt><dd>${subject !== null ? cardText(subject) : html`<span class="muted">no subject</span>`}</dd><dt>Through</dt><dd><code>${cardText(a.item.slug)}</code>${a.item.account !== null ? html` as ${cardText(a.item.account)}` : ""}</dd></dl>`
  }
  const rows = a.details.filter((d) => d.value !== a.title)
  if (rows.length === 0) return ""
  return html`<dl class="summary">${rows.map((d) => html`<dt>${cardText(detailLabelWords(d.label))}</dt><dd>${cardText(d.value)}</dd>`)}</dl>`
}

function runCredentialsBlock(run: NonNullable<ReturnType<typeof runCredentials>>, slugs: ReadonlyMap<string, string>): Html {
  return html`<div data-region="run-credentials"><p class="eyebrow">Credentials this run uses</p>${run.credentials.length
    ? html`<ul class="ref-list">${run.credentials.map((c) => html`<li><code>${cardText(c.variable)}</code> from ${c.slug !== null ? html`<code>${cardText(c.slug)}</code>${c.home !== null ? html` <span class="belongs" data-belongs="${c.home.kind}">Belongs to: ${cardText(belongsToWords(c.home, slugs, run.project.id))}</span>` : ""}` : html`<span class="muted">a credential outside your reach</span>`}</li>`)}</ul>`
    : html`<p class="muted">Only plain values.</p>`}</div>`
}

// Everything the passkey signs, unfolded: the exact request, every header
// forwarded with it, the email, and who asked. Only the digests are folded.
function wholeTruth(view: ApprovalDetail): Html {
  const a = view.approval
  const run = a.request.method === "RUN"
  const push = approvalPush(a)
  return html`<div class="truth-head" id="truth"><h2>The whole truth</h2><p class="muted">What the passkey signs, as the vault reads it. The summary above is drawn from this; if they disagree, this wins.</p></div>
  ${push !== null ? pushRequestCard(a, push.push) : html`<section class="card" aria-label="The exact request" data-region="exact-request">
    <h2>The exact request</h2>
    <p class="request-line"><span class="method">${cardText(a.request.method)}</span> <code class="url">${cardText(a.request.url)}</code></p>
    <dl class="kv small"><dt>Content type</dt><dd>${a.request.contentType !== null ? html`<code>${cardText(a.request.contentType)}</code>` : html`<span class="muted">none</span>`}</dd>
      <dt>Content encoding</dt><dd>${a.request.contentEncoding !== null ? html`<code>${cardText(a.request.contentEncoding)}</code>` : html`<span class="muted">none</span>`}</dd></dl>
    ${run && a.request.body !== null ? html`<h3>The command line</h3><p class="muted small">Every argument on its own line, exactly as it will run.</p>` : html`<h3>${REQUEST_BODY_HEADING}</h3><p class="muted small" data-region="body-note">${REQUEST_BODY_NOTE}</p>`}
    ${a.request.body !== null ? html`<pre class="request-body" tabindex="0">${cardText(a.request.body)}</pre>` : html`<p class="muted">No body.</p>`}
    <dl class="kv small"><dt>Body SHA-256</dt><dd><code class="hash">${a.request.bodySha256}</code></dd></dl>
  </section>`}
  ${a.request.headers !== null ? headersBlock(a.request.headers, a.request.headersSha256, false) : ""}
  ${a.email !== null ? emailBlocks(a.email) : ""}
  <section class="card asker" aria-label="Who is asking"><h2>Who asked</h2>
    <dl class="kv"><dt>Machine</dt><dd>${cardText(a.requestedBy.deviceName)} <span class="muted">(<code>${a.requestedBy.device}</code>)</span></dd>
      ${a.requestedBy.workload ? html`<dt>Task</dt><dd><code>${cardText(a.requestedBy.workload.label)}</code> <span class="muted small">(${TASK_LABEL_WORDS})</span></dd>` : ""}
      <dt>Session</dt><dd>${a.requestedBy.session !== null ? html`<code>${cardText(a.requestedBy.session)}</code> <span class="muted small">(${SESSION_LABEL_WORDS})</span>` : "not given"}</dd>
      <dt>${run ? "Project" : "Credential"}</dt><dd><code>${cardText(a.item.slug)}</code>${a.item.account !== null ? html`, acting as ${cardText(a.item.account)}` : ""}</dd>
      ${push === null ? html`<dt>Asked for</dt><dd>${formatUses(a.constraints.uses)}, within ${formatDuration(a.constraints.ttlSeconds)}</dd>` : ""}</dl>
  </section>
  ${technicalFold([
    ["Code", html`<code class="code-inline">${a.bindingCode}</code>`],
    ["Request digest", html`<code class="hash">${a.digest}</code> <span data-region="digest-match" hidden>${pill("matches this page", "ok")}</span><span data-region="digest-mismatch" hidden>${pill("does not match this page", "danger")}</span>`],
    ...(view.binding ? ([["Snapshot", html`<code class="hash">${view.binding.snapshotDigest}</code>`], ["Presentation", html`<code class="hash">${view.binding.presentationDigest}</code>`]] as const) : []),
    ["Body SHA-256", html`<code class="hash">${a.request.bodySha256}</code>`],
    ...(a.request.headers !== null ? ([["Headers SHA-256", html`<code class="hash">${a.request.headersSha256}</code>`]] as const) : []),
  ], html`<p class="small muted">Approve stays off until this page's own copy of the request hashes to the vault's digest. Each decision is recorded in Activity.</p>`)}`
}

function termsFold(a: ApprovalView, choices: ReturnType<typeof constraintChoices>, start: { uses: string; ttl: number }): Html {
  return html`<div class="terms-form" id="terms-form" data-region="terms-form" hidden>
    <p class="small muted terms-asked">The agent asked for ${formatUses(a.constraints.uses)}, within ${formatDuration(a.constraints.ttlSeconds)}. You may allow less, never more.</p>
    <label class="field"><span class="label">How many times</span><select form="decide" data-input="uses">${choices.uses.map((c) => html`<option value="${c.value}"${c.value === start.uses ? html` selected` : ""}>${c.label}</option>`)}</select></label>
    <label class="field"><span class="label">For how long</span><select form="decide" data-input="ttl">${choices.ttl.map((c) => html`<option value="${String(c.value)}"${c.value === start.ttl ? html` selected` : ""}>${c.label}</option>`)}</select></label>
  </div>`
}

type RuleOffer = NonNullable<NonNullable<ApprovalView["rememberOptions"]>["rule"]>
type OfferedRule = Extract<RuleOffer, { refused: null }>

function ruleRequestWords(terms: OfferedRule["terms"]): Html {
  const graphql = terms.graphql
  return html`<span class="method">${terms.method}</span> <code>${cardText(`${terms.host}${terms.anchorPath}`)}</code>${graphql !== null
    ? html`<br><span data-region="rule-graphql">${RULE_GRAPHQL_WORDS.lead} ${graphql.fields.map((f, i) => html`${i === 0 ? "" : i === graphql.fields.length - 1 ? " and " : ", "}<code>${cardText(f)}</code>`)} ${RULE_GRAPHQL_WORDS.tail}</span>`
    : ""}${terms.queryNames.length > 0 ? html`<br><span data-region="rule-query">${RULE_QUERY_WORDS} ${terms.queryNames.map((q, i) => html`${i === 0 ? "" : i === terms.queryNames.length - 1 ? " and " : ", "}<code>${cardText(q)}</code>`)}, ${RULE_QUERY_VALUES_WORDS}</span>` : ""}`
}

// What allowing a rule from now on means, from the vault's terms, on the
// approval page and the rule proposal page alike: the credential, the
// request's shape, the path and duration to choose (or, read only, the ones
// proposed), who it is for, the context, what still asks and what ends it
// sooner, and on a proposal the agent's reason, quoted as its own words.
// The choices belong to the decision form; the browser rebuilds the terms
// and their digest from them.
type RuleTermsPanel = {
  terms: PolicyRuleTerms
  account: string | null
  machine: string
  task: string | null
  context: string | null
  // null: read only, the terms as they stand.
  choices: { paths: readonly string[]; path: string; durations: readonly number[]; duration: number } | null
  reason?: string | null
  after: Html | string
}

function ruleTermsPanel(p: RuleTermsPanel): Html {
  const t = p.terms
  const c = p.choices
  const pathWords = (path: string) => html`<code>${cardText(path)}</code> <span class="muted small">${path === t.anchorPath ? RULE_PATH_EXACT_WORDS : RULE_PATH_PATTERN_WORDS}</span>`
  return html`<section class="card rule-panel" aria-label="${RULE_PANEL_TITLE}" data-region="rule-panel">
    <h2>${RULE_PANEL_TITLE}</h2>
    <dl class="kv"><dt>${RULE_PANEL_LABELS.credential}</dt><dd><code>${cardText(t.item)}</code>${p.account !== null ? html`, ${RULE_ACTING_AS_WORDS} ${cardText(p.account)}` : ""}</dd>
      <dt>${RULE_PANEL_LABELS.request}</dt><dd data-region="rule-request">${ruleRequestWords(t)}</dd>
      <dt>${RULE_PANEL_LABELS.who}</dt><dd data-region="rule-who">${cardText(ruleAskerWords(p.machine, p.task))}</dd>
      ${p.context !== null ? html`<dt>${RULE_PANEL_LABELS.context}</dt><dd data-region="rule-context">${cardText(p.context)}</dd>` : ""}${c === null ? html`
      <dt>${RULE_PANEL_LABELS.path}</dt><dd data-region="rule-path">${pathWords(t.path)}</dd>
      <dt>${RULE_PANEL_LABELS.ttl}</dt><dd data-region="rule-ttl">${formatDuration(t.ttlSeconds)}</dd>` : ""}</dl>
    ${c !== null ? html`<fieldset class="field" data-region="rule-paths"><legend class="label">${RULE_PANEL_LABELS.path}</legend>${c.paths.map((path) => html`<label class="tick"><input type="radio" form="decide" name="rule-path" data-input="rule-path" value="${path}"${path === c.path ? html` checked` : ""}><span>${pathWords(path)}</span></label>`)}</fieldset>
    <fieldset class="field" data-region="rule-ttls"><legend class="label">${RULE_PANEL_LABELS.ttl}</legend>${c.durations.map((s) => html`<label class="tick"><input type="radio" form="decide" name="rule-ttl" data-input="rule-ttl" value="${String(s)}"${s === c.duration ? html` checked` : ""}><span>${formatDuration(s)}</span></label>`)}</fieldset>
    ` : ""}<dl class="kv small"><dt>${RULE_PANEL_LABELS.stillAsks}</dt><dd>${RULE_STILL_ASKS_WORDS}</dd><dt>${RULE_PANEL_LABELS.endsSooner}</dt><dd>${RULE_ENDS_SOONER_WORDS}</dd></dl>
    ${p.reason !== undefined && p.reason !== null ? html`<p class="eyebrow">${RULE_REASON_LABEL}</p><p class="small muted">${RULE_REASON_WORDS}</p><blockquote class="reason" data-region="rule-reason">${cardText(p.reason)}</blockquote>
    ` : ""}${p.after}
  </section>`
}

function rulePanel(a: ApprovalView, offer: OfferedRule): Html {
  const t = offer.terms
  // Who is the key the terms name, by the names the request carries only
  // when they are that key's; otherwise by its id.
  const machine = t.asker.device === a.requestedBy.device ? a.requestedBy.deviceName : t.asker.device
  const task = t.asker.workload === null ? null : a.requestedBy.workload?.id === t.asker.workload ? a.requestedBy.workload.label : t.asker.workload
  return ruleTermsPanel({
    terms: t,
    account: a.item.account,
    machine,
    task,
    context: ruleContextWords(detailOf(a, "Project"), detailOf(a, "Environment")),
    choices: { paths: offer.pathChoices, path: offer.pathChoices[0] ?? t.path, durations: RULE_DURATIONS, duration: RULE_DEFAULT_DURATION },
    after: html`${offer.coSign ? html`<p class="small" data-region="rule-cosign">${RULE_COSIGN_WORDS}</p>` : ""}
    <p class="small refused" id="rule-mismatch" aria-live="polite" data-region="rule-mismatch" hidden>${RULE_MISMATCH_WORDS}</p>`,
  })
}

// ---------------------------------------------------------------- task grants on the approval page

type AreaOffer = NonNullable<NonNullable<ApprovalView["rememberOptions"]>["area"]>
type OfferedArea = Extract<AreaOffer, { refused: null }>

// Approve, and let this agent carry on (a task grant): the areas of the
// service's reviewed list, the request's own ticked, each with its words;
// how long and up to how many requests, 1 hour and 50 chosen; what still
// asks. The choices belong to the decision form; the browser rebuilds the
// terms and their digest from them, and names them on the third button.
function areaPanel(a: ApprovalView, offer: OfferedArea): Html {
  const t = offer.terms
  const machine = t.asker.device === a.requestedBy.device ? a.requestedBy.deviceName : t.asker.device
  const task = t.asker.workload === null ? null : a.requestedBy.workload?.id === t.asker.workload ? a.requestedBy.workload.label : t.asker.workload
  const context = ruleContextWords(detailOf(a, "Project"), detailOf(a, "Environment"))
  return html`<section class="card rule-panel" aria-label="${AREA_PANEL_TITLE}" data-region="area-panel">
    <h2>${AREA_PANEL_TITLE}</h2>
    <dl class="kv"><dt>${AREA_PANEL_LABELS.credential}</dt><dd><code>${cardText(t.item)}</code>${a.item.account !== null ? html`, ${RULE_ACTING_AS_WORDS} ${cardText(a.item.account)}` : ""} <span class="muted small">on <code>${cardText(t.host)}</code></span></dd>
      <dt>${AREA_PANEL_LABELS.who}</dt><dd data-region="area-who">${cardText(ruleAskerWords(machine, task))}</dd>
      ${context !== null ? html`<dt>${AREA_PANEL_LABELS.context}</dt><dd data-region="area-context">${cardText(context)}</dd>` : ""}</dl>
    <fieldset class="field" data-region="area-areas"><legend class="label">${AREA_PANEL_LABELS.areas}</legend>${offer.areas.map((area) => html`<label class="tick"><input type="checkbox" form="decide" name="area-area" data-input="area-area" value="${area.id}" data-name="${area.name}"${t.areas.includes(area.id) ? html` checked` : ""}><span><b>${cardText(area.name)}</b> <span class="muted small">${cardText(area.words)}</span></span></label>`)}</fieldset>
    <fieldset class="field" data-region="area-ttls"><legend class="label">${AREA_PANEL_LABELS.ttl}</legend>${AREA_GRANT_DURATIONS.map((s) => html`<label class="tick"><input type="radio" form="decide" name="area-ttl" data-input="area-ttl" value="${String(s)}"${s === t.ttlSeconds ? html` checked` : ""}><span>${formatDuration(s)}</span></label>`)}</fieldset>
    <fieldset class="field" data-region="area-uses"><legend class="label">${AREA_PANEL_LABELS.uses}</legend>${AREA_USES_CHOICES.map((n) => html`<label class="tick"><input type="radio" form="decide" name="area-uses" data-input="area-uses" value="${String(n)}"${n === t.maxUses ? html` checked` : ""}><span>${areaUsesWords(n)}</span></label>`)}</fieldset>
    <dl class="kv small"><dt>${AREA_PANEL_LABELS.stillAsks}</dt><dd data-region="area-still-asks">${AREA_STILL_ASKS_WORDS}</dd><dt>${AREA_PANEL_LABELS.endsSooner}</dt><dd>${AREA_ENDS_SOONER_WORDS}</dd></dl>
    ${offer.coSign ? html`<p class="small" data-region="area-cosign">${AREA_COSIGN_WORDS}</p>` : ""}
    <p class="small refused" id="area-mismatch" aria-live="polite" data-region="area-mismatch" hidden>${AREA_MISMATCH_WORDS}</p>
  </section>`
}

// The third button: the areas the vault ticked and its duration, which the
// browser renames as the person chooses; a co-sign's never changes.
function areaApproveAction(offer: OfferedArea): { action: string; label: string; passkey: true; disabled: true } {
  const names = offer.terms.areas.map((id) => offer.areas.find((a) => a.id === id)?.name ?? id)
  return { action: "approve-area", label: offer.coSign ? APPROVE_AND_ASK_MANAGER_AREA_LABEL : areaApproveLabel(names, offer.terms.ttlSeconds), passkey: true, disabled: true }
}

// For an ask a cap alone kept the machine's mandate from letting through:
// which, "This machine's mandate has used today's 50 sends."
function cappedLine(capped: MandateCappedAsk | null): Html {
  if (capped === null || capped.capped.length === 0) return html``
  return html`<ul class="plain small" data-region="mandate-capped">${capped.capped.map((c) => html`<li>${mandateCappedWords(c.class, c.cap)}</li>`)}</ul>`
}

// For the person who may sign for the machine, an ask a mandate could have
// let through: a link to sign one for these classes, or, while its mandate
// is paused or tripped, to that mandate.
function coverLine(slug: string, cover: MandateCoverAsk | null): Html {
  if (cover === null) return html``
  if (cover.state !== "sign" && cover.mandate !== null) return html`<p class="small" data-region="mandate-cover">${MANDATE_COVER_HELD_WORDS[cover.state]} <a href="${workspaceHref(slug, `/mandates/${encodeURIComponent(cover.mandate)}`)}">${MANDATE_OPEN_LINK}</a></p>`
  return html`<p class="small" data-region="mandate-cover"><a href="${workspaceHref(slug, `/sign-mandate?device=${encodeURIComponent(cover.device.id)}`)}">${cardText(mandateCoverWords(cover.device.name))}</a></p>`
}

function detailPage(view: ApprovalDetail, origin: string, viewer: Viewer, run: ReturnType<typeof runCredentials>, slugs: ReadonlyMap<string, string>, changed: boolean, now: number, pushedValue: PushedValueFacts | null, capped: MandateCappedAsk | null, cover: Html): { body: Html; bar: boolean; approving: boolean; rule: OfferedRule | null; area: OfferedArea | null } {
  const a = view.approval
  // A push is decided as asked: once, within its ten minutes, never from
  // now on (design push-providers 2.4). That follows the method, so a push
  // whose push view is missing or unreadable is still decided only as asked.
  const isPush = a.request.method === "PUSH"
  const push = approvalPush(a)
  // The card's strings, and what the page resolves around it: the run's
  // project and where each of its credentials belongs.
  const resolved = run !== null ? [run.project.slug, ...run.credentials.map((c) => (c.home !== null ? belongsToWords(c.home, slugs, run.project.id) : ""))] : []
  const warnings = mergedWarnings(a.warnings, [...approvalTexts(a, run), ...resolved])
  const warned = warnings.length > 0
  const pending = a.status === "pending" && !changed
  const deciding = pending && (a.eligibility.canApprove || a.eligibility.canDeny)
  const approving = deciding && a.eligibility.canApprove
  // A standing rule only beside an approval this viewer may give.
  const offer = approving && !isPush ? a.rememberOptions?.rule : undefined
  const offered = offer !== undefined && offer.refused === null ? offer : null
  // A task grant likewise, as the vault offers it or says why not.
  const areaOffer = approving && !isPush ? a.rememberOptions?.area : undefined
  const area = areaOffer !== undefined && areaOffer.refused === null ? areaOffer : null
  const deciders = viewer.role === "guest" ? [] : a.eligibility.deciders
  const isRun = a.request.method === "RUN"
  const env = isRun ? detailOf(a, "Environment") : null
  const choices = constraintChoices(a.constraints)
  const start = defaultTerms(choices, a)
  const allow = allowWords(usesNumber(start.uses), start.ttl)
  const fourEyes = run !== null && run.project.environments.find((e) => e.name === run.env)?.fourEyes === true
  const eyebrow = env !== null ? html`A run in <b class="asker-name">${cardText(env)}</b> needs approval` : html`An agent on <b class="asker-name">${cardText(a.requestedBy.deviceName)}</b> wants to`
  const tile = isRun ? kindTile("project", undefined, "lg") : serviceTile({ provider: a.item.provider ?? null, slug: a.item.slug }, "lg")
  const context = html`${askPlace(origin, a.workspace)}${isRun ? html` · an agent on <b>${cardText(a.requestedBy.deviceName)}</b>` : ""}, owned by ${cardText(ownerWords(a.owner))}${sessionWords(a.requestedBy)}`
  const body = html`${warningCard(warnings)}<section class="card decision${warned ? " warned" : ""}" aria-label="The decision" data-region="decision">
    <div class="decision-head">${tile}<div><p class="eyebrow">${eyebrow}</p><h1>${cardText(a.title)}</h1></div></div>
    <p class="who ask-context">${context}</p>
    ${taskLine(a.requestedBy)}
    ${push !== null ? html`${pushSummary(a, push.push, push.destination, pushedValue)}${pushReason(a)}` : approvalSummary(a)}${cappedLine(capped)}${cover}
    ${changedNotice(a, changed)}
    ${run !== null ? runCredentialsBlock(run, slugs) : ""}
    ${fourEyes ? html`<div data-region="four-eyes">${notice("info", FOUR_EYES_TITLE, FOUR_EYES_EXPLAINED)}</div>` : ""}
    ${deciders.length ? html`<p class="small" data-region="deciders">Who can approve: ${cardText(joinWords(deciders, "or"))}.</p>` : ""}
    ${deciding
      ? html`<form class="stack" id="decide" data-form="decide" novalidate>
          ${approving
            ? html`<label class="tick"><input type="checkbox" data-input="code-matches"><span>The agent showed me the code <code class="code-inline">${a.bindingCode}</code></span></label>`
            : html`<p class="small muted" data-region="cannot-approve">${cardText(a.eligibility.reason ?? "You cannot approve this.")} You can decline it.</p>`}
        </form>
        <p class="meta"><span class="timer-line">${countdownTimer(a.expiresAt, APPROVAL_TTL_MS / 1000, now)} <span class="muted">to decide</span></span>${approving && !isPush ? html`<span class="terms-line"><span class="muted">It will allow:</span> <span data-region="terms-text">${allow}</span></span>` : ""}</p>${offer !== undefined && offer.refused !== null ? html`<p class="small muted" data-region="rule-refused">${RULE_REFUSAL_WORDS[offer.refused]}</p>` : ""}${areaOffer !== undefined && areaOffer.refused !== null ? html`<p class="small muted" data-region="area-refused">${AREA_REFUSAL_WORDS[areaOffer.refused]}</p>` : ""}`
      : html`<p class="strip" data-region="settled">${pill(a.status, a.status === "approved" ? "ok" : "muted")} ${settledBy(a.decidedBy, viewer)}</p>${a.status !== "pending" ? settledWords(a) : ""}${push !== null ? pushOutcome(push.push, push.destination) : ""}`}
    <a class="jump" href="#truth">${icon("chevronDown")}<span>${a.email !== null ? "Read the message and the request as the vault reads them below" : "Read the request as the vault reads it below"}</span></a>
  </section>${offered !== null ? rulePanel(a, offered) : ""}${area !== null ? areaPanel(a, area) : ""}
  ${deciding ? html`<div class="ask-next">${notice("info", "What happens next", isRun ? RUN_NEXT_WORDS : isPush ? PUSH_NEXT_WORDS : APPROVAL_NEXT_WORDS)}</div>` : ""}
  ${wholeTruth(view)}
  ${deciding
    ? decisionBar({
        warned,
        form: "decide",
        terms: approving && !isPush ? html`<span class="terms-now"><span data-region="terms-text">${allow}</span> <button type="button" form="decide" class="link" data-action="change-terms" aria-expanded="false" aria-controls="terms-form">Change</button></span>` : "",
        caption: approving ? TICK_CODE_WORDS : "",
        fold: approving && !isPush ? termsFold(a, choices, start) : "",
        decline: a.eligibility.canDeny ? { action: "deny", label: "Decline" } : null,
        accept: approving ? { action: "approve", label: offer !== undefined || area !== null ? APPROVE_ONCE_LABEL : "Approve with passkey", passkey: true, disabled: true } : null,
        alsoAccept: [
          ...(offered !== null ? [{ action: "approve-rule", label: offered.coSign ? APPROVE_AND_ASK_MANAGER_LABEL : APPROVE_AND_ALLOW_LABEL, passkey: true, disabled: true }] : []),
          ...(area !== null ? [areaApproveAction(area)] : []),
        ],
      })
    : ""}`
  return { body, bar: deciding, approving, rule: offered, area }
}

// What a settled approval means for the agent, beside its status.
export const SETTLED_APPROVAL_WORDS: Readonly<Record<Exclude<ApprovalView["status"], "pending">, string>> = {
  approved: "The agent can go ahead, within the limits chosen.",
  denied: "Nothing was sent, and the agent has been told no.",
  expired: "Nobody decided in time, so nothing happened. The agent can ask again if it still needs to.",
  used: "The agent used this approval; it cannot be used again.",
  ended: "It was approved and its time has run out, so the agent cannot use it again.",
  revoked: "It was stopped, so the agent cannot use this approval again. Nothing already sent is undone.",
  stale: "The credential, the machine or the workspace changed since it was asked, so this approval no longer applies. The agent has to ask again.",
  superseded: "A newer ask from the same machine to the same place replaced it, so nothing was sent. Decide the newer one instead.",
}

// What a settled approval means; a superseded one names the newer ask
// from the same machine, linked, where the decision now is.
export const REPLACED_BY_TITLE = "Replaced by a newer ask from the same machine"
function settledWords(a: ApprovalDetail["approval"]): Html {
  const words = a.status === "pending" ? "" : SETTLED_APPROVAL_WORDS[a.status]
  if (a.status !== "superseded" || a.replacedBy === undefined) return html`<p class="small muted" data-region="settled-words">${words}</p>`
  return html`<div data-region="replaced-by">${notice("info", REPLACED_BY_TITLE, words, html`<a class="btn primary sm" href="${workspaceHref(a.workspace.slug, `/a/${encodeURIComponent(a.replacedBy)}`)}">Open the newer ask</a>`)}</div>`
}

// An account held back after a recovery or another security change
// (shell.accountHeld) is refused anything that widens: saying so before the
// person fills in or ticks anything, not only after they press the button.
export const ACCOUNT_HELD_TITLE = "Your account is cooling off"
export const ACCOUNT_HELD_WORDS = {
  approval: "After a recovery or another security change, approving is refused until it ends; declining still works. Your account page says when it ends; until then, ask another owner or admin if this cannot wait.",
  intake: "After a recovery or another security change, saving here is refused until it ends. Your account page says when it ends; until then, ask another owner or admin if this cannot wait.",
  connect: "After a recovery or another security change, connecting here is refused until it ends. Your account page says when it ends; until then, ask another owner or admin if this cannot wait.",
  adoption: "After a recovery or another security change, approving a batch is refused until it ends. Your account page says when it ends; until then, ask another owner or admin if this cannot wait.",
} as const

export function heldNotice(shell: WorkspaceShell, ask: keyof typeof ACCOUNT_HELD_WORDS): Html {
  if (!shell.accountHeld) return html``
  return html`<div data-region="account-held">${notice("warn", ACCOUNT_HELD_TITLE, ACCOUNT_HELD_WORDS[ask], html`<a class="btn secondary sm" href="/account">Your account</a>`)}</div>`
}

// Who decided: "by you", a name for insiders, and nothing at all for a
// guest, whatever the vault sent.
export function settledBy(decidedBy: ApprovalView["decidedBy"], viewer: Viewer): Html | string {
  if (decidedBy === null) return ""
  if (decidedBy.self) return "by you"
  if (viewer.role === "guest" || decidedBy.name === null) return ""
  return html`by ${cardText(decidedBy.name)}`
}

type StopView = ApprovalStop | Extract<PolicyRuleProposalViewProjection, { view: "stop" }>

// Someone who may only stop the ask: which machine, whose, which
// credential by name, and Stop. Nothing about the request itself.
function stopPage(view: StopView, origin: string): { body: Html; bar: boolean } {
  const warnings = askWarnings(stopTexts(view))
  const warned = warnings.length > 0
  const open = view.status === "pending" && view.eligibility.canDeny
  const owner = view.machine.owner.kind === "member" ? view.machine.owner.name : `the team ${view.machine.owner.name}`
  const body = html`${warningCard(warnings)}<section class="card decision${warned ? " warned" : ""}" aria-label="Stop this request" data-region="stop">
    <div class="decision-head">${kindTile("machine", undefined, "lg", view.machine.name)}<div><p class="eyebrow">A private request</p><h1>A machine is waiting</h1></div></div>
    <p class="who ask-context">${askPlace(origin, view.workspace)} · an agent on <b>${cardText(view.machine.name)}</b>, owned by ${cardText(owner)}${view.item !== null ? html`, for <code>${cardText(view.item.slug)}</code>` : ""}.</p>
    ${open ? html`<p>${STOP_VIEW_WORDS}</p>` : html`<p class="strip">${pill(view.status, "muted")}</p>`}
  </section>
  ${open ? html`<div class="ask-next">${notice("info", "What happens next", "Stopping tells the agent no, and nothing it asked for happens.")}</div>` : ""}
  ${open ? html`<form id="decide" data-form="decide" novalidate></form>${decisionBar({ warned, form: "decide", decline: { action: "deny", label: "Stop", tone: warned ? "danger" : "secondary" }, accept: null })}` : ""}`
  return { body, bar: open }
}

// `changedSinceRequested`: the approval read before the project differs
// from the one read after it.
// `pushedValue`: for a push, the pushed field's prefix and fingerprint as
// the viewer may read them, only for the version the push names.
// `capped`: which caps alone kept the machine's mandate from letting it
// through, with MANDATES on; `cover`: that a mandate could, for the person
// who may sign for the machine.
export type ApprovalPageData = { viewer: Viewer; view: WorkspaceApprovalView; project: WorkspaceProject | null; items: WorkspaceItemSummary[]; changedSinceRequested?: boolean; now?: number; pushedValue?: PushedValueFacts | null; capped?: MandateCappedAsk | null; cover?: MandateCoverAsk | null }

export function workspaceApprovalPage(shell: WorkspaceShell, data: ApprovalPageData): PageInput {
  const origin = shell.identity.origin
  if (data.view.view === "stop") {
    const stop = stopPage(data.view, origin)
    return { title: "Stop a request", viewer: null, workspace: shell, focus: true, bar: stop.bar, boot: { page: "ws-approval", approval: data.view.id, view: "stop" }, body: stop.body }
  }
  const view = data.view
  const run = runCredentials(view.approval, data.project, data.items)
  const slugs = new Map(data.project ? [[data.project.id, data.project.slug]] : [])
  const page = detailPage(view, origin, data.viewer, run, slugs, data.changedSinceRequested === true, data.now ?? Date.now(), data.pushedValue ?? null, data.capped ?? null, coverLine(shell.identity.workspace.slug, data.cover ?? null))
  return {
    title: spellCardText(view.approval.title),
    viewer: null,
    workspace: shell,
    focus: true,
    bar: page.bar,
    boot: { page: "ws-approval", approval: view.approval.approval, view: "detail", digest: view.approval.digest, subject: approvalSubjectOf(view.approval), binding: view.binding ?? null, headers: view.approval.request.headers, ...(page.rule !== null ? { rule: { terms: page.rule.terms, termsDigest: page.rule.termsDigest, pathChoices: page.rule.pathChoices, coSign: page.rule.coSign } } : {}), ...(page.area !== null ? { area: { terms: page.area.terms, termsDigest: page.area.termsDigest, areas: page.area.areas, coSign: page.area.coSign } } : {}) },
    body: page.approving ? html`${heldNotice(shell, "approval")}${page.body}` : page.body,
  }
}

// ---------------------------------------------------------------- intake and connect

// A viewer label for the legacy page renderers, which only hand it back as
// the page's viewer; the workspace shell replaces it.
const NO_VIEWER = { name: "", tenantName: null, role: "member" as const }

// Where the new credential will belong, after what is being asked: the
// filler may change the proposed home within their rights, in a fold whose
// summary names the home now chosen (the browser keeps it in step with the
// radios, data-region="home-current"); a rotation keeps its home.
function homeCard(view: WorkspaceIntakeView | WorkspaceConnectView, slugs: ReadonlyMap<string, string>): Html {
  const choices = view.intent === "rotate" ? [view.home] : view.permittedHomes
  const words = (home: CredentialHome) => cardText(belongsToWords(home, slugs))
  if (choices.length <= 1) return html`<section class="card" data-region="home-choice"><p class="eyebrow">Belongs to</p><p><span class="belongs" data-belongs="${view.home.kind}" data-region="home-current">${words(view.home)}</span></p></section>`
  return html`<details class="fold card home-fold" data-region="home-choice">
    <summary>${icon("chevronRight")}<span>Belongs to: <span data-region="home-current">${words(view.home)}</span>. Change</span></summary>
    <fieldset class="field"><legend class="label">Where it belongs</legend>${choices.map((h) => html`<label class="tick"><input type="radio" form="decide" name="home" data-input="home" value="${homeKey(h)}"${homeKey(h) === homeKey(view.home) ? html` checked` : ""}><span data-region="home-label">${words(h)}</span></label>`)}</fieldset>
    <p class="small muted">The agent proposed ${words(view.home)}. Your passkey signs where it belongs.</p>
  </details>`
}

// The words the page shows for each home it offers, for the warnings.
function homeTexts(view: WorkspaceIntakeView | WorkspaceConnectView, slugs: ReadonlyMap<string, string>): string[] {
  return [view.home, ...view.permittedHomes].map((h) => belongsToWords(h, slugs))
}

// The legacy request pages are frozen (pages/intake.ts, pages/connect.ts);
// the workspace page rearranges what they render. Each cut names markup
// those files write once, and a missing one is an error, never a silent
// page without its check.
function cut(body: string, markup: string | RegExp): { body: string; taken: string } {
  const found = typeof markup === "string" ? (body.includes(markup) ? markup : null) : (markup.exec(body)?.[0] ?? null)
  if (found === null) throw new Error(`the request page no longer renders ${String(markup)}`)
  return { body: body.replace(found, ""), taken: found }
}

function replaceOnce(body: string, from: string, to: string): string {
  if (!body.includes(from)) throw new Error(`the request page no longer renders ${from}`)
  return body.replace(from, to)
}

function insertBefore(body: string, marker: string, insert: Html | string): string {
  const at = body.indexOf(marker)
  if (at === -1) throw new Error(`the request page no longer renders ${marker}`)
  return body.slice(0, at) + (typeof insert === "string" ? insert : insert.value) + body.slice(at)
}

// The accepting button's label as the legacy page wrote it (already
// escaped), for the bar.
function buttonLabel(button: string): Html {
  return new Html(button.replace(/^<button[^>]*>/, "").replace(/<\/button>$/, ""))
}

// Stop this request is in the bar only when the page is warned; otherwise
// the way to say no is to leave the link to run out.
function requestNext(kind: "intake" | "connect", warned: boolean): Html {
  const accepting = kind === "intake" ? "Saving seals each value on this device, and your passkey confirms where it belongs." : "Continuing asks your passkey, then the service's own sign-in; the vault checks the account it returns."
  const declining = warned ? `Stopping closes the link and ${kind === "intake" ? "stores" : "saves"} nothing.` : `Not expecting this? Close the page: nothing is ${kind === "intake" ? "stored" : "saved"}, and the link runs out by itself.`
  return html`<div class="ask-next">${notice("info", "What happens next", `${accepting} ${declining}`)}</div>`
}

// The live request's head card is its decision card: the ember ring, and
// the red line when warned.
function decisionHead(body: string, region: "intake-head" | "connect-head", warned: boolean): string {
  return replaceOnce(body, `<section class="card ${region}" data-region="${region}">`, `<section class="card decision ${region}${warned ? " warned" : ""}" data-region="${region}">`)
}

// `fill`: BROWSER_FILL is on for this workspace (intakePage's choice).
export function workspaceIntakePage(shell: WorkspaceShell, view: WorkspaceIntakeView, projects: readonly WorkspaceProject[], now = Date.now(), fill = false): PageInput {
  const legacy = intakePage(NO_VIEWER, view, shell.identity.origin, now, fill)
  const slug = shell.identity.workspace.slug
  const slugs = new Map(projects.map((p) => [p.id, p.slug]))
  const open = legacy.boot.page === "intake"
  const base = { ...legacy, viewer: null, workspace: shell }
  // Every state shows who asked and why: warned in each of them.
  const warnings = askWarnings([...intakeTexts(view), shell.identity.workspace.name, shell.identity.workspace.slug, ...homeTexts(view, slugs)])
  const warned = warnings.length > 0
  if (!open) return { ...base, boot: { ...legacy.boot, page: "intake-closed" }, body: html`${warningCard(warnings)}${workspaceLinks(legacy.body, slug)}` }
  const { body: withoutButton, taken } = cut(workspaceLinks(legacy.body, slug).value, /<button type="button" class="btn primary" data-action="submit-intake" disabled>[\s\S]*?<\/button>/)
  const formed = replaceOnce(withoutButton, '<form class="stack" data-form="intake"', '<form class="stack" id="decide" data-form="intake"')
  const body = insertBefore(decisionHead(formed, "intake-head", warned), '<div class="two-col" data-region="intake-columns">', homeCard(view, slugs))
  return {
    ...base,
    bar: true,
    boot: { ...legacy.boot, page: "ws-intake", home: view.home, homes: view.intent === "rotate" ? [view.home] : view.permittedHomes, ...(view.then !== undefined ? { then: view.then.connect } : {}) },
    body: html`${heldNotice(shell, "intake")}${warningCard(warnings)}${new Html(body)}${requestNext("intake", warned)}${decisionBar({
      warned,
      form: "decide",
      caption: html`Turns on once the form is complete. ${PASSKEY_CONFIRMS_WORDS}`,
      decline: warned ? { action: "cancel-request", label: "Stop this request", attributes: html` data-kind="intake" data-id="${view.intake}"` } : null,
      accept: { action: "submit-intake", label: buttonLabel(taken), passkey: true, disabled: true },
    })}`,
  }
}

// Every term of the connect.start the passkey will sign, as this page read
// them, without the home (the person's choice): the browser refuses any
// prepared action that differs in one of them.
export function connectTerms(view: WorkspaceConnectView): ConnectTerms {
  return { provider: view.provider, slug: view.slug, tags: view.tags, expectedAccount: view.expect, scopes: view.scopes, intent: view.intent, target: view.target?.item ?? null, targetRevision: view.target?.configRevision ?? null, client: view.client?.item ?? null, clientRevision: view.client?.configRevision ?? null, dependencyRevision: view.dependencyRevision }
}

// The client the connect chose was rejected by its provider: signing in
// cannot work until its secret is replaced, so Continue stays off. The
// client is named and linked only when the reader may see it.
function clientRejectedNotice(slug: string, view: WorkspaceConnectView): Html {
  const rejected = view.clientRejected
  if (rejected === undefined) return html``
  const client = rejected.client === null ? "its OAuth client" : html`its OAuth client, <a href="${workspaceHref(slug, `/items/${encodeURIComponent(rejected.client)}`)}">${cardText(rejected.client)}</a>`
  return html`<div data-region="connect-client-rejected">${notice("warn", `${view.providerName} rejected the OAuth client this connection signs in through`, html`Its secret is wrong, expired or deleted, so signing in cannot work. Replace the secret of ${client}; this link was made for the client as it was, so then reconnect from the credential's page or ask the agent for a new link.`)}</div>`
}

export function workspaceConnectPage(shell: WorkspaceShell, view: WorkspaceConnectView, projects: readonly WorkspaceProject[], now = Date.now()): PageInput {
  const legacy = connectPage(NO_VIEWER, view, now)
  const slug = shell.identity.workspace.slug
  const slugs = new Map(projects.map((p) => [p.id, p.slug]))
  const open = legacy.boot.page === "connect"
  const base = { ...legacy, viewer: null, workspace: shell }
  const warnings = askWarnings([...connectTexts(view), shell.identity.workspace.name, shell.identity.workspace.slug, ...homeTexts(view, slugs)])
  const warned = warnings.length > 0
  if (!open) return { ...base, boot: { ...legacy.boot, home: view.home }, body: html`${warningCard(warnings)}${workspaceLinks(legacy.body, slug)}` }
  const { body: withoutButton, taken } = cut(workspaceLinks(legacy.body, slug).value, /<button type="button" class="btn primary" data-action="start-connect" disabled>[\s\S]*?<\/button>/)
  const body = insertBefore(decisionHead(withoutButton, "connect-head", warned), '<div data-region="connect-expired" hidden>', html`<form id="decide" data-form="connect" novalidate>${homeCard(view, slugs)}</form>`)
  return {
    ...base,
    bar: true,
    boot: { ...legacy.boot, page: "ws-connect", home: view.home, homes: view.intent === "rotate" ? [view.home] : view.permittedHomes, terms: connectTerms(view), ...(view.clientRejected !== undefined ? { blocked: true } : {}) },
    body: html`${heldNotice(shell, "connect")}${warningCard(warnings)}${clientRejectedNotice(slug, view)}${new Html(body)}${requestNext("connect", warned)}${decisionBar({
      warned,
      form: "decide",
      caption: html`Signing in at ${view.providerName} comes after your passkey.`,
      decline: warned ? { action: "cancel-request", label: "Stop this request", attributes: html` data-kind="connect" data-id="${view.connect}"` } : null,
      accept: { action: "start-connect", label: buttonLabel(taken), passkey: true, disabled: true },
    })}`,
  }
}

// ---------------------------------------------------------------- policy proposals

type PolicyStopView = Extract<PolicyRuleProposalViewProjection, { view: "stop" }>

// A proposal's stop view (/w/<slug>/p/<id>), for someone who may only stop a
// private rule proposal: the shared stop page.
export function workspacePolicyPage(shell: WorkspaceShell, view: PolicyStopView): PageInput {
  const stop = stopPage(view, shell.identity.origin)
  return { title: "Stop a request", viewer: null, workspace: shell, focus: true, bar: stop.bar, boot: { page: "ws-policy", proposal: view.id, view: "stop" }, body: stop.body }
}

// ---------------------------------------------------------------- rule proposals

type RuleProposalDetail = Extract<PolicyRuleProposalViewProjection, { view: "detail" }>["proposal"]
// The credential as the person may read it, for its account and service;
// null when they may not.
export type RuleProposalItem = { provider: string | null; account: string | null } | null

// Every string the rule proposal page shows: the agent's reason, the
// vault's summary, who asked, the terms and every path offered, who
// approved, the workspace and the owner.
export function ruleProposalTexts(view: RuleProposalDetail, item: RuleProposalItem): string[] {
  const by = view.requestedBy
  const t = view.terms
  return [
    view.reason ?? "",
    view.item,
    view.summary,
    view.bindingCode,
    view.extends ?? "",
    ..."device" in by ? [by.deviceName, by.device, by.session ?? "", by.workload?.label ?? ""] : [],
    ...view.pathChoices,
    t.item, t.itemId, t.asker.device, t.asker.workload ?? "", t.method, t.host, t.path, t.anchorPath, ...t.queryNames, ...(t.graphql?.fields ?? []), ...(t.graphql?.nestedFields ?? []),
    view.approvedBy?.name ?? "",
    item?.account ?? "",
    view.workspace.name,
    view.workspace.slug,
    view.owner.name,
  ]
}

// Why this person has no Approve on a pending proposal, in the vault's own
// words where the page can tell which applies.
function ruleProposalCannotApprove(view: RuleProposalDetail): string {
  if (view.stage === "approve") return RULE_PROPOSAL_OWNER_ONLY_WORDS
  return view.approvedBy?.self === true ? RULE_PROPOSAL_OWN_APPROVAL_WORDS : RULE_PROPOSAL_SECOND_PERSON_WORDS
}

// The rule proposal page: the decision card (what is proposed, the
// workspace once, who approved when it waits for a co-signer, the code to
// tick on an agent's own proposal), the rule panel with the agent's reason
// and the narrowing choices (or, for someone who may not approve, the terms
// as they stand), what happens next, the digests in a fold, and the bar:
// Deny and Approve with passkey, each only for someone who may.
export function workspaceRuleProposalPage(shell: WorkspaceShell, view: Extract<PolicyRuleProposalViewProjection, { view: "detail" }>, item: RuleProposalItem, now = Date.now()): PageInput {
  const p = view.proposal
  const t = p.terms
  const origin = shell.identity.origin
  const warnings = askWarnings(ruleProposalTexts(p, item))
  const warned = warnings.length > 0
  const pending = p.status === "pending"
  const approving = pending && p.canApprove
  const deciding = pending && (p.canApprove || p.canDeny)
  // An agent's own proposal shows its code; a co-sign waits for people only.
  const coded = approving && p.stage === "approve" && "device" in p.requestedBy
  const by = p.requestedBy
  const machine = "device" in by && by.device === t.asker.device ? by.deviceName : t.asker.device
  const task = t.asker.workload === null ? null : "device" in by && by.workload?.id === t.asker.workload ? by.workload.label : t.asker.workload
  // An extension moves only the rule's end: its own path, the new duration.
  const paths = p.extends !== null ? [t.path] : ruleProposalPaths(t, p.pathChoices)
  const durations = p.extends !== null ? [t.ttlSeconds] : ruleProposalDurations(t)
  const title = p.extends !== null ? ruleExtendTitle(p.extends, t.ttlSeconds) : `${RULE_PROPOSAL_TITLE}: ${t.item}`
  const eyebrow = "device" in by ? html`An agent on <b class="asker-name">${cardText(by.deviceName)}</b> proposes` : html`${p.extends !== null ? RULE_EXTEND_EYEBROW : RULE_COSIGN_EYEBROW}`
  const approved = p.stage === "co-sign" ? html`<p class="small" data-region="rule-approved-by">${cardText(ruleApprovedByWords(p.approvedBy?.name ?? null))}</p>` : ""
  const settled = p.status === "approved" && p.rule !== null ? (p.extends !== null ? ruleProposalExtendedWords(p.rule.id, Date.parse(p.rule.endsAt)) : ruleAllowedWords(Date.parse(p.rule.endsAt))) : RULE_PROPOSAL_SETTLED_WORDS[p.status as Exclude<typeof p.status, "pending">]
  const body = html`${warningCard(warnings)}<section class="card decision${warned ? " warned" : ""}" aria-label="The decision" data-region="decision">
    <div class="decision-head">${serviceTile({ provider: item?.provider ?? null, slug: t.item }, "lg")}<div><p class="eyebrow">${eyebrow}</p><h1>${cardText(title)}</h1></div></div>
    <p class="who ask-context">${askPlace(origin, p.workspace)}, for a machine owned by ${cardText(p.owner.kind === "member" ? p.owner.name : `the team ${p.owner.name}`)}${"device" in by ? sessionWords(by) : ""}</p>
    ${taskLine(by)}
    <p class="small" data-region="rule-summary"><span class="muted">${"device" in by && p.stage === "approve" ? RULE_AGENT_PROPOSED_LABEL : RULE_PROPOSED_LABEL}</span> ${cardText(p.summary)}</p>
    ${approved}
    ${!pending
      ? html`<p class="strip" data-region="settled">${pill(p.status, p.status === "approved" ? "ok" : "muted")}</p><p class="small muted" data-region="settled-words">${settled}</p>`
      : deciding
        ? html`<form class="stack" id="decide" data-form="decide" novalidate>
          ${coded ? html`<label class="tick"><input type="checkbox" data-input="code-matches"><span>The agent showed me the code <code class="code-inline">${p.bindingCode}</code></span></label>` : ""}
          ${!approving ? html`<p class="small muted" data-region="cannot-approve">${ruleProposalCannotApprove(p)} You can deny it.</p>` : ""}
        </form>
        <p class="meta"><span class="timer-line">${countdownTimer(p.expiresAt, RULE_PROPOSAL_TTL_SECONDS, now)} <span class="muted">to decide</span></span></p>`
        : html`<p class="small muted" data-region="read-only">${RULE_PROPOSAL_READ_ONLY_WORDS}</p>`}
    <a class="jump" href="#truth">${icon("chevronDown")}<span>Read the proposal's digests below</span></a>
  </section>${ruleTermsPanel({
    terms: t,
    account: item?.account ?? null,
    machine,
    task,
    context: null,
    choices: approving ? { paths, path: t.path, durations, duration: t.ttlSeconds } : null,
    reason: p.reason,
    after: approving ? html`<p class="small refused" id="rule-mismatch" aria-live="polite" data-region="rule-mismatch" hidden>${RULE_PROPOSAL_MISMATCH_WORDS}</p>` : "",
  })}
  ${deciding ? html`<div class="ask-next">${notice("info", "What happens next", p.stage === "approve" ? RULE_PROPOSAL_NEXT_WORDS : RULE_COSIGN_NEXT_WORDS)}</div>` : ""}
  <div id="truth">${technicalFold([
    ["Code", html`<code class="code-inline">${p.bindingCode}</code>`],
    ["Proposal digest", html`<code class="hash">${p.digest}</code> <span data-region="digest-match" hidden>${pill("matches this page", "ok")}</span><span data-region="digest-mismatch" hidden>${pill("does not match this page", "danger")}</span>`],
    ["Terms digest", html`<code class="hash">${p.termsDigest}</code>`],
  ], html`<p class="small muted">Approve stays off until this page's own copy of the terms hashes to the vault's digests. Each decision is recorded in Activity.</p>`)}</div>
  ${deciding
    ? decisionBar({
        warned,
        form: "decide",
        terms: html`<span data-region="terms-text">${cardText(ruleChosenTermsWords(t, t.path, t.ttlSeconds))}</span>`,
        caption: approving ? (coded ? TICK_CODE_WORDS : CHECKING_PAGE_WORDS) : "",
        decline: p.canDeny ? { action: "deny", label: "Deny" } : null,
        accept: approving ? { action: "approve", label: "Approve with passkey", passkey: true, disabled: true } : null,
      })
    : ""}`
  const boot: RuleProposalBoot & { page: string; view: "detail"; coded: boolean } = { page: "ws-rule-proposal", view: "detail", coded, proposal: p.proposal, item: p.item, digest: p.digest, stage: p.stage, extends: p.extends, reason: p.reason, terms: t, termsDigest: p.termsDigest, pathChoices: paths }
  return { title, viewer: null, workspace: shell, focus: true, bar: deciding, boot, body: approving ? html`${heldNotice(shell, "approval")}${body}` : body }
}

// ---------------------------------------------------------------- the task grant proposal page

type AreaProposalDetail = PolicyAreaProposalViewProjection["proposal"]

// Every string the task grant proposal page shows: the reason, the vault's
// summary, who asked, the terms and each area's name and words, who
// approved, the workspace and the owner.
export function areaProposalTexts(view: AreaProposalDetail, item: RuleProposalItem): string[] {
  const by = view.requestedBy
  const t = view.terms
  return [
    view.reason ?? "",
    view.item,
    view.summary,
    view.bindingCode,
    ..."device" in by ? [by.deviceName, by.device, by.session ?? "", by.workload?.label ?? ""] : [],
    ...view.areas.flatMap((a) => [a.id, a.name, a.words]),
    t.item, t.itemId, t.asker.device, t.asker.workload ?? "", t.host, t.catalogue, ...t.areas,
    view.approvedBy?.name ?? "",
    item?.account ?? "",
    view.workspace.name,
    view.workspace.slug,
    view.owner.name,
  ]
}

// The task grant proposal page: the decision card (what is proposed, the
// workspace once, who approved first, the code on an agent's own
// proposal), the terms as they were signed, read only, and Approve with
// passkey or Deny; or, settled, what became of it.
export function workspaceAreaProposalPage(shell: WorkspaceShell, p: AreaProposalDetail, item: RuleProposalItem, now = Date.now()): PageInput {
  const t = p.terms
  const origin = shell.identity.origin
  const warnings = askWarnings(areaProposalTexts(p, item))
  const warned = warnings.length > 0
  const pending = p.status === "pending"
  const approving = pending && p.canApprove
  const deciding = pending && (p.canApprove || p.canDeny)
  const coded = approving && p.stage === "approve" && "device" in p.requestedBy
  const by = p.requestedBy
  const machine = "device" in by && by.device === t.asker.device ? by.deviceName : t.asker.device
  const task = t.asker.workload === null ? null : "device" in by && by.workload?.id === t.asker.workload ? by.workload.label : t.asker.workload
  const names = t.areas.map((id) => p.areas.find((a) => a.id === id)?.name ?? id)
  const title = `${AREA_PROPOSAL_TITLE}: ${t.item}`
  const eyebrow = "device" in by ? html`An agent on <b class="asker-name">${cardText(by.deviceName)}</b> proposes` : html`${AREA_COSIGN_EYEBROW}`
  const approved = p.stage === "co-sign" ? html`<p class="small" data-region="area-approved-by">${cardText(ruleApprovedByWords(p.approvedBy?.name ?? null))}</p>` : ""
  const settled = p.status === "approved" && p.rule !== null ? areaProposalAllowedWords(Date.parse(p.rule.endsAt), t.maxUses) : AREA_PROPOSAL_SETTLED_WORDS[p.status as Exclude<typeof p.status, "pending">]
  const cannot = p.stage === "approve" ? RULE_PROPOSAL_OWNER_ONLY_WORDS : p.approvedBy?.self === true ? RULE_PROPOSAL_OWN_APPROVAL_WORDS : RULE_PROPOSAL_SECOND_PERSON_WORDS
  const body = html`${warningCard(warnings)}<section class="card decision${warned ? " warned" : ""}" aria-label="The decision" data-region="decision">
    <div class="decision-head">${serviceTile({ provider: item?.provider ?? null, slug: t.item }, "lg")}<div><p class="eyebrow">${eyebrow}</p><h1>${cardText(title)}</h1></div></div>
    <p class="who ask-context">${askPlace(origin, p.workspace)}, for a machine owned by ${cardText(p.owner.kind === "member" ? p.owner.name : `the team ${p.owner.name}`)}${"device" in by ? sessionWords(by) : ""}</p>
    ${taskLine(by)}
    <p class="small" data-region="area-summary"><span class="muted">${"device" in by && p.stage === "approve" ? RULE_AGENT_PROPOSED_LABEL : RULE_PROPOSED_LABEL}</span> ${cardText(p.summary)}</p>
    ${approved}
    ${!pending
      ? html`<p class="strip" data-region="settled">${pill(p.status, p.status === "approved" ? "ok" : "muted")}</p><p class="small muted" data-region="settled-words">${settled}</p>`
      : deciding
        ? html`<form class="stack" id="decide" data-form="decide" novalidate>
          ${coded ? html`<label class="tick"><input type="checkbox" data-input="code-matches"><span>The agent showed me the code <code class="code-inline">${p.bindingCode}</code></span></label>` : ""}
          ${!approving ? html`<p class="small muted" data-region="cannot-approve">${cannot} You can deny it.</p>` : ""}
        </form>
        <p class="meta"><span class="timer-line">${countdownTimer(p.expiresAt, RULE_PROPOSAL_TTL_SECONDS, now)} <span class="muted">to decide</span></span></p>`
        : html`<p class="small muted" data-region="read-only">${RULE_PROPOSAL_READ_ONLY_WORDS}</p>`}
    <a class="jump" href="#truth">${icon("chevronDown")}<span>Read the proposal's digests below</span></a>
  </section><section class="card rule-panel" aria-label="${AREA_PANEL_TITLE}" data-region="area-panel">
    <h2>${AREA_PANEL_TITLE}</h2>
    <p class="small muted">${AREA_PROPOSAL_SIGNED_WORDS}</p>
    <dl class="kv"><dt>${AREA_PANEL_LABELS.credential}</dt><dd><code>${cardText(t.item)}</code>${item?.account ? html`, ${RULE_ACTING_AS_WORDS} ${cardText(item.account)}` : ""} <span class="muted small">on <code>${cardText(t.host)}</code></span></dd>
      <dt>${AREA_PANEL_LABELS.who}</dt><dd data-region="area-who">${cardText(ruleAskerWords(machine, task))}</dd>
      <dt>${AREA_PANEL_LABELS.areas}</dt><dd><ul class="plain" data-region="area-areas">${t.areas.map((id) => { const a = p.areas.find((x) => x.id === id); return html`<li><b>${cardText(a?.name ?? id)}</b>${a?.words ? html` <span class="muted small">${cardText(a.words)}</span>` : ""}</li>` })}</ul></dd>
      <dt>${AREA_PANEL_LABELS.ttl}</dt><dd data-region="area-ttl">${formatDuration(t.ttlSeconds)}</dd>
      <dt>${AREA_PANEL_LABELS.uses}</dt><dd data-region="area-uses">${areaUsesWords(t.maxUses)}</dd>
      <dt>${AREA_PANEL_LABELS.stillAsks}</dt><dd data-region="area-still-asks">${AREA_STILL_ASKS_WORDS}</dd>
      <dt>${AREA_PANEL_LABELS.endsSooner}</dt><dd>${AREA_ENDS_SOONER_WORDS}</dd></dl>
    ${p.reason !== null ? html`<p class="eyebrow">${RULE_REASON_LABEL}</p><p class="small muted">${RULE_REASON_WORDS}</p><blockquote class="reason" data-region="area-reason">${cardText(p.reason)}</blockquote>` : ""}
    ${approving ? html`<p class="small refused" id="area-mismatch" aria-live="polite" data-region="area-mismatch" hidden>${RULE_PROPOSAL_PAGE_MISMATCH_WORDS}</p>` : ""}
  </section>
  ${deciding ? html`<div class="ask-next">${notice("info", "What happens next", p.stage === "approve" ? AREA_PROPOSAL_NEXT_WORDS : AREA_COSIGN_NEXT_WORDS)}</div>` : ""}
  <div id="truth">${technicalFold([
    ["Code", html`<code class="code-inline">${p.bindingCode}</code>`],
    ["Proposal digest", html`<code class="hash">${p.digest}</code> <span data-region="digest-match" hidden>${pill("matches this page", "ok")}</span><span data-region="digest-mismatch" hidden>${pill("does not match this page", "danger")}</span>`],
    ["Terms digest", html`<code class="hash">${p.termsDigest}</code>`],
  ], html`<p class="small muted">Approve stays off until this page's own copy of the terms hashes to the vault's digests. Each decision is recorded in Activity.</p>`)}</div>
  ${deciding
    ? decisionBar({
        warned,
        form: "decide",
        terms: html`<span data-region="terms-text">${cardText(areaTermsWords(names, t.host, t.ttlSeconds, t.maxUses))}</span>`,
        caption: approving ? (coded ? TICK_CODE_WORDS : CHECKING_PAGE_WORDS) : "",
        decline: p.canDeny ? { action: "deny", label: "Deny" } : null,
        accept: approving ? { action: "approve", label: "Approve with passkey", passkey: true, disabled: true } : null,
      })
    : ""}`
  const boot: AreaProposalBoot & { page: string; view: "detail"; coded: boolean } = { page: "ws-area-proposal", view: "detail", coded, proposal: p.proposal, item: p.item, digest: p.digest, stage: p.stage, reason: p.reason, terms: t, termsDigest: p.termsDigest }
  return { title, viewer: null, workspace: shell, focus: true, bar: deciding, boot, body: approving ? html`${heldNotice(shell, "approval")}${body}` : body }
}

// A proposal from the route: a rule's detail goes to its own page, a task
// grant's to its own, and a stop view to workspacePolicyPage.
export function workspaceProposalPage(shell: WorkspaceShell, view: PolicyStandingProposalViewProjection, item: RuleProposalItem, now = Date.now()): PageInput {
  if (view.view === "stop") return workspacePolicyPage(shell, view)
  if (view.proposal.kind === "rule") return workspaceRuleProposalPage(shell, { view: "detail", proposal: view.proposal }, item, now)
  return workspaceAreaProposalPage(shell, view.proposal, item, now)
}
