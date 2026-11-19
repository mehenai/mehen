// The Settings view (/operator/settings), in the Operator area: each
// deployment setting (workspace creation and sign-up) with the value in
// force, who set it, and the ceiling the deploy sets; a choice of every
// value, a narrower one taken at once with your passkey and a wider one
// proposed for a second operator to approve, with a wider choice disabled
// saying why (above the deploy's ceiling, not available yet, or no second
// operator); the open proposals to change a setting; and every change.
// Only an operator reaches it; anyone else gets the plain not-found page.

import { type DeploymentSettingKey, type DeploymentSettingValue, DEPLOYMENT_SETTING_NOT_BUILT, DEPLOYMENT_SETTING_WORDS, DEPLOYMENT_SETTINGS, deploymentSettingCeilingWords, deploymentSettingChange, deploymentSettingNotBuilt, deploymentSettingRank, deploymentSettingValues, deploymentSettingValueWords } from "@mehen/protocol/deployment-settings"
import { NEEDS_SECOND_OPERATOR_WORDS, type OperatorEventView, type OperatorProposalView } from "@mehen/protocol/operator-proposals"
import type { DeploymentSettingView, OperatorSettingsView } from "@mehen/protocol/operator-settings"
import { cardText, emptyState, notice, pageHead, pill, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import type { AccountShell } from "../shell.ts"
import { OPERATOR_PATH, operatorRequirementsNotice } from "./operator.ts"
import { actorText, readFailed } from "./platform-console.ts"

export const SETTINGS_PATH = "/operator/settings"

// What stops a choice, or null when the reader may take it.
function refusedChoice(view: OperatorSettingsView, setting: DeploymentSettingView, value: DeploymentSettingValue): string | null {
  if (deploymentSettingNotBuilt(setting.key, value)) return DEPLOYMENT_SETTING_NOT_BUILT
  if (deploymentSettingRank(setting.key, value) > deploymentSettingRank(setting.key, setting.ceiling)) return deploymentSettingCeilingWords(setting.key, setting.ceiling)
  if (deploymentSettingChange(setting.key, setting.value, value) === "widen" && view.operators < 2) return NEEDS_SECOND_OPERATOR_WORDS.change
  return null
}

// A stored value above a ceiling a later deploy lowered is what a narrowing
// moves away from, so the value in force can be stored in its place.
function narrowingFrom(setting: DeploymentSettingView): DeploymentSettingValue {
  return setting.stored !== null && deploymentSettingRank(setting.key, setting.stored) > deploymentSettingRank(setting.key, setting.ceiling) ? setting.stored : setting.value
}

function choice(view: OperatorSettingsView, setting: DeploymentSettingView, value: DeploymentSettingValue): Html {
  const label = deploymentSettingValueWords(setting.key, value)
  const inForce = value === setting.value ? html` ${pill("in force", "ok")}` : ""
  const change = deploymentSettingChange(setting.key, setting.value, value) === "widen" ? "widen" : deploymentSettingChange(setting.key, narrowingFrom(setting), value)
  if (change === "same") return html`<li class="row" data-choice="${value}"><span class="row-main"><span class="row-title">${label}${inForce}</span></span></li>`
  const refused = refusedChoice(view, setting, value)
  const kind = change === "narrow" ? "settings.narrow" : "settings.widen"
  const words = change === "narrow" ? "Narrow to this with passkey" : "Propose with passkey"
  const button = html`<button type="button" class="btn ${change === "narrow" ? "secondary" : "primary"} sm" data-action="setting" data-kind="${kind}" data-key="${setting.key}" data-value="${value}"${change === "widen" ? html` data-from="${setting.value}"` : ""} data-label="${label}"${refused !== null ? html` disabled title="${refused}"` : ""}>${icon("passkey")}<span>${words}</span></button>`
  const why = refused !== null ? html`<span class="row-sub small muted" data-region="refused">${refused}</span>` : html`<span class="row-sub small muted">${change === "narrow" ? "Applies at once: one operator, your passkey." : "A second operator approves it within 24 hours."}</span>`
  return html`<li class="row" data-choice="${value}"><span class="row-main"><span class="row-title">${label}${inForce}</span>${why}</span><span class="row-side">${button}</span></li>`
}

function storedLine(setting: DeploymentSettingView): Html {
  if (setting.stored === null || setting.updatedAt === null) return html`Nothing set here yet, so the deployment does what it did before settings.`
  const by = setting.updatedBy !== null ? html` by ${setting.updatedByName !== null ? html`${cardText(setting.updatedByName)} ` : ""}${actorText(setting.updatedBy)}` : ""
  const capped = setting.stored !== setting.value ? html` The deploy's ceiling caps it at ${deploymentSettingValueWords(setting.key, setting.value)}.` : ""
  return html`Set to ${deploymentSettingValueWords(setting.key, setting.stored)} ${timeTag(setting.updatedAt)}${by}.${capped}`
}

// A lone operator who narrows cannot widen again in the app.
function aloneWarning(view: OperatorSettingsView, setting: DeploymentSettingView): Html {
  if (view.operators >= 2 || deploymentSettingRank(setting.key, setting.value) === 0) return html``
  return html`<p class="small" data-region="alone">You are the only operator: once narrowed, widening this again needs a second operator or the script.</p>`
}

const SETTING_LEADS: Readonly<Record<DeploymentSettingKey, string>> = {
  workspace_creation: "Whether an account no operator decided on may create workspaces. Allowing or denying one account still wins over this.",
  signup_mode: "Who may make an account here. Stored and shown only: sign-up is by invitation whatever this says, until the other ways are built.",
}

function settingCard(view: OperatorSettingsView, setting: DeploymentSettingView): Html {
  const title = DEPLOYMENT_SETTING_WORDS[setting.key].title
  return html`<section class="card" data-region="setting" data-setting="${setting.key}"><h2>${title}</h2>
    <p class="small">${SETTING_LEADS[setting.key]}</p>
    <p data-region="in-force">In force: <b>${deploymentSettingValueWords(setting.key, setting.value)}</b></p>
    <p class="small muted">${storedLine(setting)}</p>
    <p class="small" data-region="ceiling">Ceiling from the deploy: ${deploymentSettingValueWords(setting.key, setting.ceiling)} (<code>${DEPLOYMENT_SETTINGS[setting.key].ceilingVar}</code> is <code>${setting.ceiling}</code>). Narrowing: one operator · widening: two operators.</p>
    ${aloneWarning(view, setting)}
    <ul class="rows" data-region="choices">${deploymentSettingValues(setting.key).map((value) => choice(view, setting, value))}</ul>
  </section>`
}

// "workspace creation to Every account", from a setting's key and the
// value a change sets; `value` null is back to the deploy's default.
function settingWords(target: string, value: unknown): Html {
  const key = Object.hasOwn(DEPLOYMENT_SETTING_WORDS, target) ? (target as DeploymentSettingKey) : null
  const what = key !== null ? DEPLOYMENT_SETTING_WORDS[key].title.toLowerCase() : target
  if (typeof value !== "string") return html`${cardText(what)} back to the deploy's default`
  return html`${cardText(what)} to ${cardText(key !== null ? deploymentSettingValueWords(key, value as DeploymentSettingValue) : value)}`
}

function paramsValue(details: Readonly<Record<string, unknown>>): unknown {
  const params = details.params
  return typeof params === "object" && params !== null ? (params as Record<string, unknown>).value : undefined
}

const CHANGE_WORDS: Readonly<Record<string, string>> = { "settings.narrow": "Narrow", "settings.widen": "Widen" }

function openRow(view: OperatorSettingsView, p: OperatorProposalView): Html {
  const yours = p.proposedBy.account === view.you
  const actions = yours
    ? html`<span class="small muted">Waits for another operator.</span><button type="button" class="btn secondary sm" data-action="cancel" data-proposal="${p.id}">${icon("x")}<span>Cancel</span></button>`
    : html`<button type="button" class="btn primary sm" data-action="approve" data-proposal="${p.id}" data-digest="${p.digest}">${icon("passkey")}<span>Approve with passkey</span></button><button type="button" class="btn secondary sm" data-action="decline" data-proposal="${p.id}">${icon("x")}<span>Decline</span></button>`
  return html`<li class="row" data-proposal="${p.id}"><span class="row-main">
      <span class="row-title">${CHANGE_WORDS[p.kind] ?? cardText(p.kind)} ${settingWords(p.target, p.params.value)}</span>
      <span class="row-sub">Proposed ${timeTag(p.proposedAt)} by ${cardText(p.proposedBy.name)} <code>${p.proposedBy.account}</code> · expires ${timeTag(p.expiresAt)}</span>
      <span class="row-sub small muted">Digest <code>${p.digest}</code></span>
    </span><span class="row-side actions">${actions}</span></li>`
}

const HISTORY_WORDS: Readonly<Record<string, string>> = {
  "settings.narrow": "Narrowed",
  "settings.widen": "Widened",
  "settings.set": "Set by the script",
  "proposal.open": "Proposed",
  "proposal.decline": "Declined a proposal",
  "proposal.cancel": "Cancelled a proposal",
  "proposal.expire": "A proposal expired after 24 hours",
}

function historyRow(e: OperatorEventView): Html {
  const words = Object.hasOwn(HISTORY_WORDS, e.kind) ? HISTORY_WORDS[e.kind] : undefined
  const value = paramsValue(e.details)
  // A proposal's own events name what it proposed only when it was opened.
  const what = e.kind.startsWith("proposal.") && e.kind !== "proposal.open" ? html`${CHANGE_WORDS[String(e.details.kind)] ?? ""} ${cardText(e.target)}` : settingWords(e.target, value)
  return html`<li class="row"><span class="row-main"><span class="row-title">${words ?? html`<code>${cardText(e.kind)}</code>`}: ${what}</span>
    <span class="row-sub">${timeTag(e.at)} · ${actorText(e.actor)}${e.approver !== null ? html`, approved by ${actorText(e.approver)}` : ""}</span></span></li>`
}

// `view` is null when it could not be read.
export function operatorSettingsPage(account: AccountShell, view: OperatorSettingsView | null): PageInput {
  const head = pageHead({ eyebrow: html`<a href="${OPERATOR_PATH}">Operator</a>`, title: "Settings", lead: "What this deployment decides for every account. Narrowing is one operator's call with a passkey; widening needs a second operator, and never goes past the ceiling the deploy sets." })
  if (view === null) return { title: "Settings", viewer: null, account, current: "operator", boot: { page: "operator-settings" }, body: html`${head}<section class="card">${readFailed("The settings")}</section>` }
  return {
    title: "Settings",
    viewer: null,
    account,
    current: "operator",
    wide: true,
    boot: { page: "operator-settings" },
    body: html`${head}
      ${operatorRequirementsNotice(view.missing)}
      <div class="two-col">
        <div class="col-main">
          ${view.settings.map((setting) => settingCard(view, setting))}
          <section class="card" data-region="operators-needed"><h2>Operators needed for two-operator actions</h2><p><b>2</b> (fixed). ${view.operators === 1 ? "There is 1 operator now." : `There are ${view.operators} operators now.`}</p></section>
        </div>
        <div class="col-side">
          <section class="card" data-region="open-proposals"><h2>Open proposals</h2>${view.open.length === 0 ? html`<p class="muted">Nothing waiting.</p>` : html`<ul class="rows">${view.open.map((p) => openRow(view, p))}</ul>`}</section>
          <section class="card" data-region="settings-history"><h2>Changes</h2>${view.history.length === 0 ? emptyState("sliders", "No changes yet", "Every change to a setting, here or by the script, is recorded here and in the Audit view.") : html`<ul class="rows">${view.history.map(historyRow)}</ul>`}</section>
          ${view.operators < 2 ? notice("info", "You are the only operator", html`${NEEDS_SECOND_OPERATOR_WORDS.change} <code>scripts/operator.ts setting</code> is the break-glass.`) : ""}
        </div>
      </div>`,
  }
}
