// The operator's pages, in the account shell: every platform (/operator,
// which links to the Operators, Audit and Settings views,
// pages/operator-operators.ts, operator-audit.ts, operator-settings.ts),
// registering one (/operator/register) and one platform with everything
// scripts/platform.ts can do to it, and removing it so its slug can be
// used again (/operator/platforms/:slug). Only an operator reaches them;
// any other account gets the plain not-found page.
// Every change is signed with a fresh passkey for that exact change, and
// every destructive one also needs the platform's slug typed back; the
// vault checks both again and records each change as operator:<account>.
// Nothing here opens a secret or reads inside a managed workspace.

import type { OperatorPlatformDetail, OperatorPlatformList, OperatorPlatformSummary, OperatorRequirement, PlatformEventPage } from "@mehen/protocol/platform-console"
import { PLATFORM_RETIRE_MAX_DAYS, operatorRequirementsRefusal } from "@mehen/protocol/platform-console"
import type { WorkspaceCreationDefault } from "@mehen/protocol/workspace"
import { cardText, emptyState, notice, pageHead, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon, iconTile } from "../icons.ts"
import type { HeldSlugs } from "../client/console-logic.ts"
import type { PageInput } from "../layout.ts"
import type { AccountShell } from "../shell.ts"
import {
  LIMIT_KEYS,
  LIMIT_WORDS,
  actorText,
  eventsCard,
  keyFields,
  keyPowerLine,
  keyList,
  limitsList,
  liveSubjects,
  overlapField,
  platformFacts,
  platformStatusPill,
  readFailed,
  reasonField,
  revokeKeyFold,
  slugConfirm,
  subjectStats,
  usageBlock,
} from "./platform-console.ts"

export const OPERATOR_PATH = "/operator"
export const OPERATOR_REGISTER_PATH = "/operator/register"

export function operatorPlatformPath(slug: string): string {
  return `/operator/platforms/${encodeURIComponent(slug)}`
}

const NEVER_INSIDE = "Nothing here opens a secret or acts inside a managed workspace."

// ---------------------------------------------------------------- /operator

function removalWords(platform: OperatorPlatformSummary): string | null {
  const removal = platform.removal
  if (removal === null) return null
  return removal.completedAt !== null ? `removed, ${removal.slug} freed` : `being removed, ${removal.slug} freed once every subject is purged`
}

function platformRow(platform: OperatorPlatformSummary): Html {
  const live = platform.keys.filter((k) => k.live).length
  const removal = removalWords(platform)
  return html`<li class="row" data-platform="${platform.slug}">${iconTile("globe")}<a class="row-main" href="${operatorPlatformPath(platform.slug)}"><span class="row-title">${cardText(platform.name)} <code>${platform.slug}</code></span><span class="row-sub">${removal ?? html`${liveSubjects(platform.subjects)} live subjects of ${platform.limits.subjects.toLocaleString("en-GB")}${platform.subjects.deleting > 0 ? ` · ${platform.subjects.deleting} being deleted` : ""} · ${live === 1 ? "1 live key" : `${live} live keys`}${platform.admins.length > 0 ? ` · ${platform.admins.length === 1 ? "1 admin" : `${platform.admins.length} admins`}` : ""}`}</span></a><span class="row-side">${platformStatusPill(platform.status)}</span></li>`
}

// This deployment's workspace creation default (the Settings view's,
// capped by WORKSPACE_CREATION), and how the Accounts view changes it for
// one account.
export function workspaceCreationWords(rule: WorkspaceCreationDefault): string {
  return rule === "accounts"
    ? "Workspace creation is on for every account (Settings). Deny on an account's page in Accounts turns it off for that account, and Allow or Back to default undoes that."
    : "Workspace creation is only for accounts an operator allows on the account's page in Accounts (Settings)."
}

// What the operator's own account lacks, said before any passkey is asked
// for; nothing when it has everything.
export function operatorRequirementsNotice(missing: readonly OperatorRequirement[]): Html {
  if (missing.length === 0) return html``
  return html`<div data-region="operator-requirements">${notice("warn", "Your changes here will be refused until your account has what an operator needs", operatorRequirementsRefusal(missing), html`<a class="btn secondary sm" href="/account">Open Your account</a>`)}</div>`
}

// `list` is null when it could not be read.
export function operatorListPage(account: AccountShell, list: OperatorPlatformList | null): PageInput {
  const register = html`<a class="btn primary" href="${OPERATOR_REGISTER_PATH}">${icon("plus")}<span>Register a platform</span></a>`
  const operators = html`<a class="btn secondary" href="/operator/operators" data-region="operators-link">${icon("users")}<span>Operators</span></a><a class="btn secondary" href="/operator/workspaces" data-region="workspaces-link">${icon("folder")}<span>Workspaces</span></a><a class="btn secondary" href="/operator/accounts" data-region="accounts-link">${icon("users")}<span>Accounts</span></a><a class="btn secondary" href="/operator/audit" data-region="audit-link">${icon("list")}<span>Audit</span></a><a class="btn secondary" href="/operator/settings" data-region="settings-link">${icon("sliders")}<span>Settings</span></a>`
  const body = list === null
    ? readFailed("The platforms")
    : list.platforms.length === 0
      ? emptyState("globe", "No platforms yet", "A platform is a business that serves its own users through Mehen. Register one with its public key.", register)
      : html`<ul class="rows" data-region="platforms">${list.platforms.map(platformRow)}</ul>`
  return {
    title: "Operator",
    viewer: null,
    account,
    current: "operator",
    boot: { page: "operator" },
    body: html`${pageHead({ eyebrow: "Operator", title: "Platforms", lead: `Every platform registered at this vault. Register, watch, limit, suspend, rotate keys, retire and remove them here, as the operator script does. ${NEVER_INSIDE}`, actions: html`${operators}${list !== null && list.platforms.length > 0 ? register : ""}` })}
      ${list !== null ? operatorRequirementsNotice(list.missing) : ""}
      <section class="card">${body}</section>
      ${list !== null ? html`<p class="small muted" data-region="workspace-creation">${workspaceCreationWords(list.workspaceCreation)}</p>` : ""}
      <p class="small muted">Each change asks for your passkey, is recorded in the platform's events as you and leaves a notice on your account. The operator script still works, from a machine no agent reaches.</p>`,
  }
}

// ---------------------------------------------------------------- /operator/register

// The slugs the platforms listed hold, so the form refuses one before the
// passkey; a removed platform's own slug is already its removed- one.
export function heldSlugs(platforms: readonly OperatorPlatformSummary[]): HeldSlugs {
  return Object.fromEntries(platforms.map((p) => [p.slug, p.removal !== null && p.removal.completedAt === null ? "removing" : "registered"]))
}

export function operatorRegisterPage(account: AccountShell, platforms: readonly OperatorPlatformSummary[]): PageInput {
  return {
    title: "Register a platform",
    viewer: null,
    account,
    current: "operator",
    boot: { page: "operator-register", heldSlugs: heldSlugs(platforms) },
    body: html`${pageHead({ eyebrow: html`<a href="${OPERATOR_PATH}">Operator</a>`, title: "Register a platform", lead: "A name, a slug and the platform's public key. It starts active with the default limits; change them on its page afterwards." })}
      <section class="card narrow" data-region="register">
        <form class="stack" data-form="platform-register" novalidate>
          <label class="field"><span class="label">Name</span><input type="text" data-input="name" maxlength="64" required autocomplete="off"><span class="hint">What you call the platform. At most 64 characters.</span></label>
          <label class="field"><span class="label">Slug</span><input type="text" class="mono" data-input="slug" maxlength="40" required autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="globex"><span class="hint">3 to 40 lower-case letters, digits and single hyphens, starting with a letter. It names the platform in every record and cannot change.</span></label>
          ${keyFields("register", "The platform's public key")}
          ${keyPowerLine()}
          ${slugConfirm(null)}
          <div class="actions"><button type="submit" class="btn primary">${icon("passkey")}<span>Register with passkey</span></button></div>
        </form>
      </section>
      <section class="card narrow" data-region="register-done" hidden>
        <h2>Registered</h2>
        <p>Give the platform both ids for its configuration. Neither is a secret.</p>
        <div class="field"><span class="label">Platform id</span><div class="copybox"><code data-region="done-platform"></code><button type="button" class="btn secondary sm" data-copy>${icon("copy")}<span>Copy</span></button></div></div>
        <div class="field"><span class="label">Key id</span><div class="copybox"><code data-region="done-key"></code><button type="button" class="btn secondary sm" data-copy>${icon("copy")}<span>Copy</span></button></div></div>
        <div class="actions"><a class="btn secondary" data-region="done-link" href="${OPERATOR_PATH}">Open the platform</a></div>
      </section>`,
  }
}

// ---------------------------------------------------------------- /operator/platforms/:slug

// `events` is null when its read failed; `older` the address of the next
// page of events, or null at the end.
export type OperatorPlatformPageData = { platform: OperatorPlatformDetail; events: PlatformEventPage | null; older: string | null; now: number }

// Which changes the platform's status allows, as scripts/platform.ts plans
// them; the vault checks the same again. A platform being removed allows
// none.
export type OperatorControls = { suspend: boolean; resume: boolean; keys: boolean; limits: boolean; deleteSubjects: boolean; retire: boolean; retireNowOnly: boolean; admins: boolean; remove: boolean }

export function operatorControls(platform: OperatorPlatformSummary, now: number): OperatorControls {
  const { status, retireAfter } = platform
  const open = platform.removal === null
  const live = open && status !== "retired"
  return {
    suspend: open && (status === "active" || status === "retiring"),
    resume: open && (status === "suspended" || (status === "retiring" && retireAfter !== null && Date.parse(retireAfter) > now)),
    keys: live,
    limits: live,
    deleteSubjects: open && liveSubjects(platform.subjects) > 0,
    retire: open && (status === "active" || status === "suspended"),
    retireNowOnly: status === "suspended",
    admins: live,
    remove: open,
  }
}

function removalNotice(platform: OperatorPlatformSummary): Html {
  const removal = platform.removal
  if (removal === null) return html``
  if (removal.completedAt !== null) return html`<div data-region="removal">${notice("info", html`Removed. Its slug <code>${removal.slug}</code> was freed ${timeTag(removal.completedAt)}.`, html`Removal started ${timeTag(removal.requestedAt)} by ${actorText(removal.by)}. The row, its keys' public halves, its events and each subject's tombstone are kept for the record under <code>${platform.slug}</code>.`)}</div>`
  return html`<div data-region="removal">${notice("warn", html`Being removed since ${timeTag(removal.requestedAt)}, by ${actorText(removal.by)}.`, html`Its calls are refused. The cron deletes and purges its subjects; once the last is purged it frees the slug <code>${removal.slug}</code>. The cron runs every 15 minutes, so with 50 subjects or fewer that is within 30 minutes. Nothing here changes it meanwhile.`)}</div>`
}

function statusCard(platform: OperatorPlatformDetail, controls: OperatorControls): Html {
  const suspend = controls.suspend
    ? html`<details class="fold" data-region="suspend"><summary>${icon("chevronRight")}<span>Suspend</span></summary>
        <form class="stack" data-form="platform-suspend" novalidate>
          <p class="small">Its own calls are refused at once and its devices' within 30 seconds. Nothing is deleted.${platform.status === "retiring" ? " Its retirement date is cleared." : ""}</p>
          ${reasonField("Kept in the platform's record.")}
          ${slugConfirm(platform.slug)}
          <div class="actions"><button type="submit" class="btn danger-quiet">${icon("passkey")}<span>Suspend with passkey</span></button></div>
        </form></details>`
    : ""
  const resume = controls.resume
    ? html`${platform.status === "retiring" ? html`<p class="small" data-region="resume-retiring">Resuming cancels its retirement: it stays registered and takes new subjects again.</p>` : ""}<form class="actions" data-form="platform-resume"><button type="submit" class="btn widen">${icon("passkey")}<span>Resume with passkey</span></button></form>`
    : ""
  return html`<section class="card" data-region="status"><h2>The platform</h2><div class="stack">${platformFacts(platform)}
    <p class="small muted">Defaults revision ${platform.defaultsRevision}. The platform sets its defaults, and so can its admins.</p>
    ${resume}</div>${suspend}</section>`
}

function usageCard(platform: OperatorPlatformDetail): Html {
  const changes = platform.operatorActions24h
  return html`<section class="card" data-region="usage"><h2>Subjects and usage</h2>
    <div class="stack">${subjectStats(platform.subjects)}
    ${usageBlock(platform.usage)}
    <p class="small muted" data-region="operator-actions">${changes === 1 ? "1 operator change" : `${changes} operator changes`} in the last 24 hours. Its subjects and what is inside their workspaces are the platform's; this page never lists them.</p></div></section>`
}

function keysCard(platform: OperatorPlatformDetail, controls: OperatorControls): Html {
  const rotate = controls.keys
    ? html`<details class="fold" data-region="rotate"><summary>${icon("chevronRight")}<span>Add a key and rotate</span></summary>
        <form class="stack" data-form="rotate-key" novalidate>
          ${keyFields("rotate", "The new public key")}
          ${overlapField()}
          ${keyPowerLine()}
          ${slugConfirm(platform.slug)}
          <div class="actions"><button type="submit" class="btn secondary">${icon("passkey")}<span>Add key with passkey</span></button></div>
        </form></details>`
    : ""
  return html`<section class="card" data-region="keys-card"><h2>Keys</h2>
    <p class="small muted">The public halves only.</p>
    ${keyList(platform.keys)}
    ${rotate}${controls.keys ? revokeKeyFold(platform.slug, platform.keys, false) : ""}</section>`
}

function limitsCard(platform: OperatorPlatformDetail, controls: OperatorControls): Html {
  const form = controls.limits
    ? html`<details class="fold" data-region="limits-edit"><summary>${icon("chevronRight")}<span>Change limits</span></summary>
        <form class="stack" data-form="platform-limits" novalidate>
          ${LIMIT_KEYS.map((key) => html`<label class="field"><span class="label">${LIMIT_WORDS[key].label}</span><input type="text" inputmode="numeric" class="mono" data-limit="${key}" value="${platform.limits[key]}" maxlength="9" autocomplete="off"><span class="hint">${LIMIT_WORDS[key].hint}</span></label>`)}
          <p class="small muted">Only the limits you change are sent. Every workspace reads them within 30 seconds, and the platform's call counters use them at once. Read the last day's usage before raising or lowering one.</p>
          <div class="actions"><button type="submit" class="btn secondary">${icon("passkey")}<span>Save limits with passkey</span></button></div>
        </form></details>`
    : ""
  return html`<section class="card" data-region="limits"><h2>Limits</h2>${limitsList(platform.limits)}${form}</section>`
}

function adminsCard(platform: OperatorPlatformDetail, controls: OperatorControls): Html {
  const rows = platform.admins.length === 0
    ? html`<p class="muted" data-region="no-admins">No admins yet. An admin finds this platform under Platforms in their own account, edits its defaults, adds and revokes its keys and deletes one subject at a time. Only you register, suspend, retire, remove it or change its limits.</p>`
    : html`<ul class="rows" data-region="admin-rows">${platform.admins.map((a) => html`<li class="row" data-admin="${a.account}"><span class="row-main"><span class="row-title">${cardText(a.name)}</span><span class="row-sub"><code>${a.account}</code></span><span class="row-sub">Added ${timeTag(a.addedAt)} by ${actorText(a.addedBy)}</span></span>${controls.admins ? html`<span class="row-side"><button type="button" class="btn danger-quiet sm" data-action="remove-admin" data-account="${a.account}">${icon("passkey")}<span>Remove</span></button></span>` : ""}</li>`)}</ul>`
  const add = controls.admins
    ? html`<details class="fold" data-region="admin-add"><summary>${icon("chevronRight")}<span>Add an admin</span></summary>
        <form class="stack" data-form="add-admin" novalidate>
          <label class="field"><span class="label">Their Mehen account id</span><input type="text" class="mono" data-input="account" maxlength="80" required autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="acc_..."><span class="hint">They find it on Your account. An admin cannot add other admins.</span></label>
          <div class="actions"><button type="submit" class="btn secondary">${icon("passkey")}<span>Add with passkey</span></button></div>
        </form></details>`
    : ""
  return html`<section class="card" data-region="admins"><h2>Platform admins</h2>${rows}${add}</section>`
}

// The destructive changes, folded at the bottom, each with what it does
// first and the slug typed back.
function dangerZone(platform: OperatorPlatformDetail, controls: OperatorControls): Html {
  const slug = platform.slug
  if (!controls.deleteSubjects && !controls.retire && !controls.remove) return html``
  const deleteSubjects = controls.deleteSubjects
    ? html`<details class="fold" data-region="delete-subjects"><summary>${icon("chevronRight")}<span>Delete every subject</span></summary>
        <form class="stack" data-form="delete-subjects" novalidate>
          <p class="small">Marks all ${liveSubjects(platform.subjects)} live subjects for deletion at once: their calls stop now and their devices' within 30 seconds. The cron deletes 50 a run; each subject's secrets go at once and its audit is kept for the platform's retention. The platform stays registered.</p>
          ${reasonField("Kept in the platform's record.")}
          ${slugConfirm(slug)}
          <div class="actions"><button type="submit" class="btn danger">${icon("passkey")}<span>Delete every subject with passkey</span></button></div>
        </form></details>`
    : ""
  const retire = controls.retire
    ? html`<details class="fold" data-region="retire"><summary>${icon("chevronRight")}<span>Retire</span></summary>
        <form class="stack" data-form="retire" novalidate>
          <p class="small">No new subjects from now. Until the date everything else keeps working; from it the platform's calls are refused, then every subject is deleted, its keys are revoked and it is marked retired. Its row stays, and so does its slug: remove it to free the slug.</p>
          ${controls.retireNowOnly
            ? html`<p class="small muted" data-region="retire-now">It is suspended, so it retires at once and stays stopped. Resume it first to give it a later date.</p><input type="hidden" data-input="after-days" value="0">`
            : html`<label class="field"><span class="label">Days until it retires</span><input type="text" inputmode="numeric" class="mono" data-input="after-days" value="30" maxlength="3" autocomplete="off"><span class="hint">0 to ${PLATFORM_RETIRE_MAX_DAYS}. 0 stops its calls now.</span></label>`}
          ${slugConfirm(slug)}
          <div class="actions"><button type="submit" class="btn danger">${icon("passkey")}<span>Retire with passkey</span></button></div>
        </form></details>`
    : ""
  const remove = controls.remove
    ? html`<details class="fold" data-region="remove"><summary>${icon("chevronRight")}<span>Remove completely</span></summary>
        <form class="stack" data-form="remove" novalidate>
          <p class="small">Retires it at once, so its calls stop now. The cron then deletes every subject and purges each one, and once the last is purged it frees the slug <code>${slug}</code> for a new platform: within 30 minutes for 50 subjects or fewer. It cannot be undone.</p>
          <p class="small muted">Kept for the record, with nothing secret in it: the platform's row under a reserved slug, its keys' public halves, every event on this page, and each subject's tombstone (a hash of its subject and its audit chain's final head).</p>
          ${reasonField("Kept in the platform's record.")}
          ${slugConfirm(slug)}
          <div class="actions"><button type="submit" class="btn danger">${icon("passkey")}<span>Remove ${slug} with passkey</span></button></div>
        </form></details>`
    : ""
  return html`<section class="card danger-zone" data-region="danger-zone"><h2>Danger zone</h2>${deleteSubjects}${retire}${remove}</section>`
}

export function operatorPlatformPage(account: AccountShell, data: OperatorPlatformPageData): PageInput {
  const { platform } = data
  const controls = operatorControls(platform, data.now)
  return {
    title: platform.name,
    viewer: null,
    account,
    current: "operator",
    wide: true,
    boot: { page: "operator-platform", platform: platform.slug, platformId: platform.id, limits: platform.limits },
    body: html`${pageHead({ eyebrow: html`<a href="${OPERATOR_PATH}">Operator</a>`, title: cardText(platform.name), lead: html`<code>${platform.slug}</code> ${platformStatusPill(platform.status)} ${NEVER_INSIDE}` })}
      ${removalNotice(platform)}
      <div class="two-col">
        <div class="col-main">
          ${statusCard(platform, controls)}
          ${usageCard(platform)}
          ${keysCard(platform, controls)}
          ${eventsCard(data.events, data.older)}
        </div>
        <div class="col-side">
          ${limitsCard(platform, controls)}
          ${adminsCard(platform, controls)}
          ${dangerZone(platform, controls)}
        </div>
      </div>`,
  }
}
