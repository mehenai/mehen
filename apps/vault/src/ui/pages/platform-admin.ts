// A platform admin's pages, in the account shell: the platforms this
// account administers (/platforms) and one of them (/platforms/:slug).
// An admin reads the platform's status and limits, its subjects counted
// by status, its usage, keys and events; edits its defaults under the
// same schema as the platform's own defaults.put; adds a key (pasted or
// made here) and rotates with overlap; revokes a key, never the last live
// one; and deletes one subject by the subject string the platform knows.
// Each change is signed with a fresh passkey for that exact change and
// recorded as admin:<account id>. Registering, suspending, resuming,
// retiring, removing and limits are the operator's alone, and nothing
// here reads inside a managed workspace.

import type { AdminPlatformDetail, AdminPlatformList, AdminPlatformSummary, PlatformEventPage } from "@mehen/protocol/platform-console"
import type { PlatformDefaults } from "@mehen/protocol/platform"
import { cardText, emptyState, kv, notice, pageHead } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon, iconTile } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import type { AccountShell } from "../shell.ts"
import { eventsCard, keyFields, keyList, keyPowerLine, limitsList, liveSubjects, overlapField, platformFacts, platformStatusPill, readFailed, revokeKeyFold, slugConfirm, subjectStats, usageBlock } from "./platform-console.ts"

export const PLATFORMS_PATH = "/platforms"

export function adminPlatformPath(slug: string): string {
  return `/platforms/${encodeURIComponent(slug)}`
}

const NEVER_INSIDE = "Nothing here reads inside a managed workspace."

// ---------------------------------------------------------------- /platforms

function platformRow(platform: AdminPlatformSummary): Html {
  return html`<li class="row" data-platform="${platform.slug}">${iconTile("globe")}<a class="row-main" href="${adminPlatformPath(platform.slug)}"><span class="row-title">${cardText(platform.name)} <code>${platform.slug}</code></span><span class="row-sub">${liveSubjects(platform.subjects)} live subjects${platform.subjects.deleting > 0 ? ` · ${platform.subjects.deleting} being deleted` : ""}</span></a><span class="row-side">${platformStatusPill(platform.status)}</span></li>`
}

// `list` is null when it could not be read.
export function adminListPage(account: AccountShell, list: AdminPlatformList | null): PageInput {
  const body = list === null
    ? readFailed("Your platforms")
    : list.platforms.length === 0
      ? emptyState("globe", "No platforms", "Mehen's operator adds you as an admin of a platform. When they do, it is listed here.")
      : html`<ul class="rows" data-region="platforms">${list.platforms.map(platformRow)}</ul>`
  return {
    title: "Platforms",
    viewer: null,
    account,
    current: "platforms",
    boot: { page: "platforms" },
    body: html`${pageHead({ title: "Platforms", lead: `The platforms you administer. You manage their keys and defaults and can delete one of their subjects; Mehen's operator registers, limits, suspends and retires them. ${NEVER_INSIDE}` })}
      <section class="card">${body}</section>`,
  }
}

// ---------------------------------------------------------------- /platforms/:slug

// `events` is null when its read failed; `older` the address of the next
// page of events, or null at the end.
export type AdminPlatformPageData = { platform: AdminPlatformDetail; events: PlatformEventPage | null; older: string | null }

// A retired platform leaves an admin nothing to change. A suspended or
// retiring one keeps its keys and defaults editable, so a leak can be
// closed while it is stopped.
export function adminMayChange(platform: AdminPlatformSummary): boolean {
  return platform.status !== "retired"
}

// JSON for an editor: two-space indent, with every character outside
// printable ASCII written as a \u escape, so a hidden or direction
// character in a stored value is never put raw into an input.
export function jsonForEditing(value: unknown): string {
  return JSON.stringify(value, null, 2).replace(/[^\x20-\x7e\n]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`)
}

function idList(ids: readonly string[] | undefined, all: string): Html {
  if (ids === undefined) return html`${all}`
  if (ids.length === 0) return html`<span class="muted">none</span>`
  return html`${ids.map((id, i) => html`${i > 0 ? ", " : ""}<code>${cardText(id)}</code>`)}`
}

function countsById(entries: readonly (readonly [string, readonly unknown[]])[], none: string): Html {
  if (entries.length === 0) return html`<span class="muted">${none}</span>`
  return html`${entries.map(([id, list], i) => html`${i > 0 ? "; " : ""}<code>${cardText(id)}</code> ${list.length}`)}`
}

function defaultsSummary(defaults: PlatformDefaults): Html {
  return kv([
    ["Templates its users may add", idList(defaults.templates, "every template in the catalogue")],
    ["OAuth providers", idList(defaults.providers, "every provider in the catalogue")],
    ["Default scopes", countsById(Object.entries(defaults.scopes), "none set")],
    ["Tags on every new item", idList(defaults.tags, "")],
    ["Keys with no template", defaults.customReads === "allow" ? "reads go through without a hold" : "every request is held"],
    ["Rules added", countsById(Object.entries(defaults.rules), "none")],
  ], "facts")
}

function defaultsCard(platform: AdminPlatformDetail, change: boolean): Html {
  const editor = change
    ? html`<details class="fold" data-region="defaults-edit"><summary>${icon("chevronRight")}<span>Edit the defaults</span></summary>
        <form class="stack" data-form="defaults" novalidate>
          <label class="field"><span class="label">Defaults, as JSON</span><textarea data-input="defaults" rows="14" spellcheck="false" autocomplete="off" autocapitalize="off">${jsonForEditing(platform.defaults)}</textarea><span class="hint">The same shape and checks as the platform's own <code>PUT /v1/platform/defaults</code>. A rule may only hold (approve) or refuse (deny), never allow, so the defaults only ever narrow what the catalogue allows.</span></label>
          <ul class="inline-error" role="alert" data-region="defaults-problems" hidden></ul>
          <p class="small muted">Every workspace uses new defaults within 30 seconds, and approvals given under the old ones go stale. Saving moves the revision on from ${platform.defaultsRevision}; if it moved since this page loaded, reload and edit again.</p>
          <div class="actions"><button type="submit" class="btn secondary">${icon("passkey")}<span>Save defaults with passkey</span></button></div>
        </form></details>`
    : ""
  return html`<section class="card" data-region="defaults"><h2>Defaults</h2><p class="small muted">Revision <span class="mono">${platform.defaultsRevision}</span>, read live by every workspace of the platform.</p>${defaultsSummary(platform.defaults)}${editor}</section>`
}

function keysCard(platform: AdminPlatformDetail, change: boolean): Html {
  const add = change
    ? html`<details class="fold" data-region="add-key"><summary>${icon("chevronRight")}<span>Add a key and rotate</span></summary>
        <form class="stack" data-form="rotate-key" novalidate>
          ${keyFields("add-key", "The new public key")}
          ${overlapField()}
          ${keyPowerLine()}
          ${slugConfirm(platform.slug)}
          <div class="actions"><button type="submit" class="btn secondary">${icon("passkey")}<span>Add key with passkey</span></button></div>
        </form></details>`
    : ""
  return html`<section class="card" data-region="keys-card"><h2>Keys</h2>
    <p class="small muted">The public halves only.</p>
    ${keyList(platform.keys)}
    ${add}${change ? revokeKeyFold(platform.slug, platform.keys, true) : ""}</section>`
}

// One subject, by the string the platform knows it by, typed in: there is
// no list to pick from.
function deleteSubjectCard(platform: AdminPlatformDetail): Html {
  return html`<section class="card danger-zone" data-region="danger-zone"><h2>Danger zone</h2>
    <details class="fold" data-region="delete-subject"><summary>${icon("chevronRight")}<span>Delete one subject</span></summary>
      <form class="stack" data-form="delete-subject" novalidate>
        <p class="small">Deletes the user's managed workspace as the platform's own delete does: every device is revoked and every secret deleted at once, and the audit is kept for the platform's retention before the workspace is erased. It cannot be undone.</p>
        <label class="field"><span class="label">The subject</span><input type="text" class="mono" data-input="subject" maxlength="128" required autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"><span class="hint">The platform's own name for the user, exactly: 8 to 128 letters, digits, hyphens and underscores. Ask the platform for it.</span></label>
        ${slugConfirm(platform.slug)}
        <div class="actions"><button type="submit" class="btn danger">${icon("passkey")}<span>Delete this subject with passkey</span></button></div>
      </form></details></section>`
}

export function adminPlatformPage(account: AccountShell, data: AdminPlatformPageData): PageInput {
  const { platform } = data
  const change = adminMayChange(platform)
  return {
    title: platform.name,
    viewer: null,
    account,
    current: "platforms",
    wide: true,
    boot: { page: "platform-admin", platform: platform.slug, platformId: platform.id, defaultsRevision: platform.defaultsRevision },
    body: html`${pageHead({ eyebrow: html`<a href="${PLATFORMS_PATH}">Platforms</a>`, title: cardText(platform.name), lead: html`<code>${platform.slug}</code> ${platformStatusPill(platform.status)} ${NEVER_INSIDE}` })}
      ${change ? "" : html`<div data-region="retired">${notice("info", "This platform is retired.", "Its keys are revoked and its subjects deleted; there is nothing left to change.")}</div>`}
      <div class="two-col">
        <div class="col-main">
          <section class="card" data-region="usage"><h2>Subjects and usage</h2><div class="stack">${subjectStats(platform.subjects)}${usageBlock(platform.usage)}</div></section>
          ${keysCard(platform, change)}
          ${defaultsCard(platform, change)}
          ${eventsCard(data.events, data.older)}
        </div>
        <div class="col-side">
          <section class="card" data-region="status"><h2>Status and limits</h2><div class="stack">${platformFacts(platform)}<h3>Limits</h3>${limitsList(platform.limits)}<p class="small muted">Only Mehen's operator changes these. Ask them to raise a limit or lift a suspension.</p></div></section>
          ${change ? deleteSubjectCard(platform) : ""}
        </div>
      </div>`,
  }
}
