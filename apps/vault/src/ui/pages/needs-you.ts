// /needs-you: everything the signed-in account may act on, in every
// workspace it is active in, grouped by workspace and soonest expiry first
// as the vault orders it (GET /api/needs-you). Each row deep-links to the
// exact page where the decision is made. The first list is drawn here; the
// client polls with the validator and redraws the list in place
// (client/pages/needs-you.ts). A workspace that could not be read, or asks
// for an identity check first, keeps a group saying so; the page never says
// "Nothing needs you" while one of them is missing.

import type { InboxResponse, InboxWorkspace } from "@mehen/protocol/inbox"
import type { WorkspaceNotice } from "@mehen/protocol/workspace"
import { cardText, emptyState, notice, pageHead, pill, timeTag } from "../components.ts"
import { type Html, html, isVaultPath } from "../html.ts"
import { inboxRow, inboxRowOf } from "../inbox-row.ts"
import type { PageInput } from "../layout.ts"
import { type AccountShell, workspaceHref } from "../shell.ts"
import { mandateEndingWords, mandateLapsedNoticeWords, mandateSignedWords, mandateTrippedWords, shareRequestedWords } from "../wording.ts"
import { LOAD_FAILED_SENTENCE, LOAD_FAILED_TITLE, NEEDS_YOU_PATH, RETRYING_WORDS, SESSION_ENDED_WORDS, emptyWords, inboxGroups, needsYouTitle } from "../client/pages/needs-you-logic.ts"

function groupHead(w: InboxWorkspace, rows: number): Html {
  const count = w.state === "ok" && rows > 0 ? pill(w.truncated ? `${rows}+ waiting` : `${rows} waiting`, "accent", false) : html``
  return html`<div class="card-head"><h2><a href="${workspaceHref(w.workspace.slug)}">${cardText(w.workspace.name)}</a> <code class="slug">${w.workspace.slug}</code></h2>${count}</div>`
}

// Why a workspace has no rows here although it may have something waiting.
// `here`: the page is that workspace's own filter, so no link to itself.
export function groupNotice(w: InboxWorkspace, here = false): Html {
  const name = cardText(w.workspace.name)
  if (w.state === "gated") return notice("warn", html`Verify your identity to see what needs you in ${name}`, undefined, html`<a class="btn secondary sm" href="${workspaceHref(w.workspace.slug)}">Open ${name}</a>`)
  if (w.state === "unavailable" && w.reason === "limit") return notice("info", html`${name} is past the first 20 workspaces this page reads`, undefined, html`<a class="btn secondary sm" href="${workspaceHref(w.workspace.slug, "/pending")}">See what waits there</a>`)
  if (w.state === "unavailable") return notice("warn", html`Could not read ${name} just now; retrying.`)
  if (w.truncated) return html`<p class="muted small" data-region="needs-truncated">This is a partial list for ${name}; completing requests may reveal more.${here ? "" : html` <a href="${workspaceHref(w.workspace.slug, "/pending")}">Open this workspace's requests</a>.`}</p>`
  return html``
}

// The list region the client replaces in place: one card per workspace,
// under its name, so rows never need a workspace label of their own. Its
// groups carry their
// workspace and state, so rows of a workspace that could not be read this
// time can be kept, greyed, from the last good list.
export function needsYouList(inbox: InboxResponse, now: number, origin: string): Html {
  const groups = inboxGroups(inbox)
  const empty = emptyWords(inbox)
  return html`<div class="needs-list" data-region="needs-list" data-count="${inbox.count}" data-complete="${inbox.complete ? "true" : "false"}">
    ${empty !== null ? html`<section class="card" data-region="needs-empty" data-tone="${empty.tone}">${emptyState(empty.tone === "failed" ? "alert" : empty.tone === "partial" ? "info" : "check", empty.title, empty.sentence, inbox.workspaces.length === 0 ? html`<a class="btn secondary" href="/workspaces">Your workspaces</a>` : undefined)}</section>` : ""}
    ${groups.map(
      (g) => html`<section class="card needs-group" data-region="needs-group" data-workspace="${g.workspace.workspace.id}" data-state="${g.workspace.state}">
      ${groupHead(g.workspace, g.items.length)}
      ${groupNotice(g.workspace)}
      <ul class="rows" data-region="needs-rows">${g.items.map((item) => inboxRow(inboxRowOf(item, g.workspace), { now, showWorkspace: false }))}</ul>
    </section>`,
    )}
    ${noticeRows(inbox.notices, origin, inbox.workspaces.length > 1)}
  </div>`
}

function noticeWords(n: WorkspaceNotice): Html {
  const p = n.payload
  switch (p.kind) {
    case "machine_added":
      return html`A machine was added: ${cardText(p.name)}, for ${cardText(p.owner.name)}`
    case "account_security":
      return html`${cardText(p.name)} ${p.event === "recovery" ? "recovered their account with a code" : "used break-glass"}`
    case "protection_changed":
      return html`Protection changed on <code>${cardText(p.project.slug)}</code> ${cardText(p.env)}`
    case "owner_changed":
      return html`${cardText(p.name)} was ${p.change}${p.change === "added" || p.change === "reinstated" ? " as an owner" : ""}`
    case "member_joined":
      return html`${cardText(p.name)} joined as ${p.role}`
    case "account_suspended":
      return html`An operator suspended ${cardText(p.name)}'s account`
    case "deletion_scheduled":
      return html`This workspace is scheduled for deletion`
    case "rotation_required":
      return html`Credentials need rotating`
    case "mandate_signed":
      return html`${cardText(mandateSignedWords(p.signer.name, p.machine, p.classes))} ${timeTag(p.expiresAt)}`
    case "mandate_tripped":
      return html`${cardText(mandateTrippedWords(p.machine))} ${timeTag(p.expiresAt)}`
    case "mandate_ending":
      return html`${cardText(mandateEndingWords(p.machine))} ${timeTag(p.expiresAt)}`
    case "mandate_lapsed":
      return html`${cardText(mandateLapsedNoticeWords(p.machine))} ${timeTag(p.expiresAt)}`
    case "project_share_requested":
      return html`${cardText(shareRequestedWords(p.machine, p.member.name, p.project.slug))}`
    case "backup_recipient":
      return html`${p.change === "added" ? "A backup key was added" : p.change === "active" ? "A backup key can now receive exports" : "A backup key was removed"}: ${cardText(p.recipient.label)} (<code>${p.recipient.fingerprint}</code>), registered by ${cardText(p.name)}`
  }
}

// A notice's link only when it is a page on this vault's own origin.
function noticeHref(url: string, origin: string): string | null {
  if (!url.startsWith(`${origin}/`)) return null
  const path = url.slice(origin.length)
  return isVaultPath(path) ? path : null
}

export function noticeRows(notices: readonly WorkspaceNotice[], origin: string, showWorkspace: boolean): Html {
  if (notices.length === 0) return html``
  return html`<section class="card" data-region="needs-notices"><div class="card-head"><h2>Notices</h2></div><ul class="rows compact">${notices.map((n) => {
    const href = noticeHref(n.url, origin)
    const main = html`<span class="row-title">${noticeWords(n)}</span><span class="row-sub">${showWorkspace ? html`${cardText(n.payload.workspace.name)} · ` : ""}${timeTag(n.payload.at)}</span>`
    // A share request's one action: the project's Shared with form, the member chosen.
    const action = n.payload.kind === "project_share_requested" && href !== null ? html`<span class="row-side"><a class="btn primary sm" href="${href}" data-action="share-request">Share</a></span>` : ""
    return html`<li class="row">${href !== null ? html`<a class="row-main" href="${href}">${main}</a>` : html`<span class="row-main">${main}</span>`}${action}</li>`
  })}</ul></section>`
}

export type NeedsYouLoad = { ok: true; inbox: InboxResponse; etag: string | null } | { ok: false }

export function needsYouPage(account: AccountShell, load: NeedsYouLoad, now: number): PageInput {
  const inbox = load.ok ? load.inbox : null
  return {
    title: inbox !== null ? needsYouTitle(inbox.count, inbox.complete) : "Needs you",
    viewer: null,
    account,
    current: "needs",
    boot: { page: "needs-you", account: account.account, etag: load.ok ? load.etag : null },
    body: html`${pageHead({ title: "Needs you", lead: "What waits for you in every workspace, soonest first. Each one opens the exact page where you decide." })}
      <span class="sr" data-region="needs-announce" aria-live="polite"></span>
      <p class="muted small needs-status" data-region="needs-status"><span data-region="needs-updated">Updated just now</span><span data-region="needs-checking" hidden> · Checking...</span></p>
      <p class="muted small" data-region="needs-retrying" role="status" hidden>${RETRYING_WORDS}</p>
      <section class="card" data-region="needs-ended" hidden>${notice("warn", SESSION_ENDED_WORDS, undefined, html`<a class="btn primary sm" href="/signin?next=${encodeURIComponent(NEEDS_YOU_PATH)}">Sign in</a>`)}</section>
      ${inbox !== null
        ? needsYouList(inbox, now, account.origin)
        : html`<div class="needs-list" data-region="needs-list"><section class="card" data-region="needs-empty" data-tone="failed">${emptyState("alert", LOAD_FAILED_TITLE, LOAD_FAILED_SENTENCE)}</section></div>`}`,
  }
}
