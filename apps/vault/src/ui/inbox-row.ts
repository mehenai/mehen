// One Needs you row, for the account inbox (/needs-you), the one-workspace
// filter (/w/:ws/pending) and the home's Needs you card. inboxRowOf maps the
// vault's inbox item (packages/protocol/src/inbox.ts) to the row's own view
// model, so the renderer never reads the union directly; inboxRow draws it.
//
// Every string an agent or a person wrote (titles, machine names, session
// labels, places, names) goes through cardText; every link is the vault's
// own href, checked as a vault path, or no link at all. A row never shows
// the hidden fingerprint group, a thumbprint or a code it was not given.

import type { InboxAction, InboxItem, InboxWorkspace } from "@mehen/protocol/inbox"
import type { FingerprintWord } from "@mehen/protocol/fingerprint"
import type { MinimalStopView } from "@mehen/protocol/workspace"
import type { PendingAsk } from "@mehen/protocol/api"
import { ringState, ringText } from "./client/countdown.ts"
import { inboxItemKey, reviewGroupWords } from "./client/pages/needs-you-logic.ts"
import { cardText, countdownTimer, fingerprintWords } from "./components.ts"
import { type Html, html, isVaultPath } from "./html.ts"
import { iconTile, kindTile, serviceTile } from "./icons.ts"
import { ROLE_WORDS, workspaceHref } from "./shell.ts"
import { TASK_LABEL_WORDS } from "./wording.ts"

export type InboxActionLabel = "Decide" | "Open" | "Connect" | "Review" | "Review together" | "Reconnect" | "Accept" | "Admit" | "Confirm" | "Reject" | "Stop"

export const INBOX_ACTION_LABELS: Readonly<Record<InboxAction, InboxActionLabel>> = {
  decide: "Decide",
  open: "Open",
  connect: "Connect",
  review: "Review",
  reconnect: "Reconnect",
  accept: "Accept",
  admit: "Admit",
  confirm: "Confirm",
  reject: "Reject",
  stop: "Stop",
}

export type InboxCheck = { kind: "code"; value: string } | { kind: "fingerprint"; groups: (string | null)[]; words: FingerprintWord[] } | null

// `cancel`: a stop row for an intake or a connect, which the row stops in
// place; an approval or a policy proposal is stopped on its own page.
// `reject`: an enrolment whose primary action is not Reject but whose
// actions hold it, drawn as a second, quieter link to the same page.
export type InboxRowAction = { label: InboxActionLabel; href: string | null; cancel?: { kind: "intake" | "connect"; id: string }; reject?: string }

export type InboxRow = {
  // The DOM key: the ask id, or the enrolment id, which a renewal keeps, so
  // a renewed row resets its countdown in place rather than moving.
  key: string
  workspace: { id: string; slug: string; name: string }
  tile: Html
  title: Html
  who: Html
  check: InboxCheck
  startedAt: string | null
  expiresAt: string | null
  action: InboxRowAction
  view: "detail" | "stop"
}

function href(raw: string): string | null {
  return isVaultPath(raw) ? raw : null
}

function sessionWords(session: string | null): Html {
  return session !== null && session !== "" ? html`, session <code>${cardText(session)}</code> (a label the agent chose, not verified)` : html``
}

function askTile(ask: PendingAsk): Html {
  if (ask.provider !== undefined && ask.provider !== null) return serviceTile({ provider: ask.provider, slug: ask.item ?? ask.id })
  if (ask.kind === "intake") return kindTile(ask.kindRequested ?? "api-key")
  if (ask.kind === "approval" && ask.item === null) return kindTile("project")
  return kindTile("api-key")
}

function askWho(ask: PendingAsk): Html {
  const by = ask.requestedBy
  if (by === null) return html`The vault`
  if ("member" in by) return html`${by.self ? "You" : "Another member"}`
  return html`An agent on ${cardText(by.deviceName)}${sessionWords(by.session)}`
}

// Which stop the row offers: an intake or a connect is cancelled in place;
// an approval opens its own page, where Deny is signed; a policy proposal
// opens its page under /p/.
function stopAction(stop: MinimalStopView, item: InboxItem, slug: string): InboxRowAction {
  const id = stop.id
  if (id.startsWith("int_")) return { label: "Stop", href: null, cancel: { kind: "intake", id } }
  if (id.startsWith("con_")) return { label: "Stop", href: null, cancel: { kind: "connect", id } }
  if (id.startsWith("pol_")) return { label: "Stop", href: workspaceHref(slug, `/p/${encodeURIComponent(id)}`) }
  return { label: "Stop", href: href(item.href) }
}

function enrolWho(enrol: Extract<InboxItem, { kind: "enrol" }>["enrol"]): Html {
  const from = enrol.host ?? enrol.name
  const place = enrol.start.place !== null ? html` in ${cardText(enrol.start.place)}` : html``
  const owner =
    enrol.state === "pending_admission" && enrol.owner !== null
      ? html`. Accepted by ${cardText(enrol.owner.name)}; waiting to be admitted`
      : enrol.claimed !== null
        ? html`. Started for ${cardText(enrol.claimed.name)}`
        : enrol.requestedOwner.kind === "team"
          ? html`. For the team ${cardText(enrol.requestedOwner.name)}`
          : html``
  return html`Asked from ${cardText(from)}${place} by ${cardText(enrol.start.clientLabel)}${sessionWords(enrol.session)}${owner}`
}

export function inboxRowOf(item: InboxItem, workspace: InboxWorkspace): InboxRow {
  const where = { id: workspace.workspace.id, slug: workspace.workspace.slug, name: workspace.workspace.name }
  const times = { startedAt: item.createdAt, expiresAt: item.expiresAt }
  const primary: InboxRowAction = { label: INBOX_ACTION_LABELS[item.action], href: href(item.href) }
  switch (item.kind) {
    case "ask": {
      const ask = item.ask
      if (ask.view === "stop") {
        const stop = ask.stop
        return {
          key: inboxItemKey(item),
          workspace: where,
          tile: kindTile("machine", undefined, undefined, stop.machine.name),
          title: html`A private request from ${cardText(stop.machine.name)}`,
          who: html`You cannot see it; you can stop it. Its machine belongs to ${cardText(stop.machine.owner.name)}${stop.item !== null ? html`; it is about <code>${cardText(stop.item.slug)}</code>` : ""}.`,
          check: null,
          ...times,
          action: stopAction(stop, item, where.slug),
          view: "stop",
        }
      }
      const detail = ask.detail
      return {
        key: inboxItemKey(item),
        workspace: where,
        tile: askTile(detail),
        title: cardText(detail.title),
        who: askWho(detail),
        check: detail.bindingCode !== undefined ? { kind: "code", value: detail.bindingCode } : null,
        ...times,
        action: primary,
        view: "detail",
      }
    }
    case "enrol": {
      const enrol = item.enrol
      const reject = item.action !== "reject" && enrol.actions.includes("reject") && primary.href !== null ? primary.href : undefined
      return {
        key: inboxItemKey(item),
        workspace: where,
        tile: kindTile("machine", enrol.backend, undefined, enrol.name),
        title: html`A new machine wants to join: ${cardText(enrol.name)}`,
        who: enrolWho(enrol),
        check: { kind: "fingerprint", groups: [...enrol.fingerprint.groups], words: enrol.fingerprint.words },
        ...times,
        action: reject !== undefined ? { ...primary, reject } : primary,
        view: "detail",
      }
    }
    case "confirm": {
      const confirm = item.confirm
      return {
        key: inboxItemKey(item),
        workspace: where,
        tile: iconTile("users"),
        title: html`${cardText(confirm.name)} joined as ${ROLE_WORDS[confirm.role].toLowerCase()}`,
        who: html`Confirm them before they can see or do anything${confirm.boundEmail !== null ? html`; invited as <code>${cardText(confirm.boundEmail)}</code>` : ""}.`,
        check: null,
        ...times,
        action: primary,
        view: "detail",
      }
    }
    case "rescope": {
      const rescope = item.rescope
      return {
        key: inboxItemKey(item),
        workspace: where,
        tile: kindTile("machine", undefined, undefined, rescope.deviceName),
        title: html`A wider scope is waiting for ${cardText(rescope.deviceName)}`,
        who: html`Proposed by ${cardText(rescope.proposer.name)}; ${rescope.as === "owner_acceptance" ? "you accept it as the machine's owner" : "you admit it for the workspace"}.`,
        check: null,
        ...times,
        action: primary,
        view: "detail",
      }
    }
    case "group": {
      const group = item.group
      return {
        key: inboxItemKey(item),
        workspace: where,
        tile: kindTile("machine", undefined, undefined, group.machine.name),
        title: group.kind === "bundle" ? html`${cardText(group.machine.name)}: ${group.count} requests to approve together` : html`${cardText(group.machine.name)}: ${group.count} asks${group.item !== null ? html` on <code>${cardText(group.item.slug)}</code>` : ""}`,
        who: html`${group.reason !== null ? html`"${cardText(group.reason)}" (the agent's words, not verified). ` : ""}${group.machine.workload !== null ? html`Task <code>${cardText(group.machine.workload.label)}</code> (${TASK_LABEL_WORDS}). ` : ""}${reviewGroupWords(group.floor, group.ownPage, group.denyOnly ?? 0)}`,
        check: null,
        ...times,
        action: { ...primary, label: "Review together" },
        view: "detail",
      }
    }
  }
}

// The hidden group is four dots, never a group; the others as printed.
function fingerprintCheck(groups: readonly (string | null)[], words: readonly FingerprintWord[]): Html {
  return html`<span class="row-check" data-check="fingerprint"><span class="row-fp" aria-label="Fingerprint, one group hidden">${groups.map((g) => (g === null ? html`<code class="row-fp-hidden" aria-label="hidden group">····</code>` : html`<code>${cardText(g)}</code>`))}</span>${fingerprintWords(words)}</span>`
}

function checkLine(check: InboxCheck): Html {
  if (check === null) return html``
  if (check.kind === "code") return html`<span class="row-check" data-check="code">Code <code class="code-inline">${cardText(check.value)}</code></span>`
  return fingerprintCheck(check.groups, check.words)
}

// The ring when both ends are known (its total from the row's own start
// and expiry, never a constant), the time left in words when only the end
// is, nothing for a row that waits until someone acts.
export function rowCountdown(startedAt: string | null, expiresAt: string | null, now: number): Html {
  if (expiresAt === null) return html``
  const end = Date.parse(expiresAt)
  if (Number.isNaN(end)) return html``
  const start = startedAt === null ? Number.NaN : Date.parse(startedAt)
  if (!Number.isNaN(start) && end > start) return html`<span class="left">${countdownTimer(expiresAt, Math.round((end - start) / 1000), now)}</span>`
  const state = ringState(end, 0, now)
  return html`<span class="left muted small">${state.expired ? "ran out" : `${ringText(state.left)} left`}</span>`
}

function actionControl(row: InboxRow): Html {
  const { action } = row
  const tone = row.view === "stop" ? "danger-quiet" : action.label === "Reject" ? "secondary" : "primary"
  if (action.cancel !== undefined) return html`<button type="button" class="btn ${tone} sm" data-action="cancel-ask" data-kind="${action.cancel.kind}" data-id="${action.cancel.id}">${action.label}</button>`
  if (action.href === null) return html``
  return html`<a class="btn ${tone} sm" href="${action.href}">${action.label}</a>`
}

// `sign`: the item's signature (inboxItemSign), on the home's card only,
// so its client can tell a change the card has not drawn.
export type InboxRowOptions = { now: number; showWorkspace: boolean; stale?: boolean; sign?: string }

export function inboxRow(row: InboxRow, options: InboxRowOptions): Html {
  const opens = row.view === "detail" ? row.action.href : null
  const main = html`<span class="row-title">${row.title}</span><span class="row-sub">${row.who}</span>${checkLine(row.check)}${options.showWorkspace ? html`<span class="row-where">${cardText(row.workspace.name)} · <code>${row.workspace.slug}</code></span>` : ""}`
  return html`<li class="row needs inbox-row${options.stale ? " stale" : ""}" data-key="${row.key}" data-view="${row.view}" data-workspace="${row.workspace.id}" data-slug="${row.workspace.slug}"${options.sign !== undefined ? html` data-sign="${options.sign}"` : ""}>
    ${row.tile}
    ${opens !== null ? html`<a class="row-main" href="${opens}">${main}</a>` : html`<span class="row-main">${main}</span>`}
    <span class="row-side">${rowCountdown(row.startedAt, row.expiresAt, options.now)}${actionControl(row)}${row.action.reject !== undefined ? html`<a class="more-link" href="${row.action.reject}">Reject</a>` : ""}</span>
  </li>`
}
