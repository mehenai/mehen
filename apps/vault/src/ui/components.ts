// Pieces several pages share: who asked, where a secret may go, pills,
// rows, tiles, strips and charts, state and empty cards, fingerprints,
// guided steps. Markup is classes over plain HTML; the stylesheet is
// client/app.css.

import type { BindingInput, Injection, ItemSummary, RequestedBy } from "@mehen/protocol/api"
import { type LeaseOnlyDelivery, isLeaseOnly, leaseOnlyWords } from "@mehen/protocol/binding"
import type { FingerprintWord } from "@mehen/protocol/fingerprint"
import { spellCardSegments, spellCardText } from "../relay/presentation.ts"
import { ringState, ringText } from "./client/countdown.ts"
import { type Html, type NativeAppLink, html, isVaultPath, nativeAppHref } from "./html.ts"
import { type IconName, icon } from "./icons.ts"
import { TASK_LABEL_WORDS, askerName, bindingLimits, formatTime, isMemberAsk } from "./wording.ts"

export type { RequestedBy }

// The machine and session rows of an ask's details, or, for an ask a
// member made from the vault's pages, where it was made. The device name
// and the session label are spelled through cardText; the member line is
// constant text, since the row records no name for a member.
export function requesterDetails(by: RequestedBy): Html {
  if (isMemberAsk(by)) return html`<dt>Asked from</dt><dd>${askerName(by)}, signed in to the vault, from Connect a service</dd>`
  return html`<dt>Machine</dt><dd>${cardText(by.deviceName)} <code>${cardText(by.device)}</code></dd>
        ${by.workload ? html`<dt>Task</dt><dd><code>${cardText(by.workload.label)}</code> <span class="muted small">(${TASK_LABEL_WORDS})</span></dd>` : ""}
        <dt>Session</dt><dd>${by.session ? html`<code>${cardText(by.session)}</code>` : "not given"}</dd>`
}

// The quieter line under an ask's machine line when a workload asked: the
// task's label, marked as the machine's words like a session label.
export function taskLine(by: RequestedBy): Html | string {
  if (isMemberAsk(by) || !by.workload) return ""
  return html`<p class="small muted" data-region="ask-task">Task: <b>${cardText(by.workload.label)}</b>, ${TASK_LABEL_WORDS}</p>`
}

// Every string here that an agent wrote (the session label, the reason)
// or that a human typed (the device name) is spelled through cardText.
export function requestedByBlock(by: RequestedBy, reason: string | null): Html {
  return html`<section class="card asker" aria-label="Who is asking">
    <p class="eyebrow">Asked by</p>
    <p class="machine">${cardText(askerName(by))}</p>
    <dl class="kv">${requesterDetails(by)}</dl>
    ${reason !== null ? html`<p class="eyebrow">Why</p><blockquote class="reason">${cardText(reason)}</blockquote>` : ""}
  </section>`
}

// The one wording for which machines an ask's tags let near what it stores:
// "Only machines allowed the tag <ai>, or every credential, can use it". A
// tag is necessary, never sufficient (TAGS_ARE_ONE_LIMIT).
export function whoMayUse(tags: readonly string[], now = ""): Html {
  const unique = [...new Set(tags)]
  if (unique.length === 0) return html`Only machines allowed every credential can use it${now}`
  return html`Only machines allowed ${unique.length === 1 ? "the tag" : "the tags"} ${unique.map((t, i) => html`${i > 0 ? " or " : ""}<code>${cardText(t)}</code>`)}, or every credential, can use it${now}`
}

// A lease-only binding names no host, so its reserved name is never shown:
// what its ceiling lets happen to it is, where the page knows it.
export function hostList(hosts: readonly string[], delivery: LeaseOnlyDelivery | null = null): Html {
  if (isLeaseOnly({ hosts })) return html`<p class="lease-only" data-region="lease-only">${leaseOnlyWords(delivery).split("mehen run").map((part, i) => (i === 0 ? part : html`<code>mehen run</code>${part}`))}</p>`
  return html`<ul class="hosts">${hosts.map((h) => html`<li><code>${cardText(h)}</code></li>`)}</ul>`
}

export function destinationBlock(binding: BindingInput, verified: boolean, source: string | null, delivery: LeaseOnlyDelivery | null = null): Html {
  const limits = bindingLimits(binding)
  const limitList = limits.length ? html`<ul class="limits">${limits.map((l) => html`<li>${cardText(l)}</li>`)}</ul>` : ""
  if (isLeaseOnly(binding)) {
    return html`<section class="card dest" aria-label="Where this secret may go">
      <p class="eyebrow">${icon("shield")}<span>Never sent to a host</span></p>
      ${hostList(binding.hosts, delivery)}
      <p class="dest-note">The vault never puts it into a request to any service.</p>
    </section>`
  }
  if (verified) {
    return html`<section class="card dest verified" aria-label="Where this secret may go">
      <p class="eyebrow">${icon("shield")}<span>Allowed to go only to</span></p>
      ${hostList(binding.hosts)}
      ${limitList}
      <p class="dest-note">Verified: this destination comes from ${source ? html`the ${source} template` : "a vault template"}, not from the agent.</p>
    </section>`
  }
  return html`<section class="card dest unverified" aria-label="Where this secret may go">
    <p class="eyebrow">Proposed by the agent, not verified</p>
    <p class="dest-warning">${binding.hosts.length === 1 ? "No template vouches for this host. Check it is the real service and that it expects the secret this way." : `No template vouches for these ${binding.hosts.length} hosts. Check each one is the real service and that it expects the secret this way.`}</p>
    ${hostList(binding.hosts)}
    ${limitList}
  </section>`
}

// How the relay puts a secret into each request: names and shapes only.
export function injectionWords(injection: Injection): Html {
  switch (injection.in) {
    case "header":
      return html`In the <code>${cardText(injection.name)}</code> header, written as <code>${cardText(injection.format)}</code>.`
    case "query":
      return html`In the <code>${cardText(injection.name)}</code> query parameter of the URL, from the field <code>${cardText(injection.field)}</code>.`
    case "basic":
      return html`As HTTP basic authentication, user from <code>${cardText(injection.username)}</code>, password from <code>${cardText(injection.password)}</code>.`
    case "headers":
      return html`As every header listed in the field <code>${cardText(injection.field)}</code>.`
  }
}

export type PillTone = "ok" | "warn" | "danger" | "accent" | "muted"

const STATUS_TONE: Record<ItemSummary["status"], PillTone> = {
  active: "ok",
  needs_reauth: "danger",
  refresh_retrying: "warn",
  disabled: "muted",
}

const STATUS_WORDS: Record<ItemSummary["status"], string> = {
  active: "Active",
  needs_reauth: "Needs reconnecting",
  refresh_retrying: "Retrying refresh",
  disabled: "Disabled",
}

export function itemStatusPill(status: ItemSummary["status"]): Html {
  return pill(STATUS_WORDS[status], STATUS_TONE[status])
}

export function itemStatusBadge(status: ItemSummary["status"]): Html {
  return itemStatusPill(status)
}

export function badge(text: string, tone: string): Html {
  return html`<span class="badge ${tone}">${text}</span>`
}

// A dot means a status; no dot means a fact about a value.
export function pill(text: string, tone: PillTone, dot = true): Html {
  return html`<span class="pill ${tone}${dot ? " dot" : ""}">${text}</span>`
}

// Text a human reads from a card, with the markers the vault generated for
// hidden characters styled, and nothing else: a marker-shaped string typed
// by someone else is a text segment and stays plain.
export function cardText(text: string): Html {
  return html`${spellCardSegments(text).map((s) => (s.kind === "marker" ? html`<mark class="marker">${s.text}</mark>` : s.text))}`
}

// True when spelling would change nothing: no control or hidden character.
// A copy box may only carry text that passes, so it copies what is read.
export function plainText(text: string): boolean {
  return spellCardText(text) === text
}

// ---------------------------------------------------------------- time

export type Countdown = { expiresAt: string; totalSeconds: number }

const RING_RADIUS = 9
const RING_CIRCUMFERENCE = +(2 * Math.PI * RING_RADIUS).toFixed(2)

export function ringOffset(fraction: number): number {
  const clamped = Math.min(1, Math.max(0, fraction))
  return +(RING_CIRCUMFERENCE * (1 - clamped)).toFixed(2)
}

// A countdown ring. With a countdown the client (wires.ts) drives the
// offset from data-expires once a second and adds .warn and .danger.
export function ring(fraction: number, tone?: "warn" | "danger", countdown?: Countdown, size?: "lg"): Html {
  const classes = ["ring", tone, size].filter((c): c is string => typeof c === "string").join(" ")
  const live = countdown ? html` data-ring data-expires="${countdown.expiresAt}" data-total="${countdown.totalSeconds}"` : ""
  return html`<svg class="${classes}" viewBox="0 0 24 24" aria-hidden="true"${live}><circle class="ring-track" cx="12" cy="12" r="${RING_RADIUS}"/><circle class="ring-fill" cx="12" cy="12" r="${RING_RADIUS}" stroke-dasharray="${RING_CIRCUMFERENCE}" stroke-dashoffset="${ringOffset(fraction)}"/></svg>`
}

export function timer(fraction: number, text: Html | string, countdown?: Countdown, tone?: "warn" | "danger"): Html {
  return html`<span class="timer">${ring(fraction, tone, countdown)}<span${countdown ? html` data-ring-text` : ""}>${text}</span></span>`
}

// A live countdown to `expiresAt`, rendered as the client will first see it
// and then driven by wires.ts.
export function countdownTimer(expiresAt: string, totalSeconds: number, now: number): Html {
  const state = ringState(Date.parse(expiresAt), totalSeconds, now)
  return timer(state.fraction, state.expired ? "ran out" : `${ringText(state.left)} left`, { expiresAt, totalSeconds }, state.tone ?? undefined)
}

// ---------------------------------------------------------------- activity

// One day of calls by policy outcome: allowed, needed you (an approval was
// requested, granted or not), refused (a deny rule or a proposed
// destination). The read that fills this does not exist yet; pages hide
// the strip when they have no data.
export type ActivityDay = { allowed: number; approved: number; refused: number }

export type ActivityWeek = { days: ActivityDay[]; labels: string[] }

export function activityTotal(days: readonly ActivityDay[]): number {
  return days.reduce((n, d) => n + d.allowed + d.approved + d.refused, 0)
}

const OUTCOMES = ["allowed", "approved", "refused"] as const

// A 70 by 20 stacked strip of seven days. Heights are SVG attributes, so
// the markup stays inside the CSP.
export function sparkline(days: readonly ActivityDay[]): Html {
  const w = 70
  const h = 20
  const gap = 3
  const bw = (w - gap * (days.length - 1)) / Math.max(1, days.length)
  const max = Math.max(1, ...days.map((d) => d.allowed + d.approved + d.refused))
  const rects: Html[] = []
  days.forEach((d, i) => {
    const x = +(i * (bw + gap)).toFixed(2)
    const total = d.allowed + d.approved + d.refused
    if (total === 0) {
      rects.push(html`<rect class="sp-empty" x="${x}" y="${h - 1.5}" width="${bw.toFixed(2)}" height="1.5" rx="0.75"/>`)
      return
    }
    const scale = (h - 2) / max
    let y = h
    for (const key of OUTCOMES) {
      const n = d[key]
      if (!n) continue
      const bh = Math.max(1.5, n * scale)
      y -= bh
      rects.push(html`<rect class="sp-${key}" x="${x}" y="${y.toFixed(2)}" width="${bw.toFixed(2)}" height="${bh.toFixed(2)}"/>`)
    }
  })
  return html`<svg class="spark" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" aria-hidden="true">${rects}</svg>`
}

export function sparklineWithCount(days: readonly ActivityDay[]): Html {
  return html`<span class="spark-wrap">${sparkline(days)}<span class="spark-n">${activityTotal(days)}</span></span>`
}

// Seven columns in a CSS grid; each holds one SVG stretched to the column
// so the bars grow with the card while labels and values stay text.
export function weekChart(days: readonly ActivityDay[], labels: readonly string[]): Html {
  const h = 72
  const max = Math.max(1, ...days.map((d) => d.allowed + d.approved + d.refused))
  const cols = days.map((d, i) => {
    const total = d.allowed + d.approved + d.refused
    const rects: Html[] = []
    let y = h
    if (total === 0) rects.push(html`<rect class="sp-empty" x="0" y="${h - 2}" width="10" height="2"/>`)
    for (const key of OUTCOMES) {
      const n = d[key]
      if (!n) continue
      const bh = Math.max(2, (n / max) * h)
      y -= bh
      rects.push(html`<rect class="sp-${key}" x="0" y="${y.toFixed(2)}" width="10" height="${bh.toFixed(2)}"/>`)
    }
    return html`<div class="col"><span class="val">${total || ""}</span><svg viewBox="0 0 10 ${h}" preserveAspectRatio="none" aria-hidden="true">${rects}</svg><span class="lbl">${labels[i] ?? ""}</span></div>`
  })
  return html`<div class="chart" role="img" aria-label="Calls over the last seven days: ${activityTotal(days)}">${cols}</div>`
}

export function chartLegend(): Html {
  return html`<ul class="legend"><li><i class="sw allowed"></i>Allowed</li><li><i class="sw approved"></i>Needed you</li><li><i class="sw refused"></i>Refused</li></ul>`
}

// ---------------------------------------------------------------- rows and cards

// `href` is a path on this vault; anything else (a scheme, `//`, `/\`, a
// control character) renders as no link at all. A link into a native app
// is named by `appLink`, never passed as a string.
export type RowInput = { tile: Html; href?: string; appLink?: NativeAppLink; title: Html | string; sub?: Html | string; data?: Html; side?: Html; needs?: boolean }

function rowHref(opts: RowInput): string | null {
  if (opts.appLink !== undefined) return nativeAppHref(opts.appLink)
  if (opts.href !== undefined && isVaultPath(opts.href)) return opts.href
  return null
}

export function row(opts: RowInput): Html {
  const main = html`<span class="row-title">${opts.title}</span>${opts.sub !== undefined ? html`<span class="row-sub">${opts.sub}</span>` : ""}`
  const href = rowHref(opts)
  return html`<li class="row${opts.needs ? " needs" : ""}">
    ${opts.tile}
    ${href !== null ? html`<a class="row-main" href="${href}">${main}</a>` : html`<span class="row-main">${main}</span>`}
    ${opts.data !== undefined ? html`<span class="row-data">${opts.data}</span>` : ""}
    ${opts.side !== undefined ? html`<span class="row-side">${opts.side}</span>` : ""}
  </li>`
}

export function cardHead(title: string, aside?: Html): Html {
  return html`<div class="card-head"><h2>${title}</h2>${aside ?? ""}</div>`
}

// ---------------------------------------------------------------- page parts

// The one page head: an optional tile, the parent place as the eyebrow (in
// sentence case, never the identity line), the title, a lead, and the
// page's actions, which wrap under the text on a narrow page.
export type PageHeadInput = { tile?: Html; eyebrow?: Html | string; title: Html | string; lead?: Html | string; actions?: Html }

export function pageHead(opts: PageHeadInput): Html {
  return html`<header class="page-head">${opts.tile ?? ""}<div class="page-head-text">${opts.eyebrow !== undefined ? html`<p class="eyebrow">${opts.eyebrow}</p>` : ""}<h1>${opts.title}</h1>${opts.lead !== undefined ? html`<p class="lead">${opts.lead}</p>` : ""}</div>${opts.actions !== undefined ? html`<div class="page-head-actions">${opts.actions}</div>` : ""}</header>`
}

// One inline notice in four tones. An error interrupts (role alert); the
// others are read when the reader reaches them (role status).
export type NoticeTone = "info" | "warn" | "error" | "ok"

export function notice(tone: NoticeTone, title: Html | string, body?: Html | string, action?: Html): Html {
  return html`<div class="notice ${tone}" role="${tone === "error" ? "alert" : "status"}"><p class="notice-title">${title}</p>${body !== undefined ? html`<p>${body}</p>` : ""}${action !== undefined ? html`<div class="notice-action">${action}</div>` : ""}</div>`
}

// A key-value list: each term beside its value, or above it in a card
// narrower than 360 px.
export type KvRow = readonly [term: Html | string, value: Html | string]

export function kv(rows: readonly KvRow[], variant?: "small" | "facts"): Html {
  return html`<dl class="kv${variant !== undefined ? ` ${variant}` : ""}">${rows.map(([term, value]) => html`<dt>${term}</dt><dd>${value}</dd>`)}</dl>`
}

// A table on a wide card that becomes a list on a narrow one, each value
// beside its column's label (data-label). Every row has one cell per column.
export function responsiveTable(columns: readonly string[], rows: readonly (readonly (Html | string)[])[]): Html {
  for (const cells of rows) if (cells.length !== columns.length) throw new Error(`a table row has ${cells.length} cells for ${columns.length} columns`)
  return html`<div class="table"><table><thead><tr>${columns.map((c) => html`<th scope="col">${c}</th>`)}</tr></thead><tbody>${rows.map(
    (cells) => html`<tr>${cells.map((cell, i) => html`<td data-label="${columns[i] ?? ""}"><span>${cell}</span></td>`)}</tr>`,
  )}</tbody></table></div>`
}

// A moment as a <time>: the machine-readable instant in datetime and the
// UTC words as the text and the title. A value that is not a time is
// shown as given, without a <time>.
export function timeTag(value: string | number): Html {
  const at = new Date(value)
  if (Number.isNaN(at.getTime())) return html`${String(value)}`
  const words = formatTime(value)
  return html`<time datetime="${at.toISOString()}" title="${words}">${words}</time>`
}

export function copyBox(value: string): Html {
  return html`<div class="copybox"><code>${value}</code><button type="button" class="btn secondary sm" data-copy>${icon("copy")}<span>Copy</span></button></div>`
}

export type StateCardInput = {
  tone: "expired" | "ok" | "danger" | "muted"
  icon: IconName
  // 2 where the page around the card already has its h1.
  level?: 1 | 2
  heading: Html | string
  lead: Html | string
  // Block content between the lead and the actions, such as word chips.
  after?: Html
  primary?: Html
  secondary?: Html
  or?: Html
}

export function stateCard(opts: StateCardInput): Html {
  const actions = opts.primary !== undefined || opts.secondary !== undefined ? html`<div class="actions">${opts.primary ?? ""}${opts.secondary ?? ""}</div>` : ""
  return html`<section class="card state ${opts.tone}">
    <span class="state-icon">${icon(opts.icon, opts.tone === "ok" ? "draw" : undefined)}</span>
    ${opts.level === 2 ? html`<h2>${opts.heading}</h2>` : html`<h1>${opts.heading}</h1>`}
    <p class="lead">${opts.lead}</p>
    ${opts.after ?? ""}
    ${actions}
    ${opts.or !== undefined ? html`<div class="or">${opts.or}</div>` : ""}
  </section>`
}

export function emptyState(name: IconName, title: Html | string, sentence: Html | string, action?: Html): Html {
  return html`<div class="empty"><span class="tile kind">${icon(name)}</span><b>${title}</b><p>${sentence}</p>${action ?? ""}</div>`
}

// ---------------------------------------------------------------- fingerprints

// Four words with their colour dots. The colour name is always text beside
// the swatch, so a colour is never told by hue alone.
export function fingerprintWords(words: readonly FingerprintWord[]): Html {
  return html`<div class="fp-words" aria-label="Fingerprint words">${words.map(
    (w) => html`<span class="fp-word"><i class="swatch c-${w.colour.name}" aria-hidden="true"></i><b>${cardText(w.word)}</b><small>${cardText(w.colour.name)}</small></span>`,
  )}</div>`
}

export const GROUP_WORDS = ["first", "second", "third", "fourth"]

// The glyph groups with one hidden: the hidden index renders four dots and
// never the group, whatever `groups` holds at that index.
export function fingerprintGlyphs(groups: readonly string[], hidden: number, state: "hidden" | "typed" | "wrong" = "hidden", typed = ""): Html {
  return html`<div class="fp-glyphs" aria-label="Fingerprint">${groups.map((g, i) => {
    if (i !== hidden) return html`<span>${g}</span>`
    const which = GROUP_WORDS[i] ?? `${i + 1}th`
    if (state === "hidden") return html`<span class="hidden" data-region="fingerprint-hidden" aria-label="the ${which} group, hidden">····</span>`
    return html`<span class="${state}" data-region="fingerprint-hidden">${typed}</span>`
  })}</div>`
}

// ---------------------------------------------------------------- guided steps

// `field` names the form field whose being filled in marks the step done;
// the client reads it from data-step-field.
export type StepInput = { title: Html | string; body?: Html | string; state: "done" | "current" | "todo"; field?: string }

export function steps(items: readonly StepInput[]): Html {
  return html`<ol class="steps">${items.map(
    (s) =>
      html`<li class="step${s.state === "todo" ? "" : ` ${s.state}`}"${s.field !== undefined ? html` data-step-field="${s.field}"` : ""}><span class="step-title">${s.title}</span>${s.body !== undefined ? html`<div class="step-body">${s.body}</div>` : ""}</li>`,
  )}</ol>`
}

// ---------------------------------------------------------------- get started

// One step of a workspace's Get started card: done from the viewer's own
// reads, a link to where it is done, and `more` (a copy box) under an
// undone step.
export type GetStartedItem = { label: string; body: Html | string; done: boolean; href: string; more?: Html }

export type GetStartedInput = { workspace: string; sub: string; items: readonly GetStartedItem[] }

// The card the home shows while a step is undone. Hide stores
// mehen.getStarted.<workspace id> in this browser only (client/shell.ts),
// and the card stays hidden there; nothing is sent.
export function getStarted(opts: GetStartedInput): Html {
  const done = opts.items.filter((i) => i.done).length
  return html`<section class="card get-started" data-region="get-started" data-workspace="${opts.workspace}">
    <div class="card-head"><h2>Get started</h2><button type="button" class="btn quiet sm" data-action="hide-get-started">Hide</button></div>
    <p class="muted">${opts.sub} <span class="get-started-count">${done} of ${opts.items.length} done.</span></p>
    <ol class="get-started-list">${opts.items.map(
      (item) => html`<li class="get-started-item${item.done ? " done" : ""}"><span class="get-started-tick" aria-hidden="true">${item.done ? icon("check") : ""}</span><span class="get-started-text"><span class="get-started-title"><a href="${item.href}">${item.label}</a>${item.done ? html` <span class="pill ok">Done</span>` : ""}</span><span class="get-started-body">${item.body}</span>${!item.done && item.more !== undefined ? item.more : ""}</span></li>`,
    )}</ol>
  </section>`
}
