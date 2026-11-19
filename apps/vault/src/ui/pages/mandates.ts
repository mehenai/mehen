// What a machine may do without asking: the list
// (/w/:ws/mandates), one mandate with its receipts (/w/:ws/mandates/:id),
// the sign page (/w/:ws/sign-mandate), the machine page's card and the
// home's strip. Every view is the vault's projection for this reader
// (5.4): a credential they cannot see is never named. Buttons are drawn
// only for who may press them (5.2), the vault deciding every press; the
// browser side is client/pages/mandates.ts and client/mandate-sign.ts.

import { MANDATE_CAP_DEFAULTS, MANDATE_CAP_MAX, MANDATE_CLASSES, MANDATE_PROPOSAL_DEFAULT_TTL_DAYS, MANDATE_ENDING_NOTICE_MS, MANDATE_LIVE_STATES, MANDATE_NOTE_MAX, MANDATE_TTL_DAYS, type MandateCandidates, type MandateClass, type MandateList, type MandateOpenProposal, type MandateProposalView, type MandateReceiptView, type MandateReceiptsPage, type MandateSchedule, type MandateTtlDays, type MandateView } from "@mehen/protocol/mandate-terms"
import type { WorkspaceDeviceView } from "@mehen/protocol/workspace"
import { spellCardText } from "../../relay/spelling.ts"
import { cardText, emptyState, kv, notice, pageHead, pill, row, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon, kindTile } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import { type WorkspaceShell, workspaceHref } from "../shell.ts"
import {
  MANDATE_ALL_CREDENTIALS, MANDATE_ALWAYS_WORDS, MANDATE_CANDIDATES_UNREAD_WORDS, MANDATE_CAPS_LABEL, MANDATE_CAPS_WORDS, MANDATE_CARD_LEAD, MANDATE_CARD_TITLE, MANDATE_CLASS_CHOICES, MANDATE_CLASSES_LABEL, MANDATE_HIDDEN_CREDENTIAL, MANDATE_ITEMS_LABEL,
  MANDATE_LIST_EMPTY, MANDATE_LIST_ENDED, MANDATE_LIST_LEAD, MANDATE_LIST_TITLE, MANDATE_LISTED_ITEMS, MANDATE_NO_CANDIDATES, MANDATE_NOTE_HINT, MANDATE_NOTE_LABEL, MANDATE_OPEN_LINK, MANDATE_PAUSE_ALL_BUTTON, MANDATE_PAUSE_BUTTON, MANDATE_PROPOSAL_CLOSED_WORDS, MANDATE_PROPOSAL_SUPERSEDED_WORDS, mandateProposalUnboundWords,
  MANDATE_RECEIPTS_EMPTY, MANDATE_RECEIPTS_LEAD, MANDATE_RECEIPTS_OLDER, MANDATE_RECEIPTS_TITLE, MANDATE_RENEW_LINK, MANDATE_SIGN_AGAIN_LINK, MANDATE_REPLACED_WORDS, MANDATE_REPLACES_WORDS, MANDATE_RESUME_BUTTON, MANDATE_RESUME_HINT, MANDATE_SCHEDULE_HINT, MANDATE_SCHEDULE_LABELS,
  MANDATE_SCHEDULE_TICK, MANDATE_SIGN_BUTTON, MANDATE_SIGN_EYEBROW, MANDATE_SIGN_LEAD, MANDATE_STATE_PILLS, MANDATE_STATE_WORDS, MANDATE_STOP_BUTTON, MANDATE_STOP_TITLE, MANDATE_STOP_WORDS, MANDATE_SUMMARY_TITLE, MANDATE_TEAM_MACHINE_WORDS, MANDATE_TERM_LABELS,
  MANDATE_TRUST_BUTTON, MANDATE_TTL_LABEL, MANDATE_UNREVIEWED_ENTRY, MANDATE_WAITING_LEAD, MANDATE_WAITING_OPEN, MANDATE_WAITING_TITLE, type MandateSummaryInput, machinesCarryingOnWords, machinesNeedResumeWords, mandateAllItemsWords, mandateCapHint, mandateClassWords, mandateDayWords, mandateDefaultNote, mandateEndsInWords, mandateHiddenItemsWords, mandateLapsedWords, mandateNotOwnerWords, mandatePauseAllConfirmWords, mandateSignSameWords,
  mandateProposedWords, mandateScheduleWords, mandateSignTitle, mandateSummaryWords, mandateTodayWords, mandateTtlWords,
} from "../wording.ts"
import { HELD_WORDS, type Viewer } from "../workspace-rights.ts"

const DAY_MS = 86_400_000
const DAY_NUMBERS = [1, 2, 3, 4, 5, 6, 0] as const
const DAY_SHORT = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"] as const
const CLASS_ORDER: readonly MandateClass[] = ["read", "change", "send", "delete"]

const elevated = (viewer: Viewer): boolean => viewer.role === "owner" || viewer.role === "admin"
export const mandateLive = (m: Pick<MandateView, "state">): boolean => MANDATE_LIVE_STATES.includes(m.state)

// Who may press which button (5.2): Pause and Stop the signer, or an owner
// or admin (who reads the mandate only while they may read the machine),
// who may also pause a paused one to take over its signer's or machine's
// pause (a repeat changes nothing);
// Resume the signer, on a paused or tripped one or one that lapsed; Renew
// the signer, in a live one's last days, or as Sign again with these terms
// on one that ended, however long ago. A held account may still narrow, so it keeps Pause and Stop
// but is offered neither Resume nor Renew.
export type MandateControls = { pause: boolean; stop: boolean; resume: boolean; renew: boolean }
export function mandateControls(m: MandateView, viewer: Viewer, now: number): MandateControls {
  const live = mandateLive(m), self = m.signer.self === true, may = viewer.held !== true
  const end = Date.parse(m.expiresAt)
  const nearEnd = live && end - now <= MANDATE_ENDING_NOTICE_MS
  return {
    pause: (m.state === "active" && (self || elevated(viewer))) || (m.state === "paused" && !self && elevated(viewer)),
    stop: live && (self || elevated(viewer)),
    resume: may && self && live && (m.state !== "active" || m.signerCurrent === false),
    renew: may && self && (nearEnd || !live),
  }
}

// "Ends in 2 days" inside a live mandate's last days, else nothing.
export function mandateEndsIn(m: Pick<MandateView, "state" | "expiresAt">, now: number): string | null {
  const left = Date.parse(m.expiresAt) - now
  if (!mandateLive(m) || left > MANDATE_ENDING_NOTICE_MS) return null
  return mandateEndsInWords(Math.max(1, Math.ceil(left / DAY_MS)))
}

const STATE_TONES = { active: "ok", paused: "warn", tripped: "danger", stopped: "muted", expired: "muted" } as const
function statePill(m: MandateView): Html {
  return pill(MANDATE_STATE_PILLS[m.state], STATE_TONES[m.state])
}

function ticked(classes: readonly MandateClass[]): MandateClass[] {
  return CLASS_ORDER.filter((c) => classes.includes(c))
}

function itemsWords(m: Pick<MandateView, "items" | "hiddenItems" | "signer">): Html {
  if (m.items === "all") return cardText(mandateAllItemsWords(m.signer.name, m.signer.self === true))
  const named = m.items.map((slug) => html`<code>${cardText(slug)}</code>`)
  const shown = named.flatMap((n, i) => (i === 0 ? [n] : [html`, `, n]))
  if (m.hiddenItems === 0) return html`${shown}`
  return html`${shown}${named.length > 0 ? " " : ""}<span data-region="mandate-hidden-items">${mandateHiddenItemsWords(m.hiddenItems, named.length === 0)}</span>`
}

function todayList(m: MandateView): Html {
  return html`<ul class="plain small" data-region="mandate-today">${ticked(m.classes).map((c) => html`<li data-class="${c}">${mandateTodayWords(m.today[c], m.caps[c], c)}</li>`)}</ul>`
}

function scheduleWords(schedule: MandateSchedule | null): string {
  return schedule === null ? MANDATE_ALWAYS_WORDS : mandateScheduleWords(schedule)
}

function mandateHref(shell: WorkspaceShell, id: string, query = ""): string {
  return workspaceHref(shell.identity.workspace.slug, `/mandates/${encodeURIComponent(id)}${query}`)
}
function signHref(shell: WorkspaceShell, query: string): string {
  return workspaceHref(shell.identity.workspace.slug, `/sign-mandate?${query}`)
}

// Resume, and the line under it the browser turns into No passkey needed
// when the vault plans none for this press.
const resumeButton = (): Html => html`<button type="button" class="btn primary sm" data-action="mandate-resume">${icon("passkey")}<span>${MANDATE_RESUME_BUTTON}</span></button>`
const resumeHint = (): Html => html`<p class="small muted" data-region="mandate-resume-hint">${MANDATE_RESUME_HINT}</p>`

// The data the browser needs to press a button: the mandate and the
// revision shown, which a press names so a change since refuses.
function controlButtons(shell: WorkspaceShell, m: MandateView, controls: MandateControls): Html {
  const buttons = [
    controls.pause ? html`<button type="button" class="btn secondary sm" data-action="mandate-pause">${MANDATE_PAUSE_BUTTON}</button>` : "",
    controls.resume ? resumeButton() : "",
    controls.renew ? html`<a class="btn secondary sm" href="${signHref(shell, `renew=${encodeURIComponent(m.id)}`)}" data-action="mandate-renew">${mandateLive(m) ? MANDATE_RENEW_LINK : MANDATE_SIGN_AGAIN_LINK}</a>` : "",
  ]
  if (!controls.pause && !controls.resume && !controls.renew) return html``
  return html`<div class="actions">${buttons}</div>${controls.resume ? resumeHint() : ""}`
}

function stopZone(m: MandateView, controls: MandateControls): Html {
  if (!controls.stop) return html``
  return html`<details class="card fold danger-zone" data-region="mandate-stop"${controlData(m)}><summary>${icon("chevronRight")}<span>${MANDATE_STOP_TITLE}</span></summary>
    <p>${MANDATE_STOP_WORDS}</p>
    <div class="actions"><button type="button" class="btn danger-quiet" data-action="mandate-stop">${MANDATE_STOP_BUTTON}</button></div>
  </details>`
}

function stateNotices(m: MandateView, now: number): Html {
  const lapsed = mandateLive(m) && m.signerCurrent === false
  const ends = mandateEndsIn(m, now)
  return html`${lapsed ? html`<div data-region="mandate-lapsed">${notice("warn", cardText(mandateLapsedWords(m.signer.name, m.signer.self === true)))}</div>` : ""}${ends !== null ? html`<p data-region="mandate-ends-in">${pill(ends, "warn")}</p>` : ""}`
}

function termsList(shell: WorkspaceShell, m: MandateView): Html {
  const ended = !mandateLive(m)
  return kv([
    [MANDATE_TERM_LABELS.machine, html`<a href="${workspaceHref(shell.identity.workspace.slug, `/devices/${encodeURIComponent(m.device.id)}`)}">${cardText(m.device.name)}</a>`],
    [MANDATE_TERM_LABELS.signer, cardText(m.signer.name)],
    [MANDATE_TERM_LABELS.state, statePill(m)],
    [MANDATE_TERM_LABELS.classes, mandateClassWords(m.classes)],
    [MANDATE_TERM_LABELS.credentials, html`<span data-region="mandate-items">${itemsWords(m)}</span>`],
    [MANDATE_TERM_LABELS.schedule, scheduleWords(m.schedule)],
    [MANDATE_TERM_LABELS.note, cardText(m.note)],
    [MANDATE_TERM_LABELS.signed, timeTag(m.createdAt)],
    [ended ? MANDATE_TERM_LABELS.ended : MANDATE_TERM_LABELS.ends, timeTag(m.expiresAt)],
  ], "facts")
}

function receiptRow(r: MandateReceiptView): Html {
  const what = mandateClassWords(r.classes)
  if (r.credential === null) {
    return html`<li class="row" data-region="mandate-receipt" data-hidden><span class="row-main"><span class="row-title">${MANDATE_HIDDEN_CREDENTIAL}</span><span class="row-sub">${what} · <code>${cardText(r.method)}</code></span></span><span class="row-side">${timeTag(r.at)}</span></li>`
  }
  const entry = r.credential.entry === "unreviewed" ? html`${MANDATE_UNREVIEWED_ENTRY}` : html`<code>${cardText(r.credential.entry)}</code>`
  return html`<li class="row" data-region="mandate-receipt"><span class="row-main"><span class="row-title"><code>${cardText(r.credential.slug)}</code></span><span class="row-sub">${what} · <code>${cardText(`${r.method} ${r.credential.host}`)}</code> · ${entry}${r.credential.run !== null ? html` · <code>${cardText(r.credential.run)}</code>` : ""}</span></span><span class="row-side">${timeTag(r.at)}</span></li>`
}

function receiptsCard(shell: WorkspaceShell, m: MandateView, page: MandateReceiptsPage | null): Html {
  const body = page === null ? html`<p class="muted">Its receipts could not be read.</p>`
    : page.receipts.length === 0 ? html`<p class="muted small">${MANDATE_RECEIPTS_EMPTY}</p>`
    : html`<ul class="rows compact">${page.receipts.map(receiptRow)}</ul>${page.next !== null ? html`<p><a class="btn secondary sm" data-region="mandate-receipts-older" href="${mandateHref(shell, m.id, `?before=${encodeURIComponent(page.next)}`)}">${MANDATE_RECEIPTS_OLDER}</a></p>` : ""}`
  return html`<section class="card" data-region="mandate-receipts"><h2>${MANDATE_RECEIPTS_TITLE}</h2><p class="small muted">${MANDATE_RECEIPTS_LEAD}</p>${body}</section>`
}

function controlData(m: MandateView): Html {
  return html` data-mandate="${m.id}" data-rev="${String(m.rev)}"`
}

// ---------------------------------------------------------------- one mandate

// others: for its signer, their other machines they may sign for.
export type MandatePageData = { viewer: Viewer; mandate: MandateView; receipts: MandateReceiptsPage | null; now: number; others?: { id: string; name: string }[] }

// "Sign the same for laptop-2": the sign page for another of the signer's
// machines on these terms. One machine per signature; never several.
function signSameLinks(shell: WorkspaceShell, m: MandateView, viewer: Viewer, others: readonly { id: string; name: string }[]): Html {
  if (m.signer.self !== true || viewer.held === true || others.length === 0) return html``
  return html`<div class="actions" data-region="mandate-sign-same">${others.map((d) => html`<a class="btn secondary sm" href="${signHref(shell, `device=${encodeURIComponent(d.id)}&from=${encodeURIComponent(m.id)}`)}">${cardText(mandateSignSameWords(d.name))}</a>`)}</div>`
}

export function mandatePage(shell: WorkspaceShell, data: MandatePageData): PageInput {
  const m = data.mandate
  const controls = mandateControls(m, data.viewer, data.now)
  const lead = m.endedReason === "replaced" ? MANDATE_REPLACED_WORDS : MANDATE_STATE_WORDS[m.state]
  return {
    title: spellCardText(`${m.device.name}: ${MANDATE_CARD_TITLE}`),
    viewer: null,
    workspace: shell,
    current: "machines",
    boot: { page: "mandate", mandate: m.id, rev: m.rev },
    body: html`${pageHead({ tile: kindTile("machine", undefined, "lg", m.device.name), eyebrow: MANDATE_CARD_TITLE, title: cardText(m.device.name), lead })}
      ${stateNotices(m, data.now)}
      <section class="card" data-region="mandate"${controlData(m)} data-state="${m.state}"><h2>The terms</h2>${termsList(shell, m)}${controlButtons(shell, m, controls)}${signSameLinks(shell, m, data.viewer, data.others ?? [])}</section>
      <section class="card" data-region="mandate-counts"><h2>${MANDATE_TERM_LABELS.today}</h2>${todayList(m)}<p class="small muted">${MANDATE_CAPS_WORDS}</p></section>
      ${receiptsCard(shell, m, data.receipts)}
      ${stopZone(m, controls)}`,
  }
}

// ---------------------------------------------------------------- the list

function listRow(shell: WorkspaceShell, m: MandateView, now: number): Html {
  const ends = mandateEndsIn(m, now)
  return row({
    tile: kindTile("machine", undefined, undefined, m.device.name),
    href: mandateHref(shell, m.id),
    title: cardText(m.device.name),
    sub: html`${mandateClassWords(m.classes)} · ${cardText(m.signer.name)} · ${mandateLive(m) ? html`until ${mandateDayWords(m.expiresAt)}` : mandateDayWords(m.expiresAt)}`,
    side: html`${statePill(m)}${ends !== null ? html` ${pill(ends, "warn", false)}` : ""}`,
  })
}

// An open proposal waiting for its machine's owner, with what it asks for
// and the machine's reason.
function proposalRow(shell: WorkspaceShell, p: MandateOpenProposal): Html {
  return row({
    tile: kindTile("machine", undefined, undefined, p.device.name),
    href: proposalHref(shell, p.id),
    title: cardText(p.device.name),
    sub: html`${mandateClassWords(p.classes)} · ${cardText(p.reason)}`,
    side: html`<span class="small muted">${MANDATE_WAITING_OPEN}</span>`,
  })
}
function proposalHref(shell: WorkspaceShell, id: string): string {
  return signHref(shell, `proposal=${encodeURIComponent(id)}`)
}
function waitingCard(shell: WorkspaceShell, proposals: readonly MandateOpenProposal[]): Html {
  if (proposals.length === 0) return html``
  return html`<section class="card" data-region="mandate-proposals"><h2>${MANDATE_WAITING_TITLE}</h2><p class="small muted">${MANDATE_WAITING_LEAD}</p><ul class="rows compact">${proposals.map((p) => proposalRow(shell, p))}</ul></section>`
}

// proposals: the open ones the reader may sign, newest first.
export type MandatesPageData = { viewer: Viewer; mandates: MandateView[]; proposals: MandateOpenProposal[]; now: number }

// Pause all: every active mandate here the reader may pause, each at the
// revision shown; the browser pauses them one by one.
function pauseAll(data: MandatesPageData): Html {
  const pausable = data.mandates.filter((m) => m.state === "active" && mandateControls(m, data.viewer, data.now).pause)
  if (pausable.length === 0) return html``
  return html`<div class="actions" data-region="mandates-pause-all"><button type="button" class="btn secondary sm" data-action="mandate-pause-all" data-pause="${pausable.map((m) => `${m.id}:${m.rev}`).join(" ")}" data-confirm="${mandatePauseAllConfirmWords(pausable.length)}">${MANDATE_PAUSE_ALL_BUTTON}</button></div><p class="small refused" data-region="mandates-pause-all-refused" aria-live="polite" hidden></p>`
}

export function mandatesPage(shell: WorkspaceShell, data: MandatesPageData): PageInput {
  const live = data.mandates.filter(mandateLive)
  const ended = data.mandates.filter((m) => !mandateLive(m))
  return {
    title: MANDATE_LIST_TITLE,
    viewer: null,
    workspace: shell,
    current: "machines",
    boot: { page: "mandates" },
    body: html`${pageHead({ eyebrow: "Machines", title: MANDATE_LIST_TITLE, lead: MANDATE_LIST_LEAD })}
      ${waitingCard(shell, data.proposals)}
      <section class="card" data-region="mandates-live">${pauseAll(data)}${live.length === 0 ? emptyState("cpu", MANDATE_LIST_EMPTY, MANDATE_CARD_LEAD) : html`<ul class="rows">${live.map((m) => listRow(shell, m, data.now))}</ul>`}</section>
      ${ended.length > 0 ? html`<section class="card" data-region="mandates-ended"><h2>${MANDATE_LIST_ENDED}</h2><ul class="rows compact">${ended.map((m) => listRow(shell, m, data.now))}</ul></section>` : ""}`,
  }
}

// ---------------------------------------------------------------- the machine page

// The machine's live mandate, the newest of its own in the list; null when
// it has none. A machine has at most one live at a time.
export function liveMandateOf(list: MandateList | null, device: string): MandateView | null {
  return list?.mandates.find((m) => m.device.id === device && mandateLive(m)) ?? null
}

// proposals: this machine's open ones its owner may sign.
export type MandateCardData = { viewer: Viewer; device: WorkspaceDeviceView; mandate: MandateView | null; proposals: MandateOpenProposal[]; now: number }

// "Carry on without asking" on a machine's page: its live mandate with
// Resume, Pause and Stop, and for its owner, Trust this machine.
export function mandateCard(shell: WorkspaceShell, data: MandateCardData): Html {
  const m = data.mandate
  const own = data.device.owner.kind === "member" && data.device.owner.member === data.viewer.member && !data.device.revoked && data.viewer.held !== true
  if (m === null && !own) return html``
  const waiting = own && data.proposals.length > 0 ? html`<div data-region="mandate-waiting"><h3>${MANDATE_WAITING_TITLE}</h3><ul class="plain small">${data.proposals.map((p) => html`<li><a href="${proposalHref(shell, p.id)}" data-action="mandate-proposal">${mandateClassWords(p.classes)}</a> · ${cardText(p.reason)}</li>`)}</ul></div>` : ""
  const trust = own && m === null ? html`<div class="actions"><a class="btn primary sm" data-action="mandate-trust" href="${signHref(shell, `device=${encodeURIComponent(data.device.device)}`)}">${MANDATE_TRUST_BUTTON}</a></div>` : ""
  if (m === null) return html`<section class="card" id="carry-on" data-region="mandate-card"><h2>${MANDATE_CARD_TITLE}</h2><p class="small muted">${MANDATE_CARD_LEAD}</p>${waiting}${trust}</section>`
  const controls = mandateControls(m, data.viewer, data.now)
  const ends = mandateEndsIn(m, data.now)
  return html`<section class="card" id="carry-on" data-region="mandate-card"${controlData(m)} data-state="${m.state}"><h2>${MANDATE_CARD_TITLE}</h2>
    ${mandateLive(m) && m.signerCurrent === false ? html`<div data-region="mandate-lapsed">${notice("warn", cardText(mandateLapsedWords(m.signer.name, m.signer.self === true)))}</div>` : ""}
    ${waiting}
    ${kv([[MANDATE_TERM_LABELS.state, html`${statePill(m)}${ends !== null ? html` ${pill(ends, "warn", false)}` : ""}`], [MANDATE_TERM_LABELS.classes, mandateClassWords(m.classes)], [MANDATE_TERM_LABELS.signer, cardText(m.signer.name)], [MANDATE_TERM_LABELS.ends, timeTag(m.expiresAt)], [MANDATE_TERM_LABELS.today, todayList(m)]])}
    <div class="actions"><a class="btn secondary sm" href="${mandateHref(shell, m.id)}">${MANDATE_OPEN_LINK}</a>${controls.resume ? resumeButton() : ""}${controls.pause ? html`<button type="button" class="btn secondary sm" data-action="mandate-pause">${MANDATE_PAUSE_BUTTON}</button>` : ""}${controls.stop ? html`<button type="button" class="btn danger-quiet sm" data-action="mandate-stop">${MANDATE_STOP_BUTTON}</button>` : ""}</div>
    ${controls.resume ? resumeHint() : ""}
  </section>`
}

// ---------------------------------------------------------------- the home

// The machines whose mandate is active now and still stood behind by its
// signer; a lapsed one covers nothing.
export function activeMandateMachines(list: MandateList | null): number | null {
  return list === null ? null : new Set(list.mandates.filter((m) => m.state === "active" && m.signerCurrent !== false).map((m) => m.device.id)).size
}

// The machines whose mandate the reader signed is active but lapsed: it
// covers nothing until they resume it.
export function resumeMandateMachines(list: MandateList | null): number | null {
  return list === null ? null : new Set(list.mandates.filter((m) => m.state === "active" && m.signer.self === true && m.signerCurrent === false).map((m) => m.device.id)).size
}

// resume: how many machines need the reader to resume their mandate.
export function mandateStrip(shell: WorkspaceShell, machines: number | null, resume: number | null = null): Html {
  const href = workspaceHref(shell.identity.workspace.slug, "/mandates")
  const carrying = machines !== null && machines > 0 ? html`<a class="strip card" data-region="mandate-strip" href="${href}">${icon("cpu")}<span>${machinesCarryingOnWords(machines)}</span>${icon("chevronRight")}</a>` : ""
  const lapsed = resume !== null && resume > 0 ? html`<a class="strip card" data-region="mandate-resume-strip" href="${href}">${icon("passkey")}<span>${machinesNeedResumeWords(resume)}</span>${icon("chevronRight")}</a>` : ""
  return html`${carrying}${lapsed}`
}

// ---------------------------------------------------------------- the sign page

// What the form opens on: a proposal's terms, a renewed mandate's, or the
// defaults: read alone ticked, every cap at its default, 30 days.
export type MandateSignStart = { classes: MandateClass[]; caps: Record<MandateClass, number>; items: "all" | string[]; ttlDays: MandateTtlDays; schedule: MandateSchedule | null; note: string }

// Without a proposal: the narrowest terms, read alone ticked, no
// credential, 30 days, and a note naming the machine. Every other kind,
// every credential and a longer term are the signer's own choice.
export function mandateSignDefaults(machine: string): MandateSignStart {
  return { classes: ["read"], caps: { ...MANDATE_CAP_DEFAULTS }, items: [], ttlDays: MANDATE_PROPOSAL_DEFAULT_TTL_DAYS, schedule: null, note: mandateDefaultNote(machine).slice(0, MANDATE_NOTE_MAX) }
}

// `from`: the proposal or the mandate renewed, if any; `candidates`: the
// credentials the vault says this person may name for this machine;
// `replaces`: the machine's live mandate, which signing replaces.
export type MandateSignData = {
  viewer: Viewer
  device: WorkspaceDeviceView
  candidates: MandateCandidates | null
  start: MandateSignStart
  proposal: MandateProposalView | null
  renews: MandateView | null
  replaces: MandateView | null
  now: number
}

// The terms a start names, by id, for the summary the page opens with:
// ticked credentials among the candidates.
function startTicks(data: MandateSignData): Set<string> {
  return new Set(data.start.items === "all" ? [] : data.start.items)
}

export function mandateSummaryOf(machine: string, start: MandateSignStart, candidates: MandateCandidates | null, now: number): string[] | null {
  const ids = new Set(start.items === "all" ? [] : start.items)
  const slugs = start.items === "all" ? "all" as const : (candidates?.items ?? []).filter((c) => ids.has(c.id)).map((c) => c.slug)
  if (slugs !== "all" && slugs.length === 0) return null
  if (start.note.trim() === "") return null
  const input: MandateSummaryInput = { machine, classes: start.classes, caps: start.caps, items: slugs, endsAt: now + start.ttlDays * DAY_MS, schedule: start.schedule }
  return mandateSummaryWords(input)
}

function classTick(c: MandateClass, start: MandateSignStart): Html {
  const words = MANDATE_CLASS_CHOICES[c]
  const on = c === "read" || start.classes.includes(c)
  return html`<label class="tick"><input type="checkbox" data-input="mandate-class" value="${c}"${on ? html` checked` : ""}${c === "read" ? html` disabled` : ""}><span><b>${words.name}</b> <span class="muted small">${words.words}</span></span></label>`
}

function capField(c: MandateClass, start: MandateSignStart): Html {
  const on = c === "read" || start.classes.includes(c)
  return html`<label class="field" data-region="mandate-cap" data-class="${c}"${on ? "" : html` hidden`}><span class="label">${MANDATE_CLASS_CHOICES[c].name}</span><input type="text" inputmode="numeric" autocomplete="off" maxlength="6" data-input="mandate-cap" data-class="${c}" value="${String(start.caps[c] > 0 ? start.caps[c] : MANDATE_CAP_DEFAULTS[c])}"><span class="hint">${mandateCapHint(MANDATE_CAP_MAX[c])}</span></label>`
}

function itemsField(data: MandateSignData): Html {
  const all = data.start.items === "all"
  const candidates = data.candidates?.items ?? []
  const ticks = startTicks(data)
  const none = candidates.length === 0
  return html`<fieldset class="field" data-region="mandate-items-field"><legend class="label">${MANDATE_ITEMS_LABEL}</legend>
    <label class="tick"><input type="radio" name="mandate-items" data-input="mandate-items" value="listed"${!all && !none ? html` checked` : ""}${none ? html` disabled` : ""}><span>${MANDATE_LISTED_ITEMS}</span></label>
    ${none ? html`<p class="small muted" data-region="mandate-no-candidates">${MANDATE_NO_CANDIDATES}</p>` : html`<ul class="plain" data-region="mandate-candidates">${candidates.map((c) => html`<li><label class="tick"><input type="checkbox" data-input="mandate-item" value="${c.id}" data-slug="${c.slug}"${ticks.has(c.id) ? html` checked` : ""}${all ? html` disabled` : ""}><span><code>${cardText(c.slug)}</code></span></label></li>`)}</ul>`}
    <label class="tick"><input type="radio" name="mandate-items" data-input="mandate-items" value="all"${all ? html` checked` : ""}><span>${MANDATE_ALL_CREDENTIALS}</span></label>
  </fieldset>`
}

function ttlField(start: MandateSignStart): Html {
  return html`<fieldset class="field" data-region="mandate-ttl"><legend class="label">${MANDATE_TTL_LABEL}</legend><div class="mandate-ticks">${MANDATE_TTL_DAYS.map((d) => html`<label class="tick"><input type="radio" name="mandate-ttl" data-input="mandate-ttl" value="${String(d)}"${d === start.ttlDays ? html` checked` : ""}><span>${mandateTtlWords(d)}</span></label>`)}</div></fieldset>`
}

// One row per window a proposal or a renewed mandate names, or one empty
// row; the zone the browser fills in when none is named.
function scheduleField(start: MandateSignStart): Html {
  const on = start.schedule !== null
  const windows = start.schedule?.windows ?? [{ days: [1, 2, 3, 4, 5], from: "09:00", to: "18:00" }]
  return html`<fieldset class="field" data-region="mandate-schedule-field">
    <label class="tick"><input type="checkbox" data-input="mandate-schedule"${on ? html` checked` : ""}><span>${MANDATE_SCHEDULE_TICK}</span></label>
    <div class="stack" data-region="mandate-schedule"${on ? "" : html` hidden`}>
      <label class="field"><span class="label">${MANDATE_SCHEDULE_LABELS.tz}</span><input type="text" data-input="mandate-tz" autocomplete="off" maxlength="64" value="${start.schedule?.tz ?? ""}"></label>
      ${windows.map((w) => html`<div class="stack" data-region="mandate-window"><div class="mandate-ticks" role="group" aria-label="${MANDATE_SCHEDULE_LABELS.days}">${DAY_NUMBERS.map((d) => html`<label class="tick"><input type="checkbox" data-input="mandate-day" value="${String(d)}"${w.days.includes(d) ? html` checked` : ""}><span>${DAY_SHORT[d]}</span></label>`)}</div>
        <div class="mandate-times"><label class="field"><span class="label">${MANDATE_SCHEDULE_LABELS.from}</span><input type="text" inputmode="numeric" autocomplete="off" maxlength="5" placeholder="09:00" data-input="mandate-from" value="${w.from}"></label><label class="field"><span class="label">${MANDATE_SCHEDULE_LABELS.to}</span><input type="text" inputmode="numeric" autocomplete="off" maxlength="5" placeholder="18:00" data-input="mandate-to" value="${w.to}"></label></div></div>`)}
      <p class="small muted">${MANDATE_SCHEDULE_HINT}</p>
    </div>
  </fieldset>`
}

// Why there is no form: someone else's machine, or for its owner, a held
// account or credentials that could not be read.
function signRefusal(shell: WorkspaceShell, data: MandateSignData): Html | null {
  const owner = data.device.owner
  if (owner.kind === "team") return html`${notice("info", MANDATE_TEAM_MACHINE_WORDS)}`
  const back = html`<p><a class="btn secondary sm" href="${workspaceHref(shell.identity.workspace.slug, `/devices/${encodeURIComponent(data.device.device)}`)}">Back to the machine</a></p>`
  if (owner.member !== data.viewer.member || data.device.revoked) return html`${notice("info", cardText(mandateNotOwnerWords(owner.name)))}${back}`
  if (data.viewer.held === true) return html`${notice("warn", HELD_WORDS)}${back}`
  if (data.candidates === null) return html`${notice("warn", MANDATE_CANDIDATES_UNREAD_WORDS)}${back}`
  return null
}

export function mandateSignPage(shell: WorkspaceShell, data: MandateSignData): PageInput {
  const refusal = signRefusal(shell, data)
  const name = data.device.name
  const head = pageHead({ tile: kindTile("machine", undefined, "lg", name), eyebrow: MANDATE_SIGN_EYEBROW, title: cardText(mandateSignTitle(name)), lead: MANDATE_SIGN_LEAD })
  if (refusal !== null) {
    return { title: spellCardText(mandateSignTitle(name)), viewer: null, workspace: shell, current: "machines", boot: { page: "mandate-sign", device: data.device.device, refused: true }, body: html`${head}${refusal ?? ""}` }
  }
  const summary = mandateSummaryOf(name, data.start, data.candidates, data.now)
  const proposal = data.proposal
  const open = proposal !== null && proposal.state === "open"
  return {
    title: spellCardText(mandateSignTitle(name)),
    viewer: null,
    workspace: shell,
    current: "machines",
    boot: { page: "mandate-sign", device: data.device.device, machine: name, signer: data.viewer.member, proposal: open ? proposal.id : null },
    body: html`${head}
      ${proposal !== null ? html`<div data-region="mandate-proposed">${notice("info", cardText(mandateProposedWords(name)), open ? cardText(proposal.reason) : proposal.closedReason === "unbound" ? mandateProposalUnboundWords(proposal.unbound ?? []) : proposal.state === "expired" && proposal.mandate !== null ? html`${MANDATE_PROPOSAL_SUPERSEDED_WORDS} <a href="${mandateHref(shell, proposal.mandate)}">${MANDATE_OPEN_LINK}</a>` : MANDATE_PROPOSAL_CLOSED_WORDS)}</div>` : ""}
      ${data.replaces !== null ? html`<div data-region="mandate-replaces">${notice("warn", MANDATE_REPLACES_WORDS, html`<a href="${mandateHref(shell, data.replaces.id)}">${MANDATE_OPEN_LINK}</a>`)}</div>` : ""}
      <form class="card stack" data-form="mandate-sign" novalidate>
        <fieldset class="field" data-region="mandate-classes"><legend class="label">${MANDATE_CLASSES_LABEL}</legend>${ticked([...MANDATE_CLASSES]).map((c) => classTick(c, data.start))}</fieldset>
        ${itemsField(data)}
        <fieldset class="field" data-region="mandate-caps"><legend class="label">${MANDATE_CAPS_LABEL}</legend><div class="mandate-times">${CLASS_ORDER.map((c) => capField(c, data.start))}</div><p class="hint">${MANDATE_CAPS_WORDS}</p></fieldset>
        ${ttlField(data.start)}
        ${scheduleField(data.start)}
        <label class="field"><span class="label">${MANDATE_NOTE_LABEL}</span><input type="text" data-input="mandate-note" maxlength="${String(MANDATE_NOTE_MAX)}" autocomplete="off" value="${data.start.note}"><span class="hint">${MANDATE_NOTE_HINT}</span></label>
      </form>
      <section class="card" data-region="mandate-summary-card"><h2>${MANDATE_SUMMARY_TITLE}</h2>
        <div class="stack" data-region="mandate-summary">${(summary ?? []).map((line) => html`<p>${cardText(line)}</p>`)}</div>
        <p class="small" data-region="mandate-refusal"${summary !== null ? html` hidden` : ""}></p>
        <div class="actions"><button type="button" class="btn primary" data-action="mandate-sign"${summary === null ? html` disabled` : ""}>${icon("passkey")}<span>${MANDATE_SIGN_BUTTON}</span></button></div>
      </section>`,
  }
}
