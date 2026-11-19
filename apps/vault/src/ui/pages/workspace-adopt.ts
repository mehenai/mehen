// The adoption review page (/w/<slug>/b/<id>): a batch a machine uploaded
// from files it already holds, every row with what would be stored, where
// it was found, and where it belongs. The person unticks or rehomes rows
// and approves the whole batch with one passkey over adoptionDigest. It
// takes the ask pages' decision layout (workspace-asks.ts): the warning
// card first when warned, the decision card, what happens next, and the
// decision bar. No value is ever in the page or its boot data: per secret
// field only its length, prefix and fingerprint.

import { ADOPTION_LIMITS, type AdoptionAffected, type AdoptionCompareView, type WorkspaceAdoptionItemView, type WorkspaceAdoptionView } from "@mehen/protocol/adopt"
import { isLeaseOnly, leaseOnlyDelivery } from "@mehen/protocol/binding"
import { KINDS } from "@mehen/protocol/kinds"
import type { CredentialHome, WorkspaceProject } from "@mehen/protocol/workspace"
import { askPlace, decisionBar, warningCard } from "../ask-evidence.ts"
import { askWarnings, stringsOf } from "../ask-safety.ts"
import { ADOPTION_RESULT_WORDS, adoptionActions, adoptionKeepOpenShown, adoptionKeepOpenWords, adoptionApproveLabel, adoptionCustom, adoptionDefaultAction, adoptionHolderGone, adoptionRenameSlug, adoptionUndecided, adoptionUndecidedWords, adoptionGroups, adoptionHomeCounts, adoptionStale, adoptionStartHome, adoptionTickedByDefault } from "../client/pages/workspace-adopt-logic.ts"
import { cardText, countdownTimer, hostList, injectionWords, notice, pill, timeTag } from "../components.ts"
import { homeKey } from "../home-key.ts"
import { type Html, html } from "../html.ts"
import type { PageInput } from "../layout.ts"
import { type WorkspaceShell, workspaceHref } from "../shell.ts"
import { PASSKEY_CONFIRMS_WORDS, SESSION_LABEL_WORDS, adoptionCount, bindingLimits, joinWords } from "../wording.ts"
import { belongsToWords } from "../workspace-rights.ts"
import { heldNotice } from "./workspace-asks.ts"

export const ADOPTION_RENAME_WORDS = "Names come from the machine's plan. Only a row whose name is already held can be kept here under another name; to store any other under another name, untick it and adopt it again under the name you want."
export const ADOPTION_UNTICKED_WORDS = "Rows with a problem, only stale sources or a destination no template vouches for start unticked."
export const ADOPTION_CLOSED_WORDS = {
  approved: "This batch was approved and its credentials are stored. The machine finishes with mehen adopt apply.",
  cancelled: "This batch was cancelled. Nothing in it was stored.",
  expired: "This batch ran out before it was approved. Nothing in it was stored.",
} as const

// Every string the page shows that came from the machine or the vault's
// records, for the hidden-character warnings.
export function adoptionTexts(view: WorkspaceAdoptionView): string[] {
  return [
    view.requestedBy.deviceName,
    view.requestedBy.session ?? "",
    ...view.machines.map((m) => m.name),
    ...view.items.flatMap((i) => [
      i.slug,
      i.providerName ?? "",
      ...stringsOf(i.binding.value),
      ...stringsOf(i.injection.value),
      ...i.tags,
      ...Object.entries(i.publicFields).flat(),
      ...i.secrets.flatMap((s) => [s.name, s.prefix]),
      ...i.sources.flatMap((s) => [s.machine, s.path, s.variable ?? "", s.pointer ?? "", ...s.stale]),
      i.repo?.remote ?? "",
      i.repo?.env ?? "",
      ...compareTexts(i.compare ?? null),
    ]),
  ]
}

function compareTexts(compare: AdoptionCompareView | null): string[] {
  if (compare === null) return []
  const { holder, affected } = compare
  return [
    holder.slug,
    ...holder.secrets.flatMap((s) => [s.name, s.prefix]),
    ...(holder.type === "staged" ? holder.sources.flatMap((s) => [s.machine, s.path, s.variable ?? "", s.pointer ?? "", ...s.stale]) : []),
    ...compare.fields.map((f) => f.name),
    ...(affected ? [...affected.references.flatMap((r) => [r.project, r.env, r.variable]), ...affected.machines, ...affected.connections] : []),
  ]
}

function joined(parts: readonly Html[]): Html {
  return html`${parts.map((part, i) => (i === 0 ? part : html`, ${part}`))}`
}

function homeOptions(item: WorkspaceAdoptionItemView, labels: ReadonlyMap<string, string>): Html {
  const start = adoptionStartHome(item)
  const none = start === null ? html`<option value="" selected>Choose where it belongs</option>` : ""
  return html`<select data-input="home" aria-label="Where ${item.slug} belongs">${none}${item.homesAllowed.map((h) => html`<option value="${homeKey(h)}"${start !== null && homeKey(h) === homeKey(start) ? html` selected` : ""}>${labels.get(homeKey(h)) ?? ""}</option>`)}</select>`
}

function destination(item: WorkspaceAdoptionItemView): Html {
  if (item.binding.verified) return html`${hostList(item.binding.value.hosts)}<p class="small muted">From ${item.providerName !== null ? html`the ${cardText(item.providerName)} template` : "a vault template"}, not from the agent.</p>`
  const hosts = item.binding.value.hosts
  if (isLeaseOnly(item.binding.value)) return hostList(hosts, leaseOnlyDelivery(item.kind, KINDS[item.kind].defaultCeiling))
  const limits = bindingLimits(item.binding.value)
  return html`<div class="adopt-custom" data-region="custom-destination"><p class="dest-warning">Proposed by the agent, not verified. ${hosts.length === 1 ? "Check this host is the real service." : `Check each of these ${hosts.length} hosts is the real service.`}</p>${hostList(hosts)}${limits.length ? html`<ul class="limits">${limits.map((l) => html`<li>${cardText(l)}</li>`)}</ul>` : ""}</div>`
}

function sourceLine(source: WorkspaceAdoptionItemView["sources"][number]): Html {
  const where = source.variable !== null ? html` as <code>${cardText(source.variable)}</code>` : source.pointer !== null ? html` at <code>${cardText(source.pointer)}</code>` : ""
  const changed = source.mtime ? html`, changed ${timeTag(source.mtime)}` : ""
  const stale = source.stale.length > 0 ? html` ${pill("stale", "warn", false)} <span class="small">${joined(source.stale.map((s) => cardText(s)))}</span>` : ""
  return html`<li><code>${cardText(source.path)}</code>${where} on ${cardText(source.machine)}${changed}${stale}</li>`
}

const RESULT_TONES = { same: "ok", differs: "warn", unknown: "muted" } as const

function holderLine(compare: AdoptionCompareView, adoption: string): Html {
  const { holder } = compare
  if (holder.type === "stored") return html`<code class="slug-inline">${cardText(holder.slug)}</code> is already in the vault, version ${holder.version}, last rotated ${holder.rotatedAt !== null ? timeTag(holder.rotatedAt) : "never"}, last used ${holder.lastUsedAt !== null ? timeTag(holder.lastUsedAt) : "never"}.`
  const [batch = "", ref = ""] = holder.id.split("/")
  return batch === adoption ? html`Row ${cardText(ref)} of this batch holds this name too.` : html`A row waiting in batch <code>${cardText(batch)}</code> holds this name.`
}

// What replacing a stored holder would reach, by name only.
function affectedList(affected: AdoptionAffected): Html {
  const devices = affected.leasingDevices === 1 ? "1 device holds a lease of its current value." : `${affected.leasingDevices} devices hold a lease of its current value.`
  return html`<div class="adopt-affected" data-region="affected"><p class="small">Replacing it reaches:</p>
    ${affected.references.length > 0 ? html`<ul class="adopt-refs">${affected.references.map((r) => html`<li><code>${cardText(r.project)} / ${cardText(r.env)} / ${cardText(r.variable)}</code></li>`)}</ul>` : html`<p class="small muted">No variable you can see uses it.</p>`}
    <p class="small">${affected.machines.length > 0 ? html`Machines that use it: ${cardText(joinWords(affected.machines))}.` : "No adopting machine uses it."} ${devices}</p>
    ${affected.connections.length > 0 ? html`<p class="small">Connections that depend on it: ${cardText(joinWords(affected.connections))}.</p>` : ""}</div>`
}

export const ADOPTION_MAP_DIFFERS_WORDS = "This machine still holds another value: check it, then revoke it at the provider."
export const ADOPTION_OTHER_BATCH_WORDS = "A row of another batch can only be kept beside this one until that batch is decided."
const ACTION_WORDS = { map: "Keep the vault's value", replace: "Replace it with this value", rename: "Keep both, this one under another name" } as const

// The actions this row may take, the one it starts with checked; a copy's
// name shows once rename is chosen.
function actionChoice(item: WorkspaceAdoptionItemView, adoption: string, taken: ReadonlySet<string>): Html {
  const actions = adoptionActions(item, adoption).filter((a): a is keyof typeof ACTION_WORDS => a !== "store")
  const start = adoptionDefaultAction(item, adoption)
  const differs = (item.compare?.fields ?? []).some((f) => f.result !== "same")
  const words = (action: keyof typeof ACTION_WORDS) => (action === "map" && differs ? `${ACTION_WORDS.map}. ${ADOPTION_MAP_DIFFERS_WORDS}` : ACTION_WORDS[action])
  return html`<fieldset class="adopt-actions" data-region="actions"><legend class="label">What to do with it</legend>
    ${actions.includes("map") || adoptionHolderGone(item) ? "" : html`<p class="small muted">${ADOPTION_OTHER_BATCH_WORDS}</p>`}
    ${actions.map((a) => html`<label class="tick"><input type="radio" name="action-${item.ref}" value="${a}" data-input="action"${a === start ? html` checked` : ""}><span>${words(a)}</span></label>`)}
    ${actions.includes("rename") ? html`<div class="adopt-rename" data-region="rename"${start === "rename" ? "" : html` hidden`}><label class="field"><span class="label">Name for this one</span><input type="text" data-input="rename-slug" value="${adoptionRenameSlug(item, taken)}" autocomplete="off" spellcheck="false" aria-label="Name for the copy of ${item.slug}"></label>${repointChoice(item)}</div>` : ""}
  </fieldset>`
}

// The variables bound to a stored holder, each a box to point it at the
// kept copy instead; a project holds one value per environment, so the
// change reaches every machine.
function repointChoice(item: WorkspaceAdoptionItemView): Html {
  const compare = item.compare ?? null
  const refs = compare?.affected?.references ?? []
  if (compare === null || refs.length === 0) return html``
  return html`<fieldset class="adopt-repoint"><legend class="label">Variables that use <code>${cardText(compare.holder.slug)}</code></legend>
    ${refs.map((r) => html`<label class="tick"><input type="checkbox" data-input="repoint" data-project="${r.project}" data-env="${r.env}" data-variable="${r.variable}"><span>Point <code>${cardText(r.project)} / ${cardText(r.env)} / ${cardText(r.variable)}</code> at this one, for every machine</span></label>`)}
    <p class="small muted">A variable you leave unticked stays on <code>${cardText(compare.holder.slug)}</code>.</p></fieldset>`
}

// A compare row's holder, the result per secret field in words, the
// holder's hints, for a stored holder what a replace reaches, and the
// actions. Never a fingerprint: those are the boot data's, for signing only.
// A holder gone or hidden shows nothing of it, only the actions left.
function conflictSection(item: WorkspaceAdoptionItemView, adoption: string, taken: ReadonlySet<string>): Html {
  const compare = item.compare ?? null
  if (compare === null) return adoptionHolderGone(item) ? html`<div class="adopt-conflict" data-region="conflict">${actionChoice(item, adoption, taken)}</div>` : html``
  const { holder } = compare
  return html`<div class="adopt-conflict" data-region="conflict">
    <p>${holderLine(compare, adoption)}</p>
    <ul class="fields">${compare.fields.map((f) => html`<li><span class="field-name">${cardText(f.name)}</span> ${pill(ADOPTION_RESULT_WORDS[f.result], RESULT_TONES[f.result], false)}</li>`)}</ul>
    <ul class="fields small">${holder.secrets.map((s) => html`<li>The vault's value: ${s.length} characters${s.prefix !== "" ? html`, starts <code>${cardText(s.prefix)}</code>` : ""}</li>`)}</ul>
    ${holder.type === "staged" ? html`<ul class="adopt-sources small">${holder.sources.map(sourceLine)}</ul>` : ""}
    ${compare.affected ? affectedList(compare.affected) : ""}
    ${actionChoice(item, adoption, taken)}
  </div>`
}

function itemRow(item: WorkspaceAdoptionItemView, labels: ReadonlyMap<string, string>, adoption: string, taken: ReadonlySet<string>): Html {
  const ticked = adoptionTickedByDefault(item)
  const custom = adoptionCustom(item)
  const stale = adoptionStale(item)
  const machines = [...new Set(item.sources.map((s) => s.machine))].join("\n")
  const what = item.providerName !== null ? cardText(item.providerName) : html`${KINDS[item.kind].label}`
  const fields = Object.entries(item.publicFields)
  return html`<li class="adopt-row${custom ? " custom" : ""}" data-row data-ref="${item.ref}" data-problem="${String(item.problem !== null)}" data-custom="${String(custom)}" data-stale="${String(stale)}" data-machines="${machines}">
    <div class="adopt-row-head">
      <label class="tick"><input type="checkbox" form="decide" data-input="include"${ticked ? html` checked` : ""}><span><code class="slug-inline">${cardText(item.slug)}</code> <span class="muted small">${item.ref}</span></span></label>
      <span class="small">${what}</span>
    </div>
    <p class="adopt-problem" role="status" data-region="row-problem"${item.problem === null ? html` hidden` : ""}>${item.problem ?? ""}</p>
    <dl class="kv small">
      <dt>Sends to</dt><dd>${destination(item)}</dd>
      ${custom && item.injection.value !== null ? html`<dt>How it is sent</dt><dd data-region="adopt-injection">${injectionWords(item.injection.value)}</dd>` : ""}
      <dt>Belongs to</dt><dd>${homeOptions(item, labels)}</dd>
      ${item.tags.length > 0 ? html`<dt>Tags</dt><dd>${item.tags.map((t) => html`<code>${cardText(t)}</code> `)}</dd>` : ""}
      ${fields.length > 0 ? html`<dt>Public fields</dt><dd><ul class="fields">${fields.map(([name, value]) => html`<li><span class="field-name">${cardText(name)}</span> <code>${cardText(value)}</code></li>`)}</ul></dd>` : ""}
      <dt>Secret</dt><dd><ul class="fields">${item.secrets.map((s) => html`<li><span class="field-name">${cardText(s.name)}</span> <span class="field-facts">${s.length} characters${s.prefix !== "" ? html`, starts <code>${cardText(s.prefix)}</code>` : ""}, fingerprint <code>${s.fingerprint}</code></span></li>`)}</ul></dd>
      <dt>Found in</dt><dd><ul class="adopt-sources">${item.sources.map(sourceLine)}</ul></dd>
      ${item.sameValueAs.length > 0 ? html`<dt>Same value as</dt><dd>${item.sameValueAs.join(", ")}</dd>` : ""}
    </dl>
    ${conflictSection(item, adoption, taken)}
  </li>`
}

export const ADOPTION_KEEP_VAULT_WORDS = "Keep the vault's value for every remaining one"

function filters(view: WorkspaceAdoptionView, homes: readonly CredentialHome[], labels: ReadonlyMap<string, string>): Html {
  const mayKeep = view.items.some((i) => adoptionActions(i, view.adoption).includes("map"))
  return html`<section class="card adopt-tools" data-region="adopt-tools" aria-label="Filter and change rows">
    <fieldset class="adopt-filters"><legend class="label">Show only</legend>
      <label class="tick"><input type="checkbox" data-filter="problem"><span>Rows with a problem</span></label>
      <label class="tick"><input type="checkbox" data-filter="custom"><span>Custom destinations</span></label>
      <label class="tick"><input type="checkbox" data-filter="stale"><span>Stale sources</span></label>
      ${view.machines.length > 1 ? html`<label class="field"><span class="label">Machine</span><select data-filter="machine"><option value="">Every machine</option>${view.machines.map((m) => html`<option value="${m.name}">${cardText(m.name)}</option>`)}</select></label>` : ""}
    </fieldset>
    <div class="adopt-bulk">
      <button type="button" class="btn secondary sm" data-action="untick-stale">Untick stale rows</button>
      ${mayKeep ? html`<button type="button" class="btn secondary sm" data-action="keep-vault-all">${ADOPTION_KEEP_VAULT_WORDS}</button>` : ""}
      ${homes.length > 0 ? html`<label class="field"><span class="label">Home for every ticked row</span><select data-input="bulk-home">${homes.map((h) => html`<option value="${homeKey(h)}">${labels.get(homeKey(h)) ?? ""}</option>`)}</select></label><button type="button" class="btn secondary sm" data-action="set-home">Set home</button>` : ""}
    </div>
  </section>`
}

// The expiry the page shows, which keep-open sends back so a second click
// extends the batch once.
function keepOpen(view: WorkspaceAdoptionView): Html {
  if (!adoptionKeepOpenShown(view) || view.maxExpiresAt === undefined) return html``
  return html`<div class="adopt-keep" data-region="keep-open"><p class="small">Open until <span data-region="expires">${timeTag(view.expiresAt)}</span>; it can be kept open until ${timeTag(view.maxExpiresAt)}.</p><button type="button" class="btn secondary sm" data-action="keep-open" data-expires="${view.expiresAt}"><span data-region="keep-open-label">${adoptionKeepOpenWords(view)}</span></button></div>`
}

function closedPage(shell: WorkspaceShell, view: WorkspaceAdoptionView): PageInput {
  const slug = shell.identity.workspace.slug
  const status = view.status === "open" ? "expired" : view.status
  return {
    title: "Adoption batch",
    viewer: null,
    workspace: shell,
    boot: { page: "ws-adoption-closed", adoption: view.adoption, status },
    body: html`<section class="card adopt-head" data-region="adopt-head"><p class="eyebrow">${cardText(view.requestedBy.deviceName)} asked to adopt credentials</p><h1>Adoption batch <code>${view.adoption}</code></h1>
      ${notice(status === "approved" ? "ok" : "info", status === "approved" ? "Approved" : status === "cancelled" ? "Cancelled" : "Ran out", ADOPTION_CLOSED_WORDS[status])}
      <p><a class="btn secondary sm" href="${workspaceHref(slug, "/credentials")}">Credentials</a></p></section>`,
  }
}

export function workspaceAdoptionPage(shell: WorkspaceShell, view: WorkspaceAdoptionView, projects: readonly WorkspaceProject[], now = Date.now()): PageInput {
  if (view.status !== "open") return closedPage(shell, view)
  const slugs = new Map(projects.map((p) => [p.id, p.slug]))
  const homes = view.items[0]?.homesAllowed ?? []
  const labels = new Map([...homes, ...view.items.map((i) => i.home)].map((h) => [homeKey(h), belongsToWords(h, slugs)]))
  const offered = homes.map((h) => [homeKey(h), labels.get(homeKey(h)) ?? ""] as const)
  const warnings = askWarnings([...adoptionTexts(view), shell.identity.workspace.name, shell.identity.workspace.slug, ...labels.values()])
  const warned = warnings.length > 0
  const ticked = view.items.filter(adoptionTickedByDefault)
  const undecided = adoptionUndecided(view.adoption, view.items, new Map(view.items.map((i) => [i.ref, { include: adoptionTickedByDefault(i), home: "", action: adoptionDefaultAction(i, view.adoption) }])))
  const taken = new Set(view.items.flatMap((i) => [i.slug, ...(i.compare ? [i.compare.holder.slug] : [])]))
  const by = view.requestedBy
  const uploaded = joined(view.machines.map((m) => html`${cardText(m.name)} (${adoptionCount(m.items)})`))
  const head = html`<section class="card decision adopt-head${warned ? " warned" : ""}" data-region="adopt-head">
    <p class="eyebrow">${cardText(by.deviceName)} asks to adopt credentials it found</p>
    <h1>Adopt ${adoptionCount(view.items.length)}</h1>
    <p class="item-sub">${askPlace(shell.identity.origin, shell.identity.workspace)}. <span class="when">${countdownTimer(view.expiresAt, ADOPTION_LIMITS.ttlMs / 1000, now)}.</span></p>
    <dl class="kv small">
      <dt>Machine</dt><dd>${cardText(by.deviceName)} <code>${by.device}</code></dd>
      <dt>Session</dt><dd>${by.session !== null ? html`<code>${cardText(by.session)}</code> <span class="muted small">(${SESSION_LABEL_WORDS})</span>` : "not given"}</dd>
      <dt>Uploaded from</dt><dd>${uploaded}</dd>
      <dt>Batch</dt><dd><code>${view.adoption}</code></dd>
    </dl>
    ${keepOpen(view)}
    <p class="small muted">${ADOPTION_UNTICKED_WORDS} ${ADOPTION_RENAME_WORDS}</p>
  </section>`
  const groups = adoptionGroups(view.items).map((g) => html`<section class="card adopt-group" data-region="adopt-group"><h2>${cardText(g.repo)}</h2>${g.folders.map((f) => html`<h3 class="small"><code>${cardText(f.folder)}</code></h3><ul class="adopt-rows">${f.items.map((i) => itemRow(i, labels, view.adoption, taken))}</ul>`)}</section>`)
  const next = html`<div class="ask-next">${notice("info", "What happens next", "Approving stores every ticked row in the home you chose, all or nothing, and your passkey confirms the whole batch. Unticked rows are left out. The machine then finishes with mehen adopt apply; the files it read stay as they are. Cancelling stores nothing.")}</div>`
  return {
    title: `Adopt ${adoptionCount(view.items.length)}`,
    viewer: null,
    workspace: shell,
    bar: true,
    wide: true,
    boot: { page: "ws-adoption", adoption: view.adoption, items: view.items, homes: offered },
    body: html`${heldNotice(shell, "adoption")}${warningCard(warnings)}<form class="stack" id="decide" data-form="adoption" novalidate>${head}${filters(view, homes, labels)}${groups}</form>${next}${decisionBar({
      warned,
      form: "decide",
      caption: html`<span data-region="home-counts">${adoptionHomeCounts(ticked.map((i) => ({ include: true, home: homeKey(adoptionStartHome(i) ?? i.home) })), offered)}</span>. <span data-region="undecided"${undecided === 0 ? html` hidden` : ""}>${undecided === 0 ? "" : adoptionUndecidedWords(undecided)}</span> ${PASSKEY_CONFIRMS_WORDS}`,
      decline: { action: "cancel-adoption", label: "Cancel batch", attributes: html` data-id="${view.adoption}"` },
      accept: { action: "approve-adoption", label: html`<span data-region="approve-label">${adoptionApproveLabel(ticked.length)}</span>`, passkey: true, disabled: true },
    })}`,
  }
}
