// A credential page's push parts (ruling U1, design push-providers 3.3):
// the allowance to put it into other services' secret stores, the places it
// was pushed to, the offer to push a rotated value to the same places, and
// those places in the delete confirmation. Shown only while pushing is on
// for the workspace; a managed workspace has no credential page at all.
// pages/workspace-credentials.ts places them.

import type { PushRecordView } from "@mehen/protocol/push"
import type { WorkspaceItemDescription, WorkspaceProject } from "@mehen/protocol/workspace"
import { pushOffered } from "../vault/areas/push-allowance.ts"
import { cardText, pill, timeTag } from "./components.ts"
import { type Html, html } from "./html.ts"
import {
  PUSHED_TO_TITLE,
  PUSH_AGAIN_ALLOWANCE_WORDS,
  PUSH_AGAIN_BUTTON,
  PUSH_AGAIN_FOUR_EYES_WORDS,
  PUSH_AGAIN_TITLE,
  PUSH_AGAIN_VIA_UNSEEN_WORDS,
  PUSH_AGAIN_WORDS,
  PUSH_ALLOWANCE_LABEL,
  PUSH_ALLOWANCE_OFF,
  PUSH_ALLOWANCE_ON,
  PUSH_ALLOWANCE_SAVE,
  PUSH_ALLOWANCE_TITLE,
  PUSH_ALLOWANCE_WORDS,
  PUSH_DELETE_WORDS,
  pushBehind,
  pushHeldThere,
  pushRecordStateWords,
  pushRecordVersionWords,
} from "./push-wording.ts"

// Whether this credential is in a protected environment that needs a
// second person, as far as the viewer's projects show: the vault refuses a
// person's push of it, or of what carried it, on the same test.
export function fourEyesCredential(slug: string, projects: readonly WorkspaceProject[]): boolean {
  return projects.some((p) => p.vars.some((v) => v.item === slug && p.environments.some((e) => e.name === v.env && e.protected && e.fourEyes)))
}

// The allowance, only where the vault would let it be turned on. Whoever may
// change the credential gets the tick and a passkey; anyone else reads it.
export function pushAllowanceCard(item: WorkspaceItemDescription, canChange: boolean): Html | string {
  if (!pushOffered(item.kind)) return ""
  const on = item.pushable === true
  return html`<section class="card" aria-label="${PUSH_ALLOWANCE_TITLE}" data-region="push-allowance">
    <div class="card-head"><h2>${PUSH_ALLOWANCE_TITLE}</h2></div>
    ${canChange
      ? html`<form class="stack" data-form="push-allowance" novalidate>
          <label class="tick"><input type="checkbox" data-input="pushable"${on ? html` checked` : ""}><span>${PUSH_ALLOWANCE_LABEL}</span></label>
          <p class="small muted">${PUSH_ALLOWANCE_WORDS}</p>
          <button type="button" class="btn secondary" data-action="save-pushable" disabled>${PUSH_ALLOWANCE_SAVE}</button>
        </form>`
      : html`<p data-region="push-allowance-state">${pill(on ? PUSH_ALLOWANCE_ON : PUSH_ALLOWANCE_OFF, on ? "ok" : "muted")} ${PUSH_ALLOWANCE_LABEL}</p><p class="small muted">${PUSH_ALLOWANCE_WORDS}</p>`}
  </section>`
}

function recordRow(r: PushRecordView): Html {
  const tone = r.state === "done" ? (r.current ? "ok" : "warn") : r.state === "unknown" ? "warn" : "danger"
  return html`<li data-push="${r.push}" data-state="${r.state}">
    <span>${cardText(r.words)}</span> ${pill(pushRecordStateWords(r), tone, false)}
    <span class="small muted" data-region="push-record-facts">${pushRecordVersionWords(r)}, ${r.via !== null ? html`with <code>${cardText(r.via)}</code>, ` : ""}${timeTag(r.at)}${typeof r.by === "string" ? html`, by ${cardText(r.by)}` : ""}</span>
  </li>`
}

// A place to push again, with the credential that carried it there before,
// which carries it again. One whose carrying credential the viewer cannot
// see is shown disabled, never ticked or signed.
function pushAgainRow(r: PushRecordView): Html {
  if (r.via === null) return html`<div data-region="push-again-unseen"><label class="tick"><input type="checkbox" disabled><span>${cardText(r.words)}</span></label><p class="small muted">${PUSH_AGAIN_VIA_UNSEEN_WORDS}</p></div>`
  return html`<label class="tick"><input type="checkbox" data-input="push-record" value="${r.push}" data-destination="${r.destination}" data-field="${r.field}" data-via="${r.via}"><span>${cardText(r.words)}</span> <span class="small muted">with <code>${cardText(r.via)}</code></span></label>`
}

// The offer to put the rotated value where an older one went: every place
// unticked, in full, signed once for up to 25. Four eyes and a missing
// allowance each say why instead.
function pushAgain(item: WorkspaceItemDescription, behind: readonly PushRecordView[], fourEyes: boolean): Html {
  const why = fourEyes ? PUSH_AGAIN_FOUR_EYES_WORDS : item.pushable !== true ? PUSH_AGAIN_ALLOWANCE_WORDS : null
  return html`<div class="stack" data-region="push-again">
    <h3>${PUSH_AGAIN_TITLE}</h3>
    ${why !== null
      ? html`<p class="small muted" data-region="push-again-refused">${why}</p>`
      : html`<form class="stack" data-form="push-again" novalidate>
          <p class="small muted">${PUSH_AGAIN_WORDS}</p>
          <fieldset class="field">${behind.map(pushAgainRow)}</fieldset>
          <button type="button" class="btn primary" data-action="push-again">${PUSH_AGAIN_BUTTON}</button>
        </form>`}
  </div>`
}

// Pushed to: the latest push to each place, as the vault lists them.
// `again`: this viewer may push it again. Four eyes is judged over the
// credential and each credential that carried it, as the vault judges it.
export function pushedToCard(item: WorkspaceItemDescription, again: boolean, projects: readonly WorkspaceProject[]): Html | string {
  const records = item.pushes ?? []
  if (records.length === 0) return ""
  const behind = records.filter(pushBehind)
  const fourEyes = [item.slug, ...behind.flatMap((r) => (r.via !== null ? [r.via] : []))].some((slug) => fourEyesCredential(slug, projects))
  return html`<section class="card" aria-label="${PUSHED_TO_TITLE}" data-region="pushed-to">
    <div class="card-head"><h2>${PUSHED_TO_TITLE}</h2></div>
    <ul class="ref-list" data-region="push-records">${records.map(recordRow)}</ul>
    ${again && behind.length > 0 ? pushAgain(item, behind, fourEyes) : ""}
  </section>`
}

// The places a deleted value stays, in the delete confirmation.
export function pushDeleteWords(item: WorkspaceItemDescription): Html | string {
  const held = (item.pushes ?? []).filter(pushHeldThere)
  if (held.length === 0) return ""
  return html`<div data-region="push-delete"><p class="small warn-text">${PUSH_DELETE_WORDS}</p><ul class="ref-list">${held.map((r) => html`<li>${cardText(r.words)}</li>`)}</ul></div>`
}
