// The How careful card on a credential's page, above "Allowed without
// asking": Ask, Let routine building through, Trust my own machines and
// Custom rules, On these machines, and Save with passkey, which signs
// item.posture (client/posture-sign.ts). Drawn only when the vault's
// description carries the posture, which it does only for someone who may
// set it, with postures on, in an unmanaged workspace. Custom stores Ask:
// main has no web editor for a credential's policy, so it shows the
// credential's own rules in three lines and points at its standing rules.
// A credential with no reviewed catalogue offers only Ask and Custom; a
// restricted account or a guest may only ask, and is told why.

import type { PostureLevel, WorkspaceItemPosture } from "@mehen/protocol"
import { postureCatalogueFor } from "@mehen/protocol/policy-rules"
import { getTemplate } from "@mehen/protocol/templates"
import { cardText, notice, timeTag } from "./components.ts"
import { type Html, html } from "./html.ts"
import { postureRowShown } from "./client/posture-machines.ts"
import { capabilitySummary } from "./policy-trust.ts"
import { RULES_CARD_ID } from "./policy-rules-list.ts"
import type { HumanItemDescription } from "./pages/workspace-credentials.ts"
import {
  POSTURE_AREAS_LABEL, POSTURE_CARD_LEAD, POSTURE_CARD_TITLE, POSTURE_CHOICES, POSTURE_CUSTOM_NO_RULES_WORDS, POSTURE_CUSTOM_PROPOSE_WORDS, POSTURE_CUSTOM_RULES_LINK, POSTURE_CUSTOM_RULES_WORDS,
  POSTURE_EVERY_MACHINE_WORDS, POSTURE_GUEST_WORDS, POSTURE_LEVELS_LABEL, POSTURE_HELD_WORDS, POSTURE_MACHINE_UNCOVERED_WORDS, POSTURE_MACHINES_LABEL, POSTURE_MACHINES_WORDS, POSTURE_NAMED_MACHINES_WORDS, POSTURE_NO_CATALOGUE_WORDS, POSTURE_NOTHING_TO_SAVE, POSTURE_SAVE_BUTTON,
  postureCustomLines, postureGrewWords, postureSetByWords,
} from "./wording.ts"
import type { Viewer } from "./workspace-rights.ts"

// The card's four choices; custom is stored as ask.
export type PostureChoice = PostureLevel | "custom"
export const POSTURE_CARD_ID = "how-careful"

// standingRules: the credential has a live standing rule, so a posture at
// ask opens on Custom; rulesCard: the "Allowed without asking" card is
// drawn below, for Custom's link.
export type PostureCardData = { item: HumanItemDescription; viewer: Viewer; standingRules: boolean; rulesCard: boolean }

// The choice the card opens on: the stored level, except that ask (or no
// posture set) reads as Custom while a standing rule is live.
export function openingChoice(posture: WorkspaceItemPosture, standingRules: boolean): PostureChoice {
  return posture.level === "ask" && standingRules ? "custom" : posture.level
}

// Whether the catalogue the posture was signed against has grown since, so
// saving the same level again would cover the new routes.
export function postureGrew(posture: WorkspaceItemPosture): boolean {
  return posture.level !== "ask" && posture.catalogue !== null && posture.catalogue.current > posture.catalogue.version
}

function choiceRow(choice: PostureChoice, selected: PostureChoice, disabled: boolean): Html {
  const words = POSTURE_CHOICES[choice]
  return html`<label class="tick"><input type="radio" name="posture-level" data-input="posture-level" value="${choice}"${choice === selected ? html` checked` : ""}${disabled ? html` disabled` : ""}><span><b>${words.name}</b> <span class="muted small">${words.words}</span></span></label>`
}

// Custom's read-only view: the credential's own rules in three lines, where
// its standing rules are, and how a new one is added.
function customPanel(item: HumanItemDescription, rulesCard: boolean, hidden: boolean): Html {
  const lines = postureCustomLines(capabilitySummary({ provider: item.provider, hosts: item.binding.hosts, policy: item.policy }))
  return html`<div class="stack" data-region="posture-custom"${hidden ? html` hidden` : ""}>
      <ul class="plain small" data-region="posture-custom-lines"><li>${cardText(lines.own)}</li><li>${cardText(lines.asks)}</li><li>${cardText(lines.refused)}</li></ul>
      <p class="small">${rulesCard ? html`${POSTURE_CUSTOM_RULES_WORDS.before}<a href="#${RULES_CARD_ID}">${POSTURE_CUSTOM_RULES_LINK}</a>${POSTURE_CUSTOM_RULES_WORDS.after}` : POSTURE_CUSTOM_NO_RULES_WORDS}</p>
      <p class="small muted">${POSTURE_CUSTOM_PROPOSE_WORDS}</p>
    </div>`
}

// On these machines: every eligible machine, or only the ones ticked; shown
// for Routine and Trust. The ticks are the vault's eligible machines for
// the level chosen, and any the posture names that no longer are.
function machinesField(posture: WorkspaceItemPosture, level: Exclude<PostureLevel, "ask">, hidden: boolean): Html {
  const named = posture.machines !== null
  const eligible = posture.eligible ?? []
  const stored = new Set(posture.machines?.map((m) => m.id) ?? [])
  const listed = [...eligible, ...(posture.machines ?? []).filter((m) => !eligible.some((x) => x.device === m.id)).map((m) => ({ device: m.id, name: m.name, levels: [] }))]
  return html`<fieldset class="field" data-region="posture-machines"${hidden ? html` hidden` : ""}><legend class="label">${POSTURE_MACHINES_LABEL}</legend>
      <label class="tick"><input type="radio" name="posture-machines" data-input="posture-machines" value="every"${named ? "" : html` checked`}><span>${POSTURE_EVERY_MACHINE_WORDS}</span></label>
      <label class="tick"><input type="radio" name="posture-machines" data-input="posture-machines" value="named"${named ? html` checked` : ""}${listed.length === 0 ? html` disabled` : ""}><span>${POSTURE_NAMED_MACHINES_WORDS}</span></label>
      ${listed.map((m) => {
        const row = postureRowShown({ levels: m.levels, stored: stored.has(m.device) }, level)
        return html`<label class="tick" data-region="posture-machine-row" data-levels="${m.levels.join(" ")}"${stored.has(m.device) ? html` data-stored` : ""}${row.shown ? "" : html` hidden`}><input type="checkbox" data-input="posture-machine" value="${m.device}"${stored.has(m.device) ? html` checked` : ""}${named ? "" : html` disabled`}><span>${cardText(m.name)}</span><span class="small muted" data-region="posture-machine-uncovered"${row.uncovered ? "" : html` hidden`}>${POSTURE_MACHINE_UNCOVERED_WORDS}</span></label>`
      })}
      <p class="small muted">${POSTURE_MACHINES_WORDS}</p>
    </fieldset>`
}

export function postureCard(data: PostureCardData): Html {
  const { item } = data
  const posture = item.posture
  if (posture === undefined) return html``
  const current = postureCatalogueFor(item.binding)
  const selected = openingChoice(posture, data.standingRules)
  const onlyAsk = data.viewer.held === true ? POSTURE_HELD_WORDS : data.viewer.role === "guest" ? POSTURE_GUEST_WORDS : null
  // Routine and Trust need a reviewed catalogue; a level stored before it
  // went stays listed, so the card shows what is set.
  const levels = (["routine", "trust"] as const).filter((l) => current !== null || posture.level === l)
  const grew = postureGrew(posture)
  const service = getTemplate(current?.template ?? posture.catalogue?.template ?? "")?.displayName ?? posture.catalogue?.template ?? ""
  const widening = selected === "routine" || selected === "trust"
  // What the client signs from (client/pages/posture.ts): the credential,
  // the posture as stored and the credential's current catalogue.
  const shown = html`data-item="${item.id}" data-slug="${item.slug}" data-rev="${String(posture.rev)}" data-level="${posture.level}" data-machines="${(posture.machines ?? []).map((m) => m.id).join(",")}" data-catalogue="${current?.template ?? ""}" data-catalogue-version="${current !== null ? String(current.version) : ""}"${grew ? html` data-grown` : ""}`
  return html`<section class="card" id="${POSTURE_CARD_ID}" aria-label="${POSTURE_CARD_TITLE}" data-region="posture" ${shown}>
    <div class="card-head"><h2>${POSTURE_CARD_TITLE}</h2></div>
    <p class="small muted">${POSTURE_CARD_LEAD}</p>
    ${grew ? notice("warn", postureGrewWords(service)) : ""}
    <fieldset class="field" data-region="posture-levels"><legend class="label">${POSTURE_LEVELS_LABEL}</legend>
      ${choiceRow("ask", selected, false)}
      ${levels.map((l) => choiceRow(l, selected, onlyAsk !== null))}
      ${choiceRow("custom", selected, false)}
    </fieldset>
    ${current !== null ? html`<p class="small muted" data-region="posture-areas"><span class="label">${POSTURE_AREAS_LABEL}</span> ${cardText(current.areas.map((a) => a.name).join(", "))}</p>` : html`<p class="small muted" data-region="posture-no-catalogue">${POSTURE_NO_CATALOGUE_WORDS}</p>`}
    ${onlyAsk !== null ? html`<p class="small muted" data-region="posture-only-ask">${onlyAsk}</p>` : ""}
    ${customPanel(item, data.rulesCard, selected !== "custom")}
    ${levels.length > 0 ? machinesField(posture, widening ? selected : "routine", !widening) : ""}
    ${posture.setBy !== null && posture.setAt !== null ? html`<p class="small muted" data-region="posture-set-by">${cardText(postureSetByWords(posture.setBy))}, ${timeTag(posture.setAt)}.</p>` : ""}
    <div class="actions"><button type="button" class="btn primary" data-action="posture-save"${grew ? "" : html` disabled`}>${POSTURE_SAVE_BUTTON}</button><span class="small muted" data-region="posture-nothing"${grew ? html` hidden` : ""}>${POSTURE_NOTHING_TO_SAVE}</span></div>
  </section>`
}
