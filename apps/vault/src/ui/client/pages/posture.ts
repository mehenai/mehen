// The How careful card's wiring (posture-card.ts) on a credential's page;
// it wires nothing when the vault drew no card. A choice shows Custom's
// read-only rules or On these machines as it needs them, and Save with
// passkey is enabled only for a posture that changes something; the flow
// itself is posture-sign.ts.

import type { PostureLevel } from "@mehen/protocol"
import { POSTURE_NO_MACHINE_WORDS, POSTURE_NOTHING_TO_SAVE } from "../../wording.ts"
import { all, find, must, withBusy } from "../dom.ts"
import { postureRowShown } from "../posture-machines.ts"
import { type PostureChoice, type PostureShown, chosenPosture, postureUnchanged, savePosture } from "../posture-sign.ts"
import type { ShellState } from "../shell-logic.ts"

// The posture as the card showed it, from its own data attributes.
export function postureShownOf(card: HTMLElement): PostureShown {
  const d = card.dataset
  const machines = (d.machines ?? "").split(",").filter((m) => m !== "")
  return {
    item: d.item ?? "", slug: d.slug ?? "", rev: Number(d.rev), level: (d.level ?? "ask") as PostureLevel,
    machines: machines.length > 0 ? machines : null,
    catalogue: d.catalogue ? { template: d.catalogue, version: Number(d.catalogueVersion) } : null,
    grown: card.hasAttribute("data-grown"),
  }
}

// What the card has chosen now: the level and, for Routine and Trust, the
// machines ticked among those drawn for it, or null for every eligible
// machine.
function chosen(card: HTMLElement): { choice: PostureChoice; named: string[] | null } {
  const choice = (find<HTMLInputElement>('[data-input="posture-level"]:checked', card)?.value ?? "ask") as PostureChoice
  const named = find<HTMLInputElement>('[data-input="posture-machines"]:checked', card)?.value === "named"
  const rows = all('[data-region="posture-machine-row"]', card).filter((row) => !row.hidden)
  return { choice, named: named ? rows.map((row) => must<HTMLInputElement>('[data-input="posture-machine"]', row)).filter((m) => m.checked).map((m) => m.value) : null }
}

// Draws On these machines for a level: the machines it would cover now,
// and any the posture names, those it would not with a note.
function drawMachines(card: HTMLElement, level: "routine" | "trust"): void {
  for (const row of all('[data-region="posture-machine-row"]', card)) {
    const drawn = postureRowShown({ levels: (row.dataset.levels ?? "").split(" "), stored: row.hasAttribute("data-stored") }, level)
    row.hidden = !drawn.shown
    must('[data-region="posture-machine-uncovered"]', row).hidden = !drawn.uncovered
  }
}

export function initPostureCard(shell: ShellState): void {
  const card = find('[data-region="posture"]')
  if (card === null) return
  const shown = postureShownOf(card)
  const save = must<HTMLButtonElement>('[data-action="posture-save"]', card)
  const nothing = must('[data-region="posture-nothing"]', card)
  const redraw = () => {
    const { choice, named } = chosen(card)
    const widening = choice === "routine" || choice === "trust"
    must('[data-region="posture-custom"]', card).hidden = choice !== "custom"
    const machines = find('[data-region="posture-machines"]', card)
    if (machines !== null) machines.hidden = !widening
    if (choice === "routine" || choice === "trust") drawMachines(card, choice)
    for (const tick of all<HTMLInputElement>('[data-input="posture-machine"]', card)) tick.disabled = named === null
    const posture = chosenPosture(choice, named)
    const unchanged = posture !== null && postureUnchanged(shown, posture)
    save.disabled = posture === null || unchanged
    nothing.hidden = !save.disabled
    nothing.textContent = posture === null ? POSTURE_NO_MACHINE_WORDS : POSTURE_NOTHING_TO_SAVE
  }
  card.addEventListener("change", redraw)
  redraw()
  // withBusy enables the button again after a refusal; redraw puts back
  // whether there is anything to save.
  save.addEventListener("click", () => void withBusy(save, "Waiting for your passkey...", async () => {
    const { choice, named } = chosen(card)
    const posture = chosenPosture(choice, named)
    if (posture === null || postureUnchanged(shown, posture)) return
    await savePosture(shell, shown, posture)
    location.reload()
  }).then(redraw))
}
