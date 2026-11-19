// The adoption review page's script: the ticks, homes, a compare row's
// action, filters and bulk actions, and one passkey over the whole batch,
// held back while a ticked compare row is undecided. The decisions are
// built from the rows the page rendered, the digest from the view in its
// boot data; the batch is read again just before signing, and anything
// changed since the page loaded, or any field of the action the vault will
// rebuild from it, refuses the passkey. Keep-open sends the expiry shown
// and shows the one the vault answers and what the next click adds. A
// refused approval marks the rows the vault named and keeps every tick.

import { ADOPTION_ACTIONS, type AdoptionKeptOpen, type WorkspaceAdoptionItemView, type WorkspaceAdoptionView } from "@mehen/protocol/adopt"
import { VaultFailure, workspaceApi } from "../api.ts"
import { type Boot, all, find, must, withBusy } from "../dom.ts"
import type { ShellState } from "../shell-logic.ts"
import { browserPasskey, signAction } from "../workspace-sign.ts"
import { localTimeWords } from "../wires.ts"
import { formatTime } from "../../wording.ts"
import { gate } from "./workspace-asks.ts"
import { type AdoptionChoice, adoptionApproveAction, adoptionApproveLabel, adoptionDecisions, adoptionHomeCounts, adoptionKeepOpenShown, adoptionKeepOpenWords, adoptionKeepVaultRefs, adoptionRefusals, adoptionShownRefusal, adoptionUndecided, adoptionUndecidedWords } from "./workspace-adopt-logic.ts"
import { needShell } from "./workspace.ts"

type AdoptionBoot = { adoption: string; items: WorkspaceAdoptionItemView[]; homes: [string, string][] }

function rowOf(ref: string): HTMLElement | null {
  return all<HTMLElement>("[data-row]").find((r) => r.dataset.ref === ref) ?? null
}

function choicesOf(rows: readonly HTMLElement[]): Map<string, AdoptionChoice> {
  return new Map(rows.map((row) => {
    const action = find<HTMLInputElement>('[data-input="action"]:checked', row)?.value
    return [row.dataset.ref ?? "", {
      include: find<HTMLInputElement>('[data-input="include"]', row)?.checked === true,
      home: find<HTMLSelectElement>('[data-input="home"]', row)?.value ?? "",
      action: ADOPTION_ACTIONS.find((a) => a === action) ?? null,
      slug: find<HTMLInputElement>('[data-input="rename-slug"]', row)?.value ?? "",
      repoint: all<HTMLInputElement>('[data-input="repoint"]:checked', row).map((box) => ({ project: box.dataset.project ?? "", env: box.dataset.env ?? "", variable: box.dataset.variable ?? "" })),
    }]
  }))
}

// A copy's name shows while rename is chosen.
function showRename(row: HTMLElement): void {
  const rename = find('[data-region="rename"]', row)
  if (rename) rename.hidden = find<HTMLInputElement>('[data-input="action"]:checked', row)?.value !== "rename"
}

// Filters only hide rows; a hidden row keeps its tick, and the bar counts it.
function applyFilters(rows: readonly HTMLElement[]): void {
  const on = (name: string) => find<HTMLInputElement>(`[data-filter="${name}"]`)?.checked === true
  const machine = find<HTMLSelectElement>('[data-filter="machine"]')?.value ?? ""
  for (const row of rows) {
    const shown = (!on("problem") || row.dataset.problem === "true") && (!on("custom") || row.dataset.custom === "true") && (!on("stale") || row.dataset.stale === "true") && (machine === "" || (row.dataset.machines ?? "").split("\n").includes(machine))
    row.hidden = !shown
  }
}

function markRefused(refused: ReadonlyMap<string, string>): void {
  for (const [ref, reason] of refused) {
    const row = rowOf(ref)
    if (row === null) continue
    row.dataset.problem = "true"
    const line = find('[data-region="row-problem"]', row)
    if (line) {
      line.textContent = reason
      line.hidden = false
    }
  }
}

export function initWorkspaceAdoption(raw: Boot, maybe: ShellState | null): void {
  const shell = needShell(maybe)
  const boot = raw as unknown as AdoptionBoot & Boot
  find<HTMLFormElement>("#decide")?.addEventListener("submit", (event) => event.preventDefault())
  const rows = all<HTMLElement>("[data-row]")
  const approve = must<HTMLButtonElement>('[data-action="approve-adoption"]')
  const cancel = find<HTMLButtonElement>('[data-action="cancel-adoption"]')
  const label = find('[data-region="approve-label"]')
  const counts = find('[data-region="home-counts"]')
  const waiting = find('[data-region="undecided"]')
  const included = () => [...choicesOf(rows).values()].filter((c) => c.include).length
  const g = gate([approve, cancel], (b) => b !== approve || (included() > 0 && adoptionUndecided(boot.adoption, boot.items, choicesOf(rows)) === 0), () => {
    const choices = choicesOf(rows)
    const n = [...choices.values()].filter((c) => c.include).length
    const undecided = adoptionUndecided(boot.adoption, boot.items, choices)
    if (label) label.textContent = adoptionApproveLabel(n)
    if (counts) counts.textContent = adoptionHomeCounts(choices.values(), boot.homes)
    if (waiting) {
      waiting.textContent = undecided === 0 ? "" : adoptionUndecidedWords(undecided)
      waiting.hidden = undecided === 0
    }
  })
  for (const input of all<HTMLInputElement | HTMLSelectElement>('[data-input="include"], [data-input="home"], [data-input="action"], [data-input="rename-slug"]')) input.addEventListener("change", g.refresh)
  for (const row of rows) for (const radio of all<HTMLInputElement>('[data-input="action"]', row)) radio.addEventListener("change", () => showRename(row))
  for (const input of all<HTMLInputElement | HTMLSelectElement>("[data-filter]")) input.addEventListener("change", () => applyFilters(rows))
  find<HTMLButtonElement>('[data-action="untick-stale"]')?.addEventListener("click", () => {
    for (const row of rows) if (row.dataset.stale === "true") for (const tick of all<HTMLInputElement>('[data-input="include"]', row)) tick.checked = false
    g.refresh()
  })
  find<HTMLButtonElement>('[data-action="keep-vault-all"]')?.addEventListener("click", () => {
    for (const ref of adoptionKeepVaultRefs(boot.adoption, boot.items, choicesOf(rows))) {
      const row = rowOf(ref)
      const map = row === null ? null : find<HTMLInputElement>('[data-input="action"][value="map"]', row)
      if (row === null || map === null) continue
      map.checked = true
      showRename(row)
    }
    g.refresh()
  })
  find<HTMLButtonElement>('[data-action="set-home"]')?.addEventListener("click", () => {
    const home = find<HTMLSelectElement>('[data-input="bulk-home"]')?.value ?? ""
    for (const row of rows) {
      if (find<HTMLInputElement>('[data-input="include"]', row)?.checked !== true) continue
      const select = find<HTMLSelectElement>('[data-input="home"]', row)
      if (select && [...select.options].some((o) => o.value === home)) select.value = home
    }
    g.refresh()
  })
  g.refresh()
  const path = `/adoptions/${encodeURIComponent(boot.adoption)}`
  const keep = find<HTMLButtonElement>('[data-action="keep-open"]')
  // Held here: withBusy puts it back into the button once the answer is shown.
  const keepLabel = find('[data-region="keep-open-label"]')
  if (keep) {
    keep.addEventListener("click", () => {
      void withBusy(keep, "Keeping it open...", async () => {
        const kept = await workspaceApi<AdoptionKeptOpen>(shell, `${path}/keep-open`, { expiresAt: keep.dataset.expires ?? "" })
        keep.dataset.expires = kept.expiresAt
        const at = find<HTMLTimeElement>('[data-region="expires"] time')
        if (at) {
          at.dateTime = kept.expiresAt
          at.textContent = localTimeWords(new Date(kept.expiresAt))
          at.title = formatTime(kept.expiresAt)
        }
        if (keepLabel) keepLabel.textContent = adoptionKeepOpenWords(kept)
        const ring = find<SVGSVGElement>('[data-region="adopt-head"] [data-ring]')
        if (ring) ring.dataset.expires = kept.expiresAt
        keep.hidden = !adoptionKeepOpenShown(kept)
      })
    })
  }
  if (cancel) {
    cancel.addEventListener("click", () => g.run(cancel, "Cancelling...", async () => {
      await workspaceApi(shell, `${path}/cancel`, {})
      location.reload()
    }))
  }
  approve.addEventListener("click", () => g.run(approve, "Waiting for your passkey...", async () => {
    const built = adoptionDecisions(boot.adoption, boot.items, choicesOf(rows))
    if (!built.ok) throw new VaultFailure(400, built.error)
    const action = await adoptionApproveAction(boot.adoption, boot.items, built.decisions)
    const stillShown = async () => adoptionShownRefusal(action, boot.items, await workspaceApi<WorkspaceAdoptionView>(shell, path), built.decisions)
    try {
      await signAction(shell, action, { path: `${path}/approve`, body: { decisions: built.decisions } }, stillShown, browserPasskey)
    } catch (error) {
      if (error instanceof VaultFailure) markRefused(adoptionRefusals(error.body))
      throw error
    }
    location.reload()
  }))
}
