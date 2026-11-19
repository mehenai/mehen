// Not now on the home's nudge lines (pages/workspaces.ts nudgeCard): POST
// /items/:slug/nudge-quiet, which needs no passkey, then the line goes, and
// the card with its last line. A refusal shows in the page's notice and the
// line stays.

import { workspaceApi } from "../api.ts"
import { find, withBusy } from "../dom.ts"
import type { ShellState } from "../shell-logic.ts"
import { NUDGE_QUIETENING_WORDS } from "../../wording.ts"

export function initNudges(shell: ShellState): void {
  const card = find('[data-region="home-nudges"]')
  if (card === null) return
  card.addEventListener("click", (event) => {
    const button = (event.target as Element | null)?.closest<HTMLButtonElement>('button[data-action="nudge-quiet"]')
    if (!button || button.disabled) return
    const slug = button.dataset.slug ?? ""
    void withBusy(button, NUDGE_QUIETENING_WORDS, async () => {
      await workspaceApi(shell, `/items/${encodeURIComponent(slug)}/nudge-quiet`, {})
      button.closest('[data-region="nudge"]')?.remove()
      if (find('[data-region="nudge"]', card) === null) card.remove()
    })
  })
}
