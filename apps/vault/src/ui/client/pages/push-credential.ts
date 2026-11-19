// The credential page's push controls in the browser: the allowance tick,
// saved with a passkey under item.update, and Push the new value to the
// same places, one passkey over item.push for the places ticked, after
// reading as the viewer each credential those rows showed carrying them.
// Both sign through workspace-sign.ts, which refuses before the passkey
// unless the vault's action is the one this page rebuilt from what it showed.

import type { ApiError } from "@mehen/protocol/api"
import { all, find, must, showProblems, withBusy } from "../dom.ts"
import { workspaceApi } from "../api.ts"
import { type ChosenPush, type ViaRead, pushAgainChoice, pushAgainMatches, pushAgainVias, pushAllowanceAction } from "../push-logic.ts"
import { PUSH_AGAIN_CHANGED_WORDS, PUSH_AGAIN_VIA_UNSEEN_WORDS } from "../../push-wording.ts"
import type { ShellState } from "../shell-logic.ts"
import { type ShownItem, sameAction } from "../workspace-logic.ts"
import { signed } from "../workspace-sign.ts"

const WAITING = "Waiting for your passkey..."

const PUSH_AGAIN_CHANGED: ApiError = { error: "conflict", message: PUSH_AGAIN_CHANGED_WORDS, next: { say: "Nothing was signed." } }

// Each carrying credential a ticked row showed, read as the viewer; null
// when a row showed none or any read fails.
async function viaReads(shell: ShellState, slugs: string[] | null): Promise<Map<string, ViaRead> | null> {
  if (slugs === null) return null
  const reads = await Promise.all(slugs.map(async (slug) => {
    const read = await workspaceApi<Partial<ViaRead>>(shell, `/items/${encodeURIComponent(slug)}`).catch(() => null)
    return read !== null && typeof read.id === "string" && Number.isInteger(read.version) ? ([slug, { id: read.id, version: read.version as number }] as const) : null
  }))
  return reads.every((r) => r !== null) ? new Map(reads as (readonly [string, ViaRead])[]) : null
}

export function initPushControls(shell: ShellState, shown: ShownItem, path: string, stillShown: () => Promise<ApiError | null>): void {
  const allowance = find('[data-form="push-allowance"]')
  if (allowance !== null) {
    const box = must<HTMLInputElement>('[data-input="pushable"]', allowance)
    const save = must<HTMLButtonElement>('[data-action="save-pushable"]', allowance)
    const was = box.checked
    box.addEventListener("change", () => { save.disabled = box.checked === was })
    save.addEventListener("click", () => void withBusy(save, WAITING, async () => {
      const change = { pushable: box.checked }
      const expected = await pushAllowanceAction(shown, change.pushable)
      await signed(shell, { prepare: { path: `${path}/action`, body: { action: "update", change } }, matches: (a) => sameAction(expected, a), stillShown, mutation: { path: `${path}/update`, body: change } })
      location.reload()
    }))
  }
  const again = find('[data-form="push-again"]')
  if (again !== null) {
    const button = must<HTMLButtonElement>('[data-action="push-again"]', again)
    button.addEventListener("click", () => void withBusy(button, WAITING, async () => {
      const chosen: ChosenPush[] = all<HTMLInputElement>('[data-input="push-record"]:checked', again).map((box) => ({ record: box.value, destination: box.dataset.destination ?? "", field: box.dataset.field ?? "", via: box.dataset.via ?? null }))
      const built = pushAgainChoice(chosen)
      if (!built.ok) return showProblems(built.problems)
      const vias = await viaReads(shell, pushAgainVias(chosen))
      if (vias === null) return showProblems([PUSH_AGAIN_VIA_UNSEEN_WORDS])
      const records = built.value
      await signed(shell, { prepare: { path: `${path}/push/action`, body: { records } }, matches: (a) => pushAgainMatches(shown, chosen, vias, a), mismatch: PUSH_AGAIN_CHANGED, stillShown, mutation: { path: `${path}/push`, body: { records } } })
      location.reload()
    }))
  }
}
