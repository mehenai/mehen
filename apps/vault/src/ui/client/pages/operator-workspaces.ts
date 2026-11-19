// The browser side of one workspace in the Operator area
// (/operator/workspaces/:id): freezing it, and proposing a restore to a
// point in time or from a day's dump, each signed with a passkey for that
// exact proposal (its digest) through the operator's step-up start. A
// restore needs the workspace id typed back first. Every refusal is the
// vault's own words.

import { CONSOLE_ROUTES } from "@mehen/protocol/platform-console"
import { type OperatorProposalAnswer, type OperatorProposalTerms, operatorProposeStepUpAction } from "@mehen/protocol/operator-proposals"
import { api } from "../api.ts"
import type { Boot } from "../dom.ts"
import { find, inputValue, must, showProblems, withBusy } from "../dom.ts"
import { consoleStepUp } from "../step-up.ts"

const WAITING = "Waiting for your passkey..."
// A time names its zone: Z or an offset, never the browser's local time.
const POINT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/

async function propose(terms: OperatorProposalTerms): Promise<OperatorProposalAnswer> {
  const stepUp = await consoleStepUp(CONSOLE_ROUTES.operatorStepUp, await operatorProposeStepUpAction(terms))
  return api<OperatorProposalAnswer>(CONSOLE_ROUTES.operatorProposals, { ...terms, stepUp })
}

// The time typed, as the vault keeps it (UTC with milliseconds), or null.
export function restorePoint(typed: string): string | null {
  const text = typed.trim()
  if (!POINT.test(text) || Number.isNaN(Date.parse(text))) return null
  return new Date(text).toISOString()
}

export function initOperatorWorkspace(boot: Boot): void {
  const workspace = typeof boot.workspace === "string" ? boot.workspace : ""
  const reload = () => location.reload()
  const freeze = find<HTMLFormElement>('[data-form="freeze"]')
  if (freeze) freeze.addEventListener("submit", (event) => {
    event.preventDefault()
    if (!confirm("Freeze this workspace now? Every credential use and everything that widens is refused until one of its owners unfreezes it.")) return
    void withBusy(must<HTMLButtonElement>('button[type="submit"]', freeze), WAITING, async () => {
      await propose({ kind: "workspace.freeze", target: workspace, params: {} })
      reload()
    })
  })
  for (const source of ["pitr", "dump"] as const) {
    const form = find<HTMLFormElement>(`[data-form="restore-${source}"]`)
    if (!form) continue
    form.addEventListener("submit", (event) => {
      event.preventDefault()
      const target = source === "pitr" ? restorePoint(inputValue('[data-input="point"]', form)) : inputValue('[data-input="date"]', form)
      const problems = [
        ...(target === null || target === "" ? [source === "pitr" ? "Type the moment with Z or an offset, such as 2026-10-31T08:15:00Z." : "Choose a day's dump."] : []),
        ...(inputValue('[data-input="confirm"]', form).trim() !== workspace ? [`Type ${workspace} to confirm.`] : []),
      ]
      if (problems.length > 0 || target === null) return showProblems(problems)
      if (!confirm(`Propose restoring this workspace ${source === "pitr" ? `to ${target}` : `from the dump of ${target}`}? Another operator approves it within 24 hours; then everything after that point is undone.`)) return
      void withBusy(must<HTMLButtonElement>('button[type="submit"]', form), WAITING, async () => {
        await propose({ kind: "workspace.restore", target: workspace, params: { source, target } })
        reload()
      })
    })
  }
}
