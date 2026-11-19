// The browser side of the Settings view (/operator/settings). A choice is
// a settings.narrow or settings.widen proposal with the setting's key as
// its target and the value as a parameter (a widening also names the value
// in force the page showed), signed with a passkey for
// that exact proposal (its digest) through the operator's step-up start:
// narrowing applies at once, widening waits for a second operator. Open
// proposals are approved, declined and cancelled as on the Operators view.
// Every refusal is the vault's own words.

import { DEPLOYMENT_SETTING_WORDS, type DeploymentSettingKey } from "@mehen/protocol/deployment-settings"
import { type OperatorProposalAnswer, type OperatorProposalTerms, operatorProposeStepUpAction } from "@mehen/protocol/operator-proposals"
import { CONSOLE_ROUTES } from "@mehen/protocol/platform-console"
import { api } from "../api.ts"
import { all, withBusy } from "../dom.ts"
import { consoleStepUp } from "../step-up.ts"
import { CONFIRM_WORDS, initProposalDecisions } from "./operators.ts"

export function initOperatorSettings(): void {
  const reload = () => location.reload()
  for (const button of all<HTMLButtonElement>('[data-action="setting"]')) {
    button.addEventListener("click", () => {
      const kind = button.dataset.kind === "settings.widen" ? "settings.widen" : "settings.narrow"
      const key = (button.dataset.key ?? "") as DeploymentSettingKey
      const value = button.dataset.value ?? ""
      const terms: OperatorProposalTerms = { kind, target: key, params: kind === "settings.widen" ? { value, from: button.dataset.from ?? "" } : { value } }
      const title = DEPLOYMENT_SETTING_WORDS[key]?.title.toLowerCase() ?? key
      if (!confirm(CONFIRM_WORDS[kind](`${title} to ${button.dataset.label ?? value}`))) return
      void withBusy(button, "Waiting for your passkey...", async () => {
        const stepUp = await consoleStepUp(CONSOLE_ROUTES.operatorStepUp, await operatorProposeStepUpAction(terms))
        await api<OperatorProposalAnswer>(CONSOLE_ROUTES.operatorProposals, { ...terms, stepUp })
        reload()
      })
    })
  }
  initProposalDecisions(reload)
}
