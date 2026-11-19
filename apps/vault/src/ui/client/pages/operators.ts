// The browser side of the Operators view (/operator/operators) and of the
// operator role's acceptance card on Your account; the Settings view
// (operator-settings.ts) uses its proposal decisions and words. Proposing and approving
// are signed with a passkey for that exact proposal (its digest) through
// the operator's step-up start; accepting through the account's own, for
// the proposal that names this account. Declining and cancelling are
// brakes and ask for no passkey. Every refusal is the vault's own words.

import { CONSOLE_ROUTES, operatorRequirementsRefusal } from "@mehen/protocol/platform-console"
import { type OperatorCandidate, type OperatorProposalAnswer, type OperatorProposalKind, operatorAcceptStepUpAction, operatorApproveStepUpAction, operatorProposeStepUpAction } from "@mehen/protocol/operator-proposals"
import { api } from "../api.ts"
import { all, find, inputValue, must, showProblems, withBusy } from "../dom.ts"
import { accountStepUp, consoleStepUp } from "../step-up.ts"

const WAITING = "Waiting for your passkey..."

function proposalPath(id: string): string {
  return CONSOLE_ROUTES.operatorProposal.replace(":id", encodeURIComponent(id))
}

async function propose(kind: OperatorProposalKind, target: string): Promise<OperatorProposalAnswer> {
  const stepUp = await consoleStepUp(CONSOLE_ROUTES.operatorStepUp, await operatorProposeStepUpAction({ kind, target, params: {} }))
  return api<OperatorProposalAnswer>(CONSOLE_ROUTES.operatorProposals, { kind, target, params: {}, stepUp })
}

// The operator role's kinds and the Settings view's; the Accounts and
// Workspaces views ask for their own.
type RoleKind = Extract<OperatorProposalKind, `operator.${string}`>
type SettingKind = Extract<OperatorProposalKind, `settings.${string}`>

export const CONFIRM_WORDS: Readonly<Record<RoleKind | SettingKind, (name: string) => string>> = {
  "operator.grant": (name) => `Propose making ${name} an operator? Another operator approves it within 24 hours, then ${name} accepts it with their own passkey.`,
  "operator.revoke": (name) => `Propose ending ${name}'s operator role? Another operator approves it within 24 hours.`,
  "operator.resign": () => "Resign as an operator now? You lose the Operator area at once.",
  "settings.narrow": (setting) => `Narrow ${setting} now? It applies at once.`,
  "settings.widen": (setting) => `Propose ${setting}? Another operator approves it within 24 hours.`,
}

// Approve (with a passkey for its digest), Decline and Cancel on every
// open proposal the page lists; the Settings view lists them too.
export function initProposalDecisions(reload: () => void): void {
  for (const button of all<HTMLButtonElement>('[data-action="approve"]')) {
    button.addEventListener("click", () => {
      const id = button.dataset.proposal ?? ""
      const digest = button.dataset.digest ?? ""
      void withBusy(button, WAITING, async () => {
        const stepUp = await consoleStepUp(CONSOLE_ROUTES.operatorStepUp, operatorApproveStepUpAction(id, digest))
        await api<OperatorProposalAnswer>(proposalPath(id), { decision: "approve", digest, stepUp })
        reload()
      })
    })
  }
  for (const decision of ["decline", "cancel"] as const) {
    for (const button of all<HTMLButtonElement>(`[data-action="${decision}"]`)) {
      button.addEventListener("click", () => {
        if (!confirm(decision === "decline" ? "Decline this proposal? Nothing changes." : "Cancel your proposal? Nothing changes.")) return
        void withBusy(button, "Sending...", async () => {
          await api<OperatorProposalAnswer>(proposalPath(button.dataset.proposal ?? ""), { decision })
          reload()
        })
      })
    }
  }
}

export function initOperatorOperators(): void {
  const reload = () => location.reload()
  for (const button of all<HTMLButtonElement>('[data-action="propose"]')) {
    button.addEventListener("click", () => {
      const kind = button.dataset.kind as RoleKind
      const target = button.dataset.target ?? ""
      if (!confirm(CONFIRM_WORDS[kind](button.dataset.name ?? target))) return
      void withBusy(button, WAITING, async () => {
        await propose(kind, target)
        reload()
      })
    })
  }
  initProposalDecisions(reload)
  const grant = find<HTMLFormElement>('[data-form="grant"]')
  if (grant) grant.addEventListener("submit", (event) => {
    event.preventDefault()
    const typed = inputValue('[data-input="account"]', grant).trim()
    if (typed === "") return showProblems(["Type their account id (acc_...) or the email of their Google sign-in."])
    void withBusy(must<HTMLButtonElement>('button[type="submit"]', grant), WAITING, async () => {
      const found = await api<OperatorCandidate>(`${CONSOLE_ROUTES.operatorAccountLookup}?q=${encodeURIComponent(typed)}`)
      if (found.operator) return showProblems([`${found.name} is an operator already.`])
      if (found.missing.length > 0) return showProblems([operatorRequirementsRefusal(found.missing, `${found.name}'s account`)])
      if (!confirm(CONFIRM_WORDS["operator.grant"](`${found.name} (${found.account})`))) return
      await propose("operator.grant", found.account)
      reload()
    })
  })
}

// Your account's acceptance card, when an approved grant names you.
export function initOperatorAcceptance(): void {
  const button = find<HTMLButtonElement>('[data-action="accept-operator"]')
  if (!button) return
  button.addEventListener("click", () => {
    const proposal = button.dataset.proposal ?? ""
    const digest = button.dataset.digest ?? ""
    void withBusy(button, WAITING, async () => {
      const stepUp = await accountStepUp(operatorAcceptStepUpAction(proposal, digest))
      await api(CONSOLE_ROUTES.operatorInvitation, { proposal, digest, stepUp })
      location.reload()
    })
  })
}
