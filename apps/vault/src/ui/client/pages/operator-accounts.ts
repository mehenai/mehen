// The browser side of one account in the Accounts view
// (/operator/accounts/:id). Each change is an operator proposal signed with
// a passkey for its exact terms (their digest) through the operator's
// step-up start: workspace creation and suspension apply at once;
// recovering access and deleting wait for a second operator. The recovery
// link is taken with a passkey for that link, shown once, and never kept
// in the page's address or storage. Every refusal is the vault's own words.

import { type OperatorBreakGlassLink, type OperatorProposalAnswer, type OperatorProposalKind, type OperatorProposalTerms, accountDeleteNameHash, operatorBreakGlassLinkStepUpAction, operatorProposeStepUpAction } from "@mehen/protocol"
import { CONSOLE_ROUTES } from "@mehen/protocol/platform-console"
import { api } from "../api.ts"
import { all, find, inputValue, must, readBoot, showProblems, withBusy } from "../dom.ts"
import { consoleStepUp } from "../step-up.ts"

const WAITING = "Waiting for your passkey..."

async function propose(terms: OperatorProposalTerms): Promise<OperatorProposalAnswer> {
  const stepUp = await consoleStepUp(CONSOLE_ROUTES.operatorStepUp, await operatorProposeStepUpAction(terms))
  return api<OperatorProposalAnswer>(CONSOLE_ROUTES.operatorProposals, { ...terms, stepUp })
}

type AccountKind = Extract<OperatorProposalKind, `account.${string}`>

const CONFIRM_WORDS: Readonly<Record<AccountKind, (name: string, creation?: string) => string>> = {
  "account.workspace_creation": (name, creation) => (creation === "default" ? `Return ${name}'s workspace creation to the deployment default?` : `${creation === "allow" ? "Allow" : "Deny"} workspace creation for ${name}?`),
  "account.suspend": (name) => `Suspend ${name}'s account now? Every session ends at once and they cannot sign in until an operator lifts it.`,
  "account.lift_suspension": (name) => `Lift ${name}'s suspension? They sign in again with their passkey.`,
  "account.break_glass": (name) => `Propose recovering ${name}'s access? Another operator approves it within 24 hours.`,
  "account.delete": (name) => `Propose deleting ${name}'s account? Another operator approves it within 24 hours, and it cannot be undone.`,
}

export function initOperatorAccount(): void {
  const boot = readBoot()
  const target = typeof boot.account === "string" ? boot.account : ""
  const name = typeof boot.name === "string" ? boot.name : target
  const done = (_answer: OperatorProposalAnswer) => location.reload()
  for (const button of all<HTMLButtonElement>('[data-action="account-propose"]')) {
    button.addEventListener("click", () => {
      const kind = button.dataset.kind as AccountKind
      const creation = button.dataset.creation
      if (!confirm(CONFIRM_WORDS[kind](name, creation))) return
      void withBusy(button, WAITING, async () => done(await propose({ kind, target, params: creation !== undefined ? { creation } : {} })))
    })
  }
  const recover = find<HTMLFormElement>('[data-form="break-glass"]')
  if (recover) recover.addEventListener("submit", (event) => {
    event.preventDefault()
    const verified = inputValue('[data-input="verified"]', recover).trim()
    if (verified === "") return showProblems(["Say how you checked, out of band, that the person asking holds this account."])
    if (!confirm(CONFIRM_WORDS["account.break_glass"](name))) return
    void withBusy(must<HTMLButtonElement>('button[type="submit"]', recover), WAITING, async () => done(await propose({ kind: "account.break_glass", target, params: { verified } })))
  })
  const remove = find<HTMLFormElement>('[data-form="delete-account"]')
  if (remove) remove.addEventListener("submit", (event) => {
    event.preventDefault()
    const typed = inputValue('[data-input="confirm-name"]', remove)
    if (typed !== name) return showProblems(["Type the account's name exactly as shown to confirm."])
    if (!confirm(CONFIRM_WORDS["account.delete"](name))) return
    void withBusy(must<HTMLButtonElement>('button[type="submit"]', remove), WAITING, async () => done(await propose({ kind: "account.delete", target, params: { nameHash: await accountDeleteNameHash(target, typed) } })))
  })
  const link = find<HTMLButtonElement>('[data-action="break-glass-link"]')
  if (link) link.addEventListener("click", () => {
    const intent = link.dataset.intent ?? ""
    void withBusy(link, WAITING, async () => {
      const stepUp = await consoleStepUp(CONSOLE_ROUTES.operatorStepUp, operatorBreakGlassLinkStepUpAction(intent))
      const shown = await api<OperatorBreakGlassLink>(CONSOLE_ROUTES.operatorBreakGlassLink.replace(":id", encodeURIComponent(target)), { intent, stepUp })
      const card = must('[data-region="break-glass-link"]')
      must('[data-region="link"]', card).textContent = shown.link
      card.hidden = false
      link.disabled = true
    })
  })
}
