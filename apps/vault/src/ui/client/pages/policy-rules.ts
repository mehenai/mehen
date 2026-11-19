// Stop and Extend on the "Allowed without asking" card (policy-rules-list.ts)
// of a credential's or a machine's page; the page has no card, and this
// wires nothing, unless the vault listed a rule. The flows themselves are
// policy-rules-sign.ts; this only reads the row and redraws it from the
// vault's answer, with the server's own markup (policy-rules-row.ts) for
// the status pill and the stopped-only row.

import type { PolicyAreaGrantView, PolicyRuleExtended, PolicyRuleStopped, PolicyRuleView } from "@mehen/protocol/policy-mode"
import type { Html } from "../../html.ts"
import { ruleStatusPill, ruleTermsOf, stoppedOnlyRow } from "../../policy-rules-row.ts"
import {
  RULE_COSIGN_CODE_WORDS, RULE_COSIGN_LINK_WORDS, RULE_EXTEND_COSIGN_WORDS, RULE_EXTEND_CHOOSE_WORDS, RULE_EXTEND_WAITING_WORDS, RULE_STOPPING_WORDS, RULE_TERM_LABELS,
  formatTime, ruleExtendedWords, ruleStopOutcomeWords, ruleStoppedHereWords, rulesAllowedWords,
} from "../../wording.ts"
import { all, el, find, must, showProblems, withBusy } from "../dom.ts"
import { coSignHref, extendRule, isStoppedOnly, ruleDuration, shownRuleTerms, stopRule } from "../policy-rules-sign.ts"
import type { ShellState } from "../shell-logic.ts"

// As the server's timeTag (components.ts) draws it: a value that is not a
// time is shown as sent.
function timeElement(value: string): HTMLElement | string {
  const at = new Date(value)
  if (Number.isNaN(at.getTime())) return value
  const words = formatTime(value)
  const node = el("time", null, words)
  node.setAttribute("datetime", at.toISOString())
  node.setAttribute("title", words)
  return node
}

// Markup policy-rules-row.ts drew, as the element it is.
function drawn(markup: Html, selector: string): HTMLElement {
  return must(selector, new DOMParser().parseFromString(markup.value, "text/html"))
}

// The compact line counts the viewer's own live rules this page lists; it
// goes once none is left.
function recount(): void {
  const line = find('[data-region="policy-rules-line"]')
  if (line === null) return
  // Task grant rows are not counted: the line counts requests rules let through.
  const count = all('[data-region="rule"][data-rule-own][data-rule-state="active"]').filter((row) => row.dataset.ruleKind !== "area").length
  if (count === 0) line.hidden = true
  else must('[data-region="policy-rules-count"]', line).textContent = rulesAllowedWords(count)
}

// Says what happened in the row's live region and moves focus there, before
// the control that had it goes.
function say(row: HTMLElement, ...words: (HTMLElement | string)[]): void {
  const outcome = must('[data-region="rule-outcome"]', row)
  outcome.replaceChildren(...words)
  outcome.focus()
}

function showStopped(row: HTMLElement, rule: PolicyRuleView | PolicyAreaGrantView): void {
  say(row, ruleStopOutcomeWords(rule.endedReason))
  row.dataset.ruleState = rule.status
  must('[data-region="rule-status"]', row).replaceChildren(drawn(ruleStatusPill(rule), ".pill"))
  must('[data-region="rule-ends-label"]', row).textContent = rule.status === "active" ? RULE_TERM_LABELS.ends : RULE_TERM_LABELS.ended
  must('[data-region="rule-ends"]', row).replaceChildren(timeElement(rule.endsAt))
  if (rule.status === "ended") {
    const ended = must('[data-region="rule-ended"]', row)
    ended.textContent = ruleStoppedHereWords(rule.endedReason)
    ended.hidden = false
    for (const fold of all('[data-region="rule-stop"], [data-region="rule-extend"]', row)) fold.remove()
  }
}

// What a viewer who may stop but not read the rule learns: every term the
// row showed goes, and only the id and its status stay, as the server draws
// that row.
function showStoppedOnly(row: HTMLElement, rule: PolicyRuleStopped | Pick<PolicyAreaGrantView, "id" | "status" | "endedReason">): void {
  say(row, ruleStopOutcomeWords(rule.endedReason))
  const stopped = drawn(stoppedOnlyRow(rule), '[data-region="rule"]')
  row.replaceWith(stopped)
  must('[data-region="rule-outcome"]', stopped).focus()
}

function showExtended(shell: ShellState, row: HTMLElement, answer: PolicyRuleExtended): void {
  if (answer.coSign === null) {
    must('[data-region="rule-ends"]', row).replaceChildren(timeElement(answer.rule.endsAt))
    // The extension's duration is now among the rule's terms.
    find('[data-action="rule-extend"]', row)?.setAttribute("data-rule-terms", JSON.stringify(ruleTermsOf(answer.rule)))
    say(row, el("p", null, ruleExtendedWords(answer.rule.endsAt)))
  } else {
    const href = coSignHref(shell, answer.coSign.id)
    const link = el("p", null, `${RULE_COSIGN_LINK_WORDS}: `)
    if (href !== null) {
      const a = el("a", null, href)
      a.setAttribute("href", href)
      link.append(a)
    }
    const code = el("p", null, `${RULE_COSIGN_CODE_WORDS}: `)
    code.append(el("code", null, answer.coSign.bindingCode))
    say(row, el("p", null, RULE_EXTEND_COSIGN_WORDS), ...(href !== null ? [link] : []), code)
    // One extension waits for its co-signer at a time.
    find('[data-region="rule-extend"]', row)?.remove()
  }
}

// While Stop or Extend runs on a row, all of that row's controls wait (both
// buttons and every duration), so nothing but the duration chosen at the
// click is signed, and Stop cannot race Extend.
async function whileRowWaits(row: HTMLElement, button: HTMLButtonElement, waiting: string, action: () => Promise<void>): Promise<void> {
  const controls = all<HTMLButtonElement | HTMLInputElement>('[data-action="rule-stop"], [data-action="rule-extend"], [data-input="rule-ttl"]', row)
  for (const control of controls) control.disabled = true
  try {
    await withBusy(button, waiting, action)
  } finally {
    for (const control of controls) control.disabled = false
  }
}

export function initPolicyRules(shell: ShellState): void {
  for (const button of all<HTMLButtonElement>('[data-action="rule-stop"]')) {
    button.addEventListener("click", () => {
      const rule = button.dataset.rule ?? ""
      const item = button.closest<HTMLElement>('[data-region="rule"]')
      if (item === null) return
      void whileRowWaits(item, button, RULE_STOPPING_WORDS, async () => {
        const answer = await stopRule(shell, rule)
        if (isStoppedOnly(answer)) showStoppedOnly(item, answer)
        else showStopped(item, answer)
        recount()
      })
    })
  }
  for (const button of all<HTMLButtonElement>('[data-action="rule-extend"]')) {
    button.addEventListener("click", () => {
      const rule = button.dataset.rule ?? ""
      const item = button.closest<HTMLElement>('[data-region="rule"]')
      if (item === null) return
      const ttl = ruleDuration(find<HTMLInputElement>('[data-input="rule-ttl"]:checked', item)?.value ?? "")
      if (ttl === null) return showProblems([RULE_EXTEND_CHOOSE_WORDS])
      void whileRowWaits(item, button, RULE_EXTEND_WAITING_WORDS, async () => showExtended(shell, item, await extendRule(shell, rule, ttl, shownRuleTerms(button.dataset.ruleTerms))))
    })
  }
}
