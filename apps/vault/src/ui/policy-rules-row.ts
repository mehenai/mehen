// The parts of a standing rule's row that the page draws again in place
// (client/pages/policy-rules.ts) exactly as the server first drew them
// (policy-rules-list.ts): its status pill, its outcome region, the row a
// viewer who may stop a rule but not read it is left with once it is
// stopped, and the terms the row shows, which Extend checks the vault's
// action against. Built on html.ts and wording.ts alone, which the browser
// bundle carries already.

import { type PolicyAreaGrantView, type PolicyRuleStopped, type PolicyRuleTerms, type PolicyRuleView, PolicyRuleTermsSchema } from "@mehen/protocol/policy-mode"
import { type Html, html } from "./html.ts"
import { RULE_ACTIVE_WORDS, RULE_ID_LABEL, RULE_STOPPED_ONLY_WORDS, ruleEndedPill, ruleStopOutcomeWords, ruleStoppedHereWords } from "./wording.ts"

// A rule's terms as the vault digests them (policyRuleTermsDigest): its
// view without the id, the people, the uses and the times.
export function ruleTermsOf(rule: PolicyRuleTerms): PolicyRuleTerms {
  return Object.fromEntries(Object.keys(PolicyRuleTermsSchema.shape).map((key) => [key, rule[key as keyof PolicyRuleTerms]])) as PolicyRuleTerms
}

// components.ts pill, spelt here so the browser bundle needs nothing else.
export function ruleStatusPill(rule: Pick<PolicyRuleView, "status"> & { endedReason: PolicyAreaGrantView["endedReason"] }): Html {
  return rule.status === "active" ? html`<span class="pill ok dot">${RULE_ACTIVE_WORDS}</span>` : html`<span class="pill muted">${ruleEndedPill(rule.endedReason)}</span>`
}

// The row's live region, shown and empty until Stop or Extend says what
// happened in it; it takes focus, but is no tab stop, when the control
// that had focus goes.
export function outcomeRegion(words: string): Html {
  return html`<div class="small" role="status" tabindex="-1" data-region="rule-outcome">${words}</div>`
}

// Only the id, the status and why it ended: never a term. Drawn once the
// viewer's Stop is answered, so its outcome says what the Stop did.
export function stoppedOnlyRow(rule: PolicyRuleStopped | Pick<PolicyAreaGrantView, "id" | "status" | "endedReason">): Html {
  return html`<li class="row" data-region="rule" data-rule="${rule.id}" data-rule-state="${rule.status}">
    <div class="row-main"><span class="row-title">${RULE_ID_LABEL} <code>${rule.id}</code></span><span class="row-sub">${RULE_STOPPED_ONLY_WORDS}${rule.status === "ended" ? ` ${ruleStoppedHereWords(rule.endedReason)}` : ""}</span>${outcomeRegion(ruleStopOutcomeWords(rule.endedReason))}</div>
    <span class="row-side" data-region="rule-status">${ruleStatusPill(rule)}</span>
  </li>`
}
