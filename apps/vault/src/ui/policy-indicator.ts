// The compact line a credential's page or a machine's page shows while
// standing rules let the viewer's own machines' requests through without
// asking (policy-rules-list.ts builds it from the page's own reads), linking
// where those rules are listed.

import { type Html, html } from "./html.ts"
import { RULES_CARD_TITLE, rulesAllowedWords } from "./wording.ts"

export type PolicyRulesLine = { count: number; href: string }

export function policyRulesLine(line: PolicyRulesLine): Html {
  return html`<section class="notice warn attention" data-region="policy-rules-line" aria-label="${RULES_CARD_TITLE}" aria-live="polite">
    <p class="notice-title"><a href="${line.href}" data-region="policy-rules-count">${rulesAllowedWords(line.count)}</a></p>
  </section>`
}
