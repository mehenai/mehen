// Why a request cannot start a task grant, one sentence for each refusal
// code (POLICY_AREA_REFUSALS): the vault's refusal (policy-rules-workspace.ts
// areaRefused), which the CLI shows, and the approval page's line
// (ui/wording.ts) say the same. No imports beyond the type, so the
// browser's bundle may carry it.
import type { PolicyAreaRefusal } from "@mehen/protocol/policy-mode"

export const AREA_REFUSAL_WORDS: Readonly<Record<PolicyAreaRefusal, string>> = {
  "area.unreviewed": "Nobody has reviewed this service's routes, so this request cannot start a task grant.",
  "area.unknown": "Pick areas from this service's reviewed list.",
  "area.not-routine": "This request is not routine building, so it cannot start a task grant.",
  "area.live-key": "This credential holds a live key, so it asks every time.",
  "area.duration": "Pick 15 minutes, 1 hour or 4 hours.",
  "area.uses": "Pick between 1 and 200 requests.",
  "area.terms": "This request cannot start a task grant.",
}
