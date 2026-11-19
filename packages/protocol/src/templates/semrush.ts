import type { Template } from "../templates.ts"
import { ALLOW_READS } from "./shared.ts"

// Semrush takes the key as the key query parameter. Without a human:
// reports, which are reads and spend API units. Changing projects and
// everything else needs an approval.
// https://developer.semrush.com/api/basics/get-started/
export const semrush: Template = {
  id: "semrush",
  displayName: "Semrush API key",
  kind: "api-key",
  category: "search",
  docsUrl: "https://www.semrush.com/accounts/subscription-info/api-units",
  binding: { hosts: ["api.semrush.com"] },
  injection: { in: "query", name: "key", field: "key" },
  policy: { default: "approve", rules: [{ ...ALLOW_READS, note: "reports, which spend API units" }] },
  ceiling: "placeholder",
  fields: { key: { label: "API key" } },
}
