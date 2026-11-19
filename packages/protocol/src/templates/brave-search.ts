import type { Template } from "../templates.ts"
import { ALLOW_READS } from "./shared.ts"

// Brave Search takes the key in X-Subscription-Token. Without a human:
// searches, which are all reads. https://api-dashboard.search.brave.com/app/documentation
export const braveSearch: Template = {
  id: "brave-search",
  displayName: "Brave Search API key",
  kind: "api-key",
  category: "search",
  docsUrl: "https://api-dashboard.search.brave.com/app/keys",
  binding: { hosts: ["api.search.brave.com"], paths: ["/res/v1/**"] },
  injection: { in: "header", name: "X-Subscription-Token", format: "{key}" },
  policy: { default: "approve", rules: [{ ...ALLOW_READS, note: "searches" }] },
  ceiling: "placeholder",
  fields: { key: { label: "API key" } },
}
