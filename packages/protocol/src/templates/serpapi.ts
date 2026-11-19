import type { Template } from "../templates.ts"
import { ALLOW_READS } from "./shared.ts"

// SerpApi takes the key as the api_key query parameter. Without a human:
// searches, the search archive and the account's usage, all reads.
// https://serpapi.com/search-api
export const serpapi: Template = {
  id: "serpapi",
  displayName: "SerpApi API key",
  kind: "api-key",
  category: "search",
  docsUrl: "https://serpapi.com/manage-api-key",
  binding: { hosts: ["serpapi.com"], paths: ["/search", "/search.json", "/searches/**", "/account", "/account.json", "/locations.json"] },
  injection: { in: "query", name: "api_key", field: "key" },
  policy: { default: "approve", rules: [{ ...ALLOW_READS, note: "searches" }] },
  ceiling: "placeholder",
  fields: { key: { label: "API key" } },
}
