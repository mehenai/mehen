import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER } from "./shared.ts"

// Without a human: reads, scraping a page, searching, mapping a site and
// parsing a file. Crawls, extraction, agent runs and monitors, which run
// long and spend many credits, need an approval, as does everything
// else. https://docs.firecrawl.dev/api-reference/v2-introduction
export const firecrawl: Template = {
  id: "firecrawl",
  displayName: "Firecrawl API key",
  kind: "api-key",
  category: "search",
  docsUrl: "https://www.firecrawl.dev/app/api-keys",
  binding: { hosts: ["api.firecrawl.dev"], paths: ["/v1/**", "/v2/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "allow", methods: ["POST"], paths: ["/v1/scrape", "/v2/scrape", "/v1/search", "/v2/search", "/v1/map", "/v2/map", "/v2/parse"], note: "scrapes, searches and maps public pages" },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "API key", pattern: "^fc-" } },
  prefixes: ["fc-"],
}
