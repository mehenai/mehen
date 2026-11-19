import type { Template } from "../templates.ts"
import { ALLOW_READS } from "./shared.ts"

// Browserbase takes the key in X-BB-API-Key. Without a human: reads,
// starting a browser session (whose connect URL carries its own signing
// key), fetching a page and searching the web. Agent runs, functions and
// their secrets, contexts and everything else need an approval.
// https://docs.browserbase.com/reference/api/overview
export const browserbase: Template = {
  id: "browserbase",
  displayName: "Browserbase API key",
  kind: "api-key",
  category: "search",
  docsUrl: "https://www.browserbase.com/settings",
  binding: { hosts: ["api.browserbase.com"], paths: ["/v1/**"] },
  injection: { in: "header", name: "X-BB-API-Key", format: "{key}" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "allow", methods: ["POST"], paths: ["/v1/sessions", "/v1/fetch", "/v1/search"], note: "starts a browser session, fetches pages and searches" },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "API key" } },
}
