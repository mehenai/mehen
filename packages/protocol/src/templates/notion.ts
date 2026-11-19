import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, WRITES } from "./shared.ts"

// Notion needs a Notion-Version header on every request; the vault only
// adds the key, so the agent sends that header itself. Without a human:
// reads, searches and data source, database, view and meeting note
// queries. Creating or changing pages, blocks, comments and everything
// else needs an approval; OAuth token routes are refused.
// https://developers.notion.com/reference/intro
export const notion: Template = {
  id: "notion",
  displayName: "Notion integration token",
  kind: "api-key",
  category: "productivity",
  docsUrl: "https://www.notion.so/profile/integrations",
  binding: { hosts: ["api.notion.com"], paths: ["/v1/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "allow",
        methods: ["POST"],
        paths: ["/v1/search", "/v1/data_sources/*/query", "/v1/databases/*/query", "/v1/views/*/queries", "/v1/blocks/meeting_notes/query"],
        note: "searches and queries",
      },
      { action: "deny", methods: WRITES, paths: ["/v1/oauth/**"], note: "OAuth tokens" },
    ],
  },
  ceiling: "placeholder",
  check: { method: "GET", path: "/v1/users/me", headers: [["Notion-Version", "2022-06-28"]] },
  fields: { key: { label: "Internal integration secret", pattern: "^(ntn_|secret_)" } },
  prefixes: ["ntn_", "secret_"],
  setup: {
    title: "In Notion",
    steps: [
      { title: "Create an internal integration", body: "Open the integrations page, choose New integration, pick the workspace and the type Internal.", docs: true },
      { title: "Choose its capabilities", body: "Tick Read content, and Update or Insert content only if the agent is to write. Copy the Internal integration secret.", field: "key" },
      {
        title: "Share pages with it",
        body: "The integration sees only the pages and databases you connect it to: on each page, the menu, then Connections, then add the integration.",
        warn: "Every request to Notion must also carry a Notion-Version header. The vault adds only the secret, so the agent sends that header itself.",
      },
    ],
  },
}
