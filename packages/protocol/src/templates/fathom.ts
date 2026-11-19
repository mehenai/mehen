import type { Template } from "../templates.ts"
import { ALLOW_READS, WRITES } from "./shared.ts"

// Fathom, the meeting recorder (fathom.ai). Without a human: reads, but
// a recording's summary or transcript needs an approval: that route
// posts the text to any URL named in its query, which no rule can see.
// Read transcripts through the meetings list instead
// (GET /meetings?include_transcript=true). Webhooks are refused.
// https://developers.fathom.ai/api-overview
export const fathom: Template = {
  id: "fathom",
  displayName: "Fathom API key",
  kind: "api-key",
  category: "productivity",
  docsUrl: "https://fathom.video/customize#api-access-header",
  binding: { hosts: ["api.fathom.ai"], paths: ["/external/v1/**"] },
  injection: { in: "header", name: "X-Api-Key", format: "{key}" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "approve",
        paths: ["/external/v1/recordings/*/summary", "/external/v1/recordings/*/transcript"],
        note: "a summary or transcript, which can be sent on to any URL; read it from the meetings list",
      },
      { action: "deny", methods: WRITES, paths: ["/external/v1/webhooks/**"], note: "webhooks send every meeting elsewhere" },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "API key" } },
}
