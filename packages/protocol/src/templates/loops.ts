import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER } from "./shared.ts"

// Loops, for product email. Without a human: reads. Sending a
// transactional email, an event (which can start an email workflow) or a
// preview is pinned to an approval, as is everything else.
// https://loops.so/docs/api-reference
export const loops: Template = {
  id: "loops",
  displayName: "Loops API key",
  kind: "api-key",
  category: "customers",
  docsUrl: "https://app.loops.so/settings?page=api",
  binding: { hosts: ["app.loops.so"], paths: ["/api/v1/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "approve", methods: ["POST"], paths: ["/api/v1/transactional", "/api/v1/events/send", "/api/v1/email-messages/*/preview"], note: "sends email, or an event that can send email" },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "API key" } },
}
