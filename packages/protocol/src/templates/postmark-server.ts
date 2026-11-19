import type { Template } from "../templates.ts"
import { ALLOW_READS, READS, WRITES } from "./shared.ts"

// A Postmark server token, which reaches one server. Without a human:
// reads, except the server itself, whose details carry its API tokens.
// Sending email is pinned to an approval, as is everything else.
// Webhooks and server settings (which say where inbound mail is posted)
// are refused. https://postmarkapp.com/developer/api/overview
export const postmarkServer: Template = {
  id: "postmark-server",
  displayName: "Postmark server token",
  kind: "api-key",
  category: "customers",
  docsUrl: "https://account.postmarkapp.com/servers",
  binding: { hosts: ["api.postmarkapp.com"] },
  injection: { in: "header", name: "X-Postmark-Server-Token", format: "{key}" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "approve", methods: READS, paths: ["/server"], note: "the server's details, which include its API tokens" },
      { action: "approve", methods: ["POST"], paths: ["/email", "/email/batch", "/email/withTemplate", "/email/batchWithTemplates"], note: "sends email" },
      { action: "deny", methods: WRITES, paths: ["/webhooks/**"], note: "webhooks" },
      { action: "deny", methods: WRITES, paths: ["/server"], note: "server settings, including where inbound mail is posted" },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "Server API token" } },
}
