import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, WRITES } from "./shared.ts"

// Without a human: reads, received mail included. Sending an email, a
// batch or a broadcast is pinned to an approval, as is everything else.
// Minting or revoking API keys, webhooks and OAuth grants are refused.
// https://resend.com/docs/api-reference/introduction
export const resend: Template = {
  id: "resend",
  displayName: "Resend API key",
  kind: "api-key",
  category: "customers",
  docsUrl: "https://resend.com/api-keys",
  binding: { hosts: ["api.resend.com"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "approve", methods: ["POST"], paths: ["/emails", "/emails/batch", "/broadcasts/*/send"], note: "sends email" },
      { action: "deny", methods: WRITES, paths: ["/api-keys/**"], note: "mints or revokes API keys" },
      { action: "deny", methods: WRITES, paths: ["/webhooks/**"], note: "webhooks" },
      { action: "deny", methods: WRITES, paths: ["/oauth/**"], note: "OAuth grants" },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "API key", pattern: "^re_" } },
  prefixes: ["re_"],
}
