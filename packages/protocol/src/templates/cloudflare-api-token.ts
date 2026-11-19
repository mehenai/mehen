import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER } from "./shared.ts"

// Without a human: reads and GraphQL Analytics queries, but not a
// tunnel's token (a floor in the Cloudflare catalogue,
// policy-catalogue.ts). Every change (DNS, Workers, storage) needs an
// approval; minting tokens is refused.
export const cloudflareApiToken: Template = {
  id: "cloudflare-api-token",
  displayName: "Cloudflare API token",
  kind: "api-key",
  category: "infrastructure",
  docsUrl: "https://dash.cloudflare.com/profile/api-tokens",
  binding: { hosts: ["api.cloudflare.com"], paths: ["/client/v4/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "allow", methods: ["POST"], paths: ["/client/v4/graphql"], body: "graphql-query", note: "GraphQL Analytics queries" },
      { action: "approve", methods: ["DELETE"], note: "deletes" },
      { action: "deny", paths: ["/client/v4/user/tokens/**", "/client/v4/accounts/*/tokens/**"], methods: ["POST", "PUT", "PATCH", "DELETE"], note: "minting tokens" },
    ],
  },
  ceiling: "placeholder",
  // Not /user/tokens/verify: an account-owned token answers 401 there.
  check: { method: "GET", path: "/client/v4/accounts?per_page=1" },
  fields: { key: { label: "API token" } },
}
