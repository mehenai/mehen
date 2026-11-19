import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, WRITES } from "./shared.ts"

// Without a human: reads, searches and questions to a site or an
// organisation. Writing content and everything else needs an approval.
// Members, invitations and permissions, private share links, integration
// tokens, transferring a collection and deleting a space are refused.
// https://gitbook.com/docs/developers/gitbook-api/api-reference
export const gitbook: Template = {
  id: "gitbook",
  displayName: "GitBook API token",
  kind: "api-key",
  category: "productivity",
  docsUrl: "https://app.gitbook.com/account/developer",
  binding: { hosts: ["api.gitbook.com"], paths: ["/v1/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "allow", methods: ["POST"], paths: ["/v1/orgs/*/sites/*/search", "/v1/orgs/*/sites/*/ask", "/v1/orgs/*/ask"], note: "searches and questions" },
      {
        action: "deny",
        methods: WRITES,
        paths: [
          "/v1/orgs/*/members/**",
          "/v1/orgs/*/invites/**",
          "/v1/orgs/*/link-invites/**",
          "/v1/orgs/*/teams/*/members/**",
          "/v1/spaces/*/permissions/**",
          "/v1/collections/*/permissions/**",
          "/v1/orgs/*/sites/*/permissions/**",
        ],
        note: "members, invitations and permissions give someone else access",
      },
      { action: "deny", methods: WRITES, paths: ["/v1/orgs/*/sites/*/share-links/**"], note: "share links open a site to anyone with the link" },
      { action: "deny", methods: WRITES, paths: ["/v1/integrations/*/installations/*/tokens/**"], note: "mints integration tokens" },
      { action: "deny", methods: WRITES, paths: ["/v1/collections/*/transfer"], note: "transfers a collection away" },
      { action: "deny", methods: ["DELETE"], paths: ["/v1/spaces/*"], note: "deletes a space" },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "API token" } },
}
