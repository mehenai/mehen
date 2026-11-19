import type { Template } from "../templates.ts"
import { ALLOW_READS, WRITES } from "./shared.ts"

// Snyk takes "token" in front of the key, not "Bearer". The hosts are
// Snyk's regions: a key works only in the region it was made in.
// Without a human: reads, testing a dependency manifest and listing the
// issues of a set of packages. Projects, settings and everything else
// need an approval; invitations, memberships, service accounts, apps and
// webhooks are refused. https://docs.snyk.io/snyk-api/rest-api/about-the-rest-api
export const snyk: Template = {
  id: "snyk",
  displayName: "Snyk API token",
  kind: "api-key",
  category: "code",
  docsUrl: "https://app.snyk.io/account",
  binding: { hosts: ["api.snyk.io", "api.us.snyk.io", "api.eu.snyk.io", "api.au.snyk.io"], paths: ["/rest/**", "/v1/**"] },
  injection: { in: "header", name: "Authorization", format: "token {key}" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "allow", methods: ["POST"], paths: ["/v1/test/**", "/rest/orgs/*/packages/issues"], note: "tests dependencies for known issues" },
      {
        action: "deny",
        methods: WRITES,
        paths: [
          "/rest/orgs/*/invites/**",
          "/rest/orgs/*/memberships/**",
          "/rest/groups/*/memberships/**",
          "/rest/groups/*/users/**",
          "/v1/org/*/invite",
          "/v1/org/*/members/**",
        ],
        note: "invitations and memberships give someone else access",
      },
      { action: "deny", methods: WRITES, paths: ["/rest/orgs/*/service_accounts/**", "/rest/groups/*/service_accounts/**"], note: "service accounts and their secrets" },
      { action: "deny", methods: WRITES, paths: ["/rest/orgs/*/apps/**", "/rest/groups/*/apps/**"], note: "Snyk Apps and their client secrets" },
      { action: "deny", methods: WRITES, paths: ["/v1/org/*/webhooks/**"], note: "webhooks" },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "API token" } },
  setup: {
    title: "In Snyk",
    steps: [
      { title: "Open your account settings", body: "Sign in to Snyk in the region your organisation lives in. A token works only in its own region.", docs: true },
      {
        title: "Copy a token",
        body: "Under Auth Token, show and copy the token. For a shared or long-lived use, an organisation service account token is better: Settings, then Service accounts.",
        field: "key",
      },
    ],
  },
}
