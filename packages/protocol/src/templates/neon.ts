import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, WRITES } from "./shared.ts"

// Neon's management API. Without a human: reads, except a database
// password, connection string or other secret, which needs an approval,
// and branch log queries. Branches, computes, databases, roles and
// everything else need an approval. Minting API keys, project and
// organisation access and invitations, transfers, outside identity
// providers (JWKS), billing and deleting a project are refused.
// https://api-docs.neon.tech/reference/getting-started-with-neon-api
export const neon: Template = {
  id: "neon",
  displayName: "Neon API key",
  kind: "api-key",
  category: "infrastructure",
  docsUrl: "https://console.neon.tech/app/settings/api-keys",
  binding: { hosts: ["console.neon.tech"], paths: ["/api/v2/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "allow", methods: ["POST"], paths: ["/api/v2/projects/*/branches/*/logs/query"], note: "queries branch logs" },
      {
        action: "approve",
        paths: [
          "/api/v2/projects/*/connection_uri",
          "/api/v2/projects/*/branches/*/roles/*/reveal_password",
          "/api/v2/projects/*/branches/*/roles/*/reset_password",
          "/api/v2/projects/*/branches/*/realtime/secret",
          "/api/v2/projects/*/branches/*/credentials/*/reveal",
        ],
        note: "a database password, connection string or other secret",
      },
      { action: "deny", methods: WRITES, paths: ["/api/v2/api_keys/**", "/api/v2/organizations/*/api_keys/**"], note: "mints or revokes API keys" },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/api/v2/projects/*/permissions/**", "/api/v2/projects/*/members/**", "/api/v2/organizations/*/invitations/**", "/api/v2/organizations/*/members/**"],
        note: "access, members and invitations give someone else access",
      },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/api/v2/projects/*/transfer_requests/**", "/api/v2/organizations/*/projects/transfer", "/api/v2/users/me/projects/transfer"],
        note: "transfers projects to another account",
      },
      { action: "deny", methods: WRITES, paths: ["/api/v2/projects/*/jwks/**"], note: "lets an outside identity provider sign in to the database" },
      { action: "deny", methods: WRITES, paths: ["/api/v2/organizations/*/billing/**"], note: "billing and spending limits" },
      { action: "deny", methods: ["DELETE"], paths: ["/api/v2/projects/*"], note: "deletes a project and every branch in it" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "NEON_API_KEY",
  check: { method: "GET", path: "/api/v2/users/me" },
  fields: { key: { label: "API key" } },
  setup: {
    title: "In the Neon console",
    steps: [
      { title: "Open API keys", body: "Organisation settings, then API keys, for a key scoped to one organisation or project; Account settings for a personal key.", docs: true },
      { title: "Create a project-scoped key", body: "Where Neon offers it, scope the key to the one project the agent works on.", field: "key" },
    ],
  },
}
