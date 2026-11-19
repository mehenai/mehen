import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, WRITES } from "./shared.ts"

// The hosts are Sentry's: sentry.io and its US and EU regions.
// Without a human: reads. Changing issues, releases, alerts and
// everything else needs an approval. Members and SCIM, service hooks,
// data forwarding, minting auth tokens, custom integrations and deleting
// an organisation or a project are refused.
// https://docs.sentry.io/api/
export const sentry: Template = {
  id: "sentry",
  displayName: "Sentry auth token",
  kind: "api-key",
  category: "observability",
  docsUrl: "https://sentry.io/settings/account/api/auth-tokens/",
  binding: { hosts: ["sentry.io", "us.sentry.io", "de.sentry.io"], paths: ["/api/0/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "deny",
        methods: WRITES,
        paths: ["/api/0/organizations/*/members/**", "/api/0/organizations/*/scim/**", "/api/0/organizations/*/invite-requests/**"],
        note: "members and invitations give someone else access",
      },
      { action: "deny", methods: WRITES, paths: ["/api/0/projects/*/*/hooks/**"], note: "service hooks send events elsewhere" },
      { action: "deny", methods: WRITES, paths: ["/api/0/organizations/*/forwarding/**"], note: "data forwarding sends every event elsewhere" },
      { action: "deny", methods: WRITES, paths: ["/api/0/api-tokens/**", "/api/0/organizations/*/org-auth-tokens/**"], note: "mints or revokes auth tokens" },
      { action: "deny", methods: WRITES, paths: ["/api/0/sentry-apps/**", "/api/0/organizations/*/sentry-apps/**"], note: "custom integrations receive webhooks and tokens" },
      { action: "deny", methods: ["DELETE"], paths: ["/api/0/organizations/*", "/api/0/projects/*/*"], note: "deletes an organisation or a project" },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "Auth token", pattern: "^sntry[us]_" } },
  prefixes: ["sntryu_", "sntrys_"],
  setup: {
    title: "In Sentry",
    steps: [
      { title: "Open your auth tokens", body: "User settings, then Personal tokens. An organisation token (Settings, then Auth tokens) suits CI and releases only.", docs: true },
      { title: "Create a token with read scopes", body: "Tick the read scopes the agent needs, for example project:read, org:read and event:read, and add write scopes only if it is to change issues.", field: "key" },
    ],
  },
}
