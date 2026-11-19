import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, WRITES } from "./shared.ts"

// A personal API key, for PostHog's private API in either cloud: the
// key works only where it was made. Without a human: reads, and HogQL,
// logs, metrics, trace and error tracking queries. Creating or changing
// insights, flags and everything else needs an approval. Invitations,
// members and roles, personal API keys, destinations and batch exports,
// and deleting a project or organisation are refused.
// https://posthog.com/docs/api
export const posthog: Template = {
  id: "posthog",
  displayName: "PostHog personal API key",
  kind: "api-key",
  category: "observability",
  docsUrl: "https://us.posthog.com/settings/user-api-keys",
  binding: { hosts: ["us.posthog.com", "eu.posthog.com"], paths: ["/api/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "allow",
        methods: ["POST"],
        paths: [
          "/api/projects/*/query",
          "/api/projects/*/query/*",
          "/api/projects/*/logs/query",
          "/api/projects/*/metrics/query",
          "/api/projects/*/tracing/spans/query",
          "/api/projects/*/error_tracking/query/**",
        ],
        note: "HogQL and other queries",
      },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/api/organizations/*/invites/**", "/api/organizations/*/members/**", "/api/organizations/*/roles/**"],
        note: "invitations, members and roles give someone else access",
      },
      { action: "deny", methods: WRITES, paths: ["/api/personal_api_keys/**", "/api/users/*/personal_api_keys/**"], note: "mints or revokes personal API keys" },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/api/projects/*/hog_functions/**", "/api/projects/*/batch_exports/**", "/api/environments/*/hog_functions/**", "/api/environments/*/batch_exports/**"],
        note: "destinations and batch exports send events elsewhere",
      },
      { action: "deny", methods: ["DELETE"], paths: ["/api/projects/*", "/api/environments/*", "/api/organizations/*"], note: "deletes a project or an organisation" },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "Personal API key", pattern: "^phx_" } },
  prefixes: ["phx_"],
  setup: {
    title: "In PostHog",
    steps: [
      {
        title: "Open your personal API keys",
        body: "In the cloud your organisation uses: us.posthog.com or eu.posthog.com, then Settings, then Personal API keys. The link opens the US cloud.",
        docs: true,
      },
      { title: "Create a key with read scopes", body: "Choose the organisation or projects it may reach, and tick read scopes only, for example Query read and Insight read.", field: "key" },
    ],
  },
}
