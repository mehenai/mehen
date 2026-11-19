import type { Template } from "../templates.ts"
import { ALLOW_READS, WRITES } from "./shared.ts"

// A PlanetScale service token goes in Authorization as "<id>:<token>",
// with no scheme, so it is stored as a username (the token id) and a
// password (the token). Without a human: reads. Deploy requests, branches,
// schema changes and everything else need an approval; database passwords
// and roles are pinned to one, as are new databases, subscriptions and
// resizes, which are billed. Service tokens, OAuth application tokens,
// members, invitations and teams, SSO, webhooks, payment methods and
// deleting a database are refused.
// https://planetscale.com/docs/api/reference/getting-started-with-planetscale-api
export const planetscale: Template = {
  id: "planetscale",
  displayName: "PlanetScale service token",
  kind: "basic-auth",
  category: "infrastructure",
  docsUrl: "https://planetscale.com/docs/api/reference/service-tokens",
  binding: { hosts: ["api.planetscale.com"], paths: ["/v1/**"] },
  injection: { in: "header", name: "Authorization", format: "{username}:{password}" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "approve",
        methods: WRITES,
        paths: ["/v1/organizations/*/databases/*/branches/*/passwords/**", "/v1/organizations/*/databases/*/branches/*/roles/**"],
        note: "mints or changes database passwords and roles",
      },
      {
        action: "approve",
        methods: WRITES,
        paths: [
          "/v1/organizations/*/databases",
          "/v1/organizations/*/database-subscriptions",
          "/v1/organizations/*/databases/*/subscription",
          "/v1/organizations/*/databases/*/branches/*/resizes",
          "/v1/organizations/*/databases/*/branches/*/cluster",
        ],
        note: "creates or resizes something billed",
      },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/v1/organizations/*/service-tokens/**", "/v1/organizations/*/oauth-applications/**"],
        note: "mints, changes or revokes service and OAuth tokens",
      },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/v1/organizations/*/members/**", "/v1/organizations/*/invitations/**", "/v1/organizations/*/teams/**", "/v1/organizations/*/sso/**"],
        note: "members, invitations, teams and SSO give someone else access",
      },
      { action: "deny", methods: WRITES, paths: ["/v1/organizations/*/databases/*/webhooks/**"], note: "webhooks send database events elsewhere" },
      { action: "deny", methods: WRITES, paths: ["/v1/organizations/*/billing/**"], note: "payment methods" },
      { action: "deny", methods: ["DELETE"], paths: ["/v1/organizations/*/databases/*"], note: "deletes a database and every branch in it" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "PLANETSCALE_SERVICE_TOKEN",
  check: { method: "GET", path: "/v1/organizations" },
  fields: { username: { label: "Service token ID" }, password: { label: "Service token", pattern: "^pscale_tkn_" } },
  prefixes: ["pscale_tkn_"],
  setup: {
    title: "In PlanetScale",
    steps: [
      { title: "Open service tokens", body: "Your organisation's Settings, then Service tokens.", docs: true },
      { title: "Create a token and copy its ID", body: "Grant it access only to the databases and actions the agent needs. The ID is shown beside the token.", field: "username" },
      { title: "Paste the token", body: "The token itself, starting pscale_tkn_; it is shown once.", field: "password" },
    ],
  },
}
