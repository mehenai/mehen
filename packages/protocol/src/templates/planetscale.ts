import type { Template } from "../templates.ts"
import { NAMED_READS, READS, WRITES } from "./shared.ts"

const DB = "/v1/organizations/*/databases/*"

// A PlanetScale service token goes in Authorization as "<id>:<token>",
// with no scheme, so it is stored as a username (the token id) and a
// password (the token). Without a human: the named reads (the user,
// organisations and their members, regions, databases, branches, schemas,
// backups, metrics and insights, and deploy requests). Every other read
// asks, and those that hand back a secret are pinned to an approval:
// roles and passwords, service and OAuth application tokens, team members
// (with their passwords) and webhooks (each carries its signing secret). Deploy requests, branches,
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
      NAMED_READS(
        [
          "/v1/user",
          "/v1/regions",
          "/v1/organizations",
          "/v1/organizations/*",
          "/v1/organizations/*/members",
          "/v1/organizations/*/regions",
          "/v1/organizations/*/audit-log",
          "/v1/organizations/*/invoices/**",
          "/v1/organizations/*/databases",
          DB,
          `${DB}/regions`,
          `${DB}/branches`,
          `${DB}/branches/*`,
          `${DB}/branches/*/schema`,
          `${DB}/branches/*/schema/lint`,
          `${DB}/branches/*/backups/**`,
          `${DB}/branches/*/metrics/**`,
          `${DB}/branches/*/insights/**`,
          `${DB}/deploy-requests/**`,
          `${DB}/deploy-queue`,
          `${DB}/schema-recommendations/**`,
        ],
        "reads of organisations, databases, branches, schemas, metrics and deploy requests",
      ),
      {
        action: "approve",
        methods: READS,
        paths: [
          `${DB}/branches/*/roles/**`,
          `${DB}/branches/*/passwords/**`,
          `${DB}/webhooks/**`,
          "/v1/organizations/*/service-tokens/**",
          "/v1/organizations/*/oauth-applications/**",
          "/v1/organizations/*/teams/*/members/**",
        ],
        note: "roles, passwords, tokens, team members and webhooks hand back secrets",
      },
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
