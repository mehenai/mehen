import type { Template } from "../templates.ts"
import { BEARER, NAMED_READS, READS, WRITES } from "./shared.ts"

// A personal access token for Supabase's Management API. A project's own
// APIs live at <ref>.supabase.co, a host that depends on the project, so
// they are not bound: the vault has no validated per-item host yet.
// Without a human: the named reads (organisations, projects, functions and
// their source, migrations, backups, branch lists, advisors, logs, types,
// buckets, action runs and snippets). Every other read asks, and those that
// hand back a secret are pinned to an approval: project API keys, edge
// function secrets, the auth configuration, the pgsodium root key, the
// claim token, a branch's details (its database password and JWT secret),
// pooler connection strings and the PostgREST JWT secret. SQL, migrations, functions,
// branches and everything else need an approval; new projects, add-ons and
// disk changes are pinned to one because they are billed, and so are
// database passwords and CLI login roles. Minting or changing API keys and
// JWT signing keys, SSO and third-party sign-in, just-in-time database
// access, project claims and transfers, replacing the pgsodium root key,
// the OAuth endpoints and deleting a project are refused.
// https://supabase.com/docs/reference/api/introduction
export const supabase: Template = {
  id: "supabase",
  displayName: "Supabase personal access token",
  kind: "api-key",
  category: "infrastructure",
  docsUrl: "https://supabase.com/dashboard/account/tokens",
  binding: { hosts: ["api.supabase.com"], paths: ["/v1/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      NAMED_READS(
        [
          "/v1/profile",
          "/v1/organizations",
          "/v1/organizations/*",
          "/v1/organizations/*/members",
          "/v1/organizations/*/projects",
          "/v1/projects",
          "/v1/projects/available-regions",
          "/v1/projects/*",
          "/v1/projects/*/health",
          "/v1/projects/*/functions",
          "/v1/projects/*/functions/*",
          "/v1/projects/*/functions/*/body",
          "/v1/projects/*/database/migrations",
          "/v1/projects/*/database/migrations/*",
          "/v1/projects/*/database/backups",
          "/v1/projects/*/branches",
          "/v1/projects/*/advisors/*",
          "/v1/projects/*/analytics/endpoints/*",
          "/v1/projects/*/types/typescript",
          "/v1/projects/*/storage/buckets",
          "/v1/projects/*/actions",
          "/v1/projects/*/actions/*",
          "/v1/projects/*/actions/*/logs",
          "/v1/branches/*/diff",
          "/v1/snippets",
          "/v1/snippets/*",
        ],
        "reads of organisations, projects, functions, migrations, branch lists, logs and snippets",
      ),
      {
        action: "approve",
        methods: READS,
        paths: [
          "/v1/projects/*/api-keys/**",
          "/v1/projects/*/secrets",
          "/v1/projects/*/config/auth",
          "/v1/projects/*/pgsodium",
          "/v1/projects/*/claim-token",
          "/v1/branches/*",
          "/v1/projects/*/config/database/pooler",
          "/v1/projects/*/config/database/pgbouncer",
          "/v1/projects/*/postgrest",
        ],
        note: "API keys, secrets, connection strings, JWT secrets and other values that hand back a secret",
      },
      {
        action: "approve",
        methods: WRITES,
        paths: ["/v1/projects/*/database/password", "/v1/projects/*/cli/login-role"],
        note: "sets a database password or mints a temporary database role",
      },
      {
        action: "approve",
        methods: WRITES,
        paths: ["/v1/projects", "/v1/projects/*/billing/addons/**", "/v1/projects/*/config/disk/**", "/v1/projects/*/upgrade"],
        note: "creates or changes something billed",
      },
      { action: "deny", methods: WRITES, paths: ["/v1/projects/*/api-keys/**", "/v1/projects/*/config/auth/signing-keys/**"], note: "mints or changes API keys and JWT signing keys" },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/v1/projects/*/config/auth/sso/**", "/v1/projects/*/config/auth/third-party-auth/**"],
        note: "lets an outside identity provider sign users in",
      },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/v1/projects/*/database/jit/**", "/v1/projects/*/jit-access"],
        note: "just-in-time database access gives someone else access",
      },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/v1/projects/*/claim-token", "/v1/organizations/*/project-claim/**"],
        note: "claims or transfers a project to another organisation",
      },
      { action: "deny", methods: WRITES, paths: ["/v1/projects/*/pgsodium"], note: "replaces the root encryption key" },
      { action: "deny", methods: WRITES, paths: ["/v1/oauth/**"], note: "OAuth tokens and grants" },
      { action: "deny", methods: ["DELETE"], paths: ["/v1/projects/*"], note: "deletes a project and its data" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "SUPABASE_ACCESS_TOKEN",
  check: { method: "GET", path: "/v1/projects" },
  fields: { key: { label: "Access token", pattern: "^sbp_" } },
  prefixes: ["sbp_"],
  setup: {
    title: "In the Supabase dashboard",
    steps: [
      { title: "Open your access tokens", body: "Account settings, then Access Tokens.", docs: true },
      { title: "Create a scoped token", body: "Where Supabase offers it, scope the token to the organisation and projects the agent works on.", field: "key" },
    ],
  },
}
