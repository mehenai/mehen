import type { Template } from "../templates.ts"
import { ALLOW_READS, READS, WRITES } from "./shared.ts"

const API = "/api/v4"

// A GitLab.com personal, project or group access token, in GitLab's own
// PRIVATE-TOKEN header. Self-managed instances have their own hosts and
// are not bound. A project is named by its numeric id: the binding refuses
// the URL-encoded "group%2Fproject" form, as it refuses every encoded
// slash. Without a human: reads, except CI/CD variables and secure files,
// which hold secrets and need an approval. Every write needs an approval,
// GraphQL queries included, since a query can read CI/CD variable values.
// Webhooks, SSH, GPG and deploy keys, every kind of access token, deploy
// and trigger tokens, runners, members, invitations, sharing and access
// requests, service accounts, transfers, push mirrors, integrations,
// account emails and deleting a project or group are refused.
// https://docs.gitlab.com/api/rest/
export const gitlab: Template = {
  id: "gitlab",
  displayName: "GitLab access token",
  kind: "api-key",
  category: "code",
  docsUrl: "https://gitlab.com/-/user_settings/personal_access_tokens",
  binding: { hosts: ["gitlab.com"], paths: [`${API}/**`, "/api/graphql"] },
  injection: { in: "header", name: "PRIVATE-TOKEN", format: "{key}" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "approve",
        methods: READS,
        paths: [`${API}/projects/*/variables/**`, `${API}/groups/*/variables/**`, `${API}/admin/ci/variables/**`, `${API}/projects/*/secure_files/**`],
        note: "CI/CD variables and secure files hand back secrets",
      },
      { action: "approve", paths: ["/api/graphql"], note: "GraphQL requests, since a query can read CI/CD variable values" },
      { action: "deny", methods: WRITES, paths: [`${API}/projects/*/hooks/**`, `${API}/groups/*/hooks/**`, `${API}/hooks/**`], note: "webhooks" },
      {
        action: "deny",
        methods: WRITES,
        paths: [`${API}/user/keys/**`, `${API}/user/gpg_keys/**`, `${API}/users/*/keys/**`, `${API}/users/*/gpg_keys/**`, `${API}/projects/*/deploy_keys/**`, `${API}/deploy_keys/**`],
        note: "SSH, GPG and deploy keys",
      },
      {
        action: "deny",
        methods: WRITES,
        paths: [
          `${API}/personal_access_tokens/**`,
          `${API}/user/personal_access_tokens/**`,
          `${API}/users/*/personal_access_tokens/**`,
          `${API}/users/*/impersonation_tokens/**`,
          `${API}/projects/*/access_tokens/**`,
          `${API}/groups/*/access_tokens/**`,
          `${API}/projects/*/deploy_tokens/**`,
          `${API}/groups/*/deploy_tokens/**`,
          `${API}/projects/*/triggers/**`,
          `${API}/groups/*/service_accounts/**`,
          `${API}/service_accounts/**`,
        ],
        note: "mints, rotates or revokes tokens",
      },
      {
        action: "deny",
        methods: WRITES,
        paths: [`${API}/user/runners/**`, `${API}/runners/**`, `${API}/projects/*/runners/**`, `${API}/groups/*/runners/**`],
        note: "runners receive jobs and their secrets",
      },
      {
        action: "deny",
        methods: WRITES,
        paths: [
          `${API}/projects/*/members/**`,
          `${API}/groups/*/members/**`,
          `${API}/projects/*/invitations/**`,
          `${API}/groups/*/invitations/**`,
          `${API}/projects/*/share/**`,
          `${API}/groups/*/share/**`,
          `${API}/projects/*/access_requests/**`,
          `${API}/groups/*/access_requests/**`,
        ],
        note: "members, invitations, sharing and access requests give someone else access",
      },
      { action: "deny", methods: WRITES, paths: [`${API}/projects/*/transfer`, `${API}/groups/*/transfer`], note: "transfers a project or group away" },
      {
        action: "deny",
        methods: WRITES,
        paths: [`${API}/projects/*/remote_mirrors/**`, `${API}/projects/*/integrations/**`, `${API}/projects/*/services/**`, `${API}/groups/*/integrations/**`],
        note: "push mirrors and integrations send code and events elsewhere",
      },
      { action: "deny", methods: WRITES, paths: [`${API}/user/emails/**`], note: "account email addresses reset the password" },
      { action: "deny", methods: ["DELETE"], paths: [`${API}/projects/*`, `${API}/groups/*`], note: "deletes a project or group" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "GITLAB_TOKEN",
  check: { method: "GET", path: `${API}/personal_access_tokens/self` },
  fields: { key: { label: "Access token", pattern: "^glpat-" } },
  prefixes: ["glpat-"],
}
