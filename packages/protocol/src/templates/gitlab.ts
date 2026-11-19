import type { Template } from "../templates.ts"
import { NAMED_READS, READS, WRITES } from "./shared.ts"

const API = "/api/v4"

// A GitLab.com personal, project or group access token, in GitLab's own
// PRIVATE-TOKEN header. Self-managed instances have their own hosts and
// are not bound. A project is named by its numeric id: the binding refuses
// the URL-encoded "group%2Fproject" form, as it refuses every encoded
// slash. Without a human: the named reads (the user, projects and groups,
// repository contents, issues, merge requests, pipelines and jobs,
// releases, labels, milestones, members, environments, deployments,
// to-dos, namespaces and search). Every other read asks, and those that
// hand back a secret are pinned to an approval: CI/CD, pipeline and
// schedule variables, secure files, trigger tokens, deploy and access
// tokens, cluster agents, webhooks, integrations and push mirrors. Every
// write needs an approval, and GraphQL queries too, since a query can read
// CI/CD variable values; GraphQL mutations are refused. Webhooks, SSH, GPG
// and deploy keys, every kind of access token, deploy and trigger tokens,
// runners, members, invitations, sharing and access requests, service
// accounts, protected branches, tags and environments, transfers, push
// mirrors, integrations, account emails, and updating or deleting a
// project or group (its settings set visibility and access) are refused.
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
      NAMED_READS(
        [
          `${API}/user`,
          `${API}/version`,
          `${API}/personal_access_tokens/self`,
          `${API}/projects`,
          `${API}/projects/*`,
          `${API}/projects/*/repository/**`,
          `${API}/projects/*/issues/**`,
          `${API}/projects/*/merge_requests/**`,
          `${API}/projects/*/pipelines`,
          `${API}/projects/*/pipelines/*`,
          `${API}/projects/*/pipelines/*/jobs`,
          `${API}/projects/*/jobs/**`,
          `${API}/projects/*/releases/**`,
          `${API}/projects/*/labels/**`,
          `${API}/projects/*/milestones/**`,
          `${API}/projects/*/members/**`,
          `${API}/projects/*/environments/**`,
          `${API}/projects/*/deployments/**`,
          `${API}/projects/*/search`,
          `${API}/groups`,
          `${API}/groups/*`,
          `${API}/groups/*/projects`,
          `${API}/groups/*/issues`,
          `${API}/groups/*/merge_requests`,
          `${API}/issues`,
          `${API}/merge_requests`,
          `${API}/todos`,
          `${API}/namespaces/**`,
          `${API}/search`,
        ],
        "reads of projects, groups, code, issues, merge requests, pipelines and jobs",
      ),
      {
        action: "approve",
        methods: READS,
        paths: [
          `${API}/projects/*/variables/**`,
          `${API}/groups/*/variables/**`,
          `${API}/admin/ci/variables/**`,
          `${API}/projects/*/secure_files/**`,
          `${API}/projects/*/triggers/**`,
          `${API}/projects/*/pipelines/*/variables`,
          `${API}/projects/*/pipeline_schedules/**`,
          `${API}/projects/*/deploy_tokens/**`,
          `${API}/groups/*/deploy_tokens/**`,
          `${API}/projects/*/access_tokens/**`,
          `${API}/groups/*/access_tokens/**`,
          `${API}/projects/*/cluster_agents/**`,
          `${API}/projects/*/hooks/**`,
          `${API}/groups/*/hooks/**`,
          `${API}/projects/*/integrations/**`,
          `${API}/projects/*/remote_mirrors/**`,
          `${API}/runners/**`,
        ],
        note: "variables, secure files, tokens, hooks, integrations and mirrors hand back secrets",
      },
      { action: "approve", paths: ["/api/graphql"], note: "GraphQL requests, since a query can read CI/CD variable values" },
      { action: "deny", paths: ["/api/graphql"], body: "graphql-mutation", note: "GraphQL requests that are not plainly a query" },
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
      {
        action: "deny",
        methods: WRITES,
        paths: [`${API}/projects/*/protected_branches/**`, `${API}/projects/*/protected_tags/**`, `${API}/projects/*/protected_environments/**`, `${API}/groups/*/protected_environments/**`],
        note: "protected branches, tags and environments decide who may push and deploy",
      },
      { action: "deny", methods: WRITES, paths: [`${API}/projects/*/transfer`, `${API}/groups/*/transfer`], note: "transfers a project or group away" },
      {
        action: "deny",
        methods: WRITES,
        paths: [`${API}/projects/*/remote_mirrors/**`, `${API}/projects/*/integrations/**`, `${API}/projects/*/services/**`, `${API}/groups/*/integrations/**`],
        note: "push mirrors and integrations send code and events elsewhere",
      },
      { action: "deny", methods: WRITES, paths: [`${API}/user/emails/**`], note: "account email addresses reset the password" },
      {
        action: "deny",
        methods: ["PUT", "PATCH", "DELETE"],
        paths: [`${API}/projects/*`, `${API}/groups/*`],
        note: "changes a project's or group's settings, which set its visibility and access, or deletes it",
      },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "GITLAB_TOKEN",
  check: { method: "GET", path: `${API}/personal_access_tokens/self` },
  fields: { key: { label: "Access token", pattern: "^glpat-" } },
  prefixes: ["glpat-"],
}
