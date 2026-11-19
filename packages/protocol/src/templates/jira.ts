import type { Template } from "../templates.ts"
import { ALLOW_READS, WRITES } from "./shared.ts"

const REST = "/ex/jira/*/rest"

// A Jira Cloud API token with scopes, which Atlassian serves only through
// its gateway, api.atlassian.com/ex/jira/<cloud id>, with the account
// email and the token as HTTP Basic credentials. A token without scopes
// works only at <site>.atlassian.net, a host that depends on the site, so
// it is not bound. Without a human: reads and JQL searches. Creating,
// editing and moving issues, comments and everything else need an
// approval. Webhooks, users, groups, project roles, permission schemes,
// app installs and deleting a project are refused.
// https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/
export const jira: Template = {
  id: "jira",
  displayName: "Jira API token with scopes",
  kind: "basic-auth",
  category: "productivity",
  docsUrl: "https://id.atlassian.com/manage-profile/security/api-tokens",
  binding: { hosts: ["api.atlassian.com"], paths: [`${REST}/**`] },
  injection: { in: "basic", username: "username", password: "password" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "allow", methods: ["POST"], paths: [`${REST}/api/3/search/jql`, `${REST}/api/3/search/approximate-count`, `${REST}/api/3/issue/bulkfetch`], note: "JQL searches and bulk issue reads" },
      { action: "deny", methods: WRITES, paths: [`${REST}/api/3/webhook/**`, `${REST}/webhooks/**`], note: "webhooks send issue events elsewhere" },
      {
        action: "deny",
        methods: WRITES,
        paths: [`${REST}/api/3/user/**`, `${REST}/api/3/group/**`, `${REST}/api/3/project/*/role/**`, `${REST}/api/3/permissionscheme/**`, `${REST}/api/3/project/*/permissionscheme/**`],
        note: "users, groups, roles and permission schemes give someone else access",
      },
      { action: "deny", methods: WRITES, paths: [`${REST}/atlassian-connect/**`, `${REST}/plugins/**`], note: "installs or changes apps, which receive events and tokens" },
      { action: "deny", methods: ["DELETE"], paths: [`${REST}/api/3/project/*`], note: "deletes a project and its issues" },
    ],
  },
  ceiling: "relay",
  fields: {
    username: { label: "Atlassian account email" },
    password: { label: "API token with scopes", hint: "Atlassian sends a token with scopes through api.atlassian.com; a token without scopes will not work here." },
  },
  setup: {
    title: "In your Atlassian account",
    steps: [
      { title: "Open API tokens", body: "Account settings, then Security, then API tokens.", docs: true },
      { title: "Give your account email", body: "The email address of the Atlassian account the token belongs to.", field: "username" },
      {
        title: "Create an API token with scopes",
        body: "Choose Create API token with scopes, pick Jira, and tick the read scopes the agent needs, adding write scopes only if it is to change issues. Agents call https://api.atlassian.com/ex/jira/<cloud id>/rest/api/3/...; the cloud id is at https://<site>.atlassian.net/_edge/tenant_info.",
        field: "password",
      },
    ],
  },
}
