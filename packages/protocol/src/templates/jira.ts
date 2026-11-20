import type { Template } from "../templates.ts"
import { NAMED_READS, WRITES } from "./shared.ts"

const API = "/ex/jira/*/rest/api/3"

// A Jira Cloud API token with scopes, which Atlassian serves only through
// its gateway, api.atlassian.com/ex/jira/<cloud id>, with the account
// email and the token as HTTP Basic credentials. A token without scopes
// works only at <site>.atlassian.net, a host that depends on the site, so
// it is not bound. The binding names any cloud id, so it covers every Jira
// site the token can reach; the token's own scopes and the account's
// access decide which those are. It binds the platform REST API v3 only:
// v2, the webhooks API, app APIs and Service Management are outside it, so
// every refusal below holds for every version the binding admits.
// Without a human: the named reads (the account, issues and their
// comments, changelogs, transitions and worklogs, JQL searches, projects
// with their statuses, components and versions, issue types, fields,
// priorities, statuses, resolutions, users and filters). Every other read
// asks. Creating, editing and moving issues, comments and everything else
// need an approval. Webhooks, users, groups, project roles, global roles
// and their actors, permission schemes, issue security schemes, updating a
// project (its body can set the permission and issue security schemes, and
// no body rule can yet prove it does not), creating or updating a filter
// (its body takes share and edit permissions), the default share scope,
// filter permissions, a filter's owner, dashboards (their bodies take share
// and edit permissions), the user's preferences (user.default.share.private
// sets default filter sharing, and a path rule cannot select the key) and
// deleting a project, at once or asynchronously, are refused.
// https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/
export const jira: Template = {
  id: "jira",
  displayName: "Jira API token with scopes",
  kind: "basic-auth",
  category: "productivity",
  docsUrl: "https://id.atlassian.com/manage-profile/security/api-tokens",
  binding: { hosts: ["api.atlassian.com"], paths: [`${API}/**`] },
  injection: { in: "basic", username: "username", password: "password" },
  policy: {
    default: "approve",
    rules: [
      NAMED_READS(
        [
          `${API}/myself`,
          `${API}/serverInfo`,
          `${API}/issue/*`,
          `${API}/issue/*/comment/**`,
          `${API}/issue/*/changelog`,
          `${API}/issue/*/transitions`,
          `${API}/issue/*/worklog/**`,
          `${API}/issue/createmeta/**`,
          `${API}/search/jql`,
          `${API}/project`,
          `${API}/project/search`,
          `${API}/project/*`,
          `${API}/project/*/statuses`,
          `${API}/project/*/components`,
          `${API}/project/*/versions`,
          `${API}/issuetype/**`,
          `${API}/field`,
          `${API}/priority/**`,
          `${API}/status/**`,
          `${API}/resolution/**`,
          `${API}/user`,
          `${API}/user/search`,
          `${API}/filter/*`,
        ],
        "reads of issues, comments, projects, fields, users and filters",
      ),
      { action: "allow", methods: ["POST"], paths: [`${API}/search/jql`, `${API}/search/approximate-count`, `${API}/issue/bulkfetch`], note: "JQL searches and bulk issue reads" },
      { action: "deny", methods: WRITES, paths: [`${API}/webhook/**`], note: "webhooks send issue events elsewhere" },
      {
        action: "deny",
        methods: WRITES,
        paths: [
          `${API}/user/**`,
          `${API}/group/**`,
          `${API}/project/*/role/**`,
          `${API}/role/**`,
          `${API}/permissionscheme/**`,
          `${API}/project/*/permissionscheme/**`,
          `${API}/issuesecurityschemes/**`,
          `${API}/project/*/issuesecuritylevelscheme/**`,
          `${API}/filter/*/permission/**`,
        ],
        note: "users, groups, roles, permission and issue security schemes, and filter sharing give someone else access",
      },
      {
        action: "deny",
        methods: ["POST", "PUT"],
        paths: [`${API}/filter`, `${API}/filter/*`],
        note: "creates or updates a filter, whose body takes share and edit permissions, or sets the default share scope",
      },
      { action: "deny", methods: ["PUT"], paths: [`${API}/filter/*/owner`], note: "gives a filter, with its sharing, to someone else" },
      { action: "deny", methods: WRITES, paths: [`${API}/dashboard/**`], note: "creates, changes, copies or bulk-edits dashboards, whose bodies take share and edit permissions" },
      { action: "deny", methods: ["PUT", "DELETE"], paths: [`${API}/mypreferences`], note: "user preferences, among them default filter sharing" },
      { action: "deny", methods: ["PUT"], paths: [`${API}/project/*`], note: "updates a project, whose body can set its permission and issue security schemes" },
      { action: "deny", methods: ["DELETE"], paths: [`${API}/project/*`], note: "deletes a project and its issues" },
      { action: "deny", methods: ["POST"], paths: [`${API}/project/*/delete`], note: "deletes a project and its issues, asynchronously" },
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
        body: "Choose Create API token with scopes, pick Jira, and tick the read scopes the agent needs, adding write scopes only if it is to change issues. Agents call https://api.atlassian.com/ex/jira/<cloud id>/rest/api/3/...; the cloud id is at https://<site>.atlassian.net/_edge/tenant_info. The credential may be used on every Jira site the token can reach, so limit the token's scopes and the account's access to the sites the agent needs.",
        field: "password",
      },
    ],
  },
}
