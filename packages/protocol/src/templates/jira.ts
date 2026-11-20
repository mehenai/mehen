import type { Template } from "../templates.ts"
import { NAMED_READS, WRITES } from "./shared.ts"

const API = "/ex/jira/*/rest/api/3"

// The read-only families the binding keeps for the named reads. Every
// write on them is refused: they are where Jira's administrative
// mutations live (creating a project, a field, a user, an issue type).
const READ_ONLY = [
  `${API}/myself`,
  `${API}/serverInfo`,
  `${API}/project`,
  `${API}/project/search`,
  `${API}/project/*`,
  `${API}/project/*/statuses`,
  `${API}/project/*/components`,
  `${API}/project/*/versions`,
  `${API}/issuetype`,
  `${API}/issuetype/*`,
  `${API}/issueLinkType`,
  `${API}/issueLinkType/*`,
  `${API}/field`,
  `${API}/priority`,
  `${API}/priority/*`,
  `${API}/status`,
  `${API}/status/*`,
  `${API}/resolution`,
  `${API}/resolution/*`,
  `${API}/user`,
  `${API}/user/search`,
  `${API}/user/assignable/search`,
  `${API}/filter/*`,
  `${API}/bulk/queue/*`,
]

// The issue surface: issues and everything under them, issue links and
// bulk issue operations.
const ISSUE_SURFACE = [`${API}/issue/**`, `${API}/issueLink/**`, `${API}/bulk/issues/**`]

// A Jira Cloud API token with scopes, which Atlassian serves only through
// its gateway, api.atlassian.com/ex/jira/<cloud id>, with the account
// email and the token as HTTP Basic credentials. A token without scopes
// works only at <site>.atlassian.net, a host that depends on the site, so
// it is not bound. The binding names any cloud id, so it covers every Jira
// site the token can reach; the token's own scopes and the account's
// access decide which those are.
//
// The binding is the platform REST API v3's issue surface, JQL search and
// the named reads, nothing more. Administrative mutations are unsupported:
// their routes are outside the binding or explicitly denied on retained
// read-only paths. Without a human: the named reads, JQL searches and bulk
// issue fetches. Every other issue write asks. Archiving, unarchiving and
// bulk issue properties are refused, and so are moving issues in bulk and
// moving worklogs. An issue write that may change who can see an issue is
// held for a person even when the item's own policy allows writes: one
// that names the security field (in fields or update, a bulk create's
// issueUpdates, or a bulk edit), any visibility key, or that cannot be
// read (json-jira-access).
//
// Issue security can depend on assignee, reporter and user/group-picker
// fields. Changing those fields can change who can see an issue. Approving
// an edit, or authorising a rule or mandate covering future edits, accepts
// that effect; those field changes do not receive a separate mandatory
// approval.
// https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/
export const jira: Template = {
  id: "jira",
  displayName: "Jira API token with scopes",
  kind: "basic-auth",
  category: "productivity",
  docsUrl: "https://id.atlassian.com/manage-profile/security/api-tokens",
  binding: { hosts: ["api.atlassian.com"], paths: [...ISSUE_SURFACE, `${API}/search/jql`, `${API}/search/approximate-count`, ...READ_ONLY] },
  injection: { in: "basic", username: "username", password: "password" },
  policy: {
    default: "approve",
    rules: [
      NAMED_READS(READ_ONLY, "reads of projects, fields, issue types, users and filters"),
      NAMED_READS(
        [
          `${API}/issue/*`,
          `${API}/issue/*/comment/**`,
          `${API}/issue/*/changelog`,
          `${API}/issue/*/transitions`,
          `${API}/issue/*/worklog/**`,
          `${API}/issue/createmeta/**`,
          `${API}/issueLink/*`,
          `${API}/search/jql`,
        ],
        "reads of issues, their comments, changelogs, transitions and worklogs, and JQL searches",
      ),
      { action: "allow", methods: ["POST"], paths: [`${API}/search/jql`, `${API}/search/approximate-count`, `${API}/issue/bulkfetch`], note: "JQL searches and bulk issue reads" },
      { action: "deny", methods: WRITES, paths: READ_ONLY, note: "administrative changes to projects, fields, users, issue types and other shared settings" },
      { action: "deny", paths: [`${API}/issue/archive`, `${API}/issue/unarchive`, `${API}/issue/properties`, `${API}/issue/properties/**`], note: "archives issues, or sets properties on many issues at once" },
      { action: "deny", methods: WRITES, paths: [`${API}/bulk/issues/move`, `${API}/issue/*/worklog/move`], note: "moves issues or worklogs to another project or issue, whose security may differ" },
      {
        action: "approve",
        methods: ["POST", "PUT", "PATCH"],
        paths: ISSUE_SURFACE,
        body: "json-jira-access",
        note: "may change who can see an issue (its security level or a visibility restriction), or cannot be read",
      },
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
        body: "Choose Create API token with scopes, pick Jira, and tick the read scopes the agent needs, adding write scopes only if it is to change issues. Agents call https://api.atlassian.com/ex/jira/<cloud id>/rest/api/3/...; the cloud id is at https://<site>.atlassian.net/_edge/tenant_info. The credential may be used on every Jira site the token can reach, so limit the token's scopes and the account's access to the sites the agent needs. Administrative mutations are unsupported: their routes are outside the binding or explicitly denied on retained read-only paths.",
        field: "password",
      },
    ],
  },
}
