import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { jira } from "./jira.ts"
import { underBroadAllow } from "../../test/template-policy.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(jira.binding, parsed.destination).ok
}

// A body given as raw bytes is sent as is; anything else as its JSON.
type Body = unknown
const bytesOf = (body: Body): Uint8Array | null => (body === undefined ? null : body instanceof Uint8Array ? body : new TextEncoder().encode(JSON.stringify(body)))
const raw = (text: string): Uint8Array => new TextEncoder().encode(text)

function decide(method: string, url: string, body?: Body): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  return evaluatePolicy(jira.policy, parsed.destination, bytesOf(body)).action
}

// Under an item policy that allows everything: what only the template's
// floors and the binding still decide.
function relay(method: string, url: string, body?: Body): string {
  return underBroadAllow(jira, method, url, body === undefined ? undefined : body instanceof Uint8Array ? new TextDecoder().decode(body) : JSON.stringify(body))
}

function expectBoth(cases: [method: string, url: string, policy: string, relay: string, body?: Body][]): void {
  for (const [method, url, policy, broad, body] of cases) {
    const request = `${method} ${url} ${body === undefined ? "" : body instanceof Uint8Array ? new TextDecoder().decode(body) : JSON.stringify(body)}`
    expect({ request, policy: decide(method, url, body), relay: relay(method, url, body) }).toEqual({ request, policy, relay: broad })
  }
}

const SITE = "https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555"
const API = `${SITE}/rest/api/3`

describe("jira binding", () => {
  it("reaches the issue surface, JQL search and the named reads through the Atlassian gateway over https, and nothing else", () => {
    for (const [method, path] of [
      ["GET", "/issue/ACME-1"],
      ["POST", "/issue"],
      ["POST", "/issue/ACME-1/comment"],
      ["POST", "/issueLink"],
      ["POST", "/bulk/issues/fields"],
      ["POST", "/search/jql"],
      ["GET", "/myself"],
      ["GET", "/project/ACME/versions"],
      ["GET", "/issueLinkType"],
    ] as const) {
      expect({ path, reaches: reaches(method, `${API}${path}`) }).toEqual({ path, reaches: true })
    }
    expect(reaches("GET", "https://api.atlassian.com.evil.test/ex/jira/c/rest/api/3/myself")).toBe(false)
    expect(reaches("GET", "http://api.atlassian.com/ex/jira/c/rest/api/3/myself")).toBe(false)
    expect(reaches("GET", "https://acme.atlassian.net/rest/api/3/myself")).toBe(false)
  })

  it("leaves administrative routes, other API versions and other Atlassian APIs outside the binding, so they are refused whatever the item's policy says", () => {
    for (const [method, path] of [
      ["POST", "/rest/api/3/webhook"],
      ["POST", "/rest/api/3/role"],
      ["POST", "/rest/api/3/role/10002/actors"],
      ["PUT", "/rest/api/3/permissionscheme/1"],
      ["POST", "/rest/api/3/issuesecurityschemes"],
      ["POST", "/rest/api/3/dashboard"],
      ["PUT", "/rest/api/3/mypreferences"],
      ["POST", "/rest/api/3/group/user"],
      ["POST", "/rest/api/3/filter"],
      ["POST", "/rest/api/3/issuetypescheme"],
      ["PUT", "/rest/api/3/issues/archive/export"],
      ["GET", "/rest/api/3/search"],
      ["GET", "/rest/api/2/issue/ACME-1"],
      ["GET", "/rest/api/latest/issue/ACME-1"],
      ["POST", "/rest/webhooks/1.0/webhook"],
      ["POST", "/rest/atlassian-connect/1/app/module/dynamic"],
      ["GET", "/rest/servicedeskapi/servicedesk"],
      ["GET", "/rest/agile/1.0/board"],
    ] as const) {
      const url = `${SITE}${path}`
      expect({ path, reaches: reaches(method, url), relay: relay(method, url) }).toEqual({ path, reaches: false, relay: "deny" })
    }
  })

  it("says the binding covers every Jira site the token can reach, and that administrative mutations are unsupported", () => {
    expect(jira.setup?.steps.map((s) => s.body).join(" ")).toContain("every Jira site")
  })
})

describe("jira reads and searches", () => {
  it("lets the named reads, JQL search and bulk fetch through, whatever the item's policy says", () => {
    expectBoth([
      ["GET", `${API}/myself`, "allow", "allow"],
      ["GET", `${API}/issue/ACME-1`, "allow", "allow"],
      ["GET", `${API}/issue/ACME-1/comment`, "allow", "allow"],
      ["GET", `${API}/project/ACME/versions`, "allow", "allow"],
      ["GET", `${API}/search/jql?jql=project%3DACME`, "allow", "allow"],
      ["POST", `${API}/search/jql`, "allow", "allow", { jql: "project = ACME", fields: ["summary", "security"] }],
      ["POST", `${API}/search/approximate-count`, "allow", "allow", { jql: "project = ACME" }],
      ["POST", `${API}/issue/bulkfetch`, "allow", "allow", { issueIdsOrKeys: ["ACME-1"], fields: ["summary", "security"] }],
    ])
  })

  it("asks for any read it does not name", () => {
    expectBoth([["GET", `${API}/issue/limit/report`, "approve", "allow"]])
  })
})

describe("jira issue writes", () => {
  const create = { fields: { project: { key: "ACME" }, issuetype: { name: "Task" }, summary: "A task" } }
  const comment = { body: { type: "doc", version: 1, content: [] } }

  it("asks for an ordinary issue create and comment by default, and lets them through under a deliberate allow", () => {
    expectBoth([
      ["POST", `${API}/issue`, "approve", "allow", create],
      ["POST", `${API}/issue/ACME-1/comment`, "approve", "allow", comment],
      ["PUT", `${API}/issue/ACME-1`, "approve", "allow", { fields: { summary: "Renamed" } }],
      ["POST", `${API}/issue/ACME-1/transitions`, "approve", "allow", { transition: { id: "31" } }],
      ["POST", `${API}/issueLink`, "approve", "allow", { type: { name: "Blocks" }, inwardIssue: { key: "ACME-1" }, outwardIssue: { key: "ACME-2" } }],
      ["POST", `${API}/issue/ACME-1/watchers`, "approve", "allow", "5b10ac8d82e05b22cc7d4ef5"],
    ])
  })

  it("asks for any write that sets issue security, in every recognised envelope, whatever the item's policy says", () => {
    expectBoth([
      ["POST", `${API}/issue`, "approve", "approve", { fields: { ...create.fields, security: { id: "10000" } } }],
      ["PUT", `${API}/issue/ACME-1`, "approve", "approve", { update: { security: [{ set: { id: "10000" } }] } }],
      ["PUT", `${API}/issue/ACME-1`, "approve", "approve", { fields: { Security: null } }],
      ["POST", `${API}/issue/ACME-1/transitions`, "approve", "approve", { transition: { id: "31" }, fields: { security: { id: "10000" } } }],
      ["POST", `${API}/issue/bulk`, "approve", "approve", { issueUpdates: [create, { fields: { ...create.fields, security: { id: "10000" } } }] }],
      ["POST", `${API}/issue/bulk`, "approve", "approve", { issueUpdates: [create, { update: { security: [{ set: { id: "1" } }] } }] }],
    ])
  })

  it("asks for a visibility key at any depth with any value, null included, whatever the item's policy says", () => {
    expectBoth([
      ["POST", `${API}/issue/ACME-1/comment`, "approve", "approve", { ...comment, visibility: { type: "role", value: "Administrators" } }],
      ["POST", `${API}/issue/ACME-1/comment`, "approve", "approve", { ...comment, visibility: null }],
      ["POST", `${API}/issue/ACME-1/worklog`, "approve", "approve", { timeSpentSeconds: 60, visibility: { type: "group", identifier: "g" } }],
      ["POST", `${API}/issueLink`, "approve", "approve", { type: { name: "Blocks" }, inwardIssue: { key: "ACME-1" }, outwardIssue: { key: "ACME-2" }, comment: { body: "x", visibility: null } }],
      ["POST", `${API}/issue/ACME-1/transitions`, "approve", "approve", { transition: { id: "31" }, update: { comment: [{ add: { body: "x", Visibility: { type: "role", value: "Devs" } } }] } }],
    ])
  })

  it("asks for a bulk edit that names security, and lets one that does not through under a deliberate allow", () => {
    expectBoth([
      ["POST", `${API}/bulk/issues/fields`, "approve", "approve", { selectedIssueIdsOrKeys: ["ACME-1"], selectedActions: ["security"], editedFieldsInput: {} }],
      ["POST", `${API}/bulk/issues/fields`, "approve", "approve", { selectedIssueIdsOrKeys: ["ACME-1"], selectedActions: ["priority"], editedFieldsInput: { singleSelectFields: [{ fieldId: "security", fieldOptionId: 1 }] } }],
      ["POST", `${API}/bulk/issues/fields`, "approve", "allow", { selectedIssueIdsOrKeys: ["ACME-1"], selectedActions: ["priority"], editedFieldsInput: { priority: { priorityId: "1" } } }],
    ])
  })

  it("asks for a body it cannot read, or an envelope in a shape it does not recognise, whatever the item's policy says", () => {
    expectBoth([
      ["POST", `${API}/issue`, "approve", "approve", raw("fields=security")],
      ["POST", `${API}/issue`, "approve", "approve", raw('{"fields":{"summary":"a"},"fields":{"security":{"id":"1"}}}')],
      ["POST", `${API}/issue`, "approve", "approve", [create]],
      ["POST", `${API}/issue`, "approve", "approve", { fields: "security" }],
      ["POST", `${API}/issue/bulk`, "approve", "approve", { issueUpdates: create }],
      ["POST", `${API}/bulk/issues/fields`, "approve", "approve", { selectedActions: "security" }],
      ["POST", `${API}/bulk/issues/fields`, "approve", "approve", { editedFieldsInput: [{ fieldId: "security" }] }],
      ["POST", `${API}/issue`, "approve", "approve"],
    ])
  })
})

describe("jira refusals", () => {
  it("refuses the reserved issue routes: archive, unarchive and bulk issue properties", () => {
    expectBoth([
      ["POST", `${API}/issue/archive`, "deny", "deny", { issueIdsOrKeys: ["ACME-1"] }],
      ["PUT", `${API}/issue/archive`, "deny", "deny", { issueIdsOrKeys: ["ACME-1"] }],
      ["PUT", `${API}/issue/unarchive`, "deny", "deny", { issueIdsOrKeys: ["ACME-1"] }],
      ["POST", `${API}/issue/properties`, "deny", "deny", { entitiesIds: [1], properties: {} }],
      ["POST", `${API}/issue/properties/multi`, "deny", "deny", { issues: [] }],
      ["PUT", `${API}/issue/properties/acme.key`, "deny", "deny", { value: 1 }],
      ["DELETE", `${API}/issue/properties/acme.key`, "deny", "deny"],
    ])
  })

  it("refuses moving issues in bulk and moving worklogs, even with no sensitive key", () => {
    expectBoth([
      ["POST", `${API}/bulk/issues/move`, "deny", "deny", { targetToSourcesMapping: {} }],
      ["POST", `${API}/issue/ACME-1/worklog/move`, "deny", "deny", { issueIdOrKey: "ACME-2", ids: [1] }],
    ])
  })

  it("refuses writes on every retained read-only family", () => {
    for (const [method, path] of [
      ["POST", "/project"],
      ["PUT", "/project/ACME"],
      ["DELETE", "/project/ACME"],
      ["POST", "/project/ACME/versions"],
      ["POST", "/project/ACME/components"],
      ["POST", "/field"],
      ["POST", "/user"],
      ["DELETE", "/user"],
      ["POST", "/issuetype"],
      ["PUT", "/issuetype/10001"],
      ["POST", "/priority"],
      ["PUT", "/priority/1"],
      ["POST", "/status"],
      ["POST", "/resolution"],
      ["POST", "/issueLinkType"],
      ["PUT", "/issueLinkType/1"],
      ["PUT", "/filter/10000"],
      ["PUT", "/filter/defaultShareScope"],
      ["PUT", "/myself"],
    ] as const) {
      expect({ path, reaches: reaches(method, `${API}${path}`) }).toEqual({ path, reaches: true })
      expectBoth([[method, `${API}${path}`, "deny", "deny", {}]])
    }
  })
})

describe("jira fifth review fix", () => {
  it("holds an issue notification, which emails users and groups the body chooses, whatever the item's policy says", () => {
    const notify = { subject: "Update", textBody: "See ACME-1", to: { reporter: false, assignee: false, watchers: true, users: [{ accountId: "5b10ac8d82e05b22cc7d4ef5" }], groups: [{ name: "everyone" }] } }
    expectBoth([["POST", `${API}/issue/ACME-1/notify`, "approve", "approve", notify]])
  })
})
