import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { jira } from "./jira.ts"
import { underBroadAllow } from "../../test/template-policy.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(jira.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(jira.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest"

describe("jira", () => {
  it("reaches Jira through the Atlassian gateway over https, and neither Confluence, a look-alike nor a site host", () => {
    expect(reaches("GET", `${API}/api/3/myself`)).toBe(true)
    expect(reaches("GET", "https://api.atlassian.com.evil.test/ex/jira/c/rest/api/3/myself")).toBe(false)
    expect(reaches("GET", "http://api.atlassian.com/ex/jira/c/rest/api/3/myself")).toBe(false)
    expect(reaches("GET", "https://api.atlassian.com/ex/confluence/c/wiki/rest/api/space")).toBe(false)
    expect(reaches("GET", "https://acme.atlassian.net/rest/api/3/myself")).toBe(false)
  })

  it("lets reads and JQL searches through", () => {
    expectAll([
      ["GET", `${API}/api/3/issue/ACME-1`, "allow"],
      ["POST", `${API}/api/3/search/jql`, "allow"],
      ["POST", `${API}/api/3/issue/bulkfetch`, "allow"],
    ])
  })

  it("holds issue changes for approval", () => {
    expectAll([
      ["POST", `${API}/api/3/issue`, "approve"],
      ["POST", `${API}/api/3/issue/ACME-1/comment`, "approve"],
      ["POST", `${API}/api/3/issue/ACME-1/transitions`, "approve"],
    ])
  })

  it("refuses webhooks, users, groups, roles, permission schemes, apps and deleting a project", () => {
    expectAll([
      ["POST", `${API}/api/3/webhook`, "deny"],
      ["POST", `${API}/api/3/user`, "deny"],
      ["POST", `${API}/api/3/group/user?groupId=g`, "deny"],
      ["POST", `${API}/api/3/project/ACME/role/10002`, "deny"],
      ["PUT", `${API}/api/3/project/ACME/permissionscheme`, "deny"],
      ["POST", `${API}/api/3/permissionscheme`, "deny"],
      ["DELETE", `${API}/api/3/project/ACME`, "deny"],
      ["POST", `${API}/api/3/Webhook`, "deny"],
    ])
  })
})

describe("jira review fixes", () => {
  it("binds the platform REST API v3 only: not v2, the webhooks API, apps or Service Management", () => {
    expect(reaches("GET", `${API}/api/3/issue/ACME-1`)).toBe(true)
    for (const path of ["/api/2/issue/ACME-1", "/api/latest/issue/ACME-1", "/webhooks/1.0/webhook", "/atlassian-connect/1/app/module/dynamic", "/plugins/1.0/", "/servicedeskapi/servicedesk", "/agile/1.0/board"]) {
      expect({ path, reaches: reaches("GET", `${API}${path}`) }).toEqual({ path, reaches: false })
    }
  })

  it("says the binding covers every Jira site the token can reach", () => {
    expect(jira.setup?.steps.map((s) => s.body).join(" ")).toContain("every Jira site")
  })

  it("lets the named reads through and holds every other read", () => {
    expectAll([
      ["GET", `${API}/api/3/myself`, "allow"],
      ["GET", `${API}/api/3/issue/ACME-1/comment`, "allow"],
      ["GET", `${API}/api/3/project/ACME/versions`, "allow"],
      ["GET", `${API}/api/3/mehen-unlisted`, "approve"],
    ])
  })

  it("refuses role actors, issue security schemes and filter permissions", () => {
    expectAll([
      ["POST", `${API}/api/3/role/10002/actors`, "deny"],
      ["DELETE", `${API}/api/3/role/10002/actors`, "deny"],
      ["PUT", `${API}/api/3/project/ACME/role/10002`, "deny"],
      ["POST", `${API}/api/3/issuesecurityschemes`, "deny"],
      ["PUT", `${API}/api/3/issuesecurityschemes/1/level`, "deny"],
      ["POST", `${API}/api/3/filter/10000/permission`, "deny"],
      ["DELETE", `${API}/api/3/filter/10000/permission/1`, "deny"],
    ])
  })
})
