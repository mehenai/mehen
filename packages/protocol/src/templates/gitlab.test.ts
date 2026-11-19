import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { gitlab } from "./gitlab.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(gitlab.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(gitlab.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://gitlab.com/api/v4"

describe("gitlab", () => {
  it("sends the token in PRIVATE-TOKEN", () => {
    expect(gitlab.injection).toEqual({ in: "header", name: "PRIVATE-TOKEN", format: "{key}" })
  })

  it("reaches the REST and GraphQL APIs on gitlab.com over https, and nothing else", () => {
    expect(reaches("GET", `${API}/projects/42`)).toBe(true)
    expect(reaches("POST", "https://gitlab.com/api/graphql")).toBe(true)
    expect(reaches("GET", "https://gitlab.com.evil.test/api/v4/projects/42")).toBe(false)
    expect(reaches("GET", "http://gitlab.com/api/v4/projects/42")).toBe(false)
    expect(reaches("GET", "https://gitlab.com/acme/app.git/info/refs")).toBe(false)
    expect(reaches("GET", "https://gitlab.example.com/api/v4/projects/42")).toBe(false)
    expect(reaches("GET", `${API}/projects/acme%2Fapp`)).toBe(false)
  })

  it("lets reads through, but not CI/CD variables or secure files", () => {
    expectAll([
      ["GET", `${API}/projects/42/merge_requests?state=opened`, "allow"],
      ["GET", `${API}/projects/42/pipelines`, "allow"],
      ["GET", `${API}/personal_access_tokens/self`, "allow"],
      ["GET", `${API}/projects/42/variables`, "approve"],
      ["GET", `${API}/groups/7/variables/TOKEN`, "approve"],
      ["GET", `${API}/projects/42/secure_files/1/download`, "approve"],
    ])
  })

  it("holds every write and every GraphQL request for approval", () => {
    expectAll([
      ["POST", `${API}/projects/42/issues`, "approve"],
      ["POST", `${API}/projects/42/merge_requests/1/notes`, "approve"],
      ["PUT", `${API}/projects/42/variables/TOKEN`, "approve"],
    ])
    expect(decide("POST", "https://gitlab.com/api/graphql", { query: "query { currentUser { username } }" })).toBe("approve")
  })

  it("refuses webhooks, keys, tokens, runners, members, transfers, mirrors, integrations, emails and deletes", () => {
    expectAll([
      ["POST", `${API}/projects/42/hooks`, "deny"],
      ["POST", `${API}/groups/7/hooks`, "deny"],
      ["POST", `${API}/user/keys`, "deny"],
      ["POST", `${API}/projects/42/deploy_keys`, "deny"],
      ["POST", `${API}/user/personal_access_tokens`, "deny"],
      ["POST", `${API}/personal_access_tokens/self/rotate`, "deny"],
      ["POST", `${API}/projects/42/access_tokens`, "deny"],
      ["POST", `${API}/groups/7/deploy_tokens`, "deny"],
      ["POST", `${API}/projects/42/triggers`, "deny"],
      ["POST", `${API}/user/runners`, "deny"],
      ["POST", `${API}/projects/42/members`, "deny"],
      ["POST", `${API}/groups/7/invitations`, "deny"],
      ["POST", `${API}/projects/42/share`, "deny"],
      ["PUT", `${API}/projects/42/access_requests/9/approve`, "deny"],
      ["PUT", `${API}/projects/42/transfer`, "deny"],
      ["POST", `${API}/projects/42/remote_mirrors`, "deny"],
      ["PUT", `${API}/projects/42/integrations/slack`, "deny"],
      ["POST", `${API}/user/emails`, "deny"],
      ["DELETE", `${API}/projects/42`, "deny"],
      ["POST", `${API}/projects/42/%68ooks`, "deny"],
      ["POST", `${API}/projects/42/Hooks`, "deny"],
    ])
  })
})
