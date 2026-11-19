import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { planetscale } from "./planetscale.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(planetscale.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(planetscale.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://api.planetscale.com/v1"
const BRANCH = `${API}/organizations/acme/databases/db/branches/main`

describe("planetscale", () => {
  it("sends the token as <id>:<token>, with no scheme", () => {
    expect(planetscale.injection).toEqual({ in: "header", name: "Authorization", format: "{username}:{password}" })
  })

  it("reaches its API over https, and nothing that looks like it or lies outside /v1", () => {
    expect(reaches("GET", `${API}/organizations`)).toBe(true)
    expect(reaches("GET", "https://api.planetscale.com.evil.test/v1/organizations")).toBe(false)
    expect(reaches("GET", "http://api.planetscale.com/v1/organizations")).toBe(false)
    expect(reaches("GET", "https://api.planetscale.com/v2/organizations")).toBe(false)
  })

  it("lets reads through", () => {
    expectAll([
      ["GET", `${API}/organizations/acme/databases`, "allow"],
      ["GET", `${BRANCH}/schema`, "allow"],
    ])
  })

  it("holds passwords, roles, billed changes and deploy requests for approval", () => {
    expectAll([
      ["POST", `${BRANCH}/passwords`, "approve"],
      ["POST", `${BRANCH}/passwords/p1/renew`, "approve"],
      ["POST", `${BRANCH}/roles`, "approve"],
      ["POST", `${API}/organizations/acme/databases`, "approve"],
      ["PUT", `${BRANCH}/resizes`, "approve"],
      ["POST", `${API}/organizations/acme/databases/db/deploy-requests`, "approve"],
    ])
  })

  it("refuses tokens, members, SSO, webhooks, payment methods and deleting a database", () => {
    expectAll([
      ["POST", `${API}/organizations/acme/service-tokens`, "deny"],
      ["POST", `${API}/organizations/acme/oauth-applications/app/token`, "deny"],
      ["PATCH", `${API}/organizations/acme/members/m1`, "deny"],
      ["POST", `${API}/organizations/acme/invitations`, "deny"],
      ["POST", `${API}/organizations/acme/teams/t/members`, "deny"],
      ["POST", `${API}/organizations/acme/sso/configure`, "deny"],
      ["POST", `${API}/organizations/acme/databases/db/webhooks`, "deny"],
      ["DELETE", `${API}/organizations/acme/billing/payment-method`, "deny"],
      ["DELETE", `${API}/organizations/acme/databases/db`, "deny"],
      ["POST", `${API}/organizations/acme/Service-Tokens`, "deny"],
    ])
  })
})
