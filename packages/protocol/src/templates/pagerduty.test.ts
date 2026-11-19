import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { pagerduty } from "./pagerduty.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(pagerduty.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(pagerduty.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://api.pagerduty.com"

describe("pagerduty", () => {
  it("sends the key as Token token=<key>", () => {
    expect(pagerduty.injection).toEqual({ in: "header", name: "Authorization", format: "Token token={key}" })
  })

  it("reaches the REST API over https, and neither a look-alike nor the Events API", () => {
    expect(reaches("GET", `${API}/incidents`)).toBe(true)
    expect(reaches("GET", "https://api.pagerduty.com.evil.test/incidents")).toBe(false)
    expect(reaches("GET", "http://api.pagerduty.com/incidents")).toBe(false)
    expect(reaches("POST", "https://events.pagerduty.com/v2/enqueue")).toBe(false)
  })

  it("lets reads through and holds incident changes for approval", () => {
    expectAll([
      ["GET", `${API}/incidents?statuses[]=triggered`, "allow"],
      ["GET", `${API}/oncalls`, "allow"],
      ["POST", `${API}/incidents`, "approve"],
      ["PUT", `${API}/incidents/P1`, "approve"],
      ["POST", `${API}/incidents/P1/status_updates`, "approve"],
      ["POST", `${API}/incidents/P1/responder_requests`, "approve"],
    ])
  })

  it("refuses users, team membership, webhooks, extensions and OAuth delegations", () => {
    expectAll([
      ["POST", `${API}/users`, "deny"],
      ["PUT", `${API}/users/U1`, "deny"],
      ["POST", `${API}/users/U1/contact_methods`, "deny"],
      ["POST", `${API}/users/U1/notification_rules`, "deny"],
      ["PUT", `${API}/teams/T1/users/U1`, "deny"],
      ["POST", `${API}/webhook_subscriptions`, "deny"],
      ["POST", `${API}/extensions`, "deny"],
      ["DELETE", `${API}/oauth_delegations`, "deny"],
      ["POST", `${API}/Webhook_Subscriptions`, "deny"],
    ])
  })
})
