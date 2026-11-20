import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { pagerduty } from "./pagerduty.ts"
import { underBroadAllow } from "../../test/template-policy.ts"

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
      ["GET", `${API}/incidents?statuses[]=triggered`, "approve"],
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

describe("pagerduty review fixes", () => {
  it("lets the named reads through and holds every other read", () => {
    expectAll([
      ["GET", `${API}/incidents/P1/notes`, "approve"],
      ["GET", `${API}/schedules/S1`, "allow"],
      ["GET", `${API}/services`, "approve"],
      ["GET", `${API}/mehen-unlisted`, "approve"],
    ])
  })

  it("holds orchestration, ruleset, integration and runner reads that return routing or integration keys whatever the item's policy says", () => {
    for (const path of [
      "/event_orchestrations",
      "/event_orchestrations/E1",
      "/event_orchestrations/E1/integrations",
      "/event_orchestrations/E1/integrations/I1",
      "/services/S1/integrations/I1",
      "/rulesets",
      "/rulesets/R1",
      "/automation_actions/runners/U1",
      "/extensions/X1",
      "/webhook_subscriptions/W1",
    ]) expect({ path, action: underBroadAllow(pagerduty, "GET", `${API}${path}`) }).toEqual({ path, action: "approve" })
  })

  it("refuses creating integrations and automation runners", () => {
    expectAll([
      ["POST", `${API}/services/S1/integrations`, "deny"],
      ["PUT", `${API}/services/S1/integrations/I1`, "deny"],
      ["POST", `${API}/event_orchestrations/E1/integrations`, "deny"],
      ["POST", `${API}/automation_actions/runners`, "deny"],
    ])
  })
})

describe("pagerduty second review fixes", () => {
  it("holds log entries, which return a channel's service_key with include[]=channels, whatever the item's policy says", () => {
    for (const path of [
      "/log_entries?include[]=channels",
      "/log_entries/L1?include[]=channels",
      "/incidents/P1/log_entries?include[]=channels",
      "/log_entries",
      "/incidents/P1/log_entries",
    ]) {
      expect({ path, policy: decide("GET", `${API}${path}`) }).toEqual({ path, policy: "approve" })
      expect({ path, relay: underBroadAllow(pagerduty, "GET", `${API}${path}`) }).toEqual({ path, relay: "approve" })
    }
  })

  it("holds services, which return integration keys with include[]=integrations, whatever the item's policy says", () => {
    for (const path of [
      "/services",
      "/services?include[]=integrations",
      "/services/S1",
      "/services/S1?include[]=integrations",
    ]) {
      expect({ path, policy: decide("GET", `${API}${path}`) }).toEqual({ path, policy: "approve" })
      expect({ path, relay: underBroadAllow(pagerduty, "GET", `${API}${path}`) }).toEqual({ path, relay: "approve" })
    }
  })

  it("refuses creating an event orchestration, which mints an integration with a routing key", () => {
    for (const path of [
      "/event_orchestrations",
    ]) {
      expect({ path, policy: decide("POST", `${API}${path}`) }).toEqual({ path, policy: "deny" })
      expect({ path, relay: underBroadAllow(pagerduty, "POST", `${API}${path}`) }).toEqual({ path, relay: "deny" })
    }
  })
})

describe("pagerduty third review fixes", () => {
  it("holds incident reads, which return a trigger log entry's service_key with include[]=first_trigger_log_entries, whatever the item's policy says", () => {
    for (const path of [
      "/incidents",
      "/incidents?include[]=first_trigger_log_entries",
      "/incidents/P1",
      "/incidents/P1?include[]=first_trigger_log_entries",
    ]) {
      expect({ path, policy: decide("GET", `${API}${path}`) }).toEqual({ path, policy: "approve" })
      expect({ path, relay: underBroadAllow(pagerduty, "GET", `${API}${path}`) }).toEqual({ path, relay: "approve" })
    }
  })

  it("asks for an incident's notes, alerts and related incidents too", () => {
    expectAll([
      ["GET", `${API}/incidents/P1/notes`, "approve"],
      ["GET", `${API}/incidents/P1/alerts`, "approve"],
      ["GET", `${API}/incidents/P1/related_incidents`, "approve"],
    ])
  })
})

describe("pagerduty fourth review fixes", () => {
  const held = (path: string) => {
    expect({ path, policy: decide("GET", `${API}${path}`), relay: underBroadAllow(pagerduty, "GET", `${API}${path}`) }).toEqual({ path, policy: "approve", relay: "approve" })
  }

  it("holds every incident sub-read, alerts with include[]=first_trigger_log_entries among them, whatever the item's policy says", () => {
    for (const path of ["/incidents/P1/alerts?include[]=first_trigger_log_entries", "/incidents/P1/alerts", "/incidents/P1/alerts/A1", "/incidents/P1/notes", "/incidents/P1/related_incidents"]) held(path)
  })

  it("holds a user's details, which with include[]=calendar_urls return bearer calendar feed URLs, whatever the item's policy says", () => {
    for (const path of ["/users/U1?include[]=calendar_urls", "/users/U1", "/users/me"]) held(path)
  })

  it("still lets the user list, schedules, escalation policies and maintenance windows through, whose include[] expands only references", () => {
    for (const path of ["/users?include[]=contact_methods", "/schedules/S1", "/escalation_policies?include[]=services", "/maintenance_windows?include[]=services", "/oncalls?include[]=users"]) {
      expect({ path, policy: decide("GET", `${API}${path}`) }).toEqual({ path, policy: "allow" })
    }
  })
})
