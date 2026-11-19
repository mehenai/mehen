import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { sendgrid } from "./sendgrid.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(sendgrid.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(sendgrid.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://api.sendgrid.com/v3"
const EU = "https://api.eu.sendgrid.com/v3"

describe("sendgrid", () => {
  it("reaches the global and EU APIs over https, and nothing that looks like them or lies outside /v3", () => {
    expect(reaches("GET", `${API}/scopes`)).toBe(true)
    expect(reaches("GET", `${EU}/scopes`)).toBe(true)
    expect(reaches("GET", "https://api.sendgrid.com.evil.test/v3/scopes")).toBe(false)
    expect(reaches("GET", "http://api.sendgrid.com/v3/scopes")).toBe(false)
    expect(reaches("GET", "https://api.sendgrid.com/v2/scopes")).toBe(false)
  })

  it("lets reads through", () => {
    expectAll([
      ["GET", `${API}/stats?start_date=2026-01-01`, "allow"],
      ["GET", `${API}/marketing/contacts`, "allow"],
    ])
  })

  it("holds sends and other writes for approval", () => {
    expectAll([
      ["POST", `${API}/mail/send`, "approve"],
      ["POST", `${EU}/mail/send`, "approve"],
      ["PUT", `${API}/marketing/singlesends/s1/schedule`, "approve"],
      ["POST", `${API}/marketing/test/send_email`, "approve"],
      ["PUT", `${API}/marketing/contacts`, "approve"],
    ])
  })

  it("refuses keys, webhooks, teammates, subusers, SSO, access settings, forwarding and account changes", () => {
    expectAll([
      ["POST", `${API}/api_keys`, "deny"],
      ["PUT", `${API}/api_keys/k1`, "deny"],
      ["PATCH", `${API}/user/webhooks/event/settings`, "deny"],
      ["POST", `${API}/user/webhooks/parse/settings`, "deny"],
      ["POST", `${API}/teammates`, "deny"],
      ["POST", `${API}/subusers`, "deny"],
      ["POST", `${API}/sso/integrations`, "deny"],
      ["PATCH", `${API}/scopes/requests/r1/approve`, "deny"],
      ["POST", `${API}/access_settings/whitelist`, "deny"],
      ["PATCH", `${API}/mail_settings/forward_bounce`, "deny"],
      ["PATCH", `${API}/mail_settings/bcc`, "deny"],
      ["PUT", `${API}/user/email`, "deny"],
      ["PUT", `${API}/user/password`, "deny"],
      ["POST", `${API}/API_KEYS`, "deny"],
    ])
  })
})
