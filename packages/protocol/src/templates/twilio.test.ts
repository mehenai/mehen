import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { twilio } from "./twilio.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(twilio.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(twilio.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://api.twilio.com/2010-04-01"
const ACCOUNT = `${API}/Accounts/AC00000000000000000000000000000000`

describe("twilio", () => {
  it("reaches the core API over https, and neither a look-alike nor another product's host", () => {
    expect(reaches("GET", `${ACCOUNT}/Messages.json`)).toBe(true)
    expect(reaches("GET", "https://api.twilio.com.evil.test/2010-04-01/Accounts.json")).toBe(false)
    expect(reaches("GET", "http://api.twilio.com/2010-04-01/Accounts.json")).toBe(false)
    expect(reaches("POST", "https://verify.twilio.com/v2/Services")).toBe(false)
    expect(reaches("GET", "https://api.twilio.com/v1/Accounts.json")).toBe(false)
  })

  it("lets reads through", () => {
    expectAll([
      ["GET", `${API}/Accounts.json`, "allow"],
      ["GET", `${ACCOUNT}/Messages.json?PageSize=20`, "allow"],
      ["GET", `${ACCOUNT}/Calls/CA1.json`, "allow"],
    ])
  })

  it("holds messages and calls for approval", () => {
    expectAll([
      ["POST", `${ACCOUNT}/Messages.json`, "approve"],
      ["POST", `${ACCOUNT}/Calls.json`, "approve"],
      ["POST", `${ACCOUNT}/Calls/CA1.json`, "approve"],
    ])
  })

  it("refuses keys, subaccounts, account changes, phone numbers, applications and SIP", () => {
    expectAll([
      ["POST", `${ACCOUNT}/Keys.json`, "deny"],
      ["DELETE", `${ACCOUNT}/Keys/SK1.json`, "deny"],
      ["POST", `${ACCOUNT}/SigningKeys.json`, "deny"],
      ["POST", `${API}/Accounts.json`, "deny"],
      ["POST", `${ACCOUNT}.json`, "deny"],
      ["POST", `${ACCOUNT}/IncomingPhoneNumbers.json`, "deny"],
      ["POST", `${ACCOUNT}/IncomingPhoneNumbers/Local.json`, "deny"],
      ["POST", `${ACCOUNT}/IncomingPhoneNumbers/PN1.json`, "deny"],
      ["POST", `${ACCOUNT}/Applications.json`, "deny"],
      ["POST", `${ACCOUNT}/SIP/CredentialLists.json`, "deny"],
      ["POST", `${ACCOUNT}/keys.json`, "deny"],
    ])
  })
})
