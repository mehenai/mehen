import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { figma } from "./figma.ts"
import { underBroadAllow } from "../../test/template-policy.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(figma.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(figma.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://api.figma.com"

describe("figma", () => {
  it("sends the token in X-Figma-Token", () => {
    expect(figma.injection).toEqual({ in: "header", name: "X-Figma-Token", format: "{key}" })
  })

  it("reaches its API over https, and nothing that looks like it", () => {
    expect(reaches("GET", `${API}/v1/me`)).toBe(true)
    expect(reaches("GET", "https://api.figma.com.evil.test/v1/me")).toBe(false)
    expect(reaches("GET", "http://api.figma.com/v1/me")).toBe(false)
    expect(reaches("GET", "https://www.figma.com/v1/me")).toBe(false)
  })

  it("lets reads through and holds writes for approval", () => {
    expectAll([
      ["GET", `${API}/v1/files/abc`, "allow"],
      ["GET", `${API}/v1/images/abc?ids=1:2`, "allow"],
      ["POST", `${API}/v1/files/abc/comments`, "approve"],
      ["POST", `${API}/v1/files/abc/variables`, "approve"],
    ])
  })

  it("refuses webhooks", () => {
    expectAll([
      ["POST", `${API}/v2/webhooks`, "deny"],
      ["PUT", `${API}/v2/webhooks/w1`, "deny"],
      ["POST", `${API}/v2/%77ebhooks`, "deny"],
    ])
  })
})

describe("figma review fixes", () => {
  it("lets the named reads through and holds every other read", () => {
    expectAll([
      ["GET", `${API}/v1/files/abc/nodes?ids=1:2`, "allow"],
      ["GET", `${API}/v1/teams/t1/projects`, "allow"],
      ["GET", `${API}/v1/activity_logs`, "approve"],
    ])
  })

  it("holds webhooks and their request history (which may carry the passcode) whatever the item's policy says", () => {
    for (const path of [
      "/v2/webhooks/w1",
      "/v2/webhooks/w1/requests",
      "/v2/teams/t1/webhooks",
    ]) expect({ path, action: underBroadAllow(figma, "GET", `${API}${path}`) }).toEqual({ path, action: "approve" })
  })
})
