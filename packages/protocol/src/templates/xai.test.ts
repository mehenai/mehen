import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { xai } from "./xai.ts"
import { underBroadAllow } from "../../test/template-policy.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(xai.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(xai.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://api.x.ai"

describe("xai", () => {
  it("reaches the inference API over https, and neither a look-alike nor the management API", () => {
    expect(reaches("POST", `${API}/v1/responses`)).toBe(true)
    expect(reaches("POST", "https://api.x.ai.evil.test/v1/responses")).toBe(false)
    expect(reaches("POST", "http://api.x.ai/v1/responses")).toBe(false)
    expect(reaches("GET", "https://management-api.x.ai/auth/teams/t/api-keys")).toBe(false)
  })

  it("lets reads and model calls through", () => {
    expectAll([
      ["GET", `${API}/v1/models`, "allow"],
      ["POST", `${API}/v1/chat/completions`, "allow"],
      ["POST", `${API}/v1/responses`, "allow"],
      ["POST", `${API}/v1/images/generations`, "allow"],
      ["POST", `${API}/v1/batches/b1/requests`, "allow"],
    ])
  })

  it("holds realtime client secrets, phone numbers and deletes for approval", () => {
    expectAll([
      ["POST", `${API}/v1/realtime/client_secrets`, "approve"],
      ["POST", `${API}/v2/phone-numbers`, "approve"],
      ["DELETE", `${API}/v2/phone-numbers/n1`, "approve"],
      ["DELETE", `${API}/v1/responses/r1`, "approve"],
    ])
  })
})

describe("xai reads", () => {
  it("lets the named reads through and holds every other read", () => {
    expectAll([
      ["GET", `${API}/v1/models/grok-4`, "allow"],
      ["GET", `${API}/v1/language-models`, "allow"],
      ["GET", `${API}/v1/responses/r1`, "allow"],
      ["GET", `${API}/v1/batches/b1/results`, "allow"],
      ["GET", `${API}/v1/api-key`, "approve"],
      ["GET", `${API}/v2/phone-numbers`, "approve"],
      ["GET", `${API}/v1/mehen-unlisted`, "approve"],
    ])
  })

  it("holds the API key's details even when the item's own policy allows everything", () => {
    for (const path of [
      "/v1/api-key",
    ]) expect({ path, action: underBroadAllow(xai, "GET", `${API}${path}`) }).toEqual({ path, action: "approve" })
  })
})
