import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { replicate } from "./replicate.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(replicate.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(replicate.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://api.replicate.com/v1"

describe("replicate", () => {
  it("reaches its API over https, and nothing that looks like it or lies outside /v1", () => {
    expect(reaches("GET", `${API}/account`)).toBe(true)
    expect(reaches("GET", "https://api.replicate.com.evil.test/v1/account")).toBe(false)
    expect(reaches("GET", "http://api.replicate.com/v1/account")).toBe(false)
    expect(reaches("GET", "https://api.replicate.com/v2/account")).toBe(false)
  })

  it("lets reads, predictions and uploads through", () => {
    expectAll([
      ["GET", `${API}/models/acme/model`, "allow"],
      ["POST", `${API}/predictions`, "allow"],
      ["POST", `${API}/models/acme/model/predictions`, "allow"],
      ["POST", `${API}/deployments/acme/dep/predictions`, "allow"],
      ["POST", `${API}/predictions/p1/cancel`, "allow"],
      ["POST", `${API}/files`, "allow"],
    ])
  })

  it("holds billed hardware, trainings, the webhook secret and other writes for approval", () => {
    expectAll([
      ["POST", `${API}/deployments`, "approve"],
      ["PATCH", `${API}/deployments/acme/dep`, "approve"],
      ["POST", `${API}/models/acme/model/versions/v1/trainings`, "approve"],
      ["GET", `${API}/webhooks/default/secret`, "approve"],
      ["DELETE", `${API}/models/acme/model`, "approve"],
      ["POST", `${API}/%64eployments`, "approve"],
    ])
  })
})
