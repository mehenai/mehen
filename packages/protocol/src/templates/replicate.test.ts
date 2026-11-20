import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { replicate } from "./replicate.ts"
import { underBroadAllow } from "../../test/template-policy.ts"

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

  it("lets named reads, cancels and uploads through", () => {
    expectAll([
      ["GET", `${API}/models/acme/model`, "allow"],
      ["GET", `${API}/models/acme/model/versions/v1`, "allow"],
      ["GET", `${API}/predictions/p1`, "allow"],
      ["GET", `${API}/collections/super-resolution`, "allow"],
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

describe("replicate review fixes", () => {
  it("holds a prediction with no body, since nothing proves it names no webhook", () => {
    expectAll([
      ["POST", `${API}/predictions`, "approve"],
      ["POST", `${API}/models/acme/model/predictions`, "approve"],
      ["POST", `${API}/deployments/acme/dep/predictions`, "approve"],
    ])
    for (const path of [
      "/predictions",
      "/models/acme/model/predictions",
      "/deployments/acme/dep/predictions",
    ]) expect({ path, action: underBroadAllow(replicate, "POST", `${API}${path}`) }).toEqual({ path, action: "approve" })
  })

  it("holds any read it does not name, and the webhook secret whatever the item's policy says", () => {
    expectAll([["GET", `${API}/mehen-unlisted`, "approve"]])
    for (const path of [
      "/webhooks/default/secret",
    ]) expect({ path, action: underBroadAllow(replicate, "GET", `${API}${path}`) }).toEqual({ path, action: "approve" })
  })
})

describe("replicate second review fixes", () => {
  const plain = { version: "v1", input: { prompt: "a cat" } }
  const hooked = { version: "v1", input: { prompt: "a cat" }, webhook: "https://evil.test/hook", webhook_events_filter: ["completed"] }

  it("lets a prediction through unless it names a webhook or cannot be read, on every prediction route, whatever the item's policy says", () => {
    for (const path of ["/predictions", "/models/acme/model/predictions", "/deployments/acme/dep/predictions"]) {
      expect({ path, policy: decide("POST", `${API}${path}`, plain) }).toEqual({ path, policy: "allow" })
      expect({ path, relay: underBroadAllow(replicate, "POST", `${API}${path}`, plain) }).toEqual({ path, relay: "allow" })
      for (const body of [hooked, "not json"]) {
        expect({ path, body, policy: decide("POST", `${API}${path}`, body) }).toEqual({ path, body, policy: "approve" })
        expect({ path, body, relay: underBroadAllow(replicate, "POST", `${API}${path}`, body) }).toEqual({ path, body, relay: "approve" })
      }
    }
  })
})
