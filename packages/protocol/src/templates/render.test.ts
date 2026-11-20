import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { render } from "./render.ts"
import { underBroadAllow } from "../../test/template-policy.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(render.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(render.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://api.render.com/v1"

describe("render", () => {
  it("reaches its API over https, and nothing that looks like it or lies outside /v1", () => {
    expect(reaches("GET", `${API}/services`)).toBe(true)
    expect(reaches("GET", "https://api.render.com.evil.test/v1/services")).toBe(false)
    expect(reaches("GET", "http://api.render.com/v1/services")).toBe(false)
    expect(reaches("GET", "https://api.render.com/v2/services")).toBe(false)
  })

  it("lets ordinary reads through", () => {
    expectAll([
      ["GET", `${API}/services`, "allow"],
      ["GET", `${API}/services/srv/deploys`, "allow"],
      ["GET", `${API}/logs?ownerId=o`, "allow"],
      ["GET", `${API}/postgres/pg`, "allow"],
      ["GET", `${API}/registrycredentials`, "approve"],
      ["GET", `${API}/mehen-unlisted`, "approve"],
    ])
  })

  it("holds reads that hand back a secret, database credentials and every write for approval", () => {
    expectAll([
      ["GET", `${API}/services/srv/env-vars`, "approve"],
      ["GET", `${API}/services/srv/secret-files/key`, "approve"],
      ["GET", `${API}/env-groups/evg`, "approve"],
      ["GET", `${API}/postgres/pg/connection-info`, "approve"],
      ["GET", `${API}/key-value/kv/connection-info`, "approve"],
      ["POST", `${API}/postgres/pg/credentials`, "approve"],
      ["POST", `${API}/services/srv/deploys`, "approve"],
    ])
  })

  it("refuses members, webhooks, log and metrics streams, and sandbox tokens", () => {
    expectAll([
      ["PATCH", `${API}/owners/own/members/usr`, "deny"],
      ["DELETE", `${API}/owners/own/members/usr`, "deny"],
      ["POST", `${API}/webhooks`, "deny"],
      ["PUT", `${API}/logs/streams/owner/own`, "deny"],
      ["PUT", `${API}/metrics-stream/own`, "deny"],
      ["POST", `${API}/sandboxes/sb/runs/exec/token`, "deny"],
      ["POST", `${API}/Webhooks`, "deny"],
    ])
  })
})

describe("render review fixes", () => {
  it("holds webhooks (they carry their signing secret), streams and other secret reads whatever the item's policy says", () => {
    for (const path of [
      "/webhooks",
      "/webhooks/wh1",
      "/logs/streams/owner/own",
      "/metrics-stream/own",
      "/services/srv/env-vars",
      "/env-groups/evg",
      "/postgres/pg/connection-info",
      "/redis/r1/connection-info",
    ]) expect({ path, action: underBroadAllow(render, "GET", `${API}${path}`) }).toEqual({ path, action: "approve" })
  })
})
