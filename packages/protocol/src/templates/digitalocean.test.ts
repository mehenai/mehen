import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { digitalocean } from "./digitalocean.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(digitalocean.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(digitalocean.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://api.digitalocean.com/v2"

describe("digitalocean", () => {
  it("reaches its API over https, and nothing that looks like it or lies outside /v2", () => {
    expect(reaches("GET", `${API}/droplets`)).toBe(true)
    expect(reaches("GET", "https://api.digitalocean.com.evil.test/v2/droplets")).toBe(false)
    expect(reaches("GET", "http://api.digitalocean.com/v2/droplets")).toBe(false)
    expect(reaches("GET", "https://api.digitalocean.com/v1/droplets")).toBe(false)
  })

  it("lets ordinary reads through", () => {
    expectAll([
      ["GET", `${API}/droplets`, "allow"],
      ["GET", `${API}/kubernetes/clusters`, "allow"],
      ["GET", `${API}/apps/a1/logs`, "allow"],
    ])
  })

  it("holds reads that hand back a secret, password resets and every write for approval", () => {
    expectAll([
      ["GET", `${API}/databases`, "approve"],
      ["GET", `${API}/databases/db1`, "approve"],
      ["GET", `${API}/databases/db1/users/admin`, "approve"],
      ["GET", `${API}/kubernetes/clusters/c1/kubeconfig`, "approve"],
      ["GET", `${API}/kubernetes/clusters/c1/credentials`, "approve"],
      ["GET", `${API}/registry/docker-credentials`, "approve"],
      ["GET", `${API}/security/secrets/s1`, "approve"],
      ["GET", `${API}/apps/a1/components/web/exec`, "approve"],
      ["POST", `${API}/databases/db1/users/admin/reset_auth`, "approve"],
      ["POST", `${API}/droplets`, "approve"],
    ])
  })

  it("refuses SSH keys, access keys and tokens, and log sinks", () => {
    expectAll([
      ["POST", `${API}/account/keys`, "deny"],
      ["DELETE", `${API}/account/keys/123`, "deny"],
      ["POST", `${API}/spaces/keys`, "deny"],
      ["POST", `${API}/functions/namespaces/ns/keys`, "deny"],
      ["POST", `${API}/dedicated-inferences/d1/tokens`, "deny"],
      ["POST", `${API}/microvms/m1/access_tokens`, "deny"],
      ["POST", `${API}/monitoring/sinks/destinations`, "deny"],
      ["POST", `${API}/account/%6beys`, "deny"],
    ])
  })
})
