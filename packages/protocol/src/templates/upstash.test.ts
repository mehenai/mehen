import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { upstash } from "./upstash.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(upstash.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(upstash.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://api.upstash.com/v2"

describe("upstash", () => {
  it("reaches the Developer API over https, and neither a look-alike, another prefix nor a database host", () => {
    expect(reaches("GET", `${API}/teams`)).toBe(true)
    expect(reaches("GET", "https://api.upstash.com.evil.test/v2/teams")).toBe(false)
    expect(reaches("GET", "http://api.upstash.com/v2/teams")).toBe(false)
    expect(reaches("GET", "https://api.upstash.com/v1/teams")).toBe(false)
    expect(reaches("GET", "https://example-12345.upstash.io/get/key")).toBe(false)
  })

  it("lets ordinary reads through", () => {
    expectAll([
      ["GET", `${API}/teams`, "allow"],
      ["GET", `${API}/redis/stats/db1`, "allow"],
      ["GET", `${API}/redis/list-backup/db1`, "allow"],
    ])
  })

  it("holds database details, password resets and billed changes for approval", () => {
    expectAll([
      ["GET", `${API}/redis/databases`, "approve"],
      ["GET", `${API}/redis/database/db1`, "approve"],
      ["GET", `${API}/vector/index/ix1`, "approve"],
      ["POST", `${API}/redis/reset-password/db1`, "approve"],
      ["POST", `${API}/vector/index/ix1/reset-password`, "approve"],
      ["POST", `${API}/redis/database`, "approve"],
      ["POST", `${API}/redis/db1/change-plan`, "approve"],
      ["PATCH", `${API}/redis/update-budget/db1`, "approve"],
    ])
  })

  it("refuses team members and moves to another team", () => {
    expectAll([
      ["POST", `${API}/teams/member`, "deny"],
      ["DELETE", `${API}/teams/member`, "deny"],
      ["POST", `${API}/redis/move-to-team`, "deny"],
      ["POST", `${API}/vector/index/ix1/transfer`, "deny"],
      ["POST", `${API}/teams/%6dember`, "deny"],
    ])
  })
})
