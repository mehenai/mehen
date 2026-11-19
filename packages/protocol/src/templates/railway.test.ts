import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { railway } from "./railway.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(railway.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(railway.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://backboard.railway.com/graphql/v2"

describe("railway", () => {
  it("reaches only POST /graphql/v2 over https", () => {
    expect(reaches("POST", API)).toBe(true)
    expect(reaches("GET", API)).toBe(false)
    expect(reaches("POST", "https://backboard.railway.com.evil.test/graphql/v2")).toBe(false)
    expect(reaches("POST", "http://backboard.railway.com/graphql/v2")).toBe(false)
    expect(reaches("POST", "https://backboard.railway.com/graphql/internal")).toBe(false)
  })

  it("holds queries as well as mutations for approval, since a query can read service variables", () => {
    expect(decide("POST", API, { query: "query { variables(projectId: \"p\", environmentId: \"e\") }" })).toBe("approve")
    expect(decide("POST", API, { query: "mutation { apiTokenCreate(input: {name: \"x\"}) }" })).toBe("approve")
  })
})
