import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { pypi } from "./pypi.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(pypi.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(pypi.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

describe("pypi", () => {
  it("reaches only POST /legacy/ on the upload host over https", () => {
    expect(reaches("POST", "https://upload.pypi.org/legacy/")).toBe(true)
    expect(reaches("GET", "https://upload.pypi.org/legacy/")).toBe(false)
    expect(reaches("POST", "https://upload.pypi.org.evil.test/legacy/")).toBe(false)
    expect(reaches("POST", "http://upload.pypi.org/legacy/")).toBe(false)
    expect(reaches("POST", "https://test.pypi.org/legacy/")).toBe(false)
    expect(reaches("GET", "https://pypi.org/pypi/requests/json")).toBe(false)
    expect(reaches("POST", "https://upload.pypi.org/other/")).toBe(false)
  })

  it("holds every upload for approval", () => {
    expect(decide("POST", "https://upload.pypi.org/legacy/")).toBe("approve")
  })
})
