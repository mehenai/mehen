import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { supabase } from "./supabase.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(supabase.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(supabase.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://api.supabase.com/v1"

describe("supabase", () => {
  it("reaches the Management API over https, and neither a look-alike, another prefix nor a project host", () => {
    expect(reaches("GET", `${API}/projects`)).toBe(true)
    expect(reaches("GET", "https://api.supabase.com.evil.test/v1/projects")).toBe(false)
    expect(reaches("GET", "http://api.supabase.com/v1/projects")).toBe(false)
    expect(reaches("GET", "https://api.supabase.com/platform/projects")).toBe(false)
    expect(reaches("GET", "https://abcdefghijklmnop.supabase.co/rest/v1/todos")).toBe(false)
  })

  it("lets ordinary reads through", () => {
    expectAll([
      ["GET", `${API}/projects`, "allow"],
      ["GET", `${API}/projects/ref/functions`, "allow"],
      ["GET", `${API}/projects/ref/database/migrations`, "allow"],
    ])
  })

  it("holds reads that hand back a secret, SQL, passwords and billed changes for approval", () => {
    expectAll([
      ["GET", `${API}/projects/ref/api-keys?reveal=true`, "approve"],
      ["GET", `${API}/projects/ref/api-keys/legacy`, "approve"],
      ["GET", `${API}/projects/ref/secrets`, "approve"],
      ["GET", `${API}/projects/ref/config/auth`, "approve"],
      ["GET", `${API}/projects/ref/pgsodium`, "approve"],
      ["GET", `${API}/projects/ref/claim-token`, "approve"],
      ["POST", `${API}/projects/ref/database/query`, "approve"],
      ["PATCH", `${API}/projects/ref/database/password`, "approve"],
      ["POST", `${API}/projects/ref/cli/login-role`, "approve"],
      ["POST", `${API}/projects`, "approve"],
      ["PATCH", `${API}/projects/ref/billing/addons`, "approve"],
      ["POST", `${API}/projects/ref/config/disk`, "approve"],
    ])
  })

  it("refuses API keys, signing keys, outside sign-in, JIT access, claims, the root key, OAuth and deleting a project", () => {
    expectAll([
      ["POST", `${API}/projects/ref/api-keys`, "deny"],
      ["PATCH", `${API}/projects/ref/api-keys/k1`, "deny"],
      ["POST", `${API}/projects/ref/config/auth/signing-keys`, "deny"],
      ["POST", `${API}/projects/ref/config/auth/sso/providers`, "deny"],
      ["POST", `${API}/projects/ref/config/auth/third-party-auth`, "deny"],
      ["POST", `${API}/projects/ref/database/jit/invite`, "deny"],
      ["PUT", `${API}/projects/ref/jit-access`, "deny"],
      ["POST", `${API}/projects/ref/claim-token`, "deny"],
      ["POST", `${API}/organizations/acme/project-claim/tok`, "deny"],
      ["PUT", `${API}/projects/ref/pgsodium`, "deny"],
      ["POST", `${API}/oauth/token`, "deny"],
      ["DELETE", `${API}/projects/ref`, "deny"],
      ["POST", `${API}/projects/ref/API-KEYS`, "deny"],
    ])
  })
})
