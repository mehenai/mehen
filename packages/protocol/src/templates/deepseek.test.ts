import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { deepseek } from "./deepseek.ts"
import { underBroadAllow } from "../../test/template-policy.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(deepseek.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(deepseek.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://api.deepseek.com"

describe("deepseek", () => {
  it("reaches its API over https, and nothing that looks like it", () => {
    expect(reaches("POST", `${API}/chat/completions`)).toBe(true)
    expect(reaches("POST", "https://api.deepseek.com.evil.test/chat/completions")).toBe(false)
    expect(reaches("POST", "http://api.deepseek.com/chat/completions")).toBe(false)
    expect(reaches("POST", "https://platform.deepseek.com/chat/completions")).toBe(false)
  })

  it("lets reads and model calls through", () => {
    expectAll([
      ["GET", `${API}/models`, "allow"],
      ["GET", `${API}/user/balance`, "allow"],
      ["GET", `${API}/mehen-unlisted`, "approve"],
      ["POST", `${API}/chat/completions`, "allow"],
      ["POST", `${API}/beta/completions`, "allow"],
      ["POST", `${API}/anthropic/v1/messages`, "allow"],
    ])
  })

  it("holds anything else for approval", () => {
    expectAll([["POST", `${API}/mehen-unlisted`, "approve"], ["DELETE", `${API}/models/x`, "approve"]])
  })
})

describe("deepseek reads", () => {
  it("allows only the model list and the balance among reads; DeepSeek documents no read that returns a secret", () => {
    expect(deepseek.policy.rules.filter((r) => r.action === "allow" && r.methods?.includes("GET")).flatMap((r) => r.paths ?? ["(any)"])).toEqual(["/models", "/user/balance"])
    expect(underBroadAllow(deepseek, "GET", `${API}/models`)).toBe("allow")
  })
})
