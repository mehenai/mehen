import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { huggingface } from "./huggingface.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(huggingface.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(huggingface.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const HUB = "https://huggingface.co"
const ROUTER = "https://router.huggingface.co"

describe("huggingface", () => {
  it("reaches the Hub and the router over https, and nothing that looks like them", () => {
    expect(reaches("GET", `${HUB}/api/whoami-v2`)).toBe(true)
    expect(reaches("POST", `${ROUTER}/v1/chat/completions`)).toBe(true)
    expect(reaches("GET", "https://huggingface.co.evil.test/api/whoami-v2")).toBe(false)
    expect(reaches("GET", "https://evil-huggingface.co/api/whoami-v2")).toBe(false)
    expect(reaches("GET", "https://api-inference.huggingface.co/models/x")).toBe(false)
    expect(reaches("GET", `http://huggingface.co/api/whoami-v2`)).toBe(false)
  })

  it("lets reads, path lookups and router chat completions through", () => {
    expectAll([
      ["GET", `${HUB}/api/models?search=bert`, "allow"],
      ["GET", `${HUB}/openai-community/gpt2/resolve/main/config.json`, "allow"],
      ["POST", `${HUB}/api/models/acme/model/paths-info/main`, "allow"],
      ["POST", `${ROUTER}/v1/chat/completions`, "allow"],
      ["POST", `${ROUTER}/hf-inference/models/acme/model`, "allow"],
    ])
  })

  it("holds commits, repositories, billed compute and visibility changes for approval", () => {
    expectAll([
      ["POST", `${HUB}/api/models/acme/model/commit/main`, "approve"],
      ["POST", `${HUB}/api/repos/create`, "approve"],
      ["POST", `${HUB}/api/jobs/acme`, "approve"],
      ["POST", `${HUB}/api/spaces/acme/space/hardware`, "approve"],
      ["PUT", `${HUB}/api/models/acme/model/settings`, "approve"],
      ["GET", `${HUB}/api/registry/token`, "approve"],
      ["POST", `${ROUTER}/together/v1/chat/completions`, "approve"],
    ])
  })

  it("refuses webhooks, members, tokens, trusted publishers, moves, provider keys and billing", () => {
    expectAll([
      ["POST", `${HUB}/api/settings/webhooks`, "deny"],
      ["POST", `${HUB}/api/settings/webhooks/abc/enable`, "deny"],
      ["PUT", `${HUB}/api/organizations/acme/members/bob/role`, "deny"],
      ["POST", `${HUB}/api/organizations/acme/scim/v2/Users`, "deny"],
      ["POST", `${HUB}/api/organizations/acme/resource-groups/rg/users`, "deny"],
      ["PUT", `${HUB}/api/organizations/acme/settings/sso/credentials`, "deny"],
      ["POST", `${HUB}/api/models/acme/model/user-access-request/grant`, "deny"],
      ["POST", `${HUB}/api/organizations/acme/service-accounts/sa/tokens`, "deny"],
      ["POST", `${HUB}/api/organizations/acme/settings/tokens/t/revoke`, "deny"],
      ["POST", `${HUB}/api/credentials/revoke`, "deny"],
      ["POST", `${HUB}/api/models/acme/model/settings/trusted-publishers`, "deny"],
      ["POST", `${HUB}/api/repos/move`, "deny"],
      ["POST", `${HUB}/api/settings/inference-providers/api-key`, "deny"],
      ["POST", `${HUB}/api/settings/billing/prepaid-credits/purchase-link`, "deny"],
      ["POST", `${HUB}/oauth/register`, "deny"],
    ])
  })

  it("still refuses an escaped or re-cased webhook route", () => {
    expectAll([
      ["POST", `${HUB}/api/settings/%77ebhooks`, "deny"],
      ["POST", `${HUB}/api/Settings/Webhooks`, "deny"],
    ])
  })
})
