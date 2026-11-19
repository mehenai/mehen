import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { base64UrlEncode, utf8 } from "@mehen/protocol"
import { policySafetyDigest } from "@mehen/protocol/policy-safety"
import { VaultError } from "../src/http.ts"
import { setRelayServices } from "../src/relay/services.ts"
import { authoriseRelay } from "../src/vault/areas/relay.ts"
import { items } from "../src/vault/areas/items.ts"
import { policy } from "../src/vault/areas/policy.ts"
import { freshTenant } from "./helpers.ts"
import { policyFixture, policyItem } from "./policy-fixtures.ts"

// The relay decides by the item's own policy in standard mode; a caller can
// name no mode, and the floors and fences hold whatever the item allows.
beforeEach(() => { setRelayServices({ async reviewRequest() { throw new VaultError("approval_required","Review this request.",{ next: { say: "Ask a human to review this request." } }) } }) })
afterEach(() => { setRelayServices({}) })
const inVault = async (test: (ctx: import("../src/vault/core.ts").VaultContext) => Promise<void>) => runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), (instance) => test(instance.context))
const root = "https://api.example.com/api/projects/12345"
function request(overrides: Record<string, unknown> = {}) { return { item: "custom-key", method: "GET", url: `${root}/tasks`, headers: [], ...overrides } }
async function refusingWithoutOpen(ctx: import("../src/vault/core.ts").VaultContext, device: import("../src/vault/core.ts").DevicePrincipal, input: unknown, code: string) {
  let opens = 0
  const guarded = { ...ctx, openField: async (...args: Parameters<typeof ctx.openField>) => { opens++; return ctx.openField(...args) } }
  const spent = ctx.sql.exec("SELECT id, uses_left FROM grants ORDER BY id").toArray()
  await expect(authoriseRelay(guarded, device, input)).rejects.toMatchObject({ code, extra: { next: { say: expect.any(String) } } })
  expect(opens).toBe(0)
  expect(ctx.sql.exec("SELECT id, uses_left FROM grants ORDER BY id").toArray()).toEqual(spent)
  expect(ctx.sql.exec("SELECT * FROM audit WHERE action = 'relay.allow'").toArray()).toEqual([])
}

describe("standard policy at the relay", () => {
  it("strips caller Mehen-Policy-State without granting authority", async () => inVault(async (ctx) => {
    const device = await policyFixture(ctx, { policy: { default: "allow", rules: [] } })
    const material = await authoriseRelay(ctx, device, request({ method: "POST", headers: [["Mehen-Policy-State", "yolo"], ["content-type", "application/json"]], body: base64UrlEncode(utf8('{"title":"a task"}')) }))
    expect(material.headers.some(([name]) => name.toLowerCase() === "mehen-policy-state")).toBe(false)
    expect(material.headers.find(([name]) => name === "authorization")?.[1]).toContain("policy-test-secret")
  }))

  it("refusal/standard caller policy header and body mode do not select widening", async () => inVault(async (ctx) => {
    const device = await policyFixture(ctx)
    await refusingWithoutOpen(ctx, device, request({ headers: [["Mehen-Policy-State", "yolo"]] }), "approval_required")
    await refusingWithoutOpen(ctx, device, request({ policyMode: "yolo" }), "bad_request")
    await refusingWithoutOpen(ctx, device, request({ session: "child" }), "forbidden")
  }))

  it("refusal/bound host, path, port, method and floor precedence", async () => inVault(async (ctx) => {
    const device = await policyFixture(ctx)
    for (const url of ["https://evil.test/api/projects/12345/tasks", "https://api.example.com:8443/api/projects/12345/tasks", "https://api.example.com/other", `${root}/%2fescape`]) await refusingWithoutOpen(ctx, device, request({ url }), "binding_refused")
    await refusingWithoutOpen(ctx, device, request({ method: "DELETE" }), "approval_required")
    await refusingWithoutOpen(ctx, device, request({ method: "POST", headers: [["X-HTTP-Method-Override", "DELETE"]] }), "forbidden")
    await refusingWithoutOpen(ctx, device, request({ url: `${root}/tasks?_method=DELETE` }), "forbidden")
  }))

  it("refusal/provider-independent known denies and approves beat base allow", async () => inVault(async (ctx) => {
    const device = await policyFixture(ctx, { provider: null, binding: { hosts: ["api.github.com"] }, policy: { default: "allow", rules: [] } })
    await refusingWithoutOpen(ctx, device, request({ method: "POST", url: "https://api.github.com/repos/acme/repo/hooks" }), "policy_denied")
    await items.putItem(ctx, { ...policyItem(), slug: "stripe-key", binding: { hosts: ["api.stripe.com"] }, policy: { default: "allow", rules: [] } }, { kind: "system", reason: "test" })
    await refusingWithoutOpen(ctx, device, request({ item: "stripe-key", method: "POST", url: "https://api.stripe.com/v1/refunds" }), "approval_required")
  }))

  it("refusal/explicit approve and default deny decide", async () => inVault(async (ctx) => {
    const device = await policyFixture(ctx)
    const item = items.getItem(ctx, "custom-key")!
    const changed = { ...item, policy: { default: "approve" as const, rules: [{ action: "approve" as const, paths: ["/api/projects/12345/tasks"] }] } }
    const prepared = policy.prepare(ctx, device, changed, { scheme: "https", host: "api.example.com", port: 443, method: "GET", path: "/api/projects/12345/tasks", search: "" }, null, null, null)
    expect(prepared.decision).toBe("approve")
    expect(policy.prepare(ctx, device, { ...changed, policy: { default: "deny", rules: [] } }, { scheme: "https", host: "api.example.com", port: 443, method: "GET", path: "/api/projects/12345/tasks", search: "" }, null, null, null).decision).toBe("deny")
  }))
})

describe("the guard's safety digest", () => {
  it("is protocol's policySafetyDigest, catalogues included, so a catalogue change makes every permit in flight stale", async () => inVault(async (ctx) => {
    const device = await policyFixture(ctx)
    const snapshot = policy.snapshot(ctx, device.device, items.getItem(ctx, "custom-key")!)
    expect(snapshot.safetyDigest).toBe(await policySafetyDigest())
  }))
})

describe("relay boundaries", () => {
  it("refusal/current device scope is checked after an asynchronous body hash even for base allow", async () => inVault(async (ctx) => {
    const { vi } = await import("vitest")
    const device = await policyFixture(ctx, { policy: { default: "allow", rules: [] } })
    const digest = crypto.subtle.digest.bind(crypto.subtle)
    const scope = { ...device.scope, modes: ["sign" as const] }
    const spy = vi.spyOn(crypto.subtle, "digest").mockImplementationOnce(async (algorithm, data) => {
      ctx.sql.exec("UPDATE devices SET scope=?,scope_rev=scope_rev+1 WHERE id=?",JSON.stringify(scope),device.device)
      return digest(algorithm, data)
    })
    try { await refusingWithoutOpen(ctx, device, request(), "forbidden") }
    finally { spy.mockRestore() }
  }))

  it("refusal/a run cannot raise exposure ceilings, nor an item request claim an environment", async () => inVault(async (ctx) => {
    const { setRelayServices } = await import("../src/relay/services.ts")
    const { newPlaceholder } = await import("@mehen/protocol")
    const device = await policyFixture(ctx, { ceiling: "relay" })
    const placeholder = newPlaceholder("test-placeholder")
    setRelayServices({ async reviewRequest() { throw new VaultError("approval_required","Review this request.",{ next: { say: "Ask a human to review this request." } }) },placeholdersFor: () => [{ placeholder, item: "custom-key", field: "key", hosts: ["api.example.com"] }] })
    try {
      await refusingWithoutOpen(ctx, device, request({ item: undefined, run: "run_test", headers: [["Authorization", placeholder]] }), "mode_refused")
      await refusingWithoutOpen(ctx, device, request({ environment: "prod" }), "bad_request")
    } finally { setRelayServices({}) }
  }))

  it("refusal/decrypted reserved header maps make zero upstream calls", async () => inVault(async (ctx) => {
    const { setUpstreamFetch } = await import("../src/relay/upstream.ts")
    const { forwardRelay } = await import("../src/relay/forward.ts")
    const device = await policyFixture(ctx, { kind: "custom-headers", ceiling: "relay", injection: { in: "headers", field: "headers" }, secretFields: { headers: '{"Mehen-Policy-State":"malicious"}' }, policy: { default: "allow", rules: [] } })
    let sends = 0
    let opens = 0
    setUpstreamFetch(async () => { sends++; return new Response("should not send") })
    try {
      const guarded = { ...ctx, openField: async (...args: Parameters<typeof ctx.openField>) => { opens++; return ctx.openField(...args) } }
      await expect(authoriseRelay(guarded, device, request()).then((material) => forwardRelay(material, null))).rejects.toMatchObject({ code: "mode_refused" })
      expect(opens).toBe(1)
      expect(sends).toBe(0)
    } finally { setUpstreamFetch(null) }
  }))

  it("refusal/large or compressed requests are refused past the ceiling", async () => inVault(async (ctx) => {
    const device = await policyFixture(ctx)
    const gzipped = new Uint8Array(await new Response((new Response("compressed").body as ReadableStream).pipeThrough(new CompressionStream("gzip"))).arrayBuffer())
    for (const input of [request({ method: "POST", body: base64UrlEncode(utf8(JSON.stringify({ text: "x".repeat(65 * 1024) }))) }), request({ method: "POST", headers: [["content-encoding", "gzip"]], body: base64UrlEncode(gzipped) })]) await refusingWithoutOpen(ctx, device, input, "mode_refused")
  }))
})
