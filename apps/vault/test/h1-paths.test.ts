// At the server: the relay forwards the canonical
// path it checked, and readBody stops reading at its byte cap.

import { describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { readBody } from "../src/http.ts"
import type { RelayMaterial } from "../src/relay/forward.ts"
import { authoriseRelay } from "../src/vault/areas/relay.ts"
import { items } from "../src/vault/areas/items.ts"
import type { VaultContext } from "../src/vault/core.ts"
import type { NewItem } from "../src/vault/services.ts"
import { freshTenant, testDevice as fabricatedDevice } from "./helpers.ts"
import { POLICY_DEVICE, registerPolicyDevice } from "./policy-fixtures.ts"

const testDevice = (overrides: Parameters<typeof fabricatedDevice>[0] = {}) => fabricatedDevice({ device: POLICY_DEVICE, ...overrides })

const SYSTEM = { kind: "system", reason: "test" } as const

const ITEM: NewItem = {
  slug: "openai-personal",
  kind: "api-key",
  provider: "openai",
  account: null,
  accountVerified: false,
  tags: ["personal"],
  ceiling: "placeholder",
  binding: { hosts: ["api.openai.com"] },
  policy: { default: "allow", rules: [{ action: "deny", paths: ["/v1/organization/**"], note: "admin API" }] },
  injection: { in: "header", name: "Authorization", format: "Bearer {key}" },
  publicFields: {},
  secretFields: { key: "sk-proj-0123456789abcdefghij" },
  description: null,
}

function authorise(ctx: VaultContext, url: string, method = "GET"): Promise<RelayMaterial> {
  return authoriseRelay(ctx, testDevice(), { item: ITEM.slug, method, url, headers: [] }) as Promise<RelayMaterial>
}

async function inVault(fn: (ctx: VaultContext) => Promise<void>): Promise<void> {
  const stub = env.TENANT_VAULT.getByName(freshTenant())
  await runInDurableObject(stub, async (instance) => {
    await registerPolicyDevice(instance.context, testDevice())
    await fn(instance.context)
  })
}

describe("the relay forwards the canonical path", () => {
  it("decodes unreserved escapes and upper-cases the rest before forwarding, leaving the query alone", async () => {
    await inVault(async (ctx) => {
      await items.putItem(ctx, ITEM, SYSTEM)
      const material = await authorise(ctx, "https://api.openai.com/v1/%6Dodels/a%3ab?x=%6d#frag")
      expect(material.url).toBe("https://api.openai.com/v1/models/a%3Ab?x=%6d")
    })
  })

  it("an encoded or re-cased path still meets the deny rule", async () => {
    await inVault(async (ctx) => {
      await items.putItem(ctx, ITEM, SYSTEM)
      for (const url of ["https://api.openai.com/v1/%6Frganization/keys", "https://api.openai.com/v1/Organization/keys", "https://api.openai.com/V1/ORGANIZATION"]) {
        await expect(authorise(ctx, url, "POST")).rejects.toMatchObject({ code: "policy_denied" })
      }
    })
  })

  it("refuses a double-encoded path before anything else", async () => {
    await inVault(async (ctx) => {
      await items.putItem(ctx, ITEM, SYSTEM)
      await expect(authorise(ctx, "https://api.openai.com/v1/%256Frganization/keys", "POST")).rejects.toMatchObject({ code: "binding_refused" })
    })
  })
})

function endlessBody(chunkBytes: number): { stream: ReadableStream<Uint8Array>; pulled: () => number } {
  let pulls = 0
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls++
      if (pulls > 10_000) controller.error(new Error("read far past the cap"))
      else controller.enqueue(new Uint8Array(chunkBytes))
    },
  })
  return { stream, pulled: () => pulls }
}

describe("readBody", () => {
  it("returns the body when it fits", async () => {
    const bytes = await readBody(new Request("https://vault.example/", { method: "POST", body: "{\"a\":1}" }), 16)
    expect(new TextDecoder().decode(bytes)).toBe("{\"a\":1}")
    expect((await readBody(new Request("https://vault.example/"), 16)).length).toBe(0)
  })

  it("refuses a declared content-length over the cap without reading", async () => {
    const { stream, pulled } = endlessBody(1024)
    const request = new Request("https://vault.example/", { method: "POST", body: stream, headers: { "content-length": "4096" } })
    await expect(readBody(request, 1000)).rejects.toMatchObject({ code: "too_large" })
    expect(pulled()).toBeLessThanOrEqual(1)
  })

  it("stops reading as soon as a body with no content-length passes the cap", async () => {
    const { stream, pulled } = endlessBody(1024)
    const request = new Request("https://vault.example/", { method: "POST", body: stream })
    expect(request.headers.get("content-length")).toBeNull()
    await expect(readBody(request, 10 * 1024)).rejects.toMatchObject({ code: "too_large" })
    expect(pulled()).toBeLessThan(20)
  })

  it("does not trust an understated content-length", async () => {
    const { stream, pulled } = endlessBody(1024)
    const request = new Request("https://vault.example/", { method: "POST", body: stream, headers: { "content-length": "10" } })
    await expect(readBody(request, 4 * 1024)).rejects.toMatchObject({ code: "too_large" })
    expect(pulled()).toBeLessThan(20)
  })
})
