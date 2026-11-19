// A secret's fingerprint is an HMAC under a key derived
// from the root, so someone holding only DO storage (which has the tenant,
// the item id and the fingerprint) cannot test guesses against it.

import { describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { base64UrlEncode, importRootKey, sha256 } from "@mehen/protocol"
import { items, secretFieldInfo } from "../src/vault/areas/items.ts"
import type { VaultContext } from "../src/vault/core.ts"
import type { NewItem } from "../src/vault/services.ts"
import { deriveFingerprintKey, parseRootKeys } from "../src/vault/keys.ts"
import { freshTenant } from "./helpers.ts"

const SYSTEM = { kind: "system", reason: "test" } as const
const VALUE = "hunter2-correct-horse"

function apiKeyItem(slug: string): NewItem {
  return {
    slug,
    kind: "api-key",
    provider: null,
    account: null,
    accountVerified: false,
    tags: [],
    ceiling: "placeholder",
    binding: { hosts: ["api.example.com"] },
    policy: { default: "allow", rules: [] },
    injection: null,
    publicFields: {},
    secretFields: { key: VALUE },
    description: null,
  }
}

function truncated(bytes: ArrayBuffer | Uint8Array<ArrayBuffer>): string {
  return base64UrlEncode(bytes).slice(0, 12)
}

async function hmacFingerprint(key: CryptoKey, itemId: string, value: string): Promise<string> {
  return truncated(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${itemId}\n${value}`)))
}

async function stored(tenant: string, slug: string): Promise<{ id: string; fingerprint: string; key: CryptoKey }> {
  return runInDurableObject(env.TENANT_VAULT.getByName(tenant), async (instance) => {
    const ctx: VaultContext = instance.context
    const item = await items.putItem(ctx, apiKeyItem(slug), SYSTEM)
    const info = secretFieldInfo(ctx, item).find((f) => f.name === "key")
    if (!info) throw new Error("no key field")
    return { id: item.id, fingerprint: info.fingerprint, key: await ctx.fingerprintKey(ctx.rootVersion) }
  })
}

describe("secret fingerprint", () => {
  it("is HMAC-SHA256 under HKDF(root, salt mehen/root/v<n>, info mehen/fingerprint/v1/<tenant>), truncated to 12", async () => {
    const tenant = freshTenant()
    const { id, fingerprint } = await stored(tenant, "acme-login")
    const ring = parseRootKeys(env.ROOT_KEYS)
    const root = await ring.versions.get(ring.current)
    if (!root) throw new Error("no root key")
    expect(fingerprint).toMatch(/^[A-Za-z0-9_-]{12}$/)
    expect(fingerprint).toBe(await hmacFingerprint(await deriveFingerprintKey(root, tenant), id, VALUE))
  })

  it("cannot be recomputed from what DO storage holds: the old unkeyed hash and another root both miss", async () => {
    const tenant = freshTenant()
    const { id, fingerprint } = await stored(tenant, "acme-login")
    const unkeyed = truncated(await sha256(`mehen/fingerprint/v1\n${tenant}\n${id}\n${VALUE}`))
    expect(fingerprint).not.toBe(unkeyed)
    const otherRoot = await importRootKey(crypto.getRandomValues(new Uint8Array(32)), 1)
    expect(fingerprint).not.toBe(await hmacFingerprint(await deriveFingerprintKey(otherRoot, tenant), id, VALUE))
  })

  it("uses a non-extractable signing key that differs per tenant", async () => {
    const a = await stored(freshTenant(), "acme-login")
    const b = await stored(freshTenant(), "acme-login")
    expect(a.key.extractable).toBe(false)
    expect(a.key.algorithm).toMatchObject({ name: "HMAC", hash: { name: "SHA-256" } })
    expect(a.key.usages).toEqual(["sign"])
    await expect(crypto.subtle.exportKey("raw", a.key)).rejects.toThrow()
    // The same value under the same item id in another tenant does not match.
    expect(await hmacFingerprint(a.key, a.id, VALUE)).toBe(a.fingerprint)
    expect(await hmacFingerprint(b.key, a.id, VALUE)).not.toBe(a.fingerprint)
  })
})
