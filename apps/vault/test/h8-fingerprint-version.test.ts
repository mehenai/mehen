// Each fingerprint is stored with the root
// version whose key wrote it, so it is only ever compared under that key,
// and one written under an older root, or with no version at all (possibly
// the old unkeyed SHA-256), is recomputed the next time the secret is opened.

import { describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { base64UrlEncode, sha256 } from "@mehen/protocol"
import { fingerprint, items } from "../src/vault/areas/items.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { TenantKeys, deriveFingerprintKey, parseRootKeys } from "../src/vault/keys.ts"
import type { ItemRecord, NewItem } from "../src/vault/services.ts"
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

type Stored = { fingerprint: string; fp_version: number | null }

function storedRow(ctx: VaultContext, item: ItemRecord): Stored {
  return ctx.sql.exec<Stored>("SELECT fingerprint, fp_version FROM item_secrets WHERE item = ? AND name = 'key'", item.id).one()
}

async function hmac(key: CryptoKey, itemId: string, value: string): Promise<string> {
  return base64UrlEncode(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${itemId}\n${value}`))).slice(0, 12)
}

// The test vault's root key as version 1, and a fresh one as version 2.
function rotatedRing(): { json: string; ring: ReturnType<typeof parseRootKeys> } {
  const current = JSON.parse(env.ROOT_KEYS) as Record<string, string>
  const json = JSON.stringify({ ...current, "2": base64UrlEncode(crypto.getRandomValues(new Uint8Array(32))) })
  return { json, ring: parseRootKeys(json) }
}

// The same DO storage, seen by a deployment whose current root is version 2.
function afterRotation(ctx: VaultContext): { ctx: VaultContext; keys: TenantKeys } {
  const keys = new TenantKeys(rotatedRing().ring, ctx.tenant)
  const rotated: VaultContext = { ...ctx, rootVersion: keys.current, fingerprintKey: (version) => keys.fingerprintKey(version) }
  return { ctx: rotated, keys }
}

function inVault(fn: (ctx: VaultContext) => Promise<void>): Promise<void> {
  return runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance) => fn(instance.context))
}

describe("fingerprint root version", () => {
  it("stores the root version beside each new fingerprint and matches it under that version's key", async () => {
    await inVault(async (ctx) => {
      const item = await items.putItem(ctx, apiKeyItem("acme-login"), SYSTEM)
      const row = storedRow(ctx, item)
      expect(row.fp_version).toBe(ctx.rootVersion)
      expect(row.fingerprint).toBe(await fingerprint(ctx, item.id, VALUE, row.fp_version as number))
    })
  })

  it("derives a distinct key for each root version, and refuses a version that is not configured", async () => {
    await inVault(async (ctx) => {
      const { keys } = afterRotation(ctx)
      expect(keys.current).toBe(2)
      const ring = parseRootKeys(env.ROOT_KEYS)
      const root1 = await ring.versions.get(1)
      if (!root1) throw new Error("no root key 1")
      expect(await hmac(await keys.fingerprintKey(1), "itm_x", VALUE)).toBe(await hmac(await deriveFingerprintKey(root1, ctx.tenant), "itm_x", VALUE))
      expect(await hmac(await keys.fingerprintKey(2), "itm_x", VALUE)).not.toBe(await hmac(await keys.fingerprintKey(1), "itm_x", VALUE))
      await expect(keys.fingerprintKey(3)).rejects.toThrow("root key version 3 is not configured")
    })
  })

  it("keeps an old-root fingerprint comparable after a rotation, then recomputes it under the new root when the secret is opened", async () => {
    await inVault(async (ctx) => {
      const item = await items.putItem(ctx, apiKeyItem("acme-login"), SYSTEM)
      const before = storedRow(ctx, item)
      const { ctx: rotated } = afterRotation(ctx)
      // Compared under the version stored with it, the old fingerprint still matches.
      expect(await fingerprint(rotated, item.id, VALUE, before.fp_version as number)).toBe(before.fingerprint)
      expect(await fingerprint(rotated, item.id, VALUE, 2)).not.toBe(before.fingerprint)

      expect(await items.openSecrets(rotated, item)).toEqual({ key: VALUE })
      const after = storedRow(ctx, item)
      expect(after.fp_version).toBe(2)
      expect(after.fingerprint).toBe(await fingerprint(rotated, item.id, VALUE, 2))
    })
  })

  it("recomputes a fingerprint stored with no version, such as the old unkeyed hash, on the next open", async () => {
    await inVault(async (ctx) => {
      const item = await items.putItem(ctx, apiKeyItem("acme-login"), SYSTEM)
      const unkeyed = base64UrlEncode(await sha256(`mehen/fingerprint/v1\n${ctx.tenant}\n${item.id}\n${VALUE}`)).slice(0, 12)
      ctx.sql.exec("UPDATE item_secrets SET fingerprint = ?, fp_version = NULL WHERE item = ?", unkeyed, item.id)

      expect(await items.openSecrets(ctx, item)).toEqual({ key: VALUE })
      const row = storedRow(ctx, item)
      expect(row).toEqual({ fingerprint: await fingerprint(ctx, item.id, VALUE, ctx.rootVersion), fp_version: ctx.rootVersion })
      expect(row.fingerprint).not.toBe(unkeyed)
    })
  })

  it("leaves a current fingerprint alone when the secret is opened", async () => {
    await inVault(async (ctx) => {
      const item = await items.putItem(ctx, apiKeyItem("acme-login"), SYSTEM)
      const before = storedRow(ctx, item)
      ctx.sql.exec("UPDATE item_secrets SET fingerprint = 'sentinel' WHERE item = ?", item.id)
      await items.openSecrets(ctx, item)
      expect(storedRow(ctx, item)).toEqual({ fingerprint: "sentinel", fp_version: before.fp_version })
    })
  })
})
