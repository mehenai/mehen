import { KINDS, secretPrefix } from "@mehen/protocol"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { describe, expect, it } from "vitest"
import { items, secretFieldInfo } from "../src/vault/areas/items.ts"
import { freshTenant } from "./helpers.ts"

const SYSTEM = { kind: "system", reason: "test" } as const

describe("item secret field metadata", () => {
  for (const spec of Object.values(KINDS)) {
    it(`refusal/${spec.kind} returns synchronous metadata only, without opening any value bytes`, async () => {
      await runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance) => {
        const ctx = instance.context
        // A one-time code secret must be one the vault can read (base32).
        const seeds = new Set(spec.fill.filter((f) => f.input === "one-time-code").map((f) => f.source))
        const secretFields = Object.fromEntries(spec.fields.filter((f) => f.secret && f.required).map((f) => [f.name, seeds.has(f.name) ? "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" : `synthetic-secret-${spec.kind}-${f.name}-never-return-this-value`]))
        const publicFields = Object.fromEntries(spec.fields.filter((f) => !f.secret).map((f) => [f.name, `public-${f.name}`]))
        const item = await items.putItem(ctx, {
          slug: `metadata-${spec.kind}`, kind: spec.kind, provider: null, account: null, accountVerified: false,
          tags: [], ceiling: spec.defaultCeiling, binding: { hosts: ["api.example.com"] },
          policy: { default: "approve", rules: [] }, injection: null, publicFields, secretFields, description: null,
        }, SYSTEM)
        const storedBefore = ctx.sql.exec("SELECT * FROM items").toArray()
        const auditBefore = ctx.sql.exec("SELECT * FROM audit").toArray()
        const noOpen = { ...ctx, openField: async () => { throw new Error("metadata must not decrypt") }, fingerprintKey: async () => { throw new Error("metadata must not derive keys") } }
        const metadata = items.secretFieldMetadata(noOpen, item)
        expect(Array.isArray(metadata)).toBe(true)
        expect(metadata).toEqual(secretFieldInfo(ctx, item))
        expect(metadata.map((f) => f.name)).toEqual(spec.fields.filter((f) => f.secret).map((f) => f.name))
        for (const field of metadata) {
          expect(Object.keys(field).sort()).toEqual(["fingerprint", "length", "name", "prefix", "set"])
          const value = secretFields[field.name]
          if (value === undefined) {
            expect(field).toEqual({ name: field.name, set: false, length: 0, prefix: "", fingerprint: "" })
          } else {
            expect(field).toEqual({ name: field.name, set: true, length: value.length, prefix: secretPrefix(value), fingerprint: expect.stringMatching(/^[A-Za-z0-9_-]{12}$/) })
            expect(JSON.stringify(metadata)).not.toContain(value)
          }
        }
        expect(ctx.sql.exec("SELECT * FROM items").toArray()).toEqual(storedBefore)
        expect(ctx.sql.exec("SELECT * FROM audit").toArray()).toEqual(auditBefore)
      })
    })
  }

  it("optional fields report set or unset correctly across secret-only rotation", async () => {
    await runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance) => {
      const ctx = instance.context
      const item = await items.putItem(ctx, {
        slug: "metadata-optional", kind: "oauth-connection", provider: null, account: null, accountVerified: false,
        tags: [], ceiling: "relay", binding: { hosts: ["api.example.com"] }, policy: { default: "approve", rules: [] },
        injection: null, publicFields: {}, secretFields: { access_token: "synthetic-access-token" }, description: null,
      }, SYSTEM)
      expect(items.secretFieldMetadata(ctx, item).find((f) => f.name === "refresh_token")).toMatchObject({ set: false, length: 0 })
      await items.replaceSecrets(ctx, item.slug, { refresh_token: "synthetic-refresh-token" }, SYSTEM)
      expect(items.secretFieldMetadata(ctx, item).find((f) => f.name === "refresh_token")).toMatchObject({ set: true, length: 23 })
      expect(items.getItem(ctx, item.slug)?.configRev).toBe(0)
    })
  })
})
