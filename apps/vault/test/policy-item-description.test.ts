import { describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { describeItem, items } from "../src/vault/areas/items.ts"
import { freshTenant } from "./helpers.ts"
import { policyFixture } from "./policy-fixtures.ts"

describe("item policyFloor projection", () => {
  it("always sends policyFloor, including an empty list for an unreviewed host, without opening secrets", async () => {
    await runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance) => {
      const ctx = instance.context
      await policyFixture(ctx)
      const guarded = { ...ctx, openField: async () => { throw new Error("description must not open secrets") } }
      const custom = describeItem(guarded, items.getItem(ctx, "custom-key")!)
      expect(custom).toHaveProperty("policyFloor", [])
      await policyFixture(ctx, { slug: "github-key", binding: { hosts: ["*.github.com"] }, policy: { default: "allow", rules: [] }, provider: null })
      const known = describeItem(guarded, items.getItem(ctx, "github-key")!)
      expect(known.policyFloor!.length).toBeGreaterThan(0)
      expect(known.policyFloor!.every((floor) => floor.rule.action !== "allow" && floor.ruleDigest.length === 43)).toBe(true)
    })
  })
})
