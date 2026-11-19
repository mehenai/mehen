import { describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { evaluatePolicyFloor } from "@mehen/protocol/policy-safety"
import { parseDestination } from "@mehen/protocol"
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

  it("lists a Drive-bound item's Drive floors, not Calendar's on the same host; a host-wide binding still lists both", async () => {
    await runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance) => {
      const ctx = instance.context
      await policyFixture(ctx, { slug: "drive-key", binding: { hosts: ["www.googleapis.com"], paths: ["/drive/v3/**", "/upload/drive/v3/**"] }, policy: { default: "allow", rules: [] }, provider: null })
      const drive = describeItem(ctx, items.getItem(ctx, "drive-key")!).policyFloor!.map((floor) => floor.id)
      expect(drive).toEqual(["google-drive.floor-1", "google-drive.floor-2", "google-drive.floor-3", "google-drive.floor-4"])
      await policyFixture(ctx, { slug: "google-key", binding: { hosts: ["www.googleapis.com"] }, policy: { default: "allow", rules: [] }, provider: null })
      const wide = describeItem(ctx, items.getItem(ctx, "google-key")!).policyFloor!.map((floor) => floor.id)
      expect(wide).toEqual(expect.arrayContaining(["google-calendar.floor-1", "google-drive.floor-1"]))
    })
  })

  // The relay matches a floor against every loose form of the path (a
  // format suffix or matrix parameters cut, decoded, case folded), so the
  // projection keeps every floor that could meet one of them: it never
  // hides one the relay applies.
  for (const path of ["/drive/v3/files/123/watch.json", "/drive/v3/files/123/watch;alt=json", "/drive/v3/files/123/%57atch"])
    it(`lists every floor the relay applies at ${path}`, async () => {
      await runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance) => {
        const ctx = instance.context
        await policyFixture(ctx, { slug: "drive-one", binding: { hosts: ["www.googleapis.com"], paths: [path] }, policy: { default: "allow", rules: [] }, provider: null })
        const dest = parseDestination("POST", `https://www.googleapis.com${path}`)
        if (!dest.ok) throw new Error(`destination ${path}`)
        const applied = evaluatePolicyFloor({ destination: dest.destination, body: null })
        expect(applied.action).toBe("deny")
        const projected = describeItem(ctx, items.getItem(ctx, "drive-one")!).policyFloor!.map((floor) => floor.id)
        expect(projected).toEqual(expect.arrayContaining(applied.reasons))
      })
    })
})
