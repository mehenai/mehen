import { describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { POLICY_FLOOR, evaluatePolicyFloor } from "@mehen/protocol/policy-safety"
import { checkBinding, parseDestination } from "@mehen/protocol"
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

  // A * in a binding admits one segment, which the relay's loose reading
  // can split in several (a fullwidth solidus normalises to "/"): Drive's
  // sharing floor applies to such a request, so the projection lists it.
  it("lists the floor a request admitted by a * segment meets once its segment splits under loose reading", async () => {
    await runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance) => {
      const ctx = instance.context
      const binding = { hosts: ["www.googleapis.com"], paths: ["/drive/v3/files/*"] }
      await policyFixture(ctx, { slug: "drive-files", binding, policy: { default: "allow", rules: [] }, provider: null })
      const dest = parseDestination("POST", "https://www.googleapis.com/drive/v3/files/123%EF%BC%8Fpermissions")
      if (!dest.ok) throw new Error("destination")
      expect(checkBinding(binding, dest.destination).ok).toBe(true)
      const applied = evaluatePolicyFloor({ destination: dest.destination, body: null })
      // The floor entries the relay applied (its other reasons are not floors a view lists).
      const floors = applied.reasons.filter((reason) => POLICY_FLOOR.some((f) => f.id === reason))
      expect(floors).toContain("google-drive.floor-1")
      const projected = describeItem(ctx, items.getItem(ctx, "drive-files")!).policyFloor!.map((floor) => floor.id)
      expect(projected).toEqual(expect.arrayContaining(floors))
    })
  })

  // A * segment can also normalise to "#" or "?" under loose reading and so
  // end the path there: Graph's $batch floor applies to such a request, so
  // the projection lists it though the binding names a segment after it.
  it("lists the floor a request admitted by a * segment meets once its segment ends the path under loose reading", async () => {
    await runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance) => {
      const ctx = instance.context
      const binding = { hosts: ["graph.microsoft.com"], paths: ["/v1.0/*/tail"] }
      await policyFixture(ctx, { slug: "graph-tail", binding, policy: { default: "allow", rules: [] }, provider: null })
      const dest = parseDestination("POST", "https://graph.microsoft.com/v1.0/$batch%EF%BC%83/tail")
      if (!dest.ok) throw new Error("destination")
      expect(checkBinding(binding, dest.destination).ok).toBe(true)
      const applied = evaluatePolicyFloor({ destination: dest.destination, body: null })
      const floors = applied.reasons.filter((reason) => POLICY_FLOOR.some((f) => f.id === reason))
      expect(floors.length).toBeGreaterThan(0)
      const projected = describeItem(ctx, items.getItem(ctx, "graph-tail")!).policyFloor!.map((floor) => floor.id)
      expect(projected).toEqual(expect.arrayContaining(floors))
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
