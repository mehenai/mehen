import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { describe, expect, it } from "vitest"
import { items, itemsArea } from "../src/vault/areas/items.ts"
import { type VaultContext, one } from "../src/vault/core.ts"
import type { NewItem } from "../src/vault/services.ts"
import { applyMigrations } from "../src/vault/tenant-vault.ts"
import { freshTenant } from "./helpers.ts"
import { fixtureSql } from "./fixture-sql.ts"
import { withTrustedSchema } from "../src/vault/areas/management-guard.ts"

const SYSTEM = { kind: "system", reason: "test" } as const
const INPUT: NewItem = {
  slug: "revision-key", kind: "api-key", provider: null, account: null, accountVerified: false,
  tags: [], ceiling: "placeholder", binding: { hosts: ["api.example.com"] },
  policy: { default: "approve", rules: [] }, injection: null, publicFields: {},
  secretFields: { key: "synthetic-revision-secret" }, description: "A",
}

function auditCount(ctx: VaultContext) {
  return one(ctx.sql.exec<{ n: number }>("SELECT count(*) AS n FROM audit"))?.n
}

// The posture tables come after every migration these tests rewind to.
const dropPostureTables = (ctx: VaultContext) => { for (const table of ["posture_nudge_quiet", "posture_ask_counts", "item_postures"]) withTrustedSchema(ctx, () => ctx.sql.exec(`DROP TABLE ${table}`)) }
const withVault = (fn: (ctx: VaultContext) => Promise<void>) => runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), (instance) => fn(instance.context))

describe("item policy revisions", () => {
  it("backfills existing items at zero through the append-only migration", async () => {
    await withVault(async (ctx) => {
      await items.putItem(ctx, INPUT, SYSTEM)
      const index = itemsArea.migrations.findIndex((migration) => migration.includes("ADD COLUMN config_rev"))
      dropPostureTables(ctx)
      withTrustedSchema(ctx, () => ctx.sql.exec("DROP TABLE item_secret_history"))
      withTrustedSchema(ctx, () => ctx.sql.exec("DROP TABLE credential_dependencies"))
      for (const column of ["pushable", "browser", "dependency_revision", "home_id", "home_kind", "config_rev"]) withTrustedSchema(ctx, () => ctx.sql.exec(`ALTER TABLE items DROP COLUMN ${column}`))
      ctx.sql.exec("UPDATE _migrations SET applied = ? WHERE area = 'items'", index)
      withTrustedSchema(ctx, () => applyMigrations(ctx.sql, ctx.storage, [itemsArea]))
      expect(items.getItem(ctx, INPUT.slug)?.configRev).toBe(0)
      withTrustedSchema(ctx, () => applyMigrations(ctx.sql, ctx.storage, [itemsArea]))
      expect(items.getItem(ctx, INPUT.slug)?.configRev).toBe(0)
    })
  })

  it("adds the replaced-value history table to a tenant on the previous schema, keeping its items and secrets", async () => {
    await withVault(async (ctx) => {
      const original = await items.putItem(ctx, INPUT, SYSTEM)
      const secrets = () => ctx.sql.exec("SELECT item,name,fingerprint,length FROM item_secrets").toArray()
      const before = secrets()
      const index = itemsArea.migrations.findIndex((migration) => migration.includes("CREATE TABLE item_secret_history"))
      expect(index).toBe(itemsArea.migrations.length - 4)
      dropPostureTables(ctx)
      withTrustedSchema(ctx, () => ctx.sql.exec("DROP TABLE item_secret_history"))
      withTrustedSchema(ctx, () => ctx.sql.exec("ALTER TABLE items DROP COLUMN browser"))
      withTrustedSchema(ctx, () => ctx.sql.exec("ALTER TABLE items DROP COLUMN pushable"))
      ctx.sql.exec("UPDATE _migrations SET applied = ? WHERE area = 'items'", index)
      withTrustedSchema(ctx, () => applyMigrations(ctx.sql, ctx.storage, [itemsArea]))
      expect(items.getItem(ctx, INPUT.slug)).toMatchObject({ id: original.id, version: 1 })
      expect(secrets()).toEqual(before)
      expect(ctx.sql.exec("SELECT count(*) AS n FROM item_secret_history").toArray()).toEqual([{ n: 0 }])
    })
  })

  it("adds fill's browser column to a tenant on the previous schema: its items have no pages and keep their revisions", async () => {
    await withVault(async (ctx) => {
      const original = await items.putItem(ctx, INPUT, SYSTEM)
      const index = itemsArea.migrations.findIndex((migration) => migration.includes("ADD COLUMN browser"))
      expect(index).toBe(itemsArea.migrations.length - 3)
      dropPostureTables(ctx)
      withTrustedSchema(ctx, () => ctx.sql.exec("ALTER TABLE items DROP COLUMN browser"))
      withTrustedSchema(ctx, () => ctx.sql.exec("ALTER TABLE items DROP COLUMN pushable"))
      ctx.sql.exec("UPDATE _migrations SET applied = ? WHERE area = 'items'", index)
      withTrustedSchema(ctx, () => applyMigrations(ctx.sql, ctx.storage, [itemsArea]))
      expect(items.getItem(ctx, INPUT.slug)).toEqual({ ...original, browser: null })
      expect(await items.openSecrets(ctx, original)).toEqual(INPUT.secretFields)
      const browser = { signinOrigins: ["https://login.example.com"], typeInto: [] }
      fixtureSql(ctx).exec("UPDATE items SET browser = ? WHERE id = ?", JSON.stringify(browser), original.id)
      expect(items.getItem(ctx, INPUT.slug)?.browser).toEqual(browser)
    })
  })

  // The legacy refresher's path and the whole-item replace keep nothing:
  // only a person's rotation through storeCredential does.
  it("keeps no replaced value for replaceSecrets or a whole-item replace", async () => {
    await withVault(async (ctx) => {
      await items.putItem(ctx, INPUT, SYSTEM)
      await items.replaceSecrets(ctx, INPUT.slug, { key: "synthetic-refreshed-secret" }, SYSTEM)
      await items.putItem(ctx, INPUT, SYSTEM, { replace: true })
      expect(ctx.sql.exec("SELECT count(*) AS n FROM item_secret_history").toArray()).toEqual([{ n: 0 }])
    })
  })

  it("whole-item replacement advances, including identical replacements; deleted ids are never reused", async () => {
    await withVault(async (ctx) => {
      const original = await items.putItem(ctx, INPUT, SYSTEM)
      for (const revision of [1, 2]) {
        const replaced = await items.putItem(ctx, INPUT, SYSTEM, { replace: true })
        expect(replaced).toMatchObject({ id: original.id, configRev: revision, version: revision + 1 })
      }
      items.deleteItem(ctx, items.getItem(ctx, INPUT.slug)!, SYSTEM)
      const recreated = await items.putItem(ctx, INPUT, SYSTEM)
      expect(recreated.id).not.toBe(original.id)
      expect(recreated.configRev).toBe(0)
    })
  })

  it("refusal/audit and seal failures leave replacement state, secrets and revision intact", async () => {
    await withVault(async (ctx) => {
      const original = await items.putItem(ctx, INPUT, SYSTEM)
      const before = auditCount(ctx)
      const replacement = { ...INPUT, description: "B", secretFields: { key: "synthetic-replacement-secret" } }
      const failingAudit = { ...ctx, audit: () => { throw new Error("synthetic audit failure") } }
      await expect(items.putItem(failingAudit, replacement, SYSTEM, { replace: true })).rejects.toThrow("synthetic audit failure")
      const failingSeal = { ...ctx, sealField: async () => { throw new Error("synthetic seal failure") } }
      await expect(items.putItem(failingSeal, replacement, SYSTEM, { replace: true })).rejects.toThrow("synthetic seal failure")
      expect(items.getItem(ctx, INPUT.slug)).toEqual(original)
      expect(auditCount(ctx)).toBe(before)
      expect(await items.openSecrets(ctx, original)).toEqual(INPUT.secretFields)
    })
  })
})
