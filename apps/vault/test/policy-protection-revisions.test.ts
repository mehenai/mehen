import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { describe, expect, it } from "vitest"
import { projects } from "../src/vault/areas/projects.ts"
import { type VaultContext, one } from "../src/vault/core.ts"
import { freshTenant } from "./helpers.ts"

const withVault = (fn: (ctx: VaultContext) => Promise<void>) => runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), (instance) => fn(instance.context))

describe("policy protection revisions", () => {
  it("missing revision reads zero; synchronous bumpers store monotonic integer text and roll back", async () => {
    await withVault(async (ctx) => {
      expect(projects.protectionRevision(ctx)).toBe(0)
      expect(() => ctx.storage.transactionSync(() => { projects.bumpProtectionRevision(ctx); throw new Error("rollback") })).toThrow("rollback")
      expect(projects.protectionRevision(ctx)).toBe(0)
      for (const revision of [1, 2, 3]) {
        projects.bumpProtectionRevision(ctx)
        expect(projects.protectionRevision(ctx)).toBe(revision)
        expect(one(ctx.sql.exec<{ value: string }>("SELECT value FROM tenant_state WHERE key = 'protection_rev'"))?.value).toBe(String(revision))
      }
    })
  })
})
