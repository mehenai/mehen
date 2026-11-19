import { describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { items } from "../src/vault/areas/items.ts"
import type { NewItem } from "../src/vault/services.ts"
import { freshTenant } from "./helpers.ts"

const SYSTEM = { kind: "system", reason: "test" } as const

export function openaiItem(slug = "openai-personal", key = "sk-proj-abcdefghijklmnop"): NewItem {
  return {
    slug,
    kind: "api-key",
    provider: "openai",
    account: null,
    accountVerified: false,
    tags: ["personal"],
    ceiling: "placeholder",
    binding: { hosts: ["api.openai.com"] },
    policy: { default: "allow", rules: [] },
    injection: { in: "header", name: "Authorization", format: "Bearer {key}" },
    publicFields: {},
    secretFields: { key },
    description: null,
  }
}

describe("items service", () => {
  it("stores sealed, opens, rotates and refuses clashes", async () => {
    const stub = env.TENANT_VAULT.getByName(freshTenant())
    await runInDurableObject(stub, async (instance, state) => {
      const ctx = instance.context
      const created = await items.putItem(ctx, openaiItem(), SYSTEM)
      expect(created.version).toBe(1)
      const raw = state.storage.sql.exec<{ ciphertext: ArrayBuffer }>("SELECT ciphertext FROM item_secrets").toArray()
      expect(new TextDecoder().decode(raw[0]?.ciphertext)).not.toContain("sk-proj-abcdefghijklmnop")
      expect(await items.openSecrets(ctx, created)).toEqual({ key: "sk-proj-abcdefghijklmnop" })
      await expect(items.putItem(ctx, openaiItem(), SYSTEM)).rejects.toMatchObject({ code: "conflict" })
      const rotated = await items.replaceSecrets(ctx, "openai-personal", { key: "sk-proj-zzzzzzzzzzzzzzzz" }, SYSTEM)
      expect(rotated.version).toBe(2)
      expect(await items.openSecrets(ctx, rotated)).toEqual({ key: "sk-proj-zzzzzzzzzzzzzzzz" })
      expect(items.summarise(rotated)).toMatchObject({ slug: "openai-personal", hosts: ["api.openai.com"], status: "active" })
    })
  })

  it("validates before writing anything", async () => {
    const stub = env.TENANT_VAULT.getByName(freshTenant())
    await runInDurableObject(stub, async (instance, state) => {
      const ctx = instance.context
      await expect(items.putItem(ctx, { ...openaiItem(), binding: { hosts: [] } }, SYSTEM)).rejects.toMatchObject({ code: "bad_request" })
      await expect(items.putItem(ctx, { ...openaiItem(), ceiling: "reveal" }, SYSTEM)).rejects.toMatchObject({ code: "mode_refused" })
      // BROWSER_FILL is on in the test env; where it is off, a fill ceiling is refused.
      const off = Object.assign(Object.create(ctx) as typeof ctx, { env: { ...ctx.env, BROWSER_FILL: "off" } })
      await expect(items.putItem(off, { ...openaiItem(), ceiling: "fill" }, SYSTEM)).rejects.toMatchObject({ code: "mode_refused", message: "Typing into web pages is not available yet." })
      await expect(items.putItem(ctx, { ...openaiItem(), secretFields: {} }, SYSTEM)).rejects.toMatchObject({ code: "bad_request" })
      await expect(items.putItem(ctx, { ...openaiItem(), slug: "Bad" }, SYSTEM)).rejects.toMatchObject({ code: "bad_request" })
      expect(state.storage.sql.exec("SELECT * FROM item_secrets").toArray()).toHaveLength(0)
    })
  })

  it("accepts a fill ceiling for a kind fill can type where BROWSER_FILL is on", async () => {
    await runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance) => {
      await expect(items.putItem(instance.context, { ...openaiItem(), ceiling: "fill" }, SYSTEM)).resolves.toMatchObject({ ceiling: "fill" })
    })
  })

  it("refuses a fill ceiling for a kind that is never typed into a page, before fill's own switch", async () => {
    await runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance, state) => {
      const database: NewItem = { ...openaiItem("warehouse"), kind: "database-url", provider: null, ceiling: "fill", binding: { hosts: ["db.example.com"] }, injection: null, secretFields: { url: "postgres://synthetic@db.example.com/app" } }
      await expect(items.putItem(instance.context, database, SYSTEM)).rejects.toMatchObject({ code: "mode_refused", message: "This kind of credential cannot be typed into web pages." })
      await expect(items.putItem(instance.context, { ...database, ceiling: "lease" }, SYSTEM)).resolves.toMatchObject({ ceiling: "lease" })
      expect(state.storage.sql.exec("SELECT * FROM items WHERE ceiling = 'fill'").toArray()).toHaveLength(0)
    })
  })

  it("reads every one-time code secret before storing or rotating it, and refuses one it cannot read without repeating it", async () => {
    await runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance, state) => {
      const ctx = instance.context
      const seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
      const totp: NewItem = { ...openaiItem("github-codes"), kind: "totp", provider: null, ceiling: "relay", binding: { hosts: ["github.com"] }, injection: null, secretFields: { seed } }
      const login: NewItem = { ...totp, slug: "github-login", kind: "password-login", publicFields: { url: "https://github.com/login", username: "alex@example.com" }, secretFields: { password: "synthetic-password" } }
      const unreadable = ["SYNTHETICUNREADABLE1", "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&encoder=steam", "JBSWY3DP", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&digits=9"]
      for (const bad of unreadable) {
        for (const [item, field] of [[totp, "seed"], [login, "totp_seed"]] as const) {
          const refusal = await items.putItem(ctx, { ...item, secretFields: { ...item.secretFields, [field]: bad } }, SYSTEM).catch((error: unknown) => error)
          expect(refusal).toMatchObject({ code: "totp_unreadable", message: expect.stringMatching(/^The one-time code secret cannot be read\. /) })
          expect(JSON.stringify(refusal)).not.toContain(bad)
        }
      }
      expect(state.storage.sql.exec("SELECT * FROM items").toArray()).toHaveLength(0)
      await items.putItem(ctx, totp, SYSTEM)
      await items.putItem(ctx, login, SYSTEM)
      await items.putItem(ctx, { ...login, slug: "github-login-codes", secretFields: { password: "synthetic-password", totp_seed: `otpauth://totp/GitHub:alex?secret=${seed}&algorithm=SHA256&digits=8&period=60` } }, SYSTEM)
      await expect(items.replaceSecrets(ctx, "github-codes", { seed: "SYNTHETICUNREADABLE1" }, SYSTEM)).rejects.toMatchObject({ code: "totp_unreadable" })
      await expect(items.replaceSecrets(ctx, "github-login", { totp_seed: "otpauth://hotp/x?secret=AAAA" }, SYSTEM)).rejects.toMatchObject({ code: "totp_unreadable" })
      expect(await items.openSecrets(ctx, items.getItem(ctx, "github-codes")!)).toEqual({ seed })
      await expect(items.replaceSecrets(ctx, "github-codes", { seed: seed.toLowerCase() }, SYSTEM)).resolves.toMatchObject({ version: 2 })
    })
  })
})
