// A person's description of a credential carries the pages a human added
// for fill (items.browser) once there are any, so the credential page can
// show and change them; a machine's description never does. The In web
// pages card saves through item.update as it is: a protected credential's
// save asks exactly what any update asks. A managed workspace refuses a
// fill ceiling or pages, as /v1/fill and the intake choice refuse there.

import { describe, expect, it } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { checkedCredential, prepareCredential, storeCredential, workspaceItemOps } from "../src/vault/areas/items-workspace.ts"
import { stepUpDigest } from "../src/vault/areas/items.ts"
import { VaultError } from "../src/http.ts"
import { setSetting } from "../src/vault/areas/workspace-runtime.ts"
import { FILL_MANAGED_REFUSAL } from "../src/vault/fill-unavailable.ts"
import { editAccessFixture } from "./access-test-support.ts"
import { credentialInput, credentialsFixture, deviceInvocation, devicePrincipal, inAccess, memberInvocation, memberPrincipal, seedCredential } from "./credentials-test-support.ts"

describe("an item's pages in its description", () => {
  it("are absent while the item has none, present on a person's description once it has, and never on a machine's", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedCredential(ctx, "typed-key")
      const person = () => workspaceItemOps["items.describe"].handler(ctx, memberPrincipal(ctx), { slug: item.slug }, memberInvocation(ctx))
      const machine = async () => workspaceItemOps["items.describe"].handler(ctx, devicePrincipal(), { slug: item.slug }, await deviceInvocation(ctx))
      expect(await person()).not.toHaveProperty("browser")
      const machineBefore = canonicalJson(await machine())
      const browser = { signinOrigins: ["https://login.example.com"], typeInto: ["https://dash.example.net"] }
      ctx.sql.exec("UPDATE items SET browser=? WHERE id=?", JSON.stringify(browser), item.id)
      expect((await person()).browser).toEqual(browser)
      expect(canonicalJson(await machine())).toBe(machineBefore)
      ctx.sql.exec("UPDATE items SET browser=NULL WHERE id=?", item.id)
      expect(await person()).not.toHaveProperty("browser")
    })
  })
})

describe("saving the In web pages card", () => {
  it("asks a protected credential's save for exactly what item.update asks: the right to change it and a passkey over the exact change", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const home = { kind: "project" as const, project: "prj_a" }
      const prepared = await prepareCredential(ctx, { ...credentialInput("protected-login", home), kind: "password-login", ceiling: "relay", injection: null, binding: { hosts: ["github.com"] }, publicFields: { url: "https://github.com/login", username: "alex@example.com" }, secretFields: { password: "not-a-real-password" } }, null)
      const item = ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
      editAccessFixture(ctx, (s) => { s.projects.find((p) => p.id === "prj_b")!.environments.find((e) => e.name === "prod")!.references.push({ variable: "LOGIN", field: "password", item: item.id, home: item.home, revision: 1 }) })
      const change = { ceiling: "fill", browser: { signinOrigins: ["https://gist.github.com"], typeInto: [] } }
      const digest = await stepUpDigest({ change, version: item.version, configRevision: item.configRev })
      const refusal = async (role: string, action?: Parameters<typeof memberInvocation>[2]) => {
        try { await workspaceItemOps["items.update"].handler(ctx, memberPrincipal(ctx, role), { slug: item.slug, change }, memberInvocation(ctx, role, action)) } catch (error) { return error instanceof VaultError ? error.toJSON() : error }
        return null
      }
      await expect(workspaceItemOps["items.action"].handler(ctx, memberPrincipal(ctx), { slug: item.slug, action: "update", change }, memberInvocation(ctx))).resolves.toEqual({ type: "item.update", item: item.id, digest })
      expect(await refusal("owner")).toEqual({ error: "forbidden", message: "This needs a passkey confirmation of the exact action." })
      expect(await refusal("guest", { type: "item.update", item: item.id, digest })).toMatchObject({ error: "forbidden" })
      expect(checkedCredential(ctx, item.slug)).toMatchObject({ ceiling: "relay", browser: null })
      expect(await refusal("owner", { type: "item.update", item: item.id, digest })).toBeNull()
      expect(checkedCredential(ctx, item.slug)).toMatchObject({ ceiling: "fill", browser: change.browser })
    })
  })
})

describe("a managed workspace's credential", () => {
  it("refuses a fill ceiling and any pages before the passkey and before any write, and still takes another change; an unmanaged one takes both", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const prepared = await prepareCredential(ctx, { ...credentialInput("managed-login", { kind: "workspace" }), kind: "password-login", ceiling: "relay", injection: null, binding: { hosts: ["github.com"] }, publicFields: { url: "https://github.com/login", username: "alex@example.com" }, secretFields: { password: "not-a-real-password" } }, null)
      const item = ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
      const changes = [{ ceiling: "fill" }, { browser: { signinOrigins: ["https://gist.github.com"], typeInto: [] } }, { browser: null }]
      const refusal = async (run: () => Promise<unknown>) => {
        try { await run() } catch (error) { return error instanceof VaultError ? error.toJSON() : error }
        return null
      }
      const prepare = (change: object) => workspaceItemOps["items.action"].handler(ctx, memberPrincipal(ctx), { slug: item.slug, action: "update", change }, memberInvocation(ctx))
      const update = async (change: object) => workspaceItemOps["items.update"].handler(ctx, memberPrincipal(ctx), { slug: item.slug, change }, memberInvocation(ctx, "owner", { type: "item.update", item: item.id, digest: await stepUpDigest({ change, version: item.version, configRevision: item.configRev }) }))
      for (const change of changes) await expect(prepare(change)).resolves.toMatchObject({ type: "item.update" })
      setSetting(ctx, "managed", { platform: "plt_fixture", subject: "sub_fixture", member: "mem_owner", createdAt: ctx.now() })
      const audit = () => ctx.sql.exec<{ n: number }>("SELECT count(*) AS n FROM audit").toArray()[0]!.n
      const before = { row: checkedCredential(ctx, item.slug), audit: audit() }
      for (const change of changes) {
        expect(await refusal(() => prepare(change))).toEqual({ error: "forbidden", message: FILL_MANAGED_REFUSAL })
        expect(await refusal(() => update(change))).toEqual({ error: "forbidden", message: FILL_MANAGED_REFUSAL })
      }
      expect(checkedCredential(ctx, item.slug)).toEqual(before.row)
      expect(audit()).toBe(before.audit)
      expect(await refusal(() => update({ ceiling: "lease" }))).toBeNull()
      expect(checkedCredential(ctx, item.slug)).toMatchObject({ ceiling: "lease", browser: null })
    })
  })
})
