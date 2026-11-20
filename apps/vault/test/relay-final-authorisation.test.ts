import { afterEach, describe, expect, it } from "vitest"
import { env } from "cloudflare:workers"
import { runInDurableObject } from "cloudflare:test"
import { authoriseRelay } from "../src/vault/areas/relay.ts"
import { items } from "../src/vault/areas/items.ts"
import { forwardRelay } from "../src/relay/forward.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { freshTenant, testDevice } from "./helpers.ts"
import { POLICY_DEVICE, registerPolicyDevice } from "./policy-fixtures.ts"
import { credentialInput } from "./credentials-test-support.ts"
import { fixtureSql } from "./fixture-sql.ts"
afterEach(() => setUpstreamFetch(null))
const request = { item: "final-key", method: "GET", url: "https://api.example.com/test", headers: [] }
describe("relay final authorisation and its honest limit", () => {
  it("discards decrypted material when revocation wins before the final point", async () => {
    const { credentialsFixture, inAccess, devicePrincipal, deviceInvocation, seedCredential } = await import("./credentials-test-support.ts")
    const { authoriseWorkspaceRelay } = await import("../src/vault/areas/relay-workspace.ts")
    const { checkedCredential } = await import("../src/vault/areas/items-workspace.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      await seedCredential(ctx, "final-key")
      let opens = 0, sends = 0
      setUpstreamFetch(async () => { sends++; return new Response("ok") })
      const wrapped = { ...ctx, async openField(ref: Parameters<typeof ctx.openField>[0], sealed: Parameters<typeof ctx.openField>[1]) {
        const value = await ctx.openField(ref, sealed)
        opens++
        ctx.sql.exec("UPDATE devices SET revoked_at=? WHERE id='dev_member'", ctx.now())
        return value
      } }
      await expect(authoriseWorkspaceRelay(wrapped, devicePrincipal(), request, await deviceInvocation(ctx))).rejects.toMatchObject({ code: "not_found", message: 'No credential called "final-key".' })
      expect(opens).toBe(1)
      expect(sends).toBe(0)
      expect(checkedCredential(ctx,"final-key")?.lastUsedAt).toBeNull()
      expect(ctx.sql.exec("SELECT * FROM audit WHERE action='relay.allow'").toArray()).toEqual([])
    })
  })

  it("lets one already-authorised handoff finish, without authorising a second send", async () => {
    const tenant = freshTenant()
    await runInDurableObject(env.TENANT_VAULT.getByName(tenant), async (instance) => {
      const ctx = instance.context, p = testDevice({ device: POLICY_DEVICE })
      await registerPolicyDevice(ctx, p)
      await items.putItem(ctx, credentialInput("final-key"), { kind: "system", reason: "fixture" })
      let sends = 0
      setUpstreamFetch(async () => { sends++; return new Response("ok"); })
      const material = await authoriseRelay(ctx, p, request)
      ctx.sql.exec("UPDATE devices SET revoked_at=? WHERE id=?", ctx.now(), POLICY_DEVICE)
      const response = await forwardRelay(material, null)
      expect(await response.text()).toBe("ok")
      expect(sends).toBe(1)
      await expect(authoriseRelay(ctx, p, request)).rejects.toMatchObject({ code: "forbidden", message: "This device is not active." })
      expect(sends).toBe(1)
      expect(ctx.sql.exec<{
        n: number
      }>("SELECT count(*) AS n FROM audit WHERE action='relay.allow'").toArray()[0]?.n).toBe(1)
    })
  })
})
const gmailRequest = { item: "gmail-test", method: "GET", url: "https://gmail.googleapis.com/gmail/v1/users/me/labels", headers: [] }
for (const revoked of [false, true]) it(`workspace relay ${revoked ? "refuses revoked device after" : "succeeds with"} its own OAuth refresh`, async () => {
  const { credentialsFixture, inAccess, devicePrincipal, deviceInvocation, seedOAuthConnection } = await import("./credentials-test-support.ts")
  const { authoriseWorkspaceRelay } = await import("../src/vault/areas/relay-workspace.ts")
  const { checkedCredential } = await import("../src/vault/areas/items-workspace.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async ctx => {
    const before = await seedOAuthConnection(ctx)
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=?", ctx.now()-1)
    let sends = 0
    setUpstreamFetch(async () => {
      sends++
      if (revoked) ctx.sql.exec("UPDATE devices SET revoked_at=? WHERE id='dev_member'", ctx.now())
      return Response.json({ access_token: "refreshed-access", expires_in: 3600 })
    })
    const pending = authoriseWorkspaceRelay(ctx, devicePrincipal(), gmailRequest, await deviceInvocation(ctx))
    if (revoked) await expect(pending).rejects.toMatchObject({ code: "not_found", message: 'No credential called "gmail-test".' })
    else expect((await pending).headers).toContainEqual(["authorization", "Bearer refreshed-access"])
    expect(sends).toBe(1)
    const current = checkedCredential(ctx, "gmail-test")!
    expect(current.version).toBe(before.version+1)
    expect(current.configRev).toBe(before.configRev)
    if (revoked) expect(current.lastUsedAt).toBeNull()
  })
})

for (const race of ["freeze", "suspended-owner"] as const) it(`rechecks ${race} after workspace opening, without material, send or use metadata`, async () => {
  const { credentialsFixture, inAccess, devicePrincipal, deviceInvocation, seedCredential } = await import("./credentials-test-support.ts")
  const { authoriseWorkspaceRelay } = await import("../src/vault/areas/relay-workspace.ts")
  const { checkedCredential } = await import("../src/vault/areas/items-workspace.ts")
  const { setSetting } = await import("../src/vault/areas/workspace-runtime.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async ctx => {
    await seedCredential(ctx,"final-key")
    let sends=0,opens=0
    setUpstreamFetch(async()=>{sends++;return new Response("unexpected")})
    const wrapped={...ctx,async openField(ref:Parameters<typeof ctx.openField>[0],sealed:Parameters<typeof ctx.openField>[1]){
      const value=await ctx.openField(ref,sealed);opens++
      if(race === "freeze")setSetting(ctx,"frozen",true)
      else fixtureSql(ctx).exec("UPDATE members SET status='suspended' WHERE id='mem_member'")
      return value
    }}
    await expect(authoriseWorkspaceRelay(wrapped,devicePrincipal(),request,await deviceInvocation(ctx))).rejects.toMatchObject(race === "freeze"?{code:"frozen",message:"This workspace is frozen."}:{code:"not_found",message:'No credential called "final-key".'})
    expect(opens).toBe(1);expect(sends).toBe(0)
    expect(checkedCredential(ctx,"final-key")?.lastUsedAt).toBeNull()
    expect(ctx.sql.exec("SELECT * FROM audit WHERE action='relay.allow'").toArray()).toEqual([])
  })
})

it("lets an already-authorised workspace handoff finish once, but authorises no second send", async () => {
  const { credentialsFixture,inAccess,devicePrincipal,deviceInvocation,seedCredential }=await import("./credentials-test-support.ts")
  const {authoriseWorkspaceRelay}=await import("../src/vault/areas/relay-workspace.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    await seedCredential(ctx,"final-key")
    let sends=0
    setUpstreamFetch(async()=>{sends++;return new Response("ok")})
    const material=await authoriseWorkspaceRelay(ctx,devicePrincipal(),request,await deviceInvocation(ctx))
    ctx.sql.exec("UPDATE devices SET revoked_at=? WHERE id='dev_member'",ctx.now())
    expect(await (await forwardRelay(material,null)).text()).toBe("ok")
    await expect(authoriseWorkspaceRelay(ctx,devicePrincipal(),request,await deviceInvocation(ctx))).rejects.toMatchObject({code:"not_found",message:"No such machine."})
    expect(sends).toBe(1)
  })
})
