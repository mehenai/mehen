import { afterEach, expect, it } from "vitest"
import { env } from "cloudflare:workers"
import { runInDurableObject } from "cloudflare:test"
import { createWorkspaceFixture } from "./workspace-fixtures.ts"
import { seedAccessStateForTests } from "./access-test-support.ts"
import { workspaceBrowser } from "./l2-helpers.ts"
import { WORKSPACE_ROUTES } from "../src/routes/workspace-prefix.ts"
import { workspaceItemsRoutes } from "../src/routes/items-workspace.ts"
import { workspaceOAuthRoutes } from "../src/routes/oauth-workspace.ts"
import { registerCredentialProvider } from "../src/vault/areas/items-workspace.ts"
import { setSetting } from "../src/vault/areas/workspace-runtime.ts"
import { seedCredential } from "./credentials-test-support.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"

afterEach(() => setUpstreamFetch(null))
it("serves registered prefixed credential routes through the real directory, session and DO authority", async () => {
  const f = await createWorkspaceFixture(), routes = [...workspaceItemsRoutes, ...workspaceOAuthRoutes]
  WORKSPACE_ROUTES.push(...routes)
  try {
    await runInDurableObject(env.TENANT_VAULT.getByName(f.workspaces.work), async (instance) => {
      const ctx = instance.context

      seedAccessStateForTests(ctx, f.state)
      setSetting(ctx, "workspace", { id: f.workspaces.work, slug: "northwind", name: "Work" })
      registerCredentialProvider()
      await seedCredential(ctx, "route-public")
      await seedCredential(ctx, "route-hidden", { kind: "member", member: "mem_member" })
    })
    const browser = workspaceBrowser(f.env, f.cookie, "northwind")
    const list = await browser.get("/items")
    expect(list.status).toBe(200)
    expect(await list.json()).toMatchObject({ items: [{ slug: "route-public", home: { kind: "workspace" } }] })
    const a = await browser.get("/items/route-hidden"), b = await browser.get("/items/route-absent")
    expect(a.status).toBe(404)
    expect(b.status).toBe(404)
    expect(a.headers.has("Mehen-Item")).toBe(false)
    expect((await a.text()).replaceAll("route-hidden", "X")).toBe((await b.text()).replaceAll("route-absent", "X"))
    const created = await browser.post("/intakes", { slug: "route-intake", provider: "openai", home: "private" })
    expect(created.status).toBe(201)
    const intake = await created.json() as {
      intake: string
      url: string
    }
    expect(intake.url).toContain("/w/northwind/i/")
    const view = await browser.get(`/intakes/${intake.intake}`)
    expect(view.status).toBe(200)
    const body = await view.json() as Record<string, unknown>
    expect(body).toMatchObject({ home: { kind: "member", member: "mem_owner" }, intent: "create", target: null, client: null, fields: [{ name: "key", secret: true }], binding: { value: { hosts: ["api.openai.com"] }, verified: true } })
    expect(JSON.stringify(body)).not.toContain("test-secret-never-returned")
    // A restore names the versions its page showed; with none kept since, it
    // refuses as changed before any passkey is checked.
    const stale = await browser.post("/items/route-public/restore", { version: 1, previous: 1, stepUp: { nonce: "unchecked", assertion: {} } })
    expect(stale.status).toBe(409)
    expect(await stale.json()).toEqual({ error: "conflict", message: "The credential changed; review and try again." })
    expect((await browser.post("/items/route-public/restore", { version: 1, stepUp: { nonce: "unchecked", assertion: {} } })).status).toBe(400)
    expect((await browser.post("/items/route-public/restore", { version: 1, previous: 1, stepUp: { nonce: "unchecked", assertion: {} } }, { origin: "https://elsewhere.example" })).status).toBe(403)
    // A posture names the revision its page showed; one set since refuses
    // as changed before any passkey is checked, and a cross-site post never lands.
    const stalePosture = await browser.post("/items/route-public/posture", { posture: { level: "ask", machines: null }, rev: 3, stepUp: { nonce: "unchecked", assertion: {} } })
    expect(stalePosture.status).toBe(409)
    expect(await stalePosture.json()).toEqual({ error: "conflict", message: "How careful this credential is changed; review and try again." })
    expect((await browser.post("/items/route-public/posture", { posture: { level: "routine", machines: ["dev_b", "dev_a"] }, rev: 0, stepUp: { nonce: "unchecked", assertion: {} } })).status).toBe(400)
    expect((await browser.post("/items/route-public/posture", { posture: { level: "ask", machines: null }, rev: 0, stepUp: { nonce: "unchecked", assertion: {} } }, { origin: "https://elsewhere.example" })).status).toBe(403)
    const planned = await browser.post("/items/route-public/action", { action: "posture", posture: { level: "ask", machines: null }, rev: 0 })
    expect(planned.status).toBe(200)
    expect(await planned.json()).toMatchObject({ type: "item.posture", level: "ask", digest: expect.any(String) })
    const nudges = await browser.get("/nudges")
    expect(nudges.status).toBe(200)
    expect(await nudges.json()).toEqual({ nudges: [] })
  }
  finally {
    for (const route of routes) {
      const index = WORKSPACE_ROUTES.indexOf(route)
      if (index >= 0)
        WORKSPACE_ROUTES.splice(index, 1)
    }
  }
})
it("allows signed own-ask cancellation, hides another machine's ids through the default workspace dispatcher", async () => {
  const { credentialsFixture, inAccess } = await import("./credentials-test-support.ts")
  const { newDeviceKey, publicJwk } = await import("./devices.ts")
  const { createProof, webCryptoSigner } = await import("@mehen/protocol")
  const { fetchWorkspaceWorker, fetchWorker, ORIGIN } = await import("./helpers.ts")
  const f = await credentialsFixture(), owner = await newDeviceKey(), other = await newDeviceKey()
  await inAccess(f.tenant, async (ctx) => {
    ctx.sql.exec("UPDATE devices SET jwk=? WHERE id='dev_member'", JSON.stringify(await publicJwk(owner)))
    ctx.sql.exec("UPDATE devices SET jwk=? WHERE id='dev_kim'", JSON.stringify(await publicJwk(other)))
  })
  const call = async (device: string, keys: CryptoKeyPair, path: string, input: unknown = {}) => {
    const body = JSON.stringify(input), proof = await createProof(webCryptoSigner(device, keys.privateKey), { method: "POST", url: `${ORIGIN}${path}`, body }, { tenant: f.tenant })
    return fetchWorkspaceWorker({ ...env }, path, { method: "POST", headers: { "Mehen-Proof": proof, "content-type": "application/json" }, body })
  }
  const created = await call("dev_member", owner, "/v1/intakes", { kind: "api-key", slug: "cancel-own", reason: "test", home: "project", project: "prj_a", binding: { hosts: ["api.example.com"] } })
  expect(created.status).toBe(201)
  const { intake } = await created.json() as {
    intake: string
  }
  const hidden = await call("dev_kim", other, `/v1/intakes/${intake}/cancel`), absent = await call("dev_kim", other, "/v1/intakes/int_absent12345/cancel")
  expect(hidden.status).toBe(404)
  expect(await hidden.text()).toBe(await absent.text())
  const cancelled = await call("dev_member", owner, `/v1/intakes/${intake}/cancel`)
  expect(cancelled.status).toBe(200)
  await inAccess(f.tenant, ctx => expect(ctx.sql.exec<{
    status: string
  }>("SELECT status FROM workspace_credential_requests WHERE id=?", intake).toArray()[0]?.status).toBe("cancelled"))

})
it("dispatches a signed workspace relay through the real Worker and hides private credentials before any send", async () => {
  const { credentialsFixture, inAccess } = await import("./credentials-test-support.ts")
  const { newDeviceKey, publicJwk } = await import("./devices.ts")
  const { createProof, webCryptoSigner } = await import("@mehen/protocol")
  const { fetchWorkspaceWorker, ORIGIN } = await import("./helpers.ts")
  const f = await credentialsFixture(), keys = await newDeviceKey()
  await inAccess(f.tenant, async ctx => {
    ctx.sql.exec("UPDATE devices SET jwk=? WHERE id='dev_member'", JSON.stringify(await publicJwk(keys)))
    await seedCredential(ctx, "dispatch-public")
  })
  let sends = 0
  setUpstreamFetch(async request => {
    sends++
    expect(request.headers.get("authorization")).toBe("Bearer test-secret-never-returned")
    return new Response("upstream-ok")
  })
  const relay = async (slug: string) => {
    const body = JSON.stringify({ item: slug, method: "GET", url: "https://api.example.com/test", headers: [] })
    const proof = await createProof(webCryptoSigner("dev_member", keys.privateKey), { method: "POST", url: `${ORIGIN}/v1/relay`, body }, { tenant: f.tenant })
    return fetchWorkspaceWorker({ ...env }, "/v1/relay", {
      method: "POST", headers: { "Mehen-Proof": proof, "content-type": "application/json" }, body,
    })
  }
  const visible = await relay("dispatch-public")
  expect(visible.status).toBe(200)
  expect(await visible.text()).toBe("upstream-ok")
  expect(sends).toBe(1)
  const absent = await relay("dispatch-private")
  expect(absent.status).toBe(404)
  const absentBody = await absent.text()
  await inAccess(f.tenant, ctx => seedCredential(ctx, "dispatch-private", { kind: "member", member: "mem_kim" }))
  const hidden = await relay("dispatch-private")
  expect(hidden.status).toBe(404)
  expect(await hidden.text()).toBe(absentBody)
  expect(sends).toBe(1)
  await inAccess(f.tenant, ctx => {
    expect(ctx.sql.exec("SELECT * FROM workspace_credential_requests").toArray()).toEqual([])
    expect(ctx.sql.exec("SELECT * FROM audit WHERE action='relay.allow'").toArray()).toHaveLength(1)
  })
})
