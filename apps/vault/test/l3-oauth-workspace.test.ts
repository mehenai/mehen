import { afterEach, describe, expect, it, vi } from "vitest"
import { getTemplate, WorkspaceStepUpActionSchema } from "@mehen/protocol"
import type { VaultContext } from "../src/vault/core.ts"
import { checkedCredential, prepareCredential, storeCredential } from "../src/vault/areas/items-workspace.ts"
import { createWorkspaceConnect, startWorkspaceConnect, finishWorkspaceConnect, workspaceAccessToken, workspaceOAuthOps } from "../src/vault/areas/oauth-workspace.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { VaultError } from "../src/http.ts"
import { credentialInput, credentialsFixture, inAccess, memberInvocation, memberPrincipal } from "./credentials-test-support.ts"
afterEach(() => { setUpstreamFetch(null); vi.restoreAllMocks() })

async function client(ctx: VaultContext, home: Parameters<typeof credentialInput>[1] = { kind: "workspace" }) {
  const template = getTemplate("google-oauth-client")
  if (!template)
    throw new Error("template")
  const prepared = await prepareCredential(ctx, { ...credentialInput("google-client", home), kind: "oauth-client", provider: template.id, binding: template.binding, policy: template.policy, injection: null, ceiling: "relay", publicFields: { client_id: "test-client" }, secretFields: { client_secret: "test-client-secret" } }, null)
  return ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
}

async function started(ctx: VaultContext, home: "workspace" | "private" | "project" = "workspace", clientHome: Parameters<typeof credentialInput>[1] = { kind: "workspace" }) {
  await client(ctx, clientHome)
  const p = memberPrincipal(ctx), i = memberInvocation(ctx)
  const c = createWorkspaceConnect(ctx, p, { provider: "google-gmail", client: "google-client", slug: "gmail-test", home, ...(home === "project" ? { project: "prj_a" } : {}), scopes: ["gmail.modify"] }, i)
  const action = WorkspaceStepUpActionSchema.parse(workspaceOAuthOps["oauth.connect_action"].handler(ctx, p, { connect: c.connect }, i))
  const auth = memberInvocation(ctx, "owner", action), state = "state-test-123456789"
  await startWorkspaceConnect(ctx, p, { connect: c.connect, state }, auth)
  return { p, i, c, state, auth }
}

function upstream(change?: () => void) {
  let sends = 0
  setUpstreamFetch(async (req) => { sends++; if (req.url.includes("/token")) {
    change?.()
    return Response.json({ access_token: "test-access", refresh_token: "test-refresh", expires_in: 3600, scope: "openid email https://www.googleapis.com/auth/gmail.modify" })
  } return Response.json({ sub: "test-subject", email: "test@example.com", email_verified: true }); })
  return () => sends
}
const finishInput = (s: Awaited<ReturnType<typeof started>>) => ({ connect: s.c.connect, state: s.state, code: "code-test", error: null })
// A finished Gmail connection, as connect, start and finish leave it.
async function connected(ctx: VaultContext, home: "workspace" | "private" | "project" = "workspace") {
  const s = await started(ctx, home)
  upstream()
  await finishWorkspaceConnect(ctx, s.p, finishInput(s), s.i)
  return checkedCredential(ctx, "gmail-test")!
}
// A finished GitHub connection with an expiring token: GitHub rotates its
// refresh token strictly.
async function githubConnection(ctx: VaultContext) {
  const template = getTemplate("github-oauth-client")!
  const prepared = await prepareCredential(ctx, { ...credentialInput("github-client"), kind: "oauth-client", provider: template.id, binding: template.binding, policy: template.policy, injection: null, ceiling: "relay", publicFields: { client_id: "gh-client" }, secretFields: { client_secret: "gh-secret" } }, null)
  ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
  const p = memberPrincipal(ctx), i = memberInvocation(ctx)
  const c = createWorkspaceConnect(ctx, p, { provider: "github-oauth", client: "github-client", slug: "github-test", home: "workspace", scopes: ["read:user"] }, i)
  const action = WorkspaceStepUpActionSchema.parse(workspaceOAuthOps["oauth.connect_action"].handler(ctx, p, { connect: c.connect }, i))
  const state = "state-github-123456789"
  await startWorkspaceConnect(ctx, p, { connect: c.connect, state }, memberInvocation(ctx, "owner", action))
  setUpstreamFetch(async (req) => req.url.includes("/access_token") ? Response.json({ access_token: "gh-access", refresh_token: "gh-refresh", expires_in: 28800, scope: "read:user" }) : Response.json({ id: 42, login: "octo" }))
  await finishWorkspaceConnect(ctx, p, { connect: c.connect, state, code: "gh-code", error: null }, i)
  return checkedCredential(ctx, "github-test")!
}
function connectionPayload(ctx: VaultContext, item: string): Record<string, unknown> {
  return JSON.parse(ctx.sql.exec<{ payload: string }>("SELECT payload FROM workspace_oauth_connections WHERE item=?", item).toArray()[0]!.payload) as Record<string, unknown>
}
describe("workspace OAuth final authority and dependencies", () => {
  it("refuses cookie-only start and foreign private/project clients before any opening or upstream send", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const s = await started(ctx), open = vi.spyOn(ctx, "openField"), sends = upstream()
      await expect(startWorkspaceConnect(ctx, s.p, { connect: s.c.connect, state: s.state }, s.i)).rejects.toMatchObject({ code: "forbidden", message: "This needs a passkey confirmation of the exact action." })
      ctx.sql.exec("UPDATE items SET home_kind='member',home_id='mem_kim' WHERE slug='google-client'")
      expect(() => createWorkspaceConnect(ctx, s.p, { provider: "google-gmail", client: "google-client", slug: "other-gmail", home: "workspace" }, s.i)).toThrowError('No credential called "google-client".')
      ctx.sql.exec("UPDATE items SET home_kind='project',home_id='prj_a' WHERE slug='google-client'")
      expect(() => createWorkspaceConnect(ctx, s.p, { provider: "google-gmail", client: "google-client", slug: "other-gmail", home: "private" }, s.i)).toThrowError("No usable OAuth client.")
      expect(open).not.toHaveBeenCalled()
      expect(sends()).toBe(0)
      expect(checkedCredential(ctx, "gmail-test")).toBeNull()
    })
  })
  for (const race of ["deleted-client", "cancelled", "removed", "epoch", "session"] as const)
    it(`refuses ${race} at OAuth completion without a stored credential`, async () => {
      const f = await credentialsFixture()
      await inAccess(f.tenant, async (ctx) => {
        const s = await started(ctx)
        const sends = upstream(() => {
          if (race === "deleted-client")
            ctx.sql.exec("DELETE FROM items WHERE slug='google-client'")
          if (race === "cancelled")
            ctx.sql.exec("UPDATE workspace_credential_requests SET status='cancelled' WHERE id=?", s.c.connect)
          if (race === "removed")
            ctx.sql.exec("UPDATE members SET status='removed' WHERE id='mem_owner'")
        })
        const i = memberInvocation(ctx)
        if (i.auth.kind !== "account")
          throw new Error("account")
        if (race === "epoch")
          i.auth.securityEpoch = 1
        if (race === "session")
          i.auth.session = "ses_different"
        const expected = race === "deleted-client" ? { error: "not_found", message: 'No credential called "google-client".', next: { command: "mehen ls", say: 'There is no credential called "google-client"; list what exists with `mehen ls`, or ask for it with `mehen request`.' } } : race === "cancelled" ? { error: "conflict", message: "This credential request is no longer open." } : race === "removed" ? { error: "not_found", message: "No such credential request." } : { error: "forbidden", message: "This connection belongs to another sign-in." }
        let failure: unknown
        try {
          await finishWorkspaceConnect(ctx, s.p, finishInput(s), i)
        }
        catch (e) {
          failure = e instanceof Error && "toJSON" in e ? (e as import("../src/http.ts").VaultError).toJSON() : e
        }
        expect(failure).toEqual(expected)
        expect(checkedCredential(ctx, "gmail-test")).toBeNull()
        expect(ctx.sql.exec<{
          n: number
        }>("SELECT count(*) AS n FROM workspace_oauth_connections").toArray()[0]?.n).toBe(0)
        expect(sends()).toBe(race === "epoch" || race === "session" ? 0 : 1)
      })
    })
  it("stores healthy workspace-client/private-connection dependencies and refuses refresh after connector removal", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const s = await started(ctx, "private")
      upstream()
      await finishWorkspaceConnect(ctx, s.p, finishInput(s), s.i)
      const item = checkedCredential(ctx, "gmail-test")
      if (!item)
        throw new Error("stored")
      expect(ctx.sql.exec("SELECT * FROM credential_dependencies WHERE connection=?", item.id).toArray()).toHaveLength(1)
      ctx.sql.exec("UPDATE members SET status='removed' WHERE id='mem_owner'")
      const open = vi.spyOn(ctx, "openField"), sends = upstream()
      await expect(workspaceAccessToken(ctx, item)).rejects.toMatchObject({ code: "needs_reauth", message: "Reconnect this credential: the person who connected it is no longer an active member." })
      expect(open).not.toHaveBeenCalled()
      expect(sends()).toBe(0)
      expect(checkedCredential(ctx, "gmail-test")?.version).toBe(item.version)
    })
  })
  it("maintains existing OAuth grants during account cooling-off", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const s = await started(ctx)
      upstream()
      await finishWorkspaceConnect(ctx, s.p, finishInput(s), s.i)
      const item = checkedCredential(ctx, "gmail-test")
      if (!item)
        throw new Error("stored")
      ctx.sql.exec("UPDATE account_security SET state=json_set(state,'$.restriction',json(?)) WHERE account='acc_owner'", JSON.stringify({ until: ctx.now() + 86400000, reason: "recovery", notice: "notice_test" }))
      expect(await workspaceAccessToken(ctx, item)).toBe("test-access")
    })
  })
})
// A refresh overwrites the tokens with no kept copy: an old refresh token
// never outlives it in item_secret_history.
it("keeps no replaced value when a refresh overwrites the tokens", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const s = await started(ctx)
    upstream()
    await finishWorkspaceConnect(ctx, s.p, finishInput(s), s.i)
    const item = checkedCredential(ctx, "gmail-test")!
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
    const sends = upstream()
    expect(await workspaceAccessToken(ctx, item)).toBe("test-access")
    expect(sends()).toBe(1)
    expect(checkedCredential(ctx, "gmail-test")!.version).toBe(item.version + 1)
    expect(ctx.sql.exec("SELECT count(*) AS n FROM item_secret_history").toArray()).toEqual([{ n: 0 }])
  })
})
it("single-flights a private scheduled refresh during cooling-off and stores a minimal maintained event", async () => {
  const { verifyAuditChain } = await import("../src/vault/audit.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const s = await started(ctx, "private")
    upstream()
    await finishWorkspaceConnect(ctx, s.p, finishInput(s), s.i)
    const item = checkedCredential(ctx, "gmail-test")
    if (!item)
      throw new Error("stored")
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
    ctx.sql.exec("UPDATE account_security SET state=json_set(state,'$.restriction',json(?)) WHERE account='acc_owner'", JSON.stringify({ until: ctx.now() + 86400000, reason: "recovery", notice: "notice_test" }))
    const sends = upstream()
    expect(await Promise.all([workspaceAccessToken(ctx, item), workspaceAccessToken(ctx, item)])).toEqual(["test-access", "test-access"])
    expect(sends()).toBe(1)
    expect(ctx.sql.exec<{
      payload: string
    }>("SELECT payload FROM workspace_oauth_connections WHERE item=?", item.id).toArray()[0]?.payload).not.toContain("refreshAttempt")
    const rows = ctx.sql.exec<import("../src/vault/audit.ts").AuditRow>("SELECT * FROM audit ORDER BY seq").toArray(), event = rows.filter(row => row.action === "oauth.refresh").at(-1)
    expect(event).toBeTruthy()
    expect(JSON.parse(event!.detail)).toEqual({ action: "oauth.refresh", at: event!.at, actor: { kind: "member", member: "mem_owner" }, session: null, item: item.id, slug: item.slug, outcome: "maintained", run: null })
    expect(verifyAuditChain(rows)).toEqual({ ok: true })
    const { beforeOffboarding } = await import("../src/vault/areas/workspace-runtime.ts")
    const current = checkedCredential(ctx, item.slug)!
    expect(beforeOffboarding(ctx, "mem_owner").exposures).toEqual(expect.arrayContaining([expect.objectContaining({ item: current.id, version: current.version, member: "mem_owner", event: "oauth.authorisation_retained", source: "entered" })]))
  })
})
for (const lost of ["connector-right", "client-revision", "client-after-exchange"] as const)
  it(`refuses refresh after loss of ${lost} without storing a new value version`, async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const s = await started(ctx)
      upstream()
      await finishWorkspaceConnect(ctx, s.p, finishInput(s), s.i)
      const item = checkedCredential(ctx, "gmail-test")
      if (!item)
        throw new Error("stored")
      ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
      const exposuresBefore = JSON.stringify(ctx.sql.exec("SELECT * FROM exposures ORDER BY event,item,version").toArray())
      if (lost === "connector-right")
        ctx.sql.exec("UPDATE members SET role='member' WHERE id='mem_owner'")
      if (lost === "client-revision")
        ctx.sql.exec("UPDATE items SET config_rev=config_rev+1 WHERE slug='google-client'")
      const open = vi.spyOn(ctx, "openField"), sends = upstream(lost === "client-after-exchange" ? () => { ctx.sql.exec("DELETE FROM items WHERE slug='google-client'"); } : undefined)
      const reason = lost === "connector-right" ? "the person who connected it may no longer maintain it" : lost === "client-revision" ? "its OAuth client was replaced or changed since it was connected" : "its OAuth client was removed"
      await expect(workspaceAccessToken(ctx, item)).rejects.toMatchObject({ code: "needs_reauth", message: `Reconnect this credential: ${reason}.` })
      if (lost !== "client-after-exchange")
        expect(open).not.toHaveBeenCalled()
      expect(sends()).toBe(lost === "client-after-exchange" ? 1 : 0)
      expect(checkedCredential(ctx, "gmail-test")?.version).toBe(item.version)
      expect(checkedCredential(ctx, "gmail-test")?.status).toBe("needs_reauth")
      expect(JSON.stringify(ctx.sql.exec("SELECT * FROM exposures ORDER BY event,item,version").toArray())).toBe(exposuresBefore)
    })
  })
it("keeps compatible project-to-workspace client rehomes refreshing under current connector rights", async () => {
  const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const s = await started(ctx, "project", { kind: "project", project: "prj_a" })
    upstream()
    await finishWorkspaceConnect(ctx, s.p, finishInput(s), s.i)
    const original = checkedCredential(ctx, "google-client")!
    const action = { type: "item.rehome" as const, item: original.id, before: original.home, after: { kind: "workspace" as const }, dependencyRevision: original.dependencyRevision }
    workspaceItemOps["items.rehome"].handler(ctx, s.p, { slug: original.slug, home: action.after }, memberInvocation(ctx, "owner", action))
    const item = checkedCredential(ctx, "gmail-test")!
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
    expect(await workspaceAccessToken(ctx, item)).toBe("test-access")
    expect(checkedCredential(ctx, "google-client")?.home).toEqual({ kind: "workspace" })
  })
})
it("refuses an incompatible dependency rehome without any state change or secret opening", async () => {
  const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
  const { canonicalJson } = await import("@mehen/protocol")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const s = await started(ctx)
    upstream()
    await finishWorkspaceConnect(ctx, s.p, finishInput(s), s.i)
    const original = checkedCredential(ctx, "google-client")!
    const action = { type: "item.rehome" as const, item: original.id, before: original.home, after: { kind: "project" as const, project: "prj_a" }, dependencyRevision: original.dependencyRevision }
    const before = canonicalJson(ctx.sql.exec("SELECT * FROM items").toArray()), edges = canonicalJson(ctx.sql.exec("SELECT * FROM credential_dependencies").toArray()), open = vi.spyOn(ctx, "openField")
    expect(() => workspaceItemOps["items.rehome"].handler(ctx, s.p, { slug: original.slug, home: action.after }, memberInvocation(ctx, "owner", action))).toThrowError("This home is incompatible with a credential dependency.")
    expect(canonicalJson(ctx.sql.exec("SELECT * FROM items").toArray())).toBe(before)
    expect(canonicalJson(ctx.sql.exec("SELECT * FROM credential_dependencies").toArray())).toBe(edges)
    expect(open).not.toHaveBeenCalled()
  })
})
it("a connector that loses create rights on a rehomed connection cannot maintain it", async () => {
  const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const s = await started(ctx, "project")
    upstream()
    await finishWorkspaceConnect(ctx, s.p, finishInput(s), s.i)
    const original = checkedCredential(ctx, "gmail-test")!
    const action = { type: "item.rehome" as const, item: original.id, before: original.home, after: { kind: "workspace" as const }, dependencyRevision: original.dependencyRevision }
    workspaceItemOps["items.rehome"].handler(ctx, s.p, { slug: original.slug, home: action.after }, memberInvocation(ctx, "owner", action))
    ctx.sql.exec("UPDATE members SET role='member' WHERE id='mem_owner'")
    const item = checkedCredential(ctx, "gmail-test")!, open = vi.spyOn(ctx, "openField"), sends = upstream()
    await expect(workspaceAccessToken(ctx, item)).rejects.toMatchObject({ code: "needs_reauth", message: "Reconnect this credential: the person who connected it may no longer maintain it." })
    expect(open).not.toHaveBeenCalled()
    expect(sends()).toBe(0)
    expect(checkedCredential(ctx, item.slug)?.status).toBe("needs_reauth")
  })
})
// A crash mid-refresh leaves its marker. Within 120 s it waits; after, the
// refresh is sent again, whether its token rotates strictly (GitHub) or not
// (Google).
for (const marker of ["fresh", "stale", "stale-strict"] as const)
  it(`handles a ${marker} unresolved refresh marker`, async () => {
    const { canonicalJson } = await import("@mehen/protocol")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = marker === "stale-strict" ? await githubConnection(ctx) : await connected(ctx, "private")
      ctx.sql.exec("UPDATE workspace_oauth_connections SET payload=json_set(payload,'$.refreshAttempt',json(?)),expires_at=? WHERE item=?", JSON.stringify({ id: "rfa_crashed", startedAt: ctx.now() - (marker === "fresh" ? 0 : 120001) }), ctx.now() - 1, item.id)
      const before = canonicalJson([ctx.sql.exec("SELECT * FROM items").toArray(), ctx.sql.exec("SELECT * FROM workspace_oauth_connections").toArray(), ctx.sql.exec("SELECT * FROM audit").toArray()])
      const sends = upstream(), open = vi.spyOn(ctx, "openField")
      if (marker === "stale-strict")
        setUpstreamFetch(async () => Response.json({ access_token: "gh-renewed", refresh_token: "gh-refresh-2", expires_in: 28800, scope: "read:user" }))
      if (marker !== "fresh") {
        expect(await workspaceAccessToken(ctx, item)).toBe(marker === "stale" ? "test-access" : "gh-renewed")
        if (marker === "stale")
          expect(sends()).toBe(1)
        expect(checkedCredential(ctx, item.slug)?.status).toBe("active")
        expect(connectionPayload(ctx, item.id)).not.toHaveProperty("refreshAttempt")
        return
      }
      await expect(workspaceAccessToken(ctx, item)).rejects.toMatchObject({ code: "refresh_retrying", message: "A credential refresh is already in progress." })
      expect(sends()).toBe(0)
      expect(open).not.toHaveBeenCalled()
      expect(checkedCredential(ctx, item.slug)?.version).toBe(item.version)
      expect(canonicalJson([ctx.sql.exec("SELECT * FROM items").toArray(), ctx.sql.exec("SELECT * FROM workspace_oauth_connections").toArray(), ctx.sql.exec("SELECT * FROM audit").toArray()])).toBe(before)
    })
  })
it("requires owner/admin connection authority for a protected client before any client secret opens", async () => {
  const { registerAccessStateProvider, accessState } = await import("../src/vault/areas/workspace-runtime.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const clientItem = await client(ctx), state = accessState(ctx)
    for (const project of state.projects)
      for (const environment of project.environments)
        if (environment.name === "prod")
          environment.references = [{ variable: "CLIENT", field: "client_secret", item: clientItem.id, home: clientItem.home, revision: 1 }]
    registerAccessStateProvider("projects", () => ({ projects: state.projects }))
    const p = memberPrincipal(ctx, "member"), i = memberInvocation(ctx, "member")
    const request = createWorkspaceConnect(ctx, p, { provider: "google-gmail", client: "google-client", slug: "protected-client-grant", home: "project", project: "prj_a" }, i)
    const open = vi.spyOn(ctx, "openField"), sends = upstream()
    let failure: unknown
    try {
      workspaceOAuthOps["oauth.connect_action"].handler(ctx, p, { connect: request.connect }, i)
    }
    catch (e) {
      failure = (e as import("../src/http.ts").VaultError).toJSON()
    }
    expect(failure).toEqual({ error: "environment_refused", message: "This OAuth client requires an owner or admin.", next: { say: "Ask an owner or admin to connect using this client." } })
    expect(open).not.toHaveBeenCalled()
    expect(sends()).toBe(0)
    const action = WorkspaceStepUpActionSchema.parse(workspaceOAuthOps["oauth.connect_action"].handler(ctx, memberPrincipal(ctx), { connect: request.connect }, memberInvocation(ctx)))
    await expect(startWorkspaceConnect(ctx, memberPrincipal(ctx), { connect: request.connect, state: "state-protected-client-123" }, memberInvocation(ctx, "owner", action))).resolves.toMatchObject({ authorizeUrl: expect.any(String) })
  })
})
it("maintains an existing protected-client grant under a still-authorised member connector", async () => {
  const { registerAccessStateProvider, accessState } = await import("../src/vault/areas/workspace-runtime.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const s = await started(ctx, "project")
    upstream()
    await finishWorkspaceConnect(ctx, s.p, finishInput(s), s.i)
    const clientItem = checkedCredential(ctx, "google-client")!, state = accessState(ctx)
    for (const project of state.projects)
      for (const environment of project.environments)
        if (environment.name === "prod")
          environment.references = [{ variable: "CLIENT", field: "client_secret", item: clientItem.id, home: clientItem.home, revision: 1 }]
    registerAccessStateProvider("projects", () => ({ projects: state.projects }))
    const share = { id: "shr_connector", project: "prj_a", subject: { kind: "member", member: "mem_owner" }, level: "edit", protected: false, expiresAt: null }
    ctx.sql.exec("INSERT INTO project_shares VALUES(?,'prj_a','member','mem_owner',?)", share.id, JSON.stringify(share))
    ctx.sql.exec("UPDATE members SET role='member' WHERE id='mem_owner'")
    const item = checkedCredential(ctx, "gmail-test")!
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
    expect(await workspaceAccessToken(ctx, item)).toBe("test-access")
  })
})
it("pins reconnects to the retained provider subject, not a reusable display label",async()=>{
 const f=await credentialsFixture();await inAccess(f.tenant,async ctx=>{
  const first=await started(ctx);upstream();await finishWorkspaceConnect(ctx,first.p,finishInput(first),first.i)
  const before=checkedCredential(ctx,"gmail-test")!
  const next=createWorkspaceConnect(ctx,first.p,{provider:"google-gmail",client:"google-client",slug:"gmail-test",home:"workspace"},first.i)
  const action=WorkspaceStepUpActionSchema.parse(workspaceOAuthOps["oauth.connect_action"].handler(ctx,first.p,{connect:next.connect},first.i))
  expect(action).toMatchObject({type:"connect.start",intent:"rotate",target:before.id,expectedAccount:"test@example.com"})
  const state="state-reconnect-123456789"
  await startWorkspaceConnect(ctx,first.p,{connect:next.connect,state},memberInvocation(ctx,"owner",action))
  setUpstreamFetch(async req=>req.url.includes("/token")?Response.json({access_token:"other-token",refresh_token:"other-refresh",expires_in:3600,scope:"openid email https://www.googleapis.com/auth/gmail.modify"}):Response.json({sub:"different-subject",email:"test@example.com",email_verified:true}))
  await expect(finishWorkspaceConnect(ctx,first.p,{connect:next.connect,state,code:"code-reconnect",error:null},first.i)).rejects.toMatchObject({code:"forbidden",message:"The provider account does not match this connection."})
  expect(checkedCredential(ctx,"gmail-test")?.version).toBe(before.version)
  expect(ctx.sql.exec<{status:string}>("SELECT status FROM workspace_credential_requests WHERE id=?",next.connect).toArray()[0]?.status).toBe("open")
 })
})
for(const phase of ["probe","seal"] as const)it(`refuses a client changed during OAuth ${phase} without storing the prepared grant`,async()=>{
 const f=await credentialsFixture();await inAccess(f.tenant,async ctx=>{
  const s=await started(ctx);let sends=0
  setUpstreamFetch(async req=>{
   sends++
   if(req.url.includes("/token"))return Response.json({access_token:"prepared-access",refresh_token:"prepared-refresh",expires_in:3600,scope:"openid email https://www.googleapis.com/auth/gmail.modify"})
   if(phase === "probe")ctx.sql.exec("UPDATE items SET config_rev=config_rev+1 WHERE slug='google-client'")
   return Response.json({sub:"test-subject",email:"test@example.com",email_verified:true})
  })
  let changed=false
  const wrapped={...ctx,async sealField(ref:Parameters<typeof ctx.sealField>[0],plain:Parameters<typeof ctx.sealField>[1]){
   const sealed=await ctx.sealField(ref,plain)
   if(phase === "seal"&&ref.type === "item-secret"&&!changed){changed=true;ctx.sql.exec("UPDATE items SET home_kind='project',home_id='prj_b' WHERE slug='google-client'")}
   return sealed
  }}
  await expect(finishWorkspaceConnect(wrapped,s.p,finishInput(s),s.i)).rejects.toMatchObject({code:phase === "probe"?"conflict":"not_found",message:phase === "probe"?"The credential changed; review and try again.":"No usable OAuth client."})
  expect(sends).toBe(2)
  expect(checkedCredential(ctx,"gmail-test")).toBeNull()
  expect(ctx.sql.exec<{n:number}>("SELECT count(*) AS n FROM workspace_oauth_connections").toArray()[0]?.n).toBe(0)
 })
})

it("chains a private client intake into a private connection with the same final home and authority checks", async () => {
  const { workspaceIntakeOps, submitWorkspaceIntake } = await import("../src/vault/areas/intake-workspace.ts")
  const { stepUpDigest } = await import("../src/vault/areas/items.ts")
  const { sealToVault } = await import("./l2-helpers.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async ctx => {
    const p = memberPrincipal(ctx), invocation = memberInvocation(ctx)
    const created = createWorkspaceConnect(ctx, p, { provider: "google-gmail", client: "google-client", slug: "chained-private", home: "private", requestClient: true, clientTags: ["work"] }, invocation)
    expect(created.intake).toBeTruthy()
    const intake = created.intake!.intake
    const view = await workspaceIntakeOps["intake.view"].handler(ctx, p, { intake }, invocation)
    expect(view.then).toEqual({ connect: created.connect, url: `https://vault.test/w/work/c/${created.connect}` })
    const submission = { slug: "google-client", home: view.home, tags: ["work"], binding: view.binding.value, publicFields: { client_id: "test-client" }, sealed: { client_secret: await sealToVault("test-client-secret", `intake/${intake}/client_secret`) } }
    await submitWorkspaceIntake(ctx, p, { intake, ...submission }, memberInvocation(ctx, "owner", { type: "intake.submit", intake, digest: await stepUpDigest(submission) }))
    const action = WorkspaceStepUpActionSchema.parse(workspaceOAuthOps["oauth.connect_action"].handler(ctx, p, { connect: created.connect }, invocation))
    const state = "state-private-chain-123456789"
    await startWorkspaceConnect(ctx, p, { connect: created.connect, state }, memberInvocation(ctx, "owner", action))
    upstream()
    await finishWorkspaceConnect(ctx, p, { connect: created.connect, state, code: "chain-code", error: null }, invocation)
    expect(checkedCredential(ctx, "google-client")?.home).toEqual({ kind: "member", member: "mem_owner" })
    expect(checkedCredential(ctx, "chained-private")?.home).toEqual({ kind: "member", member: "mem_owner" })
    const expiry = ctx.sql.exec<{ expires_at: number }>("SELECT expires_at FROM workspace_credential_requests WHERE id=?", created.connect).toArray()[0]!.expires_at
    expect(expiry).toBeLessThanOrEqual(ctx.now() + 900_000)
  })
})

it("project create authority cannot authorise reconnect without rotate",async()=>{
  const {VaultError}=await import("../src/http.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    const s=await started(ctx,"project");upstream();await finishWorkspaceConnect(ctx,s.p,finishInput(s),s.i)
    const request=createWorkspaceConnect(ctx,s.p,{provider:"google-gmail",client:"google-client",slug:"gmail-test",home:"project",project:"prj_a"},s.i)
    const action=WorkspaceStepUpActionSchema.parse(workspaceOAuthOps["oauth.connect_action"].handler(ctx,s.p,{connect:request.connect},s.i))
    const p=memberPrincipal(ctx,"member"),i=memberInvocation(ctx,"member",action),open=vi.spyOn(ctx,"openField"),seal=vi.spyOn(ctx,"sealField"),sends=upstream()
    const before=JSON.stringify(ctx.sql.exec("SELECT * FROM workspace_credential_requests WHERE id=?",request.connect).toArray())
    for(const operation of [()=>workspaceOAuthOps["oauth.connect_action"].handler(ctx,p,{connect:request.connect},i),()=>startWorkspaceConnect(ctx,p,{connect:request.connect,state:"editor-state-123456789"},i)]){
      let failure:unknown
      try{await operation()}catch(e){failure=e instanceof VaultError?e.toJSON():e}
      expect(failure).toEqual({error:"forbidden",message:"You are not allowed to do that."})
    }
    expect(JSON.stringify(ctx.sql.exec("SELECT * FROM workspace_credential_requests WHERE id=?",request.connect).toArray())).toBe(before)
    expect(open).not.toHaveBeenCalled();expect(seal).not.toHaveBeenCalled();expect(sends()).toBe(0)
  })
})

it("a cooling-off actor cannot start a new provider connection",async()=>{
  const {VaultError}=await import("../src/http.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    const s=await started(ctx),until=ctx.now()+3600000
    ctx.sql.exec("UPDATE account_security SET state=json_set(state,'$.restriction',json(?)) WHERE account='acc_owner'",JSON.stringify({until,reason:"recovery",notice:"notice_test"}))
    const before=JSON.stringify(ctx.sql.exec("SELECT * FROM workspace_credential_requests WHERE id=?",s.c.connect).toArray()),open=vi.spyOn(ctx,"openField"),seal=vi.spyOn(ctx,"sealField"),sends=upstream()
    let failure:unknown
    try{await startWorkspaceConnect(ctx,s.p,{connect:s.c.connect,state:s.state},s.auth)}catch(e){failure=e instanceof VaultError?e.toJSON():e}
    expect(failure).toEqual({error:"forbidden",message:`Your sign-in was recovered. Until ${new Date(until).toISOString().slice(0,16).replace("T"," ")} UTC you can read, deny requests, revoke machines and freeze, but not approve, change or invite.`,next:{url:"/account",say:"Use an older account passkey to resolve recovery, or wait for cooling-off to finish."}})
    expect(JSON.stringify(ctx.sql.exec("SELECT * FROM workspace_credential_requests WHERE id=?",s.c.connect).toArray())).toBe(before)
    expect(open).not.toHaveBeenCalled();expect(seal).not.toHaveBeenCalled();expect(sends()).toBe(0)
  })
})

for(const phase of ["before","during-exchange","during-sealing"] as const)it(`a connection metadata edit ${phase} keeps maintenance working without overwriting the edit`,async()=>{
  const {workspaceItemOps}=await import("../src/vault/areas/items-workspace.ts")
  const {stepUpDigest}=await import("../src/vault/areas/items.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    const s=await started(ctx);upstream();await finishWorkspaceConnect(ctx,s.p,finishInput(s),s.i)
    const item=checkedCredential(ctx,"gmail-test")!,change={description:"edited without reconnect"}
    const edit=async()=>{
      const current=checkedCredential(ctx,item.slug)!,digest=await stepUpDigest({change,version:null,configRevision:current.configRev})
      await workspaceItemOps["items.update"].handler(ctx,s.p,{slug:item.slug,change},memberInvocation(ctx,"owner",{type:"item.update",item:item.id,digest}))
    }
    if(phase === "before")await edit()
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?",ctx.now()-1,item.id)
    let sends=0,edited=false
    setUpstreamFetch(async()=>{sends++;if(phase === "during-exchange")await edit();return Response.json({access_token:"fresh-after-edit",expires_in:3600})})
    const wrapped={...ctx,async sealField(ref:Parameters<typeof ctx.sealField>[0],plain:Parameters<typeof ctx.sealField>[1]){
      const sealed=await ctx.sealField(ref,plain)
      if(phase === "during-sealing"&&!edited){edited=true;await edit()}
      return sealed
    }}
    expect(await workspaceAccessToken(wrapped,checkedCredential(ctx,item.slug)!)).toBe("fresh-after-edit")
    expect(sends).toBe(1)
    expect(checkedCredential(ctx,item.slug)).toMatchObject({status:"active",description:change.description,configRev:item.configRev+1,version:item.version+1})
    expect(await workspaceAccessToken(ctx,checkedCredential(ctx,item.slug)!)).toBe("fresh-after-edit")
    expect(sends).toBe(1)
  })
})

it("a definite provider 503 clears uncertainty and retries successfully after retryAt",async()=>{
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    const s=await started(ctx);upstream();await finishWorkspaceConnect(ctx,s.p,finishInput(s),s.i)
    const item=checkedCredential(ctx,"gmail-test")!
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?",ctx.now()-1,item.id)
    let sends=0
    setUpstreamFetch(async()=>{sends++;return sends === 1?new Response("busy",{status:503,headers:{"retry-after":"120"}}):Response.json({access_token:"retry-success",expires_in:3600})})
    await expect(workspaceAccessToken(ctx,item)).rejects.toMatchObject({code:"refresh_retrying"})
    const payload=JSON.parse(ctx.sql.exec<{payload:string}>("SELECT payload FROM workspace_oauth_connections WHERE item=?",item.id).toArray()[0]!.payload) as {retryAt:number;refreshAttempt?:unknown}
    expect(payload.refreshAttempt).toBeUndefined()
    const open=vi.spyOn(ctx,"openField")
    await expect(workspaceAccessToken(ctx,checkedCredential(ctx,item.slug)!)).rejects.toMatchObject({code:"refresh_retrying"})
    expect(open).not.toHaveBeenCalled();open.mockRestore()
    const later={...ctx,now:()=>payload.retryAt+1}
    expect(await workspaceAccessToken(later,checkedCredential(ctx,item.slug)!)).toBe("retry-success")
    expect(sends).toBe(2)
    expect(checkedCredential(ctx,item.slug)).toMatchObject({status:"active",version:item.version+1,configRev:item.configRev})
  })
})

it("a reserved connection completes without consulting the filler's exhausted name bucket",async()=>{
  const {nameMiss}=await import("../src/vault/areas/workspace-runtime.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    const s=await started(ctx)
    for(let n=0;n<20;n++)nameMiss.record(ctx,s.p,ctx.now())
    expect(nameMiss.check(ctx,s.p,ctx.now()).ok).toBe(false)
    const sends=upstream()
    await expect(finishWorkspaceConnect(ctx,s.p,finishInput(s),s.i)).resolves.toMatchObject({status:"completed"})
    expect(sends()).toBe(2)
    expect(ctx.sql.exec<{count:number}>("SELECT count FROM name_miss_buckets WHERE subject='account:acc_owner'").toArray()[0]?.count).toBe(20)
  })
})

// Google never rotates its refresh token, so an exchange whose answer was
// lost is retried and the connection keeps working; GitHub rotates it
// strictly, so the same exchange is sent again only after the 120 s it may
// still be answering. A lost answer alone never needs a person: GitHub says
// whether the lost exchange spent the token.
for(const failure of ["network","malformed-success","failed-with-token"] as const)it(`an ambiguous ${failure} refresh of a non-rotating token is retried`,async()=>{
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    const item=await connected(ctx)
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?",ctx.now()-1,item.id)
    let sends=0
    setUpstreamFetch(async()=>{
      sends++
      if(sends>1)return Response.json({access_token:"after-retry",expires_in:3600})
      if(failure === "network")throw new Error("provider connection lost")
      return failure === "malformed-success"?Response.json({unexpected:true}):Response.json({access_token:"ambiguous-access",refresh_token:"possibly-rotated"},{status:503})
    })
    await expect(workspaceAccessToken(ctx,item)).rejects.toMatchObject({code:"refresh_retrying"})
    const payload=connectionPayload(ctx,item.id) as {retryAt:number;refreshAttempt?:unknown}
    expect(payload.refreshAttempt).toBeUndefined()
    expect(checkedCredential(ctx,item.slug)?.status).toBe("refresh_retrying")
    const later={...ctx,now:()=>payload.retryAt+1}
    expect(await workspaceAccessToken(later,checkedCredential(ctx,item.slug)!)).toBe("after-retry")
    expect(sends).toBe(2)
    expect(checkedCredential(ctx,item.slug)).toMatchObject({status:"active",configRev:item.configRev})
  })
})
for(const failure of ["network","failed-with-token"] as const)for(const resend of ["renewed","bad_refresh_token"] as const)it(`an ambiguous ${failure} refresh of a strictly rotating token is sent again once it cannot be in flight, and GitHub's answer ${resend} decides`,async()=>{
  const {oauthArea}=await import("../src/vault/areas/oauth.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    const item=await githubConnection(ctx)
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?",ctx.now()-1,item.id)
    const sent:(string|null)[]=[]
    setUpstreamFetch(async(req)=>{
      sent.push(new URLSearchParams(await req.text()).get("refresh_token"))
      if(sent.length>1)return resend==="renewed"?Response.json({access_token:"gh-renewed",refresh_token:"gh-refresh-2",expires_in:28800,scope:"read:user"}):Response.json({error:"bad_refresh_token"})
      if(failure === "network")throw new Error("provider connection lost")
      return Response.json({access_token:"ambiguous-access",refresh_token:"possibly-rotated"},{status:503})
    })
    await expect(workspaceAccessToken(ctx,item)).rejects.toMatchObject({code:"refresh_retrying"})
    const payload=connectionPayload(ctx,item.id) as {retryAt:number;refreshAttempt:{startedAt:number}}
    expect(payload.refreshAttempt).toBeDefined()
    expect(payload.retryAt).toBeGreaterThan(payload.refreshAttempt.startedAt+120000)
    await expect(workspaceAccessToken(ctx,checkedCredential(ctx,item.slug)!)).rejects.toMatchObject({code:"refresh_retrying",message:"A credential refresh is already in progress."})
    expect(checkedCredential(ctx,item.slug)?.status).toBe("refresh_retrying")
    expect(sent).toEqual(["gh-refresh"])
    // The retry the failure scheduled sends the kept refresh again.
    await oauthArea.alarm!({...ctx,now:()=>payload.retryAt+1},`workspace-refresh:${item.id}`)
    expect(sent).toEqual(["gh-refresh","gh-refresh"])
    expect(connectionPayload(ctx,item.id)).not.toHaveProperty("refreshAttempt")
    if(resend==="renewed")
      expect(checkedCredential(ctx,item.slug)).toMatchObject({status:"active",review:null})
    else
      expect(checkedCredential(ctx,item.slug)).toMatchObject({status:"needs_reauth",version:item.version,configRev:item.configRev,review:{reason:"GitHub no longer accepts the sign-in, most likely because an interrupted refresh had already replaced the token"}})
  })
})

// GitHub's bad_refresh_token after a resend may also be a revoked or expired
// grant: a sign-in unused past GitHub's limit says so instead.
it("a refused resend names GitHub's idle expiry once the sign-in was unused that long", async () => {
  const { reauthReasonAt } = await import("../src/vault/areas/oauth.ts")
  const { getOAuthProvider } = await import("@mehen/protocol/templates")
  const github = getOAuthProvider("github-oauth")!, now = Date.UTC(2026, 10, 9)
  const at = (days: number) => reauthReasonAt(github, "GitHub", { connectedAt: now - 400 * 86_400_000, refreshedAt: now - days * 86_400_000 }, now, true)
  expect(at(30)).toBe("GitHub no longer accepts the sign-in, most likely because an interrupted refresh had already replaced the token")
  expect(at(365)).toBe("the sign-in was unused for too long and GitHub expired it")
})

// What each answer to a Gmail refresh does. Only an OAuth error that says the
// grant is gone needs a reconnect; a rejected client sends the person to the
// client; throttling, the provider's own failures, network errors and any
// other code wait and retry.
const REFRESH_ANSWERS = [
  { name: "invalid_grant", answer: () => Response.json({ error: "invalid_grant" }, { status: 400 }), outcome: "reconnect" },
  { name: "invalid_client", answer: () => Response.json({ error: "invalid_client" }, { status: 401 }), outcome: "client" },
  { name: "unauthorized_client", answer: () => Response.json({ error: "unauthorized_client" }, { status: 400 }), outcome: "client" },
  { name: "429 slow_down", answer: () => Response.json({ error: "slow_down" }, { status: 429, headers: { "retry-after": "300" } }), outcome: "retry" },
  { name: "503 temporarily_unavailable", answer: () => Response.json({ error: "temporarily_unavailable" }, { status: 503 }), outcome: "retry" },
  { name: "500 server_error", answer: () => Response.json({ error: "server_error" }, { status: 500 }), outcome: "retry" },
  { name: "400 invalid_request", answer: () => Response.json({ error: "invalid_request" }, { status: 400 }), outcome: "retry" },
  { name: "network error", answer: () => { throw new Error("connection reset") }, outcome: "retry" },
] as const
for (const row of REFRESH_ANSWERS)
  it(`a refresh answered ${row.name} ends in ${row.outcome}`, async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await connected(ctx)
      ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
      setUpstreamFetch(async () => row.answer())
      vi.spyOn(Math, "random").mockReturnValue(0.5)
      let failure: unknown
      try { await workspaceAccessToken(ctx, item) } catch (e) { failure = (e as import("../src/http.ts").VaultError).toJSON() }
      const stored = checkedCredential(ctx, item.slug)!
      if (row.outcome === "retry") {
        expect(failure).toMatchObject({ error: "refresh_retrying", retryAfter: row.name.startsWith("429") ? 300 : 30 })
        expect(stored.status).toBe("refresh_retrying")
        expect(connectionPayload(ctx, item.id)).toMatchObject({ failures: 1, failureDays: 1 })
        expect(connectionPayload(ctx, item.id)).not.toHaveProperty("refreshAttempt")
        return
      }
      expect(stored.status).toBe("needs_reauth")
      expect(connectionPayload(ctx, item.id)).not.toHaveProperty("refreshAttempt")
      if (row.outcome === "reconnect")
        expect(failure).toEqual({ error: "needs_reauth", message: "Reconnect this credential: Google revoked the sign-in: the password was changed, access was removed in the Google account's security settings, or the account signed in to this app too many times (Google keeps 100)." })
      else
        expect(failure).toEqual({ error: "needs_reauth", message: "Gmail rejected the OAuth client this connection uses (its secret is wrong, expired or deleted). Every connection that uses it is paused until a human replaces the client secret and then reconnects them.", next: { url: "https://vault.test/w/work/items/gmail-test", say: "Gmail rejected the OAuth client this connection uses. A human must replace its client secret in the vault, then reconnect the connections that use it; reconnecting first will not work." } })
    })
  })

it("names Testing mode when Google ends a sign-in a week after it was made", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx)
    const week = { ...ctx, now: () => ctx.now() + 7 * 86_400_000 }
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
    setUpstreamFetch(async () => Response.json({ error: "invalid_grant" }, { status: 400 }))
    const reason = 'Gmail stopped accepting the sign-in about 7 days after it was made, which is what happens when the OAuth app is in Testing. Set the app to "In production" on its consent screen, then reconnect'
    await expect(workspaceAccessToken(week, item)).rejects.toMatchObject({ code: "needs_reauth", message: `Reconnect this credential: ${reason}.` })
    expect(checkedCredential(ctx, item.slug)?.review).toEqual({ reason, at: expect.any(Number) })
  })
})

// A connection made before connectedAt was kept dates its grant from its
// connect.
it("names Testing mode for a connection made before its connect time was kept", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx)
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=?,payload=json_remove(payload,'$.connectedAt','$.refreshedAt') WHERE item=?", ctx.now() - 1, item.id)
    setUpstreamFetch(async () => Response.json({ error: "invalid_grant" }, { status: 400 }))
    await expect(workspaceAccessToken({ ...ctx, now: () => ctx.now() + 7 * 86_400_000 }, item)).rejects.toMatchObject({ code: "needs_reauth", message: expect.stringContaining("Gmail stopped accepting the sign-in about 7 days after it was made") })
  })
})

it("keeps using a token that still works while a failed refresh waits to retry", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx)
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() + 30_000, item.id)
    let sends = 0
    setUpstreamFetch(async () => { sends++; throw new Error("connection reset") })
    expect(await workspaceAccessToken(ctx, item)).toBe("test-access")
    expect(await workspaceAccessToken(ctx, checkedCredential(ctx, item.slug)!)).toBe("test-access")
    expect(sends).toBe(1)
    expect(checkedCredential(ctx, item.slug)?.status).toBe("active")
  })
})

// Each failure in a row waits longer (30 s doubling to an hour, 20% jitter
// either way), and a provider's Retry-After is waited out, up to a day.
it("waits longer after a second failed refresh than after the first", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx)
    setUpstreamFetch(async () => new Response("busy", { status: 503 }))
    const waits: number[] = []
    let now = ctx.now()
    for (let n = 0; n < 2; n++) {
      const then = { ...ctx, now: () => now }
      ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", now - 1, item.id)
      await expect(workspaceAccessToken(then, checkedCredential(ctx, item.slug)!)).rejects.toMatchObject({ code: "refresh_retrying" })
      const retryAt = connectionPayload(ctx, item.id).retryAt as number
      waits.push(retryAt - now)
      now = retryAt + 1
    }
    expect(waits[0]).toBeGreaterThanOrEqual(24_000)
    expect(waits[0]).toBeLessThanOrEqual(36_000)
    expect(waits[1]).toBeGreaterThan(waits[0]!)
  })
})

it("waits as long as the provider's Retry-After asks, a day included", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx)
    const now = ctx.now(), then = { ...ctx, now: () => now }
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", now - 1, item.id)
    setUpstreamFetch(async () => new Response("slow down", { status: 429, headers: { "retry-after": "86400" } }))
    await expect(workspaceAccessToken(then, item)).rejects.toMatchObject({ code: "refresh_retrying", extra: { retryAfter: 86400 } })
    expect(connectionPayload(ctx, item.id).retryAt).toBe(now + 86_400_000)
  })
})
it("waits until the date a provider's Retry-After names", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx)
    const now = Math.floor(ctx.now() / 1000) * 1000, then = { ...ctx, now: () => now }
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", now - 1, item.id)
    setUpstreamFetch(async () => new Response("slow down", { status: 503, headers: { "retry-after": new Date(now + 7_200_000).toUTCString() } }))
    await expect(workspaceAccessToken(then, item)).rejects.toMatchObject({ code: "refresh_retrying", extra: { retryAfter: 7200 } })
    expect(connectionPayload(ctx, item.id).retryAt).toBe(now + 7_200_000)
  })
})
// Longer than a day waits a day and tries again, so the failing days still
// add up to a Review row.
for (const form of ["date", "seconds"] as const)
  it(`waits a day, no longer, for a Retry-After ${form === "date" ? "date" : "in seconds"} a year away`, async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await connected(ctx)
      const now = Math.floor(ctx.now() / 1000) * 1000, then = { ...ctx, now: () => now }
      ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", now - 1, item.id)
      setUpstreamFetch(async () => new Response("slow down", { status: 429, headers: { "retry-after": form === "date" ? new Date(now + 365 * 86_400_000).toUTCString() : String(365 * 86_400) } }))
      await expect(workspaceAccessToken(then, item)).rejects.toMatchObject({ code: "refresh_retrying", extra: { retryAfter: 86_400 } })
      expect(connectionPayload(ctx, item.id).retryAt).toBe(now + 86_400_000)
    })
  })

// The scheduled refresh ends quietly only when the connection needs a person
// or has rescheduled its own retry; an edit racing it is retried by the
// scheduler, so the refresh chain does not stop. The retry may still find
// the raced attempt in flight, and then schedules itself for when it is not.
it("a scheduled refresh that meets an edit racing it fails, so the scheduler retries it until it renews", async () => {
  const { oauthArea } = await import("../src/vault/areas/oauth.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx)
    const now = ctx.now(), key = `workspace-refresh:${item.id}`
    const at = (ms: number) => ({ ...ctx, now: () => now + ms })
    // As the scheduler does, a job's row is removed before it runs.
    const due = () => ctx.sql.exec<{ due_at: number }>("SELECT due_at FROM schedule WHERE area='oauth' AND key=?", key).toArray()[0]?.due_at
    const run = (ms: number) => { ctx.sql.exec("DELETE FROM schedule WHERE area='oauth' AND key=?", key); return oauthArea.alarm!(at(ms), key) }
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", now - 1, item.id)
    let sends = 0
    setUpstreamFetch(async () => { if (++sends === 1) ctx.sql.exec("UPDATE items SET version=version+1 WHERE id=?", item.id); return Response.json({ access_token: sends === 1 ? "raced" : "renewed", expires_in: 3600 }) })
    await expect(run(0)).rejects.toMatchObject({ code: "conflict" })
    await run(60_000)
    expect(sends).toBe(1)
    expect(due()).toBe(now + 120_000)
    await run(120_001)
    expect(sends).toBe(2)
    expect(checkedCredential(ctx, item.slug)?.status).toBe("active")
    expect(connectionPayload(ctx, item.id)).not.toHaveProperty("refreshAttempt")
  })
})

// A refresh that fails without the provider saying the grant is gone never
// needs a reconnect, however long it lasts: once it has failed on four
// different days a person is told, once, and sees a Review row; the vault
// keeps retrying, and a refresh that works clears both.
it("a refresh failing on four different days is put in front of a person and keeps retrying, until one works", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx)
    const start = Date.UTC(2027, 0, 4, 12)
    let now = start
    const clock = { ...ctx, now: () => now }
    const failOn = async (day: number, answer: () => Response) => {
      now = start + day * 86_400_000
      setUpstreamFetch(async () => answer())
      ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=?,payload=json_remove(payload,'$.retryAt') WHERE item=?", now - 1, item.id)
      await expect(workspaceAccessToken(clock, checkedCredential(ctx, item.slug)!)).rejects.toMatchObject({ code: "refresh_retrying" })
    }
    const failing = () => ctx.sql.exec<{ account: string; payload: string }>("SELECT account,payload FROM notice_outbox").toArray().filter((n) => (JSON.parse(n.payload) as { kind: string }).kind === "connection_failing")
    for (let day = 0; day < 3; day++) await failOn(day, () => new Response("busy", { status: 503 }))
    expect(checkedCredential(ctx, item.slug)).toMatchObject({ status: "refresh_retrying", review: null })
    expect(failing()).toEqual([])
    await failOn(3, () => new Response("busy", { status: 503 }))
    const reason = "Mehen has not been able to renew the sign-in with Gmail since 2027-01-04 (last error: the provider failed (503)); it keeps trying"
    expect(checkedCredential(ctx, item.slug)).toMatchObject({ status: "refresh_retrying", review: { reason } })
    expect(failing().map((n) => n.account).sort()).toEqual(["acc_admin", "acc_owner"])
    expect(JSON.parse(failing()[0]!.payload)).toEqual({ kind: "connection_failing", workspace: { id: ctx.tenant, slug: "work", name: "Work" }, item: { id: item.id, slug: "gmail-test" }, provider: { id: "google-gmail", name: "Gmail" }, account: "test@example.com", since: new Date(start).toISOString(), reason, at: new Date(start + 3 * 86_400_000).toISOString() })
    expect(await needsYouRows(clock)).toEqual([{ kind: "review", id: "gmail-test", title: "Review gmail-test", url: "https://vault.test/w/work/items/gmail-test", expiresAt: null, requestedBy: null, item: "gmail-test", reason }])
    expect(await needsYouRows(clock, "member")).toEqual([])
    // Failing again names the last error and tells no one again.
    await failOn(4, () => { throw new Error("connection reset") })
    expect(checkedCredential(ctx, item.slug)).toMatchObject({ status: "refresh_retrying", review: { reason: "Mehen has not been able to renew the sign-in with Gmail since 2027-01-04 (last error: no answer (a network error or timeout)); it keeps trying" } })
    expect(failing()).toHaveLength(2)
    // Nor once the delivered notices are pruned, a month on.
    ctx.sql.exec("DELETE FROM notice_outbox")
    await failOn(35, () => new Response("busy", { status: 503 }))
    expect(failing()).toEqual([])
    now = start + 36 * 86_400_000
    setUpstreamFetch(async () => Response.json({ access_token: "renewed", expires_in: 3600 }))
    ctx.sql.exec("UPDATE workspace_oauth_connections SET payload=json_remove(payload,'$.retryAt') WHERE item=?", item.id)
    expect(await workspaceAccessToken(clock, checkedCredential(ctx, item.slug)!)).toBe("renewed")
    expect(checkedCredential(ctx, item.slug)).toMatchObject({ status: "active", review: null })
    expect(await needsYouRows(clock)).toEqual([])
  })
})

// The provider saying the grant is gone still needs a reconnect at once,
// however short the run of failures before it.
it("a refresh the provider ends after days of failures needs a reconnect at once", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx)
    const start = Date.UTC(2027, 0, 4, 12)
    for (let day = 0; day < 2; day++) {
      const then = { ...ctx, now: () => start + day * 86_400_000 }
      setUpstreamFetch(async () => new Response("busy", { status: 503 }))
      ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=?,payload=json_remove(payload,'$.retryAt') WHERE item=?", then.now() - 1, item.id)
      await expect(workspaceAccessToken(then, checkedCredential(ctx, item.slug)!)).rejects.toMatchObject({ code: "refresh_retrying" })
    }
    const then = { ...ctx, now: () => start + 2 * 86_400_000 }
    ctx.sql.exec("UPDATE workspace_oauth_connections SET payload=json_remove(payload,'$.retryAt') WHERE item=?", item.id)
    setUpstreamFetch(async () => Response.json({ error: "invalid_grant" }, { status: 400 }))
    await expect(workspaceAccessToken(then, checkedCredential(ctx, item.slug)!)).rejects.toMatchObject({ code: "needs_reauth" })
    expect(checkedCredential(ctx, item.slug)?.status).toBe("needs_reauth")
  })
})

it("Microsoft's interaction_required, consent_required and login_required end the grant, as invalid_grant does", async () => {
  const { getOAuthProvider } = await import("@mehen/protocol/templates")
  expect(getOAuthProvider("microsoft-graph")?.refresh.terminalErrors).toEqual(["invalid_grant", "interaction_required", "consent_required", "login_required"])
})

// A refresh answered interaction_required, as Microsoft's token endpoint
// sends it: a Microsoft connection needs a reconnect at once; a Google one,
// whose list does not name it, waits to retry.
for (const [provider, outcome] of [["microsoft-graph", "needs_reauth"], ["google-gmail", "refresh_retrying"]] as const)
  it(`a ${provider} refresh answered interaction_required ends in ${outcome}`, async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await connected(ctx)
      ctx.sql.exec("UPDATE items SET provider=? WHERE id=?", provider, item.id)
      // The client's binding admits its provider's token endpoint.
      ctx.sql.exec("UPDATE items SET binding=? WHERE slug='google-client'", JSON.stringify(getTemplate(provider === "microsoft-graph" ? "microsoft-oauth-client" : "google-oauth-client")!.binding))
      ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
      setUpstreamFetch(async () => Response.json({ error: "interaction_required", error_description: "AADSTS50076: Due to a configuration change made by your administrator, you must use multi-factor authentication." }, { status: 400 }))
      await expect(workspaceAccessToken(ctx, checkedCredential(ctx, item.slug)!)).rejects.toMatchObject({ code: outcome })
      expect(checkedCredential(ctx, item.slug)?.status).toBe(outcome)
    })
  })

// The notices about a connection go to whoever may reconnect it, worked out
// with no session: an identity rule that covers owners and admins does not
// keep them from it. A removed admin, a guest and a member who may not
// rotate a workspace credential are never sent one.
const NOTICE_TRIGGERS: Record<"connection_lost" | "oauth_client_rejected" | "connection_failing", (ctx: VaultContext, item: Awaited<ReturnType<typeof connected>>) => Promise<void>> = {
  connection_lost: async (ctx, item) => {
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
    setUpstreamFetch(async () => Response.json({ error: "invalid_grant" }, { status: 400 }))
    await expect(workspaceAccessToken(ctx, checkedCredential(ctx, item.slug)!)).rejects.toMatchObject({ code: "needs_reauth" })
  },
  oauth_client_rejected: async (ctx, item) => {
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
    setUpstreamFetch(async () => Response.json({ error: "invalid_client" }, { status: 401 }))
    await expect(workspaceAccessToken(ctx, checkedCredential(ctx, item.slug)!)).rejects.toMatchObject({ code: "needs_reauth" })
  },
  connection_failing: async (ctx, item) => {
    const start = Date.UTC(2027, 0, 4, 12)
    for (let day = 0; day < 4; day++) {
      const then = { ...ctx, now: () => start + day * 86_400_000 }
      setUpstreamFetch(async () => new Response("busy", { status: 503 }))
      ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=?,payload=json_remove(payload,'$.retryAt') WHERE item=?", then.now() - 1, item.id)
      await expect(workspaceAccessToken(then, checkedCredential(ctx, item.slug)!)).rejects.toMatchObject({ code: "refresh_retrying" })
    }
  },
}
it("a project connection's lost notice reaches its project manager an identity rule covers, and not a member who only uses the project", async () => {
  const { setSetting } = await import("../src/vault/areas/workspace-runtime.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx, "project")
    setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["owner", "admin", "member"] })
    setSetting(ctx, "identity_rule_rev", 2)
    await NOTICE_TRIGGERS.connection_lost(ctx, item)
    const sent = ctx.sql.exec<{ account: string; payload: string }>("SELECT account,payload FROM notice_outbox").toArray().filter((n) => (JSON.parse(n.payload) as { kind: string }).kind === "connection_lost")
    // Kim manages prj_a; the member's edit share and the guest's do not reach a rotation.
    expect(sent.map((n) => n.account).sort()).toEqual(["acc_admin", "acc_kim", "acc_owner"])
  })
})
for (const [kind, trigger] of Object.entries(NOTICE_TRIGGERS))
  it(`${kind} reaches the owner and admin an identity rule covers, and no removed admin, guest or member`, async () => {
    const { setSetting } = await import("../src/vault/areas/workspace-runtime.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await connected(ctx)
      setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["owner", "admin"] })
      setSetting(ctx, "identity_rule_rev", 2)
      ctx.sql.exec("UPDATE members SET role='admin',status='removed' WHERE id='mem_kim'")
      await trigger(ctx, item)
      const sent = ctx.sql.exec<{ account: string; payload: string }>("SELECT account,payload FROM notice_outbox").toArray().filter((n) => (JSON.parse(n.payload) as { kind: string }).kind === kind)
      expect(sent.map((n) => n.account).sort()).toEqual(["acc_admin", "acc_owner"])
    })
  })

// Who was told what: the outbox rows of these kinds, and the owner's Needs you rows.
function connectionNotices(ctx: VaultContext) {
  return ctx.sql.exec<{ account: string; payload: string }>("SELECT account,payload FROM notice_outbox ORDER BY created_at,id").toArray().map((n) => ({ account: n.account, payload: JSON.parse(n.payload) as { kind: string } & Record<string, unknown> })).filter((n) => n.payload.kind === "connection_lost" || n.payload.kind === "oauth_client_rejected")
}
async function needsYouRows(ctx: VaultContext, role = "owner") {
  const { credentialPending } = await import("../src/vault/areas/credentials-pending.ts")
  return credentialPending(ctx, memberPrincipal(ctx, role), memberInvocation(ctx, role)).flatMap((r) => r.view === "detail" ? [r.detail] : [])
}

it("a rejected client pauses every connection that uses it, with one notice and one row for the client", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const first = await connected(ctx)
    const again = createWorkspaceConnect(ctx, memberPrincipal(ctx), { provider: "google-gmail", client: "google-client", slug: "gmail-other", home: "workspace" }, memberInvocation(ctx))
    const action = WorkspaceStepUpActionSchema.parse(workspaceOAuthOps["oauth.connect_action"].handler(ctx, memberPrincipal(ctx), { connect: again.connect }, memberInvocation(ctx)))
    await startWorkspaceConnect(ctx, memberPrincipal(ctx), { connect: again.connect, state: "state-other-123456789" }, memberInvocation(ctx, "owner", action))
    upstream()
    await finishWorkspaceConnect(ctx, memberPrincipal(ctx), { connect: again.connect, state: "state-other-123456789", code: "code-other", error: null }, memberInvocation(ctx))
    const second = checkedCredential(ctx, "gmail-other")!
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=?", ctx.now() - 1)
    let sends = 0
    setUpstreamFetch(async () => { sends++; return Response.json({ error: "invalid_client" }, { status: 401 }) })
    await expect(workspaceAccessToken(ctx, first)).rejects.toMatchObject({ code: "needs_reauth", extra: { next: { url: "https://vault.test/w/work/items/gmail-test" } } })
    await expect(workspaceAccessToken(ctx, second)).rejects.toMatchObject({ code: "needs_reauth", extra: { next: { url: "https://vault.test/w/work/items/gmail-other" } } })
    expect(sends).toBe(1)
    expect(checkedCredential(ctx, "gmail-other")?.status).toBe("needs_reauth")
    const client = checkedCredential(ctx, "google-client")!
    expect(client).toMatchObject({ status: "needs_reauth", review: { reason: "Gmail rejected this OAuth client (its secret is wrong, expired or deleted), so the connections that use it are paused: replace its secret, then reconnect them" } })
    const notices = connectionNotices(ctx)
    expect(notices.map((n) => n.account).sort()).toEqual(["acc_admin", "acc_owner"])
    expect(notices[0]!.payload).toEqual({ kind: "oauth_client_rejected", workspace: { id: ctx.tenant, slug: "work", name: "Work" }, item: { id: client.id, slug: "google-client" }, clientRevision: client.configRev, provider: "Gmail", at: expect.any(String) })
    expect(await needsYouRows(ctx)).toEqual([{ kind: "review", id: "google-client", title: "Replace the client secret of google-client", url: "https://vault.test/w/work/items/google-client", expiresAt: null, requestedBy: null, item: "google-client", reason: "the provider rejected this OAuth client, so the connections that use it are paused; reconnect them once its secret is replaced" }])
    expect(await needsYouRows(ctx, "member")).toEqual([])
    // A new secret is a new revision: the client works again and each
    // connection's own row comes back.
    const replaced = await prepareCredential(ctx, { ...client, secretFields: { client_secret: "new-client-secret" } }, client)
    ctx.storage.transactionSync(() => storeCredential(ctx, replaced, memberPrincipal(ctx), "item.rotate"))
    expect(checkedCredential(ctx, "google-client")).toMatchObject({ status: "active", review: null })
    expect((await needsYouRows(ctx)).map((r) => [r.kind, r.id])).toEqual([["reconnect", "gmail-test"], ["reconnect", "gmail-other"]])
  })
})

// Restoring a client's previous secret replaces its secret too, so it
// clears the provider's rejection as a new secret does; any other review
// reason stays.
for (const reason of ["Gmail rejected this OAuth client (its secret is wrong, expired or deleted), so the connections that use it are paused: replace its secret, then reconnect them", "checked by hand"])
  it(`restoring a client's previous secret ${reason === "checked by hand" ? "keeps another review reason" : "clears its rejection"}`, async () => {
    const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const created = await client(ctx)
      const replaced = await prepareCredential(ctx, { ...created, secretFields: { client_secret: "new-client-secret" } }, created)
      ctx.storage.transactionSync(() => storeCredential(ctx, replaced, memberPrincipal(ctx), "item.rotate"))
      ctx.sql.exec("UPDATE items SET status='needs_reauth',review_reason=?,review_at=? WHERE id=?", reason, ctx.now(), created.id)
      const terms = { version: checkedCredential(ctx, "google-client")!.version, previous: created.version }
      const action = WorkspaceStepUpActionSchema.parse(await workspaceItemOps["items.action"].handler(ctx, memberPrincipal(ctx), { slug: "google-client", action: "restore", ...terms }, memberInvocation(ctx)))
      await workspaceItemOps["items.restore"].handler(ctx, memberPrincipal(ctx), { slug: "google-client", ...terms }, memberInvocation(ctx, "owner", action))
      expect(checkedCredential(ctx, "google-client")).toMatchObject({ status: "active", review: reason === "checked by hand" ? { reason } : null })
    })
  })

it("tells whoever may reconnect a connection once per break, with one Reconnect row until it works again", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx)
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
    setUpstreamFetch(async () => Response.json({ error: "invalid_grant" }, { status: 400 }))
    await expect(workspaceAccessToken(ctx, item)).rejects.toMatchObject({ code: "needs_reauth" })
    ctx.sql.exec("UPDATE items SET status='active' WHERE id=?", item.id)
    await expect(workspaceAccessToken({ ...ctx, now: () => ctx.now() + 60_000 }, checkedCredential(ctx, item.slug)!)).rejects.toMatchObject({ code: "needs_reauth" })
    // The same break found again is not a new one.
    await expect(workspaceAccessToken({ ...ctx, now: () => ctx.now() + 120_000 }, checkedCredential(ctx, item.slug)!)).rejects.toMatchObject({ code: "needs_reauth" })
    // One notice for the grant, however often it fails, to the owner and the
    // admin (who may rotate it) and not to the member or guest.
    const notices = connectionNotices(ctx)
    expect(notices.map((n) => n.account).sort()).toEqual(["acc_admin", "acc_owner"])
    expect(notices[0]!.payload).toMatchObject({ kind: "connection_lost", item: { id: item.id, slug: "gmail-test" }, provider: { id: "google-gmail", name: "Gmail" }, account: "test@example.com", reason: expect.stringMatching(/^Google revoked the sign-in/) })
    const rows = await needsYouRows(ctx)
    expect(rows).toEqual([{ kind: "reconnect", id: "gmail-test", title: "Reconnect gmail-test", url: "https://vault.test/w/work/items/gmail-test", expiresAt: null, requestedBy: null, item: "gmail-test", reason: expect.stringMatching(/^Google revoked the sign-in/) }])
    expect(await needsYouRows(ctx, "member")).toEqual([])
    const next = createWorkspaceConnect(ctx, memberPrincipal(ctx), { provider: "google-gmail", client: "google-client", slug: "gmail-test", home: "workspace" }, memberInvocation(ctx))
    const action = WorkspaceStepUpActionSchema.parse(workspaceOAuthOps["oauth.connect_action"].handler(ctx, memberPrincipal(ctx), { connect: next.connect }, memberInvocation(ctx)))
    await startWorkspaceConnect(ctx, memberPrincipal(ctx), { connect: next.connect, state: "state-again-123456789" }, memberInvocation(ctx, "owner", action))
    upstream()
    await finishWorkspaceConnect(ctx, memberPrincipal(ctx), { connect: next.connect, state: "state-again-123456789", code: "code-again", error: null }, memberInvocation(ctx))
    expect(checkedCredential(ctx, item.slug)).toMatchObject({ status: "active", review: null })
    expect(await needsYouRows(ctx)).toEqual([])
  })
})

// A later failure's reason replaces the first on the item and on the
// connection alike, so a reconnect clears the one Needs you shows.
it("a dead connection found dead again for another reason keeps one reason, and a reconnect clears it", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx)
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
    setUpstreamFetch(async () => Response.json({ error: "invalid_grant" }, { status: 400 }))
    await expect(workspaceAccessToken(ctx, item)).rejects.toMatchObject({ code: "needs_reauth" })
    await expect(workspaceAccessToken({ ...ctx, now: () => ctx.now() + 7 * 86_400_000 }, checkedCredential(ctx, item.slug)!)).rejects.toMatchObject({ code: "needs_reauth", message: expect.stringContaining("Testing") })
    const review = checkedCredential(ctx, item.slug)!.review!
    expect(review.reason).toContain("Testing")
    expect((connectionPayload(ctx, item.id).lost as { reason: string }).reason).toBe(review.reason)
    const next = createWorkspaceConnect(ctx, memberPrincipal(ctx), { provider: "google-gmail", client: "google-client", slug: "gmail-test", home: "workspace" }, memberInvocation(ctx))
    const action = WorkspaceStepUpActionSchema.parse(workspaceOAuthOps["oauth.connect_action"].handler(ctx, memberPrincipal(ctx), { connect: next.connect }, memberInvocation(ctx)))
    await startWorkspaceConnect(ctx, memberPrincipal(ctx), { connect: next.connect, state: "state-again-123456789" }, memberInvocation(ctx, "owner", action))
    upstream()
    await finishWorkspaceConnect(ctx, memberPrincipal(ctx), { connect: next.connect, state: "state-again-123456789", code: "code-again", error: null }, memberInvocation(ctx))
    expect(checkedCredential(ctx, item.slug)).toMatchObject({ status: "active", review: null })
  })
})

it("a rejected client is told once per revision, even after the connection that found it is deleted", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const first = await connected(ctx)
    const again = createWorkspaceConnect(ctx, memberPrincipal(ctx), { provider: "google-gmail", client: "google-client", slug: "gmail-other", home: "workspace" }, memberInvocation(ctx))
    const action = WorkspaceStepUpActionSchema.parse(workspaceOAuthOps["oauth.connect_action"].handler(ctx, memberPrincipal(ctx), { connect: again.connect }, memberInvocation(ctx)))
    await startWorkspaceConnect(ctx, memberPrincipal(ctx), { connect: again.connect, state: "state-other-123456789" }, memberInvocation(ctx, "owner", action))
    upstream()
    await finishWorkspaceConnect(ctx, memberPrincipal(ctx), { connect: again.connect, state: "state-other-123456789", code: "code-other", error: null }, memberInvocation(ctx))
    const second = checkedCredential(ctx, "gmail-other")!
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=?", ctx.now() - 1)
    let sends = 0
    setUpstreamFetch(async () => { sends++; return Response.json({ error: "invalid_client" }, { status: 401 }) })
    await expect(workspaceAccessToken(ctx, first)).rejects.toMatchObject({ code: "needs_reauth" })
    ctx.sql.exec("DELETE FROM workspace_oauth_connections WHERE item=?", first.id)
    ctx.sql.exec("DELETE FROM items WHERE id=?", first.id)
    await expect(workspaceAccessToken(ctx, second)).rejects.toMatchObject({ code: "needs_reauth" })
    expect(sends).toBe(2)
    expect(connectionNotices(ctx).map((n) => [n.account, n.payload.kind]).sort()).toEqual([["acc_admin", "oauth_client_rejected"], ["acc_owner", "oauth_client_rejected"]])
  })
})

it("an agent that meets a paused connection is sent to the rejected client, not to reconnect", async () => {
  const { connectionNeedsReauth } = await import("../src/vault/areas/oauth-workspace.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx)
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
    setUpstreamFetch(async () => Response.json({ error: "invalid_client" }, { status: 401 }))
    await expect(workspaceAccessToken(ctx, item)).rejects.toMatchObject({ code: "needs_reauth" })
    expect(connectionNeedsReauth(ctx, checkedCredential(ctx, item.slug)!, { principal: memberPrincipal(ctx), invocation: memberInvocation(ctx) }).toJSON()).toMatchObject({ error: "needs_reauth", next: { url: "https://vault.test/w/work/items/google-client" } })
    // A new client secret is a new revision: the connection now needs reconnecting.
    ctx.sql.exec("UPDATE items SET config_rev=config_rev+1 WHERE slug='google-client'")
    expect(connectionNeedsReauth(ctx, checkedCredential(ctx, item.slug)!).toJSON()).toEqual({ error: "needs_reauth", message: `"gmail-test" needs to be connected again: its OAuth client was rejected by Gmail: replace the client's secret, then reconnect.`, next: { url: "https://vault.test/w/work/items/gmail-test", say: "Reconnect this credential in the workspace." } })
  })
})

// A reconnect never drops a scope: with none asked for it keeps the
// connection's, and scopes asked for are added to them.
for (const asked of [undefined, ["gmail.send"]] as const)
  it(`a reconnect ${asked ? "asking for gmail.send adds it to" : "asking for nothing keeps"} the connection's scopes`, async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await connected(ctx)
      // Narrowed to gmail.readonly, not Gmail's default gmail.modify.
      ctx.sql.exec("UPDATE workspace_oauth_connections SET payload=json_set(payload,'$.scopes',json(?)) WHERE item=?", JSON.stringify(["https://www.googleapis.com/auth/gmail.readonly"]), item.id)
      const c = createWorkspaceConnect(ctx, memberPrincipal(ctx), { provider: "google-gmail", client: "google-client", slug: "gmail-test", home: "workspace", ...(asked ? { scopes: [...asked] } : {}) }, memberInvocation(ctx))
      const flow = JSON.parse(ctx.sql.exec<{ payload: string }>("SELECT payload FROM workspace_credential_requests WHERE id=?", c.connect).toArray()[0]!.payload) as { scopes: string[] }
      expect(flow.scopes).toEqual(["https://www.googleapis.com/auth/gmail.readonly", ...(asked ? ["https://www.googleapis.com/auth/gmail.send"] : [])])
    })
  })

// An agent meeting a dead connection gets a reconnect link pinned to its
// account and keeping its scopes, to wait on: on the failure that kills it
// and on every call after, the same open link each time.
it("a dead connection reaches the agent with a pinned reconnect link to wait on, the first time and after", async () => {
  const { authoriseWorkspaceRelay } = await import("../src/vault/areas/relay-workspace.ts")
  const { deviceInvocation, devicePrincipal } = await import("./credentials-test-support.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx)
    ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.modes',json('[\"relay\"]')) WHERE id='dev_admin'")
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
    setUpstreamFetch(async (req) => req.url.includes("oauth2") ? Response.json({ error: "invalid_grant" }, { status: 400 }) : new Response("unexpected", { status: 500 }))
    const relay = async () => { try { await authoriseWorkspaceRelay(ctx, devicePrincipal("dev_admin"), { item: item.slug, method: "GET", url: "https://gmail.googleapis.com/gmail/v1/users/me/profile", headers: [] }, await deviceInvocation(ctx, "dev_admin")) } catch (e) { if (e instanceof VaultError) return e.toJSON(); throw e } throw new Error("Expected refusal") }
    const first = await relay()
    const connect = ctx.sql.exec<{ id: string; target_id: string; payload: string; expires_at: number }>("SELECT id,target_id,payload,expires_at FROM workspace_credential_requests WHERE kind='connect' AND status='open' AND requester_device='dev_admin'").toArray()
    expect(connect).toHaveLength(1)
    const con = connect[0]!.id
    expect(first).toEqual({ error: "needs_reauth", message: `"gmail-test" must be reconnected: Google revoked the sign-in: the password was changed, access was removed in the Google account's security settings, or the account signed in to this app too many times (Google keeps 100).`, next: { url: `https://vault.test/w/work/c/${con}`, command: `mehen wait ${con} --timeout 60 --json`, say: "Gmail for test@example.com must be reconnected. Open this link, sign in to the vault, then sign in to Gmail as test@example.com." }, expiresAt: new Date(connect[0]!.expires_at).toISOString() })
    expect(connect[0]!.target_id).toBe(item.id)
    expect(JSON.parse(connect[0]!.payload)).toMatchObject({ expect: "test@example.com", scopes: ["https://www.googleapis.com/auth/gmail.modify"], pinnedIdentity: { subject: expect.any(String) } })
    expect(await relay()).toEqual(first)
    // One row for the dead connection, to whoever may reconnect it, opening
    // the agent's link; none for the agent's connect apart.
    expect(await needsYouRows(ctx)).toEqual([{ kind: "reconnect", id: "gmail-test", title: "Reconnect gmail-test", url: `https://vault.test/w/work/c/${con}`, expiresAt: null, requestedBy: null, item: "gmail-test", reason: expect.stringMatching(/^Google revoked the sign-in/) }])
    expect(await needsYouRows(ctx, "member")).toEqual([])
  })
})

// A person who opens a connection's page and saves its settings after the
// vault renewed its token is not refused: a renewal moves its version, not
// what the person saw. A reconnect still refuses.
it("a connection's settings change signed before a token renewal still saves; one signed before a reconnect does not", async () => {
  const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx), change = { description: "renewed meanwhile" }
    const action = WorkspaceStepUpActionSchema.parse(await workspaceItemOps["items.action"].handler(ctx, memberPrincipal(ctx), { slug: item.slug, change, action: "update" }, memberInvocation(ctx)))
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
    setUpstreamFetch(async () => Response.json({ access_token: "renewed", expires_in: 3600 }))
    expect(await workspaceAccessToken(ctx, item)).toBe("renewed")
    expect(checkedCredential(ctx, item.slug)).toMatchObject({ version: item.version + 1, configRev: item.configRev })
    await workspaceItemOps["items.update"].handler(ctx, memberPrincipal(ctx), { slug: item.slug, change }, memberInvocation(ctx, "owner", action))
    expect(checkedCredential(ctx, item.slug)?.description).toBe("renewed meanwhile")
    const again = { description: "reconnected meanwhile" }, current = checkedCredential(ctx, item.slug)!
    const stale = WorkspaceStepUpActionSchema.parse(await workspaceItemOps["items.action"].handler(ctx, memberPrincipal(ctx), { slug: item.slug, change: again, action: "update" }, memberInvocation(ctx)))
    ctx.sql.exec("UPDATE items SET config_rev=config_rev+1 WHERE id=?", current.id)
    await expect(workspaceItemOps["items.update"].handler(ctx, memberPrincipal(ctx), { slug: item.slug, change: again }, memberInvocation(ctx, "owner", stale))).rejects.toMatchObject({ code: "conflict" })
  })
})

it("an agent sees what a connection may do: its scopes, when its token ends and whether a renewal is retrying, never a token", async () => {
  const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
  const { deviceInvocation, devicePrincipal } = await import("./credentials-test-support.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx)
    const expiresAt = ctx.sql.exec<{ expires_at: number }>("SELECT expires_at FROM workspace_oauth_connections WHERE item=?", item.id).toArray()[0]!.expires_at
    const described = () => workspaceItemOps["items.describe"].handler(ctx, devicePrincipal("dev_admin"), { slug: item.slug }, deviceInvocationSync) as { connection?: unknown }
    const deviceInvocationSync = await deviceInvocation(ctx, "dev_admin")
    expect(described().connection).toEqual({ scopes: ["openid", "email", "https://www.googleapis.com/auth/gmail.modify"], expiresAt: new Date(expiresAt).toISOString(), refreshing: false, client: "google-client" })
    ctx.sql.exec("UPDATE workspace_oauth_connections SET payload=json_set(payload,'$.retryAt',?) WHERE item=?", ctx.now() + 60_000, item.id)
    expect(described().connection).toMatchObject({ refreshing: true })
    expect(JSON.stringify(described())).not.toContain("test-access")
  })
})

it("a connection's description names its OAuth client only to a reader who may see that client", async () => {
  const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
  const { deviceInvocation, devicePrincipal } = await import("./credentials-test-support.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await connected(ctx, "project")
    const described = async (device: string) => (workspaceItemOps["items.describe"].handler(ctx, devicePrincipal(device), { slug: item.slug }, await deviceInvocation(ctx, device)) as { connection?: { client?: string } }).connection
    expect((await described("dev_admin"))?.client).toBe("google-client")
    const team = await described("dev_service")
    expect(team).toMatchObject({ refreshing: false })
    expect(team).not.toHaveProperty("client")
  })
})

// The machine that asked for a connection, which may see its client, is told
// the client in the finished connect's status, as describe tells it.
it("a finished connect's status names the OAuth client to the machine that asked, which may see it", async () => {
  const { deviceInvocation, devicePrincipal } = await import("./credentials-test-support.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    await client(ctx)
    const machine = devicePrincipal("dev_admin"), asked = await deviceInvocation(ctx, "dev_admin")
    const c = createWorkspaceConnect(ctx, machine, { provider: "google-gmail", client: "google-client", slug: "gmail-agent", home: "workspace", reason: "Read the inbox" }, asked)
    const p = memberPrincipal(ctx), action = WorkspaceStepUpActionSchema.parse(workspaceOAuthOps["oauth.connect_action"].handler(ctx, p, { connect: c.connect }, memberInvocation(ctx)))
    await startWorkspaceConnect(ctx, p, { connect: c.connect, state: "state-agent-123456789" }, memberInvocation(ctx, "owner", action))
    upstream()
    await finishWorkspaceConnect(ctx, p, { connect: c.connect, state: "state-agent-123456789", code: "code-agent", error: null }, memberInvocation(ctx))
    const status = await workspaceOAuthOps["oauth.connectStatus"].handler(ctx, machine, { connect: c.connect }, asked)
    expect(status).toMatchObject({ status: "completed", item: { slug: "gmail-agent", connection: { client: "google-client" } } })
  })
})

// A team machine reaches the project connection but not the workspace client
// it signs in through: neither its stored reason nor an error names the
// client, whether the client was replaced or the provider rejected it. A
// machine that may see the client is still sent to it.
for (const stop of ["replaced", "rejected"] as const)
  it(`a team machine that may not see the OAuth client never learns its name when it was ${stop}`, async () => {
    const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
    const { authoriseWorkspaceRelay } = await import("../src/vault/areas/relay-workspace.ts")
    const { deviceInvocation, devicePrincipal } = await import("./credentials-test-support.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await connected(ctx, "project")
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.modes',json('[\"relay\"]')) WHERE id IN ('dev_admin','dev_service')")
      ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
      if (stop === "replaced")
        ctx.sql.exec("UPDATE items SET config_rev=config_rev+1 WHERE slug='google-client'")
      setUpstreamFetch(async () => Response.json({ error: "invalid_client" }, { status: 401 }))
      const fetched = async (device: string) => { try { await authoriseWorkspaceRelay(ctx, devicePrincipal(device), { item: item.slug, method: "GET", url: "https://gmail.googleapis.com/gmail/v1/users/me/profile", headers: [] }, await deviceInvocation(ctx, device)) } catch (e) { if (e instanceof VaultError) return e.toJSON(); throw e } throw new Error("Expected refusal") }
      const read = async (op: "items.list" | "items.describe") => workspaceItemOps[op].handler(ctx, devicePrincipal("dev_service"), { slug: item.slug }, await deviceInvocation(ctx, "dev_service"))
      const team = await fetched("dev_service")
      expect(team).toMatchObject({ error: "needs_reauth", next: { url: "https://vault.test/w/work/items/gmail-test" } })
      const reason = stop === "replaced" ? "its OAuth client was replaced or changed since it was connected" : "its OAuth client was rejected by Gmail: replace the client's secret, then reconnect"
      expect(checkedCredential(ctx, item.slug)?.review?.reason).toBe(reason)
      for (const seen of [team, await fetched("dev_service"), await read("items.list"), await read("items.describe"), connectionNotices(ctx).filter((n) => n.payload.kind === "connection_lost")])
        expect(JSON.stringify(seen)).not.toContain("google-client")
      if (stop === "rejected")
        expect(await fetched("dev_admin")).toMatchObject({ error: "needs_reauth", message: expect.stringContaining('the OAuth client "google-client"'), next: { url: "https://vault.test/w/work/items/google-client" } })
    })
  })
