import { afterEach, describe, expect, it, vi } from "vitest"
import { getTemplate, WorkspaceStepUpActionSchema } from "@mehen/protocol"
import type { VaultContext } from "../src/vault/core.ts"
import { checkedCredential, prepareCredential, storeCredential } from "../src/vault/areas/items-workspace.ts"
import { createWorkspaceConnect, startWorkspaceConnect, finishWorkspaceConnect, workspaceAccessToken, workspaceOAuthOps } from "../src/vault/areas/oauth-workspace.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { credentialInput, credentialsFixture, inAccess, memberInvocation, memberPrincipal } from "./credentials-test-support.ts"
afterEach(() => setUpstreamFetch(null))

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
      await expect(workspaceAccessToken(ctx, item)).rejects.toMatchObject({ code: "needs_reauth", message: "Reconnect this credential." })
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
      await expect(workspaceAccessToken(ctx, item)).rejects.toMatchObject({ code: "needs_reauth", message: "Reconnect this credential." })
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
    await expect(workspaceAccessToken(ctx, item)).rejects.toMatchObject({ code: "needs_reauth", message: "Reconnect this credential." })
    expect(open).not.toHaveBeenCalled()
    expect(sends()).toBe(0)
    expect(checkedCredential(ctx, item.slug)?.status).toBe("needs_reauth")
  })
})
for (const stale of [false, true])
  it(`handles a ${stale ? "stale" : "fresh"} unresolved refresh marker without replaying an exchange`, async () => {
    const { canonicalJson } = await import("@mehen/protocol")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const s = await started(ctx, "private")
      upstream()
      await finishWorkspaceConnect(ctx, s.p, finishInput(s), s.i)
      const item = checkedCredential(ctx, "gmail-test")!
      ctx.sql.exec("UPDATE workspace_oauth_connections SET payload=json_set(payload,'$.refreshAttempt',json(?)),expires_at=? WHERE item=?", JSON.stringify({ id: "rfa_crashed", startedAt: ctx.now() - (stale ? 120001 : 0) }), ctx.now() - 1, item.id)
      const before = canonicalJson([ctx.sql.exec("SELECT * FROM items").toArray(), ctx.sql.exec("SELECT * FROM workspace_oauth_connections").toArray(), ctx.sql.exec("SELECT * FROM audit").toArray()])
      const sends = upstream(), open = vi.spyOn(ctx, "openField")
      await expect(workspaceAccessToken(ctx, item)).rejects.toMatchObject({ code: stale ? "needs_reauth" : "refresh_retrying", message: stale ? "Reconnect this credential." : "A credential refresh is already in progress." })
      expect(sends()).toBe(0)
      expect(open).not.toHaveBeenCalled()
      expect(checkedCredential(ctx, item.slug)?.version).toBe(item.version)
      if (stale) {
        expect(checkedCredential(ctx, item.slug)?.status).toBe("needs_reauth")
        expect(ctx.sql.exec<{
          payload: string
        }>("SELECT payload FROM workspace_oauth_connections WHERE item=?", item.id).toArray()[0]?.payload).not.toContain("refreshAttempt")
      }
      else
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
      const current=checkedCredential(ctx,item.slug)!,digest=await stepUpDigest({change,version:current.version,configRevision:current.configRev})
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

for(const failure of ["network","malformed-success","failed-with-token"] as const)it(`an ambiguous ${failure} refresh is never replayed`,async()=>{
  const {oauthArea}=await import("../src/vault/areas/oauth.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    const s=await started(ctx);upstream();await finishWorkspaceConnect(ctx,s.p,finishInput(s),s.i)
    const item=checkedCredential(ctx,"gmail-test")!
    ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?",ctx.now()-1,item.id)
    let sends=0
    setUpstreamFetch(async()=>{
      sends++
      if(failure === "network")throw new Error("provider connection lost")
      return failure === "malformed-success"?Response.json({unexpected:true}):Response.json({access_token:"ambiguous-access",refresh_token:"possibly-rotated"},{status:503})
    })
    await expect(workspaceAccessToken(ctx,item)).rejects.toMatchObject({code:"refresh_retrying"})
    const payload=JSON.parse(ctx.sql.exec<{payload:string}>("SELECT payload FROM workspace_oauth_connections WHERE item=?",item.id).toArray()[0]!.payload) as {refreshAttempt:{startedAt:number}}
    expect(payload.refreshAttempt).toBeDefined()
    const open=vi.spyOn(ctx,"openField")
    await expect(workspaceAccessToken(ctx,checkedCredential(ctx,item.slug)!)).rejects.toMatchObject({code:"refresh_retrying",message:"A credential refresh is already in progress."})
    const later={...ctx,now:()=>payload.refreshAttempt.startedAt+120001}
    await expect(workspaceAccessToken(later,checkedCredential(ctx,item.slug)!)).rejects.toMatchObject({code:"needs_reauth",message:"Reconnect this credential."})
    expect(checkedCredential(ctx,item.slug)).toMatchObject({status:"needs_reauth",version:item.version,configRev:item.configRev})
    await oauthArea.alarm!({...later,now:()=>later.now()+3600000},`workspace-refresh:${item.id}`)
    expect(open).not.toHaveBeenCalled();expect(sends).toBe(1);open.mockRestore()
  })
})
