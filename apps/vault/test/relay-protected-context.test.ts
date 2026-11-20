import { afterEach, describe, expect, it, vi } from "vitest"
import { canonicalJson, type WorkspaceStepUpAction } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { authoriseWorkspaceRelay } from "../src/vault/areas/relay-workspace.ts"
import { checkedCredential, registerCredentialProvider, visibleCredential } from "../src/vault/areas/items-workspace.ts"
import { workspaceApproval, workspaceApprovalOps } from "../src/vault/areas/approvals-workspace.ts"
import { projectFixture, inAccess } from "./projects-workspace-fixture.ts"
import { deviceInvocation, devicePrincipal, memberInvocation, memberPrincipal } from "./credentials-test-support.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { fixtureSql } from "./fixture-sql.ts"
afterEach(() => setUpstreamFetch(null))
const request = { item: "key-workspace", method: "GET", url: "https://api.example.com/test", headers: [], context: { project: "prj_a", environment: "prod" } }

async function relayFixture() {
  const f = await projectFixture()
  await inAccess(f.tenant, ctx => {
    registerCredentialProvider()
    fixtureSql(ctx).exec("UPDATE items SET policy=?", JSON.stringify({ default: "allow", rules: [] }))
    ctx.sql.exec("UPDATE vars SET item='key-workspace' WHERE env='prod'")
    for (const project of ["prj_a", "prj_b"])
      ctx.sql.exec("INSERT OR IGNORE INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES(?,'prod','TOKEN','key-workspace','key','member:mem_owner',?)", project, ctx.now())
  })
  return f
}

async function required(ctx: VaultContext, req: unknown = request) { try {
  await authoriseWorkspaceRelay(ctx, devicePrincipal(), req, await deviceInvocation(ctx))
  throw new Error("Expected approval")
}
catch (e) {
  if (!(e instanceof VaultError) || e.code !== "approval_required")
    throw e
  expect(e.extra.approval).toBeTruthy()
  return e.extra.approval as string
} }

async function decide(ctx: VaultContext, id: string, role: string) {
  const row = workspaceApproval(ctx, id)
  if (!row)
    throw new Error("approval")
  const subject = JSON.parse(row.subject) as {
    constraints: {
      uses: number
      ttlSeconds: number
    }
  }
  const action: WorkspaceStepUpAction = { type: "approval.decide", approval: id, digest: row.digest, decision: "approve", constraints: subject.constraints }
  return workspaceApprovalOps["approvals.decide"]!.handler(ctx, memberPrincipal(ctx, role), { id, decision: "approve" }, memberInvocation(ctx, role, action))
}
const errorBody = (error: unknown) => error instanceof VaultError ? error.toJSON() : error
describe("protected relay context and final authority", () => {
  for (const bad of ["contextless", "dev", "non-referencing"] as const)
    it(`refuses ${bad} protected use before opening, storing or sending`, async () => {
      const f = await relayFixture()
      await inAccess(f.tenant, async (ctx) => {
        const { context: _context, ...withoutContext } = request
        const input = bad === "contextless" ? withoutContext : { ...request, context: { project: "prj_a", environment: bad === "dev" ? "dev" : "staging" } }
        const before = canonicalJson(ctx.sql.exec("SELECT * FROM approvals").toArray()), open = vi.spyOn(ctx, "openField")
        let sends = 0
        setUpstreamFetch(async () => { sends++; return new Response("ok"); })
        let failure: unknown
        try {
          await authoriseWorkspaceRelay(ctx, devicePrincipal(), input, await deviceInvocation(ctx))
        }
        catch (e) {
          failure = errorBody(e)
        }
        expect(failure).toEqual({ error: "environment_refused", message: "This credential needs an authorised protected context.", next: { command: "mehen run --env <environment> -- <command>", say: "Run with a literal --env in an authorised protected environment and approve that run." } })
        expect(open).not.toHaveBeenCalled()
        expect(sends).toBe(0)
        expect(canonicalJson(ctx.sql.exec("SELECT * FROM approvals").toArray())).toBe(before)
        expect(checkedCredential(ctx, "key-workspace")?.lastUsedAt).toBeNull()
      })
    })
  it("keeps protected metadata visible at an unprotected maximum, but refuses its use", async () => {
    const f = await relayFixture()
    await inAccess(f.tenant, async (ctx) => {
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.maxEnvironment','unprotected') WHERE id='dev_member'")
      expect(visibleCredential(ctx, devicePrincipal(), "key-workspace").slug).toBe("key-workspace")
      const open = vi.spyOn(ctx, "openField")
      await expect(authoriseWorkspaceRelay(ctx, devicePrincipal(), request, await deviceInvocation(ctx))).rejects.toMatchObject({ code: "environment_refused" })
      expect(open).not.toHaveBeenCalled()
    })
  })
  it("requires a manager of every four-eyes project, not the owner or a B-only manager", async () => {
    const f = await relayFixture()
    await inAccess(f.tenant, async (ctx) => {
      const id = await required(ctx)
      // Kim is initially A-only; make Kim B-only, then both, without an elevated role.
      const share = ctx.sql.exec<{
        id: string
        value: string
      }>("SELECT id,value FROM project_shares WHERE subject_id='mem_kim'").toArray()[0]!
      const b = { ...JSON.parse(share.value) as Record<string, unknown>, project: "prj_b" }
      fixtureSql(ctx).exec("UPDATE project_shares SET project='prj_b',value=? WHERE id=?", JSON.stringify(b), share.id)
      for (const role of ["member", "kim"]) {
        const before = canonicalJson(ctx.sql.exec("SELECT * FROM protected_use_grants").toArray())
        await expect(decide(ctx, id, role)).rejects.toMatchObject({ code: "forbidden", message: "You are not allowed to do that." })
        expect(canonicalJson(ctx.sql.exec("SELECT * FROM protected_use_grants").toArray())).toBe(before)
      }
      const a = { ...b, id: "shr_kim_a", project: "prj_a" }
      fixtureSql(ctx).exec("INSERT INTO project_shares VALUES(?,'prj_a','member','mem_kim',?)", a.id, JSON.stringify(a))
      await decide(ctx, id, "kim")
      const material = await authoriseWorkspaceRelay(ctx, devicePrincipal(), { ...request, approval: id }, await deviceInvocation(ctx))
      expect(material.headers).toContainEqual(["authorization", "Bearer test-fixture-key-not-a-live-secret"])
      expect(ctx.sql.exec<{
        uses_left: number
      }>("SELECT uses_left FROM protected_use_grants WHERE approval=?", id).toArray()[0]?.uses_left).toBe(0)
      const second = await required(ctx, { ...request, approval: id })
      expect(second).not.toBe(id)
    })
  })
  it("binds the exact request and refuses reference invalidation during secret opening without spending consent", async () => {
    const f = await relayFixture()
    await inAccess(f.tenant, async (ctx) => {
      const id = await required(ctx)
      await decide(ctx, id, "owner")
      const changed = await required(ctx, { ...request, url: "https://api.example.com/different", approval: id })
      expect(changed).not.toBe(id)
      let sends = 0
      setUpstreamFetch(async () => { sends++; return new Response("ok"); })
      const wrapped = { ...ctx, async openField(ref: Parameters<typeof ctx.openField>[0], sealed: Parameters<typeof ctx.openField>[1]) { const value = await ctx.openField(ref, sealed); ctx.sql.exec("UPDATE environments SET reference_rev=reference_rev+1 WHERE project='prj_b' AND name='prod'"); return value; } }
      await expect(authoriseWorkspaceRelay(wrapped, devicePrincipal(), { ...request, approval: id }, await deviceInvocation(ctx))).rejects.toMatchObject({ code: "conflict", message: "Access changed; ask for a new approval." })
      expect(sends).toBe(0)
      expect(checkedCredential(ctx, "key-workspace")?.lastUsedAt).toBeNull()
      expect(ctx.sql.exec<{
        uses_left: number
      }>("SELECT uses_left FROM protected_use_grants WHERE approval=?", id).toArray()[0]?.uses_left).toBe(1)
      expect(ctx.sql.exec<{
        n: number
      }>("SELECT count(*) AS n FROM audit WHERE action='relay.allow'").toArray()[0]?.n).toBe(0)
    })
  })
})
async function approvedRelayRun(ctx: VaultContext, beforeStart?: (approval: string) => Promise<void>, allowMissing = false) {
  const { workspaceRunOps } = await import("../src/vault/areas/runs-workspace.ts")
  const invocation = await deviceInvocation(ctx), principal = devicePrincipal()
  const input = { project: "prj_a", env: "prod", envSource: "flag", remote: null, worktree: "/test/repo", head: null, vars: ["TOKEN"], command: "bun run", argv: ["bun", "run"] }
  let approval: string | undefined
  try { await workspaceRunOps["runs.create"]!.handler(ctx, principal, input, invocation) }
  catch (error) { if (!(error instanceof VaultError) || error.code !== "approval_required") throw error; approval = error.extra.approval }
  expect(approval).toBeTruthy()
  await decide(ctx, approval!, "owner")
  await beforeStart?.(approval!)
  const created = await workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...input, approval }, invocation) as import("@mehen/protocol").WorkspaceRunCreated
  const placeholder = created.vars.find(variable => variable.delivery === "placeholder")
  if (!placeholder && !allowMissing) throw new Error("Expected a relay placeholder")
  return { approval: approval!, request: { run: created.run, method: "GET", url: "https://api.example.com/test", headers: (placeholder ? [["Authorization", `Bearer ${placeholder.value}`]] : []) as [string, string][] } }
}

describe("protected run relay integration", () => {
  it("relays twice through a retained run authorisation without spending the start grant again", async () => {
    const { forwardRelay } = await import("../src/relay/forward.ts")
    const f = await relayFixture()
    await inAccess(f.tenant, async ctx => {
      const run = await approvedRelayRun(ctx)
      let sends = 0
      setUpstreamFetch(async () => { sends++; return new Response("ok") })
      for (let n = 0; n < 2; n++) {
        const material = await authoriseWorkspaceRelay(ctx, devicePrincipal(), run.request, await deviceInvocation(ctx))
        expect(material.headers).toContainEqual(["authorization", "Bearer test-fixture-key-not-a-live-secret"])
        expect(material.workspaceAudit?.map(context => context.run)).toEqual([run.request.run])
        expect(await (await forwardRelay(material, null)).text()).toBe("ok")
      }
      expect(sends).toBe(2)
      expect(ctx.sql.exec<{ uses_left: number }>("SELECT uses_left FROM protected_use_grants WHERE approval=?", run.approval).toArray()[0]?.uses_left).toBe(0)
      expect(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM approvals").toArray()[0]?.count).toBe(1)
    })
  })

  for (const change of ["revoked-device", "lost-decider", "changed-reference"] as const) it(`refuses ${change} at the final relay point after opening, with no material release or send`, async () => {
    const f = await relayFixture()
    await inAccess(f.tenant, async ctx => {
      const run = await approvedRelayRun(ctx)
      let opens = 0, sends = 0
      setUpstreamFetch(async () => { sends++; return new Response("ok") })
      const wrapped = { ...ctx, async openField(ref: Parameters<typeof ctx.openField>[0], sealed: Parameters<typeof ctx.openField>[1]) {
        const value = await ctx.openField(ref, sealed)
        opens++
        if (change === "revoked-device") ctx.sql.exec("UPDATE devices SET revoked_at=? WHERE id='dev_member'", ctx.now())
        if (change === "lost-decider") fixtureSql(ctx).exec("UPDATE members SET role='member' WHERE id='mem_owner'")
        if (change === "changed-reference") ctx.sql.exec("UPDATE environments SET reference_rev=reference_rev+1 WHERE project='prj_b' AND name='prod'")
        return value
      } }
      await expect(authoriseWorkspaceRelay(wrapped, devicePrincipal(), run.request, await deviceInvocation(ctx))).rejects.toMatchObject({ code: change === "revoked-device" ? "not_found" : change === "lost-decider" ? "forbidden" : "conflict", message: change === "revoked-device" ? 'No credential called "key-workspace".' : change === "lost-decider" ? "This use no longer has a current approval." : "Access changed; ask for a new approval." })
      expect(opens).toBe(1)
      expect(sends).toBe(0)
      expect(checkedCredential(ctx, "key-workspace")?.lastUsedAt).toBeNull()
      expect(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM audit WHERE action='relay.allow'").toArray()[0]?.count).toBe(0)
    })
  })

  it("rejects another device's run id before opening or disclosing its stored context", async () => {
    const f = await relayFixture()
    await inAccess(f.tenant, async ctx => {
      const run = await approvedRelayRun(ctx), open = vi.spyOn(ctx, "openField")
      await expect(authoriseWorkspaceRelay(ctx, devicePrincipal("dev_kim"), run.request, await deviceInvocation(ctx, "dev_kim"))).rejects.toMatchObject({ code: "not_found", message: "No live run for this machine." })
      expect(open).not.toHaveBeenCalled()
    })
  })
})

async function oauthRelayFixture(ctx: VaultContext) {
  const { seedOAuthConnection } = await import("./credentials-test-support.ts")
  const item = await seedOAuthConnection(ctx)
  ctx.sql.exec("UPDATE vars SET item='gmail-test',field='access_token' WHERE project='prj_a' AND env='prod' AND name='TOKEN'")
  return item
}
async function scheduledRefresh(ctx: VaultContext, item: { id: string }) {
  const { oauthArea } = await import("../src/vault/areas/oauth.ts")
  ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now()-1, item.id)
  setUpstreamFetch(async()=>Response.json({access_token:"scheduled-access",expires_in:3600}))
  await oauthArea.alarm!(ctx,`workspace-refresh:${item.id}`)
}
async function humanChange(ctx: VaultContext, change:"rotation"|"rehome") {
  const { prepareCredential,storeCredential,workspaceItemOps }=await import("../src/vault/areas/items-workspace.ts")
  const item=checkedCredential(ctx,"gmail-test")!
  if(change === "rotation"){
    const prepared=await prepareCredential(ctx,{...item,secretFields:{access_token:"human-rotated",refresh_token:"human-refresh"}},item)
    ctx.storage.transactionSync(()=>storeCredential(ctx,prepared,memberPrincipal(ctx),"item.rotate"))
  }else{
    const after={kind:"project",project:"prj_a"} as const
    await workspaceItemOps["items.rehome"].handler(ctx,memberPrincipal(ctx),{slug:item.slug,home:after},memberInvocation(ctx,"owner",{type:"item.rehome",item:item.id,before:item.home,after,dependencyRevision:item.dependencyRevision}))
  }
}

it("an unspent run approval and a live run survive scheduled OAuth refresh without binding value versions",async()=>{
  const f=await relayFixture()
  await inAccess(f.tenant,async ctx=>{
    const item=await oauthRelayFixture(ctx)
    const run=await approvedRelayRun(ctx,async()=>scheduledRefresh(ctx,item),true)
    await scheduledRefresh(ctx,item)
    const {assertRunUse}=await import("../src/vault/areas/projects-workspace.ts")
    const {accessState}=await import("../src/vault/areas/workspace-runtime.ts")
    expect(assertRunUse(ctx,accessState(ctx),run.request.run,{ kind: "device" as const, deviceId: "dev_member" },ctx.now()).snapshot).not.toBeNull()
    expect(ctx.sql.exec("SELECT * FROM approvals").toArray()).toHaveLength(1)
    expect(checkedCredential(ctx,item.slug)?.version).toBe(item.version+2)
    expect(checkedCredential(ctx,item.slug)?.configRev).toBe(item.configRev)
    const saved=ctx.sql.exec<{snapshot:string;credentials:string}>("SELECT snapshot,credentials FROM workspace_run_contexts WHERE run=?",run.request.run).toArray()[0]!
    expect(saved.snapshot).not.toContain('"version"')
    expect(saved.credentials).not.toContain('"version"')
  })
})
for(const change of ["rotation","rehome"] as const){
  it(`a human ${change} voids an unspent OAuth run approval`,async()=>{
    const f=await relayFixture()
    await inAccess(f.tenant,async ctx=>{
      await oauthRelayFixture(ctx)
      let previous=""
      await expect(approvedRelayRun(ctx,async approval=>{previous=approval;await humanChange(ctx,change)},true)).rejects.toMatchObject({code:"approval_required",message:"This protected run needs approval."})
      expect(workspaceApproval(ctx,previous)?.status).toBe("approved")
      expect(ctx.sql.exec("SELECT * FROM runs").toArray()).toEqual([])
      expect(ctx.sql.exec<{uses_left:number}>("SELECT uses_left FROM protected_use_grants WHERE approval=?",previous).toArray()[0]?.uses_left).toBe(1)
    })
  })
  it(`a human ${change} voids a live OAuth run before any opening or send`,async()=>{
    const f=await relayFixture()
    await inAccess(f.tenant,async ctx=>{
      await oauthRelayFixture(ctx)
      const run=await approvedRelayRun(ctx,undefined,true)
      await humanChange(ctx,change)
      const open=vi.spyOn(ctx,"openField");let sends=0
      setUpstreamFetch(async()=>{sends++;return new Response("unexpected")})
      const {assertRunUse}=await import("../src/vault/areas/projects-workspace.ts")
      const {accessState}=await import("../src/vault/areas/workspace-runtime.ts")
      await expect(Promise.resolve().then(()=>assertRunUse(ctx,accessState(ctx),run.request.run,{ kind: "device" as const, deviceId: "dev_member" },ctx.now()))).rejects.toMatchObject(change === "rotation"?{code:"conflict",message:"A run credential changed; start a new run."}:{code:"not_found",message:"No live run for this machine."})
      expect(open).not.toHaveBeenCalled();expect(sends).toBe(0)
    })
  })
}
it("a protected item approval survives a scheduled OAuth refresh",async()=>{
  const f=await relayFixture()
  await inAccess(f.tenant,async ctx=>{
    const item=await oauthRelayFixture(ctx)
    const req={item:item.slug,context:{project:"prj_a",environment:"prod"},method:"GET",url:"https://gmail.googleapis.com/gmail/v1/users/me/labels",headers:[]}
    const approval=await required(ctx,req)
    await decide(ctx,approval,"owner")
    await scheduledRefresh(ctx,item)
    expect((await authoriseWorkspaceRelay(ctx,devicePrincipal(),{...req,approval},await deviceInvocation(ctx))).headers).toContainEqual(["authorization","Bearer scheduled-access"])
    expect(ctx.sql.exec<{uses_left:number}>("SELECT uses_left FROM protected_use_grants WHERE approval=?",approval).toArray()[0]?.uses_left).toBe(0)
  })
})

it("a protected run's ask records the run's shape and a NULL floor (counted as floor), in the project environment's review group", async () => {
  const f = await relayFixture()
  await inAccess(f.tenant, async ctx => {
    const { workspaceRunOps } = await import("../src/vault/areas/runs-workspace.ts")
    const { approvalReviewGroup } = await import("../src/vault/areas/approvals-workspace.ts")
    const { digestOf } = await import("../src/vault/areas/approvals.ts")
    const input = { project: "prj_a", env: "prod", envSource: "flag", remote: null, worktree: "/test/repo", head: null, vars: ["TOKEN"], command: "bun run", argv: ["bun", "run"] }
    let approval = ""
    try { await workspaceRunOps["runs.create"]!.handler(ctx, devicePrincipal(), input, await deviceInvocation(ctx)) } catch (error) { if (!(error instanceof VaultError) || error.code !== "approval_required") throw error; approval = error.extra.approval as string }
    const row = ctx.sql.exec<{ review_group: string; shape: string; floor: string | null; ask: string }>("SELECT review_group,shape,floor,ask FROM approvals WHERE id=?", approval).toArray()[0]!
    expect(row.shape).toBe(digestOf({ run: "prj_a", env: "prod", argv: digestOf(["bun", "run"]) }))
    expect(row.floor).toBeNull()
    expect(row.review_group).toBe(approvalReviewGroup(ctx.tenant, JSON.parse(row.ask)))
    expect(JSON.parse(row.ask).credential).toBeNull()
  })
})
