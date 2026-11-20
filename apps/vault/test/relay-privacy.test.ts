import { describe, expect, it, vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import { visibleCredential } from "../src/vault/areas/items-workspace.ts"
import { items } from "../src/vault/areas/items.ts"
import { credentialsFixture, devicePrincipal, inAccess, seedCredential } from "./credentials-test-support.ts"
import { fixtureSql } from "./fixture-sql.ts"
describe("visibleCredential device entry wall", () => {
  for (const status of ["active", "needs_reauth", "disabled"] as const)
    it(`keeps absent, foreign-private and team-hidden ${status} credentials identical before opening or reconnect`, async () => {
      const f = await credentialsFixture()
      await inAccess(f.tenant, async (ctx) => {
        await seedCredential(ctx, "private-token", { kind: "member", member: "mem_kim" })
        items.setStatus(ctx, "private-token", status, null)
        const open = vi.spyOn(ctx, "openField"), before = canonicalJson(ctx.sql.exec("SELECT * FROM workspace_credential_requests").toArray())
        const error = (slug: string) => { try {
          visibleCredential(ctx, devicePrincipal("dev_service"), slug, { context: null, mode: "relay" })
        }
        catch (e) {
          return (e as VaultError).toJSON()
        } }
        expect(canonicalJson(error("private-token")).replaceAll("private-token", "X")).toBe(canonicalJson(error("no-such-token")).replaceAll("no-such-token", "X"))
        expect(error("private-token")).toEqual({ error: "not_found", message: 'No credential called "private-token".', next: { command: "mehen ls", say: 'There is no credential called "private-token"; list what exists with `mehen ls`, or ask for it with `mehen request`.' } })
        expect(open).not.toHaveBeenCalled()
        expect(canonicalJson(ctx.sql.exec("SELECT * FROM workspace_credential_requests").toArray())).toBe(before)
      })
    })
  it("preserves lease-only use but not describe, protected metadata, and unticked private not_found", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const c = await seedCredential(ctx, "lease-key")
      await seedCredential(ctx, "own-secret", { kind: "member", member: "mem_member" })
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.modes',json('[\"lease\"]')) WHERE id='dev_member'")
      expect(() => visibleCredential(ctx, devicePrincipal(), c.slug)).toThrowError()
      expect(visibleCredential(ctx, devicePrincipal(), c.slug, { context: null, mode: "lease" }).id).toBe(c.id)
      expect(() => visibleCredential(ctx, devicePrincipal(), "own-secret", { context: null, mode: "lease" })).toThrowError()
      fixtureSql(ctx).exec("UPDATE members SET status='removed' WHERE id='mem_member'")
      expect(() => visibleCredential(ctx, devicePrincipal(), c.slug, { context: null, mode: "lease" })).toThrowError('No credential called "lease-key".')
    })
  })
})
for(const hidden of ["foreign-private","team-hidden","removed-owner","needs_reauth"] as const)it(`real item relay keeps ${hidden} byte-identical to absence before any opening, send or reconnect`,async()=>{
  const {authoriseWorkspaceRelay}=await import("../src/vault/areas/relay-workspace.ts")
  const {deviceInvocation}=await import("./credentials-test-support.ts")
  const {setUpstreamFetch}=await import("../src/relay/upstream.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    const slug="candidate",id=hidden === "team-hidden"?"dev_service":"dev_member",p=devicePrincipal(id),i=await deviceInvocation(ctx,id)
    const req={item:slug,method:"GET",url:"https://api.example.com/test",headers:[]}
    const body=async()=>{try{await authoriseWorkspaceRelay(ctx,p,req,i)}catch(e){if(e instanceof VaultError)return canonicalJson(e.toJSON());throw e}throw new Error("Expected refusal")}
    const absent=await body()
    await seedCredential(ctx,slug,hidden === "team-hidden"?{kind:"workspace"}:{kind:"member",member:"mem_kim"})
    if(hidden === "needs_reauth")items.setStatus(ctx,slug,"needs_reauth",null)
    if(hidden === "removed-owner")fixtureSql(ctx).exec("UPDATE members SET status='removed' WHERE id='mem_kim'")
    const open=vi.spyOn(ctx,"openField"),before=canonicalJson(ctx.sql.exec("SELECT * FROM workspace_credential_requests").toArray());let sends=0
    setUpstreamFetch(async()=>{sends++;return new Response("unexpected")})
    try{
      expect(await body()).toBe(absent)
      expect(JSON.parse(absent)).toEqual({error:"not_found",message:'No credential called "candidate".',next:{command:"mehen ls",say:'There is no credential called "candidate"; list what exists with `mehen ls`, or ask for it with `mehen request`.'}})
      expect(open).not.toHaveBeenCalled();expect(sends).toBe(0)
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM workspace_credential_requests").toArray())).toBe(before)
      expect(ctx.sql.exec("SELECT * FROM audit WHERE action LIKE 'relay.%'").toArray()).toEqual([])
    }finally{setUpstreamFetch(null);open.mockRestore()}
  })
})

for(const hidden of ["foreign-private","team-hidden","removed-owner","needs_reauth"] as const)it(`P3-9 future-override safety net: real run plus test-only sightings hides ${hidden} before fence auditing`,async()=>{
  const {projectFixture}=await import("./projects-workspace-fixture.ts")
  const {workspaceRunOps}=await import("../src/vault/areas/runs-workspace.ts")
  const {authoriseWorkspaceRelay}=await import("../src/vault/areas/relay-workspace.ts")
  const {relayServices}=await import("../src/relay/services.ts")
  const {registerCredentialServices}=await import("../src/vault/areas/items-workspace.ts")
  const {deviceInvocation}=await import("./credentials-test-support.ts")
  const f=await projectFixture()
  await inAccess(f.tenant,async ctx=>{
    registerCredentialServices()
    const id=hidden === "team-hidden"?"dev_service":"dev_member",p=devicePrincipal(id),i=await deviceInvocation(ctx,id)
    const run=await workspaceRunOps["runs.create"]!.handler(ctx,p,{project:"prj_a",env:"dev",envSource:"flag",remote:null,worktree:"/test",head:null,vars:["TOKEN"],command:"test",argv:["test"]},i) as import("@mehen/protocol").WorkspaceRunCreated
    const variable=run.vars.find(v=>v.delivery === "placeholder")!
    if(variable.delivery !== "placeholder")throw new Error("Expected real placeholder")
    // Private vars are impossible in production today. Only the sighting map
    // is stubbed; the run and its authorisation are real.
    const lookup=vi.spyOn(relayServices,"placeholdersFor").mockReturnValue([{placeholder:variable.value,item:"future-private",field:"key",hosts:["api.example.com"]}])
    const req={run:run.run,method:"GET",url:"https://api.example.com/test",headers:[["Authorization",`Bearer ${variable.value}`]]}
    const body=async()=>{try{await authoriseWorkspaceRelay(ctx,p,req,i)}catch(e){if(e instanceof VaultError)return canonicalJson(e.toJSON());throw e}throw new Error("Expected refusal")}
    try{
      const absent=await body()
      await seedCredential(ctx,"future-private",hidden === "team-hidden"?{kind:"workspace"}:{kind:"member",member:"mem_kim"})
      if(hidden === "needs_reauth")items.setStatus(ctx,"future-private","needs_reauth",null)
      if(hidden === "removed-owner")fixtureSql(ctx).exec("UPDATE members SET status='removed' WHERE id='mem_kim'")
      ctx.sql.exec("UPDATE environments SET fences='[\"api.example.com\"]' WHERE project='prj_a' AND name='prod'")
      const open=vi.spyOn(ctx,"openField"),send=vi.spyOn(globalThis,"fetch"),before=canonicalJson(ctx.sql.exec("SELECT * FROM workspace_credential_requests").toArray())
      expect(await body()).toBe(absent)
      expect(ctx.sql.exec("SELECT * FROM audit WHERE action LIKE 'relay.%'").toArray()).toEqual([])
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM workspace_credential_requests").toArray())).toBe(before)
      expect(open).not.toHaveBeenCalled();expect(send).not.toHaveBeenCalled();open.mockRestore();send.mockRestore()
    }finally{lookup.mockRestore()}
  })
})
