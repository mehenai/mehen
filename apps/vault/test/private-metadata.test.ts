import { describe, expect, it } from "vitest"
import { canonicalJson, PrivateEventSchema } from "@mehen/protocol"
import { appendAudit, verifyAuditChain, type AuditRow } from "../src/vault/audit.ts"
import { credentialAudit, visibleCredential } from "../src/vault/areas/items-workspace.ts"
import { credentialsFixture, devicePrincipal, inAccess, memberPrincipal, seedCredential } from "./credentials-test-support.ts"
describe("private audit stored-byte golden events", () => {
  const actions = ["item.create", "item.replace", "item.rotate", "item.restore", "item.update", "item.delete", "item.rehome", "intake.complete", "intake.cancel", "oauth.connect", "oauth.reconnect", "oauth.refresh", "relay.allow", "relay.deny", "relay.refuse", "relay.tripwire", "relay.echo", "intake.request", "oauth.connect_request", "oauth.connect_start", "oauth.connect_cancel", "oauth.refresh_attempt", "credential.request_superseded", "project.references.remove"]
  for (const action of actions)
    it(`stores only the minimal ${action} event before hashing, including for the private owner`, async () => {
      const f = await credentialsFixture()
      await inAccess(f.tenant, async (ctx) => {
        const item = await seedCredential(ctx, "private-golden", { kind: "member", member: "mem_member" })
        const before = ctx.sql.exec<{
          n: number
        }>("SELECT count(*) AS n FROM audit").toArray()[0]?.n ?? 0
        const now = ctx.now(), fixed = { ...ctx, now: () => now, audit: (event: Parameters<typeof ctx.audit>[0]) => appendAudit(ctx.sql, now, event) }
        credentialAudit(fixed, devicePrincipal(), item, action, "refused:forbidden", { host: "private.example", method: "POST", path: "/hidden", provider: "upstream", account: "other", headers: ["X-Key", "secret"], body: "secret", fields: ["key"], fingerprint: "hidden", session: "unverified-label", override: "hidden" }, "run_golden")
        const rows = ctx.sql.exec<AuditRow>("SELECT * FROM audit ORDER BY seq").toArray(), last = rows[before] as AuditRow
        const expected = { action, at: now, actor: { kind: "device", device: "dev_member", owner: { kind: "member", member: "mem_member" } }, session: null, item: item.id, slug: item.slug, outcome: "refused:forbidden", run: "run_golden" }
        expect(last.detail).toBe(canonicalJson(expected))
        expect(PrivateEventSchema.parse(JSON.parse(last.detail))).toEqual(expected)
        expect(verifyAuditChain(rows)).toEqual({ ok: true })
        expect(visibleCredential(ctx, memberPrincipal(ctx, "member"), item.slug).id).toBe(item.id)
        expect(() => visibleCredential(ctx, memberPrincipal(ctx), item.slug)).toThrowError()
      })
    })
})
it("stores fill's refusals as private outcomes, and still refuses an outcome naming no vault code", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await seedCredential(ctx, "private-fill", { kind: "member", member: "mem_member" })
    for (const outcome of ["refused:origin_mismatch", "refused:totp_unreadable"]) credentialAudit(ctx, devicePrincipal(), item, "item.fill", outcome)
    const stored = ctx.sql.exec<AuditRow>("SELECT * FROM audit WHERE action='item.fill' ORDER BY seq").toArray()
    expect(stored.map((row) => PrivateEventSchema.parse(JSON.parse(row.detail)).outcome)).toEqual(["refused:origin_mismatch", "refused:totp_unreadable"])
    expect(() => credentialAudit(ctx, devicePrincipal(), item, "item.fill", "refused:page_changed")).toThrowError("Invalid private audit outcome.")
  })
})
it("keeps a deleted private credential's echo minimal and never serialises the internal audit context", async () => {
  const { authoriseWorkspaceRelay, workspaceRelayOps } = await import("../src/vault/areas/relay-workspace.ts")
  const { deviceInvocation } = await import("./credentials-test-support.ts")
  const { setUpstreamFetch } = await import("../src/relay/upstream.ts")
  const { forwardRelay } = await import("../src/relay/forward.ts")
  const f = await credentialsFixture()
  try {
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedCredential(ctx, "private-echo", { kind: "member", member: "mem_member" })
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      const invocation = await deviceInvocation(ctx)
      const material = await authoriseWorkspaceRelay(ctx, devicePrincipal(), { item: item.slug, method: "GET", url: "https://api.example.com/echo", headers: [] }, invocation)
      ctx.sql.exec("DELETE FROM item_secrets WHERE item=?", item.id)
      ctx.sql.exec("DELETE FROM items WHERE id=?", item.id)
      setUpstreamFetch(async () => new Response("test-secret-never-returned"))
      const response = await forwardRelay(material, null, { onEcho: (slugs) => { workspaceRelayOps["relay.echo"]!.handler(ctx, { kind: "system" }, { items: slugs, host: "api.example.com", workspaceAudit: material.workspaceAudit }, { ...invocation, auth: { kind: "system" } }); } })
      const body = await response.text()
      expect(body).not.toContain("test-secret-never-returned")
      expect(body).not.toContain("workspaceAudit")
      expect(body).not.toContain(item.id)
      const rows = ctx.sql.exec<AuditRow>("SELECT * FROM audit ORDER BY seq").toArray()
      const echo = rows.find(row => row.action === "relay.echo")
      expect(echo).toBeTruthy()
      expect(JSON.parse(echo!.detail)).toEqual({ action: "relay.echo", at: echo!.at, actor: { kind: "device", device: "dev_member", owner: { kind: "member", member: "mem_member" } }, session: null, item: item.id, slug: item.slug, outcome: "scrubbed", run: null })
      expect(verifyAuditChain(rows)).toEqual({ ok: true })
    })
  }
  finally {
    setUpstreamFetch(null)
  }
})
it("rolls mixed echo flags and private audit records back together when a later append fails", async () => {
  const { workspaceRelayOps } = await import("../src/vault/areas/relay-workspace.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async ctx => {
    const first = await seedCredential(ctx, "echo-atomic-one", { kind: "member", member: "mem_member" })
    const second = await seedCredential(ctx, "echo-atomic-two", { kind: "member", member: "mem_member" })
    const before = canonicalJson(ctx.sql.exec("SELECT * FROM audit ORDER BY seq").toArray())
    let appends = 0
    const wrapped = { ...ctx, audit(event: Parameters<typeof ctx.audit>[0]) {
      if (event.action === "relay.echo" && ++appends === 2) throw new Error("echo audit failed")
      ctx.audit(event)
    } }
    const owner = { kind: "member", member: "mem_member" } as const
    const workspaceAudit = [first, second].map(item => ({ item: { id: item.id, slug: item.slug, home: item.home }, device: "dev_member", owner, session: null, run:null }))
    expect(() => workspaceRelayOps["relay.echo"]!.handler(wrapped, { kind: "system" }, { items: [first.slug, second.slug], host: "api.example.com", workspaceAudit }, { workspace: { id: ctx.tenant, slug: "work", name: "Work" }, auth: { kind: "system" } })).toThrow("echo audit failed")
    expect(ctx.sql.exec<{ review_reason: string | null }>("SELECT review_reason FROM items ORDER BY slug").toArray()).toEqual([{ review_reason: null }, { review_reason: null }])
    expect(canonicalJson(ctx.sql.exec("SELECT * FROM audit ORDER BY seq").toArray())).toBe(before)
  })
})

it("minimises real private relay allow, binding refusal and policy denial before hashing",async()=>{
  const {authoriseWorkspaceRelay}=await import("../src/vault/areas/relay-workspace.ts")
  const {deviceInvocation}=await import("./credentials-test-support.ts")
  const {vi}=await import("vitest")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    const item=await seedCredential(ctx,"private-real-relay",{kind:"member",member:"mem_member"})
    ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
    const p=devicePrincipal(),i=await deviceInvocation(ctx),req={item:item.slug,method:"GET",url:"https://api.example.com/private-path?hidden=1",headers:[]}
    await authoriseWorkspaceRelay(ctx,p,req,i)
    const open=vi.spyOn(ctx,"openField"),send=vi.spyOn(globalThis,"fetch")
    await expect(authoriseWorkspaceRelay(ctx,p,{...req,url:"https://wrong.example.com/secret-path"},i)).rejects.toMatchObject({code:"binding_refused"})
    ctx.sql.exec("UPDATE items SET policy=? WHERE id=?",JSON.stringify({default:"deny",rules:[]}),item.id)
    await expect(authoriseWorkspaceRelay(ctx,p,req,i)).rejects.toMatchObject({code:"policy_denied"})
    const rows=ctx.sql.exec<AuditRow>("SELECT * FROM audit ORDER BY seq").toArray()
    for(const [action,outcome] of [["relay.allow","allowed"],["relay.refuse","refused:binding_refused"],["relay.deny","refused:policy_denied"]]){
      const row=rows.find(row=>row.action === action)!
      expect(row).toBeTruthy()
      expect(row.detail).toBe(canonicalJson({action,at:row.at,actor:{kind:"device",device:"dev_member",owner:{kind:"member",member:"mem_member"}},session:null,item:item.id,slug:item.slug,outcome,run:null}))
    }
    expect(verifyAuditChain(rows)).toEqual({ok:true})
    expect(open).not.toHaveBeenCalled();expect(send).not.toHaveBeenCalled();open.mockRestore();send.mockRestore()
  })
})

it("an old private echo keeps its run id and never flags a replacement with the same slug",async()=>{
  const {workspaceRelayOps}=await import("../src/vault/areas/relay-workspace.ts")
  const {items}=await import("../src/vault/areas/items.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    const old=await seedCredential(ctx,"reused-private",{kind:"member",member:"mem_member"})
    ctx.sql.exec("DELETE FROM item_secrets WHERE item=?",old.id);ctx.sql.exec("DELETE FROM items WHERE id=?",old.id)
    const replacement=await seedCredential(ctx,old.slug,{kind:"member",member:"mem_member"})
    await workspaceRelayOps["relay.echo"]!.handler(ctx,{kind:"system"},{items:[old.slug],host:"private.example",workspaceAudit:[{item:{id:old.id,slug:old.slug,home:old.home},device:"dev_member",owner:{kind:"member",member:"mem_member"},session:null,run:"run_original"}]},{workspace:{id:ctx.tenant,slug:"work",name:"Work"},auth:{kind:"system"}})
    expect(items.getItem(ctx,replacement.slug)?.review).toBeNull()
    const row=ctx.sql.exec<{detail:string}>("SELECT detail FROM audit WHERE action='relay.echo'").toArray()[0]!
    expect(JSON.parse(row.detail)).toMatchObject({item:old.id,run:"run_original"})
    expect(row.detail).not.toContain("private.example")
  })
})
