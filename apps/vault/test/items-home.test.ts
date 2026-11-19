import { describe, expect, it, vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import { items } from "../src/vault/areas/items.ts"
import { assertCredentialNameFree, checkedCredential, describeCredential, prepareCredential, storeCredential, workspaceItemOps } from "../src/vault/areas/items-workspace.ts"
import { createWorkspaceIntake } from "../src/vault/areas/intake-workspace.ts"
import { createWorkspaceConnect } from "../src/vault/areas/oauth-workspace.ts"
import { nameMiss } from "../src/vault/areas/workspace-runtime.ts"
import { postureRow, seedGithub, setPosture } from "./postures-test-support.ts"
import { credentialInput, credentialsFixture, deviceInvocation, devicePrincipal, inAccess, memberInvocation, memberPrincipal, seedCredential } from "./credentials-test-support.ts"
import { fixtureSql } from "./fixture-sql.ts"
// A machine accepted without private credentials asking in its owner's
// private home, the CLI's default, is told why and what to ask for instead.
const PRIVATE_CREDENTIALS_OFF = {
  error: "forbidden",
  message: "This machine was accepted without private credentials, so it cannot ask for a credential in its owner's private home.",
  next: { say: "Ask again in a project the person can edit, or in the workspace if they are a workspace owner or admin; otherwise ask the person to tick the private credentials box on this machine's page under Machines, then ask again." },
}
describe("credential homes and namespace", () => {
  it("charges the same 20/hour bucket for machines and their owning account before probing any occupied or free name", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "private-hidden", { kind: "member", member: "mem_kim" })
      const p = devicePrincipal()
      for (let n = 0; n < 20; n++)
        expect(() => assertCredentialNameFree(ctx, p, "private-hidden")).toThrowError("name not available")
      const before = ctx.sql.exec("SELECT * FROM items").toArray()
      const error = (slug: string) => { try {
        assertCredentialNameFree(ctx, memberPrincipal(ctx, "member"), slug)
      }
      catch (e) {
        return (e as VaultError).toJSON()
      } }
      expect(error("private-hidden")).toEqual(error("unused-name"))
      expect(error("unused-name")).toEqual({ error: "rate_limited", message: "Too many unavailable names; try again later.", retryAfter: expect.any(Number) })
      expect(ctx.sql.exec("SELECT * FROM items").toArray()).toEqual(before)
      expect(ctx.sql.exec<{
        detail: string
      }>("SELECT detail FROM audit WHERE action='name.miss_limit'").toArray().map(e => JSON.parse(e.detail))).toEqual([{ subject: "device:dev_member", count: 20 }, { subject: "account:acc_member", count: 20 }])
      const events = JSON.stringify(ctx.sql.exec("SELECT detail FROM audit WHERE action='name.miss_limit'").toArray())
      expect(events).not.toContain("private-hidden")
      expect(nameMiss.check(ctx, p, ctx.now() + 3600001)).toEqual({ ok: true })
    })
  })
  it("preserves ordinary below-limit creation and checks machine private ticks, team ceilings and project edit", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const i = memberInvocation(ctx, "member")
      expect(createWorkspaceIntake(ctx, memberPrincipal(ctx, "member"), { provider: "openai", slug: "new-service", home: "private" }, i)).toMatchObject({ intake: expect.stringMatching(/^int_/) })
      const d = devicePrincipal()
      const di = await deviceInvocation(ctx)
      const ti = await deviceInvocation(ctx, "dev_service")
      const requests = [
        { run: () => createWorkspaceIntake(ctx, d, { kind: "api-key", slug: "unticked-secret", home: "private", reason: "test", binding: { hosts: ["api.example.com"] } }, di), expected: PRIVATE_CREDENTIALS_OFF },
        { run: () => createWorkspaceConnect(ctx, d, { provider: "google-gmail", client: "google-client", slug: "unticked-connection", home: "private", reason: "test" }, di), expected: PRIVATE_CREDENTIALS_OFF },
        { run: () => createWorkspaceIntake(ctx, devicePrincipal("dev_service"), { kind: "api-key", slug: "service-global", home: "workspace", reason: "test" }, ti), expected: { error: "forbidden", message: "You are not allowed to do that." } }
      ]
      for (const request of requests) {
        let failure: unknown
        try { request.run() } catch (error) { failure = error instanceof VaultError ? error.toJSON() : error }
        expect(failure).toEqual(request.expected)
      }
      expect(ctx.sql.exec<{
        n: number
      }>("SELECT count(*) AS n FROM workspace_credential_requests").toArray()[0]?.n).toBe(1)
    })
  })
  it("refuses a human item mutation after the final digest await loses authority, with no write/open/send", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedCredential(ctx, "project-key", { kind: "project", project: "prj_a" })
      const p = memberPrincipal(ctx, "kim"), change = { description: "changed" }
      const { stepUpDigest } = await import("../src/vault/areas/items.ts")
      const digest = await stepUpDigest({ change, version: item.version, configRevision: item.configRev })
      const i = memberInvocation(ctx, "kim", { type: "item.update", item: item.id, digest })
      const before = canonicalJson(checkedCredential(ctx, item.slug))
      const open = vi.spyOn(ctx, "openField")
      const pending = workspaceItemOps["items.update"].handler(ctx, p, { slug: item.slug, change }, i)
      fixtureSql(ctx).exec("DELETE FROM project_shares WHERE subject_id='mem_kim'")
      await expect(pending).rejects.toMatchObject({ code: "not_found" })
      expect(canonicalJson(checkedCredential(ctx, item.slug))).toBe(before)
      expect(open).not.toHaveBeenCalled()
    })
  })
  it("rolls storage and exposure back if the audit append fails", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const prepared = await prepareCredential(ctx, credentialInput("atomic-key"), null)
      const broken = { ...ctx, audit() { throw new Error("audit failed"); } }
      expect(() => ctx.storage.transactionSync(() => storeCredential(broken, prepared, memberPrincipal(ctx), "item.create"))).toThrowError("audit failed")
      expect(items.getItem(ctx, "atomic-key")).toBeNull()
      expect(ctx.sql.exec<{
        n: number
      }>("SELECT count(*) AS n FROM exposures WHERE item=?", prepared.id).toArray()[0]?.n).toBe(0)
    })
  })
})
it("enforces one twenty-open-asks cap across credential request kinds and reuses an unchanged own request", async () => {
  const { createCredentialRequest } = await import("../src/vault/areas/intake-workspace.ts")
  const { openAskCount } = await import("../src/vault/areas/workspace-runtime.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const p = devicePrincipal(), i = await deviceInvocation(ctx)
    const first = createWorkspaceIntake(ctx, p, { kind: "api-key", slug: "same-ask", reason: "test", binding: { hosts: ["api.example.com"] }, home: "project", project: "prj_a" }, i)
    expect(createWorkspaceIntake(ctx, p, { kind: "api-key", slug: "same-ask", reason: "test", binding: { hosts: ["api.example.com"] }, home: "project", project: "prj_a" }, i)).toEqual(first)
    for (let n = 1; n < 20; n++)
      createCredentialRequest(ctx, p, { kind: n % 2 ? "connect" : "intake", slug: `request-${n}`, home: { kind: "project", project: "prj_a" }, tags: [], payload: {}, target: null }, i)
    const count = openAskCount(ctx, "dev_member", ctx.now())
    expect(count).toBe(20)
    let failure: unknown
    try {
      createCredentialRequest(ctx, p, { kind: "intake", slug: "overflow-key", home: { kind: "project", project: "prj_a" }, tags: [], payload: {}, target: null }, i)
    }
    catch (e) {
      failure = (e as VaultError).toJSON()
    }
    expect(failure).toEqual({ error: "rate_limited", message: "This machine already has 20 open asks." })
    expect(openAskCount(ctx, "dev_member", ctx.now())).toBe(count)
    expect(ctx.sql.exec("SELECT * FROM workspace_credential_requests WHERE slug='overflow-key'").toArray()).toEqual([])
  })
})
it("prepares only the minimal private purge action for admins, and keeps unauthorised preparation indistinguishable", async () => {
  const { WorkspaceStepUpActionSchema } = await import("@mehen/protocol")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await seedCredential(ctx, "purged-private", { kind: "member", member: "mem_member" })
    const prep = async (role: string, slug: string) => workspaceItemOps["items.action"].handler(ctx, memberPrincipal(ctx, role), { slug, action: "delete" }, memberInvocation(ctx, role))
    const action = WorkspaceStepUpActionSchema.parse(await prep("admin", item.slug))
    expect(action).toEqual({ type: "item.delete", item: item.id })
    const error = async (slug: string) => { try {
      await prep("kim", slug)
    }
    catch (e) {
      return (e as VaultError).toJSON()
    } }
    expect(canonicalJson(await error(item.slug)).replaceAll(item.slug, "X")).toBe(canonicalJson(await error("absent-private")).replaceAll("absent-private", "X"))
    await workspaceItemOps["items.delete"].handler(ctx, memberPrincipal(ctx, "admin"), { slug: item.slug }, memberInvocation(ctx, "admin", action))
    expect(checkedCredential(ctx, item.slug)).toBeNull()
  })
})
it("refuses an action prepared against an older configuration before mutating or opening", async () => {
  const { WorkspaceStepUpActionSchema } = await import("@mehen/protocol")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await seedCredential(ctx, "stale-action"), p = memberPrincipal(ctx), i = memberInvocation(ctx), change = { description: "new" }
    const action = WorkspaceStepUpActionSchema.parse(await workspaceItemOps["items.action"].handler(ctx, p, { slug: item.slug, change, action: "update" }, i))
    fixtureSql(ctx).exec("UPDATE items SET config_rev=config_rev+1 WHERE id=?", item.id)
    const before = canonicalJson(checkedCredential(ctx, item.slug)), open = vi.spyOn(ctx, "openField")
    await expect(workspaceItemOps["items.update"].handler(ctx, p, { slug: item.slug, change }, memberInvocation(ctx, "owner", action))).rejects.toMatchObject({ code: "conflict", message: "The credential changed; review and try again." })
    expect(canonicalJson(checkedCredential(ctx, item.slug))).toBe(before)
    expect(open).not.toHaveBeenCalled()
  })
})
it("refuses inactive machine owners before any name probe or miss-bucket charge", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    await seedCredential(ctx, "occupied-name", { kind: "member", member: "mem_kim" })
    fixtureSql(ctx).exec("UPDATE members SET status='suspended' WHERE id='mem_member'")
    const p = devicePrincipal(), i = await deviceInvocation(ctx), open = vi.spyOn(ctx, "openField")
    const error = (slug: string) => { try {
      createWorkspaceIntake(ctx, p, { kind: "api-key", slug, reason: "test", home: "project", project: "prj_a", binding: { hosts: ["api.example.com"] } }, i)
    }
    catch (e) {
      return (e as VaultError).toJSON()
    } }
    expect(error("occupied-name")).toEqual({ error: "owner_inactive", message: "You are not allowed to do that." })
    expect(error("free-name")).toEqual(error("occupied-name"))
    expect(ctx.sql.exec("SELECT * FROM name_miss_buckets").toArray()).toEqual([])
    expect(ctx.sql.exec("SELECT * FROM workspace_credential_requests").toArray()).toEqual([])
    expect(open).not.toHaveBeenCalled()
  })
})
it("lets guest machines request only their own ticked private rotation, never shared rotation", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    await seedCredential(ctx, "guest-private", { kind: "member", member: "mem_guest" })
    await seedCredential(ctx, "guest-shared", { kind: "project", project: "prj_a" })
    const p = devicePrincipal("dev_guest"), i = await deviceInvocation(ctx, "dev_guest")
    const req = { kind: "api-key", slug: "guest-private", reason: "rotate", home: "private" }
    // Refused for the machine's scope before the name is looked up, so the
    // answer does not say whether guest-private exists.
    expect(() => createWorkspaceIntake(ctx, p, req, i)).toThrowError(PRIVATE_CREDENTIALS_OFF.message)
    ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_guest'")
    expect(createWorkspaceIntake(ctx, p, req, i)).toMatchObject({ intake: expect.stringMatching(/^int_/) })
    let failure: unknown
    try {
      createWorkspaceIntake(ctx, p, { kind: "api-key", slug: "guest-shared", reason: "rotate", home: "project", project: "prj_a" }, i)
    }
    catch (e) {
      failure = (e as VaultError).toJSON()
    }
    expect(failure).toEqual({ error: "forbidden", message: "You are not allowed to do that." })
    expect(ctx.sql.exec<{
      n: number
    }>("SELECT count(*) AS n FROM workspace_credential_requests").toArray()[0]?.n).toBe(1)
  })
})
for(const kind of ["intake","connect"] as const)it(`the real ${kind} creation path records rolled-back name misses and shares its machine/account bucket`,async()=>{
  const {createWorkspaceConnect}=await import("../src/vault/areas/oauth-workspace.ts")
  const {seedOAuthConnection}=await import("./credentials-test-support.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    if(kind === "connect")await seedOAuthConnection(ctx)
    await seedCredential(ctx,"unavailable",{kind:"member",member:"mem_kim"})
    const p=devicePrincipal(),i=await deviceInvocation(ctx)
    const request=(slug:string,human=false)=>kind === "intake"?createWorkspaceIntake(ctx,human?memberPrincipal(ctx,"member"):p,{slug,provider:"openai",home:"project",project:"prj_a",...(!human?{kind:"api-key",reason:"name probe"}:{})},human?memberInvocation(ctx,"member"):i):createWorkspaceConnect(ctx,human?memberPrincipal(ctx,"member"):p,{slug,provider:"google-gmail",client:"google-client",home:"project",project:"prj_a",...(!human?{reason:"name probe"}:{})},human?memberInvocation(ctx,"member"):i)
    const refusal=(slug:string,human=false)=>{try{request(slug,human)}catch(e){if(e instanceof VaultError)return e.toJSON();throw e}throw new Error("Expected refusal")}
    const open=vi.spyOn(ctx,"openField"),send=vi.spyOn(globalThis,"fetch")
    for(let n=0;n<20;n++)expect(refusal("unavailable")).toEqual({error:"conflict",message:"name not available"})
    expect(ctx.sql.exec<{subject:string;count:number}>("SELECT subject,count FROM name_miss_buckets ORDER BY subject").toArray()).toEqual([{subject:"account:acc_member",count:20},{subject:"device:dev_member",count:20}])
    const before=JSON.stringify(ctx.sql.exec("SELECT * FROM items ORDER BY id").toArray())
    const occupied=refusal("unavailable")
    expect(occupied).toEqual({error:"rate_limited",message:"Too many unavailable names; try again later.",retryAfter:expect.any(Number)})
    expect(refusal("free-name")).toEqual(occupied)
    expect(refusal("free-human-name",true)).toEqual(occupied)
    expect(JSON.stringify(ctx.sql.exec("SELECT * FROM items ORDER BY id").toArray())).toBe(before)
    expect(ctx.sql.exec("SELECT * FROM workspace_credential_requests WHERE status='open'").toArray()).toEqual([])
    expect(JSON.stringify(ctx.sql.exec("SELECT detail FROM audit WHERE action='name.miss_limit'").toArray())).not.toContain("unavailable")
    expect(open).not.toHaveBeenCalled();expect(send).not.toHaveBeenCalled();open.mockRestore();send.mockRestore()
  })
})

for(const kind of ["intake","connect"] as const)it(`a team machine cannot probe occupied versus free workspace ${kind} names`,async()=>{
  const {createWorkspaceConnect}=await import("../src/vault/areas/oauth-workspace.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    await seedCredential(ctx,"occupied-workspace")
    const p=devicePrincipal("dev_service"),i=await deviceInvocation(ctx,"dev_service"),open=vi.spyOn(ctx,"openField"),send=vi.spyOn(globalThis,"fetch")
    const before=JSON.stringify(ctx.sql.exec("SELECT * FROM workspace_credential_requests").toArray())
    for(const slug of ["occupied-workspace","free-workspace"]){
      let failure:unknown
      try{if(kind === "intake")createWorkspaceIntake(ctx,p,{kind:"api-key",provider:"openai",slug,home:"workspace",reason:"test"},i)
      else createWorkspaceConnect(ctx,p,{provider:"google-gmail",slug,home:"workspace",reason:"test"},i)}catch(e){failure=e instanceof VaultError?e.toJSON():e}
      expect(failure).toEqual({error:"forbidden",message:"You are not allowed to do that."})
    }
    expect(JSON.stringify(ctx.sql.exec("SELECT * FROM workspace_credential_requests").toArray())).toBe(before)
    expect(ctx.sql.exec("SELECT * FROM name_miss_buckets").toArray()).toEqual([])
    expect(open).not.toHaveBeenCalled();expect(send).not.toHaveBeenCalled();send.mockRestore();open.mockRestore()
  })
})

it("direct deletion keeps hidden and absent names byte-identical after visibility changes",async()=>{
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    const p=memberPrincipal(ctx,"member"),i=memberInvocation(ctx,"member"),slug="delete-hidden"
    const failure=()=>{try{workspaceItemOps["items.delete"].handler(ctx,p,{slug},i)}catch(e){if(e instanceof VaultError)return e.toJSON();throw e}throw new Error("Expected refusal")}
    const absent=failure(),item=await seedCredential(ctx,slug,{kind:"member",member:"mem_kim"}),open=vi.spyOn(ctx,"openField"),send=vi.spyOn(globalThis,"fetch")
    expect(failure()).toEqual(absent)
    expect(checkedCredential(ctx,slug)?.id).toBe(item.id)
    expect(open).not.toHaveBeenCalled();expect(send).not.toHaveBeenCalled();open.mockRestore();send.mockRestore()
  })
})

it("real chained connection creation charges hidden client-name misses before client probing beyond the cap",async()=>{
  const {createWorkspaceConnect}=await import("../src/vault/areas/oauth-workspace.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    await seedCredential(ctx,"occupied-client",{kind:"member",member:"mem_kim"})
    const p=devicePrincipal(),i=await deviceInvocation(ctx),open=vi.spyOn(ctx,"openField"),send=vi.spyOn(globalThis,"fetch")
    const request=(client:string)=>createWorkspaceConnect(ctx,p,{provider:"google-gmail",client,requestClient:true,slug:"chained-parent",home:"project",project:"prj_a",reason:"client needed"},i)
    const refusal=(client:string)=>{try{request(client)}catch(error){if(error instanceof VaultError)return error.toJSON();throw error}throw new Error("Expected refusal")}
    for(let n=0;n<20;n++)expect(refusal("occupied-client")).toEqual({error:"conflict",message:"name not available"})
    expect(ctx.sql.exec<{subject:string;count:number}>("SELECT subject,count FROM name_miss_buckets ORDER BY subject").toArray()).toEqual([{subject:"account:acc_member",count:20},{subject:"device:dev_member",count:20}])
    const occupied=refusal("occupied-client")
    expect(occupied).toEqual({error:"rate_limited",message:"Too many unavailable names; try again later.",retryAfter:expect.any(Number)})
    expect(refusal("free-client")).toEqual(occupied)
    expect(ctx.sql.exec("SELECT * FROM workspace_credential_requests").toArray()).toEqual([])
    expect(JSON.stringify(ctx.sql.exec("SELECT detail FROM audit WHERE action='name.miss_limit'").toArray())).not.toContain("occupied-client")
    expect(open).not.toHaveBeenCalled();expect(send).not.toHaveBeenCalled();open.mockRestore();send.mockRestore()
  })
})
it("refuses a fill ceiling while BROWSER_FILL is off on create (the path intake, adoption and connections take), on planning an update and on the update itself, and allows it where it is on", async () => {
  const { stepUpDigest } = await import("../src/vault/areas/items.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (on) => {
    const ctx = Object.assign(Object.create(on) as typeof on, { env: { ...on.env, BROWSER_FILL: "off" } })
    const refused = { code: "mode_refused", message: "Typing into web pages is not available yet." }
    await expect(prepareCredential(ctx, { ...credentialInput("fill-key"), ceiling: "fill" }, null)).rejects.toMatchObject(refused)
    const item = await seedCredential(ctx, "kept-key")
    const p = memberPrincipal(ctx), change = { ceiling: "fill" }
    await expect(workspaceItemOps["items.action"].handler(ctx, p, { slug: item.slug, action: "update", change }, memberInvocation(ctx))).rejects.toMatchObject(refused)
    const signed = memberInvocation(ctx, "owner", { type: "item.update", item: item.id, digest: await stepUpDigest({ change, version: item.version, configRevision: item.configRev }) })
    await expect(workspaceItemOps["items.update"].handler(ctx, p, { slug: item.slug, change }, signed)).rejects.toMatchObject(refused)
    expect(checkedCredential(ctx, item.slug)?.ceiling).toBe("lease")
    await expect(workspaceItemOps["items.update"].handler(on, p, { slug: item.slug, change }, signed)).resolves.toBeDefined()
    expect(checkedCredential(on, item.slug)?.ceiling).toBe("fill")
    await expect(prepareCredential(on, { ...credentialInput("fill-key"), ceiling: "fill" }, null)).resolves.toBeDefined()
  })
})
it("refuses a fill ceiling for a kind that is never typed into a page, on create, on planning an update and on the update itself", async () => {
  const { stepUpDigest } = await import("../src/vault/areas/items.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const refused = { code: "mode_refused", message: "This kind of credential cannot be typed into web pages." }
    const database = { ...credentialInput("warehouse"), kind: "database-url" as const, injection: null, binding: { hosts: ["db.example.com"] }, secretFields: { url: "postgres://synthetic@db.example.com/app" } }
    await expect(prepareCredential(ctx, { ...database, ceiling: "fill" }, null)).rejects.toMatchObject(refused)
    const prepared = await prepareCredential(ctx, database, null)
    const item = ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
    const p = memberPrincipal(ctx), change = { ceiling: "fill" }
    await expect(workspaceItemOps["items.action"].handler(ctx, p, { slug: item.slug, action: "update", change }, memberInvocation(ctx))).rejects.toMatchObject(refused)
    const signed = memberInvocation(ctx, "owner", { type: "item.update", item: item.id, digest: await stepUpDigest({ change, version: item.version, configRevision: item.configRev }) })
    await expect(workspaceItemOps["items.update"].handler(ctx, p, { slug: item.slug, change }, signed)).rejects.toMatchObject(refused)
    expect(checkedCredential(ctx, item.slug)?.ceiling).toBe("lease")
  })
})
it("sets and clears the pages a credential may be typed into under the item.update passkey, bumping its configuration revision", async () => {
  const { stepUpDigest } = await import("../src/vault/areas/items.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const item = await seedCredential(ctx, "github-key")
    const p = memberPrincipal(ctx)
    const browser = { signinOrigins: ["https://github.com"], typeInto: ["https://dash.cloudflare.com"] }
    const signedFor = async (change: object, live: { version: number; configRev: number }) => memberInvocation(ctx, "owner", { type: "item.update", item: item.id, digest: await stepUpDigest({ change, version: live.version, configRevision: live.configRev }) })
    const planned = await workspaceItemOps["items.action"].handler(ctx, p, { slug: item.slug, action: "update", change: { browser } }, memberInvocation(ctx))
    expect(planned).toEqual({ type: "item.update", item: item.id, digest: await stepUpDigest({ change: { browser }, version: item.version, configRevision: item.configRev }) })
    // A passkey over other pages, or over no pages, does not cover these.
    await expect(workspaceItemOps["items.update"].handler(ctx, p, { slug: item.slug, change: { browser } }, await signedFor({ browser: { ...browser, typeInto: [] } }, item))).rejects.toMatchObject({ code: "conflict" })
    await expect(workspaceItemOps["items.update"].handler(ctx, p, { slug: item.slug, change: { browser } }, memberInvocation(ctx))).rejects.toMatchObject({ code: "forbidden" })
    for (const bad of [{ signinOrigins: ["https://github.com/login"], typeInto: [] }, { signinOrigins: ["http://github.com"], typeInto: [] }, { signinOrigins: [], typeInto: ["https://*.example.com"] }, { signinOrigins: [] }])
      await expect(workspaceItemOps["items.update"].handler(ctx, p, { slug: item.slug, change: { browser: bad } }, await signedFor({ browser: bad }, item))).rejects.toMatchObject({ code: "bad_request" })
    expect(checkedCredential(ctx, item.slug)).toMatchObject({ browser: null, configRev: item.configRev })
    await workspaceItemOps["items.update"].handler(ctx, p, { slug: item.slug, change: { browser } }, await signedFor({ browser }, item))
    const set = checkedCredential(ctx, item.slug)!
    expect(set).toMatchObject({ browser, configRev: item.configRev + 1, version: item.version, binding: item.binding, ceiling: item.ceiling })
    const audited = ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='item.update' ORDER BY seq DESC LIMIT 1").toArray()[0]!
    expect(JSON.parse(audited.detail)).toMatchObject({ changed: ["browser"], item: item.id })
    // A rotation keeps the pages.
    const rotated = await prepareCredential(ctx, credentialInput("github-key"), set)
    ctx.storage.transactionSync(() => storeCredential(ctx, rotated, p, "item.rotate"))
    expect(checkedCredential(ctx, item.slug)?.browser).toEqual(browser)
    const live = checkedCredential(ctx, item.slug)!
    await workspaceItemOps["items.update"].handler(ctx, p, { slug: item.slug, change: { browser: null } }, await signedFor({ browser: null }, live))
    expect(checkedCredential(ctx, item.slug)).toMatchObject({ browser: null, configRev: live.configRev + 1 })
  })
})
it("refuses a change to the pages a credential may be typed into while BROWSER_FILL is off, on planning the update and on the update itself", async () => {
  const { stepUpDigest } = await import("../src/vault/areas/items.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (on) => {
    const ctx = Object.assign(Object.create(on) as typeof on, { env: { ...on.env, BROWSER_FILL: "off" } })
    const refused = { code: "mode_refused", message: "Typing into web pages is not available yet." }
    const item = await seedCredential(ctx, "github-key")
    const p = memberPrincipal(ctx), change = { browser: { signinOrigins: ["https://github.com"], typeInto: [] } }
    await expect(workspaceItemOps["items.action"].handler(ctx, p, { slug: item.slug, action: "update", change }, memberInvocation(ctx))).rejects.toMatchObject(refused)
    const signed = memberInvocation(ctx, "owner", { type: "item.update", item: item.id, digest: await stepUpDigest({ change, version: item.version, configRevision: item.configRev }) })
    await expect(workspaceItemOps["items.update"].handler(ctx, p, { slug: item.slug, change }, signed)).rejects.toMatchObject(refused)
    expect(checkedCredential(ctx, item.slug)).toMatchObject({ browser: null, configRev: item.configRev })
    await expect(workspaceItemOps["items.update"].handler(on, p, { slug: item.slug, change }, signed)).resolves.toBeDefined()
    expect(checkedCredential(on, item.slug)?.browser).toEqual(change.browser)
  })
})
it("gives a lease-only credential real hosts through a passkey binding change, and never mixes the reserved host in", async () => {
  const { LEASE_ONLY_HOST, leaseOnlyBinding } = await import("@mehen/protocol")
  const { stepUpDigest } = await import("../src/vault/areas/items.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    for (const hosts of [[LEASE_ONLY_HOST, "api.example.com"], ["*.mehen.invalid"]]) await expect(prepareCredential(ctx, { ...credentialInput("mixed-reserved"), binding: { hosts } }, null)).rejects.toMatchObject({ code: "bad_request" })
    const prepared = await prepareCredential(ctx, { ...credentialInput("lease-only-key"), binding: leaseOnlyBinding() }, null)
    const item = ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
    expect(item.binding).toEqual({ hosts: [LEASE_ONLY_HOST] })
    const p = memberPrincipal(ctx), signed = async (change: object) => memberInvocation(ctx, "owner", { type: "item.update", item: item.id, digest: await stepUpDigest({ change, version: item.version, configRevision: item.configRev }) })
    for (const hosts of [[LEASE_ONLY_HOST, "api.example.com"], ["*.mehen.invalid"]]) {
      const change = { binding: { hosts } }
      await expect(workspaceItemOps["items.update"].handler(ctx, p, { slug: item.slug, change }, await signed(change))).rejects.toMatchObject({ code: "bad_request", message: expect.stringContaining("binding.hosts") })
    }
    const change = { binding: { hosts: ["api.example.com"] } }
    await expect(workspaceItemOps["items.update"].handler(ctx, p, { slug: item.slug, change }, memberInvocation(ctx))).rejects.toMatchObject({ code: "forbidden" })
    expect(checkedCredential(ctx, item.slug)?.binding).toEqual({ hosts: [LEASE_ONLY_HOST] })
    await workspaceItemOps["items.update"].handler(ctx, p, { slug: item.slug, change }, await signed(change))
    expect(checkedCredential(ctx, item.slug)?.binding).toEqual({ hosts: ["api.example.com"] })
  })
})

// A rehome changes who may set how careful a credential is, and whose
// machines trust reaches, so it starts again at ask (postures-workspace.ts).
describe("a credential's posture across changes", () => {
  it("survives an edit, and goes back to ask on a rehome", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedGithub(ctx)
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: null })
      const update = { slug: "github-work", change: { description: "Issues for the app" } }
      const updateAction = await workspaceItemOps["items.action"].handler(ctx, memberPrincipal(ctx), { ...update, action: "update" }, memberInvocation(ctx))
      await workspaceItemOps["items.update"].handler(ctx, memberPrincipal(ctx), update, memberInvocation(ctx, "owner", updateAction as never))
      expect(postureRow(ctx)).toMatchObject({ level: "routine", rev: 1 })
      const live = checkedCredential(ctx, "github-work")!
      const action = { type: "item.rehome" as const, item: live.id, before: live.home, after: { kind: "project" as const, project: "prj_a" }, dependencyRevision: live.dependencyRevision }
      workspaceItemOps["items.rehome"].handler(ctx, memberPrincipal(ctx), { slug: "github-work", home: action.after }, memberInvocation(ctx, "owner", action))
      expect(postureRow(ctx)).toMatchObject({ level: "ask", machines: null, catalogue: null, rev: 2 })
      expect(ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='posture.reset'").toArray().map((row) => JSON.parse(row.detail))).toEqual([{ reason: "rehome", before: "routine", item: item.id, outcome: "rehome", run: null }])
    })
  })

  it("leaves nothing behind when the credential is deleted", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedGithub(ctx)
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: null })
      ctx.sql.exec("INSERT INTO posture_ask_counts(item_id,day,asked) VALUES (?,1,1)", item.id)
      ctx.sql.exec("INSERT INTO posture_nudge_quiet(member,item_id,until) VALUES ('mem_owner',?,?)", item.id, ctx.now() + 60_000)
      workspaceItemOps["items.delete"].handler(ctx, memberPrincipal(ctx), { slug: "github-work" }, memberInvocation(ctx, "owner", { type: "item.delete", item: item.id }))
      for (const table of ["item_postures", "posture_ask_counts", "posture_nudge_quiet"]) expect(ctx.sql.exec(`SELECT * FROM ${table}`).toArray()).toEqual([])
    })
  })
})
