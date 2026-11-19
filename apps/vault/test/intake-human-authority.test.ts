import { afterEach, describe, expect, it, vi } from "vitest"
import { stepUpDigest } from "../src/vault/areas/items.ts"
import { checkedCredential } from "../src/vault/areas/items-workspace.ts"
import { createWorkspaceIntake, submitWorkspaceIntake } from "../src/vault/areas/intake-workspace.ts"
import { sealToVault } from "./l2-helpers.ts"
import { credentialsFixture, inAccess, memberInvocation, memberPrincipal } from "./credentials-test-support.ts"
describe("human intake final authority", () => {
  for (const race of ["removed", "cancelled"] as const)
    it(`refuses ${race} during sealing without storing a credential or completing the request`, async () => {
      const f = await credentialsFixture()
      await inAccess(f.tenant, async (ctx) => {
        const p = memberPrincipal(ctx, "member"), i = memberInvocation(ctx, "member")
        const created = createWorkspaceIntake(ctx, p, { provider: "openai", slug: "human-key", home: "private" }, i)
        const req = { slug: "human-key", home: { kind: "member" as const, member: "mem_member" }, binding: { hosts: ["api.openai.com"] }, publicFields: {}, tags: [], sealed: { key: await sealToVault("test-value", `intake/${created.intake}/key`) } }
        const digest = await stepUpDigest(req), invocation = memberInvocation(ctx, "member", { type: "intake.submit", intake: created.intake, digest })
        const wrapped = {
          ...ctx, async sealField(ref: Parameters<typeof ctx.sealField>[0], plain: Parameters<typeof ctx.sealField>[1]) {
            const sealed = await ctx.sealField(ref, plain)
            if (race === "removed")
              ctx.sql.exec("UPDATE members SET status='removed' WHERE id='mem_member'")
            else
              ctx.sql.exec("UPDATE workspace_credential_requests SET status='cancelled' WHERE id=?", created.intake)
            return sealed
          }
        }
        await expect(submitWorkspaceIntake(wrapped, p, { intake: created.intake, ...req }, invocation)).rejects.toMatchObject({ code: race === "removed" ? "not_found" : "conflict" })
        expect(checkedCredential(ctx, "human-key")).toBeNull()
        expect(ctx.sql.exec<{
          n: number
        }>("SELECT count(*) AS n FROM exposures").toArray()[0]?.n).toBe(0)
        expect(ctx.sql.exec<{
          status: string
        }>("SELECT status FROM workspace_credential_requests WHERE id=?", created.intake).toArray()[0]?.status).toBe(race === "removed" ? "open" : "cancelled")
      })
    })
  it("refuses a wrong-kind or missing passkey before opening any submitted value", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const p = memberPrincipal(ctx, "member"), i = memberInvocation(ctx, "member")
      const c = createWorkspaceIntake(ctx, p, { provider: "openai", slug: "refused-key", home: "private" }, i)
      const req = { intake: c.intake, slug: "refused-key", home: { kind: "member", member: "mem_member" }, binding: { hosts: ["api.openai.com"] }, publicFields: {}, tags: [], sealed: {key:await sealToVault("must-not-open",`intake/${c.intake}/key`)} }
      const protocol = await import("@mehen/protocol"), submitted = vi.spyOn(protocol, "openText")
      const open = vi.spyOn(ctx, "openField"), seal = vi.spyOn(ctx, "sealField")
      for (const auth of [i, memberInvocation(ctx, "member", { type: "item.delete", item: "itm_wrong" })])
        await expect(submitWorkspaceIntake(ctx, p, req, auth)).rejects.toMatchObject({ code: "forbidden", message: "This needs a passkey confirmation of the exact action." })
      expect(open).not.toHaveBeenCalled()
      expect(seal).not.toHaveBeenCalled()
      expect(submitted).not.toHaveBeenCalled()
      submitted.mockRestore()
      expect(checkedCredential(ctx, "refused-key")).toBeNull()
    })
  })
})
it("keeps pending intake metadata readable during restriction and pending security, without permitting a fill", async () => {
  const { workspaceIntakeOps } = await import("../src/vault/areas/intake-workspace.ts")
  const { installSecurity } = await import("../src/vault/areas/workspace-runtime.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const p = memberPrincipal(ctx, "member"), i = memberInvocation(ctx, "member"), created = createWorkspaceIntake(ctx, p, { provider: "openai", slug: "safe-pending", home: "private" }, i)
    installSecurity(ctx, "acc_member", 0, { transitionId: "ast_pending", reservedEpoch: 1, revokedSessionIds: [], removedFactorIds: [], restriction: { until: ctx.now() + 3600000, reason: "recovery", notice: "notice_test" } })
    await expect(workspaceIntakeOps["intake.view"].handler(ctx, p, { intake: created.intake }, i)).resolves.toMatchObject({ intake: created.intake, status: "open", home: { kind: "member", member: "mem_member" } })
    const open = vi.spyOn(ctx, "openField")
    await expect(submitWorkspaceIntake(ctx, p, { intake: created.intake, slug: "safe-pending", home: { kind: "member", member: "mem_member" }, binding: { hosts: ["api.openai.com"] }, publicFields: {}, tags: [], sealed: {} }, i)).rejects.toMatchObject({ code: "account_pending" })
    expect(open).not.toHaveBeenCalled()
    expect(checkedCredential(ctx, "safe-pending")).toBeNull()
  })
})
it("lets project users read prospective metadata but not fill, and hides it from non-members", async () => {
  const { workspaceIntakeOps } = await import("../src/vault/areas/intake-workspace.ts")
  const { VaultError } = await import("../src/http.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const created = createWorkspaceIntake(ctx, memberPrincipal(ctx, "kim"), { provider: "openai", slug: "read-only-project", home: "project", project: "prj_a" }, memberInvocation(ctx, "kim"))
    ctx.sql.exec("UPDATE project_shares SET value=json_set(value,'$.level','use') WHERE id='shr_direct'")
    const p = memberPrincipal(ctx, "member"), i = memberInvocation(ctx, "member")
    await expect(workspaceIntakeOps["intake.view"].handler(ctx, p, { intake: created.intake }, i)).resolves.toMatchObject({ intake: created.intake, slug: "read-only-project" })
    await expect(submitWorkspaceIntake(ctx, p, { intake: created.intake, slug: "read-only-project", home: { kind: "project", project: "prj_a" }, binding: { hosts: ["api.openai.com"] }, publicFields: {}, tags: [], sealed: {} }, i)).rejects.toMatchObject({ code: "forbidden", message: "You are not allowed to do that." })
    const outsider = { kind: "member" as const, memberId: "mem_absent", account: "acc_absent", session: "ses_absent", securityEpoch: 0, sessionCheck: null }
    const outside = { ...i, auth: { ...i.auth, kind: "account" as const, account: "acc_absent", session: "ses_absent", securityEpoch: 0, sessionCheck: null, restrictedUntil: null } }
    const error = async (intake: string) => { try {
      await workspaceIntakeOps["intake.view"].handler(ctx, outsider, { intake }, outside)
    }
    catch (e) {
      return (e as InstanceType<typeof VaultError>).toJSON()
    } }
    expect(await error(created.intake)).toEqual(await error("int_absent12345"))
  })
})
it("intersects prospective metadata with the machine's stored tags", async () => {
  const { workspaceIntakeOps } = await import("../src/vault/areas/intake-workspace.ts")
  const { devicePrincipal, deviceInvocation } = await import("./credentials-test-support.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.tags',json('[\"work\"]')) WHERE id='dev_member'")
    const p = devicePrincipal(), i = await deviceInvocation(ctx), request = { kind: "api-key", reason: "test", home: "project", project: "prj_a", binding: { hosts: ["api.example.com"] } }
    const matching = createWorkspaceIntake(ctx, p, { ...request, slug: "matching-tags", tags: ["work"] }, i)
    const hidden = createWorkspaceIntake(ctx, p, { ...request, slug: "hidden-tags", tags: ["personal"] }, i)
    expect(await workspaceIntakeOps["intake.status"].handler(ctx, p, { intake: matching.intake }, i)).toMatchObject({ status: "open" })
    await expect(workspaceIntakeOps["intake.status"].handler(ctx, p, { intake: hidden.intake }, i)).rejects.toThrowError("No such credential request.")
  })
})
it("rotates a generic visible credential without changing its provider, binding, policy or home",async()=>{
 const {workspaceIntakeOps}=await import("../src/vault/areas/intake-workspace.ts")
 const {seedCredential}=await import("./credentials-test-support.ts")
 const f=await credentialsFixture();await inAccess(f.tenant,async ctx=>{
  const item=await seedCredential(ctx,"generic-rotation",{kind:"member",member:"mem_member"}),p=memberPrincipal(ctx,"member"),i=memberInvocation(ctx,"member")
  const created=createWorkspaceIntake(ctx,p,{slug:item.slug,home:"private"},i)
  const view=await workspaceIntakeOps["intake.view"].handler(ctx,p,{intake:created.intake},i)
  expect(view).toMatchObject({rotates:true,provider:null,binding:{value:item.binding},home:item.home})
  expect(()=>createWorkspaceIntake(ctx,p,{slug:item.slug,provider:"openai",home:"private"},i)).toThrowError("Rotation keeps the credential provider.")
  const submission={slug:item.slug,home:item.home,binding:item.binding,publicFields:{},tags:item.tags,sealed:{key:await sealToVault("replacement-generic-value",`intake/${created.intake}/key`)}}
  const digest=await stepUpDigest(submission)
  await submitWorkspaceIntake(ctx,p,{intake:created.intake,...submission},memberInvocation(ctx,"member",{type:"intake.submit",intake:created.intake,digest}))
  expect(checkedCredential(ctx,item.slug)).toMatchObject({provider:null,binding:item.binding,policy:item.policy,home:item.home,version:2})
 })
})
it("keeps provider-less rotations of invisible and absent slugs uniform and never creates a new generic item",async()=>{
 const {seedCredential}=await import("./credentials-test-support.ts"),{VaultError}=await import("../src/http.ts")
 const f=await credentialsFixture();await inAccess(f.tenant,async ctx=>{
  await seedCredential(ctx,"invisible-generic",{kind:"member",member:"mem_kim"})
  const p=memberPrincipal(ctx,"member"),i=memberInvocation(ctx,"member")
  const error=(slug:string)=>{try{createWorkspaceIntake(ctx,p,{slug,home:"private"},i)}catch(e){return (e as InstanceType<typeof VaultError>).toJSON()}}
  expect(JSON.stringify(error("invisible-generic")).replaceAll("invisible-generic","X")).toBe(JSON.stringify(error("absent-generic")).replaceAll("absent-generic","X"))
  expect(ctx.sql.exec("SELECT * FROM workspace_credential_requests").toArray()).toEqual([])
  expect(checkedCredential(ctx,"absent-generic")).toBeNull()
 })
})
it("never widens an old private request's history when its credential is rehomed",async()=>{
 const {workspaceIntakeOps}=await import("../src/vault/areas/intake-workspace.ts")
 const {workspaceItemOps}=await import("../src/vault/areas/items-workspace.ts")
 const {seedCredential}=await import("./credentials-test-support.ts")
 const f=await credentialsFixture();await inAccess(f.tenant,async ctx=>{
  const item=await seedCredential(ctx,"private-history",{kind:"member",member:"mem_member"}),p=memberPrincipal(ctx,"member"),i=memberInvocation(ctx,"member")
  const created=createWorkspaceIntake(ctx,p,{slug:item.slug,home:"private"},i)
  const action={type:"item.rehome" as const,item:item.id,before:item.home,after:{kind:"project" as const,project:"prj_a"},dependencyRevision:item.dependencyRevision}
  workspaceItemOps["items.rehome"].handler(ctx,p,{slug:item.slug,home:action.after},memberInvocation(ctx,"member",action))
  await expect(workspaceIntakeOps["intake.view"].handler(ctx,memberPrincipal(ctx,"kim"),{intake:created.intake},memberInvocation(ctx,"kim"))).rejects.toMatchObject({code:"not_found",message:"No such credential request."})
  await expect(workspaceIntakeOps["intake.view"].handler(ctx,p,{intake:created.intake},i)).resolves.toMatchObject({intake:created.intake,status:"cancelled"})
 })
})

for (const kind of ["intake","connect"] as const) it(`a guest with project edit cannot list, view or cancel another machine's ${kind} ask`,async()=>{
  const {workspaceIntakeOps,cancelCredentialRequest}=await import("../src/vault/areas/intake-workspace.ts")
  const {createWorkspaceConnect,workspaceOAuthOps}=await import("../src/vault/areas/oauth-workspace.ts")
  const {workspacePendingOps}=await import("../src/vault/areas/pending-workspace.ts")
  const {devicePrincipal,deviceInvocation,seedOAuthConnection}=await import("./credentials-test-support.ts")
  const {VaultError}=await import("../src/http.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    if(kind === "connect")await seedOAuthConnection(ctx,"project",{kind:"project",project:"prj_a"})
    const machine=devicePrincipal(),mi=await deviceInvocation(ctx)
    const id=kind === "intake"?createWorkspaceIntake(ctx,machine,{kind:"api-key",provider:"openai",slug:"other-intake",home:"project",project:"prj_a",reason:"Private machine reason"},mi).intake:createWorkspaceConnect(ctx,machine,{provider:"google-gmail",client:"google-client",slug:"other-connect",home:"project",project:"prj_a",reason:"Private machine reason"},mi).connect
    const guest=memberPrincipal(ctx,"guest"),gi=memberInvocation(ctx,"guest")
    const own=kind === "intake"?createWorkspaceIntake(ctx,guest,{provider:"openai",slug:"guest-own-human",home:"project",project:"prj_a"},gi).intake:createWorkspaceConnect(ctx,guest,{provider:"google-gmail",client:"google-client",slug:"guest-own-human",home:"project",project:"prj_a"},gi).connect
    const gd=await deviceInvocation(ctx,"dev_guest")
    const ownMachine=kind === "intake"?createWorkspaceIntake(ctx,devicePrincipal("dev_guest"),{kind:"api-key",provider:"openai",slug:"guest-own-machine",home:"project",project:"prj_a",reason:"own machine"},gd).intake:createWorkspaceConnect(ctx,devicePrincipal("dev_guest"),{provider:"google-gmail",client:"google-client",slug:"guest-own-machine",home:"project",project:"prj_a",reason:"own machine"},gd).connect
    const pending=await workspacePendingOps["pending.list"]!.handler(ctx,guest,{},gi) as {pending:{view:string;detail?:{id:string}}[]}
    expect(pending.pending.map(row=>row.detail?.id).sort()).toEqual([own,ownMachine].sort())
    const open=vi.spyOn(ctx,"openField"),send=vi.spyOn(globalThis,"fetch"),before=JSON.stringify(ctx.sql.exec("SELECT * FROM workspace_credential_requests ORDER BY id").toArray())
    const view=(value:string)=>kind === "intake"?workspaceIntakeOps["intake.view"].handler(ctx,guest,{intake:value},gi):Promise.resolve().then(()=>workspaceOAuthOps["oauth.connectView"].handler(ctx,guest,{connect:value},gi))
    for(const value of [id,"absent-request"]){
      await expect(view(value)).rejects.toMatchObject({code:"not_found",message:"No such credential request."})
      let failure:unknown
      try{cancelCredentialRequest(ctx,guest,value,kind,gi)}catch(e){failure=e instanceof VaultError?e.toJSON():e}
      expect(failure).toEqual({error:"not_found",message:"No such credential request."})
    }
    expect(JSON.stringify(ctx.sql.exec("SELECT * FROM workspace_credential_requests ORDER BY id").toArray())).toBe(before)
    expect(open).not.toHaveBeenCalled();expect(send).not.toHaveBeenCalled()
    expect(cancelCredentialRequest(ctx,guest,own,kind,gi)).toEqual({})
    expect(cancelCredentialRequest(ctx,guest,ownMachine,kind,gi)).toEqual({})
    send.mockRestore();open.mockRestore()
  })
})

for(const kind of ["intake","connect"] as const)it(`human ${kind} cancellation requires creator or potential-filler authority`,async()=>{
  const {cancelCredentialRequest}=await import("../src/vault/areas/intake-workspace.ts")
  const {createWorkspaceConnect}=await import("../src/vault/areas/oauth-workspace.ts")
  const {devicePrincipal,deviceInvocation,seedOAuthConnection}=await import("./credentials-test-support.ts")
  const {VaultError}=await import("../src/http.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    if(kind === "connect")await seedOAuthConnection(ctx,"project",{kind:"project",project:"prj_a"})
    const p=memberPrincipal(ctx,"member"),i=memberInvocation(ctx,"member"),machine=devicePrincipal("dev_kim"),mi=await deviceInvocation(ctx,"dev_kim")
    const create=(slug:string,human=false)=>kind === "intake"?createWorkspaceIntake(ctx,human?p:machine,{provider:"openai",slug,home:"project",project:"prj_a",...(!human?{kind:"api-key",reason:"test"}:{})},human?i:mi).intake:createWorkspaceConnect(ctx,human?p:machine,{provider:"google-gmail",client:"google-client",slug,home:"project",project:"prj_a",...(!human?{reason:"test"}:{})},human?i:mi).connect
    const own=create(`own-${kind}`,true),fillable=create(`fillable-${kind}`),unfillable=create(`unfillable-${kind}`)
    expect(cancelCredentialRequest(ctx,p,own,kind,i)).toEqual({})
    expect(cancelCredentialRequest(ctx,p,fillable,kind,i)).toEqual({})
    ctx.sql.exec("UPDATE project_shares SET value=json_set(value,'$.level','use') WHERE subject_kind='member' AND subject_id='mem_member'")
    const removed=memberPrincipal(ctx,"admin"),removedInvocation=memberInvocation(ctx,"admin")
    ctx.sql.exec("UPDATE members SET status='removed' WHERE id='mem_admin'")
    const open=vi.spyOn(ctx,"openField"),send=vi.spyOn(globalThis,"fetch"),before=JSON.stringify(ctx.sql.exec("SELECT * FROM workspace_credential_requests ORDER BY id").toArray())
    for(const [actor,auth] of [[p,i],[removed,removedInvocation]] as const)for(const id of [unfillable,"absent-request"]){
      let failure:unknown
      try{cancelCredentialRequest(ctx,actor,id,kind,auth)}catch(e){failure=e instanceof VaultError?e.toJSON():e}
      expect(failure).toEqual({error:"not_found",message:"No such credential request."})
    }
    expect(JSON.stringify(ctx.sql.exec("SELECT * FROM workspace_credential_requests ORDER BY id").toArray())).toBe(before)
    expect(open).not.toHaveBeenCalled();expect(send).not.toHaveBeenCalled();send.mockRestore();open.mockRestore()
  })
})

it("a reserved intake fills without consulting an exhausted filler name budget",async()=>{
  const {nameMiss}=await import("../src/vault/areas/workspace-runtime.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    const p=memberPrincipal(ctx,"member"),i=memberInvocation(ctx,"member"),created=createWorkspaceIntake(ctx,p,{provider:"openai",slug:"reserved-fill",home:"private"},i)
    const submission={slug:"reserved-fill",home:{kind:"member",member:"mem_member"} as const,tags:[],binding:{hosts:["api.openai.com"]},publicFields:{},sealed:{key:await sealToVault("reserved-secret",`intake/${created.intake}/key`)}}
    const digest=await stepUpDigest(submission)
    for(let n=0;n<20;n++)nameMiss.record(ctx,p,ctx.now())
    expect(nameMiss.check(ctx,p,ctx.now()).ok).toBe(false)
    await expect(submitWorkspaceIntake(ctx,p,{intake:created.intake,...submission},memberInvocation(ctx,"member",{type:"intake.submit",intake:created.intake,digest}))).resolves.toMatchObject({item:{slug:"reserved-fill"}})
    expect(ctx.sql.exec<{count:number}>("SELECT count FROM name_miss_buckets WHERE subject='account:acc_member'").toArray()[0]?.count).toBe(20)
  })
})

it("a rotation ask made stale by an edit refuses explicitly before opening submitted secrets",async()=>{
  const {seedCredential}=await import("./credentials-test-support.ts")
  const {workspaceItemOps}=await import("../src/vault/areas/items-workspace.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    const item=await seedCredential(ctx,"stale-rotation",{kind:"member",member:"mem_member"}),p=memberPrincipal(ctx,"member"),i=memberInvocation(ctx,"member")
    const created=createWorkspaceIntake(ctx,p,{slug:item.slug,home:"private"},i),change={description:"edited"},editDigest=await stepUpDigest({change,version:item.version,configRevision:item.configRev})
    await workspaceItemOps["items.update"].handler(ctx,p,{slug:item.slug,change},memberInvocation(ctx,"member",{type:"item.update",item:item.id,digest:editDigest}))
    const submission={slug:item.slug,home:item.home,tags:item.tags,binding:item.binding,publicFields:{},sealed:{key:await sealToVault("rotation-secret",`intake/${created.intake}/key`)}}
    const digest=await stepUpDigest(submission),open=vi.spyOn(ctx,"openField"),seal=vi.spyOn(ctx,"sealField"),send=vi.spyOn(globalThis,"fetch")
    const before=JSON.stringify(ctx.sql.exec("SELECT * FROM items WHERE id=?",item.id).toArray())
    await expect(submitWorkspaceIntake(ctx,p,{intake:created.intake,...submission},memberInvocation(ctx,"member",{type:"intake.submit",intake:created.intake,digest}))).rejects.toMatchObject({code:"conflict",message:"The credential changed; ask again."})
    expect(JSON.stringify(ctx.sql.exec("SELECT * FROM items WHERE id=?",item.id).toArray())).toBe(before)
    expect(open).not.toHaveBeenCalled();expect(seal).not.toHaveBeenCalled();expect(send).not.toHaveBeenCalled();open.mockRestore();seal.mockRestore();send.mockRestore()
  })
})

for(const kind of ["intake","connect"] as const)it(`workspace ${kind} status long polls until cancellation`,async()=>{
  const {workspaceIntakeOps,cancelCredentialRequest}=await import("../src/vault/areas/intake-workspace.ts")
  const {createWorkspaceConnect,workspaceOAuthOps}=await import("../src/vault/areas/oauth-workspace.ts")
  const {devicePrincipal,deviceInvocation,seedOAuthConnection}=await import("./credentials-test-support.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    if(kind === "connect")await seedOAuthConnection(ctx)
    const p=devicePrincipal(),i=await deviceInvocation(ctx),id=kind === "intake"?createWorkspaceIntake(ctx,p,{provider:"openai",kind:"api-key",slug:"wait-intake",home:"project",project:"prj_a",reason:"test"},i).intake:createWorkspaceConnect(ctx,p,{provider:"google-gmail",client:"google-client",slug:"wait-connect",home:"project",project:"prj_a",reason:"test"},i).connect
    let settled=false
    const pending=kind === "intake"?workspaceIntakeOps["intake.status"].handler(ctx,p,{intake:id,wait:true},i):workspaceOAuthOps["oauth.connectStatus"].handler(ctx,p,{connect:id,waitMs:1000},i)
    void pending.then(()=>{settled=true})
    await new Promise(resolve=>setTimeout(resolve,20));expect(settled).toBe(false)
    cancelCredentialRequest(ctx,p,id,kind,i)
    await expect(pending).resolves.toMatchObject({status:kind === "intake"?"cancelled":"failed"})
  })
})
it("long-poll status rechecks a removed owner after its wait without revealing metadata",async()=>{
  const {workspaceIntakeOps}=await import("../src/vault/areas/intake-workspace.ts")
  const {devicePrincipal,deviceInvocation}=await import("./credentials-test-support.ts")
  const f=await credentialsFixture()
  await inAccess(f.tenant,async ctx=>{
    const p=devicePrincipal(),i=await deviceInvocation(ctx),created=createWorkspaceIntake(ctx,p,{provider:"openai",kind:"api-key",slug:"wait-removed",home:"project",project:"prj_a",reason:"test"},i)
    const before=JSON.stringify(ctx.sql.exec("SELECT * FROM workspace_credential_requests").toArray()),open=vi.spyOn(ctx,"openField"),send=vi.spyOn(globalThis,"fetch")
    const refused=expect(workspaceIntakeOps["intake.status"].handler(ctx,p,{intake:created.intake,waitMs:500},i)).rejects.toMatchObject({code:"not_found",message:"No such credential request."})
    await new Promise(resolve=>setTimeout(resolve,20));ctx.sql.exec("UPDATE members SET status='removed' WHERE id='mem_member'")
    await refused
    expect(JSON.stringify(ctx.sql.exec("SELECT * FROM workspace_credential_requests").toArray())).toBe(before)
    expect(open).not.toHaveBeenCalled();expect(send).not.toHaveBeenCalled();open.mockRestore();send.mockRestore()
  })
})
it("stores a device's intake for a custom kind with no binding as lease-only, and refuses an injection with no hosts", async () => {
  const { workspaceIntakeOps } = await import("../src/vault/areas/intake-workspace.ts")
  const { devicePrincipal, deviceInvocation } = await import("./credentials-test-support.ts")
  const { LEASE_ONLY_HOST, customItemPolicy } = await import("@mehen/protocol")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const p = devicePrincipal(), i = await deviceInvocation(ctx), request = { reason: "test", home: "project", project: "prj_a" }
    const created = createWorkspaceIntake(ctx, p, { ...request, kind: "generic", slug: "session-secret" }, i)
    expect(() => createWorkspaceIntake(ctx, p, { ...request, kind: "api-key", slug: "header-no-host", injection: { in: "header", name: "X-Api-Key", format: "{key}" } }, i)).toThrowError("A custom credential sent with an injection needs a binding: name the hosts it goes to with --host.")
    expect(() => createWorkspaceIntake(ctx, p, { ...request, kind: "api-key", slug: "header-reserved", binding: { hosts: [LEASE_ONLY_HOST] }, injection: { in: "header", name: "X-Api-Key", format: "{key}" } }, i)).toThrowError("A custom credential sent with an injection needs a binding: name the hosts it goes to with --host.")
    expect(() => createWorkspaceIntake(ctx, p, { ...request, kind: "api-key", slug: "api-key-no-host" }, i)).toThrowError("An api-key credential is sent to a service: name the hosts it may go to with --host.")
    expect(() => createWorkspaceIntake(ctx, p, { ...request, kind: "basic-auth", slug: "basic-reserved", binding: { hosts: [LEASE_ONLY_HOST] } }, i)).toThrowError("A basic-auth credential is sent to a service: name the hosts it may go to with --host.")
    for (const hosts of [[LEASE_ONLY_HOST, "api.example.com"], ["*.mehen.invalid"]]) expect(() => createWorkspaceIntake(ctx, p, { ...request, kind: "generic", slug: "mixed-reserved", binding: { hosts } }, i)).toThrowError(/Invalid request: binding\.hosts/)
    const member = memberPrincipal(ctx, "member"), mi = memberInvocation(ctx, "member")
    expect(await workspaceIntakeOps["intake.view"].handler(ctx, member, { intake: created.intake }, mi)).toMatchObject({ binding: { value: { hosts: [LEASE_ONLY_HOST] }, verified: false }, injection: { value: null }, customPolicy: false })
    const submission = { slug: "session-secret", home: { kind: "project" as const, project: "prj_a" }, binding: { hosts: [LEASE_ONLY_HOST] }, publicFields: {}, tags: [], sealed: { value: await sealToVault("session-secret-value", `intake/${created.intake}/value`) } }
    const reads = { ...submission, allowReads: true }
    await expect(submitWorkspaceIntake(ctx, member, { intake: created.intake, ...reads }, memberInvocation(ctx, "member", { type: "intake.submit", intake: created.intake, digest: await stepUpDigest(reads) }))).rejects.toThrowError("A credential with no host is never sent to a service, so it takes no reads policy.")
    const digest = await stepUpDigest(submission)
    await submitWorkspaceIntake(ctx, member, { intake: created.intake, ...submission }, memberInvocation(ctx, "member", { type: "intake.submit", intake: created.intake, digest }))
    expect(checkedCredential(ctx, "session-secret")).toMatchObject({ kind: "generic", binding: { hosts: [LEASE_ONLY_HOST] }, injection: null, policy: customItemPolicy(false), home: { kind: "project", project: "prj_a" } })
  })
})
it("keeps a template's or a rotated credential's own injection when a device proposes another", async () => {
  const { workspaceIntakeOps } = await import("../src/vault/areas/intake-workspace.ts")
  const { devicePrincipal, deviceInvocation } = await import("./credentials-test-support.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    const p = devicePrincipal(), i = await deviceInvocation(ctx), member = memberPrincipal(ctx, "member"), mi = memberInvocation(ctx, "member")
    const proposal = { in: "header" as const, name: "X-Client-Secret", format: "{client_secret}" }
    const binding = { hosts: ["oauth2.googleapis.com"], paths: ["/token", "/revoke"], methods: ["POST" as const] }
    const fill = async (intake: string, publicFields: Record<string, string>, who = "member") => {
      const submission = { slug: "google-client", home: { kind: "project" as const, project: "prj_a" }, binding, publicFields, tags: [], sealed: { client_secret: await sealToVault("GOCSPX-test-fixture-not-live", `intake/${intake}/client_secret`) } }
      await submitWorkspaceIntake(ctx, memberPrincipal(ctx, who), { intake, ...submission }, memberInvocation(ctx, who, { type: "intake.submit", intake, digest: await stepUpDigest(submission) }))
    }
    const created = createWorkspaceIntake(ctx, p, { kind: "oauth-client", slug: "google-client", provider: "google-oauth-client", reason: "test", home: "project", project: "prj_a", injection: proposal }, i)
    expect(await workspaceIntakeOps["intake.view"].handler(ctx, member, { intake: created.intake }, mi)).toMatchObject({ injection: { value: null, verified: true } })
    await fill(created.intake, { client_id: "fixture.apps.googleusercontent.com" })
    expect(checkedCredential(ctx, "google-client")).toMatchObject({ provider: "google-oauth-client", injection: null })
    const rotation = createWorkspaceIntake(ctx, p, { kind: "oauth-client", slug: "google-client", reason: "test", home: "project", project: "prj_a", injection: proposal }, i)
    expect(await workspaceIntakeOps["intake.view"].handler(ctx, member, { intake: rotation.intake }, mi)).toMatchObject({ rotates: true, injection: { value: null, verified: true } })
    await fill(rotation.intake, {}, "owner")
    expect(checkedCredential(ctx, "google-client")).toMatchObject({ provider: "google-oauth-client", injection: null })
  })
})

// A person's rotation keeps the value it replaced for ADOPTION_LIMITS.replacedKeptMs,
// one set per item, restorable with a passkey.
describe("a replaced value kept and restored", () => {
  type Ctx = import("../src/vault/core.ts").VaultContext
  const pastClockTenants: string[] = []
  afterEach(async () => {
    try {
      const { runInDurableObject } = await import("cloudflare:test")
      const { env } = await import("cloudflare:workers")
      for (const tenant of pastClockTenants.splice(0))
        await runInDurableObject(env.TENANT_VAULT.getByName(tenant), async (instance, state) => {
          await instance.alarm()
          instance.context.sql.exec("DELETE FROM schedule")
          await state.storage.deleteAlarm()
        })
    } finally {
      vi.useRealTimers()
    }
  })
  async function rotate(ctx: Ctx, slug: string, value: string, role = "owner") {
    const item = checkedCredential(ctx, slug)!
    const p = memberPrincipal(ctx, role), created = createWorkspaceIntake(ctx, p, { slug, home: "workspace" }, memberInvocation(ctx, role))
    const submission = { slug, home: item.home, binding: item.binding, publicFields: {}, tags: item.tags, sealed: { key: await sealToVault(value, `intake/${created.intake}/key`) } }
    await submitWorkspaceIntake(ctx, p, { intake: created.intake, ...submission }, memberInvocation(ctx, role, { type: "intake.submit", intake: created.intake, digest: await stepUpDigest(submission) }))
    return checkedCredential(ctx, slug)!
  }
  const history = (ctx: Ctx, item: string) => ctx.sql.exec<{ name: string; version: number; ciphertext: ArrayBuffer; fingerprint: string; fp_version: number; replaced_at: number; replaced_by: string; expires_at: number }>("SELECT * FROM item_secret_history WHERE item=?", item).toArray()
  const current = (ctx: Ctx, item: string) => ctx.sql.exec<{ ciphertext: ArrayBuffer; fingerprint: string }>("SELECT ciphertext,fingerprint FROM item_secrets WHERE item=?", item).toArray()
  const bytes = (b: ArrayBuffer) => [...new Uint8Array(b)].join(",")
  async function seeded(ctx: Ctx, slug = "kept-key", home?: import("@mehen/protocol").CredentialHome) {
    const { seedCredential } = await import("./credentials-test-support.ts")
    return seedCredential(ctx, slug, home)
  }
  async function restore(ctx: Ctx, slug: string, terms: { version: number; previous: number }, role = "owner") {
    const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
    const { WorkspaceStepUpActionSchema } = await import("@mehen/protocol")
    const p = memberPrincipal(ctx, role)
    const action = WorkspaceStepUpActionSchema.parse(await workspaceItemOps["items.action"].handler(ctx, p, { slug, action: "restore", ...terms }, memberInvocation(ctx, role)))
    return workspaceItemOps["items.restore"].handler(ctx, p, { slug, ...terms }, memberInvocation(ctx, role, action))
  }

  it("keeps a person's replaced value sealed as it was, with its fingerprint, and names only its fields on the page", async () => {
    const { ADOPTION_LIMITS } = await import("@mehen/protocol")
    const { workspaceItemOps, openCredentialSecrets } = await import("../src/vault/areas/items-workspace.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seeded(ctx), [before] = current(ctx, item.id)
      const rotated = await rotate(ctx, item.slug, "rotated-value")
      expect(rotated.version).toBe(2)
      expect(await openCredentialSecrets(ctx, rotated)).toEqual({ key: "rotated-value" })
      const [kept] = history(ctx, item.id)
      expect(kept).toMatchObject({ name: "key", version: 1, fingerprint: before!.fingerprint, replaced_by: "member:mem_owner", expires_at: kept!.replaced_at + ADOPTION_LIMITS.replacedKeptMs })
      expect(bytes(kept!.ciphertext)).toBe(bytes(before!.ciphertext))
      const page = await workspaceItemOps["items.describe"].handler(ctx, memberPrincipal(ctx), { slug: item.slug }, memberInvocation(ctx))
      expect(page.previous).toEqual({ version: 1, replacedAt: new Date(kept!.replaced_at).toISOString(), expiresAt: new Date(kept!.expires_at).toISOString(), replacedBy: "owner", fields: ["key"] })
      expect(JSON.stringify(page)).not.toContain(before!.fingerprint)
    })
  })

  it("keeps only the latest replaced value when an item is rotated twice", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seeded(ctx)
      await rotate(ctx, item.slug, "second-value")
      const [second] = current(ctx, item.id)
      await rotate(ctx, item.slug, "third-value")
      const kept = history(ctx, item.id)
      expect(kept).toHaveLength(1)
      expect(kept[0]).toMatchObject({ version: 2, fingerprint: second!.fingerprint })
      expect(bytes(kept[0]!.ciphertext)).toBe(bytes(second!.ciphertext))
    })
  })

  it("keeps nothing for an OAuth connect, reconnect, refresh or a new credential: only a person's rotation and a restore", async () => {
    const { prepareCredential, storeCredential } = await import("../src/vault/areas/items-workspace.ts")
    const { credentialInput } = await import("./credentials-test-support.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seeded(ctx)
      for (const action of ["oauth.reconnect", "oauth.refresh", "oauth.connect", "item.create"]) {
        const live = checkedCredential(ctx, item.slug)!
        const prepared = await prepareCredential(ctx, { ...credentialInput(item.slug), secretFields: { key: `${action}-value` } }, live)
        ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), action))
        expect(history(ctx, item.id), action).toEqual([])
      }
      const live = checkedCredential(ctx, item.slug)!
      const prepared = await prepareCredential(ctx, { ...credentialInput(item.slug), secretFields: { key: "rotated" } }, live)
      ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.rotate"))
      expect(history(ctx, item.id)).toHaveLength(1)
    })
  })

  // An intake may target an OAuth connection; its old refresh token must not
  // outlive the overwrite, and there is nothing a restore could put back.
  it("keeps no tokens when a person rotates an OAuth connection through an intake", async () => {
    const { seedOAuthConnection } = await import("./credentials-test-support.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const connection = await seedOAuthConnection(ctx)
      const p = memberPrincipal(ctx), created = createWorkspaceIntake(ctx, p, { slug: connection.slug, home: "workspace" }, memberInvocation(ctx))
      const submission = { slug: connection.slug, home: connection.home, binding: connection.binding, publicFields: {}, tags: connection.tags, sealed: { access_token: await sealToVault("intake-access", `intake/${created.intake}/access_token`), refresh_token: await sealToVault("intake-refresh", `intake/${created.intake}/refresh_token`) } }
      await submitWorkspaceIntake(ctx, p, { intake: created.intake, ...submission }, memberInvocation(ctx, "owner", { type: "intake.submit", intake: created.intake, digest: await stepUpDigest(submission) }))
      expect(checkedCredential(ctx, connection.slug)!.version).toBe(connection.version + 1)
      expect(ctx.sql.exec("SELECT action FROM audit WHERE action='item.rotate'").toArray()).toHaveLength(1)
      expect(history(ctx, connection.id)).toEqual([])
    })
  })

  // An adoption's replace calls keepReplacedSecrets itself, with "item.rotate".
  it("keeps nothing for an OAuth connection when keepReplacedSecrets is called directly with a rotation", async () => {
    const { keepReplacedSecrets } = await import("../src/vault/areas/items.ts")
    const { seedOAuthConnection } = await import("./credentials-test-support.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const connection = await seedOAuthConnection(ctx), item = await seeded(ctx)
      ctx.storage.transactionSync(() => {
        keepReplacedSecrets(ctx, { id: connection.id, version: connection.version, kind: connection.kind }, "item.rotate", "member:mem_owner")
        keepReplacedSecrets(ctx, { id: item.id, version: item.version, kind: item.kind }, "item.rotate", "member:mem_owner")
      })
      expect(history(ctx, connection.id)).toEqual([])
      expect(history(ctx, item.id)).toHaveLength(1)
    })
  })

  it("refuses to plan or make a restore of an OAuth connection, changing nothing", async () => {
    const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
    const { seedOAuthConnection } = await import("./credentials-test-support.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const seededConnection = await seedOAuthConnection(ctx)
      ctx.sql.exec("UPDATE items SET version=version+1 WHERE id=?", seededConnection.id)
      const connection = checkedCredential(ctx, seededConnection.slug)!
      ctx.sql.exec("INSERT INTO item_secret_history (item, name, version, root_version, wrapped_dek, ciphertext, length, prefix, fingerprint, fp_version, replaced_at, replaced_by, expires_at) SELECT item, name, ?, root_version, wrapped_dek, ciphertext, length, prefix, fingerprint, fp_version, ?, 'member:mem_owner', ? FROM item_secrets WHERE item=?", connection.version - 1, ctx.now(), ctx.now() + 86_400_000, connection.id)
      const snapshot = () => JSON.stringify([checkedCredential(ctx, connection.slug), current(ctx, connection.id).map((r) => r.fingerprint), history(ctx, connection.id).map((r) => [r.version, r.fingerprint])])
      const before = snapshot(), terms = { slug: connection.slug, version: connection.version, previous: connection.version - 1 }
      const refusal = { code: "bad_request", message: "An OAuth connection keeps no previous value; reconnect it instead." }
      await expect(Promise.resolve().then(() => workspaceItemOps["items.action"].handler(ctx, memberPrincipal(ctx), { ...terms, action: "restore" }, memberInvocation(ctx)))).rejects.toMatchObject(refusal)
      const signed = { type: "item.restore" as const, item: connection.id, digest: await stepUpDigest({ item: connection.id, version: terms.version, previous: terms.previous }) }
      await expect(Promise.resolve().then(() => workspaceItemOps["items.restore"].handler(ctx, memberPrincipal(ctx), terms, memberInvocation(ctx, "owner", signed)))).rejects.toMatchObject(refusal)
      expect(snapshot()).toBe(before)
    })
  })

  it("restores by swapping, so the restore can itself be undone, and audits only the field names", async () => {
    const { openCredentialSecrets } = await import("../src/vault/areas/items-workspace.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seeded(ctx)
      await rotate(ctx, item.slug, "rotated-value")
      const [rotated] = current(ctx, item.id), [original] = history(ctx, item.id)
      const restoredAfter = ctx.now()
      const restored = await restore(ctx, item.slug, { version: 2, previous: 1 })
      expect(restored.previous).toMatchObject({ version: 2, fields: ["key"], replacedBy: "owner" })
      const live = checkedCredential(ctx, item.slug)!
      expect(live.version).toBe(3)
      expect(ctx.sql.exec<{ rotated_at: number }>("SELECT rotated_at FROM items WHERE id=?", item.id).toArray()[0]!.rotated_at).toBeGreaterThanOrEqual(restoredAfter)
      expect(await openCredentialSecrets(ctx, live)).toEqual({ key: "test-secret-never-returned" })
      expect(current(ctx, item.id)[0]!.fingerprint).toBe(original!.fingerprint)
      expect(bytes(history(ctx, item.id)[0]!.ciphertext)).toBe(bytes(rotated!.ciphertext))
      const audit = ctx.sql.exec<{ action: string; detail: string }>("SELECT action,detail FROM audit WHERE action='item.restore'").toArray()
      expect(audit).toHaveLength(1)
      expect(JSON.parse(audit[0]!.detail)).toMatchObject({ fields: ["key"] })
      expect(audit[0]!.detail).not.toContain(original!.fingerprint)
      await restore(ctx, item.slug, { version: 3, previous: 2 })
      expect(await openCredentialSecrets(ctx, checkedCredential(ctx, item.slug)!)).toEqual({ key: "rotated-value" })
      expect(history(ctx, item.id)[0]).toMatchObject({ version: 3, fingerprint: original!.fingerprint })
    })
  })

  it("redoes a kept fingerprint made under an older key version when it is restored", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seeded(ctx)
      await rotate(ctx, item.slug, "rotated-value")
      const [original] = history(ctx, item.id)
      ctx.sql.exec("UPDATE item_secret_history SET fingerprint='stale-print', fp_version=NULL WHERE item=?", item.id)
      await restore(ctx, item.slug, { version: 2, previous: 1 })
      expect(ctx.sql.exec("SELECT fingerprint,fp_version FROM item_secrets WHERE item=?", item.id).toArray()).toEqual([{ fingerprint: original!.fingerprint, fp_version: ctx.rootVersion }])
    })
  })

  it("refuses a restore without the rotation right, without a passkey, and after a rotation since the page loaded, changing nothing", async () => {
    const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
    const { WorkspaceStepUpActionSchema } = await import("@mehen/protocol")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seeded(ctx)
      await rotate(ctx, item.slug, "rotated-value")
      const snapshot = () => JSON.stringify([checkedCredential(ctx, item.slug), current(ctx, item.id).map((r) => r.fingerprint), history(ctx, item.id).map((r) => [r.version, r.fingerprint])])
      const before = snapshot(), terms = { slug: item.slug, version: 2, previous: 1 }
      const mp = memberPrincipal(ctx, "member")
      await expect(Promise.resolve().then(() => workspaceItemOps["items.action"].handler(ctx, mp, { ...terms, action: "restore" }, memberInvocation(ctx, "member")))).rejects.toMatchObject({ code: "forbidden" })
      const signed = WorkspaceStepUpActionSchema.parse(await workspaceItemOps["items.action"].handler(ctx, memberPrincipal(ctx), { ...terms, action: "restore" }, memberInvocation(ctx)))
      await expect(Promise.resolve().then(() => workspaceItemOps["items.restore"].handler(ctx, mp, terms, memberInvocation(ctx, "member", signed)))).rejects.toMatchObject({ code: "forbidden" })
      await expect(Promise.resolve().then(() => workspaceItemOps["items.restore"].handler(ctx, memberPrincipal(ctx), terms, memberInvocation(ctx)))).rejects.toMatchObject({ code: "forbidden", message: "This needs a passkey confirmation of the exact action." })
      expect(snapshot()).toBe(before)
      await rotate(ctx, item.slug, "rotated-since")
      const since = snapshot()
      await expect(Promise.resolve().then(() => workspaceItemOps["items.restore"].handler(ctx, memberPrincipal(ctx), terms, memberInvocation(ctx, "owner", signed)))).rejects.toMatchObject({ code: "conflict", message: "The credential changed; review and try again." })
      await expect(Promise.resolve().then(() => workspaceItemOps["items.action"].handler(ctx, memberPrincipal(ctx), { ...terms, action: "restore" }, memberInvocation(ctx)))).rejects.toMatchObject({ code: "conflict", message: "The credential changed; review and try again." })
      expect(snapshot()).toBe(since)
    })
  })

  // Planning and making the restore, with a passkey signed for exactly it.
  async function refusedRestore(ctx: Ctx, item: { id: string; slug: string }, role: string, refusal: { code: string; message?: string }) {
    const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
    const terms = { slug: item.slug, version: 2, previous: 1 }
    const p = memberPrincipal(ctx, role)
    const signed = { type: "item.restore" as const, item: item.id, digest: await stepUpDigest({ item: item.id, version: 2, previous: 1 }) }
    const snapshot = () => JSON.stringify([checkedCredential(ctx, item.slug), current(ctx, item.id).map((r) => r.fingerprint), history(ctx, item.id).map((r) => [r.version, r.fingerprint])])
    const before = snapshot()
    await expect(Promise.resolve().then(() => workspaceItemOps["items.action"].handler(ctx, p, { ...terms, action: "restore" }, memberInvocation(ctx, role)))).rejects.toMatchObject(refusal)
    await expect(Promise.resolve().then(() => workspaceItemOps["items.restore"].handler(ctx, p, terms, memberInvocation(ctx, role, signed)))).rejects.toMatchObject(refusal)
    expect(snapshot()).toBe(before)
  }

  it("refuses a restore to a project manager when a protected environment they may not change uses the credential", async () => {
    const { editAccessFixture } = await import("./access-test-support.ts")
    const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seeded(ctx, "kept-project", { kind: "project", project: "prj_a" })
      await rotate(ctx, item.slug, "rotated-value")
      await expect(workspaceItemOps["items.action"].handler(ctx, memberPrincipal(ctx, "kim"), { slug: item.slug, action: "restore", version: 2, previous: 1 }, memberInvocation(ctx, "kim"))).resolves.toMatchObject({ type: "item.restore" })
      editAccessFixture(ctx, (s) => { s.projects.find((p) => p.id === "prj_b")!.environments.find((e) => e.name === "prod")!.references.push({ variable: "TOKEN", field: "key", item: item.id, home: item.home, revision: 1 }) })
      await refusedRestore(ctx, item, "kim", { code: "forbidden", message: "A protected environment uses this credential, and you may not change it." })
    })
  })

  it("refuses a guest a restore of another member's private credential", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seeded(ctx, "kept-private", { kind: "member", member: "mem_member" })
      await rotate(ctx, item.slug, "rotated-value", "member")
      await refusedRestore(ctx, item, "guest", { code: "not_found" })
    })
  })

  for (const role of ["owner", "admin"])
    it(`refuses an ${role} a restore of another member's private credential, as it refuses them its rotation`, async () => {
      const f = await credentialsFixture()
      await inAccess(f.tenant, async (ctx) => {
        const item = await seeded(ctx, "kept-private", { kind: "member", member: "mem_member" })
        await rotate(ctx, item.slug, "rotated-value", "member")
        await expect(Promise.resolve().then(() => createWorkspaceIntake(ctx, memberPrincipal(ctx, role), { slug: item.slug, home: "private" }, memberInvocation(ctx, role)))).rejects.toMatchObject({ code: "not_found" })
        await refusedRestore(ctx, item, role, { code: "not_found" })
      })
    })

  // The member saw only the value that was later replaced, and a relay-only
  // credential leaves their machine no lease reach, so their removal flagged
  // nothing; the restore makes that value current again.
  it("flags a restored value a removed member saw for review, as their removal flags a current one", async () => {
    const { workspaceMemberOps } = await import("../src/vault/areas/workspace-members.ts")
    const { recordExposure } = await import("../src/vault/areas/workspace-runtime.ts")
    const { prepareCredential, storeCredential } = await import("../src/vault/areas/items-workspace.ts")
    const { credentialInput } = await import("./credentials-test-support.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const prepared = await prepareCredential(ctx, { ...credentialInput("kept-key"), ceiling: "relay" }, null)
      const item = ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
      recordExposure(ctx, { item: item.id, version: 1, member: "mem_member", device: null, event: "entered:kept-key:1", source: "entered", at: ctx.now() })
      await rotate(ctx, item.slug, "rotated-value")
      await workspaceMemberOps["access.members.remove"]!.handler(ctx, memberPrincipal(ctx), { member: "mem_member" }, memberInvocation(ctx, "owner", { type: "member.remove", member: "mem_member" }))
      expect(checkedCredential(ctx, item.slug)!.review).toBeNull()
      await restore(ctx, item.slug, { version: 2, previous: 1 })
      expect(checkedCredential(ctx, item.slug)!.review?.reason).toBe("member left: member")
    })
  })

  it("sets no review flag when everyone who saw the restored value is still a member", async () => {
    const { recordExposure } = await import("../src/vault/areas/workspace-runtime.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seeded(ctx)
      recordExposure(ctx, { item: item.id, version: 1, member: "mem_admin", device: null, event: "entered:kept-key:1", source: "entered", at: ctx.now() })
      await rotate(ctx, item.slug, "rotated-value")
      await restore(ctx, item.slug, { version: 2, previous: 1 })
      expect(ctx.sql.exec("SELECT member FROM exposures WHERE item=? AND version=3 ORDER BY member", item.id).toArray()).toEqual([{ member: "mem_admin" }, { member: "mem_owner" }])
      expect(checkedCredential(ctx, item.slug)!.review).toBeNull()
    })
  })

  it("purges a kept value 30 days after it was replaced, from the items alarm", async () => {
    const { runInDurableObject } = await import("cloudflare:test")
    const { env } = await import("cloudflare:workers")
    const { ADOPTION_LIMITS } = await import("@mehen/protocol")
    const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
    const start = Date.parse("2026-03-01T09:00:00Z")
    vi.useFakeTimers({ toFake: ["Date"], now: start })
    const f = await credentialsFixture()
    pastClockTenants.push(f.tenant)
    await inAccess(f.tenant, async (ctx) => {
      const item = await seeded(ctx)
      await rotate(ctx, item.slug, "rotated-value")
      expect(ctx.sql.exec("SELECT due_at FROM schedule WHERE area='items' AND key='secret-history'").toArray()).toEqual([{ due_at: start + ADOPTION_LIMITS.replacedKeptMs }])
    })
    vi.setSystemTime(start + ADOPTION_LIMITS.replacedKeptMs - 1)
    await runInDurableObject(env.TENANT_VAULT.getByName(f.tenant), async (instance) => {
      await instance.alarm()
      expect(instance.context.sql.exec("SELECT count(*) AS n FROM item_secret_history").toArray()).toEqual([{ n: 1 }])
    })
    vi.setSystemTime(start + ADOPTION_LIMITS.replacedKeptMs)
    await runInDurableObject(env.TENANT_VAULT.getByName(f.tenant), async (instance) => {
      const ctx = instance.context
      expect((await workspaceItemOps["items.describe"].handler(ctx, memberPrincipal(ctx), { slug: "kept-key" }, memberInvocation(ctx))).previous).toBeNull()
      await instance.alarm()
      expect(ctx.sql.exec("SELECT count(*) AS n FROM item_secret_history").toArray()).toEqual([{ n: 0 }])
      expect(ctx.sql.exec("SELECT key FROM schedule WHERE area='items'").toArray()).toEqual([])
      await expect(Promise.resolve().then(() => workspaceItemOps["items.action"].handler(ctx, memberPrincipal(ctx), { slug: "kept-key", action: "restore", version: 2, previous: 1 }, memberInvocation(ctx)))).rejects.toMatchObject({ code: "conflict" })
    })
  })

  it("deletes the kept value with its credential", async () => {
    const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seeded(ctx)
      await rotate(ctx, item.slug, "rotated-value")
      expect(history(ctx, item.id)).toHaveLength(1)
      workspaceItemOps["items.delete"].handler(ctx, memberPrincipal(ctx), { slug: item.slug }, memberInvocation(ctx, "owner", { type: "item.delete", item: item.id }))
      expect(history(ctx, item.id)).toEqual([])
    })
  })

  it("never puts the kept value in a machine's answer", async () => {
    const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
    const { devicePrincipal, deviceInvocation } = await import("./credentials-test-support.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seeded(ctx)
      await rotate(ctx, item.slug, "rotated-value")
      const i = await deviceInvocation(ctx)
      const described = await workspaceItemOps["items.describe"].handler(ctx, devicePrincipal(), { slug: item.slug }, i)
      expect(described.slug).toBe(item.slug)
      expect(described).not.toHaveProperty("previous")
      const listed = await workspaceItemOps["items.list"].handler(ctx, devicePrincipal(), {}, i)
      expect(listed.items.map((x) => x.slug)).toContain(item.slug)
      expect(JSON.stringify(listed)).not.toContain("previous")
    })
  })
})
