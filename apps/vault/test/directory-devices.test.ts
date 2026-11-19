import { beginAccessSideEffectChecks,finishAccessSideEffectChecks } from "./access-test-support.ts"
import { afterEach,beforeEach,describe,expect,it } from "vitest"
import { base64UrlEncode,RescopeProposalViewSchema,WorkspaceStepUpActionSchema } from "@mehen/protocol"
import { workspaceDeviceRoutes } from "../src/routes/workspace-devices.ts"
import { findRoute } from "../src/router.ts"
import { responseFor } from "../src/http.ts"
import { setPasskeyCeremonies,simpleWebAuthnCeremonies } from "../src/directory/webauthn.ts"
import { accountSessionStatements,insertAccountPasskey } from "../src/directory/account-store.ts"
import { currentAccountSession } from "../src/directory/account-session.ts"
import { newSession } from "../src/directory/session.ts"
import { directoryRuntimeFixture } from "./directory-runtime-fixture.ts"
import { directoryCeremonies } from "./directory-test-support.ts"
import { accountAuth,inAccess,workspaceInvoke } from "./access-test-support.ts"
import { startAccountStepUp } from "../src/directory/workspace-stepup.ts"
import { installSecurity,updateRestriction } from "../src/vault/areas/workspace-runtime.ts"
import type { WorkspaceStepUpAction } from "@mehen/protocol"
import { WORKSPACE_FULL_SCOPE } from "./workspace-fixtures.ts"
let f: Awaited<ReturnType<typeof directoryRuntimeFixture>>
beforeEach(async () => { beginAccessSideEffectChecks(); f = await directoryRuntimeFixture(); setPasskeyCeremonies(directoryCeremonies) })
afterEach(() => setPasskeyCeremonies(simpleWebAuthnCeremonies))
async function call(path: string,body?: unknown) {
  const found = findRoute(workspaceDeviceRoutes,body === undefined ? "GET" : "POST",path)
  if (!found || found === "method") throw new Error("Missing device route")
  try { return await found.route.handler(f.context(path,body,found.params),f.workspace) } catch (error) { return responseFor(error) }
}
async function scope() { return inAccess(f.tenant,ctx => ctx.sql.exec<{ scope: string }>("SELECT scope FROM devices WHERE id='dev_member'").toArray()[0]?.scope) }
describe("thin workspace machine routes",() => {
  it("gets a live canonical thumbprint action and narrows only after that exact proof",async () => {
    const after = { ...WORKSPACE_FULL_SCOPE,tags: ["only"] },prepared = await call("/devices/dev_member/action",{ change: { kind: "rescope",before: WORKSPACE_FULL_SCOPE,after } })
    const action = WorkspaceStepUpActionSchema.parse((await prepared.json() as { action: unknown }).action)
    expect(action).toMatchObject({ type: "device.rescope",thumbprint: "dev_member",before: WORKSPACE_FULL_SCOPE,after })
    const wrong = await call("/devices/dev_member/rescope",{ before: WORKSPACE_FULL_SCOPE,after,stepUp: await f.proof({ type: "device.revoke",device: "dev_member" }) })
    expect(wrong.status).toBe(403)
    expect(await wrong.json()).toEqual({ error: "forbidden",message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." })
    expect(JSON.parse(await scope() ?? "{}")).toEqual(WORKSPACE_FULL_SCOPE)
    const response = await call("/devices/dev_member/rescope",{ before: WORKSPACE_FULL_SCOPE,after,stepUp: await f.proof(action) })
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ state: "committed",scope: after })
    expect(JSON.parse(await scope() ?? "{}")).toEqual(after)
  })
  it("mixed narrowing/private-tick widening persists a proposal, not an active scope change",async () => {
    const after = { ...WORKSPACE_FULL_SCOPE,tags: ["only"],privateCredentials: true },prepared = await call("/devices/dev_member/action",{ change: { kind: "rescope_propose",before: WORKSPACE_FULL_SCOPE,after } }),action = WorkspaceStepUpActionSchema.parse((await prepared.json() as { action: unknown }).action)
    const response = await call("/devices/dev_member/rescope",{ before: WORKSPACE_FULL_SCOPE,after,stepUp: await f.proof(action) })
    expect(response.status).toBe(200)
    const view = RescopeProposalViewSchema.parse(await response.json())
    expect(view).toMatchObject({ state: "open",requiredSigners: [{ name: "member",as: "owner_acceptance" }],signedBy: [] })
    for (const hidden of ["acc_member","signatures","deviceRevision","ownerRevision","scopeRevision","pk_test"]) expect(JSON.stringify(view)).not.toContain(hidden)
    expect(JSON.parse(await scope() ?? "{}")).toEqual(WORKSPACE_FULL_SCOPE)
  })
  it("a guest machine card parses only the display evidence of another signer",async () => {
    const at = new Date().toISOString(),session = await newSession()
    await f.env.DB.batch(accountSessionStatements(f.env,session,"acc_guest",Date.now(),{ kind: "web",method: "passkey",passkey: null,client: "Browser",place: null }))
    const request = new Request(f.env.VAULT_ORIGIN,{ headers: { cookie: `__Host-mehen_session=${session.token}` } }),account = await currentAccountSession(request,f.env)
    if (!account) throw new Error("Missing guest fixture session")
    await inAccess(f.tenant,ctx => { ctx.sql.exec("UPDATE devices SET thumbprint=?,admission=? WHERE id='dev_guest'",base64UrlEncode(new Uint8Array(32)),JSON.stringify({ account: "acc_owner",member: "mem_owner",digest: "private-digest",ruleRevision: 0,gateGeneration: 0,identityCheck: "idc_private",at })) })
    const list = workspaceDeviceRoutes.find(route => route.method === "GET" && route.path === "/devices")!
    const response = await list.handler({ ...f.context("/devices"),request },{ ...f.workspace,membership: "mem_guest",account })
    expect(response.status).toBe(200)
    const body = await response.json() as { devices: { device: string; admission: unknown }[] }
    expect(body.devices.find(device => device.device === "dev_guest")?.admission).toEqual({ name: "owner",at })
    for (const hidden of ["acc_owner","mem_owner","private-digest","idc_private"]) expect(JSON.stringify(body)).not.toContain(hidden)
  })
  it("legacy admissionAccount is uniformly forbidden before planning or spending a nonce",async () => {
    const before = await scope()
    for (const admissionAccount of ["acc_admin","acc_unknown",null]) {
      const response = await call("/devices/dev_member/rescope",{ before: WORKSPACE_FULL_SCOPE,after: { ...WORKSPACE_FULL_SCOPE,privateCredentials: true },admissionAccount })
      expect(response.status).toBe(403)
      expect(await response.json()).toEqual({ error: "forbidden",message: "Choose an eligible insider for this guest's shared project." })
    }
    expect(await scope()).toBe(before)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM challenges").first()).toEqual({ n: 0 })
    await inAccess(f.tenant,ctx => expect(ctx.sql.exec("SELECT * FROM device_rescope_proposals").toArray()).toEqual([]))
  })
  it("rejects a proposal only after a passkey over the reject, leaving scope and scope_rev alone",async () => {
    const after = { ...WORKSPACE_FULL_SCOPE,privateCredentials: true }
    const proposed = await workspaceInvoke(f.tenant,"devices.rescope",{ device: "dev_owner",before: WORKSPACE_FULL_SCOPE,after },accountAuth("admin",{ type: "device.rescope",device: "dev_owner",thumbprint: "dev_owner",before: WORKSPACE_FULL_SCOPE,after }))
    if (!proposed.ok) throw new Error(JSON.stringify(proposed))
    const proposal = RescopeProposalViewSchema.parse(proposed.value)
    const stored = async () => inAccess(f.tenant,ctx => ({ device: ctx.sql.exec<{ scope: string; scope_rev: number }>("SELECT scope,scope_rev FROM devices WHERE id='dev_owner'").toArray()[0],state: (JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM device_rescope_proposals WHERE id=?",proposal.id).toArray()[0]!.value) as { state: string }).state }))
    const before = await stored()
    const prepared = await call("/devices/dev_owner/action",{ change: { kind: "rescope_reject",proposal: proposal.id } })
    const action = WorkspaceStepUpActionSchema.parse((await prepared.json() as { action: unknown }).action)
    expect(action).toEqual({ type: "device.rescope_reject",device: "dev_owner",thumbprint: "dev_owner",proposal: proposal.id })
    const accept = { type: "device.rescope_accept" as const,device: "dev_owner",thumbprint: "dev_owner",account: "acc_owner",before: WORKSPACE_FULL_SCOPE,after,admission: false }
    for (const body of [{ proposal: proposal.id },{ proposal: proposal.id,stepUp: await f.proof(accept) }]) {
      const refused = await call("/devices/dev_owner/rescope-reject",body)
      expect(refused.status).toBe(403)
      expect(await refused.json()).toEqual({ error: "forbidden",message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." })
    }
    expect(await stored()).toEqual(before)
    const response = await call("/devices/dev_owner/rescope-reject",{ proposal: proposal.id,stepUp: await f.proof(action) })
    expect(response.status).toBe(200)
    expect(RescopeProposalViewSchema.parse(await response.json())).toMatchObject({ id: proposal.id,state: "rejected",before: WORKSPACE_FULL_SCOPE,after })
    expect(await stored()).toEqual({ device: before.device,state: "rejected" })
    expect(JSON.parse(before.device?.scope ?? "{}")).toEqual(WORKSPACE_FULL_SCOPE)
  })
  it.each(["restricted","pending"] as const)("a %s owner rejects through the route with a passkey, while accept stays refused at both gates",async (standing) => {
    const after = { ...WORKSPACE_FULL_SCOPE,privateCredentials: true }
    const proposed = await workspaceInvoke(f.tenant,"devices.rescope",{ device: "dev_owner",before: WORKSPACE_FULL_SCOPE,after },accountAuth("admin",{ type: "device.rescope",device: "dev_owner",thumbprint: "dev_owner",before: WORKSPACE_FULL_SCOPE,after }))
    if (!proposed.ok) throw new Error(JSON.stringify(proposed))
    const proposal = RescopeProposalViewSchema.parse(proposed.value)
    if (standing === "restricted") {
      await f.env.DB.prepare("UPDATE accounts SET restricted_until=?,restricted_reason='recovery' WHERE id='acc_owner'").bind(Date.now()+600_000).run()
      await inAccess(f.tenant,ctx => updateRestriction(ctx,"acc_owner",0,{ reason: "recovery",until: ctx.now()+600_000,notice: "ntc_rj" }))
    } else {
      await f.env.DB.prepare("UPDATE accounts SET security_transition='trn_rj' WHERE id='acc_owner'").run()
      await inAccess(f.tenant,ctx => installSecurity(ctx,"acc_owner",0,{ transitionId: "trn_rj",reservedEpoch: 1,revokedSessionIds: [],removedFactorIds: [],restriction: null }))
    }
    const stored = async () => inAccess(f.tenant,ctx => ({ device: ctx.sql.exec<{ scope: string; scope_rev: number }>("SELECT scope,scope_rev FROM devices WHERE id='dev_owner'").toArray()[0],state: (JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM device_rescope_proposals WHERE id=?",proposal.id).toArray()[0]!.value) as { state: string }).state,audit: ctx.sql.exec("SELECT actor FROM audit WHERE action='device.rescope_rejected'").toArray() }))
    const before = await stored()
    // Accept: the directory will not start its passkey, and the vault will not plan it.
    const accept: WorkspaceStepUpAction = { type: "device.rescope_accept",device: "dev_owner",thumbprint: "dev_owner",account: "acc_owner",before: WORKSPACE_FULL_SCOPE,after,admission: false }
    await expect(f.proof(accept)).rejects.toMatchObject({ code: standing === "pending" ? "account_pending" : "forbidden" })
    expect((await call("/devices/dev_owner/rescope-accept",{ proposal: proposal.id })).status).toBe(403)
    expect(await stored()).toEqual(before)
    const prepared = await call("/devices/dev_owner/action",{ change: { kind: "rescope_reject",proposal: proposal.id } })
    expect(prepared.status).toBe(200)
    const action = WorkspaceStepUpActionSchema.parse((await prepared.json() as { action: unknown }).action)
    const response = await call("/devices/dev_owner/rescope-reject",{ proposal: proposal.id,stepUp: await f.proof(action) })
    expect(response.status).toBe(200)
    expect(RescopeProposalViewSchema.parse(await response.json())).toMatchObject({ id: proposal.id,state: "rejected" })
    expect(await stored()).toEqual({ device: before.device,state: "rejected",audit: [{ actor: "member:mem_owner" }] })
    // A fresh proof for the same reject answers the same view and audits nothing more.
    const again = await call("/devices/dev_owner/rescope-reject",{ proposal: proposal.id,stepUp: await f.proof(action) })
    expect(again.status).toBe(200)
    expect(await again.json()).toMatchObject({ id: proposal.id,state: "rejected" })
    expect(await stored()).toEqual({ device: before.device,state: "rejected",audit: [{ actor: "member:mem_owner" }] })
  })
  it("a named project-manager admission signer rejects a guest machine's proposal through the route with a passkey",async () => {
    const guestScope = await inAccess(f.tenant,ctx => JSON.parse(ctx.sql.exec<{ scope: string }>("SELECT scope FROM devices WHERE id='dev_guest'").toArray()[0]!.scope) as typeof WORKSPACE_FULL_SCOPE)
    const after = { ...guestScope,privateCredentials: true }
    const proposed = await workspaceInvoke(f.tenant,"devices.rescope",{ device: "dev_guest",before: guestScope,after,project: "prj_a",admissionMember: "mem_kim" },accountAuth("admin",{ type: "device.rescope",device: "dev_guest",thumbprint: "dev_guest",before: guestScope,after }))
    if (!proposed.ok) throw new Error(JSON.stringify(proposed))
    const proposal = RescopeProposalViewSchema.parse(proposed.value)
    const now = Date.now(),session = await newSession()
    await f.env.DB.batch(accountSessionStatements(f.env,session,"acc_kim",now,{ kind: "web",method: "passkey",passkey: null,client: "Browser",place: null }))
    await insertAccountPasskey(f.env,"acc_kim",{ credentialId: "credential-kim",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },now-1000,"signup","pk_kim").run()
    const cookie = `__Host-mehen_session=${session.token}`
    const account = await currentAccountSession(new Request(f.env.VAULT_ORIGIN,{ headers: { cookie } }),f.env)
    if (!account) throw new Error("Missing Kim's fixture session")
    const asKim = async (path: string,body: unknown) => {
      const found = findRoute(workspaceDeviceRoutes,"POST",path)
      if (!found || found === "method") throw new Error("Missing device route")
      const base = f.context(path,body,found.params)
      const request = new Request(base.url,{ method: "POST",headers: { cookie,origin: f.env.VAULT_ORIGIN,"content-type": "application/json" },body: JSON.stringify(body) })
      try { return await found.route.handler({ ...base,request },{ ...f.workspace,membership: "mem_kim",account }) } catch (error) { return responseFor(error) }
    }
    const proof = async (action: WorkspaceStepUpAction) => ({ nonce: (await startAccountStepUp(f.env,account,f.tenant,action)).nonce,assertion: { id: "credential-kim",rawId: "credential-kim",type: "public-key",response: {} } })
    const scopeBefore = await inAccess(f.tenant,ctx => ctx.sql.exec("SELECT scope,scope_rev FROM devices WHERE id='dev_guest'").toArray())
    const prepared = await asKim("/devices/dev_guest/action",{ change: { kind: "rescope_reject",proposal: proposal.id },project: "prj_a" })
    expect(prepared.status).toBe(200)
    const action = WorkspaceStepUpActionSchema.parse((await prepared.json() as { action: unknown }).action)
    expect(action).toEqual({ type: "device.rescope_reject",device: "dev_guest",thumbprint: "dev_guest",proposal: proposal.id })
    const wrong = await asKim("/devices/dev_guest/rescope-reject",{ proposal: proposal.id,project: "prj_a",stepUp: await proof({ type: "device.rescope",device: "dev_guest",thumbprint: "dev_guest",before: guestScope,after }) })
    expect(wrong.status).toBe(403)
    const response = await asKim("/devices/dev_guest/rescope-reject",{ proposal: proposal.id,project: "prj_a",stepUp: await proof(action) })
    expect(response.status).toBe(200)
    expect(RescopeProposalViewSchema.parse(await response.json())).toMatchObject({ id: proposal.id,state: "rejected" })
    expect(await inAccess(f.tenant,ctx => ctx.sql.exec("SELECT scope,scope_rev FROM devices WHERE id='dev_guest'").toArray())).toEqual(scopeBefore)
    expect(await inAccess(f.tenant,ctx => ctx.sql.exec<{ actor: string; detail: string }>("SELECT actor,detail FROM audit WHERE action='device.rescope_rejected'").toArray().map(row => ({ actor: row.actor,as: (JSON.parse(row.detail) as { as: string }).as })))).toEqual([{ actor: "member:mem_kim",as: "admission" }])
  })
  it("exports no transfer route and missing proof never revokes a device",async () => {
    const response = await call("/devices/dev_member/revoke",{})
    expect(response.status).toBe(403)
    expect(await response.json()).toEqual({ error: "forbidden",message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." })
    await inAccess(f.tenant,ctx => expect(ctx.sql.exec("SELECT revoked_at FROM devices WHERE id='dev_member'").toArray()).toEqual([{ revoked_at: null }]))
    expect(findRoute(workspaceDeviceRoutes,"POST","/devices/dev_member/transfer")).toBeNull()
  })
})

afterEach(() => finishAccessSideEffectChecks())
