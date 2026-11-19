import { expectDirectoryRefusal } from "./directory-test-support.ts"
import { beginAccessSideEffectChecks,finishAccessSideEffectChecks } from "./access-test-support.ts"
import { directoryRuntimeFixture } from "./directory-runtime-fixture.ts"
import { workspaceEnrolRoutes } from "../src/routes/enrolments.ts"
import { findRoute } from "../src/router.ts"
import { workspaceCall } from "../src/routes/context.ts"
import { PendingEnrolSchema,PendingEnrolViewSchema,digest,newMember,type InboxEnrolCandidate,type PendingEnrolRecord } from "../src/vault/areas/workspace-runtime.ts"
import { inboxEnrolRows } from "../src/vault/areas/pending-workspace.ts"
import { responseFor } from "../src/http.ts"
import { setPasskeyCeremonies,simpleWebAuthnCeremonies } from "../src/directory/webauthn.ts"
import { directoryCeremonies } from "./directory-test-support.ts"
import { directoryWorkspaceClient } from "../src/directory/workspace-client.ts"
import { resolveWorkspace } from "../src/routes/context.ts"
import { accessFixture,accessSnapshot,accountAuth,inAccess,workspaceInvoke } from "./access-test-support.ts"
import { canonicalJson,jwkThumbprint,fingerprintGroups,fingerprintOf,fingerprintGroupIndex,WorkspaceEnrolViewSchema,bodyHash,createProof,webCryptoSigner,utf8 } from "@mehen/protocol"
import { afterEach,beforeEach,describe,expect,it } from "vitest"
import { checkWorkspaceTypedGroup,enrolRegistration,startWorkspaceEnrolment,workspaceEnrolmentByCode,workspaceEnrolmentStatus,mirrorActiveEnrolment,reconcileEnrolmentMirrors,type EnrolMirrorClient,type WorkspaceEnrolmentRow } from "../src/directory/workspace-enrolment.ts"
import { enrolmentFingerprint } from "../src/directory/enrolment.ts"
import { createWorkspaceFixture,type WorkspaceTestFixture } from "./workspace-fixtures.ts"
import { newDeviceKey,publicJwk } from "./devices.ts"
let f: WorkspaceTestFixture
beforeEach(async () => { beginAccessSideEffectChecks(); f = await createWorkspaceFixture() })
const origin = "https://vault.test"
async function start(workspace = "alex",owner: { kind: "self" } | { kind: "team"; team: string } = { kind: "self" }) {
  const keys = await newDeviceKey(),input = { workspace,owner,name: "Laptop",backend: "software" as const,jwk: await publicJwk(keys) },raw = utf8(JSON.stringify(input)),url = `${origin}/v1/enrol`
  const proof = await createProof(webCryptoSigner("new",keys.privateKey),{ method: "POST",url,body: raw },{ tenant: "enrol" })
  const request = new Request(url,{ method: "POST",headers: { "Mehen-Proof": proof,"user-agent": "Mozilla/5.0 (Macintosh) Version/18.0 Safari/605.1" },body: raw })
  const started = await startWorkspaceEnrolment(f.env,request,raw,input)
  return { keys,input,raw,request,started }
}
async function poll(keys: CryptoKeyPair,enrolment: string) { const url = `${origin}/v1/enrol/${enrolment}`,proof = await createProof(webCryptoSigner(enrolment,keys.privateKey),{ method: "GET",url,body: null },{ tenant: "enrol" }); return workspaceEnrolmentStatus(f.env,new Request(url,{ headers: { "Mehen-Proof": proof } }),enrolment) }
const personal = () => ({ id: f.workspaces.personal,slug: "alex",name: "Personal" })
const client = (calls: string[]): EnrolMirrorClient => ({ async expire() { return { expired: true } },async reconcile() { return { device: null,mirrored: false,state: "pending_owner_acceptance",active: null } },async mirrored(_w,e,d) { calls.push(`mirrored:${e}:${d}`) },async discard(_w,e,d) { calls.push(`discard:${e}:${d}`) } })
describe("workspace enrolment directory",() => {
  it("start records signed intent and trusted context, without resolving existence",async () => {
    const { started } = await start("not-a-workspace")
    expect(started.url).toContain(`/w/not-a-workspace/e/${started.code}`)
    expect(await f.env.DB.prepare("SELECT workspace_intent,start_client_label,start_place,pending_state FROM enrolments WHERE id=?").bind(started.enrolment).first()).toEqual({ workspace_intent: "not-a-workspace",start_client_label: "Safari on Mac",start_place: null,pending_state: "pending_owner_acceptance" })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces").first()).toEqual({ n: 2 })
  })
  it("foreign and unknown codes refuse with exact equality and no enrolment mutation",async () => {
    const { started } = await start()
    const before = (await f.env.DB.prepare("SELECT * FROM enrolments").all()).results
    const other = { id: f.workspaces.work,slug: "northwind",name: "Work" }
    for (const code of [started.code,"23456789"]) await expectDirectoryRefusal(workspaceEnrolmentByCode(f.env,other,code),{ error: "not_found",message: "No such enrolment." })
    expect((await f.env.DB.prepare("SELECT * FROM enrolments").all()).results).toEqual(before)
    const found = await workspaceEnrolmentByCode(f.env,personal(),started.code)
    expect(found.row.start_at).toBeTypeOf("number")
    expect(await enrolmentFingerprint(found.code,found.row.thumbprint)).toHaveProperty("check")
  })
  it("nonce replay and body tampering cannot start a second enrolment",async () => {
    const s = await start()
    await expectDirectoryRefusal(startWorkspaceEnrolment(f.env,s.request,s.raw,s.input),{ error: "proof_invalid",message: "This Mehen-Proof has already been used. Sign every request afresh." })
    const raw = utf8(JSON.stringify({ ...s.input,workspace: "northwind" }))
    await expectDirectoryRefusal(startWorkspaceEnrolment(f.env,s.request,raw,{ ...s.input,workspace: "northwind" }),{ error: "proof_invalid",message: "The Mehen-Proof was signed over a different body than this request sent." })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM enrolments").first()).toEqual({ n: 1 })
    expect(await bodyHash(s.raw)).not.toBe(await bodyHash(raw))
  })
  it("the fifth hidden-group miss rejects atomically and a later correct group cannot reopen it",async () => {
    const { started } = await start(),{ row } = await workspaceEnrolmentByCode(f.env,personal(),started.code)
    const hidden = fingerprintGroups(fingerprintOf(row.thumbprint))[await fingerprintGroupIndex(started.code)],wrong = hidden === "AAAA" ? "BBBB" : "AAAA"
    for (let i=0;i<5;i++) {
      const checked = await checkWorkspaceTypedGroup(f.env,started.code,row,wrong)
      expect(checked.ok).toBe(false)
      if (!checked.ok) expect(checked.refusal.toJSON()).toEqual(i === 4 ? { error: "conflict",message: "The hidden group was wrong 5 times, so this enrolment is rejected. Start a fresh enrolment on the machine." } : { error: "forbidden",message: `That is not the hidden group of this key. Type it from the terminal: ${4-i} attempts left before this enrolment is rejected.` })
    }
    const before = await f.env.DB.prepare("SELECT status,pending_state,group_attempts,device FROM enrolments WHERE id=?").bind(row.id).first()
    expect(before).toEqual({ status: "rejected",pending_state: null,group_attempts: 5,device: null })
    await expectDirectoryRefusal(checkWorkspaceTypedGroup(f.env,started.code,row,hidden),{ error: "conflict",message: "This enrolment was already decided or has expired." })
    expect(await f.env.DB.prepare("SELECT status,pending_state,group_attempts,device FROM enrolments WHERE id=?").bind(row.id).first()).toEqual(before)
  })
  it("failed active mirror durably queues discard and poll never becomes active",async () => {
    const s = await start(),{ row } = await workspaceEnrolmentByCode(f.env,personal(),s.started.code),calls: string[] = []
    await f.env.DB.prepare("CREATE TRIGGER fail_active BEFORE UPDATE ON enrolments WHEN NEW.status='active' BEGIN SELECT RAISE(ABORT,'mirror failed'); END").run()
    await expect(mirrorActiveEnrolment(f.env,row,personal(),{ device: "dev_new",scope: { tags: [],projects: [],maxEnvironment: "unprotected",modes: ["relay"],privateCredentials: false },owner: { kind: "member",member: f.personalMember,name: "Owner" } },client(calls))).rejects.toThrow("mirror failed")
    expect(await poll(s.keys,s.started.enrolment)).toEqual({ status: "expired",reason: "discarded" })
    expect(await f.env.DB.prepare("SELECT discard_pending,discard_device FROM enrolments WHERE id=?").bind(row.id).first()).toEqual({ discard_pending: 1,discard_device: "dev_new" })
    await reconcileEnrolmentMirrors(f.env,client(calls)); await reconcileEnrolmentMirrors(f.env,client(calls))
    expect(calls).toEqual([`discard:${row.id}:dev_new`])
    await f.env.DB.prepare("DROP TRIGGER fail_active").run()
  })
  it("does not mark D1 reconciled until the pending source acknowledges expiry",async () => {
    const s = await start(),{ row } = await workspaceEnrolmentByCode(f.env,personal(),s.started.code),c = client([])
    await f.env.DB.prepare("UPDATE enrolments SET expires_at=?,hard_expires_at=? WHERE id=?").bind(Date.now()-1,Date.now()-1,row.id).run()
    c.expire = async () => ({ expired: false })
    await reconcileEnrolmentMirrors(f.env,c)
    expect(await f.env.DB.prepare("SELECT status,reconciled_at FROM enrolments WHERE id=?").bind(row.id).first()).toEqual({ status: "pending",reconciled_at: null })
    c.expire = async () => { throw new Error("unavailable") }
    await reconcileEnrolmentMirrors(f.env,c)
    expect(await f.env.DB.prepare("SELECT status,reconciled_at FROM enrolments WHERE id=?").bind(row.id).first()).toEqual({ status: "pending",reconciled_at: null })
    c.expire = async () => ({ expired: true })
    await reconcileEnrolmentMirrors(f.env,c)
    expect(await f.env.DB.prepare("SELECT status,reconciled_at FROM enrolments WHERE id=?").bind(row.id).first()).toEqual({ status: "expired",reconciled_at: expect.any(Number) })
  })
  it("reconcile leaves a lapsed lease pending and expires the attempt only at its hard cap",async () => {
    const s = await start(),{ row } = await workspaceEnrolmentByCode(f.env,personal(),s.started.code),calls: string[] = []
    await f.env.DB.prepare("UPDATE enrolments SET expires_at=? WHERE id=?").bind(Date.now()-1,row.id).run()
    await reconcileEnrolmentMirrors(f.env,client(calls))
    expect(await f.env.DB.prepare("SELECT status,expired_reason,reconciled_at FROM enrolments WHERE id=?").bind(row.id).first()).toEqual({ status: "pending",expired_reason: null,reconciled_at: null })
    await f.env.DB.prepare("UPDATE enrolments SET hard_expires_at=? WHERE id=?").bind(Date.now()-1,row.id).run()
    await reconcileEnrolmentMirrors(f.env,client(calls))
    expect(await f.env.DB.prepare("SELECT status,expired_reason FROM enrolments WHERE id=?").bind(row.id).first()).toEqual({ status: "expired",expired_reason: "hard_cap" })
    expect(await poll(s.keys,s.started.enrolment)).toEqual({ status: "expired",reason: "hard_cap" })
  })
  it("lost acknowledgement retries without discarding a successfully mirrored device",async () => {
    const s = await start(),{ row } = await workspaceEnrolmentByCode(f.env,personal(),s.started.code),calls: string[] = [],c = client(calls)
    c.mirrored = async () => { throw new Error("unavailable") }
    await mirrorActiveEnrolment(f.env,row,personal(),{ device: "dev_new",scope: { tags: [],projects: [],maxEnvironment: "unprotected",modes: ["relay"],privateCredentials: true },owner: { kind: "member",member: f.personalMember,name: "Owner" } },c)
    expect(await poll(s.keys,s.started.enrolment)).toMatchObject({ status: "active",workspace: personal(),owner: { kind: "member",member: f.personalMember },scope: { privateCredentials: true } })
    await reconcileEnrolmentMirrors(f.env,client(calls)); await reconcileEnrolmentMirrors(f.env,client(calls))
    expect(calls).toEqual([`mirrored:${row.id}:dev_new`])
  })
})

afterEach(() => setPasskeyCeremonies(simpleWebAuthnCeremonies))
describe("enrolment public view and own acceptance",() => {
  it("builds the frozen view from unbound DO planning and refuses admission proof as acceptance",async () => {
    const live = await directoryRuntimeFixture(); setPasskeyCeremonies(directoryCeremonies)
    const s = await start("work")
    const get = workspaceEnrolRoutes.find(route => route.method === "GET")!
    const rc = live.context(`/enrolments/${s.started.code}`,undefined,{ ref: s.started.code })
    const response = await get.handler(rc,live.workspace),view = WorkspaceEnrolViewSchema.parse(await response.json())
    expect(view.ref).toBe(s.started.code)
    expect(view.code).toBe(view.ref)
    expect(view.start.clientLabel).toBe("Safari on Mac")
    // The private tick starts on for the acceptor's own machine.
    expect(view.scope.privateCredentials).toBe(true)
    expect(view.actions).toContain("accept")
    await inAccess(live.tenant,ctx => expect(ctx.sql.exec("SELECT owner_id FROM devices WHERE enrolment=?",s.started.enrolment).toArray()).toEqual([]))
    const before = (await live.env.DB.prepare("SELECT * FROM enrolments WHERE id=?").bind(s.started.enrolment).all()).results
    const wrong = await live.proof({ type: "enrol.approve",enrolment: view.enrolment,digest: view.digest,owner: { kind: "member",member: live.workspace.membership,name: "Owner" },admissionRole: "owner" })
    const group = fingerprintGroups(fingerprintOf((await workspaceEnrolmentByCode(live.env,live.workspace.workspace,s.started.code)).row.thumbprint))[await fingerprintGroupIndex(s.started.code)]
    const accept = workspaceEnrolRoutes.find(route => route.path.endsWith("/accept"))!
    let error: unknown
    try { await accept.handler(live.context("",{ privateCredentials: false,group,stepUp: wrong },{ ref: s.started.code }),live.workspace) } catch (e) { error = e }
    expect(await responseFor(error).json()).toEqual({ error: "forbidden",message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." })
    expect((await live.env.DB.prepare("SELECT * FROM enrolments WHERE id=?").bind(s.started.enrolment).all()).results).toEqual(before)
    const action = { type: "enrol.accept" as const,workspace: live.tenant,enrolment: view.enrolment,thumbprint: (await workspaceEnrolmentByCode(live.env,live.workspace.workspace,s.started.code)).row.thumbprint,account: live.account,member: live.workspace.membership,scope: view.scope,start: view.start }
    const accepted = WorkspaceEnrolViewSchema.parse(await (await accept.handler(live.context("",{ privateCredentials: view.scope.privateCredentials,group,stepUp: await live.proof(action) },{ ref: s.started.code }),live.workspace)).json())
    expect(accepted.state).toBe("active")
    expect(accepted.digest).toBe(view.digest)
    expect(accepted.owner).toMatchObject({ kind: "member",member: live.workspace.membership })
    expect(await poll(s.keys,s.started.enrolment)).toMatchObject({ status: "active",workspace: { id: live.tenant },scope: { privateCredentials: true } })
  })
  it("sole owner defaults on and a team defaults off without binding any owner at GET",async () => {
    const live = await directoryRuntimeFixture(); setPasskeyCeremonies(directoryCeremonies)
    await inAccess(live.tenant,ctx => { ctx.sql.exec("UPDATE members SET status='removed' WHERE account!='acc_owner'") })
    const get = workspaceEnrolRoutes.find(route => route.method === "GET")!
    const s = await start("work"),rc = live.context("",undefined,{ ref: s.started.code })
    const ws = await resolveWorkspace(rc),own = WorkspaceEnrolViewSchema.parse(await (await get.handler(rc,ws)).json())
    expect(own.scope.privateCredentials).toBe(true)
    expect(own.owner).toBeNull()
    const { row } = await workspaceEnrolmentByCode(live.env,ws.workspace,s.started.code),group = fingerprintGroups(fingerprintOf(row.thumbprint))[await fingerprintGroupIndex(s.started.code)]
    const action = { type: "enrol.accept" as const,workspace: live.tenant,enrolment: row.id,thumbprint: row.thumbprint,account: live.account,member: ws.membership,scope: own.scope,start: own.start }
    const accept = workspaceEnrolRoutes.find(route => route.path.endsWith("/accept"))!
    await accept.handler(live.context("",{ privateCredentials: true,group,stepUp: await live.proof(action) },{ ref: s.started.code }),ws)
    const revisited = WorkspaceEnrolViewSchema.parse(await (await get.handler(rc,ws)).json())
    expect(revisited.state).toBe("active")
    expect(revisited.scope.privateCredentials).toBe(true)
    const team = await start("work",{ kind: "team",team: "tm_service" })
    const shared = WorkspaceEnrolViewSchema.parse(await (await get.handler(live.context("",undefined,{ ref: team.started.code }),live.workspace)).json())
    expect(shared.scope.privateCredentials).toBe(false)
    expect(shared.requestedOwner).toEqual({ kind: "team",team: "tm_service",name: "Service" })
    expect(shared.owner).toBeNull()
  })
})

afterEach(() => finishAccessSideEffectChecks())

async function orphanEnrolment() {
  const live = await directoryRuntimeFixture(),s = await start("work"),get = workspaceEnrolRoutes.find(route => route.method === "GET")!
  const rc = live.context("",undefined,{ ref: s.started.code }),view = WorkspaceEnrolViewSchema.parse(await (await get.handler(rc,live.workspace)).json())
  const { row } = await workspaceEnrolmentByCode(live.env,live.workspace.workspace,s.started.code)
  const action = { type: "enrol.accept" as const,workspace: live.tenant,enrolment: row.id,thumbprint: row.thumbprint,account: live.account,member: live.workspace.membership,scope: view.scope,start: view.start }
  const active = PendingEnrolViewSchema.parse(await workspaceCall(rc,live.workspace,"access.enrol.accept",{ enrolment: row.id,privateCredentials: view.scope.privateCredentials },{ action,factor: "pk_test" }))
  expect(active.state).toBe("active")
  return { live,s,row,active }
}
describe("enrolment acceptance-before-mirror crash recovery",() => {
  it("retries a crash after DO registration but before the D1 workspace binding",async () => {
    const live = await directoryRuntimeFixture(),s = await start("work"),client = directoryWorkspaceClient(live.env)
    const { row } = await workspaceEnrolmentByCode(live.env,live.workspace.workspace,s.started.code)
    await client.registerEnrol(live.tenant,enrolRegistration(row))
    expect(await live.env.DB.prepare("SELECT tenant,status FROM enrolments WHERE id=?").bind(row.id).first()).toEqual({ tenant: null,status: "pending" })
    const get = workspaceEnrolRoutes.find(route => route.method === "GET")!,rc = live.context("",undefined,{ ref: s.started.code })
    const view = WorkspaceEnrolViewSchema.parse(await (await get.handler(rc,live.workspace)).json())
    expect(view.state).toBe("pending_owner_acceptance")
    expect(view.start.at).toBe(new Date(row.start_at).toISOString())
    expect(view.expiresAt).toBe(new Date(row.expires_at).toISOString())
    expect(view.owner).toBeNull()
    expect(JSON.stringify(view)).not.toContain(row.code_hash)
    expect(await live.env.DB.prepare("SELECT tenant,status FROM enrolments WHERE id=?").bind(row.id).first()).toEqual({ tenant: live.tenant,status: "pending" })
    await inAccess(live.tenant,ctx => {
      expect(ctx.sql.exec("SELECT id FROM workspace_enrolments WHERE id=?",row.id).toArray()).toEqual([{ id: row.id }])
      expect(ctx.sql.exec("SELECT id FROM devices WHERE enrolment=?",row.id).toArray()).toEqual([])
    })
  })
  it("the cron mirrors a committed source device before the deadline",async () => {
    const { live,s,active } = await orphanEnrolment()
    expect(await poll(s.keys,s.started.enrolment)).toMatchObject({ status: "pending_owner_acceptance" })
    await reconcileEnrolmentMirrors(live.env,directoryWorkspaceClient(live.env))
    expect(await poll(s.keys,s.started.enrolment)).toMatchObject({ status: "active",device: active.device,scope: active.scope })
    expect(await live.env.DB.prepare("SELECT mirror_acknowledged FROM enrolments WHERE id=?").bind(s.started.enrolment).first()).toEqual({ mirror_acknowledged: 1 })
  })
  it("the cron discards an unmirrored source device after the deadline",async () => {
    const { live,s,row,active } = await orphanEnrolment()
    await reconcileEnrolmentMirrors(live.env,directoryWorkspaceClient(live.env),row.expires_at+1)
    expect(await poll(s.keys,s.started.enrolment)).toEqual({ status: "expired",reason: "discarded" })
    await inAccess(live.tenant,ctx => expect(ctx.sql.exec("SELECT id FROM devices WHERE id=?",active.device!).toArray()).toEqual([]))
    expect(await live.env.DB.prepare("SELECT discard_pending,reconciled_at FROM enrolments WHERE id=?").bind(row.id).first()).toEqual({ discard_pending: 0,reconciled_at: row.expires_at+1 })
  })
  it("a pending enrolment without a device survives a cron tick before its deadline",async () => {
    const live = await directoryRuntimeFixture(),s = await start("work"),get = workspaceEnrolRoutes.find(route => route.method === "GET")!
    await get.handler(live.context("",undefined,{ ref: s.started.code }),live.workspace)
    await reconcileEnrolmentMirrors(live.env,directoryWorkspaceClient(live.env))
    expect(await poll(s.keys,s.started.enrolment)).toMatchObject({ status: "pending_owner_acceptance" })
    expect(await live.env.DB.prepare("SELECT reconciled_at FROM enrolments WHERE id=?").bind(s.started.enrolment).first()).toEqual({ reconciled_at: null })
  })
})

// Records stored before the lease: detail.expiresAt and no
// claimedAccount, their digest bound by any stored acceptance or admission.
// Nothing may rewrite them; every reader maps them in memory.
type Live = Awaited<ReturnType<typeof directoryRuntimeFixture>>
async function seedLegacy(live: Live,row: WorkspaceEnrolmentRow,patch: (terms: { digest: string }) => Record<string,unknown> = () => ({})): Promise<string> {
  const terms = { enrolment: row.id,start: { at: new Date(row.start_at).toISOString(),place: row.start_place,clientLabel: row.start_client_label },thumbprint: row.thumbprint,requestedOwner: JSON.parse(row.owner_intent) as unknown,scope: { tags: [],projects: [],modes: ["relay","sign","mint","placeholder"],maxEnvironment: "unprotected",privateCredentials: false },detail: { name: row.name,backend: row.backend,host: row.host,jwk: JSON.parse(row.jwk) as unknown,codeHash: row.code_hash,expiresAt: new Date(row.expires_at).toISOString() } }
  const legacyDigest = digest(terms)
  const value = canonicalJson({ ...terms,workspace: { id: live.tenant,slug: "work",name: "Work" },state: "pending_owner_acceptance",digest: legacyDigest,owner: null,acceptance: null,admission: null,device: null,admissionProject: null,...patch({ digest: legacyDigest }) })
  await inAccess(live.tenant,ctx => { ctx.sql.exec("INSERT INTO workspace_enrolments(id,thumbprint,value) VALUES (?,?,?)",row.id,row.thumbprint,value) })
  // The D1 row as migration 0008 leaves a pre-lease row: its hard cap is its
  // expiry and no hidden group is persisted.
  await live.env.DB.prepare("UPDATE enrolments SET tenant=?,hard_expires_at=?,hidden_group=NULL WHERE id=?").bind(live.tenant,row.expires_at,row.id).run()
  return legacyDigest
}
const storedValue = (live: Live,id: string) => inAccess(live.tenant,ctx => JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM workspace_enrolments WHERE id=?",id).one().value) as Record<string,unknown> & { digest: string; detail: Record<string,unknown> })
describe("stored legacy DO enrolment JSON",() => {
  it("a legacy pending record reads, re-registers idempotently, accepts in its own names and lists its machine with its start",async () => {
    const live = await directoryRuntimeFixture(); setPasskeyCeremonies(directoryCeremonies)
    const s = await start("work"),{ row } = await workspaceEnrolmentByCode(live.env,live.workspace.workspace,s.started.code)
    const legacyDigest = await seedLegacy(live,row)
    const get = workspaceEnrolRoutes.find(route => route.method === "GET")!
    const view = WorkspaceEnrolViewSchema.parse(await (await get.handler(live.context("",undefined,{ ref: s.started.code }),live.workspace)).json())
    // The page plans the private tick on; the person unticks it, so the legacy terms are accepted unchanged.
    expect(view).toMatchObject({ state: "pending_owner_acceptance",scope: { privateCredentials: true },actions: ["accept","reject"] })
    const client = directoryWorkspaceClient(live.env),registration = enrolRegistration((await workspaceEnrolmentByCode(live.env,live.workspace.workspace,s.started.code)).row)
    expect(await client.registerEnrol(live.tenant,registration)).toMatchObject({ enrolment: row.id,digest: legacyDigest,claimedAccount: null,detail: { hardExpiresAt: new Date(row.expires_at).toISOString() } })
    await expect(client.registerEnrol(live.tenant,{ ...registration,claimedAccount: "acc_member" })).rejects.toMatchObject({ code: "conflict",message: "This enrolment has different terms." })
    const group = fingerprintGroups(fingerprintOf(row.thumbprint))[await fingerprintGroupIndex(s.started.code)]
    const action = { type: "enrol.accept" as const,workspace: live.tenant,enrolment: row.id,thumbprint: row.thumbprint,account: live.account,member: live.workspace.membership,scope: { ...view.scope,privateCredentials: false },start: view.start }
    const accept = workspaceEnrolRoutes.find(route => route.path.endsWith("/accept"))!
    const accepted = WorkspaceEnrolViewSchema.parse(await (await accept.handler(live.context("",{ privateCredentials: false,group,stepUp: await live.proof(action) },{ ref: s.started.code }),live.workspace)).json())
    expect(accepted).toMatchObject({ state: "active",digest: legacyDigest })
    const stored = await storedValue(live,row.id)
    expect(stored).toMatchObject({ state: "active",digest: legacyDigest,acceptance: { digest: legacyDigest },detail: { expiresAt: new Date(row.expires_at).toISOString() } })
    expect(stored).not.toHaveProperty("claimedAccount")
    expect(stored).not.toHaveProperty("legacy")
    expect(stored.detail).not.toHaveProperty("hardExpiresAt")
    // The access fixture's placeholder machines have no real keys to list.
    await inAccess(live.tenant,ctx => { ctx.sql.exec("DELETE FROM devices WHERE enrolment IS NULL") })
    const devices = (await workspaceCall(live.context(""),live.workspace,"devices.list",{})) as { devices: { device: string; start: unknown }[] }
    expect(devices.devices.find(d => d.device === stored.device)).toMatchObject({ start: view.start })
    expect(await client.registerEnrol(live.tenant,registration)).toMatchObject({ state: "active",digest: legacyDigest })
  })
  it("a legacy guest acceptance awaiting admission is admitted against its stored digest",async () => {
    const live = await directoryRuntimeFixture()
    const s = await start("work"),{ row } = await workspaceEnrolmentByCode(live.env,live.workspace.workspace,s.started.code)
    const generation = await inAccess(live.tenant,ctx => ctx.sql.exec<{ gate_generation: number }>("SELECT gate_generation FROM members WHERE id='mem_guest'").one().gate_generation)
    const at = new Date().toISOString()
    const legacyDigest = await seedLegacy(live,row,({ digest: bound }) => ({ state: "pending_admission",owner: { kind: "member",member: "mem_guest",name: "guest" },acceptance: { account: "acc_guest",member: "mem_guest",digest: bound,ruleRevision: 0,gateGeneration: generation,identityCheck: null,at } }))
    const owner = { kind: "member" as const,member: "mem_guest",name: "guest" }
    const admitted = await workspaceInvoke(live.tenant,"access.enrol.admit",{ enrolment: row.id,project: "prj_a" },accountAuth("kim",{ type: "enrol.approve",enrolment: row.id,digest: legacyDigest,owner,admissionRole: "member" }))
    expect(admitted).toMatchObject({ ok: true,value: { state: "active",digest: legacyDigest,device: expect.stringMatching(/^dev_/) } })
    const stored = await storedValue(live,row.id)
    expect(stored).toMatchObject({ state: "active",digest: legacyDigest,acceptance: { digest: legacyDigest,at },admission: { digest: legacyDigest,account: "acc_kim" },detail: { expiresAt: new Date(row.expires_at).toISOString() } })
    expect(stored).not.toHaveProperty("claimedAccount")
  })
  it("reconcile, rejection and expiry read a legacy record and keep its original terminal time",async () => {
    const live = await directoryRuntimeFixture()
    const s = await start("work"),{ row } = await workspaceEnrolmentByCode(live.env,live.workspace.workspace,s.started.code)
    const legacyDigest = await seedLegacy(live,row)
    const system = { kind: "system",reason: "test" } as const
    expect(await workspaceInvoke(live.tenant,"access.enrol.reconcile",{ enrolment: row.id },system)).toEqual({ ok: true,value: { device: null,mirrored: false,state: "pending_owner_acceptance",active: null } })
    expect(await workspaceInvoke(live.tenant,"access.enrol.expire",{ enrolment: row.id },system)).toEqual({ ok: true,value: { expired: false } })
    const before = await storedValue(live,row.id)
    expect(await workspaceInvoke(live.tenant,"access.enrol.reject",{ enrolment: row.id },accountAuth("owner"))).toMatchObject({ ok: true,value: { state: "rejected",digest: legacyDigest } })
    expect(await storedValue(live,row.id)).toEqual({ ...before,state: "rejected" })
    const other = await start("work"),{ row: lapsing } = await workspaceEnrolmentByCode(live.env,live.workspace.workspace,other.started.code)
    const ended = Date.now()-1
    await seedLegacy(live,{ ...lapsing,expires_at: ended })
    expect(await workspaceInvoke(live.tenant,"access.enrol.expire",{ enrolment: lapsing.id },system)).toEqual({ ok: true,value: { expired: true } })
    const expired = await storedValue(live,lapsing.id)
    expect(expired).toMatchObject({ state: "expired",detail: { expiresAt: new Date(ended).toISOString() } })
    expect(expired).not.toHaveProperty("claimedAccount")
  })
  it("a new registration carries the hard cap and the claim, never the legacy names",async () => {
    const live = await directoryRuntimeFixture()
    const s = await start("work"),get = workspaceEnrolRoutes.find(route => route.method === "GET")!
    await get.handler(live.context("",undefined,{ ref: s.started.code }),live.workspace)
    const stored = await storedValue(live,s.started.enrolment)
    expect(stored).toMatchObject({ claimedAccount: null,detail: { hardExpiresAt: expect.any(String) } })
    expect(stored.detail).not.toHaveProperty("expiresAt")
    expect(stored).not.toHaveProperty("legacy")
  })
})

// The claim and the two visibility answers, decided inside the workspace
// from live standing.
async function registered(tenant: string,claimedAccount: string | null = null,owner: { kind: "self" } | { kind: "team"; team: string } = { kind: "self" },key?: CryptoKeyPair) {
  const keys = key ?? await newDeviceKey(),jwk = await publicJwk(keys),thumbprint = await jwkThumbprint(jwk)
  const input = { enrolment: `enr_${crypto.randomUUID().replaceAll("-","")}`,start: { at: new Date().toISOString(),place: null,clientLabel: "Bun" },thumbprint,requestedOwner: owner,claimedAccount,scope: { tags: [],projects: [],modes: ["relay","sign","mint","placeholder"],maxEnvironment: "unprotected" },detail: { name: "Laptop",backend: "software",host: null,jwk,codeHash: "hash-only",hardExpiresAt: new Date(Date.now()+86_400_000).toISOString() } }
  const result = await workspaceInvoke(tenant,"access.enrol.register",input,{ kind: "system",reason: "test" })
  if (!result.ok) throw new Error(JSON.stringify(result))
  return PendingEnrolSchema.parse(result.value)
}
function candidateOf(value: PendingEnrolRecord,patch: Partial<InboxEnrolCandidate> = {}): InboxEnrolCandidate {
  return { enrolment: value.enrolment,thumbprint: value.thumbprint,name: "Laptop",host: null,backend: "software",start: value.start,session: "native-app:fa987f",requestedOwner: value.requestedOwner,claimedAccount: value.claimedAccount,claimedName: value.claimedAccount === null ? null : "member",status: "pending",pendingState: value.requestedOwner.kind === "team" ? "pending_admission" : "pending_owner_acceptance",lease: "live",acceptedByAccount: null,expiresAt: new Date(Date.now()+3_600_000).toISOString(),hardExpiresAt: new Date(Date.now()+86_400_000).toISOString(),hiddenGroup: 1,...patch }
}
async function visibility(tenant: string,role: string,candidate: InboxEnrolCandidate) {
  const result = await workspaceInvoke(tenant,"access.enrol.visible",{ candidate },accountAuth(role))
  if (!result.ok) throw new Error(JSON.stringify(result))
  return result.value
}
const acceptAs = (tenant: string,value: PendingEnrolRecord,role: string) => workspaceInvoke(tenant,"access.enrol.accept",{ enrolment: value.enrolment,privateCredentials: false },accountAuth(role,{ type: "enrol.accept",enrolment: value.enrolment,workspace: tenant,thumbprint: value.thumbprint,account: `acc_${role}`,member: `mem_${role}`,scope: value.scope,start: value.start }))
describe("the claim in the workspace",() => {
  it("access.enrol.accept refuses every account but the claimed one, whatever the caller's role",async () => {
    const { tenant } = await accessFixture(),value = await registered(tenant,"acc_member")
    for (const role of ["owner","admin","kim"]) {
      const before = await accessSnapshot(tenant)
      expect(await acceptAs(tenant,value,role)).toEqual({ ok: false,error: { status: 403,vaultError: { error: "forbidden",message: "This machine was started for another account." } } })
      expect(await accessSnapshot(tenant)).toBe(before)
    }
    expect(await workspaceInvoke(tenant,"access.enrol.view",{ enrolment: value.enrolment },accountAuth("owner"))).toMatchObject({ ok: true,value: { actions: ["reject"],claimedAccount: "acc_member" } })
    expect(await workspaceInvoke(tenant,"access.enrol.view",{ enrolment: value.enrolment },accountAuth("member"))).toMatchObject({ ok: true,value: { actions: ["accept","reject"] } })
    expect(await acceptAs(tenant,value,"member")).toMatchObject({ ok: true,value: { state: "active",owner: { kind: "member",member: "mem_member" } } })
  })
  it("a claim is part of the registered terms: a different claim on re-registration is a conflict",async () => {
    const { tenant } = await accessFixture(),value = await registered(tenant,null)
    const { scope: _scope,workspace: _workspace,state: _state,digest: _digest,owner: _owner,acceptance: _acceptance,admission: _admission,device: _device,admissionProject: _project,...terms } = value
    const input = { ...terms,scope: { tags: [],projects: [],modes: ["relay","sign","mint","placeholder"],maxEnvironment: "unprotected" } }
    expect(await workspaceInvoke(tenant,"access.enrol.register",input,{ kind: "system",reason: "test" })).toMatchObject({ ok: true })
    expect(await workspaceInvoke(tenant,"access.enrol.register",{ ...input,claimedAccount: "acc_member" },{ kind: "system",reason: "test" })).toEqual({ ok: false,error: { status: 409,vaultError: { error: "conflict",message: "This enrolment has different terms." } } })
  })
  it("one key may hold many attempts in the workspace, but only one live machine",async () => {
    const { tenant } = await accessFixture(),key = await newDeviceKey()
    const first = await registered(tenant,null,{ kind: "self" },key),second = await registered(tenant,null,{ kind: "self" },key)
    expect(second.thumbprint).toBe(first.thumbprint)
    const history = () => inAccess(tenant,ctx => ctx.sql.exec<{ id: string; value: string }>("SELECT id,value FROM workspace_enrolments WHERE thumbprint=? ORDER BY id",first.thumbprint).toArray())
    const before = (await history()).find(row => row.id === first.enrolment)!.value
    expect(await acceptAs(tenant,second,"member")).toMatchObject({ ok: true,value: { state: "active" } })
    const snapshot = await accessSnapshot(tenant)
    expect(await acceptAs(tenant,first,"member")).toEqual({ ok: false,error: { status: 409,vaultError: { error: "conflict",message: "This key is already enrolled. Revoke it and enrol a fresh key." } } })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    expect((await history()).find(row => row.id === first.enrolment)!.value).toBe(before)
    expect(await history()).toHaveLength(2)
  })
  it("a claimed account that is suspended is refused at acceptance",async () => {
    const { tenant } = await accessFixture(),value = await registered(tenant,"acc_member")
    await inAccess(tenant,ctx => { ctx.sql.exec("UPDATE members SET status='suspended' WHERE id='mem_member'") })
    expect(await acceptAs(tenant,value,"member")).toMatchObject({ ok: false,error: { vaultError: { error: "not_found" } } })
  })
})
describe("access.enrol.visible: may view and may act",() => {
  it("an unclaimed start is seen and decided by owners and admins only",async () => {
    const { tenant } = await accessFixture(),value = await registered(tenant),live = candidateOf(value)
    for (const role of ["owner","admin"]) expect(await visibility(tenant,role,live)).toEqual({ visible: true,actions: ["accept","reject"] })
    for (const role of ["member","kim","guest"]) expect(await visibility(tenant,role,live)).toEqual({ visible: false,actions: [] })
    expect(await visibility(tenant,"owner",candidateOf(value,{ lease: "lapsed" }))).toEqual({ visible: true,actions: ["reject"] })
    expect(await visibility(tenant,"owner",candidateOf(value,{ lease: "terminal",status: "expired",pendingState: null }))).toEqual({ visible: true,actions: [] })
    expect(await visibility(tenant,"member",candidateOf(value,{ lease: "lapsed" }))).toEqual({ visible: false,actions: [] })
  })
  it("a claimed start is decided by the claimed account; owners and admins may only reject it",async () => {
    const { tenant } = await accessFixture(),value = await registered(tenant,"acc_member"),live = candidateOf(value)
    expect(await visibility(tenant,"member",live)).toEqual({ visible: true,actions: ["accept","reject"] })
    for (const role of ["owner","admin"]) expect(await visibility(tenant,role,live)).toEqual({ visible: true,actions: ["reject"] })
    for (const role of ["kim","guest"]) expect(await visibility(tenant,role,live)).toEqual({ visible: false,actions: [] })
    expect(await visibility(tenant,"member",candidateOf(value,{ lease: "lapsed" }))).toEqual({ visible: true,actions: [] })
  })
  it("a guest's accepted machine: the guest views it, never acts; the project's manager and owners admit it; an unrelated guest sees nothing",async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant,ctx => { newMember(ctx,"acc_stranger","Stranger","guest","active","mem_stranger") })
    const value = await registered(tenant)
    expect(await acceptAs(tenant,value,"guest")).toMatchObject({ ok: true,value: { state: "pending_admission" } })
    for (const lease of ["live","lapsed","terminal"] as const) {
      const candidate = candidateOf(value,{ lease,acceptedByAccount: "acc_guest",pendingState: "pending_admission" })
      expect(await visibility(tenant,"guest",candidate)).toEqual({ visible: true,actions: [] })
      expect(await visibility(tenant,"stranger",candidate)).toEqual({ visible: false,actions: [] })
      expect(await visibility(tenant,"member",candidate)).toEqual({ visible: false,actions: [] })
    }
    const live = candidateOf(value,{ acceptedByAccount: "acc_guest",pendingState: "pending_admission" })
    expect(await visibility(tenant,"kim",live)).toEqual({ visible: true,actions: ["admit","reject"] })
    expect(await visibility(tenant,"owner",live)).toEqual({ visible: true,actions: ["admit","reject"] })
  })
  it("a team's machine is admitted by owners and admins only",async () => {
    const { tenant } = await accessFixture(),value = await registered(tenant,null,{ kind: "team",team: "tm_service" }),live = candidateOf(value)
    expect(await visibility(tenant,"owner",live)).toEqual({ visible: true,actions: ["admit","reject"] })
    for (const role of ["member","kim","guest"]) expect(await visibility(tenant,role,live)).toEqual({ visible: false,actions: [] })
  })
  it("a suspended caller is refused with the workspace's own code",async () => {
    const { tenant } = await accessFixture(),value = await registered(tenant)
    await inAccess(tenant,ctx => { ctx.sql.exec("UPDATE members SET status='suspended' WHERE id='mem_admin'") })
    expect(await workspaceInvoke(tenant,"access.enrol.visible",{ candidate: candidateOf(value) },accountAuth("admin"))).toMatchObject({ ok: false,error: { vaultError: { error: "owner_inactive" } } })
  })
})
describe("inboxEnrolRows",() => {
  it("lists a row exactly when it is visible, live and the caller has something to do, never the hidden group or the thumbprint",async () => {
    const { tenant } = await accessFixture()
    const open = await registered(tenant),guestMachine = await registered(tenant),legacy = await registered(tenant),lapsed = await registered(tenant)
    expect(await acceptAs(tenant,guestMachine,"guest")).toMatchObject({ ok: true })
    const candidates = [candidateOf(open),candidateOf(guestMachine,{ acceptedByAccount: "acc_guest",pendingState: "pending_admission" }),candidateOf(legacy,{ hiddenGroup: null }),candidateOf(lapsed,{ lease: "lapsed" })]
    const rows = (role: string) => inAccess(tenant,ctx => inboxEnrolRows(ctx,{ auth: accountAuth(role),workspace: { id: tenant,slug: "work",name: "Work" } },candidates))
    const owner = await rows("owner")
    expect(owner.map(item => [item.kind === "enrol" && item.enrol.enrolment,item.action])).toEqual([[open.enrolment,"accept"],[guestMachine.enrolment,"admit"]])
    expect(owner[0]).toMatchObject({ kind: "enrol",href: `/w/work/e/${open.enrolment}`,createdAt: open.start.at,enrol: { owner: null,claimed: null,state: "pending_owner_acceptance",session: "native-app:fa987f",actions: ["accept","reject"] } })
    const first = owner[0]!
    if (first.kind !== "enrol") throw new Error("not an enrolment row")
    expect(first.enrol.fingerprint.groups[1]).toBeNull()
    expect(first.enrol.fingerprint.groups.filter(group => group !== null)).toHaveLength(3)
    expect(JSON.stringify(owner)).not.toContain(open.thumbprint)
    expect(JSON.stringify(owner)).not.toContain(fingerprintGroups(fingerprintOf(open.thumbprint))[1])
    expect((await rows("kim")).map(item => item.kind === "enrol" && item.enrol.enrolment)).toEqual([guestMachine.enrolment])
    expect(await rows("guest")).toEqual([])
    expect(await rows("member")).toEqual([])
  })
})
