import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { setOidcFetchForTest } from "../../src/directory/oidc.ts"
import { sha256Text } from "../../src/directory/session.ts"
import { fakeGoogle } from "../oidc-google.ts"
import { createProof, webCryptoSigner, jwkThumbprint, fingerprintGroupIndex, fingerprintGroups, fingerprintOf, type WorkspaceApprovalView, type WorkspaceStepUpAction, type WorkspaceDeviceScope } from "@mehen/protocol"
import { newDeviceKey, publicJwk } from "../devices.ts"
import type { InboxItem, InboxResponse } from "@mehen/protocol/inbox"
import { interceptInbox } from "./inbox-intercept.ts"
import { assertion } from "./passkeys.ts"
import { protectedJourney } from "./protected-journey.ts"
import { body, workJourney } from "./workspace-journey.ts"
import { appGate, googleFlow, googleRule, linkGoogle, nativeSession, setGoogleRule, webGate } from "./oidc-journey.ts"
let google: Awaited<ReturnType<typeof fakeGoogle>>
beforeEach(async () => { google = await fakeGoogle(); setOidcFetchForTest(google.fetcher) })
afterEach(() => setOidcFetchForTest(null))
async function gatedJourney() { const f = await workJourney(); await linkGoogle(f,google); await setGoogleRule(f,google); return f }
describe("oidc-gate authoritative admission through worker.fetch", () => {
  it("owner-only exact rule enable re-gates the next root request, then a fresh gate restores it", async () => {
    const f = await gatedJourney()
    const refused = await f.request(`/api/w/${f.work.slug}`,f.alex)
    expect(refused.status).toBe(403); expect(await refused.json()).toMatchObject({ error: "identity_required",next: { say: "Verify with Google, then confirm any change with your passkey." } })
    await webGate(f,google)
    expect(await body(await f.request(`/api/w/${f.work.slug}`,f.alex))).toEqual(f.work)
    const saved = await f.snapshot(f.work)
    expect((await f.request(`/api/w/${f.work.slug}/identity-rule`,f.alex,{ rule: googleRule })).status).toBe(400)
    expect(await f.snapshot(f.work)).toEqual(saved)
    expect((await f.request("/api/w/unknown",f.alex)).status).toBe(404)
  })
  it("ordinary admitted reads do not re-gate with time, but covered widening at twelve hours refuses", async () => {
    const f = await gatedJourney(); await webGate(f,google)
    const old = Date.now()-43200000
    await f.db.prepare("UPDATE session_identity_checks SET succeeded_at=? WHERE workspace=?").bind(old,f.work.id).run()
    await f.sql(f.work,"UPDATE workspace_identity_checks SET value=json_set(value,'$.succeededAt',?)",new Date(old).toISOString())
    // Inject only evidence age, consistently in D1 and DO, as if twelve hours passed.
    expect((await f.request(`/api/w/${f.work.slug}`,f.alex)).status).toBe(200)
    expect((await f.request(`/api/w/${f.work.slug}/members`,f.alex)).status).toBe(200)
    const result = await f.request(`/api/w/${f.work.slug}/stepup/start`,f.alex,{ action: { type: "workspace.update",name: "Renamed",slug: f.work.slug } })
    expect(result.status).toBe(403); expect(await result.json()).toMatchObject({ error: "identity_required" })
  })
  it("a passkey grace window does not pass the identity gate: covered widening at twelve hours still refuses", async () => {
    const f = await gatedJourney(); await webGate(f,google)
    f.env.STEPUP_GRACE = "on"
    const renamed = { type: "workspace.update" as const,name: "Renamed",slug: f.work.slug }
    expect(await body(await f.signed(`/api/w/${f.work.slug}/settings`,f.alex,{ change: "name",name: "Renamed" },renamed,f.work.slug))).toMatchObject({ workspace: { name: "Renamed" } })
    const again = { type: "workspace.update" as const,name: "Again",slug: f.work.slug }
    expect(await body(await f.request(`/api/w/${f.work.slug}/stepup/start`,f.alex,{ action: again }))).toHaveProperty("grace")
    const old = Date.now()-43200000
    await f.db.prepare("UPDATE session_identity_checks SET succeeded_at=? WHERE workspace=?").bind(old,f.work.id).run()
    await f.sql(f.work,"UPDATE workspace_identity_checks SET value=json_set(value,'$.succeededAt',?)",new Date(old).toISOString())
    const result = await f.request(`/api/w/${f.work.slug}/stepup/start`,f.alex,{ action: again })
    expect(result.status).toBe(403); expect(await result.json()).toMatchObject({ error: "identity_required" })
  })
  it("changed rules, reversed evidence and replayed results cannot install stale authority", async () => {
    const f = await gatedJourney(); await webGate(f,google)
    const older = await googleFlow(f,google,f.alex,{ purpose: "gate",workspace: f.work.slug }),newer = await googleFlow(f,google,f.alex,{ purpose: "gate",workspace: f.work.slug })
    expect((await f.request("/api/auth/oidc/google/gate",f.alex,{ result: newer.id },{ cookie: `${f.alex.cookie}; ${newer.cookie}` })).status).toBe(200)
    expect((await f.request("/api/auth/oidc/google/gate",f.alex,{ result: older.id },{ cookie: `${f.alex.cookie}; ${older.cookie}` })).status).toBe(403)
    expect((await f.request("/api/auth/oidc/google/gate",f.alex,{ result: newer.id },{ cookie: `${f.alex.cookie}; ${newer.cookie}` })).status).toBe(403)
    const pending = await googleFlow(f,google,f.alex,{ purpose: "gate",workspace: f.work.slug })
    await setGoogleRule(f,google,{ ...googleRule,domains: ["northwind.example","example.com"] })
    expect((await f.request("/api/auth/oidc/google/gate",f.alex,{ result: pending.id },{ cookie: `${f.alex.cookie}; ${pending.cookie}` })).status).toBe(403)
    expect((await f.request(`/api/w/${f.work.slug}`,f.alex)).status).toBe(403)
  })
  it("provider outage refuses new admission but leaves admitted sessions and enrolled machines unchanged", async () => {
    const f = await workJourney(),machine = await f.machine(f.alex,f.work)
    await linkGoogle(f,google); await setGoogleRule(f,google); await webGate(f,google)
    const pending = await f.request("/api/auth/oidc/google/start",f.alex,{ purpose: "gate",workspace: f.work.slug }),cookie = pending.headers.get("set-cookie")!.split(";")[0]!,{ url } = await body<{ url: string }>(pending),authorised = google.authorise(url)
    google.faults.unavailable = true
    expect((await f.request(`/auth/oidc/google/callback?${new URLSearchParams(authorised)}`,undefined,undefined,{ cookie: `${f.alex.cookie}; ${cookie}` })).status).toBe(403)
    expect((await f.request(`/api/w/${f.work.slug}`,f.alex)).status).toBe(200)
    expect((await f.deviceCall(machine,"/v1/me")).status).toBe(200)
    await f.signin(f.alex)
    expect((await f.request(`/api/w/${f.work.slug}`,f.alex)).status).toBe(403)
  })
  it("an old admitted session cannot accept a machine without fresh exact-operation evidence", async () => {
    const f = await gatedJourney(); await webGate(f,google)
    const machine = await f.startMachine(f.work)
    expect((await f.acceptMachine(f.alex,f.work,machine,false)).status).toBe(403)
    const view = await body<{ scope: import("@mehen/protocol").WorkspaceDeviceScope; start: import("@mehen/protocol").EnrolStartContext }>(await f.request(`/api/w/${f.work.slug}/enrolments/${machine.started.code}`,f.alex))
    const action: WorkspaceStepUpAction = { type: "enrol.accept",workspace: f.work.id,enrolment: machine.started.enrolment,thumbprint: machine.thumbprint,account: f.alex.account,member: await f.member(f.alex,f.work),scope: { ...view.scope,privateCredentials: false },start: view.start }
    await webGate(f,google,f.alex,{ action })
    await body(await f.acceptMachine(f.alex,f.work,machine,false))
    expect(await f.db.prepare("SELECT consumed_at FROM operation_identity_checks WHERE purpose='acceptance'").first()).toEqual({ consumed_at: expect.any(Number) })
  })
  it("an uncovered caller's machine view is unchanged when another role is covered", async () => {
    const f = await workJourney(),machine = await f.startMachine(f.work),path = `/api/w/${f.work.slug}/enrolments/${machine.started.code}`
    const before = await body<{ actions: string[]; scope: unknown; requestedOwner: unknown }>(await f.request(path,f.alex))
    await linkGoogle(f,google); await setGoogleRule(f,google,{ ...googleRule,roles: ["admin"] })
    const after = await body<{ actions: string[]; scope: unknown; requestedOwner: unknown }>(await f.request(path,f.alex))
    expect(after.actions).toEqual(before.actions); expect(after.scope).toEqual(before.scope); expect(after.requestedOwner).toEqual(before.requestedOwner)
    expect(after.actions).toContain("accept")
  })
  it("covered promotion leaves the old role effective until a fresh qualifying gate", async () => {
    const f = await protectedJourney()
    await linkGoogle(f,google); await linkGoogle(f,google,f.tom,{ sub: "google-tom",email: "tom@northwind.example" })
    await setGoogleRule(f,google); await webGate(f,google); await webGate(f,google,f.tom,{}, { sub: "google-tom",email: "tom@northwind.example" })
    expect(await body(await f.memberChange(f.alex,f.work,f.tom.member!,"role","owner"))).toMatchObject({ role: "admin",pendingRole: "owner" })
    expect(await f.sql(f.work,"SELECT role,pending_role FROM members WHERE id=?",f.tom.member!)).toEqual([{ role: "admin",pending_role: "owner" }])
    expect((await f.request(`/api/w/${f.work.slug}`,f.tom)).status).toBe(403)
    const failed = await googleFlow(f,google,f.tom,{ purpose: "gate",workspace: f.work.slug },{ sub: "google-tom",email: "tom@other.test",hd: "other.test" })
    expect((await f.request("/api/auth/oidc/google/gate",f.tom,{ result: failed.id },{ cookie: `${f.tom.cookie}; ${failed.cookie}` })).status).toBe(403)
    expect(await f.sql(f.work,"SELECT role,pending_role FROM members WHERE id=?",f.tom.member!)).toEqual([{ role: "admin",pending_role: "owner" }])
    await webGate(f,google,f.tom,{}, { sub: "google-tom",email: "tom@northwind.example" })
    expect(await f.sql(f.work,"SELECT role,pending_role FROM members WHERE id=?",f.tom.member!)).toEqual([{ role: "owner",pending_role: null }])
  })
  it("F3: covered team-owned widening needs fresh device.rescope evidence, not just session admission", async () => {
    const f = await gatedJourney(); await webGate(f,google)
    // Approved prerequisite only: the team HTTP routes belong to UI-PEOPLE.
    // It grants no member or machine authority; every operation below is HTTP.
    const member = await f.member(f.alex,f.work),team = "tm_oidc_service"
    await f.sql(f.work,"INSERT INTO teams(id,slug,name,created_by,created_at) VALUES (?,'oidc-service','Service',?,?)",team,member,Date.now())
    const keys = await newDeviceKey(),jwk = await publicJwk(keys),input = { workspace: f.work.slug,owner: { kind: "team",team },name: "Team machine",backend: "software",jwk }
    const proof = await createProof(webCryptoSigner("new",keys.privateKey),{ method: "POST",url: `${f.env.VAULT_ORIGIN}/v1/enrol`,body: JSON.stringify(input) },{ tenant: "enrol" })
    const started = await body<{ enrolment: string; code: string }>(await f.request("/v1/enrol",undefined,input,{ "Mehen-Proof": proof }),201),base = `/api/w/${f.work.slug}/enrolments/${started.code}`
    const view = await body<{ digest: string; scope: WorkspaceDeviceScope }>(await f.request(base,f.alex)),owner = { kind: "team" as const,team,name: "Service" },action: WorkspaceStepUpAction = { type: "enrol.approve",enrolment: started.enrolment,digest: view.digest,owner,admissionRole: "owner" }
    await webGate(f,google,f.alex,{ action })
    const thumbprint = await jwkThumbprint(jwk),group = fingerprintGroups(fingerprintOf(thumbprint))[await fingerprintGroupIndex(started.code)]!
    await body(await f.signed(`${base}/admit`,f.alex,{ group },action,f.work.slug))
    const active = await body<{ device: string; scope: WorkspaceDeviceScope }>(await f.deviceCall({ keys,device: started.enrolment,workspace: f.work },`/v1/enrol/${started.enrolment}`,undefined,"enrol"))
    const devicePath = `/api/w/${f.work.slug}/devices/${active.device}`,after = { ...active.scope,maxEnvironment: "protected" as const }
    const planned = await body<{ action: WorkspaceStepUpAction }>(await f.request(`${devicePath}/action`,f.alex,{ change: { kind: "rescope_propose",before: active.scope,after } }))
    const before = await f.snapshot(f.work)
    expect((await f.signed(`${devicePath}/rescope`,f.alex,{ before: active.scope,after },planned.action,f.work.slug)).status).toBe(403)
    expect(await f.snapshot(f.work)).toEqual(before)
    await webGate(f,google,f.alex,{ action: planned.action })
    expect(await body(await f.signed(`${devicePath}/rescope`,f.alex,{ before: active.scope,after },planned.action,f.work.slug))).toMatchObject({ state: "committed" })
    expect(await body(await f.deviceCall({ keys,device: active.device,workspace: f.work },"/v1/me"))).toMatchObject({ scope: after })
  })
  it("F4: a promoter demoted during consent cannot activate the pending role", async () => {
    const f = await protectedJourney(),noor = await f.guest(f.alex,f.work,f.project.id,"Noor")
    await body(await f.memberChange(f.alex,f.work,noor.member!,"role","owner"))
    await linkGoogle(f,google); await linkGoogle(f,google,f.tom,{ sub: "google-tom",email: "tom@northwind.example" })
    await setGoogleRule(f,google); await webGate(f,google)
    expect(await body(await f.memberChange(f.alex,f.work,f.tom.member!,"role","owner"))).toMatchObject({ role: "admin",pendingRole: "owner" })
    const pending = await googleFlow(f,google,f.tom,{ purpose: "gate",workspace: f.work.slug },{ sub: "google-tom",email: "tom@northwind.example" })
    await body(await f.memberChange(f.alex,f.work,await f.member(f.alex,f.work),"role","member"))
    const response = await f.request("/api/auth/oidc/google/gate",f.tom,{ result: pending.id },{ cookie: `${f.tom.cookie}; ${pending.cookie}` })
    expect(response.status).toBe(409)
    expect(await response.json()).toEqual({ error: "conflict",message: "This pending promotion is no longer available." })
    expect(await f.sql(f.work,"SELECT role,pending_role FROM members WHERE id=?",f.tom.member!)).toEqual([{ role: "admin",pending_role: null }])
  })
  it("unlink invalidates existing sessions before completing and an in-flight check cannot restore them", async () => {
    const f = await gatedJourney(); await webGate(f,google)
    const pending = await googleFlow(f,google,f.alex,{ purpose: "gate",workspace: f.work.slug }),identity = await f.db.prepare("SELECT id FROM oidc_identities WHERE account=?").bind(f.alex.account).first<{ id: string }>()
    expect(await body(await f.signed(`/api/account/identities/${identity!.id}/unlink`,f.alex,{}, { type: "identity.unlink",provider: "google",identity: identity!.id }))).toEqual({ pending: false })
    expect(await f.db.prepare("SELECT id FROM oidc_identities WHERE id=?").bind(identity!.id).first()).toBeNull()
    expect((await f.request(`/api/w/${f.work.slug}`,f.alex)).status).toBe(403)
    expect((await f.request("/api/auth/oidc/google/gate",f.alex,{ result: pending.id },{ cookie: `${f.alex.cookie}; ${pending.cookie}` })).status).toBe(403)
  })
})
describe("native gate hand-off through worker.fetch", () => {
  it("cookie evidence is insufficient; PKCE and the exact bearer admit the app, with one redemption winner", async () => {
    const f = await gatedJourney(); await webGate(f,google)
    const app = await nativeSession(f)
    expect((await f.request("/app/v1/pending",f.alex)).status).toBe(401)
    expect((await f.request(`/app/v1/w/${f.work.slug}/approvals/absent/decide`,undefined,{ decision: "approve",stepUp: { nonce: "none",assertion: {} } },app.headers)).status).toBe(403)
    expect((await f.request("/app/v1/pending",undefined,undefined,app.headers)).status).toBe(403)
    expect((await f.request(`/app/v1/w/${f.work.slug}/approvals/absent`,undefined,undefined,app.headers)).status).toBe(403)
    const handoff = await appGate(f,google,app)
    expect(handoff.callback.status).toBe(303); expect(handoff.callback.headers.get("location")).toMatch(/^https:\/\/vault.test\/app\/v1\/gate\/callback#code=/)
    expect((await f.request("/app/v1/gate",undefined,{ code: handoff.code,verifier: "wrong".padEnd(64,"x") },app.headers)).status).toBe(403)
    const other = await nativeSession(f)
    expect((await f.request("/app/v1/gate",undefined,{ code: handoff.code,verifier: handoff.verifier },other.headers)).status).toBe(403)
    const outcomes = await Promise.all([f.request("/app/v1/gate",undefined,{ code: handoff.code,verifier: handoff.verifier },app.headers),f.request("/app/v1/gate",undefined,{ code: handoff.code,verifier: handoff.verifier },app.headers)])
    expect(outcomes.filter(response => response.status === 200)).toHaveLength(1)
    expect((await f.request("/app/v1/pending",undefined,undefined,app.headers)).status).toBe(200)
    expect((await f.request("/app/v1/gate",undefined,{ code: handoff.code,verifier: handoff.verifier },app.headers)).status).toBe(403)
    expect((await f.request(`/app/v1/w/not-a-workspace/approvals/absent`,undefined,undefined,app.headers)).status).toBe(404)
    const hash = await sha256Text(app.token)
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM session_identity_checks c JOIN web_sessions s ON s.id=c.session WHERE s.token_hash=? AND c.session_kind='app'").bind(hash).first()).toEqual({ n: 1 })
  })
  it("a gated app views and approves a real protected ask with exact native passkey proof", async () => {
    const f = await protectedJourney()
    await linkGoogle(f,google); await linkGoogle(f,google,f.tom,{ sub: "google-tom",email: "tom@northwind.example" })
    await setGoogleRule(f,google); await webGate(f,google)
    const app = await nativeSession(f,f.tom),approval = await f.askRun()
    expect((await f.request(`/app/v1/w/${f.work.slug}/approvals/${approval}`,undefined,undefined,app.headers)).status).toBe(403)
    const handoff = await appGate(f,google,app,{ sub: "google-tom",email: "tom@northwind.example" })
    expect(handoff.callback.status).toBe(303)
    expect((await f.request("/app/v1/gate",undefined,{ code: handoff.code,verifier: handoff.verifier },app.headers)).status).toBe(200)
    const view = await body<WorkspaceApprovalView>(await f.request(`/app/v1/w/${f.work.slug}/approvals/${approval}`,undefined,undefined,app.headers))
    if (view.view !== "detail") throw new Error("Eligible app decider did not receive detail")
    expect(view.approval.workspace).toEqual(f.work)
    const action: WorkspaceStepUpAction = { type: "approval.decide",approval,digest: view.approval.digest,decision: "approve",constraints: view.approval.constraints }
    async function proof(input = action) { const start = await body<{ nonce: string; options: { challenge: string } }>(await f.request("/app/v1/stepup",undefined,{ scope: f.work.id,action: input },app.headers)); return { nonce: start.nonce,assertion: await assertion(f.tom.passkey,start.options.challenge,++f.tom.counter) } }
    const wrong = await proof({ ...action,digest: "wrong-digest" })
    expect((await f.request(`/app/v1/w/${f.work.slug}/approvals/${approval}/decide`,undefined,{ decision: "approve",stepUp: wrong },app.headers)).status).toBe(403)
    expect(await f.sql(f.work,"SELECT status FROM approvals WHERE id=?",approval)).toEqual([{ status: "pending" }])
    const beforeRemember = await f.snapshot(f.work)
    const remembered = await f.request(`/app/v1/w/${f.work.slug}/approvals/${approval}/decide`,undefined,{ decision: "approve",remember: { kind: "exact",selector: { device: view.approval.requestedBy.device,session: null } },stepUp: wrong },app.headers)
    expect(remembered.status).toBe(403)
    expect(await remembered.json()).toEqual({ error: "forbidden",message: "Remembered approvals need the vault page, not the app route." })
    expect(await f.snapshot(f.work)).toEqual(beforeRemember)
    expect((await f.request(`/app/v1/w/${f.work.slug}/approvals/${approval}/decide`,undefined,{ decision: "approve",constraints: { ...view.approval.constraints,ttlSeconds: view.approval.constraints.ttlSeconds+1 },stepUp: wrong },app.headers)).status).toBe(400)
    expect((await f.request(`/app/v1/w/${f.work.slug}/approvals/${approval}/decide`,undefined,{ decision: "approve",stepUp: await proof() },app.headers)).status).toBe(200)
    expect(await f.sql(f.work,"SELECT status FROM approvals WHERE id=?",approval)).toEqual([{ status: "approved" }])
    await f.run(approval)
  })
  it("Needs you shows a gated workspace as gated with no rows until its check passes; the app read refuses it whole until its own gate", async () => {
    const f = await gatedJourney(),start = await f.startMachine(f.work)
    const gated = await body<InboxResponse>(await f.request("/api/needs-you",f.alex))
    expect(gated.workspaces).toEqual([{ workspace: f.work,role: null,state: "gated",reason: null,count: null,truncated: false },{ workspace: f.personal,role: "owner",state: "ok",reason: null,count: 0,truncated: false }])
    expect(gated).toMatchObject({ items: [],count: 0,complete: false })
    expect(JSON.stringify(gated)).not.toContain(start.started.enrolment)
    expect(await body(await f.request(`/api/w/${f.work.slug}/inbox`,f.alex))).toEqual({ workspace: gated.workspaces[0],items: [],notices: [] })
    await webGate(f,google)
    const open = await body<InboxResponse>(await f.request("/api/needs-you",f.alex))
    expect(open).toMatchObject({ count: 1,complete: true })
    expect(open.items.map(item => item.kind === "enrol" && item.enrol.enrolment)).toEqual([start.started.enrolment])
    // The web gate is not the app's: the app read still refuses, never answering without the workspace.
    const app = await nativeSession(f)
    expect((await f.request("/app/v1/pending",undefined,undefined,app.headers)).status).toBe(403)
    const handoff = await appGate(f,google,app)
    expect((await f.request("/app/v1/gate",undefined,{ code: handoff.code,verifier: handoff.verifier },app.headers)).status).toBe(200)
    const listed = await body<{ pending: unknown[]; notices: unknown[]; inbox: InboxItem[] }>(await f.request("/app/v1/pending",undefined,undefined,app.headers))
    expect(listed.pending).toEqual([])
    expect(listed.inbox.map(item => item.kind === "enrol" && item.enrol.enrolment)).toEqual([start.started.enrolment])
  })
  it("a gate invalidated between the Worker's reads and the workspace's read gates the group, and the old validator earns no 304", async () => {
    const f = await gatedJourney(),start = await f.startMachine(f.work)
    await webGate(f,google)
    const open = await f.request("/api/needs-you",f.alex),tag = open.headers.get("etag")!
    expect((await body<InboxResponse>(open)).items.map(item => item.kind === "enrol" && item.enrol.enrolment)).toEqual([start.started.enrolment])
    const restore = interceptInbox(f,async (workspace,_invocation,proceed) => {
      if (workspace === f.work.id) { restore(); await setGoogleRule(f,google,{ ...googleRule,domains: ["northwind.example","example.com"] }) }
      return proceed()
    })
    const changed = await f.request("/api/needs-you",f.alex,undefined,{ "if-none-match": tag })
    restore()
    expect(changed.status).toBe(200)
    expect(changed.headers.get("etag")).not.toBe(tag)
    const gated = await body<InboxResponse>(changed)
    expect(gated.workspaces[0]).toEqual({ workspace: f.work,role: null,state: "gated",reason: null,count: null,truncated: false })
    expect(gated).toMatchObject({ items: [],count: 0,complete: false })
    expect(JSON.stringify(gated)).not.toContain(start.started.enrolment)
    expect((await f.request("/api/needs-you",f.alex,undefined,{ "if-none-match": tag })).status).toBe(200)
  })
  it("a victim's Google identity in an attacker-started app flow yields no usable code or link", async () => {
    const f = await gatedJourney(),app = await nativeSession(f),before = await f.db.prepare("SELECT id FROM oidc_identities").all(),handoff = await appGate(f,google,app,{ sub: "victim-subject",email: "victim@northwind.example" })
    expect(handoff.callback.status).toBe(403); expect(handoff.code).toBe("")
    expect(await f.db.prepare("SELECT id FROM oidc_identities").all()).toMatchObject({ results: before.results })
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM app_gate_codes").first()).toEqual({ n: 0 })
  })
  it.each(["expiry","signout","rule","recovery"] as const)("refuses hand-off after %s", async kind => {
    const f = await gatedJourney(); await webGate(f,google)
    const app = await nativeSession(f),handoff = await appGate(f,google,app)
    if (kind === "expiry") { const now = Date.now(); await f.db.prepare("UPDATE app_gate_codes SET created_at=?,expires_at=?").bind(now-300001,now-1).run() }
    if (kind === "signout") expect((await f.request("/app/v1/session/end",undefined,{},app.headers)).status).toBe(200)
    if (kind === "rule") await setGoogleRule(f,google,{ ...googleRule,domains: ["northwind.example","example.com"] })
    if (kind === "recovery") expect((await f.request("/api/auth/recovery",undefined,{ code: f.alex.codes[0] })).status).toBe(200)
    const response = await f.request("/app/v1/gate",undefined,{ code: handoff.code,verifier: handoff.verifier },app.headers)
    expect([401,403]).toContain(response.status)
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM session_identity_checks WHERE session_kind='app'").first()).toEqual({ n: 0 })
  })
})
