import { afterEach, beforeEach, describe, expect, it } from "vitest"
import type { WorkspaceStepUpAction } from "@mehen/protocol"
import { setOidcFetchForTest } from "../../src/directory/oidc.ts"
import { fakeGoogle } from "../oidc-google.ts"
import { body, workJourney } from "./workspace-journey.ts"
import { googleFlow, googleRule, linkGoogle, setGoogleRule, webGate } from "./oidc-journey.ts"
let google: Awaited<ReturnType<typeof fakeGoogle>>
beforeEach(async () => { google = await fakeGoogle(); setOidcFetchForTest(google.fetcher) })
afterEach(() => setOidcFetchForTest(null))

describe("Google sign-in account and caller evidence regressions", () => {
  it.each(["signout","everywhere"] as const)("pending unlink commits after %s and permits a later recovery", async mode => {
    const f = await workJourney(); await linkGoogle(f,google); await setGoogleRule(f,google); await webGate(f,google)
    const identity = await f.db.prepare("SELECT id FROM oidc_identities WHERE account=?").bind(f.alex.account).first<{ id: string }>()
    const generation = (await f.sql<{ gate_generation: number }>(f.work,"SELECT gate_generation FROM members WHERE account=?",f.alex.account))[0]!.gate_generation
    f.faults.blockWorkspace = f.work.id
    expect(await body(await f.signed(`/api/account/identities/${identity!.id}/unlink`,f.alex,{}, { type: "identity.unlink",provider: "google",identity: identity!.id }))).toEqual({ pending: true })
    const pending = await f.db.prepare("SELECT security_transition FROM accounts WHERE id=?").bind(f.alex.account).first<{ security_transition: string }>()
    expect((await f.request(mode === "signout" ? "/api/auth/signout" : "/api/account/sessions/end-all",f.alex,{})).status).toBe(200)
    f.faults.blockWorkspace = ""
    // Advance only the retry schedule, as if the next maintenance minute arrived.
    await f.db.prepare("UPDATE account_security_transitions SET next_retry_at=0 WHERE id=?").bind(pending!.security_transition).run()
    await f.cron()
    expect(await f.db.prepare("SELECT state FROM account_security_transitions WHERE id=?").bind(pending!.security_transition).first()).toEqual({ state: "committed" })
    expect(await f.db.prepare("SELECT id FROM oidc_identities WHERE id=?").bind(identity!.id).first()).toBeNull()
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM web_sessions WHERE account=?").bind(f.alex.account).first()).toEqual({ n: 0 })
    expect(await f.sql(f.work,"SELECT gate_generation FROM members WHERE account=?",f.alex.account)).toEqual([{ gate_generation: generation+1 }])
    expect(await f.sql(f.personal,"SELECT gate_generation FROM members WHERE account=?",f.alex.account)).toEqual([{ gate_generation: 1 }])
    const recovery = await f.request("/api/auth/recovery",undefined,{ code: f.alex.codes[0] })
    expect(recovery.status).toBe(200); expect(await recovery.json()).toMatchObject({ pending: false })
    expect(await f.db.prepare("SELECT security_transition FROM accounts WHERE id=?").bind(f.alex.account).first()).toEqual({ security_transition: null })
  })

  it("a gated covered owner keeps the full projects, credentials, homes, pending and override views", async () => {
    const f = await workJourney(),member = await f.member(f.alex,f.work)
    await f.credential(f.alex,f.work,"view-key",{ kind: "workspace" })
    await f.credential(f.alex,f.work,"own-key",{ kind: "member",member })
    await body(await f.projectMutation(f.alex,f.work,"variable",{ project: f.project.id,name: "TOKEN",env: "dev",item: "view-key",field: "key",before: null },`/projects/${f.project.id}/vars/TOKEN`))
    const override = { environment: "dev",variable: "TOKEN",source: { kind: "item",item: "own-key",field: "key" } },overridePath = `/api/w/${f.work.slug}/projects/${f.project.id}/overrides`
    const action = await body<WorkspaceStepUpAction>(await f.request(`${overridePath}/action`,f.alex,override))
    await body(await f.signed(overridePath,f.alex,override,action,f.work.slug))
    const intake = await body<{ intake: string }>(await f.request(`/api/w/${f.work.slug}/intakes`,f.alex,{ provider: "openai",slug: "pending-key",home: "workspace" }),201)
    const paths = ["/projects",`/projects/${f.project.id}`,"/items","/items/own-key",`/intakes/${intake.intake}`,"/pending",`/projects/${f.project.id}/overrides`]
    const baseline = await Promise.all(paths.map(path => f.request(`/api/w/${f.work.slug}${path}`,f.alex).then(response => body(response))))
    await linkGoogle(f,google); await setGoogleRule(f,google)
    for (const path of paths) { const response = await f.request(`/api/w/${f.work.slug}${path}`,f.alex); expect(response.status).toBe(403); expect(await response.json()).toMatchObject({ error: "identity_required" }) }
    await webGate(f,google)
    for (let index=0;index<paths.length;index++) expect(await body(await f.request(`/api/w/${f.work.slug}${paths[index]}`,f.alex))).toEqual(baseline[index])
    expect(await body(await f.request(`${overridePath}/action`,f.alex,override))).toEqual(action)
    await f.credential(f.alex,f.work,"created-after-gate",{ kind: "workspace" })
  })

  it("an uncovered guest's project and private credential views stay unchanged", async () => {
    const f = await workJourney(),guest = await f.guest(f.alex,f.work,f.project.id,"Guest")
    await f.credential(guest,f.work,"guest-own",{ kind: "member",member: guest.member! })
    const paths = ["/projects",`/projects/${f.project.id}`,"/items","/items/guest-own","/pending"]
    const baseline = await Promise.all(paths.map(path => f.request(`/api/w/${f.work.slug}${path}`,guest).then(response => body(response))))
    await linkGoogle(f,google); await setGoogleRule(f,google)
    for (let index=0;index<paths.length;index++) expect(await body(await f.request(`/api/w/${f.work.slug}${paths[index]}`,guest))).toEqual(baseline[index])
    await f.credential(guest,f.work,"guest-new",{ kind: "member",member: guest.member! })
  })

  it("a same-session rejoin replaces the former member's sequence and never admits their stale D1 row", async () => {
    const f = await workJourney(),tom = await f.guest(f.alex,f.work,f.project.id,"Tom")
    await body(await f.memberChange(f.alex,f.work,tom.member!,"role","member"))
    await linkGoogle(f,google); await linkGoogle(f,google,tom,{ sub: "google-tom",email: "tom@northwind.example" })
    await setGoogleRule(f,google); await webGate(f,google)
    for (let n=0;n<5;n++) await webGate(f,google,tom,{}, { sub: "google-tom",email: "tom@northwind.example" })
    const previous = await f.db.prepare("SELECT id,session,member,sequence FROM session_identity_checks WHERE account=? AND workspace=?").bind(tom.account,f.work.id).first<{ id: string; session: string; member: string; sequence: number }>()
    expect(previous!.sequence).toBe(5)
    await body(await f.memberChange(f.alex,f.work,tom.member!,"remove"))
    const invite = await f.invite(f.alex,f.work,{ role: "member",email: "tom@northwind.example",teams: [],shares: [],expiresAt: new Date(Date.now()+86400000).toISOString() }),proof = await googleFlow(f,google,tom,{ purpose: "invite",invite: invite.code },{ sub: "google-tom",email: "tom@northwind.example" })
    const joined = await body<{ member: string }>(await f.request("/api/account/invites/join",tom,{ code: invite.code,oidcResult: proof.id },{ cookie: `${tom.cookie}; ${proof.cookie}` }))
    expect(joined.member).not.toBe(previous!.member)
    await body(await f.memberChange(f.alex,f.work,joined.member,"confirm"))
    expect(await f.db.prepare("SELECT member,sequence FROM session_identity_checks WHERE account=? AND workspace=?").bind(tom.account,f.work.id).first()).toEqual({ member: joined.member,sequence: 1 })
    expect((await f.request(`/api/w/${f.work.slug}`,tom)).status).toBe(200)
    // Inject the old member row with otherwise matching revision/generation.
    await f.db.prepare("UPDATE session_identity_checks SET id=?,member=?,sequence=? WHERE account=? AND workspace=?").bind(previous!.id,previous!.member,previous!.sequence,tom.account,f.work.id).run()
    for (const path of ["", "/projects"]) { const refused = await f.request(`/api/w/${f.work.slug}${path}`,tom); expect(refused.status).toBe(403); expect(await refused.json()).toMatchObject({ error: "identity_required" }) }
    await webGate(f,google,tom,{}, { sub: "google-tom",email: "tom@northwind.example" })
    expect(await f.db.prepare("SELECT member,sequence FROM session_identity_checks WHERE account=? AND workspace=?").bind(tom.account,f.work.id).first()).toEqual({ member: joined.member,sequence: 2 })
    expect((await f.request(`/api/w/${f.work.slug}`,tom)).status).toBe(200)
    expect((await f.request(`/api/w/${f.work.slug}/projects`,tom)).status).toBe(200)
  })
})
