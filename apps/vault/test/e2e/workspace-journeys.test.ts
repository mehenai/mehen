import { afterEach, describe, expect, it } from "vitest"
import { setUpstreamFetch } from "../../src/relay/upstream.ts"
import { acceptedScope, expectedMember, body, journey, refusal, workJourney } from "./workspace-journey.ts"
import type { InviteTerms, WorkspaceStepUpAction } from "@mehen/protocol"

afterEach(() => setUpstreamFetch(null))

describe("real Worker workspace journeys", () => {
  it("bootstrap: operator invite, real passkey, required recovery and Personal", async () => {
    const f = await journey()
    const create = { slug: "alex", name: "Personal" }
    await refusal(await f.signed("/api/workspaces", f.alex, create, { type: "workspace.create", ...create }), 403, { error: "forbidden", message: "Set up account recovery before activation.", next: { url: "https://vault.test/account", say: "Save recovery codes or add a second passkey before activating a membership." } })
    expect((await f.db.prepare("SELECT * FROM workspaces").all()).results).toEqual([])
    await f.recoverySetup(f.alex)
    const personal = await f.createWorkspace(f.alex, "alex", "Personal")
    expect(await body(await f.request("/api/w/alex", f.alex))).toEqual(personal)
    expect(await f.sql(personal, "SELECT account,role,status FROM members")).toEqual([{ account: f.alex.account, role: "owner", status: "active" }])
    const accountPage = await f.request("/account", f.alex, undefined, { accept: "text/html" })
    expect(accountPage.status).toBe(200)
    expect(await accountPage.text()).toContain("Personal")
    const unknown = await f.request("/unknown-html", f.alex, undefined, { accept: "text/html" })
    const hidden = await f.request("/w/unknown/", f.alex, undefined, { accept: "text/html" })
    expect(unknown.status).toBe(404)
    expect(await unknown.text()).toBe(await hidden.text())
    expect((await f.request("/settings", f.alex)).headers.get("location")).toBe("/w/alex/")
  })

  it("invites: email-bound member refusal, open guest redemption, confirmation and promotion", async () => {
    const f = await workJourney()
    const terms: InviteTerms = { role: "member", email: "tom@northwind.example", teams: [], shares: [], expiresAt: new Date(Date.now() + 86400000).toISOString() }
    const bound = await f.invite(f.alex, f.work, terms)
    await refusal(await f.request("/api/auth/signup/options", undefined, { invite: bound.code, name: "Tom" }), 403, { error: "identity_required", message: "Prove the invited email before joining.", next: { url: "/signup", say: "Verify the invited email with Google, then continue." } })
    await refusal(await f.request("/api/account/invites/join", f.alex, { code: bound.code }), 403, { error: "identity_required", message: "Prove the invited email before joining.", next: { url: "/signup", say: "Verify the invited email with Google, then continue." } })
    const invalid = { ...terms, email: null }
    expect((await f.request("/api/w/northwind/invites", f.alex, { terms: invalid, email: false })).status).toBe(400)
    const tom = await f.guest(f.alex, f.work, f.project.id, "Tom", false)
    for (const change of ["suspend", "reinstate"]) {
      await refusal(await f.request(`/api/w/northwind/members/${tom.member}/action`, f.alex, { change }), 409, { error: "conflict", message: "This membership cannot be confirmed this way." })
      await refusal(await f.request(`/api/w/northwind/members/${tom.member}/${change}`, f.alex, {}), 409, { error: "conflict", message: "This membership cannot be confirmed this way." })
      expect(await f.sql(f.work, "SELECT status FROM members WHERE id=?", tom.member!)).toEqual([{ status: "unconfirmed" }])
    }
    expect(await body(await f.memberChange(f.alex, f.work, tom.member!, "confirm"))).toEqual(expectedMember(tom.member!, "Tom", "guest"))
    expect(await body(await f.memberChange(f.alex, f.work, tom.member!, "role", "admin"))).toEqual(expectedMember(tom.member!, "Tom", "admin"))
    expect(await f.sql(f.work, "SELECT account,role,status FROM members WHERE id=?", tom.member!)).toEqual([{ account: tom.account, role: "admin", status: "active" }])
  })

  it("machine: real CLI-shaped signed enrolment, private tick, active poll and guest admission", async () => {
    const f = await workJourney()
    const machine = await f.machine(f.alex, f.work)
    expect(await body(await f.deviceCall(machine, "/v1/me"))).toEqual(await f.expectedMachineStatus(f.alex, machine))
    expect(await body(await f.deviceCall(machine, "/v1/pending"))).toEqual({ pending: [], notices: [{ id: expect.stringMatching(/^ntc_/), account: f.alex.account, payload: { kind: "machine_added", workspace: f.work, device: machine.device, name: "integration-machine", owner: { kind: "member", member: await f.member(f.alex, f.work), name: "Alex" }, place: null, at: expect.any(String) }, at: expect.any(Number), url: `https://vault.test/w/northwind/devices/${machine.device}` }] })
    const guest = await f.guest(f.alex, f.work, f.project.id, "Guest")
    const start = await f.startMachine(f.work)
    const accepted = await body<{ state: string; digest: string; owner: import("@mehen/protocol").OwnerRef }>(await f.acceptMachine(guest, f.work, start, false))
    expect(accepted).toEqual(await f.expectedEnrol(guest, f.work, start, "pending_admission", false))
    const polling = { workspace: f.work, keys: start.keys, device: start.started.enrolment }
    const before = await f.snapshot(f.work)
    const self: WorkspaceStepUpAction = { type: "enrol.approve", enrolment: start.started.enrolment, digest: accepted.digest, owner: accepted.owner, admissionRole: "guest" }
    await refusal(await f.signed(`/api/w/northwind/enrolments/${start.started.code}/admit`, guest, { group: start.group, project: f.project.id }, self, "northwind"), 403, { error: "forbidden", message: "This enrolment needs an eligible insider admission." })
    expect(await f.snapshot(f.work)).toEqual(before)
    expect(await body(await f.deviceCall(polling, `/v1/enrol/${start.started.enrolment}`, undefined, "enrol"))).toEqual({ status: "pending_admission", expiresAt: expect.any(String), hardExpiresAt: expect.any(String) })
    const peer = await f.guest(f.alex, f.work, f.project.id, "Peer")
    await body(await f.memberChange(f.alex, f.work, peer.member!, "role", "member"))
    const peerAction: WorkspaceStepUpAction = { ...self, admissionRole: "member" }
    const peerBefore = await f.snapshot(f.work)
    await refusal(await f.signed(`/api/w/northwind/enrolments/${start.started.code}/admit`, peer, { group: start.group, project: f.project.id }, peerAction, "northwind"), 403, { error: "forbidden", message: "This enrolment needs an eligible insider admission." })
    expect(await f.snapshot(f.work)).toEqual(peerBefore)
    const action: WorkspaceStepUpAction = { type: "enrol.approve", enrolment: start.started.enrolment, digest: accepted.digest, owner: accepted.owner, admissionRole: "owner" }
    expect(await body(await f.signed(`/api/w/northwind/enrolments/${start.started.code}/admit`, f.alex, { group: start.group, project: f.project.id }, action, "northwind"))).toEqual(await f.expectedEnrol(guest, f.work, start, "active", false))
    expect(await body(await f.deviceCall(polling, `/v1/enrol/${start.started.enrolment}`, undefined, "enrol"))).toEqual({ status: "active", tenant: f.work.id, workspace: f.work, device: expect.stringMatching(/^dev_/), owner: { kind: "member", member: guest.member, name: "Guest" }, scope: acceptedScope(false) })
  })

  it("credentials: project and workspace intake, real signed relay, hidden bytes and guest asks", async () => {
    const f = await workJourney(), machine = await f.machine(f.alex, f.work)
    await f.credential(f.alex, f.work, "project-key", { kind: "project", project: f.project.id })
    await f.credential(f.alex, f.work, "workspace-key", { kind: "workspace" })
    let sends = 0
    setUpstreamFetch(async request => { sends++; expect(request.headers.get("authorization")).toBe("Bearer sk-integration-not-a-real-secret"); return new Response("fake-upstream") })
    const relay = (slug: string) => f.deviceCall(machine, "/v1/relay", { item: slug, method: "GET", url: "https://api.openai.com/v1/models", headers: [] })
    expect(await (await relay("project-key")).text()).toBe("fake-upstream")
    const guest = await f.guest(f.alex, f.work, f.project.id, "Guest")
    const absent = await relay("hidden-key"), absentBytes = await absent.text()
    expect(absent.status).toBe(404)
    await f.credential(guest, f.work, "hidden-key", { kind: "member", member: guest.member! })
    const hidden = await relay("hidden-key")
    expect(hidden.status).toBe(404)
    expect(await hidden.text()).toBe(absentBytes)
    expect(sends).toBe(1)
    const own = await body<{ intake: string }>(await f.request("/api/w/northwind/intakes", guest, { provider: "openai", slug: "guest-ask", home: "private" }), 201)
    const foreign = await body<{ intake: string }>(await f.request("/api/w/northwind/intakes", f.alex, { provider: "openai", slug: "owner-ask", home: "project", project: f.project.id }), 201)
    const pending = await body<{ pending: { detail: { id: string } }[]; notices: unknown[] }>(await f.request("/api/w/northwind/pending", guest))
    expect(pending.pending.map(entry => entry.detail.id)).toEqual([own.intake])
    expect(pending).toEqual({ pending: [{ view: "detail", workspace: f.work, owner: { kind: "member", member: guest.member, name: "Guest" }, detail: { kind: "intake", id: own.intake, title: "Add guest-ask", url: `https://vault.test/w/northwind/i/${own.intake}`, expiresAt: expect.any(String), requestedBy: { member: guest.member, self: true }, item: "guest-ask", provider: "openai", kindRequested: "api-key", createdAt: expect.any(String) } }], notices: [] })
    const a = await f.request(`/api/w/northwind/intakes/${foreign.intake}`, guest), b = await f.request("/api/w/northwind/intakes/int_absent12345", guest)
    expect(a.status).toBe(404)
    expect(await a.text()).toBe(await b.text())
  })
})
