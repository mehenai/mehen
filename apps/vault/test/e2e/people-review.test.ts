// People page regressions through the real Worker: a pending recovery
// waits honestly and finishes with the same code's ceremony; the last typed
// group still accepts; the bootstrap account is told it has nothing to
// join; a guest's wider scope goes through an insider; a team's admission
// and a guest's invitation name the workspace credentials they delegate;
// workspace creation is offered only where it would be allowed; a scope
// proposal is rejected and admitted through the machine page.
import { describe, expect, it } from "vitest"
import { createProof, fingerprintGroupIndex, fingerprintGroups, fingerprintOf, jwkThumbprint, webCryptoSigner, type TeamView, type WorkspaceDeviceScope, type WorkspaceRef, type WorkspaceStepUpAction } from "@mehen/protocol"
import { ORIGIN } from "../helpers.ts"
import { sha256Text } from "../../src/directory/session.ts"
import { newDeviceKey, publicJwk } from "../devices.ts"
import { RECOVERY_PENDING_HEADING } from "../../src/ui/pages/account-setup.ts"
import { body, refusal, workJourney, type Person } from "./workspace-journey.ts"
import { assertion, registration, softwarePasskey } from "./passkeys.ts"
import { type RescopeShown, rescopeRejectAction, rescopeSignBody } from "../../src/ui/client/people-logic.ts"

const HTML = { accept: "text/html" }

function bootOf(page: string): Record<string, unknown> {
  const raw = /data-boot="([^"]*)"/.exec(page)?.[1]
  if (raw === undefined) throw new Error("no boot payload")
  return JSON.parse(raw.replaceAll("&quot;", '"').replaceAll("&#39;", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&#96;", "`").replaceAll("&amp;", "&")) as Record<string, unknown>
}

function wrongGroup(group: string): string {
  return group === "2222" ? "3333" : "2222"
}

async function reviewJourney() {
  const f = await workJourney()
  const ui = (person: Person, workspace: WorkspaceRef, path: string, input?: unknown) => f.request(`/api/w/${workspace.slug}${path}`, person, input, { "Mehen-Workspace": workspace.id })
  const uiSigned = async (person: Person, workspace: WorkspaceRef, action: WorkspaceStepUpAction, path: string, input: Record<string, unknown>) => {
    const { nonce, options } = await body<{ nonce: string; options: { challenge: string } }>(await ui(person, workspace, "/stepup/start", { action }))
    return ui(person, workspace, path, { ...input, stepUp: { nonce, assertion: await assertion(person.passkey, options.challenge, ++person.counter) } })
  }
  const html = async (person: Person | { cookie: string } | undefined, path: string) => {
    const response = await f.request(path, person as Person | undefined, undefined, HTML)
    expect(response.status, path).toBe(200)
    return response.text()
  }
  return { ...f, ui, uiSigned, html }
}

describe("people page fixes through the Worker", () => {
  it("pending recovery: an honest waiting page, then the same ceremony registers a passkey without another code", async () => {
    const f = await reviewJourney()
    f.faults.blockInstall = true
    const started = await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[0] })
    const ceremony = { cookie: started.headers.get("set-cookie")!.split(";")[0]! }
    const { transition } = await body<{ pending: boolean; transition: string }>(started, 202)
    const waiting = await f.html(ceremony, "/recover/passkey")
    expect(bootOf(waiting)).toEqual({ page: "recover-pending" })
    expect(waiting).toContain(RECOVERY_PENDING_HEADING)
    expect(waiting).toContain("you&#39;ll be restricted until it completes")
    expect(waiting).not.toMatch(/15 minutes ran out|Use another code|data-form="recover-passkey"/)
    expect(await body(await f.request("/api/auth/recovery/status", ceremony as Person))).toEqual({ state: "pending" })
    // Pending grants nothing: no ceremony session, no registration.
    expect((await f.request("/api/auth/recovery/passkey/options", ceremony as Person, {})).status).toBe(401)
    // The workspace comes back; the due retry commits the same transition.
    f.faults.blockInstall = false
    await f.db.prepare("UPDATE account_security_transitions SET next_retry_at=0 WHERE id=?").bind(transition).run()
    await f.request("/api/auth/recovery/status", ceremony as Person)
    expect(await body(await f.request("/api/auth/recovery/status", ceremony as Person))).toEqual({ state: "live" })
    const ready = await f.html(ceremony, "/recover/passkey")
    expect(ready).toContain('data-form="recover-passkey"')
    const passkey = await softwarePasskey()
    const { options } = await body<{ options: { challenge: string } }>(await f.request("/api/auth/recovery/passkey/options", ceremony as Person, {}))
    const registered = await f.request("/api/auth/recovery/passkey/verify", ceremony as Person, { response: await registration(passkey, options.challenge), name: "Recovered" })
    expect(registered.status).toBe(200)
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM recovery_codes WHERE account=? AND status='used'").bind(f.alex.account).first()).toEqual({ n: 1 })
    // An unknown or spent ceremony says it has ended.
    expect(await body(await f.request("/api/auth/recovery/status", { cookie: "__Host-mehen_session=not-a-ceremony" } as Person))).toEqual({ state: "ended" })
    expect(await f.html({ cookie: "__Host-mehen_session=not-a-ceremony" }, "/recover/passkey")).toContain("15 minutes ran out")
  })

  it("pending recovery cancelled by an older factor has ended: no form, no session, before or after the cancel commits", async () => {
    const f = await reviewJourney()
    f.faults.blockInstall = true
    const started = await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[0] })
    const ceremony = { cookie: started.headers.get("set-cookie")!.split(";")[0]! } as Person
    const { transition } = await body<{ pending: boolean; transition: string }>(started, 202)
    expect(await body(await f.request("/api/auth/recovery/status", ceremony))).toEqual({ state: "pending" })
    const [notice] = (await f.db.prepare("SELECT id FROM account_notices WHERE account=? AND kind='recovery'").bind(f.alex.account).all<{ id: string }>()).results
    await f.signin(f.alex)
    const action: WorkspaceStepUpAction = { type: "recovery.resolve", notice: notice!.id, outcome: "cancel" }
    expect(await body(await f.signed(`/api/account/recovery/${notice!.id}/resolve`, f.alex, { outcome: "cancel" }, action))).toEqual({ pending: true })
    const ended = async () => {
      expect(await body(await f.request("/api/auth/recovery/status", ceremony))).toEqual({ state: "ended" })
      const page = await f.html(ceremony, "/recover/passkey")
      expect(page).not.toMatch(/data-form="recover-passkey"|recover-pending/)
      expect(page).toContain("15 minutes ran out")
      expect((await f.request("/api/auth/recovery/passkey/options", ceremony, {})).status).toBe(401)
      expect(await f.db.prepare("SELECT COUNT(*) AS n FROM web_sessions WHERE account=? AND kind='recovery'").bind(f.alex.account).first()).toEqual({ n: 0 })
    }
    await ended()
    // The cancellation's barrier is still pending and untouched by reading the status.
    expect(await f.db.prepare("SELECT state FROM account_security_transitions WHERE id=?").bind(transition).first()).toEqual({ state: "pending" })
    f.faults.blockInstall = false
    await f.db.prepare("UPDATE account_security_transitions SET next_retry_at=0 WHERE id=?").bind(transition).run()
    await f.cron()
    expect(await f.db.prepare("SELECT state FROM account_security_transitions WHERE id=?").bind(transition).first()).toEqual({ state: "committed" })
    await ended()
  })

  it("two pending recoveries in one transition: cancelling one notice leaves the other ceremony pending", async () => {
    const f = await reviewJourney()
    f.faults.blockInstall = true
    const first = await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[0] })
    const firstCeremony = { cookie: first.headers.get("set-cookie")!.split(";")[0]! } as Person
    const one = await body<{ transition: string }>(first, 202)
    const second = await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[1] })
    const secondCeremony = { cookie: second.headers.get("set-cookie")!.split(";")[0]! } as Person
    const two = await body<{ transition: string }>(second, 202)
    expect(two.transition).toBe(one.transition)
    const notices = (await f.db.prepare("SELECT id FROM account_notices WHERE account=? AND kind='recovery' ORDER BY at,id").bind(f.alex.account).all<{ id: string }>()).results
    expect(notices).toHaveLength(2)
    // Which notice belongs to the second ceremony, from the transition's own effects.
    const effects = JSON.parse((await f.db.prepare("SELECT effects FROM account_security_transitions WHERE id=?").bind(one.transition).first<{ effects: string }>())!.effects) as { kind: string; notice: string; ceremony?: { tokenHash: string } }[]
    const secondHash = await sha256Text(secondCeremony.cookie.split("=")[1]!)
    const secondNotice = effects.find((e) => e.kind === "recovery.start" && e.ceremony?.tokenHash === secondHash)!.notice
    await f.signin(f.alex)
    const action: WorkspaceStepUpAction = { type: "recovery.resolve", notice: secondNotice, outcome: "cancel" }
    expect((await f.signed(`/api/account/recovery/${secondNotice}/resolve`, f.alex, { outcome: "cancel" }, action)).status).toBe(200)
    expect(await body(await f.request("/api/auth/recovery/status", secondCeremony))).toEqual({ state: "ended" })
    expect(await body(await f.request("/api/auth/recovery/status", firstCeremony))).toEqual({ state: "pending" })
    expect(await f.html(firstCeremony, "/recover/passkey")).toContain("recover-pending")
  })

  it("enrol: a correct fifth group finishes acceptance; no extra guess; a plan is bound to its actor and terms", async () => {
    const f = await reviewJourney()
    const start = await f.startMachine(f.work)
    const plan = (person: Person, group: string, privateCredentials = false) => f.ui(person, f.work, `/enrolments/${start.started.code}/action`, { kind: "accept", group, privateCredentials })
    for (let i = 0; i < 4; i++) expect((await plan(f.alex, wrongGroup(start.group))).status).toBe(403)
    const { action } = await body<{ action: WorkspaceStepUpAction }>(await plan(f.alex, start.group))
    expect(await f.db.prepare("SELECT group_attempts,status FROM enrolments WHERE id=?").bind(start.started.enrolment).first()).toEqual({ group_attempts: 4, status: "pending" })
    // The planned action does not sign different terms.
    await refusal(await f.uiSigned(f.alex, f.work, action, `/enrolments/${start.started.code}/accept`, { group: start.group, privateCredentials: true }), 403, { error: "forbidden", message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." })
    expect(await body(await f.uiSigned(f.alex, f.work, action, `/enrolments/${start.started.code}/accept`, { group: start.group, privateCredentials: false }))).toMatchObject({ state: "active" })
    expect(await f.sql(f.work, "SELECT id FROM devices WHERE enrolment=?", start.started.enrolment)).toHaveLength(1)

    // After four wrong guesses and a correct plan, a fifth wrong guess still rejects.
    const second = await f.startMachine(f.work)
    const plan2 = (group: string) => f.ui(f.alex, f.work, `/enrolments/${second.started.code}/action`, { kind: "accept", group, privateCredentials: false })
    for (let i = 0; i < 4; i++) expect((await plan2(wrongGroup(second.group))).status).toBe(403)
    expect((await plan2(second.group)).status).toBe(200)
    await refusal(await plan2(wrongGroup(second.group)), 409, { error: "conflict", message: "The hidden group was wrong 5 times, so this enrolment is rejected. Start a fresh enrolment on the machine." })
    expect((await plan2(second.group)).status).toBe(409)

    // Another person cannot use Alex's plan.
    const third = await f.startMachine(f.work)
    const alexPlan = await body<{ action: WorkspaceStepUpAction }>(await f.ui(f.alex, f.work, `/enrolments/${third.started.code}/action`, { kind: "accept", group: third.group, privateCredentials: false }))
    const gina = await f.guest(f.alex, f.work, f.project.id, "Gina")
    expect((await f.uiSigned(gina, f.work, alexPlan.action, `/enrolments/${third.started.code}/accept`, { group: third.group, privateCredentials: false })).status).toBe(403)
    expect(await f.sql(f.work, "SELECT id FROM devices WHERE enrolment=?", third.started.enrolment)).toEqual([])
  })

  it("bootstrap: the server says the first account has nothing to join; an invited account cannot create a workspace", async () => {
    const f = await reviewJourney()
    expect(f.alex.onboarding).toBe("bootstrap")
    const gina = await f.guest(f.alex, f.work, f.project.id, "Gina")
    expect(gina.onboarding).toBe("join")
    // Gina has recovery set up and is active, but the operator never allowed her.
    const page = await f.html(gina, "/workspaces/new")
    expect(page).toContain('data-region="create-not-allowed"')
    expect(page).not.toContain('data-form="workspace-create"')
    expect(await f.html(gina, "/workspaces")).not.toContain('href="/workspaces/new"')
    const before = await f.db.prepare("SELECT COUNT(*) AS n FROM workspaces").first()
    const { nonce, options } = await body<{ nonce: string; options: { challenge: string } }>(await f.request("/api/account/stepup/start", gina, { action: { type: "workspace.create", name: "Mine", slug: "gina-own" } }))
    expect((await f.request("/api/workspaces", gina, { name: "Mine", slug: "gina-own", stepUp: { nonce, assertion: await assertion(gina.passkey, options.challenge, ++gina.counter) } })).status).toBe(403)
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM workspaces").first()).toEqual(before)
  })

  it("guest widening: the guest may only narrow; an insider proposes, the guest accepts, and it commits", async () => {
    const f = await reviewJourney()
    const gina = await f.guest(f.alex, f.work, f.project.id, "Gina")
    const start = await f.startMachine(f.work)
    expect(await body(await f.acceptMachine(gina, f.work, start, false))).toMatchObject({ state: "pending_admission" })
    const admitBoot = bootOf(await f.html(f.alex, `/w/northwind/e/${start.started.code}`))
    const admit: WorkspaceStepUpAction = { type: "enrol.approve", enrolment: String(admitBoot.enrolment), digest: String(admitBoot.digest), owner: admitBoot.owner as { kind: "member"; member: string; name: string }, admissionRole: "owner" }
    expect(await body(await f.uiSigned(f.alex, f.work, admit, `/enrolments/${start.started.code}/admit`, { group: start.group }))).toMatchObject({ state: "active" })
    const [device] = await f.sql<{ id: string }>(f.work, "SELECT id FROM devices WHERE enrolment=?", start.started.enrolment)
    const path = `/w/northwind/devices/${device!.id}`
    const own = await f.html(gina, path)
    const ownBoot = bootOf(own) as { scope: WorkspaceDeviceScope; propose: boolean }
    expect(ownBoot.propose).toBe(false)
    expect(own).toContain("Narrow what it may use")
    expect(own).toContain("ask the person who invited you, or an owner or admin, to propose the wider scope")
    expect(own).not.toMatch(/data-person=|rescope-admit/)
    // The server refuses the guest's own widening as the page says.
    const wider = { ...ownBoot.scope, privateCredentials: true }
    const selfPlan = await f.ui(gina, f.work, `/devices/${device!.id}/action`, { change: { kind: "rescope_propose", before: ownBoot.scope, after: wider } })
    const { action: selfAction } = await body<{ action: WorkspaceStepUpAction }>(selfPlan)
    await refusal(await f.uiSigned(gina, f.work, selfAction, `/devices/${device!.id}/rescope`, { before: ownBoot.scope, after: wider }), 403, { error: "forbidden", message: "Choose an eligible insider for this guest's shared project." })
    // The insider proposes from the page's own boot and planning call.
    const insiderBoot = bootOf(await f.html(f.alex, path)) as { scope: WorkspaceDeviceScope; propose: boolean }
    expect(insiderBoot.propose).toBe(true)
    const proposed = await body<{ action: WorkspaceStepUpAction }>(await f.ui(f.alex, f.work, `/devices/${device!.id}/action`, { change: { kind: "rescope_propose", before: insiderBoot.scope, after: wider } }))
    const proposal = await body<{ id: string; state: string }>(await f.uiSigned(f.alex, f.work, proposed.action, `/devices/${device!.id}/rescope`, { before: insiderBoot.scope, after: wider }))
    expect(proposal.state).toBe("open")
    // The guest's page offers acceptance as their own machine, and nothing else.
    const offered = await f.html(gina, path)
    expect(offered).toContain(`data-action="rescope-accept" data-proposal="${proposal.id}"`)
    expect(offered).not.toContain("rescope-admit")
    const accept = await body<{ action: WorkspaceStepUpAction }>(await f.ui(gina, f.work, `/devices/${device!.id}/action`, { change: { kind: "rescope_accept", proposal: proposal.id } }))
    expect(await body(await f.uiSigned(gina, f.work, accept.action, `/devices/${device!.id}/rescope-accept`, { proposal: proposal.id }))).toMatchObject({ state: "committed" })
    const [after] = await f.sql<{ scope: string }>(f.work, "SELECT scope FROM devices WHERE id=?", device!.id)
    expect(JSON.parse(after!.scope)).toMatchObject({ privateCredentials: true })
  })

  it("delegation: a guest invitation and a team admission name the workspace credentials they let someone use, and only those", async () => {
    const f = await reviewJourney()
    await f.credential(f.alex, f.work, "shared-key", { kind: "workspace" })
    await f.credential(f.alex, f.work, "unrelated-key", { kind: "workspace" })
    await f.credential(f.alex, f.work, "alex-own", { kind: "member", member: await f.member(f.alex, f.work) })
    await body(await f.projectMutation(f.alex, f.work, "variable", { project: f.project.id, name: "TOKEN", env: "dev", item: "shared-key", field: "key", before: null }, `/projects/${f.project.id}/vars/TOKEN`))
    const people = await f.html(f.alex, "/w/northwind/people")
    expect(people).toContain(`data-share="${f.project.id}" data-delegates="shared-key"`)
    expect(people).not.toMatch(/data-delegates="[^"]*(unrelated-key|alex-own)/)
    // A team with the project, and its machine waiting for admission.
    const { action: create } = await body<{ action: WorkspaceStepUpAction }>(await f.ui(f.alex, f.work, "/teams/action", { kind: "create", name: "Bots", slug: "bots" }))
    const team = await body<TeamView>(await f.uiSigned(f.alex, f.work, create, "/teams", { team: create.type === "team.update" ? create.team : "", name: "Bots", slug: "bots" }), 201)
    await body(await f.projectMutation(f.alex, f.work, "share", { project: f.project.id, subject: { kind: "team", team: team.id }, before: null, after: { level: "use", protected: false, expiresAt: null } }, `/projects/${f.project.id}/shares`))
    const keys = await newDeviceKey(), jwk = await publicJwk(keys)
    const input = { workspace: f.work.slug, owner: { kind: "team", team: team.id }, name: "bot-runner", backend: "software", jwk }
    const proof = await createProof(webCryptoSigner("new", keys.privateKey), { method: "POST", url: `${ORIGIN}/v1/enrol`, body: JSON.stringify(input) }, { tenant: "enrol" })
    const started = await body<{ enrolment: string; code: string }>(await f.request("/v1/enrol", undefined, input, { "Mehen-Proof": proof }), 201)
    const group = fingerprintGroups(fingerprintOf(await jwkThumbprint(jwk)))[await fingerprintGroupIndex(started.code)]!
    const admitPage = await f.html(f.alex, `/w/northwind/e/${started.code}`)
    const preview = /data-region="admit-delegation">([\s\S]*?)<\/p>/.exec(admitPage)?.[1] ?? ""
    expect(preview).toContain("<code>shared-key</code>")
    expect(preview).not.toMatch(/unrelated-key|alex-own/)
    expect(admitPage.indexOf('data-region="admit-delegation"')).toBeLessThan(admitPage.indexOf('data-action="enrol-admit"'))
    const boot = bootOf(admitPage)
    const action: WorkspaceStepUpAction = { type: "enrol.approve", enrolment: String(boot.enrolment), digest: String(boot.digest), owner: boot.owner as { kind: "team"; team: string; name: string }, admissionRole: "owner" }
    expect(await body(await f.uiSigned(f.alex, f.work, action, `/enrolments/${started.code}/admit`, { group }))).toMatchObject({ state: "active" })
  })
})

// The proposal card's terms as the machine page serves them, or null when
// the page has no card.
function cardOf(page: string): (RescopeShown & { actions: string[] }) | null {
  const card = /<section class="card decision[^"]*" data-region="proposal"([^>]*)>([\s\S]*?)<\/section>/.exec(page)
  if (!card) return null
  const attribute = (name: string) => new RegExp(` data-${name}="([^"]*)"`).exec(card[1]!)?.[1] ?? null
  return { proposal: attribute("proposal") ?? "", device: attribute("device") ?? "", thumbprint: attribute("thumbprint") ?? "", project: attribute("project"), actions: [...card[2]!.matchAll(/data-action="(rescope-[a-z]+)"/g)].map((m) => m[1]!) }
}

describe("a guest's scope proposal through the machine page", () => {
  it("the owning guest and the admission signer each reject through the page, leaving scope and scope_rev unchanged; the signer's Admit carries the project", async () => {
    const f = await reviewJourney()
    const gina = await f.guest(f.alex, f.work, f.project.id, "Gina")
    const tom = await f.guest(f.alex, f.work, f.project.id, "Tom")
    expect(await body(await f.memberChange(f.alex, f.work, tom.member!, "role", "admin"))).toMatchObject({ role: "admin" })
    const start = await f.startMachine(f.work)
    expect(await body(await f.acceptMachine(gina, f.work, start, false))).toMatchObject({ state: "pending_admission" })
    const admitBoot = bootOf(await f.html(f.alex, `/w/northwind/e/${start.started.code}`))
    const admitEnrol: WorkspaceStepUpAction = { type: "enrol.approve", enrolment: String(admitBoot.enrolment), digest: String(admitBoot.digest), owner: admitBoot.owner as { kind: "member"; member: string; name: string }, admissionRole: "owner" }
    expect(await body(await f.uiSigned(f.alex, f.work, admitEnrol, `/enrolments/${start.started.code}/admit`, { group: start.group }))).toMatchObject({ state: "active" })
    const [{ id: device }] = (await f.sql<{ id: string }>(f.work, "SELECT id FROM devices WHERE enrolment=?", start.started.enrolment)) as [{ id: string }]
    const path = `/w/northwind/devices/${device}`
    const machine = async () => (await f.sql<{ scope: string; scope_rev: number }>(f.work, "SELECT scope,scope_rev FROM devices WHERE id=?", device))[0]!
    // Alex proposes a wider scope that Gina accepts and Tom admits.
    const propose = async () => {
      const boot = bootOf(await f.html(f.alex, path)) as { scope: WorkspaceDeviceScope }
      const after = { ...boot.scope, privateCredentials: true }
      const { action } = await body<{ action: WorkspaceStepUpAction }>(await f.ui(f.alex, f.work, `/devices/${device}/action`, { change: { kind: "rescope_propose", before: boot.scope, after } }))
      const proposal = await body<{ id: string; state: string }>(await f.uiSigned(f.alex, f.work, action, `/devices/${device}/rescope`, { before: boot.scope, after, admissionMember: tom.member }))
      expect(proposal.state).toBe("open")
      return proposal.id
    }
    // Reject as the page does: the plan must be the card's own terms, then sign and send.
    const rejectThroughPage = async (person: Person) => {
      const shown = cardOf(await f.html(person, path))!
      const planned = await body<{ action: WorkspaceStepUpAction }>(await f.ui(person, f.work, `/devices/${device}/action`, { change: { kind: "rescope_reject", proposal: shown.proposal }, ...(shown.project !== null ? { project: shown.project } : {}) }))
      expect(planned.action).toEqual(rescopeRejectAction(shown))
      return body<{ id: string; state: string }>(await f.uiSigned(person, f.work, rescopeRejectAction(shown), `/devices/${device}/rescope-reject`, rescopeSignBody(shown)))
    }

    // 1. Gina, the owning guest: Accept and Reject, no project.
    const first = await propose()
    const before = await machine()
    const ginaCard = cardOf(await f.html(gina, path))!
    expect(ginaCard).toEqual({ proposal: first, device, thumbprint: start.thumbprint, project: null, actions: ["rescope-accept", "rescope-reject"] })
    // Alex proposed and signs nothing more: no actions on his card.
    expect(cardOf(await f.html(f.alex, path))).toMatchObject({ proposal: first, project: null, actions: [] })
    expect(await rejectThroughPage(gina)).toMatchObject({ id: first, state: "rejected" })
    expect(await machine()).toEqual(before)
    expect(cardOf(await f.html(gina, path))).toBeNull()

    // 2. Tom, the admission signer: Admit and Reject for the guest's shared project.
    const second = await propose()
    expect(await machine()).toEqual(before)
    const tomCard = cardOf(await f.html(tom, path))!
    expect(tomCard).toEqual({ proposal: second, device, thumbprint: start.thumbprint, project: f.project.id, actions: ["rescope-admit", "rescope-reject"] })
    expect(await rejectThroughPage(tom)).toMatchObject({ id: second, state: "rejected" })
    expect(await machine()).toEqual(before)
    expect(cardOf(await f.html(tom, path))).toBeNull()

    // 3. Tom admits through the page with the card's project; Gina then accepts and it commits.
    const third = await propose()
    const admitCard = cardOf(await f.html(tom, path))!
    // Without the project, as the page sent Admit before, the vault refuses the admission.
    expect((await f.ui(tom, f.work, `/devices/${device}/action`, { change: { kind: "rescope_admit", proposal: third } })).status).toBe(403)
    const admitPlan = await body<{ action: WorkspaceStepUpAction }>(await f.ui(tom, f.work, `/devices/${device}/action`, { change: { kind: "rescope_admit", proposal: third }, project: admitCard.project }))
    expect(await body(await f.uiSigned(tom, f.work, admitPlan.action, `/devices/${device}/rescope-admit`, rescopeSignBody(admitCard)))).toMatchObject({ id: third, state: "open" })
    expect(await machine()).toEqual(before)
    expect(cardOf(await f.html(tom, path))).toMatchObject({ proposal: third, actions: [] })
    const acceptPlan = await body<{ action: WorkspaceStepUpAction }>(await f.ui(gina, f.work, `/devices/${device}/action`, { change: { kind: "rescope_accept", proposal: third } }))
    expect(await body(await f.uiSigned(gina, f.work, acceptPlan.action, `/devices/${device}/rescope-accept`, { proposal: third }))).toMatchObject({ id: third, state: "committed" })
    const committed = await machine()
    expect(JSON.parse(committed.scope)).toMatchObject({ privateCredentials: true })
    expect(committed.scope_rev).toBeGreaterThan(before.scope_rev)
  })
})
