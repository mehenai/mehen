// The browser's own enrolment path through the real Worker. The page never
// holds the key's thumbprint (it would give the hidden group away), so it
// asks /enrolments/:code/action for the exact enrol.accept to sign, and only
// a matching typed group returns it. The INTEGRATION journeys took the
// thumbprint from the CLI side; these prove the browser path end to end.
import { describe, expect, it } from "vitest"
import type { CredentialHome, WorkspaceEnrolView, WorkspaceStepUpAction } from "@mehen/protocol"
import { fingerprintGroupCheck } from "@mehen/protocol/fingerprint"
import { credentialStart, sameAction } from "../../src/ui/client/workspace-logic.ts"
import { type ConnectTerms, type ShownAcceptance, type ShownFingerprint, acceptanceMismatch, connectStartExpected } from "../../src/ui/client/ask-logic.ts"
import { body, refusal, workJourney } from "./workspace-journey.ts"
import { WS, fillIntake, page as projectsPage, setup, uiSigned } from "./ui-projects-journey.ts"

function wrongGroup(group: string): string {
  return group === "2222" ? "3333" : "2222"
}

describe("browser enrolment acceptance", () => {
  it("enrol: the typed group releases the exact action, which the real accept route takes", async () => {
    const f = await workJourney()
    const start = await f.startMachine(f.work)
    const view = await body<{ scope: { privateCredentials: boolean }; actions: string[] }>(await f.request(`/api/w/northwind/enrolments/${start.started.code}`, f.alex))
    expect(view.actions).toContain("accept")
    expect(JSON.stringify(view)).not.toContain(start.thumbprint)
    const { action } = await body<{ action: WorkspaceStepUpAction }>(await f.request(`/api/w/northwind/enrolments/${start.started.code}/action`, f.alex, { kind: "accept", group: start.group, privateCredentials: false }))
    expect(action).toEqual({ type: "enrol.accept", workspace: f.work.id, enrolment: start.started.enrolment, thumbprint: start.thumbprint, account: f.alex.account, member: await f.member(f.alex, f.work), scope: { ...view.scope, privateCredentials: false }, start: expect.any(Object) })
    const accepted = await body<{ state: string }>(await f.signed(`/api/w/northwind/enrolments/${start.started.code}/accept`, f.alex, { group: start.group, privateCredentials: false }, action, "northwind"))
    expect(accepted.state).toBe("active")
    const [device] = await f.sql<{ scope: string }>(f.work, "SELECT scope FROM devices WHERE enrolment=?", start.started.enrolment)
    expect(JSON.parse(device!.scope)).toMatchObject({ privateCredentials: false })
    expect(await f.db.prepare("SELECT group_attempts FROM enrolments WHERE id=?").bind(start.started.enrolment).first()).toEqual({ group_attempts: 0 })
  })

  it("enrol: a wrong group is refused and counted, and returns no thumbprint", async () => {
    const f = await workJourney()
    const start = await f.startMachine(f.work)
    const response = await f.request(`/api/w/northwind/enrolments/${start.started.code}/action`, f.alex, { kind: "accept", group: wrongGroup(start.group), privateCredentials: true })
    const text = await response.clone().text()
    expect(text).not.toContain(start.thumbprint)
    await refusal(response, 403, { error: "forbidden", message: "That is not the hidden group of this key. Type it from the terminal: 4 attempts left before this enrolment is rejected." })
    expect(await f.db.prepare("SELECT group_attempts,status FROM enrolments WHERE id=?").bind(start.started.enrolment).first()).toEqual({ group_attempts: 1, status: "pending" })
  })

  it("enrol: someone other than the owning account gets no action and no attempt is spent", async () => {
    const f = await workJourney()
    const guest = await f.guest(f.alex, f.work, f.project.id, "Gina")
    const start = await f.startMachine(f.work)
    expect(await body<{ state: string }>(await f.acceptMachine(guest, f.work, start, false))).toMatchObject({ state: "pending_admission" })
    const attempts = await f.db.prepare("SELECT group_attempts FROM enrolments WHERE id=?").bind(start.started.enrolment).first()
    const response = await f.request(`/api/w/northwind/enrolments/${start.started.code}/action`, f.alex, { kind: "accept", group: start.group, privateCredentials: true })
    expect(await response.clone().text()).not.toContain(start.thumbprint)
    await refusal(response, 403, { error: "forbidden", message: "Only the owning account can accept this machine." })
    expect(await f.db.prepare("SELECT group_attempts FROM enrolments WHERE id=?").bind(start.started.enrolment).first()).toEqual(attempts)
  })

  it("enrol: once five wrong groups reject it, planning refuses exactly as accept does", async () => {
    const f = await workJourney()
    const start = await f.startMachine(f.work)
    const plan = (group: string) => f.request(`/api/w/northwind/enrolments/${start.started.code}/action`, f.alex, { kind: "accept", group, privateCredentials: true })
    for (let i = 0; i < 4; i++) expect((await plan(wrongGroup(start.group))).status).toBe(403)
    await refusal(await plan(wrongGroup(start.group)), 409, { error: "conflict", message: "The hidden group was wrong 5 times, so this enrolment is rejected. Start a fresh enrolment on the machine." })
    const planned = await plan(start.group)
    // Accept with a genuinely signed action (the test knows the thumbprint
    // from the machine's side), so its refusal is the group check's.
    const view = await body<{ scope: import("@mehen/protocol").WorkspaceDeviceScope; start: import("@mehen/protocol").EnrolStartContext }>(await f.request(`/api/w/northwind/enrolments/${start.started.code}`, f.alex))
    const action: WorkspaceStepUpAction = { type: "enrol.accept", workspace: f.work.id, enrolment: start.started.enrolment, thumbprint: start.thumbprint, account: f.alex.account, member: await f.member(f.alex, f.work), scope: { ...view.scope, privateCredentials: true }, start: view.start }
    const accepted = await f.signed(`/api/w/northwind/enrolments/${start.started.code}/accept`, f.alex, { group: start.group, privateCredentials: true }, action, "northwind")
    expect(planned.status).toBe(accepted.status)
    expect(await planned.text()).toBe(await accepted.text())
    expect(await f.sql(f.work, "SELECT id FROM devices WHERE enrolment=?", start.started.enrolment)).toEqual([])
  })
})

// The enrolment page by id: the page Needs you links
// to. It hides the same group as the code form, its browser check is keyed
// by the id, and it never carries the clear code.
describe("the enrolment page by id", () => {
  type Work = Awaited<ReturnType<typeof workJourney>>
  async function page(f: Work, path: string, person: Parameters<Work["request"]>[1]): Promise<{ status: number; text: string }> {
    const response = await f.request(path, person, undefined, { accept: "text/html" })
    return { status: response.status, text: await response.text() }
  }

  function bootOf(text: string): Record<string, unknown> {
    const raw = /data-boot="([^"]+)"/.exec(text)?.[1] ?? "{}"
    return JSON.parse(raw.replaceAll("&quot;", '"').replaceAll("&amp;", "&")) as Record<string, unknown>
  }

  it("enrol: the id form hides the same group, keys its check by the id, carries no code, and accepts through the id route", async () => {
    const f = await workJourney()
    const start = await f.startMachine(f.work)
    const id = start.started.enrolment
    const byCode = await page(f, `/w/northwind/e/${start.started.code}`, f.alex)
    const byId = await page(f, `/w/northwind/e/${id}`, f.alex)
    expect(byId.status).toBe(200)
    const codeBoot = bootOf(byCode.text)
    const idBoot = bootOf(byId.text)
    expect(idBoot).toMatchObject({ page: "workspace-enrol", ref: id, enrolment: id, hidden: codeBoot.hidden, lease: "live" })
    expect(idBoot.check).toBe(await fingerprintGroupCheck(id, start.group))
    expect(codeBoot.check).toBe(await fingerprintGroupCheck(start.started.code, start.group))
    for (const shown of [start.started.code, start.started.code.replace("-", "")]) expect(byId.text).not.toContain(shown)
    expect(byId.text).not.toContain(start.thumbprint)
    expect(byId.text).toContain('data-action="enrol-accept"')
    const view = await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${id}`, f.alex))
    expect(view.ref).toBe(id)
    expect(view.code).toBeUndefined()
    const { action } = await body<{ action: WorkspaceStepUpAction }>(await f.request(`/api/w/northwind/enrolments/${id}/action`, f.alex, { kind: "accept", group: start.group, privateCredentials: false }))
    expect(action).toMatchObject({ type: "enrol.accept", enrolment: id, thumbprint: start.thumbprint })
    // What the page's browser code compares before the passkey:
    // the vault's planned acceptance is exactly the page's, key included.
    expect(acceptanceMismatch(action, idBoot.acceptance as ShownAcceptance, idBoot.fingerprint as ShownFingerprint, false, start.group)).toBeNull()
    expect(acceptanceMismatch(action, codeBoot.acceptance as ShownAcceptance, codeBoot.fingerprint as ShownFingerprint, false, start.group)).toBeNull()
    expect(JSON.stringify(idBoot)).not.toContain(start.thumbprint)
    expect(await body<{ state: string }>(await f.signed(`/api/w/northwind/enrolments/${id}/accept`, f.alex, { group: start.group, privateCredentials: false }, action, "northwind"))).toMatchObject({ state: "active" })
    const closed = await page(f, `/w/northwind/e/${id}`, f.alex)
    expect(bootOf(closed.text).page).toBe("enrol-closed")
    expect(closed.text).toContain("<h1>Enrolled</h1>")
  })

  it("enrol: behind a proxy on an https origin, a loopback peer is the proxy, so the page never says the browser is on this machine", async () => {
    const f = await workJourney()
    const start = await f.startMachine(f.work)
    // What Caddy or Tailscale in front of `mehen serve --origin https://...` looks like: every peer is 127.0.0.1.
    const proxied = await f.request(`/w/northwind/e/${start.started.code}`, f.alex, undefined, { accept: "text/html", "cf-connecting-ip": "127.0.0.1" })
    const text = await proxied.text()
    expect(/data-region="enrol-acceptor">([^<]*)</.exec(text)?.[1]).toBe("somewhere the vault cannot place")
    const view = await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${start.started.code}`, f.alex, undefined, { "cf-connecting-ip": "::1" }))
    expect(view.acceptorLocal).toBeUndefined()
  })

  it("enrol: a lapsed link by id shows the lapsed card with Reject for an owner, and Reject works on the lapsed lease", async () => {
    const f = await workJourney()
    const start = await f.startMachine(f.work)
    const id = start.started.enrolment
    await f.db.prepare("UPDATE enrolments SET expires_at=? WHERE id=?").bind(Date.now() - 1000, id).run()
    const lapsed = await page(f, `/w/northwind/e/${id}`, f.alex)
    expect(lapsed.status).toBe(200)
    expect(bootOf(lapsed.text).page).toBe("enrol-closed")
    expect(lapsed.text).toContain("This link has lapsed.")
    expect(lapsed.text).toContain(`data-action="enrol-reject" data-ref="${id}"`)
    expect(lapsed.text).not.toMatch(/data-action="enrol-(accept|admit)"|data-input="fingerprint-group"/)
    expect(lapsed.text).not.toContain(start.started.code)
    expect((await f.request(`/api/w/northwind/enrolments/${id}/reject`, f.alex, {})).status).toBe(200)
    expect(await f.db.prepare("SELECT status FROM enrolments WHERE id=?").bind(id).first()).toEqual({ status: "rejected" })
  })

  it("enrol: an id the caller may not see is the not-found page", async () => {
    const f = await workJourney()
    const start = await f.startMachine(f.work)
    const guest = await f.guest(f.alex, f.work, f.project.id, "Gina")
    expect((await page(f, `/w/northwind/e/${start.started.enrolment}`, guest)).status).toBe(404)
    expect((await page(f, "/w/northwind/e/enr_absent000001", f.alex)).status).toBe(404)
  })
})

// The workspace connect page keeps its passkey step-up exactly: the provider's sign-in address comes back only from a start
// signed for this connect.start, with its home; without a step-up, or with
// one for other terms, nothing starts and no sign-in state is stored.
describe("the connect page's passkey", () => {
  it("connect: the provider redirect is reached only after the passkey confirms connect.start with the shown terms", async () => {
    const f = await setup()
    const home: CredentialHome = { kind: "workspace" }
    const connect = credentialStart("google-gmail", "connect", "gmail-alex", home)
    const started = await body<{ connect: string; intake?: { intake: string } }>(await f.request(`/api/w/${WS}${connect.path}`, f.alex, connect.body), 201)
    await fillIntake(f, f.alex, started.intake!.intake, home)
    const shown = await projectsPage(f, `/w/${WS}/c/${started.connect}`, f.alex)
    expect(shown.text).toMatch(/<button type="button" form="decide" class="btn primary" data-action="start-connect" disabled>/)
    expect(shown.text).toContain("&quot;page&quot;:&quot;ws-connect&quot;")
    const states = async () => (await f.db.prepare("SELECT COUNT(*) AS n FROM oauth_states WHERE connect=?").bind(started.connect).first<{ n: number }>())?.n
    const path = `/api/w/${WS}/connect/${started.connect}`
    const action = await body<WorkspaceStepUpAction>(await f.request(`${path}/action`, f.alex, { home }))
    expect(action).toMatchObject({ type: "connect.start", connect: started.connect, provider: "google-gmail", slug: "gmail-alex", home, intent: "create" })
    expect(Object.keys(action).sort()).toEqual(["client", "clientRevision", "connect", "dependencyRevision", "expectedAccount", "home", "intent", "provider", "scopes", "slug", "tags", "target", "targetRevision", "type"])
    // No step-up: refused, nothing stored.
    expect((await f.request(`${path}/start`, f.alex, { home })).status).toBe(400)
    // A passkey over other terms (another home): refused, nothing stored.
    const other: CredentialHome = { kind: "member", member: await f.member(f.alex, f.work) }
    const otherAction = await body<WorkspaceStepUpAction>(await f.request(`${path}/action`, f.alex, { home: other }))
    const wrong = await f.request(`${path}/start`, f.alex, { home, stepUp: await f.proof(f.alex, otherAction, WS) })
    expect(wrong.status).toBeGreaterThanOrEqual(400)
    expect(wrong.status).toBeLessThan(500)
    expect(await wrong.text()).not.toContain("authorizeUrl")
    expect(await states()).toBe(0)
    // The page's own path: prepare, check, passkey, start.
    // The page's own expectation, built from its boot as its browser code
    // builds it, is exactly the vault's action: the comparison the handler
    // makes before the passkey holds for an honest page.
    const boot = JSON.parse((/data-boot="([^"]+)"/.exec(shown.text)?.[1] ?? "{}").replaceAll("&quot;", '"').replaceAll("&amp;", "&")) as { connect: string; terms: ConnectTerms }
    const expected = connectStartExpected(boot.connect, boot.terms, home)
    expect(expected).toEqual(action)
    const opened = await body<{ authorizeUrl: string }>(await uiSigned(f, f.alex, f.work, { path: `/connect/${started.connect}/action`, body: { home } }, (a) => expected !== null && sameAction(expected, a), { path: `/connect/${started.connect}/start`, body: { home } }))
    expect(new URL(opened.authorizeUrl).protocol).toBe("https:")
    expect(await states()).toBe(1)
  })
})
