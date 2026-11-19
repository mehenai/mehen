// Scoped enrolment: a machine asks for less than usual, the page shows it,
// the acceptor's passkey signs it, and a crafted request can only narrow.
import { createProof, fingerprintGroupIndex, fingerprintGroups, fingerprintOf, jwkThumbprint, webCryptoSigner, type EnrolRequestedScope, type WorkspaceDeviceScope, type WorkspaceStepUpAction } from "@mehen/protocol"
import { expect, it } from "vitest"
import { ORIGIN } from "./helpers.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"
import { body, refusal, workJourney } from "./e2e/workspace-journey.ts"

type Work = Awaited<ReturnType<typeof workJourney>>

async function startScoped(f: Work, scope: unknown, userAgent?: string) {
  const keys = await newDeviceKey(), jwk = await publicJwk(keys)
  const input = { workspace: f.work.slug, owner: { kind: "self" }, name: "scoped-machine", backend: "software", jwk, scope }
  const proof = await createProof(webCryptoSigner("new", keys.privateKey), { method: "POST", url: `${ORIGIN}/v1/enrol`, body: JSON.stringify(input) }, { tenant: "enrol" })
  return { response: await f.request("/v1/enrol", undefined, input, { "Mehen-Proof": proof, ...(userAgent ? { "user-agent": userAgent } : {}) }), keys, jwk }
}
async function started(f: Work, scope: EnrolRequestedScope, userAgent?: string) {
  const { response, keys, jwk } = await startScoped(f, scope, userAgent)
  const start = await body<{ enrolment: string; code: string }>(response, 201)
  const thumbprint = await jwkThumbprint(jwk)
  const group = fingerprintGroups(fingerprintOf(thumbprint))[await fingerprintGroupIndex(start.code)]!
  return { keys, started: start, thumbprint, group }
}
const asked: EnrolRequestedScope = { tags: ["ci"], modes: ["relay", "placeholder"], privateCredentials: false, workloads: "required" }
const narrowed: WorkspaceDeviceScope = { tags: ["ci"], projects: [], modes: ["relay", "placeholder"], maxEnvironment: "unprotected", privateCredentials: false, workloads: "required" }

it("the page shows what the machine asked for, hides the private tick, and the passkey signs exactly that scope", async () => {
  const f = await workJourney()
  const start = await started(f, asked)
  const view = await body<{ scope: WorkspaceDeviceScope; requested: EnrolRequestedScope }>(await f.request(`/api/w/northwind/enrolments/${start.started.code}`, f.alex))
  expect(view.scope).toEqual(narrowed)
  expect(view.requested).toEqual(asked)
  const page = await (await f.request(`/w/northwind/e/${start.started.code}`, f.alex, undefined, { accept: "text/html" })).text()
  expect(page).toContain("This machine asked for less than usual")
  expect(page).toContain("Uses only these credentials: those tagged ci")
  expect(page).toContain("Never uses your private credentials")
  expect(page).toContain("Acts only through short-lived workloads")
  expect(page).not.toContain('data-input="enrol-private"')
  await refusal(await f.request(`/api/w/northwind/enrolments/${start.started.code}/action`, f.alex, { kind: "accept", group: start.group, privateCredentials: true }), 403, { error: "forbidden", message: "This machine asked not to use private credentials. Accept it without them." })
  const { action } = await body<{ action: WorkspaceStepUpAction }>(await f.request(`/api/w/northwind/enrolments/${start.started.code}/action`, f.alex, { kind: "accept", group: start.group, privateCredentials: false }))
  expect(action).toMatchObject({ type: "enrol.accept", scope: narrowed })
  const accepted = await body<{ state: string; scope: WorkspaceDeviceScope }>(await f.signed(`/api/w/northwind/enrolments/${start.started.code}/accept`, f.alex, { group: start.group, privateCredentials: false }, action, "northwind"))
  expect(accepted).toMatchObject({ state: "active", scope: narrowed })
  const pending = { keys: start.keys, device: start.started.enrolment, workspace: f.work }
  const active = await body<{ status: string; device: string; scope: WorkspaceDeviceScope }>(await f.deviceCall(pending, `/v1/enrol/${start.started.enrolment}`, undefined, "enrol"))
  expect(active).toMatchObject({ status: "active", scope: narrowed })
  const machine = { keys: start.keys, device: active.device, workspace: f.work }
  expect((await body<{ scope: WorkspaceDeviceScope }>(await f.deviceCall(machine, "/v1/me"))).scope).toEqual(narrowed)
  // Workloads required from the first request: its own key may not relay.
  const relay = await f.deviceCall(machine, "/v1/relay", { item: "anything", method: "GET", url: "https://api.openai.com/v1/models", headers: [] })
  expect(relay.status).toBe(403)
  expect(await relay.json()).toMatchObject({ error: "workload_required" })
})

it("a passkey over a wider scope than the machine asked for is refused", async () => {
  const f = await workJourney()
  const start = await started(f, { modes: ["relay"] })
  const view = await body<{ scope: WorkspaceDeviceScope; start: unknown }>(await f.request(`/api/w/northwind/enrolments/${start.started.code}`, f.alex))
  expect(view.scope.modes).toEqual(["relay"])
  const wider: WorkspaceStepUpAction = { type: "enrol.accept", workspace: f.work.id, enrolment: start.started.enrolment, thumbprint: start.thumbprint, account: f.alex.account, member: await f.member(f.alex, f.work), scope: { ...view.scope, modes: ["relay", "sign", "mint", "placeholder"] }, start: view.start as never }
  const response = await f.signed(`/api/w/northwind/enrolments/${start.started.code}/accept`, f.alex, { group: start.group, privateCredentials: view.scope.privateCredentials }, wider, "northwind")
  expect(response.status).toBe(403)
  expect(await f.db.prepare("SELECT status FROM enrolments WHERE id=?").bind(start.started.enrolment).first()).toEqual({ status: "pending" })
})

it("a crafted request cannot add lease, a protected environment or private credentials", async () => {
  const f = await workJourney()
  for (const scope of [{ modes: ["lease"] }, { maxEnvironment: "protected" }, { privateCredentials: true }, { modes: ["reveal"] }, { tags: [] }]) {
    const { response } = await startScoped(f, scope)
    expect(response.status, JSON.stringify(scope)).toBe(400)
    expect(await response.json()).toMatchObject({ error: "bad_request" })
  }
  expect(await f.db.prepare("SELECT COUNT(*) AS n FROM enrolments").first()).toEqual({ n: 0 })
  const start = await started(f, { modes: ["relay", "lease"] })
  expect((await body<{ scope: WorkspaceDeviceScope }>(await f.request(`/api/w/northwind/enrolments/${start.started.code}`, f.alex))).scope.modes).toEqual(["relay"])
})

it("a machine that asks for fill at enrolment is refused, since typing into web pages is not available yet", async () => {
  const f = await workJourney()
  for (const scope of [{ modes: ["fill"] }, { modes: ["relay", "fill"] }]) {
    const { response } = await startScoped(f, scope)
    expect(response.status, JSON.stringify(scope)).toBe(403)
    expect(await response.json()).toEqual({ error: "mode_refused", message: "Typing into web pages is not available yet." })
  }
  expect(await f.db.prepare("SELECT COUNT(*) AS n FROM enrolments").first()).toEqual({ n: 0 })
})

it("an enrolment without a requested scope keeps the usual scope and the private tick", async () => {
  const f = await workJourney()
  const start = await f.startMachine(f.work)
  const view = await body<Record<string, unknown>>(await f.request(`/api/w/northwind/enrolments/${start.started.code}`, f.alex))
  expect(view.requested).toBeUndefined()
  expect(view.scope).toEqual({ tags: [], projects: [], modes: ["relay", "sign", "mint", "placeholder"], maxEnvironment: "unprotected", privateCredentials: true })
  const page = await (await f.request(`/w/northwind/e/${start.started.code}`, f.alex, undefined, { accept: "text/html" })).text()
  expect(page).toContain('data-input="enrol-private"')
  expect(page).not.toContain("asked for less than usual")
})

it("a machine enrolling through the client library is named by it and its host's product, never as a browser", async () => {
  const f = await workJourney()
  const start = await started(f, { modes: ["relay"], workloads: "required" }, "mehen-client/0.1.0 globex/2.4.1")
  const view = await body<{ start: { clientLabel: string } }>(await f.request(`/api/w/northwind/enrolments/${start.started.code}`, f.alex))
  expect(view.start.clientLabel).toBe("mehen-client 0.1.0 (globex/2.4.1)")
  const page = await (await f.request(`/w/northwind/e/${start.started.code}`, f.alex, undefined, { accept: "text/html" })).text()
  expect(page).toContain("mehen-client 0.1.0 (globex/2.4.1)")
  expect(page).not.toContain("by A browser")
})
