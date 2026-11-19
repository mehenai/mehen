// POST /v1/push end to end (design push-providers 3.1 and 3.2): a machine
// asks, the Worker makes the via's preview reads, a person approves with a
// passkey, and the decide route sends the value to a fake GitHub; the value
// appears in no answer, audit row or log.
import { afterEach, expect, it, vi } from "vitest"
import type { ApprovalSubject, ApprovalViewProjection, WorkspaceStepUpAction } from "@mehen/protocol"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { pushErrorFor } from "../src/routes/push.ts"
import { VaultError } from "../src/http.ts"
import { body } from "./e2e/workspace-journey.ts"
import { nativeSession } from "./e2e/oidc-journey.ts"
import { assertion } from "./e2e/passkeys.ts"
import { VALUE, VIA_TOKEN, fakeGitHub, pushJourney, stored, to } from "./push-journey.ts"

afterEach(() => setUpstreamFetch(null))

it("asks, is approved, and puts the value into GitHub sealed, naming the outcome and never the value", async () => {
  const log = vi.spyOn(console, "log"), error = vi.spyOn(console, "error"), warn = vi.spyOn(console, "warn")
  const f = await pushJourney()
  const sent = fakeGitHub()
  const asked = await body<{ error: string; approval: string; next: { url: string } }>(await f.deviceCall(f.machine, "/v1/push", { item: "openai-prod", to, reason: "deploys need it" }), 409)
  expect(asked).toMatchObject({ error: "approval_required", approval: expect.stringMatching(/^apr_/) })
  // Only the preview reads the via's policy allows, with the via's token.
  expect(sent.map((s) => `${s.method} ${s.url}`)).toEqual(["GET https://api.github.com/repos/acme/api", "GET https://api.github.com/repos/acme/api/actions/secrets/OPENAI_API_KEY"])
  expect(sent.every((s) => s.authorization === `Bearer ${VIA_TOKEN}`)).toBe(true)
  const decided = await f.decide(asked.approval)
  if (decided.view !== "detail") throw new Error("Expected the detail view")
  expect(decided.approval.push).toMatchObject({ destination: "github:acme/api/OPENAI_API_KEY", state: "done", outcome: "created", providerStatus: 201, preview: { provider: "github", owner: "acme", private: true, exists: false }, newDestination: true })
  const write = sent.find((s) => s.method === "PUT")!
  expect(write.url).toBe("https://api.github.com/repos/acme/api/actions/secrets/OPENAI_API_KEY")
  expect(JSON.parse(write.body)).toEqual({ encrypted_value: expect.any(String), key_id: "k1" })
  expect(write.body).not.toContain(VALUE)
  // The machine reads how it went, and the credential lists where it went.
  expect(await body(await f.deviceCall(f.machine, `/v1/approvals/${asked.approval}`))).toMatchObject({ status: "used", push: { state: "done", outcome: "created" } })
  const described = await body<{ pushes: unknown[] }>(await f.request(`/api/w/${f.work.slug}/items/openai-prod`, f.alex))
  expect(described.pushes).toEqual([expect.objectContaining({ destination: "github:acme/api/OPENAI_API_KEY", state: "done", current: true, via: "gh-token", by: "integration-machine" })])
  // Asked again within ten minutes: the same push answers, nothing is sent.
  const before = sent.length
  expect(await body(await f.deviceCall(f.machine, "/v1/push", { item: "openai-prod", to }))).toMatchObject({ outcome: "created", destination: "github:acme/api/OPENAI_API_KEY" })
  expect(sent.length).toBe(before + 2)
  const everything = JSON.stringify([asked, decided, described, await f.sql(f.work, "SELECT * FROM audit"), await f.sql(f.work, "SELECT * FROM pushes"), log.mock.calls, error.mock.calls, warn.mock.calls])
  expect(everything).not.toContain(VALUE)
  expect(everything).not.toContain(VIA_TOKEN)
})

it("is not sent when the workspace is frozen between the decision and the send, and spends the approval", async () => {
  const f = await pushJourney()
  const sent = fakeGitHub()
  const asked = await body<{ approval: string }>(await f.deviceCall(f.machine, "/v1/push", { item: "openai-prod", to }), 409)
  // Freeze just after the decision commits: the decide route then sends.
  const freezeAfterDecide = f.env.TENANT_VAULT
  f.env.TENANT_VAULT = new Proxy(freezeAfterDecide, { get(target, key) {
    if (key !== "getByName") return Reflect.get(target, key)
    return (name: string) => {
      const stub = target.getByName(name)
      return new Proxy(stub, { get(object, prop) {
        if (prop !== "invoke") { const value = Reflect.get(object, prop) as unknown; return typeof value === "function" ? value.bind(object) : value }
        return async (input: { op: string }) => {
          if (input.op === "push.execute") await object.invoke({ op: "access.operator_freeze", input: { operator: "acc_operator_test" }, auth: { kind: "system", reason: "test" } } as never)
          return object.invoke(input as never)
        }
      } })
    }
  } })
  const decided = await f.decide(asked.approval)
  f.env.TENANT_VAULT = freezeAfterDecide
  if (decided.view !== "detail") throw new Error("Expected the detail view")
  expect(decided.approval.push?.state).toBe("not_sent")
  expect(sent.some((s) => s.method === "PUT")).toBe(false)
  expect(await f.sql(f.work, "SELECT uses_left FROM protected_use_grants WHERE approval=?", asked.approval)).toEqual([{ uses_left: 0 }])
})

it("a provider's refusal fails the push and is told only to a mehen that knows provider_refused", async () => {
  const f = await pushJourney()
  fakeGitHub(() => Response.json({ message: "Resource not accessible by integration" }, { status: 403 }))
  const asked = await body<{ approval: string }>(await f.deviceCall(f.machine, "/v1/push", { item: "openai-prod", to }), 409)
  const decided = await f.decide(asked.approval)
  if (decided.view !== "detail") throw new Error("Expected the detail view")
  expect(decided.approval.push).toMatchObject({ state: "failed", providerStatus: 403 })
  const refused = new VaultError("provider_refused", "gh-token may not write secrets in acme/api.", { providerStatus: 403 })
  expect(pushErrorFor(refused, "0.3.18")).toBe(refused)
  for (const old of ["0.3.16", null]) expect(pushErrorFor(refused, old)).toMatchObject({ code: "upstream_failed", message: "gh-token may not write secrets in acme/api.", extra: {} })
})

it("a person puts the value again where it went before with one passkey, and the page lists the new push", async () => {
  const f = await pushJourney()
  const sent = fakeGitHub()
  const asked = await body<{ approval: string }>(await f.deviceCall(f.machine, "/v1/push", { item: "openai-prod", to }), 409)
  await f.decide(asked.approval)
  const [first] = await f.sql<{ id: string }>(f.work, "SELECT id FROM pushes WHERE approval=?", asked.approval)
  const API = `/api/w/${f.work.slug}/items/openai-prod/push`
  const action = await body<WorkspaceStepUpAction>(await f.request(`${API}/action`, f.alex, { records: [first!.id] }))
  expect(action).toMatchObject({ type: "item.push", field: "key", pushes: [{ destination: "github:acme/api/OPENAI_API_KEY" }] })
  const described = await body<{ pushes: { push: string; state: string; by: string | null }[] }>(await f.signed(API, f.alex, { records: [first!.id] }, action, f.work.slug))
  expect(described.pushes).toEqual([expect.objectContaining({ state: "done", by: "Alex" })])
  expect(described.pushes[0]!.push).not.toBe(first!.id)
  expect(sent.filter((s) => s.method === "PUT")).toHaveLength(2)
  // A passkey over another version is refused before anything is queued.
  const queued = (await f.sql(f.work, "SELECT id FROM pushes")).length
  expect((await f.signed(API, f.alex, { records: [described.pushes[0]!.push] }, { ...action, version: (action as { version: number }).version + 1 } as WorkspaceStepUpAction, f.work.slug)).status).toBe(403)
  expect(await f.sql(f.work, "SELECT id FROM pushes")).toHaveLength(queued)
})

it("the app refuses to decide a push, which it cannot show, and the approval stays pending with nothing queued", async () => {
  const f = await pushJourney()
  const sent = fakeGitHub()
  const asked = await body<{ approval: string }>(await f.deviceCall(f.machine, "/v1/push", { item: "openai-prod", to }), 409)
  const app = await nativeSession(f)
  const view = await body<ApprovalViewProjection>(await f.request(`/app/v1/w/${f.work.slug}/approvals/${asked.approval}`, undefined, undefined, app.headers))
  if (view.view !== "detail") throw new Error("Expected the detail view")
  for (const decision of ["approve", "deny"] as const) {
    const action: WorkspaceStepUpAction = { type: "approval.decide", approval: asked.approval, digest: view.approval.digest, decision, constraints: view.approval.constraints }
    const start = await body<{ nonce: string; options: { challenge: string } }>(await f.request("/app/v1/stepup", undefined, { scope: f.work.id, action }, app.headers))
    const stepUp = { nonce: start.nonce, assertion: await assertion(f.alex.passkey, start.options.challenge, ++f.alex.counter) }
    const refused = await f.request(`/app/v1/w/${f.work.slug}/approvals/${asked.approval}/decide`, undefined, { decision, stepUp }, app.headers)
    expect(refused.status).toBe(403)
    expect(await refused.json()).toEqual({ error: "forbidden", message: "Decide this push on its vault page." })
  }
  expect(await f.sql(f.work, "SELECT status FROM approvals WHERE id=?", asked.approval)).toEqual([{ status: "pending" }])
  expect(await f.sql(f.work, "SELECT id FROM pushes")).toEqual([])
  expect(sent.some((s) => s.method === "PUT")).toBe(false)
})

it("the app refuses a person who may only deny a push, though they see only its stop view, and the approval stays pending", async () => {
  const f = await pushJourney()
  fakeGitHub()
  // Bob's machine pushes through Bob's own private GitHub token, which Alex may not see.
  const bob = await f.guest(f.alex, f.work, f.project.id, "Bob")
  await body(await f.memberChange(f.alex, f.work, bob.member!, "role", "member"))
  await stored(f, bob, f.work, "bob-github", "github-pat", VIA_TOKEN, { kind: "member", member: bob.member! })
  const machine = await f.enrolMachine(bob, f.work)
  const asked = await body<{ approval: string }>(await f.deviceCall(machine, "/v1/push", { item: "openai-prod", to, with: "bob-github" }), 409)
  const app = await nativeSession(f)
  const view = await body<ApprovalViewProjection>(await f.request(`/app/v1/w/${f.work.slug}/approvals/${asked.approval}`, undefined, undefined, app.headers))
  expect(view).toMatchObject({ view: "stop", eligibility: { canApprove: false, canDeny: true } })
  const [row] = await f.sql<{ digest: string; subject: string }>(f.work, "SELECT digest,subject FROM approvals WHERE id=?", asked.approval)
  const action: WorkspaceStepUpAction = { type: "approval.decide", approval: asked.approval, digest: row!.digest, decision: "deny", constraints: (JSON.parse(row!.subject) as ApprovalSubject).constraints }
  const start = await body<{ nonce: string; options: { challenge: string } }>(await f.request("/app/v1/stepup", undefined, { scope: f.work.id, action }, app.headers))
  const stepUp = { nonce: start.nonce, assertion: await assertion(f.alex.passkey, start.options.challenge, ++f.alex.counter) }
  const refused = await f.request(`/app/v1/w/${f.work.slug}/approvals/${asked.approval}/decide`, undefined, { decision: "deny", stepUp }, app.headers)
  expect(refused.status).toBe(403)
  expect(await refused.json()).toEqual({ error: "forbidden", message: "Decide this push on its vault page." })
  expect(await f.sql(f.work, "SELECT status FROM approvals WHERE id=?", asked.approval)).toEqual([{ status: "pending" }])
})
