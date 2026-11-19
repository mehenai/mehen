// Every ask a workload makes is its own: only it reads, waits on or spends
// it; its device's own key lists and cancels it, never spends it; another
// workload of the same device finds nothing.
import { createProof, webCryptoSigner, type WorkspaceRunCreated, type WorkspaceStepUpAction } from "@mehen/protocol"
import type { ApprovalBundleCreated } from "@mehen/protocol/api"
import { expect, it } from "vitest"
import { ORIGIN } from "./helpers.ts"
import { body } from "./e2e/workspace-journey.ts"
import { protectedJourney } from "./e2e/protected-journey.ts"
import { workloadJourney } from "./workload-journey.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"
import type { Machine } from "./e2e/workspace-journey.ts"

const intake = { kind: "api-key", slug: "stripe-task", provider: "stripe", reason: "payments", home: "workspace" }
const runInput = (project: string) => ({ project, env: "dev", envSource: "flag", remote: null, worktree: "/w", head: null, vars: [], command: "true", argv: ["true"] })
type Pending = { pending: { view: string; detail?: { id: string } }[] }
const pendingIds = async (response: Response) => (await body<Pending>(response)).pending.flatMap((p) => p.detail ? [p.detail.id] : [])

// Both workloads name the asked-for slug in their items, so only ownership
// keeps one out of the other's asks.
it("intakes: only the asking workload polls or cancels one, its device lists it and ends it only by revoking the workload, another workload sees nothing", async () => {
  const f = await workloadJourney()
  const a = await f.createWorkload(f.machine, { items: ["stripe-task"] }, "task-a"), b = await f.createWorkload(f.machine, { items: ["stripe-task"] }, "task-b")
  const created = await body<{ intake: string }>(await f.workloadCall(f.as(a), "/v1/intakes", intake), 201)
  expect((await f.workloadCall(f.as(a), `/v1/intakes/${created.intake}`)).status).toBe(200)
  for (const response of [await f.workloadCall(f.as(b), `/v1/intakes/${created.intake}`), await f.deviceCall(f.machine, `/v1/intakes/${created.intake}`), await f.workloadCall(f.as(b), `/v1/intakes/${created.intake}/cancel`, {})]) expect(response.status).toBe(404)
  expect(await pendingIds(await f.workloadCall(f.as(a), "/v1/pending"))).toEqual([created.intake])
  expect(await pendingIds(await f.workloadCall(f.as(b), "/v1/pending"))).toEqual([])
  expect(await pendingIds(await f.deviceCall(f.machine, "/v1/pending"))).toEqual([created.intake])
  // The same request from another workload is never handed the first one's ask: the name is held.
  expect(await body(await f.workloadCall(f.as(b), "/v1/intakes", intake), 409)).toEqual({ error: "conflict", message: "name not available" })
  expect(await body<{ intake: string }>(await f.workloadCall(f.as(a), "/v1/intakes", intake), 201)).toMatchObject({ intake: created.intake })
  expect(await f.sql(f.work, "SELECT requester_workload FROM workspace_credential_requests WHERE id=?", created.intake)).toEqual([{ requester_workload: a.view.workload }])
  // The device's own key never cancels a workload's ask; revoking the workload ends it.
  expect((await f.deviceCall(f.machine, `/v1/intakes/${created.intake}/cancel`, {})).status).toBe(404)
  expect(await f.sql(f.work, "SELECT status FROM workspace_credential_requests WHERE id=?", created.intake)).toEqual([{ status: "open" }])
  await body(await f.deviceCall(f.machine, `/v1/workloads/${a.view.workload}`, undefined, undefined, undefined, "DELETE"))
  expect(await f.sql(f.work, "SELECT status FROM workspace_credential_requests WHERE id=?", created.intake)).toEqual([{ status: "cancelled" }])
  expect(await pendingIds(await f.deviceCall(f.machine, "/v1/pending"))).toEqual([])
  const audit = await f.sql<{ detail: string }>(f.work, "SELECT detail FROM audit WHERE action='intake.request' ORDER BY seq")
  expect(JSON.parse(audit[0]!.detail)).toMatchObject({ by: { workload: { id: a.view.workload, label: "task-a" } } })
})

it("connections: only the asking workload polls or cancels one; its device and another workload cannot cancel it", async () => {
  const f = await workloadJourney()
  const items = ["gmail-task", "google-oauth-client"]
  const a = await f.createWorkload(f.machine, { items }, "task-a"), b = await f.createWorkload(f.machine, { items }, "task-b")
  const created = await body<{ connect: string }>(await f.workloadCall(f.as(a), "/v1/connect", { provider: "google-gmail", slug: "gmail-task", reason: "mail", home: "workspace", requestClient: true }))
  expect((await f.workloadCall(f.as(a), `/v1/connect/${created.connect}`)).status).toBe(200)
  for (const response of [await f.workloadCall(f.as(b), `/v1/connect/${created.connect}`), await f.deviceCall(f.machine, `/v1/connect/${created.connect}`), await f.workloadCall(f.as(b), `/v1/connect/${created.connect}/cancel`, {}), await f.deviceCall(f.machine, `/v1/connect/${created.connect}/cancel`, {})]) expect(response.status).toBe(404)
  expect(await body(await f.workloadCall(f.as(a), `/v1/connect/${created.connect}/cancel`, {}))).toEqual({})
})

it("runs: only the starting workload renews, leases from or ends one; its device ends it by revoking the workload; another workload finds none", async () => {
  const f = await workloadJourney()
  const scope = { items: ["openai-main"], projects: [f.project.id] }
  const a = await f.createWorkload(f.machine, scope, "task-a"), b = await f.createWorkload(f.machine, scope, "task-b")
  const run = await body<WorkspaceRunCreated>(await f.workloadCall(f.as(a), "/v1/runs", runInput(f.project.id)), 201)
  expect(await f.sql(f.work, "SELECT workload FROM runs WHERE id=?", run.run)).toEqual([{ workload: a.view.workload }])
  expect((await f.workloadCall(f.as(a), `/v1/runs/${run.run}/renew`, {})).status).toBe(200)
  expect((await f.workloadCall(f.as(b), `/v1/runs/${run.run}/renew`, {})).status).toBe(404)
  expect((await f.deviceCall(f.machine, `/v1/runs/${run.run}/renew`, {})).status).toBe(404)
  expect((await f.workloadCall(f.as(b), `/v1/runs/${run.run}`, undefined, "DELETE")).status).toBe(404)
  expect((await f.deviceCall(f.machine, `/v1/runs/${run.run}`, undefined, undefined, undefined, "DELETE")).status).toBe(404)
  expect((await f.workloadCall(f.as(a), `/v1/runs/${run.run}`, undefined, "DELETE")).status).toBe(200)
  const second = await body<WorkspaceRunCreated>(await f.workloadCall(f.as(a), "/v1/runs", runInput(f.project.id)), 201)
  await body(await f.deviceCall(f.machine, `/v1/workloads/${a.view.workload}`, undefined, undefined, undefined, "DELETE"))
  expect(await f.sql(f.work, "SELECT ended_at IS NOT NULL AS ended FROM runs WHERE id=?", second.run)).toEqual([{ ended: 1 }])
})

it("approvals: only the asking workload waits on or spends its approval; its device and another workload never spend it", async () => {
  const f = await protectedJourney()
  const keys = new Map<string, CryptoKeyPair>()
  async function workload(label: string) {
    const pair = await newDeviceKey()
    const view = await body<{ workload: string }>(await f.deviceCall(f.machine, "/v1/workloads", { jwk: await publicJwk(pair), label, scope: { items: ["prod-key"] } }), 201)
    keys.set(view.workload, pair)
    return view.workload
  }
  async function call(id: string, path: string, input?: unknown) {
    const method = input === undefined ? "GET" : "POST", encoded = input === undefined ? null : JSON.stringify(input)
    const proof = await createProof(webCryptoSigner(f.machine.device, keys.get(id)!.privateKey, id), { method, url: `${ORIGIN}${path}`, body: encoded }, { tenant: f.work.id })
    return f.request(path, undefined, input, { "Mehen-Proof": proof }, method)
  }
  const runInputProd = { project: f.project.id, env: "prod", envSource: "flag", remote: null, worktree: "/integration", head: null, vars: ["TOKEN"], command: "node test.js", argv: ["node", "test.js"] }
  const a = await workload("task-a"), b = await workload("task-b")
  const asked = await body<{ approval: string; next: { command?: string } }>(await call(a, "/v1/runs", runInputProd), 409)
  // A workload waits with its own key, so its ask carries no mehen wait command.
  expect(asked.next.command).toBeUndefined()
  expect(await f.sql(f.work, "SELECT workload FROM approvals WHERE id=?", asked.approval)).toEqual([{ workload: a }])
  expect((await call(a, `/v1/approvals/${asked.approval}`)).status).toBe(200)
  expect((await call(b, `/v1/approvals/${asked.approval}`)).status).toBe(404)
  expect((await f.deviceCall(f.machine, `/v1/approvals/${asked.approval}`)).status).toBe(404)
  expect(await pendingIds(await f.deviceCall(f.machine, "/v1/pending"))).toEqual([asked.approval])
  expect(await pendingIds(await call(b, "/v1/pending"))).toEqual([])
  await f.approve(asked.approval)
  const machine: Machine = f.machine
  for (const [asker, response] of [["workload", await call(b, "/v1/runs", { ...runInputProd, approval: asked.approval })], ["device", await f.deviceCall(machine, "/v1/runs", { ...runInputProd, approval: asked.approval })]] as const) {
    const refused = await body<{ error: string; approval: string; next: { command?: string } }>(response, 409)
    expect(refused.error).toBe("approval_required")
    expect(refused.approval).not.toBe(asked.approval)
    expect(refused.next.command).toBe(asker === "device" ? `mehen wait ${refused.approval}` : undefined)
  }
  expect(await f.sql(f.work, "SELECT uses_left FROM protected_use_grants WHERE approval=?", asked.approval)).toEqual([{ uses_left: 1 }])
  expect((await call(a, "/v1/runs", { ...runInputProd, approval: asked.approval })).status).toBe(201)
  expect(await f.sql(f.work, "SELECT uses_left FROM protected_use_grants WHERE approval=?", asked.approval)).toEqual([{ uses_left: 0 }])
})

it("bundles: POST /v1/approvals/bundles asks, and only the asking workload reads GET /v1/approvals/bundles/:id; its device, another workload and another machine find nothing", async () => {
  const f = await workloadJourney()
  await f.credential(f.alex, f.work, "openai-main", { kind: "workspace" })
  await f.sql(f.work, "UPDATE items SET policy=? WHERE slug='openai-main'", JSON.stringify({ default: "approve", rules: [] }))
  const a = await f.createWorkload(f.machine, { items: ["openai-main"] }, "task-a"), b = await f.createWorkload(f.machine, { items: ["openai-main"] }, "task-b")
  const request = { item: "openai-main", method: "POST", url: "https://api.openai.com/v1/files", headers: [["Content-Type", "application/json"]], body: Buffer.from("{}").toString("base64url") }
  expect(await body(await f.workloadCall(f.as(a), "/v1/approvals/bundles", { requests: [{ ...request, env: "prod" }] }), 400)).toMatchObject({ error: "bad_request", message: "A relay request cannot select a policy mode or claim an environment." })
  const created = await body<ApprovalBundleCreated>(await f.workloadCall(f.as(a), "/v1/approvals/bundles", { requests: [request], reason: "Upload the files" }))
  const asked = created.results[0]!.approval!
  expect(created).toEqual({ bundle: expect.stringMatching(/^bnd_/), url: `https://vault.test/w/northwind/g/${created.bundle}`, expiresAt: expect.any(String), code: expect.stringMatching(/^[A-Z2-9]{6}$/), results: [{ index: 0, outcome: "ask", approval: expect.stringMatching(/^apr_/), bindingCode: expect.any(String) }] })
  expect(await f.sql(f.work, "SELECT workload,bundle FROM approvals WHERE id=?", asked)).toEqual([{ workload: a.view.workload, bundle: created.bundle }])
  expect(await body(await f.workloadCall(f.as(a), `/v1/approvals/bundles/${created.bundle}`))).toEqual({ bundle: created.bundle, approvals: [{ id: asked, status: "pending" }] })
  const other = await f.enrolMachine(f.alex, f.work)
  for (const response of [await f.workloadCall(f.as(b), `/v1/approvals/bundles/${created.bundle}`), await f.deviceCall(f.machine, `/v1/approvals/bundles/${created.bundle}`), await f.deviceCall(other, `/v1/approvals/bundles/${created.bundle}`)]) expect(await body(response, 404)).toEqual({ error: "not_found", message: "No such object." })
  const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/northwind/approvals/${asked}/action`, f.alex, { decision: "approve" }))
  await body(await f.signed(`/api/w/northwind/approvals/${asked}/decide`, f.alex, { decision: "approve" }, action, "northwind"))
  expect(await body(await f.workloadCall(f.as(a), `/v1/approvals/bundles/${created.bundle}?wait=1`))).toEqual({ bundle: created.bundle, approvals: [{ id: asked, status: "approved" }] })
})

it("bundles: a workload whose open asks and requests would pass its five is refused before anything is written, and another workload's identical ask is never taken in", async () => {
  const f = await workloadJourney()
  await f.credential(f.alex, f.work, "openai-main", { kind: "workspace" })
  await f.sql(f.work, "UPDATE items SET policy=? WHERE slug='openai-main'", JSON.stringify({ default: "approve", rules: [] }))
  const a = await f.createWorkload(f.machine, { items: ["openai-main"] }, "task-a"), b = await f.createWorkload(f.machine, { items: ["openai-main"] }, "task-b")
  const request = (n: number) => ({ item: "openai-main", method: "POST", url: "https://api.openai.com/v1/files", headers: [["Content-Type", "application/json"]], body: Buffer.from(`{"n":${n}}`).toString("base64url") })
  const first = await body<ApprovalBundleCreated>(await f.workloadCall(f.as(a), "/v1/approvals/bundles", { requests: [request(1), request(2), request(3)] }))
  expect(first.results.map((r) => r.outcome)).toEqual(["ask", "ask", "ask"])
  const written = async () => [await f.sql(f.work, "SELECT id FROM approval_bundles ORDER BY id"), await f.sql(f.work, "SELECT id FROM approvals ORDER BY id"), await f.sql(f.work, "SELECT seq FROM audit WHERE action IN ('approval.bundle','approval.request') ORDER BY seq")]
  const before = await written()
  expect(await body(await f.workloadCall(f.as(a), "/v1/approvals/bundles", { requests: [request(4), request(5), request(6)] }), 429)).toEqual({ error: "rate_limited", message: "This task's workload's open asks and these 3 requests would pass its own limit of 5. Settle some, or send fewer at once." })
  expect(await written()).toEqual(before)
  // b sends a's first request byte for byte: it gets an ask of its own, and a's stays in a's bundle.
  const theirs = await body<ApprovalBundleCreated>(await f.workloadCall(f.as(b), "/v1/approvals/bundles", { requests: [request(1)] }))
  const mine = first.results[0]!.approval!, asked = theirs.results[0]!.approval!
  expect(theirs.results).toEqual([{ index: 0, outcome: "ask", approval: expect.stringMatching(/^apr_/), bindingCode: expect.any(String) }])
  expect(asked).not.toBe(mine)
  expect(await f.sql(f.work, "SELECT id,workload,bundle FROM approvals WHERE id IN (?,?) ORDER BY id=?", mine, asked, asked)).toEqual([{ id: mine, workload: a.view.workload, bundle: first.bundle }, { id: asked, workload: b.view.workload, bundle: theirs.bundle }])
})

it("approvals count toward a workload's five open asks, and a sibling workload still asks", async () => {
  const f = await protectedJourney()
  const keys = new Map<string, CryptoKeyPair>()
  async function workload(label: string) {
    const pair = await newDeviceKey()
    const view = await body<{ workload: string }>(await f.deviceCall(f.machine, "/v1/workloads", { jwk: await publicJwk(pair), label, scope: {} }), 201)
    keys.set(view.workload, pair)
    return view.workload
  }
  async function call(id: string, path: string, input?: unknown) {
    const method = input === undefined ? "GET" : "POST", encoded = input === undefined ? null : JSON.stringify(input)
    const proof = await createProof(webCryptoSigner(f.machine.device, keys.get(id)!.privateKey, id), { method, url: `${ORIGIN}${path}`, body: encoded }, { tenant: f.work.id })
    return f.request(path, undefined, input, { "Mehen-Proof": proof }, method)
  }
  const prodRun = (n: number) => ({ project: f.project.id, env: "prod", envSource: "flag", remote: null, worktree: "/integration", head: null, vars: ["TOKEN"], command: `node test-${n}.js`, argv: ["node", `test-${n}.js`] })
  const busy = await workload("busy"), sibling = await workload("sibling")
  for (const n of [1, 2, 3, 4, 5]) expect((await body<{ error: string }>(await call(busy, "/v1/runs", prodRun(n)), 409)).error).toBe("approval_required")
  expect(await body(await call(busy, "/v1/runs", prodRun(6)), 429)).toEqual({ error: "rate_limited", message: "This task's workload already has 5 open asks, its own limit. Settle one before asking again." })
  expect((await body<{ error: string }>(await call(sibling, "/v1/runs", prodRun(6)), 409)).error).toBe("approval_required")
})

it("a device whose scope requires workloads may only read, manage workloads, freeze and revoke itself with its own key", async () => {
  const f = await workloadJourney()
  await f.credential(f.alex, f.work, "openai-main", { kind: "workspace" })
  await f.sql(f.work, "UPDATE devices SET scope=json_set(scope,'$.workloads','required') WHERE id=?", f.machine.device)
  const required = { error: "workload_required", message: "This machine acts only through workloads.", next: { say: "Create a workload for this task with the machine's key and sign the request with the workload's key." } }
  for (const [path, input, method] of [["/v1/relay", { item: "openai-main", method: "GET", url: "https://api.openai.com/v1/models", headers: [] }, "POST"], ["/v1/intakes", intake, "POST"], ["/v1/connect", { provider: "google-gmail", slug: "gmail-new", reason: "mail", home: "workspace" }, "POST"], ["/v1/runs", runInput(f.project.id), "POST"], [`/v1/projects/${f.project.id}`, undefined, "GET"], ["/v1/lease", { run: "run_x", item: "openai-main" }, "POST"], ["/v1/approvals/apr_x", undefined, "GET"], ["/v1/policy/context?item=openai-main", undefined, "GET"]] as const) {
    const response = await f.deviceCall(f.machine, path, input, undefined, undefined, method)
    expect(response.status, path).toBe(403)
    expect(await response.json(), path).toEqual(required)
  }
  for (const path of ["/v1/me", "/v1/items", "/v1/items/openai-main", "/v1/pending", "/v1/workloads"]) expect((await f.deviceCall(f.machine, path)).status, path).toBe(200)
  const task = await f.createWorkload(f.machine, { items: ["openai-main"] })
  expect((await f.workloadCall(f.as(task), "/v1/intakes", { ...intake, slug: "openai-main", provider: "openai" })).status).toBe(201)
  expect((await f.deviceCall(f.machine, "/v1/freeze", {})).status).toBe(200)
  expect((await f.deviceCall(f.machine, "/v1/devices/self/revoke", {})).status).toBe(200)
})
