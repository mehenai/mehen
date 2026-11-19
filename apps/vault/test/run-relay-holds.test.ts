// A request held by policy through a run, as one by item is held: the
// managed workspace's computer, a workload pinned to its project with only
// placeholder mode, POSTs with the run's placeholder. It is answered
// approval_required with an approval for that run's credential only, the
// platform decides it, and the same request then goes through once.
import { afterEach, expect, it, vi } from "vitest"
import { type PlatformApprovalView, type PlatformProjectView, type WorkspaceRunCreated } from "@mehen/protocol"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { json, managedSubject, platform, signed, sql, type Signer } from "./managed-support.ts"
import { body, workJourney } from "./e2e/workspace-journey.ts"
import type { WorkspaceStepUpAction } from "@mehen/protocol"

const cleanups: (() => void)[] = []
afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup()
  setUpstreamFetch(null)
  vi.useRealTimers()
})

const HOST = "echo-test.globex.ai"
const SECRET = "ek-test-not-real-0001"

// What reached the upstream: each request's method, URL and Authorization.
function fakeUpstream(): { method: string; url: string; authorization: string | null }[] {
  const sent: { method: string; url: string; authorization: string | null }[] = []
  setUpstreamFetch(async (request) => {
    sent.push({ method: request.method, url: request.url, authorization: request.headers.get("authorization") })
    return new Response("{}", { headers: { "content-type": "application/json" } })
  })
  return sent
}

// A subject whose platform lets reads with a template-less key through,
// the key set as a variable of its computers project, and a run of that
// environment by a workload pinned to the project with placeholder mode only.
async function computerRun() {
  const f = await managedSubject()
  cleanups.push(f.restore)
  f.directory.defaults = { ...f.directory.defaults, customReads: "allow" }
  f.directory.defaultsRevision = 2
  // Past the workspace's 30-second read of its platform row.
  vi.useFakeTimers({ toFake: ["Date"] })
  vi.setSystemTime(Date.now() + 31_000)
  await f.intake("the-key", { host: HOST }, { key: SECRET })
  await f.intake("other-key", { host: HOST }, { key: "ek-test-not-real-0002" })
  const project = await platform<PlatformProjectView>(f.tenant, "platform.projects.create", { body: { slug: "computers", environments: [{ name: "computers" }], defaultEnv: "computers" } })
  await platform(f.tenant, "platform.projects.setVar", { params: { project: project.id, name: "THE_KEY" }, body: { env: "computers", before: null, item: "the-key" } })
  const machine = await f.device()
  const task = await f.workload(machine, { projects: [project.id], modes: ["placeholder"] })
  const run = await json<WorkspaceRunCreated>(await signed(f.tenant, task, "/v1/runs", { project: project.id, env: "computers", envSource: "flag", remote: null, worktree: "/workspace", head: null, vars: ["THE_KEY"], command: "globex computer" }), 201)
  const key = run.vars.find((v) => v.name === "THE_KEY")
  if (key?.delivery !== "placeholder") throw new Error("Expected a placeholder")
  const through = (signer: Signer, method: string, path: string, approval?: string) => signed(f.tenant, signer, "/v1/relay", { run: run.run, method, url: `https://${HOST}${path}`, headers: [["Authorization", `Bearer ${key.value}`]], ...(approval ? { approval } : {}) })
  return { ...f, project, machine, task, run, placeholder: key.value, through }
}

it("holds a run's write as approval_required for the platform to decide, then sends the same request once with the approval", async () => {
  const f = await computerRun()
  const sent = fakeUpstream()
  await json(await f.through(f.task, "GET", "/c/b1"))
  expect(sent).toEqual([{ method: "GET", url: `https://${HOST}/c/b1`, authorization: `Bearer ${SECRET}` }])

  const held = await json<{ error: string; approval: string; next: unknown; deciders: string[] }>(await f.through(f.task, "POST", "/c/b2"), 409)
  expect(held).toEqual({ error: "approval_required", message: "This request needs approval.", approval: expect.stringMatching(/^apr_/), bindingCode: expect.any(String), expiresAt: expect.any(String), deciders: [], next: { say: "The platform decides this request." } })
  expect(sent).toHaveLength(1)
  // The approval names only the credential the run's placeholder resolves to, and only the workload that asked.
  const [row] = await sql<{ item: string; device: string; workload: string; ask: string }>(f.tenant, "SELECT item,device,workload,ask FROM approvals WHERE id=?", held.approval)
  expect(row).toMatchObject({ item: "the-key", device: f.task.device, workload: f.task.workload })
  const [theKey] = await sql<{ id: string }>(f.tenant, "SELECT id FROM items WHERE slug='the-key'")
  expect(JSON.parse(row!.ask)).toEqual({ device: f.task.device, workload: f.task.workload, credential: theKey!.id, credentials: [theKey!.id], context: { project: f.project.id, environment: "computers" }, mode: "placeholder" })
  // The workload that asked reads its approval and lists it, as it would one asked by item.
  expect(await json(await signed(f.tenant, f.task, `/v1/approvals/${held.approval}`))).toMatchObject({ approval: held.approval, status: "pending" })
  expect((await json<{ pending: { detail?: { id: string } }[] }>(await signed(f.tenant, f.task, "/v1/pending"))).pending.map((p) => p.detail?.id)).toEqual([held.approval])

  const view = await platform<PlatformApprovalView>(f.tenant, "platform.approvals.get", { params: { approval: held.approval } })
  expect(view).toMatchObject({ approval: held.approval, status: "pending", device: f.task.device, workload: { id: f.task.workload }, item: "the-key", request: { method: "POST", url: `https://${HOST}/c/b2` } })
  expect(await platform(f.tenant, "platform.approvals.list", { query: { status: "pending" } })).toEqual({ approvals: [view] })
  // The same request asked again before a decision is the same approval.
  expect((await json<{ approval: string }>(await f.through(f.task, "POST", "/c/b2"), 409)).approval).toBe(held.approval)
  // The workload's own key may not spend it before it is decided.
  expect((await json<{ error: string }>(await f.through(f.task, "POST", "/c/b2", held.approval), 409)).error).toBe("approval_required")
  expect(sent).toHaveLength(1)

  expect(await platform<PlatformApprovalView>(f.tenant, "platform.approvals.decide", { params: { approval: held.approval }, body: { decision: "approve", digest: view.digest } })).toMatchObject({ status: "approved" })
  // Another request under the approval is a new hold, never this one.
  expect((await json<{ approval: string }>(await f.through(f.task, "POST", "/c/other", held.approval), 409)).approval).not.toBe(held.approval)
  await json(await f.through(f.task, "POST", "/c/b2", held.approval))
  expect(sent).toEqual([{ method: "GET", url: `https://${HOST}/c/b1`, authorization: `Bearer ${SECRET}` }, { method: "POST", url: `https://${HOST}/c/b2`, authorization: `Bearer ${SECRET}` }])
  expect((await platform<PlatformApprovalView>(f.tenant, "platform.approvals.get", { params: { approval: held.approval } })).status).toBe("used")
  // One use: the same request with the spent approval is held again.
  const again = await json<{ error: string; approval: string }>(await f.through(f.task, "POST", "/c/b2", held.approval), 409)
  expect(again.error).toBe("approval_required")
  expect(again.approval).not.toBe(held.approval)
  expect(sent).toHaveLength(2)
  // The run carries on: it was never ended by the hold.
  await json(await f.through(f.task, "GET", "/c/b3"))
  expect(await sql(f.tenant, "SELECT ended_at FROM runs WHERE id=?", f.run.run)).toEqual([{ ended_at: null }])
})

it("keeps a denied run hold final: the same request with that approval is held anew and never sent", async () => {
  const f = await computerRun()
  const sent = fakeUpstream()
  const held = await json<{ approval: string }>(await f.through(f.task, "POST", "/c/b2"), 409)
  const view = await platform<PlatformApprovalView>(f.tenant, "platform.approvals.get", { params: { approval: held.approval } })
  expect(await platform<PlatformApprovalView>(f.tenant, "platform.approvals.decide", { params: { approval: held.approval }, body: { decision: "deny", digest: view.digest } })).toMatchObject({ status: "denied" })
  const after = await json<{ error: string; approval: string }>(await f.through(f.task, "POST", "/c/b2", held.approval), 409)
  expect(after.error).toBe("approval_required")
  expect(after.approval).not.toBe(held.approval)
  expect((await platform<PlatformApprovalView>(f.tenant, "platform.approvals.get", { params: { approval: held.approval } })).status).toBe("denied")
  expect(sent).toEqual([])
})

// A person's own workspace: their machine's own run (as mehen run makes
// one) of an environment that holds an OpenAI key, with the device's modes
// as enrolled or narrowed to placeholder only.
async function ownRun(modes: string[] | null) {
  const f = await workJourney()
  const machine = await f.machine(f.alex, f.work)
  await f.credential(f.alex, f.work, "openai-main", { kind: "workspace" })
  await body(await f.deviceCall(machine, `/v1/projects/${f.project.id}/vars/OPENAI_KEY`, { env: "dev", item: "openai-main", field: "key" }, undefined, undefined, "PUT"))
  if (modes) await f.sql(f.work, "UPDATE devices SET scope=json_set(scope,'$.modes',json(?)) WHERE id=?", JSON.stringify(modes), machine.device)
  const run = await body<WorkspaceRunCreated>(await f.deviceCall(machine, "/v1/runs", { project: f.project.id, env: "dev", envSource: "flag", remote: null, worktree: "/work", head: null, vars: ["OPENAI_KEY"], command: "node task.js", argv: ["node", "task.js"] }), 201)
  const key = run.vars.find((v) => v.name === "OPENAI_KEY")
  if (key?.delivery !== "placeholder") throw new Error("Expected a placeholder")
  const through = (method: string, path: string, approval?: string) => f.deviceCall(machine, "/v1/relay", { run: run.run, method, url: `https://api.openai.com${path}`, headers: [["Authorization", `Bearer ${key.value}`]], ...(approval ? { approval } : {}) })
  async function decide(id: string, decision: "approve" | "deny") {
    const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${f.work.slug}/approvals/${id}/action`, f.alex, { decision }))
    return body<{ view: string; approval: { status: string } }>(await f.signed(`/api/w/${f.work.slug}/approvals/${id}/decide`, f.alex, { decision }, action, f.work.slug))
  }
  return { ...f, machine, run, through, decide }
}

for (const [label, modes] of [["as enrolled", null], ["placeholder only", ["placeholder"]]] as const) {
  it(`holds a write through a person's own run (device modes ${label}) for its owner to decide, then sends it once`, async () => {
    const f = await ownRun(modes ? [...modes] : null)
    const sent = fakeUpstream()
    await body(await f.through("GET", "/v1/models"))
    const held = await body<{ error: string; approval: string; deciders: string[]; next: Record<string, unknown> }>(await f.through("DELETE", "/v1/files/file-1"), 409)
    expect(held).toMatchObject({ error: "approval_required", approval: expect.stringMatching(/^apr_/), deciders: ["Alex"], next: { url: `https://vault.test/w/${f.work.slug}/a/${held.approval}`, command: `mehen wait ${held.approval}` } })
    expect(await f.sql(f.work, "SELECT item,device,workload FROM approvals WHERE id=?", held.approval)).toEqual([{ item: "openai-main", device: f.machine.device, workload: null }])
    expect(await body(await f.deviceCall(f.machine, `/v1/approvals/${held.approval}`))).toMatchObject({ approval: held.approval, status: "pending" })
    expect((await f.decide(held.approval, "approve")).approval.status).toBe("approved")
    if (!modes) {
      // The grant serves the run's placeholder use only: the same request naming the credential, in the run's context, is a new ask.
      const byItem = await body<{ error: string; approval: string }>(await f.deviceCall(f.machine, "/v1/relay", { item: "openai-main", context: { project: f.project.id, environment: "dev" }, method: "DELETE", url: "https://api.openai.com/v1/files/file-1", headers: [], approval: held.approval }), 409)
      expect(byItem.error).toBe("approval_required")
      expect(byItem.approval).not.toBe(held.approval)
      expect(sent).toHaveLength(1)
    }
    await body(await f.through("DELETE", "/v1/files/file-1", held.approval))
    expect(sent.map((s) => [s.method, s.url])).toEqual([["GET", "https://api.openai.com/v1/models"], ["DELETE", "https://api.openai.com/v1/files/file-1"]])
    expect(sent.every((s) => s.authorization === "Bearer sk-integration-not-a-real-secret")).toBe(true)
    const again = await body<{ error: string; approval: string }>(await f.through("DELETE", "/v1/files/file-1", held.approval), 409)
    expect(again.approval).not.toBe(held.approval)
    expect((await f.decide(again.approval, "deny")).approval.status).toBe("denied")
    expect((await body<{ approval: string }>(await f.through("DELETE", "/v1/files/file-1", again.approval), 409)).approval).not.toBe(again.approval)
    expect(sent).toHaveLength(2)
  })
}

it("binds a run's approval to the run's workload: another workload of the device, with its own run, cannot spend it", async () => {
  const f = await computerRun()
  const sent = fakeUpstream()
  const held = await json<{ approval: string }>(await f.through(f.task, "POST", "/c/b2"), 409)
  const view = await platform<PlatformApprovalView>(f.tenant, "platform.approvals.get", { params: { approval: held.approval } })
  await platform(f.tenant, "platform.approvals.decide", { params: { approval: held.approval }, body: { decision: "approve", digest: view.digest } })
  const other = await f.workload(f.machine, { projects: [f.project.id], modes: ["placeholder"] }, "globex:grant-2")
  // The first workload's run is no run of the second's.
  expect((await json<{ error: string }>(await f.through(other, "POST", "/c/b2", held.approval), 404)).error).toBe("not_found")
  const theirs = await json<WorkspaceRunCreated>(await signed(f.tenant, other, "/v1/runs", { project: f.project.id, env: "computers", envSource: "flag", remote: null, worktree: "/workspace", head: null, vars: ["THE_KEY"], command: "globex computer" }), 201)
  const placeholder = theirs.vars.find((v) => v.name === "THE_KEY")
  if (placeholder?.delivery !== "placeholder") throw new Error("Expected a placeholder")
  const own = await json<{ error: string; approval: string }>(await signed(f.tenant, other, "/v1/relay", { run: theirs.run, method: "POST", url: `https://${HOST}/c/b2`, headers: [["Authorization", `Bearer ${placeholder.value}`]], approval: held.approval }), 409)
  expect(own.error).toBe("approval_required")
  expect(own.approval).not.toBe(held.approval)
  expect(sent).toEqual([])
  // The workload that asked still spends it.
  await json(await f.through(f.task, "POST", "/c/b2", held.approval))
  expect(sent).toHaveLength(1)
})
