// A workload's reach is its device's intersected with its own scope, in
// every area: items, relay, intakes, connections, projects and runs.
import { expect, it } from "vitest"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { body } from "./e2e/workspace-journey.ts"
import { workloadJourney } from "./workload-journey.ts"

const relayModels = (item: string) => ({ item, method: "GET", url: "https://api.openai.com/v1/models", headers: [] })
const runInput = (project: string) => ({ project, env: "dev", envSource: "flag", remote: null, worktree: "/w", head: null, vars: [], command: "true", argv: ["true"] })

async function reachJourney() {
  const f = await workloadJourney()
  await f.credential(f.alex, f.work, "openai-main", { kind: "workspace" })
  await f.credential(f.alex, f.work, "openai-other", { kind: "workspace" })
  return f
}

it("items outside a workload's items are absent from its list and not found on show, as outside a device's scope", async () => {
  const f = await reachJourney()
  const task = await f.createWorkload(f.machine, { items: ["openai-main"] })
  const slugs = async (response: Response) => (await body<{ items: { slug: string }[] }>(response)).items.map((i) => i.slug)
  expect(await slugs(await f.deviceCall(f.machine, "/v1/items"))).toEqual(["openai-main", "openai-other"])
  expect(await slugs(await f.workloadCall(f.as(task), "/v1/items"))).toEqual(["openai-main"])
  expect((await f.workloadCall(f.as(task), "/v1/items/openai-main")).status).toBe(200)
  const hidden = await f.workloadCall(f.as(task), "/v1/items/openai-other")
  const narrowed = await f.enrolMachine(f.alex, f.work)
  await f.sql(f.work, "UPDATE devices SET scope=json_set(scope,'$.tags',json('[\"elsewhere\"]')) WHERE id=?", narrowed.device)
  const outsideDevice = await f.deviceCall(narrowed, "/v1/items/openai-other")
  expect(hidden.status).toBe(outsideDevice.status)
  expect(await hidden.json()).toEqual(await outsideDevice.json())
})

it("a workload relays only what its scope names, in its modes, and is refused as a device outside its scope is", async () => {
  const f = await reachJourney()
  const sends: string[] = []
  setUpstreamFetch(async (request) => { sends.push(request.url); return new Response("ok") })
  try {
    const task = await f.createWorkload(f.machine, { items: ["openai-main"], modes: ["relay"] })
    expect((await f.workloadCall(f.as(task), "/v1/relay", relayModels("openai-main"))).status).toBe(200)
    expect(sends).toHaveLength(1)
    const refused = await f.workloadCall(f.as(task), "/v1/relay", relayModels("openai-other"))
    const narrowed = await f.enrolMachine(f.alex, f.work)
    await f.sql(f.work, "UPDATE devices SET scope=json_set(scope,'$.tags',json('[\"elsewhere\"]')) WHERE id=?", narrowed.device)
    const outsideDevice = await f.deviceCall(narrowed, "/v1/relay", relayModels("openai-other"))
    expect(refused.status).toBe(outsideDevice.status)
    expect(await refused.json()).toEqual(await outsideDevice.json())
    const signOnly = await f.createWorkload(f.machine, { modes: ["sign"] }, "sign-only")
    const noRelay = await f.workloadCall(f.as(signOnly), "/v1/relay", relayModels("openai-main"))
    await f.sql(f.work, "UPDATE devices SET scope=json_set(scope,'$.tags',json('[]'),'$.modes',json('[\"sign\"]')) WHERE id=?", narrowed.device)
    const deviceNoRelay = await f.deviceCall(narrowed, "/v1/relay", relayModels("openai-main"))
    expect(noRelay.status).toBe(deviceNoRelay.status)
    expect(await noRelay.json()).toEqual(await deviceNoRelay.json())
    expect(sends).toHaveLength(1)
  } finally { setUpstreamFetch(null) }
})

it("a workload never reaches a project outside its projects, nor runs there", async () => {
  const f = await reachJourney()
  const task = await f.createWorkload(f.machine, { projects: ["prj_elsewhere"] })
  expect((await f.deviceCall(f.machine, `/v1/projects/${f.project.id}`)).status).toBe(200)
  const project = await f.workloadCall(f.as(task), `/v1/projects/${f.project.id}`)
  expect(project.status).toBe(404)
  const run = await f.workloadCall(f.as(task), "/v1/runs", runInput(f.project.id))
  expect(run.status).toBe(404)
  const inside = await f.createWorkload(f.machine, { projects: [f.project.id] }, "inside")
  expect((await f.workloadCall(f.as(inside), `/v1/projects/${f.project.id}`)).status).toBe(200)
  expect((await f.workloadCall(f.as(inside), "/v1/runs", runInput(f.project.id))).status).toBe(201)
})

it("a workload never reaches what its device cannot, even when its scope names it", async () => {
  const f = await reachJourney()
  await f.sql(f.work, "UPDATE devices SET scope=json_set(scope,'$.tags',json('[\"elsewhere\"]')) WHERE id=?", f.machine.device)
  const task = await f.createWorkload(f.machine, { items: ["openai-main"] })
  expect((await f.workloadCall(f.as(task), "/v1/items/openai-main")).status).toBe(404)
  expect((await body<{ items: unknown[] }>(await f.workloadCall(f.as(task), "/v1/items"))).items).toEqual([])
  const widen = await f.deviceCall(f.machine, "/v1/workloads", { jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" }, label: "wider", scope: { tags: ["other"] } })
  expect(widen.status).toBe(400)
  expect(await widen.json()).toMatchObject({ error: "bad_request", message: expect.stringContaining("scope.tags") })
})

it("a workload asks for an intake or a connection only for a credential its scope names, refused before anything is created", async () => {
  const f = await reachJourney()
  const task = await f.createWorkload(f.machine, { items: ["openai-main", "anthropic-new"] })
  const before = await f.sql(f.work, "SELECT * FROM workspace_credential_requests")
  const intake = await f.workloadCall(f.as(task), "/v1/intakes", { kind: "api-key", slug: "stripe-new", provider: "stripe", reason: "pay", home: "workspace" })
  expect(intake.status).toBe(403)
  expect(await intake.json()).toMatchObject({ error: "forbidden", message: 'This workload may only ask for "openai-main", "anthropic-new".' })
  const connect = await f.workloadCall(f.as(task), "/v1/connect", { provider: "google-gmail", slug: "gmail-new", reason: "mail", home: "workspace" })
  expect(connect.status).toBe(403)
  expect(await f.sql(f.work, "SELECT * FROM workspace_credential_requests")).toEqual(before)
  expect((await f.workloadCall(f.as(task), "/v1/intakes", { kind: "api-key", slug: "anthropic-new", provider: "anthropic", reason: "model", home: "workspace" })).status).toBe(201)
})
