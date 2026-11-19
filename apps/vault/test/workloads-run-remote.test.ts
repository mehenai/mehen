// A workload whose scope names a project in projects runs it with no remote,
// even when the project binds remotes: its device chose the project for it,
// and it has no checkout to mismatch (pinnedWorkloadRun). Everything else
// keeps the remote check: a device's own key, a workload scoped by items,
// tags or nothing, any non-null remote, and every protected environment.
import { createProof, webCryptoSigner, type WorkspaceRunCreated } from "@mehen/protocol"
import { afterEach, expect, it } from "vitest"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"
import { ORIGIN } from "./helpers.ts"
import { body, refusal } from "./e2e/workspace-journey.ts"
import { protectedJourney } from "./e2e/protected-journey.ts"
import { workloadJourney } from "./workload-journey.ts"

afterEach(() => setUpstreamFetch(null))

const REMOTE = "github.com/acme/platform"
const mismatch = { error: "remote_mismatch", message: "This checkout does not match the project's bound repository." }
const runInput = (project: string, remote: string | null = null) => ({ project, env: "dev", envSource: "flag", remote, worktree: "/workspace", head: null, vars: ["OPENAI_KEY"], command: "globex computer" })

async function boundJourney() {
  const f = await workloadJourney()
  await f.credential(f.alex, f.work, "openai-main", { kind: "workspace" })
  await body(await f.deviceCall(f.machine, `/v1/projects/${f.project.id}/vars/OPENAI_KEY`, { env: "dev", item: "openai-main", field: "key" }, undefined, undefined, "PUT"))
  const bind = (project: string, remote: string, bound = true) => f.projectMutation(f.alex, f.work, "remote", { project, remote, bound }, `/projects/${project}/remotes`)
  await body(await bind(f.project.id, REMOTE))
  const runs = () => f.sql(f.work, "SELECT id FROM runs ORDER BY rowid")
  return { ...f, bind, runs }
}

it("a pinned workload creates, renews, relays through and ends a run with no remote in a project that binds remotes", async () => {
  const f = await boundJourney()
  const task = await f.createWorkload(f.machine, { projects: [f.project.id], modes: ["placeholder"] }, "globex:grant-1")
  const run = await body<WorkspaceRunCreated>(await f.workloadCall(f.as(task), "/v1/runs", runInput(f.project.id)), 201)
  const key = run.vars.find((v) => v.name === "OPENAI_KEY")
  if (key?.delivery !== "placeholder") throw new Error("Expected a placeholder")
  expect(run.interceptHosts).toEqual(["api.openai.com"])
  expect(await f.sql(f.work, "SELECT workload,remote FROM runs WHERE id=?", run.run)).toEqual([{ workload: task.view.workload, remote: null }])
  const [audit] = await f.sql<{ detail: string }>(f.work, "SELECT detail FROM audit WHERE action='run.create' AND target=?", run.run)
  const detail = JSON.parse(audit!.detail) as Record<string, unknown>
  expect(detail).toMatchObject({ project: f.project.id, env: "dev", remote: null, pinnedWorkload: true, by: { workload: { id: task.view.workload, label: "globex:grant-1" } } })
  expect(JSON.stringify(detail)).not.toContain(key.value)

  expect((await f.workloadCall(f.as(task), `/v1/runs/${run.run}/renew`, {})).status).toBe(200)
  const sends: (string | null)[] = []
  setUpstreamFetch(async (request) => { sends.push(request.headers.get("authorization")); return new Response("ok", { headers: { "content-type": "text/plain" } }) })
  const relayed = await f.workloadCall(f.as(task), "/v1/relay", { run: run.run, method: "GET", url: "https://api.openai.com/v1/models", headers: [["Authorization", `Bearer ${key.value}`]] })
  expect(relayed.status).toBe(200)
  expect(await relayed.text()).toBe("ok")
  expect(sends).toHaveLength(1)
  expect(sends[0]).not.toContain(key.value)

  // Binding or unbinding remotes later does not end it: there is no checkout to mismatch.
  await body(await f.bind(f.project.id, "github.com/acme/replacement"))
  await body(await f.bind(f.project.id, REMOTE, false))
  expect((await f.workloadCall(f.as(task), `/v1/runs/${run.run}/renew`, {})).status).toBe(200)
  expect(await body(await f.workloadCall(f.as(task), `/v1/runs/${run.run}`, undefined, "DELETE"))).toEqual({ run: run.run, ended: true })
})

it("a pinned workload's run that names a remote is checked as today", async () => {
  const f = await boundJourney()
  const task = await f.createWorkload(f.machine, { projects: [f.project.id] })
  const before = await f.runs()
  await refusal(await f.workloadCall(f.as(task), "/v1/runs", runInput(f.project.id, "github.com/evil/other")), 403, mismatch)
  expect(await f.runs()).toEqual(before)
  expect((await f.workloadCall(f.as(task), "/v1/runs", runInput(f.project.id, REMOTE))).status).toBe(201)
})

it("a device's own key and a workload whose scope names no projects are remote_mismatch with no remote", async () => {
  const f = await boundJourney()
  const before = await f.runs()
  await refusal(await f.deviceCall(f.machine, "/v1/runs", runInput(f.project.id)), 403, mismatch)
  for (const [index, scope] of [{ items: ["openai-main"] }, { tags: ["task"] }, {}].entries()) {
    const task = await f.createWorkload(f.machine, scope, `task-${index}`)
    await refusal(await f.workloadCall(f.as(task), "/v1/runs", runInput(f.project.id)), 403, mismatch)
  }
  expect(await f.runs()).toEqual(before)
})

it("a device's own run with no remote still stops when the project gains a remote", async () => {
  const f = await workloadJourney()
  const run = await body<WorkspaceRunCreated>(await f.deviceCall(f.machine, "/v1/runs", { ...runInput(f.project.id), vars: [] }), 201)
  await body(await f.projectMutation(f.alex, f.work, "remote", { project: f.project.id, remote: REMOTE, bound: true }, `/projects/${f.project.id}/remotes`))
  await refusal(await f.deviceCall(f.machine, `/v1/runs/${run.run}/renew`, {}), 403, { error: "remote_mismatch", message: "This run's repository is no longer bound." })
})

it("a pinned workload's run in another project is refused as a device scoped to that project is", async () => {
  const f = await boundJourney()
  const other = await body<{ id: string }>(await f.deviceCall(f.machine, "/v1/projects", { slug: "other-project", remote: null, defaultEnv: "dev", environments: [{ name: "dev", protected: false }] }), 201)
  await body(await f.bind(other.id, "github.com/acme/other"))
  const task = await f.createWorkload(f.machine, { projects: [f.project.id] })
  const scoped = await f.enrolMachine(f.alex, f.work)
  await f.sql(f.work, "UPDATE devices SET scope=json_set(scope,'$.projects',json(?)) WHERE id=?", JSON.stringify([f.project.id]), scoped.device)
  const input = { ...runInput(other.id), vars: [] }
  const before = await f.runs()
  const refused = await f.workloadCall(f.as(task), "/v1/runs", input)
  const device = await f.deviceCall(scoped, "/v1/runs", input)
  expect(refused.status).toBe(404)
  expect(device.status).toBe(404)
  expect(await refused.json()).toEqual(await device.json())
  expect(await f.runs()).toEqual(before)
})

it("a protected environment keeps the remote check for a pinned workload: remote_mismatch, nothing created", async () => {
  const f = await protectedJourney()
  await body(await f.projectMutation(f.alex, f.work, "remote", { project: f.project.id, remote: REMOTE, bound: true }, `/projects/${f.project.id}/remotes`))
  const pair = await newDeviceKey()
  const view = await body<{ workload: string }>(await f.deviceCall(f.machine, "/v1/workloads", { jwk: await publicJwk(pair), label: "pinned", scope: { projects: [f.project.id] } }), 201)
  const input = { project: f.project.id, env: "prod", envSource: "flag", remote: null, worktree: "/workspace", head: null, vars: ["TOKEN"], command: "node test.js", argv: ["node", "test.js"] }
  const proof = await createProof(webCryptoSigner(f.machine.device, pair.privateKey, view.workload), { method: "POST", url: `${ORIGIN}/v1/runs`, body: JSON.stringify(input) }, { tenant: f.work.id })
  const tables = () => Promise.all(["runs", "approvals", "protected_use_grants"].map((table) => f.sql(f.work, `SELECT * FROM ${table} ORDER BY rowid`)))
  const before = await tables()
  await refusal(await f.request("/v1/runs", undefined, input, { "Mehen-Proof": proof }, "POST"), 403, mismatch)
  expect(await tables()).toEqual(before)
})

it("a pinned workload's run with no remote is held off another environment's fenced host, as a device's run is", async () => {
  const f = await boundJourney()
  await body(await f.projectMutation(f.alex, f.work, "environment", { project: f.project.id, env: "prod", protected: true, fourEyes: true, fences: ["api.openai.com"], before: { protected: true, fourEyes: true, fences: [] } }, `/projects/${f.project.id}/environments/prod`))
  const sends: string[] = []
  setUpstreamFetch(async (request) => { sends.push(request.url); return new Response("ok", { headers: { "content-type": "text/plain" } }) })
  const fenced = { error: "environment_refused", message: "api.openai.com is fenced to another environment of this project, and this run is env=dev. Nothing was sent, and this was recorded." }
  const relayThrough = async (call: (path: string, input: unknown) => Promise<Response>, run: WorkspaceRunCreated) => {
    const key = run.vars.find((v) => v.name === "OPENAI_KEY")
    if (key?.delivery !== "placeholder") throw new Error("Expected a placeholder")
    const response = await call("/v1/relay", { run: run.run, method: "GET", url: "https://api.openai.com/v1/models", headers: [["Authorization", `Bearer ${key.value}`]] })
    expect({ status: response.status, body: await response.json() }).toMatchObject({ status: 403, body: fenced })
  }
  await relayThrough((path, input) => f.deviceCall(f.machine, path, input), await body<WorkspaceRunCreated>(await f.deviceCall(f.machine, "/v1/runs", runInput(f.project.id, REMOTE)), 201))
  const task = await f.createWorkload(f.machine, { projects: [f.project.id], modes: ["placeholder"] }, "globex:fenced")
  await relayThrough((path, input) => f.workloadCall(f.as(task), path, input), await body<WorkspaceRunCreated>(await f.workloadCall(f.as(task), "/v1/runs", runInput(f.project.id)), 201))
  expect(sends).toEqual([])
  expect(await f.sql(f.work, "SELECT count(*) AS n FROM audit WHERE action='relay.tripwire'")).toEqual([{ n: 2 }])
})
