// @mehen/client against the real Worker and Durable Object: the client's own
// fetch is worker.fetch, so every proof, path, body and answer shape it uses
// is the vault's, not a fake's. A person accepts through the journey helpers.
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test"
import { CLIENT_VERSION, MehenRefusal, createClient, deviceSigner, enrolmentStatus, generateKey, startEnrolment, workloadSigner, type EnrolRequestedScope, type Fetcher, type MehenClient } from "@mehen/client"
import { canonicalJson, sha256B64, type WorkspaceDeviceScope, type WorkspaceStepUpAction } from "@mehen/protocol"
import { expect, it } from "vitest"
import worker from "../src/index.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { ORIGIN } from "./helpers.ts"
import { body, workJourney, type Person } from "./e2e/workspace-journey.ts"

type Work = Awaited<ReturnType<typeof workJourney>>

const HOST_PRODUCT = "globex/2.4.1"
const asked: EnrolRequestedScope = { modes: ["relay"], workloads: "required", privateCredentials: false }
const accepted: WorkspaceDeviceScope = { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay"], privateCredentials: false, workloads: "required" }
const relayModels = (item: string) => ({ item, method: "GET", url: "https://api.openai.com/v1/models" })

function workerFetch(f: Work): Fetcher {
  return async (request) => {
    const ctx = createExecutionContext()
    // An outgoing request as the Worker receives it: no incoming cf properties.
    const response = await worker.fetch(request as Request<unknown, IncomingRequestCfProperties>, f.env, ctx)
    await waitOnExecutionContext(ctx)
    return response
  }
}

async function refused(call: Promise<unknown>): Promise<MehenRefusal> {
  try {
    await call
  } catch (error) {
    if (error instanceof MehenRefusal) return error
    throw error
  }
  throw new Error("Expected a refusal")
}

const said = (refusal: MehenRefusal) => ({ code: refusal.code, status: refusal.status, message: refusal.message, next: refusal.next })

// The machine's owner widens it to protected environments, as the machine's
// page does: a proposal and an acceptance, each under a passkey.
async function allowProtected(f: Work, person: Person, device: string, before: WorkspaceDeviceScope) {
  const after = { ...before, maxEnvironment: "protected" as const }, base = `/api/w/${f.work.slug}/devices/${device}`
  const { action } = await body<{ action: WorkspaceStepUpAction }>(await f.request(`${base}/action`, person, { change: { kind: "rescope_propose", before, after } }))
  const proposal = await body<{ id: string }>(await f.signed(`${base}/rescope`, person, { before, after }, action, f.work.slug))
  const planned = await body<{ action: WorkspaceStepUpAction }>(await f.request(`${base}/action`, person, { change: { kind: "rescope_accept", proposal: proposal.id } }))
  expect(await body(await f.signed(`${base}/rescope-accept`, person, { proposal: proposal.id }, planned.action, f.work.slug))).toMatchObject({ afterDigest: await sha256B64(canonicalJson(after)), state: "committed" })
  return after
}

it("a host enrols a scoped machine, gives each task its own workload, and ends them, all through @mehen/client", async () => {
  const f = await workJourney()
  const fetch = workerFetch(f)
  const connection = { vaultUrl: ORIGIN, fetch, userAgent: HOST_PRODUCT }

  // 1. Scoped enrolment: started by the client, accepted by a person.
  const deviceKey = await generateKey()
  const started = await startEnrolment({ ...connection, key: deviceKey, workspace: f.work.slug, owner: { kind: "self" }, name: "Globex agent", host: "globex.ai", scope: asked })
  expect(started).toMatchObject({ enrolment: expect.stringMatching(/^enr_/), url: `${ORIGIN}/w/${f.work.slug}/e/${started.code}` })
  expect(await enrolmentStatus({ ...connection, key: deviceKey, enrolment: started.enrolment })).toMatchObject({ status: "pending_owner_acceptance" })

  // 5. The enrol page names the client library and the host's product, never a browser.
  const view = await body<{ scope: WorkspaceDeviceScope; requested: unknown; start: { clientLabel: string } }>(await f.request(`/api/w/${f.work.slug}/enrolments/${started.code}`, f.alex))
  expect(view).toMatchObject({ scope: accepted, requested: asked, start: { clientLabel: `mehen-client ${CLIENT_VERSION} (${HOST_PRODUCT})` } })
  const page = await (await f.request(`/w/${f.work.slug}/e/${started.code}`, f.alex, undefined, { accept: "text/html" })).text()
  expect(page).toContain(`mehen-client ${CLIENT_VERSION} (${HOST_PRODUCT})`)
  expect(page).not.toContain("A browser")
  expect(page).toContain("Acts only through short-lived workloads")

  const start = { keys: { privateKey: deviceKey.privateKey, publicKey: deviceKey.publicKey }, started: { enrolment: started.enrolment, code: started.code, url: started.url }, thumbprint: started.fingerprint.thumbprint, group: started.fingerprint.groups[started.hiddenGroup] }
  await body(await f.acceptMachine(f.alex, f.work, start, false))
  const active = await enrolmentStatus({ ...connection, key: deviceKey, enrolment: started.enrolment })
  if (active.status !== "active") throw new Error(`Enrolment is ${active.status}`)
  expect(active).toMatchObject({ device: expect.stringMatching(/^dev_/), tenant: f.work.id, workspace: f.work, scope: accepted })

  // 2. The device's own key reads itself and may not relay.
  const device = createClient({ ...connection, tenant: active.tenant, signer: deviceSigner(active.device, deviceKey.privateKey) })
  const me = await device.me()
  expect(me).toMatchObject({ device: active.device, name: "Globex agent", scope: accepted, workspace: f.work })
  expect("workload" in me).toBe(false)
  await f.credential(f.alex, f.work, "openai-main", { kind: "workspace" })
  await f.credential(f.alex, f.work, "openai-other", { kind: "workspace" })
  const required = await refused(device.relay(relayModels("openai-main")))
  expect(said(required)).toEqual({ code: "workload_required", status: 403, message: "This machine acts only through workloads.", next: { say: "Create a workload for this task with the machine's key and sign the request with the workload's key." } })

  // 3. A workload for one item relays it, and nothing else.
  const taskKey = await generateKey()
  const created = await device.workloads.create({ jwk: taskKey.jwk, label: "globex:grant-1", scope: { items: ["openai-main"] } })
  expect(created).toMatchObject({ workload: expect.stringMatching(/^wl_/), device: active.device, label: "globex:grant-1", scope: { items: ["openai-main"] }, state: "active" })
  const task: MehenClient = createClient({ ...connection, tenant: active.tenant, signer: workloadSigner(active.device, created.workload, taskKey.privateKey) })
  const taskMe = await task.me()
  expect(taskMe).toMatchObject({ device: active.device, workload: { workload: created.workload, label: "globex:grant-1", state: "active" } })
  const sends: string[] = []
  setUpstreamFetch(async (request) => { sends.push(request.url); return new Response("ok", { headers: { "content-type": "text/plain" } }) })
  try {
    const relayed = await task.relay(relayModels("openai-main"))
    expect({ kind: relayed.kind, status: relayed.status, body: new TextDecoder().decode(relayed.body) }).toEqual({ kind: "response", status: 200, body: "ok" })
    expect(sends).toEqual(["https://api.openai.com/v1/models"])
    const outsideTask = await refused(task.relay(relayModels("openai-other")))
    const narrowed = await f.machine(f.alex, f.work)
    await f.sql(f.work, "UPDATE devices SET scope=json_set(scope,'$.tags',json('[\"elsewhere\"]')) WHERE id=?", narrowed.device)
    const outsideDevice = await refused(createClient({ ...connection, tenant: f.work.id, signer: deviceSigner(narrowed.device, narrowed.keys.privateKey) }).relay(relayModels("openai-other")))
    expect(said(outsideTask)).toEqual(said(outsideDevice))
    expect(sends).toHaveLength(1)

    // A protected item: the refusal carries everything a host shows a person.
    await allowProtected(f, f.alex, active.device, me.scope)
    await f.credential(f.alex, f.work, "prod-key", { kind: "workspace" })
    await body(await f.projectMutation(f.alex, f.work, "variable", { project: f.project.id, name: "TOKEN", env: "prod", item: "prod-key", field: "key", before: null }, `/projects/${f.project.id}/vars/TOKEN`))
    const guardedKey = await generateKey()
    const guardedView = await device.workloads.create({ jwk: guardedKey.jwk, label: "globex:grant-2", ttlSeconds: 600, scope: { items: ["prod-key"] } })
    const guarded = createClient({ ...connection, tenant: active.tenant, signer: workloadSigner(active.device, guardedView.workload, guardedKey.privateKey) })
    const ask = await refused(guarded.relay({ ...relayModels("prod-key"), context: { project: f.project.id, environment: "prod" } }))
    expect(ask).toMatchObject({ code: "approval_required", status: 409, approval: expect.stringMatching(/^apr_/), bindingCode: expect.stringMatching(/\S/), expiresAt: expect.any(String) })
    expect(ask.link).toBe(`${ORIGIN}/w/${f.work.slug}/a/${ask.approval}`)
    // A workload waits with its own key (client.approval), so no mehen wait command; the device's own ask keeps it.
    expect(ask.next?.command).toBeUndefined()
    expect(new URL(ask.link!).origin).toBe(ORIGIN)
    expect(await guarded.approval(ask.approval!)).toMatchObject({ approval: ask.approval, status: "pending", bindingCode: ask.bindingCode, expiresAt: ask.expiresAt })
    const own = await f.machine(f.alex, f.work)
    const [stored] = await f.sql<{ scope: string }>(f.work, "SELECT scope FROM devices WHERE id=?", own.device)
    await allowProtected(f, f.alex, own.device, JSON.parse(stored!.scope) as WorkspaceDeviceScope)
    const ownClient = createClient({ ...connection, tenant: f.work.id, signer: deviceSigner(own.device, own.keys.privateKey) })
    const deviceAsk = await refused(ownClient.relay({ ...relayModels("prod-key"), context: { project: f.project.id, environment: "prod" } }))
    expect(deviceAsk).toMatchObject({ code: "approval_required", next: { command: `mehen wait ${deviceAsk.approval}` } })
    expect(sends).toHaveLength(1)

    // 4. List, renew and revoke; the revoked workload's next request is refused.
    expect((await device.workloads.list()).map((w) => w.workload).sort()).toEqual([created.workload, guardedView.workload].sort())
    const renewed = await device.workloads.renew(created.workload, { ttlSeconds: 7200 })
    expect(Date.parse(renewed.expiresAt)).toBeGreaterThan(Date.parse(created.expiresAt))
    const revoked = await device.workloads.revoke(created.workload)
    expect(revoked).toMatchObject({ workload: created.workload, state: "revoked", revokedBy: "device" })
    expect(await device.workloads.revoke(created.workload)).toEqual(revoked)
    const ended = await refused(task.relay(relayModels("openai-main")))
    expect(said(ended)).toEqual({ code: "workload_ended", status: 403, message: "This workload has ended. Create a new one from its device.", next: { say: "This task's workload has ended; its device must create a new workload for it." } })
    expect((await device.workloads.list()).map((w) => w.workload)).toEqual([guardedView.workload])

    // Revoking the device ends its other live workload on the next request.
    expect((await guarded.me()).workload?.workload).toBe(guardedView.workload)
    await device.revokeSelf()
    expect(said(await refused(guarded.me()))).toEqual(said(ended))
    expect(sends).toHaveLength(1)
  } finally {
    setUpstreamFetch(null)
  }
})

it("a host gives a task a project's environment through @mehen/client: a pinned workload, a run with no remote, a streamed relay through the run, and the run ended with the workload", async () => {
  const f = await workJourney()
  const fetch = workerFetch(f)
  const connection = { vaultUrl: ORIGIN, fetch, userAgent: HOST_PRODUCT }
  const machine = await f.machine(f.alex, f.work)
  const device = createClient({ ...connection, tenant: f.work.id, signer: deviceSigner(machine.device, machine.keys.privateKey) })
  await f.credential(f.alex, f.work, "openai-main", { kind: "workspace" })
  await body(await f.projectMutation(f.alex, f.work, "remote", { project: f.project.id, remote: "github.com/acme/platform", bound: true }, `/projects/${f.project.id}/remotes`))
  await body(await f.deviceCall(machine, `/v1/projects/${f.project.id}/vars/OPENAI_API_KEY`, { env: "dev", item: "openai-main", field: "key" }, undefined, undefined, "PUT"))
  await body(await f.deviceCall(machine, `/v1/projects/${f.project.id}/vars/DATABASE_HOST`, { env: "dev", plain: "db.internal" }, undefined, undefined, "PUT"))

  const taskKey = await generateKey()
  const created = await device.workloads.create({ jwk: taskKey.jwk, label: "globex:grant-3", scope: { projects: [f.project.id], modes: ["placeholder"] } })
  const task = createClient({ ...connection, tenant: f.work.id, session: "globex:thread-1", signer: workloadSigner(machine.device, created.workload, taskKey.privateKey) })
  const project = await task.project(f.project.id)
  expect(project).toMatchObject({ id: f.project.id, slug: "platform", remotes: ["github.com/acme/platform"], defaultEnv: "dev" })
  const names = project.vars.filter((v) => v.env === "dev").map((v) => v.name).sort()
  expect(names).toEqual(["DATABASE_HOST", "OPENAI_API_KEY"])

  const run = await task.runs.create({ project: f.project.id, env: "dev", envSource: "flag", remote: null, worktree: "/workspace", head: null, vars: names, command: "globex computer" })
  expect(run.vars.map((v) => ({ name: v.name, delivery: v.delivery }))).toEqual([{ name: "DATABASE_HOST", delivery: "plain" }, { name: "OPENAI_API_KEY", delivery: "placeholder" }])
  expect(run.interceptHosts).toEqual(["api.openai.com"])
  expect(await f.sql(f.work, "SELECT workload,session,remote FROM runs WHERE id=?", run.run)).toEqual([{ workload: created.workload, session: "globex:thread-1", remote: null }])
  const key = run.vars.find((v) => v.delivery === "placeholder")
  if (key?.delivery !== "placeholder") throw new Error("Expected a placeholder")

  const sent: (string | null)[] = []
  setUpstreamFetch(async (request) => {
    sent.push(request.headers.get("authorization"))
    return new Response("data: one\n\ndata: two\n\n", { headers: { "content-type": "text/event-stream" } })
  })
  try {
    const streamed = await task.relayStream({ run: run.run, method: "POST", url: "https://api.openai.com/v1/responses", headers: [["authorization", `Bearer ${key.value}`], ["content-type", "application/json"]], body: "{}" })
    expect({ kind: streamed.kind, status: streamed.status, type: streamed.headers.get("content-type") }).toEqual({ kind: "stream", status: 200, type: "text/event-stream" })
    expect(await new Response(streamed.body).text()).toBe("data: one\n\ndata: two\n\n")
    expect(sent).toHaveLength(1)
    expect(sent[0]).not.toContain(key.value)
    const buffered = await task.relay({ run: run.run, method: "GET", url: "https://api.openai.com/v1/models", headers: [["authorization", `Bearer ${key.value}`]] })
    expect(buffered.status).toBe(200)

    // Only the workload that created the run renews or ends it; the device's own key finds none.
    expect(said(await refused(device.runs.renew(run.run)))).toMatchObject({ code: "not_found" })
    expect(Date.parse((await task.runs.renew(run.run)).expiresAt)).toBeGreaterThan(Date.now())
    expect(said(await refused(device.runs.end(run.run)))).toMatchObject({ code: "not_found" })

    // Revoking the workload ends the run: its placeholder no longer relays.
    await device.workloads.revoke(created.workload)
    expect(await f.sql(f.work, "SELECT ended_at IS NOT NULL AS ended FROM runs WHERE id=?", run.run)).toEqual([{ ended: 1 }])
    expect(said(await refused(task.relayStream({ run: run.run, method: "GET", url: "https://api.openai.com/v1/models", headers: [["authorization", `Bearer ${key.value}`]] })))).toMatchObject({ code: "workload_ended" })
    expect(sent).toHaveLength(2)
  } finally {
    setUpstreamFetch(null)
  }
})
