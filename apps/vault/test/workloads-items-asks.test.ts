// A workload scoped by items follows its own asks end to end: it polls and
// waits on its intake, lists it, and learns when a person completes it; a
// workload whose items name the provider's client as well as the connection
// polls and completes a connection and its client intake. A workload whose
// items do not name a slug, or that did not ask, sees nothing.
import { expect, it } from "vitest"
import { body } from "./e2e/workspace-journey.ts"
import { completeStartedConnect, fillIntake } from "./e2e/ui-projects-journey.ts"
import { workloadJourney } from "./workload-journey.ts"

const intake = { kind: "api-key", slug: "openai-task", provider: "openai", reason: "model", home: "workspace" }
const workspace = { kind: "workspace" } as const
type Pending = { pending: { detail?: { id: string } }[] }
const pendingIds = async (response: Response) => (await body<Pending>(response)).pending.flatMap((p) => p.detail ? [p.detail.id] : [])

it("an items-scoped workload polls, waits on, lists and sees the completion of its own intake", async () => {
  const f = await workloadJourney()
  const task = await f.createWorkload(f.machine, { items: ["openai-task"], modes: ["relay"] }, "task-a")
  const created = await body<{ intake: string }>(await f.workloadCall(f.as(task), "/v1/intakes", intake), 201)
  expect(await body(await f.workloadCall(f.as(task), `/v1/intakes/${created.intake}`))).toMatchObject({ intake: created.intake, status: "open" })
  expect(await pendingIds(await f.workloadCall(f.as(task), "/v1/pending"))).toEqual([created.intake])
  await fillIntake(f, f.alex, created.intake, workspace)
  expect(await body(await f.workloadCall(f.as(task), `/v1/intakes/${created.intake}?wait=1`))).toMatchObject({ intake: created.intake, status: "completed", item: { slug: "openai-task" } })
  expect(await pendingIds(await f.workloadCall(f.as(task), "/v1/pending"))).toEqual([])
})

it("a workload whose items do not name a slug sees neither another workload's ask for it nor the device's", async () => {
  const f = await workloadJourney()
  const asker = await f.createWorkload(f.machine, { items: ["openai-task"] }, "asker")
  const outsider = await f.createWorkload(f.machine, { items: ["something-else"] }, "outsider")
  const sibling = await f.createWorkload(f.machine, { items: ["openai-task", "openai-device"] }, "sibling")
  const asked = await body<{ intake: string }>(await f.workloadCall(f.as(asker), "/v1/intakes", intake), 201)
  const own = await body<{ intake: string }>(await f.deviceCall(f.machine, "/v1/intakes", { ...intake, slug: "openai-device" }), 201)
  for (const task of [outsider, sibling]) {
    for (const id of [asked.intake, own.intake]) {
      expect(await body(await f.workloadCall(f.as(task), `/v1/intakes/${id}`), 404)).toEqual({ error: "not_found", message: "No such credential request." })
      expect((await f.workloadCall(f.as(task), `/v1/intakes/${id}?wait=1`)).status).toBe(404)
    }
    expect(await pendingIds(await f.workloadCall(f.as(task), "/v1/pending"))).toEqual([])
  }
})

it("an items-scoped workload naming the provider's client polls and completes a connection and its client intake", async () => {
  const f = await workloadJourney()
  const task = await f.createWorkload(f.machine, { items: ["gmail-task", "google-oauth-client"], modes: ["relay"] }, "task-mail")
  const created = await body<{ connect: string; intake: { intake: string } }>(await f.workloadCall(f.as(task), "/v1/connect", { provider: "google-gmail", slug: "gmail-task", reason: "mail", home: "workspace", requestClient: true }))
  expect(await body(await f.workloadCall(f.as(task), `/v1/connect/${created.connect}`))).toMatchObject({ connect: created.connect, status: "open" })
  expect(await body(await f.workloadCall(f.as(task), `/v1/intakes/${created.intake.intake}`))).toMatchObject({ intake: created.intake.intake, status: "open" })
  expect((await pendingIds(await f.workloadCall(f.as(task), "/v1/pending"))).sort()).toEqual([created.connect, created.intake.intake].sort())
  await fillIntake(f, f.alex, created.intake.intake, workspace)
  expect(await body(await f.workloadCall(f.as(task), `/v1/intakes/${created.intake.intake}`))).toMatchObject({ status: "completed", item: { slug: "google-oauth-client", kind: "oauth-client" } })
  await completeStartedConnect(f, f.alex, f.work, created.connect, workspace, "task-mail")
  expect(await body(await f.workloadCall(f.as(task), `/v1/connect/${created.connect}?wait=1`))).toMatchObject({ connect: created.connect, status: "completed", item: { slug: "gmail-task", kind: "oauth-connection" } })
})

it("an items-scoped workload naming an existing client connects through it, and one naming only the connection is told to list the client", async () => {
  const f = await workloadJourney()
  const client = await body<{ intake: string }>(await f.request(`/api/w/${f.work.slug}/intakes`, f.alex, { provider: "google-oauth-client", slug: "google-oauth-client", home: "workspace" }), 201)
  await fillIntake(f, f.alex, client.intake, workspace)
  const narrow = await f.createWorkload(f.machine, { items: ["gmail-task"] }, "narrow")
  const before = await f.sql(f.work, "SELECT * FROM workspace_credential_requests")
  for (const requestClient of [false, true]) {
    const refused = await f.workloadCall(f.as(narrow), "/v1/connect", { provider: "google-gmail", slug: "gmail-task", reason: "mail", home: "workspace", ...(requestClient ? { requestClient } : {}) })
    expect(await body(refused, 403)).toEqual({ error: "forbidden", message: 'This workload may only ask for "gmail-task". To connect, also list the provider\'s client, "google-oauth-client", in this workload\'s items.', next: { say: "Create a workload whose items name both the connection and its provider's OAuth client." } })
  }
  expect(await f.sql(f.work, "SELECT * FROM workspace_credential_requests")).toEqual(before)
  const task = await f.createWorkload(f.machine, { items: ["gmail-task", "google-oauth-client"] }, "task-mail")
  const created = await body<{ connect: string; intake?: unknown }>(await f.workloadCall(f.as(task), "/v1/connect", { provider: "google-gmail", slug: "gmail-task", reason: "mail", home: "workspace" }))
  expect(created.intake).toBeUndefined()
  expect(await body(await f.workloadCall(f.as(task), `/v1/connect/${created.connect}`))).toMatchObject({ connect: created.connect, status: "open" })
  await completeStartedConnect(f, f.alex, f.work, created.connect, workspace, "task-mail")
  expect(await body(await f.workloadCall(f.as(task), `/v1/connect/${created.connect}`))).toMatchObject({ status: "completed", item: { slug: "gmail-task" } })
})
