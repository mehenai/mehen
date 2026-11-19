// A workload never opens an ask it could not then follow: an intake or a
// connection for a credential its scope's tags or projects would hide from it
// is refused before anything is created or counted. One it can see, it polls.
import { expect, it } from "vitest"
import { body } from "./e2e/workspace-journey.ts"
import { workloadJourney } from "./workload-journey.ts"

const intake = (slug: string, extra: Record<string, unknown> = {}) => ({ kind: "api-key", slug, provider: "openai", reason: "model", home: "workspace", ...extra })
const next = { say: "Ask for a credential this task's workload can see, or create a workload whose scope covers it." }
const requests = (f: Awaited<ReturnType<typeof workloadJourney>>) => f.sql(f.work, "SELECT id FROM workspace_credential_requests ORDER BY id")

it("a tags-scoped workload asking with none of its tags, or none at all, is refused and nothing is created or counted", async () => {
  const f = await workloadJourney()
  const task = await f.createWorkload(f.machine, { tags: ["t1", "t2"] }, "task-tags")
  for (const [slug, extra] of [["untagged", {}], ["no-tags", { tags: [] }], ["other-tags", { tags: ["t3"] }]] as const) {
    expect(await body(await f.workloadCall(f.as(task), "/v1/intakes", intake(slug, extra)), 403)).toEqual({ error: "forbidden", message: `This workload could not see "${slug}". To ask for it, give it one of this workload's tags: "t1", "t2".`, next })
  }
  for (const requestClient of [false, true]) {
    expect(await body(await f.workloadCall(f.as(task), "/v1/connect", { provider: "google-gmail", slug: "gmail-task", reason: "mail", home: "workspace", ...(requestClient ? { requestClient, clientTags: ["t3"] } : {}) }), 403)).toEqual({ error: "forbidden", message: `This workload could not see "gmail-task". To ask for it, give it one of this workload's tags: "t1", "t2".`, next })
  }
  expect(await requests(f)).toEqual([])
  // Not counted: the workload still has all five of its open asks.
  for (let n = 0; n < 5; n++) expect((await f.workloadCall(f.as(task), "/v1/intakes", intake(`own-${n}`, { tags: ["t2"] }))).status).toBe(201)
})

it("a tags-scoped workload asking with one of its tags polls and lists its intake and its connection", async () => {
  const f = await workloadJourney()
  const task = await f.createWorkload(f.machine, { tags: ["t1"] }, "task-tags")
  const created = await body<{ intake: string }>(await f.workloadCall(f.as(task), "/v1/intakes", intake("tagged", { tags: ["t1", "other"] })), 201)
  expect(await body(await f.workloadCall(f.as(task), `/v1/intakes/${created.intake}`))).toMatchObject({ intake: created.intake, status: "open" })
  const connect = await body<{ connect: string; intake: { intake: string } }>(await f.workloadCall(f.as(task), "/v1/connect", { provider: "google-gmail", slug: "gmail-task", reason: "mail", home: "workspace", requestClient: true, clientTags: ["t1"] }))
  expect(await body(await f.workloadCall(f.as(task), `/v1/connect/${connect.connect}`))).toMatchObject({ connect: connect.connect, status: "open" })
  expect(await body(await f.workloadCall(f.as(task), `/v1/intakes/${connect.intake.intake}`))).toMatchObject({ intake: connect.intake.intake, status: "open" })
  const pending = await body<{ pending: { detail?: { id: string } }[] }>(await f.workloadCall(f.as(task), "/v1/pending"))
  expect(pending.pending.flatMap((p) => p.detail ? [p.detail.id] : []).sort()).toEqual([created.intake, connect.connect, connect.intake.intake].sort())
})

it("a projects-scoped workload asking for a credential homed outside its projects is refused, and one homed inside polls", async () => {
  const f = await workloadJourney()
  const other = await body<{ id: string }>(await f.deviceCall(f.machine, "/v1/projects", { slug: "other-project", remote: null, defaultEnv: "dev", environments: [{ name: "dev", protected: false }] }), 201)
  const task = await f.createWorkload(f.machine, { projects: [f.project.id] }, "task-project")
  const before = await requests(f)
  expect(await body(await f.workloadCall(f.as(task), "/v1/intakes", intake("elsewhere", { home: "project", project: other.id })), 403)).toEqual({ error: "forbidden", message: `This workload could not see "elsewhere". To ask for it, home it in one of this workload's projects: "${f.project.id}".`, next })
  expect(await requests(f)).toEqual(before)
  const created = await body<{ intake: string }>(await f.workloadCall(f.as(task), "/v1/intakes", intake("inside", { home: "project", project: f.project.id })), 201)
  expect(await body(await f.workloadCall(f.as(task), `/v1/intakes/${created.intake}`))).toMatchObject({ intake: created.intake, status: "open" })
})

it("a tags-scoped workload rotating a credential it sees is judged by that credential's tags, not the request's", async () => {
  const f = await workloadJourney()
  await f.credential(f.alex, f.work, "tagged-key", { kind: "workspace" })
  await f.sql(f.work, "UPDATE items SET tags=? WHERE slug=?", JSON.stringify(["t1"]), "tagged-key")
  const task = await f.createWorkload(f.machine, { tags: ["t1"] }, "task-rotate")
  const created = await body<{ intake: string }>(await f.workloadCall(f.as(task), "/v1/intakes", intake("tagged-key")), 201)
  expect(await body(await f.workloadCall(f.as(task), `/v1/intakes/${created.intake}`))).toMatchObject({ intake: created.intake, status: "open" })
})

it("the device's own key never replaces a workload's ask, nor a workload the device's", async () => {
  const f = await workloadJourney()
  await f.credential(f.alex, f.work, "openai-main", { kind: "workspace" })
  await f.sql(f.work, "UPDATE items SET policy=? WHERE slug=?", JSON.stringify({ default: "approve", rules: [] }), "openai-main")
  const task = await f.createWorkload(f.machine, { items: ["openai-main"], modes: ["relay"] }, "task-relay")
  const relay = (path: string, replaces?: string) => ({ item: "openai-main", method: "POST", url: `https://api.openai.com/v1/${path}`, headers: [], ...(replaces ? { replaces } : {}) })
  const asked = await body<{ approval: string }>(await f.workloadCall(f.as(task), "/v1/relay", relay("files")), 409)
  const own = await body<{ approval: string }>(await f.deviceCall(f.machine, "/v1/relay", relay("files?purpose=other")), 409)
  for (const [response, replaced] of [[await f.deviceCall(f.machine, "/v1/relay", relay("files?purpose=again", asked.approval)), asked.approval], [await f.workloadCall(f.as(task), "/v1/relay", relay("files?purpose=again", own.approval)), own.approval]] as const) {
    expect(await body(response, 400)).toEqual({ error: "bad_request", message: `${replaced} is not an open ask from this machine to the same place.` })
  }
  expect(await f.sql(f.work, "SELECT id,policy_status FROM approvals ORDER BY id")).toEqual([asked.approval, own.approval].sort().map((id) => ({ id, policy_status: null })))
})
