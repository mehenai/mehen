import { env } from "cloudflare:workers"
import { createExecutionContext } from "cloudflare:test"
import worker from "../../src/index.ts"
import { ORIGIN } from "../helpers.ts"
import { expect, it } from "vitest"
import type { WorkspaceRunCreated, WorkspaceStepUpAction } from "@mehen/protocol"
import { setUpstreamFetch } from "../../src/relay/upstream.ts"
import { body, refusal, workJourney } from "./workspace-journey.ts"

it("personal override: real passkey source choice, owner-only Worker run, signed relay, unticked refusal and clear", async () => {
  const f = await workJourney(), base = `/api/w/${f.work.slug}/projects/${f.project.id}`
  const ownMember = await f.member(f.alex, f.work)
  const shared = await f.credential(f.alex, f.work, "shared-key", { kind: "workspace" })
  const privateKey = await f.credential(f.alex, f.work, "personal-key", { kind: "member", member: ownMember })
  await body(await f.projectMutation(f.alex, f.work, "variable", { project: f.project.id, env: "dev", name: "TOKEN", before: null, item: "shared-key", field: "key" }, `/projects/${f.project.id}/vars/TOKEN`))
  const input = { environment: "dev", variable: "TOKEN", source: { kind: "item", item: "personal-key", field: "key" } }
  const action = await body<WorkspaceStepUpAction>(await f.request(`${base}/overrides/action`, f.alex, input))
  expect(action).toEqual({ type: "override.set", project: f.project.id, ...input, source: { ...input.source, item: privateKey.id } })
  expect(await body(await f.signed(`${base}/overrides`, f.alex, input, action, f.work.slug))).toMatchObject({ overrides: [{ ...input }] })
  const machine = await f.machine(f.alex, f.work)
  expect(await body(await f.deviceCall(machine, `/v1/projects/${f.project.id}/overrides`))).toEqual({ overrides: [{ environment: "dev", variable: "TOKEN", source: { kind: "item", item: "personal-key", field: "key" } }] })
  const runInput = { project: f.project.id, env: "dev", envSource: "flag", remote: null, worktree: "/fixture", head: null, vars: ["TOKEN"], command: "test", argv: ["test"] }
  const run = await body<WorkspaceRunCreated>(await f.deviceCall(machine, "/v1/runs", runInput), 201)
  expect(run.overrides).toEqual(["TOKEN"])
  expect(run.vars).toEqual([expect.objectContaining({ name: "TOKEN", delivery: "placeholder", item: "personal-key" })])
  const token = run.vars[0]
  if (token?.delivery !== "placeholder") throw new Error("Expected the personal placeholder")
  let sends = 0
  setUpstreamFetch(async request => { sends++; expect(request.headers.get("authorization")).toBe("Bearer sk-integration-not-a-real-secret"); return new Response("override-ok") })
  try {
    const response = await f.deviceCall(machine, "/v1/relay", { run: run.run, method: "GET", url: "https://api.openai.com/v1/models", headers: [["authorization", `Bearer ${token.value}`]] })
    expect(response.status).toBe(200); expect(await response.text()).toBe("override-ok"); expect(sends).toBe(1)
  } finally { setUpstreamFetch(null) }
  const before = await f.snapshot(f.work)
  const foreign = await f.guest(f.alex, f.work, f.project.id, "Tom")
  expect(await body(await f.request(`${base}/overrides`, foreign))).toEqual({ overrides: [] })
  const foreignInput = { ...input, source: { kind: "item", item: "personal-key", field: "key" } }
  const hidden = await f.request(`${base}/overrides/action`, foreign, foreignInput)
  const absent = await f.request(`${base}/overrides/action`, foreign, { ...foreignInput, source: { kind: "item", item: "absent-key", field: "key" } })
  expect(hidden.status).toBe(404); expect(await hidden.text()).toBe(await absent.text())
  expect(JSON.stringify(await body(await f.request(`${base}/overrides`, foreign)))).not.toContain(privateKey.id)
  const untickedStart = await f.startMachine(f.work)
  await body(await f.acceptMachine(f.alex, f.work, untickedStart, false))
  const pending = { keys: untickedStart.keys, device: untickedStart.started.enrolment, workspace: f.work }
  const active = await body<{ device: string }>(await f.deviceCall(pending, `/v1/enrol/${untickedStart.started.enrolment}`, undefined, "enrol"))
  await refusal(await f.deviceCall({ ...pending, device: active.device }, "/v1/runs", runInput), 404, { error: "not_found", message: "No such object.", next: { say: "Use a machine allowed to reach your private credentials, or clear your override." } })
  const clear = { ...input, source: null }
  const clearAction = await body<WorkspaceStepUpAction>(await f.request(`${base}/overrides/action`, f.alex, clear))
  expect(await body(await f.signed(`${base}/overrides`, f.alex, clear, clearAction, f.work.slug))).toEqual({ overrides: [] })
  const sharedRun = await body<WorkspaceRunCreated>(await f.deviceCall(machine, "/v1/runs", runInput), 201)
  expect(sharedRun.overrides).toEqual([])
  expect(sharedRun.vars[0]).toMatchObject({ item: "shared-key" })
  expect(shared.id).not.toBe(privateKey.id)
  expect(before.overrides).toHaveLength(1)
})
