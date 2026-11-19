// Service runs started by a workload, through the real Worker: a workload
// acts within its device's scope, so a machine allowed service runs lets its
// workloads start them, and they still end with the workload.
import { expect, it } from "vitest"
import type { WorkspaceRunCreated } from "@mehen/protocol"
import { body } from "./e2e/workspace-journey.ts"
import { workloadJourney } from "./workload-journey.ts"

it("a service run started by a workload renews with no hard end and ends when the workload is revoked", async () => {
  const f = await workloadJourney()
  await f.credential(f.alex, f.work, "openai-main", { kind: "workspace" })
  await body(await f.deviceCall(f.machine, `/v1/projects/${f.project.id}/vars/OPENAI_KEY`, { env: "dev", item: "openai-main", field: "key" }, undefined, undefined, "PUT"))
  await f.sql(f.work, "UPDATE devices SET scope=json_set(scope,'$.serviceRuns',json('true')) WHERE id=?", f.machine.device)
  const task = await f.createWorkload(f.machine, { projects: [f.project.id], modes: ["placeholder"] }, "resident")
  const input = { project: f.project.id, env: "dev", envSource: "flag", remote: null, worktree: "/workspace", head: null, vars: ["OPENAI_KEY"], command: "bot", service: true }
  const run = await body<WorkspaceRunCreated>(await f.workloadCall(f.as(task), "/v1/runs", input), 201)
  expect(run.endsAt).toBeNull()
  expect(await f.sql(f.work, "SELECT workload,service FROM runs WHERE id=?", run.run)).toEqual([{ workload: task.view.workload, service: 1 }])
  expect(await body(await f.workloadCall(f.as(task), `/v1/runs/${run.run}/renew`, {}))).toMatchObject({ run: run.run, endsAt: null })
  await body(await f.deviceCall(f.machine, `/v1/workloads/${task.view.workload}`, undefined, undefined, undefined, "DELETE"))
  const after = await f.workloadCall(f.as(task), `/v1/runs/${run.run}/renew`, {})
  expect({ status: after.status, error: (await after.json() as { error: string }).error }).toEqual({ status: 403, error: "workload_ended" })
  expect(await f.sql<{ ended: number }>(f.work, "SELECT ended_at IS NOT NULL AS ended FROM runs WHERE id=?", run.run)).toEqual([{ ended: 1 }])
})
