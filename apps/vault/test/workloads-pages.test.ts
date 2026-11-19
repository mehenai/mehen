// What people see of workloads: the machine's page lists them and ends one
// with a passkey; ask pages name the task; the audit names it on every row.
import { createProof, webCryptoSigner, type WorkloadView, type WorkspaceStepUpAction } from "@mehen/protocol"
import { expect, it } from "vitest"
import { auditLine } from "../src/ui/wording.ts"
import { ORIGIN } from "./helpers.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"
import { body, refusal } from "./e2e/workspace-journey.ts"
import { protectedJourney } from "./e2e/protected-journey.ts"
import { workloadJourney } from "./workload-journey.ts"

it("a person sees a machine's live workloads and ends one with a passkey over the machine and the workload", async () => {
  const f = await workloadJourney()
  const task = await f.createWorkload(f.machine, { modes: ["relay"] }, "globex:grant-1")
  const base = `/api/w/northwind/devices/${f.machine.device}`
  expect(await body(await f.request(`${base}/workloads`, f.alex))).toEqual({ workloads: [task.view] })
  const page = await (await f.request(`/w/northwind/devices/${f.machine.device}`, f.alex, undefined, { accept: "text/html" })).text()
  expect(page).toContain('data-region="workloads"')
  expect(page).toContain("<code>globex:grant-1</code>")
  expect(page).toContain(`data-action="workload-revoke" data-workload="${task.view.workload}"`)
  const { action } = await body<{ action: WorkspaceStepUpAction }>(await f.request(`${base}/action`, f.alex, { change: { kind: "workload_revoke", workload: task.view.workload } }))
  expect(action).toEqual({ type: "workload.revoke", device: f.machine.device, workload: task.view.workload })
  // A passkey over revoking the machine never ends one workload, nor one over another workload.
  const other = await f.createWorkload(f.machine, {}, "other")
  expect((await f.signed(`${base}/workloads/${task.view.workload}/revoke`, f.alex, {}, { type: "device.revoke", device: f.machine.device }, "northwind")).status).toBe(403)
  expect((await f.signed(`${base}/workloads/${task.view.workload}/revoke`, f.alex, {}, { type: "workload.revoke", device: f.machine.device, workload: other.view.workload }, "northwind")).status).toBe(403)
  expect((await f.workloadCall(f.as(task), "/v1/me")).status).toBe(200)
  const revoked = await body<WorkloadView>(await f.signed(`${base}/workloads/${task.view.workload}/revoke`, f.alex, {}, action, "northwind"))
  expect(revoked).toMatchObject({ workload: task.view.workload, state: "revoked", revokedBy: "member" })
  await refusal(await f.workloadCall(f.as(task), "/v1/me"), 403, { error: "workload_ended", message: "This workload has ended. Create a new one from its device.", next: { say: "This task's workload has ended; its device must create a new workload for it." } })
  expect((await f.workloadCall(f.as(other), "/v1/me")).status).toBe(200)
  expect((await f.request(`/api/w/northwind/devices/dev_absent0001/workloads`, f.alex)).status).toBe(404)
})

it("an approval a workload asked for names the task on its page, and every audit row it caused names it", async () => {
  const f = await protectedJourney()
  const keys = await newDeviceKey()
  const view = await body<WorkloadView>(await f.deviceCall(f.machine, "/v1/workloads", { jwk: await publicJwk(keys), label: "globex:grant-9", scope: {} }), 201)
  const input = { project: f.project.id, env: "prod", envSource: "flag", remote: null, worktree: "/integration", head: null, vars: ["TOKEN"], command: "node test.js", argv: ["node", "test.js"] }
  const proof = await createProof(webCryptoSigner(f.machine.device, keys.privateKey, view.workload), { method: "POST", url: `${ORIGIN}/v1/runs`, body: JSON.stringify(input) }, { tenant: f.work.id })
  const asked = await body<{ approval: string }>(await f.request("/v1/runs", undefined, input, { "Mehen-Proof": proof }), 409)
  const detail = await body<{ view: string; approval: { requestedBy: { workload?: { id: string; label: string } } } }>(await f.request(`/api/w/northwind/approvals/${asked.approval}`, f.tom))
  expect(detail.approval.requestedBy.workload).toEqual({ id: view.workload, label: "globex:grant-9" })
  const page = await (await f.request(`/w/northwind/a/${asked.approval}`, f.tom, undefined, { accept: "text/html" })).text()
  expect(page).toContain('Task: <b>globex:grant-9</b>, as the machine named it')
  const rows = await f.sql<{ actor: string; action: string; target: string | null; detail: string }>(f.work, "SELECT actor,action,target,detail FROM audit WHERE action IN ('approval.request','workload.created') ORDER BY seq")
  const request = rows.find((r) => r.action === "approval.request")!
  expect(JSON.parse(request.detail)).toMatchObject({ by: { workload: { id: view.workload, label: "globex:grant-9" } } })
  const words = { self: null, devices: new Map([[f.machine.device, "integration-machine"]]) }
  expect(auditLine(request, words).pieces.map((p) => p.text).join("")).toContain(". Task: globex:grant-9, as the machine named it")
  expect(auditLine(rows.find((r) => r.action === "workload.created")!, words).pieces.map((p) => p.text).join("")).toBe(" created the workload globex:grant-9 on integration-machine")
  // No key, thumbprint or proof in any row.
  const jwk = await publicJwk(keys)
  for (const row of await f.sql<{ detail: string }>(f.work, "SELECT detail FROM audit")) for (const secret of [view.thumbprint, jwk.x, jwk.y]) expect(row.detail).not.toContain(secret)
})
