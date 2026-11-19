import { expect } from "vitest"
import type { WorkspaceStepUpAction } from "@mehen/protocol"
import type { WorkspaceRunCreated } from "@mehen/protocol"
import { body, workJourney, type Machine, type Person } from "./workspace-journey.ts"

export async function protectedJourney() {
  const f = await workJourney()
  const tom = await f.guest(f.alex, f.work, f.project.id, "Tom")
  await body(await f.memberChange(f.alex, f.work, tom.member!, "role", "admin"))
  const machine = await f.protectedMachine(f.alex, f.work)
  const sharedCredential = await f.credential(tom, f.work, "prod-key", { kind: "workspace" })
  const variable = { project: f.project.id, name: "TOKEN", env: "prod", item: "prod-key", field: "key", before: null }
  await body(await f.projectMutation(f.alex, f.work, "variable", variable, `/projects/${f.project.id}/vars/TOKEN`))
  const runInput = { project: f.project.id, env: "prod", envSource: "flag", remote: null, worktree: "/integration", head: null, vars: ["TOKEN"], command: "node test.js", argv: ["node", "test.js"] }
  async function askRun(caller: Machine = machine) {
    const response = await f.deviceCall(caller, "/v1/runs", runInput)
    const error = await body<{ error: string; message: string; approval: string; bindingCode: string; expiresAt: string; deciders: string[]; next: { url: string; command: string; say: string } }>(response, 409)
    expect(error).toEqual({ error: "approval_required", message: "This protected run needs approval.", approval: expect.stringMatching(/^apr_/), bindingCode: expect.any(String), expiresAt: expect.any(String), deciders: expect.any(Array), next: { url: `https://vault.test/w/northwind/a/${error.approval}`, command: `mehen wait ${error.approval}`, say: error.deciders.length ? `Send this link to ${error.deciders.join(" or ")}.` : "Send this link to a manager of platform." } })
    expect(await f.sql(f.work, "SELECT status,policy_status FROM approvals WHERE id=?", error.approval)).toEqual([{ status: "pending", policy_status: null }])
    return error.approval
  }
  async function approve(id: string, decider: Person = tom) {
    const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/northwind/approvals/${id}/action`, decider, { decision: "approve" }))
    const result = await body(await f.signed(`/api/w/northwind/approvals/${id}/decide`, decider, { decision: "approve" }, action, "northwind"))
    expect(await f.sql(f.work, "SELECT status FROM approvals WHERE id=?", id)).toEqual([{ status: "approved" }])
    return result
  }
  async function run(id: string, caller: Machine = machine) {
    const created = await body<WorkspaceRunCreated>(await f.deviceCall(caller, "/v1/runs", { ...runInput, approval: id }), 201)
    expect(created).toEqual({ run: expect.stringMatching(/^run_/), expiresAt: expect.any(String), endsAt: expect.any(String), project: { id: f.project.id, slug: "platform" }, env: "prod", vars: [{ name: "TOKEN", delivery: "placeholder", value: expect.any(String), item: "prod-key", hosts: ["api.openai.com"] }], interceptHosts: ["api.openai.com"], fencedHosts: [], overrides: [], authorisation: { id: expect.stringMatching(/^rau_/), context: { project: f.project.id, environment: "prod" }, expiresAt: expect.any(String) } })
    return created
  }
  async function relay(created: WorkspaceRunCreated, caller: Machine = machine) {
    const value = created.vars[0]
    if (!value || value.delivery !== "placeholder") throw new Error("No placeholder")
    return f.deviceCall(caller, "/v1/relay", { run: created.run, method: "GET", url: "https://api.openai.com/v1/models", headers: [["Authorization", `Bearer ${value.value}`]] })
  }
  return { ...f, tom, machine, sharedCredential, askRun, approve, run, relay }
}
