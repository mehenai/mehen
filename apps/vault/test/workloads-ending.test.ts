// Workloads end with their machine's owner through the real routes: a
// suspended, removed or departed owner ends every workload of their
// machines as owner_inactive; a revoked machine ends them as device_revoked.
// The expiry sweep runs from the scheduled alarm and ends what an expired
// workload asked for.
import { createProof, fingerprintGroupIndex, fingerprintGroups, fingerprintOf, jwkThumbprint, webCryptoSigner, type TeamView, type WorkspaceStepUpAction } from "@mehen/protocol"
import { expect, it } from "vitest"
import { auditLine } from "../src/ui/wording.ts"
import { ORIGIN } from "./helpers.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"
import { body, type Machine, type Person } from "./e2e/workspace-journey.ts"
import { workloadJourney, type Workload } from "./workload-journey.ts"

const ended = { error: "workload_ended", message: "This workload has ended. Create a new one from its device.", next: { say: "This task's workload has ended; its device must create a new workload for it." } }
const WS = "northwind"

// Tom, a member with his own machine, one of whose tasks has an open intake.
async function ownerJourney() {
  const f = await workloadJourney()
  const tom = await f.guest(f.alex, f.work, f.project.id, "Tom")
  await body(await f.memberChange(f.alex, f.work, tom.member!, "role", "member"))
  const machine = await f.enrolMachine(tom, f.work)
  const task = await f.createWorkload(machine, { items: ["stripe-task"], modes: ["relay"] }, "tom-task")
  const asked = await body<{ intake: string }>(await f.workloadCall(f.as(task), "/v1/intakes", { kind: "api-key", slug: "stripe-task", provider: "stripe", reason: "payments", home: "private" }), 201)
  async function endedAs(reason: "owner_inactive" | "device_revoked") {
    expect(await f.sql(f.work, "SELECT revoked_by,ended_at IS NOT NULL AS ended FROM workloads WHERE id=?", task.view.workload)).toEqual([{ revoked_by: reason, ended: 1 }])
    expect(await f.sql(f.work, "SELECT status FROM workspace_credential_requests WHERE id=?", asked.intake)).toEqual([{ status: "cancelled" }])
    const refused = await f.workloadCall(f.as(task), "/v1/me")
    expect(refused.status).toBe(403)
    expect(await refused.json()).toEqual(ended)
    const rows = await f.sql<{ actor: string; action: string; target: string | null; detail: string }>(f.work, "SELECT actor,action,target,detail FROM audit WHERE action='workload.revoke_all'")
    expect(rows).toHaveLength(1)
    expect(JSON.parse(rows[0]!.detail)).toMatchObject({ device: machine.device, reason, workloads: [{ id: task.view.workload, label: "tom-task" }] })
    return auditLine(rows[0]!, { self: null, devices: new Map([[machine.device, "integration-machine"]]) }).pieces.map((p) => p.text).join("")
  }
  return { ...f, tom, tomMachine: machine, task, endedAs }
}

async function memberAction(f: Awaited<ReturnType<typeof ownerJourney>>, person: Person, member: string, change: "suspend" | "reinstate") {
  const { action } = await body<{ action: WorkspaceStepUpAction }>(await f.request(`/api/w/${WS}/members/${member}/action`, person, { change }))
  return body(await f.signed(`/api/w/${WS}/members/${member}/${change}`, person, {}, action, WS))
}

it("suspending the owner through the people route ends their machines' workloads as owner_inactive, and reinstating them does not bring one back", async () => {
  const f = await ownerJourney()
  await memberAction(f, f.alex, f.tom.member!, "suspend")
  expect(await f.endedAs("owner_inactive")).toBe(" ended every workload of integration-machine, because its owner lost access")
  await memberAction(f, f.alex, f.tom.member!, "reinstate")
  expect((await f.deviceCall(f.tomMachine, "/v1/me")).status).toBe(200)
  expect(await body(await f.deviceCall(f.tomMachine, `/v1/workloads/${f.task.view.workload}`))).toMatchObject({ state: "revoked", revokedBy: "owner_inactive" })
  expect((await f.workloadCall(f.as(f.task), "/v1/me")).status).toBe(403)
})

it("removing the owner through the people route ends their machines' workloads as owner_inactive", async () => {
  const f = await ownerJourney()
  expect(await body(await f.memberChange(f.alex, f.work, f.tom.member!, "remove"))).toEqual({ removed: true, member: f.tom.member })
  expect(await f.endedAs("owner_inactive")).toBe(" ended every workload of integration-machine, because its owner lost access")
})

it("the owner leaving through the leave route ends their machines' workloads as owner_inactive", async () => {
  const f = await ownerJourney()
  expect(await body(await f.signed(`/api/w/${WS}/leave`, f.tom, {}, { type: "member.leave", member: f.tom.member! }, WS))).toEqual({ removed: true, member: f.tom.member })
  expect(await f.endedAs("owner_inactive")).toBe(" ended every workload of integration-machine, because its owner lost access")
})

it("revoking the machine on its page ends its workloads as device_revoked", async () => {
  const f = await ownerJourney()
  const { action } = await body<{ action: WorkspaceStepUpAction }>(await f.request(`/api/w/${WS}/devices/${f.tomMachine.device}/action`, f.alex, { change: { kind: "revoke" } }))
  await body(await f.signed(`/api/w/${WS}/devices/${f.tomMachine.device}/revoke`, f.alex, {}, action, WS))
  expect(await f.endedAs("device_revoked")).toBe(" ended every workload of integration-machine, because the machine was revoked")
})

// A team is deleted only once its machines are revoked, so revoking them is
// what ends their workloads; the team.delete ending is a backstop for a
// machine the team still somehow owns (workloads.test.ts drives that hook).
it("a team's machine keeps its workloads until it is revoked, and the team cannot be deleted before that", async () => {
  const f = await workloadJourney()
  const { action: create } = await body<{ action: WorkspaceStepUpAction }>(await f.request(`/api/w/${WS}/teams/action`, f.alex, { kind: "create", name: "Bots", slug: "bots" }))
  const team = await body<TeamView>(await f.signed(`/api/w/${WS}/teams`, f.alex, { team: create.type === "team.update" ? create.team : "", name: "Bots", slug: "bots" }, create, WS), 201)
  const machine = await teamMachine(f, team)
  const task = await f.createWorkload(machine, {}, "bot-task")
  const { action: remove } = await body<{ action: WorkspaceStepUpAction }>(await f.request(`/api/w/${WS}/teams/action`, f.alex, { kind: "delete", team: team.id }))
  expect(await body(await f.signed(`/api/w/${WS}/teams/${team.id}/update`, f.alex, { change: "delete" }, remove, WS), 409)).toEqual({ error: "conflict", message: "Revoke its machines first." })
  expect((await f.workloadCall(f.as(task), "/v1/me")).status).toBe(200)
  const { action: revoke } = await body<{ action: WorkspaceStepUpAction }>(await f.request(`/api/w/${WS}/devices/${machine.device}/action`, f.alex, { change: { kind: "revoke" } }))
  await body(await f.signed(`/api/w/${WS}/devices/${machine.device}/revoke`, f.alex, {}, revoke, WS))
  expect(await f.sql(f.work, "SELECT revoked_by FROM workloads WHERE id=?", task.view.workload)).toEqual([{ revoked_by: "device_revoked" }])
  expect(await body(await f.signed(`/api/w/${WS}/teams/${team.id}/update`, f.alex, { change: "delete" }, remove, WS))).toEqual({ deleted: true, team: team.id })
})

// A machine a team owns, admitted by an owner on its enrolment page.
async function teamMachine(f: Awaited<ReturnType<typeof workloadJourney>>, team: TeamView): Promise<Machine> {
  const keys = await newDeviceKey(), jwk = await publicJwk(keys)
  const input = { workspace: f.work.slug, owner: { kind: "team", team: team.id }, name: "bot-runner", backend: "software", jwk }
  const proof = await createProof(webCryptoSigner("new", keys.privateKey), { method: "POST", url: `${ORIGIN}/v1/enrol`, body: JSON.stringify(input) }, { tenant: "enrol" })
  const started = await body<{ enrolment: string; code: string }>(await f.request("/v1/enrol", undefined, input, { "Mehen-Proof": proof }), 201)
  const view = await body<{ digest: string }>(await f.request(`/api/w/${WS}/enrolments/${started.code}`, f.alex))
  const group = fingerprintGroups(fingerprintOf(await jwkThumbprint(jwk)))[await fingerprintGroupIndex(started.code)]!
  const action: WorkspaceStepUpAction = { type: "enrol.approve", enrolment: started.enrolment, digest: view.digest, owner: { kind: "team", team: team.id, name: team.name }, admissionRole: "owner" }
  expect(await body(await f.signed(`/api/w/${WS}/enrolments/${started.code}/admit`, f.alex, { group }, action, WS))).toMatchObject({ state: "active" })
  const active = await body<{ device: string }>(await f.deviceCall({ keys, device: started.enrolment, workspace: f.work }, `/v1/enrol/${started.enrolment}`, undefined, "enrol"))
  return { keys, device: active.device, workspace: f.work }
}

it("the scheduled alarm sweeps an expired workload once and ends what it asked for", async () => {
  const f = await workloadJourney()
  const task: Workload = await f.createWorkload(f.machine, { items: ["stripe-task"] }, "task-expire")
  const asked = await body<{ intake: string }>(await f.workloadCall(f.as(task), "/v1/intakes", { kind: "api-key", slug: "stripe-task", provider: "stripe", reason: "payments", home: "workspace" }), 201)
  expect(await f.sql(f.work, "SELECT due_at FROM schedule WHERE area='devices' AND key='workloads'")).toEqual([{ due_at: Date.parse(task.view.expiresAt) }])
  const past = Date.now() - 1000
  await f.sql(f.work, "UPDATE workloads SET expires_at=? WHERE id=?", past, task.view.workload)
  await f.sql(f.work, "UPDATE schedule SET due_at=? WHERE area='devices' AND key='workloads'", past)
  const { runInDurableObject } = await import("cloudflare:test")
  const { env } = await import("cloudflare:workers")
  await runInDurableObject(env.TENANT_VAULT.getByName(f.work.id), async (instance) => { await instance.alarm() })
  expect(await f.sql(f.work, "SELECT ended_at IS NOT NULL AS ended,revoked_by FROM workloads WHERE id=?", task.view.workload)).toEqual([{ ended: 1, revoked_by: null }])
  expect(await f.sql(f.work, "SELECT status FROM workspace_credential_requests WHERE id=?", asked.intake)).toEqual([{ status: "cancelled" }])
  expect(await f.sql(f.work, "SELECT action FROM audit WHERE action='workload.expired'")).toHaveLength(1)
  await f.sql(f.work, "INSERT INTO schedule(area,key,due_at) VALUES ('devices','workloads',?) ON CONFLICT(area,key) DO UPDATE SET due_at=excluded.due_at", past)
  await runInDurableObject(env.TENANT_VAULT.getByName(f.work.id), async (instance) => { await instance.alarm() })
  expect(await f.sql(f.work, "SELECT action FROM audit WHERE action='workload.expired'")).toHaveLength(1)
})
