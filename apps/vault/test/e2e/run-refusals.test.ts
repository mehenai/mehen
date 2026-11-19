import { expect, it } from "vitest"
import type { WorkspaceRunCreated } from "@mehen/protocol"
import { protectedJourney } from "./protected-journey.ts"
import { body, refusal, workJourney } from "./workspace-journey.ts"

const inputFor = (project: string) => ({ project, env: "prod", envSource: "flag", remote: null, worktree: "/integration", head: null, vars: ["TOKEN"], command: "node test.js", argv: ["node", "test.js"] })
type Journey = Pick<Awaited<ReturnType<typeof workJourney>>,"sql" | "work">
async function runState(f: Journey) {
  return Promise.all(["runs","workspace_run_contexts","run_authorisations","run_placeholders","approvals","protected_use_grants","consent_lineage","exposures"].map(table => f.sql(f.work,`SELECT * FROM ${table} ORDER BY rowid`)))
}

for (const change of ["remote","implicit-env","undeclared","long-argument","long-total"] as const) it(`run planning refuses ${change} without creating runs or approvals`,async () => {
  const f = await protectedJourney(),input = inputFor(f.project.id)
  const changes = {
    remote: { remote: "github.com/evil/other" },
    "implicit-env": { envSource: "default" },
    undeclared: { vars: ["TOKEN","NOT_DECLARED"] },
    "long-argument": { argv: ["node","x".repeat(1025)] },
    "long-total": { argv: Array(5).fill("x".repeat(1000)) },
  }
  const expected = {
    remote: { status: 403,error: "remote_mismatch",message: "This checkout does not match the project's bound repository." },
    "implicit-env": { status: 403,error: "environment_refused",message: "A protected run needs a literal --env." },
    undeclared: { status: 400,error: "bad_request",message: "The project does not declare NOT_DECLARED." },
    "long-argument": { status: 403,error: "mode_refused",message: "Send a complete command line small enough for a person to approve." },
    "long-total": { status: 403,error: "mode_refused",message: "Send a complete command line small enough for a person to approve." },
  }[change]
  const before = await runState(f)
  await refusal(await f.deviceCall(f.machine,"/v1/runs",{ ...input,...changes[change] }),expected.status,{ error: expected.error,message: expected.message })
  expect(await runState(f)).toEqual(before)
})

for (const change of ["argv","command","variables"] as const) it(`protected run approval binding refuses changed ${change} and retains the approved request`,async () => {
  const f = await protectedJourney(),approved = await f.askRun()
  await f.approve(approved)
  const before = await runState(f),original = await f.sql(f.work,"SELECT * FROM approvals WHERE id=?",approved)
  const patch = change === "argv" ? { argv: ["node","evil.js"] } : change === "command" ? { command: "node evil.js" } : { vars: [] }
  const response = await f.deviceCall(f.machine,"/v1/runs",{ ...inputFor(f.project.id),...patch,approval: approved })
  const error = await body<{ approval: string }>(response,409)
  expect(error).toEqual({ error: "approval_required",message: "This protected run needs approval.",approval: expect.stringMatching(/^apr_/),bindingCode: expect.any(String),expiresAt: expect.any(String),deciders: ["Tom"],next: { url: `https://vault.test/w/northwind/a/${error.approval}`,command: `mehen wait ${error.approval}`,say: "Send this link to Tom." } })
  expect(error.approval).not.toBe(approved)
  expect(await f.sql(f.work,"SELECT * FROM approvals WHERE id=?",approved)).toEqual(original)
  expect((await runState(f)).filter((_,i) => i !== 4)).toEqual(before.filter((_,i) => i !== 4))
  expect(await f.sql(f.work,"SELECT status FROM approvals WHERE id=?",error.approval)).toEqual([{ status: "pending" }])
  // The refused substitution did not consume the original start grant.
  await f.run(approved)
})

it("another machine cannot end a run owned by the enrolled requester",async () => {
  const f = await protectedJourney(),other = await f.protectedMachine(f.alex,f.work),approval = await f.askRun()
  await f.approve(approval)
  const run = await f.run(approval),before = await runState(f)
  await refusal(await f.deviceCall(other,`/v1/runs/${run.run}`,undefined,undefined,undefined,"DELETE"),404,{ error: "not_found",message: "No such object." })
  expect(await runState(f)).toEqual(before)
  expect(await f.sql(f.work,"SELECT ended_at FROM runs WHERE id=?",run.run)).toEqual([{ ended_at: null }])
})

it("repository unbound mid-run refuses renewal without changing the live run",async () => {
  const f = await workJourney(),machine = await f.machine(f.alex,f.work),remote = "github.com/acme/platform"
  const binding = { project: f.project.id,remote,bound: true }
  await body(await f.projectMutation(f.alex,f.work,"remote",binding,`/projects/${f.project.id}/remotes`))
  await body(await f.projectMutation(f.alex,f.work,"remote",{ ...binding,remote: "github.com/acme/replacement" },`/projects/${f.project.id}/remotes`))
  const run = await body<WorkspaceRunCreated>(await f.deviceCall(machine,"/v1/runs",{ ...inputFor(f.project.id),env: "dev",vars: [],remote }),201)
  await body(await f.projectMutation(f.alex,f.work,"remote",{ ...binding,bound: false },`/projects/${f.project.id}/remotes`))
  const before = await runState(f)
  await refusal(await f.deviceCall(machine,`/v1/runs/${run.run}/renew`,{}),403,{ error: "remote_mismatch",message: "This run's repository is no longer bound." })
  expect(await runState(f)).toEqual(before)
})

it("a protected run refuses a mid-run lease of a declared credential the approval did not show",async () => {
  const f = await protectedJourney()
  await f.credential(f.tom,f.work,"unshown-key",{ kind: "workspace" })
  await body(await f.projectMutation(f.alex,f.work,"variable",{ project: f.project.id,env: "prod",name: "UNSHOWN",item: "unshown-key",field: "key",before: null },`/projects/${f.project.id}/vars/UNSHOWN`))
  await f.sql(f.work,"UPDATE items SET injection=NULL,ceiling='lease' WHERE slug IN ('prod-key','unshown-key')")
  await f.sql(f.work,"UPDATE devices SET scope=json_set(scope,'$.modes',json('[\"relay\",\"placeholder\",\"lease\"]')) WHERE id=?",f.machine.device)
  const approval = await f.askRun()
  await f.approve(approval)
  const run = await body<WorkspaceRunCreated>(await f.deviceCall(f.machine,"/v1/runs",{ ...inputFor(f.project.id),approval }),201)
  expect(run.vars).toEqual([{ name: "TOKEN",delivery: "lease",value: "sk-integration-not-a-real-secret",item: "prod-key" }])
  expect(await f.sql(f.work,"SELECT leased_vars FROM runs WHERE id=?",run.run)).toEqual([{ leased_vars: '["TOKEN"]' }])
  const before = await runState(f)
  await refusal(await f.deviceCall(f.machine,"/v1/lease",{ run: run.run,item: "unshown-key",field: "key" }),403,{ error: "mode_refused",message: "This run did not authorise a lease of this field." })
  expect(await runState(f)).toEqual(before)
  // The refused lease does not revoke what the person actually authorised.
  expect(await body(await f.deviceCall(f.machine,"/v1/lease",{ run: run.run,item: "prod-key",field: "key" }))).toEqual({ value: "sk-integration-not-a-real-secret",expiresAt: run.expiresAt })
})

it("protected run approval binding refuses a stored id whose binding digest no longer matches",async () => {
  const f = await protectedJourney(),approval = await f.askRun()
  await f.approve(approval)
  const [stored] = await f.sql<{ binding_digest: string }>(f.work,"SELECT binding_digest FROM approvals WHERE id=?",approval)
  // Isolate the binding-digest check from the independent snapshot guard.
  await f.sql(f.work,"UPDATE approvals SET binding_digest='changed-binding' WHERE id=?",approval)
  const before = await runState(f)
  const response = await f.deviceCall(f.machine,"/v1/runs",{ ...inputFor(f.project.id),approval })
  const error = await body<{ approval: string }>(response,409)
  expect(error).toEqual({ error: "approval_required",message: "This protected run needs approval.",approval: expect.stringMatching(/^apr_/),bindingCode: expect.any(String),expiresAt: expect.any(String),deciders: ["Tom"],next: { url: `https://vault.test/w/northwind/a/${error.approval}`,command: `mehen wait ${error.approval}`,say: "Send this link to Tom." } })
  expect(error.approval).not.toBe(approval)
  expect((await runState(f)).filter((_,i) => i !== 4)).toEqual(before.filter((_,i) => i !== 4))
  await f.sql(f.work,"UPDATE approvals SET binding_digest=? WHERE id=?",stored!.binding_digest,approval)
  await f.run(approval)
})
