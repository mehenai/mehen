import { env } from "cloudflare:workers"
import { runInDurableObject } from "cloudflare:test"
import { expect, it, vi } from "vitest"
import type { WorkspaceRunCreated } from "@mehen/protocol"
import { prepareCredential,storeCredential } from "../../src/vault/areas/items-workspace.ts"
import { body,workJourney } from "./workspace-journey.ts"

for (const boundary of ["tags","no-lease-mode","reveal-ceiling"] as const) it(`workspace run delivery refuses ${boundary} without decrypting or exposing the credential`,async () => {
  const f = await workJourney(),machine = await f.machine(f.alex,f.work),member = await f.member(f.alex,f.work)
  const secret = "synthetic-run-secret-not-for-output",note = boundary === "reveal-ceiling",field = note ? "text" : "key"
  await runInDurableObject(env.TENANT_VAULT.getByName(f.work.id),async instance => {
    const ctx = instance.context
    const prepared = await prepareCredential(ctx,{ slug: "run-secret",home: { kind: "workspace" },kind: note ? "note" : "api-key",provider: null,account: null,accountVerified: false,tags: ["private"],ceiling: note ? "reveal" : "lease",binding: { hosts: ["api.example.com"] },policy: { default: "allow",rules: [] },injection: null,publicFields: {},secretFields: { [field]: secret },description: null },null)
    ctx.storage.transactionSync(() => storeCredential(ctx,prepared,{ kind: "member",memberId: member,account: f.alex.account,session: "fixture-session",securityEpoch: 0,sessionCheck: null },"item.create"))
  })
  const variable = { project: f.project.id,env: "dev",name: "SECRET",item: "run-secret",field,before: null }
  await body(await f.projectMutation(f.alex,f.work,"variable",variable,`/projects/${f.project.id}/vars/SECRET`))
  await f.sql(f.work,"UPDATE devices SET scope=json_set(scope,'$.modes',json(?),'$.tags',json(?)) WHERE id=?",JSON.stringify(boundary === "no-lease-mode" ? ["relay"] : ["lease"]),JSON.stringify(boundary === "tags" ? ["work"] : []),machine.device)
  // The request itself still enters through worker.fetch and real proof validation.
  const exposures = await f.sql(f.work,"SELECT * FROM exposures ORDER BY event")
  let opens = 0
  await runInDurableObject(env.TENANT_VAULT.getByName(f.work.id),instance => { vi.spyOn(instance.context,"openField").mockImplementation(async () => { opens++; throw new Error("Unexpected secret open") }) })
  try {
    const response = await f.deviceCall(machine,"/v1/runs",{ project: f.project.id,env: "dev",envSource: "flag",remote: null,worktree: "/test",head: null,vars: ["SECRET"],command: "test",argv: ["test"] })
    const result = await body<WorkspaceRunCreated>(response,201)
    expect(result.vars).toEqual([{ name: "SECRET",delivery: "missing",next: { say: boundary === "tags" ? "This variable's credential is outside this machine's reach." : boundary === "no-lease-mode" ? "This variable cannot be delivered in this environment." : "Neither a placeholder nor a lease is permitted." } }])
    expect(JSON.stringify(result)).not.toContain(secret)
    expect(await f.sql(f.work,"SELECT * FROM exposures ORDER BY event")).toEqual(exposures)
    expect(await f.sql(f.work,"SELECT leased_vars FROM runs WHERE id=?",result.run)).toEqual([{ leased_vars: "[]" }])
    expect(opens).toBe(0)
  } finally { await runInDurableObject(env.TENANT_VAULT.getByName(f.work.id),() => vi.restoreAllMocks()) }
})
