import { expect,it } from "vitest"
import { AccountSessionSchema,WorkspaceAuditPageSchema } from "@mehen/protocol"
import type { WorkspaceStepUpAction } from "@mehen/protocol"
import { body,refusal } from "./workspace-journey.ts"
import { protectedJourney } from "./protected-journey.ts"

it("cutover: default-on bootstrap, recovery, two workspaces, invite/join, signed enrolment, credential, project/environment, protected run, approval and audit",async () => {
  // This helper uses worker.fetch throughout: bootstrap and real passkey,
  // acknowledged recovery, Personal then Northwind, project, invited guest's
  // recovery and join/confirmation, manager promotion, signed enrolment and
  // protected-scope acceptance, a sealed workspace credential and prod ref.
  const f = await protectedJourney()
  const account = AccountSessionSchema.parse(await body(await f.request("/api/account",f.alex)))
  expect(account.memberships.map(m => m.workspace.id).sort()).toEqual([f.personal.id,f.work.id].sort())
  expect(account.recoverySetupRequired).toBe(false)
  expect(f.personal.id).not.toBe(f.work.id)
  expect((await f.request("/workspaces/new",f.alex,undefined,{ accept: "text/html" })).status).toBe(200)
  const id = await f.askRun()
  const before = await f.snapshot(f.work)
  await refusal(await f.request(`/api/w/northwind/approvals/${id}/action`,f.alex,{ decision: "approve" }),403,{ error: "forbidden",message: "You are not allowed to do that." })
  expect(await f.snapshot(f.work)).toEqual(before)
  await f.approve(id)
  const run = await f.run(id)
  expect(run.env).toBe("prod")
  expect(run.vars.map(v => v.name)).toEqual(["TOKEN"])
  const audit = WorkspaceAuditPageSchema.parse(await body(await f.request("/api/w/northwind/audit",f.alex)))
  expect(audit.verified).toBe(true)
  expect(audit.filtered).toBe(false)
  for (const action of ["workspace.create","member.join","member.confirm","device.enrol","item.create","project.create","approval.approve","run.create"]) expect(audit.events.some(event => event.action === action),action).toBe(true)
  const own = WorkspaceAuditPageSchema.parse(await body(await f.request("/api/w/alex/audit",f.alex)))
  expect(own.events.some(event => event.target === f.project.id || event.target === f.machine.device)).toBe(false)
  await refusal(await f.request("/api/members",f.alex),404,{ error: "not_found",message: "No such operation." })
})
