import { canonicalJson } from "@mehen/protocol"
import { accessFixture, inAccess, accountAuth } from "./access-test-support.ts"
import { accessMember } from "./workspace-fixtures.ts"
import { projectAccessState, projectWorkspaceOps } from "../src/vault/areas/projects-workspace.ts"
import { workspaceApprovalOps } from "../src/vault/areas/approvals-workspace.ts"
import { workspaceApprovalBatchOps } from "../src/vault/areas/approvals-batch-workspace.ts"
import { accessState, registerAccessStateProvider } from "../src/vault/areas/workspace-runtime.ts"
import type { AccessState } from "../src/vault/access.ts"
import type { VaultContext } from "../src/vault/core.ts"
import type { WorkspaceStepUpAction } from "@mehen/protocol"
import { items } from "../src/vault/areas/items.ts"

export async function projectFixture() {
  const f = await accessFixture()
  await inAccess(f.tenant, async (ctx) => {
    for (const c of f.state.credentials) {
      const item = await items.putItem(ctx, { slug: c.id.replace("itm_", "key-"), kind: "api-key", provider: null, account: null, accountVerified: false, tags: [], ceiling: "placeholder", binding: { hosts: ["api.example.com"] }, policy: { default: "approve", rules: [] }, injection: { in: "header", name: "Authorization", format: "Bearer {key}" }, publicFields: {}, secretFields: { key: "test-fixture-key-not-a-live-secret" }, description: null }, { kind: "system", reason: "test" })
      const oldId = c.id
      c.id = item.id
      for (const p of f.state.projects) for (const e of p.environments) for (const r of e.references) if (r.item === oldId) r.item = item.id
    }
    for (const p of f.state.projects) {
      fixtureSql(ctx).exec("INSERT INTO projects(id,slug,default_env,created_by,created_at,updated_at) VALUES(?,?,'dev','member:mem_owner',?,?)", p.id, p.id.replace("prj_", "project-"), ctx.now(), ctx.now())
      for (const e of p.environments) {
        ctx.sql.exec("INSERT INTO environments(project,name,protected,fences,four_eyes) VALUES(?,?,?,?,?)", p.id, e.name, e.protected ? 1 : 0, JSON.stringify(e.fences), e.fourEyes ? 1 : 0)
        for (const r of e.references) {
          const slug = ctx.sql.exec<{ slug: string }>("SELECT slug FROM items WHERE id=?", r.item).toArray()[0]!.slug
          ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES(?,?,?,?,?,'member:mem_owner',?)", p.id, e.name, r.variable, slug, r.field, ctx.now())
        }
      }
    }
    ctx.sql.exec("UPDATE access_fixture_state SET value=?", canonicalJson(f.state))
    registerAccessStateProvider("projects", (ctx, credentials) => ({ projects: projectAccessState(ctx, credentials) }))
  })
  return f
}
export function callProject(ctx: VaultContext, state: AccessState, role: string, op: string, input: unknown, action?: WorkspaceStepUpAction) {
  const spec = projectWorkspaceOps[op] ?? workspaceApprovalOps[op] ?? workspaceApprovalBatchOps[op]
  if (!spec) throw new Error(`No workspace op ${op}`)
  return spec.handler(ctx, accessMember(state, role), input, { auth: accountAuth(role, action), workspace: { id: ctx.tenant, slug: "work", name: "Work" } })
}
export function projectState(ctx: VaultContext) { return accessState(ctx) }
export { inAccess, accountAuth }

import { createProof } from "@mehen/protocol"
import { workspaceRunOps } from "../src/vault/areas/runs-workspace.ts"
import { workspaceApproval } from "../src/vault/areas/approvals-workspace.ts"
import { VaultError } from "../src/http.ts"
import { fixtureSql } from "./fixture-sql.ts"
export const PROJECT_RUN_INPUT = { project: "prj_a", env: "prod", envSource: "flag", remote: null, worktree: "/fixture", head: null, vars: ["TOKEN"], command: "test", argv: ["test"] }
export async function projectDeviceInvocation(ctx: VaultContext, device = "dev_kim") {
  const proof = await createProof({ deviceId: device, sign: async () => new Uint8Array(64) }, { method: "POST", url: "https://vault.test/v1/runs" }, { tenant: ctx.tenant })
  return { auth: { kind: "device" as const, proof, method: "POST", url: "https://vault.test/v1/runs", bodyHash: "" }, workspace: { id: ctx.tenant, slug: "work", name: "Work" } }
}
export async function approvedProjectRun(ctx: VaultContext, input = PROJECT_RUN_INPUT, device = "dev_kim", decider = "owner") {
  const invocation = await projectDeviceInvocation(ctx, device), principal = { kind: "device" as const, deviceId: device }
  let approval: string | undefined
  try { await workspaceRunOps["runs.create"]!.handler(ctx, principal, input, invocation) } catch (error) { if (!(error instanceof VaultError) || error.code !== "approval_required") throw error; approval = error.extra.approval }
  if (!approval) throw new Error("Expected a run approval")
  const row = workspaceApproval(ctx, approval)!
  callProject(ctx, projectState(ctx), decider, "approvals.decide", { id: row.id, decision: "approve" }, { type: "approval.decide", approval: row.id, digest: row.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 3600 } })
  const result = await workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...input, approval }, invocation) as import("@mehen/protocol").WorkspaceRunCreated
  return { run: result.run, approval, invocation, principal, input, result }
}
export function projectSecurityRows(ctx: VaultContext): string {
  return canonicalJson(["tenant_state", "projects", "environments", "vars", "project_shares", "approvals", "protected_use_grants", "consent_lineage", "runs", "run_authorisations", "run_placeholders", "notice_outbox", "exposures", "audit"].map((table) => ({ table, rows: ctx.sql.exec(`SELECT * FROM ${table}`).toArray() })))
}
