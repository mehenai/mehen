// Batch approvals in one workspace object: a machine's held asks, made as
// the relay makes them, and a person deciding a list of them under one
// (fixture) passkey, as the approval-batch decide route does.
import type { ApprovalBatchResult, ApprovalGroupView, WorkspaceStepUpAction } from "@mehen/protocol"
import type { PolicyFloorView } from "@mehen/protocol/policy-mode"
import { prepareApprovedUse } from "../src/vault/areas/projects-workspace.ts"
import { workspaceApproval, type WorkspaceApprovalRow } from "../src/vault/areas/approvals-workspace.ts"
import { digestOf } from "../src/vault/areas/approvals.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { workspaceRunOps } from "../src/vault/areas/runs-workspace.ts"
import { VaultError } from "../src/http.ts"
import { items } from "../src/vault/areas/items.ts"
import { editAccessFixture } from "./access-test-support.ts"
import { callProject, PROJECT_RUN_INPUT, projectDeviceInvocation, projectState } from "./projects-workspace-fixture.ts"

export type BatchAsk = { device?: string; slug?: string; context?: { project: string; env: string } | null; body?: string; title?: string; shape?: string; floor?: PolicyFloorView["reason"][] | null; replaces?: string | null }

// One held relay ask (a POST to api.example.com) by `device` on the
// credential `slug`, the fixture's key-<role> naming each.
export function batchAsk(ctx: VaultContext, ask: BatchAsk = {}): WorkspaceApprovalRow {
  const { device = "dev_kim", slug = "key-workspace", context = null, body = "{}", title = "Write a record", shape = "shape-write", floor = [], replaces = null } = ask
  const state = projectState(ctx)
  const item = state.credentials.find((c) => ctx.sql.exec<{ slug: string }>("SELECT slug FROM items WHERE id=?", c.id).toArray()[0]?.slug === slug)
  if (!item) throw new Error(`No fixture credential ${slug}`)
  const presentation = { title, details: [{ label: "Action", value: "Write" }], body }
  const subject = { item: slug, method: "POST", url: "https://api.example.com/write", contentType: "application/json", contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf(body), constraints: { uses: 1, ttlSeconds: 600 } }
  const required = prepareApprovedUse(ctx, state, { principal: { kind: "device", deviceId: device }, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation, batch: { floor, shape, replaces } }, { ...item, slug, version: 1 }, context, subject, null, ctx.now())
  return workspaceApproval(ctx, required.approvalId)!
}

// A credential homed in prj_b that prj_a's `env` references: Kim, who
// manages prj_a and has no share in prj_b, may deny an ask to use it there
// but not read it.
export async function projectBCredential(ctx: VaultContext, slug: string, env: "dev" | "prod"): Promise<void> {
  const item = await items.putItem(ctx, { slug, kind: "api-key", provider: null, account: null, accountVerified: false, tags: [], ceiling: "placeholder", binding: { hosts: ["api.example.com"] }, policy: { default: "approve", rules: [] }, injection: { in: "header", name: "Authorization", format: "Bearer {key}" }, publicFields: {}, secretFields: { key: "test-fixture-key-not-a-live-secret" }, description: null }, { kind: "system", reason: "test" })
  editAccessFixture(ctx, (state) => { state.credentials.push({ id: item.id, home: { kind: "project", project: "prj_b" }, tags: [] }) })
  ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_a',?,?,?,'key','member:mem_owner',?)", env, slug.toUpperCase().replaceAll("-", "_"), slug, ctx.now())
}

// A run's held ask: `device` starting the fixture's run in prj_a prod.
export async function runAsk(ctx: VaultContext, device = "dev_kim"): Promise<WorkspaceApprovalRow> {
  try { await workspaceRunOps["runs.create"]!.handler(ctx, { kind: "device", deviceId: device }, PROJECT_RUN_INPUT, await projectDeviceInvocation(ctx, device)) } catch (error) {
    if (error instanceof VaultError && error.code === "approval_required" && error.extra.approval) return workspaceApproval(ctx, error.extra.approval)!
    throw error
  }
  throw new Error("Expected a run approval")
}

export type BatchEntries = { id: string; decision: "approve" | "deny" }[]
export function batchActionFor(ctx: VaultContext, role: string, entries: BatchEntries): WorkspaceStepUpAction {
  return callProject(ctx, projectState(ctx), role, "approvals.action_many", { entries }) as WorkspaceStepUpAction
}
export function decideBatch(ctx: VaultContext, role: string, entries: BatchEntries, action = batchActionFor(ctx, role, entries)): ApprovalBatchResult {
  return callProject(ctx, projectState(ctx), role, "approvals.decide_many", { entries }, action) as ApprovalBatchResult
}
export function groupView(ctx: VaultContext, role: string, id: string): ApprovalGroupView {
  return callProject(ctx, projectState(ctx), role, "approvals.group", { id }) as ApprovalGroupView
}
// Each result's outcome by approval id.
export function outcomes(result: ApprovalBatchResult): Record<string, string> {
  return Object.fromEntries(result.results.map((r) => [r.approval, r.outcome]))
}
