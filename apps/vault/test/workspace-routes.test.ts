import { env } from "cloudflare:workers"
import { createExecutionContext, runInDurableObject } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import worker from "../src/index.ts"
import { responseFor } from "../src/http.ts"
import { resolveWorkspace, workspaceCall, type RequestContext } from "../src/routes/context.ts"
import { WORKSPACE_HEADER, WORKSPACE_ROUTES, assertWorkspaceNameAvailable } from "../src/routes/workspace-prefix.ts"
import type { WorkspaceInvocation } from "../src/vault/core.ts"
import { createWorkspaceFixture } from "./workspace-fixtures.ts"
import { fetchWorkspaceWorker, ORIGIN } from "./helpers.ts"
import { workspaceBrowser } from "./l2-helpers.ts"
import { workspaceStepUpEvidence } from "./stepup-fake.ts"

async function initialiseMetadataVaults(f: Awaited<ReturnType<typeof createWorkspaceFixture>>) {
 for (const [id,slug,member] of [[f.workspaces.personal,"alex",f.personalMember],[f.workspaces.work,"northwind","mem_owner"]]) {
  const result = await runInDurableObject(f.env.TENANT_VAULT.getByName(id!), instance => {

   return instance.invoke({ op: "access.init",input: { workspace: id,slug,name: slug,member,owner: { account: f.account,name: "owner" } },auth: { kind: "system",reason: "workspace metadata fixture" } })
  })
  expect(result.ok).toBe(true)
 }
}

async function bytes(response: Response) { return { status: response.status, body: await response.text(), headers: [...response.headers] } }
describe("workspace prefix", () => {
 it("foreign and unknown workspaces are byte-identical and never workspace_unknown", async () => {
  const f = await createWorkspaceFixture()
  await f.env.DB.prepare("DELETE FROM memberships WHERE account=? AND workspace=?").bind(f.account, f.workspaces.work).run()
  const foreign = await bytes(await fetchWorkspaceWorker(f.env, "/api/w/northwind", { headers: { cookie: f.cookie } }))
  const unknown = await bytes(await fetchWorkspaceWorker(f.env, "/api/w/not-a-workspace", { headers: { cookie: f.cookie } }))
  expect(foreign).toEqual(unknown)
  expect(JSON.parse(foreign.body)).toEqual({ error: "not_found", message: "No such workspace." })
 })
 it("resolves both memberships and permanent aliases to canonical metadata", async () => {
  const f = await createWorkspaceFixture()
  await initialiseMetadataVaults(f)
  await f.env.DB.prepare("INSERT INTO workspace_slugs(slug,workspace,retired_at) VALUES ('old-alex',?,?)").bind(f.workspaces.personal, Date.now()).run()
  for (const slug of ["alex", "old-alex", "northwind"]) {
   const response = await workspaceBrowser(f.env, f.cookie, slug).get("")
   expect(response.status).toBe(200)
   expect(await response.json()).toMatchObject({ id: slug === "northwind" ? f.workspaces.work : f.workspaces.personal, slug: slug === "northwind" ? "northwind" : "alex" })
  }
 })
 it("joining, left, deleted workspace and invalid cookie do not route", async () => {
  const f = await createWorkspaceFixture()
  for (const state of ["joining", "left"]) {
   await f.env.DB.prepare("UPDATE memberships SET state=? WHERE id=?").bind(state, f.personalMember).run()
   expect((await fetchWorkspaceWorker(f.env, "/api/w/alex", { headers: { cookie: f.cookie } })).status).toBe(404)
  }
  expect((await fetchWorkspaceWorker(f.env, "/api/w/alex", { headers: { cookie: "bad" } })).status).toBe(401)
  await f.env.DB.prepare("UPDATE workspaces SET status='deleted' WHERE id=?").bind(f.workspaces.work).run()
  expect((await fetchWorkspaceWorker(f.env, "/api/w/northwind", { headers: { cookie: f.cookie } })).status).toBe(404)
 })
 it("app/recovery cookies, idle/absolute expiry and deleting accounts cannot use browser prefix", async () => {
  const f = await createWorkspaceFixture()
  const get = () => fetchWorkspaceWorker(f.env, "/api/w/alex", { headers: { cookie: f.cookie } })
  for (const kind of ["app", "recovery"]) {
   await f.env.DB.prepare("UPDATE web_sessions SET kind=?").bind(kind).run()
   expect((await get()).status).toBe(401)
  }
  await f.env.DB.prepare("UPDATE web_sessions SET kind='web',last_seen_at=?").bind(Date.now() - 7 * 86400000).run()
  expect((await get()).status).toBe(401)
  await f.env.DB.prepare("UPDATE web_sessions SET last_seen_at=?,expires_at=?").bind(Date.now(), Date.now() - 1).run()
  expect((await get()).status).toBe(401)
  await f.env.DB.prepare("UPDATE web_sessions SET expires_at=?").bind(Date.now() + 600000).run()
  await f.env.DB.prepare("UPDATE accounts SET status='deleting' WHERE id=?").bind(f.account).run()
  expect((await get()).status).toBe(401)
 })
 it("unsafe requests still require same origin before touching workspace tables", async () => {
  const response = await fetchWorkspaceWorker(env, "/api/w/alex/items", { method: "POST", headers: { origin: "https://evil.test", "content-type": "application/json" }, body: "{}" })
  expect(response.status).toBe(403)
 })
 it("workspaceCall carries account/session/committed epoch/factor, never D1 role hint", async () => {
  const f = await createWorkspaceFixture()
  await f.env.DB.prepare("UPDATE accounts SET security_epoch=7,security_transition='transition-pending' WHERE id=?").bind(f.account).run()
  await f.env.DB.prepare("UPDATE memberships SET role_hint='guest' WHERE account=?").bind(f.account).run()
  const rc: RequestContext = { request: new Request(`${ORIGIN}/api/w/alex`, { headers: { cookie: f.cookie } }), env: f.env, ctx: createExecutionContext(), url: new URL(`${ORIGIN}/api/w/alex`), params: { ws: "alex" } }
  const workspace = await resolveWorkspace(rc)
  let invocation: WorkspaceInvocation | null = null
  const stub = { invoke: async (call: WorkspaceInvocation) => { invocation = call; return { ok: true as const, value: "done" } } }
  const response = await workspaceCall(rc, workspace, "access.status", {}, workspaceStepUpEvidence({ type: "device.revoke", device: "dev_x" }), stub)
  expect(response).toBe("done")
  expect(invocation).toMatchObject({ auth: { kind: "account", account: f.account, session: f.session, securityEpoch: 7, stepUpFactor: "pk_fixture", sessionCheck: null } })
  expect(invocation).not.toHaveProperty("auth.role")
 })
})
describe("workspace header", () => {
 it("refuses a request naming another workspace id with the unknown-workspace bytes and reaches no handler", async () => {
  const f = await createWorkspaceFixture()
  await initialiseMetadataVaults(f)
  let reached = 0
  const probe = { method: "POST", path: "/probe", handler: async () => { reached++; return new Response(null, { status: 204 }) } }
  WORKSPACE_ROUTES.push(probe)
  try {
   const send = (path: string, id: string | null, method = "GET") => fetchWorkspaceWorker(f.env, path, { method, headers: { cookie: f.cookie, origin: ORIGIN, "sec-fetch-site": "same-origin", ...(id === null ? {} : { [WORKSPACE_HEADER]: id }) } })
   expect((await send("/api/w/alex", f.workspaces.personal)).status).toBe(200)
   expect((await send("/api/w/alex", null)).status).toBe(200)
   const unknown = await bytes(await send("/api/w/not-a-workspace", null))
   expect(await bytes(await send("/api/w/alex", f.workspaces.work))).toEqual(unknown)
   expect(await bytes(await send("/api/w/alex", "tn_NotAWorkspace1"))).toEqual(unknown)
   expect(await bytes(await send("/api/w/alex/probe", f.workspaces.work, "POST"))).toEqual(unknown)
   expect(reached).toBe(0)
   expect((await send("/api/w/alex/probe", f.workspaces.personal, "POST")).status).toBe(204)
   expect(reached).toBe(1)
  } finally {
   WORKSPACE_ROUTES.splice(WORKSPACE_ROUTES.indexOf(probe), 1)
  }
 })
})
describe("workspace namespace refusals", () => {
 it("five aliases allowed; sixth rename reserves nothing", () => {
  const rows = { canonical: ["alex"], aliases: [] as { slug: string; workspace: string }[] }
  for (let i = 0; i < 5; i++) { expect(() => assertWorkspaceNameAvailable(`name-${i}`, rows, "tn_a")).not.toThrow(); rows.aliases.push({ slug: `old-${i}`, workspace: "tn_a" }) }
  expect(() => assertWorkspaceNameAvailable("sixth-name", rows, "tn_a")).toThrow()
  expect(rows.canonical).toEqual(["alex"])
  expect(rows.aliases).toHaveLength(5)
 })
 it("reserved, migration prefix, aliased and occupied names get identical status/body/headers", async () => {
  const rows = { canonical: ["occupied"], aliases: [{ slug: "aliased", workspace: "tn_a" }] }
  const responses = []
  for (const name of ["api", "legacy-any", "aliased", "occupied"]) {
   try { assertWorkspaceNameAvailable(name, rows) } catch (error) { responses.push(await bytes(responseFor(error))) }
  }
  expect(responses).toHaveLength(4)
  for (const response of responses) expect(response).toEqual(responses[0])
  expect(responses[0]).toMatchObject({ status: 409, body: '{"error":"conflict","message":"name not available"}' })
 })
 it("ships the destructive migrations in order and a fresh DO binding with workspaces enabled", () => {
  const deployed = Object.keys(import.meta.glob<string>("../migrations/*.sql", { query: "?raw", import: "default", eager: true })).map(p => p.split("/").pop()).sort()
  expect(deployed).toEqual(["0001_directory.sql", "0002_identity.sql", "0003_enrol_group.sql", "0004_auth.sql", "0005_accounts.sql", "0006_oidc.sql", "0007_cutover.sql", "0008_needs_you.sql", "0009_requested_scope.sql", "0010_platforms.sql", "0011_platform_delete_attempts.sql", "0012_operator_console.sql", "0013_vault_backups.sql", "0014_device_cli_versions.sql", "0015_operator_proposals.sql", "0016_email_proofs.sql", "0017_account_suspension.sql", "0018_deployment_settings.sql", "0019_invite_emails.sql", "0020_enrolment_prune.sql"])
  const config = Object.values(import.meta.glob<string>("../wrangler.jsonc", { query: "?raw", import: "default", eager: true }))[0]!
  expect(config).not.toContain('"class_name": "TenantVault"')
  expect(config).toContain('"deleted_classes": ["TenantVault"]')
  expect(config).toContain('"new_sqlite_classes": ["WorkspaceVault"]')
  expect(config).not.toContain("migrations-workspaces")
 })
})

it("all names refuse byte-identically before probing when a shared miss budget is exhausted", async () => {
 const rows = { canonical: ["occupied"], aliases: [] }
 const budget = { now: 1_800_000, budgets: [{ windowStart: 0, count: 20 }] }
 const responses = []
 for (const slug of ["occupied", "free-name", "api"]) {
  try { assertWorkspaceNameAvailable(slug, rows, undefined, budget) } catch (error) { responses.push(await bytes(responseFor(error))) }
 }
 expect(responses).toHaveLength(3)
 expect(responses[0]).toEqual(responses[1])
 expect(responses[0]).toEqual(responses[2])
 expect(responses[0]).toMatchObject({ status: 429, body: '{"error":"rate_limited","message":"Too many unavailable names; try again later.","retryAfter":1800}' })
 expect(() => assertWorkspaceNameAvailable("free-name", rows, undefined, { ...budget, budgets: [{ windowStart: 0, count: 19 }] })).not.toThrow()
})

it("workspaceCall maps live checks but refuses expired, wrong-epoch and wrong-workspace evidence", async () => {
 const f = await createWorkspaceFixture()
 const now = Date.now()
 await f.env.DB.prepare("INSERT INTO oidc_identities(id,account,provider,issuer,subject,email,email_verified,linked_at,last_verified_at) VALUES ('oidc_check',?,'google','https://accounts.google.com','subject','owner@example.com',1,?,?)").bind(f.account,now,now).run()
 const rc: RequestContext = { request: new Request(`${ORIGIN}/api/w/alex`, { headers: { cookie: f.cookie } }), env: f.env, ctx: createExecutionContext(), url: new URL(`${ORIGIN}/api/w/alex`), params: { ws: "alex" } }
 const workspace = await resolveWorkspace(rc)
 for (const variant of ["live", "expired", "epoch", "workspace"]) {
  await f.env.DB.prepare("DELETE FROM session_identity_checks").run()
  await f.env.DB.prepare("INSERT INTO session_identity_checks(id,session,workspace,member,identity,account,session_kind,security_epoch,claims,rule_revision,gate_generation,sequence,started_at,succeeded_at,purpose,expires_at) VALUES ('chk_live',?,?,?,'oidc_check',?,'web',?,'{}',2,3,4,?,?,'session',?)").bind(f.session,variant === "workspace" ? f.workspaces.work : f.workspaces.personal,f.personalMember,f.account,variant === "epoch" ? 1 : 0,now-1000,now-500,variant === "expired" ? now-1 : now+600000).run()
  let invocation: WorkspaceInvocation | null = null
  const stub = { invoke: async (call: WorkspaceInvocation) => { invocation = call; return { ok: true as const, value: "done" } } }
  await workspaceCall(rc,workspace,"access.status",{},undefined,stub)
  expect(invocation).toMatchObject({ auth: { sessionCheck: variant === "live" ? { id: "chk_live", identityRuleRev: 2, gateGeneration: 3, checkSequence: 4, succeededAt: new Date(now-500).toISOString(), expiresAt: new Date(now+600000).toISOString() } : null } })
 }
})

import type { ApprovalBatchResult, ApprovalGroupView, WorkspaceRunCreated, WorkspaceStepUpAction } from "@mehen/protocol"
import { body, workJourney } from "./e2e/workspace-journey.ts"
import { projectFixture, projectState, inAccess, callProject } from "./projects-workspace-fixture.ts"
import { batchAsk } from "./approvals-batch-support.ts"
import { setSetting } from "../src/vault/areas/workspace-runtime.ts"
import type { VaultContext } from "../src/vault/core.ts"
import type { VaultError } from "../src/http.ts"
// Review together's routes: the group read, polled with If-None-Match, and
// the approval-batch pair, built then signed as a single decision is.
describe("batch approval routes", () => {
 it("reads a group with an ETag, builds and decides a list under one passkey, same-origin and signed-in only", async () => {
  const f = await workJourney()
  const machine = await f.machine(f.alex, f.work)
  await f.credential(f.alex, f.work, "openai-main", { kind: "workspace" })
  await body(await f.deviceCall(machine, `/v1/projects/${f.project.id}/vars/OPENAI_KEY`, { env: "dev", item: "openai-main", field: "key" }, undefined, undefined, "PUT"))
  const run = await body<WorkspaceRunCreated>(await f.deviceCall(machine, "/v1/runs", { project: f.project.id, env: "dev", envSource: "flag", remote: null, worktree: "/work", head: null, vars: ["OPENAI_KEY"], command: "node task.js", argv: ["node", "task.js"] }), 201)
  const key = run.vars.find((v) => v.name === "OPENAI_KEY")
  if (key?.delivery !== "placeholder") throw new Error("Expected a placeholder")
  const held: string[] = []
  for (const query of ["?x=1", "?x=2"]) held.push((await body<{ approval: string }>(await f.deviceCall(machine, "/v1/relay", { run: run.run, method: "DELETE", url: `https://api.openai.com/v1/files/file-1${query}`, headers: [["Authorization", `Bearer ${key.value}`]] }), 409)).approval)
  const groups = await f.sql<{ review_group: string }>(f.work, "SELECT DISTINCT review_group FROM approvals")
  expect(groups).toHaveLength(1)
  const path = `/api/w/${f.work.slug}/approvals`, group = groups[0]!.review_group, batch = `/api/w/${f.work.slug}/approval-batch`
  const read = await f.request(`${path}/groups/${group}`, f.alex)
  const etag = read.headers.get("etag")
  expect(read.headers.get("cache-control")).toBe("no-store")
  const view = await body<ApprovalGroupView>(read)
  expect(view.rows.map((r) => r.view === "detail" ? [r.approval.approval, r.newerSameShape] : null)).toEqual([[held[0], held[1]], [held[1], null]])
  const again = await f.request(`${path}/groups/${group}`, f.alex, undefined, { "if-none-match": etag! })
  expect([again.status, await again.text()]).toEqual([304, ""])
  expect(await body(await f.request(`${path}/groups/grp_absent`, f.alex), 404)).toEqual({ error: "not_found", message: "No such object." })
  const entries = held.map((id) => ({ id, decision: "approve" }))
  expect((await f.request(`${batch}/action`, f.alex, { entries }, { origin: "https://evil.test", "sec-fetch-site": "cross-site" })).status).toBe(403)
  expect((await f.request(`${batch}/decide`, undefined, { entries })).status).toBe(401)
  const action = await body<WorkspaceStepUpAction>(await f.request(`${batch}/action`, f.alex, { entries }))
  expect(action).toMatchObject({ type: "approval.decide_many", entries: [...held].sort().map((approval) => ({ approval, decision: "approve" })) })
  const decided = await body<ApprovalBatchResult>(await f.signed(`${batch}/decide`, f.alex, { entries }, action, f.work.slug))
  expect(decided).toMatchObject({ batch: expect.stringMatching(/^apb_/), approved: 2, denied: 0, skipped: 0 })
  expect(await f.sql(f.work, "SELECT status FROM approvals ORDER BY id")).toEqual([{ status: "approved" }, { status: "approved" }])
  const after = await f.request(`${path}/groups/${group}`, f.alex, undefined, { "if-none-match": etag! })
  expect(after.status).toBe(200)
  expect(after.headers.get("etag")).not.toBe(etag)
 })
 it("refuses every batch op while APPROVAL_BATCHES is off, and in a managed workspace", async () => {
  const f = await projectFixture()
  await inAccess(f.tenant, (ctx) => {
   const row = batchAsk(ctx)
   const entries = [{ id: row.id, decision: "deny" }]
   const off = Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, APPROVAL_BATCHES: "off" } })
   const refusals = (on: VaultContext) => [["approvals.group", { id: row.review_group }], ["approvals.action_many", { entries }], ["approvals.decide_many", { entries }]].map(([op, input]) => { try { callProject(on, projectState(on), "kim", op as string, input); return null } catch (error) { return (error as VaultError).toJSON() } })
   const unavailable = { error: "forbidden", message: "Deciding asks together is not available yet." }
   expect(refusals(off)).toEqual(Array(3).fill(unavailable))
   setSetting(ctx, "managed", { platform: "plt_test", subject: "subject", member: "mem_owner" })
   expect(refusals(ctx)).toEqual(Array(3).fill(unavailable))
  })
 })
})
