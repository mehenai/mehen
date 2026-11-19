import { clearOverridesForCredential, clearOverridesForEnvironment } from "./overrides-workspace.ts"
// Protected-use subjects bind the complete reference graph, not just the
// selected environment. State at a final point must be freshly loaded inside
// the caller's synchronous transaction, never invocation-cached.

import { canonicalJson, type CredentialHome } from "@mehen/protocol"
import { VaultError } from "../../http.ts"
import { can, eligibility, fourEyesProjects, principalDevice, type AccessAsk, type AccessPrincipal, type AccessState, type AccessProject, type AccessCredential } from "../access.ts"
import { one, rows, type VaultContext } from "../core.ts"
import { approvalBinding, askedCredentials, requesterBasis, consentCurrent, readConsent, staleWorkspaceConsent, requestWorkspaceApproval, workspaceApproval, type ApprovalAskBatch, type WorkspaceApprovalRow } from "./approvals-workspace.ts"
import { items } from "./items.ts"
import { EnvironmentStateSchema, NAME_UNAVAILABLE, ShareSubjectSchema, ShareTermsSchema, type EnvironmentState, type Share, type WorkspaceNoticePayload, type WorkspaceProject, type WorkspaceRef, type WorkspaceStepUpAction } from "@mehen/protocol"
import { EnvName, ProjectCreate, VarName, VarSet, type ProjectBinding } from "@mehen/protocol/api"
import { KINDS } from "@mehen/protocol/kinds"
import { z } from "zod"
import { effectiveAccess, environmentChangeIsLoosening, type AccessAction, type AccessTarget, type VariableSource } from "../access.ts"
import { randomId } from "../core.ts"
import { digestOf, parseOpInput } from "./approvals.ts"
import { loadProject, normaliseRemote, secretLikeness, type ProjectRecord } from "./projects.ts"
import * as workspaceRuntime from "./workspace-runtime.ts"
import type { WorkspaceInvocationContext } from "./workspace-runtime.ts"
import { auditPrivateEvent } from "../audit.ts"
import { managedDefaultsRevision } from "../managed-platform.ts"
import { lapseMandatesOnLostManagement, scheduleMandateSweep } from "./mandates-workspace.ts"
import { beforeManagementChange } from "./management-guard.ts"

export type CheckedCredential = { id: string; slug: string; home: CredentialHome; version?: number; configRevision?: number }
export type ProtectedSnapshot = {
  device: string
  // Present only when a workload asked: the approval then serves only it.
  workload?: string
  requester: ReturnType<typeof requesterBasis>
  requesterProjects: string[]
  item: CheckedCredential
  project: string
  environment: string
  protected: boolean
  reason: "protected" | "policy"
  fourEyes: string[]
  requestDigest: string
  run?: { items: CheckedCredential[]; revision: number; protectionRevision: number; remote: string | null }
  references: { project: string; environment: string; revision: number; protectionRevision: number }[]
  // In a managed workspace only: the platform defaults' revision the policy
  // was computed under, so a change stales a pending or granted approval.
  platformDefaults?: number
  // As the ask's mode: present only when a run's placeholder or a fill asked.
  mode?: "placeholder" | "fill"
  // Present only when a push asked (areas/pushes.ts).
  push?: import("./push-records.ts").PushSnapshotPart
}
// The mode a held request uses its credential in: a relay by item, a run's
// placeholder swapped on its declared surface, or a fill into a web page.
export type ApprovedUseMode = "relay" | "placeholder" | "fill"
// The defaults' revision a snapshot binds, present only in a managed workspace.
function platformDefaultsPart(ctx: VaultContext): { platformDefaults?: number } {
  const revision = managedDefaultsRevision(ctx)
  return revision === null ? {} : { platformDefaults: revision }
}

export const WORKSPACE_PROTECTED_GRANTS_MIGRATION = `CREATE TABLE protected_use_grants (
  approval TEXT PRIMARY KEY, lineage TEXT NOT NULL REFERENCES consent_lineage(id),
  snapshot TEXT NOT NULL, uses_left INTEGER, expires_at INTEGER NOT NULL, revoked_at INTEGER
);`

function refusal(decision: ReturnType<typeof can>): void {
  if (!decision.allowed) throw new VaultError(decision.error, decision.message, decision.next ? { next: decision.next } : {})
}

function referenceSnapshot(state: AccessState, item: string): ProtectedSnapshot["references"] {
  return state.projects.flatMap((p) => p.environments.filter((e) => e.references.some((r) => r.item === item)).map((e) => ({ project: p.id, environment: e.name, revision: e.revision, protectionRevision: e.protectionRevision }))).sort((a, b) => `${a.project}/${a.environment}`.localeCompare(`${b.project}/${b.environment}`))
}

export function approvedUseSnapshot(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, item: CheckedCredential, context: { project: string; env: string } | null, now: number, mode: ApprovedUseMode = "relay"): { snapshot: ProtectedSnapshot; ask: AccessAsk | null } {
  if (principal.kind !== "device") throw new VaultError("forbidden", "Only an enrolled machine can use a credential.")
  const useContext = context ? { project: context.project, environment: context.env } : null
  refusal(can(state, principal, { type: "item.use", context: useContext }, { credential: item.id, mode }, now))
  const env = state.projects.find((p) => p.id === context?.project)?.environments.find((e) => e.name === context?.env)
  if (context && !env) throw new VaultError("not_found", "No such object.")
  const protectedItem = state.projects.some((p) => p.environments.some((e) => e.protected && e.references.some((r) => r.item === item.id)))
  if (protectedItem && (!env?.protected || !env.references.some((r) => r.item === item.id))) throw new VaultError("environment_refused", "This credential needs an authorised protected context.")
  const asker = principal.workload !== undefined ? { workload: principal.workload } : {}
  const asked = mode === "relay" ? {} : { mode }
  const ask: AccessAsk & { credentials: string[] } = { device: principal.deviceId, ...asker, credential: item.id, credentials: [item.id], context: useContext, ...asked }
  const requesterProjects = [...new Set([...(context ? [context.project] : []), ...(item.home.kind === "project" ? [item.home.project] : [])])]
  return { snapshot: { device: principal.deviceId, ...asker, requester: requesterBasis(state, principal.deviceId, requesterProjects, now), requesterProjects, item: {id:item.id,slug:item.slug,home:structuredClone(item.home),configRevision:item.configRevision??0}, project: context?.project ?? "", environment: context?.env ?? "", protected: protectedItem, reason: protectedItem ? "protected" : "policy", requestDigest: "", fourEyes: fourEyesProjects(state, ask).sort(), references: referenceSnapshot(state, item.id), ...platformDefaultsPart(ctx), ...asked }, ask }
}

// noAsk: where no approved grant matches and a new ask would be opened, the
// refusal to throw instead (the approval dial's Let it work); nothing is asked.
export function prepareApprovedUse(ctx: VaultContext, state: AccessState, caller: { principal: AccessPrincipal; workspace: WorkspaceRef; presentation: import("../services.ts").ApprovalPresentation; mode?: ApprovedUseMode; batch: ApprovalAskBatch; noAsk?: () => VaultError }, item: CheckedCredential, context: { project: string; env: string } | null, subject: import("@mehen/protocol/api").ApprovalSubject, approvalId: string | null, now: number): { kind: "approved" | "required"; snapshot: ProtectedSnapshot; approvalId: string; deciders: string[] } {
  const { snapshot, ask } = approvedUseSnapshot(ctx, state, caller.principal, item, context, now, caller.mode)
  snapshot.requestDigest = digestOf({ subject, presentation: caller.presentation })
  if (!ask) throw new VaultError("bad_request", "This credential needs an approval subject.")
  const previous = approvalId === null ? unspentApproval(ctx, snapshot, approvalBinding(subject, caller.presentation, snapshot).digest, now) : workspaceApproval(ctx, approvalId)
  if (previous && previous.device === snapshot.device && previous.status === "approved" && previous.expires_at > now && previous.snapshot === canonicalJson(snapshot) && previous.binding_digest === approvalBinding(subject, caller.presentation, snapshot).digest) {
    try { assertApprovedUse(ctx, state, snapshot, previous.id, now); return { kind: "approved", snapshot, approvalId: previous.id, deciders: [] } } catch (error) { if (!(error instanceof VaultError)) throw error }
  }
  if (caller.noAsk) throw caller.noAsk()
  let row: ReturnType<typeof requestWorkspaceApproval>
  row = ctx.storage.transactionSync(() => {
    const live = workspaceRuntime.accessState(ctx)
    const checked = approvedUseSnapshot(ctx, live, caller.principal, item, context, ctx.now(), caller.mode)
    checked.snapshot.requestDigest = snapshot.requestDigest
    if (canonicalJson(checked.snapshot) !== canonicalJson(snapshot)) throw new VaultError("conflict", "Access changed; ask for a new approval.")
    return requestWorkspaceApproval(ctx, live, ask, caller.workspace, subject, caller.presentation, snapshot, ctx.now(), caller.batch)
  })
  const device = state.devices.find((d) => d.id === ask.device)
  const guest = device?.owner.kind === "member" && state.members.some((m) => m.id === device.owner.id && m.standing.effectiveRole === "guest")
  const deciders = guest ? [] : state.members.filter((m) => eligibility(state, m.id, ask, now).canApprove).map((m) => m.name)
  return { kind: "required", snapshot, approvalId: row.id, deciders }
}

// The grant is found by the request itself: a resend without the approval id
// spends this machine's (or workload's) approved, unspent grant for the same
// binding, oldest decision first, rather than opening a second approval.
function unspentApproval(ctx: VaultContext, snapshot: ProtectedSnapshot, binding: string, now: number): WorkspaceApprovalRow | null {
  const found = one(ctx.sql.exec<{ id: string }>("SELECT a.id FROM approvals a JOIN protected_use_grants g ON g.approval=a.id WHERE a.device=? AND a.workload IS ? AND a.binding_digest=? AND a.status='approved' AND a.policy_status IS NULL AND a.expires_at>? AND g.revoked_at IS NULL AND (g.uses_left IS NULL OR g.uses_left>0) AND g.expires_at>? ORDER BY a.decided_at, a.id LIMIT 1", snapshot.device, snapshot.workload ?? null, binding, now, now))
  return found ? workspaceApproval(ctx, found.id) : null
}

/** Pass freshly loaded state after the last await, inside the final synchronous
 * transaction. The credential owner also rechecks its value/config revision. */
export function assertApprovedUse(ctx: VaultContext, state: AccessState, snapshot: ProtectedSnapshot, approvalId: string | null, now: number): void {
  const fresh = snapshot.run ? currentRunSnapshot(ctx, state, snapshot, now) : approvedUseSnapshot(ctx, state, snapshotPrincipal(snapshot), snapshot.item, snapshot.project ? { project: snapshot.project, env: snapshot.environment } : null, now, snapshot.mode)
  fresh.snapshot.requestDigest = snapshot.requestDigest
  if (canonicalJson(fresh.snapshot) !== canonicalJson(snapshot)) throw new VaultError("conflict", "Access changed; ask for a new approval.")
  const approval = approvalId === null ? null : workspaceApproval(ctx, approvalId)
  if (!approval || approval.status !== "approved" || approval.device !== snapshot.device) throw new VaultError("forbidden", "This use no longer has a current approval.")
  const grant = approvalId === null ? null : one(ctx.sql.exec<{ lineage: string; snapshot: string; uses_left: number | null; expires_at: number; revoked_at: number | null }>("SELECT * FROM protected_use_grants WHERE approval=?", approvalId))
  const consent = grant ? readConsent(ctx, grant.lineage) : null
  const continuingRun = !!snapshot.run && !!grant && activeRunApproval(ctx, snapshot, grant.lineage, now)
  if (!grant || !consent || grant.revoked_at !== null || !continuingRun && (grant.uses_left === 0 || grant.expires_at <= now || approval.expires_at <= now) || canonicalJson(snapshot) !== grant.snapshot || canonicalJson(consent.ask) !== canonicalJson(fresh.ask) || !consentCurrent(ctx, state, consent.lineage, consent.ask, now)) throw new VaultError("forbidden", "This use no longer has a current approval.")
}

function activeRunApproval(ctx: VaultContext, snapshot: ProtectedSnapshot, lineage: string, now: number): boolean {
  return one(ctx.sql.exec("SELECT 1 FROM workspace_run_contexts c JOIN runs r ON r.id=c.run JOIN run_authorisations a ON a.run=r.id WHERE c.snapshot=? AND r.device=? AND r.ended_at IS NULL AND r.expires_at>? AND a.lineage=? AND a.revoked_at IS NULL AND a.valid_from<=? AND a.valid_until>?", canonicalJson(snapshot), snapshot.device, now, lineage, now, now)) !== null
}
export function assertRunCredential(state: AccessState, principal: Extract<AccessPrincipal, { kind: "device" }>, credential: string, context: { project: string; environment: string }, now: number): void {
  const decisions = (["relay", "placeholder", "lease"] as const).map((mode) => can(state, principal, { type: "item.use", context }, { credential, mode }, now))
  if (!decisions.some((decision) => decision.allowed)) refusal(decisions[0]!)
}
// Who a stored snapshot asked as: its device, and its workload when one asked.
export function snapshotPrincipal(snapshot: ProtectedSnapshot): Extract<AccessPrincipal, { kind: "device" }> {
  return { kind: "device", deviceId: snapshot.device, ...(snapshot.workload !== undefined ? { workload: snapshot.workload } : {}) }
}
export function currentRunSnapshot(ctx: VaultContext, state: AccessState, snapshot: ProtectedSnapshot, now: number): { snapshot: ProtectedSnapshot; ask: AccessAsk } {
  const principal = snapshotPrincipal(snapshot)
  const context = { project: snapshot.project, environment: snapshot.environment }
  const env = state.projects.find((p) => p.id === snapshot.project)?.environments.find((e) => e.name === snapshot.environment)
  refusal(can(state, principal, { type: env?.protected ? "run.protected" : "run.unprotected" }, { project: snapshot.project, environment: snapshot.environment }, now))
  if (!env || !snapshot.run) throw new VaultError("not_found", "No such object.")
  const references = new Map<string, ProtectedSnapshot["references"][number]>()
  references.set(`${snapshot.project}/${snapshot.environment}`, { project: snapshot.project, environment: snapshot.environment, revision: env.revision, protectionRevision: env.protectionRevision })
  for (const item of snapshot.run.items) {
    assertRunCredential(state, principal, item.id, context, now)
    for (const r of referenceSnapshot(state, item.id)) references.set(`${r.project}/${r.environment}`, r)
  }
  const ask: AccessAsk = { device: snapshot.device, ...(snapshot.workload !== undefined ? { workload: snapshot.workload } : {}), credential: null, credentials: snapshot.run.items.map((i) => i.id), context }
  for (const id of askedCredentials(state, ask)) for (const r of referenceSnapshot(state, id)) references.set(`${r.project}/${r.environment}`, r)
  const project = loadProject(ctx, snapshot.project)
  const remoteCurrent = project && (snapshot.run.remote === null ? project.remotes.length === 0 : project.remotes.includes(snapshot.run.remote))
  if (!remoteCurrent) throw new VaultError("remote_mismatch", "This run's repository is no longer bound.")
  return { ask, snapshot: { ...snapshot, item: {id:snapshot.item.id,slug:snapshot.item.slug,home:snapshot.item.home,configRevision:snapshot.item.configRevision??0}, requester: requesterBasis(state, snapshot.device, snapshot.requesterProjects, now), references: [...references.values()].sort((a, b) => `${a.project}/${a.environment}`.localeCompare(`${b.project}/${b.environment}`)), fourEyes: fourEyesProjects(state, ask).sort(), run: { ...snapshot.run, items:snapshot.run.items.map(item=>({id:item.id,slug:item.slug,home:item.home,configRevision:item.configRevision??0})), revision: env.revision, protectionRevision: env.protectionRevision }, ...platformDefaultsPart(ctx) } }
}

// Call only after assertApprovedUse, in the same synchronous transaction.
export function consumeApprovedUse(ctx: VaultContext, snapshot: ProtectedSnapshot, approvalId: string | null): void {
  if (approvalId === null) throw new VaultError("forbidden", "This use needs an approval.")
  const result = ctx.sql.exec("UPDATE protected_use_grants SET uses_left=CASE WHEN uses_left IS NULL THEN NULL ELSE uses_left-1 END WHERE approval=? AND revoked_at IS NULL AND expires_at>? AND (uses_left IS NULL OR uses_left>0) AND snapshot=?", approvalId, ctx.now(), canonicalJson(snapshot))
  if (!result.rowsWritten) throw new VaultError("forbidden", "This approval is no longer usable.")
}

export function runContext(ctx: VaultContext, runId: string): { project: string; env: string; snapshot: ProtectedSnapshot | null } | null {
  const run = one(ctx.sql.exec<{ project: string; env: string; snapshot: string | null }>("SELECT r.project,r.env,a.snapshot FROM runs r LEFT JOIN workspace_run_contexts a ON a.run=r.id WHERE r.id=? AND r.ended_at IS NULL AND r.expires_at>?", runId, ctx.now()))
  return run ? { project: run.project, env: run.env, snapshot: run.snapshot ? JSON.parse(run.snapshot) as ProtectedSnapshot : null } : null
}

export const WORKSPACE_PROJECT_MIGRATION = `ALTER TABLE environments ADD COLUMN four_eyes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE environments ADD COLUMN reference_rev INTEGER NOT NULL DEFAULT 1;
ALTER TABLE environments ADD COLUMN protection_rev INTEGER NOT NULL DEFAULT 1;
ALTER TABLE projects ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;`

export function projectAccessState(ctx: VaultContext, credentials: AccessCredential[]): AccessProject[] {
  const ids = new Map(rows(ctx.sql.exec<{ id: string; slug: string }>("SELECT id, slug FROM items")).map((i) => [i.slug, i.id]))
  const byId = new Map(credentials.map((c) => [c.id, c]))
  return rows(ctx.sql.exec<{ id: string; slug: string }>("SELECT id,slug FROM projects ORDER BY id")).map((p) => ({ id: p.id, slug: p.slug, environments: rows(ctx.sql.exec<{ name: string; protected: number; four_eyes: number; fences: string; reference_rev: number; protection_rev: number }>("SELECT name,protected,four_eyes,fences,reference_rev,protection_rev FROM environments WHERE project=? ORDER BY name", p.id)).map((e) => ({ name: e.name, protected: e.protected === 1, fourEyes: e.four_eyes === 1, revision: e.reference_rev, protectionRevision: e.protection_rev, fences: JSON.parse(e.fences) as string[], plainVariables: Object.fromEntries(rows(ctx.sql.exec<{ name: string; plain: string }>("SELECT name,plain FROM vars WHERE project=? AND env=? AND plain IS NOT NULL", p.id, e.name)).map((v) => [v.name, v.plain])), references: rows(ctx.sql.exec<{ name: string; item: string; field: string }>("SELECT name,item,field FROM vars WHERE project=? AND env=? AND item IS NOT NULL ORDER BY name", p.id, e.name)).flatMap((v) => {
    // Credential identifiers in evaluator references are stable ids, never slugs.
    const id = ids.get(v.item)
    const credential = id === undefined ? undefined : byId.get(id)
    return credential ? [{ variable: v.name, field: v.field, item: credential.id, home: credential.home, revision: e.reference_rev }] : []
  }) })) }))
}

type ProjectRuntime = Pick<typeof workspaceRuntime, "accessState" | "eligibilityState" | "authorise" | "requireStepUp" | "queueNotice" | "bumpAccessRevision" | "setProjectShare" | "nameMiss">
type ProjectOperation = { auth: ("account" | "device")[]; handler(ctx: VaultContext, principal: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext): unknown }
const Id = z.string().min(1).max(64)
const Fence = z.string().max(253).regex(/^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/)
export const WorkspaceEnvironmentInput = EnvironmentStateSchema.extend({ project: Id, env: EnvName, before: EnvironmentStateSchema, fences: z.array(Fence).max(32) }).strict()
export const WorkspaceVariableSource = z.discriminatedUnion("kind", [z.strictObject({ kind: z.literal("item"), item: Id, field: z.string() }), z.strictObject({ kind: z.literal("plain"), value: z.string() })]).nullable()
export const WorkspaceVarInput = VarSet.extend({ project: Id, name: VarName, before: WorkspaceVariableSource }).strict()
export const WorkspaceShareInput = z.strictObject({ project: Id, subject: ShareSubjectSchema, before: ShareTermsSchema.nullable(), after: ShareTermsSchema.nullable() })
export const WorkspaceProjectCreate = ProjectCreate.extend({ environments: z.array(z.strictObject({ name: EnvName, protected: z.boolean(), fourEyes: z.boolean() })).min(1).max(32) }).strict()
export function workspaceEnvironmentDigest(input: z.infer<typeof WorkspaceEnvironmentInput>): string {
  return digestOf({ change: "environment.update", project: input.project, env: input.env, protected: input.protected, fences: input.fences, fourEyes: input.fourEyes })
}
export function workspaceVarDigest(input: z.infer<typeof WorkspaceVarInput>): string {
  return digestOf({ change: "var.set", project: input.project, env: input.env, name: input.name, item: input.item ?? null, field: input.field ?? null, plain: input.plain ?? null })
}
function projectSource(project: ProjectRecord, env: string, name: string): VariableSource {
  const v = project.vars.find((v) => v.env === env && v.name === name)
  return v?.item !== null && v?.item !== undefined ? { kind: "item", item: v.item, field: v.field ?? "" } : v?.plain !== null && v?.plain !== undefined ? { kind: "plain", value: v.plain } : null
}
function evaluatorSource(ctx: VaultContext, source: VariableSource): VariableSource {
  return source?.kind === "item" ? { ...source, item: items.getItem(ctx, source.item)?.id ?? source.item } : source
}
function mustProject(ctx: VaultContext, id: string): ProjectRecord {
  const project = loadProject(ctx, id)
  if (!project) throw new VaultError("not_found", "No such object.")
  return project
}
function projectView(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, project: ProjectRecord, now: number): WorkspaceProject {
  const device = principal.kind === "device" ? state.devices.find((d) => d.id === principal.deviceId) : null
  const subject = device ? { kind: device.owner.kind, id: device.owner.id } : { kind: "member" as const, id: principal.kind === "member" ? principal.memberId : "" }
  const access = effectiveAccess(state, subject, project.id, now)
  const guest = principal.kind === "member" && state.members.some((m) => m.id === principal.memberId && m.standing.effectiveRole === "guest")
  return { id: project.id, slug: project.slug, remotes: project.remotes, defaultEnv: project.defaultEnv,
    access: device ? { ...access, runProtected: access.runProtected && device.scope.maxEnvironment === "protected", editProtected: false } : access,
    ...(principal.kind === "member" && access.level === "manage" && !guest ? { shares: state.shares.filter((s) => s.project === project.id) } : {}),
    environments: project.environments.map((e) => ({ ...e, fourEyes: state.projects.find((p) => p.id === project.id)?.environments.find((env) => env.name === e.name)?.fourEyes ?? false })),
    vars: project.vars.map((v) => {
      const item = v.item === null ? null : items.getItem(ctx, v.item)
      const visible = item !== null && can(state, principal, { type: "item.read" }, { credential: item.id }, now).allowed
      // A person who may edit sees a plain value: it is declared non-secret
      // config, and a change must name it as its before-state. Machines never.
      const plainShown = v.item === null && v.plain !== null && principal.kind === "member" && (access.level === "edit" || access.level === "manage")
      return { name: v.name, env: v.env, source: v.item !== null ? "item" : v.plain !== null ? "plain" : "unset", item: visible ? v.item : null, field: visible ? v.field : null, ...(v.item !== null && !visible ? { note: "This variable points at a credential outside your reach." } : {}), ...(plainShown ? { value: v.plain } : {}) }
    }),
  }
}
function actor(principal: AccessPrincipal): string { return principal.kind === "member" ? `member:${principal.memberId}` : `device:${principal.deviceId}` }
function protectedNotice(runtime: ProjectRuntime, ctx: VaultContext, invocation: WorkspaceInvocationContext, principal: AccessPrincipal, project: ProjectRecord, env: string, changes: Extract<WorkspaceNoticePayload, { kind: "protection_changed" }>["changes"]): void {
  if (!changes.length) return
  runtime.queueNotice(ctx, { kind: "protection_changed", workspace: invocation.workspace, project: { id: project.id, slug: project.slug }, env, changes, by: principal.kind === "member" ? principal.memberId : principal.deviceId, at: new Date(ctx.now()).toISOString() })
}
function touchProject(runtime: ProjectRuntime, ctx: VaultContext, project: string): void {
  ctx.sql.exec("UPDATE projects SET revision=revision+1,updated_at=? WHERE id=?", ctx.now(), project)
  runtime.bumpAccessRevision(ctx)
  staleWorkspaceConsent(ctx, runtime.accessState(ctx))
}
// A variable's write, inside the caller's transaction once it has checked
// var.set (and any step-up): `state` is the access state before the write.
// `input.item` is the credential's slug.
export function storeProjectVar(ctx: VaultContext, invocation: WorkspaceInvocationContext, principal: AccessPrincipal, project: ProjectRecord, input: { env: string; name: string; item?: string; plain?: string }, field: string | null, after: VariableSource, state: AccessState = workspaceRuntime.accessState(ctx), runtime: ProjectRuntime = workspaceRuntime): void {
  const env = state.projects.find((p) => p.id === project.id)?.environments.find((e) => e.name === input.env)
  const reference = env?.references.find((r) => r.variable === input.name)
  const removed = env?.protected && reference?.home.kind === "workspace" && (after?.kind !== "item" || reference.item !== after.item)
  ctx.sql.exec(`INSERT INTO vars(project,env,name,item,field,plain,updated_by,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(project,env,name) DO UPDATE SET item=excluded.item,field=excluded.field,plain=excluded.plain,updated_by=excluded.updated_by,updated_at=excluded.updated_at`, project.id, input.env, input.name, input.item ?? null, field, input.plain ?? null, actor(principal), ctx.now())
  ctx.sql.exec("UPDATE environments SET reference_rev=reference_rev+1 WHERE project=? AND name=?", project.id, input.env)
  touchProject(runtime, ctx, project.id)
  ctx.audit({ actor: actor(principal), action: "project.var.set", target: project.id, detail: { env: input.env, name: input.name, source: after?.kind ?? "unset", item: input.item ?? null, field } })
  if (removed) protectedNotice(runtime, ctx, invocation, principal, project, input.env, ["reference_removed"])
}
// What a variable is bound to now, as var.set's evaluator reads it.
export function projectVarSource(ctx: VaultContext, project: ProjectRecord, env: string, name: string): VariableSource {
  return evaluatorSource(ctx, projectSource(project, env, name))
}

function miss(runtime: ProjectRuntime, ctx: VaultContext, principal: AccessPrincipal): never {
  ctx.storage.transactionSync(() => runtime.nameMiss.record(ctx, principal, ctx.now()))
  throw new VaultError(NAME_UNAVAILABLE.error, NAME_UNAVAILABLE.message)
}
function checkBudget(runtime: ProjectRuntime, ctx: VaultContext, principal: AccessPrincipal): void {
  const budget = runtime.nameMiss.check(ctx, principal, ctx.now())
  if (!budget.ok) throw new VaultError("rate_limited", "Too many unavailable names; try again later.", { retryAfter: budget.retryAfter })
}

function workspaceProjectOperations(runtime: ProjectRuntime): Record<string, ProjectOperation> {
  return {
    "projects.action": { auth: ["account"], handler(ctx, _principal, raw, invocation) {
      const input = parseOpInput(z.strictObject({ change: z.enum(["create", "environment", "variable", "share", "delete", "remote"]), input: z.unknown() }), raw)
      return projectAction(runtime, ctx, invocation, input.change, input.input)
    } },
    "projects.get": { auth: ["account", "device"], handler(ctx, principal, raw, invocation) {
      const { id } = parseOpInput(z.strictObject({ id: Id }), raw)
      const state = runtime.eligibilityState(ctx, invocation)
      runtime.authorise(ctx, invocation, { type: "project.read" }, { project: id }, ctx.now())
      return projectView(ctx, state, principal, mustProject(ctx, id), ctx.now())
    } },
    // A remote bound to no project and one bound to a project this machine
    // may not use answer alike, in body and in work done, so a machine learns
    // of no other remote. An unbound remote is checked against an id far
    // shorter than any randomId makes, so no project has it.
    "projects.find": { auth: ["device"], handler(ctx, _principal, raw, invocation) {
      const { remote } = parseOpInput(z.strictObject({ remote: z.string().min(1).max(512) }), raw)
      const normalised = normaliseRemote(remote)
      const bound = normalised === null ? null : one(ctx.sql.exec<{ project: string }>("SELECT project FROM remotes WHERE remote=?", normalised))
      try {
        runtime.authorise(ctx, invocation, { type: "project.read" }, { project: bound?.project ?? "prj_none" }, ctx.now())
      } catch (error) {
        if (error instanceof VaultError && error.code === "not_found") throw new VaultError("not_found", "No such object.")
        throw error
      }
      if (!bound) throw new VaultError("not_found", "No such object.")
      const project = mustProject(ctx, bound.project)
      const binding: ProjectBinding = { id: project.id, slug: project.slug, defaultEnv: project.defaultEnv, environments: project.environments.map((e) => ({ name: e.name, protected: e.protected, variables: project.vars.filter((v) => v.env === e.name).map((v) => v.name) })) }
      return binding
    } },
    "projects.list": { auth: ["account"], handler(ctx, principal, _raw, invocation) {
      runtime.authorise(ctx, invocation, { type: "asks.read" }, {}, ctx.now())
      const state = runtime.eligibilityState(ctx, invocation)
      return { projects: state.projects.filter((p) => can(state, principal, { type: "project.read" }, { project: p.id }, ctx.now()).allowed).map((p) => projectView(ctx, state, principal, mustProject(ctx, p.id), ctx.now())) }
    } },
    "projects.create": { auth: ["account", "device"], handler(ctx, principal, raw, invocation) {
      const input = principal.kind === "device" ? { ...parseOpInput(ProjectCreate, raw), environments: parseOpInput(ProjectCreate, raw).environments.map((e) => ({ ...e, fourEyes: false })) } : parseOpInput(WorkspaceProjectCreate, raw)
      runtime.authorise(ctx, invocation, { type: principal.kind === "device" ? "project.init" : "project.create" }, {}, ctx.now())
      checkBudget(runtime, ctx, principal)
      const remote = input.remote === null ? null : normaliseRemote(input.remote)
      if (input.remote !== null && remote === null) throw new VaultError("bad_request", "That is not a git remote.")
      if (one(ctx.sql.exec("SELECT 1 FROM projects WHERE slug=?", input.slug)) || remote !== null && one(ctx.sql.exec("SELECT 1 FROM remotes WHERE remote=?", remote))) miss(runtime, ctx, principal)
      const envs = input.environments.map((e) => ({ ...e, protected: e.protected || e.name === "prod" || e.name === "production" }))
      if (new Set(envs.map((e) => e.name)).size !== envs.length || !envs.some((e) => e.name === input.defaultEnv && !e.protected)) throw new VaultError("bad_request", "Choose distinct environments and an unprotected default.")
      const id = randomId("prj")
      ctx.storage.transactionSync(() => {
        const decision = runtime.authorise(ctx, invocation, { type: principal.kind === "device" ? "project.init" : "project.create" }, {}, ctx.now())
        if (principal.kind === "member") runtime.requireStepUp(ctx, decision, { type: "project.create", slug: input.slug, remote: input.remote, environments: input.environments }, invocation)
        ctx.sql.exec("INSERT INTO projects(id,slug,default_env,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?)", id, input.slug, input.defaultEnv, actor(principal), ctx.now(), ctx.now())
        if (remote !== null) ctx.sql.exec("INSERT INTO remotes(remote,project) VALUES(?,?)", remote, id)
        for (const e of envs) ctx.sql.exec("INSERT INTO environments(project,name,protected,fences,four_eyes) VALUES(?,?,?,'[]',?)", id, e.name, e.protected ? 1 : 0, e.fourEyes ? 1 : 0)
        const state = runtime.accessState(ctx)
        const member = principal.kind === "member" ? principal.memberId : state.devices.find((d) => d.id === principal.deviceId)?.owner.id
        if (!member) throw new VaultError("forbidden", "The machine owner is no longer active.")
        runtime.setProjectShare(ctx, { id: randomId("shr"), project: id, subject: { kind: "member", member }, level: "manage", protected: true, expiresAt: null }, null)
        runtime.bumpAccessRevision(ctx)
        ctx.audit({ actor: actor(principal), action: "project.create", target: id, detail: { slug: input.slug, remote } })
      })
      return projectView(ctx, runtime.eligibilityState(ctx, invocation), principal, mustProject(ctx, id), ctx.now())
    } },
    "projects.setEnvironment": { auth: ["account"], handler(ctx, principal, raw, invocation) {
      const input = parseOpInput(WorkspaceEnvironmentInput, raw)
      const after: EnvironmentState = { protected: input.protected, fences: [...new Set(input.fences)].sort(), fourEyes: input.fourEyes }
      ctx.storage.transactionSync(() => {
        const state = runtime.accessState(ctx)
        const decision = runtime.authorise(ctx, invocation, { type: "environment.update", before: input.before, after }, { project: input.project, environment: input.env }, ctx.now())
        const project = mustProject(ctx, input.project)
        const live = state.projects.find((p) => p.id === project.id)?.environments.find((e) => e.name === input.env)
        if (!live) throw new VaultError("not_found", "No such object.")
        if (input.protected && project.defaultEnv === input.env) throw new VaultError("bad_request", "A protected environment cannot be the default.")
        runtime.requireStepUp(ctx, decision, { type: "item.update", item: project.id, digest: workspaceEnvironmentDigest(input) }, invocation)
        const changes: Extract<WorkspaceNoticePayload, { kind: "protection_changed" }>["changes"] = []
        if (live.protected && !after.protected && live.references.some((r) => r.home.kind === "workspace")) changes.push("unprotected")
        if (live.fourEyes && !after.fourEyes && live.references.some((r) => r.home.kind === "workspace")) changes.push("four_eyes_off")
        if (live.fences.some((f) => !after.fences.includes(f))) changes.push("fence_removed")
        if (after.fences.some((f) => !live.fences.includes(f))) changes.push("fence_added")
        ctx.sql.exec("UPDATE environments SET protected=?,fences=?,four_eyes=?,protection_rev=protection_rev+1 WHERE project=? AND name=?", after.protected ? 1 : 0, JSON.stringify(after.fences), after.fourEyes ? 1 : 0, project.id, input.env)
        if (!live.protected && after.protected) {
          clearOverridesForEnvironment(ctx, project.id, input.env)
          ctx.sql.exec("UPDATE runs SET ended_at=? WHERE project=? AND env=? AND ended_at IS NULL AND id IN(SELECT run FROM workspace_run_contexts WHERE snapshot IS NULL)", ctx.now(), project.id, input.env)
          ctx.sql.exec("DELETE FROM run_placeholders WHERE run IN(SELECT r.id FROM runs r JOIN workspace_run_contexts c ON c.run=r.id WHERE r.project=? AND r.env=? AND r.ended_at IS NOT NULL AND c.snapshot IS NULL)", project.id, input.env)
        }
        touchProject(runtime, ctx, project.id)
        ctx.audit({ actor: actor(principal), action: "project.environment.update", target: project.id, detail: { env: input.env, ...after, loosened: environmentChangeIsLoosening(live, after) } })
        protectedNotice(runtime, ctx, invocation, principal, project, input.env, changes)
      })
      return projectView(ctx, runtime.eligibilityState(ctx, invocation), principal, mustProject(ctx, input.project), ctx.now())
    } },
    "projects.setVar": { auth: ["account", "device"], handler(ctx, principal, raw, invocation) {
      const parsed = principal.kind === "device" ? parseOpInput(WorkspaceVarInput.partial({ before: true }), raw) : parseOpInput(WorkspaceVarInput, raw)
      const input = { ...parsed, before: parsed.before === undefined ? projectSource(mustProject(ctx, parsed.project), parsed.env, parsed.name) : parsed.before }
      if (input.item !== undefined && input.plain !== undefined || input.field !== undefined && input.item === undefined) throw new VaultError("bad_request", "A variable has one source.")
      if (input.plain !== undefined && secretLikeness(input.plain)) throw new VaultError("bad_request", "This value looks like a secret; store it as a credential instead.")
      const item = input.item === undefined ? null : items.getItem(ctx, input.item)
      const field = item ? input.field ?? KINDS[item.kind].primary : null
      const after: VariableSource = input.item !== undefined ? { kind: "item", item: item?.id ?? input.item, field: field ?? "" } : input.plain !== undefined ? { kind: "plain", value: input.plain } : null
      ctx.storage.transactionSync(() => {
        const state = runtime.accessState(ctx)
        const project = mustProject(ctx, input.project)
        const decision = runtime.authorise(ctx, invocation, { type: "var.set", before: evaluatorSource(ctx, input.before), after }, { project: input.project, environment: input.env, variable: input.name }, ctx.now())
        if (item && (!field || !KINDS[item.kind].fields.some((f) => f.name === field))) throw new VaultError("bad_request", "Choose an existing credential field.")
        if (canonicalJson(projectSource(project, input.env, input.name)) !== canonicalJson(input.before)) throw new VaultError("conflict", "The expected state changed.")
        if (principal.kind === "member") runtime.requireStepUp(ctx, decision, { type: "item.update", item: project.id, digest: workspaceVarDigest(input) }, invocation)
        storeProjectVar(ctx, invocation, principal, project, input, field, after, state, runtime)
      })
      return projectView(ctx, runtime.eligibilityState(ctx, invocation), principal, mustProject(ctx, input.project), ctx.now())
    } },
    "projects.share": { auth: ["account"], handler(ctx, principal, raw, invocation) {
      const input = parseOpInput(WorkspaceShareInput, raw)
      ctx.storage.transactionSync(() => {
        const state = runtime.accessState(ctx)
        const member = input.subject.kind === "member" ? state.members.find((m) => input.subject.kind === "member" && m.id === input.subject.member) : null
        const decision = runtime.authorise(ctx, invocation, { type: "project.share", after: input.after }, { project: input.project, ...(input.subject.kind === "member" ? { member: input.subject.member } : { team: input.subject.team }) }, ctx.now())
        if (input.subject.kind === "member" ? !member || member.status !== "active" : !state.teams.some((t) => input.subject.kind === "team" && t.id === input.subject.team)) throw new VaultError("not_found", "No such object.")
        if (member?.standing.effectiveRole === "guest" && input.after?.level === "manage") throw new VaultError("bad_request", "A guest cannot manage a project.")
        if (input.after?.expiresAt !== null && input.after?.expiresAt !== undefined && (Date.parse(input.after.expiresAt) <= ctx.now() || Date.parse(input.after.expiresAt) > ctx.now() + 365 * 86_400_000)) throw new VaultError("bad_request", "A share must expire within 365 days.")
        const old = state.shares.find((s) => s.project === input.project && canonicalJson(s.subject) === canonicalJson(input.subject)) ?? null
        const oldTerms = old ? { level: old.level, protected: old.protected, expiresAt: old.expiresAt } : null
        if (canonicalJson(oldTerms) !== canonicalJson(input.before)) throw new VaultError("conflict", "The expected state changed.")
        runtime.requireStepUp(ctx, decision, { type: "project.share", ...input }, invocation)
        // A manage share that expired before the sweep came to it lapses
        // first, so granting it again does not restore cover.
        beforeManagementChange(ctx)
        runtime.setProjectShare(ctx, input.after ? { id: old?.id ?? randomId("shr"), project: input.project, subject: input.subject, ...input.after } : null, old)
        // Management of the project's credentials' home taken away lapses
        // the mandates its holders signed, for good.
        lapseMandatesOnLostManagement(ctx, state, runtime.accessState(ctx), "share")
        scheduleMandateSweep(ctx)
        runtime.bumpAccessRevision(ctx)
        staleWorkspaceConsent(ctx, runtime.accessState(ctx))
        ctx.audit({ actor: actor(principal), action: input.after ? "project.share" : "project.unshare", target: input.project, detail: { subject: input.subject, before: input.before, after: input.after } })
      })
      return projectView(ctx, runtime.eligibilityState(ctx, invocation), principal, mustProject(ctx, input.project), ctx.now())
    } },
    "projects.setRemote": { auth: ["account"], handler(ctx, principal, raw, invocation) {
      const input = parseOpInput(WorkspaceRemoteInput, raw)
      runtime.authorise(ctx, invocation, { type: "remote.update" }, { project: input.project }, ctx.now())
      checkBudget(runtime, ctx, principal)
      const normalised = normaliseRemote(input.remote)
      if (normalised === null || normalised !== input.remote) throw new VaultError("bad_request", "Send the normalised repository shown before confirmation.")
      const occupied = one(ctx.sql.exec<{ project: string }>("SELECT project FROM remotes WHERE remote=?", normalised))
      if (input.bound && occupied && occupied.project !== input.project) miss(runtime, ctx, principal)
      ctx.storage.transactionSync(() => {
        const decision = runtime.authorise(ctx, invocation, { type: "remote.update" }, { project: input.project }, ctx.now())
        const project = mustProject(ctx, input.project)
        const remote = normaliseRemote(input.remote)
        if (remote === null || remote !== input.remote) throw new VaultError("bad_request", "Send the normalised repository shown before confirmation.")
        runtime.requireStepUp(ctx, decision, { type: "item.update", item: project.id, digest: digestOf({ change: input.bound ? "remote.bind" : "remote.unbind", project: project.id, remote }) }, invocation)
        const owner = one(ctx.sql.exec<{ project: string }>("SELECT project FROM remotes WHERE remote=?", remote))
        if (!input.bound && owner?.project === project.id && project.remotes.length === 1) throw new VaultError("bad_request", "Bind a replacement before removing the last repository.")
        if (input.bound && !owner) ctx.sql.exec("INSERT INTO remotes(remote,project) VALUES(?,?)", remote, project.id)
        else if (!input.bound) ctx.sql.exec("DELETE FROM remotes WHERE remote=? AND project=?", remote, project.id)
        touchProject(runtime, ctx, project.id)
        ctx.audit({ actor: actor(principal), action: input.bound ? "project.remote.bind" : "project.remote.unbind", target: project.id, detail: { remote } })
      })
      return projectView(ctx, runtime.eligibilityState(ctx, invocation), principal, mustProject(ctx, input.project), ctx.now())
    } },
    "projects.delete": { auth: ["account"], handler(ctx, principal, raw, invocation) {
      const { project: id } = parseOpInput(z.strictObject({ project: Id }), raw)
      ctx.storage.transactionSync(() => {
        const state = runtime.accessState(ctx)
        const decision = runtime.authorise(ctx, invocation, { type: "project.delete" }, { project: id }, ctx.now())
        if (state.credentials.some((c) => c.home.kind === "project" && c.home.project === id)) throw new VaultError("conflict", "Delete or re-home this project's credentials before deleting the project.")
        runtime.requireStepUp(ctx, decision, { type: "project.delete", project: id }, invocation)
        beforeManagementChange(ctx)
        const project = mustProject(ctx, id)
        for (const env of state.projects.find((p) => p.id === id)?.environments ?? []) if (env.protected && env.references.some((r) => r.home.kind === "workspace")) protectedNotice(runtime, ctx, invocation, principal, project, env.name, ["project_deleted"])
        for (const share of state.shares.filter((s) => s.project === id)) runtime.setProjectShare(ctx, null, share)
        ctx.sql.exec("UPDATE runs SET ended_at=? WHERE project=? AND ended_at IS NULL", ctx.now(), id)
        ctx.sql.exec("DELETE FROM run_placeholders WHERE run IN(SELECT id FROM runs WHERE project=?)", id)
        ctx.sql.exec("UPDATE run_authorisations SET revoked_at=? WHERE run IN(SELECT id FROM runs WHERE project=?)", ctx.now(), id)
        ctx.sql.exec("DELETE FROM projects WHERE id=?", id)
        runtime.bumpAccessRevision(ctx)
        staleWorkspaceConsent(ctx, runtime.accessState(ctx))
        ctx.audit({ actor: actor(principal), action: "project.delete", target: id })
      })
      return { deleted: true }
    } },
  }
}

export const WorkspaceRemoteInput = z.strictObject({ project: Id, remote: z.string().min(1).max(512), bound: z.boolean() })
function projectAction(runtime: ProjectRuntime, ctx: VaultContext, invocation: WorkspaceInvocationContext, change: "create" | "environment" | "variable" | "share" | "delete" | "remote", raw: unknown): WorkspaceStepUpAction {
  switch (change) {
    case "create": {
      const input = parseOpInput(WorkspaceProjectCreate, raw)
      runtime.authorise(ctx, invocation, { type: "project.create" }, {}, ctx.now())
      return { type: "project.create", slug: input.slug, remote: input.remote, environments: input.environments }
    }
    case "environment": {
      const input = parseOpInput(WorkspaceEnvironmentInput, raw)
      runtime.authorise(ctx, invocation, { type: "environment.update", before: input.before, after: { protected: input.protected, fences: input.fences, fourEyes: input.fourEyes } }, { project: input.project, environment: input.env }, ctx.now())
      return { type: "item.update", item: input.project, digest: workspaceEnvironmentDigest(input) }
    }
    case "variable": {
      const input = parseOpInput(WorkspaceVarInput, raw)
      const item = input.item === undefined ? null : items.getItem(ctx, input.item)
      const after = input.item !== undefined ? { kind: "item" as const, item: item?.id ?? input.item, field: input.field ?? (item ? KINDS[item.kind].primary : null) ?? "" } : input.plain !== undefined ? { kind: "plain" as const, value: input.plain } : null
      runtime.authorise(ctx, invocation, { type: "var.set", before: evaluatorSource(ctx, input.before), after }, { project: input.project, environment: input.env, variable: input.name }, ctx.now())
      return { type: "item.update", item: input.project, digest: workspaceVarDigest(input) }
    }
    case "share": {
      const input = parseOpInput(WorkspaceShareInput, raw)
      const member = input.subject.kind === "member" ? runtime.accessState(ctx).members.find((m) => input.subject.kind === "member" && m.id === input.subject.member) : null
      runtime.authorise(ctx, invocation, { type: "project.share", after: input.after }, { project: input.project, ...(input.subject.kind === "member" ? { member: input.subject.member } : { team: input.subject.team }) }, ctx.now())
      // A stale before-state is refused here, before anyone is asked for a
      // passkey; the mutation compares again for a race after this point.
      const live = runtime.accessState(ctx).shares.find((s) => s.project === input.project && canonicalJson(s.subject) === canonicalJson(input.subject)) ?? null
      if (canonicalJson(live ? { level: live.level, protected: live.protected, expiresAt: live.expiresAt } : null) !== canonicalJson(input.before)) throw new VaultError("conflict", "The expected state changed.")
      return { type: "project.share", ...input }
    }
    case "delete": {
      const input = parseOpInput(z.strictObject({ project: Id }), raw)
      runtime.authorise(ctx, invocation, { type: "project.delete" }, { project: input.project }, ctx.now())
      if (runtime.accessState(ctx).credentials.some((c) => c.home.kind === "project" && c.home.project === input.project)) throw new VaultError("conflict", "Delete or re-home this project's credentials before deleting the project.")
      return { type: "project.delete", project: input.project }
    }
    case "remote": {
      const input = parseOpInput(WorkspaceRemoteInput, raw)
      runtime.authorise(ctx, invocation, { type: "remote.update" }, { project: input.project }, ctx.now())
      return { type: "item.update", item: input.project, digest: digestOf({ change: input.bound ? "remote.bind" : "remote.unbind", project: input.project, remote: input.remote }) }
    }
  }
}

workspaceRuntime.registerAccessStateProvider("projects", (ctx, credentials) => ({ projects: projectAccessState(ctx, credentials) }))
export const projectWorkspaceOps: NonNullable<import("../core.ts").Area["workspaceOps"]> = Object.fromEntries(Object.entries(workspaceProjectOperations(workspaceRuntime)).map(([name, spec]) => [name, { auth: spec.auth, handler(ctx, principal, input, invocation) {
  if (principal.kind === "system") throw new VaultError("forbidden", "System calls cannot mutate projects.")
  return spec.handler(ctx, principal, input, invocation)
} }]))

// CREDENTIALS calls before deleting/re-homing, inside its transaction. This
// hook uses only the supplied old home and PROJECTS-owned rows: authority may
// already be mid-change, so reconstructing accessState here would be wrong.
export function onCredentialRemoved(ctx: VaultContext, item: { id: string; slug: string; home: CredentialHome }, reason: "deleted" | "rehomed" | "offboarded", by: string): void {
  clearOverridesForCredential(ctx, item, reason)
  const affected = rows(ctx.sql.exec<{ project: string; env: string; protected: number; slug: string }>("SELECT DISTINCT v.project,v.env,e.protected,p.slug FROM vars v JOIN environments e ON e.project=v.project AND e.name=v.env JOIN projects p ON p.id=v.project WHERE v.item=?", item.slug))
  ctx.sql.exec("UPDATE vars SET item=NULL,field=NULL,plain=NULL,updated_by=?,updated_at=? WHERE item=?", `member:${by}`, ctx.now(), item.slug)
  for (const env of affected) {
    ctx.sql.exec("UPDATE environments SET reference_rev=reference_rev+1,protection_rev=protection_rev+1 WHERE project=? AND name=?", env.project, env.env)
    ctx.sql.exec("UPDATE projects SET revision=revision+1,updated_at=? WHERE id=?", ctx.now(), env.project)
    ctx.sql.exec("UPDATE runs SET ended_at=? WHERE project=? AND env=? AND ended_at IS NULL", ctx.now(), env.project, env.env)
    ctx.sql.exec("DELETE FROM run_placeholders WHERE run IN (SELECT id FROM runs WHERE project=? AND env=?)", env.project, env.env)
    if (env.protected === 1 && item.home.kind === "workspace") workspaceRuntime.queueNotice(ctx, { kind: "protection_changed", workspace: workspaceRuntime.workspaceRef(ctx), project: { id: env.project, slug: env.slug }, env: env.env, changes: ["reference_removed"], by, at: new Date(ctx.now()).toISOString() })
  }
  // A run may inherit a reference without delivering that credential (for
  // example a plain-only run). Its graph dependency still has to be voided.
  const graphIds = affected.flatMap((env) => rows(ctx.sql.exec<{ id: string }>("SELECT id FROM approvals WHERE ask IS NOT NULL AND EXISTS(SELECT 1 FROM json_each(approvals.snapshot,'$.references') r WHERE json_extract(r.value,'$.project')=? AND json_extract(r.value,'$.environment')=?)", env.project, env.env)).map((row) => row.id))
  // The joins retain the original consent and decider rather than inventing a
  // new decision from the machine owner after a credential disappears.
  const ids = rows(ctx.sql.exec<{ id: string }>("SELECT id FROM approvals WHERE ask IS NOT NULL AND (json_extract(ask,'$.credential')=? OR EXISTS(SELECT 1 FROM json_each(json_extract(approvals.ask,'$.credentials')) WHERE value=?))", item.id, item.id)).map((r) => r.id)
  for (const id of new Set([...ids, ...graphIds])) {
    ctx.sql.exec("UPDATE approvals SET policy_status='stale' WHERE id=?", id)
    ctx.sql.exec("UPDATE protected_use_grants SET revoked_at=? WHERE approval=?", ctx.now(), id)
    ctx.sql.exec("UPDATE consent_lineage SET revoked_at=? WHERE decision=?", ctx.now(), id)
    ctx.sql.exec("UPDATE run_authorisations SET revoked_at=? WHERE lineage IN(SELECT id FROM consent_lineage WHERE decision=?)", ctx.now(), id)
  }
  workspaceRuntime.bumpAccessRevision(ctx)
  if (item.home.kind === "member") auditPrivateEvent(ctx, { action: "project.references.remove", at: ctx.now(), actor: { kind: "member", member: by }, session: null, item: item.id, slug: item.slug, outcome: reason, run: null }, item.home.member)
  else ctx.audit({ actor: `member:${by}`, action: "project.references.remove", target: item.id, detail: { reason, environments: affected.length } })
}

// A workload whose scope names the project in projects was given the project
// by its device and has no checkout to mismatch, so its unprotected run may
// name no remote even when the project binds remotes, at start and on every
// use. A device's own key, a workload scoped by items, tags or other
// projects, and every protected run still match a bound remote.
export function pinnedWorkloadRun(state: AccessState, principal: Extract<AccessPrincipal, { kind: "device" }>, project: string, protectedEnv: boolean, now: number): boolean {
  return !protectedEnv && principalDevice(state, principal, now)?.workload?.projects?.includes(project) === true
}

// A run owns a continuing authorisation separate from the spent one-use start
// approval. The caller passes state reloaded inside its final transaction.
// Only the key that started the run uses it: the device's own key its own
// runs, a workload its own; another workload of the device sees no run.
export function assertRunUse(ctx: VaultContext, state: AccessState, runId: string, principal: Extract<AccessPrincipal, { kind: "device" }>, now: number): { project: string; env: string; snapshot: ProtectedSnapshot | null } {
  if (workspaceRuntime.setting(ctx, "frozen", false)) throw new VaultError("frozen", "This workspace is frozen.")
  const run = one(ctx.sql.exec<{ project: string; env: string; remote: string | null; grant_id: string | null; service: number }>("SELECT project,env,remote,grant_id,service FROM runs WHERE id=? AND device=? AND workload IS ? AND ended_at IS NULL AND expires_at>?", runId, principal.deviceId, principal.workload ?? null, now))
  if (!run) throw new VaultError("not_found", "No live run for this machine.")
  const saved = one(ctx.sql.exec<{ snapshot: string | null; credentials: string }>("SELECT snapshot,credentials FROM workspace_run_contexts WHERE run=?", runId))
  if (!saved) throw new VaultError("not_found", "No live run for this machine.")
  const env = state.projects.find((p) => p.id === run.project)?.environments.find((e) => e.name === run.env)
  refusal(can(state, principal, { type: env?.protected ? "run.protected" : "run.unprotected" }, { project: run.project, environment: run.env }, now))
  if (run.service && principalDevice(state, principal, now)?.scope.serviceRuns !== true) throw new VaultError("forbidden", "This machine may no longer run services; its owner changed what it may use.")
  const project = loadProject(ctx, run.project)
  const pinned = run.remote === null && pinnedWorkloadRun(state, principal, run.project, env?.protected ?? false, now)
  if (!project || !pinned && (run.remote === null ? project.remotes.length > 0 : !project.remotes.includes(run.remote))) throw new VaultError("remote_mismatch", "This run's repository is no longer bound.")
  for (const credential of JSON.parse(saved.credentials) as CheckedCredential[]) {
    const item = items.getItem(ctx, credential.slug)
    if (!item || item.id !== credential.id || canonicalJson(state.credentials.find(c=>c.id===item.id)?.home)!==canonicalJson(credential.home) || credential.configRevision !== undefined && item.configRev !== credential.configRevision) throw new VaultError("conflict", "A run credential changed; start a new run.")
    assertRunCredential(state, principal, credential.id, { project: run.project, environment: run.env }, now)
  }
  const snapshot = saved.snapshot ? JSON.parse(saved.snapshot) as ProtectedSnapshot : null
  if (snapshot) assertApprovedUse(ctx, state, snapshot, run.grant_id, now)
  else if (env?.protected) throw new VaultError("forbidden", "This run has no protected authorisation.")
  return { project: run.project, env: run.env, snapshot }
}
