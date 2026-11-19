import { canonicalJson, isLeaseOnly, type WorkspaceRunCreated } from "@mehen/protocol"
import { RunCreate, LeaseRequest, RUN_ARGV_LIMITS, type RunVar, type ApprovalSubject } from "@mehen/protocol/api"
import { deviceModeAllowed, KINDS } from "@mehen/protocol/kinds"
import { newPlaceholder } from "@mehen/protocol/placeholder"
import { z } from "zod"
import { VaultError } from "../../http.ts"
import { can, eligibility, principalDevice, type AccessAsk, type AccessPrincipal, type AccessState } from "../access.ts"
import { one, randomId, rows, type Area, type VaultContext } from "../core.ts"
import type { ApprovalPresentation, ItemRecord, OverrideResolutionHook } from "../services.ts"
import { digestOf, parseOpInput } from "./approvals.ts"
import { requestWorkspaceApproval, approvalBinding, workspaceApproval, readConsent, requesterBasis, accessChangeDevices } from "./approvals-workspace.ts"
import { askGroupExtra } from "./pending-workspace.ts"
import { assertApprovedUse, assertRunUse, consumeApprovedUse, currentRunSnapshot, pinnedWorkloadRun, type CheckedCredential, type ProtectedSnapshot } from "./projects-workspace.ts"
import { loadProject, normaliseRemote, requireEnvironment, type ProjectRecord } from "./projects.ts"
import { items, secretFieldInfo } from "./items.ts"
import { accessState, authorise, queueNotice, recordExposure, registerOffboardingHook, registerAccessChangeHook, workspaceRef, type WorkspaceInvocationContext } from "./workspace-runtime.ts"
import { RUN_MAX_LIFE_MS, RUN_TTL_MS } from "./runs.ts"
import { auditPrivateEvent } from "../audit.ts"

export const WORKSPACE_RUN_MIGRATION = `CREATE TABLE workspace_run_contexts (
  run TEXT PRIMARY KEY REFERENCES runs(id), snapshot TEXT, source_digest TEXT NOT NULL,
  credentials TEXT NOT NULL, overrides TEXT NOT NULL, approval TEXT
);`
// The workload that started the run, when one did: only it may use, renew,
// lease from or end the run. Its device's own key cannot end it; revoking
// the workload ends its live runs.
export const WORKSPACE_RUN_WORKLOAD_MIGRATION = `ALTER TABLE runs ADD COLUMN workload TEXT;
CREATE INDEX runs_workload ON runs(workload);`
// A service run (RunCreate.service) has no maximum life; every renewal
// re-plans it from the variables it asked for (vars, a JSON list) and ends it
// when the plan no longer matches source_digest, or the hosts fenced to the
// project's other environments no longer match fenced_hosts (a sorted JSON
// list, what the run's local relay refuses).
export const WORKSPACE_RUN_SERVICE_MIGRATION = `ALTER TABLE runs ADD COLUMN service INTEGER NOT NULL DEFAULT 0;
ALTER TABLE workspace_run_contexts ADD COLUMN vars TEXT;
ALTER TABLE workspace_run_contexts ADD COLUMN fenced_hosts TEXT;`
let overrideResolution: OverrideResolutionHook | null = null
// Registered by the area registry before workspace run dispatch.
export function registerOverrideResolutionHook(hook: OverrideResolutionHook | null): void { overrideResolution = hook }

type RunRow = { id: string; device: string; workload: string | null; session: string | null; project: string; env: string; remote: string | null; created_at: number; expires_at: number; ended_at: number | null; grant_id: string | null; leased_vars: string; service: number }
// pinnedWithoutRemote: a project-pinned workload's run that names no remote
// in a project that binds remotes (pinnedWorkloadRun), for the audit.
type Plan = { pinnedWithoutRemote: boolean; vars: RunVar[]; leases: { name: string; item: ItemRecord; field: string }[]; placeholders: { name: string; item: ItemRecord; field: string; prefix: string }[]; credentials: CheckedCredential[]; overrides: string[]; sourceDigest: string }
function devicePrincipal(principal: import("./workspace-runtime.ts").WorkspaceRuntimePrincipal): Extract<AccessPrincipal, { kind: "device" }> {
  if (principal.kind !== "device") throw new VaultError("forbidden", "Only an enrolled machine can start a run.")
  return principal
}
// A run refused because the project is not shared with the machine's owner
// (project_unshared): the project's managers are told, once a UTC day per
// project and member (queueNotice), and the refusal's next links to the
// project's page. Its link has no query, which mehen refuses on a refusal's
// link; only the notice, which a browser opens, chooses the member
// (shareRequestPath). A team's machine, or any other refusal, is passed on
// as it was.
function shareRequested(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, invocation: WorkspaceInvocationContext, project: string, error: unknown): unknown {
  if (!(error instanceof VaultError) || error.code !== "project_unshared") return error
  const state = accessState(ctx)
  const device = state.devices.find((d) => d.id === principal.deviceId), found = state.projects.find((p) => p.id === project)
  const member = device?.owner.kind === "member" ? state.members.find((m) => m.id === device.owner.id) : undefined
  if (!device || !found || !member) return error
  const machine = ctx.sql.exec<{ name: string }>("SELECT name FROM devices WHERE id=?", device.id).toArray()[0]?.name ?? device.id
  const day = new Date(ctx.now()).toISOString().slice(0, 10)
  queueNotice(ctx, { kind: "project_share_requested", workspace: workspaceRef(ctx), project: { id: found.id, slug: found.slug }, member: { member: member.id, name: member.name }, device: device.id, machine, at: new Date(ctx.now()).toISOString() }, `${found.id}:${member.id}:${day}`)
  return new VaultError(error.code, error.message, { ...error.extra, next: { say: error.message, ...error.extra.next, url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/projects/${encodeURIComponent(found.id)}` } })
}
function requireDecision(decision: ReturnType<typeof can>): void { if (!decision.allowed) throw new VaultError(decision.error, decision.message, decision.next ? { next: decision.next } : {}) }
function planRun(ctx: VaultContext, state: AccessState, principal: Extract<AccessPrincipal, { kind: "device" }>, input: z.infer<typeof RunCreate>): Plan {
  const project = loadProject(ctx, input.project)
  // Let the evaluator supply the uniform visibility refusal before reading names.
  const envState = state.projects.find((p) => p.id === input.project)?.environments.find((e) => e.name === input.env)
  requireDecision(can(state, principal, { type: envState?.protected ? "run.protected" : "run.unprotected" }, { project: input.project, environment: input.env }, ctx.now()))
  if (!project) throw new VaultError("not_found", "No such object.")
  const env = requireEnvironment(project, input.env)
  const device = principalDevice(state, principal, ctx.now())
  if (!device) throw new VaultError("not_found", "No such object.")
  const remote = input.remote === null ? null : normaliseRemote(input.remote)
  const pinnedWithoutRemote = input.remote === null && project.remotes.length > 0 && pinnedWorkloadRun(state, principal, project.id, env.protected, ctx.now())
  if (input.remote !== null && remote === null || (remote === null ? project.remotes.length > 0 && !pinnedWithoutRemote : !project.remotes.includes(remote))) throw new VaultError("remote_mismatch", "This checkout does not match the project's bound repository.")
  if (env.protected && input.envSource !== "flag") throw new VaultError("environment_refused", "A protected run needs a literal --env.")
  const vars: RunVar[] = [], leases: Plan["leases"] = [], placeholders: Plan["placeholders"] = [], credentials: CheckedCredential[] = [], overrides: string[] = []
  const sources: unknown[] = []
  for (const name of [...new Set(input.vars)]) {
    if (!project.vars.some((v) => v.name === name)) throw new VaultError("bad_request", `The project does not declare ${name}.`)
    const shared = project.vars.find((v) => v.env === env.name && v.name === name)
    if (!env.protected && device.owner.kind === "member" && !overrideResolution) throw new VaultError("internal", "Workspace override resolution is not registered.")
    const override = !env.protected && device.owner.kind === "member" && overrideResolution ? overrideResolution(ctx, device.owner.id, project.id, env.name, name) : null
    if (override?.kind === "item" && !device.scope.privateCredentials) throw new VaultError("not_found", "No such object.", { next: { say: "Use a machine allowed to reach your private credentials, or clear your override." } })
    if (override) overrides.push(name)
    const source = override ?? (shared?.item ? { kind: "item" as const, item: shared.item, field: shared.field ?? "" } : shared?.plain !== null && shared?.plain !== undefined ? { kind: "plain" as const, value: shared.plain } : null)
    sources.push({ name, source })
    if (!source) { vars.push({ name, delivery: "missing", next: { say: `Set ${name} for this environment.`, command: `mehen env set ${name} --env ${env.name}` } }); continue }
    if (source.kind === "plain") { vars.push({ name, delivery: "plain", value: source.value }); continue }
    const item = items.getItem(ctx, source.item)
    const visible = item && (can(state, principal, { type: "item.read" }, { credential: item.id }, ctx.now()).allowed || ["lease", "placeholder"].some((mode) => can(state, principal, { type: "item.use", context: { project: project.id, environment: env.name } }, { credential: item.id, mode: mode as "lease" | "placeholder" }, ctx.now()).allowed))
    if (!item || !visible) { vars.push({ name, delivery: "missing", next: { say: "This variable's credential is outside this machine's reach." } }); continue }
    const usable = can(state, principal, { type: "item.use", context: { project: project.id, environment: env.name } }, { credential: item.id, mode: "lease" }, ctx.now()).allowed || can(state, principal, { type: "item.use", context: { project: project.id, environment: env.name } }, { credential: item.id, mode: "placeholder" }, ctx.now()).allowed
    if (!usable || item.status === "disabled") { vars.push({ name, delivery: "missing", next: { say: "This variable cannot be delivered in this environment." } }); continue }
    const spec = KINDS[item.kind].fields.find((f) => f.name === source.field)
    if (!spec) { vars.push({ name, delivery: "missing", next: { say: "This variable's credential field no longer exists." } }); continue }
    const home = state.credentials.find((c) => c.id === item.id)?.home
    if (!home) throw new VaultError("not_found", "No such object.")
    if (!credentials.some((c) => c.id === item.id)) credentials.push({ id: item.id, slug: item.slug, home, configRevision: item.configRev })
    if (!spec.secret) { const value = item.publicFields[spec.name]; vars.push(value === undefined ? { name, delivery: "missing", next: { say: "This field is not set." } } : { name, delivery: "plain", value }); continue }
    const info = secretFieldInfo(ctx, item).find((f) => f.name === spec.name)
    if (!info?.set) { vars.push({ name, delivery: "missing", next: { say: "This credential field is not set." } }); continue }
    // A lease-only item has no host to swap a placeholder on, so a run leases it.
    if (item.injection && !isLeaseOnly(item.binding) && deviceModeAllowed(item.ceiling, "placeholder") && device.scope.modes.includes("placeholder") && can(state, principal, { type: "item.use", context: { project: project.id, environment: env.name } }, { credential: item.id, mode: "placeholder" }, ctx.now()).allowed) placeholders.push({ name, item, field: spec.name, prefix: info.prefix })
    else if (deviceModeAllowed(item.ceiling, "lease") && device.scope.modes.includes("lease")) leases.push({ name, item, field: spec.name })
    else vars.push({ name, delivery: "missing", next: { say: "Neither a placeholder nor a lease is permitted." } })
  }
  return { pinnedWithoutRemote, vars, leases, placeholders, credentials, overrides, sourceDigest: digestOf({ sources, credentials, leases: leases.map((l) => l.name), placeholders: placeholders.map((p) => p.name) }) }
}
function runApproval(ctx: VaultContext, state: AccessState, principal: Extract<AccessPrincipal, { kind: "device" }>, invocation: WorkspaceInvocationContext, input: z.infer<typeof RunCreate>, plan: Plan): { snapshot: ProtectedSnapshot; approval: string } {
  const project = loadProject(ctx, input.project)!
  if (!input.argv || input.argv.some((arg) => arg.length > RUN_ARGV_LIMITS.argChars) || input.argv.reduce((n, arg) => n + arg.length, 0) > RUN_ARGV_LIMITS.totalChars) throw new VaultError("mode_refused", "Send a complete command line small enough for a person to approve.")
  const presentation: ApprovalPresentation = { title: `Run ${project.slug} in ${input.env}`, details: [{ label: "Project", value: project.slug }, { label: "Environment", value: input.env }, { label: "Variables", value: input.vars.join(", ") }, ...plan.leases.map((l) => ({ label: "Real value", value: l.name })), ...plan.placeholders.map((p) => ({ label: "Placeholder", value: p.name }))], body: input.argv.map((arg) => JSON.stringify(arg)).join("\n"), settled: { details: [{ label: "Command SHA-256", value: digestOf(input.argv) }], body: null } }
  const subject: ApprovalSubject = { item: project.slug, method: "RUN", url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/projects/${project.id}`, contentType: null, contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf({ input: { ...input, approval: null }, sourceDigest: plan.sourceDigest }), constraints: { uses: 1, ttlSeconds: 3600 } }
  const base: ProtectedSnapshot = { device: principal.deviceId, ...(principal.workload !== undefined ? { workload: principal.workload } : {}), requester: requesterBasis(state, principal.deviceId, [project.id], ctx.now()), requesterProjects: [project.id], item: plan.credentials[0] ?? { id: project.id, slug: project.slug, home: { kind: "project", project: project.id }, configRevision: 0 }, project: project.id, environment: input.env, protected: true, reason: "protected", requestDigest: digestOf({ subject, presentation }), references: [], fourEyes: [], run: { items: plan.credentials, revision: 0, protectionRevision: 0, remote: input.remote === null ? null : normaliseRemote(input.remote) } }
  const { snapshot, ask } = currentRunSnapshot(ctx, state, base, ctx.now())
  const approval = input.approval ? workspaceApproval(ctx, input.approval) : null
  if (approval && approval.binding_digest === approvalBinding(subject, presentation, snapshot).digest) {
    try { assertApprovedUse(ctx, state, snapshot, approval.id, ctx.now()); return { snapshot, approval: approval.id } } catch (error) { if (!(error instanceof VaultError)) throw error }
  }
  // A run is decided on its own page, so its floor is NULL (counted as floor); its shape is the project, environment and command.
  const row = ctx.storage.transactionSync(() => requestWorkspaceApproval(ctx, state, ask, invocation.workspace, subject, presentation, snapshot, ctx.now(), { floor: null, shape: digestOf({ run: project.id, env: input.env, argv: digestOf(input.argv) }), replaces: null }))
  const device = state.devices.find((d) => d.id === principal.deviceId)
  const guest = device?.owner.kind === "member" && state.members.some((m) => m.id === device.owner.id && m.standing.effectiveRole === "guest")
  const deciders = guest ? [] : state.members.filter((m) => eligibility(state, m.id, ask, ctx.now()).canApprove).map((m) => m.name)
  // No command for a workload: mehen wait signs with the device's key, which cannot see a workload's approval.
  throw new VaultError("approval_required", "This protected run needs approval.", { approval: row.id, bindingCode: row.binding_code, expiresAt: new Date(row.expires_at).toISOString(), deciders, next: { url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/a/${row.id}`, ...(principal.workload === undefined ? { command: `mehen wait ${row.id}` } : {}), say: deciders.length ? `Send this link to ${deciders.join(" or ")}.` : `Send this link to a manager of ${project.slug}.` }, ...askGroupExtra(ctx, principal, invocation, row) })
}
// A service run lives while it renews, so only a machine a human allowed to
// (its scope's serviceRuns) starts one, and never in a protected environment,
// whose approval covers one run of at most two hours.
function assertServiceRun(ctx: VaultContext, state: AccessState, principal: Extract<AccessPrincipal, { kind: "device" }>, invocation: WorkspaceInvocationContext, protectedEnv: boolean): void {
  if (protectedEnv) throw new VaultError("environment_refused", "A service run cannot use a protected environment.", { next: { say: "Run the service in an unprotected environment, or run without --service: a protected run needs an approval and lives at most two hours." } })
  if (principalDevice(state, principal, ctx.now())?.scope.serviceRuns !== true) throw new VaultError("forbidden", "This machine may not start service runs.", { next: { url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/devices/${encodeURIComponent(principal.deviceId)}`, say: "Ask the machine's owner to tick May run services on its page under Machines and sign the change with a passkey, then run again." } })
}
function runEndsAt(createdAt: number, approved: boolean): number {
  return createdAt + (approved ? RUN_MAX_LIFE_MS.approved : RUN_MAX_LIFE_MS.other)
}
function validateRun(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, id: string, invocation?: WorkspaceInvocationContext): RunRow {
  const state = accessState(ctx)
  const checked = assertRunUse(ctx, state, id, principal, ctx.now())
  const env = state.projects.find((p) => p.id === checked.project)?.environments.find((e) => e.name === checked.env)
  if (invocation) authorise(ctx, invocation, { type: env?.protected ? "run.protected" : "run.unprotected" }, { project: checked.project, environment: checked.env }, ctx.now())
  const run = one(ctx.sql.exec<RunRow>("SELECT * FROM runs WHERE id=? AND device=? AND workload IS ? AND ended_at IS NULL AND expires_at>?", id, principal.deviceId, principal.workload ?? null, ctx.now()))
  if (!run) throw new VaultError("not_found", "No live run for this machine.")
  return run
}
// The hosts fenced to the project's other environments, which the run's
// local relay refuses: the vault never sees a leased value's request.
function fencedHostsOutside(project: ProjectRecord, env: string): string[] {
  return [...new Set(project.environments.filter((e) => e.name !== env).flatMap((e) => e.fences))].sort()
}
// With no maximum life to bound a stale plan, a service run is planned again
// on every renewal: a changed binding, override, delivery, credential or
// fence ends it, since its relay only learns fences when it starts. A plan
// that is now refused (an override to a private credential this machine may
// not use, say) is a changed source too.
function assertServicePlan(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, run: RunRow): void {
  const changed = new VaultError("conflict", "Run sources changed; start a new run.")
  const saved = one(ctx.sql.exec<{ source_digest: string; vars: string | null; fenced_hosts: string | null }>("SELECT source_digest,vars,fenced_hosts FROM workspace_run_contexts WHERE run=?", run.id))
  const vars = saved?.vars ? z.array(z.string()).parse(JSON.parse(saved.vars)) : null
  const project = loadProject(ctx, run.project)
  if (!saved || !vars || !project || JSON.stringify(fencedHostsOutside(project, run.env)) !== saved.fenced_hosts) throw changed
  let sourceDigest: string
  try {
    sourceDigest = planRun(ctx, accessState(ctx), principal, { project: run.project, env: run.env, envSource: "flag", remote: run.remote, worktree: "", head: null, command: "", vars }).sourceDigest
  } catch (error) {
    if (error instanceof VaultError) throw changed
    throw error
  }
  if (sourceDigest !== saved.source_digest) throw changed
}
export const workspaceRunOps: NonNullable<Area["workspaceOps"]> = {
  "runs.create": { auth: ["device"], async handler(ctx, runtimePrincipal, raw, invocation): Promise<WorkspaceRunCreated> {
    const principal = devicePrincipal(runtimePrincipal), input = parseOpInput(RunCreate, raw)
    const state = accessState(ctx), env = state.projects.find((p) => p.id === input.project)?.environments.find((e) => e.name === input.env)
    try { authorise(ctx, invocation, { type: env?.protected ? "run.protected" : "run.unprotected" }, { project: input.project, environment: input.env }, ctx.now()) } catch (error) { throw shareRequested(ctx, principal, invocation, input.project, error) }
    const plan = planRun(ctx, state, principal, input)
    if (input.service) assertServiceRun(ctx, state, principal, invocation, env?.protected === true)
    const approval = env?.protected ? runApproval(ctx, state, principal, invocation, input, plan) : null
    const opened = new Map<string, Record<string, string>>()
    for (const lease of plan.leases) if (!opened.has(lease.item.id)) opened.set(lease.item.id, await items.openSecrets(ctx, lease.item))
    const id = randomId("run"), now = ctx.now(), expiresAt = now + RUN_TTL_MS
    const placeholders = plan.placeholders.map((p) => ({ ...p, value: newPlaceholder(p.prefix) }))
    const vars: RunVar[] = [...plan.vars, ...placeholders.map((p): RunVar => ({ name: p.name, delivery: "placeholder", value: p.value, item: p.item.slug, hosts: p.item.binding.hosts })), ...plan.leases.map((l): RunVar => { const value = opened.get(l.item.id)?.[l.field]; return value === undefined ? { name: l.name, delivery: "missing", next: { say: "This field is no longer set." } } : { name: l.name, delivery: "lease", value, item: l.item.slug } })]
    let authorisation: WorkspaceRunCreated["authorisation"] = null
    ctx.storage.transactionSync(() => {
      const freshState = accessState(ctx), freshEnv = freshState.projects.find((p) => p.id === input.project)?.environments.find((e) => e.name === input.env)
      authorise(ctx, invocation, { type: freshEnv?.protected ? "run.protected" : "run.unprotected" }, { project: input.project, environment: input.env }, ctx.now())
      const freshPlan = planRun(ctx, freshState, principal, input)
      if (freshPlan.sourceDigest !== plan.sourceDigest || freshEnv?.protected !== env?.protected) throw new VaultError("conflict", "Run sources changed; start a new run.")
      if (input.service) assertServiceRun(ctx, freshState, principal, invocation, freshEnv?.protected === true)
      for (const lease of plan.leases) if (items.getItem(ctx, lease.item.slug)?.version !== lease.item.version) throw new VaultError("conflict", "The credential changed.")
      if (approval) { assertApprovedUse(ctx, freshState, approval.snapshot, approval.approval, ctx.now()); consumeApprovedUse(ctx, approval.snapshot, approval.approval) }
      ctx.sql.exec("INSERT INTO runs(id,device,workload,session,project,env,remote,worktree,head,command,grant_id,leased_vars,service,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", id, principal.deviceId, principal.workload ?? null, input.session ?? null, input.project, input.env, input.remote === null ? null : normaliseRemote(input.remote), input.worktree, input.head, (input.argv?.slice(0, 2).join(" ") ?? input.command).slice(0, 200), approval?.approval ?? null, JSON.stringify(plan.leases.map((l) => l.name)), input.service ? 1 : 0, now, expiresAt)
      ctx.sql.exec("INSERT INTO workspace_run_contexts(run,snapshot,source_digest,credentials,overrides,approval,vars,fenced_hosts) VALUES(?,?,?,?,?,?,?,?)", id, approval ? canonicalJson(approval.snapshot) : null, plan.sourceDigest, JSON.stringify(plan.credentials), JSON.stringify(plan.overrides), approval?.approval ?? null, JSON.stringify(input.vars), JSON.stringify(fencedHostsOutside(loadProject(ctx, input.project)!, input.env)))
      if (approval) {
        const row = workspaceApproval(ctx, approval.approval)!, consent = row.lineage ? readConsent(ctx, row.lineage) : null
        if (!consent) throw new VaultError("forbidden", "The run approval lost its consent.")
        const aid = randomId("rau"), until = Math.min(consent.lineage.expiresAt, now + RUN_MAX_LIFE_MS.approved)
        ctx.sql.exec("INSERT INTO run_authorisations(id,run,lineage,revision,valid_from,valid_until) VALUES(?,?,?,1,?,?)", aid, id, consent.lineage.id, now, until)
        authorisation = { id: aid, context: { project: input.project, environment: input.env }, expiresAt: new Date(until).toISOString() }
      }
      for (const p of placeholders) ctx.sql.exec("INSERT INTO run_placeholders(placeholder,run,item,field,hosts) VALUES(?,?,?,?,?)", p.value, id, p.item.slug, p.field, JSON.stringify(p.item.binding.hosts))
      ctx.audit({ actor: `device:${principal.deviceId}`, action: "run.create", target: id, detail: { project: input.project, env: input.env, vars: vars.map((v) => ({ name: v.name, delivery: v.delivery })), overrides: plan.overrides, approval: approval?.approval ?? null, ...(input.service ? { service: true } : {}), ...(freshPlan.pinnedWithoutRemote ? { remote: null, pinnedWorkload: true } : {}) } })
      const device = freshState.devices.find((d) => d.id === principal.deviceId)!
      for (const lease of plan.leases) {
        const event = `run:${id}:lease:${lease.item.id}:${lease.item.version}`
        auditLease(ctx, freshState, principal.deviceId, lease.item, id)
        recordExposure(ctx, { event, item: lease.item.id, version: lease.item.version, member: device.owner.kind === "member" ? device.owner.id : null, device: device.id, source: "leased", at: now })
      }
    })
    ctx.schedule("runs", id, expiresAt)
    const project = loadProject(ctx, input.project)!
    return { run: id, expiresAt: new Date(expiresAt).toISOString(), endsAt: input.service ? null : new Date(runEndsAt(now, approval !== null)).toISOString(), project: { id: project.id, slug: project.slug }, env: input.env, vars, interceptHosts: [...new Set(placeholders.flatMap((p) => p.item.binding.hosts))].sort(), fencedHosts: fencedHostsOutside(project, input.env), overrides: plan.overrides, authorisation }
  } },
  "runs.renew": { auth: ["device"], handler(ctx, runtimePrincipal, raw, invocation) {
    const principal = devicePrincipal(runtimePrincipal), { run: id } = parseOpInput(z.strictObject({ run: z.string().max(64) }), raw)
    return ctx.storage.transactionSync(() => {
      const run = validateRun(ctx, principal, id, invocation)
      if (run.service) assertServicePlan(ctx, principal, run)
      const endsAt = run.service ? null : runEndsAt(run.created_at, run.grant_id !== null), expiresAt = Math.min(ctx.now() + RUN_TTL_MS, endsAt ?? Infinity)
      ctx.sql.exec("UPDATE runs SET expires_at=? WHERE id=?", expiresAt, run.id)
      ctx.audit({ actor: `device:${principal.deviceId}`, action: "run.renew", target: id })
      return { run: id, expiresAt: new Date(expiresAt).toISOString(), endsAt: endsAt === null ? null : new Date(endsAt).toISOString() }
    })
  } },
  "runs.end": { auth: ["device"], handler(ctx, runtimePrincipal, raw, invocation) {
    const principal = devicePrincipal(runtimePrincipal), { run: id } = parseOpInput(z.strictObject({ run: z.string().max(64) }), raw)
    return ctx.storage.transactionSync(() => {
      const run = one(ctx.sql.exec<RunRow>("SELECT * FROM runs WHERE id=?", id))
      // Only the key that started a run ends it; the device ends a workload's
      // runs by revoking the workload.
      if (!run || run.workload !== (principal.workload ?? null)) throw new VaultError("not_found", "No such run.")
      authorise(ctx, invocation, { type: "run.end" }, { device: run.device, run: run.id }, ctx.now())
      ctx.sql.exec("UPDATE runs SET ended_at=? WHERE id=? AND ended_at IS NULL", ctx.now(), id)
      ctx.sql.exec("DELETE FROM run_placeholders WHERE run=?", id)
      ctx.sql.exec("UPDATE run_authorisations SET revoked_at=? WHERE run=?", ctx.now(), id)
      ctx.audit({ actor: `device:${principal.deviceId}`, action: "run.end", target: id })
      return { run: id, ended: true }
    })
  } },
  "runs.lease": { auth: ["device"], async handler(ctx, runtimePrincipal, raw, invocation) {
    const principal = devicePrincipal(runtimePrincipal), input = parseOpInput(LeaseRequest, raw), run = validateRun(ctx, principal, input.run, invocation)
    const leased = JSON.parse(run.leased_vars) as string[]
    // Check the signed lease set before planning only that set; checking the
    // selected plan afterwards made the refusal unreachable for omitted vars.
    if (run.grant_id && !loadProject(ctx, run.project)?.vars.some(v => v.env === run.env && leased.includes(v.name) && v.item === input.item && (input.field === undefined || v.field === input.field))) throw new VaultError("mode_refused", "This run did not authorise a lease of this field.")
    const runInput = { project: run.project, env: run.env, envSource: "flag" as const, remote: run.remote, worktree: "", head: null, command: "", vars: leased }
    const plan = planRun(ctx, accessState(ctx), principal, runInput)
    const lease = plan.leases.find(l => l.item.slug === input.item && (input.field === undefined || l.field === input.field))
    if (!lease) throw new VaultError("not_found", "No such credential in this run.")
    const { item, field } = lease
    const value = (await items.openSecrets(ctx, item))[field]
    if (value === undefined) throw new VaultError("mode_refused", "This field is not set.")
    ctx.storage.transactionSync(() => {
      validateRun(ctx, principal, input.run, invocation)
      if (planRun(ctx, accessState(ctx), principal, runInput).sourceDigest !== plan.sourceDigest) throw new VaultError("conflict", "Run sources changed; start a new run.")
      if (items.getItem(ctx, item.slug)?.version !== item.version) throw new VaultError("conflict", "The credential changed.")
      const state = accessState(ctx), device = state.devices.find((d) => d.id === principal.deviceId)!
      authorise(ctx, invocation, { type: "item.use", context: { project: run.project, environment: run.env } }, { credential: item.id, mode: "lease" }, ctx.now())
      auditLease(ctx, state, principal.deviceId, item, run.id)
      recordExposure(ctx, { event: `run:${run.id}:lease:${item.id}:${item.version}`, item: item.id, version: item.version, member: device.owner.kind === "member" ? device.owner.id : null, device: device.id, source: "leased", at: ctx.now() })
    })
    return { value, expiresAt: new Date(run.expires_at).toISOString() }
  } },
}

export function workspaceRunPlaceholders(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, run: string) {
  validateRun(ctx, principal, run)
  return rows(ctx.sql.exec<{ placeholder: string; item: string; field: string; hosts: string }>("SELECT * FROM run_placeholders WHERE run=?", run)).map((p) => ({ placeholder: p.placeholder, item: p.item, field: p.field, hosts: JSON.parse(p.hosts) as string[] }))
}
export function invalidateMemberRuns(ctx: VaultContext, member: string): void {
  for (const device of accessChangeDevices(accessState(ctx), member, {})) invalidateDeviceRuns(ctx, device)
}
function invalidateDeviceRuns(ctx: VaultContext, device: string): void {
    ctx.sql.exec("UPDATE runs SET ended_at=? WHERE device=? AND ended_at IS NULL", ctx.now(), device)
    ctx.sql.exec("DELETE FROM run_placeholders WHERE run IN (SELECT id FROM runs WHERE device=?)", device)
    ctx.sql.exec("UPDATE approvals SET status='denied' WHERE device=? AND ask IS NOT NULL AND status='pending'", device)
    ctx.sql.exec("UPDATE protected_use_grants SET revoked_at=? WHERE approval IN(SELECT id FROM approvals WHERE device=? AND ask IS NOT NULL)", ctx.now(), device)
    ctx.sql.exec("UPDATE run_authorisations SET revoked_at=? WHERE run IN(SELECT id FROM runs WHERE device=?)", ctx.now(), device)
    ctx.sql.exec("UPDATE policy_proposals SET status='cancelled' WHERE device=? AND ask IS NOT NULL AND status='pending'", device)
}

registerOffboardingHook("projects", (ctx, snapshot) => invalidateMemberRuns(ctx, snapshot.member))
registerAccessChangeHook("projects", (ctx, member, _reason, target) => {
  for (const device of accessChangeDevices(accessState(ctx), member, target)) invalidateDeviceRuns(ctx, device)
})

export function auditLease(ctx: VaultContext, state: AccessState, deviceId: string, item: ItemRecord, run: string): void {
  const credential = state.credentials.find((c) => c.id === item.id), device = state.devices.find((d) => d.id === deviceId)
  if (!device) throw new VaultError("not_found", "No such object.")
  if (credential?.home.kind === "member") auditPrivateEvent(ctx, { action: "run.lease", at: ctx.now(), actor: { kind: "device", device: deviceId, owner: device.owner.kind === "member" ? { kind: "member", member: device.owner.id } : { kind: "team", team: device.owner.id } }, session: null, item: item.id, slug: item.slug, outcome: "leased", run }, credential.home.member)
  else ctx.audit({ actor: `device:${deviceId}`, action: "run.lease", target: item.id, detail: { run, outcome: "leased" } })
}
