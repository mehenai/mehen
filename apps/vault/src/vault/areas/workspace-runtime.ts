// Workspace authority is reloaded here at the final synchronous commit point.
// The Worker verifies account step-ups; the dispatcher verifies device proofs.
import { createHash } from "node:crypto"
import { z } from "zod"
import { SessionIdentityCheckSchema, WorkspaceRoleSchema, AccountRestrictionSchema, AccountSecurityStateSchema, PendingAccountSecuritySchema, InviteTermsSchema, EnrolStartContextSchema, EnrolOwnerIntentSchema, EnrolEvidenceSchema, WorkspaceEnrolEvidenceViewSchema, OwnerRefSchema, WorkspaceDeviceScopeSchema, WorkspaceRefSchema, WorkloadScopeSchema, EnrolRequestedScopeSchema, isDeviceJwk, WorkspaceNoticePayloadSchema, WorkspaceNoticeSchema, canonicalJson, exhaustedNameBudget, parseProof } from "@mehen/protocol"
import { platformMaySatisfy } from "@mehen/protocol"
import type { AccountSecurityState, PendingAccountSecurity, WorkspaceNoticePayload, WorkspaceStepUpAction } from "@mehen/protocol"
import { VaultError } from "../../http.ts"
import { INVITE_TTL_MS } from "@mehen/protocol"
import { can, classify, stepUpSatisfies } from "../access.ts"
import type { AccessAction, AccessDecision, AccessMember, AccessPrincipal, AccessState, AccessTarget } from "../access.ts"
import type { AccountInvocationAuth, DeviceAuth, PlatformInvocationAuth, SystemAuth, VaultContext } from "../core.ts"
import { one, randomId } from "../core.ts"
import { lapseMandates } from "./mandates-lapse.ts"
import type { ExposureFact } from "../services.ts"
import { beforeManagementChange, isolateManagementGuardsForTests } from "./management-guard.ts"
export { beforeManagementChange, registerManagementGuard } from "./management-guard.ts"

export type WorkspaceRuntimeAuth = AccountInvocationAuth | DeviceAuth | PlatformInvocationAuth | Pick<SystemAuth, "kind" | "actor">
export type DeviceInvocationAuth = DeviceAuth
export type WorkspaceInvocationContext = { auth: WorkspaceRuntimeAuth; workspace: import("@mehen/protocol").WorkspaceRef }
export type WorkspaceRuntimePrincipal = AccessPrincipal | { kind: "system" }
export type AccessAllowed = Extract<AccessDecision, { allowed: true }> & { auth: WorkspaceRuntimeAuth; principal: AccessPrincipal; classification: import("../access.ts").AccessClassification; action: AccessAction; target: AccessTarget }
// Retained authority checks ignore only the named member's session gate;
// membership, role, recovery restrictions and pending transitions remain live.
export function capabilityState(state: AccessState, member: string): AccessState {
  return { ...state, members: state.members.map(m => m.id === member ? { ...m, standing: { ...m.standing, identityGate: { ...m.standing.identityGate, covered: false } } } : m) }
}
export type AccessStateProvider = (ctx: VaultContext, credentials: AccessState["credentials"]) => Partial<Pick<AccessState, "projects" | "credentials">>
const providers = new Map<"projects" | "credentials", AccessStateProvider>()
export function registerAccessStateProvider(name: "projects" | "credentials", provider: AccessStateProvider): void { providers.set(name, provider) }
export function digest(value: unknown): string { return createHash("sha256").update(canonicalJson(value)).digest("base64url") }
export function setting<T>(ctx: VaultContext, key: string, fallback: T): T {
  const row = one(ctx.sql.exec<{ value: string }>("SELECT value FROM tenant_state WHERE key=?", key))
  return row ? JSON.parse(row.value) as T : fallback
}
export function setSetting(ctx: VaultContext, key: string, value: unknown): void { ctx.sql.exec("INSERT INTO tenant_state(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, canonicalJson(value)) }
export function bumpAccessRevision(ctx: VaultContext): number { const revision = setting(ctx, "access_rev", 0) + 1; setSetting(ctx, "access_rev", revision); return revision }
// The one platform fact a managed workspace keeps (areas/managed.ts): the
// platform that owns it, the subject it is for, and the subject member that
// stands for that subject. Absent in every other workspace.
export type ManagedSetting = { platform: string; subject: string; member: string; createdAt: number }
export function managedSetting(ctx: VaultContext): ManagedSetting | null { return setting<ManagedSetting | null>(ctx, "managed", null) }
export function workspaceRef(ctx: VaultContext): import("@mehen/protocol").WorkspaceRef {
  const workspace = setting<import("@mehen/protocol").WorkspaceRef | null>(ctx, "workspace", null)
  if (!workspace) throw new VaultError("not_found", "No such workspace.")
  return workspace
}
export function security(ctx: VaultContext, account: string): AccountSecurityState | null {
  const row = one(ctx.sql.exec<{ state: string }>("SELECT state FROM account_security WHERE account=?", account))
  return row ? AccountSecurityStateSchema.parse(JSON.parse(row.state)) : null
}
function saveSecurity(ctx: VaultContext, state: AccountSecurityState): void { ctx.sql.exec("INSERT INTO account_security(account,state) VALUES (?,?) ON CONFLICT(account) DO UPDATE SET state=excluded.state", state.account, canonicalJson(state)) }
const union = (a: string[], b: string[]) => [...new Set([...a, ...b])].sort()
function strictest(a: AccountSecurityState["restriction"], b: AccountSecurityState["restriction"]): AccountSecurityState["restriction"] { return !a || b && b.until > a.until ? b : a }
export function installSecurity(ctx: VaultContext, account: string, committedEpoch: number, pending: PendingAccountSecurity | null): AccountSecurityState {
  const old = security(ctx, account) ?? { account, installedEpoch: 0, restriction: null, revokedSessionIds: [], removedFactorIds: [], deleting: false, pending: null }
  const next = structuredClone(old)
  next.installedEpoch = Math.max(old.installedEpoch, committedEpoch)
  if (pending && pending.reservedEpoch > next.installedEpoch && (!old.pending || pending.reservedEpoch >= old.pending.reservedEpoch)) {
    next.pending = { ...pending, revokedSessionIds: union(old.pending?.revokedSessionIds ?? [], pending.revokedSessionIds), removedFactorIds: union(old.pending?.removedFactorIds ?? [], pending.removedFactorIds), restriction: strictest(old.pending?.restriction ?? null, pending.restriction) }
    next.revokedSessionIds = union(old.revokedSessionIds, next.pending.revokedSessionIds)
    next.removedFactorIds = union(old.removedFactorIds, next.pending.removedFactorIds)
    next.restriction = strictest(old.restriction, next.pending.restriction)
  }
  if (next.pending && next.installedEpoch >= next.pending.reservedEpoch) next.pending = null
  saveSecurity(ctx, next)
  if (canonicalJson(old) !== canonicalJson(next)) {
    ctx.audit({ actor: "system", action: "account.security.install", target: account, detail: { installedEpoch: next.installedEpoch, reservedEpoch: next.pending?.reservedEpoch ?? null } })
    for (const hook of securityChangeHooks.values()) hook(ctx, account)
  }
  return next
}
// Run after an account's security state here changed (a new epoch, a
// recovery pending, a restriction), inside the same transaction.
export type SecurityChangeHook = (ctx: VaultContext, account: string) => void
const securityChangeHooks = new Map<string, SecurityChangeHook>()
export function registerSecurityChangeHook(name: string, hook: SecurityChangeHook): void { securityChangeHooks.set(name, hook) }
export function observeCommittedEpoch(ctx: VaultContext, account: string, epoch: number): AccountSecurityState { return installSecurity(ctx, account, epoch, null) }
export type MemberRow = { id: string; account: string; name: string; role: import("@mehen/protocol").WorkspaceRole; pending_role: import("@mehen/protocol").WorkspaceRole | null; status: AccessMember["status"]; check_sequence: number; pending_action: string | null; pending_by: string | null; pending_since: number | null; gate_generation: number; joined_at: number; revision: number }
export function memberRows(ctx: VaultContext): MemberRow[] { return ctx.sql.exec<MemberRow>("SELECT * FROM members").toArray() }
export function pendingRoleOf(member: Pick<MemberRow,"pending_role" | "pending_since">,now: number): import("@mehen/protocol").WorkspaceRole | null { return member.pending_since !== null && member.pending_since+INVITE_TTL_MS>now ? member.pending_role : null }
function frozen<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value)
    for (const child of Object.values(value)) frozen(child)
  }
  return value
}
// Frozen, because every call on this object shares one copy
// (TenantVault.invoke): a caller that needs a changed state copies it.
export function accessState(ctx: VaultContext): AccessState {
  const memo = ctx.accessStateMemo
  if (memo?.state && memo.writes === ctx.storageWrites && ctx.now() < memo.until) return memo.state
  const writes = ctx.storageWrites, now = ctx.now()
  const built = buildAccessState(ctx, now)
  if (memo) Object.assign(memo, { writes, until: built.until, state: frozen(built.state) })
  return built.state
}
// `until` is when the state next changes without a write: the first open
// invite's pending role to lapse.
function buildAccessState(ctx: VaultContext, now: number): { state: AccessState; until: number } {
  const rows = memberRows(ctx)
  const until = Math.min(Infinity, ...rows.map((m) => m.pending_since === null ? Infinity : m.pending_since + INVITE_TTL_MS).filter((at) => at > now))
  const members = rows.map((m): AccessMember => {
    const sec = security(ctx, m.account)
    const rule = setting<import("@mehen/protocol").IdentityRule>(ctx, "identity_rule", null)
    return { id: m.id, account: m.account, name: m.name, status: m.status, canCreateWorkspaces: false, standing: { identityRule: rule, checkSequence: m.check_sequence, effectiveRole: m.role, pendingRole: pendingRoleOf(m,now), restriction: sec?.restriction ?? null, identityGate: { covered: rule?.roles.includes(m.role) ?? false, admitted: !rule?.roles.includes(m.role), checkedAt: null }, identityRuleRev: setting(ctx, "identity_rule_rev", 0), gateGeneration: m.gate_generation, transitionPending: sec?.pending !== null && sec?.pending !== undefined } }
  })
  const teams = ctx.sql.exec<{ id: string; name: string }>("SELECT id,name FROM teams").toArray().map((t) => ({ ...t, members: ctx.sql.exec<{ member: string }>("SELECT member FROM team_members WHERE team=?", t.id).toArray().map((m) => m.member) }))
  const shares = ctx.sql.exec<{ value: string }>("SELECT value FROM project_shares").toArray().map((s) => JSON.parse(s.value) as import("@mehen/protocol").Share)
  const devices = ctx.sql.exec<{ id: string; owner_kind: "member" | "team"; owner_id: string; scope: string; revoked_at: number | null }>("SELECT id,owner_kind,owner_id,scope,revoked_at FROM devices WHERE owner_kind IS NOT NULL").toArray().map((d) => ({ id: d.id, owner: { kind: d.owner_kind, id: d.owner_id }, scope: JSON.parse(d.scope) as import("@mehen/protocol").WorkspaceDeviceScope, status: d.revoked_at === null ? "active" as const : "revoked" as const }))
  // Every workload not yet swept as ended; the evaluator checks expiry and revocation itself.
  const workloads = ctx.sql.exec<{ id: string; device: string; scope: string; expires_at: number; revoked_at: number | null }>("SELECT id,device,scope,expires_at,revoked_at FROM workloads WHERE ended_at IS NULL").toArray().map((w) => ({ id: w.id, device: w.device, scope: WorkloadScopeSchema.parse(JSON.parse(w.scope)), expiresAt: w.expires_at, revokedAt: w.revoked_at }))
  const credentials = providers.get("credentials")?.(ctx, []).credentials ?? []
  const projects = providers.get("projects")?.(ctx, credentials).projects ?? []
  const endedShares = ctx.sql.exec<{ share: string }>("SELECT e.share FROM share_ends_settled e JOIN project_shares s ON s.id=e.share AND s.value=e.terms").toArray().map((row) => row.share)
  return { state: { accessRev: setting(ctx, "access_rev", 0), members, teams, shares, devices, workloads, projects, credentials, endedShares }, until }
}
export function principalOf(ctx: VaultContext, auth: WorkspaceRuntimeAuth): WorkspaceRuntimePrincipal {
  if (auth.kind === "system") return { kind: "system" }
  if (auth.kind === "device") { const claims = parseProof(auth.proof).claims; return { kind: "device", deviceId: claims.dev, ...(claims.wkl !== undefined ? { workload: claims.wkl } : {}) } }
  if (auth.kind === "platform") return platformPrincipal(ctx, auth)
  const state = accessState(ctx)
  const member = state.members.find((m) => m.account === auth.account && m.status !== "removed")
  if (!member) throw new VaultError("not_found", "No such workspace.")
  let sec = security(ctx, auth.account)
  if (auth.securityEpoch < (sec?.installedEpoch ?? 0) || sec?.revokedSessionIds.includes(auth.session) || auth.stepUpFactor && sec?.removedFactorIds.includes(auth.stepUpFactor) || sec?.deleting) throw new VaultError("unauthenticated", "This session is no longer authorised.")
  if (auth.securityEpoch > (sec?.installedEpoch ?? 0)) sec = observeCommittedEpoch(ctx, auth.account, auth.securityEpoch)
  return { kind: "member", memberId: member.id, account: auth.account, session: auth.session, securityEpoch: auth.securityEpoch, sessionCheck: auth.sessionCheck }
}
// A platform acts as its managed workspace's subject member, and only there:
// the evaluator sees an owner, and the operation list is what limits it.
function platformPrincipal(ctx: VaultContext, auth: PlatformInvocationAuth): Extract<AccessPrincipal, { kind: "member" }> {
  const managed = managedSetting(ctx)
  const member = managed && managed.platform === auth.platform && managed.subject === auth.subject ? accessState(ctx).members.find((m) => m.id === managed.member && m.status === "active") : undefined
  if (!member) throw new VaultError("not_found", "No such subject.")
  return { kind: "member", memberId: member.id, account: member.account, session: `platform:${auth.key}`, securityEpoch: 0, sessionCheck: null }
}
export function authorise(ctx: VaultContext, invocation: WorkspaceInvocationContext, action: AccessAction, target: AccessTarget = {}, now = ctx.now()): AccessAllowed {
  const auth = invocation.auth
  const principal = principalOf(ctx, auth)
  if (principal.kind === "system") throw new VaultError("forbidden", "System calls have no member authority.")
  const state = eligibilityState(ctx, invocation)
  const classification = classify(state, action, target)
  const decision = can(state, principal, action, target, now)
  if (!decision.allowed) {
    const sec = auth.kind === "account" ? security(ctx, auth.account) : null
    const transition = decision.error === "account_pending" && sec?.pending ? { id: sec.pending.transitionId, reservedEpoch: sec.pending.reservedEpoch, targets: 0, acknowledged: 0, state: "pending" as const } : undefined
    throw new VaultError(decision.error, decision.message, { ...(decision.next ? { next: decision.next } : {}), ...(transition ? { transition, next: { url: `${ctx.env.VAULT_ORIGIN}/account`, say: "Wait for this account security change to finish." } } : {}) })
  }
  if (principal.kind === "device" && !["read", "narrow"].includes(classification) && setting(ctx, "frozen", false)) throw new VaultError("frozen", "This workspace is frozen.")
  return { ...decision, auth, principal, classification, action, target }
}
export function requireStepUp(ctx: VaultContext, decision: AccessAllowed, expected: WorkspaceStepUpAction, invocation: WorkspaceInvocationContext): void {
  decision = authorise(ctx, invocation, decision.action, decision.target, ctx.now())
  const auth = invocation.auth
  // The platform's proof over the exact request is its attestation, for the
  // step-ups PLATFORM_STEP_UPS lists; where an action binds state, the
  // handler compares what the body names, as it does for a passkey.
  if (auth.kind === "platform") {
    if (!stepUpSatisfies(decision, expected) || !platformMaySatisfy(expected)) throw new VaultError("forbidden", "A platform cannot confirm this action.")
    return
  }
  if (!stepUpSatisfies(decision, expected)) throw new VaultError("forbidden", "This needs a passkey confirmation of the exact action.")
  const account = verifiedStepUp(ctx, invocation, expected)
  const principal = principalOf(ctx, account)
  if (principal.kind === "member" && accessState(ctx).members.find((m) => m.id === principal.memberId)?.standing.identityGate.covered && (expected.type === "enrol.accept" || expected.type === "enrol.approve" || expected.type === "device.rescope_accept" || decision.action.type === "device.rescope_admit" || expected.type === "workspace.identity_rule")) {
    requireOperationIdentity(ctx, principal.memberId, expected, account.operationCheck)
  }
}
// The passkey half of requireStepUp: a person's assertion with a passkey
// factor that is not removed, over exactly `expected`. approval.decide_many
// checks it once, then each entry's rights as its own approval.decide.
export function verifiedStepUp(ctx: VaultContext, invocation: WorkspaceInvocationContext, expected: WorkspaceStepUpAction): AccountInvocationAuth {
  const auth = invocation.auth
  const verified = auth.kind === "account" ? auth.stepUp ?? null : null
  const sec = auth.kind === "account" ? security(ctx, auth.account) : null
  if (auth.kind !== "account" || !auth.stepUpFactor?.startsWith("pk_") || sec?.removedFactorIds.includes(auth.stepUpFactor) || canonicalJson(verified) !== canonicalJson(expected)) throw new VaultError("forbidden", "This needs a passkey confirmation of the exact action.")
  return auth
}
function nameSubjects(ctx: VaultContext, p: WorkspaceRuntimePrincipal): string[] {
  if (p.kind === "system") throw new VaultError("forbidden", "System calls cannot reserve names.")
  if (p.kind === "member") { const m = accessState(ctx).members.find((m) => m.id === p.memberId); if (!m || m.status !== "active") throw new VaultError("forbidden", "No active membership."); return [`account:${m.account}`] }
  const d = accessState(ctx).devices.find((d) => d.id === p.deviceId)
  if (!d || d.status !== "active") throw new VaultError("forbidden", "No active machine.")
  const account = d.owner.kind === "member" ? accessState(ctx).members.find((m) => m.id === d.owner.id)?.account : undefined
  return [`device:${p.deviceId}`, ...(account ? [`account:${account}`] : [])]
}
export const nameMiss = {
  check(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, now = ctx.now()): { ok: true } | { ok: false; retryAfter: number } {
    const refusal = exhaustedNameBudget(nameSubjects(ctx, principal).map((subject) => one(ctx.sql.exec<{ windowStart: number; count: number }>("SELECT window_start AS windowStart,count FROM name_miss_buckets WHERE subject=?", subject))).filter((b) => b !== null), now)
    return refusal ? { ok: false, retryAfter: refusal.retryAfter } : { ok: true }
  },
  record(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, now = ctx.now()): void {
    ctx.storage.transactionSync(() => { for (const subject of nameSubjects(ctx, principal)) {
      const old = one(ctx.sql.exec<{ window_start: number; count: number }>("SELECT window_start,count FROM name_miss_buckets WHERE subject=?", subject))
      const fresh = !old || old.window_start + 3_600_000 <= now
      const count = fresh ? 1 : old.count + 1
      ctx.sql.exec("INSERT INTO name_miss_buckets(subject,window_start,count) VALUES (?,?,?) ON CONFLICT(subject) DO UPDATE SET window_start=excluded.window_start,count=excluded.count", subject, fresh ? now : old.window_start, count)
      if (count === 20) ctx.audit({ actor: "system", action: "name.miss_limit", detail: { subject, count } })
    } })
  },
}
export function recordExposure(ctx: VaultContext, fact: ExposureFact): void {
  ctx.sql.exec("INSERT OR IGNORE INTO exposures(event,item,version,member,device,source,at) VALUES (?,?,?,?,?,?,?)", fact.event, fact.item, fact.version, fact.member, fact.device, fact.source, fact.at)
}
// How many accounts it queued the notice for.
export function queueNotice(ctx: VaultContext, payload: WorkspaceNoticePayload, sourceId?: string): number {
  // A managed workspace's only member has no account to notify, and its
  // platform reads the audit instead.
  if (managedSetting(ctx)) return 0
  const checked = WorkspaceNoticePayloadSchema.parse(payload)
  const members = memberRows(ctx)
  const recipients = checked.kind === "member_joined" ? members.filter((m) => m.status === "active" && m.id === checked.by).map((m) => m.account) : checked.kind === "mandate_ending" || checked.kind === "mandate_lapsed" ? [] : members.filter((m) => m.status === "active" && (m.role === "owner" || checked.kind !== "owner_changed" && m.role === "admin")).map((m) => m.account)
  if (checked.kind === "owner_changed" || checked.kind === "backup_recipient") { const subject = members.find((m) => m.id === checked.member); if (subject) recipients.push(subject.account) }
  // A mandate that tripped goes to its signer too, whatever their role; one
  // ending or lapsed goes to its signer alone.
  if (checked.kind === "mandate_tripped" || checked.kind === "mandate_ending" || checked.kind === "mandate_lapsed") { const signer = members.find((m) => m.status === "active" && m.id === checked.signer.member); if (signer) recipients.push(signer.account) }
  let queued = 0
  for (const account of new Set(recipients)) {
    if ((checked.kind === "account_security" || checked.kind === "account_suspended") && account === checked.account) continue
    const id = `ntc_${digest({ account, payload: checked, source: sourceId ?? null })}`
    ctx.sql.exec("INSERT OR IGNORE INTO notice_outbox(id,account,payload,created_at,next_retry_at) VALUES (?,?,?,?,?)", id, account, canonicalJson(checked), ctx.now(), ctx.now())
    ctx.schedule("access", "notice-outbox", ctx.now() + 60_000)
    queued++
  }
  return queued
}
export const SecurityInstallInput = z.strictObject({ account: z.string(), committedEpoch: z.number().int().nonnegative(), pending: PendingAccountSecuritySchema.nullable() })
export const SecurityCommitInput = SecurityInstallInput.omit({ pending: true })
export const SecurityOutput = z.strictObject({ installedEpoch: z.number().int().nonnegative() })
export const OutboxDrainInput = z.strictObject({ limit: z.number().int().min(1).max(100).default(50) })
// One notice wire type everywhere: the outbox envelope is the
// protocol's WorkspaceNotice.
export const OutboxEventSchema = WorkspaceNoticeSchema
export const OutboxDrainOutput = z.strictObject({ events: z.array(OutboxEventSchema) })
export function drainOutbox(ctx: VaultContext, limit: number): z.infer<typeof OutboxDrainOutput> {
  const events = ctx.sql.exec<{ id: string; account: string; payload: string; created_at: number }>("SELECT id,account,payload,created_at FROM notice_outbox WHERE acknowledged_at IS NULL AND next_retry_at<=? ORDER BY created_at,id LIMIT ?", ctx.now(), limit).toArray().map((e) => {
    const payload = WorkspaceNoticePayloadSchema.parse(JSON.parse(e.payload))
    const path = payload.kind === "machine_added" ? `/devices/${encodeURIComponent(payload.device)}` : payload.kind === "member_joined" ? "/people" : payload.kind === "mandate_signed" || payload.kind === "mandate_tripped" || payload.kind === "mandate_ending" || payload.kind === "mandate_lapsed" ? `/mandates/${encodeURIComponent(payload.mandate)}` : "/"
    return { id: e.id, account: e.account, payload, at: e.created_at, url: `${ctx.env.VAULT_ORIGIN}/w/${encodeURIComponent(payload.workspace.slug)}${path}` }
  })
  return OutboxDrainOutput.parse({ events })
}
export function newMember(ctx: VaultContext, account: string, name: string, role: import("@mehen/protocol").WorkspaceRole, status: AccessMember["status"], id = randomId("mem")): string {
  const existing = one(ctx.sql.exec<{ account: string }>("SELECT account FROM members WHERE id=?", id))
  if (existing) { if (existing.account !== account) throw new VaultError("conflict", "This membership reservation belongs to another account."); return id }
  beforeManagementChange(ctx)
  ctx.sql.exec("INSERT INTO members(id,account,name,role,status,joined_at) VALUES (?,?,?,?,?,?)", id, account, name, role, status, ctx.now())
  if (!security(ctx, account)) saveSecurity(ctx, { account, installedEpoch: 0, pending: null, restriction: null, revokedSessionIds: [], removedFactorIds: [], deleting: false })
  return id
}

// Grants an invitation's teams and shares and makes its member active, on
// confirmation or on a redemption that joins straight away. The caller has
// checked the terms and owns the synchronous transaction.
export function activateInvitedMember(ctx: VaultContext, member: string, invite: string, terms: import("@mehen/protocol").InviteTerms): void {
  beforeManagementChange(ctx)
  for (const team of terms.teams) ctx.sql.exec("INSERT INTO team_members(team,member) VALUES (?,?)", team, member)
  for (const share of terms.shares) { const value = { ...share, id: randomId("shr"), subject: { kind: "member", member } }; ctx.sql.exec("INSERT INTO project_shares VALUES (?,?,?,?,?)", value.id, share.project, "member", member, canonicalJson(value)) }
  ctx.sql.exec("UPDATE members SET status='active',revision=revision+1 WHERE id=?", member)
  ctx.sql.exec("UPDATE invites SET status='active' WHERE id=?", invite)
}

// The caller owns authorisation and the surrounding synchronous transaction.
export function setProjectShare(ctx: VaultContext, after: import("@mehen/protocol").Share | null, before: import("@mehen/protocol").Share | null): void {
  const subject = before ?? after
  if (!subject) throw new VaultError("bad_request", "A share subject is required.")
  if (before && after && (before.id !== after.id || before.project !== after.project || canonicalJson(before.subject) !== canonicalJson(after.subject))) throw new VaultError("conflict", "The expected state changed.")
  const id = subject.subject.kind === "member" ? subject.subject.member : subject.subject.team
  const old = one(ctx.sql.exec<{ value: string }>("SELECT value FROM project_shares WHERE project=? AND subject_kind=? AND subject_id=?", subject.project, subject.subject.kind, id))
  if (canonicalJson(old ? JSON.parse(old.value) : null) !== canonicalJson(before)) throw new VaultError("conflict", "The expected state changed.")
  beforeManagementChange(ctx)
  if (after) ctx.sql.exec("INSERT INTO project_shares(id,project,subject_kind,subject_id,value) VALUES (?,?,?,?,?) ON CONFLICT(project,subject_kind,subject_id) DO UPDATE SET value=excluded.value", after.id, after.project, after.subject.kind, id, canonicalJson(after))
  else ctx.sql.exec("DELETE FROM project_shares WHERE id=?", subject.id)
  bumpAccessRevision(ctx)
}

const openAskCounters = new Map<string, (ctx: VaultContext, device: string, now: number) => number>()
export function registerOpenAskCounter(name: string, counter: (ctx: VaultContext, device: string, now: number) => number): void { openAskCounters.set(name, counter) }
export function openAskCount(ctx: VaultContext, device: string, now = ctx.now()): number { return [...openAskCounters.values()].reduce((count, counter) => count + counter(ctx, device, now), 0) }
// The same asks counted for one workload: its approvals and credential requests.
const workloadAskCounters = new Map<string, (ctx: VaultContext, workload: string, now: number) => number>()
export function registerWorkloadAskCounter(name: string, counter: (ctx: VaultContext, workload: string, now: number) => number): void { workloadAskCounters.set(name, counter) }
export function openWorkloadAskCount(ctx: VaultContext, workload: string, now = ctx.now()): number { return [...workloadAskCounters.values()].reduce((count, counter) => count + counter(ctx, workload, now), 0) }
export const SecurityRestrictionInput = SecurityCommitInput.extend({ restriction: AccountRestrictionSchema.nullable() })
export function updateRestriction(ctx: VaultContext, account: string, committedEpoch: number, restriction: AccountSecurityState["restriction"]): AccountSecurityState {
  const state = security(ctx, account)
  if (!state || state.pending || committedEpoch < state.installedEpoch) throw new VaultError("conflict", "The account security change is not committed here.")
  const next = { ...state, installedEpoch: Math.max(state.installedEpoch, committedEpoch), restriction }
  saveSecurity(ctx, next)
  if (canonicalJson(state) !== canonicalJson(next)) {
    ctx.audit({ actor: "system", action: "account.security.restriction", target: account, detail: { installedEpoch: next.installedEpoch, restrictedUntil: restriction?.until ?? null } })
    for (const hook of securityChangeHooks.values()) hook(ctx, account)
  }
  return next
}

const offboardingHooks = new Map<string, import("../services.ts").OffboardingHook>()
// role: the member's new role, for a role change that takes effect at once;
// narrowing: for a rescope, whether the new scope only narrows the old.
export type AccessChangeTarget = { team?: string; device?: string; role?: import("@mehen/protocol").WorkspaceRole; narrowing?: boolean }
export type AccessChangeHook = (ctx: VaultContext, member: string | null, reason: string, target: AccessChangeTarget) => void
const accessChangeHooks = new Map<string, AccessChangeHook>()
let exposureProvider: ((ctx: VaultContext) => { item: string; version: number; ceiling: import("@mehen/protocol").Mode }[]) | null = null
export function registerOffboardingHook(name: string, hook: import("../services.ts").OffboardingHook): void { offboardingHooks.set(name, hook) }
export function registerAccessChangeHook(name: string, hook: AccessChangeHook): void { accessChangeHooks.set(name, hook) }
// Test support only; no operation exposes registry isolation.
export function isolateAccessLifecycleForTests(): () => void {
  const offboarding = new Map(offboardingHooks)
  const changes = new Map(accessChangeHooks)
  const restoreGuards = isolateManagementGuardsForTests()
  const exposures = exposureProvider
  offboardingHooks.clear(); accessChangeHooks.clear(); exposureProvider = null
  return () => {
    offboardingHooks.clear(); accessChangeHooks.clear(); restoreGuards()
    for (const [name, hook] of offboarding) offboardingHooks.set(name, hook)
    for (const [name, hook] of changes) accessChangeHooks.set(name, hook)
    exposureProvider = exposures
  }
}
export function registerExposureProvider(provider: NonNullable<typeof exposureProvider>): void { exposureProvider = provider }
function requireHooks(names: string[], registered: Map<string, unknown>): void { if (names.some((name) => !registered.has(name))) throw new VaultError("internal", "Workspace lifecycle services are not registered.") }
export function accessChanged(ctx: VaultContext, member: string | null, reason: string, target: AccessChangeTarget = {}): void {
  requireHooks(["consent", "projects", "overrides"], accessChangeHooks)
  beforeManagementChange(ctx)
  for (const hook of accessChangeHooks.values()) hook(ctx, member, reason, target)
  const state = accessState(ctx)
  const subject = state.members.find((m) => m.id === member)
  const devices = state.devices.filter((d) => target.device ? d.id === target.device : target.team ? d.owner.kind === "team" && d.owner.id === target.team : d.owner.kind === "member" && d.owner.id === member).map((d) => d.id)
  for (const row of ctx.sql.exec<{ id: string; value: string }>("SELECT id,value FROM device_rescope_proposals").toArray()) {
    const value = JSON.parse(row.value) as import("@mehen/protocol").DeviceRescopeProposal
    if (value.state === "open" && (devices.includes(value.device) || !target.device && value.requiredSigners.some((s) => s.account === subject?.account))) ctx.sql.exec("UPDATE device_rescope_proposals SET value=? WHERE id=?", canonicalJson({ ...value, state: "void" }), row.id)
  }
  bumpAccessRevision(ctx)
}
export function beforeOffboarding(ctx: VaultContext, member: string): import("../services.ts").OffboardingSnapshot {
  requireHooks(["credentials", "projects", "consent", "overrides"], offboardingHooks)
  if (!exposureProvider) throw new VaultError("internal", "Workspace exposure service is not registered.")
  const state = accessState(ctx)
  const devices = state.devices.filter((d) => d.owner.kind === "member" && d.owner.id === member && d.status === "active")
  const current = exposureProvider(ctx)
  const versions = new Map(current.map((item) => [item.item, item.version]))
  const exposures = ctx.sql.exec<{ item: string; version: number; member: string | null; device: string | null; event: string; source: ExposureFact["source"]; at: number }>("SELECT * FROM exposures WHERE member=?", member).toArray().filter((e) => versions.get(e.item) === e.version)
  for (const item of current.filter((item) => item.ceiling === "lease")) {
    for (const device of devices) {
      const contexts = [null, ...state.projects.flatMap((project) => project.environments.map((env) => ({ project: project.id, environment: env.name })))]
      if (contexts.some((context) => can(state, { kind: "device", deviceId: device.id }, { type: "item.use", context }, { credential: item.item, mode: "lease" }, ctx.now()).allowed)) exposures.push({ item: item.item, version: item.version, member, device: device.id, event: `reachable:${device.id}:${item.item}:${item.version}`, source: "reachable_lease", at: ctx.now() })
    }
  }
  return { removal: randomId("rem"), by: member, member, devices: devices.map((d) => d.id), privateItems: state.credentials.filter((c) => c.home.kind === "member" && c.home.member === member).map((c) => c.id), exposures, accessRevision: state.accessRev }
}
export function runOffboardingHooks(ctx: VaultContext, snapshot: import("../services.ts").OffboardingSnapshot): void {
  requireHooks(["credentials", "projects", "consent", "overrides"], offboardingHooks)
  for (const hook of offboardingHooks.values()) hook(ctx, snapshot)
}
export const workspaceAccessService: import("../services.ts").WorkspaceAccessService = {
  member: (ctx, account) => accessState(ctx).members.find((m) => m.account === account && m.status !== "removed") ?? null,
  security, installSecurity: (ctx, account, committedEpoch, pending) => { installSecurity(ctx, account, committedEpoch, pending) },
  observeCommittedEpoch: (ctx, account, committedEpoch) => { observeCommittedEpoch(ctx, account, committedEpoch) },
  state: accessState, beforeOffboarding,
}

export function revokeSession(ctx: VaultContext, account: string, session: string): void {
  const state = security(ctx, account)
  if (!state || state.revokedSessionIds.includes(session)) return
  saveSecurity(ctx, { ...state, revokedSessionIds: union(state.revokedSessionIds, [session]) })
  ctx.audit({ actor: "system", action: "account.session_revoke", target: account, detail: { session } })
}

export type WorkspaceNotice = z.infer<typeof OutboxEventSchema>
export function noticesFor(ctx: VaultContext, principal: WorkspaceRuntimePrincipal): WorkspaceNotice[] { return noticeScan(ctx, principal, null).notices }
// The caller's notices, oldest first. With a scan limit only the newest
// `scan` stored rows are read before filtering, and `truncated` says older
// rows were left unread.
export function noticeScan(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, scan: number | null): { notices: WorkspaceNotice[]; truncated: boolean } {
  const state = accessState(ctx)
  const device = principal.kind === "device" ? state.devices.find((d) => d.id === principal.deviceId && d.status === "active") : null
  const member = principal.kind === "member" ? state.members.find((m) => m.id === principal.memberId) : device?.owner.kind === "member" ? state.members.find((m) => m.id === device.owner.id) : null
  if (!member || member.status !== "active") return { notices: [], truncated: false }
  const account = member.account
  type NoticeRow = { id: string; account: string; payload: string; created_at: number }
  let stored = scan === null ? ctx.sql.exec<NoticeRow>("SELECT id,account,payload,created_at FROM notice_outbox WHERE account=? ORDER BY created_at,id", account).toArray() : ctx.sql.exec<NoticeRow>("SELECT id,account,payload,created_at FROM notice_outbox WHERE account=? ORDER BY created_at DESC,id DESC LIMIT ?", account, scan + 1).toArray().reverse()
  const truncated = scan !== null && stored.length > scan
  if (truncated) stored = stored.slice(1)
  const notices = stored.flatMap((row) => {
    const payload = WorkspaceNoticePayloadSchema.parse(JSON.parse(row.payload))
    if (principal.kind === "device" && !(payload.kind === "machine_added" && payload.device === principal.deviceId)) return []
    if (member.standing.effectiveRole === "guest" && !(payload.kind === "machine_added" && payload.owner.kind === "member" && payload.owner.member === member.id || payload.kind === "owner_changed" && payload.member === member.id)) return []
    return [OutboxEventSchema.parse({ id: row.id, account: row.account, payload, at: row.created_at, url: `${ctx.env.VAULT_ORIGIN}/w/${payload.workspace.slug}${payload.kind === "machine_added" ? `/devices/${payload.device}` : payload.kind === "backup_recipient" ? "/settings" : payload.kind === "member_joined" ? "/people" : "/"}` })]
  })
  return { notices, truncated }
}

export const WorkspaceInviteViewSchema = z.strictObject({ id: z.string(), terms: InviteTermsSchema, digest: z.string(), status: z.enum(["open", "pending_confirmation", "active", "revoked", "expired"]), inviter: z.strictObject({ member: z.string(), name: z.string() }), boundEmail: z.string().nullable(), createdAt: z.iso.datetime(), expiresAt: z.iso.datetime() })
export type WorkspaceInviteView = z.infer<typeof WorkspaceInviteViewSchema>

const enrolDetailFields = { name: z.string().min(1).max(64), backend: z.enum(["software", "secure-enclave"]), host: z.string().max(253).nullable(), jwk: z.custom<import("@mehen/protocol").DeviceJwk>(isDeviceJwk), codeHash: z.string() }
const enrolTermsFields = { enrolment: z.string(), start: EnrolStartContextSchema, thumbprint: z.string(), requestedOwner: EnrolOwnerIntentSchema, scope: WorkspaceDeviceScopeSchema.omit({ privateCredentials: true }) }
const pendingEnrolFields = { scope: WorkspaceDeviceScopeSchema, workspace: WorkspaceRefSchema, state: z.enum(["pending_owner_acceptance", "pending_admission", "active", "rejected", "expired"]), digest: z.string(), owner: OwnerRefSchema.nullable().default(null), acceptance: EnrolEvidenceSchema.nullable().default(null), admission: EnrolEvidenceSchema.nullable().default(null), device: z.string().nullable().default(null), admissionProject: z.string().nullable().default(null) }
// New registrations: the attempt's hard cap (fixed at start, never the
// renewable lease) and the claim are inside the signed terms.
// requested: what the machine asked for at enrolment, when it asked for less
// than usual (directory/workspace-enrolment.ts requestedEnrolScope); a term
// its digest binds, present only on records that carry it.
export const EnrolRegisterInput = z.strictObject({ ...enrolTermsFields, requested: EnrolRequestedScopeSchema.optional(), claimedAccount: z.string().min(1).max(128).nullable(), detail: z.strictObject({ ...enrolDetailFields, hardExpiresAt: z.iso.datetime() }).optional() })
export const PendingEnrolSchema = EnrolRegisterInput.extend(pendingEnrolFields)
// The shape every record stored before the lease carries: detail.expiresAt,
// no claimedAccount. Frozen: stored acceptance and admission evidence binds
// the digest of exactly these terms, so nothing rewrites them.
const LegacyEnrolRegisterInput = z.strictObject({ ...enrolTermsFields, detail: z.strictObject({ ...enrolDetailFields, expiresAt: z.iso.datetime() }).optional() })
export const LegacyPendingEnrolSchema = LegacyEnrolRegisterInput.extend(pendingEnrolFields)
export type PendingEnrolRecord = z.infer<typeof PendingEnrolSchema>
export type PendingEnrol = PendingEnrolRecord & { legacy: boolean }
// Every reader of workspace_enrolments.value goes through here. A legacy
// record is mapped in memory (its expiry is its hard cap, it has no claim)
// and keeps its stored digest verbatim.
export function readStoredEnrol(value: string): PendingEnrol {
  const raw: unknown = JSON.parse(value)
  const current = PendingEnrolSchema.safeParse(raw)
  if (current.success) return { ...current.data, legacy: false }
  const { detail, ...legacy } = LegacyPendingEnrolSchema.parse(raw)
  return { ...legacy, ...(detail ? { detail: { name: detail.name, backend: detail.backend, host: detail.host, jwk: detail.jwk, codeHash: detail.codeHash, hardExpiresAt: detail.expiresAt } } : {}), claimedAccount: null, legacy: true }
}
// The record without the in-memory legacy mark: what leaves the DO.
export function enrolRecord(value: PendingEnrol): PendingEnrolRecord {
  const { legacy: _legacy, ...record } = value
  return PendingEnrolSchema.parse(record)
}
// The terms as stored, in the record's own field names: what its digest and
// any stored evidence bind.
export function storedEnrolTerms(value: PendingEnrol): Record<string, unknown> {
  const { enrolment, start, thumbprint, requestedOwner, scope, detail } = value
  if (!value.legacy) return { enrolment, start, thumbprint, requestedOwner, scope, ...(value.requested ? { requested: value.requested } : {}), claimedAccount: value.claimedAccount, ...(detail ? { detail } : {}) }
  return { enrolment, start, thumbprint, requestedOwner, scope, ...(detail ? { detail: { name: detail.name, backend: detail.backend, host: detail.host, jwk: detail.jwk, codeHash: detail.codeHash, expiresAt: detail.hardExpiresAt } } : {}) }
}
// A legacy record is written back in its legacy field names, so the digest
// its evidence binds stays what the stored terms hash to.
export function saveEnrol(ctx: VaultContext, value: PendingEnrol): void {
  const record = enrolRecord(value)
  const stored = value.legacy ? LegacyPendingEnrolSchema.parse({ ...(({ claimedAccount: _claimed, detail: _detail, ...rest }) => rest)(record), ...storedEnrolTerms(value) }) : record
  ctx.sql.exec("UPDATE workspace_enrolments SET value=? WHERE id=?", canonicalJson(stored), value.enrolment)
}
export const PendingEnrolViewSchema = PendingEnrolSchema.omit({ detail: true }).extend({ detail: EnrolRegisterInput.shape.detail.unwrap().omit({ codeHash: true }).optional(), acceptance: WorkspaceEnrolEvidenceViewSchema.nullable(), admission: WorkspaceEnrolEvidenceViewSchema.nullable(), actions: z.array(z.enum(["accept", "admit", "reject"])), defaultPrivateCredentials: z.boolean(), planning: z.strictObject({ scope: WorkspaceDeviceScopeSchema, digest: z.string() }).nullable() })
export type PendingEnrolView = z.infer<typeof PendingEnrolViewSchema>
// An enrolment as the Worker read it from D1, handed to the workspace so its
// own evaluator decides, from live standing, who may see it and act on it.
export const InboxEnrolCandidateSchema = z.strictObject({ enrolment: z.string(), thumbprint: z.string(), name: z.string(), host: z.string().nullable(), backend: z.enum(["software", "secure-enclave"]), start: EnrolStartContextSchema, session: z.string().max(120).nullable(), requestedOwner: EnrolOwnerIntentSchema, claimedAccount: z.string().nullable(), claimedName: z.string().nullable(), status: z.enum(["pending", "expired", "rejected", "active"]), pendingState: z.enum(["pending_owner_acceptance", "pending_admission"]).nullable(), lease: z.enum(["live", "lapsed", "terminal"]), acceptedByAccount: z.string().nullable(), expiresAt: z.iso.datetime(), hardExpiresAt: z.iso.datetime(), hiddenGroup: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]).nullable() })
export type InboxEnrolCandidate = z.infer<typeof InboxEnrolCandidateSchema>
export const EnrolVisibilitySchema = z.strictObject({ visible: z.boolean(), actions: z.array(z.enum(["accept", "admit", "reject"])) })
export type EnrolVisibility = z.infer<typeof EnrolVisibilitySchema>
export const EnrolReconcileOutputSchema = z.strictObject({ device: z.string().nullable(), mirrored: z.boolean(), state: PendingEnrolSchema.shape.state, active: z.strictObject({ scope: WorkspaceDeviceScopeSchema, owner: OwnerRefSchema, acceptance: EnrolEvidenceSchema.nullable(), admission: EnrolEvidenceSchema.nullable() }).nullable() })

export function eligibilityState(ctx: VaultContext, invocation: WorkspaceInvocationContext): AccessState {
  const state = accessState(ctx)
  if (invocation.auth.kind !== "account") return state
  const auth = invocation.auth
  const caller = state.members.find((m) => m.account === auth.account && m.status !== "removed")
  if (caller) {
    const check = auth.sessionCheck
    const valid = installedSessionCheck(ctx, caller.id, auth.session, auth.securityEpoch, check) && !!check && check.identityRuleRev === caller.standing.identityRuleRev && check.gateGeneration === caller.standing.gateGeneration && Number.isFinite(Date.parse(check.expiresAt)) && Date.parse(check.expiresAt) > ctx.now() && Number.isFinite(Date.parse(check.succeededAt)) && Date.parse(check.succeededAt) <= ctx.now()
    const identityGate = { ...caller.standing.identityGate, admitted: valid, checkedAt: valid && check ? Date.parse(check.succeededAt) : null }
    return { ...state, members: state.members.map((m) => m === caller ? { ...m, standing: { ...m.standing, identityGate } } : m) }
  }
  return state
}
export function retainedGateValid(ctx: VaultContext, basis: { sessionCheck: import("@mehen/protocol").SessionIdentityCheck | null; session: string; account: string; securityEpoch: number }, now = ctx.now()): boolean {
  const state = accessState(ctx)
  const member = state.members.find((m) => m.account === basis.account && m.status === "active")
  const sec = security(ctx, basis.account)
  if (!member || !sec || sec.installedEpoch !== basis.securityEpoch || sec.revokedSessionIds.includes(basis.session) || sec.deleting || sec.pending) return false
  if (!member.standing.identityGate.covered) return true
  const check = basis.sessionCheck
  return installedSessionCheck(ctx, member.id, basis.session, basis.securityEpoch, check) && !!check && check.identityRuleRev === member.standing.identityRuleRev && check.gateGeneration === member.standing.gateGeneration && Number.isFinite(Date.parse(check.expiresAt)) && Date.parse(check.expiresAt) > now && Number.isFinite(Date.parse(check.succeededAt)) && Date.parse(check.succeededAt) <= now && now - Date.parse(check.succeededAt) < 43_200_000
}
// A standing rule's consent in an identity-gated workspace: the approver's
// live standing (still admitted under the identity rule revision and gate
// generation their check was made under, the same security epoch, the
// session not revoked) in place of retainedGateValid's 12-hour session
// check, which would end every rule within 12 hours.
export function standingGateValid(ctx: VaultContext, basis: { sessionCheck: import("@mehen/protocol").SessionIdentityCheck | null; session: string; account: string; securityEpoch: number }): boolean {
  const member = accessState(ctx).members.find((m) => m.account === basis.account && m.status === "active")
  const sec = security(ctx, basis.account)
  if (!member || !sec || sec.installedEpoch !== basis.securityEpoch || sec.revokedSessionIds.includes(basis.session) || sec.deleting || sec.pending) return false
  if (!member.standing.identityGate.covered) return true
  const check = basis.sessionCheck
  return !!check && check.identityRuleRev === member.standing.identityRuleRev && check.gateGeneration === member.standing.gateGeneration
}

export type OutboxEvent = z.infer<typeof OutboxEventSchema>
type NoticeDelivery = (env: import("../../env.ts").Env, events: OutboxEvent[]) => Promise<string[]>
let noticeDelivery: NoticeDelivery | null = null
// About three days of backoff (one minute doubling to the six-hour cap).
export const NOTICE_MAX_ATTEMPTS = 20
export function registerNoticeDelivery(delivery: NoticeDelivery): () => void { const previous = noticeDelivery; noticeDelivery = delivery; return () => { noticeDelivery = previous } }
export async function deliverNoticeOutbox(ctx: VaultContext): Promise<void> {
  const events = drainOutbox(ctx, 50).events
  let acknowledged: string[] = []
  if (noticeDelivery && events.length) {
    try { acknowledged = await noticeDelivery(ctx.env, events) } catch { /* Source durability is the retry boundary. */ }
  }
  ctx.storage.transactionSync(() => {
    ctx.sql.exec("DELETE FROM notice_outbox WHERE acknowledged_at IS NOT NULL AND acknowledged_at<?", ctx.now() - 30 * 86_400_000)
    const sent = new Set(events.map((event) => event.id))
    for (const id of new Set(acknowledged)) if (sent.has(id)) ctx.sql.exec("UPDATE notice_outbox SET acknowledged_at=? WHERE id=? AND acknowledged_at IS NULL", ctx.now(), id)
    for (const event of events) {
      const row = one(ctx.sql.exec<{ attempts: number }>("SELECT attempts FROM notice_outbox WHERE id=? AND acknowledged_at IS NULL", event.id))
      if (!row) continue
      ctx.sql.exec("UPDATE notice_outbox SET attempts=attempts+1,next_retry_at=? WHERE id=?", ctx.now() + Math.min(60_000 * 2 ** Math.min(row.attempts, 8), 21_600_000), event.id)
      // The last attempt ends delivery: acknowledged, so it is neither retried nor kept past the prune.
      if (row.attempts + 1 >= NOTICE_MAX_ATTEMPTS) {
        ctx.sql.exec("UPDATE notice_outbox SET acknowledged_at=? WHERE id=?", ctx.now(), event.id)
        console.warn(JSON.stringify({ at: "workspace.notice.given_up", notice: event.id, attempts: row.attempts + 1 }))
      }
    }
    const due = one(ctx.sql.exec<{ due: number | null }>("SELECT MIN(next_retry_at) AS due FROM notice_outbox WHERE acknowledged_at IS NULL"))?.due
    if (due !== null && due !== undefined) ctx.schedule("access", "notice-outbox", Math.max(ctx.now() + 1000, due))
    else ctx.unschedule("access", "notice-outbox")
  })
}


export const OperationCheckSchema = z.strictObject({ id: z.string().min(1), subjectDigest: z.string(), identityRuleRev: z.number().int().nonnegative(), gateGeneration: z.number().int().nonnegative(), succeededAt: z.iso.datetime(), expiresAt: z.iso.datetime() })
export const IdentityInstallInput = z.strictObject({ purpose: z.enum(["session", "invite"]).optional(), account: z.string().min(1), member: z.string().min(1), session: z.string().min(1), securityEpoch: z.number().int().nonnegative(), sessionCheck: SessionIdentityCheckSchema.nullable(), invalidation: z.string().min(1).max(128).optional(), operationCheck: OperationCheckSchema.optional(), pendingRole: WorkspaceRoleSchema.nullable().optional() }).refine(input => input.sessionCheck !== null || input.invalidation !== undefined,"An invalidation needs its event id")
export type IdentityInstall = z.infer<typeof IdentityInstallInput>
export function requireOperationIdentity(ctx: VaultContext, memberId: string, expected: WorkspaceStepUpAction, evidence: import("../core.ts").OperationCheck | undefined): void {
  const member = memberRows(ctx).find((m) => m.id === memberId && m.status !== "removed")
  if (!member || !evidence || evidence.subjectDigest !== digest(expected) || evidence.identityRuleRev !== setting(ctx, "identity_rule_rev", 0) || evidence.gateGeneration !== member.gate_generation || !Number.isFinite(Date.parse(evidence.expiresAt)) || Date.parse(evidence.expiresAt) <= ctx.now() || !Number.isFinite(Date.parse(evidence.succeededAt)) || Date.parse(evidence.succeededAt) > ctx.now() || ctx.now() - Date.parse(evidence.succeededAt) >= 43_200_000) throw new VaultError("identity_required", "Check your workspace identity for this exact operation.")
}
export function sessionIdentityCheckMatches(a: import("@mehen/protocol").SessionIdentityCheck, b: import("@mehen/protocol").SessionIdentityCheck): boolean {
  return a.id === b.id && a.checkSequence === b.checkSequence && a.identityRuleRev === b.identityRuleRev && a.gateGeneration === b.gateGeneration && Number.isFinite(Date.parse(a.succeededAt)) && Date.parse(a.succeededAt) === Date.parse(b.succeededAt) && Number.isFinite(Date.parse(a.expiresAt)) && Date.parse(a.expiresAt) === Date.parse(b.expiresAt)
}
export function installedSessionCheck(ctx: VaultContext, member: string, session: string, epoch: number, check: import("@mehen/protocol").SessionIdentityCheck | null): boolean {
  const row = one(ctx.sql.exec<{ value: string; security_epoch: number }>("SELECT value,security_epoch FROM workspace_identity_checks WHERE member=? AND session=?", member, session))
  const installed = row ? SessionIdentityCheckSchema.safeParse(JSON.parse(row.value)) : null
  return !!check && !!row && row.security_epoch === epoch && !!installed?.success && sessionIdentityCheckMatches(installed.data, check)
}
// Called only by the system operation inside its synchronous transaction.
export function installIdentity(ctx: VaultContext, input: IdentityInstall): { member: string; identityRuleRev: number; gateGeneration: number; checkSequence: number; role: import("@mehen/protocol").WorkspaceRole } | { promotionRefused: true } {
  const member = memberRows(ctx).find((m) => m.id === input.member && m.account === input.account && (m.status === "active" || m.status === "unconfirmed"))
  const sec = security(ctx, input.account)
  if (!member) throw new VaultError("not_found", "No such membership.")
  const check = input.sessionCheck
  // Invalidation only removes authority and must survive its initiating session.
  if (!sec || check !== null && (sec.installedEpoch !== input.securityEpoch || sec.deleting || sec.revokedSessionIds.includes(input.session))) throw new VaultError("unauthenticated", "This session is no longer authorised.")
  const revision = setting(ctx, "identity_rule_rev", 0)
  const key = check ? `identity_install:${member.id}:${input.session}` : `identity_install:${member.id}:invalidation:${input.invalidation}`
  const previous = setting<{ digest: string; revision: number; generation: number } | null>(ctx, key, null)
  const result = () => ({ member: member.id, identityRuleRev: revision, gateGeneration: member.gate_generation, checkSequence: member.check_sequence, role: member.role })
  if (!check && previous) {
    if (previous.digest !== digest(input)) throw new VaultError("conflict","This identity invalidation event changed.")
    return result()
  }
  if (check && previous?.digest === digest(input) && previous.revision === revision && previous.generation === member.gate_generation && installedSessionCheck(ctx, member.id, input.session, input.securityEpoch, check)) return result()
  if (!check) {
    if (input.pendingRole !== undefined || input.operationCheck) throw new VaultError("bad_request", "An invalidation cannot activate a role.")
    ctx.sql.exec("UPDATE members SET gate_generation=gate_generation+1,revision=revision+1 WHERE id=?", member.id)
    ctx.sql.exec("DELETE FROM workspace_identity_checks WHERE member=?", member.id)
    member.gate_generation++
    // Their mandates stop covering with the generation; the lapse and its
    // notice say so.
    lapseMandates(ctx, { member: member.id }, "identity_invalidated")
  } else {
    if (sec.pending || check.identityRuleRev !== revision || check.gateGeneration !== member.gate_generation || check.checkSequence <= member.check_sequence || Date.parse(check.succeededAt) > ctx.now() || Date.parse(check.expiresAt) <= ctx.now() || Date.parse(check.expiresAt) <= Date.parse(check.succeededAt)) throw new VaultError("identity_required", "This identity check is no longer current.")
    if (member.status === "unconfirmed") {
      if (input.purpose !== "invite" || input.pendingRole !== undefined) throw new VaultError("identity_required", "Check the exact invitation before confirmation.")
      const invite = one(ctx.sql.exec<{ digest: string; terms: string; status: string }>("SELECT digest,terms,status FROM invites WHERE member=?", member.id))
      if (!invite || invite.status !== "pending_confirmation" || Date.parse(InviteTermsSchema.parse(JSON.parse(invite.terms)).expiresAt) <= ctx.now()) throw new VaultError("conflict", "The invitation terms changed.")
      requireOperationIdentity(ctx, member.id, { type: "member.confirm", member: member.id, termsDigest: invite.digest, identityRuleRevision: revision }, input.operationCheck)
    } else if (input.purpose === "invite") throw new VaultError("conflict", "This membership is no longer pending confirmation.")
    if (input.pendingRole !== undefined && input.pendingRole !== null) {
      if (input.pendingRole !== member.pending_role || !member.pending_action) throw new VaultError("conflict", "This pending role changed.")
      requireOperationIdentity(ctx, member.id, JSON.parse(member.pending_action) as WorkspaceStepUpAction, input.operationCheck)
      const state = accessState(ctx), promoter = state.members.find(m => m.id === member.pending_by)
      const expired = member.pending_since === null || member.pending_since + INVITE_TTL_MS <= ctx.now()
      const principal: AccessPrincipal | null = promoter ? { kind: "member", account: promoter.account, memberId: promoter.id, session: "pending-promotion", securityEpoch: security(ctx, promoter.account)?.installedEpoch ?? 0, sessionCheck: null } : null
      if (expired || !promoter || promoter.status !== "active" || !principal || !can(capabilityState(state, promoter.id), principal, { type: "member.role" }, { member: member.id, role: input.pendingRole }, ctx.now()).allowed) {
        ctx.sql.exec("UPDATE members SET pending_role=NULL,pending_since=NULL,pending_action=NULL,pending_by=NULL,revision=revision+1 WHERE id=?", member.id)
        bumpAccessRevision(ctx)
        ctx.audit({ actor: "system", action: "member.promotion_cancelled", target: member.id, detail: { role: member.pending_role, reason: expired ? "expired" : "promoter_ineligible" } })
        return { promotionRefused: true }
      }
      beforeManagementChange(ctx)
      ctx.sql.exec("UPDATE members SET role=pending_role,pending_role=NULL,pending_since=NULL,pending_action=NULL,pending_by=NULL,revision=revision+1 WHERE id=?", member.id)
      member.role = input.pendingRole
    }
    ctx.sql.exec("UPDATE members SET check_sequence=? WHERE id=?", check.checkSequence, member.id)
    member.check_sequence = check.checkSequence
    ctx.sql.exec("INSERT INTO workspace_identity_checks(member,session,security_epoch,value,operation_check,purpose) VALUES (?,?,?,?,?,?) ON CONFLICT(member,session) DO UPDATE SET security_epoch=excluded.security_epoch,value=excluded.value,operation_check=excluded.operation_check,purpose=excluded.purpose", member.id, input.session, input.securityEpoch, canonicalJson(check), input.operationCheck ? canonicalJson(input.operationCheck) : null, input.purpose ?? "session")
  }
  setSetting(ctx, key, { digest: digest(input), revision, generation: member.gate_generation })
  bumpAccessRevision(ctx)
  ctx.audit({ actor: `member:${member.id}`, action: "member.gate", target: member.id, detail: { admitted: check !== null, session: input.session, identityRuleRev: revision, gateGeneration: member.gate_generation, checkSequence: member.check_sequence, role: member.role } })
  return result()
}


export function inviteCreatorEligible(ctx: VaultContext, creator: string, _rawBasis: string | null, invitedRole: import("@mehen/protocol").WorkspaceRole): boolean {
  const member = accessState(ctx).members.find(m => m.id === creator)
  if (!member || member.status !== "active" || !["owner", "admin"].includes(member.standing.effectiveRole) || invitedRole === "owner" && member.standing.effectiveRole !== "owner" || member.standing.transitionPending || member.standing.restriction && member.standing.restriction.until > ctx.now()) return false
  if (!member.standing.identityGate.covered) return true
  const sec = security(ctx,member.account)
  if (!sec || sec.deleting || sec.pending) return false
  return ctx.sql.exec<{ session: string; security_epoch: number; value: string }>("SELECT session,security_epoch,value FROM workspace_identity_checks WHERE member=?",member.id).toArray().some(row => {
    const check = SessionIdentityCheckSchema.parse(JSON.parse(row.value))
    return row.security_epoch === sec.installedEpoch && !sec.revokedSessionIds.includes(row.session) && check.identityRuleRev === member.standing.identityRuleRev && check.gateGeneration === member.standing.gateGeneration && Date.parse(check.expiresAt)>ctx.now() && Date.parse(check.succeededAt)<=ctx.now()
  })
}

export function requireInviteIdentity(ctx: VaultContext, member: MemberRow, termsDigest: string): void {
  const sec = security(ctx, member.account), revision = setting(ctx, "identity_rule_rev", 0)
  const evidence = ctx.sql.exec<{ session: string; security_epoch: number; value: string; operation_check: string | null }>("SELECT session,security_epoch,value,operation_check FROM workspace_identity_checks WHERE member=? AND purpose='invite'", member.id).toArray().some(row => {
    const check = SessionIdentityCheckSchema.parse(JSON.parse(row.value))
    if (!sec || sec.pending || sec.deleting || sec.installedEpoch !== row.security_epoch || sec.revokedSessionIds.includes(row.session) || check.identityRuleRev !== revision || check.gateGeneration !== member.gate_generation || Date.parse(check.expiresAt) <= ctx.now()) return false
    try { requireOperationIdentity(ctx, member.id, { type: "member.confirm", member: member.id, termsDigest, identityRuleRevision: revision }, row.operation_check ? OperationCheckSchema.parse(JSON.parse(row.operation_check)) : undefined); return true } catch { return false }
  })
  if (!evidence) throw new VaultError("identity_required", "Check the invited identity before confirmation.")
}
