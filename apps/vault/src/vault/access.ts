// One pure evaluator for human matrix rows and live machine ceilings. The caller
// passes current state and time; invocation caches are never final authority.
import { PENDING_RESTRICTION_UNTIL, canonicalJson, scopeChangeIsNarrowing } from "@mehen/protocol"
import type { AccountRestriction, CredentialHome, EffectiveAccess, Eligibility, EnvironmentState, ErrorCode, InviteTerms, ItemUseContext, NextStep, OwnerRef, SessionIdentityCheck, IdentityRule, PostureLevel, Share, WorkloadScope, WorkspaceDeviceScope, WorkspaceRole, WorkspaceStepUpAction } from "@mehen/protocol"

export type AccountStanding = { identityRule: IdentityRule; checkSequence: number; effectiveRole: WorkspaceRole; pendingRole: WorkspaceRole | null; restriction: AccountRestriction | null; identityGate: { covered: boolean; admitted: boolean; checkedAt: number | null }; transitionPending: boolean; identityRuleRev: number; gateGeneration: number }
export type AccessMember = { id: string; account: string; name: string; status: "unconfirmed" | "active" | "suspended" | "removed"; standing: AccountStanding; canCreateWorkspaces: boolean }
// workload: set only on the device a workload acts as (principalDevice), never
// on a stored device; its items and tags narrow deviceCredential.
export type AccessDevice = { id: string; status: "active" | "revoked"; owner: { kind: "member" | "team"; id: string }; scope: WorkspaceDeviceScope; workload?: WorkloadScope }
export type AccessWorkload = { id: string; device: string; scope: WorkloadScope; expiresAt: number; revokedAt: number | null }
export type CredentialReference = { variable: string; field: string; item: string; home: CredentialHome; revision: number }
export type AccessEnvironment = { name: string; protected: boolean; fourEyes: boolean; revision: number; protectionRevision: number; fences: string[]; references: CredentialReference[]; plainVariables?: Record<string, string> }
export type AccessProject = { id: string; slug: string; environments: AccessEnvironment[] }
export type AccessCredential = { id: string; slug?: string; home: CredentialHome; tags: string[] }
// endedShares: the shares whose end was settled with their terms as they
// are (share_ends_settled), which count as ended whatever the clock says.
export type AccessState = { accessRev: number; members: AccessMember[]; teams: { id: string; name: string; members: string[] }[]; shares: Share[]; projects: AccessProject[]; credentials: AccessCredential[]; devices: AccessDevice[]; workloads?: AccessWorkload[]; endedShares?: readonly string[] }
export type AccessPrincipal = { kind: "member"; account: string; memberId: string; session: string; securityEpoch: number; sessionCheck: SessionIdentityCheck | null } | { kind: "device"; deviceId: string; workload?: string }
// workload: the workload that asked, when one did; its scope narrows who may approve.
// mode: "placeholder" when a run's placeholder asked to use the credential,
// "fill" when a machine asked to type it into a web page; absent for a relay
// by item, so asks stored before it read as they did.
// via: a push's destination credential (areas/pushes.ts), credentials[1]:
// the machine must use it at relay and the decider must see it.
export type AccessAsk = { device: string; workload?: string; credential: string | null; credentials: string[]; context: ItemUseContext | null; mode?: "placeholder" | "fill"; via?: string }
// prospectiveSlug and prospectiveTags: the credential a request would create,
// so a workload scoped by items or tags can follow its own ask.
// push: the use puts the value into another service (areas/pushes.ts), so
// it is classified as a reveal, which a cooling-off owner's machine may not.
export type AccessTarget = { push?: true; prospectiveSlug?: string; prospectiveTags?: string[]; client?: string; member?: string; role?: WorkspaceRole; team?: string; project?: string; environment?: string; variable?: string; credential?: string; device?: string; creator?: string; run?: string; proposal?: string; before?: WorkspaceDeviceScope; after?: WorkspaceDeviceScope; inviteTerms?: InviteTerms; destinationHome?: CredentialHome; context?: ItemUseContext; mode?: WorkspaceDeviceScope["modes"][number]; ask?: AccessAsk; acceptingAccount?: string; owningAccount?: string; rescopeAs?: "owner_acceptance" | "admission" }
const ACCESS_ACTION_KINDS = [
  "passkey.add", "passkey.rename", "passkey.remove", "session.end", "recovery.generate", "identity.link", "identity.unlink", "workspace.create", "account.delete",
  "workspace.update", "workspace.identity_rule", "workspace.delete", "workspace.delete_cancel", "workspace.freeze", "workspace.unfreeze", "workspace.export",
  "member.invite", "invite.revoke", "member.confirm", "member.role", "member.suspend", "member.reinstate", "member.remove", "member.leave", "account.reset", "members.read", "member.machines",
  "team.update", "team.members", "project.create", "project.init", "project.read", "project.share", "environment.tighten", "environment.loosen", "remote.update", "variable.set", "override.set", "run.unprotected", "run.protected", "run.end", "project.delete",
  "credential.create", "credential.metadata", "credential.use", "credential.rotate", "credential.restore", "credential.update", "credential.rehome", "credential.delete", "credential.reveal", "credential.push", "intake.cancel", "connect.cancel", "credential.connect", "credential.reconnect", "credential.adopt",
  // How careful a credential is: credential.posture_ask, back to ask, narrows.
  "credential.posture", "credential.posture_ask",
  "enrol.accept", "enrol.approve", "enrol.reject", "device.rescope", "device.rescope_propose", "device.rescope_admit", "device.rescope_accept", "device.rescope_reject", "device.revoke", "device.self_revoke", "device.read_self", "devices.read", "device.transfer", "workload.revoke",
  "approval.approve", "approval.deny", "policy.approve", "policy.rule.approve", "policy.cosign", "policy.cosigner_revoke", "policy.deny", "policy.stop", "policy.acknowledge", "audit.read", "asks.read", "ask.detail",
  "backup.recipient_add", "backup.recipient_remove", "backup.export", "backup.read",
  // A mandate (areas/mandates-workspace.ts): signing and resuming one widen;
  // pausing and stopping narrow.
  "mandate.sign", "mandate.resume", "mandate.pause", "mandate.stop",
  // The approval dial (areas/approval-dial-workspace.ts): asking less widens
  // and is signed; asking more narrows.
  "workspace.approvals_less", "workspace.approvals_more",
] as const
type ShareTerms = Pick<Share, "level" | "protected" | "expiresAt">
type ScopedAccessTarget = AccessTarget & { before?: WorkspaceDeviceScope; after?: WorkspaceDeviceScope; shareAfter?: ShareTerms | null }
type AccessActionKind = typeof ACCESS_ACTION_KINDS[number]
export type VariableSource = { kind: "item"; item: string; field: string } | { kind: "plain"; value: string } | null
type SimpleAccessAction = Exclude<AccessActionKind, "environment.tighten" | "environment.loosen" | "variable.set" | "device.rescope" | "device.rescope_accept" | "members.read" | "credential.metadata" | "credential.use" | "ask.detail" | "project.share" | "credential.posture" | "credential.posture_ask"> | "people.read" | "item.read" | "approval.read"
export type AccessAction = { [K in SimpleAccessAction]: { type: K } }[SimpleAccessAction]
  // after: the share's new terms, null when it is removed; absent counts as giving.
  | { type: "project.share"; after?: ShareTerms | null }
  | { [K in "device.rescope" | "device.rescope_accept"]: { type: K; before: WorkspaceDeviceScope; after: WorkspaceDeviceScope } }["device.rescope" | "device.rescope_accept"]
  | { type: "environment.update"; before: EnvironmentState; after: EnvironmentState }
  | { type: "var.set"; before: VariableSource; after: VariableSource }
  | { type: "item.use"; context: ItemUseContext | null }
  | { type: "credential.posture"; level: PostureLevel }

export type AccessDecision = { allowed: true; stepUp: WorkspaceStepUpAction["type"] | null } | { allowed: false; error: ErrorCode; message: string; next?: NextStep }
export type AccessClassification = "read" | "narrow" | "widen" | "approve" | "reveal"
const no = (error: ErrorCode = "forbidden"): AccessDecision => ({ allowed: false, error, message: error === "not_found" ? "No such object." : "You are not allowed to do that." })
const yes = (stepUp: WorkspaceStepUpAction["type"] | null = null): AccessDecision => ({ allowed: true, stepUp })
const PRIVATE_CREDENTIALS_OFF: AccessDecision = {
  allowed: false,
  error: "forbidden",
  message: "This machine was accepted without private credentials, so it cannot ask for a credential in its owner's private home.",
  next: { say: "Ask again in a project the person can edit, or in the workspace if they are a workspace owner or admin; otherwise ask the person to tick the private credentials box on this machine's page under Machines, then ask again." },
}
const rank = { use: 1, edit: 2, manage: 3 } as const
const admin = (role: WorkspaceRole) => role === "owner" || role === "admin"
// A share gives access until its end, and never once that end was settled
// (a settled end is final, so a clock set back cannot revive it) until its
// terms change.
const activeShare = (state: AccessState, share: Share, now: number): boolean => !(state.endedShares?.includes(share.id) ?? false) && (share.expiresAt === null || Number.isFinite(Date.parse(share.expiresAt)) && Date.parse(share.expiresAt) > now)
// Whether new terms give no more than a share gives now: no higher level, no
// protected context it does not give, and an end no later than its own.
function shareNarrows(current: ShareTerms, after: ShareTerms): boolean {
  const protectedContext = (terms: ShareTerms) => terms.level === "manage" || terms.protected
  const endsInTime = current.expiresAt === null || after.expiresAt !== null && Date.parse(after.expiresAt) <= Date.parse(current.expiresAt)
  return rank[after.level] <= rank[current.level] && (!protectedContext(after) || protectedContext(current)) && endsInTime
}
const empty = (): EffectiveAccess => ({ level: null, runProtected: false, editProtected: false, sources: [] })
const usable = (member: AccessMember | undefined) => member?.status === "active"
const humanUsable = (member: AccessMember | undefined) => usable(member) && (!member?.standing.identityGate.covered || member.standing.identityGate.admitted)

export function effectiveAccess(state: AccessState, subject: { kind: "member" | "team"; id: string }, project: string, now: number): EffectiveAccess {
  if (!state.projects.some((p) => p.id === project)) return empty()
  const member = subject.kind === "member" ? state.members.find((m) => m.id === subject.id) : undefined
  if (subject.kind === "member" && !usable(member)) return empty()
  if (subject.kind === "team" && !state.teams.some((t) => t.id === subject.id)) return empty()
  const out = empty()
  if (member && admin(member.standing.effectiveRole)) return { level: "manage", runProtected: true, editProtected: true, sources: [{ kind: "role", role: member.standing.effectiveRole }] }
  for (const share of state.shares) {
    if (share.project !== project || !activeShare(state, share, now)) continue
    const direct = share.subject.kind === subject.kind && (share.subject.kind === "member" ? share.subject.member : share.subject.team) === subject.id
    const viaTeam = member && member.standing.effectiveRole !== "guest" && share.subject.kind === "team" && state.teams.some((t) => t.id === (share.subject.kind === "team" ? share.subject.team : "") && t.members.includes(member.id))
    if (!direct && !viaTeam) continue
    const level = member?.standing.effectiveRole === "guest" && share.level === "manage" ? "edit" : share.level
    if (out.level === null || rank[level] > rank[out.level]) out.level = level
    out.runProtected ||= level === "manage" || share.protected
    out.editProtected ||= level === "manage" || (level === "edit" && share.protected)
    out.sources.push({ kind: "share", share, via: share.subject })
  }
  return out
}
// Planning data only. Reload state after the last await at the final check.
export type DeviceReach = { device: string; owner: OwnerRef; ownerActive: boolean; scope: WorkspaceDeviceScope; projects: Record<string, EffectiveAccess>; privateCredentials: boolean; accessRev: number }
function subjectOf(device: AccessDevice) { return { kind: device.owner.kind, id: device.owner.id } }
function environment(state: AccessState, context: ItemUseContext | undefined | null): AccessEnvironment | undefined { return state.projects.find((p) => p.id === context?.project)?.environments.find((e) => e.name === context?.environment) }
function permitsRun(access: EffectiveAccess, env: AccessEnvironment, device?: AccessDevice): boolean { return access.level !== null && (!env.protected || (access.runProtected && (device === undefined || device.scope.maxEnvironment === "protected"))) }
export function visibleHuman(state: AccessState, member: AccessMember, credential: AccessCredential, now: number): boolean {
  const home = credential.home
  if (home.kind === "member") return home.member === member.id
  if (home.kind === "workspace" && member.standing.effectiveRole !== "guest") return true
  if (home.kind === "project") return effectiveAccess(state, { kind: "member", id: member.id }, home.project, now).level !== null
  return state.projects.some((p) => effectiveAccess(state, { kind: "member", id: member.id }, p.id, now).level !== null && p.environments.some((e) => e.references.some((r) => r.item === credential.id)))
}
// No project has an empty id: a workload whose projects no longer meet its
// device's matches none, never (as an empty list would) every project.
const NO_PROJECT = ""
// The one place a workload's scope meets its device's. Modes and projects
// intersect into the scope every device check reads; items and tags ride on
// the device for deviceCredential. A workload that ended, or names another
// device, acts as no device at all.
export function principalDevice(state: AccessState, principal: AccessPrincipal, now: number): AccessDevice | undefined {
  if (principal.kind !== "device") return undefined
  return workloadDevice(state, principal.deviceId, principal.workload, now)
}
function workloadDevice(state: AccessState, deviceId: string, workloadId: string | undefined, now: number): AccessDevice | undefined {
  const device = state.devices.find((d) => d.id === deviceId)
  if (!device || workloadId === undefined) return device
  const workload = state.workloads?.find((w) => w.id === workloadId && w.device === device.id)
  if (!workload || workload.revokedAt !== null || workload.expiresAt <= now) return undefined
  const scope = workload.scope
  const modes = scope.modes ? device.scope.modes.filter((m) => scope.modes?.includes(m)) : device.scope.modes
  const projects = scope.projects === undefined ? device.scope.projects : device.scope.projects.length === 0 ? scope.projects : device.scope.projects.filter((p) => scope.projects?.includes(p))
  return { ...device, scope: { ...device.scope, modes, projects: scope.projects !== undefined && projects.length === 0 ? [NO_PROJECT] : projects }, workload: scope }
}
export function workloadCovers(scope: WorkloadScope | undefined, credential: AccessCredential): boolean {
  if (scope === undefined) return true
  if (scope.items && (credential.slug === undefined || !scope.items.includes(credential.slug))) return false
  return !scope.tags || credential.tags.some((t) => scope.tags?.includes(t))
}
function deviceCredential(state: AccessState, device: AccessDevice, credential: AccessCredential, now: number, context?: ItemUseContext, metadata = false, mode: WorkspaceDeviceScope["modes"][number] = "relay"): boolean {
  const owner = state.members.find((m) => m.id === device.owner.id)
  if (!device.scope.modes.includes(mode)) return false
  if (!workloadCovers(device.workload, credential)) return false
  if (device.status !== "active" || (device.owner.kind === "member" ? !usable(owner) : !state.teams.some((t) => t.id === device.owner.id))) return false
  if (device.scope.tags.length > 0 && !credential.tags.some((t) => device.scope.tags.includes(t))) return false
  if (!metadata && context) {
    const env = environment(state, context)
    if (!env || credential.home.kind !== "member" && !env.references.some((r) => r.item === credential.id) || (device.scope.projects.length > 0 && !device.scope.projects.includes(context.project)) || !permitsRun(effectiveAccess(state, subjectOf(device), context.project, now), env, device)) return false
  }
  if (credential.home.kind === "member") return device.owner.kind === "member" && credential.home.member === device.owner.id && device.scope.privateCredentials && (metadata || !environment(state, context)?.protected)
  const access = (project: string) => device.scope.projects.length === 0 || device.scope.projects.includes(project) ? effectiveAccess(state, subjectOf(device), project, now) : empty()
  const references = state.projects.flatMap((p) => p.environments.filter((e) => e.references.some((r) => r.item === credential.id)).map((env) => ({ project: p.id, env })))
  if (references.some((r) => r.env.protected) && !metadata) {
    const env = environment(state, context)
    if (!context || !env?.protected || !env.references.some((r) => r.item === credential.id) || !permitsRun(access(context.project), env, device)) return false
  }
  if (credential.home.kind === "workspace" && device.owner.kind === "member" && owner && owner.standing.effectiveRole !== "guest") return true
  if (credential.home.kind === "project" && access(credential.home.project).level !== null) return true
  return references.some((r) => metadata ? access(r.project).level !== null : context?.project === r.project && context.environment === r.env.name && permitsRun(access(r.project), r.env, device))
}
export function reach(state: AccessState, d: AccessDevice, now: number): DeviceReach {
  const member = state.members.find((m) => m.id === d.owner.id)
  const team = state.teams.find((t) => t.id === d.owner.id)
  const owner: OwnerRef = d.owner.kind === "member" ? { kind: "member", member: d.owner.id, name: member?.name ?? "" } : { kind: "team", team: d.owner.id, name: team?.name ?? "" }
  const ownerActive = d.status === "active" && (d.owner.kind === "member" ? usable(member) : team !== undefined)
  return { device: d.id, owner, ownerActive, scope: d.scope, projects: ownerActive ? Object.fromEntries(state.projects.filter((p) => d.scope.projects.length === 0 || d.scope.projects.includes(p.id)).map((p) => {
    const access = effectiveAccess(state, subjectOf(d), p.id, now)
    return [p.id, { ...access, runProtected: access.runProtected && d.scope.maxEnvironment === "protected", editProtected: false }]
  }).filter(([, a]) => typeof a === "object" && a !== null && "level" in a && a.level !== null)) : {}, privateCredentials: ownerActive && d.owner.kind === "member" && d.scope.privateCredentials, accessRev: state.accessRev }
}
function classifyKind(action: AccessActionKind, target: ScopedAccessTarget, before = target.before, after = target.after): AccessClassification {
  if (action === "credential.reveal" || action === "credential.push" || action === "backup.export" || action === "credential.use" && target.push) return "reveal"
  if (action === "approval.approve" || action === "policy.approve" || action === "policy.rule.approve" || action === "policy.cosign" || action === "run.protected" || action === "run.unprotected" || action === "credential.use") return "approve"
  if (action === "device.rescope") return before && after && scopeChangeIsNarrowing(before, after) ? "narrow" : "widen"
  if (["workspace.freeze", "device.revoke", "workload.revoke", "device.self_revoke", "approval.deny", "policy.deny", "policy.stop", "policy.cosigner_revoke", "invite.revoke", "intake.cancel", "connect.cancel", "enrol.reject", "device.rescope_reject", "session.end", "run.end", "backup.recipient_remove", "credential.posture_ask", "mandate.pause", "mandate.stop", "workspace.approvals_more"].includes(action)) return "narrow"
  if (["passkey.rename", "workspace.export", "members.read", "member.machines", "project.read", "credential.metadata", "device.read_self", "devices.read", "audit.read", "asks.read", "ask.detail", "backup.read"].includes(action)) return "read"
  return "widen"
}
export function fourEyesProjects(state: AccessState, ask: AccessAsk): string[] {
  const liveItems = ask.credential === null ? environment(state, ask.context)?.references.map((reference) => reference.item) ?? [] : []
  const items = [...ask.credentials, ...liveItems]
  return state.projects.filter((p) => p.environments.some((e) => e.protected && e.fourEyes && (e.references.some((r) => items.includes(r.item)) || ask.credential === null && p.id === ask.context?.project && e.name === ask.context.environment))).map((p) => p.id)
}
// What a backup export holds for a member, from live state: workspace
// credentials for an owner or admin, project credentials where they manage
// the project, and their own private ones; never anyone else's private
// credential. A credential a four-eyes environment references is left out,
// and listed, because an export would sidestep the second person.
export type BackupScope = { credentials: AccessCredential[]; fourEyes: AccessCredential[]; projects: AccessProject[] }
export function backupScope(state: AccessState, memberId: string, now: number): BackupScope {
  const m = state.members.find((m) => m.id === memberId)
  if (!m || m.status !== "active") return { credentials: [], fourEyes: [], projects: [] }
  const level = (project: string) => effectiveAccess(state, { kind: "member", id: m.id }, project, now).level
  const inScope = (c: AccessCredential) => c.home.kind === "member" ? c.home.member === m.id : c.home.kind === "workspace" ? admin(m.standing.effectiveRole) : level(c.home.project) === "manage"
  const fourEyes = (c: AccessCredential) => state.projects.some((p) => p.environments.some((e) => e.protected && e.fourEyes && e.references.some((r) => r.item === c.id)))
  const candidates = state.credentials.filter(inScope)
  return { credentials: candidates.filter((c) => !fourEyes(c)), fourEyes: candidates.filter(fourEyes), projects: state.projects.filter((p) => level(p.id) !== null) }
}
function eligibilityFor(state: AccessState, memberId: string, ask: AccessAsk, now: number): Eligibility {
  const m = state.members.find((m) => m.id === memberId)
  const asked = ask.via === undefined ? [ask.credential] : [ask.credential, ask.via]
  if (!Array.isArray(ask.credentials) || (ask.credential !== null && (ask.credentials.length !== asked.length || ask.credentials.some((id, i) => id !== asked[i]))) || ask.via !== undefined && (ask.credential === null || ask.via === ask.credential || ask.context !== null) || ask.credentials.some((id) => !state.credentials.some((credential) => credential.id === id))) return { canApprove: false, canDeny: false, canReadAskDetail: false, deciders: [], reason: "Not an eligible approver" }
  const context = environment(state, ask.context)
  if (ask.credential === null && (!context || ask.credentials.some((id) => !context.references.some((reference) => reference.item === id)))) return { canApprove: false, canDeny: false, canReadAskDetail: false, deciders: [], reason: "Not an eligible approver" }
  const d = workloadDevice(state, ask.device, ask.workload, now)
  const c = state.credentials.find((c) => c.id === ask.credential)
  const v = ask.via === undefined ? undefined : state.credentials.find((c) => c.id === ask.via)
  if (ask.credential !== null && (!c || ask.context && (!d || !deviceCredential(state, d, c, now, ask.context, false, ask.mode ?? "relay")))) return { canApprove: false, canDeny: false, canReadAskDetail: false, deciders: [], reason: "Not an eligible approver" }
  const own = d?.owner.kind === "member" && d.owner.id === memberId
  if (m?.standing.effectiveRole === "guest" && !own) return { canApprove: false, canDeny: false, canReadAskDetail: false, deciders: [], reason: "Not an eligible approver" }
  const manage = (p: string) => effectiveAccess(state, { kind: "member", id: memberId }, p, now).level === "manage"
  const project = ask.context?.project ?? (c?.home.kind === "project" ? c.home.project : undefined)
  const privateOwn = c?.home.kind === "member" && c.home.member === memberId
  const visible = !!m && (c ? visibleHuman(state, m, c, now) : project !== undefined && effectiveAccess(state, { kind: "member", id: memberId }, project, now).level !== null) && (!v || visibleHuman(state, m, v, now))
  const required = fourEyesProjects(state, ask)
  let approve = false
  if (m && d && humanUsable(m) && reach(state, d, now).ownerActive && visible) {
    const ownAccess = project ? effectiveAccess(state, { kind: "member", id: memberId }, project, now) : null
    const env = environment(state, ask.context)
    const requesterProjectAccess = ask.context ? effectiveAccess(state, subjectOf(d), ask.context.project, now) : null
    const requesterContext = !ask.context || !!env && (d.scope.projects.length === 0 || d.scope.projects.includes(ask.context.project)) && requesterProjectAccess !== null && permitsRun(requesterProjectAccess, env, d)
    const inRights = requesterContext && (!c || deviceCredential(state, d, c, now, ask.context ?? undefined, false, ask.mode ?? "relay")) && (!v || deviceCredential(state, d, v, now, undefined, false, "relay")) && (!env?.protected || ownAccess?.runProtected === true)
    if (inRights) {
      if (required.length > 0) approve = !own && required.every(manage)
      else if (c?.home.kind === "member") approve = own && privateOwn
      else if (d.owner.kind === "team" || state.members.find((o) => o.id === d.owner.id)?.standing.effectiveRole === "guest") approve = project !== undefined && (admin(m.standing.effectiveRole) || manage(project))
      else approve = own
      // A push's via only narrows who decides: a private one is its owner's alone.
      approve = approve && (v?.home.kind !== "member" || own && v.home.member === memberId)
    }
    if (m.standing.transitionPending || (m.standing.restriction !== null && m.standing.restriction.until > now) || (m.standing.identityGate.covered && (m.standing.identityGate.checkedAt === null || now - m.standing.identityGate.checkedAt >= 43_200_000))) approve = false
  }
  const deny = !!m && humanUsable(m) && !!d && (own || admin(m.standing.effectiveRole) || (c?.home.kind !== "member" && project !== undefined && manage(project)) || (d.owner.kind === "team" && state.teams.some((t) => t.id === d.owner.id && t.members.includes(memberId))))
  return { canApprove: approve, canDeny: deny, canReadAskDetail: visible && !!m && humanUsable(m), deciders: [], reason: approve ? null : "Not an eligible approver" }
}

export function eligibility(state: AccessState, memberId: string, ask: AccessAsk, now: number): Eligibility {
  const result = eligibilityFor(state, memberId, ask, now)
  const machine = workloadDevice(state, ask.device, ask.workload, now)
  const guestMachine = machine?.owner.kind === "member" && state.members.some((m) => m.id === machine.owner.id && m.standing.effectiveRole === "guest")
  const guestViewer = state.members.some((m) => m.id === memberId && m.standing.effectiveRole === "guest")
  return { ...result, deciders: result.canReadAskDetail && !guestMachine && !guestViewer ? state.members.filter((m) => eligibilityFor(state, m.id, ask, now).canApprove).map((m) => m.name) : [] }
}

function canKind(state: AccessState, principal: AccessPrincipal, action: AccessActionKind, target: ScopedAccessTarget, now: number, ownerRefusal: AccessDecision | null): AccessDecision {
  const device = principalDevice(state, principal, now)
  const m = principal.kind === "member" ? state.members.find((m) => m.id === principal.memberId) : device?.owner.kind === "member" ? state.members.find((m) => m.id === device.owner.id) : undefined
  const standing = m?.standing
  const role = standing?.effectiveRole
  if (principal.kind === "member" && (!m || principal.account !== m.account)) return no("not_found")
  if (device && action !== "device.self_revoke" && !reach(state, device, now).ownerActive) return no("owner_inactive")
  if (principal.kind === "device" && !device) return no(principal.workload === undefined ? "not_found" : "workload_ended")
  if (m && m.status !== "active" && action !== "device.self_revoke") return no("owner_inactive")
  const check = principal.kind === "member" ? principal.sessionCheck : null
  if (principal.kind === "member" && standing?.identityGate.covered && (!standing.identityGate.admitted || !check || standing.identityRuleRev === undefined || standing.gateGeneration === undefined || check.identityRuleRev !== standing.identityRuleRev || check.gateGeneration !== standing.gateGeneration || Date.parse(check.expiresAt) <= now || !Number.isFinite(Date.parse(check.expiresAt)))) return no("identity_required")
  const c: AccessCredential | undefined = target.credential ? state.credentials.find((c) => c.id === target.credential) : action === "credential.metadata" && target.destinationHome ? { id: "prospective-credential", slug: target.prospectiveSlug, home: target.destinationHome, tags: target.prospectiveTags ?? [] } : undefined
  if ((target.credential || action === "credential.metadata" && target.destinationHome) && (!c || (device ? !deviceCredential(state, device, c, now, target.context, true, action === "credential.use" ? target.mode ?? "relay" : "relay") : !m || !visibleHuman(state, m, c, now)))) {
    // Purging someone else's private credential is the matrix's sole delete exception.
    if (!(action === "credential.delete" && c?.home.kind === "member" && role && admin(role) && !device)) return no("not_found")
  }
  const classification = classifyKind(action, target)
  // A machine may still approve its own runs while its owner cools off, but
  // never widens or reveals.
  const restrictedAction = principal.kind === "device" ? classification === "widen" || classification === "reveal" : !["read", "narrow"].includes(classification)
  if (standing?.transitionPending && restrictedAction) return no("account_pending")
  if (standing?.restriction && standing.restriction.until > now && restrictedAction) return { allowed: false, error: "forbidden", message: standing.restriction.until >= PENDING_RESTRICTION_UNTIL ? "Your sign-in was recovered. While the pending security transition finishes, you can read, deny requests, revoke machines and freeze, but not approve, change or invite." : `Your sign-in was recovered. Until ${new Date(standing.restriction.until).toISOString().slice(0, 16).replace("T", " ")} UTC you can read, deny requests, revoke machines and freeze, but not approve, change or invite.`, next: { url: "/account", say: "Use an older account passkey to resolve recovery, or wait for cooling-off to finish." } }
  if (principal.kind === "member" && standing?.identityGate.covered && !["read", "narrow"].includes(classification) && (!check || !Number.isFinite(Date.parse(check.succeededAt)) || Date.parse(check.succeededAt) > now || now - Date.parse(check.succeededAt) >= 43_200_000)) return no("identity_required")
  if (ownerRefusal) return ownerRefusal
  const human = principal.kind === "member"
  const elevated = role !== undefined && admin(role)
  if ((action === "credential.connect" || action === "credential.reconnect") && target.client && state.projects.some((project) => project.environments.some((env) => env.protected && env.references.some((reference) => reference.item === target.client))) && (!human || !elevated)) return { allowed: false, error: "environment_refused", message: "This OAuth client requires an owner or admin.", next: { say: "Ask an owner or admin to connect using this client." } }
  const ownDevice = (d: AccessDevice | undefined) => human && d?.owner.kind === "member" && d.owner.id === m?.id
  const subject = device ? subjectOf(device) : { kind: "member" as const, id: m?.id ?? "" }
  const access = (p = target.project) => p ? (device && device.scope.projects.length > 0 && !device.scope.projects.includes(p) ? empty() : effectiveAccess(state, subject, p, now)) : empty()
  const has = (level: "use" | "edit" | "manage", p = target.project) => { const a = access(p); return a.level !== null && rank[a.level] >= rank[level] }
  const env = state.projects.find((p) => p.id === target.project)?.environments.find((e) => e.name === target.environment)
  const targetDevice = state.devices.find((d) => d.id === target.device)
  // Admitting, and rejecting as the admission signer, judge the machine's owner.
  const admitsFor = action === "device.rescope_admit" || action === "device.rescope_reject" && target.rescopeAs === "admission"
  const subjectMember = state.members.find((m) => m.id === (admitsFor && targetDevice?.owner.kind === "member" ? targetDevice.owner.id : target.member))
  const manageHome = (home: CredentialHome | undefined) => home?.kind === "member" ? home.member === m?.id : home?.kind === "workspace" ? elevated : home?.kind === "project" && has("manage", home.project)
  const createHome = (home: CredentialHome | undefined) => home?.kind === "member" ? home.member === m?.id : home?.kind === "workspace" ? elevated : home?.kind === "project" && has("edit", home.project)
  const lastOwner = (member: AccessMember | undefined) => member?.status === "active" && member.standing.effectiveRole === "owner" && !state.members.some((other) => other.id !== member.id && other.status === "active" && other.standing.effectiveRole === "owner")
  const guestSharedOn = (project: string | undefined) => subjectMember?.status === "active" && subjectMember.standing.effectiveRole === "guest" && state.shares.some((share) => share.project === project && share.subject.kind === "member" && share.subject.member === subjectMember.id && activeShare(state, share, now))
  const guestShared = guestSharedOn(target.project)
  const guestAdmission = role === "member" && has("manage") && guestShared
  const beforeScope = admitsFor ? targetDevice?.scope : undefined
  const projectsOnly = beforeScope !== undefined && target.after !== undefined && canonicalJson({ ...beforeScope, projects: [] }) === canonicalJson({ ...target.after, projects: [] })
  const afterProjects = target.after?.projects.length === 0 ? state.projects.filter((p) => guestSharedOn(p.id)).map((p) => p.id) : target.after?.projects ?? []
  const guestScopeAdmission = guestAdmission && target.after !== undefined && afterProjects.length > 0 && afterProjects.every((project) => projectsOnly && beforeScope !== undefined && (beforeScope.projects.length === 0 || beforeScope.projects.includes(project)) || has("manage", project) && guestSharedOn(project))
  const rescopeAcceptAuthority = () => human && ownDevice(targetDevice) && target.owningAccount === m?.account
  const rescopeAdmitAuthority = () => human && targetDevice?.status === "active" && targetDevice.owner.kind === "member" && !!target.before && !!target.after && !!target.proposal && subjectMember?.id !== m?.id && guestShared && (elevated || guestScopeAdmission)
  if (["member.role", "member.suspend", "member.reinstate", "member.confirm", "member.remove"].includes(action) && (!human || !elevated)) return no()
  if (["member.role", "member.suspend", "member.reinstate", "member.remove", "team.members"].includes(action) && !subjectMember) return no("not_found")
  if (action === "project.share" && (!human || role === "guest" || !has("manage"))) return no()
  if ((action === "enrol.approve" || action === "enrol.reject" || action === "project.share") && (target.member !== undefined && !subjectMember || target.team !== undefined && !state.teams.some((team) => team.id === target.team) || target.member === undefined && target.team === undefined)) return no("not_found")
  const askDevice = target.ask ? state.devices.find((d) => d.id === target.ask?.device) : undefined
  const ownAsk = target.ask && ownDevice(askDevice)
  const elig = target.ask && m ? eligibility(state, m.id, target.ask, now) : null
  if (human && ["approval.approve", "approval.deny", "policy.approve", "policy.rule.approve", "policy.cosign", "policy.cosigner_revoke", "policy.deny", "policy.stop"].includes(action) && (!elig || !elig.canReadAskDetail && !elig.canDeny)) return no("not_found")
  switch (action) {
    case "passkey.add": case "passkey.remove": case "recovery.generate": case "identity.link": case "identity.unlink": return human ? yes(action) : no()
    case "passkey.rename": case "session.end": return human ? yes() : no()
    case "workspace.create": return human && m?.canCreateWorkspaces ? yes(action) : no()
    case "account.delete": return human && !lastOwner(m) ? yes(action) : no()
    case "workspace.update": case "workspace.identity_rule": case "workspace.delete": case "workspace.delete_cancel": case "workspace.unfreeze": return human && role === "owner" ? yes(action) : no()
    case "workspace.freeze": return role !== "guest" && device?.workload === undefined && (human || device?.owner.kind === "team" || !!m) ? yes() : no()
    case "workspace.export": return human && elevated ? yes() : no()
    case "workspace.approvals_less": return human && elevated ? yes("workspace.approvals") : no()
    case "workspace.approvals_more": return human && elevated ? yes() : no()
    case "member.invite": return human && elevated && (target.role !== "owner" || role === "owner") ? yes(action) : no()
    case "invite.revoke": return human && (elevated || (role === "member" && target.creator === m?.id)) ? yes() : no()
    case "member.confirm": return human && elevated && (target.inviteTerms !== undefined && (target.inviteTerms.role !== "owner" || role === "owner")) ? yes(action) : no()
    case "member.role":
      if (subjectMember?.status === "unconfirmed") return { allowed: false, error: "conflict", message: "This membership cannot be confirmed this way." }
      return human && elevated && (role === "owner" || (target.role !== "owner" && subjectMember?.standing.effectiveRole !== "owner")) && !lastOwner(subjectMember) ? yes(action) : no()
    case "member.suspend": case "member.reinstate":
      if (subjectMember?.status !== (action === "member.suspend" ? "active" : "suspended")) return { allowed: false, error: "conflict", message: "This membership cannot be confirmed this way." }
      return human && elevated && (role === "owner" || subjectMember?.standing.effectiveRole !== "owner") && !lastOwner(subjectMember) ? yes(action) : no()
    case "member.remove": return human && elevated && (role === "owner" || subjectMember?.standing.effectiveRole !== "owner") && !lastOwner(subjectMember) ? yes(action) : no()
    case "member.leave": return human && target.member === m?.id && !lastOwner(subjectMember) ? yes(action) : no()
    case "account.reset": case "device.transfer": case "credential.reveal": return no()
    case "members.read": return human && role !== "guest" ? yes() : no()
    case "member.machines": return human && (elevated || target.member === m?.id && (!target.device || ownDevice(targetDevice)) || (role === "member" && targetDevice?.owner.kind === "team" && targetDevice.owner.id === target.team && state.teams.some((t) => t.id === target.team && t.members.includes(m?.id ?? "")))) ? yes() : no()
    case "team.update": return human && elevated ? yes(action) : no()
    case "team.members": return human && elevated && subjectMember?.standing.effectiveRole !== "guest" ? yes(action) : no()
    case "project.create": return human && role !== "guest" ? yes(action) : no()
    // A workload never creates workspace structure, whatever its scope.
    case "project.init":
      if (device?.workload !== undefined) return { allowed: false, error: "forbidden", message: "A workload never creates a project, and a machine that acts only through workloads creates none.", next: { say: "A person creates the project on Mehen's site, or from a machine enrolled without --workloads-only." } }
      return device?.owner.kind === "member" && role !== "guest" && device.scope.projects.length === 0 ? yes() : no()
    case "project.read": return has("use") ? yes() : no("not_found")
    case "project.share": {
      // A share that lets a team's machine reach a workspace credential
      // delegates it, as variable.set does: one in an unprotected environment,
      // or in a protected one when the share gives a protected context (absent
      // terms count as giving one). Removing any share, or narrowing a team's
      // live one, gives nothing new.
      const shareAfter = target.shareAfter
      const givesProtected = shareAfter === undefined || shareAfter !== null && (shareAfter.level === "manage" || shareAfter.protected)
      const project = state.projects.find((p) => p.id === target.project)
      const current = state.shares.find((s) => s.project === target.project && s.subject.kind === "team" && s.subject.team === target.team && activeShare(state, s, now))
      const narrowing = shareAfter !== undefined && shareAfter !== null && current !== undefined && shareNarrows(current, shareAfter)
      const teamDelegation = shareAfter !== null && !narrowing && state.devices.some((d) => d.status === "active" && d.owner.kind === "team" && d.owner.id === target.team) && !!project?.environments.some((e) => (!e.protected || givesProtected) && e.references.some((r) => r.home.kind === "workspace"))
      if (!human || role === "guest" || !has("manage")) return no()
      if (shareAfter === null || elevated) return yes(action)
      if (subjectMember?.standing.effectiveRole === "guest") return no()
      if (teamDelegation && project) return { allowed: false, error: "forbidden", message: "You are not allowed to do that.", next: { say: `Only an owner or admin can share ${project.slug} with a team that has a machine: it uses workspace credentials.` } }
      return yes(action)
    }
    case "environment.tighten": case "environment.loosen": case "remote.update": case "project.delete": {
      if (!human || role === "guest" || !has("manage")) return no()
      if (action === "environment.loosen" && env?.references.some((r) => r.home.kind === "workspace") && !elevated) return no()
      return yes(action === "project.delete" ? action : "item.update")
    }
    case "variable.set": {
      if (!env || !has("edit") || (env.protected && (!human || !access().editProtected))) return no()
      if (c?.home.kind === "member" || (c?.home.kind === "project" && c.home.project !== target.project)) return no()
      const sharedService = state.shares.some((s) => s.project === target.project && activeShare(state, s, now) && (s.subject.kind === "member" ? state.members.some((m) => m.id === (s.subject.kind === "member" ? s.subject.member : "") && m.standing.effectiveRole === "guest") : state.devices.some((d) => d.status === "active" && d.owner.kind === "team" && d.owner.id === (s.subject.kind === "team" ? s.subject.team : ""))))
      if (c?.home.kind === "workspace" && (env.protected || sharedService) && (!human || !elevated)) return no()
      return yes(human ? "item.update" : null)
    }
    case "override.set": return human && has("use") && env !== undefined && !env.protected && (!c || c.home.kind === "member" && c.home.member === m?.id) ? yes(action) : no()
    case "run.end": return no("not_found")
    case "run.unprotected": case "run.protected": return device && env && env.protected === (action === "run.protected") && permitsRun(access(), env, device) ? yes() : no()
    case "credential.metadata": return c ? yes() : no("not_found")
    case "credential.use": {
      if (device && c && deviceCredential(state, device, c, now, target.context, false, target.mode ?? "relay")) return yes()
      if (device && c && (state.projects.some((p) => p.environments.some((e) => e.protected && e.references.some((r) => r.item === c.id))) || environment(state, target.context)?.protected)) return { allowed: false, error: "environment_refused", message: "This credential needs an authorised protected context.", next: { command: "mehen run --env <environment> -- <command>", say: "Run with a literal --env in an authorised protected environment and approve that run." } }
      return no("not_found")
    }
    case "credential.create": case "credential.connect":
      if (device) {
        if (action === "credential.connect") return no()
        const home = target.destinationHome
        // The machine knows its own scope, so saying why its owner's private
        // home is refused reveals nothing; another member's home stays absent.
        if (home?.kind === "member" && device.owner.kind === "member" && home.member === device.owner.id && !device.scope.privateCredentials) return PRIVATE_CREDENTIALS_OFF
        return home?.kind === "member" ? device.owner.kind === "member" && home.member === device.owner.id && device.scope.privateCredentials ? yes() : no("not_found") : home?.kind === "project" ? has("edit", home.project) ? yes() : no() : home?.kind === "workspace" && device.owner.kind === "member" && elevated ? yes() : no()
      }
      return human && createHome(target.destinationHome) ? yes(action === "credential.connect" ? "connect.start" : "intake.submit") : no()
    // Storing an adopted batch: a person, never a machine, into a home they
    // may create in. A guest's machine cannot start a batch, so no guest
    // approves one.
    case "credential.adopt": return human && role !== "guest" && createHome(target.destinationHome) ? yes("adoption.approve") : no()
    case "credential.rotate":
      if (device) return c && (role !== "guest" || device.owner.kind === "member" && c.home.kind === "member" && c.home.member === device.owner.id && device.scope.privateCredentials) && deviceCredential(state, device, c, now, target.context, true) ? yes() : no()
      return human && manageHome(c?.home) && (role !== "guest" || c?.home.kind === "member") ? yes("intake.submit") : no()
    // Putting a kept previous value back: a person's rotation right, and
    // where a protected environment uses the credential, the right to
    // change that environment's variables (as variable.set asks).
    case "credential.restore": {
      if (!human || !c || !manageHome(c.home) || role === "guest" && c.home.kind !== "member") return no()
      const protectedUse = state.projects.filter((p) => p.environments.some((e) => e.protected && e.references.some((r) => r.item === c.id)))
      if (protectedUse.some((p) => !access(p.id).editProtected)) return { allowed: false, error: "forbidden", message: "A protected environment uses this credential, and you may not change it.", next: { say: "Ask an owner, an admin or a manager of that project to restore it." } }
      return yes("item.restore")
    }
    case "credential.update": case "credential.reconnect": return human && manageHome(c?.home) && (role !== "guest" || c?.home.kind === "member") ? yes(action === "credential.update" ? "item.update" : "connect.start") : no()
    // credential.update's predicate: a manager of the home, or a private credential's owner.
    case "credential.posture": case "credential.posture_ask": return human && manageHome(c?.home) && (role !== "guest" || c?.home.kind === "member") ? yes("item.posture") : no()
    // A person putting a credential where it was pushed before (item.push,
    // design 3.3): whoever could approve a machine's push of it, so a
    // private one only its owner, a shared one an admin or a manager of its
    // home and never a guest, and never one a four-eyes environment references.
    case "credential.push":
      if (!human || !c || !manageHome(c.home) || c.home.kind !== "member" && role === "guest") return no()
      if (fourEyesProjects(state, { device: "", credential: c.id, credentials: [c.id], context: null }).length > 0) return { allowed: false, error: "forbidden", message: "Push this from a machine's ask, so a second person decides." }
      return yes("item.push")
    case "credential.delete": return human && (manageHome(c?.home) && role !== "guest" || c?.home.kind === "member" && (c.home.member === m?.id || elevated)) ? yes("item.delete") : no()
    case "credential.rehome": {
      const to = target.destinationHome
      if (!human || !c || !to || to.kind === "member") return no()
      if (c.home.kind === "member") return c.home.member === m?.id && to.kind === "project" && has("edit", to.project) ? yes("item.rehome") : no()
      if (!elevated) return no()
      if (to.kind === "project" && state.projects.some((p) => p.id !== to.project && p.environments.some((e) => e.references.some((r) => r.item === c.id)))) return no()
      return yes("item.rehome")
    }
    case "intake.cancel": case "connect.cancel": return device ? target.device === device.id ? yes() : no("not_found") : human && (ownAsk || elevated || target.creator === m?.id && !target.device && !target.ask?.device || (role !== "guest" && (c ? manageHome(c.home) : createHome(target.destinationHome)))) ? yes() : no("not_found")
    case "enrol.accept": return human && target.owningAccount === m?.account && target.acceptingAccount === m?.account ? yes(action) : no()
    case "enrol.approve": return human && (target.team ? elevated : elevated || guestScopeAdmission) ? yes(action) : no()
    case "enrol.reject": return human && (subjectMember?.account === m?.account || elevated || guestAdmission) ? yes() : no()
    case "device.rescope_propose":
      return human && targetDevice?.status === "active" && target.before && target.after && (targetDevice.owner.kind === "team" ? elevated && !target.after.privateCredentials : elevated || ownDevice(targetDevice)) ? yes("device.rescope") : no()
    case "device.rescope_admit": return rescopeAdmitAuthority() ? yes("device.rescope") : no()
    case "device.rescope": {
      if (!human || !targetDevice || !(elevated || ownDevice(targetDevice)) || !target.before || !target.after || targetDevice.owner.kind === "team" && target.after.privateCredentials) return no()
      if (scopeChangeIsNarrowing(target.before, target.after)) return yes(action)
      return targetDevice.owner.kind === "team" && elevated ? yes(action) : no()
    }
    case "device.rescope_accept": return rescopeAcceptAuthority() ? yes(action) : no()
    // Rejecting narrows: the signer's own accept or admit authority, with no
    // cooling-off or pending-transition refusal, since nothing gains reach.
    case "device.rescope_reject": return (target.rescopeAs === "owner_acceptance" ? rescopeAcceptAuthority() : target.rescopeAs === "admission" && rescopeAdmitAuthority()) ? yes(action) : no()
    case "device.revoke": return human && (elevated || ownDevice(targetDevice)) ? yes(action) : no()
    case "workload.revoke": return human && (elevated || ownDevice(targetDevice)) ? yes(action) : no()
    // For now: a member who is not a guest, for a machine they own; resuming
    // is the signer's alone (target.member). Pausing and stopping are the
    // signer's, or an owner's or admin's.
    case "mandate.sign": return human && role !== "guest" && targetDevice?.status === "active" && ownDevice(targetDevice) ? yes(action) : no()
    case "mandate.resume": return human && role !== "guest" && target.member === m?.id && ownDevice(targetDevice) ? yes(action) : no()
    case "mandate.pause": case "mandate.stop": return human && (elevated || target.member === m?.id) ? yes() : no()
    case "device.self_revoke": return device?.status === "active" && device.id === target.device ? yes() : no()
    case "device.read_self": return device && device.id === target.device ? yes() : no("not_found")
    case "devices.read": return human && (!target.device || elevated || ownDevice(targetDevice) || role === "member" && targetDevice?.owner.kind === "team" && state.teams.some((t) => t.id === targetDevice.owner.id && t.members.includes(m?.id ?? ""))) ? yes() : no()
    case "approval.approve": case "policy.approve": return human && elig?.canApprove && (action !== "policy.approve" || manageHome(c?.home)) ? yes(action === "policy.approve" ? "policy.decide" : "approval.decide") : no()
    // A standing rule for a machine (policy-rules-workspace.ts): a person
    // who is not a guest and may approve the ask, and owns the machine
    // unless a team does; never an admin for another member's machine.
    case "policy.rule.approve": return human && role !== "guest" && elig?.canApprove && (askDevice?.owner.kind === "team" || ownAsk) ? yes("policy.decide") : no()
    // A standing rule's second signature (policy-rules-workspace.ts): a
    // manager of the credential's home who may read the ask, when the
    // machine's owner who approved does not manage it.
    case "policy.cosign": return human && elig?.canReadAskDetail && manageHome(c?.home) ? yes("policy.decide") : no()
    // Ending a standing rule by policy.cosign's rule, classed narrow as
    // policy.stop and policy.deny are: a recovery restriction, a pending
    // security transition or a 12-hour-old identity check does not refuse
    // it, and no passkey.
    case "policy.cosigner_revoke": return human && elig?.canReadAskDetail && manageHome(c?.home) ? yes() : no()
    case "approval.deny": case "policy.deny": return human && elig?.canDeny ? yes(action === "policy.deny" ? "policy.decide" : "approval.decide") : no()
    case "policy.stop": return device && target.ask?.device === device.id && principal.kind === "device" && principal.workload === target.ask.workload || human && (elevated || elig?.canApprove) ? yes() : no()
    case "policy.acknowledge": return human && (elevated || elig?.canApprove) ? yes() : no()
    case "audit.read": return human ? yes() : no()
    case "asks.read": return human || device?.id === target.device ? yes() : no("not_found")
    case "ask.detail": return human && elig?.canReadAskDetail ? yes() : no("not_found")
    // Backups (areas/backups.ts), owners only in v1. target.member is the
    // recipient's registrant: only they, or one of their own machines acting
    // with its own key, export to it.
    case "backup.recipient_add": return human && role === "owner" ? yes(action) : no()
    case "backup.recipient_remove": return human && (role === "owner" || target.member === m?.id) ? yes(action) : no()
    case "backup.export": return role === "owner" && target.member === m?.id && (human || device?.owner.kind === "member" && device.workload === undefined) ? yes() : no()
    case "backup.read": return role !== undefined && role !== "guest" && (human || device?.owner.kind === "member" && device.workload === undefined) ? yes() : no()
  }
  return no()
}
/** Routes rebuild the canonical action from live state, call this guard, then
 * verify its passkey. Wrong-kind route tests must refuse without state change;
 * a mismatched kind is a server bug, never authority supplied by the caller. */
export function stepUpSatisfies(decision: AccessDecision, action: WorkspaceStepUpAction | null): boolean { return decision.allowed && (decision.stepUp === null || action?.type === decision.stepUp) }

export function environmentChangeIsLoosening(before: EnvironmentState, after: EnvironmentState): boolean {
  return before.protected && !after.protected || before.fourEyes && !after.fourEyes || before.fences.some((f) => !after.fences.includes(f))
}
function actionKind(action: AccessAction): AccessActionKind {
  switch (action.type) {
    case "environment.update": return environmentChangeIsLoosening(action.before, action.after) ? "environment.loosen" : "environment.tighten"
    case "var.set": return "variable.set"
    case "people.read": return "members.read"
    case "item.read": return "credential.metadata"
    case "item.use": return "credential.use"
    case "approval.read": return "ask.detail"
    case "credential.posture": return action.level === "ask" ? "credential.posture_ask" : "credential.posture"
    default: return action.type
  }
}
// The action's before is an expected-value check only. Classification always
// uses current state, including in pending/restricted account decisions.
export function classify(state: AccessState, action: AccessAction, target: AccessTarget): AccessClassification {
  const d = state.devices.find((d) => d.id === target.device)
  return classifyKind(actionKind(action), target, d?.scope, action.type === "device.rescope" ? action.after : undefined)
}
export function can(state: AccessState, principal: AccessPrincipal, action: AccessAction, target: AccessTarget, now: number): AccessDecision {
  const m = principal.kind === "member" ? state.members.find((m) => m.id === principal.memberId) : undefined
  const d = principalDevice(state, principal, now)
  if (principal.kind === "device" && principal.workload !== undefined && !d) return no("workload_ended")
  const elevated = m !== undefined && admin(m.standing.effectiveRole)
  const project = state.projects.find((p) => p.id === target.project)
  const env = project?.environments.find((e) => e.name === target.environment)
  const targetDevice = state.devices.find((d) => d.id === target.device)
  // Ending a run only narrows, so even an unadmitted human can stop it.
  if (action.type === "run.end") {
    if (!target.run || targetDevice?.status !== "active") return no("not_found")
    return d?.id === targetDevice.id || principal.kind === "member" && usable(m) && principal.account === m?.account && (elevated || targetDevice.owner.kind === "member" && targetDevice.owner.id === m?.id) ? yes() : no("not_found")
  }
  // Do not turn stale-before checks into object, private-home or scope oracles.
  if (target.project && action.type !== "project.read") {
    const access = effectiveAccess(state, d ? subjectOf(d) : { kind: "member", id: m?.id ?? "" }, target.project, now)
    if (!project || access.level === null || d && d.scope.projects.length > 0 && !d.scope.projects.includes(target.project)) {
      if (project && access.level === null && target.project.startsWith("prj_") && (action.type === "run.unprotected" || action.type === "run.protected")) {
        const owner = m ?? (d?.owner.kind === "member" ? state.members.find((m) => m.id === d.owner.id) : undefined)
        return { allowed: false, error: "project_unshared", message: "This project has not been shared with the owner.", next: { say: owner?.standing.effectiveRole === "guest" ? "Ask the person who invited you to share this project" : owner ? `Ask an owner or project manager to share this project with ${owner.name}.` : "Ask an owner or project manager to share this project with the machine's team." } }
      }
      return no("not_found")
    }
  }
  if (target.environment && !env) return no("not_found")
  if ((action.type === "device.rescope" || action.type === "device.rescope_accept") && (!targetDevice || !m || !(elevated || targetDevice.owner.kind === "member" && targetDevice.owner.id === m.id))) return no("not_found")
  const newCredential = action.type === "var.set" && action.after?.kind === "item" ? action.after.item : target.credential
  const c = state.credentials.find((c) => c.id === newCredential)
  if (newCredential && (!c || (d ? !deviceCredential(state, d, c, now, target.context, true, action.type === "item.use" ? target.mode ?? "relay" : "relay") : !m || !visibleHuman(state, m, c, now))) && !(action.type === "credential.delete" && elevated && c?.home.kind === "member")) return no("not_found")
  if ((action.type === "credential.connect" || action.type === "credential.reconnect") && target.client) {
    const client = state.credentials.find((credential) => credential.id === target.client)
    if (!client || (d ? !deviceCredential(state, d, client, now, target.context, true) : !m || !visibleHuman(state, m, client, now))) return no("not_found")
  }
  const hasWorkspaceReference = (e: AccessEnvironment) => e.references.some((r) => r.home.kind === "workspace")
  const needsOwner = (change: "loosen" | "fences" | "protect" = "loosen"): AccessDecision => {
    if (!project || action.type !== "project.delete" && !env) return no("not_found")
    return { allowed: false, error: "forbidden", message: "You are not allowed to do that.", next: { say: action.type === "project.delete" ? `Only an owner or admin can delete ${project.slug}: a protected environment uses workspace credentials.` : change === "fences" ? `Only an owner or admin can change fences for ${project.slug}/${env!.name}.` : `Only an owner or admin can ${change} ${project.slug}/${env!.name}: it uses workspace credentials.` } }
  }
  let stale = false
  let ownerRefusal: AccessDecision | null = null
  if (action.type === "environment.update") {
    if ((target.environment === "prod" || target.environment === "production") && !action.after.protected) return { allowed: false, error: "bad_request", message: "prod and production are always protected." }
    if (!env) return no("not_found")
    const live = { protected: env.protected, fences: env.fences, fourEyes: env.fourEyes }
    const fenceChange = live.fences.some((f) => !action.after.fences.includes(f)) || action.after.fences.some((f) => !live.fences.includes(f))
    const protectingWorkspaceReference = hasWorkspaceReference(env) && !live.protected && action.after.protected
    if (!elevated && (fenceChange || protectingWorkspaceReference || hasWorkspaceReference(env) && environmentChangeIsLoosening(live, action.after))) ownerRefusal = needsOwner(protectingWorkspaceReference ? "protect" : fenceChange && (!hasWorkspaceReference(env) || !environmentChangeIsLoosening(live, action.after)) ? "fences" : "loosen")
    stale = canonicalJson(live) !== canonicalJson(action.before)
  }
  if (action.type === "var.set") {
    if (!env || !target.variable) return no("not_found")
    const live = env.references.find((r) => r.variable === target.variable)
    // A workload changes a variable only when it covers what it is bound to
    // now, as well as (checked above) what it is being bound to. A plain
    // value it sets, changes or unsets, or one a binding replaces, sits only
    // in a project its scope names: items and tags say nothing of plain values.
    if (d?.workload !== undefined) {
      if (live) {
        const bound = state.credentials.find((credential) => credential.id === live.item)
        if (!bound || !workloadCovers(d.workload, bound)) return no("not_found")
      }
      const plainChange = action.after?.kind === "plain" || !live && (action.after?.kind !== "item" || env.plainVariables?.[target.variable] !== undefined)
      if (plainChange && (target.project === undefined || !d.workload.projects?.includes(target.project))) return { allowed: false, error: "forbidden", message: "A task's workload changes plain variables only in projects it names.", next: { say: "Create a workload whose scope names this project in projects." } }
    }
    if (env.protected && live?.home.kind === "workspace" && (action.after?.kind !== "item" || action.after.item !== live.item) && !elevated) ownerRefusal = needsOwner()
    if (live) stale = action.before?.kind !== "item" || action.before.item !== live.item || action.before.field !== live.field
    else {
      const plain = env.plainVariables?.[target.variable]
      stale = plain === undefined ? action.before !== null : action.before?.kind !== "plain" || action.before.value !== plain
    }
  }
  if (action.type === "project.delete" && project?.environments.some((e) => e.protected && hasWorkspaceReference(e)) && !elevated) ownerRefusal = needsOwner()
  const scopedTarget = action.type === "device.rescope" || action.type === "device.rescope_accept" ? { ...target, before: targetDevice?.scope, after: action.after } : action.type === "project.share" ? { ...target, shareAfter: action.after } : target
  if (action.type === "device.rescope_propose" || action.type === "device.rescope_admit" || action.type === "device.rescope_reject") stale = canonicalJson(targetDevice?.scope) !== canonicalJson(target.before)
  if (action.type === "device.rescope" || action.type === "device.rescope_accept") stale = canonicalJson(targetDevice?.scope) !== canonicalJson(action.before)
  const checkedTarget = newCredential ? { ...scopedTarget, credential: newCredential } : scopedTarget
  const contextual = action.type === "item.use" ? { ...checkedTarget, context: action.context ?? checkedTarget.context } : checkedTarget
  const liveKind = action.type === "environment.update" && env ? environmentChangeIsLoosening(env, action.after) ? "environment.loosen" : "environment.tighten" : actionKind(action)
  const decision = canKind(state, principal, liveKind, contextual, now, ownerRefusal)
  if (!decision.allowed) return decision
  if (stale) return { allowed: false, error: "conflict", message: "The expected state changed.", next: { say: "Reload this page and review the change again." } }
  return decision
}
