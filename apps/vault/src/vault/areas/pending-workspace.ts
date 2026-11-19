import { DeviceRescopeProposalSchema, InviteTermsSchema, type ApprovalBatchState, WorkspaceDeviceScopeSchema, fingerprintGroups, fingerprintOf, fingerprintWords, type PendingKind, type WorkspaceNotice, type WorkspacePendingAsk, type WorkspaceRef, type WorkspaceRole } from "@mehen/protocol"
import type { InboxAction, InboxItem } from "@mehen/protocol/inbox"
import { z } from "zod"
import { VaultError } from "../../http.ts"
import type { AccessPrincipal } from "../access.ts"
import type { Area, VaultContext } from "../core.ts"
import { one } from "../core.ts"
import { accessState, digest, eligibilityState, authorise, inviteCreatorEligible, memberRows, noticesFor, noticeScan, principalOf, readStoredEnrol, workspaceRef, EnrolVisibilitySchema, InboxEnrolCandidateSchema, type EnrolVisibility, type InboxEnrolCandidate, type PendingEnrol, type WorkspaceInvocationContext } from "./workspace-runtime.ts"
import type { AccessMember, AccessState } from "../access.ts"
import { enrolDecisions } from "./workspace-devices.ts"
import { batchesHere, deviceSeesAsk, storedApprovalProjection, workspaceApproval, workspaceApprovalStatus, type WorkspaceApprovalRow } from "./approvals-workspace.ts"
import { askingWorkload } from "./workloads.ts"
import type { ApiError, PendingGroup } from "@mehen/protocol/api"
import { compareVersions } from "@mehen/protocol/version"
import { PENDING_GROUPS_CLI } from "../../cli-version.ts"
import { approvalGroupRow, approvalGroupSection } from "./approvals-batch-workspace.ts"
import { can, eligibility, type AccessAsk } from "../access.ts"

type PendingProvider = (ctx: VaultContext, principal: AccessPrincipal, invocation: WorkspaceInvocationContext) => WorkspacePendingAsk[]
const providers = new Map<"credentials" | "policy" | "adoptions", PendingProvider>()
export function registerWorkspacePendingProvider(name: "credentials" | "policy" | "adoptions", provider: PendingProvider): void { providers.set(name, provider) }

export function assertPendingProviders(registered: ReadonlySet<string>): void {
  if (!["credentials", "policy", "adoptions"].every((name) => registered.has(name))) throw new VaultError("internal", "A required pending provider is unavailable.")
}

export function workspacePending(ctx: VaultContext, principal: AccessPrincipal, invocation: WorkspaceInvocationContext): WorkspacePendingAsk[] {
  return pendingAsks(ctx, principal, invocation, null).pending
}
// Each listed approval's stored row, and whether this caller may decide it
// in a group: approve it, or deny it when it is no four-eyes ask (a
// four-eyes ask they may only deny, such as their own machine's, keeps its
// own row). A machine never may.
type PendingApproval = { row: WorkspaceApprovalRow; decidable: boolean }
// Every open ask the caller may see. With an approval scan limit, at most
// that many pending approvals are read from storage before filtering and
// `truncated` says more were left unread. Only member asks carry createdAt:
// a 0.2.0 CLI decodes a machine's own asks strictly and would drop them.
function pendingAsks(ctx: VaultContext, principal: AccessPrincipal, invocation: WorkspaceInvocationContext, approvalScan: number | null): { pending: WorkspacePendingAsk[]; truncated: boolean; approvals: Map<string, PendingApproval> } {
  assertPendingProviders(new Set(providers.keys()))
  authorise(ctx, invocation, { type: "asks.read" }, principal.kind === "device" ? { device: principal.deviceId } : {}, ctx.now())
  const state = eligibilityState(ctx, invocation), pending: WorkspacePendingAsk[] = [], listed = new Map<string, PendingApproval>()
  let approvals = approvalScan === null ? ctx.sql.exec<{ id: string }>("SELECT id FROM approvals WHERE ask IS NOT NULL AND status='pending' AND expires_at>? ORDER BY expires_at,id", ctx.now()).toArray() : ctx.sql.exec<{ id: string }>("SELECT id FROM approvals WHERE ask IS NOT NULL AND status='pending' AND expires_at>? ORDER BY expires_at,id LIMIT ?", ctx.now(), approvalScan + 1).toArray()
  const truncated = approvalScan !== null && approvals.length > approvalScan
  if (truncated) approvals = approvals.slice(0, approvalScan)
  for (const { id } of approvals) {
    const row = workspaceApproval(ctx, id)
    if (!row) continue
    if (principal.kind === "device") {
      if (!machineListsApproval(ctx, state, principal, row)) continue
      const device = state.devices.find((d) => d.id === principal.deviceId)
      if (!device) throw new VaultError("not_found", "No such object.")
      const owner = device.owner.kind === "member" ? { kind: "member" as const, member: device.owner.id, name: state.members.find((m) => m.id === device.owner.id)?.name ?? "" } : { kind: "team" as const, team: device.owner.id, name: state.teams.find((t) => t.id === device.owner.id)?.name ?? "" }
      const presentation = JSON.parse(row.presentation) as import("../services.ts").ApprovalPresentation
      pending.push({ view: "detail", workspace: invocation.workspace, owner, detail: { kind: "approval", id: row.id, title: presentation.title, url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/a/${row.id}`, expiresAt: new Date(row.expires_at).toISOString(), item: row.item, requestedBy: { device: row.device, deviceName: row.device_name, session: row.session }, bindingCode: row.binding_code } })
      listed.set(row.id, { row, decidable: false })
      continue
    }
    if (workspaceApprovalStatus(ctx, row) !== "pending") continue
    const ask = JSON.parse(row.ask) as import("../access.ts").AccessAsk
    const device = state.devices.find((d) => d.id === ask.device)
    const rights = eligibility(state, principal.memberId, ask, ctx.now())
    const own = device?.owner.kind === "member" && device.owner.id === principal.memberId
    if (!own && !rights.canApprove && !rights.canDeny) continue
    let projection: ReturnType<typeof storedApprovalProjection>
    try { projection = storedApprovalProjection(ctx, state, principal, row) } catch (error) { if (error instanceof VaultError && error.code === "not_found") continue; throw error }
    if (projection.view === "stop") pending.push({ view: "stop", workspace: projection.workspace, owner: projection.machine.owner, stop: projection })
    else pending.push({ view: "detail", workspace: projection.approval.workspace, owner: projection.approval.owner, detail: { kind: "approval", id: row.id, title: projection.approval.title, url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/a/${row.id}`, expiresAt: new Date(row.expires_at).toISOString(), item: row.item, requestedBy: projection.approval.requestedBy, bindingCode: row.binding_code, createdAt: new Date(row.created_at).toISOString() } })
    listed.set(row.id, { row, decidable: projection.view === "detail" && (rights.canApprove || rights.canDeny && !fourEyesAsk(row)) })
  }
  for (const provider of providers.values()) pending.push(...provider(ctx, principal, invocation))
  return { pending, truncated, approvals: listed }
}
// Whether a machine's key lists this approval as open: still pending (not
// stale), its own (a device's key lists its workloads' asks too, a workload
// only its own), and one it may see.
function machineListsApproval(ctx: VaultContext, state: AccessState, principal: Extract<AccessPrincipal, { kind: "device" }>, row: WorkspaceApprovalRow): boolean {
  if (row.device !== principal.deviceId || principal.workload !== undefined && row.workload !== principal.workload) return false
  return workspaceApprovalStatus(ctx, row) === "pending" && deviceSeesAsk(state, principal, JSON.parse(row.ask) as AccessAsk, ctx.now())
}

// Batch approvals: the review group (grp_) a listed approval may be shown in.
// A bundled ask keeps its own row; a superseded one is never pending.
function reviewGroupOf(entry: PendingApproval | undefined): string | null {
  if (!entry || entry.row.bundle != null || entry.row.policy_status !== null) return null
  return entry.row.review_group ?? null
}
// The group a listed approval joins in the inbox: its bundle (bnd_), or else
// its review group.
function inboxGroupOf(entry: PendingApproval | undefined): string | null {
  if (!entry || entry.row.policy_status !== null) return null
  return entry.row.bundle ?? reviewGroupOf(entry)
}
function fourEyesAsk(row: WorkspaceApprovalRow): boolean {
  return ((JSON.parse(row.snapshot) as { fourEyes?: string[] }).fourEyes?.length ?? 0) > 0
}
type GroupedAsk = { ask: WorkspacePendingAsk; row: WorkspaceApprovalRow }
// What the group row counts: every listed ask of the group, its members and
// those that keep a row of their own (a four-eyes ask the viewer may only
// deny, a stop row), each in the one section Review together lists it under
// for this viewer (approvalGroupRow, approvalGroupSection). So the row's
// count is the page's, and it never calls routine what the page asks a
// closer look at. Its times are its members'.
function groupItem(ctx: VaultContext, state: AccessState, principal: Extract<AccessPrincipal, { kind: "member" }>, workspace: WorkspaceRef, group: string, members: GroupedAsk[], others: WorkspaceApprovalRow[]): InboxItem {
  const rows = members.map((m) => m.row), first = members[0]!
  const sections = [...rows, ...others].map((row) => approvalGroupSection(approvalGroupRow(ctx, state, principal, row)))
  const counted = (section: ApprovalBatchState) => sections.filter((s) => s === section).length
  const bundle = group.startsWith("bnd_") ? ctx.sql.exec<{ device: string; workload: string | null; reason: string | null }>("SELECT device,workload,reason FROM approval_bundles WHERE id=?", group).toArray()[0] ?? null : null
  const run = !(JSON.parse(first.row.ask) as AccessAsk).credential
  return {
    kind: "group", workspace, href: workspacePath(workspace, `/g/${encodeURIComponent(group)}`), action: "review",
    // The oldest ask's creation and the soonest expiry: the countdown ring's total spans both.
    createdAt: new Date(Math.min(...rows.map((row) => row.created_at))).toISOString(), expiresAt: new Date(Math.min(...rows.map((row) => row.expires_at))).toISOString(),
    group: { group, kind: group.startsWith("bnd_") ? "bundle" : "machine", machine: { device: first.row.device, name: first.row.device_name, workload: askingWorkload(ctx, first.row.workload).workload ?? null }, owner: first.ask.owner, item: run || group.startsWith("bnd_") ? null : { slug: first.row.item }, count: sections.length, floor: counted("floor"), ownPage: counted("own-page"), denyOnly: counted("deny-only"), reason: bundle?.reason ?? null },
  }
}
// /v1/pending for a machine: its review groups of two or more open asks,
// at the top level so no row changes shape, and only to a mehen that reads
// them (PENDING_GROUPS_CLI). An older one, or one that names no version,
// gets the list exactly as before.
function machinePendingGroups(ctx: VaultContext, invocation: WorkspaceInvocationContext, pending: WorkspacePendingAsk[], approvals: Map<string, PendingApproval>): PendingGroup[] | null {
  const version = invocation.auth.kind === "device" ? invocation.auth.cliVersion ?? null : null
  if (!batchesHere(ctx) || version === null || compareVersions(version, PENDING_GROUPS_CLI) < 0) return null
  const groups = new Map<string, string[]>()
  for (const ask of pending) {
    if (ask.view !== "detail" || ask.detail.kind !== "approval") continue
    const group = reviewGroupOf(approvals.get(ask.detail.id))
    if (group !== null) groups.set(group, [...(groups.get(group) ?? []), ask.detail.id])
  }
  return [...groups].filter(([, ids]) => ids.length >= 2).map(([id, ids]) => ({ id, url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/g/${id}`, approvals: ids, bundle: false }))
}
// What approval_required adds for a machine's new ask with batch approvals
// on: its review group, the group's page and how many of the group's asks
// are open, as the machine's /v1/pending would list them, and only to a
// mehen that reads it (PENDING_GROUPS_CLI); never for a bundled or
// superseded ask. next.url stays the ask's own page.
export function askGroupExtra(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, invocation: WorkspaceInvocationContext, row: WorkspaceApprovalRow): { group?: ApiError["group"] } {
  const version = invocation.auth.kind === "device" ? invocation.auth.cliVersion ?? null : null
  const group = row.review_group ?? null
  if (!batchesHere(ctx) || version === null || compareVersions(version, PENDING_GROUPS_CLI) < 0 || group === null || row.bundle != null || row.policy_status !== null) return {}
  const state = eligibilityState(ctx, invocation)
  const open = ctx.sql.exec<{ id: string }>("SELECT id FROM approvals WHERE review_group=? AND bundle IS NULL AND status='pending' AND policy_status IS NULL AND expires_at>?", group, ctx.now()).toArray()
    .filter(({ id }) => { const stored = workspaceApproval(ctx, id); return stored !== null && machineListsApproval(ctx, state, principal, stored) }).length
  return { group: { id: group, url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/g/${group}`, open } }
}
// The inbox rows of the open asks: with batch approvals on here, two or more
// asks of one bundle, or else of one review group, that this caller may
// decide are one group row,
// in the place of the first of them, so a group counts once against
// INBOX_ITEMS_PER_WORKSPACE. Anything else is a row of its own, as before,
// and every ask is when the reader asked for no collapsing (the app).
function askItems(ctx: VaultContext, state: AccessState, principal: Extract<AccessPrincipal, { kind: "member" }>, workspace: WorkspaceRef, pending: WorkspacePendingAsk[], approvals: Map<string, PendingApproval>, collapse: boolean): InboxItem[] {
  if (!collapse || !batchesHere(ctx)) return pending.map((ask) => askItem(ctx, workspace, ask))
  const groupOf = (ask: WorkspacePendingAsk): string | null => {
    if (ask.view !== "detail" || ask.detail.kind !== "approval") return null
    const entry = approvals.get(ask.detail.id)
    return entry?.decidable ? inboxGroupOf(entry) : null
  }
  const groups = new Map<string, GroupedAsk[]>(), others = new Map<string, WorkspaceApprovalRow[]>()
  for (const ask of pending) {
    const group = groupOf(ask)
    if (group !== null && ask.view === "detail") groups.set(group, [...(groups.get(group) ?? []), { ask, row: approvals.get(ask.detail.id)!.row }])
    const entry = group === null ? approvals.get(ask.view === "stop" ? ask.stop.id : ask.detail.id) : undefined
    const alone = entry !== undefined && !entry.decidable ? inboxGroupOf(entry) : null
    if (alone !== null) others.set(alone, [...(others.get(alone) ?? []), entry!.row])
  }
  const items: InboxItem[] = [], shown = new Set<string>()
  for (const ask of pending) {
    const group = groupOf(ask), members = group === null ? [] : groups.get(group) ?? []
    if (group === null || members.length < 2) items.push(askItem(ctx, workspace, ask))
    else if (!shown.has(group)) { shown.add(group); items.push(groupItem(ctx, state, principal, workspace, group, members, others.get(group) ?? [])) }
  }
  return items
}
type EnrolSubject = { state: "pending_owner_acceptance" | "pending_admission" | null; lease: InboxEnrolCandidate["lease"]; owner: PendingEnrol["owner"]; requestedOwner: PendingEnrol["requestedOwner"]; claimedAccount: string | null; acceptedByAccount: string | null; scope: PendingEnrol["scope"] }
// The candidate as the workspace knows it: once registered, the copy's state,
// owner and acceptance are authoritative; a settled copy settles the lease.
function enrolSubject(ctx: VaultContext, candidate: InboxEnrolCandidate): EnrolSubject {
  const saved = one(ctx.sql.exec<{ value: string }>("SELECT value FROM workspace_enrolments WHERE id=?", candidate.enrolment))
  const copy = saved ? readStoredEnrol(saved.value) : null
  const settled = copy !== null && (copy.state === "active" || copy.state === "rejected" || copy.state === "expired")
  return {
    state: copy && !settled ? (copy.state as "pending_owner_acceptance" | "pending_admission") : candidate.pendingState,
    lease: settled ? "terminal" : candidate.lease,
    owner: copy?.owner ?? null,
    requestedOwner: copy?.requestedOwner ?? candidate.requestedOwner,
    claimedAccount: copy ? copy.claimedAccount : candidate.claimedAccount,
    acceptedByAccount: copy?.acceptance?.account ?? candidate.acceptedByAccount,
    scope: copy?.scope ?? { tags: [], projects: [], modes: ["relay", "sign", "mint", "placeholder"], maxEnvironment: "unprotected", privateCredentials: false },
  }
}
// Two answers from one rule, evaluated here against the caller's live
// standing. May view: owners and admins; the claimed
// account; for an admission, whoever may admit it; and the account that
// accepted the machine, for its own row awaiting admission or settled,
// view only. May act: at a live lease the visibility table's actions, at a
// lapsed one only an owner's or admin's reject, at a terminal one nothing.
// The caller and the evaluator's state, read once per invocation and never
// kept across calls.
type ReadState = { principal: ReturnType<typeof principalOf>; state: AccessState }
function readState(ctx: VaultContext, invocation: WorkspaceInvocationContext): ReadState { return { principal: principalOf(ctx, invocation.auth), state: eligibilityState(ctx, invocation) } }
function visibilityOf(ctx: VaultContext, { principal, state }: ReadState, subject: EnrolSubject): EnrolVisibility {
  const caller = principal.kind === "member" ? state.members.find((m) => m.id === principal.memberId && m.status === "active") : undefined
  if (principal.kind !== "member" || !caller) return { visible: false, actions: [] }
  const elevated = caller.standing.effectiveRole === "owner" || caller.standing.effectiveRole === "admin"
  const claimant = subject.claimedAccount !== null && subject.claimedAccount === caller.account
  const decisions = subject.state === null ? [] : enrolDecisions(ctx, state, principal, caller, subject)
  const admitter = subject.state === "pending_admission" && decisions.includes("admit")
  const accepter = subject.acceptedByAccount === caller.account && (subject.state === "pending_admission" || subject.lease === "terminal")
  const visible = elevated || claimant || admitter || accepter
  if (!visible || subject.lease === "terminal" || subject.state === null) return { visible, actions: [] }
  if (subject.lease === "lapsed") return { visible, actions: elevated && decisions.includes("reject") ? ["reject"] : [] }
  const actions = decisions.filter((action) => {
    if (action === "accept") return subject.state === "pending_owner_acceptance" && (subject.claimedAccount === null ? elevated : claimant)
    if (action === "admit") return subject.state === "pending_admission" && (elevated || admitter)
    return elevated || claimant && subject.state === "pending_owner_acceptance" || subject.state === "pending_admission" && admitter
  })
  return { visible, actions }
}
export function enrolVisibility(ctx: VaultContext, invocation: WorkspaceInvocationContext, candidate: InboxEnrolCandidate): EnrolVisibility {
  return visibilityOf(ctx, readState(ctx, invocation), enrolSubject(ctx, candidate))
}
// The enrolment rows of the inbox: a row is listed exactly when it is
// visible, its lease is live and the caller has something to do. A guest
// whose accepted machine waits for admission can open its page and is never
// listed. Rows from before 0008 have no persisted hidden group and are
// never listed.
export function inboxEnrolRows(ctx: VaultContext, invocation: WorkspaceInvocationContext, candidates: InboxEnrolCandidate[]): InboxItem[] {
  const workspace = workspaceRef(ctx), state = accessState(ctx), read = readState(ctx, invocation), items: InboxItem[] = []
  for (const candidate of candidates) {
    if (candidate.hiddenGroup === null) continue
    const subject = enrolSubject(ctx, candidate)
    if (subject.lease !== "live" || subject.state === null) continue
    const { visible, actions } = visibilityOf(ctx, read, subject)
    const action = (["accept", "admit", "reject"] as const).find((verb) => actions.includes(verb))
    if (!visible || !action) continue
    const groups: [string | null, string | null, string | null, string | null] = [...fingerprintGroups(fingerprintOf(candidate.thumbprint))]
    groups[candidate.hiddenGroup] = null
    const requestedOwner = subject.requestedOwner.kind === "team" ? { kind: "team" as const, team: subject.requestedOwner.team, name: state.teams.find((t) => t.id === (subject.requestedOwner.kind === "team" ? subject.requestedOwner.team : ""))?.name ?? "" } : { kind: "self" as const }
    items.push({ kind: "enrol", workspace, href: `/w/${workspace.slug}/e/${candidate.enrolment}`, action, createdAt: candidate.start.at, expiresAt: candidate.expiresAt, enrol: { enrolment: candidate.enrolment, name: candidate.name, host: candidate.host, backend: candidate.backend, start: candidate.start, session: candidate.session, requestedOwner, owner: subject.owner, claimed: subject.claimedAccount === null ? null : { account: subject.claimedAccount, name: candidate.claimedName ?? "" }, state: subject.state, fingerprint: { groups, words: fingerprintWords(candidate.thumbprint) }, actions, hardExpiresAt: candidate.hardExpiresAt } })
  }
  return items
}
// Per-workspace bounds of pending.inbox. The Worker sends at
// most INBOX_CANDIDATES_PER_WORKSPACE enrolment candidates. At most
// INBOX_SCAN_LIMIT approvals and INBOX_NOTICE_SCAN_LIMIT notices are read
// from storage before filtering; at most INBOX_ITEMS_PER_WORKSPACE items and
// INBOX_NOTICES_PER_WORKSPACE notices are returned, and the serialised answer
// stays within INBOX_BYTES_PER_WORKSPACE. Whole rows and whole notices past
// any bound are left out and the answer says truncated.
export const INBOX_CANDIDATES_PER_WORKSPACE = 50
export const INBOX_SCAN_LIMIT = 200
export const INBOX_NOTICE_SCAN_LIMIT = 50
export const INBOX_ITEMS_PER_WORKSPACE = 25
// Anyone with a fresh key may start an unclaimed enrolment naming a known
// workspace, and its lease runs out sooner than most asks. Genuine items
// fill the budget first; the unclaimed take at most this share of it, so a
// flood of starts can never push a real ask off the list.
export const INBOX_UNCLAIMED_ENROLMENTS_PER_WORKSPACE = 5
export const INBOX_NOTICES_PER_WORKSPACE = 10
export const INBOX_BYTES_PER_WORKSPACE = 65_536
export type WorkspaceInboxAnswer = { viewer: { member: string; role: WorkspaceRole }; items: InboxItem[]; notices: WorkspaceNotice[]; truncated: boolean }

const ASK_ACTIONS: Record<PendingKind, InboxAction> = { approval: "decide", intake: "open", connect: "connect", review: "review", reconnect: "reconnect", policy: "review", "policy-review": "review", adoption: "review" }
function workspacePath(workspace: WorkspaceRef, path: string): string { return `/w/${encodeURIComponent(workspace.slug)}${path}` }
function askDetailHref(workspace: WorkspaceRef, detail: Extract<WorkspacePendingAsk, { view: "detail" }>["detail"]): string {
  const id = encodeURIComponent(detail.id)
  switch (detail.kind) {
    case "approval": return workspacePath(workspace, `/a/${id}`)
    case "intake": return workspacePath(workspace, `/i/${id}`)
    case "connect": return workspacePath(workspace, `/c/${id}`)
    case "policy": return workspacePath(workspace, `/p/${id}`)
    case "adoption": return workspacePath(workspace, `/b/${id}`)
    case "reconnect": case "review": case "policy-review": return detail.item === null ? workspacePath(workspace, "/pending") : workspacePath(workspace, `/items/${encodeURIComponent(detail.item)}`)
  }
}
// A stop view carries neither time; both come from the row it stands for.
const STOP_SOURCES: [prefix: string, table: string][] = [["apr_", "approvals"], ["pol_", "policy_proposals"], ["int_", "workspace_credential_requests"], ["con_", "workspace_credential_requests"]]
function stopTimes(ctx: VaultContext, id: string): { createdAt: string | null; expiresAt: string | null } {
  const table = STOP_SOURCES.find(([prefix]) => id.startsWith(prefix))?.[1]
  const row = table ? one(ctx.sql.exec<{ created_at: number; expires_at: number }>(`SELECT created_at,expires_at FROM ${table} WHERE id=?`, id)) : null
  return row ? { createdAt: new Date(row.created_at).toISOString(), expiresAt: new Date(row.expires_at).toISOString() } : { createdAt: null, expiresAt: null }
}
// A stop row opens the page that can stop it: an approval's or a policy
// proposal's own page (each draws its stop view), else the workspace's
// Needs you, where an intake or connect is cancelled in place.
function stopHref(workspace: WorkspaceRef, id: string): string {
  if (id.startsWith("apr_")) return workspacePath(workspace, `/a/${encodeURIComponent(id)}`)
  if (id.startsWith("pol_")) return workspacePath(workspace, `/p/${encodeURIComponent(id)}`)
  return workspacePath(workspace, "/pending")
}
function askItem(ctx: VaultContext, workspace: WorkspaceRef, ask: WorkspacePendingAsk): InboxItem {
  if (ask.view === "stop") return { kind: "ask", workspace, href: stopHref(workspace, ask.stop.id), action: "stop", ...stopTimes(ctx, ask.stop.id), ask }
  return { kind: "ask", workspace, href: askDetailHref(workspace, ask.detail), action: ASK_ACTIONS[ask.detail.kind], createdAt: ask.detail.createdAt ?? null, expiresAt: ask.detail.expiresAt, ask }
}
// Members who joined through an invitation and wait for confirmation, listed
// to a caller who could confirm them now: the invitation is unexpired, its
// creator still eligible, and member.confirm allows this caller.
function confirmationItems(ctx: VaultContext, state: AccessState, principal: Extract<AccessPrincipal, { kind: "member" }>, workspace: WorkspaceRef): InboxItem[] {
  const now = ctx.now()
  if (!can(state, principal, { type: "member.invite" }, {}, now).allowed) return []
  const members = memberRows(ctx), items: InboxItem[] = []
  for (const invite of ctx.sql.exec<{ id: string; terms: string; digest: string; creator: string; creator_evidence: string | null; member: string }>("SELECT id,terms,digest,creator,creator_evidence,member FROM invites WHERE status='pending_confirmation' AND member IS NOT NULL ORDER BY created_at,id").toArray()) {
    const subject = members.find((m) => m.id === invite.member && m.status === "unconfirmed")
    const terms = InviteTermsSchema.safeParse(JSON.parse(invite.terms))
    if (!subject || !terms.success || Date.parse(terms.data.expiresAt) <= now || !inviteCreatorEligible(ctx, invite.creator, invite.creator_evidence, terms.data.role)) continue
    if (!can(state, principal, { type: "member.confirm" }, { member: subject.id, inviteTerms: terms.data }, now).allowed) continue
    const joinedAt = new Date(subject.joined_at).toISOString()
    items.push({ kind: "confirm", workspace, href: workspacePath(workspace, `/people#confirm-${encodeURIComponent(subject.id)}`), action: "confirm", createdAt: joinedAt, expiresAt: terms.data.expiresAt, confirm: { member: subject.id, name: subject.name, role: terms.data.role, invite: invite.id, termsDigest: invite.digest, boundEmail: terms.data.email, joinedAt } })
  }
  return items
}
// Scope proposals this caller can still sign or reject now. The stored
// signer list only says who was asked; the authority is decided here from
// live standing, exactly as the accept, admit and reject routes decide it:
// the proposal must still be valid for its machine (open, unexpired, same
// thumbprint, scope, scope revision and owner revision, machine not
// revoked), and the evaluator must allow the signer's accept or admit, or
// at least the narrowing reject in that role. A guest only ever as the owner
// of their own machine.
function rescopeItems(ctx: VaultContext, state: AccessState, principal: Extract<AccessPrincipal, { kind: "member" }>, caller: AccessMember, workspace: WorkspaceRef): InboxItem[] {
  const now = ctx.now(), items: InboxItem[] = [], members = memberRows(ctx)
  for (const saved of ctx.sql.exec<{ value: string }>("SELECT value FROM device_rescope_proposals ORDER BY id").toArray()) {
    const proposal = DeviceRescopeProposalSchema.parse(JSON.parse(saved.value))
    const signer = proposal.requiredSigners.find((s) => s.account === caller.account)
    if (proposal.state !== "open" || Date.parse(proposal.expiresAt) <= now || !signer || proposal.signedBy.includes(caller.account)) continue
    const device = one(ctx.sql.exec<{ name: string; thumbprint: string; scope: string; scope_rev: number; revoked_at: number | null; owner_kind: string | null; owner_id: string | null; owner_revision: number }>("SELECT name,thumbprint,scope,scope_rev,revoked_at,owner_kind,owner_id,owner_revision FROM devices WHERE id=?", proposal.device))
    if (!device || device.revoked_at !== null || device.thumbprint !== proposal.thumbprint || device.scope_rev !== proposal.scopeRevision || proposal.beforeDigest !== digest(JSON.parse(device.scope))) continue
    const ownerRevision = members.find((m) => m.id === device.owner_id)?.revision ?? device.owner_revision
    if (proposal.ownerRevision !== ownerRevision) continue
    if (caller.standing.effectiveRole === "guest" && !(signer.as === "owner_acceptance" && device.owner_kind === "member" && device.owner_id === caller.id)) continue
    const owningAccount = state.members.find((m) => m.id === device.owner_id)?.account
    const live = WorkspaceDeviceScopeSchema.parse(JSON.parse(device.scope))
    const allowed = (project: string | undefined) => {
      const target = { device: proposal.device, owningAccount, project, proposal: proposal.id, before: proposal.before, after: proposal.after }
      const sign = signer.as === "owner_acceptance" ? can(state, principal, { type: "device.rescope_accept", before: proposal.before, after: proposal.after }, target, now) : can(state, principal, { type: "device.rescope_admit" }, target, now)
      return sign.allowed || can(state, principal, { type: "device.rescope_reject" }, { ...target, before: live, rescopeAs: signer.as }, now).allowed
    }
    if (!(signer.as === "owner_acceptance" ? allowed(undefined) : state.projects.some((project) => allowed(project.id)))) continue
    items.push({ kind: "rescope", workspace, href: workspacePath(workspace, `/devices/${encodeURIComponent(proposal.device)}`), action: "review", createdAt: null, expiresAt: proposal.expiresAt, rescope: { proposal: proposal.id, device: proposal.device, deviceName: device.name, owner: proposal.owner, proposer: proposal.proposer, as: signer.as } })
  }
  return items
}
export function inboxItemId(item: InboxItem): string {
  switch (item.kind) {
    case "ask": return item.ask.view === "stop" ? item.ask.stop.id : item.ask.detail.id
    case "enrol": return item.enrol.enrolment
    case "confirm": return item.confirm.member
    case "rescope": return item.rescope.proposal
    case "group": return item.group.group
  }
}
function timeOf(iso: string | null): number | null { return iso === null ? null : Date.parse(iso) }
// The inbox order inside one workspace: expiresAt ascending with no expiry
// last, then createdAt newest first with none last, then id.
export function compareInboxItems(a: InboxItem, b: InboxItem): number {
  const ae = timeOf(a.expiresAt), be = timeOf(b.expiresAt)
  if (ae !== be) return ae === null ? 1 : be === null ? -1 : ae - be
  const ac = timeOf(a.createdAt), bc = timeOf(b.createdAt)
  if (ac !== bc) return ac === null ? 1 : bc === null ? -1 : bc - ac
  const ai = inboxItemId(a), bi = inboxItemId(b)
  return ai < bi ? -1 : ai > bi ? 1 : 0
}
const encoder = new TextEncoder()
function serialisedBytes(value: unknown): number { return encoder.encode(JSON.stringify(value)).byteLength }
// An enrolment nobody has taken: no account claimed it and nobody accepted it.
function unclaimedEnrolment(item: InboxItem): boolean {
  return item.kind === "enrol" && item.enrol.claimed === null && item.enrol.owner === null
}
// The count and byte bounds: genuine items in order, then the unclaimed
// enrolments in order up to their share, then the newest notices, each
// whole or not at all. What is kept stays in the order it was given.
export function boundedInbox(viewer: WorkspaceInboxAnswer["viewer"], items: InboxItem[], notices: WorkspaceNotice[], truncated: boolean): WorkspaceInboxAnswer {
  const genuine = items.filter((item) => !unclaimedEnrolment(item)), unclaimed = items.filter(unclaimedEnrolment)
  const genuineTaken = genuine.slice(0, INBOX_ITEMS_PER_WORKSPACE)
  const unclaimedTaken = unclaimed.slice(0, Math.min(INBOX_UNCLAIMED_ENROLMENTS_PER_WORKSPACE, INBOX_ITEMS_PER_WORKSPACE - genuineTaken.length))
  let cut = truncated || genuineTaken.length + unclaimedTaken.length < items.length || notices.length > INBOX_NOTICES_PER_WORKSPACE
  let size = serialisedBytes({ viewer, items: [], notices: [], truncated: false })
  const kept = new Set<InboxItem>(), newest: WorkspaceNotice[] = []
  for (const item of [...genuineTaken, ...unclaimedTaken]) {
    const bytes = serialisedBytes(item) + 1
    if (size + bytes > INBOX_BYTES_PER_WORKSPACE) { cut = true; break }
    kept.add(item); size += bytes
  }
  for (const notice of notices.slice(-INBOX_NOTICES_PER_WORKSPACE).reverse()) {
    const bytes = serialisedBytes(notice) + 1
    if (size + bytes > INBOX_BYTES_PER_WORKSPACE) { cut = true; break }
    newest.push(notice); size += bytes
  }
  return { viewer, items: items.filter((item) => kept.has(item)), notices: newest.reverse(), truncated: cut }
}
// A review group (grp_) or bundle (bnd_) id, as /w/<slug>/g/<id> names it.
export const INBOX_GROUP_ID = /^(grp|bnd)_[A-Za-z0-9_-]{1,60}$/
// The asks of one review group or bundle, one row each, as the group's page
// lists them until Review together replaces it: nothing else, and an
// unknown or unseen id reads exactly as an empty group.
function groupAskItems(ctx: VaultContext, workspace: WorkspaceRef, pending: WorkspacePendingAsk[], approvals: Map<string, PendingApproval>, group: string): InboxItem[] {
  const inGroup = (ask: WorkspacePendingAsk): boolean => {
    const row = approvals.get(ask.view === "stop" ? ask.stop.id : ask.detail.id)?.row
    return row !== undefined && (group.startsWith("bnd_") ? row.bundle === group : row.review_group === group)
  }
  return pending.filter(inGroup).map((ask) => askItem(ctx, workspace, ask))
}
function workspaceInboxAnswer(ctx: VaultContext, invocation: WorkspaceInvocationContext, candidates: InboxEnrolCandidate[], group: string | null, collapse: boolean): WorkspaceInboxAnswer {
  const decision = authorise(ctx, invocation, { type: "asks.read" }, {}, ctx.now())
  const member = decision.principal.kind === "member" ? decision.principal : null
  const state = eligibilityState(ctx, invocation)
  const caller = member ? state.members.find((m) => m.id === member.memberId) : undefined
  if (!member || !caller) throw new VaultError("forbidden", "Only people have an inbox.")
  if (group !== null && !batchesHere(ctx)) throw new VaultError("not_found", "No such review group.")
  const workspace = workspaceRef(ctx), viewer = { member: caller.id, role: caller.standing.effectiveRole }
  const asks = pendingAsks(ctx, member, invocation, INBOX_SCAN_LIMIT)
  if (group !== null) return boundedInbox(viewer, groupAskItems(ctx, workspace, asks.pending, asks.approvals, group).sort(compareInboxItems), [], asks.truncated)
  const notices = noticeScan(ctx, member, INBOX_NOTICE_SCAN_LIMIT)
  const items = [...askItems(ctx, state, member, workspace, asks.pending, asks.approvals, collapse), ...inboxEnrolRows(ctx, invocation, candidates), ...confirmationItems(ctx, state, member, workspace), ...rescopeItems(ctx, state, member, caller, workspace)].sort(compareInboxItems)
  return boundedInbox(viewer, items, notices.notices, asks.truncated || notices.truncated)
}
export const workspacePendingOps: NonNullable<Area["workspaceOps"]> = {
  // Everything this account may act on in this workspace, decided here from
  // live standing: the Worker's candidates are filtered, never trusted.
  "pending.inbox": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const { enrolments, group, collapse } = z.strictObject({ enrolments: z.array(InboxEnrolCandidateSchema).max(INBOX_CANDIDATES_PER_WORKSPACE), group: z.string().regex(INBOX_GROUP_ID).optional(), collapse: z.boolean().optional() }).parse(raw)
    return workspaceInboxAnswer(ctx, invocation, enrolments, group ?? null, collapse ?? true)
  } },
  "access.enrol.visible": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const { candidate } = z.strictObject({ candidate: InboxEnrolCandidateSchema }).parse(raw)
    authorise(ctx, invocation, { type: "asks.read" }, {}, ctx.now())
    return EnrolVisibilitySchema.parse(enrolVisibility(ctx, invocation, candidate))
  } },
  "pending.list": { auth: ["account", "device"], handler(ctx, principal, _input, invocation) {
    if (principal.kind === "system") throw new VaultError("forbidden", "System calls have no pending queue.")
    const asks = pendingAsks(ctx, principal, invocation, null)
    const groups = principal.kind === "device" ? machinePendingGroups(ctx, invocation, asks.pending, asks.approvals) : null
    return { pending: asks.pending, notices: noticesFor(ctx, principal), ...(groups === null ? {} : { groups }) }
  } },
}
