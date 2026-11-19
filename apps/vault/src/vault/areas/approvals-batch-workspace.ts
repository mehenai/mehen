// Review together (batch approvals): the asks of one review group (grp_) or
// bundle (bnd_) as one viewer may see them, each with its batch state, and
// one passkey over a sorted list of up to 25 decisions, each then decided
// in its own transaction with the checks a single decision makes.

import { APPROVAL_BATCH_MAX, type ApprovalBatchEntry, type ApprovalBatchOutcome, type ApprovalBatchResult, type ApprovalBatchState, type ApprovalGroupRow, type ApprovalGroupView, type ApprovalOwnPageReason, type WorkspaceStepUpAction } from "@mehen/protocol"
import type { ApprovalSubject } from "@mehen/protocol/api"
import type { PolicyFloorView } from "@mehen/protocol/policy-mode"
import { z } from "zod"
import { VaultError } from "../../http.ts"
import { textWarnings } from "../../relay/spelling.ts"
import { eligibility, principalDevice, stepUpSatisfies, type AccessAsk, type AccessPrincipal, type AccessState } from "../access.ts"
import { randomId, type VaultContext } from "../core.ts"
import { digestOf, parseOpInput } from "./approvals.ts"
import { approvalRowProjection, assertApprovalGraphCurrent, batchesHere, reviewGroupCode, recordDecision, workspaceApproval, workspaceApprovalStatus, type WorkspaceApprovalRow } from "./approvals-workspace.ts"
import type { ProtectedSnapshot } from "./projects-workspace.ts"
import { isPushSubject } from "./push-records.ts"
import { askingWorkload } from "./workloads.ts"
import { authorise, eligibilityState, verifiedStepUp, type WorkspaceInvocationContext } from "./workspace-runtime.ts"

export function batchesUnavailable(): VaultError {
  return new VaultError("forbidden", "Deciding asks together is not available yet.")
}
function assertBatchesHere(ctx: VaultContext): void {
  if (!batchesHere(ctx)) throw batchesUnavailable()
}

// What the page sends to build or decide a batch: each ask once, at most 25.
export const ApprovalBatchDecisions = z.strictObject({ entries: z.array(z.strictObject({ id: z.string().max(64), decision: z.enum(["approve", "deny"]) })).min(1).max(APPROVAL_BATCH_MAX) })
type BatchDecisions = z.infer<typeof ApprovalBatchDecisions>
function parseDecisions(raw: unknown): BatchDecisions {
  const input = parseOpInput(ApprovalBatchDecisions, raw)
  if (new Set(input.entries.map((e) => e.id)).size !== input.entries.length) throw new VaultError("bad_request", "Each ask may appear once in a batch.")
  return input
}

// Every string a detail view holds. A warning found anywhere in it is a
// warning found in what the ask's own page shows.
function detailStrings(value: unknown): string[] {
  if (typeof value === "string") return [value]
  if (Array.isArray(value)) return value.flatMap(detailStrings)
  if (typeof value === "object" && value !== null) return Object.values(value).flatMap(detailStrings)
  return []
}

// Why an ask is decided on its own page whoever looks at it: a run,
// four-eyes or a push, read from the stored ask, snapshot and subject alone.
function storedOwnPage(row: WorkspaceApprovalRow): Extract<ApprovalOwnPageReason, "run" | "four-eyes" | "push"> | null {
  const ask = JSON.parse(row.ask) as AccessAsk, snapshot = JSON.parse(row.snapshot) as ProtectedSnapshot
  if (snapshot.run !== undefined || ask.credential === null) return "run"
  if (isPushSubject(JSON.parse(row.subject) as ApprovalSubject)) return "push"
  return snapshot.fourEyes.length > 0 ? "four-eyes" : null
}

// One ask of a group as `principal` sees it (not_found when they may not),
// with its batch state: own-page (a run, four-eyes, a push, a warning, or
// no binding to check), deny-only, floor (floor reasons, a NULL floor, or a
// protected credential's use, ruling B2) or routine. A stop view is
// own-page for a run, four-eyes or push ask, which a batch refuses, and
// deny-only otherwise.
export function approvalGroupRow(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, row: WorkspaceApprovalRow): ApprovalGroupRow {
  const projected = approvalRowProjection(ctx, state, principal, row)
  if (projected.view === "stop") return { view: "stop", stop: projected, batch: storedOwnPage(row) !== null ? "own-page" : "deny-only" }
  const detail = projected.approval
  const snapshot = JSON.parse(row.snapshot) as ProtectedSnapshot, subject = JSON.parse(row.subject) as ApprovalSubject
  const bound = !!row.snapshot_digest && !!row.presentation_digest && digestOf({ subject, snapshotDigest: row.snapshot_digest, presentationDigest: row.presentation_digest }) === row.digest
  const warned = detail.warnings.length > 0 || textWarnings(detailStrings(detail)).length > 0
  const ownPage: ApprovalOwnPageReason | null = storedOwnPage(row) ?? (warned ? "warning" : !bound ? "unbound" : null)
  const floor = row.floor === null || row.floor === undefined ? null : JSON.parse(row.floor) as PolicyFloorView["reason"][]
  const isProtected = snapshot.protected === true
  const batch = ownPage !== null ? "own-page" : !detail.eligibility.canApprove ? "deny-only" : floor === null || floor.length > 0 || isProtected ? "floor" : "routine"
  return { view: "detail", approval: detail, binding: projected.binding ?? { snapshotDigest: "", presentationDigest: "" }, batch, ownPage, floor: floor ?? [], createdAt: new Date(row.created_at).toISOString(), replacedBy: detail.replacedBy ?? null, protected: isProtected, newerSameShape: null }
}

// Where Review together lists a row, and how a group's inbox row counts it:
// its batch state, except that a push (by its request's method, or its push
// presentation) is decided on its own page, where it is sent, whatever the
// classifier named; decide_many refuses it too. Once ApprovalOwnPageReason
// has "push" (example/push-followups), approvalGroupRow places it itself.
export function approvalGroupSection(row: ApprovalGroupRow): ApprovalBatchState {
  return row.view === "detail" && (isPushSubject(row.approval.request) || row.approval.push !== undefined) ? "own-page" : row.batch
}

// An ask as the viewer sees it in a group, or null when they do not see it,
// as the pending list decides: their own machine's, or one they may approve
// or deny, in a view the projection lets them read.
function visibleGroupRow(ctx: VaultContext, state: AccessState, principal: Extract<AccessPrincipal, { kind: "member" }>, row: WorkspaceApprovalRow): ApprovalGroupRow | null {
  const ask = JSON.parse(row.ask) as AccessAsk
  const device = state.devices.find((d) => d.id === ask.device)
  const rights = eligibility(state, principal.memberId, ask, ctx.now())
  const own = device?.owner.kind === "member" && device.owner.id === principal.memberId
  if (!own && !rights.canApprove && !rights.canDeny) return null
  try { return approvalGroupRow(ctx, state, principal, row) } catch (error) { if (error instanceof VaultError && error.code === "not_found") return null; throw error }
}

const SETTLED_WINDOW_MS = 3_600_000
const SETTLED_ROWS = 50
// The rows of a group: pending oldest first, then those settled in the last
// hour, oldest first. A machine group holds at most 20 pending asks (the
// per-machine cap); settled rows are bounded here. A bundled ask is listed
// only on its bundle's page, never also on its machine's review group page.
function groupRows(ctx: VaultContext, column: "review_group" | "bundle", id: string): WorkspaceApprovalRow[] {
  const now = ctx.now()
  const inGroup = column === "review_group" ? "review_group=? AND bundle IS NULL" : "bundle=?"
  const pending = ctx.sql.exec<WorkspaceApprovalRow>(`SELECT * FROM approvals WHERE ${inGroup} AND ask IS NOT NULL AND status='pending' AND policy_status IS NULL AND expires_at>? ORDER BY created_at,id`, id, now).toArray()
  const settled = ctx.sql.exec<WorkspaceApprovalRow>(`SELECT * FROM approvals WHERE ${inGroup} AND ask IS NOT NULL AND NOT (status='pending' AND policy_status IS NULL AND expires_at>?) AND (decided_at>? OR status='pending' AND expires_at>?) ORDER BY created_at DESC,id DESC LIMIT ?`, id, now, now - SETTLED_WINDOW_MS, now - SETTLED_WINDOW_MS, SETTLED_ROWS).toArray().reverse()
  return [...pending, ...settled]
}

export function approvalGroupView(ctx: VaultContext, state: AccessState, principal: Extract<AccessPrincipal, { kind: "member" }>, invocation: WorkspaceInvocationContext, id: string): ApprovalGroupView {
  const kind = id.startsWith("grp_") ? "machine" : id.startsWith("bnd_") ? "bundle" : null
  if (kind === null) throw new VaultError("not_found", "No such object.")
  const shown = groupRows(ctx, kind === "machine" ? "review_group" : "bundle", id).flatMap((row) => { const view = visibleGroupRow(ctx, state, principal, row); return view ? [{ row, view }] : [] })
  const first = shown[0]
  if (!first) throw new VaultError("not_found", "No such object.")
  // The newest pending row of each shape; older ones of that shape name it.
  const newest = new Map<string, string>()
  for (const { row, view } of shown) if (row.shape && view.view === "detail" && view.approval.status === "pending") newest.set(row.shape, row.id)
  const rows = shown.map(({ row, view }): ApprovalGroupRow => {
    if (view.view !== "detail") return view
    const latest = row.shape && view.approval.status === "pending" ? newest.get(row.shape) ?? null : null
    return { ...view, newerSameShape: latest !== row.id ? latest : null }
  })
  // A viewer who may read no ask's detail learns only what a stop view shows.
  const reads = rows.some((r) => r.view === "detail")
  const bundle = kind === "bundle" ? ctx.sql.exec<{ device: string; workload: string | null; reason: string | null }>("SELECT device,workload,reason FROM approval_bundles WHERE id=?", id).toArray()[0] ?? null : null
  const device = bundle?.device ?? first.row.device, workloadId = bundle ? bundle.workload : first.row.workload
  const machine = state.devices.find((d) => d.id === device)
  const owner = machine?.owner.kind === "team" ? { kind: "team" as const, team: machine.owner.id, name: state.teams.find((t) => t.id === machine.owner.id)?.name ?? "" } : { kind: "member" as const, member: machine?.owner.id ?? "", name: state.members.find((m) => m.id === machine?.owner.id)?.name ?? "" }
  const workload = reads ? askingWorkload(ctx, workloadId).workload ?? null : null
  const asked = JSON.parse(first.row.ask) as AccessAsk
  return { group: id, kind, workspace: invocation.workspace, machine: { device, name: first.row.device_name, owner, workload }, item: kind === "machine" && asked.credential !== null ? { slug: first.row.item } : null, reason: reads ? bundle?.reason ?? null : null, code: reads ? reviewGroupCode(ctx, id) : null, rows }
}

// The action a batch signs, from storage: each ask's stored digest and its
// requested limits, sorted by approval id. Shortening a grant or
// remembering it stays on the ask's own page. An id the viewer cannot see
// is refused exactly as one that does not exist.
function batchAction(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "member" }>, invocation: WorkspaceInvocationContext, input: BatchDecisions): Extract<WorkspaceStepUpAction, { type: "approval.decide_many" }> {
  authorise(ctx, invocation, { type: "asks.read" }, {}, ctx.now())
  const state = eligibilityState(ctx, invocation)
  const entries = input.entries.map(({ id, decision }): ApprovalBatchEntry => {
    const row = workspaceApproval(ctx, id)
    if (!row || !visibleGroupRow(ctx, state, principal, row)) throw new VaultError("not_found", "No such object.")
    const { uses, ttlSeconds } = (JSON.parse(row.subject) as ApprovalSubject).constraints
    return { approval: row.id, digest: row.digest, decision, uses, ttlSeconds }
  })
  return { type: "approval.decide_many", entries: entries.sort((a, b) => a.approval < b.approval ? -1 : a.approval > b.approval ? 1 : 0) }
}

class OwnPageRefusal extends VaultError {
  constructor() { super("forbidden", "Decide this one on its own page.") }
}

// One entry, in its own transaction: today's decision without its step-up,
// which the batch checked once. A refusal rolls back this entry only. A run,
// four-eyes or push ask is refused whatever the view, so not even a person
// who may only deny it decides it here; a warning needs the detail view to
// find.
function decideEntry(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "member" }>, invocation: WorkspaceInvocationContext, entry: ApprovalBatchEntry, batch: string): { outcome: ApprovalBatchOutcome; message: string } {
  try {
    ctx.storage.transactionSync(() => {
      const row = workspaceApproval(ctx, entry.approval)
      if (!row) throw new VaultError("not_found", "No such object.")
      if (row.digest !== entry.digest) throw new VaultError("conflict", "It changed after the list was signed.")
      const state = eligibilityState(ctx, invocation), ask = JSON.parse(row.ask) as AccessAsk
      const decision = authorise(ctx, invocation, { type: entry.decision === "approve" ? "approval.approve" : "approval.deny" }, { ask }, ctx.now())
      const constraints = { uses: entry.uses, ttlSeconds: entry.ttlSeconds }
      if (!stepUpSatisfies(decision, { type: "approval.decide", approval: row.id, digest: entry.digest, decision: entry.decision, constraints })) throw new VaultError("forbidden", "This needs a passkey confirmation of the exact action.")
      const shown = approvalGroupRow(ctx, state, principal, row)
      if (storedOwnPage(row) !== null || shown.view === "detail" && shown.ownPage !== null) throw new OwnPageRefusal()
      recordDecision(ctx, state, principal, row, entry.decision, constraints, invocation, batch)
    })
    return entry.decision === "approve" ? { outcome: "approved", message: "Approved." } : { outcome: "denied", message: "Denied." }
  } catch (error) {
    if (!(error instanceof VaultError)) throw error
    return refusedEntry(ctx, invocation, entry, error)
  }
}
// Why an entry was left undecided, read from the ask as it stands now.
function refusedEntry(ctx: VaultContext, invocation: WorkspaceInvocationContext, entry: ApprovalBatchEntry, error: VaultError): { outcome: ApprovalBatchOutcome; message: string } {
  const row = workspaceApproval(ctx, entry.approval)
  if (!row) return { outcome: "forbidden", message: error.message }
  const ask = JSON.parse(row.ask) as AccessAsk, state = eligibilityState(ctx, invocation)
  const asker = principalDevice(state, { kind: "device", deviceId: ask.device, ...(ask.workload !== undefined ? { workload: ask.workload } : {}) }, ctx.now())
  if (row.status !== "pending") return { outcome: "decided", message: "It was already decided." }
  if (row.policy_status === "superseded") return { outcome: "superseded", message: "A newer ask to the same place replaced it." }
  if (row.expires_at <= ctx.now()) return { outcome: "expired", message: "It had expired." }
  if (row.policy_status !== null || asker?.status !== "active" || workspaceApprovalStatus(ctx, row) === "stale" || entry.decision === "approve" && !graphCurrent(ctx, state, row, ask)) return { outcome: "stale", message: "Access changed since it was asked; the agent must ask again." }
  if (error instanceof OwnPageRefusal) return { outcome: "own_page", message: error.message }
  if (error.code === "conflict") return { outcome: "changed", message: error.message }
  return { outcome: "forbidden", message: error.message }
}

function graphCurrent(ctx: VaultContext, state: AccessState, row: WorkspaceApprovalRow, ask: AccessAsk): boolean {
  try { assertApprovalGraphCurrent(ctx, state, JSON.parse(row.snapshot) as ProtectedSnapshot, ask); return true } catch (error) { if (error instanceof VaultError) return false; throw error }
}

export const workspaceApprovalBatchOps: NonNullable<import("../core.ts").Area["workspaceOps"]> = {
  "approvals.group": { auth: ["account"], handler(ctx, principal, raw, invocation) {
    if (principal.kind !== "member") throw new VaultError("not_found", "No such object.")
    assertBatchesHere(ctx)
    const { id } = parseOpInput(z.strictObject({ id: z.string().max(64) }), raw)
    authorise(ctx, invocation, { type: "asks.read" }, {}, ctx.now())
    return approvalGroupView(ctx, eligibilityState(ctx, invocation), principal, invocation, id)
  } },
  "approvals.action_many": { auth: ["account"], handler(ctx, principal, raw, invocation) {
    if (principal.kind !== "member") throw new VaultError("forbidden", "Only a person can decide an approval.")
    assertBatchesHere(ctx)
    return batchAction(ctx, principal, invocation, parseDecisions(raw))
  } },
  // One passkey over the exact list, then each entry on its own, with no
  // await between them. A batch never remembers a rule or a grant. The
  // batch is recorded even when an unexpected error stops it: the entries
  // decided by then stay decided, and every other entry counts as skipped.
  "approvals.decide_many": { auth: ["account"], handler(ctx, principal, raw, invocation): ApprovalBatchResult {
    if (principal.kind !== "member") throw new VaultError("forbidden", "Only a person can decide an approval.")
    assertBatchesHere(ctx)
    const expected = batchAction(ctx, principal, invocation, parseDecisions(raw))
    verifiedStepUp(ctx, invocation, expected)
    const batch = randomId("apb")
    const results: ApprovalBatchResult["results"] = []
    const counts = () => {
      const approved = results.filter((r) => r.outcome === "approved").length, denied = results.filter((r) => r.outcome === "denied").length
      return { approved, denied, skipped: expected.entries.length - approved - denied }
    }
    try {
      for (const entry of expected.entries) results.push({ approval: entry.approval, ...decideEntry(ctx, principal, invocation, entry, batch) })
    } finally {
      ctx.audit({ actor: `member:${principal.memberId}`, action: "approval.batch", target: batch, detail: counts() })
    }
    return { batch, results, ...counts() }
  } },
}
