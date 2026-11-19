// The account-wide Needs you read. D1 names the
// account's workspaces and the live enrolment candidates aimed at them; each
// workspace's own vault then decides, from the caller's live standing, what
// this account may see and act on. Nothing here authorises a row: a
// candidate the workspace does not list never reaches the response.
//
// Bounds: at most INBOX_WORKSPACE_LIMIT workspaces are read, at most
// INBOX_CONCURRENCY vault calls are in flight (a timed-out call keeps its
// slot until it settles), every call gets min(INBOX_CALL_BUDGET_MS, what is
// left of INBOX_DEADLINE_MS) and an answer that loses its race is discarded.
// A workspace that could not be read is never reported as an empty one.

import { canonicalJson, type WorkspaceNotice } from "@mehen/protocol"
import type { InboxItem, InboxResponse, InboxWorkspace, WorkspaceInboxResponse } from "@mehen/protocol/inbox"
import type { AccountWebSession } from "./account-session.ts"
import { sha256Text } from "./session.ts"
import { enrolCandidateOf, type WorkspaceEnrolmentRow } from "./workspace-enrolment.ts"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { timed } from "../server-timing.ts"
import { workspaceCall, type RequestContext, type WorkspaceRequest } from "../routes/context.ts"
import type { WorkspaceVaultStub } from "../vault/core.ts"
import { compareInboxItems, INBOX_CANDIDATES_PER_WORKSPACE, type WorkspaceInboxAnswer } from "../vault/areas/pending-workspace.ts"
import type { InboxEnrolCandidate } from "../vault/areas/workspace-runtime.ts"

export const INBOX_WORKSPACE_LIMIT = 20
export const INBOX_CONCURRENCY = 6
export const INBOX_DEADLINE_MS = 4000
export const INBOX_CALL_BUDGET_MS = 2500

// Time as the fan-out sees it; tests replace it to place calls in the deadline.
export type InboxClock = { now(): number; after(ms: number): Promise<void> }
const SYSTEM_CLOCK: InboxClock = { now: () => Date.now(), after: (ms) => new Promise((resolve) => setTimeout(resolve, ms)) }
// group: one workspace's read of a single review group or bundle (the
// group's page), with no enrolment candidates.
export type InboxOptions = { sessionKind: "web" | "app"; clock?: InboxClock; stubFor?: (workspace: string) => WorkspaceVaultStub; group?: string }
// For the app adapter, which refuses rather than answer without a workspace:
// gateRefusal is the first identity_required a workspace answered with;
// unreadable the refusal for the first workspace that could not be read
// (its own error when it answered with one, else a retryable upstream_failed).
export type AccountInbox = { inbox: InboxResponse; gateRefusal: VaultError | null; unreadable: VaultError | null }

type WorkspaceRead = { summary: InboxWorkspace; items: InboxItem[]; notices: WorkspaceNotice[]; refusal: VaultError | null }
type CallOutcome = { kind: "answer"; answer: WorkspaceInboxAnswer } | { kind: "refused"; error: VaultError } | { kind: "failed" } | { kind: "timeout" } | { kind: "deadline" }
type CandidateSet = { candidates: InboxEnrolCandidate[]; truncated: boolean }
type CandidateRow = WorkspaceEnrolmentRow & { inbox_workspace: string; inbox_rank: number; claimed_name: string | null }

// Live, listable enrolments aimed at these workspaces by the same predicate
// the enrolment pages use, ranked per workspace by expiry, those an account
// claimed or accepted first, so unclaimed starts never crowd them out. One
// more than the cap is read so a cut workspace is marked truncated.
async function inboxCandidates(env: Env, workspaces: string[], now: number): Promise<Map<string, CandidateSet>> {
  const sets = new Map<string, CandidateSet>(workspaces.map((id) => [id, { candidates: [], truncated: false }]))
  if (!workspaces.length) return sets
  const rows = await env.DB.prepare(`SELECT r.*,a.name AS claimed_name FROM (
      SELECT e.*,w.id AS inbox_workspace,ROW_NUMBER() OVER (PARTITION BY w.id ORDER BY e.claimed_account IS NULL AND e.accepted_by_account IS NULL,e.expires_at,e.id) AS inbox_rank
      FROM enrolments e JOIN workspaces w ON (e.workspace_intent=w.slug OR EXISTS (SELECT 1 FROM workspace_slugs s WHERE s.workspace=w.id AND s.slug=e.workspace_intent)) AND (e.tenant IS NULL OR e.tenant=w.id)
      WHERE w.id IN (${workspaces.map(() => "?").join(",")}) AND w.status='active' AND e.status='pending' AND e.discard_pending=0 AND e.expires_at>? AND e.hidden_group IS NOT NULL
    ) r LEFT JOIN accounts a ON a.id=r.claimed_account WHERE r.inbox_rank<=? ORDER BY r.inbox_workspace,r.inbox_rank`)
    .bind(...workspaces, now, INBOX_CANDIDATES_PER_WORKSPACE + 1).all<CandidateRow>()
  for (const row of rows.results) {
    const set = sets.get(row.inbox_workspace)
    if (!set) continue
    if (row.inbox_rank > INBOX_CANDIDATES_PER_WORKSPACE) set.truncated = true
    else set.candidates.push(enrolCandidateOf(row, row.claimed_name, now))
  }
  return sets
}

// At most INBOX_CONCURRENCY holders. A waiter that gives up (the deadline
// passed first) is withdrawn: if its slot was already handed over, the slot
// passes straight on, so an expired waiter never starts a call.
type SlotRequest = { granted: Promise<void>; withdraw(): void }
function slots(limit: number): { acquire(): SlotRequest; release(): void } {
  let held = 0
  const waiting: { grant(): void; withdrawn: boolean }[] = []
  const release = () => {
    for (let next = waiting.shift(); next; next = waiting.shift()) if (!next.withdrawn) { next.grant(); return }
    held--
  }
  return {
    acquire: () => {
      if (held < limit) { held++; let given = true; return { granted: Promise.resolve(), withdraw: () => { if (given) { given = false; release() } } } }
      let granted = false
      const waiter = { grant: () => {}, withdrawn: false }
      const promise = new Promise<void>((resolve) => { waiter.grant = () => { granted = true; resolve() } })
      waiting.push(waiter)
      return { granted: promise, withdraw: () => { if (granted) { granted = false; release() } else waiter.withdrawn = true } }
    },
    release,
  }
}

function unavailable(target: WorkspaceRequest, reason: "limit" | "deadline" | "timeout" | "error", code?: string): WorkspaceRead {
  if (reason !== "limit") console.error(JSON.stringify({ at: "inbox.unavailable", workspace: target.workspace.id, reason, code: code ?? null }))
  return { summary: { workspace: target.workspace, role: null, state: "unavailable", reason, count: null, truncated: false }, items: [], notices: [], refusal: null }
}
function classify(target: WorkspaceRequest, outcome: CallOutcome, candidates: CandidateSet): WorkspaceRead {
  switch (outcome.kind) {
    case "answer": {
      const { viewer, items, notices, truncated } = outcome.answer
      return { summary: { workspace: target.workspace, role: viewer.role, state: "ok", reason: null, count: items.length, truncated: truncated || candidates.truncated }, items, notices, refusal: null }
    }
    case "refused":
      if (outcome.error.code === "unauthenticated") throw outcome.error
      if (outcome.error.code === "identity_required") return { summary: { workspace: target.workspace, role: null, state: "gated", reason: null, count: null, truncated: false }, items: [], notices: [], refusal: outcome.error }
      if (outcome.error.code === "owner_inactive" || outcome.error.code === "not_found") return { summary: { workspace: target.workspace, role: null, state: "inactive", reason: null, count: null, truncated: false }, items: [], notices: [], refusal: outcome.error }
      return { ...unavailable(target, "error", outcome.error.code), refusal: outcome.error }
    case "failed": return unavailable(target, "error")
    case "timeout": return unavailable(target, "timeout")
    case "deadline": return unavailable(target, "deadline")
  }
}

// One pending.inbox call per workspace under the concurrency, deadline and
// per-call budgets. A session that ended (unauthenticated) ends the read.
function readInboxes(rc: RequestContext, targets: WorkspaceRequest[], options: InboxOptions): Promise<WorkspaceRead[]> {
  return timed("inbox", () => readInboxesNow(rc, targets, options))
}
async function readInboxesNow(rc: RequestContext, targets: WorkspaceRequest[], options: InboxOptions): Promise<WorkspaceRead[]> {
  const clock = options.clock ?? SYSTEM_CLOCK
  const candidates = options.group === undefined ? await inboxCandidates(rc.env, targets.map((t) => t.workspace.id), clock.now()) : new Map<string, CandidateSet>()
  const pool = slots(INBOX_CONCURRENCY), deadline = clock.now() + INBOX_DEADLINE_MS
  // One shared timer ends every read still waiting for a slot at the deadline.
  const expired = clock.after(INBOX_DEADLINE_MS).then(() => "deadline" as const)
  const reads = targets.map(async (target): Promise<WorkspaceRead> => {
    const set = candidates.get(target.workspace.id) ?? { candidates: [], truncated: false }
    const slot = pool.acquire()
    if (await Promise.race([slot.granted.then(() => "slot" as const), expired]) === "deadline") { slot.withdraw(); return classify(target, { kind: "deadline" }, set) }
    const budget = Math.min(INBOX_CALL_BUDGET_MS, deadline - clock.now())
    if (budget <= 0) { slot.withdraw(); return classify(target, { kind: "deadline" }, set) }
    // The app's `pending` lists every ask item's ask, so its asks are never collapsed into group rows.
    const call: Promise<CallOutcome> = workspaceCall(rc, target, "pending.inbox", { enrolments: set.candidates, ...(options.group === undefined ? {} : { group: options.group }), ...(options.sessionKind === "app" ? { collapse: false } : {}) }, undefined, options.stubFor?.(target.workspace.id))
      .then((answer): CallOutcome => ({ kind: "answer", answer: answer as WorkspaceInboxAnswer }), (error: unknown): CallOutcome => error instanceof VaultError ? { kind: "refused", error } : { kind: "failed" })
    void call.then(() => slot.withdraw())
    const timeout = clock.after(budget).then((): CallOutcome => ({ kind: "timeout" }))
    return classify(target, await Promise.race([call, timeout]), set)
  })
  return Promise.all(reads)
}

function soonest(items: InboxItem[]): number | null {
  const times = items.flatMap((item) => item.expiresAt === null ? [] : [Date.parse(item.expiresAt)])
  return times.length ? Math.min(...times) : null
}
// Groups by their soonest expiry (a group with none last), then workspace
// name; inside a group the item order of compareInboxItems.
function mergedItems(reads: WorkspaceRead[]): InboxItem[] {
  const groups = reads.filter((read) => read.items.length).map((read) => ({ read, soonest: soonest(read.items) }))
  groups.sort((a, b) => {
    if (a.soonest !== b.soonest) return a.soonest === null ? 1 : b.soonest === null ? -1 : a.soonest - b.soonest
    const an = a.read.summary.workspace.name, bn = b.read.summary.workspace.name
    if (an !== bn) return an < bn ? -1 : 1
    return a.read.summary.workspace.id < b.read.summary.workspace.id ? -1 : 1
  })
  return groups.flatMap(({ read }) => [...read.items].sort(compareInboxItems))
}

function unreadableRefusal(reads: WorkspaceRead[]): VaultError | null {
  const read = reads.find((r) => r.summary.state === "unavailable")
  if (!read) return null
  return read.refusal ?? new VaultError("upstream_failed", `${read.summary.workspace.name} could not be read just now.`, { retryAfter: 5, next: { say: "Try again in a few seconds." } })
}
export async function accountInbox(rc: RequestContext, account: AccountWebSession, options: InboxOptions): Promise<AccountInbox> {
  const memberships = await rc.env.DB.prepare("SELECT w.id,w.slug,w.name,m.id AS membership FROM workspaces w JOIN memberships m ON m.workspace=w.id WHERE m.account=? AND m.state='member' AND w.status='active' ORDER BY w.name,w.id")
    .bind(account.account).all<{ id: string; slug: string; name: string; membership: string }>()
  const targets = memberships.results.map((row): WorkspaceRequest => ({ workspace: { id: row.id, slug: row.slug, name: row.name }, membership: row.membership, account, sessionKind: options.sessionKind }))
  const read = await readInboxes(rc, targets.slice(0, INBOX_WORKSPACE_LIMIT), options)
  const reads = [...read, ...targets.slice(INBOX_WORKSPACE_LIMIT).map((target) => unavailable(target, "limit"))]
  const workspaces = reads.map((r) => r.summary)
  return {
    inbox: {
      workspaces,
      items: mergedItems(reads),
      notices: reads.flatMap((r) => r.notices),
      count: workspaces.reduce((sum, w) => sum + (w.state === "ok" ? w.count ?? 0 : 0), 0),
      complete: workspaces.every((w) => w.state !== "gated" && w.state !== "unavailable" && !w.truncated),
    },
    gateRefusal: reads.find((r) => r.summary.state === "gated")?.refusal ?? null,
    unreadable: unreadableRefusal(reads),
  }
}

// GET /api/w/:ws/inbox: the same read for one workspace the caller belongs to.
// A group read the workspace answers not_found (batch approvals not on
// there) is not found, never an inactive workspace.
export async function workspaceInbox(rc: RequestContext, workspace: WorkspaceRequest, options: InboxOptions): Promise<WorkspaceInboxResponse> {
  const [read] = await readInboxes(rc, [{ ...workspace, sessionKind: options.sessionKind }], options)
  if (!read) throw new VaultError("internal", "The workspace inbox could not be read.")
  if (options.group !== undefined && read.refusal?.code === "not_found") throw read.refusal
  return { workspace: read.summary, items: read.items, notices: read.notices }
}

// A weak validator over content only: equal data gives an equal tag.
export async function inboxEtag(inbox: InboxResponse): Promise<string> {
  return `W/"${await sha256Text(canonicalJson({ workspaces: inbox.workspaces, items: inbox.items, notices: inbox.notices }))}"`
}
// If-None-Match against our tag, ignoring the weak prefix Cloudflare may add
// or strip.
export function etagMatches(header: string | null, etag: string): boolean {
  if (header === null) return false
  const bare = (tag: string) => tag.trim().replace(/^W\//, "")
  return header.split(",").some((tag) => tag.trim() === "*" || bare(tag) === bare(etag))
}
