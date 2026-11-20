// accountInbox over fake workspace vaults: the
// merge and its order, the workspace states, the limit, the candidate cut,
// the deadline and per-call budgets, discarded late answers, at most six
// calls in flight, and a validator that depends on content only.
import { createExecutionContext } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { describe, expect, it, vi } from "vitest"
import type { WorkspaceNotice, WorkspaceRef } from "@mehen/protocol"
import type { InboxItem } from "@mehen/protocol/inbox"
import { accountInbox, etagMatches, inboxEtag, workspaceInbox, type InboxClock } from "../src/directory/account-inbox.ts"
import type { AccountWebSession } from "../src/directory/account-session.ts"
import type { RequestContext } from "../src/routes/context.ts"
import type { InvocationResult, WorkspaceVaultStub } from "../src/vault/core.ts"
import type { WorkspaceInvocation } from "../src/vault/core.ts"
import { boundedInbox, compareInboxItems, INBOX_BYTES_PER_WORKSPACE, INBOX_ITEMS_PER_WORKSPACE, INBOX_UNCLAIMED_ENROLMENTS_PER_WORKSPACE, registerWorkspacePendingProvider, workspacePendingOps, type WorkspaceInboxAnswer } from "../src/vault/areas/pending-workspace.ts"
import type { InboxEnrolCandidate } from "../src/vault/areas/workspace-runtime.ts"
import type { VaultContext } from "../src/vault/core.ts"
import type { ApprovalAskBatch } from "../src/vault/areas/approvals-workspace.ts"
import { approvalGroupSection, workspaceApprovalBatchOps } from "../src/vault/areas/approvals-batch-workspace.ts"
import type { ApprovalGroupView } from "@mehen/protocol/workspace"
import { inboxRow, inboxRowOf } from "../src/ui/inbox-row.ts"
import { renderDocument } from "../src/ui/layout.ts"
import { workspaceReviewPage } from "../src/ui/pages/workspace-review.ts"
import { galleryShell } from "../src/ui/workspace-projects-gallery.ts"
import { PUSH_METHOD } from "../src/vault/areas/push-records.ts"
import type { ApprovalPresentation } from "../src/vault/services.ts"
import { prepareApprovedUse } from "../src/vault/areas/projects-workspace.ts"
import { digestOf } from "../src/vault/areas/approvals.ts"
import { workspaceRunOps } from "../src/vault/areas/runs-workspace.ts"
import { VaultError } from "../src/http.ts"
import { PROJECT_RUN_INPUT, accountAuth, inAccess, projectDeviceInvocation, projectFixture, projectState } from "./projects-workspace-fixture.ts"
import { accessMember } from "./workspace-fixtures.ts"
import { fixtureSql } from "./fixture-sql.ts"

type Seeded = { account: AccountWebSession; workspaces: (WorkspaceRef & { membership: string })[] }
// One account in `names.length` active workspaces, straight into D1.
async function seed(names: string[]): Promise<Seeded> {
  const tag = crypto.randomUUID().replaceAll("-", "").slice(0, 10), now = Date.now()
  const account: AccountWebSession = { account: `acc_${tag}`, name: "Alex", session: `ses_${tag}`, securityEpoch: 0, transition: null, restrictedUntil: null }
  const workspaces = names.map((name, i) => ({ id: `tn_${tag}${i}`, slug: `w${tag}x${i}`, name, membership: `mem_${tag}${i}` }))
  await env.DB.batch([
    env.DB.prepare("INSERT INTO accounts(id,name,created_at) VALUES (?,?,?)").bind(account.account, account.name, now),
    ...workspaces.flatMap((w) => [
      env.DB.prepare("INSERT INTO workspaces(id,slug,name,status,created_by,created_at) VALUES (?,?,?,'active',?,?)").bind(w.id, w.slug, w.name, account.account, now),
      env.DB.prepare("INSERT INTO memberships(id,account,workspace,state,role_hint,updated_at) VALUES (?,?,?,'member','owner',?)").bind(w.membership, account.account, w.id, now),
    ]),
  ])
  return { account, workspaces }
}
function context(): RequestContext {
  const url = new URL("https://vault.test/api/needs-you")
  return { request: new Request(url), env: { ...env }, ctx: createExecutionContext(), url, params: {} }
}
const ref = (w: WorkspaceRef): WorkspaceRef => ({ id: w.id, slug: w.slug, name: w.name })
function confirmItem(w: WorkspaceRef, member: string, expiresAt: string | null): InboxItem {
  return { kind: "confirm", workspace: ref(w), href: `/w/${w.slug}/people#confirm-${member}`, action: "confirm", createdAt: null, expiresAt, confirm: { member, name: member, role: "member", invite: `inv_${member}`, termsDigest: "digest", boundEmail: null, joinedAt: new Date(0).toISOString() } }
}
// An enrolment row as the inbox lists it: unclaimed and ownerless unless given.
function enrolItem(w: WorkspaceRef, enrolment: string, expiresAt: string, claimed: { account: string; name: string } | null = null): InboxItem {
  return { kind: "enrol", workspace: ref(w), href: `/w/${w.slug}/e/${enrolment}`, action: claimed ? "reject" : "accept", createdAt: new Date(0).toISOString(), expiresAt, enrol: { enrolment, name: enrolment, host: null, backend: "software", start: { at: new Date(0).toISOString(), place: null, clientLabel: "mehen 0.3.0" }, session: null, requestedOwner: { kind: "self" }, owner: null, claimed, state: "pending_owner_acceptance", fingerprint: { groups: [null, "AAAA", "BBBB", "CCCC"], words: [] }, actions: claimed ? ["reject"] : ["accept", "reject"], hardExpiresAt: new Date(Date.parse(expiresAt) + 86_400_000).toISOString() } }
}
const answer = (items: InboxItem[], notices: WorkspaceNotice[] = [], truncated = false): WorkspaceInboxAnswer => ({ viewer: { member: "mem_viewer", role: "owner" }, items, notices, truncated })
const ok = (value: WorkspaceInboxAnswer): InvocationResult => ({ ok: true, value })
const refused = (error: string): InvocationResult => ({ ok: false, error: { vaultError: { error: error as "forbidden", message: "Refused." }, status: 403 } })
type Deferred = { promise: Promise<InvocationResult>; resolve(value: InvocationResult): void }
function deferred(): Deferred { let resolve: (value: InvocationResult) => void = () => {}; const promise = new Promise<InvocationResult>((r) => { resolve = r }); return { promise, resolve } }
function stubs(answers: Record<string, (invocation: WorkspaceInvocation) => Promise<InvocationResult>>): { stubFor(id: string): WorkspaceVaultStub; calls: { workspace: string; invocation: WorkspaceInvocation }[] } {
  const calls: { workspace: string; invocation: WorkspaceInvocation }[] = []
  return { calls, stubFor: (id) => ({ invoke: (invocation) => { calls.push({ workspace: id, invocation }); const reply = answers[id]; if (!reply) throw new Error(`Unexpected call to ${id}`); return reply(invocation) } }) }
}
function manualClock(start = 10_000_000): { clock: InboxClock; set(now: number): void; timers: { ms: number; fire(): void }[] } {
  let now = start
  const timers: { ms: number; fire(): void }[] = []
  return { clock: { now: () => now, after: (ms) => new Promise<void>((resolve) => timers.push({ ms, fire: resolve })) }, set: (value) => { now = value }, timers }
}
const inMinutes = (minutes: number) => new Date(Date.now() + minutes * 60_000).toISOString()

describe("accountInbox merge, order and validator", () => {
  it("groups by the soonest expiry then name, counts ok rows and keeps one validator for equal data", async () => {
    const { account, workspaces: [alpha, beta, gamma] } = await seed(["Alpha", "Beta", "Gamma"])
    const alphaItems = [confirmItem(alpha!, "mem_a2", null), confirmItem(alpha!, "mem_a1", inMinutes(30))]
    let betaExpiry = inMinutes(10)
    const fake = stubs({ [alpha!.id]: async () => ok(answer(alphaItems)), [beta!.id]: async () => ok(answer([confirmItem(beta!, "mem_b1", betaExpiry)])), [gamma!.id]: async () => ok(answer([])) })
    const first = await accountInbox(context(), account, { sessionKind: "web", stubFor: fake.stubFor })
    expect(first.inbox.items.map((item) => item.kind === "confirm" && item.confirm.member)).toEqual(["mem_b1", "mem_a1", "mem_a2"])
    expect(first.inbox.workspaces).toEqual([alpha, beta, gamma].map((w) => ({ workspace: ref(w!), role: "owner", state: "ok", reason: null, count: w === alpha ? 2 : w === beta ? 1 : 0, truncated: false })))
    expect(first.inbox).toMatchObject({ count: 3, complete: true, notices: [] })
    expect(first.gateRefusal).toBeNull()
    // Every call is the account's own pending.inbox with this session.
    expect(fake.calls.map((c) => [c.invocation.op, c.invocation.auth])).toEqual([alpha, beta, gamma].map(() => ["pending.inbox", expect.objectContaining({ kind: "account", account: account.account, session: account.session, sessionCheck: null })]))
    const again = await accountInbox(context(), account, { sessionKind: "web", stubFor: fake.stubFor })
    const tag = await inboxEtag(first.inbox)
    expect(tag).toMatch(/^W\/"[A-Za-z0-9_-]{43}"$/)
    expect(await inboxEtag(again.inbox)).toBe(tag)
    betaExpiry = inMinutes(11)
    expect(await inboxEtag((await accountInbox(context(), account, { sessionKind: "web", stubFor: fake.stubFor })).inbox)).not.toBe(tag)
    expect(etagMatches(tag, tag)).toBe(true)
    expect(etagMatches(tag.slice(2), tag)).toBe(true)
    expect(etagMatches(`"other", ${tag.slice(2)}`, tag)).toBe(true)
    expect(etagMatches('"other"', tag)).toBe(false)
    expect(etagMatches(null, tag)).toBe(false)
  })
  it("carries every workspace's notice envelopes unchanged", async () => {
    const { account, workspaces: [alpha] } = await seed(["Alpha"])
    const notice: WorkspaceNotice = { id: "ntc_one", account: account.account, payload: { kind: "machine_added", workspace: ref(alpha!), device: "dev_one", name: "Laptop", owner: { kind: "member", member: "mem_viewer", name: "Alex" }, place: null, at: new Date(0).toISOString() }, at: 1, url: `https://vault.test/w/${alpha!.slug}/devices/dev_one` }
    const result = await accountInbox(context(), account, { sessionKind: "web", stubFor: stubs({ [alpha!.id]: async () => ok(answer([], [notice])) }).stubFor })
    expect(result.inbox.notices).toEqual([notice])
  })
})

describe("accountInbox workspace states", () => {
  it("never reports a refused, failed or unread workspace as empty", async () => {
    const seeded = await seed(["A gated", "B inactive", "C removed", "D failing", "E throwing", "F fine"])
    const [gated, inactive, removed, failing, throwing, fine] = seeded.workspaces
    const fake = stubs({
      [gated!.id]: async () => refused("identity_required"),
      [inactive!.id]: async () => refused("owner_inactive"),
      [removed!.id]: async () => refused("not_found"),
      [failing!.id]: async () => refused("upstream_failed"),
      [throwing!.id]: async () => { throw new Error("Workspace unreachable") },
      [fine!.id]: async () => ok(answer([confirmItem(fine!, "mem_f", null)])),
    })
    const { inbox, gateRefusal } = await accountInbox(context(), seeded.account, { sessionKind: "app", stubFor: fake.stubFor })
    const summary = (state: string, reason: string | null) => ({ role: null, state, reason, count: null, truncated: false })
    expect(inbox.workspaces.map(({ workspace: _w, ...rest }) => rest)).toEqual([summary("gated", null), summary("inactive", null), summary("inactive", null), summary("unavailable", "error"), summary("unavailable", "error"), { role: "owner", state: "ok", reason: null, count: 1, truncated: false }])
    expect(inbox).toMatchObject({ count: 1, complete: false })
    expect(inbox.items).toHaveLength(1)
    expect(gateRefusal?.code).toBe("identity_required")
    expect(fake.calls.every((c) => c.invocation.op === "pending.inbox")).toBe(true)
  })
  it("an ended session ends the whole read", async () => {
    const { account, workspaces: [alpha, beta] } = await seed(["Alpha", "Beta"])
    const fake = stubs({ [alpha!.id]: async () => ok(answer([confirmItem(alpha!, "mem_a", null)])), [beta!.id]: async () => refused("unauthenticated") })
    await expect(accountInbox(context(), account, { sessionKind: "web", stubFor: fake.stubFor })).rejects.toMatchObject({ code: "unauthenticated" })
  })
  it("reads twenty workspaces and reports the twenty-first as unavailable for the limit without calling it", async () => {
    const names = Array.from({ length: 21 }, (_, i) => `Workspace ${String(i).padStart(2, "0")}`)
    const seeded = await seed(names)
    const fake = stubs(Object.fromEntries(seeded.workspaces.slice(0, 20).map((w) => [w.id, async () => ok(answer([]))])))
    const { inbox } = await accountInbox(context(), seeded.account, { sessionKind: "web", stubFor: fake.stubFor })
    expect(fake.calls).toHaveLength(20)
    expect(inbox.workspaces[20]).toEqual({ workspace: ref(seeded.workspaces[20]!), role: null, state: "unavailable", reason: "limit", count: null, truncated: false })
    expect(inbox.complete).toBe(false)
  })
  it("the one-workspace read classifies exactly as the account read", async () => {
    const { account, workspaces: [alpha] } = await seed(["Alpha"])
    const read = await workspaceInbox(context(), { workspace: ref(alpha!), membership: alpha!.membership, account }, { sessionKind: "web", stubFor: stubs({ [alpha!.id]: async () => refused("identity_required") }).stubFor })
    expect(read).toEqual({ workspace: { workspace: ref(alpha!), role: null, state: "gated", reason: null, count: null, truncated: false }, items: [], notices: [] })
  })
})

describe("accountInbox bounds", () => {
  it("hands the workspace at most fifty live candidates and marks a fifty-first as truncated", async () => {
    const { account, workspaces: [alpha, beta] } = await seed(["Alpha", "Beta"])
    const now = Date.now(), rows = Array.from({ length: 51 }, (_, i) => i)
    await env.DB.batch([
      ...rows.map((i) => env.DB.prepare(`INSERT INTO enrolments(id,code_hash,jwk,thumbprint,name,backend,status,created_at,expires_at,workspace_intent,owner_intent,start_at,start_client_label,pending_state,hard_expires_at,hidden_group)
        VALUES (?,?,'{}',?,?,'software','pending',?,?,?,'{"kind":"self"}',?,'mehen 0.3.0','pending_owner_acceptance',?,1)`).bind(`enr_${alpha!.id}${i}`, `hash_${alpha!.id}${i}`, `thumb_${i}`, `machine-${i}`, now, now + 600_000 + i, alpha!.slug, now, now + 86_400_000)),
      // Not listable: lapsed, from before 0008, discarded, and aimed at another workspace.
      env.DB.prepare(`INSERT INTO enrolments(id,code_hash,jwk,thumbprint,name,backend,status,created_at,expires_at,workspace_intent,owner_intent,start_at,start_client_label,pending_state,hard_expires_at,hidden_group) VALUES ('enr_${beta!.id}lapsed','h_${beta!.id}1','{}','t','lapsed','software','pending',?,?,?,'{"kind":"self"}',?,'x','pending_owner_acceptance',?,1)`).bind(now, now - 1, beta!.slug, now, now + 86_400_000),
      env.DB.prepare(`INSERT INTO enrolments(id,code_hash,jwk,thumbprint,name,backend,status,created_at,expires_at,workspace_intent,owner_intent,start_at,start_client_label,pending_state,hard_expires_at,hidden_group) VALUES ('enr_${beta!.id}legacy','h_${beta!.id}2','{}','t','legacy','software','pending',?,?,?,'{"kind":"self"}',?,'x','pending_owner_acceptance',?,NULL)`).bind(now, now + 600_000, beta!.slug, now, now + 600_000),
      env.DB.prepare(`INSERT INTO enrolments(id,code_hash,jwk,thumbprint,name,backend,status,created_at,expires_at,workspace_intent,owner_intent,start_at,start_client_label,pending_state,hard_expires_at,hidden_group,discard_pending,discard_device) VALUES ('enr_${beta!.id}discarded','h_${beta!.id}3','{}','t','discarded','software','pending',?,?,?,'{"kind":"self"}',?,'x','pending_owner_acceptance',?,1,1,'dev_x')`).bind(now, now + 600_000, beta!.slug, now, now + 86_400_000),
      env.DB.prepare(`INSERT INTO enrolments(id,code_hash,jwk,thumbprint,name,backend,status,created_at,expires_at,workspace_intent,owner_intent,start_at,start_client_label,pending_state,hard_expires_at,hidden_group) VALUES ('enr_${beta!.id}elsewhere','h_${beta!.id}4','{}','t','elsewhere','software','pending',?,?,'some-other-workspace','{"kind":"self"}',?,'x','pending_owner_acceptance',?,1)`).bind(now, now + 600_000, now, now + 86_400_000),
    ])
    const sent: Record<string, InboxEnrolCandidate[]> = {}
    const reply = (id: string) => async (invocation: WorkspaceInvocation) => { sent[id] = (invocation.input as { enrolments: InboxEnrolCandidate[] }).enrolments; return ok(answer([])) }
    const { inbox } = await accountInbox(context(), account, { sessionKind: "web", stubFor: stubs({ [alpha!.id]: reply(alpha!.id), [beta!.id]: reply(beta!.id) }).stubFor })
    expect(sent[alpha!.id]).toHaveLength(50)
    expect(sent[alpha!.id]!.map((c) => c.name)).toEqual(rows.slice(0, 50).map((i) => `machine-${i}`))
    expect(sent[alpha!.id]![0]).toEqual({ enrolment: `enr_${alpha!.id}0`, thumbprint: "thumb_0", name: "machine-0", host: null, backend: "software", start: { at: new Date(now).toISOString(), place: null, clientLabel: "mehen 0.3.0" }, session: null, requestedOwner: { kind: "self" }, claimedAccount: null, claimedName: null, status: "pending", pendingState: "pending_owner_acceptance", lease: "live", acceptedByAccount: null, expiresAt: new Date(now + 600_000).toISOString(), hardExpiresAt: new Date(now + 86_400_000).toISOString(), hiddenGroup: 1 })
    expect(sent[beta!.id]).toEqual([])
    expect(inbox.workspaces.map((w) => [w.state, w.truncated])).toEqual([["ok", true], ["ok", false]])
    expect(inbox.complete).toBe(false)
  })
  it("cuts twenty-six items to twenty-five, keeps the ten newest notices and stays inside 64 KiB with whole rows", () => {
    const workspace = { id: "tn_bound", slug: "bound", name: "Bound" }
    const items = Array.from({ length: 26 }, (_, i) => confirmItem(workspace, `mem_${String(i).padStart(2, "0")}`, null))
    const notices = Array.from({ length: 12 }, (_, i): WorkspaceNotice => ({ id: `ntc_${String(i).padStart(2, "0")}`, account: "acc_x", payload: { kind: "deletion_scheduled", workspace, by: "mem_x", at: new Date(0).toISOString(), deleteAfter: new Date(0).toISOString() }, at: i, url: "https://vault.test/w/bound/" }))
    const counted = boundedInbox({ member: "mem_v", role: "owner" }, items, notices, false)
    expect(counted.items).toEqual(items.slice(0, 25))
    expect(counted.notices.map((n) => n.id)).toEqual(notices.slice(2).map((n) => n.id))
    expect(counted.truncated).toBe(true)
    expect(boundedInbox({ member: "mem_v", role: "owner" }, items.slice(0, 3), [], false).truncated).toBe(false)
    const large = items.map((item) => item.kind === "confirm" ? { ...item, confirm: { ...item.confirm, name: "x".repeat(9_000) } } : item)
    const sized = boundedInbox({ member: "mem_v", role: "owner" }, large, notices, false)
    expect(sized.items).toEqual(large.slice(0, sized.items.length))
    expect(sized.items.length).toBe(7)
    expect(sized.notices).toEqual([])
    expect(new TextEncoder().encode(JSON.stringify(sized)).byteLength).toBeLessThanOrEqual(INBOX_BYTES_PER_WORKSPACE)
    expect(sized.truncated).toBe(true)
  })
  it("fills the budget with genuine items before unclaimed public enrolments, which take at most their share, and says truncated whenever either is cut", () => {
    const workspace = { id: "tn_fair", slug: "fair", name: "Fair" }
    const viewer = { member: "mem_v", role: "owner" as const }
    const minute = (n: number) => new Date(Date.UTC(2030, 0, 1, 0, n)).toISOString()
    // Unclaimed starts all run out before anything genuine does.
    const unclaimed = Array.from({ length: 25 }, (_, i) => enrolItem(workspace, `enr_u${String(i).padStart(2, "0")}`, minute(i)))
    const claimed = enrolItem(workspace, "enr_claimed", minute(50), { account: "acc_mia", name: "Mia" })
    const ask = confirmItem(workspace, "mem_fresh", minute(60))
    const flooded = boundedInbox(viewer, [...unclaimed, claimed, ask].sort(compareInboxItems), [], false)
    expect(INBOX_UNCLAIMED_ENROLMENTS_PER_WORKSPACE).toBe(5)
    expect(flooded.items).toEqual([...unclaimed.slice(0, INBOX_UNCLAIMED_ENROLMENTS_PER_WORKSPACE), claimed, ask])
    expect(flooded.truncated).toBe(true)
    // Genuine items near the budget leave the unclaimed only what is left.
    const genuine = Array.from({ length: 22 }, (_, i) => confirmItem(workspace, `mem_g${String(i).padStart(2, "0")}`, minute(100 + i)))
    const near = boundedInbox(viewer, [...unclaimed, ...genuine].sort(compareInboxItems), [], false)
    expect(near.items).toEqual([...unclaimed.slice(0, 3), ...genuine])
    expect(near.truncated).toBe(true)
    const full = Array.from({ length: INBOX_ITEMS_PER_WORKSPACE }, (_, i) => confirmItem(workspace, `mem_f${String(i).padStart(2, "0")}`, minute(100 + i)))
    const crowded = boundedInbox(viewer, [...unclaimed.slice(0, 2), ...full].sort(compareInboxItems), [], false)
    expect(crowded.items).toEqual(full)
    expect(crowded.truncated).toBe(true)
    // Alone, the unclaimed still take only their share; within it nothing is cut.
    const alone = boundedInbox(viewer, unclaimed.slice(0, 6), [], false)
    expect(alone.items).toEqual(unclaimed.slice(0, 5))
    expect(alone.truncated).toBe(true)
    expect(boundedInbox(viewer, unclaimed.slice(0, 5), [], false)).toEqual({ viewer, items: unclaimed.slice(0, 5), notices: [], truncated: false })
    // The byte bound spends itself on genuine items first.
    const heavy = genuine.slice(0, 8).map((item) => item.kind === "confirm" ? { ...item, confirm: { ...item.confirm, name: "x".repeat(9_000) } } : item)
    const sized = boundedInbox(viewer, [...unclaimed, ...heavy].sort(compareInboxItems), [], false)
    expect(sized.items).toEqual(heavy.slice(0, 7))
    expect(sized.truncated).toBe(true)
  })
  it("hands the workspace claimed and accepted candidates before any unclaimed start, however soon the unclaimed run out", async () => {
    const { account, workspaces: [alpha] } = await seed(["Alpha"])
    const now = Date.now(), rows = Array.from({ length: 50 }, (_, i) => i)
    const insert = `INSERT INTO enrolments(id,code_hash,jwk,thumbprint,name,backend,status,created_at,expires_at,workspace_intent,owner_intent,start_at,start_client_label,pending_state,hard_expires_at,hidden_group,claimed_account,acceptance_digest,accepted_by_account,accepted_by_member,accepted_at)
      VALUES (?,?,'{}',?,?,'software','pending',?,?,?,'{"kind":"self"}',?,'mehen 0.3.0',?,?,1,?,?,?,?,?)`
    await env.DB.batch([
      ...rows.map((i) => env.DB.prepare(insert).bind(`enr_${alpha!.id}u${i}`, `hash_${alpha!.id}u${i}`, `thumb_u${i}`, `unclaimed-${i}`, now, now + 60_000 + i, alpha!.slug, now, "pending_owner_acceptance", now + 86_400_000, null, null, null, null, null)),
      env.DB.prepare(insert).bind(`enr_${alpha!.id}claimed`, `hash_${alpha!.id}claimed`, "thumb_c", "claimed", now, now + 3_000_000, alpha!.slug, now, "pending_owner_acceptance", now + 86_400_000, account.account, null, null, null, null),
      env.DB.prepare(insert).bind(`enr_${alpha!.id}accepted`, `hash_${alpha!.id}accepted`, "thumb_a", "accepted", now, now + 3_000_001, alpha!.slug, now, "pending_admission", now + 86_400_000, null, "digest", account.account, alpha!.membership, now),
    ])
    let sent: InboxEnrolCandidate[] = []
    const { inbox } = await accountInbox(context(), account, { sessionKind: "web", stubFor: stubs({ [alpha!.id]: async (invocation) => { sent = (invocation.input as { enrolments: InboxEnrolCandidate[] }).enrolments; return ok(answer([])) } }).stubFor })
    expect(sent.map((c) => c.name)).toEqual(["claimed", "accepted", ...rows.slice(0, 48).map((i) => `unclaimed-${i}`)])
    expect(inbox.workspaces.map((w) => w.truncated)).toEqual([true])
  })
  it("gives a call started 3.9 s in a 100 ms budget, discards its late answer and keeps a timed-out call's slot until it settles", async () => {
    const seeded = await seed(Array.from({ length: 8 }, (_, i) => `Workspace ${i}`))
    const time = manualClock(), start = 10_000_000
    const pending = seeded.workspaces.map(() => deferred())
    let inFlight = 0, most = 0
    const fake = stubs(Object.fromEntries(seeded.workspaces.map((w, i) => [w.id, async () => { inFlight++; most = Math.max(most, inFlight); try { return await pending[i]!.promise } finally { inFlight-- } }])))
    const read = accountInbox(context(), seeded.account, { sessionKind: "web", clock: time.clock, stubFor: fake.stubFor })
    // The first timer is the shared deadline; then one budget per started call.
    await vi.waitFor(() => expect(time.timers).toHaveLength(7))
    expect(time.timers.map((t) => t.ms)).toEqual([4000, 2500, 2500, 2500, 2500, 2500, 2500])
    expect(fake.calls).toHaveLength(6)
    // Six calls time out; none settles, so no seventh call starts.
    for (const timer of time.timers.slice(1)) timer.fire()
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(fake.calls).toHaveLength(6)
    // The first late answer frees one slot at 3.9 s: the seventh call gets what is left of the deadline.
    time.set(start + 3900)
    pending[0]!.resolve(ok(answer([confirmItem(seeded.workspaces[0]!, "mem_late", null)])))
    await vi.waitFor(() => expect(time.timers).toHaveLength(8))
    expect(time.timers[7]!.ms).toBe(100)
    time.timers[7]!.fire()
    // The next slot frees after the deadline: the eighth workspace is never called.
    time.set(start + 4000)
    pending[1]!.resolve(ok(answer([])))
    const { inbox } = await read
    expect(fake.calls).toHaveLength(7)
    expect(most).toBe(6)
    expect(inbox.workspaces.map((w) => w.reason)).toEqual(["timeout", "timeout", "timeout", "timeout", "timeout", "timeout", "timeout", "deadline"])
    expect(inbox.items).toEqual([])
    expect(inbox).toMatchObject({ count: 0, complete: false })
    for (const later of pending) later.resolve(ok(answer([])))
  })
  it.each([7, 20])("six calls that never settle cannot hold %i workspaces past the deadline; queued ones are never started", async (workspaces) => {
    const seeded = await seed(Array.from({ length: workspaces }, (_, i) => `Workspace ${String(i).padStart(2, "0")}`))
    const time = manualClock(), start = 10_000_000
    const pending = seeded.workspaces.map(() => deferred())
    const fake = stubs(Object.fromEntries(seeded.workspaces.map((w, i) => [w.id, () => pending[i]!.promise])))
    let settled = false
    const read = accountInbox(context(), seeded.account, { sessionKind: "web", clock: time.clock, stubFor: fake.stubFor }).then((result) => { settled = true; return result })
    await vi.waitFor(() => expect(time.timers).toHaveLength(7))
    const [deadline, ...budgets] = time.timers
    time.set(start + 2500)
    for (const timer of budgets) timer.fire()
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(settled).toBe(false)
    // No stub settles: the shared deadline alone ends the read.
    time.set(start + 4000)
    deadline!.fire()
    const { inbox } = await read
    expect(fake.calls).toHaveLength(6)
    expect(inbox.workspaces.map((w) => [w.state, w.reason])).toEqual(seeded.workspaces.map((_, i) => ["unavailable", i < 6 ? "timeout" : "deadline"]))
    expect(inbox).toMatchObject({ items: [], notices: [], count: 0, complete: false })
    const before = structuredClone(inbox)
    // Late answers free every slot; no expired waiter starts a call and nothing is merged.
    for (const [i, later] of pending.entries()) later.resolve(ok(answer([confirmItem(seeded.workspaces[i]!, "mem_late", null)])))
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(fake.calls).toHaveLength(6)
    expect(inbox).toEqual(before)
  })
})

// Batch approvals (APPROVAL_BATCHES, on in the test env): two or more open
// asks of one review group that the viewer may decide are one group row,
// linked to Review together, counted once against the per-workspace cap.
describe("grouped asks in the inbox", () => {
  const WORK = { id: "", slug: "work", name: "Work" }
  const switchedOff = (ctx: VaultContext): VaultContext => Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, APPROVAL_BATCHES: "off" } })
  const inboxAs = (ctx: VaultContext, role = "owner"): WorkspaceInboxAnswer => workspacePendingOps["pending.inbox"]!.handler(ctx, accessMember(projectState(ctx), role), { enrolments: [] }, { auth: accountAuth(role), workspace: { ...WORK, id: ctx.tenant } }) as WorkspaceInboxAnswer
  const SUBJECT = { method: "POST", url: "https://api.example.com/v1/things", contentType: null, contentEncoding: null, headersSha256: digestOf([]), constraints: { uses: 1, ttlSeconds: 600 } }
  // One open ask from `device` on the credential homed at `home` ("kim": Kim's private one).
  function ask(ctx: VaultContext, body: string, options: { device?: string; home?: "project" | "workspace" | "kim"; batch?: Partial<ApprovalAskBatch>; presentation?: Partial<ApprovalPresentation>; method?: string } = {}): string {
    const state = projectState(ctx), home = options.home ?? "workspace", slug = `key-${home}`
    const item = state.credentials.find((c) => home === "kim" ? c.home.kind === "member" && c.home.member === "mem_kim" : c.home.kind === home)!
    const caller = { principal: { kind: "device" as const, deviceId: options.device ?? "dev_kim" }, workspace: { ...WORK, id: ctx.tenant }, presentation: { title: `Ask ${body}`, details: [], body: null, ...options.presentation }, batch: { floor: [], shape: `shape-${body}`, replaces: null, ...options.batch } }
    return prepareApprovedUse(ctx, state, caller, { ...item, slug, version: 1 }, home === "project" ? { project: "prj_a", env: "prod" } : null, { ...SUBJECT, item: slug, bodySha256: digestOf(body), ...(options.method !== undefined ? { method: options.method } : {}) }, null, ctx.now()).approvalId
  }
  const groupOf = (ctx: VaultContext, id: string) => ctx.sql.exec<{ review_group: string }>("SELECT review_group FROM approvals WHERE id=?", id).toArray()[0]!.review_group
  const groups = (answer: WorkspaceInboxAnswer) => answer.items.filter((item): item is Extract<InboxItem, { kind: "group" }> => item.kind === "group")
  const askIds = (answer: WorkspaceInboxAnswer) => answer.items.flatMap((item) => item.kind === "ask" && item.ask.view === "detail" ? [item.ask.detail.id] : [])
  const drawnGroup = (ctx: VaultContext, answer: WorkspaceInboxAnswer, role: string) => inboxRow(inboxRowOf(groups(answer)[0]!, { workspace: { ...WORK, id: ctx.tenant }, role: role === "owner" ? "owner" : "member", state: "ok", reason: null, count: 1, truncated: false }), { now: ctx.now(), showWorkspace: false }).value
  // The heading Review together draws for the group, as `role` sees it.
  const reviewTitle = (ctx: VaultContext, role: string, group: string) => {
    const view = workspaceApprovalBatchOps["approvals.group"]!.handler(ctx, accessMember(projectState(ctx), role), { id: group }, { auth: accountAuth(role), workspace: { ...WORK, id: ctx.tenant } }) as ApprovalGroupView
    const page = renderDocument(workspaceReviewPage(galleryShell({ role: "member", member: `mem_${role}` }), { viewer: { role: "member", member: `mem_${role}` }, group, view, now: ctx.now() })).value
    return page.slice(page.indexOf("<h1>"), page.indexOf("</h1>"))
  }

  it("collapses two or more asks of one review group into one row with the count, the Review together link, the oldest ask's time and the soonest expiry, so its ring never overstates the time left", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      const plain = ask(ctx, "plain"), send = ask(ctx, "send", { batch: { floor: ["send"] } }), warned = ask(ctx, "warned", { presentation: { warnings: ["This request carries hidden text."] } }), unknown = ask(ctx, "unknown", { batch: { floor: null } })
      const times = [[plain, 1_000, 3_601_000], [send, 4_000, 3_604_000], [warned, 2_000, 3_602_000], [unknown, 3_000, 3_603_000]] as const
      const base = ctx.now()
      for (const [id, created, expires] of times) ctx.sql.exec("UPDATE approvals SET created_at=?,expires_at=? WHERE id=?", base + created, base + expires, id)
      // Kim may approve her machine's asks.
      const owner = inboxAs(ctx, "kim")
      const group = groupOf(ctx, plain)
      expect(askIds(owner)).toEqual([])
      const name = ctx.sql.exec<{ device_name: string }>("SELECT device_name FROM approvals WHERE id=?", plain).toArray()[0]!.device_name
      expect(groups(owner)).toEqual([{ kind: "group", workspace: { ...WORK, id: ctx.tenant }, href: `/w/work/g/${group}`, action: "review", createdAt: new Date(base + 1_000).toISOString(), expiresAt: new Date(base + 3_601_000).toISOString(), group: { group, kind: "machine", machine: { device: "dev_kim", name, workload: null }, owner: expect.objectContaining({ kind: expect.any(String) }), item: { slug: "key-workspace" }, count: 4, floor: 2, ownPage: 1, denyOnly: 0, reason: null } }])
      // The countdown ring's total is expiresAt minus createdAt: the oldest ask's full hour.
      const [row] = groups(owner)
      expect(Date.parse(row!.expiresAt!) - Date.parse(row!.createdAt!)).toBe(3_600_000)
    })
  })

  it("keeps a single ask a single row", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      const only = ask(ctx, "only")
      const owner = inboxAs(ctx)
      expect(groups(owner)).toEqual([])
      expect(askIds(owner)).toEqual([only])
    })
  })

  it("counts runs and four-eyes asks as deciding on their own page, never also as needing a closer look", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      const invocation = await projectDeviceInvocation(ctx)
      for (const command of ["first", "second"]) {
        await expect(workspaceRunOps["runs.create"]!.handler(ctx, { kind: "device", deviceId: "dev_kim" }, { ...PROJECT_RUN_INPUT, command, argv: [command] }, invocation)).rejects.toBeInstanceOf(VaultError)
      }
      // prj_a prod needs a second person.
      ask(ctx, "four-eyes-1", { home: "project", batch: { floor: ["send"] } }); ask(ctx, "four-eyes-2", { home: "project" })
      expect(groups(inboxAs(ctx)).map((row) => [row.group.count, row.group.floor, row.group.ownPage, row.group.item?.slug ?? null]).sort()).toEqual([[2, 0, 2, null], [2, 0, 2, "key-project"]])
    })
  })

  it("keeps the raiser's own four-eyes asks, which they may only deny, single rows while an approver sees them grouped", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      // prj_a prod needs a second person; dev_kim is Kim's.
      const asked = [ask(ctx, "four-eyes-1", { home: "project" }), ask(ctx, "four-eyes-2", { home: "project" })].sort()
      const raiser = inboxAs(ctx, "kim")
      expect(groups(raiser)).toEqual([])
      expect(askIds(raiser).sort()).toEqual(asked)
      expect(groups(inboxAs(ctx)).map((row) => row.group.count)).toEqual([2])
    })
  })

  it("keeps the raiser's four-eyes ask a row of its own in a mixed group, counts it under own page as the page lists it, and leaves it out of the group's soonest expiry", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      const plain = [ask(ctx, "plain-1"), ask(ctx, "plain-2")], fourEyes = ask(ctx, "four-eyes", { home: "project" })
      // One review group holding both kinds; the four-eyes ask expires first.
      const now = ctx.now()
      for (const [id, expiresAt] of [[plain[0]!, now + 3_000_000], [plain[1]!, now + 2_000_000], [fourEyes, now + 1_000_000]] as const) ctx.sql.exec("UPDATE approvals SET review_group='grp_mixed', expires_at=? WHERE id=?", expiresAt, id)
      const raiser = inboxAs(ctx, "kim")
      expect(groups(raiser).map((row) => [row.group.count, row.group.floor, row.group.ownPage, row.group.denyOnly, row.expiresAt])).toEqual([[3, 0, 1, 0, new Date(now + 2_000_000).toISOString()]])
      expect(askIds(raiser)).toEqual([fourEyes])
      expect(drawnGroup(ctx, raiser, "kim")).not.toContain("All routine.")
      expect(reviewTitle(ctx, "kim", "grp_mixed")).toContain("3 asks")
      expect(groups(inboxAs(ctx)).map((row) => [row.group.count, row.expiresAt])).toEqual([[3, new Date(now + 1_000_000).toISOString()]])
    })
  })

  it("counts a stop row of the group's under the section the page lists it in, so the group row is never called routine", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      // The owner may approve their own machine's asks, and may stop one on Kim's private credential but not read it.
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_kim'")
      const plain = [ask(ctx, "plain-1", { device: "dev_owner" }), ask(ctx, "plain-2", { device: "dev_owner" })], hidden = ask(ctx, "hidden", { home: "kim" })
      for (const id of [...plain, hidden]) ctx.sql.exec("UPDATE approvals SET review_group='grp_mixed' WHERE id=?", id)
      const owner = inboxAs(ctx)
      expect(owner.items.filter((item) => item.kind === "ask").map((item) => item.kind === "ask" && item.ask.view === "stop" ? item.ask.stop.id : null)).toEqual([hidden])
      expect(groups(owner).map((row) => [row.group.count, row.group.floor, row.group.ownPage, row.group.denyOnly])).toEqual([[3, 0, 0, 1]])
      const drawn = drawnGroup(ctx, owner, "owner")
      expect(drawn).toContain("1 can only be denied.")
      expect(drawn).not.toContain("All routine.")
      expect(reviewTitle(ctx, "owner", "grp_mixed")).toContain("3 asks")
    })
  })

  it("counts only the part of a group the viewer lists: a run ask gone stale is not counted", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      const invocation = await projectDeviceInvocation(ctx)
      const run = (command: string) => expect(workspaceRunOps["runs.create"]!.handler(ctx, { kind: "device", deviceId: "dev_kim" }, { ...PROJECT_RUN_INPUT, command, argv: [command] }, invocation)).rejects.toBeInstanceOf(VaultError)
      await run("first")
      fixtureSql(ctx).exec("UPDATE items SET config_rev=config_rev+1")
      await run("second"); await run("third")
      expect(ctx.sql.exec<{ n: number }>("SELECT count(DISTINCT review_group) AS n FROM approvals").one().n).toBe(1)
      expect(groups(inboxAs(ctx)).map((row) => row.group.count)).toEqual([2])
    })
  })

  it("never groups stop rows: asks on a private credential reach the owner as single stop rows", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_kim'")
      ask(ctx, "private-1", { home: "kim" }); ask(ctx, "private-2", { home: "kim" })
      const owner = inboxAs(ctx)
      expect(groups(owner)).toEqual([])
      expect(owner.items.map((item) => item.kind === "ask" ? item.ask.view : item.kind)).toEqual(["stop", "stop"])
      expect(groups(inboxAs(ctx, "kim")).map((row) => row.group.count)).toEqual([2])
    })
  })

  it("counts a group once against the per-workspace cap, and with the switch off lists every ask as today", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      for (let i = 0; i < 20; i++) ask(ctx, `kim-${i}`)
      for (let i = 0; i < 10; i++) ask(ctx, `member-${i}`, { device: "dev_member", home: "workspace" })
      const owner = inboxAs(ctx)
      expect(groups(owner).map((row) => row.group.count).sort()).toEqual([10, 20])
      expect(owner.items).toHaveLength(2)
      expect(owner.truncated).toBe(false)
      const off = inboxAs(switchedOff(ctx))
      expect(groups(off)).toEqual([])
      expect(off.items).toHaveLength(INBOX_ITEMS_PER_WORKSPACE)
      expect(off.truncated).toBe(true)
    })
  })

  it("leaves superseded and bundled asks out of a group", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      const first = ask(ctx, "first", { batch: { shape: "same-place" } })
      const second = ask(ctx, "second", { batch: { shape: "same-place", replaces: first } })
      const other = ask(ctx, "other")
      const bundled = ask(ctx, "bundled")
      ctx.sql.exec("UPDATE approvals SET bundle='bnd_test' WHERE id=?", bundled)
      const owner = inboxAs(ctx)
      expect(groups(owner).map((row) => row.group.count)).toEqual([2])
      expect(askIds(owner)).toEqual([bundled])
      expect(JSON.stringify(owner)).not.toContain(first)
      expect(second).not.toBe(first)
    })
  })

  it("counts each ask of a group row in the section Review together lists it under for the same viewer: a warning found in its text decides on its own page", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      const plain = ask(ctx, "plain")
      ask(ctx, "send", { batch: { floor: ["send"] } })
      // No stored warning: only the text scan the ask's own page runs finds it.
      ask(ctx, "bell", { presentation: { title: "Ask bell\u0007" } })
      ask(ctx, "plain-2")
      // Kim may approve her machine's asks; the owner, not an eligible approver, may only deny them.
      const sections = (role: string) => {
        const view = workspaceApprovalBatchOps["approvals.group"]!.handler(ctx, accessMember(projectState(ctx), role), { id: groupOf(ctx, plain) }, { auth: accountAuth(role), workspace: { ...WORK, id: ctx.tenant } }) as ApprovalGroupView
        const placed = (section: string) => view.rows.filter((r) => approvalGroupSection(r) === section).length
        return { count: view.rows.length, floor: placed("floor"), ownPage: placed("own-page"), denyOnly: placed("deny-only"), routine: placed("routine") }
      }
      const counts = (role: string) => { const [row] = groups(inboxAs(ctx, role)); return { count: row!.group.count, floor: row!.group.floor, ownPage: row!.group.ownPage, denyOnly: row!.group.denyOnly, routine: row!.group.count - row!.group.floor - row!.group.ownPage - row!.group.denyOnly! } }
      expect(sections("kim")).toEqual({ count: 4, floor: 1, ownPage: 1, denyOnly: 0, routine: 2 })
      expect(counts("kim")).toEqual(sections("kim"))
      expect(sections("owner")).toEqual({ count: 4, floor: 0, ownPage: 1, denyOnly: 3, routine: 0 })
      expect(counts("owner")).toEqual(sections("owner"))
      const drawn = inboxRow(inboxRowOf(groups(inboxAs(ctx))[0]!, { workspace: { ...WORK, id: ctx.tenant }, role: "owner", state: "ok", reason: null, count: 1, truncated: false }), { now: ctx.now(), showWorkspace: false }).value
      expect(drawn).toContain("1 decides on its own page. 3 can only be denied.")
      expect(drawn).not.toContain("All routine.")
    })
  })

  it("lists a push under Decide on its own page, never ticked, and the group row counts it there, whatever the classifier named", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      const plain = ask(ctx, "plain")
      ask(ctx, "plain-2")
      const pushed = ask(ctx, "pushed", { method: PUSH_METHOD })
      const view = workspaceApprovalBatchOps["approvals.group"]!.handler(ctx, accessMember(projectState(ctx), "kim"), { id: groupOf(ctx, plain) }, { auth: accountAuth("kim"), workspace: { ...WORK, id: ctx.tenant } }) as ApprovalGroupView
      const push = view.rows.find((r) => r.view === "detail" && r.approval.approval === pushed)!
      expect(approvalGroupSection(push)).toBe("own-page")
      const [row] = groups(inboxAs(ctx, "kim"))
      expect(row!.group).toMatchObject({ count: 3, floor: 0, ownPage: 1, denyOnly: 0 })
      const page = renderDocument(workspaceReviewPage(galleryShell({ role: "member", member: "mem_kim" }), { viewer: { role: "member", member: "mem_kim" }, group: view.group, view, now: ctx.now() })).value
      const drawn = page.slice(page.indexOf(`data-approval="${pushed}"`), page.indexOf("</li>", page.indexOf(`data-approval="${pushed}"`)))
      expect(page).toContain(`data-approval="${pushed}" data-section="own-page"`)
      expect(drawn).not.toContain('data-input="pick"')
      expect(drawn).toContain("Decide it on its own page")
      expect(page).toContain("Approve 2 with passkey")
    })
  })

  it("collapses two or more asks of one bundle into one bundle row with the agent's reason, linked to its own review page", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      const bundled = [ask(ctx, "bundled-1"), ask(ctx, "bundled-2", { batch: { floor: ["destructive"] } })]
      const alone = ask(ctx, "alone"), single = ask(ctx, "single")
      ctx.sql.exec("INSERT INTO approval_bundles(id,device,workload,reason,created_at,expires_at) VALUES ('bnd_contoso','dev_kim',NULL,'Set up Contoso',?,?)", ctx.now(), ctx.now() + 3_600_000)
      for (const id of bundled) ctx.sql.exec("UPDATE approvals SET bundle='bnd_contoso' WHERE id=?", id)
      ctx.sql.exec("UPDATE approvals SET bundle='bnd_single' WHERE id=?", single)
      const owner = inboxAs(ctx, "kim")
      const bundle = groups(owner).find((row) => row.group.kind === "bundle")
      expect(bundle).toMatchObject({ href: "/w/work/g/bnd_contoso", action: "review", group: { group: "bnd_contoso", kind: "bundle", machine: { device: "dev_kim" }, item: null, count: 2, floor: 1, ownPage: 0, denyOnly: 0, reason: "Set up Contoso" } })
      // The bundle's asks never join the machine's review group, and one bundled ask stays a row of its own.
      expect(groups(owner).map((row) => [row.group.kind, row.group.count])).toEqual([["bundle", 2]])
      expect(askIds(owner).sort()).toEqual([alone, single].sort())
    })
  })

  it("lists a bundled ask on its bundle's page only, never also on its machine's review group page, whose count matches its Needs you row", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      const plain = [ask(ctx, "plain-1"), ask(ctx, "plain-2")], bundled = [ask(ctx, "bundled-1"), ask(ctx, "bundled-2")]
      ctx.sql.exec("INSERT INTO approval_bundles(id,device,workload,reason,created_at,expires_at) VALUES ('bnd_contoso','dev_kim',NULL,'Set up Contoso',?,?)", ctx.now(), ctx.now() + 3_600_000)
      for (const id of bundled) ctx.sql.exec("UPDATE approvals SET bundle='bnd_contoso' WHERE id=?", id)
      const group = groupOf(ctx, plain[0]!)
      // Every ask to the same target carries the machine's review group, the bundled ones too.
      expect(bundled.map((id) => groupOf(ctx, id))).toEqual([group, group])
      const listed = (id: string) => (workspaceApprovalBatchOps["approvals.group"]!.handler(ctx, accessMember(projectState(ctx), "kim"), { id }, { auth: accountAuth("kim"), workspace: { ...WORK, id: ctx.tenant } }) as ApprovalGroupView).rows.flatMap((r) => r.view === "detail" ? [r.approval.approval] : [])
      expect(listed(group).sort()).toEqual([...plain].sort())
      expect(listed("bnd_contoso").sort()).toEqual([...bundled].sort())
      const machineRow = groups(inboxAs(ctx, "kim")).find((row) => row.group.group === group)
      expect(machineRow!.group.count).toBe(listed(group).length)
      expect(reviewTitle(ctx, "kim", group)).toContain("2 asks")
    })
  })

  it("changes the validator when an ask joins or leaves a group", async () => {
    const { account, workspaces: [alpha] } = await seed(["Alpha"])
    const f = await projectFixture()
    const answers: WorkspaceInboxAnswer[] = []
    await inAccess(f.tenant, (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      ask(ctx, "one"); ask(ctx, "two")
      answers.push(inboxAs(ctx))
      const three = ask(ctx, "three")
      answers.push(inboxAs(ctx))
      ctx.sql.exec("UPDATE approvals SET status='denied' WHERE id=?", three)
      answers.push(inboxAs(ctx))
    })
    const tags: string[] = []
    for (const read of answers) tags.push(await inboxEtag((await accountInbox(context(), account, { sessionKind: "web", stubFor: stubs({ [alpha!.id]: async () => ok(read) }).stubFor })).inbox))
    expect(answers.map((read) => groups(read).map((row) => row.group.count))).toEqual([[2], [3], [2]])
    expect(tags[1]).not.toBe(tags[0])
    expect(tags[2]).not.toBe(tags[1])
    expect(tags[2]).toBe(tags[0])
  })
})
