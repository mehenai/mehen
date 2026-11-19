import { expect, it, vi } from "vitest"
import { reconcileWorkspaceMetadata } from "../src/directory/workspace-aliases.ts"
import { drainWorkspaceNotices } from "../src/directory/account-events.ts"
import { maintainWorkspaceDirectory } from "../src/directory/workspace-maintenance.ts"
import { reconcileEnrolmentMirrors, type EnrolMirrorClient } from "../src/directory/workspace-enrolment.ts"
import { ENROLMENT_PRUNE_BATCHES, ENROLMENT_PRUNE_LIMIT, ENROLMENT_SETTLED_KEEP_MS } from "../src/directory/enrolment.ts"
import { createWorkspaceFixture } from "./workspace-fixtures.ts"

it("workspace maintenance bounds metadata and notices to 100, rotating across every workspace in consecutive windows", async () => {
  const f = await createWorkspaceFixture()
  await f.env.DB.batch(Array.from({ length: 148 }, (_, n) => f.env.DB.prepare("INSERT INTO workspaces(id,slug,name,status,created_by,created_at) VALUES (?,?,'Work','active',?,?)").bind(`tn_window${String(n).padStart(4, "0")}`, `window-${n}`, f.account, Date.now())))
  const metadataAll = new Set<string>(), noticesAll = new Set<string>()
  for (const now of [1800000, 2700000]) {
    const metadata: string[] = [], notices: string[] = []
    await reconcileWorkspaceMetadata(f.env, {
      async metadata(id) {
        metadata.push(id); metadataAll.add(id)
        const workspace = await f.env.DB.prepare("SELECT id,slug,name FROM workspaces WHERE id=?").bind(id).first<{ id: string; slug: string; name: string }>()
        if (!workspace) throw new Error("Unknown test workspace")
        return { workspace, displayRev: 1, appliedReservations: [] }
      },
      async membership() { throw new Error("Unexpected membership call") },
    }, now)
    await drainWorkspaceNotices(f.env, {
      async drain(id, limit) { expect(limit).toBe(100); notices.push(id); noticesAll.add(id); return { events: [] } },
      async ack() { throw new Error("No notices need acknowledgement") },
    }, now)
    expect(metadata.length).toBeLessThanOrEqual(100)
    expect(notices.length).toBeLessThanOrEqual(100)
    expect(metadata).toHaveLength(now === 1800000 ? 100 : 50)
    expect(notices).toEqual(metadata)
  }
  expect(metadataAll.size).toBe(150)
  expect(noticesAll.size).toBe(150)
})

it("workspace maintenance expires challenges before any fallible catalogue sweep", async () => {
  const f = await createWorkspaceFixture(), now = Date.now(), prepared: string[] = []
  await f.env.DB.prepare("INSERT INTO challenges(id,kind,challenge,expires_at) VALUES ('maintenance-expired','account-signin','old',?)").bind(now - 1).run()
  const db = new Proxy(f.env.DB, { get(target, prop) {
    if (prop === "prepare") return (query: string) => {
      prepared.push(query)
      if (query.startsWith("SELECT")) throw new Error("Injected catalogue failure")
      return target.prepare(query)
    }
    const value = Reflect.get(target, prop) as unknown
    return typeof value === "function" ? value.bind(target) : value
  } })
  const errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
  try { await maintainWorkspaceDirectory({ ...f.env, DB: db }, now) } finally { errors.mockRestore() }
  expect(prepared[0]).toBe("DELETE FROM challenges WHERE expires_at<=?")
  const firstSweep = prepared.findIndex(query => query.startsWith("SELECT"))
  expect(firstSweep).toBeGreaterThan(0)
  expect(prepared[firstSweep]).toMatch(/^SELECT id,tenant,source,target,actor,intent_hash,created_at,state,bookmark,undo_bookmark FROM vault_restore_intents /)
  expect(prepared.slice(0, firstSweep).every(query => /^(DELETE|UPDATE) /.test(query))).toBe(true)
  expect(await f.env.DB.prepare("SELECT id FROM challenges WHERE id='maintenance-expired'").first()).toBeNull()
})

it("workspace maintenance expires an enrolment only at its hard cap, never on a lapsed lease", async () => {
  const f = await createWorkspaceFixture(), now = Date.now()
  // Opened on their page, so their workspace holds a copy and an expired one is kept.
  const row = (id: string, expiresAt: number, hardExpiresAt: number) => f.env.DB.prepare(`INSERT INTO enrolments(id,code_hash,jwk,thumbprint,name,backend,status,tenant,created_at,expires_at,hard_expires_at,workspace_intent,owner_intent,start_at,start_client_label,pending_state)
    VALUES (?,?,'{}',?,'Laptop','software','pending',?,?,?,?,'alex','{"kind":"self"}',?,'CLI','pending_owner_acceptance')`).bind(id, `hash-${id}`, `thumb-${id}`, f.workspaces.personal, now - 7_200_000, expiresAt, hardExpiresAt, now - 7_200_000)
  await f.env.DB.batch([row("enr_lapsed", now - 1, now + 3_600_000), row("enr_capped", now - 2, now - 1), row("enr_live", now + 3_600_000, now + 86_400_000)])
  const errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
  try { await maintainWorkspaceDirectory(f.env, now) } finally { errors.mockRestore() }
  expect((await f.env.DB.prepare("SELECT id,status,pending_state,expired_reason FROM enrolments ORDER BY id").all()).results).toEqual([
    { id: "enr_capped", status: "expired", pending_state: null, expired_reason: "hard_cap" },
    { id: "enr_lapsed", status: "pending", pending_state: "pending_owner_acceptance", expired_reason: null },
    { id: "enr_live", status: "pending", pending_state: "pending_owner_acceptance", expired_reason: null },
  ])
})

it("workspace maintenance deletes a settled enrolment thirty days past its hard cap, keeping one its workspace has still to hear of", async () => {
  const f = await createWorkspaceFixture(), now = Date.now(), old = now - 30 * 86_400_000 - 1, recent = now - 29 * 86_400_000
  // Claimed by an account, so none goes at its hard cap as one that never reached a workspace.
  const row = (id: string, status: "expired" | "rejected" | "active", intent: string, hardExpiresAt: number, extra: { reconciledAt?: number; discardDevice?: string } = {}) => f.env.DB.prepare(`INSERT INTO enrolments(id,code_hash,jwk,thumbprint,name,backend,status,tenant,device,created_at,expires_at,hard_expires_at,workspace_intent,owner_intent,start_at,start_client_label,expired_reason,reconciled_at,discard_pending,discard_device,mirror_acknowledged,claimed_account)
    VALUES (?,?,'{}',?,'Laptop','software',?,?,?,?,?,?,?,'{"kind":"self"}',?,'CLI',?,?,?,?,?,?)`).bind(id, `hash-${id}`, `thumb-${id}`, status, status === "active" || extra.discardDevice ? f.workspaces.personal : null, status === "active" ? "dev_kept" : null, hardExpiresAt - 86_400_000, hardExpiresAt, hardExpiresAt, intent, hardExpiresAt - 86_400_000, status === "expired" ? "hard_cap" : null, extra.reconciledAt ?? null, extra.discardDevice ? 1 : 0, extra.discardDevice ?? null, status === "active" ? 1 : 0, f.account)
  await f.env.DB.batch([
    // Started for a workspace that does not exist: nothing will ever reconcile it.
    row("enr_nowhere", "expired", "no-such-workspace", old),
    row("enr_told", "rejected", "alex", old, { reconciledAt: old }),
    row("enr_recent", "expired", "no-such-workspace", recent),
    row("enr_untold", "expired", "alex", old),
    row("enr_discarding", "expired", "alex", old, { discardDevice: "dev_discard" }),
    row("enr_active", "active", "alex", old),
  ])
  const errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
  try { await maintainWorkspaceDirectory(f.env, now) } finally { errors.mockRestore() }
  expect((await f.env.DB.prepare("SELECT id FROM enrolments ORDER BY id").all()).results).toEqual([{ id: "enr_active" }, { id: "enr_discarding" }, { id: "enr_recent" }, { id: "enr_untold" }])
})

// Settled attempts straight into D1, `count` of them, oldest first by n:
// expired at their hard cap and aimed at `intent`.
function settledRows(db: D1Database, count: number, createdAt: number, hardExpiresAt: number, intent: string, reason: "hard_cap" | "superseded", claimed: string | null = null) {
  return db.prepare(`WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<?)
    INSERT INTO enrolments(id,code_hash,jwk,thumbprint,name,backend,status,created_at,expires_at,hard_expires_at,workspace_intent,owner_intent,start_at,start_client_label,expired_reason,claimed_account)
    SELECT printf('enr_prune%05d',i),printf('hash-%05d',i),'{}',printf('thumb-%05d',i),'Laptop','software','expired',?+i,?,?,?,'{"kind":"self"}',?+i,'CLI',?,? FROM n`).bind(count - 1, createdAt, hardExpiresAt, hardExpiresAt, intent, createdAt, reason, claimed).run()
}
const pruneId = (n: number) => `enr_prune${String(n).padStart(5, "0")}`

it("workspace maintenance prunes an unclaimed attempt that never reached a workspace at its hard cap, and keeps thirty days for one a workspace or an account holds", async () => {
  const f = await createWorkspaceFixture(), now = Date.now()
  type Extra = { status?: "expired" | "rejected"; reason?: string | null; tenant?: string; claimed?: string; reconciledAt?: number; discardDevice?: string }
  const row = (id: string, hardExpiresAt: number, extra: Extra = {}) => f.env.DB.prepare(`INSERT INTO enrolments(id,code_hash,jwk,thumbprint,name,backend,status,tenant,created_at,expires_at,hard_expires_at,workspace_intent,owner_intent,start_at,start_client_label,expired_reason,claimed_account,reconciled_at,discard_pending,discard_device)
    VALUES (?,?,'{}',?,'Laptop','software',?,?,?,?,?,'alex','{"kind":"self"}',?,'CLI',?,?,?,?,?)`).bind(id, `hash-${id}`, `thumb-${id}`, extra.status ?? "expired", extra.tenant ?? null, hardExpiresAt - 86_400_000, hardExpiresAt, hardExpiresAt, hardExpiresAt - 86_400_000, extra.status === "rejected" ? null : extra.reason === undefined ? "hard_cap" : extra.reason, extra.claimed ?? null, extra.reconciledAt ?? null, extra.discardDevice ? 1 : 0, extra.discardDevice ?? null)
  await f.env.DB.batch([
    // Superseded by the same key, or run out at the hard cap, and never opened or claimed.
    row("enr_superseded", now - 1, { reason: "superseded" }),
    row("enr_capped", now - 1),
    row("enr_superseded_early", now + 3_600_000, { reason: "superseded" }),
    row("enr_claimed", now - 1, { claimed: f.account }),
    row("enr_acknowledged", now - 1, { tenant: f.workspaces.personal, reconciledAt: now }),
    row("enr_source", now - 1, { reason: "source", reconciledAt: now }),
    row("enr_legacy", now - 1, { reason: null }),
    row("enr_rejected", now - 1, { status: "rejected" }),
    row("enr_discarding", now - 1, { reason: "discarded", tenant: f.workspaces.personal, discardDevice: "dev_discard" }),
  ])
  const left = async () => (await f.env.DB.prepare("SELECT id FROM enrolments ORDER BY id").all<{ id: string }>()).results.map(r => r.id)
  const errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
  try {
    await maintainWorkspaceDirectory(f.env, now)
    expect(await left()).toEqual(["enr_acknowledged", "enr_claimed", "enr_discarding", "enr_legacy", "enr_rejected", "enr_source", "enr_superseded_early"])
    await maintainWorkspaceDirectory(f.env, now + ENROLMENT_SETTLED_KEEP_MS - 2)
    expect(await left()).toContain("enr_acknowledged")
    await maintainWorkspaceDirectory(f.env, now + ENROLMENT_SETTLED_KEEP_MS)
    expect(await left()).not.toContain("enr_acknowledged")
  } finally { errors.mockRestore() }
})

it("workspace maintenance prunes 1,200 attempts that never reached a workspace in one run, in batches that stop on a short one", async () => {
  const f = await createWorkspaceFixture(), now = Date.now()
  await settledRows(f.env.DB, 1_200, now - 86_400_000, now - 1, "alex", "superseded")
  const deletes: string[] = []
  const db = new Proxy(f.env.DB, { get(target, prop) {
    if (prop === "prepare") return (query: string) => { if (query.startsWith("DELETE FROM enrolments")) deletes.push(query); return target.prepare(query) }
    const value = Reflect.get(target, prop) as unknown
    return typeof value === "function" ? value.bind(target) : value
  } })
  const errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
  try { await maintainWorkspaceDirectory({ ...f.env, DB: db }, now) } finally { errors.mockRestore() }
  expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM enrolments").first()).toEqual({ n: 0 })
  // 500, 500 and a short 200 in the never-reached step; one empty batch in the thirty-day step.
  expect(deletes).toHaveLength(4)
})

it("workspace maintenance prunes settled enrolments oldest first and at most its ceiling a run, in a step whose limit or failure never holds back the expiry sweeps", async () => {
  const f = await createWorkspaceFixture(), now = Date.now(), old = now - ENROLMENT_SETTLED_KEEP_MS - 1, ceiling = ENROLMENT_PRUNE_LIMIT * ENROLMENT_PRUNE_BATCHES
  expect([ENROLMENT_PRUNE_LIMIT, ENROLMENT_PRUNE_BATCHES]).toEqual([500, 10])
  // Claimed, so only the thirty-day step takes them.
  await settledRows(f.env.DB, ceiling + 100, old - 86_400_000, old, "no-such-workspace", "hard_cap", f.account)
  const challenge = () => f.env.DB.prepare("INSERT INTO challenges(id,kind,challenge,expires_at) VALUES ('prune-expired','account-signin','old',?)").bind(now - 1).run()
  const left = async () => (await f.env.DB.prepare("SELECT id FROM enrolments ORDER BY id").all<{ id: string }>()).results.map(r => r.id)
  const errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
  try {
    await challenge()
    await maintainWorkspaceDirectory(f.env, now)
    expect(await left()).toEqual(Array.from({ length: 100 }, (_, n) => pruneId(ceiling + n)))
    expect(await f.env.DB.prepare("SELECT id FROM challenges WHERE id='prune-expired'").first()).toBeNull()
    // A failing prune leaves the expiry sweeps done and its rows for the next run.
    await challenge()
    const db = new Proxy(f.env.DB, { get(target, prop) {
      if (prop === "prepare") return (query: string) => { if (query.startsWith("DELETE FROM enrolments")) throw new Error("Injected prune failure"); return target.prepare(query) }
      const value = Reflect.get(target, prop) as unknown
      return typeof value === "function" ? value.bind(target) : value
    } })
    await maintainWorkspaceDirectory({ ...f.env, DB: db }, now)
    expect(await f.env.DB.prepare("SELECT id FROM challenges WHERE id='prune-expired'").first()).toBeNull()
    expect(await left()).toHaveLength(100)
    await maintainWorkspaceDirectory(f.env, now)
    expect(await left()).toEqual([])
  } finally { errors.mockRestore() }
})

it("enrolment reconcile reaches a later lost acceptance and a later settled row behind 100 earlier pending starts", async () => {
  const f = await createWorkspaceFixture(), now = Date.now()
  // The settled row's workspace saw it, so the prune does not take it unreconciled.
  const row = (id: string, createdAt: number, status: "pending" | "expired") => f.env.DB.prepare(`INSERT INTO enrolments(id,code_hash,jwk,thumbprint,name,backend,status,tenant,created_at,expires_at,hard_expires_at,workspace_intent,owner_intent,start_at,start_client_label,pending_state,expired_reason)
    VALUES (?,?,'{}',?,'Laptop','software',?,?,?,?,?,'alex','{"kind":"self"}',?,'CLI',?,?)`).bind(id, `hash-${id}`, `thumb-${id}`, status, status === "expired" ? f.workspaces.personal : null, createdAt, now + 86_400_000, now + 86_400_000, createdAt, status === "pending" ? "pending_owner_acceptance" : null, status === "pending" ? null : "hard_cap")
  // 100 earlier starts that need no account and have nothing to reconcile
  // until their hard cap, then a later start whose acceptance reply was lost
  // and a later row D1 has already settled.
  await f.env.DB.batch([...Array.from({ length: 100 }, (_, n) => row(`enr_early${String(n).padStart(3, "0")}`, now - 7_200_000 + n, "pending")), row("enr_later", now - 60_000, "pending"), row("enr_settled", now - 30_000, "expired")])
  const asked: string[][] = []
  const scope = { tags: [], projects: [], maxEnvironment: "unprotected" as const, modes: ["relay" as const], privateCredentials: false }
  const client: EnrolMirrorClient = {
    async reconcile(_workspace, enrolment) {
      asked.at(-1)?.push(enrolment)
      return enrolment === "enr_later" ? { device: "dev_later", mirrored: false, state: "active", active: { scope, owner: { kind: "member", member: f.personalMember, name: "Owner" }, acceptance: null, admission: null } } : { device: null, mirrored: false, state: enrolment === "enr_settled" ? "expired" : "pending_owner_acceptance", active: null }
    },
    async mirrored() {},
    async expire() { return { expired: true } },
    async discard() { throw new Error("Nothing is discarded here") },
  }
  for (const tick of [0, 1, 2]) {
    asked.push([])
    await reconcileEnrolmentMirrors(f.env, client, now + tick * 900_000)
    expect(asked.at(-1)!.length).toBeLessThanOrEqual(100)
  }
  // The settled row is reached on the first run, the lost acceptance within
  // the windows that cover every pending row.
  expect(asked[0]).toContain("enr_settled")
  expect(asked.flat()).toContain("enr_later")
  expect(await f.env.DB.prepare("SELECT id,status,device,reconciled_at IS NOT NULL AS reconciled FROM enrolments WHERE id IN ('enr_later','enr_settled') ORDER BY id").all().then(r => r.results)).toEqual([
    { id: "enr_later", status: "active", device: "dev_later", reconciled: 0 },
    { id: "enr_settled", status: "expired", device: null, reconciled: 1 },
  ])
  // No earlier start was expired early: only the hard cap ends one.
  expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM enrolments WHERE id GLOB 'enr_early*' AND status='pending'").first()).toEqual({ n: 100 })
})

it("enrolment reconcile tells the sources of up to 200 settled rows a run that a workspace saw or an account claimed, oldest first, asking each once even when one fails, and leaves one that never reached a workspace to the prune", async () => {
  const f = await createWorkspaceFixture(), now = Date.now(), createdAt = now - 86_400_000
  await settledRows(f.env.DB, 220, createdAt, now + 86_400_000, "alex", "superseded", f.account)
  // Older than every claimed row: one the workspace saw, one expired before
  // 0008 with no reason, and one that never reached a workspace.
  const row = (id: string, at: number, reason: "superseded" | null, tenant: string | null) => f.env.DB.prepare(`INSERT INTO enrolments(id,code_hash,jwk,thumbprint,name,backend,status,tenant,created_at,expires_at,hard_expires_at,workspace_intent,owner_intent,start_at,start_client_label,expired_reason)
    VALUES (?,?,'{}',?,'Laptop','software','expired',?,?,?,?,'alex','{"kind":"self"}',?,'CLI',?)`).bind(id, `hash-${id}`, `thumb-${id}`, tenant, at, now + 86_400_000, now + 86_400_000, at, reason)
  await f.env.DB.batch([row("enr_unreached", createdAt - 3, "superseded", null), row("enr_seen", createdAt - 2, "superseded", f.workspaces.personal), row("enr_legacy", createdAt - 1, null, null)])
  const asked: string[] = []
  const client: EnrolMirrorClient = {
    async reconcile(_workspace, enrolment) {
      asked.push(enrolment)
      if (enrolment === pruneId(7)) throw new Error("Injected unreachable source")
      return { device: null, mirrored: false, state: "pending_owner_acceptance", active: null }
    },
    async mirrored() {},
    async expire() { return { expired: true } },
    async discard() { throw new Error("Nothing is discarded here") },
  }
  const errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
  try {
    await reconcileEnrolmentMirrors(f.env, client, now)
    expect(asked).toEqual(["enr_seen", "enr_legacy", ...Array.from({ length: 198 }, (_, n) => pruneId(n))])
    expect(await f.env.DB.prepare("SELECT id FROM enrolments WHERE reconciled_at IS NULL ORDER BY id").all<{ id: string }>().then(r => r.results.map(row => row.id))).toEqual([pruneId(7), ...Array.from({ length: 22 }, (_, n) => pruneId(198 + n)), "enr_unreached"])
    // The never-reached row goes at its hard cap with no reconcile; the others keep their thirty days.
    await maintainWorkspaceDirectory(f.env, now + 86_400_000)
  } finally { errors.mockRestore() }
  const left = await f.env.DB.prepare("SELECT id FROM enrolments ORDER BY id").all<{ id: string }>().then(r => r.results.map(row => row.id))
  expect(left).not.toContain("enr_unreached")
  expect(left).toHaveLength(222)
})
