// The pushes table and what reads it: an approved push waiting to be sent,
// how far each approval's push has got, and the latest push to each
// destination. The asks, sends and sweeps are in pushes.ts; this module
// imports nothing from the approvals so the approvals may read it.

import { parsePushDestination, pushDestinationWords, type PushApprovalStatus, type PushApprovalView, type PushDestination, type PushOutcome, type PushRecordView } from "@mehen/protocol"
import type { ApprovalSubject } from "@mehen/protocol/api"
import { VaultError } from "../../http.ts"
import { one, randomId, rows, type VaultContext } from "../core.ts"
import type { ApprovalPresentation } from "../services.ts"

export const PUSHES_MIGRATION = `CREATE TABLE pushes(id TEXT PRIMARY KEY, item TEXT NOT NULL, field TEXT NOT NULL, item_version INTEGER NOT NULL,
  provider TEXT NOT NULL, destination TEXT NOT NULL, owner_key TEXT NOT NULL, via TEXT NOT NULL, via_version INTEGER NOT NULL,
  approval TEXT, device TEXT, workload TEXT, member TEXT, state TEXT NOT NULL, outcome TEXT, provider_status INTEGER,
  created_at INTEGER NOT NULL, finished_at INTEGER);
CREATE INDEX pushes_item ON pushes(item, destination, created_at);
CREATE INDEX pushes_owner ON pushes(provider, owner_key, state);
CREATE TABLE push_tickets(id TEXT PRIMARY KEY, device TEXT NOT NULL, workload TEXT, request TEXT NOT NULL, via TEXT NOT NULL, workspace TEXT NOT NULL, expires_at INTEGER NOT NULL);`

export type PushState = "queued" | "sending" | PushRecordView["state"]
export type PushRow = { id: string; item: string; field: string; item_version: number; provider: string; destination: string; owner_key: string; via: string; via_version: number; approval: string | null; device: string | null; workload: string | null; member: string | null; state: PushState; outcome: PushOutcome | null; provider_status: number | null; created_at: number; finished_at: number | null }

// A push approval's subject (design 2.4): the method, the URL's scheme and
// the only limits a decider may sign.
export const PUSH_METHOD = "PUSH"
export const PUSH_URL_PREFIX = "mehen-push:"
export const PUSH_CONSTRAINTS = { uses: 1, ttlSeconds: 600 } as const
// An approved push is sent within two minutes or not at all; one being sent
// that has not been recorded in five is no longer known.
export const PUSH_QUEUED_MS = 120_000
export const PUSH_SENDING_MS = 300_000
export const PUSH_SWEEP_KEY = "push-sweep"

// What a push approval's snapshot binds beside the asker's: both
// credentials' value and configuration, so an edit, rotation or restore of
// either while it waits makes it stale, and where it goes.
export type PushSnapshotPart = { item: { id: string; version: number; configRev: number }; via: { id: string; version: number; configRev: number }; field: string; destination: string; ownerKey: string }
// What the card shows about a push (ApprovalPresentation.push), bound by the
// presentation digest.
export type PushPresentation = Omit<PushApprovalView, "state" | "outcome" | "providerStatus">

export function isPushSubject(subject: Pick<ApprovalSubject, "method">): boolean {
  return subject.method === PUSH_METHOD
}

export function pushRow(ctx: VaultContext, id: string): PushRow | null {
  return one(ctx.sql.exec<PushRow>("SELECT * FROM pushes WHERE id=?", id))
}

export function storedDestination(row: Pick<PushRow, "destination">): PushDestination {
  const d = parsePushDestination(row.destination)
  if (d === null) throw new Error("corrupt push destination")
  return d
}

// The next sweep: the oldest queued push's two minutes, or the oldest
// sending one's five.
export function schedulePushSweep(ctx: VaultContext): void {
  const due = one(ctx.sql.exec<{ due: number | null }>("SELECT MIN(CASE state WHEN 'queued' THEN created_at+? ELSE created_at+? END) AS due FROM pushes WHERE state IN ('queued','sending')", PUSH_QUEUED_MS, PUSH_SENDING_MS))?.due ?? null
  if (due === null) ctx.unschedule("pushes", PUSH_SWEEP_KEY)
  else ctx.schedule("pushes", PUSH_SWEEP_KEY, Math.max(due, ctx.now() + 1))
}

export function insertQueuedPush(ctx: VaultContext, part: PushSnapshotPart, by: { approval: string; device: string; workload: string | null } | { member: string }): string {
  const id = randomId("psh")
  const d = parsePushDestination(part.destination)
  if (d === null) throw new VaultError("internal", "A push names a destination the vault cannot read.")
  const asker = "member" in by ? { approval: null, device: null, workload: null, member: by.member } : { ...by, member: null }
  ctx.sql.exec("INSERT INTO pushes(id,item,field,item_version,provider,destination,owner_key,via,via_version,approval,device,workload,member,state,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'queued',?)", id, part.item.id, part.field, part.item.version, d.provider, part.destination, part.ownerKey, part.via.id, part.via.version, asker.approval, asker.device, asker.workload, asker.member, ctx.now())
  schedulePushSweep(ctx)
  return id
}

// Inside the decide transaction: the approval's one use is spent at once
// (a failed push spends it too, ruling U2) and the push waits to be sent.
export function queueApprovedPush(ctx: VaultContext, approval: { id: string; device: string; workload: string | null; snapshot: string }): void {
  const part = (JSON.parse(approval.snapshot) as { push?: PushSnapshotPart }).push
  if (!part) throw new VaultError("internal", "This push approval has no push.")
  ctx.sql.exec("UPDATE protected_use_grants SET uses_left=0 WHERE approval=?", approval.id)
  insertQueuedPush(ctx, part, { approval: approval.id, device: approval.device, workload: approval.workload })
}

// A pending push whose credential or via changed since it was asked: the
// value, or anything a configuration revision covers (the allowance among
// them), is no longer the one shown.
export function pushSnapshotChanged(ctx: VaultContext, snapshot: string): boolean {
  const part = (JSON.parse(snapshot) as { push?: PushSnapshotPart }).push
  if (!part) return false
  return [part.item, part.via].some((c) => {
    const row = one(ctx.sql.exec<{ version: number; config_rev: number }>("SELECT version,config_rev FROM items WHERE id=?", c.id))
    return row?.version !== c.version || row.config_rev !== c.configRev
  })
}

function approvalPush(ctx: VaultContext, approval: string): PushRow | null {
  return one(ctx.sql.exec<PushRow>("SELECT * FROM pushes WHERE approval=? ORDER BY created_at DESC LIMIT 1", approval))
}

// ApprovalStatus.push: absent on any other approval.
export function pushApprovalStatus(ctx: VaultContext, approval: { id: string; presentation: string }): PushApprovalStatus | undefined {
  const shown = (JSON.parse(approval.presentation) as ApprovalPresentation).push
  if (!shown) return undefined
  const row = approvalPush(ctx, approval.id)
  return { destination: shown.destination, field: shown.field, version: shown.version, state: row?.state ?? "pending", ...(row?.outcome ? { outcome: row.outcome } : {}), ...(row?.provider_status != null ? { providerStatus: row.provider_status } : {}) }
}

// ApprovalView.push: what the card showed, and how far it has got.
export function pushApprovalView(ctx: VaultContext, approval: { id: string; presentation: string }): PushApprovalView | undefined {
  const shown = (JSON.parse(approval.presentation) as ApprovalPresentation).push
  const status = pushApprovalStatus(ctx, approval)
  return shown && status ? { ...shown, ...status } : undefined
}

// The latest finished push to each destination this item was put into,
// newest first. Queued and sending pushes are the approvals' to report.
// The via is named only where the viewer sees it, and a machine or a guest
// is never told who pushed.
export function latestPushes(ctx: VaultContext, item: { id: string; version: number }, viewer: { seesVia: (slug: string) => boolean; seesWho: boolean }): PushRecordView[] {
  const latest = rows(ctx.sql.exec<PushRow & { via_slug: string | null; by_device: string | null; by_member: string | null }>(
    `SELECT p.*, v.slug AS via_slug, a.device_name AS by_device, m.name AS by_member FROM pushes p
     LEFT JOIN items v ON v.id=p.via LEFT JOIN approvals a ON a.id=p.approval LEFT JOIN members m ON m.id=p.member
     WHERE p.item=? AND p.state IN ('done','failed','unknown','not_sent')
       AND p.created_at=(SELECT MAX(q.created_at) FROM pushes q WHERE q.item=p.item AND q.destination=p.destination AND q.state IN ('done','failed','unknown','not_sent'))
     ORDER BY p.created_at DESC, p.id`, item.id))
  return latest.map((p) => ({ push: p.id, destination: p.destination, words: pushDestinationWords(storedDestination(p)), field: p.field, version: p.item_version, current: p.item_version === item.version, via: p.via_slug !== null && viewer.seesVia(p.via_slug) ? p.via_slug : null, state: p.state as PushRecordView["state"], outcome: p.outcome, providerStatus: p.provider_status, at: new Date(p.finished_at ?? p.created_at).toISOString(), ...(viewer.seesWho ? { by: p.by_member ?? p.by_device ?? null } : {}) }))
}
