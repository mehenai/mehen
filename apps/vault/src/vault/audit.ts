// The audit chain: every event carries the hash of the one before it, so
// rewriting history means rewriting every later hash, and the head hash is
// published in each audit read for an outside copy to compare against.

import { createHash } from "node:crypto"
import { canonicalJson } from "@mehen/protocol/api"
import { ERROR_CODES, PrivateEventSchema } from "@mehen/protocol"
import type { PrivateEvent } from "@mehen/protocol"
import type { VaultContext } from "./core.ts"
import type { AuditEvent } from "./core.ts"

export const AUDIT_MIGRATIONS = [
  `CREATE TABLE audit (
     seq INTEGER PRIMARY KEY,
     at INTEGER NOT NULL,
     actor TEXT NOT NULL,
     action TEXT NOT NULL,
     target TEXT,
     detail TEXT NOT NULL,
     prev TEXT NOT NULL,
     hash TEXT NOT NULL
   );
   CREATE INDEX audit_target ON audit (target, seq);`,
  // Time-bounded reads (the activity counts) without a scan of the whole chain.
  `CREATE INDEX audit_at ON audit (at);`,
  `CREATE TABLE audit_private_owners(seq INTEGER PRIMARY KEY,member TEXT NOT NULL);`,
]

export const GENESIS = "mehen/audit/v1"
// A managed workspace's chain starts from a value binding its platform and
// the workspace, so a chain copied from one workspace never passes for
// another platform's, or another workspace's.
export function managedAuditGenesis(platform: string, tenant: string): string {
  return `${GENESIS}/platform/${platform}/${tenant}`
}

export type AuditRow = {
  seq: number
  at: number
  actor: string
  action: string
  target: string | null
  detail: string
  prev: string
  hash: string
}

export function auditHash(prev: string, entry: Omit<AuditRow, "hash" | "prev">): string {
  return createHash("sha256").update(prev).update("\n").update(canonicalJson(entry)).digest("base64url")
}

// Synchronous on purpose: no await between reading the head and writing the
// next row, so concurrent requests on the DO cannot fork the chain.
function privateOutcomeValid(outcome: string): boolean { return /^[a-z_]+$/.test(outcome) || /^refused:[a-z_]+$/.test(outcome) && (ERROR_CODES as readonly string[]).includes(outcome.slice(8)) }

export function appendAudit(sql: SqlStorage, at: number, event: AuditEvent, genesis = GENESIS): void {
  if (event.private && !privateOutcomeValid(event.private.outcome)) throw new Error("Invalid private audit outcome.")
  const head = sql.exec<{ seq: number; hash: string }>("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").toArray()[0]
  const seq = (head?.seq ?? 0) + 1
  const prev = head?.hash ?? genesis
  const entry = {
    seq,
    at,
    actor: event.actor,
    action: event.action,
    target: event.target ?? null,
    detail: canonicalJson(event.private ? PrivateEventSchema.parse({ ...event.private, action: event.action, at }) : event.detail ?? {}),
  }
  sql.exec(
    "INSERT INTO audit (seq, at, actor, action, target, detail, prev, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    seq,
    at,
    entry.actor,
    entry.action,
    entry.target,
    entry.detail,
    prev,
    auditHash(prev, entry),
  )
  if (event.private && event.privateOwner) sql.exec("INSERT INTO audit_private_owners(seq,member) VALUES (?,?)", seq, event.privateOwner)
}

export function verifyAuditChain(rowsInOrder: AuditRow[], startPrev = GENESIS): { ok: true } | { ok: false; seq: number } {
  let prev = startPrev
  for (const row of rowsInOrder) {
    const { hash, prev: rowPrev, ...entry } = row
    if (rowPrev !== prev || auditHash(prev, entry) !== hash) return { ok: false, seq: row.seq }
    prev = hash
  }
  return { ok: true }
}

// The resource owner supplies the privacy marker; arbitrary rich detail never
// reaches the stored private record, even for the credential's own member.
export function auditPrivateEvent(ctx: VaultContext, event: PrivateEvent, privateOwner: string): void {
  const { action, at: _at, ...minimal } = PrivateEventSchema.parse(event)
  if (!privateOutcomeValid(minimal.outcome)) throw new Error("Invalid private audit outcome.")
  const actor = minimal.actor.kind === "member" ? `member:${minimal.actor.member}` : minimal.actor.kind === "device" ? `device:${minimal.actor.device}` : `enrolment:${minimal.actor.enrolment}`
  ctx.audit({ actor, action, target: minimal.item, private: minimal, privateOwner })
}

// Whether an audit row is part of an item's history: the item is its
// target, or its detail names it as an approval's or a grant's item, among
// a refusal's or a tripwire's items, or as a run's delivered var.
export function auditNamesItem(row: { target: string | null; detail: string }, slug: string): boolean {
  if (row.target === slug) return true
  if (!row.detail.includes(slug)) return false
  let detail: unknown
  try {
    detail = JSON.parse(row.detail)
  } catch {
    return false
  }
  if (typeof detail !== "object" || detail === null) return false
  const minimal = PrivateEventSchema.safeParse(detail)
  if (minimal.success) return minimal.data.slug === slug
  const { item, items, vars } = detail as { item?: unknown; items?: unknown; vars?: unknown }
  if (item === slug) return true
  if (Array.isArray(items) && items.includes(slug)) return true
  if (typeof vars === "object" && vars !== null) return Object.values(vars).some((v) => typeof v === "string" && v.endsWith(`:${slug}`))
  return false
}
