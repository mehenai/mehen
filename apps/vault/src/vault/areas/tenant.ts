// Workspace freeze and audit projections.

import { Slug } from "@mehen/protocol/api"
import { z } from "zod"
import { PrivateEventSchema, WorkspaceAuditPageSchema } from "@mehen/protocol"
import { can, effectiveAccess } from "../access.ts"
import { authorise, eligibilityState } from "./workspace-runtime.ts"
import { auditNamesItem,verifyAuditChain } from "../audit.ts"
import { VaultError } from "../../http.ts"
import type { AuditRow } from "../audit.ts"
import { type Area, type VaultContext } from "../core.ts"
import { auditGenesisOf } from "../managed-platform.ts"

export const AUDIT_PAGE_SIZE = 50

const AUDIT_COLUMNS = "seq, at, actor, action, target, detail, prev, hash"

import { workspaceMemberOps } from "./workspace-members.ts"

// Cursor and legacy before are exclusive, stable sequence bounds, not offsets.
export const WorkspaceAuditQuery = z.strictObject({ cursor: z.string().regex(/^[1-9][0-9]*$/).refine(value => Number.isSafeInteger(Number(value))).optional(), before: z.number().int().positive().max(Number.MAX_SAFE_INTEGER).optional(), item: Slug.optional(), limit: z.number().int().min(1).max(200).default(AUDIT_PAGE_SIZE) }).refine(q => q.cursor === undefined || q.before === undefined, "Use one audit cursor.")
function auditObject(row: AuditRow): Record<string, unknown> | null {
  try { const detail: unknown = JSON.parse(row.detail); return typeof detail === "object" && detail !== null && !Array.isArray(detail) ? detail as Record<string, unknown> : null } catch { return null }
}
function workspaceAudit(ctx: VaultContext, raw: unknown, invocation: import("./workspace-runtime.ts").WorkspaceInvocationContext) {
  const decision = authorise(ctx, invocation, { type: "audit.read" }, {}, ctx.now())
  if (decision.principal.kind !== "member") throw new VaultError("forbidden", "Only people read audit events.")
  const q = WorkspaceAuditQuery.parse(raw ?? {}), state = eligibilityState(ctx, invocation)
  const principal = decision.principal, member = state.members.find(m => m.id === principal.memberId)!
  const elevated = member.standing.effectiveRole === "owner" || member.standing.effectiveRole === "admin"
  const ownDevices = new Set(state.devices.filter(d => d.owner.kind === "member" && d.owner.id === member.id).map(d => `device:${d.id}`))
  const ownTeams = new Set(state.teams.filter(t => t.members.includes(member.id)).map(t => t.id))
  const editedProjects = new Set(state.projects.filter(p => ["edit", "manage"].includes(effectiveAccess(state, { kind: "member", id: member.id }, p.id, ctx.now()).level ?? "")).map(p => p.id))
  const privateOwners = new Map(ctx.sql.exec<{ seq: number; member: string }>("SELECT seq,member FROM audit_private_owners").toArray().map(row => [row.seq, row.member]))
  const all = ctx.sql.exec<AuditRow>(`SELECT ${AUDIT_COLUMNS} FROM audit ORDER BY seq`).toArray()
  const readable = all.filter(row => {
    const detail = auditObject(row), minimal = PrivateEventSchema.safeParse(detail)
    if (elevated) return true
    // Private ownership precedes actor/project filters, even after a purge,
    // rehome or the former admin actor's later demotion. Missing index closes.
    if (minimal.success || privateOwners.has(row.seq)) return privateOwners.get(row.seq) === member.id && (member.standing.effectiveRole !== "guest" || row.actor === `member:${member.id}` || ownDevices.has(row.actor))
    if (!detail) return false
    const credential = state.credentials.find(c => c.id === row.target || c.slug === row.target || c.id === detail.item || c.slug !== undefined && c.slug === detail.item)
    if (credential?.home.kind === "member") return credential.home.member === member.id
    if (row.actor === `member:${member.id}` || ownDevices.has(row.actor)) return true
    if (member.standing.effectiveRole === "guest") return false
    const project = state.projects.find(p => p.id === row.target || p.id === detail.project)
    if (project && editedProjects.has(project.id)) return true
    if (credential?.home.kind === "project" && editedProjects.has(credential.home.project)) return true
    if (credential?.home.kind === "workspace" && can(state, principal, { type: "item.read" }, { credential: credential.id }, ctx.now()).allowed) return true
    return ownTeams.has(row.target ?? "") || typeof detail.team === "string" && ownTeams.has(detail.team)
  })
  const visibleItem = q.item === undefined || state.credentials.some(c => c.slug === q.item && can(state, principal, { type: "item.read" }, { credential: c.id }, ctx.now()).allowed)
  const bound = q.cursor === undefined ? q.before ?? Number.MAX_SAFE_INTEGER : Number(q.cursor)
  const matching = visibleItem ? readable.filter(row => row.seq < bound && (q.item === undefined || auditNamesItem(row, q.item) || state.credentials.some(c => c.slug === q.item && (row.target === c.id || auditObject(row)?.item === c.id)))).reverse() : []
  const events = matching.slice(0, q.limit), head = all.at(-1)
  return WorkspaceAuditPageSchema.parse({ events, head: elevated && head ? { seq: head.seq, hash: head.hash } : null, verified: verifyAuditChain(all, auditGenesisOf(ctx)).ok, filtered: readable.length !== all.length, next: matching.length > events.length ? String(events.at(-1)!.seq) : null })
}

// A managed workspace's audit as its platform reads it: every row, newest
// first, with the head, verified from the platform's own first link.
export function platformAuditPage(ctx: VaultContext, query: { cursor?: string | undefined; limit?: number | undefined }) {
  const all = ctx.sql.exec<AuditRow>(`SELECT ${AUDIT_COLUMNS} FROM audit ORDER BY seq`).toArray()
  const bound = query.cursor === undefined ? Number.MAX_SAFE_INTEGER : Number(query.cursor)
  const matching = all.filter(row => row.seq < bound).reverse()
  const events = matching.slice(0, query.limit ?? AUDIT_PAGE_SIZE), head = all.at(-1)
  return WorkspaceAuditPageSchema.parse({ events, head: head ? { seq: head.seq, hash: head.hash } : null, verified: verifyAuditChain(all, auditGenesisOf(ctx)).ok, filtered: false, next: matching.length > events.length ? String(events.at(-1)!.seq) : null })
}

export const tenantArea: Area = {
  workspaceOps: { "tenant.freeze": workspaceMemberOps["access.freeze"]!, "tenant.audit": { auth: ["account"], handler(ctx, _p, raw, invocation) { return workspaceAudit(ctx, raw, invocation) } } },
  name: "tenant",
  migrations: [],
}
