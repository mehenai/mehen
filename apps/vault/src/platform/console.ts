// What the operator console and a platform admin's pages read from D1:
// who may open them, and a platform's status, limits, keys, subject counts,
// usage, admins and events. Every answer is built from the directory's own
// rows and parsed with platform-console.ts's schemas; nothing here reaches
// a managed workspace, so nothing here can show its items, values or
// requests.

import { type AdminPlatformDetail, AdminPlatformDetailSchema, type AdminPlatformSummary, AdminPlatformSummarySchema, type ConsoleAccess, ConsoleAccessSchema, INITIAL_PLATFORM_DEFAULTS, type OperatorPlatformDetail, OperatorPlatformDetailSchema, type OperatorPlatformSummary, OperatorPlatformSummarySchema, PLATFORM_EVENTS_PAGE_SIZE, type PlatformAdminView, type PlatformEventPage, PlatformEventPageSchema, type PlatformKeyView, PlatformLimitsSchema, type PlatformRemoval, type PlatformUsage, type SubjectCountsByStatus, PlatformDefaultsShapeSchema, PlatformStatusSchema } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { type PlatformRow, platformRowById, platformRowBySlug } from "./operator-plan.ts"
import { MANAGED_WORKSPACE_STATUSES } from "./registry.ts"
import { activityCounts, activityEventId } from "./sweeps.ts"

const DAY_MS = 86_400_000

function iso(ms: number): string {
  return new Date(ms).toISOString()
}

function isoOrNull(ms: number | null): string | null {
  return ms === null ? null : iso(ms)
}

export async function isOperator(env: Env, account: string): Promise<boolean> {
  const row = await env.DB.prepare("SELECT is_operator FROM accounts WHERE id=? AND status='active'").bind(account).first<{ is_operator: number }>()
  return row?.is_operator === 1
}

export async function isPlatformAdmin(env: Env, account: string, platform: string): Promise<boolean> {
  const row = await env.DB.prepare("SELECT 1 AS admin FROM platform_admins pa JOIN accounts a ON a.id=pa.account WHERE pa.platform=? AND pa.account=? AND pa.removed_at IS NULL AND a.status='active'").bind(platform, account).first()
  return row !== null
}

export async function readPlatformRowBySlug(env: Env, slug: string): Promise<PlatformRow | null> {
  return env.DB.prepare(platformRowBySlug(slug)).first<PlatformRow>()
}

export async function readPlatformRowById(env: Env, id: string): Promise<PlatformRow | null> {
  return env.DB.prepare(platformRowById(id)).first<PlatformRow>()
}

async function administeredRows(env: Env, account: string): Promise<PlatformRow[]> {
  const ids = await env.DB.prepare("SELECT pa.platform FROM platform_admins pa JOIN platforms p ON p.id=pa.platform WHERE pa.account=? AND pa.removed_at IS NULL ORDER BY p.name,p.id").bind(account).all<{ platform: string }>()
  const rows: PlatformRow[] = []
  for (const { platform } of ids.results) {
    const row = await readPlatformRowById(env, platform)
    if (row) rows.push(row)
  }
  return rows
}

export async function consoleAccess(env: Env, account: string): Promise<ConsoleAccess> {
  const rows = await administeredRows(env, account)
  return ConsoleAccessSchema.parse({ operator: await isOperator(env, account), platforms: rows.map((row) => ({ id: row.id, slug: row.slug, name: row.name })) })
}

export async function hasAdministeredPlatforms(env: Env, account: string): Promise<boolean> {
  return (await administeredRows(env, account)).length > 0
}

async function keysOf(env: Env, platform: string, now: number): Promise<PlatformKeyView[]> {
  const rows = await env.DB.prepare("SELECT id,thumbprint,created_at,created_by,expires_at,revoked_at FROM platform_keys WHERE platform=? ORDER BY created_at,id").bind(platform).all<{ id: string; thumbprint: string; created_at: number; created_by: string; expires_at: number | null; revoked_at: number | null }>()
  return rows.results.map((k) => ({ id: k.id, thumbprint: k.thumbprint, createdAt: iso(k.created_at), createdBy: k.created_by, expiresAt: isoOrNull(k.expires_at), revokedAt: isoOrNull(k.revoked_at), live: k.revoked_at === null && (k.expires_at === null || k.expires_at > now) }))
}

async function subjectCounts(env: Env, platform: string): Promise<SubjectCountsByStatus> {
  const rows = await env.DB.prepare("SELECT status,COUNT(*) AS n FROM managed_workspaces WHERE platform=? GROUP BY status").bind(platform).all<{ status: string; n: number }>()
  const counts = Object.fromEntries(MANAGED_WORKSPACE_STATUSES.map((status) => [status, rows.results.find((row) => row.status === status)?.n ?? 0]))
  return counts as SubjectCountsByStatus
}

async function adminsOf(env: Env, platform: string): Promise<PlatformAdminView[]> {
  const rows = await env.DB.prepare("SELECT pa.account,a.name,pa.added_at,pa.added_by FROM platform_admins pa JOIN accounts a ON a.id=pa.account WHERE pa.platform=? AND pa.removed_at IS NULL ORDER BY pa.added_at,pa.account").bind(platform).all<{ account: string; name: string; added_at: number; added_by: string }>()
  return rows.results.map((row) => ({ account: row.account, name: row.name, addedAt: iso(row.added_at), addedBy: row.added_by }))
}

async function usageOf(env: Env, platform: string): Promise<PlatformUsage> {
  const row = await env.DB.prepare("SELECT at,detail FROM platform_events WHERE id=?").bind(activityEventId(platform)).first<{ at: number; detail: string }>()
  if (!row) return null
  const counts = activityCounts(JSON.parse(row.detail))
  return { asOf: iso(row.at), devices: counts.devices, itemsAdded: counts.added, itemsDeleted: counts.deleted, decisions: counts.decisions, refusals: counts.refusals }
}

function removalOf(row: PlatformRow): PlatformRemoval {
  if (row.removing_at === null) return null
  return { requestedAt: iso(row.removing_at), by: row.removing_by ?? "unknown", slug: row.removed_slug ?? row.slug, completedAt: isoOrNull(row.removed_at) }
}

function defaultsOf(row: PlatformRow) {
  const parsed = PlatformDefaultsShapeSchema.safeParse(JSON.parse(row.defaults))
  return parsed.success ? parsed.data : INITIAL_PLATFORM_DEFAULTS
}

export async function operatorPlatformSummary(env: Env, row: PlatformRow, now = Date.now()): Promise<OperatorPlatformSummary> {
  return OperatorPlatformSummarySchema.parse({
    id: row.id,
    slug: row.slug,
    name: row.name,
    status: PlatformStatusSchema.parse(row.status),
    statusAt: iso(row.status_at),
    statusBy: row.status_by,
    statusReason: row.status_reason,
    retireAfter: isoOrNull(row.retire_after),
    removal: removalOf(row),
    createdAt: iso(row.created_at),
    createdBy: row.created_by,
    limits: PlatformLimitsSchema.parse(JSON.parse(row.limits)),
    subjects: await subjectCounts(env, row.id),
    keys: await keysOf(env, row.id, now),
    admins: await adminsOf(env, row.id),
  })
}

export async function operatorPlatformDetail(env: Env, row: PlatformRow, now = Date.now()): Promise<OperatorPlatformDetail> {
  const operator = await env.DB.prepare("SELECT COUNT(*) AS n FROM platform_events WHERE platform=? AND at>=? AND action LIKE 'operator.%'").bind(row.id, now - DAY_MS).first<{ n: number }>()
  return OperatorPlatformDetailSchema.parse({ ...(await operatorPlatformSummary(env, row, now)), defaults: defaultsOf(row), defaultsRevision: row.defaults_rev, usage: await usageOf(env, row.id), operatorActions24h: operator?.n ?? 0 })
}

export async function operatorPlatformList(env: Env, now = Date.now()): Promise<OperatorPlatformSummary[]> {
  const ids = await env.DB.prepare("SELECT id FROM platforms ORDER BY removed_at IS NOT NULL,name,id").all<{ id: string }>()
  const platforms: OperatorPlatformSummary[] = []
  for (const { id } of ids.results) {
    const row = await readPlatformRowById(env, id)
    if (row) platforms.push(await operatorPlatformSummary(env, row, now))
  }
  return platforms
}

export async function adminPlatformSummary(env: Env, row: PlatformRow): Promise<AdminPlatformSummary> {
  return AdminPlatformSummarySchema.parse({ id: row.id, slug: row.slug, name: row.name, status: PlatformStatusSchema.parse(row.status), retireAfter: isoOrNull(row.retire_after), subjects: await subjectCounts(env, row.id) })
}

export async function adminPlatformDetail(env: Env, row: PlatformRow, now = Date.now()): Promise<AdminPlatformDetail> {
  return AdminPlatformDetailSchema.parse({ ...(await adminPlatformSummary(env, row)), statusAt: iso(row.status_at), limits: PlatformLimitsSchema.parse(JSON.parse(row.limits)), keys: await keysOf(env, row.id, now), defaults: defaultsOf(row), defaultsRevision: row.defaults_rev, usage: await usageOf(env, row.id) })
}

export async function adminPlatformList(env: Env, account: string): Promise<AdminPlatformSummary[]> {
  const rows = await administeredRows(env, account)
  return Promise.all(rows.map((row) => adminPlatformSummary(env, row)))
}

// Newest first, PLATFORM_EVENTS_PAGE_SIZE a page, without the rolling
// activity row (that is the usage). `before` is the last page's `next`.
export async function platformEventPage(env: Env, platform: string, before: string | undefined): Promise<PlatformEventPage> {
  const [at, id] = before === undefined ? [null, null] : [Number(before.slice(0, before.indexOf("."))), before.slice(before.indexOf(".") + 1)]
  const rows = await env.DB.prepare("SELECT id,at,actor,action,detail FROM platform_events WHERE platform=? AND id!=? AND (? IS NULL OR at<? OR (at=? AND id<?)) ORDER BY at DESC,id DESC LIMIT ?")
    .bind(platform, activityEventId(platform), at, at, at, id, PLATFORM_EVENTS_PAGE_SIZE + 1)
    .all<{ id: string; at: number; actor: string; action: string; detail: string }>()
  const page = rows.results.slice(0, PLATFORM_EVENTS_PAGE_SIZE)
  const last = page.at(-1)
  return PlatformEventPageSchema.parse({
    events: page.map((row) => ({ id: row.id, at: iso(row.at), actor: row.actor, action: row.action, detail: JSON.parse(row.detail) as Record<string, unknown> })),
    next: rows.results.length > PLATFORM_EVENTS_PAGE_SIZE && last ? `${last.at}.${last.id}` : null,
  })
}
