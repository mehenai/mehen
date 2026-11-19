// The platform directory in D1: platforms, their public keys, and one
// managed workspace per subject a platform names. D1 holds no secrets, so
// a key row is only the public half, and a subject's secrets live in its
// own workspace object.

import { type DeviceJwk, type PlatformDefaults, PlatformDefaultsShapeSchema, PlatformJwkSchema, type PlatformLimits, PlatformLimitsSchema, type PlatformStatus, PlatformStatusSchema } from "@mehen/protocol"
import { z } from "zod"

export const MANAGED_WORKSPACE_STATUSES = ["creating", "active", "deleting", "deleted", "purged"] as const
export type ManagedWorkspaceStatus = (typeof MANAGED_WORKSPACE_STATUSES)[number]
// The statuses the unique index managed_workspaces_live covers: at most one
// such workspace per platform and subject.
export const LIVE_WORKSPACE_STATUSES = ["creating", "active", "deleting"] as const

export type PlatformRecord = {
  id: string
  slug: string
  name: string
  status: PlatformStatus
  limits: PlatformLimits
  defaults: PlatformDefaults
  defaultsRevision: number
  createdAt: number
  statusAt: number
  statusReason: string | null
  retireAfter: number | null
}

export type PlatformKeyRecord = {
  id: string
  platform: PlatformRecord
  jwk: DeviceJwk
  createdAt: number
  expiresAt: number | null
  revokedAt: number | null
}

export type ManagedWorkspaceRecord = {
  tenant: string
  platform: string
  subject: string | null
  subjectHash: string
  status: ManagedWorkspaceStatus
  createdAt: number
  deletedAt: number | null
  purgeAfter: number | null
  finalAuditHead: string | null
}

// What a managed workspace reads of its platform, at most every
// PLATFORM_REFRESH_SECONDS, and never stores.
export type ManagedPlatformState = {
  platform: { id: string; slug: string; name: string; status: PlatformStatus; removing: boolean; limits: PlatformLimits; defaults: PlatformDefaults; defaultsRevision: number }
  workspace: { status: ManagedWorkspaceStatus; subject: string | null }
}

const PlatformRowSchema = z.object({
  id: z.string(),
  slug: z.string(),
  name: z.string(),
  status: PlatformStatusSchema,
  limits: z.string(),
  defaults: z.string(),
  defaults_rev: z.number().int().positive(),
  created_at: z.number(),
  status_at: z.number(),
  status_reason: z.string().nullable(),
  retire_after: z.number().nullable(),
})

const ManagedWorkspaceRowSchema = z.object({
  tenant: z.string(),
  platform: z.string(),
  subject: z.string().nullable(),
  subject_hash: z.string(),
  status: z.enum(MANAGED_WORKSPACE_STATUSES),
  created_at: z.number(),
  deleted_at: z.number().nullable(),
  purge_after: z.number().nullable(),
  final_audit_head: z.string().nullable(),
})

export const PLATFORM_COLUMNS = "p.id,p.slug,p.name,p.status,p.limits,p.defaults,p.defaults_rev,p.created_at,p.status_at,p.status_reason,p.retire_after"
export const WORKSPACE_COLUMNS = "w.tenant,w.platform,w.subject,w.subject_hash,w.status,w.created_at,w.deleted_at,w.purge_after,w.final_audit_head"

export function platformRecord(raw: unknown): PlatformRecord {
  const row = PlatformRowSchema.parse(raw)
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    status: row.status,
    limits: PlatformLimitsSchema.parse(JSON.parse(row.limits)),
    defaults: PlatformDefaultsShapeSchema.parse(JSON.parse(row.defaults)),
    defaultsRevision: row.defaults_rev,
    createdAt: row.created_at,
    statusAt: row.status_at,
    statusReason: row.status_reason,
    retireAfter: row.retire_after,
  }
}

export function managedWorkspaceRecord(raw: unknown): ManagedWorkspaceRecord {
  const row = ManagedWorkspaceRowSchema.parse(raw)
  return {
    tenant: row.tenant,
    platform: row.platform,
    subject: row.subject,
    subjectHash: row.subject_hash,
    status: row.status,
    createdAt: row.created_at,
    deletedAt: row.deleted_at,
    purgeAfter: row.purge_after,
    finalAuditHead: row.final_audit_head,
  }
}

// A retirement whose date has passed acts as a suspension until the sweep
// has deleted every subject and marked the platform retired.
export function effectivePlatformStatus(platform: Pick<PlatformRecord, "status" | "retireAfter">, now: number): PlatformStatus {
  if (platform.status === "retiring" && platform.retireAfter !== null && platform.retireAfter <= now) return "suspended"
  return platform.status
}

export async function readPlatform(db: D1Database, id: string): Promise<PlatformRecord | null> {
  const row = await db.prepare(`SELECT ${PLATFORM_COLUMNS} FROM platforms p WHERE p.id=?`).bind(id).first()
  return row ? platformRecord(row) : null
}

export async function readPlatformBySlug(db: D1Database, slug: string): Promise<PlatformRecord | null> {
  const row = await db.prepare(`SELECT ${PLATFORM_COLUMNS} FROM platforms p WHERE p.slug=?`).bind(slug).first()
  return row ? platformRecord(row) : null
}

// One D1 read: the key by its id, with its platform.
export async function readPlatformKey(db: D1Database, kid: string): Promise<PlatformKeyRecord | null> {
  const row = await db
    .prepare(`SELECT k.id AS key_id,k.jwk AS key_jwk,k.created_at AS key_created_at,k.expires_at AS key_expires_at,k.revoked_at AS key_revoked_at,${PLATFORM_COLUMNS} FROM platform_keys k JOIN platforms p ON p.id=k.platform WHERE k.id=?`)
    .bind(kid)
    .first<Record<string, unknown>>()
  if (!row) return null
  const key = z.object({ key_id: z.string(), key_jwk: z.string(), key_created_at: z.number(), key_expires_at: z.number().nullable(), key_revoked_at: z.number().nullable() }).parse(row)
  return { id: key.key_id, platform: platformRecord(row), jwk: PlatformJwkSchema.parse(JSON.parse(key.key_jwk)), createdAt: key.key_created_at, expiresAt: key.key_expires_at, revokedAt: key.key_revoked_at }
}

// The subject's workspace as its platform sees it: the live one, else the
// latest deleted one awaiting its purge (so its audit can still be read).
// Found only under the platform that names it, so another platform's
// identical subject string is a different row or none.
export async function findSubjectWorkspace(db: D1Database, platform: string, subject: string): Promise<ManagedWorkspaceRecord | null> {
  const row = await db
    .prepare(`SELECT ${WORKSPACE_COLUMNS} FROM managed_workspaces w WHERE w.platform=? AND w.subject=? AND w.status!='purged' ORDER BY CASE WHEN w.status IN ('creating','active','deleting') THEN 0 ELSE 1 END, w.created_at DESC LIMIT 1`)
    .bind(platform, subject)
    .first()
  return row ? managedWorkspaceRecord(row) : null
}

// The interface a managed workspace reads its platform through: one D1
// query for the platform's row and the workspace's own status.
export async function readManagedPlatform(db: D1Database, tenant: string, now = Date.now()): Promise<ManagedPlatformState | null> {
  const row = await db
    .prepare(`SELECT ${PLATFORM_COLUMNS},p.removing_at IS NOT NULL AS removing,w.status AS workspace_status,w.subject AS workspace_subject FROM managed_workspaces w JOIN platforms p ON p.id=w.platform WHERE w.tenant=?`)
    .bind(tenant)
    .first<Record<string, unknown>>()
  if (!row) return null
  const platform = platformRecord(row)
  const workspace = z.object({ removing: z.number().int(), workspace_status: z.enum(MANAGED_WORKSPACE_STATUSES), workspace_subject: z.string().nullable() }).parse(row)
  return {
    platform: { id: platform.id, slug: platform.slug, name: platform.name, status: effectivePlatformStatus(platform, now), removing: workspace.removing === 1, limits: platform.limits, defaults: platform.defaults, defaultsRevision: platform.defaultsRevision },
    workspace: { status: workspace.workspace_status, subject: workspace.workspace_subject },
  }
}
