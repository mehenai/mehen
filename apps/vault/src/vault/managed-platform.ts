// What a managed workspace knows of its platform (D0 1.5, 1.8): the
// platform's row (status, limits, defaults and their revision) and the
// workspace's own directory status, read from D1 at most every
// PLATFORM_REFRESH_SECONDS and held in memory only. Nothing here is ever
// stored in the workspace: a change at the platform reaches every workspace
// within the interval, with no call into any of them.
//
// This module imports no area, so every area can use it.

import { DEFAULT_PLATFORM_LIMITS, PLATFORM_REFRESH_SECONDS, PlatformDefaultsShapeSchema, PlatformLimitsSchema, PlatformStatusSchema, customItemPolicy, managedItemPolicy, type PlatformDefaults, type PlatformLimits, type PlatformStatus } from "@mehen/protocol"
import { z } from "zod"
import { VaultError } from "../http.ts"
import { GENESIS, managedAuditGenesis } from "./audit.ts"
import type { AuditEvent, VaultContext } from "./core.ts"
import type { ItemRecord } from "./services.ts"
import { managedSetting, setting, type ManagedSetting } from "./areas/workspace-runtime.ts"

export const ManagedWorkspaceStatusSchema = z.enum(["creating", "active", "deleting", "deleted", "purged"])
export type ManagedWorkspaceStatus = z.infer<typeof ManagedWorkspaceStatusSchema>

// What a managed workspace reads of its platform: the platform's row, with
// its effective status and whether the operator is removing it, and this
// workspace's own row in managed_workspaces. The same shape as the
// directory's readManagedPlatform (platform/registry.ts).
export type ManagedPlatformRow = {
  platform: { id: string; slug: string; name: string; status: PlatformStatus; removing: boolean; limits: PlatformLimits; defaults: PlatformDefaults; defaultsRevision: number }
  workspace: { status: ManagedWorkspaceStatus; subject: string | null }
}

// The seam to the platform directory (D0 1.2). `read` has the signature of
// the directory's readManagedPlatform(db, tenant) (platform/registry.ts):
// null when the directory holds no managed workspace for the tenant.
// `purged` records a workspace its own alarm purged: its final audit head,
// with its subject dropped and the hash kept as the tombstone (the
// directory's sweep records the purges it makes itself).
export type ManagedDirectory = {
  read(db: D1Database, tenant: string): Promise<ManagedPlatformRow | null>
  purged(db: D1Database, tenant: string, finalAuditHead: string | null): Promise<void>
}

const D1RowSchema = z.object({
  id: z.string(),
  slug: z.string(),
  name: z.string(),
  status: PlatformStatusSchema,
  limits: z.string(),
  defaults: z.string(),
  defaults_rev: z.number().int().positive(),
  retire_after: z.number().nullable(),
  removing: z.number().int(),
  workspace_status: ManagedWorkspaceStatusSchema,
  workspace_subject: z.string().nullable(),
})

// One D1 query: the platform's row joined to this workspace's. A platform
// past its retirement date is retired, whatever the sweep has written yet.
export const d1ManagedDirectory: ManagedDirectory = {
  async read(db, tenant) {
    const raw = await db.prepare("SELECT p.id,p.slug,p.name,p.status,p.limits,p.defaults,p.defaults_rev,p.retire_after,p.removing_at IS NOT NULL AS removing,w.status AS workspace_status,w.subject AS workspace_subject FROM managed_workspaces w JOIN platforms p ON p.id=w.platform WHERE w.tenant=?").bind(tenant).first()
    if (raw === null) return null
    const row = D1RowSchema.parse(raw)
    const status: PlatformStatus = row.status === "retiring" && row.retire_after !== null && row.retire_after <= Date.now() ? "retired" : row.status
    return {
      platform: { id: row.id, slug: row.slug, name: row.name, status, removing: row.removing === 1, limits: PlatformLimitsSchema.parse({ ...DEFAULT_PLATFORM_LIMITS, ...(JSON.parse(row.limits) as object) }), defaults: PlatformDefaultsShapeSchema.parse(JSON.parse(row.defaults)), defaultsRevision: row.defaults_rev },
      workspace: { status: row.workspace_status, subject: row.workspace_subject },
    }
  },
  async purged(db, tenant, finalAuditHead) {
    await db.prepare("UPDATE managed_workspaces SET status='purged',subject=NULL,final_audit_head=COALESCE(?,final_audit_head) WHERE tenant=? AND status='deleted'").bind(finalAuditHead, tenant).run()
  },
}

let directory: ManagedDirectory = d1ManagedDirectory
// Replaces the directory, with the registry's readManagedPlatform or a test's stub; answers the
// function that puts the previous one back.
export function registerManagedDirectory(next: ManagedDirectory): () => void {
  const previous = directory
  directory = next
  return () => { directory = previous }
}
export function managedDirectory(): ManagedDirectory { return directory }

// Keyed by the object's storage: one entry per live object, gone with it.
const held = new WeakMap<DurableObjectStorage, { row: ManagedPlatformRow; readAt: number }>()
const purgedObjects = new WeakSet<DurableObjectStorage>()

export function platformUnreadable(): VaultError {
  return new VaultError("upstream_failed", "The platform could not be read; try again.", { retryAfter: 5 })
}
export function platformSuspended(): VaultError {
  return new VaultError("platform_suspended", "This platform is suspended.")
}

// Reads this workspace's platform row when the one held is older than the
// interval (or always, with `force`), and holds it for this object; null
// when the directory holds no managed workspace for this tenant.
export async function readManagedPlatform(ctx: VaultContext, force = false): Promise<ManagedPlatformRow | null> {
  const current = held.get(ctx.storage)
  if (!force && current && ctx.now() - current.readAt < PLATFORM_REFRESH_SECONDS * 1000) return current.row
  let row: ManagedPlatformRow | null
  try {
    row = await directory.read(ctx.env.DB, ctx.tenant)
  } catch (error) {
    console.error(JSON.stringify({ at: "managed.platform_read", error: error instanceof Error ? error.name : "unknown" }))
    throw platformUnreadable()
  }
  if (row === null) held.delete(ctx.storage)
  else held.set(ctx.storage, { row, readAt: ctx.now() })
  return row
}

// The platform's row for this managed workspace, read at most every
// interval; null in every other workspace.
export async function refreshManagedPlatform(ctx: VaultContext, force = false): Promise<ManagedPlatformRow | null> {
  return managedSetting(ctx) ? readManagedPlatform(ctx, force) : null
}

// The row as last read, for synchronous code inside a call (policy at use,
// approval snapshots, limits). Null before the first read.
export function cachedManagedPlatform(ctx: VaultContext): ManagedPlatformRow | null {
  return held.get(ctx.storage)?.row ?? null
}

// The platform row a managed call needs: the row is read before every
// platform and device call, so a miss here fails closed.
export function heldManagedPlatform(ctx: VaultContext): ManagedPlatformRow {
  const row = cachedManagedPlatform(ctx)
  if (!row) throw platformUnreadable()
  return row
}

// Platform calls keep working while the platform is retiring; anything else
// is suspension.
export function platformLive(status: PlatformStatus): boolean {
  return status === "active" || status === "retiring"
}

export type ManagedStatus = "active" | "deleting" | "deleted"
export function managedStatus(ctx: VaultContext): ManagedStatus {
  return setting<ManagedStatus>(ctx, "managed_status", "active")
}

// The policy an item is used under: in a managed workspace the catalogue's
// current policy for its template or provider plus the platform's rules,
// computed now and never stored (managedItemPolicy); with no platform row
// held, every request is held. Elsewhere the item's own policy.
export function managedPolicyView<T extends ItemRecord>(ctx: VaultContext, item: T): T {
  if (!managedSetting(ctx)) return item
  const row = cachedManagedPlatform(ctx)
  return { ...item, policy: row ? managedItemPolicy(item.provider, row.platform.defaults) : customItemPolicy(false) }
}

// The defaults' revision every approval snapshot in a managed workspace
// binds, so a change stales what was approved under the old rules. Null in
// every other workspace, whose snapshots are unchanged: only a managed
// workspace ever holds a platform row, and it holds one through every
// device and platform call.
export function managedDefaultsRevision(ctx: VaultContext): number | null {
  return cachedManagedPlatform(ctx)?.platform.defaultsRevision ?? null
}

// While its platform is suspended, or cannot be read, a managed workspace's
// scheduled work (OAuth refreshes among it) waits: a failed read never
// falls back to the row held from before, however recent.
export async function managedWorkWaits(ctx: VaultContext): Promise<boolean> {
  if (!managedSetting(ctx)) return false
  const row = await readManagedPlatform(ctx).catch(() => null)
  return row === null || !platformLive(row.platform.status)
}

// What a device may still do while its platform is suspended: stop itself,
// or stop the workspace.
const SUSPENDED_DEVICE_OPS = new Set(["devices.revokeSelf", "devices.self_revoke", "tenant.freeze", "access.freeze"])

// Before a device call is handled in a managed workspace, from the row read
// at most every interval: a subject being deleted refuses every call, and a
// suspended platform every call but stopping.
export async function admitManagedDeviceCall(ctx: VaultContext, op: string): Promise<void> {
  if (!managedSetting(ctx)) return
  const row = await readManagedPlatform(ctx)
  // The directory may still say creating for up to the interval after the
  // workspace was made.
  const listed = row?.workspace.status === "creating" || row?.workspace.status === "active"
  if (row === null || managedStatus(ctx) !== "active" || !listed) throw new VaultError("device_revoked", "This device has been revoked.")
  if (!platformLive(row.platform.status) && !SUSPENDED_DEVICE_OPS.has(op)) throw platformSuspended()
}

// Every row a managed workspace writes names its platform, whoever caused
// it, and its chain starts from the platform's own first link. A private
// event's minimal record keeps its fields, with the platform beside them:
// the platform reads the whole chain, so nothing is hidden by it.
export function managedAuditShape(sql: SqlStorage, tenant: string, event: AuditEvent): { event: AuditEvent; genesis: string } {
  const raw = sql.exec<{ value: string }>("SELECT value FROM tenant_state WHERE key='managed'").toArray()[0]
  if (!raw) return { event, genesis: GENESIS }
  const managed = JSON.parse(raw.value) as ManagedSetting
  const { private: minimal, privateOwner: _owner, ...plain } = event
  const detail = minimal ? { ...minimal, ...event.detail, platform: managed.platform } : { ...event.detail, platform: managed.platform }
  return { event: { ...plain, target: event.target ?? minimal?.item ?? null, detail }, genesis: managedAuditGenesis(managed.platform, tenant) }
}

// The chain's first link for this workspace.
export function auditGenesisOf(ctx: VaultContext): string {
  const managed = managedSetting(ctx)
  return managed ? managedAuditGenesis(managed.platform, ctx.tenant) : GENESIS
}

// A purged object answers nothing until it is next constructed, empty.
export function markManagedPurged(storage: DurableObjectStorage): void { purgedObjects.add(storage) }
export function managedPurged(storage: DurableObjectStorage): boolean { return purgedObjects.has(storage) }
