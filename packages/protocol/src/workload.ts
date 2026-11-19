// Workloads: short-lived child keys a device creates under itself, each
// with a scope that can only narrow the device's. A hosted agent platform,
// a CI runner fanning out jobs or a harness starting subagents gives every
// task its own workload, so the vault itself keeps one task out of another's
// credentials, approvals and runs, and the audit names the task.
//
// A workload signs its own requests: the proof's header `kid` is the
// workload id, `dev` the parent device and `wkl` the workload id. Only the
// parent device's own key creates, renews, lists or revokes workloads; a
// workload never creates another.
//
// Machine routes, signed by the parent device:
//   POST   /v1/workloads              WorkloadCreate        -> 201 WorkloadView
//   GET    /v1/workloads              (active only)         -> WorkloadList
//   GET    /v1/workloads/:id                                -> WorkloadView
//   POST   /v1/workloads/:id/renew    WorkloadRenew         -> WorkloadView
//   DELETE /v1/workloads/:id          (idempotent)          -> WorkloadView, state revoked
// GET /v1/me signed by a workload answers the device and `workload`.

import { z } from "zod"
import { DeviceModeSchema, DeviceTagSchema } from "./workspace.ts"

export const WORKLOAD_ID = /^wl_[A-Za-z0-9_-]{8,64}$/
export const WorkloadIdSchema = z.string().regex(WORKLOAD_ID)

// The same alphabet and length as a session label. Chosen by the machine,
// so every page that shows it marks it as the machine's words.
export const WorkloadLabelSchema = z.string().regex(/^[A-Za-z0-9_.:-]{1,120}$/)

export const WORKLOAD_DEFAULT_TTL_SECONDS = 60 * 60
export const WORKLOAD_MAX_TTL_SECONDS = 24 * 60 * 60
export const WORKLOAD_MAX_LIFE_SECONDS = 7 * 24 * 60 * 60
export const WORKLOAD_MAX_LIVE_PER_DEVICE = 256

const ItemSlug = z.string().regex(/^[a-z][a-z0-9-]{1,63}$/).refine((s) => !s.endsWith("-") && !s.includes("--"), "invalid slug")

// Each field narrows the device's scope; an absent field adds no narrowing.
// The vault refuses a tag, project or mode outside the device's scope with
// bad_request. Items are not checked for existence at creation, since an
// intake or a connection the workload asks for may create one later; an item
// outside the device's reach is simply never usable.
export const WorkloadScopeSchema = z.strictObject({
  items: z.array(ItemSlug).min(1).max(64).optional(),
  tags: z.array(DeviceTagSchema).min(1).max(32).optional(),
  projects: z.array(z.string().min(1).max(64)).min(1).max(32).optional(),
  modes: z.array(DeviceModeSchema).min(1).max(6).optional(),
})
export type WorkloadScope = z.infer<typeof WorkloadScopeSchema>

export const WorkloadJwkSchema = z.strictObject({ kty: z.literal("EC"), crv: z.literal("P-256"), x: z.string().min(1).max(64), y: z.string().min(1).max(64) })

export const WorkloadCreateSchema = z.strictObject({
  jwk: WorkloadJwkSchema,
  label: WorkloadLabelSchema,
  ttlSeconds: z.int().min(60).max(WORKLOAD_MAX_TTL_SECONDS).optional(),
  scope: WorkloadScopeSchema,
})
export type WorkloadCreate = z.infer<typeof WorkloadCreateSchema>

// Moves expiresAt to now + ttlSeconds, never past hardExpiresAt.
export const WorkloadRenewSchema = z.strictObject({ ttlSeconds: z.int().min(60).max(WORKLOAD_MAX_TTL_SECONDS).optional() })
export type WorkloadRenew = z.infer<typeof WorkloadRenewSchema>

export const WorkloadStateSchema = z.enum(["active", "expired", "revoked"])
export type WorkloadState = z.infer<typeof WorkloadStateSchema>

// device: the parent device revoked it; member: a person revoked it from the
// machine's page; device_revoked: the parent device was revoked;
// owner_inactive: the device's owner was suspended, removed or left, or its
// owning team was deleted.
export const WorkloadRevokedBySchema = z.enum(["device", "member", "device_revoked", "owner_inactive"])

export const WorkloadViewSchema = z.strictObject({
  workload: WorkloadIdSchema,
  device: z.string().min(1).max(128),
  label: WorkloadLabelSchema,
  thumbprint: z.string(),
  scope: WorkloadScopeSchema,
  state: WorkloadStateSchema,
  createdAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  hardExpiresAt: z.iso.datetime(),
  lastSeenAt: z.iso.datetime().nullable(),
  revokedAt: z.iso.datetime().nullable(),
  revokedBy: WorkloadRevokedBySchema.nullable(),
})
export type WorkloadView = z.infer<typeof WorkloadViewSchema>

export const WorkloadListSchema = z.strictObject({ workloads: z.array(WorkloadViewSchema).max(WORKLOAD_MAX_LIVE_PER_DEVICE) })
export type WorkloadList = z.infer<typeof WorkloadListSchema>
