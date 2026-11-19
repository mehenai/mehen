// Workloads: short-lived child keys a device creates under itself, each with
// a scope that only narrows the device's (packages/protocol/src/workload.ts).
// The devices area owns the table; this module owns the rows, the proof
// lookup, the device-key rules (a workload never manages workloads; a device
// whose scope says workloads "required" acts only through them), the ending
// of every workload with its device, and the expiry sweep.
//
// Reach is not decided here: the principal carries the workload, and the
// evaluator (principalDevice in access.ts) and deviceCovers (devices.ts)
// intersect its scope with the device's, so no area can forget it.

import { WORKLOAD_DEFAULT_TTL_SECONDS, WORKLOAD_MAX_LIFE_SECONDS, WORKLOAD_MAX_LIVE_PER_DEVICE, WorkloadCreateSchema, WorkloadIdSchema, WorkloadRenewSchema, WorkloadScopeSchema, WorkloadViewSchema, WorkspaceDeviceScopeSchema, canonicalJson, jwkThumbprint, parseProof } from "@mehen/protocol"
import type { CredentialHome, WorkloadScope, WorkloadView, WorkspaceDeviceScope } from "@mehen/protocol"
import { z } from "zod"
import { VaultError } from "../../http.ts"
import type { Area, DeviceAuth, PrincipalWorkload, VaultContext } from "../core.ts"
import type { AccessPrincipal } from "../access.ts"
import { workloadCovers } from "../access.ts"
import { one, randomId, rows } from "../core.ts"
import { refuseFillUnlessOn } from "../fill-unavailable.ts"
import { fillOnly, refuseFillForOldCli, workloadForCli, workloadHiddenFromCli } from "../fill-old-cli.ts"
import { authorise, openWorkloadAskCount, principalOf, registerAccessChangeHook, requireStepUp } from "./workspace-runtime.ts"
import type { WorkspaceInvocationContext } from "./workspace-runtime.ts"

export const WORKLOADS_MIGRATION = `CREATE TABLE workloads (
  id TEXT PRIMARY KEY, device TEXT NOT NULL, label TEXT NOT NULL, jwk TEXT NOT NULL, thumbprint TEXT NOT NULL, scope TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, hard_expires_at INTEGER NOT NULL, last_seen_at INTEGER,
  revoked_at INTEGER, revoked_by TEXT, ended_at INTEGER
);
CREATE INDEX workloads_device ON workloads(device);
CREATE INDEX workloads_thumbprint ON workloads(thumbprint);
CREATE INDEX workloads_live ON workloads(ended_at, expires_at);`

export type WorkloadRow = { id: string; device: string; label: string; jwk: string; thumbprint: string; scope: string; created_at: number; expires_at: number; hard_expires_at: number; last_seen_at: number | null; revoked_at: number | null; revoked_by: WorkloadView["revokedBy"]; ended_at: number | null }

export const WORKLOAD_ENDED_MESSAGE = "This workload has ended. Create a new one from its device."
export function workloadEnded(): VaultError {
  return new VaultError("workload_ended", WORKLOAD_ENDED_MESSAGE, { next: { say: "This task's workload has ended; its device must create a new workload for it." } })
}

const iso = (ms: number) => new Date(ms).toISOString()
export function workloadState(row: WorkloadRow, now: number): WorkloadView["state"] {
  if (row.revoked_at !== null) return "revoked"
  return row.expires_at <= now ? "expired" : "active"
}
export function workloadLive(row: WorkloadRow, now: number): boolean { return workloadState(row, now) === "active" }
export function workloadScope(row: WorkloadRow): WorkloadScope { return WorkloadScopeSchema.parse(JSON.parse(row.scope)) }
export function workloadView(row: WorkloadRow, now: number): WorkloadView {
  return WorkloadViewSchema.parse({ workload: row.id, device: row.device, label: row.label, thumbprint: row.thumbprint, scope: workloadScope(row), state: workloadState(row, now), createdAt: iso(row.created_at), expiresAt: iso(row.expires_at), hardExpiresAt: iso(row.hard_expires_at), lastSeenAt: row.last_seen_at === null ? null : iso(row.last_seen_at), revokedAt: row.revoked_at === null ? null : iso(row.revoked_at), revokedBy: row.revoked_by })
}
export function workloadRow(ctx: VaultContext, id: string): WorkloadRow | null {
  return one(ctx.sql.exec<WorkloadRow>("SELECT * FROM workloads WHERE id=?", id))
}
// The workload an ask names, for people's pages: its id and the label its
// machine gave it. Nothing when no workload asked; spread into requestedBy.
export function askingWorkload(ctx: VaultContext, id: string | null): { workload?: { id: string; label: string } } {
  const row = id === null ? null : workloadRow(ctx, id)
  return row ? { workload: { id: row.id, label: row.label } } : {}
}
export function principalWorkload(row: WorkloadRow): PrincipalWorkload { return { id: row.id, label: row.label, scope: workloadScope(row) } }

// What the proof's `wkl` names, under the device that signed `dev`. An
// unknown id is unauthenticated, as an unknown device is.
export function workloadForProof(ctx: VaultContext, device: string, workload: string): WorkloadRow {
  const row = one(ctx.sql.exec<WorkloadRow>("SELECT * FROM workloads WHERE id=? AND device=?", workload, device))
  if (!row) throw new VaultError("unauthenticated", "This workload is not known to this vault.", { next: { say: "Create the workload from its device, then sign with the key it registered." } })
  return row
}
// Only once the proof verified against the workload's own key: a workload
// that expired or was revoked, or whose device was, has ended. A proof that
// does not verify learns nothing about whether it has.
export function assertWorkloadLive(ctx: VaultContext, device: { revoked_at: number | null }, row: WorkloadRow): void {
  if (device.revoked_at !== null || !workloadLive(row, ctx.now())) throw workloadEnded()
}

// The ops a device whose scope says workloads "required" may still call with
// its own key; and the ops a workload may never call.
const REQUIRED_DEVICE_OPS = new Set(["devices.me", "items.list", "items.describe", "pending.list", "tenant.freeze", "devices.revokeSelf", "devices.self_revoke", "workloads.create", "workloads.list", "workloads.get", "workloads.renew", "workloads.revoke"])
// Freezing stops every member and machine in the workspace, so it stays with
// the device's own key: one task never affects everyone else.
const FREEZE_OPS = new Set(["tenant.freeze", "access.freeze"])
const DEVICE_KEY_OPS = new Set(["workloads.create", "workloads.list", "workloads.get", "workloads.renew", "workloads.revoke", "devices.revokeSelf", "devices.self_revoke", ...FREEZE_OPS])
// Called by the dispatcher after the proof verified, before any handler.
export function assertDeviceKeyRule(ctx: VaultContext, op: string, auth: DeviceAuth): void {
  const claims = parseProof(auth.proof).claims
  if (claims.wkl !== undefined) {
    if (DEVICE_KEY_OPS.has(op)) throw new VaultError("forbidden", op.startsWith("workloads.") ? "A workload cannot manage workloads. Its device's own key creates, renews and revokes them." : FREEZE_OPS.has(op) ? "A workload cannot freeze the workspace. Its device's own key can." : "A workload cannot revoke its device. Its device can revoke this workload.")
    return
  }
  const device = one(ctx.sql.exec<{ scope: string }>("SELECT scope FROM devices WHERE id=?", claims.dev))
  if (!device || REQUIRED_DEVICE_OPS.has(op)) return
  if (WorkspaceDeviceScopeSchema.parse(JSON.parse(device.scope)).workloads === "required") throw new VaultError("workload_required", "This machine acts only through workloads.", { next: { say: "Create a workload for this task with the machine's key and sign the request with the workload's key." } })
}

function parentDevice(ctx: VaultContext, invocation: WorkspaceInvocationContext): { id: string; scope: WorkspaceDeviceScope; thumbprint: string } {
  const principal = principalOf(ctx, invocation.auth)
  if (principal.kind !== "device" || principal.workload !== undefined) throw new VaultError("forbidden", "Only a machine's own key manages its workloads.")
  authorise(ctx, invocation, { type: "device.read_self" }, { device: principal.deviceId }, ctx.now())
  const row = one(ctx.sql.exec<{ id: string; scope: string; thumbprint: string }>("SELECT id,scope,thumbprint FROM devices WHERE id=? AND revoked_at IS NULL", principal.deviceId))
  if (!row) throw new VaultError("not_found", "No such machine.")
  return { id: row.id, scope: WorkspaceDeviceScopeSchema.parse(JSON.parse(row.scope)), thumbprint: row.thumbprint }
}
function ownWorkload(ctx: VaultContext, device: string, id: string): WorkloadRow {
  const row = WorkloadIdSchema.safeParse(id).success ? workloadRow(ctx, id) : null
  if (!row || row.device !== device) throw new VaultError("not_found", "No such workload.")
  return row
}
// Each field the workload names must sit inside the device's: tags and
// projects within a non-empty device list, modes within the device's modes.
function assertWithinDevice(scope: WorkloadScope, device: WorkspaceDeviceScope): void {
  const outside = (field: string, values: readonly string[], allowed: readonly string[]) => {
    const extra = values.filter((v) => !allowed.includes(v))
    if (extra.length) throw new VaultError("bad_request", `scope.${field}: ${extra.map((v) => `"${v}"`).join(", ")} ${extra.length === 1 ? "is" : "are"} outside this machine's scope.`)
  }
  if (scope.tags && device.tags.length > 0) outside("tags", scope.tags, device.tags)
  if (scope.projects && device.projects.length > 0) outside("projects", scope.projects, device.projects)
  if (scope.modes) outside("modes", scope.modes, device.modes)
}
function auditWorkload(ctx: VaultContext, actor: string, action: string, row: WorkloadRow, extra: Record<string, unknown> = {}): void {
  ctx.audit({ actor, action, target: row.id, detail: { device: row.device, workload: { id: row.id, label: row.label }, ...extra } })
}
function live(ctx: VaultContext, device: string): WorkloadRow[] {
  return rows(ctx.sql.exec<WorkloadRow>("SELECT * FROM workloads WHERE device=? AND revoked_at IS NULL AND expires_at>? ORDER BY created_at,id", device, ctx.now()))
}
// Ends what a workload asked for that nobody may use any more: its pending
// approvals and open credential requests, and its live runs.
function endWorkloadAsks(ctx: VaultContext, ids: string[]): void {
  for (const id of ids) {
    ctx.sql.exec("UPDATE approvals SET policy_status='stale' WHERE workload=? AND status='pending' AND policy_status IS NULL", id)
    ctx.sql.exec("UPDATE workspace_credential_requests SET status='cancelled' WHERE requester_workload=? AND status='open'", id)
    ctx.sql.exec("DELETE FROM run_placeholders WHERE run IN (SELECT id FROM runs WHERE workload=? AND ended_at IS NULL)", id)
    ctx.sql.exec("UPDATE runs SET ended_at=? WHERE workload=? AND ended_at IS NULL", ctx.now(), id)
  }
}
function revokeRows(ctx: VaultContext, ids: string[], by: NonNullable<WorkloadRow["revoked_by"]>): void {
  for (const id of ids) ctx.sql.exec("UPDATE workloads SET revoked_at=?,revoked_by=?,ended_at=COALESCE(ended_at,?) WHERE id=? AND revoked_at IS NULL", ctx.now(), by, ctx.now(), id)
  endWorkloadAsks(ctx, ids)
}
// A workload never outlives its device: revoking the device, or its owner
// losing standing, ends every workload it made, and says which it was.
type DeviceEnding = "device_revoked" | "owner_inactive"
export function endDeviceWorkloads(ctx: VaultContext, devices: string[], reason: DeviceEnding): void {
  for (const device of devices) {
    const ended = rows(ctx.sql.exec<WorkloadRow>("SELECT * FROM workloads WHERE device=? AND revoked_at IS NULL", device))
    if (!ended.length) continue
    revokeRows(ctx, ended.map((w) => w.id), reason)
    ctx.audit({ actor: "system", action: "workload.revoke_all", target: device, detail: { device, reason, workloads: ended.map((w) => ({ id: w.id, label: w.label })) } })
  }
}
const OWNER_ENDINGS = new Set(["suspend", "remove", "leave"])
registerAccessChangeHook("workloads", (ctx, member, reason, target) => {
  if (reason !== "revoke" && !OWNER_ENDINGS.has(reason)) return
  const devices = target.device ? [target.device] : member !== null ? rows(ctx.sql.exec<{ id: string }>("SELECT id FROM devices WHERE owner_kind='member' AND owner_id=?", member)).map((d) => d.id) : []
  endDeviceWorkloads(ctx, devices, reason === "revoke" ? "device_revoked" : "owner_inactive")
})
// A deleted team leaves its machines with no owner standing.
registerAccessChangeHook("workloads-team", (ctx, _member, reason, target) => {
  if (reason !== "team.delete" || !target.team) return
  endDeviceWorkloads(ctx, rows(ctx.sql.exec<{ id: string }>("SELECT id FROM devices WHERE owner_kind='team' AND owner_id=?", target.team)).map((d) => d.id), "owner_inactive")
})

export const WORKLOAD_SWEEP_KEY = "workloads"
function scheduleSweep(ctx: VaultContext): void {
  const next = one(ctx.sql.exec<{ due: number | null }>("SELECT MIN(expires_at) AS due FROM workloads WHERE ended_at IS NULL"))?.due
  if (next !== null && next !== undefined) ctx.schedule("devices", WORKLOAD_SWEEP_KEY, next)
}
// Expiry is checked on every request; this marks each expired workload ended
// once, audits it, and ends what it asked for.
export function sweepWorkloads(ctx: VaultContext): void {
  ctx.storage.transactionSync(() => {
    const expired = rows(ctx.sql.exec<WorkloadRow>("SELECT * FROM workloads WHERE ended_at IS NULL AND (revoked_at IS NOT NULL OR expires_at<=?)", ctx.now()))
    for (const row of expired) {
      ctx.sql.exec("UPDATE workloads SET ended_at=? WHERE id=?", ctx.now(), row.id)
      if (row.revoked_at === null) auditWorkload(ctx, "system", "workload.expired", row)
    }
    endWorkloadAsks(ctx, expired.map((w) => w.id))
    scheduleSweep(ctx)
  })
}

const quoted = (values: readonly string[]) => values.map((v) => `"${v}"`).join(", ")
function liveWorkloadScope(ctx: VaultContext, principal: AccessPrincipal): WorkloadScope | undefined {
  if (principal.kind !== "device" || principal.workload === undefined) return undefined
  const row = workloadRow(ctx, principal.workload)
  if (!row || !workloadLive(row, ctx.now())) throw workloadEnded()
  return workloadScope(row)
}
const cannotSee = (slug: string, missing: string) => new VaultError("forbidden", `This workload could not see "${slug}". To ask for it, ${missing}.`, { next: { say: "Ask for a credential this task's workload can see, or create a workload whose scope covers it." } })
// An intake or connection a workload asks for must name a credential its
// scope names, homed (when in a project) in a project its scope names:
// refused before anything is created or any name is probed.
export function assertWorkloadMayAsk(ctx: VaultContext, principal: AccessPrincipal, slug: string, home: CredentialHome): void {
  const scope = liveWorkloadScope(ctx, principal)
  if (scope?.items && !scope.items.includes(slug)) throw new VaultError("forbidden", `This workload may only ask for ${quoted(scope.items)}.`, { next: { say: "Ask for a credential this task's workload names, or create a workload whose scope names it." } })
  if (scope?.projects && home.kind === "project" && !scope.projects.includes(home.project)) throw cannotSee(slug, `home it in one of this workload's projects: ${quoted(scope.projects)}`)
}
// The credential an intake or connection is about: its slug and home as the
// request gives them, and its tags (the request's, or a rotation's target's).
export type AskedCredential = { slug: string; tags: readonly string[]; home: CredentialHome }
// Nor does a workload open an ask it could not then follow: the evaluator's
// own workloadCovers must let it see the credential, so the ask and its
// status poll cannot drift. Refused before anything is created or counted.
export function assertWorkloadMayFollow(ctx: VaultContext, principal: AccessPrincipal, asked: AskedCredential): void {
  assertWorkloadMayAsk(ctx, principal, asked.slug, asked.home)
  const scope = liveWorkloadScope(ctx, principal)
  if (scope === undefined || workloadCovers(scope, { id: "", slug: asked.slug, tags: [...asked.tags], home: asked.home })) return
  throw cannotSee(asked.slug, `give it one of this workload's tags: ${quoted(scope.tags ?? [])}`)
}
// A connection from a workload scoped by items also names the provider's
// OAuth client: the vault reads the client (or asks for it) as the workload.
export function assertWorkloadMayConnect(ctx: VaultContext, principal: AccessPrincipal, slug: string, clientSlug: string, home: CredentialHome): void {
  assertWorkloadMayAsk(ctx, principal, slug, home)
  const items = liveWorkloadScope(ctx, principal)?.items
  if (items && !items.includes(clientSlug)) throw new VaultError("forbidden", `This workload may only ask for ${quoted(items)}. To connect, also list the provider's client, "${clientSlug}", in this workload's items.`, { next: { say: "Create a workload whose items name both the connection and its provider's OAuth client." } })
}
// One task may hold this many open asks, on top of its device's 20, so a
// runaway task never uses up the asks of the device's other tasks.
export const WORKLOAD_MAX_OPEN_ASKS = 5
export function assertWorkloadAskRoom(ctx: VaultContext, workload: string | undefined, now = ctx.now()): void {
  if (workload !== undefined && openWorkloadAskCount(ctx, workload, now) >= WORKLOAD_MAX_OPEN_ASKS) throw new VaultError("rate_limited", `This task's workload already has ${WORKLOAD_MAX_OPEN_ASKS} open asks, its own limit. Settle one before asking again.`)
}
const IdInput = z.strictObject({ workload: z.string().max(80) })
// A workload as its device's own CLI is answered (fill-old-cli.ts).
const cliOf = (invocation: WorkspaceInvocationContext) => invocation.auth.kind === "device" ? invocation.auth.cliVersion ?? null : null
function forCli(view: WorkloadView, invocation: WorkspaceInvocationContext): WorkloadView {
  return workloadForCli(view, cliOf(invocation))
}
const shownToCli = (row: WorkloadRow, invocation: WorkspaceInvocationContext) => !workloadHiddenFromCli(workloadScope(row), cliOf(invocation))
// A device's own workload, as its CLI may see it: a fill-only one is not
// there for a CLI that cannot read fill.
function deviceWorkload(ctx: VaultContext, device: string, id: string, invocation: WorkspaceInvocationContext): WorkloadRow {
  const row = ownWorkload(ctx, device, id)
  if (!shownToCli(row, invocation)) throw new VaultError("not_found", "No such workload.")
  return row
}
export const workloadOps: NonNullable<Area["workspaceOps"]> = {
  "workloads.create": { auth: ["device"], async handler(ctx, _p, raw, invocation) {
    const input = WorkloadCreateSchema.parse(raw)
    refuseFillUnlessOn(ctx, input.scope.modes ?? [])
    const thumbprint = await jwkThumbprint(input.jwk)
    return ctx.storage.transactionSync(() => {
      const device = parentDevice(ctx, invocation)
      assertWithinDevice(input.scope, device.scope)
      // A workload's fill is refused as its device's would be (ruling F2).
      const machine = one(ctx.sql.exec<{ name: string; last_cli_version: string | null }>("SELECT name,last_cli_version FROM devices WHERE id=?", device.id))
      refuseFillForOldCli({ name: machine?.name ?? device.id, lastCliVersion: machine?.last_cli_version ?? null }, [], input.scope.modes ?? [])
      // Nor is a fill-only workload made for a caller that could not see it.
      if (fillOnly(input.scope.modes)) refuseFillForOldCli({ name: machine?.name ?? device.id, lastCliVersion: cliOf(invocation) }, [], input.scope.modes ?? [])
      const now = ctx.now()
      if (thumbprint === device.thumbprint || one(ctx.sql.exec("SELECT id FROM devices WHERE thumbprint=? AND revoked_at IS NULL", thumbprint)) || one(ctx.sql.exec("SELECT id FROM workloads WHERE thumbprint=? AND revoked_at IS NULL AND expires_at>?", thumbprint, now))) throw new VaultError("conflict", "This key is already in use. Generate a fresh key for every workload.")
      if (live(ctx, device.id).length >= WORKLOAD_MAX_LIVE_PER_DEVICE) throw new VaultError("rate_limited", `This machine already has ${WORKLOAD_MAX_LIVE_PER_DEVICE} live workloads. Revoke finished ones before creating more.`)
      const id = randomId("wl")
      ctx.sql.exec("INSERT INTO workloads(id,device,label,jwk,thumbprint,scope,created_at,expires_at,hard_expires_at) VALUES (?,?,?,?,?,?,?,?,?)", id, device.id, input.label, canonicalJson(input.jwk), thumbprint, canonicalJson(input.scope), now, now + (input.ttlSeconds ?? WORKLOAD_DEFAULT_TTL_SECONDS) * 1000, now + WORKLOAD_MAX_LIFE_SECONDS * 1000)
      const row = workloadRow(ctx, id)!
      auditWorkload(ctx, `device:${device.id}`, "workload.created", row, { scope: input.scope, expiresAt: iso(row.expires_at) })
      scheduleSweep(ctx)
      return forCli(workloadView(row, now), invocation)
    })
  } },
  "workloads.list": { auth: ["device"], handler(ctx, _p, _raw, invocation) {
    const device = parentDevice(ctx, invocation)
    return { workloads: live(ctx, device.id).filter((w) => shownToCli(w, invocation)).map((w) => forCli(workloadView(w, ctx.now()), invocation)) }
  } },
  "workloads.get": { auth: ["device"], handler(ctx, _p, raw, invocation) {
    const device = parentDevice(ctx, invocation)
    return forCli(workloadView(deviceWorkload(ctx, device.id, IdInput.parse(raw).workload, invocation), ctx.now()), invocation)
  } },
  "workloads.renew": { auth: ["device"], handler(ctx, _p, raw, invocation) {
    const input = IdInput.extend(WorkloadRenewSchema.shape).parse(raw)
    return ctx.storage.transactionSync(() => {
      const device = parentDevice(ctx, invocation)
      const row = deviceWorkload(ctx, device.id, input.workload, invocation)
      if (!workloadLive(row, ctx.now())) throw workloadEnded()
      const expiresAt = Math.min(ctx.now() + (input.ttlSeconds ?? WORKLOAD_DEFAULT_TTL_SECONDS) * 1000, row.hard_expires_at)
      ctx.sql.exec("UPDATE workloads SET expires_at=? WHERE id=?", expiresAt, row.id)
      const renewed = workloadRow(ctx, row.id)!
      auditWorkload(ctx, `device:${device.id}`, "workload.renewed", renewed, { expiresAt: iso(expiresAt) })
      scheduleSweep(ctx)
      return forCli(workloadView(renewed, ctx.now()), invocation)
    })
  } },
  "workloads.revoke": { auth: ["device"], handler(ctx, _p, raw, invocation) {
    const input = IdInput.parse(raw)
    return ctx.storage.transactionSync(() => {
      const device = parentDevice(ctx, invocation)
      const row = deviceWorkload(ctx, device.id, input.workload, invocation)
      if (row.revoked_at === null) {
        revokeRows(ctx, [row.id], "device")
        auditWorkload(ctx, `device:${device.id}`, "workload.revoked", row, { by: "device" })
      }
      return forCli(workloadView(workloadRow(ctx, row.id)!, ctx.now()), invocation)
    })
  } },
  // A person's view of a machine's live workloads (the machine's page).
  "workloads.of_device": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const { device } = z.strictObject({ device: z.string().max(80) }).parse(raw)
    try { authorise(ctx, invocation, { type: "devices.read" }, { device }, ctx.now()) } catch (error) { if (error instanceof VaultError && (error.code === "forbidden" || error.code === "not_found")) throw new VaultError("not_found", "No such machine."); throw error }
    if (!one(ctx.sql.exec("SELECT id FROM devices WHERE id=? AND owner_kind IS NOT NULL", device))) throw new VaultError("not_found", "No such machine.")
    return { workloads: live(ctx, device).map((w) => workloadView(w, ctx.now())) }
  } },
  // A person ends one workload with the same passkey step-up as revoking its
  // machine; the signed action binds the machine and the workload.
  "workloads.revoke_member": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const input = z.strictObject({ device: z.string().max(80), workload: z.string().max(80) }).parse(raw)
    return ctx.storage.transactionSync(() => {
      const decision = workloadRevokeDecision(ctx, invocation, input.device)
      const row = ownWorkload(ctx, input.device, input.workload)
      requireStepUp(ctx, decision, { type: "workload.revoke", device: input.device, workload: row.id }, invocation)
      if (row.revoked_at === null) {
        revokeRows(ctx, [row.id], "member")
        auditWorkload(ctx, decision.principal.kind === "member" ? `member:${decision.principal.memberId}` : "system", "workload.revoked", row, { by: "member" })
      }
      return workloadView(workloadRow(ctx, row.id)!, ctx.now())
    })
  } },
}
// Who may end a machine's workload: whoever may revoke the machine. Every
// refusal looks like a machine that is not there.
export function workloadRevokeDecision(ctx: VaultContext, invocation: WorkspaceInvocationContext, device: string) {
  try {
    authorise(ctx, invocation, { type: "devices.read" }, { device }, ctx.now())
    return authorise(ctx, invocation, { type: "workload.revoke" }, { device }, ctx.now())
  } catch (error) { if (error instanceof VaultError && (error.code === "forbidden" || error.code === "not_found")) throw new VaultError("not_found", "No such machine."); throw error }
}
