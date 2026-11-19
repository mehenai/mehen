// Enrolled machines: their public keys and scopes, the nonce store that
// refuses a replayed proof, and the ops a device or a member uses to see and
// revoke them. A device enters the table only when a member approves its
// enrolment with a passkey step-up (the Worker side is directory/enrolment.ts).

import { type DeviceJwk, type ProofCheck, PROOF_MAX_SKEW_SECONDS, WorkspaceSlugSchema, importDeviceKey, isDeviceJwk, parseProof, verifyProof } from "@mehen/protocol"
import { type DeviceScope, type DeviceView, type Me, ModeSchema, Tag, canonicalJson } from "@mehen/protocol/api"
import { fingerprintOf, fingerprintWords } from "@mehen/protocol/fingerprint"
import { z } from "zod"
import { VaultError } from "../../http.ts"
import { type Area, type DeviceAuth, type DevicePrincipal, type VaultContext, actorOf, one, rows } from "../core.ts"
import type { DeviceCovers, DevicePolicyState } from "../services.ts"
import { copyCliVersion } from "./device-cli-versions.ts"

// Reveal is for a human in a browser, never for a device.
export const DeviceScopeSchema = z.object({
  tags: z.array(Tag).max(32),
  projects: z.array(z.string().min(1).max(64)).max(32),
  maxEnvironment: z.enum(["unprotected", "protected"]),
  modes: z.array(ModeSchema.exclude(["reveal"])).min(1).max(6),
})

const RegisterInput = z.object({
  enrolment: z.string().regex(/^enr_[A-Za-z0-9]{8,40}$/),
  code: z.string(),
  device: z.string().regex(/^dev_[A-Za-z0-9]{8,40}$/),
  name: z.string().min(1).max(64),
  backend: z.enum(["secure-enclave", "software"]),
  host: z.string().max(253).nullable(),
  jwk: z.custom<DeviceJwk>(isDeviceJwk),
  thumbprint: z.string().min(1).max(64),
  scope: DeviceScopeSchema,
})

const DeviceInput = z.object({ device: z.string().min(1).max(64) })
const RescopeInput = z.object({ device: z.string().min(1).max(64), before: DeviceScopeSchema, scope: DeviceScopeSchema })
const DiscardInput = z.object({ enrolment: z.string().min(1).max(64), device: z.string().min(1).max(64) })

export const CAPABILITIES: Me["capabilities"] = {
  environmentV2: false,
  runBaseUrl: false,
  runFiles: false,
  sealedEnvImport: true,
  policyV1: false,
}

export const devicePolicyState: DevicePolicyState = (ctx, device) => {
  const row = one(ctx.sql.exec<DeviceRow>("SELECT * FROM devices WHERE id = ?", device))
  return row ? { scopeRev: row.scope_rev, active: row.revoked_at === null, scope: parseScope(row.scope), name: row.name } : null
}

const LAST_SEEN_EVERY_MS = 60_000
const PRUNE_EVERY_MS = 30_000
// Long past an enrolment's 15 minutes, so by then D1 has decided it.
export const ORPHAN_SWEEP_AFTER_MS = 3600_000

type DeviceRow = {
  id: string
  name: string
  backend: string
  host: string | null
  jwk: string
  thumbprint: string
  scope: string
  scope_rev: number
  created_at: number
  last_seen_at: number | null
  last_cli_version: string | null
  revoked_at: number | null
}

// Per Durable Object instance, keyed on its storage so every per-call
// context shares it: imported keys (a device's key never changes under its
// id) and when the nonce table was last pruned.
const instanceState = new WeakMap<DurableObjectStorage, { keys: Map<string, CryptoKey>; prunedAt: number }>()

function stateFor(ctx: VaultContext): { keys: Map<string, CryptoKey>; prunedAt: number } {
  let state = instanceState.get(ctx.storage)
  if (!state) {
    state = { keys: new Map(), prunedAt: 0 }
    instanceState.set(ctx.storage, state)
  }
  return state
}

// signer: whose key the proof names, a workload's (wkl) or the device's own.
export function proofRefusal(reason: Exclude<ProofCheck, { ok: true }>["reason"], signer: "device" | "workload" = "device"): VaultError {
  const messages: Record<typeof reason, string> = {
    signature: `The Mehen-Proof signature does not verify with this ${signer}'s key.`,
    method: "The Mehen-Proof was signed for a different HTTP method than this request.",
    url: "The Mehen-Proof was signed for a different URL than this request.",
    body: "The Mehen-Proof was signed over a different body than this request sent.",
    expired: `The Mehen-Proof is more than ${PROOF_MAX_SKEW_SECONDS} seconds old. Check this machine's clock and retry.`,
    future: `The Mehen-Proof is dated more than ${PROOF_MAX_SKEW_SECONDS} seconds in the future. Check this machine's clock and retry.`,
  }
  return new VaultError("proof_invalid", messages[reason])
}

export function replayRefusal(): VaultError {
  return new VaultError("proof_invalid", "This Mehen-Proof has already been used. Sign every request afresh.")
}

function parseScope(text: string): DeviceScope {
  return DeviceScopeSchema.parse(JSON.parse(text))
}

function view(row: DeviceRow): DeviceView {
  return {
    device: row.id,
    name: row.name,
    backend: row.backend,
    host: row.host,
    scope: parseScope(row.scope),
    createdAt: new Date(row.created_at).toISOString(),
    lastSeenAt: row.last_seen_at === null ? null : new Date(row.last_seen_at).toISOString(),
    revoked: row.revoked_at !== null,
    ...(row.revoked_at !== null ? { revokedAt: new Date(row.revoked_at).toISOString() } : {}),
    fingerprintWords: fingerprintWords(row.thumbprint),
  }
}

function isFrozen(ctx: VaultContext): boolean {
  return one(ctx.sql.exec<{ value: string }>("SELECT value FROM tenant_state WHERE key = 'frozen'"))?.value === "1"
}

function revoke(ctx: VaultContext, device: string, actor: string): void {
  ctx.storage.transactionSync(() => {
    const result = ctx.sql.exec("UPDATE devices SET revoked_at = ?, scope_rev = scope_rev + 1 WHERE id = ? AND revoked_at IS NULL", ctx.now(), device)
    if (result.rowsWritten === 0) {
      const exists = one(ctx.sql.exec<{ id: string }>("SELECT id FROM devices WHERE id = ?", device))
      if (!exists) throw new VaultError("not_found", "No such device in this vault.")
      return
    }
    ctx.audit({ actor, action: "device.revoke", target: device })
  })
}

import { workspaceDeviceOps } from "./workspace-devices.ts"
import { WORKLOADS_MIGRATION, WORKLOAD_SWEEP_KEY, assertWorkloadLive, principalWorkload, sweepWorkloads, workloadForProof, workloadOps } from "./workloads.ts"

export const devicesArea: Area = {
  workspaceOps: { ...workspaceDeviceOps, ...workloadOps, "devices.revokeSelf": workspaceDeviceOps["devices.self_revoke"]! },
  name: "devices",
  migrations: [
    `CREATE TABLE devices (
       id TEXT PRIMARY KEY,
       name TEXT NOT NULL,
       backend TEXT NOT NULL,
       host TEXT,
       jwk TEXT NOT NULL,
       thumbprint TEXT NOT NULL,
       scope TEXT NOT NULL,
       created_at INTEGER NOT NULL,
       last_seen_at INTEGER,
       revoked_at INTEGER
     );
     CREATE INDEX devices_thumbprint ON devices (thumbprint);
     CREATE TABLE device_nonces (
       device TEXT NOT NULL,
       jti TEXT NOT NULL,
       expires_at INTEGER NOT NULL,
       PRIMARY KEY (device, jti)
     );
     CREATE INDEX device_nonces_expiry ON device_nonces (expires_at);`,
    // The D1 enrolment a device came from, so a repeated register is idempotent.
    `ALTER TABLE devices ADD COLUMN enrolment TEXT;
     CREATE UNIQUE INDEX devices_enrolment ON devices (enrolment);`,
    `ALTER TABLE devices ADD COLUMN scope_rev INTEGER NOT NULL DEFAULT 0;`,
    `ALTER TABLE devices ADD COLUMN owner_kind TEXT;
     ALTER TABLE devices ADD COLUMN owner_id TEXT;
     ALTER TABLE devices ADD COLUMN owner_revision INTEGER NOT NULL DEFAULT 1;
     ALTER TABLE devices ADD COLUMN acceptance TEXT;
     ALTER TABLE devices ADD COLUMN admission TEXT;`,
    WORKLOADS_MIGRATION,
    // The version the machine's `mehen/<x.y.z>` User-Agent last named.
    `ALTER TABLE devices ADD COLUMN last_cli_version TEXT;`,
  ],
  async alarm(ctx, key) {
    if (key === WORKLOAD_SWEEP_KEY) sweepWorkloads(ctx)
    else await sweepOrphan(ctx, key)
  },
}

// Keyed by enrolment, an hour after register: the device is removed if it
// was never seen and D1 does not hold its enrolment active for this tenant
// and this device, so the machine can never learn it. A D1 failure throws,
// and the alarm retries with backoff; nothing is deleted on an error.
export async function sweepOrphan(ctx: VaultContext, enrolment: string): Promise<void> {
  const device = one(ctx.sql.exec<{ id: string; created_at: number }>("SELECT id, created_at FROM devices WHERE enrolment = ? AND last_seen_at IS NULL", enrolment))
  if (!device) return
  const due = device.created_at + ORPHAN_SWEEP_AFTER_MS
  if (ctx.now() < due) {
    ctx.schedule("devices", enrolment, due)
    return
  }
  const claim = await ctx.env.DB.prepare("SELECT status, tenant, device FROM enrolments WHERE id = ?")
    .bind(enrolment)
    .first<{ status: string; tenant: string | null; device: string | null }>()
  if (claim?.status === "active" && claim.tenant === ctx.tenant && claim.device === device.id) return
  const removed = ctx.sql.exec("DELETE FROM devices WHERE id = ? AND enrolment = ? AND last_seen_at IS NULL", device.id, enrolment)
  if (removed.rowsWritten > 0) ctx.audit({ actor: "system", action: "device.sweep", target: device.id, detail: { enrolment } })
}

// Keyed by the signing key's id: a device id or a workload id.
async function deviceKey(ctx: VaultContext, row: { id: string; jwk: string }): Promise<CryptoKey> {
  const { keys } = stateFor(ctx)
  const cached = keys.get(row.id)
  if (cached) return cached
  const jwk: unknown = JSON.parse(row.jwk)
  if (!isDeviceJwk(jwk)) throw new Error("stored device key is not a P-256 JWK")
  const key = await importDeviceKey(jwk)
  keys.set(row.id, key)
  return key
}

function pruneNonces(ctx: VaultContext, now: number): void {
  const state = stateFor(ctx)
  if (now - state.prunedAt < PRUNE_EVERY_MS) return
  state.prunedAt = now
  ctx.sql.exec("DELETE FROM device_nonces WHERE expires_at < ?", now)
}

// The CLI's enrol command for this workspace: `mehen enrol` refuses to
// start without --workspace, so the refusal names this vault's own slug,
// or the CLI's own `<slug>` placeholder when the vault has no valid one
// recorded (a store from before workspaces).
function enrolCommand(ctx: VaultContext): string {
  let slug: string | null = null
  try {
    const row = one(ctx.sql.exec<{ value: string }>("SELECT value FROM tenant_state WHERE key = 'workspace'"))
    const recorded: unknown = row ? (JSON.parse(row.value) as { slug?: unknown }).slug : null
    slug = WorkspaceSlugSchema.safeParse(recorded).success ? (recorded as string) : null
  } catch {
    slug = null
  }
  return `mehen enrol --workspace ${slug ?? "<slug>"}`
}

// Verifies a Mehen-Proof against the device table and the nonce store: the
// tenant, a live device, its key over this exact method, URL and body,
// the skew window, then the proof id, which is spent here. A workload's
// proof (`wkl`) names a workload of that device and verifies against the
// workload's own key, never the device's; only then is a workload that has
// ended (or whose device was revoked) refused. Nonces are per signing key.
export async function authenticateDevice(ctx: VaultContext, auth: DeviceAuth): Promise<DevicePrincipal> {
  let proof: ReturnType<typeof parseProof>
  try {
    proof = parseProof(auth.proof)
  } catch {
    throw new VaultError("proof_invalid", "The Mehen-Proof header is malformed.")
  }
  const { claims } = proof
  if (claims.ten !== ctx.tenant) throw new VaultError("proof_invalid", "This Mehen-Proof was signed for a different vault.")
  const row = one(ctx.sql.exec<DeviceRow>("SELECT * FROM devices WHERE id = ?", claims.dev))
  if (!row) {
    const command = enrolCommand(ctx)
    throw new VaultError("unauthenticated", "This machine is not enrolled in this vault.", {
      next: { command, say: `This machine is not enrolled with the vault; run \`${command}\` and approve it in the browser.` },
    })
  }
  const workload = claims.wkl === undefined ? null : workloadForProof(ctx, row.id, claims.wkl)
  if (workload === null && row.revoked_at !== null) {
    const command = enrolCommand(ctx)
    throw new VaultError("device_revoked", "This device has been revoked. Enrol it again if it should have access.", {
      next: { command, say: `This machine's access to the vault was revoked; run \`${command}\` and a human must approve the new enrolment.` },
    })
  }
  const now = ctx.now()
  const signer = workload ?? row
  const check = await verifyProof(proof, await deviceKey(ctx, signer), { method: auth.method, url: auth.url, bodyHash: auth.bodyHash, now })
  if (!check.ok) throw proofRefusal(check.reason, workload ? "workload" : "device")
  if (workload) assertWorkloadLive(ctx, row, workload)
  pruneNonces(ctx, now)
  const spent = ctx.sql.exec(
    "INSERT INTO device_nonces (device, jti, expires_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
    signer.id,
    claims.jti,
    (claims.iat + PROOF_MAX_SKEW_SECONDS + 1) * 1000,
  )
  if (spent.rowsWritten === 0) throw replayRefusal()
  // A device's own proof records its CLI version; a new one is written at
  // once, inside the throttle too, and no version leaves the old one.
  const version = workload ? null : (auth.cliVersion ?? null)
  const versionChanged = version !== null && version !== row.last_cli_version
  if (signer.last_seen_at === null || now - signer.last_seen_at >= LAST_SEEN_EVERY_MS || versionChanged) {
    if (workload) ctx.sql.exec("UPDATE workloads SET last_seen_at = ? WHERE id = ?", now, signer.id)
    else ctx.sql.exec("UPDATE devices SET last_seen_at = ?, last_cli_version = COALESCE(?, last_cli_version) WHERE id = ?", now, version, signer.id)
  }
  if (versionChanged) await copyCliVersion(ctx, row.id, version, now)
  return {
    kind: "device",
    device: row.id,
    name: row.name,
    scope: parseScope(row.scope),
    session: claims.sid ?? null,
    grant: claims.gnt ?? null,
    workload: workload ? principalWorkload(workload) : null,
  }
}

// Empty scope tags cover every item; otherwise the item must carry one of
// them. A workload's scope is intersected here, never unioned: the item must
// also be one it names and carry one of its tags, in one of its modes.
export const deviceCovers: DeviceCovers = (principal, item, mode) => {
  if (!principal.scope.modes.includes(mode)) return false
  const workload = principal.workload?.scope
  if (workload?.modes && (mode === "reveal" || !workload.modes.includes(mode))) return false
  if (workload?.items && !workload.items.includes(item.slug)) return false
  if (workload?.tags && !item.tags.some((tag) => workload.tags?.includes(tag))) return false
  if (principal.scope.tags.length === 0) return true
  return item.tags.some((tag) => principal.scope.tags.includes(tag))
}
