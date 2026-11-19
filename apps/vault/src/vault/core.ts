// The shape every area of the TenantVault Durable Object plugs into. An
// area owns its tables (its own migration list), its RPC operations and its
// alarm keys, in one module under areas/. The DO core owns nothing but
// dispatch, authentication order, keys, the schedule and the audit chain.

import type { DeviceScope, StepUpActionInput } from "@mehen/protocol/api"
import type { Env } from "../env.ts"
import type { WireError } from "../http.ts"

export type DevicePrincipal = {
  kind: "device"
  device: string
  name: string
  scope: DeviceScope
  session: string | null
  grant: string | null
  // The workload that signed, when one did: its scope narrows the device's
  // (deviceCovers, and principalDevice in access.ts).
  workload: PrincipalWorkload | null
}
export type PrincipalWorkload = { id: string; label: string; scope: import("@mehen/protocol").WorkloadScope }
export type DeviceAccessPrincipal = Extract<import("./access.ts").AccessPrincipal, { kind: "device" }>
// The evaluator's principal for a verified device, with its workload when one signed.
export function accessPrincipalOf(principal: DevicePrincipal): DeviceAccessPrincipal {
  return { kind: "device", deviceId: principal.device, ...(principal.workload ? { workload: principal.workload.id } : {}) }
}

// A not-yet-approved device polling its own enrolment.
export type PendingDevicePrincipal = { kind: "pending-device"; enrolment: string }

// Set by the Worker after it has checked the web session (and, when the
// route needs one, a passkey step-up over `stepUp`). The DO trusts it: only
// code in this deployment can reach the DO.
export type MemberPrincipal = {
  kind: "member"
  member: string
  role: "owner" | "member"
  stepUp: StepUpActionInput | null
}

// Who asked for an intake or a connect: a device, keyed by its id, or a
// member from the vault's own pages, keyed under a prefix no device id can
// carry (areas/intake.ts, requesterOf). Rows are keyed by `key`, so reuse,
// supersede and polling never cross from one requester to another. `name`
// and `session` are what a row records about a device; empty for a member.
export type Requester = { principal: DevicePrincipal | MemberPrincipal; key: string; name: string; session: string | null }

// `actor`, when set, is who the system acts for, as the audit records it
// (a platform admin deleting a subject from the console: admin:<account>);
// otherwise the audit says "system".
export type SystemAuth = { kind: "system"; reason: string; actor?: string }
export type SystemPrincipal = SystemAuth
export type PublicPrincipal = { kind: "public" }

export type Principal = DevicePrincipal | PendingDevicePrincipal | MemberPrincipal | SystemPrincipal | PublicPrincipal

// cliVersion: the version the request's `mehen/<x.y.z>` User-Agent names
// (cli-version.ts cliVersionOf), null or absent for any other caller.
export type DeviceAuth = { kind: "device"; proof: string; method: string; url: string; bodyHash: string; cliVersion?: string | null }

// Set by the Worker only after it verified the Mehen-Platform-Proof against
// the platform's live key and spent its nonce (platform/auth.ts, then
// routes/platform.ts): the platform, the key that signed, the subject the
// path names, and the proof's id and time. Trusted by the object for the
// same reason account auth is: only this deployment reaches it. The managed
// workspace checks it is this platform's and this subject's
// (areas/managed.ts).
export type PlatformInvocationAuth = { kind: "platform"; platform: string; key: string; subject: string; jti: string; iat: number }

export type InvocationAuth =
  | DeviceAuth
  | { kind: "member"; member: string; role: "owner" | "member"; stepUp?: StepUpActionInput }
  | { kind: "system"; reason: string }
  | { kind: "public" }

export type Invocation = { op: string; auth: InvocationAuth; input: unknown }

export type InvocationResult = { ok: true; value: unknown } | { ok: false; error: WireError }

export type AuditEvent = {
  privateOwner?: string
  private?: Omit<import("@mehen/protocol").PrivateEvent, "action" | "at">
  actor: string // "device:dev_x", "member:mem_x", "system", "public"
  action: string // "item.create", "relay.allow", "approval.decide"
  target?: string | null
  detail?: Record<string, unknown>
}

export type FieldRef = { type: string; id: string }
export type SealedField = { rootVersion: number; wrappedDek: Uint8Array<ArrayBuffer>; ciphertext: Uint8Array<ArrayBuffer> }

export type VaultContext = {
  tenant: string
  env: Env
  sql: SqlStorage
  storage: DurableObjectStorage
  now(): number
  // Envelope encryption under the tenant KEK of the current root version.
  sealField(ref: FieldRef, plaintext: Uint8Array<ArrayBuffer>): Promise<SealedField>
  openField(ref: FieldRef, sealed: SealedField): Promise<Uint8Array<ArrayBuffer>>
  // The root key version that sealField and new fingerprints use.
  readonly rootVersion: number
  // Non-extractable HMAC-SHA256 key for secret fingerprints written under
  // this root version (keys.ts).
  fingerprintKey(version: number): Promise<CryptoKey>
  audit(event: AuditEvent): void
  // Run `area.alarm(ctx, key)` at or after `at` (ms). Re-scheduling a key moves it.
  schedule(area: string, key: string, at: number): void
  unschedule(area: string, key: string): void
  // Work that must finish after the response (never holds secrets).
  waitUntil(promise: Promise<unknown>): void
  // Ends this object's session at once; the next call builds it afresh from
  // storage, which is when a restore's bookmark or restored tables take
  // effect (areas/vault-backup.ts).
  restart(reason: string): void
  // Changes whenever this object's storage may have: every statement through
  // `sql` that is not a SELECT, a synchronous transaction that rolled back,
  // and deleteAll.
  readonly storageWrites: number
  // Changes whenever any table's rows may have: a count the revision
  // triggers keep in the database (management-guard.ts) with the number of
  // synchronous transactions that rolled back, which return it to a value
  // it had. The access-state memo is stamped with it.
  accessRevision(): string
  // Present on invocation contexts only (TenantVault.invoke), one per
  // object and shared by its calls: the evaluator state accessState built,
  // the access revision when it built it, and the time it holds until.
  readonly accessStateMemo?: AccessStateMemo
}
export type AccessStateMemo = { revision: string | null; until: number; state: import("./access.ts").AccessState | null }

export type Area = {
  name: string
  // Applied in order, once each, tracked per area. Append only: never edit
  // or reorder an entry that has shipped.
  migrations: string[]
  workspaceOps?: Record<string, { auth: ("account" | "device" | "system" | "platform")[]; handler(ctx: VaultContext, principal: import("./areas/workspace-runtime.ts").WorkspaceRuntimePrincipal, input: unknown, invocation: import("./areas/workspace-runtime.ts").WorkspaceInvocationContext): Promise<unknown> | unknown }>
  alarm?(ctx: VaultContext, key: string): Promise<void>
}

export function actorOf(principal: Principal): string {
  switch (principal.kind) {
    case "device":
      return `device:${principal.device}`
    case "pending-device":
      return `enrolment:${principal.enrolment}`
    case "member":
      return `member:${principal.member}`
    case "system":
      return "system"
    case "public":
      return "public"
  }
}

export function randomId(prefix: string, bytes = 16): string {
  const raw = crypto.getRandomValues(new Uint8Array(bytes))
  let text = ""
  for (const b of raw) text += String.fromCharCode(b)
  return `${prefix}_${btoa(text).replaceAll("+", "").replaceAll("/", "").replaceAll("=", "").slice(0, Math.ceil(bytes * 1.3))}`
}

export function rows<T extends Record<string, SqlStorageValue>>(cursor: SqlStorageCursor<T>): T[] {
  return cursor.toArray()
}

export function one<T extends Record<string, SqlStorageValue>>(cursor: SqlStorageCursor<T>): T | null {
  return cursor.toArray()[0] ?? null
}

// SQLite BLOBs come back as ArrayBuffer.
export function blob(value: SqlStorageValue): Uint8Array<ArrayBuffer> {
  if (value instanceof ArrayBuffer) return new Uint8Array(value)
  throw new Error("expected a blob column")
}

// Frozen account invocation seam. Legacy dispatch/principals remain unchanged
// until ACCESS's first turn implements the live membership resolution.
export type OperationCheck = { id: string; subjectDigest: string; identityRuleRev: number; gateGeneration: number; succeededAt: string; expiresAt: string }
export type AccountInvocationAuth = {
  kind: "account"
  account: string
  session: string
  securityEpoch: number // committed D1 epoch, never the reserved pending epoch
  stepUp?: import("@mehen/protocol").WorkspaceStepUpAction
  stepUpFactor?: string // passkeys.handle (pk_), never a credential id
  // A passkey now, or the session's grace window (the factor is the passkey
  // that opened it); the audit wrapper records a graced one.
  stepUpConfirmation?: import("@mehen/protocol").StepUpConfirmation
  // Set only after DIRECTORY/OIDC verifies and consumes operation_identity_checks.
  operationCheck?: OperationCheck
  sessionCheck: import("@mehen/protocol").SessionIdentityCheck | null
  restrictedUntil: number | null
}
export type WorkspaceInvocation = { op: string; input: unknown; auth: AccountInvocationAuth | DeviceAuth | SystemAuth | PlatformInvocationAuth }
export type WorkspaceVaultStub = { invoke(invocation: WorkspaceInvocation): Promise<InvocationResult> }
export type WorkspaceMemberPrincipal = Extract<import("./access.ts").AccessPrincipal, { kind: "member" }>
export type WorkspaceDevicePrincipal = Omit<DevicePrincipal, "scope"> & { scope: import("@mehen/protocol").WorkspaceDeviceScope; owner: import("@mehen/protocol").OwnerRef; reach: import("./access.ts").DeviceReach; scopeRevision: number }
export type WorkspaceAccountSecurity = import("@mehen/protocol").AccountSecurityState
