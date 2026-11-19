// Internal contracts between areas. Each function is implemented and
// exported by the area that owns it (named in brackets) and called directly
// by the others, inside the same Durable Object call. Areas never read
// another area's tables: they go through these functions.
//
// Changing a signature here changes every area that calls it: say so in the PR.

import type { ItemBrowser, Mode } from "@mehen/protocol"
import type { ApprovalEmail, BindingInput, DeviceScope, Injection, ItemSummary, NextStep, PolicyInput, SecretFieldInfo } from "@mehen/protocol/api"
import type { Destination } from "@mehen/protocol/binding"
import type { PolicySecuritySnapshot } from "@mehen/protocol/policy-mode"
import type { ItemKind } from "@mehen/protocol/kinds"
import type { DevicePrincipal, Principal, VaultContext } from "./core.ts"

// ---------------------------------------------------------------- [L2 items] areas/items.ts

export type ItemRecord = {
  id: string // itm_...
  slug: string
  kind: ItemKind
  provider: string | null
  account: string | null
  accountVerified: boolean
  tags: string[]
  ceiling: Mode
  binding: BindingInput
  policy: PolicyInput
  injection: Injection | null
  publicFields: Record<string, string>
  // The pages a human added for fill: more sign-in pages, and other
  // services' pages it may be typed into. Null until a human sets them.
  browser: ItemBrowser | null
  status: ItemSummary["status"]
  // Set while the item is flagged for a human to look at.
  review: { reason: string; at: number } | null
  version: number
  configRev: number
  description: string | null
  createdAt: number
  updatedAt: number
  lastUsedAt: number | null
}

export type NewItem = {
  slug: string
  kind: ItemKind
  provider: string | null
  account: string | null
  accountVerified: boolean
  tags: string[]
  ceiling: Mode
  binding: BindingInput
  policy: PolicyInput
  injection: Injection | null
  publicFields: Record<string, string>
  secretFields: Record<string, string>
  description: string | null
}

export type ItemsService = {
  getItem(ctx: VaultContext, slug: string): ItemRecord | null
  secretFieldMetadata(ctx: VaultContext, item: ItemRecord): SecretFieldInfo[]
  // Decrypts the item's secret fields. Callers must not let the values leave
  // the DO except as the relay's injection or an allowed lease.
  openSecrets(ctx: VaultContext, item: ItemRecord): Promise<Record<string, string>>
  // Creates, or with `replace` overwrites, an item. Refuses a slug clash otherwise.
  putItem(ctx: VaultContext, input: NewItem, actor: Principal, options?: { replace?: boolean }): Promise<ItemRecord>
  // Rotates secret fields in place (OAuth refresh, re-intake). Bumps version.
  replaceSecrets(ctx: VaultContext, slug: string, secrets: Record<string, string>, actor: Principal): Promise<ItemRecord>
  // Removes the item and its secrets, synchronously, so a caller can take
  // back an item it just created when what must go with it failed to land.
  // Whatever referenced the item is the caller's to clean up.
  deleteItem(ctx: VaultContext, item: ItemRecord, actor: Principal): void
  setStatus(ctx: VaultContext, slug: string, status: ItemSummary["status"], reason: string | null): void
  // Flags the item for review; replacing the whole item clears the flag.
  flagForReview(ctx: VaultContext, slug: string, reason: string): void
  summarise(item: ItemRecord): ItemSummary
}

// ---------------------------------------------------------------- [L1 devices] areas/devices.ts

// True when the device's scope (tags, modes) covers this item in this mode.
export type DeviceCovers = (principal: DevicePrincipal, item: ItemRecord, mode: Mode) => boolean

export type DevicePolicyState = (ctx: VaultContext, device: string) => { scopeRev: number; active: boolean; scope: DeviceScope; name: string } | null

// ---------------------------------------------------------------- [L4 approvals] areas/approvals.ts

export type ApprovalPresentation = {
  // What the stored card becomes once the approval is decided or expires,
  // for a card that shows something not to keep at rest (a run's whole
  // command line).
  settled?: { details: { label: string; value: string }[]; body: string | null }
  title: string
  details: { label: string; value: string }[]
  // The whole body as shown to the human (ApprovalView.request.body).
  body: string | null
  // Absent on approvals stored before cards carried them.
  warnings?: string[]
  email?: ApprovalEmail
  // Every header forwarded from the agent, as sent (ApprovalView.request.headers;
  // the page spells them for reading and the browser recomputes headersSha256 over them).
  // Absent on a card that sends no request (a run), and on cards stored before.
  headers?: [string, string][]
  // A push's card (areas/pushes.ts): what goes where, using what, and what
  // the provider said before anyone decided.
  push?: import("./areas/push-records.ts").PushPresentation
}

// ---------------------------------------------------------------- [L4 runs] areas/runs.ts

export type RunPlaceholder = { placeholder: string; item: string; field: string; hosts: string[] }

// A live run's environment and the hosts fenced to its project's other
// environments, read from the project on every call.
export type RunFences = { env: string; fencedHosts: string[] }

export type RunsService = {
  // The live run's placeholders, only if the run belongs to this device.
  placeholdersFor(ctx: VaultContext, principal: DevicePrincipal, run: string): RunPlaceholder[]
  // Null unless the run is live and belongs to this device.
  fencesFor(ctx: VaultContext, principal: DevicePrincipal, run: string): RunFences | null
  // True only for this device's live run in a still-protected environment,
  // started with an approval grant, by a device allowed protected
  // environments: the one place a protected item may be delivered.
  isApprovedProtectedRun(ctx: VaultContext, principal: DevicePrincipal, run: string): boolean
}

// ---------------------------------------------------------------- [L4 projects] areas/projects.ts

export type ProjectsService = {
  protectionRevision(ctx: VaultContext): number
  bumpProtectionRevision(ctx: VaultContext): void
  // True when a variable of any protected environment points at this item
  // slug. Computed on every call, never stored, so it cannot drift from the
  // variables: such an item is protected wherever it is used.
  isProtectedItem(ctx: VaultContext, item: string): boolean
  // The hosts fenced to every environment, of any project, in which no
  // variable points at this item slug: an item named directly (item mode)
  // never reaches them. Read on every call.
  fencesAgainstItem(ctx: VaultContext, item: string): string[]
}

export type { NextStep }

// These declarations attach to the implemented services in POL-SERVER's turn.
export type PolicyPermit = {
  itemId: string
  snapshot: PolicySecuritySnapshot
  guardDigest: string
  decision: "allow" | "approve" | "deny"
  reasons: string[]
  request: { mode: Mode; run: string | null; item: string; device: string; session: string | null; method: string; host: string; routeId: string | null; policyMode: "standard" }
}

export type PolicyService = {
  snapshot(ctx: VaultContext, deviceId: string, item: ItemRecord): PolicySecuritySnapshot
  prepare(ctx: VaultContext, device: DevicePrincipal, item: ItemRecord, destination: Destination, body: Uint8Array | null, contentType: string | null, contentEncoding: string | null): PolicyPermit
  assertCurrent(ctx: VaultContext, permits: PolicyPermit[]): void
  recordUse(ctx: VaultContext, permits: PolicyPermit[], requestDigest: string): void
}

// Workspace service declarations sit beside legacy services. Runtime owners
// implement these inside the final synchronous authorisation transaction.
export type CredentialDependency = { item: string; version: number; configRevision: number; home: import("@mehen/protocol").CredentialHome }
export type ConsentBasis = {
  sessionCheck: import("@mehen/protocol").SessionIdentityCheck | null
  session: string
  account: string
  securityEpoch: number
  member: string
  role: import("@mehen/protocol").WorkspaceRole
  sources: import("@mehen/protocol").AccessSource[]
  accessRevision: number
  context: import("@mehen/protocol").ItemUseContext | null
  referenceRevisions: { project: string; environment: string; revision: number; protectionRevision: number }[]
  fourEyesProjects: string[]
  expiresAt: number | null
}
export type ConsentLineage = { id: string; decision: string; basis: ConsentBasis; createdAt: number; expiresAt: number; revokedAt: number | null }
export type RunAuthorisation = { id: string; run: string; lineage: ConsentLineage; revision: number; validFrom: number; validUntil: number; revokedAt: number | null }
export type ExposureFact = { item: string; version: number; member: string | null; device: string | null; event: string; source: "entered" | "leased" | "reachable_lease" | "exported" | "filled" | "pushed"; at: number }
export type OffboardingSnapshot = { removal: string; by: string; member: string; devices: string[]; privateItems: string[]; exposures: ExposureFact[]; accessRevision: number }
export type OffboardingHook = (ctx: VaultContext, snapshot: OffboardingSnapshot) => void
export type WorkspaceAccessService = {
  member(ctx: VaultContext, account: string): import("./access.ts").AccessMember | null
  security(ctx: VaultContext, account: string): import("@mehen/protocol").AccountSecurityState | null
  installSecurity(ctx: VaultContext, account: string, committedEpoch: number, pending: import("@mehen/protocol").PendingAccountSecurity | null): void
  observeCommittedEpoch(ctx: VaultContext, account: string, committedEpoch: number): void
  state(ctx: VaultContext): import("./access.ts").AccessState
  beforeOffboarding(ctx: VaultContext, member: string): OffboardingSnapshot
}
export type WorkspaceItemsService = { home(ctx: VaultContext, item: string): import("@mehen/protocol").CredentialHome | null; dependencies(ctx: VaultContext, item: string): CredentialDependency[]; offboard: OffboardingHook }
export type WorkspaceConsentService = { current(ctx: VaultContext, lineage: ConsentLineage, now: number): boolean; invalidate(ctx: VaultContext, member: string): void; offboard: OffboardingHook }
// PROJECTS supplies the hook; OVERRIDES implements it in its later turn.
export type OverrideResolutionHook = (ctx: VaultContext, member: string, project: string, environment: string, variable: string) => { kind: "item"; item: string; field: string } | { kind: "plain"; value: string } | null
