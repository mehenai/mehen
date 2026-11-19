// What the vault answers each machine route with, as Zod schemas. The
// protocol publishes most responses as plain types; each schema here is
// annotated with that type, so a protocol change that this client does not
// follow fails the typecheck. Objects strip keys they do not know, so a vault
// that adds a field does not break an older client; a field this client
// relies on that is missing or malformed fails the parse.

import { z } from "zod"
import {
  BindingSchema,
  type ApprovalStatus,
  type ConnectCreated,
  type ConnectStatus,
  type EnrolRenewResponse,
  type EnrolStartResponse,
  InjectionSchema,
  type IntakeCreated,
  type IntakeStatus,
  type ItemSummary,
  KindSchema,
  ModeSchema,
  type NextStep,
  type PendingAsk,
  type PendingKind,
  PolicySchema,
  type RequestedBy,
  type RunVar,
  Slug,
} from "@mehen/protocol/api"
import { PolicyDeviceIdSchema, type PolicyFloorView } from "@mehen/protocol/policy-mode"
import { WorkloadViewSchema } from "@mehen/protocol/workload"
import {
  CredentialHomeSchema,
  type EnrolExpiredReason,
  ItemUseContextSchema,
  MinimalStopViewSchema,
  OwnerRefSchema,
  WorkspaceDeviceScopeSchema,
  type WorkspaceEnrolStatus,
  type WorkspaceItemDescription,
  type WorkspaceItemSummary,
  type WorkspaceMe,
  type WorkspacePendingAsk,
  type WorkspaceProject,
  WorkspaceRefSchema,
  type WorkspaceRunCreated,
} from "@mehen/protocol/workspace"
import { vaultLink } from "./origin.ts"

// The id shapes the vault mints (randomId) and the CLI accepts.
export const ENROLMENT_ID = /^enr_[A-Za-z0-9_-]{1,64}$/
export const APPROVAL_ID = /^apr_[A-Za-z0-9_-]{1,60}$/
export const INTAKE_ID = /^int_[A-Za-z0-9_-]{1,60}$/
export const CONNECT_ID = /^con_[A-Za-z0-9_-]{1,60}$/
export const RUN_ID = /^run_[A-Za-z0-9_-]{1,60}$/
export const PROJECT_ID = /^prj_[A-Za-z0-9_-]{1,60}$/

const Iso = z.iso.datetime()

// GET /v1/me. Signed by a workload, the answer also names the workload.
export type MachineIdentity = WorkspaceMe

export type ApprovalState = Pick<ApprovalStatus, "approval" | "status" | "bindingCode" | "summary" | "item" | "expiresAt">

// POST /v1/runs/:id/renew and DELETE /v1/runs/:id.
export type RunRenewed = { run: string; expiresAt: string }
export type RunEnded = { run: string; ended: true }

// GET /v1/projects/:id as a machine reads it: what a run needs to name
// (the bound remotes, the environments and the variables each declares).
export type MachineProject = Pick<WorkspaceProject, "id" | "slug" | "remotes" | "defaultEnv" | "environments" | "vars">

export const NextStepSchema: z.ZodType<NextStep> = z.object({ url: z.string().optional(), command: z.string().optional(), say: z.string() })

const EnrolExpiredReasonSchema: z.ZodType<EnrolExpiredReason> = z.enum(["hard_cap", "superseded", "discarded", "source", "legacy"])

export const EnrolStatusSchema: z.ZodType<WorkspaceEnrolStatus> = z.discriminatedUnion("status", [
  z.object({ status: z.enum(["pending_owner_acceptance", "pending_admission"]), expiresAt: Iso, hardExpiresAt: Iso }),
  z.object({ status: z.literal("expired"), reason: EnrolExpiredReasonSchema }),
  z.object({ status: z.literal("rejected") }),
  z
    .object({ status: z.literal("active"), tenant: z.string().min(1), workspace: WorkspaceRefSchema, device: PolicyDeviceIdSchema, scope: WorkspaceDeviceScopeSchema, owner: OwnerRefSchema })
    .refine((v) => v.workspace.id === v.tenant, "the workspace is not the tenant"),
])

export const EnrolRenewSchema: z.ZodType<EnrolRenewResponse> = z.object({ enrolment: z.string().regex(ENROLMENT_ID), expiresAt: Iso, hardExpiresAt: Iso })

export const MachineIdentitySchema: z.ZodType<MachineIdentity> = z.object({
  tenant: z.string().min(1),
  device: PolicyDeviceIdSchema,
  name: z.string(),
  scope: WorkspaceDeviceScopeSchema,
  frozen: z.boolean(),
  fingerprint: z.string(),
  capabilities: z.object({ environmentV2: z.boolean(), runBaseUrl: z.boolean(), runFiles: z.boolean(), sealedEnvImport: z.boolean(), policyV1: z.boolean() }),
  workspace: WorkspaceRefSchema,
  owner: OwnerRefSchema,
  displayRev: z.number().int(),
  workload: WorkloadViewSchema.optional(),
})

const ItemSummaryShape = {
  slug: Slug,
  kind: KindSchema,
  provider: z.string().nullable(),
  account: z.string().nullable(),
  accountVerified: z.boolean(),
  tags: z.array(z.string()),
  ceiling: ModeSchema,
  hosts: z.array(z.string()),
  status: z.enum(["active", "needs_reauth", "refresh_retrying", "disabled"]),
  review: z.object({ reason: z.string(), since: z.string() }).optional(),
  updatedAt: z.string(),
  lastUsedAt: z.string().nullable().optional(),
  policy: PolicySchema.optional(),
}

export const ItemSummarySchema: z.ZodType<ItemSummary> = z.object(ItemSummaryShape)

export const WorkspaceItemSummarySchema: z.ZodType<WorkspaceItemSummary> = z.object({ ...ItemSummaryShape, home: CredentialHomeSchema })

export const ItemListSchema = z.object({ items: z.array(WorkspaceItemSummarySchema) })

const PolicyFloorViewSchema: z.ZodType<PolicyFloorView> = z.object({
  id: z.string(),
  host: z.string(),
  action: z.enum(["deny", "approve"]),
  reason: z.enum(["credential", "persistence", "send", "money", "sharing", "destructive", "opaque"]),
  rule: PolicySchema.shape.rules.element,
  ruleDigest: z.string(),
})

export const WorkspaceItemDescriptionSchema: z.ZodType<WorkspaceItemDescription> = z.object({
  ...ItemSummaryShape,
  home: CredentialHomeSchema,
  description: z.string().nullable(),
  publicFields: z.record(z.string(), z.string()),
  secretFields: z.array(z.object({ name: z.string(), set: z.boolean(), length: z.number().int().nonnegative(), prefix: z.string(), fingerprint: z.string() })),
  binding: BindingSchema,
  policy: PolicySchema,
  injection: InjectionSchema.nullable(),
  version: z.number().int(),
  lastUsedAt: z.string().nullable(),
  rotatedAt: z.string().nullable(),
  policyFloor: z.array(PolicyFloorViewSchema).optional(),
})

export const ApprovalStateSchema: z.ZodType<ApprovalState> = z.object({
  approval: z.string().regex(APPROVAL_ID),
  status: z.enum(["pending", "approved", "denied", "expired", "used", "revoked", "stale"]),
  bindingCode: z.string(),
  summary: z.string(),
  item: z.string().optional(),
  expiresAt: Iso,
})

export const IntakeStatusSchema: z.ZodType<IntakeStatus> = z.object({
  intake: z.string().regex(INTAKE_ID),
  status: z.enum(["open", "completed", "expired", "cancelled"]),
  item: ItemSummarySchema.optional(),
  expiresAt: Iso,
  superseded: z.literal(true).optional(),
})

export const ConnectStatusSchema: z.ZodType<ConnectStatus> = z.object({
  connect: z.string().regex(CONNECT_ID),
  status: z.enum(["open", "completed", "mismatch", "failed", "expired"]),
  item: ItemSummarySchema.optional(),
  account: z.string().optional(),
  grantedScopes: z.array(z.string()).optional(),
  message: z.string().optional(),
  expiresAt: Iso,
})

const RequestedBySchema: z.ZodType<RequestedBy> = z.union([
  z.object({ device: z.string(), deviceName: z.string(), session: z.string().nullable() }),
  z.object({ member: z.string(), self: z.boolean() }),
])

const PENDING_KINDS = ["intake", "connect", "approval", "reconnect", "review", "policy", "policy-review"] as const satisfies readonly PendingKind[]

export const EmptySchema = z.object({})

// The schemas whose answers carry a link a person opens: each link must be
// on exactly the vault's origin, and is handed over absolute.
export function linkedSchemas(origin: string) {
  const Link = z.string().transform((value, context) => {
    const link = vaultLink(origin, value)
    if (link === null) context.addIssue({ code: "custom", message: "is not a link on the vault's origin" })
    return link ?? z.NEVER
  })

  const EnrolStart: z.ZodType<EnrolStartResponse> = z.object({
    enrolment: z.string().regex(ENROLMENT_ID),
    code: z.string().regex(/^[A-Za-z0-9-]{4,32}$/),
    url: Link,
    fingerprint: z.string(),
    expiresAt: Iso,
    hardExpiresAt: Iso,
  })

  // A managed workspace's intakes and connects carry no link: its platform
  // fills them in on its own pages. Every other workspace's carry one.
  const IntakeCreatedSchema: z.ZodType<IntakeCreated> = z.object({ intake: z.string().regex(INTAKE_ID), url: Link.optional(), expiresAt: Iso })

  const ConnectCreatedSchema: z.ZodType<ConnectCreated> = z.object({ connect: z.string().regex(CONNECT_ID), url: Link.optional(), expiresAt: Iso, intake: IntakeCreatedSchema.optional() })

  const PendingAskSchema: z.ZodType<PendingAsk> = z.object({
    kind: z.enum(PENDING_KINDS),
    id: z.string().min(1),
    title: z.string(),
    url: Link,
    expiresAt: Iso.nullable(),
    requestedBy: RequestedBySchema.nullable(),
    item: z.string().nullable(),
    bindingCode: z.string().optional(),
    kindRequested: KindSchema.optional(),
    provider: z.string().nullable().optional(),
    account: z.string().nullable().optional(),
    reason: z.string().optional(),
    createdAt: Iso.optional(),
  })

  const WorkspacePendingAskSchema: z.ZodType<WorkspacePendingAsk> = z.discriminatedUnion("view", [
    z.object({ workspace: WorkspaceRefSchema, owner: OwnerRefSchema, view: z.literal("detail"), detail: PendingAskSchema }),
    z.object({ workspace: WorkspaceRefSchema, owner: OwnerRefSchema, view: z.literal("stop"), stop: MinimalStopViewSchema }),
  ])

  return {
    EnrolStart,
    IntakeCreated: IntakeCreatedSchema,
    ConnectCreated: ConnectCreatedSchema,
    PendingAsks: z.object({ pending: z.array(WorkspacePendingAskSchema), notices: z.array(z.unknown()).optional() }),
  }
}

export const WorkloadListAnswerSchema = z.object({ workloads: z.array(WorkloadViewSchema) })

// One variable of a run. A delivery this client does not know fails the
// parse: a host must never guess what a new kind of value is.
export const RunVarSchema: z.ZodType<RunVar> = z.discriminatedUnion("delivery", [
  z.object({ name: z.string(), delivery: z.literal("plain"), value: z.string() }),
  z.object({ name: z.string(), delivery: z.literal("placeholder"), value: z.string(), item: z.string(), hosts: z.array(z.string()) }),
  z.object({ name: z.string(), delivery: z.literal("base-url"), value: z.string(), item: z.string() }),
  z.object({ name: z.string(), delivery: z.literal("lease"), value: z.string(), item: z.string() }),
  z.object({ name: z.string(), delivery: z.literal("missing"), next: NextStepSchema }),
])

export const WorkspaceRunCreatedSchema: z.ZodType<WorkspaceRunCreated> = z.object({
  run: z.string().regex(RUN_ID),
  expiresAt: Iso,
  project: z.object({ id: z.string().regex(PROJECT_ID), slug: z.string() }),
  env: z.string(),
  vars: z.array(RunVarSchema),
  interceptHosts: z.array(z.string()),
  fencedHosts: z.array(z.string()),
  overrides: z.array(z.string()),
  authorisation: z.object({ id: z.string(), context: ItemUseContextSchema, expiresAt: Iso }).nullable(),
})

export const RunRenewedSchema: z.ZodType<RunRenewed> = z.object({ run: z.string().regex(RUN_ID), expiresAt: Iso })

export const RunEndedSchema: z.ZodType<RunEnded> = z.object({ run: z.string().regex(RUN_ID), ended: z.literal(true) })

export const MachineProjectSchema: z.ZodType<MachineProject> = z.object({
  id: z.string().regex(PROJECT_ID),
  slug: z.string(),
  remotes: z.array(z.string()),
  defaultEnv: z.string(),
  environments: z.array(z.object({ name: z.string(), protected: z.boolean(), fences: z.array(z.string()), fourEyes: z.boolean() })),
  vars: z.array(
    z.object({
      name: z.string(),
      env: z.string(),
      source: z.enum(["item", "plain", "unset"]),
      item: z.string().nullable(),
      field: z.string().nullable(),
      note: z.string().optional(),
      protectedBy: z.array(z.object({ project: z.string(), env: z.string() })).optional(),
    }),
  ),
})
