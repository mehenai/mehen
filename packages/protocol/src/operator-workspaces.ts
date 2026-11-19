// The operator console's Workspaces view (CONSOLE_ROUTES in
// platform-console.ts): every workspace on this deployment, one page at a
// time, and one workspace with its people counted, its backups and
// restores, and the operator events that name it. Restoring and freezing
// are operator proposals (operator-proposals.ts, kinds workspace.restore
// and workspace.freeze), sent to the proposals route.
//
// Nothing here reaches inside a workspace: no credential, project, member,
// machine, ask or audit event. Owners are named, everyone else is counted.

import { z } from "zod"
import { WorkspaceIdSchema } from "./operator-workspace-terms.ts"
import { OperatorAccountRefSchema, OperatorEventViewSchema, OperatorProposalViewSchema } from "./operator-proposals.ts"
import { OperatorRequirementSchema } from "./platform-console.ts"

const Iso = z.iso.datetime()
const Count = z.number().int().nonnegative()

export const OPERATOR_WORKSPACES_PAGE_SIZE = 25
export const OPERATOR_WORKSPACE_EVENTS_SHOWN = 50
export const OPERATOR_WORKSPACE_RESTORES_SHOWN = 10
// The dumps a restore may name, as the bucket keeps them: every day of the
// last 35, and the first of each month for a year.
export const OPERATOR_WORKSPACE_DUMPS_SHOWN = 48

// ---------------------------------------------------------------- the list

// `all` is every workspace in the directory; `managed` the platforms'
// managed workspaces, which the directory lists apart.
export const OperatorWorkspaceFilterSchema = z.enum(["all", "active", "creating", "deleting", "managed"])
export type OperatorWorkspaceFilter = z.infer<typeof OperatorWorkspaceFilterSchema>

// `before`: the cursor the previous page answered as `next`.
const Cursor = z.string().regex(/^\d{1,16}:tn_[A-Za-z0-9_-]{1,64}$/)
export const OperatorWorkspaceQuerySchema = z.strictObject({
  q: z.string().trim().max(80).optional(),
  filter: OperatorWorkspaceFilterSchema.optional(),
  before: Cursor.optional(),
})
export type OperatorWorkspaceQuery = z.infer<typeof OperatorWorkspaceQuerySchema>

export const OperatorWorkspaceStatusSchema = z.enum(["creating", "active", "deleting", "deleted"])
export type OperatorWorkspaceStatus = z.infer<typeof OperatorWorkspaceStatusSchema>

// One workspace of the directory. `owners` come from the workspace object
// itself, null when it did not answer; `members` counts the memberships the
// directory holds (anyone joined or joining).
export const OperatorWorkspaceRowSchema = z.strictObject({
  kind: z.literal("workspace"),
  id: z.string(),
  slug: z.string(),
  name: z.string(),
  status: OperatorWorkspaceStatusSchema,
  owners: z.array(OperatorAccountRefSchema).nullable(),
  members: Count,
  createdBy: OperatorAccountRefSchema.nullable(),
  createdAt: Iso,
})
export type OperatorWorkspaceRow = z.infer<typeof OperatorWorkspaceRowSchema>

// One platform-managed workspace: its platform, never its subject.
export const OperatorManagedWorkspaceRowSchema = z.strictObject({
  kind: z.literal("managed"),
  id: z.string(),
  platform: z.strictObject({ id: z.string(), slug: z.string(), name: z.string() }),
  status: z.enum(["creating", "active", "deleting", "deleted", "purged"]),
  createdAt: Iso,
})
export type OperatorManagedWorkspaceRow = z.infer<typeof OperatorManagedWorkspaceRowSchema>

export const OperatorWorkspaceListSchema = z.strictObject({
  filter: OperatorWorkspaceFilterSchema,
  q: z.string(),
  workspaces: z.array(z.discriminatedUnion("kind", [OperatorWorkspaceRowSchema, OperatorManagedWorkspaceRowSchema])).max(OPERATOR_WORKSPACES_PAGE_SIZE),
  next: Cursor.nullable(),
})
export type OperatorWorkspaceList = z.infer<typeof OperatorWorkspaceListSchema>

// ---------------------------------------------------------------- one workspace

// Roles as the directory's memberships hint them (the workspace object is
// the authority), and `joining` those mid-join. From the object itself:
// `owners` by name, and `unconfirmed`, people an owner or admin has still
// to confirm; both null when it did not answer.
export const OperatorWorkspacePeopleSchema = z.strictObject({
  owners: z.array(OperatorAccountRefSchema).nullable(),
  roles: z.strictObject({ owner: Count, admin: Count, member: Count, guest: Count }),
  joining: Count,
  unconfirmed: Count.nullable(),
})
export type OperatorWorkspacePeople = z.infer<typeof OperatorWorkspacePeopleSchema>

export const OperatorRestoreViewSchema = z.strictObject({
  id: z.string(),
  source: z.enum(["pitr", "dump"]),
  target: z.string(),
  actor: z.string(),
  state: z.enum(["pending", "restarting", "done", "failed", "expired"]),
  createdAt: Iso,
  completedAt: Iso.nullable(),
  error: z.string().nullable(),
})
export type OperatorRestoreView = z.infer<typeof OperatorRestoreViewSchema>

// `lastDump`: the newest good dump; `lastFailure`: the newest failed day,
// when it is newer than that; `dumps`: the days a restore may name, newest
// first. The weekly pull runs off Cloudflare and leaves no record here.
export const OperatorWorkspaceBackupsSchema = z.strictObject({
  lastDump: z.strictObject({ date: z.string(), bytes: Count, sha256: z.string(), rootVersion: Count, at: Iso }).nullable(),
  lastFailure: z.strictObject({ date: z.string(), error: z.string(), attempts: Count }).nullable(),
  dumps: z.array(z.string()).max(OPERATOR_WORKSPACE_DUMPS_SHOWN),
  restores: z.array(OperatorRestoreViewSchema).max(OPERATOR_WORKSPACE_RESTORES_SHOWN),
})
export type OperatorWorkspaceBackups = z.infer<typeof OperatorWorkspaceBackupsSchema>

// `frozen` from the workspace object, null when it did not answer;
// `slugs` the slugs it has given up, newest first; `restore` the open
// restore proposal for it; `operators` how many operators there are, since
// a restore needs two; `missing` what the reader's own account lacks.
export const OperatorWorkspaceDetailSchema = z.strictObject({
  you: z.string(),
  workspace: z.strictObject({
    id: WorkspaceIdSchema,
    slug: z.string(),
    name: z.string(),
    status: OperatorWorkspaceStatusSchema,
    frozen: z.boolean().nullable(),
    createdAt: Iso,
    createdBy: OperatorAccountRefSchema.nullable(),
    deleteAfter: Iso.nullable(),
    displayRevision: Count,
    slugs: z.array(z.strictObject({ slug: z.string(), retiredAt: Iso })),
  }),
  people: OperatorWorkspacePeopleSchema,
  backups: OperatorWorkspaceBackupsSchema,
  restore: OperatorProposalViewSchema.nullable(),
  operators: Count,
  missing: z.array(OperatorRequirementSchema),
  events: z.array(OperatorEventViewSchema).max(OPERATOR_WORKSPACE_EVENTS_SHOWN),
})
export type OperatorWorkspaceDetail = z.infer<typeof OperatorWorkspaceDetailSchema>
