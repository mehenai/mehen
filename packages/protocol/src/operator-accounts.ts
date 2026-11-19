// The Accounts view of the operator console (routes in CONSOLE_ROUTES): every
// account at this deployment, searched by name, id or linked Google email
// and filtered, one bounded page at a time; one account with its
// workspaces, passkeys and sessions as metadata only, and its events. Its
// changes are operator proposals (OPERATOR_PROPOSAL_KINDS): workspace
// creation, suspending and lifting by one operator; recovering access and
// deleting by two. Never a public key, a hash, a token or anything inside a
// workspace.

import { z } from "zod"
import { OperatorProposalViewSchema } from "./operator-proposals.ts"
import { AccountIdSchema, OperatorRequirementSchema } from "./platform-console.ts"
import { WorkspaceCreationDefaultSchema, WorkspaceCreationSourceSchema } from "./workspace.ts"

const Iso = z.iso.datetime()
const Count = z.number().int().nonnegative()
const Id = z.string().min(1).max(128)

export const OPERATOR_ACCOUNTS_PAGE = 50
export const OPERATOR_ACCOUNT_EVENTS_SHOWN = 50
export const OPERATOR_ACCOUNT_WORKSPACES_SHOWN = 100
// What "Deleted account" leaves of the name; deleting is refused while the
// account is a member of any workspace.
export const DELETED_ACCOUNT_NAME = "Deleted account"

export const OPERATOR_ACCOUNT_FILTERS = ["all", "suspended", "cooling-off", "no-recovery", "no-workspace", "operators"] as const
export const OperatorAccountFilterSchema = z.enum(OPERATOR_ACCOUNT_FILTERS)
export type OperatorAccountFilter = z.infer<typeof OperatorAccountFilterSchema>

// The next page starts before this account: its creation time and id.
export const OperatorAccountCursorSchema = z.string().regex(/^[0-9]{1,16}~acc_[A-Za-z0-9_-]{1,64}$/)

export const OperatorAccountListQuerySchema = z.strictObject({
  q: z.string().trim().max(254).optional(),
  filter: OperatorAccountFilterSchema.default("all"),
  before: OperatorAccountCursorSchema.optional(),
})
export type OperatorAccountListQuery = z.infer<typeof OperatorAccountListQuerySchema>

export const OperatorAccountStatusSchema = z.enum(["active", "deleting", "deleted"])

// Cooling off after a recovery or break-glass: until when, or null while the
// recovery is still reaching the account's workspaces.
export const OperatorAccountCoolingOffSchema = z.strictObject({ reason: z.enum(["recovery", "reset", "break-glass"]), until: Iso.nullable() })

// One account as the list shows it. `email` is the first linked Google
// sign-in's; `recovery` how it would get back in (null: not set up).
export const OperatorAccountSummarySchema = z.strictObject({
  account: AccountIdSchema,
  name: z.string(),
  email: z.string().nullable(),
  status: OperatorAccountStatusSchema,
  createdAt: Iso,
  operator: z.boolean(),
  suspendedAt: Iso.nullable(),
  coolingOff: OperatorAccountCoolingOffSchema.nullable(),
  transitionPending: z.boolean(),
  recovery: z.enum(["codes", "passkey"]).nullable(),
  lastSeenAt: Iso.nullable(),
  workspaces: Count,
  passkeys: z.strictObject({ count: Count, synced: Count, securityKeys: Count }),
  workspaceCreation: WorkspaceCreationSourceSchema,
})
export type OperatorAccountSummary = z.infer<typeof OperatorAccountSummarySchema>

export const OperatorAccountListSchema = z.strictObject({
  you: AccountIdSchema,
  operators: Count,
  workspaceCreation: WorkspaceCreationDefaultSchema,
  missing: z.array(OperatorRequirementSchema),
  accounts: z.array(OperatorAccountSummarySchema).max(OPERATOR_ACCOUNTS_PAGE),
  next: OperatorAccountCursorSchema.nullable(),
})
export type OperatorAccountList = z.infer<typeof OperatorAccountListSchema>

// A workspace the account belongs to, from the directory: `roleHint` is only
// a hint, since the workspace itself holds the member's role.
export const OperatorAccountWorkspaceSchema = z.strictObject({ workspace: Id, slug: z.string(), name: z.string(), roleHint: z.enum(["owner", "admin", "member", "guest"]), state: z.enum(["joining", "member", "left"]), since: Iso })
export type OperatorAccountWorkspace = z.infer<typeof OperatorAccountWorkspaceSchema>

// A passkey as metadata: never its key or credential id.
export const OperatorAccountPasskeySchema = z.strictObject({ name: z.string().nullable(), authenticator: z.string(), synced: z.boolean().nullable(), addedVia: z.enum(["signup", "settings", "recovery", "reset", "break-glass"]), createdAt: Iso, lastUsedAt: Iso.nullable() })
export type OperatorAccountPasskey = z.infer<typeof OperatorAccountPasskeySchema>

// Live sessions as counts by kind, and the latest sign of life.
export const OperatorAccountSessionsSchema = z.strictObject({ web: Count, app: Count, recovery: Count, lastSeenAt: Iso.nullable() })

export const OperatorAccountEventSchema = z.strictObject({ id: z.string(), at: Iso, action: z.string(), detail: z.record(z.string(), z.unknown()) })

// The account's recovery link while one is live: `yours` when you proposed
// it, so only you may take its link, once, when `state` is ready.
export const OperatorAccountBreakGlassSchema = z.strictObject({ intent: Id, state: z.enum(["pending", "ready"]), expiresAt: Iso, proposedBy: z.string(), yours: z.boolean(), linkTaken: z.boolean() })
export type OperatorAccountBreakGlass = z.infer<typeof OperatorAccountBreakGlassSchema>

export const OperatorAccountDetailSchema = z.strictObject({
  you: AccountIdSchema,
  operators: Count,
  workspaceCreationDefault: WorkspaceCreationDefaultSchema,
  missing: z.array(OperatorRequirementSchema),
  account: OperatorAccountSummarySchema,
  emails: z.array(z.string()),
  deletedAt: Iso.nullable(),
  workspaces: z.array(OperatorAccountWorkspaceSchema).max(OPERATOR_ACCOUNT_WORKSPACES_SHOWN),
  passkeys: z.array(OperatorAccountPasskeySchema),
  sessions: OperatorAccountSessionsSchema,
  events: z.array(OperatorAccountEventSchema).max(OPERATOR_ACCOUNT_EVENTS_SHOWN),
  open: z.array(OperatorProposalViewSchema),
  breakGlass: OperatorAccountBreakGlassSchema.nullable(),
})
export type OperatorAccountDetail = z.infer<typeof OperatorAccountDetailSchema>

const StepUpSchema = z.strictObject({ nonce: z.string().min(1).max(200), assertion: z.unknown() })

export const OperatorBreakGlassLinkRequestSchema = z.strictObject({ intent: Id, stepUp: StepUpSchema.optional() })
export type OperatorBreakGlassLinkRequest = z.infer<typeof OperatorBreakGlassLinkRequestSchema>
// The single-use link, shown once: it works until `expiresAt`.
export const OperatorBreakGlassLinkSchema = z.strictObject({ link: z.string(), expiresAt: Iso })
export type OperatorBreakGlassLink = z.infer<typeof OperatorBreakGlassLinkSchema>
