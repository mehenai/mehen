// The operator console and platform admins in Mehen's own web app: every
// route's path, request and answer, and the passkey step-up each write
// carries. The vault parses every request and every answer with these
// schemas, and the pages are built on the same types.
//
// The operator is an account the operator script marked; a platform admin
// is an account the operator added to one platform. Neither ever reaches a
// managed workspace's items, values or requests: nothing here names one.
//
// Every write is a `command` with its terms. The step-up binds the platform
// (its slug, and its id once it has one), the command and the SHA-256 of the
// canonical JSON of the whole command, so a passkey confirms exactly the
// change it was asked for, once. A
// destructive command, and every command that adds a key (which is then the
// platform), also carries `confirm`, the platform's slug typed back.
// The vault takes the digest of the command as its schema parses it, so a
// page sends the command exactly in that shape: a member a schema drops
// changes the digest, and the step-up is refused.

import { z } from "zod"
import { WorkspaceCreationDefaultSchema } from "./workspace.ts"
import { sha256B64 } from "./bytes.ts"
import { canonicalJson } from "./canonical-json.ts"
import { PlatformDefaultsSchema, PlatformDefaultsShapeSchema, PlatformIdSchema, PlatformKeyIdSchema, PlatformLimitsSchema, PlatformNameSchema, PlatformSlugSchema, PlatformStatusSchema, PlatformSubjectSchema } from "./platform.ts"
import type { WorkspaceStepUpAction } from "./workspace.ts"

const Iso = z.iso.datetime()
const Count = z.number().int().nonnegative()
const Revision = z.number().int().positive()

export const ACCOUNT_ID = /^acc_[A-Za-z0-9_-]{1,64}$/
export const AccountIdSchema = z.string().regex(ACCOUNT_ID)

// A removed platform's slug is renamed to this prefix and 24 random
// characters, so its own slug can be registered again; no slug with the
// prefix can be registered.
export const REMOVED_PLATFORM_SLUG_PREFIX = "removed-"
export const PLATFORM_KEY_MAX_OVERLAP_HOURS = 168
export const PLATFORM_RETIRE_MAX_DAYS = 365
export const PLATFORM_EVENTS_PAGE_SIZE = 50

// ---------------------------------------------------------------- what an operator account must have

// An operator acts on other people's accounts, so the account must have
// recovery set up, at least two passkeys with one of them a security key
// (USB, NFC or Bluetooth, as the account page labels one), no cooling-off
// and no security change pending. Checked when the role is granted and on
// every operator write; each value names one thing the account lacks.
export const OPERATOR_REQUIREMENTS = ["recovery", "two-passkeys", "security-key", "cooling-off", "security-change"] as const
export const OperatorRequirementSchema = z.enum(OPERATOR_REQUIREMENTS)
export type OperatorRequirement = z.infer<typeof OperatorRequirementSchema>

export const OPERATOR_REQUIREMENT_WORDS: Readonly<Record<OperatorRequirement, string>> = {
  recovery: "recovery is not set up",
  "two-passkeys": "it has fewer than two passkeys",
  "security-key": "none of its passkeys is a security key",
  "cooling-off": "it is cooling off after a recovery",
  "security-change": "a security change on it is still pending",
}

export const OPERATOR_REQUIREMENTS_RULE = "An operator account needs recovery set up, at least two passkeys with one of them a security key, no cooling-off and no security change pending."

// What the vault answers an operator write from an account that lacks
// something, and what the pages say: `whose` is "Your account" or the
// account's name.
export function operatorRequirementsRefusal(missing: readonly OperatorRequirement[], whose = "Your account"): string {
  return `${whose} cannot act as an operator yet: ${missing.map((m) => OPERATOR_REQUIREMENT_WORDS[m]).join("; ")}. ${OPERATOR_REQUIREMENTS_RULE}`
}

// ---------------------------------------------------------------- routes

export const CONSOLE_ROUTES = {
  // GET: what this account may open (ConsoleAccess). Every signed-in account.
  access: "/api/account/console",
  // The operator's, not_found for every other account.
  operatorStepUp: "/api/operator/stepup/start", // POST { action } -> { nonce, options }
  operatorPlatforms: "/api/operator/platforms", // GET OperatorPlatformList; POST OperatorRegisterRequest -> 201 OperatorChangeAnswer
  operatorPlatform: "/api/operator/platforms/:slug", // GET OperatorPlatformDetail; POST OperatorChangeRequest -> OperatorChangeAnswer
  operatorEvents: "/api/operator/platforms/:slug/events", // GET ?before=<cursor> -> PlatformEventPage
  // The Operators view (operator-proposals.ts): every operator, the
  // proposals and the operator events.
  operatorOperators: "/api/operator/operators", // GET OperatorsView
  operatorAccountLookup: "/api/operator/operators/lookup", // GET ?q=<acc_ id or linked email> -> OperatorCandidate
  operatorProposals: "/api/operator/proposals", // POST OperatorProposeRequest -> 201 OperatorProposalAnswer (200, applied, for a one-operator kind)
  operatorProposal: "/api/operator/proposals/:id", // POST OperatorProposalDecision -> OperatorProposalAnswer
  // The Workspaces view (operator-workspaces.ts); restoring and freezing
  // a workspace are proposals to operatorProposals.
  operatorWorkspaces: "/api/operator/workspaces", // GET ?q=&filter=&before= -> OperatorWorkspaceList
  operatorWorkspace: "/api/operator/workspaces/:id", // GET OperatorWorkspaceDetail
  // The Audit and Settings views (operator-audit.ts, operator-settings.ts);
  // a setting changes through operatorProposals.
  operatorAudit: "/api/operator/audit", // GET ?actor&action&target&from&to&before -> OperatorAuditPage
  operatorSettings: "/api/operator/settings", // GET OperatorSettingsView
  // Every signed-in account: an approved operator role waiting for it to accept.
  operatorInvitation: "/api/account/operator-invitation", // GET OperatorInvitationRead; POST OperatorAcceptRequest -> OperatorAcceptAnswer
  // The Accounts view (operator-accounts.ts); its changes are proposals.
  operatorAccounts: "/api/operator/accounts", // GET ?q=&filter=&before= -> OperatorAccountList
  operatorAccount: "/api/operator/accounts/:id", // GET OperatorAccountDetail
  operatorBreakGlassLink: "/api/operator/accounts/:id/break-glass-link", // POST OperatorBreakGlassLinkRequest -> OperatorBreakGlassLink
  // A platform admin's, for the platforms they administer only.
  adminPlatforms: "/api/platforms", // GET AdminPlatformList
  adminPlatform: "/api/platforms/:slug", // GET AdminPlatformDetail; POST AdminChangeRequest -> AdminChangeAnswer
  adminEvents: "/api/platforms/:slug/events", // GET ?before=<cursor> -> PlatformEventPage
  adminStepUp: "/api/platforms/:slug/stepup/start", // POST { action } -> { nonce, options }
} as const

// ---------------------------------------------------------------- requests

// Free words (a reason): no control characters and no space at either end,
// so what the page signs is what the vault reads.
const Words = z
  .string()
  .min(1)
  .max(200)
  .refine((value) => value.trim() === value && !/[\u0000-\u001f\u007f]/.test(value), "Use plain words with no space at either end.")
// The platform's slug, typed back by the person.
const Confirm = z.string().min(1).max(64)
// A public JWK as pasted or generated in the browser. The vault checks it is
// a P-256 public key and refuses one with a private part (`d`) in a plain
// sentence, so it is not narrowed here.
export const PublicJwkInputSchema = z.record(z.string(), z.unknown())
// Only the limits that change; the vault lays them over the current ones
// (the defaults, for a new platform) and checks the result.
export const PlatformLimitsChangeSchema = PlatformLimitsSchema.partial()
export type PlatformLimitsChange = z.infer<typeof PlatformLimitsChangeSchema>
const OverlapHours = z.number().int().min(0).max(PLATFORM_KEY_MAX_OVERLAP_HOURS)

export const OperatorRegisterSchema = z.strictObject({ command: z.literal("register"), slug: PlatformSlugSchema, name: PlatformNameSchema, key: PublicJwkInputSchema, limits: PlatformLimitsChangeSchema, confirm: Confirm })

export const OperatorPlatformCommandSchema = z.discriminatedUnion("command", [
  z.strictObject({ command: z.literal("suspend"), reason: Words, confirm: Confirm }),
  z.strictObject({ command: z.literal("resume") }),
  z.strictObject({ command: z.literal("rotate-key"), key: PublicJwkInputSchema, overlapHours: OverlapHours, confirm: Confirm }),
  z.strictObject({ command: z.literal("revoke-key"), key: PlatformKeyIdSchema, confirm: Confirm }),
  z.strictObject({ command: z.literal("limits"), limits: PlatformLimitsChangeSchema }),
  z.strictObject({ command: z.literal("delete-subjects"), reason: Words, confirm: Confirm }),
  z.strictObject({ command: z.literal("retire"), afterDays: z.number().int().min(0).max(PLATFORM_RETIRE_MAX_DAYS), confirm: Confirm }),
  z.strictObject({ command: z.literal("remove"), reason: Words, confirm: Confirm }),
  z.strictObject({ command: z.literal("add-admin"), account: AccountIdSchema }),
  z.strictObject({ command: z.literal("remove-admin"), account: AccountIdSchema }),
])

export type OperatorRegister = z.infer<typeof OperatorRegisterSchema>
export type OperatorPlatformCommand = z.infer<typeof OperatorPlatformCommandSchema>
export type OperatorCommand = OperatorRegister | OperatorPlatformCommand

export const AdminPlatformCommandSchema = z.discriminatedUnion("command", [
  // The same schema and rules as the platform's own defaults.put; `revision`
  // is the one the editor started from, refused once it has moved.
  z.strictObject({ command: z.literal("defaults"), defaults: PlatformDefaultsSchema, revision: Revision }),
  z.strictObject({ command: z.literal("rotate-key"), key: PublicJwkInputSchema, overlapHours: OverlapHours, confirm: Confirm }),
  z.strictObject({ command: z.literal("revoke-key"), key: PlatformKeyIdSchema, confirm: Confirm }),
  z.strictObject({ command: z.literal("delete-subject"), subject: PlatformSubjectSchema, confirm: Confirm }),
])
export type AdminPlatformCommand = z.infer<typeof AdminPlatformCommandSchema>

// The commands that also need the slug typed back: the destructive ones, and
// the ones that add a key, because whoever holds a key's private half is the
// platform until the key is revoked.
export const SLUG_CONFIRMED_PLATFORM_COMMANDS = ["register", "rotate-key", "suspend", "revoke-key", "delete-subjects", "retire", "remove", "delete-subject"] as const

// The step-up proof every write carries: the nonce from the step-up start
// and the browser's WebAuthn assertion. Without it the write is refused.
const StepUpSchema = z.strictObject({ nonce: z.string().min(1).max(200), assertion: z.unknown() })
export const OperatorRegisterRequestSchema = z.strictObject({ command: OperatorRegisterSchema, stepUp: StepUpSchema.optional() })
export type OperatorRegisterRequest = z.infer<typeof OperatorRegisterRequestSchema>
export const OperatorChangeRequestSchema = z.strictObject({ command: OperatorPlatformCommandSchema, stepUp: StepUpSchema.optional() })
export type OperatorChangeRequest = z.infer<typeof OperatorChangeRequestSchema>
export const AdminChangeRequestSchema = z.strictObject({ command: AdminPlatformCommandSchema, stepUp: StepUpSchema.optional() })
export type AdminChangeRequest = z.infer<typeof AdminChangeRequestSchema>

// ---------------------------------------------------------------- the step-up

export async function platformCommandDigest(command: OperatorCommand | AdminPlatformCommand): Promise<string> {
  return sha256B64(canonicalJson(command))
}

// What the operator's passkey confirms: `slug` is the one the command names
// (for register, the new one) and `platformId` that platform's id, null only
// for register. The id means a proof made for one platform never serves
// another registered later under the same slug.
export async function operatorStepUpAction(slug: string, platformId: string | null, command: OperatorCommand): Promise<WorkspaceStepUpAction> {
  if ((command.command === "register") !== (platformId === null)) throw new Error("A console step-up names the platform's id for every command but register.")
  return { type: "platform.operate", platform: slug, platformId, command: command.command, digest: await platformCommandDigest(command) }
}

export async function adminStepUpAction(slug: string, platformId: string, command: AdminPlatformCommand): Promise<WorkspaceStepUpAction> {
  return { type: "platform.administer", platform: slug, platformId, command: command.command, digest: await platformCommandDigest(command) }
}

// ---------------------------------------------------------------- answers

export const ConsoleAccessSchema = z.strictObject({
  operator: z.boolean(),
  platforms: z.array(z.strictObject({ id: PlatformIdSchema, slug: PlatformSlugSchema, name: z.string() })),
})
export type ConsoleAccess = z.infer<typeof ConsoleAccessSchema>

export const PlatformKeyViewSchema = z.strictObject({
  id: PlatformKeyIdSchema,
  thumbprint: z.string(),
  createdAt: Iso,
  createdBy: z.string(),
  expiresAt: Iso.nullable(),
  revokedAt: Iso.nullable(),
  // Neither revoked nor past its expiry.
  live: z.boolean(),
})
export type PlatformKeyView = z.infer<typeof PlatformKeyViewSchema>

export const SubjectCountsByStatusSchema = z.strictObject({ creating: Count, active: Count, deleting: Count, deleted: Count, purged: Count })
export type SubjectCountsByStatus = z.infer<typeof SubjectCountsByStatusSchema>

// The last 24 hours of the platform's calls, as of the cron's last copy;
// null before the first.
export const PlatformUsageSchema = z.strictObject({ asOf: Iso, devices: Count, itemsAdded: Count, itemsDeleted: Count, decisions: Count, refusals: Count }).nullable()
export type PlatformUsage = z.infer<typeof PlatformUsageSchema>

// Set once the operator removed the platform. `slug` is the one it had;
// `completedAt` is when the cron freed it, after every subject was purged.
export const PlatformRemovalSchema = z.strictObject({ requestedAt: Iso, by: z.string(), slug: PlatformSlugSchema, completedAt: Iso.nullable() }).nullable()
export type PlatformRemoval = z.infer<typeof PlatformRemovalSchema>

export const PlatformAdminViewSchema = z.strictObject({ account: AccountIdSchema, name: z.string(), addedAt: Iso, addedBy: z.string() })
export type PlatformAdminView = z.infer<typeof PlatformAdminViewSchema>

export const OperatorPlatformSummarySchema = z.strictObject({
  id: PlatformIdSchema,
  slug: PlatformSlugSchema,
  name: z.string(),
  status: PlatformStatusSchema,
  statusAt: Iso,
  statusBy: z.string(),
  statusReason: z.string().nullable(),
  retireAfter: Iso.nullable(),
  removal: PlatformRemovalSchema,
  createdAt: Iso,
  createdBy: z.string(),
  limits: PlatformLimitsSchema,
  subjects: SubjectCountsByStatusSchema,
  keys: z.array(PlatformKeyViewSchema),
  admins: z.array(PlatformAdminViewSchema),
})
export type OperatorPlatformSummary = z.infer<typeof OperatorPlatformSummarySchema>
// workspaceCreation: this deployment's rule for accounts the operator has
// not decided on, shown beside the platforms; missing: what the reading
// operator's own account lacks before it can make a change.
export const OperatorPlatformListSchema = z.strictObject({ platforms: z.array(OperatorPlatformSummarySchema), workspaceCreation: WorkspaceCreationDefaultSchema, missing: z.array(OperatorRequirementSchema) })
export type OperatorPlatformList = z.infer<typeof OperatorPlatformListSchema>

export const OperatorPlatformDetailSchema = OperatorPlatformSummarySchema.extend({
  defaults: PlatformDefaultsShapeSchema,
  defaultsRevision: Revision,
  usage: PlatformUsageSchema,
  operatorActions24h: Count,
})
export type OperatorPlatformDetail = z.infer<typeof OperatorPlatformDetailSchema>

export const OperatorChangeAnswerSchema = z.strictObject({ done: z.string(), platform: OperatorPlatformDetailSchema })
export type OperatorChangeAnswer = z.infer<typeof OperatorChangeAnswerSchema>

export const AdminPlatformSummarySchema = z.strictObject({ id: PlatformIdSchema, slug: PlatformSlugSchema, name: z.string(), status: PlatformStatusSchema, retireAfter: Iso.nullable(), subjects: SubjectCountsByStatusSchema })
export type AdminPlatformSummary = z.infer<typeof AdminPlatformSummarySchema>
export const AdminPlatformListSchema = z.strictObject({ platforms: z.array(AdminPlatformSummarySchema) })
export type AdminPlatformList = z.infer<typeof AdminPlatformListSchema>

export const AdminPlatformDetailSchema = AdminPlatformSummarySchema.extend({
  statusAt: Iso,
  limits: PlatformLimitsSchema,
  keys: z.array(PlatformKeyViewSchema),
  defaults: PlatformDefaultsShapeSchema,
  defaultsRevision: Revision,
  usage: PlatformUsageSchema,
})
export type AdminPlatformDetail = z.infer<typeof AdminPlatformDetailSchema>

export const AdminChangeAnswerSchema = z.strictObject({ done: z.string(), platform: AdminPlatformDetailSchema })
export type AdminChangeAnswer = z.infer<typeof AdminChangeAnswerSchema>

// One platform_events row, newest first. `actor` is `operator:<who>`,
// `admin:<account id>`, `platform:<key id>` or `system`; `detail` holds ids,
// counts and reasons, never a secret or a subject's name.
export const PlatformEventViewSchema = z.strictObject({ id: z.string(), at: Iso, actor: z.string(), action: z.string(), detail: z.record(z.string(), z.unknown()) })
export type PlatformEventView = z.infer<typeof PlatformEventViewSchema>
export const PlatformEventPageSchema = z.strictObject({ events: z.array(PlatformEventViewSchema).max(PLATFORM_EVENTS_PAGE_SIZE), next: z.string().nullable() })
export type PlatformEventPage = z.infer<typeof PlatformEventPageSchema>
// The cursor is the `next` of the page before: opaque to the pages.
export const PlatformEventQuerySchema = z.strictObject({ before: z.string().regex(/^\d{1,16}\.[A-Za-z0-9_-]{1,128}$/).optional() })
