// The HTTP contract between the vault and everything that talks to it: the
// `mehen` CLI, `mehen mcp`, the web UI and any other agent. Request bodies are zod
// schemas because the server must validate them; responses are plain types.
//
// Two audiences, two prefixes:
//   /v1/*   machines. Every request carries a Mehen-Proof by the device key.
//   /api/*  the browser. A passkey web session cookie, plus a passkey
//           step-up assertion on anything that widens access.
//
// Every error, from either prefix, is JSON shaped as ApiError with the
// header `Mehen-Error: 1`, so a relayed upstream response can never be confused
// with a vault refusal. `next` always tells the caller what to do about it.

import { z } from "zod"
import { ItemUseContextSchema } from "./workspace.ts"
import { ALLOW_BODY_MATCHERS, BODY_MATCHERS } from "./body-match.ts"
import { LEASE_ONLY_HOST, misusesLeaseOnlyHost } from "./binding.ts"
import type { FingerprintGroupIndex, FingerprintWord } from "./fingerprint.ts"
import { PushDestinationSchema, type PushApprovalStatus, type PushApprovalView, type PushRecordView } from "./push.ts"
import { PolicyRememberSchema, type PolicyApprovalContext, type PolicyAreaOffer, type PolicyFloorView, type PolicyGrantStatus, type PolicyRouteScope, type PolicyRuleOffer, type PolicyRuleProposalRef, type PolicyRuleRef, type PolicyWindowMode } from "./policy-mode.ts"
import type { StepUpProof } from "./step-up-proof.ts"

// ---------------------------------------------------------------- errors

export const ERROR_CODES = [
  "bad_request",
  "unauthenticated", // no or invalid proof or session
  "proof_invalid", // signature, skew, replay or URL/body mismatch
  "device_pending", // enrolment not approved yet
  "device_revoked",
  "forbidden", // authenticated, but the device scope or role does not cover it
  "not_found",
  "conflict",
  "ambiguous", // several items could serve; pick one from `choices`
  "binding_refused", // the destination is outside the item's binding
  "surface_refused", // a placeholder or secret appeared outside its declared surface
  "policy_denied",
  "approval_required", // 409, `next` is the approval link, `approval` the id
  "mode_refused", // the item's ceiling or the device does not allow this exposure
  "environment_refused", // protected environment without an explicit --env and a grant
  "remote_mismatch", // project id claimed from a repo whose origin is not bound to it
  "needs_reauth", // OAuth connection is dead; `next` is a reconnect link
  "refresh_retrying", // transient refresh failure, retry after `retryAfter`
  "intake_required", // the credential does not exist yet; `next` is an intake link
  "frozen", // the tenant is frozen
  "rate_limited",
  "too_large",
  "upstream_failed", // the relay could not reach the upstream
  "internal",
  "account_pending",
  "owner_inactive",
  "identity_required",
  "project_unshared",
  "cli_outdated", // HTTP 426: the vault refuses an identified client below its minimum version
  "workload_ended", // the signing workload expired or was revoked, or its device was
  "workload_required", // the device acts only through workloads; its own key may not do this
  "platform_suspended", // the platform is suspended or retired (platform.ts)
  "quota_exceeded", // past one of the platform's limits (platform.ts)
  "origin_mismatch", // fill: the page is not one the item's lists allow (fill.ts)
  "totp_unreadable", // a one-time code secret that is not base32 or an otpauth://totp link (totp.ts)
  "provider_refused", // a provider refused a push into its secret store (push.ts); `providerStatus` is its HTTP status
] as const

export type ErrorCode = (typeof ERROR_CODES)[number]

// Process exit codes for `mehen` and anything else that wraps the vault. One
// table, so every tool and every doc agrees.
export const EXIT = {
  ok: 0,
  error: 1,
  usage: 2,
  approval: 3,
  human: 4, // a human must act
  refused: 5, // the vault refused by rule; retrying will not help
  identity: 6, // this machine's identity is not accepted
  transient: 7, // network, upstream or rate limit; retry, after `retryAfter` when given
} as const

export type ExitCode = (typeof EXIT)[keyof typeof EXIT]

export const EXIT_FOR_ERROR: Record<ErrorCode, ExitCode> = {
  bad_request: EXIT.usage,
  ambiguous: EXIT.usage,
  unauthenticated: EXIT.identity,
  proof_invalid: EXIT.identity,
  device_revoked: EXIT.identity,
  device_pending: EXIT.human,
  intake_required: EXIT.human,
  needs_reauth: EXIT.human,
  frozen: EXIT.human,
  approval_required: EXIT.approval,
  forbidden: EXIT.refused,
  binding_refused: EXIT.refused,
  surface_refused: EXIT.refused,
  policy_denied: EXIT.refused,
  mode_refused: EXIT.refused,
  environment_refused: EXIT.refused,
  remote_mismatch: EXIT.refused,
  refresh_retrying: EXIT.transient,
  rate_limited: EXIT.transient,
  upstream_failed: EXIT.transient,
  not_found: EXIT.error,
  conflict: EXIT.error,
  too_large: EXIT.error,
  internal: EXIT.error,
  account_pending: EXIT.human,
  owner_inactive: EXIT.human,
  identity_required: EXIT.human,
  project_unshared: EXIT.human,
  cli_outdated: EXIT.error,
  workload_ended: EXIT.identity,
  workload_required: EXIT.refused,
  platform_suspended: EXIT.refused,
  quota_exceeded: EXIT.refused,
  origin_mismatch: EXIT.refused,
  totp_unreadable: EXIT.human,
  provider_refused: EXIT.refused,
}

export type NextStep = {
  // What a human must open, when one must act.
  url?: string | undefined
  // A command an agent can run to continue, e.g. "mehen wait apr_3kq...".
  command?: string | undefined
  // One sentence an agent can relay to its human verbatim.
  say: string
  // Only in an error from mehen's MCP server, never from the vault: the
  // tool that does the step and its arguments, partial where a placeholder
  // such as "<mdt_id>" stands for a value the agent fills in.
  tool?: string | undefined
  arguments?: Record<string, string> | undefined
}

export type ApiError = {
  error: ErrorCode
  message: string
  next?: NextStep
  approval?: string
  bindingCode?: string
  choices?: { slug: string; account: string | null }[]
  retryAfter?: number
  // When `next.url` is a link that expires (approval_required, needs_reauth
  // with a reconnect link): the ISO time it stops working.
  expiresAt?: string
  // Only with approval_required; guest machines receive an empty list.
  deciders?: string[]
  // Only with account_pending.
  transition?: import("./workspace.ts").AccountSecurityTransitionView
  // Only on the enrolment renew route's terminal 409: the settled state, the
  // same answer a poll would give, the full active answer when active.
  enrolment?: import("./workspace.ts").WorkspaceEnrolStatus
  // Only on a refused adoption approval (conflict): each included row the
  // approval would fail, and why. Nothing in the batch was stored.
  refused?: { ref: string; reason: string }[]
  // Only on a forbidden standing rule (remember, propose, a decision): why
  // the request cannot be allowed from now on.
  ruleRefused?: import("./policy-mode.ts").PolicyRuleRefusal
  // Only on a forbidden task grant (remember, propose, a decision): why the
  // request or the terms cannot be granted.
  areaRefused?: import("./policy-mode.ts").PolicyAreaRefusal
  // Only on a forbidden request that the approval dial's Let it work
  // refused rather than asking a person: why trust would not let it through.
  dialRefused?: import("./workspace.ts").ApprovalDialRefusal
  // Only on not_found from a Google step whose invitation is no longer
  // active, so a page can drop the code it saved without reading the message.
  reason?: "invite_inactive"
  // Only with approval_required: the review group or bundle the ask is in,
  // how many of its asks are open and, when it has one, the group code its
  // Review together page shows. next.url stays the ask's own page.
  group?: { id: string; url: string; open: number; code?: string }
  // Only with approval_required: the machine's mandate would have let this
  // request through but for today's caps of these classes.
  mandate?: { id: string; capped: import("./mandate-terms.ts").MandateClass[] }
  // Only with approval_required, to the machine itself: a mandate could let
  // requests like this through; state says why this one asked.
  mandateCover?: import("./mandate-terms.ts").MandateCoverHint
  // Only with provider_refused: the HTTP status the provider answered.
  providerStatus?: number
}

export function apiErrorExtrasValid(error: ApiError): boolean {
  return (error.deciders === undefined || error.error === "approval_required") && (error.group === undefined || error.error === "approval_required") && (error.mandate === undefined || error.error === "approval_required") && (error.mandateCover === undefined || error.error === "approval_required") && (error.transition === undefined || error.error === "account_pending") && (error.refused === undefined || error.error === "conflict") && (error.ruleRefused === undefined || error.error === "forbidden") && (error.areaRefused === undefined || error.error === "forbidden") && (error.dialRefused === undefined || error.error === "forbidden") && (error.providerStatus === undefined || error.error === "provider_refused")
}

export const ERROR_HEADER = "Mehen-Error"
export const ITEM_HEADER = "Mehen-Item"
// On a relay response a standing rule allowed without asking: the rul_ id.
export const RULE_HEADER = "Mehen-Rule"
// On a relay response a credential's posture allowed without asking: its
// level, routine or trust.
export const POSTURE_HEADER = "Mehen-Posture"
// On a relay response a mandate let through without asking: its mdt_ id.
export const MANDATE_HEADER = "Mehen-Mandate"

// ---------------------------------------------------------------- ids and shared shapes

export const Slug = z.string().regex(/^[a-z][a-z0-9-]{1,63}$/).refine((s) => !s.endsWith("-") && !s.includes("--"), "invalid slug")
export const Tag = z.string().regex(/^[a-z0-9][a-z0-9:_-]{0,39}$/)
export const EnvName = z.string().regex(/^[a-z][a-z0-9-]{0,31}$/)
export const VarName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/)

export const ModeSchema = z.enum(["relay", "sign", "mint", "placeholder", "fill", "lease", "reveal"])
export const KindSchema = z.enum([
  "api-key",
  "bearer-token",
  "basic-auth",
  "custom-headers",
  "oauth-client",
  "oauth-connection",
  "google-service-account",
  "github-app",
  "hmac-key",
  "ssh-key",
  "password-login",
  "totp",
  "database-url",
  "smtp-imap",
  "cloud-access-key",
  "file",
  "note",
  "generic",
])

// Members write path globs, so each is short and holds at most four "**".
const PathPattern = z
  .string()
  .max(256)
  .refine((p) => (p.match(/\*\*/g) ?? []).length <= 4, 'may hold at most 4 "**"')
const MethodName = z.string().min(1).max(16)

export const BindingSchema = z.object({
  hosts: z
    .array(z.string().min(1).max(253))
    .min(1)
    .max(32)
    .refine((hosts) => !misusesLeaseOnlyHost(hosts), `may name ${LEASE_ONLY_HOST} only on its own, and no other host under mehen.invalid`),
  schemes: z.array(z.enum(["https", "http", "wss", "ws"])).optional(),
  ports: z.array(z.number().int().min(1).max(65535)).optional(),
  paths: z.array(PathPattern.startsWith("/")).max(64).optional(),
  methods: z.array(MethodName).max(16).optional(),
})

export const PolicySchema = z.object({
  default: z.enum(["allow", "approve", "deny"]),
  rules: z
    .array(
      z
        .object({
          action: z.enum(["allow", "approve", "deny"]),
          methods: z.array(MethodName).max(16).optional(),
          paths: z.array(PathPattern).max(32).optional(),
          // Narrows the rule to requests whose body matches (body-match.ts).
          body: z.enum(BODY_MATCHERS).optional(),
          note: z.string().max(200).optional(),
        })
        .refine(
          (r) => r.body === undefined || (r.action === "allow") === ALLOW_BODY_MATCHERS.includes(r.body),
          'an allow rule may carry only the "graphql-query" body matcher, and a deny or approve rule any other',
        ),
    )
    .max(64),
})

// Where and how a secret goes into a request. Fixed per item by a human or
// a template; never chosen by the caller of the relay.
export const InjectionSchema = z.discriminatedUnion("in", [
  // format uses {field} markers: "Bearer {key}", "token {token}".
  z.object({ in: z.literal("header"), name: z.string().min(1).max(64), format: z.string().min(1).max(200) }),
  z.object({ in: z.literal("query"), name: z.string().min(1).max(64), field: z.string() }),
  z.object({ in: z.literal("basic"), username: z.string(), password: z.string() }),
  z.object({ in: z.literal("headers"), field: z.string() }), // custom-headers: a JSON map of header to value
])

export type BindingInput = z.infer<typeof BindingSchema>
export type PolicyInput = z.infer<typeof PolicySchema>
export type Injection = z.infer<typeof InjectionSchema>

export type SecretFieldInfo = {
  name: string
  set: boolean
  length: number
  prefix: string // well-known prefix only ("sk-proj-", "ghp_"), never secret characters
  fingerprint: string // first 12 chars of base64url HMAC-SHA256 over item and value, keyed per tenant from the root key
}

export type ItemSummary = {
  slug: string
  kind: z.infer<typeof KindSchema>
  provider: string | null
  account: string | null // verified where the provider allows it
  accountVerified: boolean
  tags: string[]
  ceiling: z.infer<typeof ModeSchema>
  hosts: string[]
  status: "active" | "needs_reauth" | "refresh_retrying" | "disabled"
  // Present while the item is flagged for a human to look at, for example
  // because an upstream echoed its value back. Cleared when it is replaced.
  review?: { reason: string; since: string } | undefined
  updatedAt: string
  // When the relay last used it; null for never. Set on every summary the
  // vault builds (the list and the description alike).
  lastUsedAt?: string | null | undefined
  // The item's policy, so a list can say what agents may do with it. Set on
  // every summary the vault builds; the CLI's own summary leaves it out.
  policy?: PolicyInput | undefined
}

export type ItemDescription = ItemSummary & {
  description: string | null
  publicFields: Record<string, string>
  secretFields: SecretFieldInfo[]
  binding: BindingInput
  policy: PolicyInput
  injection: Injection | null
  version: number
  lastUsedAt: string | null
  rotatedAt: string | null
  policyFloor?: PolicyFloorView[] | undefined
  // The latest push to each destination this item was put into (push.ts);
  // absent from a vault without pushes.
  pushes?: PushRecordView[] | undefined
  // How careful the credential is, as a machine may know it: the level,
  // whether it lets this key through, and the catalogue it reads. Never
  // which other machines it covers. Absent from a vault without postures.
  posture?: ItemDescriptionPosture | undefined
}
export type ItemDescriptionPosture = { level: import("./policy-mode.ts").PostureLevel; coversThisKey: boolean; catalogue: import("./policy-mode.ts").PostureCatalogue | null }

// ---------------------------------------------------------------- /v1: enrolment (proof by the new key, `ten` = "enrol")

export const EnrolStart = z.object({
  name: z.string().min(1).max(64),
  backend: z.enum(["secure-enclave", "software"]),
  jwk: z.object({ kty: z.literal("EC"), crv: z.literal("P-256"), x: z.string(), y: z.string() }),
  host: z.string().max(253).optional(), // hostname, shown to the approver
})
export type EnrolStartResponse = {
  enrolment: string // enr_...; the proof `kid` while pending
  code: string // 8 characters, shown on the approval page
  url: string // https://vault/e/<code>
  fingerprint: string // JWK thumbprint, first 16 characters, grouped
  expiresAt: string
  hardExpiresAt: string // the lease's fixed end; renewal never moves it
}
// POST /v1/enrol/:enrolment/renew. Never the code or the URL.
export type EnrolRenewResponse = { enrolment: string; expiresAt: string; hardExpiresAt: string }
// GET /v1/enrol/:enrolment
export type EnrolStatus =
  | { status: "pending"; expiresAt: string }
  | { status: "rejected" | "expired" }
  | { status: "active"; tenant: string; device: string; scope: DeviceScope }

export type DeviceScope = {
  tags: string[] // empty: every item
  projects: string[] // empty: every project
  maxEnvironment: "unprotected" | "protected"
  modes: z.infer<typeof ModeSchema>[]
}

// ---------------------------------------------------------------- /v1: items

// GET /v1/me. `fingerprint` is fingerprintOf the key the vault holds for
// this device, as its devices page shows it (four groups of four).
// workload: present only when a workload signed GET /v1/me; a device's own
// proof never carries it. Everything else describes the device.
// ownerRole: the role of the member who owns the device, or team for a
// team's device; absent from an older vault.
export type Me = { tenant: string; device: string; name: string; scope: DeviceScope; frozen: boolean; fingerprint: string; capabilities: { environmentV2: boolean; runBaseUrl: boolean; runFiles: boolean; sealedEnvImport: boolean; policyV1: boolean }; ownerRole?: import("./workspace.ts").WorkspaceRole | "team" | undefined; workload?: import("./workload.ts").WorkloadView | undefined }
// GET /v1/items?tag=&kind=&provider=
export type ItemList = { items: ItemSummary[] }
// GET /v1/items/:slug -> ItemDescription

// POST /v1/intakes: an agent asks a human for a credential.
export const IntakeCreate = z.object({
  kind: KindSchema,
  slug: Slug,
  provider: z.string().max(64).optional(), // template id: "openai", "github-pat", "google-oauth-client"
  reason: z.string().min(1).max(500),
  tags: z.array(Tag).max(16).optional(),
  // Proposed only; the human sees it and may change it. A template's binding wins.
  binding: BindingSchema.optional(),
  // Proposed only, for a new item of a kind the relay injects and no
  // template; the human sees it marked unverified. Without one the kind's
  // usual injection is used ("Bearer {key}" in Authorization for an api-key).
  injection: InjectionSchema.optional(),
  session: z.string().max(120).optional(), // agent session label, shown to the human
  // An open intake from this device for the same slug with the same kind,
  // provider, binding, injection and tags is returned again instead of a
  // second link; one with other parameters is refused. `fresh` supersedes
  // the open one (it is cancelled) and makes a new link.
  fresh: z.boolean().optional(),
})
// `url` is absent in a managed workspace (platform.ts): no Mehen page serves it.
export type IntakeCreated = { intake: string; url?: string | undefined; expiresAt: string }
// GET /v1/intakes/:id
export type IntakeStatus = {
  intake: string
  status: "open" | "completed" | "expired" | "cancelled"
  item?: ItemSummary | undefined
  // When the link stops working (the request's own expiry, whatever its status).
  expiresAt: string
  // Set on a cancelled intake that this device replaced with `fresh: true`.
  superseded?: true | undefined
}

// ---------------------------------------------------------------- /v1: relay

// The longest relay body, in base64url characters, so at most 10,500,000 bytes as sent.
export const MAX_RELAY_BODY_CHARS = 14_000_000

export const RelayRequest = z.object({
  context: ItemUseContextSchema.optional(),
  // Exactly one of item (inject that item per its injection) or run (swap
  // the run's placeholders found in the declared surfaces).
  item: Slug.optional(),
  run: z.string().max(64).optional(),
  method: z.string().min(1).max(16),
  url: z.string().url().max(8192),
  headers: z.array(z.tuple([z.string().max(256), z.string().max(16384)])).max(100),
  body: z.string().max(MAX_RELAY_BODY_CHARS).optional(), // base64url
  session: z.string().max(120).optional(),
  // Present when retrying after an approval was granted.
  approval: z.string().max(64).optional(),
  // An open ask of this machine (and workload) to the same place that this
  // request replaces, when it is held for approval: that ask then reads
  // superseded. Refused unless the vault has batch approvals on.
  replaces: z.string().regex(/^apr_[A-Za-z0-9_-]{1,60}$/).optional(),
})
export type RelayRequestInput = z.infer<typeof RelayRequest>
// Response: the upstream status, filtered headers and body, streamed, with
// Mehen-Item: <slug> (<account>) and Mehen-Upstream: 1. A vault refusal carries
// Mehen-Error: 1 instead.
export const UPSTREAM_HEADER = "Mehen-Upstream"

// ---------------------------------------------------------------- /v1: OAuth connections

export const ConnectCreate = z.object({
  provider: z.string().max(64), // template id: "google-gmail"
  // The oauth-client item. May be left out with `requestClient`, when it
  // defaults to the provider's client template id.
  client: Slug.optional(),
  slug: Slug, // the connection item to create, or reconnect
  scopes: z.array(z.string().max(200)).max(50).optional(), // within the template's allowed set
  expect: z.string().max(320).optional(), // expected account (email or login)
  reason: z.string().min(1).max(500),
  session: z.string().max(120).optional(),
  // When the client item does not exist yet: also create an intake for it
  // (kind oauth-client, the provider's client template) chained to this
  // connect, which can only start once that intake has saved the client.
  requestClient: z.boolean().optional(),
  // Tags for the client item that intake creates; the human sees them.
  clientTags: z.array(Tag).max(16).optional(),
  // As IntakeCreate.fresh: an open connect from this device for the same
  // slug and parameters is returned again; `fresh` supersedes it.
  fresh: z.boolean().optional(),
})
export type ConnectCreated = {
  connect: string
  // Absent in a managed workspace (platform.ts): the platform starts connections.
  url?: string | undefined
  expiresAt: string
  // The chained client intake, when `requestClient` made one: the human
  // fills it in first, and its page leads on to this connect.
  intake?: IntakeCreated | undefined
}
// GET /v1/connect/:id
export type ConnectStatus = {
  connect: string
  status: "open" | "completed" | "mismatch" | "failed" | "expired"
  item?: ItemSummary | undefined
  account?: string | undefined
  grantedScopes?: string[] | undefined
  message?: string | undefined
  // When the link stops working. A connect chained to a client intake
  // lives as long as that intake, then 15 minutes from its completion.
  expiresAt: string
}

// ---------------------------------------------------------------- /v1: projects and runs

export const ProjectCreate = z.object({
  slug: Slug,
  remote: z.string().max(512).nullable(), // normalised origin, "github.com/example/foo"
  environments: z.array(z.object({ name: EnvName, protected: z.boolean() })).min(1).max(16),
  defaultEnv: EnvName,
})
export type Project = {
  id: string // prj_...
  slug: string
  remotes: string[]
  defaultEnv: string
  environments: { name: string; protected: boolean; fences: string[] }[]
  // A device sees `item: null` with a `note` for an item outside its scope.
  // A member sees `protectedBy` on a variable of an unprotected environment
  // whose item backs a protected environment: runs here never receive it.
  vars: { name: string; env: string; source: "item" | "plain" | "unset"; item: string | null; field: string | null; note?: string | undefined; protectedBy?: { project: string; env: string }[] | undefined }[]
  // Set on a change's response when it has effects beyond the variable itself.
  warnings?: string[] | undefined
}
// GET /v1/projects?remote=: the project bound to a checkout's origin, for a
// machine that may use it. Variable names only, never a value or an item.
export const ProjectBindingSchema = z.object({
  id: z.string().regex(/^prj_[A-Za-z0-9_-]{1,60}$/),
  slug: Slug,
  defaultEnv: EnvName,
  environments: z.array(z.object({ name: EnvName, protected: z.boolean(), variables: z.array(VarName) })),
})
export type ProjectBinding = z.infer<typeof ProjectBindingSchema>

// PUT /v1/projects/:id/vars/:name. Agents may only set unprotected environments.
export const VarSet = z.object({
  env: EnvName,
  item: Slug.optional(),
  field: z.string().max(64).optional(),
  plain: z.string().max(4096).optional(), // non-secret config only; refused if it looks like a secret
})

export const RunCreate = z.object({
  project: z.string().max(64),
  env: EnvName,
  envSource: z.enum(["flag", "env-var", "default"]), // protected environments need "flag"
  remote: z.string().max(512).nullable(),
  worktree: z.string().max(1024),
  head: z.string().max(64).nullable(),
  vars: z.array(VarName).max(500),
  command: z.string().max(200), // argv[0] and the first argument, for the audit log
  // The whole command line. A protected run needs it: its approval covers
  // argvSha256 = base64url(SHA-256(canonicalJson(argv))) and its card shows
  // every argument. Only an argv within RUN_ARGV_LIMITS can be approved.
  argv: z.array(z.string().max(65_536)).min(1).max(4096).optional(),
  session: z.string().max(120).optional(),
  approval: z.string().max(64).optional(),
  // A service run (mehen run --service): no maximum life while it renews, and
  // re-planned on every renewal. Only from a device whose scope has
  // serviceRuns, and only in an unprotected environment.
  service: z.boolean().optional(),
})
// What an approval card can show in full: longer command lines are refused
// for approval; wrap them in a script.
export const RUN_ARGV_LIMITS = { totalChars: 4096, argChars: 1024 } as const
export type RunVar =
  | { name: string; delivery: "plain"; value: string }
  | { name: string; delivery: "placeholder"; value: string; item: string; hosts: string[] }
  | { name: string; delivery: "base-url"; value: string; item: string } // OPENAI_BASE_URL style, to the local relay
  | { name: string; delivery: "lease"; value: string; item: string }
  | { name: string; delivery: "missing"; next: NextStep }
export type RunCreated = {
  run: string // run_...
  expiresAt: string // runs renew with POST /v1/runs/:id/renew while the child lives
  // The run's hard end: renewal never moves expiresAt past it. Absent from an
  // older vault; null for a run with no maximum life.
  endsAt?: string | null | undefined
  project: { id: string; slug: string }
  env: string
  vars: RunVar[]
  // Hosts the local relay must terminate TLS for; everything else is tunnelled.
  interceptHosts: string[]
  // Hosts fenced to other environments: the local relay refuses them.
  fencedHosts: string[]
}
// POST /v1/runs/:id/renew answers Pick<RunCreated, "run" | "expiresAt" | "endsAt">.
// DELETE /v1/runs/:id ends it; its placeholders die.

// ---------------------------------------------------------------- /v1: approvals, leases, control

// GET /v1/approvals/:id (long-polls up to 25 s with ?wait=1)
// superseded: answered only to mehen 0.3.17 and later, with replacedBy, the
// newer ask from this machine to the same place; an older mehen reads stale.
export type ApprovalStatus = {
  approval: string
  status: "pending" | "approved" | "denied" | "expired" | "used" | "revoked" | "stale" | "superseded"
  replacedBy?: string | undefined
  bindingCode: string
  summary: string
  item?: string | undefined
  policyContext?: PolicyApprovalContext | undefined
  rememberOptions?: { route: { scope: PolicyRouteScope; policyMode: PolicyWindowMode; maxTtlSeconds: number } | null } | undefined
  grant?: PolicyGrantStatus | undefined
  // After an approval that remembered the request as a standing rule: the
  // rule, or, when a manager of the credential's home must co-sign, the
  // proposal that waits for them (an ask: write its link and code).
  rule?: PolicyRuleRef | undefined
  ruleProposal?: PolicyRuleProposalRef | undefined
  // When the undecided approval stops being decidable.
  expiresAt: string
  // When a human approved it: an approval that reads expired with this set was
  // given and ended unused, not left undecided.
  approvedAt?: string | undefined
  // Only on an approval that asked for a push (push.ts): how far it has got.
  // `mehen wait` and `mehen push --wait` end when its state is done, failed,
  // unknown or not_sent.
  push?: PushApprovalStatus | undefined
}

// POST /v1/approvals/bundles: up to APPROVAL_BUNDLE_MAX relay requests run
// through the relay's authorisation without opening a secret or sending
// anything; each held one becomes an ask in the bundle, which a human
// reviews together at `url` (/w/<slug>/g/bnd_...). reason: the agent's
// words, shown unverified.
export const APPROVAL_BUNDLE_MAX = 20
export const ApprovalBundleCreate = z.strictObject({ requests: z.array(RelayRequest.omit({ approval: true, replaces: true })).min(1).max(APPROVAL_BUNDLE_MAX), reason: z.string().max(200).optional() })
// POST /v1/push: put one secret field of `item` (its kind's primary when
// `field` is left out) into the store `to` names, using the credential
// `with` names, else the one this machine may use for that provider.
// reason: the agent's words, shown unverified.
export const PushRequest = z.strictObject({ item: Slug, field: z.string().min(1).max(64).optional(), to: PushDestinationSchema, with: Slug.optional(), reason: z.string().max(200).optional() })
export type PushRequestInput = z.infer<typeof PushRequest>
export type ApprovalBundleOutcome = "ask" | "allowed" | "refused"
// mandateCover: only on an "ask", as on approval_required to the machine
// itself: a mandate could let requests like this through, and why this one
// asked. code: the bundle's group code, which its Review together page
// shows, so the person checks one code for the whole bundle.
export type ApprovalBundleCreated = { bundle: string; url: string; expiresAt: string; code?: string; results: { index: number; outcome: ApprovalBundleOutcome; approval?: string; bindingCode?: string; mandateCover?: import("./mandate-terms.ts").MandateCoverHint; error?: Pick<ApiError, "error" | "message" | "next" | "dialRefused"> }[] }
// GET /v1/approvals/bundles/:id (long-polls up to 25 s with ?wait=1)
export type ApprovalBundleStatus = { bundle: string; approvals: { id: string; status: ApprovalStatus["status"] }[] }

// POST /v1/lease: the value into one child process. Refused unless the item's
// ceiling, the device scope and the run allow "lease".
export const LeaseRequest = z.object({ item: Slug, field: z.string().max(64).optional(), run: z.string().max(64) })
export type Lease = { value: string; expiresAt: string }

// POST /v1/devices/self/revoke, POST /v1/freeze: the panic buttons a device may press.

// ---------------------------------------------------------------- /api: the browser

export const PUBLIC_SEAL_KEY_PATH = "/v1/seal-key" // GET, unauthenticated: { jwk, kid }

// Step-up: the passkey challenge is derived from the action, so what the
// human sees is what they sign.
// challenge = base64url(SHA-256("mehen-stepup/v1\n" + nonce + "\n" + canonical JSON of action)).
// The server rebuilds the action from what it is about to do, never from the
// action the page claims. Field rules:
//   enrol.approve    enrolment = the code from the /e/<code> URL, upper case;
//                    thumbprint = the full RFC 7638 thumbprint stored on that
//                    enrolment. The page never holds it: it posts an
//                    EnrolApproveStepUpRequest and the server fills it in
//   approval.decide  digest = the stored approval digest (ApprovalView.digest);
//                    constraints = the uses and duration the human chose (deny
//                    signs ApprovalView.constraints)
//   item.update      digest = base64url(SHA-256(canonicalJson(the update body
//                    without stepUp))), i.e. { binding?, policy?, ceiling?, tags?, description? }
export const StepUpAction = z.discriminatedUnion("type", [
  z.object({ type: z.literal("intake.submit"), intake: z.string(), digest: z.string() }),
  z.object({ type: z.literal("enrol.approve"), enrolment: z.string(), thumbprint: z.string(), scope: z.unknown() }),
  z.object({
    type: z.literal("approval.decide"),
    approval: z.string(),
    digest: z.string(),
    decision: z.enum(["approve", "deny"]),
    constraints: z.strictObject({ uses: z.number().int().min(1).max(100).nullable(), ttlSeconds: z.number().int().min(60).max(86_400) }),
    remember: PolicyRememberSchema.optional(),
  }).strict().refine((action) => action.decision !== "deny" || action.remember === undefined, "Deny cannot remember access"),
  z.strictObject({
    type: z.literal("policy.decide"),
    proposal: z.string(),
    digest: z.string(),
    decision: z.enum(["approve", "deny"]),
    effectDigest: z.string().nullable(),
  }).refine((action) => action.decision === "deny" ? action.effectDigest === null : action.effectDigest !== null, "Only approval has an effect digest"),
  z.object({ type: z.literal("item.update"), item: z.string(), digest: z.string() }),
  z.object({ type: z.literal("item.reveal"), item: z.string(), field: z.string() }),
  z.object({ type: z.literal("item.delete"), item: z.string() }),
  z.object({ type: z.literal("device.revoke"), device: z.string() }),
  z.object({ type: z.literal("device.rescope"), device: z.string(), before: z.unknown(), scope: z.unknown() }),
  z.object({ type: z.literal("invite.create"), role: z.enum(["owner", "member"]) }),
  z.object({ type: z.literal("tenant.unfreeze") }),
  // [AUTH] sign-in and recovery. Every one is a passkey assertion; whether a
  // member in a cooling-off may sign it is decided in step-up-rules.ts.
  z.object({ type: z.literal("passkey.add") }),
  z.object({ type: z.literal("passkey.remove"), passkey: z.string() }), // pk_ handle
  z.object({ type: z.literal("recovery.generate") }),
  z.object({ type: z.literal("recovery.resolve"), notice: z.string(), outcome: z.enum(["cancel", "keep"]) }),
  z.object({ type: z.literal("member.reset"), member: z.string() }),
  z.object({ type: z.literal("member.remove"), member: z.string() }),
  z.object({ type: z.literal("member.confirm"), member: z.string() }),
])
export type StepUpActionInput = z.infer<typeof StepUpAction>

// The approval digest ties a decision to one exact request.
// digest = base64url(SHA-256(canonical JSON of { item, method, url, contentType, contentEncoding, headersSha256, bodySha256, constraints })).
// contentType and contentEncoding are the request's headers as sent (null
// when absent), because they change how the same body bytes are read.
// headersSha256 = base64url(SHA-256(canonical JSON of [[name, value], ...])):
// every header the relay forwards from the agent, as sent (names lower
// case, sorted by name then value), apart from the ones the item's own
// injection overwrites. A run approval sends no request and binds [].
// `constraints` here are what the agent's request asked for (the defaults
// when it asked for nothing); the human's choice travels in the step-up
// action, so changing uses or duration never changes the digest.
export type ApprovalSubject = {
  item: string
  method: string
  url: string
  contentType: string | null
  contentEncoding: string | null
  headersSha256: string
  bodySha256: string
  constraints: { uses: number | null; ttlSeconds: number }
}

// Canonical JSON (keys sorted, no whitespace, arrays in order) is used for
// every digest above. It lives in its own module so the browser bundle can
// import it without zod.
export { canonicalJson } from "./canonical-json.ts"

// ---------------------------------------------------------------- /api: the browser routes
//
// Same-origin JSON only (the Worker checks Origin and Sec-Fetch-Site on every
// non-GET). The session is the __Host-mehen_session cookie. A body field
// `stepUp: StepUpProof` is required wherever the comment says "step-up":
// the page first calls POST /api/stepup with the action, gets a nonce and
// WebAuthn request options whose challenge commits to (nonce, action), runs
// navigator.credentials.get, and sends { nonce, assertion } back. Inside a
// passkey grace window the start answers { nonce, grace: { until } } with no
// options, and the page sends { nonce, grace: true } (WORKSPACE_STEP_UP_GRACE).
//
// The UI builds pages against these shapes.

export { StepUpProofSchema, type StepUpProof } from "./step-up-proof.ts"
// GET /api/account/stepup/grace: this browser session's passkey grace
// window, until when; POST /api/account/stepup/grace/end ends it.
export type StepUpGraceRead = { grace: { until: string } | null }

// POST /api/auth/signup/options { invite } -> { options } (WebAuthn creation options, opaque to the page)
// POST /api/auth/signup/verify  { invite, name, response } -> { member }
//      The first owner signs up with the BOOTSTRAP_CODE as the invite; that creates the tenant.
// POST /api/auth/signin/options {} -> { options, flow }
// POST /api/auth/signin/verify  { flow, response } -> { member }
// POST /api/auth/signout        {} -> {}
// GET  /api/session -> SessionInfo | 401
export type SessionInfo = {
  member: string
  name: string
  role: "owner" | "member"
  tenant: string
  tenantName: string
  status: "unconfirmed" | "active"
  // Set while a recovery, reset or break-glass cooling-off runs.
  restricted: { reason: "recovery" | "reset" | "break-glass"; until: string; notice: string } | null
}
// POST /api/stepup { action: StepUpActionInput | EnrolApproveStepUpRequest } -> { nonce, options }
//      For enrol.approve the page posts the code and scope only; the server
//      looks the pending enrolment up and signs over its stored thumbprint.
export type EnrolApproveStepUpRequest = { type: "enrol.approve"; enrolment: string; scope: DeviceScope }
// GET  /api/enrolments/:code -> EnrolmentView
// The key's fingerprint (fingerprintOf) with one group withheld. The page
// shows `groups` with four dots at `hidden`; the owner types the hidden group
// from the terminal or a native app's card, the page compares it against `check`
// (fingerprintGroupCheck) before the passkey prompt, and the server compares
// it against the stored thumbprint on approve. The view never carries the
// full fingerprint, the thumbprint, the hidden group or the key.
export type EnrolmentFingerprint = {
  groups: [string, string, string] // the three shown groups, in fingerprint order, the hidden one left out
  hidden: FingerprintGroupIndex
  check: string
  words: FingerprintWord[]
}
export type EnrolmentView = {
  code: string
  name: string
  host: string | null
  backend: "secure-enclave" | "software"
  fingerprint: EnrolmentFingerprint
  status: "pending" | "active" | "rejected" | "expired"
  expiresAt: string
  // Expired, owner only: the same key has a newer pending enrolment. Its
  // code is stored hashed, so the view says only until when that link lives;
  // the terminal and a native app's card carry the link itself.
  fresh?: { expiresAt: string }
}
// POST /api/enrolments/:code/approve { scope: DeviceScope, group, stepUp } -> { device }   step-up "enrol.approve"
//      `group` is the hidden fingerprint group as typed; wrong five times and the enrolment is rejected.
// POST /api/enrolments/:code/reject {} -> {}                                          owner only
// GET  /api/devices -> { devices: DeviceView[] }
//      `fingerprintWords` are the key's four words (fingerprintWords), so a machine card reads like its enrol card did.
// `revokedAt` is set only on a revoked device.
export type DeviceView = { device: string; name: string; backend: string; host: string | null; scope: DeviceScope; createdAt: string; lastSeenAt: string | null; revoked: boolean; revokedAt?: string; fingerprintWords: FingerprintWord[] }
// POST /api/devices/:id/revoke { stepUp } -> {}                                       step-up "device.revoke"
// POST /api/devices/:id/scope { before: DeviceScope, scope: DeviceScope, stepUp } -> DeviceView   owner only, step-up "device.rescope"
//      The action carries the scope the page showed and the whole new scope, as /api/stepup validated them. 409 conflict when
//      the stored scope is no longer `before`. It applies from the machine's next request, live runs included.
// POST /api/invites { role } -> { url, expiresAt }                                     owner only
// [V20] GET /api/members -> { members: MemberView[] }     the people in the member's own vault, any member
export type MemberView = { member: string; name: string; role: "owner" | "member"; joinedAt: string; status: "unconfirmed" | "active" }
// [V20] GET /api/passkeys -> { passkeys: PasskeyView[] }  the signed-in member's own passkeys only.
//      Never the credential id, the public key or the counter. `authenticator`
//      is a description from the stored transports ("Built into a device").
export type PasskeyView = {
  passkey: string // pk_ handle
  name: string | null
  authenticator: string
  synced: boolean | null // credentialBackedUp; null for passkeys from before 0004
  addedVia: "signup" | "settings" | "recovery" | "reset" | "break-glass"
  createdAt: string
  lastUsedAt: string | null
  lastUsedClient: string | null
  lastUsedPlace: string | null // "Amsterdam, NL"
  current: boolean // opened this session
}

// [AUTH] sign-in and recovery. Every `name`, `client`,
// `place` and `memberName` is stored text: pages spell it through cardText,
// the CLI through terminalText.
export type SessionView = {
  session: string // ses_
  kind: "web" | "app"
  method: "signup" | "passkey" | "recovery" | "reset"
  client: string
  place: string | null
  passkeyName: string | null
  createdAt: string
  lastSeenAt: string
  current: boolean
}
// GET /api/account/sessions. mayEndOtherSessions: whether this sign-in may end
// the others; false while a recovery is open, unless it was made with a
// passkey from before the recovery.
export type AccountSessionsRead = { sessions: SessionView[]; mayEndOtherSessions: boolean }
export type RecoveryStatus = { active: { generatedAt: string; total: number; left: number } | null }
export type RecoveryCodesIssued = { batch: string; codes: string[]; confirmPosition: number; expiresAt: string }
export type SecurityNotice = {
  notice: string // ntc_
  kind: "recovery" | "reset" | "break-glass" | "join"
  member: string
  memberName: string
  at: string
  client: string | null
  place: string | null
  restrictedUntil: string | null
  url: string // VAULT_ORIGIN + "/settings#security"
  // Members only: whether the reader may resolve or confirm it. Absent for devices.
  canResolve?: boolean
}
// POST /api/tenant/freeze {} -> { frozen: true }   any member, no step-up
// POST /api/tenant/unfreeze { stepUp } -> {}                                           step-up "tenant.unfreeze"
// GET  /api/audit?before= -> { events, head }

// Who asked for an intake or a connect. A device's ask names the machine
// (the name the owner approved at enrolment) and the agent's own session
// label; an ask a member started from the vault's own pages names the
// member, and `self` says whether the member reading this view is that
// member, decided by the vault from the session and never from a request.
// workload: the workload that asked, when one did, shown to people only; its
// label is the machine's words, like the session label.
export type AskingWorkload = { id: string; label: string }
export type RequestedBy = { device: string; deviceName: string; session: string | null; workload?: AskingWorkload | undefined } | { member: string; self: boolean }

// GET  /api/intakes/:id -> IntakeView
export type IntakeView = {
  intake: string
  status: "open" | "completed" | "expired" | "cancelled"
  kind: z.infer<typeof KindSchema>
  slug: string
  provider: string | null
  providerName: string | null
  reason: string
  requestedBy: RequestedBy
  // True when `slug` already exists: submitting replaces its secret fields
  // only, and its binding cannot change. `fields` then lists secret fields only.
  rotates: boolean
  // Field specs from KINDS plus the provider template's hints.
  fields: { name: string; label: string; secret: boolean; required: boolean; multiline: boolean; hint: string | null }[]
  // The template's binding (verified) or the agent's proposal (unverified, shown in red).
  binding: { value: BindingInput; verified: boolean }
  // How the relay will put the secret into a request: the template's or the
  // kind's usual way (verified), or the agent's proposal (unverified, shown in red).
  injection: { value: Injection | null; verified: boolean }
  // True for a new credential without a template: it is stored with
  // customItemPolicy (binding.ts), every request held for approval unless
  // the human ticks reads (IntakeSubmitBody.allowReads). False for a
  // template's policy or a rotation, which keeps the item's.
  customPolicy: boolean
  // The tags the agent asked for, sorted. A new item is stored with them, so
  // they decide which machines may use it (a device scoped to any of them).
  // A rotation keeps the existing item's tags.
  tags: string[]
  sealKey: { jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }; kid: string }
  // The seal context for every secret field: `intake/<intake>/<field>`.
  expiresAt: string
  // Set when a connect was created along with this intake and waits for the
  // client it saves: where the page leads once the credential is in.
  then?: { connect: string; url: string }
  // Set on a cancelled intake that the asking device replaced with a newer link.
  superseded?: true
}
// POST /api/intakes/:id/submit IntakeSubmit -> { item: ItemSummary }                   step-up "intake.submit"
//      digest = base64url(SHA-256(canonicalJson({ slug, binding, publicFields, sealed, tags, allowReads? }))) where
//      `sealed` maps field name to the SealedBox and `tags` is IntakeView.tags (the intake's
//      stored tags, sorted), so the passkey signs exactly what is stored and who may use it.
//      `allowReads: true` is in the digest only when sent as true, and `ceiling` only when sent.
export type IntakeSubmitBody = {
  slug: string
  publicFields: Record<string, string>
  sealed: Record<string, unknown> // field name -> SealedBox from seal(sealKey, value, `intake/<intake>/<field>`)
  binding: BindingInput
  tags: string[] // IntakeView.tags, unchanged; the vault signs over its own copy
  // Only when IntakeView.customPolicy: reads (GET, HEAD, OPTIONS) go through
  // without approval. Signed when true; refused with a template or a rotation.
  allowReads?: boolean
  // Only on a new password-login, where typing into web pages is on: the
  // person chose "Type it into the sign-in page". Signed when sent; absent,
  // the kind's own ceiling is stored. Refused on a rotation or another kind.
  ceiling?: "fill"
  stepUp: StepUpProof
}
// POST /api/intakes/:id/cancel {} -> {}
// GET  /api/items -> { items: ItemSummary[] }
// GET  /api/items/:slug -> ItemDescription
// POST /api/items/:slug/update { binding?, policy?, ceiling?, tags?, description?, stepUp } -> ItemDescription   step-up "item.update" (digest of the change)
// POST /api/items/:slug/delete { stepUp } -> {}                                          step-up "item.delete"

// GET  /api/connect/:id -> ConnectView
export type ConnectView = {
  connect: string
  status: "open" | "completed" | "mismatch" | "failed" | "expired"
  provider: string
  providerName: string
  slug: string
  scopes: string[]
  expect: string | null
  reason: string
  requestedBy: RequestedBy
  // True when `slug` is already connected: the sign-in is pinned to that
  // connection's account and its tokens are replaced once it completes.
  // Decided by the vault from the connection it holds, never from a request.
  reconnect: boolean
  // On a reconnect, the scopes the existing connection holds (those the
  // provider's template allows), so a page can show where `scopes` differ.
  // Null when there is no existing connection to compare with.
  currentScopes: string[] | null
  // The account actually signed in to, once known (completed or mismatch).
  account: string | null
  // The outcome in words, once there is one.
  message: string | null
  // When the link stops working (as ConnectStatus.expiresAt). Always sent.
  expiresAt?: string
  // Set when this connect waits for a client intake: the intake the human
  // must fill in first, and whether it has done its part.
  awaiting?: { intake: string; url: string; status: "open" | "completed" | "expired" | "cancelled" }
}
// POST /api/connect/:id/start {} -> { authorizeUrl }    the page then navigates there
// GET  /oauth/callback?code&state -> 302 to /c/:id (the page shows the outcome)

// An email on an approval card (a Gmail send that carries the whole
// message). A summary only: the whole decoded message is always
// request.body, shown last. Every string is shown as text, never as HTML.
export type ApprovalEmail = {
  // Every address in every To, Cc and Bcc header; external when its domain
  // is not the account's own (always, when that domain is unknown).
  recipients: { header: string; address: string; external: boolean }[]
  accountDomain: string | null
  // Every header of the message in order, encoded words decoded; To, Cc,
  // Bcc, Reply-To and From are highlighted.
  headers: { name: string; value: string; highlight: boolean }[]
  // Text parts, HTML parts as text and as source, text outside any part,
  // and the request's other fields, in message order. Parts are left out
  // when anything in the message is unreadable (see ApprovalView.warnings).
  sections: { heading: string; note: string | null; text: string }[]
  // `text` for text attachments, `sha256` (hex) for the others.
  attachments: { name: string; type: string; bytes: number; text: string | null; sha256: string | null }[]
}

// GET  /api/approvals/:id -> ApprovalView
export type ApprovalView = {
  approval: string
  // "expired": never decided in time. "ended": approved, and the grant's
  // time ran out before its uses did. "superseded": replacedBy, a newer ask
  // from the same machine to the same place, replaced it.
  status: "pending" | "approved" | "denied" | "expired" | "used" | "ended" | "revoked" | "stale" | "superseded"
  replacedBy?: string
  policyContext?: PolicyApprovalContext
  // `rule`: a standing rule the human may turn on with this approval, or
  // why this request asks every time; absent when rules do not apply.
  // `area`: a task grant the human may start with this approval, or why
  // this request cannot start one; absent when task grants do not apply.
  rememberOptions?: { route: { scope: PolicyRouteScope; policyMode: PolicyWindowMode; maxTtlSeconds: number } | null; rule?: PolicyRuleOffer; area?: PolicyAreaOffer }
  // What a remember on this approval made, as ApprovalStatus names it: the
  // standing rule, or the proposal that waits for a co-signer (the other
  // null). Present only when rules are on and the viewer may read that rule
  // or proposal.
  rule?: PolicyRuleRef | null
  ruleProposal?: PolicyRuleProposalRef | null
  // The member who approved or denied it, null while undecided. `self` is
  // decided by the vault from the session; `name` is null when that member
  // has left the vault.
  decidedBy: { name: string | null; self: boolean } | null
  bindingCode: string
  // `provider` is the item's template or OAuth provider id, for the
  // service's tile on the page; null for a run or an item without one.
  item: { slug: string; account: string | null; provider?: string | null }
  requestedBy: { device: string; deviceName: string; session: string | null; workload?: AskingWorkload }
  // Human terms: "Send an email", with To, Cc, Subject and attachments.
  title: string
  details: { label: string; value: string }[]
  // Shown in red at the top of the card: what the vault could not read.
  warnings: string[]
  email: ApprovalEmail | null
  // `body` is the whole body as the upstream will read it (JSON and form
  // bodies pretty-printed, an email's whole decoded source); null only when
  // there is none. `headers` is every forwarded header the digest binds
  // (headersSha256), as shown; null on a card that sends no request (a run).
  request: {
    method: string
    url: string
    contentType: string | null
    contentEncoding: string | null
    headers: [string, string][] | null
    headersSha256: string
    bodySha256: string
    body: string | null
  }
  digest: string
  constraints: { uses: number | null; ttlSeconds: number }
  expiresAt: string
  // Only on an approval that asked for a push (push.ts).
  push?: PushApprovalView
}
// POST /api/approvals/:id/decide { decision, constraints?, stepUp } -> ApprovalView   step-up "approval.decide"
// GET  /api/projects -> { projects: Project[] }
// GET  /api/projects/:id -> Project
// POST /api/projects/:id/vars/:name { env, item?, field?, plain?, stepUp } -> Project   step-up "item.update"
//      item = the project id; digest = base64url(SHA-256(canonicalJson({ change: "var.set", project, env, name,
//      item, field, plain }))) with null for each of item, field and plain that was not sent.
// POST /api/projects/:id/environments/:name { protected, fences, stepUp } -> Project   step-up "item.update"
//      item = the project id; digest = base64url(SHA-256(canonicalJson({ change: "environment.update", project,
//      env, protected, fences }))) with fences exactly as sent. prod and production stay protected; the default
//      environment cannot be protected.
// POST /api/projects/:id/remotes { remote, bound, stepUp } -> Project   step-up "item.update"
//      Binds (bound true) or unbinds a git remote. item = the project id; digest = base64url(SHA-256(canonicalJson(
//      { change: "remote.bind" | "remote.unbind", project, remote }))) with remote exactly as sent. A remote bound to
//      another project is refused. With no remote bound, only a checkout with no origin may claim the project.

// ---------------------------------------------------------------- pending asks and activity (V-7)

// One thing waiting for a human. `url` is always on the vault's own origin,
// built from the id; it is never stored or taken from a request. Nothing
// here is a secret: the ids, titles and codes are what the links and cards
// already show. Titles are stored text as the agent sent it (a device name,
// a session label, a recipient address): a page or terminal spells them
// through spellCardText or its equivalent before showing them.
export type PendingKind = "intake" | "connect" | "approval" | "reconnect" | "review" | "policy" | "policy-review" | "adoption"
export type PendingAsk = {
  kind: PendingKind
  // int_, con_, apr_, pol_ or adp_ for an ask; the item slug for reconnect and
  // review; the source pov_ or gnt_ for member-only policy-review.
  id: string
  // One sentence in the house style: "Send an email to priya@acme.example",
  // "Paste the OpenAI API key for openai-personal", "Reconnect gmail-alex".
  title: string
  url: string
  // When the link stops working; null for an item that needs reconnecting
  // or review, which waits until someone acts.
  expiresAt: string | null
  // The machine and agent session, or the member, that asked; null when the
  // vault itself flagged the item (review).
  requestedBy: RequestedBy | null
  // The item the ask concerns, when there is one: an intake's or connect's
  // slug, an approval's item, the flagged item.
  item: string | null
  // Approvals and rule proposals: the code the page must show.
  bindingCode?: string | undefined
  // Intakes only: what is being asked for.
  kindRequested?: z.infer<typeof KindSchema> | undefined
  // Intakes and connects: the template or provider id.
  provider?: string | null | undefined
  // Connects: the account the sign-in must be as, when pinned or expected.
  account?: string | null | undefined
  // Review only: why the vault flagged the item, as its page shows it.
  reason?: string | undefined
  // Adoptions only: how many credentials the batch holds.
  items?: number | undefined
  // When the ask was made. Approval, credential and policy asks carry it;
  // reconnect and review leave it absent.
  createdAt?: string | undefined
}
// GET /v1/pending  (device: its own intakes, connects and approvals)
// GET /api/pending (member: every open ask in the tenant, plus reconnect and review)
// Both gain `notices`: a device gets every unresolved recovery, reset and
// break-glass notice of its tenant (never "join"); a member gets those plus
// "join" when they are an owner.
// `groups`: the review groups and bundles holding two or more of this
// machine's open approvals, top level so no row changes shape. code: the
// group code its Review together page shows, when it has one.
export type PendingGroup = { id: string; url: string; approvals: string[]; bundle: boolean; code?: string }
export type PendingList = { pending: PendingAsk[]; notices?: SecurityNotice[]; groups?: PendingGroup[] }

// GET /api/activity?days=7 (member). Counts over the audit log, per UTC day
// ("YYYY-MM-DD"): allowed is relay.allow, neededYou is approval.request,
// refused is relay.deny and relay.refuse. Every list is zero-filled for
// each of the `days` days, oldest first, so a chart needs no gaps logic.
export type ActivityDay = { day: string; allowed: number; neededYou: number; refused: number }
export type Activity = {
  // The window actually used, after clamping to 1 to 31.
  days: number
  // The first day's start and the moment the counts were read.
  from: string
  until: string
  total: ActivityDay[]
  items: { item: string; days: ActivityDay[] }[]
  devices: { device: string; days: ActivityDay[] }[]
}

// An open reset link as an owner sees it. `createdBy` is the owner who made
// it, or "break-glass" for a link the operator script wrote into D1.
export type ResetLinkView = {
  member: string
  memberName: string
  createdBy: { kind: "owner"; member: string; name: string | null } | { kind: "break-glass" }
  createdAt: string
  expiresAt: string
}

// Workspace callers use these additions; legacy requests keep their old shape.
const HomeInput = { home: z.enum(["private", "project", "workspace"]), project: z.string().min(1).max(64).optional() }
const validHomeInput = (v: { home: string; project?: string | undefined }) => v.home === "project" ? v.project !== undefined : v.project === undefined
export const WorkspaceIntakeCreate = IntakeCreate.extend(HomeInput).strict().refine(validHomeInput, "Project home requires its project id")
export const WorkspaceConnectCreate = ConnectCreate.extend(HomeInput).strict().refine(validHomeInput, "Project home requires its project id")
export const WorkspaceMemberConnectCreate = ConnectCreate.omit({ reason: true, session: true }).extend(HomeInput).strict().refine(validHomeInput, "Project home requires its project id")

export const HTTP_STATUS_FOR_ERROR: Record<ErrorCode, number> = {
  bad_request: 400,
  unauthenticated: 401,
  proof_invalid: 401,
  device_pending: 403,
  device_revoked: 403,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  ambiguous: 409,
  binding_refused: 403,
  surface_refused: 403,
  policy_denied: 403,
  approval_required: 409,
  mode_refused: 403,
  environment_refused: 403,
  remote_mismatch: 403,
  needs_reauth: 424,
  refresh_retrying: 503,
  intake_required: 404,
  frozen: 423,
  rate_limited: 429,
  too_large: 413,
  upstream_failed: 502,
  internal: 500,
  account_pending: 403,
  owner_inactive: 403,
  identity_required: 403,
  project_unshared: 403,
  cli_outdated: 426,
  workload_ended: 403,
  workload_required: 403,
  platform_suspended: 403,
  quota_exceeded: 403,
  origin_mismatch: 403,
  totp_unreadable: 400,
  provider_refused: 502,
}

// Local refusal codes never cross a server response boundary.
export const LOCAL_ERROR_CODES = ["pin_outdated", "workspace_unbound", "workspace_mismatch", "workspace_unknown", "context_ambiguous", "workspace_not_allowed", "config_dir_retired"] as const
export type LocalWorkspaceErrorCode = typeof LOCAL_ERROR_CODES[number]
export const EXIT_FOR_LOCAL_ERROR: Record<LocalWorkspaceErrorCode, ExitCode> = { pin_outdated: EXIT.usage, workspace_unbound: EXIT.usage, workspace_mismatch: EXIT.usage, workspace_unknown: EXIT.usage, context_ambiguous: EXIT.usage, workspace_not_allowed: EXIT.usage, config_dir_retired: EXIT.usage }
