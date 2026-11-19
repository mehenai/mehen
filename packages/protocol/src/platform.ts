// Platform mode: a business the operator registered (a platform) signs its
// own calls with its own P-256 key, names each of its users by an opaque
// subject, and gets one managed workspace per subject. This module is the
// whole contract: ids, the platform proof, every route's request and answer
// schemas, the route table the API reference is generated from, limits,
// the platform's defaults and the policy a managed item is used under.
//
// OAuth uses the subject's own app: its client is an oauth-client item in
// the subject's workspace, added through a sealed intake like any key, for
// a catalogue provider or with its own provider definition
// (custom-provider.ts). The callback is the platform's own. Platforms hold
// no OAuth clients of their own.
//
// The platform proof is a compact JWS (ES256, P-256) in the
// `Mehen-Platform-Proof` header:
//
//   header  { alg: "ES256", typ: "mehen-platform+jwt", kid: <pky_ key id> }
//   payload { plt, sub?, htm, htu, bh, iat, jti }
//
// `htm`, `htu`, `bh`, `iat` and `jti` mean exactly what they mean in a
// device proof (proof.ts). `sub` is required on every route under
// /v1/platform/subjects/:subject and must equal that path segment; it is
// absent everywhere else. There is no `ten`: the vault finds the workspace
// from the verified platform and the subject, never from the caller. Its
// own header and `typ` mean a device proof and a platform proof can never
// stand in for each other: parseProof refuses this `typ`, and
// parsePlatformProof refuses every other.

import { z } from "zod"
import { type ErrorCode, BindingSchema, EnvName, InjectionSchema, KindSchema, ModeSchema, PolicySchema, Slug, Tag, type ItemSummary, type ConnectStatus, type PolicyInput, VarName } from "./api.ts"
import { customItemPolicy } from "./binding.ts"
import { type Bytes, base64UrlDecode, randomId, sha256B64 } from "./bytes.ts"
import { type ProofRequest, type RequestClaims, type RequestProofFailure, bodyHash, checkRequestProof, decodeJwsSegment, hasRequestClaims, normaliseUrl, signCompactJws, splitCompactJws } from "./proof.ts"
import { isPolicyHost } from "./policy-mode.ts"
import { CustomOAuthProviderSchema, PublicHttpsUrlSchema } from "./custom-provider.ts"
import { connectionPolicy, getOAuthProvider, getTemplate, normaliseScope } from "./templates.ts"
import { WorkspaceAuditPageSchema, WorkspaceDeviceScopeSchema, type WorkspaceDeviceScope, type WorkspaceStepUpAction } from "./workspace.ts"

// ---------------------------------------------------------------- ids

export const PLATFORM_ID = /^plt_[A-Za-z0-9_-]{4,64}$/
export const PLATFORM_KEY_ID = /^pky_[A-Za-z0-9_-]{4,64}$/
// The platform's opaque name for one of its users. Unique within its
// platform only; Mehen never interprets it.
export const PLATFORM_SUBJECT = /^[A-Za-z0-9_-]{8,128}$/
export const MANAGED_TENANT_ID = /^tn_[A-Za-z0-9]{8,40}$/
export const PLATFORM_DEVICE_ID = /^dev_[A-Za-z0-9_-]{1,60}$/
export const PLATFORM_INTAKE_ID = /^int_[A-Za-z0-9_-]{1,60}$/
export const PLATFORM_CONNECT_ID = /^con_[A-Za-z0-9_-]{1,60}$/
export const PLATFORM_APPROVAL_ID = /^apr_[A-Za-z0-9_-]{1,60}$/
export const PLATFORM_PROJECT_ID = /^prj_[A-Za-z0-9_-]{1,60}$/
export const PLATFORM_WORKLOAD_ID = /^wl_[A-Za-z0-9_-]{8,64}$/

export const PlatformIdSchema = z.string().regex(PLATFORM_ID)
export const PlatformKeyIdSchema = z.string().regex(PLATFORM_KEY_ID)
export const PlatformSubjectSchema = z.string().regex(PLATFORM_SUBJECT)
// 3 to 40 characters, a lower-case letter first, no "--" (as D1 checks it).
export const PlatformSlugSchema = z.string().regex(/^[a-z][a-z0-9-]{2,39}$/).refine((s) => !s.includes("--"), "invalid platform slug")
export const PlatformNameSchema = z.string().min(1).max(64)
export const ManagedTenantIdSchema = z.string().regex(MANAGED_TENANT_ID)
const DeviceIdSchema = z.string().regex(PLATFORM_DEVICE_ID)
const IntakeIdSchema = z.string().regex(PLATFORM_INTAKE_ID)
const ConnectIdSchema = z.string().regex(PLATFORM_CONNECT_ID)
const ApprovalIdSchema = z.string().regex(PLATFORM_APPROVAL_ID)
const ProjectIdSchema = z.string().regex(PLATFORM_PROJECT_ID)
const Iso = z.iso.datetime()
const Count = z.number().int().nonnegative()
const Revision = z.number().int().positive()

// The subject member's account and the tombstone are both derived from the
// platform and the subject, so neither needs storing to be found again.
function subjectKey(platform: string, subject: string): string {
  return `${platform}\n${subject}`
}

// managed_workspaces.subject_hash: SHA-256 of platform, newline, subject.
export async function platformSubjectHash(platform: string, subject: string): Promise<string> {
  return sha256B64(subjectKey(platform, subject))
}

// The subject member's `account`: `sbj_` and the first 32 characters of
// the same hash.
export const SUBJECT_MEMBER_PREFIX = "sbj_"
export async function subjectMemberAccount(platform: string, subject: string): Promise<string> {
  return `${SUBJECT_MEMBER_PREFIX}${(await platformSubjectHash(platform, subject)).slice(0, 32)}`
}

// ---------------------------------------------------------------- the platform proof

export const PLATFORM_PROOF_HEADER = "Mehen-Platform-Proof"
export const PLATFORM_PROOF_TYPE = "mehen-platform+jwt"
export const PLATFORM_PATH_PREFIX = "/v1/platform"
const SUBJECTS_PREFIX = `${PLATFORM_PATH_PREFIX}/subjects/`

export type PlatformProofClaims = RequestClaims & {
  plt: string // platform id
  sub?: string // subject, on routes under /v1/platform/subjects/:subject only
}

export type PlatformSigner = {
  platformId: string
  keyId: string
  sign(data: Bytes): Promise<Bytes>
}

export type ParsedPlatformProof = {
  kid: string
  claims: PlatformProofClaims
  signingInput: Bytes
  signature: Bytes
}

export type PlatformProofCheck =
  | { ok: true; claims: PlatformProofClaims }
  | { ok: false; reason: RequestProofFailure | "subject" }

// The subject a platform path names: the segment after
// /v1/platform/subjects/, or null for a route that names none. The segment
// is returned as sent; one that is not a valid subject never equals `sub`.
export function platformPathSubject(pathname: string): string | null {
  if (!pathname.startsWith(SUBJECTS_PREFIX)) return null
  const segment = pathname.slice(SUBJECTS_PREFIX.length).split("/")[0] ?? ""
  return segment === "" ? null : segment
}

// `sub` is taken from the URL, so the proof can never name another subject
// than the path it signs.
export async function createPlatformProof(signer: PlatformSigner, request: ProofRequest, context: { now?: number } = {}): Promise<string> {
  const htu = normaliseUrl(request.url)
  const subject = platformPathSubject(new URL(htu).pathname)
  const claims: PlatformProofClaims = {
    plt: signer.platformId,
    ...(subject !== null ? { sub: subject } : {}),
    htm: request.method.toUpperCase(),
    htu,
    bh: await bodyHash(request.body),
    iat: Math.floor((context.now ?? Date.now()) / 1000),
    jti: randomId("jti", 12),
  }
  const header = { alg: "ES256", typ: PLATFORM_PROOF_TYPE, kid: signer.keyId }
  return signCompactJws(header, claims, (data) => signer.sign(data), "platform")
}

const PLATFORM_HEADER_KEYS = new Set(["alg", "typ", "kid"])
const PLATFORM_CLAIM_KEYS = new Set(["plt", "sub", "htm", "htu", "bh", "iat", "jti"])

function isPlatformClaims(value: unknown): value is PlatformProofClaims {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false
  const c = value as Record<string, unknown>
  return (
    Object.keys(c).every((key) => PLATFORM_CLAIM_KEYS.has(key)) &&
    typeof c.plt === "string" && PLATFORM_ID.test(c.plt) &&
    (c.sub === undefined || (typeof c.sub === "string" && PLATFORM_SUBJECT.test(c.sub))) &&
    hasRequestClaims(c)
  )
}

// Parses without verifying, so the Worker can find the key by `kid`.
// Nothing in the result is trusted until verifyPlatformProof. A header or
// payload with any member a platform proof does not have is refused, so a
// device proof's claims can never parse here.
export function parsePlatformProof(token: string): ParsedPlatformProof {
  const jws = splitCompactJws(token)
  const hdr = jws.header
  if (hdr.alg !== "ES256" || hdr.typ !== PLATFORM_PROOF_TYPE) throw new Error("unsupported proof type")
  if (!Object.keys(hdr).every((key) => PLATFORM_HEADER_KEYS.has(key))) throw new Error("malformed proof header")
  if (typeof hdr.kid !== "string" || !PLATFORM_KEY_ID.test(hdr.kid)) throw new Error("proof key id is not a platform key")
  const claims = decodeJwsSegment(jws.payload)
  if (!isPlatformClaims(claims)) throw new Error("malformed proof claims")
  return { kid: hdr.kid, claims, signingInput: jws.signingInput, signature: base64UrlDecode(jws.signature) }
}

// Verifies a parsed proof against the request as the Worker received it:
// signature, method, URL, body hash, the 60-second skew, and `sub` against
// the subject the URL's path names (both absent, or equal). The key's
// platform must equal `claims.plt`, and the nonce is spent, by the caller.
export async function verifyPlatformProof(
  proof: ParsedPlatformProof,
  publicKey: CryptoKey,
  received: { method: string; url: string; bodyHash: string; now?: number },
): Promise<PlatformProofCheck> {
  const failure = await checkRequestProof(proof, publicKey, received)
  if (failure !== null) return { ok: false, reason: failure }
  const pathSubject = platformPathSubject(new URL(normaliseUrl(received.url)).pathname)
  if ((proof.claims.sub ?? null) !== pathSubject) return { ok: false, reason: "subject" }
  return { ok: true, claims: proof.claims }
}

// A software signer over a WebCrypto key: tests, scripts and a platform's
// own server.
export function webCryptoPlatformSigner(platformId: string, keyId: string, privateKey: CryptoKey): PlatformSigner {
  return {
    platformId,
    keyId,
    async sign(data) {
      return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, data))
    },
  }
}

// ---------------------------------------------------------------- limits

export const PLATFORM_DECISION_MAX_TTL_SECONDS = 900
export const PLATFORM_DECISION_MIN_TTL_SECONDS = 60
export const PLATFORM_DECISION_USES = 1
// A managed workspace reads its platform's row (status, limits, defaults)
// at most this often; a change reaches every workspace within it.
export const PLATFORM_REFRESH_SECONDS = 30
export const PLATFORM_INTAKE_TTL_SECONDS = 10 * 60
export const PLATFORM_CONNECT_TTL_SECONDS = 15 * 60
// Subjects the deletion sweep finishes per cron run.
export const PLATFORM_DELETE_BATCH = 50
export const PLATFORM_KEY_OVERLAP_HOURS = 24
export const PLATFORM_SUBJECTS_PAGE_SIZE = 100
export const PLATFORM_AUDIT_PAGE_MAX = 200
export const PLATFORM_AUDIT_RETENTION_MAX_DAYS = 90

// Per platform, set by the operator; a per-subject number is one value at
// the platform, read live by every workspace, never copied into one.
export const PlatformLimitsSchema = z.strictObject({
  subjects: z.int().min(1).max(10_000_000),
  devicesPerSubject: z.int().min(1).max(1_000),
  itemsPerSubject: z.int().min(1).max(10_000),
  projectsPerSubject: z.int().min(1).max(1_000),
  // Open intakes and connects the platform made, per subject.
  openRequestsPerSubject: z.int().min(1).max(100),
  callsPerMinute: z.int().min(1).max(100_000),
  subjectWritesPerMinute: z.int().min(1).max(10_000),
  decisionsPerMinute: z.int().min(1).max(10_000),
  subjectDecisionsPerMinute: z.int().min(1).max(1_000),
  decisionTtlSeconds: z.int().min(PLATFORM_DECISION_MIN_TTL_SECONDS).max(PLATFORM_DECISION_MAX_TTL_SECONDS),
  auditRetentionDays: z.int().min(0).max(PLATFORM_AUDIT_RETENTION_MAX_DAYS),
})
export type PlatformLimits = z.infer<typeof PlatformLimitsSchema>

export const DEFAULT_PLATFORM_LIMITS: PlatformLimits = {
  subjects: 1_000,
  devicesPerSubject: 16,
  itemsPerSubject: 100,
  projectsPerSubject: 16,
  openRequestsPerSubject: 10,
  callsPerMinute: 600,
  subjectWritesPerMinute: 60,
  decisionsPerMinute: 30,
  subjectDecisionsPerMinute: 10,
  decisionTtlSeconds: PLATFORM_DECISION_MAX_TTL_SECONDS,
  auditRetentionDays: 30,
}

// ---------------------------------------------------------------- devices, step-ups

// A managed device relays and serves placeholders; it never leases, mints,
// signs or reveals, so no value ever leaves the vault through it.
export const PLATFORM_DEVICE_MODES = ["relay", "placeholder"] as const
export type PlatformDeviceMode = (typeof PLATFORM_DEVICE_MODES)[number]

export function platformDeviceScope(modes: readonly PlatformDeviceMode[]): WorkspaceDeviceScope {
  return { tags: [], projects: [], maxEnvironment: "unprotected", modes: [...modes], privateCredentials: false, workloads: "required" }
}

// The step-ups a platform's proof stands in for, each the counterpart of a
// person's passkey. `item.update` only for a project's variables (its
// `item` is the project's prj_ id): never an item's binding, policy or
// ceiling.
export const PLATFORM_STEP_UPS = [
  "intake.submit",
  "connect.start",
  "approval.decide",
  "item.delete",
  "project.create",
  "project.delete",
  "device.revoke",
  "workload.revoke",
  "workspace.unfreeze",
  "item.update",
] as const satisfies readonly WorkspaceStepUpAction["type"][]
export type PlatformStepUp = (typeof PLATFORM_STEP_UPS)[number]

export function platformMaySatisfy(action: WorkspaceStepUpAction): boolean {
  if (!(PLATFORM_STEP_UPS as readonly string[]).includes(action.type)) return false
  if (action.type === "item.update") return PLATFORM_PROJECT_ID.test(action.item)
  return true
}

// ---------------------------------------------------------------- defaults and the managed item policy

// A rule a platform adds to a template's or provider's policy: it may hold
// (approve) or refuse (deny), never allow, so it can only narrow.
export const PlatformPolicyRuleSchema = PolicySchema.shape.rules.element.refine(
  (rule) => rule.action !== "allow",
  "A platform rule may only hold (approve) or refuse (deny).",
)
export type PlatformPolicyRule = z.infer<typeof PlatformPolicyRuleSchema>

const CatalogueId = z.string().min(1).max(64)

// Set once at the platform and read live by every workspace beneath it.
// Absent `templates` or `providers` is the whole catalogue. `scopes` are the
// OAuth scopes a connect asks for when it names none; `tags` go on every
// new item; `customReads` says whether a key with no template may be read
// (GET, HEAD, OPTIONS) without a hold; `rules` are added to the policy of
// the template or provider they are keyed by.
//
// PlatformDefaultsSchema checks every id against the catalogue, for a body;
// an answer is read with PlatformDefaultsShapeSchema, so a catalogue change
// after the defaults were set never makes a stored answer unreadable.
export const PlatformDefaultsShapeSchema = z.strictObject({
  templates: z.array(CatalogueId).max(256).optional(),
  providers: z.array(CatalogueId).max(64).optional(),
  scopes: z.record(CatalogueId, z.array(z.string().min(1).max(200)).max(50)),
  tags: z.array(Tag).max(16),
  customReads: z.enum(["allow", "approve"]),
  rules: z.record(CatalogueId, z.array(PlatformPolicyRuleSchema).max(64)),
})
export const PlatformDefaultsSchema = PlatformDefaultsShapeSchema
  .superRefine((defaults, ctx) => {
    const issue = (path: (string | number)[], message: string) => ctx.addIssue({ code: "custom", path, message })
    defaults.templates?.forEach((id, i) => {
      if (getTemplate(id) === null) issue(["templates", i], `The catalogue has no template "${id}".`)
    })
    defaults.providers?.forEach((id, i) => {
      if (getOAuthProvider(id) === null) issue(["providers", i], `The catalogue has no OAuth provider "${id}".`)
    })
    for (const [id, scopes] of Object.entries(defaults.scopes)) {
      const provider = getOAuthProvider(id)
      if (provider === null) {
        issue(["scopes", id], `The catalogue has no OAuth provider "${id}".`)
        continue
      }
      scopes.forEach((scope, i) => {
        if (normaliseScope(provider, scope) === null) issue(["scopes", id, i], `"${scope}" is not a scope ${provider.displayName} allows.`)
      })
    }
    for (const id of Object.keys(defaults.rules)) {
      if (getTemplate(id) === null && getOAuthProvider(id) === null) issue(["rules", id], `The catalogue has no template or OAuth provider "${id}".`)
    }
    if (new Set(defaults.tags).size !== defaults.tags.length) issue(["tags"], "Each tag may appear once.")
  })
export type PlatformDefaults = z.infer<typeof PlatformDefaultsShapeSchema>

export const INITIAL_PLATFORM_DEFAULTS: PlatformDefaults = { scopes: {}, tags: [], customReads: "approve", rules: {} }

// The catalogue's own policy for an item's template or OAuth provider (its
// `provider`), or null for a key with no template.
function cataloguePolicy(provider: string): PolicyInput | null {
  const template = getTemplate(provider)
  if (template !== null) return template.policy
  const oauth = getOAuthProvider(provider)
  return oauth === null ? null : connectionPolicy(oauth)
}

// The policy an item in a managed workspace is used under, computed at the
// moment of use and never stored: the catalogue's current policy for its
// template or provider plus the platform's rules for it, or for an item
// with no template the custom policy with the platform's `customReads`.
// Every added rule holds or refuses, and evaluatePolicy lets deny beat
// approve beat allow, so the result never allows what the catalogue's
// policy holds or refuses. A rule whose action is not approve or deny is
// dropped here too, so that holds even for defaults that skipped the
// schema. An item whose template has left the catalogue holds everything.
export function managedItemPolicy(provider: string | null, defaults: PlatformDefaults): PolicyInput {
  if (provider === null) return customItemPolicy(defaults.customReads === "allow")
  const base = cataloguePolicy(provider)
  if (base === null) return customItemPolicy(false)
  const added = (Object.hasOwn(defaults.rules, provider) ? (defaults.rules[provider] ?? []) : []).filter((rule) => rule.action === "approve" || rule.action === "deny")
  return { default: base.default, rules: [...base.rules, ...added] }
}

// ---------------------------------------------------------------- shared shapes

// A sealed box (seal.ts) as a body carries it. The context it was sealed
// under is the vault's to check.
export const SealedBoxSchema = z.strictObject({
  v: z.literal(1),
  epk: z.strictObject({ kty: z.literal("EC"), crv: z.literal("P-256"), x: z.string().regex(/^[A-Za-z0-9_-]{43}$/), y: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }),
  iv: z.string().regex(/^[A-Za-z0-9_-]{16}$/),
  ct: z.string().regex(/^[A-Za-z0-9_-]+$/).max(2_000_000),
})

export const PlatformJwkSchema = z.strictObject({ kty: z.literal("EC"), crv: z.literal("P-256"), x: z.string().regex(/^[A-Za-z0-9_-]{43}$/), y: z.string().regex(/^[A-Za-z0-9_-]{43}$/) })

export const PlatformEmptySchema = z.strictObject({})

// An item as the platform sees it: Mehen's metadata, never a value.
export const PlatformItemSummarySchema: z.ZodType<ItemSummary> = z.object({
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
})

// One step of an OAuth client template's set-up (templates.ts
// ClientSetupStep), as an intake's answer carries it. The body may hold
// CLIENT_SETUP_CALLBACK for the platform's page to replace.
export const ClientSetupStepSchema = z.object({ title: z.string().min(1).max(80), body: z.string().min(1).max(400), consoleUrl: z.url({ protocol: /^https$/ }).optional() })

// ---------------------------------------------------------------- the platform: routes 1, 4, 30 and 31

export const PlatformStatusSchema = z.enum(["active", "suspended", "retiring", "retired"])
export type PlatformStatus = z.infer<typeof PlatformStatusSchema>

export const PlatformViewSchema = z.object({
  platform: z.object({ id: PlatformIdSchema, slug: PlatformSlugSchema, name: z.string(), status: PlatformStatusSchema }),
  limits: z.object(PlatformLimitsSchema.shape),
  defaults: PlatformDefaultsShapeSchema,
  defaultsRevision: Revision,
  usage: z.object({ subjects: Count }),
  keys: z.array(z.object({ id: PlatformKeyIdSchema, createdAt: Iso, expiresAt: Iso.nullable(), revoked: z.boolean() })),
})
export type PlatformView = z.infer<typeof PlatformViewSchema>

export const SubjectStatusSchema = z.enum(["creating", "active", "deleting", "deleted"])
export type SubjectStatus = z.infer<typeof SubjectStatusSchema>

export const SubjectListQuerySchema = z.strictObject({ cursor: z.string().min(1).max(256).optional() })
export const SubjectListSchema = z.object({
  subjects: z.array(z.object({ subject: PlatformSubjectSchema, status: SubjectStatusSchema, createdAt: Iso })).max(PLATFORM_SUBJECTS_PAGE_SIZE),
  next: z.string().nullable(),
})
export type SubjectList = z.infer<typeof SubjectListSchema>

export const PlatformDefaultsViewSchema = z.object({ defaults: PlatformDefaultsShapeSchema, defaultsRevision: Revision })
export type PlatformDefaultsView = z.infer<typeof PlatformDefaultsViewSchema>

// DELETE /v1/platform/subjects: `confirm` is the platform's own slug.
export const SubjectsRemoveAllSchema = z.strictObject({ confirm: PlatformSlugSchema })
export const SubjectsRemovalSchema = z.object({ deleting: Count })
export type SubjectsRemoval = z.infer<typeof SubjectsRemovalSchema>

// ---------------------------------------------------------------- a subject: routes 5 to 29

export const SubjectViewSchema = z.object({
  subject: PlatformSubjectSchema,
  status: SubjectStatusSchema,
  createdAt: Iso,
  counts: z.object({ devices: Count, items: Count, projects: Count }),
})
export type SubjectView = z.infer<typeof SubjectViewSchema>

export const SubjectRemovalSchema = z.object({ subject: PlatformSubjectSchema, status: z.literal("deleted"), purgeAfter: Iso })
export type SubjectRemoval = z.infer<typeof SubjectRemovalSchema>

// The platform's own words for the device, as the audit shows them.
export const PlatformDeviceLabelSchema = z.string().regex(/^[A-Za-z0-9_.:-]{1,120}$/)

export const PlatformDeviceCreateSchema = z.strictObject({
  name: z.string().min(1).max(64),
  jwk: PlatformJwkSchema,
  modes: z.array(z.enum(PLATFORM_DEVICE_MODES)).min(1).max(PLATFORM_DEVICE_MODES.length).refine((modes) => new Set(modes).size === modes.length, "Each mode may appear once."),
  label: PlatformDeviceLabelSchema.optional(),
})
export type PlatformDeviceCreate = z.infer<typeof PlatformDeviceCreateSchema>

export const PlatformDeviceViewSchema = z.object({
  device: DeviceIdSchema,
  tenant: ManagedTenantIdSchema,
  name: z.string(),
  label: z.string().nullable(),
  scope: WorkspaceDeviceScopeSchema,
  createdAt: Iso,
  revoked: z.boolean(),
})
export type PlatformDeviceView = z.infer<typeof PlatformDeviceViewSchema>

export const PlatformDeviceListEntrySchema = PlatformDeviceViewSchema.extend({ lastSeenAt: Iso.nullable(), liveWorkloads: Count })
export type PlatformDeviceListEntry = z.infer<typeof PlatformDeviceListEntrySchema>
export const PlatformDeviceListSchema = z.object({ devices: z.array(PlatformDeviceListEntrySchema) })
export type PlatformDeviceList = z.infer<typeof PlatformDeviceListSchema>

export const PlatformItemFilterSchema = z.strictObject({ kind: KindSchema.optional(), tag: Tag.optional() })
export type PlatformItemFilter = z.infer<typeof PlatformItemFilterSchema>
export const PlatformItemListSchema = z.object({ items: z.array(PlatformItemSummarySchema) })
export type PlatformItemList = z.infer<typeof PlatformItemListSchema>

export const ItemRemovalSchema = z.object({ slug: Slug, deleted: z.literal(true), providerRevoked: z.boolean() })
export type ItemRemoval = z.infer<typeof ItemRemovalSchema>

// A catalogue template (an OAuth client template among them: the
// subject's own app for that provider), one host for a key with no
// template, or an OAuth client with its own provider definition. The
// definition is not secret and is fixed with the item; the client secret
// is sealed like any field.
export const PlatformIntakeServiceSchema = z.union([
  z.strictObject({ template: CatalogueId.refine((id) => getTemplate(id) !== null, "The catalogue has no such template.") }),
  z.strictObject({ host: z.string().refine(isPolicyHost, "Use a canonical literal host.") }),
  z.strictObject({ customProvider: CustomOAuthProviderSchema }),
])

export const PlatformIntakeCreateSchema = z.strictObject({
  slug: Slug,
  service: PlatformIntakeServiceSchema,
  tags: z.array(Tag).max(16).optional(),
  reason: z.string().min(1).max(500).optional(),
})
export type PlatformIntakeCreate = z.infer<typeof PlatformIntakeCreateSchema>

const FieldName = z.string().regex(/^[a-z][a-z0-9_]{0,63}$/)

export const PlatformIntakeSchema = z.object({
  intake: IntakeIdSchema,
  sealKey: z.object({ jwk: z.object({ kty: z.literal("EC"), crv: z.literal("P-256"), x: z.string(), y: z.string() }), kid: z.string() }),
  fields: z.array(z.object({ name: FieldName, label: z.string(), secret: z.boolean(), required: z.boolean(), multiline: z.boolean(), hint: z.string().nullable() })),
  binding: z.object({ hosts: z.array(z.string()), known: z.boolean() }),
  rotates: z.boolean(),
  // An OAuth client template's set-up steps (templates.ts clientSetup);
  // null for anything else.
  setup: z.array(ClientSetupStepSchema).nullable(),
  expiresAt: Iso,
})
export type PlatformIntake = z.infer<typeof PlatformIntakeSchema>

// Every box is sealed under `intake/<intake>/<field>`. `terms` are the
// binding and injection the platform showed its user, which the vault
// requires equal to its own: always for an intake a workload asked for
// with no template, where the workload proposed them; checked when sent
// for any other.
export const PlatformIntakeTermsSchema = z.strictObject({ binding: BindingSchema, injection: InjectionSchema.nullable() })
export type PlatformIntakeTerms = z.infer<typeof PlatformIntakeTermsSchema>

export const PlatformIntakeSubmitSchema = z.strictObject({
  sealed: z.record(FieldName, SealedBoxSchema).refine((sealed) => Object.keys(sealed).length >= 1 && Object.keys(sealed).length <= 16, "Send between 1 and 16 sealed fields."),
  publicFields: z.record(FieldName, z.string().max(4096)).refine((fields) => Object.keys(fields).length <= 16, "Send at most 16 public fields.").optional(),
  terms: PlatformIntakeTermsSchema.optional(),
})
export type PlatformIntakeSubmit = z.infer<typeof PlatformIntakeSubmitSchema>

export const PlatformIntakeSubmittedSchema = z.object({ item: PlatformItemSummarySchema })
export type PlatformIntakeSubmitted = z.infer<typeof PlatformIntakeSubmittedSchema>

// A connection with the subject's own OAuth client. `provider` names a
// catalogue provider, and `client` the subject's oauth-client item for it
// (absent: the item named after the provider's client template, such as
// google-oauth-client). With no `provider`, `client` names an oauth-client
// item carrying its own provider definition, which decides the scopes
// allowed. `redirectUri` is the platform's own callback, the one the
// subject registered in their app; it is sent to the provider as is.
export const PlatformConnectStartSchema = z
  .strictObject({
    provider: CatalogueId.refine((id) => getOAuthProvider(id) !== null, "The catalogue has no such OAuth provider.").optional(),
    client: Slug.optional(),
    slug: Slug,
    redirectUri: PublicHttpsUrlSchema,
    scopes: z.array(z.string().min(1).max(200)).min(1).max(50).optional(),
    expect: z.string().min(1).max(320).optional(),
    tags: z.array(Tag).max(16).optional(),
  })
  .refine((start) => start.provider !== undefined || start.client !== undefined, "Name a catalogue provider, or the client whose own provider definition to use.")
  .superRefine((start, ctx) => {
    if (start.provider === undefined || start.scopes === undefined) return
    const provider = getOAuthProvider(start.provider)
    if (provider === null) return
    start.scopes.forEach((scope, i) => {
      if (normaliseScope(provider, scope) === null) ctx.addIssue({ code: "custom", path: ["scopes", i], message: `"${scope}" is not a scope ${provider.displayName} allows.` })
    })
  })
export type PlatformConnectStart = z.infer<typeof PlatformConnectStartSchema>

export const PlatformConnectStartedSchema = z.object({ connect: ConnectIdSchema, authorizeUrl: z.url({ protocol: /^https$/ }), expiresAt: Iso })
export type PlatformConnectStarted = z.infer<typeof PlatformConnectStartedSchema>

// What the platform's OAuth callback received: the state, and the code or
// the provider's error, never both.
export const PlatformConnectFinishSchema = z
  .strictObject({
    state: z.string().min(16).max(256),
    code: z.string().min(1).max(4096).optional(),
    error: z.string().min(1).max(256).optional(),
  })
  .refine((finish) => (finish.code === undefined) !== (finish.error === undefined), "Send the code or the error, not both.")
export type PlatformConnectFinish = z.infer<typeof PlatformConnectFinishSchema>

export const PlatformConnectFailureSchema = z.enum(["denied", "provider", "mismatch", "wider"])
export const PlatformConnectFinishedSchema = z.discriminatedUnion("status", [
  z.object({ connect: ConnectIdSchema, status: z.literal("completed"), item: PlatformItemSummarySchema }),
  z.object({ connect: ConnectIdSchema, status: z.literal("failed"), reason: PlatformConnectFailureSchema }),
])
export type PlatformConnectFinished = z.infer<typeof PlatformConnectFinishedSchema>

export const PlatformConnectStatusSchema: z.ZodType<ConnectStatus> = z.object({
  connect: ConnectIdSchema,
  status: z.enum(["open", "completed", "mismatch", "failed", "expired"]),
  item: PlatformItemSummarySchema.optional(),
  account: z.string().optional(),
  grantedScopes: z.array(z.string()).optional(),
  message: z.string().optional(),
  expiresAt: Iso,
})

export const PlatformApprovalStatusSchema = z.enum(["pending", "approved", "denied", "expired", "used", "ended", "revoked", "stale"])
export const PlatformApprovalListQuerySchema = z.strictObject({ status: PlatformApprovalStatusSchema.optional() })

// A platform's own reference for a decision, kept in the audit.
export const PlatformDecisionRefSchema = z.string().regex(/^[A-Za-z0-9_.:-]{1,64}$/)

export const PlatformApprovalViewSchema = z.object({
  approval: ApprovalIdSchema,
  status: PlatformApprovalStatusSchema,
  digest: z.string(),
  device: DeviceIdSchema,
  workload: z.object({ id: z.string().regex(PLATFORM_WORKLOAD_ID), label: z.string() }).nullable(),
  item: Slug,
  request: z.object({
    method: z.string(),
    url: z.string(),
    contentType: z.string().nullable(),
    contentEncoding: z.string().nullable(),
    headersSha256: z.string(),
    bodySha256: z.string(),
  }),
  title: z.string(),
  warnings: z.array(z.string()),
  constraints: z.object({ uses: z.number().int().min(1).nullable(), ttlSeconds: z.number().int().positive() }),
  expiresAt: Iso,
  decidedBy: z.object({ platform: PlatformIdSchema, key: PlatformKeyIdSchema, ref: PlatformDecisionRefSchema.nullable() }).nullable(),
})
export type PlatformApprovalView = z.infer<typeof PlatformApprovalViewSchema>
export const PlatformApprovalListSchema = z.object({ approvals: z.array(PlatformApprovalViewSchema) })
export type PlatformApprovalList = z.infer<typeof PlatformApprovalListSchema>

// One use, always; `ttlSeconds` at most the platform's decisionTtlSeconds.
export const PlatformApprovalDecideSchema = z.strictObject({
  decision: z.enum(["approve", "deny"]),
  digest: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  ttlSeconds: z.int().min(PLATFORM_DECISION_MIN_TTL_SECONDS).max(PLATFORM_DECISION_MAX_TTL_SECONDS).optional(),
  ref: PlatformDecisionRefSchema.optional(),
})
export type PlatformApprovalDecide = z.infer<typeof PlatformApprovalDecideSchema>

// Every environment of a managed project is unprotected, with no four-eyes
// and no remote.
export const PlatformProjectCreateSchema = z
  .strictObject({
    slug: Slug,
    environments: z.array(z.strictObject({ name: EnvName })).min(1).max(16),
    defaultEnv: EnvName,
  })
  .refine((project) => new Set(project.environments.map((e) => e.name)).size === project.environments.length, "Each environment may appear once.")
  .refine((project) => project.environments.some((e) => e.name === project.defaultEnv), "The default environment must be one of the environments.")
export type PlatformProjectCreate = z.infer<typeof PlatformProjectCreateSchema>

// A variable's value as the platform set it: a plain value, or an item's
// field (null for the kind's primary field).
export const PlatformVarValueSchema = z.union([
  z.strictObject({ plain: z.string().max(4096) }),
  z.strictObject({ item: Slug, field: FieldName.nullable() }),
])
export type PlatformVarValue = z.infer<typeof PlatformVarValueSchema>

export const PlatformProjectVarSchema = z.object({
  name: VarName,
  env: EnvName,
  source: z.enum(["plain", "item", "unset"]),
  value: z.string().optional(),
  item: Slug.optional(),
  field: z.string().nullable().optional(),
})

export const PlatformProjectViewSchema = z.object({
  id: ProjectIdSchema,
  slug: Slug,
  defaultEnv: EnvName,
  environments: z.array(z.object({ name: EnvName })),
  vars: z.array(PlatformProjectVarSchema),
})
export type PlatformProjectView = z.infer<typeof PlatformProjectViewSchema>

// PUT .../projects/:project/vars/:name. `before` is the value the platform
// last read (null for unset); a stale one is `conflict`. Neither `plain`
// nor `item` unsets the variable; `field` goes with `item` only.
export const PlatformVarSetSchema = z
  .strictObject({
    env: EnvName,
    before: PlatformVarValueSchema.nullable(),
    plain: z.string().max(4096).optional(),
    item: Slug.optional(),
    field: FieldName.optional(),
  })
  .refine((set) => set.plain === undefined || set.item === undefined, "Set a plain value or an item, not both.")
  .refine((set) => set.field === undefined || set.item !== undefined, "A field goes with an item.")
export type PlatformVarSet = z.infer<typeof PlatformVarSetSchema>

export const PlatformProjectRemovalSchema = z.object({ deleted: z.literal(true) })

export const PlatformAuditQuerySchema = z.strictObject({
  cursor: z.string().regex(/^[1-9][0-9]*$/).refine((value) => Number.isSafeInteger(Number(value))).optional(),
  limit: z.coerce.number().int().min(1).max(PLATFORM_AUDIT_PAGE_MAX).optional(),
})
export type PlatformAuditQuery = z.infer<typeof PlatformAuditQuerySchema>

export const PlatformFrozenSchema = z.object({ frozen: z.literal(true) })
export const PlatformUnfrozenSchema = z.object({ frozen: z.literal(false) })
export const PlatformEmptyAnswerSchema = z.object({})

// ---------------------------------------------------------------- the route table

// Every platform route: P5 generates the API reference from this table, the
// Worker routes by it and the client calls by it. `refusals` are the route's
// own, beyond PLATFORM_COMMON_REFUSALS. `status` lists the success statuses.
export type PlatformRoute = {
  readonly number: number
  readonly name: string
  readonly method: "GET" | "PUT" | "POST" | "DELETE"
  readonly path: string
  readonly params: Readonly<Record<string, z.ZodType<string>>>
  readonly query: z.ZodType | null
  readonly body: z.ZodType | null
  readonly answer: z.ZodType
  readonly status: readonly number[]
  readonly refusals: readonly ErrorCode[]
  readonly prose: string
}

export const PLATFORM_COMMON_REFUSALS = ["unauthenticated", "proof_invalid", "platform_suspended", "rate_limited", "bad_request", "not_found"] as const satisfies readonly ErrorCode[]

const SUBJECT_PATH = "/v1/platform/subjects/:subject"
const subjectParams = { subject: PlatformSubjectSchema }
const DeviceParam = DeviceIdSchema
const ItemParam = Slug
const IntakeParam = IntakeIdSchema
const ConnectParam = ConnectIdSchema
const ApprovalParam = ApprovalIdSchema
const ProjectParam = ProjectIdSchema

export const PLATFORM_ROUTES = [
  {
    number: 1, name: "platform.view", method: "GET", path: "/v1/platform", params: {}, query: null, body: null, answer: PlatformViewSchema, status: [200], refusals: [],
    prose: "Reads the platform as Mehen holds it: its status, limits, defaults and their revision, how many subjects it has, and its keys.",
  },
  {
    number: 4, name: "subjects.list", method: "GET", path: "/v1/platform/subjects", params: {}, query: SubjectListQuerySchema, body: null, answer: SubjectListSchema, status: [200], refusals: [],
    prose: "Lists the platform's own subjects, a page at a time, with each one's status. Another platform's subjects are never listed.",
  },
  {
    number: 5, name: "subjects.ensure", method: "PUT", path: SUBJECT_PATH, params: subjectParams, query: null, body: PlatformEmptySchema, answer: SubjectViewSchema, status: [200, 201], refusals: ["quota_exceeded", "conflict"],
    prose: "Makes sure the subject has its managed workspace: 201 when it is made, 200 when it already existed. Refused while the subject is still being deleted, and while the platform is retiring.",
  },
  {
    number: 6, name: "subjects.get", method: "GET", path: SUBJECT_PATH, params: subjectParams, query: null, body: null, answer: SubjectViewSchema, status: [200], refusals: [],
    prose: "Reads one subject: its status and how many devices, items and projects its workspace holds. A deleted subject is answered until its purge, so its audit can still be read.",
  },
  {
    number: 7, name: "subjects.remove", method: "DELETE", path: SUBJECT_PATH, params: subjectParams, query: null, body: PlatformEmptySchema, answer: SubjectRemovalSchema, status: [200], refusals: [],
    prose: "Deletes a subject: every device is revoked, every secret and item deleted, and the audit kept until the purge date in the answer, when the whole workspace is erased. Repeating it answers the same.",
  },
  {
    number: 8, name: "devices.create", method: "POST", path: `${SUBJECT_PATH}/devices`, params: subjectParams, query: null, body: PlatformDeviceCreateSchema, answer: PlatformDeviceViewSchema, status: [200, 201], refusals: ["quota_exceeded", "conflict", "frozen"],
    prose: "Provisions a device in the subject's workspace for one of the platform's agents, with no enrolment page. It may only relay and serve placeholders, and acts only through workloads. The same key again answers the existing device with 200.",
  },
  {
    number: 9, name: "devices.list", method: "GET", path: `${SUBJECT_PATH}/devices`, params: subjectParams, query: null, body: null, answer: PlatformDeviceListSchema, status: [200], refusals: [],
    prose: "Lists the subject's devices, with when each was last seen and how many live workloads it has.",
  },
  {
    number: 10, name: "devices.revoke", method: "DELETE", path: `${SUBJECT_PATH}/devices/:device`, params: { ...subjectParams, device: DeviceParam }, query: null, body: null, answer: PlatformDeviceViewSchema, status: [200], refusals: ["frozen"],
    prose: "Revokes a device. Its workloads, open asks and runs end with it. Repeating it answers the same.",
  },
  {
    number: 11, name: "items.list", method: "GET", path: `${SUBJECT_PATH}/items`, params: subjectParams, query: PlatformItemFilterSchema, body: null, answer: PlatformItemListSchema, status: [200], refusals: [],
    prose: "Lists the subject's items by Mehen's metadata (name, kind, provider, account, tags, hosts, status and policy). Never a value.",
  },
  {
    number: 12, name: "items.remove", method: "DELETE", path: `${SUBJECT_PATH}/items/:slug`, params: { ...subjectParams, slug: ItemParam }, query: null, body: null, answer: ItemRemovalSchema, status: [200], refusals: ["frozen"],
    prose: "Deletes an item and its secrets. Approvals and grants on it end. An OAuth connection's token is handed back to the provider first where the provider allows it.",
  },
  {
    number: 13, name: "intakes.create", method: "POST", path: `${SUBJECT_PATH}/intakes`, params: subjectParams, query: null, body: PlatformIntakeCreateSchema, answer: PlatformIntakeSchema, status: [201], refusals: ["conflict", "quota_exceeded", "frozen"],
    prose: "Opens a request for a credential and answers the vault's seal key and the fields to fill in: a key from a catalogue template or for one host, or the person's own OAuth app, for a catalogue provider (with its set-up steps) or with its own provider definition. The person types the values into the platform's own page, which seals each secret in their browser before it reaches the platform. An existing name of the same kind is a rotation and keeps where the key may go. It lives 10 minutes and carries no link.",
  },
  {
    number: 14, name: "intakes.submit", method: "POST", path: `${SUBJECT_PATH}/intakes/:intake/submit`, params: { ...subjectParams, intake: IntakeParam }, query: null, body: PlatformIntakeSubmitSchema, answer: PlatformIntakeSubmittedSchema, status: [200], refusals: ["conflict", "quota_exceeded", "frozen"],
    prose: "Submits the sealed values for an open request. Each box opens only for this request and field, and only once. The name, where the key may go, its tags and its home are the request's, never the body's.",
  },
  {
    number: 15, name: "intakes.cancel", method: "POST", path: `${SUBJECT_PATH}/intakes/:intake/cancel`, params: { ...subjectParams, intake: IntakeParam }, query: null, body: PlatformEmptySchema, answer: PlatformEmptyAnswerSchema, status: [200], refusals: [],
    prose: "Cancels an open request for a credential.",
  },
  {
    number: 16, name: "connects.start", method: "POST", path: `${SUBJECT_PATH}/connects`, params: subjectParams, query: null, body: PlatformConnectStartSchema, answer: PlatformConnectStartedSchema, status: [201], refusals: ["conflict", "quota_exceeded", "frozen"],
    prose: "Starts connecting an account with the person's own OAuth app, held in their workspace, and answers the provider's authorisation URL, carrying Mehen's state, the platform's callback and a PKCE challenge where the provider supports one, for the platform to send the person to. Without scopes it asks for the platform's default scopes for a catalogue provider, else the catalogue's, or every scope of the app's own provider definition. It lives 15 minutes.",
  },
  {
    number: 17, name: "connects.finish", method: "POST", path: `${SUBJECT_PATH}/connects/finish`, params: subjectParams, query: null, body: PlatformConnectFinishSchema, answer: PlatformConnectFinishedSchema, status: [200], refusals: ["conflict", "quota_exceeded", "upstream_failed", "frozen"],
    prose: "Finishes a connection with what the platform's callback received. Mehen exchanges the code with the app's client secret, which only Mehen holds, and its own PKCE verifier where it sent a challenge, so the code is useless to anyone else. A state that is not this subject's is not found; a state already used or expired is a conflict.",
  },
  {
    number: 18, name: "connects.get", method: "GET", path: `${SUBJECT_PATH}/connects/:connect`, params: { ...subjectParams, connect: ConnectParam }, query: null, body: null, answer: PlatformConnectStatusSchema, status: [200], refusals: [],
    prose: "Reads a connection's progress and outcome.",
  },
  {
    number: 19, name: "connects.cancel", method: "POST", path: `${SUBJECT_PATH}/connects/:connect/cancel`, params: { ...subjectParams, connect: ConnectParam }, query: null, body: PlatformEmptySchema, answer: PlatformEmptyAnswerSchema, status: [200], refusals: [],
    prose: "Cancels a connection that has not finished.",
  },
  {
    number: 20, name: "approvals.list", method: "GET", path: `${SUBJECT_PATH}/approvals`, params: subjectParams, query: PlatformApprovalListQuerySchema, body: null, answer: PlatformApprovalListSchema, status: [200], refusals: [],
    prose: "Lists the subject's held requests, filtered by status.",
  },
  {
    number: 21, name: "approvals.get", method: "GET", path: `${SUBJECT_PATH}/approvals/:approval`, params: { ...subjectParams, approval: ApprovalParam }, query: null, body: null, answer: PlatformApprovalViewSchema, status: [200], refusals: [],
    prose: "Reads one held request: the exact request it would send, its digest, the device and workload that asked, what Mehen could not read, and who decided it.",
  },
  {
    number: 22, name: "approvals.decide", method: "POST", path: `${SUBJECT_PATH}/approvals/:approval/decide`, params: { ...subjectParams, approval: ApprovalParam }, query: null, body: PlatformApprovalDecideSchema, answer: PlatformApprovalViewSchema, status: [200], refusals: ["conflict", "frozen"],
    prose: "Approves or denies a held request, naming its digest. An approval is good for one use of that exact request by the workload that asked, for at most the platform's decision limit (15 minutes at most). A digest that is not the request's, or a request no longer pending, is a conflict: the request changed, ask again.",
  },
  {
    number: 23, name: "projects.create", method: "POST", path: `${SUBJECT_PATH}/projects`, params: subjectParams, query: null, body: PlatformProjectCreateSchema, answer: PlatformProjectViewSchema, status: [200, 201], refusals: ["conflict", "quota_exceeded", "frozen"],
    prose: "Creates a project, a named set of settings and keys for computers, with its environments. Every environment is unprotected. The same name again, with the same environments and default environment, answers the existing project with 200; the same name with other environments or another default environment is a conflict.",
  },
  {
    number: 24, name: "projects.get", method: "GET", path: `${SUBJECT_PATH}/projects/:project`, params: { ...subjectParams, project: ProjectParam }, query: null, body: null, answer: PlatformProjectViewSchema, status: [200], refusals: [],
    prose: "Reads a project and its variables, plain values included.",
  },
  {
    number: 25, name: "projects.setVar", method: "PUT", path: `${SUBJECT_PATH}/projects/:project/vars/:name`, params: { ...subjectParams, project: ProjectParam, name: VarName }, query: null, body: PlatformVarSetSchema, answer: PlatformProjectViewSchema, status: [200], refusals: ["conflict", "frozen"],
    prose: "Sets one variable in one environment to a plain value or an item's field, or unsets it when neither is sent. `before` is the value last read; a stale one is a conflict. A plain value that looks like a secret is refused.",
  },
  {
    number: 26, name: "projects.remove", method: "DELETE", path: `${SUBJECT_PATH}/projects/:project`, params: { ...subjectParams, project: ProjectParam }, query: null, body: PlatformEmptySchema, answer: PlatformProjectRemovalSchema, status: [200], refusals: ["frozen"],
    prose: "Deletes a project. Its runs and their placeholders end.",
  },
  {
    number: 27, name: "audit.read", method: "GET", path: `${SUBJECT_PATH}/audit`, params: subjectParams, query: PlatformAuditQuerySchema, body: null, answer: WorkspaceAuditPageSchema, status: [200], refusals: [],
    prose: "Reads the subject's audit chain a page at a time, every row, with its head and whether it verified. Every row names the platform.",
  },
  {
    number: 28, name: "workspace.freeze", method: "POST", path: `${SUBJECT_PATH}/freeze`, params: subjectParams, query: null, body: PlatformEmptySchema, answer: PlatformFrozenSchema, status: [200], refusals: [],
    prose: "Freezes the subject's workspace: nothing is used or changed until it is unfrozen.",
  },
  {
    number: 29, name: "workspace.unfreeze", method: "POST", path: `${SUBJECT_PATH}/unfreeze`, params: subjectParams, query: null, body: PlatformEmptySchema, answer: PlatformUnfrozenSchema, status: [200], refusals: [],
    prose: "Unfreezes the subject's workspace.",
  },
  {
    number: 30, name: "defaults.put", method: "PUT", path: "/v1/platform/defaults", params: {}, query: null, body: PlatformDefaultsSchema, answer: PlatformDefaultsViewSchema, status: [200], refusals: [],
    prose: "Replaces the platform's defaults: which templates and providers its users may add, default OAuth scopes and tags, rules added to a template's or provider's policy, and whether keys with no template may be read without a hold. Rules may only hold or refuse, never allow. Every workspace uses the new defaults within 30 seconds, and approvals made under the old ones go stale.",
  },
  {
    number: 31, name: "subjects.removeAll", method: "DELETE", path: "/v1/platform/subjects", params: {}, query: null, body: SubjectsRemoveAllSchema, answer: SubjectsRemovalSchema, status: [200], refusals: [],
    prose: "Deletes every subject the platform has, each as deleting one does, 50 at a time. `confirm` must be the platform's own slug. The platform stays registered.",
  },
] as const satisfies readonly PlatformRoute[]

export type PlatformRouteName = (typeof PLATFORM_ROUTES)[number]["name"]

export function platformRoute<N extends PlatformRouteName>(name: N): Extract<(typeof PLATFORM_ROUTES)[number], { name: N }> {
  const route = PLATFORM_ROUTES.find((r) => r.name === name)
  if (route === undefined) throw new Error(`no platform route ${name}`)
  return route as Extract<(typeof PLATFORM_ROUTES)[number], { name: N }>
}
