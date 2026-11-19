// Intakes: an agent asks for a credential it does not have, a
// human fills in a one-time form whose secret fields are sealed in the
// browser to the vault, and the DO opens them here and stores the item.
// The agent learns the outcome, never the value.

import { z } from "zod"
import {
  type BindingInput,
  BindingSchema,
  type Injection,
  IntakeCreate,
  type IntakeCreated,
  type IntakeStatus,
  type IntakeView,
  type ItemSummary,
  type RequestedBy,
  Slug,
  Tag,
  canonicalJson,
} from "@mehen/protocol/api"
import { KINDS, type ItemKind, IntakeSealedBoxSchema, NATURAL_INJECTION, type Template, customItemPolicy, getTemplate, isItemKind, isReservedHeader, isSealedBox, openText } from "@mehen/protocol"
import { VaultError } from "../../http.ts"
import { sealPrivateKey, sealPublicJwk } from "../../seal-key.ts"
import { type Area, type DevicePrincipal, type MemberPrincipal, type Principal, type Requester, type VaultContext, actorOf, one, randomId } from "../core.ts"
import type { IntakesService, ItemRecord } from "../services.ts"
import "./credentials-pending.ts"
import { credentialOps } from "./items-workspace.ts"
import { workspaceIntakeOps, workspaceRequestMigration, workspaceRequestWorkloadMigration } from "./intake-workspace.ts"
import { deviceCovers } from "./devices.ts"
import { assertBindingHosts, items, parseOpInput, stepUpDigest } from "./items.ts"

const INTAKE_TTL_MS = 24 * 3600_000
// An open intake with less than this left is not handed out again.
const REUSE_MARGIN_MS = 60_000
const INTAKE_ID = /^int_[A-Za-z0-9_-]{8,64}$/
const SUPERSEDED = "superseded"
// A row claimed for saving this long ago with no outcome written is
// resolved from what was stored (the isolate died mid-save).
export const SAVING_STALE_MS = 60_000

export const NAME_TAKEN = "That name is taken. Pick another name."

// The reason recorded on an ask a member starts from Connect a service:
// fixed, since the member types no reason and a page quotes this line.
export const MEMBER_REASON = "Started from Connect a service in the vault."

// The requester key of an ask a member made. Device ids are `dev_...`, so a
// key with this prefix never equals one, and a device filtering rows by its
// own id never sees a member's row.
const MEMBER_KEY_PREFIX = "member:"

export function requesterOf(principal: DevicePrincipal | MemberPrincipal, session: string | null = null): Requester {
  if (principal.kind === "device") return { principal, key: principal.device, name: principal.name, session: session ?? principal.session }
  return { principal, key: `${MEMBER_KEY_PREFIX}${principal.member}`, name: "", session: null }
}

// Who asked, as a view says it: the row's device and the name the owner
// approved, or the member, with `self` decided here from the principal the
// Worker took from the session.
export function requestedByOf(row: { device: string; device_name: string; session: string | null }, viewer: Principal): RequestedBy {
  if (row.device.startsWith(MEMBER_KEY_PREFIX)) {
    const member = row.device.slice(MEMBER_KEY_PREFIX.length)
    return { member, self: viewer.kind === "member" && viewer.member === member }
  }
  return { device: row.device, deviceName: row.device_name, session: row.session }
}

// A device may only touch items its scope covers; a member sees them all.
function covers(requester: Requester, item: ItemRecord): boolean {
  return requester.principal.kind === "member" || deviceCovers(requester.principal, item, "relay")
}

type IntakeRow = {
  id: string
  kind: string
  slug: string
  provider: string | null
  reason: string
  tags: string
  proposed_binding: string | null
  proposed_injection: string | null
  rotation: number
  device: string
  device_name: string
  session: string | null
  // `saving`: claimed by a submit whose item is being stored; reads as open.
  status: "open" | "saving" | "completed" | "cancelled"
  item: string | null
  created_at: number
  expires_at: number
  completed_at: number | null
  // The connect created along with this intake, which waits for the client it saves.
  connect: string | null
  cancel_reason: string | null
  claimed_at: number | null
}

const INTAKE_MIGRATIONS = [
  `CREATE TABLE intakes (
       id TEXT PRIMARY KEY,
       kind TEXT NOT NULL,
       slug TEXT NOT NULL,
       provider TEXT,
       reason TEXT NOT NULL,
       tags TEXT NOT NULL,
       proposed_binding TEXT,
       rotation INTEGER NOT NULL,
       device TEXT NOT NULL,
       device_name TEXT NOT NULL,
       session TEXT,
       status TEXT NOT NULL,
       item TEXT,
       created_at INTEGER NOT NULL,
       expires_at INTEGER NOT NULL,
       completed_at INTEGER
     );
     CREATE INDEX intakes_device ON intakes (device, created_at);`,
  `ALTER TABLE intakes ADD COLUMN proposed_injection TEXT;`,
  `ALTER TABLE intakes ADD COLUMN connect TEXT;
   ALTER TABLE intakes ADD COLUMN cancel_reason TEXT;`,
  `ALTER TABLE intakes ADD COLUMN claimed_at INTEGER;`,
]

// A saving row is still in progress to everyone outside the submit.
function effectiveStatus(ctx: VaultContext, row: IntakeRow): IntakeStatus["status"] {
  if (row.status === "saving") return "open"
  return row.status === "open" && ctx.now() >= row.expires_at ? "expired" : row.status
}

function savingKey(id: string): string {
  return `saving:${id}`
}

// True when the item this claim was storing is there: created (or, for a
// rotation, changed) since the claim.
function storedSince(ctx: VaultContext, row: IntakeRow, claimedAt: number): boolean {
  const item = items.getItem(ctx, row.slug)
  if (!item || item.kind !== row.kind) return false
  return row.rotation === 1 ? item.updatedAt >= claimedAt : item.createdAt >= claimedAt
}

// A claim with no outcome after SAVING_STALE_MS belongs to a submit that
// died with its isolate. What it stored decides the row: an item in place
// completes it, otherwise the row is handed back (and reads expired if its
// time is up). Rows resolve on read and from the alarm the claim scheduled.
function resolveStale(ctx: VaultContext, row: IntakeRow): IntakeRow {
  if (row.status !== "saving" || row.claimed_at === null || ctx.now() < row.claimed_at + SAVING_STALE_MS) return row
  const stored = storedSince(ctx, row, row.claimed_at)
  if (stored) ctx.sql.exec("UPDATE intakes SET status = 'completed', item = ?, completed_at = ?, claimed_at = NULL WHERE id = ? AND status = 'saving'", row.slug, ctx.now(), row.id)
  else ctx.sql.exec("UPDATE intakes SET status = 'open', item = NULL, claimed_at = NULL WHERE id = ? AND status = 'saving'", row.id)
  ctx.unschedule("intake", savingKey(row.id))
  ctx.audit({ actor: "system", action: "intake.recover", target: row.slug, detail: { intake: row.id, stored } })
  return one(ctx.sql.exec<IntakeRow>("SELECT * FROM intakes WHERE id = ?", row.id)) ?? row
}

function getIntake(ctx: VaultContext, id: string): IntakeRow | null {
  if (!INTAKE_ID.test(id)) return null
  const row = one(ctx.sql.exec<IntakeRow>("SELECT * FROM intakes WHERE id = ?", id))
  return row ? resolveStale(ctx, row) : null
}

function requireIntake(ctx: VaultContext, id: string): IntakeRow {
  const row = getIntake(ctx, id)
  if (!row) throw new VaultError("not_found", "No such credential request. It may belong to another vault; ask the agent for a new link.")
  return row
}

function requireOpen(ctx: VaultContext, row: IntakeRow): void {
  if (row.status === "saving") throw new VaultError("conflict", "This credential request is being saved right now.")
  const status = effectiveStatus(ctx, row)
  if (status === "open") return
  if (row.cancel_reason === SUPERSEDED) {
    throw new VaultError("conflict", "This credential request was replaced by a newer link from the same machine. Ask the agent for its current link.")
  }
  const why = {
    completed: "has already been filled in",
    cancelled: "was cancelled",
    expired: "has expired",
  }[status]
  throw new VaultError("conflict", `This credential request ${why}. Ask the agent for a new one if it still needs the credential.`)
}

function kindOf(row: IntakeRow): ItemKind {
  if (!isItemKind(row.kind)) throw new Error("corrupt intake kind")
  return row.kind
}

// Where the credential will be allowed to go and how it is put into a
// request, and whether the vault (a template, or the kind's usual
// injection) vouches for each. A rotation always keeps the existing item's.
type IntakePlan = {
  rotation: ItemRecord | null
  template: Template | null
  binding: BindingInput
  verified: boolean
  injection: Injection | null
  injectionVerified: boolean
}

function planFor(ctx: VaultContext, row: IntakeRow): IntakePlan {
  if (row.rotation === 1) {
    const item = items.getItem(ctx, row.slug)
    if (!item || item.kind !== row.kind) {
      throw new VaultError("conflict", `The item "${row.slug}" this request would rotate was deleted or replaced. Cancel this request and ask the agent for a new one.`)
    }
    const template = item.provider ? getTemplate(item.provider) : null
    const verified = template !== null && canonicalJson(template.binding) === canonicalJson(item.binding)
    return { rotation: item, template, binding: item.binding, verified, injection: item.injection, injectionVerified: true }
  }
  const template = row.provider ? getTemplate(row.provider) : null
  if (template) return { rotation: null, template, binding: template.binding, verified: true, injection: template.injection, injectionVerified: true }
  if (!row.proposed_binding) throw new Error("intake without a template or a binding")
  const binding = JSON.parse(row.proposed_binding) as BindingInput
  if (row.proposed_injection) return { rotation: null, template: null, binding, verified: false, injection: JSON.parse(row.proposed_injection) as Injection, injectionVerified: false }
  return { rotation: null, template: null, binding, verified: false, injection: NATURAL_INJECTION[kindOf(row)], injectionVerified: true }
}

const INJECTION_HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/

// An agent's proposed injection may only name this kind's fields, must put
// a secret field into the request, and may only be one header (never a
// reserved one), one query parameter or basic credentials: a header map
// would let the human's entry name any header at all.
export function assertProposedInjection(kind: ItemKind, injection: Injection): void {
  const spec = KINDS[kind]
  const fields = new Map(spec.fields.map((f) => [f.name, f]))
  const secretNames = spec.fields.filter((f) => f.secret).map((f) => f.name).join(", ")
  const bad = (why: string): never => {
    throw new VaultError("bad_request", `The proposed injection ${why}. A ${spec.label} has the secret field(s) ${secretNames}; use for example { "in": "header", "name": "Authorization", "format": "Bearer {${spec.fields.find((f) => f.secret)?.name ?? "key"}}" }.`)
  }
  const secret = (name: string): boolean => fields.get(name)?.secret === true
  switch (injection.in) {
    case "header": {
      if (!INJECTION_HEADER_NAME.test(injection.name) || isReservedHeader(injection.name)) bad(`cannot use the header "${injection.name}"`)
      if (/[\r\n\0]/.test(injection.format)) bad("has a line break in its format")
      const markers = [...injection.format.matchAll(/\{([a-z][a-z0-9_]*)\}/g)].map((m) => m[1] as string)
      const unknown = markers.filter((m) => !fields.has(m))
      if (unknown.length > 0) bad(`names ${unknown.map((m) => `{${m}}`).join(", ")}, which a ${spec.label} does not have`)
      if (!markers.some(secret)) bad("puts no secret field into the header")
      break
    }
    case "query":
      if (!INJECTION_HEADER_NAME.test(injection.name)) bad(`cannot use the query parameter "${injection.name}"`)
      if (!secret(injection.field)) bad(`names "${injection.field}", which is not a secret field of a ${spec.label}`)
      break
    case "basic":
      if (!fields.has(injection.username)) bad(`names "${injection.username}", which a ${spec.label} does not have`)
      if (!secret(injection.password)) bad(`names "${injection.password}", which is not a secret field of a ${spec.label}`)
      break
    case "headers":
      bad("is a header map, which an agent may not propose; propose one header, a query parameter or basic credentials")
  }
}

function summaryOf(ctx: VaultContext, row: IntakeRow): ItemSummary | undefined {
  if (effectiveStatus(ctx, row) !== "completed" || !row.item) return undefined
  const item = items.getItem(ctx, row.item)
  return item ? items.summarise(item) : undefined
}

function intakeUrl(ctx: VaultContext, id: string): string {
  return `${ctx.env.VAULT_ORIGIN}/i/${id}`
}

function createdOf(ctx: VaultContext, row: Pick<IntakeRow, "id" | "expires_at">): IntakeCreated {
  return { intake: row.id, url: intakeUrl(ctx, row.id), expiresAt: new Date(row.expires_at).toISOString() }
}

function statusOf(ctx: VaultContext, row: IntakeRow): IntakeStatus {
  const item = summaryOf(ctx, row)
  return {
    intake: row.id,
    status: effectiveStatus(ctx, row),
    ...(item ? { item } : {}),
    expiresAt: new Date(row.expires_at).toISOString(),
    ...(row.cancel_reason === SUPERSEDED ? { superseded: true as const } : {}),
  }
}

// What a new intake row would hold, apart from who asked and why: the
// values a second request must repeat to get the same link back.
type IntakeShape = {
  kind: ItemKind
  provider: string | null
  proposedBinding: string | null
  proposedInjection: string | null
  rotation: boolean
  tags: string[]
}

function shapeOf(row: IntakeRow): IntakeShape {
  return {
    kind: kindOf(row),
    provider: row.provider,
    proposedBinding: row.proposed_binding === null ? null : canonicalJson(JSON.parse(row.proposed_binding)),
    proposedInjection: row.proposed_injection === null ? null : canonicalJson(JSON.parse(row.proposed_injection)),
    rotation: row.rotation === 1,
    tags: intakeTags(row),
  }
}

function sameShape(a: IntakeShape, b: IntakeShape): boolean {
  return canonicalJson(a) === canonicalJson(b)
}

// This requester's open intake for the slug, if it has time left. Only the
// asker's own rows are ever considered, so a link never travels to another
// machine or member.
function openIntakeFor(ctx: VaultContext, requester: Requester, slug: string): IntakeRow | null {
  return one(
    ctx.sql.exec<IntakeRow>(
      "SELECT * FROM intakes WHERE device = ? AND slug = ? AND status = 'open' AND expires_at > ? ORDER BY created_at DESC LIMIT 1",
      requester.key,
      slug,
      ctx.now() + REUSE_MARGIN_MS,
    ),
  )
}

function finishingNow(open: IntakeRow): VaultError {
  return new VaultError("conflict", `A human is saving the credential for "${open.slug}" right now (request ${open.id}). Wait for it instead of asking again.`, {
    next: { command: `mehen wait ${open.id}`, say: `Your credential for "${open.slug}" is being saved; the agent is waiting for it.` },
  })
}

// This requester's intake for the slug that a human is saving right now, if any.
function submittingFor(ctx: VaultContext, requester: Requester, slug: string): IntakeRow | null {
  const rows = ctx.sql.exec<IntakeRow>("SELECT * FROM intakes WHERE device = ? AND slug = ? AND status = 'saving'", requester.key, slug).toArray()
  return rows.map((row) => resolveStale(ctx, row)).find((row) => row.status === "saving") ?? null
}

// Closes every other open intake this requester has for the slug, so one
// link is live per requester and slug. A row a human is saving right now is
// not open, so it is left alone: its claim decides it.
function supersedeOthers(ctx: VaultContext, requester: Requester, slug: string, keep: string): void {
  const rows = ctx.sql.exec<IntakeRow>("SELECT * FROM intakes WHERE device = ? AND slug = ? AND status = 'open' AND id != ?", requester.key, slug, keep).toArray()
  for (const old of rows) {
    const written = ctx.sql.exec(
      "UPDATE intakes SET status = 'cancelled', cancel_reason = ?, completed_at = ? WHERE id = ? AND status = 'open' AND device = ?",
      SUPERSEDED,
      ctx.now(),
      old.id,
      requester.key,
    ).rowsWritten
    if (written === 0) continue
    ctx.audit({ actor: actorOf(requester.principal), action: "intake.supersede", target: old.slug, detail: { intake: old.id, by: keep } })
  }
}

type IntakeRequest = z.infer<typeof IntakeCreate>

// What to do with this requester's open intake for the same slug: one asking
// for the same thing (same shape) and one asking for something else.
type OnOpen = { same: "reuse" | "supersede"; different: "refuse" | "supersede" }

function onOpenFor(fresh: boolean | undefined): OnOpen {
  return fresh ? { same: "supersede", different: "supersede" } : { same: "reuse", different: "refuse" }
}

// Validates the request, then returns this requester's matching open intake
// or inserts a new row. `connect` chains the intake to a connect waiting
// for the item it will save.
function createIntake(ctx: VaultContext, requester: Requester, req: IntakeRequest, connect: string | null, onOpen: OnOpen): IntakeCreated {
  const principal = requester.principal
  const template = req.provider === undefined ? null : getTemplate(req.provider)
  if (req.provider !== undefined && !template) {
    throw new VaultError("bad_request", `Unknown provider "${req.provider}". Leave the provider out and propose a binding instead, or use one the vault knows.`)
  }
  if (template && template.kind !== req.kind) {
    throw new VaultError("bad_request", `The "${template.id}" provider is a ${KINDS[template.kind].label}, not a ${KINDS[req.kind].label}.`)
  }
  const existing = items.getItem(ctx, req.slug)
  // The same words whether or not the device may see the item, so the
  // answer says nothing about what lies outside its scope.
  if (existing && (existing.kind !== req.kind || !covers(requester, existing))) {
    throw new VaultError("conflict", NAME_TAKEN)
  }
  if (existing && req.provider !== undefined && req.provider !== existing.provider) {
    throw new VaultError("bad_request", `"${req.slug}" already exists with another provider; a rotation keeps its provider. Leave the provider out to rotate it.`)
  }
  let proposed: BindingInput | null = null
  if (!existing && !template) {
    if (!req.binding) {
      throw new VaultError("bad_request", "Without a provider, propose a binding: the hosts this credential may be sent to. The human will see it marked as unverified.")
    }
    assertBindingHosts(req.binding)
    proposed = req.binding
  }
  if (req.injection !== undefined) {
    if (existing) throw new VaultError("bad_request", `"${req.slug}" already exists, and a rotation keeps how it is sent. Leave the injection out to rotate it.`)
    if (template) throw new VaultError("bad_request", `The ${template.displayName} template fixes how this credential is sent. Leave the injection out.`)
    if (NATURAL_INJECTION[req.kind] === null) throw new VaultError("bad_request", `The relay never puts a ${KINDS[req.kind].label} into a request, so it takes no injection. Leave it out.`)
    assertProposedInjection(req.kind, req.injection)
  }
  const provider = existing ? existing.provider : (req.provider ?? null)
  const shape: IntakeShape = {
    kind: req.kind,
    provider,
    proposedBinding: proposed ? canonicalJson(proposed) : null,
    proposedInjection: req.injection !== undefined ? canonicalJson(req.injection) : null,
    rotation: existing !== null,
    tags: [...(req.tags ?? [])].sort(),
  }
  const open = openIntakeFor(ctx, requester, req.slug)
  const id = randomId("int")
  if (open) {
    const same = sameShape(shapeOf(open), shape)
    if (!same && onOpen.different === "refuse") {
      const url = intakeUrl(ctx, open.id)
      const until = new Date(open.expires_at).toISOString()
      if (principal.kind === "member") {
        throw new VaultError("conflict", `You already asked for "${req.slug}" with other details (request ${open.id}, open until ${until}).`, {
          next: { url, say: "Open that request to finish it, or cancel it from its page and start again here." },
          expiresAt: until,
        })
      }
      throw new VaultError("conflict", `This machine already asked for "${req.slug}" with other details (request ${open.id}, open until ${until}). Wait for that one, or repeat this request with fresh: true (mehen request --new) to replace it.`, {
        next: { url, command: `mehen wait ${open.id}`, say: `A request for "${req.slug}" is already waiting for you at ${url}. If the agent needs something different it will ask again with a new link.` },
        expiresAt: until,
      })
    }
    if (same && onOpen.same === "reuse") {
      // The page leads on to the newest connect that asked for this item.
      if (connect !== null) ctx.sql.exec("UPDATE intakes SET connect = ? WHERE id = ? AND device = ?", connect, open.id, requester.key)
      ctx.audit({ actor: actorOf(principal), action: "intake.reuse", target: req.slug, detail: { intake: open.id, ...(connect !== null ? { connect } : {}) } })
      supersedeOthers(ctx, requester, req.slug, open.id)
      return createdOf(ctx, open)
    }
  }
  // Superseding or adding a link: refused while a human is saving one.
  const saving = submittingFor(ctx, requester, req.slug)
  if (saving) throw finishingNow(saving)
  const now = ctx.now()
  const expiresAt = now + INTAKE_TTL_MS
  ctx.sql.exec(
    `INSERT INTO intakes (id, kind, slug, provider, reason, tags, proposed_binding, proposed_injection, rotation, device, device_name, session, status, item, created_at, expires_at, completed_at, connect, cancel_reason)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', NULL, ?, ?, NULL, ?, NULL)`,
    id,
    req.kind,
    req.slug,
    provider,
    req.reason,
    JSON.stringify(req.tags ?? []),
    proposed ? JSON.stringify(proposed) : null,
    req.injection !== undefined ? JSON.stringify(req.injection) : null,
    existing ? 1 : 0,
    requester.key,
    requester.name,
    requester.session,
    now,
    expiresAt,
    connect,
  )
  supersedeOthers(ctx, requester, req.slug, id)
  ctx.audit({
    actor: actorOf(principal),
    action: "intake.create",
    target: req.slug,
    detail: {
      intake: id,
      kind: req.kind,
      provider,
      rotation: existing !== null,
      verified: existing === null && template !== null,
      ...(req.injection !== undefined ? { injection: req.injection.in } : {}),
      ...(connect !== null ? { connect } : {}),
      hosts: existing ? existing.binding.hosts : (template?.binding.hosts ?? proposed?.hosts ?? []),
    },
  })
  return createdOf(ctx, { id, expires_at: expiresAt })
}

const IntakeIdInput = z.object({ intake: z.string().max(80) })
const IntakeStatusInput = z.object({ intake: z.string().max(80), wait: z.boolean().optional() })

// The browser seals each secret field with seal(sealKey, value, `intake/<intake>/<field>`).
// The body the passkey signs over: stepUpDigest(canonical fields below).
// `tags` echoes the IntakeView's tags so the Worker can rebuild the action;
// the DO signs over the intake's stored tags instead, so a body that names
// other tags fails the step-up check. `allowReads` is the human's tick on a
// credential without a template (IntakeView.customPolicy); it is signed
// only when true, so a submission without it keeps the digest it had.
// `ceiling: "fill"` is the person's "Type it into the sign-in page" on a new
// password-login (submitWorkspaceIntake, intake-workspace.ts); absent, the
// body and its digest are what they were before it existed.
export const IntakeSubmission = z.object({
  slug: Slug,
  binding: BindingSchema,
  publicFields: z.record(z.string().max(64), z.string().max(4096)),
  sealed: z.record(z.string().max(64), IntakeSealedBoxSchema),
  tags: z.array(Tag).max(16),
  allowReads: z.boolean().optional(),
  ceiling: z.literal("fill").optional(),
})
export type IntakeSubmissionInput = z.infer<typeof IntakeSubmission>

export function intakeSubmitDigest(submission: IntakeSubmissionInput): Promise<string> {
  return stepUpDigest({
    slug: submission.slug,
    binding: submission.binding,
    publicFields: submission.publicFields,
    sealed: submission.sealed,
    tags: [...submission.tags].sort(),
    ...(submission.allowReads === true ? { allowReads: true } : {}),
    ...(submission.ceiling !== undefined ? { ceiling: submission.ceiling } : {}),
  })
}

// The tags the agent asked for, which a new item is stored with.
function intakeTags(row: IntakeRow): string[] {
  return (JSON.parse(row.tags) as string[]).sort()
}

const IntakeSubmitInput = IntakeSubmission.extend({ intake: z.string().max(80) })

async function openSealedFields(ctx: VaultContext, row: IntakeRow, sealed: IntakeSubmissionInput["sealed"]): Promise<Record<string, string>> {
  const spec = KINDS[kindOf(row)]
  const secretNames = new Set(spec.fields.filter((f) => f.secret).map((f) => f.name))
  const key = await sealPrivateKey(ctx.env)
  const out: Record<string, string> = {}
  for (const [name, box] of Object.entries(sealed)) {
    if (!secretNames.has(name)) throw new VaultError("bad_request", `"${name}" is not a secret field of a ${spec.label}.`)
    if (!isSealedBox(box)) throw new VaultError("bad_request", `The sealed value for "${name}" is malformed. Reload the page and enter it again.`)
    let value: string
    try {
      value = await openText(key, box, `intake/${row.id}/${name}`)
    } catch {
      throw new VaultError("bad_request", `The sealed value for "${name}" was not sealed for this request. Reload the page and enter it again.`)
    }
    if (value !== "") out[name] = value
  }
  return out
}

// POST /api/intakes: a member adds a credential from Connect a service. Only
// a built-in template, by id: the kind, hosts, policy and injection are the
// template's, so a member never proposes any of them (strict: a body that
// carries a binding or an injection is refused, not ignored).
export const MemberIntakeCreate = z.strictObject({
  provider: z.string().max(64),
  slug: Slug,
  tags: z.array(Tag).max(16).optional(),
  fresh: z.boolean().optional(),
})

async function storeSubmission(ctx: VaultContext, principal: Principal, row: IntakeRow, req: z.infer<typeof IntakeSubmitInput>): Promise<ItemRecord> {
  if (req.slug !== row.slug) throw new VaultError("bad_request", `This request is for "${row.slug}"; the name cannot change. Cancel it and ask the agent for a new one to use another name.`)
  const kind = kindOf(row)
  const spec = KINDS[kind]
  const plan = planFor(ctx, row)
  const sameBinding = canonicalJson(req.binding) === canonicalJson(plan.binding)
  if (plan.rotation) {
    if (!sameBinding) throw new VaultError("bad_request", `Rotating "${row.slug}" keeps its binding. Change the binding from the item page instead.`)
    if (Object.keys(req.publicFields).length > 0) throw new VaultError("bad_request", "A rotation replaces secret fields only; leave the public fields out.")
  } else if (plan.template && !sameBinding) {
    throw new VaultError("bad_request", `The ${plan.template.displayName} template fixes where this credential may go; a custom binding is refused.`)
  }
  if (req.allowReads === true && (plan.rotation || plan.template)) {
    throw new VaultError(
      "bad_request",
      plan.rotation
        ? `Replacing the secret of "${row.slug}" keeps its policy. Change what agents may do from the item page instead.`
        : `The ${plan.template?.displayName ?? "provider"} template fixes what agents may do with this credential; allowReads is only for a credential without a template.`,
    )
  }
  assertBindingHosts(req.binding)
  const secrets = await openSealedFields(ctx, row, req.sealed)
  if (plan.rotation) {
    for (const field of spec.fields) {
      if (field.secret && field.required && secrets[field.name] === undefined) throw new VaultError("bad_request", `${spec.label} needs "${field.label}".`)
    }
    return items.replaceSecrets(ctx, row.slug, secrets, principal)
  }
  return items.putItem(
    ctx,
    {
      slug: row.slug,
      kind,
      provider: row.provider,
      account: null,
      accountVerified: false,
      tags: intakeTags(row),
      ceiling: plan.template?.ceiling ?? spec.defaultCeiling,
      binding: req.binding,
      policy: plan.template?.policy ?? customItemPolicy(req.allowReads === true),
      injection: plan.injection,
      publicFields: req.publicFields,
      secretFields: secrets,
      description: null,
    },
    principal,
  )
}

export const intakes: IntakesService = {
  createForConnect(ctx, requester, input) {
    const req: IntakeRequest = {
      kind: "oauth-client",
      slug: input.slug,
      provider: input.provider,
      reason: input.reason,
      tags: input.tags,
    }
    return createIntake(ctx, requester, req, input.connect, { same: "reuse", different: input.fresh ? "supersede" : "refuse" })
  },
  outcome(ctx, id) {
    const row = getIntake(ctx, id)
    if (!row) return null
    const status = effectiveStatus(ctx, row)
    return { status, item: status === "completed" ? row.item : null, tags: intakeTags(row), url: intakeUrl(ctx, row.id), expiresAt: row.expires_at, completedAt: row.completed_at }
  },
}

export const intakeArea: Area = {
  name: "intake",
  get migrations() { return [...INTAKE_MIGRATIONS,workspaceRequestMigration,workspaceRequestWorkloadMigration] },
  get workspaceOps() { return credentialOps(workspaceIntakeOps) },
  // Keyed `saving:<intake>`: resolves a claim its submit never settled.
  async alarm(ctx, key) {
    if (!key.startsWith("saving:")) return
    const row = getIntake(ctx, key.slice("saving:".length))
    if (row?.status === "saving" && row.claimed_at !== null) ctx.schedule("intake", key, row.claimed_at + SAVING_STALE_MS)
  },
}
