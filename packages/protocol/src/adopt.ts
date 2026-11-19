// Adoption (`mehen adopt`): a machine reads secrets it already holds in its
// own files, seals each secret field to the vault in the CLI, and uploads
// them into one batch; a person reviews the batch and approves it with one
// passkey. The vault opens each box when it arrives and keeps it only under
// the workspace's root key until approval stores the items.

import { z } from "zod"
import { type BindingInput, BindingSchema, EnvName, type Injection, InjectionSchema, KindSchema, Slug, Tag, VarName } from "./api.ts"
import { sha256B64 } from "./bytes.ts"
import { canonicalJson } from "./canonical-json.ts"
import type { ItemKind } from "./kinds.ts"
import { IntakeSealedBoxSchema } from "./sealed-box.ts"
import { type CredentialHome, CredentialHomeSchema } from "./workspace.ts"

export const ADOPTION_ID = /^adp_[A-Za-z0-9_-]{1,60}$/
// One row of a batch; the plan, the review page and `adopt status` share it.
export const ADOPTION_REF = /^a[0-9a-z]{3,7}$/

// The `adopt/` prefix never collides with an intake's `intake/<intake>/<field>`,
// so a box sealed for a batch cannot fill an intake, nor the reverse.
export function adoptionSealContext(adoption: string, ref: string, field: string): string {
  return `adopt/${adoption}/${ref}/${field}`
}

// The reason the vault gives for a row a reviewer unticked; the CLI reads
// it to list that row as left out rather than refused.
export const ADOPTION_LEFT_OUT = "Left out at review."

export const ADOPTION_LIMITS = {
  // Per batch, every machine's uploads together, compare rows included.
  maxItems: 500,
  // Distinct devices uploading into one batch.
  maxMachines: 8,
  // One upload body, under the vault's 1 000 000 byte JSON limit.
  maxChunkBytes: 900_000,
  // The sum of plaintext lengths staged in one batch, compare rows included.
  maxStagedBytes: 8_000_000,
  maxOpenPerMember: 3,
  // An intake's default life.
  ttlMs: 86_400_000,
  // Compare rows naming one holder: per batch, and per workspace a day,
  // past which the result is unknown.
  maxComparesPerTarget: 1,
  maxComparesPerTargetPerDay: 10,
  // "Keep open 3 more days", up to maxLifeMs from the batch's creation.
  keepOpenMs: 3 * 86_400_000,
  maxLifeMs: 7 * 86_400_000,
  // How long a replaced value stays restorable.
  replacedKeptMs: 30 * 86_400_000,
  // A machine's index: how long the vault keeps it, and its items.
  indexKeptMs: 30 * 86_400_000,
  maxIndexItems: 2_000,
} as const

const AdoptionRef = z.string().regex(ADOPTION_REF)
const FieldName = z.string().max(64)

// POST /v1/adoptions (device) -> 201 AdoptionCreated
export const AdoptionCreate = z.strictObject({
  // Shown on the review page; the vault also records the device.
  machine: z.string().min(1).max(64),
  reason: z.string().min(1).max(500).optional(),
  session: z.string().max(120).optional(),
  expectedItems: z.number().int().min(1).max(ADOPTION_LIMITS.maxItems),
})
export type AdoptionCreateInput = z.infer<typeof AdoptionCreate>
export type AdoptionCreated = {
  adoption: string
  url: string
  expiresAt: string
  sealKey: { jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }; kid: string }
  limits: typeof ADOPTION_LIMITS
}

const SourceRef = z.strictObject({
  // The realpath as the CLI read it.
  path: z.string().min(1).max(1024),
  variable: VarName.optional(),
  // A JSON pointer, for settings files.
  pointer: z.string().max(512).optional(),
  stale: z.array(z.string().max(80)).max(4),
  // When the file last changed, as the CLI read it.
  mtime: z.iso.datetime().optional(),
})

// POST /v1/adoptions/:id/items (device) AdoptionUpload -> AdoptionUploaded.
// Each secret field is sealed with adoptionSealContext(adoption, ref, field).
// A template item sends binding and injection null; project homes name the
// project by its prj_ id. `compare`: the slug may already be staged or
// stored, and the vault compares this row's value with the holder's for
// the review page alone, answering exactly as for any other row; absent
// is false.
export const AdoptionItemUpload = z.strictObject({
  ref: AdoptionRef,
  slug: Slug,
  kind: KindSchema,
  provider: z.string().max(64).nullable(),
  binding: BindingSchema.nullable(),
  injection: InjectionSchema.nullable(),
  home: CredentialHomeSchema,
  tags: z.array(Tag).max(16),
  publicFields: z.record(FieldName, z.string().max(4096)),
  sealed: z.record(FieldName, IntakeSealedBoxSchema),
  sources: z.array(SourceRef).min(1).max(32),
  repo: z.strictObject({ remote: z.string().max(300).nullable(), env: EnvName.nullable() }).nullable(),
  compare: z.boolean().optional(),
})
export type AdoptionItemUploadInput = z.infer<typeof AdoptionItemUpload>
export const AdoptionUpload = z.strictObject({ items: z.array(AdoptionItemUpload).min(1).max(200) })
export type AdoptionUploadInput = z.infer<typeof AdoptionUpload>
export type AdoptionUploaded = { adoption: string; accepted: string[]; refused: { ref: string; reason: string }[] }

// A variable a plan item backs: the prj_ id, or the slug of a project the
// plan would create.
const AdoptionIndexUse = z.strictObject({ project: z.string().min(1).max(128), env: EnvName, variable: VarName, field: FieldName })

// POST /v1/adoptions/index (device): every item of this machine's plan,
// ticked, unticked, already in the vault or store-only, with where it was
// found and what it backs, for the inventory page. Built from the plan, so
// nothing in it is derived from a value. It replaces this machine's last
// index and is dropped after indexKeptMs.
export const AdoptionIndex = z.strictObject({
  machine: z.string().min(1).max(64),
  items: z.array(z.strictObject({
    ref: AdoptionRef,
    slug: Slug,
    kind: KindSchema,
    provider: z.string().max(64).nullable(),
    home: z.enum(["private", "workspace", "project"]),
    project: z.string().min(1).max(128).nullable(),
    include: z.boolean(),
    exists: z.boolean(),
    storeOnly: z.boolean(),
    sources: z.array(SourceRef).min(1).max(32),
    uses: z.array(AdoptionIndexUse).max(64),
  })).max(ADOPTION_LIMITS.maxIndexItems),
})
export type AdoptionIndexInput = z.infer<typeof AdoptionIndex>
export type AdoptionIndexed = { machine: string; items: number; expiresAt: string }

// GET /adoptions (member): every name this member's adoptions touch, from
// their open batches' rows, what their approved batches stored or mapped,
// and their machines' last indexes, value-free. `compare` is shown only
// where the batch view would show it, as one result over the row's fields.
export type AdoptionInventoryEntry =
  | { from: "staged"; machine: string; adoption: string; ref: string; kind: ItemKind; home: CredentialHome; sources: AdoptionSourceView[]; compare: AdoptionCompareResult | null }
  | { from: "approved"; machine: string; adoption: string; ref: string; outcome: "created" | "mapped" | "replaced"; sources: AdoptionSourceView[] }
  | { from: "plan"; machine: string; ref: string; kind: ItemKind; home: "private" | "workspace" | "project"; project: string | null; include: boolean; exists: boolean; storeOnly: boolean; sources: AdoptionSourceView[]; uses: { project: string; env: string; variable: string; field: string }[] }
export type AdoptionInventoryRow = {
  slug: string
  // The item under this name, when this member can see one.
  stored: { id: string; kind: ItemKind; home: CredentialHome; version: number } | null
  entries: AdoptionInventoryEntry[]
}
export type WorkspaceAdoptionInventory = {
  rows: AdoptionInventoryRow[]
  // This member's machines with an index, and when each was sent.
  indexes: { device: string; machine: string; indexedAt: string; expiresAt: string }[]
}

const AdoptionOutcome = z.strictObject({ ref: AdoptionRef, slug: Slug })

// GET /v1/adoptions/:id[?wait=1] (device). Strict, so no compare result
// reaches a machine before or after approval: `mapped` is both a value the
// vault already held and a differing one the reviewer kept the vault's
// for, so the outcome never says which. `created` holds a rename under its
// new slug. `mapped` and `replaced` are absent from a vault older than them.
export const AdoptionStatusSchema = z.strictObject({
  adoption: z.string(),
  status: z.enum(["open", "approved", "cancelled", "expired"]),
  expiresAt: z.iso.datetime(),
  machines: z.array(z.strictObject({ device: z.string(), name: z.string(), items: z.number().int().min(0) })),
  created: z.array(AdoptionOutcome).optional(),
  mapped: z.array(AdoptionOutcome).optional(),
  replaced: z.array(AdoptionOutcome).optional(),
  refused: z.array(z.strictObject({ ref: AdoptionRef, reason: z.string() })).optional(),
  // While open: every staged row's ref, slug and the machine that sent it.
  // Absent from a vault older than the field.
  staged: z.array(z.strictObject({ ref: AdoptionRef, slug: Slug, machine: z.string() })).optional(),
})
export type AdoptionStatus = z.infer<typeof AdoptionStatusSchema>

export const ADOPTION_COMPARE_RESULTS = ["same", "differs", "unknown"] as const
export type AdoptionCompareResult = (typeof ADOPTION_COMPARE_RESULTS)[number]

type AdoptionSourceView = { machine: string; path: string; variable: string | null; pointer: string | null; stale: string[]; mtime?: string | null }
type AdoptionHolderSecret = { name: string; length: number; prefix: string }

// The row or item already holding a compare row's name. A staged holder is
// `<adoption>/<ref>` with no version, since a staged row never changes; a
// stored one is the item by id, at the version the comparison was made.
export type AdoptionCompareHolder =
  | { type: "staged"; id: string; slug: string; kind: ItemKind; version: null; secrets: AdoptionHolderSecret[]; sources: AdoptionSourceView[] }
  | { type: "stored"; id: string; slug: string; kind: ItemKind; version: number; secrets: AdoptionHolderSecret[]; rotatedAt: string | null; lastUsedAt: string | null }

// For the review page only: no device-facing answer carries a result. Per
// secret field, whether this row's value is the holder's, and `fingerprint`,
// this row's value keyed as the holder's item would carry it, which a
// replace signs; null unless this reviewer may replace the holder.
// What replacing a stored holder would reach, by name only, among what
// the reviewer may see: the project variables that reference it, the
// machines whose adopted sources map to it, how many devices hold a lease
// of its current value, and the OAuth connections that depend on it.
export type AdoptionAffected = {
  references: { project: string; env: string; variable: string }[]
  machines: string[]
  leasingDevices: number
  connections: string[]
}
export type AdoptionCompareView = {
  holder: AdoptionCompareHolder
  fields: { name: string; result: AdoptionCompareResult; fingerprint: string | null }[]
  // For a stored holder; absent from a vault older than the field.
  affected?: AdoptionAffected
}

// GET /adoptions/:id (member). No value is ever in a view: per secret field
// its length, well-known prefix, the keyed fingerprint the stored item will
// carry, and `box`, the digest of the uploaded sealed box.
export type WorkspaceAdoptionItemView = {
  ref: string
  slug: string
  kind: ItemKind
  provider: string | null
  providerName: string | null
  // verified: the binding and injection come from a template.
  binding: { value: BindingInput; verified: boolean }
  injection: { value: Injection | null; verified: boolean }
  home: CredentialHome
  // The homes this member may choose.
  homesAllowed: CredentialHome[]
  tags: string[]
  publicFields: Record<string, string>
  secrets: { name: string; length: number; prefix: string; fingerprint: string; box: string }[]
  sources: AdoptionSourceView[]
  // Other refs in this batch with the same value.
  sameValueAs: string[]
  repo: { remote: string | null; env: string | null } | null
  // A rule this member's approval would fail, or null.
  problem: string | null
  // A compare row's holder and per-field result; null or absent for an
  // ordinary row.
  compare?: AdoptionCompareView | null
}
export type WorkspaceAdoptionView = {
  adoption: string
  status: AdoptionStatus["status"]
  expiresAt: string
  requestedBy: { device: string; deviceName: string; session: string | null }
  machines: AdoptionStatus["machines"]
  items: WorkspaceAdoptionItemView[]
  // The latest expiry keep-open can reach; absent from a vault older than it.
  maxExpiresAt?: string
}

// POST /adoptions/:id/keep-open (member, account only): keepOpenMs more,
// up to maxLifeMs from creation. `expiresAt` is the expiry the page shows,
// so a repeated click extends the batch once.
export const AdoptionKeepOpen = z.strictObject({ expiresAt: z.iso.datetime() })
export type AdoptionKeepOpenInput = z.infer<typeof AdoptionKeepOpen>
export type AdoptionKeptOpen = { adoption: string; expiresAt: string; maxExpiresAt: string }

// store: a new item (absent means store). For a compare row: map keeps the
// holder's value and this machine maps to it; replace rotates the holder to
// this row's value; rename stores this row as a new item named `slug`.
export const ADOPTION_ACTIONS = ["store", "map", "replace", "rename"] as const
export type AdoptionAction = (typeof ADOPTION_ACTIONS)[number]

// A project variable a rename points at the new item, for every machine.
const AdoptionRepoint = z.strictObject({ project: z.string().min(1).max(128), env: EnvName, variable: VarName })
const repointKey = (r: z.infer<typeof AdoptionRepoint>) => `${r.project}\n${r.env}\n${r.variable}`

// POST /adoptions/:id/approve (member) { decisions, stepUp }, step-up
// "adoption.approve". Every staged ref needs exactly one decision; an
// unknown or missing ref fails the whole approval.
export const AdoptionDecision = z
  .strictObject({
    ref: AdoptionRef,
    include: z.boolean(),
    home: CredentialHomeSchema,
    action: z.enum(ADOPTION_ACTIONS).optional(),
    slug: Slug.optional(),
    repoint: z.array(AdoptionRepoint).max(64).optional(),
  })
  .refine((d) => (d.action === "rename") === (d.slug !== undefined), { message: "A rename, and only a rename, names a slug.", path: ["slug"] })
  .refine((d) => d.repoint === undefined || d.action === "rename", { message: "Only a rename repoints variables.", path: ["repoint"] })
  .refine((d) => new Set((d.repoint ?? []).map(repointKey)).size === (d.repoint ?? []).length, { message: "Each variable is repointed once.", path: ["repoint"] })
export type AdoptionDecisionInput = z.infer<typeof AdoptionDecision>
export const AdoptionApprove = z.strictObject({ decisions: z.array(AdoptionDecision).min(1).max(ADOPTION_LIMITS.maxItems) })
export type AdoptionApproveInput = z.infer<typeof AdoptionApprove>

function byCodeUnit(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

// What the "adoption.approve" passkey signs, computed alike by the review
// page and the vault from the view and the decisions. An included row binds
// everything that is stored, the chosen home, and per secret field the
// keyed fingerprint (the exact value under the exact item id) and the
// uploaded box; an excluded row binds only its ref, so no row can be slipped
// in after review. `sources` and `sameValueAs` inform the decision but do
// not change what is stored, so they are not signed. A store decision
// signs exactly what it signed before actions existed, so a batch staged
// before them can still be approved. Any other action also binds the
// action and the holder by id and version; a rename the name it stores
// under and the variables it repoints; a replace the fingerprints under
// the holder's id. The compare result is not signed: it follows from the
// row and the holder's version.
export function adoptionDigestInput(adoption: string, items: readonly WorkspaceAdoptionItemView[], decisions: readonly AdoptionDecisionInput[]) {
  const byRef = new Map(decisions.map((d) => [d.ref, d]))
  return {
    adoption,
    items: [...items].sort((a, b) => byCodeUnit(a.ref, b.ref)).map((item) => {
      const decision = byRef.get(item.ref)
      if (!decision?.include) return { ref: item.ref, include: false }
      const secrets = [...item.secrets]
        .sort((a, b) => byCodeUnit(a.name, b.name))
        .map((s) => ({ name: s.name, length: s.length, prefix: s.prefix, fingerprint: s.fingerprint, box: s.box }))
      const stored = {
        ref: item.ref,
        include: true,
        slug: item.slug,
        kind: item.kind,
        provider: item.provider,
        binding: item.binding.value,
        injection: item.injection.value,
        home: decision.home,
        tags: [...item.tags].sort(byCodeUnit),
        publicFields: item.publicFields,
        secrets,
      }
      const action = decision.action ?? "store"
      if (action === "store") return stored
      const holder = item.compare?.holder ?? null
      const underHolder = new Map((item.compare?.fields ?? []).map((f) => [f.name, f.fingerprint]))
      return {
        ...stored,
        ...(action === "rename" ? { slug: decision.slug } : {}),
        ...(action === "replace" ? { secrets: secrets.map((s) => ({ ...s, fingerprint: underHolder.get(s.name) ?? null })) } : {}),
        action,
        target: holder === null ? null : { id: holder.id, version: holder.version },
        ...(action === "rename" ? { repoint: [...(decision.repoint ?? [])].sort((a, b) => byCodeUnit(repointKey(a), repointKey(b))).map((r) => ({ project: r.project, env: r.env, variable: r.variable })) } : {}),
      }
    }),
  }
}

// base64url(SHA-256(canonicalJson(adoptionDigestInput(...)))), as every step-up digest.
export function adoptionDigest(adoption: string, items: readonly WorkspaceAdoptionItemView[], decisions: readonly AdoptionDecisionInput[]): Promise<string> {
  return sha256B64(canonicalJson(adoptionDigestInput(adoption, items, decisions)))
}

// The project variables an approval points at renamed rows, counted from
// the included renames' decisions. The "adoption.approve" action carries
// it beside the digest, so the grace table can see a repoint, which on its
// own path is an item.update and always asks.
export function adoptionRepoints(decisions: readonly AdoptionDecisionInput[]): number {
  return decisions.reduce((n, d) => n + (d.include && d.action === "rename" ? (d.repoint?.length ?? 0) : 0), 0)
}
