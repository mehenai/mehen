// Adoption (`mehen adopt`): a machine uploads secrets it already holds,
// each secret field sealed to the vault in the CLI, into one batch; a person
// reviews the batch and stores it with one passkey. Each box is opened when
// it arrives and kept only under the workspace's root key, in this area's
// own tables, until approval stores the items or the batch ends. No value
// ever leaves this module: views carry a field's length, well-known prefix,
// the keyed fingerprint the stored item will carry and the uploaded box's
// digest, and the in-batch duplicate tag never leaves the DO.
import { z } from "zod"
import { ADOPTION_LEFT_OUT, ADOPTION_LIMITS, AdoptionApprove, AdoptionCreate, AdoptionIndex, AdoptionKeepOpen, AdoptionUpload, secretLikeness, KINDS, NAME_UNAVAILABLE, adoptionDigest, adoptionRepoints, adoptionSealContext, canonicalJson, customItemPolicy, getTemplate, isLeaseOnly, leaseOnlyAllowed, leaseOnlyBinding, leaseOnlyRefusal, NATURAL_INJECTION, nameRateRefusal, openText, publicFieldRefusal, secretPrefix, timingSafeEqualText, CredentialHomeSchema, type AdoptionAction, type AdoptionAffected, type AdoptionCompareResult, type AdoptionCompareView, type AdoptionCreated, type AdoptionDecisionInput, type AdoptionIndexed, type AdoptionIndexInput, type AdoptionKeptOpen, type AdoptionInventoryEntry, type WorkspaceAdoptionInventory, type AdoptionItemUploadInput, type AdoptionStatus, type AdoptionUploaded, type BindingInput, type CredentialHome, type Injection, type ItemKind, type Template, type WorkspaceAdoptionItemView, type WorkspaceAdoptionView, type WorkspacePendingAsk } from "@mehen/protocol"
import { ADOPTION_HOLDER_GONE } from "../../adoption-words.ts"
import { VaultError } from "../../http.ts"
import { sealPrivateKey, sealPublicJwk } from "../../seal-key.ts"
import { can, effectiveAccess, reach, type AccessPrincipal, type AccessState, type VariableSource } from "../access.ts"
import { blob, one, randomId, rows, type Area, type Principal, type VaultContext } from "../core.ts"
import { waitForStorageWrite } from "../storage-waits.ts"
import { devicePolicyState } from "./devices.ts"
import { assertProposedInjection } from "./intake.ts"
import { fingerprint, items, keepReplacedSecrets, parseOpInput, sealSecrets, stepUpDigest, storeReplacedSecrets, type SealedSecret } from "./items.ts"
import { assertNameBudget, checkedCredential, credentialAccessState, credentialAudit, credentialOps, prepareCredential, registerNameHolder, storeCredential, type CheckedCredential, type PreparedCredential, type WorkspaceItemInput } from "./items-workspace.ts"
import { registerWorkspacePendingProvider } from "./pending-workspace.ts"
import { loadProject, type ProjectRecord } from "./projects.ts"
import { projectVarSource, storeProjectVar } from "./projects-workspace.ts"
import { accessState, authorise, managedSetting, nameMiss, openAskCount, recordExposure, registerAccessChangeHook, registerOffboardingHook, registerOpenAskCounter, requireStepUp, setting, type WorkspaceInvocationContext } from "./workspace-runtime.ts"

const MIGRATION = `CREATE TABLE adoption_batches (
  id TEXT PRIMARY KEY, requester_member TEXT, requester_device TEXT NOT NULL,
  session TEXT, reason TEXT, status TEXT NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, decided_at INTEGER, decided_by TEXT
);
CREATE INDEX adoption_batches_member ON adoption_batches(requester_member, status);
CREATE INDEX adoption_batches_device ON adoption_batches(requester_device, status);
CREATE TABLE adoption_items (
  adoption TEXT NOT NULL, ref TEXT NOT NULL, item_id TEXT NOT NULL, device TEXT NOT NULL,
  slug TEXT NOT NULL, kind TEXT NOT NULL, provider TEXT, binding TEXT NOT NULL, injection TEXT,
  home TEXT NOT NULL, tags TEXT NOT NULL, public_fields TEXT NOT NULL, sources TEXT NOT NULL,
  repo TEXT, status TEXT NOT NULL, refusal TEXT, uploaded_at INTEGER NOT NULL,
  PRIMARY KEY (adoption, ref)
);
CREATE INDEX adoption_items_slug ON adoption_items(slug, status);
CREATE TABLE adoption_secrets (
  adoption TEXT NOT NULL, ref TEXT NOT NULL, field TEXT NOT NULL,
  root_version INTEGER NOT NULL, wrapped_dek BLOB NOT NULL, ciphertext BLOB NOT NULL,
  length INTEGER NOT NULL, prefix TEXT NOT NULL, fingerprint TEXT NOT NULL, fp_version INTEGER NOT NULL,
  box_digest TEXT NOT NULL, dup_tag TEXT NOT NULL,
  PRIMARY KEY (adoption, ref, field)
);
CREATE TABLE adoption_machines (adoption TEXT NOT NULL, device TEXT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (adoption, device));`

// Compare rows and their decisions, machines' plan indexes, and the daily
// compare count per holder. holder is `<adoption>/<ref>` for a staged row
// (holder_version NULL) or an item id; match is same, differs or unknown.
const RECONCILE_MIGRATION = `ALTER TABLE adoption_items ADD COLUMN compare INTEGER NOT NULL DEFAULT 0;
ALTER TABLE adoption_items ADD COLUMN holder TEXT;
ALTER TABLE adoption_items ADD COLUMN holder_version INTEGER;
ALTER TABLE adoption_items ADD COLUMN action TEXT;
ALTER TABLE adoption_items ADD COLUMN decided_slug TEXT;
ALTER TABLE adoption_items ADD COLUMN repoint TEXT;
ALTER TABLE adoption_secrets ADD COLUMN match TEXT;
ALTER TABLE adoption_secrets ADD COLUMN target_fingerprint TEXT;
CREATE TABLE adoption_indexes (
  device TEXT PRIMARY KEY, member TEXT, machine TEXT NOT NULL, items TEXT NOT NULL,
  uploaded_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE INDEX adoption_indexes_member ON adoption_indexes(member);
CREATE TABLE adoption_compare_counts (target TEXT NOT NULL, day INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (target, day));`

// requester_member is null for a team-owned machine's batch.
type BatchRow = { id: string; requester_member: string | null; requester_device: string; session: string | null; reason: string | null; status: string; created_at: number; expires_at: number; decided_at: number | null; decided_by: string | null }
// status: staged (waiting for review), created, excluded (left out at
// review), refused (at upload, with refusal), cancelled or expired.
type ItemRow = { adoption: string; ref: string; item_id: string; device: string; slug: string; kind: string; provider: string | null; binding: string; injection: string | null; home: string; tags: string; public_fields: string; sources: string; repo: string | null; status: string; refusal: string | null; uploaded_at: number; compare: number; holder: string | null; holder_version: number | null; action: string | null; decided_slug: string | null; repoint: string | null }
type SecretRow = { adoption: string; ref: string; field: string; root_version: number; wrapped_dek: ArrayBuffer; ciphertext: ArrayBuffer; length: number; prefix: string; fingerprint: string; fp_version: number; box_digest: string; dup_tag: string; match: string | null; target_fingerprint: string | null }
type Source = WorkspaceAdoptionItemView["sources"][number]

export const ADOPTION_CHANGED = "This batch changed; reload it."
const NO_SUCH = "No such adoption."
const NOT_OPEN = "This adoption batch is no longer open."
const BOX_MISMATCH = "The sealed field does not belong to this adoption."

const noSuch = () => new VaultError("not_found", NO_SUCH)
function stagedRef(adoption: string, ref: string, field: string) { return { type: "adoption-secret", id: `${adoption}/${ref}/${field}` } }

function batchRow(ctx: VaultContext, id: string): BatchRow {
  const row = one(ctx.sql.exec<BatchRow>("SELECT * FROM adoption_batches WHERE id=?", id))
  if (!row) throw noSuch()
  return row
}
function batchStatus(ctx: VaultContext, row: BatchRow): AdoptionStatus["status"] {
  return row.status === "open" && row.expires_at <= ctx.now() ? "expired" : row.status as AdoptionStatus["status"]
}
function assertOpen(ctx: VaultContext, row: BatchRow): void {
  if (batchStatus(ctx, row) !== "open") throw new VaultError("conflict", NOT_OPEN)
}
function itemRows(ctx: VaultContext, adoption: string, status?: string): ItemRow[] {
  return status === undefined ? rows(ctx.sql.exec<ItemRow>("SELECT * FROM adoption_items WHERE adoption=? ORDER BY ref", adoption)) : rows(ctx.sql.exec<ItemRow>("SELECT * FROM adoption_items WHERE adoption=? AND status=? ORDER BY ref", adoption, status))
}
function secretRows(ctx: VaultContext, adoption: string): SecretRow[] {
  return rows(ctx.sql.exec<SecretRow>("SELECT * FROM adoption_secrets WHERE adoption=? ORDER BY ref,field", adoption))
}
function homeOf(row: ItemRow): CredentialHome { return CredentialHomeSchema.parse(JSON.parse(row.home)) }

// The staged rows as the approval signs them: any upload, refresh or
// change between the review and the store shows here.
function stagedSnapshot(ctx: VaultContext, adoption: string): string {
  const staged = itemRows(ctx, adoption, "staged").map(({ status: _s, refusal: _r, ...row }) => row)
  const secrets = secretRows(ctx, adoption).map(({ wrapped_dek: _w, ciphertext: _c, ...row }) => row)
  return canonicalJson({ staged, secrets })
}

// A name is taken when an item has it, an open intake or connect holds it,
// or a staged row of an open batch does (other than this row itself). A
// compare row does not hold its name: the row or item it compares with does.
function stagedHolder(ctx: VaultContext, slug: string, now: number, except?: { adoption: string; ref: string }): ItemRow | null {
  return one(ctx.sql.exec<ItemRow>("SELECT i.* FROM adoption_items i JOIN adoption_batches b ON b.id=i.adoption WHERE i.slug=? AND i.status='staged' AND i.holder IS NULL AND b.status='open' AND b.expires_at>? AND NOT (i.adoption=? AND i.ref=?) LIMIT 1", slug, now, except?.adoption ?? "", except?.ref ?? ""))
}
function requestHolds(ctx: VaultContext, slug: string, now: number): boolean {
  return one(ctx.sql.exec("SELECT 1 FROM workspace_credential_requests WHERE slug=? AND status='open' AND expires_at>? LIMIT 1", slug, now)) !== null
}
function nameTaken(ctx: VaultContext, slug: string, own: { adoption: string; ref: string }): boolean {
  const now = ctx.now()
  return items.getItem(ctx, slug) !== null || requestHolds(ctx, slug, now) || stagedHolder(ctx, slug, now, own) !== null
}
registerNameHolder("adoptions", (ctx, slug, now) => stagedHolder(ctx, slug, now) !== null)
registerOpenAskCounter("adoptions", (ctx, device, now) => one(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM adoption_batches WHERE requester_device=? AND status='open' AND expires_at>?", device, now))?.count ?? 0)

// ---------------------------------------------------------------- who

type Machine = { deviceId: string; owner: { kind: "member" | "team"; id: string } }

// A machine's own key, live and not frozen; a workload never adopts.
function adoptingMachine(ctx: VaultContext, p: AccessPrincipal, invocation: WorkspaceInvocationContext): Machine {
  if (p.kind !== "device") throw new VaultError("forbidden", "Only a machine uploads an adoption.")
  if (p.workload !== undefined) throw new VaultError("forbidden", "A workload cannot adopt secrets. Run `mehen adopt` with the machine's own key.")
  authorise(ctx, invocation, { type: "device.read_self" }, { device: p.deviceId })
  const device = accessState(ctx).devices.find(d => d.id === p.deviceId)
  if (!device) throw new VaultError("not_found", "This machine is not enrolled in this vault.")
  return { deviceId: device.id, owner: device.owner }
}
function assertNotGuestMachine(state: AccessState, machine: Machine): void {
  const owner = machine.owner.kind === "member" ? state.members.find(m => m.id === machine.owner.id) : undefined
  if (owner?.standing.effectiveRole === "guest") throw new VaultError("forbidden", "A guest's machine cannot adopt secrets.", { next: { say: "Ask an owner or admin to add these credentials, or add each one with `mehen request`." } })
}
function assertNotManaged(ctx: VaultContext): void {
  if (managedSetting(ctx)) throw new VaultError("forbidden", "A managed workspace does not take adoptions; its platform adds credentials.")
}
function assertNotFrozen(ctx: VaultContext): void {
  if (setting(ctx, "frozen", false)) throw new VaultError("frozen", "This workspace is frozen.")
}
// The machine that started the batch, or another active machine of the
// same member (`mehen adopt submit --join`).
function machineMay(machine: Machine, batch: BatchRow): boolean {
  return batch.requester_device === machine.deviceId || machine.owner.kind === "member" && batch.requester_member === machine.owner.id
}
function machineBatch(ctx: VaultContext, machine: Machine, id: string): BatchRow {
  const batch = one(ctx.sql.exec<BatchRow>("SELECT * FROM adoption_batches WHERE id=?", id))
  if (!batch || !machineMay(machine, batch)) throw noSuch()
  return batch
}
// The person who asked, through any machine of theirs; for a team
// machine's batch, an owner or admin.
function personMay(state: AccessState, p: AccessPrincipal, batch: Pick<BatchRow, "requester_member">): boolean {
  if (p.kind !== "member") return false
  const member = state.members.find(m => m.id === p.memberId)
  if (!member || member.standing.effectiveRole === "guest") return false
  if (batch.requester_member !== null) return batch.requester_member === p.memberId
  return member.standing.effectiveRole === "owner" || member.standing.effectiveRole === "admin"
}
function personBatch(ctx: VaultContext, p: AccessPrincipal, id: string, invocation: WorkspaceInvocationContext): BatchRow {
  authorise(ctx, invocation, { type: "asks.read" }, {})
  const batch = one(ctx.sql.exec<BatchRow>("SELECT * FROM adoption_batches WHERE id=?", id))
  if (!batch || !personMay(credentialAccessState(ctx, invocation), p, batch)) throw noSuch()
  return batch
}

// ---------------------------------------------------------------- create

// Checked before the first await and again in the transaction that writes.
function assertRoomForBatch(ctx: VaultContext, machine: Machine, now: number): void {
  const open = machine.owner.kind === "member"
    ? one(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM adoption_batches WHERE requester_member=? AND status='open' AND expires_at>?", machine.owner.id, now))?.count ?? 0
    : one(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM adoption_batches WHERE requester_device=? AND status='open' AND expires_at>?", machine.deviceId, now))?.count ?? 0
  if (open >= ADOPTION_LIMITS.maxOpenPerMember) throw new VaultError("rate_limited", `There are already ${ADOPTION_LIMITS.maxOpenPerMember} open adoption batches.`, { next: { say: "Approve, cancel or let an open batch expire first, or upload into one with `mehen adopt submit --join <adp_id>`." } })
  if (openAskCount(ctx, machine.deviceId, now) >= 20) throw new VaultError("rate_limited", "This machine already has 20 open asks.")
}

async function createAdoption(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext): Promise<AdoptionCreated> {
  const raw = parseOpInput(AdoptionCreate, input)
  const machine = adoptingMachine(ctx, p, invocation)
  assertNotManaged(ctx)
  assertNotFrozen(ctx)
  assertNotGuestMachine(accessState(ctx), machine)
  const now = ctx.now()
  assertRoomForBatch(ctx, machine, now)
  const id = randomId("adp")
  const sealKey = await sealPublicJwk(ctx.env)
  return ctx.storage.transactionSync(() => {
    assertRoomForBatch(ctx, machine, now)
    ctx.sql.exec("INSERT INTO adoption_batches(id,requester_member,requester_device,session,reason,status,created_at,expires_at) VALUES (?,?,?,?,?,'open',?,?)", id, machine.owner.kind === "member" ? machine.owner.id : null, machine.deviceId, raw.session ?? null, raw.reason ?? null, now, now + ADOPTION_LIMITS.ttlMs)
    ctx.sql.exec("INSERT INTO adoption_machines(adoption,device,name) VALUES (?,?,?)", id, machine.deviceId, raw.machine)
    ctx.schedule("adoptions", id, now + ADOPTION_LIMITS.ttlMs)
    ctx.audit({ actor: `device:${machine.deviceId}`, action: "adoption.create", target: id, detail: { expectedItems: raw.expectedItems } })
    return { adoption: id, url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/b/${id}`, expiresAt: new Date(now + ADOPTION_LIMITS.ttlMs).toISOString(), sealKey, limits: ADOPTION_LIMITS }
  })
}

// ---------------------------------------------------------------- upload

type Shape = { template: Template | null; binding: BindingInput; injection: Injection | null }

// Every rule an item must meet before its boxes are opened, as the reason
// it is refused, or its effective binding and injection.
function itemShape(ctx: VaultContext, p: AccessPrincipal, state: AccessState, item: AdoptionItemUploadInput): Shape | string {
  const template = item.provider === null ? null : getTemplate(item.provider)
  if (item.provider !== null && !template) return "Unknown credential template."
  if (template && template.kind !== item.kind) return "The credential kind does not match its template."
  if (template && (item.binding !== null || item.injection !== null)) return "A template item sends no binding or injection of its own."
  if (!template && item.injection !== null && NATURAL_INJECTION[item.kind] === null) return `The relay never puts a ${KINDS[item.kind].label} into a request, so it takes no injection. Leave it out.`
  if (!template && item.injection !== null && (item.binding === null || isLeaseOnly(item.binding))) return "A custom credential sent with an injection needs a binding with the hosts it goes to."
  if (!template && (item.binding === null || isLeaseOnly(item.binding)) && !leaseOnlyAllowed(item.kind)) return leaseOnlyRefusal(item.kind)
  const spec = KINDS[item.kind]
  for (const name of Object.keys(item.sealed)) if (spec.fields.find(f => f.name === name)?.secret !== true) return `"${name}" is not a secret field of a ${spec.label}.`
  for (const [name, value] of Object.entries(item.publicFields)) {
    const refusal = publicFieldRefusal(item.kind, name, value)
    if (refusal) return refusal
  }
  for (const field of spec.fields) if (field.required && (field.secret ? item.sealed[field.name] === undefined : !item.publicFields[field.name])) return `${spec.label} needs "${field.label}".`
  try {
    if (!template && item.binding) {
      for (const host of item.binding.hosts) if (!/^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(host)) throw new VaultError("bad_request", `"${host}" is not a host the vault can bind to: use a hostname such as api.example.com or *.example.com.`)
    }
    if (!template && item.injection) assertProposedInjection(item.kind, item.injection)
  } catch (error) {
    if (error instanceof VaultError) return error.message
    throw error
  }
  const home = can(state, p, { type: "credential.create" }, { destinationHome: item.home }, ctx.now())
  if (!home.allowed) return home.error === "not_found" ? "No such home." : home.message
  return { template, binding: template?.binding ?? item.binding ?? leaseOnlyBinding(), injection: template ? template.injection : item.injection ?? NATURAL_INJECTION[item.kind] }
}

type Staged = { item: AdoptionItemUploadInput; shape: Shape; itemId: string; bytes: number; holder: Holder | null; secrets: { field: string; length: number; prefix: string; fingerprint: string; fpVersion: number; box: string; dupTag: string; match: Match | null; sealed: Awaited<ReturnType<VaultContext["sealField"]>> }[] }

async function keyedTag(ctx: VaultContext, text: string): Promise<string> {
  const mac = await crypto.subtle.sign("HMAC", await ctx.fingerprintKey(ctx.rootVersion), new TextEncoder().encode(text))
  let bin = ""
  for (const b of new Uint8Array(mac)) bin += String.fromCharCode(b)
  return btoa(bin)
}
// Keyed per batch, so equal values match only inside this batch.
function dupTag(ctx: VaultContext, adoption: string, value: string): Promise<string> {
  return keyedTag(ctx, `adopt/${adoption}\n${value}`)
}

// ---------------------------------------------------------------- compare

// The staged row or stored item already holding a compare row's name. A
// staged holder is `<adoption>/<ref>`; a stored one is the item's id.
type Holder = { type: "staged"; id: string; row: ItemRow } | { type: "stored"; id: string; item: CheckedCredential }
// Per secret field: the result, and for a stored holder this value keyed
// under the holder's id, the fingerprint a replace stores.
type Match = { match: AdoptionCompareResult; target: string | null }

const ONE_COMPARE = "Another row in this batch is already compared with this name."
const NAME_MOVED = "The name changed hands during the upload; send this row again."
const DAY_MS = 86_400_000

function stagedId(row: { adoption: string; ref: string }): string { return `${row.adoption}/${row.ref}` }

// First a staged row of an open batch this machine may use, then a stored
// item it can see. One it cannot see leaves the name unavailable exactly as
// any taken name, so a compare row gives no new signal that a name exists.
function holderFor(ctx: VaultContext, state: AccessState, machine: Machine, slug: string, own: { adoption: string; ref: string }): Holder | "free" | "unavailable" {
  const now = ctx.now()
  const staged = stagedHolder(ctx, slug, now, own)
  if (staged) return machineMay(machine, batchRow(ctx, staged.adoption)) ? { type: "staged", id: stagedId(staged), row: staged } : "unavailable"
  const stored = checkedCredential(ctx, slug)
  if (stored) return can(state, { kind: "device", deviceId: machine.deviceId }, { type: "item.read" }, { credential: stored.id }, now).allowed ? { type: "stored", id: stored.id, item: stored } : "unavailable"
  return requestHolds(ctx, slug, now) ? "unavailable" : "free"
}
function sameHolder(a: Holder | "free" | "unavailable", b: Holder | null): boolean {
  if (typeof a === "string" || b === null) return a === "free" && b === null
  return a.id === b.id && (a.type === "staged" || b.type === "stored" && a.item.version === b.item.version)
}
function comparesInBatch(ctx: VaultContext, adoption: string, holder: string, ref: string): number {
  return one(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM adoption_items WHERE adoption=? AND status='staged' AND holder=? AND ref<>?", adoption, holder, ref))?.count ?? 0
}

// Counts a compare with this holder today; past the day's cap (true) the
// result is unknown.
function countCompare(ctx: VaultContext, target: string, day: number): boolean {
  const capped = (one(ctx.sql.exec<{ count: number }>("SELECT count FROM adoption_compare_counts WHERE target=? AND day=?", target, day))?.count ?? 0) >= ADOPTION_LIMITS.maxComparesPerTargetPerDay
  ctx.sql.exec("INSERT INTO adoption_compare_counts(target,day,count) VALUES (?,?,1) ON CONFLICT(target,day) DO UPDATE SET count=count+1", target, day)
  return capped
}

async function stagedValues(ctx: VaultContext, adoption: string, ref: string): Promise<Record<string, string>> {
  const values: Record<string, string> = {}
  for (const s of rows(ctx.sql.exec<SecretRow>("SELECT * FROM adoption_secrets WHERE adoption=? AND ref=?", adoption, ref))) values[s.field] = new TextDecoder().decode(await ctx.openField(stagedRef(adoption, ref, s.field), { rootVersion: s.root_version, wrappedDek: blob(s.wrapped_dek), ciphertext: blob(s.ciphertext) }))
  return values
}

// The same work whatever the result: a staged holder's value and this one
// keyed alike under `adopt-compare/<holder>/<field>` and compared in
// constant time; a stored holder's fingerprint recomputed for this value
// under the root version the holder's was written with. A stored
// fingerprint of unknown version compares as unknown.
async function compareValues(ctx: VaultContext, holder: Holder, values: Record<string, string>): Promise<Map<string, Match>> {
  const out = new Map<string, Match>()
  if (holder.type === "staged") {
    const theirs = await stagedValues(ctx, holder.row.adoption, holder.row.ref)
    for (const [field, value] of Object.entries(values)) {
      const [mine, other] = await Promise.all([keyedTag(ctx, `adopt-compare/${holder.id}/${field}\n${value}`), keyedTag(ctx, `adopt-compare/${holder.id}/${field}\n${theirs[field] ?? ""}`)])
      out.set(field, { match: timingSafeEqualText(mine, other) && theirs[field] !== undefined ? "same" : "differs", target: null })
    }
    return out
  }
  const stored = new Map(rows(ctx.sql.exec<{ name: string; fingerprint: string; fp_version: number | null }>("SELECT name,fingerprint,fp_version FROM item_secrets WHERE item=?", holder.id)).map(s => [s.name, s]))
  for (const [field, value] of Object.entries(values)) {
    const s = stored.get(field)
    const target = await fingerprint(ctx, holder.id, value, ctx.rootVersion)
    const version = s?.fp_version ?? null
    const atVersion = version === null ? null : version === ctx.rootVersion ? target : await fingerprint(ctx, holder.id, value, version).catch(() => null)
    out.set(field, { match: s === undefined ? "differs" : atVersion === null ? "unknown" : timingSafeEqualText(atVersion, s.fingerprint) ? "same" : "differs", target })
  }
  return out
}

type ItemColumns = Omit<ItemRow, "adoption" | "ref" | "item_id" | "status" | "refusal" | "uploaded_at" | "compare" | "holder" | "holder_version" | "action" | "decided_slug" | "repoint">

// The row an upload stores. A refused row keeps neither its public fields,
// one of which may be the very secret it was refused for, nor its sources.
function itemColumns(item: AdoptionItemUploadInput, status: "staged" | "refused", shape: Shape | null, device: string): ItemColumns {
  const sources: Source[] = status === "staged" ? item.sources.map(s => ({ machine: device, path: s.path, variable: s.variable ?? null, pointer: s.pointer ?? null, stale: s.stale, ...(s.mtime ? { mtime: s.mtime } : {}) })) : []
  return { device, slug: item.slug, kind: item.kind, provider: item.provider, binding: canonicalJson(shape?.binding ?? item.binding ?? { hosts: [] }), injection: shape ? shape.injection === null ? null : canonicalJson(shape.injection) : null, home: canonicalJson(item.home), tags: canonicalJson(item.tags), public_fields: status === "staged" ? canonicalJson(item.publicFields) : "{}", sources: canonicalJson(sources), repo: item.repo === null ? null : canonicalJson(item.repo) }
}

// Checked before the first await and again in the transaction that writes.
function assertRoomForMachine(ctx: VaultContext, adoption: string, device: string): void {
  const joined = one(ctx.sql.exec("SELECT 1 FROM adoption_machines WHERE adoption=? AND device=?", adoption, device)) !== null
  const machines = one(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM adoption_machines WHERE adoption=?", adoption))?.count ?? 0
  if (!joined && machines >= ADOPTION_LIMITS.maxMachines) throw new VaultError("conflict", `This batch already has ${ADOPTION_LIMITS.maxMachines} machines.`)
}

async function uploadAdoption(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext): Promise<AdoptionUploaded> {
  const req = parseOpInput(AdoptionUpload.extend({ adoption: z.string().max(80) }), input)
  const machine = adoptingMachine(ctx, p, invocation)
  assertNotFrozen(ctx)
  const batch = machineBatch(ctx, machine, req.adoption)
  assertOpen(ctx, batch)
  const state = accessState(ctx)
  assertNotGuestMachine(state, machine)
  assertRoomForMachine(ctx, batch.id, machine.deviceId)
  const accepted: string[] = [], refused: { ref: string; reason: string }[] = []
  // Refusals kept on the batch, so `mehen adopt status` can list them.
  const kept: { item: AdoptionItemUploadInput; reason: string }[] = []
  const refuse = (item: AdoptionItemUploadInput, reason: string, keep = true) => { refused.push({ ref: item.ref, reason }); if (keep) kept.push({ item, reason }) }
  const refs = new Set<string>(), slugs = new Set<string>(), candidates: { item: AdoptionItemUploadInput; shape: Shape; holder: Holder | null }[] = []
  let budget: string | null = null
  for (const item of req.items) {
    if (refs.has(item.ref)) { refuse(item, "This row appears twice in the upload.", false); continue }
    refs.add(item.ref)
    const existing = one(ctx.sql.exec<ItemRow>("SELECT * FROM adoption_items WHERE adoption=? AND ref=?", batch.id, item.ref))
    if (existing && existing.status === "staged") {
      // A retried upload of the very same row and boxes is already in.
      const boxes = rows(ctx.sql.exec<{ field: string; box_digest: string }>("SELECT field,box_digest FROM adoption_secrets WHERE adoption=? AND ref=? ORDER BY field", batch.id, item.ref))
      const sent = await Promise.all(Object.entries(item.sealed).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(async ([field, box]) => ({ field, box_digest: await stepUpDigest(box) })))
      const { adoption: _a, ref: _r, item_id: _i, status: _s, refusal: _f, uploaded_at: _u, compare: _c, holder: _h, holder_version: _v, action: _d, decided_slug: _n, repoint: _p, ...stored } = existing
      const shape = itemShape(ctx, p, state, item)
      if (typeof shape !== "string" && canonicalJson(stored) === canonicalJson(itemColumns(item, "staged", shape, machine.deviceId)) && existing.compare === (item.compare === true ? 1 : 0) && canonicalJson(boxes) === canonicalJson(sent)) accepted.push(item.ref)
      else refuse(item, "This row is already in the batch with different contents.", false)
      continue
    }
    if (budget !== null) { refuse(item, budget); continue }
    const shape = itemShape(ctx, p, state, item)
    if (typeof shape === "string") { refuse(item, shape); continue }
    const allowed = nameMiss.check(ctx, p)
    if (!allowed.ok) {
      const refusal = nameRateRefusal(allowed.retryAfter)
      if (accepted.length === 0 && candidates.length === 0 && refused.length === 0) throw new VaultError(refusal.error, refusal.message, { retryAfter: refusal.retryAfter })
      budget = `${refusal.message} Retry after ${refusal.retryAfter} seconds.`
      refuse(item, budget)
      continue
    }
    const own = { adoption: batch.id, ref: item.ref }
    const found = slugs.has(item.slug) ? "unavailable" : item.compare === true ? holderFor(ctx, state, machine, item.slug, own) : nameTaken(ctx, item.slug, own) ? "unavailable" : "free"
    if (found === "unavailable") {
      nameMiss.record(ctx, p)
      refuse(item, NAME_UNAVAILABLE.message)
      continue
    }
    const holder = found === "free" ? null : found
    if (holder && comparesInBatch(ctx, batch.id, holder.id, item.ref) + candidates.filter(c => c.holder?.id === holder.id).length >= ADOPTION_LIMITS.maxComparesPerTarget) { refuse(item, ONE_COMPARE); continue }
    slugs.add(item.slug)
    candidates.push({ item, shape, holder })
  }
  const key = await sealPrivateKey(ctx.env)
  const staged: Staged[] = []
  for (const { item, shape, holder } of candidates) {
    const values: Record<string, string> = {}
    let reason: string | null = null
    for (const [field, box] of Object.entries(item.sealed)) {
      try { values[field] = await openText(key, box, adoptionSealContext(batch.id, item.ref, field)) } catch { reason = BOX_MISMATCH; break }
      if ((values[field] ?? "").length > 65_536) { reason = `"${field}" is too large.`; break }
      if (values[field] === "" && KINDS[item.kind].fields.find(f => f.name === field)?.required) { reason = `${KINDS[item.kind].label} needs "${field}".`; break }
    }
    if (reason !== null) { refuse(item, reason); continue }
    const itemId = randomId("itm"), fpVersion = ctx.rootVersion
    const matches = holder ? await compareValues(ctx, holder, values) : null
    const secrets = await Promise.all(Object.entries(values).map(async ([field, value]) => ({
      field,
      length: value.length,
      prefix: secretPrefix(value),
      fingerprint: await fingerprint(ctx, itemId, value, fpVersion),
      fpVersion,
      box: await stepUpDigest(item.sealed[field]),
      dupTag: await dupTag(ctx, batch.id, value),
      match: matches?.get(field) ?? null,
      sealed: await ctx.sealField(stagedRef(batch.id, item.ref, field), new TextEncoder().encode(value) as Uint8Array<ArrayBuffer>),
    })))
    staged.push({ item, shape, itemId, holder, secrets, bytes: Object.values(values).reduce((n, v) => n + v.length, 0) })
  }
  ctx.storage.transactionSync(() => {
    const live = batchRow(ctx, batch.id)
    assertOpen(ctx, live)
    assertRoomForMachine(ctx, batch.id, machine.deviceId)
    let count = one(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM adoption_items WHERE adoption=? AND status='staged'", batch.id))?.count ?? 0
    let bytes = one(ctx.sql.exec<{ bytes: number | null }>("SELECT sum(length) AS bytes FROM adoption_secrets WHERE adoption=?", batch.id))?.bytes ?? 0
    const now = ctx.now(), day = Math.floor(now / DAY_MS)
    ctx.sql.exec("DELETE FROM adoption_compare_counts WHERE day<?", day)
    const write = (item: AdoptionItemUploadInput, status: "staged" | "refused", itemId: string, shape: Shape | null, refusal: string | null, holder: Holder | null = null) => {
      const c = itemColumns(item, status, shape, machine.deviceId)
      ctx.sql.exec(`INSERT INTO adoption_items(adoption,ref,item_id,device,slug,kind,provider,binding,injection,home,tags,public_fields,sources,repo,status,refusal,uploaded_at,compare,holder,holder_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(adoption,ref) DO UPDATE SET item_id=excluded.item_id,device=excluded.device,slug=excluded.slug,kind=excluded.kind,provider=excluded.provider,binding=excluded.binding,injection=excluded.injection,home=excluded.home,tags=excluded.tags,public_fields=excluded.public_fields,sources=excluded.sources,repo=excluded.repo,status=excluded.status,refusal=excluded.refusal,uploaded_at=excluded.uploaded_at,compare=excluded.compare,holder=excluded.holder,holder_version=excluded.holder_version WHERE adoption_items.status='refused'`,
        batch.id, item.ref, itemId, c.device, c.slug, c.kind, c.provider, c.binding, c.injection, c.home, c.tags, c.public_fields, c.sources, c.repo, status, refusal, now, item.compare === true ? 1 : 0, holder?.id ?? null, holder?.type === "stored" ? holder.item.version : null)
    }
    for (const s of staged) {
      let reason: string | null = null
      const own = { adoption: batch.id, ref: s.item.ref }
      const found = s.holder || s.item.compare === true ? holderFor(ctx, state, machine, s.item.slug, own) : nameTaken(ctx, s.item.slug, own) ? "unavailable" : "free"
      if (one(ctx.sql.exec("SELECT 1 FROM adoption_items WHERE adoption=? AND ref=? AND status='staged'", batch.id, s.item.ref))) reason = "This row is already in the batch."
      else if (found === "unavailable") reason = NAME_UNAVAILABLE.message
      else if (!sameHolder(found, s.holder)) reason = NAME_MOVED
      else if (s.holder && comparesInBatch(ctx, batch.id, s.holder.id, s.item.ref) >= ADOPTION_LIMITS.maxComparesPerTarget) reason = ONE_COMPARE
      else if (count >= ADOPTION_LIMITS.maxItems) reason = `This batch is full: at most ${ADOPTION_LIMITS.maxItems} credentials.`
      else if (bytes + s.bytes > ADOPTION_LIMITS.maxStagedBytes) reason = `This batch holds as much as it can: at most ${ADOPTION_LIMITS.maxStagedBytes} characters of secrets.`
      if (reason !== null) { refuse(s.item, reason); continue }
      write(s.item, "staged", s.itemId, s.shape, null, s.holder)
      let capped = false
      if (s.holder) {
        capped = countCompare(ctx, s.holder.id, day)
        if (s.holder.type === "stored") credentialAudit(ctx, p, s.holder.item, "adoption.compare", "allowed", { adoption: batch.id, ref: s.item.ref })
        else ctx.audit({ actor: `device:${machine.deviceId}`, action: "adoption.compare", target: s.holder.id, detail: { adoption: batch.id, ref: s.item.ref } })
      }
      for (const secret of s.secrets) ctx.sql.exec("INSERT INTO adoption_secrets(adoption,ref,field,root_version,wrapped_dek,ciphertext,length,prefix,fingerprint,fp_version,box_digest,dup_tag,match,target_fingerprint) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch.id, s.item.ref, secret.field, secret.sealed.rootVersion, secret.sealed.wrappedDek, secret.sealed.ciphertext, secret.length, secret.prefix, secret.fingerprint, secret.fpVersion, secret.box, secret.dupTag, secret.match === null ? null : capped ? "unknown" : secret.match.match, secret.match?.target ?? null)
      count++
      bytes += s.bytes
      accepted.push(s.item.ref)
    }
    // At most maxItems refusals are kept per batch; past that a refusal is
    // only answered, though a row already kept may still be rewritten.
    let keptRefusals = one(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM adoption_items WHERE adoption=? AND status='refused'", batch.id))?.count ?? 0
    for (const { item, reason } of kept) {
      const known = one(ctx.sql.exec("SELECT 1 FROM adoption_items WHERE adoption=? AND ref=?", batch.id, item.ref)) !== null
      if (!known && keptRefusals >= ADOPTION_LIMITS.maxItems) continue
      write(item, "refused", "", null, reason)
      if (!known) keptRefusals++
    }
    ctx.sql.exec("INSERT OR IGNORE INTO adoption_machines(adoption,device,name) VALUES (?,?,?)", batch.id, machine.deviceId, devicePolicyState(ctx, machine.deviceId)?.name ?? machine.deviceId)
    ctx.audit({ actor: `device:${machine.deviceId}`, action: "adoption.upload", target: batch.id, detail: { accepted: accepted.length, refused: refused.length } })
  })
  return { adoption: batch.id, accepted, refused }
}

// ---------------------------------------------------------------- status

function machinesOf(ctx: VaultContext, adoption: string): AdoptionStatus["machines"] {
  return rows(ctx.sql.exec<{ device: string; name: string; items: number }>("SELECT m.device,m.name,(SELECT count(*) FROM adoption_items i WHERE i.adoption=m.adoption AND i.device=m.device AND i.status IN ('staged','created','mapped','replaced')) AS items FROM adoption_machines m WHERE m.adoption=? ORDER BY m.rowid", adoption))
}

// An open batch also names its staged rows, so another machine joining it
// leaves out a name already there instead of spending the name budget.
function statusOf(ctx: VaultContext, batch: BatchRow): AdoptionStatus {
  const all = itemRows(ctx, batch.id)
  const status = batchStatus(ctx, batch)
  const machines = machinesOf(ctx, batch.id)
  const outcome = (status: string) => all.filter(i => i.status === status).map(i => ({ ref: i.ref, slug: i.decided_slug ?? i.slug }))
  const created = outcome("created"), mapped = outcome("mapped"), replaced = outcome("replaced")
  const refused = all.filter(i => i.status === "refused" || i.status === "excluded").map(i => ({ ref: i.ref, reason: i.status === "excluded" ? ADOPTION_LEFT_OUT : i.refusal ?? "" }))
  const names = new Map(machines.map(m => [m.device, m.name]))
  const staged = status === "open" ? all.filter(i => i.status === "staged").map(i => ({ ref: i.ref, slug: i.slug, machine: names.get(i.device) ?? i.device })) : null
  return { adoption: batch.id, status, expiresAt: new Date(batch.expires_at).toISOString(), machines, ...(created.length ? { created } : {}), ...(mapped.length ? { mapped } : {}), ...(replaced.length ? { replaced } : {}), ...(refused.length ? { refused } : {}), ...(staged ? { staged } : {}) }
}

async function adoptionStatus(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext): Promise<AdoptionStatus> {
  const { adoption, wait, waitMs } = parseOpInput(z.object({ adoption: z.string().max(80), wait: z.boolean().optional(), waitMs: z.number().int().min(0).max(30000).optional() }), input)
  const deadline = ctx.now() + (waitMs ?? (wait ? 30000 : 0))
  for (;;) {
    const machine = adoptingMachine(ctx, p, invocation)
    const batch = machineBatch(ctx, machine, adoption)
    const now = ctx.now()
    if (batchStatus(ctx, batch) !== "open" || now >= deadline) return statusOf(ctx, batch)
    await waitForStorageWrite(ctx.storage, Math.min(deadline, batch.expires_at) - now)
  }
}

// ---------------------------------------------------------------- ending

function clearRefusedFields(ctx: VaultContext, adoption: string): void {
  ctx.sql.exec("UPDATE adoption_items SET public_fields='{}' WHERE adoption=? AND status='refused' AND public_fields<>'{}'", adoption)
}

// Ends an open batch: its staged rows end with it and its staged secrets
// are erased in the same transaction.
function endBatch(ctx: VaultContext, batch: BatchRow, status: "cancelled" | "expired", actor: string, reason: string): void {
  ctx.sql.exec("UPDATE adoption_batches SET status=?,decided_at=? WHERE id=? AND status='open'", status, ctx.now(), batch.id)
  ctx.sql.exec("UPDATE adoption_items SET status=? WHERE adoption=? AND status='staged'", status, batch.id)
  clearRefusedFields(ctx, batch.id)
  ctx.sql.exec("DELETE FROM adoption_secrets WHERE adoption=?", batch.id)
  ctx.unschedule("adoptions", batch.id)
  ctx.audit({ actor, action: status === "expired" ? "adoption.expire" : "adoption.cancel", target: batch.id, detail: { reason } })
}

function cancelAdoption(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext): Record<string, never> {
  const { adoption } = parseOpInput(z.object({ adoption: z.string().max(80) }), input)
  return ctx.storage.transactionSync(() => {
    const batch = p.kind === "device" ? machineBatch(ctx, adoptingMachine(ctx, p, invocation), adoption) : personBatch(ctx, p, adoption, invocation)
    assertOpen(ctx, batch)
    endBatch(ctx, batch, "cancelled", p.kind === "device" ? `device:${p.deviceId}` : `member:${p.memberId}`, p.kind === "device" ? "machine" : "person")
    return {}
  })
}

const KEPT_LONGEST = "This batch is already kept open as long as it can be."
const EXPIRY_MOVED = "This batch's expiry has changed; reload it."

// A person keeps a batch open keepOpenMs longer, up to maxLifeMs from its
// creation. The expiry the page showed must still be the batch's, so a
// repeated click extends it once.
function keepOpenAdoption(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext): AdoptionKeptOpen {
  const req = parseOpInput(AdoptionKeepOpen.extend({ adoption: z.string().max(80) }), input)
  assertNotFrozen(ctx)
  return ctx.storage.transactionSync(() => {
    const batch = personBatch(ctx, p, req.adoption, invocation)
    assertOpen(ctx, batch)
    const longest = batch.created_at + ADOPTION_LIMITS.maxLifeMs
    if (Date.parse(req.expiresAt) !== batch.expires_at) throw new VaultError("conflict", EXPIRY_MOVED)
    if (batch.expires_at >= longest) throw new VaultError("conflict", KEPT_LONGEST)
    const expiresAt = Math.min(batch.expires_at + ADOPTION_LIMITS.keepOpenMs, longest)
    ctx.sql.exec("UPDATE adoption_batches SET expires_at=? WHERE id=? AND status='open'", expiresAt, batch.id)
    ctx.schedule("adoptions", batch.id, expiresAt)
    ctx.audit({ actor: p.kind === "member" ? `member:${p.memberId}` : `device:${p.deviceId}`, action: "adoption.keep_open", target: batch.id, detail: { from: batch.expires_at, to: expiresAt } })
    return { adoption: batch.id, expiresAt: new Date(expiresAt).toISOString(), maxExpiresAt: new Date(longest).toISOString() }
  })
}

function endOpenBatches(ctx: VaultContext, where: string, value: string, reason: string): void {
  for (const batch of rows(ctx.sql.exec<BatchRow>(`SELECT * FROM adoption_batches WHERE status='open' AND ${where}`, value))) endBatch(ctx, batch, "cancelled", "system", reason)
}
registerOffboardingHook("adoptions", (ctx, snapshot) => {
  endOpenBatches(ctx, "requester_member=?", snapshot.member, "member_removed")
  ctx.sql.exec("DELETE FROM adoption_indexes WHERE member=?", snapshot.member)
  for (const device of snapshot.devices) {
    endOpenBatches(ctx, "id IN (SELECT adoption FROM adoption_machines WHERE device=?)", device, "member_removed")
    ctx.sql.exec("DELETE FROM adoption_indexes WHERE device=?", device)
  }
})
// A revoked machine's uploads end their batch; a member who can no longer
// act, or who becomes a guest, ends theirs.
const OWNER_ENDINGS = new Set(["suspend", "remove", "leave"])
registerAccessChangeHook("adoptions", (ctx, member, reason, target) => {
  if (reason === "revoke" && target.device) {
    endOpenBatches(ctx, "id IN (SELECT adoption FROM adoption_machines WHERE device=?)", target.device, "device_revoked")
    ctx.sql.exec("DELETE FROM adoption_indexes WHERE device=?", target.device)
  }
  else if (OWNER_ENDINGS.has(reason) && member !== null) endOpenBatches(ctx, "requester_member=?", member, "owner_inactive")
  else if (reason === "role" && target.role === "guest" && member !== null) endOpenBatches(ctx, "requester_member=?", member, "owner_guest")
})

// ---------------------------------------------------------------- view

function homesFor(ctx: VaultContext, state: AccessState, p: AccessPrincipal): CredentialHome[] {
  const candidates: CredentialHome[] = [{ kind: "workspace" }, ...state.projects.map(project => ({ kind: "project" as const, project: project.id })), ...(p.kind === "member" ? [{ kind: "member" as const, member: p.memberId }] : [])]
  return candidates.filter(home => can(state, p, { type: "credential.adopt" }, { destinationHome: home }, ctx.now()).allowed)
}

const NAME_GONE = "This name is no longer available."

// The first rule approving this row into `home` would fail for this person.
// A compare row's name is its holder's; what it may do with it is decided.
function approvalProblem(ctx: VaultContext, state: AccessState, p: AccessPrincipal, row: ItemRow, home: CredentialHome): string | null {
  if (!can(state, p, { type: "credential.adopt" }, { destinationHome: home }, ctx.now()).allowed) return "You cannot add credentials to this home; choose another."
  if (row.holder === null && nameTaken(ctx, row.slug, { adoption: row.adoption, ref: row.ref })) return NAME_GONE
  return null
}

// Kinds whose values are often short or chosen by a person: a result for
// them is shown only to a reviewer who may rotate or reveal the stored
// holder, never against a staged one.
const LOW_ENTROPY = new Set(["password-login", "basic-auth", "smtp-imap", "totp", "generic"])

function itemById(ctx: VaultContext, id: string): CheckedCredential | null {
  const slug = one(ctx.sql.exec<{ slug: string }>("SELECT slug FROM items WHERE id=?", id))?.slug
  return slug === undefined ? null : checkedCredential(ctx, slug)
}
// A staged holder that still holds its name: its row staged in a batch
// still open.
function waitingHolder(ctx: VaultContext, holder: string): ItemRow | null {
  const [adoption, ref] = holder.split("/")
  return one(ctx.sql.exec<ItemRow>("SELECT i.* FROM adoption_items i JOIN adoption_batches b ON b.id=i.adoption WHERE i.adoption=? AND i.ref=? AND i.status='staged' AND b.status='open' AND b.expires_at>?", adoption ?? "", ref ?? "", ctx.now()))
}
// The holder a compare row was compared with, as its row records it.
function rowHolder(ctx: VaultContext, row: ItemRow): Holder | null {
  if (row.holder === null) return null
  if (row.holder_version === null) {
    const held = waitingHolder(ctx, row.holder)
    return held ? { type: "staged", id: row.holder, row: held } : null
  }
  const item = itemById(ctx, row.holder)
  return item ? { type: "stored", id: item.id, item } : null
}

function mayRotate(ctx: VaultContext, state: AccessState, p: AccessPrincipal, item: CheckedCredential): boolean {
  return can(state, p, { type: "credential.rotate" }, { credential: item.id }, ctx.now()).allowed
}
// A replace changes the value every protected environment that references
// the holder runs with, so it needs the right to change those environments.
// The refusal names no project, which this reviewer may not see.
const PROTECTED_REFUSAL = "A protected environment uses this credential; only someone who may change protected environments there can replace its value."
function protectedRefusal(ctx: VaultContext, state: AccessState, p: AccessPrincipal, item: CheckedCredential): string | null {
  for (const project of state.projects) {
    if (!project.environments.some(env => env.protected && env.references.some(r => r.item === item.id))) continue
    if (p.kind !== "member" || !effectiveAccess(state, { kind: "member", id: p.memberId }, project.id, ctx.now()).editProtected) return PROTECTED_REFUSAL
  }
  return null
}
function mayReplace(ctx: VaultContext, state: AccessState, p: AccessPrincipal, item: CheckedCredential): boolean {
  return mayRotate(ctx, state, p, item) && protectedRefusal(ctx, state, p, item) === null
}
function resultsShown(ctx: VaultContext, state: AccessState, p: AccessPrincipal, row: ItemRow, holder: Holder): boolean {
  const kind = holder.type === "stored" ? holder.item.kind : holder.row.kind
  if (!LOW_ENTROPY.has(row.kind) && !LOW_ENTROPY.has(kind)) return true
  return holder.type === "stored" && (mayRotate(ctx, state, p, holder.item) || can(state, p, { type: "credential.reveal" }, { credential: holder.id }, ctx.now()).allowed)
}

// What replacing a stored holder would reach, by name only.
function affectedBy(ctx: VaultContext, state: AccessState, p: AccessPrincipal, item: CheckedCredential): AdoptionAffected {
  const now = ctx.now()
  const references = state.projects.filter(project => can(state, p, { type: "project.read" }, { project: project.id }, now).allowed).flatMap(project => project.environments.flatMap(env => env.references.filter(r => r.item === item.id).map(r => ({ project: project.slug, env: env.name, variable: r.variable }))))
  // Only from batches this reviewer may see, as the inventory lists them.
  const machines = [...new Set(rows(ctx.sql.exec<{ name: string; requester_member: string | null }>("SELECT m.name,b.requester_member FROM adoption_items i JOIN adoption_machines m ON m.adoption=i.adoption AND m.device=i.device JOIN adoption_batches b ON b.id=i.adoption WHERE (i.status='created' AND i.item_id=?) OR (i.status IN ('mapped','replaced') AND i.holder=?) ORDER BY m.name", item.id, item.id)).filter(m => personMay(state, p, m)).map(m => m.name))]
  const leasingDevices = one(ctx.sql.exec<{ count: number }>("SELECT count(DISTINCT device) AS count FROM exposures WHERE item=? AND version=? AND source='leased' AND device IS NOT NULL", item.id, item.version))?.count ?? 0
  const connections = rows(ctx.sql.exec<{ connection: string }>("SELECT connection FROM credential_dependencies WHERE client=?", item.id)).flatMap(edge => {
    const connection = itemById(ctx, edge.connection)
    return connection && can(state, p, { type: "item.read" }, { credential: connection.id }, now).allowed ? [connection.slug] : []
  }).sort()
  return { references: references.sort((a, b) => canonicalJson(a) < canonicalJson(b) ? -1 : 1), machines, leasingDevices, connections }
}

// A compare row's holder and per-field result for this reviewer, or null
// when the row has no holder or the reviewer cannot see it. `fingerprint`
// is what a replace stores: for a stored holder the value keyed under the
// holder's id, only for a reviewer who may replace it; for a staged holder
// the row's own, under the item id it is stored as.
function holderVisible(ctx: VaultContext, state: AccessState, p: AccessPrincipal, holder: Holder): boolean {
  return holder.type === "stored" ? can(state, p, { type: "item.read" }, { credential: holder.id }, ctx.now()).allowed : personMay(state, p, batchRow(ctx, holder.row.adoption))
}
function compareView(ctx: VaultContext, state: AccessState, p: AccessPrincipal, row: ItemRow, own: SecretRow[], names: Map<string, string>): AdoptionCompareView | null {
  const holder = rowHolder(ctx, row)
  if (!holder || !holderVisible(ctx, state, p, holder)) return null
  const shown = resultsShown(ctx, state, p, row, holder)
  const fields = own.map(s => ({ name: s.field, result: shown ? (s.match ?? "unknown") as AdoptionCompareResult : "unknown" as const, fingerprint: !shown ? null : holder.type === "staged" ? s.fingerprint : mayReplace(ctx, state, p, holder.item) ? s.target_fingerprint : null }))
  if (holder.type === "staged") {
    const held = rows(ctx.sql.exec<SecretRow>("SELECT * FROM adoption_secrets WHERE adoption=? AND ref=? ORDER BY field", holder.row.adoption, holder.row.ref))
    const heldNames = holder.row.adoption === row.adoption ? names : new Map(machinesOf(ctx, holder.row.adoption).map(m => [m.device, m.name]))
    return { holder: { type: "staged", id: holder.id, slug: holder.row.slug, kind: holder.row.kind as ItemKind, version: null, secrets: held.map(s => ({ name: s.field, length: s.length, prefix: s.prefix })), sources: (JSON.parse(holder.row.sources) as Source[]).map(s => ({ ...s, machine: heldNames.get(s.machine) ?? s.machine })) }, fields }
  }
  const item = holder.item
  const times = one(ctx.sql.exec<{ rotated_at: number | null; last_used_at: number | null }>("SELECT rotated_at,last_used_at FROM items WHERE id=?", item.id))
  const iso = (ms: number | null | undefined) => ms === null || ms === undefined ? null : new Date(ms).toISOString()
  const secrets = items.secretFieldMetadata(ctx, item).filter(s => s.set).map(s => ({ name: s.name, length: s.length, prefix: s.prefix }))
  return { holder: { type: "stored", id: item.id, slug: item.slug, kind: item.kind, version: row.holder_version ?? item.version, secrets, rotatedAt: iso(times?.rotated_at), lastUsedAt: iso(times?.last_used_at) }, fields, affected: affectedBy(ctx, state, p, item) }
}

function itemViews(ctx: VaultContext, state: AccessState, p: AccessPrincipal, batch: BatchRow, list: ItemRow[]): WorkspaceAdoptionItemView[] {
  const secrets = secretRows(ctx, batch.id)
  const names = new Map(machinesOf(ctx, batch.id).map(m => [m.device, m.name]))
  const homesAllowed = homesFor(ctx, state, p)
  return list.map(row => {
    const kind = row.kind as ItemKind
    const template = row.provider === null ? null : getTemplate(row.provider)
    const own = secrets.filter(s => s.ref === row.ref)
    const tags = new Set(own.map(s => s.dup_tag))
    // A compare row's equality is its compare view's alone, under that view's gate.
    const sameValueAs = row.compare === 1 ? [] : [...new Set(secrets.filter(s => s.ref !== row.ref && tags.has(s.dup_tag)).map(s => s.ref))].filter(ref => list.some(r => r.ref === ref && r.compare !== 1)).sort()
    const home = homeOf(row)
    const compare = row.compare === 1 ? compareView(ctx, state, p, row, own, names) : null
    const problem = row.status === "staged" ? approvalProblem(ctx, state, p, row, home) ?? (row.holder !== null && compare === null ? ADOPTION_HOLDER_GONE : null) : null
    return {
      ref: row.ref,
      slug: row.slug,
      kind,
      provider: row.provider,
      providerName: template?.displayName ?? null,
      binding: { value: JSON.parse(row.binding) as BindingInput, verified: template !== null },
      injection: { value: row.injection === null ? null : JSON.parse(row.injection) as Injection, verified: template !== null },
      home,
      homesAllowed,
      tags: (JSON.parse(row.tags) as string[]).sort(),
      publicFields: JSON.parse(row.public_fields) as Record<string, string>,
      secrets: own.map(s => ({ name: s.field, length: s.length, prefix: s.prefix, fingerprint: s.fingerprint, box: s.box_digest })),
      sources: (JSON.parse(row.sources) as Source[]).map(s => ({ ...s, machine: names.get(s.machine) ?? s.machine })),
      sameValueAs,
      repo: row.repo === null ? null : JSON.parse(row.repo) as { remote: string | null; env: string | null },
      problem,
      compare,
    }
  })
}

function viewOf(ctx: VaultContext, p: AccessPrincipal, batch: BatchRow, invocation: WorkspaceInvocationContext): WorkspaceAdoptionView {
  const state = credentialAccessState(ctx, invocation)
  const status = batchStatus(ctx, batch)
  const list = itemRows(ctx, batch.id).filter(row => status === "open" ? row.status === "staged" : row.status !== "refused")
  const names = new Map(machinesOf(ctx, batch.id).map(m => [m.device, m.name]))
  return { adoption: batch.id, status, expiresAt: new Date(batch.expires_at).toISOString(), requestedBy: { device: batch.requester_device, deviceName: names.get(batch.requester_device) ?? devicePolicyState(ctx, batch.requester_device)?.name ?? batch.requester_device, session: batch.session }, machines: machinesOf(ctx, batch.id), items: itemViews(ctx, state, p, batch, list), maxExpiresAt: new Date(batch.created_at + ADOPTION_LIMITS.maxLifeMs).toISOString() }
}

// A root key rotated since upload leaves fingerprints under the old key;
// they are recomputed before the view, so what a person signs is what the
// stored item will carry. A compare row's value keyed under a stored
// holder's id is recomputed with them; its result is not.
async function refreshFingerprints(ctx: VaultContext, adoption: string): Promise<void> {
  const stale = rows(ctx.sql.exec<SecretRow>("SELECT * FROM adoption_secrets WHERE adoption=? AND fp_version<>?", adoption, ctx.rootVersion))
  if (stale.length === 0) return
  const fresh = await Promise.all(stale.map(async s => {
    const row = one(ctx.sql.exec<{ item_id: string; holder: string | null; holder_version: number | null }>("SELECT item_id,holder,holder_version FROM adoption_items WHERE adoption=? AND ref=?", adoption, s.ref))
    const value = new TextDecoder().decode(await ctx.openField(stagedRef(adoption, s.ref, s.field), { rootVersion: s.root_version, wrappedDek: blob(s.wrapped_dek), ciphertext: blob(s.ciphertext) }))
    const target = row?.holder && row.holder_version !== null ? await fingerprint(ctx, row.holder, value, ctx.rootVersion) : null
    return { s, fingerprint: await fingerprint(ctx, row?.item_id ?? "", value, ctx.rootVersion), dupTag: await dupTag(ctx, adoption, value), target }
  }))
  ctx.storage.transactionSync(() => {
    for (const { s, fingerprint: fp, dupTag: tag, target } of fresh) ctx.sql.exec("UPDATE adoption_secrets SET fingerprint=?,fp_version=?,dup_tag=?,target_fingerprint=? WHERE adoption=? AND ref=? AND field=? AND fp_version=?", fp, ctx.rootVersion, tag, target, adoption, s.ref, s.field, s.fp_version)
  })
}

// The item a closed staged holder became once its batch was approved: the
// one it was stored as, the one it was mapped to or replaced, or the one
// of the row in its batch that replaced it. Only one the compare row's
// machine may read, as holderFor admits a stored holder at upload.
function approvedHolder(ctx: VaultContext, state: AccessState, row: ItemRow): CheckedCredential | null {
  const [adoption, ref] = (row.holder ?? "").split("/")
  const held = one(ctx.sql.exec<ItemRow>("SELECT * FROM adoption_items WHERE adoption=? AND ref=?", adoption ?? "", ref ?? ""))
  const id = held?.status === "created" ? held.item_id
    : held?.status === "replaced" || held?.status === "mapped" && held.holder_version !== null ? held.holder
    : held?.status === "mapped" ? one(ctx.sql.exec<{ item_id: string }>("SELECT item_id FROM adoption_items WHERE adoption=? AND holder=? AND status='created' AND action='replace'", held.adoption, stagedId(held)))?.item_id ?? null
    : null
  const item = id === null ? null : itemById(ctx, id)
  return item && can(state, { kind: "device", deviceId: row.device }, { type: "item.read" }, { credential: item.id }, ctx.now()).allowed ? item : null
}

// A compare row whose staged holder's batch has closed is compared again:
// once that batch was approved, with the item the holder became, as an
// upload compares with a stored item; once it was cancelled or expired, or
// the holder was left out or became nothing this row's machine may read,
// with nothing, so the row is stored as an ordinary one. A row of the batch
// already compared with that item keeps it: this row is then bound to
// nothing, so one holder is never compared twice in a batch.
async function rebindClosedHolders(ctx: VaultContext, p: AccessPrincipal, adoption: string): Promise<void> {
  const closed = itemRows(ctx, adoption, "staged").filter(row => row.holder !== null && row.holder_version === null && waitingHolder(ctx, row.holder) === null)
  if (closed.length === 0) return
  const state = accessState(ctx)
  const rebound = await Promise.all(closed.map(async row => {
    const item = approvedHolder(ctx, state, row)
    const matches = item ? await compareValues(ctx, { type: "stored", id: item.id, item }, await stagedValues(ctx, adoption, row.ref)) : null
    return { row, item, matches }
  }))
  ctx.storage.transactionSync(() => {
    const day = Math.floor(ctx.now() / DAY_MS), live = accessState(ctx)
    for (const rebind of rebound) {
      const { row } = rebind
      const item = rebind.item && approvedHolder(ctx, live, row)?.id === rebind.item.id && comparesInBatch(ctx, adoption, rebind.item.id, row.ref) < ADOPTION_LIMITS.maxComparesPerTarget ? rebind.item : null
      const matches = item ? rebind.matches : null
      if (ctx.sql.exec("UPDATE adoption_items SET holder=?,holder_version=? WHERE adoption=? AND ref=? AND status='staged' AND holder=? AND holder_version IS NULL", item?.id ?? null, item?.version ?? null, adoption, row.ref, row.holder).rowsWritten === 0) continue
      const capped = item ? countCompare(ctx, item.id, day) : false
      if (item) credentialAudit(ctx, p, item, "adoption.compare", "allowed", { adoption, ref: row.ref })
      for (const field of rows(ctx.sql.exec<{ field: string }>("SELECT field FROM adoption_secrets WHERE adoption=? AND ref=?", adoption, row.ref))) {
        const match = matches?.get(field.field) ?? null
        ctx.sql.exec("UPDATE adoption_secrets SET match=?,target_fingerprint=? WHERE adoption=? AND ref=? AND field=?", match === null ? null : capped ? "unknown" : match.match, match?.target ?? null, adoption, row.ref, field.field)
      }
    }
  })
}

async function viewAdoption(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext): Promise<WorkspaceAdoptionView> {
  const { adoption } = parseOpInput(z.object({ adoption: z.string().max(80) }), input)
  const batch = personBatch(ctx, p, adoption, invocation)
  if (batchStatus(ctx, batch) === "open") {
    await refreshFingerprints(ctx, adoption)
    await rebindClosedHolders(ctx, p, adoption)
  }
  return viewOf(ctx, p, personBatch(ctx, p, adoption, invocation), invocation)
}

// ---------------------------------------------------------------- approve

function decisionsFor(staged: ItemRow[], decisions: readonly AdoptionDecisionInput[]): Map<string, AdoptionDecisionInput> {
  const byRef = new Map(decisions.map(d => [d.ref, d]))
  if (byRef.size !== decisions.length || decisions.length !== staged.length || staged.some(row => !byRef.has(row.ref))) throw new VaultError("bad_request", "Every row in the batch needs exactly one decision.", { next: { say: ADOPTION_CHANGED } })
  return byRef
}

function itemInput(row: ItemRow, home: CredentialHome, secrets: Record<string, string>): WorkspaceItemInput {
  const kind = row.kind as ItemKind
  const template = row.provider === null ? null : getTemplate(row.provider)
  return { slug: row.slug, kind, provider: row.provider, account: null, accountVerified: false, tags: JSON.parse(row.tags) as string[], ceiling: template?.ceiling ?? KINDS[kind].defaultCeiling, binding: JSON.parse(row.binding) as BindingInput, policy: template?.policy ?? customItemPolicy(false), injection: row.injection === null ? null : JSON.parse(row.injection) as Injection, publicFields: JSON.parse(row.public_fields) as Record<string, string>, secretFields: secrets, description: null, home }
}

function refusedApproval(refused: { ref: string; reason: string }[]): VaultError {
  return new VaultError("conflict", refused.length === 1 ? "One credential in this batch cannot be stored, so nothing was stored." : `${refused.length} credentials in this batch cannot be stored, so nothing was stored.`, { refused, next: { say: "Untick those rows or choose another home for them, then approve again." } })
}

// A rename's name is tested as an ordinary create tests one: within the
// name budget, each taken name a miss, answered as any unavailable name.
function assertRenamesFree(ctx: VaultContext, p: AccessPrincipal, included: ItemRow[], byRef: Map<string, AdoptionDecisionInput>): void {
  let taken = false
  for (const row of included) {
    const decision = byRef.get(row.ref) as AdoptionDecisionInput
    if (decision.action !== "rename") continue
    assertNameBudget(ctx, p)
    if (!nameTaken(ctx, decision.slug as string, { adoption: row.adoption, ref: row.ref })) continue
    nameMiss.record(ctx, p)
    taken = true
  }
  if (taken) throw new VaultError(NAME_UNAVAILABLE.error, NAME_UNAVAILABLE.message)
}

function approvalRefusals(ctx: VaultContext, p: AccessPrincipal, invocation: WorkspaceInvocationContext, included: ItemRow[], byRef: Map<string, AdoptionDecisionInput>): { ref: string; reason: string }[] {
  const state = credentialAccessState(ctx, invocation)
  const renames = included.flatMap(row => byRef.get(row.ref)?.action === "rename" ? [byRef.get(row.ref)!.slug!] : [])
  return included.flatMap(row => {
    const decision = byRef.get(row.ref) as AdoptionDecisionInput
    const reason = approvalProblem(ctx, state, p, row, decision.home) ?? actionProblem(ctx, state, p, row, decision, included, renames)
    return reason === null ? [] : [{ ref: row.ref, reason }]
  })
}

const UNDECIDED = "This row was sent to be compared, so it needs a decision: store it, keep the vault's value, replace it or keep both under another name."
const NAME_HELD = "This name is already held: keep the vault's value, replace it or keep both under another name."
const NOTHING_HELD = "Nothing else holds this name, so this row can only be stored."
const HOLDER_LEFT_OUT = "The row this one was compared with is left out; store that row too, or keep both under another name."
const OTHER_BATCH = "The row this one was compared with waits in another batch; approve that batch first, or keep both under another name."
const NOT_ROTATABLE = "You cannot change this credential's value."
const OTHER_KIND = "Only a credential of the same kind can replace this one."
const RENAMED_ALIKE = "Two rows are kept under this name; choose another for one of them."
const NOT_REPOINTABLE = "You cannot point one of these variables at the new credential."
const PROTECTED_REPOINT = "One of these variables is in a protected environment; only someone who may change protected environments there can point it at the new credential."

// A row's action as decided. A store-only row with none is stored, as
// before actions existed; a compare row, which only a CLI that compares
// sends and the page always decides, is undecided (null) without one.
function actionOf(row: ItemRow, decision: AdoptionDecisionInput): AdoptionAction | null {
  return decision.action ?? (row.compare === 1 ? null : "store")
}

type Repoint = { project: ProjectRecord; env: string; variable: string; field: string; after: VariableSource }

// A rename's repoint, each variable bound to the renamed item as
// projects.setVar binds it, with the rights var.set asks for there; the
// approval's passkey stands in for setVar's own. The item does not exist
// until approval, so it is judged as the credential it will be. A refusal
// names no project or variable this reviewer may not see.
function repoints(ctx: VaultContext, state: AccessState, p: AccessPrincipal, row: ItemRow, decision: AdoptionDecisionInput): (Repoint | string)[] {
  const now = ctx.now()
  const renamed = { id: row.item_id, slug: decision.slug, home: decision.home, tags: JSON.parse(row.tags) as string[] }
  const judged: AccessState = { ...state, credentials: [...state.credentials.filter(c => c.id !== renamed.id), renamed] }
  return (decision.repoint ?? []).map(r => {
    const project = state.projects.find(x => x.id === r.project) ?? state.projects.find(x => x.slug === r.project)
    const record = project ? loadProject(ctx, project.id) : null
    const env = project?.environments.find(e => e.name === r.env)
    if (!project || !record || !env || !can(state, p, { type: "project.read" }, { project: project.id }, now).allowed) return NOT_REPOINTABLE
    const before = projectVarSource(ctx, record, r.env, r.variable)
    // setVar's field when none is named: the kind's primary.
    const kept = KINDS[row.kind as ItemKind].primary
    if (kept === null) return NOT_REPOINTABLE
    const after: VariableSource = { kind: "item", item: renamed.id, field: kept }
    if (can(judged, p, { type: "var.set", before, after }, { project: project.id, environment: r.env, variable: r.variable }, now).allowed) return { project: record, env: r.env, variable: r.variable, field: kept, after }
    if (env.protected && p.kind === "member" && !effectiveAccess(state, { kind: "member", id: p.memberId }, project.id, now).editProtected) return PROTECTED_REPOINT
    return NOT_REPOINTABLE
  })
}

// A repoint moves a variable off the holder, where the view shows it; one
// bound elsewhere since the view was built, or moved by another row of the
// approval (`moved`), means the batch changed.
function assertRepointsOnHolder(ctx: VaultContext, state: AccessState, row: ItemRow, decision: AdoptionDecisionInput, moved: Set<string>): void {
  const holder = rowHolder(ctx, row)
  const held = holder === null ? null : holder.type === "stored" ? holder.id : holder.row.item_id
  for (const r of decision.repoint ?? []) {
    const project = state.projects.find(x => x.id === r.project) ?? state.projects.find(x => x.slug === r.project)
    const record = project ? loadProject(ctx, project.id) : null
    const source = record ? projectVarSource(ctx, record, r.env, r.variable) : null
    const key = `${record?.id ?? r.project}\n${r.env}\n${r.variable}`
    if (held === null || source?.kind !== "item" || source.item !== held || moved.has(key)) throw new VaultError("conflict", ADOPTION_CHANGED)
    moved.add(key)
  }
}

// The first rule this row's action would fail; its home and name for a
// store are approvalProblem's.
function actionProblem(ctx: VaultContext, state: AccessState, p: AccessPrincipal, row: ItemRow, decision: AdoptionDecisionInput, included: ItemRow[], renames: string[]): string | null {
  const action = actionOf(row, decision)
  if (action === null) return UNDECIDED
  if (row.holder === null) return action === "store" ? null : NOTHING_HELD
  const holder = rowHolder(ctx, row)
  if (!holder) return ADOPTION_HOLDER_GONE
  // A holder the view does not show is never mapped or replaced blind.
  if (action !== "store" && action !== "rename" && !holderVisible(ctx, state, p, holder)) return ADOPTION_HOLDER_GONE
  if (action === "store") return NAME_HELD
  if (action === "rename") {
    const slug = decision.slug as string
    if (renames.filter(r => r === slug).length > 1) return RENAMED_ALIKE
    return repoints(ctx, state, p, row, decision).find(r => typeof r === "string") as string | undefined ?? null
  }
  if (holder.type === "staged") {
    if (holder.row.adoption !== row.adoption) return OTHER_BATCH
    if (action === "map") return included.some(r => r.ref === holder.row.ref) ? null : HOLDER_LEFT_OUT
    if (row.kind !== holder.row.kind) return OTHER_KIND
    return items.getItem(ctx, row.slug) !== null ? NAME_GONE : null
  }
  if (action === "map") return null
  if (row.kind !== holder.item.kind) return OTHER_KIND
  if (!mayRotate(ctx, state, p, holder.item)) return NOT_ROTATABLE
  return protectedRefusal(ctx, state, p, holder.item)
}

// One passkey over the whole batch, re-checked for every home it stores into.
function requireBatchStepUp(ctx: VaultContext, invocation: WorkspaceInvocationContext, expected: { type: "adoption.approve"; adoption: string; digest: string; repoints: number }, homes: CredentialHome[]): void {
  for (const home of new Map(homes.map(h => [canonicalJson(h), h])).values()) requireStepUp(ctx, authorise(ctx, invocation, { type: "credential.adopt" }, { destinationHome: home }), expected, invocation)
}

const DECIDED = new Set(["created", "mapped", "replaced", "excluded"])
function sameOutcome(ctx: VaultContext, batch: BatchRow, decisions: readonly AdoptionDecisionInput[]): boolean {
  const decided = itemRows(ctx, batch.id).filter(row => DECIDED.has(row.status))
  const byRef = new Map(decisions.map(d => [d.ref, d]))
  return byRef.size === decisions.length && decided.length === decisions.length && decided.every(row => {
    const d = byRef.get(row.ref)
    if (d === undefined || d.include !== (row.status !== "excluded")) return false
    return !d.include || canonicalJson(d.home) === canonicalJson(homeOf(row)) && (d.action ?? null) === row.action && (d.slug ?? null) === row.decided_slug && canonicalJson(d.repoint ?? null) === (row.repoint ?? "null")
  })
}

type Prepared = { row: ItemRow; action: AdoptionAction; outcome: "created" | "mapped" | "replaced"; credential?: PreparedCredential; replace?: { holder: CheckedCredential; sealed: SealedSecret[] } }

async function approveAdoption(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext): Promise<AdoptionStatus> {
  const req = parseOpInput(AdoptionApprove.extend({ adoption: z.string().max(80) }), input)
  if (p.kind !== "member") throw new VaultError("forbidden", "Only a person approves an adoption.")
  const batch = personBatch(ctx, p, req.adoption, invocation)
  // The same decisions again, once stored, answer what was stored.
  if (batch.status === "approved" && sameOutcome(ctx, batch, req.decisions)) return statusOf(ctx, batch)
  assertOpen(ctx, batch)
  await rebindClosedHolders(ctx, p, batch.id)
  const staged = itemRows(ctx, batch.id, "staged")
  const byRef = decisionsFor(staged, req.decisions)
  const included = staged.filter(row => byRef.get(row.ref)?.include)
  if (included.length === 0) throw new VaultError("bad_request", "Tick at least one credential to store, or cancel the batch.")
  const homes = included.map(row => (byRef.get(row.ref) as AdoptionDecisionInput).home)
  const auditRefusal = (refused: number) => ctx.audit({ actor: `member:${p.memberId}`, action: "adoption.refused", target: batch.id, detail: { included: included.length, refused } })
  assertRenamesFree(ctx, p, included, byRef)
  const early = approvalRefusals(ctx, p, invocation, included, byRef)
  if (early.length > 0) { auditRefusal(early.length); throw refusedApproval(early) }
  if (secretRows(ctx, batch.id).some(s => s.fp_version !== ctx.rootVersion)) throw new VaultError("conflict", ADOPTION_CHANGED)
  const snapshot = stagedSnapshot(ctx, batch.id)
  const state = credentialAccessState(ctx, invocation)
  const digest = await adoptionDigest(batch.id, itemViews(ctx, state, p, batch, staged), req.decisions)
  const expected = { type: "adoption.approve" as const, adoption: batch.id, digest, repoints: adoptionRepoints(req.decisions) }
  const signed = invocation.auth.kind === "account" ? invocation.auth.stepUp : undefined
  if (signed?.type === "adoption.approve" && signed.adoption === batch.id && signed.digest !== digest) throw new VaultError("conflict", ADOPTION_CHANGED)
  requireBatchStepUp(ctx, invocation, expected, homes)
  const secrets = secretRows(ctx, batch.id)
  const actions = new Map(included.map(row => [row.ref, actionOf(row, byRef.get(row.ref) as AdoptionDecisionInput) as AdoptionAction]))
  // A staged holder whose compare row replaces it is mapped to that row.
  const outvoted = new Set(included.flatMap(row => actions.get(row.ref) === "replace" && row.holder_version === null && row.holder !== null ? [row.holder] : []))
  const prepared: Prepared[] = []
  for (const row of included) {
    const decision = byRef.get(row.ref) as AdoptionDecisionInput
    const action = actions.get(row.ref) as AdoptionAction
    if (action === "map" || outvoted.has(stagedId(row))) { prepared.push({ row, action, outcome: "mapped" }); continue }
    const own = secrets.filter(s => s.ref === row.ref)
    const values: Record<string, string> = {}
    for (const s of own) values[s.field] = new TextDecoder().decode(await ctx.openField(stagedRef(batch.id, row.ref, s.field), { rootVersion: s.root_version, wrappedDek: blob(s.wrapped_dek), ciphertext: blob(s.ciphertext) }))
    const holder = rowHolder(ctx, row)
    if (action === "replace" && holder?.type === "stored") {
      // A rotation of the holder, carrying exactly the fingerprints signed under its id.
      if (holder.item.version !== row.holder_version) throw new VaultError("conflict", ADOPTION_CHANGED)
      const sealed = await sealSecrets(ctx, holder.id, values)
      for (const s of own) if (s.target_fingerprint === null || sealed.find(c => c.name === s.field)?.fingerprint !== s.target_fingerprint) throw new VaultError("conflict", ADOPTION_CHANGED)
      prepared.push({ row, action, outcome: "replaced", replace: { holder: holder.item, sealed } })
      continue
    }
    const input = itemInput(row, decision.home, values)
    const credential = await prepareCredential(ctx, action === "rename" ? { ...input, slug: decision.slug as string } : input, null, row.item_id)
    // The stored item carries exactly the fingerprint that was signed.
    for (const s of own) if (credential.secrets.find(c => c.name === s.field)?.fingerprint !== s.fingerprint) throw new VaultError("conflict", ADOPTION_CHANGED)
    prepared.push({ row, action, outcome: "created", credential })
  }
  const session = invocation.auth.kind === "account" ? invocation.auth.session : null
  const actor: Principal = { kind: "member", member: p.memberId, role: state.members.find(m => m.id === p.memberId)?.standing.effectiveRole === "owner" ? "owner" : "member", stepUp: null }
  try {
    return ctx.storage.transactionSync(() => {
      const live = batchRow(ctx, batch.id)
      assertOpen(ctx, live)
      if (stagedSnapshot(ctx, batch.id) !== snapshot) throw new VaultError("conflict", ADOPTION_CHANGED)
      requireBatchStepUp(ctx, invocation, expected, homes)
      assertRenamesFree(ctx, p, included, byRef)
      const late = approvalRefusals(ctx, p, invocation, included, byRef)
      if (late.length > 0) throw refusedApproval(late)
      const current = credentialAccessState(ctx, invocation)
      const moved = new Set<string>()
      for (const { row, action } of prepared) if (action === "rename") assertRepointsOnHolder(ctx, current, row, byRef.get(row.ref) as AdoptionDecisionInput, moved)
      for (const { row, action, outcome, credential, replace } of prepared) {
        const decision = byRef.get(row.ref) as AdoptionDecisionInput
        if (credential) {
          // The access state before this row is stored, as var.set judged it.
          const before = action === "rename" ? credentialAccessState(ctx, invocation) : null
          const item = storeCredential(ctx, credential, p, "item.create", session)
          credentialAudit(ctx, p, item, "adoption.item", "allowed", { adoption: batch.id, ref: row.ref, action }, null, session)
          if (before) for (const r of repoints(ctx, before, p, row, decision)) {
            if (typeof r === "string") throw new VaultError("conflict", ADOPTION_CHANGED)
            storeProjectVar(ctx, invocation, p, r.project, { env: r.env, name: r.variable, item: item.slug }, r.field, r.after)
          }
        } else if (replace) {
          const live = checkedCredential(ctx, replace.holder.slug)
          if (!live || live.id !== replace.holder.id || live.version !== row.holder_version) throw new VaultError("conflict", ADOPTION_CHANGED)
          // The holder's current values are kept 30 days, restorable with a passkey.
          keepReplacedSecrets(ctx, live, "item.rotate", `member:${p.memberId}`)
          storeReplacedSecrets(ctx, live, replace.sealed, actor)
          const stored = checkedCredential(ctx, live.slug) as CheckedCredential
          recordExposure(ctx, { item: stored.id, version: stored.version, member: p.memberId, device: null, event: "adoption.replace", source: "entered", at: ctx.now() })
          credentialAudit(ctx, p, stored, "item.rotate", "allowed", { fields: replace.sealed.map(s => s.name).sort(), adoption: batch.id, ref: row.ref }, null, session)
          credentialAudit(ctx, p, stored, "adoption.item", "allowed", { adoption: batch.id, ref: row.ref, action }, null, session)
        } else if (row.holder_version !== null && row.holder !== null) {
          const holder = itemById(ctx, row.holder)
          if (holder) credentialAudit(ctx, p, holder, "adoption.item", "allowed", { adoption: batch.id, ref: row.ref, action }, null, session)
        } else ctx.audit({ actor: `member:${p.memberId}`, action: "adoption.item", target: batch.id, detail: { ref: row.ref, action, holder: row.holder ?? stagedId(row) } })
        ctx.sql.exec("UPDATE adoption_items SET status=?,home=?,action=?,decided_slug=?,repoint=? WHERE adoption=? AND ref=?", outcome, canonicalJson(decision.home), decision.action ?? null, decision.slug ?? null, decision.repoint === undefined ? null : canonicalJson(decision.repoint), batch.id, row.ref)
      }
      ctx.sql.exec("UPDATE adoption_items SET status='excluded' WHERE adoption=? AND status='staged'", batch.id)
      clearRefusedFields(ctx, batch.id)
      ctx.sql.exec("UPDATE adoption_batches SET status='approved',decided_at=?,decided_by=? WHERE id=?", ctx.now(), p.memberId, batch.id)
      ctx.sql.exec("DELETE FROM adoption_secrets WHERE adoption=?", batch.id)
      ctx.unschedule("adoptions", batch.id)
      ctx.audit({ actor: `member:${p.memberId}`, action: "adoption.approve", target: batch.id, detail: { created: prepared.filter(x => x.outcome === "created").length, mapped: prepared.filter(x => x.outcome === "mapped").length, replaced: prepared.filter(x => x.outcome === "replaced").length, excluded: staged.length - prepared.length } })
      return statusOf(ctx, batchRow(ctx, batch.id))
    })
  } catch (error) {
    // A refusal found in the transaction is audited once it has rolled back.
    if (error instanceof VaultError && error.extra.refused !== undefined) auditRefusal(error.extra.refused.length)
    throw error
  }
}

// ---------------------------------------------------------------- index

type IndexRow = { device: string; member: string | null; machine: string; items: string; uploaded_at: number; expires_at: number }
type IndexItem = AdoptionIndexInput["items"][number]

// Every free string in an index, so none that looks like a secret is kept.
function indexStrings(input: AdoptionIndexInput): { ref: string | null; value: string }[] {
  return [{ ref: null, value: input.machine }, ...input.items.flatMap(i => [i.slug, i.provider, i.project, ...i.sources.flatMap(s => [s.path, s.variable, s.pointer, ...s.stale]), ...i.uses.flatMap(u => [u.project, u.env, u.variable, u.field])].flatMap(value => typeof value === "string" ? [{ ref: i.ref, value }] : []))]
}

function purgeIndexes(ctx: VaultContext): void {
  ctx.sql.exec("DELETE FROM adoption_indexes WHERE expires_at<=?", ctx.now())
}

// A machine's whole plan, value-free, replacing its last one.
function indexAdoption(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext): AdoptionIndexed {
  const req = parseOpInput(AdoptionIndex, input)
  const machine = adoptingMachine(ctx, p, invocation)
  assertNotManaged(ctx)
  assertNotFrozen(ctx)
  assertNotGuestMachine(accessState(ctx), machine)
  for (const { ref, value } of indexStrings(req)) {
    const why = secretLikeness(value)
    if (why !== null) throw new VaultError("bad_request", `${ref === null ? "The machine name" : `A string in ${ref}`} looks like a secret (${why}), so the index was not kept.`)
  }
  const now = ctx.now(), expiresAt = now + ADOPTION_LIMITS.indexKeptMs
  ctx.storage.transactionSync(() => {
    purgeIndexes(ctx)
    ctx.sql.exec("INSERT INTO adoption_indexes(device,member,machine,items,uploaded_at,expires_at) VALUES (?,?,?,?,?,?) ON CONFLICT(device) DO UPDATE SET member=excluded.member,machine=excluded.machine,items=excluded.items,uploaded_at=excluded.uploaded_at,expires_at=excluded.expires_at", machine.deviceId, machine.owner.kind === "member" ? machine.owner.id : null, req.machine, canonicalJson(req.items), now, expiresAt)
    ctx.schedule("adoptions", `index:${machine.deviceId}`, expiresAt)
    ctx.audit({ actor: `device:${machine.deviceId}`, action: "adoption.index", target: machine.deviceId, detail: { items: req.items.length } })
  })
  return { machine: req.machine, items: req.items.length, expiresAt: new Date(expiresAt).toISOString() }
}

// The indexes a person may read: their own machines', and for an owner or
// admin a team machine's, as personMay admits batches.
function indexesFor(ctx: VaultContext, state: AccessState, p: AccessPrincipal): IndexRow[] {
  return rows(ctx.sql.exec<IndexRow>("SELECT * FROM adoption_indexes WHERE expires_at>? ORDER BY uploaded_at,device", ctx.now())).filter(row => personMay(state, p, { requester_member: row.member }))
}

function combined(fields: AdoptionCompareView["fields"]): AdoptionCompareResult {
  return fields.length > 0 && fields.every(f => f.result === "same") ? "same" : fields.some(f => f.result === "differs") ? "differs" : "unknown"
}

function inventoryAdoption(ctx: VaultContext, p: AccessPrincipal, _input: unknown, invocation: WorkspaceInvocationContext): WorkspaceAdoptionInventory {
  authorise(ctx, invocation, { type: "asks.read" }, {})
  const state = credentialAccessState(ctx, invocation), now = ctx.now()
  const bySlug = new Map<string, AdoptionInventoryEntry[]>()
  const add = (slug: string, entry: AdoptionInventoryEntry) => bySlug.set(slug, [...bySlug.get(slug) ?? [], entry])
  const batches = rows(ctx.sql.exec<BatchRow>("SELECT * FROM adoption_batches WHERE status IN ('open','approved') ORDER BY created_at,id")).filter(batch => personMay(state, p, batch) && (batch.status === "approved" || batch.expires_at > now))
  for (const batch of batches) {
    const names = new Map(machinesOf(ctx, batch.id).map(m => [m.device, m.name]))
    const secrets = secretRows(ctx, batch.id)
    for (const row of itemRows(ctx, batch.id)) {
      const sources = (JSON.parse(row.sources) as Source[]).map(s => ({ ...s, machine: names.get(s.machine) ?? s.machine }))
      const machine = names.get(row.device) ?? row.device
      if (batch.status === "open" && row.status === "staged") {
        const compare = row.compare === 1 ? compareView(ctx, state, p, row, secrets.filter(s => s.ref === row.ref), names) : null
        add(row.slug, { from: "staged", machine, adoption: batch.id, ref: row.ref, kind: row.kind as ItemKind, home: homeOf(row), sources, compare: compare === null ? null : combined(compare.fields) })
      } else if (row.status === "created" || row.status === "mapped" || row.status === "replaced") add(row.decided_slug ?? row.slug, { from: "approved", machine, adoption: batch.id, ref: row.ref, outcome: row.status, sources })
    }
  }
  const indexes = indexesFor(ctx, state, p)
  for (const index of indexes) for (const i of JSON.parse(index.items) as IndexItem[]) add(i.slug, { from: "plan", machine: index.machine, ref: i.ref, kind: i.kind, home: i.home, project: i.project, include: i.include, exists: i.exists, storeOnly: i.storeOnly, sources: i.sources.map(s => ({ machine: index.machine, path: s.path, variable: s.variable ?? null, pointer: s.pointer ?? null, stale: s.stale, ...(s.mtime ? { mtime: s.mtime } : {}) })), uses: i.uses })
  const visible = (slug: string) => {
    const item = checkedCredential(ctx, slug)
    return item && can(state, p, { type: "item.read" }, { credential: item.id }, now).allowed ? { id: item.id, kind: item.kind, home: item.home, version: item.version } : null
  }
  return {
    rows: [...bySlug.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([slug, entries]) => ({ slug, stored: visible(slug), entries })),
    indexes: indexes.map(i => ({ device: i.device, machine: i.machine, indexedAt: new Date(i.uploaded_at).toISOString(), expiresAt: new Date(i.expires_at).toISOString() })),
  }
}

// ---------------------------------------------------------------- pending

function adoptionPending(ctx: VaultContext, principal: AccessPrincipal, invocation: WorkspaceInvocationContext): WorkspacePendingAsk[] {
  if (principal.kind === "device" && principal.workload !== undefined) return []
  const state = credentialAccessState(ctx, invocation), now = ctx.now()
  const open = rows(ctx.sql.exec<BatchRow>("SELECT * FROM adoption_batches WHERE status='open' AND expires_at>? ORDER BY created_at,id", now))
  return open.flatMap(batch => {
    if (principal.kind === "device" ? batch.requester_device !== principal.deviceId : !personMay(state, principal, batch)) return []
    const device = state.devices.find(d => d.id === batch.requester_device)
    if (!device) return []
    const count = one(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM adoption_items WHERE adoption=? AND status='staged'", batch.id))?.count ?? 0
    const name = one(ctx.sql.exec<{ name: string }>("SELECT name FROM adoption_machines WHERE adoption=? AND device=?", batch.id, batch.requester_device))?.name ?? devicePolicyState(ctx, batch.requester_device)?.name ?? batch.requester_device
    return [{ workspace: invocation.workspace, owner: reach(state, device, now).owner, view: "detail" as const, detail: { kind: "adoption" as const, id: batch.id, title: count === 1 ? "Adopt 1 credential" : `Adopt ${count} credentials`, url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/b/${batch.id}`, expiresAt: new Date(batch.expires_at).toISOString(), requestedBy: { device: batch.requester_device, deviceName: name, session: batch.session }, item: null, items: count, ...(principal.kind === "member" ? { createdAt: new Date(batch.created_at).toISOString() } : {}) } }]
  })
}
registerWorkspacePendingProvider("adoptions", adoptionPending)

export const workspaceAdoptionOps = {
  "adoption.create": { auth: ["device"] as const, handler: createAdoption },
  "adoption.upload": { auth: ["device"] as const, handler: uploadAdoption },
  "adoption.status": { auth: ["device"] as const, handler: adoptionStatus },
  "adoption.cancel": { auth: ["account", "device"] as const, handler: cancelAdoption },
  "adoption.view": { auth: ["account"] as const, handler: viewAdoption },
  "adoption.approve": { auth: ["account"] as const, handler: approveAdoption },
  "adoption.keepOpen": { auth: ["account"] as const, handler: keepOpenAdoption },
  "adoption.index": { auth: ["device"] as const, handler: indexAdoption },
  "adoption.inventory": { auth: ["account"] as const, handler: inventoryAdoption },
}

export const adoptionsArea: Area = {
  name: "adoptions",
  migrations: [MIGRATION, RECONCILE_MIGRATION],
  get workspaceOps() { return credentialOps(workspaceAdoptionOps) },
  // Keyed by batch: an abandoned batch's staged secrets are erased once it
  // expires. Keyed `index:<device>`: a machine's index is dropped once kept
  // indexKeptMs.
  async alarm(ctx, key) {
    if (key.startsWith("index:")) { purgeIndexes(ctx); return }
    ctx.storage.transactionSync(() => {
      const batch = one(ctx.sql.exec<BatchRow>("SELECT * FROM adoption_batches WHERE id=?", key))
      if (!batch || batch.status !== "open") return
      if (batch.expires_at > ctx.now()) { ctx.schedule("adoptions", key, batch.expires_at); return }
      endBatch(ctx, batch, "expired", "system", "expired")
    })
  },
}
