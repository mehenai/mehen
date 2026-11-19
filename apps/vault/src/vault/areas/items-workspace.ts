// Credential storage and evaluator adapters. Prepared ciphertext is never
// authority: callers commit it only inside their final synchronous transaction.
import { z } from "zod"
import { CredentialHomeSchema, KINDS, isItemKind, modeAllowed, settingsPinnedVersion, NAME_UNAVAILABLE, canonicalJson, nameRateRefusal, type CredentialHome, type ItemPreviousVersion, type ItemUseContext, type WorkspaceItemDescription, type PrivateEvent, type CredentialCreationContext, type PushRecordView } from "@mehen/protocol"
import { Slug, KindSchema, Tag, type ItemConnection } from "@mehen/protocol/api"
import { VaultError } from "../../http.ts"
import type { AccessAction, AccessPrincipal, AccessState, AccessTarget } from "../access.ts"
import { can } from "../access.ts"
import { blob, one, rows, randomId, type VaultContext, type Area } from "../core.ts"
import {onCredentialRemoved} from "./projects-workspace.ts"
import { compatibleClientHome, isClientRejectedReason } from "./oauth-workspace.ts"
import { auditPrivateEvent } from "../audit.ts"
import { FILL_MANAGED_REFUSAL, refuseBrowserChangeUnlessOn, refuseFillUnlessOn } from "../fill-unavailable.ts"
import { managedPolicyView } from "../managed-platform.ts"
import type { ItemRecord, NewItem, OffboardingHook, WorkspaceItemsService } from "../services.ts"
import { ItemChange, assertBindingHosts, assertFillableKind, describeItem, fingerprint, items, keepReplacedSecrets, keptSecrets, parseOpInput, sealSecrets, stepUpDigest, secretRef, storeSecrets, validateNewItem } from "./items.ts"
import { devicePolicyState } from "./devices.ts"
import { PostureTerms, forgetPosture, machinePosture, personPosture, postureAction, resetPostureOnRehome } from "./postures-workspace.ts"
import { assertPushableChange, itemPushable, pushesOn } from "./push-allowance.ts"
import { latestPushes } from "./push-records.ts"
import { accessState, eligibilityState, authorise, managedSetting, nameMiss, recordExposure, registerAccessStateProvider, registerExposureProvider, registerOffboardingHook, requireStepUp, type WorkspaceInvocationContext } from "./workspace-runtime.ts"

export type CheckedCredential = ItemRecord & {
  home: CredentialHome
  dependencyRevision: number
}

export type WorkspaceItemInput = NewItem & {
  home: CredentialHome
}

export type PreparedCredential = {
  input: WorkspaceItemInput
  id: string
  expected: CheckedCredential | null
  secrets: Awaited<ReturnType<typeof sealSecrets>>
}

type HomeRow = { home_kind: string; home_id: string | null }
function storedHome(row: HomeRow): CredentialHome {
  if (!["member", "project", "workspace"].includes(row.home_kind) || row.home_kind !== "workspace" && !row.home_id)
    throw new Error("Invalid stored credential home")
  return row.home_kind === "member" ? { kind: "member", member: row.home_id ?? "" } : row.home_kind === "project" ? { kind: "project", project: row.home_id ?? "" } : { kind: "workspace" }
}

export function credentialHome(ctx: VaultContext, id: string): CredentialHome | null {
  const row = one(ctx.sql.exec<HomeRow>("SELECT home_kind, home_id FROM items WHERE id = ?", id))
  return row ? storedHome(row) : null
}

export function checkedCredential(ctx: VaultContext, slug: string): CheckedCredential | null {
  const item = items.getItem(ctx, slug)
  if (!item)
    return null
  const row = one(ctx.sql.exec<{
    dependency_revision: number
  }>("SELECT dependency_revision FROM items WHERE id = ?", item.id))
  return { ...item, home: credentialHome(ctx, item.id) as CredentialHome, dependencyRevision: row?.dependency_revision ?? 0 }
}

export function credentialAccessState(ctx: VaultContext, invocation?: WorkspaceInvocationContext): AccessState { return invocation?.auth.kind === "account" ? eligibilityState(ctx, invocation) : accessState(ctx); }

export function registerCredentialProvider(): void {
  // One read of the four fields the evaluator uses, not a whole credential each.
  registerAccessStateProvider("credentials", (ctx) => ({
    credentials: rows(ctx.sql.exec<HomeRow & { id: string; slug: string; kind: string; tags: string }>("SELECT id, slug, kind, tags, home_kind, home_id FROM items")).map((row) => {
      if (!isItemKind(row.kind)) throw new Error("corrupt item kind")
      return { id: row.id, slug: row.slug, home: storedHome(row), tags: JSON.parse(row.tags) as string[] }
    })
  }))
}

export function missingCredential(slug: string): VaultError {
  return new VaultError("not_found", `No credential called "${slug}".`, { next: { command: "mehen ls", say: `There is no credential called "${slug}"; list what exists with \`mehen ls\`, or ask for it with \`mehen request\`.` } })
}
// All device entry points use this before status, ceiling or OAuth inspection.
// item.use uses its own mode: lease-only machines cannot describe, but may lease.

export function visibleCredential(ctx: VaultContext, principal: AccessPrincipal, slug: string, use?: {
  context: ItemUseContext | null
  mode: "relay" | "placeholder" | "fill" | "lease"
}, invocation?: WorkspaceInvocationContext): CheckedCredential {
  if (invocation?.auth.kind === "account") authorise(ctx, invocation, { type: "asks.read" }, {}, ctx.now())
  const c = checkedCredential(ctx, slug)
  if (!c)
    throw missingCredential(slug)
  const action: AccessAction = use ? { type: "item.use", context: use.context } : { type: "item.read" }
  const target: AccessTarget = { credential: c.id, ...(use ? { mode: use.mode } : {}) }
  const decision = can(credentialAccessState(ctx, invocation), principal, action, target, ctx.now())
  if (!decision.allowed) {
    if (decision.error === "environment_refused" && use)
      throw new VaultError(decision.error, decision.message, decision.next ? { next: decision.next } : {})
    throw missingCredential(slug)
  }
  return c
}

export async function openCredentialSecrets(ctx: VaultContext, item: CheckedCredential): Promise<Record<string, string>> {
  const stored = rows(ctx.sql.exec<{
    name: string
    root_version: number
    wrapped_dek: ArrayBuffer
    ciphertext: ArrayBuffer
  }>("SELECT name,root_version,wrapped_dek,ciphertext FROM item_secrets WHERE item=?", item.id))
  const out: Record<string, string> = {}
  for (const field of stored)
    out[field.name] = new TextDecoder().decode(await ctx.openField(secretRef(item, field.name), { rootVersion: field.root_version, wrappedDek: blob(field.wrapped_dek), ciphertext: blob(field.ciphertext) }))
  return out
}

export function credentialChanged(): VaultError { return new VaultError("conflict", "The credential changed; review and try again.") }

export function assertCredentialCurrent(ctx: VaultContext, prepared: CheckedCredential): CheckedCredential {
  const current = checkedCredential(ctx, prepared.slug)
  if (!current || current.id !== prepared.id || current.version !== prepared.version || current.configRev !== prepared.configRev || current.dependencyRevision !== prepared.dependencyRevision || canonicalJson(current.home) !== canonicalJson(prepared.home))
    throw credentialChanged()
  return current
}

export function assertNameBudget(ctx: VaultContext, principal: AccessPrincipal): void {
  const budget = nameMiss.check(ctx, principal, ctx.now())
  if (!budget.ok) {
    const refusal = nameRateRefusal(budget.retryAfter)
    throw new VaultError(refusal.error, refusal.message, { retryAfter: refusal.retryAfter })
  }
}

export function unavailableName(ctx: VaultContext, principal: AccessPrincipal): never {
  nameMiss.record(ctx, principal, ctx.now())
  throw new VaultError(NAME_UNAVAILABLE.error, NAME_UNAVAILABLE.message)
}

// Names other areas hold until a person decides, beside open intakes and
// connects: an open adoption batch's staged rows (adoptions.ts).
const nameHolders = new Map<string, (ctx: VaultContext, slug: string, now: number) => boolean>()
export function registerNameHolder(name: string, holds: (ctx: VaultContext, slug: string, now: number) => boolean): void { nameHolders.set(name, holds) }
function heldElsewhere(ctx: VaultContext, slug: string): boolean { return [...nameHolders.values()].some(holds => holds(ctx, slug, ctx.now())) }

export function assertCredentialNameFree(ctx: VaultContext, principal: AccessPrincipal, slug: string, reservation?: string): void {
  assertNameBudget(ctx, principal)
  const reserved = one(ctx.sql.exec<{
    id: string
  }>("SELECT id FROM workspace_credential_requests WHERE slug = ? AND status = 'open' AND expires_at > ? AND id != ?", slug, ctx.now(), reservation ?? ""))
  if (items.getItem(ctx, slug) || reserved || heldElsewhere(ctx, slug))
    unavailableName(ctx, principal)
}

// A final fill can only use its already-authorised stored reservation, never
// guess another name. It does not consume the filler's namespace miss budget.
export function assertCredentialReservation(ctx: VaultContext, slug: string, reservation: string): void {
  const own = one(ctx.sql.exec("SELECT 1 FROM workspace_credential_requests WHERE id=? AND slug=? AND status='open' AND expires_at>?", reservation, slug, ctx.now()))
  const other = one(ctx.sql.exec("SELECT 1 FROM workspace_credential_requests WHERE slug=? AND status='open' AND expires_at>? AND id<>?", slug, ctx.now(), reservation))
  if (!own || other || items.getItem(ctx, slug) || heldElsewhere(ctx, slug)) throw new VaultError(NAME_UNAVAILABLE.error, NAME_UNAVAILABLE.message)
}

export function permittedCredentialHomes(ctx: VaultContext, p: AccessPrincipal, invocation?: WorkspaceInvocationContext): CredentialHome[] {
  const state = credentialAccessState(ctx, invocation)
  const candidates: CredentialHome[] = [{ kind: "workspace" }, ...state.projects.map(project => ({ kind: "project" as const, project: project.id }))]
  if (p.kind === "member")
    candidates.push({ kind: "member", member: p.memberId })
  return candidates.filter(home => can(state, p, { type: "credential.create" }, { destinationHome: home }, ctx.now()).allowed)
}

export function credentialCreationContext(ctx: VaultContext, p: AccessPrincipal, home: CredentialHome, target: CheckedCredential | null, client: CheckedCredential | null = null, invocation?: WorkspaceInvocationContext): CredentialCreationContext {
  return { home, permittedHomes: target ? [target.home] : permittedCredentialHomes(ctx, p, invocation), intent: target ? "rotate" : "create", target: target ? { item: target.id, version: target.version, configRevision: target.configRev } : null, client: client ? { item: client.id, configRevision: client.configRev } : null, dependencyRevision: target?.dependencyRevision ?? 0 }
}

export function creationHome(ctx: VaultContext, principal: AccessPrincipal, home: "private" | "project" | "workspace", project?: string): CredentialHome {
  if (home === "workspace")
    return { kind: "workspace" }
  if (home === "project") {
    if (!project)
      throw new VaultError("bad_request", "Project home requires a project id.")
    return { kind: "project", project }
  }
  const state = credentialAccessState(ctx)
  const member = principal.kind === "member" ? principal.memberId : state.devices.find((d) => d.id === principal.deviceId)?.owner
  if (typeof member === "string")
    return { kind: "member", member }
  if (member?.kind === "member")
    return { kind: "member", member: member.id }
  throw new VaultError("not_found", "No such home.")
}

// A managed workspace's platform cannot decide fills yet, so a person
// there may neither raise a credential's ceiling to fill nor set the pages
// it is typed into, as /v1/fill and the intake choice refuse there.
function refuseFillChangeIfManaged(ctx: VaultContext, change: { ceiling?: string; browser?: unknown }): void {
  if ((change.ceiling === "fill" || change.browser !== undefined) && managedSetting(ctx) !== null) throw new VaultError("forbidden", FILL_MANAGED_REFUSAL)
}

export function assertItemRight(ctx: VaultContext, invocation: WorkspaceInvocationContext, action: AccessAction, target: AccessTarget) { return authorise(ctx, invocation, action, target, ctx.now()); }

export async function prepareCredential(ctx: VaultContext, input: WorkspaceItemInput, expected: CheckedCredential | null, reservedId?: string): Promise<PreparedCredential> {
  validateNewItem(input)
  // A replaced item keeping its fill ceiling is not refused with the switch off.
  if (expected?.ceiling !== input.ceiling) refuseFillUnlessOn(ctx, [input.ceiling])
  assertBindingHosts(input.binding)
  const id = expected?.id ?? reservedId ?? randomId("itm")
  return { input, id, expected, secrets: await sealSecrets(ctx, id, input.secretFields) }
}
// No await, no permission cache, no nested independently committed mutation.

export function storeCredential(ctx: VaultContext, prepared: PreparedCredential, principal: AccessPrincipal, action: string, session: string | null = null, configChange = true): CheckedCredential {
  const { input, expected, id } = prepared
  if (expected)
    assertCredentialCurrent(ctx, expected)
  else if (items.getItem(ctx, input.slug))
    throw new VaultError(NAME_UNAVAILABLE.error, NAME_UNAVAILABLE.message)
  const now = ctx.now()
  if (expected) {
    keepReplacedSecrets(ctx, expected, action, actorString(principal))
    ctx.sql.exec("DELETE FROM item_secrets WHERE item = ?", id)
  }
  ctx.sql.exec(`INSERT INTO items (id,slug,kind,provider,account,account_verified,tags,ceiling,binding,policy,injection,public_fields,status,version,config_rev,description,created_at,updated_at,rotated_at,home_kind,home_id,dependency_revision)
  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'active',1,0,?,?,?,?,?,?,0)
  ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,provider=excluded.provider,account=excluded.account,account_verified=excluded.account_verified,tags=excluded.tags,ceiling=excluded.ceiling,binding=excluded.binding,policy=excluded.policy,injection=excluded.injection,public_fields=excluded.public_fields,status='active',version=items.version+1,config_rev=items.config_rev+?,description=excluded.description,updated_at=excluded.updated_at,rotated_at=excluded.rotated_at`, id, input.slug, input.kind, input.provider, input.account, input.accountVerified ? 1 : 0, JSON.stringify(input.tags), input.ceiling, JSON.stringify(input.binding), JSON.stringify(input.policy), input.injection ? JSON.stringify(input.injection) : null, JSON.stringify(input.publicFields), input.description, expected?.createdAt ?? now, now, expected ? now : null, input.home.kind, input.home.kind === "member" ? input.home.member : input.home.kind === "project" ? input.home.project : null, configChange ? 1 : 0)
  storeSecrets(ctx, id, prepared.secrets)
  // A replaced value clears why it was flagged (a rejected OAuth client's
  // secret, a member who left), as a single-tenant replace does.
  if (expected && action === "item.rotate")
    ctx.sql.exec("UPDATE items SET review_reason=NULL,review_at=NULL WHERE id=?", id)
  const stored = checkedCredential(ctx, input.slug) as CheckedCredential
  credentialAudit(ctx, principal, stored, action, action === "oauth.refresh" ? "maintained" : "allowed", {}, null, session)
  const member = principal.kind === "member" ? principal.memberId : credentialAccessState(ctx).devices.find((d) => d.id === principal.deviceId)?.owner
  if (action !== "oauth.refresh")
    recordExposure(ctx, { item: id, version: stored.version, member: typeof member === "string" ? member : member?.kind === "member" ? member.id : null, device: principal.kind === "device" ? principal.deviceId : null, event: action, source: "entered", at: now })
  return stored
}

function actorString(principal: AccessPrincipal): string { return principal.kind === "member" ? `member:${principal.memberId}` : `device:${principal.deviceId}` }

export function credentialAudit(ctx: VaultContext, principal: AccessPrincipal, item: CheckedCredential, action: string, outcome: string, detail: Record<string, unknown> = {}, run: string | null = null, session: string | null = null): void {
  const device = principal.kind === "device" ? credentialAccessState(ctx).devices.find((d) => d.id === principal.deviceId) : null
  const actor = actorString(principal)
  const privateDetail: PrivateEvent = { action, at: ctx.now(), actor: principal.kind === "member" ? { kind: "member", member: principal.memberId } : { kind: "device", device: principal.deviceId, owner: device?.owner.kind === "team" ? { kind: "team", team: device.owner.id } : { kind: "member", member: device?.owner.id ?? "" } }, session, item: item.id, slug: item.slug, outcome, run }
  // auditPrivateEvent validates labels and refused:<code> before hashing.
  if (item.home.kind === "member")
    auditPrivateEvent(ctx, privateDetail, item.home.member)
  else
    ctx.audit({ actor, action, target: item.slug, detail: { ...detail, item: item.id, outcome, run } })
}

// In a managed workspace an item is described under the policy it is used
// under, computed now (managed-platform.ts).
// describeItem never sets a posture; the describe op adds the one its
// reader may know.
// A connection's OAuth client is named only to the reader passed (by
// describe and the connect and intake statuses), and only when that reader
// may see the client.
export function describeCredential(ctx: VaultContext, item: CheckedCredential, reader?: ConnectionReader): WorkspaceItemDescription { const { posture: _none, ...described } = describeItem(ctx, managedPolicyView(ctx, item)); return { ...described, home: item.home, ...connectionOf(ctx, item, reader) }; }

type ConnectionReader = { principal: AccessPrincipal; invocation: WorkspaceInvocationContext }

// ItemDescription.connection: what an OAuth connection may do, from what the
// provider granted it.
function connectionOf(ctx: VaultContext, item: CheckedCredential, reader: ConnectionReader | undefined): { connection?: ItemConnection } {
  if (item.kind !== "oauth-connection") return {}
  const row = one(ctx.sql.exec<{ payload: string; expires_at: number | null; client_id: string | null; client: string | null }>("SELECT c.payload AS payload,c.expires_at AS expires_at,i.id AS client_id,i.slug AS client FROM workspace_oauth_connections c LEFT JOIN items i ON i.id=c.client WHERE c.item=?", item.id))
  if (!row) return {}
  const basis = JSON.parse(row.payload) as { scopes?: string[]; retryAt?: number }
  const seesClient = reader !== undefined && row.client_id !== null && can(credentialAccessState(ctx, reader.invocation), reader.principal, { type: "item.read" }, { credential: row.client_id }, ctx.now()).allowed
  return { connection: { scopes: basis.scopes ?? [], expiresAt: row.expires_at === null ? null : new Date(row.expires_at).toISOString(), refreshing: basis.retryAt !== undefined && basis.retryAt > ctx.now(), ...(seesClient && row.client !== null ? { client: row.client } : {}) } }
}

// ItemDescription.pushes: where this item was put, in a workspace with
// pushes on or once it has been pushed; absent otherwise.
function pushesOf(ctx: VaultContext, item: CheckedCredential, viewer: AccessPrincipal, invocation: WorkspaceInvocationContext): { pushes?: PushRecordView[] } {
  const seesVia = (slug: string) => {
    try { visibleCredential(ctx, viewer, slug, undefined, invocation); return true }
    catch (error) { if (error instanceof VaultError && error.code === "not_found") return false; throw error }
  }
  const seesWho = viewer.kind === "member" && credentialAccessState(ctx, invocation).members.find((m) => m.id === viewer.memberId)?.standing.effectiveRole !== "guest"
  const pushes = latestPushes(ctx, item, { seesVia, seesWho })
  return pushes.length > 0 || pushesOn(ctx.env, ctx.tenant) ? { pushes } : {}
}

// The kept previous value as a person's page shows it: names and times only.
export function previousVersion(ctx: VaultContext, item: string): ItemPreviousVersion | null {
  const kept = rows(ctx.sql.exec<{ name: string; version: number; replaced_at: number; replaced_by: string; expires_at: number }>("SELECT name, version, replaced_at, replaced_by, expires_at FROM item_secret_history WHERE item = ? AND expires_at > ? ORDER BY name", item, ctx.now()))
  const first = kept[0]
  if (!first) return null
  const [kind, id = ""] = first.replaced_by.split(":")
  const replacedBy = kind === "member" ? credentialAccessState(ctx).members.find((m) => m.id === id)?.name : devicePolicyState(ctx, id)?.name
  return { version: first.version, replacedAt: new Date(first.replaced_at).toISOString(), expiresAt: new Date(first.expires_at).toISOString(), replacedBy: replacedBy ?? id, fields: kept.map((k) => k.name) }
}

// The versions a restore's page showed: the item's and the kept one's.
export const RestoreTerms = z.object({ version: z.number().int().positive(), previous: z.number().int().positive() })

// What a restore's passkey signs: the item, its version and the kept
// version as the page showed them, so a rotation since refuses.
async function restoreAction(item: CheckedCredential, terms: z.infer<typeof RestoreTerms>) {
  return { type: "item.restore" as const, item: item.id, digest: await stepUpDigest({ item: item.id, version: terms.version, previous: terms.previous }) }
}

function assertRestorable(ctx: VaultContext, item: CheckedCredential, terms: z.infer<typeof RestoreTerms>): void {
  if (item.kind === "oauth-connection") throw new VaultError("bad_request", "An OAuth connection keeps no previous value; reconnect it instead.")
  if (item.version !== terms.version || keptSecrets(ctx, item.id)[0]?.version !== terms.previous) throw credentialChanged()
}

export function credentialDependencies(ctx: VaultContext, item: string) { return rows(ctx.sql.exec<{
  connection: string
  client: string
  client_revision: number
  revision: number
}>("SELECT * FROM credential_dependencies WHERE client=? OR connection=?", item, item)); }

export function invalidateCredentialDependencies(ctx: VaultContext, item: string): void {
  ctx.sql.exec("UPDATE workspace_credential_requests SET status='cancelled' WHERE client_id=? OR target_id=?", item, item)
  ctx.sql.exec("DELETE FROM workspace_oauth_connections WHERE item=?", item)
  ctx.unschedule("oauth", `workspace-refresh:${item}`)
  for (const edge of credentialDependencies(ctx, item)) {
    if (edge.client === item) {
      ctx.sql.exec("UPDATE items SET status='disabled',dependency_revision=dependency_revision+1 WHERE id=?", edge.connection)
      ctx.unschedule("oauth", `workspace-refresh:${edge.connection}`)
    }
    else
      ctx.sql.exec("UPDATE items SET dependency_revision=dependency_revision+1 WHERE id=?", edge.client)
  }
  ctx.sql.exec("DELETE FROM credential_dependencies WHERE connection=? OR client=?", item, item)
  // The request bytes kept for standing rules on it.
  ctx.sql.exec("DELETE FROM policy_rule_anchors WHERE item=?", item)
  forgetPosture(ctx, item)
}

export function rehomeCredentialDependencies(ctx: VaultContext, item: CheckedCredential, home: CredentialHome): void {
  const edges = credentialDependencies(ctx, item.id)
  for (const edge of edges) {
    const clientHome = edge.client === item.id ? home : credentialHome(ctx, edge.client)
    const connectionHome = edge.connection === item.id ? home : credentialHome(ctx, edge.connection)
    if (!clientHome || !connectionHome || !compatibleClientHome(clientHome, connectionHome))
      throw new VaultError("conflict", "This home is incompatible with a credential dependency.")
  }
  ctx.sql.exec("UPDATE workspace_credential_requests SET status='cancelled' WHERE client_id=? OR target_id=?", item.id, item.id)
  for (const edge of edges) {
    const connection = one(ctx.sql.exec<{
      payload: string
    }>("SELECT payload FROM workspace_oauth_connections WHERE item=?", edge.connection))
    if (!connection)
      throw new VaultError("conflict", "This home is incompatible with a credential dependency.")
    const basis = JSON.parse(connection.payload) as Record<string, unknown>
    const next = { ...basis, ...(edge.client === item.id ? { clientRevision: item.configRev + 1 } : {}), ...(edge.connection === item.id ? { credentialRevision: item.configRev + 1, home } : {}) }
    ctx.sql.exec("UPDATE workspace_oauth_connections SET payload=? WHERE item=?", JSON.stringify(next), edge.connection)
    ctx.sql.exec("UPDATE credential_dependencies SET client_revision=?,revision=revision+1 WHERE connection=?", edge.client === item.id ? item.configRev + 1 : edge.client_revision, edge.connection)
    if (edge.connection !== item.id)
      ctx.sql.exec("UPDATE items SET dependency_revision=dependency_revision+1 WHERE id=?", edge.connection)
  }
}

export const offboardCredentials:OffboardingHook=(ctx,snapshot)=>{
 for(const id of snapshot.privateItems){
  const slug=one(ctx.sql.exec<{slug:string}>("SELECT slug FROM items WHERE id=?",id))?.slug
  const item=slug?checkedCredential(ctx,slug):null
  if(!item)continue
  if(item.home.kind!=="member"||item.home.member!==snapshot.member)throw new VaultError("conflict","The credential home changed during removal.")
  onCredentialRemoved(Object.assign(Object.create(ctx),{audit(){ /* member.remove is the sole removal event. */ }}),item,"offboarded",snapshot.by)
  invalidateCredentialDependencies(ctx,id)
  ctx.sql.exec("DELETE FROM item_secret_history WHERE item=?",id)
  ctx.sql.exec("DELETE FROM item_secrets WHERE item=?",id)
  ctx.sql.exec("DELETE FROM items WHERE id=?",id)
 }
 const name=credentialAccessState(ctx).members.find(member=>member.id===snapshot.member)?.name??snapshot.member
 for(const id of new Set(snapshot.exposures.map(fact=>fact.item))){
  const current=one(ctx.sql.exec<{slug:string;version:number;home_kind:string}>("SELECT slug,version,home_kind FROM items WHERE id=?",id))
  if(!current||current.home_kind === "member"||!snapshot.exposures.some(fact=>fact.item===id&&fact.version===current.version))continue
  flagMemberLeft(ctx,current.slug,name)
 }
 ctx.sql.exec("UPDATE workspace_credential_requests SET status='cancelled' WHERE requester_member=?",snapshot.member)
 for(const device of snapshot.devices)ctx.sql.exec("UPDATE workspace_credential_requests SET status='cancelled' WHERE requester_device=?",device)
}

function flagMemberLeft(ctx: VaultContext, slug: string, name: string): void { items.flagForReview(ctx, slug, `member left: ${name}`) }

export function registerCredentialServices(): void {
  registerCredentialProvider()
  registerExposureProvider(ctx => rows(ctx.sql.exec<{
    item: string
    version: number
    ceiling: import("@mehen/protocol").Mode
  }>("SELECT id AS item,version,ceiling FROM items")))
  registerOffboardingHook("credentials", offboardCredentials)
}
registerCredentialServices()

export const workspaceItems: WorkspaceItemsService = {
  home: credentialHome,
  dependencies(ctx, item) {
    return credentialDependencies(ctx, item).flatMap(edge => {
      const id = edge.client === item ? edge.connection : edge.client
      const slug = one(ctx.sql.exec<{
        slug: string
      }>("SELECT slug FROM items WHERE id=?", id))?.slug
      const credential = slug ? checkedCredential(ctx, slug) : null
      return credential ? [{ item: credential.id, version: credential.version, configRevision: credential.configRev, home: credential.home }] : []
    })
  },
  offboard: offboardCredentials,
}
const SlugInput = z.object({ slug: Slug })

export const workspaceItemOps = {
  "items.action": {
    auth: ["account"] as const, async handler(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext) {
      const req = parseOpInput(z.object({ slug: Slug, change: ItemChange.optional(), home: CredentialHomeSchema.optional(), action: z.enum(["update", "delete", "rehome", "restore", "posture"]), ...RestoreTerms.partial().shape, ...PostureTerms.partial().shape }), input)
      if (req.action === "delete") {
        const item = checkedCredential(ctx, req.slug)
        if (!item)
          throw missingCredential(req.slug)
        try {
          assertItemRight(ctx, invocation, { type: "credential.delete" }, { credential: item.id })
        }
        catch (error) {
          if (error instanceof VaultError)
            throw missingCredential(req.slug)
          throw error
        }
        return { type: "item.delete", item: item.id }
      }
      const item = visibleCredential(ctx, p, req.slug, undefined, invocation)
      if (req.action === "rehome") {
        if (!req.home)
          throw new VaultError("bad_request", "Choose a home.")
        assertItemRight(ctx, invocation, { type: "credential.rehome" }, { credential: item.id, destinationHome: req.home })
        return { type: "item.rehome", item: item.id, before: item.home, after: req.home, dependencyRevision: item.dependencyRevision }
      }
      if (req.action === "restore") {
        if (req.version === undefined || req.previous === undefined)
          throw new VaultError("bad_request", "Name the version shown and the previous version to restore.")
        const terms = { version: req.version, previous: req.previous }
        assertRestorable(ctx, item, terms)
        assertItemRight(ctx, invocation, { type: "credential.restore" }, { credential: item.id })
        return restoreAction(item, terms)
      }
      if (req.action === "posture") {
        if (req.posture === undefined || req.rev === undefined)
          throw new VaultError("bad_request", "Choose how careful it is, and name the revision shown.")
        return (await postureAction(ctx, item, { posture: req.posture, rev: req.rev }, invocation)).action
      }
      if (req.change?.ceiling !== undefined) {
        assertFillableKind(item.kind, req.change.ceiling)
        refuseFillUnlessOn(ctx, [req.change.ceiling])
      }
      refuseBrowserChangeUnlessOn(ctx, req.change?.browser)
      refuseFillChangeIfManaged(ctx, req.change ?? {})
      const digest = await stepUpDigest({ change: req.change ?? {}, version: settingsPinnedVersion(item.kind, item.version), configRevision: item.configRev })
      assertCredentialCurrent(ctx, item)
      assertItemRight(ctx, invocation, { type: "credential.update" }, { credential: item.id })
      return { type: "item.update", item: item.id, digest }
    }
  },
  "items.list": {
    auth: ["account", "device"] as const, handler(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext) {
      if (p.kind === "member") authorise(ctx, invocation, { type: "asks.read" }, {}, ctx.now())
      const q = parseOpInput(z.object({ tag: Tag.optional(), kind: KindSchema.optional(), provider: z.string().max(64).optional() }), input)
      return { items: rows(ctx.sql.exec<{
          slug: string
        }>("SELECT slug FROM items ORDER BY slug")).flatMap(({ slug }) => { try {
          const c = visibleCredential(ctx, p, slug, undefined, invocation)
          return (q.tag === undefined || c.tags.includes(q.tag)) && (q.kind === undefined || c.kind === q.kind) && (q.provider === undefined || c.provider === q.provider) ? [{ ...items.summarise(managedPolicyView(ctx, c)), home: c.home }] : []
        }
        catch (e) {
          if (e instanceof VaultError && e.code === "not_found")
            return []
          throw e
        } }) }
    }
  },
  "items.describe": { auth: ["account", "device"] as const, handler(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext) {
      const item = visibleCredential(ctx, p, parseOpInput(SlugInput, input).slug, undefined, invocation)
      // A person's page keeps the stable identity and revisions it showed, so
      // it signs only an action about that credential and no replacement.
      if (p.kind !== "member") {
        const posture = p.kind === "device" ? machinePosture(ctx, p, item) : undefined
        return { ...describeCredential(ctx, item, { principal: p, invocation }), ...pushesOf(ctx, item, p, invocation), ...(posture ? { posture } : {}) }
      }
      // Its OAuth client or connections, as far as this person may see them;
      // others are only counted as present, never named.
      const dependencies: { slug: string; role: "client" | "connection" }[] = []
      let hiddenDependencies = false
      for (const edge of credentialDependencies(ctx, item.id)) {
        const other = edge.client === item.id ? edge.connection : edge.client
        const slug = one(ctx.sql.exec<{ slug: string }>("SELECT slug FROM items WHERE id=?", other))?.slug
        if (!slug) continue
        try { visibleCredential(ctx, p, slug, undefined, invocation); dependencies.push({ slug, role: edge.client === item.id ? "connection" : "client" }) }
        catch (error) { if (error instanceof VaultError && error.code === "not_found") hiddenDependencies = true; else throw error }
      }
      // The pages a human added for fill, once there are any: a person's only.
      const browser = item.browser !== null ? { browser: item.browser } : {}
      const posture = personPosture(ctx, p, item, invocation)
      return { ...describeCredential(ctx, item, { principal: p, invocation }), ...pushesOf(ctx, item, p, invocation), ...browser, previous: previousVersion(ctx, item.id), pushable: itemPushable(ctx, item.id), id: item.id, configRevision: item.configRev, dependencyRevision: item.dependencyRevision, dependencies, hiddenDependencies, ...(posture ? { posture } : {}) }
    } },
  // Restoring swaps: the kept fields become current (a new version), and the
  // fields they replace become the kept set, so a restore can be undone.
  // The sealed values move as they are; only a stale fingerprint is redone.
  "items.restore": {
    auth: ["account"] as const, async handler(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext) {
      const { slug, ...terms } = parseOpInput(RestoreTerms.extend({ slug: Slug }), input)
      const before = visibleCredential(ctx, p, slug, undefined, invocation)
      const action = await restoreAction(before, terms)
      const signed = invocation.auth.kind === "account" ? invocation.auth.stepUp : undefined
      const check = () => {
        const live = assertCredentialCurrent(ctx, before)
        assertRestorable(ctx, live, terms)
        const decision = assertItemRight(ctx, invocation, { type: "credential.restore" }, { credential: live.id })
        if (signed?.type === "item.restore" && signed.item === live.id && signed.digest !== action.digest) throw credentialChanged()
        requireStepUp(ctx, decision, action, invocation)
        if (p.kind !== "member") throw new VaultError("forbidden", "Only a person can restore a credential.")
        return { live, member: p.memberId }
      }
      check()
      const kept = keptSecrets(ctx, before.id)
      const refreshed = new Map<string, string>()
      for (const k of kept) {
        if (k.fp_version !== null && k.fp_version >= ctx.rootVersion) continue
        const value = new TextDecoder().decode(await ctx.openField(secretRef(before, k.name), { rootVersion: k.root_version, wrappedDek: blob(k.wrapped_dek), ciphertext: blob(k.ciphertext) }))
        refreshed.set(k.name, await fingerprint(ctx, before.id, value, ctx.rootVersion))
      }
      return ctx.storage.transactionSync(() => {
        const { live, member } = check()
        const now = ctx.now()
        if (canonicalJson(keptSecrets(ctx, live.id).map((k) => [k.name, k.replaced_at])) !== canonicalJson(kept.map((k) => [k.name, k.replaced_at]))) throw credentialChanged()
        keepReplacedSecrets(ctx, live, "item.restore", `member:${member}`)
        ctx.sql.exec("DELETE FROM item_secrets WHERE item = ?", live.id)
        for (const k of kept) {
          const fresh = refreshed.get(k.name)
          ctx.sql.exec("INSERT INTO item_secrets (item, name, root_version, wrapped_dek, ciphertext, length, prefix, fingerprint, fp_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", live.id, k.name, k.root_version, k.wrapped_dek, k.ciphertext, k.length, k.prefix, fresh ?? k.fingerprint, fresh === undefined ? k.fp_version : ctx.rootVersion)
        }
        ctx.sql.exec("UPDATE items SET status='active', version=version+1, config_rev=config_rev+1, updated_at=?, rotated_at=? WHERE id=?", now, now, live.id)
        // A restore replaces the secret too, so it clears a rejected OAuth
        // client's reason, as a rotation does.
        if (live.review !== null && isClientRejectedReason(live.review.reason))
          ctx.sql.exec("UPDATE items SET review_reason=NULL,review_at=NULL WHERE id=?", live.id)
        // Whoever had the restored value has the new version: a member who
        // leaves still flags it for review (offboardCredentials), and one who
        // has already left flags it now, as their removal would have.
        ctx.sql.exec("INSERT OR IGNORE INTO exposures(event,item,version,member,device,source,at) SELECT event,item,?,member,device,source,at FROM exposures WHERE item=? AND version=?", live.version + 1, live.id, terms.previous)
        if (live.home.kind !== "member") {
          const exposed = new Set(rows(ctx.sql.exec<{ member: string | null }>("SELECT DISTINCT member FROM exposures WHERE item=? AND version=?", live.id, live.version + 1)).map((e) => e.member))
          for (const left of credentialAccessState(ctx).members.filter((m) => m.status === "removed" && exposed.has(m.id))) flagMemberLeft(ctx, slug, left.name)
        }
        credentialAudit(ctx, p, live, "item.restore", "allowed", { fields: kept.map((k) => k.name) }, null, invocation.auth.kind === "account" ? invocation.auth.session : null)
        const stored = checkedCredential(ctx, slug) as CheckedCredential
        return { ...describeCredential(ctx, stored), previous: previousVersion(ctx, stored.id) }
      })
    }
  },
  "items.update": {
    auth: ["account"] as const, async handler(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext) {
      const { slug, change } = parseOpInput(z.object({ slug: Slug, change: ItemChange }), input)
      const before = visibleCredential(ctx, p, slug, undefined, invocation)
      if (change.ceiling !== undefined) {
        assertFillableKind(before.kind, change.ceiling)
        refuseFillUnlessOn(ctx, [change.ceiling])
      }
      refuseBrowserChangeUnlessOn(ctx, change.browser)
      refuseFillChangeIfManaged(ctx, change)
      const digest = await stepUpDigest({ change, version: settingsPinnedVersion(before.kind, before.version), configRevision: before.configRev })
      return ctx.storage.transactionSync(() => {
        const live = assertCredentialCurrent(ctx, before)
        const decision = assertItemRight(ctx, invocation, { type: "credential.update" }, { credential: live.id })
        if (invocation.auth.kind === "account" && invocation.auth.stepUp?.type === "item.update" && invocation.auth.stepUp.item === live.id && invocation.auth.stepUp.digest !== digest)
          throw new VaultError("conflict", "The credential changed; review and try again.")
        requireStepUp(ctx, decision, { type: "item.update", item: live.id, digest }, invocation)
        if (!Object.keys(change).length)
          throw new VaultError("bad_request", "Nothing to change.")
        const { pushable, ...edits } = change
        const next = { ...live, ...edits }
        if (!modeAllowed(KINDS[live.kind].maxCeiling, next.ceiling))
          throw new VaultError("mode_refused", "The exposure ceiling exceeds this credential kind.")
        assertBindingHosts(next.binding)
        assertPushableChange(ctx, live.kind, pushable)
        ctx.sql.exec("UPDATE items SET binding=?,policy=?,ceiling=?,tags=?,description=?,browser=?,pushable=?,config_rev=config_rev+1,updated_at=? WHERE id=?", JSON.stringify(next.binding), JSON.stringify(next.policy), next.ceiling, JSON.stringify(next.tags), next.description, next.browser === null ? null : JSON.stringify(next.browser), Number(pushable ?? itemPushable(ctx, live.id)), ctx.now(), live.id)
        if (live.kind === "oauth-connection") ctx.sql.exec("UPDATE workspace_oauth_connections SET payload=json_set(payload,'$.credentialRevision',?) WHERE item=?", live.configRev+1, live.id)
        credentialAudit(ctx, p, live, "item.update", "allowed", { changed: Object.keys(change).sort() }, null, invocation.auth.kind === "account" ? invocation.auth.session : null)
        return describeCredential(ctx, checkedCredential(ctx, slug) as CheckedCredential)
      })
    }
  },
  "items.delete": {
    auth: ["account"] as const, handler(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext) {
      const { slug } = parseOpInput(SlugInput, input)
      const item = checkedCredential(ctx, slug)
      if (!item)
        throw missingCredential(slug)
      return ctx.storage.transactionSync(() => {
        let decision
        try { decision = assertItemRight(ctx, invocation, { type: "credential.delete" }, { credential: item.id }) }
        catch (error) {
          if (error instanceof VaultError && ["not_found", "forbidden"].includes(error.code)) throw missingCredential(slug)
          throw error
        }
        requireStepUp(ctx, decision, { type: "item.delete", item: item.id }, invocation)
        if(p.kind!=="member")throw new VaultError("forbidden","Only a person can delete a credential.")
        onCredentialRemoved(ctx,item,"deleted",p.memberId)
        invalidateCredentialDependencies(ctx, item.id)
        ctx.sql.exec("DELETE FROM item_secret_history WHERE item=?", item.id)
        ctx.sql.exec("DELETE FROM item_secrets WHERE item=?", item.id)
        ctx.sql.exec("DELETE FROM items WHERE id=?", item.id)
        credentialAudit(ctx, p, item, "item.delete", "allowed", {}, null, invocation.auth.kind === "account" ? invocation.auth.session : null)
        return {}
      })
    }
  },
  "items.rehome": {
    auth: ["account"] as const, handler(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext) {
      const { slug, home } = parseOpInput(z.object({ slug: Slug, home: CredentialHomeSchema }), input)
      const item = visibleCredential(ctx, p, slug, undefined, invocation)
      return ctx.storage.transactionSync(() => {
        requireStepUp(ctx, assertItemRight(ctx, invocation, { type: "credential.rehome" }, { credential: item.id, destinationHome: home }), { type: "item.rehome", item: item.id, before: item.home, after: home, dependencyRevision: item.dependencyRevision }, invocation)
        if(p.kind!=="member")throw new VaultError("forbidden","Only a person can rehome a credential.")
        rehomeCredentialDependencies(ctx, item, home)
        onCredentialRemoved(ctx,item,"rehomed",p.memberId)
        resetPostureOnRehome(ctx, p, item)
        ctx.sql.exec("UPDATE items SET home_kind=?,home_id=?,config_rev=config_rev+1,dependency_revision=dependency_revision+1 WHERE id=?", home.kind, home.kind === "project" ? home.project : home.kind === "member" ? home.member : null, item.id)
        credentialAudit(ctx, p, item, "item.rehome", "allowed", {}, null, invocation.auth.kind === "account" ? invocation.auth.session : null)
        return describeCredential(ctx, checkedCredential(ctx, slug) as CheckedCredential)
      })
    }
  },
}

export function credentialOps(ops: Record<string, {
  auth: readonly ("account" | "device" | "system")[]
  handler(ctx: VaultContext, p: AccessPrincipal, input: unknown, i: WorkspaceInvocationContext): unknown
}>): NonNullable<Area["workspaceOps"]> {
  return Object.fromEntries(Object.entries(ops).map(([name, op]) => [name, { auth: [...op.auth], handler(ctx, p, input, i) { if (p.kind === "system")
        throw new VaultError("forbidden", "Only a member or machine may do that."); return op.handler(ctx, p, input, i); } }]))
}
