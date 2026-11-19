// Managed workspaces (D0 1.5, 1.6, 1.8, 1.9): one workspace per subject of a
// platform, owned by it, whose one member (the subject member) stands for
// the subject and has no account, session or passkey. The platform acts
// here only through the platform.* operations below, each named after its
// route in @mehen/protocol's PLATFORM_ROUTES and admitted to platform auth
// alone; no other operation lists "platform". Its devices are ordinary
// devices from then on, under the existing /v1 routes.
//
// Every platform op takes { params, query, body } as the Worker parsed the
// route (platform/workspace-calls.ts: params without the subject, null for
// a part the route has none of) and answers the route's answer; a route
// with two success statuses also answers `created`. The answers carry no
// secret, no Mehen page link and no command.

import { z } from "zod"
import {
  KINDS,
  NATURAL_INJECTION,
  PLATFORM_DECISION_USES,
  PLATFORM_INTAKE_TTL_SECONDS,
  PLATFORM_ROUTES,
  PlatformApprovalDecideSchema,
  PlatformApprovalListQuerySchema,
  PlatformAuditQuerySchema,
  PlatformDeviceCreateSchema,
  PlatformDeviceLabelSchema,
  PlatformEmptySchema,
  PlatformIntakeCreateSchema,
  PlatformIntakeSubmitSchema,
  PlatformItemFilterSchema,
  PlatformProjectCreateSchema,
  PlatformVarSetSchema,
  WorkspaceDeviceScopeSchema,
  canonicalJson,
  customClientBinding,
  getOAuthProvider,
  getTemplate,
  isPublicHostName,
  jwkThumbprint,
  platformDeviceScope,
  subjectMemberAccount,
  type ApprovalSubject,
  type CustomOAuthProvider,
  type Injection,
  type ItemKind,
  type ItemSummary,
  type PlatformApprovalView,
  type PlatformDeviceListEntry,
  type PlatformDeviceView,
  type PlatformProjectCreate,
  type PlatformProjectView,
  type PlatformVarValue,
  type SubjectView,
  type Template,
} from "@mehen/protocol"
import { Slug, VarName } from "@mehen/protocol/api"
import { VaultError } from "../../http.ts"
import { sealPublicJwk } from "../../seal-key.ts"
import type { AccessPrincipal } from "../access.ts"
import { type Area, type PlatformInvocationAuth, type VaultContext, one, randomId, rows } from "../core.ts"
import { cachedManagedPlatform, heldManagedPlatform, managedDirectory, managedPolicyView, managedStatus, markManagedPurged, platformLive, platformSuspended, readManagedPlatform, type ManagedStatus } from "../managed-platform.ts"
import type { ApprovalPresentation } from "../services.ts"
import { assertApprovalGraphCurrent, invalidateConsent, storePlatformConsent, workspaceApproval, workspaceApprovalStatus, type WorkspaceApprovalRow } from "./approvals-workspace.ts"
import { forgetCliVersions } from "./device-cli-versions.ts"
import { cancelCredentialRequest, createCredentialRequest, requestHome, requestRow, submitWorkspaceIntake } from "./intake-workspace.ts"
import { assertBindingHosts, items, parseOpInput } from "./items.ts"
import { checkedCredential, credentialAudit, invalidateCredentialDependencies, openCredentialSecrets, type CheckedCredential } from "./items-workspace.ts"
import { revokeToken } from "./oauth.ts"
import { loadProject } from "./projects.ts"
import { onCredentialRemoved, projectWorkspaceOps } from "./projects-workspace.ts"
import { platformAuditPage } from "./tenant.ts"
import { askingWorkload } from "./workloads.ts"
import { beforeManagementChange } from "./management-guard.ts"
import { workspaceMemberOps } from "./workspace-members.ts"
import { accessChanged, accessState, authorise, bumpAccessRevision, managedSetting, newMember, requireStepUp, setProjectShare, setSetting, setting, type ManagedSetting, type WorkspaceInvocationContext, type WorkspaceRuntimePrincipal } from "./workspace-runtime.ts"

export const MANAGED_MIGRATIONS = [
  // A platform connect's state, by its hash, so a finish settles it once
  // (areas/oauth-workspace.ts); a device's provisioning (platform, key,
  // time, label); a decision's attestation; and a custom OAuth client's
  // fixed provider definition, written once when the client is stored and
  // never updated (areas/intake-workspace.ts).
  `CREATE TABLE platform_connect_states (state_hash TEXT PRIMARY KEY, connect TEXT NOT NULL, expires_at INTEGER NOT NULL);
   ALTER TABLE devices ADD COLUMN provisioned_by TEXT;
   ALTER TABLE approvals ADD COLUMN decided_by_platform TEXT;
   ALTER TABLE items ADD COLUMN custom_provider TEXT;`,
]


const PURGE_KEY = "purge"
// A purge waits at least this long after the deletion, so the directory has
// recorded the deletion before the purge records its head.
const PURGE_MIN_DELAY_MS = 5 * 60_000
const DAY_MS = 86_400_000
// The subject member's name, which nothing shows: the subject has no account.
const SUBJECT_MEMBER_NAME = "Subject"
const iso = (ms: number): string => new Date(ms).toISOString()

function notFound(): VaultError { return new VaultError("not_found", "No such subject.") }
export function overLimit(): VaultError { return new VaultError("quota_exceeded", "That is past this platform's limit.") }
function changedRequest(): VaultError { return new VaultError("conflict", "The request changed; ask again.") }

function routeOf(op: string): (typeof PLATFORM_ROUTES)[number] | undefined {
  return PLATFORM_ROUTES.find((route) => `platform.${route.name}` === op)
}

// Platform calls that still answer while the subject is being deleted, or
// after, until the purge: its view, its deletion again, and its audit.
const AFTER_DELETION = new Set(["platform.subjects.get", "platform.subjects.remove", "platform.audit.read"])

// Platform calls that reach an object its platform has not set up: making
// it, and removing it, which finds nothing to delete, so a subject whose
// creation was interrupted is removed and answers the same on a retry.
const BEFORE_SETUP = new Set(["platform.subjects.ensure", "platform.subjects.remove"])

// Before a platform call is handled, from the platform's row read at most
// every PLATFORM_REFRESH_SECONDS: the workspace must be this platform's and
// this subject's, listed, live, and its platform live; and a frozen
// workspace refuses the routes that list `frozen`. The proof's nonce is
// spent, and the platform's limits counted, by its PlatformVault before the
// call reaches the workspace (platform/platform-vault.ts).
export async function admitPlatformCall(ctx: VaultContext, auth: PlatformInvocationAuth, op: string): Promise<void> {
  const route = routeOf(op)
  if (!route) throw new VaultError("forbidden", "You are not allowed to do that.")
  const managed = managedSetting(ctx)
  if (!managed && !BEFORE_SETUP.has(op)) throw notFound()
  if (managed && (managed.platform !== auth.platform || managed.subject !== auth.subject)) throw notFound()
  if (managed) {
    const row = await readManagedPlatform(ctx)
    if (row === null || managedStatus(ctx) !== "active" && !AFTER_DELETION.has(op)) throw notFound()
    if (!platformLive(row.platform.status)) throw platformSuspended()
  }
  if (managed && (route.refusals as readonly string[]).includes("frozen") && setting(ctx, "frozen", false)) throw new VaultError("frozen", "This workspace is frozen.")
}

// A platform handler's write, in one transaction that reads the subject's
// status again first: a call admitted while the subject was active, that
// awaited while its deletion began, writes nothing. An operation run inside
// it nests its own transaction in this one, so it must not await.
export function subjectWrite<T>(ctx: VaultContext, write: () => T): T {
  return ctx.storage.transactionSync(() => {
    if (managedStatus(ctx) !== "active") throw notFound()
    return write()
  })
}

function platformAuthOf(invocation: WorkspaceInvocationContext): PlatformInvocationAuth {
  if (invocation.auth.kind !== "platform") throw new VaultError("forbidden", "Only a platform may do that.")
  return invocation.auth
}
function managedOf(ctx: VaultContext): ManagedSetting {
  const managed = managedSetting(ctx)
  if (!managed) throw notFound()
  return managed
}
function subjectMember(principal: WorkspaceRuntimePrincipal): Extract<AccessPrincipal, { kind: "member" }> {
  if (principal.kind !== "member") throw notFound()
  return principal
}

// The route's own input, as the Worker parsed it.
const RouteInput = z.object({ params: z.record(z.string(), z.string()).default({}), query: z.unknown().optional(), body: z.unknown().optional() })
function routeInput(raw: unknown): z.infer<typeof RouteInput> { return parseOpInput(RouteInput, raw) }
function param<T extends z.ZodType<string>>(input: z.infer<typeof RouteInput>, name: string, schema: T): z.infer<T> {
  return parseOpInput(z.object({ [name]: schema }), input.params)[name] as z.infer<T>
}
function body<T extends z.ZodType>(input: z.infer<typeof RouteInput>, schema: T): z.infer<T> {
  return parseOpInput(schema, input.body ?? {})
}
function query<T extends z.ZodType>(input: z.infer<typeof RouteInput>, schema: T): z.infer<T> {
  return parseOpInput(schema, input.query ?? {})
}

function count(ctx: VaultContext, sql: string, ...bindings: SqlStorageValue[]): number {
  return one(ctx.sql.exec<{ count: number }>(sql, ...bindings))?.count ?? 0
}

// ---------------------------------------------------------------- subjects: routes 5 to 7

const SUBJECT_STATUS: Record<ManagedStatus, SubjectView["status"]> = { active: "active", deleting: "deleting", deleted: "deleted" }

function subjectView(ctx: VaultContext): SubjectView {
  const managed = managedOf(ctx)
  return {
    subject: managed.subject,
    status: SUBJECT_STATUS[managedStatus(ctx)],
    createdAt: iso(managed.createdAt),
    counts: { devices: count(ctx, "SELECT count(*) AS count FROM devices WHERE revoked_at IS NULL"), items: count(ctx, "SELECT count(*) AS count FROM items"), projects: count(ctx, "SELECT count(*) AS count FROM projects") },
  }
}

// An object removed before it was set up, while this instance lives: a
// creation awaiting the directory or the subject's account when the removal
// ran sets nothing up after it. Only an in-flight creation can race the
// removal, and it holds this instance; the directory gives a removed
// subject a new object, so no later creation comes here.
const removedBeforeSetup = new WeakSet<DurableObjectStorage>()

// Makes this object the subject's managed workspace, once: the directory
// must already hold this tenant for this platform and subject. An object
// that holds anything else is never adopted.
async function ensureSubject(ctx: VaultContext, invocation: WorkspaceInvocationContext): Promise<unknown> {
  const auth = platformAuthOf(invocation)
  if (managedSetting(ctx)) return subjectView(ctx)
  const row = await readManagedPlatform(ctx, true)
  if (row === null || row.platform.id !== auth.platform || row.workspace.subject !== auth.subject || (row.workspace.status !== "creating" && row.workspace.status !== "active")) throw notFound()
  if (row.platform.status !== "active") throw platformSuspended()
  const account = await subjectMemberAccount(auth.platform, auth.subject)
  ctx.storage.transactionSync(() => {
    if (managedSetting(ctx)) return
    if (removedBeforeSetup.has(ctx.storage)) throw notFound()
    if (one(ctx.sql.exec("SELECT 1 FROM tenant_state WHERE key='workspace'")) || one(ctx.sql.exec("SELECT 1 FROM members")) || one(ctx.sql.exec("SELECT 1 FROM audit"))) throw new VaultError("conflict", "This workspace already holds something else.")
    const member = newMember(ctx, account, SUBJECT_MEMBER_NAME, "owner", "active")
    // The platform first, so every row from here names it and the chain
    // starts from its own first link.
    setSetting(ctx, "managed", { platform: auth.platform, subject: auth.subject, member, createdAt: ctx.now() } satisfies ManagedSetting)
    setSetting(ctx, "managed_status", "active")
    setSetting(ctx, "workspace", { id: ctx.tenant, slug: "managed", name: row.platform.name })
    bumpAccessRevision(ctx)
    ctx.audit({ actor: `member:${member}`, action: "workspace.create", target: ctx.tenant, detail: { subject: auth.subject } })
  })
  return subjectView(ctx)
}

// What step 4 deletes: every held request (its presentation, subject and
// snapshot with the approval), its grants, consent and runs; and every
// secret, item, project, variable, request and connect. Children first.
// What it keeps until the purge: the audit; the subject member, its
// account's security row and the workspace's own settings, so the subject
// and its audit still answer; and each device and workload row, for
// authentication rather than the audit, so a key that calls again is
// answered revoked or ended. Those rows keep only their key and its
// ending: step 4 scrubs a device's name and label and a workload's label
// and scope.
const DELETION_TABLES = ["protected_use_grants", "grants", "run_authorisations", "workspace_run_contexts", "run_placeholders", "runs", "consent_lineage", "approvals", "exposures", "removal_exposures", "notice_outbox", "item_secret_history", "item_secrets", "items", "workspace_oauth_connections", "credential_dependencies", "workspace_credential_requests", "vars", "environments", "remotes", "project_shares", "projects", "overrides", "platform_connect_states"]

// Steps 2 to 4 of D0 1.9: every device revoked (ending its workloads, asks
// and runs), every open intake and connect cancelled; then each connection's
// token handed back where its provider allows it; then every held request,
// secret, item, project and variable deleted in one transaction
// (DELETION_TABLES), the last audit row written, and the purge set for the platform's audit retention. Repeating
// it answers the same; an object its platform never made has nothing to
// delete or keep.
export async function deleteSubject(ctx: VaultContext, actor: string): Promise<{ purgeAfter: number }> {
  const managed = managedSetting(ctx)
  if (!managed) {
    removedBeforeSetup.add(ctx.storage)
    return { purgeAfter: ctx.now() }
  }
  const done = setting<number | null>(ctx, "managed_purge_after", null)
  if (managedStatus(ctx) === "deleted" && done !== null) return { purgeAfter: done }
  const retentionDays = (await readManagedPlatform(ctx, true))?.platform.limits.auditRetentionDays ?? 0
  const devices = ctx.storage.transactionSync(() => {
    setSetting(ctx, "managed_status", "deleting")
    const live = rows(ctx.sql.exec<{ id: string }>("SELECT id FROM devices WHERE revoked_at IS NULL")).map((d) => d.id)
    for (const device of live) {
      accessChanged(ctx, managed.member, "revoke", { device })
      ctx.sql.exec("UPDATE devices SET revoked_at=?,scope_rev=scope_rev+1 WHERE id=? AND revoked_at IS NULL", ctx.now(), device)
    }
    ctx.sql.exec("UPDATE workspace_credential_requests SET status='cancelled' WHERE status='open'")
    ctx.sql.exec("UPDATE approvals SET policy_status='stale' WHERE status='pending' AND policy_status IS NULL")
    invalidateConsent(ctx, managed.member)
    bumpAccessRevision(ctx)
    forgetCliVersions(ctx, live)
    return live.length
  })
  let providerRevoked = 0
  for (const { slug } of rows(ctx.sql.exec<{ slug: string }>("SELECT slug FROM items WHERE kind='oauth-connection'"))) {
    const item = checkedCredential(ctx, slug)
    if (item && await revokeConnectionToken(ctx, item)) providerRevoked++
  }
  const purgeAfter = ctx.now() + retentionDays * DAY_MS
  ctx.storage.transactionSync(() => {
    const removed = { devices, items: count(ctx, "SELECT count(*) AS count FROM items"), projects: count(ctx, "SELECT count(*) AS count FROM projects"), providerRevoked }
    const present = new Set(rows(ctx.sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table'")).map((t) => t.name))
    beforeManagementChange(ctx)
    for (const table of DELETION_TABLES) if (present.has(table)) ctx.sql.exec(`DELETE FROM ${table}`)
    ctx.sql.exec("UPDATE devices SET name=id,provisioned_by=NULL")
    ctx.sql.exec("UPDATE workloads SET label='',scope='{}'")
    bumpAccessRevision(ctx)
    ctx.audit({ actor, action: "workspace.delete", target: ctx.tenant, detail: removed })
    setSetting(ctx, "managed_status", "deleted")
    setSetting(ctx, "managed_purge_after", purgeAfter)
    ctx.schedule("managed", PURGE_KEY, Math.max(purgeAfter, ctx.now() + PURGE_MIN_DELAY_MS))
  })
  return { purgeAfter }
}

// Step 6: the object's storage is erased, the alarm with it, and its final
// audit head answered; not before the purge date. The head reaches the
// directory before anything is erased, whether the directory's sweep or the
// object's own alarm purges, so a failed directory write leaves the object
// whole for the next try. An object already erased, or never made, answers
// null.
//
// `early` is the directory's sweep purging a platform the operator is
// removing, whose audit no one can read once its keys are revoked: the date
// is skipped only when the directory, read again now, says so too.
export async function purgeSubject(ctx: VaultContext, early = false): Promise<{ auditHead: string | null }> {
  if (!managedSetting(ctx)) return { auditHead: null }
  const due = setting<number | null>(ctx, "managed_purge_after", null)
  if (managedStatus(ctx) !== "deleted" || due === null) throw new VaultError("conflict", "This subject is not deleted.")
  const removing = early && (await readManagedPlatform(ctx, true))?.platform.removing === true
  if (ctx.now() < due && !removing) throw new VaultError("conflict", "This subject's audit is kept until its purge date.")
  const head = one(ctx.sql.exec<{ hash: string }>("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1"))?.hash ?? null
  await managedDirectory().purged(ctx.env.DB, ctx.tenant, head)
  await ctx.storage.deleteAll()
  markManagedPurged(ctx.storage)
  return { auditHead: head }
}

// ---------------------------------------------------------------- devices: routes 8 to 10

type DeviceRow = { id: string; name: string; scope: string; thumbprint: string; created_at: number; last_seen_at: number | null; revoked_at: number | null; provisioned_by: string | null; owner_id: string | null }
const ProvisionedSchema = z.object({ platform: z.string(), key: z.string(), at: z.number(), label: PlatformDeviceLabelSchema.nullable() })

function deviceView(ctx: VaultContext, row: DeviceRow): PlatformDeviceView {
  const provisioned = row.provisioned_by === null ? null : ProvisionedSchema.parse(JSON.parse(row.provisioned_by))
  return { device: row.id, tenant: ctx.tenant, name: row.name, label: provisioned?.label ?? null, scope: WorkspaceDeviceScopeSchema.parse(JSON.parse(row.scope)), createdAt: iso(row.created_at), revoked: row.revoked_at !== null }
}

// A device for one of the platform's agents, with no enrolment page: it may
// only relay and serve placeholders, through workloads. The same live key
// again answers that device.
async function createDevice(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext): Promise<unknown> {
  const auth = platformAuthOf(invocation), member = subjectMember(principal)
  const input = body(routeInput(raw), PlatformDeviceCreateSchema)
  const thumbprint = await jwkThumbprint(input.jwk)
  return subjectWrite(ctx, () => {
    const same = one(ctx.sql.exec<DeviceRow>("SELECT * FROM devices WHERE thumbprint=? ORDER BY created_at DESC LIMIT 1", thumbprint))
    if (same) {
      if (same.revoked_at === null && same.provisioned_by !== null) return { ...deviceView(ctx, same), created: false }
      throw new VaultError("conflict", "This key belonged to another device. Make a new key.")
    }
    if (one(ctx.sql.exec("SELECT 1 FROM workloads WHERE thumbprint=?", thumbprint))) throw new VaultError("conflict", "This key is in use by a workload. Make a new key.")
    if (count(ctx, "SELECT count(*) AS count FROM devices WHERE revoked_at IS NULL") >= heldManagedPlatform(ctx).platform.limits.devicesPerSubject) throw overLimit()
    const id = randomId("dev")
    const row = heldManagedPlatform(ctx)
    ctx.sql.exec("INSERT INTO devices(id,name,backend,host,jwk,thumbprint,scope,created_at,owner_kind,owner_id,provisioned_by) VALUES (?,?,'software',?,?,?,?,?,'member',?,?)", id, input.name, row.platform.slug, canonicalJson(input.jwk), thumbprint, canonicalJson(platformDeviceScope(input.modes)), ctx.now(), member.memberId, canonicalJson({ platform: auth.platform, key: auth.key, at: ctx.now(), label: input.label ?? null }))
    bumpAccessRevision(ctx)
    ctx.audit({ actor: `member:${member.memberId}`, action: "device.provision", target: id, detail: { name: input.name, label: input.label ?? null, modes: input.modes } })
    const created = one(ctx.sql.exec<DeviceRow>("SELECT * FROM devices WHERE id=?", id))
    if (!created) throw new Error("Device insertion failed")
    return { ...deviceView(ctx, created), created: true }
  })
}

function listDevices(ctx: VaultContext): unknown {
  const devices: PlatformDeviceListEntry[] = rows(ctx.sql.exec<DeviceRow>("SELECT * FROM devices ORDER BY created_at,id")).map((row) => ({
    ...deviceView(ctx, row),
    lastSeenAt: row.last_seen_at === null ? null : iso(row.last_seen_at),
    liveWorkloads: count(ctx, "SELECT count(*) AS count FROM workloads WHERE device=? AND revoked_at IS NULL AND ended_at IS NULL AND expires_at>?", row.id, ctx.now()),
  }))
  return { devices }
}

// Its workloads, open asks and runs end with it. Repeating it answers the same.
function revokeDevice(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, raw: unknown): unknown {
  const member = subjectMember(principal)
  const id = param(routeInput(raw), "device", z.string().min(1).max(64))
  return subjectWrite(ctx, () => {
    const row = one(ctx.sql.exec<DeviceRow>("SELECT * FROM devices WHERE id=?", id))
    if (!row) throw new VaultError("not_found", "No such device.")
    if (row.revoked_at === null) {
      accessChanged(ctx, row.owner_id, "revoke", { device: row.id })
      ctx.sql.exec("UPDATE devices SET revoked_at=?,scope_rev=scope_rev+1 WHERE id=?", ctx.now(), row.id)
      ctx.audit({ actor: `member:${member.memberId}`, action: "device.revoke", target: row.id })
      forgetCliVersions(ctx, [row.id])
    }
    const after = one(ctx.sql.exec<DeviceRow>("SELECT * FROM devices WHERE id=?", id))
    if (!after) throw new Error("Device disappeared")
    return deviceView(ctx, after)
  })
}

// ---------------------------------------------------------------- items: routes 11 and 12

// Mehen's metadata, under the policy the item is used under now.
function summary(ctx: VaultContext, item: CheckedCredential): ItemSummary {
  return items.summarise(managedPolicyView(ctx, item))
}

function listItems(ctx: VaultContext, raw: unknown): unknown {
  const filter = query(routeInput(raw), PlatformItemFilterSchema)
  const found = rows(ctx.sql.exec<{ slug: string }>("SELECT slug FROM items ORDER BY slug")).flatMap(({ slug }) => {
    const item = checkedCredential(ctx, slug)
    return item && (filter.kind === undefined || item.kind === filter.kind) && (filter.tag === undefined || item.tags.includes(filter.tag)) ? [summary(ctx, item)] : []
  })
  return { items: found }
}

// Best effort and bounded, outside any transaction: a connection's token is
// handed back to its provider where the catalogue names a revocation
// endpoint (Google's). Nothing depends on the answer.
async function revokeConnectionToken(ctx: VaultContext, item: CheckedCredential): Promise<boolean> {
  if (item.kind !== "oauth-connection" || item.provider === null) return false
  const provider = getOAuthProvider(item.provider)
  if (!provider?.auth.revokeUrl) return false
  try {
    const secrets = await openCredentialSecrets(ctx, item)
    const token = secrets.refresh_token || secrets.access_token
    return token ? await revokeToken(provider, token) : false
  } catch {
    return false
  }
}

async function removeItem(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, raw: unknown): Promise<unknown> {
  const member = subjectMember(principal)
  const slug = param(routeInput(raw), "slug", Slug)
  const item = checkedCredential(ctx, slug)
  if (!item) throw new VaultError("not_found", "No such item.")
  const providerRevoked = await revokeConnectionToken(ctx, item)
  return subjectWrite(ctx, () => {
    const live = checkedCredential(ctx, slug)
    if (!live || live.id !== item.id) throw new VaultError("not_found", "No such item.")
    beforeManagementChange(ctx)
    onCredentialRemoved(ctx, live, "deleted", member.memberId)
    invalidateCredentialDependencies(ctx, live.id)
    ctx.sql.exec("DELETE FROM item_secret_history WHERE item=?", live.id)
    ctx.sql.exec("DELETE FROM item_secrets WHERE item=?", live.id)
    ctx.sql.exec("DELETE FROM items WHERE id=?", live.id)
    credentialAudit(ctx, member, live, "item.delete", "allowed", { providerRevoked })
    return { slug, deleted: true, providerRevoked }
  })
}

// ---------------------------------------------------------------- intakes: routes 13 to 15

type IntakePlan = { kind: ItemKind; provider: string | null; template: Template | null; binding: { hosts: string[]; paths?: string[]; methods?: string[] }; injection: Injection | null; customProvider: CustomOAuthProvider | null }

function intakePlan(ctx: VaultContext, service: z.infer<typeof PlatformIntakeCreateSchema>["service"]): IntakePlan {
  if ("template" in service) {
    const template = getTemplate(service.template)
    if (!template) throw new VaultError("bad_request", "The catalogue has no such template.")
    const offered = heldManagedPlatform(ctx).platform.defaults.templates
    if (offered !== undefined && !offered.includes(template.id)) throw new VaultError("bad_request", "This platform does not offer that service.")
    return { kind: template.kind, provider: template.id, template, binding: template.binding, injection: template.injection, customProvider: null }
  }
  // A host the vault's relay cannot reach (an IP literal, a single-label or
  // private name) is refused here, before the person types their key.
  if ("host" in service) {
    const binding = { hosts: [service.host] }
    assertBindingHosts(binding)
    if (!isPublicHostName(service.host)) throw new VaultError("bad_request", "That address is not one a key can be sent to: use a public host name, not an IP address or a private name.")
    return { kind: "api-key", provider: null, template: null, binding, injection: NATURAL_INJECTION["api-key"], customProvider: null }
  }
  // A public client (no secret, PKCE only) is deferred: the item kind and
  // the sealed submit both need a secret.
  if (service.customProvider.clientAuth === "none") throw new VaultError("bad_request", "A client without a secret is not supported yet.")
  return { kind: "oauth-client", provider: null, template: null, binding: customClientBinding(service.customProvider), injection: null, customProvider: service.customProvider }
}

// The definition a custom client was stored with (items.custom_provider).
function customDefinitionOf(ctx: VaultContext, item: string): string | null {
  return one(ctx.sql.exec<{ custom_provider: string | null }>("SELECT custom_provider FROM items WHERE id=?", item))?.custom_provider ?? null
}

function openPlatformRequests(ctx: VaultContext, member: string): number {
  return count(ctx, "SELECT count(*) AS count FROM workspace_credential_requests WHERE requester_member=? AND requester_device IS NULL AND status='open' AND expires_at>?", member, ctx.now())
}
// New items on their way: the platform's open intakes and connects for a
// name not yet held. A connect started again for the same name replaces
// the open one, so `replacing` leaves that one out.
function openNewItemRequests(ctx: VaultContext, member: string, replacing: string | null = null): number {
  return count(ctx, "SELECT count(*) AS count FROM workspace_credential_requests WHERE kind IN ('intake','connect') AND target_id IS NULL AND requester_member=? AND requester_device IS NULL AND status='open' AND expires_at>? AND NOT (kind='connect' AND slug IS ?)", member, ctx.now(), replacing)
}

// Whether the subject already holds as many items as its platform allows:
// checked again in the transaction that stores a new item, whatever was
// counted when its intake or connect began. With no platform row held, full.
export function managedItemsFull(ctx: VaultContext): boolean {
  const row = cachedManagedPlatform(ctx)
  return row === null || count(ctx, "SELECT count(*) AS count FROM items") >= row.platform.limits.itemsPerSubject
}

// A request for a credential, answered with the vault's seal key and the
// fields the platform's page shows: the person's browser seals each secret
// to the seal key under intake/<intake>/<field>. An existing name of the
// same kind is a rotation, which keeps where the key may go.
async function createIntake(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext): Promise<unknown> {
  const member = subjectMember(principal)
  const input = body(routeInput(raw), PlatformIntakeCreateSchema)
  const plan = intakePlan(ctx, input.service)
  const row = heldManagedPlatform(ctx)
  const target = checkedCredential(ctx, input.slug)
  if (target && target.kind !== plan.kind) throw new VaultError("conflict", "That name belongs to another kind of credential.")
  if (target && target.provider !== plan.provider) throw new VaultError("conflict", "A rotation keeps the credential's service.")
  if (target && plan.customProvider && canonicalJson(plan.customProvider) !== customDefinitionOf(ctx, target.id)) throw new VaultError("conflict", "A provider definition is fixed; add a new item for a new one.")
  const tags = target?.tags ?? [...new Set([...row.platform.defaults.tags, ...(input.tags ?? [])])]
  if (tags.length > 16) throw new VaultError("bad_request", "An item carries at most 16 tags.")
  if (!target && count(ctx, "SELECT count(*) AS count FROM items") + openNewItemRequests(ctx, member.memberId) >= row.platform.limits.itemsPerSubject) throw overLimit()
  if (openPlatformRequests(ctx, member.memberId) >= row.platform.limits.openRequestsPerSubject) throw overLimit()
  const template = target ? (target.provider ? getTemplate(target.provider) : null) : plan.template
  const payload = { kind: plan.kind, provider: target ? target.provider : plan.provider, tags, target, ...(target || plan.template ? {} : { binding: plan.binding, injection: plan.injection }), ...(input.reason ? { reason: input.reason } : {}), ...(plan.customProvider && !target ? { customProvider: plan.customProvider } : {}) }
  const request = subjectWrite(ctx, () => createCredentialRequest(ctx, member, { kind: "intake", slug: input.slug, home: { kind: "workspace" }, tags, payload, target, ttl: PLATFORM_INTAKE_TTL_SECONDS * 1000 }, invocation))
  const fields = KINDS[plan.kind].fields.filter((field) => !target || field.secret).map((field) => ({ name: field.name, label: template?.fields?.[field.name]?.label ?? field.label, secret: field.secret, required: field.required, multiline: template?.fields?.[field.name]?.multiline ?? field.multiline ?? false, hint: template?.fields?.[field.name]?.hint ?? null }))
  return { intake: request.id, sealKey: await sealPublicJwk(ctx.env), fields, binding: { hosts: (target?.binding ?? plan.binding).hosts, known: target !== null || template !== null }, rotates: target !== null, setup: template?.clientSetup ?? null, expiresAt: iso(request.expires_at) }
}

// The slug, binding, tags and home are the request's, never the body's.
// Each box opens only under intake/<intake>/<field>, and the submit closes
// the request in the transaction that stores the item, so a second one is
// a conflict. An intake a device's workload made is submitted the same way,
// but where the workload proposed its binding and injection (a new item
// with no template) the platform must send the terms it showed its user,
// so it never stores terms only the workload chose.
async function submitIntake(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext): Promise<unknown> {
  const member = subjectMember(principal)
  const input = routeInput(raw)
  const id = param(input, "intake", z.string().min(1).max(64))
  const submitted = body(input, PlatformIntakeSubmitSchema)
  const request = requestRow(ctx, id)
  if (request.kind !== "intake") throw new VaultError("not_found", "No such credential request.")
  const plan = JSON.parse(request.payload) as { kind: ItemKind; provider?: string | null; binding?: IntakePlan["binding"]; injection?: Injection; tags?: string[]; target: CheckedCredential | null }
  const template = plan.target ? (plan.target.provider ? getTemplate(plan.target.provider) : null) : plan.provider ? getTemplate(plan.provider) : null
  const binding = plan.target?.binding ?? template?.binding ?? plan.binding
  if (!binding) throw new VaultError("bad_request", "This credential request has no binding.")
  const injection = plan.target ? plan.target.injection : template ? template.injection : plan.injection ?? NATURAL_INJECTION[plan.kind]
  const workloadProposed = request.requester_device !== null && !plan.target && !template
  if (submitted.terms === undefined) {
    if (workloadProposed) throw new VaultError("bad_request", "A workload proposed this intake's terms: send the terms your user was shown, its binding and injection.")
  } else {
    const differing = [canonicalJson(submitted.terms.binding) !== canonicalJson(binding) ? "binding" : null, canonicalJson(submitted.terms.injection) !== canonicalJson(injection) ? "injection" : null].filter((name) => name !== null)
    if (differing.length > 0) throw new VaultError("bad_request", `The terms sent differ from this intake's: ${differing.join(", ")}.`)
  }
  await submitWorkspaceIntake(ctx, member, { intake: request.id, slug: request.slug, home: requestHome(request), binding, tags: plan.target?.tags ?? plan.tags ?? [], publicFields: submitted.publicFields ?? {}, sealed: submitted.sealed }, invocation, (target) => {
    if (managedStatus(ctx) !== "active") throw notFound()
    if (!target && managedItemsFull(ctx)) throw overLimit()
  })
  const item = checkedCredential(ctx, request.slug)
  if (!item) throw new Error("Submitted item disappeared")
  return { item: summary(ctx, item) }
}

function cancelIntake(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext): unknown {
  const member = subjectMember(principal)
  const input = routeInput(raw)
  body(input, PlatformEmptySchema)
  subjectWrite(ctx, () => cancelCredentialRequest(ctx, member, param(input, "intake", z.string().min(1).max(64)), "intake", invocation))
  return {}
}

// ---------------------------------------------------------------- approvals: routes 20 to 22

const DecidedSchema = z.object({ platform: z.string(), key: z.string(), jti: z.string(), ref: z.string().nullable() })

function approvalView(ctx: VaultContext, row: WorkspaceApprovalRow): PlatformApprovalView {
  const subject = JSON.parse(row.subject) as ApprovalSubject
  const presentation = JSON.parse(row.presentation) as ApprovalPresentation
  const standing = workspaceApprovalStatus(ctx, row)
  const decided = row.decided_by_platform ? DecidedSchema.parse(JSON.parse(row.decided_by_platform)) : null
  return {
    approval: row.id,
    // A managed workspace never replaces an ask; a row that somehow reads superseded is no longer the one asked.
    status: standing === "expired" && row.status === "approved" ? "ended" : standing === "superseded" ? "stale" : standing,
    digest: row.digest,
    device: row.device,
    workload: askingWorkload(ctx, row.workload).workload ?? null,
    item: row.item,
    request: { method: subject.method, url: subject.url, contentType: subject.contentType, contentEncoding: subject.contentEncoding, headersSha256: subject.headersSha256, bodySha256: subject.bodySha256 },
    title: presentation.title,
    warnings: presentation.warnings ?? [],
    constraints: subject.constraints,
    expiresAt: iso(row.expires_at),
    decidedBy: decided ? { platform: decided.platform, key: decided.key, ref: decided.ref } : null,
  }
}

function approvalOf(ctx: VaultContext, id: string): WorkspaceApprovalRow {
  const row = workspaceApproval(ctx, id)
  if (!row) throw new VaultError("not_found", "No such approval.")
  return row
}

function listApprovals(ctx: VaultContext, raw: unknown): unknown {
  const filter = query(routeInput(raw), PlatformApprovalListQuerySchema)
  const approvals = rows(ctx.sql.exec<WorkspaceApprovalRow>("SELECT * FROM approvals WHERE ask IS NOT NULL ORDER BY created_at DESC,id")).map((row) => approvalView(ctx, row)).filter((view) => filter.status === undefined || view.status === filter.status)
  return { approvals }
}

// The platform's counterpart of a person's passkey on an approval: the body
// names the approval's digest, the platform's proof signs the body, and the
// digest is compared with the pending row's in the deciding transaction. An
// approval serves one use of that exact request by the workload that asked,
// for at most the platform's decisionTtlSeconds.
function decideApproval(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext): unknown {
  const auth = platformAuthOf(invocation), member = subjectMember(principal), managed = managedOf(ctx)
  const input = routeInput(raw)
  const id = param(input, "approval", z.string().min(1).max(64))
  const decided = body(input, PlatformApprovalDecideSchema)
  const limit = heldManagedPlatform(ctx).platform.limits.decisionTtlSeconds
  const ttlSeconds = decided.ttlSeconds ?? limit
  if (ttlSeconds > limit) throw new VaultError("bad_request", `A decision lasts at most ${limit} seconds on this platform.`)
  subjectWrite(ctx, () => {
    const row = approvalOf(ctx, id)
    if (decided.digest !== row.digest || workspaceApprovalStatus(ctx, row) !== "pending") throw changedRequest()
    const state = accessState(ctx), ask = JSON.parse(row.ask) as import("../access.ts").AccessAsk
    const decision = authorise(ctx, invocation, { type: decided.decision === "approve" ? "approval.approve" : "approval.deny" }, { ask }, ctx.now())
    const constraints = { uses: PLATFORM_DECISION_USES, ttlSeconds }
    requireStepUp(ctx, decision, { type: "approval.decide", approval: row.id, digest: row.digest, decision: decided.decision, constraints }, invocation)
    let lineage: string | null = null
    if (decided.decision === "approve") {
      const snapshot = JSON.parse(row.snapshot) as import("./projects-workspace.ts").ProtectedSnapshot
      assertApprovalGraphCurrent(ctx, state, snapshot, ask)
      const grantExpiresAt = Math.min(row.expires_at, ctx.now() + ttlSeconds * 1000)
      const consent = storePlatformConsent(ctx, state, row.id, ask, grantExpiresAt, { kind: "platform", platform: auth.platform, key: auth.key, subject: managed.subject, member: member.memberId })
      ctx.sql.exec("INSERT INTO protected_use_grants(approval,lineage,snapshot,uses_left,expires_at) VALUES(?,?,?,?,?)", row.id, consent.id, row.snapshot, PLATFORM_DECISION_USES, Math.min(grantExpiresAt, consent.expiresAt))
      lineage = consent.id
    }
    ctx.sql.exec("UPDATE approvals SET status=?,decided_by=?,decided_at=?,lineage=?,decided_by_platform=? WHERE id=?", decided.decision === "approve" ? "approved" : "denied", member.memberId, ctx.now(), lineage, canonicalJson({ platform: auth.platform, key: auth.key, jti: auth.jti, ref: decided.ref ?? null }), row.id)
    ctx.audit({ actor: `member:${member.memberId}`, action: decided.decision === "approve" ? "approval.approve" : "approval.deny", target: row.id, detail: { item: row.item, device: row.device, outcome: decided.decision, attestation: { digest: row.digest, jti: auth.jti, ref: decided.ref ?? null } } })
  })
  return approvalView(ctx, approvalOf(ctx, id))
}

// ---------------------------------------------------------------- projects: routes 23 to 26

function projectView(ctx: VaultContext, id: string): PlatformProjectView {
  const project = loadProject(ctx, id)
  if (!project) throw new VaultError("not_found", "No such project.")
  return {
    id: project.id,
    slug: project.slug,
    defaultEnv: project.defaultEnv,
    environments: project.environments.map((e) => ({ name: e.name })),
    vars: project.vars.map((v) => v.item !== null ? { name: v.name, env: v.env, source: "item" as const, item: v.item, field: v.field } : v.plain !== null ? { name: v.name, env: v.env, source: "plain" as const, value: v.plain } : { name: v.name, env: v.env, source: "unset" as const }),
  }
}

// Whether a stored project is the one this create would make: the same
// default and environments, every one unprotected, and no remote.
function sameProjectShape(ctx: VaultContext, id: string, input: PlatformProjectCreate): boolean {
  const project = loadProject(ctx, id)
  if (!project || project.defaultEnv !== input.defaultEnv || project.remotes.length > 0) return false
  if (project.environments.some((e) => e.protected) || count(ctx, "SELECT count(*) AS count FROM environments WHERE project=? AND four_eyes!=0", id) > 0) return false
  const wanted = input.environments.map((e) => e.name).sort()
  const held = project.environments.map((e) => e.name).sort()
  return wanted.length === held.length && wanted.every((name, i) => name === held[i])
}

// Every environment unprotected, with no four-eyes and no remote; the
// subject member manages it. The same slug again, in the same shape,
// answers that project, as a device's key does; any other shape is a
// conflict.
function createProject(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext): unknown {
  const member = subjectMember(principal)
  const input = body(routeInput(raw), PlatformProjectCreateSchema)
  const id = randomId("prj")
  const made = subjectWrite(ctx, () => {
    const decision = authorise(ctx, invocation, { type: "project.create" }, {}, ctx.now())
    requireStepUp(ctx, decision, { type: "project.create", slug: input.slug, remote: null, environments: input.environments.map((e) => ({ name: e.name, protected: false, fourEyes: false })) }, invocation)
    const same = one(ctx.sql.exec<{ id: string }>("SELECT id FROM projects WHERE slug=?", input.slug))
    if (same) {
      if (sameProjectShape(ctx, same.id, input)) return { id: same.id, created: false }
      throw new VaultError("conflict", "That name is in use by another project.")
    }
    if (count(ctx, "SELECT count(*) AS count FROM projects") >= heldManagedPlatform(ctx).platform.limits.projectsPerSubject) throw overLimit()
    beforeManagementChange(ctx)
    ctx.sql.exec("INSERT INTO projects(id,slug,default_env,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?)", id, input.slug, input.defaultEnv, `member:${member.memberId}`, ctx.now(), ctx.now())
    for (const e of input.environments) ctx.sql.exec("INSERT INTO environments(project,name,protected,fences,four_eyes) VALUES(?,?,0,'[]',0)", id, e.name)
    setProjectShare(ctx, { id: randomId("shr"), project: id, subject: { kind: "member", member: member.memberId }, level: "manage", protected: true, expiresAt: null }, null)
    bumpAccessRevision(ctx)
    ctx.audit({ actor: `member:${member.memberId}`, action: "project.create", target: id, detail: { slug: input.slug, remote: null } })
    return { id, created: true }
  })
  return { ...projectView(ctx, made.id), created: made.created }
}

function getProject(ctx: VaultContext, raw: unknown, invocation: WorkspaceInvocationContext): unknown {
  const id = param(routeInput(raw), "project", z.string().min(1).max(64))
  authorise(ctx, invocation, { type: "project.read" }, { project: id }, ctx.now())
  return projectView(ctx, id)
}

// Today's variable change, as the subject member, with the platform's proof
// standing in for the passkey over item.update on the project's id.
// `before` is the value the platform last read; a stale one is a conflict.
async function setProjectVar(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext): Promise<unknown> {
  const input = routeInput(raw)
  const project = param(input, "project", z.string().min(1).max(64))
  const name = param(input, "name", VarName)
  const change = body(input, PlatformVarSetSchema)
  const setVar = projectWorkspaceOps["projects.setVar"]
  if (!setVar) throw new Error("projects.setVar is not registered")
  await subjectWrite(ctx, () => setVar.handler(ctx, principal, { project, name, env: change.env, before: variableSource(ctx, change.before), ...(change.plain !== undefined ? { plain: change.plain } : {}), ...(change.item !== undefined ? { item: change.item } : {}), ...(change.field !== undefined ? { field: change.field } : {}) }, invocation))
  return projectView(ctx, project)
}

// A platform's view of a value (a field of null is the kind's primary
// field) as the project code stores it.
function variableSource(ctx: VaultContext, value: PlatformVarValue | null): { kind: "plain"; value: string } | { kind: "item"; item: string; field: string } | null {
  if (value === null) return null
  if ("plain" in value) return { kind: "plain", value: value.plain }
  const item = items.getItem(ctx, value.item)
  return { kind: "item", item: value.item, field: value.field ?? (item ? KINDS[item.kind].primary ?? "" : "") }
}

async function removeProject(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext): Promise<unknown> {
  const input = routeInput(raw)
  body(input, PlatformEmptySchema)
  const remove = projectWorkspaceOps["projects.delete"]
  if (!remove) throw new Error("projects.delete is not registered")
  await subjectWrite(ctx, () => remove.handler(ctx, principal, { project: param(input, "project", z.string().min(1).max(64)) }, invocation))
  return { deleted: true }
}

// ---------------------------------------------------------------- audit and freeze: routes 27 to 29

function readAudit(ctx: VaultContext, raw: unknown): unknown {
  return platformAuditPage(ctx, query(routeInput(raw), PlatformAuditQuerySchema))
}

async function freeze(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext, frozen: boolean): Promise<unknown> {
  body(routeInput(raw), PlatformEmptySchema)
  const op = workspaceMemberOps[frozen ? "access.freeze" : "access.unfreeze"]
  if (!op) throw new Error("freeze is not registered")
  await subjectWrite(ctx, () => op.handler(ctx, principal, {}, invocation))
  return { frozen }
}

// ---------------------------------------------------------------- the area

type PlatformHandler = (ctx: VaultContext, principal: WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext) => unknown
const platformOp = (handler: PlatformHandler) => ({ auth: ["platform" as const], handler })

export const managedOps: NonNullable<Area["workspaceOps"]> = {
  "platform.subjects.ensure": platformOp((ctx, _p, raw, invocation) => { body(routeInput(raw), PlatformEmptySchema); return ensureSubject(ctx, invocation) }),
  "platform.subjects.get": platformOp((ctx) => (subjectView(ctx))),
  // Route 7, and the directory's sweep finishing a subject left deleting.
  "platform.subjects.remove": { auth: ["platform", "system"], async handler(ctx, _p, raw, invocation) {
    body(routeInput(raw), PlatformEmptySchema)
    const auth = invocation.auth
    return deleteSubject(ctx, auth.kind === "platform" ? `platform:${auth.platform}` : auth.kind === "system" && auth.actor !== undefined ? auth.actor : "system")
  } },
  // The directory's sweep, once a deleted subject's purge date has passed,
  // or at once for a platform being removed (`early`). System auth only: no
  // platform route reaches it.
  "platform.subjects.purge": { auth: ["system"], handler(ctx, _p, raw) {
    const { early } = body(routeInput(raw), z.strictObject({ early: z.literal(true).optional() }))
    return purgeSubject(ctx, early === true)
  } },
  "platform.devices.create": platformOp(createDevice),
  "platform.devices.list": platformOp((ctx) => listDevices(ctx)),
  "platform.devices.revoke": platformOp((ctx, p, raw) => revokeDevice(ctx, p, raw)),
  "platform.items.list": platformOp((ctx, _p, raw) => listItems(ctx, raw)),
  "platform.items.remove": platformOp((ctx, p, raw) => removeItem(ctx, p, raw)),
  "platform.intakes.create": platformOp(createIntake),
  "platform.intakes.submit": platformOp(submitIntake),
  "platform.intakes.cancel": platformOp(cancelIntake),
  "platform.approvals.list": platformOp((ctx, _p, raw) => listApprovals(ctx, raw)),
  "platform.approvals.get": platformOp((ctx, _p, raw) => (approvalView(ctx, approvalOf(ctx, param(routeInput(raw), "approval", z.string().min(1).max(64)))))),
  "platform.approvals.decide": platformOp(decideApproval),
  "platform.projects.create": platformOp(createProject),
  "platform.projects.get": platformOp((ctx, _p, raw, invocation) => getProject(ctx, raw, invocation)),
  "platform.projects.setVar": platformOp(setProjectVar),
  "platform.projects.remove": platformOp(removeProject),
  "platform.audit.read": platformOp((ctx, _p, raw) => readAudit(ctx, raw)),
  "platform.workspace.freeze": platformOp((ctx, p, raw, invocation) => freeze(ctx, p, raw, invocation, true)),
  "platform.workspace.unfreeze": platformOp((ctx, p, raw, invocation) => freeze(ctx, p, raw, invocation, false)),
}

export const managedArea: Area = {
  name: "managed",
  migrations: MANAGED_MIGRATIONS,
  workspaceOps: managedOps,
  async alarm(ctx, key) {
    if (key !== PURGE_KEY) return
    await purgeSubject(ctx)
  },
}

// Limits a platform's connect is held to when it starts (areas/oauth-workspace.ts):
// a new item counts the subject's items with its open intakes and connects
// for new items, all but an open connect for this same name, which this
// start replaces; and its open requests.
export function assertManagedConnectRoom(ctx: VaultContext, member: string, slug: string, newItem: boolean): void {
  const row = cachedManagedPlatform(ctx)
  if (!row) return
  if (newItem && count(ctx, "SELECT count(*) AS count FROM items") + openNewItemRequests(ctx, member, slug) >= row.platform.limits.itemsPerSubject) throw overLimit()
  if (openPlatformRequests(ctx, member) >= row.platform.limits.openRequestsPerSubject) throw overLimit()
}
