// Backups, layer 2 (`mehen backup export`): an owner registers an age
// recipient with a passkey; a day later it is active, and every owner and
// admin, and the owner, has been told. The registrant, from the browser or
// one of their own machines, asks for an export: this object opens every
// credential in their scope, builds one mehen-backup/v1 bundle in memory,
// encrypts it with age to that recipient and hands back only the
// ciphertext. Every exported item version is recorded as an exposure, and
// the audit names the export, never a value. A platform-managed workspace
// has none of it.

import { Encrypter } from "age-encryption"
import { z } from "zod"
import {
  BACKUP_EXCLUSION_REASONS,
  BACKUP_EXPORT_LIMITS,
  BACKUP_FORMAT,
  BACKUP_HIDDEN_ITEM,
  BACKUP_LIMITS,
  BACKUP_RECIPIENT_DELAY_MS,
  type BackupBundle,
  type BackupExportMeta,
  type BackupItem,
  type BackupProject,
  BackupRecipientAddSchema,
  BackupRecipientIdSchema,
  type BackupRecipientView,
  type BackupStatus,
  ageRecipientFingerprint,
  backupPlaintext,
  backupRecipientAddAction,
  sha256Hex,
  type WorkspaceNoticePayload,
} from "@mehen/protocol"
import { VaultError } from "../../http.ts"
import { type AccessCredential, type AccessPrincipal, type AccessState, backupScope, can } from "../access.ts"
import { type Area, one, randomId, rows, type VaultContext } from "../core.ts"
import { parseOpInput } from "./items.ts"
import { checkedCredential, openCredentialSecrets } from "./items-workspace.ts"
import { type AccessAllowed, accessState, authorise, eligibilityState, managedSetting, queueNotice, recordExposure, requireStepUp, workspaceRef, type WorkspaceInvocationContext, type WorkspaceRuntimePrincipal } from "./workspace-runtime.ts"

type RecipientRow = { id: string; recipient: string; label: string; registrant: string; registered_at: number; active_at: number; activated: number }
type ExportRow = { id: string; at: number; items: number }

const AREA = "backups"
const ACTIVATE = "activate:"
// Recipients with an export being built in this object. An export awaits
// while it opens values and encrypts, so a second one to the same recipient
// is refused here before it opens anything; the final transaction checks
// the ten-minute limit again for anything this misses.
const exporting = new WeakMap<DurableObjectStorage, Set<string>>()

function notManaged(ctx: VaultContext): void {
  if (managedSetting(ctx)) throw new VaultError("not_found", "No such operation.")
}

function memberPrincipal(principal: WorkspaceRuntimePrincipal): Extract<AccessPrincipal, { kind: "member" }> {
  if (principal.kind !== "member") throw new VaultError("forbidden", "Only a person signed in to the vault does this.")
  return principal
}

// The member a call stands for: the person, or the machine's owner.
function viewerMember(state: AccessState, principal: AccessPrincipal): string | null {
  if (principal.kind === "member") return principal.memberId
  const device = state.devices.find((d) => d.id === principal.deviceId)
  return device?.owner.kind === "member" ? device.owner.id : null
}

function actorOf(principal: AccessPrincipal): string {
  return principal.kind === "member" ? `member:${principal.memberId}` : `device:${principal.deviceId}`
}

function liveRecipients(ctx: VaultContext): RecipientRow[] {
  return rows(ctx.sql.exec<RecipientRow>("SELECT id,recipient,label,registrant,registered_at,active_at,activated FROM backup_recipients WHERE removed_at IS NULL ORDER BY registered_at,id"))
}

function liveRecipient(ctx: VaultContext, id: string): RecipientRow {
  const row = BackupRecipientIdSchema.safeParse(id).success ? one(ctx.sql.exec<RecipientRow>("SELECT id,recipient,label,registrant,registered_at,active_at,activated FROM backup_recipients WHERE id=? AND removed_at IS NULL", id)) : null
  if (!row) throw new VaultError("not_found", "No such backup recipient.")
  return row
}

function iso(ms: number): string {
  return new Date(ms).toISOString()
}

function notice(ctx: VaultContext, row: RecipientRow, change: "added" | "active" | "removed", by: string): void {
  const name = accessState(ctx).members.find((m) => m.id === row.registrant)?.name ?? ""
  const payload: WorkspaceNoticePayload = { kind: "backup_recipient", workspace: workspaceRef(ctx), member: row.registrant, name, recipient: { id: row.id, fingerprint: ageRecipientFingerprint(row.recipient), label: row.label }, change, activeAt: iso(row.active_at), by, at: iso(ctx.now()) }
  queueNotice(ctx, payload, `${row.id}:${change}`)
}

// In-scope credentials and variables changed after `since`; everything in
// scope when there is no export yet.
function changedSince(ctx: VaultContext, state: AccessState, member: string, since: number | null): number {
  const scope = backupScope(state, member, ctx.now())
  const after = since ?? -1
  let count = 0
  for (const c of scope.credentials) {
    const row = one(ctx.sql.exec<{ updated_at: number; rotated_at: number | null }>("SELECT updated_at,rotated_at FROM items WHERE id=?", c.id))
    if (row && Math.max(row.updated_at, row.rotated_at ?? 0) > after) count++
  }
  for (const p of scope.projects) count += one(ctx.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM vars WHERE project=? AND updated_at>?", p.id, after))?.n ?? 0
  return count
}

function lastExport(ctx: VaultContext, recipient: string): ExportRow | null {
  return one(ctx.sql.exec<ExportRow>("SELECT id,at,items FROM backup_exports WHERE recipient=? ORDER BY at DESC,id DESC LIMIT 1", recipient))
}

function status(ctx: VaultContext, principal: AccessPrincipal, invocation: WorkspaceInvocationContext): BackupStatus {
  const state = eligibilityState(ctx, invocation)
  const now = ctx.now()
  const viewer = viewerMember(state, principal)
  const live = liveRecipients(ctx)
  const recipients = live.map((row): BackupRecipientView => {
    const mine = row.registrant === viewer
    const last = mine ? lastExport(ctx, row.id) : null
    const active = now >= row.active_at
    return {
      id: row.id,
      recipient: row.recipient,
      fingerprint: ageRecipientFingerprint(row.recipient),
      label: row.label,
      status: active ? "active" : "pending",
      registrant: { member: row.registrant, name: state.members.find((m) => m.id === row.registrant)?.name ?? "" },
      mine,
      registeredAt: iso(row.registered_at),
      activeAt: iso(row.active_at),
      lastExport: last ? { id: last.id, at: iso(last.at), items: last.items } : null,
      changedSince: mine ? changedSince(ctx, state, row.registrant, last?.at ?? null) : null,
      rights: { export: active && can(state, principal, { type: "backup.export" }, { member: row.registrant }, now).allowed, remove: can(state, principal, { type: "backup.recipient_remove" }, { member: row.registrant }, now).allowed },
    }
  })
  return { recipients, rights: { add: live.length < BACKUP_LIMITS.maxRecipients && can(state, principal, { type: "backup.recipient_add" }, {}, now).allowed }, now: iso(now) }
}

const RecipientInput = z.strictObject({ id: z.string().min(1).max(128) })

async function addRecipient(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext): Promise<BackupRecipientView> {
  notManaged(ctx)
  const input = parseOpInput(BackupRecipientAddSchema, raw)
  const expected = await backupRecipientAddAction(input)
  const member = memberPrincipal(principal)
  const decision = authorise(ctx, invocation, { type: "backup.recipient_add" })
  requireStepUp(ctx, decision, expected, invocation)
  const live = liveRecipients(ctx)
  if (live.length >= BACKUP_LIMITS.maxRecipients) throw new VaultError("conflict", `This workspace already has ${BACKUP_LIMITS.maxRecipients} backup recipients; remove one first.`)
  if (live.some((r) => r.recipient === input.recipient)) throw new VaultError("conflict", "This recipient is already registered.")
  const now = ctx.now()
  const row: RecipientRow = { id: randomId("bkr"), recipient: input.recipient, label: input.label, registrant: member.memberId, registered_at: now, active_at: now + BACKUP_RECIPIENT_DELAY_MS, activated: 0 }
  ctx.storage.transactionSync(() => {
    ctx.sql.exec("INSERT INTO backup_recipients(id,recipient,label,registrant,registered_at,active_at,activated) VALUES (?,?,?,?,?,?,0)", row.id, row.recipient, row.label, row.registrant, row.registered_at, row.active_at)
    ctx.schedule(AREA, `${ACTIVATE}${row.id}`, row.active_at)
    ctx.audit({ actor: actorOf(member), action: "backup.recipient_add", target: row.id, detail: { fingerprint: ageRecipientFingerprint(row.recipient), label: row.label, activeAt: iso(row.active_at) } })
    notice(ctx, row, "added", member.memberId)
  })
  const view = status(ctx, member, invocation).recipients.find((r) => r.id === row.id)
  if (!view) throw new VaultError("internal", "The recipient was not stored.")
  return view
}

function removeRecipient(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext): { id: string; removed: true } {
  notManaged(ctx)
  const { id } = parseOpInput(RecipientInput, raw)
  const member = memberPrincipal(principal)
  const row = liveRecipient(ctx, id)
  const decision = authorise(ctx, invocation, { type: "backup.recipient_remove" }, { member: row.registrant })
  requireStepUp(ctx, decision, { type: "backup.recipient_remove", id: row.id }, invocation)
  ctx.storage.transactionSync(() => {
    ctx.sql.exec("UPDATE backup_recipients SET removed_at=?,removed_by=? WHERE id=?", ctx.now(), member.memberId, row.id)
    ctx.unschedule(AREA, `${ACTIVATE}${row.id}`)
    ctx.audit({ actor: actorOf(member), action: "backup.recipient_remove", target: row.id, detail: { fingerprint: ageRecipientFingerprint(row.recipient), label: row.label } })
    notice(ctx, row, "removed", member.memberId)
  })
  return { id: row.id, removed: true }
}

type Included = { credential: AccessCredential; item: BackupItem; valuesExported: boolean }

function itemOf(ctx: VaultContext, c: AccessCredential, secretFields: Record<string, string>): BackupItem {
  const slug = c.slug ?? ""
  const record = checkedCredential(ctx, slug)
  if (!record || record.id !== c.id) throw new VaultError("conflict", "A credential changed while it was being exported; try again.")
  const rotated = one(ctx.sql.exec<{ rotated_at: number | null }>("SELECT rotated_at FROM items WHERE id=?", c.id))?.rotated_at ?? null
  return { id: record.id, slug: record.slug, kind: record.kind, provider: record.provider, account: record.account, home: record.home, tags: record.tags, binding: record.binding, policy: record.policy, ceiling: record.ceiling, injection: record.injection, description: record.description, publicFields: record.publicFields, secretFields, version: record.version, rotatedAt: rotated === null ? null : iso(rotated) }
}

// The scope the export reads, as one comparable value: re-read at the
// final synchronous point, a change in between refuses the export.
function scopeFingerprint(ctx: VaultContext, state: AccessState, member: string): string {
  const scope = backupScope(state, member, ctx.now())
  const versions = scope.credentials.map((c) => [c.id, one(ctx.sql.exec<{ version: number; config_rev: number }>("SELECT version,config_rev FROM items WHERE id=?", c.id))])
  return JSON.stringify({ accessRev: state.accessRev, versions, fourEyes: scope.fourEyes.map((c) => c.id), projects: scope.projects.map((p) => p.id) })
}

// A reference names its credential's slug only when the export holds the
// credential or lists it as left out; any other (another member's private
// one, say) is BACKUP_HIDDEN_ITEM, as a project view shows it no slug.
function projectsOf(ctx: VaultContext, state: AccessState, projects: AccessState["projects"], exported: Set<string>, named: Set<string>): BackupProject[] {
  const slugOf = (id: string) => (named.has(id) ? (state.credentials.find((c) => c.id === id)?.slug ?? BACKUP_HIDDEN_ITEM) : BACKUP_HIDDEN_ITEM)
  return projects.map((p) => {
    const row = one(ctx.sql.exec<{ default_env: string }>("SELECT default_env FROM projects WHERE id=?", p.id))
    const remotes = rows(ctx.sql.exec<{ remote: string }>("SELECT remote FROM remotes WHERE project=? ORDER BY remote", p.id)).map((r) => r.remote)
    return {
      id: p.id,
      slug: p.slug,
      remotes,
      defaultEnv: row?.default_env ?? null,
      environments: p.environments.map((e) => ({
        name: e.name,
        protected: e.protected,
        fences: e.fences,
        fourEyes: e.fourEyes,
        vars: Object.fromEntries([
          ...Object.entries(e.plainVariables ?? {}).map(([name, plain]) => [name, { plain }] as const),
          ...e.references.map((r) => [r.variable, exported.has(r.item) ? { item: slugOf(r.item), field: r.field } : { item: slugOf(r.item), field: r.field, notExported: true as const }] as const),
        ]),
      })),
    }
  })
}

function overridesOf(ctx: VaultContext, member: string, projects: Set<string>): BackupBundle["overrides"] {
  type Row = { project: string; env: string; name: string; item: string | null; field: string | null; plain: string | null; slug: string | null }
  return rows(ctx.sql.exec<Row>("SELECT o.project,o.env,o.name,o.item,o.field,o.plain,i.slug FROM overrides o LEFT JOIN items i ON i.id=o.item WHERE o.member=? ORDER BY o.project,o.env,o.name", member))
    .filter((o) => projects.has(o.project))
    .map((o) => ({ project: o.project, environment: o.env, variable: o.name, source: o.item === null ? { kind: "plain" as const, value: o.plain ?? "" } : { kind: "item" as const, item: o.slug ?? o.item, field: o.field ?? "" } }))
}

async function ageEncrypt(plaintext: Uint8Array, recipient: string): Promise<Uint8Array<ArrayBuffer>> {
  const encrypter = new Encrypter()
  encrypter.addRecipient(recipient)
  return new Uint8Array(await encrypter.encrypt(plaintext))
}

export type BackupExportResult = { export: BackupExportMeta; ciphertext: Uint8Array<ArrayBuffer> }

async function exportBackup(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext): Promise<BackupExportResult> {
  notManaged(ctx)
  const { recipient: id } = parseOpInput(z.strictObject({ recipient: z.string().min(1).max(128) }), raw)
  if (principal.kind === "system") throw new VaultError("forbidden", "System calls have no member authority.")
  const row = liveRecipient(ctx, id)
  const first = authorise(ctx, invocation, { type: "backup.export" }, { member: row.registrant })
  const now = ctx.now()
  if (now < row.active_at) throw new VaultError("conflict", `This backup recipient becomes active at ${iso(row.active_at)}, a day after it was registered.`, { next: { say: "Wait until then; every owner and admin was told it was added and can remove it before." } })
  const last = lastExport(ctx, row.id)
  if (last && now - last.at < BACKUP_EXPORT_LIMITS.intervalMs) {
    const retryAfter = Math.ceil((last.at + BACKUP_EXPORT_LIMITS.intervalMs - now) / 1000)
    throw new VaultError("rate_limited", "One export per backup recipient every ten minutes.", { retryAfter })
  }
  const inFlight = exporting.get(ctx.storage) ?? new Set<string>()
  exporting.set(ctx.storage, inFlight)
  if (inFlight.has(row.id)) throw new VaultError("rate_limited", "An export to this backup recipient is already being made.", { retryAfter: BACKUP_EXPORT_LIMITS.intervalMs / 1000 })
  inFlight.add(row.id)
  try {
    return await buildExport(ctx, invocation, row, first, now)
  } finally {
    inFlight.delete(row.id)
  }
}

async function buildExport(ctx: VaultContext, invocation: WorkspaceInvocationContext, row: RecipientRow, first: AccessAllowed, now: number): Promise<BackupExportResult> {
  const state = accessState(ctx)
  const scope = backupScope(state, row.registrant, now)
  if (scope.credentials.length > BACKUP_EXPORT_LIMITS.maxItems) throw new VaultError("too_large", `An export holds at most ${BACKUP_EXPORT_LIMITS.maxItems} credentials; this scope has ${scope.credentials.length}.`)
  const before = scopeFingerprint(ctx, state, row.registrant)

  const included: Included[] = []
  for (const credential of scope.credentials) {
    const record = checkedCredential(ctx, credential.slug ?? "")
    if (!record || record.id !== credential.id) throw new VaultError("conflict", "A credential changed while it was being exported; try again.")
    const valuesExported = record.kind !== "oauth-connection"
    included.push({ credential, item: itemOf(ctx, credential, valuesExported ? await openCredentialSecrets(ctx, record) : {}), valuesExported })
  }
  const excluded = [
    ...scope.fourEyes.map((c) => ({ slug: c.slug ?? c.id, reason: BACKUP_EXCLUSION_REASONS.fourEyes })),
    ...included.filter((i) => !i.valuesExported).map((i) => ({ slug: i.item.slug, reason: BACKUP_EXCLUSION_REASONS.oauthConnection })),
  ].sort((a, b) => a.slug.localeCompare(b.slug))
  const registrant = state.members.find((m) => m.id === row.registrant)
  const head = one(ctx.sql.exec<{ seq: number; hash: string }>("SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1"))
  const bundle: BackupBundle = {
    format: BACKUP_FORMAT,
    id: randomId("bkx"),
    vault: ctx.env.VAULT_ORIGIN,
    workspace: workspaceRef(ctx),
    exportedAt: iso(now),
    registrant: { member: row.registrant, name: registrant?.name ?? "" },
    recipient: { id: row.id, fingerprint: ageRecipientFingerprint(row.recipient) },
    auditHead: head ? { seq: head.seq, hash: head.hash } : null,
    items: included.map((i) => i.item),
    projects: projectsOf(ctx, state, scope.projects, new Set(included.filter((i) => i.valuesExported).map((i) => i.credential.id)), new Set([...scope.credentials, ...scope.fourEyes].map((c) => c.id))),
    overrides: overridesOf(ctx, row.registrant, new Set(scope.projects.map((p) => p.id))),
    excluded,
  }
  const plaintext = new TextEncoder().encode(backupPlaintext(bundle))
  for (const item of bundle.items) item.secretFields = {}
  let ciphertext: Uint8Array<ArrayBuffer>
  try {
    if (plaintext.length > BACKUP_EXPORT_LIMITS.maxBytes) throw new VaultError("too_large", `An export holds at most ${BACKUP_EXPORT_LIMITS.maxBytes} bytes; this scope comes to more.`)
    ciphertext = await ageEncrypt(plaintext, row.recipient)
  } finally {
    plaintext.fill(0)
  }
  const sha256 = await sha256Hex(ciphertext)

  // The final point: live rights and the scope exactly as read.
  return ctx.storage.transactionSync(() => {
    const decision = authorise(ctx, invocation, first.action, first.target)
    if (liveRecipient(ctx, row.id).recipient !== row.recipient) throw new VaultError("conflict", "The backup recipient changed; try again.")
    if (scopeFingerprint(ctx, accessState(ctx), row.registrant) !== before) throw new VaultError("conflict", "Something in the export's scope changed while it was being built; try again.")
    const at = ctx.now()
    const latest = lastExport(ctx, row.id)
    if (latest && at - latest.at < BACKUP_EXPORT_LIMITS.intervalMs) throw new VaultError("rate_limited", "Another export to this backup recipient was made first; one every ten minutes.", { retryAfter: Math.ceil((latest.at + BACKUP_EXPORT_LIMITS.intervalMs - at) / 1000) })
    ctx.sql.exec("INSERT INTO backup_exports(id,recipient,actor,items,projects,excluded,bytes,sha256,at) VALUES (?,?,?,?,?,?,?,?,?)", bundle.id, row.id, actorOf(decision.principal), bundle.items.length, bundle.projects.length, bundle.excluded.length, ciphertext.length, sha256, at)
    const device = decision.principal.kind === "device" ? decision.principal.deviceId : null
    for (const i of included) if (i.valuesExported) recordExposure(ctx, { event: `export:${bundle.id}`, item: i.item.id, version: i.item.version, member: row.registrant, device, source: "exported", at })
    ctx.audit({ actor: actorOf(decision.principal), action: "backup.export", target: bundle.id, detail: { recipient: row.id, fingerprint: ageRecipientFingerprint(row.recipient), items: bundle.items.length, projects: bundle.projects.length, excluded: bundle.excluded.length, sha256 } })
    return {
      export: { id: bundle.id, workspace: bundle.workspace, recipient: bundle.recipient, exportedAt: bundle.exportedAt, items: bundle.items.length, projects: bundle.projects.length, excluded: bundle.excluded.length, ciphertext: { bytes: ciphertext.length, sha256 } },
      ciphertext,
    }
  })
}

function activate(ctx: VaultContext, id: string): void {
  const row = one(ctx.sql.exec<RecipientRow>("SELECT id,recipient,label,registrant,registered_at,active_at,activated FROM backup_recipients WHERE id=? AND removed_at IS NULL", id))
  if (!row || row.activated === 1) return
  if (ctx.now() < row.active_at) {
    ctx.schedule(AREA, `${ACTIVATE}${row.id}`, row.active_at)
    return
  }
  ctx.storage.transactionSync(() => {
    ctx.sql.exec("UPDATE backup_recipients SET activated=1 WHERE id=?", row.id)
    ctx.audit({ actor: "system", action: "backup.recipient_active", target: row.id, detail: { fingerprint: ageRecipientFingerprint(row.recipient), label: row.label } })
    notice(ctx, row, "active", "system")
  })
}

export const workspaceBackupOps = {
  "backup.status": { auth: ["account", "device"] as ("account" | "device")[], handler(ctx: VaultContext, principal: WorkspaceRuntimePrincipal, _raw: unknown, invocation: WorkspaceInvocationContext): BackupStatus {
    notManaged(ctx)
    const decision = authorise(ctx, invocation, { type: "backup.read" })
    return status(ctx, decision.principal, invocation)
  } },
  "backup.recipient_add": { auth: ["account"] as ("account" | "device")[], handler: addRecipient },
  "backup.recipient_remove": { auth: ["account"] as ("account" | "device")[], handler: removeRecipient },
  "backup.export": { auth: ["account", "device"] as ("account" | "device")[], handler: exportBackup },
}

export const backupsArea: Area = {
  name: AREA,
  migrations: [
    `CREATE TABLE backup_recipients (
       id TEXT PRIMARY KEY,
       recipient TEXT NOT NULL,
       label TEXT NOT NULL,
       registrant TEXT NOT NULL,
       registered_at INTEGER NOT NULL,
       active_at INTEGER NOT NULL,
       activated INTEGER NOT NULL DEFAULT 0,
       removed_at INTEGER,
       removed_by TEXT
     );
     CREATE TABLE backup_exports (
       id TEXT PRIMARY KEY,
       recipient TEXT NOT NULL REFERENCES backup_recipients (id),
       actor TEXT NOT NULL,
       items INTEGER NOT NULL,
       projects INTEGER NOT NULL,
       excluded INTEGER NOT NULL,
       bytes INTEGER NOT NULL,
       sha256 TEXT NOT NULL,
       at INTEGER NOT NULL
     );
     CREATE INDEX backup_exports_recipient ON backup_exports (recipient, at);`,
  ],
  workspaceOps: workspaceBackupOps,
  async alarm(ctx, key) {
    if (key.startsWith(ACTIVATE)) activate(ctx, key.slice(ACTIVATE.length))
  },
}
