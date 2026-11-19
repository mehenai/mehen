// Items: one credential each, its public fields in the clear and every
// secret field sealed on its own (envelope encryption, AAD bound to tenant,
// item and field). The storage core and ItemsService live here; the ops
// module adds the ops (list, describe, update, delete) and the intake area on top.

import { z } from "zod"
import {
  type BindingInput,
  BindingSchema,
  InjectionSchema,
  type ItemDescription,
  type ItemList,
  type ItemSummary,
  type SecretFieldInfo,
  KindSchema,
  ModeSchema,
  PolicySchema,
  Slug,
  type StepUpActionInput,
  Tag,
  canonicalJson,
} from "@mehen/protocol/api"
import { ADOPTION_LIMITS, type ItemBrowser, ItemBrowserSchema, type ItemKind, KINDS, type Mode, isItemKind, isSlug, modeAllowed, parseTotp, secretPrefix, sha256B64, validHostPattern } from "@mehen/protocol"
import { itemPolicyFloor } from "./policy.ts"
import { VaultError } from "../../http.ts"
import { refuseFillUnlessOn } from "../fill-unavailable.ts"
import { type Area, type Principal, type VaultContext, actorOf, blob, one, randomId, rows } from "../core.ts"
import type { ItemRecord, ItemsService, NewItem } from "../services.ts"
import { deviceCovers } from "./devices.ts"
import { credentialOps, workspaceItemOps } from "./items-workspace.ts"
import { workspacePostureOps } from "./postures-workspace.ts"
import { forgetConnection } from "./oauth.ts"
import { beforeManagementChange } from "./management-guard.ts"

// Op inputs arrive as `unknown` across the DO boundary; every op parses its own.
export function parseOpInput<T extends z.ZodType>(schema: T, input: unknown): z.infer<T> {
  const result = schema.safeParse(input ?? {})
  if (!result.success) {
    const issue = result.error.issues[0]
    throw new VaultError("bad_request", `Invalid request: ${issue ? `${issue.path.join(".") || "body"} ${issue.message}` : "bad shape"}.`)
  }
  return result.data
}

// What a passkey step-up commits to when it covers a change: the browser
// and the DO both compute base64url(SHA-256(canonicalJson(value))).
export function stepUpDigest(value: unknown): Promise<string> {
  return sha256B64(canonicalJson(value))
}

export function assertBindingHosts(binding: BindingInput): void {
  for (const host of binding.hosts) {
    if (!validHostPattern(host)) {
      throw new VaultError("bad_request", `"${host}" is not a host the vault can bind to: use a hostname such as api.example.com or *.example.com.`)
    }
  }
}

const ItemListInput = z.object({ tag: Tag.optional(), kind: KindSchema.optional(), provider: z.string().max(64).optional() })
const ItemSlugInput = z.object({ slug: Slug })

// Everything a member may change on an item, and nothing else: the step-up
// digest for "item.update" is stepUpDigest(change) over exactly this object.
export const ItemChange = z.strictObject({
  binding: BindingSchema.optional(),
  policy: PolicySchema.optional(),
  ceiling: ModeSchema.optional(),
  tags: z.array(Tag).max(16).optional(),
  description: z.string().max(500).nullable().optional(),
  // The pages a human added for fill; null clears them.
  browser: ItemBrowserSchema.nullable().optional(),
  pushable: z.boolean().optional(),
})
export type ItemChangeInput = z.infer<typeof ItemChange>
const ItemUpdateInput = z.object({ slug: Slug, change: ItemChange })

function visibleTo(principal: Principal, item: ItemRecord): boolean {
  return principal.kind === "device" ? deviceCovers(principal, item, "relay") : true
}

// The same refusal whether the item is missing or outside the device's scope,
// so a device cannot learn which slugs exist beyond what it may use.
function findVisible(ctx: VaultContext, principal: Principal, slug: string): ItemRecord {
  const item = items.getItem(ctx, slug)
  if (!item || !visibleTo(principal, item)) {
    const next = { command: "mehen ls", say: `There is no item called "${slug}" this machine may use; list the ones it can with \`mehen ls\`.` }
    throw new VaultError("not_found", `No item called "${slug}" is available here.`, principal.kind === "device" ? { next } : {})
  }
  return item
}

function requireAction<T extends StepUpActionInput["type"]>(principal: Principal, type: T): Extract<StepUpActionInput, { type: T }> {
  const stepUp = principal.kind === "member" ? principal.stepUp : null
  if (stepUp?.type !== type) throw new VaultError("forbidden", "This needs a passkey confirmation.")
  return stepUp as Extract<StepUpActionInput, { type: T }>
}

export function describeItem(ctx: VaultContext, item: ItemRecord): ItemDescription {
  const times = one(ctx.sql.exec<{ last_used_at: number | null; rotated_at: number | null }>("SELECT last_used_at, rotated_at FROM items WHERE id = ?", item.id))
  const iso = (ms: number | null | undefined) => (ms === null || ms === undefined ? null : new Date(ms).toISOString())
  return {
    ...items.summarise(item),
    description: item.description,
    publicFields: item.publicFields,
    secretFields: secretFieldInfo(ctx, item),
    binding: item.binding,
    policy: item.policy,
    policyFloor: itemPolicyFloor(item),
    injection: item.injection,
    version: item.version,
    lastUsedAt: iso(times?.last_used_at),
    rotatedAt: iso(times?.rotated_at),
  }
}

// How careful each credential is (postures-workspace.ts). item_postures:
// one row per credential once a posture was ever set (rev counts every
// change, so a page that read an older one is refused); catalogue and
// catalogue_version
// are what a routine or trust posture was signed at, null for ask.
// posture_ask_counts: the nudge's value-free counts, by credential and UTC
// day. posture_nudge_quiet: a person's "Not now".
export const ITEM_POSTURES_MIGRATION = `CREATE TABLE item_postures (item_id TEXT PRIMARY KEY, level TEXT NOT NULL, machines TEXT, catalogue TEXT, catalogue_version INTEGER, rev INTEGER NOT NULL, set_by TEXT NOT NULL, set_at INTEGER NOT NULL);
CREATE TABLE posture_ask_counts (item_id TEXT NOT NULL, day INTEGER NOT NULL, asked INTEGER NOT NULL DEFAULT 0, routine INTEGER NOT NULL DEFAULT 0, denied INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (item_id, day));
CREATE INDEX posture_ask_counts_day ON posture_ask_counts(day);
CREATE TABLE posture_nudge_quiet (member TEXT NOT NULL, item_id TEXT NOT NULL, until INTEGER NOT NULL, PRIMARY KEY (member, item_id));`

export const itemsArea: Area = {
  name: "items",
  migrations: [
    `CREATE TABLE items (
       id TEXT PRIMARY KEY,
       slug TEXT NOT NULL UNIQUE,
       kind TEXT NOT NULL,
       provider TEXT,
       account TEXT,
       account_verified INTEGER NOT NULL DEFAULT 0,
       tags TEXT NOT NULL,
       ceiling TEXT NOT NULL,
       binding TEXT NOT NULL,
       policy TEXT NOT NULL,
       injection TEXT,
       public_fields TEXT NOT NULL,
       status TEXT NOT NULL,
       status_reason TEXT,
       version INTEGER NOT NULL,
       description TEXT,
       created_at INTEGER NOT NULL,
       updated_at INTEGER NOT NULL,
       rotated_at INTEGER,
       last_used_at INTEGER
     );
     CREATE TABLE item_secrets (
       item TEXT NOT NULL REFERENCES items (id) ON DELETE CASCADE,
       name TEXT NOT NULL,
       root_version INTEGER NOT NULL,
       wrapped_dek BLOB NOT NULL,
       ciphertext BLOB NOT NULL,
       length INTEGER NOT NULL,
       prefix TEXT NOT NULL,
       fingerprint TEXT NOT NULL,
       PRIMARY KEY (item, name)
     );`,
    `ALTER TABLE items ADD COLUMN review_reason TEXT;
     ALTER TABLE items ADD COLUMN review_at INTEGER;`,
    // The root version whose fingerprint key wrote each fingerprint. NULL
    // for rows written before it was kept, which may be unkeyed SHA-256:
    // openSecrets recomputes those, and any under an older root version.
    `ALTER TABLE item_secrets ADD COLUMN fp_version INTEGER;`,
    `ALTER TABLE items ADD COLUMN config_rev INTEGER NOT NULL DEFAULT 0;`,
    `ALTER TABLE items ADD COLUMN home_kind TEXT NOT NULL DEFAULT 'workspace';
     ALTER TABLE items ADD COLUMN home_id TEXT;
     ALTER TABLE items ADD COLUMN dependency_revision INTEGER NOT NULL DEFAULT 0;
     CREATE TABLE credential_dependencies (connection TEXT PRIMARY KEY, client TEXT NOT NULL, client_revision INTEGER NOT NULL, revision INTEGER NOT NULL);
     CREATE INDEX credential_dependencies_client ON credential_dependencies(client);`,
    // The secret fields a person's rotation replaced, one set per item (the
    // latest), sealed exactly as item_secrets held them, until expires_at.
    // version: the item version those fields belonged to.
    `CREATE TABLE item_secret_history (
       item TEXT NOT NULL REFERENCES items (id) ON DELETE CASCADE,
       name TEXT NOT NULL,
       version INTEGER NOT NULL,
       root_version INTEGER NOT NULL,
       wrapped_dek BLOB NOT NULL,
       ciphertext BLOB NOT NULL,
       length INTEGER NOT NULL,
       prefix TEXT NOT NULL,
       fingerprint TEXT NOT NULL,
       fp_version INTEGER,
       replaced_at INTEGER NOT NULL,
       replaced_by TEXT NOT NULL,
       expires_at INTEGER NOT NULL,
       PRIMARY KEY (item, name)
     );
     CREATE INDEX item_secret_history_expires ON item_secret_history(expires_at);`,
    // ItemBrowser JSON, or NULL: the pages a human added for fill. Set only
    // by items.update, which bumps config_rev with it.
    `ALTER TABLE items ADD COLUMN browser TEXT;`,
    // May be put into other services' secret stores (push-allowance.ts).
    `ALTER TABLE items ADD COLUMN pushable INTEGER NOT NULL DEFAULT 0;`,
    ITEM_POSTURES_MIGRATION,
  ],
  get workspaceOps() { return credentialOps({ ...workspaceItemOps, ...workspacePostureOps }) },
  async alarm(ctx, key) {
    if (key === SECRET_HISTORY_SWEEP_KEY) sweepSecretHistory(ctx)
  },
}

// Which overwrites keep the replaced fields, by the action the store records:
// a person's rotation (an intake's, or an adoption's replace) and a restore.
// An OAuth connection keeps none, however it is overwritten (a refresh, a
// reconnect, an intake or an adoption's replace), so no old token outlives it.
const KEEPS_REPLACED = new Set(["item.rotate", "item.restore"])
export const SECRET_HISTORY_SWEEP_KEY = "secret-history"

// Inside the caller's transaction, before it overwrites item_secrets: the
// fields it is about to replace become the item's one kept set, replacing
// any kept before. `by` is the audit actor (member:<id> or device:<id>).
export function keepReplacedSecrets(ctx: VaultContext, item: { id: string; version: number; kind: string }, action: string, by: string): void {
  if (!KEEPS_REPLACED.has(action) || item.kind === "oauth-connection") return
  const now = ctx.now()
  ctx.sql.exec("DELETE FROM item_secret_history WHERE item = ?", item.id)
  ctx.sql.exec(
    `INSERT INTO item_secret_history (item, name, version, root_version, wrapped_dek, ciphertext, length, prefix, fingerprint, fp_version, replaced_at, replaced_by, expires_at)
     SELECT item, name, ?, root_version, wrapped_dek, ciphertext, length, prefix, fingerprint, fp_version, ?, ?, ? FROM item_secrets WHERE item = ?`,
    item.version,
    now,
    by,
    now + ADOPTION_LIMITS.replacedKeptMs,
    item.id,
  )
  sweepSecretHistory(ctx)
}

// Every kept set past its expiry goes, and the items alarm is set for the next.
export function sweepSecretHistory(ctx: VaultContext): void {
  const now = ctx.now()
  ctx.sql.exec("DELETE FROM item_secret_history WHERE expires_at <= ?", now)
  const due = one(ctx.sql.exec<{ due: number | null }>("SELECT MIN(expires_at) AS due FROM item_secret_history"))?.due ?? null
  if (due === null) ctx.unschedule("items", SECRET_HISTORY_SWEEP_KEY)
  else ctx.schedule("items", SECRET_HISTORY_SWEEP_KEY, due)
}

export type KeptSecret = { name: string; version: number; root_version: number; wrapped_dek: ArrayBuffer; ciphertext: ArrayBuffer; length: number; prefix: string; fingerprint: string; fp_version: number | null; replaced_at: number; replaced_by: string; expires_at: number }

// The item's kept set while it is restorable, whatever the sweep has done yet.
export function keptSecrets(ctx: VaultContext, itemId: string): KeptSecret[] {
  return rows(ctx.sql.exec<KeptSecret>("SELECT name, version, root_version, wrapped_dek, ciphertext, length, prefix, fingerprint, fp_version, replaced_at, replaced_by, expires_at FROM item_secret_history WHERE item = ? AND expires_at > ? ORDER BY name", itemId, ctx.now()))
}

type ItemRow = {
  id: string
  slug: string
  kind: string
  provider: string | null
  account: string | null
  account_verified: number
  tags: string
  ceiling: string
  binding: string
  policy: string
  injection: string | null
  public_fields: string
  status: string
  status_reason: string | null
  version: number
  config_rev: number
  description: string | null
  created_at: number
  updated_at: number
  rotated_at: number | null
  last_used_at: number | null
  review_reason: string | null
  review_at: number | null
  browser: string | null
}

const ITEM_COLUMNS =
  "id, slug, kind, provider, account, account_verified, tags, ceiling, binding, policy, injection, public_fields, status, status_reason, version, description, created_at, updated_at, rotated_at, last_used_at, review_reason, review_at, config_rev"

function toRecord(row: ItemRow): ItemRecord {
  if (!isItemKind(row.kind)) throw new Error("corrupt item kind")
  return {
    id: row.id,
    slug: row.slug,
    kind: row.kind,
    provider: row.provider,
    account: row.account,
    accountVerified: row.account_verified === 1,
    tags: JSON.parse(row.tags) as string[],
    ceiling: row.ceiling as ItemRecord["ceiling"],
    binding: JSON.parse(row.binding) as ItemRecord["binding"],
    policy: JSON.parse(row.policy) as ItemRecord["policy"],
    injection: row.injection ? (JSON.parse(row.injection) as ItemRecord["injection"]) : null,
    publicFields: JSON.parse(row.public_fields) as Record<string, string>,
    browser: row.browser === null ? null : (JSON.parse(row.browser) as ItemBrowser),
    status: row.status as ItemRecord["status"],
    review: row.review_reason !== null && row.review_at !== null ? { reason: row.review_reason, at: row.review_at } : null,
    version: row.version,
    configRev: row.config_rev,
    description: row.description,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastUsedAt: row.last_used_at,
  }
}

export function secretRef(item: { id: string }, field: string) {
  return { type: "item-secret", id: `${item.id}/${field}` }
}

// Keyed, so someone holding only DO storage cannot test guesses against it.
// A stored fingerprint is only ever compared with one computed under the
// root version stored beside it (item_secrets.fp_version).
export async function fingerprint(ctx: Parameters<ItemsService["openSecrets"]>[0], itemId: string, value: string, version: number): Promise<string> {
  const digest = await crypto.subtle.sign("HMAC", await ctx.fingerprintKey(version), new TextEncoder().encode(`${itemId}\n${value}`))
  let bin = ""
  for (const b of new Uint8Array(digest)) bin += String.fromCharCode(b)
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "").slice(0, 12)
}

// A fill ceiling only for a kind with something fill may type (KindSpec.fill).
export function assertFillableKind(kind: ItemKind, ceiling: Mode): void {
  if (ceiling === "fill" && KINDS[kind].fill.length === 0) throw new VaultError("mode_refused", "This kind of credential cannot be typed into web pages.")
}

// Every one-time code secret is read before it is stored, so a code can
// always be computed from it; the refusal never repeats the secret.
export function assertTotpSeedsReadable(kind: ItemKind, secretFields: Record<string, string>): void {
  for (const field of KINDS[kind].fill) {
    if (field.input !== "one-time-code") continue
    const seed = secretFields[field.source]
    if (seed === undefined || seed === "") continue
    const parsed = parseTotp(seed)
    if (!parsed.ok) throw new VaultError("totp_unreadable", `The one-time code secret cannot be read. ${parsed.reason}`)
  }
}

// Everything a new or replaced item must satisfy, checked before any write.
export function validateNewItem(input: NewItem): void {
  if (!isSlug(input.slug)) throw new VaultError("bad_request", `"${input.slug}" is not a valid item name: lowercase letters, digits and single hyphens.`)
  if (!isItemKind(input.kind)) throw new VaultError("bad_request", `Unknown kind "${input.kind}".`)
  const spec = KINDS[input.kind]
  assertFillableKind(input.kind, input.ceiling)
  if (!modeAllowed(spec.maxCeiling, input.ceiling)) {
    throw new VaultError("mode_refused", `A ${spec.label} can never be exposed beyond "${spec.maxCeiling}".`)
  }
  if (!BindingSchema.safeParse(input.binding).success) throw new VaultError("bad_request", "Every item needs a valid binding: at least one host.")
  if (!PolicySchema.safeParse(input.policy).success) throw new VaultError("bad_request", "Invalid policy.")
  if (input.injection !== null && !InjectionSchema.safeParse(input.injection).success) throw new VaultError("bad_request", "Invalid injection.")
  const known = new Map(spec.fields.map((field) => [field.name, field]))
  for (const name of Object.keys(input.publicFields)) {
    const field = known.get(name)
    if (!field || field.secret) throw new VaultError("bad_request", `"${name}" is not a public field of a ${spec.label}.`)
  }
  for (const name of Object.keys(input.secretFields)) {
    const field = known.get(name)
    if (!field || !field.secret) throw new VaultError("bad_request", `"${name}" is not a secret field of a ${spec.label}.`)
    if ((input.secretFields[name] ?? "").length > 65_536) throw new VaultError("too_large", `"${name}" is too large.`)
  }
  for (const field of spec.fields) {
    if (!field.required) continue
    const value = field.secret ? input.secretFields[field.name] : input.publicFields[field.name]
    if (value === undefined || value === "") throw new VaultError("bad_request", `${spec.label} needs "${field.label}".`)
  }
  assertTotpSeedsReadable(input.kind, input.secretFields)
  for (const tag of input.tags) if (!/^[a-z0-9][a-z0-9:_-]{0,39}$/.test(tag)) throw new VaultError("bad_request", `Invalid tag "${tag}".`)
}

export type SealedSecret = { name: string; length: number; prefix: string; fingerprint: string; fpVersion: number; sealed: import("../core.ts").SealedField }

// Async half: encrypt. Nothing is written, so a failure leaves no trace.
export async function sealSecrets(ctx: Parameters<ItemsService["openSecrets"]>[0], itemId: string, secrets: Record<string, string>): Promise<SealedSecret[]> {
  const fpVersion = ctx.rootVersion
  return Promise.all(
    Object.entries(secrets).map(async ([name, value]) => ({
      name,
      length: value.length,
      prefix: secretPrefix(value),
      fingerprint: await fingerprint(ctx, itemId, value, fpVersion),
      fpVersion,
      sealed: await ctx.sealField(secretRef({ id: itemId }, name), new Uint8Array(new TextEncoder().encode(value))),
    })),
  )
}

// Sync half: write, inside the caller's transaction.
export function storeSecrets(ctx: Parameters<ItemsService["openSecrets"]>[0], itemId: string, sealed: SealedSecret[]): void {
  for (const s of sealed) {
    ctx.sql.exec(
      `INSERT INTO item_secrets (item, name, root_version, wrapped_dek, ciphertext, length, prefix, fingerprint, fp_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (item, name) DO UPDATE SET root_version = excluded.root_version, wrapped_dek = excluded.wrapped_dek,
         ciphertext = excluded.ciphertext, length = excluded.length, prefix = excluded.prefix, fingerprint = excluded.fingerprint, fp_version = excluded.fp_version`,
      itemId,
      s.name,
      s.sealed.rootVersion,
      s.sealed.wrappedDek,
      s.sealed.ciphertext,
      s.length,
      s.prefix,
      s.fingerprint,
      s.fpVersion,
    )
  }
}

// A rotation's write, inside the caller's transaction: the new values,
// then the version bump, and nothing written before them, so the values
// and version being replaced are still current on entry. The caller
// audits `item.rotate`.
export function storeReplacedSecrets(ctx: VaultContext, item: ItemRecord, sealed: SealedSecret[], _actor: Principal): void {
  storeSecrets(ctx, item.id, sealed)
  ctx.sql.exec("UPDATE items SET version = version + 1, updated_at = ?, rotated_at = ? WHERE id = ?", ctx.now(), ctx.now(), item.id)
}

export function secretFieldInfo(ctx: VaultContext, item: ItemRecord): SecretFieldInfo[] {
  const present = rows(
    ctx.sql.exec<{ name: string; length: number; prefix: string; fingerprint: string }>(
      "SELECT name, length, prefix, fingerprint FROM item_secrets WHERE item = ? ORDER BY name",
      item.id,
    ),
  )
  const byName = new Map(present.map((p) => [p.name, p]))
  return KINDS[item.kind].fields
    .filter((f) => f.secret)
    .map((f) => {
      const p = byName.get(f.name)
      return { name: f.name, set: p !== undefined, length: p?.length ?? 0, prefix: p?.prefix ?? "", fingerprint: p?.fingerprint ?? "" }
    })
}

export const items: ItemsService = {
  secretFieldMetadata: secretFieldInfo,

  getItem(ctx, slug) {
    const row = one(ctx.sql.exec<ItemRow>(`SELECT ${ITEM_COLUMNS}, browser FROM items WHERE slug = ?`, slug))
    return row ? toRecord(row) : null
  },

  async openSecrets(ctx, item) {
    const stored = rows(
      ctx.sql.exec<{ name: string; root_version: number; wrapped_dek: ArrayBuffer; ciphertext: ArrayBuffer; fp_version: number | null }>(
        "SELECT name, root_version, wrapped_dek, ciphertext, fp_version FROM item_secrets WHERE item = ?",
        item.id,
      ),
    )
    const out: Record<string, string> = {}
    const current = ctx.rootVersion
    const stale: { name: string; fingerprint: string }[] = []
    for (const s of stored) {
      const plain = await ctx.openField(secretRef(item, s.name), {
        rootVersion: s.root_version,
        wrappedDek: blob(s.wrapped_dek),
        ciphertext: blob(s.ciphertext),
      })
      const value = new TextDecoder().decode(plain)
      out[s.name] = value
      if (s.fp_version === null || s.fp_version < current) stale.push({ name: s.name, fingerprint: await fingerprint(ctx, item.id, value, current) })
    }
    // A value replaced meanwhile already carries a current fingerprint, so
    // only rows still stale are rewritten.
    for (const s of stale) {
      ctx.sql.exec(
        "UPDATE item_secrets SET fingerprint = ?, fp_version = ? WHERE item = ? AND name = ? AND (fp_version IS NULL OR fp_version < ?)",
        s.fingerprint,
        current,
        item.id,
        s.name,
        current,
      )
    }
    ctx.sql.exec("UPDATE items SET last_used_at = ? WHERE id = ?", ctx.now(), item.id)
    return out
  },

  async putItem(ctx, input, actor: Principal, options) {
    validateNewItem(input)
    refuseFillUnlessOn(ctx, [input.ceiling])
    const existing = items.getItem(ctx, input.slug)
    if (existing && !options?.replace) {
      throw new VaultError("conflict", `An item called "${input.slug}" already exists. Pick another name, or replace it from the vault.`)
    }
    const now = ctx.now()
    const id = existing?.id ?? randomId("itm")
    const sealed = await sealSecrets(ctx, id, input.secretFields)
    ctx.storage.transactionSync(() => {
      if (existing) {
        ctx.sql.exec(
          `UPDATE items SET kind = ?, provider = ?, account = ?, account_verified = ?, tags = ?, ceiling = ?, binding = ?, policy = ?, injection = ?,
             public_fields = ?, status = 'active', status_reason = NULL, review_reason = NULL, review_at = NULL, version = version + 1, config_rev = config_rev + 1, description = ?, updated_at = ?, rotated_at = ? WHERE id = ?`,
          input.kind,
          input.provider,
          input.account,
          input.accountVerified ? 1 : 0,
          JSON.stringify(input.tags),
          input.ceiling,
          JSON.stringify(input.binding),
          JSON.stringify(input.policy),
          input.injection ? JSON.stringify(input.injection) : null,
          JSON.stringify(input.publicFields),
          input.description,
          now,
          now,
          id,
        )
        const keep = Object.keys(input.secretFields)
        for (const field of secretFieldInfo(ctx, existing)) {
          if (field.set && !keep.includes(field.name)) ctx.sql.exec("DELETE FROM item_secrets WHERE item = ? AND name = ?", id, field.name)
        }
        storeSecrets(ctx, id, sealed)
      } else {
        beforeManagementChange(ctx)
        ctx.sql.exec(
          `INSERT INTO items (${ITEM_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', NULL, 1, ?, ?, ?, NULL, NULL, NULL, NULL, 0)`,
          id,
          input.slug,
          input.kind,
          input.provider,
          input.account,
          input.accountVerified ? 1 : 0,
          JSON.stringify(input.tags),
          input.ceiling,
          JSON.stringify(input.binding),
          JSON.stringify(input.policy),
          input.injection ? JSON.stringify(input.injection) : null,
          JSON.stringify(input.publicFields),
          input.description,
          now,
          now,
        )
        storeSecrets(ctx, id, sealed)
      }
      ctx.audit({ actor: actorOf(actor), action: existing ? "item.replace" : "item.create", target: input.slug, detail: { kind: input.kind, provider: input.provider } })
    })
    return items.getItem(ctx, input.slug) as ItemRecord
  },

  deleteItem(ctx, item, actor) {
    beforeManagementChange(ctx)
    ctx.sql.exec("DELETE FROM item_secret_history WHERE item = ?", item.id)
    ctx.sql.exec("DELETE FROM item_secrets WHERE item = ?", item.id)
    ctx.sql.exec("DELETE FROM items WHERE id = ?", item.id)
    ctx.audit({ actor: actorOf(actor), action: "item.delete", target: item.slug, detail: { kind: item.kind, hosts: item.binding.hosts } })
  },

  async replaceSecrets(ctx, slug, secrets, actor) {
    const item = items.getItem(ctx, slug)
    if (!item) throw new VaultError("not_found", `No item called "${slug}".`)
    const spec = KINDS[item.kind]
    for (const name of Object.keys(secrets)) {
      if (!spec.fields.some((f) => f.name === name && f.secret)) throw new VaultError("bad_request", `"${name}" is not a secret field of a ${spec.label}.`)
    }
    assertTotpSeedsReadable(item.kind, secrets)
    const sealed = await sealSecrets(ctx, item.id, secrets)
    ctx.storage.transactionSync(() => storeReplacedSecrets(ctx, item, sealed, actor))
    ctx.audit({ actor: actorOf(actor), action: "item.rotate", target: slug, detail: { fields: Object.keys(secrets).sort() } })
    return items.getItem(ctx, slug) as ItemRecord
  },

  setStatus(ctx, slug, status, reason) {
    ctx.sql.exec("UPDATE items SET status = ?, status_reason = ?, updated_at = ? WHERE slug = ?", status, reason, ctx.now(), slug)
  },

  flagForReview(ctx, slug, reason) {
    ctx.sql.exec("UPDATE items SET review_reason = ?, review_at = ? WHERE slug = ?", reason, ctx.now(), slug)
  },

  summarise(item): ItemSummary {
    return {
      slug: item.slug,
      kind: item.kind,
      provider: item.provider,
      account: item.account,
      accountVerified: item.accountVerified,
      tags: item.tags,
      ceiling: item.ceiling,
      hosts: item.binding.hosts,
      status: item.status,
      ...(item.review ? { review: { reason: item.review.reason, since: new Date(item.review.at).toISOString() } } : {}),
      updatedAt: new Date(item.updatedAt).toISOString(),
      lastUsedAt: typeof item.lastUsedAt === "number" ? new Date(item.lastUsedAt).toISOString() : null,
      policy: item.policy,
    }
  },
}
