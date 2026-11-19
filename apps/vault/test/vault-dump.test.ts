// The operator's backup of the vault itself (areas/vault-backup.ts, the
// cron's directory/vault-backups.ts and scripts/vault-backup.ts): a dump
// opens only as its own workspace, under its own root key version and
// generation, restores row for row into an empty object, and is reached by
// system calls alone. PITR is not available in workerd, so its path runs
// against a stubbed storage. Each real restart is ctx.abort("vault restore"),
// which workerd logs as "uncaught exception ... broken.outputGateBroken;
// jsg.Error: vault restore": the runtime logs an abort's error and no code
// can catch it, so those lines are the four restarts here, not a failure.
import { describe, expect, it, vi } from "vitest"
import { env } from "cloudflare:workers"
import { base64UrlEncode, canonicalJson, utf8 } from "@mehen/protocol"
import type { InvocationResult, VaultContext, WorkspaceInvocation } from "../src/vault/core.ts"
import { MAX_DUMP_DATABASE_BYTES, backupObjectKey, monthlyObjectKey, openVaultDump, sha256Hex, utcDate, vaultBackupOps, dumpVault, type DumpResult } from "../src/vault/areas/vault-backup.ts"
import { WORKSPACE_GENERATION } from "../src/directory/workspace-cutover.ts"
import { VAULT_BACKUP_BATCH, backUpWorkspaceVaults, restoreIntentDigest, runVaultRestores, vaultBackupClient, type VaultBackupClient } from "../src/directory/vault-backups.ts"
import { maintainWorkspaceDirectory } from "../src/directory/workspace-maintenance.ts"
import { VaultError } from "../src/http.ts"
import { secretRef } from "../src/vault/areas/items.ts"
import { auditLine } from "../src/ui/wording.ts"
import { parseArgs, runVaultBackup, type VaultBackupIo } from "../scripts/vault-backup.ts"
import { accountAuth, inAccess } from "./access-test-support.ts"
import { credentialsFixture, seedCredential } from "./credentials-test-support.ts"
import { platformAuth } from "./managed-support.ts"
import { createWorkspaceFixture, type WorkspaceTestFixture } from "./workspace-fixtures.ts"
import { beforeManagementChange } from "../src/vault/areas/management-guard.ts"

const SECRET = "test-secret-never-returned"
const SLUG = "acme-billing-ledger-key"
const SYSTEM = { kind: "system", reason: "test" } as const
let intents = 0
const intentId = () => `vri_${(++intents).toString(16).padStart(8, "0")}${"0".repeat(24)}`

function invoke(tenant: string, op: string, input: unknown, auth: WorkspaceInvocation["auth"] = SYSTEM): Promise<InvocationResult> {
  return env.TENANT_VAULT.getByName(tenant).invoke({ op, input, auth }) as Promise<InvocationResult>
}
async function value<T>(tenant: string, op: string, input: unknown): Promise<T> {
  const result = await invoke(tenant, op, input)
  if (!result.ok) throw new Error(`${op}: ${result.error.vaultError.error}: ${result.error.vaultError.message}`)
  return result.value as T
}
async function refusal(tenant: string, op: string, input: unknown, auth: WorkspaceInvocation["auth"] = SYSTEM) {
  const result = await invoke(tenant, op, input, auth)
  if (result.ok) throw new Error(`${op} was not refused`)
  return { error: result.error.vaultError.error, message: result.error.vaultError.message }
}

async function seededWorkspace(): Promise<string> {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => { await seedCredential(ctx, SLUG); await seedCredential(ctx, "second-key") })
  return f.tenant
}

function hex(value: ArrayBuffer): string {
  return Array.from(new Uint8Array(value), (b) => b.toString(16).padStart(2, "0")).join("")
}
// Every application table and its rows, BLOBs as hex, in a stable order.
function snapshot(ctx: VaultContext): { schema: string[]; tables: { name: string; rows: string[] }[] } {
  const schema = ctx.sql.exec<{ type: string; name: string; sql: string }>("SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*' ORDER BY type, name").toArray()
  return {
    schema: schema.map((entry) => `${entry.type} ${entry.name}: ${entry.sql}`),
    tables: schema.filter((entry) => entry.type === "table").map(({ name }) => ({ name, rows: ctx.sql.exec(`SELECT * FROM "${name}"`).toArray().map((row) => JSON.stringify(Object.fromEntries(Object.entries(row).map(([k, v]) => [k, v instanceof ArrayBuffer ? `hex:${hex(v)}` : v])))).sort() })),
  }
}
// What a lost object looks like: every table there, every row gone but
// the migrations and the generation marker.
function wipe(ctx: VaultContext): void {
  const tables = ctx.sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*' AND name NOT IN ('_migrations','_workspace_generation') ORDER BY rowid DESC").toArray()
  ctx.storage.transactionSync(() => {
    ctx.sql.exec("PRAGMA defer_foreign_keys = ON")
    beforeManagementChange(ctx)
    for (const { name } of tables) ctx.sql.exec(`DELETE FROM "${name}"`)
  })
}
// The object writes a dump only for its own today: other days' dumps are
// written through a context whose clock is at noon that day.
function onDay(ctx: VaultContext, date: string): VaultContext {
  return Object.assign(Object.create(ctx) as VaultContext, { now: () => Date.parse(`${date}T12:00:00.000Z`) })
}
async function dumpOn(tenant: string, date: string): Promise<DumpResult> {
  const result = await inAccess(tenant, (ctx) => dumpVault(onDay(ctx, date), date))
  if ("refused" in result) throw new Error(result.message)
  return result
}
async function stored(tenant: string, date: string): Promise<Uint8Array<ArrayBuffer>> {
  const object = await env.VAULT_BACKUPS.get(backupObjectKey(tenant, date))
  if (!object) throw new Error("no dump in the bucket")
  return new Uint8Array(await object.arrayBuffer())
}
function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer
    return true
  }
  return false
}

describe("vaultbackup.dump", () => {
  it("writes ws/<tenant>/<date>.bin holding no test secret's bytes and no slug in the clear, opening only with the object's own keys", async () => {
    const tenant = await seededWorkspace(), today = utcDate(Date.now())
    const result = await value<{ key: string; bytes: number; sha256: string; rootVersion: number }>(tenant, "vaultbackup.dump", { date: today })
    const bytes = await stored(tenant, today)
    expect(result).toEqual({ date: today, key: `ws/${tenant}/${today}.bin`, bytes: bytes.length, sha256: await sha256Hex(bytes), rootVersion: 1 })
    const sealedSecrets = await inAccess(tenant, (ctx) => ctx.sql.exec<{ ciphertext: ArrayBuffer }>("SELECT ciphertext FROM item_secrets").toArray().map((row) => new Uint8Array(row.ciphertext)))
    expect(sealedSecrets.length).toBe(2)
    const needles = [utf8(SECRET), utf8(btoa(SECRET)), utf8(base64UrlEncode(utf8(SECRET))), utf8(SLUG), utf8("second-key"), ...sealedSecrets.map((secret) => secret.slice(0, 24))]
    for (const needle of needles) expect(contains(bytes, needle)).toBe(false)
    // The needles are meaningful: opened with the object's own keys, the
    // dump has the slugs and the sealed secret blobs, and still no secret in the clear.
    const opened = await inAccess(tenant, (ctx) => openVaultDump(ctx, today, bytes))
    const text = JSON.stringify(opened)
    expect(text).toContain(SLUG)
    expect(text).not.toContain(SECRET)
    expect(opened.tables.map((table) => table.name)).toEqual(expect.arrayContaining(["_migrations", "_workspace_generation", "items", "item_secrets", "audit"]))
    expect(opened.tables.find((table) => table.name === "_workspace_generation")?.rows).toEqual([[WORKSPACE_GENERATION]])
    expect(opened.tables.some((table) => table.name.startsWith("_cf_") || table.name.startsWith("sqlite_"))).toBe(false)
  })

  it("is idempotent per tenant and date, keeps the first of the month under monthly/, and refuses an empty object", async () => {
    const tenant = await seededWorkspace()
    const first = await dumpOn(tenant, "2026-11-01")
    await inAccess(tenant, async (ctx) => { await seedCredential(ctx, "later-key") })
    expect(await dumpOn(tenant, "2026-11-01")).toEqual(first)
    const monthly = await env.VAULT_BACKUPS.get(monthlyObjectKey(tenant, "2026-11-01"))
    expect(monthly && await sha256Hex(new Uint8Array(await monthly.arrayBuffer()))).toBe(first.sha256)
    await dumpOn(tenant, "2026-10-30")
    expect(await env.VAULT_BACKUPS.head(monthlyObjectKey(tenant, "2026-10-30"))).toBeNull()
    const empty = (await credentialsFixture()).tenant, today = utcDate(Date.now())
    await inAccess(empty, wipe)
    expect(await refusal(empty, "vaultbackup.dump", { date: today })).toEqual({ error: "conflict", message: "This workspace object is empty; nothing was dumped." })
    expect(await env.VAULT_BACKUPS.head(backupObjectKey(empty, today))).toBeNull()
  })

  it("writes only today's UTC date", async () => {
    const tenant = await seededWorkspace(), now = Date.now()
    for (const date of [utcDate(now - 86_400_000), utcDate(now + 86_400_000), "2027-01-01"]) {
      expect(await refusal(tenant, "vaultbackup.dump", { date })).toEqual({ error: "bad_request", message: "A dump is written only for today's UTC date." })
      expect(await env.VAULT_BACKUPS.head(backupObjectKey(tenant, date))).toBeNull()
    }
  })

  it("records an object already at today's key only if it opens as this workspace's dump of today, and a monthly copy only if it is the same bytes", async () => {
    const tenant = await seededWorkspace(), other = await seededWorkspace(), today = utcDate(Date.now())
    const refused = { date: today, key: backupObjectKey(tenant, today), refused: "backup_corrupt", message: "The object already at today's key does not open as this workspace's dump of today; it is not a backup." }
    // Planted: a well-formed header over bytes that are not a dump.
    await env.VAULT_BACKUPS.put(backupObjectKey(tenant, today), utf8(`${JSON.stringify({ format: "mehen-vault-backup/v1", tenant, date: today, rootVersion: 1 })}\n${"x".repeat(64)}`))
    expect(await value(tenant, "vaultbackup.dump", { date: today })).toEqual(refused)
    // Another workspace's real dump of today.
    await value(other, "vaultbackup.dump", { date: today })
    await env.VAULT_BACKUPS.put(backupObjectKey(tenant, today), await stored(other, today))
    expect(await value(tenant, "vaultbackup.dump", { date: today })).toEqual(refused)
    // This workspace's own dump of another day under today's key.
    const yesterday = utcDate(Date.now() - 86_400_000)
    await dumpOn(tenant, yesterday)
    await env.VAULT_BACKUPS.put(backupObjectKey(tenant, today), await stored(tenant, yesterday))
    expect(await value(tenant, "vaultbackup.dump", { date: today })).toEqual(refused)
    // Its real dump of today is answered as it is.
    await env.VAULT_BACKUPS.delete(backupObjectKey(tenant, today))
    const real = await value<{ sha256: string }>(tenant, "vaultbackup.dump", { date: today })
    expect(await value(tenant, "vaultbackup.dump", { date: today })).toEqual(real)
    // On the first of the month, a monthly object that is not the day's bytes is refused too.
    const first = "2026-12-01"
    await env.VAULT_BACKUPS.put(monthlyObjectKey(tenant, first), utf8("planted"))
    expect(await inAccess(tenant, (ctx) => dumpVault(onDay(ctx, first), first))).toEqual({ date: first, key: monthlyObjectKey(tenant, first), refused: "backup_corrupt", message: "The object already at this month's key is not this workspace's dump of the first; it is not a backup." })
  })
})

describe("a workspace too large to dump in one piece", () => {
  it("is refused as too_large from its storage size, before anything is read or written", async () => {
    const tenant = await seededWorkspace()
    await inAccess(tenant, async (ctx) => {
      const large = Object.assign(Object.create(ctx) as VaultContext, { storage: { sql: { databaseSize: MAX_DUMP_DATABASE_BYTES + 1 } } })
      await expect(dumpVault(large, utcDate(Date.now()))).rejects.toMatchObject({ code: "too_large", message: `This workspace's storage is ${MAX_DUMP_DATABASE_BYTES + 1} bytes, above the ${MAX_DUMP_DATABASE_BYTES}-byte limit for a dump; nothing was dumped.` })
    })
    expect(await env.VAULT_BACKUPS.head(backupObjectKey(tenant, utcDate(Date.now())))).toBeNull()
  })
})

describe("vaultbackup.restore from a dump", () => {
  it("round-trips into an empty object row for row, audits the restore after the restart, and the secrets open again", async () => {
    const tenant = await seededWorkspace()
    const before = await inAccess(tenant, snapshot)
    await dumpOn(tenant, "2026-10-30")
    expect(await refusal(tenant, "vaultbackup.restore", { intent: intentId(), source: "dump", date: "2026-10-30" })).toEqual({ error: "conflict", message: "This workspace is not empty. A dump restores only into an empty object; restore to a point in time instead." })
    await inAccess(tenant, wipe)
    expect((await inAccess(tenant, snapshot)).tables.filter((table) => table.rows.length > 0).map((table) => table.name)).toEqual(["_migrations", "_workspace_generation"])
    const intent = intentId()
    const staged = await value<{ source: string; tables: number; rows: number }>(tenant, "vaultbackup.restore", { intent, source: "dump", date: "2026-10-30" })
    expect(staged).toEqual({ source: "dump", date: "2026-10-30", tables: before.tables.length, rows: before.tables.reduce((n, table) => n + table.rows.length, 0) })
    const record = { intent, source: "dump", target: "2026-10-30", bookmark: null, undoBookmark: null, actor: "operator:alex" }
    expect(await refusal(tenant, "vaultbackup.restored", record)).toEqual({ error: "conflict", message: "This workspace has not restarted since the restore was staged." })
    // The reset ends the call itself.
    expect(await invoke(tenant, "vaultbackup.restart", { intent }).then(() => "answered", (error: Error) => error.message)).toBe("vault restore")
    expect(await value(tenant, "vaultbackup.restored", record)).toEqual({ recorded: true })
    const after = await inAccess(tenant, snapshot)
    // Row for row, but for what the restore itself added: its audit event and the record of the intent it staged.
    const added = (name: string, row: string) => name === "audit" ? row.includes('"action":"system.restore"') : name === "tenant_state" && row.includes('"key":"vault_restore_staged"')
    expect({ ...after, tables: after.tables.map((table) => ({ ...table, rows: table.rows.filter((row) => !added(table.name, row)) })) }).toEqual(before)
    expect(await value(tenant, "vaultbackup.restored", record)).toEqual({ recorded: true })
    await inAccess(tenant, async (ctx) => {
      const audit = ctx.sql.exec<{ actor: string; action: string; detail: string }>("SELECT actor, action, detail FROM audit WHERE action = 'system.restore'").toArray()
      expect(audit).toEqual([{ actor: "operator:alex", action: "system.restore", detail: canonicalJson({ bookmark: null, intent, source: "dump", target: "2026-10-30", undoBookmark: null }) }])
      const secret = ctx.sql.exec<{ item: string; name: string; root_version: number; wrapped_dek: ArrayBuffer; ciphertext: ArrayBuffer }>("SELECT s.item, s.name, s.root_version, s.wrapped_dek, s.ciphertext FROM item_secrets s JOIN items i ON i.id = s.item WHERE i.slug = ?", SLUG).one()
      const opened = await ctx.openField(secretRef({ id: secret.item }, secret.name), { rootVersion: secret.root_version, wrappedDek: new Uint8Array(secret.wrapped_dek), ciphertext: new Uint8Array(secret.ciphertext) })
      expect(new TextDecoder().decode(opened)).toBe(SECRET)
    })
  })

  it("answers the same intent again with what it staged, even after the restart, so a lost reply never reads as a refusal", async () => {
    const tenant = await seededWorkspace()
    await dumpOn(tenant, "2026-10-30")
    await inAccess(tenant, wipe)
    const intent = intentId()
    const staged = await value(tenant, "vaultbackup.restore", { intent, source: "dump", date: "2026-10-30" })
    expect(await value(tenant, "vaultbackup.restore", { intent, source: "dump", date: "2026-10-30" })).toEqual(staged)
    expect(await invoke(tenant, "vaultbackup.restart", { intent }).then(() => "answered", (error: Error) => error.message)).toBe("vault restore")
    expect(await value(tenant, "vaultbackup.restore", { intent, source: "dump", date: "2026-10-30" })).toEqual(staged)
    expect(await refusal(tenant, "vaultbackup.restore", { intent: intentId(), source: "dump", date: "2026-10-30" })).toEqual({ error: "conflict", message: "This workspace is not empty. A dump restores only into an empty object; restore to a point in time instead." })
  })

  it("refuses every other call while a restore is staged and the object has not restarted", async () => {
    const tenant = await seededWorkspace()
    const echo = { items: [], host: "api.example.com", workspaceAudit: [] }
    expect((await invoke(tenant, "relay.echo", echo)).ok).toBe(true)
    await dumpOn(tenant, "2026-10-30")
    await inAccess(tenant, wipe)
    const intent = intentId()
    await value(tenant, "vaultbackup.restore", { intent, source: "dump", date: "2026-10-30" })
    const refused = { error: "conflict", message: "This workspace is being restored. Try again in a few minutes." }
    expect(await refusal(tenant, "relay.echo", echo)).toEqual(refused)
    expect(await refusal(tenant, "access.identity.context", {}, accountAuth("owner"))).toEqual(refused)
    expect(await refusal(tenant, "vaultbackup.restored", { intent, source: "dump", target: "2026-10-30", bookmark: null, undoBookmark: null, actor: "operator:alex" })).toEqual({ error: "conflict", message: "This workspace has not restarted since the restore was staged." })
    expect(await invoke(tenant, "vaultbackup.restart", { intent }).then(() => "answered", (error: Error) => error.message)).toBe("vault restore")
    expect((await invoke(tenant, "relay.echo", echo)).ok).toBe(true)
  })

  it("refuses another tenant's dump, by its header and, with a forged header, by the AAD", async () => {
    const source = await seededWorkspace()
    await dumpOn(source, "2026-10-29")
    const bytes = await stored(source, "2026-10-29")
    const target = (await credentialsFixture()).tenant
    await inAccess(target, wipe)
    await env.VAULT_BACKUPS.put(backupObjectKey(target, "2026-10-29"), bytes)
    expect(await refusal(target, "vaultbackup.restore", { intent: intentId(), source: "dump", date: "2026-10-29" })).toEqual({ error: "conflict", message: "That backup is another workspace's." })
    const end = bytes.indexOf(0x0a)
    const forged = new Uint8Array([...utf8(new TextDecoder().decode(bytes.slice(0, end)).replace(source, target)), ...bytes.slice(end)])
    await env.VAULT_BACKUPS.put(backupObjectKey(target, "2026-10-29"), forged)
    expect(await refusal(target, "vaultbackup.restore", { intent: intentId(), source: "dump", date: "2026-10-29" })).toEqual({ error: "conflict", message: "That backup does not open as this workspace's." })
    expect(await refusal(target, "vaultbackup.restore", { intent: intentId(), source: "dump", date: "2026-10-27" })).toEqual({ error: "not_found", message: "There is no backup of this workspace for that date." })
    expect((await inAccess(target, snapshot)).tables.filter((table) => table.rows.length > 0).map((table) => table.name)).toEqual(["_migrations", "_workspace_generation"])
  })

  it("refuses a dump from another generation, under a root key version this deploy lacks, or from newer code", async () => {
    const tenant = await seededWorkspace()
    await inAccess(tenant, async (ctx) => {
      ctx.sql.exec("UPDATE _workspace_generation SET generation = 'workspaces-older'")
      await dumpVault(onDay(ctx, "2026-10-20"), "2026-10-20")
      ctx.sql.exec("UPDATE _workspace_generation SET generation = ?", WORKSPACE_GENERATION)
      const rotated = Object.assign(onDay(ctx, "2026-10-21"), { env: { ...ctx.env, ROOT_KEYS: JSON.stringify({ ...JSON.parse(ctx.env.ROOT_KEYS) as Record<string, string>, 2: base64UrlEncode(crypto.getRandomValues(new Uint8Array(32))) }) } })
      expect(await dumpVault(rotated, "2026-10-21")).toMatchObject({ rootVersion: 2 })
      await dumpVault(onDay(ctx, "2026-10-22"), "2026-10-22")
      wipe(ctx)
    })
    expect(await refusal(tenant, "vaultbackup.restore", { intent: intentId(), source: "dump", date: "2026-10-20" })).toEqual({ error: "conflict", message: "That backup is from another workspace storage generation." })
    expect(await refusal(tenant, "vaultbackup.restore", { intent: intentId(), source: "dump", date: "2026-10-21" })).toEqual({ error: "conflict", message: "That backup needs root key version 2, which this deploy does not have." })
    await inAccess(tenant, async (ctx) => {
      ctx.sql.exec("UPDATE _migrations SET applied = applied - 1 WHERE area = 'core'")
      const staged = vaultBackupOps["vaultbackup.restore"]!.handler(ctx, { kind: "system" }, { intent: intentId(), source: "dump", date: "2026-10-22" }, { auth: SYSTEM, workspace: { id: ctx.tenant, slug: "work", name: "Work" } })
      await expect(staged).rejects.toThrow("That backup was written by newer vault code than this deploy runs.")
      ctx.sql.exec("UPDATE _migrations SET applied = applied + 1 WHERE area = 'core'")
    })
    expect((await inAccess(tenant, snapshot)).tables.filter((table) => table.rows.length > 0).map((table) => table.name)).toEqual(["_migrations", "_workspace_generation"])
  })
})

describe("vaultbackup.restore to a point in time", () => {
  function stubbedStorage() {
    return { getBookmarkForTime: vi.fn(async (_at: number | Date) => "bookmark-at-target"), onNextSessionRestoreBookmark: vi.fn(async (_bookmark: string) => "bookmark-undo") }
  }
  it("takes the bookmark for the time, keeps the undo bookmark, restarts, and audits only in the next session", async () => {
    const tenant = (await credentialsFixture()).tenant
    await inAccess(tenant, async (ctx) => {
      const now = Date.parse("2026-11-01T12:00:00.000Z"), restart = vi.fn()
      const storage = stubbedStorage()
      const session = Object.assign(Object.create(ctx) as VaultContext, { storage, now: () => now, restart })
      const invocation = { auth: SYSTEM, workspace: { id: ctx.tenant, slug: "work", name: "Work" } }
      const ops = vaultBackupOps
      const intent = intentId()
      for (const at of ["2026-10-01T11:59:59.000Z", "2026-11-01T12:00:01.000Z"]) await expect(ops["vaultbackup.restore"]!.handler(session, { kind: "system" }, { intent, source: "pitr", at }, invocation)).rejects.toMatchObject({ code: "bad_request" })
      expect(storage.getBookmarkForTime).not.toHaveBeenCalled()
      const staged = await ops["vaultbackup.restore"]!.handler(session, { kind: "system" }, { intent, source: "pitr", at: "2026-10-31T08:15:00.000Z" }, invocation)
      expect(staged).toEqual({ source: "pitr", at: "2026-10-31T08:15:00.000Z", bookmark: "bookmark-at-target", undoBookmark: "bookmark-undo" })
      expect(storage.getBookmarkForTime).toHaveBeenCalledWith(Date.parse("2026-10-31T08:15:00.000Z"))
      expect(storage.onNextSessionRestoreBookmark).toHaveBeenCalledWith("bookmark-at-target")
      const record = { intent, source: "pitr", target: "2026-10-31T08:15:00.000Z", bookmark: "bookmark-at-target", undoBookmark: "bookmark-undo", actor: "operator:alex" }
      expect(() => ops["vaultbackup.restored"]!.handler(session, { kind: "system" }, record, invocation)).toThrow("This workspace has not restarted since the restore was staged.")
      ops["vaultbackup.restart"]!.handler(session, { kind: "system" }, { intent }, invocation)
      expect(restart).toHaveBeenCalledWith("vault restore")
      // The next session has another storage object: the restore took.
      const next = Object.assign(Object.create(ctx) as VaultContext, { storage: stubbedStorage() })
      expect(ops["vaultbackup.restored"]!.handler(next, { kind: "system" }, record, invocation)).toEqual({ recorded: true })
      expect(ops["vaultbackup.restored"]!.handler(next, { kind: "system" }, record, invocation)).toEqual({ recorded: true })
      const { actor, ...detail } = record
      expect(ctx.sql.exec<{ actor: string; detail: string }>("SELECT actor, detail FROM audit WHERE action = 'system.restore'").toArray()).toEqual([{ actor, detail: canonicalJson(detail) }])
      expect(() => ops["vaultbackup.restored"]!.handler(next, { kind: "system" }, { ...record, actor: "admin:acct_x" }, invocation)).toThrow()
      const words = auditLine({ actor, action: "system.restore", target: null, detail: canonicalJson(detail) }, { self: null, devices: new Map() })
      expect([words.actor, ...words.pieces.map((piece) => piece.text)].join("")).toBe("The operator restored the workspace to 2026-10-31T08:15:00.000Z. Everything after that point was undone")
    })
  })

  it("answers the same intent again with the first stage, never a second undo bookmark, and stages a new intent afresh", async () => {
    const tenant = (await credentialsFixture()).tenant
    await inAccess(tenant, async (ctx) => {
      const now = Date.parse("2026-11-01T12:00:00.000Z")
      const storage = stubbedStorage()
      const session = Object.assign(Object.create(ctx) as VaultContext, { storage, now: () => now, restart: vi.fn() })
      const invocation = { auth: SYSTEM, workspace: { id: ctx.tenant, slug: "work", name: "Work" } }
      const restore = vaultBackupOps["vaultbackup.restore"]!
      const intent = intentId()
      const first = await restore.handler(session, { kind: "system" }, { intent, source: "pitr", at: "2026-10-31T08:15:00.000Z" }, invocation)
      storage.onNextSessionRestoreBookmark.mockImplementation(async () => "bookmark-undo-later")
      // A lost reply: the cron asks again with the same intent.
      expect(await restore.handler(session, { kind: "system" }, { intent, source: "pitr", at: "2026-10-31T08:15:00.000Z" }, invocation)).toEqual(first)
      expect(storage.onNextSessionRestoreBookmark).toHaveBeenCalledTimes(1)
      const another = intentId()
      expect(await restore.handler(session, { kind: "system" }, { intent: another, source: "pitr", at: "2026-10-30T08:15:00.000Z" }, invocation)).toMatchObject({ undoBookmark: "bookmark-undo-later" })
    })
  })
})

describe("system calls only", () => {
  it("refuses every vaultbackup op to members, devices and platforms", async () => {
    const tenant = await seededWorkspace()
    const proof = "eyJhbGciOiJFUzI1NiJ9.e30.sig"
    const inputs: Record<string, unknown> = {
      "vaultbackup.dump": { date: "2026-10-31" },
      "vaultbackup.restore": { intent: intentId(), source: "pitr", at: "2026-10-31T00:00:00.000Z" },
      "vaultbackup.restart": { intent: intentId() },
      "vaultbackup.restored": { intent: intentId(), source: "pitr", target: "x", bookmark: null, undoBookmark: null, actor: "operator:x" },
    }
    expect(Object.keys(vaultBackupOps).sort()).toEqual(Object.keys(inputs).sort())
    for (const [op, spec] of Object.entries(vaultBackupOps)) {
      expect(spec.auth, op).toEqual(["system"])
      for (const auth of [accountAuth("owner"), { kind: "device" as const, proof, method: "POST", url: "https://vault.test/v1/me", bodyHash: "" }, platformAuth()]) {
        expect(await refusal(tenant, op, inputs[op], auth), `${op} as ${auth.kind}`).toEqual({ error: "forbidden", message: "You are not allowed to do that." })
      }
    }
    expect(await env.VAULT_BACKUPS.head(backupObjectKey(tenant, "2026-10-31"))).toBeNull()
  })
})

describe("the daily cron entry", () => {
  async function addWorkspace(f: WorkspaceTestFixture, id: string, slug: string, status = "active") {
    await f.env.DB.prepare("INSERT INTO workspaces(id,slug,name,status,created_by,created_at,delete_after) VALUES (?,?,'Backup',?,?,?,?)").bind(id, slug, status, f.account, Date.now(), status === "deleting" ? Date.now() + 86_400_000 : null).run()
  }
  function stubClient(failing: Set<string>): VaultBackupClient & { dumps: string[] } {
    const dumps: string[] = []
    return {
      dumps,
      async dump(tenant, date) {
        dumps.push(tenant)
        if (failing.has(tenant)) throw new VaultError("upstream_failed", "Workspace unavailable.")
        return { date, key: backupObjectKey(tenant, date), bytes: 100 + dumps.length, sha256: "a".repeat(64), rootVersion: 1 }
      },
      async restore() { throw new Error("no restore here") }, async restart() {}, async restored() {},
    }
  }
  const rows = (f: WorkspaceTestFixture) => f.env.DB.prepare("SELECT tenant,date,outcome,bytes,error,attempts FROM vault_backup_runs ORDER BY tenant").all().then((r) => r.results)

  it("dumps every active workspace once a day; one failure does not stop the rest and is tried again, an ok run never again", async () => {
    const f = await createWorkspaceFixture(), now = Date.parse("2026-11-01T03:00:00.000Z")
    await addWorkspace(f, "tn_Failing123", "failing-ws")
    await addWorkspace(f, "tn_Deleting12", "deleting-ws", "deleting")
    const failing = new Set(["tn_Failing123"])
    const client = stubClient(failing)
    await backUpWorkspaceVaults(f.env, client, now)
    expect(client.dumps.sort()).toEqual([f.workspaces.personal, f.workspaces.work, "tn_Failing123"].sort())
    expect(await rows(f)).toEqual([
      { tenant: f.workspaces.personal, date: "2026-11-01", outcome: "ok", bytes: expect.any(Number), error: null, attempts: 1 },
      { tenant: f.workspaces.work, date: "2026-11-01", outcome: "ok", bytes: expect.any(Number), error: null, attempts: 1 },
      { tenant: "tn_Failing123", date: "2026-11-01", outcome: "failed", bytes: null, error: "upstream_failed: Workspace unavailable.", attempts: 1 },
    ].sort((a, b) => a.tenant.localeCompare(b.tenant)))
    client.dumps.length = 0
    await backUpWorkspaceVaults(f.env, client, now + 900_000)
    expect(client.dumps).toEqual(["tn_Failing123"])
    failing.clear()
    client.dumps.length = 0
    await backUpWorkspaceVaults(f.env, client, now + 1_800_000)
    expect(client.dumps).toEqual(["tn_Failing123"])
    expect((await rows(f)).find((row) => (row as { tenant: string }).tenant === "tn_Failing123")).toMatchObject({ outcome: "ok", error: null, attempts: 3 })
    client.dumps.length = 0
    await backUpWorkspaceVaults(f.env, client, now + 2_700_000)
    expect(client.dumps).toEqual([])
    // The next UTC day starts again.
    await backUpWorkspaceVaults(f.env, client, now + 86_400_000)
    expect(client.dumps.length).toBe(3)
  })

  it("never tries a too_large workspace again the same UTC day, and status names it", async () => {
    const f = await createWorkspaceFixture(), now = Date.parse("2026-11-01T03:00:00.000Z")
    const client = stubClient(new Set())
    const dump = client.dump
    client.dump = async (tenant, date) => {
      if (tenant === f.workspaces.work) { client.dumps.push(tenant); throw new VaultError("too_large", "This workspace's storage is 40000000 bytes, above the 33554432-byte limit for a dump; nothing was dumped.") }
      return dump(tenant, date)
    }
    await backUpWorkspaceVaults(f.env, client, now)
    expect(client.dumps.sort()).toEqual([f.workspaces.personal, f.workspaces.work].sort())
    client.dumps.length = 0
    await backUpWorkspaceVaults(f.env, client, now + 900_000)
    expect(client.dumps).toEqual([])
    const report: string[] = []
    const statusIo = { async query(_t: unknown, sql: string) { return (await f.env.DB.prepare(sql).all()).results }, print(line: string) { report.push(line) }, now: () => now + 900_000 } as unknown as VaultBackupIo
    expect(await runVaultBackup(parseArgs(["--local", "status"]), statusIo)).toBe(0)
    expect(report).toContain(`Failed: ${f.workspaces.work} 2026-11-01, 1 attempts: too_large: This workspace's storage is 40000000 bytes, above the 33554432-byte limit for a dump; nothing was dumped.`)
    await backUpWorkspaceVaults(f.env, client, now + 86_400_000)
    expect(client.dumps).toContain(f.workspaces.work)
  })

  it("dumps first the workspaces whose last good dump is oldest, so a full batch never leaves the same ones behind", async () => {
    const f = await createWorkspaceFixture(), now = Date.parse("2026-11-01T03:00:00.000Z")
    const recent = Array.from({ length: VAULT_BACKUP_BATCH }, (_, i) => `tn_Recent${String(i).padStart(4, "0")}`)
    const stale = "tn_zzzzStale1"
    const run = (tenant: string, date: string) => f.env.DB.prepare("INSERT INTO vault_backup_runs(tenant,date,outcome,bytes,sha256,root_version,attempted_at) VALUES (?,?,'ok',1,?,1,?)").bind(tenant, date, "a".repeat(64), now)
    await f.env.DB.batch([...recent, stale].map((id) => f.env.DB.prepare("INSERT INTO workspaces(id,slug,name,status,created_by,created_at) VALUES (?,?,'Backup','active',?,?)").bind(id, `ws-${id.slice(3).toLowerCase()}`, f.account, now)))
    await f.env.DB.batch([...recent.map((id) => run(id, "2026-10-31")), run(stale, "2026-10-29")])
    const client = stubClient(new Set())
    await backUpWorkspaceVaults(f.env, client, now)
    expect(client.dumps.length).toBe(VAULT_BACKUP_BATCH)
    // Never dumped first, then the oldest good dump, before any of yesterday's.
    expect(client.dumps.slice(0, 2).sort()).toEqual([f.workspaces.personal, f.workspaces.work].sort())
    expect(client.dumps[2]).toBe(stale)
  })

  it("records a refused object at today's key as a failed run, never as a backup", async () => {
    const f = await createWorkspaceFixture(), now = Date.parse("2026-11-01T03:00:00.000Z")
    const client = stubClient(new Set())
    const message = "The object already at today's key does not open as this workspace's dump of today; it is not a backup."
    client.dump = async (tenant, date) => ({ date, key: backupObjectKey(tenant, date), refused: "backup_corrupt", message })
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
    try { await backUpWorkspaceVaults(f.env, client, now) } finally { errors.mockRestore() }
    expect(await rows(f)).toEqual([f.workspaces.personal, f.workspaces.work].sort().map((tenant) => ({ tenant, date: "2026-11-01", outcome: "failed", bytes: null, error: `backup_corrupt: ${message}`, attempts: 1 })))
  })

  it("runs from the directory's maintenance through the real objects, recording each dump's bytes and sha256", async () => {
    // The objects' own clock decides the date: stay ten minutes clear of the UTC day's end.
    const f = await createWorkspaceFixture(), now = Math.min(Date.now(), Math.ceil(Date.now() / 86_400_000) * 86_400_000 - 600_000)
    const tenant = await seededWorkspace()
    await addWorkspace(f, tenant, "seeded-ws")
    const empty = (await credentialsFixture()).tenant
    await inAccess(empty, wipe)
    await addWorkspace(f, empty, "empty-ws")
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
    try { await maintainWorkspaceDirectory(f.env, now) } finally { errors.mockRestore() }
    const recorded = await f.env.DB.prepare("SELECT tenant,outcome,bytes,sha256,root_version,error FROM vault_backup_runs WHERE tenant IN (?,?) ORDER BY tenant=?").bind(tenant, empty, empty).all<{ tenant: string; outcome: string; bytes: number | null; sha256: string | null; root_version: number | null; error: string | null }>()
    const bytes = await stored(tenant, utcDate(now))
    expect(recorded.results).toEqual([
      { tenant, outcome: "ok", bytes: bytes.length, sha256: await sha256Hex(bytes), root_version: 1, error: null },
      { tenant: empty, outcome: "failed", bytes: null, sha256: null, root_version: null, error: "conflict: This workspace object is empty; nothing was dumped." },
    ])
  })
})

describe("restore intents", () => {
  function io(f: WorkspaceTestFixture, typed: string | null, now = Date.now()): VaultBackupIo & { output: string[]; asked: string[] } {
    const output: string[] = [], asked: string[] = []
    return {
      output, asked,
      async query(_target, sql) { return (await f.env.DB.prepare(sql).all()).results as never[] },
      async execute(_target, sql) { await f.env.DB.prepare(sql).run() },
      async bookmark() { return "fixture-bookmark" },
      async wrangler() { throw new Error("no wrangler in restore") },
      async read() { return null }, async rename() {}, async remove() {}, async mkdir() {},
      print(line) { output.push(line) },
      async ask(prompt) { asked.push(prompt); return typed },
      now: () => now,
    }
  }
  const intentRows = (f: WorkspaceTestFixture) => f.env.DB.prepare("SELECT id,tenant,source,target,actor,state,bookmark,undo_bookmark,error FROM vault_restore_intents ORDER BY created_at").all<Record<string, unknown>>().then((r) => r.results)

  it("parses only explicit, well-formed arguments", () => {
    for (const argv of [[], ["status"], ["--remote", "status", "x"], ["--local", "pull"], ["--local", "restore", "--tenant", "tn_x'--", "--dump", "2026-10-01", "--actor", "operator:a"], ["--local", "restore", "--tenant", "tn_Alpha123456", "--dump", "2026-02-30", "--actor", "operator:a"], ["--local", "restore", "--tenant", "tn_Alpha123456", "--pitr", "yesterday", "--actor", "operator:a"], ["--local", "restore", "--tenant", "tn_Alpha123456", "--pitr", "2026-10-31T09:00", "--actor", "operator:a"], ["--local", "restore", "--tenant", "tn_Alpha123456", "--pitr", "2026-10-31T09:00:00", "--actor", "operator:a"], ["--local", "restore", "--tenant", "tn_Alpha123456", "--pitr", "2026-10-31", "--actor", "operator:a"], ["--local", "restore", "--tenant", "tn_Alpha123456", "--pitr", "2026-10-31T09:00:00+0100", "--actor", "operator:a"], ["--local", "restore", "--tenant", "tn_Alpha123456", "--dump", "2026-10-01", "--actor", "a';"]]) expect(() => parseArgs(argv), argv.join(" ")).toThrow("Usage:")
    expect(parseArgs(["--remote", "restore", "--tenant", "tn_Alpha123456", "--pitr", "2026-10-31T09:00:00+01:00", "--actor", "operator:alex"]).command).toEqual({ kind: "restore", tenant: "tn_Alpha123456", actor: "operator:alex", source: "pitr", target: "2026-10-31T08:00:00.000Z" })
    expect(parseArgs(["--remote", "restore", "--tenant", "tn_Alpha123456", "--pitr", "2026-10-31T08:00:00.250Z", "--actor", "operator:alex"]).command).toMatchObject({ source: "pitr", target: "2026-10-31T08:00:00.250Z" })
    expect(parseArgs(["--remote", "restore", "--tenant", "tn_Alpha123456", "--pitr", "2026-10-31T03:00-05:00", "--actor", "operator:alex"]).command).toMatchObject({ source: "pitr", target: "2026-10-31T08:00:00.000Z" })
    expect(parseArgs(["--remote", "status"]).target).toMatchObject({ database: "mehen", bucket: "mehen-vault-backups", d1: ["--remote", "--env", ""], r2: ["--remote", "--jurisdiction", "eu"] })
  })

  it("needs the workspace id typed back, then records one hashed intent the cron carries out and audits", async () => {
    // Every step stays on one UTC day, at least ten minutes before its end.
    const f = await createWorkspaceFixture(), now = Math.min(Date.now(), Math.ceil(Date.now() / 86_400_000) * 86_400_000 - 600_000)
    const tenant = await seededWorkspace()
    await f.env.DB.prepare("INSERT INTO workspaces(id,slug,name,status,created_by,created_at) VALUES (?,'restore-ws','Restore','active',?,?)").bind(tenant, f.account, now).run()
    const date = new Date(now).toISOString().slice(0, 10)
    const client = vaultBackupClient(f.env)
    await backUpWorkspaceVaults(f.env, client, now)
    const args = parseArgs(["--local", "restore", "--tenant", tenant, "--dump", date, "--actor", "operator:test"])
    for (const typed of [null, "restore-ws", f.workspaces.work]) expect(await runVaultBackup(args, io(f, typed, now))).toBe(1)
    expect(await intentRows(f)).toEqual([])
    const confirmed = io(f, tenant, now)
    expect(await runVaultBackup(args, confirmed)).toBe(0)
    expect(confirmed.asked).toEqual([`Type the workspace id ${tenant} to confirm: `])
    expect(confirmed.output.join("\n")).toContain("Everything in this workspace after that point is undone")
    const [written] = await f.env.DB.prepare("SELECT id,tenant,source,target,actor,intent_hash,created_at FROM vault_restore_intents").all<{ id: string; tenant: string; source: "dump"; target: string; actor: string; intent_hash: string; created_at: number }>().then((r) => r.results)
    expect(written?.intent_hash).toBe(await restoreIntentDigest({ id: written!.id, tenant, source: "dump", target: date, actor: "operator:test", createdAt: written!.created_at }))
    expect(await runVaultBackup(args, io(f, tenant, now))).toBe(1)
    // The cron: the object is not empty, so the dump restore is refused and recorded.
    await runVaultRestores(f.env, client, now + 60_000)
    expect(await intentRows(f)).toEqual([{ id: written!.id, tenant, source: "dump", target: date, actor: "operator:test", state: "failed", bookmark: null, undo_bookmark: null, error: "conflict: This workspace is not empty. A dump restores only into an empty object; restore to a point in time instead." }])
    // Lost: the object is empty. A new intent restores it, restarts it and audits it.
    await inAccess(tenant, wipe)
    const again = io(f, tenant, now + 120_000)
    expect(await runVaultBackup(args, again)).toBe(0)
    await runVaultRestores(f.env, client, now + 180_000)
    const done = (await intentRows(f)).at(-1)
    expect(done).toMatchObject({ tenant, source: "dump", target: date, state: "done", error: null })
    const audit = await inAccess(tenant, (ctx) => ctx.sql.exec<{ actor: string; detail: string }>("SELECT actor, detail FROM audit WHERE action = 'system.restore'").toArray())
    expect(audit.map((row) => ({ actor: row.actor, detail: JSON.parse(row.detail) as unknown }))).toEqual([{ actor: "operator:test", detail: { bookmark: null, intent: done!.id, source: "dump", target: date, undoBookmark: null } }])
    expect((await inAccess(tenant, snapshot)).tables.find((table) => table.name === "items")?.rows.some((row) => row.includes(SLUG))).toBe(true)
    const report = io(f, null, now + 240_000)
    expect(await runVaultBackup(parseArgs(["--local", "status"]), report)).toBe(0)
    // The fixture's own two workspaces were never opened, so their objects are empty: refused, not dumped.
    const refused = "1 attempts: conflict: This workspace object is empty; nothing was dumped."
    expect(report.output).toEqual([
      expect.stringMatching(new RegExp(`^Today \\(${date}, UTC\\): 3 active workspaces; 2 failed, 1 ok \\(\\d+ bytes\\)\\.$`)),
      `No dump since yesterday: ${f.workspaces.personal} (alex), last never`,
      `No dump since yesterday: ${f.workspaces.work} (northwind), last never`,
      `Failed: ${f.workspaces.personal} ${date}, ${refused}`,
      `Failed: ${f.workspaces.work} ${date}, ${refused}`,
      `Restore ${done!.id}: ${tenant} dump ${date}, done`,
      `Restore ${written!.id}: ${tenant} dump ${date}, failed, conflict: This workspace is not empty. A dump restores only into an empty object; restore to a point in time instead.`,
    ])
  })

  it("refuses an intent changed after it was confirmed, keeps the PITR bookmarks, and waits for the restart before it is done", async () => {
    const f = await createWorkspaceFixture(), now = Date.now()
    const calls: string[] = []
    let restarted = false
    const client: VaultBackupClient = {
      async dump() { throw new Error("no dump here") },
      async restore(tenant, input) { calls.push(`restore ${tenant} ${input.source} ${"at" in input ? input.at : input.date}`); return { source: "pitr", at: "at" in input ? input.at : "", bookmark: "bm-target", undoBookmark: "bm-undo" } },
      async restart(tenant) { calls.push(`restart ${tenant}`) },
      async restored(tenant, input) { calls.push(`restored ${tenant} ${input.bookmark} ${input.undoBookmark} ${input.actor}`); if (!restarted) throw new VaultError("conflict", "This workspace has not restarted since the restore was staged.") },
    }
    const at = new Date(now - 3_600_000).toISOString()
    const args = parseArgs(["--local", "restore", "--tenant", f.workspaces.work, "--pitr", at, "--actor", "operator:test"])
    expect(await runVaultBackup(args, io(f, f.workspaces.work, now))).toBe(0)
    await f.env.DB.prepare("UPDATE vault_restore_intents SET target=?").bind(new Date(now - 7_200_000).toISOString()).run()
    await runVaultRestores(f.env, client, now)
    expect(calls).toEqual([])
    expect(await intentRows(f)).toMatchObject([{ state: "failed", error: "intent_changed: the intent no longer matches what was recorded." }])
    expect(await runVaultBackup(args, io(f, f.workspaces.work, now))).toBe(0)
    await runVaultRestores(f.env, client, now)
    expect(calls).toEqual([`restore ${f.workspaces.work} pitr ${at}`, `restart ${f.workspaces.work}`, `restored ${f.workspaces.work} bm-target bm-undo operator:test`, `restart ${f.workspaces.work}`])
    expect((await intentRows(f)).at(-1)).toMatchObject({ state: "restarting", bookmark: "bm-target", undo_bookmark: "bm-undo" })
    restarted = true
    calls.length = 0
    await runVaultRestores(f.env, client, now + 900_000)
    expect(calls).toEqual([`restored ${f.workspaces.work} bm-target bm-undo operator:test`])
    expect((await intentRows(f)).at(-1)).toMatchObject({ state: "done" })
    // An intent the cron never reached within the hour expires.
    expect(await runVaultBackup(args, io(f, f.workspaces.work, now + 900_000))).toBe(0)
    await runVaultRestores(f.env, client, now + 900_000 + 3_600_000)
    expect((await intentRows(f)).at(-1)).toMatchObject({ state: "expired" })
  })
})

describe("the restore plan on the operator's terminal", () => {
  it("spells a workspace name's control characters, so no ESC or BEL from it reaches the terminal", async () => {
    const f = await createWorkspaceFixture(), now = Date.now(), output: string[] = []
    await f.env.DB.prepare("UPDATE workspaces SET name=? WHERE id=?").bind("Mallory\u001b[31m red\u001b[0m\u0007\u009b2J", f.workspaces.work).run()
    const terminal = { async query(_t: unknown, sql: string) { return (await f.env.DB.prepare(sql).all()).results }, async bookmark() { return "fixture-bookmark" }, print(line: string) { output.push(line) }, async ask() { return null }, now: () => now } as unknown as VaultBackupIo
    expect(await runVaultBackup(parseArgs(["--local", "restore", "--tenant", f.workspaces.work, "--pitr", new Date(now - 3_600_000).toISOString(), "--actor", "operator:test"]), terminal)).toBe(1)
    expect(output.filter((line) => /[\u0000-\u001f\u007f-\u009f]/.test(line))).toEqual([])
    expect(output.find((line) => line.startsWith("Restore "))).toContain(`Restore Mallory\\u001B[31m red\\u001B[0m\\u0007\\u009B2J (northwind, ${f.workspaces.work}, active)`)
  })
})

describe("an intent changed in D1", () => {
  it("is refused in every state: one written already restarting is never staged, restarted or audited", async () => {
    const f = await createWorkspaceFixture(), now = Date.now()
    const calls: string[] = []
    const client: VaultBackupClient = {
      async dump() { throw new Error("no dump here") },
      async restore(tenant) { calls.push(`restore ${tenant}`); throw new Error("not staged") },
      async restart(tenant) { calls.push(`restart ${tenant}`) },
      async restored(tenant) { calls.push(`restored ${tenant}`) },
    }
    const fields = { id: intentId(), tenant: f.workspaces.work, source: "pitr" as const, target: new Date(now - 3_600_000).toISOString(), actor: "operator:test", createdAt: now }
    const hash = await restoreIntentDigest(fields)
    await f.env.DB.prepare("INSERT INTO vault_restore_intents(id,tenant,source,target,actor,intent_hash,created_at,expires_at,state,bookmark,undo_bookmark) VALUES (?,?,?,?,?,?,?,?,'restarting','bm-forged','bm-undo')")
      .bind(fields.id, fields.tenant, fields.source, new Date(now - 7_200_000).toISOString(), fields.actor, hash, now, now + 3_600_000).run()
    await runVaultRestores(f.env, client, now)
    expect(calls).toEqual([])
    expect(await f.env.DB.prepare("SELECT state,error FROM vault_restore_intents WHERE id=?").bind(fields.id).first()).toEqual({ state: "failed", error: "intent_changed: the intent no longer matches what was recorded." })
  })
})

describe("an intent stuck restarting", () => {
  it("fails after 6 hours, so it no longer blocks the next restore of that workspace", async () => {
    const f = await createWorkspaceFixture(), now = Date.now()
    const calls: string[] = []
    const client: VaultBackupClient = {
      async dump() { throw new Error("no dump here") },
      async restore() { throw new Error("no restore here") },
      async restart(tenant) { calls.push(`restart ${tenant}`) },
      async restored(tenant) { calls.push(`restored ${tenant}`); throw new VaultError("internal", "Something went wrong.") },
    }
    const createdAt = now - 6 * 3_600_000
    const fields = { id: intentId(), tenant: f.workspaces.work, source: "pitr" as const, target: new Date(createdAt - 3_600_000).toISOString(), actor: "operator:test", createdAt }
    await f.env.DB.prepare("INSERT INTO vault_restore_intents(id,tenant,source,target,actor,intent_hash,created_at,expires_at,state,bookmark,undo_bookmark) VALUES (?,?,?,?,?,?,?,?,'restarting','bm','bm-undo')")
      .bind(fields.id, fields.tenant, fields.source, fields.target, fields.actor, await restoreIntentDigest(fields), createdAt, createdAt + 3_600_000).run()
    await runVaultRestores(f.env, client, now - 60_000)
    expect(calls).toEqual([`restored ${f.workspaces.work}`])
    expect(await f.env.DB.prepare("SELECT state FROM vault_restore_intents WHERE id=?").bind(fields.id).first()).toEqual({ state: "restarting" })
    calls.length = 0
    await runVaultRestores(f.env, client, now)
    expect(calls).toEqual([])
    expect(await f.env.DB.prepare("SELECT state,error,completed_at FROM vault_restore_intents WHERE id=?").bind(fields.id).first()).toEqual({ state: "failed", error: "restart_timeout: the workspace did not confirm the restore within 6 hours; check it and its audit before recording another.", completed_at: now })
    const args = parseArgs(["--local", "restore", "--tenant", f.workspaces.work, "--pitr", new Date(now - 3_600_000).toISOString(), "--actor", "operator:test"])
    const output: string[] = []
    const io = { async query(_t: unknown, sql: string) { return (await f.env.DB.prepare(sql).all()).results }, async execute(_t: unknown, sql: string) { await f.env.DB.prepare(sql).run() }, async bookmark() { return "bm-d1" }, print(line: string) { output.push(line) }, async ask() { return f.workspaces.work }, now: () => now } as unknown as VaultBackupIo
    expect(await runVaultBackup(args, io)).toBe(0)
  })
})

describe("pull", () => {
  it("fetches each recorded dump of the last 35 days, keeps only those matching their size and sha256, and exports D1, printing every command", async () => {
    const f = await createWorkspaceFixture(), now = Date.parse("2026-11-01T10:00:00.000Z")
    const good = utf8("good dump bytes"), bad = utf8("tampered bytes!")
    await f.env.DB.batch([
      f.env.DB.prepare("INSERT INTO vault_backup_runs(tenant,date,outcome,bytes,sha256,root_version,attempted_at) VALUES (?,'2026-10-31','ok',?,?,1,?)").bind(f.workspaces.work, good.length, await sha256Hex(good), now),
      f.env.DB.prepare("INSERT INTO vault_backup_runs(tenant,date,outcome,bytes,sha256,root_version,attempted_at) VALUES (?,'2026-10-31','ok',?,?,1,?)").bind(f.workspaces.personal, good.length, await sha256Hex(good), now),
      f.env.DB.prepare("INSERT INTO vault_backup_runs(tenant,date,outcome,bytes,sha256,root_version,attempted_at) VALUES (?,'2026-09-01','ok',?,?,1,?)").bind(f.workspaces.work, good.length, await sha256Hex(good), now),
      f.env.DB.prepare("INSERT INTO vault_backup_runs(tenant,date,outcome,error,attempted_at) VALUES (?,'2026-11-01','failed','error',?)").bind(f.workspaces.work, now),
    ])
    const remote = new Map([[`mehen-vault-backups-local/ws/${f.workspaces.work}/2026-10-31.bin`, good], [`mehen-vault-backups-local/ws/${f.workspaces.personal}/2026-10-31.bin`, bad]])
    const files = new Map<string, Uint8Array>(), output: string[] = []
    const transport: VaultBackupIo = {
      async query(_target, sql) { return (await f.env.DB.prepare(sql).all()).results as never[] },
      async execute() { throw new Error("pull writes nothing to D1") },
      async bookmark() { throw new Error("pull needs no bookmark") },
      async wrangler(args) {
        if (args[0] === "r2") files.set(args[args.indexOf("--file") + 1]!, remote.get(args[3]!)!)
        else files.set(args[args.indexOf("--output") + 1]!, utf8("-- d1 export"))
      },
      async read(path) { return files.get(path) ?? null },
      async rename(from, to) { files.set(to, files.get(from)!); files.delete(from) },
      async remove(path) { files.delete(path) },
      async mkdir() {},
      print(line) { output.push(line) },
      async ask() { throw new Error("pull asks nothing") },
      now: () => now,
    }
    expect(await runVaultBackup(parseArgs(["--local", "pull", "--to", "/backups/"]), transport)).toBe(1)
    expect([...files.keys()].sort()).toEqual([`/backups/d1/mehen-local-2026-11-01.sql`, `/backups/ws/${f.workspaces.work}/2026-10-31.bin`])
    expect(output).toEqual([
      `$ bunx wrangler r2 object get mehen-vault-backups-local/ws/${f.workspaces.personal}/2026-10-31.bin --file /backups/ws/${f.workspaces.personal}/2026-10-31.bin.part --local --env local`,
      `MISMATCH: ws/${f.workspaces.personal}/2026-10-31.bin does not match its recorded size and sha256; not kept.`,
      `$ bunx wrangler r2 object get mehen-vault-backups-local/ws/${f.workspaces.work}/2026-10-31.bin --file /backups/ws/${f.workspaces.work}/2026-10-31.bin.part --local --env local`,
      `$ bunx wrangler d1 export mehen-local --local --env local --output /backups/d1/mehen-local-2026-11-01.sql`,
      "Pulled 1 new dumps, 0 already here and verified, 1 mismatched, and a D1 export, into /backups.",
    ])
    output.length = 0
    remote.set(`mehen-vault-backups-local/ws/${f.workspaces.personal}/2026-10-31.bin`, good)
    expect(await runVaultBackup(parseArgs(["--local", "pull", "--to", "/backups"]), transport)).toBe(0)
    expect(output.at(-1)).toBe("Pulled 1 new dumps, 1 already here and verified, 0 mismatched, and a D1 export, into /backups.")
  })
})
