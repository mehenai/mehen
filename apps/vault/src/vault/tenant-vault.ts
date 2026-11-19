// One Durable Object per workspace: the only place plaintext exists, for the
// length of a call. Every operation enters through `invoke`, which
// authenticates, checks the freeze, dispatches to the owning area and turns
// any refusal into a plain WireError: a thrown error keeps its message and
// fields across RPC but loses its prototype, so instanceof VaultError fails.

import { z } from "zod"
import { DurableObject } from "cloudflare:workers"
import { openRecord, parseProof, sealRecord } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError, toWireError } from "../http.ts"
import { AUDIT_MIGRATIONS, appendAudit } from "./audit.ts"
import { type AccessStateMemo, type Area, type Invocation, type InvocationResult, type VaultContext, type WorkspaceInvocation, one } from "./core.ts"
import { authenticateDevice } from "./areas/devices.ts"
import { assertDeviceKeyRule } from "./areas/workloads.ts"
import { AREAS } from "./registry.ts"
import { accessState, managedSetting, principalOf, setting, type WorkspaceRuntimePrincipal } from "./areas/workspace-runtime.ts"
import { admitPlatformCall } from "./areas/managed.ts"
import { restoreAwaitingRestart } from "./areas/vault-backup.ts"
import { admitManagedDeviceCall, managedAuditShape, managedPurged } from "./managed-platform.ts"
import { TenantKeys, parseRootKeys } from "./keys.ts"
import { wakeStorageWaiters } from "./storage-waits.ts"
import { GUARD_TABLE, accessRevisionOf, assertPlainStatement, clearLeftoverMarker, enableRecursiveTriggers, installGuardTables, installGuardTriggers, managementScope, registerGuardSql } from "./areas/management-guard.ts"

const CORE: Area = {
  name: "core",
  migrations: [
    `CREATE TABLE tenant_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
     CREATE TABLE schedule (area TEXT NOT NULL, key TEXT NOT NULL, due_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (area, key));
     CREATE INDEX schedule_due ON schedule (due_at);`,
    ...AUDIT_MIGRATIONS,
  ],
}

const ALARM_RETRY_MS = 60_000
const ALARM_BATCH = 50
const READ_STATEMENT = /^\s*SELECT\b/i

// The object's storage as the vault uses it, patched in place rather than
// wrapped, because areas key their per-object state on its identity
// (managed-platform.ts, vault-backup.ts, storage-waits.ts):
// - every statement that is not a SELECT, a synchronous transaction that
//   rolled back, and deleteAll call `counted` and wake the long polls;
// - a synchronous transaction is the management guard's scope: its callback
//   may not return a promise, and the outermost one deletes the guard's
//   marker before it commits (management-guard.ts);
// - storage.sql is the same checked SQL as ctx.sql, which runs only reads
//   and row changes outside migrations and restores, and never a statement
//   naming the guard's own tables (management-guard.ts assertPlainStatement),
//   so no area reaches the raw handle. Only this module holds it, and hands
//   the guard its own unchecked SQL (registerGuardSql).
// It answers the SQL migrations run on (counted, unchecked) and the SQL
// everything else runs on.
function vaultStorage(storage: DurableObjectStorage, counted: () => void, rolledBack: () => void): { migrations: SqlStorage; sql: SqlStorage } {
  const raw = storage.sql, transactionSync = storage.transactionSync.bind(storage), deleteAll = storage.deleteAll.bind(storage)
  const scope = managementScope(storage)
  const wrote = () => {
    counted()
    wakeStorageWaiters(storage)
  }
  storage.transactionSync = <T>(closure: () => T): T => {
    scope.depth++
    try {
      return transactionSync(() => {
        const result = closure()
        if (result instanceof Promise || (typeof result === "object" && result !== null && typeof (result as { then?: unknown }).then === "function")) {
          throw new VaultError("internal", "A synchronous transaction's callback returned a promise.")
        }
        if (scope.depth === 1 && scope.ready) raw.exec(`DELETE FROM ${GUARD_TABLE}`)
        return result
      })
    } catch (error) {
      rolledBack()
      wrote()
      throw error
    } finally {
      scope.depth--
    }
  }
  storage.deleteAll = (options) => {
    wrote()
    scope.ready = false
    return deleteAll(options).finally(wrote)
  }
  const migrations: SqlStorage = {
    exec(query, ...bindings) {
      if (!READ_STATEMENT.test(query)) wrote()
      return raw.exec(query, ...bindings)
    },
    get databaseSize() {
      return raw.databaseSize
    },
    Cursor: raw.Cursor,
    Statement: raw.Statement,
  }
  const sql: SqlStorage = {
    exec(query, ...bindings) {
      assertPlainStatement(storage, query)
      return migrations.exec(query, ...bindings)
    },
    get databaseSize() {
      return raw.databaseSize
    },
    Cursor: raw.Cursor,
    Statement: raw.Statement,
  }
  Object.defineProperty(storage, "sql", { value: sql, configurable: true, writable: true })
  registerGuardSql(storage, migrations)
  return { migrations, sql }
}

// Keyed by the object's own context, made once in the constructor, which
// carries the write counter the memo is stamped with: one memo per live
// object, gone with it, shared by every call on it and never by another
// counter. It holds only the workspace-wide evaluator state;
// eligibilityState decides each caller's own gate on a copy.
const accessStateMemos = new WeakMap<VaultContext, AccessStateMemo>()

// One invocation's context. accessState builds the evaluator state once and
// every call on this object reuses it until the object's storage is next
// written, by any call, an alarm or a transaction that rolled back, or an
// open invite lapses. The build is synchronous, so no call sees it half done.
export function invocationContext(base: VaultContext): VaultContext {
  let memo = accessStateMemos.get(base)
  if (!memo) {
    memo = { revision: null, until: 0, state: null }
    accessStateMemos.set(base, memo)
  }
  return Object.assign(Object.create(base) as VaultContext, { accessStateMemo: memo })
}

// Each migration in a transaction of its own; in a workspace object
// (guarded) it holds the management guard's marker, as a migration may
// move rows of the graph tables, whose triggers an earlier start installed.
export function applyMigrations(sql: SqlStorage, storage: DurableObjectStorage, areas: Area[], guarded = false): void {
  sql.exec("CREATE TABLE IF NOT EXISTS _migrations (area TEXT PRIMARY KEY, applied INTEGER NOT NULL)")
  for (const area of areas) {
    const applied = one(sql.exec<{ applied: number }>("SELECT applied FROM _migrations WHERE area = ?", area.name))?.applied ?? 0
    if (applied > area.migrations.length) throw new Error(`area ${area.name} has fewer migrations than applied`)
    for (let i = applied; i < area.migrations.length; i++) {
      storage.transactionSync(() => {
        if (guarded) sql.exec(`INSERT OR IGNORE INTO ${GUARD_TABLE}(id) VALUES (1)`)
        sql.exec(area.migrations[i] as string)
        sql.exec(
          "INSERT INTO _migrations (area, applied) VALUES (?, ?) ON CONFLICT (area) DO UPDATE SET applied = excluded.applied",
          area.name,
          i + 1,
        )
      })
    }
  }
}

export class TenantVault extends DurableObject<Env> {
  private readonly sql: SqlStorage
  private keys: TenantKeys | null = null
  private storageWrites = 0
  private rollbacks = 0
  private readonly areas: Map<string, Area>
  readonly context: VaultContext

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env)
    const raw = ctx.storage.sql
    this.initialiseStorage(raw)
    const { migrations, sql } = vaultStorage(ctx.storage, () => { this.storageWrites++ }, () => { this.rollbacks++ })
    this.sql = sql
    this.areas = new Map(AREAS.map((a) => [a.name, a]))
    // The trusted start: the guard's tables, recursive triggers, the
    // migrations (each holding the marker), then every guard trigger put
    // back and checked, before anything is served.
    enableRecursiveTriggers(migrations)
    installGuardTables(migrations)
    managementScope(ctx.storage).ready = true
    applyMigrations(migrations, ctx.storage, [CORE, ...AREAS], true)
    installGuardTriggers(migrations)
    this.context = this.makeContext()
    clearLeftoverMarker(this.context)
  }

  // Before anything else touches the object's storage, on the raw SQL:
  // WorkspaceVault checks its storage generation here.
  protected initialiseStorage(_sql: SqlStorage): void {}

  private tenant(): string {
    const name = this.ctx.id.name
    if (!name) throw new Error("TenantVault must be addressed by name")
    return name
  }

  private tenantKeys(): TenantKeys {
    this.keys ??= new TenantKeys(parseRootKeys(this.env.ROOT_KEYS), this.tenant())
    return this.keys
  }

  private makeContext(): VaultContext {
    const sql = this.sql
    const self = this
    return {
      get tenant() {
        return self.tenant()
      },
      env: this.env,
      sql,
      storage: this.ctx.storage,
      get storageWrites() {
        return self.storageWrites
      },
      accessRevision() {
        return `${accessRevisionOf(self.ctx.storage)}:${self.rollbacks}`
      },
      now: () => Date.now(),
      async sealField(ref, plaintext) {
        const keys = self.tenantKeys()
        const version = keys.current
        const sealed = await sealRecord(await keys.kek(version), { tenant: self.tenant(), ...ref }, plaintext)
        return { rootVersion: version, wrappedDek: sealed.wrappedDek, ciphertext: sealed.ciphertext }
      },
      async openField(ref, sealed) {
        const kek = await self.tenantKeys().kek(sealed.rootVersion)
        return openRecord(kek, { tenant: self.tenant(), ...ref }, { wrappedDek: sealed.wrappedDek, ciphertext: sealed.ciphertext })
      },
      get rootVersion() {
        return self.tenantKeys().current
      },
      fingerprintKey(version) {
        return self.tenantKeys().fingerprintKey(version)
      },
      audit(event) {
        const shaped = managedAuditShape(sql, self.tenant(), event)
        appendAudit(sql, Date.now(), shaped.event, shaped.genesis)
      },
      schedule(area, key, at) {
        sql.exec(
          "INSERT INTO schedule (area, key, due_at, attempts) VALUES (?, ?, ?, 0) ON CONFLICT (area, key) DO UPDATE SET due_at = excluded.due_at, attempts = 0",
          area,
          key,
          at,
        )
        self.armAlarm()
      },
      unschedule(area, key) {
        sql.exec("DELETE FROM schedule WHERE area = ? AND key = ?", area, key)
      },
      waitUntil(promise) {
        self.ctx.waitUntil(promise)
      },
      restart(reason) {
        self.ctx.abort(reason)
      },
    }
  }

  private armAlarm(): void {
    const next = one(this.sql.exec<{ due: number | null }>("SELECT MIN(due_at) AS due FROM schedule"))?.due
    if (next === null || next === undefined) return
    void this.ctx.storage.getAlarm().then((current) => {
      if (current === null || current > next) return this.ctx.storage.setAlarm(next)
    })
  }

  async invoke(invocation: Invocation | WorkspaceInvocation): Promise<InvocationResult> {
    try {
      if (!managedPurged(this.ctx.storage)) clearLeftoverMarker(this.context)
      if (restoreAwaitingRestart(this.ctx.storage) && !invocation.op.startsWith("vaultbackup.")) throw new VaultError("conflict", "This workspace is being restored. Try again in a few minutes.")
      const workspaceSpec = [...this.areas.values()].map((area) => area.workspaceOps?.[invocation.op]).find((spec) => spec !== undefined)
      if (invocation.auth.kind === "account" || workspaceSpec) {
        if (!workspaceSpec) throw new VaultError("not_found", "No such operation.")
        const auth = invocation.auth
        if (auth.kind !== "account" && auth.kind !== "device" && auth.kind !== "system" && auth.kind !== "platform" || !workspaceSpec.auth.includes(auth.kind)) throw new VaultError("forbidden", "You are not allowed to do that.")
        // A purged managed workspace is empty until this object is next built;
        // purging it again answers that nothing was left.
        if (managedPurged(this.ctx.storage) && invocation.op === "platform.subjects.purge" && auth.kind === "system") return { ok: true, value: { auditHead: null } }
        if (managedPurged(this.ctx.storage)) throw auth.kind === "device" ? new VaultError("unauthenticated", "This machine is not enrolled in this vault.") : new VaultError("not_found", "No such workspace.")
        const call = invocationContext(this.context)
        const workload = auth.kind === "device" ? (await authenticateDevice(call, auth)).workload : null
        if (auth.kind === "device") {
          assertDeviceKeyRule(call, invocation.op, auth)
          await admitManagedDeviceCall(call, invocation.op)
        }
        if (auth.kind === "platform") await admitPlatformCall(call, auth, invocation.op)
        // Only subjects.ensure and subjects.remove reach an object its
        // platform has not made yet; it has no subject member until ensure
        // makes one.
        const principal: WorkspaceRuntimePrincipal = auth.kind === "platform" && !managedSetting(call) ? { kind: "system" } : principalOf(call, auth)
        // Every row a workload caused names it, by id and by the label its machine gave it.
        const actedAs = workload ? { id: workload.id, label: workload.label } : null
        const context: VaultContext = Object.assign(Object.create(call) as VaultContext, { audit: (event: import("./core.ts").AuditEvent) => {
          // A row the platform caused is the platform's, with the key that
          // signed; rows the vault writes during the call keep their actor.
          if (auth.kind === "platform") {
            const managed = managedSetting(this.context)
            const actor = managed && event.actor === `member:${managed.member}` ? `platform:${auth.platform}` : event.actor
            this.context.audit({ ...event, actor, detail: { ...event.detail, by: { platform: auth.platform, key: auth.key } } })
            return
          }
          const state = accessState(call)
          const member = principal.kind === "member" ? state.members.find((m) => m.id === principal.memberId) : undefined
          const device = principal.kind === "device" ? state.devices.find((d) => d.id === principal.deviceId) : undefined
          const by = member && auth.kind === "account" ? { account: member.account, session: auth.session } : device ? { owner: `${device.owner.kind}:${device.owner.id}`, session: auth.kind === "device" ? parseProof(auth.proof).claims.sid ?? null : null, ...(actedAs ? { workload: actedAs } : {}) } : undefined
          const named = actedAs && event.private?.actor.kind === "device" ? { ...event, private: { ...event.private, actor: { ...event.private.actor, workload: actedAs } } } : event
          // A call whose step-up rode a passkey grace window says so on every
          // row it writes, the private record included.
          const confirmation = auth.kind === "account" && auth.stepUpConfirmation?.kind === "grace" ? auth.stepUpConfirmation : null
          const confirmed = confirmation && named.private ? { ...named, private: { ...named.private, confirmation } } : named
          this.context.audit({ ...confirmed, detail: { ...confirmed.detail, ...(by ? { by } : {}), ...(confirmation && !confirmed.private ? { confirmation } : {}) } })
        } })
        return { ok: true, value: await workspaceSpec.handler(context, principal, invocation.input, { auth, workspace: setting(this.context, "workspace", { id: this.tenant(), slug: "new", name: "Workspace" }) }) }
      }
      throw new VaultError("not_found", "No such operation.")
    } catch (error) {
      if (error instanceof z.ZodError) return { ok: false, error: toWireError(new VaultError("bad_request", "Invalid workspace request.")) }
      if (!(error instanceof VaultError)) console.error(JSON.stringify({ at: "invoke", op: invocation.op, error: error instanceof Error ? error.name : "unknown" }))
      return { ok: false, error: toWireError(error) }
    }
  }

  override async alarm(): Promise<void> {
    if (managedPurged(this.ctx.storage)) return
    clearLeftoverMarker(this.context)
    const now = Date.now()
    const due = this.sql
      .exec<{ area: string; key: string; attempts: number }>("SELECT area, key, attempts FROM schedule WHERE due_at <= ? ORDER BY due_at LIMIT ?", now, ALARM_BATCH)
      .toArray()
    for (const job of due) {
      const area = this.areas.get(job.area)
      // Removed before running, so a handler that re-schedules its own key keeps the new time.
      this.sql.exec("DELETE FROM schedule WHERE area = ? AND key = ? AND due_at <= ?", job.area, job.key, now)
      if (!area?.alarm) continue
      try {
        await area.alarm(this.context, job.key)
        // A managed workspace's purge erased every table, the schedule too.
        if (managedPurged(this.ctx.storage)) return
      } catch (error) {
        console.error(JSON.stringify({ at: "alarm", area: job.area, error: error instanceof Error ? error.name : "unknown" }))
        const backoff = Math.min(ALARM_RETRY_MS * 2 ** job.attempts, 6 * 3600_000)
        this.sql.exec(
          "INSERT INTO schedule (area, key, due_at, attempts) VALUES (?, ?, ?, ?) ON CONFLICT (area, key) DO NOTHING",
          job.area,
          job.key,
          now + backoff,
          job.attempts + 1,
        )
      }
    }
    const next = one(this.sql.exec<{ due: number | null }>("SELECT MIN(due_at) AS due FROM schedule"))?.due
    if (next !== null && next !== undefined) await this.ctx.storage.setAlarm(Math.max(next, Date.now() + 1000))
  }
}
