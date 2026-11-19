// One Durable Object per platform (named by its plt_ id). It holds no
// secret and never touches D1: the Worker reads the directory and passes
// in what is needed. It is the one place every platform call passes
// through, so it serialises what must be counted exactly:
// - each platform proof's nonce, spent once per key (a replay from any
//   isolate meets the same table);
// - the platform's own limits (calls a minute, writes and decisions a
//   minute per subject and in all), which the operator changes without a
//   deploy, so they cannot be fixed rate-limit bindings;
// - the last day's activity by route and outcome, for the operator's `show`;
// - its own audit chain of platform-level changes (defaults, delete-all).
// Device and workload traffic never passes through it.

import { DurableObject } from "cloudflare:workers"
import { PROOF_MAX_SKEW_SECONDS, type PlatformLimits } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError, type WireError, toWireError } from "../http.ts"
import { AUDIT_MIGRATIONS, appendAudit } from "../vault/audit.ts"
import { type Area, one } from "../vault/core.ts"
import { applyMigrations } from "../vault/tenant-vault.ts"
import { platformExpiredRefusal, platformReplayRefusal } from "./auth.ts"

const PLATFORM_VAULT_AREA: Area = {
  name: "platform",
  migrations: [
    `CREATE TABLE platform_nonces (key TEXT NOT NULL, jti TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (key, jti));
     CREATE INDEX platform_nonces_expiry ON platform_nonces (expires_at);
     CREATE TABLE platform_counters (name TEXT NOT NULL, window INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (name, window));
     CREATE TABLE platform_activity (hour INTEGER NOT NULL, route TEXT NOT NULL, outcome TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (hour, route, outcome));`,
    ...AUDIT_MIGRATIONS,
  ],
}

const MINUTE_MS = 60_000
// How long past its freshness by the object's own clock a proof fresh by the
// Worker's is still admitted: that clock reads after the body, the key
// lookup and the signature, so an honest proof near the limit is not refused.
const ADMIT_GRACE_MS = 30_000
// How long a nonce outlives its proof's freshness and grace by the object's own clock,
// so a clock that steps back when the object moves still finds it.
const NONCE_KEPT_PAST_FRESHNESS_MS = MINUTE_MS
const HOUR_MS = 3_600_000
const ACTIVITY_KEPT_HOURS = 25

export type PlatformAdmission = {
  key: string
  jti: string
  iat: number
  // platformSubjectHash of the subject the proof names, so no subject's name
  // is kept here: a counter can outlive the subject's purge.
  subjectHash: string | null
  write: boolean
  decision: boolean
  limits: Pick<PlatformLimits, "callsPerMinute" | "subjectWritesPerMinute" | "decisionsPerMinute" | "subjectDecisionsPerMinute">
}

export type PlatformAdmissionResult = { ok: true } | { ok: false; error: WireError }

export type PlatformAuditEntry = { actor: string; action: string; target?: string | null; detail: Record<string, unknown> }

// Counts by route and outcome ("ok" or the refusal's code) over a window.
export type PlatformActivity = { since: number; routes: Record<string, Record<string, number>> }

export class PlatformVault extends DurableObject<Env> {
  private readonly sql: SqlStorage

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env)
    this.sql = ctx.storage.sql
    applyMigrations(this.sql, ctx.storage, [PLATFORM_VAULT_AREA])
  }

  // Spends the proof's nonce, then counts the call against the platform's
  // limits in fixed one-minute windows. A refused call counts against
  // nothing, and its nonce stays spent. `now` is the Worker's clock, read
  // before the body arrived, so admissions can reach here out of its order:
  // nonces are purged by this object's clock alone, and a proof is fresh
  // only while it is by the Worker's clock and, within the grace, by this
  // object's, so none is admitted after its nonce could have gone.
  async admit(admission: PlatformAdmission, now = Date.now()): Promise<PlatformAdmissionResult> {
    try {
      const objectNow = Date.now()
      const freshUntil = (admission.iat + PROOF_MAX_SKEW_SECONDS + 1) * 1000
      if (freshUntil <= now || freshUntil + ADMIT_GRACE_MS <= objectNow) throw platformExpiredRefusal()
      this.sql.exec("DELETE FROM platform_nonces WHERE expires_at <= ?", objectNow - ADMIT_GRACE_MS - NONCE_KEPT_PAST_FRESHNESS_MS)
      const spent = this.sql.exec(
        "INSERT INTO platform_nonces (key, jti, expires_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
        admission.key,
        admission.jti,
        freshUntil,
      )
      if (spent.rowsWritten === 0) throw platformReplayRefusal()
      const window = Math.floor(now / MINUTE_MS)
      const counters: [string, number][] = [["calls", admission.limits.callsPerMinute]]
      if (admission.write && admission.subjectHash !== null) counters.push([`writes:${admission.subjectHash}`, admission.limits.subjectWritesPerMinute])
      if (admission.decision) counters.push(["decisions", admission.limits.decisionsPerMinute])
      if (admission.decision && admission.subjectHash !== null) counters.push([`decisions:${admission.subjectHash}`, admission.limits.subjectDecisionsPerMinute])
      this.sql.exec("DELETE FROM platform_counters WHERE window < ?", window)
      for (const [name, limit] of counters) {
        const count = one(this.sql.exec<{ count: number }>("SELECT count FROM platform_counters WHERE name = ? AND window = ?", name, window))?.count ?? 0
        if (count >= limit) {
          const retryAfter = Math.max(1, Math.ceil(((window + 1) * MINUTE_MS - now) / 1000))
          throw new VaultError("rate_limited", "This platform is making too many calls; slow down.", { retryAfter })
        }
      }
      for (const [name] of counters) {
        this.sql.exec("INSERT INTO platform_counters (name, window, count) VALUES (?, ?, 1) ON CONFLICT (name, window) DO UPDATE SET count = count + 1", name, window)
      }
      return { ok: true }
    } catch (error) {
      if (!(error instanceof VaultError)) console.error(JSON.stringify({ at: "platform.admit", error: error instanceof Error ? error.name : "unknown" }))
      return { ok: false, error: toWireError(error) }
    }
  }

  // One call's outcome, by route name and refusal code; never its content.
  async record(route: string, outcome: string, now = Date.now()): Promise<void> {
    const hour = Math.floor(now / HOUR_MS)
    this.sql.exec("DELETE FROM platform_activity WHERE hour < ?", hour - ACTIVITY_KEPT_HOURS)
    this.sql.exec("INSERT INTO platform_activity (hour, route, outcome, count) VALUES (?, ?, ?, 1) ON CONFLICT (hour, route, outcome) DO UPDATE SET count = count + 1", hour, route, outcome)
  }

  async activity(since: number): Promise<PlatformActivity> {
    const routes: PlatformActivity["routes"] = {}
    const rows = this.sql.exec<{ route: string; outcome: string; count: number }>("SELECT route, outcome, SUM(count) AS count FROM platform_activity WHERE hour >= ? GROUP BY route, outcome ORDER BY route, outcome", Math.floor(since / HOUR_MS)).toArray()
    for (const row of rows) (routes[row.route] ??= {})[row.outcome] = row.count
    return { since, routes }
  }

  async audit(entry: PlatformAuditEntry, now = Date.now()): Promise<void> {
    appendAudit(this.sql, now, { actor: entry.actor, action: entry.action, target: entry.target ?? null, detail: entry.detail })
  }

  // A retired platform keeps nothing here.
  async erase(): Promise<void> {
    await this.ctx.storage.deleteAll()
  }
}
