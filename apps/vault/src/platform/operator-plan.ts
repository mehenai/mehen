// Every change to a platform in D1, planned once for both ways in: the
// operator script (scripts/platform.ts, from the operator's machine) and
// the console in the web app (routes/console.ts, the operator's and a
// platform admin's pages). Given what D1 holds now, a change is a short
// list of SQL statements run as one batch: the first must match (it
// returns a row) or nothing is recorded, and the platform_events row is
// written only when the change applied. Both ways run the same statements,
// so both reach the same D1 state; only the actor differs.
//
// Nothing here opens a secret or acts inside a managed workspace.

import { DEFAULT_PLATFORM_LIMITS, INITIAL_PLATFORM_DEFAULTS, PLATFORM_KEY_ID, PlatformJwkSchema, type PlatformDefaults, type PlatformLimits, PlatformLimitsSchema, REMOVED_PLATFORM_SLUG_PREFIX, canonicalJson, importDeviceKey, jwkThumbprint, platformSubjectHash, randomId, sha256B64 } from "@mehen/protocol"

const DAY_MS = 86_400_000
const HOUR_MS = 3_600_000

// A platform's row as the planner reads it.
export type PlatformRow = {
  id: string
  slug: string
  name: string
  status: string
  limits: string
  defaults: string
  defaults_rev: number
  created_at: number
  created_by: string
  status_at: number
  status_by: string
  status_reason: string | null
  retire_after: number | null
  removing_at: number | null
  removing_by: string | null
  removed_at: number | null
  removed_slug: string | null
}

const PLATFORM_ROW_COLUMNS = "id,slug,name,status,limits,defaults,defaults_rev,created_at,created_by,status_at,status_by,status_reason,retire_after,removing_at,removing_by,removed_at,removed_slug"

export function platformRowBySlug(slug: string): string {
  return `SELECT ${PLATFORM_ROW_COLUMNS} FROM platforms WHERE slug=${sqlText(slug)}`
}

export function platformRowById(id: string): string {
  return `SELECT ${PLATFORM_ROW_COLUMNS} FROM platforms WHERE id=${sqlText(id)}`
}

// Every value is validated before it reaches SQL; text is quoted as a
// literal with its single quotes doubled.
export function sqlText(value: string): string {
  if (/[\u0000]/.test(value)) throw new Error("Refusing a NUL in an operator value.")
  return `'${value.replaceAll("'", "''")}'`
}

export function sqlInt(value: number): string {
  if (!Number.isSafeInteger(value)) throw new Error("Refusing a non-integer operator value.")
  return String(value)
}

export function iso(ms: number | null): string {
  return ms === null ? "never" : new Date(ms).toISOString()
}

// A key or limits the planner refuses, with a sentence for the person.
export class PlatformInputError extends Error {}

export type PublicKey = { jwk: string; thumbprint: string }

// A P-256 public JWK, pasted, generated in a browser or read from a file;
// never one holding a private part.
export async function publicKeyOf(raw: unknown): Promise<PublicKey> {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new PlatformInputError("The key is not a JWK.")
  if ("d" in raw) throw new PlatformInputError("The key holds a private part; send only the public half.")
  const { kty, crv, x, y } = raw as Record<string, unknown>
  const parsed = PlatformJwkSchema.safeParse({ kty, crv, x, y })
  if (!parsed.success) throw new PlatformInputError("The key is not a P-256 public JWK.")
  try {
    await importDeviceKey(parsed.data)
  } catch {
    throw new PlatformInputError("The key's point is not on P-256.")
  }
  return { jwk: canonicalJson(parsed.data), thumbprint: await jwkThumbprint(parsed.data) }
}

// Limits laid over `base`: a partial object changes only what it names.
export function limitsOver(raw: unknown, base: PlatformLimits): PlatformLimits {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new PlatformInputError("The limits are not an object.")
  const parsed = PlatformLimitsSchema.safeParse({ ...base, ...raw })
  if (!parsed.success) throw new PlatformInputError(`The limits are refused: ${parsed.error.issues.map((issue) => `${issue.path.join(".") || "limits"} ${issue.message}`).join("; ")}.`)
  return parsed.data
}

// A change and who makes it: `operator:<who>` (the script's label, or the
// console's account id) or `admin:<account id>`.
export type PlatformChange =
  | { command: "register"; slug: string; name: string; key: unknown; limits: unknown; actor: string }
  | { command: "suspend"; slug: string; reason: string; actor: string }
  | { command: "resume"; slug: string; actor: string }
  | { command: "rotate-key"; slug: string; key: unknown; overlapHours: number; actor: string }
  | { command: "revoke-key"; slug: string; key: string; actor: string }
  | { command: "limits"; slug: string; limits: unknown; actor: string }
  | { command: "delete-subjects"; slug: string; reason: string; actor: string }
  | { command: "retire"; slug: string; afterDays: number; actor: string }
  | { command: "remove"; slug: string; reason: string; actor: string }
  | { command: "add-admin"; slug: string; account: string; actor: string }
  | { command: "remove-admin"; slug: string; account: string; actor: string }
  | { command: "defaults"; slug: string; defaults: PlatformDefaults; revision: number; actor: string }
  | { command: "delete-subject"; slug: string; subject: string; actor: string }

// What a platform admin may change; everything else is the operator's.
export const ADMIN_COMMANDS: readonly PlatformChange["command"][] = ["defaults", "rotate-key", "revoke-key", "delete-subject"]
// What only the console's admin pages change; the operator never does.
const ADMIN_ONLY_COMMANDS: readonly PlatformChange["command"][] = ["defaults", "delete-subject"]

export type PlatformPlan = { summary: string; statements: string[]; done: string; event: string }

export type PlanIds = { event: string; platform: string; key: string; admin?: string }

export function newPlanIds(): PlanIds {
  return { event: randomId("pev"), platform: randomId("plt"), key: randomId("pky"), admin: randomId("pad") }
}

// Reads what the plan needs beyond the platform's own row.
export type PlanReader = <T>(sql: string) => Promise<T[]>

function roleOf(actor: string): "operator" | "admin" {
  if (/^operator:[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(actor)) return "operator"
  if (/^admin:acc_[A-Za-z0-9_-]{1,64}$/.test(actor)) return "admin"
  throw new Error("Refusing an actor that is neither operator: nor admin:.")
}

// The event is written only when the statement before it in the batch
// changed something (or `guard` holds), so a guard that no longer matched
// records nothing.
function eventInsert(id: string, platform: string, at: number, actor: string, action: string, detail: Record<string, unknown>, guard?: string): string {
  const values = `${sqlText(id)},${sqlText(platform)},${sqlInt(at)},${sqlText(actor)},${sqlText(action)},${sqlText(JSON.stringify(detail))}`
  return guard === undefined ? `INSERT INTO platform_events (id,platform,at,actor,action,detail) VALUES (${values})` : `INSERT INTO platform_events (id,platform,at,actor,action,detail) SELECT ${values} WHERE ${guard}`
}

// The plan for a change, from what D1 holds now. A string is the reason
// it cannot apply; a PlatformInputError is a key or limits refused.
export async function planPlatformChange(change: PlatformChange, platform: PlatformRow | null, read: PlanReader, now: number, ids: PlanIds): Promise<PlatformPlan | string> {
  const role = roleOf(change.actor)
  if (role === "admin" && !ADMIN_COMMANDS.includes(change.command)) return "a platform admin cannot do that"
  if (role === "operator" && ADMIN_ONLY_COMMANDS.includes(change.command)) return "that is the platform admins' to change"
  const at = sqlInt(now)
  const actor = sqlText(change.actor)
  const action = (verb: string) => `${role}.${verb}`
  if (change.command === "register") {
    // A platform being removed keeps its slug until the cron has purged every
    // subject: two runs, 15 minutes apart, for up to 50 subjects.
    if (platform) return platform.removing_at !== null ? `${change.slug} is still held by the platform being removed; it is free once the cron has purged that platform's subjects, within 30 minutes for 50 or fewer` : "a platform with that slug exists"
    if (change.slug.startsWith(REMOVED_PLATFORM_SLUG_PREFIX)) return `slugs starting ${REMOVED_PLATFORM_SLUG_PREFIX} are kept for removed platforms`
    const key = await publicKeyOf(change.key)
    if ((await read<{ id: string }>(`SELECT id FROM platform_keys WHERE thumbprint=${sqlText(key.thumbprint)}`)).length > 0) return "that key is already registered; the platform must make a new one"
    const limits = change.limits === null ? DEFAULT_PLATFORM_LIMITS : limitsOver(change.limits, DEFAULT_PLATFORM_LIMITS)
    return {
      summary: `register ${change.slug} ("${change.name}") as ${ids.platform} with key ${ids.key} (thumbprint ${key.thumbprint}), limits ${canonicalJson(limits)}`,
      statements: [
        `INSERT INTO platforms (id,slug,name,status,limits,defaults,defaults_rev,created_at,created_by,status_at,status_by) VALUES (${sqlText(ids.platform)},${sqlText(change.slug)},${sqlText(change.name)},'active',${sqlText(canonicalJson(limits))},${sqlText(canonicalJson(INITIAL_PLATFORM_DEFAULTS))},1,${at},${actor},${at},${actor}) RETURNING id`,
        `INSERT INTO platform_keys (id,platform,jwk,thumbprint,created_at,created_by) VALUES (${sqlText(ids.key)},${sqlText(ids.platform)},${sqlText(key.jwk)},${sqlText(key.thumbprint)},${at},${actor})`,
        eventInsert(ids.event, ids.platform, now, change.actor, action("register"), { key: ids.key, thumbprint: key.thumbprint, limits }),
      ],
      done: `Registered ${change.slug}. Platform id ${ids.platform}, key id ${ids.key}: give both to the platform for its configuration.`,
      event: ids.event,
    }
  }
  if (!platform) return "no platform with that slug"
  if (platform.removing_at !== null) return "the platform is being removed"
  const id = sqlText(platform.id)
  switch (change.command) {
    case "suspend":
      if (platform.status !== "active" && platform.status !== "retiring") return `the platform is ${platform.status}`
      return {
        summary: `suspend ${platform.slug} (${platform.id}), now ${platform.status}: its calls are refused at once and its devices' within 30 seconds${platform.status === "retiring" ? "; its retirement date is cleared" : ""}`,
        statements: [
          `UPDATE platforms SET status='suspended',retire_after=NULL,status_at=${at},status_by=${actor},status_reason=${sqlText(change.reason)} WHERE id=${id} AND status IN ('active','retiring') AND removing_at IS NULL RETURNING id`,
          eventInsert(ids.event, platform.id, now, change.actor, action("suspend"), { reason: change.reason, from: platform.status }, "changes()>0"),
        ],
        done: `Suspended ${platform.slug}.`,
        event: ids.event,
      }
    case "resume":
      if (platform.status !== "suspended" && !(platform.status === "retiring" && (platform.retire_after ?? 0) > now)) return `the platform is ${platform.status}${platform.status === "retiring" ? " and its retirement date has passed" : ""}`
      return {
        summary: `resume ${platform.slug} (${platform.id}), now ${platform.status}`,
        statements: [
          `UPDATE platforms SET status='active',retire_after=NULL,status_at=${at},status_by=${actor},status_reason=NULL WHERE id=${id} AND (status='suspended' OR (status='retiring' AND retire_after>${at})) AND removing_at IS NULL RETURNING id`,
          eventInsert(ids.event, platform.id, now, change.actor, action("resume"), { from: platform.status }, "changes()>0"),
        ],
        done: `Resumed ${platform.slug}.`,
        event: ids.event,
      }
    case "rotate-key": {
      if (platform.status === "retired") return "the platform is retired"
      const key = await publicKeyOf(change.key)
      if ((await read<{ id: string }>(`SELECT id FROM platform_keys WHERE thumbprint=${sqlText(key.thumbprint)}`)).length > 0) return "that key is already registered; the platform must make a new one"
      const until = now + change.overlapHours * HOUR_MS
      return {
        summary: `add key ${ids.key} (thumbprint ${key.thumbprint}) to ${platform.slug} (${platform.id}); every other live key expires at ${iso(until)}`,
        statements: [
          `INSERT INTO platform_keys (id,platform,jwk,thumbprint,created_at,created_by) SELECT ${sqlText(ids.key)},${id},${sqlText(key.jwk)},${sqlText(key.thumbprint)},${at},${actor} WHERE EXISTS (SELECT 1 FROM platforms WHERE id=${id} AND status!='retired' AND removing_at IS NULL) RETURNING id`,
          `UPDATE platform_keys SET expires_at=${sqlInt(until)} WHERE platform=${id} AND id!=${sqlText(ids.key)} AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>${sqlInt(until)}) AND EXISTS (SELECT 1 FROM platform_keys WHERE id=${sqlText(ids.key)})`,
          eventInsert(ids.event, platform.id, now, change.actor, action("rotate_key"), { key: ids.key, thumbprint: key.thumbprint, overlapHours: change.overlapHours }, `EXISTS (SELECT 1 FROM platform_keys WHERE id=${sqlText(ids.key)})`),
        ],
        done: `Added key ${ids.key} to ${platform.slug}; the platform must use it before ${iso(until)}.`,
        event: ids.event,
      }
    }
    case "revoke-key": {
      if (!PLATFORM_KEY_ID.test(change.key)) return "no such key"
      const [key] = await read<{ revoked_at: number | null }>(`SELECT revoked_at FROM platform_keys WHERE id=${sqlText(change.key)} AND platform=${id}`)
      if (!key) return "the platform has no such key"
      if (key.revoked_at !== null) return "the key is already revoked"
      // An admin never leaves the platform without a live key, now or once a
      // rotation's overlap ends, so another key must have no expiry; the
      // operator may, after suspending it, when a key leaked.
      const others = `EXISTS (SELECT 1 FROM platform_keys o WHERE o.platform=${id} AND o.id!=${sqlText(change.key)} AND o.revoked_at IS NULL AND o.expires_at IS NULL)`
      if (role === "admin" && (await read<{ id: string }>(`SELECT 1 AS id WHERE ${others}`)).length === 0) return "that would leave the platform with no key once its other keys end; add a new key first"
      return {
        summary: `revoke key ${change.key} of ${platform.slug} (${platform.id}) at once`,
        statements: [
          `UPDATE platform_keys SET revoked_at=${at},revoked_by=${actor} WHERE id=${sqlText(change.key)} AND platform=${id} AND revoked_at IS NULL${role === "admin" ? ` AND ${others}` : ""} RETURNING id`,
          eventInsert(ids.event, platform.id, now, change.actor, action("revoke_key"), { key: change.key }, "changes()>0"),
        ],
        done: `Revoked ${change.key}.`,
        event: ids.event,
      }
    }
    case "limits": {
      const before = PlatformLimitsSchema.parse(JSON.parse(platform.limits))
      const after = limitsOver(change.limits, before)
      return {
        summary: `set ${platform.slug}'s limits from ${canonicalJson(before)} to ${canonicalJson(after)}`,
        statements: [
          `UPDATE platforms SET limits=${sqlText(canonicalJson(after))} WHERE id=${id} AND limits=${sqlText(platform.limits)} AND removing_at IS NULL RETURNING id`,
          eventInsert(ids.event, platform.id, now, change.actor, action("limits"), { before, after }, "changes()>0"),
        ],
        done: `Set ${platform.slug}'s limits.`,
        event: ids.event,
      }
    }
    case "delete-subjects": {
      const [live] = await read<{ n: number }>(`SELECT COUNT(*) AS n FROM managed_workspaces WHERE platform=${id} AND status IN ('creating','active')`)
      if ((live?.n ?? 0) === 0) return "the platform has no live subjects"
      return {
        summary: `mark every live subject of ${platform.slug} (${platform.id}) deleting; the cron deletes them 50 a run and the platform stays registered`,
        statements: [
          `UPDATE managed_workspaces SET status='deleting' WHERE platform=${id} AND status IN ('creating','active') RETURNING tenant`,
          eventInsert(ids.event, platform.id, now, change.actor, action("delete_subjects"), { reason: change.reason, subjects: live?.n ?? 0 }, "changes()>0"),
        ],
        done: `Marked ${platform.slug}'s live subjects deleting.`,
        event: ids.event,
      }
    }
    case "retire": {
      if (platform.status !== "active" && platform.status !== "suspended") return `the platform is ${platform.status}`
      // Retiring is live until its date, so retiring a suspended platform
      // later would lift its suspension at once.
      if (platform.status === "suspended" && change.afterDays > 0) return "the platform is suspended; retire it after 0 days, or resume it first"
      const after = now + change.afterDays * DAY_MS
      return {
        summary: `retire ${platform.slug} (${platform.id}): no new subjects from now; ${change.afterDays === 0 ? "its calls stop now" : `everything else works until ${iso(after)}`}; then every subject is deleted, its keys revoked and it is marked retired`,
        statements: [
          `UPDATE platforms SET status='retiring',retire_after=${sqlInt(after)},status_at=${at},status_by=${actor},status_reason=NULL WHERE id=${id} AND (status='active' OR (status='suspended' AND ${sqlInt(after)}<=${at})) AND removing_at IS NULL RETURNING id`,
          eventInsert(ids.event, platform.id, now, change.actor, action("retire"), { afterDays: change.afterDays, retireAfter: after }, "changes()>0"),
        ],
        done: `${platform.slug} retires after ${iso(after)}.`,
        event: ids.event,
      }
    }
    case "remove": {
      // Retired at once (a retired platform stays retired), every live
      // subject marked deleting and every admin ended; the cron then deletes
      // and purges every subject, retires the platform and frees its slug.
      const [live] = await read<{ n: number }>(`SELECT COUNT(*) AS n FROM managed_workspaces WHERE platform=${id} AND status IN ('creating','active')`)
      const marked = `EXISTS (SELECT 1 FROM platforms WHERE id=${id} AND removing_at=${at} AND removing_by=${actor})`
      const first =
        platform.status === "retired"
          ? `UPDATE platforms SET removing_at=${at},removing_by=${actor} WHERE id=${id} AND status='retired' AND removing_at IS NULL RETURNING id`
          : `UPDATE platforms SET status='retiring',retire_after=${at},status_at=${at},status_by=${actor},status_reason=${sqlText(change.reason)},removing_at=${at},removing_by=${actor} WHERE id=${id} AND status=${sqlText(platform.status)} AND removing_at IS NULL RETURNING id`
      return {
        summary: `remove ${platform.slug} (${platform.id}), now ${platform.status}: its calls stop now and its devices' within 30 seconds; its ${live?.n ?? 0} live subjects are deleted and every subject purged by the cron, its keys revoked, and then the slug ${platform.slug} is free; the row, its keys, its events and its subjects' tombstones are kept`,
        statements: [
          first,
          `UPDATE managed_workspaces SET status='deleting' WHERE platform=${id} AND status IN ('creating','active') AND ${marked}`,
          `UPDATE platform_admins SET removed_at=${at},removed_by=${actor} WHERE platform=${id} AND removed_at IS NULL AND ${marked}`,
          eventInsert(ids.event, platform.id, now, change.actor, action("remove"), { reason: change.reason, from: platform.status, slug: platform.slug, subjects: live?.n ?? 0 }, marked),
        ],
        done: `Removing ${platform.slug}: its calls stop now. The cron deletes and purges its subjects, then frees the slug ${platform.slug}.`,
        event: ids.event,
      }
    }
    case "add-admin": {
      if (platform.status === "retired") return "the platform is retired"
      const account = sqlText(change.account)
      const [person] = await read<{ name: string }>(`SELECT name FROM accounts WHERE id=${account} AND status='active'`)
      if (!person) return "no active account with that id"
      if ((await read<{ id: string }>(`SELECT id FROM platform_admins WHERE platform=${id} AND account=${account} AND removed_at IS NULL`)).length > 0) return "that account is already an admin of the platform"
      const admin = ids.admin ?? randomId("pad")
      return {
        summary: `make ${person.name} (${change.account}) an admin of ${platform.slug} (${platform.id})`,
        statements: [
          `INSERT INTO platform_admins (id,platform,account,added_at,added_by) SELECT ${sqlText(admin)},${id},${account},${at},${actor} WHERE EXISTS (SELECT 1 FROM accounts WHERE id=${account} AND status='active') AND EXISTS (SELECT 1 FROM platforms WHERE id=${id} AND status!='retired' AND removing_at IS NULL) AND NOT EXISTS (SELECT 1 FROM platform_admins WHERE platform=${id} AND account=${account} AND removed_at IS NULL) RETURNING id`,
          eventInsert(ids.event, platform.id, now, change.actor, action("add_admin"), { account: change.account }, "changes()>0"),
        ],
        done: `${person.name} is now an admin of ${platform.slug}.`,
        event: ids.event,
      }
    }
    case "remove-admin": {
      const account = sqlText(change.account)
      if ((await read<{ id: string }>(`SELECT id FROM platform_admins WHERE platform=${id} AND account=${account} AND removed_at IS NULL`)).length === 0) return "that account is not an admin of the platform"
      return {
        summary: `end ${change.account}'s admin role on ${platform.slug} (${platform.id})`,
        statements: [
          `UPDATE platform_admins SET removed_at=${at},removed_by=${actor} WHERE platform=${id} AND account=${account} AND removed_at IS NULL RETURNING id`,
          eventInsert(ids.event, platform.id, now, change.actor, action("remove_admin"), { account: change.account }, "changes()>0"),
        ],
        done: `${change.account} is no longer an admin of ${platform.slug}.`,
        event: ids.event,
      }
    }
    case "defaults": {
      if (platform.status === "retired") return "the platform is retired"
      if (change.revision !== platform.defaults_rev) return "the defaults changed since they were read; read them again"
      const revision = platform.defaults_rev + 1
      const detail = { revision, before: await sha256B64(canonicalJson(JSON.parse(platform.defaults))), after: await sha256B64(canonicalJson(change.defaults)) }
      return {
        summary: `set ${platform.slug}'s defaults to revision ${revision}`,
        statements: [
          `UPDATE platforms SET defaults=${sqlText(canonicalJson(change.defaults))},defaults_rev=${sqlInt(revision)} WHERE id=${id} AND defaults_rev=${sqlInt(platform.defaults_rev)} AND status!='retired' AND removing_at IS NULL RETURNING id`,
          eventInsert(ids.event, platform.id, now, change.actor, action("defaults"), detail, "changes()>0"),
        ],
        done: `Set ${platform.slug}'s defaults; they are revision ${revision}.`,
        event: ids.event,
      }
    }
    case "delete-subject": {
      const [row] = await read<{ tenant: string; status: string }>(`SELECT tenant,status FROM managed_workspaces WHERE platform=${id} AND subject=${sqlText(change.subject)} AND status IN ('creating','active','deleting') LIMIT 1`)
      if (!row) return "the platform has no live subject by that name"
      if (row.status === "deleting") return "that subject is already being deleted"
      // The event names the workspace and the subject's hash, never the
      // subject, which goes at the purge while the event stays.
      return {
        summary: `delete ${platform.slug}'s subject in ${row.tenant}`,
        statements: [
          `UPDATE managed_workspaces SET status='deleting' WHERE tenant=${sqlText(row.tenant)} AND status IN ('creating','active') RETURNING tenant`,
          eventInsert(ids.event, platform.id, now, change.actor, action("delete_subject"), { tenant: row.tenant, subjectHash: await platformSubjectHash(platform.id, change.subject) }, "changes()>0"),
        ],
        done: "The subject is being deleted: its devices are revoked and its secrets deleted, and its audit is kept for the platform's retention.",
        event: ids.event,
      }
    }
  }
}
