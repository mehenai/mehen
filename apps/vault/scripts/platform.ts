// Offline operator commands for platform mode (the pattern of operator.ts):
// D1 only, from the operator's machine, never over HTTP. Every change
// prints the D1 bookmark and its plan, asks for the platform's slug typed
// back, then runs one guarded batch whose first statement must match, and
// which writes one platform_events row. The plans are operator-plan.ts's,
// the same the web console runs, so the script stays the break-glass for
// everything the console does. Nothing here opens a secret or acts inside a
// managed workspace.

import { ACCOUNT_ID, PLATFORM_KEY_ID, PLATFORM_KEY_MAX_OVERLAP_HOURS, PLATFORM_KEY_OVERLAP_HOURS, PLATFORM_RETIRE_MAX_DAYS, PlatformNameSchema, PlatformSlugSchema, randomId } from "@mehen/protocol"
import { type PlanIds, type PlatformChange, PlatformInputError, type PlatformPlan, type PlatformRow, iso, planPlatformChange, platformRowBySlug, sqlInt, sqlText } from "../src/platform/operator-plan.ts"
import { MANAGED_WORKSPACE_STATUSES, type ManagedWorkspaceStatus } from "../src/platform/registry.ts"
import { activityCounts, activityEventId } from "../src/platform/sweeps.ts"
import type { OperatorTarget } from "./operator.ts"
import { spelledPrint } from "./terminal.ts"

export { sqlText }

const ACTOR = /^operator:[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/
const DAY_MS = 86_400_000

const USAGE = `Usage: bun scripts/platform.ts (--remote | --local) <command> <slug> ...
  register <slug> --name "<Name>" --key <public-jwk.json> [--limits <limits.json>] --actor operator:<you>
  show <slug>
  subjects <slug> [--status <status>]
  suspend <slug> --reason "<words>" --actor operator:<you>
  resume <slug> --actor operator:<you>
  rotate-key <slug> --key <new-public-jwk.json> [--overlap-hours ${PLATFORM_KEY_OVERLAP_HOURS}] --actor operator:<you>
  revoke-key <slug> <pky_id> --actor operator:<you>
  limits <slug> --limits <limits.json> --actor operator:<you>
  delete-subjects <slug> --reason "<words>" --actor operator:<you>
  retire <slug> --after-days <n> --actor operator:<you>
  remove <slug> --reason "<words>" --actor operator:<you>
  add-admin <slug> <acc_id> --actor operator:<you>
  remove-admin <slug> <acc_id> --actor operator:<you>`

export type PlatformCommand =
  | { command: "register"; slug: string; name: string; keyFile: string; limitsFile: string | null; actor: string }
  | { command: "show"; slug: string }
  | { command: "subjects"; slug: string; status: ManagedWorkspaceStatus | null }
  | { command: "suspend"; slug: string; reason: string; actor: string }
  | { command: "resume"; slug: string; actor: string }
  | { command: "rotate-key"; slug: string; keyFile: string; overlapHours: number; actor: string }
  | { command: "revoke-key"; slug: string; key: string; actor: string }
  | { command: "limits"; slug: string; limitsFile: string; actor: string }
  | { command: "delete-subjects"; slug: string; reason: string; actor: string }
  | { command: "retire"; slug: string; afterDays: number; actor: string }
  | { command: "remove"; slug: string; reason: string; actor: string }
  | { command: "add-admin"; slug: string; account: string; actor: string }
  | { command: "remove-admin"; slug: string; account: string; actor: string }

export type PlatformArgs = { target: OperatorTarget } & PlatformCommand

function usage(): never {
  throw new Error(USAGE)
}

// Free words (a name, a reason): printable, no quotes that could end a SQL
// literal unescaped (they are escaped anyway), no control characters.
function words(value: string | undefined, max: number): string {
  if (value === undefined || value.trim() === "" || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) usage()
  return value.trim()
}

function wholeNumber(value: string | undefined, max: number): number {
  if (value === undefined || !/^\d{1,4}$/.test(value)) usage()
  const n = Number(value)
  if (n > max) usage()
  return n
}

export function parsePlatformArgs(argv: string[]): PlatformArgs {
  const [where, command, slug, ...rest] = argv
  if (where !== "--remote" && where !== "--local") usage()
  if (!PlatformSlugSchema.safeParse(slug).success || slug === undefined) usage()
  const remote = where === "--remote"
  const target: OperatorTarget = { kind: remote ? "remote" : "local", database: remote ? "mehen" : "mehen-local", flags: remote ? ["--remote", "--env", ""] : ["--local", "--env", "local"] }
  const positional: string[] = []
  const flags = new Map<string, string>()
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i] as string
    if (!arg.startsWith("--")) {
      positional.push(arg)
      continue
    }
    const value = rest[i + 1]
    if (value === undefined || flags.has(arg)) usage()
    flags.set(arg, value)
    i++
  }
  const allowed = (names: string[], positionals = 0) => {
    if ([...flags.keys()].some((name) => !names.includes(name)) || positional.length !== positionals) usage()
  }
  const actor = () => {
    const value = flags.get("--actor")
    if (value === undefined || !ACTOR.test(value)) usage()
    return value
  }
  switch (command) {
    case "register":
      allowed(["--name", "--key", "--limits", "--actor"])
      if (!PlatformNameSchema.safeParse(flags.get("--name")).success) usage()
      return { target, command, slug, name: words(flags.get("--name"), 64), keyFile: words(flags.get("--key"), 1024), limitsFile: flags.has("--limits") ? words(flags.get("--limits"), 1024) : null, actor: actor() }
    case "show":
      allowed([])
      return { target, command, slug }
    case "subjects": {
      allowed(["--status"])
      const status = flags.get("--status")
      if (status !== undefined && !(MANAGED_WORKSPACE_STATUSES as readonly string[]).includes(status)) usage()
      return { target, command, slug, status: (status as ManagedWorkspaceStatus | undefined) ?? null }
    }
    case "suspend":
    case "delete-subjects":
    case "remove":
      allowed(["--reason", "--actor"])
      return { target, command, slug, reason: words(flags.get("--reason"), 200), actor: actor() }
    case "resume":
      allowed(["--actor"])
      return { target, command, slug, actor: actor() }
    case "rotate-key":
      allowed(["--key", "--overlap-hours", "--actor"])
      return { target, command, slug, keyFile: words(flags.get("--key"), 1024), overlapHours: flags.has("--overlap-hours") ? wholeNumber(flags.get("--overlap-hours"), PLATFORM_KEY_MAX_OVERLAP_HOURS) : PLATFORM_KEY_OVERLAP_HOURS, actor: actor() }
    case "revoke-key": {
      allowed(["--actor"], 1)
      const key = positional[0]
      if (key === undefined || !PLATFORM_KEY_ID.test(key)) usage()
      return { target, command, slug, key, actor: actor() }
    }
    case "limits":
      allowed(["--limits", "--actor"])
      return { target, command, slug, limitsFile: words(flags.get("--limits"), 1024), actor: actor() }
    case "retire":
      allowed(["--after-days", "--actor"])
      return { target, command, slug, afterDays: wholeNumber(flags.get("--after-days"), PLATFORM_RETIRE_MAX_DAYS), actor: actor() }
    case "add-admin":
    case "remove-admin": {
      allowed(["--actor"], 1)
      const account = positional[0]
      if (account === undefined || !ACCOUNT_ID.test(account)) usage()
      return { target, command, slug, account, actor: actor() }
    }
    default:
      return usage()
  }
}

export type PlatformIo = {
  query<T>(target: OperatorTarget, sql: string): Promise<T[]>
  // One batch, run as one transaction; the rows each statement returned.
  batch(target: OperatorTarget, statements: string[]): Promise<unknown[][]>
  bookmark(target: OperatorTarget): Promise<string>
  ask(prompt: string): Promise<string | null>
  readFile(path: string): Promise<string>
  print(line: string): void
  now(): number
}

async function readJson(io: PlatformIo, path: string, what: string): Promise<unknown> {
  try {
    return JSON.parse(await io.readFile(path))
  } catch {
    throw new Error(`The ${what} file is not JSON.`)
  }
}

// The change the planner takes: the key and limits files read as JSON.
async function changeOf(args: Exclude<PlatformArgs, { command: "show" | "subjects" }>, io: PlatformIo): Promise<PlatformChange> {
  const { target: _target, ...rest } = args
  switch (rest.command) {
    case "register":
      return { command: "register", slug: rest.slug, name: rest.name, key: await readJson(io, rest.keyFile, "key"), limits: rest.limitsFile === null ? null : await readJson(io, rest.limitsFile, "limits"), actor: rest.actor }
    case "rotate-key":
      return { command: "rotate-key", slug: rest.slug, key: await readJson(io, rest.keyFile, "key"), overlapHours: rest.overlapHours, actor: rest.actor }
    case "limits":
      return { command: "limits", slug: rest.slug, limits: await readJson(io, rest.limitsFile, "limits"), actor: rest.actor }
    default:
      return rest
  }
}

// The plan for a change, from what D1 holds now (operator-plan.ts, shared
// with the web console). Null with a reason when the change cannot apply.
export async function platformPlan(args: Exclude<PlatformArgs, { command: "show" | "subjects" }>, platform: PlatformRow | null, io: PlatformIo, ids: PlanIds): Promise<PlatformPlan | string> {
  try {
    return await planPlatformChange(await changeOf(args, io), platform, (sql) => io.query(args.target, sql), io.now(), ids)
  } catch (error) {
    if (error instanceof PlatformInputError) throw new Error(error.message)
    throw error
  }
}

// The operator's view of one platform with its N workspaces.
async function show(args: Extract<PlatformArgs, { command: "show" }>, platform: PlatformRow, io: PlatformIo): Promise<number> {
  const id = sqlText(platform.id)
  const keys = await io.query<{ id: string; created_at: number; expires_at: number | null; revoked_at: number | null }>(args.target, `SELECT id,created_at,expires_at,revoked_at FROM platform_keys WHERE platform=${id} ORDER BY created_at,id`)
  const statuses = await io.query<{ status: string; n: number }>(args.target, `SELECT status,COUNT(*) AS n FROM managed_workspaces WHERE platform=${id} GROUP BY status`)
  const activity = await io.query<{ at: number; detail: string }>(args.target, `SELECT at,detail FROM platform_events WHERE id=${sqlText(activityEventId(platform.id))}`)
  const since = io.now() - DAY_MS
  const operator = await io.query<{ n: number }>(args.target, `SELECT COUNT(*) AS n FROM platform_events WHERE platform=${id} AND at>=${sqlInt(since)} AND action LIKE 'operator.%'`)
  const total = statuses.reduce((sum, row) => sum + row.n, 0)
  const byStatus = MANAGED_WORKSPACE_STATUSES.map((status) => `${statuses.find((row) => row.status === status)?.n ?? 0} ${status}`).join(", ")
  io.print(`Platform ${platform.name} (${platform.slug}, ${platform.id})`)
  io.print(`Status: ${platform.status} since ${iso(platform.status_at)} by ${platform.status_by}${platform.status_reason ? `: ${platform.status_reason}` : ""}${platform.retire_after !== null ? `; retires after ${iso(platform.retire_after)}` : ""}`)
  if (platform.removing_at !== null) io.print(`Removal asked ${iso(platform.removing_at)} by ${platform.removing_by ?? "unknown"}; ${platform.removed_at !== null ? `slug ${platform.removed_slug ?? "unknown"} freed ${iso(platform.removed_at)}` : "the cron is deleting and purging its subjects"}`)
  io.print(`Registered ${iso(platform.created_at)} by ${platform.created_by}`)
  io.print(`Limits: ${platform.limits}`)
  io.print(`Defaults revision: ${platform.defaults_rev}`)
  io.print(`Keys: ${keys.length}`)
  for (const key of keys) io.print(`  ${key.id} added ${iso(key.created_at)}, ${key.revoked_at !== null ? `revoked ${iso(key.revoked_at)}` : key.expires_at !== null ? `expires ${iso(key.expires_at)}` : "live"}`)
  io.print(`Workspaces: ${total} (${byStatus})`)
  const admins = await io.query<{ account: string; name: string; added_at: number; added_by: string }>(args.target, `SELECT a.account,c.name,a.added_at,a.added_by FROM platform_admins a JOIN accounts c ON c.id=a.account WHERE a.platform=${id} AND a.removed_at IS NULL ORDER BY a.added_at,a.account`)
  io.print(`Admins: ${admins.length}`)
  for (const admin of admins) io.print(`  ${admin.name} (${admin.account}) added ${iso(admin.added_at)} by ${admin.added_by}`)
  const row = activity[0]
  if (!row) io.print("Last 24 hours: no activity recorded yet.")
  else {
    const counts = activityCounts(JSON.parse(row.detail))
    io.print(`Last 24 hours, as of ${iso(row.at)}: ${counts.devices} devices made, ${counts.added} items added, ${counts.deleted} items deleted, ${counts.decisions} decisions, ${counts.refusals} refusals`)
  }
  io.print(`Operator actions in the last 24 hours: ${operator[0]?.n ?? 0}`)
  return 0
}

async function subjects(args: Extract<PlatformArgs, { command: "subjects" }>, platform: PlatformRow, io: PlatformIo): Promise<number> {
  const rows = await io.query<{ tenant: string; subject: string | null; status: string; created_at: number; deleted_at: number | null; purge_after: number | null }>(args.target, `SELECT tenant,subject,status,created_at,deleted_at,purge_after FROM managed_workspaces WHERE platform=${sqlText(platform.id)}${args.status ? ` AND status=${sqlText(args.status)}` : ""} ORDER BY created_at,tenant`)
  io.print(`${platform.slug} (${platform.id}): ${rows.length} workspaces${args.status ? ` ${args.status}` : ""}`)
  for (const row of rows) io.print(`${row.tenant} ${row.subject ?? "(purged)"} ${row.status} created ${iso(row.created_at)}${row.deleted_at !== null ? ` deleted ${iso(row.deleted_at)}` : ""}${row.purge_after !== null && row.status === "deleted" ? ` purges after ${iso(row.purge_after)}` : ""}`)
  return 0
}

export async function runPlatform(args: PlatformArgs, terminal: PlatformIo, ids: PlanIds = { event: randomId("pev"), platform: randomId("plt"), key: randomId("pky"), admin: randomId("pad") }): Promise<number> {
  const io = spelledPrint(terminal)
  const [platform] = await io.query<PlatformRow>(args.target, platformRowBySlug(args.slug))
  if (args.command === "show" || args.command === "subjects") {
    if (!platform) {
      io.print("No platform with that slug.")
      return 1
    }
    return args.command === "show" ? show(args, platform, io) : subjects(args, platform, io)
  }
  const plan = await platformPlan(args, platform ?? null, io, ids)
  if (typeof plan === "string") {
    io.print(`Nothing changed: ${plan}.`)
    return 1
  }
  const bookmark = await io.bookmark(args.target)
  if (!bookmark) throw new Error("No D1 bookmark; nothing changed.")
  io.print(`D1 bookmark before change: ${bookmark}`)
  io.print(`On ${args.target.kind} database ${args.target.database}, actor ${args.actor}: ${plan.summary}.`)
  io.print("One batch; its first statement must match, or nothing is recorded:")
  for (const statement of plan.statements) io.print(statement)
  if ((await io.ask(`Type the platform's slug ${args.slug}: `))?.trim() !== args.slug) {
    io.print("Nothing changed: the slug confirmation did not match.")
    return 1
  }
  const results = await io.batch(args.target, plan.statements)
  if ((results[0]?.length ?? 0) === 0) {
    io.print("Nothing changed: the platform no longer matched.")
    return 1
  }
  io.print(plan.done)
  return 0
}

async function platformIo(): Promise<PlatformIo> {
  const { spawnSync } = await import("node:child_process")
  const { readFile } = await import("node:fs/promises")
  const { createInterface } = await import("node:readline/promises")
  const run = (args: string[]) => {
    const result = spawnSync("bunx", ["wrangler", ...args], { cwd: import.meta.dirname + "/..", encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] })
    if (result.status !== 0) throw new Error("Platform command failed; inspect the database before retrying.")
    return JSON.parse(result.stdout) as unknown
  }
  const execute = (target: OperatorTarget, sql: string): unknown[][] => {
    const result = run(["d1", "execute", target.database, ...target.flags, "--json", "--command", sql]) as { success?: boolean; results?: unknown[] }[]
    if (result.length === 0 || result.some((r) => r.success !== true)) throw new Error("D1 did not confirm the platform statements.")
    return result.map((r) => r.results ?? [])
  }
  return {
    async query<T>(target: OperatorTarget, sql: string) {
      return (execute(target, sql)[0] ?? []) as T[]
    },
    async batch(target, statements) {
      return execute(target, statements.join(";\n"))
    },
    async bookmark(target) {
      if (target.kind === "local") return "local database, no time travel"
      const result = run(["d1", "time-travel", "info", target.database, "--json"]) as { bookmark?: unknown }
      if (typeof result.bookmark !== "string") throw new Error("D1 gave no bookmark.")
      return result.bookmark
    },
    async ask(prompt) {
      if (!process.stdin.isTTY) return null
      const rl = createInterface({ input: process.stdin, output: process.stdout })
      try {
        return await rl.question(prompt)
      } finally {
        rl.close()
      }
    },
    readFile: (path) => readFile(path, "utf8"),
    print: (line) => console.log(line),
    now: () => Date.now(),
  }
}

if ((import.meta as { main?: boolean }).main) {
  try {
    process.exitCode = await runPlatform(parsePlatformArgs(process.argv.slice(2)), await platformIo())
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Platform command failed.")
    process.exitCode = 1
  }
}
