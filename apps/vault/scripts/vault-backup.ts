// The operator's backup and restore of the vault itself (docs/OPERATIONS.md,
// Backup and recovery), run by hand from the operator's machine with
// wrangler access; never by tests against production.
//   status   what the cron dumped today, what failed, and recent restores;
//   pull     every dump of the last 35 days and a D1 export into a directory
//            off Cloudflare, each dump checked against vault_backup_runs;
//   restore  records one hashed restore intent after the workspace id is
//            typed back; the cron carries it out (directory/vault-backups.ts).
// Every wrangler command is printed before it runs.
import { RESTORE_INTENT_COLUMNS, newRestoreIntent, restoreIntentDigest, restoreIntentValues, restorePointInWindow, type RestoreIntentFields } from "../src/directory/vault-backups.ts"
import { backupObjectKey, utcDate } from "../src/vault/areas/vault-backup.ts"
import { spelledPrint } from "./terminal.ts"

export type Target = { kind: "remote" | "local"; database: string; bucket: string; d1: string[]; r2: string[] }
const targets: Record<Target["kind"], Target> = {
  remote: { kind: "remote", database: "mehen", bucket: "mehen-vault-backups", d1: ["--remote", "--env", ""], r2: ["--remote", "--jurisdiction", "eu"] },
  local: { kind: "local", database: "mehen-local", bucket: "mehen-vault-backups-local", d1: ["--local", "--env", "local"], r2: ["--local", "--env", "local"] },
}
const tenantId = /^tn_[A-Za-z0-9]{8,40}$/
const actorId = /^operator:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/
const dateText = /^\d{4}-\d{2}-\d{2}$/
// A time to restore to names its zone: Z or an offset, never the machine's local time.
const pitrText = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/
const DAILY_DAYS = 35

export const USAGE = "Usage: bun scripts/vault-backup.ts (--remote | --local) (status | pull --to <dir> | restore --tenant tn_id (--pitr <iso time with Z or an offset> | --dump <yyyy-mm-dd>) --actor operator:label)"
export type RestoreTarget = { source: "pitr"; target: string } | { source: "dump"; target: string }
export type VaultBackupArgs = { target: Target; command: { kind: "status" } | { kind: "pull"; to: string } | ({ kind: "restore"; tenant: string; actor: string } & RestoreTarget) }

function calendarDate(text: string): boolean {
  return dateText.test(text) && !Number.isNaN(Date.parse(`${text}T00:00:00Z`)) && new Date(`${text}T00:00:00Z`).toISOString().startsWith(text)
}

export function parseArgs(argv: string[]): VaultBackupArgs {
  if (!["--remote", "--local"].includes(argv[0] ?? "")) throw new Error(USAGE)
  const target = targets[argv[0] === "--remote" ? "remote" : "local"]
  const [command, ...rest] = argv.slice(1)
  if (command === "status" && rest.length === 0) return { target, command: { kind: "status" } }
  if (command === "pull" && rest.length === 2 && rest[0] === "--to" && rest[1] && !rest[1].startsWith("-")) return { target, command: { kind: "pull", to: rest[1] } }
  if (command === "restore" && rest.length === 6 && rest[0] === "--tenant" && tenantId.test(rest[1] ?? "") && rest[4] === "--actor" && actorId.test(rest[5] ?? "")) {
    const [flag, value] = [rest[2], rest[3] ?? ""]
    const base = { kind: "restore" as const, tenant: rest[1]!, actor: rest[5]! }
    if (flag === "--dump" && calendarDate(value)) return { target, command: { ...base, source: "dump", target: value } }
    if (flag === "--pitr" && pitrText.test(value) && !Number.isNaN(Date.parse(value))) return { target, command: { ...base, source: "pitr", target: new Date(value).toISOString() } }
  }
  throw new Error(USAGE)
}

// The one statement restore writes, the row the console's approved
// workspace.restore writes too (directory/vault-backups.ts): every value
// checked there, so the SQL text can carry nothing else.
export function restoreIntentStatement(intent: RestoreIntentFields, hash: string): string {
  const [id, tenant, source, target, actor, intentHash, createdAt, expiresAt] = restoreIntentValues(intent, hash)
  return `INSERT INTO vault_restore_intents(${RESTORE_INTENT_COLUMNS}) VALUES ('${id}','${tenant}','${source}','${target}','${actor}','${intentHash}',${createdAt},${expiresAt})`
}

export type VaultBackupIo = {
  query<T>(target: Target, sql: string): Promise<T[]>
  execute(target: Target, sql: string): Promise<void>
  bookmark(target: Target): Promise<string>
  wrangler(args: string[]): Promise<void>
  read(path: string): Promise<Uint8Array | null>
  rename(from: string, to: string): Promise<void>
  remove(path: string): Promise<void>
  mkdir(path: string): Promise<void>
  print(line: string): void
  ask(prompt: string): Promise<string | null>
  now(): number
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes))), (b) => b.toString(16).padStart(2, "0")).join("")
}

async function run(io: VaultBackupIo, args: string[]): Promise<void> {
  io.print(`$ bunx wrangler ${args.map((arg) => arg === "" ? "''" : arg).join(" ")}`)
  await io.wrangler(args)
}

async function status(target: Target, io: VaultBackupIo): Promise<number> {
  const today = utcDate(io.now()), since = utcDate(io.now() - 7 * 86_400_000)
  const [active] = await io.query<{ n: number }>(target, "SELECT COUNT(*) AS n FROM workspaces WHERE status='active'")
  const runs = await io.query<{ outcome: string; n: number; bytes: number | null }>(target, `SELECT outcome,COUNT(*) AS n,SUM(bytes) AS bytes FROM vault_backup_runs WHERE date='${today}' GROUP BY outcome ORDER BY outcome`)
  io.print(`Today (${today}, UTC): ${active?.n ?? 0} active workspaces; ${runs.map((r) => `${r.n} ${r.outcome}${r.bytes ? ` (${r.bytes} bytes)` : ""}`).join(", ") || "no dumps yet"}.`)
  const stale = await io.query<{ id: string; slug: string; last: string | null }>(target, `SELECT w.id,w.slug,(SELECT MAX(r.date) FROM vault_backup_runs r WHERE r.tenant=w.id AND r.outcome='ok') AS last FROM workspaces w WHERE w.status='active' AND COALESCE((SELECT MAX(r.date) FROM vault_backup_runs r WHERE r.tenant=w.id AND r.outcome='ok'),'')<'${utcDate(io.now() - 86_400_000)}' ORDER BY w.id`)
  for (const row of stale) io.print(`No dump since yesterday: ${row.id} (${row.slug}), last ${row.last ?? "never"}`)
  const failed = await io.query<{ tenant: string; date: string; attempts: number; error: string }>(target, `SELECT tenant,date,attempts,error FROM vault_backup_runs WHERE outcome='failed' AND date>='${since}' ORDER BY date DESC,tenant LIMIT 50`)
  for (const row of failed) io.print(`Failed: ${row.tenant} ${row.date}, ${row.attempts} attempts: ${row.error}`)
  const intents = await io.query<{ id: string; tenant: string; source: string; target: string; state: string; bookmark: string | null; undo_bookmark: string | null; error: string | null }>(target, "SELECT id,tenant,source,target,state,bookmark,undo_bookmark,error FROM vault_restore_intents ORDER BY created_at DESC LIMIT 20")
  for (const row of intents) io.print(`Restore ${row.id}: ${row.tenant} ${row.source} ${row.target}, ${row.state}${row.undo_bookmark ? `, undo bookmark ${row.undo_bookmark}` : ""}${row.error ? `, ${row.error}` : ""}`)
  return 0
}

async function pull(target: Target, to: string, io: VaultBackupIo): Promise<number> {
  const dir = to.replace(/\/+$/, "")
  const rows = await io.query<{ tenant: string; date: string; bytes: number; sha256: string }>(target, `SELECT tenant,date,bytes,sha256 FROM vault_backup_runs WHERE outcome='ok' AND date>='${utcDate(io.now() - (DAILY_DAYS - 1) * 86_400_000)}' ORDER BY date,tenant`)
  let fetched = 0, kept = 0, bad = 0
  for (const row of rows) {
    if (!tenantId.test(row.tenant) || !calendarDate(row.date) || !/^[0-9a-f]{64}$/.test(row.sha256)) { io.print(`Skipped a malformed run row for ${row.tenant} ${row.date}.`); bad++; continue }
    const key = backupObjectKey(row.tenant, row.date), dest = `${dir}/${key}`
    const existing = await io.read(dest)
    if (existing) {
      if (existing.length === row.bytes && await sha256Hex(existing) === row.sha256) { kept++; continue }
      io.print(`MISMATCH: ${dest} is already there and differs from the recorded dump; left as it is.`); bad++; continue
    }
    await io.mkdir(`${dir}/ws/${row.tenant}`)
    const part = `${dest}.part`
    await run(io, ["r2", "object", "get", `${target.bucket}/${key}`, "--file", part, ...target.r2])
    const bytes = await io.read(part)
    if (!bytes || bytes.length !== row.bytes || await sha256Hex(bytes) !== row.sha256) {
      await io.remove(part)
      io.print(`MISMATCH: ${key} does not match its recorded size and sha256; not kept.`); bad++; continue
    }
    await io.rename(part, dest)
    fetched++
  }
  await io.mkdir(`${dir}/d1`)
  await run(io, ["d1", "export", target.database, ...target.d1, "--output", `${dir}/d1/${target.database}-${utcDate(io.now())}.sql`])
  io.print(`Pulled ${fetched} new dumps, ${kept} already here and verified, ${bad} mismatched, and a D1 export, into ${dir}.`)
  return bad === 0 ? 0 : 1
}

async function restore(target: Target, command: Extract<VaultBackupArgs["command"], { kind: "restore" }>, io: VaultBackupIo): Promise<number> {
  const [workspace] = await io.query<{ id: string; slug: string; name: string; status: string }>(target, `SELECT id,slug,name,status FROM workspaces WHERE id='${command.tenant}'`)
  if (!workspace || workspace.id !== command.tenant) { io.print("Nothing changed: no workspace with that id."); return 1 }
  if (command.source === "dump") {
    const [dumped] = await io.query<{ bytes: number; sha256: string }>(target, `SELECT bytes,sha256 FROM vault_backup_runs WHERE tenant='${command.tenant}' AND date='${command.target}' AND outcome='ok'`)
    if (!dumped) { io.print("Nothing changed: no recorded dump of that workspace on that date."); return 1 }
    io.print(`Dump ${backupObjectKey(command.tenant, command.target)}: ${dumped.bytes} bytes, sha256 ${dumped.sha256}.`)
  } else {
    if (!restorePointInWindow(command.target, io.now())) { io.print("Nothing changed: a point-in-time restore reaches back at most 30 days, and not into the future."); return 1 }
  }
  const live = await io.query<{ id: string }>(target, `SELECT id FROM vault_restore_intents WHERE tenant='${command.tenant}' AND state IN ('pending','restarting')`)
  if (live.length) { io.print(`Nothing changed: restore ${live[0]!.id} for this workspace is still in progress.`); return 1 }
  const bookmark = await io.bookmark(target)
  if (!bookmark) throw new Error("No D1 bookmark; nothing changed.")
  io.print(`D1 bookmark before change: ${bookmark}`)
  io.print(`Restore ${workspace.name} (${workspace.slug}, ${workspace.id}, ${workspace.status}) on ${target.kind} database ${target.database} ${command.source === "dump" ? `from the dump of ${command.target}` : `to ${command.target}`}, actor ${command.actor}.`)
  io.print("Everything in this workspace after that point is undone: revocations, removals, approvals and rotations made since come back as they were. Freeze the workspace first, then save the audit tail past that point (GET /api/w/<slug>/audit), and re-apply its revocations afterwards.")
  if (command.source === "dump") io.print("A dump restores only into an empty workspace object; the cron refuses any other, and refuses a dump of another workspace, generation or missing root key version.")
  else io.print("The cron keeps the undo bookmark with the intent. The object restarts once to take the restore.")
  if ((await io.ask(`Type the workspace id ${workspace.id} to confirm: `))?.trim() !== workspace.id) { io.print("Nothing changed: workspace confirmation did not match."); return 1 }
  const intent = newRestoreIntent({ tenant: workspace.id, actor: command.actor, source: command.source, target: command.target }, io.now())
  await io.execute(target, restoreIntentStatement(intent, await restoreIntentDigest(intent)))
  io.print(`Recorded restore intent ${intent.id}. The cron (every 15 minutes) carries it out within the hour; follow it with: bun scripts/vault-backup.ts --${target.kind} status`)
  return 0
}

export async function runVaultBackup(args: VaultBackupArgs, terminal: VaultBackupIo): Promise<number> {
  const { target, command } = args
  const io = spelledPrint(terminal)
  if (command.kind === "status") return status(target, io)
  if (command.kind === "pull") return pull(target, command.to, io)
  return restore(target, command, io)
}

async function wranglerIo(): Promise<VaultBackupIo> {
  const { spawnSync } = await import("node:child_process")
  const { mkdir, readFile, rename, rm } = await import("node:fs/promises")
  const { createInterface } = await import("node:readline/promises")
  const cwd = `${import.meta.dirname}/..`
  async function query<T>(target: Target, sql: string): Promise<T[]> {
    const result = spawnSync("bunx", ["wrangler", "d1", "execute", target.database, ...target.d1, "--json", "--command", sql], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] })
    if (result.status !== 0) throw new Error("D1 command failed.")
    const parsed = JSON.parse(result.stdout) as { success?: boolean; results?: T[] }[]
    if (parsed.length !== 1 || parsed[0]?.success !== true) throw new Error("D1 did not confirm the statement.")
    return parsed[0].results ?? []
  }
  return {
    query, async execute(target, sql) { await query(target, sql) },
    async bookmark(target) {
      if (target.kind === "local") return "local database, no time travel"
      const result = spawnSync("bunx", ["wrangler", "d1", "time-travel", "info", target.database, "--json"], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] })
      const parsed = result.status === 0 ? JSON.parse(result.stdout) as { bookmark?: unknown } : {}
      if (typeof parsed.bookmark !== "string") throw new Error("D1 gave no bookmark.")
      return parsed.bookmark
    },
    async wrangler(args) {
      if (spawnSync("bunx", ["wrangler", ...args], { cwd, stdio: ["ignore", "inherit", "inherit"] }).status !== 0) throw new Error("wrangler failed; nothing more was done.")
    },
    async read(path) { try { return new Uint8Array(await readFile(path)) } catch { return null } },
    rename, async remove(path) { await rm(path, { force: true }) }, async mkdir(path) { await mkdir(path, { recursive: true }) },
    print: (line) => console.log(line),
    async ask(prompt) { if (!process.stdin.isTTY) return null; const rl = createInterface({ input: process.stdin, output: process.stdout }); try { return await rl.question(prompt) } finally { rl.close() } },
    now: () => Date.now(),
  }
}
if ((import.meta as { main?: boolean }).main) {
  try { process.exitCode = await runVaultBackup(parseArgs(process.argv.slice(2)), await wranglerIo()) }
  catch (error) { console.error(error instanceof Error ? error.message : "Vault backup failed."); process.exitCode = 1 }
}
