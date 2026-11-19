// Which mehen each active machine runs, across every workspace, before the
// operator raises CLI_MINIMUM_VERSION (docs/OPERATIONS.md, Releasing the
// CLI, step 7). Read-only, run by hand from the operator's machine with the
// same wrangler access as scripts/vault-backup.ts; never by tests against
// production. It reads D1's device_cli_versions (migrations/0014), which each
// workspace object keeps: a machine's row is written when its version
// changes and deleted when it is revoked. A machine that has not called
// since then has no row and is not counted.
//   bun scripts/fleet-versions.ts --remote                 machines per version
//   bun scripts/fleet-versions.ts --remote --below 0.3.1   and every one below it
import { compareVersions } from "@mehen/protocol/version"

export type Target = { kind: "remote" | "local"; database: string; d1: string[] }
const targets: Record<Target["kind"], Target> = {
  remote: { kind: "remote", database: "mehen", d1: ["--remote", "--env", ""] },
  local: { kind: "local", database: "mehen-local", d1: ["--local", "--env", "local"] },
}
const VERSION = /^\d{1,6}\.\d{1,6}\.\d{1,6}$/

export const USAGE = "Usage: bun scripts/fleet-versions.ts (--remote | --local) [--below <x.y.z>]"
export type FleetVersionsArgs = { target: Target; below: string | null }

export function parseArgs(argv: string[]): FleetVersionsArgs {
  if (!["--remote", "--local"].includes(argv[0] ?? "")) throw new Error(USAGE)
  const target = targets[argv[0] === "--remote" ? "remote" : "local"]
  if (argv.length === 1) return { target, below: null }
  if (argv.length === 3 && argv[1] === "--below" && VERSION.test(argv[2] ?? "")) return { target, below: argv[2]! }
  throw new Error(USAGE)
}

// Only machines of an active workspace, named by its slug; a platform's
// managed workspace by its platform's slug and its tenant id.
export const FLEET_QUERY = "SELECT COALESCE(w.slug, 'managed:' || p.slug || '/' || v.tenant, v.tenant) AS workspace, v.device, v.version, v.seen_at FROM device_cli_versions v LEFT JOIN workspaces w ON w.id=v.tenant LEFT JOIN managed_workspaces m ON m.tenant=v.tenant LEFT JOIN platforms p ON p.id=m.platform WHERE COALESCE(w.status, m.status)='active' ORDER BY workspace, v.device"
export type FleetRow = { workspace: string; device: string; version: string; seen_at: number }

// Machines per version, oldest version first. A row whose version is not
// x.y.z is counted apart, never compared.
export function versionCounts(rows: readonly FleetRow[]): { counts: { version: string; machines: number }[]; unreadable: number } {
  const counts = new Map<string, number>()
  let unreadable = 0
  for (const row of rows) {
    if (VERSION.test(row.version)) counts.set(row.version, (counts.get(row.version) ?? 0) + 1)
    else unreadable++
  }
  return { counts: [...counts].map(([version, machines]) => ({ version, machines })).sort((a, b) => compareVersions(a.version, b.version)), unreadable }
}

export function machinesBelow(rows: readonly FleetRow[], version: string): FleetRow[] {
  return rows.filter((row) => VERSION.test(row.version) && compareVersions(row.version, version) < 0)
}

export type FleetVersionsIo = {
  query<T>(target: Target, sql: string): Promise<T[]>
  print(line: string): void
}

export async function runFleetVersions(args: FleetVersionsArgs, io: FleetVersionsIo): Promise<number> {
  const rows = await io.query<FleetRow>(args.target, FLEET_QUERY)
  const { counts, unreadable } = versionCounts(rows)
  io.print(`Active machines by mehen version on ${args.target.kind} database ${args.target.database}: ${rows.length} in all.`)
  for (const { version, machines } of counts) io.print(`  mehen ${version}: ${machines}`)
  if (unreadable > 0) io.print(`  not a version: ${unreadable}`)
  io.print("A machine that has not called the vault since versions were recorded is not listed.")
  if (args.below === null) return 0
  const below = machinesBelow(rows, args.below)
  io.print(`Below ${args.below}: ${below.length}.`)
  for (const row of below) io.print(`  ${row.workspace} ${row.device} mehen ${row.version}, since ${new Date(row.seen_at).toISOString()}`)
  return 0
}

async function wranglerIo(): Promise<FleetVersionsIo> {
  const { spawnSync } = await import("node:child_process")
  const cwd = `${import.meta.dirname}/..`
  return {
    async query<T>(target: Target, sql: string): Promise<T[]> {
      const result = spawnSync("bunx", ["wrangler", "d1", "execute", target.database, ...target.d1, "--json", "--command", sql], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] })
      if (result.status !== 0) throw new Error("D1 command failed.")
      const parsed = JSON.parse(result.stdout) as { success?: boolean; results?: T[] }[]
      if (parsed.length !== 1 || parsed[0]?.success !== true) throw new Error("D1 did not confirm the statement.")
      return parsed[0].results ?? []
    },
    print: (line) => console.log(line),
  }
}
if ((import.meta as { main?: boolean }).main) {
  try { process.exitCode = await runFleetVersions(parseArgs(process.argv.slice(2)), await wranglerIo()) }
  catch (error) { console.error(error instanceof Error ? error.message : "Fleet versions failed."); process.exitCode = 1 }
}
