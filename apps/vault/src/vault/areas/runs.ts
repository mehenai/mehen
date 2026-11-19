// Runs: one `mehen run` each. The vault, not the manifest, decides how each
// variable is delivered (R5, R8): a plain value, a placeholder for items
// that are only ever sent over HTTP, a lease of the value only when nothing
// lower fits and everything allows it, otherwise missing with the fix.
// Protected environments need a typed --env, a device allowed for them and
// a live approval (R4). An item behind any protected environment's variable
// is protected wherever it is used, so it reaches only such an approved run.
// Ending or expiring a run kills its placeholders.

import { type Area, type DevicePrincipal, type VaultContext, accessPrincipalOf, one, rows } from "../core.ts"
import type { RunsService } from "../services.ts"
import {
  type EnvironmentRecord,
  type ProjectRecord,
  loadProject,
} from "./projects.ts"

import { assertRunUse } from "./projects-workspace.ts"
import { accessState } from "./workspace-runtime.ts"
import { workspaceRunOps, WORKSPACE_RUN_MIGRATION, WORKSPACE_RUN_SERVICE_MIGRATION, WORKSPACE_RUN_WORKLOAD_MIGRATION, workspaceRunPlaceholders } from "./runs-workspace.ts"

export const RUN_TTL_MS = 15 * 60_000
// Renewal never stretches a run past this: an approved protected run lives
// two hours at most, any other twelve. Then `mehen run` again. A service run
// (runs-workspace.ts) has none.
export const RUN_MAX_LIFE_MS = { approved: 2 * 3_600_000, other: 12 * 3_600_000 } as const

type RunRow = {
  id: string
  device: string
  session: string | null
  project: string
  env: string
  remote: string | null
  worktree: string
  head: string | null
  command: string
  grant_id: string | null
  leased_vars: string
  created_at: number
  expires_at: number
  ended_at: number | null
}

function approvedProtectedRun(device: DevicePrincipal, env: EnvironmentRecord, run: RunRow): boolean {
  return env.protected && run.grant_id !== null && device.scope.maxEnvironment === "protected"
}

// The hosts fenced to the project's other environments: a run in `env`
// never reaches them.
function fencesOutside(project: ProjectRecord, env: string): string[] {
  return [...new Set(project.environments.filter((e) => e.name !== env).flatMap((e) => e.fences))].sort()
}

// Why a run that has not ended may no longer be used: since it started, the
// owner took its project out of the machine's scope, or a human unbound the
// repository it was started from (or bound one, when it had none). Checked
// on every renew, lease, placeholder swap and relay call, so a change on the
// machines or project page applies from the machine's next request.
function runRevoked(ctx: VaultContext, device: DevicePrincipal, run: RunRow): string | null {
  if (device.scope.projects.length > 0 && !device.scope.projects.includes(run.project)) {
    return "This machine may no longer use the run's project; its owner changed what it may use."
  }
  const bound =
    run.remote === null
      ? one(ctx.sql.exec("SELECT 1 AS hit FROM remotes WHERE project = ? LIMIT 1", run.project)) === null
      : one(ctx.sql.exec("SELECT 1 AS hit FROM remotes WHERE project = ? AND remote = ?", run.project, run.remote)) !== null
  return bound ? null : "The repository this run started from is no longer bound to its project."
}

function openRun(ctx: VaultContext, device: DevicePrincipal, id: string): RunRow | null {
  return one(ctx.sql.exec<RunRow>("SELECT * FROM runs WHERE id = ? AND device = ? AND ended_at IS NULL AND expires_at > ?", id, device.device, ctx.now()))
}

function liveRun(ctx: VaultContext, device: DevicePrincipal, id: string): RunRow | null {
  const run = openRun(ctx, device, id)
  return run !== null && runRevoked(ctx, device, run) === null ? run : null
}

export const runsArea: Area = {
  name: "runs",
  workspaceOps: workspaceRunOps,
  migrations: [
    `CREATE TABLE runs (
       id TEXT PRIMARY KEY,
       device TEXT NOT NULL,
       session TEXT,
       project TEXT NOT NULL,
       env TEXT NOT NULL,
       remote TEXT,
       worktree TEXT NOT NULL,
       head TEXT,
       command TEXT NOT NULL,
       grant_id TEXT,
       created_at INTEGER NOT NULL,
       expires_at INTEGER NOT NULL,
       ended_at INTEGER
     );
     CREATE INDEX runs_device ON runs (device);
     CREATE TABLE run_placeholders (
       placeholder TEXT PRIMARY KEY,
       run TEXT NOT NULL REFERENCES runs (id),
       item TEXT NOT NULL,
       field TEXT NOT NULL,
       hosts TEXT NOT NULL
     );
     CREATE INDEX run_placeholders_run ON run_placeholders (run);`,
    // The variable names a run was given as real values; for an approved
    // protected run, exactly those the human saw.
    `ALTER TABLE runs ADD COLUMN leased_vars TEXT NOT NULL DEFAULT '[]';`,
    WORKSPACE_RUN_MIGRATION,
    WORKSPACE_RUN_WORKLOAD_MIGRATION,
    WORKSPACE_RUN_SERVICE_MIGRATION,
  ],
  // Keyed by run id: once a run has expired without being renewed, its
  // placeholders are deleted.
  async alarm(ctx, key) {
    const run = one(ctx.sql.exec<{ expires_at: number; ended_at: number | null }>("SELECT expires_at, ended_at FROM runs WHERE id = ?", key))
    if (!run) return
    if (run.ended_at === null && run.expires_at > ctx.now()) {
      ctx.schedule("runs", key, run.expires_at)
      return
    }
    ctx.sql.exec("DELETE FROM run_placeholders WHERE run = ?", key)
  },
}

export const runs: RunsService = {
  isApprovedProtectedRun(ctx, principal, id) {
    if (one(ctx.sql.exec("SELECT 1 FROM workspace_run_contexts WHERE run=?", id))) return assertRunUse(ctx, accessState(ctx), id, accessPrincipalOf(principal), ctx.now()).snapshot !== null
    const run = liveRun(ctx, principal, id)
    if (!run) return false
    const env = loadProject(ctx, run.project)?.environments.find((e) => e.name === run.env)
    return env !== undefined && approvedProtectedRun(principal, env, run)
  },
  fencesFor(ctx, principal, id) {
    // A workspace run is judged by assertRunUse alone: the legacy remote
    // rule would drop a pinned workload's run with no remote, and with it
    // every fence.
    const workspace = one(ctx.sql.exec("SELECT 1 FROM workspace_run_contexts WHERE run=?", id)) !== null
    if (workspace) assertRunUse(ctx, accessState(ctx), id, accessPrincipalOf(principal), ctx.now())
    const run = workspace ? openRun(ctx, principal, id) : liveRun(ctx, principal, id)
    const project = run ? loadProject(ctx, run.project) : null
    if (!run || !project) return null
    return { env: run.env, fencedHosts: fencesOutside(project, run.env) }
  },
  placeholdersFor(ctx, principal, run) {
    if (one(ctx.sql.exec("SELECT 1 FROM workspace_run_contexts WHERE run=?", run))) return workspaceRunPlaceholders(ctx, accessPrincipalOf(principal), run)
    if (!liveRun(ctx, principal, run)) return []
    return rows(ctx.sql.exec<{ placeholder: string; item: string; field: string; hosts: string }>("SELECT placeholder, item, field, hosts FROM run_placeholders WHERE run = ? ORDER BY placeholder", run)).map(
      (p) => ({ placeholder: p.placeholder, item: p.item, field: p.field, hosts: JSON.parse(p.hosts) as string[] }),
    )
  },
}
