// Projects (R4, R5): a coding project's stable id, the git remotes allowed
// to claim it, its environments (protected or not, with host fences) and
// its variables. A repo's mehen.toml only names variables; what each one
// resolves to, and which environments are protected, lives here and is
// widened only by a member with a passkey.

import { EnvName, VarName, VarSet } from "@mehen/protocol/api"
import { normaliseRemote } from "@mehen/protocol/remote"
import { secretLikeness } from "@mehen/protocol/secret-likeness"
import { z } from "zod"
import { VaultError } from "../../http.ts"
import { type Area, type DevicePrincipal, type VaultContext, one, rows } from "../core.ts"
import type { ProjectsService } from "../services.ts"
import { digestOf } from "./approvals.ts"

import { projectWorkspaceOps, WORKSPACE_PROJECT_MIGRATION } from "./projects-workspace.ts"

export { normaliseRemote, secretLikeness }

export type EnvironmentRecord = { name: string; protected: boolean; fences: string[] }
export type VarRecord = { name: string; env: string; item: string | null; field: string | null; plain: string | null }
export type ProjectRecord = {
  id: string
  slug: string
  defaultEnv: string
  remotes: string[]
  environments: EnvironmentRecord[]
  vars: VarRecord[]
}

const ProjectId = z.string().max(64)
const SetVarInput = VarSet.extend({ project: ProjectId, name: VarName })
export type SetVarInput = z.infer<typeof SetVarInput>
// A fence is a host or a "*.example.com" pattern.
const Fence = z
  .string()
  .max(253)
  .regex(/^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/, "must be a lowercase host or *.host pattern")
const SetEnvironmentInput = z.object({ project: ProjectId, env: EnvName, protected: z.boolean(), fences: z.array(Fence).max(32) })
export type SetEnvironmentInput = z.infer<typeof SetEnvironmentInput>
const SetRemoteInput = z.object({ project: ProjectId, remote: z.string().min(1).max(512), bound: z.boolean() })
export type SetRemoteInput = z.infer<typeof SetRemoteInput>

// The digests a member's "item.update" step-up commits to, with `item` set
// to the project id. The browser computes the same from what it shows.
export function varChangeDigest(input: SetVarInput): string {
  return digestOf({
    change: "var.set",
    project: input.project,
    env: input.env,
    name: input.name,
    item: input.item ?? null,
    field: input.field ?? null,
    plain: input.plain ?? null,
  })
}

export function environmentChangeDigest(input: SetEnvironmentInput): string {
  return digestOf({ change: "environment.update", project: input.project, env: input.env, protected: input.protected, fences: input.fences })
}

export function remoteChangeDigest(input: SetRemoteInput): string {
  return digestOf({ change: input.bound ? "remote.bind" : "remote.unbind", project: input.project, remote: input.remote })
}

export const projectsArea: Area = {
  name: "projects",
  get workspaceOps() { return projectWorkspaceOps },
  get migrations() { return [
    `CREATE TABLE projects (
       id TEXT PRIMARY KEY,
       slug TEXT NOT NULL UNIQUE,
       default_env TEXT NOT NULL,
       created_by TEXT NOT NULL,
       created_at INTEGER NOT NULL,
       updated_at INTEGER NOT NULL
     );
     CREATE TABLE remotes (
       remote TEXT PRIMARY KEY,
       project TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE
     );
     CREATE INDEX remotes_project ON remotes (project);
     CREATE TABLE environments (
       project TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
       name TEXT NOT NULL,
       protected INTEGER NOT NULL,
       fences TEXT NOT NULL,
       PRIMARY KEY (project, name)
     );
     CREATE TABLE vars (
       project TEXT NOT NULL,
       env TEXT NOT NULL,
       name TEXT NOT NULL,
       item TEXT,
       field TEXT,
       plain TEXT,
       updated_by TEXT NOT NULL,
       updated_at INTEGER NOT NULL,
       PRIMARY KEY (project, env, name),
       FOREIGN KEY (project, env) REFERENCES environments (project, name) ON DELETE CASCADE
     );`,
    WORKSPACE_PROJECT_MIGRATION,
  ] },
}

export function loadProject(ctx: VaultContext, id: string): ProjectRecord | null {
  const row = one(ctx.sql.exec<{ id: string; slug: string; default_env: string }>("SELECT id, slug, default_env FROM projects WHERE id = ?", id))
  if (!row) return null
  return {
    id: row.id,
    slug: row.slug,
    defaultEnv: row.default_env,
    remotes: rows(ctx.sql.exec<{ remote: string }>("SELECT remote FROM remotes WHERE project = ? ORDER BY remote", id)).map((r) => r.remote),
    environments: rows(ctx.sql.exec<{ name: string; protected: number; fences: string }>("SELECT name, protected, fences FROM environments WHERE project = ? ORDER BY name", id)).map(
      (e) => ({ name: e.name, protected: e.protected === 1, fences: JSON.parse(e.fences) as string[] }),
    ),
    vars: rows(
      ctx.sql.exec<{ name: string; env: string; item: string | null; field: string | null; plain: string | null }>(
        "SELECT name, env, item, field, plain FROM vars WHERE project = ? ORDER BY name, env",
        id,
      ),
    ),
  }
}

export function requireProject(ctx: VaultContext, id: string): ProjectRecord {
  const project = loadProject(ctx, id)
  if (!project) {
    throw new VaultError("not_found", `No project ${id} in this vault.`, {
      next: { command: "mehen init", say: "This repository's mehen.toml names a project the vault does not know; run `mehen init` to create one." },
    })
  }
  return project
}

export function requireEnvironment(project: ProjectRecord, name: string): EnvironmentRecord {
  const env = project.environments.find((e) => e.name === name)
  if (!env) throw new VaultError("not_found", `"${project.slug}" has no environment "${name}". It has: ${project.environments.map((e) => e.name).join(", ")}.`)
  return env
}

// Empty scope projects cover every project.
export function assertCoversProject(principal: DevicePrincipal, project: ProjectRecord): void {
  if (principal.scope.projects.length > 0 && !principal.scope.projects.includes(project.id)) {
    throw new VaultError("forbidden", `This device's scope does not cover the project "${project.slug}".`)
  }
}

export function isProtectedItem(ctx: VaultContext, item: string): boolean {
  return (
    one(ctx.sql.exec("SELECT 1 AS hit FROM vars v JOIN environments e ON e.project = v.project AND e.name = v.env WHERE e.protected = 1 AND v.item = ? LIMIT 1", item)) !== null
  )
}

export function fencesAgainstItem(ctx: VaultContext, item: string): string[] {
  const fenced = rows(
    ctx.sql.exec<{ fences: string }>(
      `SELECT e.fences FROM environments e
       WHERE e.fences <> '[]' AND NOT EXISTS (SELECT 1 FROM vars v WHERE v.project = e.project AND v.env = e.name AND v.item = ?)`,
      item,
    ),
  )
  return [...new Set(fenced.flatMap((e) => JSON.parse(e.fences) as string[]))].sort()
}

function protectionRevision(ctx: VaultContext): number {
  return Number(one(ctx.sql.exec<{ value: string }>("SELECT value FROM tenant_state WHERE key = 'protection_rev'"))?.value ?? 0)
}

function bumpProtectionRevision(ctx: VaultContext): void {
  ctx.sql.exec("INSERT INTO tenant_state (key, value) VALUES ('protection_rev', '1') ON CONFLICT (key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)")
}

export const projects: ProjectsService = { isProtectedItem, fencesAgainstItem, protectionRevision, bumpProtectionRevision }
