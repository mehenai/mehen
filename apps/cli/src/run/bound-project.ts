// The project the vault has bound to a checkout's origin remote, for a
// checkout with no mehen.toml: a fresh clone of a repo that is already a
// project, or a git worktree outside the main checkout. mehen init binds to
// it; run and env check name it and send the agent to mehen init, since a
// committed mehen.toml stays the source of truth and only init writes one.

import { EXIT, type ProjectBinding, ProjectBindingSchema } from "@mehen/protocol/api"
import { VaultApiError, type VaultApi } from "../vault-api.ts"
import { CommandError } from "./deps.ts"
import { type GitFacts, type Located, findManifest, gitFacts, locateManifest } from "./manifest.ts"

// Null when the checkout has no remote, no project this machine may use is
// bound to it (the vault answers both as not_found), or the vault predates
// the lookup (405).
export async function boundProject(api: VaultApi, remote: string | null): Promise<ProjectBinding | null> {
  if (remote === null) return null
  let answer: unknown
  try {
    answer = await api.request<unknown>("GET", `/v1/projects?remote=${encodeURIComponent(remote)}`)
  } catch (error) {
    if (error instanceof VaultApiError && (error.status === 404 || error.status === 405)) return null
    throw error
  }
  const parsed = ProjectBindingSchema.safeParse(answer)
  if (!parsed.success) {
    throw new CommandError(EXIT.error, `the vault's answer for the project bound to ${remote} could not be read`, { say: "Nothing was written. Try again; if it keeps failing, report it with this message." })
  }
  return parsed.data
}

// Every variable name the project defines in any environment, once.
export function boundVariables(project: ProjectBinding): string[] {
  return [...new Set(project.environments.flatMap((e) => e.variables))].sort()
}

// The refusal for a checkout with no mehen.toml whose remote is a project
// this machine may use, or null when there is a manifest or no such project.
export async function boundCheckoutRefusal(api: VaultApi, cwd: string, facts: GitFacts = gitFacts(cwd)): Promise<CommandError | null> {
  if (findManifest(cwd, facts.root) !== null) return null
  const project = await boundProject(api, facts.remote)
  if (project === null) return null
  return new CommandError(EXIT.error, `no mehen.toml in this checkout, but its remote ${facts.remote} is project ${project.slug} (${project.id})`, {
    say: `run mehen init to bind this checkout to project ${project.slug}`,
    command: "mehen init",
  })
}

// locateManifest, naming the bound project when the checkout has no manifest.
// The lookup only sharpens a refusal that comes anyway, so a lookup that
// fails leaves locateManifest's own refusal standing. Only init, where the
// lookup decides between binding and creating, lets the failure through.
export async function locateProjectManifest(api: VaultApi, cwd: string): Promise<Located> {
  const facts = gitFacts(cwd)
  const refusal = await boundCheckoutRefusal(api, cwd, facts).catch(() => null)
  if (refusal !== null) throw refusal
  return locateManifest(cwd, facts)
}
