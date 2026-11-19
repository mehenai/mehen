// Which project and credential controls a workspace page offers, from what
// the page's reads say about the viewer: their role, the project's effective
// access and the homes of the credentials its variables point at. It mirrors
// the evaluator (vault/access.ts) so a page never offers what the vault would
// refuse; the vault still decides every change. Pure and free of Worker
// imports, so the browser bundle and the tests use the same rules.

import type { CredentialHome, EffectiveAccess, WorkspaceProject, WorkspaceRole } from "@mehen/protocol/workspace"

// `held`: the account is restricted after a recovery, or a security change
// is still reaching its workspaces. The vault then lets a person read, deny,
// narrow and freeze, and refuses every other change (access.ts
// restrictedAction), so a held viewer is offered none of these controls.
// Absent reads as not held.
export type Viewer = { role: WorkspaceRole; member: string; held?: boolean }

// Said once on a page whose changes a held viewer is not offered.
export const HELD_WORDS = "Your account is restricted after a recovery or a security change, so this page offers no changes until that is over. Reading and denying still work."

const elevated = (role: WorkspaceRole): boolean => role === "owner" || role === "admin"
const rank = { use: 1, edit: 2, manage: 3 } as const

export function hasLevel(access: EffectiveAccess | null | undefined, level: "use" | "edit" | "manage"): boolean {
  return access?.level !== null && access?.level !== undefined && rank[access.level] >= rank[level]
}

// ---------------------------------------------------------------- Belongs to

export type HomeKind = CredentialHome["kind"]

export const HOME_WORDS: Readonly<Record<HomeKind, string>> = { project: "This project", workspace: "Whole workspace", member: "Only me" }

// "This project (platform)", "Whole workspace", "Only me". Inside the
// project the home names, the project goes without saying.
export function belongsToWords(home: CredentialHome, projectSlugs: ReadonlyMap<string, string>, here: string | null = null): string {
  if (home.kind !== "project" || home.project === here) return HOME_WORDS[home.kind]
  const slug = projectSlugs.get(home.project)
  return slug === undefined ? "A project you cannot open" : `${HOME_WORDS.project} (${slug})`
}

// The homes a viewer may create a credential in: always their own private
// one; a project they edit; the whole workspace for owners and admins.
export function creatableHomes(viewer: Viewer, projects: readonly Pick<WorkspaceProject, "id" | "slug" | "access">[]): CredentialHome[] {
  if (viewer.held === true) return []
  return [
    { kind: "member", member: viewer.member },
    ...projects.filter((p) => hasLevel(p.access, "edit")).map((p): CredentialHome => ({ kind: "project", project: p.id })),
    ...(elevated(viewer.role) ? [{ kind: "workspace" } as const] : []),
  ]
}

// ---------------------------------------------------------------- credentials

export type CredentialControls = {
  // Replace the secret through a new intake (or reconnect).
  rotate: boolean
  // Binding, policy, ceiling, tags, description.
  update: boolean
  delete: boolean
  // Where it may move to; empty when it may not move.
  rehomeTo: CredentialHome[]
}

// Managing a credential's home: its owner for a private one, owners and
// admins for the workspace, the project's managers for a project one.
function managesHome(viewer: Viewer, home: CredentialHome, access: (project: string) => EffectiveAccess | null): boolean {
  if (home.kind === "member") return home.member === viewer.member
  if (home.kind === "workspace") return elevated(viewer.role)
  return hasLevel(access(home.project), "manage")
}

// `references`: the projects whose variables point at this credential, as
// far as the viewer can see; owners and admins see them all.
export function credentialControls(viewer: Viewer, home: CredentialHome, projects: readonly Pick<WorkspaceProject, "id" | "access">[], references: readonly string[]): CredentialControls {
  if (viewer.held === true) return { rotate: false, update: false, delete: false, rehomeTo: [] }
  const access = (id: string) => projects.find((p) => p.id === id)?.access ?? null
  const manages = managesHome(viewer, home, access)
  const guest = viewer.role === "guest"
  const own = home.kind === "member" && home.member === viewer.member
  const rehomeTo: CredentialHome[] = []
  if (own) rehomeTo.push(...projects.filter((p) => hasLevel(p.access, "edit")).map((p): CredentialHome => ({ kind: "project", project: p.id })))
  else if (elevated(viewer.role) && home.kind !== "member") {
    if (home.kind === "project") rehomeTo.push({ kind: "workspace" })
    // Into a project only while no other project's variables point at it.
    for (const p of projects) {
      if (home.kind === "project" && home.project === p.id) continue
      if (references.every((r) => r === p.id)) rehomeTo.push({ kind: "project", project: p.id })
    }
  }
  return { rotate: manages && (!guest || own), update: manages && (!guest || own), delete: (manages && !guest) || own, rehomeTo }
}

// Putting a rotated value where an older one was pushed: the owner of a
// private credential; for a shared one an owner, an admin, or whoever
// manages where it belongs, never a guest (access.ts credential.push).
export function canPushAgain(viewer: Viewer, home: CredentialHome, projects: readonly Pick<WorkspaceProject, "id" | "access">[]): boolean {
  if (viewer.held === true) return false
  if (home.kind === "member") return home.member === viewer.member
  if (viewer.role === "guest") return false
  return elevated(viewer.role) || managesHome(viewer, home, (id) => projects.find((p) => p.id === id)?.access ?? null)
}

// Owners and admins may purge someone else's private credential by its
// name alone; the page that does it shows nothing about it.
export function canPurgePrivate(viewer: Viewer): boolean {
  return viewer.held !== true && elevated(viewer.role)
}

// Members, admins and owners create projects in the browser; guests never.
export function canCreateProject(viewer: Viewer): boolean {
  return viewer.held !== true && viewer.role !== "guest"
}

// ---------------------------------------------------------------- projects

export type EnvironmentControls = {
  protect: boolean
  unprotect: boolean
  fourEyesOn: boolean
  fourEyesOff: boolean
  fences: boolean
  // Variables may be set here at all; which sources is below.
  setVariables: boolean
  // A variable may point at a workspace credential.
  workspaceSources: boolean
  // A variable whose current source is a workspace credential may be
  // removed or repointed.
  repointWorkspace: boolean
  // The vault's own words for a control it keeps for owners and admins,
  // shown where the control would be.
  ownerOnly: string[]
}

export type ProjectControls = {
  share: boolean
  // Sharing with a guest needs an owner or admin.
  shareWithGuests: boolean
  remotes: boolean
  delete: boolean
  deleteOwnerOnly: string | null
  environments: Record<string, EnvironmentControls>
}

// What the page knows about one environment's variables: which point at a
// workspace credential.
export type EnvironmentReferences = { workspaceReference: boolean }

const ALWAYS_PROTECTED = new Set(["prod", "production"])

// `sharedWithService`: the project is shared with a guest or with a team
// that may own a machine; there only owners and admins point variables at
// workspace credentials. Null when the page cannot know (the vault shows the
// share list to managers only): then the page does not offer them either.
export function projectControls(viewer: Viewer, project: Pick<WorkspaceProject, "slug" | "access" | "defaultEnv" | "environments">, references: Readonly<Record<string, EnvironmentReferences>>, sharedWithService: boolean | null): ProjectControls {
  const live = viewer.held !== true
  const boss = live && elevated(viewer.role)
  const manage = live && viewer.role !== "guest" && hasLevel(project.access, "manage")
  const edit = live && hasLevel(project.access, "edit")
  const environments: Record<string, EnvironmentControls> = {}
  for (const env of project.environments) {
    const where = `${project.slug}/${env.name}`
    const workspaceReference = references[env.name]?.workspaceReference === true
    const ownerOnly: string[] = []
    const loosenAllowed = manage && (boss || !workspaceReference)
    if (manage && !boss && workspaceReference && (env.protected && !ALWAYS_PROTECTED.has(env.name) || env.fourEyes)) ownerOnly.push(`Only an owner or admin can loosen ${where}: it uses workspace credentials.`)
    if (manage && !boss && workspaceReference && !env.protected) ownerOnly.push(`Only an owner or admin can protect ${where}: it uses workspace credentials.`)
    if (manage && !boss) ownerOnly.push(`Only an owner or admin can change fences for ${where}.`)
    environments[env.name] = {
      protect: manage && !env.protected && env.name !== project.defaultEnv && (boss || !workspaceReference),
      unprotect: loosenAllowed && env.protected && !ALWAYS_PROTECTED.has(env.name),
      fourEyesOn: manage && env.protected && !env.fourEyes,
      fourEyesOff: loosenAllowed && env.fourEyes,
      fences: manage && boss,
      setVariables: edit && (!env.protected || project.access.editProtected),
      workspaceSources: boss || (!env.protected && sharedWithService === false && edit),
      repointWorkspace: !env.protected || boss,
      ownerOnly,
    }
  }
  const protectedWorkspace = project.environments.some((e) => e.protected && references[e.name]?.workspaceReference === true)
  return {
    share: manage,
    shareWithGuests: manage && boss,
    remotes: manage,
    delete: manage && (boss || !protectedWorkspace),
    deleteOwnerOnly: manage && !boss && protectedWorkspace ? `Only an owner or admin can delete ${project.slug}: a protected environment uses workspace credentials.` : null,
    environments,
  }
}

// ---------------------------------------------------------------- access sources

export type SourceLine = { from: string; level: string; protectedRun: boolean; protectedEdit: boolean; expiresAt: string | null }

// Each source of a person's access as it was granted, never folded into a
// level plus a tick: "use, including protected" from a team and "edit" from
// a direct share stay two lines.
export function accessSourceLines(access: EffectiveAccess, names: { member: (id: string) => string; team: (id: string) => string }): SourceLine[] {
  return access.sources.map((source) => {
    if (source.kind === "role") return { from: `Workspace ${source.role}`, level: "manage", protectedRun: true, protectedEdit: true, expiresAt: null }
    const { share } = source
    const from = source.via.kind === "member" ? `Shared with ${names.member(source.via.member)}` : `Through the team ${names.team(source.via.team)}`
    const manage = share.level === "manage"
    return { from, level: share.level, protectedRun: manage || share.protected, protectedEdit: manage || (share.level === "edit" && share.protected), expiresAt: share.expiresAt }
  })
}
