// The gallery entries for the workspace project, credential and audit
// pages, with fixtures for every role that sees them differently: owner,
// a member who manages a project, a guest (the ask pages are
// workspace-asks-gallery.ts, built on these fixtures). Names repeat and one is
// hostile, so the gallery shows the id or slug beside every name and the
// marker in place of any control character. The audit page is here before
// its reader is served. Nothing here is imported by the Worker.

import { leaseOnlyBinding } from "@mehen/protocol/binding"
import { canonicalJson } from "@mehen/protocol/canonical-json"
import { type PushDestination, type PushRecordView, formatPushDestination, pushDestinationWords } from "@mehen/protocol/push"
import type { Share, TeamView, WorkspaceItemSummary, WorkspaceMemberView, WorkspaceProject, WorkspaceRef } from "@mehen/protocol/workspace"
import { type WorkspaceAuditPage, workspaceAuditPage } from "./pages/workspace-audit.ts"
import { type HumanItemDescription, workspaceCredentialPage, workspaceCredentialsPage } from "./pages/workspace-credentials.ts"
import { workspaceProjectPage, workspaceProjectsPage } from "./pages/workspace-projects.ts"
import { GALLERY_ORIGIN, type ShellGalleryEntry } from "./shell-gallery.ts"
import type { WorkspaceShell } from "./shell.ts"
import type { Viewer } from "./workspace-rights.ts"

const NOW = Date.parse("2026-10-27T18:30:00Z")
const ISO = (offset: number) => new Date(NOW + offset).toISOString()

export const GALLERY_WORKSPACE: WorkspaceRef = { id: "tn_8kQw2Lm4Zp7Rt5Vx", slug: "northwind", name: "Northwind" }

// Two people called Tom, and a name with a quote, markup, a right-to-left
// override and a bell.
export const GALLERY_HOSTILE_NAME = "Noor\u202e\" <b>admin</b>\u0007"
export const GALLERY_MEMBERS: WorkspaceMemberView[] = [
  { member: "mem_alex0001", name: "Alex", role: "owner", pendingRole: null, status: "active", teams: [], machines: 2, joinedAt: ISO(-90 * 86_400_000) },
  { member: "mem_tom00001", name: "Tom", role: "admin", pendingRole: null, status: "active", teams: ["tm_eng00001"], machines: 1, joinedAt: ISO(-80 * 86_400_000) },
  { member: "mem_tom00002", name: "Tom", role: "member", pendingRole: null, status: "active", teams: [], machines: 0, joinedAt: ISO(-10 * 86_400_000) },
  { member: "mem_kim00001", name: "Kim", role: "member", pendingRole: null, status: "active", teams: ["tm_eng00001"], machines: 1, joinedAt: ISO(-30 * 86_400_000) },
  { member: "mem_noor0001", name: GALLERY_HOSTILE_NAME, role: "member", pendingRole: null, status: "active", teams: [], machines: 0, joinedAt: ISO(-5 * 86_400_000) },
  { member: "mem_sam00001", name: "Sam", role: "guest", pendingRole: null, status: "active", teams: [], machines: 1, joinedAt: ISO(-2 * 86_400_000) },
]

// Two teams with the same name told apart by slug, and one with the hostile
// name. Engineering is the team the project is already shared with.
export const GALLERY_TEAMS: TeamView[] = [
  { id: "tm_eng00001", slug: "engineering", name: "Engineering", members: [{ member: "mem_tom00001", name: "Tom", role: "member" }, { member: "mem_kim00001", name: "Kim", role: "member" }], shares: [], machines: 1 },
  { id: "tm_plat0001", slug: "platform", name: "Platform", members: [], shares: [], machines: 0 },
  { id: "tm_plat0002", slug: "platform-ops", name: "Platform", members: [], shares: [], machines: 2 },
  { id: "tm_hostile1", slug: "noor-crew", name: GALLERY_HOSTILE_NAME, members: [], shares: [], machines: 0 },
]

export const VIEWERS: Readonly<Record<"owner" | "manager" | "guest", Viewer>> = {
  owner: { role: "owner", member: "mem_alex0001" },
  manager: { role: "member", member: "mem_kim00001" },
  guest: { role: "guest", member: "mem_sam00001" },
}

export function galleryShell(viewer: Viewer): WorkspaceShell {
  const role = viewer.role
  return {
    identity: { origin: GALLERY_ORIGIN, account: "acc_4Hq9Tz2Lm7Vb1Nc8", workspace: GALLERY_WORKSPACE },
    accountName: GALLERY_MEMBERS.find((m) => m.member === viewer.member)?.name ?? "Alex",
    memberships: [{ workspace: GALLERY_WORKSPACE, member: viewer.member, role, pendingRole: null, status: "active" }],
    pages: ["home", "credentials", "projects", "asks", "audit"],
    reads: [],
    accountPages: ["workspaces", "account"],
    accountHeld: viewer.held === true,
  }
}

const share = (id: string, subject: Share["subject"], level: Share["level"], prot: boolean, expiresAt: string | null = null): Share => ({ id, project: "prj_platform01", subject, level, protected: prot, expiresAt })

const SHARES: Share[] = [
  share("shr_alex0001", { kind: "member", member: "mem_alex0001" }, "manage", true),
  share("shr_kim00001", { kind: "member", member: "mem_kim00001" }, "manage", true),
  share("shr_eng00001", { kind: "team", team: "tm_eng00001" }, "use", true),
  share("shr_sam00001", { kind: "member", member: "mem_sam00001" }, "edit", false, ISO(30 * 86_400_000)),
]

const ENVIRONMENTS: WorkspaceProject["environments"] = [
  { name: "dev", protected: false, fences: [], fourEyes: false },
  { name: "staging", protected: false, fences: ["api.openai.com"], fourEyes: false },
  { name: "prod", protected: true, fences: [], fourEyes: true },
]

const VARS: WorkspaceProject["vars"] = [
  { name: "OPENAI_API_KEY", env: "dev", source: "item", item: "platform-openai", field: "key" },
  { name: "LOG_LEVEL", env: "dev", source: "plain", item: null, field: null },
  { name: "OPENAI_API_KEY", env: "prod", source: "item", item: "openai-prod", field: "key" },
  { name: "GITHUB_TOKEN", env: "prod", source: "item", item: null, field: null, note: "This variable points at a credential outside your reach." },
  { name: "SENTRY_DSN", env: "staging", source: "unset", item: null, field: null },
]

export function galleryProject(access: WorkspaceProject["access"], withShares: boolean): WorkspaceProject {
  return { id: "prj_platform01", slug: "platform", remotes: ["github.com/northwind/platform"], defaultEnv: "dev", access, ...(withShares ? { shares: SHARES } : {}), environments: ENVIRONMENTS, vars: VARS }
}

const OWNER_ACCESS: WorkspaceProject["access"] = { level: "manage", runProtected: true, editProtected: true, sources: [{ kind: "role", role: "owner" }] }
// Kim: Manage directly, and Use including protected through Engineering;
// two sources, kept apart.
const MANAGER_ACCESS: WorkspaceProject["access"] = { level: "manage", runProtected: true, editProtected: true, sources: [{ kind: "share", share: SHARES[1] as Share, via: { kind: "member", member: "mem_kim00001" } }, { kind: "share", share: SHARES[2] as Share, via: { kind: "team", team: "tm_eng00001" } }] }
const GUEST_ACCESS: WorkspaceProject["access"] = { level: "edit", runProtected: false, editProtected: false, sources: [{ kind: "share", share: SHARES[3] as Share, via: { kind: "member", member: "mem_sam00001" } }] }

const OTHER_PROJECT: WorkspaceProject = { id: "prj_website01", slug: "website", remotes: [], defaultEnv: "dev", access: OWNER_ACCESS, environments: [{ name: "dev", protected: false, fences: [], fourEyes: false }], vars: [] }

const summary = (slug: string, home: WorkspaceItemSummary["home"], provider: string | null, extra: Partial<WorkspaceItemSummary> = {}): WorkspaceItemSummary => ({ slug, kind: "api-key", provider, account: null, accountVerified: false, tags: [], ceiling: "relay", hosts: ["api.openai.com"], status: "active", updatedAt: ISO(-86_400_000), lastUsedAt: ISO(-3_600_000), home, ...extra })

export const GALLERY_ITEMS: WorkspaceItemSummary[] = [
  summary("openai-prod", { kind: "workspace" }, "openai"),
  summary("platform-openai", { kind: "project", project: "prj_platform01" }, "openai"),
  summary("github-alex", { kind: "member", member: "mem_alex0001" }, "github", { hosts: ["api.github.com"] }),
  summary("stripe-test", { kind: "workspace" }, "stripe", { hosts: ["api.stripe.com"], review: { reason: "member left: Tom", since: ISO(-7_200_000) } }),
]

// Someone else's private credential: never in any fixture a page renders.
export const GALLERY_FOREIGN_PRIVATE = "github-kim"

export function description(item: WorkspaceItemSummary, extra: Partial<Pick<HumanItemDescription, "dependencies" | "hiddenDependencies">> = {}): HumanItemDescription {
  return { ...item, lastUsedAt: item.lastUsedAt ?? null, description: null, publicFields: {}, secretFields: [{ name: "key", set: true, length: 51, prefix: item.provider === "github" ? "ghp_" : "sk-proj-", fingerprint: "Xq3vB9kR2mLw" }], binding: { hosts: item.hosts }, policy: { default: "allow", rules: [] }, injection: null, version: 3, rotatedAt: ISO(-20 * 86_400_000), id: `itm_${item.slug.replaceAll("-", "")}`, configRevision: 2, dependencyRevision: 1, dependencies: [], hiddenDependencies: false, ...extra }
}

// A Google OAuth client one visible connection signs in through, and one
// the owner cannot see (another member's private connection).
const OAUTH_CLIENT = summary("google-client", { kind: "workspace" }, "google-oauth-client", { kind: "oauth-client", hosts: ["oauth2.googleapis.com"] })

// The same client once Google rejected it: the Replace the client secret
// row in Needs you lands here.
const OAUTH_CLIENT_REJECTED = { ...OAUTH_CLIENT, status: "needs_reauth" as const, review: { reason: "Gmail rejected this OAuth client (its secret is wrong, expired or deleted), so the connections that use it are paused: replace its secret, then reconnect them", since: ISO(-3_600_000) } }

// A Gmail connection whose provider stopped accepting its token: the
// Reconnect row in Needs you lands here.
const GMAIL_REAUTH = summary("gmail-alex", { kind: "workspace" }, "google-gmail", { kind: "oauth-connection", account: "alex@northwind.example", accountVerified: true, hosts: ["gmail.googleapis.com"], status: "needs_reauth" })

// A secret adopted from a .env with no template: only mehen run delivers it.
const LEASE_ONLY = summary("jwt-secret", { kind: "project", project: "prj_platform01" }, null, { kind: "generic", ceiling: "lease", hosts: leaseOnlyBinding().hosts })

// A website login agents may type into its sign-in pages: one from its
// sign-in address, one from its hosts and one a person added, and another
// service's page it may also be typed into.
export const GALLERY_LOGIN: HumanItemDescription = {
  ...description(summary("github-login", { kind: "workspace" }, null, { kind: "password-login", account: "alex@example.com", ceiling: "fill", hosts: ["github.com", "api.github.com"] })),
  publicFields: { url: "https://github.com/login", username: "alex@example.com" },
  secretFields: [{ name: "password", set: true, length: 24, prefix: "", fingerprint: "Pw7kR2mLwXq3" }],
  browser: { signinOrigins: ["https://gist.github.com"], typeInto: ["https://dash.cloudflare.com"] },
}

const { browser: _pages, ...LOGIN_WITHOUT_PAGES } = GALLERY_LOGIN

// A workspace credential whose value a rotation replaced two days ago: the
// previous one is kept for restore.
const REPLACED: HumanItemDescription = { ...description(GALLERY_ITEMS[0] as WorkspaceItemSummary), previous: { version: 2, replacedAt: ISO(-2 * 86_400_000), expiresAt: ISO(28 * 86_400_000), replacedBy: "Kim", fields: ["key"] } }

// Where a credential was put, as items.describe lists it (design
// push-providers 3.3): the latest push to each place. A rotation since left
// four places on version 3 and one on the current version 4; the credential
// that carried the push to infra is not one this viewer sees.
const pushed = (d: PushDestination, record: Omit<PushRecordView, "destination" | "words" | "field">): PushRecordView => ({ destination: formatPushDestination(d), words: pushDestinationWords(d), field: "key", ...record })
export const GALLERY_PUSHES: PushRecordView[] = [
  pushed({ provider: "cloudflare", account: "0123456789abcdef0123456789abcdef", script: "edge-api", name: "OPENAI_API_KEY" }, { push: "psh_cf000001", version: 3, current: false, via: "cloudflare-deploy", state: "failed", outcome: null, providerStatus: 403, at: ISO(-21 * 86_400_000), by: "Kim" }),
  pushed({ provider: "github", owner: "northwind", repo: "platform", store: "actions", environment: null, name: "OPENAI_API_KEY" }, { push: "psh_gh000001", version: 3, current: false, via: "github-ci", state: "done", outcome: "replaced", providerStatus: 201, at: ISO(-20 * 86_400_000), by: "Alex" }),
  pushed({ provider: "github", owner: "northwind", repo: "website", store: "environment", environment: "production", name: "OPENAI_API_KEY" }, { push: "psh_gh000002", version: 3, current: false, via: "github-ci", state: "done", outcome: "created", providerStatus: 201, at: ISO(-19 * 86_400_000), by: "mac-mini" }),
  pushed({ provider: "vercel", project: "web-app", team: null, target: "production", name: "OPENAI_API_KEY" }, { push: "psh_vc000001", version: 4, current: true, via: null, state: "unknown", outcome: null, providerStatus: null, at: ISO(-3_600_000) }),
  pushed({ provider: "github", owner: "northwind", repo: "infra", store: "dependabot", environment: null, name: "OPENAI_API_KEY" }, { push: "psh_gh000003", version: 3, current: false, via: null, state: "done", outcome: "created", providerStatus: 201, at: ISO(-18 * 86_400_000), by: "Kim" }),
]
// A workspace credential no protected environment needs four eyes for,
// allowed to be pushed, rotated since three of its pushes.
const PUSHED_ITEM = summary("openai-ci", { kind: "workspace" }, "openai")
const PUSHABLE: HumanItemDescription = { ...description(PUSHED_ITEM), version: 4, pushable: true, pushes: GALLERY_PUSHES }

const AT = (offset: number) => NOW + offset
const row = (seq: number, offset: number, actor: string, action: string, target: string | null, detail: unknown): WorkspaceAuditPage["events"][number] => ({ seq, at: AT(offset), actor, action, target, detail: canonicalJson(detail), prev: `h${seq - 1}`, hash: `h${seq}` })

const AUDIT: WorkspaceAuditPage = {
  verified: true,
  filtered: false,
  head: { seq: 48, hash: "h48" },
  next: "45",
  events: [
    row(48, -60_000, "member:mem_tom00001", "project.environment.update", "prj_platform01", { env: "prod", protected: true, fences: [], fourEyes: false, loosened: true }),
    row(47, -120_000, "member:mem_alex0001", "project.share", "prj_platform01", { subject: { kind: "member", member: "mem_kim00001" }, before: null, after: { level: "edit", protected: true, expiresAt: null } }),
    row(46, -180_000, "device:dev_macmini1", "relay.allow", "itm_githubalex", { action: "relay.allow", at: AT(-180_000), actor: { kind: "device", device: "dev_macmini1", owner: { kind: "member", member: "mem_alex0001" } }, session: null, item: "itm_githubalex", slug: "github-alex", outcome: "allowed", run: null }),
    row(45, -240_000, "member:mem_alex0001", "member.remove", "mem_tom00002", { member: "mem_tom00002", machines: 2, privateItems: 1, rotate: 3 }),
  ],
}

const AUDIT_NAMES = { members: new Map(GALLERY_MEMBERS.map((m) => [m.member, m.name])), devices: new Map([["dev_macmini1", "mac-mini"]]) }

export const WORKSPACE_PROJECT_PAGE_KINDS = ["ws-projects", "ws-project", "ws-credentials", "ws-credential", "ws-audit"] as const

const GROUP = "Workspace projects and credentials"

export function workspaceProjectsGallery(): ShellGalleryEntry[] {
  const owner = galleryShell(VIEWERS.owner)
  const manager = galleryShell(VIEWERS.manager)
  const guest = galleryShell(VIEWERS.guest)
  const heldOwner: Viewer = { ...VIEWERS.owner, held: true }
  const ownerProject = galleryProject(OWNER_ACCESS, true)
  const managerProject = galleryProject(MANAGER_ACCESS, true)
  const guestProject = galleryProject(GUEST_ACCESS, false)
  const workspaceItems = GALLERY_ITEMS.filter((i) => i.home.kind !== "member" || i.home.member === VIEWERS.owner.member)
  return [
    { id: "ws-projects-owner", group: GROUP, title: "Projects, owner", note: "Every project in the workspace with the owner's level, and the new-project form.", page: workspaceProjectsPage(owner, { viewer: VIEWERS.owner, projects: [ownerProject, OTHER_PROJECT] }) },
    { id: "ws-projects-guest", group: GROUP, title: "Projects, guest", note: "Only the project shared with the guest; no new-project form.", page: workspaceProjectsPage(guest, { viewer: VIEWERS.guest, projects: [guestProject] }) },
    { id: "ws-project-owner", group: GROUP, title: "Project, owner", note: "Access sources kept apart, shares with duplicate and hostile names beside their ids, protect, four-eyes and fences offered, variables with Belongs to.", page: workspaceProjectPage(owner, { viewer: VIEWERS.owner, project: ownerProject, items: workspaceItems, members: GALLERY_MEMBERS, overrides: [{ environment: "dev", variable: "OPENAI_API_KEY", source: { kind: "item", item: "github-alex", field: "key" }, updatedAt: ISO(-3_600_000) }], teams: GALLERY_TEAMS }) },
    { id: "ws-project-share-teams", group: GROUP, title: "Project, sharing with a team", note: "The share form offers teams beside people: two teams called Platform told apart by slug, a hostile team name made inert, and the existing team share named. Choosing a team says which workspace credentials its machines could then use.", page: workspaceProjectPage(owner, { viewer: VIEWERS.owner, project: ownerProject, items: workspaceItems, members: GALLERY_MEMBERS, overrides: [], teams: GALLERY_TEAMS }) },
    { id: "ws-project-manager", group: GROUP, title: "Project, member who manages it", note: "Prod uses a workspace credential: loosening and fences are owner-or-admin only and the page says so in the vault's words instead of offering them.", page: workspaceProjectPage(manager, { viewer: VIEWERS.manager, project: managerProject, items: GALLERY_ITEMS.filter((i) => i.home.kind !== "member"), members: GALLERY_MEMBERS, overrides: [], teams: GALLERY_TEAMS }) },
    { id: "ws-project-guest", group: GROUP, title: "Project, guest", note: "No share list, no people, no protection controls; unprotected variables only.", page: workspaceProjectPage(guest, { viewer: VIEWERS.guest, project: guestProject, items: GALLERY_ITEMS.filter((i) => i.home.kind === "project" || i.slug === "openai-prod"), members: null, overrides: null }) },
    { id: "ws-project-held", group: GROUP, title: "Project, owner whose account is restricted", note: "After a recovery the vault refuses every change but reading, denying, narrowing and freezing: the page says so once and offers no control.", page: workspaceProjectPage(galleryShell(heldOwner), { viewer: heldOwner, project: ownerProject, items: workspaceItems, members: GALLERY_MEMBERS, overrides: [{ environment: "dev", variable: "OPENAI_API_KEY", source: { kind: "item", item: "github-alex", field: "key" }, updatedAt: ISO(-3_600_000) }], teams: GALLERY_TEAMS }) },
    { id: "ws-credentials-owner", group: GROUP, title: "Credentials, owner", note: "Each credential with Belongs to; the owner's own private one appears, nobody else's; the remove-by-name form shows nothing about what it removes.", page: workspaceCredentialsPage(owner, { viewer: VIEWERS.owner, items: workspaceItems, projects: [ownerProject, OTHER_PROJECT] }) },
    { id: "ws-credentials-adding", group: GROUP, title: "Credentials, adding one", note: "The add sheet the page head's button opens: the service, the name and where it belongs, then Continue to the page that seals it.", page: workspaceCredentialsPage(owner, { viewer: VIEWERS.owner, items: workspaceItems, projects: [ownerProject, OTHER_PROJECT], adding: true }) },
    { id: "ws-credentials-held", group: GROUP, title: "Credentials, owner whose account is restricted", note: "The list to read, with no Add a credential and no remove-by-name, and one line saying why.", page: workspaceCredentialsPage(galleryShell(heldOwner), { viewer: heldOwner, items: workspaceItems, projects: [ownerProject, OTHER_PROJECT] }) },
    { id: "ws-credential-private", group: GROUP, title: "Credential, own private", note: "Only me: its own metadata, the private audit limit, and moving it into a project the owner edits.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: description(GALLERY_ITEMS[2] as WorkspaceItemSummary), projects: [ownerProject, OTHER_PROJECT] }) },
    { id: "ws-credential-oauth-client", group: GROUP, title: "OAuth client with dependent connections", note: "Delete and move list the connections that sign in through it; a connection the viewer cannot see is only said to exist.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: description(OAUTH_CLIENT, { dependencies: [{ slug: "gmail-alex", role: "connection" }], hiddenDependencies: true }), projects: [ownerProject, OTHER_PROJECT] }) },
    { id: "ws-credential-client-rejected", group: GROUP, title: "OAuth client, rejected by its provider", note: "The Replace the client secret row in Needs you lands here: why its connections are paused, and Replace, which clears it.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: description(OAUTH_CLIENT_REJECTED), projects: [ownerProject, OTHER_PROJECT] }) },
    { id: "ws-credential-reconnect", group: GROUP, title: "Connection, needs reconnecting", note: "The Reconnect row in Needs you lands here: why, and Reconnect, which signs in to the provider again under the same name.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: description(GMAIL_REAUTH), projects: [ownerProject, OTHER_PROJECT] }) },
    { id: "ws-credential-review", group: GROUP, title: "Credential, needs review", note: "The Review row in Needs you lands here: the reason and since when, and Replace, which clears it.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: description(GALLERY_ITEMS[3] as WorkspaceItemSummary), projects: [ownerProject, OTHER_PROJECT] }) },
    { id: "ws-credential-workspace", group: GROUP, title: "Credential, whole workspace", note: "Used by prod: replace, move with the exact warning, delete listing what depends on it.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: description(GALLERY_ITEMS[0] as WorkspaceItemSummary), projects: [ownerProject, OTHER_PROJECT] }) },
    { id: "ws-credential-previous", group: GROUP, title: "Credential with a replaced value kept", note: "A rotation replaced its value: until when the previous one is kept, who replaced it and when, which fields, and Restore it with passkey.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: REPLACED, projects: [ownerProject, OTHER_PROJECT] }) },
    { id: "ws-credential-previous-held", group: GROUP, title: "Credential with a replaced value, restricted account", note: "The kept value is described, and no restore is offered to someone who may not change it.", page: workspaceCredentialPage(galleryShell(heldOwner), { viewer: heldOwner, item: REPLACED, projects: [ownerProject, OTHER_PROJECT] }) },
    { id: "ws-credential-web-pages", group: GROUP, title: "Credential, in web pages", note: "Where typing into web pages is on: how agents may use it, each sign-in page marked where it came from with Remove on the one added, the page of another service it may also be typed into, and Save with passkey.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: GALLERY_LOGIN, projects: [ownerProject], fill: true }) },
    { id: "ws-credential-web-pages-read-only", group: GROUP, title: "Credential, in web pages, for someone who may not change it", note: "The same lists to read, with no choice, no Add and no Save.", page: workspaceCredentialPage(guest, { viewer: VIEWERS.guest, item: GALLERY_LOGIN, projects: [guestProject], fill: true }) },
    { id: "ws-credential-web-pages-ceiling", group: GROUP, title: "Credential, in web pages, its ceiling decides", note: "A login whose ceiling is lease: no choice is offered, since saving changes only relay or fill.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: { ...LOGIN_WITHOUT_PAGES, ceiling: "lease" }, projects: [ownerProject], fill: true }) },
    { id: "ws-credential-web-pages-key", group: GROUP, title: "API key, in web pages", note: "No sign-in pages for a key: only the pages of other services it may be typed into, None to start, and a line while its ceiling does not allow typing.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: description(GALLERY_ITEMS[0] as WorkspaceItemSummary), projects: [ownerProject], fill: true }) },
    { id: "ws-credential-lease-only", group: GROUP, title: "Credential with no host", note: "Adopted from a .env with no template: May only go to reads No host, only delivered into a process with mehen run.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: description(LEASE_ONLY), projects: [ownerProject, OTHER_PROJECT] }) },
    { id: "ws-credential-push-allowance", group: GROUP, title: "Credential, may be put into other services' secret stores", note: "Its own card after the standing rules: the tick, off until someone who may change the credential saves it with a passkey. Pushed nowhere yet, so no Pushed to.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: { ...description(PUSHED_ITEM), pushable: false, pushes: [] }, projects: [ownerProject, OTHER_PROJECT], pushes: true }) },
    { id: "ws-credential-pushed", group: GROUP, title: "Credential, pushed and since rotated", note: "Pushed to lists the latest push to each place: where, how it went, the version with older than the current value, when and by whom. Each names the credential that carried it where the viewer sees it. Push the new value to the same places offers the places still on an older value, each unticked, and greys out one whose carrying credential the viewer cannot see; delete lists the places its copies stay.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: PUSHABLE, projects: [ownerProject, OTHER_PROJECT], pushes: true }) },
    { id: "ws-credential-pushed-four-eyes", group: GROUP, title: "Credential, pushed, needs four eyes", note: "Prod needs a second person for it, so the page offers no push again and says to push it from a machine's ask.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: { ...description(GALLERY_ITEMS[0] as WorkspaceItemSummary), version: 4, pushable: true, pushes: GALLERY_PUSHES }, projects: [ownerProject, OTHER_PROJECT], pushes: true }) },
    { id: "ws-credential-pushed-not-allowed", group: GROUP, title: "Credential, pushed, allowance since turned off", note: "The places stay listed; push again says to allow it first.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: { ...PUSHABLE, pushable: false }, projects: [ownerProject, OTHER_PROJECT], pushes: true }) },
    { id: "ws-credential-pushed-reader", group: GROUP, title: "Credential, pushed, read by a member who may not change it", note: "The allowance as a fact without a tick, and the list without push again.", page: workspaceCredentialPage(manager, { viewer: VIEWERS.manager, item: PUSHABLE, projects: [managerProject, OTHER_PROJECT], pushes: true }) },
    { id: "ws-audit-owner", group: GROUP, title: "Activity, owner", note: "The design's sentences, the chain verified, each event's stored bytes folded; a private event stays minimal.", page: workspaceAuditPage(owner, { viewer: VIEWERS.owner, page: AUDIT, names: AUDIT_NAMES }) },
    { id: "ws-audit-member", group: GROUP, title: "Activity, member", note: "A filtered view: only owners and admins can verify the whole chain.", page: workspaceAuditPage(manager, { viewer: VIEWERS.manager, page: { ...AUDIT, filtered: true, next: null, events: AUDIT.events.slice(1, 2) }, names: AUDIT_NAMES }) },
  ]
}

export const GALLERY_FIXTURES = { SHARES, MANAGER_ACCESS, OWNER_ACCESS, GUEST_ACCESS }
