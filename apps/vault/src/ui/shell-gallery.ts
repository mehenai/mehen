// The workspace shell's gallery entries: every shell and picker page, the
// workspace home with its Get started variants, the account inbox and the
// one-workspace filter of Needs you, with fixture data, including the ones
// whose reads have not merged yet and so are not served live (the account
// page is in account-gallery.ts). scripts/ui-gallery.ts renders them with
// the rest; shell-gallery.test.ts checks every shell page is here and every
// fixture matches the frozen protocol shapes. Every fixture pins `now`.
// Nothing here is imported by the Worker.

import { fingerprintGroups, fingerprintOf, fingerprintWords } from "@mehen/protocol/fingerprint"
import type { InboxItem, InboxResponse, InboxWorkspace, WorkspaceInboxResponse } from "@mehen/protocol/inbox"
import type { AccountSession, MembershipView, MinimalStopView, WorkspaceDeviceView, WorkspaceNotice, WorkspaceRef } from "@mehen/protocol/workspace"
import type { PageInput } from "./layout.ts"
import { needsYouPage } from "./pages/needs-you.ts"
import { workspacePendingPage } from "./pages/workspace-pending.ts"
import { type HomeData, pickerPage, workspaceHomePage, workspaceNotFoundPage } from "./pages/workspaces.ts"
import type { AccountPageKey, AccountShell, ShellIdentity, WorkspacePageKey, WorkspaceShell } from "./shell.ts"
import { staleRefusal } from "./client/shell-logic.ts"
import { GALLERY_ITEMS, GALLERY_MEMBERS, galleryProject, GALLERY_FIXTURES } from "./workspace-projects-gallery.ts"
import { PEOPLE_DEVICE, PEOPLE_INVITES } from "./people-gallery.ts"

export const GALLERY_ORIGIN = "https://app.mehen.dev"

// The shell pages the gallery must show, by the boot page each renders.
export const SHELL_PAGES = ["workspace-home", "workspaces", "error", "ws-pending", "needs-you"] as const

// The clock every fixture here is drawn at.
export const GALLERY_NOW = Date.parse("2026-10-27T18:30:00Z")
const ISO = (offset: number) => new Date(GALLERY_NOW + offset).toISOString()
const MIN = 60_000

export type ShellGalleryEntry = {
  id: string
  group: string
  title: string
  note: string
  page: PageInput
  swap?: [string | RegExp, string][]
  notice?: { tone: "warn" | "error" | "info"; title: string; lines: string[] }
}

function membership(id: string, slug: string, name: string, overrides: Partial<MembershipView> = {}): MembershipView {
  return { workspace: { id, slug, name }, member: `mem_${slug.replaceAll("-", "")}01`, role: "owner", pendingRole: null, status: "active", ...overrides }
}

const PERSONAL = membership("tn_1glzRP4mFIhFAOIMdmsfx", "alex", "Personal")
const NORTHWIND = membership("tn_8kQw2Lm4Zp7Rt5Vx", "northwind", "Northwind", { role: "admin" })
// Same display name as the real one: only the slug tells them apart.
const NORTHWIND_TWIN = membership("tn_3hNc6Yb9Gd2Ks1Pw", "northwind-labs", "Northwind", { role: "member" })
const CLIENT_GUEST = membership("tn_5tFj8Rw1Qx4Mn7Lz", "acme-rebuild", "Acme rebuild", { role: "guest", status: "unconfirmed" })
const SUSPENDED = membership("tn_7mVb3Ns6Kc9Wq2Dh", "old-side-project", "Old side project", { role: "member", status: "suspended" })
// Quotes, markup and a right-to-left override: shown as text, with the marker.
const HOSTILE = membership("tn_2pLs5Gx8Hv1Jr4Ty", "hostile-name", "Northwind\u202e\" <b>admin</b>\u0007", { role: "member" })
// The longest a workspace name and slug may be.
const LONG = membership("tn_9qWe4Rt7Yu1Io3Pa", "montgomery-fitzwilliam-office-consultant", "The Montgomery-Fitzwilliam household, office and consultancy co.", { role: "member" })

export const GALLERY_HOSTILE = HOSTILE
export const GALLERY_TWINS = [NORTHWIND, NORTHWIND_TWIN] as const

export const GALLERY_MEMBERSHIPS: readonly MembershipView[] = [PERSONAL, NORTHWIND, NORTHWIND_TWIN, CLIENT_GUEST, SUSPENDED, HOSTILE, LONG]

const ACCOUNT = "acc_4Hq9Tz2Lm7Vb1Nc8"

export const GALLERY_SESSION: AccountSession = { account: ACCOUNT, name: "Alex Rae", canCreateWorkspaces: false, workspaceCreation: "default", recoverySetupRequired: false, securityEpoch: 3, pendingTransition: null, restricted: null, memberships: [...GALLERY_MEMBERSHIPS] }

const RESTRICTED_SESSION: AccountSession = { ...GALLERY_SESSION, restricted: { reason: "recovery", until: "2026-10-28T09:20:00.000Z", notice: "ntc_1a2b3c4d5e6f7081" } }

const NEW_ACCOUNT: AccountSession = { ...GALLERY_SESSION, name: "Tom Barker", memberships: [] }
const CAN_CREATE: AccountSession = { ...NEW_ACCOUNT, canCreateWorkspaces: true }
const WAITING: AccountSession = { ...NEW_ACCOUNT, memberships: [membership("tn_8kQw2Lm4Zp7Rt5Vx", "northwind", "Northwind", { role: "member", status: "unconfirmed" })] }
const RECOVERY_FIRST: AccountSession = { ...NEW_ACCOUNT, recoverySetupRequired: true }

const ALL_ACCOUNT_PAGES: readonly AccountPageKey[] = ["workspaces", "needs-you", "account"]
// Every page the workspace shell can link to: the seven of the rail and
// the More sheet's Teams, Connect an agent and Settings.
const ALL_PAGES: readonly WorkspacePageKey[] = ["home", "needs", "credentials", "projects", "machines", "people", "teams", "connect-agent", "audit", "settings", "asks"]

function identity(m: MembershipView): ShellIdentity {
  return { origin: GALLERY_ORIGIN, account: ACCOUNT, workspace: m.workspace }
}

function shell(m: MembershipView, memberships: readonly MembershipView[] | null, pages: readonly WorkspacePageKey[] = ["home"]): WorkspaceShell {
  return { identity: identity(m), accountName: GALLERY_SESSION.name, memberships, pages, reads: [], accountPages: memberships === null ? [] : ALL_ACCOUNT_PAGES, accountHeld: false }
}

export const GALLERY_ACCOUNT_SHELL: AccountShell = { origin: GALLERY_ORIGIN, account: ACCOUNT, name: GALLERY_SESSION.name, accountPages: ALL_ACCOUNT_PAGES }

// ---------------------------------------------------------------- inbox fixtures

const WORK: WorkspaceRef = NORTHWIND.workspace
const HOME: WorkspaceRef = PERSONAL.workspace
const CLIENT: WorkspaceRef = { id: "tn_6yHn2Bv5Cx8Zl1Mk", slug: "acme", name: "Acme" }
const MAC_MINI = { device: "dev_macmini1", deviceName: "sam-mac-mini", session: "native-app:fa987f" }
const THUMBPRINT = "ZlSQ8zyOFnhkWls5Qf2JrXm9cTbA7hLp0eNvK1sYdGw"

function workspaceRow(workspace: WorkspaceRef, count: number | null, overrides: Partial<InboxWorkspace> = {}): InboxWorkspace {
  return { workspace, role: "owner", state: "ok", reason: null, count, truncated: false, ...overrides }
}

function approval(workspace: WorkspaceRef, id: string, title: string, expiresIn: number, overrides: Partial<Extract<InboxItem, { kind: "ask" }>> = {}): InboxItem {
  return {
    kind: "ask",
    workspace,
    href: `/w/${workspace.slug}/a/${id}`,
    action: "decide",
    createdAt: ISO(expiresIn - 60 * MIN),
    expiresAt: ISO(expiresIn),
    ask: { workspace, owner: { kind: "member", member: "mem_alex0001", name: "Alex" }, view: "detail", detail: { kind: "approval", id, title, url: `${GALLERY_ORIGIN}/w/${workspace.slug}/a/${id}`, expiresAt: ISO(expiresIn), item: "gmail-alex", requestedBy: MAC_MINI, bindingCode: "MK7RQ4", provider: "google-gmail", createdAt: ISO(expiresIn - 60 * MIN) } },
    ...overrides,
  }
}

function intake(workspace: WorkspaceRef, id: string, slug: string, expiresIn: number): InboxItem {
  return {
    kind: "ask",
    workspace,
    href: `/w/${workspace.slug}/i/${id}`,
    action: "open",
    createdAt: ISO(expiresIn - 24 * 60 * MIN),
    expiresAt: ISO(expiresIn),
    ask: { workspace, owner: { kind: "member", member: "mem_alex0001", name: "Alex" }, view: "detail", detail: { kind: "intake", id, title: `Paste the OpenAI API key for ${slug}`, url: `${GALLERY_ORIGIN}/w/${workspace.slug}/i/${id}`, expiresAt: ISO(expiresIn), item: slug, requestedBy: { ...MAC_MINI, session: null }, provider: "openai", kindRequested: "api-key", createdAt: ISO(expiresIn - 24 * 60 * MIN) } },
  }
}

function stop(workspace: WorkspaceRef, id: string, machine: string, expiresIn: number): InboxItem {
  const view: MinimalStopView = { view: "stop", id, workspace, machine: { device: "dev_kimlaptop1", name: machine, owner: { kind: "member", member: "mem_kim00001", name: "Kim" } }, item: { slug: "github-kim" }, status: "pending", eligibility: { canApprove: false, canDeny: true, canReadAskDetail: false, deciders: [], reason: null } }
  return { kind: "ask", workspace, href: id.startsWith("apr_") ? `/w/${workspace.slug}/a/${id}` : `/w/${workspace.slug}/pending`, action: "stop", createdAt: ISO(expiresIn - 60 * MIN), expiresAt: ISO(expiresIn), ask: { workspace, owner: { kind: "member", member: "mem_kim00001", name: "Kim" }, view: "stop", stop: view } }
}

function enrolment(workspace: WorkspaceRef, id: string, name: string, expiresIn: number, overrides: Partial<Extract<InboxItem, { kind: "enrol" }>["enrol"]> = {}, action: InboxItem["action"] = "accept"): InboxItem {
  const groups: [string | null, string | null, string | null, string | null] = [...fingerprintGroups(fingerprintOf(THUMBPRINT))]
  groups[2] = null
  return {
    kind: "enrol",
    workspace,
    href: `/w/${workspace.slug}/e/${id}`,
    action,
    createdAt: ISO(expiresIn - 60 * MIN),
    expiresAt: ISO(expiresIn),
    enrol: {
      enrolment: id,
      name,
      host: `${name}.local`,
      backend: "secure-enclave",
      start: { at: ISO(expiresIn - 60 * MIN), place: "Amsterdam, NL", clientLabel: "mehen 0.3.0 on macOS" },
      session: "claude-code:7c21",
      requestedOwner: { kind: "self" },
      owner: null,
      claimed: null,
      state: "pending_owner_acceptance",
      fingerprint: { groups, words: fingerprintWords(THUMBPRINT) },
      actions: ["accept", "reject"],
      hardExpiresAt: ISO(23 * 60 * MIN),
      ...overrides,
    },
  }
}

function confirmation(workspace: WorkspaceRef, member: string, name: string, expiresIn: number, boundEmail = "tom@northwind.example"): InboxItem {
  return { kind: "confirm", workspace, href: `/w/${workspace.slug}/people#confirm-${member}`, action: "confirm", createdAt: ISO(-20 * MIN), expiresAt: ISO(expiresIn), confirm: { member, name, role: "member", invite: "inv_4k2m9q", termsDigest: "Gd7x2Kq9Vm4Nb1Zc8Rt3Yw6Hs5Jd0Fe7Gu2Ai9Ok4Pq", boundEmail, joinedAt: ISO(-20 * MIN) } }
}

function rescope(workspace: WorkspaceRef): InboxItem {
  return { kind: "rescope", workspace, href: `/w/${workspace.slug}/devices/dev_tomlaptop01`, action: "review", createdAt: null, expiresAt: ISO(3 * 24 * 60 * MIN), rescope: { proposal: "rsp_8w2n5r", device: "dev_tomlaptop01", deviceName: "tom-laptop", owner: { kind: "member", member: "mem_tom01", name: "Tom Barker" }, proposer: { member: "mem_alex0001", name: "Alex" }, as: "owner_acceptance" } }
}

const NOTICE: WorkspaceNotice = { id: "ntc_machine01", account: ACCOUNT, payload: { kind: "machine_added", workspace: WORK, device: "dev_tomlaptop01", name: "tom-laptop", owner: { kind: "member", member: "mem_tom01", name: "Tom Barker" }, place: "Amsterdam, NL", at: ISO(-45 * MIN) }, at: GALLERY_NOW - 45 * MIN, url: `${GALLERY_ORIGIN}/w/northwind/devices/dev_tomlaptop01` }

// Three workspaces with rows, grouped as the vault sends them: the group
// with the soonest expiry first.
const WORK_ITEMS: InboxItem[] = [
  approval(WORK, "apr_6t3vb9nx2w", "Send an email to priya@acme.example", 12 * MIN),
  enrolment(WORK, "enr_4h8s2kd9pq", "tom-laptop", 41 * MIN),
  stop(WORK, "apr_9pk2mw4zq1", "kim-laptop", 50 * MIN),
  confirmation(WORK, "mem_tom01", "Tom Barker", 6 * 24 * 60 * MIN),
]
const HOME_ITEMS: InboxItem[] = [intake(HOME, "int_4hz8rq2nk1", "openai-personal", 20 * 60 * MIN), rescope(HOME)]
const CLIENT_ITEMS: InboxItem[] = [enrolment(CLIENT, "enr_7j3k9m2x4b", "acme-ci", 55 * MIN, { claimed: { account: "acc_noor0001", name: "Noor" }, actions: ["reject"] }, "reject")]

export const INBOX_THREE: InboxResponse = {
  workspaces: [workspaceRow(CLIENT, 1, { role: "admin" }), workspaceRow(WORK, 4, { role: "admin" }), workspaceRow(HOME, 2)],
  items: [...WORK_ITEMS, ...CLIENT_ITEMS, ...HOME_ITEMS],
  notices: [NOTICE],
  count: 7,
  complete: true,
}

// Grouped asks (batch approvals): a review group needing a closer look at
// some, an all-routine one, and an agent's bundle with its reason.
function group(workspace: WorkspaceRef, id: string, expiresIn: number, extra: Partial<Extract<InboxItem, { kind: "group" }>["group"]>): InboxItem {
  return {
    kind: "group",
    workspace,
    href: `/w/${workspace.slug}/g/${id}`,
    action: "review",
    createdAt: ISO(expiresIn - 60 * MIN),
    expiresAt: ISO(expiresIn),
    group: { group: id, kind: id.startsWith("bnd_") ? "bundle" : "machine", machine: { device: MAC_MINI.device, name: MAC_MINI.deviceName, workload: null }, owner: { kind: "member", member: "mem_alex0001", name: "Alex" }, item: { slug: "cloudflare-api-token" }, count: 12, floor: 3, ownPage: 1, denyOnly: 0, reason: null, ...extra },
  }
}
export const INBOX_GROUPS: InboxResponse = {
  workspaces: [workspaceRow(WORK, 3, { role: "admin" })],
  items: [
    group(WORK, "grp_7kq2mw4zx1aaaaaaaaaaaa", 8 * MIN, {}),
    group(WORK, "grp_4hx8wq2mz6aaaaaaaaaaaa", 25 * MIN, { count: 2, floor: 0, ownPage: 0, item: { slug: "github-alex" }, machine: { device: MAC_MINI.device, name: MAC_MINI.deviceName, workload: { id: "wl_task8kq2mw4z", label: "globex:grant-7f3k" } } }),
    group(WORK, "bnd_5lq2mw4zl9aaaaaaaaaaaa", 40 * MIN, { count: 4, floor: 1, ownPage: 0, denyOnly: 1, item: null, reason: "Set up the staging D1 databases for the preview deploys" }),
  ],
  notices: [],
  count: 3,
  complete: true,
}

export const INBOX_EMPTY: InboxResponse = { workspaces: [workspaceRow(WORK, 0), workspaceRow(HOME, 0)], items: [], notices: [], count: 0, complete: true }

export const INBOX_UNAVAILABLE: InboxResponse = {
  workspaces: [workspaceRow(WORK, 4), workspaceRow(HOME, null, { state: "unavailable", reason: "timeout" })],
  items: WORK_ITEMS,
  notices: [],
  count: 4,
  complete: false,
}

export const INBOX_GATED_EMPTY: InboxResponse = {
  workspaces: [workspaceRow(WORK, null, { state: "gated" }), workspaceRow(HOME, 0)],
  items: [],
  notices: [],
  count: 0,
  complete: false,
}

const INBOX_FAILED: InboxResponse = {
  workspaces: [workspaceRow(WORK, null, { state: "unavailable", reason: "error" }), workspaceRow(HOME, null, { state: "unavailable", reason: "deadline" })],
  items: [],
  notices: [],
  count: 0,
  complete: false,
}

const LONG_REF: WorkspaceRef = LONG.workspace
const LONG_HOST = `${"api-gateway-".repeat(9)}eu-west-1.internal`
const LONG_EMAIL = `${"alexandra.montgomery-fitzwilliam.".repeat(4)}office@${"consultancy-".repeat(8)}example.com`.slice(0, 254)
const INBOX_LONG: InboxResponse = {
  workspaces: [workspaceRow(LONG_REF, 3, { truncated: true }), workspaceRow(HOME, 1)],
  items: [
    enrolment(LONG_REF, "enr_9z8y7x6w5v", "montgomery-fitzwilliam-office-and-consultancy-production-mini", 30 * MIN, { host: LONG_HOST, session: "a-very-long-session-label-an-agent-chose-for-itself-0123456789abcdef" }),
    approval(LONG_REF, "apr_2b3c4d5e6f", "Send an email to a long list of people at montgomery-fitzwilliam-office-and-consultancy.example about the quarterly review", 45 * MIN),
    confirmation(LONG_REF, "mem_long0001", "Alexandra Montgomery-Fitzwilliam of the household, office and consultancy", 6 * 24 * 60 * MIN),
    confirmation(HOME, "mem_long0002", "Sam", 6 * 24 * 60 * MIN, LONG_EMAIL),
  ],
  notices: [],
  count: 4,
  complete: false,
}

function single(inbox: InboxResponse, id: string): WorkspaceInboxResponse {
  const workspace = inbox.workspaces.find((w) => w.workspace.id === id)
  if (workspace === undefined) throw new Error(`gallery: no workspace ${id}`)
  return { workspace, items: inbox.items.filter((i) => i.workspace.id === id), notices: inbox.notices.filter((n) => n.payload.workspace.id === id) }
}

// ---------------------------------------------------------------- home fixtures

const OWNER_VIEWER = { role: "owner" as const, member: "mem_alex0001" }
const OWN_DEVICE: WorkspaceDeviceView = { ...PEOPLE_DEVICE, device: "dev_macmini1", name: "sam-mac-mini", owner: { kind: "member", member: OWNER_VIEWER.member, name: "Alex" } }

// items.nudges for the home's nudge lines: a Cloudflare token and a
// GitHub token that asked often this week.
export const HOME_NUDGES = [{ slug: "cloudflare-api-token-local-secrets-2", asked: 21, routine: 15 }, { slug: "github-work", asked: 12, routine: 7 }]

function home(overrides: Partial<HomeData> = {}): HomeData {
  return {
    viewer: OWNER_VIEWER,
    inbox: single(INBOX_THREE, WORK.id),
    devices: [OWN_DEVICE, PEOPLE_DEVICE],
    items: GALLERY_ITEMS,
    projects: [galleryProject(GALLERY_FIXTURES.OWNER_ACCESS, true)],
    members: GALLERY_MEMBERS,
    invites: PEOPLE_INVITES,
    settings: null,
    now: GALLERY_NOW,
    ...overrides,
  }
}

// A new workspace: nothing connected, nothing added, nobody invited.
function fresh(viewer: HomeData["viewer"]): HomeData {
  return home({ viewer, inbox: single(INBOX_EMPTY, WORK.id), devices: [], items: [], projects: [], members: viewer.role === "guest" ? null : [GALLERY_MEMBERS[0] ?? (() => { throw new Error("gallery: members") })()], invites: viewer.role === "owner" ? [] : null })
}

const WORK_SHELL = (role: MembershipView["role"] = "owner") => shell({ ...NORTHWIND, role }, GALLERY_MEMBERSHIPS, ALL_PAGES)

export function shellGallery(): ShellGalleryEntry[] {
  const twinShell = shell(NORTHWIND_TWIN, GALLERY_MEMBERSHIPS)
  const stale = staleRefusal({ ...identity(NORTHWIND), pages: ["home"], reads: [] }, "account-changed")
  const frozen = home({ settings: { frozen: true, rights: { rename: true, freeze: true, unfreeze: true } } })
  return [
    { id: "workspace-home", group: "Workspaces", title: "Workspace home, owner", note: "The dashboard: what needs you in this workspace first (five rows at most, See all to the filter), then the lists in counts. Every step of Get started is done, so its card is gone. The seven-page rail, the top bar and the phone's five tabs with More.", page: workspaceHomePage(WORK_SHELL(), home()) },
    { id: "workspace-home-mandates", group: "Workspaces", title: "Workspace home, a machine carrying on without asking", note: "A strip under what needs you says how many machines carry on without asking now, linking to the list.", page: workspaceHomePage(WORK_SHELL(), home({ mandateMachines: 1 })) },
    { id: "workspace-home-mandates-resume", group: "Workspaces", title: "Workspace home, a mandate to resume", note: "A mandate the reader signed covers nothing since a change to their access or account: a strip says how many machines need them to resume it.", page: workspaceHomePage(WORK_SHELL(), home({ mandateMachines: 1, mandateResume: 1 })) },
    { id: "workspace-home-get-started-owner", group: "Workspaces", title: "Workspace home, new, owner or admin", note: "Nothing connected or added yet: Get started has its four steps, with the line to give an agent under the first.", page: workspaceHomePage(WORK_SHELL(), fresh(OWNER_VIEWER)) },
    { id: "workspace-home-get-started-local", group: "Workspaces", title: "Workspace home, new, on a local vault", note: "A vault that cannot verify an email address: the invite step says to invite someone by link.", page: workspaceHomePage(WORK_SHELL(), { ...fresh(OWNER_VIEWER), emailInvites: false }) },
    { id: "workspace-home-get-started-member", group: "Workspaces", title: "Workspace home, new, member", note: "A member's Get started has two steps: connect an agent and add a credential.", page: workspaceHomePage(WORK_SHELL("member"), fresh({ role: "member", member: "mem_kim00001" })) },
    { id: "workspace-home-get-started-guest", group: "Workspaces", title: "Workspace home, new, guest", note: "A guest's has one step, with who admits a guest's machine; no People count.", page: workspaceHomePage(WORK_SHELL("guest"), fresh({ role: "guest", member: "mem_sam00001" })) },
    { id: "workspace-home-frozen", group: "Workspaces", title: "Workspace home, frozen", note: "Once the settings read is served: the frozen notice first, with Unfreeze for an owner.", page: workspaceHomePage(WORK_SHELL(), frozen) },
    { id: "workspace-home-nudges", group: "Workspaces", title: "Workspace home, credentials asking often", note: "Up to three credentials that asked often this week with none denied, most of it routine building: each line links to its How careful card, and Not now quietens it for 7 days.", page: workspaceHomePage(WORK_SHELL(), home({ nudges: HOME_NUDGES })) },
    { id: "workspace-home-read-failed", group: "Workspaces", title: "Workspace home, reads failed", note: "The inbox and the lists could not be read: the card says so and the counts show ?, never a zero.", page: workspaceHomePage(WORK_SHELL(), home({ inbox: null, items: null, devices: null, projects: null })) },
    { id: "workspace-home-more-open", group: "Workspaces", title: "Phone tabs, More open", note: "The fifth tab opens a sheet with Machines, People, Teams, Activity, Connect an agent, Settings, the account's pages, Docs and Sign out.", page: workspaceHomePage(WORK_SHELL(), home()), swap: [['<details class="more-sheet" data-region="more-sheet">', '<details class="more-sheet" data-region="more-sheet" open>']] },
    { id: "workspace-home-identity", group: "Workspaces", title: "Workspace home, identity only", note: "A build that serves only the workspace's identity: name, slug and origin, the rail with only served pages, the switcher with this workspace alone.", page: workspaceHomePage(shell(PERSONAL, null)) },
    { id: "workspace-home-switcher", group: "Workspaces", title: "Workspace switcher, open", note: "Every workspace by name, slug and role; two named Northwind told apart by slug; unconfirmed and suspended ones are not links; a hostile name stays text; the longest name and slug wrap or cut.", page: workspaceHomePage(twinShell), swap: [[/<details class="switcher">/g, '<details class="switcher" open>']] },
    { id: "workspace-home-hostile", group: "Workspaces", title: "Workspace home, hostile name", note: "The current workspace's name carries a quote, markup, a right-to-left override and a control character: the title, the switcher's accessible name and the page all show markers, with the slug and origin intact.", page: workspaceHomePage(shell(HOSTILE, GALLERY_MEMBERSHIPS)) },
    { id: "workspace-home-long", group: "Workspaces", title: "Workspace home, longest name and slug", note: "A 64-character name and a 40-character slug in the switcher, the title and the rows.", page: workspaceHomePage(shell(LONG, GALLERY_MEMBERSHIPS, ALL_PAGES), home({ inbox: single(INBOX_LONG, LONG_REF.id) })) },
    { id: "workspace-stale-tab", group: "Workspaces", title: "Stale tab refused", note: "Another account signed in to this browser in another tab: this tab says which workspace it shows and sends nothing.", page: workspaceHomePage(shell(NORTHWIND, GALLERY_MEMBERSHIPS)), notice: { tone: "error", title: stale.message, lines: [stale.next?.say ?? ""] } },
    { id: "workspaces-picker", group: "Workspaces", title: "Your workspaces", note: "The picker: each workspace with its slug, role and state, and its count from the account inbox, left out where that workspace did not answer.", page: pickerPage(GALLERY_ACCOUNT_SHELL, GALLERY_SESSION, GALLERY_ORIGIN, INBOX_UNAVAILABLE) },
    { id: "workspaces-picker-restricted", group: "Workspaces", title: "Your workspaces, account restricted", note: "During a recovery cooling-off the account can read, deny, narrow and freeze, not approve.", page: pickerPage(GALLERY_ACCOUNT_SHELL, RESTRICTED_SESSION, GALLERY_ORIGIN) },
    { id: "workspaces-no-invite", group: "Workspaces", title: "Your workspaces, not in one yet", note: "No membership and no right to create one: how to get in, and the account id to give the operator.", page: pickerPage({ ...GALLERY_ACCOUNT_SHELL, name: NEW_ACCOUNT.name }, NEW_ACCOUNT, GALLERY_ORIGIN) },
    { id: "workspaces-create-first", group: "Workspaces", title: "Your workspaces, create the first", note: "An account the operator allowed, with no workspace yet: the create form inline.", page: pickerPage({ ...GALLERY_ACCOUNT_SHELL, name: CAN_CREATE.name }, CAN_CREATE, GALLERY_ORIGIN) },
    { id: "workspaces-waiting", group: "Workspaces", title: "Your workspaces, waiting to be confirmed", note: "Joined, not yet confirmed: the page waits by itself and offers the message to send whoever invited them.", page: pickerPage({ ...GALLERY_ACCOUNT_SHELL, name: WAITING.name }, WAITING, GALLERY_ORIGIN) },
    { id: "workspaces-recovery-first", group: "Workspaces", title: "Your workspaces, recovery first", note: "No way back in yet: recovery comes before joining or creating.", page: pickerPage({ ...GALLERY_ACCOUNT_SHELL, name: RECOVERY_FIRST.name }, RECOVERY_FIRST, GALLERY_ORIGIN) },
    { id: "workspace-not-found", group: "Workspaces", title: "No such workspace page", note: "An unknown workspace, another account's workspace and an unknown page all render exactly this.", page: workspaceNotFoundPage(GALLERY_ACCOUNT_SHELL) },
    { id: "needs-you-three", group: "Needs you", title: "Needs you, three workspaces", note: "Grouped by workspace, soonest expiry first: an approval with its code, an enrolment with its fingerprint (the hidden group as dots), a private ask that can only be stopped, a confirmation, a claimed machine offered only Reject, a credential request and a wider scope; each with its countdown and one verb.", page: needsYouPage(GALLERY_ACCOUNT_SHELL, { ok: true, inbox: INBOX_THREE, etag: null }, GALLERY_NOW) },
    { id: "needs-you-groups", group: "Needs you", title: "Needs you, grouped asks", note: "A machine's asks on one credential in one row: how many need a closer look and decide on their own page, the soonest countdown, Review together; an all-routine group with its task; an agent's bundle with its reason quoted as its own words.", page: needsYouPage(GALLERY_ACCOUNT_SHELL, { ok: true, inbox: INBOX_GROUPS, etag: null }, GALLERY_NOW) },
    { id: "needs-you-empty", group: "Needs you", title: "Needs you, empty", note: "Every workspace answered and nothing waits.", page: needsYouPage(GALLERY_ACCOUNT_SHELL, { ok: true, inbox: INBOX_EMPTY, etag: null }, GALLERY_NOW) },
    { id: "needs-you-unavailable", group: "Needs you", title: "Needs you, one workspace unavailable", note: "Personal did not answer in time: its group says so and the rest show; the tab title's count is a floor.", page: needsYouPage(GALLERY_ACCOUNT_SHELL, { ok: true, inbox: INBOX_UNAVAILABLE, etag: null }, GALLERY_NOW) },
    { id: "needs-you-gated", group: "Needs you", title: "Needs you, nothing in the workspaces that answered", note: "Northwind asks for an identity check first: never an unqualified Nothing needs you.", page: needsYouPage(GALLERY_ACCOUNT_SHELL, { ok: true, inbox: INBOX_GATED_EMPTY, etag: null }, GALLERY_NOW) },
    { id: "needs-you-failed", group: "Needs you", title: "Needs you, nothing could be read", note: "No workspace answered: what to do until it can.", page: needsYouPage(GALLERY_ACCOUNT_SHELL, { ok: true, inbox: INBOX_FAILED, etag: null }, GALLERY_NOW) },
    { id: "needs-you-ended", group: "Needs you", title: "Needs you, session ended", note: "The poll got a 401: every row cleared, and the way to sign in again.", page: needsYouPage(GALLERY_ACCOUNT_SHELL, { ok: true, inbox: INBOX_EMPTY, etag: null }, GALLERY_NOW), swap: [['data-region="needs-ended" hidden>', 'data-region="needs-ended">'], [/<div class="needs-list"[\s\S]*?<\/section>\s*<\/div>/, '<div class="needs-list" data-region="needs-list"></div>']] },
    { id: "needs-you-long", group: "Needs you", title: "Needs you, long values", note: "The longest workspace name and slug, a 120-character host, a long session label, a long title and a 254-character email, cut where a cap cut the list.", page: needsYouPage(GALLERY_ACCOUNT_SHELL, { ok: true, inbox: INBOX_LONG, etag: null }, GALLERY_NOW) },
    { id: "ws-pending-owner", group: "Needs you", title: "Needs you in one workspace, owner", note: "The filter at /w/northwind/pending: the same rows, this workspace's own count, the other workspaces as a line the poll fills.", page: workspacePendingPage(WORK_SHELL(), { viewer: OWNER_VIEWER, inbox: single(INBOX_THREE, WORK.id), now: GALLERY_NOW }), swap: [['data-region="needs-elsewhere" hidden><a href="/needs-you" data-fill="needs-elsewhere"></a>', 'data-region="needs-elsewhere"><a href="/needs-you" data-fill="needs-elsewhere">3 more in other workspaces</a>']] },
    { id: "ws-pending-guest", group: "Needs you", title: "Needs you in one workspace, guest", note: "A guest sees only their own machines' asks; here there are none.", page: workspacePendingPage(WORK_SHELL("guest"), { viewer: { role: "guest", member: "mem_sam00001" }, inbox: single(INBOX_EMPTY, WORK.id), now: GALLERY_NOW }) },
    { id: "ws-pending-gated", group: "Needs you", title: "Needs you in one workspace, identity check first", note: "The workspace asks for an identity check before it lists anything: no rows and no empty claim.", page: workspacePendingPage(WORK_SHELL(), { viewer: OWNER_VIEWER, inbox: single(INBOX_GATED_EMPTY, WORK.id), now: GALLERY_NOW }) },
  ]
}
