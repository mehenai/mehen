// The people, team, machine and Connect an agent pages with fixture data,
// for scripts/ui-gallery.ts; the enrolment page (workspace-asks-gallery.ts)
// and the account setup pages (account-gallery.ts) build on these fixtures.
// Fixtures parse with the frozen protocol schemas (people-gallery.test.ts),
// include two people and two teams with the same name, and a hostile name
// with a quote, markup, a newline, a shell command, a URL, a direction
// override and a bell. Nothing here is imported by the Worker.

import type { WorkloadView } from "@mehen/protocol"
import type { AccountSession, MembershipView, TeamView, WorkspaceDeviceView, WorkspaceMemberView, WorkspaceProject } from "@mehen/protocol/workspace"
import { fingerprintWords } from "@mehen/protocol/fingerprint"
import type { WorkspaceInviteView } from "../vault/areas/workspace-runtime.ts"
import type { InviteEmailed } from "@mehen/protocol/workspace"
import { type PeopleViewer, inviteMadeWords, inviteMessage } from "./client/people-logic.ts"
import { escapeHtml } from "./html.ts"
import type { PageInput } from "./layout.ts"
import { connectAgentPage } from "./pages/connect-agent.ts"
import { machinePage, machinesPage } from "./pages/machines.ts"
import { type PeopleData, peoplePage, teamsPage } from "./pages/people.ts"
import type { WorkspaceShell } from "./shell.ts"

export const PEOPLE_ORIGIN = "https://app.mehen.dev"
const NOW = Date.parse("2026-10-27T18:30:00Z")
const at = (minutes: number) => new Date(NOW + minutes * 60_000).toISOString()

export const HOSTILE_NAME = "Tom\"; rm -rf ~ <b>x</b>\nhttps://evil.example \u202eadmin\u0007"

const ACCOUNT = "acc_4Hq9Tz2Lm7Vb1Nc8"

export const PEOPLE_WORKSPACE = { id: "tn_8kQw2Lm4Zp7Rt5Vx", slug: "northwind", name: "Northwind" }
export const HOSTILE_WORKSPACE = { id: "tn_2pLs5Gx8Hv1Jr4Ty", slug: "hostile-name", name: HOSTILE_NAME }

function membership(role: MembershipView["role"], workspace = PEOPLE_WORKSPACE, member = "mem_alex01"): MembershipView {
  return { workspace, member, role, pendingRole: null, status: "active" }
}

export function peopleShell(role: MembershipView["role"], options: { workspace?: typeof PEOPLE_WORKSPACE; held?: boolean; member?: string } = {}): WorkspaceShell {
  const workspace = options.workspace ?? PEOPLE_WORKSPACE
  return {
    identity: { origin: PEOPLE_ORIGIN, account: ACCOUNT, workspace },
    accountName: "Alex Rae",
    memberships: [membership(role, workspace, options.member)],
    pages: ["home", "machines", "projects", "people", "teams", "connect-agent", "asks"],
    reads: ["/pending", "/devices", "/projects"],
    accountPages: ["workspaces", "account"],
    accountHeld: options.held ?? false,
  }
}

function viewer(role: MembershipView["role"], member = "mem_alex01", blocked = false): PeopleViewer {
  return { member, role, blocked }
}

const member = (id: string, name: string, role: WorkspaceMemberView["role"], status: WorkspaceMemberView["status"] = "active", teams: string[] = [], machines = 0): WorkspaceMemberView => ({ member: id, name, role, pendingRole: null, status, teams, machines, joinedAt: at(-60 * 24 * 10) })

export const PEOPLE_MEMBERS: WorkspaceMemberView[] = [
  member("mem_alex01", "Alex Rae", "owner", "active", ["tm_platform01"], 2),
  member("mem_tom01", "Tom Barker", "owner", "active", ["tm_platform01"], 1),
  member("mem_noor01", "Noor Eddial", "admin"),
  // Two people share one name; only their roles and ids tell them apart.
  member("mem_sam01", "Sam", "member", "active", ["tm_platform01", "tm_platform02"]),
  member("mem_sam02", "Sam", "member", "suspended"),
  // A second active Sam, same role, nothing else to tell them apart but
  // the member id the page shows beside each.
  member("mem_sam03", "Sam", "member"),
  member("mem_guest01", "Gina (contractor)", "guest"),
  member("mem_hostile01", HOSTILE_NAME, "member", "unconfirmed"),
]

export const PEOPLE_PROJECTS: WorkspaceProject[] = [
  { id: "prj_platform01", slug: "platform", remotes: [], defaultEnv: "dev", vars: [], environments: [{ name: "dev", protected: false, fences: [], fourEyes: false }, { name: "prod", protected: true, fences: [], fourEyes: true }], access: { level: "manage", runProtected: true, editProtected: true, sources: [{ kind: "role", role: "owner" }] } },
  { id: "prj_site01", slug: "site", remotes: [], defaultEnv: "dev", vars: [{ name: "OPENAI_API_KEY", env: "dev", source: "item", item: "openai-shared", field: "key" }, { name: "DEPLOY_TOKEN", env: "dev", source: "item", item: "site-deploy", field: "token" }], environments: [{ name: "dev", protected: false, fences: [], fourEyes: false }], access: { level: "manage", runProtected: true, editProtected: true, sources: [{ kind: "role", role: "owner" }] } },
]

// The same projects as a manager reads them, with the guest Gina's share on
// the site project: the project her machine's admission is signed for.
export const GUEST_SHARED_PROJECTS: WorkspaceProject[] = PEOPLE_PROJECTS.map((p) => ({ ...p, shares: p.id === "prj_site01" ? [{ id: "shr_gina01", project: p.id, subject: { kind: "member", member: "mem_guest01" }, level: "edit", protected: false, expiresAt: null }] : [] }))

// What the viewer can see, with homes: one workspace credential the site
// project references, one project credential, one unrelated workspace
// credential and someone's private one, which no grant delegates.
export const PEOPLE_CREDENTIALS = [
  { slug: "openai-shared", home: { kind: "workspace" } },
  { slug: "site-deploy", home: { kind: "project", project: "prj_site01" } },
  { slug: "unrelated-key", home: { kind: "workspace" } },
  { slug: "alex-private", home: { kind: "member", member: "mem_alex01" } },
]

export const PEOPLE_TEAMS: TeamView[] = [
  { id: "tm_platform01", slug: "platform", name: "Platform", members: [{ member: "mem_alex01", name: "Alex Rae", role: "member" }, { member: "mem_tom01", name: "Tom Barker", role: "member" }, { member: "mem_sam01", name: "Sam", role: "member" }], shares: [{ id: "shr_1", project: "prj_platform01", subject: { kind: "team", team: "tm_platform01" }, level: "use", protected: false, expiresAt: null }], machines: 1 },
  // The same display name as the first; the short name tells them apart.
  { id: "tm_platform02", slug: "platform-ops", name: "Platform", members: [{ member: "mem_sam01", name: "Sam", role: "member" }], shares: [], machines: 0 },
]

const TERMS_DIGEST = "dgst_hostile_terms"

export const PEOPLE_INVITES: WorkspaceInviteView[] = [
  { id: "inv_open01", terms: { role: "member", email: "noor@northwind.example", teams: ["tm_platform01"], shares: [], expiresAt: at(60 * 24 * 6), onJoin: "activate" }, digest: "dgst_open", status: "open", inviter: { member: "mem_alex01", name: "Alex Rae" }, boundEmail: "noor@northwind.example", createdAt: at(-60), expiresAt: at(60 * 24 * 6) },
  { id: "inv_guest01", terms: { role: "guest", email: null, teams: [], shares: [{ project: "prj_site01", level: "edit", protected: false, expiresAt: null }], expiresAt: at(60 * 24 * 2), onJoin: "confirm" }, digest: "dgst_guest", status: "open", inviter: { member: "mem_noor01", name: "Noor Eddial" }, boundEmail: null, createdAt: at(-120), expiresAt: at(60 * 24 * 2) },
  { id: "inv_used01", terms: { role: "member", email: "tom@northwind.example", teams: ["tm_platform01"], shares: [{ project: "prj_platform01", level: "edit", protected: true, expiresAt: null }], expiresAt: at(60 * 24) }, digest: TERMS_DIGEST, status: "pending_confirmation", inviter: { member: "mem_alex01", name: "Alex Rae" }, boundEmail: "tom@northwind.example", createdAt: at(-600), expiresAt: at(60 * 24) },
]

export function peopleData(role: MembershipView["role"], blocked = false): PeopleData {
  return { viewer: viewer(role, "mem_alex01", blocked), members: PEOPLE_MEMBERS, invites: role === "owner" || role === "admin" ? PEOPLE_INVITES : null, teams: PEOPLE_TEAMS, projects: PEOPLE_PROJECTS, credentials: role === "owner" || role === "admin" ? PEOPLE_CREDENTIALS : null }
}

// A code in the issuer's alphabet (directory/enrolment.ts enrolmentCode).
export const CONNECT_CODE = "7XK2M9QP"

export const THUMBPRINT = "Q3x9Lw2Zk8Pt4Rv7Ny1Hs6Bd5Fg0Jm3Kc2Xa8Ue4WoA"

// Two tasks a machine is running: one with a narrow scope, one with all of it.
export const GALLERY_WORKLOADS: WorkloadView[] = [
  { workload: "wl_task8kq2mw4z", device: "dev_tomlaptop01", label: "globex:grant-7f3k", thumbprint: "t".repeat(43), scope: { items: ["openai-shared"], modes: ["relay"] }, state: "active", createdAt: at(-20), expiresAt: at(40), hardExpiresAt: at(7 * 24 * 60), lastSeenAt: at(-2), revokedAt: null, revokedBy: null },
  { workload: "wl_task3vx9kd2m", device: "dev_tomlaptop01", label: "ci:job-4182", thumbprint: "u".repeat(43), scope: {}, state: "active", createdAt: at(-5), expiresAt: at(55), hardExpiresAt: at(7 * 24 * 60), lastSeenAt: null, revokedAt: null, revokedBy: null },
]

export const PEOPLE_DEVICE: WorkspaceDeviceView = {
  device: "dev_tomlaptop01",
  name: "tom-laptop",
  backend: "secure-enclave",
  host: "toms-mbp.local",
  owner: { kind: "member", member: "mem_tom01", name: "Tom Barker" },
  scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay", "sign", "mint", "placeholder"], privateCredentials: false },
  scopeRevision: 1,
  acceptance: { name: "Tom Barker", at: at(-30) },
  admission: null,
  pendingRescope: null,
  createdAt: at(-30),
  lastSeenAt: at(-2),
  lastCliVersion: "0.3.1",
  revoked: false,
  fingerprintWords: fingerprintWords(THUMBPRINT),
  start: null,
}

const PROPOSAL = {
  id: "rsp_1", device: "dev_tomlaptop01", thumbprint: THUMBPRINT, before: PEOPLE_DEVICE.scope, after: { ...PEOPLE_DEVICE.scope, maxEnvironment: "protected" as const }, beforeDigest: "b", afterDigest: "a",
  proposer: { member: "mem_alex01", name: "Alex Rae" }, requiredSigners: [{ name: "Tom Barker", as: "owner_acceptance" as const }], signedBy: [], expiresAt: at(60 * 24), state: "open" as const,
}

const TEAM_DEVICE: WorkspaceDeviceView = { ...PEOPLE_DEVICE, device: "dev_teambot0001", name: "team-bot", host: "ci-host", backend: "software", owner: { kind: "team", team: "tm_platform01", name: "Platform" }, acceptance: null, admission: { name: "Alex Rae", at: at(-600) }, lastCliVersion: "0.3.0" }

export const PEOPLE_SESSION: AccountSession = { account: ACCOUNT, name: "Alex Rae", canCreateWorkspaces: false, workspaceCreation: "default", recoverySetupRequired: false, securityEpoch: 3, pendingTransition: null, restricted: null, memberships: [membership("owner")] }

export type PeopleGalleryEntry = { id: string; group: string; title: string; note: string; page: PageInput; reveal?: string[]; fill?: Record<string, string>; swap?: [string, string][] }

// The invite form with an email typed, and the page once the invitation is
// made, its link emailed or not: what the client writes into it.
export const INVITE_FORM_EMAIL = "ravi@northwind.example"
export const INVITE_MADE_URL = `${PEOPLE_ORIGIN}/signup#k7Qm2vXr9pLw4sNt8bHd3fGj`
// The machine page's change form, shown opened.
const OPEN_SCOPE_FORM: [string, string] = ['<details class="fold" data-region="scope-change">', '<details class="fold" data-region="scope-change" open>']
const INVITE_EMAIL_INPUT = '<input type="email" data-input="invite-email" autocomplete="off" maxlength="254">'
export function inviteMadeSwaps(emailed: InviteEmailed): [string, string][] {
  const terms = { ...PEOPLE_INVITES[0]!.terms, email: INVITE_FORM_EMAIL }
  return [
    ['<form class="stack" data-form="invite" novalidate>', '<form class="stack" data-form="invite" novalidate hidden>'],
    [`data-region="invite-made-lead">${escapeHtml(inviteMadeWords({ role: "member", email: null }))}<`, `data-region="invite-made-lead">${escapeHtml(inviteMadeWords(terms, emailed))}<`],
  ]
}
function inviteMadeFill(): Record<string, string> {
  return { "invite-url": INVITE_MADE_URL, "invite-message": inviteMessage(PEOPLE_WORKSPACE, INVITE_MADE_URL, { ...PEOPLE_INVITES[0]!.terms, email: INVITE_FORM_EMAIL }) }
}

export function peopleGallery(): PeopleGalleryEntry[] {
  const cli = { minimum: "0.3.0", recommended: "0.3.1" }
  const machines = { viewer: viewer("owner"), projects: PEOPLE_PROJECTS, now: NOW, cli }
  const tomMachines = { viewer: viewer("member", "mem_tom01"), projects: PEOPLE_PROJECTS, now: NOW, cli }
  return [
    { id: "people-owner", group: "People", title: "People, as an owner", note: "Every person with role and state; changes the evaluator would allow: none on yourself or the last owner; two people named Sam; a hostile name waiting for confirmation; invitations and the invite form.", page: peoplePage(peopleShell("owner"), peopleData("owner")) },
    { id: "people-confirm", group: "People", title: "Confirming a person", note: "The exact terms the passkey signs, shown once the vault returns their digest.", page: peoplePage(peopleShell("owner"), peopleData("owner")), reveal: ["confirm-panel"] },
    { id: "people-invite-form", group: "People", title: "Inviting someone by email", note: "An email typed: Email the link to them is ticked, so the vault emails the link as it makes the invitation. An open guest link hides it.", page: peoplePage(peopleShell("owner"), peopleData("owner")), swap: [[INVITE_EMAIL_INPUT, INVITE_EMAIL_INPUT.replace(">", ` value="${INVITE_FORM_EMAIL}">`)]] },
    { id: "people-invite-sent", group: "People", title: "Invitation made, link emailed", note: "The vault emailed the link to the invited address; it is still here to copy.", page: peoplePage(peopleShell("owner"), peopleData("owner")), reveal: ["invite-made"], fill: inviteMadeFill(), swap: inviteMadeSwaps("sent") },
    { id: "people-invite-limited", group: "People", title: "Invitation made, too many emails", note: "Past the limits for the inviter or the address: the invitation is made, the link was not emailed, and the page says to send it.", page: peoplePage(peopleShell("owner"), peopleData("owner")), reveal: ["invite-made"], fill: inviteMadeFill(), swap: inviteMadeSwaps("limited") },
    { id: "people-invite-failed", group: "People", title: "Invitation made, email failed", note: "Email Sending refused: the invitation is made and the link is here to copy and send.", page: peoplePage(peopleShell("owner"), peopleData("owner")), reveal: ["invite-made"], fill: inviteMadeFill(), swap: inviteMadeSwaps("failed") },
    { id: "people-local-owner", group: "People", title: "People on a local vault, as an owner", note: "A vault with no Google sign-in and no email sending cannot verify an email address: the form offers a guest by link only, with the line that says why, and its projects open; no teams, which a guest never joins.", page: peoplePage(peopleShell("owner"), { ...peopleData("owner"), emailInvites: false }) },
    { id: "people-local-no-project", group: "People", title: "People on a local vault, no project yet", note: "A guest needs a shared project, so the line says to create one first.", page: peoplePage(peopleShell("owner"), { ...peopleData("owner"), projects: [], teams: [], emailInvites: false }) },
    { id: "people-admin", group: "People", title: "People, as an admin", note: "An admin changes no owner and cannot invite one.", page: peoplePage(peopleShell("admin"), { ...peopleData("admin"), viewer: viewer("admin", "mem_noor01") }) },
    { id: "people-member", group: "People", title: "People, as a member", note: "A member reads the list and changes nothing; no invitations.", page: peoplePage(peopleShell("member"), { ...peopleData("member"), viewer: viewer("member", "mem_sam01") }) },
    { id: "people-held", group: "People", title: "People, account held back", note: "During a recovery cooling-off, an owner reads but changes nobody.", page: peoplePage(peopleShell("owner", { held: true }), peopleData("owner", true)) },
    { id: "people-guest", group: "People", title: "People, as a guest", note: "A guest sees no other people at all.", page: peoplePage(peopleShell("guest"), { viewer: viewer("guest", "mem_guest01"), members: [], invites: null, teams: null, projects: null, credentials: null }) },
    { id: "teams-owner", group: "People", title: "Teams, as an owner", note: "Two teams named Platform told apart by short name; members, project shares, add and take out; delete only with no machines.", page: teamsPage(peopleShell("owner"), peopleData("owner")) },
    { id: "teams-member", group: "People", title: "Teams, as a member", note: "Read only.", page: teamsPage(peopleShell("member"), { ...peopleData("member"), viewer: viewer("member", "mem_sam01") }) },
    { id: "machines", group: "Machines", title: "Machines", note: "Each machine with its owner, person or team.", page: machinesPage(peopleShell("owner"), [PEOPLE_DEVICE, { ...TEAM_DEVICE, pendingRescope: null }, { ...PEOPLE_DEVICE, device: "dev_old", name: "old-desktop", lastCliVersion: "0.2.0", revoked: true, revokedAt: at(-6000) }], machines) },
    { id: "machine-fill", group: "Machines", title: "A machine that may be allowed to type into web pages", note: "Typing into web pages is on here and the machine runs mehen 0.3.17: the change form, opened, offers it among the ways, unticked; ticking it is a wider scope.", page: machinePage(peopleShell("owner"), { ...PEOPLE_DEVICE, lastCliVersion: "0.3.17" }, { ...machines, fill: true }), swap: [OPEN_SCOPE_FORM] },
    { id: "machine-fill-update-first", group: "Machines", title: "A machine whose mehen is too old to type into web pages", note: "It runs mehen 0.3.16: the tick is off, with the words to update mehen on it first.", page: machinePage(peopleShell("owner"), { ...PEOPLE_DEVICE, lastCliVersion: "0.3.16" }, { ...machines, fill: true }), swap: [OPEN_SCOPE_FORM] },
    { id: "machine-review", group: "Machines", title: "A new machine, from its notice", note: "Revoke one tap from the top; owner, key, start time, place and client, fingerprint and scope.", page: machinePage(peopleShell("owner"), { ...PEOPLE_DEVICE, start: { at: at(-33), place: "Amsterdam, NL", clientLabel: "mehen 0.2.0 on macOS" } }, machines) },
    { id: "machine-own-proposal", group: "Machines", title: "Your machine, a wider scope waiting", note: "The owner accepts it on their own machine, with the acceptance warning.", page: machinePage(peopleShell("member", { member: "mem_tom01" }), { ...PEOPLE_DEVICE, pendingRescope: { ...PROPOSAL, requiredSigners: [{ account: ACCOUNT, name: "Tom Barker", as: "owner_acceptance" }] } }, tomMachines) },
    { id: "machine-service-proposal", group: "Machines", title: "Your machine, may run services waiting", note: "Granting service runs is a wider scope: the owner accepts it on their own machine; the form shows the tick off until then.", page: machinePage(peopleShell("member", { member: "mem_tom01" }), { ...PEOPLE_DEVICE, pendingRescope: { ...PROPOSAL, after: { ...PEOPLE_DEVICE.scope, serviceRuns: true }, requiredSigners: [{ account: ACCOUNT, name: "Tom Barker", as: "owner_acceptance" }] } }, tomMachines) },
    { id: "machine-workloads", group: "Machines", title: "A machine with live workloads", note: "Each task's label marked as the machine's words, its scope in words, when it ends and when it was last seen, and Revoke with a passkey.", page: machinePage(peopleShell("owner"), PEOPLE_DEVICE, { ...machines, workloads: GALLERY_WORKLOADS }) },
    { id: "machine-team", group: "Machines", title: "A team's machine", note: "No private credentials tick; owners and admins sign wider scope.", page: machinePage(peopleShell("owner"), TEAM_DEVICE, machines) },
    { id: "machine-hostile", group: "Machines", title: "A machine with a hostile name", note: "The tab title spells the name; the page marks it.", page: machinePage(peopleShell("owner"), { ...PEOPLE_DEVICE, name: HOSTILE_NAME, owner: { kind: "member", member: "mem_hostile01", name: HOSTILE_NAME } }, machines) },
    { id: "machine-own-proposal-held", group: "Machines", title: "Your machine, held back", note: "During a recovery cooling-off the owner cannot accept wider scope.", page: machinePage(peopleShell("member", { member: "mem_tom01", held: true }), { ...PEOPLE_DEVICE, pendingRescope: { ...PROPOSAL, requiredSigners: [{ account: ACCOUNT, name: "Tom Barker", as: "owner_acceptance" }] } }, { ...tomMachines, viewer: viewer("member", "mem_tom01", true) }) },
    { id: "machine-guest", group: "Machines", title: "A guest's own machine", note: "Narrowing only; an insider proposes anything wider.", page: machinePage(peopleShell("guest", { member: "mem_guest01" }), { ...PEOPLE_DEVICE, owner: { kind: "member", member: "mem_guest01", name: "Gina (contractor)" }, scope: { ...PEOPLE_DEVICE.scope, projects: ["prj_site01"] } }, { viewer: viewer("guest", "mem_guest01"), projects: PEOPLE_PROJECTS, now: NOW }) },
    { id: "machine-guest-admission", group: "Machines", title: "A guest's machine, you admit its wider scope", note: "The designated admission signer gets Admit with a quiet Reject beside it, both for the guest's shared project.", page: machinePage(peopleShell("admin", { member: "mem_noor01" }), { ...PEOPLE_DEVICE, owner: { kind: "member", member: "mem_guest01", name: "Gina (contractor)" }, pendingRescope: { ...PROPOSAL, requiredSigners: [{ name: "Gina (contractor)", as: "owner_acceptance" }, { account: ACCOUNT, name: "Noor Eddial", as: "admission" }] } }, { viewer: viewer("admin", "mem_noor01"), projects: GUEST_SHARED_PROJECTS, now: NOW }) },
    { id: "machine-rescope-hostile", group: "Machines", title: "Rescope, hostile proposer", note: "A proposer's name with a direction override and a bell: the warning comes first, the card turns red, Reject is emphasised and accepting is quiet; both are passkey steps.", page: machinePage(peopleShell("member", { member: "mem_tom01" }), { ...PEOPLE_DEVICE, pendingRescope: { ...PROPOSAL, proposer: { member: "mem_hostile01", name: HOSTILE_NAME }, requiredSigners: [{ account: ACCOUNT, name: "Tom Barker", as: "owner_acceptance" }] } }, tomMachines) },
    { id: "connect-agent", group: "Machines", title: "Connect an agent", note: "As served: the prompt and the three commands carry only the slug and the origin; the prompt and enrol boxes wait for the connect code.", page: connectAgentPage(peopleShell("member")) },
    { id: "connect-agent-code", group: "Machines", title: "Connect an agent, with a connect code", note: "The issuer answered: the prompt names the code and the enrol box carries --connect; the page says what the code does and when it ends.", page: connectAgentPage(peopleShell("member"), { state: "issued", code: CONNECT_CODE, expiresAt: at(60 * 24) }) },
    { id: "connect-agent-no-code", group: "Machines", title: "Connect an agent, no connect code", note: "The issuer refused (here, rate limited): its words, and the boxes without --connect, which work through an owner or admin.", page: connectAgentPage(peopleShell("member"), { state: "refused", say: "Wait a minute, then reload the page for a connect code." }) },
    { id: "connect-agent-hostile", group: "Machines", title: "Connect an agent, hostile workspace name", note: "The hostile name shows marked in the page; nothing of it is in what is copied.", page: connectAgentPage(peopleShell("member", { workspace: HOSTILE_WORKSPACE })) },
  ]
}
