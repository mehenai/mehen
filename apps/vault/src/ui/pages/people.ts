// /w/:ws/people and /w/:ws/teams. People: who is in the workspace, their
// role and state, the invitations still open and, for owners and admins,
// the changes the workspace would allow them, each signed with a passkey.
// A guest sees no other people at all. Teams: each team's members and
// project shares; owners and admins create, rename and delete teams and
// change their members. There is no maintainer role.
//
// Every name came from a person, so it is card text. Every control here is
// one the evaluator would allow this viewer (people-logic.ts); the server
// refuses anything else, and its refusal is shown as it comes.

import type { TeamView, WorkspaceMemberView, WorkspaceProject, WorkspaceRole } from "@mehen/protocol/workspace"
import type { WorkspaceInviteView } from "../../vault/areas/workspace-runtime.ts"
import { ACTIVATION_BUTTON, type CredentialHomeOf, INVITE_MAX_DAYS, type PeopleViewer, ROLE_LABELS, ROLE_PLACEHOLDER, activationWords, delegatedCredentials, elevated, inviteMadeWords, inviteRoles, memberActions, onJoinWords, personLabel, roleChoices } from "../client/people-logic.ts"
import { spellCardText } from "../../relay/spelling.ts"
import { cardText, emptyState, notice, pageHead, pill, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import type { WorkspaceShell } from "../shell.ts"

export type PeopleData = {
  viewer: PeopleViewer | null
  members: WorkspaceMemberView[]
  // Only owners and admins may list invitations; null for everyone else.
  invites: WorkspaceInviteView[] | null
  teams: TeamView[] | null
  projects: WorkspaceProject[] | null
  // Every credential this viewer can see, with its home: what a project
  // share would also delegate. Null when it could not be read.
  credentials: CredentialHomeOf[] | null
  // Whether this vault can complete an email-bound invitation
  // (emailInvitesCompletable); absent reads as it can.
  emailInvites?: boolean
}

export const LINK_ONLY_INVITE_WORDS = "This vault cannot verify an email address, so it invites by link, as a guest: anyone with the link may join, you confirm them once they have joined, and then you can change their role."

export const LINK_ONLY_NO_PROJECT_WORDS = "A guest needs a project shared with them, so create a project first."

export const GUEST_PEOPLE_WORDS = "You are a guest here. Guests see the projects shared with them, not the other people in this workspace."

const STATUS_WORDS: Readonly<Record<WorkspaceMemberView["status"], string>> = { active: "Active", unconfirmed: "Waiting for confirmation", suspended: "Suspended" }

function projectSlug(projects: readonly WorkspaceProject[] | null, id: string): Html {
  const found = projects?.find((p) => p.id === id)
  return found ? html`<code>${cardText(found.slug)}</code>` : html`<span class="muted">a project you cannot see</span>`
}

function teamName(teams: readonly TeamView[] | null, id: string): Html {
  const found = teams?.find((t) => t.id === id)
  return found ? html`${cardText(found.name)} <code>${found.slug}</code>` : html`<span class="muted">a team</span>`
}

// A list page has no eyebrow: the switcher names the workspace.
function head(title: string, lead: string): Html {
  return pageHead({ title, lead })
}

function blockedNote(viewer: PeopleViewer | null): Html {
  if (viewer === null || !viewer.blocked || !elevated(viewer.role)) return html``
  return html`<div data-region="people-held">${notice("warn", "You can read here, not change people", html`Your account is held back after a recovery or a security change, so you cannot invite or change people yet. See <a href="/account">your account</a>.`)}</div>`
}

// ---------------------------------------------------------------- invitations

function termsList(terms: WorkspaceInviteView["terms"], data: PeopleData): Html {
  return html`<dl class="kv facts invite-terms">
    <dt>Role</dt><dd>${ROLE_LABELS[terms.role]}</dd>
    <dt>For</dt><dd>${terms.email !== null ? html`<code>${terms.email}</code>, who proves it before joining` : "Anyone with the link (an open guest invitation)"}</dd>
    <dt>When they join</dt><dd data-region="invite-on-join">${onJoinWords(terms)}</dd>
    <dt>Teams</dt><dd>${terms.teams.length === 0 ? "None" : html`${terms.teams.map((t, i) => html`${i > 0 ? ", " : ""}${teamName(data.teams, t)}`)}`}</dd>
    <dt>Projects</dt><dd>${terms.shares.length === 0 ? "None directly" : html`<ul class="plain">${terms.shares.map((s) => html`<li>${projectSlug(data.projects, s.project)}: ${s.level}${s.protected ? ", including protected environments" : ""}${s.expiresAt !== null ? html`, until ${timeTag(s.expiresAt)}` : ""}</li>`)}</ul>`}</dd>
    <dt>Ends</dt><dd>${timeTag(terms.expiresAt)}</dd>
    ${terms.shares.length > 0 ? html`<dt>Also lets them use</dt><dd>${delegationWords(delegatedCredentials(terms.shares.map((x) => x.project), data.projects, data.credentials))}</dd>` : ""}
  </dl>`
}

export const DELEGATION_UNKNOWN_WORDS = "The workspace credentials these projects would let them use could not be read, so this cannot be signed now. Reload the page."

// The workspace credentials a project grant delegates, named before any
// passkey signs it (design 8.3): a guest or a team using a shared project
// can use every whole-workspace credential its variables reference.
export function delegationWords(slugs: readonly string[] | null): Html {
  if (slugs === null) return html`<span class="inline-error" data-region="delegation-unknown">${DELEGATION_UNKNOWN_WORDS}</span>`
  if (slugs.length === 0) return html`<span data-region="delegation">No whole-workspace credentials</span>`
  return html`<span data-region="delegation">These whole-workspace credentials: ${slugs.map((slug, i) => html`${i > 0 ? ", " : ""}<code>${cardText(slug)}</code>`)}</span>`
}

const INVITE_STATUS: Readonly<Record<WorkspaceInviteView["status"], string>> = { open: "Open", pending_confirmation: "Used, waiting for confirmation", active: "Accepted", revoked: "Revoked", expired: "Ran out" }

function inviteRow(invite: WorkspaceInviteView, data: PeopleData): Html {
  const live = invite.status === "open"
  return html`<li class="invite" data-invite="${invite.id}">
    <div class="invite-head"><b>${ROLE_LABELS[invite.terms.role]}</b> ${invite.boundEmail !== null ? html`<code>${invite.boundEmail}</code>` : pill("open link", "warn", false)} ${pill(INVITE_STATUS[invite.status], live ? "accent" : "muted", false)}</div>
    <p class="small muted">Sent by ${cardText(invite.inviter.name)} on ${timeTag(invite.createdAt)}; ends ${timeTag(invite.expiresAt)}.</p>
    <details class="fold"><summary>${icon("chevronRight")}<span>Terms</span></summary>${termsList(invite.terms, data)}</details>
    ${live ? html`<button type="button" class="btn danger-quiet sm" data-action="invite-revoke" data-invite="${invite.id}">Revoke</button>` : ""}
  </li>`
}

// What sharing this one project would delegate, for the browser to show as
// the person ticks projects: the slugs, or a marker that it is unknown.
function shareDelegation(project: string, data: PeopleData): Html {
  const slugs = delegatedCredentials([project], data.projects, data.credentials)
  return slugs === null ? html` data-delegates-unknown` : html` data-delegates="${slugs.join(" ")}"`
}

// A vault that cannot verify an email address offers the one invitation it
// can complete: an open guest link, which an owner or admin confirms.
function inviteBinding(linkOnly: boolean, projects: number): Html {
  if (linkOnly) return html`<fieldset class="field" data-region="invite-binding">
        <legend class="label">Who may use the link</legend>
        <label class="tick" data-region="invite-open"><input type="radio" name="invite-binding" data-input="invite-binding" value="open" checked><span>Anyone with the link (guests only)</span></label>
      </fieldset>
      <p class="small muted" data-region="invite-link-only">${LINK_ONLY_INVITE_WORDS}${projects === 0 ? ` ${LINK_ONLY_NO_PROJECT_WORDS}` : ""}</p>`
  return html`<fieldset class="field" data-region="invite-binding">
        <legend class="label">Who may use the link</legend>
        <label class="tick"><input type="radio" name="invite-binding" data-input="invite-binding" value="email" checked><span>Only the person with this email, after they prove it</span></label>
        <label class="tick" data-region="invite-open"><input type="radio" name="invite-binding" data-input="invite-binding" value="open"><span>Anyone with the link (guests only)</span></label>
      </fieldset>
      <label class="field"><span class="label">Email</span><input type="email" data-input="invite-email" autocomplete="off" maxlength="254"></label>
      <label class="tick" data-region="invite-email-link"><input type="checkbox" data-input="invite-email-link" checked><span>Email the link to them</span></label>
      <label class="tick" data-region="invite-confirm-myself"><input type="checkbox" data-input="invite-confirm-myself"><span>Confirm them myself when they join</span></label>`
}

function inviteForm(viewer: PeopleViewer, data: PeopleData): Html {
  const linkOnly = data.emailInvites === false
  const roles = inviteRoles(viewer).filter((r) => !linkOnly || r === "guest")
  if (roles.length === 0) return html``
  const selected = linkOnly ? "guest" : "member"
  const projects = data.projects ?? []
  // A guest joins no team, so a link-only form offers none.
  const teams = linkOnly ? [] : data.teams ?? []
  return html`<section class="card" data-region="invite">
    <h2>Invite someone</h2>
    <form class="stack" data-form="invite" novalidate>
      <label class="field"><span class="label">Role</span>
        <select data-input="invite-role">${roles.map((r) => html`<option value="${r}"${r === selected ? html` selected` : ""}>${ROLE_LABELS[r]}</option>`)}</select></label>
      ${inviteBinding(linkOnly, projects.length)}
      <div class="oidc-slot" data-slot="oidc-invite-proof" hidden></div>
      ${teams.length > 0 || projects.length > 0 ? html`<details class="fold" data-region="invite-access"${linkOnly ? html` open` : ""}><summary>${icon("chevronRight")}<span>${linkOnly ? "Access: projects" : "Access: teams and projects"}</span></summary><div class="stack">
      ${teams.length > 0 ? html`<fieldset class="field" data-region="invite-teams"><legend class="label">Teams (not for guests)</legend>${teams.map((t) => html`<label class="tick"><input type="checkbox" data-input="invite-team" value="${t.id}"><span>${cardText(t.name)} <code>${t.slug}</code></span></label>`)}</fieldset>` : ""}
      ${projects.length > 0 ? html`<fieldset class="field" data-region="invite-projects"><legend class="label">Share projects directly (a guest needs at least one)</legend>${projects.map((p) => html`<div class="share-row" data-share="${p.id}"${shareDelegation(p.id, data)}>
          <label class="tick"><input type="checkbox" data-input="invite-project" value="${p.id}"><span><code>${cardText(p.slug)}</code></span></label>
          <select data-input="invite-level" aria-label="Level for ${p.slug}"><option value="use">use</option><option value="edit">edit</option><option value="manage">manage (not for guests)</option></select>
          <label class="tick"><input type="checkbox" data-input="invite-protected"><span>including protected environments</span></label>
        </div>`)}</fieldset>` : ""}
      </div></details>` : ""}
      <div class="card-inset" data-region="invite-delegation" hidden><p class="label">This also lets them use</p><ul class="plain" data-region="invite-delegation-list"></ul><p class="inline-error" data-region="invite-delegation-unknown" hidden>${DELEGATION_UNKNOWN_WORDS}</p></div>
      <label class="field"><span class="label">Ends after</span>
        <select data-input="invite-days">${Array.from({ length: INVITE_MAX_DAYS }, (_, i) => i + 1).map((d) => html`<option value="${d}"${d === INVITE_MAX_DAYS ? html` selected` : ""}>${d} day${d === 1 ? "" : "s"}</option>`)}</select></label>
      <button type="submit" class="btn primary" data-action="invite-create">${icon("passkey")}<span>Create invitation with passkey</span></button>
    </form>
    <div data-region="invite-made" hidden>
      <p class="lead" data-region="invite-made-lead">${inviteMadeWords({ role: "member", email: null })}</p>
      <div class="copybox"><code data-region="invite-url"></code><button type="button" class="btn secondary sm" data-copy>${icon("copy")}<span>Copy</span></button></div>
      <p class="label">Or copy a message to send with it</p>
      <div class="copybox"><code data-region="invite-message"></code><button type="button" class="btn secondary sm" data-copy>${icon("copy")}<span>Copy</span></button></div>
    </div>
  </section>`
}

// ---------------------------------------------------------------- people

// The exact terms a confirmation signs, for each invitation now waiting on
// one. The page shows the one whose digest the vault returns for this
// person; if none matches, nothing is offered.
function confirmPanel(member: WorkspaceMemberView, data: PeopleData): Html {
  const waiting = (data.invites ?? []).filter((i) => i.status === "pending_confirmation" && i.terms.role === member.role)
  return html`<div class="confirm-panel" id="confirm-${member.member}" data-region="confirm-panel" data-member="${member.member}" hidden>
    <p class="activation">${cardText(activationWords(personLabel(member, data.members), member.role))}</p>
    ${waiting.map((i) => html`<div data-terms-digest="${i.digest}" hidden>${termsList(i.terms, data)}</div>`)}
    <p class="inline-error" role="alert" data-region="confirm-error" hidden></p>
    <button type="button" class="btn primary" data-action="member-confirm-sign" data-member="${member.member}" disabled>${icon("passkey")}<span>${ACTIVATION_BUTTON}</span></button>
  </div>`
}

// Confirming a new person is the row's one primary action and stays in view;
// every other change sits in the person's Manage fold, with the consequence
// of removing said once at its top and Remove as the outline danger button.
function memberControls(viewer: PeopleViewer | null, member: WorkspaceMemberView, data: PeopleData): Html {
  if (viewer === null) return html``
  const actions = memberActions(viewer, member, data.members)
  if (actions.length === 0) return html``
  // Every control is named for its person, with the member id when another
  // person here has the same name, so a screen reader can tell them apart.
  const who = spellCardText(personLabel(member, data.members))
  if (actions.includes("confirm")) {
    return html`<div class="member-actions" data-member="${member.member}"><button type="button" class="btn primary sm" data-action="member-confirm" data-member="${member.member}" aria-label="Review and confirm ${who}">Review and confirm</button>${confirmPanel(member, data)}</div>`
  }
  const roles = roleChoices(viewer, member)
  return html`<details class="fold manage" data-region="manage" data-member="${member.member}"><summary>${icon("chevronRight")}<span>Manage</span></summary>
    ${actions.includes("remove") ? html`<p class="small muted">Removing revokes their machines and deletes their private credentials.</p>` : ""}
    <div class="member-actions">
    ${actions.includes("role") ? html`<label class="inline"><span class="sr">New role for ${who}</span><select data-input="member-role" data-member="${member.member}"><option value="" selected disabled>${ROLE_PLACEHOLDER}</option>${roles.map((r: WorkspaceRole) => html`<option value="${r}">${ROLE_LABELS[r]}</option>`)}</select></label><button type="button" class="btn secondary sm" data-action="member-role" data-member="${member.member}" aria-label="Change the role of ${who}" disabled>Change role</button>` : ""}
    ${actions.includes("suspend") ? html`<button type="button" class="btn secondary sm" data-action="member-suspend" data-member="${member.member}" aria-label="Suspend ${who}">Suspend</button>` : ""}
    ${actions.includes("reinstate") ? html`<button type="button" class="btn secondary sm" data-action="member-reinstate" data-member="${member.member}" aria-label="Reinstate ${who}">Reinstate</button>` : ""}
    ${actions.includes("remove") ? html`<button type="button" class="btn danger-quiet sm" data-action="member-remove" data-member="${member.member}" aria-label="Remove ${who}">Remove</button>` : ""}
    </div>
  </details>`
}

// The person's name, and their member id beside it when it is shared.
function personName(member: { member: string; name: string }, everyone: readonly { member: string; name: string }[]): Html {
  const twin = personLabel(member, everyone) !== member.name
  return html`<b>${cardText(member.name)}</b>${twin ? html` <code class="member-id">${member.member}</code>` : ""}`
}

function memberRow(viewer: PeopleViewer | null, member: WorkspaceMemberView, data: PeopleData): Html {
  const you = viewer?.member === member.member
  return html`<li class="person" data-person="${member.member}">
    <div class="person-head">${personName(member, data.members)}${you ? html` <span class="muted">(you)</span>` : ""} ${pill(ROLE_LABELS[member.role], member.role === "owner" ? "accent" : "muted", false)}${member.pendingRole !== null ? html` ${pill(`becoming ${ROLE_LABELS[member.pendingRole]}`, "warn", false)}` : ""} ${pill(STATUS_WORDS[member.status], member.status === "active" ? "ok" : "warn")}</div>
    <p class="small muted">${member.teams.length > 0 ? html`Teams: ${member.teams.map((t, i) => html`${i > 0 ? ", " : ""}${teamName(data.teams, t)}`)}. ` : ""}${member.machines} machine${member.machines === 1 ? "" : "s"}. Joined ${timeTag(member.joinedAt)}.</p>
    ${memberControls(viewer, member, data)}
  </li>`
}

export function peoplePage(shell: WorkspaceShell, data: PeopleData): PageInput {
  const base = { title: "People", viewer: null, workspace: shell, current: "people" as const }
  if (data.viewer?.role === "guest") {
    return { ...base, boot: { page: "people-guest" }, body: html`${head("People", GUEST_PEOPLE_WORDS)}` }
  }
  const viewer = data.viewer
  const invites = data.invites
  return {
    ...base,
    boot: { page: "people" },
    body: html`${head("People", "Everyone in this workspace, their role and whether they can act yet.")}
      ${blockedNote(viewer)}
      <section class="card"><h2>People</h2>${data.members.length === 0 ? emptyState("users", "Nobody yet", "Invite someone below.") : html`<ul class="list people">${data.members.map((m) => memberRow(viewer, m, data))}</ul>`}</section>
      ${viewer !== null ? inviteForm(viewer, data) : ""}
      ${invites !== null ? html`<section class="card" data-region="invites"><h2>Invitations</h2>${invites.length === 0 ? html`<p class="muted">No invitations.</p>` : html`<ul class="list invites">${invites.map((i) => inviteRow(i, data))}</ul>`}</section>` : ""}`,
  }
}

// ---------------------------------------------------------------- teams

function teamCard(viewer: PeopleViewer | null, team: TeamView, data: PeopleData): Html {
  const manage = viewer !== null && !viewer.blocked && elevated(viewer.role)
  const candidates = data.members.filter((m) => m.status === "active" && m.role !== "guest" && !team.members.some((t) => t.member === m.member))
  // Everyone a name could be confused with: the workspace's people and the
  // team's own list (which may name someone no longer listed).
  const everyone = [...data.members, ...team.members.filter((t) => !data.members.some((m) => m.member === t.member))]
  return html`<section class="card team" data-team="${team.id}">
    <div class="card-head"><h2>${cardText(team.name)} <code>${team.slug}</code></h2>${pill(`${team.machines} machine${team.machines === 1 ? "" : "s"}`, "muted", false)}</div>
    <h3>Members</h3>
    ${team.members.length === 0 ? html`<p class="muted">No members.</p>` : html`<ul class="plain">${team.members.map((m) => html`<li>${personName(m, everyone)}${manage ? html` <button type="button" class="btn secondary sm" data-action="team-member-remove" data-team="${team.id}" data-member="${m.member}" aria-label="Take ${spellCardText(personLabel(m, everyone))} out of ${spellCardText(team.name)} (${team.slug})">Take out</button>` : ""}</li>`)}</ul>`}
    ${manage && candidates.length > 0 ? html`<div class="inline-form"><label class="inline"><span class="sr">Add to ${cardText(team.name)}</span><select data-input="team-member" data-team="${team.id}">${candidates.map((m) => html`<option value="${m.member}">${spellCardText(personLabel(m, everyone))}</option>`)}</select></label><button type="button" class="btn secondary sm" data-action="team-member-add" data-team="${team.id}">Add to team</button></div>` : ""}
    <h3>Project shares</h3>
    ${team.shares.length === 0 ? html`<p class="muted">No projects shared with this team yet. Share one with it under Shared with, on the project's page.</p>` : html`<ul class="plain">${team.shares.map((s) => html`<li>${projectSlug(data.projects, s.project)}: ${s.level}${s.protected ? ", including protected environments" : ""}${s.expiresAt !== null ? html`, until ${timeTag(s.expiresAt)}` : ""}</li>`)}</ul>`}
    ${manage ? html`<details class="fold"><summary>${icon("chevronRight")}<span>Rename${team.machines === 0 ? " or delete" : ""}</span></summary>
      <form class="stack" data-form="team-rename" data-team="${team.id}" novalidate>
        <label class="field"><span class="label">Name</span><input type="text" data-input="team-name" maxlength="64" value="${team.name}"></label>
        <label class="field"><span class="label">Short name</span><input type="text" data-input="team-slug" maxlength="32" value="${team.slug}" autocapitalize="off" spellcheck="false"></label>
        <button type="submit" class="btn secondary sm">${icon("passkey")}<span>Rename with passkey</span></button>
      </form>
      ${team.machines === 0 ? html`<button type="button" class="btn danger-quiet sm" data-action="team-delete" data-team="${team.id}">Delete team</button>` : html`<p class="small muted">Revoke its machines before deleting this team.</p>`}
    </details>` : ""}
  </section>`
}

export function teamsPage(shell: WorkspaceShell, data: PeopleData): PageInput {
  const viewer = data.viewer
  const manage = viewer !== null && !viewer.blocked && elevated(viewer.role)
  const teams = data.teams ?? []
  return {
    title: "Teams",
    viewer: null,
    workspace: shell,
    current: "teams",
    boot: { page: "teams" },
    body: html`${head("Teams", "Groups of members that projects and shared machines can be given to. Owners and admins manage them; a team has no maintainer.")}
      ${blockedNote(viewer)}
      ${teams.length === 0 ? html`<section class="card">${emptyState("users", "No teams yet", manage ? "Create one below." : "Owners and admins create teams.")}</section>` : teams.map((t) => teamCard(viewer, t, data))}
      ${manage ? html`<section class="card" data-region="team-create"><h2>New team</h2><form class="stack" data-form="team-create" novalidate>
        <label class="field"><span class="label">Name</span><input type="text" data-input="team-name" maxlength="64"></label>
        <label class="field"><span class="label">Short name</span><input type="text" data-input="team-slug" maxlength="32" autocapitalize="off" spellcheck="false" placeholder="platform"><span class="hint">Lower case letters, digits and dashes.</span></label>
        <button type="submit" class="btn primary">${icon("passkey")}<span>Create team with passkey</span></button>
      </form></section>` : ""}`,
  }
}
