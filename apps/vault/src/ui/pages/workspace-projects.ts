// A workspace's projects: the list, and one project with its access, shares,
// environments (protected, a second approver, the hosts that belong to one),
// variables and repositories.
// Every control is offered only where workspace-rights.ts says the vault
// would allow it; where the vault keeps a change for owners and admins the
// page says so in the vault's own words instead. Names are stored text and
// go through cardText; links and keys use ids and slugs only.

import type { Share, TeamView, WorkspaceItemSummary, WorkspaceMemberView, WorkspaceProject } from "@mehen/protocol/workspace"
import { cardText, emptyState, notice, pageHead, pill, responsiveTable, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon, kindTile } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import { type WorkspaceShell, workspaceHref } from "../shell.ts"
import { SHARE_END_HINT, joinWords } from "../wording.ts"
import { overrideOffered } from "../client/workspace-logic.ts"
import { type EnvironmentControls, type EnvironmentReferences, type ProjectControls, type Viewer, HELD_WORDS, accessSourceLines, belongsToWords, canCreateProject, projectControls } from "../workspace-rights.ts"

export type ProjectsPageData = { viewer: Viewer; projects: WorkspaceProject[] }

export type ProjectPageData = {
  viewer: Viewer
  project: WorkspaceProject
  // The credentials the viewer can see, for each variable's Belongs to and
  // the sources a variable may be pointed at; null when the read failed.
  items: WorkspaceItemSummary[] | null
  // The people, for share subjects and their names; null for guests, who
  // never see the member list.
  members: WorkspaceMemberView[] | null
  // The viewer's own overrides, from WS-OVERRIDES' read; null while that read
  // is not served, when "Use my own" is not offered at all.
  overrides: ProjectOverride[] | null
  // The workspace's teams, for team share subjects and their names; null
  // for guests, who are never sent a team list, and when the read failed.
  teams?: TeamView[] | null
  // ?share=<mem_>, from a share request's link: the share form starts open
  // with that member chosen, when they are among its choices.
  shareWith?: string | null
}

// A variable as the vault shows it to a person; `value` is a plain value,
// sent only to those who may edit it.
export type ShownVariable = WorkspaceProject["vars"][number] & { value?: string }

// One of the viewer's own overrides (WS-OVERRIDES browser contract).
export type ProjectOverride = { environment: string; variable: string; source: { kind: "plain"; value: string } | { kind: "item"; item: string; field: string }; updatedAt: string }

const LEVEL_WORDS: Readonly<Record<"use" | "edit" | "manage", string>> = { use: "Use", edit: "Edit", manage: "Manage" }

function envPills(env: WorkspaceProject["environments"][number]): Html {
  return html`${env.protected ? html`<span class="pill warn">${icon("lock")}Protected</span>` : pill("Unprotected", "muted")}${env.fourEyes ? html` <span class="pill accent" data-pill="four-eyes">${icon("users")}Second approver</span>` : ""}${env.fences.length ? html` ${pill(`${env.fences.length} reserved ${env.fences.length === 1 ? "host" : "hosts"}`, "muted", false)}` : ""}`
}

// An environment's hosts are reserved to it: runs in the project's other
// environments are refused when they connect to one (runs.ts builds the
// blocked set from the other environments). They are not an allowlist for
// runs in this environment, and the words must never say they are.
export function reservedHostsWords(env: string): string {
  return `These hosts belong to ${env}: Mehen refuses requests to them from runs in this project's other environments. It matches host names, not DNS aliases, and does not sandbox a program's direct network access. This does not limit where runs in ${env} may connect.`
}

export function reservedHostsHint(env: string): string {
  return `Mehen refuses requests to these hosts from runs in this project's other environments. It matches host names, not DNS aliases, and does not sandbox a program's direct network access. This does not limit where runs in ${env} may connect; an empty list reserves none.`
}

function accessWords(project: WorkspaceProject): string {
  const level = project.access.level
  if (level === null) return "No access"
  return LEVEL_WORDS[level]
}

// The list's second pill names the environments that need an approval for
// every run, as in "prod protected".
function protectedWords(project: WorkspaceProject): string | null {
  const names = project.environments.filter((e) => e.protected).map((e) => e.name)
  return names.length ? `${joinWords(names)} protected` : null
}

function projectEntry(project: WorkspaceProject, slug: string): Html {
  const search = [project.slug, ...project.remotes, ...project.environments.map((e) => e.name)].join(" ").toLowerCase()
  const guarded = protectedWords(project)
  return html`<li class="row" data-row data-search="${search}">
    ${kindTile("project")}
    <a class="row-main" href="${workspaceHref(slug, `/projects/${encodeURIComponent(project.id)}`)}"><span class="row-title">${cardText(project.slug)}</span><span class="row-sub">${project.remotes.length ? cardText(joinWords(project.remotes)) : "no repository bound"}</span></a>
    <span class="row-side">${pill(accessWords(project), "muted", false)}${guarded !== null ? html` <span class="pill warn">${cardText(guarded)}</span>` : ""}</span>
  </li>`
}

// Members, admins and owners create projects in the browser; guests never.
function createForm(viewer: Viewer): Html {
  if (!canCreateProject(viewer)) return html``
  return html`<details class="fold edit" data-region="create-project">
    <summary>${icon("chevronRight")}<span>New project</span></summary>
    <form class="stack" data-form="create-project" novalidate>
      <label class="field"><span class="label">Name (lowercase letters, digits and dashes)</span>
        <input type="text" data-input="slug" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="platform"></label>
      <label class="field"><span class="label">Repository origin, optional</span>
        <input type="text" data-input="remote" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="git@github.com:owner/repo.git"></label>
      <fieldset class="field"><legend class="label">Environments</legend>
        <label class="tick"><input type="checkbox" data-env="dev" checked disabled><span><code>dev</code>, the default</span></label>
        <label class="tick"><input type="checkbox" data-env="staging" checked><span><code>staging</code></span></label>
        <label class="tick"><input type="checkbox" data-env="prod" checked disabled><span><code>prod</code>, always protected</span></label>
        <label class="tick"><input type="checkbox" data-input="prod-four-eyes"><span>Needs a second person on <code>prod</code>: a run there needs approval from someone other than the machine's owner</span></label>
      </fieldset>
      <p class="small muted">You get Manage on the project you create.</p>
      <button type="button" class="btn primary" data-action="create-project">Create with passkey</button>
    </form>
  </details>`
}

export function workspaceProjectsPage(shell: WorkspaceShell, data: ProjectsPageData): PageInput {
  const slug = shell.identity.workspace.slug
  const { projects } = data
  return {
    title: "Projects",
    viewer: null,
    workspace: shell,
    current: "projects",
    boot: { page: "ws-projects" },
    body: html`${pageHead({ title: "Projects", lead: `Repositories you run code from. Each environment gets its variables from the vault; protected ones need an approval for every run.${data.viewer.role === "guest" ? " You see only the projects shared with you." : ""}` })}
      ${data.viewer.held === true ? notice("warn", HELD_WORDS) : ""}
      ${createForm(data.viewer)}
      ${projects.length
        ? html`<div class="toolbar"><label class="search">${icon("search")}<input type="search" data-input="search" placeholder="Search projects" aria-label="Search projects by name, repository or environment" autocomplete="off"><kbd>/</kbd></label></div>
          <section class="card"><ul class="rows" data-region="list">${projects.map((p) => projectEntry(p, slug))}</ul>
          <div data-region="no-match" hidden>${emptyState("search", "Nothing matches", "Try another word.")}</div></section>`
        : html`<section class="card">${emptyState("folder", "No projects yet", data.viewer.role === "guest" ? "When a project is shared with you, it appears here." : "Create one here, or run mehen init in a repository.")}</section>`}`,
  }
}

// ---------------------------------------------------------------- one project

type Names = { member: (id: string) => string; team: (id: string) => string }

function namesFrom(data: ProjectPageData): Names {
  const members = new Map((data.members ?? []).map((m) => [m.member, m.name]))
  const teams = new Map((data.viewer.role === "guest" ? [] : (data.teams ?? [])).map((t) => [t.id, t]))
  return {
    // A name may repeat; the id or slug beside it tells two apart.
    member: (id) => (id === data.viewer.member ? "you" : members.has(id) ? `${members.get(id)} (${id})` : id),
    team: (id) => {
      const team = teams.get(id)
      return team === undefined ? id : `${team.name} (${team.slug})`
    },
  }
}

// The viewer's effective access as one sentence, as in "Manage, including
// protected runs and edits (as workspace owner)."
export function accessSentence(access: WorkspaceProject["access"]): string {
  if (access.level === null) return "You have no access to this project."
  const reach = access.runProtected && access.editProtected ? ", including protected runs and edits" : access.runProtected ? ", including protected runs" : access.editProtected ? ", including protected edits" : ", unprotected environments only"
  const role = access.sources.find((s) => s.kind === "role")
  return `${LEVEL_WORDS[access.level]}${reach}${role?.kind === "role" ? ` (as workspace ${role.role})` : ""}.`
}

// The sentence first; folded under it, each source as it was granted, as a
// table that becomes a labelled list on a narrow card. Sources can differ,
// so each keeps its own protected run and protected edit.
function accessCard(data: ProjectPageData, names: Names): Html {
  const { access } = data.project
  const lines = accessSourceLines(access, names)
  return html`<section class="card" aria-label="Your access" data-region="your-access">
    <div class="card-head"><h2>Your access</h2></div>
    <p data-region="access-sentence">${accessSentence(access)}</p>
    ${lines.length
      ? html`<details class="fold" data-region="access-sources"><summary>${icon("chevronRight")}<span>Where this comes from</span></summary>
      ${responsiveTable(
        ["From", "Level", "Protected runs", "Protected edits", "Until"],
        lines.map((l) => [cardText(l.from), l.level === "use" || l.level === "edit" || l.level === "manage" ? LEVEL_WORDS[l.level] : l.level, l.protectedRun ? "Yes" : "No", l.protectedEdit ? "Yes" : "No", l.expiresAt === null ? "No end" : timeTag(l.expiresAt)]),
      )}
    </details>`
      : ""}
  </section>`
}

function shareSubjectWords(share: Share, names: Names): string {
  return share.subject.kind === "member" ? names.member(share.subject.member) : `team ${names.team(share.subject.team)}`
}

function shareTerms(share: Pick<Share, "level" | "protected" | "expiresAt">): Html {
  const level = LEVEL_WORDS[share.level]
  const tick = share.level !== "manage" && share.protected ? ", including protected environments" : ""
  return html`${level}${tick}${share.expiresAt !== null ? html`, until ${timeTag(share.expiresAt)}` : ""}`
}

// The workspace credentials this project's variables point at: what a new
// guest share would also let them use (design 8.3).
function workspaceReach(data: ProjectPageData): string[] {
  const homes = new Map((data.items ?? []).map((i) => [i.slug, i.home]))
  const out = new Set<string>()
  for (const v of data.project.vars) if (v.item !== null && homes.get(v.item)?.kind === "workspace") out.add(v.item)
  return [...out].sort()
}

function shareLevelOptions(): Html {
  return html`<option value="use">Use</option><option value="edit">Edit</option><option value="manage">Manage</option>`
}

const SHARE_GUEST_OWNER_ONLY = "Only an owner or admin can share this project with a guest."

function sharesCard(data: ProjectPageData, controls: ProjectControls, names: Names): Html {
  const shares = data.project.shares
  if (shares === undefined) {
    return html`<section class="card" aria-label="Shared with" data-region="shares"><div class="card-head"><h2>Shared with</h2></div>
      <p class="small muted">${data.viewer.role === "guest" ? "Shared with you. Only the people who manage this project see who else it is shared with." : "Only the project's managers see who it is shared with."}</p></section>`
  }
  const members = (data.members ?? []).filter((m) => m.status === "active" && m.member !== data.viewer.member && (controls.shareWithGuests || m.role !== "guest"))
  // A guest is never shown a team list; the route does not read one for them.
  const teams = data.viewer.role === "guest" ? [] : (data.teams ?? [])
  const reach = workspaceReach(data)
  const asked = data.shareWith != null && members.some((m) => m.member === data.shareWith) ? data.shareWith : null
  // A share request naming a guest this viewer may not share with: the form
  // says why and chooses no one, so nobody else is shared with by mistake.
  const notOffered = data.shareWith != null && asked === null && controls.share && !controls.shareWithGuests && (data.members ?? []).some((m) => m.member === data.shareWith && m.status === "active" && m.role === "guest") ? SHARE_GUEST_OWNER_ONLY : null
  return html`<section class="card" aria-label="Shared with" data-region="shares">
    <div class="card-head"><h2>Shared with</h2></div>
    ${shares.length
      ? html`<ul class="share-list">${shares.map(
          (s) => html`<li data-share="${s.id}"><span class="share-who">${cardText(shareSubjectWords(s, names))}</span> <span class="share-terms">${shareTerms(s)}</span>${
            controls.share ? html` <button type="button" class="btn danger-quiet sm" data-action="unshare" data-subject="${JSON.stringify(s.subject)}">${icon("x")}<span>Unshare</span></button>` : ""
          }</li>`,
        )}</ul>`
      : html`<p class="muted">Not shared with anyone yet.</p>`}
    ${controls.share
      ? html`<details class="fold edit" data-region="share-fold"${asked !== null || notOffered !== null ? " open" : ""}>
          <summary>${icon("chevronRight")}<span>Share this project</span></summary>
          <form class="stack" data-form="share" novalidate>
            ${notOffered !== null ? html`<p class="notice warn" data-region="share-not-offered">${notOffered}</p>` : ""}
            <label class="field"><span class="label">With</span><select data-input="subject">${notOffered !== null ? html`<option value="" selected>Choose who to share with</option>` : ""}<optgroup label="People">${members.map(
              (m) => html`<option value="${m.member}" data-kind="member" data-role="${m.role}"${m.member === asked ? " selected" : ""}>${cardText(m.name)} (${m.member})${m.role === "guest" ? ", guest" : ""}</option>`,
            )}</optgroup>${teams.length
              ? html`<optgroup label="Teams" data-region="team-subjects">${teams.map((t) => html`<option value="${t.id}" data-kind="team">${cardText(t.name)} (team ${cardText(t.slug)})</option>`)}</optgroup>`
              : ""}</select></label>
            <label class="field"><span class="label">Level</span><select data-input="level">${shareLevelOptions()}</select></label>
            <label class="tick" data-region="protected-tick"><input type="checkbox" data-input="protected"><span>Including protected environments</span></label>
            <p class="small muted">Manage always includes protected environments. A guest gets at most Edit.</p>
            <label class="field"><span class="label">Ends, optional (UTC day, included)</span><input type="date" data-input="ends" autocomplete="off"><span class="hint">${SHARE_END_HINT}</span></label>
            ${reach.length ? html`<p class="small warn-text" data-region="guest-reach" hidden>This also lets the guest use: ${joinWords(reach.map((r) => `${r} (workspace credential)`))}. This list is shown to you; the passkey signs the share itself.</p>` : ""}
            ${reach.length && teams.length ? html`<p class="small warn-text" data-region="team-reach" hidden>This also lets the team's members and its machines use: ${joinWords(reach.map((r) => `${r} (workspace credential)`))}. This list is shown to you; the passkey signs the share itself.</p>` : ""}
            <p class="small warn-text" data-region="share-end-change" hidden></p>
            <button type="button" class="btn primary" data-action="share">Share with passkey</button>
          </form>
        </details>`
      : ""}
  </section>`
}

function sourceLine(data: ProjectPageData, ws: string, v: WorkspaceProject["vars"][number], homes: ReadonlyMap<string, WorkspaceItemSummary>, slugs: ReadonlyMap<string, string>): Html {
  if (v.source === "item" && v.item !== null) {
    const item = homes.get(v.item)
    const belongs = item === undefined ? "" : belongsToWords(item.home, slugs, data.project.id)
    return html`from <a href="${workspaceHref(ws, `/items/${encodeURIComponent(v.item)}`)}"><code>${cardText(v.item)}${v.field ? html`#${cardText(v.field)}` : ""}</code></a>${
      belongs ? html` <span class="belongs" data-belongs="${item?.home.kind ?? ""}">Belongs to: ${belongs}</span>` : ""
    }`
  }
  if (v.source === "item") return html`<span class="muted">${cardText(v.note ?? "A credential outside your reach.")}</span>`
  const value = (v as ShownVariable).value
  if (v.source === "plain") return value !== undefined ? html`the plain value <code data-plain>${cardText(value)}</code>` : html`a plain, non-secret value stored in the vault`
  return pill("not set", "warn", false)
}

function varForm(env: string, controls: EnvironmentControls, choices: readonly WorkspaceItemSummary[], slugs: ReadonlyMap<string, string>, here: string, sharingUnknown: boolean): Html {
  const allowed = choices.filter((i) => (i.home.kind === "project" && i.home.project === here) || (i.home.kind === "workspace" && controls.workspaceSources))
  return html`<details class="fold edit">
    <summary>${icon("chevronRight")}<span>Set a variable in ${cardText(env)}</span></summary>
    <form class="stack" data-form="var" data-env="${env}" novalidate>
      <label class="field"><span class="label">Variable name</span>
        <input type="text" data-input="name" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="OPENAI_API_KEY"></label>
      <label class="field"><span class="label">From a credential</span><select data-input="item"><option value="">None</option>${allowed.map(
        (i) => html`<option value="${i.slug}" data-home="${i.home.kind}">${cardText(i.slug)} (Belongs to: ${belongsToWords(i.home, slugs, here)})</option>`,
      )}</select></label>
      <label class="field"><span class="label">Field, optional</span><input type="text" data-input="field" autocomplete="off" spellcheck="false" placeholder="key"></label>
      <label class="field"><span class="label">Or a plain value that is not secret</span>
        <input type="text" data-input="plain" autocomplete="off" autocapitalize="off" spellcheck="false"></label>
      ${controls.workspaceSources ? "" : html`<p class="small muted" data-region="no-workspace-sources">${sharingUnknown ? "Ask a manager of this project, or an owner or admin, to point a variable here at a workspace credential." : "Only an owner or admin can point a variable here at a workspace credential."}</p>`}
      <button type="button" class="btn primary" data-action="set-var">Save with passkey</button>
    </form>
  </details>`
}

function environmentForm(env: WorkspaceProject["environments"][number], controls: EnvironmentControls): Html {
  const any = controls.protect || controls.unprotect || controls.fourEyesOn || controls.fourEyesOff || controls.fences
  if (!any) return html``
  return html`<details class="fold edit">
    <summary>${icon("chevronRight")}<span>Change protection</span></summary>
    <form class="stack" data-form="environment" data-env="${env.name}" novalidate>
      ${controls.protect ? html`<label class="tick"><input type="checkbox" data-input="protected" data-control="protect"><span>Protect ${cardText(env.name)}: every run needs <code>--env ${cardText(env.name)}</code> typed out, an allowed machine and an approval</span></label>` : ""}
      ${controls.unprotect ? html`<label class="tick"><input type="checkbox" data-input="protected" data-control="unprotect" checked><span>Protected (untick to stop protecting ${cardText(env.name)})</span></label>` : ""}
      ${controls.fourEyesOn ? html`<label class="tick"><input type="checkbox" data-input="four-eyes" data-control="four-eyes-on"><span>Needs a second person: approval from someone other than the machine's owner</span></label>` : ""}
      ${controls.fourEyesOff ? html`<label class="tick"><input type="checkbox" data-input="four-eyes" data-control="four-eyes-off" checked><span>Needs a second person (untick to let the machine's owner approve)</span></label>` : ""}
      ${controls.fences ? html`<label class="field"><span class="label">Hosts that belong to ${cardText(env.name)}, one per line</span>
        <textarea data-input="fences" data-control="fences" rows="3" autocomplete="off" autocapitalize="off" spellcheck="false">${env.fences.join("\n")}</textarea><span class="hint">${cardText(reservedHostsHint(env.name))}</span></label>` : ""}
      <button type="button" class="btn secondary" data-action="save-environment">Save with passkey</button>
    </form>
  </details>`
}

const FOUR_EYES_WORDS = "Needs a second person: a run here needs approval from someone other than the machine's owner, and that person must manage every project whose second-approver rule covers the credentials the run uses."

// "Use my own" is offered only once the override read is served, only where
// the project has a row for exactly this variable in exactly this
// environment, and never in a protected one.
function overridable(data: ProjectPageData, env: WorkspaceProject["environments"][number], v: WorkspaceProject["vars"][number]): boolean {
  return data.overrides !== null && data.project.access.level !== null && overrideOffered(data.project, env.name, v.name)
}

// Under a variable the viewer has overridden: that their runs use their
// own source. A plain override is named only as "your own plain value": the
// page never prints the value back, here or in its boot state.
function ownSourceLine(data: ProjectPageData, env: WorkspaceProject["environments"][number], v: WorkspaceProject["vars"][number]): Html {
  if (!overridable(data, env, v)) return html``
  const mine = (data.overrides ?? []).find((o) => o.environment === env.name && o.variable === v.name)
  if (mine === undefined) return html``
  return html`<p class="small" data-own-source="${mine.source.kind}">Your runs use your own ${mine.source.kind === "item" ? html`<code>${cardText(mine.source.item)}</code>` : "plain value"} instead.${data.viewer.held === true ? "" : html` <button type="button" class="link" data-action="clear-own" data-env="${env.name}" data-var="${v.name}">Stop using my own</button>`}</p>`
}

// One "Your overrides" fold per environment, with a form for each variable
// the viewer may point at their own source.
function overridesFold(data: ProjectPageData, env: WorkspaceProject["environments"][number], vars: readonly WorkspaceProject["vars"][number][]): Html {
  const offered = data.viewer.held === true ? [] : vars.filter((v) => overridable(data, env, v))
  if (offered.length === 0) return html``
  const own = (data.items ?? []).filter((i) => i.home.kind === "member" && i.home.member === data.viewer.member)
  return html`<details class="fold edit" data-region="overrides"><summary>${icon("chevronRight")}<span>Your overrides</span></summary>
    <p class="small muted">Point a variable at your own credential or value. Only runs on your own machines use it; everyone else keeps the shared source.</p>
    ${offered.map(
      (v) => html`<div class="own-override" data-override="${env.name}/${v.name}">
      <form class="stack" data-form="own" data-env="${env.name}" data-var="${v.name}" novalidate>
        <p><b>Use my own for <code>${cardText(v.name)}</code></b></p>
        <label class="field"><span class="label">One of your own credentials</span><select data-input="item"><option value="">None</option>${own.map((i) => html`<option value="${i.slug}">${cardText(i.slug)}</option>`)}</select></label>
        <label class="field"><span class="label">Its field</span><input type="text" data-input="field" autocomplete="off" spellcheck="false" placeholder="key"></label>
        <label class="field"><span class="label">Or a plain value that is not secret</span><input type="text" data-input="plain" autocomplete="off" spellcheck="false"></label>
        <button type="button" class="btn secondary" data-action="use-own">Use mine with passkey</button>
      </form></div>`,
    )}
  </details>`
}

function environmentCard(data: ProjectPageData, ws: string, env: WorkspaceProject["environments"][number], controls: EnvironmentControls, homes: ReadonlyMap<string, WorkspaceItemSummary>, slugs: ReadonlyMap<string, string>, sharingUnknown: boolean): Html {
  const vars = data.project.vars.filter((v) => v.env === env.name)
  return html`<section class="card env${env.protected ? " protected" : ""}" id="env-${env.name}" data-env-card="${env.name}" aria-label="Environment ${env.name}">
    <div class="card-head"><h2>${cardText(env.name)}${env.name === data.project.defaultEnv ? html` <span class="small muted">default</span>` : ""}</h2><span>${envPills(env)}</span></div>
    ${env.protected ? html`<p class="small muted">Never chosen by default: needs <code>--env ${cardText(env.name)}</code> typed out, an allowed machine and an approval for each run.</p>` : ""}
    ${env.fourEyes ? html`<p class="small muted" data-region="four-eyes-words">${FOUR_EYES_WORDS}</p>` : ""}
    ${env.fences.length ? html`<p class="small muted" data-region="reserved-hosts">${cardText(reservedHostsWords(env.name))}</p><ul class="hosts fences">${env.fences.map((f) => html`<li><code>${cardText(f)}</code></li>`)}</ul>` : ""}
    ${vars.length ? html`<dl class="vars">${vars.map((v) => html`<dt data-var="${v.name}" data-source="${v.source}"><code>${cardText(v.name)}</code></dt><dd>${sourceLine(data, ws, v, homes, slugs)}${ownSourceLine(data, env, v)}</dd>`)}</dl>` : html`<p class="muted">No variables.</p>`}
    ${controls.ownerOnly.length ? html`<ul class="owner-only" data-region="owner-only">${controls.ownerOnly.map((line) => html`<li>${cardText(line)}</li>`)}</ul>` : ""}
    ${controls.setVariables ? varForm(env.name, controls, data.items ?? [], slugs, data.project.id, sharingUnknown) : ""}
    ${overridesFold(data, env, vars)}
    ${environmentForm(env, controls)}
  </section>`
}

function remotesCard(project: WorkspaceProject, controls: ProjectControls): Html {
  const last = project.remotes.length === 1
  return html`<section class="card remotes" aria-label="Repositories" data-region="remotes">
    <div class="card-head"><h2>Repositories</h2></div>
    <p class="small muted">${project.remotes.length ? "Only checkouts whose origin remote, as the CLI reports it, is one of these may use this project. This prevents use from a mismatched checkout; it does not attest the repository's contents." : "None bound, so only a checkout with no origin remote may use this project."}</p>
    ${project.remotes.length
      ? html`<ul class="remote-list">${project.remotes.map(
          (r) => html`<li><code>${cardText(r)}</code>${controls.remotes && !last ? html`<button type="button" class="btn danger-quiet sm" data-action="unbind-remote" data-remote="${r}">${icon("x")}<span>Unbind</span></button>` : ""}</li>`,
        )}</ul>`
      : ""}
    ${controls.remotes
      ? html`<details class="fold edit"><summary>${icon("chevronRight")}<span>Bind a repository</span></summary>
          <form class="stack" data-form="remote" novalidate>
            <label class="field"><span class="label">The repository's origin URL</span><input type="text" data-input="remote" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="git@github.com:owner/repo.git"></label>
            <p class="small muted">The vault binds the normalised repository shown before you confirm. Bind only a repository you control.</p>
            <button type="button" class="btn primary" data-action="bind-remote">Bind with passkey</button>
          </form></details>`
      : ""}
  </section>`
}

// Deleting is the last card, folded, and an outline button: the passkey
// prompt is the confirmation.
function dangerCard(controls: ProjectControls, project: WorkspaceProject): Html {
  if (controls.deleteOwnerOnly !== null) return html`<section class="card danger-zone" aria-label="Danger zone" data-region="delete-project"><div class="card-head"><h2>Danger zone</h2></div><p class="small muted">${cardText(controls.deleteOwnerOnly)}</p></section>`
  if (!controls.delete) return html``
  return html`<section class="card danger-zone" aria-label="Danger zone" data-region="delete-project"><div class="card-head"><h2>Danger zone</h2></div>
    <details class="fold"><summary>${icon("chevronRight")}<span>Delete this project</span></summary>
      <div class="stack"><p class="small muted">Its variables, environments and shares go, and its runs end. Delete or move its own credentials first.</p>
      <button type="button" class="btn danger-quiet" data-action="delete-project" data-project="${project.id}">Delete ${cardText(project.slug)} with passkey</button></div>
    </details></section>`
}

// Environments whose variables point at a workspace credential, as far as
// the viewer's credential list tells.
export function environmentReferences(project: WorkspaceProject, items: readonly WorkspaceItemSummary[]): Record<string, EnvironmentReferences> {
  const homes = new Map(items.map((i) => [i.slug, i.home.kind]))
  return Object.fromEntries(project.environments.map((e) => [e.name, { workspaceReference: project.vars.some((v) => v.env === e.name && v.item !== null && homes.get(v.item) === "workspace") }]))
}

// Shared with a guest or a team (which may own a machine): there only
// owners and admins point variables at workspace credentials. Null when the
// vault did not send the share list (it does only to managers): unknown, so
// the page does not offer what the vault might refuse.
export function sharedWithService(project: WorkspaceProject, members: readonly WorkspaceMemberView[] | null): boolean | null {
  if (project.shares === undefined) return null
  const guests = new Set((members ?? []).filter((m) => m.role === "guest").map((m) => m.member))
  return (project.shares ?? []).some((s) => s.subject.kind === "team" || guests.has(s.subject.member))
}

export function workspaceProjectPage(shell: WorkspaceShell, data: ProjectPageData): PageInput {
  const { project } = data
  const items = data.items ?? []
  const homes = new Map(items.map((i) => [i.slug, i]))
  const slugs = new Map([[project.id, project.slug]])
  const sharing = sharedWithService(project, data.members)
  const controls = projectControls(data.viewer, project, environmentReferences(project, items), sharing)
  const names = namesFrom(data)
  const guests = (data.members ?? []).filter((m) => m.role === "guest").map((m) => m.member)
  return {
    title: project.slug,
    viewer: null,
    workspace: shell,
    current: "projects",
    boot: {
      page: "ws-project",
      project: { id: project.id, slug: project.slug },
      environments: project.environments.map((e) => ({ name: e.name, protected: e.protected, fences: e.fences, fourEyes: e.fourEyes })),
      // Only sources the page can name as a before-state: a visible
      // credential, a plain value shown to this editor, or unset.
      vars: (project.vars as ShownVariable[]).filter((v) => !(v.source === "item" && v.item === null) && !(v.source === "plain" && v.value === undefined)).map((v) => ({ env: v.env, name: v.name, item: v.item, field: v.field, ...(v.source === "plain" && v.value !== undefined ? { plain: v.value } : {}) })),
      shares: (project.shares ?? []).map((s) => ({ subject: s.subject, level: s.level, protected: s.protected, expiresAt: s.expiresAt })),
      guests,
    },
    body: html`${pageHead({
        tile: kindTile("project", undefined, "xl"),
        eyebrow: "Project",
        title: cardText(project.slug),
        lead: html`${project.remotes.length ? cardText(joinWords(project.remotes)) : "No repository bound"} <code class="muted">${project.id}</code>`,
      })}
      ${data.viewer.held === true ? notice("warn", HELD_WORDS) : ""}
      ${accessCard(data, names)}
      ${sharesCard(data, controls, names)}
      ${project.environments.map((env) => environmentCard(data, shell.identity.workspace.slug, env, controls.environments[env.name] as EnvironmentControls, homes, slugs, sharing === null))}
      ${remotesCard(project, controls)}
      ${dangerCard(controls, project)}`,
  }
}
