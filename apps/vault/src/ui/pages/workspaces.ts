// The shell's own pages: a workspace's home, the picker of the account's
// workspaces, and the one not-found page every /w/ address answers with
// when its workspace is unknown, not the account's, or has no such page
// (the account page is account.ts). A workspace is always named with its
// slug and the vault's origin beside its name, because two workspaces may
// share a name and a rename changes it.

import type { InboxResponse, InboxWorkspace, WorkspaceInboxResponse } from "@mehen/protocol/inbox"
import type { AccountSession, MembershipView, WorkspaceDeviceView, WorkspaceItemSummary, WorkspaceMemberView, WorkspaceProject, WorkspaceSettingsView } from "@mehen/protocol/workspace"
import type { WorkspaceInviteView } from "../../vault/areas/workspace-runtime.ts"
import type { PostureNudge } from "../../vault/areas/postures-workspace.ts"
import { mandateStrip } from "./mandates.ts"
import { POSTURE_CARD_ID } from "../posture-card.ts"
import { NUDGE_CARD_TITLE, NUDGE_CHANGE_LINK, NUDGE_NOT_NOW_BUTTON, nudgeWords } from "../wording.ts"
import { agentSetup, restrictionUntil } from "../client/people-logic.ts"
import { type GetStartedItem, cardText, copyBox, emptyState, getStarted, notice, pageHead } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon } from "../icons.ts"
import { inboxRow, inboxRowOf } from "../inbox-row.ts"
import { NOT_FOUND_ERROR, type PageInput, errorBody } from "../layout.ts"
import { formatTime } from "../wording.ts"
import type { Viewer } from "../workspace-rights.ts"
import { OPERATOR_DENIED_WORDS, RECOVERY_SETUP_WORDS, confirmationWaiting, createLink, creationBlock } from "./account-setup.ts"
import { groupNotice } from "./needs-you.ts"
import { HOME_NEEDS_ROWS, inboxItemSign } from "../client/pages/needs-you-logic.ts"
import { type AccountShell, ROLE_WORDS, type WorkspacePageKey, type WorkspaceShell, identityLine, workspaceHref } from "../shell.ts"

export const WORKSPACE_NOT_FOUND_HEADING = "There is no workspace page here"

// What the home reads, besides the workspace's identity: this workspace's
// inbox and the lists the summaries and the Get started card count, each
// filtered by the vault to what this viewer may see. `members` and
// `invites` are null where the vault refuses them (a guest, a member who
// may not invite) and `settings` until its read is served. A read that
// failed is null too, and its card says so instead of claiming a zero.
export type HomeData = {
  viewer: Viewer
  inbox: WorkspaceInboxResponse | null
  devices: WorkspaceDeviceView[] | null
  items: WorkspaceItemSummary[] | null
  projects: WorkspaceProject[] | null
  members: WorkspaceMemberView[] | null
  invites: WorkspaceInviteView[] | null
  settings: WorkspaceSettingsView | null
  now: number
  // items.nudges, null or absent where it was not read.
  nudges?: readonly PostureNudge[] | null
  // How many machines carry on without asking now, with MANDATES on;
  // null or absent where it was not read.
  mandateMachines?: number | null
  // How many of the reader's machines need them to resume a lapsed mandate.
  mandateResume?: number | null
  // Whether this vault can complete an email-bound invitation
  // (emailInvitesCompletable); absent reads as it can.
  emailInvites?: boolean
}

function frozenNotice(shell: WorkspaceShell, settings: WorkspaceSettingsView | null): Html {
  if (settings === null || !settings.frozen) return html``
  const slug = shell.identity.workspace.slug
  const action = settings.rights.unfreeze && shell.pages.includes("settings") ? html`<a class="btn widen sm" href="${workspaceHref(slug, "/settings#unfreeze")}">Unfreeze</a>` : undefined
  const activity = shell.pages.includes("audit") ? html`See <a href="${workspaceHref(slug, "/audit")}">Activity</a> for what tripped it.` : html`See Activity for what tripped it.`
  return html`<div data-region="frozen">${notice("error", "This workspace is frozen: every machine use is refused.", settings.rights.unfreeze ? activity : html`${activity} Ask an owner to unfreeze it.`, action)}</div>`
}

// The home's own words for a workspace it could not read: reload, not
// "retrying", since the client redraws the card only when the account
// inbox reads the workspace, which may never happen (past its limit).
function needsNotice(w: InboxWorkspace): Html {
  if (w.state === "unavailable" && w.reason !== "limit") return notice("warn", html`Could not read ${cardText(w.workspace.name)} just now.`, "Reload the page to try again.")
  return groupNotice(w)
}

// This workspace's first rows, "See all" to the one-workspace filter, and
// the account's other workspaces as a count the client fills. The card
// carries its workspace's state, how many requests it read and whether
// that list was partial, and each row its signature, so the client can
// tell when the account inbox knows more and redraw it
// (client/pages/needs-you.ts); a workspace that could not be read keeps
// an empty row list for the last good rows the client keeps, greyed.
function needsCard(shell: WorkspaceShell, inbox: WorkspaceInboxResponse | null, now: number): Html {
  const slug = shell.identity.workspace.slug
  const all = shell.pages.includes("needs") ? html`<a class="more-link" href="${workspaceHref(slug, "/pending")}">See all${icon("chevronRight")}</a>` : html``
  const elsewhere = html`<p class="small" data-region="needs-elsewhere" hidden><a href="/needs-you" data-fill="needs-elsewhere"></a></p>`
  if (inbox === null) return html`<section class="card" data-region="home-needs"><div class="card-head"><h2>Needs you</h2>${all}</div>${notice("warn", "Could not read what is waiting here just now.", "Reload the page to try again.")}${elsewhere}</section>`
  const rows = inbox.items.slice(0, HOME_NEEDS_ROWS)
  const more = inbox.items.length - rows.length
  const empty = inbox.workspace.state === "ok" && !inbox.workspace.truncated && rows.length === 0
  return html`<section class="card" data-region="home-needs" data-state="${inbox.workspace.state}" data-count="${inbox.items.length}" data-truncated="${inbox.workspace.truncated ? "true" : "false"}"><div class="card-head"><h2>Needs you</h2>${all}</div>
    ${needsNotice(inbox.workspace)}
    ${rows.length > 0 || inbox.workspace.state === "unavailable" ? html`<ul class="rows" data-region="needs-rows">${rows.map((item) => inboxRow(inboxRowOf(item, inbox.workspace), { now, showWorkspace: false, sign: inboxItemSign(item) }))}</ul>` : ""}
    ${more > 0 ? html`<p class="small muted">${more} more here. <a href="${workspaceHref(slug, "/pending")}">See all</a>.</p>` : ""}
    ${empty ? emptyState("check", "Nothing needs you here", "When an agent asks for something you may decide in this workspace, it appears here with a countdown. A new machine is listed for owners and admins, and for you when its agent used your connect code; otherwise open the link the agent gives you.") : ""}
    ${elsewhere}
  </section>`
}

// At most three credentials that asked often this week, none denied, most
// of it routine building, each with a link to its How careful card and Not
// now (client/pages/nudges.ts); nothing when there is none.
function nudgeCard(shell: WorkspaceShell, nudges: readonly PostureNudge[] | null | undefined): Html {
  if (!nudges || nudges.length === 0) return html``
  const slug = shell.identity.workspace.slug
  return html`<section class="card" data-region="home-nudges"><div class="card-head"><h2>${NUDGE_CARD_TITLE}</h2></div>
    <ul class="rows">${nudges.slice(0, 3).map((n) => html`<li class="row" data-region="nudge" data-slug="${n.slug}">
      <div class="row-main"><p><code>${cardText(n.slug)}</code>${nudgeWords(n.asked, n.routine)}</p></div>
      <span class="row-side"><a class="btn secondary sm" href="${workspaceHref(slug, `/items/${encodeURIComponent(n.slug)}#${POSTURE_CARD_ID}`)}">${NUDGE_CHANGE_LINK}</a><button type="button" class="btn quiet sm" data-action="nudge-quiet" data-slug="${n.slug}">${NUDGE_NOT_NOW_BUTTON}</button></span>
    </li>`)}</ul>
  </section>`
}

function stat(label: string, value: number | null, href: string | null, note?: string): Html {
  const body = html`<b>${value === null ? "?" : String(value)}</b><span>${label}</span>${note !== undefined ? html`<span class="stat-note">${note}</span>` : ""}`
  return href !== null ? html`<a class="stat" href="${href}">${body}</a>` : html`<span class="stat">${body}</span>`
}

// Credentials, Machines, Projects and People, counted from the lists the
// viewer may read; People only for whoever may read the members.
function summaries(shell: WorkspaceShell, data: HomeData): Html {
  const slug = shell.identity.workspace.slug
  const link = (key: WorkspacePageKey, path: string) => (shell.pages.includes(key) ? workspaceHref(slug, path) : null)
  const machines = data.devices?.filter((d) => !d.revoked) ?? null
  const yours = machines?.filter((d) => d.owner.kind === "member" && d.owner.member === data.viewer.member).length ?? null
  return html`<section class="card" data-region="home-summary"><div class="card-head"><h2>In this workspace</h2></div><div class="stats home-stats">
    ${stat("Credentials", data.items?.length ?? null, link("credentials", "/credentials"))}
    ${stat("Machines", machines?.length ?? null, link("machines", "/devices"), yours !== null && yours > 0 ? `${yours} yours` : undefined)}
    ${stat("Projects", data.projects?.length ?? null, link("projects", "/projects"))}
    ${data.members !== null ? stat("People", data.members.length, link("people", "/people")) : ""}
  </div>${data.items === null || data.devices === null || data.projects === null ? html`<p class="small muted">A ? is a list that could not be read just now.</p>` : ""}</section>`
}

const CONNECT_LABEL = "Connect an agent"

const GUEST_ADMISSION = "An owner, an admin or a manager of the shared project admits a guest's machine before it can use anything."

// The Get started items this viewer sees, each
// done from what the viewer's own reads show: owners and admins four,
// members the first two, guests the first with the admission sentence.
// Once one of the viewer's own machines is enrolled (mehen up enrols the
// machine it runs on), the card no longer offers to connect one.
export function getStartedItems(shell: WorkspaceShell, data: HomeData): GetStartedItem[] {
  const connected = data.devices?.some((d) => !d.revoked && d.owner.kind === "member" && d.owner.member === data.viewer.member) ?? false
  const items = allGetStartedItems(shell, data)
  return connected ? items.slice(1) : items
}

function allGetStartedItems(shell: WorkspaceShell, data: HomeData): GetStartedItem[] {
  const slug = shell.identity.workspace.slug
  const role = data.viewer.role
  const setup = agentSetup(shell.identity.origin, slug)
  const connect: GetStartedItem = {
    label: CONNECT_LABEL,
    body: html`Paste this line into your agent, then open the approval link it gives you. The <a href="${workspaceHref(slug, "/connect-agent")}">Connect an agent page</a> gives a line that also sends the approval to your Needs you.${role === "guest" ? html` ${GUEST_ADMISSION}` : ""}`,
    more: setup !== null ? copyBox(setup.prompt) : undefined,
    done: data.devices?.some((d) => !d.revoked && d.owner.kind === "member" && d.owner.member === data.viewer.member) ?? false,
    href: workspaceHref(slug, "/connect-agent"),
  }
  if (role === "guest") return [connect]
  const credential: GetStartedItem = {
    label: "Add a credential",
    body: "Ask your agent for one (it sends you a link to fill in), or add one from Credentials.",
    done: (data.items?.length ?? 0) > 0,
    href: workspaceHref(slug, "/credentials"),
  }
  if (role === "member") return [connect, credential]
  return [
    connect,
    credential,
    {
      label: "Invite a colleague",
      body: data.emailInvites === false ? "Invite someone by link; you confirm them once they have joined." : "Email-bound invitations; you confirm them once they have joined.",
      done: (data.members?.length ?? 0) > 1 || (data.invites?.some((i) => i.status === "open") ?? false),
      href: workspaceHref(slug, "/people"),
    },
    {
      label: "Create a project",
      body: html`Projects hold environments and the variables your code reads through <code>mehen run</code>.`,
      done: (data.projects?.length ?? 0) > 0,
      href: workspaceHref(slug, "/projects"),
    },
  ]
}

const STEP_WORDS: Readonly<Record<number, string>> = { 1: "One step", 2: "Two short steps", 3: "Three short steps", 4: "Four short steps" }

function getStartedCard(shell: WorkspaceShell, data: HomeData): Html {
  const items = getStartedItems(shell, data)
  if (items.length === 0 || items.every((i) => i.done)) return html``
  return getStarted({ workspace: shell.identity.workspace.id, sub: `${STEP_WORDS[items.length] ?? `${items.length} short steps`}. This card goes away when they are done.`, items })
}

// The workspace's home: the frozen notice when it is frozen, what needs
// you here, credentials that ask often, the Get started card while anything in it is undone, and the
// workspace's lists in counts. Without `data` (a build serving only the
// workspace's identity), who and where, and nothing that needs a read.
export function workspaceHomePage(shell: WorkspaceShell, data?: HomeData): PageInput {
  const slug = shell.identity.workspace.slug
  // While Get started shows its first step undone, that step is the way to
  // connect; the header offers no second one beside it.
  const first = data !== undefined ? getStartedItems(shell, data)[0] : undefined
  const stepShown = first !== undefined && first.label === CONNECT_LABEL && !first.done
  const agent = shell.pages.includes("connect-agent") && !stepShown ? html`<a class="btn secondary" href="${workspaceHref(slug, "/connect-agent")}">${icon("terminal")}<span>Connect an agent</span></a>` : undefined
  const head = pageHead({ title: cardText(shell.identity.workspace.name), lead: html`<span class="workspace-identity">${identityLine(shell.identity)}</span>`, actions: agent })
  return {
    title: "Home",
    viewer: null,
    workspace: shell,
    current: "home",
    boot: { page: "workspace-home" },
    body: data === undefined ? head : html`${head}${frozenNotice(shell, data.settings)}${needsCard(shell, data.inbox, data.now)}${mandateStrip(shell, data.mandateMachines ?? null, data.mandateResume ?? null)}${nudgeCard(shell, data.nudges)}${getStartedCard(shell, data)}${summaries(shell, data)}`,
  }
}

// A workspace's count in the picker: from the account inbox, and only when
// that workspace answered; never a zero made up for one that did not.
function countWords(m: MembershipView, counts: ReadonlyMap<string, InboxWorkspace>): string | null {
  const w = counts.get(m.workspace.id)
  if (w === undefined || w.state !== "ok" || w.count === null || w.count === 0) return null
  if (w.truncated) return `${w.count}+ things need you`
  return w.count === 1 ? "1 thing needs you" : `${w.count} things need you`
}

function statusWords(m: MembershipView, counts: ReadonlyMap<string, InboxWorkspace>): string | null {
  if (m.status === "unconfirmed") return "Waiting for an owner or admin to confirm you"
  if (m.status === "suspended") return "Suspended: ask an owner or admin of this workspace to reinstate you"
  return countWords(m, counts)
}

// One workspace in a list: name, then slug, role and state, so two
// workspaces with one name never read as one.
export function membershipItem(m: MembershipView, counts: ReadonlyMap<string, InboxWorkspace> = new Map()): Html {
  const status = statusWords(m, counts)
  const main = html`<span class="main"><span class="title">${cardText(m.workspace.name)} <code class="slug">${m.workspace.slug}</code></span><span class="sub">${ROLE_WORDS[m.role]}${m.pendingRole !== null ? `, becoming ${ROLE_WORDS[m.pendingRole]}` : ""}${status !== null ? ` · ${status}` : ""}</span></span>`
  if (m.status !== "active") return html`<li class="membership muted">${icon("folder")}${main}</li>`
  return html`<li class="membership"><a href="${workspaceHref(m.workspace.slug)}">${icon("folder")}${main}${icon("chevronRight")}</a></li>`
}

export function restrictionNotice(session: AccountSession): Html {
  if (session.restricted !== null) {
    // A recovery that has not committed has no end date yet (null):
    // "Until recovery completes", never the pending sentinel as a year.
    const until = restrictionUntil(session.restricted.until, formatTime)
    return html`<section class="card shell-warn" data-region="account-restricted"><h2>Your account is cooling off</h2><p>${until.charAt(0).toUpperCase()}${until.slice(1)} you can read, deny, narrow and freeze in every workspace, but not approve or widen anything.</p></section>`
  }
  if (session.pendingTransition !== null) {
    return html`<section class="card shell-warn" data-region="account-pending"><h2>A security change is still reaching your workspaces</h2><p>Until it has, you can read, deny, narrow and freeze, but not approve or widen anything.</p></section>`
  }
  return html``
}

export function membershipList(session: AccountSession, origin: string, inbox: InboxResponse | null = null): Html {
  if (session.memberships.length === 0) return emptyState("users", "No workspaces yet", html`<a href="/workspaces">Your workspaces</a> says how to join or create one.`)
  const counts = new Map((inbox?.workspaces ?? []).map((w) => [w.workspace.id, w]))
  return html`<p class="muted">Workspaces at <span class="identity-origin">${origin}</span></p><ul class="list memberships">${session.memberships.map((m) => membershipItem(m, counts))}</ul>`
}

// Which of the picker's states the account is in:
// recovery first while nothing is open; then no membership, as an account
// that may create one or one that may not; then a single membership
// waiting to be confirmed; otherwise the list.
export type PickerState = "recovery" | "create-first" | "waiting" | "no-workspace" | "list"

export function pickerState(session: AccountSession): PickerState {
  const open = session.memberships.some((m) => m.status === "active")
  // Open workspaces stay open while recovery waits: only joining and
  // creating need it first, and the list's create link says so.
  if (!open && session.recoverySetupRequired) return "recovery"
  if (session.memberships.length === 0) return creationBlock(session) === null ? "create-first" : "no-workspace"
  // The waiting screen is for one membership, waiting: any other mix shows
  // the list, so no workspace or status is hidden behind the first.
  if (session.memberships.length === 1 && session.memberships[0]?.status === "unconfirmed") return "waiting"
  return "list"
}

function createFirst(): Html {
  return html`<section class="card narrow" data-region="create-first">
    <h2>Create your first workspace</h2>
    <p class="lead">A workspace holds your credentials, projects, machines and people. Give it a name and a short name for addresses and commands.</p>
    <form class="stack" data-form="workspace-create" novalidate>
      <label class="field"><span class="label">Name</span><input type="text" data-input="workspace-name" maxlength="64" required></label>
      <label class="field"><span class="label">Short name</span><input type="text" data-input="workspace-slug" maxlength="40" autocapitalize="off" spellcheck="false" placeholder="acme"><span class="hint">Lower case letters, digits and single dashes; three to forty characters.</span></label>
      <button type="submit" class="btn primary">${icon("passkey")}<span>Create with passkey</span></button>
    </form>
  </section>`
}

function noWorkspace(session: AccountSession): Html {
  return html`<section class="card narrow" data-region="no-workspace">
    <h2>You are not in a workspace yet</h2>
    <p class="lead">You join a workspace by invitation. ${session.workspaceCreation === "operator-denied" ? OPERATOR_DENIED_WORDS : "Ask a workspace owner to invite you, or ask the operator of this deployment to let your account create one."} Your account id:</p>
    ${copyBox(session.account)}
    <div class="actions"><a class="btn secondary" href="/account">Your account</a></div>
  </section>`
}

function recoveryFirst(): Html {
  return html`<section class="card narrow" data-region="recovery-first">
    <h2>Set up a way back in first</h2>
    <p class="lead">${RECOVERY_SETUP_WORDS}</p>
    <div class="actions"><a class="btn primary" href="/account/recovery">Set up recovery</a></div>
  </section>`
}

function pickerBody(state: PickerState, session: AccountSession, origin: string, inbox: InboxResponse | null): Html {
  switch (state) {
    case "recovery":
      return recoveryFirst()
    case "create-first":
      return createFirst()
    case "no-workspace":
      return noWorkspace(session)
    case "waiting":
      return confirmationWaiting(session.memberships.find((m) => m.status === "unconfirmed")?.workspace.name ?? "")
    case "list":
      return html`<section class="card">${membershipList(session, origin, inbox)}${createLink(session)}</section>`
  }
}

// /workspaces: the account's workspaces, or, when there is none it can
// open, which first-run state it is in and the next step. `inbox` gives
// each workspace its count; null when it was not read.
export function pickerPage(account: AccountShell, session: AccountSession, origin: string, inbox: InboxResponse | null = null): PageInput {
  const state = pickerState(session)
  const waiting = state === "waiting" ? session.memberships.find((m) => m.status === "unconfirmed") : undefined
  return {
    title: "Your workspaces",
    viewer: null,
    account,
    current: "workspaces",
    boot: { page: "workspaces", state, ...(waiting !== undefined ? { waiting: waiting.workspace.slug } : {}) },
    body: html`${pageHead({ title: "Your workspaces", lead: state === "list" ? "Choose a workspace. Each one has its own people, projects, credentials and machines." : undefined })}
      ${restrictionNotice(session)}
      ${pickerBody(state, session, origin, inbox)}`,
  }
}

// Every /w/ address the account cannot open: an unknown workspace, another
// account's workspace and an unknown page all render these same bytes.
export function workspaceNotFoundPage(account: AccountShell): PageInput {
  return { title: WORKSPACE_NOT_FOUND_HEADING, viewer: null, account, boot: { page: "error" }, body: errorBody(NOT_FOUND_ERROR, WORKSPACE_NOT_FOUND_HEADING, 404) }
}
