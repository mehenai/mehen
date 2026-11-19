// Human pages use account sessions and canonical workspace routing only.
import type { InboxResponse, WorkspaceInboxResponse } from "@mehen/protocol/inbox"
import type { AccountSession, ApprovalGroupView, WorkspaceDeviceView, WorkspaceItemSummary, WorkspaceMemberView, WorkspaceProject, WorkspaceSettingsView } from "@mehen/protocol/workspace"
import type { WorkspaceInviteView } from "../vault/areas/workspace-runtime.ts"
import type { PostureNudge } from "../vault/areas/postures-workspace.ts"
import type { Env } from "../env.ts"
import { VaultError, errorResponse } from "../http.ts"
import { type AccountWebSession, currentAccountSession } from "../directory/account-session.ts"
import { accountRecoveryCeremony } from "../directory/workspace-recovery.ts"
import { retryAccountSecurityIfDue } from "../directory/account-security.ts"
import { emailInvitesCompletable } from "../directory/invite-email.ts"
import { type Route, matchPath } from "../router.ts"
import { withPageReads } from "../page-reads.ts"
import { NOT_FOUND_ERROR, type PageInput, SESSION_ENDED_HEADING, type Viewer, errorPage, errorPageInput, pageResponse, redirect, sessionEndedError } from "../ui/layout.ts"
import { type Loaded, accountReadServed, apiGet, workspaceApiGet, workspaceReadServed } from "../ui/load.ts"
import { recoverPage, recoverPasskeyPage, signinPage } from "../ui/pages/account.ts"
import { recoverPendingPage } from "../ui/pages/account-setup.ts"
import { type HomeData, pickerPage, workspaceHomePage, workspaceNotFoundPage } from "../ui/pages/workspaces.ts"
import { needsYouPage } from "../ui/pages/needs-you.ts"
import { workspacePendingPage } from "../ui/pages/workspace-pending.ts"
import { workspaceReviewPage } from "../ui/pages/workspace-review.ts"
import { approvalGroupEtag } from "./approvals-workspace.ts"
import { NEEDS_YOU_API, NEEDS_YOU_PATH } from "../ui/client/pages/needs-you-logic.ts"
import { inboxEtag } from "../directory/account-inbox.ts"
import { INBOX_GROUP_ID } from "../vault/areas/pending-workspace.ts"
import { type AccountPageKey, type AccountShell, CONSOLE_PAGES, type ConsolePageKey, type WorkspacePageKey, type WorkspaceShell, workspaceHref } from "../ui/shell.ts"
import { safeNext } from "../ui/wording.ts"
import { type Handler, type RequestContext, type WorkspaceRequest, resolveWorkspace } from "./context.ts"
import { PALETTE_READS } from "../ui/client/palette-logic.ts"
import { PEOPLE_PAGES } from "./ui-people.ts"
import { accountFallback, accountPageWithCards, accountRecovery, workspaceCreate, workspaceSignup } from "./ui-account.ts"
import { WORKSPACE_PROJECT_PAGES, viewerOf } from "./ui-projects.ts"
import { SETTINGS_PAGES } from "./ui-settings.ts"
import { MANDATE_PAGES } from "./ui-mandates.ts"
import { activeMandateMachines, resumeMandateMachines } from "../ui/pages/mandates.ts"
import { mandatesOn } from "../vault/areas/mandates-workspace.ts"
import type { MandateList } from "@mehen/protocol/mandate-terms"
import { consoleLinks, consolePage, consoleServed, inConsoleNamespace } from "./ui-operator.ts"

function signinRedirect(rc: RequestContext): Response { return redirect(`/signin?next=${encodeURIComponent(rc.url.pathname + rc.url.search)}`) }
function signinNeeded(rc: RequestContext): Response { return errorPage(null, 401, sessionEndedError(rc.url.pathname + rc.url.search), SESSION_ENDED_HEADING) }

// ---------------------------------------------------------------- workspace shell

// The account read every account page, the landing and the switcher's
// other workspaces need. Until it is served they are not.
export const ACCOUNT_READ = "/api/account"

const ACCOUNT_PAGE_READS: Readonly<Record<Exclude<AccountPageKey, ConsolePageKey>, readonly string[]>> = { workspaces: [ACCOUNT_READ], "needs-you": [NEEDS_YOU_API], account: [ACCOUNT_READ] }

// The account pages every account has, then the consoles `consoles` names
// (the ones this account may open), each while its reads are served.
export function servedAccountPages(consoles: readonly ConsolePageKey[] = []): AccountPageKey[] {
  const base = (Object.keys(ACCOUNT_PAGE_READS) as Exclude<AccountPageKey, ConsolePageKey>[]).filter((key) => ACCOUNT_PAGE_READS[key].every(accountReadServed))
  return [...base, ...CONSOLE_PAGES.filter((key) => consoles.includes(key) && consoleServed(key))]
}

function accountShell(env: Env, account: AccountWebSession, consoles: readonly ConsolePageKey[] = []): AccountShell {
  return { origin: env.VAULT_ORIGIN, account: account.account, name: account.name, accountPages: servedAccountPages(consoles) }
}

// The shell an account page draws, with the console links this account
// may follow: the not-found pages keep the plain shell and its one read.
async function accountShellWithConsoles(rc: RequestContext, account: AccountWebSession): Promise<AccountShell> {
  return accountShell(rc.env, account, await consoleLinks(rc))
}

async function loadAccount(rc: RequestContext): Promise<AccountSession | null> {
  if (!accountReadServed(ACCOUNT_READ)) return null
  const loaded = await apiGet<AccountSession>(rc, ACCOUNT_READ)
  return loaded.ok ? loaded.value : null
}

function workspaceNotFound(env: Env, account: AccountWebSession): Response {
  return pageResponse(workspaceNotFoundPage(accountShell(env, account)), 404)
}

// No such page, with workspaces on: the account's not-found page, or the
// signed-out one. Nothing here reads the legacy member tables.
async function notFoundOn(rc: RequestContext): Promise<Response> {
  if (!(rc.request.headers.get("accept") ?? "").includes("text/html")) throw new VaultError("not_found", "No such route.")
  const account = await currentAccountSession(rc.request, rc.env)
  return account ? workspaceNotFound(rc.env, account) : errorPage(null, 404, NOT_FOUND_ERROR)
}

export type WorkspacePageContext = { workspace: WorkspaceRequest; shell: WorkspaceShell }

// A page under /w/:ws. `reads` are the workspace reads it needs, relative to
// the prefix ("" is the workspace's identity); it is served only while
// every one of them is, so a page never goes live before its route merges.
// `on`, where given, is a per-workspace switch: while it says no, the page is
// not found and the shell does not link to it.
export type WorkspacePage = { key: WorkspacePageKey; path: string; reads: readonly string[]; on?: (env: Env, workspace: string) => boolean; render: (rc: RequestContext, page: WorkspacePageContext) => Promise<Response> }

// The home's reads: this workspace's
// inbox and the lists its cards count. /members, /invites and /settings
// are read only for whoever the vault lets read them, and never gate it.
// The home is served on its identity alone; its cards appear once every
// one of these reads is served, so a build without them
// shows who and where, and nothing that needs a read it lacks.
export const HOME_READS = ["", "/inbox", "/devices", "/items", "/projects"] as const

function settled<T>(loaded: Loaded<T>): T | null {
  return loaded.ok ? loaded.value : null
}

async function homePage(rc: RequestContext, page: WorkspacePageContext): Promise<Response> {
  if (!HOME_READS.every(workspaceReadServed)) return pageResponse(workspaceHomePage(page.shell))
  const viewer = viewerOf(page)
  const read = <T,>(path: string) => workspaceApiGet<T>(rc, page.workspace, path)
  const skip = Promise.resolve(null)
  const insider = viewer.role !== "guest"
  const elevated = viewer.role === "owner" || viewer.role === "admin"
  const mandates = mandatesOn(rc.env, page.workspace.workspace.id) && workspaceReadServed("/mandates")
  const [inbox, devices, items, projects, members, invites, settings, nudges, mandateList] = await Promise.all([
    read<WorkspaceInboxResponse>("/inbox"),
    read<{ devices: WorkspaceDeviceView[] }>("/devices"),
    read<{ items: WorkspaceItemSummary[] }>("/items"),
    read<{ projects: WorkspaceProject[] }>("/projects"),
    insider && workspaceReadServed("/members") ? read<WorkspaceMemberView[]>("/members") : skip,
    elevated && workspaceReadServed("/invites") ? read<{ invites: WorkspaceInviteView[] }>("/invites") : skip,
    insider && workspaceReadServed("/settings") ? read<WorkspaceSettingsView>("/settings") : skip,
    // A guest may never set a credential to routine, so is never nudged.
    insider && workspaceReadServed("/nudges") ? read<{ nudges: PostureNudge[] }>("/nudges") : skip,
    mandates ? read<MandateList>("/mandates") : skip,
  ])
  for (const loaded of [inbox, devices, items, projects]) if (!loaded.ok && loaded.error.error === "unauthenticated") return signinRedirect(rc)
  const data: HomeData = {
    viewer,
    inbox: settled(inbox),
    devices: settled(devices)?.devices ?? null,
    items: settled(items)?.items ?? null,
    projects: settled(projects)?.projects ?? null,
    members: members !== null ? settled(members) : null,
    invites: invites !== null ? (settled(invites)?.invites ?? null) : null,
    settings: settings !== null ? settled(settings) : null,
    now: Date.now(),
    nudges: nudges !== null ? (settled(nudges)?.nudges ?? null) : null,
    mandateMachines: mandateList !== null ? activeMandateMachines(settled(mandateList)) : null,
    mandateResume: mandateList !== null ? resumeMandateMachines(settled(mandateList)) : null,
    emailInvites: emailInvitesCompletable(rc.env),
  }
  return pageResponse(workspaceHomePage(page.shell, data))
}

// /w/:ws/pending, the one-workspace filter of Needs you.
async function pendingPage(rc: RequestContext, page: WorkspacePageContext): Promise<Response> {
  const loaded = await workspaceApiGet<WorkspaceInboxResponse>(rc, page.workspace, "/inbox")
  if (!loaded.ok) return loaded.error.error === "unauthenticated" ? signinRedirect(rc) : pageResponse({ ...errorPageInput(null, loaded.status, loaded.error), workspace: page.shell }, loaded.status)
  return pageResponse(workspacePendingPage(page.shell, { viewer: viewerOf(page), inbox: loaded.value, now: Date.now() }))
}

// /w/:ws/g/:id, Review together, where a review group's (or bundle's) inbox
// row leads. A group with nothing this viewer may see reads as an empty
// one. Not found wherever the workspace refuses the group read (batch
// approvals off, or a managed workspace, which the vault refuses as
// forbidden), and for anything that is not a group's id.
async function groupPage(rc: RequestContext, page: WorkspacePageContext): Promise<Response> {
  const id = rc.params.id ?? ""
  if (!INBOX_GROUP_ID.test(id)) return workspaceNotFound(rc.env, page.workspace.account)
  const loaded = await workspaceApiGet<ApprovalGroupView>(rc, page.workspace, `/approvals/groups/${encodeURIComponent(id)}`)
  if (!loaded.ok && loaded.error.error === "not_found") return pageResponse(workspaceReviewPage(page.shell, { viewer: viewerOf(page), group: id, view: null }))
  if (!loaded.ok && loaded.error.error === "forbidden") return workspaceNotFound(rc.env, page.workspace.account)
  if (!loaded.ok) return loaded.error.error === "unauthenticated" ? signinRedirect(rc) : pageResponse({ ...errorPageInput(null, loaded.status, loaded.error), workspace: page.shell }, loaded.status)
  return pageResponse(workspaceReviewPage(page.shell, { viewer: viewerOf(page), group: id, view: loaded.value, etag: await approvalGroupEtag(loaded.value) }))
}

export const WORKSPACE_PAGES: WorkspacePage[] = [
  { key: "home", path: "/", reads: [""], render: homePage },
  { key: "needs", path: "/pending", reads: ["/inbox"], render: (rc, page) => pendingPage(rc, page) },
  { key: "needs", path: "/g/:id", reads: ["/approvals/groups/:id"], render: groupPage },
  ...PEOPLE_PAGES,
  ...WORKSPACE_PROJECT_PAGES,
  ...SETTINGS_PAGES,
  ...MANDATE_PAGES,
]

function pageServed(page: WorkspacePage, env: Env, workspace: string): boolean {
  return page.reads.every(workspaceReadServed) && (page.on?.(env, workspace) ?? true)
}

export function servedWorkspacePages(env: Env, workspace: string): WorkspacePageKey[] {
  return [...new Set(WORKSPACE_PAGES.filter((page) => pageServed(page, env, workspace)).map((p) => p.key))]
}

async function workspaceShell(rc: RequestContext, workspace: WorkspaceRequest): Promise<WorkspaceShell> {
  const [session, consoles] = await Promise.all([loadAccount(rc), consoleLinks(rc)])
  return {
    identity: { origin: rc.env.VAULT_ORIGIN, account: workspace.account.account, workspace: workspace.workspace },
    accountName: workspace.account.name,
    memberships: session?.memberships ?? null,
    pages: servedWorkspacePages(rc.env, workspace.workspace.id),
    reads: PALETTE_READS.filter(workspaceReadServed),
    accountPages: servedAccountPages(consoles),
    accountHeld: session === null || session.restricted !== null || session.pendingTransition !== null,
  }
}

// Every /w/ page goes through here: the switch, the account's session, the
// resolver (an unknown workspace and another account's answer the same
// not-found page), the page itself, and then the canonical slug, so an old
// alias or a bare /w/<slug> lands on /w/<canonical>/... before anything is
// shown.
function workspacePage(page: WorkspacePage | null): Handler {
  return async (rc) => {
    const account = await currentAccountSession(rc.request, rc.env)
    if (!account) return signinRedirect(rc)
    let workspace: WorkspaceRequest
    try {
      workspace = await resolveWorkspace(rc)
    } catch (error) {
      if (error instanceof VaultError && error.code === "not_found") return workspaceNotFound(rc.env, account)
      if (error instanceof VaultError && error.code === "unauthenticated") return signinRedirect(rc)
      throw error
    }
    if (page === null || !pageServed(page, rc.env, workspace.workspace.id)) return workspaceNotFound(rc.env, account)
    // What follows /w/<ws> as the browser sent it; empty for a bare /w/<ws>.
    const rest = rc.url.pathname.slice(`/w/${rc.url.pathname.split("/")[2] ?? ""}`.length)
    if (rc.params.ws !== workspace.workspace.slug || rest === "") {
      return redirect(`${workspaceHref(workspace.workspace.slug, rest === "" ? "/" : rest)}${rc.url.search}`)
    }
    return page.render(rc, { workspace, shell: await workspaceShell(rc, workspace) })
  }
}

// The whole page namespace the workspace shell owns: /w at any depth, and
// the account pages. Handled before the route table, so an address no
// pattern could match (a trailing slash, five segments, a bad escape) still
// gets the one not-found page. The Worker checks the fresh-start guard first.
function inShellNamespace(path: string): boolean {
  return path === "/w" || path.startsWith("/w/") || path === "/workspaces" || path === "/account" || path === "/workspaces/new" || path === "/account/recovery" || path === NEEDS_YOU_PATH || inConsoleNamespace(path)
}

const NOT_ALLOWED = { error: "bad_request" as const, message: "Method not allowed." }

export async function workspacePagePrefix(rc: RequestContext): Promise<Response | null> {
  if (!inShellNamespace(rc.url.pathname)) return null
  return withPageReads(rc.request, () => shellPage(rc))
}

async function shellPage(rc: RequestContext): Promise<Response> {
  const path = rc.url.pathname
  // The consoles answer every method as an unknown address would.
  if (inConsoleNamespace(path)) return consolePage(rc, (a) => accountShellWithConsoles(rc, a), notFoundOn)
  if (rc.request.method !== "GET" && rc.request.method !== "HEAD") return errorResponse(NOT_ALLOWED, 405)
  if (path === "/workspaces") return pickerRoute(rc)
  if (path === NEEDS_YOU_PATH) return needsYouRoute(rc)
  if (path === "/account") return accountPageRoute("account", await accountPageWithCards(rc))(rc)
  if (path === "/account/recovery") return servedAccountPages().includes("account") ? accountRecovery(rc, (a) => accountShellWithConsoles(rc, a)) : notFoundOn(rc)
  if (path === "/workspaces/new") return servedAccountPages().includes("workspaces") ? workspaceCreate(rc, (a) => accountShellWithConsoles(rc, a)) : notFoundOn(rc)
  // /w/<ws><rest>: the slug as sent, decoded once; a bad escape or an empty
  // slug is just a workspace nobody has.
  const raw = path.split("/")[2] ?? ""
  let ws = ""
  try {
    ws = decodeURIComponent(raw)
  } catch {
    ws = ""
  }
  const rest = path.slice(`/w/${raw}`.length)
  let page: WorkspacePage | null = null
  let params: Record<string, string> = {}
  if (ws !== "") {
    for (const candidate of WORKSPACE_PAGES) {
      const found = matchPath(candidate.path, rest === "" ? "/" : rest)
      if (found !== null && (rest !== "" || candidate.path === "/")) {
        page = candidate
        params = found
        break
      }
    }
  }
  return workspacePage(page)({ ...rc, params: { ...params, ws } })
}

// The account inbox as a page reads it, through GET /api/needs-you with the
// visitor's cookie; null while that route is not served or when it fails.
async function loadInbox(rc: RequestContext): Promise<Loaded<InboxResponse> | null> {
  if (!servedAccountPages().includes("needs-you")) return null
  return apiGet<InboxResponse>(rc, NEEDS_YOU_API)
}

// Where an account goes with no workspace in the address: to Needs you
// when anything waits for it, else straight into its one workspace when it
// has exactly one it can open, else the picker. The inbox read keeps to its
// own deadline, so a stalled workspace cannot stall the landing.
async function landing(rc: RequestContext): Promise<Response> {
  const account = await currentAccountSession(rc.request, rc.env)
  if (!account) return signinRedirect(rc)
  const inbox = await loadInbox(rc)
  if (inbox?.ok && inbox.value.count > 0) return redirect(NEEDS_YOU_PATH)
  const session = await loadAccount(rc)
  const open = session?.memberships.filter((m) => m.status === "active") ?? []
  const only = open.length === 1 ? open[0] : undefined
  return redirect(only !== undefined ? workspaceHref(only.workspace.slug) : "/workspaces")
}

// With workspaces on, an old address with no workspace in it: a place
// (Home, Credentials, Machines, ...) goes to the landing, and an ask link
// (/a, /i, /c, /e, /p) is not found, because every ask now lives under its
// workspace and no old one survived the fresh start.
// An account page: reached only with workspaces on, served only while its
// read is.
function accountPageRoute(key: AccountPageKey, render: (account: AccountShell, session: AccountSession, origin: string) => PageInput): Handler {
  return async (rc) => {
    if (!servedAccountPages().includes(key)) return notFoundOn(rc)
    const account = await currentAccountSession(rc.request, rc.env)
    if (!account) return signinRedirect(rc)
    const loaded = await apiGet<AccountSession>(rc, ACCOUNT_READ)
    if (!loaded.ok) return loaded.error.error === "unauthenticated" ? signinNeeded(rc) : accountFallback(rc, accountShell(rc.env, account), loaded.error, loaded.status)
    return pageResponse({ current: "account", ...render(await accountShellWithConsoles(rc, account), loaded.value, rc.env.VAULT_ORIGIN) })
  }
}

// /workspaces: the picker, with each workspace's count from one inbox read.
async function pickerRoute(rc: RequestContext): Promise<Response> {
  if (!servedAccountPages().includes("workspaces")) return notFoundOn(rc)
  const account = await currentAccountSession(rc.request, rc.env)
  if (!account) return signinRedirect(rc)
  const [loaded, inbox] = await Promise.all([apiGet<AccountSession>(rc, ACCOUNT_READ), loadInbox(rc)])
  if (!loaded.ok) return loaded.error.error === "unauthenticated" ? signinNeeded(rc) : accountFallback(rc, accountShell(rc.env, account), loaded.error, loaded.status)
  return pageResponse(pickerPage(await accountShellWithConsoles(rc, account), loaded.value, rc.env.VAULT_ORIGIN, inbox?.ok ? inbox.value : null))
}

// /needs-you: the account inbox, drawn with the list it read and that
// list's validator, so the page's first poll asks only whether it changed.
async function needsYouRoute(rc: RequestContext): Promise<Response> {
  if (!servedAccountPages().includes("needs-you")) return notFoundOn(rc)
  const account = await currentAccountSession(rc.request, rc.env)
  if (!account) return signinRedirect(rc)
  const loaded = await apiGet<InboxResponse>(rc, NEEDS_YOU_API)
  if (!loaded.ok && loaded.error.error === "unauthenticated") return signinNeeded(rc)
  const shell = await accountShellWithConsoles(rc, account)
  return pageResponse(needsYouPage(shell, loaded.ok ? { ok: true, inbox: loaded.value, etag: await inboxEtag(loaded.value) } : { ok: false }, Date.now()))
}

// The docs are the account's, not a workspace's: with workspaces on they
// render in the account shell for any signed-in account.
// The docs moved to the public docs site. The old addresses answer a 301
// to the matching page there, signed in or not: operations and the plan are
// internal now, so they and anything unknown go to the docs home.
export const DOCS_SITE = "https://docs.mehen.dev"
export const DOCS_REDIRECTS: Readonly<Record<string, string>> = {
  overview: "/",
  concepts: "/concepts",
  "agent-guide": "/reference/cli",
  skill: "/skill",
  integrating: "/guides/harnesses",
  "threat-model": "/security/threat-model",
}

function docsRedirect(slug: string | null): Response {
  const path = slug !== null && Object.hasOwn(DOCS_REDIRECTS, slug) ? DOCS_REDIRECTS[slug] as string : "/"
  return redirect(`${DOCS_SITE}${path}`, 301)
}

export const uiRoutes: Route<Handler>[] = [
  { method: "GET", path: "/signin", handler: async rc => {
    const invite = rc.url.searchParams.get("invite")
    if (invite) return redirect(`/signup#${encodeURIComponent(invite)}`)
    const next = safeNext(rc.url.searchParams.get("next"))
    return await currentAccountSession(rc.request,rc.env) ? redirect(next) : pageResponse(signinPage(next,rc.env.VAULT_ORIGIN))
  } },
  { method: "GET", path: "/signup", handler: workspaceSignup },
  { method: "GET", path: "/recover", handler: async () => pageResponse(recoverPage(true)) },
  { method: "GET", path: "/recover/passkey", handler: async rc => {
    const ceremony = await accountRecoveryCeremony(rc.env,rc.request)
    if (ceremony.transition) rc.ctx.waitUntil(retryAccountSecurityIfDue(rc.env,ceremony.transition).catch(() => console.error(JSON.stringify({ at: "account.recovery.retry",transition: ceremony.transition }))))
    return pageResponse(ceremony.state === "pending" ? recoverPendingPage() : recoverPasskeyPage(ceremony.state === "live"))
  } },
  ...["/", "/credentials", "/connect", "/items/:slug", "/devices", "/audit", "/projects", "/projects/:id", "/settings", "/policy/overrides/:id", "/policy/grants/:id"].map(path => ({ method: "GET",path,handler: landing })),
  ...["/i/:id", "/e/:code", "/a/:id", "/p/:id", "/c/:id"].map(path => ({ method: "GET",path,handler: notFoundOn })),
  { method: "GET",path: "/docs",handler: async () => docsRedirect(null) },
  { method: "GET",path: "/docs/:slug",handler: async rc => docsRedirect(rc.params.slug ?? null) },
]
