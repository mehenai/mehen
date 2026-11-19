// The consoles' pages: the operator's (/operator, /operator/register,
// /operator/platforms/:slug, /operator/operators, /operator/workspaces,
// /operator/workspaces/:id, /operator/accounts, /operator/accounts/:id,
// /operator/audit and /operator/settings) and a platform admin's
// (/platforms, /platforms/:slug). Each reads the console's own GET routes
// (CONSOLE_ROUTES) with the visitor's cookie, so it sees exactly what the
// vault lets this account see, and is served only while those reads are.
// An account the vault refuses (not the operator, not an admin of that
// platform), anyone signed out, and any request that is not a browser's GET
// for a page get exactly what an address with no page gets (routes/ui.ts's
// notFoundOn, with the plain account shell): the consoles are invisible to
// everyone else. routes/ui.ts dispatches these and builds the account
// shell, whose links come from consoleLinks.

import { CONSOLE_ROUTES, type ConsoleAccess, type OperatorPlatformDetail, type OperatorPlatformList, type AdminPlatformDetail, type AdminPlatformList, type PlatformEventPage, PlatformEventQuerySchema } from "@mehen/protocol/platform-console"
import { type AccountWebSession, currentAccountSession } from "../directory/account-session.ts"
import { VaultError } from "../http.ts"
import { SESSION_ENDED_HEADING, errorPage, pageResponse, sessionEndedError } from "../ui/layout.ts"
import { type Loaded, accountReadServed, apiGet } from "../ui/load.ts"
import type { OperatorsView } from "@mehen/protocol/operator-proposals"
import { OPERATORS_PATH, operatorsPage } from "../ui/pages/operator-operators.ts"
import { ACCOUNTS_PATH, operatorAccountPage, operatorAccountsPage } from "../ui/pages/operator-accounts.ts"
import { ACCOUNT_ID, type OperatorAccountDetail, type OperatorAccountList, OperatorAccountListQuerySchema } from "@mehen/protocol"
import { type OperatorWorkspaceDetail, type OperatorWorkspaceList, OperatorWorkspaceQuerySchema } from "@mehen/protocol/operator-workspaces"
import { operatorWorkspacePage, operatorWorkspacesPage } from "../ui/pages/operator-workspaces.ts"
import { type OperatorAuditPage, type OperatorAuditQuery, operatorAuditQuery, operatorAuditSearch } from "@mehen/protocol/operator-audit"
import type { OperatorSettingsView } from "@mehen/protocol/operator-settings"
import { AUDIT_PATH, operatorAuditPage } from "../ui/pages/operator-audit.ts"
import { SETTINGS_PATH, operatorSettingsPage } from "../ui/pages/operator-settings.ts"
import { OPERATOR_PATH, OPERATOR_REGISTER_PATH, operatorListPage, operatorPlatformPage, operatorPlatformPath, operatorRegisterPage } from "../ui/pages/operator.ts"
import { PLATFORMS_PATH, adminListPage, adminPlatformPage, adminPlatformPath } from "../ui/pages/platform-admin.ts"
import type { AccountShell, ConsolePageKey } from "../ui/shell.ts"
import type { RequestContext } from "./context.ts"

// A route pattern with its :slug filled in.
function withSlug(pattern: string, slug: string): string {
  return pattern.replace(":slug", encodeURIComponent(slug))
}

// Each console's reads: its pages and its link are served only while every
// one of them is.
const CONSOLE_READS: Readonly<Record<ConsolePageKey, readonly string[]>> = {
  operator: [CONSOLE_ROUTES.access, CONSOLE_ROUTES.operatorPlatforms, withSlug(CONSOLE_ROUTES.operatorPlatform, "x"), withSlug(CONSOLE_ROUTES.operatorEvents, "x"), CONSOLE_ROUTES.operatorOperators, CONSOLE_ROUTES.operatorWorkspaces, CONSOLE_ROUTES.operatorWorkspace.replace(":id", "x"), CONSOLE_ROUTES.operatorAccounts, CONSOLE_ROUTES.operatorAccount.replace(":id", "acc_x"), CONSOLE_ROUTES.operatorAudit, CONSOLE_ROUTES.operatorSettings],
  platforms: [CONSOLE_ROUTES.access, CONSOLE_ROUTES.adminPlatforms, withSlug(CONSOLE_ROUTES.adminPlatform, "x"), withSlug(CONSOLE_ROUTES.adminEvents, "x")],
}

export function consoleServed(key: ConsolePageKey): boolean {
  return CONSOLE_READS[key].every(accountReadServed)
}

// The consoles this account may open, from GET /api/account/console: none
// while that read is not served or when it fails.
export async function consoleLinks(rc: RequestContext): Promise<ConsolePageKey[]> {
  if (!consoleServed("operator") && !consoleServed("platforms")) return []
  const loaded = await apiGet<ConsoleAccess>(rc, CONSOLE_ROUTES.access)
  if (!loaded.ok) return []
  return [...(loaded.value.operator ? (["operator"] as const) : []), ...(loaded.value.platforms.length > 0 ? (["platforms"] as const) : [])]
}

// The console's own page addresses.
export function inConsoleNamespace(path: string): boolean {
  return path === OPERATOR_PATH || path.startsWith(`${OPERATOR_PATH}/`) || path === PLATFORMS_PATH || path.startsWith(`${PLATFORMS_PATH}/`)
}

type ShellFor = (account: AccountWebSession) => Promise<AccountShell>
// What an address with no page answers: routes/ui.ts's notFoundOn.
type NotFound = () => Promise<Response>

// A slug as the address carries it: one segment, decoded once.
function slugOf(rest: string): string | null {
  if (rest === "" || rest.includes("/")) return null
  try {
    return decodeURIComponent(rest)
  } catch {
    return null
  }
}

// A refused or failed console read, as the page answers it: no session is
// the sign-in card; a refusal (the vault answers anyone not allowed with
// not_found) the not-found page; anything else the error page.
function refused(rc: RequestContext, notFound: NotFound, loaded: { status: number; error: Extract<Loaded<unknown>, { ok: false }>["error"] }): Promise<Response> | Response {
  if (loaded.error.error === "unauthenticated") return errorPage(null, 401, sessionEndedError(rc.url.pathname + rc.url.search), SESSION_ENDED_HEADING)
  if (loaded.error.error === "not_found" || loaded.error.error === "forbidden") return notFound()
  return errorPage(null, loaded.status, loaded.error)
}

// One page of events, from the page's own ?before=, and the address of the
// next; a cursor the schema refuses reads the newest page.
async function eventsFor(rc: RequestContext, route: string, page: string): Promise<{ events: PlatformEventPage | null; older: string | null }> {
  const query = PlatformEventQuerySchema.safeParse({ before: rc.url.searchParams.get("before") ?? undefined })
  const before = query.success ? query.data.before : undefined
  const loaded = await apiGet<PlatformEventPage>(rc, before !== undefined ? `${route}?before=${encodeURIComponent(before)}` : route)
  if (!loaded.ok) return { events: null, older: null }
  return { events: loaded.value, older: loaded.value.next !== null ? `${page}?before=${encodeURIComponent(loaded.value.next)}#events` : null }
}

// The shell is drawn only for a page served, so a refusal never reads the
// console links either.
type Draw = () => Promise<AccountShell>

async function operatorPage(rc: RequestContext, shell: Draw, notFound: NotFound, rest: string): Promise<Response> {
  if (rest === "" || rest === OPERATOR_REGISTER_PATH.slice(OPERATOR_PATH.length + 1)) {
    // The list read is the operator check on both: anyone else is refused it.
    const loaded = await apiGet<OperatorPlatformList>(rc, CONSOLE_ROUTES.operatorPlatforms)
    if (!loaded.ok) return refused(rc, notFound, loaded)
    return pageResponse(rest === "" ? operatorListPage(await shell(), loaded.value) : operatorRegisterPage(await shell(), loaded.value.platforms))
  }
  if (rest === OPERATORS_PATH.slice(OPERATOR_PATH.length + 1)) {
    // The operators read is the operator check: anyone else is refused it.
    const loaded = await apiGet<OperatorsView>(rc, CONSOLE_ROUTES.operatorOperators)
    if (!loaded.ok) return refused(rc, notFound, loaded)
    return pageResponse(operatorsPage(await shell(), loaded.value))
  }
  if (rest === "workspaces" || rest.startsWith("workspaces/")) return operatorWorkspacesPageFor(rc, shell, notFound, rest.slice("workspaces".length))
  const accounts = ACCOUNTS_PATH.slice(OPERATOR_PATH.length + 1)
  if (rest === accounts || rest.startsWith(`${accounts}/`)) return accountsPage(rc, shell, notFound, rest === accounts ? null : rest.slice(accounts.length + 1))
  if (rest === AUDIT_PATH.slice(OPERATOR_PATH.length + 1)) return auditPage(rc, shell, notFound)
  if (rest === SETTINGS_PATH.slice(OPERATOR_PATH.length + 1)) {
    // The settings read is the operator check: anyone else is refused it.
    const loaded = await apiGet<OperatorSettingsView>(rc, CONSOLE_ROUTES.operatorSettings)
    if (!loaded.ok) return refused(rc, notFound, loaded)
    return pageResponse(operatorSettingsPage(await shell(), loaded.value))
  }
  const slug = rest.startsWith("platforms/") ? slugOf(rest.slice("platforms/".length)) : null
  if (slug === null) return notFound()
  const [loaded, events] = await Promise.all([
    apiGet<OperatorPlatformDetail>(rc, withSlug(CONSOLE_ROUTES.operatorPlatform, slug)),
    eventsFor(rc, withSlug(CONSOLE_ROUTES.operatorEvents, slug), operatorPlatformPath(slug)),
  ])
  if (!loaded.ok) return refused(rc, notFound, loaded)
  return pageResponse(operatorPlatformPage(await shell(), { platform: loaded.value, ...events, now: Date.now() }))
}

// The Workspaces view: its list, with the page's own search, filter and
// cursor (one the schema refuses reads the newest page of every workspace),
// or one workspace. Each read is the operator check.
async function operatorWorkspacesPageFor(rc: RequestContext, shell: Draw, notFound: NotFound, rest: string): Promise<Response> {
  if (rest === "") {
    const raw: Record<string, string> = {}
    for (const key of ["q", "filter", "before"]) {
      const value = rc.url.searchParams.get(key)
      if (value) raw[key] = value
    }
    const params = new URLSearchParams(OperatorWorkspaceQuerySchema.safeParse(raw).success ? raw : {})
    const loaded = await apiGet<OperatorWorkspaceList>(rc, params.size > 0 ? `${CONSOLE_ROUTES.operatorWorkspaces}?${params}` : CONSOLE_ROUTES.operatorWorkspaces)
    return loaded.ok ? pageResponse(operatorWorkspacesPage(await shell(), loaded.value)) : refused(rc, notFound, loaded)
  }
  const id = rest.startsWith("/") ? slugOf(rest.slice(1)) : null
  if (id === null) return notFound()
  const loaded = await apiGet<OperatorWorkspaceDetail>(rc, CONSOLE_ROUTES.operatorWorkspace.replace(":id", encodeURIComponent(id)))
  return loaded.ok ? pageResponse(operatorWorkspacePage(await shell(), loaded.value)) : refused(rc, notFound, loaded)
}

// The accounts list, with the page's own search, filter and cursor, or one
// account (`id`); each read is the operator check.
async function accountsPage(rc: RequestContext, shell: Draw, notFound: NotFound, id: string | null): Promise<Response> {
  if (id === null) {
    const query = OperatorAccountListQuerySchema.safeParse(Object.fromEntries(rc.url.searchParams))
    const read = query.success ? query.data : { filter: "all" as const }
    const params = new URLSearchParams()
    if (read.q !== undefined && read.q !== "") params.set("q", read.q)
    if (read.filter !== "all") params.set("filter", read.filter)
    if (query.success && query.data.before !== undefined) params.set("before", query.data.before)
    const loaded = await apiGet<OperatorAccountList>(rc, params.size > 0 ? `${CONSOLE_ROUTES.operatorAccounts}?${params.toString()}` : CONSOLE_ROUTES.operatorAccounts)
    if (!loaded.ok) return refused(rc, notFound, loaded)
    return pageResponse(operatorAccountsPage(await shell(), { list: loaded.value, q: read.q ?? "", filter: read.filter }))
  }
  const account = slugOf(id)
  if (account === null || !ACCOUNT_ID.test(account)) return notFound()
  const loaded = await apiGet<OperatorAccountDetail>(rc, CONSOLE_ROUTES.operatorAccount.replace(":id", encodeURIComponent(account)))
  if (!loaded.ok) return refused(rc, notFound, loaded)
  return pageResponse(operatorAccountPage(await shell(), loaded.value))
}

// The Audit view, with the address's own filters. Filters the view does
// not take read nothing but the operator check, and say so.
async function auditPage(rc: RequestContext, shell: Draw, notFound: NotFound): Promise<Response> {
  const parsed = operatorAuditQuery(rc.url.searchParams)
  const query: OperatorAuditQuery = parsed.ok ? parsed.query : {}
  const loaded = await apiGet<OperatorAuditPage>(rc, `${CONSOLE_ROUTES.operatorAudit}${operatorAuditSearch(query, query.before)}`)
  if (!loaded.ok) return refused(rc, notFound, loaded)
  return pageResponse(operatorAuditPage(await shell(), { page: parsed.ok ? loaded.value : null, query: parsed.ok ? parsed.query : null }))
}

async function adminPage(rc: RequestContext, shell: Draw, notFound: NotFound, rest: string): Promise<Response> {
  if (rest === "") {
    const loaded = await apiGet<AdminPlatformList>(rc, CONSOLE_ROUTES.adminPlatforms)
    return loaded.ok ? pageResponse(adminListPage(await shell(), loaded.value)) : refused(rc, notFound, loaded)
  }
  const slug = slugOf(rest)
  if (slug === null) return notFound()
  const [loaded, events] = await Promise.all([
    apiGet<AdminPlatformDetail>(rc, withSlug(CONSOLE_ROUTES.adminPlatform, slug)),
    eventsFor(rc, withSlug(CONSOLE_ROUTES.adminEvents, slug), adminPlatformPath(slug)),
  ])
  if (!loaded.ok) return refused(rc, notFound, loaded)
  return pageResponse(adminPlatformPage(await shell(), { platform: loaded.value, ...events }))
}

function wantsPage(rc: RequestContext): boolean {
  return (rc.request.method === "GET" || rc.request.method === "HEAD") && (rc.request.headers.get("accept") ?? "").includes("text/html")
}

// Every method, before routes/ui.ts refuses any. A request that is not a
// browser's GET for a page, or one signed out, gets what an unknown address
// gets: the JSON not_found, or the not-found page.
export async function consolePage(rc: RequestContext, shellFor: ShellFor, notFoundOn: (rc: RequestContext) => Promise<Response>): Promise<Response> {
  if (!wantsPage(rc)) throw new VaultError("not_found", "No such route.")
  const notFound = () => notFoundOn(rc)
  const account = await currentAccountSession(rc.request, rc.env)
  if (!account) return notFound()
  const path = rc.url.pathname
  const operator = path === OPERATOR_PATH || path.startsWith(`${OPERATOR_PATH}/`)
  if (!consoleServed(operator ? "operator" : "platforms")) return notFound()
  const base = operator ? OPERATOR_PATH : PLATFORMS_PATH
  const rest = path === base ? "" : path.slice(base.length + 1)
  const shell = () => shellFor(account)
  return operator ? operatorPage(rc, shell, notFound, rest) : adminPage(rc, shell, notFound, rest)
}
