// The account setup pages with workspaces on: /signup (joining from an
// invitation), /account/recovery and /workspaces/new, the account page's
// cards and its fallback when GET /api/account cannot answer. routes/ui.ts dispatches
// them; the account shell comes from there, so this module needs nothing
// of it at load time.

import type { AccountSessionsRead, ApiError, PasskeyView, RecoveryStatus, StepUpGraceRead } from "@mehen/protocol/api"
import type { AccountSession } from "@mehen/protocol/workspace"
import type { OperatorInvitationRead } from "@mehen/protocol/operator-proposals"
import { CONSOLE_ROUTES } from "@mehen/protocol/platform-console"
import { type AccountWebSession, currentAccountSession } from "../directory/account-session.ts"
import { type PageInput, errorPage, pageResponse, redirect } from "../ui/layout.ts"
import { type Loaded, apiGet } from "../ui/load.ts"
import { accountRecoveryPage, workspaceCreatePage, workspaceSignupPage } from "../ui/pages/account-setup.ts"
import { type AccountCards, type AccountSecurityStatus, accountPage, accountStatusPage } from "../ui/pages/account.ts"
import type { AccountShell } from "../ui/shell.ts"
import type { RequestContext } from "./context.ts"

export const ACCOUNT_STATUS_READ = "/api/account/security-transition"

type ShellFor = (account: AccountWebSession) => Promise<AccountShell>

function signinRedirect(rc: RequestContext): Response {
  return redirect(`/signin?next=${encodeURIComponent(rc.url.pathname + rc.url.search)}`)
}

// /signup: a new account from the invitation, or, already signed in, joining
// it with this account. Recovery readiness comes from the directory's own
// status read, so the page asks for setup only when the vault would.
export async function workspaceSignup(rc: RequestContext): Promise<Response> {
  const account = await currentAccountSession(rc.request, rc.env)
  if (!account) {
    const firstAccount = (await rc.env.DB.prepare("SELECT 1 AS found FROM accounts LIMIT 1").first()) === null
    return pageResponse(workspaceSignupPage({ signedIn: false, recoveryReady: false, firstAccount }))
  }
  const status = await apiGet<AccountSecurityStatus>(rc, ACCOUNT_STATUS_READ)
  return pageResponse(workspaceSignupPage({ signedIn: true, recoveryReady: status.ok && !status.value.recoverySetupRequired }))
}

export async function accountRecovery(rc: RequestContext, shellFor: ShellFor): Promise<Response> {
  const account = await currentAccountSession(rc.request, rc.env)
  if (!account) return signinRedirect(rc)
  const [recovery, status] = await Promise.all([apiGet<RecoveryStatus>(rc, "/api/account/recovery"), apiGet<AccountSecurityStatus>(rc, ACCOUNT_STATUS_READ)])
  if (!recovery.ok) return errorPage(null, recovery.status, recovery.error)
  return pageResponse(accountRecoveryPage(await shellFor(account), recovery.value, !status.ok || status.value.recoverySetupRequired))
}

export async function workspaceCreate(rc: RequestContext, shellFor: ShellFor): Promise<Response> {
  const account = await currentAccountSession(rc.request, rc.env)
  if (!account) return signinRedirect(rc)
  const session = await apiGet<AccountSession>(rc, "/api/account")
  if (!session.ok) return errorPage(null, session.status, session.error)
  return pageResponse(workspaceCreatePage(await shellFor(account), session.value))
}

// GET /api/account failed for a signed-in account (a workspace out of
// reach): the account page shows the directory's own status instead.
export async function accountFallback(rc: RequestContext, account: AccountShell, error: ApiError, status: number): Promise<Response> {
  const read = await apiGet<AccountSecurityStatus>(rc, ACCOUNT_STATUS_READ)
  if (!read.ok) return errorPage(null, status, error)
  return pageResponse(accountStatusPage(account, read.value, error), status)
}

function listed<T, K extends string>(loaded: Loaded<Record<K, T[]>>, key: K): Loaded<T[]> {
  return loaded.ok ? { ok: true, value: loaded.value[key] } : loaded
}

// /account's render with its cards: passkeys, sessions, recovery, an
// operator role waiting to be accepted and this browser's passkey grace, from their own account reads, in
// parallel, each shown as failed on its own.
// The account read and its fallback stay routes/ui.ts's.
export async function accountPageWithCards(rc: RequestContext): Promise<(account: AccountShell, session: AccountSession, origin: string) => PageInput> {
  const [passkeys, sessions, recovery, invitation, grace] = await Promise.all([
    apiGet<{ passkeys: PasskeyView[] }>(rc, "/api/account/passkeys"),
    apiGet<AccountSessionsRead>(rc, "/api/account/sessions"),
    apiGet<RecoveryStatus>(rc, "/api/account/recovery"),
    apiGet<OperatorInvitationRead>(rc, CONSOLE_ROUTES.operatorInvitation),
    apiGet<StepUpGraceRead>(rc, "/api/account/stepup/grace"),
  ])
  const cards: AccountCards = { passkeys: listed(passkeys, "passkeys"), sessions: listed(sessions, "sessions"), mayEndOtherSessions: sessions.ok && sessions.value.mayEndOtherSessions, recovery, now: Date.now(), operatorInvitation: invitation.ok ? invitation.value.invitation : null, grace: grace.ok ? grace.value.grace : null }
  return (account, session, origin) => accountPage(account, session, origin, cards)
}
