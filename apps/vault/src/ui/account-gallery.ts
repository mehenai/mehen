// The account pages with fixture data, for scripts/ui-gallery.ts: the
// account page apart from every workspace, the page when a workspace's
// security state is out of reach, joining from an invitation step by step
// and waiting for confirmation, setting up recovery again, creating a workspace, and the recovery that is still
// reaching every workspace. The fixtures are the shell and people
// galleries' own. Nothing here is imported by the Worker.

import { Html } from "./html.ts"
import type { PageInput } from "./layout.ts"
import type { PasskeyView, SessionView } from "@mehen/protocol/api"
import { type AccountCards, accountPage, accountStatusPage } from "./pages/account.ts"
import { accountRecoveryPage, recoverPendingPage, workspaceCreatePage, workspaceSignupPage } from "./pages/account-setup.ts"
import { pickerPage } from "./pages/workspaces.ts"
import { PEOPLE_ORIGIN, PEOPLE_SESSION } from "./people-gallery.ts"
import { GALLERY_ACCOUNT_SHELL, GALLERY_ORIGIN, GALLERY_SESSION } from "./shell-gallery.ts"
import type { AccountShell } from "./shell.ts"

const NOW = Date.parse("2026-10-27T18:30:00Z")
const at = (minutes: number) => new Date(NOW + minutes * 60_000).toISOString()

export const ACCOUNT_PASSKEYS: PasskeyView[] = [
  { passkey: "pk_0a1b2c3d4e5f60718293", name: "MacBook Touch ID", authenticator: "This device's passkey", synced: true, addedVia: "signup", createdAt: "2026-10-12T09:14:00Z", lastUsedAt: at(-5), lastUsedClient: "Safari on Mac", lastUsedPlace: "Amsterdam, NL", current: true },
  { passkey: "pk_1b2c3d4e5f6071829304", name: null, authenticator: "A security key", synced: false, addedVia: "settings", createdAt: "2026-10-13T11:02:00Z", lastUsedAt: null, lastUsedClient: null, lastUsedPlace: null, current: false },
]
export const ACCOUNT_SESSIONS: SessionView[] = [
  { session: "ses_current01", kind: "web", method: "passkey", client: "Safari on Mac", place: "Amsterdam, NL", passkeyName: "MacBook Touch ID", createdAt: at(-60 * 26), lastSeenAt: at(-1), current: true },
  { session: "ses_phone01", kind: "app", method: "passkey", client: "Jeff on iPhone", place: "Amsterdam, NL", passkeyName: null, createdAt: at(-60 * 24 * 3), lastSeenAt: at(-45), current: false },
]
const ACCOUNT_CARDS: AccountCards = { passkeys: { ok: true, value: ACCOUNT_PASSKEYS }, sessions: { ok: true, value: ACCOUNT_SESSIONS }, mayEndOtherSessions: true, recovery: { ok: true, value: { active: { generatedAt: at(-60 * 24 * 14), total: 10, left: 9 } } }, now: NOW, grace: { until: at(12) } }
const CARD_FAILED = { ok: false as const, status: 503, error: { error: "upstream_failed" as const, message: "The vault is busy." } }

const ACCOUNT_SHELL: AccountShell = { origin: PEOPLE_ORIGIN, account: PEOPLE_SESSION.account, name: "Alex Rae", accountPages: ["workspaces", "account"] }

// The account pages' boot pages the gallery must show.
export const ACCOUNT_PAGES = ["account", "workspace-signup", "account-recovery", "workspace-create", "recover-pending"] as const

export type AccountGalleryEntry = { id: string; group: string; title: string; note: string; page: PageInput; reveal?: string[]; hide?: string[] }

// /signup as the browser leaves it at each step for Tom, invited to
// Northwind as a member: the names the client fills in, the step list's
// marks, and the one card it shows. `at` is the step's index in the list.
function signupAt(state: { signedIn: boolean; recoveryReady: boolean }, at: number, verified: boolean): PageInput {
  const page = workspaceSignupPage(state)
  let step = 0
  const body = page.body.value
    .replaceAll('data-fill="workspace-name"></', 'data-fill="workspace-name">Northwind</')
    .replace('data-fill="invite-role"></', 'data-fill="invite-role">a member</')
    .replace('data-fill="verified-email"></', 'data-fill="verified-email">tom@northwind.example</')
    .replace(/<li class="step">/g, () => {
      const mark = step < at ? " done" : step === at ? " current" : ""
      step += 1
      return `<li class="step${mark}">`
    })
    .replace('data-region="verified" hidden', verified ? 'data-region="verified"' : 'data-region="verified" hidden')
  return { ...page, body: new Html(body) }
}

function signupGallery(): AccountGalleryEntry[] {
  const signedOut = { signedIn: false, recoveryReady: false }
  const group = "Account setup"
  return [
    { id: "signup-step-1", group, title: "Joining: 1 verify your email", note: "A bound invitation, peeked: the workspace and role named, never the email. Google proves the address before any passkey exists.", page: signupAt(signedOut, 0, false), reveal: ["signup-invite", "signup-verify"] },
    { id: "signup-step-1-lapsed", group, title: "Joining: Google check lapsed", note: "The proof lasts ten minutes; past that, or refused, the page asks again instead of a wall.", page: signupAt({ signedIn: true, recoveryReady: true }, 0, false), reveal: ["signup-invite", "signup-verify", "verify-lapsed"], hide: ["verify-lead"] },
    { id: "signup-step-1-email", group, title: "Joining: 1 verify with an emailed code", note: "Beside Google: a six-digit code sent to the invited address, never shown, typed back here.", page: signupAt(signedOut, 0, false), reveal: ["signup-invite", "signup-verify", "email-code", "email-code-sent"], hide: ["email-code-start"] },
    { id: "signup-step-1-email-failed", group, title: "Joining: the code could not be sent", note: "Email Sending refused: the page says so and Google is still there to press.", page: signupAt(signedOut, 0, false), reveal: ["signup-invite", "signup-verify", "email-code", "email-code-failed"] },
    { id: "signup-step-1-google-only", group, title: "Joining: only Google, under the identity rule", note: "The invited role falls under the workspace's Google Workspace rule, which an emailed code cannot satisfy.", page: signupAt(signedOut, 0, false), reveal: ["signup-invite", "signup-verify", "email-code-google-only"] },
    { id: "signup-step-2", group, title: "Joining: 2 create your passkey", note: "Back from Google on the same page, the proof named.", page: signupAt(signedOut, 1, true), reveal: ["signup-invite", "signup-passkey"] },
    { id: "signup-step-3", group, title: "Joining: 3 set up recovery", note: "Saving codes is the primary; a second passkey the quiet alternative.", page: signupAt({ signedIn: true, recoveryReady: false }, 2, true), reveal: ["signup-invite", "signup-recovery"] },
    { id: "signup-step-4", group, title: "Joining: 4 join", note: "Automatic once recovery is ready.", page: signupAt({ signedIn: true, recoveryReady: true }, 3, true), reveal: ["signup-invite", "signup-join"] },
    { id: "signup-waiting", group, title: "Joining: waiting for confirmation", note: "Polls every ten seconds; the copy box is the message for whoever invited them.", page: signupAt({ signedIn: true, recoveryReady: true }, 4, true), reveal: ["signup-invite", "signup-waiting"] },
    { id: "signup-waiting-retrying", group, title: "Joining: waiting, a check failed", note: "A failed check is said once and retried; nothing else changes.", page: signupAt({ signedIn: true, recoveryReady: true }, 4, true), reveal: ["signup-invite", "signup-waiting", "confirm-retrying"] },
    { id: "signup-waiting-ended", group, title: "Joining: waiting, session ended", note: "Signed out elsewhere or every session ended: the poll stops and links to sign in.", page: signupAt({ signedIn: true, recoveryReady: true }, 4, true), reveal: ["signup-invite", "signup-waiting", "confirm-ended"] },
    { id: "signup-first-run", group, title: "Joining: a new vault's owner", note: "Signed out on a vault with no account yet: the bootstrap code, so the page welcomes its owner.", page: workspaceSignupPage({ ...signedOut, firstAccount: true }), reveal: ["signup-plain", "signup-passkey"] },
    { id: "signup-bootstrap", group, title: "Joining: no invitation to name", note: "Signed out with a code that is no live invitation: the deployment's bootstrap code, or a dead link the signup will refuse.", page: workspaceSignupPage(signedOut), reveal: ["signup-plain", "signup-passkey"] },
    { id: "signup-invite-unknown", group, title: "Joining: the invitation does not work", note: "Signed in, with a code that is expired, revoked or another account's.", page: workspaceSignupPage({ signedIn: true, recoveryReady: true }), reveal: ["signup-invite-unknown"] },
    { id: "signup-no-invitation", group, title: "Joining: no invitation", note: "/signup opened without a code.", page: workspaceSignupPage(signedOut), reveal: ["signup-no-invite"] },
  ]
}

export function accountGallery(): AccountGalleryEntry[] {
  return [
    { id: "account", group: "Workspaces", title: "Your account", note: "The account apart from every workspace: name, id, the vault, its workspaces, then passkeys, sessions, recovery and appearance from the account's own routes.", page: accountPage(GALLERY_ACCOUNT_SHELL, GALLERY_SESSION, GALLERY_ORIGIN, ACCOUNT_CARDS) },
    { id: "account-one-passkey", group: "Workspaces", title: "Your account, one passkey", note: "The only passkey cannot be removed until another is added; the vault refuses it too. It syncs and there are no codes, so Recovery says codes are a second way back in.", page: accountPage(GALLERY_ACCOUNT_SHELL, GALLERY_SESSION, GALLERY_ORIGIN, { ...ACCOUNT_CARDS, passkeys: { ok: true, value: [ACCOUNT_PASSKEYS[0] as PasskeyView] }, recovery: { ok: true, value: { active: null } } }) },
    { id: "account-hostile", group: "Workspaces", title: "Your account, hostile names", note: "A passkey name and a browser label with markup and invisible characters: spelled, never markup.", page: accountPage(GALLERY_ACCOUNT_SHELL, GALLERY_SESSION, GALLERY_ORIGIN, { ...ACCOUNT_CARDS, passkeys: { ok: true, value: [{ ...(ACCOUNT_PASSKEYS[0] as PasskeyView), name: "Key\u200b <b>Admin</b> with a very long name that keeps going" }, ACCOUNT_PASSKEYS[1] as PasskeyView] }, sessions: { ok: true, value: [{ ...(ACCOUNT_SESSIONS[1] as SessionView), client: "Chrome\u202e <i>on</i> a very long device label that goes on and on", place: "Amsterdam\u0007, NL" }] } }) },
    { id: "account-cards-failed", group: "Workspaces", title: "Your account, the card reads failed", note: "Each card says its own read failed; nothing invented.", page: accountPage(GALLERY_ACCOUNT_SHELL, GALLERY_SESSION, GALLERY_ORIGIN, { passkeys: CARD_FAILED, sessions: CARD_FAILED, mayEndOtherSessions: false, recovery: CARD_FAILED, now: NOW }) },
    ...signupGallery(),
    { id: "account-recovery", group: "Account setup", title: "Recovery", note: "Set up again after the last code or second passkey went.", page: accountRecoveryPage(ACCOUNT_SHELL, { active: { generatedAt: at(-60 * 24 * 30), total: 10, left: 0 } }, true) },
    { id: "account-recovery-required", group: "Account setup", title: "Your account, recovery needed", note: "Recovery needs setting up again; workspaces stay open.", page: accountPage(ACCOUNT_SHELL, { ...PEOPLE_SESSION, recoverySetupRequired: true }, PEOPLE_ORIGIN, { ...ACCOUNT_CARDS, recovery: { ok: true, value: { active: { generatedAt: at(-60 * 24 * 30), total: 10, left: 0 } } } }) },
    { id: "account-pending-recovery", group: "Account setup", title: "Your account, recovery not committed", note: "Restricted until recovery completes, never a date from the sentinel.", page: accountPage(ACCOUNT_SHELL, { ...PEOPLE_SESSION, restricted: { reason: "recovery", until: null, notice: "ntc_1" } }, PEOPLE_ORIGIN, ACCOUNT_CARDS) },
    { id: "account-status-fallback", group: "Account setup", title: "Your account, a workspace out of reach", note: "The directory's own status when the account read cannot answer.", page: accountStatusPage(ACCOUNT_SHELL, { pendingTransition: { id: "trn_1", reservedEpoch: 4, targets: 3, acknowledged: 2, state: "pending" }, recoverySetupRequired: false }, { error: "upstream_failed", message: "Workspace security metadata is temporarily unavailable." }) },
    { id: "workspaces-create-link", group: "Account setup", title: "Your workspaces, may create", note: "The create link shows only when the account read says so: here by the deployment default, which lets every account create workspaces.", page: pickerPage(ACCOUNT_SHELL, { ...PEOPLE_SESSION, canCreateWorkspaces: true }, PEOPLE_ORIGIN) },
    { id: "workspaces-new", group: "Account setup", title: "New workspace", note: "An allowed account with recovery set up: the form.", page: workspaceCreatePage(ACCOUNT_SHELL, { ...PEOPLE_SESSION, canCreateWorkspaces: true }) },
    { id: "workspaces-new-not-allowed", group: "Account setup", title: "New workspace, not allowed", note: "A deployment where the operator allows each account, and this one is not yet: why, and no form.", page: workspaceCreatePage(ACCOUNT_SHELL, PEOPLE_SESSION) },
    { id: "workspaces-new-denied", group: "Account setup", title: "New workspace, turned off by the operator", note: "The operator denied this account: said so, and no form.", page: workspaceCreatePage(ACCOUNT_SHELL, { ...PEOPLE_SESSION, workspaceCreation: "operator-denied" }) },
    { id: "signup-pending-recovery", group: "Account setup", title: "Recovery still reaching workspaces", note: "The code was accepted; no session exists until every workspace has the change, and the page waits rather than asking for another code.", page: recoverPendingPage() },
  ]
}
