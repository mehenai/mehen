// The account's own setup pages, with workspaces on: joining from an
// invitation (/signup#<code>), recovery setup (/account/recovery) and
// creating a workspace (/workspaces/new). Nothing here is inside a
// workspace; the invitation code stays in the address's fragment and in the
// tab's sessionStorage, never in a URL the server sees.
//
// The order an invited person goes through is fixed by the vault: the proof
// of a bound invitation's email (Google, or a code emailed to it), a passkey, then recovery (ten codes
// saved and one typed back, or a second passkey), then joining, then waiting
// until an owner or admin confirms them (no wait when the invitation lets
// them straight in), then where the vault's onboarding answer names.

import type { AccountSession } from "@mehen/protocol/workspace"
import type { RecoveryStatus } from "@mehen/protocol/api"
import { cardText, steps } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import type { AccountShell } from "../shell.ts"
import { recoveryStatusWords } from "../client/security-logic.ts"
import { emailCodeOption } from "./email-code.ts"

export const COPY_REFUSED_WORDS = "This browser would not copy them. Use Download to save them to a file instead."

export const RECOVERY_SETUP_WORDS = "Before you can join or create a workspace, set up a way back in: save ten recovery codes and type one back, or add a second passkey."

// The recovery step, shared by sign-up and /account/recovery. Codes are
// filled in by the browser from the vault's reply and never kept. Saving
// codes is the one primary; a second passkey is the quiet alternative,
// below the codes once they show. Copy and Download hand over the codes
// as they are; typing one back still proves they were kept.
export function recoveryStep(heading: string): Html {
  return html`<section class="card narrow" data-region="recovery-step">
    <h2>${heading}</h2>
    <p class="lead">${RECOVERY_SETUP_WORDS}</p>
    <div class="actions"><button type="button" class="btn primary" data-action="make-codes">${icon("passkey")}<span>Save recovery codes</span></button></div>
    <div data-region="codes-issued" hidden>
      <p>Save these somewhere only you can reach, away from this device. Each works once.</p>
      <ol class="codes mono" data-region="codes-list"></ol>
      <div class="actions"><button type="button" class="btn secondary sm" data-action="copy-codes">${icon("copy")}<span>Copy</span></button>
        <button type="button" class="btn secondary sm" data-action="download-codes"><span>Download</span></button></div>
      <p class="small muted" role="status" data-region="codes-copy-error" hidden>${COPY_REFUSED_WORDS}</p>
      <label class="field"><span class="label">Type code number <b data-region="codes-position"></b> to show you saved them</span>
        <input type="text" class="mono" data-input="codes-confirm" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="64"></label>
      <p class="inline-error" role="alert" data-region="codes-error" hidden></p>
      <button type="button" class="btn primary" data-action="confirm-codes">Confirm</button>
    </div>
    <div class="actions"><button type="button" class="btn quiet" data-action="add-second-passkey">Or add a second passkey</button></div>
    <p data-region="recovery-done" hidden>${icon("check")} Recovery is set up.</p>
  </section>`
}

export const CONFIRMATION_RETRY_WORDS = "Could not check just now; retrying."
export const CONFIRMATION_ENDED_WORDS = "Your session has ended. Sign in to keep waiting."
export const CONFIRMATION_REMOVED_WORDS = "You were not confirmed: an owner or admin removed you from this workspace. Ask the person who invited you if you expected to join."

// Waiting for an owner or admin to confirm a joined membership, on /signup
// and on the picker. The browser fills the workspace's name where it is not
// known at render (data-fill="workspace-name") and drives the two lines
// through ui/client/confirmation-poll.ts, and the removed line when the
// membership is gone. The copy box is the message the
// person can send whoever invited them, in case that owner has no inbox row
// yet.
export function confirmationWaiting(name: string, hidden = false): Html {
  const named = html`<span data-fill="workspace-name">${cardText(name)}</span>`
  return html`<section class="card narrow" data-region="signup-waiting"${hidden ? html` hidden` : ""}>
    <h2>Waiting for ${named} to confirm you</h2>
    <p class="lead">You have joined. An owner or admin confirms new people before they can see or do anything. This page moves on by itself.</p>
    <p class="label">Tell the person who invited you</p>
    <div class="copybox"><code>I have joined ${named} on Mehen; please confirm me on the People page.</code><button type="button" class="btn secondary sm" data-copy>${icon("copy")}<span>Copy</span></button></div>
    <p class="muted" role="status" data-region="confirm-retrying" hidden>${CONFIRMATION_RETRY_WORDS}</p>
    <p data-region="confirm-ended" hidden>${CONFIRMATION_ENDED_WORDS} <a class="btn secondary sm" href="/signin?next=%2Fworkspaces">Sign in</a></p>
    <p data-region="confirm-removed" hidden>${CONFIRMATION_REMOVED_WORDS} <a class="btn secondary sm" href="/workspaces">Your workspaces</a></p>
  </section>`
}

// The four steps of joining from an invitation, in the vault's order: the
// Google proof of a bound invitation's email (before any passkey exists),
// the passkey, recovery, then the join itself. The browser marks them.
export const SIGNUP_STEPS = ["Verify your email", "Create your passkey", "Set up recovery", "Join"] as const

// Around the invitation's end date, filled in by the browser from the peek:
// when it stops working, and what to do if it was not expected.
export const INVITE_TERMS_WORDS = ["This invitation works until ", ". Not expecting it? Close this page: nothing is created until you make a passkey, and the link runs out by itself."] as const

// /signup with workspaces on. Every state is rendered hidden and the browser
// shows one at a time: it peeks at the invitation (POST /api/auth/invite/peek)
// to name the workspace and role, keeps the code and any Google proof in
// sessionStorage so a reload or the return from Google resumes at the same
// step, and joins by itself once recovery is ready. `signedIn`: an account is
// already signed in in this browser, so the invitation is joined with it;
// `recoveryReady`: that account can activate a membership now; `firstAccount`:
// the vault has no account yet, so the code can only be its bootstrap code and
// the page welcomes its owner instead of talking about invitations.
export function workspaceSignupPage(state: { signedIn: boolean; recoveryReady: boolean; firstAccount?: boolean }): PageInput {
  const first = state.firstAccount === true
  return {
    title: first ? "Welcome to your vault" : "Join a workspace",
    viewer: null,
    boot: { page: "workspace-signup", signedIn: state.signedIn, recoveryReady: state.recoveryReady, ...(first ? { firstAccount: true } : {}) },
    body: html`<section class="card narrow" data-region="signup-invite" hidden>
        <h1>You are invited to <b data-fill="workspace-name"></b> as <span data-fill="invite-role"></span>.</h1>
        ${steps(SIGNUP_STEPS.map((title) => ({ title, state: "todo" as const })))}
        <p class="muted" data-region="verified" hidden>Verified <code data-fill="verified-email"></code>.</p>
        <p class="small muted" data-region="invite-terms">${INVITE_TERMS_WORDS[0]}<span data-fill="invite-expiry"></span>${INVITE_TERMS_WORDS[1]}</p>
      </section>
      <section class="card narrow" data-region="signup-plain" hidden>
        <h1>${state.firstAccount ? "Welcome to your vault" : "Create your account"}</h1>
        <p class="muted" data-region="signup-first-lead"${state.firstAccount ? "" : " hidden"}>This vault is new and has no owner yet. Make a passkey to own it: it signs you in and confirms every change. There is no password, and nothing leaves this vault.</p>
        <p class="muted" data-region="signup-plain-lead"${state.firstAccount ? " hidden" : ""}>If this link came from a workspace invitation, it may have expired or been used; ask the person who sent it for a new one.</p>
        <p class="muted" data-region="signup-bootstrap-lead" hidden>Your account is created. Set up recovery, then create your first workspace.</p>
      </section>
      <section class="card narrow" data-region="signup-verify" hidden>
        <h2>Verify your email</h2>
        <p class="lead" data-region="verify-lead">This invitation is for one email address. Prove it is yours with Google; Google only identifies you, your passkey signs everything.</p>
        <p class="lead" data-region="verify-lapsed" hidden>Your email check has lapsed. Verify again to join.</p>
        <div class="actions"><button type="button" class="btn primary" data-action="verify-google">Verify with Google</button></div>
        ${emailCodeOption()}
      </section>
      <section class="card narrow" data-region="signup-passkey" hidden>
        <h2>Create your passkey</h2>
        <p class="lead">Choose the name people in the workspace will see, then create a passkey on this device. There is no password.</p>
        <form class="stack" data-form="workspace-signup" novalidate>
          <label class="field"><span class="label">Your name</span><input type="text" data-input="name" autocomplete="name" maxlength="64" required></label>
          <button type="submit" class="btn primary" data-action="signup" disabled>${icon("passkey")}<span>Create passkey</span></button>
        </form>
        ${first ? "" : html`<p class="muted">Already have an account here? <a href="/signin?next=%2Fsignup">Sign in</a>, then this page carries on with it.</p>`}
      </section>
      <div data-region="signup-recovery" hidden>${recoveryStep("Set up recovery")}</div>
      <section class="card narrow" data-region="signup-join" hidden>
        <h2>Join <span data-fill="workspace-name"></span></h2>
        <p class="lead" data-region="join-working">Joining with your account...</p>
        <div class="actions"><button type="button" class="btn primary" data-action="join" hidden>Try joining again</button></div>
      </section>
      ${confirmationWaiting("", true)}
      <section class="card narrow" data-region="signup-invite-unknown" hidden>
        <h1>This invitation does not work</h1>
        <p class="lead">It has expired, been revoked or been used by another account. Ask the person who invited you for a new link.</p>
        <p><a class="btn secondary" href="/workspaces">Your workspaces</a></p>
      </section>
      <section class="card narrow" data-region="signup-no-invite" hidden>
        <h1>You need an invitation</h1>
        <p class="lead">Open the invitation link you were sent. Mehen never creates accounts on its own.</p>
        <p><a href="/signin">I already have a passkey</a></p>
      </section>`,
  }
}

// /account/recovery: the current state, and the step that sets it up again.
export function accountRecoveryPage(account: AccountShell, status: RecoveryStatus, required: boolean): PageInput {
  return {
    title: "Recovery",
    viewer: null,
    account,
    boot: { page: "account-recovery", signedIn: { origin: account.origin, account: account.account } },
    body: html`<header class="page-head"><div><p class="eyebrow">Account</p><h1>Recovery</h1>
      <p class="lead">${status.active !== null ? `Recovery codes: ${recoveryStatusWords(status.active)}.` : "No recovery codes yet."} ${required ? "Recovery needs setting up again." : "Recovery is set up."}</p></div></header>
      ${recoveryStep(required ? "Set up recovery again" : "Make new codes or add a passkey")}`,
  }
}

// Why this account cannot create a workspace now, or null when it can: the
// deployment default or the operator's decision (directory/workspace-creation.ts),
// no recovery restriction or pending security change,
// and recovery set up. The server enforces the same; this only decides
// whether the form and the picker's link are offered at all.
export type CreationBlock = { region: string; words: string; link?: { href: string; label: string } }
export const OPERATOR_DENIED_WORDS = "The operator has turned off workspace creation for this account; ask them, or ask to be invited to a workspace."

export function creationBlock(session: AccountSession): CreationBlock | null {
  if (!session.canCreateWorkspaces) return { region: "create-not-allowed", words: session.workspaceCreation === "operator-denied" ? OPERATOR_DENIED_WORDS : "This account cannot create workspaces. The deployment's operator decides who can; ask to be invited to one instead." }
  if (session.restricted !== null || session.pendingTransition !== null) return { region: "create-held", words: "Your account is held back after a recovery or a security change, so it cannot create a workspace until that completes.", link: { href: "/account", label: "Your account" } }
  if (session.recoverySetupRequired) return { region: "create-recovery", words: "Set up recovery before creating a workspace.", link: { href: "/account/recovery", label: "Set up recovery" } }
  return null
}

// /workspaces/new. The form only when the account may create one now;
// otherwise why not, and the way on. A refusal is shown as it comes.
export function workspaceCreatePage(account: AccountShell, session: AccountSession): PageInput {
  const block = creationBlock(session)
  return {
    title: "New workspace",
    viewer: null,
    account,
    boot: { page: "workspace-create", signedIn: { origin: account.origin, account: account.account } },
    body: html`<header class="page-head"><div><p class="eyebrow">Account</p><h1>New workspace</h1>
      <p class="lead">A workspace has its own people, projects, credentials and machines. Recovery must be set up before you create one.</p></div></header>
      ${block !== null ? html`<section class="card shell-warn" data-region="${block.region}"><p>${block.words}</p>${block.link !== undefined ? html`<p><a class="btn secondary" href="${block.link.href}">${block.link.label}</a></p>` : ""}</section>` : html`<section class="card narrow"><form class="stack" data-form="workspace-create" novalidate>
        <label class="field"><span class="label">Name</span><input type="text" data-input="workspace-name" maxlength="64" required></label>
        <label class="field"><span class="label">Short name, used in addresses and commands</span><input type="text" data-input="workspace-slug" maxlength="40" autocapitalize="off" spellcheck="false" placeholder="acme"><span class="hint">Lower case letters, digits and single dashes; three to forty characters.</span></label>
        <button type="submit" class="btn primary">${icon("passkey")}<span>Create with passkey</span></button>
      </form></section>`}`,
  }
}

// Whether the picker offers "Create a workspace", and where it leads: only
// when this account may create one and it is not held back; to
// recovery first while that is missing.
export function createLink(session: AccountSession): Html {
  const block = creationBlock(session)
  if (block === null) return html`<p data-region="create-link"><a class="btn secondary" href="/workspaces/new">${icon("plus")}<span>Create a workspace</span></a></p>`
  if (block.region === "create-recovery") return html`<p data-region="create-link"><a class="btn secondary" href="/account/recovery">${icon("plus")}<span>Create a workspace (set up recovery first)</span></a></p>`
  return html``
}

// The account page's notice that recovery needs setting up again. Access to
// existing workspaces stays; only new joins and creation wait for it.
export function recoveryWarning(session: AccountSession): Html {
  if (!session.recoverySetupRequired) return html``
  return html`<section class="card shell-warn" data-region="recovery-required"><h2>Set up recovery again</h2><p>Your account has no working way back in if you lose this passkey. Save new recovery codes or add another passkey. Your workspaces stay open meanwhile.</p><p><a class="btn primary" href="/account/recovery">Set up recovery</a></p></section>`
}

export const RECOVERY_PENDING_HEADING = "Your code was accepted"
export const RECOVERY_PENDING_WORDS = "Recovery is still reaching your workspaces; you'll be restricted until it completes. Keep this page open: it moves on to setting up your new passkey by itself. Do not use another code."

// /recover/passkey while the recovery this browser started is still
// reaching the account's workspaces: no session exists yet, so there is
// nothing to sign with. The page waits on the ceremony's status and reloads
// into the passkey form once it commits, with the same code's ceremony.
export function recoverPendingPage(): PageInput {
  return {
    title: "Recovery in progress",
    viewer: null,
    boot: { page: "recover-pending" },
    body: html`<section class="card narrow" data-region="recover-pending">
      <h1>${RECOVERY_PENDING_HEADING}</h1>
      <p class="lead">${RECOVERY_PENDING_WORDS}</p>
      <p class="muted" data-region="recover-pending-state" aria-live="polite">Waiting for every workspace to take the change.</p>
    </section>`,
  }
}
