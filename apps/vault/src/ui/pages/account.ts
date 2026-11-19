// Signing in with a passkey, signing in with a recovery code and setting up
// the new passkey it allows, and the account page (/account) apart from
// every workspace. Every page but the account page works without a member
// session; the browser code drives the WebAuthn ceremonies.

import type { ApiError, PasskeyView, RecoveryStatus, SessionView, StepUpGraceRead } from "@mehen/protocol/api"
import type { AccountSession } from "@mehen/protocol/workspace"
import type { OperatorInvitation } from "@mehen/protocol/operator-proposals"
import { operatorRequirementsRefusal } from "@mehen/protocol/platform-console"
import { spellCardText } from "../../relay/spelling.ts"
import { APPEARANCES, DEFAULT_APPEARANCE } from "../client/appearance.ts"
import { dateWords, recoveryStatusWords } from "../client/security-logic.ts"
import { cardText, emptyState, notice, pill, plainText, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon, iconTile, vaultMark } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import type { Loaded } from "../load.ts"
import type { AccountShell } from "../shell.ts"
import { SESSIONS_RECOVERY_LIMIT_WORDS, relativeAgo } from "../wording.ts"
import { recoveryWarning } from "./account-setup.ts"
import { membershipList, restrictionNotice } from "./workspaces.ts"

// With no recovery codes, an account whose passkey syncs can still get back
// in: codes are advice then, not a requirement (/account says it too).
const SYNCED_PASSKEY_RECOVERY_WORDS = "Your passkey syncs through your password manager, so you can get back in if you lose this device. Recovery codes are a second way back in."

function sectionError(what: string, loaded: { ok: false; error: { message: string } }): Html {
  return html`<p class="inline-error">Could not load ${what}: ${loaded.error.message}</p>`
}

function hostOf(origin: string): string {
  try {
    return new URL(origin).host
  } catch {
    return origin
  }
}

// `origin` is the vault's own VAULT_ORIGIN, so a person can check the
// address bar against it before using a passkey.
export function signinPage(next: string, origin?: string): PageInput {
  return {
    title: "Sign in",
    viewer: null,
    boot: { page: "signin", next },
    body: html`<section class="card narrow">
      <h1>Sign in</h1>
      <p class="lead">Use the passkey you created for this vault. Your phone or computer will ask for Face ID, Touch ID or your device code.</p>
      <button type="button" class="button primary" data-action="signin" disabled>Sign in with a passkey</button>
      <p class="muted">New here? Open the invitation link you were sent to create your passkey.</p>
      <p class="muted" data-region="signin-no-invitation">No invitation yet? Ask the person who runs your workspace to invite you; Mehen never creates accounts on its own.</p>
      <p class="muted">Lost your passkey? Use another passkey or <a href="/recover">a recovery code</a>. If you have neither, contact the operator of this deployment for account recovery; a workspace owner cannot reset your account.</p>
      ${origin !== undefined ? html`<p class="small muted recognise">The real vault is at <b>${cardText(hostOf(origin))}</b> and shows this mark ${vaultMark("inline", "coil-s")}. Check the address bar before you use your passkey.</p>` : ""}
    </section>`,
  }
}

// /recover: one code in, a recovery session out. The code is typed by a
// person and never kept by the page: no autocomplete, no autocorrect.
// `workspaces`: the account recovery route answers instead of the legacy
// one, so the browser goes on to set up a passkey however it answers.
export function recoverPage(workspaces = false): PageInput {
  return {
    title: "Use a recovery code",
    viewer: null,
    boot: workspaces ? { page: "recover", workspaces: true } : { page: "recover" },
    body: html`<section class="card narrow" data-region="recover">
      <h1>Use a recovery code</h1>
      <p class="lead">Type one of the ten codes you saved. It signs you in once, for 15 minutes, so you can set up a new passkey.</p>
      <form class="stack" data-form="recover" novalidate>
        <label class="field">
          <span class="label">Recovery code</span>
          <input type="text" class="mono" data-input="recovery-code" autocomplete="off" autocapitalize="characters" autocorrect="off" spellcheck="false" maxlength="64" placeholder="XXXX-XXXX-XXXX-XXXX" required>
          <span class="hint">Four groups of four. Spaces and dashes do not matter.</span>
        </label>
        <p class="inline-error" role="alert" data-region="recover-error" hidden></p>
        <button type="submit" class="button primary" data-action="recover" disabled>Continue</button>
      </form>
      <p class="muted">Using a code records a security notice on your account and restricts it in every workspace. Once recovery completes, a 24-hour cooling-off lets you read, deny, narrow and freeze, but not approve or widen anything. An older passkey on this account can end it early; another workspace owner cannot.</p>
      <p class="muted">No codes and no other passkey? Contact the operator of this deployment for account recovery; a workspace owner cannot reset your account. <a href="/signin">Sign in with a passkey instead</a>.</p>
    </section>`,
  }
}

// /recover/passkey: the one thing a recovery session may do. `live` is
// whether the cookie still holds one; without it the page says how to start
// again rather than offering buttons that would be refused.
export function recoverPasskeyPage(live: boolean): PageInput {
  const gone = html`<section class="card narrow" data-region="recover-gone"${live ? html` hidden` : ""}>
      <h1>Start again with another code</h1>
      <p class="lead">Your code has been used and the 15 minutes ran out. Use another code.</p>
      <p><a class="button primary" href="/recover">Use another code</a></p>
    </section>`
  if (!live) return { title: "Set up a new passkey", viewer: null, boot: { page: "recover-passkey" }, body: gone }
  return {
    title: "Set up a new passkey",
    viewer: null,
    boot: { page: "recover-passkey" },
    body: html`<section class="card narrow" data-region="recover-passkey">
        <h1>Set up a new passkey</h1>
        <p class="lead">Your code worked. Within 15 minutes, create a passkey on this device or on a security key. Your other sessions have been signed out.</p>
        <form class="stack" data-form="recover-passkey" novalidate>
          <label class="field">
            <span class="label">Name for the new passkey</span>
            <input type="text" data-input="passkey-name" maxlength="64" autocomplete="off" placeholder="Optional, such as My new phone">
          </label>
          <button type="button" class="button primary" data-action="recover-passkey" data-kind="device" disabled>${icon("passkey")}<span>Create a passkey on this device</span></button>
          <button type="button" class="button secondary" data-action="recover-passkey" data-kind="security-key" disabled>${icon("key")}<span>Use a security key</span></button>
        </form>
        <p class="muted">Once recovery completes, for 24 hours you can read, deny, narrow and freeze, but not approve or widen anything. An older passkey on this account can end that early; another workspace owner cannot.</p>
      </section>
      ${gone}`,
  }
}

// /account's cards beyond the account read: each from its own account route
// (GET /api/account/passkeys, /sessions, /recovery), each failing on its own.
// `mayEndOtherSessions`: the sessions read's word on whether this sign-in may
// end the others; when not, only its own row keeps its button.
// `operatorInvitation`: an approved operator role waiting for this account
// to accept it; absent or null when there is none or its read failed.
// `grace`: this browser session's passkey grace window; absent or null when
// there is none or its read failed.
export type AccountCards = { passkeys: Loaded<PasskeyView[]>; sessions: Loaded<SessionView[]>; mayEndOtherSessions: boolean; recovery: Loaded<RecoveryStatus>; now: number; operatorInvitation?: OperatorInvitation | null; grace?: StepUpGraceRead["grace"] }

// The operator role two operators approved for this account: who proposed
// and approved it, until when, and Accept with this account's own passkey,
// or what the account lacks first.
function operatorInvitationCard(invitation: OperatorInvitation | null | undefined): Html {
  if (invitation === null || invitation === undefined) return html``
  const missing = invitation.missing.length > 0
  return html`<section class="card" data-region="operator-invitation"><h2>Become an operator</h2>
    <p>${cardText(invitation.proposedBy.name)} proposed making you an operator of this vault and ${cardText(invitation.approvedBy.name)} approved it. An operator registers and runs platforms and decides, with another operator, who else is one. Nothing changes until you accept, before ${timeTag(invitation.expiresAt)}.</p>
    ${missing ? notice("warn", "Your account needs something first", operatorRequirementsRefusal(invitation.missing)) : ""}
    <div class="actions"><button type="button" class="btn primary" data-action="accept-operator" data-proposal="${invitation.proposal}" data-digest="${invitation.digest}"${missing ? " disabled" : ""}>${icon("passkey")}<span>Accept with passkey</span></button></div></section>`
}

function passkeyTitle(passkey: PasskeyView): string {
  return passkey.name !== null && passkey.name.trim() !== "" ? passkey.name : passkey.authenticator
}

function passkeyRow(passkey: PasskeyView, only: boolean, now: number): Html {
  const named = passkey.name !== null && passkey.name.trim() !== ""
  const label = spellCardText(passkeyTitle(passkey))
  const used = passkey.lastUsedAt === null ? "never used" : `used ${relativeAgo(passkey.lastUsedAt, now) ?? passkey.lastUsedAt}`
  const remove = only
    ? html`<button type="button" class="btn danger-quiet sm" data-action="remove-passkey" data-passkey="${passkey.passkey}" data-name="${label}" data-keep-disabled disabled title="Add another passkey first.">${icon("x")}<span>Remove</span></button>`
    : html`<button type="button" class="btn danger-quiet sm" data-action="remove-passkey" data-passkey="${passkey.passkey}" data-name="${label}" disabled>${icon("x")}<span>Remove</span></button>`
  return html`<li data-passkey-row="${passkey.passkey}">${iconTile(passkey.authenticator.startsWith("A security key") ? "key" : passkey.authenticator.startsWith("A phone") ? "phone" : "passkey")}<span class="main"><span class="title">${cardText(passkeyTitle(passkey))}${passkey.current ? html` ${pill("this session", "ok", false)}` : ""}</span><span class="sub">${named ? html`${cardText(passkey.authenticator)} · ` : ""}added ${dateWords(passkey.createdAt)} · ${used}</span>${only ? html`<span class="sub">Your only passkey. Add another before you can remove it.</span>` : ""}<span class="rename-field" data-region="rename" hidden><input type="text" data-input="rename" maxlength="64" value="${named && plainText(passkey.name as string) ? (passkey.name as string) : ""}" placeholder="New name" aria-label="New name for ${label}"><button type="button" class="btn secondary sm" data-action="save-rename" disabled>Save</button><button type="button" class="btn quiet sm" data-action="cancel-rename" disabled>Cancel</button></span></span><span class="side"><button type="button" class="btn quiet sm" data-action="rename-passkey" disabled>Rename</button>${remove}</span></li>`
}

function passkeysCard(cards: AccountCards): Html {
  const loaded = cards.passkeys
  const list = loaded.ok ? loaded.value : []
  const body = loaded.ok
    ? list.length > 0
      ? html`<ul class="list list-actions" data-region="passkeys">${list.map((p) => passkeyRow(p, list.length === 1, cards.now))}</ul>`
      : emptyState("passkey", "No passkeys listed", "This session was opened another way; sign in with a passkey to see them here.")
    : sectionError("your passkeys", loaded)
  return html`<section class="card" id="passkeys" aria-label="Passkeys" data-region="account-passkeys">
    <h2>Passkeys</h2>
    <p class="muted">Each one signs you in and confirms changes in every workspace. Keep at least two, ideally one on a security key kept somewhere else.</p>
    ${body}
    <div class="card-foot passkey-add">
      <label class="field">Name for the new one <input type="text" data-input="passkey-name" maxlength="64" placeholder="Optional, such as YubiKey on my keyring" autocomplete="off"></label>
      <button type="button" class="btn secondary sm" data-action="add-passkey" data-kind="device" disabled>${icon("passkey")}<span>Add a passkey</span></button>
      <button type="button" class="btn secondary sm" data-action="add-passkey" data-kind="security-key" disabled>${icon("key")}<span>Add a security key</span></button>
    </div>
    <p class="small muted">Adding or removing one asks for a passkey you already have first.</p>
    ${graceLine(cards.grace)}
  </section>`
}

// After a passkey confirmation this browser does not ask again for 15
// minutes, except for the changes that always ask; Ask every time ends that.
function graceLine(grace: AccountCards["grace"]): Html {
  if (grace === null || grace === undefined) return html``
  return html`<div class="card-foot" data-region="stepup-grace"><p class="small">Passkey confirmed, no need to confirm again until ${timeTag(grace.until)}.</p><button type="button" class="btn quiet sm" data-action="end-stepup-grace" disabled>Ask every time</button></div>`
}

const SESSION_METHOD: Record<SessionView["method"], string> = {
  signup: "Opened at sign-up",
  passkey: "Signed in with a passkey",
  recovery: "Signed in with a recovery code",
  reset: "Opened from a reset link",
}

function sessionRow(session: SessionView, now: number, mayEnd: boolean): Html {
  const how = session.method === "passkey" && session.passkeyName !== null ? html`Signed in with ${cardText(session.passkeyName)}` : html`${SESSION_METHOD[session.method]}`
  const seen = relativeAgo(session.lastSeenAt, now) ?? session.lastSeenAt
  const end = mayEnd ? html`<span class="side"><button type="button" class="btn danger-quiet sm" data-action="end-session" data-session="${session.session}" data-current="${session.current ? "1" : "0"}" data-name="${spellCardText(session.client)}" disabled>${icon("signout")}<span>${session.current ? "Sign out here" : "End"}</span></button></span>` : ""
  return html`<li>${iconTile(session.kind === "app" ? "phone" : "globe")}<span class="main"><span class="title">${cardText(session.client)}${session.current ? html` ${pill("this browser", "ok", false)}` : ""}</span><span class="sub">${session.place !== null ? html`${cardText(session.place)} · ` : ""}${how}</span><span class="sub">opened ${dateWords(session.createdAt)} · seen ${seen}</span></span>${end}</li>`
}

function sessionsCard(cards: AccountCards): Html {
  const loaded = cards.sessions
  const list = loaded.ok ? loaded.value : []
  const body = loaded.ok
    ? list.length > 0
      ? html`<ul class="list list-actions" data-region="sessions">${list.map((s) => sessionRow(s, cards.now, s.current || cards.mayEndOtherSessions))}</ul>`
      : emptyState("globe", "No sessions listed", "Sign in again to see where you are signed in.")
    : sectionError("your sessions", loaded)
  return html`<section class="card" id="sessions" aria-label="Sessions" data-region="account-sessions">
    <h2>Sessions</h2>
    <p class="muted">The browsers and apps signed in as you. Ending one signs it out at once. Machines are separate; each workspace lists its own.</p>
    ${body}
    ${loaded.ok && list.length > 0 ? (cards.mayEndOtherSessions ? html`<div class="card-foot"><button type="button" class="btn danger-quiet sm" data-action="end-all-sessions" disabled>${icon("signout")}<span>Sign out everywhere, this browser too</span></button></div>` : html`<p class="small muted" data-region="sessions-recovery-limit">${SESSIONS_RECOVERY_LIMIT_WORDS}</p>`) : ""}
  </section>`
}

function recoveryCard(session: AccountSession, cards: AccountCards): Html {
  const loaded = cards.recovery
  const active = loaded.ok ? loaded.value.active : null
  // With no codes, a passkey that syncs is what makes recovery set up.
  const synced = cards.passkeys.ok && cards.passkeys.value.some((p) => p.synced === true)
  const setUp = session.recoverySetupRequired ? "Recovery needs setting up again." : "Recovery is set up."
  const words = active !== null ? `Recovery codes: ${recoveryStatusWords(active)}. ${setUp}` : !session.recoverySetupRequired && synced ? SYNCED_PASSKEY_RECOVERY_WORDS : `No recovery codes yet. ${setUp}`
  const status = loaded.ok ? html`<p data-region="recovery-status">${words}</p>` : sectionError("your recovery", loaded)
  return html`<section class="card" id="recovery" aria-label="Recovery" data-region="account-recovery">
    <h2>Recovery</h2>
    <p class="muted">A recovery code or a second passkey is your way back in if you lose this one. Never paste a code into a chat or give one to an agent.</p>
    ${status}
    <p><a class="btn secondary sm" href="/account/recovery">${icon("key")}<span>${session.recoverySetupRequired ? "Set up recovery" : "Make new codes or add a passkey"}</span></a></p>
  </section>`
}

function appearanceCard(): Html {
  return html`<section class="card" id="appearance" aria-label="Appearance">
    <h2>Appearance</h2>
    <span class="chips appearance" role="group" aria-label="Appearance" data-region="appearance">${APPEARANCES.map(
      (a) => html`<button type="button" class="chip" data-theme-choice="${a.value}" aria-pressed="${a.value === DEFAULT_APPEARANCE ? "true" : "false"}">${a.label}</button>`,
    )}</span>
    <p class="small muted">Kept in this browser only. Motion follows the system's reduce motion setting.</p>
  </section>`
}

// /account: the account itself, apart from every workspace. The restricted
// and pending-change notices first; then the account, its workspaces, and
// the cards for passkeys, sessions, recovery and appearance. Linked Google
// identities keep their inactive slot until that card is built.
export function accountPage(account: AccountShell, session: AccountSession, origin: string, cards: AccountCards): PageInput {
  return {
    title: "Your account",
    viewer: null,
    account,
    boot: { page: "account" },
    body: html`<header class="page-head"><div><p class="eyebrow">Account</p><h1>${cardText(session.name)}</h1><p class="lead">Your passkeys and recovery belong to this account, not to any one workspace.</p></div></header>
      ${restrictionNotice(session)}
      ${recoveryWarning(session)}
      ${operatorInvitationCard(cards.operatorInvitation)}
      <section class="card"><h2>Account</h2><dl class="kv facts"><dt>Name</dt><dd>${cardText(session.name)}</dd><dt>Account id</dt><dd><code>${session.account}</code></dd><dt>Vault</dt><dd><span class="identity-origin">${origin}</span></dd></dl><div class="oidc-slot" data-slot="oidc-account-identities" hidden></div></section>
      <section class="card"><h2>Workspaces</h2>${membershipList(session, origin)}</section>
      ${passkeysCard(cards)}
      ${sessionsCard(cards)}
      ${recoveryCard(session, cards)}
      ${appearanceCard()}`,
  }
}

// The account page when GET /api/account cannot answer (a workspace's
// security state is out of reach): what the directory alone can say, the
// pending security change and whether recovery needs setting up, read from
// GET /api/account/security-transition. Never an invented empty list.
export type AccountSecurityStatus = { pendingTransition: AccountSession["pendingTransition"]; recoverySetupRequired: boolean }

export function accountStatusPage(account: AccountShell, status: AccountSecurityStatus, error: ApiError): PageInput {
  const pending = status.pendingTransition
  return {
    title: "Your account",
    viewer: null,
    account,
    boot: { page: "account" },
    body: html`<header class="page-head"><div><p class="eyebrow">Account</p><h1>${cardText(account.name)}</h1><p class="lead">${cardText(error.message)}</p></div></header>
      ${pending !== null ? html`<section class="card shell-warn" data-region="account-pending"><h2>A security change is still reaching your workspaces</h2><p>${pending.acknowledged} of ${pending.targets} workspaces have it so far. Until every one has, you can read, deny, narrow and freeze, but not approve or widen anything. The vault keeps retrying; nothing here needs you to act.</p></section>` : html`<section class="card" data-region="account-unavailable"><p>A workspace could not answer just now. Reload in a minute.</p></section>`}
      ${status.recoverySetupRequired ? html`<section class="card shell-warn" data-region="recovery-required"><h2>Set up recovery again</h2><p><a class="btn primary" href="/account/recovery">Set up recovery</a></p></section>` : ""}`,
  }
}
