// Connecting an OAuth account. The member is signed in before the provider
// is involved, so nobody else can finish the connection with their own
// account. After the provider's callback the same page shows the outcome.
// A connect chained to a client intake first points at that intake, then
// opens with a "step 1 done" strip once the client is saved.

import type { ConnectView } from "@mehen/protocol/api"
import { getOAuthProvider, getTemplate, normaliseScope } from "@mehen/protocol/templates"
import { cardText, countdownTimer, requesterDetails, stateCard, taskLine, whoMayUse } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon, serviceTile } from "../icons.ts"
import type { PageInput, Viewer } from "../layout.ts"
import { TAGS_ARE_ONE_LIMIT, askerAsks, askerUsers, formatTime, isMemberAsk, scopeWords, tagsChosenWords } from "../wording.ts"

// A usable connect link lasts 15 minutes; one waiting on its client intake
// lives as long as that intake, 24 hours.
const CONNECT_TOTAL_SECONDS = 15 * 60
const INTAKE_TOTAL_SECONDS = 24 * 3600

// Every string an agent wrote (expect, reason, session), a human typed (the
// device name) or the provider returned (the account, the message) is
// spelled through cardText where it is rendered.

// Back to Connect a service for an ask a member made there; nothing on the
// request shapes it. An agent's ask has no button: askLine says to ask that
// agent, since the page does not know which agent or app it is.
function askAgain(view: ConnectView): Html | undefined {
  if (isMemberAsk(view.requestedBy)) return html`<a class="btn primary" href="/connect">${icon("grid")}<span>Start again from Connect a service</span></a>`
  return undefined
}

function expectText(view: ConnectView): Html | null {
  return view.expect ? html`<strong>${cardText(view.expect)}</strong>` : null
}

function askLine(view: ConnectView, then: Html | string = ""): Html {
  const expect = expectText(view)
  const by = view.requestedBy
  if (isMemberAsk(by)) return html`<p>Start the connection to ${view.providerName}${expect !== null ? html` as ${expect}` : ""} again from Connect a service. ${then}</p>`
  return html`<p>Ask the agent on ${cardText(by.deviceName)} for a new link to connect ${view.providerName}${expect !== null ? html` as ${expect}` : ""}. ${then}</p>`
}

// The OAuth client a connect signs in through, by its template's name.
function clientName(view: ConnectView): string {
  const template = getOAuthProvider(view.provider)?.clientTemplate
  return (template !== undefined ? getTemplate(template)?.displayName : undefined) ?? "OAuth client"
}

// The vault's stored outcome ends with what to do next; the card says that
// itself, for the right asker, so the message's own ending is left off.
function outcomeText(message: string): string {
  return message.replace(/\s*(?:Ask the agent for a new link(?: to try again)?|Start it again)\.$/, "")
}

// What a closed link was for, above its state card.
function closedHead(view: ConnectView): Html {
  return html`<section class="card connect-head" data-region="connect-head">
    <div class="item-head">
      ${serviceTile({ provider: view.provider, slug: view.slug }, "xl")}
      <div class="item-head-text">
        <h1>${headTitle(view)}</h1>
        <p class="item-sub">${view.reconnect ? view.providerName : html`<code class="slug-inline">${cardText(view.slug)}</code>`}</p>
      </div>
    </div>
  </section>`
}

function closedCard(view: ConnectView): Html | null {
  const expect = expectText(view)
  switch (view.status) {
    case "open":
      return null
    case "completed":
      return stateCard({
        tone: "ok",
        icon: "check",
        level: 2,
        heading: view.reconnect ? "Reconnected" : "Connected",
        lead: html`${view.providerName} is connected${view.account ? html` for <strong>${cardText(view.account)}</strong>` : ""} and stored as <code>${cardText(view.slug)}</code>. Only machines allowed its tags, or every credential, can use it, and only within its home, its owner's rights, each machine's scope and the rules for ${view.providerName}.`,
        primary: html`<a class="btn secondary" href="/items/${encodeURIComponent(view.slug)}">Open the credential</a>`,
      })
    case "mismatch":
      return stateCard({
        tone: "danger",
        icon: "x",
        level: 2,
        heading: "Wrong account",
        lead: html`You signed in to ${view.providerName}${view.account ? html` as <strong>${cardText(view.account)}</strong>` : ""}, but this link was for ${expect ?? "a different account"}. Nothing was saved and nothing was overwritten.`,
        primary: askAgain(view),
        or: askLine(view, html`Then sign in to ${view.providerName} as ${expect ?? "the right account"}.`),
      })
    case "failed":
      return stateCard({
        tone: "danger",
        icon: "x",
        level: 2,
        heading: "The connection failed",
        lead: html`${view.message !== null ? cardText(outcomeText(view.message)) : `${view.providerName} did not complete the connection.`} Nothing was saved. You may already have authorised the app at ${view.providerName}; check there if you want to withdraw that access.`,
        primary: askAgain(view),
        or: askLine(view),
      })
    case "expired":
      return stateCard({
        tone: "expired",
        icon: "clock",
        level: 2,
        heading: view.expiresAt !== undefined ? html`This link ran out at ${formatTime(view.expiresAt)}` : "This link has expired",
        lead:
          view.awaiting?.status === "expired"
            ? html`The ${clientName(view)} was not added in time, so this connection could not start. Nothing was saved.`
            : html`Connect links last 15 minutes. This connection did not complete in Mehen and nothing was saved. If you already signed in at ${view.providerName}, you may have authorised the app there; check there if you want to withdraw that access.`,
        primary: askAgain(view),
        or: askLine(view),
      })
  }
}

function expiredCard(view: ConnectView): Html {
  return html`<div data-region="connect-expired" hidden>${stateCard({
    tone: "expired",
    icon: "clock",
    level: 2,
    heading: view.expiresAt !== undefined ? html`This link ran out at ${formatTime(view.expiresAt)}` : "This link has expired",
    lead: html`Nothing was saved. This link no longer works; ${isMemberAsk(view.requestedBy) ? "start again from Connect a service" : "ask for a new link"}.`,
    primary: askAgain(view),
    or: askLine(view),
  })}</div>`
}

// "Connect Gmail", or on a reconnect "Reconnect gmail-alex": the slug names
// the connection whose tokens the sign-in replaces, never the account.
function pageTitle(view: ConnectView): string {
  return view.reconnect ? `Reconnect ${view.slug}` : `Connect ${view.providerName}`
}

function headTitle(view: ConnectView): Html {
  return view.reconnect ? html`Reconnect <code class="slug-inline">${cardText(view.slug)}</code>` : html`Connect ${view.providerName}`
}

function headCard(view: ConnectView, now: number): Html {
  const waiting = view.awaiting?.status === "open"
  const chained = view.awaiting !== undefined
  const total = waiting ? INTAKE_TOTAL_SECONDS : CONNECT_TOTAL_SECONDS
  return html`<section class="card connect-head" data-region="connect-head">
    <div class="item-head">
      ${serviceTile({ provider: view.provider, slug: view.slug }, "xl")}
      <div class="item-head-text">
        <p class="eyebrow">${cardText(askerAsks(view.requestedBy, view.reconnect ? "reconnect" : "connect"))}</p>
        <h1>${headTitle(view)}</h1>
        ${taskLine(view.requestedBy)}
        <p class="item-sub">${chained ? html`<b>Step ${waiting ? "1" : "2"} of 2.</b> ` : ""}${view.reconnect ? html`Already connected to ${view.providerName}; this signs it in again.` : html`Will be saved as <code class="slug-inline">${cardText(view.slug)}</code>.`}${view.expiresAt !== undefined ? html` <span class="when">${countdownTimer(view.expiresAt, total, now)}, single use.</span>` : ""}</p>
      </div>
    </div>
    ${view.reconnect ? html`<p class="reconnect-note" data-region="connect-reconnect">${icon("refresh")}<span>The existing token is replaced only after you sign in, and the account must match.</span></p>` : ""}
    ${chained ? html`<div class="progress" aria-label="Step ${waiting ? "1" : "2"} of 2"><span class="${waiting ? "current" : "done"}"></span><span class="${waiting ? "" : "current"}"></span></div>` : ""}
    <details class="fold">
      <summary>${icon("chevronRight")}<span>${isMemberAsk(view.requestedBy) ? "Where this came from" : "Why it is asking"}</span></summary>
      <blockquote class="reason">${cardText(view.reason)}</blockquote>
      <dl class="kv small">
        ${requesterDetails(view.requestedBy)}
      </dl>
    </details>
  </section>`
}

function awaitingCard(view: ConnectView, intake: string): Html {
  const client = clientName(view)
  return html`<section class="card state muted" data-region="connect-awaiting">
    <span class="state-icon">${icon("badge")}</span>
    <h2>First, add the ${client}</h2>
    <p class="lead">This connection signs in through an OAuth client the vault does not have yet. Step 1 asks you to paste it; once it is saved, that page comes straight back here.</p>
    <div class="actions"><a class="btn primary" href="/i/${encodeURIComponent(intake)}">${icon("arrowRight")}<span>Add the ${client}</span></a></div>
  </section>`
}

// The tags the connection will carry are terms the passkey signs, so the
// page shows every one of them, in the intake page's wording. A connect
// without tags shows no card.
function tagsCard(view: ConnectView, tags: readonly string[]): Html | string {
  if (tags.length === 0) return ""
  return html`<section class="card" aria-label="Which machines may use it" data-region="connect-tags">
    <p class="eyebrow">Who may use it</p>
    <p class="lead">${whoMayUse(tags)}.</p>
    <p class="small muted">${TAGS_ARE_ONE_LIMIT} ${tagsChosenWords(view.requestedBy, "sign in", "link")}</p>
  </section>`
}

function accountCard(view: ConnectView): Html {
  return html`<section class="card" data-region="connect-account">
    <p class="eyebrow">The account</p>
    ${view.expect
      ? html`<p class="expect">Sign in as <strong>${cardText(view.expect)}</strong>. If ${view.providerName} signs you in as anyone else, the vault refuses the connection and saves nothing.</p>`
      : html`<p class="expect">No account was named. Check which account ${view.providerName} signs you in with; the vault records it as the connection's account.</p>`}
  </section>`
}

// How the scopes asked for stand against the connection's own, on a
// reconnect: wider (asked for now, not held) is shown in red; narrower (held,
// no longer asked for) is listed plainly. Compared after normalising, so a
// short Google scope and its full URL are the same scope.
export function scopeChanges(view: ConnectView): { wider: Set<string>; narrower: string[] } {
  const provider = getOAuthProvider(view.provider)
  const norm = (s: string): string => (provider ? (normaliseScope(provider, s) ?? s) : s)
  if (!view.reconnect || view.currentScopes === null) return { wider: new Set(), narrower: [] }
  const current = new Set(view.currentScopes.map(norm))
  const asked = new Set(view.scopes.map(norm))
  return { wider: new Set(view.scopes.filter((s) => !current.has(norm(s)))), narrower: view.currentScopes.filter((s) => !asked.has(norm(s))) }
}

function scopeItem(s: string, wider: boolean): Html {
  return html`<li${wider ? html` class="wider"` : ""}><span class="scope-words">${cardText(scopeWords(s))}</span>${wider ? html` <span class="pill danger">wider than now</span>` : ""}${scopeWords(s) !== s ? html`<code class="scope-raw">${cardText(s)}</code>` : ""}</li>`
}

function scopesCard(view: ConnectView, live: boolean): Html {
  const google = getOAuthProvider(view.provider)?.clientTemplate === "google-oauth-client"
  const asker = cardText(askerUsers(view.requestedBy))
  const { wider, narrower } = scopeChanges(view)
  return html`<section class="card" data-region="connect-scopes">
    <h2>${view.reconnect && wider.size === 0 ? "It will still be able to" : "It will be able to"}</h2>
    <ul class="scopes">${view.scopes.map((s) => scopeItem(s, wider.has(s)))}</ul>
    ${view.reconnect && wider.size > 0 ? html`<p class="small danger-text" data-region="connect-wider">This asks for more than the connection has now. If that is not what you expected, do not sign in.</p>` : ""}
    ${view.reconnect && wider.size === 0 && view.currentScopes !== null ? html`<p class="small muted" data-region="connect-same">The same as the connection has now, nothing more.</p>` : ""}
    ${narrower.length > 0 ? html`<p class="small muted" data-region="connect-narrower">No longer asked for: ${narrower.map((s, i) => html`${i > 0 ? "; " : ""}${cardText(scopeWords(s))}`)}.</p>` : ""}
    <p class="small muted">The vault keeps the tokens. ${asker} only ever ${isMemberAsk(view.requestedBy) ? "make" : "makes"} calls through the vault, within the rules for ${view.providerName}.</p>
    ${live
      ? html`<button type="button" class="btn primary" data-action="start-connect" disabled>${view.reconnect ? html`Reconnect ${cardText(view.slug)}` : html`Continue to ${view.providerName}`}</button>
          ${google ? html`<p class="hint">Google shows an unverified app screen because the client is yours, not Google's: choose Advanced, then Go to Mehen, or the name you gave the app.</p>` : ""}`
      : ""}
  </section>`
}

// tags: the stored tags a workspace connect will carry (WorkspaceConnectView).
export function connectPage(viewer: Viewer, view: ConnectView & { tags?: readonly string[] }, now = Date.now()): PageInput {
  const closed = closedCard(view)
  if (closed !== null) return { title: pageTitle(view), viewer, focus: true, boot: { page: "connect-closed", connect: view.connect }, body: html`${closedHead(view)}${closed}` }
  const waiting = view.awaiting?.status === "open" ? view.awaiting.intake : null
  return {
    title: pageTitle(view),
    viewer,
    focus: true,
    boot: waiting !== null ? { page: "connect-waiting", connect: view.connect } : { page: "connect", connect: view.connect },
    body: html`${headCard(view, now)}
      ${view.message !== null ? html`<p class="callout" data-region="connect-retry">${icon("alert")}<span>${cardText(view.message)}</span></p>` : ""}
      ${waiting !== null ? awaitingCard(view, waiting) : ""}
      ${view.awaiting?.status === "completed" ? html`<p class="strip ok" data-region="connect-step-done">${icon("check")}<span>Step 1 done: the ${clientName(view)} is saved. Now the account.</span></p>` : ""}
      ${accountCard(view)}
      ${tagsCard(view, view.tags ?? [])}
      ${scopesCard(view, waiting === null)}
      ${expiredCard(view)}`,
  }
}
