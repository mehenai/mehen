// A workspace's credentials: the list with each one's Belongs to, adding
// one through an intake or a connection, and one credential's page with
// rotate, re-home and delete where workspace-rights.ts says the vault would
// allow them. Someone else's private credential never appears: the vault
// leaves it out of every read, and the owner-and-admin purge form takes a
// name and shows nothing about what it removes. No page shows a value.

import type { ItemDescription } from "@mehen/protocol/api"
import type { WorkspaceItemDescription, WorkspaceItemSummary, WorkspaceProject } from "@mehen/protocol/workspace"
import { isLeaseOnly, leaseOnlyDelivery } from "@mehen/protocol/binding"
import { type SigninOriginSource, signinOriginSources } from "@mehen/protocol/fill"
import { KINDS, deviceModeAllowed } from "@mehen/protocol/kinds"
import { OAUTH_PROVIDERS, TEMPLATES, getOAuthProvider, getTemplate } from "@mehen/protocol/templates"
import { cardText, emptyState, hostList, itemStatusPill, notice, pageHead, pill, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon, serviceTile } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import { type PolicyRulesCardData, credentialRulesLine, policyRulesCard } from "../policy-rules-list.ts"
import { hasActiveRule, isGrant } from "../policy-rules-list.ts"
import { postureCard } from "../posture-card.ts"
import { pushAllowanceCard, pushDeleteWords, pushedToCard } from "../push-credential.ts"
import { type WorkspaceShell, workspaceHref } from "../shell.ts"
import { MODE_WORDS, TYPE_INTO_WARNING, joinWords } from "../wording.ts"
import { type Viewer, HELD_WORDS, belongsToWords, canPurgePrivate, canPushAgain, creatableHomes, credentialControls } from "../workspace-rights.ts"

// `adding` renders the add sheet open, for the gallery; the page itself
// opens it from the page head's button.
export type CredentialsPageData = { viewer: Viewer; items: WorkspaceItemSummary[]; projects: WorkspaceProject[]; adding?: boolean }

// What items.describe adds for a person: the stable identity and revisions
// the page binds its signatures to, and the OAuth client or connections the
// credential is tied to, as far as this person may see them.
export type CredentialDependency = { slug: string; role: "client" | "connection" }
export type HumanItemDescription = WorkspaceItemDescription & { id: string; configRevision: number; dependencyRevision: number; dependencies: CredentialDependency[]; hiddenDependencies: boolean }

// rules: the credential's standing rules, read only with POLICY_RULES on.
// pushes: pushing is on for this workspace (PUSH); off, the page shows
// nothing about it.
// fill: BROWSER_FILL is on for this workspace, so the In web pages card shows.
export type CredentialPageData = { viewer: Viewer; item: HumanItemDescription; projects: WorkspaceProject[]; rules?: PolicyRulesCardData; pushes?: boolean; fill?: boolean }

// The uniform refusal for a taken, hidden, private or pending name, in
// words: the vault says only that the name is not available.
export const NAME_NOT_AVAILABLE_WORDS = "That name is not available. Choose another; for a credential only you use, try adding your own name, as in openai-alex."

// The exact 7.4 warning for a move (CREDENTIALS P3-8).
export const REHOME_WARNING = "Moving this credential removes every current variable reference, including references in the destination project. Rebind those variables after the move. Existing approvals and runs that depend on those references are invalidated."

// The private owner's own audit limit (design 7.2).
export const PRIVATE_AUDIT_WORDS = "You will not see which hosts or paths your private credential was sent to; investigate misuse with the provider's own logs."

function slugMap(projects: readonly WorkspaceProject[]): Map<string, string> {
  return new Map(projects.map((p) => [p.id, p.slug]))
}

function serviceName(item: Pick<WorkspaceItemSummary, "provider" | "kind">): string {
  if (item.provider !== null) {
    const name = getTemplate(item.provider)?.displayName ?? getOAuthProvider(item.provider)?.displayName
    if (name !== undefined) return name
  }
  return KINDS[item.kind]?.label ?? item.kind
}

// The badge beside the facts' own "Belongs to" label, so it carries only
// the place.
function belongsBadge(item: Pick<WorkspaceItemSummary, "home">, slugs: ReadonlyMap<string, string>): Html {
  return html`<span class="belongs" data-belongs="${item.home.kind}">${belongsToWords(item.home, slugs)}</span>`
}

// Belongs to is a fact about the credential, so it is text under the name;
// the side holds only its status.
function credentialRow(item: WorkspaceItemSummary, slugs: ReadonlyMap<string, string>, ws: string): Html {
  const status = item.review !== undefined && item.status === "active" ? pill("Needs review", "warn") : itemStatusPill(item.status)
  return html`<li class="row" data-row data-group="${item.home.kind}" data-search="${[item.slug, item.provider ?? "", serviceName(item), item.account ?? "", ...(isLeaseOnly(item) ? [] : item.hosts)].join(" ").toLowerCase()}">
    ${serviceTile(item)}
    <a class="row-main" href="${workspaceHref(ws, `/items/${encodeURIComponent(item.slug)}`)}"><span class="row-title">${cardText(item.slug)}</span><span class="row-sub">${cardText(serviceName(item))}${item.account !== null ? html` as ${cardText(item.account)}` : ""}. Belongs to: ${belongsToWords(item.home, slugs)}</span></a>
    <span class="row-side">${status}</span>
  </li>`
}

function homeChoice(home: ReturnType<typeof creatableHomes>[number], slugs: ReadonlyMap<string, string>, checked: boolean): Html {
  const value = home.kind === "project" ? `project:${home.project}` : home.kind
  return html`<label class="tick"><input type="radio" name="home" data-input="home" value="${value}"${checked ? html` checked` : ""}><span>${belongsToWords(home, slugs)}</span></label>`
}

function providerOptions(): Html {
  const templates = Object.values(TEMPLATES).sort((a, b) => a.displayName.localeCompare(b.displayName))
  const oauth = Object.values(OAUTH_PROVIDERS).sort((a, b) => a.displayName.localeCompare(b.displayName))
  return html`<optgroup label="Paste a key">${templates.map((t) => html`<option value="${t.id}" data-way="intake">${t.displayName}</option>`)}</optgroup>
    <optgroup label="Sign in to connect">${oauth.map((p) => html`<option value="${p.id}" data-way="connect">${p.displayName}</option>`)}</optgroup>`
}

// The add form, in a sheet the page head's button opens. Its checks and the
// vault's refusals show in the sheet's own notice: the page's notice sits
// behind the scrim while the sheet is open.
function addSheet(data: CredentialsPageData, slugs: ReadonlyMap<string, string>): Html {
  const homes = creatableHomes(data.viewer, data.projects)
  return html`<div class="sheet" data-region="add-credential" role="dialog" aria-modal="true" aria-labelledby="add-credential-title"${data.adding === true ? "" : html` hidden`}>
    <div class="sheet-panel">
      <div class="sheet-grip"></div>
      <div class="sheet-head"><h2 id="add-credential-title">Add a credential</h2><button type="button" class="icon-btn" data-action="close-sheet" aria-label="Close">${icon("x")}</button></div>
      <form class="stack" data-form="add-credential" novalidate>
        <label class="field"><span class="label">Service</span><select data-input="provider">${providerOptions()}</select></label>
        <label class="field"><span class="label">Name</span><input type="text" data-input="slug" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="openai-dev"></label>
        <fieldset class="field" data-region="homes"><legend class="label">Belongs to</legend>${homes.map((h, i) => homeChoice(h, slugs, i === 0))}</fieldset>
        <p class="small muted">You paste the key or sign in on the next page; the vault seals it there and you confirm with your passkey.</p>
        <div class="notice" data-region="sheet-notice" role="alert" aria-live="assertive" hidden></div>
        <button type="button" class="btn primary" data-action="add-credential">Continue</button>
      </form>
    </div>
  </div>`
}

// Owners and admins may remove someone else's private credential by name,
// under Manage at the foot of the page. The form shows nothing about it,
// before or after: no kind, no owner, no hosts. An unknown name gets the
// same answer as one they may not remove.
function manageListCard(viewer: Viewer): Html {
  if (!canPurgePrivate(viewer)) return html``
  return html`<section class="card" aria-label="Manage" data-region="manage-list"><div class="card-head"><h2>Manage</h2></div>
    <details class="fold edit" data-region="purge-private">
    <summary>${icon("chevronRight")}<span>Remove a private credential by name</span></summary>
    <form class="stack" data-form="purge" novalidate>
      <p class="small muted">For a credential that belonged to someone who has left, or on their request. It belongs to one person only, so you confirm by its name; nothing about it is shown here.</p>
      <label class="field"><span class="label">Name</span><input type="text" data-input="slug" autocomplete="off" autocapitalize="off" spellcheck="false"></label>
      <button type="button" class="btn danger-quiet" data-action="purge">Remove with passkey</button>
    </form>
  </details></section>`
}

export function workspaceCredentialsPage(shell: WorkspaceShell, data: CredentialsPageData): PageInput {
  const ws = shell.identity.workspace.slug
  const slugs = slugMap(data.projects)
  const count = (kind: string) => data.items.filter((i) => i.home.kind === kind).length
  const adds = creatableHomes(data.viewer, data.projects).length > 0
  return {
    title: "Credentials",
    viewer: null,
    workspace: shell,
    current: "credentials",
    boot: { page: "ws-credentials", member: data.viewer.member },
    body: html`${pageHead({
        title: "Credentials",
        lead: "What agents may use through this workspace. No page shows a value: the vault sends it on for an agent, or leases it to an allowed machine.",
        actions: adds ? html`<button type="button" class="btn primary" data-action="open-add" aria-haspopup="dialog">${icon("plus")}<span>Add a credential</span></button>` : undefined,
      })}
      ${data.viewer.held === true ? notice("warn", HELD_WORDS) : ""}
      ${adds ? addSheet(data, slugs) : ""}
      ${data.items.length
        ? html`<div class="toolbar"><label class="search">${icon("search")}<input type="search" data-input="search" placeholder="Search credentials" aria-label="Search credentials by name, service, account or host" autocomplete="off"><kbd>/</kbd></label></div>
          <div class="chips" data-region="chips" role="group" aria-label="Filter by home">
            <button type="button" class="chip" data-chip="all" data-value="" aria-pressed="true">All <span class="n">${data.items.length}</span></button>
            ${(["project", "workspace", "member"] as const).filter((k) => count(k) > 0).map((k) => html`<button type="button" class="chip" data-chip="group" data-value="${k}" aria-pressed="false">${k === "project" ? "Project" : k === "workspace" ? "Whole workspace" : "Only me"} <span class="n">${count(k)}</span></button>`)}
          </div>
          <section class="card"><ul class="rows" data-region="list">${data.items.map((i) => credentialRow(i, slugs, ws))}</ul>
          <div data-region="no-match" hidden>${emptyState("search", "Nothing matches", "Try another word, or All.")}</div></section>`
        : html`<section class="card">${emptyState("key", "No credentials yet", adds ? "Add one with the button above, or an agent asks for one with a link you fill in." : "An agent asks for one with a link you fill in.")}</section>`}
      ${manageListCard(data.viewer)}`,
  }
}

// ---------------------------------------------------------------- one credential

// The project environments whose variables point at this credential, as
// far as the viewer's projects list shows.
export function credentialReferences(slug: string, projects: readonly WorkspaceProject[]): { project: WorkspaceProject; env: string; name: string }[] {
  return projects.flatMap((p) => p.vars.filter((v) => v.item === slug).map((v) => ({ project: p, env: v.env, name: v.name })))
}

// What an owner looks for first: where it belongs, the service, its status
// and where it may go. Version, tags and the secrets' facts, which are for
// an investigator, are folded under Details.
function factsCard(item: WorkspaceItemDescription, slugs: ReadonlyMap<string, string>): Html {
  return html`<section class="card" aria-label="About this credential">
    ${item.description !== null ? html`<p class="desc">${cardText(item.description)}</p>` : ""}
    <dl class="kv facts">
      <dt>Belongs to</dt><dd>${belongsBadge(item, slugs)}</dd>
      <dt>Service</dt><dd>${cardText(serviceName(item))}${item.account !== null ? html` as ${cardText(item.account)}` : ""}</dd>
      <dt>Status</dt><dd>${itemStatusPill(item.status)}</dd>
      <dt>Last used</dt><dd>${item.lastUsedAt !== null ? timeTag(item.lastUsedAt) : "never"}</dd>
    </dl>
    <p class="eyebrow">May only go to</p>
    ${hostList(item.binding.hosts, leaseOnlyDelivery(item.kind, item.ceiling))}
    ${item.home.kind === "member" ? html`<p class="small muted" data-region="private-audit">${PRIVATE_AUDIT_WORDS}</p>` : ""}
    <details class="fold" data-region="details"><summary>${icon("chevronRight")}<span>Details</span></summary>
      <dl class="kv facts">
        <dt>Version</dt><dd>${item.version}</dd>
        <dt>Tags</dt><dd>${item.tags.length ? item.tags.map((t) => html`<span class="tag">${cardText(t)}</span>`) : html`<span class="muted">none</span>`}</dd>
      </dl>
      <p class="eyebrow">Secrets held</p>
      <ul class="fields">${item.secretFields.map((f) => html`<li><span class="field-name">${cardText(f.name)}</span> ${f.set ? html`<span class="field-facts">${f.length} characters${f.prefix ? html`, starts <code>${cardText(f.prefix)}</code>` : ""}, fingerprint <code>${cardText(f.fingerprint)}</code></span>` : html`<span class="muted">not set</span>`}</li>`)}</ul>
      <p class="small muted">Never shown. The fingerprint lets you match a leaked value without revealing it.</p>
    </details>
  </section>`
}

// The value a rotation or an adoption replaced, kept for a while: when it
// goes, who replaced it and when, which fields; Restore it for whoever may
// change the credential's value. The vault's refusals show as it words them.
function previousCard(item: HumanItemDescription, restore: boolean): Html {
  const previous = item.previous ?? null
  if (previous === null) return html``
  return html`<section class="card" aria-label="Previous value" data-region="previous">
    <p>Previous value kept until ${timeTag(previous.expiresAt)}, replaced by ${cardText(previous.replacedBy)} on ${timeTag(previous.replacedAt)}, fields: ${previous.fields.map((f, i) => html`${i === 0 ? "" : ", "}<code>${cardText(f)}</code>`)}.</p>
    ${restore ? html`<div class="manage-row"><p class="small muted">Restoring puts these fields back as they were; the value now in use is kept in its place.</p><button type="button" class="btn secondary" data-action="restore">Restore it with passkey</button></div>` : ""}
  </section>`
}

function dependencyWords(item: HumanItemDescription): Html {
  const connections = item.dependencies.filter((d) => d.role === "connection")
  const clients = item.dependencies.filter((d) => d.role === "client")
  return html`${connections.length ? html`<p class="small warn-text" data-region="dependent-connections">Connections that sign in through this client: ${cardText(joinWords(connections.map((d) => d.slug)))}. Deleting it disables them; moving it must keep them compatible or the vault refuses.</p>` : ""}${clients.length ? html`<p class="small muted" data-region="oauth-client">Signs in through the OAuth client ${cardText(joinWords(clients.map((d) => d.slug)))}.</p>` : ""}${item.hiddenDependencies ? html`<p class="small warn-text" data-region="hidden-dependants">Other connections you cannot see also depend on it.</p>` : ""}`
}

function referencesCard(item: HumanItemDescription, refs: ReturnType<typeof credentialReferences>, ws: string): Html {
  return html`<section class="card" aria-label="Used by" data-region="references">
    <div class="card-head"><h2>Used by</h2></div>
    ${refs.length
      ? html`<ul class="ref-list">${refs.map((r) => html`<li><a href="${workspaceHref(ws, `/projects/${encodeURIComponent(r.project.id)}#env-${r.env}`)}">${cardText(r.project.slug)}/${cardText(r.env)}</a> <code>${cardText(r.name)}</code></li>`)}</ul>`
      : html`<p class="muted">No variable you can see points at it.</p>`}
    ${item.dependencies.length ? html`<ul class="ref-list" data-region="dependencies">${item.dependencies.map((d) => html`<li><a href="${workspaceHref(ws, `/items/${encodeURIComponent(d.slug)}`)}"><code>${cardText(d.slug)}</code></a> <span class="muted small">${d.role === "connection" ? "connection through this client" : "its OAuth client"}</span></li>`)}</ul>` : ""}
    ${item.hiddenDependencies ? html`<p class="small muted">Other connections you cannot see depend on it.</p>` : ""}
  </section>`
}

// How a member gets a fresh secret into this item: a connection signs in
// again through POST /api/connect, a templated item asks for the secret
// through POST /api/intakes, both under the same slug so the vault replaces
// rather than adds. An item with no template can only be replaced by an
// agent's mehen request, which the vault treats as a rotation of the slug.
type ReplaceAction =
  | { kind: "connect"; provider: string; label: string }
  | { kind: "intake"; provider: string; label: string }
  | { kind: "agent"; command: string }
  | { kind: "none" }

function replaceAction(item: Pick<ItemDescription, "kind" | "provider" | "slug">): ReplaceAction {
  if (item.kind === "oauth-connection") {
    const provider = item.provider !== null ? getOAuthProvider(item.provider) : null
    return provider !== null ? { kind: "connect", provider: provider.id, label: `Reconnect ${provider.displayName}` } : { kind: "none" }
  }
  const template = item.provider !== null ? getTemplate(item.provider) : null
  if (template !== null && template.kind === item.kind) return { kind: "intake", provider: template.id, label: "Replace the secret" }
  return { kind: "agent", command: `mehen request ${item.kind} --name ${item.slug} --reason "replace the secret"` }
}

// How a fresh secret gets in: a connection signs in to its provider again
// (POST /connect under the same name is a reconnect), anything else is
// filled in through a new intake on the same name. Null for a connection
// whose provider the catalogue does not know: only its platform reconnects it.
export type CredentialRenewal = { starts: "connect"; provider: string; label: string; words: string } | { starts: "intake"; label: string; words: string }

export function credentialRenewal(item: Pick<WorkspaceItemDescription, "kind" | "provider" | "slug" | "account">): CredentialRenewal | null {
  const action = replaceAction(item)
  if (action.kind === "connect") return { starts: "connect", provider: action.provider, label: action.label, words: `Sign in again${item.account !== null ? ` as ${item.account}` : ""}: the vault keeps its name, where it belongs, its tags and its rules.` }
  if (item.kind === "oauth-connection") return null
  return { starts: "intake", label: "Replace", words: "Replace the secret: you fill in a new value and the old one stops working in the vault." }
}

// The reason a Needs you row (Reconnect, Review) brings someone here, with
// what clears it, at the top of the page.
// `renewal` is null when this viewer may not renew it.
function attentionNotice(item: WorkspaceItemDescription, renewal: CredentialRenewal | null): Html {
  const clears = renewal === null ? " Whoever manages where it belongs can clear it." : renewal.starts === "connect" ? " Reconnecting under Manage clears it." : " Replacing the secret under Manage clears it."
  if (item.status === "needs_reauth") return html`<div class="notice error" data-region="item-reconnect"><p><b>Needs reconnecting.</b> The provider stopped accepting its token, so agents cannot use it until someone signs in again.${clears}</p></div>`
  if (item.review !== undefined) return html`<div class="notice warn" data-region="item-review"><p><b>Needs review</b> since ${timeTag(item.review.since)}: ${cardText(item.review.reason)}.${clears}</p></div>`
  return html``
}

// "In web pages", for a kind fill can type, where
// BROWSER_FILL is on. The choice sets the ceiling to fill or relay, so it
// is offered only on a sign-in kind whose ceiling is one of the two; any
// other is never changed here. Sign-in pages carry signinOriginSources'
// marks; only an added one may be removed. A page of another service is
// typed into only after a person approves each time.
const SIGNIN_SOURCE_WORDS: Readonly<Record<SigninOriginSource, string>> = { address: "from its sign-in address", hosts: "from its hosts", added: "added" }
const FILL_CHOICE = { fill: html`<strong>Type it into the sign-in page</strong> mehen types it in only after checking the page's address. A script on that page, including one the agent runs, can read it.`, relay: html`<strong>Not at all</strong> Only you can use it.` }

// The browser adds rows of the same shape (client/pages/workspace.ts webPageNode).
function webPageRow(origin: string, sub: string | null, remove: "remove-signin-page" | "remove-type-into" | null): Html {
  return html`<li class="row" data-origin="${origin}"><span class="row-main"><span class="row-title"><code>${origin}</code></span>${sub !== null ? html`<span class="row-sub">${sub}</span>` : ""}</span>${remove !== null ? html`<span class="row-side"><button type="button" class="btn danger-quiet sm" data-action="${remove}" data-origin="${origin}">Remove</button></span>` : ""}</li>`
}

function webPagesCard(item: HumanItemDescription, update: boolean): Html {
  const fill = KINDS[item.kind].fill
  if (fill.length === 0) return html``
  const signIn = fill.some((f) => f.signIn)
  const choice = signIn && (item.ceiling === "relay" || item.ceiling === "fill")
  const signinPages = signinOriginSources({ publicFields: item.publicFields, binding: item.binding, browser: item.browser ?? null })
  const typeInto = item.browser?.typeInto ?? []
  const how = !signIn
    ? deviceModeAllowed(item.ceiling, "fill") ? html`` : html`<p class="small muted" data-region="web-not-allowed">Agents cannot type it anywhere until its ceiling allows typing into web pages.</p>`
    : !choice
      ? html`<p class="small muted" data-region="web-ceiling-fixed">Its ceiling, ${MODE_WORDS[item.ceiling].label.toLowerCase()}, already decides this.</p>`
      : update
        ? html`<div>${(["fill", "relay"] as const).map((c) => html`<label class="tick"><input type="radio" name="web-ceiling" data-input="web-ceiling" value="${c}"${item.ceiling === c ? html` checked` : ""}><span>${FILL_CHOICE[c]}</span></label>`)}</div>`
        : html`<p data-region="web-ceiling-shown"><strong>${item.ceiling === "fill" ? "Type it into the sign-in page" : "Not at all"}</strong></p>`
  const add = (input: string, action: string, label: string, placeholder: string) => update
    ? html`<div class="web-page-add"><label class="field"><span class="label">${label}</span><input type="text" class="mono" data-input="${input}" placeholder="${placeholder}" autocomplete="off" autocapitalize="off" spellcheck="false"></label>
      <button type="button" class="btn secondary sm" data-action="${action}">${icon("plus")}<span>${label}</span></button></div>`
    : ""
  return html`<section class="card" aria-label="In web pages" data-region="in-web-pages"><div class="card-head"><h2>In web pages</h2></div>
    ${signIn ? html`<fieldset class="field" data-region="web-ceiling"><legend class="label">How agents may use it</legend>${how}</fieldset>` : how}
    ${signIn
      ? html`<p class="eyebrow web-pages-part">Sign-in pages</p>
        <ul class="rows" data-region="signin-pages">${signinPages.map((p) => webPageRow(p.origin, SIGNIN_SOURCE_WORDS[p.source], update && p.source === "added" ? "remove-signin-page" : null))}</ul>
        <p class="muted small" data-region="signin-pages-none"${signinPages.length > 0 ? html` hidden` : ""}>None</p>
        ${add("signin-page", "add-signin-page", "Add a sign-in page", "https://login.example.com")}`
      : ""}
    <p class="eyebrow web-pages-part">May also be typed into</p>
    <ul class="rows" data-region="type-into">${typeInto.map((origin) => webPageRow(origin, null, update ? "remove-type-into" : null))}</ul>
    <p class="muted small" data-region="type-into-none"${typeInto.length > 0 ? html` hidden` : ""}>None</p>
    ${update ? html`${add("type-into", "add-type-into", "Add a page", "https://dash.example.com")}
      <p class="small warn-text" data-region="type-into-warning" hidden>${TYPE_INTO_WARNING}</p>
      <div class="manage-row web-pages-part"><p class="small muted">Turns on once something here changes.</p><button type="button" class="btn primary" data-action="save-web-pages" disabled>${icon("passkey")}<span>Save with passkey</span></button></div>` : ""}
  </section>`
}

// Replace and move under Manage; delete in its own danger zone below, as an
// outline button in a fold: the passkey prompt is the confirmation.
function manageCard(data: CredentialPageData, refs: ReturnType<typeof credentialReferences>, slugs: ReadonlyMap<string, string>): Html {
  const { item, viewer } = data
  const controls = credentialControls(viewer, item.home, data.projects, [...new Set(refs.map((r) => r.project.id))])
  const renewal = controls.rotate ? credentialRenewal(item) : null
  if (renewal === null && !controls.delete && controls.rehomeTo.length === 0) return html``
  const dependants = html`${refs.length ? html`<p class="small warn-text">Variables that use it now: ${cardText(joinWords(refs.map((r) => `${r.project.slug}/${r.env} ${r.name}`)))}.</p>` : ""}${dependencyWords(item)}`
  const manage = renewal !== null || controls.rehomeTo.length > 0
  return html`${manage ? html`<section class="card" aria-label="Manage" data-region="manage">
    <div class="card-head"><h2>Manage</h2></div>
    ${renewal !== null ? html`<div class="manage-row"><p>${renewal.words}</p><button type="button" class="btn secondary" data-action="rotate" data-starts="${renewal.starts}"${renewal.starts === "connect" ? html` data-provider="${renewal.provider}"` : ""}>${icon("refresh")}<span>${renewal.label}</span></button></div>` : ""}
    ${controls.rehomeTo.length
      ? html`<details class="fold edit" data-region="rehome"><summary>${icon("chevronRight")}<span>Change where it belongs</span></summary>
          <form class="stack" data-form="rehome" novalidate>
            <fieldset class="field"><legend class="label">Belongs to</legend>${controls.rehomeTo.map(
              (h, i) => html`<label class="tick"><input type="radio" name="rehome" data-input="rehome" value="${h.kind === "project" ? `project:${h.project}` : h.kind}"${i === 0 ? html` checked` : ""}><span>${belongsToWords(h, slugs)}</span></label>`,
            )}</fieldset>
            <p class="small warn-text" data-region="rehome-warning">${REHOME_WARNING}</p>
            ${dependants}
            <button type="button" class="btn primary" data-action="rehome">Move with passkey</button>
          </form></details>`
      : ""}
  </section>` : ""}
  ${controls.delete
    ? html`<section class="card danger-zone" aria-label="Danger zone" data-region="danger-zone"><div class="card-head"><h2>Danger zone</h2></div>
        <details class="fold" data-region="delete"><summary>${icon("chevronRight")}<span>Delete this credential</span></summary>
          <div class="stack"><p>Deleting it unsets every variable that uses it and ends the approvals and runs that depend on it.</p>${dependants}${data.pushes === true ? pushDeleteWords(item) : ""}
          <button type="button" class="btn danger-quiet" data-action="delete">Delete ${cardText(item.slug)} with passkey</button></div></details></section>`
    : ""}`
}

export function workspaceCredentialPage(shell: WorkspaceShell, data: CredentialPageData): PageInput {
  const ws = shell.identity.workspace.slug
  const { item } = data
  const slugs = slugMap(data.projects)
  const refs = credentialReferences(item.slug, data.projects)
  const rulesLine = credentialRulesLine(ws, data.rules)
  const controls = credentialControls(data.viewer, item.home, data.projects, [...new Set(refs.map((r) => r.project.id))])
  const webPages = data.fill === true && KINDS[item.kind].fill.length > 0
  // What the card's Save compares with: only for someone who may change it.
  const web = webPages && controls.update ? { web: { ceiling: item.ceiling, signinOrigins: item.browser?.signinOrigins ?? [], typeInto: item.browser?.typeInto ?? [] } } : {}
  return {
    title: item.slug,
    viewer: null,
    workspace: shell,
    current: "credentials",
    ...(rulesLine !== undefined ? { policyRules: rulesLine } : {}),
    boot: { page: "ws-credential", slug: item.slug, home: item.home, id: item.id, version: item.version, configRevision: item.configRevision, dependencyRevision: item.dependencyRevision, ...(item.previous ? { previous: item.previous.version } : {}), ...web },
    body: html`${pageHead({ tile: serviceTile(item, "xl"), eyebrow: "Credential", title: cardText(item.slug), lead: html`${cardText(serviceName(item))}${item.account !== null ? html` as ${cardText(item.account)}` : ""}` })}
      ${data.viewer.held === true ? notice("warn", HELD_WORDS) : ""}
      ${attentionNotice(item, controls.rotate ? credentialRenewal(item) : null)}
      ${factsCard(item, slugs)}${previousCard(item, controls.rotate)}
      ${webPages ? webPagesCard(item, controls.update) : ""}${postureCard({ item, viewer: data.viewer, standingRules: data.rules?.rules.some((r) => !isGrant(r) && r.status === "active") ?? false, rulesCard: data.rules !== undefined && hasActiveRule(data.rules.rules) })}${policyRulesCard(ws, data.rules, data.projects)}${data.pushes === true ? html`${pushAllowanceCard(item, controls.update)}${pushedToCard(item, canPushAgain(data.viewer, item.home, data.projects), data.projects)}` : ""}${referencesCard(item, refs, ws)}
      ${manageCard(data, refs, slugs)}`,
  }
}
