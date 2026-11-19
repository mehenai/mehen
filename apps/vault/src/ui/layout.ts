// The page shell every UI route renders into, and the response headers that
// go with it. The client bundle finds its page and ids in `data-boot` on
// <main>, so no page ever needs an inline script.
//
// Two shells: the app shell (a rail from 1140 px, a top bar below that, a
// tab bar on the phone) for the pages a member browses to, and the focus
// shell (brand and one Home link) for the pages a link lands on and for
// anyone not signed in.

import type { ApiError } from "@mehen/protocol/api"
import { escapeDeceptiveJson } from "../relay/presentation.ts"
import { timedSync } from "../server-timing.ts"
import { spellCardText } from "../relay/spelling.ts"
import { cardText } from "./components.ts"
import { type Html, html, safeHref } from "./html.ts"
import { BRAND_SLUGS, type IconName, brandLogo, icon, vaultMark } from "./icons.ts"
import { type PolicyRulesLine, policyRulesLine } from "./policy-indicator.ts"
import { ACCOUNT_NAV, type AccountPageKey, type AccountShell, MORE_PAGES, PHONE_TABS, WORKSPACE_NAV, type WorkspaceNavItem, type WorkspaceShell, accountLinkKeys, identityLine, workspaceHref, workspaceSwitcher } from "./shell.ts"

export const PAGE_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

export const VAULT_TITLE = "Mehen"

// The lockup's wordmark: lowercase, as the identity board sets it.
export const WORDMARK = "mehen"

// The docs live on their own site; every Docs link in the shell goes there,
// in the same tab.
export const DOCS_HOME = "https://docs.mehen.dev/"

export type Viewer = { name: string; tenantName: string | null; role: "owner" | "member" }

export type Boot = { page: string; [key: string]: unknown }

export type Current = "home" | "needs" | "credentials" | "machines" | "rules" | "projects" | "people" | "teams" | "connect-agent" | "audit" | "catalogue" | "settings" | "workspaces" | "account" | "operator" | "platforms"

// Rail links to surfaces whose routes other lanes add; off until they exist.
export type ShellLinks = { credentials?: boolean; catalogue?: boolean; settings?: boolean }

export type PageInput = {
  title: string
  viewer: Viewer | null
  boot: Boot
  body: Html
  // The focus shell: a link-landed page with the brand and one Home link.
  focus?: boolean
  current?: Current
  // Two columns from 900 px: the page is 1160 px wide instead of 760.
  wide?: boolean
  // A decision bar is fixed to the bottom; the page pads for it.
  bar?: boolean
  // How many things need the member now; the rail and the Home tab show
  // the count. Left out, the client fills it from /api/pending.
  pending?: number
  links?: ShellLinks
  // A credential's or machine's page, with POLICY_RULES on: the compact
  // line counting the viewer's own machines' standing rules there.
  policyRules?: PolicyRulesLine
  // A page inside one workspace: the workspace shell (switcher, rail of the
  // workspace's served pages) instead of the legacy one, and `shell` in the
  // boot payload. `viewer` is null on these pages.
  workspace?: WorkspaceShell
  // A page about the account itself, outside every workspace (the picker,
  // the account page): the focus shell with the account's links.
  account?: AccountShell
}

type NavItem = { id: Current; label: string; icon: IconName; href: string }

const TABS: NavItem[] = [
  { id: "home", label: "Home", icon: "home", href: "/" },
  { id: "credentials", label: "Credentials", icon: "key", href: "/credentials" },
  { id: "machines", label: "Machines", icon: "cpu", href: "/devices" },
  { id: "projects", label: "Projects", icon: "folder", href: "/projects" },
  { id: "audit", label: "Audit", icon: "list", href: "/audit" },
]

function current(item: Current, page: PageInput): Html {
  return page.current === item ? html` aria-current="page"` : html``
}

function navLink(item: NavItem, page: PageInput, withIcon: boolean, extra: Html = html``): Html {
  return html`<a href="${item.href}"${current(item.id, page)}>${withIcon ? icon(item.icon) : ""}<span>${item.label}</span>${extra}</a>`
}

export function initialOf(name: string): string {
  const first = Array.from(name.trim())[0] ?? "?"
  return first.toUpperCase()
}

export function brandLockup(sub: string | null): Html {
  return html`<a class="brand" href="/">${vaultMark()}<span class="brand-text"><span class="brand-name">${WORDMARK}</span>${sub !== null ? html`<span class="brand-sub">${sub}</span>` : ""}</span></a>`
}

function pendingCount(page: PageInput): Html {
  if (page.pending === undefined) return html`<b class="count" data-region="pending-count" data-fill hidden></b>`
  const n = page.pending
  return html`<b class="count" data-region="pending-count"${n > 0 ? "" : html` hidden`}>${n > 0 ? n : ""}</b>`
}

function homeCount(item: NavItem, page: PageInput): Html {
  return item.id === "home" ? pendingCount(page) : html``
}

// /credentials (V-16) and /settings (V-20) exist, so their links are on
// unless a page says otherwise.
function shellLinks(page: PageInput): ShellLinks {
  return { credentials: true, settings: true, catalogue: true, ...page.links }
}

// The tabs a page shows: Credentials only while its route is on.
function tabs(page: PageInput): NavItem[] {
  const links = shellLinks(page)
  return TABS.filter((t) => t.id !== "credentials" || links.credentials)
}

function rail(viewer: Viewer, page: PageInput): Html {
  const links = shellLinks(page)
  const [home, ...rest] = tabs(page)
  return html`<aside class="rail" aria-label="Vault">
  ${brandLockup(viewer.tenantName)}
  <button type="button" class="search-btn" data-action="palette">${icon("search")}<span>Search</span><kbd>⌘K</kbd></button>
  <nav class="rail-nav" aria-label="Pages">
    ${navLink(home as NavItem, page, true)}
    <a href="/#needs-you"${current("needs", page)}>${icon("bell")}<span>Needs you</span>${pendingCount(page)}</a>
    ${rest.map((t) => navLink(t, page, true))}
  </nav>
  <nav class="rail-nav rail-foot" aria-label="More">
    ${links.catalogue ? html`<a href="/connect"${current("catalogue", page)}>${icon("grid")}<span>Connect a service</span></a>` : ""}
    ${links.settings ? html`<a href="/settings"${current("settings", page)}>${icon("sliders")}<span>Settings</span></a>` : ""}
    <a href="${DOCS_HOME}" rel="noopener">${icon("book")}<span>Docs</span></a>
  </nav>
  <div class="rail-user">
    <span class="avatar" aria-hidden="true">${initialOf(viewer.name)}</span>
    <span class="user-text"><span class="user-name">${viewer.name}</span><span class="user-role">${viewer.role === "owner" ? "Owner" : "Member"}</span></span>
    <button type="button" class="icon-btn" data-action="signout" aria-label="Sign out">${icon("signout")}</button>
  </div>
</aside>`
}

function topBar(viewer: Viewer, page: PageInput): Html {
  const links = shellLinks(page)
  return html`<header class="top">
  ${brandLockup(viewer.tenantName)}
  <nav class="top-nav" aria-label="Pages">${tabs(page).map((t) => navLink(t, page, false, homeCount(t, page)))}</nav>
  <div class="top-tools">
    <button type="button" class="icon-btn" data-action="palette" aria-label="Search">${icon("search")}</button>
    ${links.catalogue ? html`<a class="icon-btn" href="/connect" aria-label="Connect a service">${icon("plus")}</a>` : ""}
    <a class="icon-btn" href="${DOCS_HOME}" rel="noopener" aria-label="Docs">${icon("book")}</a>
    ${links.settings ? html`<a class="avatar" href="/settings" aria-label="${viewer.name}, settings">${initialOf(viewer.name)}</a>` : ""}
    <button type="button" class="icon-btn" data-action="signout" aria-label="Sign out">${icon("signout")}</button>
  </div>
</header>`
}

function tabBar(page: PageInput): Html {
  return html`<nav class="tabs" aria-label="Vault">${tabs(page).map((t) => navLink(t, page, true, homeCount(t, page)))}</nav>`
}

// ---------------------------------------------------------------- workspace shell

// The account-wide Needs you count: rendered hidden and empty, and filled
// only by the client's poll of GET /api/needs-you (client/pages/needs-you.ts),
// so no page ever shows a count it did not just read, nor a zero.
const NEEDS_COUNT = html`<b class="count" data-region="pending-count" data-fill hidden></b>`

function navServed(shell: WorkspaceShell, item: WorkspaceNavItem): boolean {
  return item.account !== undefined ? shell.accountPages.includes(item.account) : shell.pages.includes(item.key)
}

function workspaceNav(shell: WorkspaceShell): WorkspaceNavItem[] {
  return WORKSPACE_NAV.filter((item) => navServed(shell, item))
}

function navHref(shell: WorkspaceShell, item: WorkspaceNavItem): string {
  return item.account !== undefined ? ACCOUNT_NAV[item.account].path : workspaceHref(shell.identity.workspace.slug, item.path)
}

// People is current on the Teams page too: Teams is its segment.
function navCurrent(item: WorkspaceNavItem, page: PageInput): boolean {
  return page.current === item.key || (item.key === "people" && page.current === "teams")
}

function workspaceLink(shell: WorkspaceShell, item: WorkspaceNavItem, page: PageInput, withIcon: boolean): Html {
  return html`<a href="${navHref(shell, item)}"${navCurrent(item, page) ? html` aria-current="page"` : ""}>${withIcon ? icon(item.icon) : ""}<span>${item.label}</span>${item.key === "needs" ? NEEDS_COUNT : ""}</a>`
}

function workspaceBrand(shell: WorkspaceShell): Html {
  return html`<a class="brand" href="${workspaceHref(shell.identity.workspace.slug)}">${vaultMark()}<span class="brand-text"><span class="brand-name">${WORDMARK}</span></span></a>`
}

function accountLinks(pages: AccountShell["accountPages"]): Html {
  return html`${accountLinkKeys(pages).map((key) => html`<a href="${ACCOUNT_NAV[key].path}">${icon(ACCOUNT_NAV[key].icon)}<span>${ACCOUNT_NAV[key].label}</span></a>`)}`
}

// Connect an agent (an action, not a place) and Settings, while served.
function railActions(shell: WorkspaceShell, page: PageInput): Html {
  return html`${MORE_PAGES.filter((item) => item.key !== "teams" && shell.pages.includes(item.key)).map((item) => workspaceLink(shell, item, page, true))}`
}

function workspaceRail(shell: WorkspaceShell, page: PageInput): Html {
  return html`<aside class="rail" aria-label="Workspace">
  ${workspaceBrand(shell)}
  ${workspaceSwitcher(shell)}
  <button type="button" class="search-btn" data-action="palette">${icon("search")}<span>Search</span><kbd>⌘K</kbd></button>
  <nav class="rail-nav" aria-label="Pages">${workspaceNav(shell).map((item) => workspaceLink(shell, item, page, true))}</nav>
  <nav class="rail-nav rail-foot" aria-label="More">
    ${railActions(shell, page)}
    ${accountLinks(shell.accountPages)}
    <a href="${DOCS_HOME}" rel="noopener">${icon("book")}<span>Docs</span></a>
  </nav>
  <div class="rail-user">
    <span class="avatar" aria-hidden="true">${initialOf(shell.accountName)}</span>
    <span class="user-text"><span class="user-name">${cardText(shell.accountName)}</span></span>
    <button type="button" class="icon-btn" data-action="signout" aria-label="Sign out">${icon("signout")}</button>
  </div>
</aside>`
}

function workspaceTopBar(shell: WorkspaceShell, page: PageInput): Html {
  return html`<header class="top">
  ${workspaceBrand(shell)}
  ${workspaceSwitcher(shell)}
  <nav class="top-nav" aria-label="Pages">${workspaceNav(shell).map((item) => workspaceLink(shell, item, page, false))}</nav>
  <div class="top-tools">
    <button type="button" class="icon-btn" data-action="palette" aria-label="Search">${icon("search")}</button>
    <a class="icon-btn" href="${DOCS_HOME}" rel="noopener" aria-label="Docs">${icon("book")}</a>
    <button type="button" class="icon-btn" data-action="signout" aria-label="Sign out">${icon("signout")}</button>
  </div>
</header>`
}

// The phone's tab bar: Home, Needs you, Credentials and Projects as served,
// then More, a disclosure whose list holds every other page and the
// account's links. It opens without a script; the client adds Escape, a
// tap outside and Tab past the end to close it (client/shell.ts).
function workspaceTabBar(shell: WorkspaceShell, page: PageInput): Html {
  const nav = workspaceNav(shell)
  const tabs = nav.filter((item) => PHONE_TABS.includes(item.key))
  // Teams sits beside People, its other segment; then the rail's actions.
  const extra = MORE_PAGES.filter((item) => shell.pages.includes(item.key))
  const rest = nav.filter((item) => !PHONE_TABS.includes(item.key)).flatMap((item) => (item.key === "people" ? [item, ...extra.filter((e) => e.key === "teams")] : [item]))
  rest.push(...extra.filter((e) => !rest.includes(e)))
  const here = rest.some((item) => navCurrent(item, page) || page.current === item.key)
  return html`<nav class="tabs" aria-label="Workspace">${tabs.map((item) => workspaceLink(shell, item, page, true))}<details class="more-sheet" data-region="more-sheet">
  <summary${here ? html` aria-current="page"` : ""}>${icon("more")}<span>More</span></summary>
  <div class="more-panel" data-region="more-panel">
    <ul class="more-list">
      ${rest.map((item) => html`<li>${workspaceLink(shell, item, page, true)}</li>`)}
      ${accountLinkKeys(shell.accountPages).map((key) => html`<li><a href="${ACCOUNT_NAV[key].path}">${icon(ACCOUNT_NAV[key].icon)}<span>${ACCOUNT_NAV[key].label}</span></a></li>`)}
      <li><a href="${DOCS_HOME}" rel="noopener">${icon("book")}<span>Docs</span></a></li>
      <li><button type="button" data-action="signout">${icon("signout")}<span>Sign out</span></button></li>
    </ul>
  </div>
</details></nav>`
}

// People and Teams are one place with two segments: on either page, a
// two-segment control at the top of the page, while both are served.
function peopleSegments(shell: WorkspaceShell, page: PageInput): Html {
  if ((page.current !== "people" && page.current !== "teams") || !shell.pages.includes("people") || !shell.pages.includes("teams")) return html``
  const segment = (key: "people" | "teams", label: string, path: string) => html`<a href="${workspaceHref(shell.identity.workspace.slug, path)}"${page.current === key ? html` aria-current="page"` : ""}>${label}</a>`
  return html`<nav class="segments" aria-label="People and teams" data-region="people-segments">${segment("people", "People", "/people")}${segment("teams", "Teams", "/teams")}</nav>`
}

// The boot payload's `shell`: what the client keys its caches and checks
// its calls by. Built from the resolver's identity only.
export type ShellBoot = { origin: string; account: string; workspace: { id: string; slug: string; name: string }; pages: string[]; reads: string[] }

export function shellBoot(shell: WorkspaceShell): ShellBoot {
  const { origin, account, workspace } = shell.identity
  return { origin, account, workspace: { id: workspace.id, slug: workspace.slug, name: workspace.name }, pages: [...shell.pages], reads: [...shell.reads] }
}

// A link-landed page inside a workspace (an ask): the brand, whose
// workspace this is with its slug and origin, and the way to its home.
function workspaceFocusTop(shell: WorkspaceShell): Html {
  return html`<header class="top focus-top">
  ${brandLockup(null)}
  <span class="focus-identity">${identityLine(shell.identity)}</span>
  <a class="top-link" href="${workspaceHref(shell.identity.workspace.slug)}">${icon("home")}<span>Home</span></a>
</header>`
}

// The account pages' own current link: the open page's key.
const ACCOUNT_CURRENT: Readonly<Record<AccountPageKey, Current>> = { workspaces: "workspaces", "needs-you": "needs", account: "account", operator: "operator", platforms: "platforms" }

// The account pages' top bar: All workspaces, Needs you with the
// account-wide count, Your account and Docs, the open one marked.
function accountTop(account: AccountShell, page: PageInput): Html {
  return html`<header class="top focus-top account-top">
  ${brandLockup(null)}
  <nav class="top-nav account-nav" aria-label="Account">${account.accountPages.map((key) => html`<a class="top-link" href="${ACCOUNT_NAV[key].path}"${page.current === ACCOUNT_CURRENT[key] ? html` aria-current="page"` : ""}>${ACCOUNT_NAV[key].short === ACCOUNT_NAV[key].label ? ACCOUNT_NAV[key].label : html`<span class="label-long">${ACCOUNT_NAV[key].label}</span><span class="label-short">${ACCOUNT_NAV[key].short}</span>`}${key === "needs-you" ? NEEDS_COUNT : ""}</a>`)}<a class="top-link docs-link" href="${DOCS_HOME}" rel="noopener">Docs</a></nav>
  <button type="button" class="icon-btn" data-action="signout" aria-label="Sign out">${icon("signout")}</button>
</header>`
}

function focusTop(viewer: Viewer | null): Html {
  return html`<header class="top focus-top">
  ${brandLockup(null)}
  ${viewer ? html`<a class="top-link" href="/">${icon("home")}<span>Home</span></a>` : ""}
</header>`
}

// The tiles the palette may show, as <template>s the client clones: every
// brand mark and the kind, machine and action icons. Nothing else in the
// palette is markup; the client builds the rest from text.
const PALETTE_ICONS: IconName[] = ["key", "link", "badge", "lock", "braces", "mail", "desktop", "tower", "laptop", "phone", "watch", "bell", "grid", "sliders", "list", "book", "users", "terminal", "snowflake"]

function paletteTiles(): Html {
  return html`<div data-region="palette-tiles" hidden>${BRAND_SLUGS.map((slug) => html`<template data-tile="brand:${slug}">${brandLogo(slug)}</template>`)}${PALETTE_ICONS.map((name) => html`<template data-tile="icon:${name}">${icon(name)}</template>`)}</div>`
}

// The command palette's shell, hidden until the client opens it. The list
// is empty here: the client fills it from the member's own reads.
function paletteMount(): Html {
  return html`<div class="palette-scrim" data-region="palette" hidden>
  <div class="palette" role="dialog" aria-modal="true" aria-label="Command palette">
    <div class="palette-input">${icon("search")}<input type="text" role="combobox" aria-expanded="false" aria-controls="palette-list" aria-autocomplete="list" aria-label="Search or run a command" placeholder="Search the vault" autocomplete="off" spellcheck="false"><kbd>esc</kbd><button type="button" class="icon-btn palette-close" data-action="close-palette" aria-label="Close">${icon("x")}</button></div>
    <div class="palette-list" id="palette-list" role="listbox" aria-label="Results"></div>
    <div class="palette-foot"><span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>↵</kbd> open</span><span><kbd>⌘</kbd><kbd>↵</kbd> open in a new tab</span><span><kbd>?</kbd> all shortcuts</span></div>
  </div>
  ${paletteTiles()}
</div>`
}

function keys(rows: readonly [string, Html][]): Html {
  return html`<div class="keys">${rows.map(([what, combo]) => html`<span>${what}</span><span class="combo">${combo}</span>`)}</div>`
}

const kbd = (...names: string[]): Html => html`${names.map((n) => html`<kbd>${n}</kbd>`)}`

const goKeys = (letter: string): Html => html`${kbd("G")} then ${kbd(letter)}`

// The `?` sheet: every shortcut, and the rule that none of them decides.
// The focus shell has no palette, so its sheet does not offer one.
const LEGACY_GO: readonly [string, string][] = [
  ["Go home", "H"],
  ["Go to Credentials", "C"],
  ["Go to Machines", "M"],
  ["Go to Projects", "P"],
  ["Go to Audit", "A"],
]

// The G keys a workspace page offers: only its served pages.
function workspaceGo(shell: WorkspaceShell): [string, string][] {
  const letters: Partial<Record<string, string>> = { home: "H", credentials: "C", machines: "M", projects: "P", audit: "A" }
  return workspaceNav(shell).flatMap((item): [string, string][] => {
    const letter = letters[item.key]
    return letter === undefined ? [] : [[item.key === "home" ? "Go home" : `Go to ${item.label}`, letter]]
  })
}

function shortcutsSheet(withPalette: boolean, go: readonly [string, string][] = LEGACY_GO): Html {
  return html`<div class="palette-scrim" data-region="shortcuts" hidden>
  <div class="palette sheet-keys" role="dialog" aria-modal="true" aria-labelledby="shortcuts-title">
    <div class="sheet-head"><h2 id="shortcuts-title">Keyboard shortcuts</h2><button type="button" class="icon-btn" data-action="close-shortcuts" aria-label="Close">${icon("x")}</button></div>
    <h3>Anywhere</h3>
    ${keys([
      ...(withPalette ? [["Command palette", kbd("⌘", "K")] as [string, Html]] : []),
      ["Search this list", kbd("/")],
      ...go.map(([what, letter]): [string, Html] => [what, goKeys(letter)]),
      ["Next and previous row", kbd("J", "K")],
      ["Open the selected row", kbd("↵")],
      ["This sheet", kbd("?")],
    ])}
    <h3>On an approval</h3>
    <p class="muted small">Nothing on the keyboard approves. These move focus; the passkey still confirms.</p>
    ${keys([
      ["Focus the binding-code tick", kbd("T")],
      ["Jump to the whole truth", kbd("W")],
      ["Focus Deny", kbd("D")],
      ["Focus Approve, when it is enabled", kbd("Y")],
    ])}
    <p class="muted small">On a phone none of this applies: the tab bar and the decision bar are the shortcuts${withPalette ? ", and the palette opens from the search icon" : ""}.</p>
  </div>
</div>`
}

function mainBlock(page: PageInput): Html {
  const boot =
    page.workspace !== undefined
      ? { ...page.boot, shell: shellBoot(page.workspace) }
      : page.account !== undefined
        ? { ...page.boot, signedIn: { origin: page.account.origin, account: page.account.account } }
        : page.boot
  return html`<main id="app" class="page${page.wide ? " wide" : ""}" data-boot="${escapeDeceptiveJson(JSON.stringify(boot))}">

${page.policyRules !== undefined ? policyRulesLine(page.policyRules) : ""}<div id="notice" class="notice" role="alert" aria-live="assertive" hidden></div>
${page.workspace !== undefined && page.focus !== true ? peopleSegments(page.workspace, page) : ""}
${page.body}
</main>`
}

function documentShell(input: PageInput, focus: boolean): Html {
  const workspace = input.workspace
  if (workspace !== undefined && !focus) {
    return html`<div class="frame">
${workspaceRail(workspace, input)}
<div class="content">
${workspaceTopBar(workspace, input)}
${mainBlock(input)}
</div>
</div>
${workspaceTabBar(workspace, input)}
${paletteMount()}
${shortcutsSheet(true, workspaceGo(workspace))}`
  }
  if (workspace !== undefined) {
    return html`${workspaceFocusTop(workspace)}
${mainBlock(input)}
${shortcutsSheet(false, [])}`
  }
  if (input.account !== undefined) {
    return html`${accountTop(input.account, input)}
${mainBlock(input)}`
  }
  return focus
    ? html`${focusTop(input.viewer)}
${mainBlock(input)}
${input.viewer ? shortcutsSheet(false) : ""}`
    : html`<div class="frame">
${rail(input.viewer as Viewer, input)}
<div class="content">
${topBar(input.viewer as Viewer, input)}
${mainBlock(input)}
</div>
</div>
${tabBar(input)}
${paletteMount()}
${shortcutsSheet(true)}`
}

// The tab's title: the page, then on a workspace page the
// workspace's name with its slug, then Mehen, joined by middle dots. The
// slug stays so two workspaces with one name never share a tab title; the
// name is spelled, so a hidden character shows as its marker words.
export function documentTitle(input: Pick<PageInput, "title" | "workspace">): string {
  const workspace = input.workspace?.identity.workspace
  return [input.title, ...(workspace !== undefined ? [`${spellCardText(workspace.name)} (${workspace.slug})`] : []), VAULT_TITLE].join(" · ")
}

export function renderDocument(input: PageInput): Html {
  const focus = input.focus === true || (input.viewer === null && input.workspace === undefined)
  const bodyClass = [focus ? "focus" : "app", input.bar ? "has-bar" : ""].filter(Boolean).join(" ")
  const shell = documentShell(input, focus)
  return html`<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light">
<meta name="theme-color" content="#f3ead8">
<meta name="referrer" content="no-referrer">
<title>${documentTitle(input)}</title>
<link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/assets/apple-touch-icon.png">
<link rel="preload" href="/assets/fonts/Inter-normal-100-900.woff2" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="/assets/fonts/Fraunces-normal-100-900.woff2" as="font" type="font/woff2" crossorigin>
<script src="/assets/theme.js"></script>
<link rel="stylesheet" href="/assets/app.css">
<script type="module" src="/assets/app.js"></script>
</head>
<body class="${bodyClass}">
${shell}
</body>
</html>
`
}

export function pageResponse(page: PageInput, status = 200): Response {
  return new Response(timedSync("render", () => renderDocument(page).value), {
    status,
    headers: { "content-type": "text/html; charset=utf-8", "content-security-policy": PAGE_CSP },
  })
}

export function redirect(location: string, status = 302): Response {
  return new Response(null, { status, headers: { location, "content-security-policy": PAGE_CSP } })
}

export const ERROR_HEADING = "This page could not be shown"

// The next step on a page whose subject the vault did not find (or will
// not say exists to this person), when the vault gave none.
export const NOT_FOUND_NEXT = "Check the link. What it pointed to may have been removed, or be one only someone else can open."

// A refusal or failure as a page. Signing in again is routine, so it gets a
// plain card and a passkey button; anything else is red. A failure the
// vault gave no next step for says to reload, a miss to check the link,
// and every error page links home, where the Freeze brake is.
export function errorBody(error: ApiError, heading = ERROR_HEADING, status = 0): Html {
  const next = error.next
  const signin = error.error === "unauthenticated"
  const href = next?.url !== undefined ? safeHref(next.url) : "#"
  const url = href === "#" ? null : href
  const say = next?.say ?? (status >= 500 ? "Reload the page to try again." : error.error === "not_found" ? NOT_FOUND_NEXT : null)
  return html`<section class="card${signin ? "" : " error-card"}">
    <h1>${heading}</h1>
    <p class="lead">${error.message}</p>
    ${say !== null ? html`<p>${say}</p>` : ""}
    ${url !== null ? html`<p><a class="button primary" href="${url}">${signin ? "Sign in with a passkey" : url === "/" ? "Go to the vault's home" : "Continue"}</a></p>` : ""}
    ${next?.command ? html`<p>Or run <code>${next.command}</code></p>` : ""}
    ${url !== "/" && !signin ? html`<p><a href="/">Back to the vault</a></p>` : ""}
  </section>`
}

export function errorPageInput(viewer: Viewer | null, status: number, error: ApiError, heading = ERROR_HEADING): PageInput {
  return { title: heading, viewer, boot: { page: "error" }, body: errorBody(error, heading, status) }
}

export function errorPage(viewer: Viewer | null, status: number, error: ApiError, heading = ERROR_HEADING): Response {
  return pageResponse(errorPageInput(viewer, status, error, heading), status)
}

// An address the vault has no page for, asked for by a browser.
export const NOT_FOUND_ERROR: ApiError = { error: "not_found", message: "There is no page at this address.", next: { url: "/", say: "Check the address and try again." } }

export const SESSION_ENDED_HEADING = "Sign in to continue"

// A page whose read the vault refused for want of a session; `path` is the
// page, which /signin returns to.
export function sessionEndedError(path: string): ApiError {
  return { error: "unauthenticated", message: "Your session has ended.", next: { url: `/signin?next=${encodeURIComponent(path)}`, say: "Sign in with your passkey and the vault brings you back to this page." } }
}
