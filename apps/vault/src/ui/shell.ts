// The workspace shell's identity and switcher. Every workspace page carries
// the authenticated workspace (id, canonical slug, name), the vault's origin
// and the account, from the resolver, never from a name: names repeat and
// change, so wherever identity matters the page shows the slug and origin
// beside the name, and every link and cache key is built from the slug or id.

import type { MembershipView, WorkspaceRef, WorkspaceRole } from "@mehen/protocol/workspace"
import { spellCardText } from "../relay/spelling.ts"
import { cardText } from "./components.ts"
import { type Html, html } from "./html.ts"
import type { IconName } from "./icons.ts"

// What the resolver authenticated for this page: the boot payload's `shell`.
export type ShellIdentity = { origin: string; account: string; workspace: WorkspaceRef }

// The workspace pages the shell can link to, by key. A key is in a page's
// `pages` only while its route is served, so the rail never links to a page
// that does not exist yet.
// "asks" is the ask pages (/a, /i, /c, /e, /p): not in the rail, but the
// palette links to them. "needs" is /w/<slug>/pending, the one-workspace
// filter of Needs you.
export type WorkspacePageKey = "home" | "needs" | "credentials" | "machines" | "rules" | "projects" | "people" | "teams" | "connect-agent" | "audit" | "settings" | "asks"

// The account pages, outside any workspace. "needs-you" is the account
// inbox, which every shell links to as Needs you. "operator" and
// "platforms" are the consoles: listed only for an account the operator
// script flagged, or one that administers a platform (CONSOLE_PAGES).
export type AccountPageKey = "workspaces" | "needs-you" | "account" | ConsolePageKey

export const CONSOLE_PAGES = ["operator", "platforms"] as const
export type ConsolePageKey = (typeof CONSOLE_PAGES)[number]

export type WorkspaceShell = {
  identity: ShellIdentity
  accountName: string
  // Every membership of the account, from GET /api/account; null while that
  // read is not served, when the switcher shows only this workspace.
  memberships: readonly MembershipView[] | null
  pages: readonly WorkspacePageKey[]
  // The palette's workspace reads (palette-logic.ts PALETTE_READS) served.
  reads: readonly string[]
  accountPages: readonly AccountPageKey[]
  // The account is restricted after a recovery, or a security change is
  // still reaching its workspaces (or the account read failed): pages offer
  // nothing that widens or changes people. The server refuses it anyway.
  accountHeld: boolean
}

export type AccountShell = { origin: string; account: string; name: string; accountPages: readonly AccountPageKey[] }

// `path` is under /w/<slug>, except for an item that is an account page
// (`account`), whose address is that page's own: Needs you is the account
// inbox at /needs-you from every workspace, shown while it is served.
export type WorkspaceNavItem = { key: WorkspacePageKey; label: string; icon: IconName; path: string; account?: AccountPageKey }

// The rail's and top bar's pages in order. Teams has no entry of its own:
// it is a segment of People, and People is current on either page.
export const WORKSPACE_NAV: readonly WorkspaceNavItem[] = [
  { key: "home", label: "Home", icon: "home", path: "/" },
  { key: "needs", label: "Needs you", icon: "bell", path: "/needs-you", account: "needs-you" },
  { key: "credentials", label: "Credentials", icon: "key", path: "/credentials" },
  { key: "projects", label: "Projects", icon: "folder", path: "/projects" },
  { key: "machines", label: "Machines", icon: "cpu", path: "/devices" },
  { key: "rules", label: "My rules", icon: "shield", path: "/rules" },
  { key: "people", label: "People", icon: "users", path: "/people" },
  { key: "audit", label: "Activity", icon: "list", path: "/audit" },
]

// The phone's tab bar: these four, then More for everything else.
export const PHONE_TABS: readonly WorkspacePageKey[] = ["home", "needs", "credentials", "projects"]

// What the More sheet lists after the rail's other pages, in order.
export const MORE_PAGES: readonly WorkspaceNavItem[] = [
  { key: "teams", label: "Teams", icon: "grid", path: "/teams" },
  { key: "connect-agent", label: "Connect an agent", icon: "terminal", path: "/connect-agent" },
  { key: "settings", label: "Settings", icon: "sliders", path: "/settings" },
]

// `short` is the label the account pages' top bar uses on a small phone;
// `icon` the one a workspace's rail and More sheet show beside it.
export const ACCOUNT_NAV: Readonly<Record<AccountPageKey, { label: string; short: string; path: string; icon: IconName }>> = {
  workspaces: { label: "All workspaces", short: "Workspaces", path: "/workspaces", icon: "grid" },
  "needs-you": { label: "Needs you", short: "Needs you", path: "/needs-you", icon: "bell" },
  account: { label: "Your account", short: "Account", path: "/account", icon: "shield" },
  operator: { label: "Operator", short: "Operator", path: "/operator", icon: "badge" },
  platforms: { label: "Platforms", short: "Platforms", path: "/platforms", icon: "globe" },
}

// The account links in a workspace's rail foot, switcher and More sheet:
// Needs you is a page of the rail itself there.
export function accountLinkKeys(pages: readonly AccountPageKey[]): AccountPageKey[] {
  return pages.filter((key) => key !== "needs-you")
}

export const ROLE_WORDS: Readonly<Record<WorkspaceRole, string>> = { owner: "Owner", admin: "Admin", member: "Member", guest: "Guest" }

// /w/<slug><path>, from the canonical slug only.
export function workspaceHref(slug: string, path = "/"): string {
  return `/w/${encodeURIComponent(slug)}${path}`
}

// The same as plain text, for a document title or an accessible name: the
// name spelled, so a direction override or control character is a visible
// marker there too, never a raw character that could reorder the slug.
export function identityText(identity: Pick<ShellIdentity, "origin" | "workspace">): string {
  return `${spellCardText(identity.workspace.name)} (${identity.workspace.slug}) at ${identity.origin}`
}

// "Personal (alex) at https://app.mehen.dev": the name, then what proves it.
export function identityLine(identity: Pick<ShellIdentity, "origin" | "workspace">): Html {
  return html`<span class="identity"><span class="identity-name">${cardText(identity.workspace.name)}</span> <span class="identity-proof">(<code>${identity.workspace.slug}</code>) at <span class="identity-origin">${identity.origin}</span></span></span>`
}

function membershipRow(m: MembershipView, current: string): Html {
  const here = m.workspace.id === current
  const label = html`<span class="switcher-name">${cardText(m.workspace.name)}</span><code class="switcher-slug">${m.workspace.slug}</code><span class="switcher-role">${ROLE_WORDS[m.role]}${m.status === "active" ? "" : m.status === "unconfirmed" ? ", waiting to be confirmed" : ", suspended"}</span>`
  if (m.status !== "active") return html`<li><span class="switcher-row muted">${label}</span></li>`
  return html`<li><a class="switcher-row" href="${workspaceHref(m.workspace.slug)}"${here ? html` aria-current="true"` : ""}>${label}</a></li>`
}

// This workspace's own pages outside the top bar's links (Connect an agent,
// Settings), in the switcher's menu: from 900 px to the rail the top bar has
// neither a rail foot nor a More sheet to hold them. The rail hides them.
function switcherPages(shell: WorkspaceShell): Html {
  return html`${MORE_PAGES.filter((item) => item.key !== "teams" && shell.pages.includes(item.key)).map((item) => html`<a class="switcher-link switcher-page" href="${workspaceHref(shell.identity.workspace.slug, item.path)}">${item.label}</a>`)}`
}

// A <details> menu: it opens and closes with no script. The current workspace
// leads; the others follow as the account read lists them.
export function workspaceSwitcher(shell: WorkspaceShell): Html {
  const { workspace, origin } = shell.identity
  const others = (shell.memberships ?? []).filter((m) => m.workspace.id !== workspace.id)
  const listed = shell.memberships?.find((m) => m.workspace.id === workspace.id)
  const current: Html =
    listed !== undefined
      ? membershipRow(listed, workspace.id)
      : html`<li><a class="switcher-row" href="${workspaceHref(workspace.slug)}" aria-current="true"><span class="switcher-name">${cardText(workspace.name)}</span><code class="switcher-slug">${workspace.slug}</code></a></li>`
  return html`<details class="switcher">
  <summary aria-label="Workspace: ${identityText(shell.identity)}. Switch workspace"><span class="switcher-name">${cardText(workspace.name)}</span><code class="switcher-slug">${workspace.slug}</code></summary>
  <div class="switcher-menu">
    <p class="switcher-origin">Workspaces at <span class="identity-origin">${origin}</span></p>
    <ul class="switcher-list">${current}${others.map((m) => membershipRow(m, workspace.id))}</ul>
    ${switcherPages(shell)}
    ${accountLinkKeys(shell.accountPages).map((key) => html`<a class="switcher-link" href="${ACCOUNT_NAV[key].path}">${ACCOUNT_NAV[key].label}</a>`)}
  </div>
</details>`
}
