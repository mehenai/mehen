// The shell's gallery registration: every shell, picker and account page
// is in the gallery (the only place pages for unmerged reads exist), the
// gallery script renders them, every fixture matches the frozen protocol
// shapes, and identity always shows as name, slug and origin.

import { describe, expect, it } from "vitest"
import { AccountSessionSchema, MembershipViewSchema } from "@mehen/protocol/workspace"
import { NOT_FOUND_NEXT, errorBody, renderDocument } from "./layout.ts"
import { workspaceHomePage } from "./pages/workspaces.ts"
import { GALLERY_ACCOUNT_SHELL, GALLERY_HOSTILE, GALLERY_MEMBERSHIPS, GALLERY_ORIGIN, GALLERY_SESSION, GALLERY_TWINS, INBOX_GATED_EMPTY, INBOX_UNAVAILABLE, SHELL_PAGES, shellGallery } from "./shell-gallery.ts"
import { NOTHING_NEEDS_YOU } from "./client/pages/needs-you-logic.ts"
import { buildEntries } from "./client/palette-logic.ts"
import type { AccountSession, MembershipView } from "@mehen/protocol/workspace"
import type { InboxResponse } from "@mehen/protocol/inbox"
import { pickerPage } from "./pages/workspaces.ts"
import { needsYouPage } from "./pages/needs-you.ts"
import { workspacePendingPage } from "./pages/workspace-pending.ts"

const GALLERY_SCRIPT = Object.values(import.meta.glob<string>("../../scripts/ui-gallery.ts", { query: "?raw", import: "default", eager: true }))[0] ?? ""

describe("error pages", () => {
  it("say what to do next after a miss the vault gave no next step for, and keep the vault's own", () => {
    expect(errorBody({ error: "not_found", message: "No such machine." }, undefined, 404).value).toContain(`<p>${NOT_FOUND_NEXT}</p>`)
    const own = errorBody({ error: "not_found", message: "There is no page at this address.", next: { url: "/", say: "Check the address and try again." } }, undefined, 404).value
    expect(own).toContain("Check the address and try again.")
    expect(own).not.toContain(NOT_FOUND_NEXT)
    expect(errorBody({ error: "forbidden", message: "You are not allowed to do that." }, undefined, 403).value).not.toContain(NOT_FOUND_NEXT)
  })
})

describe("the palette's tiles", () => {
  it("has a template for every icon a workspace palette entry can show", () => {
    const page = renderDocument((shellGallery().find((e) => e.id === "workspace-home") as { page: Parameters<typeof renderDocument>[0] }).page).value
    const scope = { kind: "workspace" as const, slug: "northwind", name: "Northwind", pages: ["home", "needs", "credentials", "machines", "projects", "people", "teams", "connect-agent", "audit", "settings", "asks"], reads: [] }
    const settings = { frozen: false, rights: { rename: true, freeze: true, unfreeze: true } }
    const icons = buildEntries({ pending: null, items: null, devices: null, projects: null, settings }, 0, scope).flatMap((e) => (e.tile.kind === "icon" ? [e.tile.name] : []))
    expect(icons).toContain("snowflake")
    for (const name of icons) expect(page, name).toContain(`<template data-tile="icon:${name}">`)
  })
})

describe("the shell gallery", () => {
  it("is registered in the gallery script", () => {
    expect(GALLERY_SCRIPT).toContain('import { shellGallery } from "../src/ui/shell-gallery.ts"')
    expect(GALLERY_SCRIPT).toContain("...shellGallery(),")
  })

  it("has every shell page, each id once", () => {
    const entries = shellGallery()
    expect(new Set(entries.map((e) => e.id)).size).toBe(entries.length)
    const pages = new Set(entries.map((e) => e.page.boot.page))
    for (const page of SHELL_PAGES) expect(pages, page).toContain(page)
  })

  it("uses fixtures in the frozen protocol shapes", () => {
    expect(AccountSessionSchema.parse(GALLERY_SESSION)).toEqual(GALLERY_SESSION)
    for (const m of GALLERY_MEMBERSHIPS) expect(MembershipViewSchema.parse(m)).toEqual(m)
    // Two workspaces share a display name; their slugs differ.
    const twins = GALLERY_MEMBERSHIPS.filter((m) => m.workspace.name === "Northwind")
    expect(twins.length).toBe(2)
    expect(new Set(twins.map((m) => m.workspace.slug)).size).toBe(2)
  })

  it("shows the slug beside every workspace name and the origin wherever a workspace is named", () => {
    const render = (id: string) => renderDocument((shellGallery().find((e) => e.id === id) as { page: Parameters<typeof renderDocument>[0] }).page).value
    for (const entry of shellGallery()) if (entry.page.boot.page !== "error") expect(renderDocument(entry.page).value, entry.id).toContain(GALLERY_ORIGIN)
    const picker = render("workspaces-picker")
    const switcher = render("workspace-home-switcher")
    for (const m of GALLERY_MEMBERSHIPS) {
      expect(picker).toContain(`<code class="slug">${m.workspace.slug}</code>`)
      expect(switcher).toContain(`<code class="switcher-slug">${m.workspace.slug}</code>`)
    }
  })

  it("renders a hostile workspace name as text with its marker, never markup", () => {
    for (const id of ["workspaces-picker", "workspace-home-switcher"]) {
      const page = renderDocument((shellGallery().find((e) => e.id === id) as { page: Parameters<typeof renderDocument>[0] }).page).value
      expect(page, id).toContain('<mark class="marker">[RLO U+202E]</mark>&quot; &lt;b&gt;admin&lt;/b&gt;')
      expect(page, id).not.toContain("<b>admin</b>")
      expect(page, id).not.toContain("\u202e")
    }
  })

  it("spells a hostile current workspace in the title (with its slug), the switcher's accessible name (with slug and origin) and the page", () => {
    const page = renderDocument((shellGallery().find((e) => e.id === "workspace-home-hostile") as { page: Parameters<typeof renderDocument>[0] }).page).value
    const title = /<title>([^<]*)<\/title>/.exec(page)?.[1] ?? ""
    const label = /<summary aria-label="([^"]*)"/.exec(page)?.[1] ?? ""
    expect(GALLERY_HOSTILE.workspace.name).toMatch(/[\u202e\u0007]/)
    for (const [what, text] of [["title", title], ["aria-label", label], ["page", page]] as const) {
      expect(text, what).not.toMatch(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/)
    }
    for (const [what, text] of [["title", title], ["aria-label", label]] as const) {
      expect(text, what).toContain("[RLO U+202E]")
      expect(text, what).toContain(what === "title" ? "(hostile-name) · Mehen" : `(hostile-name) at ${GALLERY_ORIGIN}`)
      expect(text, what).not.toContain("<b>")
    }
  })

  it("gives two workspaces with one name distinct titles", () => {
    const titles = GALLERY_TWINS.map((m) => {
      const shell = { identity: { origin: GALLERY_ORIGIN, account: GALLERY_SESSION.account, workspace: m.workspace }, accountName: "Alex", memberships: null, pages: ["home" as const], reads: [], accountPages: [], accountHeld: false }
      return /<title>([^<]*)<\/title>/.exec(renderDocument(workspaceHomePage(shell)).value)?.[1]
    })
    expect(GALLERY_TWINS[0].workspace.name).toBe(GALLERY_TWINS[1].workspace.name)
    expect(titles[0]).not.toBe(titles[1])
    expect(titles[0]).toBe(`Home · ${GALLERY_TWINS[0].workspace.name} (${GALLERY_TWINS[0].workspace.slug}) · Mehen`)
  })

  it("never offers Google sign-in or a destructive control", () => {
    for (const entry of shellGallery()) {
      const page = renderDocument(entry.page).value
      expect(page, entry.id).not.toMatch(/with Google|\/auth\/oidc|data-action="(delete|remove|leave)"/)
    }
  })

  const rendered = (id: string) => renderDocument((shellGallery().find((e) => e.id === id) as { page: Parameters<typeof renderDocument>[0] }).page).value

  it("never draws the account-wide count on the server, in any shell", () => {
    for (const entry of shellGallery()) {
      const page = renderDocument(entry.page).value
      for (const count of page.matchAll(/<b class="count"[^>]*>([^<]*)<\/b>/g)) {
        expect(count[0], entry.id).toBe('<b class="count" data-region="pending-count" data-fill hidden></b>')
      }
    }
    expect(rendered("workspace-home")).toContain('href="/needs-you"><svg')
    expect(rendered("needs-you-three")).toMatch(/href="\/needs-you" aria-current="page">Needs you<b class="count" data-region="pending-count" data-fill hidden><\/b>/)
  })

  it("gives the phone five tabs at most: Home, Needs you, Credentials, Projects and More with the rest", () => {
    const page = rendered("workspace-home")
    const tabs = /<nav class="tabs"[^>]*>([\s\S]*?)<details class="more-sheet"/.exec(page)?.[1] ?? ""
    expect([...tabs.matchAll(/<span>([^<]+)<\/span>/g)].map((m) => m[1])).toEqual(["Home", "Needs you", "Credentials", "Projects"])
    const more = /data-region="more-sheet"[\s\S]*?<\/details>/.exec(page)?.[0] ?? ""
    expect([...more.matchAll(/<span>([^<]+)<\/span>/g)].map((m) => m[1])).toEqual(["More", "Machines", "People", "Teams", "Activity", "Connect an agent", "Settings", "All workspaces", "Your account", "Docs", "Sign out"])
    // The rail has the seven pages, Activity for /audit, and one People entry.
    const rail = /<nav class="rail-nav" aria-label="Pages">([\s\S]*?)<\/nav>/.exec(page)?.[1] ?? ""
    expect([...rail.matchAll(/<span>([^<]+)<\/span>/g)].map((m) => m[1])).toEqual(["Home", "Needs you", "Credentials", "Projects", "Machines", "People", "Activity"])
  })

  it("never says Nothing needs you while a workspace is gated or could not be read", () => {
    for (const [id, inbox] of [["needs-you-gated", INBOX_GATED_EMPTY], ["needs-you-unavailable", INBOX_UNAVAILABLE]] as const) {
      const page = rendered(id)
      expect(inbox.complete, id).toBe(false)
      expect(page, id).not.toContain(`<b>${NOTHING_NEEDS_YOU}</b>`)
    }
    expect(rendered("needs-you-gated")).toContain("Verify your identity to see what needs you in Northwind")
    expect(rendered("needs-you-unavailable")).toContain("Could not read Personal just now; retrying.")
    expect(rendered("needs-you-unavailable")).toContain("<title>(4+) Needs you · Mehen</title>")
    expect(rendered("needs-you-empty")).toContain(`<b>${NOTHING_NEEDS_YOU}</b>`)
  })

  it("marks the home's Needs you card with its workspace's state, count and partial flag, and each row with its signature, for the client's redraw", () => {
    const home = rendered("workspace-home")
    expect(home).toMatch(/<section class="card" data-region="home-needs" data-state="ok" data-count="\d+" data-truncated="false">/)
    const rows = /<section class="card" data-region="home-needs"[\s\S]*?<\/section>/.exec(home)?.[0] ?? ""
    const signs = [...rows.matchAll(/<li class="row needs inbox-row"[^>]*data-sign="([^"]*)"/g)].map((m) => m[1])
    expect(signs.length).toBeGreaterThan(0)
    for (const sign of signs) expect(sign).toMatch(/^\S+ (\S+Z|-) [a-z]+ ([a-z_]+|-)$/)
    expect(rendered("workspace-home-read-failed")).toContain('<section class="card" data-region="home-needs"><div class="card-head">')
    // Unread: an empty row list the last good rows can be kept in.
    const membership = GALLERY_MEMBERSHIPS[0]
    if (membership === undefined) throw new Error("no gallery membership")
    const shell = { identity: { origin: GALLERY_ORIGIN, account: GALLERY_SESSION.account, workspace: membership.workspace }, accountName: "Alex", memberships: null, pages: ["home" as const], reads: [], accountPages: [], accountHeld: false }
    const unread = { workspace: { workspace: membership.workspace, role: "owner" as const, state: "unavailable" as const, reason: "timeout" as const, count: null, truncated: false }, items: [], notices: [] }
    const page = renderDocument(workspaceHomePage(shell, { viewer: { role: "owner", member: "mem_alex0001" }, inbox: unread, devices: [], items: [], projects: [], members: null, invites: null, settings: null, now: 0 })).value
    const card = /<section class="card" data-region="home-needs"[\s\S]*?<\/section>/.exec(page)?.[0] ?? ""
    expect(card).toContain('data-state="unavailable" data-count="0" data-truncated="false"')
    // Nothing on the home retries a read the account inbox cannot make for it, so it says to reload.
    expect(card).toContain(`Could not read ${membership.workspace.name} just now.`)
    expect(card).toContain("Reload the page to try again.")
    expect(card).not.toContain("retrying")
    expect(card).toContain('<ul class="rows" data-region="needs-rows"></ul>')
  })

  it("says to invite someone by link on a vault that cannot verify an email address, and keeps the email words elsewhere", () => {
    const rendered = (id: string) => renderDocument((shellGallery().find((e) => e.id === id) as { page: Parameters<typeof renderDocument>[0] }).page).value
    const local = rendered("workspace-home-get-started-local")
    expect(local).toContain("Invite someone by link; you confirm them once they have joined.")
    expect(local).not.toContain("Email-bound invitations")
    expect(rendered("workspace-home-get-started-owner")).toContain("Email-bound invitations; you confirm them once they have joined.")
  })

  it("shows the picker's first-run states in their own words", () => {
    expect(rendered("workspaces-no-invite")).toContain("You are not in a workspace yet")
    expect(rendered("workspaces-no-invite")).toContain(`<code>${GALLERY_SESSION.account}</code>`)
    expect(rendered("workspaces-create-first")).toContain('data-form="workspace-create"')
    expect(rendered("workspaces-waiting")).toContain("Waiting for <span data-fill=\"workspace-name\">Northwind</span> to confirm you")
    expect(rendered("workspaces-recovery-first")).toContain("Set up a way back in first")
    // Counts only where the workspace answered.
    const picker = rendered("workspaces-picker")
    expect(picker).toContain("Admin · 4 things need you")
    expect(picker).not.toMatch(/Personal <code class="slug">alex<\/code><\/span><span class="sub">Owner ·/)
  })

  const shellOf = { origin: GALLERY_ORIGIN, account: GALLERY_SESSION.account, name: "Tom", accountPages: ["workspaces", "needs-you", "account"] as const }
  const member = (slug: string, status: MembershipView["status"]): MembershipView => ({ workspace: { id: `tn_${slug}0000001`, slug, name: slug.toUpperCase() }, member: `mem_${slug}`, role: "member", pendingRole: null, status })
  const session = (memberships: MembershipView[]): AccountSession => ({ ...GALLERY_SESSION, canCreateWorkspaces: true, memberships })

  it("keeps the waiting screen for one membership, waiting, and lists every membership otherwise", () => {
    for (const memberships of [[member("alpha", "unconfirmed"), member("beta", "unconfirmed")], [member("alpha", "unconfirmed"), member("gamma", "suspended")]]) {
      const page = pickerPage(shellOf, session(memberships), GALLERY_ORIGIN)
      const body = renderDocument(page).value
      expect(page.boot.state).toBe("list")
      expect(page.boot).not.toHaveProperty("waiting")
      for (const m of memberships) expect(body).toContain(`<code class="slug">${m.workspace.slug}</code>`)
      expect(body).toContain('data-region="create-link"')
    }
    const one = pickerPage(shellOf, session([member("alpha", "unconfirmed")]), GALLERY_ORIGIN)
    expect(one.boot).toMatchObject({ state: "waiting", waiting: "alpha" })
    // One membership that joined straight away is active: no wait.
    const straightIn = pickerPage(shellOf, session([member("alpha", "active")]), GALLERY_ORIGIN)
    expect(straightIn.boot.state).toBe("list")
    expect(straightIn.boot).not.toHaveProperty("waiting")
    // A suspended membership says who can lift it, not just the word.
    expect(renderDocument(pickerPage(shellOf, session([member("alpha", "unconfirmed"), member("gamma", "suspended")]), GALLERY_ORIGIN)).value).toContain("Member · Suspended: ask an owner or admin of this workspace to reinstate you")
  })

  it("keeps a workspace cut with no row left, without a zero claim or a link to itself", () => {
    const cut = { workspace: { id: "tn_cut0000001", slug: "cut", name: "Cut" }, role: "owner" as const, state: "ok" as const, reason: null, count: 0, truncated: true }
    const inbox: InboxResponse = { workspaces: [cut], items: [], notices: [], count: 0, complete: false }
    const account = renderDocument(needsYouPage(GALLERY_ACCOUNT_SHELL, { ok: true, inbox, etag: null }, 0)).value
    expect(account).toContain('data-workspace="tn_cut0000001" data-state="ok"')
    expect(account).toContain("This is a partial list for Cut; completing requests may reveal more.")
    expect(account).toContain(`href="/w/cut/pending">Open this workspace's requests</a>`)
    expect(account).not.toMatch(/Nothing is waiting in Cut|Nothing needs you/)
    const shell = { identity: { origin: GALLERY_ORIGIN, account: GALLERY_SESSION.account, workspace: cut.workspace }, accountName: "Tom", memberships: null, pages: ["home" as const, "needs" as const], reads: [], accountPages: [], accountHeld: false }
    const filter = renderDocument(workspacePendingPage(shell, { viewer: { role: "owner", member: "mem_x" }, inbox: { workspace: cut, items: [], notices: [] }, now: 0 })).value
    expect(filter).toContain("This is a partial list for Cut")
    expect(filter).not.toContain("Open this workspace's requests")
    expect(filter).not.toContain("Nothing is waiting for you in Cut")
  })
})


describe("grouped asks in Needs you", () => {
  it("draws a group row with its counts, Review together and the soonest countdown, and a bundle with its reason quoted", () => {
    const page = renderDocument((shellGallery().find((e) => e.id === "needs-you-groups") as { page: Parameters<typeof renderDocument>[0] }).page).value
    expect(page).toContain("sam-mac-mini: 12 asks on <code>cloudflare-api-token</code>")
    expect(page).toContain("3 need a closer look. 1 decides on its own page.")
    expect(page).toContain("All routine.")
    expect(page).toContain("sam-mac-mini: 4 requests to approve together")
    expect(page).toContain('"Set up the staging D1 databases for the preview deploys" (the agent\'s words, not verified).')
    expect(page).toContain("1 can only be denied.")
    expect(page.match(/>Review together</g)?.length).toBe(3)
    expect(page).toContain('href="/w/northwind/g/bnd_5lq2mw4zl9aaaaaaaaaaaa"')
  })
})
