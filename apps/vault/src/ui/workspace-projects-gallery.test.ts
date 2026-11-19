// The workspace project, credential and audit pages, rendered from the
// gallery's fixtures: what each role sees and what it never sees. Someone
// else's private credential never appears, forbidden controls are absent, a
// guest sees no people, and repeated or hostile names stay told apart and
// inert. The ask pages are tested in workspace-asks-gallery.test.ts.

import { describe, expect, it } from "vitest"
import { EffectiveAccessSchema, ShareSchema, WorkspaceMemberViewSchema } from "@mehen/protocol/workspace"
import { renderDocument } from "./layout.ts"
import { FILTERED_VIEW_WORDS } from "./pages/workspace-audit.ts"
import { type HumanItemDescription, NAME_NOT_AVAILABLE_WORDS, REHOME_WARNING, workspaceCredentialPage } from "./pages/workspace-credentials.ts"
import { accessSentence } from "./pages/workspace-projects.ts"
import { nameRefusalWords } from "./client/workspace-logic.ts"
import { HELD_WORDS } from "./workspace-rights.ts"
import { SHARE_END_HINT } from "./wording.ts"
import { GALLERY_FIXTURES, GALLERY_FOREIGN_PRIVATE, GALLERY_HOSTILE_NAME, GALLERY_ITEMS, GALLERY_MEMBERS, GALLERY_PUSHES, VIEWERS, WORKSPACE_PROJECT_PAGE_KINDS, description, galleryShell, workspaceProjectsGallery } from "./workspace-projects-gallery.ts"
import type { ShellGalleryEntry } from "./shell-gallery.ts"
import { LEASE_ONLY_HOST } from "@mehen/protocol/binding"

const GALLERY_SCRIPT = Object.values(import.meta.glob<string>("../../scripts/ui-gallery.ts", { query: "?raw", import: "default", eager: true }))[0] ?? ""

function entry(id: string): ShellGalleryEntry {
  const found = workspaceProjectsGallery().find((e) => e.id === id)
  if (found === undefined) throw new Error(`no gallery entry ${id}`)
  return found
}

function rendered(id: string): string {
  return renderDocument(entry(id).page).value
}

// The part of a page between two markers, to look at one card.
function between(text: string, from: string, to: string): string {
  const start = text.indexOf(from)
  const end = text.indexOf(to, start + from.length)
  return text.slice(start, end === -1 ? undefined : end)
}

describe("the workspace projects gallery", () => {
  it("is registered in the gallery script, with every page kind once per id", () => {
    expect(GALLERY_SCRIPT).toContain('import { workspaceProjectsGallery } from "../src/ui/workspace-projects-gallery.ts"')
    expect(GALLERY_SCRIPT).toContain("...workspaceProjectsGallery(),")
    const entries = workspaceProjectsGallery()
    expect(new Set(entries.map((e) => e.id)).size).toBe(entries.length)
    const kinds = new Set(entries.map((e) => e.page.boot.page))
    for (const kind of WORKSPACE_PROJECT_PAGE_KINDS) expect(kinds, kind).toContain(kind)
  })

  it("uses fixtures in the frozen protocol shapes", () => {
    for (const m of GALLERY_MEMBERS) expect(WorkspaceMemberViewSchema.parse(m)).toEqual(m)
    for (const s of GALLERY_FIXTURES.SHARES) expect(ShareSchema.parse(s)).toEqual(s)
    for (const a of [GALLERY_FIXTURES.OWNER_ACCESS, GALLERY_FIXTURES.MANAGER_ACCESS, GALLERY_FIXTURES.GUEST_ACCESS]) expect(EffectiveAccessSchema.parse(a)).toEqual(a)
  })
})

describe("private metadata", () => {
  it("someone else's private credential appears on no list, project or credential page", () => {
    for (const e of workspaceProjectsGallery()) {
      expect(renderDocument(e.page).value, e.id).not.toContain(GALLERY_FOREIGN_PRIVATE)
    }
  })

  it("the remove-by-name form shows nothing about any credential", () => {
    const purge = between(rendered("ws-credentials-owner"), 'data-region="purge-private"', "</details>")
    expect(purge).toContain('data-input="slug"')
    expect(purge).not.toMatch(/value="[^"]+"/)
    expect(purge).not.toContain("Belongs to")
  })

  it("an own private credential says what its owner will not see", () => {
    expect(rendered("ws-credential-private")).toContain("You will not see which hosts or paths your private credential was sent to; investigate misuse with the provider&#39;s own logs.")
    expect(rendered("ws-credential-workspace")).not.toContain('data-region="private-audit"')
  })
})

describe("controls", () => {
  it("an owner gets protection, fences, shares and delete; no owner-only lines", () => {
    const page = rendered("ws-project-owner")
    for (const control of ['data-control="four-eyes-off"', 'data-control="fences"', 'data-control="protect"', 'data-form="share"', 'data-action="delete-project"', 'data-form="remote"']) expect(page, control).toContain(control)
    expect(page).not.toContain('data-region="owner-only"')
    // prod can never be unprotected, by anyone.
    expect(between(page, 'data-env-card="prod"', "</section>")).not.toContain('data-control="unprotect"')
  })

  // The end is a UTC day, as every time on the page is shown; the line that
  // says an end is removed or moved later sits just before the button.
  it("the share form offers an end as a UTC day, empty for No end, with the end-change line before the button", () => {
    const form = between(rendered("ws-project-owner"), 'data-form="share"', "</form>")
    expect(form).toContain('<input type="date" data-input="ends"')
    expect(between(form, 'data-input="ends"', "</label>")).toContain(SHARE_END_HINT)
    expect(SHARE_END_HINT).toContain("23:59 UTC")
    expect(SHARE_END_HINT).toContain("No end")
    expect(form).toMatch(/<p class="small warn-text" data-region="share-end-change" hidden><\/p>\s*<button type="button" class="btn primary" data-action="share">/)
  })

  it("a member who manages it gets the vault's owner-only words where loosening and fences would be", () => {
    const page = rendered("ws-project-manager")
    const prod = between(page, 'data-env-card="prod"', "</section>")
    expect(prod).toContain("Only an owner or admin can loosen platform/prod: it uses workspace credentials.")
    expect(prod).toContain("Only an owner or admin can change fences for platform/prod.")
    for (const hidden of ['data-control="four-eyes-off"', 'data-control="fences"', 'data-control="unprotect"']) expect(prod, hidden).not.toContain(hidden)
    expect(page).not.toContain('data-control="fences"')
    expect(page).toContain("Only an owner or admin can delete platform: a protected environment uses workspace credentials.")
    expect(page).not.toContain('data-action="delete-project"')
    // Sharing with a guest needs an owner or admin: Sam is not offered.
    expect(between(page, 'data-input="subject"', "</select>")).not.toContain("mem_sam00001")
  })

  it("a guest sees no people, no share list and no protection controls", () => {
    const page = rendered("ws-project-guest")
    expect(page).toContain("Shared with you.")
    for (const hidden of ["Kim", "Tom", "mem_kim00001", 'data-form="share"', 'data-form="environment"', 'data-action="delete-project"', 'data-form="remote"', 'data-region="owner-only"']) expect(page, hidden).not.toContain(hidden)
    expect(rendered("ws-projects-guest")).not.toContain('data-region="create-project"')
    expect(rendered("ws-projects-owner")).toContain('data-region="create-project"')
  })
})

describe("a restricted account", () => {
  it("is told once why the project and credential pages offer no change, and is offered none", () => {
    const project = rendered("ws-project-held")
    const list = rendered("ws-credentials-held")
    for (const page of [project, list]) expect(page.split(HELD_WORDS).length - 1).toBe(1)
    for (const hidden of ['data-form="share"', 'data-action="unshare"', 'data-form="environment"', 'data-form="var"', 'data-form="remote"', 'data-action="delete-project"', 'data-region="overrides"', 'data-action="clear-own"']) expect(project, hidden).not.toContain(hidden)
    // What it is still told: its own override stays named.
    expect(project).toContain('data-own-source="item"')
    for (const hidden of ['data-action="open-add"', 'data-region="add-credential"', 'data-region="purge-private"']) expect(list, hidden).not.toContain(hidden)
    expect(rendered("ws-credentials-owner")).not.toContain(HELD_WORDS)
    expect(rendered("ws-project-owner")).not.toContain(HELD_WORDS)
  })
})

describe("dependants and overrides", () => {
  it("an OAuth client's delete and move list its visible connections and only say others exist", () => {
    const page = rendered("ws-credential-oauth-client")
    expect(between(page, 'data-region="delete"', "</details>")).toContain("gmail-alex")
    expect(between(page, 'data-region="rehome"', "</details>")).toContain("gmail-alex")
    expect(page).toContain('data-region="hidden-dependants"')
    expect(rendered("ws-credential-workspace")).not.toContain('data-region="dependent-connections"')
  })

  it("Use my own appears only on an exact unprotected row, and only once the override read is served", () => {
    const owner = rendered("ws-project-owner")
    expect(owner).toContain('data-override="dev/OPENAI_API_KEY"')
    expect(owner).toContain("Stop using my own")
    expect(owner).not.toContain('data-override="prod/')
    // GITHUB_TOKEN exists in prod only: no dev or staging control for it.
    expect(owner).not.toContain("/GITHUB_TOKEN")
    expect(rendered("ws-project-guest")).not.toContain("data-override=")
  })
})

describe("renewing a credential", () => {
  it("a connection that needs reconnecting says why and offers Reconnect, which connects again under its provider", () => {
    const page = body("ws-credential-reconnect")
    expect(page).toContain('data-region="item-reconnect"')
    expect(page).toContain("Reconnecting under Manage clears it.")
    const manage = between(page, 'data-region="manage"', "</section>")
    expect(manage).toContain('data-starts="connect" data-provider="google-gmail"')
    expect(manage).toContain("<span>Reconnect Gmail</span>")
    expect(manage).not.toContain("<span>Replace</span>")
  })

  it("a credential flagged for review says why, and Replace starts an intake", () => {
    const page = body("ws-credential-review")
    expect(page).toContain('data-region="item-review"')
    expect(page).toContain("member left: Tom")
    expect(between(page, 'data-region="manage"', "</section>")).toContain('data-starts="intake"')
    expect(body("ws-credential-workspace")).not.toContain('data-region="item-review"')
    expect(body("ws-credential-workspace")).not.toContain('data-region="item-reconnect"')
  })
})

describe("names", () => {
  it("two people named Tom are told apart by id in the share choices", () => {
    const select = between(rendered("ws-project-owner"), 'data-input="subject"', "</select>")
    expect(select).toContain("Tom (mem_tom00001)")
    expect(select).toContain("Tom (mem_tom00002)")
  })

  it("a hostile name renders as text with its markers", () => {
    const page = rendered("ws-project-owner")
    expect(page).not.toContain("<b>admin</b>")
    expect(page).not.toContain("\u202e")
    expect(page).not.toContain("\u0007")
    expect(page).toContain("mem_noor0001")
    expect(GALLERY_HOSTILE_NAME).toContain("\u202e")
  })

  it("the uniform name refusal and the rehome warning use their exact words", () => {
    expect(nameRefusalWords({ error: "conflict", message: "name not available" })).toBe(NAME_NOT_AVAILABLE_WORDS)
    expect(rendered("ws-credential-workspace")).toContain(REHOME_WARNING)
  })
})

// The page's own markup, without the shell around it.
function body(id: string): string {
  return entry(id).page.body.value
}

describe("layout and emphasis", () => {
  it("lists the access sources through responsiveTable, folded under one sentence", () => {
    for (const id of ["ws-project-owner", "ws-project-share-teams", "ws-project-manager", "ws-project-guest"]) {
      const access = between(body(id), 'data-region="your-access"', "</section>")
      expect(access, id).not.toContain('class="sources"')
      expect(access, id).toContain('data-region="access-sentence"')
      const sources = between(access, 'data-region="access-sources"', "</details>")
      expect(sources, id).toContain('<div class="table"><table>')
      for (const label of ["From", "Level", "Protected runs", "Protected edits", "Until"]) expect(sources, `${id} ${label}`).toContain(`data-label="${label}"`)
    }
    expect(body("ws-project-owner")).toContain("Manage, including protected runs and edits (as workspace owner).")
    expect(body("ws-project-guest")).toContain("Edit, unprotected environments only.")
  })

  // The sentence is the effective answer; the fold holds only the sources,
  // each with its own rights, so two that differ are never merged.
  it("folds only the sources under the sentence, each keeping its own protected rights", () => {
    for (const id of ["ws-project-owner", "ws-project-share-teams", "ws-project-manager", "ws-project-guest"]) {
      const sources = between(body(id), 'data-region="access-sources"', "</details>")
      expect(sources, id).not.toContain('class="kv facts"')
      expect(sources, id).not.toContain("data-fact=")
    }
    const manager = between(body("ws-project-manager"), 'data-region="your-access"', "</section>")
    expect(between(manager, 'data-region="access-sentence"', "</p>")).toContain("Manage, including protected runs and edits.")
    const rows = between(manager, "<tbody>", "</tbody>").split("<tr>").slice(1).map((row) => [...row.matchAll(/<td data-label="([^"]+)"><span>(.*?)<\/span><\/td>/g)].map((m) => `${m[1]}: ${m[2]}`))
    expect(rows).toEqual([
      ["From: Shared with you", "Level: Manage", "Protected runs: Yes", "Protected edits: Yes", "Until: No end"],
      ["From: Through the team Engineering (engineering)", "Level: Use", "Protected runs: Yes", "Protected edits: No", "Until: No end"],
    ])
  })

  it("says the access in one sentence for every combination", () => {
    expect(accessSentence({ level: null, runProtected: false, editProtected: false, sources: [] })).toBe("You have no access to this project.")
    expect(accessSentence({ level: "use", runProtected: true, editProtected: false, sources: [] })).toBe("Use, including protected runs.")
    expect(accessSentence({ level: "edit", runProtected: false, editProtected: true, sources: [] })).toBe("Edit, including protected edits.")
  })

  it("puts at most one primary button in each card and in the page head", () => {
    for (const e of workspaceProjectsGallery()) {
      const page = e.page.body.value
      const parts = [...page.split("<section").slice(1), between(page, '<header class="page-head"', "</header>")]
      for (const part of parts) expect(part.split('class="btn primary"').length - 1, e.id).toBeLessThanOrEqual(1)
    }
  })

  it("offers delete and remove as outline buttons, folded, never the filled danger", () => {
    for (const e of workspaceProjectsGallery()) expect(e.page.body.value, e.id).not.toMatch(/class="btn danger[" ]/)
    const project = between(body("ws-project-owner"), '<section class="card danger-zone"', "</section>")
    expect(project).toContain('data-region="delete-project"')
    expect(project).toMatch(/<details class="fold">[\s\S]*class="btn danger-quiet" data-action="delete-project"/)
    const credential = between(body("ws-credential-workspace"), 'data-region="danger-zone"', "</section>")
    expect(credential).toMatch(/<details class="fold" data-region="delete">[\s\S]*class="btn danger-quiet" data-action="delete"/)
    expect(between(body("ws-credential-workspace"), 'data-region="manage"', "</section>")).not.toContain('data-action="delete"')
    const manage = between(body("ws-credentials-owner"), 'data-region="manage-list"', "</section>")
    expect(manage).toContain('class="btn danger-quiet" data-action="purge"')
  })

  it("gives every fold a chevron, never a plus or an x", () => {
    for (const e of workspaceProjectsGallery()) {
      for (const summary of e.page.body.value.split("<summary>").slice(1)) {
        const head = summary.slice(0, summary.indexOf("</summary>"))
        expect(head, e.id).toContain("M9 6l6 6-6 6")
      }
    }
  })

  it("gives the credentials list the search the / shortcut focuses, with a no-match state", () => {
    const list = body("ws-credentials-owner")
    expect(list).toContain('<input type="search" data-input="search"')
    expect(list).toContain('data-region="no-match" hidden')
  })

  it("lists a credential's home as text under its name, and opens the add form in a sheet", () => {
    const list = body("ws-credentials-owner")
    expect(list).toContain("OpenAI API key. Belongs to: Whole workspace")
    expect(list).not.toContain('class="belongs"')
    expect(between(list, '<header class="page-head"', "</header>")).toContain('data-action="open-add"')
    expect(list).toMatch(/<div class="sheet" data-region="add-credential" role="dialog" aria-modal="true" aria-labelledby="add-credential-title" hidden>/)
    expect(body("ws-credentials-adding")).not.toMatch(/data-region="add-credential"[^>]* hidden>/)
  })

  it("folds an investigator's facts about a credential under Details", () => {
    const details = between(body("ws-credential-workspace"), 'data-region="details"', "</details>")
    expect(details).toContain("Secrets held")
    expect(details).toContain("Version")
  })

  it("has one Your overrides fold per environment, its forms keyed by variable", () => {
    const dev = between(body("ws-project-owner"), 'data-env-card="dev"', "</section>")
    expect(dev.split('data-region="overrides"').length - 1).toBe(1)
    expect(dev).toContain('data-form="own" data-env="dev" data-var="OPENAI_API_KEY"')
    expect(dev).toContain('data-form="own" data-env="dev" data-var="LOG_LEVEL"')
    // The status line stays beside the variable, outside the fold.
    expect(between(dev, 'data-var="OPENAI_API_KEY" data-source', "</dd>")).toContain("Stop using my own")
  })

  it("uses the glossary's words for four-eyes and fences", () => {
    const page = body("ws-project-owner")
    expect(page).toContain(">Second approver</span>")
    expect(page).toContain("1 reserved host")
    // The words a person reads, without the markup's hooks.
    expect(page.replace(/<[^>]*>/g, "")).not.toMatch(/four-eyes|fence/i)
  })

  // runs.ts blocks an environment's hosts in the project's other
  // environments; nothing limits where runs in that environment connect.
  // The words say which way the rule points, never an allowlist.
  it("says an environment's hosts are kept from the other environments, not that its runs reach only them", () => {
    const words = (html: string) => html.replace(/<[^>]*>/g, "").replace(/&#39;/g, "'")
    const staging = between(body("ws-project-owner"), 'data-env-card="staging"', "</section>")
    expect(words(staging)).toContain("1 reserved host")
    expect(words(staging)).toContain("These hosts belong to staging: Mehen refuses requests to them from runs in this project's other environments. It matches host names, not DNS aliases, and does not sandbox a program's direct network access. This does not limit where runs in staging may connect.")
    expect(between(staging, 'data-region="reserved-hosts"', "</ul>")).toContain("<code>api.openai.com</code>")
    expect(words(staging)).toContain("Hosts that belong to staging, one per line")
    expect(words(staging)).toContain("Mehen refuses requests to these hosts from runs in this project's other environments. It matches host names, not DNS aliases, and does not sandbox a program's direct network access. This does not limit where runs in staging may connect; an empty list reserves none.")
    // An empty list: no pill and no read sentence, and the form says it reserves none.
    const dev = between(body("ws-project-owner"), 'data-env-card="dev"', "</section>")
    expect(words(dev)).not.toContain("reserved host")
    expect(dev).not.toContain('data-region="reserved-hosts"')
    expect(words(dev)).toContain("This does not limit where runs in dev may connect; an empty list reserves none.")
    for (const e of workspaceProjectsGallery()) expect(words(e.page.body.value), e.id).not.toMatch(/connect only to|connect to nothing else|hosts? only\b/i)
  })
})

describe("the audit page", () => {
  it("leads with the chain's state and folds the head's hash; times are <time> elements", () => {
    const owner = body("ws-audit-owner")
    const head = between(owner, '<header class="page-head"', "</header>")
    expect(head).toContain("<h1>Activity</h1>")
    expect(head).toContain('data-region="chain"')
    expect(head).not.toContain("h48")
    expect(between(owner, 'data-region="chain-head"', "</details>")).toContain('<code class="hash">h48</code>')
    expect(owner).toContain('<time datetime="2026-10-27T18:29:00.000Z"')
    expect(body("ws-audit-member")).not.toContain('data-region="chain-head"')
  })

  it("owners see the chain verified; others get the filtered view; private events stay minimal", () => {
    const owner = rendered("ws-audit-owner")
    expect(owner).toContain("Chain verified")
    // The shared audit sentences only: nothing about a transition or a
    // notice the stored row does not carry.
    expect(owner).toContain("Tom changed the protection or fences of <code>prod</code>")
    expect(owner).not.toContain("four-eyes off")
    expect(owner).not.toContain("notified")
    expect(owner).toContain('data-minimal="1"')
    const member = rendered("ws-audit-member")
    expect(member).toContain(FILTERED_VIEW_WORDS)
    expect(member).not.toContain("Chain verified")
  })
})

describe("lease-only credentials", () => {
  it("the credential page reads the lease-only words where hosts go, never the reserved host", () => {
    const page = body("ws-credential-lease-only")
    expect(between(page, "May only go to", "</p>")).toBe("May only go to")
    expect(page).toContain('<p class="lease-only" data-region="lease-only">No host: only delivered into a process with <code>mehen run</code>.</p>')
    expect(page).not.toContain(LEASE_ONLY_HOST)
  })
})

describe("a replaced value", () => {
  it("says until when it is kept, who replaced it and when, and which fields, and offers Restore it with the versions shown", () => {
    const page = rendered("ws-credential-previous")
    const card = between(page, 'data-region="previous"', "</section>")
    expect(card).toMatch(/Previous value kept until <time datetime="[^"]+"[^>]*>[^<]+<\/time>, replaced by Kim on <time datetime="[^"]+"[^>]*>[^<]+<\/time>, fields: <code>key<\/code>\./)
    expect(card).toContain('<button type="button" class="btn secondary" data-action="restore">Restore it with passkey</button>')
    expect(page).toMatch(/data-boot="[^"]*&quot;previous&quot;:2[,}]/)
  })

  it("offers no restore to someone who may not change its value, and no card without a kept value", () => {
    const held = between(rendered("ws-credential-previous-held"), 'data-region="previous"', "</section>")
    expect(held).toContain("Previous value kept until")
    expect(held).not.toContain('data-action="restore"')
    expect(rendered("ws-credential-workspace")).not.toContain('data-region="previous"')
  })
})

// A credential's push parts (ruling U1, design push-providers 3.3): only
// while pushing is on, the allowance only for kinds the vault would let be
// pushed, the places it went with how far each got, push again only for
// places on an older value and only for someone the vault would let, and
// the places its copies stay in the delete confirmation.
describe("pushes on a credential's page", () => {
  const PUSH_REGIONS = ['data-region="push-allowance"', 'data-region="pushed-to"', 'data-region="push-again"', 'data-region="push-delete"', "secret stores"]
  const page = (id: string) => between(rendered(id), "<main", "</main>")

  it("shows nothing about pushing while it is off, even for a credential with pushes", () => {
    for (const e of workspaceProjectsGallery()) {
      if (e.id.startsWith("ws-credential-push")) continue
      for (const absent of PUSH_REGIONS) expect(renderDocument(e.page).value, `${e.id} ${absent}`).not.toContain(absent)
    }
    const off = workspaceCredentialPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, item: { ...description(GALLERY_ITEMS[0]!), pushable: true, pushes: GALLERY_PUSHES }, projects: [] })
    for (const absent of PUSH_REGIONS) expect(renderDocument(off).value, absent).not.toContain(absent)
  })

  it("puts the allowance in its own card after the standing rules, a tick and a passkey for whoever may change the credential", () => {
    const text = page("ws-credential-push-allowance")
    const card = between(text, 'data-region="push-allowance"', "</section>")
    expect(card).toContain("<h2>Other services&#39; secret stores</h2>")
    expect(card).toContain('<label class="tick"><input type="checkbox" data-input="pushable"><span>May be put into other services&#39; secret stores</span></label>')
    expect(card).toContain('data-action="save-pushable" disabled>Save with passkey</button>')
    expect(text.indexOf('data-region="push-allowance"')).toBeLessThan(text.indexOf('data-region="references"'))
    expect(text).not.toContain('data-region="pushed-to"')
    expect(between(page("ws-credential-pushed"), 'data-region="push-allowance"', "</section>")).toContain('data-input="pushable" checked>')
    const reader = between(page("ws-credential-pushed-reader"), 'data-region="push-allowance"', "</section>")
    expect(reader).toContain('data-region="push-allowance-state"><span class="pill ok dot">Allowed</span> May be put into other services&#39; secret stores</p>')
    for (const absent of ['data-input="pushable"', "save-pushable"]) expect(reader, absent).not.toContain(absent)
  })

  it("offers the allowance only for a kind the vault would let be pushed, never an OAuth client or connection", () => {
    const shown = (item: HumanItemDescription) => renderDocument(workspaceCredentialPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, item, projects: [], pushes: true })).value
    expect(shown({ ...description(GALLERY_ITEMS[0]!), pushable: false })).toContain('data-region="push-allowance"')
    for (const kind of ["oauth-client", "oauth-connection"] as const) expect(shown({ ...description({ ...GALLERY_ITEMS[0]!, kind }), pushable: false }), kind).not.toContain('data-region="push-allowance"')
  })

  it("lists the latest push to each place: where, how it went, the version and whether it is older, with what, when, and by whom only when the vault says", () => {
    const list = between(page("ws-credential-pushed"), 'data-region="push-records"', "</ul>")
    const rows = list.split("<li ").slice(1)
    expect(rows).toHaveLength(5)
    expect(rows[1]).toContain("<span>GitHub northwind/platform, Actions secret OPENAI_API_KEY</span> <span class=\"pill warn\">Replaced</span>")
    expect(rows[1]).toContain('data-region="push-record-facts">version 3, older than the current value, with <code>github-ci</code>, <time datetime="2026-10-07T18:30:00.000Z"')
    expect(rows[1]).toContain(", by Alex</span>")
    expect(rows[0]).toContain('<span class="pill danger">Refused (403)</span>')
    expect(rows[0]).toContain("with <code>cloudflare-deploy</code>")
    expect(rows[3]).toContain('<span class="pill warn">Not confirmed</span>')
    expect(rows[3]).toContain('data-region="push-record-facts">version 4, <time')
    expect(rows[3]).not.toContain("older than the current value")
    expect(rows[3]).not.toContain(", by ")
    for (const hidden of [rows[3], rows[4]]) expect(hidden).not.toContain("with ")
  })

  it("offers push again for the places a done push left on an older value, each unticked", () => {
    const again = between(page("ws-credential-pushed"), 'data-region="push-again"', "</form>")
    expect(again).toContain("<h3>Push the new value to the same places</h3>")
    const boxes = again.match(/<input type="checkbox" data-input="push-record"[^>]*>/g) ?? []
    expect(boxes).toEqual([
      '<input type="checkbox" data-input="push-record" value="psh_gh000001" data-destination="github:northwind/platform/OPENAI_API_KEY" data-field="key" data-via="github-ci">',
      '<input type="checkbox" data-input="push-record" value="psh_gh000002" data-destination="github:northwind/website/env/production/OPENAI_API_KEY" data-field="key" data-via="github-ci">',
    ])
    expect(again).toContain('<span>GitHub northwind/platform, Actions secret OPENAI_API_KEY</span> <span class="small muted">with <code>github-ci</code></span>')
    expect(again).toContain('data-action="push-again">Push with passkey</button>')
    expect(again).not.toContain("itm_")
  })

  it("shows a place whose carrying credential the viewer cannot see disabled, with why, and never as a place to tick", () => {
    const again = between(page("ws-credential-pushed"), 'data-region="push-again"', "</form>")
    const unseen = between(again, 'data-region="push-again-unseen"', "</div>")
    expect(unseen).toContain('<label class="tick"><input type="checkbox" disabled><span>GitHub northwind/infra, Dependabot secret OPENAI_API_KEY</span></label>')
    expect(unseen).toContain('<p class="small muted">The credential that carried it is not one you can see, so it cannot be pushed again from here.</p>')
    expect(again).not.toContain("psh_gh000003")
  })

  it("says why instead when four eyes guard it or the allowance is off, and offers nothing to someone who may not push it", () => {
    const refused = (id: string) => between(page(id), 'data-region="push-again"', "</div>")
    expect(refused("ws-credential-pushed-four-eyes")).toContain('data-region="push-again-refused">Push this from a machine&#39;s ask, so a second person decides.</p>')
    expect(refused("ws-credential-pushed-not-allowed")).toContain('data-region="push-again-refused">Allow it under Other services&#39; secret stores first to push it again.</p>')
    for (const id of ["ws-credential-pushed-four-eyes", "ws-credential-pushed-not-allowed"]) expect(page(id), id).not.toContain('data-action="push-again"')
    const reader = page("ws-credential-pushed-reader")
    expect(reader).toContain('data-region="pushed-to"')
    expect(reader).not.toContain('data-region="push-again"')
  })

  it("lists in the delete confirmation the places a copy stays, never one that was refused", () => {
    const zone = between(page("ws-credential-pushed"), 'data-region="push-delete"', "</div>")
    expect(zone).toContain("Deleting removes it from Mehen only. The copies in these places stay where they are.")
    expect(zone.match(/<li>[^<]*<\/li>/g)).toEqual(["<li>GitHub northwind/platform, Actions secret OPENAI_API_KEY</li>", "<li>GitHub northwind/website, environment production, Actions secret OPENAI_API_KEY</li>", "<li>Vercel web-app, production variable OPENAI_API_KEY</li>", "<li>GitHub northwind/infra, Dependabot secret OPENAI_API_KEY</li>"])
    expect(page("ws-credential-push-allowance")).not.toContain('data-region="push-delete"')
  })
})
