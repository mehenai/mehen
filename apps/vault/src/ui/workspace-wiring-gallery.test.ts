// The wiring on the workspace pages, rendered from the gallery: team
// share subjects (visible to managers, never to guests, duplicate and
// hostile names told apart and inert), the run approval that changed while
// its page was built, and the Use my own action check that insists on the
// credential's stable id.

import { describe, expect, it } from "vitest"
import { TeamViewSchema } from "@mehen/protocol/workspace"
import { renderDocument } from "./layout.ts"
import { workspaceApprovalPage } from "./pages/workspace-asks.ts"
import { CHANGED_SINCE_REQUESTED } from "./wording.ts"
import { workspaceProjectPage } from "./pages/workspace-projects.ts"
import { overrideChange } from "./client/workspace-logic.ts"
import { GALLERY_FIXTURES, GALLERY_HOSTILE_NAME, GALLERY_ITEMS, GALLERY_MEMBERS, GALLERY_TEAMS, VIEWERS, galleryShell, workspaceProjectsGallery } from "./workspace-projects-gallery.ts"
import { galleryRunApproval, galleryStaleRunApproval, workspaceAsksGallery } from "./workspace-asks-gallery.ts"
import type { WorkspaceProject } from "@mehen/protocol/workspace"

function rendered(id: string): string {
  const found = [...workspaceProjectsGallery(), ...workspaceAsksGallery()].find((e) => e.id === id)
  if (found === undefined) throw new Error(`no gallery entry ${id}`)
  return renderDocument(found.page).value
}

function between(text: string, from: string, to: string): string {
  const start = text.indexOf(from)
  const end = text.indexOf(to, start + from.length)
  return text.slice(start, end === -1 ? undefined : end)
}

const shareForm = (text: string) => between(text, 'data-form="share"', "</form>")

describe("team share subjects", () => {
  it("the gallery's teams are in the frozen protocol shape", () => {
    for (const t of GALLERY_TEAMS) expect(TeamViewSchema.parse(t)).toEqual(t)
  })

  it("a manager's share form offers every team by name and slug beside the people", () => {
    const form = shareForm(rendered("ws-project-share-teams"))
    expect(form).toContain('data-region="team-subjects"')
    for (const t of GALLERY_TEAMS) expect(form, t.id).toContain(`value="${t.id}" data-kind="team"`)
    // Two teams called Platform stay apart by slug.
    expect(form).toContain("Platform (team platform)")
    expect(form).toContain("Platform (team platform-ops)")
    // People are still offered, with their own kind.
    expect(form).toContain('value="mem_tom00002" data-kind="member"')
  })

  it("a hostile team name is inert in the option and in the share list", () => {
    const page = rendered("ws-project-share-teams")
    expect(page).not.toContain("<b>admin</b>")
    expect(page).not.toContain("\u202e")
    expect(page).not.toContain("\u0007")
    expect(page).toContain("&lt;b&gt;admin&lt;/b&gt;")
    expect(GALLERY_HOSTILE_NAME).toContain("<b>")
  })

  it("an existing team share is named by the team, not its id alone", () => {
    const list = between(rendered("ws-project-share-teams"), 'class="share-list"', "</ul>")
    expect(list).toContain("team Engineering (engineering)")
  })

  it("choosing a team has its own reach warning, hidden until chosen", () => {
    const form = shareForm(rendered("ws-project-share-teams"))
    expect(form).toContain('data-region="team-reach" hidden')
    expect(between(form, 'data-region="team-reach"', "</p>")).toContain("openai-prod (workspace credential)")
  })

  it("a guest's page has no team list, even if teams were somehow passed", () => {
    const project: WorkspaceProject = { id: "prj_platform01", slug: "platform", remotes: [], defaultEnv: "dev", access: GALLERY_FIXTURES.GUEST_ACCESS, environments: [{ name: "dev", protected: false, fences: [], fourEyes: false }], vars: [] }
    const page = renderDocument(workspaceProjectPage(galleryShell(VIEWERS.guest), { viewer: VIEWERS.guest, project, items: [], members: null, overrides: null, teams: GALLERY_TEAMS })).value
    for (const t of GALLERY_TEAMS) {
      expect(page, t.id).not.toContain(t.id)
      expect(page, t.slug).not.toContain(`(team ${t.slug})`)
    }
    expect(page).not.toContain('data-region="team-subjects"')
    expect(rendered("ws-project-guest")).not.toContain("tm_")
  })

  it("without the team read, the form offers people only and a team share falls back to its id", () => {
    const project = { id: "prj_platform01", slug: "platform", remotes: [], defaultEnv: "dev", access: GALLERY_FIXTURES.OWNER_ACCESS, shares: GALLERY_FIXTURES.SHARES, environments: [{ name: "dev", protected: false, fences: [], fourEyes: false }], vars: [] } satisfies WorkspaceProject
    const page = renderDocument(workspaceProjectPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, project, items: GALLERY_ITEMS, members: GALLERY_MEMBERS, overrides: null, teams: null })).value
    expect(shareForm(page)).not.toContain('data-kind="team"')
    expect(page).toContain("team tm_eng00001")
  })
})

describe("a run approval that changed while its page was built", () => {
  it("says so and offers no decision", () => {
    const page = rendered("ws-approval-changed")
    expect(page).toContain('data-region="changed-since-requested"')
    expect(page).toContain(CHANGED_SINCE_REQUESTED)
    expect(page).not.toContain('data-action="approve"')
    expect(page).not.toContain('data-form="decide"')
  })

  it("a pending approval the second read found changed is not decidable either", () => {
    const project = { id: "prj_platform01", slug: "platform", remotes: [], defaultEnv: "dev", access: GALLERY_FIXTURES.OWNER_ACCESS, environments: [{ name: "prod", protected: true, fences: [], fourEyes: true }], vars: [] } satisfies WorkspaceProject
    const shell = galleryShell({ role: "admin", member: "mem_tom00001" })
    const changed = renderDocument(workspaceApprovalPage(shell, { viewer: { role: "admin", member: "mem_tom00001" }, view: galleryRunApproval(true, ["Tom"]), project, items: [], changedSinceRequested: true })).value
    expect(changed).toContain(CHANGED_SINCE_REQUESTED)
    expect(changed).not.toContain('data-action="approve"')
    const steady = renderDocument(workspaceApprovalPage(shell, { viewer: { role: "admin", member: "mem_tom00001" }, view: galleryRunApproval(true, ["Tom"]), project, items: [], changedSinceRequested: false })).value
    expect(steady).not.toContain('data-region="changed-since-requested"')
    expect(steady).toContain('data-action="approve"')
  })

  it("a stale run approval says it changed even without a race", () => {
    const project = { id: "prj_platform01", slug: "platform", remotes: [], defaultEnv: "dev", access: GALLERY_FIXTURES.OWNER_ACCESS, environments: [{ name: "prod", protected: true, fences: [], fourEyes: false }], vars: [] } satisfies WorkspaceProject
    const page = renderDocument(workspaceApprovalPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, view: galleryStaleRunApproval(), project, items: [] })).value
    expect(page).toContain(CHANGED_SINCE_REQUESTED)
  })
})

describe("Use my own signs only a stable-id action", () => {
  const change = overrideChange("prj_a", "dev", "OPENAI_API_KEY", { kind: "item", item: "openai-alex", field: "key" })
  const action = { type: "override.set", project: "prj_a", environment: "dev", variable: "OPENAI_API_KEY", source: { kind: "item", item: "itm_Q2w8Zr4", field: "key" } }

  it("accepts the vault's canonical action with the stable id in place of the slug", () => {
    expect(change.matches(action)).toBe(true)
  })

  it("refuses an action that still carries a slug, or anything that is not an item id", () => {
    for (const item of ["openai-alex", "other-key", "", "itm_", "itm_a b"]) expect(change.matches({ ...action, source: { ...action.source, item } }), item).toBe(false)
  })

  it("refuses an action with any extra part, at the top or in its source", () => {
    expect(change.matches({ ...action, member: "mem_other" })).toBe(false)
    expect(change.matches({ ...action, source: { ...action.source, value: "x" } })).toBe(false)
    const plain = overrideChange("prj_a", "dev", "LOG_LEVEL", { kind: "plain", value: "debug" })
    expect(plain.matches({ type: "override.set", project: "prj_a", environment: "dev", variable: "LOG_LEVEL", source: { kind: "plain", value: "debug" } })).toBe(true)
    expect(plain.matches({ type: "override.set", project: "prj_a", environment: "dev", variable: "LOG_LEVEL", source: { kind: "plain", value: "debug", item: "itm_x" } })).toBe(false)
  })
})

describe("Use my own never prints a plain override value", () => {
  it("the summary names a plain override only as your own plain value", () => {
    const SENTINEL = "PLAIN-OVERRIDE-MUST-NOT-BE-RENDERED"
    const project: WorkspaceProject = { id: "prj_platform01", slug: "platform", remotes: [], defaultEnv: "dev", access: GALLERY_FIXTURES.OWNER_ACCESS, environments: [{ name: "dev", protected: false, fences: [], fourEyes: false }], vars: [{ name: "LOG_LEVEL", env: "dev", source: "unset", item: null, field: null }] }
    const page = renderDocument(workspaceProjectPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, project, items: [], members: GALLERY_MEMBERS, overrides: [{ environment: "dev", variable: "LOG_LEVEL", source: { kind: "plain", value: SENTINEL }, updatedAt: "2026-10-27T18:00:00.000Z" }], teams: null })).value
    expect(page).toContain('data-own-source="plain">Your runs use your own plain value instead.')
    expect(page).toContain('data-action="clear-own" data-env="dev" data-var="LOG_LEVEL"')
    expect(page).not.toContain(SENTINEL)
  })
})

describe("shared wording", () => {
  it("the changed-since-requested sentence lives in wording.ts, exactly, naming no source or value", () => {
    expect(CHANGED_SINCE_REQUESTED).toBe("This request changed since it was asked for: a credential it uses, or the access it needs, is no longer what was requested. Nothing can be approved from this page; reload it, or ask the agent to run again for a fresh approval.")
  })
})
