// The project page's share form in the browser path:
// the page the server renders, run in test/mini-dom.ts with the production
// initWorkspaceProject wiring it, the API answered here and the passkey
// prompt stubbed. Picking a team by its own option element sends kind "team"
// and its stable id to the preparation, the step-up and the mutation; an
// existing team share supplies the before-state; the team reach warning
// shows for teams only; and a prepared action about anyone else refuses
// before the step-up starts. The form starts from the chosen subject's
// current terms, its end included, as a UTC day: changing only the level
// keeps the end exactly, removing or extending it is said beside the button
// before the passkey, and a passed end is refused with nothing sent.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import type { Share, WorkspaceItemSummary, WorkspaceProject } from "@mehen/protocol/workspace"
import { renderDocument } from "../src/ui/layout.ts"
import { workspaceProjectPage } from "../src/ui/pages/workspace-projects.ts"
import { GALLERY_MEMBERS, GALLERY_TEAMS, VIEWERS, galleryShell } from "../src/ui/workspace-projects-gallery.ts"
import { initWorkspaceProject } from "../src/ui/client/pages/workspace.ts"
import { ShellState } from "../src/ui/client/shell-logic.ts"
import type { Boot } from "../src/ui/client/dom.ts"
import { SHARE_END_PASSED_PROBLEM, SHARE_END_TOO_LATE_PROBLEM, SHARE_NO_LONGER_ENDS_WORDS, shareEndsLaterWords } from "../src/ui/wording.ts"
import { type MiniBrowser, type MiniElement, MiniEvent, installPage, settle } from "./mini-dom.ts"

const passkey = vi.hoisted(() => ({ prompts: 0 }))
vi.mock("@simplewebauthn/browser", () => ({
  startAuthentication: async () => {
    passkey.prompts++
    return { id: "test-assertion" }
  },
  startRegistration: async () => ({ id: "test-registration" }),
}))

const WORKSPACE = { id: "tn_8kQw2Lm4Zp7Rt5Vx", slug: "northwind", name: "Northwind" }
const PROJECT = "prj_platform01"
const PLATFORM = GALLERY_TEAMS.find((t) => t.slug === "platform")!
const PLATFORM_OPS = GALLERY_TEAMS.find((t) => t.slug === "platform-ops")!
// Platform-ops already has Use, including protected environments.
const OPS_SHARE: Share = { id: "shr_ops00001", project: PROJECT, subject: { kind: "team", team: PLATFORM_OPS.id }, level: "use", protected: true, expiresAt: null }
// Kim has Edit, including protected environments, ending in a week at a
// time of day the form's UTC day does not name; Noor's share has ended.
const DAY = 86_400_000
const KIM_SHARE: Share = { id: "shr_kim00001", project: PROJECT, subject: { kind: "member", member: "mem_kim00001" }, level: "edit", protected: true, expiresAt: new Date(Date.now() + 7 * DAY).toISOString() }
const NOOR_SHARE: Share = { id: "shr_noor0001", project: PROJECT, subject: { kind: "member", member: "mem_noor0001" }, level: "use", protected: false, expiresAt: "2025-12-31T10:00:00.000Z" }
const utcDay = (at: number) => new Date(at).toISOString().slice(0, 10)
const KIM_DAY = utcDay(Date.parse(KIM_SHARE.expiresAt!))

const project: WorkspaceProject = {
  id: PROJECT, slug: "platform", remotes: [], defaultEnv: "dev",
  access: { level: "manage", runProtected: true, editProtected: true, sources: [{ kind: "role", role: "owner" }] },
  shares: [OPS_SHARE, KIM_SHARE, NOOR_SHARE],
  environments: [{ name: "dev", protected: false, fences: [], fourEyes: false }],
  vars: [{ name: "OPENAI_API_KEY", env: "dev", source: "item", item: "openai-prod", field: "key" }],
}
const items: WorkspaceItemSummary[] = [{ slug: "openai-prod", kind: "api-key", provider: "openai", account: null, accountVerified: false, tags: [], ceiling: "relay", hosts: ["api.openai.com"], status: "active", updatedAt: "2026-10-27T18:00:00.000Z", home: { kind: "workspace" } }]

let browser: MiniBrowser | null = null
// What the vault's preparation hands back; by default the canonical share.
let prepared: (input: Record<string, unknown>) => unknown

beforeEach(() => {
  passkey.prompts = 0
  prepared = (input) => ({ type: "project.share", project: input.project, subject: input.subject, before: input.before, after: input.after })
})
afterEach(() => {
  browser?.restore()
  browser = null
})

type Viewer = (typeof VIEWERS)[keyof typeof VIEWERS] | { role: "admin"; member: string }
function open(shareWith: string | null = null, viewer: Viewer = VIEWERS.owner): MiniBrowser {
  const markup = renderDocument(workspaceProjectPage(galleryShell(viewer), { viewer, project, items, members: GALLERY_MEMBERS, overrides: [], teams: GALLERY_TEAMS, shareWith })).value
  browser = installPage(markup, (path, body) => {
    if (path === "/api/w/northwind/projects/action") return { status: 200, body: prepared((body as { input: Record<string, unknown> }).input) }
    if (path === "/api/w/northwind") return { status: 200, body: WORKSPACE }
    if (path === "/api/w/northwind/stepup/start") return { status: 200, body: { nonce: "n1", options: { challenge: "c1", allowCredentials: [] } } }
    if (path === `/api/w/northwind/projects/${PROJECT}/shares`) return { status: 200, body: {} }
    return { status: 404, body: { error: "not_found", message: "No such route." } }
  })
  const boot = JSON.parse(browser.document.querySelector("#app")?.getAttribute("data-boot") ?? "{}") as Boot
  initWorkspaceProject(boot, new ShellState({ origin: "https://vault.test", account: "acc_4Hq9Tz2Lm7Vb1Nc8", workspace: WORKSPACE, pages: [], reads: [] }))
  return browser
}

function shareForm(b: MiniBrowser) {
  const form = b.document.querySelector('[data-form="share"]')
  if (form === null) throw new Error("no share form")
  const subject = form.querySelector('[data-input="subject"]')!
  const option = (value: string): MiniElement => {
    const found = subject.options.find((o) => o.getAttribute("value") === value)
    if (found === undefined) throw new Error(`no option ${value}`)
    return found
  }
  return {
    option,
    subject,
    pick(o: MiniElement) {
      o.selected = true
      subject.dispatchEvent(new MiniEvent("change", { bubbles: true }))
    },
    teamReach: form.querySelector('[data-region="team-reach"]')!,
    guestReach: form.querySelector('[data-region="guest-reach"]')!,
    level: form.querySelector('[data-input="level"]')!,
    protect: form.querySelector('[data-input="protected"]')!,
    ends: form.querySelector('[data-input="ends"]')!,
    endChange: form.querySelector('[data-region="share-end-change"]')!,
    chooseLevel(value: string) {
      this.level.value = value
      this.level.dispatchEvent(new MiniEvent("change", { bubbles: true }))
    },
    end(day: string) {
      this.ends.value = day
      this.ends.dispatchEvent(new MiniEvent("input", { bubbles: true }))
    },
    async share() {
      form.querySelector('[data-action="share"]')!.click()
      await settle()
    },
  }
}

const sent = (b: MiniBrowser, path: string) => b.calls.filter((c) => c.path === path).map((c) => c.body)

describe("the share form's team subjects in the browser", () => {
  it("each of two teams called Platform is shared by its own option, as kind team with its stable id, in preparation, step-up and mutation", async () => {
    for (const team of [PLATFORM, PLATFORM_OPS]) {
      const b = open()
      const form = shareForm(b)
      const platforms = b.document.querySelectorAll('[data-kind="team"]').filter((o) => o.textContent.startsWith("Platform ("))
      expect(platforms.map((o) => o.getAttribute("value"))).toEqual([PLATFORM.id, PLATFORM_OPS.id])
      form.pick(platforms.find((o) => o.getAttribute("value") === team.id)!)
      await form.share()
      const before = team.id === PLATFORM_OPS.id ? { level: "use", protected: true, expiresAt: null } : null
      const input = { project: PROJECT, subject: { kind: "team", team: team.id }, before, after: before ?? { level: "use", protected: false, expiresAt: null } }
      expect(sent(b, "/api/w/northwind/projects/action"), team.slug).toEqual([{ change: "share", input }])
      expect(sent(b, "/api/w/northwind/stepup/start"), team.slug).toEqual([{ action: { type: "project.share", ...input } }])
      expect(sent(b, `/api/w/northwind/projects/${PROJECT}/shares`), team.slug).toEqual([{ ...input, stepUp: { nonce: "n1", assertion: { id: "test-assertion" } } }])
      expect(b.reloaded, team.slug).toBe(1)
      b.restore()
    }
    expect(passkey.prompts).toBe(2)
  })

  it("the team reach warning shows for a team and goes for a member; the guest one only for a guest", () => {
    const form = shareForm(open())
    expect(form.teamReach.textContent).toContain("openai-prod (workspace credential)")
    form.pick(form.option(PLATFORM.id))
    expect([form.teamReach.hidden, form.guestReach.hidden]).toEqual([false, true])
    form.pick(form.option("mem_tom00002"))
    expect([form.teamReach.hidden, form.guestReach.hidden]).toEqual([true, true])
    form.pick(form.option("mem_sam00001"))
    expect([form.teamReach.hidden, form.guestReach.hidden]).toEqual([true, false])
    form.pick(form.option(PLATFORM_OPS.id))
    expect([form.teamReach.hidden, form.guestReach.hidden]).toEqual([false, true])
  })

  it("a member chosen by its option is still shared as kind member", async () => {
    const b = open()
    const form = shareForm(b)
    form.pick(form.option("mem_tom00002"))
    await form.share()
    expect(sent(b, "/api/w/northwind/projects/action")).toEqual([{ change: "share", input: { project: PROJECT, subject: { kind: "member", member: "mem_tom00002" }, before: null, after: { level: "use", protected: false, expiresAt: null } } }])
  })

  // A share request's link names the member: the form starts
  // open with them chosen, their current terms filled in.
  it("?share= opens the form with that member chosen, and shares with them", async () => {
    const b = open("mem_tom00002")
    expect(b.document.querySelector('[data-region="share-fold"]')!.hasAttribute("open")).toBe(true)
    const form = shareForm(b)
    expect(form.option("mem_tom00002").selected).toBe(true)
    expect(b.document.querySelectorAll("option[selected]").map((o) => o.getAttribute("value"))).toEqual(["mem_tom00002"])
    await form.share()
    expect(sent(b, "/api/w/northwind/projects/action")).toEqual([{ change: "share", input: { project: PROJECT, subject: { kind: "member", member: "mem_tom00002" }, before: null, after: { level: "use", protected: false, expiresAt: null } } }])
  })

  it("?share= naming someone with a share starts from their terms; naming nobody it offers changes nothing", () => {
    const kim = shareForm(open("mem_kim00001"))
    expect([kim.option("mem_kim00001").selected, kim.level.value, kim.protect.checked, kim.ends.value]).toEqual([true, "edit", true, KIM_DAY])
    browser!.restore()
    for (const shareWith of [null, "mem_nobody01"]) {
      const b = open(shareWith)
      expect(b.document.querySelector('[data-region="share-fold"]')!.hasAttribute("open"), String(shareWith)).toBe(false)
      expect(b.document.querySelectorAll("option[selected]"), String(shareWith)).toEqual([])
      b.restore()
    }
  })

  for (const viewer of [VIEWERS.owner, { role: "admin" as const, member: "mem_tom00001" }])
    it(`?share= naming a guest opens the form with the guest chosen for an ${viewer.role}`, () => {
      const b = open("mem_sam00001", viewer)
      expect(b.document.querySelector('[data-region="share-fold"]')!.hasAttribute("open")).toBe(true)
      expect(b.document.querySelectorAll("option[selected]").map((o) => o.getAttribute("value"))).toEqual(["mem_sam00001"])
      expect(b.document.querySelector('[data-region="share-not-offered"]')).toBeNull()
    })

  it("?share= naming a guest a project manager may not share with says so, chooses no one, and shares with no one", async () => {
    const b = open("mem_sam00001", VIEWERS.manager)
    expect(b.document.querySelector('[data-region="share-fold"]')!.hasAttribute("open")).toBe(true)
    expect(b.document.querySelector('[data-region="share-not-offered"]')!.textContent).toBe("Only an owner or admin can share this project with a guest.")
    const form = shareForm(b)
    expect(form.subject.value).toBe("")
    expect(b.document.querySelectorAll("option[selected]").map((o) => o.getAttribute("value"))).toEqual([""])
    expect(() => form.option("mem_sam00001")).toThrow()
    await form.share()
    expect(sent(b, "/api/w/northwind/projects/action")).toEqual([])
    expect(passkey.prompts).toBe(0)
  })

  it("a prepared action about anyone but the chosen team refuses before the step-up starts", async () => {
    for (const other of [{ kind: "member", member: PLATFORM.id }, { kind: "team", team: PLATFORM_OPS.id }]) {
      prepared = (input) => ({ type: "project.share", project: input.project, subject: other, before: input.before, after: input.after })
      const b = open()
      const form = shareForm(b)
      form.pick(form.option(PLATFORM.id))
      await form.share()
      expect(b.calls.map((c) => c.path), JSON.stringify(other)).toEqual(["/api/w/northwind/projects/action"])
      expect(b.reloaded).toBe(0)
      expect(b.document.querySelector("#notice")?.textContent).toContain("something changed since the page loaded")
      b.restore()
    }
    expect(passkey.prompts).toBe(0)
  })
})

describe("the share form's end in the browser", () => {
  const kimBefore = { level: "edit", protected: true, expiresAt: KIM_SHARE.expiresAt }
  const signedAfter = (b: MiniBrowser) => (sent(b, "/api/w/northwind/projects/action") as { input: { before: unknown; after: unknown } }[]).map((c) => [c.input.before, c.input.after])

  it("starts from the chosen subject's level, protected tick and end, and a subject with no share from none", () => {
    const form = shareForm(open())
    form.pick(form.option("mem_kim00001"))
    expect([form.level.value, form.protect.checked, form.ends.value]).toEqual(["edit", true, KIM_DAY])
    expect(form.endChange.hidden).toBe(true)
    form.pick(form.option("mem_tom00002"))
    expect([form.level.value, form.protect.checked, form.ends.value]).toEqual(["use", false, ""])
  })

  it("changing only the level signs the end the share already has, to the millisecond", async () => {
    const b = open()
    const form = shareForm(b)
    form.pick(form.option("mem_kim00001"))
    form.chooseLevel("use")
    expect(form.endChange.hidden).toBe(true)
    await form.share()
    expect(signedAfter(b)).toEqual([[kimBefore, { level: "use", protected: true, expiresAt: KIM_SHARE.expiresAt }]])
    expect(sent(b, "/api/w/northwind/stepup/start")).toEqual([{ action: { type: "project.share", project: PROJECT, subject: { kind: "member", member: "mem_kim00001" }, before: kimBefore, after: { level: "use", protected: true, expiresAt: KIM_SHARE.expiresAt } } }])
    expect(passkey.prompts).toBe(1)
  })

  it("clearing the end says the share will no longer end, beside the button, and signs no end", async () => {
    const b = open()
    const form = shareForm(b)
    form.pick(form.option("mem_kim00001"))
    form.end("")
    expect([form.endChange.hidden, form.endChange.textContent]).toEqual([false, SHARE_NO_LONGER_ENDS_WORDS])
    await form.share()
    expect(signedAfter(b)).toEqual([[kimBefore, { level: "edit", protected: true, expiresAt: null }]])
    expect(passkey.prompts).toBe(1)
  })

  it("a later day says the new end before the passkey; an earlier one ends the share at 23:59 UTC that day and says nothing", async () => {
    const later = utcDay(Date.parse(KIM_SHARE.expiresAt!) + 10 * DAY)
    const b = open()
    const form = shareForm(b)
    form.pick(form.option("mem_kim00001"))
    form.end(later)
    expect([form.endChange.hidden, form.endChange.textContent]).toEqual([false, shareEndsLaterWords(`${later}T23:59:59.999Z`)])
    expect(form.endChange.textContent).toMatch(/^This share will now end on \d{1,2} [A-Z][a-z]{2} \d{4}, 23:59 UTC\.$/)
    await form.share()
    expect(signedAfter(b)).toEqual([[kimBefore, { level: "edit", protected: true, expiresAt: `${later}T23:59:59.999Z` }]])
    b.restore()

    const earlier = utcDay(Date.now() + 2 * DAY)
    const again = open()
    const narrowed = shareForm(again)
    narrowed.pick(narrowed.option("mem_kim00001"))
    narrowed.end(earlier)
    expect(narrowed.endChange.hidden).toBe(true)
    await narrowed.share()
    expect(signedAfter(again)).toEqual([[kimBefore, { level: "edit", protected: true, expiresAt: `${earlier}T23:59:59.999Z` }]])
  })

  it("a day that has passed, typed or kept from an ended share, is refused with nothing sent and no passkey", async () => {
    for (const [who, day] of [["mem_tom00002", "2020-01-01"], ["mem_noor0001", null]] as const) {
      const b = open()
      const form = shareForm(b)
      form.pick(form.option(who))
      if (day !== null) form.end(day)
      else expect(form.ends.value, who).toBe("2025-12-31")
      await form.share()
      expect(b.calls.map((c) => c.path), who).toEqual([])
      expect(b.document.querySelector("#notice")?.textContent, who).toContain(SHARE_END_PASSED_PROBLEM)
      b.restore()
    }
    expect(passkey.prompts).toBe(0)
  })

  it("a day more than 365 days away is refused before anything is sent, as the vault would refuse it", async () => {
    const b = open()
    const form = shareForm(b)
    form.pick(form.option("mem_tom00002"))
    form.end(utcDay(Date.now() + 400 * DAY))
    await form.share()
    expect(b.calls).toEqual([])
    expect(b.document.querySelector("#notice")?.textContent).toContain(SHARE_END_TOO_LATE_PROBLEM)
    expect(passkey.prompts).toBe(0)
  })
})
