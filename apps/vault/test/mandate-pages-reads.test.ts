// What the mandate pages, the machine page, the home and the ask page read
// for what a machine may do without asking (routes/ui-mandates.ts,
// routes/ui-people.ts, routes/ui.ts homePage, routes/ui-projects.ts),
// counted at the one door every workspaceApiGet goes through
// (routes/workspace-prefix.ts workspacePrefix), which this stub answers, as
// posture-pages-reads.test.ts does. With MANDATES off here none of them
// reads a mandate route, and the mandate pages are not served.
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest"
import type { RequestContext } from "../src/routes/context.ts"
import type { WorkspacePage } from "../src/routes/ui.ts"

const vault = vi.hoisted(() => ({ reads: [] as string[], answers: new Map<string, unknown>(), refusals: new Map<string, { status: number; body: unknown }>() }))
vi.mock("../src/routes/workspace-prefix.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/routes/workspace-prefix.ts")>()),
  workspacePrefix: async (rc: RequestContext) => {
    const path = rc.url.pathname.replace(/^\/api\/w\/[^/]+/, "") + rc.url.search
    vault.reads.push(path)
    const refusal = vault.refusals.get(path)
    if (refusal !== undefined) return Response.json(refusal.body, { status: refusal.status })
    return vault.answers.has(path) ? Response.json(vault.answers.get(path)) : Response.json({ error: "not_found", message: "No such route." }, { status: 404 })
  },
}))

type Fixtures = typeof import("../src/ui/people-gallery.ts") & typeof import("../src/ui/mandates-gallery.ts") & typeof import("../src/ui/workspace-projects-gallery.ts") & typeof import("../src/ui/workspace-asks-gallery.ts")
let fx: Fixtures
let pages: Record<"home" | "machine" | "ask" | "list" | "sign" | "mandate", WorkspacePage>
beforeAll(async () => {
  vi.resetModules()
  await import("../src/index.ts")
  const [ui, ...galleries] = await Promise.all([import("../src/routes/ui.ts"), import("../src/ui/people-gallery.ts"), import("../src/ui/mandates-gallery.ts"), import("../src/ui/workspace-projects-gallery.ts"), import("../src/ui/workspace-asks-gallery.ts")])
  fx = Object.assign({}, ...galleries) as Fixtures
  const at = (path: string) => ui.WORKSPACE_PAGES.find((p) => p.path === path) ?? (() => { throw new Error(`no page ${path}`) })()
  pages = { home: at("/"), machine: at("/devices/:id"), ask: at("/a/:id"), list: at("/mandates"), sign: at("/sign-mandate"), mandate: at("/mandates/:id") }
})

const TOM = { role: "member" as const, member: "mem_tom01" }
const MANDATE = () => fx.GALLERY_MANDATE
const CANDIDATES = { items: [{ id: "itm_githubtom0000001", slug: "github-tom" }, { id: "itm_slackplat000001", slug: "slack-platform" }, { id: "itm_openaitom000001", slug: "openai-tom" }] }

beforeEach(() => {
  const m = MANDATE()
  vault.reads = []
  vault.refusals = new Map()
  vault.answers = new Map<string, unknown>([
    ["", fx.GALLERY_WORKSPACE],
    ["/inbox", { workspace: { workspace: fx.GALLERY_WORKSPACE, state: "ok", truncated: false }, items: [] }],
    ["/items", { items: [] }],
    ["/projects", { projects: [] }],
    ["/devices", { devices: [fx.PEOPLE_DEVICE] }],
    [`/devices/${fx.PEOPLE_DEVICE.device}`, fx.PEOPLE_DEVICE],
    [`/devices/${fx.PEOPLE_DEVICE.device}/workloads`, { workloads: [] }],
    // Tom's laptop active, Kim's desk active, an older one stopped.
    ["/mandates", { mandates: [m, { ...m, id: "mdt_kimdesk0000000001", device: { id: "dev_kimdesk01", name: "kim-desk" } }, { ...m, id: "mdt_tomold00000000001", state: "stopped", endedReason: "stopped" }], proposals: [] }],
    [`/mandates/${m.id}`, m],
    [`/mandates/${m.id}/uses`, fx.GALLERY_RECEIPTS],
    [`/mandates/${m.id}/uses?before=1761500000000.mdu_0001`, { receipts: [], next: null }],
    [`/mandate-candidates?device=${fx.PEOPLE_DEVICE.device}`, CANDIDATES],
    ["/approvals/apr_3mz8kq1vx5", fx.galleryEmailApproval()],
    ["/mandate-asks/apr_3mz8kq1vx5", { mandate: m.id, capped: [{ class: "send", cap: 50 }] }],
  ])
})

const ON = { POLICY_RULES: "off", MANDATES: "on", VAULT_ORIGIN: "https://vault.test" }
const OFF = { ...ON, MANDATES: "tn_elsewhere0001" }

async function open(page: WorkspacePage, params: Record<string, string>, options: { viewer?: { role: "owner" | "admin" | "member" | "guest"; member: string }; env?: Record<string, string>; query?: string } = {}): Promise<string> {
  const viewer = options.viewer ?? fx.VIEWERS.owner
  const url = new URL(`https://vault.test/w/${fx.GALLERY_WORKSPACE.slug}${options.query ?? ""}`)
  const rc = { request: new Request(url), env: options.env ?? ON, ctx: {}, url, params } as unknown as RequestContext
  const workspace = { workspace: fx.GALLERY_WORKSPACE, membership: viewer.member, account: {} } as never
  const response = await page.render(rc, { workspace, shell: fx.galleryShell(viewer) })
  expect(response.status).toBe(200)
  return response.text()
}
const mandateReads = () => vault.reads.filter((r) => r.startsWith("/mandate"))

describe("the switch", () => {
  it("serves the mandate pages only with MANDATES on here", () => {
    for (const page of [pages.list, pages.sign, pages.mandate]) {
      expect(page.on?.(ON as never, fx.GALLERY_WORKSPACE.id)).toBe(true)
      expect(page.on?.(OFF as never, fx.GALLERY_WORKSPACE.id)).toBe(false)
    }
  })

  it("reads no mandate route on the home, the machine page or the ask page with MANDATES off", async () => {
    expect(await open(pages.home, {}, { env: OFF })).not.toContain('data-region="mandate-strip"')
    expect(await open(pages.machine, { id: fx.PEOPLE_DEVICE.device }, { viewer: TOM, env: OFF })).not.toContain('data-region="mandate-card"')
    expect(await open(pages.ask, { id: "apr_3mz8kq1vx5" }, { env: OFF })).not.toContain('data-region="mandate-capped"')
    expect(mandateReads()).toEqual([])
  })
})

describe("the home's strip", () => {
  it("counts the machines whose mandate is active and links to the list", async () => {
    const page = await open(pages.home, {})
    expect(mandateReads()).toEqual(["/mandates"])
    expect(page).toContain(`<a class="strip card" data-region="mandate-strip" href="/w/${fx.GALLERY_WORKSPACE.slug}/mandates">`)
    expect(page).toContain("<span>2 machines are carrying on without asking</span>")
    vault.answers.set("/mandates", { mandates: [MANDATE()], proposals: [] })
    expect(await open(pages.home, {})).toContain("<span>1 machine is carrying on without asking</span>")
    vault.answers.set("/mandates", { mandates: [{ ...MANDATE(), state: "paused" }], proposals: [] })
    expect(await open(pages.home, {})).not.toContain('data-region="mandate-strip"')
    // Active, but its signer no longer stands behind it: it covers nothing.
    vault.answers.set("/mandates", { mandates: [{ ...MANDATE(), signerCurrent: false }], proposals: [] })
    const lapsed = await open(pages.home, {})
    expect(lapsed).not.toContain('data-region="mandate-strip"')
    // Its signer is told to resume it; someone else reading it is not.
    expect(lapsed).toContain(`<a class="strip card" data-region="mandate-resume-strip" href="/w/${fx.GALLERY_WORKSPACE.slug}/mandates">`)
    expect(lapsed).toContain("<span>1 machine needs you to resume its mandate</span>")
    vault.answers.set("/mandates", { mandates: [{ ...MANDATE(), signerCurrent: false, signer: { name: "Tom Barker", self: false } }], proposals: [] })
    expect(await open(pages.home, {})).not.toContain('data-region="mandate-resume-strip"')
  })
})

describe("the machine page's card", () => {
  it("shows the machine's live mandate with Pause and Stop for its signer, and no Trust", async () => {
    const page = await open(pages.machine, { id: fx.PEOPLE_DEVICE.device }, { viewer: TOM })
    expect(mandateReads()).toEqual(["/mandates"])
    const card = page.slice(page.indexOf('data-region="mandate-card"'), page.indexOf("</section>", page.indexOf('data-region="mandate-card"')))
    expect(card).toContain(`data-mandate="${MANDATE().id}" data-rev="2" data-state="active"`)
    expect(card).toContain('data-action="mandate-pause"')
    expect(card).toContain('data-action="mandate-stop"')
    expect(card).not.toContain('data-action="mandate-trust"')
    expect(card).toContain("12 of 50 sends today")
  })

  it("offers its owner Trust this machine when it has no live mandate, and nobody else", async () => {
    vault.answers.set("/mandates", { mandates: [{ ...MANDATE(), state: "stopped", endedReason: "stopped" }], proposals: [] })
    const own = await open(pages.machine, { id: fx.PEOPLE_DEVICE.device }, { viewer: TOM })
    expect(own).toContain(`<a class="btn primary sm" data-action="mandate-trust" href="/w/${fx.GALLERY_WORKSPACE.slug}/sign-mandate?device=${fx.PEOPLE_DEVICE.device}">Trust this machine</a>`)
    expect(await open(pages.machine, { id: fx.PEOPLE_DEVICE.device })).not.toContain('data-region="mandate-card"')
  })

  it("shows its owner what this machine proposed, and no other machine's proposals", async () => {
    const waiting = (id: string, device: { id: string; name: string }) => ({ id, url: `https://vault.test/w/${fx.GALLERY_WORKSPACE.slug}/sign-mandate?proposal=${id}`, expiresAt: "2026-11-03T18:30:00.000Z", createdAt: "2026-10-27T18:10:00.000Z", device, classes: ["read"], items: "all", hiddenItems: 0, reason: `For ${device.name}` })
    vault.answers.set("/mandates", { mandates: [], proposals: [waiting("mdp_tomlaptop0000000001", { id: fx.PEOPLE_DEVICE.device, name: fx.PEOPLE_DEVICE.name }), waiting("mdp_tomother0000000001", { id: "dev_tomother01", name: "tom-other" })] })
    const card = await open(pages.machine, { id: fx.PEOPLE_DEVICE.device }, { viewer: TOM })
    const waitingRegion = card.slice(card.indexOf('data-region="mandate-waiting"'))
    expect(waitingRegion).toContain(`href="/w/${fx.GALLERY_WORKSPACE.slug}/sign-mandate?proposal=mdp_tomlaptop0000000001"`)
    expect(card).not.toContain("mdp_tomother0000000001")
    const list = await open(pages.list, {})
    expect(list).toContain("mdp_tomlaptop0000000001")
    expect(list).toContain("mdp_tomother0000000001")
  })

  it("draws no card when the list could not be read", async () => {
    vault.answers.delete("/mandates")
    expect(await open(pages.machine, { id: fx.PEOPLE_DEVICE.device }, { viewer: TOM })).not.toContain('data-region="mandate-card"')
  })
})

describe("the ask page", () => {
  it("says which cap sent a covered request back to asking, and nothing for an ask with no capped record", async () => {
    const page = await open(pages.ask, { id: "apr_3mz8kq1vx5" })
    expect(mandateReads()).toEqual(["/mandate-asks/apr_3mz8kq1vx5", "/mandate-covers/apr_3mz8kq1vx5"])
    expect(page).toContain("<li>This machine&#39;s mandate has used today&#39;s 50 sends.</li>")
    vault.answers.delete("/mandate-asks/apr_3mz8kq1vx5")
    expect(await open(pages.ask, { id: "apr_3mz8kq1vx5" })).not.toContain('data-region="mandate-capped"')
  })

  it("offers whoever may sign for the machine a mandate for asks like this, or its paused mandate, and nobody else anything", async () => {
    const slug = fx.GALLERY_WORKSPACE.slug
    // An ask from Tom's laptop.
    const asked = fx.galleryEmailApproval()
    if (asked.view === "detail") vault.answers.set("/approvals/apr_3mz8kq1vx5", { ...asked, approval: { ...asked.approval, owner: { kind: "member", member: TOM.member, name: "Tom" } } })
    vault.answers.set("/mandate-covers/apr_3mz8kq1vx5", { device: { id: fx.PEOPLE_DEVICE.device, name: fx.PEOPLE_DEVICE.name }, classes: ["change", "send"], state: "sign", mandate: null })
    const sign = await open(pages.ask, { id: "apr_3mz8kq1vx5" }, { viewer: TOM })
    expect(sign).toContain(`<p class="small" data-region="mandate-cover"><a href="/w/${slug}/sign-mandate?device=${fx.PEOPLE_DEVICE.device}&amp;classes=change,send">Let ${fx.PEOPLE_DEVICE.name} carry on with requests like this</a></p>`)
    vault.answers.set("/mandate-covers/apr_3mz8kq1vx5", { device: { id: fx.PEOPLE_DEVICE.device, name: fx.PEOPLE_DEVICE.name }, classes: ["send"], state: "paused", mandate: MANDATE().id })
    const paused = await open(pages.ask, { id: "apr_3mz8kq1vx5" }, { viewer: TOM })
    expect(paused.slice(paused.indexOf('data-region="mandate-cover"'))).toContain(`href="/w/${slug}/mandates/${MANDATE().id}"`)
    expect(paused).not.toContain("/sign-mandate?")
    vault.answers.delete("/mandate-covers/apr_3mz8kq1vx5")
    expect(await open(pages.ask, { id: "apr_3mz8kq1vx5" }, { viewer: TOM })).not.toContain('data-region="mandate-cover"')
    // Anyone but the machine's owner could never sign for it: the page does not ask.
    vault.answers.set("/mandate-covers/apr_3mz8kq1vx5", { device: { id: fx.PEOPLE_DEVICE.device, name: fx.PEOPLE_DEVICE.name }, classes: ["send"], state: "sign", mandate: null })
    vault.reads = []
    expect(await open(pages.ask, { id: "apr_3mz8kq1vx5" })).not.toContain('data-region="mandate-cover"')
    expect(vault.reads).not.toContain("/mandate-covers/apr_3mz8kq1vx5")
  })
})

describe("the mandate pages", () => {
  it("lists live ones before ended ones", async () => {
    const page = await open(pages.list, {})
    expect(page.indexOf('data-region="mandates-live"')).toBeLessThan(page.indexOf('data-region="mandates-ended"'))
    expect(page.slice(page.indexOf('data-region="mandates-ended"'))).toContain("mdt_tomold00000000001")
  })

  it("reads one mandate and its receipts, passing the page of receipts asked for", async () => {
    await open(pages.mandate, { id: MANDATE().id })
    expect(mandateReads()).toEqual([`/mandates/${MANDATE().id}`, `/mandates/${MANDATE().id}/uses`])
    vault.reads = []
    const older = await open(pages.mandate, { id: MANDATE().id }, { query: "?before=1761500000000.mdu_0001" })
    expect(mandateReads()).toEqual([`/mandates/${MANDATE().id}`, `/mandates/${MANDATE().id}/uses?before=1761500000000.mdu_0001`])
    expect(older).toContain("Nothing has gone through on trust yet.")
  })

  it("offers its signer the same terms for each other machine of theirs, read from the machines they may read", async () => {
    const tomDesk = { ...fx.PEOPLE_DEVICE, device: "dev_tomdesk00001", name: "tom-desk" }
    vault.answers.set("/devices", { devices: [fx.PEOPLE_DEVICE, tomDesk, { ...tomDesk, device: "dev_tomold000001", name: "tom-old", revoked: true }, { ...tomDesk, device: "dev_kimdesk01", name: "kim-desk", owner: { kind: "member", member: "mem_kim00001", name: "Kim" } }] })
    const page = await open(pages.mandate, { id: MANDATE().id }, { viewer: TOM })
    expect(vault.reads).toContain("/devices")
    const links = [...page.matchAll(/sign-mandate\?device=(\w+)&amp;from=/g)].map((m) => m[1])
    expect(links).toEqual(["dev_tomdesk00001"])
    vault.reads = []
    vault.answers.set(`/mandates/${MANDATE().id}`, { ...MANDATE(), signer: { name: "Tom Barker", self: false } })
    expect(await open(pages.mandate, { id: MANDATE().id })).not.toContain('data-region="mandate-sign-same"')
    expect(vault.reads).not.toContain("/devices")
  })

  it("opens the sign page on another mandate's terms, keeping the credentials this machine reaches", async () => {
    vault.answers.set(`/mandate-candidates?device=${fx.PEOPLE_DEVICE.device}`, { items: [CANDIDATES.items[1]!] })
    const page = await open(pages.sign, {}, { viewer: TOM, query: `?device=${fx.PEOPLE_DEVICE.device}&from=${MANDATE().id}` })
    expect(mandateReads()).toEqual([`/mandates/${MANDATE().id}`, `/mandate-candidates?device=${fx.PEOPLE_DEVICE.device}`, "/mandates"])
    expect([...page.matchAll(/data-input="mandate-item" value="(\w+)"[^>]*checked/g)].map((m) => m[1])).toEqual(["itm_slackplat000001"])
    expect([...page.matchAll(/data-input="mandate-class" value="(\w+)" checked/g)].map((m) => m[1])).toEqual(["read", "change", "send"])
    expect(page).toContain(`value="${MANDATE().note}"`)
    expect(page).not.toContain('data-region="mandate-renews"')
  })

  it("answers an address no mandate could have as not found, reading nothing", async () => {
    const url = new URL(`https://vault.test/w/${fx.GALLERY_WORKSPACE.slug}`)
    const rc = { request: new Request(url), env: ON, ctx: {}, url, params: { id: "../devices" } } as unknown as RequestContext
    const response = await pages.mandate.render(rc, { workspace: { workspace: fx.GALLERY_WORKSPACE, membership: fx.VIEWERS.owner.member, account: {} } as never, shell: fx.galleryShell(fx.VIEWERS.owner) })
    expect(response.status).toBe(404)
    expect(mandateReads()).toEqual([])
  })

  it("opens the sign page for a machine on its credentials and the machine's live mandate, which signing replaces", async () => {
    const page = await open(pages.sign, {}, { viewer: TOM, query: `?device=${fx.PEOPLE_DEVICE.device}` })
    expect(mandateReads()).toEqual([`/mandate-candidates?device=${fx.PEOPLE_DEVICE.device}`, "/mandates"])
    expect([...page.matchAll(/data-input="mandate-item" value="(\w+)"/g)].map((m) => m[1])).toEqual(CANDIDATES.items.map((c) => c.id))
    expect(page).toContain('data-region="mandate-replaces"')
    expect(page).toContain('data-input="mandate-items" value="listed" checked')
    expect(await open(pages.sign, {}, { viewer: TOM, query: `?device=${fx.PEOPLE_DEVICE.device}&items=all` })).toContain('data-input="mandate-items" value="all" checked')
  })

  it("opens from an ask on the classes it named, read always, and every class otherwise", async () => {
    const ticked = (page: string) => [...page.matchAll(/data-input="mandate-class" value="(\w+)" checked/g)].map((m) => m[1])
    expect(ticked(await open(pages.sign, {}, { viewer: TOM, query: `?device=${fx.PEOPLE_DEVICE.device}&classes=send,nonsense` }))).toEqual(["read", "send"])
    expect(ticked(await open(pages.sign, {}, { viewer: TOM, query: `?device=${fx.PEOPLE_DEVICE.device}` }))).toEqual(["read", "change", "send", "delete"])
  })

  it("renews a mandate on its terms, ticking the credentials it names that the person may name now", async () => {
    const page = await open(pages.sign, {}, { viewer: TOM, query: `?renew=${MANDATE().id}` })
    expect(mandateReads()).toEqual([`/mandates/${MANDATE().id}`, `/mandate-candidates?device=${fx.PEOPLE_DEVICE.device}`, "/mandates"])
    expect([...page.matchAll(/data-input="mandate-item" value="(\w+)"[^>]*checked/g)].map((m) => m[1])).toEqual(["itm_githubtom0000001", "itm_slackplat000001"])
    expect(page).toContain('value="Triage issues and post the daily build summary"')
    expect(page).toContain('data-input="mandate-ttl" value="30" checked')
  })

  it("refuses the form to anyone but the machine's owner", async () => {
    vault.answers.delete(`/mandate-candidates?device=${fx.PEOPLE_DEVICE.device}`)
    const page = await open(pages.sign, {}, { query: `?device=${fx.PEOPLE_DEVICE.device}` })
    expect(page).not.toContain('data-form="mandate-sign"')
    expect(page).toContain("Only Tom Barker can let this machine carry on without asking.")
  })

  it("answers a frozen workspace's refusal of the candidates with the vault's own words, never a form", async () => {
    vault.refusals.set(`/mandate-candidates?device=${fx.PEOPLE_DEVICE.device}`, { status: 423, body: { error: "frozen", message: "This workspace is frozen." } })
    const url = new URL(`https://vault.test/w/${fx.GALLERY_WORKSPACE.slug}?device=${fx.PEOPLE_DEVICE.device}`)
    const rc = { request: new Request(url), env: ON, ctx: {}, url, params: {} } as unknown as RequestContext
    const response = await pages.sign.render(rc, { workspace: { workspace: fx.GALLERY_WORKSPACE, membership: TOM.member, account: {} } as never, shell: fx.galleryShell(TOM) })
    expect(response.status).toBe(423)
    const page = await response.text()
    expect(page).toContain("This workspace is frozen.")
    expect(page).not.toContain('data-form="mandate-sign"')
  })
})
