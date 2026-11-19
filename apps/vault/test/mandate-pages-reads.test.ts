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
    expect(sign).toContain(`<p class="small" data-region="mandate-cover"><a href="/w/${slug}/sign-mandate?device=${fx.PEOPLE_DEVICE.device}">Let ${fx.PEOPLE_DEVICE.name} carry on with requests like this</a></p>`)
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

  // The live form, and the source's terms the person may choose to use.
  const parts = (page: string) => {
    const at = page.indexOf('<template data-region="mandate-source-form">')
    return { live: at < 0 ? page : page.slice(0, at), source: at < 0 ? "" : page.slice(at, page.indexOf("</template>", at)) }
  }
  const checkedItems = (html: string) => [...html.matchAll(/data-input="mandate-item" value="(\w+)"[^>]*checked/g)].map((m) => m[1])
  const checkedClasses = (html: string) => [...html.matchAll(/data-input="mandate-class" value="(\w+)" checked/g)].map((m) => m[1])
  const broad = () => ({ ...MANDATE(), state: "expired" as const, endedReason: "expired" as const, items: "all" as const, classes: ["change", "delete", "read", "send"], caps: { read: 50_000, change: 10_000, send: 500, delete: 200 }, ttlDays: 90 as const })

  it("names another mandate's terms as text with Use these terms, and opens the form narrow, for this machine or another with no history", async () => {
    vault.answers.set(`/mandates/${MANDATE().id}`, broad())
    vault.answers.set(`/mandate-candidates?device=${fx.PEOPLE_DEVICE.device}`, { items: [CANDIDATES.items[1]!] })
    const page = await open(pages.sign, {}, { viewer: TOM, query: `?device=${fx.PEOPLE_DEVICE.device}&from=${MANDATE().id}` })
    expect(mandateReads()).toEqual([`/mandates/${MANDATE().id}`, `/mandate-candidates?device=${fx.PEOPLE_DEVICE.device}`, "/mandates"])
    const { live, source } = parts(page)
    expect([checkedItems(live), checkedClasses(live)]).toEqual([[], ["read"]])
    expect(live).toContain('data-input="mandate-ttl" value="30" checked')
    expect(live).toContain('data-input="mandate-items" value="listed" checked')
    expect(live).toContain('data-region="mandate-source"')
    expect(live).toContain('data-action="mandate-use-source"')
    // Its terms in words, and the form they would fill only once pressed.
    expect(live).toContain("every credential it can use")
    expect(source).toContain('data-input="mandate-items" value="all" checked')
    expect(checkedClasses(source)).toEqual(["read", "change", "send", "delete"])
    expect(source).toContain('data-input="mandate-ttl" value="90" checked')
    expect(page).not.toContain('data-region="mandate-renews"')
  })

  it("prefills only from an open, bound proposal: a closed legacy one or an expired one opens narrow, with its terms as text behind Use these terms", async () => {
    const base = { id: "mdp_tomlaptop0000000001", device: { id: fx.PEOPLE_DEVICE.device, name: fx.PEOPLE_DEVICE.name }, items: [{ id: "itm_githubtom0000001", slug: "github-tom" }], hiddenItems: 0, classes: ["change", "delete", "read", "send"], caps: { read: 50_000, change: 10_000, send: 500, delete: 200 }, ttlDays: 90, schedule: null, note: "Everything", reason: "Everything", mandate: null, createdAt: "2026-11-01T09:00:00.000Z", expiresAt: "2026-11-08T09:00:00.000Z" }
    const legacy = { ...base, state: "expired", items: [], unbound: ["github-tom"], closedReason: "unbound" }
    const expired = { ...base, state: "expired" }
    const boot = (page: string) => JSON.parse((/data-boot="([^"]*)"/.exec(page)?.[1] ?? "{}").replace(/&quot;/g, '"').replace(/&amp;/g, "&")) as { proposal?: string | null }
    for (const [name, proposal] of [["legacy", legacy], ["expired", expired]] as const) {
      vault.answers.set(`/mandate-proposals/${base.id}`, proposal)
      const page = await open(pages.sign, {}, { viewer: TOM, query: `?proposal=${base.id}` })
      const { live, source } = parts(page)
      expect([checkedItems(live), checkedClasses(live), ttl(live)], name).toEqual([[], ["read"], "30"])
      expect(live, name).toContain('data-action="mandate-use-source"')
      expect(boot(page).proposal, name).toBeNull()
      expect(checkedClasses(source), name).toEqual(["read", "change", "send", "delete"])
      expect(source, name).toContain('data-input="mandate-ttl" value="90" checked')
    }
    // The open, bound one still opens on its terms, signed against it.
    vault.answers.set(`/mandate-proposals/${base.id}`, { ...base, state: "open" })
    const open_ = await open(pages.sign, {}, { viewer: TOM, query: `?proposal=${base.id}` })
    expect(checkedClasses(parts(open_).live)).toEqual(["read", "change", "send", "delete"])
    expect(boot(open_).proposal).toBe(base.id)
    expect(open_).not.toContain('data-action="mandate-use-source"')
  })

  it("names a renewed mandate's terms as text with Use these terms, and opens the form narrow, even for an expired broad one", async () => {
    vault.answers.set(`/mandates/${MANDATE().id}`, broad())
    const page = await open(pages.sign, {}, { viewer: TOM, query: `?renew=${MANDATE().id}` })
    const { live, source } = parts(page)
    expect([checkedItems(live), checkedClasses(live)]).toEqual([[], ["read"]])
    expect(live).toContain('data-input="mandate-ttl" value="30" checked')
    expect(live).not.toContain('data-input="mandate-items" value="all" checked')
    expect(live).toContain('data-action="mandate-use-source"')
    expect(source).toContain('data-input="mandate-items" value="all" checked')
    expect(source).toContain('data-input="mandate-ttl" value="90" checked')
  })

  it("starts a fresh form, and a class not yet ticked, at the caps a machine may propose", async () => {
    const page = await open(pages.sign, {}, { viewer: TOM, query: `?device=${fx.PEOPLE_DEVICE.device}` })
    const caps = Object.fromEntries([...page.matchAll(/data-input="mandate-cap" data-class="(\w+)" value="(\d+)"/g)].map((m) => [m[1], Number(m[2])]))
    expect(caps).toEqual({ read: 500, change: 100, send: 10, delete: 5 })
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
  })

  const ticked = (page: string) => [...page.matchAll(/data-input="mandate-class" value="(\w+)" checked/g)].map((m) => m[1])
  const items = (page: string) => [...page.matchAll(/data-input="mandate-item" value="(\w+)"[^>]*checked/g)].map((m) => m[1])
  const ttl = (page: string) => /data-input="mandate-ttl" value="(\d+)" checked/.exec(page)?.[1]

  it("opens with no proposal on the narrowest terms, whatever the address asks: no credential, read only, 30 days; every credential is the person's own choice", async () => {
    for (const query of [`?device=${fx.PEOPLE_DEVICE.device}`, `?device=${fx.PEOPLE_DEVICE.device}&items=all&classes=change,send,delete`]) {
      const page = await open(pages.sign, {}, { viewer: TOM, query })
      expect([items(page), ticked(page), ttl(page)], query).toEqual([[], ["read"], "30"])
      expect(page, query).toContain('data-input="mandate-items" value="listed" checked')
      expect(page, query).toContain('<input type="radio" name="mandate-items" data-input="mandate-items" value="all">')
    }
  })

  it("opens a proposal on its own terms only: the address never widens them", async () => {
    const proposal = { id: "mdp_tomlaptop0000000001", device: { id: fx.PEOPLE_DEVICE.device, name: fx.PEOPLE_DEVICE.name }, items: [{ id: "itm_githubtom0000001", slug: "github-tom" }], hiddenItems: 0, classes: ["change", "read"], caps: { read: 500, change: 100, send: 0, delete: 0 }, ttlDays: 7, schedule: null, note: "Triage", reason: "Triage", state: "open", mandate: null, createdAt: "2026-11-19T09:00:00.000Z", expiresAt: "2026-11-26T09:00:00.000Z" }
    vault.answers.set(`/mandate-proposals/${proposal.id}`, proposal)
    for (const query of [`?proposal=${proposal.id}`, `?proposal=${proposal.id}&items=all&classes=send,delete`]) {
      const page = await open(pages.sign, {}, { viewer: TOM, query })
      expect([items(page), ticked(page), ttl(page)], query).toEqual([["itm_githubtom0000001"], ["read", "change"], "7"])
      expect(page, query).not.toContain('data-input="mandate-items" value="all" checked')
    }
  })

  it("renews a mandate: its terms, with the credentials it names that the person may name now, wait behind Use these terms", async () => {
    const page = await open(pages.sign, {}, { viewer: TOM, query: `?renew=${MANDATE().id}` })
    expect(mandateReads()).toEqual([`/mandates/${MANDATE().id}`, `/mandate-candidates?device=${fx.PEOPLE_DEVICE.device}`, "/mandates"])
    const { live, source } = parts(page)
    expect(checkedItems(live)).toEqual([])
    expect(checkedItems(source)).toEqual(["itm_githubtom0000001", "itm_slackplat000001"])
    expect(source).toContain('value="Triage issues and post the daily build summary"')
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
