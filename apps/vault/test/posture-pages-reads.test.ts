// What the credential page and the home read for how careful a credential
// is (routes/ui-projects.ts, routes/ui.ts homePage),
// counted at the one door every workspaceApiGet goes through
// (routes/workspace-prefix.ts workspacePrefix), which this stub answers, as
// policy-rules-reads.test.ts does: the credential's page ticks the machines
// its description names as eligible and reads no other list, and the home reads
// items.nudges for anyone but a guest and draws at most three lines, each
// with Change how careful it is and Not now.
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest"
import type { RequestContext } from "../src/routes/context.ts"
import type { WorkspacePage } from "../src/routes/ui.ts"

const vault = vi.hoisted(() => ({ reads: [] as string[], answers: new Map<string, unknown>() }))
vi.mock("../src/routes/workspace-prefix.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/routes/workspace-prefix.ts")>()),
  workspacePrefix: async (rc: RequestContext) => {
    const path = rc.url.pathname.replace(/^\/api\/w\/[^/]+/, "") + rc.url.search
    vault.reads.push(path)
    return vault.answers.has(path) ? Response.json(vault.answers.get(path)) : Response.json({ error: "not_found", message: "No such route." }, { status: 404 })
  },
}))

type Fixtures = typeof import("../src/ui/people-gallery.ts") & typeof import("../src/ui/posture-gallery.ts") & typeof import("../src/ui/workspace-projects-gallery.ts")
let fx: Fixtures
let pages: { credential: WorkspacePage; home: WorkspacePage }
beforeAll(async () => {
  vi.resetModules()
  await import("../src/index.ts")
  const [projects, ui, ...galleries] = await Promise.all([import("../src/routes/ui-projects.ts"), import("../src/routes/ui.ts"), import("../src/ui/people-gallery.ts"), import("../src/ui/posture-gallery.ts"), import("../src/ui/workspace-projects-gallery.ts")])
  fx = Object.assign({}, ...galleries) as Fixtures
  const credential = projects.WORKSPACE_PROJECT_PAGES.find((p) => p.path === "/items/:slug")
  const home = ui.WORKSPACE_PAGES.find((p) => p.key === "home")
  if (!credential || !home) throw new Error("no page")
  pages = { credential, home }
})

const NUDGES = [
  { slug: "cloudflare-api-token-local-secrets-2", asked: 21, routine: 15 },
  { slug: "github-work", asked: 12, routine: 1 },
  { slug: "stripe-test", asked: 10, routine: 5 },
  { slug: "a-fourth", asked: 10, routine: 5 },
]

beforeEach(() => {
  vault.reads = []
  vault.answers = new Map<string, unknown>([
    ["/items/openai-prod", fx.description(fx.GALLERY_ITEMS[0]!)],
    ["/items/cloudflare-prod", { ...fx.description(fx.GALLERY_ITEMS[0]!), slug: "cloudflare-prod", provider: "cloudflare-api-token", binding: { hosts: ["api.cloudflare.com"] }, posture: fx.POSTURE_ASK }],
    ["/projects", { projects: [] }],
    ["/devices", { devices: [fx.PEOPLE_DEVICE, { ...fx.PEOPLE_DEVICE, device: "dev_gone00001", name: "old-laptop", revoked: true }] }],
    ["", fx.GALLERY_WORKSPACE],
    ["/inbox", { workspace: { workspace: fx.GALLERY_WORKSPACE, state: "ok", truncated: false }, items: [] }],
    ["/items", { items: [] }],
    ["/nudges", { nudges: NUDGES }],
  ])
})

async function open(page: WorkspacePage, params: Record<string, string>, viewer = fx.VIEWERS.owner): Promise<string> {
  const url = new URL(`https://vault.test/w/${fx.GALLERY_WORKSPACE.slug}`)
  const rc = { request: new Request(url), env: { POLICY_RULES: "off", POLICY_POSTURES: "on", VAULT_ORIGIN: "https://vault.test" }, ctx: {}, url, params } as unknown as RequestContext
  const workspace = { workspace: fx.GALLERY_WORKSPACE, membership: viewer.member, account: {} } as never
  const response = await page.render(rc, { workspace, shell: fx.galleryShell(viewer) })
  expect(response.status).toBe(200)
  return response.text()
}

describe("the credential page's How careful card", () => {
  it("ticks only the machines the description names as eligible, and reads no machine list for them", async () => {
    const plain = await open(pages.credential, { slug: "openai-prod" })
    expect(plain).not.toContain('data-region="posture"')
    vault.reads = []
    const careful = await open(pages.credential, { slug: "cloudflare-prod" })
    expect(careful).toContain('<section class="card" id="how-careful"')
    expect(vault.reads).not.toContain("/devices")
    expect([...careful.matchAll(/data-input="posture-machine" value="(\w+)"/g)].map((m) => m[1])).toEqual(fx.POSTURE_ELIGIBLE.map((m) => m.device))
    expect(careful).not.toContain("dev_gone00001")
  })
})

describe("the home's nudge", () => {
  it("draws at most three lines, each linking to the credential's How careful card, with Not now", async () => {
    const page = await open(pages.home, {})
    expect(vault.reads).toContain("/nudges")
    const card = page.slice(page.indexOf('data-region="home-nudges"'), page.indexOf("</section>", page.indexOf('data-region="home-nudges"')))
    expect(card.match(/data-region="nudge"/g)).toHaveLength(3)
    expect(card).not.toContain("a-fourth")
    expect(card).toContain("<p><code>cloudflare-api-token-local-secrets-2</code> asked 21 times this week, none denied; 15 were routine building.</p>")
    expect(card).toContain("<p><code>github-work</code> asked 12 times this week, none denied; 1 was routine building.</p>")
    expect(card).toContain(`<a class="btn secondary sm" href="/w/${fx.GALLERY_WORKSPACE.slug}/items/cloudflare-api-token-local-secrets-2#how-careful">Change how careful it is</a><button type="button" class="btn quiet sm" data-action="nudge-quiet" data-slug="cloudflare-api-token-local-secrets-2">Not now</button>`)
    // Between Needs you and the counts.
    expect(page.indexOf('data-region="home-needs"')).toBeLessThan(page.indexOf('data-region="home-nudges"'))
    expect(page.indexOf('data-region="home-nudges"')).toBeLessThan(page.indexOf('data-region="home-summary"'))
  })

  it("never reads it for a guest, and draws nothing when there is none", async () => {
    const guest = await open(pages.home, {}, fx.VIEWERS.guest)
    expect(vault.reads).not.toContain("/nudges")
    expect(guest).not.toContain('data-region="home-nudges"')
    vault.answers.set("/nudges", { nudges: [] })
    expect(await open(pages.home, {})).not.toContain('data-region="home-nudges"')
  })
})
