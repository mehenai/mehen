// What the credential, machine and My rules pages read for their standing rules
// (routes/ui-projects.ts credentialRules, routes/ui-people.ts, ui/load.ts
// loadPolicyRules), counted at the one door every workspaceApiGet goes
// through (routes/workspace-prefix.ts workspacePrefix), which this stub
// answers: with POLICY_RULES off no rules read; on, the credential's page
// reads its machines (GET /devices) only to name a rule it lists. The
// Worker loaded every module before this file ran, with the real door, so
// they are loaded again, from the Worker's entry, once the stub is in place.
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest"
import type { PolicyRuleView } from "@mehen/protocol/policy-mode"
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

type Fixtures = typeof import("../src/ui/people-gallery.ts") & typeof import("../src/ui/policy-rules-gallery.ts") & typeof import("../src/ui/workspace-projects-gallery.ts")
let fx: Fixtures
let pages: { credential: WorkspacePage; machine: WorkspacePage; mine: WorkspacePage }
beforeAll(async () => {
  vi.resetModules()
  await import("../src/index.ts")
  const [projects, people, ...galleries] = await Promise.all([import("../src/routes/ui-projects.ts"), import("../src/routes/ui-people.ts"), import("../src/ui/people-gallery.ts"), import("../src/ui/policy-rules-gallery.ts"), import("../src/ui/workspace-projects-gallery.ts")])
  fx = Object.assign({}, ...galleries) as Fixtures
  pages = { credential: pageOf(projects.WORKSPACE_PROJECT_PAGES, "/items/:slug"), machine: pageOf(people.PEOPLE_PAGES, "/devices/:id"), mine: pageOf(projects.WORKSPACE_PROJECT_PAGES, "/rules") }
})

beforeEach(() => {
  const device = fx.PEOPLE_DEVICE.device
  vault.reads = []
  vault.answers = new Map<string, unknown>([
    ["/items/openai-prod", fx.description(fx.GALLERY_ITEMS[0]!)],
    ["/projects", { projects: [] }],
    ["/devices", { devices: [fx.PEOPLE_DEVICE] }],
    [`/devices/${device}`, fx.PEOPLE_DEVICE],
    [`/devices/${device}/workloads`, { workloads: [] }],
  ])
})

function pageOf(list: WorkspacePage[], path: string): WorkspacePage {
  const found = list.find((p) => p.path === path)
  if (!found) throw new Error(`no page ${path}`)
  return found
}

const NOW = Date.parse("2026-10-27T18:30:00Z")
const active = (id: string): PolicyRuleView => fx.galleryRule(NOW, { id, item: "openai-prod", asker: { device: fx.PEOPLE_DEVICE.device, workload: null }, method: "POST", host: "api.openai.com", path: "/v1/embeddings" })
const ended = (id: string): PolicyRuleView => ({ ...active(id), status: "ended", endedReason: "expired" })

// Both pages' lists answer the same rules.
function rulesAre(rules: PolicyRuleView[]): void {
  vault.answers.set("/policy/rules?item=openai-prod&include=grants", rules)
  vault.answers.set(`/policy/rules?device=${fx.PEOPLE_DEVICE.device}&include=grants`, rules)
}

async function open(page: WorkspacePage, params: Record<string, string>, switched: "on" | "off"): Promise<string> {
  const url = new URL(`https://vault.test/w/${fx.GALLERY_WORKSPACE.slug}`)
  const rc = { request: new Request(url), env: { POLICY_RULES: switched, VAULT_ORIGIN: "https://vault.test" }, ctx: {}, url, params } as unknown as RequestContext
  const workspace = { workspace: fx.GALLERY_WORKSPACE, membership: fx.VIEWERS.owner.member, account: {} } as never
  const response = await page.render(rc, { workspace, shell: fx.galleryShell(fx.VIEWERS.owner) })
  expect(response.status).toBe(200)
  return response.text()
}

const credential = (switched: "on" | "off") => open(pages.credential, { slug: "openai-prod" }, switched)
const machine = (switched: "on" | "off") => open(pages.machine, { id: fx.PEOPLE_DEVICE.device }, switched)
const ruleReads = () => vault.reads.filter((p) => p.startsWith("/policy/rules"))
const deviceListReads = () => vault.reads.filter((p) => p === "/devices")

describe("the standing rules reads", () => {
  it("with POLICY_RULES off neither page reads any rule, even with rules standing", async () => {
    rulesAre([active("rul_live0001")])
    expect(await credential("off")).not.toContain('data-region="policy-rules"')
    expect(await machine("off")).not.toContain('data-region="policy-rules"')
    expect(ruleReads()).toEqual([])
    expect(deviceListReads()).toEqual([])
  })

  it("on, an empty list costs one rules read and no machines read", async () => {
    rulesAre([])
    expect(await credential("on")).not.toContain('data-region="policy-rules"')
    expect(ruleReads()).toEqual(["/policy/rules?item=openai-prod&include=grants"])
    expect(deviceListReads()).toEqual([])
  })

  it("on, a list of only ended rules shows no card and reads no machines", async () => {
    rulesAre([ended("rul_gone0001"), ended("rul_gone0002")])
    expect(await credential("on")).not.toContain('data-region="policy-rules"')
    expect(await machine("on")).not.toContain('data-region="policy-rules"')
    expect(deviceListReads()).toEqual([])
  })

  it("on, an active rule costs one rules read and one machines read, to name it", async () => {
    rulesAre([active("rul_live0001"), ended("rul_gone0001")])
    expect(await credential("on")).toContain('data-rule="rul_live0001"')
    expect(ruleReads()).toEqual(["/policy/rules?item=openai-prod&include=grants"])
    expect(deviceListReads()).toEqual(["/devices"])
    vault.reads = []
    // The machine's page names it from its own read of the machine.
    expect(await machine("on")).toContain('data-rule="rul_live0001"')
    expect(ruleReads()).toEqual([`/policy/rules?device=${fx.PEOPLE_DEVICE.device}&include=grants`])
    expect(deviceListReads()).toEqual([])
  })
})

describe("the My rules page's reads", () => {
  const mine = () => open(pages.mine, {}, "on")

  it("is served only while POLICY_RULES is on for the workspace", () => {
    const env = (POLICY_RULES: string) => ({ POLICY_RULES }) as never
    expect(pages.mine.on?.(env("off"), fx.GALLERY_WORKSPACE.id)).toBe(false)
    expect(pages.mine.on?.(env("on"), fx.GALLERY_WORKSPACE.id)).toBe(true)
    expect(pages.mine.reads).toEqual(["/policy/rules"])
  })

  it("with no live rule reads the list alone and says there is none", async () => {
    vault.answers.set("/policy/rules?include=grants", [ended("rul_gone0001")])
    const body = await mine()
    expect(body).toContain("No rules")
    expect(body).not.toContain('data-rule="rul_gone0001"')
    expect(vault.reads).toEqual(["/policy/rules?include=grants"])
  })

  it("with a live rule names it by its credential and machine, with Stop and Extend", async () => {
    vault.answers.set("/policy/rules?include=grants", [active("rul_live0001"), ended("rul_gone0001")])
    const body = await mine()
    expect(body).toContain('data-rule="rul_live0001"')
    expect(body).not.toContain('data-rule="rul_gone0001"')
    expect(body).toContain('data-action="rule-stop"')
    expect(body).toContain(`/w/${fx.GALLERY_WORKSPACE.slug}/items/openai-prod`)
    expect(body).toContain(fx.PEOPLE_DEVICE.name)
    expect(vault.reads.sort()).toEqual(["/devices", "/policy/rules?include=grants", "/projects"])
  })

  it("draws hostile machine, approver and co-signer names as text", async () => {
    const hostile = '<img src=x onerror="alert(1)">'
    vault.answers.set("/devices", { devices: [{ ...fx.PEOPLE_DEVICE, name: hostile }] })
    vault.answers.set("/policy/rules?include=grants", [{ ...active("rul_live0001"), approvedBy: hostile, coSignedBy: { name: hostile } }])
    const body = await mine()
    expect(body).not.toContain(hostile)
    expect(body).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;")
  })
})
