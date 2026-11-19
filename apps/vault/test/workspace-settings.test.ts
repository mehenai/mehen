// The workspace settings read and page through worker.fetch: GET /api/w/:ws/settings answers whether the
// workspace is frozen and what the caller may change, each right from the
// evaluator (rename and unfreeze for an owner, freeze for anyone but a
// guest); the page draws controls by those rights, never by role; the
// writes keep their guards; the home's frozen notice and the palette's
// Freeze entry read the same route.
import { describe, expect, it } from "vitest"
import type { WorkspaceSettingsView } from "@mehen/protocol/workspace"
import { buildEntries } from "../src/ui/client/palette-logic.ts"
import { body, refusal, workJourney, type Person } from "./e2e/workspace-journey.ts"
import { settingsArea } from "../src/vault/areas/settings-workspace.ts"
import { setSetting, updateRestriction } from "../src/vault/areas/workspace-runtime.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { accountAuth, inAccess, projectFixture, projectState } from "./projects-workspace-fixture.ts"
import { accessMember } from "./workspace-fixtures.ts"

type Journey = Awaited<ReturnType<typeof workJourney>>
const HTML = { accept: "text/html" }

async function settings(f: Journey, person: Person, slug = "northwind"): Promise<WorkspaceSettingsView> {
  const response = await f.request(`/api/w/${slug}/settings`, person)
  expect(response.headers.get("cache-control")).toBe("no-store")
  return body<WorkspaceSettingsView>(response)
}

async function page(f: Journey, person: Person, path = "/settings"): Promise<string> {
  const response = await f.request(`/w/northwind${path}`, person, undefined, HTML)
  expect(response.status).toBe(200)
  return response.text()
}

// Mia a member, Ben an admin, Tom a guest, all in Northwind.
async function people(f: Journey) {
  const mia = await f.guest(f.alex, f.work, f.project.id, "Mia")
  await body(await f.memberChange(f.alex, f.work, mia.member!, "role", "member"))
  const ben = await f.guest(f.alex, f.work, f.project.id, "Ben")
  await body(await f.memberChange(f.alex, f.work, ben.member!, "role", "admin"))
  const tom = await f.guest(f.alex, f.work, f.project.id, "Tom")
  return { mia, ben, tom }
}

describe("GET /api/w/:ws/settings", () => {
  it("gives each caller its own rights from the evaluator: rename and unfreeze for an owner, freeze for anyone but a guest", async () => {
    const f = await workJourney()
    const { mia, ben, tom } = await people(f)
    expect(await settings(f, f.alex)).toEqual({ frozen: false, rights: { rename: true, freeze: true, unfreeze: true }, approvals: { level: "writes", askLess: true, askMore: false } })
    // An admin is not an owner: the brake and the approval dial, nothing else.
    expect(await settings(f, ben)).toEqual({ frozen: false, rights: { rename: false, freeze: true, unfreeze: false }, approvals: { level: "writes", askLess: true, askMore: false } })
    expect(await settings(f, mia)).toEqual({ frozen: false, rights: { rename: false, freeze: true, unfreeze: false }, approvals: { level: "writes", askLess: false, askMore: false } })
    expect(await settings(f, tom)).toEqual({ frozen: false, rights: { rename: false, freeze: false, unfreeze: false }, approvals: { level: "writes", askLess: false, askMore: false } })
  })

  it("is refused signed out, and answers another account's workspace as no such workspace", async () => {
    const f = await workJourney()
    const { mia } = await people(f)
    expect((await f.request("/api/w/northwind/settings")).status).toBe(401)
    const other = await f.request("/api/w/alex/settings", mia)
    expect(other.status).toBe(404)
    expect(await other.json()).toEqual({ error: "not_found", message: "No such workspace." })
  })

  it("follows a freeze by a member, and the write guards stay: a member cannot unfreeze or rename", async () => {
    const f = await workJourney()
    const { mia, tom } = await people(f)
    // A guest's freeze is refused as before.
    expect((await f.request("/api/w/northwind/freeze", tom, {})).status).toBe(403)
    expect((await settings(f, f.alex)).frozen).toBe(false)
    expect(await body(await f.request("/api/w/northwind/freeze", mia, {}))).toEqual({})
    expect(await settings(f, mia)).toEqual({ frozen: true, rights: { rename: false, freeze: true, unfreeze: false }, approvals: { level: "writes", askLess: false, askMore: false } })
    expect((await f.request("/api/w/northwind/unfreeze", mia, {})).status).toBe(403)
    expect((await f.request("/api/w/northwind/settings", mia, { change: "name", name: "Taken over" })).status).toBe(403)
    expect((await settings(f, f.alex)).frozen).toBe(true)
    expect(await body(await f.signed("/api/w/northwind/unfreeze", f.alex, {}, { type: "workspace.unfreeze" }, "northwind"))).toEqual({})
    expect((await settings(f, mia)).frozen).toBe(false)
  })
})

describe("the settings page", () => {
  it("draws an owner every control by right, with the facts and the workspace id for mehen.toml", async () => {
    const f = await workJourney()
    const owner = await page(f, f.alex)
    expect(owner).toContain("<title>Settings · Northwind (northwind) · Mehen</title>")
    expect(owner).toContain(`Workspace id, for <code>mehen.toml</code></dt><dd><code>${f.work.id}</code>`)
    expect(owner).toContain('data-form="workspace-name"')
    expect(owner).toContain('data-form="workspace-slug"')
    expect(owner).toContain('class="btn danger-quiet" data-action="freeze-start"')
    expect(owner).toContain('data-region="freeze-confirm" hidden')
    expect(owner).not.toContain('data-action="workspace-unfreeze"')
    expect(owner).toContain('data-boot="{&quot;page&quot;:&quot;workspace-settings&quot;')
  })

  it("gives a member and an admin the brake only, a guest one sentence, and never a control the read did not grant", async () => {
    const f = await workJourney()
    const { mia, ben, tom } = await people(f)
    for (const person of [mia, ben]) {
      const shown = await page(f, person)
      expect(shown).not.toContain('data-form="workspace-name"')
      expect(shown).not.toContain('data-form="workspace-slug"')
      expect(shown).toContain('data-action="freeze-start"')
      expect(shown).toContain("Only an owner can change it, or the name.")
    }
    const guest = await page(f, tom)
    expect(guest).toContain("Settings are for the workspace's members.")
    expect(guest).not.toMatch(/data-action="(freeze-start|workspace-freeze|workspace-unfreeze)"|data-form="workspace-/)
  })

  it("shows the frozen state: Unfreeze with passkey for the owner after Activity, ask an owner for anyone else, and Freeze gone", async () => {
    const f = await workJourney()
    const { mia } = await people(f)
    await body(await f.request("/api/w/northwind/freeze", mia, {}))
    const owner = await page(f, f.alex)
    expect(owner).toContain('class="btn widen" data-action="workspace-unfreeze"')
    expect(owner).toContain("Read Activity first")
    expect(owner).not.toContain('data-action="freeze-start"')
    const member = await page(f, mia)
    expect(member).toContain("Ask an owner to unfreeze it.")
    expect(member).not.toContain('data-action="workspace-unfreeze"')
    // The home's frozen notice reads the same route.
    const home = await page(f, mia, "/")
    expect(home).toContain('data-region="frozen"')
    expect(home).toContain("This workspace is frozen: every machine use is refused.")
    expect(home).toContain(`See <a href="/w/northwind/audit">Activity</a> for what tripped it. Ask an owner to unfreeze it.`)
    expect(await page(f, f.alex, "/")).toContain(`href="/w/northwind/settings#unfreeze">Unfreeze</a>`)
  })
})

// The approval dial's route (areas/approval-dial-workspace.ts; its rules in
// approval-dial.test.ts).
describe("POST /api/w/:ws/settings/approvals", () => {
    it("moves the dial with the passkey signed over both levels to ask less, and none to ask more", async () => {
    const f = await workJourney()
    expect((await settings(f, f.alex)).approvals).toEqual({ level: "writes", askLess: true, askMore: false })
    await refusal(await f.request("/api/w/northwind/settings/approvals", f.alex, { before: "writes", after: "work" }), 403, { error: "forbidden", message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." })
    const wrong = await f.signed("/api/w/northwind/settings/approvals", f.alex, { before: "writes", after: "work" }, { type: "workspace.unfreeze" }, "northwind")
    expect(wrong.status).toBe(403)
    expect((await settings(f, f.alex)).approvals?.level).toBe("writes")
    expect(await body(await f.signed("/api/w/northwind/settings/approvals", f.alex, { before: "writes", after: "work" }, { type: "workspace.approvals", before: "writes", after: "work" }, "northwind"))).toEqual({ level: "work" })
    expect((await settings(f, f.alex)).approvals).toEqual({ level: "work", askLess: false, askMore: true })
    expect(await body(await f.request("/api/w/northwind/settings/approvals", f.alex, { before: "work", after: "writes" }))).toEqual({ level: "writes" })
  })

  it("refuses a member, and a body that names no level", async () => {
    const f = await workJourney()
    const mia = await f.guest(f.alex, f.work, f.project.id, "Mia")
    await body(await f.memberChange(f.alex, f.work, mia.member!, "role", "member"))
    expect((await settings(f, mia)).approvals).toEqual({ level: "writes", askLess: false, askMore: false })
    expect((await f.request("/api/w/northwind/settings/approvals", mia, { before: "writes", after: "writes" })).status).toBe(403)
    expect((await f.request("/api/w/northwind/settings/approvals", f.alex, { before: "writes", after: "never" })).status).toBe(400)
  })

  it("draws the dial on the settings page by its rights: the three levels for an owner, the level alone for a member", async () => {
    const f = await workJourney()
    const { mia } = await people(f)
    const owner = await page(f, f.alex)
    expect(owner).toContain('data-region="approvals" data-level="writes"')
    expect(owner.match(/data-input="approvals-level"/g)).toHaveLength(2)
    for (const name of ["Ask on writes", "Let it work"]) expect(owner).toContain(`<b>${name}</b>`)
    expect(owner).toContain("<li>Protected environments still need a person.</li>")
    expect(owner).toContain('value="writes" checked')
    expect(owner).toContain('data-action="approvals-save" disabled')
    const member = await page(f, mia)
    expect(member).toContain("This workspace is set to <b>Ask on writes</b>")
    expect(member).toContain("Only an owner or admin can change it.")
    expect(member).not.toContain('data-input="approvals-level"')
  })
})

describe("the palette's Freeze entry", () => {
  const scope = { kind: "workspace" as const, slug: "northwind", name: "Northwind", pages: ["home", "settings"], reads: [] }
  const sources = (settings: WorkspaceSettingsView | null) => ({ pending: null, items: null, devices: null, projects: null, settings })
  const freeze = (s: WorkspaceSettingsView | null, at = scope) => buildEntries(sources(s), 0, at).filter((e) => e.title.startsWith("Freeze"))

  it("is offered by right to open the confirm step, and never when frozen, unread, not allowed or on the legacy vault", () => {
    expect(freeze({ frozen: false, rights: { rename: false, freeze: true, unfreeze: false } }).map((e) => [e.title, e.href])).toEqual([["Freeze Northwind", "/w/northwind/settings#freeze"]])
    expect(freeze({ frozen: true, rights: { rename: true, freeze: true, unfreeze: true } })).toEqual([])
    expect(freeze({ frozen: false, rights: { rename: false, freeze: false, unfreeze: false } })).toEqual([])
    expect(freeze(null)).toEqual([])
    expect(freeze({ frozen: false, rights: { rename: false, freeze: true, unfreeze: false } }, { ...scope, pages: ["home"] })).toEqual([])
    expect(buildEntries(sources({ frozen: false, rights: { rename: true, freeze: true, unfreeze: true } }), 0).filter((e) => e.title.startsWith("Freeze"))).toEqual([])
  })
})

describe("access.settings in the workspace", () => {
  const op = settingsArea.workspaceOps!["access.settings"]!
  const read = (ctx: VaultContext, role: string) => op.handler(ctx, accessMember(projectState(ctx), role), {}, { auth: accountAuth(role), workspace: { id: ctx.tenant, slug: "work", name: "Work" } })

  it("holds back rename and unfreeze from an owner in a recovery cooling-off and keeps the brake", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      expect(read(ctx, "owner")).toEqual({ frozen: false, rights: { rename: true, freeze: true, unfreeze: true }, approvals: { level: "writes", askLess: true, askMore: false } })
      updateRestriction(ctx, "acc_owner", 0, { reason: "recovery", until: ctx.now() + 86_400_000, notice: "ntc_recovery" })
      expect(read(ctx, "owner")).toEqual({ frozen: false, rights: { rename: false, freeze: true, unfreeze: false }, approvals: { level: "writes", askLess: false, askMore: false } })
    })
  })

  it("is refused as the activity is for a member the identity rule covers without a check", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["member"] })
      expect(() => read(ctx, "member")).toThrow(expect.objectContaining({ code: "identity_required" }))
    })
  })
})
