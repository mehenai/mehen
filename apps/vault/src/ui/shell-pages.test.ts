// The workspace shell through the real Worker: the /w/:ws page prefix, the
// switch that keeps it off, uniform not-found pages, canonical slugs, pages
// served only while their reads are, and what the old unprefixed addresses
// become with workspaces on.

import { env } from "cloudflare:workers"
import { afterEach, beforeEach, describe, expect, it } from "vitest"
import type { AccountSession, MembershipView } from "@mehen/protocol/workspace"
import { AccountSessionSchema } from "@mehen/protocol/workspace"
import { json } from "../http.ts"
import type { Handler } from "../routes/context.ts"
import { workspaceDirectoryEntryRoutes } from "../routes/directory.ts"
import { ACCOUNT_READ, WORKSPACE_PAGES, servedAccountPages, servedWorkspacePages } from "../routes/ui.ts"
import type { InboxResponse, InboxWorkspace } from "@mehen/protocol/inbox"
import { NEEDS_YOU_API } from "./client/pages/needs-you-logic.ts"
import { WORKSPACE_ROUTES, type WorkspaceHandler } from "../routes/workspace-prefix.ts"
import { workspaceApiGet } from "./load.ts"
import type { Route } from "../router.ts"
import { createWorkspaceFixture, type WorkspaceTestFixture } from "../../test/workspace-fixtures.ts"
import { fetchWorkspaceWorker, freshTenant } from "../../test/helpers.ts"

const HTML = { accept: "text/html" }

async function bytes(response: Response) {
  return { status: response.status, location: response.headers.get("location"), body: await response.text() }
}

// Status, every header and the body: what "byte-identical" means here.
// Every header but Server-Timing, whose durations differ from one response to the next.
async function full(response: Response) {
  return { status: response.status, headers: [...response.headers].filter(([name]) => name !== "server-timing").sort(), body: await response.text() }
}

// Records every SQL statement the Worker prepares against this database.
function recording(db: D1Database, seen: string[]): D1Database {
  return new Proxy(db, {
    get(target, prop) {
      if (prop === "prepare") return (sql: string) => { seen.push(sql); return target.prepare(sql) }
      const value = Reflect.get(target, prop) as unknown
      return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value
    },
  })
}

// Fails any statement that names a table of the staged workspace schema.
function noWorkspaceTables(db: D1Database): D1Database {
  return new Proxy(db, {
    get(target, prop) {
      if (prop === "prepare") return (sql: string) => {
        if (/\b(workspaces|memberships|accounts|workspace_slugs)\b/.test(sql)) throw new Error(`workspace table touched: ${sql}`)
        return target.prepare(sql)
      }
      const value = Reflect.get(target, prop) as unknown
      return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value
    },
  })
}

// Every shape of /w/ address no route pattern could match, plus the ones it could.
const ODD_PATHS = ["/w", "/w/", "/w/alex/credentials/", "/w/alex/x/y/z/q", "/w/no-such-workspace/x/y/z/q", "/w/alex//", "/w/%ZZ/", "/w/%ZZ/x/y/z/q", "/w//x"]

function page(f: WorkspaceTestFixture, path: string, cookie: string | null = f.cookie) {
  return fetchWorkspaceWorker(f.env, path, { headers: cookie === null ? HTML : { ...HTML, cookie } })
}

function bootOf(body: string): Record<string, unknown> {
  const raw = /data-boot="([^"]*)"/.exec(body)?.[1]
  if (raw === undefined) throw new Error("no boot payload")
  const text = raw.replaceAll("&quot;", '"').replaceAll("&#39;", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&#96;", "`").replaceAll("&amp;", "&")
  return JSON.parse(text) as Record<string, unknown>
}

function membership(id: string, slug: string, name: string, overrides: Partial<MembershipView> = {}): MembershipView {
  return { workspace: { id, slug, name }, member: `mem_${slug.replaceAll("-", "")}`, role: "owner", pendingRole: null, status: "active", ...overrides }
}

function accountSession(f: WorkspaceTestFixture, memberships: MembershipView[]): AccountSession {
  return AccountSessionSchema.parse({ account: f.account, name: "owner", canCreateWorkspaces: false, workspaceCreation: "default", recoverySetupRequired: false, securityEpoch: 0, pendingTransition: null, restricted: null, memberships })
}

// GET /api/account stands in for DIRECTORY's route: the shell's account
// pages must light up when it is registered and stay off until then.
const injected: { routes: Route<Handler>[]; workspace: Route<WorkspaceHandler>[]; pages: number } = { routes: [], workspace: [], pages: 0 }

function serveAccount(session: AccountSession): void {
  const route: Route<Handler> = { method: "GET", path: ACCOUNT_READ, handler: async () => json(session) }
  workspaceDirectoryEntryRoutes.unshift(route)
  injected.routes.push(route)
}

// GET /api/needs-you stands in for the inbox route the same way.
function serveInbox(inbox: InboxResponse): void {
  const route: Route<Handler> = { method: "GET", path: NEEDS_YOU_API, handler: async () => json(inbox) }
  workspaceDirectoryEntryRoutes.unshift(route)
  injected.routes.push(route)
}

function inboxOf(counts: [string, string, string, number | null][]): InboxResponse {
  const workspaces: InboxWorkspace[] = counts.map(([id, slug, name, count]) => ({ workspace: { id, slug, name }, role: "owner", state: count === null ? "unavailable" : "ok", reason: count === null ? "timeout" : null, count, truncated: false }))
  const total = workspaces.reduce((n, w) => n + (w.count ?? 0), 0)
  return { workspaces, items: [], notices: [], count: total, complete: workspaces.every((w) => w.state === "ok") }
}

const registeredWorkspace = [...WORKSPACE_ROUTES]
const registeredDirectory = [...workspaceDirectoryEntryRoutes]
// Feature lanes register their pages too; these cases inject their own, so
// only the pages that need nothing beyond the workspace's identity (the home
// and Connect an agent) stay registered while they run.
const registeredPages = [...WORKSPACE_PAGES]
const identityOnlyPages = registeredPages.filter((p) => p.key === "home" || p.key === "connect-agent")
beforeEach(() => {
  WORKSPACE_ROUTES.splice(0)
  workspaceDirectoryEntryRoutes.splice(0)
  WORKSPACE_PAGES.splice(0, WORKSPACE_PAGES.length, ...identityOnlyPages)
})
afterEach(() => {
  for (const route of injected.routes) workspaceDirectoryEntryRoutes.splice(workspaceDirectoryEntryRoutes.indexOf(route), 1)
  for (const route of injected.workspace) WORKSPACE_ROUTES.splice(WORKSPACE_ROUTES.indexOf(route), 1)
  WORKSPACE_PAGES.splice(WORKSPACE_PAGES.length - injected.pages, injected.pages)
  injected.routes = []
  injected.workspace = []
  injected.pages = 0
  WORKSPACE_ROUTES.splice(0, WORKSPACE_ROUTES.length, ...registeredWorkspace)
  workspaceDirectoryEntryRoutes.splice(0, workspaceDirectoryEntryRoutes.length, ...registeredDirectory)
  WORKSPACE_PAGES.splice(0, WORKSPACE_PAGES.length, ...registeredPages)
})

describe("the /w/:ws page prefix", () => {

  it("sends a visitor with no account session to sign in, coming back to the same page", async () => {
    const f = await createWorkspaceFixture()
    const response = await page(f, "/w/alex/?tab=1", null)
    expect(response.status).toBe(302)
    expect(response.headers.get("location")).toBe(`/signin?next=${encodeURIComponent("/w/alex/?tab=1")}`)
  })

  it("renders the home in the workspace shell with the authenticated id, slug and origin in the boot", async () => {
    const f = await createWorkspaceFixture()
    const response = await page(f, "/w/alex/")
    expect(response.status).toBe(200)
    const body = await response.text()
    expect(bootOf(body)).toEqual({ page: "workspace-home", shell: { origin: f.env.VAULT_ORIGIN, account: f.account, workspace: { id: f.workspaces.personal, slug: "alex", name: "Personal" }, pages: ["home", "connect-agent"], reads: [] } })
    expect(body).toContain('<span class="identity-name">Personal</span> <span class="identity-proof">(<code>alex</code>) at <span class="identity-origin">https://vault.test</span></span>')
    expect(body).toContain('<details class="switcher">')
    // Rail links only to served pages: home and the account-level docs.
    expect(body).toContain('href="/w/alex/"')
    for (const dead of ["/credentials", "/devices", "/projects", "/audit", "/connect", "/settings", "/workspaces", "/account", "/w/alex/credentials", "#needs-you"]) expect(body).not.toContain(`href="${dead}"`)
    // No Google sign-in before WS-OIDC merges.
    expect(body).not.toMatch(/with Google|\/auth\/oidc/)
  })

  it("redirects a bare address and a permanent alias to the canonical slug, keeping the query", async () => {
    const f = await createWorkspaceFixture()
    await f.env.DB.prepare("INSERT INTO workspace_slugs(slug,workspace,retired_at) VALUES ('old-alex',?,?)").bind(f.workspaces.personal, Date.now()).run()
    for (const [from, to] of [["/w/alex", "/w/alex/"], ["/w/old-alex/", "/w/alex/"], ["/w/old-alex", "/w/alex/"], ["/w/old-alex/?x=1", "/w/alex/?x=1"]]) {
      const response = await page(f, from as string)
      expect(response.status).toBe(302)
      expect(response.headers.get("location")).toBe(to)
    }
  })

  it("answers an unknown workspace, another account's workspace, a joining one and an unknown page with identical bytes", async () => {
    const f = await createWorkspaceFixture()
    await f.env.DB.prepare("DELETE FROM memberships WHERE account=? AND workspace=?").bind(f.account, f.workspaces.work).run()
    const unknown = await bytes(await page(f, "/w/not-a-workspace/"))
    expect(unknown.status).toBe(404)
    for (const path of ["/w/northwind/", "/w/northwind", "/w/northwind/credentials", "/w/alex/credentials", "/w/alex/a/apr_x", "/w/alex/policy/grants/x"]) {
      expect(await bytes(await page(f, path))).toEqual(unknown)
    }
    await f.env.DB.prepare("UPDATE memberships SET state='joining' WHERE id=?").bind(f.personalMember).run()
    expect(await bytes(await page(f, "/w/alex/"))).toEqual(unknown)
    expect(unknown.body).not.toContain("northwind")
    expect(unknown.body).not.toContain("Personal")
  })

  it("serves a workspace page only while every read it needs is served, and the rail follows", async () => {
    const f = await createWorkspaceFixture()
    // Connect an agent needs only the workspace's identity, like the home.
    expect(servedWorkspacePages(f.env, f.workspaces.personal)).toEqual(["home", "connect-agent"])
    WORKSPACE_PAGES.push({ key: "credentials", path: "/credentials", reads: ["/items"], render: async (rc, ctx) => {
      const loaded = await workspaceApiGet<{ items: string[] }>(rc, ctx.workspace, "/items")
      return new Response(loaded.ok ? `credentials ${loaded.value.items.length}` : "failed")
    } })
    injected.pages = 1
    expect(servedWorkspacePages(f.env, f.workspaces.personal)).toEqual(["home", "connect-agent"])
    expect(await (await page(f, "/w/alex/")).text()).not.toContain('href="/w/alex/credentials"')
    // Unserved, the page is the uniform not-found page.
    expect(await bytes(await page(f, "/w/alex/credentials"))).toEqual(await bytes(await page(f, "/w/not-a-workspace/")))
    const named: (string | null)[] = []
    const items: Route<WorkspaceHandler> = { method: "GET", path: "/items", handler: async (rc) => { named.push(rc.request.headers.get("Mehen-Workspace")); return json({ items: ["a"] }) } }
    WORKSPACE_ROUTES.push(items)
    injected.workspace.push(items)
    expect(servedWorkspacePages(f.env, f.workspaces.personal)).toEqual(["home", "connect-agent", "credentials"])
    const home = await (await page(f, "/w/alex/")).text()
    expect(home).toContain('href="/w/alex/credentials"')
    // The palette is told it may read /items, and nothing it may not.
    expect(bootOf(home)).toMatchObject({ shell: { pages: ["home", "connect-agent", "credentials"], reads: ["/items"] } })
    // Served, it renders, and its server-side read names the workspace id.
    expect(await (await page(f, "/w/alex/credentials")).text()).toBe("credentials 1")
    expect(named).toEqual([f.workspaces.personal])
  })
})

describe("the /w/ namespace at every depth", () => {

  it("with workspaces on, gives every odd address the one not-found page, reads no legacy table and runs no page handler", async () => {
    const f = await createWorkspaceFixture()
    await f.env.DB.prepare("DELETE FROM memberships WHERE account=? AND workspace=?").bind(f.account, f.workspaces.work).run()
    let rendered = 0
    WORKSPACE_PAGES.push({ key: "credentials", path: "/credentials", reads: [""], render: async () => { rendered++; return new Response("credentials page") } })
    injected.pages = 1
    const seen: string[] = []
    const watched = { ...f.env, DB: recording(f.env.DB, seen) }
    const get = (path: string, cookie: string | null = f.cookie) => fetchWorkspaceWorker(watched, path, { headers: cookie === null ? HTML : { ...HTML, cookie } })
    const unknown = await full(await get("/w/not-a-workspace/"))
    expect(unknown.status).toBe(404)
    for (const path of [...ODD_PATHS, "/w/northwind/x/y/z/q", "/w/northwind/credentials/"]) expect(await full(await get(path)), path).toEqual(unknown)
    await f.env.DB.prepare("UPDATE memberships SET state='joining' WHERE id=?").bind(f.personalMember).run()
    expect(await full(await get("/w/alex/credentials"))).toEqual(unknown)
    await f.env.DB.prepare("UPDATE memberships SET state='member' WHERE id=?").bind(f.personalMember).run()
    expect(rendered).toBe(0)
    // The page itself still dispatches at its own address.
    expect(await (await get("/w/alex/credentials")).text()).toBe("credentials page")
    expect(rendered).toBe(1)
    expect(seen.length).toBeGreaterThan(0)
    for (const sql of seen.filter(query => !query.includes("sqlite_master"))) expect(sql).not.toMatch(/\bFROM members\b|\bJOIN members\b|\btenants\b/)
    // Signed out, every one of them asks for a sign-in first.
    for (const path of ODD_PATHS) {
      const response = await get(path, null)
      expect(response.status, path).toBe(302)
      expect(response.headers.get("location"), path).toBe(`/signin?next=${encodeURIComponent(path)}`)
    }
  })

  it("with workspaces on, refuses other methods with the existing 405", async () => {
    const f = await createWorkspaceFixture()
    for (const path of ["/w/alex/", "/w/alex/x/y/z/q", "/workspaces", "/account"]) {
      const response = await fetchWorkspaceWorker(f.env, path, { method: "POST", headers: { cookie: f.cookie, "content-type": "application/json" }, body: "{}" })
      expect(response.status, path).toBe(405)
      expect(await response.json()).toEqual({ error: "bad_request", message: "Method not allowed." })
    }
  })
})

describe("account pages", () => {
  it("stay off until GET /api/account is served, then list every workspace by name, slug and role", async () => {
    const f = await createWorkspaceFixture()
    expect(servedAccountPages()).toEqual([])
    const unknown = await bytes(await page(f, "/w/not-a-workspace/"))
    expect(await bytes(await page(f, "/workspaces"))).toEqual(unknown)
    expect(await bytes(await page(f, "/account"))).toEqual(unknown)
    // Two workspaces with one name: the slug tells them apart everywhere.
    serveAccount(accountSession(f, [membership(f.workspaces.personal, "alex", "Northwind"), membership(f.workspaces.work, "northwind", "Northwind", { role: "admin" })]))
    expect(servedAccountPages()).toEqual(["workspaces", "account"])
    const picker = await page(f, "/workspaces")
    expect(picker.status).toBe(200)
    const body = await picker.text()
    expect(body).toContain('<a href="/w/alex/">')
    expect(body).toContain('<a href="/w/northwind/">')
    expect(body).toContain('Northwind <code class="slug">alex</code>')
    expect(body).toContain('Northwind <code class="slug">northwind</code>')
    // The count comes only from the account inbox, which this test does not serve.
    expect(body).not.toContain("things need you")
    expect(body).toContain('class="sub">Admin</span>')
    expect(body).toContain("https://vault.test")
    const account = await (await page(f, "/account")).text()
    expect(account).toContain(`<code>${f.account}</code>`)
    expect(account).not.toContain('class="switcher"')
    // The switcher now lists the other workspace and the account pages.
    const home = await (await page(f, "/w/alex/")).text()
    expect(home).toContain('href="/w/northwind/"')
    expect(home).toContain('href="/workspaces"')
    expect(home).toContain('href="/account"')
  })

  it("count each workspace in the picker from the account inbox, leaving out one that did not answer", async () => {
    const f = await createWorkspaceFixture()
    serveAccount(accountSession(f, [membership(f.workspaces.personal, "alex", "Personal"), membership(f.workspaces.work, "northwind", "Northwind", { role: "admin" })]))
    serveInbox(inboxOf([[f.workspaces.work, "northwind", "Northwind", 2], [f.workspaces.personal, "alex", "Personal", null]]))
    const body = await (await page(f, "/workspaces")).text()
    expect(body).toContain("Admin · 2 things need you")
    expect(body).toContain('Personal <code class="slug">alex</code></span><span class="sub">Owner</span>')
    expect(body).toMatch(/href="\/needs-you"[^>]*>Needs you<b class="count" data-region="pending-count" data-fill hidden><\/b>/)
  })

  it("serve /needs-you only while the inbox route is, and land there when something waits", async () => {
    const f = await createWorkspaceFixture()
    serveAccount(accountSession(f, [membership(f.workspaces.personal, "alex", "Personal"), membership(f.workspaces.work, "northwind", "Northwind")]))
    const unknown = await bytes(await page(f, "/w/not-a-workspace/"))
    expect(await bytes(await page(f, "/needs-you"))).toEqual(unknown)
    expect((await page(f, "/")).headers.get("location")).toBe("/workspaces")
    serveInbox(inboxOf([[f.workspaces.work, "northwind", "Northwind", 0], [f.workspaces.personal, "alex", "Personal", 0]]))
    expect(servedAccountPages()).toEqual(["workspaces", "needs-you", "account"])
    // Nothing waits: today's landing.
    expect((await page(f, "/")).headers.get("location")).toBe("/workspaces")
    const needs = await page(f, "/needs-you")
    expect(needs.status).toBe(200)
    const body = await needs.text()
    expect(bootOf(body)).toMatchObject({ page: "needs-you", account: f.account, etag: expect.stringMatching(/^W\/"/) })
    expect(body).toContain("<title>Needs you · Mehen</title>")
    expect(body).toContain('href="/needs-you" aria-current="page">Needs you')
    expect(body).toContain("Nothing needs you")
    // Signed out, it asks for a sign-in that comes back to it.
    expect((await page(f, "/needs-you", null)).headers.get("location")).toBe(`/signin?next=${encodeURIComponent("/needs-you")}`)
  })

  it("land on /needs-you when the inbox counts anything", async () => {
    const f = await createWorkspaceFixture()
    serveAccount(accountSession(f, [membership(f.workspaces.personal, "alex", "Personal")]))
    serveInbox(inboxOf([[f.workspaces.personal, "alex", "Personal", 1]]))
    expect((await page(f, "/")).headers.get("location")).toBe("/needs-you")
    // A place still goes to the landing, which now goes to Needs you.
    expect((await page(f, "/credentials")).headers.get("location")).toBe("/needs-you")
  })

  it("never lists a workspace the account cannot open as a link", async () => {
    const f = await createWorkspaceFixture()
    serveAccount(accountSession(f, [membership(f.workspaces.personal, "alex", "Personal"), membership("tn_Gamma123456", "client", "Client", { role: "guest", status: "unconfirmed" })]))
    const body = await (await page(f, "/workspaces")).text()
    expect(body).not.toContain('href="/w/client/"')
    expect(body).toContain("Waiting for an owner or admin to confirm you")
  })
})

describe("unprefixed addresses with workspaces on", () => {
  it("send places to the picker, or straight into the account's only workspace", async () => {
    const f = await createWorkspaceFixture()
    for (const path of ["/", "/credentials", "/connect", "/items/x", "/devices", "/audit", "/projects", "/projects/prj_x", "/policy/overrides/pov_x", "/policy/grants/pog_x"]) {
      const response = await page(f, path)
      expect(response.status, path).toBe(302)
      expect(response.headers.get("location"), path).toBe("/workspaces")
    }
    serveAccount(accountSession(f, [membership(f.workspaces.personal, "alex", "Personal"), membership(f.workspaces.work, "northwind", "Work", { status: "suspended" })]))
    expect((await page(f, "/credentials")).headers.get("location")).toBe("/w/alex/")
  })

  it("send a signed-out visitor to sign in first", async () => {
    const f = await createWorkspaceFixture()
    const response = await page(f, "/devices", null)
    expect(response.headers.get("location")).toBe(`/signin?next=${encodeURIComponent("/devices")}`)
  })

  it("answer old ask links with the uniform not-found page, never a guessed workspace", async () => {
    const f = await createWorkspaceFixture()
    serveAccount(accountSession(f, [membership(f.workspaces.personal, "alex", "Personal")]))
    const unknown = await bytes(await page(f, "/w/not-a-workspace/"))
    for (const path of ["/a/apr_x", "/i/int_x", "/c/con_x", "/e/ABCD-EFGH", "/p/pop_x"]) expect(await bytes(await page(f, path)), path).toEqual(unknown)
  })

  it("send the docs to the docs site, and link there from the shell", async () => {
    const f = await createWorkspaceFixture()
    for (const path of ["/docs", "/docs/nope"]) {
      const docs = await page(f, path)
      expect(docs.status, path).toBe(301)
      expect(docs.headers.get("location"), path).toBe("https://docs.mehen.dev/")
    }
    serveAccount(accountSession(f, [membership(f.workspaces.personal, "alex", "Personal")]))
    const home = await (await page(f, "/w/alex/")).text()
    expect(home).toContain('href="https://docs.mehen.dev/" rel="noopener"')
    expect(home).not.toContain('href="/docs"')
  })
})

describe("the client bundle", () => {
  // shell-logic.test.ts drives initShell itself; this holds the bundle to
  // starting it before any page wiring can make a call.
  it("starts the tab's shell before any page wiring", () => {
    const main = Object.values(import.meta.glob<string>("./client/main.ts", { query: "?raw", import: "default", eager: true }))[0] ?? ""
    const shellAt = main.indexOf("const shell = initShell(boot)")
    expect(shellAt).toBeGreaterThan(0)
    for (const later of ["initSignout()", "initPalette(shell)", "PAGES[boot.page]"]) expect(main.indexOf(later), later).toBeGreaterThan(shellAt)
  })
})
