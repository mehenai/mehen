import { env } from "cloudflare:workers"
import { createExecutionContext } from "cloudflare:test"
import { expect, it, vi } from "vitest"
import worker from "../../src/index.ts"
import { WORKSPACE_ROUTES, registerWorkspaceRoutes } from "../../src/routes/workspace-prefix.ts"
import { workspaceDirectoryEntryRoutes } from "../../src/routes/directory.ts"
import { ROUTES } from "../../src/routes/index.ts"
import { WORKSPACE_PAGES } from "../../src/routes/ui.ts"
import { ORIGIN } from "../helpers.ts"
import { body, workJourney } from "./workspace-journey.ts"

type RoutePattern = { method: string; path: string }
function patternsOverlap(a: RoutePattern, b: RoutePattern): boolean {
  const methods = (method: string) => method === "GET" ? ["GET", "HEAD"] : [method]
  if (!methods(a.method).some(method => methods(b.method).includes(method))) return false
  const left = a.path.split("/"), right = b.path.split("/")
  return left.length === right.length && left.every((segment, n) => segment === right[n] || segment.startsWith(":") && right[n] !== "" || right[n]?.startsWith(":") && segment !== "")
}

it("route overlap guard detects parameter shadowing and implicit HEAD", () => {
  expect(patternsOverlap({ method: "GET", path: "/items/:slug" }, { method: "GET", path: "/items/action" })).toBe(true)
  expect(patternsOverlap({ method: "GET", path: "/items/:slug" }, { method: "HEAD", path: "/items/:id" })).toBe(true)
  expect(patternsOverlap({ method: "GET", path: "/items/:slug" }, { method: "POST", path: "/items/action" })).toBe(false)
  expect(patternsOverlap({ method: "GET", path: "/items/:slug" }, { method: "GET", path: "/items/" })).toBe(false)
})

it("registration: every workspace, directory and page route has one method/path owner", () => {
  const routes = [
    { method: "GET", path: "/api/w/:ws" },
    ...registerWorkspaceRoutes(WORKSPACE_ROUTES),
    ...workspaceDirectoryEntryRoutes,
    ...WORKSPACE_PAGES.map(page => ({ method: "GET", path: `/w/:ws${page.path}` })),
    { method: "GET", path: "/account" },
    { method: "GET", path: "/workspaces" },
  ]
  const overlaps = routes.flatMap((route, index) => routes.slice(index + 1).filter(other => patternsOverlap(route, other)).map(other => `${route.method} ${route.path} <> ${other.method} ${other.path}`))
  expect(overlaps).toEqual([])
  const replacements = workspaceDirectoryEntryRoutes.flatMap(route => ROUTES.filter(legacy => patternsOverlap(route, legacy)).map(() => `${route.method} ${route.path}`)).sort()
  expect(replacements).toEqual([])
  expect(WORKSPACE_ROUTES.filter(route => route.method === "POST" && route.path === "/freeze")).toHaveLength(1)
  for (const path of ["/members", "/invites", "/devices", "/items", "/projects", "/pending", "/policy/context"]) expect(WORKSPACE_ROUTES.some(route => route.path === path)).toBe(true)
})

it("header: real routes refuse a stale workspace id with unknown-workspace bytes before mutation", async () => {
  const f = await workJourney()
  const before = await f.snapshot(f.work)
  const unknown = await f.request("/api/w/no-such-workspace", f.alex)
  expect(unknown.status).toBe(404)
  const expected = await unknown.text()
  for (const [path, input] of [["/api/w/northwind", undefined], ["/api/w/northwind/freeze", {}]] as const) {
    const refused = await f.request(path, f.alex, input, { "Mehen-Workspace": f.personal.id })
    expect(refused.status).toBe(404)
    expect(await refused.text()).toBe(expected)
  }
  expect(await f.snapshot(f.work)).toEqual(before)
  expect(await body(await f.request("/api/w/northwind", f.alex, undefined, { "Mehen-Workspace": f.work.id }))).toEqual(f.work)
})

it("recover passkey page: flag on, account and ceremony cookies render without legacy reads", async () => {
  const f = await workJourney()
  const errors = vi.spyOn(console, "error")
  try {
    const account = await f.request("/recover/passkey", f.alex, undefined, { accept: "text/html" })
    expect(account.status).toBe(200)
    expect(await account.text()).not.toContain('data-action="recover-passkey"')
    const started = await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[0] })
    expect(started.status).toBe(200)
    const ceremony = { ...f.alex, cookie: started.headers.get("set-cookie")!.split(";")[0]! }
    const live = await f.request("/recover/passkey", ceremony, undefined, { accept: "text/html" })
    expect(live.status).toBe(200)
    expect(await live.text()).toContain('data-action="recover-passkey"')
    expect(errors).not.toHaveBeenCalled()
  } finally { errors.mockRestore() }
})
