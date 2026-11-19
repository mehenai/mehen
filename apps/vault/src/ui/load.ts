// Pages read their data through the same /api routes the browser uses, by
// dispatching inside the Worker with the visitor's own cookie. The pages are
// therefore built against the /api contract only, and see exactly what the
// signed-in member may see.

import type { Activity, ApiError, DeviceView, PendingList, Project } from "@mehen/protocol/api"
import type { ListedRules } from "./policy-rules-list.ts"
import { VaultError, isWireError, toWireError } from "../http.ts"
import { findRoute } from "../router.ts"
import type { RequestContext, WorkspaceRequest } from "../routes/context.ts"
import { WORKSPACE_HEADER, WORKSPACE_ROUTES, workspacePrefix } from "../routes/workspace-prefix.ts"
import { policyRulesOn } from "../vault/areas/policy-rules-workspace.ts"

import { workspaceDirectoryEntryRoutes, workspaceDirectoryPrefix } from "../routes/directory.ts"

export type Loaded<T> = { ok: true; value: T } | { ok: false; status: number; error: ApiError }

function failure(status: number, error: ApiError): { ok: false; status: number; error: ApiError } {
  return { ok: false, status, error }
}

function isApiError(value: unknown): value is ApiError {
  return typeof value === "object" && value !== null && typeof (value as ApiError).error === "string" && typeof (value as ApiError).message === "string"
}

function innerRequest(rc: RequestContext, path: string, extra: Record<string, string> = {}): { url: URL; request: Request } {
  const url = new URL(path, rc.env.VAULT_ORIGIN)
  const headers = new Headers({ accept: "application/json", origin: rc.env.VAULT_ORIGIN, "sec-fetch-site": "same-origin", ...extra })
  const cookie = rc.request.headers.get("cookie")
  if (cookie) headers.set("cookie", cookie)
  return { url, request: new Request(url.href, { method: "GET", headers }) }
}

export async function apiGet<T>(rc: RequestContext, path: string): Promise<Loaded<T>> {
  const { url, request } = innerRequest(rc, path)
  return settle<T>(async () => (await workspaceDirectoryPrefix({ request, env: rc.env, ctx: rc.ctx, url, params: {} })) ?? json404())
}

// A read under the workspace prefix, /api/w/<slug><path>, dispatched the
// same way: the prefix resolves the workspace again from the cookie, so
// the page sees only what this account may see there.
export async function workspaceApiGet<T>(rc: RequestContext, workspace: WorkspaceRequest, path: string): Promise<Loaded<T>> {
  const { url, request } = innerRequest(rc, `/api/w/${encodeURIComponent(workspace.workspace.slug)}${path}`, { [WORKSPACE_HEADER]: workspace.workspace.id })
  return settle<T>(async () => (await workspacePrefix({ request, env: rc.env, ctx: rc.ctx, url, params: {} })) ?? json404())
}

function json404(): Response {
  return new Response(JSON.stringify({ error: "not_found", message: "No such route." }), { status: 404, headers: { "content-type": "application/json" } })
}

function served(found: ReturnType<typeof findRoute>): boolean {
  return found !== null && found !== "method"
}

// Whether this build serves an account-level read (GET /api/account and
// the like). A page that needs a read that is not served is not served
// either, so no live page is ever built on a route that has not merged.
export function accountReadServed(path: string): boolean {
  return served(findRoute(workspaceDirectoryEntryRoutes, "GET", path))
}

// The same for a read under the workspace prefix; "" is its root, the
// workspace's own identity, which the prefix always serves.
export function workspaceReadServed(path: string): boolean {
  return path === "" || served(findRoute(WORKSPACE_ROUTES, "GET", path))
}

async function settle<T>(call: () => Promise<Response>): Promise<Loaded<T>> {
  let response: Response
  try {
    response = await call()
  } catch (error) {
    if (error instanceof VaultError) return failure(error.status, error.toJSON())
    if (isWireError(error)) return failure(error.status, error.vaultError)
    console.error(JSON.stringify({ at: "ui.load", error: error instanceof Error ? error.name : "unknown" }))
    const wire = toWireError(error)
    return failure(wire.status, wire.vaultError)
  }
  let body: unknown
  try {
    body = await response.json()
  } catch {
    return failure(502, { error: "internal", message: "The vault sent a reply this page could not read. Reload to try again." })
  }
  if (response.ok) return { ok: true, value: body as T }
  return failure(response.status, isApiError(body) ? body : { error: "internal", message: "Something went wrong inside the vault." })
}

// A read a page can do without: null when the route refuses or fails, so
// the page leaves that section out instead of failing as a whole. A
// refused session still surfaces, through the page's own required reads.
async function optional<T>(rc: RequestContext, path: string): Promise<T | null> {
  const loaded = await apiGet<T>(rc, path)
  return loaded.ok ? loaded.value : null
}

export const ACTIVITY_DAYS = 7

// What waits for a human (V-7's GET /api/pending).
export function loadPending(rc: RequestContext): Promise<PendingList | null> {
  return optional<PendingList>(rc, "/api/pending")
}

// Seven days of calls by outcome (V-7's GET /api/activity).
export function loadActivity(rc: RequestContext): Promise<Activity | null> {
  return optional<Activity>(rc, `/api/activity?days=${ACTIVITY_DAYS}`)
}

// The machines, for naming actors and for the side column.
export function loadDevices(rc: RequestContext): Promise<DeviceView[] | null> {
  return optional<{ devices: DeviceView[] }>(rc, "/api/devices").then((v) => v?.devices ?? null)
}

// The projects, for the side column.
export function loadProjects(rc: RequestContext): Promise<Project[] | null> {
  return optional<{ projects: Project[] }>(rc, "/api/projects").then((v) => v?.projects ?? null)
}

// A credential's or a machine's standing rules (GET /policy/rules?item= or
// ?device=), for its page's card. Read only with POLICY_RULES on for this
// workspace (policyRulesOn), so with it off the page makes no read and
// renders as before rules; null when off, refused or failed, and the page
// shows no card.
export async function loadPolicyRules(rc: RequestContext, workspace: WorkspaceRequest, of: { item: string } | { device: string }): Promise<ListedRules | null> {
  if (!policyRulesOn(rc.env, workspace.workspace.id)) return null
  const query = "item" in of ? `item=${encodeURIComponent(of.item)}` : `device=${encodeURIComponent(of.device)}`
  // Task grants as well, which a person on the web may always read.
  const loaded = await workspaceApiGet<ListedRules>(rc, workspace, `/policy/rules?${query}&include=grants`)
  return loaded.ok ? loaded.value : null
}
