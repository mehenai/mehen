import { exhaustedNameBudget, NAME_UNAVAILABLE, type NameMissBudget, RESERVED_WORKSPACE_SLUGS, WorkspaceSlugSchema } from "@mehen/protocol"
import { VaultError, errorResponse, json } from "../http.ts"
import { findRoute, type Route } from "../router.ts"
import { resolveWorkspace, type Handler, type RequestContext, type WorkspaceRequest } from "./context.ts"

import { workspaceOidcRoutes } from "./oidc.ts"
import { assertWorkspaceSessionGate } from "../directory/oidc-flow.ts"
import { workspaceDirectoryRoutes } from "./workspaces.ts"
import { workspacePeopleRoutes } from "./people.ts"
import { workspaceEnrolRoutes } from "./enrolments.ts"
import { workspaceDeviceRoutes } from "./workspace-devices.ts"
import { workspaceSystemRoutes } from "./system.ts"
import { workspaceItemsRoutes } from "./items-workspace.ts"
import { workspaceAdoptionsRoutes } from "./adoptions-workspace.ts"
import { workspaceBackupRoutes } from "./backups.ts"
import { workspaceOAuthRoutes } from "./oauth-workspace.ts"
import { workspaceProjectsRoutes } from "./projects-workspace.ts"
import { workspaceApprovalsRoutes } from "./approvals-workspace.ts"
import { workspacePendingRoutes } from "./pending-workspace.ts"
import { workspacePolicyRoutes } from "./policy-workspace.ts"
import { workspaceTeamRoutes } from "./teams.ts"

import { workspaceOverridesRoutes } from "./overrides-workspace.ts"
import { workspaceSettingsRoutes } from "./settings-workspace.ts"
import { workspaceMandateRoutes } from "./mandates.ts"

export type WorkspaceHandler = (rc: RequestContext, workspace: WorkspaceRequest) => Promise<Response>
// The one registration seam. Each area supplies its route array here;
// never wrap a legacy memberCall handler under /api/w.
export const WORKSPACE_ROUTES: Route<WorkspaceHandler>[] = [
  ...workspaceDirectoryRoutes,
  ...workspaceOidcRoutes,
  ...workspacePeopleRoutes,
  ...workspaceTeamRoutes,
  ...workspaceEnrolRoutes,
  ...workspaceSystemRoutes,
  ...workspaceDeviceRoutes,
  ...workspaceItemsRoutes,
  ...workspaceAdoptionsRoutes,
  ...workspaceBackupRoutes,
  ...workspaceOAuthRoutes,
  ...workspaceProjectsRoutes,
  ...workspaceApprovalsRoutes,
  ...workspacePendingRoutes,
  ...workspacePolicyRoutes,
  ...workspaceOverridesRoutes,
  ...workspaceSettingsRoutes,
  ...workspaceMandateRoutes,
]
// A browser tab names the workspace id it opened; a path that resolves to any
// other workspace is refused exactly as an unknown one, before any handler.
export const WORKSPACE_HEADER = "Mehen-Workspace"
export function registerWorkspaceRoutes(routes: Route<WorkspaceHandler>[]): Route<Handler>[] {
  return routes.map((route) => ({ method: route.method, path: `/api/w/:ws${route.path}`, handler: async (rc) => {
    const workspace = await resolveWorkspace(rc)
    const named = rc.request.headers.get(WORKSPACE_HEADER)
    if (named !== null && named !== workspace.workspace.id) throw new VaultError("not_found", "No such workspace.")
    return route.handler(rc, workspace)
  } }))
}
export async function workspacePrefix(rc: RequestContext): Promise<Response | null> {
  if (!rc.url.pathname.startsWith("/api/w/")) return null
  const routes = registerWorkspaceRoutes([{ method: "GET", path: "", handler: async (_rc, ws) => { await assertWorkspaceSessionGate(_rc.env,ws.account,ws.workspace,"web"); return json(ws.workspace) } }, ...WORKSPACE_ROUTES])
  const found = findRoute(routes, rc.request.method, rc.url.pathname)
  if (found === "method") return errorResponse({ error: "bad_request", message: "Method not allowed." }, 405)
  if (!found) throw new VaultError("not_found", "No such workspace.")
  return found.route.handler({ ...rc, params: found.params })
}
export type WorkspaceSlugRows = { canonical: string[]; aliases: { slug: string; workspace: string }[] }
export function workspaceNameAvailable(slug: string, rows: WorkspaceSlugRows): boolean {
  return WorkspaceSlugSchema.safeParse(slug).success && !(RESERVED_WORKSPACE_SLUGS as readonly string[]).includes(slug) && !rows.canonical.includes(slug) && !rows.aliases.some((a) => a.slug === slug)
}
export function assertWorkspaceNameAvailable(slug: string, rows: WorkspaceSlugRows, renamingWorkspace?: string, budget?: { budgets: NameMissBudget[]; now: number }): void {
  const exhausted = budget && exhaustedNameBudget(budget.budgets, budget.now)
  if (exhausted) throw new VaultError(exhausted.error, exhausted.message, { retryAfter: exhausted.retryAfter })
  if (!workspaceNameAvailable(slug, rows) || (renamingWorkspace !== undefined && rows.aliases.filter((a) => a.workspace === renamingWorkspace).length >= 5)) throw new VaultError(NAME_UNAVAILABLE.error, NAME_UNAVAILABLE.message)
}
