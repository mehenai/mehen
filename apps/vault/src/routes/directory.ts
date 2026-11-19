import { VaultError,errorResponse } from "../http.ts"
import { findRoute } from "../router.ts"
import { accountRoutes } from "./account.ts"
import { workspaceAppRoutes } from "./app.ts"
import { oidcRoutes } from "./oidc.ts"
import { emailProofRoutes } from "./email-proof.ts"
import { accountAppRoutes } from "./account-app.ts"
import { consoleRoutes,operatorAccount } from "./console.ts"
import { consoleOperatorRoutes } from "./console-operators.ts"
import { consoleAuditSettingsRoutes } from "./console-audit-settings.ts"
import { consoleWorkspaceRoutes } from "./console-workspaces.ts"
import { consoleAccountRoutes } from "./console-accounts.ts"
import { needsYouRoutes } from "./needs-you.ts"
import { workspaceAccountRoutes,workspaceEnrolDeviceRoutes } from "./workspaces.ts"
import type { RequestContext } from "./context.ts"
export const workspaceDirectoryEntryRoutes = [...oidcRoutes,...emailProofRoutes,...workspaceAppRoutes,...accountRoutes,...needsYouRoutes,...accountAppRoutes,...workspaceAccountRoutes,...workspaceEnrolDeviceRoutes,...consoleRoutes,...consoleOperatorRoutes,...consoleWorkspaceRoutes,...consoleAccountRoutes,...consoleAuditSettingsRoutes]
export async function workspaceDirectoryPrefix(rc: RequestContext): Promise<Response | null> {
  const found = findRoute(workspaceDirectoryEntryRoutes,rc.request.method,rc.url.pathname)
  // Only an operator learns that an operator route exists: anyone else's
  // session is read for an unknown operator path too, so a wrong method and
  // an unknown path cost the same.
  const operatorPath = rc.url.pathname.startsWith("/api/operator/")
  if (found === "method") {
    if (operatorPath) await operatorAccount(rc)
    return errorResponse({ error: "bad_request",message: "Method not allowed." },405)
  }
  if (found) return found.route.handler({ ...rc,params: found.params })
  if (operatorPath) await operatorAccount(rc)
  if (rc.url.pathname.startsWith("/api/") && !rc.url.pathname.startsWith("/api/w/") || rc.url.pathname.startsWith("/app/v1/")) throw new VaultError("not_found","No such operation.")
  return null
}
