import { workspaceInbox } from "../directory/account-inbox.ts"
import { VaultError, json } from "../http.ts"
import type { Route } from "../router.ts"
import { INBOX_GROUP_ID } from "../vault/areas/pending-workspace.ts"
import { workspaceCall } from "./context.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"
export const workspacePendingRoutes: Route<WorkspaceHandler>[] = [
  { method: "GET", path: "/pending", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "pending.list")) },
  // ?group=grp_... or bnd_...: that group's asks alone, one row each.
  { method: "GET", path: "/inbox", handler: async (rc, ws) => {
    const group = rc.url.searchParams.get("group")
    if (group !== null && !INBOX_GROUP_ID.test(group)) throw new VaultError("bad_request", "That is not a review group (grp_...) or a bundle (bnd_...).")
    return json(await workspaceInbox(rc, ws, { sessionKind: "web", ...(group === null ? {} : { group }) }), 200, { "cache-control": "no-store" })
  } },
]
