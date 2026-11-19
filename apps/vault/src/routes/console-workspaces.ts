// The Workspaces view's reads (CONSOLE_ROUTES in the protocol package):
// every workspace on this deployment and one at a time, on a web session,
// not_found to an account without the operator role like every other
// operator route. Restoring and freezing a workspace are proposals, sent to
// the proposals route (console-operators.ts).

import { CONSOLE_ROUTES, OperatorWorkspaceDetailSchema, OperatorWorkspaceListSchema, OperatorWorkspaceQuerySchema, WorkspaceIdSchema } from "@mehen/protocol"
import { operatorWorkspaceDetail, operatorWorkspaceList } from "../directory/operator-workspaces.ts"
import { VaultError, json } from "../http.ts"
import type { Route } from "../router.ts"
import { accountBrowser } from "./account.ts"
import type { Handler } from "./context.ts"
import { operatorAccount } from "./console.ts"

export const consoleWorkspaceRoutes: Route<Handler>[] = [
  accountBrowser("GET", CONSOLE_ROUTES.operatorWorkspaces, async (rc) => {
    await operatorAccount(rc)
    const query = OperatorWorkspaceQuerySchema.safeParse(Object.fromEntries(rc.url.searchParams))
    if (!query.success) throw new VaultError("bad_request", "Search by a name, a slug or a workspace id (tn_...), with a filter of all, active, creating, deleting or managed.")
    return json(OperatorWorkspaceListSchema.parse(await operatorWorkspaceList(rc.env, query.data)))
  }),
  accountBrowser("GET", CONSOLE_ROUTES.operatorWorkspace, async (rc) => {
    const account = await operatorAccount(rc)
    const id = WorkspaceIdSchema.safeParse(rc.params.id)
    if (!id.success) throw new VaultError("not_found", "No such workspace.")
    return json(OperatorWorkspaceDetailSchema.parse(await operatorWorkspaceDetail(rc.env, id.data, account.account)))
  }),
]
