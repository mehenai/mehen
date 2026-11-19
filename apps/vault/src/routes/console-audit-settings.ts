// The Audit and Settings views' reads (CONSOLE_ROUTES in the protocol
// package), on a web session, not_found to an account without the
// operator role like every other operator route. Both only read: a setting
// changes through the proposals route (console-operators.ts), as a
// settings.narrow or settings.widen proposal.

import { CONSOLE_ROUTES, OperatorSettingsViewSchema, operatorAuditQuery } from "@mehen/protocol"
import { operatorAuditPage } from "../directory/operator-audit.ts"
import { operatorSettingsView } from "../directory/operator-settings.ts"
import { VaultError, json } from "../http.ts"
import type { Route } from "../router.ts"
import { accountBrowser } from "./account.ts"
import type { Handler } from "./context.ts"
import { operatorAccount } from "./console.ts"

export const consoleAuditSettingsRoutes: Route<Handler>[] = [
  accountBrowser("GET", CONSOLE_ROUTES.operatorAudit, async (rc) => {
    await operatorAccount(rc)
    const query = operatorAuditQuery(rc.url.searchParams)
    if (!query.ok) throw new VaultError("bad_request", "Those are not the Audit view's filters: actor, action and target are up to 128 characters, from and to are days (YYYY-MM-DD).")
    return json(await operatorAuditPage(rc.env, query.query))
  }),
  accountBrowser("GET", CONSOLE_ROUTES.operatorSettings, async (rc) => {
    const account = await operatorAccount(rc)
    return json(OperatorSettingsViewSchema.parse(await operatorSettingsView(rc.env, account.account)))
  }),
]
