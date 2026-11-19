// The Accounts view's routes (CONSOLE_ROUTES in the protocol package): the
// accounts list and one account, read on the operator's web session, and the
// proposer taking an approved recovery's link with a passkey. Like every
// operator route they answer not_found to an account without the role. The
// view's changes are operator proposals (routes/console-operators.ts,
// directory/operator-account-kinds.ts).

import { ACCOUNT_ID, CONSOLE_ROUTES, OperatorAccountDetailSchema, OperatorAccountListQuerySchema, OperatorAccountListSchema, OperatorBreakGlassLinkRequestSchema, OperatorBreakGlassLinkSchema, operatorBreakGlassLinkStepUpAction } from "@mehen/protocol"
import { operatorAccountDetail, operatorAccountList, takeBreakGlassLink } from "../directory/operator-accounts.ts"
import { requireAccountStepUp } from "../directory/workspace-stepup.ts"
import { VaultError, json } from "../http.ts"
import type { Route } from "../router.ts"
import { accountBody, accountBrowser } from "./account.ts"
import type { Handler, RequestContext } from "./context.ts"
import { operatorAccount } from "./console.ts"

function accountInPath(rc: RequestContext): string {
  const id = rc.params.id ?? ""
  if (!ACCOUNT_ID.test(id)) throw new VaultError("not_found", "No such account.")
  return id
}

export const consoleAccountRoutes: Route<Handler>[] = [
  accountBrowser("GET", CONSOLE_ROUTES.operatorAccounts, async (rc) => {
    const account = await operatorAccount(rc)
    const query = OperatorAccountListQuerySchema.safeParse(Object.fromEntries(rc.url.searchParams))
    if (!query.success) throw new VaultError("bad_request", "That is not a search or a page of the accounts.")
    return json(OperatorAccountListSchema.parse(await operatorAccountList(rc.env, account.account, query.data)))
  }),
  accountBrowser("GET", CONSOLE_ROUTES.operatorAccount, async (rc) => {
    const account = await operatorAccount(rc)
    const detail = await operatorAccountDetail(rc.env, account.account, accountInPath(rc))
    if (!detail) throw new VaultError("not_found", "No such account.")
    return json(OperatorAccountDetailSchema.parse(detail))
  }),
  // Shown once, to the operator who proposed recovering this account's
  // access; everything is checked before the passkey is asked for.
  accountBrowser("POST", CONSOLE_ROUTES.operatorBreakGlassLink, async (rc) => {
    const account = await operatorAccount(rc)
    const target = accountInPath(rc)
    const { intent, stepUp } = await accountBody(rc, OperatorBreakGlassLinkRequestSchema)
    const link = await takeBreakGlassLink(rc.env, account.account, target, intent, () => requireAccountStepUp(rc, account, "-", operatorBreakGlassLinkStepUpAction(intent), stepUp))
    return json(OperatorBreakGlassLinkSchema.parse(link))
  }),
]
