// GET /api/needs-you: everything the signed-in account may act on, across
// its workspaces. Never cached; the client revalidates with If-None-Match.
import { accountInbox, etagMatches, inboxEtag } from "../directory/account-inbox.ts"
import { json } from "../http.ts"
import type { Route } from "../router.ts"
import { requireAccount } from "./account.ts"
import type { Handler } from "./context.ts"

export const needsYouRoutes: Route<Handler>[] = [
  { method: "GET", path: "/api/needs-you", handler: async (rc) => {
    const account = await requireAccount(rc)
    const { inbox } = await accountInbox(rc, account, { sessionKind: "web" })
    const etag = await inboxEtag(inbox), headers = { "cache-control": "no-store", etag }
    if (etagMatches(rc.request.headers.get("if-none-match"), etag)) return new Response(null, { status: 304, headers })
    return json(inbox, 200, headers)
  } },
]
