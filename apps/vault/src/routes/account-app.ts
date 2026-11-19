import { WorkspaceStepUpActionSchema } from "@mehen/protocol"
import { z } from "zod"
import { accountSigninOptions,accountSigninVerify,AccountSigninVerify } from "../directory/workspace-accounts.ts"
import { requireAccountAppSession } from "../directory/workspace-app-session.ts"
import { accountSessionView,endOwnAccountSession } from "../directory/workspace-account-admin.ts"
import { APP_CLIENTS } from "../directory/app-session.ts"
import { placeOf } from "../directory/session.ts"
import { startAccountStepUp } from "../directory/workspace-stepup.ts"
import { retryAccountSecurityIfDue } from "../directory/account-security.ts"
import { mirrorAccountEvents } from "../directory/account-events.ts"
import { VaultError,json,parseJson,readBody } from "../http.ts"
import type { Route } from "../router.ts"
import type { Handler,RequestContext } from "./context.ts"
import { limitWorkspaceStepUp } from "./account.ts"
export async function requireAppAccount(rc: RequestContext) {
  const account = await requireAccountAppSession(rc.request,rc.env)
  if (account.transition) rc.ctx.waitUntil(retryAccountSecurityIfDue(rc.env,account.transition).catch(() => console.error(JSON.stringify({ at: "account.security.retry",transition: account.transition }))))
  return account
}
const app = (method: string,path: string,handler: Handler): Route<Handler> => ({ method,path,handler })
export const accountAppRoutes: Route<Handler>[] = [
  app("POST","/app/v1/session/options",async rc => { await readBody(rc.request); return json(await accountSigninOptions(rc.env)) }),
  app("POST","/app/v1/session",async rc => {
    const input = parseJson(AccountSigninVerify.extend({ client: z.enum(APP_CLIENTS) }),await readBody(rc.request)),result = await accountSigninVerify(rc.env,input,{ client: input.client,place: placeOf(rc.request) },Date.now(),"app")
    const account = await requireAccountAppSession(new Request(rc.request.url,{ headers: { authorization: `Bearer ${result.session.token}` } }),rc.env)
    const opened = await rc.env.DB.prepare("SELECT expires_at FROM web_sessions WHERE id=? AND account=?").bind(result.session.id,result.account).first<{ expires_at: number }>()
    if (!opened) throw new VaultError("unauthenticated","Sign in to the vault again in the app.")
    return json({ token: result.session.token,expiresAt: new Date(opened.expires_at).toISOString(),session: await accountSessionView(rc.env,account) })
  }),
  app("GET","/app/v1/session",async rc => json(await accountSessionView(rc.env,await requireAppAccount(rc)))),
  app("POST","/app/v1/session/end",async rc => { const account = await requireAppAccount(rc); await endOwnAccountSession(rc.env,account,account.session); rc.ctx.waitUntil(mirrorAccountEvents(rc.env)); return json({}) }),
  app("GET","/app/v1/workspaces",async rc => json((await accountSessionView(rc.env,await requireAppAccount(rc))).memberships)),
  app("POST","/app/v1/stepup",async rc => {
    const account = await requireAppAccount(rc),{ scope,action } = parseJson(z.strictObject({ scope: z.string().min(1).max(128),action: WorkspaceStepUpActionSchema }),await readBody(rc.request))
    if (action.type !== "approval.decide" || action.remember !== undefined) throw new VaultError("forbidden","The app can only confirm exact request decisions. Open the vault page for other changes.")
    const indexed = await rc.env.DB.prepare("SELECT w.id FROM workspaces w JOIN memberships m ON m.workspace=w.id WHERE w.id=? AND w.status='active' AND m.account=? AND m.state='member'").bind(scope,account.account).first()
    if (!indexed) throw new VaultError("not_found","No such workspace.")
    await limitWorkspaceStepUp(rc,account.account)
    return json(await startAccountStepUp(rc.env,account,scope,action,{ allowGrace: false }))
  }),
]
