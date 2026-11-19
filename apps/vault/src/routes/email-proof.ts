// The emailed code that proves an invited email, beside Google's proof
// (directory/email-proof.ts). Both routes spend AUTH_RATE_LIMITER by address,
// as the Google start does, before anything else.
import { z } from "zod"
import { currentAccountSession } from "../directory/account-session.ts"
import { startEmailProof, verifyEmailProof } from "../directory/email-proof.ts"
import { VaultError, json } from "../http.ts"
import type { Route } from "../router.ts"
import { accountBody, accountBrowser } from "./account.ts"
import type { Handler, RequestContext } from "./context.ts"

async function limitEmailProof(rc: RequestContext): Promise<void> {
  const check = await rc.env.AUTH_RATE_LIMITER?.limit({ key: `email:${rc.request.headers.get("cf-connecting-ip") ?? "unknown"}` })
  if (!check?.success) throw new VaultError("rate_limited","Too many code attempts. Try again shortly.",{ retryAfter: 60 })
}
const InviteCode = z.string().min(8).max(200)

export const emailProofRoutes: Route<Handler>[] = [
  accountBrowser("POST","/api/auth/email/start",async rc => {
    await limitEmailProof(rc)
    const { code } = await accountBody(rc,z.strictObject({ code: InviteCode }))
    const started = await startEmailProof(rc.env,code,await currentAccountSession(rc.request,rc.env))
    return json({ sent: true,expiresAt: started.expiresAt },200,{ "set-cookie": started.cookie })
  }),
  // The proof handle the signup and the join pass as emailProof, beside the
  // __Host-mehen_email cookie, as they pass oidcResult beside Google's.
  accountBrowser("POST","/api/auth/email/verify",async rc => {
    await limitEmailProof(rc)
    const { code,emailCode } = await accountBody(rc,z.strictObject({ code: InviteCode,emailCode: z.string().max(32) }))
    return json(await verifyEmailProof(rc.env,rc.request,code,emailCode))
  }),
]
