import { accountBreakGlassOptions,accountBreakGlassVerify } from "../directory/account-break-glass.ts"
import { sha256Text } from "../directory/session.ts"
import { oidcCookieToken } from "../directory/oidc-flow.ts"
import { OIDC_COOKIE } from "../directory/oidc-flow.ts"
import { EMAIL_COOKIE, emailCookieToken } from "../directory/email-proof.ts"
import { readCookie } from "../directory/session.ts"
import { WorkspaceStepUpActionSchema } from "@mehen/protocol"
import type { AccountSessionsRead,StepUpGraceRead } from "@mehen/protocol/api"
import { z } from "zod"
import { accountRecoverySetupRequiredNow } from "../directory/account-recovery-setup.ts"
import { accountSecurityStatus,retryAccountSecurityIfDue } from "../directory/account-security.ts"
import { currentAccountSession,type AccountWebSession } from "../directory/account-session.ts"
import { accountSessionView,accountPasskeys,accountSessions,mayEndOtherAccountSessions,renameAccountPasskey,endAllAccountSessions,endOwnAccountSession,removeAccountPasskey,assertAccountOnboarding } from "../directory/workspace-account-admin.ts"
import { accountSignupOptions,accountSignupVerify,accountSigninOptions,accountSigninVerify,AccountSignupOptions,AccountSignupVerify,AccountSigninVerify } from "../directory/workspace-accounts.ts"
import { accountRecoveryCeremony,accountRecoveryStatus,accountPasskeyOptions,accountPasskeyVerify,accountRecoverySession,confirmAccountRecoveryCodes,firstRecoveryCodesAfterSignup,issueAccountRecoveryCodes,resolveAccountRecovery,startAccountRecovery } from "../directory/workspace-recovery.ts"
import { ownAccountEvents,ownAccountNotices,mirrorAccountEvents } from "../directory/account-events.ts"
import { endStepUpGrace,liveStepUpGrace,requireAccountStepUp,startAccountStepUp } from "../directory/workspace-stepup.ts"
import { NO_INVITATION,hasOperatorInvitation } from "../directory/operator-proposals.ts"
import { isOperator } from "../platform/console.ts"
import { findAccountPasskey } from "../directory/account-store.ts"
import { credentialId } from "../directory/webauthn.ts"
import { PasskeyKind,PasskeyName } from "../directory/passkey-admin.ts"
import { StepUpAssertionProofSchema } from "@mehen/protocol/step-up-proof"
import { assertSameOrigin,clientLabel,placeOf,sessionCookie,clearSessionCookie } from "../directory/session.ts"
import { completeWorkspaceJoin,peekWorkspaceInvite,reserveWorkspaceJoin } from "../directory/workspace-invites.ts"
import { VaultError,json,parseJson,readBody } from "../http.ts"
import type { Route } from "../router.ts"
import type { Handler,RequestContext } from "./context.ts"
export async function requireAccount(rc: RequestContext): Promise<AccountWebSession> {
  const account = await currentAccountSession(rc.request,rc.env)
  if (!account) throw new VaultError("unauthenticated","Sign in with your passkey to continue.")
  if (account.transition) rc.ctx.waitUntil(retryAccountSecurityIfDue(rc.env,account.transition).catch(() => console.error(JSON.stringify({ at: "account.security.retry",transition: account.transition }))))
  return account
}
export function accountBrowser(method: string,path: string,handler: Handler): Route<Handler> {
  return { method,path,handler: async rc => { if (method !== "GET") assertSameOrigin(rc.request,rc.env); return handler(rc) } }
}
export async function accountBody<T extends z.ZodType>(rc: RequestContext,schema: T): Promise<z.infer<T>> { return parseJson(schema,await readBody(rc.request)) }
const Proof = z.strictObject({ stepUp: StepUpAssertionProofSchema.optional() })
const Registration = z.strictObject({ response: z.record(z.string(),z.unknown()),name: PasskeyName.optional() })
export async function limitWorkspaceStepUp(rc: RequestContext,account: string): Promise<void> {
  const check = await rc.env.AUTH_RATE_LIMITER?.limit({ key: `stepup:${account}` })
  if (!check?.success) throw new VaultError("rate_limited","Too many passkey confirmation attempts. Try again shortly.",{ retryAfter: 60 })
}
async function breakGlassCode(rc: RequestContext,code: string): Promise<boolean> {
  return (await rc.env.DB.prepare("SELECT id FROM account_break_glass_intents WHERE code_hash=?").bind(await sha256Text(code)).first()) !== null
}
export const accountRoutes: Route<Handler>[] = [
  accountBrowser("POST","/api/auth/signup/options",async rc => { const input = await accountBody(rc,AccountSignupOptions); return json(await (await breakGlassCode(rc,input.invite) ? accountBreakGlassOptions(rc.env,input.invite) : accountSignupOptions(rc.env,input,Date.now(),readCookie(rc.request,OIDC_COOKIE) ?? undefined,readCookie(rc.request,EMAIL_COOKIE) ?? undefined))) }),
  // `onboarding` is what the new account does next, decided by the server
  // from the code it checked: "bootstrap" goes on to recovery and the
  // picker, "join" to the invitation's join. `recoveryReady`: the new
  // passkey is already a way back in (it syncs), so /signup skips recovery.
  // Neither carries a secret.
  accountBrowser("POST","/api/auth/signup/verify",async rc => { const input = await accountBody(rc,AccountSignupVerify),from = { client: clientLabel(rc.request.headers.get("user-agent")),place: placeOf(rc.request) }; const result = await (await breakGlassCode(rc,input.invite) ? accountBreakGlassVerify(rc.env,input.invite,input.response,from).then(value => ({ ...value,via: "break-glass" as const })) : accountSignupVerify(rc.env,input,from,Date.now(),readCookie(rc.request,OIDC_COOKIE) ?? undefined,readCookie(rc.request,EMAIL_COOKIE) ?? undefined)); return json({ account: result.account,onboarding: result.via,recoveryReady: !(await accountRecoverySetupRequiredNow(rc.env,result.account)) },200,{ "set-cookie": sessionCookie(result.session.token) }) }),
  accountBrowser("POST","/api/auth/signin/options",async rc => { const body = await accountBody(rc,z.strictObject({ oidcResult: z.string().max(128).optional() })); return json(await accountSigninOptions(rc.env,Date.now(),body.oidcResult ? { result: body.oidcResult,cookie: oidcCookieToken(rc.request,"signin") } : undefined)) }),
  accountBrowser("POST","/api/auth/signin/verify",async rc => { const result = await accountSigninVerify(rc.env,await accountBody(rc,AccountSigninVerify),{ client: clientLabel(rc.request.headers.get("user-agent")),place: placeOf(rc.request) },Date.now(),"web",readCookie(rc.request,OIDC_COOKIE) ?? undefined); return json({ account: result.account },200,{ "set-cookie": sessionCookie(result.session.token) }) }),
  accountBrowser("POST","/api/auth/signout",async rc => { const account = await requireAccount(rc); await endOwnAccountSession(rc.env,account,account.session); rc.ctx.waitUntil(mirrorAccountEvents(rc.env)); return json({},200,{ "set-cookie": clearSessionCookie() }) }),
  accountBrowser("GET","/api/account",async rc => json(await accountSessionView(rc.env,await requireAccount(rc)))),
  accountBrowser("GET","/api/account/security-transition",async rc => { const account = await requireAccount(rc); return json({ pendingTransition: await accountSecurityStatus(rc.env,account.account),recoverySetupRequired: await accountRecoverySetupRequiredNow(rc.env,account.account) }) }),
  accountBrowser("GET","/api/account/events",async rc => json(await ownAccountEvents(rc.env,(await requireAccount(rc)).account))),
  accountBrowser("GET","/api/account/notices",async rc => json(await ownAccountNotices(rc.env,(await requireAccount(rc)).account))),
  accountBrowser("GET","/api/account/passkeys",async rc => json({ passkeys: await accountPasskeys(rc.env,await requireAccount(rc)) })),
  accountBrowser("GET","/api/account/sessions",async rc => { const account = await requireAccount(rc),now = Date.now(); return json({ sessions: await accountSessions(rc.env,account,now),mayEndOtherSessions: await mayEndOtherAccountSessions(rc.env,account,now) } satisfies AccountSessionsRead) }),
  accountBrowser("POST","/api/account/stepup/start",async rc => {
    const account = await requireAccount(rc),{ action } = await accountBody(rc,z.strictObject({ action: WorkspaceStepUpActionSchema }))
    // The console's step-ups start only on its own routes (routes/console.ts),
    // which check the role first; proposing and approving as an operator too.
    if (action.type === "platform.operate" || action.type === "platform.administer" || action.type === "operator.propose" || action.type === "operator.approve" || action.type === "operator.break_glass_link") throw new VaultError("not_found","No such operation.")
    // Accepting the operator role: only the account an approved grant names, and not one that holds the role.
    if (action.type === "operator.accept" && (!(await hasOperatorInvitation(rc.env,account.account,action.proposal)) || await isOperator(rc.env,account.account))) throw new VaultError("not_found",NO_INVITATION)
    // An adoption is approved in its workspace, never with an account-wide step-up.
    if (action.type === "adoption.approve") throw new VaultError("not_found","No such adoption.")
    if (action.type === "account.delete" && action.account !== account.account) throw new VaultError("not_found","No such account.")
    if (action.type === "passkey.remove" && !(await rc.env.DB.prepare("SELECT handle FROM passkeys WHERE account=? AND handle=?").bind(account.account,action.passkey).first())) throw new VaultError("not_found","No such passkey.")
    if (action.type === "recovery.resolve" && !(await rc.env.DB.prepare("SELECT id FROM account_notices WHERE account=? AND id=? AND resolved_at IS NULL").bind(account.account,action.notice).first())) throw new VaultError("not_found","No such notice.")
    await limitWorkspaceStepUp(rc,account.account)
    return json(await startAccountStepUp(rc.env,account,"-",action))
  }),
  // This browser session's passkey grace window, and "Ask every time", which
  // ends it with no passkey: it only narrows.
  accountBrowser("GET","/api/account/stepup/grace",async rc => { const grace = await liveStepUpGrace(rc.env,await requireAccount(rc)); return json({ grace: grace ? { until: new Date(grace.until).toISOString() } : null } satisfies StepUpGraceRead) }),
  accountBrowser("POST","/api/account/stepup/grace/end",async rc => { await endStepUpGrace(rc.env,await requireAccount(rc)); return json({}) }),
  accountBrowser("POST","/api/account/passkeys/:id/rename",async rc => { const actor = await requireAccount(rc),{ name } = await accountBody(rc,z.strictObject({ name: PasskeyName })); return json({ passkey: await renameAccountPasskey(rc.env,actor,rc.params.id ?? "",name) }) }),
  accountBrowser("GET","/api/account/recovery",async rc => json(await accountRecoveryStatus(rc.env,(await requireAccount(rc)).account))),
  accountBrowser("POST","/api/account/passkeys/options",async rc => { const account = await requireAccount(rc),{ stepUp,kind } = await accountBody(rc,Proof.extend({ kind: PasskeyKind.default("device") })); const evidence = await requireAccountStepUp(rc,account,"-",{ type: "passkey.add" },stepUp); return json(await accountPasskeyOptions(rc.env,account,"settings",Date.now(),evidence.factor,kind)) }),
  accountBrowser("POST","/api/account/passkeys/verify",async rc => { const account = await requireAccount(rc),{ response,name } = await accountBody(rc,Registration); await accountPasskeyVerify(rc.env,account,response,"settings",Date.now(),name); const key = await findAccountPasskey(rc.env,credentialId(response)),passkey = key?.account === account.account ? (await accountPasskeys(rc.env,account)).find(value => value.passkey === key.handle) : null; if (!passkey) throw new VaultError("not_found","You have no passkey with that id."); return json({ passkey }) }),
  accountBrowser("POST","/api/account/passkeys/:id/remove",async rc => { const account = await requireAccount(rc),{ stepUp } = await accountBody(rc,Proof),passkey = rc.params.id ?? ""; const evidence = await requireAccountStepUp(rc,account,"-",{ type: "passkey.remove",passkey },stepUp); return json(await removeAccountPasskey(rc.env,account,passkey,evidence.factor)) }),
  accountBrowser("POST","/api/account/sessions/:id/end",async rc => { const account = await requireAccount(rc); await readBody(rc.request); await endOwnAccountSession(rc.env,account,rc.params.id ?? ""); rc.ctx.waitUntil(mirrorAccountEvents(rc.env)); return json({}) }),
  accountBrowser("POST","/api/account/sessions/end-all",async rc => { const account = await requireAccount(rc); await readBody(rc.request); return json(await endAllAccountSessions(rc.env,account)) }),
  // No step-up only for the account's first codes from its sign-up session
  // (FIRST_CODES_AFTER_SIGNUP_MS); a proof sent anyway is checked as usual.
  accountBrowser("POST","/api/account/recovery/generate",async rc => { const account = await requireAccount(rc),{ stepUp } = await accountBody(rc,Proof),now = Date.now(),afterSignup = stepUp === undefined && await firstRecoveryCodesAfterSignup(rc.env,account,now); if (!afterSignup) await requireAccountStepUp(rc,account,"-",{ type: "recovery.generate" },stepUp); return json(await issueAccountRecoveryCodes(rc.env,account,now,afterSignup)) }),
  accountBrowser("POST","/api/account/recovery/confirm",async rc => { const account = await requireAccount(rc),input = await accountBody(rc,z.strictObject({ batch: z.string().max(128),code: z.string().max(128) })); await confirmAccountRecoveryCodes(rc.env,account,input.batch,input.code); return json({}) }),
  accountBrowser("POST","/api/auth/recovery",async rc => { if (rc.request.headers.has("Mehen-Proof") || rc.request.headers.get("sec-fetch-site") !== "same-origin" || rc.request.headers.get("sec-fetch-mode") !== "cors") throw new VaultError("forbidden","Use a recovery code only on the vault's recovery page, not through an agent or another site."); const { code } = await accountBody(rc,z.strictObject({ code: z.string().max(128) })),result = await startAccountRecovery(rc.env,rc.request,code); return json({ pending: result.pending,transition: result.transition },result.pending ? 202 : 200,{ "set-cookie": sessionCookie(result.session.token) }) }),
  // A recovery ceremony's own status, by its cookie: never a session. While
  // pending, its transition's due retry is scheduled, not awaited.
  accountBrowser("GET","/api/auth/recovery/status",async rc => { const ceremony = await accountRecoveryCeremony(rc.env,rc.request); if (ceremony.transition) rc.ctx.waitUntil(retryAccountSecurityIfDue(rc.env,ceremony.transition).catch(() => console.error(JSON.stringify({ at: "account.recovery.retry", transition: ceremony.transition })))); return json({ state: ceremony.state }) }),
  accountBrowser("POST","/api/auth/recovery/passkey/options",async rc => { const { kind } = await accountBody(rc,z.strictObject({ kind: PasskeyKind.default("device") })); return json(await accountPasskeyOptions(rc.env,await accountRecoverySession(rc.env,rc.request),"recovery",Date.now(),undefined,kind)) }),
  accountBrowser("POST","/api/auth/recovery/passkey/verify",async rc => { const account = await accountRecoverySession(rc.env,rc.request),{ response,name } = await accountBody(rc,Registration),session = await accountPasskeyVerify(rc.env,account,response,"recovery",Date.now(),name); if (!session) throw new Error("Missing recovered session"); return json({},200,{ "set-cookie": sessionCookie(session.token) }) }),
  accountBrowser("POST","/api/account/recovery/:id/resolve",async rc => { const account = await requireAccount(rc),{ outcome,stepUp } = await accountBody(rc,Proof.extend({ outcome: z.enum(["cancel","keep"]) })),notice = rc.params.id ?? "",evidence = await requireAccountStepUp(rc,account,"-",{ type: "recovery.resolve",notice,outcome },stepUp); return json(await resolveAccountRecovery(rc.env,account,evidence.factor,notice,outcome)) }),
  // What /signup names before anything is created. Under /api/auth/, so the
  // sign-in limiter counts it; signed in, the account may read its own used code.
  accountBrowser("POST","/api/auth/invite/peek",async rc => { const { code } = await accountBody(rc,z.strictObject({ code: z.string().min(8).max(200) })); return json(await peekWorkspaceInvite(rc.env,code,await currentAccountSession(rc.request,rc.env))) }),
  accountBrowser("POST","/api/account/invites/join",async rc => { const account = await requireAccount(rc),{ code,oidcResult,emailProof } = await accountBody(rc,z.strictObject({ code: z.string().min(8).max(200),oidcResult: z.string().max(128).optional(),emailProof: z.string().max(128).optional() })),reservation = await reserveWorkspaceJoin(rc.env,account,code,undefined,Date.now(),oidcResult ? { result: oidcResult,cookie: oidcCookieToken(rc.request,"invite") } : undefined,emailProof ? { proof: emailProof,cookie: emailCookieToken(rc.request) } : undefined); return json(await completeWorkspaceJoin(rc.env,reservation)) }),
  accountBrowser("GET","/api/account/onboarding/:workspace",async rc => { const account = await requireAccount(rc); return json(await assertAccountOnboarding(rc.env,account,rc.params.workspace ?? "")) }),
]
