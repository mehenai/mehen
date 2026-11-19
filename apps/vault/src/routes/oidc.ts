import { IdentityRuleSchema, WorkspaceStepUpActionSchema } from "@mehen/protocol"
import { z } from "zod"
import { bootstrapAppOidc, callbackOidcFlow, createAppGateCode, finishWorkspaceGate, oidcIdentityContext, startInviteOidc, startWorkspaceGate, finishOidcLink, identityForResult, oidcCookieToken, oidcNext, readOidcResult, startOidcFlow } from "../directory/oidc-flow.ts"
import { oidcConfigured, OidcPurpose, oidcRefusal } from "../directory/oidc.ts"
import { sha256Text } from "../directory/session.ts"
import { reserveAccountSecurity, retryAccountSecurity } from "../directory/account-security.ts"
import { StepUpAssertionProofSchema } from "@mehen/protocol/step-up-proof"
import { requireAccountStepUp, requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import { oidcVerifyPage } from "../ui/pages/oidc-verify.ts"
import { SESSION_ENDED_HEADING, errorPage, pageResponse, sessionEndedError } from "../ui/layout.ts"
import { VaultError, json } from "../http.ts"
import type { Route } from "../router.ts"
import { accountBody, accountBrowser, requireAccount } from "./account.ts"
import { workspaceCall, type Handler } from "./context.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"

function purposeQuery(value: string | null) { const parsed = OidcPurpose.safeParse(value); if (!parsed.success) throw new VaultError("bad_request","Unknown Google verification purpose."); return parsed.data }
const Start = z.strictObject({ purpose: OidcPurpose, workspace: z.string().max(128).optional(), action: WorkspaceStepUpActionSchema.optional(), rule: IdentityRuleSchema.optional(), invite: z.string().min(8).max(200).optional(), next: z.string().max(1024).optional(), stepUp: StepUpAssertionProofSchema.optional() })
// The Google pages a browser lands on, the callback above all: a refusal
// there is a page with the vault's message and what to do next, never the
// JSON an API caller gets. A caller that does not ask for HTML keeps the
// JSON refusal and its status.
export const GOOGLE_REFUSED_HEADING = "Google could not verify you"
export const GOOGLE_REFUSED_NEXT = "If an invitation sent you here, open its link again and choose the Google account it was sent to. Otherwise go back to the page that sent you to Google and start again."
function oidcPage(handler: Handler): Handler {
  return async rc => {
    try { return await handler(rc) } catch (error) {
      if (!(error instanceof VaultError) || !(rc.request.headers.get("accept") ?? "").includes("text/html")) throw error
      if (error.code === "unauthenticated") return errorPage(null,error.status,sessionEndedError(rc.url.pathname + rc.url.search),SESSION_ENDED_HEADING)
      if (error.code !== "identity_required") return errorPage(null,error.status,error.toJSON())
      return errorPage(null,error.status,{ ...error.toJSON(),next: { say: GOOGLE_REFUSED_NEXT } },GOOGLE_REFUSED_HEADING)
    }
  }
}
export const oidcRoutes: Route<Handler>[] = [
  { method: "GET",path: "/auth/oidc/verify",handler: oidcPage(async rc => {
    const purpose = purposeQuery(rc.url.searchParams.get("purpose") ?? "signin")
    if (purpose === "link" || purpose === "gate") await requireAccount(rc)
    return pageResponse(oidcVerifyPage({ mode: "verify",enabled: oidcConfigured(rc.env),purpose,workspace: rc.url.searchParams.get("workspace") ?? undefined,next: oidcNext(rc.url.searchParams.get("next")) ?? undefined }))
  }) },
  { method: "GET",path: "/auth/oidc/result",handler: oidcPage(async rc => {
    const purpose = purposeQuery(rc.url.searchParams.get("purpose"))
    // An invitation's proof is used on /signup; an older link lands there too.
    if (purpose === "invite") return new Response(null,{ status: 303,headers: { location: "/signup" } })
    const result = await readOidcResult(rc.env,rc.url.searchParams.get("result") ?? "",oidcCookieToken(rc.request,purpose),purpose)
    const account = await (await import("../directory/account-session.ts")).currentAccountSession(rc.request,rc.env)
    if (result.account !== null && (account?.account !== result.account || result.session !== null && account.session !== result.session || result.security_epoch !== null && account.securityEpoch !== result.security_epoch)) throw oidcRefusal("account_mismatch",purpose)
    return pageResponse(oidcVerifyPage({ mode: "result",enabled: oidcConfigured(rc.env),purpose,result: result.id,workspace: result.workspace ?? undefined,next: oidcNext(rc.url.searchParams.get("next")) ?? undefined,identity: { email: result.email,subject: result.subject,name: result.name } }))
  }) },
  { method: "GET",path: "/auth/oidc/google/app/start",handler: async rc => { return pageResponse(oidcVerifyPage({ mode: "app-start",enabled: oidcConfigured(rc.env) })) } },
  { method: "GET",path: "/app/v1/gate/callback",handler: async rc => { return pageResponse(oidcVerifyPage({ mode: "app-callback",enabled: false })) } },
  accountBrowser("POST","/api/auth/oidc/google/app/start",async rc => {
    if (rc.request.headers.get("sec-fetch-site") !== "same-origin" || rc.request.headers.get("sec-fetch-mode") !== "cors") throw oidcRefusal("request_invalid","gate")
    const body = await accountBody(rc,z.strictObject({ state: z.string().max(128),flow: z.string().max(128) })),start = await bootstrapAppOidc(rc.env,body.state,body.flow)
    return json({ url: start.url },200,{ "set-cookie": start.cookie })
  }),
  accountBrowser("GET", "/api/auth/oidc/google/config", async rc => json({ enabled: oidcConfigured(rc.env) })),
  accountBrowser("POST", "/api/auth/oidc/google/start", async rc => {
    const check = await rc.env.AUTH_RATE_LIMITER?.limit({ key: `oidc:${rc.request.headers.get("cf-connecting-ip") ?? "unknown"}` })
    if (!check?.success) throw new VaultError("rate_limited","Too many Google verification attempts. Try again shortly.",{ retryAfter: 60 })
    const body = await accountBody(rc, Start)
    const account = body.purpose === "link" || body.purpose === "invite" ? await (await import("../directory/account-session.ts")).currentAccountSession(rc.request, rc.env) : null
    if (body.purpose === "link") {
      const current = account ?? await requireAccount(rc)
      await requireAccountStepUp(rc, current, "-", { type: "identity.link", provider: "google" }, body.stepUp)
    }
    if (body.purpose === "gate") {
      const current = await requireAccount(rc)
      if (!body.workspace) throw oidcRefusal("request_invalid","gate")
      const workspace = await rc.env.DB.prepare("SELECT w.id FROM workspaces w JOIN memberships m ON m.workspace=w.id WHERE m.account=? AND m.state='member' AND w.status='active' AND (w.id=? OR w.slug=? OR EXISTS (SELECT 1 FROM workspace_slugs s WHERE s.workspace=w.id AND s.slug=?))").bind(current.account,body.workspace,body.workspace,body.workspace).first<{ id: string }>()
      if (!workspace) throw new VaultError("not_found","No such workspace.")
      const start = await startWorkspaceGate(rc.env,current,workspace.id,body)
      return json({ url: start.url },200,{ "set-cookie": start.cookie })
    }
    if (body.purpose === "invite" && !body.invite) throw oidcRefusal("request_invalid","invite")
    const start = body.purpose === "invite" ? await startInviteOidc(rc.env,await sha256Text(body.invite!),account,body.next) : await startOidcFlow(rc.env, { purpose: body.purpose, ...(account ? { account } : {}), ...(body.invite ? { inviteHash: await sha256Text(body.invite) } : {}), next: body.next })
    return json({ url: start.url }, 200, { "set-cookie": start.cookie })
  }),
  { method: "GET", path: "/auth/oidc/google/callback", handler: oidcPage(async rc => {
    const result = await callbackOidcFlow(rc.env, rc.request), cookie = { "set-cookie": result.resultCookie }
    if (result.app_session_hash) return new Response(null,{ status: 303,headers: { location: await createAppGateCode(rc.env,result),...cookie } })
    // The invitation's proof goes back to /signup in the fragment, which the
    // server never sees again; the id is bound to the Google step's cookie and
    // grants nothing on its own.
    if (result.purpose === "invite") return new Response(null,{ status: 303,headers: { location: `/signup#oidc=${encodeURIComponent(result.id)}`,...cookie } })
    return new Response(null, { status: 303, headers: { location: `/auth/oidc/result?result=${encodeURIComponent(result.id)}&purpose=${result.purpose}${result.next ? `&next=${encodeURIComponent(result.next)}` : ""}`,...cookie } })
  }) },
  accountBrowser("POST", "/api/auth/oidc/google/result", async rc => {
    const { result: id, purpose } = await accountBody(rc, z.strictObject({ result: z.string().max(128), purpose: OidcPurpose })), result = await readOidcResult(rc.env, id, oidcCookieToken(rc.request, purpose), purpose)
    if (purpose === "link" || purpose === "gate") {
      const account = await requireAccount(rc)
      if (result.account !== account.account || result.session !== account.session || result.security_epoch !== account.securityEpoch) throw oidcRefusal("account_mismatch", purpose)
    }
    if (purpose === "signin" && !await identityForResult(rc.env, result)) throw oidcRefusal("no_linked_identity", purpose)
    return json({ purpose, identity: { provider: "google", email: result.email, subject: result.subject, name: result.name }, workspace: result.workspace })
  }),
  accountBrowser("POST","/api/auth/oidc/google/gate",async rc => {
    const account = await requireAccount(rc),{ result: id } = await accountBody(rc,z.strictObject({ result: z.string().max(128) })),result = await readOidcResult(rc.env,id,oidcCookieToken(rc.request,"gate"),"gate")
    await finishWorkspaceGate(rc.env,account,result)
    return json({ verified: true })
  }),
  accountBrowser("POST", "/api/account/identities/link", async rc => {
    const account = await requireAccount(rc), body = await accountBody(rc, z.strictObject({ result: z.string().max(128), email: z.email(), subject: z.string().max(255) })), result = await readOidcResult(rc.env, body.result, oidcCookieToken(rc.request, "link"), "link")
    await finishOidcLink(rc.env, account, result, body)
    return json({ linked: true })
  }),
  accountBrowser("POST","/api/account/identities/:id/unlink",async rc => {
    const account = await requireAccount(rc),{ stepUp } = await accountBody(rc,z.strictObject({ stepUp: StepUpAssertionProofSchema })),identity = rc.params.id ?? ""
    if (!await rc.env.DB.prepare("SELECT id FROM oidc_identities WHERE id=? AND account=?").bind(identity,account.account).first()) throw new VaultError("not_found","No such identity.")
    const evidence = await requireAccountStepUp(rc,account,"-",{ type: "identity.unlink",provider: "google",identity },stepUp)
    const transition = await reserveAccountSecurity(rc.env,account.account,{ effect: { kind: "identity.unlink",identity,session: account.session,invalidation: crypto.randomUUID() },revokedSessionIds: [],removedFactorIds: [],authorisingFactor: evidence.factor,session: { id: account.session,epoch: account.securityEpoch } })
    return json({ pending: await retryAccountSecurity(rc.env,transition) !== null })
  }),
  accountBrowser("GET", "/api/account/identities", async rc => {
    const account = await requireAccount(rc), identities = await rc.env.DB.prepare("SELECT id,provider,email,domain,name,linked_at AS linkedAt,last_verified_at AS lastVerifiedAt FROM oidc_identities WHERE account=? ORDER BY linked_at,id").bind(account.account).all()
    return json({ identities: identities.results })
  }),
]

export const workspaceOidcRoutes: Route<WorkspaceHandler>[] = [
  { method: "GET",path: "/identity",handler: async (rc,workspace) => json(await oidcIdentityContext(rc.env,workspace.workspace.id,workspace.account.account)) },
  { method: "POST",path: "/identity-rule",handler: async (rc,workspace) => {
    if (!oidcConfigured(rc.env)) throw oidcRefusal("not_configured","gate")
    const { rule,stepUp } = await accountBody(rc,z.strictObject({ rule: IdentityRuleSchema,stepUp: StepUpAssertionProofSchema })),action = { type: "workspace.identity_rule",rule } as const
    const evidence = await requireWorkspaceStepUp(rc,workspace,action,stepUp)
    return json(await workspaceCall(rc,workspace,"access.identity_rule",{ rule },evidence))
  } },
]
