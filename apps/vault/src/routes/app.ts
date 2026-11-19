// Native workspace gates and exact decisions use app bearers, never cookies.
import { assertWorkspaceSessionGate, startWorkspaceGate, redeemAppGateCode } from "../directory/oidc-flow.ts"
import { accountInbox } from "../directory/account-inbox.ts"
import { sha256Text as appSessionHash } from "../directory/session.ts"
import { AppGateStartSchema, AppGateRedeemSchema, WorkspaceStepUpActionSchema, type WorkspacePendingAsk } from "@mehen/protocol"
import { WorkspaceApprovalDecisionInput } from "../vault/areas/approvals-workspace.ts"
import { requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import { StepUpProofSchema } from "@mehen/protocol/step-up-proof"
import { requireAppAccount } from "./account-app.ts"
import { workspaceCall, type WorkspaceRequest, type RequestContext, type Handler } from "./context.ts"
import { VaultError, json, parseJson, readBody } from "../http.ts"
import type { Route } from "../router.ts"

// Fresh-schema native routes never use the legacy cookie/member dispatcher.
export const workspaceAppRoutes: Route<Handler>[] = [
  { method: "POST",path: "/app/v1/gate/start",handler: async rc => {
    const account = await requireAppAccount(rc),body = parseJson(AppGateStartSchema,await readBody(rc.request)),workspace = await resolveAppWorkspace({ ...rc,params: { ...rc.params,ws: body.workspace } },true)
    const check = await rc.env.AUTH_RATE_LIMITER?.limit({ key: `oidc:${account.account}` })
    if (!check?.success) throw new VaultError("rate_limited","Too many Google verification attempts. Try again shortly.",{ retryAfter: 60 })
    const start = await startWorkspaceGate(rc.env,account,workspace.workspace.id,{ app: { sessionHash: await appSessionHash(rc.request.headers.get("authorization")!.slice(7)),challenge: body.pkceChallenge } })
    return json({ url: start.url })
  } },
  { method: "POST",path: "/app/v1/gate",handler: async rc => {
    const account = await requireAppAccount(rc),body = parseJson(AppGateRedeemSchema,await readBody(rc.request))
    await redeemAppGateCode(rc.env,account,await appSessionHash(rc.request.headers.get("authorization")!.slice(7)),body.code,body.verifier)
    return json({ verified: true })
  } },
  // The account inbox through the app's bearer: `pending` keeps today's
  // shape (every ask item's ask), `notices` the same envelopes, `inbox` and
  // `truncated` are additive. No partial aggregate: a covered workspace
  // without an app gate, or a workspace that could not be read, refuses the
  // whole read, as it always has; this shape has no way to say a workspace
  // is missing. `truncated` says a workspace's list was cut to its bounds.
  { method: "GET",path: "/app/v1/pending",handler: async rc => {
    const { inbox,gateRefusal,unreadable } = await accountInbox(rc,await requireAppAccount(rc),{ sessionKind: "app" })
    if (gateRefusal) throw gateRefusal
    if (unreadable) throw unreadable
    const pending: WorkspacePendingAsk[] = inbox.items.flatMap(item => item.kind === "ask" ? [item.ask] : [])
    return json({ pending,notices: inbox.notices,inbox: inbox.items,truncated: inbox.workspaces.some(w => w.truncated) })
  } },
  { method: "GET",path: "/app/v1/w/:ws/approvals/:id",handler: async rc => json(await workspaceCall(rc,await resolveAppWorkspace(rc),"approvals.view",{ id: rc.params.id })) },
  { method: "POST",path: "/app/v1/w/:ws/approvals/:id/decide",handler: async rc => {
    const workspace = await resolveAppWorkspace(rc),{ stepUp,...terms } = parseJson(WorkspaceApprovalDecisionInput.omit({ id: true,surface: true }).extend({ stepUp: StepUpProofSchema }),await readBody(rc.request))
    if (terms.remember !== undefined) throw new VaultError("forbidden","Remembered approvals need the vault page, not the app route.")
    const input = { id: rc.params.id,...terms,surface: "app" as const },expected = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc,workspace,"approvals.action",input))
    const evidence = await requireWorkspaceStepUp(rc,workspace,expected,stepUp)
    return json(await workspaceCall(rc,workspace,"approvals.decide",input,evidence))
  } },
]
export async function resolveAppWorkspace(rc: RequestContext,allowUngated = false): Promise<WorkspaceRequest> {
  const account = await requireAppAccount(rc)
  const row = await rc.env.DB.prepare("SELECT w.id,w.slug,w.name,m.id AS membership FROM workspaces w JOIN memberships m ON m.workspace=w.id WHERE m.account=? AND m.state='member' AND w.status='active' AND (w.slug=? OR w.id=? OR EXISTS (SELECT 1 FROM workspace_slugs s WHERE s.workspace=w.id AND s.slug=?))").bind(account.account,rc.params.ws,rc.params.ws,rc.params.ws).first<{ id: string; slug: string; name: string; membership: string }>()
  if (!row) throw new VaultError("not_found","No such workspace.")
  if (!allowUngated) await assertWorkspaceSessionGate(rc.env,account,row,"app")
  return { workspace: { id: row.id,slug: row.slug,name: row.name },membership: row.membership,account,sessionKind: "app" }
}
