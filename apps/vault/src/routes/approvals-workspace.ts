import { canonicalJson, WorkspaceStepUpActionSchema, type ApprovalViewProjection } from "@mehen/protocol"
import { sendPushes } from "./push.ts"
import { json, parseJson, readBody } from "../http.ts"
import type { Route } from "../router.ts"
import { requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import { etagMatches } from "../directory/account-inbox.ts"
import { sha256Text } from "../directory/session.ts"
import { workspaceCall } from "./context.ts"
import { WorkspaceApprovalDecisionInput } from "../vault/areas/approvals-workspace.ts"
import { ApprovalBatchDecisions } from "../vault/areas/approvals-batch-workspace.ts"
import { StepUpProofSchema } from "@mehen/protocol/step-up-proof"
import type { WorkspaceHandler } from "./workspace-prefix.ts"
// A group's validator: the Review together page boots with it, so its
// first poll is a 304 while nothing changed.
export async function approvalGroupEtag(view: unknown): Promise<string> {
  return `W/"${await sha256Text(canonicalJson(view))}"`
}
export const workspaceApprovalsRoutes: Route<WorkspaceHandler>[] = [
  // Review together polls this with If-None-Match; never cached.
  { method: "GET", path: "/approvals/groups/:id", handler: async (rc, ws) => {
    const view = await workspaceCall(rc, ws, "approvals.group", { id: rc.params.id })
    const etag = await approvalGroupEtag(view), headers = { "cache-control": "no-store", etag }
    if (etagMatches(rc.request.headers.get("if-none-match"), etag)) return new Response(null, { status: 304, headers })
    return json(view, 200, headers)
  } },
  { method: "POST", path: "/approval-batch/action", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "approvals.action_many", parseJson(ApprovalBatchDecisions, await readBody(rc.request)))) },
  { method: "POST", path: "/approval-batch/decide", handler: async (rc, ws) => {
    const { stepUp, ...input } = parseJson(ApprovalBatchDecisions.extend({ stepUp: StepUpProofSchema }), await readBody(rc.request))
    const expected = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "approvals.action_many", input))
    const evidence = await requireWorkspaceStepUp(rc, ws, expected, stepUp)
    return json(await workspaceCall(rc, ws, "approvals.decide_many", input, evidence))
  } },
  { method: "GET", path: "/approvals/:id", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "approvals.view", { id: rc.params.id })) },
  { method: "POST", path: "/approvals/:id/action", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "approvals.action", { id: rc.params.id, ...parseJson(WorkspaceApprovalDecisionInput.omit({ id: true, surface: true }), await readBody(rc.request)) })) },
  { method: "POST", path: "/approvals/:id/decide", handler: async (rc, ws) => {
    const { stepUp, ...terms } = parseJson(WorkspaceApprovalDecisionInput.omit({ id: true, surface: true }).extend({ stepUp: StepUpProofSchema }), await readBody(rc.request))
    const input = { id: rc.params.id, ...terms }
    const expected = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "approvals.action", input))
    const evidence = await requireWorkspaceStepUp(rc, ws, expected, stepUp)
    const decided = (await workspaceCall(rc, ws, "approvals.decide", input, evidence)) as ApprovalViewProjection
    // An approved push is sent now, and the page waits a while to say how it went.
    if (decided.view !== "detail" || decided.approval.push?.state !== "queued") return json(decided)
    await sendPushes(rc.ctx, rc.env, ws.workspace.id, [{ approval: decided.approval.approval }])
    return json(await workspaceCall(rc, ws, "approvals.view", { id: rc.params.id }))
  } },
]
