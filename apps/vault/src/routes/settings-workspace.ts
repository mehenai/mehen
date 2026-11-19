// GET /api/w/:ws/settings: whether the workspace is frozen, how often it
// asks, and what the caller may change on its settings page. The writes
// stay where they were: POST /settings (workspaces.ts),
// /freeze (system.ts) and /unfreeze (workspace-devices.ts), each with its
// guard. POST /settings/approvals moves the approval dial: a change that
// asks less carries a passkey over workspace.approvals with both levels,
// which the vault checks against its own level; one that asks more none.
import { StepUpProofSchema } from "@mehen/protocol/step-up-proof"
import { WorkspaceApprovalsChangeSchema, WorkspaceApprovalsChangedSchema, WorkspaceSettingsViewSchema, approvalDialAsksLess } from "@mehen/protocol/workspace"
import { requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import { json } from "../http.ts"
import type { Route } from "../router.ts"
import { accountBody } from "./account.ts"
import { workspaceCall } from "./context.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"

export const workspaceSettingsRoutes: Route<WorkspaceHandler>[] = [
  { method: "GET", path: "/settings", handler: async (rc, ws) => json(WorkspaceSettingsViewSchema.parse(await workspaceCall(rc, ws, "access.settings")), 200, { "cache-control": "no-store" }) },
  {
    method: "POST", path: "/settings/approvals", handler: async (rc, ws) => {
      const { stepUp, ...change } = await accountBody(rc, WorkspaceApprovalsChangeSchema.extend({ stepUp: StepUpProofSchema.optional() }))
      const evidence = approvalDialAsksLess(change.before, change.after) ? await requireWorkspaceStepUp(rc, ws, { type: "workspace.approvals", ...change }, stepUp) : undefined
      return json(WorkspaceApprovalsChangedSchema.parse(await workspaceCall(rc, ws, "access.approvals", change, evidence)))
    },
  },
]
