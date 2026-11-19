// The workspace settings read: whether the workspace is frozen, how often
// it asks (the approval dial) and what the signed-in member may change on
// its settings page. Each right is the one evaluator's answer for the action
// the page would send, so the page draws controls by right, never by role,
// and the write routes keep their guards. access.approvals changes the dial
// (approval-dial-workspace.ts).
import { WorkspaceSettingsViewSchema, type WorkspaceApprovalsView } from "@mehen/protocol/workspace"
import type { Area } from "../core.ts"
import { can } from "../access.ts"
import { VaultError } from "../../http.ts"
import { approvalDialView, setApprovalDial } from "./approval-dial-workspace.ts"
import { authorise, eligibilityState, setting } from "./workspace-runtime.ts"

const withApprovals = (approvals: WorkspaceApprovalsView | undefined) => (approvals === undefined ? {} : { approvals })

export const settingsArea: Area = {
  name: "settings",
  migrations: [],
  workspaceOps: {
    // Refused as reading the activity is (a removed, suspended or
    // identity-gated caller); otherwise every member, guests included,
    // reads it, and a guest's rights are all false.
    "access.settings": { auth: ["account"], handler(ctx, _p, _raw, invocation) {
      const now = ctx.now()
      const { principal } = authorise(ctx, invocation, { type: "audit.read" }, {}, now)
      const state = eligibilityState(ctx, invocation)
      const allowed = (type: "workspace.update" | "workspace.freeze" | "workspace.unfreeze") => can(state, principal, { type }, {}, now).allowed
      return WorkspaceSettingsViewSchema.parse({ frozen: setting(ctx, "frozen", false), rights: { rename: allowed("workspace.update"), freeze: allowed("workspace.freeze"), unfreeze: allowed("workspace.unfreeze") }, ...withApprovals(approvalDialView(ctx, state, principal, now)) })
    } },
    "access.approvals": { auth: ["account"], handler: (ctx, p, raw, invocation) => { if (p.kind === "system") throw new VaultError("forbidden", "System calls have no member authority."); return setApprovalDial(ctx, p, raw, invocation) } },
  },
}
