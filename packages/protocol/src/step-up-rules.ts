// What a member may still sign during a cooling-off:
// after a recovery code, a reset link or a break-glass link, for
// RESTRICTION_MS, a member may read and narrow but not widen. Every step-up
// is a passkey; this table only says which of them a restricted member may
// sign. It is a Record over every action type, so a new action does not
// compile until someone decides here whether it narrows or widens.

import type { StepUpActionInput } from "./api.ts"

// One cooling-off for recovery, reset and break-glass alike.
export const RESTRICTION_MS = 24 * 3_600_000

export type StepUpActionType = StepUpActionInput["type"]

type Verdict = "allowed" | "refused"
type Rule<A> = Verdict | ((action: A) => Verdict)

export const WHILE_RESTRICTED: { readonly [T in StepUpActionType]: Rule<Extract<StepUpActionInput, { type: T }>> } = {
  // Deny narrows; approve spends a credential.
  "approval.decide": (action) => (action.decision === "deny" ? "allowed" : "refused"),
  "policy.decide": (action) => (action.decision === "deny" ? "allowed" : "refused"),
  "device.revoke": "allowed",
  // The defender's tool. Who may resolve is checked where the notice is
  // resolved: a passkey older than the notice, or another unrestricted owner.
  "recovery.resolve": "allowed",
  "intake.submit": "refused",
  "enrol.approve": "refused",
  // A new scope may widen what a machine can use; revoking it is the narrow way.
  "device.rescope": "refused",
  "item.update": "refused",
  "item.reveal": "refused",
  "item.delete": "refused",
  "invite.create": "refused",
  "tenant.unfreeze": "refused",
  "passkey.add": "refused",
  "passkey.remove": "refused",
  "recovery.generate": "refused",
  "member.reset": "refused",
  "member.remove": "refused",
  "member.confirm": "refused",
}

export function allowedWhileRestricted(action: StepUpActionInput): boolean {
  const rule = WHILE_RESTRICTED[action.type] as Rule<StepUpActionInput>
  return (typeof rule === "function" ? rule(action) : rule) === "allowed"
}

// Empty tag/project filters denote the universe, not the empty set.
// workloads: "required" is narrower than "allowed", and absent means "allowed".
// serviceRuns: absent means false, and granting it widens.
import type { WorkspaceDeviceScope, WorkspaceStepUpAction } from "./workspace.ts"
export function effectiveFilterSubset(after: readonly string[], before: readonly string[]): boolean {
  return before.length === 0 || (after.length !== 0 && after.every((s) => before.includes(s)))
}
export function scopeChangeIsNarrowing(before: WorkspaceDeviceScope, after: WorkspaceDeviceScope): boolean {
  return effectiveFilterSubset(after.tags, before.tags) && effectiveFilterSubset(after.projects, before.projects)
    && after.modes.every((m) => before.modes.includes(m))
    && (before.maxEnvironment === "protected" || after.maxEnvironment === "unprotected")
    && (!after.privateCredentials || before.privateCredentials)
    && (after.workloads === "required" || before.workloads !== "required")
    && (!after.serviceRuns || before.serviceRuns === true)
}
export const WORKSPACE_WHILE_RESTRICTED: Record<WorkspaceStepUpAction["type"], "allowed" | "refused" | "decide" | "scope"> = {
  "workspace.create": "refused", "workspace.update": "refused", "workspace.identity_rule": "refused", "workspace.delete": "refused", "workspace.delete_cancel": "refused", "workspace.unfreeze": "refused",
  "member.invite": "refused", "member.confirm": "refused", "member.role": "refused", "member.suspend": "refused", "member.reinstate": "refused", "member.remove": "refused", "member.leave": "refused", "account.delete": "refused",
  "identity.link": "refused", "identity.unlink": "refused", "team.update": "refused", "team.members": "refused", "project.create": "refused", "project.share": "refused", "project.configure": "refused", "project.delete": "refused", "override.set": "refused", "item.rehome": "refused", "connect.start": "refused", "enrol.accept": "refused", "enrol.approve": "refused", "device.rescope": "scope", "device.rescope_accept": "refused", "device.rescope_reject": "allowed", "device.revoke": "allowed", "workload.revoke": "allowed", "approval.decide": "decide", "policy.decide": "decide", "item.update": "refused", "item.delete": "refused", "item.restore": "refused", "item.push": "refused", "intake.submit": "refused", "adoption.approve": "refused", "passkey.add": "refused", "passkey.remove": "refused", "recovery.generate": "refused", "recovery.resolve": "allowed", "platform.operate": "refused", "platform.administer": "refused", "operator.propose": "refused", "operator.approve": "refused", "operator.accept": "refused", "operator.break_glass_link": "refused",
  // A new backup recipient can receive every exported value; removing one narrows.
  "backup.recipient_add": "refused", "backup.recipient_remove": "allowed",
  // A batch narrows only when every entry denies.
  "approval.decide_many": "decide",
  // Back to ask narrows; routine and trust widen.
  "item.posture": "decide",
  // A mandate lets a machine carry on without asking; pausing and stopping
  // one need no step-up.
  "mandate.sign": "refused", "mandate.resume": "refused",
  // Only asking less is signed; asking more needs no step-up.
  "workspace.approvals": "refused",
}
export function workspaceAllowedWhileRestricted(action: WorkspaceStepUpAction): boolean {
  const rule = WORKSPACE_WHILE_RESTRICTED[action.type]
  if (rule === "allowed") return true
  if ((action.type === "approval.decide" || action.type === "policy.decide") && action.decision === "deny") return true
  if (action.type === "approval.decide_many") return action.entries.every((entry) => entry.decision === "deny")
  if (action.type === "item.posture") return action.level === "ask"
  return action.type === "device.rescope" && scopeChangeIsNarrowing(action.before, action.after)
}

// After a real passkey confirmation, a browser session may confirm further
// actions for STEP_UP_GRACE_MS without asking for the passkey again.
// An action is graced only when the canonical
// action itself shows it cannot widen who can act, how someone proves who
// they are, what a credential is exposed to, or relax a protection; an
// opaque digest is fresh. "fresh" always asks, whatever the window. A
// Record over every action type, so a new action does not compile until
// someone decides here whether it may ride a window.
export const STEP_UP_GRACE_MS = 15 * 60_000
type Grace = "graced" | "fresh"
export const WORKSPACE_STEP_UP_GRACE: { readonly [T in WorkspaceStepUpAction["type"]]: Grace | ((action: Extract<WorkspaceStepUpAction, { type: T }>) => Grace) } = {
  "passkey.add": "fresh", "passkey.remove": "fresh", "recovery.generate": "fresh", "recovery.resolve": "fresh", "identity.link": "fresh", "identity.unlink": "fresh", "account.delete": "fresh",
  "workspace.delete": "fresh", "workspace.delete_cancel": "fresh", "workspace.identity_rule": "fresh", "workspace.unfreeze": "fresh",
  "member.invite": "fresh", "member.confirm": "fresh", "member.role": "fresh", "member.remove": "fresh", "member.suspend": "fresh", "member.reinstate": "fresh",
  "team.members": "fresh", "project.share": "fresh", "project.configure": "fresh", "project.delete": "fresh", "override.set": "fresh",
  // One digest over project environment protection and fences, or a
  // credential's policy, exposure and binding: nothing to tell a narrowing by.
  "item.update": "fresh", "item.rehome": "fresh",
  "backup.recipient_add": "fresh", "backup.recipient_remove": "fresh", "enrol.approve": "fresh", "enrol.accept": "fresh",
  "device.rescope_accept": "fresh",
  "platform.operate": "fresh", "platform.administer": "fresh", "operator.propose": "fresh", "operator.approve": "fresh", "operator.accept": "fresh", "operator.break_glass_link": "fresh",
  "device.rescope": (action) => (scopeChangeIsNarrowing(action.before, action.after) ? "graced" : "fresh"),
  // A remembered approval makes a standing rule.
  "approval.decide": (action) => (action.remember === undefined ? "graced" : "fresh"),
  // Approving makes or extends a rule, a task grant or a co-signature.
  "policy.decide": (action) => (action.decision === "deny" ? "graced" : "fresh"),
  // Routine and trust let covered requests through without asking.
  "item.posture": (action) => (action.level === "ask" ? "graced" : "fresh"),
  "approval.decide_many": "graced",
  // item.delete destroys a value and its history but widens nothing: a recorded residual risk.
  "item.push": "graced", "item.restore": "graced", "item.delete": "graced",
  // A repoint rebinds project variables, which their own path signs as item.update.
  "adoption.approve": (action) => (action.repoints === 0 ? "graced" : "fresh"),
  "intake.submit": "graced", "connect.start": "graced",
  "project.create": "graced", "team.update": "graced", "member.leave": "graced",
  "device.revoke": "graced", "device.rescope_reject": "graced", "workload.revoke": "graced",
  // access.workspace_update changes the name and slug only.
  "workspace.update": "graced", "workspace.create": "graced",
  // Signing lets a machine carry on without asking, new trust every time.
  // A resume brings back the exact terms and revision already signed: after
  // an owner's or admin's pause, a relaxing the signer had already chosen;
  // after a trip (a runaway machine) or a lapse (an account recovered, a
  // role changed), a protection relaxed.
  "mandate.sign": "fresh", "mandate.resume": (action) => (action.from === "paused" ? "graced" : "fresh"),
  // Asking less lets agents carry on without a person, workspace-wide.
  "workspace.approvals": "fresh",
}
export function workspaceStepUpGraced(action: WorkspaceStepUpAction): boolean {
  const rule = WORKSPACE_STEP_UP_GRACE[action.type] as Grace | ((action: WorkspaceStepUpAction) => Grace)
  return (typeof rule === "function" ? rule(action) : rule) === "graced"
}
