// The policy ops a workspace serves. Standing rules (rul_, behind
// POLICY_RULES) are policy-rules-workspace.ts's; the legacy widening window
// is gone, and its ops answer as they did while it was off: preview, propose
// and approve of a window refuse, and a window's proposal, deny or stop
// names nothing a workspace holds.

import type { PolicyContext } from "@mehen/protocol/policy-mode"
import { z } from "zod"
import { VaultError } from "../../http.ts"
import { can } from "../access.ts"
import { one, type Area, type VaultContext } from "../core.ts"
import { accessState, authorise, registerOpenAskCounter } from "./workspace-runtime.ts"
import { registerWorkspacePendingProvider } from "./pending-workspace.ts"
import { parseOpInput } from "./approvals.ts"
import { items } from "./items.ts"
import { policy, guardDigest, itemPolicyFloor, policyHelpNext } from "./policy.ts"
import { policyRulesOn, ruleProposalOps, ruleProposalRow, ruleProposalsPending, workspacePolicyRuleOps } from "./policy-rules-workspace.ts"

// policy_proposals' workspace columns: rule proposals read ask and lineage;
// workspace_view held a window proposal's view and is no longer written.
export const WORKSPACE_POLICY_MIGRATION = `ALTER TABLE policy_proposals ADD COLUMN ask TEXT;
ALTER TABLE policy_proposals ADD COLUMN workspace_view TEXT;
ALTER TABLE policy_proposals ADD COLUMN lineage TEXT;`
function disabled(): never { throw new VaultError("forbidden", "Policy widening is not available yet.", { next: policyHelpNext }) }
// A standing rule's body names where it comes from; a legacy window's never does.
const ruleBody = (raw: unknown): boolean => typeof raw === "object" && raw !== null && "from" in raw
const IdInput = z.object({ id: z.string().max(64) })
const isRuleProposal = (ctx: VaultContext, raw: unknown): boolean => {
  const parsed = IdInput.safeParse(raw)
  return parsed.success && ruleProposalRow(ctx, parsed.data.id) !== null
}
const rulePreview = workspacePolicyRuleOps["policy.rules.preview"]!, rulePropose = workspacePolicyRuleOps["policy.rules.propose"]!
export const workspacePolicyOps: NonNullable<Area["workspaceOps"]> = {
  ...workspacePolicyRuleOps,
  "policy.preview": { auth: ["account", "device"], handler: (ctx, principal, raw, invocation) => ruleBody(raw) ? rulePreview.handler(ctx, principal, raw, invocation) : disabled() },
  "policy.propose": { auth: ["account", "device"], handler: (ctx, principal, raw, invocation) => ruleBody(raw) ? rulePropose.handler(ctx, principal, raw, invocation) : disabled() },
  "policy.approve": { auth: ["account"], handler: disabled },
  // The device side of a proposal (/v1/policy/state, cancel, a grant's
  // revoke) answers as preview and propose do while widening is off.
  "policy.state": { auth: ["device"], handler: disabled },
  "policy.cancel": { auth: ["device"], handler(ctx, principal, raw, invocation) {
    if (!isRuleProposal(ctx, raw) || principal.kind === "system") disabled()
    return ruleProposalOps.cancel(ctx, principal, parseOpInput(z.strictObject({ id: z.string().max(64) }), raw).id, invocation)
  } },
  "policy.revoke-grant": { auth: ["device"], handler: disabled },
  "policy.context": { auth: ["account", "device"], handler(ctx, principal, raw, invocation): PolicyContext {
    const parsed = parseOpInput(z.strictObject({ item: z.string().max(64), device: z.string().max(64).optional(), session: z.string().nullable().optional() }), raw)
    const input = { ...parsed, device: parsed.device ?? (principal.kind === "device" ? principal.deviceId : ""), session: parsed.session ?? null }
    const item = items.getItem(ctx, input.item)
    if (!item) throw new VaultError("not_found", "No such object.")
    if (principal.kind === "system" || principal.kind === "device" && principal.deviceId !== input.device) throw new VaultError("not_found", "No such object.")
    authorise(ctx, invocation, { type: "item.read" }, { credential: item.id }, ctx.now())
    if (principal.kind === "member") authorise(ctx, invocation, { type: "devices.read" }, { device: input.device }, ctx.now())
    const state = accessState(ctx)
    const asker = principal.kind === "device" && principal.workload !== undefined ? { workload: principal.workload } : {}
    if (!state.devices.some((d) => d.id === input.device && d.status === "active") || !can(state, { kind: "device", deviceId: input.device, ...asker }, { type: "item.read" }, { credential: item.id }, ctx.now()).allowed) throw new VaultError("not_found", "No such object.")
    const snapshot = policy.snapshot(ctx, input.device, item)
    return { item: item.slug, selector: { device: input.device, session: input.session, ...asker }, baseMode: "standard", effectiveMode: "standard", basePolicy: item.policy, floor: itemPolicyFloor(item), snapshot, baseDigest: guardDigest(snapshot), slotRevision: 0, predecessor: null, state: { widening: [], observedAt: new Date(ctx.now()).toISOString() } }
  } },
  "policy.status": { auth: ["account", "device"], handler(ctx, principal, raw, invocation) {
    if (principal.kind !== "system" && isRuleProposal(ctx, raw)) {
      const input = parseOpInput(z.strictObject({ id: z.string().max(64), wait: z.boolean().optional() }), raw)
      return ruleProposalOps.status(ctx, principal, input.id, input.wait === true, invocation)
    }
    // With standing rules on, an id that names no rule proposal is a typo,
    // another workspace's or one purged: not a switched-off feature.
    if (principal.kind === "device" && policyRulesOn(ctx.env, ctx.tenant)) {
      throw new VaultError("not_found", "No such policy proposal.", { next: { command: "mehen pending", say: "No such policy proposal in this workspace; mehen pending lists this machine's open asks, in every workspace." } })
    }
    if (principal.kind === "device") disabled()
    if (principal.kind === "system") throw new VaultError("not_found", "No such object.")
    parseOpInput(z.strictObject({ id: z.string().max(64) }), raw)
    authorise(ctx, invocation, { type: "asks.read" }, {}, ctx.now())
    throw new VaultError("not_found", "No such object.")
  } },
  "policy.action": { auth: ["account"], handler(ctx, _principal, raw, invocation) {
    if (isRuleProposal(ctx, raw)) return ruleProposalOps.action(ctx, raw, invocation)
    const input = parseOpInput(z.strictObject({ id: z.string().max(64), decision: z.enum(["approve", "deny"]) }), raw)
    if (input.decision === "approve") disabled()
    throw new VaultError("not_found", "No such object.")
  } },
  "policy.decide": { auth: ["account"], handler(ctx, principal, raw, invocation) {
    if (principal.kind !== "system" && isRuleProposal(ctx, raw)) return ruleProposalOps.decide(ctx, principal, raw, invocation)
    const input = parseOpInput(z.strictObject({ id: z.string().max(64), decision: z.enum(["approve", "deny"]) }), raw)
    if (input.decision === "approve") disabled()
    if (principal.kind !== "member") throw new VaultError("forbidden", "Only a person can deny a proposal.")
    throw new VaultError("not_found", "No such object.")
  } },
  // A window's stop: no workspace holds a window.
  "policy.stop": { auth: ["account", "device"], handler(ctx, principal, raw) {
    if (principal.kind === "system") throw new VaultError("not_found", "No such object.")
    parseOpInput(z.strictObject({ id: z.string().max(64) }), raw)
    throw new VaultError("not_found", "No such object.")
  } },
}
registerOpenAskCounter("policy", (ctx, device, now) => one(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM policy_proposals WHERE device=? AND status='pending' AND expires_at>?", device, now))?.count ?? 0)
registerWorkspacePendingProvider("policy", ruleProposalsPending)
