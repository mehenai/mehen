import { z } from "zod"
import { PolicyDecideSchema, PolicyRuleDecisionSchema, PolicyRuleExtendSchema } from "@mehen/protocol/policy-mode"
import { WorkspaceStepUpActionSchema } from "@mehen/protocol"
import { json, parseJson, readBody } from "../http.ts"
import type { Route } from "../router.ts"
import { requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import { StepUpProofSchema } from "@mehen/protocol/step-up-proof"
import { policyRulesOn } from "../vault/areas/policy-rules-workspace.ts"
import { workspaceCall } from "./context.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"
function jsonOrNull(bytes: Uint8Array): unknown {
  try { return JSON.parse(new TextDecoder().decode(bytes)) } catch { return null }
}
const RuleDecide = z.union([
  z.strictObject({ decision: z.literal("approve"), effective: z.strictObject({ path: z.string(), ttlSeconds: z.number() }), stepUp: StepUpProofSchema }),
  z.strictObject({ decision: z.literal("deny"), stepUp: StepUpProofSchema }),
])
export const workspacePolicyRoutes: Route<WorkspaceHandler>[] = [
  { method: "GET", path: "/policy/context", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "policy.context", { item: rc.url.searchParams.get("item"), device: rc.url.searchParams.get("device"), session: rc.url.searchParams.get("session") })) },
  { method: "GET", path: "/policy/proposals/:id", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "policy.status", { id: rc.params.id })) },
  // With standing rules on, a rule's decision names its effective path and
  // duration; a legacy window's names an effectiveChange (or, for an action,
  // nothing). A decide in a rule's shape is marked kind "rule", which the
  // vault accepts only for a rule's proposal.
  { method: "POST", path: "/policy/proposals/:id/action", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "policy.action", { id: rc.params.id, ...parseJson(policyRulesOn(rc.env, ws.workspace.id) ? z.union([z.strictObject({ decision: z.enum(["approve", "deny"]) }), PolicyRuleDecisionSchema]) : z.strictObject({ decision: z.enum(["approve", "deny"]) }), await readBody(rc.request)) })) },
  { method: "POST", path: "/policy/proposals/:id/decide", handler: async (rc, ws) => {
    const body = await readBody(rc.request)
    const rule = policyRulesOn(rc.env, ws.workspace.id) ? RuleDecide.safeParse(jsonOrNull(body)) : null
    if (rule?.success) {
      const { stepUp, ...decision } = rule.data
      const input = { id: rc.params.id, kind: "rule", ...decision }
      const expected = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "policy.action", input))
      const evidence = await requireWorkspaceStepUp(rc, ws, expected, stepUp)
      return json(await workspaceCall(rc, ws, "policy.decide", input, evidence))
    }
    const { stepUp, decision } = parseJson(PolicyDecideSchema, body)
    const input = { id: rc.params.id, decision }
    const expected = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "policy.action", input))
    const evidence = await requireWorkspaceStepUp(rc, ws, expected, stepUp)
    return json(await workspaceCall(rc, ws, "policy.decide", input, evidence))
  } },
  { method: "GET", path: "/policy/rules", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "policy.rules", Object.fromEntries(rc.url.searchParams))) },
  { method: "POST", path: "/policy/rules/:id/revoke", handler: async (rc, ws) => {
    parseJson(z.strictObject({}), await readBody(rc.request))
    return json(await workspaceCall(rc, ws, "policy.rules.revoke", { id: rc.params.id }))
  } },
  { method: "POST", path: "/policy/rules/:id/extend/action", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "policy.rules.extend-action", { id: rc.params.id, ...parseJson(PolicyRuleExtendSchema, await readBody(rc.request)) })) },
  { method: "POST", path: "/policy/rules/:id/extend/decide", handler: async (rc, ws) => {
    const { stepUp, ...extend } = parseJson(PolicyRuleExtendSchema.extend({ stepUp: StepUpProofSchema }), await readBody(rc.request))
    const input = { id: rc.params.id, ...extend }
    const expected = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "policy.rules.extend-action", input))
    const evidence = await requireWorkspaceStepUp(rc, ws, expected, stepUp)
    return json(await workspaceCall(rc, ws, "policy.rules.extend", input, evidence))
  } },
  { method: "POST", path: "/policy/overrides/:id/revoke", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "policy.stop", { id: rc.params.id })) },
  ...(["preview", "proposals"] as const).map((path): Route<WorkspaceHandler> => ({ method: "POST", path: `/policy/${path}`, handler: async (rc, ws) => json(await workspaceCall(rc, ws, path === "preview" ? "policy.preview" : "policy.propose", parseJson(z.record(z.string(), z.unknown()), await readBody(rc.request)))) })),
]
