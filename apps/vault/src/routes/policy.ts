import { z } from "zod"
import { PolicyAreaProposalSchema, PolicyDecideSchema, PolicyPreviewRequestSchema, PolicyProposeSchema, PolicyRuleProposalSchema, PolicySelectorSchema, POLICY_REQUEST_LIMIT, type PolicyProposalView } from "@mehen/protocol/policy-mode"
import { VaultError, json, parseJson } from "../http.ts"
import type { Route } from "../router.ts"
import { policyHelpNext } from "../vault/areas/policy.ts"
import { policyRulesOn } from "../vault/areas/policy-rules-workspace.ts"
import { type Handler, deviceRequest } from "./context.ts"

const Empty = z.strictObject({})
function parsePolicyJson<T extends z.ZodType>(schema: T, bytes: Uint8Array): z.infer<T> {
  try { return parseJson(schema, bytes) }
  catch (error) {
    if (error instanceof VaultError) throw new VaultError(error.code, error.message, { ...error.extra, next: policyHelpNext })
    throw error
  }
}
function namesKey(bytes: Uint8Array, key: string): boolean {
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(bytes))
    return typeof value === "object" && value !== null && !Array.isArray(value) && key in value
  } catch { return false }
}
const deviceRoutes: Route<Handler>[] = [
  { method: "GET", path: "/v1/policy/context", handler: async (rc) => {
    const query = parsePolicyJson(z.strictObject({ item: z.string() }), new TextEncoder().encode(JSON.stringify(Object.fromEntries(rc.url.searchParams))))
    const device = await deviceRequest(rc)
    return json(await device.call("policy.context", query))
  } },
  { method: "GET", path: "/v1/policy/state", handler: async (rc) => {
    parsePolicyJson(Empty, new TextEncoder().encode(JSON.stringify(Object.fromEntries(rc.url.searchParams))))
    return json(await (await deviceRequest(rc)).call("policy.state"))
  } },
  ...(["preview", "proposals"] as const).map((path): Route<Handler> => ({ method: "POST", path: `/v1/policy/${path}`, handler: async (rc) => {
    const device = await deviceRequest(rc, POLICY_REQUEST_LIMIT)
    // With standing rules on, a rule's body names where it comes from
    // (`from`), and a task grant's proposal also names its areas (`area`);
    // anything else is a legacy window's. The workspace answers a task
    // grant's body to a mehen that cannot read one as it did before grants.
    const rules = policyRulesOn(rc.env, device.tenant) && namesKey(device.body, "from")
    const input = rules && path === "proposals" && namesKey(device.body, "area") ? parsePolicyJson(PolicyAreaProposalSchema, device.body) : rules ? parsePolicyJson(PolicyRuleProposalSchema, device.body) : path === "preview" ? parsePolicyJson(PolicyPreviewRequestSchema, device.body) : parsePolicyJson(PolicyProposeSchema, device.body)
    const result = await device.call(path === "preview" ? "policy.preview" : "policy.propose", input) as Record<string, unknown>
    const { reused, ...response } = result
    return json(response, path === "proposals" && reused !== true ? 201 : 200)
  } })),
  { method: "GET", path: "/v1/policy/proposals/:id", handler: async (rc) => {
    const query = parsePolicyJson(z.strictObject({ wait: z.literal("1").optional() }), new TextEncoder().encode(JSON.stringify(Object.fromEntries(rc.url.searchParams))))
    return json(await (await deviceRequest(rc)).call("policy.status", { id: rc.params["id"], wait: query.wait === "1" }))
  } },
  { method: "GET", path: "/v1/policy/rules", handler: async (rc) => {
    const query = parsePolicyJson(z.strictObject({ item: z.string().max(64).optional(), include: z.literal("grants").optional() }), new TextEncoder().encode(JSON.stringify(Object.fromEntries(rc.url.searchParams))))
    return json(await (await deviceRequest(rc)).call("policy.rules", query))
  } },
  { method: "POST", path: "/v1/policy/rules/:id/revoke", handler: async (rc) => {
    const device = await deviceRequest(rc, POLICY_REQUEST_LIMIT)
    parsePolicyJson(Empty, device.body)
    return json(await device.call("policy.rules.revoke", { id: rc.params["id"] }))
  } },
  ...(["proposals/:id/cancel", "overrides/:id/revoke", "grants/:id/revoke"] as const).map((path): Route<Handler> => ({ method: "POST", path: `/v1/policy/${path}`, handler: async (rc) => {
    const device = await deviceRequest(rc, POLICY_REQUEST_LIMIT)
    parsePolicyJson(Empty, device.body)
    return json(await device.call(path.startsWith("proposals") ? "policy.cancel" : path.startsWith("overrides") ? "policy.stop" : "policy.revoke-grant", { id: rc.params["id"] }))
  } })),
]
export const policyRoutes: Route<Handler>[] = deviceRoutes
