// Mandates: a machine proposes one, reads its own and
// pauses it; a person reads those on machines they may read, signs one for
// their own machine and resumes it, with a passkey unless they or the
// machine paused it and they still stand behind it, and pauses or stops one.
// With MANDATES off here every route answers as an unknown route does.

import { z } from "zod"
import { POLICY_REQUEST_LIMIT } from "@mehen/protocol/policy-mode"
import { StepUpProofSchema } from "@mehen/protocol/step-up-proof"
import { MandateActionAnswerSchema, MandateActionRequestSchema, MandateProposeSchema, MandateRevSchema, MandateSignSchema, WorkspaceStepUpActionSchema } from "@mehen/protocol"
import { assertSameOrigin } from "../directory/session.ts"
import { requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import type { Env } from "../env.ts"
import { VaultError, json, parseJson, readBody } from "../http.ts"
import type { Route } from "../router.ts"
import { mandatesOn } from "../vault/areas/mandates-workspace.ts"
import { type Handler, deviceRequest, workspaceCall } from "./context.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"

const Empty = z.strictObject({})
const UsesQuery = z.strictObject({ before: z.string().max(120).optional() })
const DeviceQuery = z.strictObject({ device: z.string().max(80) })
const query = (url: URL): Uint8Array => new TextEncoder().encode(JSON.stringify(Object.fromEntries(url.searchParams)))
function available(env: Env, workspace: string): void {
  if (!mandatesOn(env, workspace)) throw new VaultError("not_found", "No such route.")
}

export const mandateDeviceRoutes: Route<Handler>[] = [
  { method: "POST", path: "/v1/mandates/proposals", handler: async (rc) => {
    const device = await deviceRequest(rc, POLICY_REQUEST_LIMIT)
    available(rc.env, device.tenant)
    return json(await device.call("mandates.propose", parseJson(MandateProposeSchema, device.body)), 201)
  } },
  { method: "GET", path: "/v1/mandates", handler: async (rc) => {
    const device = await deviceRequest(rc)
    available(rc.env, device.tenant)
    parseJson(Empty, query(rc.url))
    return json(await device.call("mandates.mine", {}))
  } },
  { method: "GET", path: "/v1/mandates/:id", handler: async (rc) => {
    const device = await deviceRequest(rc)
    available(rc.env, device.tenant)
    parseJson(Empty, query(rc.url))
    return json(await device.call("mandates.mine_one", { id: rc.params["id"] }))
  } },
  { method: "GET", path: "/v1/mandates/:id/uses", handler: async (rc) => {
    const device = await deviceRequest(rc)
    available(rc.env, device.tenant)
    const { before } = parseJson(UsesQuery, query(rc.url))
    return json(await device.call("mandates.mine_uses", { id: rc.params["id"], ...(before !== undefined ? { before } : {}) }))
  } },
  { method: "POST", path: "/v1/mandates/:id/pause", handler: async (rc) => {
    const device = await deviceRequest(rc, POLICY_REQUEST_LIMIT)
    available(rc.env, device.tenant)
    return json(await device.call("mandates.mine_pause", { id: rc.params["id"], ...parseJson(MandateRevSchema, device.body) }))
  } },
]

export const workspaceMandateRoutes: Route<WorkspaceHandler>[] = [
  { method: "GET", path: "/mandates", handler: async (rc, ws) => {
    available(rc.env, ws.workspace.id)
    return json(await workspaceCall(rc, ws, "mandates.list", {}))
  } },
  // Beside /mandates, not under it, where /mandates/proposals/uses would
  // also be a mandate's receipts.
  { method: "GET", path: "/mandate-proposals/:id", handler: async (rc, ws) => {
    available(rc.env, ws.workspace.id)
    return json(await workspaceCall(rc, ws, "mandates.proposal", { id: rc.params.id }))
  } },
  // The sign page's credentials for one of the reader's machines, beside
  // /mandates for the same reason.
  { method: "GET", path: "/mandate-candidates", handler: async (rc, ws) => {
    available(rc.env, ws.workspace.id)
    return json(await workspaceCall(rc, ws, "mandates.candidates", parseJson(DeviceQuery, query(rc.url))))
  } },
  // Which caps kept the machine's mandate from letting an ask through.
  { method: "GET", path: "/mandate-asks/:approval", handler: async (rc, ws) => {
    available(rc.env, ws.workspace.id)
    return json(await workspaceCall(rc, ws, "mandates.capped_ask", { approval: rc.params.approval }))
  } },
  // That a mandate could let asks like this through, for whoever may sign it.
  { method: "GET", path: "/mandate-covers/:approval", handler: async (rc, ws) => {
    available(rc.env, ws.workspace.id)
    return json(await workspaceCall(rc, ws, "mandates.cover_ask", { approval: rc.params.approval }))
  } },
  { method: "GET", path: "/mandates/:id", handler: async (rc, ws) => {
    available(rc.env, ws.workspace.id)
    return json(await workspaceCall(rc, ws, "mandates.show", { id: rc.params.id }))
  } },
  { method: "GET", path: "/mandates/:id/uses", handler: async (rc, ws) => {
    available(rc.env, ws.workspace.id)
    const { before } = parseJson(UsesQuery, query(rc.url))
    return json(await workspaceCall(rc, ws, "mandates.uses", { id: rc.params.id, ...(before !== undefined ? { before } : {}) }))
  } },
  // Planning only: the mandate.sign or mandate.resume action the page signs,
  // or { stepUp: null } for a resume that needs no passkey, rebuilt from
  // live state, which sign and resume rebuild and check again.
  { method: "POST", path: "/mandates/action", handler: async (rc, ws) => {
    assertSameOrigin(rc.request, rc.env)
    available(rc.env, ws.workspace.id)
    const input = parseJson(MandateActionRequestSchema, await readBody(rc.request))
    return json(MandateActionAnswerSchema.parse(await workspaceCall(rc, ws, "mandates.action", input)))
  } },
  { method: "POST", path: "/mandates", handler: async (rc, ws) => {
    assertSameOrigin(rc.request, rc.env)
    available(rc.env, ws.workspace.id)
    const { stepUp, ...input } = parseJson(MandateSignSchema.extend({ stepUp: StepUpProofSchema }), await readBody(rc.request))
    const expected = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "mandates.action", { op: "sign", ...input }))
    return json(await workspaceCall(rc, ws, "mandates.sign", input, await requireWorkspaceStepUp(rc, ws, expected, stepUp)), 201)
  } },
  { method: "POST", path: "/mandates/:id/resume", handler: async (rc, ws) => {
    assertSameOrigin(rc.request, rc.env)
    available(rc.env, ws.workspace.id)
    const { stepUp, rev } = parseJson(MandateRevSchema.extend({ stepUp: StepUpProofSchema.optional() }), await readBody(rc.request))
    const id = rc.params.id
    const expected = MandateActionAnswerSchema.parse(await workspaceCall(rc, ws, "mandates.action", { op: "resume", id, rev }))
    if ("stepUp" in expected) return json(await workspaceCall(rc, ws, "mandates.resume", { id, rev }))
    return json(await workspaceCall(rc, ws, "mandates.resume", { id, rev }, await requireWorkspaceStepUp(rc, ws, expected, stepUp)))
  } },
  ...(["pause", "stop"] as const).map((change): Route<WorkspaceHandler> => ({ method: "POST", path: `/mandates/:id/${change}`, handler: async (rc, ws) => {
    assertSameOrigin(rc.request, rc.env)
    available(rc.env, ws.workspace.id)
    const { rev } = parseJson(MandateRevSchema, await readBody(rc.request))
    return json(await workspaceCall(rc, ws, change === "pause" ? "mandates.pause" : "mandates.stop", { id: rc.params.id, rev }))
  } })),
]
