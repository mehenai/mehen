import { z } from "zod"
import { WorkspaceStepUpActionSchema } from "@mehen/protocol"
import { requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import { VaultError, json, parseJson, readBody } from "../http.ts"
import type { Route } from "../router.ts"
import { parseOpInput } from "../vault/areas/approvals.ts"
import { OverrideInput } from "../vault/areas/overrides-workspace.ts"
import { StepUpAssertionProofSchema } from "@mehen/protocol/step-up-proof"
import { deviceRequest, type Handler, workspaceCall } from "./context.ts"
import { type WorkspaceHandler } from "./workspace-prefix.ts"

export const workspaceOverridesRoutes: Route<WorkspaceHandler>[] = [
  { method: "GET", path: "/projects/:id/overrides", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "overrides.list", { project: rc.params.id })) },
  { method: "POST", path: "/projects/:id/overrides/action", handler: async (rc, ws) => {
    const body = parseJson(z.record(z.string(), z.unknown()), await readBody(rc.request))
    return json(await workspaceCall(rc, ws, "overrides.action", parseOpInput(OverrideInput, { ...body, project: rc.params.id })))
  } },
  { method: "POST", path: "/projects/:id/overrides", handler: async (rc, ws) => {
    const { stepUp, ...body } = parseJson(z.record(z.string(), z.unknown()), await readBody(rc.request))
    const input = parseOpInput(OverrideInput, { ...body, project: rc.params.id })
    const proof = parseOpInput(StepUpAssertionProofSchema, stepUp)
    const expected = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "overrides.action", input))
    const evidence = await requireWorkspaceStepUp(rc, ws, expected, proof)
    return json(await workspaceCall(rc, ws, "overrides.set", input, evidence))
  } },
]

export const overridesDeviceRoutes: Route<Handler>[] = [
  { method: "GET", path: "/v1/projects/:id/overrides", handler: async rc => {
    const device = await deviceRequest(rc)
    return json(await device.call("overrides.machine", { project: rc.params.id }))
  } },
]
