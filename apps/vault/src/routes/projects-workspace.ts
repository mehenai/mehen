import { z } from "zod"
import { StepUpProofSchema } from "@mehen/protocol/step-up-proof"
import { json, parseJson, readBody } from "../http.ts"
import { requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import type { Route } from "../router.ts"
import { workspaceCall } from "./context.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"
import { parseOpInput } from "../vault/areas/approvals.ts"
import { WorkspaceStepUpActionSchema } from "@mehen/protocol"
import { WorkspaceEnvironmentInput, WorkspaceProjectCreate, WorkspaceShareInput, WorkspaceVarInput, WorkspaceRemoteInput } from "../vault/areas/projects-workspace.ts"

export const workspaceProjectsRoutes: Route<WorkspaceHandler>[] = [
  { method: "GET", path: "/projects", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "projects.list")) },
  { method: "GET", path: "/projects/:id", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "projects.get", { id: rc.params.id })) },
  { method: "POST", path: "/projects/action", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "projects.action", parseJson(z.strictObject({ change: z.enum(["create", "environment", "variable", "share", "delete", "remote"]), input: z.unknown() }), await readBody(rc.request)))) },
  ...([
    { path: "/projects", op: "projects.create", change: "create", schema: WorkspaceProjectCreate },
    { path: "/projects/:id/environments/:name", op: "projects.setEnvironment", change: "environment", schema: WorkspaceEnvironmentInput },
    { path: "/projects/:id/vars/:name", op: "projects.setVar", change: "variable", schema: WorkspaceVarInput },
    { path: "/projects/:id/shares", op: "projects.share", change: "share", schema: WorkspaceShareInput },
    { path: "/projects/:id/remotes", op: "projects.setRemote", change: "remote", schema: WorkspaceRemoteInput },
    { path: "/projects/:id/delete", op: "projects.delete", change: "delete", schema: z.strictObject({ project: z.string().max(64) }) },
  ] as const).map(({ path, op, change, schema }): Route<WorkspaceHandler> => ({ method: "POST", path, handler: async (rc, ws) => {
    const { stepUp: proof, ...supplied } = parseJson(z.record(z.string(), z.unknown()), await readBody(rc.request))
    const stepUp = parseOpInput(StepUpProofSchema, proof)
    const input = parseOpInput(schema, { ...supplied, ...(rc.params.id ? { project: rc.params.id } : {}), ...(rc.params.name ? change === "environment" ? { env: rc.params.name } : { name: rc.params.name } : {}) })
    const expected = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "projects.action", { change, input }))
    const evidence = await requireWorkspaceStepUp(rc, ws, expected, stepUp)
    return json(await workspaceCall(rc, ws, op, input, evidence), change === "create" ? 201 : 200)
  } })),
]
