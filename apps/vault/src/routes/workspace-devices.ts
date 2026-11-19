import { WorkloadListSchema,WorkloadViewSchema,RescopeProposalViewSchema,RescopeRejectRequestSchema,scopeChangeIsNarrowing,WorkspaceDeviceScopeSchema,WorkspaceDeviceViewSchema,WorkspaceStepUpActionSchema } from "@mehen/protocol"
import { z } from "zod"
import { requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import { StepUpProofSchema } from "@mehen/protocol/step-up-proof"
import { json,VaultError } from "../http.ts"
import type { Route } from "../router.ts"
import { workspaceCall,type RequestContext,type WorkspaceRequest } from "./context.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"
import { accountBody } from "./account.ts"
const legacyAdmissionRefusal = () => new VaultError("forbidden","Choose an eligible insider for this guest's shared project.")
const ScopeChange = z.strictObject({ before: WorkspaceDeviceScopeSchema,after: WorkspaceDeviceScopeSchema })
const Change = z.discriminatedUnion("kind",[
  ScopeChange.extend({ kind: z.literal("rescope") }),ScopeChange.extend({ kind: z.literal("rescope_propose") }),
  z.strictObject({ kind: z.literal("rescope_accept"),proposal: z.string() }),z.strictObject({ kind: z.literal("rescope_admit"),proposal: z.string() }),z.strictObject({ kind: z.literal("rescope_reject"),proposal: z.string() }),z.strictObject({ kind: z.literal("revoke") }),
  z.strictObject({ kind: z.literal("workload_revoke"),workload: z.string().max(80) }),
])
async function action(rc: RequestContext,ws: WorkspaceRequest,change: z.infer<typeof Change>,project?: string) {
  const result = await workspaceCall(rc,ws,"access.devices.action",{ device: rc.params.id ?? "",change,...(project ? { project } : {}) })
  return z.strictObject({ action: WorkspaceStepUpActionSchema }).parse(result).action
}
export const workspaceDeviceRoutes: Route<WorkspaceHandler>[] = [
  { method: "GET",path: "/devices",handler: async (rc,ws) => json(z.strictObject({ devices: z.array(WorkspaceDeviceViewSchema) }).parse(await workspaceCall(rc,ws,"devices.list",{}))) },
  { method: "GET",path: "/devices/:id",handler: async (rc,ws) => {
    const { devices } = z.strictObject({ devices: z.array(WorkspaceDeviceViewSchema) }).parse(await workspaceCall(rc,ws,"devices.list",{}))
    const device = devices.find(value => value.device === rc.params.id)
    if (!device) throw new VaultError("not_found","No such machine.")
    return json(device)
  } },
  { method: "POST",path: "/devices/:id/action",handler: async (rc,ws) => { const input = await accountBody(rc,z.strictObject({ change: Change,project: z.string().optional() })); return json({ action: await action(rc,ws,input.change,input.project) }) } },
  { method: "POST",path: "/devices/:id/revoke",handler: async (rc,ws) => {
    const { stepUp } = await accountBody(rc,z.strictObject({ stepUp: StepUpProofSchema.optional() })),expected = await action(rc,ws,{ kind: "revoke" }),evidence = await requireWorkspaceStepUp(rc,ws,expected,stepUp)
    return json(await workspaceCall(rc,ws,"devices.revoke",{ device: rc.params.id ?? "" },evidence))
  } },
  // A machine's live workloads, and ending one with the passkey step-up that
  // revokes the machine, over the exact machine and workload.
  { method: "GET",path: "/devices/:id/workloads",handler: async (rc,ws) => json(WorkloadListSchema.parse(await workspaceCall(rc,ws,"workloads.of_device",{ device: rc.params.id ?? "" }))) },
  { method: "POST",path: "/devices/:id/workloads/:workload/revoke",handler: async (rc,ws) => {
    const { stepUp } = await accountBody(rc,z.strictObject({ stepUp: StepUpProofSchema.optional() })),workload = rc.params.workload ?? ""
    const expected = await action(rc,ws,{ kind: "workload_revoke",workload }),evidence = await requireWorkspaceStepUp(rc,ws,expected,stepUp)
    return json(WorkloadViewSchema.parse(await workspaceCall(rc,ws,"workloads.revoke_member",{ device: rc.params.id ?? "",workload },evidence)))
  } },
  { method: "POST",path: "/devices/:id/rescope",handler: async (rc,ws) => {
    const input = await accountBody(rc,z.preprocess(value => {
      if (typeof value === "object" && value !== null && "admissionAccount" in value) throw legacyAdmissionRefusal()
      return value
    },ScopeChange.extend({ project: z.string().optional(),admissionMember: z.string().regex(/^mem_[A-Za-z0-9_-]{1,64}$/).optional(),stepUp: StepUpProofSchema.optional() })))
    const expected = await action(rc,ws,{ kind: scopeChangeIsNarrowing(input.before,input.after) ? "rescope" : "rescope_propose",before: input.before,after: input.after },input.project)
    const evidence = await requireWorkspaceStepUp(rc,ws,expected,input.stepUp)
    const result = await workspaceCall(rc,ws,"devices.rescope",{ device: rc.params.id ?? "",before: input.before,after: input.after,...(input.project ? { project: input.project } : {}),...(input.admissionMember ? { admissionMember: input.admissionMember } : {}) },evidence)
    return json(scopeChangeIsNarrowing(input.before,input.after) ? z.strictObject({ state: z.literal("committed"),scope: WorkspaceDeviceScopeSchema }).parse(result) : RescopeProposalViewSchema.parse(result))
  } },
  ...(["accept","admit"] as const).map((signAs): Route<WorkspaceHandler> => ({ method: "POST",path: `/devices/:id/rescope-${signAs}`,handler: async (rc,ws) => {
    const input = await accountBody(rc,z.strictObject({ proposal: z.string(),project: z.string().optional(),stepUp: StepUpProofSchema.optional() }))
    const expected = await action(rc,ws,{ kind: signAs === "accept" ? "rescope_accept" : "rescope_admit",proposal: input.proposal },input.project),evidence = await requireWorkspaceStepUp(rc,ws,expected,input.stepUp)
    return json(RescopeProposalViewSchema.parse(await workspaceCall(rc,ws,`devices.rescope_${signAs}`,{ proposal: input.proposal,...(input.project ? { project: input.project } : {}) },evidence)))
  } })),
  { method: "POST",path: "/devices/:id/rescope-reject",handler: async (rc,ws) => {
    const input = await accountBody(rc,RescopeRejectRequestSchema.extend({ stepUp: StepUpProofSchema.optional() }))
    const expected = await action(rc,ws,{ kind: "rescope_reject",proposal: input.proposal },input.project),evidence = await requireWorkspaceStepUp(rc,ws,expected,input.stepUp)
    return json(RescopeProposalViewSchema.parse(await workspaceCall(rc,ws,"devices.rescope_reject",{ device: rc.params.id ?? "",proposal: input.proposal,...(input.project ? { project: input.project } : {}) },evidence)))
  } },
  { method: "POST",path: "/unfreeze",handler: async (rc,ws) => { const { stepUp } = await accountBody(rc,z.strictObject({ stepUp: StepUpProofSchema.optional() })),evidence = await requireWorkspaceStepUp(rc,ws,{ type: "workspace.unfreeze" },stepUp); return json(await workspaceCall(rc,ws,"access.unfreeze",{},evidence)) } },
]
