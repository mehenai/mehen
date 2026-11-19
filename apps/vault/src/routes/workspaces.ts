import { WorkspaceStepUpActionSchema,WorkspaceEnrolStartSchema,type WorkspaceStepUpAction } from "@mehen/protocol"
import { z } from "zod"
import { initialiseWorkspace,reserveWorkspace } from "../directory/workspace-index.ts"
import { finaliseWorkspaceSlug,reserveWorkspaceSlug } from "../directory/workspace-aliases.ts"
import { checkWorkspaceName } from "../directory/workspace-names.ts"
import { directoryWorkspaceClient } from "../directory/workspace-client.ts"
import { renewWorkspaceEnrolment,startWorkspaceEnrolment,workspaceEnrolmentStatus } from "../directory/workspace-enrolment.ts"
import { requireAccountStepUp,requireWorkspaceStepUp,startAccountStepUp } from "../directory/workspace-stepup.ts"
import { StepUpProofSchema } from "@mehen/protocol/step-up-proof"
import { VaultError,json,parseJson,readBody } from "../http.ts"
import type { Route } from "../router.ts"
import { workspaceCall,type Handler } from "./context.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"
import { accountBody,accountBrowser,limitWorkspaceStepUp,requireAccount } from "./account.ts"
const Create = z.strictObject({ name: z.string().trim().min(1).max(64),slug: z.string().trim().toLowerCase().min(1).max(64),stepUp: StepUpProofSchema.optional() })
const Settings = z.discriminatedUnion("change",[z.strictObject({ change: z.literal("name"),name: z.string().trim().min(1).max(64),stepUp: StepUpProofSchema.optional() }),z.strictObject({ change: z.literal("slug"),slug: z.string().trim().toLowerCase().min(1).max(64),stepUp: StepUpProofSchema.optional() })])
export const workspaceAccountRoutes: Route<Handler>[] = [
  accountBrowser("POST","/api/workspaces",async rc => {
    const account = await requireAccount(rc),input = await accountBody(rc,Create),action: WorkspaceStepUpAction = { type: "workspace.create",name: input.name,slug: input.slug }
    await checkWorkspaceName(rc.env,account.account,input.slug,{ canonical: [],aliases: [] })
    const evidence = await requireAccountStepUp(rc,account,"-",action,input.stepUp)
    const reservation = await reserveWorkspace(rc.env,account,input,action,{ confirmation: evidence.confirmation })
    return json(await initialiseWorkspace(rc.env,reservation),201)
  }),
]
export const workspaceDirectoryRoutes: Route<WorkspaceHandler>[] = [
  { method: "POST",path: "/stepup/start",handler: async (rc,ws) => {
    const { action } = await accountBody(rc,z.strictObject({ action: WorkspaceStepUpActionSchema }))
    if ("workspace" in action && action.workspace !== ws.workspace.id) throw new VaultError("not_found","No such workspace.")
    // Only a batch this person may review, refused as unknown otherwise.
    if (action.type === "adoption.approve") await workspaceCall(rc,ws,"adoption.view",{ adoption: action.adoption })
    await limitWorkspaceStepUp(rc,ws.account.account)
    return json(await startAccountStepUp(rc.env,ws.account,ws.workspace.id,action))
  } },
  { method: "POST",path: "/settings",handler: async (rc,ws) => {
    const input = await accountBody(rc,Settings)
    if (input.change === "slug") await checkWorkspaceName(rc.env,ws.account.account,input.slug,{ canonical: [],aliases: [] })
    const client = directoryWorkspaceClient(rc.env),before = await client.metadata(ws.workspace.id)
    const after = { ...before.workspace,...(input.change === "name" ? { name: input.name } : { slug: input.slug }) },action: WorkspaceStepUpAction = { type: "workspace.update",name: after.name,slug: after.slug }
    const evidence = await requireWorkspaceStepUp(rc,ws,action,input.stepUp)
    if (input.change === "name") {
      const result = z.strictObject({ displayRev: z.number().int().nonnegative() }).parse(await workspaceCall(rc,ws,"access.workspace_update",{ name: input.name },evidence))
      await rc.env.DB.prepare("UPDATE workspaces SET name=?,display_rev=? WHERE id=? AND display_rev<?").bind(input.name,result.displayRev,ws.workspace.id,result.displayRev).run()
      return json({ workspace: after,displayRev: result.displayRev })
    }
    const reservation = await reserveWorkspaceSlug(rc.env,ws.account.account,ws.workspace,input.slug)
    try {
      await workspaceCall(rc,ws,"access.workspace_update",{ slug: input.slug,reservation: { id: reservation.id,expiresAt: new Date(reservation.expiresAt).toISOString() } },evidence)
      const metadata = await client.metadata(ws.workspace.id)
      await finaliseWorkspaceSlug(rc.env,reservation,metadata)
      return json({ workspace: metadata.workspace,displayRev: metadata.displayRev })
    } catch (error) {
      // A definitive DO refusal is known not to have applied. An unavailable
      // response leaves the reservation for expiry and source reconciliation.
      if (error instanceof VaultError && ["forbidden","not_found","account_pending","identity_required"].includes(error.code)) await rc.env.DB.prepare("DELETE FROM workspace_slug_reservations WHERE id=?").bind(reservation.id).run()
      throw error
    }
  } },
]
export const workspaceEnrolDeviceRoutes: Route<Handler>[] = [
  { method: "POST",path: "/v1/enrol",handler: async rc => { const raw = await readBody(rc.request,16384); return json(await startWorkspaceEnrolment(rc.env,rc.request,raw,parseJson(WorkspaceEnrolStartSchema,raw)),201) } },
  { method: "GET",path: "/v1/enrol/:enrolment",handler: async rc => { return json(await workspaceEnrolmentStatus(rc.env,rc.request,rc.params.enrolment ?? "")) } },
  // The body is empty: the proof is the only input, as for the poll.
  { method: "POST",path: "/v1/enrol/:enrolment/renew",handler: async rc => { await readBody(rc.request,0); return json(await renewWorkspaceEnrolment(rc.env,rc.request,rc.params.enrolment ?? "")) } },
]
