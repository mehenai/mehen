// Adoption routes for the person who reviews a batch: read it, approve it
// with one passkey over the whole batch, or cancel it; and the inventory of
// every name their adoptions touch.
import { z } from "zod"
import { StepUpProofSchema } from "@mehen/protocol/step-up-proof"
import { AdoptionApprove, AdoptionKeepOpen, adoptionDigest, adoptionRepoints, type WorkspaceAdoptionView } from "@mehen/protocol"
import { assertSameOrigin } from "../directory/session.ts"
import { requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import { json, parseJson, readBody } from "../http.ts"
import type { Route } from "../router.ts"
import { workspaceCall } from "./context.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"

export const workspaceAdoptionsRoutes: Route<WorkspaceHandler>[] = [
  { method: "GET", path: "/adoptions", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "adoption.inventory", {})) },
  { method: "GET", path: "/adoptions/:id", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "adoption.view", { adoption: rc.params.id })) },
  {
    // The action is rebuilt from the batch as the vault holds it now and the
    // decisions sent; the operation rebuilds and checks it once more.
    method: "POST", path: "/adoptions/:id/approve", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      const { stepUp, decisions } = parseJson(AdoptionApprove.extend({ stepUp: StepUpProofSchema }), await readBody(rc.request))
      const adoption = rc.params.id as string
      const view = await workspaceCall(rc, ws, "adoption.view", { adoption }) as WorkspaceAdoptionView
      // A retry after the batch was stored answers what was stored, or is refused.
      if (view.status !== "open") return json(await workspaceCall(rc, ws, "adoption.approve", { adoption, decisions }))
      const action = { type: "adoption.approve" as const, adoption, digest: await adoptionDigest(adoption, view.items, decisions), repoints: adoptionRepoints(decisions) }
      return json(await workspaceCall(rc, ws, "adoption.approve", { adoption, decisions }, await requireWorkspaceStepUp(rc, ws, action, stepUp)))
    },
  },
  {
    method: "POST", path: "/adoptions/:id/keep-open", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      return json(await workspaceCall(rc, ws, "adoption.keepOpen", { adoption: rc.params.id, ...parseJson(AdoptionKeepOpen, await readBody(rc.request)) }))
    },
  },
  { method: "POST", path: "/adoptions/:id/cancel", handler: async (rc, ws) => { assertSameOrigin(rc.request, rc.env); return json(await workspaceCall(rc, ws, "adoption.cancel", { adoption: rc.params.id })) } },
]
