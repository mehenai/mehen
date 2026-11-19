import { z } from "zod"
import { StepUpProofSchema } from "@mehen/protocol/step-up-proof"
import { CredentialHomeSchema, WorkspaceStepUpActionSchema } from "@mehen/protocol"
import { assertSameOrigin } from "../directory/session.ts"
import { requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import { json, parseJson, readBody } from "../http.ts"
import { ItemChange, stepUpDigest } from "../vault/areas/items.ts"
import { IntakeSubmission } from "../vault/areas/intake.ts"
import { RestoreTerms } from "../vault/areas/items-workspace.ts"
import { PostureTerms } from "../vault/areas/postures-workspace.ts"
import type { Route } from "../router.ts"
import { workspaceCall } from "./context.ts"
import { sendPushes } from "./push.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"
const PushRecords = z.array(z.string().max(64)).min(1).max(25)

export const workspaceItemsRoutes: Route<WorkspaceHandler>[] = [
  { method: "GET", path: "/items", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "items.list", Object.fromEntries(rc.url.searchParams))) },
  { method: "GET", path: "/items/:slug", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "items.describe", { slug: rc.params.slug })) },
  // Planning only: the canonical action the browser signs before it calls
  // update, delete, rehome, restore or posture, which rebuild and check it again.
  {
    method: "POST", path: "/items/:slug/action", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      const input = parseJson(z.strictObject({ action: z.enum(["update", "delete", "rehome", "restore", "posture"]), change: ItemChange.optional(), home: CredentialHomeSchema.optional(), ...RestoreTerms.partial().shape, ...PostureTerms.partial().shape }), await readBody(rc.request))
      return json(WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "items.action", { slug: rc.params.slug, ...input })))
    }
  },
  {
    method: "POST", path: "/items/:slug/update", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      const { stepUp, ...change } = parseJson(ItemChange.extend({ stepUp: StepUpProofSchema }), await readBody(rc.request))
      const slug = rc.params.slug
      const expected = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "items.action", { slug, change, action: "update" }))
      const evidence = await requireWorkspaceStepUp(rc, ws, expected, stepUp)
      return json(await workspaceCall(rc, ws, "items.update", { slug, change }, evidence))
    }
  },
  {
    method: "POST", path: "/items/:slug/delete", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      const { stepUp } = parseJson(z.object({ stepUp: StepUpProofSchema }), await readBody(rc.request))
      const slug = rc.params.slug
      const expected = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "items.action", { slug, action: "delete" }))
      return json(await workspaceCall(rc, ws, "items.delete", { slug }, await requireWorkspaceStepUp(rc, ws, expected, stepUp)))
    }
  },
  {
    method: "POST", path: "/items/:slug/rehome", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      const { stepUp, home } = parseJson(z.object({ stepUp: StepUpProofSchema, home: CredentialHomeSchema }), await readBody(rc.request))
      const slug = rc.params.slug
      const expected = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "items.action", { slug, home, action: "rehome" }))
      return json(await workspaceCall(rc, ws, "items.rehome", { slug, home }, await requireWorkspaceStepUp(rc, ws, expected, stepUp)))
    }
  },
  // The versions are the page's: one rotated since refuses as changed
  // before any passkey is checked.
  {
    method: "POST", path: "/items/:slug/restore", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      const { stepUp, ...terms } = parseJson(RestoreTerms.extend({ stepUp: StepUpProofSchema }), await readBody(rc.request))
      const slug = rc.params.slug
      const expected = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "items.action", { slug, action: "restore", ...terms }))
      return json(await workspaceCall(rc, ws, "items.restore", { slug, ...terms }, await requireWorkspaceStepUp(rc, ws, expected, stepUp)))
    }
  },
  // Planning only: the item.push action the page signs for these records.
  {
    method: "POST", path: "/items/:slug/push/action", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      const { records } = parseJson(z.strictObject({ records: PushRecords }), await readBody(rc.request))
      return json(WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "push.action", { slug: rc.params.slug, records })))
    }
  },
  // Putting the current value where it was pushed before (design 3.3): one
  // passkey over the action rebuilt from the records, then each push is sent
  // and the page waits a while to say how they went.
  {
    method: "POST", path: "/items/:slug/push", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      const { stepUp, records } = parseJson(z.strictObject({ records: PushRecords, stepUp: StepUpProofSchema }), await readBody(rc.request))
      const slug = rc.params.slug
      const expected = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "push.action", { slug, records }))
      const queued = (await workspaceCall(rc, ws, "push.again", { slug, records }, await requireWorkspaceStepUp(rc, ws, expected, stepUp))) as { pushes: string[] }
      await sendPushes(rc.ctx, rc.env, ws.workspace.id, queued.pushes.map((push) => ({ push })))
      return json(await workspaceCall(rc, ws, "items.describe", { slug }))
    }
  },
  // How careful the credential is: the posture and the posture revision the
  // page showed; one changed since refuses before any passkey is checked.
  {
    method: "POST", path: "/items/:slug/posture", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      const { stepUp, ...terms } = parseJson(PostureTerms.extend({ stepUp: StepUpProofSchema }), await readBody(rc.request))
      const slug = rc.params.slug
      const expected = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "items.action", { slug, action: "posture", ...terms }))
      return json(await workspaceCall(rc, ws, "items.posture", { slug, ...terms }, await requireWorkspaceStepUp(rc, ws, expected, stepUp)) ?? {})
    }
  },
  // The home's nudge toward a posture, and its "Not now".
  { method: "GET", path: "/nudges", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "items.nudges", {})) },
  { method: "POST", path: "/items/:slug/nudge-quiet", handler: async (rc, ws) => { assertSameOrigin(rc.request, rc.env); return json(await workspaceCall(rc, ws, "items.nudge_quiet", { slug: rc.params.slug })) } },
  { method: "POST", path: "/intakes", handler: async (rc, ws) => { assertSameOrigin(rc.request, rc.env); return json(await workspaceCall(rc, ws, "intake.createByMember", parseJson(z.unknown(), await readBody(rc.request))), 201); } },
  { method: "GET", path: "/intakes/:id", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "intake.view", { intake: rc.params.id })) },
  {
    method: "POST", path: "/intakes/:id/submit", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      const { stepUp, ...submission } = parseJson(IntakeSubmission.extend({ home: CredentialHomeSchema, stepUp: StepUpProofSchema }), await readBody(rc.request))
      const intake = rc.params.id as string
      const action = { type: "intake.submit" as const, intake, digest: await stepUpDigest({ ...submission, tags: [...submission.tags].sort() }) }
      return json(await workspaceCall(rc, ws, "intake.submit", { intake, ...submission }, await requireWorkspaceStepUp(rc, ws, action, stepUp)))
    }
  },
  { method: "POST", path: "/intakes/:id/cancel", handler: async (rc, ws) => { assertSameOrigin(rc.request, rc.env); return json(await workspaceCall(rc, ws, "intake.cancel", { intake: rc.params.id })); } },
]