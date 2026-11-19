// Teams under /api/w/:ws: a thin forwarder to the workspace's own team
// operations, which authorise every change and check its passkey in the
// same transaction. The browser asks /teams/action for the exact action to
// sign (a fresh tm_ id for a new team), signs it, and sends the change with
// its proof; the route rebuilds that action from the request and the DO
// refuses anything else.

import { TeamViewSchema, type WorkspaceStepUpAction } from "@mehen/protocol"
import { z } from "zod"
import { StepUpProofSchema } from "@mehen/protocol/step-up-proof"
import { requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import { VaultError, json } from "../http.ts"
import type { Route } from "../router.ts"
import { randomId } from "../vault/core.ts"
import { accountBody } from "./account.ts"
import { type RequestContext, type WorkspaceRequest, workspaceCall } from "./context.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"

const TEAM_ID = /^tm_[A-Za-z0-9_-]{1,64}$/
const TeamSlug = z.string().trim().toLowerCase().regex(/^[a-z][a-z0-9-]{1,30}[a-z0-9]$/)
const TeamName = z.string().trim().min(1).max(64)
const Proof = { stepUp: StepUpProofSchema.optional() }
const MemberChange = z.enum(["add", "remove"])

const Planned = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("create"), name: TeamName, slug: TeamSlug }),
  z.strictObject({ kind: z.literal("rename"), team: z.string(), name: TeamName, slug: TeamSlug }),
  z.strictObject({ kind: z.literal("delete"), team: z.string() }),
  z.strictObject({ kind: z.literal("members"), team: z.string(), member: z.string(), change: MemberChange }),
])

async function teams(rc: RequestContext, ws: WorkspaceRequest) {
  return z.array(TeamViewSchema).parse(await workspaceCall(rc, ws, "access.teams.read", {}))
}

// An existing team of this workspace, or the same refusal as for one that
// never existed.
async function existing(rc: RequestContext, ws: WorkspaceRequest, team: string) {
  const found = TEAM_ID.test(team) ? (await teams(rc, ws)).find((t) => t.id === team) : undefined
  if (!found) throw new VaultError("not_found", "No such available team.")
  return found
}

function teamView(value: unknown) {
  return TeamViewSchema.parse(value)
}

export const workspaceTeamRoutes: Route<WorkspaceHandler>[] = [
  { method: "GET", path: "/teams", handler: async (rc, ws) => json({ teams: await teams(rc, ws) }) },
  {
    method: "POST",
    path: "/teams/action",
    handler: async (rc, ws) => {
      const input = await accountBody(rc, Planned)
      let action: WorkspaceStepUpAction
      if (input.kind === "create") {
        await teams(rc, ws)
        action = { type: "team.update", team: randomId("tm"), change: "create", name: input.name, slug: input.slug }
      } else if (input.kind === "members") {
        const team = await existing(rc, ws, input.team)
        action = { type: "team.members", team: team.id, member: input.member, change: input.change }
      } else {
        const team = await existing(rc, ws, input.team)
        action = input.kind === "rename" ? { type: "team.update", team: team.id, change: "rename", name: input.name, slug: input.slug } : { type: "team.update", team: team.id, change: "delete", name: null, slug: null }
      }
      return json({ action })
    },
  },
  {
    method: "POST",
    path: "/teams",
    handler: async (rc, ws) => {
      const input = await accountBody(rc, z.strictObject({ team: z.string().regex(TEAM_ID), name: TeamName, slug: TeamSlug, ...Proof }))
      const change = { team: input.team, change: "create" as const, name: input.name, slug: input.slug }
      const evidence = await requireWorkspaceStepUp(rc, ws, { type: "team.update", ...change }, input.stepUp)
      return json(teamView(await workspaceCall(rc, ws, "access.team.update", change, evidence)), 201)
    },
  },
  {
    method: "POST",
    path: "/teams/:id/update",
    handler: async (rc, ws) => {
      const input = await accountBody(rc, z.discriminatedUnion("change", [z.strictObject({ change: z.literal("rename"), name: TeamName, slug: TeamSlug, ...Proof }), z.strictObject({ change: z.literal("delete"), ...Proof })]))
      const team = rc.params.id ?? ""
      if (!TEAM_ID.test(team)) throw new VaultError("not_found", "No such available team.")
      const change = input.change === "rename" ? { team, change: "rename" as const, name: input.name, slug: input.slug } : { team, change: "delete" as const, name: null, slug: null }
      const evidence = await requireWorkspaceStepUp(rc, ws, { type: "team.update", ...change }, input.stepUp)
      const result = await workspaceCall(rc, ws, "access.team.update", change, evidence)
      return json(change.change === "delete" ? { deleted: true, team } : teamView(result))
    },
  },
  {
    method: "POST",
    path: "/teams/:id/members",
    handler: async (rc, ws) => {
      const input = await accountBody(rc, z.strictObject({ member: z.string().max(128), change: MemberChange, ...Proof }))
      const team = rc.params.id ?? ""
      if (!TEAM_ID.test(team)) throw new VaultError("not_found", "No such available team.")
      const change = { team, member: input.member, change: input.change }
      const evidence = await requireWorkspaceStepUp(rc, ws, { type: "team.members", ...change }, input.stepUp)
      return json(teamView(await workspaceCall(rc, ws, "access.team.members", change, evidence)))
    },
  },
]
