import { z } from "zod"
import { StepUpProofSchema } from "@mehen/protocol/step-up-proof"
import { CredentialHomeSchema, WorkspaceStepUpActionSchema } from "@mehen/protocol"
import { assertSameOrigin, randomToken, sha256Text } from "../directory/session.ts"
import { requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import { VaultError, json, parseJson, readBody } from "../http.ts"
import type { Route } from "../router.ts"
import { errorPage, redirect } from "../ui/layout.ts"
import { resolveWorkspace, workspaceCall, type RequestContext } from "./context.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"

export const workspaceOAuthRoutes: Route<WorkspaceHandler>[] = [
  { method: "POST", path: "/connect", handler: async (rc, ws) => { assertSameOrigin(rc.request, rc.env); return json(await workspaceCall(rc, ws, "oauth.connectCreateByMember", parseJson(z.unknown(), await readBody(rc.request))), 201); } },
  { method: "GET", path: "/connect/:id", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "oauth.connectView", { connect: rc.params.id })) },
  // Planning only: the canonical connect.start the browser signs; start
  // rebuilds it from current state and checks it again.
  {
    method: "POST", path: "/connect/:id/action", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      const { home } = parseJson(z.strictObject({ home: CredentialHomeSchema.optional() }), await readBody(rc.request))
      return json(WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "oauth.connect_action", { connect: rc.params.id, home })))
    }
  },
  {
    method: "POST", path: "/connect/:id/start", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      const { stepUp, home } = parseJson(z.object({ stepUp: StepUpProofSchema, home: CredentialHomeSchema.optional() }), await readBody(rc.request))
      const connect = rc.params.id as string
      const action = WorkspaceStepUpActionSchema.parse(await workspaceCall(rc, ws, "oauth.connect_action", { connect, home }))
      if (action.type !== "connect.start")
        throw new VaultError("internal", "Unexpected connection action.")
      const evidence = await requireWorkspaceStepUp(rc, ws, action, stepUp), state = randomToken(32)
      const started = await workspaceCall(rc, ws, "oauth.connectStart", { connect, state, home }, evidence) as {
        authorizeUrl: string
        stateExpiresAt: number
      }
      await rc.env.DB.prepare("INSERT INTO oauth_states(state_hash,tenant,connect,expires_at,account,membership,initiating_session,security_epoch,intent,target_id,target_revision,client_id,client_revision,dependency_revision) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(await sha256Text(state), ws.workspace.id, connect, started.stateExpiresAt, ws.account.account, ws.membership, ws.account.session, ws.account.securityEpoch, action.intent, action.target, action.targetRevision, action.client, action.clientRevision, action.dependencyRevision).run()
      return json({ authorizeUrl: started.authorizeUrl })
    }
  },
  { method: "POST", path: "/connect/:id/cancel", handler: async (rc, ws) => { assertSameOrigin(rc.request, rc.env); return json(await workspaceCall(rc, ws, "oauth.connectCancel", { connect: rc.params.id })); } },
]

// The provider sends the person's browser back here, so every refusal is a
// page that says what happened and, once the connection is known, links to
// its page to start again from: the state is spent either way.
export const OAUTH_CALLBACK_HEADING = "The connection was not finished"

export async function workspaceOAuthCallback(rc: RequestContext): Promise<Response> {
  const known: { connectPage: string | null } = { connectPage: null }
  try {
    return await finishOAuthCallback(rc, known)
  } catch (error) {
    if (!(error instanceof VaultError)) throw error
    const next = known.connectPage === null ? { url: "/", say: "Open the vault and start the connection again from its page." } : { url: known.connectPage, say: "Open the connection's page and start it again." }
    return errorPage(null, error.status, { error: error.code, message: error.message, next }, OAUTH_CALLBACK_HEADING)
  }
}

async function finishOAuthCallback(rc: RequestContext, known: { connectPage: string | null }): Promise<Response> {
  const state = rc.url.searchParams.get("state")
  if (!state || state.length > 128)
    throw new VaultError("bad_request", "This address carries no connection the vault started.")
  const hash = await sha256Text(state)
  const row = await rc.env.DB.prepare("SELECT s.*,w.slug FROM oauth_states s JOIN workspaces w ON w.id=s.tenant WHERE state_hash=? AND cancelled_at IS NULL").bind(hash).first<{
    tenant: string
    slug: string
    connect: string
    account: string
    initiating_session: string
    security_epoch: number
    expires_at: number
  }>()
  if (!row)
    throw new VaultError("bad_request", "This connection attempt has expired or was already used.")
  known.connectPage = `/w/${row.slug}/c/${row.connect}`
  if (row.expires_at <= Date.now())
    throw new VaultError("bad_request", "This connection attempt has expired or was already used.")
  const scoped = { ...rc, params: { ...rc.params, ws: row.slug } }, ws = await resolveWorkspace(scoped)
  if (ws.account.account !== row.account || ws.account.session !== row.initiating_session || ws.account.securityEpoch !== row.security_epoch)
    throw new VaultError("forbidden", "This connection was started in another sign-in.")
  const consumed = await rc.env.DB.prepare("DELETE FROM oauth_states WHERE state_hash=? AND account=? AND initiating_session=? AND security_epoch=? AND cancelled_at IS NULL").bind(hash, row.account, row.initiating_session, row.security_epoch).run()
  if (consumed.meta.changes !== 1)
    throw new VaultError("bad_request", "This connection attempt has expired or was already used.")
  await workspaceCall(scoped, ws, "oauth.connectFinish", { connect: row.connect, state, code: rc.url.searchParams.get("code"), error: rc.url.searchParams.get("error") })
  return redirect(`${rc.env.VAULT_ORIGIN}/w/${ws.workspace.slug}/c/${row.connect}`)
}
