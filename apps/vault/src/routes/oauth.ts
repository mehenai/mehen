// Credential-connection OAuth is separate from account sign-in OIDC.
import { WorkspaceConnectCreate } from "@mehen/protocol/api"
import { json, parseJson } from "../http.ts"
import type { Route } from "../router.ts"
import { type Handler, deviceRequest } from "./context.ts"
import { workspaceOAuthCallback } from "./oauth-workspace.ts"
const LONG_POLL_MS = 25_000

export const oauthRoutes: Route<Handler>[] = [
  {
    method: "POST",
    path: "/v1/connect",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("oauth.connectCreate", parseJson(WorkspaceConnectCreate, device.body)))
    },
  },
  {
    method: "GET",
    path: "/v1/connect/:id",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      const waitMs = rc.url.searchParams.get("wait") === "1" ? LONG_POLL_MS : 0
      return json(await device.call("oauth.connectStatus", { connect: rc.params.id, waitMs }))
    },
  },
  {
    method:"POST",path:"/v1/connect/:id/cancel",handler:async rc=>{
      const device=await deviceRequest(rc)
      return json(await device.call("oauth.connectCancel",{connect:rc.params.id}))
    },
  },
  { method: "GET",path: "/oauth/callback",handler: workspaceOAuthCallback },
]
