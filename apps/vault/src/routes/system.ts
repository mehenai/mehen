// Health, the public seal key, and the device panic buttons.

import { PUBLIC_SEAL_KEY_PATH } from "@mehen/protocol/api"
import { json } from "../http.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"
import type { Route } from "../router.ts"
import { sealPublicJwk } from "../seal-key.ts"
import { type Handler, deviceRequest, workspaceCall } from "./context.ts"

export const systemRoutes: Route<Handler>[] = [
  { method: "POST",path: "/v1/devices/self/revoke",handler: async rc => json(await (await deviceRequest(rc)).call("devices.revokeSelf")) },
  { method: "GET", path: "/healthz", handler: async () => json({ ok: true }) },
  {
    method: "GET",
    path: PUBLIC_SEAL_KEY_PATH,
    handler: async ({ env }) => json(await sealPublicJwk(env), 200, { "cache-control": "public, max-age=300" }),
  },
  {
    method: "GET",
    path: "/v1/me",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("devices.me"))
    },
  },
  {
    method: "POST",
    path: "/v1/freeze",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("tenant.freeze"))
    },
  },
]

export const workspaceSystemRoutes: Route<WorkspaceHandler>[] = [
  { method: "POST", path: "/freeze", handler: async (rc, workspace) => json(await workspaceCall(rc, workspace, "access.freeze", {})) },
  { method: "GET", path: "/audit", handler: async (rc, workspace) => {
    const { searchParams } = rc.url
    return json(await workspaceCall(rc, workspace, "tenant.audit", {
      ...(searchParams.has("cursor") ? { cursor: searchParams.get("cursor") } : {}),
      ...(searchParams.has("before") ? { before: Number(searchParams.get("before")) } : {}),
      ...(searchParams.has("item") ? { item: searchParams.get("item") } : {}),
      ...(searchParams.has("limit") ? { limit: Number(searchParams.get("limit")) } : {}),
    }))
  } },
]
