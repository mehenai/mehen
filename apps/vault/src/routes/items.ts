// Credential device routes enter only workspace operations.
import { WorkspaceIntakeCreate } from "@mehen/protocol/api"
import { json, parseJson } from "../http.ts"
import type { Route } from "../router.ts"
import { type Handler, deviceRequest } from "./context.ts"

function listFilters(url: URL): { tag?: string; kind?: string; provider?: string } {
  const out: { tag?: string; kind?: string; provider?: string } = {}
  for (const key of ["tag", "kind", "provider"] as const) {
    const value = url.searchParams.get(key)
    if (value) out[key] = value
  }
  return out
}

export const itemsRoutes: Route<Handler>[] = [
  // ------------------------------------------------------------ devices
  {
    method: "GET",
    path: "/v1/items",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("items.list", listFilters(rc.url)))
    },
  },
  {
    method: "GET",
    path: "/v1/items/:slug",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("items.describe", { slug: rc.params.slug }))
    },
  },
  {
    method: "POST",
    path: "/v1/intakes",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("intake.create", parseJson(WorkspaceIntakeCreate, device.body)), 201)
    },
  },
  {
    method: "GET",
    path: "/v1/intakes/:id",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("intake.status", { intake: rc.params.id, wait: rc.url.searchParams.get("wait") === "1" }))
    },
  },

  {
    method:"POST",path:"/v1/intakes/:id/cancel",handler:async rc=>{
      const device=await deviceRequest(rc)
      return json(await device.call("intake.cancel",{intake:rc.params.id}))
    },
  },

]
