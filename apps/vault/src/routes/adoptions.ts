// Adoption device routes (`mehen adopt`): start a batch, upload sealed
// items into it, poll it and cancel it, and send the machine's value-free
// plan index. Each enters one workspace operation.
import { AdoptionCreate, AdoptionIndex, AdoptionUpload } from "@mehen/protocol"
import { json, parseJson } from "../http.ts"
import type { Route } from "../router.ts"
import { type Handler, deviceRequest } from "./context.ts"

export const adoptionsRoutes: Route<Handler>[] = [
  {
    method: "POST", path: "/v1/adoptions", handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("adoption.create", parseJson(AdoptionCreate, device.body)), 201)
    },
  },
  {
    method: "POST", path: "/v1/adoptions/index", handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("adoption.index", parseJson(AdoptionIndex, device.body)))
    },
  },
  {
    method: "POST", path: "/v1/adoptions/:id/items", handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("adoption.upload", { adoption: rc.params.id, ...parseJson(AdoptionUpload, device.body) }))
    },
  },
  {
    method: "GET", path: "/v1/adoptions/:id", handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("adoption.status", { adoption: rc.params.id, wait: rc.url.searchParams.get("wait") === "1" }))
    },
  },
  {
    method: "POST", path: "/v1/adoptions/:id/cancel", handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("adoption.cancel", { adoption: rc.params.id }))
    },
  },
]
