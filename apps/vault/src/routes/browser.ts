// POST /v1/fill: one field of a credential, sealed to the machine's own
// throwaway key, for one web page (areas/browser-workspace.ts).

import { FillRequestSchema, FillResponseSchema } from "@mehen/protocol"
import { json, parseJson } from "../http.ts"
import type { Route } from "../router.ts"
import { type Handler, deviceRequest } from "./context.ts"

export const browserRoutes: Route<Handler>[] = [
  { method: "POST", path: "/v1/fill", handler: async (rc) => {
    const device = await deviceRequest(rc)
    return json(FillResponseSchema.parse(await device.call("browser.fill", parseJson(FillRequestSchema, device.body))))
  } },
]
