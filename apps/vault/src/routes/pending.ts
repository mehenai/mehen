import { json } from "../http.ts"
import type { Route } from "../router.ts"
import { type Handler, deviceRequest } from "./context.ts"

export const pendingRoutes: Route<Handler>[] = [
  { method: "GET",path: "/v1/pending",handler: async rc => json(await (await deviceRequest(rc)).call("pending.list")) },
]
