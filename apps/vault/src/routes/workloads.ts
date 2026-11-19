// Workload routes for proof-signed machines: only the parent device's own
// key manages its workloads (packages/protocol/src/workload.ts).
import { WorkloadCreateSchema, WorkloadListSchema, WorkloadRenewSchema, WorkloadViewSchema } from "@mehen/protocol"
import { json, parseJson } from "../http.ts"
import type { Route } from "../router.ts"
import { type Handler, deviceRequest } from "./context.ts"

export const workloadRoutes: Route<Handler>[] = [
  { method: "POST", path: "/v1/workloads", handler: async (rc) => {
    const device = await deviceRequest(rc)
    return json(WorkloadViewSchema.parse(await device.call("workloads.create", parseJson(WorkloadCreateSchema, device.body))), 201)
  } },
  { method: "GET", path: "/v1/workloads", handler: async (rc) => json(WorkloadListSchema.parse(await (await deviceRequest(rc)).call("workloads.list"))) },
  { method: "GET", path: "/v1/workloads/:id", handler: async (rc) => json(WorkloadViewSchema.parse(await (await deviceRequest(rc)).call("workloads.get", { workload: rc.params.id ?? "" }))) },
  { method: "POST", path: "/v1/workloads/:id/renew", handler: async (rc) => {
    const device = await deviceRequest(rc)
    return json(WorkloadViewSchema.parse(await device.call("workloads.renew", { ...parseJson(WorkloadRenewSchema, device.body), workload: rc.params.id ?? "" })))
  } },
  { method: "DELETE", path: "/v1/workloads/:id", handler: async (rc) => json(WorkloadViewSchema.parse(await (await deviceRequest(rc)).call("workloads.revoke", { workload: rc.params.id ?? "" }))) },
]
