// A machine polls only its own workspace approval, and asks for and reads
// only its own bundles.
import { z } from "zod"
import { ApprovalBundleCreate } from "@mehen/protocol/api"
import { VaultError, json, parseJson } from "../http.ts"
import type { Route } from "../router.ts"
import { type Handler, deviceRequest } from "./context.ts"

export const approvalsRoutes: Route<Handler>[] = [
  {
    method: "GET",
    path: "/v1/approvals/:id",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("approvals.status", { id: rc.params["id"], wait: rc.url.searchParams.get("wait") === "1" }))
    },
  },
  {
    method: "POST",
    path: "/v1/approvals/bundles",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      // Each request is refused as /v1/relay refuses one that claims a policy mode or an environment.
      const raw = parseJson(z.object({ requests: z.array(z.unknown()) }).loose(), device.body)
      if (raw.requests.some((request) => typeof request === "object" && request !== null && ["policyMode", "env", "environment"].some((field) => field in request))) throw new VaultError("bad_request", "A relay request cannot select a policy mode or claim an environment.", { next: { say: "Remove policyMode, env and environment from each request in the bundle." } })
      return json(await device.call("approvals.bundle", parseJson(ApprovalBundleCreate, device.body)))
    },
  },
  {
    method: "GET",
    path: "/v1/approvals/bundles/:id",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("approvals.bundle_status", { id: rc.params["id"], wait: rc.url.searchParams.get("wait") === "1" }))
    },
  },
]
