// POST /v1/relay: the DO authorises and hands back the injection material;
// this Worker makes the upstream call so the DO never waits on upstream
// latency.

import { z } from "zod"
import { RelayRequest } from "@mehen/protocol/api"
import { base64UrlDecode } from "@mehen/protocol"
import { FORWARDED_HEADER } from "@mehen/protocol/api"
import { VaultError, parseJson, responseFor } from "../http.ts"
import { type RelayMaterial, forwardRelay } from "../relay/forward.ts"
import type { Route } from "../router.ts"
import { invokeVault } from "../vault/client.ts"
import { type Handler, deviceRequest } from "./context.ts"

// RelayRequest allows a 14,000,000 character base64url body; this leaves
// room for the JSON around it.
export const MAX_RELAY_REQUEST_BYTES = 14 * 1024 * 1024

export const relayRoutes: Route<Handler>[] = [
  {
    method: "POST",
    path: "/v1/relay",
    handler: async (rc) => {
      const device = await deviceRequest(rc, MAX_RELAY_REQUEST_BYTES)
      const raw = parseJson(z.unknown(), device.body)
      if (typeof raw === "object" && raw !== null && ["policyMode", "env", "environment"].some((field) => field in raw)) throw new VaultError("bad_request", "A relay request cannot select a policy mode or claim an environment.", { next: { say: "Remove policyMode, env and environment from the relay request body." } })
      const input = parseJson(RelayRequest, device.body)
      const material = (await device.call("relay.authorise", input)) as RelayMaterial
      let body: Uint8Array<ArrayBuffer> | null = null
      if (input.body !== undefined && input.body !== "") {
        try {
          body = base64UrlDecode(input.body)
        } catch {
          throw new VaultError("bad_request", "The relay body must be base64url.")
        }
      }
      const host = new URL(material.url).host
      try {
        return await forwardRelay(material, body, {
          onEcho: (items) => {
            rc.ctx.waitUntil(
              invokeVault(rc.env, device.tenant, { op: "relay.echo", input: { items, host, ...(material.workspaceAudit?{workspaceAudit:material.workspaceAudit}:{}) }, auth: { kind: "system", reason: "relay echo" } }).catch(() => undefined),
            )
          },
        })
      } catch (error) {
        // From here the request may have gone upstream: never marked as
        // refused before forwarding (markRelayRefusal).
        if (!(error instanceof VaultError)) console.error(JSON.stringify({ at: "relay.forward", error: error instanceof Error ? error.name : "unknown" }))
        const refused = responseFor(error)
        refused.headers.set(FORWARDED_HEADER, "yes")
        return refused
      }
    },
  },
]
