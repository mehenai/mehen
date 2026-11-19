// POST /v1/push (design push-providers 3.1): the DO checks the ask and hands
// back only the via's preview reads, which this Worker makes, so the DO
// never waits on a provider; then the DO files the approval. Once a human
// approves, sendPush hands the value from the DO to the provider here and
// reports what the provider said.

import { compareVersions } from "@mehen/protocol/version"
import { PushRequest } from "@mehen/protocol/api"
import type { Env } from "../env.ts"
import { VaultError, json, parseJson } from "../http.ts"
import { PUSH_CLI, cliVersionOf } from "../cli-version.ts"
import { pushPreview, pushWrite } from "../push/adapters.ts"
import type { Route } from "../router.ts"
import { invokeVault } from "../vault/client.ts"
import type { PushHandOut, PushPrepared } from "../vault/areas/pushes.ts"
import { type Handler, deviceRequest } from "./context.ts"

const MAX_PUSH_REQUEST_BYTES = 4096
const SYSTEM = { kind: "system" as const, reason: "push" }

// provider_refused reaches only a mehen that knows it (ruling X1); an older
// or unknown one reads upstream_failed with the same sentence.
export function pushErrorFor(error: unknown, cliVersion: string | null): unknown {
  if (!(error instanceof VaultError) || error.code !== "provider_refused") return error
  if (cliVersion !== null && compareVersions(cliVersion, PUSH_CLI) >= 0) return error
  const { providerStatus: _status, ...extra } = error.extra
  return new VaultError("upstream_failed", error.message, extra)
}

export const pushRoutes: Route<Handler>[] = [
  {
    method: "POST",
    path: "/v1/push",
    handler: async (rc) => {
      const cliVersion = cliVersionOf(rc.request.headers.get("user-agent"))
      try {
        const device = await deviceRequest(rc, MAX_PUSH_REQUEST_BYTES)
        const input = parseJson(PushRequest, device.body)
        const prepared = (await device.call("push.prepare", input)) as PushPrepared
        const allowed = new Set(prepared.allowed.map((call) => `${call.method} ${call.url}`))
        const preview = await pushPreview(prepared.destination, prepared.via, (call) => allowed.has(`${call.method} ${call.url}`))
        return json(await invokeVault(rc.env, device.tenant, { op: "push.ask", input: { ticket: prepared.ticket, preview }, auth: SYSTEM }))
      } catch (error) {
        throw pushErrorFor(error, cliVersion)
      }
    },
  },
]

// One approved push, start to end: the DO's last checks and the value's
// hand-out, the provider's write here, and its outcome back to the DO. A
// push the DO no longer sends was recorded not_sent there.
export async function sendPush(env: Env, tenant: string, target: { push: string } | { approval: string }): Promise<void> {
  const handOut = (await invokeVault(env, tenant, { op: "push.execute", input: target, auth: SYSTEM })) as PushHandOut
  if (!handOut.sent) return
  let record: { state: "done" | "failed" | "unknown"; outcome: string | null; providerStatus: number | null }
  try {
    const written = await pushWrite(handOut.destination, handOut.value, handOut.via)
    record = { state: "done", outcome: written.outcome, providerStatus: written.providerStatus }
  } catch (error) {
    // upstream_failed: nothing came back that says whether it was written.
    const known = error instanceof VaultError && error.code !== "upstream_failed"
    record = { state: known ? "failed" : "unknown", outcome: null, providerStatus: error instanceof VaultError && typeof error.extra.providerStatus === "number" ? error.extra.providerStatus : null }
  }
  await invokeVault(env, tenant, { op: "push.record", input: { push: handOut.push, ...record }, auth: SYSTEM })
}

// The decide route and the rotation route wait this long for the provider
// before answering; the push carries on after.
export const PUSH_WAIT_MS = 20_000
export async function sendPushes(ctx: ExecutionContext, env: Env, tenant: string, targets: ({ push: string } | { approval: string })[]): Promise<void> {
  const sending = Promise.allSettled(targets.map((target) => sendPush(env, tenant, target)))
  ctx.waitUntil(sending)
  let timer: ReturnType<typeof setTimeout> | undefined
  await Promise.race([sending, new Promise((resolve) => { timer = setTimeout(resolve, PUSH_WAIT_MS) })])
  clearTimeout(timer)
}
