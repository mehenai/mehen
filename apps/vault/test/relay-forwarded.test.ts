// Mehen-Forwarded on /v1/relay refusals: "no" for every refusal before the
// vault sent anything upstream, so a machine may resend a write; "yes" once
// it may have gone, so it checks first. A relayed answer carries neither.
import { afterEach, expect, it } from "vitest"
import { FORWARDED_HEADER, UPSTREAM_HEADER } from "@mehen/protocol/api"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { fetchWorker } from "./helpers.ts"
import { workJourney } from "./e2e/workspace-journey.ts"

const relay = (overrides: Record<string, unknown> = {}) => ({ item: "openai-main", method: "GET", url: "https://api.openai.com/v1/models", headers: [], ...overrides })

afterEach(() => setUpstreamFetch(null))

it("marks a refusal before forwarding no, one after yes, and a relayed answer neither", async () => {
  const f = await workJourney(), machine = await f.machine(f.alex, f.work)
  await f.credential(f.alex, f.work, "openai-main", { kind: "workspace" })
  const sends: string[] = []
  setUpstreamFetch(async (request) => { sends.push(request.method); return new Response("ok") })
  const answered = await f.deviceCall(machine, "/v1/relay", relay())
  expect([answered.status, answered.headers.get(UPSTREAM_HEADER), answered.headers.has(FORWARDED_HEADER)]).toEqual([200, "1", false])
  // Refused before anything left: no proof, an unbound host, a malformed body.
  const unsigned = await fetchWorker("/v1/relay", { method: "POST", body: JSON.stringify(relay()) })
  const unbound = await f.deviceCall(machine, "/v1/relay", relay({ method: "POST", url: "https://evil.example/v1/x" }))
  const malformed = await f.deviceCall(machine, "/v1/relay", { item: "openai-main", method: "POST" })
  for (const [name, refused] of [["unsigned", unsigned], ["unbound", unbound], ["malformed", malformed]] as const) {
    expect([refused.status >= 400, refused.headers.get("mehen-error"), refused.headers.get(FORWARDED_HEADER)], name).toEqual([true, "1", "no"])
  }
  expect(sends).toEqual(["GET"])
  // Refused after the request may have gone upstream.
  setUpstreamFetch(async (request) => { sends.push(request.method); throw new Error("reset") })
  const failed = await f.deviceCall(machine, "/v1/relay", relay())
  expect([failed.status, failed.headers.get("mehen-error"), failed.headers.get(FORWARDED_HEADER), (await failed.json() as { error: string }).error]).toEqual([502, "1", "yes", "upstream_failed"])
  setUpstreamFetch(async () => new Response("x", { headers: { "content-length": String(64 * 1024 * 1024) } }))
  const huge = await f.deviceCall(machine, "/v1/relay", relay())
  expect([huge.headers.get(FORWARDED_HEADER), (await huge.json() as { error: string }).error]).toEqual(["yes", "too_large"])
})
