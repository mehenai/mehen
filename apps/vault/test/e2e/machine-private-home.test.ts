// A machine accepted without private credentials asks for a credential in
// its owner's private home, which mehen request and mehen connect choose
// when no home is given. Through the real Worker both answer forbidden with
// the reason and the home to ask in instead, not "No such object.", and
// nothing is created; the workspace home still works.
import { expect, it } from "vitest"
import { body, workJourney } from "./workspace-journey.ts"

const REFUSAL = {
  error: "forbidden",
  message: "This machine was accepted without private credentials, so it cannot ask for a credential in its owner's private home.",
  next: { say: "Ask again in a project the person can edit, or in the workspace if they are a workspace owner or admin; otherwise ask the person to tick the private credentials box on this machine's page under Machines, then ask again." },
}

it("a machine without private credentials asking in its owner's private home is refused forbidden with what to ask instead", async () => {
  const f = await workJourney()
  const start = await f.startMachine(f.work)
  await body(await f.acceptMachine(f.alex, f.work, start, false))
  const pending = { keys: start.keys, device: start.started.enrolment, workspace: f.work }
  const active = await body<{ device: string; scope: { privateCredentials: boolean } }>(await f.deviceCall(pending, `/v1/enrol/${start.started.enrolment}`, undefined, "enrol"))
  expect(active.scope.privateCredentials).toBe(false)
  const machine = { keys: start.keys, device: active.device, workspace: f.work }
  const asks = [
    ["/v1/intakes", { kind: "api-key", provider: "openai", slug: "openai-private", reason: "model", home: "private" }],
    ["/v1/connect", { provider: "google-gmail", client: "google-client", slug: "gmail-private", reason: "triage", home: "private" }],
  ] as const
  for (const [path, input] of asks) {
    const refused = await f.deviceCall(machine, path, input)
    expect(refused.status).toBe(403)
    expect(refused.headers.get("Mehen-Error")).toBe("1")
    expect(await refused.json()).toEqual(REFUSAL)
  }
  expect(await f.sql<{ n: number }>(f.work, "SELECT count(*) AS n FROM workspace_credential_requests")).toEqual([{ n: 0 }])
  // The owner's machine may still ask in the workspace home.
  await body(await f.deviceCall(machine, "/v1/intakes", { ...asks[0][1], home: "workspace" }), 201)
})
