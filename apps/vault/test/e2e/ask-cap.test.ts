// A machine's 20 open asks through the real Worker, intakes and connects
// counted together: a connect past them is refused rate_limited with the
// link where the person decides them, and nothing is opened.
import { expect, it } from "vitest"
import { credentialStart } from "../../src/ui/client/workspace-logic.ts"
import { body } from "./workspace-journey.ts"
import { WS, fillIntake, setup } from "./ui-projects-journey.ts"

it("a connect past a machine's 20 open intakes and connects is refused with the workspace's home, and opens nothing", async () => {
  const f = await setup(), home = { kind: "workspace" } as const
  // The workspace's Google OAuth client, made through a person's own connect.
  const start = credentialStart("google-gmail", "connect", "gmail-person", home)
  const created = await body<{ connect: string; intake?: { intake: string } }>(await f.request(`/api/w/${WS}${start.path}`, f.alex, start.body), 201)
  if (created.intake) await fillIntake(f, f.alex, created.intake.intake, home)
  const machine = await f.machine(f.alex, f.work)
  for (let n = 0; n < 10; n++) {
    await body(await f.deviceCall(machine, "/v1/intakes", { kind: "api-key", provider: "openai", slug: `openai-${n}`, reason: "model", home: "workspace" }), 201)
    await body(await f.deviceCall(machine, "/v1/connect", { provider: "google-gmail", slug: `gmail-${n}`, reason: "mail", home: "workspace" }))
  }
  const opened = async () => (await f.sql<{ n: number }>(f.work, "SELECT count(*) AS n FROM workspace_credential_requests WHERE status='open'"))[0]!.n
  const before = await opened()
  const refused = await f.deviceCall(machine, "/v1/connect", { provider: "google-gmail", slug: "gmail-overflow", reason: "mail", home: "workspace" })
  expect(refused.status).toBe(429)
  expect(await refused.json()).toEqual({ error: "rate_limited", message: "This machine already has 20 open asks.", next: { url: `https://vault.test/w/${WS}/`, say: "Ask the person to decide this machine's open asks at the link, then ask for the rest." } })
  expect(await opened()).toBe(before)
  expect(await f.sql(f.work, "SELECT id FROM workspace_credential_requests WHERE slug='gmail-overflow'")).toEqual([])
})
