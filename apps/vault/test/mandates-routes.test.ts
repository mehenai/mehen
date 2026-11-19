// Mandate routes (routes/mandates.ts) through the real directory, session and
// DO authority: a list, the planned action, a sign or resume refused before
// any passkey with a stale or missing proof, a cross-site post, and the
// routes gone with MANDATES off, a machine's too.
import { expect, it } from "vitest"
import { env } from "cloudflare:workers"
import { runInDurableObject } from "cloudflare:test"
import { createWorkspaceFixture } from "./workspace-fixtures.ts"
import { seedAccessStateForTests } from "./access-test-support.ts"
import { workspaceBrowser } from "./l2-helpers.ts"
import { setSetting } from "../src/vault/areas/workspace-runtime.ts"
import { terms } from "./mandates-test-support.ts"
import { createProof } from "@mehen/protocol"
import { PROOF_HEADER } from "../src/routes/context.ts"
import { ORIGIN, fetchWorkspaceWorker } from "./helpers.ts"

const PROOF = { nonce: "unchecked", assertion: {} }
it("serves the mandate routes under the workspace prefix, behind MANDATES", async () => {
  const f = await createWorkspaceFixture()
  await runInDurableObject(env.TENANT_VAULT.getByName(f.workspaces.work), async (instance) => {
    seedAccessStateForTests(instance.context, f.state)
    setSetting(instance.context, "workspace", { id: f.workspaces.work, slug: "northwind", name: "Work" })
  })
  const browser = workspaceBrowser(f.env, f.cookie, "northwind")
  const list = await browser.get("/mandates")
  expect(list.status).toBe(200)
  expect(await list.json()).toEqual({ mandates: [], proposals: [] })
  const planned = await browser.post("/mandates/action", { op: "sign", terms: terms() })
  expect(planned.status).toBe(200)
  expect(await planned.json()).toEqual({ type: "mandate.sign", device: "dev_owner", digest: expect.any(String) })
  expect((await browser.post("/mandates", { terms: terms() })).status).toBe(400)
  expect((await browser.post("/mandates", { terms: terms(), stepUp: PROOF }, { origin: "https://elsewhere.example" })).status).toBe(403)
  expect((await browser.post("/mandates", { terms: terms(), stepUp: PROOF })).status).toBe(403)
  const candidates = await browser.get("/mandate-candidates?device=dev_owner")
  expect([candidates.status, await candidates.json()]).toEqual([200, { items: [] }])
  expect((await browser.get("/mandate-candidates")).status).toBe(400)
  expect((await browser.get("/mandate-candidates?device=dev_member")).status).toBe(404)
  const ask = await browser.get("/mandate-asks/apr_absent0000000000000")
  expect([ask.status, await ask.json()]).toEqual([404, { error: "not_found", message: "No such ask." }])
  const cover = await browser.get("/mandate-covers/apr_absent0000000000000")
  expect([cover.status, await cover.json()]).toEqual([404, { error: "not_found", message: "No such ask." }])
  expect((await browser.get("/mandates/mdt_absent00000000000000")).status).toBe(404)
  const proposal = await browser.get("/mandate-proposals/mdp_absent00000000000000")
  expect([proposal.status, await proposal.json()]).toEqual([404, { error: "not_found", message: "No such proposal." }])
  expect((await browser.post("/mandates/mdt_absent00000000000000/pause", { rev: 0 })).status).toBe(400)
  const off = workspaceBrowser({ ...f.env, MANDATES: "tn_elsewhere0001" }, f.cookie, "northwind")
  for (const path of ["/mandates", "/mandate-candidates?device=dev_owner", "/mandate-asks/apr_absent0000000000000", "/mandate-covers/apr_absent0000000000000"]) {
    const gone = await off.get(path)
    expect([path, gone.status, await gone.json()]).toEqual([path, 404, { error: "not_found", message: "No such route." }])
  }
})

it("answers a machine's mandate reads as an unknown route with MANDATES off, whatever the query", async () => {
  const f = await createWorkspaceFixture()
  const off = { ...f.env, MANDATES: "tn_elsewhere0001" }
  for (const path of ["/v1/mandates?x=1", "/v1/mandates/asked?x=1", "/v1/mandates/mdt_absent00000000000000?x=1", "/v1/mandates/mdt_absent00000000000000/uses?x=1"]) {
    const proof = await createProof({ deviceId: "dev_owner", sign: async () => new Uint8Array(64) }, { method: "GET", url: `${ORIGIN}${path}` }, { tenant: f.workspaces.work })
    const answer = await fetchWorkspaceWorker(off, path, { headers: { [PROOF_HEADER]: proof } })
    expect([path, answer.status, await answer.json()]).toEqual([path, 404, { error: "not_found", message: "No such route." }])
  }
})
