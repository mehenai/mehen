// A resume through the mandate routes (routes/mandates.ts): planned as
// { stepUp: null } and made without a passkey when the signer paused it,
// and a passkey asked when an admin did, over the signer's pause included. Its own file, since the workspace
// fixture's ids, and so its object's storage, are fixed.
import { expect, it } from "vitest"
import { env } from "cloudflare:workers"
import { runInDurableObject } from "cloudflare:test"
import type { MandateChanged } from "@mehen/protocol"
import { createWorkspaceFixture } from "./workspace-fixtures.ts"
import { seedAccessStateForTests } from "./access-test-support.ts"
import { workspaceBrowser } from "./l2-helpers.ts"
import { setSetting } from "../src/vault/areas/workspace-runtime.ts"
import { mandateOp, signMandate, terms } from "./mandates-test-support.ts"

it("resumes without a passkey a mandate its signer paused, and asks one for a mandate an admin paused, after the signer or not", async () => {
  const f = await createWorkspaceFixture()
  const vault = env.TENANT_VAULT.getByName(f.workspaces.work)
  const signPaused = (...pausers: string[]) => runInDurableObject(vault, async (instance) => {
    const id = (await signMandate(instance.context, "owner", terms())).mandate.id
    for (const [i, pauser] of pausers.entries()) await mandateOp(instance.context, "mandates.pause", pauser, { id, rev: i + 1 })
    return id
  })
  await runInDurableObject(vault, (instance) => {
    seedAccessStateForTests(instance.context, f.state)
    setSetting(instance.context, "workspace", { id: f.workspaces.work, slug: "northwind", name: "Work" })
  })
  const browser = workspaceBrowser(f.env, f.cookie, "northwind")

  const mine = await signPaused("owner")
  const planned = await browser.post("/mandates/action", { op: "resume", id: mine, rev: 2 })
  expect([planned.status, await planned.json()]).toEqual([200, { stepUp: null }])
  expect((await browser.post(`/mandates/${mine}/resume`, { rev: 2 }, { origin: "https://elsewhere.example" })).status).toBe(403)
  const resumed = await browser.post(`/mandates/${mine}/resume`, { rev: 2 })
  expect(resumed.status).toBe(200)
  expect(((await resumed.json()) as MandateChanged).mandate).toMatchObject({ state: "active", rev: 3, signerCurrent: true })

  for (const pausers of [["admin"], ["owner", "admin"]]) {
    const theirs = await signPaused(...pausers)
    const rev = pausers.length + 1
    const asked = await browser.post("/mandates/action", { op: "resume", id: theirs, rev })
    expect(await asked.json()).toEqual({ type: "mandate.resume", mandate: theirs, digest: expect.any(String), rev, from: "paused" })
    const refused = await browser.post(`/mandates/${theirs}/resume`, { rev })
    expect([refused.status, await refused.json()]).toEqual([403, { error: "forbidden", message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." }])
  }
})
