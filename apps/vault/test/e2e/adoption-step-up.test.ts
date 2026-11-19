// `mehen adopt` over HTTP: the machine's /v1/adoptions routes and the
// reviewer's /api/w/:ws/adoptions routes, with the one "adoption.approve"
// passkey over the whole batch. The account-wide step-up never signs one.
import { expect, it } from "vitest"
import { ADOPTION_LIMITS, adoptionDigest, adoptionSealContext, importSealPublicKey, seal, type AdoptionCreated, type AdoptionKeptOpen, type AdoptionStatus, type AdoptionUploaded, type WorkspaceAdoptionInventory, type WorkspaceAdoptionView, type WorkspaceStepUpAction } from "@mehen/protocol"
import { adoptionApproveAction, adoptionDecisions } from "../../src/ui/client/pages/workspace-adopt-logic.ts"
import { body, refusal, workJourney, type Machine } from "./workspace-journey.ts"

const VALUE = "sk-proj-adoption-journey-not-a-real-secret"

async function uploadOne(f: Awaited<ReturnType<typeof workJourney>>, machine: Machine, created: AdoptionCreated, ref: string, slug: string) {
  const key = await seal(await importSealPublicKey(created.sealKey.jwk), VALUE, adoptionSealContext(created.adoption, ref, "key"))
  const item = { ref, slug, kind: "api-key", provider: "openai", binding: null, injection: null, home: { kind: "workspace" }, tags: [], publicFields: {}, sealed: { key }, sources: [{ path: "/srv/app/.env", variable: "OPENAI_API_KEY", stale: [] }], repo: null }
  return body<AdoptionUploaded>(await f.deviceCall(machine, `/v1/adoptions/${created.adoption}/items`, { items: [item] }))
}

it("adoption.approve: the account step-up never starts one, the workspace one only for a batch this person may review", async () => {
  const f = await workJourney()
  const action: WorkspaceStepUpAction = { type: "adoption.approve", adoption: "adp_none", digest: "x", repoints: 0 }
  const before = await f.snapshot(f.work)
  await refusal(await f.request(`/api/w/${f.work.slug}/stepup/start`, f.alex, { action }), 404, { error: "not_found", message: "No such adoption." })
  await refusal(await f.request("/api/account/stepup/start", f.alex, { action }), 404, { error: "not_found", message: "No such adoption." })
  expect(await f.snapshot(f.work)).toEqual(before)
})

it("adopt over HTTP: a machine fills a batch, the person approves it with one passkey, a retry answers the same", async () => {
  const f = await workJourney()
  const machine = await f.machine(f.alex, f.work)
  expect((await body<{ capabilities: { sealedEnvImport: boolean } }>(await f.deviceCall(machine, "/v1/me"))).capabilities.sealedEnvImport).toBe(true)
  const created = await body<AdoptionCreated>(await f.deviceCall(machine, "/v1/adoptions", { machine: "office", expectedItems: 1 }), 201)
  expect(created).toEqual({ adoption: expect.stringMatching(/^adp_/), url: `${f.env.VAULT_ORIGIN}/w/northwind/b/${created.adoption}`, expiresAt: expect.any(String), sealKey: await body(await f.request("/v1/seal-key")), limits: ADOPTION_LIMITS })
  expect(await uploadOne(f, machine, created, "a001", "adopted-key")).toEqual({ adoption: created.adoption, accepted: ["a001"], refused: [] })
  const pending = await body<{ pending: { view: string; detail?: { kind: string; id: string; items?: number } }[] }>(await f.deviceCall(machine, "/v1/pending"))
  expect(pending.pending.find(ask => ask.detail?.id === created.adoption)?.detail).toMatchObject({ kind: "adoption", items: 1 })
  expect(await body<AdoptionStatus>(await f.deviceCall(machine, `/v1/adoptions/${created.adoption}`))).toMatchObject({ status: "open", machines: [{ name: "office", items: 1 }] })

  const path = `/api/w/${f.work.slug}/adoptions/${created.adoption}`
  const view = await body<WorkspaceAdoptionView>(await f.request(path, f.alex))
  expect(view.items).toEqual([expect.objectContaining({ ref: "a001", slug: "adopted-key", secrets: [{ name: "key", length: VALUE.length, prefix: "sk-proj-", fingerprint: expect.any(String), box: expect.any(String) }] })])
  expect(JSON.stringify(view)).not.toContain(VALUE)
  // The review page reads the same view; an unknown batch is not found.
  const shown = await f.request(`/w/${f.work.slug}/b/${created.adoption}`, f.alex, undefined, { accept: "text/html" })
  const html = await shown.text()
  expect(shown.status).toBe(200)
  expect(html).toContain('data-ref="a001"')
  expect(html).toContain('data-action="approve-adoption"')
  expect(html).not.toContain(VALUE)
  expect((await f.request(`/w/${f.work.slug}/b/adp_absent0001`, f.alex, undefined, { accept: "text/html" })).status).toBe(404)
  // The page's own decisions and action: an explicit store, over the digest a store-only page signed.
  const built = adoptionDecisions(created.adoption, view.items, new Map([["a001", { include: true, home: "workspace" }]]))
  if (!built.ok) throw new Error(built.error.message)
  const { decisions } = built
  expect(decisions).toEqual([{ ref: "a001", include: true, home: { kind: "workspace" }, action: "store" }])
  const action = await adoptionApproveAction(created.adoption, view.items, decisions)
  expect(action.digest).toBe(await adoptionDigest(created.adoption, view.items, [{ ref: "a001", include: true, home: { kind: "workspace" } }]))
  // A passkey over another digest is refused before anything is stored.
  const stale = await f.signed(`${path}/approve`, f.alex, { decisions }, { ...action, digest: "a".repeat(43) }, f.work.slug)
  expect(stale.status).toBe(403)
  expect(await f.sql(f.work, "SELECT id FROM items WHERE slug='adopted-key'")).toEqual([])
  const approved = await body<AdoptionStatus>(await f.signed(`${path}/approve`, f.alex, { decisions }, action, f.work.slug))
  expect(approved).toMatchObject({ status: "approved", created: [{ ref: "a001", slug: "adopted-key" }] })
  const [item] = await f.sql<{ id: string }>(f.work, "SELECT id FROM items WHERE slug='adopted-key'")
  expect(item).toBeDefined()
  expect(await body(await f.request(`${path}/approve`, f.alex, { decisions, stepUp: { nonce: "spent", assertion: {} } }))).toEqual(approved)
  expect(await body<AdoptionStatus>(await f.deviceCall(machine, `/v1/adoptions/${created.adoption}?wait=1`))).toEqual(approved)
  expect(await f.sql(f.work, "SELECT * FROM adoption_secrets")).toEqual([])
})

it("adopt over HTTP: an oversize chunk is refused, a cancelled batch takes nothing more, and a restricted account cannot approve", async () => {
  const f = await workJourney()
  const machine = await f.machine(f.alex, f.work)
  const created = await body<AdoptionCreated>(await f.deviceCall(machine, "/v1/adoptions", { machine: "office", expectedItems: 1 }), 201)
  const huge = await f.deviceCall(machine, `/v1/adoptions/${created.adoption}/items`, { items: [], padding: "x".repeat(1_100_000) })
  expect(huge.status).toBe(413)
  await uploadOne(f, machine, created, "a001", "restricted-key")
  const path = `/api/w/${f.work.slug}/adoptions/${created.adoption}`
  const view = await body<WorkspaceAdoptionView>(await f.request(path, f.alex))
  const decisions = [{ ref: "a001", include: true, home: { kind: "workspace" as const } }]
  const action = { type: "adoption.approve" as const, adoption: created.adoption, digest: await adoptionDigest(created.adoption, view.items, decisions), repoints: 0 }
  await f.db.prepare("UPDATE accounts SET restricted_until=?,restricted_reason='break-glass' WHERE id=?").bind(Date.now() + 86_400_000, f.alex.account).run()
  const started = await f.request(`/api/w/${f.work.slug}/stepup/start`, f.alex, { action })
  expect(started.status).toBe(403)
  await f.db.prepare("UPDATE accounts SET restricted_until=NULL,restricted_reason=NULL WHERE id=?").bind(f.alex.account).run()
  expect(await f.sql(f.work, "SELECT id FROM items WHERE slug='restricted-key'")).toEqual([])
  expect(await body(await f.request(`${path}/cancel`, f.alex, {}))).toEqual({})
  await refusal(await f.deviceCall(machine, `/v1/adoptions/${created.adoption}/cancel`, {}), 409, { error: "conflict", message: "This adoption batch is no longer open." })
  expect(await f.sql(f.work, "SELECT * FROM adoption_secrets")).toEqual([])
})

it("adopt reconcile over HTTP: a machine sends its plan index, the person reads the inventory and keeps the batch open once per click", async () => {
  const f = await workJourney()
  const machine = await f.machine(f.alex, f.work)
  const created = await body<AdoptionCreated>(await f.deviceCall(machine, "/v1/adoptions", { machine: "office", expectedItems: 1 }), 201)
  await uploadOne(f, machine, created, "a001", "inventoried-key")
  const plan = { ref: "a001", slug: "inventoried-key", kind: "api-key", provider: "openai", home: "workspace", project: null, include: true, exists: false, storeOnly: false, sources: [{ path: "/srv/app/.env", variable: "OPENAI_API_KEY", stale: [] }], uses: [] }
  expect(await body(await f.deviceCall(machine, "/v1/adoptions/index", { machine: "office", items: [plan] }))).toEqual({ machine: "office", items: 1, expiresAt: expect.any(String) })
  const inventory = await body<WorkspaceAdoptionInventory>(await f.request(`/api/w/${f.work.slug}/adoptions`, f.alex))
  expect(inventory.rows).toMatchObject([{ slug: "inventoried-key", stored: null, entries: [{ from: "staged", ref: "a001" }, { from: "plan", ref: "a001" }] }])
  expect(JSON.stringify(inventory)).not.toContain(VALUE)
  // The inventory page reads the same rows and links the open batch to its review page.
  const listed = await f.request(`/w/${f.work.slug}/adopt`, f.alex, undefined, { accept: "text/html" })
  const listedHtml = await listed.text()
  expect(listed.status).toBe(200)
  expect(listedHtml).toContain('data-slug="inventoried-key"')
  expect(listedHtml).toContain(`<a href="/w/${f.work.slug}/b/${created.adoption}"><code>${created.adoption}</code></a>`)
  expect(listedHtml).toContain("office sent its plan")
  expect(listedHtml).not.toContain(VALUE)
  const path = `/api/w/${f.work.slug}/adoptions/${created.adoption}`
  const view = await body<WorkspaceAdoptionView>(await f.request(path, f.alex))
  const kept = await body<AdoptionKeptOpen>(await f.request(`${path}/keep-open`, f.alex, { expiresAt: view.expiresAt }))
  expect(Date.parse(kept.expiresAt) - Date.parse(view.expiresAt)).toBe(ADOPTION_LIMITS.keepOpenMs)
  expect(kept.maxExpiresAt).toBe(view.maxExpiresAt)
  await refusal(await f.request(`${path}/keep-open`, f.alex, { expiresAt: view.expiresAt }), 409, { error: "conflict", message: "This batch's expiry has changed; reload it." })
  expect((await f.request(`${path}/keep-open`, f.alex, { expiresAt: kept.expiresAt }, { origin: "https://evil.example" })).status).toBe(403)
})

it("the inventory page shows an empty state before any adoption, and only to a signed-in person", async () => {
  const f = await workJourney()
  const empty = await f.request(`/w/${f.work.slug}/adopt`, f.alex, undefined, { accept: "text/html" })
  expect(empty.status).toBe(200)
  const html = await empty.text()
  expect(html).toContain("Nothing adopted yet")
  expect(html).not.toContain("inventory-row")
  const anonymous = await f.request(`/w/${f.work.slug}/adopt`, undefined, undefined, { accept: "text/html" })
  expect([anonymous.status, anonymous.headers.get("location")]).toEqual([302, `/signin?next=${encodeURIComponent(`/w/${f.work.slug}/adopt`)}`])
})

it("the review page's keep-open control sends the expiry it shows, shows the new one, and is gone once the batch is kept open as long as it can be", async () => {
  const f = await workJourney()
  const machine = await f.machine(f.alex, f.work)
  const created = await body<AdoptionCreated>(await f.deviceCall(machine, "/v1/adoptions", { machine: "office", expectedItems: 1 }), 201)
  await uploadOne(f, machine, created, "a001", "kept-open-key")
  const page = async () => (await f.request(`/w/${f.work.slug}/b/${created.adoption}`, f.alex, undefined, { accept: "text/html" })).text()
  const shown = (html: string) => html.match(/data-action="keep-open" data-expires="([^"]+)"/)?.[1] ?? null
  const path = `/api/w/${f.work.slug}/adoptions/${created.adoption}`
  let expiresAt = shown(await page())
  expect(expiresAt).toBe((await body<WorkspaceAdoptionView>(await f.request(path, f.alex))).expiresAt)
  const answers: AdoptionKeptOpen[] = []
  while (expiresAt !== null) {
    const kept = await body<AdoptionKeptOpen>(await f.request(`${path}/keep-open`, f.alex, { expiresAt }))
    answers.push(kept)
    expiresAt = shown(await page())
    if (expiresAt !== null) expect(expiresAt).toBe(kept.expiresAt)
  }
  expect(answers.length).toBe(2)
  expect(answers.at(-1)!.expiresAt).toBe(answers.at(-1)!.maxExpiresAt)
  expect(await page()).not.toContain('data-region="keep-open"')
  await refusal(await f.request(`${path}/keep-open`, f.alex, { expiresAt: answers.at(-1)!.expiresAt }), 409, { error: "conflict", message: "This batch is already kept open as long as it can be." })
})
