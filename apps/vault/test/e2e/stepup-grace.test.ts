// Passkey grace over HTTP: with STEPUP_GRACE on, one real
// passkey in the browser session, then an item deletion, an OAuth connection
// start and an adoption each start with `grace`, send `{ nonce, grace: true }`
// through their own route's proof schema, leave the passkey untouched and say
// on their audit rows that they rode the window.
import { expect, it } from "vitest"
import { generateX25519Identity, identityToRecipient } from "age-encryption"
import { adoptionDigest, importSealPublicKey, seal, adoptionSealContext, type AdoptionCreated, type MandateChanged, type MandateTerms, type WorkspaceAdoptionView, type WorkspaceStepUpAction } from "@mehen/protocol"
import { credentialStart } from "../../src/ui/client/workspace-logic.ts"
import { body, type Person } from "./workspace-journey.ts"
import { WS, addCredential, fillIntake, setup } from "./ui-projects-journey.ts"

type Journey = Awaited<ReturnType<typeof setup>>
async function graced(f: Journey, person: Person, path: string, input: Record<string, unknown>, action: WorkspaceStepUpAction) {
  const started = await body<{ nonce: string; grace?: { until: string }; options?: unknown }>(await f.request(`/api/w/${WS}/stepup/start`, person, { action }))
  expect(started).toEqual({ nonce: expect.any(String), grace: { until: expect.any(String) } })
  return f.request(`/api/w/${WS}${path}`, person, { ...input, stepUp: { nonce: started.nonce, grace: true } })
}

it("one passkey, then an item deletion, an OAuth connection start and an adoption ride the window, each audited as graced", async () => {
  const f = await setup(), home = { kind: "workspace" } as const
  // Everything that needs a passkey of its own, before grace is on.
  await addCredential(f, f.alex, f.work, "first-key", home)
  await addCredential(f, f.alex, f.work, "second-key", home)
  const connect = credentialStart("google-gmail", "connect", "gmail-graced", home)
  const created = await body<{ connect: string; intake?: { intake: string } }>(await f.request(`/api/w/${WS}${connect.path}`, f.alex, connect.body), 201)
  if (created.intake) await fillIntake(f, f.alex, created.intake.intake, home)
  const machine = await f.machine(f.alex, f.work)
  const adoption = await body<AdoptionCreated>(await f.deviceCall(machine, "/v1/adoptions", { machine: "office", expectedItems: 1 }), 201)
  const key = await seal(await importSealPublicKey(adoption.sealKey.jwk), "sk-graced-adoption-not-a-real-secret", adoptionSealContext(adoption.adoption, "a001", "key"))
  await body(await f.deviceCall(machine, `/v1/adoptions/${adoption.adoption}/items`, { items: [{ ref: "a001", slug: "adopted-graced", kind: "api-key", provider: "openai", binding: null, injection: null, home, tags: [], publicFields: {}, sealed: { key }, sources: [{ path: "/srv/app/.env", variable: "OPENAI_API_KEY", stale: [] }], repo: null }] }))

  f.env.STEPUP_GRACE = "on"
  const first = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/items/first-key/action`, f.alex, { action: "delete" }))
  await body(await f.signed(`/api/w/${WS}/items/first-key/delete`, f.alex, {}, first, WS))
  const passkey = () => f.db.prepare("SELECT counter,backed_up,last_used_at FROM passkeys WHERE account=?").bind(f.alex.account).all().then(r => r.results)
  const before = await passkey()

  const second = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/items/second-key/action`, f.alex, { action: "delete" }))
  expect(second).toMatchObject({ type: "item.delete" })
  await body(await graced(f, f.alex, "/items/second-key/delete", {}, second))
  expect(await f.sql(f.work, "SELECT slug FROM items WHERE slug='second-key'")).toEqual([])

  const start = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/connect/${created.connect}/action`, f.alex, { home }))
  expect(start).toMatchObject({ type: "connect.start" })
  const started = await body<{ authorizeUrl: string }>(await graced(f, f.alex, `/connect/${created.connect}/start`, { home }, start))
  expect(new URL(started.authorizeUrl).searchParams.get("state")).toBeTruthy()

  const view = await body<WorkspaceAdoptionView>(await f.request(`/api/w/${WS}/adoptions/${adoption.adoption}`, f.alex))
  const decisions = [{ ref: "a001", include: true, home }]
  const approve: WorkspaceStepUpAction = { type: "adoption.approve", adoption: adoption.adoption, digest: await adoptionDigest(adoption.adoption, view.items, decisions), repoints: 0 }
  expect(await body(await graced(f, f.alex, `/adoptions/${adoption.adoption}/approve`, { decisions }, approve))).toMatchObject({ status: "approved" })

  expect(await passkey()).toEqual(before)
  const rows = await f.sql<{ action: string; detail: string }>(f.work, "SELECT action,detail FROM audit ORDER BY seq")
  const confirmations = rows.map(row => ({ action: row.action, confirmation: (JSON.parse(row.detail) as { confirmation?: unknown }).confirmation ?? null }))
  const graceOf = (action: string) => confirmations.filter(row => row.action === action).map(row => row.confirmation)
  // The passkey deletion is not marked; the graced one is, with when the passkey was used.
  expect(graceOf("item.delete")).toEqual([null, { kind: "grace", provenAt: expect.any(Number) }])
  expect(confirmations.filter(row => row.confirmation !== null).length).toBeGreaterThanOrEqual(3)
  expect(new Set(confirmations.flatMap(row => row.confirmation === null ? [] : [JSON.stringify(row.confirmation)])).size).toBe(1)
})

it("an adoption that repoints a project variable asks inside the window, and a grace proof the server rebuilds as repointing is refused", async () => {
  const f = await setup(), home = { kind: "workspace" } as const
  const machine = await f.machine(f.alex, f.work)
  const adoption = await body<AdoptionCreated>(await f.deviceCall(machine, "/v1/adoptions", { machine: "office", expectedItems: 1 }), 201)
  const key = await seal(await importSealPublicKey(adoption.sealKey.jwk), "sk-repointed-adoption-not-a-real-secret", adoptionSealContext(adoption.adoption, "a001", "key"))
  await body(await f.deviceCall(machine, `/v1/adoptions/${adoption.adoption}/items`, { items: [{ ref: "a001", slug: "adopted-repointed", kind: "api-key", provider: "openai", binding: null, injection: null, home, tags: [], publicFields: {}, sealed: { key }, sources: [{ path: "/srv/app/.env", variable: "OPENAI_API_KEY", stale: [] }], repo: null }] }))
  f.env.STEPUP_GRACE = "on"
  await addCredential(f, f.alex, f.work, "opener-key", home)

  const view = await body<WorkspaceAdoptionView>(await f.request(`/api/w/${WS}/adoptions/${adoption.adoption}`, f.alex))
  const repointing = [{ ref: "a001", include: true, home, action: "rename" as const, slug: "adopted-renamed", repoint: [{ project: f.platform.id, env: "dev", variable: "OPENAI_API_KEY" }] }]
  const asks: WorkspaceStepUpAction = { type: "adoption.approve", adoption: adoption.adoption, digest: await adoptionDigest(adoption.adoption, view.items, repointing), repoints: 1 }
  expect(await body(await f.request(`/api/w/${WS}/stepup/start`, f.alex, { action: asks }))).toHaveProperty("options")
  // The client claims no repoints at start; the route rebuilds one from the decisions.
  const claimed: WorkspaceStepUpAction = { ...asks, repoints: 0 }
  const refused = await graced(f, f.alex, `/adoptions/${adoption.adoption}/approve`, { decisions: repointing }, claimed)
  expect(refused.status).toBe(403)
  expect(await f.sql(f.work, "SELECT slug FROM items WHERE slug='adopted-renamed'")).toEqual([])
})

it("a proof that carries both an assertion and grace, or grace false, is refused by the route before any step-up", async () => {
  const f = await setup(), home = { kind: "workspace" } as const
  await addCredential(f, f.alex, f.work, "kept-key", home)
  f.env.STEPUP_GRACE = "on"
  for (const stepUp of [{ nonce: "n", assertion: {}, grace: true }, { nonce: "n", grace: false }]) {
    const response = await f.request(`/api/w/${WS}/items/kept-key/delete`, f.alex, { stepUp })
    expect(response.status).toBe(400)
  }
  expect(await f.sql(f.work, "SELECT slug FROM items WHERE slug='kept-key'")).toEqual([{ slug: "kept-key" }])
})

it("routes whose actions always ask refuse a grace proof as a bad request, inside a live window", async () => {
  const f = await setup()
  f.env.STEPUP_GRACE = "on"
  f.env.GOOGLE_SIGNIN_CLIENT_ID = "test-google-client"; f.env.GOOGLE_SIGNIN_CLIENT_SECRET = "test-only-google-secret"
  await addCredential(f, f.alex, f.work, "opener-key", { kind: "workspace" })
  const stepUp = { nonce: "n", grace: true }
  const recipient = await identityToRecipient(await generateX25519Identity())
  const routes: [string, Record<string, unknown>][] = [
    ["/api/account/passkeys/options", {}],
    ["/api/account/passkeys/pk_unknown/remove", {}],
    ["/api/account/recovery/generate", {}],
    ["/api/account/recovery/ntc_unknown/resolve", { outcome: "cancel" }],
    ["/api/auth/oidc/google/start", { purpose: "link" }],
    ["/api/account/identities/oid_unknown/unlink", {}],
    [`/api/w/${WS}/identity-rule`, { rule: { provider: "google", domains: ["northwind.example"], roles: ["owner"] } }],
    [`/api/w/${WS}/backup/recipients`, { recipient, label: "Safe" }],
    [`/api/w/${WS}/backup/recipients/rcp_unknown/remove`, {}],
    [`/api/w/${WS}/enrolments/unknown/accept`, { group: "0000", privateCredentials: false }],
    [`/api/w/${WS}/enrolments/unknown/admit`, { group: "0000" }],
    [`/api/w/${WS}/projects/${f.platform.id}/overrides`, { environment: "dev", variable: "OPENAI_API_KEY", source: null }],
  ]
  const answered: { path: string; status: number }[] = []
  for (const [path, input] of routes) answered.push({ path, status: (await f.request(path, f.alex, { ...input, stepUp })).status })
  expect(answered).toEqual(routes.map(([path]) => ({ path, status: 400 })))
})

it("an ordinary approval and a private credential's deletion carry the grace on their audit rows, the private record included", async () => {
  const f = await setup()
  const [member] = await f.sql<{ id: string }>(f.work, "SELECT id FROM members WHERE account=? AND status!='removed'", f.alex.account)
  if (!member) throw new Error("Alex is not a member")
  await addCredential(f, f.alex, f.work, "private-key", { kind: "member", member: member.id })
  const machine = await f.protectedMachine(f.alex, f.work)
  const asked = (await body<{ approval: string }>(await f.deviceCall(machine, "/v1/runs", { project: f.platform.id, env: "prod", envSource: "flag", remote: null, worktree: "/graced", head: null, vars: [], command: "node graced.js", argv: ["node", "graced.js"] }), 409)).approval

  f.env.STEPUP_GRACE = "on"
  await addCredential(f, f.alex, f.work, "opener-key", { kind: "workspace" })
  const seq = (await f.sql<{ seq: number }>(f.work, "SELECT MAX(seq) AS seq FROM audit"))[0]!.seq

  const decide = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/approvals/${asked}/action`, f.alex, { decision: "approve" }))
  expect(decide).toMatchObject({ type: "approval.decide", decision: "approve" })
  expect(decide).not.toHaveProperty("remember")
  await body(await graced(f, f.alex, `/approvals/${asked}/decide`, { decision: "approve" }, decide))
  const remove = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/items/private-key/action`, f.alex, { action: "delete" }))
  await body(await graced(f, f.alex, "/items/private-key/delete", {}, remove))

  const rows = await f.sql<{ action: string; detail: string }>(f.work, "SELECT action,detail FROM audit WHERE seq>? ORDER BY seq", seq)
  const marked = rows.map(row => ({ action: row.action, confirmation: (JSON.parse(row.detail) as { confirmation?: unknown }).confirmation }))
  expect(marked.filter(row => row.action.startsWith("approval.")).length).toBeGreaterThan(0)
  expect(marked.filter(row => row.action === "item.delete").length).toBe(1)
  for (const row of marked) expect(row, row.action).toEqual({ action: row.action, confirmation: { kind: "grace", provenAt: expect.any(Number) } })
  // The private record is still a valid private record, with the grace in it.
  const deleted = rows.find(row => row.action === "item.delete")!
  expect(JSON.parse(deleted.detail)).toMatchObject({ actor: { kind: "member", member: member.id }, confirmation: { kind: "grace" } })
})

it("signing in with a passkey opens the window: an ask is then decided with no second passkey, and an always-fresh step still asks", async () => {
  const f = await setup()
  const machine = await f.protectedMachine(f.alex, f.work)
  const asked = (await body<{ approval: string }>(await f.deviceCall(machine, "/v1/runs", { project: f.platform.id, env: "prod", envSource: "flag", remote: null, worktree: "/signed-in", head: null, vars: [], command: "node signed-in.js", argv: ["node", "signed-in.js"] }), 409)).approval
  f.env.STEPUP_GRACE = "on"
  await f.signin(f.alex)
  const passkey = () => f.db.prepare("SELECT counter,last_used_at FROM passkeys WHERE account=?").bind(f.alex.account).all().then(r => r.results)
  const signedIn = await passkey()
  const seq = (await f.sql<{ seq: number }>(f.work, "SELECT MAX(seq) AS seq FROM audit"))[0]!.seq

  const decide = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/approvals/${asked}/action`, f.alex, { decision: "approve" }))
  await body(await graced(f, f.alex, `/approvals/${asked}/decide`, { decision: "approve" }, decide))
  expect(await passkey()).toEqual(signedIn)
  const decided = await f.sql<{ detail: string }>(f.work, "SELECT detail FROM audit WHERE action LIKE 'approval.%' AND seq>?", seq)
  expect(decided.map(row => (JSON.parse(row.detail) as { confirmation?: unknown }).confirmation)).toEqual([{ kind: "grace", provenAt: expect.any(Number) }])

  const terms: MandateTerms = { device: machine.device, items: "all", classes: ["read"], caps: { read: 100, change: 0, send: 0, delete: 0 }, ttlDays: 7, schedule: null, note: "After signing in" }
  const sign = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/mandates/action`, f.alex, { op: "sign", terms }))
  const fresh = await body<{ nonce: string; grace?: unknown }>(await f.request(`/api/w/${WS}/stepup/start`, f.alex, { action: sign }))
  expect(fresh).toEqual({ nonce: expect.any(String), options: expect.anything() })
})

it("with the approval dial at Let it work, a passkey sign-in's window still decides a protected run's ask, and never moves the dial to ask less", async () => {
  const f = await setup()
  const machine = await f.protectedMachine(f.alex, f.work)
  const less: WorkspaceStepUpAction = { type: "workspace.approvals", before: "writes", after: "work" }
  expect(await body(await f.signed(`/api/w/${WS}/settings/approvals`, f.alex, { before: "writes", after: "work" }, less, WS))).toEqual({ level: "work" })
  // Let it work never lets a protected run through: it still asks a person.
  const asked = (await body<{ approval: string }>(await f.deviceCall(machine, "/v1/runs", { project: f.platform.id, env: "prod", envSource: "flag", remote: null, worktree: "/dial", head: null, vars: [], command: "node dial.js", argv: ["node", "dial.js"] }), 409)).approval
  f.env.STEPUP_GRACE = "on"
  await f.signin(f.alex)

  const decide = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/approvals/${asked}/action`, f.alex, { decision: "approve" }))
  await body(await graced(f, f.alex, `/approvals/${asked}/decide`, { decision: "approve" }, decide))
  expect(await f.sql(f.work, "SELECT status FROM approvals WHERE id=?", asked)).toEqual([{ status: "approved" }])

  // Asking more needs no passkey; asking less again needs a fresh one, window or not.
  expect(await body(await f.request(`/api/w/${WS}/settings/approvals`, f.alex, { before: "work", after: "writes" }))).toEqual({ level: "writes" })
  const started = await body<{ nonce: string; grace?: unknown }>(await f.request(`/api/w/${WS}/stepup/start`, f.alex, { action: less }))
  expect(started).toEqual({ nonce: expect.any(String), options: expect.anything() })
  const refused = await f.request(`/api/w/${WS}/settings/approvals`, f.alex, { before: "writes", after: "work", stepUp: { nonce: started.nonce, grace: true } })
  expect(refused.status).toBe(403)
  expect(await body(await f.request(`/api/w/${WS}/settings/approvals`, f.alex, { before: "writes", after: "writes" }))).toEqual({ level: "writes" })
})

it("a workspace created on the window says so on its account event; one created with a passkey does not", async () => {
  const f = await setup()
  f.env.STEPUP_GRACE = "on"
  await addCredential(f, f.alex, f.work, "opener-key", { kind: "workspace" })
  const create = { name: "Graced", slug: "graced-work" }
  const started = await body<{ nonce: string; grace?: { until: string } }>(await f.request("/api/account/stepup/start", f.alex, { action: { type: "workspace.create", ...create } }))
  expect(started.grace).toEqual({ until: expect.any(String) })
  const created = await body<{ id: string }>(await f.request("/api/workspaces", f.alex, { ...create, stepUp: { nonce: started.nonce, grace: true } }), 201)
  const events = await f.db.prepare("SELECT detail FROM account_events WHERE account=? AND action='account.workspace_create'").bind(f.alex.account).all<{ detail: string }>()
  const details = events.results.map(row => JSON.parse(row.detail) as { workspace: string; confirmation?: unknown })
  expect(details.find(detail => detail.workspace === created.id)).toEqual({ workspace: created.id, confirmation: { kind: "grace", provenAt: expect.any(Number) } })
  expect(details.find(detail => detail.workspace === f.work.id)).toEqual({ workspace: f.work.id })
})

it("signing a mandate asks for the passkey inside the window; resuming one an admin paused rides it, audited as graced", async () => {
  const f = await setup()
  const machine = await f.machine(f.alex, f.work)
  f.env.STEPUP_GRACE = "on"
  await addCredential(f, f.alex, f.work, "opener-key", { kind: "workspace" })
  const terms: MandateTerms = { device: machine.device, items: "all", classes: ["read"], caps: { read: 100, change: 0, send: 0, delete: 0 }, ttlDays: 7, schedule: null, note: "Building the release" }

  const sign = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/mandates/action`, f.alex, { op: "sign", terms }))
  expect(sign).toMatchObject({ type: "mandate.sign" })
  const asked = await body<{ nonce: string }>(await f.request(`/api/w/${WS}/stepup/start`, f.alex, { action: sign }))
  expect(asked).toHaveProperty("options")
  expect(asked).not.toHaveProperty("grace")
  const refused = await f.request(`/api/w/${WS}/mandates`, f.alex, { terms, stepUp: { nonce: asked.nonce, grace: true } })
  expect([refused.status, await refused.json()]).toEqual([403, { error: "forbidden", message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." }])
  expect(await f.sql(f.work, "SELECT id FROM mandates")).toEqual([])
  const { mandate } = await body<MandateChanged>(await f.signed(`/api/w/${WS}/mandates`, f.alex, { terms }, sign, WS), 201)

  // As an owner's or admin's pause leaves it: resuming needs a passkey.
  await f.sql(f.work, "UPDATE mandates SET state='paused',paused_by='admin',rev=rev+1 WHERE id=?", mandate.id)
  const resume = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/mandates/action`, f.alex, { op: "resume", id: mandate.id, rev: 2 }))
  expect(resume).toEqual({ type: "mandate.resume", mandate: mandate.id, digest: expect.any(String), rev: 2, from: "paused" })
  expect((await body<MandateChanged>(await graced(f, f.alex, `/mandates/${mandate.id}/resume`, { rev: 2 }, resume))).mandate).toMatchObject({ state: "active", rev: 3 })

  const rows = await f.sql<{ action: string; detail: string }>(f.work, "SELECT action,detail FROM audit WHERE target=? ORDER BY seq", mandate.id)
  const details = rows.map(row => ({ action: row.action, detail: JSON.parse(row.detail) as { stepUp?: boolean; confirmation?: unknown } }))
  expect(details.find(row => row.action === "mandate.sign")?.detail).not.toHaveProperty("confirmation")
  expect(details.find(row => row.action === "mandate.resume")?.detail).toMatchObject({ stepUp: true, confirmation: { kind: "grace", provenAt: expect.any(Number) } })
})

it("resuming a tripped or lapsed mandate asks for the passkey inside the window, and a grace proof for it is refused", async () => {
  const f = await setup()
  const machine = await f.machine(f.alex, f.work)
  f.env.STEPUP_GRACE = "on"
  await addCredential(f, f.alex, f.work, "opener-key", { kind: "workspace" })
  const terms: MandateTerms = { device: machine.device, items: "all", classes: ["read"], caps: { read: 100, change: 0, send: 0, delete: 0 }, ttlDays: 7, schedule: null, note: "Building the release" }
  const sign = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/mandates/action`, f.alex, { op: "sign", terms }))
  const { mandate } = await body<MandateChanged>(await f.signed(`/api/w/${WS}/mandates`, f.alex, { terms }, sign, WS), 201)
  for (const [from, change] of [["tripped", "UPDATE mandates SET state='tripped',rev=rev+1 WHERE id=?"], ["lapsed", "UPDATE mandates SET state='active',lapsed_at=1,rev=rev+1 WHERE id=?"]] as const) {
    await f.sql(f.work, change, mandate.id)
    const [{ rev }] = await f.sql<{ rev: number }>(f.work, "SELECT rev FROM mandates WHERE id=?", mandate.id) as [{ rev: number }]
    const resume = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/mandates/action`, f.alex, { op: "resume", id: mandate.id, rev }))
    expect(resume).toEqual({ type: "mandate.resume", mandate: mandate.id, digest: expect.any(String), rev, from })
    const started = await body<{ nonce: string }>(await f.request(`/api/w/${WS}/stepup/start`, f.alex, { action: resume }))
    expect([from, started]).toEqual([from, { nonce: expect.any(String), options: expect.anything() }])
    const refused = await f.request(`/api/w/${WS}/mandates/${mandate.id}/resume`, f.alex, { rev, stepUp: { nonce: started.nonce, grace: true } })
    expect([from, refused.status]).toEqual([from, 403])
    expect(await f.sql(f.work, "SELECT state,rev FROM mandates WHERE id=?", mandate.id)).toEqual([{ state: from === "tripped" ? "tripped" : "active", rev }])
    expect((await body<MandateChanged>(await f.signed(`/api/w/${WS}/mandates/${mandate.id}/resume`, f.alex, { rev }, resume, WS))).mandate).toMatchObject({ state: "active", rev: rev + 1 })
  }
})

// What the account page's Sign out everywhere confirmation says it does.
it("signing out everywhere stops every mandate its person signed until they resume it with their passkey, and the machine stays enrolled", async () => {
  const f = await setup()
  const machine = await f.machine(f.alex, f.work)
  await addCredential(f, f.alex, f.work, "opener-key", { kind: "workspace" })
  const terms: MandateTerms = { device: machine.device, items: "all", classes: ["read"], caps: { read: 100, change: 0, send: 0, delete: 0 }, ttlDays: 7, schedule: null, note: "Building the release" }
  const sign = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/mandates/action`, f.alex, { op: "sign", terms }))
  const { mandate } = await body<MandateChanged>(await f.signed(`/api/w/${WS}/mandates`, f.alex, { terms }, sign, WS), 201)
  expect(await body(await f.request("/api/account/sessions/end-all", f.alex, {}))).toEqual({ pending: false })
  expect(await f.sql(f.work, "SELECT state,lapsed_at IS NOT NULL AS lapsed FROM mandates WHERE id=?", mandate.id)).toEqual([{ state: "active", lapsed: 1 }])
  expect(await f.sql(f.work, "SELECT revoked_at FROM devices WHERE id=?", machine.device)).toEqual([{ revoked_at: null }])
})

it("the account page reads the window and Ask every time ends it with no passkey; the next confirmation asks again", async () => {
  const f = await setup()
  f.env.STEPUP_GRACE = "on"
  expect(await body(await f.request("/api/account/stepup/grace", f.alex))).toEqual({ grace: null })
  await addCredential(f, f.alex, f.work, "opener-key", { kind: "workspace" })
  const read = await body<{ grace: { until: string } | null }>(await f.request("/api/account/stepup/grace", f.alex))
  expect(Date.parse(read.grace!.until)).toBeGreaterThan(Date.now())
  const shown = await f.request("/account", f.alex, undefined, { accept: "text/html" })
  expect(await shown.text()).toContain('data-action="end-stepup-grace"')
  expect(await body(await f.request("/api/account/stepup/grace/end", f.alex, {}))).toEqual({})
  expect(await body(await f.request("/api/account/stepup/grace", f.alex))).toEqual({ grace: null })
  const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/items/opener-key/action`, f.alex, { action: "delete" }))
  expect(await body(await f.request(`/api/w/${WS}/stepup/start`, f.alex, { action }))).toHaveProperty("options")
})
