// Systematic fresh-schema gate: every registered device route and remaining
// legacy page/auth pattern must reach a workspace op or a deliberate refusal.
import { expect, it, vi } from "vitest"
import { env } from "cloudflare:workers"
import { runInDurableObject } from "cloudflare:test"
import { PolicyPreviewRequestSchema } from "@mehen/protocol/policy-mode"
import { generateSealKeyPair } from "@mehen/protocol"
import type { PendingFixturePort } from "../../../cli/src/pending-fixture-port.ts"
import { ROUTES } from "../../src/routes/index.ts"
import { workspaceDirectoryEntryRoutes } from "../../src/routes/directory.ts"
import { WORKSPACE_PAGES } from "../../src/routes/ui.ts"
import { DOCS_REDIRECTS } from "../../src/routes/ui.ts"
import { setUpstreamFetch } from "../../src/relay/upstream.ts"
import { body, workJourney } from "./workspace-journey.ts"
import { newDeviceKey, publicJwk } from "../devices.ts"

const modulePath = new URL("../../../cli/src/testing/pending-fixture-port.ts", import.meta.url).pathname
const { pendingFixturePort: cli } = await import(modulePath) as { pendingFixturePort: PendingFixturePort }
const key = (method: string, path: string) => `${method} ${path}`
const NOT_YET = { error: "forbidden", message: "Policy widening is not available yet." }
// POLICY_RULES for the Worker's routes and the workspace's vault alike.
async function switchRules(f: Awaited<ReturnType<typeof workJourney>>, value: string) {
  f.env.POLICY_RULES = value
  await runInDurableObject(env.TENANT_VAULT.getByName(f.work.id), (instance) => { instance.context.env = { ...instance.context.env, POLICY_RULES: value } })
}

it("fresh schema route sweep: every /v1 route called by the CLI and its real workspace pending projection avoids legacy D1", async () => {
  const f = await workJourney(), machine = await f.machine(f.alex, f.work), covered = new Set<string>()
  await f.credential(f.alex, f.work, "smoke-key", { kind: "workspace" })
  const errors = vi.spyOn(console, "error")
  setUpstreamFetch(async () => new Response("smoke-upstream"))
  async function call(method: string, pattern: string, path = pattern, input?: unknown) {
    covered.add(key(method, pattern))
    const response = await f.deviceCall(machine, path, input, f.work.id, machine.device, method)
    expect(response.status, `${method} ${path}`).toBeLessThan(500)
    return response
  }
  try {
    expect(await body(await call("GET", "/v1/me"))).toHaveProperty("device", machine.device)
    expect(await body(await call("GET", "/v1/seal-key"))).toHaveProperty("kid")
    await body(await call("GET", "/v1/items"))
    await body(await call("GET", "/v1/items/:slug", "/v1/items/smoke-key"))
    const intake = await body<{ intake: string }>(await call("POST", "/v1/intakes", "/v1/intakes", { kind: "api-key", provider: "openai", slug: "smoke-ask", reason: "Smoke test", home: "private" }), 201)
    await body(await call("GET", "/v1/intakes/:id", `/v1/intakes/${intake.intake}`))
    const pending = await body<{ pending: unknown[]; notices: unknown[] }>(await call("GET", "/v1/pending"))
    const context = { origin: f.env.VAULT_ORIGIN, workspace: f.work, device: machine.device }
    expect(cli.normaliseWorkspacePending(pending.pending, context)).toEqual([{ kind: "intake", id: intake.intake, title: "Add smoke-ask", url: `${context.origin}/w/northwind/i/${intake.intake}`, expiresAt: expect.any(String), requestedBy: { device: machine.device, deviceName: "integration-machine", session: null }, item: "smoke-ask", provider: "openai", kindRequested: "api-key" }])
    expect(cli.workspaceMachineNotices(pending.notices, context).notices.map(notice => notice.payload.device)).toEqual([machine.device])
    await call("POST", "/v1/intakes/:id/cancel", `/v1/intakes/${intake.intake}/cancel`, {})
    const adoption = await body<{ adoption: string }>(await call("POST", "/v1/adoptions", "/v1/adoptions", { machine: "smoke", expectedItems: 1 }), 201)
    const box = { v: 1, epk: { kty: "EC", crv: "P-256", x: "x", y: "y" }, iv: "iv", ct: "ct" }
    expect(await body(await call("POST", "/v1/adoptions/:id/items", `/v1/adoptions/${adoption.adoption}/items`, { items: [{ ref: "a001", slug: "smoke-adopt", kind: "api-key", provider: "openai", binding: null, injection: null, home: { kind: "workspace" }, tags: [], publicFields: {}, sealed: { key: box }, sources: [{ path: "/smoke/.env", stale: [] }], repo: null }] }))).toEqual({ adoption: adoption.adoption, accepted: [], refused: [{ ref: "a001", reason: "The sealed field does not belong to this adoption." }] })
    await body(await call("GET", "/v1/adoptions/:id", `/v1/adoptions/${adoption.adoption}`))
    await body(await call("POST", "/v1/adoptions/:id/cancel", `/v1/adoptions/${adoption.adoption}/cancel`, {}))
    expect(await body(await call("POST", "/v1/adoptions/index", "/v1/adoptions/index", { machine: "smoke", items: [] }))).toMatchObject({ machine: "smoke", items: 0 })
    expect(await body(await call("GET", "/v1/backup/recipients"))).toEqual({ recipients: [] })
    expect(await body(await call("GET", "/v1/backup/status"))).toMatchObject({ recipients: [], rights: { add: false } })
    expect((await call("POST", "/v1/backup/exports", "/v1/backup/exports", { recipient: "bkr_missing123" })).status).toBe(404)
    await call("POST", "/v1/connect", "/v1/connect", { provider: "google-gmail", slug: "smoke-connect", client: "missing-client", reason: "Smoke test", home: "private" })
    await call("GET", "/v1/connect/:id", "/v1/connect/con_missing123")
    await call("POST", "/v1/connect/:id/cancel", "/v1/connect/con_missing123/cancel", {})
    await call("GET", "/v1/approvals/:id", "/v1/approvals/apr_missing123")
    const planned = await body<{ bundle: string; results: { outcome: string }[] }>(await call("POST", "/v1/approvals/bundles", "/v1/approvals/bundles", { requests: [{ item: "smoke-key", method: "GET", url: "https://api.openai.com/v1/models", headers: [] }] }))
    expect(planned.results).toEqual([{ index: 0, outcome: "allowed" }])
    expect(await body(await call("GET", "/v1/approvals/bundles/:id", `/v1/approvals/bundles/${planned.bundle}`))).toEqual({ bundle: planned.bundle, approvals: [] })
    const smoke = await body<{ id: string }>(await call("POST", "/v1/projects", "/v1/projects", { slug: "smoke-project", remote: "github.com/acme/smoke", defaultEnv: "dev", environments: [{ name: "dev", protected: false }] }), 201)
    expect(await body(await call("GET", "/v1/projects", "/v1/projects?remote=git%40github.com%3Aacme%2Fsmoke.git"))).toEqual({ id: smoke.id, slug: "smoke-project", defaultEnv: "dev", environments: [{ name: "dev", protected: false, variables: [] }] })
    expect((await call("GET", "/v1/projects", "/v1/projects?remote=github.com%2Facme%2Fabsent")).status).toBe(404)
    await body(await call("GET", "/v1/projects/:id", `/v1/projects/${f.project.id}`))
    expect(await body(await call("GET", "/v1/projects/:id/overrides", `/v1/projects/${f.project.id}/overrides`))).toEqual({ overrides: [] })
    await body(await call("PUT", "/v1/projects/:id/vars/:name", `/v1/projects/${f.project.id}/vars/SMOKE`, { env: "dev", plain: "hello" }))
    const run = await body<{ run: string }>(await call("POST", "/v1/runs", "/v1/runs", { project: f.project.id, env: "dev", envSource: "flag", remote: null, worktree: "/smoke", head: null, vars: ["SMOKE"], command: "node smoke.js", argv: ["node", "smoke.js"] }), 201)
    await body(await call("POST", "/v1/runs/:id/renew", `/v1/runs/${run.run}/renew`, {}))
    await call("POST", "/v1/lease", "/v1/lease", { run: run.run, item: "smoke-key", field: "key" })
    expect(await (await call("POST", "/v1/relay", "/v1/relay", { item: "smoke-key", method: "GET", url: "https://api.openai.com/v1/models", headers: [] })).text()).toBe("smoke-upstream")
    await body(await call("DELETE", "/v1/runs/:id", `/v1/runs/${run.run}`))
    // This machine was never given fill, so the credential is not one it may type.
    const sealKey = await crypto.subtle.exportKey("jwk", (await generateSealKeyPair()).publicKey) as JsonWebKey
    expect(await body(await call("POST", "/v1/fill", "/v1/fill", { item: "smoke-key", field: "key", origin: "https://dashboard.example.net", page: "/settings", recipient: { kty: "EC", crv: "P-256", x: sealKey.x, y: sealKey.y } }), 404)).toMatchObject({ error: "not_found" })
    const policy = { change: { kind: "mode", target: { kind: "item", item: "smoke-key" }, selector: { device: machine.device, session: null }, policyMode: "relaxed", scope: { host: "api.openai.com", methods: ["GET"], path: "/v1/**", anchorPath: "/v1/models", basis: "reviewed" }, ttlSeconds: 60, notAfter: null }, reason: "Smoke test" }
    // smoke-key has not been allowed to leave: refused before any provider call.
    expect((await call("POST", "/v1/push", "/v1/push", { item: "smoke-key", to: { provider: "github", owner: "acme", repo: "smoke", store: "actions", environment: null, name: "SMOKE" } })).status).toBe(403)
    await call("GET", "/v1/policy/context", "/v1/policy/context?item=smoke-key")
    await call("GET", "/v1/policy/state")
    expect((await call("POST", "/v1/policy/preview", "/v1/policy/preview", PolicyPreviewRequestSchema.parse(policy))).status).toBe(403)
    expect((await call("POST", "/v1/policy/proposals", "/v1/policy/proposals", { ...policy, baseDigest: "a".repeat(43), slotRevision: 0 })).status).toBe(403)
    await call("GET", "/v1/policy/proposals/:id", "/v1/policy/proposals/pol_missing123")
    for (const path of ["proposals/:id/cancel", "overrides/:id/revoke", "grants/:id/revoke"]) await call("POST", `/v1/policy/${path}`, `/v1/policy/${path.replace(":id", "pol_missing123")}`, {})
    // Standing rules are off in the test env, as in production.
    expect(await (await call("GET", "/v1/policy/rules")).json()).toMatchObject(NOT_YET)
    await switchRules(f, "on")
    expect(await body(await call("GET", "/v1/policy/rules"))).toEqual([])
    expect((await call("POST", "/v1/policy/rules/:id/revoke", "/v1/policy/rules/rul_missing123/revoke", {})).status).toBe(404)
    await switchRules(f, "off")
    const start = await f.startMachine(f.work)
    covered.add("POST /v1/enrol")
    const poll = await f.deviceCall({ ...machine, keys: start.keys, device: start.started.enrolment }, `/v1/enrol/${start.started.enrolment}`, undefined, "enrol")
    expect(await body(poll)).toEqual({ status: "pending_owner_acceptance", expiresAt: expect.any(String), hardExpiresAt: expect.any(String) })
    covered.add("GET /v1/enrol/:enrolment")
    const renew = await f.deviceCall({ ...machine, keys: start.keys, device: start.started.enrolment }, `/v1/enrol/${start.started.enrolment}/renew`, undefined, "enrol", start.started.enrolment, "POST")
    expect(await body(renew)).toEqual({ enrolment: start.started.enrolment, expiresAt: expect.any(String), hardExpiresAt: expect.any(String) })
    covered.add("POST /v1/enrol/:enrolment/renew")
    const workload = await body<{ workload: string }>(await call("POST", "/v1/workloads", "/v1/workloads", { jwk: await publicJwk(await newDeviceKey()), label: "smoke-task", scope: { modes: ["relay"] } }), 201)
    await body(await call("GET", "/v1/workloads"))
    await body(await call("GET", "/v1/workloads/:id", `/v1/workloads/${workload.workload}`))
    await body(await call("POST", "/v1/workloads/:id/renew", `/v1/workloads/${workload.workload}/renew`, {}))
    await body(await call("DELETE", "/v1/workloads/:id", `/v1/workloads/${workload.workload}`))
    // This machine asked for nothing a mandate could cover, so a proposal of
    // its own is refused, and every credential always is.
    expect(await body(await call("GET", "/v1/mandates/asked"))).toEqual({ items: [], classes: [] })
    expect(await body(await call("POST", "/v1/mandates/proposals", "/v1/mandates/proposals", { terms: { items: "all", classes: ["read"], caps: { read: 100, change: 0, send: 0, delete: 0 }, ttlDays: 7, schedule: null, note: "Smoke test" }, reason: "Smoke test" }), 403)).toMatchObject({ error: "forbidden", mandateRefused: "items_all" })
    expect(await body(await call("GET", "/v1/mandates"))).toEqual({ mandates: [], proposals: [] })
    // A proposal's state for its wait, read for one that does not exist.
    expect((await call("GET", "/v1/mandates/proposals/:id", "/v1/mandates/proposals/mdp_missing123?wait=1")).status).toBe(404)
    expect((await call("GET", "/v1/mandates/:id", "/v1/mandates/mdt_missing123")).status).toBe(404)
    expect((await call("GET", "/v1/mandates/:id/uses", "/v1/mandates/mdt_missing123/uses")).status).toBe(404)
    expect((await call("POST", "/v1/mandates/:id/pause", "/v1/mandates/mdt_missing123/pause", { rev: 1 })).status).toBe(404)
    await call("POST", "/v1/freeze", "/v1/freeze", {})
    await call("POST", "/v1/devices/self/revoke", "/v1/devices/self/revoke", {})
    const expected = new Set([...ROUTES, ...workspaceDirectoryEntryRoutes].filter(route => route.path.startsWith("/v1/")).map(route => key(route.method, route.path)))
    expect([...covered].sort()).toEqual([...expected].sort())
    expect(errors).not.toHaveBeenCalled()
  } finally { errors.mockRestore(); setUpstreamFetch(null) }
}, 120_000)

// A list naming only other workspaces is off for this one, byte for byte.
for (const value of ["off", "tn_elsewhere0001,tn_elsewhere0002"]) it(`with POLICY_RULES ${JSON.stringify(value)}, every route standing rules added or read answers as it did before them`, async () => {
  const f = await workJourney(), machine = await f.machine(f.alex, f.work)
  await switchRules(f, value)
  const device = (method: string, path: string, input?: unknown) => f.deviceCall(machine, path, input, f.work.id, machine.device, method)
  const page = (path: string, input?: unknown) => f.request(`/api/w/northwind${path}`, f.alex, input)
  const answer = async (response: Response) => ({ status: response.status, body: await response.json() })
  const notYet = { status: 403, body: expect.objectContaining(NOT_YET) }
  const stepUp = { nonce: "n", assertion: {} }
  const fromApproval = { from: { approval: "apr_missing123" }, reason: "Smoke test" }
  // A rule's body is read as a legacy window's, which it is not.
  expect(await answer(await device("POST", "/v1/policy/preview", fromApproval))).toEqual({ status: 400, body: expect.objectContaining({ error: "bad_request", message: "Invalid request: change Invalid input: expected object, received undefined." }) })
  expect(await answer(await device("POST", "/v1/policy/proposals", fromApproval))).toEqual({ status: 400, body: expect.objectContaining({ error: "bad_request", message: "Invalid request: change Invalid input: expected object, received undefined." }) })
  expect(await answer(await device("GET", "/v1/policy/proposals/pol_missing123"))).toEqual(notYet)
  expect(await answer(await device("POST", "/v1/policy/proposals/pol_missing123/cancel", {}))).toEqual(notYet)
  expect(await answer(await page("/policy/preview", fromApproval))).toEqual(notYet)
  expect(await answer(await page("/policy/proposals", fromApproval))).toEqual(notYet)
  expect(await answer(await page("/policy/proposals/pol_missing123/action", { decision: "approve", effective: { path: "/v1/models", ttlSeconds: 86_400 } }))).toEqual({ status: 400, body: expect.objectContaining({ error: "bad_request", message: "Invalid request: body Unrecognized key: \"effective\"." }) })
  expect(await answer(await page("/policy/proposals/pol_missing123/decide", { decision: "deny", stepUp }))).toEqual({ status: 400, body: expect.objectContaining({ error: "bad_request", message: "Invalid request: effectiveChange Invalid input: expected null, received undefined." }) })
  // The routes rules added refuse as widening does.
  expect(await answer(await device("GET", "/v1/policy/rules"))).toEqual(notYet)
  expect(await answer(await device("POST", "/v1/policy/rules/rul_missing123/revoke", {}))).toEqual(notYet)
  expect(await answer(await page("/policy/rules?item=smoke-key"))).toEqual(notYet)
  // A person's own list (My rules) refuses as the item and machine lists do.
  expect(await answer(await page("/policy/rules"))).toEqual(notYet)
  // The My rules page is the workspace's not-found page, and nothing links to it.
  const html = async (path: string) => { const response = await f.request(path, f.alex, undefined, { accept: "text/html" }); return { status: response.status, body: await response.text() } }
  expect(await html("/w/northwind/rules")).toEqual(await html("/w/northwind/no-such-page"))
  expect((await html("/w/northwind/")).body).not.toContain("/w/northwind/rules")
  expect(await answer(await page("/policy/rules/rul_missing123/revoke", {}))).toEqual(notYet)
  expect(await answer(await page("/policy/rules/rul_missing123/extend/action", { ttlSeconds: 86_400 }))).toEqual(notYet)
  expect(await answer(await page("/policy/rules/rul_missing123/extend/decide", { ttlSeconds: 86_400, stepUp }))).toEqual(notYet)
}, 120_000)

it("fresh schema route sweep: every remaining page, doc and /auth path is safe for anonymous, account and ceremony cookies", async () => {
  const f = await workJourney(), queries: string[] = []
  const db = new Proxy(f.db, { get(target, prop) {
    if (prop === "prepare") return (query: string) => { queries.push(query); return target.prepare(query) }
    const value = Reflect.get(target, prop) as unknown
    return typeof value === "function" ? value.bind(target) : value
  } })
  f.env.DB = db
  const legacyPages = ROUTES.filter(route => !["/api/", "/app/", "/v1/"].some(prefix => route.path.startsWith(prefix)))
  const paths = new Map(legacyPages.map(route => [route.path, route.path.replace(/:[a-z]+/gi, "missing")]))
  for (const slug of Object.keys(DOCS_REDIRECTS)) paths.set(`/docs/${slug}`, `/docs/${slug}`)
  for (const page of WORKSPACE_PAGES) paths.set(`/w/:ws${page.path}`, `/w/northwind${page.path}`)
  for (const path of ["/account", "/workspaces", "/needs-you", "/auth/oidc/google/callback", "/auth/oidc/continue", "/unknown-html"]) paths.set(path, path)
  // The workspace settings page is served (its read merged) and swept.
  expect(paths.get("/w/:ws/settings")).toBe("/w/northwind/settings")
  // So is the adoption inventory, the path mehen adopt inventory links to.
  expect(paths.get("/w/:ws/adopt")).toBe("/w/northwind/adopt")
  const errors = vi.spyOn(console, "error")
  async function probe(person?: typeof f.alex) {
    for (const path of paths.values()) for (const method of ["GET", "HEAD"]) {
      const response = await f.request(path, person, undefined, { accept: "text/html" }, method)
      expect(response.status, `${method} ${path}`).toBeLessThan(500)
    }
    for (const route of legacyPages.filter(route => route.path.startsWith("/auth/"))) {
      const response = await f.request(route.path.replace(/:[a-z]+/gi, "missing"), person, route.method === "GET" ? undefined : {}, {}, route.method)
      expect(response.status).toBeLessThan(500)
    }
  }
  try {
    await probe()
    await probe(f.alex)
    const started = await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[0] })
    expect(started.status).toBe(200)
    await probe({ ...f.alex, cookie: started.headers.get("set-cookie")!.split(";")[0]! })
    expect(queries.filter(query => /\b(?:FROM|JOIN|INTO|UPDATE)\s+(?:members|tenants|invites|security_notices)\b/i.test(query))).toEqual([])
    expect(queries.filter(query => /\b(?:web_sessions|passkeys|s|p)\.member\b/i.test(query))).toEqual([])
    expect(errors).not.toHaveBeenCalled()
  } finally { errors.mockRestore() }
}, 120_000)
