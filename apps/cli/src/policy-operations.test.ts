import { afterAll, afterEach, beforeAll, beforeEach, expect, test } from "bun:test"
import type { Me } from "@mehen/protocol/api"
import { type PolicyChange, type PolicyContext, type PolicyPreview, PolicyAreaProposalSchema, PolicyRuleProposalSchema } from "@mehen/protocol/policy-mode"
import { readLedger } from "./ledger.ts"
import { settle } from "./operations.ts"
import { areaProposal, cancelPolicy, convenienceProposal, listRules, listRulesAndGrants, policyCapabilities, postureAllowed, previewPolicy, proposeArea, proposePolicy, proposeRule, readPolicyState, ruleProposal, rulesAllowed, showPolicy, stopPolicy } from "./policy-operations.ts"
import { openSession, type VaultSession } from "./session.ts"
import { MockVault, item, vaultError } from "./testing/mock-vault.ts"
import { RULES_OFF, grantCreated, grantView, ruleCreated, ruleView } from "./testing/policy-rules-fixtures.ts"
import { tempDir } from "./testing/run-mehen.ts"

function policyChange(device = "dev_test"): PolicyChange {
  return { kind: "mode", target: { kind: "item", item: "example-key" }, selector: { device, session: "pol-test" }, policyMode: "relaxed", scope: { host: "api.example.com", methods: ["POST"], path: "/projects/123/**", anchorPath: "/projects/123/issues", basis: "unreviewed" }, ttlSeconds: 3600, notAfter: null }
}
function policyContext(change: PolicyChange): PolicyContext {
  return { item: change.target.item, selector: change.selector, baseMode: "standard", effectiveMode: "standard", basePolicy: { default: "approve", rules: [] }, floor: [], snapshot: { itemId: "itm_test", device: change.selector.device, configRev: 0, scopeRev: 0, protectionRev: 0, safetyDigest: "safety", frozen: false }, baseDigest: "a".repeat(43), slotRevision: 3, predecessor: null, state: { widening: [], observedAt: new Date().toISOString() } }
}
function policyPreview(change: PolicyChange): PolicyPreview {
  return { change, reason: "Manage project issues", context: policyContext(change), baseDigest: "a".repeat(43), slotRevision: 3, summary: "Relax project issues", diff: [], warnings: ["Unreviewed semantics. Remote persistence may outlive the window."] }
}
function policyCreated(change: PolicyChange, origin: string) {
  return { proposal: "pol_test", item: change.target.item, status: "pending", bindingCode: "CODE42", summary: "Relax project issues", expiresAt: new Date(Date.now() + 3600000).toISOString(), outcome: null, url: `${origin}/p/pol_test`, next: { say: "Review" } }
}

let vault: MockVault
const scope = () => vault.ledgerScope()
let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>
let session: VaultSession
let change: PolicyChange
beforeAll(() => { vault = new MockVault() })
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  vault.lastDevice = null
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url, MEHEN_SESSION: "pol-test" }
  const device = await vault.enrolSoftware(dir.path)
  session = await openSession(env)
  change = policyChange(device)
  vault.seen.length = 0
  vault.overrides.clear()
  vault.items.splice(2)
  vault.items.push(item("example-key", { binding: { hosts: ["api.example.com"] }, policy: { default: "approve", rules: [] } }))
  vault.overrides.set("POST /v1/policy/preview", (_req, seen) => Response.json(policyPreview((JSON.parse(seen.body) as { change: PolicyChange }).change)))
  vault.overrides.set("POST /v1/policy/proposals", () => Response.json(policyCreated(change, vault.url)))
})
afterEach(async () => dir.remove())

const convenience = () => ({ item: "example-key", policyMode: "relaxed", action: null, session: true, device: false, host: "api.example.com", methods: ["POST", "POST"], path: "/projects/123/**", anchorPath: "/projects/123/issues", reason: "Manage project issues", duration: null, until: null })

test("preview and convenience submit exactly the returned digest and revision without granting access", async () => {
  const proposal = await convenienceProposal(session, convenience(), env)
  expect(proposal).toEqual({ change, reason: "Manage project issues", baseDigest: "a".repeat(43), slotRevision: 3 })
  const result = await proposePolicy(session, proposal, env)
  expect(result).toMatchObject({ status: "pending", ask: { kind: "policy", id: "pol_test", check: { label: "code", value: "CODE42" }, requestedBy: { device: "test-machine", session: "pol-test" } }, next: { command: "mehen wait pol_test" } })
  expect(result.ask?.what).toContain("No access has changed yet")
  expect((await readLedger(vault.slotDir(dir.path), scope())).map((e) => e.ask.id)).toEqual(["pol_test"])
  const sent = vault.seen.filter((s) => s.path === "/v1/policy/proposals").at(-1)
  expect(JSON.parse(sent!.body)).toEqual(proposal)
  expect(vault.seen.some((s) => s.path === "/v1/relay")).toBe(false)
})

test("refusal/missing session or ambiguous selector never broadens and makes zero requests", async () => {
  for (const input of [{ ...convenience(), session: true, device: true }, { ...convenience(), session: false, device: false }, convenience()]) {
    const before = vault.seen.length
    await expect(convenienceProposal(session, input, { ...env, MEHEN_SESSION: "" })).rejects.toMatchObject({ code: "usage" })
    expect(vault.seen.length).toBe(before)
  }
})

test("refusal/file selectors cannot impersonate another device or a different session", async () => {
  for (const selector of [{ device: "dev_other", session: "pol-test" }, { device: change.selector.device, session: "other" }]) {
    const before = vault.seen.length
    await expect(previewPolicy(session, { change: { ...change, selector }, reason: "Task" }, env)).rejects.toMatchObject({ code: "usage" })
    await expect(proposePolicy(session, { change: { ...change, selector }, reason: "Task", baseDigest: "a".repeat(43), slotRevision: 0 }, env)).rejects.toMatchObject({ code: "usage" })
    expect(vault.seen.length).toBe(before)
  }
})

test("explicit device-wide selection is null, never the ambient session", async () => {
  const proposal = await convenienceProposal(session, { ...convenience(), session: false, device: true }, env)
  expect(proposal.change.selector).toEqual({ device: change.selector.device, session: null })
})

test("refusal/invalid finite terms, phase-2 actions, times and broad pins never propose", async () => {
  for (const input of [{ ...convenience(), policyMode: "standard" }, { ...convenience(), action: "approve" }, { ...convenience(), duration: "0" }, { ...convenience(), duration: "9h" }, { ...convenience(), until: "tomorrow" }, { ...convenience(), until: new Date(Date.now() - 1000).toISOString() }, { ...convenience(), duration: "1h", until: new Date().toISOString() }, { ...convenience(), path: "/**" }, { ...convenience(), methods: ["DELETE"] }]) {
    await expect(convenienceProposal(session, input, env)).rejects.toMatchObject({ code: "usage" })
  }
  expect(vault.seen.some((s) => s.path === "/v1/policy/proposals")).toBe(false)
})

test("catalogue basis and lifetime defaults are deterministic, --until is capped with its deadline", async () => {
  vault.items.push(item("github-key", { binding: { hosts: ["api.github.com"] } }))
  const reviewed = await convenienceProposal(session, { ...convenience(), item: "github-key", host: "api.github.com", path: "/repos/alex/vault/issues/**", anchorPath: "/repos/alex/vault/issues" }, env)
  expect(reviewed.change).toMatchObject({ scope: { basis: "reviewed" }, ttlSeconds: 7200 })
  const now = Date.now()
  const until = new Date(now + 12 * 3600000).toISOString()
  const unreviewed = await convenienceProposal(session, { ...convenience(), until }, env, now)
  expect(unreviewed.change).toMatchObject({ ttlSeconds: 28800, notAfter: until })
})

test("refusal/a changed preview is conflict and never silently relabelled or retried", async () => {
  vault.overrides.set("POST /v1/policy/preview", () => Response.json(policyPreview({ ...change, selector: { ...change.selector, session: null } })))
  await expect(convenienceProposal(session, convenience(), env)).rejects.toMatchObject({ code: "conflict" })
  expect(vault.seen.filter((s) => s.path === "/v1/policy/preview")).toHaveLength(1)
  expect(vault.seen.some((s) => s.path === "/v1/policy/proposals")).toBe(false)
})

test("refusal/malformed proposal links are rebuilt at the enrolled origin with a warning", async () => {
  for (const url of ["https://evil.example/p/pol_test", `${vault.url}/w/mock-space/p/pol_other`, `${vault.url}/w/mock-space/p/pol_test?x=1`, `${vault.url}/w/mock-space/p/pol_test#x`, `${vault.url}/w/mock-space/p/pol_%74est`, `${vault.url.replace('://', '://user@')}/p/pol_test`]) {
    vault.overrides.set("POST /v1/policy/proposals", () => Response.json({ ...policyCreated(change, vault.url), url, next: { url, command: "evil", say: url } }))
    const pending = proposePolicy(session, { change, reason: "Task", baseDigest: "a".repeat(43), slotRevision: 3 }, env)
    await expect(pending).resolves.toMatchObject({ url: `${vault.url}/w/mock-space/p/pol_test` })
    const accepted = await pending
    expect(String(accepted.url)).toBe(`${vault.url}/w/mock-space/p/pol_test`)
    expect(accepted.warning).not.toBeNull()
    expect(JSON.stringify(accepted)).not.toContain("evil")
  }
})

test("refusal/terminal proposal results preserve the actual narrowed and ended outcome", async () => {
  await proposePolicy(session, { change, reason: "Task", baseDigest: "a".repeat(43), slotRevision: 3 }, env)
  const outcome = { change: { ...change, ttlSeconds: 60 }, override: "pov_narrowed", grant: null, effectiveUntil: new Date().toISOString(), active: false, endedReason: "revoked" }
  vault.overrides.set("POST /v1/policy/proposals", () => Response.json({ ...policyCreated(change, vault.url), status: "approved", outcome }))
  expect(await proposePolicy(session, { change, reason: "Task", baseDigest: "a".repeat(43), slotRevision: 3 }, env)).toMatchObject({ status: "approved", outcome, ask: null })
  expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])
  for (const status of ["denied", "expired", "cancelled", "stale"]) {
    vault.overrides.set("POST /v1/policy/proposals", () => Response.json({ ...policyCreated(change, vault.url), status }))
    await expect(proposePolicy(session, { change, reason: "Task", baseDigest: "a".repeat(43), slotRevision: 3 }, env)).rejects.toMatchObject({ code: status })
  }
})

test("cancel removes the local ask, Stop signs only the matching id route, show uses only current proof context", async () => {
  await proposePolicy(session, { change, reason: "Task", baseDigest: "a".repeat(43), slotRevision: 3 }, env)
  vault.overrides.set("POST /v1/policy/proposals/pol_test/cancel", () => { const { url: _url, next: _next, ...status } = policyCreated(change, vault.url); return Response.json({ ...status, status: "cancelled" }) })
  expect((await cancelPolicy(session, "pol_test")).status).toBe("cancelled")
  expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])
  for (const id of ["pov_test", "gnt_test"]) {
    vault.overrides.set(`POST /v1/policy/${id.startsWith("pov_") ? "overrides" : "grants"}/${id}/revoke`, () => Response.json({ id, stopped: [id], status: "revoked", effectiveAt: new Date().toISOString() }))
    expect((await stopPolicy(session, id)).status).toBe("revoked")
  }
  vault.overrides.set("GET /v1/policy/context", () => Response.json(policyContext(change)))
  expect((await showPolicy(session, "example-key")).item).toBe("example-key")
  expect(vault.seen.at(-1)).toMatchObject({ search: "?item=example-key", claims: { sid: "pol-test" } })
})

test("refusal/invalid stop, cancel, item and response ids never become request paths or accepted results", async () => {
  const before = vault.seen.length
  await expect(stopPolicy(session, "pov_x/next")).rejects.toMatchObject({ code: "usage" })
  await expect(cancelPolicy(session, "pol_x?wait=1")).rejects.toMatchObject({ code: "usage" })
  await expect(showPolicy(session, "bad/slug")).rejects.toMatchObject({ code: "usage" })
  expect(vault.seen.length).toBe(before)
  vault.overrides.set("POST /v1/policy/overrides/pov_test/revoke", () => Response.json({ id: "pov_other", stopped: [], status: "revoked", effectiveAt: new Date().toISOString() }))
  await expect(stopPolicy(session, "pov_test")).rejects.toMatchObject({ code: "internal" })
})

test("refusal/unsupported or failed state is unavailable, never an invented empty active list", async () => {
  const me = await session.api.request<Me>("GET", "/v1/me")
  expect(policyCapabilities(me)).toEqual({ environmentV2: false, runBaseUrl: false, runFiles: false, sealedEnvImport: false, policyV1: false })
  const before = vault.seen.length
  expect(await readPolicyState(session.api, vault.url, me)).toBeNull()
  expect(vault.seen.length).toBe(before)
  const supported = { ...me, capabilities: { ...policyCapabilities(me), policyV1: true } }
  vault.overrides.set("GET /v1/policy/state", () => vaultError("internal", "No state"))
  expect(await readPolicyState(session.api, vault.url, supported)).toBeNull()
  vault.overrides.set("GET /v1/policy/state", () => Response.json({ widening: [], observedAt: new Date().toISOString() }))
  expect(await readPolicyState(session.api, vault.url, supported)).toMatchObject({ widening: [] })
})

test("refusal/invalid responses or mismatched context, proposal and cancellation identity never pass through", async () => {
  for (const value of [null, {}, { ...policyContext(change), item: "other-key" }, { ...policyContext(change), selector: { device: "dev_other", session: null } }]) {
    vault.overrides.set("GET /v1/policy/context", () => Response.json(value))
    await expect(showPolicy(session, "example-key")).rejects.toMatchObject({ code: "internal" })
  }
  for (const value of [null, { ...policyCreated(change, vault.url), item: "other-key" }, { ...policyCreated(change, vault.url), proposal: "pol_x/next" }]) {
    vault.overrides.set("POST /v1/policy/proposals", () => Response.json(value))
    await expect(proposePolicy(session, { change, reason: "Task", baseDigest: "a".repeat(43), slotRevision: 3 }, env)).rejects.toMatchObject({ code: "internal" })
  }
  const { url: _url, next: _next, ...status } = policyCreated(change, vault.url)
  vault.overrides.set("POST /v1/policy/proposals/pol_test/cancel", () => Response.json({ ...status, proposal: "pol_other", status: "cancelled" }))
  await expect(cancelPolicy(session, "pol_test")).rejects.toMatchObject({ code: "internal" })
})

test("refusal/proposal input remains strict even when called without a CLI or MCP parser", async () => {
  const before = vault.seen.length
  for (const value of [{ change, reason: "Task", baseDigest: "a".repeat(43), slotRevision: 0, controls: {} }, { change: { ...change, selector: { ...change.selector, run: "run_test" } }, reason: "Task", baseDigest: "a".repeat(43), slotRevision: 0 }]) {
    await expect(proposePolicy(session, value, env)).rejects.toMatchObject({ code: "usage" })
  }
  expect(vault.seen.length).toBe(before)
})

test("installed waiter retains remembered grant kind, scope, parent and exact stopped wording", () => {
  const grant = { id: "gnt_test", uses: null, expiresAt: new Date().toISOString(), kind: "route", scope: { selector: change.selector, route: change.scope }, parent: "pov_test" }
  expect(settle("approval", "apr_test", { approval: "apr_test", status: "approved", grant })).toMatchObject({ status: { grant } })
  try {
    settle("approval", "apr_test", { approval: "apr_test", status: "revoked", grant })
    throw new Error("revoked settled as success")
  } catch (error) {
    expect(error).toMatchObject({ code: "denied", extras: { status: "revoked", grant }, next: { say: "This approval or grant was stopped. Do not retry it or work around it; ask the human before proposing access again." } })
  }
})

// ---------------------------------------------------------------- standing rules

const exampleSource = () => ({ item: "example-key", method: "post", url: "https://api.example.com/tasks", body: new TextEncoder().encode('{"a":1}'), contentType: "application/json", context: null })

test("ruleProposal builds the vault's PolicyRuleProposal, and refuses what the vault would", () => {
  expect(ruleProposal({ source: exampleSource(), path: null, duration: "1d", reason: "Track" }, "h")).toEqual(PolicyRuleProposalSchema.parse({ from: { item: "example-key", method: "POST", url: "https://api.example.com/tasks", bodyBase64: "eyJhIjoxfQ==", contentType: "application/json" }, ttlSeconds: 86_400, reason: "Track" }))
  expect(ruleProposal({ source: { approval: "apr_held1" }, path: "/tasks/*", duration: null, reason: "Track" }, "h")).toEqual({ from: { approval: "apr_held1" }, path: "/tasks/*", reason: "Track" })
  for (const input of [{ source: exampleSource(), path: null, duration: "2h", reason: "x" }, { source: { ...exampleSource(), method: "DELETE" }, path: null, duration: null, reason: "x" }, { source: exampleSource(), path: "/tasks/**", duration: null, reason: "x" }, { source: exampleSource(), path: null, duration: null, reason: " " }, { source: { approval: "pol_x" }, path: null, duration: null, reason: "x" }]) {
    expect(() => ruleProposal(input, "h")).toThrow(expect.objectContaining({ code: "usage" }))
  }
})

test("proposeRule hands over the proposal's ask; an older vault's answer without stage or rule still works", async () => {
  const { stage: _stage, rule: _rule, ...old } = ruleCreated(vault.url)
  vault.overrides.set("POST /v1/policy/proposals", () => Response.json(old, { status: 201 }))
  const result = await proposeRule(session, ruleProposal({ source: exampleSource(), path: null, duration: null, reason: "Track" }, "h"))
  expect(result).toMatchObject({ proposal: "pol_rule", status: "pending", ask: { kind: "policy", url: `${vault.url}/w/mock-space/p/pol_rule`, check: { value: "CODE42" } }, next: { command: "mehen wait pol_rule" }, warning: null })
  expect(result.stage).toBeUndefined()
})

test("refusal/proposeRule rebuilds a foreign proposal link at the enrolled origin and refuses a mismatched item", async () => {
  vault.overrides.set("POST /v1/policy/proposals", () => Response.json({ ...ruleCreated(vault.url), url: "https://evil.example/w/mock-space/p/pol_rule" }, { status: 201 }))
  const rebuilt = await proposeRule(session, ruleProposal({ source: exampleSource(), path: null, duration: null, reason: "Track" }, "h"))
  expect(String(rebuilt.url)).toBe(`${vault.url}/w/mock-space/p/pol_rule`)
  expect(rebuilt.warning).not.toBeNull()
  vault.overrides.set("POST /v1/policy/proposals", () => Response.json(ruleCreated(vault.url, { item: "other-key" }), { status: 201 }))
  await expect(proposeRule(session, ruleProposal({ source: exampleSource(), path: null, duration: null, reason: "Track" }, "h"))).rejects.toMatchObject({ code: "internal" })
})

test("ruleCall reads the switched-off forbidden as one line with the vault's next; other refusals pass through", async () => {
  vault.overrides.set("POST /v1/policy/proposals", () => vaultError(RULES_OFF.error, RULES_OFF.message, { next: RULES_OFF.next! }))
  await expect(proposeRule(session, ruleProposal({ source: { approval: "apr_held1" }, path: null, duration: null, reason: "x" }, "h"))).rejects.toMatchObject({ code: "forbidden", message: "Standing rules are not switched on for this workspace yet.", next: RULES_OFF.next })
  vault.overrides.set("POST /v1/policy/proposals", () => vaultError("forbidden", "A guest's machine cannot propose a rule."))
  await expect(proposeRule(session, ruleProposal({ source: { approval: "apr_held1" }, path: null, duration: null, reason: "x" }, "h"))).rejects.toMatchObject({ code: "forbidden", message: "A guest's machine cannot propose a rule." })
})

// ---------------------------------------------------------------- task grants

test("areaProposal builds the vault's PolicyAreaProposal from a held request, and refuses what the vault would", () => {
  const base = { approval: "apr_held1", item: "github-work", areas: ["issues"], duration: null, uses: null, reason: "Triage" }
  expect(areaProposal(base, "h")).toEqual(PolicyAreaProposalSchema.parse({ from: { approval: "apr_held1" }, area: { item: "github-work", areas: ["issues"] }, reason: "Triage" }))
  expect(areaProposal({ ...base, areas: ["pulls", "issues"], duration: "15m", uses: "1" }, "h")).toEqual({ from: { approval: "apr_held1" }, area: { item: "github-work", areas: ["pulls", "issues"], ttlSeconds: 900, maxUses: 1 }, reason: "Triage" })
  expect(areaProposal({ ...base, duration: "4h", uses: "200" }, "h").area).toMatchObject({ ttlSeconds: 14_400, maxUses: 200 })
  for (const input of [{ duration: "1d" }, { duration: "30m" }, { uses: "0" }, { uses: "201" }, { uses: "1e2" }, { uses: "-1" }, { uses: "" }, { areas: [] }, { areas: ["issues", "issues"] }, { areas: ["Issues"] }, { approval: "pol_x" }, { item: "Not A Slug" }, { reason: " " }]) {
    expect(() => areaProposal({ ...base, ...input }, "h"), JSON.stringify(input)).toThrow(expect.objectContaining({ code: "usage" }))
  }
})

test("proposeArea hands over the proposal's ask and refuses an answer for another credential", async () => {
  vault.overrides.set("POST /v1/policy/proposals", () => Response.json(grantCreated(vault.url), { status: 201 }))
  const result = await proposeArea(session, areaProposal({ approval: "apr_held1", item: "github-work", areas: ["issues"], duration: null, uses: null, reason: "Triage" }, "h"))
  expect(result).toMatchObject({ proposal: "pol_grant", status: "pending", ask: { kind: "policy", url: `${vault.url}/w/mock-space/p/pol_grant`, check: { value: "CODE42" } }, next: { command: "mehen wait pol_grant" }, warning: null })
  vault.overrides.set("POST /v1/policy/proposals", () => Response.json(grantCreated(vault.url, { item: "other-key" }), { status: 201 }))
  await expect(proposeArea(session, areaProposal({ approval: "apr_held1", item: "github-work", areas: ["issues"], duration: null, uses: null, reason: "Triage" }, "h"))).rejects.toMatchObject({ code: "internal" })
})

test("a 0.3.16-shaped list (rules only, the four rule endings) still parses for ls and --grants; a grant row parses only where grants are asked for", async () => {
  const rules = [ruleView({ id: "rul_live" }), ruleView({ id: "rul_old", status: "ended", endedReason: "credential-changed" })]
  vault.overrides.set("GET /v1/policy/rules", () => Response.json(rules))
  expect(await listRules(session, null)).toEqual(rules)
  expect(await listRulesAndGrants(session, null)).toEqual(rules)
  const grant = grantView({ id: "rul_grant", status: "ended", endedReason: "replaced" })
  vault.overrides.set("GET /v1/policy/rules", () => Response.json([...rules, grant]))
  expect(await listRulesAndGrants(session, "github-work")).toEqual([...rules, grant])
  await expect(listRules(session, null)).rejects.toMatchObject({ code: "internal" })
  // A field the vault adds later is dropped, never passed through.
  vault.overrides.set("GET /v1/policy/rules", () => Response.json([{ ...grant, later: "x" }]))
  expect(await listRulesAndGrants(session, null)).toEqual([grant])
  for (const broken of [{ ...grant, endedReason: "melted" }, { ...grant, maxUses: 0 }, { ...grant, areas: ["pulls", "issues"] }, { ...grant, receipt: [{ entry: "x" }] }]) {
    vault.overrides.set("GET /v1/policy/rules", () => Response.json([broken]))
    await expect(listRulesAndGrants(session, null)).rejects.toMatchObject({ code: "internal" })
  }
})

test("rulesAllowed looks rules and task grants up once with include=grants; postureAllowed reads only the levels it knows", async () => {
  vault.overrides.set("GET /v1/policy/rules", () => Response.json([ruleView({ id: "rul_live", endsAt: "2027-01-10T14:00:00.000Z" }), grantView({ id: "rul_grant", endsAt: "2027-01-10T16:40:00.000Z", uses: 7, maxUses: 10 })]))
  const response = new Response("ok", { headers: { "Mehen-Rule": "rul_live, rul_grant", "Mehen-Posture": "routine, trust" } })
  expect(await rulesAllowed(session.api, response, "github-work")).toEqual([{ id: "rul_live", endsAt: "2027-01-10T14:00:00.000Z" }, { id: "rul_grant", endsAt: "2027-01-10T16:40:00.000Z", grant: { uses: 7, maxUses: 10 } }])
  expect(vault.seen.filter((s) => s.path === "/v1/policy/rules").map((s) => s.search)).toEqual(["?item=github-work&include=grants"])
  expect(postureAllowed(response)).toEqual(["routine", "trust"])
  expect(postureAllowed(new Response("ok"))).toBeNull()
  expect(postureAllowed(new Response("ok", { headers: { "Mehen-Posture": "ask" } }))).toBeNull()
})
