import { expect, test } from "bun:test"
import { z } from "zod"
import { PolicyRuleProposalSchema } from "@mehen/protocol/policy-mode"
import type { VaultSession } from "../session.ts"
import { RULES_OFF, RULES_OFF_BODY, grantCreated, grantView, ruleCreated, rulePreview, ruleStatus, ruleView } from "../testing/policy-rules-fixtures.ts"
import { VaultApiError, type VaultApi } from "../vault-api.ts"
import { CallRegistry } from "./call-registry.ts"
import type { ToolDeps } from "./shared.ts"
import { vaultPolicy } from "./vault-policy.ts"

const call = { signal: new AbortController().signal, progressToken: null }
const VAULT = "https://vault.example"
function deps(api: VaultApi, configDir = "/unused"): ToolDeps {
  const config = { vault: VAULT, tenant: "ten_test", device: "dev_test", backend: "software" as const, workspaceSlug: "test-space", workspaceName: "Test Space" }
  const session: VaultSession = { api, config, vaultUrl: config.vault, configDir, selection: { dir: configDir, config, reason: "workspace" }, ledger: { vaultUrl: config.vault, workspace: config.tenant, device: config.device, workspaceSlug: "test-space" }, context: { origin: config.vault, workspace: null, device: config.device } }
  const server = { home: "/unused", managed: null, ceiling: null, allowed: null, pin: null, manifest: null, slots: new Map(), seen: new Map(), realRoot: "/unused" }
  return { env: {}, server, apps: { negotiated: false }, used: null, session: async () => session, span: async () => ({ active: [], pending: [], corrupt: [], absent: [] }), open: async () => session, validate: async () => config, notify: () => {}, calls: new CallRegistry(), toolsets: ["core", "policy"] }
}

type Seen = { method: string; path: string; body: unknown }
function vault(answer: (seen: Seen) => unknown): { api: VaultApi; seen: Seen[] } {
  const seen: Seen[] = []
  const api: VaultApi = {
    request: async <T>(method: string, path: string, body?: unknown) => {
      const request = { method, path, body }
      seen.push(request)
      if (path === "/v1/me") return { name: "test-machine" } as T
      return answer(request) as T
    },
    relay: async () => { throw new Error("unexpected relay") },
  }
  return { api, seen }
}

const example = { item: "example-key", method: "POST", url: "https://api.example.com/tasks" }

test("vault_policy has a closed object-root input schema with the seven rule actions, flag-shaped", () => {
  const schema = z.toJSONSchema(vaultPolicy.input, { io: "input" })
  expect(schema.type).toBe("object")
  for (const key of ["oneOf", "anyOf", "allOf"]) expect(schema).not.toHaveProperty(key)
  expect(JSON.stringify(schema)).toContain('"additionalProperties":false')
  expect((schema.properties as { action: { enum: string[] } }).action.enum).toEqual(["show", "ls", "preview", "propose", "status", "cancel", "revoke"])
  for (const value of [
    { action: "show", item: "example-key" },
    { action: "ls" },
    { action: "ls", item: "example-key" },
    { action: "preview", from: "apr_held1" },
    { action: "propose", ...example, body: "{}", contentType: "application/json", context: { project: "prj_3kQ9vXyZ7", environment: "dev" }, path: "/tasks", for: "30d", reason: "Track tasks" },
    { action: "status", id: "pol_rule" },
    { action: "cancel", id: "pol_rule" },
    { action: "revoke", id: "rul_live" },
  ]) expect(vaultPolicy.input.safeParse(value).success).toBe(true)
  expect(vaultPolicy.description).toContain("only the person's passkey turns a rule on")
  expect(vaultPolicy.description).toContain("Rules never cover sending messages, moving money, sharing or publishing, credential or access changes, anything left running or deletes, nor protected environments or credentials holding a live key.")
})

test("vault_policy's method names only the methods a standing rule covers", () => {
  const schema = z.toJSONSchema(vaultPolicy.input, { io: "input" })
  expect((schema.properties as { method: { description: string } }).method.description).toBe("preview or propose example: GET, HEAD, POST, PUT or PATCH.")
})

test("refusal/vault_policy refuses approve, the window actions, mixed sources, bad durations and ids before session or network", async () => {
  const { api, seen } = vault(() => { throw new Error("unexpected request") })
  let sessions = 0
  const dependencies = { ...deps(api), session: async () => { sessions++; throw new Error("unexpected session") } }
  for (const value of [
    { action: "approve", id: "pol_test" },
    { action: "stop", id: "rul_live" },
    { action: "show", item: "example-key", id: "rul_live" },
    { action: "propose", from: "apr_held1" },
    { action: "propose", from: "apr_held1", ...example, reason: "x" },
    { action: "propose", from: "apr_held1", context: { project: "prj_3kQ9vXyZ7", environment: "dev" }, reason: "x" },
    { action: "propose", item: "example-key", method: "POST", reason: "x" },
    { action: "propose", ...example, body: "{}", bodyBase64: "e30=", reason: "x" },
    { action: "propose", ...example, method: "DELETE", reason: "x" },
    { action: "preview", ...example, for: "2d" },
    { action: "revoke", id: "pol_rule" },
    { action: "status", id: "rul_live" },
    { action: "cancel", id: "pol_x/next" },
  ]) {
    await expect(vaultPolicy.call(value, dependencies, call)).rejects.toMatchObject({ code: "usage" })
  }
  expect(sessions).toBe(0)
  expect(seen).toEqual([])
})

test("propose sends the PolicyRuleProposal, says which context it sent and hands over the Allow from now on ask", async () => {
  const { tempDir } = await import("../testing/run-mehen.ts")
  const dir = await tempDir()
  try {
    const { api, seen } = vault(() => ruleCreated(VAULT, { summary: "POST api.example.com/tasks, from test-machine, in project-a / dev, 7 days" }))
    const result = await vaultPolicy.call({ action: "propose", ...example, body: "{}", contentType: "application/json", context: { project: "prj_3kQ9vXyZ7", environment: "dev" }, for: "1d", reason: "Track tasks" }, deps(api, dir.path), call)
    const sent = seen.find((s) => s.path === "/v1/policy/proposals")
    expect(sent).toMatchObject({ method: "POST" })
    expect(sent?.body).toEqual(PolicyRuleProposalSchema.parse({ from: { ...example, bodyBase64: "e30=", contentType: "application/json", context: { project: "prj_3kQ9vXyZ7", environment: "dev" } }, ttlSeconds: 86_400, reason: "Track tasks" }))
    expect(result.structured).toMatchObject({ proposal: "pol_rule", status: "pending", note: "Context sent: project prj_3kQ9vXyZ7, environment dev." })
    expect(result.handover).toMatchObject([{ ask: { kind: "policy", title: "Allow from now on", url: `${VAULT}/w/test-space/p/pol_rule`, check: { label: "code", value: "CODE42" } }, then: 'vault_wait { "id": "pol_rule" }' }])
    const none = await vaultPolicy.call({ action: "propose", ...example, reason: "Track tasks" }, deps(api, dir.path), call)
    expect(none.structured.note).toBe("No context was sent: the rule will cover only requests made outside any project. Give context to bind one.")
    const held = await vaultPolicy.call({ action: "propose", from: "apr_held1", reason: "Track tasks" }, deps(api, dir.path), call)
    expect(seen.filter((s) => s.path === "/v1/policy/proposals").at(-1)?.body).toEqual({ from: { approval: "apr_held1" }, reason: "Track tasks" })
    expect(held.structured.note).toBe("Context: the one apr_held1 was asked in.")
  } finally { await dir.remove() }
})

test("preview, ls, status, cancel and revoke each call one route and return the vault's answer, with no handover", async () => {
  const preview = rulePreview(), rules = [ruleView()], status = ruleStatus({ stage: "co-sign" }), revoked = ruleView({ status: "ended", endedReason: "revoked" })
  const { api, seen } = vault(({ path }) => {
    if (path === "/v1/policy/preview") return preview
    if (path.startsWith("/v1/policy/rules?") || path === "/v1/policy/rules") return rules
    if (path === "/v1/policy/proposals/pol_rule") return status
    if (path === "/v1/policy/proposals/pol_rule/cancel") return ruleStatus({ status: "cancelled" })
    if (path === "/v1/policy/rules/rul_live/revoke") return revoked
    throw new Error(`unexpected ${path}`)
  })
  const run = (value: Record<string, unknown>) => vaultPolicy.call(value, deps(api), call)
  const previewed = await run({ action: "preview", ...example })
  expect(previewed.structured).toEqual(preview)
  expect(previewed.handover).toEqual([])
  expect(seen.at(-1)?.body).toMatchObject({ from: example })
  expect((await run({ action: "ls", item: "example-key" })).structured).toEqual({ rules })
  expect(seen.at(-1)).toMatchObject({ method: "GET", path: "/v1/policy/rules?item=example-key" })
  expect((await run({ action: "status", id: "pol_rule" })).structured).toMatchObject({ proposal: "pol_rule", stage: "co-sign" })
  expect((await run({ action: "cancel", id: "pol_rule" })).structured).toMatchObject({ status: "cancelled" })
  expect(seen.at(-1)).toMatchObject({ method: "POST", path: "/v1/policy/proposals/pol_rule/cancel", body: {} })
  expect((await run({ action: "revoke", id: "rul_live" })).structured).toEqual(revoked)
  expect(seen.at(-1)).toMatchObject({ method: "POST", path: "/v1/policy/rules/rul_live/revoke", body: {} })
})

test("switch off: every rule action answers the one line with the forbidden code and the vault's next", async () => {
  const { api } = vault(({ path }) => { throw path === "/v1/policy/preview" || path === "/v1/policy/proposals" ? new VaultApiError(400, RULES_OFF_BODY) : new VaultApiError(403, RULES_OFF) })
  for (const value of [{ action: "ls" }, { action: "preview", from: "apr_held1" }, { action: "propose", from: "apr_held1", reason: "x" }, { action: "status", id: "pol_rule" }, { action: "cancel", id: "pol_rule" }, { action: "revoke", id: "rul_live" }]) {
    await expect(vaultPolicy.call(value, deps(api), call)).rejects.toMatchObject({ code: "forbidden", message: "Standing rules are not switched on for this workspace yet.", next: RULES_OFF.next })
  }
})

test("refusal/vault_policy's flat schema refuses unknown fields before the handler", async () => {
  const value = { action: "show", item: "example-key", unknown: true }
  expect(vaultPolicy.input.safeParse(value).success).toBe(false)
  const { handleMessage } = await import("../mcp.ts")
  const dependencies = { ...deps(vault(() => { throw new Error("unexpected request") }).api), session: async () => { throw new Error("unexpected session") } }
  const reply = await handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "vault_policy", arguments: value } }, dependencies)
  expect(reply).toMatchObject({ result: { isError: true, structuredContent: { error: "usage", next: { say: "Fix the arguments to match the tool's input schema." } } } })
})

test("refusal/vault_policy validates missing and wrong-action fields with action-specific next on the wire", async () => {
  const { handleMessage } = await import("../mcp.ts")
  let sessions = 0
  const dependencies = { ...deps(vault(() => { throw new Error("unexpected request") }).api), session: async () => { sessions++; throw new Error("unexpected session") } }
  for (const [value, say] of [
    [{ action: "revoke" }, "For action revoke, supply only action and id (rul_)."],
    [{ action: "status", item: "example-key" }, "For action status, supply only action and id (pol_)."],
    [{ action: "show" }, "For action show, supply only action and item."],
  ] as const) {
    expect(vaultPolicy.input.safeParse(value).success).toBe(true)
    const reply = await handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "vault_policy", arguments: value } }, dependencies)
    expect(reply).toMatchObject({ result: { isError: true, structuredContent: { error: "usage", message: say, next: { say } } } })
  }
  expect(sessions).toBe(0)
})

test("propose with area sends a task grant from the held request and hands over the ask; ls with grants asks for them", async () => {
  const { tempDir } = await import("../testing/run-mehen.ts")
  const dir = await tempDir()
  try {
    const rows = [ruleView(), grantView()]
    const { api, seen } = vault(({ path }) => (path.startsWith("/v1/policy/rules") ? (path.includes("include=grants") ? rows : [rows[0]]) : grantCreated(VAULT)))
    const result = await vaultPolicy.call({ action: "propose", from: "apr_held1", item: "github-work", area: ["issues", "pulls"], for: "15m", uses: 20, reason: "Triage the backlog" }, deps(api, dir.path), call)
    expect(seen.find((s) => s.path === "/v1/policy/proposals")?.body).toEqual({ from: { approval: "apr_held1" }, area: { item: "github-work", areas: ["issues", "pulls"], ttlSeconds: 900, maxUses: 20 }, reason: "Triage the backlog" })
    expect(result.structured).toMatchObject({ proposal: "pol_grant", status: "pending" })
    expect(result.handover).toMatchObject([{ ask: { kind: "policy", url: `${VAULT}/w/test-space/p/pol_grant`, check: { label: "code", value: "CODE42" } }, then: 'vault_wait { "id": "pol_grant" }' }])
    await vaultPolicy.call({ action: "propose", from: "apr_held1", item: "github-work", area: ["issues"], reason: "x" }, deps(api, dir.path), call)
    expect(seen.filter((s) => s.path === "/v1/policy/proposals").at(-1)?.body).toEqual({ from: { approval: "apr_held1" }, area: { item: "github-work", areas: ["issues"] }, reason: "x" })
    expect((await vaultPolicy.call({ action: "ls", grants: true }, deps(api), call)).structured).toEqual({ rules: rows })
    expect(seen.at(-1)).toMatchObject({ method: "GET", path: "/v1/policy/rules?include=grants" })
    await vaultPolicy.call({ action: "ls", item: "github-work", grants: false }, deps(api), call)
    expect(seen.at(-1)).toMatchObject({ method: "GET", path: "/v1/policy/rules?item=github-work" })
  } finally { await dir.remove() }
})

test("refusal/vault_policy refuses a task grant without from, item or reason, mixed with a rule's fields, or with a rule's duration or uses out of range, before session or network", async () => {
  const { api, seen } = vault(() => { throw new Error("unexpected request") })
  let sessions = 0
  const dependencies = { ...deps(api), session: async () => { sessions++; throw new Error("unexpected session") } }
  const grant = { action: "propose", from: "apr_held1", item: "github-work", area: ["issues"], reason: "x" }
  for (const value of [
    { ...grant, from: undefined }, { ...grant, item: undefined }, { ...grant, reason: undefined },
    { ...grant, for: "1d" }, { ...grant, uses: 0 }, { ...grant, uses: 201 }, { ...grant, uses: 2.5 },
    { ...grant, path: "/repos/*" }, { ...grant, method: "POST" }, { ...grant, context: { project: "prj_3kQ9vXyZ7", environment: "dev" } },
    { ...grant, area: [] }, { ...grant, area: ["issues", "issues"] },
    { action: "propose", from: "apr_held1", uses: 5, reason: "x" },
    { action: "propose", ...example, for: "1h", reason: "x" },
    { action: "preview", from: "apr_held1", item: "github-work", area: ["issues"] },
    { action: "show", item: "github-work", grants: true },
  ]) {
    await expect(vaultPolicy.call(value as Parameters<typeof vaultPolicy.call>[0], dependencies, call), JSON.stringify(value)).rejects.toMatchObject({ code: "usage" })
  }
  expect(sessions).toBe(0)
  expect(seen).toEqual([])
})
