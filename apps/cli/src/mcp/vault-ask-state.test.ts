import { afterAll, afterEach, beforeAll, beforeEach, expect, test } from "bun:test"
import { approvalAsk, askUrlFor } from "../ask.ts"
import { addLedgerEntry, readLedger } from "../ledger.ts"
import { MockVault } from "../testing/mock-vault.ts"
import { jsonLines, runJv, tempDir } from "../testing/run-mehen.ts"

let vault: MockVault
const scope = () => vault.ledgerScope()
let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  vault.lastDevice = null
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url }
  vault.overrides.clear()
  vault.sequences.clear()
  await vault.enrolSoftware(dir.path)
})
afterEach(async () => dir.remove())

type Result = { isError: boolean; structuredContent: Record<string, unknown>; content: { type: string; text?: string }[] }

async function askState(args: Record<string, unknown>): Promise<Result> {
  const result = await runJv(["mcp"], env, `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "vault_ask_state", arguments: args } })}\n`)
  expect(result.code).toBe(0)
  expect(result.stderr).toBe("")
  return (JSON.parse(result.stdout) as { result: Result }).result
}

const by = { device: "test-machine", session: null }
const inMinutes = (n: number) => new Date(Date.now() + n * 60_000).toISOString()

async function recordApproval(id: string, expiresAt = inMinutes(50)): Promise<void> {
  const url = askUrlFor(vault.askVault(), "approval", id)!.url
  await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask: approvalAsk({ id, url, summary: "Send", bindingCode: "Q7", expiresAt, requestedBy: by }) })
}

const ledgerIds = async () => (await readLedger(vault.slotDir(dir.path), scope())).map((e) => e.ask.id)

test("vault_ask_state reads a settled approval as done and leaves the ledger entry for the agent's own vault_wait", async () => {
  const expiresAt = inMinutes(50)
  await recordApproval("apr_done", expiresAt)
  vault.overrides.set("GET /v1/approvals/apr_done", () => Response.json({ approval: "apr_done", status: "approved", bindingCode: "Q7", summary: "Send", secret: "never-shown" }))
  const result = await askState({ id: "apr_done" })
  expect(result.isError).toBe(false)
  expect(result.structuredContent).toEqual({ id: "apr_done", kind: "approval", state: "done", expiresAt, message: "The request was approved." })
  expect(JSON.stringify(result)).not.toContain("never-shown")
  expect(await ledgerIds()).toEqual(["apr_done"])
})

test("vault_ask_state maps each outcome to a card state, from one check and never writing the ledger", async () => {
  const cases: [string, string, () => Promise<void>, Record<string, unknown>, string][] = [
    ["apr_wait", "/v1/approvals/apr_wait", () => recordApproval("apr_wait"), { approval: "apr_wait", status: "pending", summary: "Send", expiresAt: inMinutes(48) }, "waiting"],
    ["apr_no", "/v1/approvals/apr_no", () => recordApproval("apr_no"), { approval: "apr_no", status: "denied", summary: "Send" }, "declined"],
    ["apr_stop", "/v1/approvals/apr_stop", () => recordApproval("apr_stop"), { approval: "apr_stop", status: "revoked", summary: "Send", item: "example-key" }, "declined"],
    ["apr_old", "/v1/approvals/apr_old", () => recordApproval("apr_old"), { approval: "apr_old", status: "expired", summary: "Send" }, "expired"],
    ["apr_moved", "/v1/approvals/apr_moved", () => recordApproval("apr_moved"), { approval: "apr_moved", status: "stale", summary: "Send", item: "example-key" }, "stale"],
    ["int_gone", "/v1/intakes/int_gone", async () => {}, { intake: "int_gone", status: "cancelled" }, "cancelled"],
    ["con_fail", "/v1/connect/con_fail", async () => {}, { connect: "con_fail", status: "failed", message: "the provider refused" }, "failed"],
    ["con_who", "/v1/connect/con_who", async () => {}, { connect: "con_who", status: "mismatch", account: "other@example.com" }, "mismatch"],
    ["pol_wait", "/v1/policy/proposals/pol_wait", async () => {}, { proposal: "pol_wait", item: "example-key", status: "pending", bindingCode: "CODE", summary: "Relax", expiresAt: inMinutes(30), outcome: null }, "waiting"],
    ["adp_open", "/v1/adoptions/adp_open", async () => {}, { adoption: "adp_open", status: "open", expiresAt: inMinutes(60), machines: [] }, "waiting"],
    ["adp_done", "/v1/adoptions/adp_done", async () => {}, { adoption: "adp_done", status: "approved", expiresAt: inMinutes(60), machines: [] }, "done"],
    ["apr_replaced", "/v1/approvals/apr_replaced", () => recordApproval("apr_replaced"), { approval: "apr_replaced", status: "superseded", replacedBy: "apr_newer", summary: "Send" }, "stale"],
    ["bnd_wait", "/v1/approvals/bundles/bnd_wait", async () => {}, { bundle: "bnd_wait", approvals: [{ id: "apr_b1", status: "approved" }, { id: "apr_b2", status: "pending" }] }, "waiting"],
    ["bnd_done", "/v1/approvals/bundles/bnd_done", async () => {}, { bundle: "bnd_done", approvals: [{ id: "apr_b1", status: "approved" }, { id: "apr_b2", status: "used" }] }, "done"],
    ["bnd_no", "/v1/approvals/bundles/bnd_no", async () => {}, { bundle: "bnd_no", approvals: [{ id: "apr_b1", status: "approved" }, { id: "apr_b2", status: "denied" }] }, "declined"],
  ]
  for (const [id, path, record, body, state] of cases) {
    await record()
    const before = await ledgerIds()
    vault.overrides.set(`GET ${path}`, () => Response.json(body))
    const polls = vault.seen.length
    const result = await askState({ id })
    expect(result.isError).toBe(false)
    expect(result.structuredContent).toMatchObject({ id, state, message: expect.any(String) })
    expect(Object.keys(result.structuredContent).sort()).toEqual(["expiresAt", "id", "kind", "message", "state"])
    // waitSeconds 0 checks once.
    expect(vault.seen.slice(polls).filter((c) => c.path === path)).toHaveLength(1)
    expect(await ledgerIds()).toEqual(before)
  }
  const waiting = await askState({ id: "pol_wait" })
  expect(waiting.structuredContent.expiresAt).toEqual(expect.any(String))
})

test("vault_ask_state reads a push that did not go through as failed, with or without the provider's status", async () => {
  const push = (providerStatus: number | null) => ({ destination: "github:acme/web/API_TOKEN", field: "key", version: 3, state: "failed", ...(providerStatus === null ? {} : { providerStatus }) })
  for (const [id, providerStatus] of [["apr_refused", 403], ["apr_broke", null]] as const) {
    await recordApproval(id)
    vault.overrides.set(`GET /v1/approvals/${id}`, () => Response.json({ approval: id, status: "used", bindingCode: "Q7", summary: "Push", push: push(providerStatus) }))
    const result = await askState({ id })
    expect(result.isError).toBe(false)
    expect(result.structuredContent).toMatchObject({ id, kind: "approval", state: "failed", message: expect.any(String) })
  }
})

test("vault_ask_state with waitSeconds follows the ask until it changes", async () => {
  await recordApproval("apr_seq")
  vault.sequences.set("approval:apr_seq", [
    { approval: "apr_seq", status: "pending", bindingCode: "Q7", summary: "Send" },
    { approval: "apr_seq", status: "approved", bindingCode: "Q7", summary: "Send" },
  ])
  const result = await askState({ id: "apr_seq", waitSeconds: 10 })
  expect(result.structuredContent).toMatchObject({ id: "apr_seq", state: "done" })
  expect(await ledgerIds()).toEqual(["apr_seq"])
})

test("vault_ask_state refuses an enrolment id and anything that is not an ask id before asking the vault", async () => {
  for (const id of ["enr_abc", "pol_x/next", "imp_x", "apr_"]) {
    const before = vault.seen.length
    const result = await askState({ id })
    expect(result.isError).toBe(true)
    expect(result.structuredContent.error).toBe("usage")
    expect(vault.seen.length).toBe(before)
  }
  expect((await askState({ id: "apr_x", waitSeconds: 26 })).structuredContent.error).toBe("usage")
})

test("vault_ask_state passes a status it does not know through as a tool error", async () => {
  vault.overrides.set("GET /v1/approvals/apr_odd", () => Response.json({ approval: "apr_odd", status: "sideways" }))
  const odd = await askState({ id: "apr_odd" })
  expect(odd.isError).toBe(true)
  expect(odd.structuredContent.error).toBe("internal")
})

test("vault_ask_state is listed only to a host that negotiated MCP Apps, with visibility app", async () => {
  const init = (capabilities: Record<string, unknown>) => JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities, clientInfo: { name: "t", version: "1" } } })
  const list = '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  const tools = async (capabilities: Record<string, unknown>) => {
    const run = await runJv(["mcp"], env, `${init(capabilities)}\n${list}\n`)
    const reply = jsonLines(run.stdout).find((m) => (m as { id?: number }).id === 2) as { result: { tools: { name: string; _meta?: unknown }[] } }
    return reply.result.tools
  }
  expect((await tools({})).map((t) => t.name)).not.toContain("vault_ask_state")
  const negotiated = await tools({ extensions: { "io.modelcontextprotocol/ui": { mimeTypes: ["text/html;profile=mcp-app"] } } })
  expect(negotiated.find((t) => t.name === "vault_ask_state")?._meta).toEqual({ ui: { visibility: ["app"] } })
})
