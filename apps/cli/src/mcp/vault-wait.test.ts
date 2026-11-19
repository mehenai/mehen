import { afterAll, afterEach, beforeAll, beforeEach, expect, test } from "bun:test"
import { policyAsk, approvalAsk, askUrlFor } from "../ask.ts"
import { addLedgerEntry, readLedger } from "../ledger.ts"
import { mandateCreated } from "../testing/mandate-fixtures.ts"
import { MockVault } from "../testing/mock-vault.ts"
import { runJv, tempDir } from "../testing/run-mehen.ts"

let vault: MockVault
const scope = () => vault.ledgerScope()
let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>

beforeAll(() => { vault = new MockVault() })
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  vault.lastDevice = null
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url }
  vault.overrides.clear()
  await vault.enrolSoftware(dir.path)
})
afterEach(async () => dir.remove())

type WaitOutput = { isError: boolean; structuredContent: Record<string, unknown> }
async function wait(id: string): Promise<WaitOutput> {
  const result = await runJv(["mcp"], env, `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "vault_wait", arguments: { id, timeoutSeconds: 0 } } })}\n`)
  expect(result.code).toBe(0)
  expect(result.stderr).toBe("")
  return (JSON.parse(result.stdout) as { result: WaitOutput }).result
}

const by = { device: "test-machine", session: null }
const expiresAt = () => new Date(Date.now() + 3_600_000).toISOString()
const proposal = () => ({ proposal: "pol_x", item: "example-key", status: "pending", bindingCode: "CODE", summary: "Relax a route", expiresAt: expiresAt(), outcome: null })

async function record(): Promise<void> {
  const link = askUrlFor(vault.askVault(), "policy", "pol_x")!
  await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask: policyAsk({ id: "pol_x", url: link.url, summary: "Relax a route", bindingCode: "CODE", expiresAt: expiresAt(), requestedBy: by }) })
}

test("vault_wait pol_ returns the actual narrowed and ended policy outcome", async () => {
  await record()
  const outcome = { change: { kind: "mode", policyMode: "relaxed", ttlSeconds: 60 }, override: "pov_narrowed", grant: null, effectiveUntil: expiresAt(), active: false, endedReason: "revoked" }
  vault.overrides.set("GET /v1/policy/proposals/pol_x", () => Response.json({ ...proposal(), status: "approved", outcome }))
  const result = await wait("pol_x")
  expect(result.isError).toBe(false)
  expect(result.structuredContent).toMatchObject({ id: "pol_x", kind: "policy", status: "approved", outcome })
  expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])
})

test("vault_wait policy terminal refusals retain status and remove the locked entry", async () => {
  for (const status of ["denied", "expired", "cancelled", "stale"] as const) {
    await record()
    vault.overrides.set("GET /v1/policy/proposals/pol_x", () => Response.json({ ...proposal(), status }))
    const result = await wait("pol_x")
    expect(result.isError).toBe(true)
    expect(result.structuredContent).toMatchObject({ error: status, kind: "policy", status })
    expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])
  }
})

test("vault_wait stale/revoked approval retains grant metadata and distinct stopped text", async () => {
  const grant = { id: "gnt_x", uses: null, expiresAt: expiresAt(), kind: "route", scope: { selector: { device: "dev_x", session: null }, route: null }, parent: "pov_x" }
  for (const status of ["revoked", "stale"] as const) {
    const url = askUrlFor(vault.askVault(), "approval", "apr_x")!.url
    await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask: approvalAsk({ id: "apr_x", url, summary: "Read", bindingCode: "CODE", expiresAt: expiresAt(), requestedBy: by }) })
    vault.overrides.set("GET /v1/approvals/apr_x", () => Response.json({ approval: "apr_x", status, item: "example-key", grant, summary: "Read", expiresAt: expiresAt() }))
    const result = await wait("apr_x")
    expect(result.isError).toBe(true)
    expect(result.structuredContent).toMatchObject({ kind: "approval", status, grant, error: status === "revoked" ? "denied" : "stale" })
    if (status === "revoked") {
      expect(JSON.stringify(result.structuredContent.next)).toContain("stopped")
      expect(JSON.stringify(result.structuredContent.next)).not.toContain("denied")
    }
    expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])
  }
})

test("vault_wait on a superseded approval ends at once with the newer ask's wait and removes the entry", async () => {
  const url = askUrlFor(vault.askVault(), "approval", "apr_old")!.url
  await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask: approvalAsk({ id: "apr_old", url, summary: "Create", bindingCode: "CODE", expiresAt: expiresAt(), requestedBy: by }) })
  vault.overrides.set("GET /v1/approvals/apr_old", () => Response.json({ approval: "apr_old", status: "superseded", replacedBy: "apr_new", item: "example-key", summary: "Create", bindingCode: "CODE", expiresAt: expiresAt() }))
  const result = await wait("apr_old")
  expect(result.isError).toBe(true)
  expect(result.structuredContent).toMatchObject({ error: "superseded", kind: "approval", replacedBy: "apr_new", next: { say: "Wait on apr_new; if you meant both, send them together with mehen plan submit.", tool: "vault_wait", arguments: { id: "apr_new" } } })
  expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])
})

test("vault_wait timeout retains the policy ask and never settles pending access", async () => {
  await record()
  vault.overrides.set("GET /v1/policy/proposals/pol_x", () => Response.json(proposal()))
  const result = await wait("pol_x")
  expect(result.isError).toBe(true)
  expect(result.structuredContent).toMatchObject({ error: "timeout", ask: { kind: "policy", id: "pol_x" } })
  expect((await readLedger(vault.slotDir(dir.path), scope())).map((e) => e.ask.id)).toEqual(["pol_x"])
})

test("vault_wait refuses hostile pol_ ids before making a vault request", async () => {
  for (const id of ["pol_", "pol_x/next", "pol_x?wait=1", "pol_x#fragment", "pol_x\n", "imp_x"]) {
    const before = vault.seen.length
    const result = await wait(id)
    expect(result.isError).toBe(true)
    expect(result.structuredContent.error).toBe("usage")
    expect(vault.seen.length).toBe(before)
  }
})

test("vault_wait apr_ after a remember carries the rule, or the co-sign proposal at this vault's link only", async () => {
  const approved = { approval: "apr_x", status: "approved", item: "example-key", summary: "Create a task", bindingCode: "CODE", expiresAt: expiresAt(), grant: null }
  const rule = { id: "rul_live", endsAt: expiresAt() }
  vault.overrides.set("GET /v1/approvals/apr_x", () => Response.json({ ...approved, rule }))
  expect((await wait("apr_x")).structuredContent).toMatchObject({ kind: "approval", status: "approved", rule })
  const ruleProposal = { id: "pol_cosign", url: askUrlFor(vault.askVault(), "policy", "pol_cosign")!.url, bindingCode: "COSIGN", expiresAt: expiresAt() }
  vault.overrides.set("GET /v1/approvals/apr_x", () => Response.json({ ...approved, ruleProposal }))
  expect((await wait("apr_x")).structuredContent).toMatchObject({ kind: "approval", ruleProposal })
  vault.overrides.set("GET /v1/approvals/apr_x", () => Response.json({ ...approved, ruleProposal: { ...ruleProposal, url: "https://evil.example/w/mock-space/p/pol_cosign" } }))
  expect((await wait("apr_x")).structuredContent).not.toHaveProperty("ruleProposal")
})

test("vault_wait on a push approval returns once the push is done, and a refused push is provider_refused with its providerStatus", async () => {
  const status = (push: Record<string, unknown>) => ({ approval: "apr_push", status: "used", bindingCode: "K7Q2MX", summary: "Put openai-prod into GitHub acme/app, Actions secret OPENAI_API_KEY, using github-pat-ci", expiresAt: expiresAt(), push: { destination: "github:acme/app/OPENAI_API_KEY", field: "key", version: 3, ...push } })
  vault.overrides.set("GET /v1/approvals/apr_push", () => Response.json(status({ state: "sending" })))
  const sending = await wait("apr_push")
  expect(sending.isError).toBe(true)
  expect(sending.structuredContent).toMatchObject({ error: "timeout", message: "The push was approved and is still being sent. Wait again with mehen wait apr_push; do not push again." })
  expect(JSON.stringify(sending.structuredContent.next)).not.toContain('"command"')
  expect(sending.structuredContent.next).toMatchObject({ tool: "vault_wait", arguments: { id: "apr_push" } })
  expect((sending.structuredContent.next as { say: string }).say).not.toContain("vault_wait")
  expect(sending.structuredContent).not.toHaveProperty("ask")
  expect(JSON.stringify(sending.structuredContent.next)).toContain("do not push again without asking the human")
  expect(JSON.stringify(sending)).not.toContain("A human has not acted yet")
  vault.overrides.set("GET /v1/approvals/apr_push", () => Response.json(status({ state: "done", outcome: "replaced" })))
  const done = await wait("apr_push")
  expect(done.isError).toBe(false)
  expect(done.structuredContent).toMatchObject({ id: "apr_push", kind: "approval", push: { state: "done", outcome: "replaced" } })
  vault.overrides.set("GET /v1/approvals/apr_push", () => Response.json(status({ state: "failed", providerStatus: 404 })))
  const refused = await wait("apr_push")
  expect(refused.isError).toBe(true)
  expect(refused.structuredContent).toMatchObject({ error: "provider_refused", providerStatus: 404, push: { state: "failed" } })
})

test("with two workspaces and none named, vault_wait mdp_ finds the one vault_mandate proposed it in, and vault_pending does not list it", async () => {
  const home = await tempDir()
  try {
    const homeEnv = { HOME: home.path, MEHEN_CONFIG_DIR: "", MEHEN_VAULT_URL: vault.url }
    const root = `${home.path}/.config/mehen`
    await vault.enrolSoftware(root, { config: { tenant: "tn_second00000001", workspaceSlug: "second-space", workspaceName: "Second" } })
    const first = await vault.enrolSoftware(root)
    const callTool = async (name: string, args: Record<string, unknown>) => {
      const result = await runJv(["mcp"], homeEnv, `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } })}\n`)
      return (JSON.parse(result.stdout) as { result: WaitOutput }).result
    }
    vault.overrides.set("GET /v1/mandates/asked", () => Response.json({ items: ["github-work"], classes: [] }))
    vault.overrides.set("POST /v1/mandates/proposals", () => Response.json(mandateCreated(vault.url), { status: 201 }))
    expect((await callTool("vault_mandate", { action: "propose", note: "Nightly triage", workspace: "mock-space" })).isError).toBe(false)
    expect((await callTool("vault_pending", {})).structuredContent).toMatchObject({ pending: [] })
    vault.overrides.set("GET /v1/mandates/proposals/mdp_new", () => Response.json({ proposal: "mdp_new", state: "signed", mandate: "mdt_m1", expiresAt: "2026-11-15T09:00:00.000Z" }))
    const before = vault.seen.length
    const waited = await callTool("vault_wait", { id: "mdp_new", timeoutSeconds: 0 })
    expect(waited.isError).toBe(false)
    expect(waited.structuredContent).toMatchObject({ kind: "mandate", state: "signed", mandate: "mdt_m1" })
    expect(vault.seen.slice(before).map((s) => s.claims.dev)).toEqual([first])
    const gone = await callTool("vault_wait", { id: "mdp_new", timeoutSeconds: 0 })
    expect(gone.structuredContent).toMatchObject({ error: "not_found", next: { say: expect.stringContaining('vault_mandate { "action": "list" }') } })
  } finally {
    await home.remove()
  }
})
