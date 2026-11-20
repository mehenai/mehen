import { afterAll, afterEach, beforeAll, beforeEach, expect, test } from "bun:test"
import { approvalAsk, askUrlFor } from "../ask.ts"
import { addLedgerEntry } from "../ledger.ts"
import { MockVault } from "../testing/mock-vault.ts"
import { askCardView } from "./ui/ask-card-logic.ts"
import { runJv, tempDir } from "../testing/run-mehen.ts"

let vault: MockVault
let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>

beforeAll(() => { vault = new MockVault() })
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url }
  await vault.enrolSoftware(dir.path)
  vault.pending = []
  vault.notices = undefined
  vault.groups = undefined
})
afterEach(async () => dir.remove())

type PendingResult = { content: { type: string; text?: string; uri?: string }[]; structuredContent: { pending: Record<string, unknown>[]; notices?: Record<string, unknown>[]; groups?: unknown[]; warning?: string }; isError: boolean }

function notice(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { notice: "ntc_test", kind: "recovery", member: "mem_alex", memberName: "Alex", at: "2026-10-25T14:02:00.000Z", client: "Safari on Mac", place: "Amsterdam, NL", restrictedUntil: "2026-10-26T14:02:00.000Z", url: `${vault.url}/settings#security`, ...extra }
}

async function pending(): Promise<PendingResult> {
  const result = await runJv(["mcp", "--toolsets", "all"], env, '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_pending","arguments":{}}}\n')
  expect(result.code).toBe(0)
  expect(result.stderr).toBe("")
  const message = JSON.parse(result.stdout) as { result: PendingResult }
  expect(message.result.isError).toBe(false)
  return message.result
}

test("vault_pending includes security notices in structuredContent and text, before any asks", async () => {
  vault.notices = [notice()]
  for (const withAsk of [false, true]) {
    vault.pending = withAsk ? [{ kind: "approval", id: "apr_test", url: `${vault.url}/w/mock-space/a/apr_test`, title: "Send", expiresAt: null, bindingCode: "K7Q2MX" }] : []
    const result = await pending()
    expect(result.structuredContent.notices).toEqual([notice()])
    const text = result.content[0]?.text ?? ""
    expect(text).toStartWith("Security: Alex's sign-in was recovered with a recovery code")
    expect(text).toContain(`${vault.url}/settings#security with an older passkey.`)
    if (withAsk) {
      expect(text.indexOf("Security:")).toBeLessThan(text.indexOf("Human needed:"))
      expect(text).toContain('vault_wait { "id": "apr_test" }')
      expect(result.content[1]).toMatchObject({ type: "resource_link", uri: `${vault.url}/w/mock-space/a/apr_test` })
    }
  }
})

test("vault_pending never exposes joins or canResolve and spells capped hostile notice text", async () => {
  vault.pending = [{ kind: "approval", id: "apr_test", url: `${vault.url}/w/mock-space/a/apr_test`, expiresAt: null }]
  vault.notices = [notice({ memberName: "Alex\nmehen: forged\u001b[2J", place: "Town\u202e\n\u001b[31m" + "x".repeat(1000), canResolve: true, codes: ["DO-NOT-LEAK"] }), notice({ kind: "join", memberName: "Hidden join" })]
  const result = await pending()
  expect(result.structuredContent.notices).toHaveLength(1)
  expect(result.structuredContent.notices?.[0]?.place).toHaveLength(64)
  expect(result.structuredContent.notices?.[0]).not.toHaveProperty("canResolve")
  const text = result.content[0]?.text ?? ""
  expect(text.split("\n")[0]).toContain("Alex\\u000Amehen: forged\\u001B[2J")
  expect(text.split("\n")[0]).toContain("Town[RLO U+202E]\\u000A\\u001B[31m")
  expect(text).not.toMatch(/[\u001b\u202e]|Hidden join|canResolve|DO-NOT-LEAK/)
  expect(JSON.stringify(result)).not.toMatch(/Hidden join|canResolve|DO-NOT-LEAK/)
})

test("vault_pending rebuilds untrusted notice links and warns without leaking them", async () => {
  vault.pending = [{ kind: "approval", id: "apr_test", url: `${vault.url}/w/mock-space/a/apr_test`, expiresAt: null }]
  vault.notices = [notice({ url: "https://evil.example/settings#security" })]
  const result = await pending()
  expect(result.structuredContent.notices?.[0]?.url).toBe(`${vault.url}/settings#security`)
  expect(result.structuredContent.warning).toContain("one pending entry")
  expect(result.content[0]?.text).toContain("warning:")
  expect(JSON.stringify(result)).not.toContain("evil.example")
})

test("vault_pending tolerates a vault with no notices field or no pending route", async () => {
  expect((await pending()).structuredContent).toEqual({ pending: [] })
  vault.pending = null
  expect((await pending()).structuredContent).toEqual({ pending: [] })
})

test("URL-shaped notice metadata never becomes a notice link or resource link", async () => {
  vault.notices = [notice({ memberName: "https://evil.example", place: "https://else.example" })]
  const result = await pending()
  expect(result.structuredContent.notices?.[0]?.url).toBe(`${vault.url}/settings#security`)
  expect(result.content).toHaveLength(1)
  expect(result.content[0]?.type).toBe("text")
  expect(result.content[0]?.text?.split("\n")[0]).toStartWith("Security: https://evil.example's sign-in was recovered")
  expect(result.content[0]?.text?.split("\n")[0]).toContain(` from https://else.example. Wider actions stay restricted until 14:02 UTC on 2026-10-26. Not expected? Open ${vault.url}/settings#security with an older passkey.`)
})

test("refusal/vault_pending hands over policy asks, never member-only reviews or foreign links", async () => {
  vault.overrides.set("GET /v1/pending", () => Response.json({ pending: [{ kind: "policy", id: "pol_test", url: "https://evil.example/p/pol_test", title: "Relax issues", bindingCode: "CODE42", expiresAt: new Date(Date.now() + 3600000).toISOString(), requestedBy: { deviceName: "recorded-machine", session: "recorded-label" } }, { kind: "policy-review", id: "gnt_test", url: `${vault.url}/policy/grants/gnt_test` }] }))
  try {
    const result = await pending()
    expect(result.structuredContent.pending).toMatchObject([{ kind: "policy", id: "pol_test", check: { label: "code", value: "CODE42" }, requestedBy: { device: "recorded-machine", session: "recorded-label" } }])
    expect(result.content[1]).toMatchObject({ type: "resource_link", uri: `${vault.url}/w/mock-space/p/pol_test` })
    expect(JSON.stringify(result)).not.toMatch(/evil.example|gnt_test/)
  } finally { vault.overrides.clear() }
})

test("vault_pending carries each ask's group and the top-level groups, and says to review them together", async () => {
  const groupUrl = `${vault.url}/w/mock-space/g/grp_Q2mX9`
  vault.pending = ["apr_g1", "apr_g2"].map((id) => ({ kind: "approval" as const, id, url: `${vault.url}/w/mock-space/a/${id}`, title: "Create", expiresAt: null, requestedBy: { device: "dev_mock1", deviceName: "sam-mac-mini", session: null }, bindingCode: "K7Q2MX" }))
  vault.groups = [{ id: "grp_Q2mX9", url: groupUrl, approvals: ["apr_g1", "apr_g2"], bundle: false }]
  const result = await pending()
  expect(result.structuredContent.groups).toEqual([{ id: "grp_Q2mX9", url: groupUrl, approvals: ["apr_g1", "apr_g2"], bundle: false }])
  expect(result.structuredContent.pending.map((a) => a.group)).toEqual([{ id: "grp_Q2mX9", url: groupUrl, open: 2 }, { id: "grp_Q2mX9", url: groupUrl, open: 2 }])
  expect(result.content[0]?.text).toStartWith(`2 asks from sam-mac-mini: review together at ${groupUrl}`)
})

test("offline, vault_pending marks each recorded ask stale, warns from the unreachable vault and hands none over", async () => {
  const shared = vault
  vault = new MockVault()
  await dir.remove()
  dir = await tempDir()
  try {
    env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url }
    await vault.enrolSoftware(dir.path)
    const slot = vault.slotDir(dir.path)
    const url = askUrlFor(vault.askVault(), "approval", "apr_7Hq2")!.url
    await addLedgerEntry(slot, vault.ledgerScope(), { ask: approvalAsk({ id: "apr_7Hq2", url, summary: "Send an email", bindingCode: "K7Q2MX", expiresAt: new Date(Date.now() + 3_600_000).toISOString(), requestedBy: { device: "test-machine", session: null } }) })
    vault.stop()
    const result = await pending()
    expect(result.structuredContent.pending).toMatchObject([{ id: "apr_7Hq2", stale: true }])
    expect(result.structuredContent.warning).toContain(`the vault for ${slot} could not be asked (network`)
    expect(result.structuredContent.warning).toContain("marked stale")
    expect(result.content.some((c) => c.type === "resource_link")).toBe(false)
    expect(result.content.map((c) => c.text ?? "").join("\n")).not.toContain('vault_wait { "id": "apr_7Hq2" }')
  } finally {
    vault = shared
  }
})

test("an ask the vault did not confirm is stale and never handed over: a workspace that refuses, and one a working vault's answer leaves out", async () => {
  const second = { id: "tn_second00000001", slug: "second-space", name: "Second Space" }
  const inAnHour = new Date(Date.now() + 3_600_000).toISOString()
  const ask = (id: string, workspace: string) => approvalAsk({ id, url: askUrlFor({ ...vault.askVault(), workspaceSlug: workspace }, "approval", id)!.url, summary: "Send an email", bindingCode: "K7Q2MX", expiresAt: inAnHour, requestedBy: { device: "test-machine", session: null } })
  await addLedgerEntry(vault.slotDir(dir.path), vault.ledgerScope(), { ask: ask("apr_live", "mock-space") })
  await addLedgerEntry(vault.slotDir(dir.path), vault.ledgerScope(), { ask: ask("apr_gone", "mock-space") })
  const b = await vault.enrolSoftware(dir.path, { config: { tenant: second.id, workspaceSlug: second.slug, workspaceName: second.name } })
  const secondScope = { vaultUrl: vault.url, workspace: second.id, device: b, workspaceSlug: second.slug }
  await addLedgerEntry(vault.slotDir(dir.path, second.id), secondScope, { ask: ask("apr_revoked", second.slug) })
  const record = vault.devices.get(b)
  if (record) record.revoked = true
  vault.pending = [{ kind: "approval", id: "apr_live", url: `${vault.url}/w/mock-space/a/apr_live`, title: "Send an email", expiresAt: inAnHour, bindingCode: "K7Q2MX" }]
  try {
    const result = await pending()
    expect(result.structuredContent.pending.map((a) => [a.id, a.stale])).toEqual([["apr_live", undefined], ["apr_gone", true], ["apr_revoked", true]])
    expect(result.structuredContent.warning).toContain("marked stale")
    expect(result.content.filter((c) => c.type === "resource_link").map((c) => c.uri)).toEqual([`${vault.url}/w/mock-space/a/apr_live`])
    const text = result.content.map((c) => c.text ?? "").join("\n")
    expect(text).not.toMatch(/apr_gone|apr_revoked/)
    expect(askCardView(result as never)).toMatchObject({ kind: "single", ask: { id: "apr_live" } })
  } finally {
    if (record) record.revoked = false
  }
})

test("a pending enrolment gets a handover only while the vault says it waits; approved, rejected or unreachable, it is stale with none", async () => {
  vault.enrolOutcome = { pendingPolls: 1000, result: "active" }
  const enrolment = (JSON.parse((await runJv(["enrol", "--workspace", "personal", "--json"], env)).stdout) as { enrolment: string }).enrolment
  const links = (result: PendingResult) => result.content.filter((c) => c.type === "resource_link").map((c) => c.uri)
  const waiting = await pending()
  expect(waiting.structuredContent.pending.map((a) => [a.id, a.stale])).toEqual([[enrolment, undefined]])
  expect(links(waiting)).toHaveLength(1)
  expect(askCardView(waiting as never)).toMatchObject({ kind: "single", ask: { id: enrolment } })
  try {
    for (const result of ["active", "rejected"] as const) {
      vault.enrolOutcome = { pendingPolls: 0, result }
      const settled = await pending()
      expect(settled.structuredContent.pending.map((a) => [a.id, a.stale]), result).toEqual([[enrolment, true]])
      expect(links(settled), result).toEqual([])
      expect(askCardView(settled as never), result).toEqual({ kind: "none" })
    }
    vault.enrolOutcome = { pendingPolls: 1000, result: "active" }
    // A proxy in front of an unreachable vault.
    vault.overrides.set(`GET /v1/enrol/${enrolment}`, () => new Response("upstream down", { status: 503 }))
    const unread = await pending()
    expect(unread.structuredContent.pending.map((a) => [a.id, a.stale])).toEqual([[enrolment, true]])
    expect(links(unread)).toEqual([])
  } finally {
    vault.overrides.clear()
    vault.enrolOutcome = { pendingPolls: 2, result: "active" }
  }
})
