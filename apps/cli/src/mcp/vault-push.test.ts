import { afterAll, afterEach, beforeAll, beforeEach, expect, test } from "bun:test"
import { ERROR_HEADER } from "@mehen/protocol/api"
import { MOCK_EXPIRES_AT, MockVault, vaultError } from "../testing/mock-vault.ts"
import { runJv, tempDir } from "../testing/run-mehen.ts"

let vault: MockVault
let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>

beforeAll(() => { vault = new MockVault() })
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url }
  vault.overrides.clear()
  await vault.enrolSoftware(dir.path)
})
afterEach(async () => dir.remove())

type ToolResult = { isError: boolean; structuredContent: Record<string, unknown>; content: { type: string; text?: string; uri?: string }[] }
async function push(args: Record<string, unknown>): Promise<ToolResult> {
  const result = await runJv(["mcp", "--toolsets", "all"], env, `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "vault_push", arguments: args } })}\n`)
  expect(result.code).toBe(0)
  return (JSON.parse(result.stdout) as { result: ToolResult }).result
}

const TO = { provider: "github", owner: "acme", repo: "app", store: "actions", environment: null, name: "OPENAI_API_KEY" }

test("vault_push sends the destination as given and hands back approval_required with the ask and vault_wait", async () => {
  const bodies: unknown[] = []
  const link = `${vault.url}/w/mock-space/a/apr_p1`
  vault.overrides.set("POST /v1/push", (_request, seen) => {
    bodies.push(JSON.parse(seen.body))
    return vaultError("approval_required", "This push needs a human's approval.", { approval: "apr_p1", bindingCode: "K7Q2MX", expiresAt: MOCK_EXPIRES_AT, next: { url: link, command: "mehen wait apr_p1", say: "Send this link to Alex." } })
  })
  const result = await push({ item: "openai-prod", field: "key", to: TO, with: "github-pat-ci", reason: "evals" })
  expect(bodies).toEqual([{ item: "openai-prod", field: "key", to: TO, with: "github-pat-ci", reason: "evals" }])
  expect(result.isError).toBe(true)
  expect(result.structuredContent).toMatchObject({ error: "approval_required", approval: "apr_p1", ask: { kind: "approval", id: "apr_p1", url: link, check: { label: "code", value: "K7Q2MX" } }, next: { say: "Send this link to Alex." } })
  expect(result.content[0]?.text).toContain('vault_wait { "id": "apr_p1" }')
  expect(result.content.some((block) => block.type === "resource_link" && block.uri === link)).toBe(true)
})

test("vault_push returns PushResult field by field for the same push done in the last ten minutes", async () => {
  const done = { push: "psh_1", item: "openai-prod", field: "key", version: 3, destination: "github:acme/app/OPENAI_API_KEY", via: "github-pat-ci", outcome: "replaced", at: "2026-11-06T09:15:00.000Z" }
  vault.overrides.set("POST /v1/push", () => Response.json({ ...done, internal: "never shown" }))
  const result = await push({ item: "openai-prod", to: TO })
  expect(result.isError).toBe(false)
  expect(result.structuredContent).toEqual(done)
})

test("vault_push refusals: provider_refused keeps providerStatus; a destination the schema refuses never reaches the vault", async () => {
  vault.overrides.set("POST /v1/push", () => Response.json({ error: "provider_refused", message: "GitHub says acme/app does not exist, or github-pat-ci cannot see it.", providerStatus: 404 }, { status: 502, headers: { [ERROR_HEADER]: "1" } }))
  const refused = await push({ item: "openai-prod", to: TO })
  expect(refused.isError).toBe(true)
  expect(refused.structuredContent).toMatchObject({ error: "provider_refused", providerStatus: 404 })
  const before = vault.seen.length
  for (const to of [{ ...TO, name: "GITHUB_TOKEN" }, { ...TO, provider: "gitlab" }, "github:acme/app/OPENAI_API_KEY"]) {
    const result = await push({ item: "openai-prod", to })
    expect(result.isError).toBe(true)
    expect(result.structuredContent).toMatchObject({ error: "usage" })
  }
  expect(vault.seen.length).toBe(before)
})
