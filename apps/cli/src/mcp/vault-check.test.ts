import { afterAll, afterEach, beforeAll, beforeEach, expect, test } from "bun:test"
import { MockVault } from "../testing/mock-vault.ts"
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
})
afterEach(async () => dir.remove())

test("refusal/vault_check never presents a local allow as server authorisation", async () => {
  const before = vault.seen.length
  const result = await runJv(["mcp", "--toolsets", "all"], env, '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_check","arguments":{"item":"openai-personal","method":"GET","url":"https://api.openai.com/v1/models"}}}\n')
  expect(result.code).toBe(0)
  const output = (JSON.parse(result.stdout) as { result: { structuredContent: Record<string, unknown>; content: { text: string }[] } }).result
  expect(output.structuredContent).toMatchObject({ decision: "allow", advisory: true, scope: "base-policy-only" })
  expect(output.content[0]?.text).toContain("Live windows, floors, protection and grants are not included; this cannot predict permission to send")
  expect(output.content[0]?.text).toContain("mehen policy show openai-personal")
  expect(vault.seen.slice(before).map((s) => s.path)).toEqual(["/v1/items/openai-personal"])
})
