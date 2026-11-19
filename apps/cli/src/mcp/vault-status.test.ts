import { afterAll, afterEach, beforeAll, beforeEach, expect, test } from "bun:test"
import { join } from "node:path"
import { readConfig, writeConfig } from "../config.ts"
import { mandateView } from "../testing/mandate-fixtures.ts"
import { MockVault, SCOPE, vaultError } from "../testing/mock-vault.ts"
import { runJv, tempDir } from "../testing/run-mehen.ts"

let vault: MockVault
let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>
let device: string
beforeAll(() => { vault = new MockVault() })
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url, MEHEN_SESSION: "pol-test" }
  device = await vault.enrolSoftware(dir.path)
  vault.overrides.clear()
})
afterEach(async () => dir.remove())

async function status() {
  const result = await runJv(["mcp"], env, '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_status","arguments":{}}}\n')
  expect(result.code).toBe(0)
  return (JSON.parse(result.stdout) as { result: { isError: boolean; structuredContent: Record<string, unknown> } }).result
}
// The one workspace's signed check in StatusAll.
function policyState(result: { structuredContent: Record<string, unknown> }): unknown {
  const [entry] = result.structuredContent.workspaces as { check: { ok: boolean; status: { policyState: unknown } } }[]
  expect(entry?.check.ok).toBe(true)
  return entry?.check.status.policyState
}
function supported() {
  vault.overrides.set("GET /v1/me", () => Response.json({ tenant: "ten_mock", device, name: "test-machine", scope: SCOPE, frozen: false, capabilities: { environmentV2: false, runBaseUrl: false, runFiles: false, sealedEnvImport: false, policyV1: true } }))
}
function state() {
  return { observedAt: new Date().toISOString(), widening: [{ id: "pov_test", kind: "mode", item: "example-key", selector: { device, session: "pol-test" }, policyMode: "relaxed", scope: { host: "api.example.com", methods: ["POST"], path: "/projects/123/**", anchorPath: "/projects/123/issues", basis: "unreviewed" }, expiresAt: new Date(Date.now() + 3600000).toISOString(), parent: null, reviewUrl: `${vault.url}/policy/overrides/pov_test`, stopUrl: `${vault.url}/api/policy/overrides/pov_test/revoke` }] }
}

test("vault_status carries observed current-enrolment policyState and uses the current proof session", async () => {
  supported()
  const active = state()
  vault.overrides.set("GET /v1/policy/state", () => Response.json(active))
  const result = await status()
  expect(result.isError).toBe(false)
  expect(policyState(result)).toEqual(active)
  expect(vault.seen.filter((s) => s.path === "/v1/policy/state").at(-1)).toMatchObject({ claims: { dev: device, sid: "pol-test" } })
})

test("refusal/vault_status missing capabilities and failed refresh stay unavailable, not inactive", async () => {
  const before = vault.seen.filter((s) => s.path === "/v1/policy/state").length
  expect(policyState(await status())).toBeNull()
  expect(vault.seen.filter((s) => s.path === "/v1/policy/state")).toHaveLength(before)
  supported()
  vault.overrides.set("GET /v1/policy/state", () => vaultError("internal", "Unavailable"))
  expect(policyState(await status())).toBeNull()
})

test("refusal/vault_status rejects foreign, cross-id, encoded, queried and credentialled review or Stop links", async () => {
  supported()
  for (const url of ["https://evil.example/policy/overrides/pov_test", `${vault.url}/policy/overrides/pov_other`, `${vault.url}/policy/overrides/pov_%74est`, `${vault.url}/policy/overrides/pov_test?x=1`, `${vault.url}/policy/overrides/pov_test#x`, `${vault.url.replace('://', '://user@')}/policy/overrides/pov_test`]) {
    const active = state()
    active.widening[0]!.reviewUrl = url
    vault.overrides.set("GET /v1/policy/state", () => Response.json(active))
    expect(policyState(await status())).toBeNull()
  }
  const active = state()
  active.widening[0]!.stopUrl = `${vault.url}/api/policy/grants/gnt_other/revoke`
  vault.overrides.set("GET /v1/policy/state", () => Response.json(active))
  expect(policyState(await status())).toBeNull()
})

// The shape of a JSON value: every key, the type of every leaf, the first
// element of every array.
function shapeOf(value: unknown): unknown {
  if (value === null) return "null"
  if (Array.isArray(value)) return value.length ? [shapeOf(value[0])] : []
  if (typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, shapeOf(v)]))
  return typeof value
}

test("vault_status is StatusAll in the shape of the shared fixture, status-all.json, for an active and a pending workspace in one server", async () => {
  const spanning = { ...env, MEHEN_SESSION: "pi-4f2a", MEHEN_WORKSPACES: "mock-space,personal" }
  // The fixture's active entry carries the fingerprint recorded at enrolment.
  const config = await readConfig(vault.slotDir(dir.path))
  await writeConfig(vault.slotDir(dir.path), { ...config!, fingerprint: "ZLSQ 8ZY0 FNHK WLS5" })
  const enrol = await runJv(["enrol", "--workspace", "personal", "--json"], spanning)
  expect(enrol.code).toBe(0)
  const enrolment = (JSON.parse(enrol.stdout) as { enrolment: string }).enrolment
  const result = await runJv(["mcp"], spanning, '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_status","arguments":{}}}\n')
  expect(result.code).toBe(0)
  const all = (JSON.parse(result.stdout) as { result: { isError: boolean; structuredContent: { workspaces: { state: string }[]; cli: object } } }).result
  expect(all.isError).toBe(false)
  expect(all.structuredContent).toMatchObject({ home: dir.path, allowed: ["mock-space", "personal"], selected: vault.slotDir(dir.path), next: null, workspaces: [{ state: "active", device, check: { ok: true } }, { state: "pending", enrolment }] })
  const fixture = JSON.parse(await Bun.file(join(import.meta.dir, "fixtures", "status-all.json")).text()) as { workspaces: { state: string }[]; cli: object }
  expect(shapeOf(all.structuredContent.workspaces)).toEqual(shapeOf(fixture.workspaces))
  expect(Object.keys(all.structuredContent).sort()).toEqual(Object.keys(fixture).sort())
  expect(Object.keys(all.structuredContent.cli).sort()).toEqual(Object.keys(fixture.cli).sort())
  // "Enrolled" is an active entry; there is no enrolled boolean.
  expect(all.structuredContent).not.toHaveProperty("enrolled")
})

test("vault_status carries this machine's live mandate and waiting proposals beside policyState, and leaves both out when the vault will not say", async () => {
  vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [mandateView()], proposals: [] }))
  const [entry] = (await status()).structuredContent.workspaces as { check: { ok: boolean; status: Record<string, unknown> } }[]
  expect(entry?.check.status).toMatchObject({ mandate: { id: "mdt_live", state: "active" }, mandateProposals: 0 })
  vault.overrides.set("GET /v1/mandates", () => vaultError("not_found", "No such route."))
  const [off] = (await status()).structuredContent.workspaces as { check: { ok: boolean; status: Record<string, unknown> } }[]
  expect(off?.check.ok).toBe(true)
  expect(off?.check.status).not.toHaveProperty("mandate")
})
