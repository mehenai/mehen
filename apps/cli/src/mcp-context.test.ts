// One MCP server spanning the allowed set:
// setup registers the one plain `mehen` entry; a pinned server
// refuses a mismatch before reading stdin; a call that needs one workspace
// and names none under several is context_ambiguous; a cwd outside the
// ceiling or disagreeing with the pin is refused before any network call or
// session; each slot's identity is latched and a replaced slot is refused
// for the life of the server while the others serve; and session cache
// keys carry the full identity.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { mkdir, readFile, rename, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { type Config, defaultConfigDir, readConfig } from "./config.ts"
import { pendingSlotPath } from "./home.ts"
import { bindMcpContext, mcpDeps, sessionKey } from "./mcp.ts"
import { latchState, resolveSlot, restoreLatchState, slotKey, spanSlots } from "./mcp/binding.ts"
import type { McpServer, ToolOutput } from "./mcp/shared.ts"
import { vaultEnv } from "./mcp/vault-env.ts"
import { vaultList } from "./mcp/vault-list.ts"
import { vaultStatus } from "./mcp/vault-status.ts"
import { manifestWorkspace } from "./run/manifest.ts"
import { agents, serverEntry } from "./setup/agents.ts"
import { jsonEntry } from "./setup/formats.ts"
import { setup } from "./setup/index.ts"
import { MOCK_TENANT, MOCK_WORKSPACE, MockVault, deviceFor, vaultError } from "./testing/mock-vault.ts"
import { MAIN, runJv, tempDir } from "./testing/run-mehen.ts"

let vault: MockVault
let home: { path: string; remove(): Promise<void> }
let env: Record<string, string>

const SECOND = { id: "tn_second00000001", slug: "second-space", name: "Second Space" }

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  home = await tempDir()
  env = { HOME: home.path, MEHEN_CONFIG_DIR: "" }
  vault.overrides.clear()
  vault.workspace = { ...MOCK_WORKSPACE }
  vault.lastDevice = null
})
afterEach(() => home.remove())

const base = () => defaultConfigDir(env)
// The two slots under the one root: the mock workspace and a second one.
const firstSlot = () => vault.slotDir(base())
const second = () => vault.slotDir(base(), SECOND.id)

// Two slots under one root: the mock's workspace and a second workspace,
// both enrolled with the same mock vault.
async function twoContexts(): Promise<{ first: string; secondDevice: string }> {
  const first = await vault.enrolSoftware(base())
  const secondDevice = await vault.enrolSoftware(base(), { config: { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name } })
  return { first, secondDevice }
}

const call = { signal: new AbortController().signal, progressToken: null }

// StatusAll's entries, and one slot's signed check.
type Entry = { state: string; slot?: string; origin?: string; entry?: string; device?: string; workspace?: { id: string; slug: string | null }; check?: { ok: boolean; error?: string; status?: Record<string, unknown> } }
const entries = (out: ToolOutput) => (out.structured as { workspaces: Entry[] }).workspaces
const checkOf = (out: ToolOutput, dir: string) => entries(out).find((e) => e.slot === dir)?.check
// vault_doctor's DoctorReport: one slot's enrolled check.
type Check = { check: string; status: string; detail: string; error?: string }
type Report = { ok: boolean; machine: Check[]; origins: { origin: string; checks: Check[] }[]; workspaces: { slot: string; state: string; checks: Check[] }[] }
const reportOf = (out: ToolOutput) => out.structured as Report
const enrolledAt = (out: ToolOutput, dir: string) => reportOf(out).workspaces.find((w) => w.slot === dir)?.checks.find((c) => c.check === "enrolled")
const bindingOf = (server: McpServer, dir: string) => server.slots.get(slotKey(server, dir))

// A pending enrolment for mock-space in its pending slot (a key and the
// legacy ledger entry today's enrol writes): a server started with nothing
// else binds this slot at startup, and the enrolment that lands lands here.
async function pendingAt(root: string, id = "enr_pendingA0000"): Promise<string> {
  const { createDeviceKey } = await import("./device-key.ts")
  const { addLedgerEntry } = await import("./ledger.ts")
  const { enrolAsk, askUrl } = await import("./ask.ts")
  const dir = pendingSlotPath(root, vault.url, "mock-space")
  const { jwk } = await createDeviceKey(dir, "software", {}, { vault: vault.url, tenant: null })
  vault.enrolments.set(id, { id, jwk, name: "a-mac", backend: "software", polls: 0, workspace: "mock-space", owner: { kind: "self" } })
  const link = askUrl(`${vault.url}/w/mock-space/e/ABCD2345`, { vaultUrl: vault.url, workspaceSlug: "mock-space" })!
  await addLedgerEntry(dir, { vaultUrl: vault.url, workspace: null, device: null }, { ask: enrolAsk({ id, url: link.url, name: "a-mac", backend: "software", fingerprint: "ZLSQ 8ZY0 FNHK WLS5", expiresAt: new Date(Date.now() + 600_000).toISOString(), requestedBy: { device: "d", session: null } }), enrol: { code: "ABCD2345", name: "a-mac", backend: "software", jwk, workspace: "mock-space", team: null } })
  return dir
}

// Another enrolment (B) landing in an existing slot directory, replacing
// what it holds: its config, key and scope, registered with the mock as
// enrolSoftware registers one.
async function landIn(dir: string, config: Partial<Config>): Promise<string> {
  const scratch = await tempDir()
  try {
    const device = await vault.enrolSoftware(scratch.path, { config })
    const from = vault.slotDir(scratch.path, config.tenant ?? MOCK_TENANT)
    await mkdir(dir, { recursive: true, mode: 0o700 })
    for (const file of ["config.json", "device-key.json", "device-key.scope.json"]) await rename(join(from, file), join(dir, file))
    return device
  } finally {
    await scratch.remove()
  }
}

describe("setup registrations (RS2-13, call 5)", () => {
  const binary = "/opt/mehen/bin/mehen"
  const agent = () => agents(home.path, "darwin").find((a) => a.name === "claude-code")!
  const codex = () => agents(home.path, "darwin").find((a) => a.name === "codex")!
  const run = (extra: Partial<Parameters<typeof setup>[0]> = {}) => setup({ home: home.path, binary, env: { PATH: "" }, names: ["claude-code", "codex"], platform: "darwin", ...extra })

  test("no-flags setup writes exactly today's mehen entry, byte for byte, and still works after a rename", async () => {
    await run()
    const text = await readFile(agent().file, "utf8")
    expect(text).toBe(`{\n  "mcpServers": {"mehen":{"type":"stdio","command":"/opt/mehen/bin/mehen","args":["mcp"]}}}\n`)
    expect(await readFile(codex().file, "utf8")).toBe(`[mcp_servers.mehen]\ncommand = "/opt/mehen/bin/mehen"\nargs = ["mcp"]\ntool_timeout_sec = 660\n`)
    expect(jsonEntry(text, "mcpServers")).toEqual(serverEntry(agent(), binary))
    // The plain server resolves through the default enrolment's stored id,
    // never a slug: a rename changes nothing it reads.
    await vault.enrolSoftware(base())
    vault.workspace = { id: MOCK_TENANT, slug: "renamed", name: "Renamed" }
    const server = await bindMcpContext(env, home.path)
    const deps = mcpDeps(env, server, () => undefined)
    // A single-slot server needs no workspace argument.
    const status = await vaultStatus.call({}, deps, call)
    expect(entries(status)).toMatchObject([{ state: "active", workspace: { id: MOCK_TENANT }, check: { ok: true, status: { tenant: MOCK_TENANT, workspace: { id: MOCK_TENANT, slug: "renamed", name: "Renamed" } } } }])
  })
})

describe("one server spanning the allowed set", () => {
  test("an explicit --workspace whose id is not exactly one local context's stored tenant exits 2 before reading stdin and serves nothing", async () => {
    await twoContexts()
    const before = vault.seen.length
    for (const selector of ["tn_unknown0000001", "nowhere"]) {
      const result = await runJv(["mcp", "--workspace", selector], env, '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
      expect(result.code).toBe(EXIT.usage)
      expect(result.stdout).toBe("")
      expect(result.stderr).toContain(`No enrolment on this machine is in workspace ${selector}.`)
    }
    // An explicit selection that disagrees with the id asked for (MEHEN_CONFIG_DIR
    // is only the root now, so the disagreeing selection is MEHEN_WORKSPACE).
    const mismatch = await runJv(["mcp", "--workspace", SECOND.id], { ...env, MEHEN_CONFIG_DIR: base(), MEHEN_WORKSPACE: "mock-space" }, '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
    expect(mismatch.code).toBe(EXIT.usage)
    expect(mismatch.stdout).toBe("")
    expect(mismatch.stderr).toContain(`--workspace ${SECOND.id} disagrees with MEHEN_WORKSPACE=mock-space.`)
    expect(vault.seen.length).toBe(before)
    // The matching id serves, pinned to that workspace: status lists it alone.
    const ok = await runJv(["mcp", "--workspace", SECOND.id], env, '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_status","arguments":{}}}\n')
    expect(ok.code).toBe(0)
    const reply = JSON.parse(ok.stdout) as { result: { structuredContent: { workspaces: Entry[]; selected: string } } }
    expect(reply.result.structuredContent.selected).toBe(second())
    expect(reply.result.structuredContent.workspaces).toMatchObject([{ state: "active", slot: second(), check: { ok: true, status: { tenant: SECOND.id, slot: second() } } }])
  })

  test("vault_env's own cwd decides: a checkout disagreeing with the pin is workspace_mismatch before any network call or session; outside the ceiling is workspace_not_allowed", async () => {
    await twoContexts()
    const repo = await tempDir()
    try {
      await writeFile(join(repo.path, "mehen.toml"), `project = "prj_1"\nworkspace = "${SECOND.id}"\n`)
      const pinned = { ...env, MEHEN_WORKSPACE: "mock-space" }
      const server = await bindMcpContext(pinned, home.path)
      const deps = mcpDeps(pinned, server, () => undefined)
      const before = vault.seen.length
      let thrown: unknown
      try {
        await vaultEnv.call({ cwd: repo.path }, deps, call)
      } catch (error) {
        thrown = error
      }
      expect(thrown).toMatchObject({ code: "workspace_mismatch" })
      expect(String((thrown as { next: { say: string } }).next.say)).toContain("Leave workspace out of the call")
      // Through the server: the refusal is a tool error and nothing was sent.
      const result = await runJv(["mcp", "--workspace", "mock-space"], env, JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "vault_env", arguments: { cwd: repo.path } } }) + "\n")
      expect(result.code).toBe(0)
      const reply = JSON.parse(result.stdout) as { result: { isError: boolean; structuredContent: { error: string } } }
      expect(reply.result.isError).toBe(true)
      expect(reply.result.structuredContent.error).toBe("workspace_mismatch")
      // An unpinned server resolves the checkout's own workspace; a workspace argument that disagrees refuses.
      const spanning = await bindMcpContext(env, home.path)
      expect((await resolveSlot(spanning, null, { manifest: manifestWorkspace(repo.path), strict: true })).config.tenant).toBe(SECOND.id)
      await expect(resolveSlot(spanning, "mock-space", { manifest: manifestWorkspace(repo.path), strict: true })).rejects.toMatchObject({ code: "workspace_mismatch" })
      // A ceiling without that workspace: the checkout cannot widen it.
      const narrowed = { ...env, MEHEN_WORKSPACES: "mock-space" }
      const ceilinged = mcpDeps(narrowed, await bindMcpContext(narrowed, home.path), () => undefined)
      await expect(vaultEnv.call({ cwd: repo.path }, ceilinged, call)).rejects.toMatchObject({ code: "workspace_not_allowed" })
      expect(vault.seen.length).toBe(before)
      // The pinned workspace's own checkout passes the check.
      await writeFile(join(repo.path, "mehen.toml"), `project = "prj_1"\nworkspace = "${MOCK_TENANT}"\nvault = "${vault.url}"\n`)
      expect((await resolveSlot(server, null, { manifest: manifestWorkspace(repo.path), strict: true })).config.tenant).toBe(MOCK_TENANT)
      // An unbound manifest is refused under two workspaces, even with the pin, and passes under one.
      await writeFile(join(repo.path, "mehen.toml"), 'project = "prj_1"\n')
      await expect(resolveSlot(server, null, { manifest: manifestWorkspace(repo.path), strict: true })).rejects.toMatchObject({ code: "workspace_unbound" })
      await expect(vaultEnv.call({ cwd: repo.path }, deps, call)).rejects.toMatchObject({ code: "workspace_unbound" })
      // A malformed manifest is refused too, never treated as absent.
      await writeFile(join(repo.path, "mehen.toml"), `project = "prj_1"\nworkspace = "${SECOND.id}"\nvault = "${vault.url}/forbidden-path"\n`)
      expect(() => manifestWorkspace(repo.path)).toThrow(expect.objectContaining({ code: "workspace_unbound" }))
      await expect(vaultEnv.call({ cwd: repo.path }, deps, call)).rejects.toMatchObject({ code: "workspace_unbound" })
      // Same id at another origin is foreign too.
      await writeFile(join(repo.path, "mehen.toml"), `project = "prj_1"\nworkspace = "${MOCK_TENANT}"\nvault = "https://other.example"\n`)
      await expect(resolveSlot(server, null, { manifest: manifestWorkspace(repo.path), strict: true })).rejects.toMatchObject({ code: "workspace_mismatch" })
      await expect(resolveSlot(spanning, null, { manifest: manifestWorkspace(repo.path), strict: true })).rejects.toMatchObject({ code: "workspace_unknown" })
      expect(vault.seen.length).toBe(before)
    } finally {
      await repo.remove()
    }
  })

  test("a server started in a checkout uses that checkout's workspace by default; one started elsewhere spans both, and a call that needs one names it or is context_ambiguous", async () => {
    await twoContexts()
    const repo = await tempDir()
    const lines = (...calls: [string, Record<string, unknown>][]) => calls.map(([name, args], i) => JSON.stringify({ jsonrpc: "2.0", id: i + 1, method: "tools/call", params: { name, arguments: args } })).join("\n") + "\n"
    type Reply = { id: number; result: { isError: boolean; structuredContent: Record<string, unknown> } }
    const replies = (stdout: string) => stdout.trim().split("\n").map((l) => JSON.parse(l) as Reply).sort((a, b) => a.id - b.id)
    try {
      await writeFile(join(repo.path, "mehen.toml"), `project = "prj_1"\nworkspace = "${SECOND.id}"\n`)
      const before = vault.seen.length
      const inRepo = await runJv(["mcp", "--toolsets", "inspect"], env, lines(["vault_show", { item: "openai-personal" }]), repo.path)
      expect(inRepo.code).toBe(0)
      expect(replies(inRepo.stdout)[0]?.result.isError).toBe(false)
      expect(vault.seen.slice(before).map((c) => [c.path, c.claims.ten])).toEqual([["/v1/items/openai-personal", SECOND.id]])
      // There is no default: elsewhere a call that needs one workspace names it.
      const seen = vault.seen.length
      const refusals = await runJv(["mcp", "--toolsets", "inspect"], env, lines(["vault_show", { item: "openai-personal" }], ["vault_request", { kind: "api-key", name: "x", reason: "r", provider: "openai" }]), home.path)
      expect(refusals.code).toBe(0)
      for (const refused of replies(refusals.stdout)) {
        expect(refused.result.isError).toBe(true)
        expect(refused.result.structuredContent).toMatchObject({ error: "context_ambiguous" })
        const say = String((refused.result.structuredContent as { next: { say: string } }).next.say)
        expect(say).toContain('workspace: "mock-space"')
        expect(say).toContain(`workspace: "${SECOND.slug}"`)
      }
      expect(vault.seen.length).toBe(seen)
      const named = await runJv(["mcp", "--toolsets", "inspect"], env, lines(["vault_status", {}], ["vault_show", { item: "openai-personal", workspace: "mock-space" }]), home.path)
      const [status, show] = replies(named.stdout)
      expect((status?.result.structuredContent as { workspaces: Entry[] }).workspaces.map((e) => e.slot).sort()).toEqual([firstSlot(), second()].sort())
      expect(status?.result.structuredContent.selected).toBeNull()
      expect(show?.result.isError).toBe(false)
      expect(vault.seen.filter((c) => c.path === "/v1/items/openai-personal").at(-1)?.claims.ten).toBe(MOCK_TENANT)
    } finally {
      await repo.remove()
    }
  })

  // A tool error's ask carries the bound server's own call
  // identity; two servers on A and B never borrow each other's.
  test("concurrent servers on A and B attach their own provenance to a refusal's ask, never the other's", async () => {
    const { first, secondDevice } = await twoContexts()
    vault.overrides.set("POST /v1/relay", (_request, seen) => vaultError("approval_required", "Needs approval.", { next: { url: `${vault.url}/w/${seen.claims.ten === SECOND.id ? SECOND.slug : "mock-space"}/a/apr_1`, say: "x" }, approval: "apr_1", bindingCode: "K7Q2" }))
    const call = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "vault_fetch", arguments: { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x" } } }) + "\n"
    const [a, b] = await Promise.all([runJv(["mcp", "--workspace", "mock-space"], env, call), runJv(["mcp", "--workspace", SECOND.id], env, call)])
    const askOf = (result: { stdout: string }) => (JSON.parse(result.stdout) as { result: { structuredContent: { ask: { url: string; context: unknown } } } }).result.structuredContent.ask
    expect(askOf(a)).toMatchObject({ url: `${vault.url}/w/mock-space/a/apr_1`, context: { origin: vault.url, workspace: MOCK_WORKSPACE, device: first } })
    expect(askOf(b)).toMatchObject({ url: `${vault.url}/w/${SECOND.slug}/a/apr_1`, context: { origin: vault.url, workspace: SECOND, device: secondDevice } })
  })

  test("session cache keys carry origin, workspace, device and the real directory: identical ids at other origins never collide", () => {
    const config = { vault: "https://a.example", tenant: MOCK_TENANT, device: "dev_a" }
    const key = sessionKey("/ctx", config)
    expect(sessionKey("/ctx", { ...config, vault: "https://b.example" })).not.toBe(key)
    expect(sessionKey("/ctx", { ...config, tenant: "tn_other000000001" })).not.toBe(key)
    expect(sessionKey("/ctx", { ...config, device: "dev_b" })).not.toBe(key)
    expect(sessionKey("/other", config)).not.toBe(key)
    expect(sessionKey("/ctx", { ...config })).toBe(key)
    expect(JSON.parse(key)).toEqual(["/ctx", "https://a.example", MOCK_TENANT, "dev_a"])
  })

  test("the enrolment landing in the bound directory mid-run takes effect; a different one later is refused", async () => {
    // A server started beside a pending enrolment binds its slot.
    const slot = await pendingAt(base())
    const server = await bindMcpContext(env, home.path)
    expect(server.slots.size).toBe(0)
    const deps = mcpDeps(env, server, () => undefined)
    expect(entries(await vaultStatus.call({}, deps, call))).toMatchObject([{ state: "pending", slot }])
    await landIn(slot, {})
    expect(entries(await vaultStatus.call({}, deps, call))).toMatchObject([{ state: "active", slot, check: { ok: true, status: { tenant: MOCK_TENANT } } }])
    // A server that read an enrolment at start latched it then, and refuses a replacement before its first use.
    const pinned = mcpDeps(env, await bindMcpContext(env, home.path), () => undefined)
    await landIn(slot, { tenant: SECOND.id })
    await expect(pinned.session()).rejects.toMatchObject({ code: "workspace_mismatch" })
  })

  // The identity a server serves is latched, from its binding or
  // from the first enrolment to land, and rechecked on disk before any
  // cached session is handed back.
  test("a server that started empty latches the first enrolment: a replacement is refused, never served, cached or written over", async () => {
    const slot = await pendingAt(base())
    const bound = await bindMcpContext(env, home.path)
    const deps = mcpDeps(env, bound, () => undefined)
    const a = await landIn(slot, {})
    const first = await deps.session()
    expect(bindingOf(bound, slot)).toEqual({ latched: { vault: vault.url, tenant: MOCK_TENANT, device: a } })
    expect(first.config.device).toBe(a)
    const requests = vault.seen.length
    // B replaces A in the same directory, with its own key.
    const b = await landIn(slot, { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name })
    await expect(deps.session()).rejects.toMatchObject({ code: "workspace_mismatch" })
    await expect(deps.session()).rejects.toMatchObject({ code: "workspace_mismatch" })
    // Status reports the refusal as the slot's check; nothing is signed for it.
    expect(checkOf(await vaultStatus.call({}, deps, call), slot)).toMatchObject({ ok: false, error: "workspace_mismatch" })
    expect(bindingOf(bound, slot)).toMatchObject({ refused: { reason: expect.stringContaining("changed") } })
    expect(vault.seen.length).toBe(requests)
    // Nothing was written over B's config, and A's cached signer never signed again.
    expect(await readConfig(slot)).toMatchObject({ tenant: SECOND.id, device: b, workspaceSlug: SECOND.slug })
    expect(vault.seen.filter((c) => c.claims.dev === a).length).toBe(vault.seen.slice(0, requests).filter((c) => c.claims.dev === a).length)
  })

  // Every path that can sign goes through the one latch: doctor
  // first latches A; a replacement is refused by doctor, status and fetch
  // alike, with no B signature, and a later normal session cannot latch B.
  test("doctor first latches the enrolment; after a replacement doctor, status and fetch all refuse without a B signature and a session cannot latch B", async () => {
    const slot = await pendingAt(base())
    const bound = await bindMcpContext(env, home.path)
    const deps = mcpDeps(env, bound, () => undefined)
    const { vaultDoctor } = await import("./mcp/vault-doctor.ts")
    const { vaultFetch } = await import("./mcp/vault-fetch.ts")
    // Pre-enrolment: unsigned diagnostics still work and nothing is latched.
    const empty = reportOf(await vaultDoctor.call({}, deps, call))
    expect(empty.ok).toBe(false)
    expect(empty.origins.flatMap((o) => o.checks).find((c) => c.check === "reachable")?.status).toBe("ok")
    expect(bound.slots.size).toBe(0)
    const a = await landIn(slot, {})
    const first = reportOf(await vaultDoctor.call({}, deps, call))
    expect(first.ok).toBe(true)
    expect(bindingOf(bound, slot)).toEqual({ latched: { vault: vault.url, tenant: MOCK_TENANT, device: a } })
    const b = await landIn(slot, { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name })
    const requests = vault.seen.length
    const again = await vaultDoctor.call({}, deps, call)
    expect(reportOf(again).ok).toBe(false)
    expect(enrolledAt(again, slot)).toMatchObject({ status: "fail", error: "workspace_mismatch" })
    // Nothing was probed or signed for the refused slot.
    expect(reportOf(again).origins).toEqual([])
    expect(checkOf(await vaultStatus.call({}, deps, call), slot)).toMatchObject({ ok: false, error: "workspace_mismatch" })
    await expect(vaultFetch.call({ item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/models" }, deps, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
    await expect(deps.session()).rejects.toMatchObject({ code: "workspace_mismatch" })
    expect(vault.seen.length).toBe(requests)
    expect(vault.seen.some((c) => c.claims.dev === b)).toBe(false)
    // The slot is refused for the life of this server; A is never served again either.
    expect(bindingOf(bound, slot)).toMatchObject({ refused: { reason: expect.stringContaining(b) } })
    // A's config removed while its key remains: refused too, never revived from the startup snapshot.
    await landIn(slot, {})
    const fresh = mcpDeps(env, await bindMcpContext(env, home.path), () => undefined)
    await deps.session().catch(() => undefined)
    expect((await vaultDoctor.call({}, fresh, call)).structured).toMatchObject({ ok: true })
    const { rm } = await import("node:fs/promises")
    await rm(join(slot, "config.json"))
    const seen = vault.seen.length
    expect((await vaultDoctor.call({}, fresh, call)).structured).toMatchObject({ ok: false })
    expect(enrolledAt(await vaultDoctor.call({}, fresh, call), slot)?.error).toBe("workspace_mismatch")
    await expect(fresh.session()).rejects.toMatchObject({ code: "workspace_mismatch" })
    expect(vault.seen.length).toBe(seen)
  })

  test("an enrolment that lands on disk while a pending enrolment waits is never overwritten: vault_wait refuses with no poll, signature or write", async () => {
    const { createDeviceKey } = await import("./device-key.ts")
    const { addLedgerEntry, readLedger } = await import("./ledger.ts")
    const { enrolAsk, askUrl } = await import("./ask.ts")
    const { vaultWait } = await import("./mcp/vault-wait.ts")
    const pendingDir = pendingSlotPath(base(), vault.url, "mock-space")
    // A pending enrolment A, and a server started beside it, bound to its slot.
    const { jwk } = await createDeviceKey(pendingDir, "software", {}, { vault: vault.url, tenant: null })
    const id = "enr_pendingA0001"
    vault.enrolments.set(id, { id, jwk, name: "a-mac", backend: "software", polls: 0, workspace: "mock-space", owner: { kind: "self" } })
    const link = askUrl(`${vault.url}/w/mock-space/e/ABCD2345`, { vaultUrl: vault.url, workspaceSlug: "mock-space" })!
    await addLedgerEntry(pendingDir, { vaultUrl: vault.url, workspace: null, device: null }, { ask: enrolAsk({ id, url: link.url, name: "a-mac", backend: "software", fingerprint: "ZLSQ 8ZY0 FNHK WLS5", expiresAt: new Date(Date.now() + 600_000).toISOString(), requestedBy: { device: "d", session: null } }), enrol: { code: "ABCD2345", name: "a-mac", backend: "software", jwk, workspace: "mock-space", team: null } })
    const bound = await bindMcpContext(env, home.path)
    expect(bound.slots.size).toBe(0)
    const deps = mcpDeps(env, bound, () => undefined)
    // B lands in the same directory from another process while the server's snapshot still says empty.
    const b = await landIn(pendingDir, { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name })
    const before = vault.seen.length
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    await expect(vaultWait.call({ id, timeoutSeconds: 1 }, deps, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
    expect(vault.seen.length).toBe(before)
    expect(vault.enrolments.get(id)?.polls).toBe(0)
    expect(await readConfig(pendingDir)).toMatchObject({ tenant: SECOND.id, device: b })
    // Nothing was latched by the refused wait: A was never served, B never signed.
    expect(bound.slots.size).toBe(0)
    // The ledger entry for A is still there (nothing settled).
    expect((await readLedger(pendingDir, { vaultUrl: vault.url, workspace: null, device: null })).map((e) => e.ask.id)).toEqual([id])
    // Normal completion into an actually empty directory still works, and
    // vault_wait itself latches the identity it activated: no
    // session or status call stands between completion and the latch.
    const emptyDir = await tempDir()
    const emptySlot = pendingSlotPath(emptyDir.path, vault.url, "mock-space")
    // The finish step renames the pending slot to the workspace's active slot,
    // and the server's binding follows the slot it committed.
    const emptyActive = vault.slotDir(emptyDir.path)
    try {
      const otherEnv = { ...env, MEHEN_CONFIG_DIR: emptyDir.path, MEHEN_VAULT_URL: vault.url }
      const { jwk: jwk2 } = await createDeviceKey(emptySlot, "software", {}, { vault: vault.url, tenant: null })
      const id2 = "enr_pendingA0002"
      vault.enrolments.set(id2, { id: id2, jwk: jwk2, name: "a-mac", backend: "software", polls: 0, workspace: "mock-space", owner: { kind: "self" } })
      await addLedgerEntry(emptySlot, { vaultUrl: vault.url, workspace: null, device: null }, { ask: enrolAsk({ id: id2, url: link.url, name: "a-mac", backend: "software", fingerprint: "ZLSQ 8ZY0 FNHK WLS5", expiresAt: new Date(Date.now() + 600_000).toISOString(), requestedBy: { device: "d", session: null } }), enrol: { code: "ABCD2345", name: "a-mac", backend: "software", jwk: jwk2, workspace: "mock-space", team: null } })
      const otherBound = await bindMcpContext(otherEnv, home.path)
      const other = mcpDeps(otherEnv, otherBound, () => undefined)
      const done = await vaultWait.call({ id: id2, timeoutSeconds: 5 }, other, call)
      expect(done.structured).toMatchObject({ status: "active", tenant: MOCK_TENANT, device: deviceFor(id2) })
      expect(await readConfig(emptyActive)).toMatchObject({ tenant: MOCK_TENANT, workspaceSlug: "mock-space" })
      expect(await readConfig(emptySlot)).toBeNull()
      expect(bindingOf(otherBound, emptyActive)).toEqual({ latched: { vault: vault.url, tenant: MOCK_TENANT, device: deviceFor(id2) } })
      // B replaces A before any other tool runs: doctor, status and fetch refuse, and an enrolment wait signs nothing, without a B signature or write.
      const { vaultDoctor } = await import("./mcp/vault-doctor.ts")
      const { vaultFetch } = await import("./mcp/vault-fetch.ts")
      const bDevice = await landIn(emptyActive, { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name })
      const requests = vault.seen.length
      const report = await vaultDoctor.call({}, other, call)
      expect(reportOf(report).ok).toBe(false)
      expect(enrolledAt(report, emptyActive)?.error).toBe("workspace_mismatch")
      expect(checkOf(await vaultStatus.call({}, other, call), emptyActive)).toMatchObject({ ok: false, error: "workspace_mismatch" })
      await expect(vaultFetch.call({ item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/models" }, other, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
      // An enrolment no slot records is not found; the spanning server has no one directory to refuse it in.
      await expect(vaultWait.call({ id: "enr_pendingA0003", timeoutSeconds: 1 }, other, call)).rejects.toMatchObject({ code: "not_found" })
      expect(vault.seen.length).toBe(requests)
      expect(vault.seen.some((c) => c.claims.dev === bDevice)).toBe(false)
      expect(bindingOf(otherBound, emptyActive)).toMatchObject({ refused: { reason: expect.stringContaining(bDevice) } })
      expect(await readConfig(emptyActive)).toMatchObject({ device: bDevice })
    } finally {
      await emptyDir.remove()
    }
  })

  // The barrier case: B lands between A's activation commit and the
  // server's completion validation. A's success is not reported, B is not
  // latched as A's result, and the server serves neither afterwards.
  test("an enrolment that lands between activation commit and completion validation makes vault_wait refuse: no A success, B never latched, nothing served", async () => {
    const { createDeviceKey } = await import("./device-key.ts")
    const { addLedgerEntry } = await import("./ledger.ts")
    const { enrolAsk, askUrl } = await import("./ask.ts")
    const { vaultWait } = await import("./mcp/vault-wait.ts")
    const { vaultDoctor } = await import("./mcp/vault-doctor.ts")
    const emptyDir = await tempDir()
    const emptySlot = pendingSlotPath(emptyDir.path, vault.url, "mock-space")
    // The finish step renames the pending slot to the workspace's active slot,
    // and the server's binding follows the slot it committed.
    const emptyActive = vault.slotDir(emptyDir.path)
    try {
      const otherEnv = { ...env, MEHEN_CONFIG_DIR: emptyDir.path, MEHEN_VAULT_URL: vault.url }
      const { jwk } = await createDeviceKey(emptySlot, "software", {}, { vault: vault.url, tenant: null })
      const id = "enr_barrierA0001"
      vault.enrolments.set(id, { id, jwk, name: "a-mac", backend: "software", polls: 0, workspace: "mock-space", owner: { kind: "self" } })
      const link = askUrl(`${vault.url}/w/mock-space/e/ABCD2345`, { vaultUrl: vault.url, workspaceSlug: "mock-space" })!
      await addLedgerEntry(emptySlot, { vaultUrl: vault.url, workspace: null, device: null }, { ask: enrolAsk({ id, url: link.url, name: "a-mac", backend: "software", fingerprint: "ZLSQ 8ZY0 FNHK WLS5", expiresAt: new Date(Date.now() + 600_000).toISOString(), requestedBy: { device: "d", session: null } }), enrol: { code: "ABCD2345", name: "a-mac", backend: "software", jwk, workspace: "mock-space", team: null } })
      const bound = await bindMcpContext(otherEnv, home.path)
      let bDevice = ""
      const deps = { ...mcpDeps(otherEnv, bound, () => undefined), barriers: { afterActivation: async () => { bDevice = await landIn(emptyActive, { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name }) } } }
      await expect(vaultWait.call({ id, timeoutSeconds: 5 }, deps, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
      expect(bDevice).not.toBe("")
      // The slot is refused: A was latched as the identity this server
      // activated, B landed after it and is never served, nor is A.
      expect(bindingOf(bound, emptyActive)).toMatchObject({ refused: { reason: expect.stringContaining(`another enrolment (${bDevice})`) } })
      const requests = vault.seen.length
      const report = (await vaultDoctor.call({}, deps, call)).structured as { ok: boolean }
      expect(report.ok).toBe(false)
      expect(checkOf(await vaultStatus.call({}, deps, call), emptyActive)).toMatchObject({ ok: false, error: "workspace_mismatch" })
      await expect(deps.session()).rejects.toMatchObject({ code: "workspace_mismatch" })
      expect(vault.seen.length).toBe(requests)
      expect(vault.seen.some((c) => c.claims.dev === bDevice)).toBe(false)
      expect(await readConfig(emptyActive)).toMatchObject({ device: bDevice })
    } finally {
      await emptyDir.remove()
    }
  })

  // The admission a server resolved at startup is what it serves.
  // An admitted pending slot vanishing and a slot of the same slug at
  // another origin appearing changes nothing without a restart.
  test("an unlatched server never follows its admitted pending slot to an enrolment at another origin", async () => {
    const slot = await pendingAt(base())
    const narrowed = { ...env, MEHEN_WORKSPACES: "mock-space" }
    const bound = await bindMcpContext(narrowed, home.path)
    expect(bound.slots.size).toBe(0)
    // The entry resolved at start to the pending slot's origin.
    expect(latchState(bound).allowed).toEqual([{ entry: "mock-space", origin: vault.url, workspace: null }])
    const deps = mcpDeps(narrowed, bound, () => undefined)
    const { rm } = await import("node:fs/promises")
    await rm(slot, { recursive: true })
    const elsewhere = "https://different.example"
    const { writeConfig } = await import("./config.ts")
    await writeConfig(vault.slotDir(base(), MOCK_TENANT, elsewhere), { vault: elsewhere, tenant: MOCK_TENANT, device: "dev_elsewhere0001", backend: "software", workspaceSlug: "mock-space", workspaceName: "Elsewhere" })
    const before = vault.seen.length
    // The slot at the other origin is not admitted: status lists the entry as not enrolled, nothing else.
    expect(entries(await vaultStatus.call({}, deps, call))).toEqual([expect.objectContaining({ state: "absent", entry: "mock-space" })])
    await expect(deps.session()).rejects.toMatchObject({ code: "unauthenticated" })
    await expect(deps.session("mock-space")).rejects.toMatchObject({ code: "workspace_unknown" })
    expect(bound.slots.size).toBe(0)
    expect(vault.seen.length).toBe(before)
  })

  // The key-scope and origin guards run before any cached session is returned.
  test("a cached session refuses once only the key scope names another origin or workspace: no signature, no other key, and a restored scope works again", async () => {
    const a = await vault.enrolSoftware(base())
    const bound = await bindMcpContext(env, home.path)
    const deps = mcpDeps(env, bound, () => undefined)
    const { vaultFetch } = await import("./mcp/vault-fetch.ts")
    vault.relay = () => new Response("ok", { status: 200, headers: { "Mehen-Upstream": "1" } })
    expect(checkOf(await vaultStatus.call({}, deps, call), firstSlot())).toMatchObject({ ok: true, status: { device: a } })
    const scopePath = join(firstSlot(), "device-key.scope.json")
    const good = await readFile(scopePath, "utf8")
    for (const scope of [{ vault: "https://other.example", tenant: MOCK_TENANT }, { vault: vault.url, tenant: SECOND.id }]) {
      await writeFile(scopePath, `${JSON.stringify(scope)}\n`)
      const requests = vault.seen.length
      // Status reads the slot as one mehen cannot use, and signs nothing for it.
      expect(entries(await vaultStatus.call({}, deps, call)).find((e) => e.slot === firstSlot())).toMatchObject({ state: "corrupt", reason: "scope_mismatch" })
      await expect(deps.session()).rejects.toMatchObject({ code: "workspace_mismatch" })
      await expect(vaultFetch.call({ item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/models" }, deps, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
      expect(vault.seen.length).toBe(requests)
      // A guard's refusal is not a tombstone: the latch stands, and a restored scope works again.
      expect(bindingOf(bound, firstSlot())).toEqual({ latched: { vault: vault.url, tenant: MOCK_TENANT, device: a } })
      expect(await readConfig(firstSlot())).toMatchObject({ device: a, tenant: MOCK_TENANT })
      expect(await readFile(scopePath, "utf8")).toBe(`${JSON.stringify(scope)}\n`)
    }
    await writeFile(scopePath, good)
    expect(checkOf(await vaultStatus.call({}, deps, call), firstSlot())).toMatchObject({ ok: true, status: { device: a } })
    expect(vault.seen.at(-1)?.claims).toMatchObject({ dev: a, ten: MOCK_TENANT })
    expect(((await vaultFetch.call({ item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/models" }, deps, call)).structured as { status: number }).status).toBe(200)
  })

  // A rename that status recorded refreshes the cached session's
  // display evidence: ledger scope, call provenance and the links built
  // under it follow the disk, while the stable identity and key stay.
  test("after a rename recorded by vault_status, the same server's asks and provenance use the new canonical slug, never the old alias", async () => {
    const a = await vault.enrolSoftware(base())
    const bound = await bindMcpContext(env, home.path)
    const deps = mcpDeps(env, bound, () => undefined)
    const { vaultFetch } = await import("./mcp/vault-fetch.ts")
    const { vaultRequest } = await import("./mcp/vault-request.ts")
    const { readLedger } = await import("./ledger.ts")
    const beforeRename = await deps.session()
    expect(beforeRename.context.workspace?.slug).toBe("mock-space")
    vault.workspace = { id: MOCK_TENANT, slug: "renamed-space", name: "Renamed Space" }
    expect(checkOf(await vaultStatus.call({}, deps, call), firstSlot())).toMatchObject({ ok: true, status: { workspace: { slug: "renamed-space" } } })
    const after = await deps.session()
    expect(after.config.device).toBe(a)
    expect(after.context.workspace).toEqual({ id: MOCK_TENANT, slug: "renamed-space", name: "Renamed Space" })
    expect(after.ledger.workspaceSlug).toBe("renamed-space")
    expect(bindingOf(bound, firstSlot())).toEqual({ latched: { vault: vault.url, tenant: MOCK_TENANT, device: a } })
    // A refusal's ask is checked and built under the new slug, with the new provenance.
    vault.overrides.set("POST /v1/relay", () => vaultError("approval_required", "Needs approval.", { next: { url: `${vault.url}/w/renamed-space/a/apr_rename`, say: "x" }, approval: "apr_rename", bindingCode: "K7Q2" }))
    let thrown: unknown
    try {
      await vaultFetch.call({ item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x" }, deps, call)
    } catch (error) {
      thrown = error
    }
    const { askForError } = await import("./ask.ts")
    const { toCliError } = await import("./errors.ts")
    const { ask } = askForError(toCliError(thrown), env, { vaultUrl: vault.url, workspaceSlug: "renamed-space" })
    expect(ask).toMatchObject({ url: `${vault.url}/w/renamed-space/a/apr_rename`, context: { origin: vault.url, workspace: { id: MOCK_TENANT, slug: "renamed-space", name: "Renamed Space" }, device: a } })
    expect(ask?.url).not.toContain("mock-space")
    // A new ask is recorded and read back under the new slug.
    const created = await vaultRequest.call({ kind: "api-key", name: "openai-new", reason: "r", provider: "openai" }, deps, call)
    const recorded = created.structured as { ask: { url: string; context: { workspace: { slug: string } } } }
    expect(recorded.ask.url).toContain("/w/renamed-space/i/")
    expect(recorded.ask.context.workspace.slug).toBe("renamed-space")
    const entries = await readLedger(firstSlot(), { vaultUrl: vault.url, workspace: MOCK_TENANT, device: a, workspaceSlug: "renamed-space" })
    expect(entries.map((e) => e.ask.context?.workspace?.slug)).toEqual(["renamed-space"])
    expect(await readLedger(firstSlot(), { vaultUrl: vault.url, workspace: MOCK_TENANT, device: a, workspaceSlug: "mock-space" })).toEqual([])
    vault.overrides.clear()
    vault.relay = () => new Response("ok", { status: 200, headers: { "Mehen-Upstream": "1" } })
  })

  test("a server bound to A with an open cached session refuses once B replaces A on disk: no cached signer, no request, no write", async () => {
    const a = await vault.enrolSoftware(base())
    const bound = await bindMcpContext(env, home.path)
    const deps = mcpDeps(env, bound, () => undefined)
    const session = await deps.session()
    expect(checkOf(await vaultStatus.call({}, deps, call), firstSlot())).toMatchObject({ ok: true, status: { device: a } })
    const requests = vault.seen.length
    const b = await landIn(firstSlot(), { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name })
    await expect(deps.session()).rejects.toMatchObject({ code: "workspace_mismatch" })
    expect(checkOf(await vaultStatus.call({}, deps, call), firstSlot())).toMatchObject({ ok: false, error: "workspace_mismatch" })
    // The cached A session was not handed back: same object never returned again, no new request signed by A.
    expect(vault.seen.length).toBe(requests)
    expect(await readConfig(firstSlot())).toMatchObject({ tenant: SECOND.id, device: b, workspaceSlug: SECOND.slug, workspaceName: SECOND.name })
    expect(session.config.device).toBe(a)
  })

  // A pinned server's doctor and enrolment wait never leave the
  // pinned workspace.
  test("vault_doctor and vault_wait on a pinned server never re-select: a pending enrolment in B stays untouched", async () => {
    const { first } = await twoContexts()
    // A server pinned to A by name.
    const named = { ...env, MEHEN_WORKSPACE: "mock-space" }
    const bound = await bindMcpContext(named, home.path)
    expect(bound.pin).toEqual({ text: "mock-space", vault: vault.url, tenant: MOCK_TENANT })
    const deps = mcpDeps(named, bound, () => undefined)
    expect((await deps.session()).config.device).toBe(first)
    // Only B's pending slot records a pending enrolment.
    const { createDeviceKey } = await import("./device-key.ts")
    const { addLedgerEntry, readLedger } = await import("./ledger.ts")
    const { enrolAsk, askUrl } = await import("./ask.ts")
    const { vaultWait } = await import("./mcp/vault-wait.ts")
    const { vaultDoctor } = await import("./mcp/vault-doctor.ts")
    const pendingDir = pendingSlotPath(base(), vault.url, SECOND.slug)
    const { jwk } = await createDeviceKey(pendingDir, "software", {})
    const id = "enr_inB0000001"
    vault.enrolments.set(id, { id, jwk, name: "b-mac", backend: "software", polls: 0, workspace: SECOND.slug, owner: { kind: "self" } })
    const link = askUrl(`${vault.url}/w/${SECOND.slug}/e/ABCD2345`, { vaultUrl: vault.url, workspaceSlug: SECOND.slug })!
    await addLedgerEntry(pendingDir, { vaultUrl: vault.url, workspace: null, device: null }, { ask: enrolAsk({ id, url: link.url, name: "b-mac", backend: "software", fingerprint: "ZLSQ 8ZY0 FNHK WLS5", expiresAt: new Date(Date.now() + 600_000).toISOString(), requestedBy: { device: "d", session: null } }), enrol: { code: "ABCD2345", name: "b-mac", backend: "software", jwk, workspace: SECOND.slug, team: null } })
    const before = vault.seen.length
    const report = await vaultDoctor.call({}, deps, call)
    expect(reportOf(report).workspaces.map((w) => w.slot)).toEqual([firstSlot()])
    expect(enrolledAt(report, firstSlot())?.detail).toContain(first)
    // Every signed request doctor made was A's.
    for (const seen of vault.seen.slice(before)) expect(seen.claims.dev).toBe(first)
    const polls = vault.seen.length
    await expect(vaultWait.call({ id, timeoutSeconds: 1 }, deps, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
    expect(vault.seen.length).toBe(polls)
    expect(vault.enrolments.get(id)?.polls).toBe(0)
    expect(await readConfig(pendingDir)).toBeNull()
    expect((await readLedger(pendingDir, { vaultUrl: vault.url, workspace: null, device: null })).map((e) => e.ask.id)).toEqual([id])
    // A server bound to an empty A directory: wait resumes only an enrolment recorded in that directory.
    const emptyA = await tempDir()
    try {
      const empty = mcpDeps({ ...env, MEHEN_CONFIG_DIR: emptyA.path }, await bindMcpContext({ ...env, MEHEN_CONFIG_DIR: emptyA.path }, home.path), () => undefined)
      await expect(vaultWait.call({ id, timeoutSeconds: 1 }, empty, call)).rejects.toMatchObject({ code: "not_found" })
      expect(vault.seen.length).toBe(polls)
    } finally {
      await emptyA.remove()
    }
  })

  // An explicit selector must resolve to an enrolled identity even
  // with an explicit, empty directory.
  test("an explicit unknown --workspace with an empty MEHEN_CONFIG_DIR exits 2 before stdin, with nothing consumed, created or sent", async () => {
    const empty = await tempDir()
    try {
      const before = vault.seen.length
      for (const selector of ["tn_unknown0000001", "nowhere"]) {
        const proc = Bun.spawn([process.execPath, MAIN, "mcp", "--workspace", selector], {
          env: { PATH: process.env.PATH ?? "", HOME: home.path, MEHEN_CONFIG_DIR: empty.path, MEHEN_VAULT_URL: vault.url },
          stdin: "pipe",
          stdout: "pipe",
          stderr: "pipe",
          timeout: 10_000,
        })
        // stdin stays open and unwritten: a server that read it would hang here.
        const code = await proc.exited
        expect(code).toBe(EXIT.usage)
        expect(await new Response(proc.stdout).text()).toBe("")
        expect(await new Response(proc.stderr).text()).toContain(`No enrolment on this machine is in workspace ${selector}.`)
        proc.stdin.end()
      }
      expect(vault.seen.length).toBe(before)
      const { readdir } = await import("node:fs/promises")
      expect(await readdir(empty.path)).toEqual([])
    } finally {
      await empty.remove()
    }
  })

  // An unbound manifest under several known contexts is refused
  // through the explicit-directory path too, before any session.
  test("vault_env in an unbound checkout is refused under two known contexts even with MEHEN_CONFIG_DIR, and passes under one", async () => {
    await twoContexts()
    const repo = await tempDir()
    try {
      await writeFile(join(repo.path, "mehen.toml"), 'project = "prj_1"\n')
      // The root named explicitly, and one of its two workspaces selected.
      const explicit = { ...env, MEHEN_CONFIG_DIR: base(), MEHEN_WORKSPACE: "mock-space" }
      const bound = await bindMcpContext(explicit, home.path)
      expect((await spanSlots(bound)).active).toHaveLength(2)
      const before = vault.seen.length
      const result = await runJv(["mcp"], explicit, JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "vault_env", arguments: { cwd: repo.path } } }) + "\n")
      const reply = JSON.parse(result.stdout) as { result: { isError: boolean; structuredContent: { error: string; next: { command: string } } } }
      expect(reply.result.isError).toBe(true)
      expect(reply.result.structuredContent).toMatchObject({ error: "workspace_unbound", next: { command: "mehen workspace bind" } })
      expect(vault.seen.length).toBe(before)
      // A server started in that checkout refuses at startup for the same reason.
      const startup = await runJv(["mcp"], explicit, '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n', repo.path)
      expect(startup.code).toBe(EXIT.usage)
      expect(startup.stdout).toBe("")
      // One known context: the legacy manifest still works.
      const one = await tempDir()
      try {
        await vault.enrolSoftware(join(one.path, ".config", "mehen"))
        const single = await bindMcpContext({ HOME: one.path, MEHEN_CONFIG_DIR: "" }, home.path)
        expect((await resolveSlot(single, null, { manifest: manifestWorkspace(repo.path), strict: true })).config.tenant).toBe(MOCK_TENANT)
      } finally {
        await one.remove()
      }
    } finally {
      await repo.remove()
    }
  })

  test("workspace and owner names are echoed as data: hidden characters are spelled out in the text and kept raw in the structured result", async () => {
    await vault.enrolSoftware(base())
    vault.workspace = { id: MOCK_TENANT, slug: "mock-space", name: "Mock\u001b[31m $(evil) \"name\"" }
    const result = await runJv(["mcp"], env, '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_status","arguments":{}}}\n')
    const reply = JSON.parse(result.stdout) as { result: { content: { text: string }[]; structuredContent: { workspaces: { check: { status: { workspace: { name: string } } } }[] } } }
    expect(reply.result.structuredContent.workspaces[0]?.check.status.workspace.name).toBe("Mock\u001b[31m $(evil) \"name\"")
    expect(reply.result.content[0]?.text).not.toContain("\u001b")
    expect(reply.result.content[0]?.text).toContain("Mock\\u001b[31m $(evil)")
  })
})

describe("the per-slot latch table", () => {
  const noop = () => undefined
  const imports = async () => ({
    ...(await import("./mcp/vault-show.ts")),
    ...(await import("./mcp/vault-list.ts")),
    ...(await import("./mcp/vault-wait.ts")),
    ...(await import("./mcp/vault-pending.ts")),
    ...(await import("./mcp/vault-doctor.ts")),
    ...(await import("./mcp/vault-request.ts")),
  })

  test("a slot whose enrolment changed is refused for the life of the server while the other slot keeps serving", async () => {
    const { first, secondDevice } = await twoContexts()
    const server = await bindMcpContext(env, home.path)
    const deps = mcpDeps(env, server, noop)
    expect((await deps.session("mock-space")).config.device).toBe(first)
    expect((await deps.session(SECOND.slug)).config.device).toBe(secondDevice)
    const saved = await Promise.all(["config.json", "device-key.json", "device-key.scope.json"].map(async (f) => [f, await readFile(join(second(), f), "utf8")] as const))
    const replaced = await landIn(second(), { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name })
    const before = vault.seen.filter((c) => c.claims.dev !== first).length
    await expect(deps.session(SECOND.slug)).rejects.toMatchObject({ code: "workspace_mismatch", next: { say: expect.stringContaining("Restart the agent") } })
    expect((await deps.session("mock-space")).config.device).toBe(first)
    const status = await vaultStatus.call({}, deps, call)
    expect(checkOf(status, second())).toMatchObject({ ok: false, error: "workspace_mismatch" })
    expect(checkOf(status, firstSlot())).toMatchObject({ ok: true, status: { device: first } })
    // The original enrolment put back: still refused, a tombstone does not heal inside a running server.
    for (const [file, text] of saved) await writeFile(join(second(), file), text, { mode: 0o600 })
    await expect(deps.session(SECOND.slug)).rejects.toMatchObject({ code: "workspace_mismatch" })
    expect(bindingOf(server, second())).toMatchObject({ refused: { reason: expect.stringContaining(replaced), since: expect.any(String) } })
    expect(vault.seen.filter((c) => c.claims.dev !== first).length).toBe(before)
    // A new server latches what is on disk now.
    expect((await mcpDeps(env, await bindMcpContext(env, home.path), noop).session(SECOND.slug)).config.device).toBe(secondDevice)
  })

  test("MEHEN_WORKSPACES narrows the server: a workspace outside it is workspace_not_allowed for every tool, before anything is sent; the one inside needs no argument", async () => {
    await twoContexts()
    const narrowed = { ...env, MEHEN_WORKSPACES: "mock-space" }
    const server = await bindMcpContext(narrowed, home.path)
    const deps = mcpDeps(narrowed, server, noop)
    const tools = await imports()
    const before = vault.seen.length
    for (const workspace of [SECOND.slug, SECOND.id]) {
      await expect(vaultStatus.call({ workspace }, deps, call)).rejects.toMatchObject({ code: "workspace_not_allowed" })
      await expect(tools.vaultDoctor.call({ workspace }, deps, call)).rejects.toMatchObject({ code: "workspace_not_allowed" })
      await expect(tools.vaultShow.call({ item: "openai-personal", workspace }, deps, call)).rejects.toMatchObject({ code: "workspace_not_allowed" })
      await expect(tools.vaultList.call({ workspace }, deps, call)).rejects.toMatchObject({ code: "workspace_not_allowed" })
      await expect(tools.vaultPending.call({ workspace }, deps, call)).rejects.toMatchObject({ code: "workspace_not_allowed" })
      await expect(tools.vaultWait.call({ id: "apr_outside01", workspace, timeoutSeconds: 0 }, deps, call)).rejects.toMatchObject({ code: "workspace_not_allowed" })
      await expect(tools.vaultRequest.call({ kind: "api-key", name: "x", reason: "r", provider: "openai", workspace }, deps, call)).rejects.toMatchObject({ code: "workspace_not_allowed" })
    }
    expect(vault.seen.length).toBe(before)
    const status = await vaultStatus.call({}, deps, call)
    expect(entries(status).map((e) => e.slot)).toEqual([firstSlot()])
    expect(status.structured).toMatchObject({ allowed: ["mock-space"], selected: firstSlot() })
    expect((await deps.session()).config.tenant).toBe(MOCK_TENANT)
    expect(vault.seen.slice(before).some((c) => c.claims.ten === SECOND.id)).toBe(false)
  })

  test("MEHEN_WORKSPACE pins every call: a conflicting workspace argument is workspace_mismatch, and a pin outside the ceiling refuses at start", async () => {
    await twoContexts()
    const pinned = { ...env, MEHEN_WORKSPACE: "mock-space" }
    const deps = mcpDeps(pinned, await bindMcpContext(pinned, home.path), noop)
    const tools = await imports()
    const before = vault.seen.length
    await expect(deps.session(SECOND.slug)).rejects.toMatchObject({ code: "workspace_mismatch" })
    await expect(vaultStatus.call({ workspace: SECOND.slug }, deps, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
    await expect(tools.vaultShow.call({ item: "openai-personal", workspace: SECOND.id }, deps, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
    expect(vault.seen.length).toBe(before)
    // The pinned workspace named by its id is the same workspace.
    expect((await deps.session(MOCK_TENANT)).config.tenant).toBe(MOCK_TENANT)
    expect(entries(await vaultStatus.call({}, deps, call)).map((e) => e.slot)).toEqual([firstSlot()])
    await expect(bindMcpContext({ ...pinned, MEHEN_WORKSPACES: SECOND.slug }, home.path)).rejects.toMatchObject({ code: "workspace_not_allowed" })
  })

  test("an unbound checkout refuses workspace_unbound before the only-slot shortcut and before a workspace argument once a second workspace is enrolled", async () => {
    await vault.enrolSoftware(base())
    const repo = await tempDir()
    try {
      await writeFile(join(repo.path, "mehen.toml"), 'project = "prj_1"\n')
      const server = await bindMcpContext(env, repo.path)
      const deps = mcpDeps(env, server, noop)
      expect((await deps.session()).config.tenant).toBe(MOCK_TENANT)
      await vault.enrolSoftware(base(), { config: { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name } })
      const before = vault.seen.length
      await expect(deps.session()).rejects.toMatchObject({ code: "workspace_unbound", next: { command: "mehen workspace bind" } })
      await expect(deps.session("mock-space")).rejects.toMatchObject({ code: "workspace_unbound" })
      expect(vault.seen.length).toBe(before)
    } finally {
      await repo.remove()
    }
  })

  test("a slot vault_wait enrols is latched and later calls use it; a pending entry in the ceiling admits only the workspace it activates into", async () => {
    await vault.enrolSoftware(base(), { config: { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name } })
    const id = "enr_latchWait0001"
    await pendingAt(base(), id)
    const narrowed = { ...env, MEHEN_WORKSPACES: "mock-space", MEHEN_VAULT_URL: vault.url }
    const server = await bindMcpContext(narrowed, home.path)
    const deps = mcpDeps(narrowed, server, noop)
    const tools = await imports()
    expect(latchState(server).allowed).toEqual([{ entry: "mock-space", origin: vault.url, workspace: null }])
    expect(entries(await vaultStatus.call({}, deps, call))).toMatchObject([{ state: "pending", enrolment: id }])
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    const done = await tools.vaultWait.call({ id, timeoutSeconds: 5 }, deps, call)
    expect(done.structured).toMatchObject({ status: "active", tenant: MOCK_TENANT, device: deviceFor(id) })
    expect(bindingOf(server, firstSlot())).toEqual({ latched: { vault: vault.url, tenant: MOCK_TENANT, device: deviceFor(id) } })
    // No argument: the one admitted workspace is the new one.
    await tools.vaultShow.call({ item: "openai-personal" }, deps, call)
    expect(vault.seen.at(-1)?.claims).toMatchObject({ dev: deviceFor(id), ten: MOCK_TENANT })
    await expect(deps.session(SECOND.slug)).rejects.toMatchObject({ code: "workspace_not_allowed" })
  })

  test("an entry that resolved to a workspace id never admits another workspace that takes the same slug later", async () => {
    const a = await vault.enrolSoftware(base())
    const narrowed = { ...env, MEHEN_WORKSPACES: "mock-space" }
    const server = await bindMcpContext(narrowed, home.path)
    const deps = mcpDeps(narrowed, server, noop)
    expect(latchState(server).allowed).toEqual([{ entry: "mock-space", origin: vault.url, workspace: MOCK_TENANT }])
    expect(bindingOf(server, firstSlot())).toEqual({ latched: { vault: vault.url, tenant: MOCK_TENANT, device: a } })
    const { rm } = await import("node:fs/promises")
    await rm(firstSlot(), { recursive: true })
    const imposter = await vault.enrolSoftware(base(), { config: { tenant: SECOND.id, workspaceSlug: "mock-space", workspaceName: "Imposter" } })
    const before = vault.seen.length
    const status = await vaultStatus.call({}, deps, call)
    expect(entries(status).some((e) => e.slot === second())).toBe(false)
    expect(checkOf(status, firstSlot())).toMatchObject({ ok: false, error: "workspace_mismatch" })
    await expect(deps.session()).rejects.toMatchObject({ code: "workspace_mismatch" })
    await expect(deps.session("mock-space")).rejects.toMatchObject({ code: "workspace_mismatch" })
    await expect(deps.session(SECOND.id)).rejects.toMatchObject({ code: "workspace_not_allowed" })
    expect(vault.seen.length).toBe(before)
    expect(vault.seen.some((c) => c.claims.dev === imposter)).toBe(false)
  })

  test("McpLatchState round-trips; a changed home, or the same MEHEN_WORKSPACES resolved to another workspace, is refused; a latched slot that changed comes back refused", async () => {
    const a = await vault.enrolSoftware(base())
    const narrowed = { ...env, MEHEN_WORKSPACES: "mock-space" }
    const server = await bindMcpContext(narrowed, home.path)
    const state = JSON.parse(JSON.stringify(latchState(server))) as unknown
    expect(state).toEqual({ v: 1, home: base(), allowed: [{ entry: "mock-space", origin: vault.url, workspace: MOCK_TENANT }], pin: null, manifest: null, slots: { [slotKey(server, firstSlot())]: { latched: { vault: vault.url, tenant: MOCK_TENANT, device: a } } }, seen: { [slotKey(server, firstSlot())]: { dir: firstSlot(), config: expect.objectContaining({ vault: vault.url, tenant: MOCK_TENANT, device: a, workspaceSlug: "mock-space" }) } } })
    const next = await bindMcpContext(narrowed, home.path)
    next.slots.clear()
    next.seen.clear()
    await restoreLatchState(next, state)
    expect(latchState(next)).toEqual(state as ReturnType<typeof latchState>)
    expect((await mcpDeps(narrowed, next, noop).session()).config.device).toBe(a)
    const other = await tempDir()
    try {
      const otherEnv = { HOME: other.path, MEHEN_CONFIG_DIR: "", MEHEN_WORKSPACES: "mock-space" }
      await expect(restoreLatchState(await bindMcpContext(otherEnv, home.path), state)).rejects.toMatchObject({ code: "workspace_mismatch" })
      // The same string resolved to another workspace id at the same vault.
      await vault.enrolSoftware(join(other.path, ".config", "mehen"), { config: { tenant: SECOND.id, workspaceSlug: "mock-space", workspaceName: "Another" } })
      const differently = await bindMcpContext(otherEnv, home.path)
      expect(latchState(differently).allowed?.map((e) => e.entry)).toEqual(["mock-space"])
      await expect(restoreLatchState(differently, { ...(state as object), home: differently.home })).rejects.toMatchObject({ code: "workspace_mismatch" })
      // And to another vault.
      const third = await tempDir()
      try {
        const { writeConfig } = await import("./config.ts")
        await writeConfig(vault.slotDir(join(third.path, ".config", "mehen"), MOCK_TENANT, "https://elsewhere.example"), { vault: "https://elsewhere.example", tenant: MOCK_TENANT, device: "dev_elsewhere0001", backend: "software", workspaceSlug: "mock-space", workspaceName: "Elsewhere" })
        const elsewhere = await bindMcpContext({ ...otherEnv, HOME: third.path }, home.path)
        await expect(restoreLatchState(elsewhere, { ...(state as object), home: elsewhere.home })).rejects.toMatchObject({ code: "workspace_mismatch" })
      } finally {
        await third.remove()
      }
    } finally {
      await other.remove()
    }
    await expect(restoreLatchState(next, { ...(state as object), v: 2 })).rejects.toMatchObject({ code: "workspace_mismatch" })
    // A latched slot whose device changed before the takeover is refused, never served.
    const replaced = await landIn(firstSlot(), {})
    const later = await bindMcpContext(narrowed, home.path)
    later.slots.clear()
    later.seen.clear()
    await restoreLatchState(later, state)
    expect(bindingOf(later, firstSlot())).toMatchObject({ refused: { reason: expect.stringContaining(replaced) } })
    const before = vault.seen.length
    await expect(mcpDeps(narrowed, later, noop).session()).rejects.toMatchObject({ code: "workspace_mismatch" })
    expect(vault.seen.length).toBe(before)
  })

  test("McpLatchState carries the pin as it resolved and the startup manifest: a server that resolves another pin, or another manifest, refuses it", async () => {
    await vault.enrolSoftware(base())
    const pinned = { ...env, MEHEN_WORKSPACE: "mock-space" }
    const state = latchState(await bindMcpContext(pinned, home.path))
    expect(state.pin).toEqual({ text: "mock-space", vault: vault.url, tenant: MOCK_TENANT })
    expect(state.manifest).toBeNull()
    await restoreLatchState(await bindMcpContext(pinned, home.path), state)
    await expect(restoreLatchState(await bindMcpContext(env, home.path), state)).rejects.toMatchObject({ code: "workspace_mismatch", message: expect.stringContaining("its pin resolved to another workspace") })
    await expect(restoreLatchState(await bindMcpContext(pinned, home.path), { ...state, pin: { ...state.pin!, tenant: SECOND.id } })).rejects.toMatchObject({ code: "workspace_mismatch", message: expect.stringContaining("its pin resolved to another workspace") })
    const manifest = { path: join(home.path, "mehen.toml"), workspace: MOCK_TENANT, vault: null }
    await expect(restoreLatchState(await bindMcpContext(pinned, home.path), { ...state, manifest })).rejects.toMatchObject({ code: "workspace_mismatch", message: expect.stringContaining("its startup manifest is not this server's") })
  })

  test("on a managed host (rule 0) the server serves the pin alone: another slot under the root is never listed or used, and a call naming it is workspace_mismatch", async () => {
    const { chmodSync, mkdirSync, realpathSync, writeFileSync } = await import("node:fs")
    const owner = realpathSync(home.path)
    chmodSync(owner, 0o700)
    const marker = join(owner, ".config", "mehen")
    mkdirSync(marker, { recursive: true, mode: 0o700 })
    chmodSync(join(owner, ".config"), 0o755)
    writeFileSync(join(marker, "managed-agents"), "", { mode: 0o600 })
    const root = join(owner, "agent-root")
    // A pin names a device id of the vault's own form.
    const device = "dev_pinnedWork0001"
    const mocked = await vault.enrolSoftware(root)
    vault.devices.set(device, vault.devices.get(mocked)!)
    const { writeConfig } = await import("./config.ts")
    await writeConfig(vault.slotDir(root), { ...(await readConfig(vault.slotDir(root)))!, device })
    await vault.enrolSoftware(root, { config: { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name } })
    // An owner-provisioned layout-2 root (rule 0 never migrates).
    writeFileSync(join(root, "mehen.json"), JSON.stringify({ layout: 2, migratedAt: new Date().toISOString(), from: null }), { mode: 0o600 })
    const pinned = vault.slotDir(root)
    for (let dir = pinned; dir !== owner; dir = join(dir, "..")) chmodSync(dir, 0o700)
    const scope = { tags: ["work"], projects: [], maxEnvironment: "unprotected", modes: ["relay"], privateCredentials: false }
    const agentDir = join(owner, "agent")
    mkdirSync(agentDir, { mode: 0o700 })
    writeFileSync(join(pinned, "contexts.json"), JSON.stringify({ version: 3, contexts: { work: { agentDir, configDir: pinned, origin: vault.url, tenant: MOCK_TENANT, device, scope } } }), { mode: 0o600 })
    const files = { ownerRoot: owner, allowLoopbackHttpForTests: true }
    const managed = { HOME: owner, MEHEN_CONFIG_DIR: pinned, MEHEN_MANAGED_CONTEXT: "work" }
    const server = await bindMcpContext(managed, home.path, files)
    expect(server.managed).toBe(pinned)
    const deps = mcpDeps(managed, server, noop)
    const tools = await imports()
    const status = await vaultStatus.call({}, deps, call)
    expect(entries(status).map((e) => e.slot)).toEqual([pinned])
    expect(status.structured).toMatchObject({ allowed: null, selected: pinned })
    const before = vault.seen.length
    await expect(deps.session(SECOND.slug)).rejects.toMatchObject({ code: "workspace_mismatch" })
    await expect(tools.vaultShow.call({ item: "openai-personal", workspace: SECOND.id }, deps, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
    expect(vault.seen.length).toBe(before)
    await tools.vaultShow.call({ item: "openai-personal" }, deps, call)
    expect(vault.seen.at(-1)?.claims).toMatchObject({ dev: device, ten: MOCK_TENANT })
    // The launcher's variables unset or changed: the server refuses at start, as every command does.
    await expect(bindMcpContext({ HOME: owner }, home.path, files)).rejects.toMatchObject({ code: "workspace_mismatch" })
    await expect(bindMcpContext({ ...managed, MEHEN_WORKSPACE: SECOND.slug }, home.path, files)).rejects.toMatchObject({ code: "workspace_mismatch" })
    await expect(bindMcpContext({ ...managed, MEHEN_WORKSPACES: SECOND.slug }, home.path, files)).rejects.toMatchObject({ code: "workspace_not_allowed" })
  })

  test("one server attaches each call's own workspace provenance to a refusal's ask, never another workspace's", async () => {
    const { first, secondDevice } = await twoContexts()
    vault.overrides.set("POST /v1/relay", (_request, seen) => vaultError("approval_required", "Needs approval.", { next: { url: `${vault.url}/w/${seen.claims.ten === SECOND.id ? SECOND.slug : "mock-space"}/a/apr_1`, say: "x" }, approval: "apr_1", bindingCode: "K7Q2" }))
    const fetchIn = (id: number, workspace: string) => JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "vault_fetch", arguments: { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x", workspace } } })
    const result = await runJv(["mcp"], env, `${fetchIn(1, "mock-space")}\n${fetchIn(2, SECOND.slug)}\n`)
    const replies = result.stdout.trim().split("\n").map((l) => JSON.parse(l) as { id: number; result: { structuredContent: { ask: { url: string; context: unknown } } } }).sort((x, y) => x.id - y.id)
    expect(replies[0]?.result.structuredContent.ask).toMatchObject({ url: `${vault.url}/w/mock-space/a/apr_1`, context: { origin: vault.url, workspace: MOCK_WORKSPACE, device: first } })
    expect(replies[1]?.result.structuredContent.ask).toMatchObject({ url: `${vault.url}/w/${SECOND.slug}/a/apr_1`, context: { origin: vault.url, workspace: SECOND, device: secondDevice } })
  })
})

// A late slot is checked again when it is first used, against the
// admission frozen at start and the identity the call chose.
describe("a late slot replaced between discovery and first use", () => {
  const noop = () => undefined

  async function lateSlot(): Promise<{ deps: ReturnType<typeof mcpDeps>; server: McpServer; slot: Awaited<ReturnType<typeof spanSlots>>["active"][number] }> {
    const narrowed = { ...env, MEHEN_WORKSPACES: "mock-space", MEHEN_VAULT_URL: vault.url }
    const server = await bindMcpContext(narrowed, home.path)
    const deps = mcpDeps(narrowed, server, noop)
    // Enrolled after the server started, for an entry absent at start.
    await vault.enrolSoftware(base())
    const [slot] = (await deps.span()).active
    if (!slot) throw new Error("no late slot")
    return { deps, server, slot }
  }

  async function replaceWith(dir: string, config: Config): Promise<void> {
    const { createDeviceKey, writeKeyScope } = await import("./device-key.ts")
    const { writeConfig } = await import("./config.ts")
    const { jwk } = await createDeviceKey(dir, "software", {})
    vault.devices.set(config.device, { jwk, revoked: false, tenant: config.tenant })
    await writeConfig(dir, config)
    await writeKeyScope(dir, "software", { vault: config.vault, tenant: config.tenant })
  }

  test("replaced by another workspace at the same vault: workspace_not_allowed, nothing latched, opened or sent", async () => {
    const { deps, server, slot } = await lateSlot()
    const old = (await readConfig(slot.dir))!
    await replaceWith(slot.dir, { ...old, tenant: "tn_other00000001", device: "dev_outside000001", workspaceSlug: "outside", workspaceName: "Outside" })
    const before = vault.seen.length
    await expect(deps.open(slot)).rejects.toMatchObject({ code: "workspace_not_allowed" })
    await expect(deps.validate(slot)).rejects.toMatchObject({ code: "workspace_not_allowed" })
    expect(server.slots.size).toBe(0)
    expect(vault.seen.length).toBe(before)
    expect(vault.seen.some((c) => c.claims.ten === "tn_other00000001" || c.claims.dev === "dev_outside000001")).toBe(false)
  })

  test("replaced by the same slug at another vault: workspace_mismatch, nothing latched, opened or sent", async () => {
    const { deps, server, slot } = await lateSlot()
    const old = (await readConfig(slot.dir))!
    await replaceWith(slot.dir, { ...old, vault: "https://elsewhere.example", device: "dev_elsewhere00001" })
    const before = vault.seen.length
    await expect(deps.open(slot)).rejects.toMatchObject({ code: "workspace_mismatch" })
    expect(server.slots.size).toBe(0)
    expect(vault.seen.length).toBe(before)
    // Another device in the same workspace, after the call chose the old one: drift, not served either.
    await replaceWith(slot.dir, { ...old, device: "dev_drifted000001" })
    await expect(deps.open(slot)).rejects.toMatchObject({ code: "workspace_mismatch" })
    expect(server.slots.size).toBe(0)
    expect(vault.seen.length).toBe(before)
  })

  test("a first validation and an activation racing for one slot: the later commit never replaces the other's latch or revives a tombstone", async () => {
    const { deps, server, slot } = await lateSlot()
    const config = (await readConfig(slot.dir))!
    const { latchActivated } = await import("./mcp/binding.ts")
    // The activation commits B synchronously while the validation of A is in its first read.
    const other: Config = { ...config, device: "dev_racingB000001" }
    const [validated, activated] = await Promise.allSettled([deps.validate(slot), latchActivated(env, server, slot.dir, other)])
    expect(activated.status).toBe("rejected")
    expect(validated.status).toBe("rejected")
    expect(bindingOf(server, slot.dir)).toMatchObject({ refused: expect.any(Object) })
    // The tombstone stays: neither a validation of what is on disk nor an activation of it revives the slot.
    const before = vault.seen.length
    await expect(deps.open(slot)).rejects.toMatchObject({ code: "workspace_mismatch" })
    await expect(latchActivated(env, server, slot.dir, config)).rejects.toMatchObject({ code: "workspace_mismatch" })
    expect(bindingOf(server, slot.dir)).toMatchObject({ refused: expect.any(Object) })
    expect(vault.seen.length).toBe(before)
  })

  test("two first validations racing for one slot latch one identity, and an activation of another identity afterwards refuses the slot", async () => {
    const { deps, server, slot } = await lateSlot()
    const config = (await readConfig(slot.dir))!
    const results = await Promise.all([deps.validate(slot), deps.validate(slot)])
    expect(results.map((c) => c.device)).toEqual([config.device, config.device])
    expect(bindingOf(server, slot.dir)).toEqual({ latched: { vault: config.vault, tenant: config.tenant, device: config.device } })
    const { latchActivated } = await import("./mcp/binding.ts")
    await expect(latchActivated(env, server, slot.dir, { ...config, device: "dev_racingC000001" })).rejects.toMatchObject({ code: "workspace_mismatch" })
    expect(bindingOf(server, slot.dir)).toMatchObject({ refused: expect.any(Object) })
  })
})

// The pin is the workspace it resolved to at start, by origin and
// id. A rename leaves it there and a reused slug never moves it.
describe("a pinned server and a reused slug", () => {
  const noop = () => undefined
  const OTHER = "tn_other00000001"
  const showed = () => vault.seen.filter((c) => c.path === "/v1/items/openai-personal").at(-1)?.claims

  async function reusedSlug(extra: Record<string, string>) {
    const { writeConfig } = await import("./config.ts")
    const a = await vault.enrolSoftware(base())
    const pinnedEnv = { ...env, MEHEN_WORKSPACE: "mock-space", MEHEN_VAULT_URL: vault.url, ...extra }
    const server = await bindMcpContext(pinnedEnv, home.path)
    expect(server.pin).toEqual({ text: "mock-space", vault: vault.url, tenant: MOCK_TENANT })
    const deps = mcpDeps(pinnedEnv, server, noop)
    // A is renamed (the vault reports the new slug too), then B is enrolled under A's old slug.
    vault.workspace = { id: MOCK_TENANT, slug: "renamed-space", name: "Renamed" }
    await writeConfig(firstSlot(), { ...(await readConfig(firstSlot()))!, workspaceSlug: "renamed-space", workspaceName: "Renamed" })
    const b = await vault.enrolSoftware(base(), { config: { tenant: OTHER, workspaceSlug: "mock-space", workspaceName: "Slug Reuser" } })
    return { a, b, deps, server }
  }

  for (const [name, extra] of [["an unrestricted ceiling", {}], ["a ceiling holding both workspaces", { MEHEN_WORKSPACES: `mock-space,${OTHER}` }]] as const) {
    test(`under ${name}, only A is ever selected and B is never signed for`, async () => {
      const { a, b, deps } = await reusedSlug(extra)
      const { vaultShow } = await import("./mcp/vault-show.ts")
      const { vaultList } = await import("./mcp/vault-list.ts")
      const { vaultDoctor } = await import("./mcp/vault-doctor.ts")
      const { vaultPending } = await import("./mcp/vault-pending.ts")
      const { vaultWait } = await import("./mcp/vault-wait.ts")
      const { addLedgerEntry } = await import("./ledger.ts")
      const { approvalAsk, askUrl } = await import("./ask.ts")
      const before = vault.seen.length
      // Single-workspace tools with no argument: A.
      await vaultShow.call({ item: "openai-personal" }, deps, call)
      expect(showed()).toMatchObject({ dev: a, ten: MOCK_TENANT })
      expect((await deps.session("renamed-space")).config.device).toBe(a)
      // Spanning tools: A alone.
      expect(entries(await vaultStatus.call({}, deps, call)).map((e) => e.slot)).toEqual([firstSlot()])
      expect(((await vaultList.call({}, deps, call)).structured as { items: { workspace: string }[] }).items.every((i) => i.workspace === MOCK_TENANT)).toBe(true)
      expect(reportOf(await vaultDoctor.call({}, deps, call)).workspaces.map((w) => w.slot)).toEqual([firstSlot()])
      // An ask B made is not A's to list or wait on.
      const link = askUrl(`${vault.url}/w/mock-space/a/apr_inB0000001`, { vaultUrl: vault.url, workspaceSlug: "mock-space" })!
      await addLedgerEntry(vault.slotDir(base(), OTHER), { vaultUrl: vault.url, workspace: OTHER, device: b, workspaceSlug: "mock-space" }, { ask: approvalAsk({ id: "apr_inB0000001", url: link.url, summary: "s", bindingCode: null, expiresAt: new Date(Date.now() + 600_000).toISOString(), requestedBy: { device: "d", session: null } }) })
      expect(((await vaultPending.call({}, deps, call)).structured as { pending: { id: string }[] }).pending.map((p) => p.id)).not.toContain("apr_inB0000001")
      await expect(vaultWait.call({ id: "apr_inB0000001", timeoutSeconds: 0 }, deps, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
      // An enrolment pending under the reused slug is not the pinned workspace either.
      const enr = "enr_reusedSlug0001"
      await pendingAt(base(), enr)
      vault.enrolOutcome = { pendingPolls: 0, result: "active" }
      await expect(vaultWait.call({ id: enr, timeoutSeconds: 1 }, deps, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
      expect(vault.enrolments.get(enr)?.polls).toBe(0)
      // Explicit arguments naming B, by its slug or its id: refused.
      const seen = vault.seen.length
      for (const workspace of ["mock-space", OTHER]) {
        await expect(deps.session(workspace)).rejects.toMatchObject({ code: "workspace_mismatch" })
        await expect(vaultShow.call({ item: "openai-personal", workspace }, deps, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
        await expect(vaultStatus.call({ workspace }, deps, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
        await expect(vaultList.call({ workspace }, deps, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
        await expect(vaultWait.call({ id: "apr_inB0000001", workspace, timeoutSeconds: 0 }, deps, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
      }
      expect(vault.seen.length).toBe(seen)
      expect(vault.seen.slice(before).some((c) => c.claims.dev === b || c.claims.ten === OTHER)).toBe(false)
    })
  }

  test("the pin includes the origin: the same workspace id at another vault is never selected, and A gone is refused rather than replaced", async () => {
    const { writeConfig } = await import("./config.ts")
    const a = await vault.enrolSoftware(base())
    const pinnedEnv = { ...env, MEHEN_WORKSPACE: MOCK_TENANT }
    const server = await bindMcpContext(pinnedEnv, home.path)
    const deps = mcpDeps(pinnedEnv, server, noop)
    const elsewhere = vault.slotDir(base(), MOCK_TENANT, "https://elsewhere.example")
    await writeConfig(elsewhere, { vault: "https://elsewhere.example", tenant: MOCK_TENANT, device: "dev_elsewhere00001", backend: "software", workspaceSlug: "mock-space", workspaceName: "Elsewhere" })
    const { vaultShow } = await import("./mcp/vault-show.ts")
    await vaultShow.call({ item: "openai-personal" }, deps, call)
    expect(showed()).toMatchObject({ dev: a, ten: MOCK_TENANT })
    expect(entries(await vaultStatus.call({}, deps, call)).map((e) => e.slot)).toEqual([firstSlot()])
    expect((await deps.session(MOCK_TENANT)).config.vault).toBe(vault.url)
    const { rm } = await import("node:fs/promises")
    await rm(firstSlot(), { recursive: true })
    const before = vault.seen.length
    await expect(deps.session()).rejects.toMatchObject({ code: "workspace_mismatch" })
    await expect(deps.session(MOCK_TENANT)).rejects.toMatchObject({ code: "workspace_mismatch" })
    expect(entries(await vaultStatus.call({}, deps, call)).map((e) => e.slot)).toEqual([firstSlot()])
    expect(vault.seen.length).toBe(before)
    expect(bindingOf(server, firstSlot())).toMatchObject({ refused: expect.any(Object) })
  })
})

// Status compares the enrolment with the latch before the key's
// health can make it read as corrupt, so a changed enrolment is refused for
// the life of the server even when its key is broken at the time.
describe("status and a changed enrolment with a broken key", () => {
  const noop = () => undefined
  const FILES = ["config.json", "device-key.json", "device-key.scope.json"]
  const breakers: [string, (dir: string) => Promise<void>][] = [
    ["missing", async (dir) => (await import("node:fs/promises")).rm(join(dir, "device-key.json"))],
    ["insecure", async (dir) => (await import("node:fs/promises")).chmod(join(dir, "device-key.json"), 0o644)],
    ["scoped to another workspace", async (dir) => writeFile(join(dir, "device-key.scope.json"), `${JSON.stringify({ vault: vault.url, tenant: SECOND.id })}\n`)],
  ]
  const changes: [string, (c: Config) => Config][] = [
    ["device", (c) => ({ ...c, device: "dev_replaced000001" })],
    ["workspace", (c) => ({ ...c, tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name })],
  ]
  for (const [keyState, breakKey] of breakers) {
    for (const [what, change] of changes) {
      test(`a changed ${what} seen while the key is ${keyState} is refused until restart, after the files are restored`, async () => {
        const { writeConfig } = await import("./config.ts")
        const { vaultShow } = await import("./mcp/vault-show.ts")
        const a = await vault.enrolSoftware(base())
        const server = await bindMcpContext(env, home.path)
        const deps = mcpDeps(env, server, noop)
        const dir = firstSlot()
        const saved = await Promise.all(FILES.map(async (f) => [f, await readFile(join(dir, f), "utf8")] as const))
        const good = (await readConfig(dir))!
        await writeConfig(dir, change(good))
        await breakKey(dir)
        const before = vault.seen.length
        await vaultStatus.call({}, deps, call)
        expect(bindingOf(server, dir)).toMatchObject({ refused: { reason: expect.any(String) } })
        const { chmod } = await import("node:fs/promises")
        for (const [file, text] of saved) {
          await writeFile(join(dir, file), text, { mode: 0o600 })
          await chmod(join(dir, file), 0o600)
        }
        await expect(deps.session()).rejects.toMatchObject({ code: "workspace_mismatch" })
        await expect(vaultShow.call({ item: "openai-personal" }, deps, call)).rejects.toMatchObject({ code: "workspace_mismatch" })
        expect(checkOf(await vaultStatus.call({}, deps, call), dir)).toMatchObject({ ok: false, error: "workspace_mismatch" })
        expect(vault.seen.length).toBe(before)
        // A new server serves the restored enrolment.
        expect((await mcpDeps(env, await bindMcpContext(env, home.path), noop).session()).config.device).toBe(a)
      })
    }
  }

  test("only the key broken, the enrolment unchanged: status reports it and the slot works again once the key is back (the guards still run first)", async () => {
    const a = await vault.enrolSoftware(base())
    const server = await bindMcpContext(env, home.path)
    const deps = mcpDeps(env, server, noop)
    const dir = firstSlot()
    const { rename } = await import("node:fs/promises")
    await rename(join(dir, "device-key.json"), join(home.path, "key-aside"))
    expect(entries(await vaultStatus.call({}, deps, call)).find((e) => e.slot === dir)).toMatchObject({ state: "corrupt", reason: "key_missing" })
    expect(bindingOf(server, dir)).toEqual({ latched: { vault: vault.url, tenant: MOCK_TENANT, device: a } })
    await rename(join(home.path, "key-aside"), join(dir, "device-key.json"))
    expect(checkOf(await vaultStatus.call({}, deps, call), dir)).toMatchObject({ ok: true, status: { device: a } })
  })
})

// vault_list pages through the rows of every workspace in one order: the
// mock lists the same two items in each.
describe("vault_list across two workspaces", () => {
  const noop = () => undefined
  type Page = { workspaces: { id: string }[]; items: { slug: string; workspace: string }[]; total: number; nextOffset?: number }
  const list = async (args: Record<string, unknown>) => {
    const deps = mcpDeps(env, await bindMcpContext(env, home.path), noop)
    return (await vaultList.call(args, deps, call)).structured as Page
  }

  test("a page that ends in the first workspace's rows continues into the second's on the next page", async () => {
    await twoContexts()
    const first = await list({ limit: 3 })
    const [a = "", b = ""] = first.workspaces.map((w) => w.id)
    expect([a, b].sort()).toEqual([MOCK_TENANT, SECOND.id].sort())
    expect(first).toMatchObject({ total: 4, nextOffset: 3 })
    expect(first.items.map((i) => [i.workspace, i.slug])).toEqual([[a, "openai-personal"], [a, "github-work"], [b, "openai-personal"]])
    const next = await list({ limit: 3, offset: 3 })
    expect(next.total).toBe(4)
    expect(next.nextOffset).toBeUndefined()
    expect(next.items.map((i) => [i.workspace, i.slug])).toEqual([[b, "github-work"]])
  })

  test("an empty search filters nothing", async () => {
    await twoContexts()
    const all = await list({})
    expect(all.total).toBe(4)
    expect(await list({ search: "" })).toEqual(all)
  })
})
