import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { z } from "zod"
import { ITEM_HEADER, MANDATE_HEADER, RULE_HEADER, UPSTREAM_HEADER } from "@mehen/protocol/api"
import { LEASE_ONLY_HOST } from "@mehen/protocol/binding"
import { fingerprintOf } from "@mehen/protocol/fingerprint"
import { jwkThumbprint } from "@mehen/protocol/proof"
import { OAUTH_PROVIDERS, TEMPLATES } from "@mehen/protocol/templates"
import { type AskUrl, approvalAsk, askUrl, enrolAsk, intakeAsk, withContext } from "./ask.ts"
import { readConfig } from "./config.ts"
import { OUTCOME_UNKNOWN_SAY } from "./errors.ts"
import { createDeviceKey } from "./device-key.ts"
import { pendingSlotPath } from "./home.ts"
import { addLedgerEntry, readLedger } from "./ledger.ts"
import { FETCH_BODY_LIMIT, MCP_PROTOCOL_VERSION, mcpThen, progressMessage } from "./mcp.ts"
import { TOOLS } from "./mcp/registry.ts"
import { waitTarget } from "./operations.ts"
import { MOCK_EXPIRES_AT, MOCK_OWNER, MOCK_TENANT, MOCK_WORKSPACE, MockVault, deviceFor, item, vaultError } from "./testing/mock-vault.ts"
import { pendingWorkspaceFixtures } from "./testing/pending-workspace-fixtures.ts"
import { ruleView } from "./testing/policy-rules-fixtures.ts"
import { mandateView } from "./testing/mandate-fixtures.ts"
import { MAIN, tempDir } from "./testing/run-mehen.ts"

type Message = { jsonrpc: "2.0"; id?: number | string | null; method?: string; params?: Record<string, unknown>; result?: Record<string, unknown>; error?: { code: number; message: string } }

type Content = { type: string; text?: string; uri?: string; name?: string; description?: string; mimeType?: string }

// The server starts on the first message, with the root and ceiling the
// test has set up by then; a slot enrolled later is served by the same
// server, latched on its first use.
class McpClient {
  private proc: ReturnType<typeof Bun.spawn<"pipe", "pipe", "pipe">> | null = null
  private home: string | null = null
  private readonly waiting = new Map<number | string | null, (message: Message) => void>()
  readonly received: Message[] = []
  private nextId = 1

  constructor(private readonly env: Record<string, string>) {}

  private started(): ReturnType<typeof Bun.spawn<"pipe", "pipe", "pipe">> {
    if (this.proc) return this.proc
    // HOME is an empty directory: a server under test never discovers this user's own enrolments.
    this.home = mkdtempSync(join(tmpdir(), "mehen-mcp-home-"))
    const proc = Bun.spawn([process.execPath, MAIN, "mcp"], {
      env: { PATH: process.env.PATH ?? "", HOME: this.home, MEHEN_POLL_INTERVAL_MS: "20", ...this.env },
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
      timeout: 30_000,
    })
    this.proc = proc
    void this.read(proc)
    return proc
  }

  private async read(proc: ReturnType<typeof Bun.spawn<"pipe", "pipe", "pipe">>): Promise<void> {
    const decoder = new TextDecoder()
    let buffer = ""
    const reader = proc.stdout.getReader()
    for (;;) {
      const { done, value } = await reader.read()
      if (done) return
      buffer += decoder.decode(value, { stream: true })
      let newline = buffer.indexOf("\n")
      while (newline !== -1) {
        const message = JSON.parse(buffer.slice(0, newline)) as Message
        buffer = buffer.slice(newline + 1)
        newline = buffer.indexOf("\n")
        this.received.push(message)
        // A server notification has no id and answers nothing.
        if (message.method !== undefined) continue
        const id = message.id ?? null
        this.waiting.get(id)?.(message)
        this.waiting.delete(id)
      }
    }
  }

  send(line: string): void {
    const proc = this.started()
    proc.stdin.write(`${line}\n`)
    proc.stdin.flush()
  }

  request(method: string, params?: unknown): Promise<Message> {
    const id = this.nextId++
    const reply = new Promise<Message>((resolve) => this.waiting.set(id, resolve))
    this.send(JSON.stringify({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) }))
    return reply
  }

  notifications(method: string): Message[] {
    return this.received.filter((m) => m.method === method)
  }

  expectReply(id: number | string | null): Promise<Message> {
    return new Promise<Message>((resolve) => this.waiting.set(id, resolve))
  }

  async close(): Promise<number> {
    const proc = this.proc
    this.proc = null
    if (!proc) return 0
    proc.stdin.end()
    const code = await proc.exited
    if (this.home !== null) rmSync(this.home, { recursive: true, force: true })
    this.home = null
    return code
  }
}

let vault: MockVault
let dir: { path: string; remove(): Promise<void> }
let mcp: McpClient
const scope = () => vault.ledgerScope()

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  vault.overrides.clear()
  vault.sequences.clear()
  vault.lastDevice = null
  mcp = new McpClient({ MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url, MEHEN_SESSION: "mcp-test" })
})
afterEach(async () => {
  await mcp.close()
  await dir.remove()
})

// Each tool's outputSchema, as a validator: a host's MCP SDK checks an
// error's structuredContent against it too, so every error result this
// suite gets from such a tool must meet it (outputSchemaRefuses).
const OUTPUT_SCHEMAS = new Map(TOOLS.flatMap((t) => (t.output ? [[t.name, z.fromJSONSchema(t.output as never)] as const] : [])))

function outputSchemaRefuses(name: string, result: Record<string, unknown>): string | null {
  const parsed = OUTPUT_SCHEMAS.get(name)?.safeParse(result.structuredContent)
  return parsed === undefined || parsed.success ? null : `${name}: ${parsed.error.message}`
}

async function callTool(name: string, args: Record<string, unknown>, meta?: Record<string, unknown>): Promise<Record<string, unknown>> {
  const reply = await mcp.request("tools/call", { name, arguments: args, ...(meta ? { _meta: meta } : {}) })
  expect(reply.error).toBeUndefined()
  const result = reply.result as Record<string, unknown>
  if (result.isError === true) expect(outputSchemaRefuses(name, result)).toBeNull()
  return result
}

function content(result: Record<string, unknown>): Content[] {
  return result.content as Content[]
}

function text(result: Record<string, unknown>): string {
  return content(result)[0]?.text ?? ""
}

function resourceLinks(result: Record<string, unknown>): Content[] {
  return content(result).filter((c) => c.type === "resource_link")
}

// Every resource_link in a result points at the ask in structuredContent (or
// at one of the pending asks): the uri is ask.url and nothing else.
function expectLinksMatchAsks(result: Record<string, unknown>): void {
  const structured = result.structuredContent as { ask?: { url: string; title: string; what: string; check: { label: string; value: string } | null }; pending?: { url: string }[] }
  const asks = structured.ask ? [structured.ask] : (structured.pending ?? [])
  const links = resourceLinks(result)
  expect(links.map((l) => l.uri)).toEqual(asks.map((a) => a.url))
  for (const link of links) expect(link).toMatchObject({ type: "resource_link", mimeType: "text/html" })
  if (structured.ask) {
    const check = structured.ask.check ? ` (${structured.ask.check.label} ${structured.ask.check.value})` : ""
    expect(links[0]).toEqual({ type: "resource_link", uri: structured.ask.url, name: `${structured.ask.title}${check}`, description: structured.ask.what, mimeType: "text/html" })
  }
}

const by = { device: "test-box", session: "pi-1" }
const inMinutes = (n: number) => new Date(Date.now() + n * 60_000).toISOString()
const vaultLink = (path: string): AskUrl => (askUrl(`${vault.url}/w/mock-space${path}`, vault.askVault()) as { url: AskUrl }).url

function googleClient(slug: string, account: string | null = null) {
  return item(slug, { kind: "oauth-client", provider: "google-oauth-client", account, hosts: ["oauth2.googleapis.com"] })
}

describe("mehen mcp protocol", () => {
  test("initialize, notifications/initialized, ping", async () => {
    const init = await mcp.request("initialize", { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "test", version: "1" } })
    expect(init.result).toMatchObject({ protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "mehen" } })
    const instructions = init.result?.instructions as string
    expect(instructions).toStartWith("Mehen lets you use credentials without reading them. Start with vault_status.")
    expect(instructions).toContain("never ask a human to paste a value into the chat")
    expect(instructions).toContain("give the human the `ask`")
    expect(instructions).toContain("never open the link yourself")
    expect(instructions).toContain("nothing you send can approve anything")
    expect(instructions).toContain("when vault_status says it is not enrolled and you cannot run commands, ask the human to run its next.command in a terminal")
    expect(instructions).toContain("with `next.arguments` to add to the call (keep the call's other arguments when it is the tool you called")
    expect(instructions).toContain("a `next.command` without `next.tool` only the mehen command line runs: if you cannot run commands, ask the human to run it in a terminal")
    mcp.send(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }))
    const ping = await mcp.request("ping")
    expect(ping.result).toEqual({})
    // The notification produced no reply.
    expect(mcp.received.filter((m) => m.id === undefined || m.id === null)).toHaveLength(0)
  })

  test("initialize answers with the revision the host asked for when it is one this server speaks, else the latest", async () => {
    const asked = async (protocolVersion: string) => (await mcp.request("initialize", { protocolVersion, capabilities: {}, clientInfo: { name: "test", version: "1" } })).result?.protocolVersion
    expect(await asked("2025-06-18")).toBe("2025-06-18")
    expect(await asked("2025-03-26")).toBe("2025-03-26")
    expect(await asked("2024-11-05")).toBe("2024-11-05")
    expect(await asked("2099-01-01")).toBe(MCP_PROTOCOL_VERSION)
  })

  test("tools/list has the vault tools with JSON Schema inputs and the right required fields", async () => {
    const list = await mcp.request("tools/list")
    const tools = list.result?.tools as { name: string; description: string; inputSchema: { type: string; properties: Record<string, unknown>; required?: string[] } }[]
    expect(tools.map((t) => t.name)).toEqual(["vault_status", "vault_doctor", "vault_templates", "vault_list", "vault_show", "vault_check", "vault_request", "vault_connect", "vault_fetch", "vault_plan", "vault_fill", "vault_push", "vault_env", "vault_wait", "vault_pending", "vault_policy", "vault_mandate", "vault_adopt_scan", "vault_adopt_status"])
    for (const tool of tools) expect(tool.inputSchema.type).toBe("object")
    const required = (name: string) => tools.find((t) => t.name === name)?.inputSchema.required ?? []
    expect(required("vault_status")).toEqual([])
    expect(required("vault_doctor")).toEqual([])
    expect(required("vault_templates")).toEqual([])
    expect(required("vault_check")).toEqual(["item", "method", "url"])
    expect(required("vault_request")).toEqual(["kind", "name", "reason"])
    // client is optional now: the one matching client is picked.
    expect(required("vault_connect")).toEqual(["provider", "name", "reason"])
    expect(Object.keys(tools.find((t) => t.name === "vault_connect")?.inputSchema.properties ?? {})).toContain("requestClient")
    expect(required("vault_fetch")).toEqual(["method", "url"])
    expect(required("vault_wait")).toEqual(["id"])
    expect(required("vault_pending")).toEqual([])
    // No tool approves, enrols, revokes or freezes, and none opens a link.
    expect(tools.map((t) => t.name).filter((n) => /approve|enrol|revoke|freeze|open/.test(n))).toEqual([])
    for (const tool of tools) expect(tool.description).not.toMatch(/\bapproves?\b.*\bfor you\b/)
    expect(tools.find((t) => t.name === "vault_wait")?.description).toContain("enr_")
    expect(tools.find((t) => t.name === "vault_fetch")?.description).toContain("Any upstream status is a success here")
  })

  test("unknown method, unknown tool and bad JSON are JSON-RPC errors", async () => {
    expect((await mcp.request("resources/list")).error?.code).toBe(-32601)
    expect((await mcp.request("tools/call", { name: "vault_reveal", arguments: {} })).error?.code).toBe(-32602)
    const parse = mcp.expectReply(null)
    mcp.send("{not json")
    expect((await parse).error?.code).toBe(-32700)
  })

  test("exits when stdin closes", async () => {
    await mcp.request("ping")
    expect(await mcp.close()).toBe(0)
  })
})

describe("mehen mcp tools", () => {
  test("a tool call before enrolment is a tool error saying to enrol", async () => {
    const result = await callTool("vault_list", {})
    expect(result.isError).toBe(true)
    expect(result.structuredContent).toMatchObject({ error: "unauthenticated", next: { command: "mehen enrol --workspace <slug> --json" } })
    expect(text(result)).toContain("mehen enrol")
    expect(resourceLinks(result)).toEqual([])
  })

  test("vault_status before enrolment is not an error: enrolled false and the enrol command", async () => {
    const before = vault.seen.length
    const result = await callTool("vault_status", {})
    expect(result.isError).toBe(false)
    // StatusAll: no active entry, and next is the enrol step.
    expect(result.structuredContent).toMatchObject({ home: dir.path, allowed: null, workspaces: [], selected: null, next: { command: "mehen enrol --workspace <slug> --json", say: "Run `mehen enrol --workspace <slug> --json` on this machine (the slug is on the workspace's Connect an agent page) and accept it in the browser with your passkey. If you cannot run commands, ask the human to run this in a terminal and open the link it prints." } })
    expect(Object.keys(result.structuredContent as object).sort()).toEqual(["allowed", "cli", "home", "next", "selected", "workspaces"])
    expect(JSON.parse(text(result))).toEqual(result.structuredContent)
    // Nothing was sent: an unenrolled machine has no proof to send.
    expect(vault.seen.length).toBe(before)
  })

  test("vault_status after enrolment reports the device, fingerprint, session and pending count", async () => {
    await vault.enrolSoftware(dir.path, { fingerprint: "ZLSQ 8ZY0 FNHK WLS5" })
    await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask: approvalAsk({ id: "apr_7Hq2", url: vaultLink("/a/apr_7Hq2"), summary: "Send", bindingCode: "K7Q2MX", expiresAt: inMinutes(50), requestedBy: by }) })
    const result = await callTool("vault_status", {})
    expect(result.isError).toBe(false)
    const structured = result.structuredContent as { selected: string; next: unknown; workspaces: { state: string; check: { ok: boolean; status: Record<string, unknown> } }[] }
    expect(structured).toMatchObject({ selected: vault.slotDir(dir.path), next: null, workspaces: [{ state: "active", slot: vault.slotDir(dir.path), origin: vault.url, workspace: { id: MOCK_TENANT, slug: MOCK_WORKSPACE.slug, name: MOCK_WORKSPACE.name } }] })
    const [entry] = structured.workspaces
    expect(entry?.check).toMatchObject({ ok: true, status: { vault: vault.url, tenant: MOCK_TENANT, workspace: MOCK_WORKSPACE, owner: MOCK_OWNER, slot: vault.slotDir(dir.path), name: "test-machine", backend: "software", fingerprint: "ZLSQ 8ZY0 FNHK WLS5", session: "mcp-test", frozen: false, pending: 1 } })
    expect(Object.keys(entry?.check.status ?? {}).sort()).toEqual(["backend", "device", "fingerprint", "fingerprintFrom", "frozen", "name", "owner", "pending", "policyState", "scope", "session", "slot", "tenant", "vault", "workspace"])
  })

  test("vault_doctor answers before enrolment as a success with ok false and the enrol step, and after it with every check passing", async () => {
    // A PATH with no agent on it: the skill rows find nothing to warn about.
    mcp = new McpClient({ MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url, MEHEN_SESSION: "mcp-test", PATH: "/usr/bin:/bin" })
    const before = await callTool("vault_doctor", {})
    expect(before.isError).toBe(false)
    expect(before.structuredContent).toMatchObject({ ok: false, next: { command: "mehen enrol --workspace <slug> --json" } })
    // An enrolment made after the server started is picked up and latched on first use: no restart.
    await vault.enrolSoftware(dir.path)
    const after = await callTool("vault_doctor", {})
    expect(after.structuredContent).toMatchObject({ ok: true, exitCode: 0, next: null, workspaces: [{ state: "active", slot: vault.slotDir(dir.path) }] })
    const report = after.structuredContent as { machine: { check: string; status: string }[]; origins: { checks: { check: string; status: string }[] }[]; session: { check: string; status: string }; workspaces: { checks: { check: string; status: string }[] }[] }
    const checks = [...report.machine, ...report.origins.flatMap((o) => o.checks), report.session, ...report.workspaces.flatMap((w) => w.checks)]
    expect(checks.length).toBeGreaterThan(5)
    // A run from source installs nothing: its on_path and update rows are skipped.
    expect(checks.filter((c) => c.status !== "ok").map(({ check, status }) => ({ check, status }))).toEqual([{ check: "on_path", status: "skipped" }, { check: "update", status: "skipped" }])
    expect(report.machine.filter((c) => c.check === "skill").map((c) => c.status)).toEqual(["ok", "ok"])
  })

  test("vault_templates lists every template and OAuth provider by id and title, needs no enrolment and sends nothing", async () => {
    const before = vault.seen.length
    const all = await callTool("vault_templates", {})
    expect(all.isError).toBe(false)
    expect(text(all).length).toBeLessThan(10_000)
    const listed = all.structuredContent as { templates: Record<string, unknown>[]; oauthProviders: Record<string, unknown>[] }
    expect(listed.templates.map((t) => t.id)).toEqual(Object.keys(TEMPLATES))
    expect(listed.oauthProviders.map((p) => p.id)).toEqual(Object.keys(OAUTH_PROVIDERS))
    expect(listed.templates[0]).toEqual({ id: "openai", title: TEMPLATES.openai?.displayName, category: "ai", kind: "api-key", hosts: ["api.openai.com"] })
    expect(listed.oauthProviders.find((p) => p.id === "google-gmail")).toEqual({ id: "google-gmail", title: OAUTH_PROVIDERS["google-gmail"]?.displayName, category: OAUTH_PROVIDERS["google-gmail"]?.category, clientTemplate: "google-oauth-client", hosts: OAUTH_PROVIDERS["google-gmail"]?.upstream.binding.hosts })
    expect(listed.oauthProviders.find((p) => p.id === "google-gmail")?.hosts).toEqual(["gmail.googleapis.com"])
    const one = await callTool("vault_templates", { id: "google-gmail" })
    expect(one.structuredContent).toMatchObject({ type: "oauth-provider", id: "google-gmail", clientTemplate: "google-oauth-client", redirectUri: `${vault.url}/oauth/callback`, policySummary: { allowed: expect.any(Array), approve: expect.any(Array), deny: expect.any(Array) } })
    const client = await callTool("vault_templates", { id: "google-oauth-client" })
    expect(client.structuredContent).toMatchObject({ type: "template", id: "google-oauth-client", kind: "oauth-client", redirectUri: `${vault.url}/oauth/callback` })
    const unknown = await callTool("vault_templates", { id: "nope" })
    expect(unknown.isError).toBe(true)
    expect(unknown.structuredContent).toMatchObject({ error: "not_found", next: { say: "List the templates and providers with vault_templates and use an id from there." } })
    expect(vault.seen.length).toBe(before)
  })

  test("a tool error's next names the tool, never a mehen command a model without a shell cannot run", async () => {
    await vault.enrolSoftware(dir.path)
    const schema = { say: "Fix the arguments to match the tool's input schema." }
    const template = await callTool("vault_templates", { id: "nope" })
    expect((template.structuredContent as { next: unknown }).next).toEqual({ say: "List the templates and providers with vault_templates and use an id from there.", tool: "vault_templates" })
    expect(text(template)).toBe('not_found: No template or OAuth provider is called "nope".\nnext: List the templates and providers with vault_templates and use an id from there.\n  call: vault_templates')
    const wait = await callTool("vault_wait", { id: "foo" })
    expect(wait.structuredContent).toMatchObject({ error: "usage", next: schema })
    expect((wait.structuredContent as { next: Record<string, unknown> }).next.command).toBeUndefined()
    const provider = await callTool("vault_connect", { provider: "nope", client: "google-oauth-client", name: "gmail-alex", reason: "triage" })
    expect(provider.structuredContent).toMatchObject({ error: "usage", next: { say: "List the templates and providers with vault_templates and use an id from there." } })
    const home = await callTool("vault_request", { kind: "api-key", name: "openai", reason: "tests", home: "project" })
    expect(home.structuredContent).toMatchObject({ error: "usage", next: schema })
    for (const result of [template, wait, provider, home]) expect(text(result)).not.toContain("mehen ")
  })

  test("a vault refusal's next names the tool that does its step, and keeps a command only the command line runs", async () => {
    await vault.enrolSoftware(dir.path)
    const missing = await callTool("vault_show", { item: "nope" })
    expect((missing.structuredContent as { next: unknown }).next).toEqual({ say: "List the items.", tool: "vault_list" })
    expect(text(missing)).toEndWith("next: List the items.\n  call: vault_list")
    expect(text(missing)).not.toContain("mehen ")
    vault.overrides.set("GET /v1/items", () => vaultError("cli_outdated", "Too old.", { next: { command: "mehen update", say: "Update mehen." } }))
    const outdated = await callTool("vault_list", {})
    expect((outdated.structuredContent as { next: unknown }).next).toEqual({ command: "mehen update", say: "Update mehen." })
    expect(text(outdated)).toEndWith("next: Update mehen.\n  run:  mehen update")
  })

  test("vault_check says allow, approve, refuse or outside the binding, and never sends the request", async () => {
    await vault.enrolSoftware(dir.path)
    vault.items.push(item("gmail-ish", { binding: { hosts: ["api.example.com"], paths: ["/v1/**"] }, policy: { default: "approve", rules: [{ methods: ["GET"], action: "allow", note: "read" }, { methods: ["DELETE"], action: "deny", note: "never delete" }] } }))
    try {
      const before = vault.seen.length
      const allowed = await callTool("vault_check", { item: "gmail-ish", method: "GET", url: "https://api.example.com/v1/things", headers: { accept: "application/json" } })
      expect(allowed.isError).toBe(false)
      expect(allowed.structuredContent).toEqual({ item: "gmail-ish", method: "GET", url: "https://api.example.com/v1/things", decision: "allow", matched: [{ action: "allow", note: "read" }], reason: null, bodyUnknown: false, advisory: true, scope: "base-policy-only" })
      const approve = await callTool("vault_check", { item: "gmail-ish", method: "POST", url: "https://api.example.com/v1/things", body: "{}" })
      expect(approve.structuredContent).toMatchObject({ decision: "approve", matched: [], advisory: true })
      const deny = await callTool("vault_check", { item: "gmail-ish", method: "DELETE", url: "https://api.example.com/v1/things/1" })
      expect(deny.structuredContent).toMatchObject({ decision: "deny", matched: [{ action: "deny", note: "never delete" }] })
      const outside = await callTool("vault_check", { item: "gmail-ish", method: "GET", url: "https://evil.example/v1/things" })
      expect(outside.structuredContent).toMatchObject({ decision: "binding_refused", reason: "host evil.example is not api.example.com" })
      // Four checks, four item reads, nothing relayed and no approval made.
      const calls = vault.seen.slice(before)
      expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(Array<string>(4).fill("GET /v1/items/gmail-ish"))
      expect(calls.some((c) => c.path === "/v1/relay" || c.method === "POST")).toBe(false)
      const bad = await callTool("vault_check", { item: "gmail-ish", method: "GET", url: "not a url" })
      expect(bad.isError).toBe(true)
      expect(bad.structuredContent).toMatchObject({ error: "usage" })
    } finally {
      vault.items.pop()
    }
  })

  test("vault_list and vault_show return metadata", async () => {
    await vault.enrolSoftware(dir.path)
    const list = await callTool("vault_list", { tag: "ai" })
    expect(list.isError).toBe(false)
    expect((list.structuredContent as { items: { slug: string }[] }).items.map((i) => i.slug)).toEqual(["openai-personal"])
    const show = await callTool("vault_show", { item: "openai-personal" })
    expect(show.structuredContent).toMatchObject({ slug: "openai-personal", binding: { hosts: ["api.openai.com"] }, policySummary: { allowed: [], approve: [], deny: [], rest: "allowed" } })
    expect(JSON.parse(text(show))).toMatchObject({ slug: "openai-personal" })
    expect(JSON.stringify(list)).not.toContain("sk-")
  })

  test("vault_list answers a few hundred items in compact rows a page at a time, well under a host's 50,000-character limit", async () => {
    await vault.enrolSoftware(dir.path)
    const added = Array.from({ length: 300 }, (_, i) =>
      i % 4 === 0
        ? item(`lease-only-secret-${i}`, { kind: "generic", provider: null, tags: ["ops"], hosts: [LEASE_ONLY_HOST] })
        : item(`service-credential-${i}`, { account: `team-account-${i}@example.com`, accountVerified: true, tags: ["ai", "prod"] }),
    )
    vault.items.push(...added)
    try {
      const first = await callTool("vault_list", {})
      expect(first.isError).toBe(false)
      expect(text(first).length).toBeLessThan(20_000)
      expect(JSON.parse(text(first))).toEqual(first.structuredContent)
      const page = first.structuredContent as { items: Record<string, unknown>[]; total: number; nextOffset?: number }
      expect(page).toMatchObject({ total: 302, nextOffset: 100 })
      expect(page.items).toHaveLength(100)
      expect(page).toMatchObject({ workspaces: [MOCK_WORKSPACE] })
      expect(page.items[0]).toEqual({ slug: "openai-personal", workspace: MOCK_TENANT, kind: "api-key", provider: "openai", status: "active", ceiling: "placeholder", hosts: ["api.openai.com"] })
      expect(page.items.find((i) => i.slug === "lease-only-secret-0")).toEqual({ slug: "lease-only-secret-0", workspace: MOCK_TENANT, kind: "generic", status: "active", ceiling: "placeholder", hosts: [], leaseOnly: true })
      const last = (await callTool("vault_list", { offset: 300 })).structuredContent as { items: { slug: string }[]; nextOffset?: number }
      expect(last.items.map((i) => i.slug)).toEqual(["service-credential-298", "service-credential-299"])
      expect(last.nextOffset).toBeUndefined()
      const found = (await callTool("vault_list", { search: "ACCOUNT-7@", limit: 5 })).structuredContent as { items: { slug: string; account: string }[]; total: number }
      expect(found).toMatchObject({ total: 1, items: [{ slug: "service-credential-7", account: "team-account-7@example.com" }] })
    } finally {
      vault.items.splice(-added.length)
    }
  })

  test("vault_show's policySummary describes an item's rules from their matchers, never from their notes", async () => {
    await vault.enrolSoftware(dir.path)
    vault.items.push(item("tricky", { policy: { default: "deny", rules: [{ methods: ["POST"], paths: ["/v1/send"], action: "approve", note: "read only, harmless" }] } }))
    try {
      const show = await callTool("vault_show", { item: "tricky" })
      const summary = (show.structuredContent as { policySummary: { allowed: string[]; approve: string[]; deny: string[]; rest: string } }).policySummary
      expect(summary).toEqual({ allowed: [], approve: ["POST on /v1/send"], deny: [], rest: "deny" })
      expect(JSON.stringify(summary)).not.toContain("harmless")
    } finally {
      vault.items.pop()
    }
  })

  test("a successful result's text is spelled out for a human while structuredContent stays the raw result", async () => {
    await vault.enrolSoftware(dir.path)
    vault.items.push(item("odd-item", { description: "reads\u202e mail\u001b[2K and more\uFFFE[31m" }))
    try {
      const show = await callTool("vault_show", { item: "odd-item" })
      expect(show.isError).toBe(false)
      expect((show.structuredContent as { description: string }).description).toBe("reads\u202e mail\u001b[2K and more\uFFFE[31m")
      const shown = text(show)
      expect(shown).not.toContain("\u202e")
      expect(shown).not.toContain("\u001b")
      expect(shown).not.toContain("\uFFFE")
      // JSON.stringify had already escaped the control character; visibleText spelled the rest.
      expect(shown).toContain("reads[RLO U+202E] mail\\u001b[2K and more[NONCHAR U+FFFE][31m")
      // Still JSON a host can parse: the line breaks are its own.
      expect(JSON.parse(shown)).toMatchObject({ slug: "odd-item" })
    } finally {
      vault.items.pop()
    }
  })

  test("vault_request returns the ask, a resource_link to it, next with the session label, and records the ledger", async () => {
    await vault.enrolSoftware(dir.path)
    const result = await callTool("vault_request", { kind: "api-key", name: "openai-new", reason: "summarise mail", provider: "openai" })
    expect(result.isError).toBe(false)
    const out = result.structuredContent as { intake: string; url: string; kind: string; name: string; provider: string; ask: Record<string, unknown>; next: { url: string; command: string; say: string } }
    expect(out).toMatchObject({ kind: "api-key", name: "openai-new", provider: "openai", url: `${vault.url}/w/mock-space/i/${out.intake}` })
    expect(out.ask).toMatchObject({ kind: "intake", id: out.intake, url: out.url, title: "Add a credential", what: "Add openai-new (OpenAI API key, goes to api.openai.com) so the agent can summarise mail", check: { label: "asked by" }, expiresAt: MOCK_EXPIRES_AT, requestedBy: { session: "mcp-test" }, wait: `mehen wait ${out.intake} --timeout 60 --json` })
    expect(out.next).toMatchObject({ url: out.url, command: `mehen wait ${out.intake} --timeout 60 --json` })
    expect(JSON.parse(vault.seen.at(-1)?.body ?? "{}")).toMatchObject({ session: "mcp-test" })
    // content: the ask block with the MCP then: line, then the resource_link.
    expectLinksMatchAsks(result)
    const lines = text(result).split("\n")
    expect(lines[0]).toBe("Human needed: add a credential")
    expect(lines[1]).toBe(`  open:    ${out.url}`)
    expect(lines[2]).toBe("  what:    Add openai-new (OpenAI API key, goes to api.openai.com) so the agent can summarise mail")
    expect(lines.at(-1)).toBe(`  then:    vault_wait { "id": "${out.intake}" }`)
    expect(text(result)).not.toContain("mehen wait")
    // The ask is in this machine's ledger, so mehen pending and vault_pending see it.
    const ledger = await readLedger(vault.slotDir(dir.path), scope())
    expect(ledger.map((e) => [e.ask.id, e.slug, e.command])).toEqual([[out.intake, "openai-new", "mehen request api-key --name openai-new --provider openai --reason 'summarise mail' --home private"]])
  })

  test("vault_pending lists what this machine has open, with a resource_link per ask, before and after enrolment", async () => {
    const empty = await callTool("vault_pending", {})
    expect(empty.isError).toBe(false)
    expect(empty.structuredContent).toEqual({ pending: [] })
    expect(resourceLinks(empty)).toEqual([])
    // An enrolment made after the server started is served by the same server.
    await vault.enrolSoftware(dir.path)
    await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask: approvalAsk({ id: "apr_7Hq2", url: vaultLink("/a/apr_7Hq2"), summary: "Send an email to sam@example.com", item: "gmail-alex", bindingCode: "K7Q2MX", expiresAt: inMinutes(50), requestedBy: by }) })
    const made = await callTool("vault_request", { kind: "api-key", name: "openai-new", reason: "summarise mail", provider: "openai" })
    const intake = (made.structuredContent as { intake: string }).intake
    const result = await callTool("vault_pending", {})
    expect(result.isError).toBe(false)
    const pending = (result.structuredContent as { pending: { id: string; kind: string }[] }).pending
    expect(pending.map((a) => [a.kind, a.id])).toEqual([["approval", "apr_7Hq2"], ["intake", intake]])
    expectLinksMatchAsks(result)
    expect(text(result)).toContain("Human needed: approve a request")
    expect(text(result)).toContain('  then:    vault_wait { "id": "apr_7Hq2" }')
    expect(text(result)).toContain(`  then:    vault_wait { "id": "${intake}" }`)
    // The vault's own list is merged in when the server has it.
    vault.pending = [{ kind: "connect", id: "con_srv", url: `${vault.url}/w/mock-space/c/con_srv`, title: "Connect gmail-work to Gmail", expiresAt: null, requestedBy: { device: "d", deviceName: "sam-mac-mini", session: "pi-4f2a" }, item: "gmail-work", provider: "google-gmail", account: "work@example.com" }]
    try {
      const merged = await callTool("vault_pending", {})
      const all = (merged.structuredContent as { pending: { id: string; requestedBy: unknown }[] }).pending
      expect(all.map((a) => a.id)).toEqual(["con_srv", "apr_7Hq2", intake])
      expect(all[0]?.requestedBy).toEqual({ device: "sam-mac-mini", session: "pi-4f2a" })
      expectLinksMatchAsks(merged)
    } finally {
      vault.pending = null
    }
  })

  test("vault_pending renders the own workspace projection and machine notice, not foreign, stop or unknown entries", async () => {
    await vault.enrolSoftware(dir.path)
    const fixture = pendingWorkspaceFixtures(vault.url, MOCK_WORKSPACE, vault.lastDevice!, MOCK_OWNER)
    vault.overrides.set("GET /v1/pending", () => Response.json({ pending: fixture.pending, notices: [fixture.machine, { ...fixture.machine, payload: { ...fixture.machine.payload, device: "dev_foreign" } }] }))
    try {
      const result = await callTool("vault_pending", {})
      const expected = withContext(intakeAsk({ id: "int_workspace", url: vaultLink("/i/int_workspace"), name: "workspace-key", kind: "api-key", provider: "openai", reason: null, expiresAt: "2030-01-01T00:00:00.000Z", requestedBy: { device: "workspace-machine", session: null } }), { origin: vault.url, workspace: MOCK_WORKSPACE, device: vault.lastDevice! })
      expect(result.isError).toBe(false)
      expect(result.structuredContent).toEqual({ pending: [expected], notices: [fixture.machine] })
      expect(text(result)).toContain(`Machine added on 2026-10-27: this machine, workspace-machine (${vault.lastDevice}), in Mock Space (mock-space) at ${vault.url}. Open ${fixture.machine.url} to review it.`)
      expect(text(result)).not.toMatch(/foreign|int_stopped|unknown|int_other|dev_other/)
      expectLinksMatchAsks(result)
      expect(resourceLinks(result)).toHaveLength(1)
    } finally { vault.overrides.clear() }
  })

  test("vault_request proposes hosts, paths and an injection for a credential without a template", async () => {
    await vault.enrolSoftware(dir.path)
    const injection = { in: "header", name: "X-Api-Key", format: "{key}" }
    const result = await callTool("vault_request", { kind: "api-key", name: "acme-key", reason: "call Acme", hosts: ["api.acme.test"], paths: ["/v2/**"], injection })
    expect(result.isError).toBe(false)
    expect(JSON.parse(vault.seen.at(-1)?.body ?? "{}")).toMatchObject({ binding: { hosts: ["api.acme.test"], paths: ["/v2/**"] }, injection })
    const bad = await callTool("vault_request", { kind: "api-key", name: "acme-key", reason: "r", hosts: ["api.acme.test"], injection: { in: "header", name: "X" } })
    expect(bad.isError).toBe(true)
  })

  test("vault_request and vault_connect take new, as mehen request --new and mehen connect --new, and send fresh only then", async () => {
    await vault.enrolSoftware(dir.path)
    await callTool("vault_request", { kind: "api-key", name: "openai-new", reason: "summarise mail", provider: "openai", new: true })
    expect(JSON.parse(vault.seen.at(-1)?.body ?? "{}")).toMatchObject({ slug: "openai-new", fresh: true })
    await callTool("vault_request", { kind: "api-key", name: "openai-new", reason: "summarise mail", provider: "openai" })
    expect(JSON.parse(vault.seen.at(-1)?.body ?? "{}")).not.toHaveProperty("fresh")
    await callTool("vault_connect", { provider: "google-gmail", client: "google-oauth-client", name: "gmail-alex", reason: "drafts", new: true })
    expect(JSON.parse([...vault.seen].reverse().find((r) => r.path === "/v1/connect")?.body ?? "{}")).toMatchObject({ fresh: true })
  })

  test("vault_list and vault_show carry the review flag", async () => {
    await vault.enrolSoftware(dir.path)
    const review = { reason: "an upstream echoed its value back", since: "2026-10-23T10:00:00.000Z" }
    vault.items.push({ ...vault.items[0], slug: "echoed-key", review } as (typeof vault.items)[number])
    try {
      const list = await callTool("vault_list", {})
      expect((list.structuredContent as { items: { slug: string; review?: unknown }[] }).items.find((i) => i.slug === "echoed-key")?.review).toEqual(review)
      const show = await callTool("vault_show", { item: "echoed-key" })
      expect((show.structuredContent as { review?: unknown }).review).toEqual(review)
    } finally {
      vault.items.pop()
    }
  })

  test("vault_connect with a named client returns the ask and a resource_link to it", async () => {
    await vault.enrolSoftware(dir.path)
    const before = vault.seen.length
    const result = await callTool("vault_connect", { provider: "google-gmail", client: "google-client", name: "gmail-alex", reason: "triage", expect: "alex@example.com" })
    expect(result.isError).toBe(false)
    const out = result.structuredContent as { connect: string; url: string; client: string; account: string; ask: Record<string, unknown>; next: Record<string, unknown> }
    expect(out.connect).toStartWith("con_")
    expect(out).toMatchObject({ provider: "google-gmail", client: "google-client", name: "gmail-alex", account: "alex@example.com", url: `${vault.url}/w/mock-space/c/${out.connect}` })
    expect(out.ask).toMatchObject({ kind: "connect", id: out.connect, url: out.url, title: "Connect an account", what: "Connect gmail-alex to Gmail as alex@example.com so the agent can triage", check: { label: "account", value: "alex@example.com" } })
    expect(out.next).toMatchObject({ url: out.url, command: `mehen wait ${out.connect} --timeout 60 --json` })
    expectLinksMatchAsks(result)
    expect(resourceLinks(result)[0]?.name).toBe("Connect an account (account alex@example.com)")
    // The client was named, so no listing was needed.
    expect(vault.seen.slice(before).map((c) => c.path)).toEqual(["/v1/connect"])
    expect((await readLedger(vault.slotDir(dir.path), scope())).map((e) => e.ask.id)).toEqual([out.connect])
  })

  test("vault_connect without a client picks the one client made from the provider's client template", async () => {
    await vault.enrolSoftware(dir.path)
    vault.items.push(googleClient("google-oauth-work", "work@example.com"), item("github-app", { kind: "oauth-client", provider: "github-oauth-app" }))
    try {
      const before = vault.seen.length
      const result = await callTool("vault_connect", { provider: "google-gmail", name: "gmail-alex", reason: "triage" })
      expect(result.isError).toBe(false)
      expect(result.structuredContent).toMatchObject({ client: "google-oauth-work" })
      const calls = vault.seen.slice(before)
      expect(`${calls[0]?.path}${calls[0]?.search}`).toBe("/v1/items?kind=oauth-client&provider=google-oauth-client")
      expect(calls[1]?.path).toBe("/v1/connect")
      expect(JSON.parse(calls[1]?.body ?? "{}")).toMatchObject({ client: "google-oauth-work", slug: "gmail-alex" })
    } finally {
      vault.items.splice(-2)
    }
  })

  test("vault_connect with several matching clients is a usage error that lists them and creates nothing", async () => {
    await vault.enrolSoftware(dir.path)
    vault.items.push(googleClient("google-oauth-client"), googleClient("google-oauth-work", "work@example.com"))
    try {
      const before = vault.seen.length
      const result = await callTool("vault_connect", { provider: "google-gmail", name: "gmail-alex", reason: "triage" })
      expect(result.isError).toBe(true)
      expect(result.structuredContent).toMatchObject({ error: "usage", choices: [{ slug: "google-oauth-client", account: null }, { slug: "google-oauth-work", account: "work@example.com" }] })
      expect(vault.seen.slice(before).every((c) => c.path !== "/v1/connect")).toBe(true)
    } finally {
      vault.items.splice(-2)
    }
  })

  test("vault_connect with no client at all is client_missing with the exact vault_request arguments and the setup, and no link", async () => {
    await vault.enrolSoftware(dir.path)
    const before = vault.seen.length
    const result = await callTool("vault_connect", { provider: "google-gmail", name: "gmail-alex", reason: "triage", expect: "alex@example.com" })
    expect(result.isError).toBe(true)
    const out = result.structuredContent as { error: string; message: string; request: Record<string, string>; setup: Record<string, unknown>; next: { command?: string; url?: string; say: string }; ask?: unknown }
    expect(out.error).toBe("client_missing")
    expect(out.message).toBe("No Google OAuth client is in the vault yet; a Gmail connection needs one (template google-oauth-client).")
    expect(out.request).toEqual({ kind: "oauth-client", name: "google-oauth-client", provider: "google-oauth-client", reason: "connect Gmail as alex@example.com: triage" })
    expect(out.setup).toEqual({ redirectUri: `${vault.url}/oauth/callback`, docsUrl: "https://console.cloud.google.com/apis/credentials" })
    // The request object is the step: vault_request does it, so no command goes with it.
    expect(out.next.command).toBeUndefined()
    expect(out.next).toMatchObject({ tool: "vault_request", say: "Ask the human for a Google OAuth client first, then run this command again; or repeat it with `requestClient` to ask for both at once." })
    expect(out.next.url).toBeUndefined()
    expect(out.ask).toBeUndefined()
    expect(resourceLinks(result)).toEqual([])
    expect(vault.seen.slice(before).map((c) => c.path)).toEqual(["/v1/items"])
    // The request object is exactly what vault_request takes.
    const made = await callTool("vault_request", out.request)
    expect(made.isError).toBe(false)
    expect(JSON.parse(vault.seen.at(-1)?.body ?? "{}")).toEqual({ kind: "oauth-client", slug: "google-oauth-client", provider: "google-oauth-client", reason: "connect Gmail as alex@example.com: triage", session: "mcp-test", home: "private" })
  })

  test("vault_connect with requestClient returns the chained client intake's ask as step client, then the connect on a second call", async () => {
    await vault.enrolSoftware(dir.path)
    vault.overrides.set("POST /v1/connect", (_request, seen) => {
      const body = JSON.parse(seen.body) as { client?: string; requestClient?: boolean }
      const base = { connect: "con_chain", url: `${vault.url}/w/mock-space/c/con_chain`, expiresAt: MOCK_EXPIRES_AT }
      if (body.requestClient && !body.client && !vault.items.some((i) => i.kind === "oauth-client")) {
        return Response.json({ ...base, intake: { intake: "int_client", url: `${vault.url}/w/mock-space/i/int_client`, expiresAt: MOCK_EXPIRES_AT } })
      }
      return Response.json(base)
    })
    const first = await callTool("vault_connect", { provider: "google-gmail", name: "gmail-alex", reason: "triage", expect: "alex@example.com", requestClient: true })
    expect(first.isError).toBe(false)
    expect(JSON.parse(vault.seen.at(-1)?.body ?? "{}")).toEqual({ provider: "google-gmail", slug: "gmail-alex", expect: "alex@example.com", reason: "triage", session: "mcp-test", requestClient: true, home: "private" })
    const step = first.structuredContent as { step: string; intake: string; url: string; connect: string; client: string; ask: Record<string, unknown>; next: { command: string }; then: string }
    expect(step).toMatchObject({ step: "client", intake: "int_client", url: `${vault.url}/w/mock-space/i/int_client`, connect: "con_chain", client: "google-oauth-client", name: "gmail-alex" })
    expect(step.ask).toMatchObject({ kind: "intake", id: "int_client", what: `Add google-oauth-client (Google OAuth client, redirect URI ${vault.url}/oauth/callback) so the agent can connect Gmail as alex@example.com: triage` })
    expect(step.then).toContain("call vault_connect again")
    expectLinksMatchAsks(first)
    expect(text(first)).toContain('  then:    vault_wait { "id": "int_client" }, then vault_connect again with the same arguments')
    expect((await readLedger(vault.slotDir(dir.path), scope())).map((e) => e.ask.id)).toEqual(["con_chain", "int_client"])
    // The client is saved; the same call now picks it and returns the connect ask.
    vault.items.push(googleClient("google-oauth-client"))
    try {
      const second = await callTool("vault_connect", { provider: "google-gmail", name: "gmail-alex", reason: "triage", expect: "alex@example.com", requestClient: true })
      expect(second.isError).toBe(false)
      expect(second.structuredContent).toMatchObject({ connect: "con_chain", client: "google-oauth-client", ask: { kind: "connect", id: "con_chain" } })
      expect((second.structuredContent as { step?: string }).step).toBeUndefined()
      expectLinksMatchAsks(second)
      expect(JSON.parse(vault.seen.at(-1)?.body ?? "{}")).toMatchObject({ client: "google-oauth-client" })
      expect(JSON.parse(vault.seen.at(-1)?.body ?? "{}").requestClient).toBeUndefined()
    } finally {
      vault.items.pop()
      vault.overrides.clear()
    }
  })

  test("vault_connect passes clientTags to a chained client intake, so a tag-scoped machine can use the client", async () => {
    await vault.enrolSoftware(dir.path)
    vault.overrides.set("POST /v1/connect", () =>
      Response.json({ connect: "con_tags", url: `${vault.url}/w/mock-space/c/con_tags`, expiresAt: MOCK_EXPIRES_AT, intake: { intake: "int_tags", url: `${vault.url}/w/mock-space/i/int_tags`, expiresAt: MOCK_EXPIRES_AT } }),
    )
    try {
      const result = await callTool("vault_connect", { provider: "google-gmail", name: "gmail-alex", reason: "triage", requestClient: true, clientTags: ["code", "home"] })
      expect(result.isError).toBe(false)
      expect(JSON.parse(vault.seen.at(-1)?.body ?? "{}")).toMatchObject({ requestClient: true, clientTags: ["code", "home"] })
      // Without clientTags the body carries none, as before.
      await callTool("vault_connect", { provider: "google-gmail", name: "gmail-alex", reason: "triage", requestClient: true })
      expect(JSON.parse(vault.seen.at(-1)?.body ?? "{}").clientTags).toBeUndefined()
    } finally {
      vault.overrides.clear()
    }
  })

  test("invalid arguments are a tool error the model can correct", async () => {
    await vault.enrolSoftware(dir.path)
    const result = await callTool("vault_request", { kind: "password", name: "x", reason: "r" })
    expect(result.isError).toBe(true)
    expect(result.structuredContent).toMatchObject({ error: "usage" })
  })

  test("vault_fetch returns status, headers and the body as text", async () => {
    await vault.enrolSoftware(dir.path)
    vault.relay = (request) =>
      new Response(JSON.stringify({ got: request.body }), { status: 202, headers: { [UPSTREAM_HEADER]: "1", [ITEM_HEADER]: "openai-personal (alex)", "x-id": "1" } })
    const result = await callTool("vault_fetch", { item: "openai-personal", method: "post", url: "https://api.openai.com/v1/x", headers: { "content-type": "application/json" }, body: "hi" })
    expect(result.isError).toBe(false)
    expect(result.structuredContent).toMatchObject({ status: 202, item: "openai-personal (alex)", truncated: false, headers: { "x-id": "1" }, body: JSON.stringify({ got: "aGk" }) })
  })

  test("vault_fetch carries rules when standing rules allowed the request, and ignores a malformed Mehen-Rule", async () => {
    await vault.enrolSoftware(dir.path)
    const endsAt = "2027-01-10T14:00:00.000Z"
    vault.overrides.set("GET /v1/policy/rules", () => Response.json([ruleView({ id: "rul_live", endsAt })]))
    vault.relay = () => new Response('{"ok":true}', { status: 200, headers: { [UPSTREAM_HEADER]: "1", [RULE_HEADER]: "rul_live" } })
    const ruled = await callTool("vault_fetch", { item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/x" })
    expect(ruled.structuredContent).toMatchObject({ status: 200, body: '{"ok":true}', rules: [{ id: "rul_live", endsAt }] })
    const picked = await callTool("vault_fetch", { item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/x", select: "ok" })
    expect(picked.structuredContent).toMatchObject({ selected: true, rules: [{ id: "rul_live", endsAt }] })
    vault.relay = () => new Response("ok", { status: 200, headers: { [UPSTREAM_HEADER]: "1", [RULE_HEADER]: "rul_live, rul_other" } })
    expect((await callTool("vault_fetch", { item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/x" })).structuredContent).toMatchObject({ rules: [{ id: "rul_live", endsAt }, { id: "rul_other", endsAt: null }] })
    vault.relay = () => new Response("ok", { status: 200, headers: { [UPSTREAM_HEADER]: "1", [RULE_HEADER]: "rul_a b" } })
    const malformed = (await callTool("vault_fetch", { item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/x" })).structuredContent
    expect(malformed).not.toHaveProperty("rules")
    expect(malformed).not.toHaveProperty("rule")
  })

  test("vault_fetch carries mandate when this machine's mandate allowed the request, and a capped ask says which caps in words", async () => {
    await vault.enrolSoftware(dir.path)
    vault.relay = () => new Response("ok", { status: 200, headers: { [UPSTREAM_HEADER]: "1", [MANDATE_HEADER]: "mdt_live" } })
    expect((await callTool("vault_fetch", { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x" })).structuredContent).toMatchObject({ status: 200, body: "ok", mandate: "mdt_live" })
    vault.relay = () => new Response("ok", { status: 200, headers: { [UPSTREAM_HEADER]: "1", [MANDATE_HEADER]: "mdt_a b" } })
    expect((await callTool("vault_fetch", { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x" })).structuredContent).not.toHaveProperty("mandate")
    vault.overrides.set("POST /v1/relay", () => vaultError("approval_required", "This request needs a human's approval.", { next: { url: `${vault.url}/w/mock-space/a/apr_1`, say: "Ask the human." }, approval: "apr_1", mandate: { id: "mdt_live", capped: ["send"] } }))
    vault.overrides.set("GET /v1/mandates/mdt_live", () => Response.json(mandateView()))
    const capped = await callTool("vault_fetch", { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x" })
    expect(capped.isError).toBe(true)
    expect(capped.structuredContent).toMatchObject({ error: "approval_required", message: "This request needs a human's approval. This machine's mandate has used today's 50 sends.", mandate: { id: "mdt_live", capped: ["send"] }, ask: { kind: "approval", id: "apr_1" } })
  })

  test("vault_fetch carries mandateCover on an ask a mandate could cover, its page checked, and says the state's line in its text", async () => {
    await vault.enrolSoftware(dir.path)
    const page = `${vault.url}/w/mock-space/mandates/mdt_live`
    vault.overrides.set("POST /v1/relay", () => vaultError("approval_required", "This request needs a human's approval.", { next: { url: `${vault.url}/w/mock-space/a/apr_1`, say: "Ask the human." }, approval: "apr_1", ...({ mandateCover: { classes: ["read", "send"], state: "not_covering", mandate: "mdt_live", url: "https://evil.example/x" } } as object) }))
    const held = await callTool("vault_fetch", { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x" })
    expect(held.isError).toBe(true)
    expect(held.structuredContent).toMatchObject({ error: "approval_required", mandateCover: { state: "not_covering", mandate: "mdt_live", url: page }, ask: { kind: "approval", id: "apr_1" } })
    const text = (held.content as { type: string; text?: string }[])[0]?.text ?? ""
    expect(text).toContain(`mandate: This machine's mandate is not covering requests right now; its signer can see why at ${page}.`)
    expect(JSON.stringify(held)).not.toContain("evil.example")
    vault.overrides.set("POST /v1/relay", () => vaultError("approval_required", "This request needs a human's approval.", { next: { url: `${vault.url}/w/mock-space/a/apr_1`, say: "Ask the human." }, approval: "apr_1", ...({ mandateCover: { classes: ["read", "send"], state: "none", mandate: null, url: null } } as object) }))
    const none = await callTool("vault_fetch", { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x" })
    const noneText = (none.content as { type: string; text?: string }[])[0]?.text ?? ""
    expect(noneText).toContain('propose one for only this credential and these kinds: vault_mandate { "action": "propose", "items": ["openai-personal"], "classes": ["read", "send"], "note": "<why>" }.')
    expect(noneText).not.toContain("mehen mandate propose")
  })

  test("vault_fetch reports a rule that ended before the relay's last check with the vault's message and a next that does not loop", async () => {
    await vault.enrolSoftware(dir.path)
    const message = "The rule that allowed this request has ended; send it again to ask for approval."
    vault.overrides.set("POST /v1/relay", () => vaultError("conflict", message))
    const result = await callTool("vault_fetch", { item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/x" })
    expect(result.isError).toBe(true)
    expect(result.structuredContent).toMatchObject({ error: "conflict", message, next: { say: "The standing rule that allowed this request has ended. Send it once more to ask for approval; do not retry in a loop." } })
  })

  test("vault_fetch sends replaces, refuses a malformed one before anything is sent, and explains a vault without batch approvals", async () => {
    await vault.enrolSoftware(dir.path)
    let seen: unknown = null
    vault.relay = (request) => {
      seen = request
      return new Response("ok", { status: 200, headers: { [UPSTREAM_HEADER]: "1" } })
    }
    const request = { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x", body: "two" }
    expect((await callTool("vault_fetch", { ...request, replaces: "apr_old1" })).isError).toBe(false)
    expect(seen).toMatchObject({ replaces: "apr_old1" })
    const before = vault.seen.length
    const bad = await callTool("vault_fetch", { ...request, replaces: "int_old1" })
    expect(bad.isError).toBe(true)
    expect(bad.structuredContent).toMatchObject({ error: "usage" })
    expect(String((bad.structuredContent as { message: string }).message)).toContain("replaces takes the id of this machine's open ask (apr_...)")
    expect(vault.seen.length).toBe(before)
    vault.overrides.set("POST /v1/relay", () => vaultError("forbidden", "Replacing an ask is not available yet."))
    try {
      const old = await callTool("vault_fetch", { ...request, replaces: "apr_old1" })
      expect(old.isError).toBe(true)
      expect(old.structuredContent).toMatchObject({ error: "forbidden", message: "Replacing an ask is not available yet.", next: { say: "This vault does not replace asks yet. Send the same request again without replaces; apr_old1 stays open until a human decides it or it expires." } })
    } finally {
      vault.overrides.clear()
    }
  })

  test("vault_plan submit asks for a bundle with inline bodies: the ask to hand over, each result's approval and shell repeat", async () => {
    await vault.enrolSoftware(dir.path)
    const plan = { version: 1, reason: "Set up", requests: [{ item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/a", headers: ["Content-Type: application/json"], body: "@not-a-file" }, { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/b", body: "it's" }] }
    const result = await callTool("vault_plan", { action: "submit", plan })
    expect(result.isError).toBe(false)
    const out = result.structuredContent as { bundle: string; ask: { kind: string; id: string; check: unknown }; results: { approval: string; repeat: string | null; note?: string }[] }
    expect(out.ask).toMatchObject({ kind: "bundle", id: out.bundle, check: { label: "codes", value: "CODE1, CODE2 (2)" } })
    const sent = JSON.parse(vault.seen.at(-1)?.body ?? "{}") as { requests: { body: string }[] }
    // Inline: "@not-a-file" is the body's text, never a file; no shell -d carries it.
    expect(sent.requests[0]?.body).toBe(Buffer.from("@not-a-file").toString("base64url"))
    expect(out.results[0]?.repeat).toBeNull()
    expect(out.results[0]?.note).toBe("The body is not text a shell command can carry, so there is no repeat: pass fetch to vault_fetch as it is.")
    expect(out.results[1]?.repeat).toBe(`mehen fetch openai-personal POST https://api.openai.com/v1/b -d 'it'\\''s' --approval ${out.results[1]?.approval}`)
    expect(text(result)).toContain(`vault_wait { "id": "${out.bundle}" }`)
    const waited = await callTool("vault_wait", { id: out.bundle, timeoutSeconds: 0 })
    expect(waited.structuredContent).toMatchObject({ error: "timeout" })
  })

  test("vault_plan submit carries each ask's mandateCover with its page checked, and says its line before the ask block", async () => {
    await vault.enrolSoftware(dir.path)
    const page = `${vault.url}/w/mock-space/mandates/mdt_live`
    vault.overrides.set("POST /v1/approvals/bundles", () => Response.json({ bundle: "bnd_cover", url: `${vault.url}/w/mock-space/g/bnd_cover`, expiresAt: MOCK_EXPIRES_AT, results: [{ index: 0, outcome: "ask", approval: "apr_one", bindingCode: "CODE1", mandateCover: { classes: ["read", "change"], state: "tripped", mandate: "mdt_live", url: page } }] }))
    const result = await callTool("vault_plan", { action: "submit", plan: { version: 1, requests: [{ item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/a", body: "one" }] } })
    expect((result.structuredContent as { results: unknown[] }).results[0]).toMatchObject({ mandateCover: { state: "tripped", url: page } })
    expect(text(result)).toStartWith(`request 1: This machine's mandate is tripped; the person who signed it can resume it at ${page}.`)
  })

  test("vault_plan submit gives each result fetch, the vault_fetch arguments that send the same request with its approval", async () => {
    await vault.enrolSoftware(dir.path)
    const plan = {
      version: 1,
      project: "prj_3kQ9vXyZ7",
      env: "dev",
      requests: [
        { item: "openai-personal", method: "post", url: "https://api.openai.com/v1/a", headers: ["Content-Type:  application/json ", "X-Note: it's"], body: '{"a":1}' },
        { item: "openai-personal", method: "PUT", url: "https://api.openai.com/v1/b", bodyBase64: Buffer.from([0xff, 0xfe, 0x00, 0x41]).toString("base64") },
        { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/c", headers: ["X-A: 1", "X-A: 2"], body: "two" },
      ],
    }
    const result = await callTool("vault_plan", { action: "submit", plan })
    expect(result.isError).toBe(false)
    const sent = JSON.parse(vault.seen.at(-1)?.body ?? "{}") as { requests: Record<string, unknown>[] }
    const out = result.structuredContent as { results: { approval: string; repeat: string | null; fetch: Record<string, unknown> | null; note?: string }[] }
    const [text, bytes, twice] = out.results as [(typeof out.results)[0], (typeof out.results)[0], (typeof out.results)[0]]
    expect(text.fetch).toEqual({ item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/a", headers: { "Content-Type": "application/json", "X-Note": "it's" }, body: '{"a":1}', context: { project: "prj_3kQ9vXyZ7", environment: "dev" }, approval: text.approval })
    expect(bytes.fetch).toMatchObject({ headers: {}, bodyBase64: Buffer.from([0xff, 0xfe, 0x00, 0x41]).toString("base64"), approval: bytes.approval })
    expect(bytes.note).toBe("The body is not text a shell command can carry, so there is no repeat: pass fetch to vault_fetch as it is.")
    expect(twice.fetch).toBeNull()
    expect(twice.note).toBe("vault_fetch's headers record cannot hold the header X-A given twice, so there is no fetch: send this request with its repeat in a shell instead.")
    expect(twice.repeat).not.toBeNull()
    // Each fetch, passed to vault_fetch as it is, sends what the bundle held plus its approval.
    for (const [index, entry] of [text, bytes].entries()) {
      const relayed: unknown[] = []
      vault.relay = (request) => {
        relayed.push(request)
        return new Response("ok", { status: 200, headers: { [UPSTREAM_HEADER]: "1" } })
      }
      expect((await callTool("vault_fetch", entry.fetch as Record<string, unknown>)).isError).toBe(false)
      expect(relayed).toEqual([{ ...(sent.requests[index] as Record<string, unknown>), approval: entry.approval }])
    }
  })

  test("vault_plan check advises on each request; a vault without bundles refuses submit with the one-by-one way on", async () => {
    await vault.enrolSoftware(dir.path)
    const plan = { version: 1, requests: [{ item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/models" }, { item: "openai-personal", method: "GET", url: "https://evil.example/" }] }
    const before = vault.seen.length
    const checked = await callTool("vault_plan", { action: "check", plan })
    expect(checked.structuredContent).toMatchObject({ counts: { allow: 1, approve: 0, refuse: 1 }, sameShape: [], advisory: true })
    expect(vault.seen.slice(before).every((s) => s.path !== "/v1/approvals/bundles")).toBe(true)
    vault.overrides.set("POST /v1/approvals/bundles", () => vaultError("forbidden", "Asking for several requests at once is not available yet."))
    try {
      const old = await callTool("vault_plan", { action: "submit", plan })
      expect(old.isError).toBe(true)
      expect(old.structuredContent).toMatchObject({ error: "forbidden", next: { say: "Send the requests one by one with vault_fetch; each that needs approval asks on its own." } })
    } finally {
      vault.overrides.clear()
    }
    const tooMany = await callTool("vault_plan", { action: "submit", plan: { version: 1, requests: Array.from({ length: 21 }, () => plan.requests[0]) } })
    expect(tooMany.structuredContent).toMatchObject({ error: "usage" })
  })

  test("vault_fetch truncates a body over 256 KiB with a note", async () => {
    await vault.enrolSoftware(dir.path)
    const big = "a".repeat(FETCH_BODY_LIMIT + 1000)
    vault.relay = () => new Response(big, { status: 200, headers: { [UPSTREAM_HEADER]: "1" } })
    const result = await callTool("vault_fetch", { item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/x" })
    const out = result.structuredContent as { body: string; truncated: boolean; note: string }
    expect(out.truncated).toBe(true)
    expect(out.body).toHaveLength(FETCH_BODY_LIMIT)
    expect(out.note).toContain("256 KiB")
  })

  test("vault_fetch with select picks one part of a JSON body from the whole response, past the 256 KiB cut", async () => {
    await vault.enrolSoftware(dir.path)
    const filler = "a".repeat(FETCH_BODY_LIMIT + 1000)
    vault.relay = () => new Response(JSON.stringify({ filler, data: [{ id: "app_1" }] }), { status: 200, headers: { [UPSTREAM_HEADER]: "1" } })
    const picked = await callTool("vault_fetch", { item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/x", select: "data[0].id" })
    expect(picked.isError).toBe(false)
    expect(picked.structuredContent).toMatchObject({ status: 200, selected: "app_1", found: true })
    expect(picked.structuredContent).not.toHaveProperty("body")
    const missing = await callTool("vault_fetch", { item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/x", select: "data.3" })
    expect(missing.structuredContent).toMatchObject({ selected: null, found: false })
    vault.relay = () => new Response("<html>", { status: 200, headers: { [UPSTREAM_HEADER]: "1" } })
    const notJson = await callTool("vault_fetch", { item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/x", select: "data" })
    expect(notJson.isError).toBe(true)
    expect(notJson.structuredContent).toMatchObject({ error: "usage" })
    expect(String((notJson.structuredContent as { message: string }).message)).toContain("so select has nothing to pick from")
  })

  test("vault_fetch with timeoutSeconds stops waiting: a read with a network error safe to resend, a write with outcome_unknown", async () => {
    await vault.enrolSoftware(dir.path)
    vault.relay = () => new Response(new ReadableStream<Uint8Array>({ start() {} }), { status: 200, headers: { [UPSTREAM_HEADER]: "1" } })
    const result = await callTool("vault_fetch", { item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/slow", timeoutSeconds: 1 })
    expect(result.isError).toBe(true)
    expect(result.structuredContent).toMatchObject({ error: "network", next: { say: "A read changes nothing upstream: send it again, or give `timeoutSeconds` more time." } })
    const write = await callTool("vault_fetch", { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/slow", body: "{}", timeoutSeconds: 1 })
    expect(write.isError).toBe(true)
    expect(write.structuredContent).toMatchObject({ error: "outcome_unknown", next: { say: OUTCOME_UNKNOWN_SAY } })
    expect(write.structuredContent).not.toHaveProperty("retryAfter")
  })

  // An approval-needed result stays an error result: the call did not do
  // what was asked, and the resource_link beside the text gives a host the
  // button for the same link the ask carries.
  test("a vault refusal is a tool error with the message, next, the ask and a resource_link whose uri is ask.url", async () => {
    await vault.enrolSoftware(dir.path)
    const link = `${vault.url}/w/mock-space/a/apr_9`
    vault.overrides.set("POST /v1/relay", () => vaultError("approval_required", "Sending email needs approval.", { next: { url: link, command: "mehen wait apr_9", say: "Ask the human to approve." }, approval: "apr_9", bindingCode: "Q7" }))
    const result = await callTool("vault_fetch", { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x" })
    expect(result.isError).toBe(true)
    expect(result.structuredContent).toEqual({
      error: "approval_required",
      message: "Sending email needs approval.",
      next: { url: link, say: "Ask the human to approve.", tool: "vault_wait", arguments: { id: "apr_9" } },
      approval: "apr_9",
      bindingCode: "Q7",
      ask: {
        kind: "approval",
        id: "apr_9",
        url: link,
        title: "Approve a request",
        what: "Sending email needs approval",
        check: { label: "code", value: "Q7" },
        expiresAt: null,
        account: null,
        requestedBy: { device: (result.structuredContent as { ask: { requestedBy: { device: string } } }).ask.requestedBy.device, session: "mcp-test" },
        wait: "mehen wait apr_9 --timeout 60 --json",
        // The failing call's own provenance, never a rendering-time selection.
        context: { origin: vault.url, workspace: MOCK_WORKSPACE, device: vault.lastDevice },
      },
    })
    const ask = (result.structuredContent as { ask: { url: string } }).ask
    expect(content(result)).toHaveLength(2)
    expect(content(result)[1]).toEqual({ type: "resource_link", uri: ask.url, name: "Approve a request (code Q7)", description: "Sending email needs approval", mimeType: "text/html" })
    expect(content(result)[1]?.uri).toBe(link)
    const shown = text(result)
    expect(shown.split("\n")[0]).toBe("approval_required: Sending email needs approval.")
    expect(shown).toContain("next: Ask the human to approve.")
    // The then: line names the wait, so no call: line repeats it.
    expect(shown).not.toContain("call:")
    expect(shown).toContain(`  open:    ${link}`)
    expect(shown).toContain("  check:   the page shows code Q7")
    expect(shown.split("\n").at(-1)).toBe('  then:    vault_wait { "id": "apr_9" }')
    expect(shown).not.toContain("mehen wait")
    expect(shown).not.toContain("\u001b")
    // A refusal that hands over no link has no resource_link.
    vault.overrides.set("POST /v1/relay", () => vaultError("policy_denied", "Denied.", { next: { say: "Do not." } }))
    const denied = await callTool("vault_fetch", { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x" })
    expect(denied.isError).toBe(true)
    expect(resourceLinks(denied)).toEqual([])
    expect((denied.structuredContent as { ask?: unknown }).ask).toBeUndefined()
  })

  test("a needs_reauth refusal hands over the reconnect link as an ask and a resource_link", async () => {
    await vault.enrolSoftware(dir.path)
    const link = `${vault.url}/w/mock-space/c/con_re`
    vault.overrides.set("POST /v1/relay", () => vaultError("needs_reauth", "Google revoked the sign-in for gmail-alex.", { next: { url: link, command: "mehen wait con_re", say: "Reconnect." } }))
    const result = await callTool("vault_fetch", { item: "gmail-alex", method: "GET", url: "https://gmail.googleapis.com/gmail/v1/users/me" })
    expect(result.isError).toBe(true)
    expect(result.structuredContent).toMatchObject({ error: "needs_reauth", ask: { kind: "reconnect", id: "con_re", url: link, check: null } })
    expectLinksMatchAsks(result)
    expect(text(result)).toContain('  then:    vault_wait { "id": "con_re" }')
  })

  // A link the vault hands back that is not on the vault this machine uses
  // is never in an MCP result: the same rule as the CLI.
  test("vault_request and vault_connect refuse a foreign link and return the vault's own, with a warning; the resource_link is the vault's own too", async () => {
    await vault.enrolSoftware(dir.path)
    vault.linkOrigin = "https://evil.example"
    try {
      const request = await callTool("vault_request", { kind: "api-key", name: "openai-new", reason: "r", provider: "openai" })
      expect(request.isError).toBe(false)
      expect(JSON.stringify(request)).not.toContain("evil.example")
      const created = request.structuredContent as { intake: string; url: string; ask: { url: string }; next: { url?: string; say: string }; warning?: string }
      expect(created.url).toBe(`${vault.url}/w/mock-space/i/${created.intake}`)
      expect(created.ask.url).toBe(created.url)
      expect(created.next.url).toBe(created.url)
      expect(created.warning).toContain(`not on ${vault.url}`)
      expectLinksMatchAsks(request)
      expect(resourceLinks(request)[0]?.uri).toBe(created.url)
      expect(text(request)).toStartWith(`warning: The vault returned a link that is not on ${vault.url}`)
      const connect = await callTool("vault_connect", { provider: "google-gmail", client: "google-client", name: "gmail-alex", reason: "r" })
      expect(JSON.stringify(connect)).not.toContain("evil.example")
      const con = connect.structuredContent as { connect: string; url: string; next: { url?: string }; warning?: string }
      expect(con.url).toBe(`${vault.url}/w/mock-space/c/${con.connect}`)
      expect(con.next.url).toBe(con.url)
      expect(con.warning).toContain("not on")
      expectLinksMatchAsks(connect)
      // The ledger holds only the vault's own links.
      for (const entry of await readLedger(vault.slotDir(dir.path), scope())) expect(entry.ask.url).toStartWith(vault.url)
    } finally {
      vault.linkOrigin = null
    }
  })

  test("vault_request and vault_connect for a machine without private credentials name the home argument to use instead", async () => {
    await vault.enrolSoftware(dir.path)
    vault.overrides.set("POST /v1/intakes", () => vaultError("not_found", "Not found."))
    vault.overrides.set("POST /v1/connect", () => vaultError("forbidden", "Private credentials are off for this machine."))
    for (const [tool, args] of [["vault_request", { kind: "api-key", name: "openai-new", reason: "r", provider: "openai" }], ["vault_connect", { provider: "google-gmail", client: "google-client", name: "gmail-alex", reason: "triage" }]] as const) {
      const result = await callTool(tool, args)
      expect(result.isError).toBe(true)
      const body = result.structuredContent as { error: string; message: string; next: { command?: string; say: string } }
      expect(body.error).toBe("forbidden")
      expect(body.message).toStartWith("This machine was accepted without private credentials")
      expect(body.next.command).toBeUndefined()
      expect(body.next.say).toStartWith('Ask again in a project you can edit with home: "project" with project: "<prj_id>", or with home: "workspace"')
      expect(body.message).toContain("which is where an ask goes when no home is given")
      const explicit = (await callTool(tool, { ...args, home: "private" })).structuredContent as { error: string; message: string }
      expect(explicit).toMatchObject({ error: "forbidden", message: "This machine was accepted without private credentials, so it cannot ask for a credential in its owner's private home." })
    }
  })

  test("an intake id the vault returns that mehen does not know never reaches next.command, and the ask's link is not trusted either", async () => {
    await vault.enrolSoftware(dir.path)
    vault.overrides.set("POST /v1/intakes", () => Response.json({ intake: "int_1/../../admin", url: `${vault.url}/w/mock-space/i/int_1`, expiresAt: MOCK_EXPIRES_AT }))
    const result = await callTool("vault_request", { kind: "api-key", name: "openai-new", reason: "r", provider: "openai" })
    expect(result.isError).toBe(false)
    const body = result.structuredContent as { url: string | null; next: { url?: string; command?: string; say: string }; warning?: string }
    expect(body.url).toBeNull()
    expect(body.next.command).toBeUndefined()
    expect(body.next.url).toBeUndefined()
    expect(body.warning).toContain("not on")
    vault.overrides.clear()
  })

  test("a tool error whose next.url is not on the vault drops the link from the result and the text", async () => {
    await vault.enrolSoftware(dir.path)
    for (const url of ["https://evil.example/a/apr_9", `${vault.url.replace("127.0.0.1", "127.0.0.1.evil.example")}/a/apr_9`, `${vault.url}/w/mock-space/a/apr_9\u200b`]) {
      vault.overrides.set("POST /v1/relay", () => vaultError("approval_required", "Needs approval.", { next: { url, command: "mehen wait apr_9", say: `Open ${url} now.` }, bindingCode: "Q7" }))
      const result = await callTool("vault_fetch", { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x" })
      expect(result.isError).toBe(true)
      const serialised = JSON.stringify(result)
      expect(serialised).not.toContain("evil.example")
      expect(serialised).not.toContain("\u200b")
      expect(serialised).not.toContain("Open http")
      const body = result.structuredContent as { next: { url?: string; say: string }; ask?: unknown }
      expect(body.next.url).toBeUndefined()
      expect(body.next.say).toContain(`not on ${vault.url}`)
      expect(body.ask).toBeUndefined()
      // No ask, so no resource_link: a foreign url never becomes a button.
      expect(resourceLinks(result)).toEqual([])
      expect(text(result)).toContain("warning:")
      expect(text(result)).not.toContain("open:")
      // A non-link code with a foreign next.url is treated the same way.
      vault.overrides.set("POST /v1/relay", () => vaultError("policy_denied", "Denied.", { next: { url, say: "x" } }))
      const denied = await callTool("vault_fetch", { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x" })
      expect(JSON.stringify(denied)).not.toContain("evil.example")
      expect((denied.structuredContent as { next: { url?: string } }).next.url).toBeUndefined()
    }
    // With an approval id the ask is rebuilt on the vault's own link.
    vault.overrides.set("POST /v1/relay", () => vaultError("approval_required", "Needs approval.", { next: { url: "https://evil.example/a/apr_9", say: "x" }, approval: "apr_9", bindingCode: "Q7" }))
    const rebuilt = await callTool("vault_fetch", { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x" })
    expect((rebuilt.structuredContent as { ask: { url: string } }).ask.url).toBe(`${vault.url}/w/mock-space/a/apr_9`)
    expect(JSON.stringify(rebuilt)).not.toContain("evil.example")
    expectLinksMatchAsks(rebuilt)
    expect(resourceLinks(rebuilt)).toEqual([expect.objectContaining({ uri: `${vault.url}/w/mock-space/a/apr_9` })])
  })

  test("a foreign link in the vault's pending list never becomes a resource_link either", async () => {
    await vault.enrolSoftware(dir.path)
    vault.pending = [
      { kind: "approval", id: "apr_f1", url: "https://evil.example/a/apr_f1", title: "Send", expiresAt: null, requestedBy: null, item: null, bindingCode: "K7Q2MX" },
      { kind: "approval", id: "apr_1/../x", url: `${vault.url}/w/mock-space/a/apr_1`, title: "Send", expiresAt: null, requestedBy: null, item: null, bindingCode: "K7Q2MX" },
    ]
    try {
      const result = await callTool("vault_pending", {})
      expect(result.isError).toBe(false)
      expect(JSON.stringify(result)).not.toContain("evil.example")
      expect(JSON.stringify(result)).not.toContain("../")
      const pending = (result.structuredContent as { pending: { id: string; url: string }[]; warning: string }).pending
      expect(pending).toEqual([expect.objectContaining({ id: "apr_f1", url: `${vault.url}/w/mock-space/a/apr_f1` })])
      expect((result.structuredContent as { warning: string }).warning).toContain("2 pending entries came with a link not on the vault or an id mehen does not know")
      expect(resourceLinks(result)).toEqual([expect.objectContaining({ uri: `${vault.url}/w/mock-space/a/apr_f1` })])
      expect(text(result)).toStartWith("warning: 2 pending entries")
    } finally {
      vault.pending = null
    }
  })

  test("hidden and control characters in an ask reach the text spelled out and the resource_link only as data", async () => {
    await vault.enrolSoftware(dir.path)
    vault.overrides.set("POST /v1/relay", () => vaultError("approval_required", "Send\u001b[2K mail\u202e to sam", { next: { url: `${vault.url}/w/mock-space/a/apr_h`, say: "Open\u001b[A it" }, approval: "apr_h", bindingCode: "K7\u200bQ2" }))
    const result = await callTool("vault_fetch", { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x" })
    const shown = text(result)
    expect(shown).not.toContain("\u001b")
    expect(shown).not.toContain("\u202e")
    expect(shown).not.toContain("\u200b")
    expect(shown).toContain("approval_required: Send\\u001B[2K mail[RLO U+202E] to sam")
    expect(shown).toContain("  what:    Send\\u001B[2K mail[RLO U+202E] to sam")
    expect(shown).toContain("  check:   the page shows code K7[ZWSP U+200B]Q2")
    // structuredContent carries the raw strings as data (JSON escapes the
    // control); the resource_link's uri is the checked link and its display
    // fields are spelled out like the text block.
    expect((result.structuredContent as { bindingCode: string; ask: { what: string } }).bindingCode).toBe("K7\u200bQ2")
    expect((result.structuredContent as { ask: { what: string } }).ask.what).toBe("Send\u001b[2K mail\u202e to sam")
    expect(resourceLinks(result)[0]).toEqual({ type: "resource_link", uri: `${vault.url}/w/mock-space/a/apr_h`, name: "Approve a request (code K7[ZWSP U+200B]Q2)", description: "Send\\u001B[2K mail[RLO U+202E] to sam", mimeType: "text/html" })
    expect(JSON.stringify(content(result))).not.toContain("\u001b")
    expect(JSON.stringify(content(result))).not.toContain("\u200b")
  })

  test("a hidden character in a pending title from the vault reaches the resource_link spelled out, never raw", async () => {
    await vault.enrolSoftware(dir.path)
    vault.pending = [{ kind: "approval", id: "apr_rlo", url: `${vault.url}/w/mock-space/a/apr_rlo`, title: "Send\u202e liam\u200b to sam\u001b[2J", expiresAt: null, requestedBy: { device: "d", deviceName: "box\u202e", session: null }, item: "gmail-alex", bindingCode: "K7\u202eQ2" }]
    try {
      const result = await callTool("vault_pending", {})
      expect(result.isError).toBe(false)
      const link = resourceLinks(result)[0]
      expect(link).toEqual({ type: "resource_link", uri: `${vault.url}/w/mock-space/a/apr_rlo`, name: "Approve a request (code K7[RLO U+202E]Q2)", description: "Send[RLO U+202E] liam[ZWSP U+200B] to sam\\u001B[2J, from gmail-alex", mimeType: "text/html" })
      const shown = JSON.stringify(content(result))
      expect(shown).not.toContain("\u202e")
      expect(shown).not.toContain("\u200b")
      expect(shown).not.toContain("\u001b")
      // structuredContent is the raw ask, as --json would print it.
      const ask = (result.structuredContent as { pending: { what: string; check: { value: string }; requestedBy: { device: string } }[] }).pending[0]
      expect(ask?.what).toBe("Send\u202e liam\u200b to sam\u001b[2J, from gmail-alex")
      expect(ask?.check.value).toBe("K7\u202eQ2")
      expect(ask?.requestedBy.device).toBe("box\u202e")
    } finally {
      vault.pending = null
    }
  })

  test("a hostile error message cannot steer a host that prints the text", async () => {
    await vault.enrolSoftware(dir.path)
    vault.overrides.set("POST /v1/relay", () => vaultError("policy_denied", "Denied\u001b[2K\u001b[32m allowed\u202e", { next: { say: "Fine\u001b[A", command: "mehen ls\u001b[2J" } }))
    const result = await callTool("vault_fetch", { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x" })
    const shown = text(result)
    expect(shown).not.toContain("\u001b")
    expect(shown).not.toContain("\u202e")
    expect(shown).toContain("policy_denied: Denied\\u001B[2K\\u001B[32m allowed[RLO U+202E]\nnext: Fine\\u001B[A\n  run:  mehen ls\\u001B[2J")
  })

  test("vault_wait returns the outcome, drops the settled ask from the ledger, and a timeout is a tool error that re-hands the ask", async () => {
    await vault.enrolSoftware(dir.path)
    await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask: approvalAsk({ id: "apr_1", url: vaultLink("/a/apr_1"), summary: "Send", bindingCode: "Q7", expiresAt: inMinutes(50), requestedBy: by }) })
    vault.sequences.set("approval:apr_1", [
      { approval: "apr_1", status: "pending", bindingCode: "Q7", summary: "Send" },
      { approval: "apr_1", status: "approved", bindingCode: "Q7", summary: "Send" },
    ])
    const done = await callTool("vault_wait", { id: "apr_1", timeoutSeconds: 10 })
    expect(done.isError).toBe(false)
    expect(done.structuredContent).toMatchObject({ id: "apr_1", kind: "approval", status: "approved" })
    expect(resourceLinks(done)).toEqual([])
    expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])
    // A timeout with the ask in the ledger hands the link over again.
    await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask: approvalAsk({ id: "apr_2", url: vaultLink("/a/apr_2"), summary: "Send again", bindingCode: "R8", expiresAt: inMinutes(50), requestedBy: by }) })
    const pending = await callTool("vault_wait", { id: "apr_2", timeoutSeconds: 0 })
    expect(pending.isError).toBe(true)
    expect(pending.structuredContent).toMatchObject({ error: "timeout", ask: { id: "apr_2", check: { label: "code", value: "R8" } } })
    expect((pending.structuredContent as { next: { command?: string } }).next.command).toBeUndefined()
    expectLinksMatchAsks(pending)
    expect(text(pending)).toContain('  then:    vault_wait { "id": "apr_2" }')
    expect((await readLedger(vault.slotDir(dir.path), scope())).map((e) => e.ask.id)).toEqual(["apr_2"])
    // Without a ledger entry a timeout carries no ask and no link.
    const unknown = await callTool("vault_wait", { id: "int_2", timeoutSeconds: 0 })
    expect(unknown.isError).toBe(true)
    expect(unknown.structuredContent).toMatchObject({ error: "timeout" })
    expect(resourceLinks(unknown)).toEqual([])
  })

  test("vault_wait filters a completed intake's item through pickSummary", async () => {
    await vault.enrolSoftware(dir.path)
    vault.sequences.set("intake:int_done", [{ intake: "int_done", status: "completed", item: { ...item("openai-new"), secretValue: "sk-leak", extra: 1 } }])
    const done = await callTool("vault_wait", { id: "int_done", timeoutSeconds: 5 })
    expect(done.isError).toBe(false)
    const out = done.structuredContent as { item: Record<string, unknown> }
    expect(out.item.slug).toBe("openai-new")
    expect(out.item.secretValue).toBeUndefined()
    expect(out.item.extra).toBeUndefined()
    expect(JSON.stringify(done)).not.toContain("sk-leak")
  })

  test("vault_wait sends notifications/progress only when the call carried a progressToken", async () => {
    await vault.enrolSoftware(dir.path)
    vault.statusExpiresAt = inMinutes(48)
    try {
      const silent = await callTool("vault_wait", { id: "apr_quiet", timeoutSeconds: 1 })
      expect(silent.isError).toBe(true)
      expect(mcp.notifications("notifications/progress")).toEqual([])
      const noisy = await callTool("vault_wait", { id: "apr_loud", timeoutSeconds: 1 }, { progressToken: "tok-1" })
      expect(noisy.isError).toBe(true)
      const progress = mcp.notifications("notifications/progress")
      expect(progress.length).toBeGreaterThanOrEqual(1)
      expect(progress[0]).toEqual({ jsonrpc: "2.0", method: "notifications/progress", params: { progressToken: "tok-1", progress: expect.any(Number), total: 1, message: "waiting for approval apr_loud; the link expires in 48 min" } })
      // Every notification names the token this call carried, and nothing arrives once it is over.
      for (const n of progress) expect(n.params?.progressToken).toBe("tok-1")
      const count = progress.length
      await mcp.request("ping")
      expect(mcp.notifications("notifications/progress")).toHaveLength(count)
      const numbered = await callTool("vault_wait", { id: "int_num", timeoutSeconds: 0 }, { progressToken: 7 })
      expect(numbered.isError).toBe(true)
      expect(mcp.notifications("notifications/progress").at(-1)?.params).toMatchObject({ progressToken: 7, total: 0, message: "waiting for intake int_num; the link expires in 48 min" })
    } finally {
      vault.statusExpiresAt = null
    }
  })

  // A host that cancels a call has stopped listening: the server must stop
  // too, so no further signed poll reaches the vault and no further
  // progress notification is sent, and no response is sent for that id.
  test("notifications/cancelled stops a vault_wait: no more polls, no more progress, no response", async () => {
    await vault.enrolSoftware(dir.path)
    // The server is up before the timed part begins.
    expect((await mcp.request("ping")).result).toEqual({})
    const settle = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
    const id = 900
    mcp.send(JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "vault_wait", arguments: { id: "apr_cancel", timeoutSeconds: 10 }, _meta: { progressToken: "tok-c" } } }))
    // Let it poll a few times (MEHEN_POLL_INTERVAL_MS is 20) and send its first
    // progress. Wait for that rather than a fixed time: on a busy runner the
    // first polls can take longer than 150 ms to arrive.
    const pollsOf = () => vault.seen.filter((c) => c.path === "/v1/approvals/apr_cancel").length
    for (let waited = 0; waited < 5_000 && (pollsOf() < 2 || mcp.notifications("notifications/progress").length < 1); waited += 25) await settle(25)
    const pollsBefore = pollsOf()
    expect(pollsBefore).toBeGreaterThan(1)
    expect(mcp.notifications("notifications/progress").length).toBeGreaterThanOrEqual(1)
    mcp.send(JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: id, reason: "the user moved on" } }))
    await settle(100)
    const polls = vault.seen.filter((c) => c.path === "/v1/approvals/apr_cancel").length
    const progress = mcp.notifications("notifications/progress").length
    await settle(300)
    expect(vault.seen.filter((c) => c.path === "/v1/approvals/apr_cancel").length).toBe(polls)
    expect(mcp.notifications("notifications/progress").length).toBe(progress)
    expect(mcp.received.some((m) => m.id === id)).toBe(false)
    // The server is still serving, and the ledger was not touched (nothing settled).
    expect((await mcp.request("ping")).result).toEqual({})
    expect(mcp.received.some((m) => m.id === id)).toBe(false)
    // Cancelling an id that is not in flight, or a malformed one, is ignored.
    mcp.send(JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 12345 } }))
    mcp.send(JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: { nested: true } } }))
    expect((await mcp.request("ping")).result).toEqual({})
    // A new wait on the same server still polls and reports progress.
    const again = await callTool("vault_wait", { id: "apr_cancel", timeoutSeconds: 0 }, { progressToken: "tok-d" })
    expect(again.isError).toBe(true)
    expect(mcp.notifications("notifications/progress").at(-1)?.params).toMatchObject({ progressToken: "tok-d" })
  }, 20_000)

  test("cancelling a call that is not a wait sends no response for it either", async () => {
    await vault.enrolSoftware(dir.path)
    // The server is up before the timed part begins.
    expect((await mcp.request("ping")).result).toEqual({})
    vault.overrides.set("GET /v1/items", async () => {
      await new Promise((resolve) => setTimeout(resolve, 200))
      return Response.json({ items: [] })
    })
    const id = 901
    mcp.send(JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "vault_list", arguments: {} } }))
    await new Promise((resolve) => setTimeout(resolve, 50))
    mcp.send(JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: id } }))
    await new Promise((resolve) => setTimeout(resolve, 400))
    expect(mcp.received.some((m) => m.id === id)).toBe(false)
    expect((await mcp.request("ping")).result).toEqual({})
  })

  test("progress messages carry the id, the kind and the link's remaining life only", () => {
    const now = new Date("2026-10-24T16:00:00.000Z")
    expect(progressMessage(waitTarget("apr_7Hq2"), "apr_7Hq2", "2026-10-24T16:48:00.000Z", now)).toBe("waiting for approval apr_7Hq2; the link expires in 48 min")
    expect(progressMessage(waitTarget("int_1"), "int_1", null, now)).toBe("waiting for intake int_1")
    expect(progressMessage(waitTarget("con_1"), "con_1", "2026-10-24T15:00:00.000Z", now)).toBe("waiting for connection con_1; the link has expired")
    expect(progressMessage(waitTarget("enr_1"), "enr_1", "2026-10-24T16:14:00.000Z", now)).toBe("waiting for enrolment enr_1; the link expires in 14 min")
    expect(mcpThen(approvalAsk({ id: "apr_7Hq2", url: vaultLink("/a/apr_7Hq2"), summary: "s", bindingCode: null, expiresAt: null, requestedBy: by }))).toBe('vault_wait { "id": "apr_7Hq2" }')
  })

  test("vault_wait on an enr_ id finishes an enrolment this machine started at its terminal, and never starts one", async () => {
    // An older mehen enrol made the key and the ledger entry (adopted as the
    // slot's record); the vault holds the pending enrolment.
    const pending = pendingSlotPath(dir.path, vault.url, "mock-space")
    const { jwk } = await createDeviceKey(pending, "software", {})
    const id = "enr_mcp1"
    vault.enrolments.set(id, { id, jwk, name: "test-mac", backend: "software", polls: 0, workspace: "mock-space", owner: { kind: "self" } })
    const fingerprint = fingerprintOf(await jwkThumbprint(jwk))
    await addLedgerEntry(pending, scope(), {
      ask: enrolAsk({ id, url: vaultLink("/e/ABCD2345"), name: "test-mac", backend: "software", fingerprint, expiresAt: inMinutes(14), requestedBy: by }),
      command: "mehen enrol --workspace mock-space --name test-mac --backend software",
      enrol: { code: "ABCD2345", name: "test-mac", backend: "software", jwk, workspace: "mock-space", team: null },
    })
    expect(await readConfig(pending)).toBeNull()
    const before = vault.seen.length
    const result = await callTool("vault_wait", { id, timeoutSeconds: 10 })
    expect(result.isError).toBe(false)
    expect(result.structuredContent).toMatchObject({ id, kind: "enrol", status: "active", tenant: MOCK_TENANT, device: deviceFor(id) })
    for (const poll of vault.seen.slice(before)) expect(poll).toMatchObject({ method: "GET", path: `/v1/enrol/${id}`, claims: { ten: "enrol", dev: id } })
    // The finish step renamed the pending slot into the workspace's active slot.
    expect(await readConfig(vault.slotDir(dir.path))).toEqual({ vault: vault.url, tenant: MOCK_TENANT, device: deviceFor(id), backend: "software", fingerprint, name: "test-mac", workspaceSlug: MOCK_WORKSPACE.slug, workspaceName: MOCK_WORKSPACE.name, owner: MOCK_OWNER })
    expect(await readConfig(pending)).toBeNull()
    expect(await readLedger(vault.slotDir(dir.path), { vaultUrl: vault.url, workspace: null, device: null })).toEqual([])
    // The same server now answers vault_status with the new active slot, which the wait latched.
    expect((await callTool("vault_status", {})).structuredContent).toMatchObject({ workspaces: [{ state: "active", device: deviceFor(id), fingerprint, check: { ok: true, status: { device: deviceFor(id), workspace: MOCK_WORKSPACE } } }] })
    // An enrolment no slot this server may use records cannot be waited on, and nothing is sent.
    const seen = vault.seen.length
    const unknown = await callTool("vault_wait", { id: "enr_unknown" })
    expect(unknown.isError).toBe(true)
    expect(unknown.structuredContent).toMatchObject({ error: "not_found" })
    expect(vault.seen.length).toBe(seen)
  })

  test("vault_env says how each declared variable resolves, never a value", async () => {
    await vault.enrolSoftware(dir.path)
    const project = join(dir.path, "project")
    await Bun.write(join(project, "mehen.toml"), 'project = "prj_test"\ndefault_env = "dev"\n\n[vars]\nOPENAI_API_KEY = "vault"\nDATABASE_URL = "vault"\nLOG_LEVEL = "info"\n')
    vault.overrides.set("GET /v1/projects/prj_test", () =>
      Response.json({
        id: "prj_test",
        slug: "test",
        remotes: [],
        defaultEnv: "dev",
        environments: [{ name: "dev", protected: false, fences: [] }],
        vars: [
          { name: "OPENAI_API_KEY", env: "dev", source: "item", item: "openai-personal", field: "key" },
          { name: "DATABASE_URL", env: "dev", source: "unset", item: null, field: null },
        ],
      }),
    )
    const listed = await callTool("vault_env", { cwd: project })
    expect(listed.isError).toBe(false)
    const lines = (listed.structuredContent as { variables: string[] }).variables
    expect(lines.find((l) => l.startsWith("OPENAI_API_KEY"))).toContain("vault item openai-personal#key")
    expect(lines.find((l) => l.startsWith("DATABASE_URL"))).toContain("unset")
    expect(lines.find((l) => l.startsWith("LOG_LEVEL"))).toContain("plain value in mehen.toml")
    expect(JSON.stringify(listed)).not.toContain("info")

    const checked = await callTool("vault_env", { cwd: project, check: true })
    expect(checked.isError).toBe(true)
    expect(checked.structuredContent).toMatchObject({ error: "command_failed" })
    expect((checked.structuredContent as { message: string }).message).toContain("DATABASE_URL")

    const missing = await callTool("vault_env", { cwd: dir.path })
    expect(missing.isError).toBe(true)
    expect((missing.structuredContent as { message: string }).message).toContain("no mehen.toml")
    expect((await callTool("vault_env", { cwd: "relative/path" })).structuredContent).toMatchObject({ error: "usage" })
  })

  test("vault_env in a checkout with no mehen.toml whose remote is a project names it, with mehen init as the next step", async () => {
    await vault.enrolSoftware(dir.path)
    const clone = join(dir.path, "clone")
    for (const args of [["init", "-q", clone], ["-C", clone, "remote", "add", "origin", "git@github.com:example/demo.git"]]) expect(Bun.spawnSync(["git", ...args]).exitCode).toBe(0)
    vault.overrides.set("GET /v1/projects", (request) =>
      new URL(request.url).searchParams.get("remote") === "github.com/example/demo"
        ? Response.json({ id: "prj_test", slug: "demo", defaultEnv: "dev", environments: [{ name: "dev", protected: false, variables: ["OPENAI_API_KEY"] }] })
        : vaultError("not_found", "No such object."),
    )
    const result = await callTool("vault_env", { cwd: clone, check: true })
    expect(result.isError).toBe(true)
    expect(result.structuredContent).toMatchObject({
      error: "command_failed",
      message: "no mehen.toml in this checkout, but its remote github.com/example/demo is project demo (prj_test)",
      next: { say: "run mehen init to bind this checkout to project demo", command: "mehen init" },
    })
  })

  test("vault_env in a checkout with no mehen.toml whose remote lookup the vault refuses says only that mehen.toml is missing", async () => {
    await vault.enrolSoftware(dir.path)
    const clone = join(dir.path, "clone")
    for (const args of [["init", "-q", clone], ["-C", clone, "remote", "add", "origin", "git@github.com:example/demo.git"]]) expect(Bun.spawnSync(["git", ...args]).exitCode).toBe(0)
    vault.overrides.set("GET /v1/projects", () => vaultError("workload_required", "Act through a workload."))
    const result = await callTool("vault_env", { cwd: clone, check: true })
    expect(result.isError).toBe(true)
    expect(result.structuredContent).toMatchObject({ error: "command_failed" })
    expect((result.structuredContent as { message: string }).message).toContain("no mehen.toml")
    expect((result.structuredContent as { message: string }).message).not.toContain("workload")
  })

  test("not_found, usage, approval_required and command_failed results from the tools with an outputSchema meet it", async () => {
    await vault.enrolSoftware(dir.path)
    expect([...OUTPUT_SCHEMAS.keys()]).toEqual(["vault_templates", "vault_list", "vault_check", "vault_fetch", "vault_env", "vault_pending"])
    const clone = join(dir.path, "clone")
    for (const args of [["init", "-q", clone], ["-C", clone, "remote", "add", "origin", "git@github.com:example/demo.git"]]) expect(Bun.spawnSync(["git", ...args]).exitCode).toBe(0)
    vault.overrides.set("GET /v1/projects", () => Response.json({ id: "prj_test", slug: "demo", defaultEnv: "dev", environments: [{ name: "dev", protected: false, variables: [] }] }))
    vault.overrides.set("POST /v1/relay", () => vaultError("approval_required", "Sending needs approval.", { next: { url: `${vault.url}/w/mock-space/a/apr_9`, command: "mehen wait apr_9", say: "Ask the human to approve." }, approval: "apr_9", bindingCode: "Q7" }))
    const results: [string, Record<string, unknown>][] = [
      ["vault_templates", await callTool("vault_templates", { id: "nope" })],
      ["vault_check", await callTool("vault_check", { item: "nope", method: "GET", url: "https://api.openai.com/v1/x" })],
      ["vault_list", await callTool("vault_list", { limit: 0 })],
      ["vault_pending", await callTool("vault_pending", { workspace: 7 })],
      ["vault_fetch", await callTool("vault_fetch", { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/x" })],
      ["vault_env", await callTool("vault_env", { cwd: clone, check: true })],
    ]
    expect(results.map(([name, r]) => [name, (r.structuredContent as { error: string }).error])).toEqual([
      ["vault_templates", "not_found"],
      ["vault_check", "not_found"],
      ["vault_list", "usage"],
      ["vault_pending", "usage"],
      ["vault_fetch", "approval_required"],
      ["vault_env", "command_failed"],
    ])
    for (const [name, result] of results) expect(outputSchemaRefuses(name, result)).toBeNull()
    // The check bites: a schema that typed a field an error carries, or required one it lacks, would refuse it.
    const typedError = z.fromJSONSchema({ type: "object", properties: { error: { type: "integer" } } } as never)
    expect(typedError.safeParse(results[0]?.[1].structuredContent).success).toBe(false)
    const requiredTemplates = z.fromJSONSchema({ type: "object", properties: { templates: { type: "array" } }, required: ["templates"] } as never)
    expect(requiredTemplates.safeParse(results[0]?.[1].structuredContent).success).toBe(false)
    const optionalTemplates = z.fromJSONSchema({ type: "object", properties: { templates: { type: "array" } } } as never)
    expect(optionalTemplates.safeParse(results[0]?.[1].structuredContent).success).toBe(true)
  })

  test("calls run concurrently: a ping answers while a wait is pending", async () => {
    await vault.enrolSoftware(dir.path)
    const wait = mcp.request("tools/call", { name: "vault_wait", arguments: { id: "int_slow", timeoutSeconds: 1 } })
    const ping = await mcp.request("ping")
    expect(ping.result).toEqual({})
    expect(mcp.received.some((m) => m.id === 1)).toBe(false)
    expect(((await wait).result as { isError: boolean }).isError).toBe(true)
  })
})

describe("adoption tools", () => {
  const LONG = `sk-proj-${"Xv7N".repeat(14)}`
  const MID = "Wq8Lz3Rk"

  test("vault_adopt_scan returns counts per folder with its proposed home, writes the 0600 scan file with the names, needs no enrolment and sends nothing", async () => {
    const { mkdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } = await import("node:fs")
    const machine = realpathSync(mkdtempSync(join(tmpdir(), "mehen-mcp-adopt-")))
    const code = join(machine, "code", "billing-api")
    mkdirSync(code, { recursive: true })
    writeFileSync(join(code, ".env"), `OPENAI_API_KEY=${LONG}\nSESSION_SECRET=${MID}\nLOG_LEVEL=debug\n`)
    const seen = vault.seen.length
    const result = await callTool("vault_adopt_scan", { roots: [join(machine, "code")], defaults: false })
    expect(result.isError).toBe(false)
    const structured = result.structuredContent as { scan: string; folders: unknown[]; entries?: unknown }
    expect(structured.folders).toEqual([{ folder: code, category: "config", home: "private", secrets: 2, config: 1, unknown: 0, unsupported: 0, stale: 0 }])
    expect(structured.entries).toBeUndefined()
    const saved = JSON.parse(readFileSync(structured.scan, "utf8")) as { entries: { variable: string; provider: string | null; home: string }[] }
    expect(saved.entries.map((e) => [e.variable, e.provider, e.home])).toEqual([["OPENAI_API_KEY", "openai", "private"], ["SESSION_SECRET", null, "private"], ["LOG_LEVEL", null, "private"]])
    for (const text of [JSON.stringify(result), readFileSync(structured.scan, "utf8")]) {
      expect(text).not.toContain(LONG)
      expect(text).not.toContain(MID)
    }
    expect(statSync(structured.scan).mode & 0o777).toBe(0o600)
    expect(vault.seen.length).toBe(seen)
    const relative = await callTool("vault_adopt_scan", { roots: ["code"] })
    expect(relative.structuredContent).toMatchObject({ error: "usage" })
    rmSync(machine, { recursive: true, force: true })
  })

  test("vault_adopt_status returns the batch and its checked /b/ link", async () => {
    await vault.enrolSoftware(dir.path)
    const status = { adoption: "adp_mcp001", status: "approved", expiresAt: inMinutes(60), machines: [{ device: "dev_x", name: "test-box", items: 2 }], created: [{ ref: "a001", slug: "openai-billing-api" }], refused: [{ ref: "a002", reason: "slug taken" }] }
    vault.overrides.set("GET /v1/adoptions/adp_mcp001", () => Response.json(status))
    const result = await callTool("vault_adopt_status", { adoption: "adp_mcp001" })
    expect(result.isError).toBe(false)
    expect(result.structuredContent).toEqual({ ...status, url: `${vault.url}/w/mock-space/b/adp_mcp001` })
    const bad = await callTool("vault_adopt_status", { adoption: "int_x" })
    expect(bad.structuredContent).toMatchObject({ error: "usage" })
  })
})
