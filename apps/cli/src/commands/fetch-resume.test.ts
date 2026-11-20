import { afterAll, afterEach, beforeAll, beforeEach, expect, test } from "bun:test"
import { readFile, readdir, stat, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { EXIT, type RelayRequestInput, UPSTREAM_HEADER } from "@mehen/protocol/api"
import { MockVault, vaultError } from "../testing/mock-vault.ts"
import { type JvResult, runJv, tempDir } from "../testing/run-mehen.ts"

// After a human approves a held request, mehen sends the saved request
// again: mehen fetch --resume, mehen wait --execute, vault_fetch with
// approval alone, and vault_wait with execute.

let vault: MockVault
let dir: { path: string; remove(): Promise<void> }
let env: Record<string, string>
let sent: RelayRequestInput[]

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url, MEHEN_SESSION: "agent-1" }
  vault.overrides.clear()
  vault.sequences.clear()
  sent = []
  await vault.enrolSoftware(dir.path)
  // Held the first time, answered once the request carries its approval.
  vault.relay = (request) => {
    sent.push(request)
    if (request.approval === "apr_1") return new Response('{"id":"msg_1"}', { status: 200, headers: { [UPSTREAM_HEADER]: "1", "Content-Type": "application/json" } })
    return vaultError("approval_required", "This request needs a human's approval.", { next: { url: `${vault.url}/w/mock-space/a/apr_1`, command: "mehen wait apr_1", say: "Ask the human." }, approval: "apr_1", bindingCode: "K7Q2" })
  }
})
afterEach(async () => dir.remove())

const cache = () => join(dir.path, "pending-requests")
// Holds every request under `id` until it carries that approval: each round
// of a test that holds again needs its own approval, since a spent one is
// never saved again.
const holdAs = (id: string) => {
  vault.relay = (request) => {
    sent.push(request)
    if (request.approval === id) return new Response('{"id":"msg_1"}', { status: 200, headers: { [UPSTREAM_HEADER]: "1", "Content-Type": "application/json" } })
    return vaultError("approval_required", "This request needs a human's approval.", { next: { url: `${vault.url}/w/mock-space/a/${id}`, command: `mehen wait ${id}`, say: "Ask the human." }, approval: id, bindingCode: "K7Q2" })
  }
}
const json = (result: JvResult) => JSON.parse(result.stdout) as Record<string, unknown>
const held = (extra: string[] = []) => runJv(["fetch", "gmail-support", "POST", "https://gmail.googleapis.com/send", "-H", "Content-Type: application/json", "-d", '{"to":"sam@example.com"}', ...extra], env)
const approved = () => vault.sequences.set("approval:apr_1", [{ approval: "apr_1", status: "approved", bindingCode: "K7Q2", summary: "Send an email" }])

test("a held fetch saves the request and says how to send it again once approved", async () => {
  const result = await held(["--json"])
  expect(result.code).toBe(EXIT.approval)
  expect(json(result)).toMatchObject({ error: "approval_required", approval: "apr_1", replay: { saved: true, expiresAt: expect.any(String) } })
  expect((await readdir(cache())).filter((name) => name !== ".swept")).toEqual(["apr_1.json"])
  expect((await stat(join(cache(), "apr_1.json"))).mode & 0o777).toBe(0o600)
  const human = await held()
  // The folder is the root's own: the next command finds nothing to migrate.
  expect(human.stderr).not.toContain("migrated")
  expect(human.stderr).toContain("replay: saved for an hour; once approved, `mehen fetch --resume apr_1` (or `mehen wait apr_1 --execute`) sends it again, once.")
})

test("mehen fetch --resume sends the identical request once, with its approval, and a second resume sends nothing", async () => {
  await held()
  const first = sent[0] as RelayRequestInput
  const resumed = await runJv(["fetch", "--resume", "apr_1"], env)
  expect(resumed.code).toBe(EXIT.ok)
  expect(resumed.stdout).toBe('{"id":"msg_1"}')
  expect(sent).toHaveLength(2)
  expect(sent[1]).toEqual({ ...first, approval: "apr_1" })
  await expect(stat(join(cache(), "apr_1.json"))).rejects.toMatchObject({ code: "ENOENT" })
  const again = await runJv(["fetch", "--resume", "apr_1", "--json"], env)
  expect(again.code).toBe(EXIT.error)
  expect(json(again)).toMatchObject({ error: "replay_missing", next: { say: expect.stringContaining("byte for byte") } })
  expect(sent).toHaveLength(2)
})

test("--resume takes the output flags, and refuses anything that would change the request", async () => {
  await held()
  const before = sent.length
  for (const extra of [["gmail-support", "POST", "https://x.example/"], ["-H", "X: 1"], ["-d", "{}"], ["--approval", "apr_1"], ["--replaces", "apr_2"], ["--run", "run_1"], ["--project", "prj_3kQ9vXyZ7", "--env", "prod"]]) {
    const refused = await runJv(["fetch", "--resume", "apr_1", ...extra, "--json"], env)
    expect(refused.code).toBe(EXIT.usage)
  }
  expect((await runJv(["fetch", "--resume", "int_1", "--json"], env)).code).toBe(EXIT.usage)
  expect(sent.length).toBe(before)
  const selected = await runJv(["fetch", "--resume", "apr_1", "--select", "id", "--json"], env)
  expect(selected.code).toBe(EXIT.ok)
  expect(json(selected)).toMatchObject({ status: 200, selected: "msg_1", found: true })
})

test("a request saved by another machine is refused and nothing is sent", async () => {
  await held()
  const path = join(cache(), "apr_1.json")
  const saved = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>
  await writeFile(path, JSON.stringify({ ...saved, device: "dev_someone_else" }), { mode: 0o600 })
  const before = sent.length
  const refused = await runJv(["fetch", "--resume", "apr_1", "--json"], env)
  expect(refused.code).toBe(EXIT.error)
  expect(json(refused)).toMatchObject({ error: "replay_missing", message: expect.stringContaining("another machine") })
  expect(sent.length).toBe(before)
})

test("a body over 64 KiB is not saved, and the answer says to send it again byte for byte", async () => {
  const big = join(dir.path, "big.json")
  await writeFile(big, `"${"a".repeat(64 * 1024)}"`)
  const result = await runJv(["fetch", "gmail-support", "POST", "https://gmail.googleapis.com/send", "-d", `@${big}`, "--json"], env)
  expect(json(result)).toMatchObject({ replay: { saved: false, reason: expect.stringContaining("64 KiB") } })
  await expect(stat(join(cache(), "apr_1.json"))).rejects.toMatchObject({ code: "ENOENT" })
})

test("a resumed write whose answer never comes is outcome_unknown, and is never sent a third time", async () => {
  await held()
  vault.relay = (request) => {
    sent.push(request)
    return new Response("Gateway", { status: 502 })
  }
  const unknown = await runJv(["fetch", "--resume", "apr_1", "--json"], env)
  expect(unknown.code).toBe(EXIT.transient)
  expect(json(unknown)).toMatchObject({ error: "outcome_unknown" })
  expect(sent).toHaveLength(2)
  expect((await runJv(["fetch", "--resume", "apr_1", "--json"], env)).code).toBe(EXIT.error)
  expect(sent).toHaveLength(2)
})

test("mehen wait --execute waits, then sends the saved request once approved, with fetch's exit code", async () => {
  await held()
  approved()
  const result = await runJv(["wait", "apr_1", "--execute", "--timeout", "5"], env)
  expect(result.code).toBe(EXIT.ok)
  expect(result.stdout).toBe('{"id":"msg_1"}')
  expect(sent).toHaveLength(2)
  expect(sent[1]?.approval).toBe("apr_1")
  const json = await runJv(["wait", "apr_1", "--execute", "--timeout", "5", "--json"], env)
  expect(json.code).toBe(EXIT.error)
  expect(JSON.parse(json.stdout)).toMatchObject({ error: "replay_missing" })
})

test("mehen wait --execute on a push only waits: the vault performs the push and nothing is replayed", async () => {
  vault.sequences.set("approval:apr_p1", [{ approval: "apr_p1", status: "approved", bindingCode: "K7Q2", summary: "Push", push: { destination: "github:acme/app/OPENAI_API_KEY", field: "key", version: 3, state: "done", outcome: "created" } }])
  const before = sent.length
  const result = await runJv(["wait", "apr_p1", "--execute", "--timeout", "5", "--json"], env)
  expect(result.code).toBe(EXIT.ok)
  expect(JSON.parse(result.stdout)).toMatchObject({ id: "apr_p1", kind: "approval", push: { state: "done" } })
  expect(sent.length).toBe(before)
})

test("--execute is for approvals only, and not with --events", async () => {
  expect((await runJv(["wait", "int_1", "--execute", "--json"], env)).code).toBe(EXIT.usage)
  expect((await runJv(["wait", "apr_1", "--execute", "--json", "--events"], env)).code).toBe(EXIT.usage)
})

// The MCP tools: vault_fetch with approval alone, and vault_wait with execute.
async function call(name: string, args: Record<string, unknown>): Promise<{ isError: boolean; structuredContent: Record<string, unknown>; content: { text: string }[] }> {
  const result = await runJv(["mcp"], env, `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } })}\n`)
  return (JSON.parse(result.stdout) as { result: { isError: boolean; structuredContent: Record<string, unknown>; content: { text: string }[] } }).result
}

test("vault_fetch saves a held request, and vault_fetch with approval alone sends it again once", async () => {
  const first = await call("vault_fetch", { item: "gmail-support", method: "POST", url: "https://gmail.googleapis.com/send", headers: { "Content-Type": "application/json" }, body: '{"to":"sam@example.com"}' })
  expect(first.isError).toBe(true)
  expect(first.structuredContent).toMatchObject({ error: "approval_required", replay: { saved: true } })
  expect(first.content[0]?.text).toContain('`vault_fetch { "approval": "apr_1" }`')
  const resumed = await call("vault_fetch", { approval: "apr_1" })
  expect(resumed.isError).toBe(false)
  expect(resumed.structuredContent).toMatchObject({ status: 200, body: '{"id":"msg_1"}' })
  expect(sent[1]).toEqual({ ...(sent[0] as RelayRequestInput), approval: "apr_1" })
  const again = await call("vault_fetch", { approval: "apr_1" })
  expect(again.structuredContent).toMatchObject({ error: "replay_missing" })
  expect((await call("vault_fetch", { approval: "apr_1", method: "GET" })).structuredContent).toMatchObject({ error: "usage" })
  expect((await call("vault_fetch", { item: "gmail-support" })).structuredContent).toMatchObject({ error: "usage" })
})

test("vault_wait with execute sends the saved request once approved, and on a push only waits", async () => {
  await call("vault_fetch", { item: "gmail-support", method: "POST", url: "https://gmail.googleapis.com/send", body: "{}" })
  approved()
  const result = await call("vault_wait", { id: "apr_1", execute: true, timeoutSeconds: 5 })
  expect(result.isError).toBe(false)
  expect(result.structuredContent).toMatchObject({ status: 200, body: '{"id":"msg_1"}' })
  expect(sent).toHaveLength(2)
  vault.sequences.set("approval:apr_p1", [{ approval: "apr_p1", status: "approved", bindingCode: "K7Q2", summary: "Push", push: { destination: "github:acme/app/OPENAI_API_KEY", field: "key", version: 3, state: "done", outcome: "created" } }])
  const push = await call("vault_wait", { id: "apr_p1", execute: true, timeoutSeconds: 5 })
  expect(push.structuredContent).toMatchObject({ id: "apr_p1", kind: "approval", push: { state: "done" } })
  expect(sent).toHaveLength(2)
})

// The session label is a display label, not authority: a replay is signed
// with the label the request was held with, so the proof and the body
// agree with what the human saw, whatever MEHEN_SESSION says now.
test("a replay is signed with the saved session label, whether MEHEN_SESSION changed or is unset", async () => {
  for (const [round, now] of ([{ MEHEN_SESSION: "agent-2" }, {}] as Record<string, string>[]).entries()) {
    sent = []
    holdAs(`apr_round${round}`)
    await held()
    const { MEHEN_SESSION: _label, ...base } = env
    const resumed = await runJv(["fetch", "--resume", `apr_round${round}`, "--json"], { ...base, ...now })
    expect(resumed.code).toBe(EXIT.ok)
    expect(sent[1]?.session).toBe("agent-1")
    expect(vault.seen.at(-1)?.claims.sid).toBe("agent-1")
  }
  // Held with no label, resumed with one: the proof carries none either.
  const { MEHEN_SESSION: _label, ...unlabelled } = env
  sent = []
  holdAs("apr_unlabelled")
  await runJv(["fetch", "gmail-support", "POST", "https://gmail.googleapis.com/send", "-d", "{}"], unlabelled)
  expect(sent[0]?.session).toBeUndefined()
  expect((await runJv(["fetch", "--resume", "apr_unlabelled"], { ...unlabelled, MEHEN_SESSION: "agent-3" })).code).toBe(EXIT.ok)
  expect(sent[1]?.session).toBeUndefined()
  expect(vault.seen.at(-1)?.claims.sid).toBeUndefined()
})

test("vault_fetch and vault_wait replay with the saved session label too", async () => {
  await call("vault_fetch", { item: "gmail-support", method: "POST", url: "https://gmail.googleapis.com/send", body: "{}" })
  env = { ...env, MEHEN_SESSION: "agent-2" }
  expect((await call("vault_fetch", { approval: "apr_1" })).isError).toBe(false)
  expect(sent[1]?.session).toBe("agent-1")
  expect(vault.seen.at(-1)?.claims.sid).toBe("agent-1")
  env = { ...env, MEHEN_SESSION: "agent-1" }
  holdAs("apr_2")
  await call("vault_fetch", { item: "gmail-support", method: "POST", url: "https://gmail.googleapis.com/send", body: "{}" })
  vault.sequences.set("approval:apr_2", [{ approval: "apr_2", status: "approved", bindingCode: "K7Q2", summary: "Send an email" }])
  const { MEHEN_SESSION: _label, ...unset } = env
  env = unset
  expect((await call("vault_wait", { id: "apr_2", execute: true, timeoutSeconds: 5 })).isError).toBe(false)
  expect(sent.at(-1)?.session).toBe("agent-1")
  expect(vault.seen.at(-1)?.claims.sid).toBe("agent-1")
})

// Every check that can fail on this machine runs before the saved request
// is claimed: a failure sends nothing and keeps it for a corrected call.
test("a local failure before sending keeps the saved request, and the corrected call sends it exactly once", async () => {
  await held()
  const missing = join(dir.path, "no-such-folder", "out.json")
  const refused = await runJv(["fetch", "--resume", "apr_1", "-o", missing, "--json"], env)
  expect(refused.code).toBe(EXIT.usage)
  for (const bad of [["--select", "["], ["--max-time", "0"], ["--select", "a", "-o", join(dir.path, "x")]]) expect((await runJv(["fetch", "--resume", "apr_1", ...bad, "--json"], env)).code).toBe(EXIT.usage)
  expect(sent).toHaveLength(1)
  expect((await stat(join(cache(), "apr_1.json"))).isFile()).toBe(true)
  const written = join(dir.path, "out.json")
  expect((await runJv(["fetch", "--resume", "apr_1", "-o", written], env)).code).toBe(EXIT.ok)
  expect(await readFile(written, "utf8")).toBe('{"id":"msg_1"}')
  expect(sent).toHaveLength(2)
  expect((await runJv(["fetch", "--resume", "apr_1"], env)).code).toBe(EXIT.error)
  expect(sent).toHaveLength(2)
})

test("vault_fetch with a bad select keeps the saved request, and the corrected call sends it exactly once", async () => {
  await call("vault_fetch", { item: "gmail-support", method: "POST", url: "https://gmail.googleapis.com/send", body: "{}" })
  for (const args of [{ approval: "apr_1", select: "[" }, { approval: "apr_1", timeoutSeconds: 0 }]) expect((await call("vault_fetch", args)).structuredContent).toMatchObject({ error: "usage" })
  expect(sent).toHaveLength(1)
  expect((await stat(join(cache(), "apr_1.json"))).isFile()).toBe(true)
  expect((await call("vault_fetch", { approval: "apr_1", select: "id" })).structuredContent).toMatchObject({ selected: "msg_1", found: true })
  expect(sent).toHaveLength(2)
  expect((await call("vault_fetch", { approval: "apr_1" })).structuredContent).toMatchObject({ error: "replay_missing" })
  expect(sent).toHaveLength(2)
})

// The vault reuses one pending approval for identical asks: a duplicate
// request held after the first was sent again is not saved again, so it
// is never sent a second time.
test("an identical request held again after its approval was sent again is not saved, and resume sends nothing more", async () => {
  await held()
  expect((await runJv(["fetch", "--resume", "apr_1"], env)).code).toBe(EXIT.ok)
  const again = await held(["--json"])
  expect(json(again)).toMatchObject({ error: "approval_required", approval: "apr_1", replay: { saved: false, reason: expect.stringContaining("already sent again") } })
  expect((await runJv(["fetch", "--resume", "apr_1", "--json"], env)).code).toBe(EXIT.error)
  expect(sent.filter((request) => request.approval === "apr_1")).toHaveLength(1)
})
