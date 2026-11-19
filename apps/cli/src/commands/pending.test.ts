import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { EXIT } from "@mehen/protocol/api"
import { fingerprintOf } from "@mehen/protocol/fingerprint"
import { jwkThumbprint } from "@mehen/protocol/proof"
import { type AskUrl, approvalAsk, askUrl, enrolAsk, intakeAsk, withContext } from "../ask.ts"
import { pendingSlotPath } from "../home.ts"
import { addLedgerEntry, readLedger } from "../ledger.ts"
import { MOCK_OWNER, MOCK_WORKSPACE, MOCK_TENANT, MockVault } from "../testing/mock-vault.ts"
import { type JvResult, runJv, tempDir } from "../testing/run-mehen.ts"
import { pendingWorkspaceFixtures } from "../testing/pending-workspace-fixtures.ts"
import { PENDING_RESTRICTION_UNTIL, restrictionText } from "./pending.ts"

let vault: MockVault
const scope = () => vault.ledgerScope()
let dir: { path: string; remove(): Promise<void> }
let env: Record<string, string>

const by = { device: "test-box", session: "pi-1" }
const inAnHour = () => new Date(Date.now() + 3_600_000).toISOString()
const link = (path: string): AskUrl => (askUrl(`${vault.url}/w/mock-space${path}`, vault.askVault()) as { url: AskUrl }).url

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  vault.lastDevice = null
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url }
  vault.pending = null
  vault.notices = undefined
  vault.groups = undefined
})
afterEach(async () => dir.remove())

function json(result: JvResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>
}

async function seedLedger(): Promise<void> {
  await addLedgerEntry(vault.slotDir(dir.path), scope(), {
    ask: intakeAsk({ id: "int_3kQ9", url: link("/i/int_3kQ9"), name: "openai-new", kind: "api-key", provider: "openai", reason: "summarise the support inbox", expiresAt: inAnHour(), requestedBy: by }),
    slug: "openai-new",
    command: 'mehen request api-key --name openai-new --provider openai --reason "summarise the support inbox"',
  })
  await addLedgerEntry(vault.slotDir(dir.path), scope(), {
    ask: approvalAsk({ id: "apr_7Hq2", url: link("/a/apr_7Hq2"), summary: "Send an email to sam@example.com", item: "gmail-alex", bindingCode: "K7Q2MX", expiresAt: inAnHour(), requestedBy: by }),
  })
}

// The vault's own list confirming the two seeded asks, so they are current
// rather than stale.
function confirmLedger(): void {
  const requested = { device: vault.lastDevice ?? "test-box", deviceName: "test-box", session: "pi-1" }
  vault.pending = [
    { kind: "intake", id: "int_3kQ9", url: `${vault.url}/w/mock-space/i/int_3kQ9`, expiresAt: inAnHour(), requestedBy: requested, item: "openai-new", provider: "openai", kindRequested: "api-key" },
    { kind: "approval", id: "apr_7Hq2", url: `${vault.url}/w/mock-space/a/apr_7Hq2`, title: "Send an email to sam@example.com", expiresAt: inAnHour(), requestedBy: requested, item: "gmail-alex", bindingCode: "K7Q2MX" },
  ]
}

describe("mehen pending", () => {
  test("with nothing open it says so, enrolled or not", async () => {
    const before = await runJv(["pending"], env)
    expect(before.code).toBe(EXIT.ok)
    expect(before.stdout).toBe("Nothing is waiting for a human.\n")
    await vault.enrolSoftware(dir.path)
    expect((await runJv(["pending"], env)).stdout).toBe("Nothing is waiting for a human.\n")
    expect(json(await runJv(["pending", "--json"], env))).toEqual({ pending: [] })
  })

  test("lists the ledger's asks as a table, marked stale, when the server has no /v1/pending (404)", async () => {
    await vault.enrolSoftware(dir.path)
    await seedLedger()
    const result = await runJv(["pending"], env)
    expect(result.code).toBe(EXIT.ok)
    const lines = result.stdout.trimEnd().split("\n")
    expect(lines[0]).toMatch(/^KIND\s+ID\s+WHAT\s+EXPIRES\s+THEN$/)
    expect(lines[1]).toMatch(/^intake\s+int_3kQ9\s+add openai-new \(OpenAI API key, goes to api.openai.com\)\s+in (59|60) min \((tomorrow )?\d\d:\d\d\) \(stale\)\s+mehen wait int_3kQ9 --timeout 60 --json$/)
    expect(lines[2]).toMatch(/^approval\s+apr_7Hq2\s+send an email to sam@example.com, from gmail-alex\s+in (59|60) min \((tomorrow )?\d\d:\d\d\) \(stale\)\s+mehen wait apr_7Hq2 --timeout 60 --json$/)
    expect(vault.seen.at(-1)).toMatchObject({ method: "GET", path: "/v1/pending" })
  })

  test("re-shows one ask by id or by the slug it creates, as the ask block, without a QR off a TTY", async () => {
    await vault.enrolSoftware(dir.path)
    await seedLedger()
    confirmLedger()
    const byId = await runJv(["pending", "apr_7Hq2"], env)
    expect(byId.code).toBe(EXIT.ok)
    const lines = byId.stdout.trimEnd().split("\n")
    expect(lines[0]).toBe("Human needed: approve a request")
    expect(lines[1]).toBe(`  open:    ${vault.url}/w/mock-space/a/apr_7Hq2`)
    expect(lines[2]).toBe("  what:    Send an email to sam@example.com, from gmail-alex")
    expect(lines[3]).toBe("  check:   the page shows code K7Q2MX")
    expect(lines[5]).toBe("  then:    mehen wait apr_7Hq2 --timeout 60 --json")
    expect(byId.stdout).not.toMatch(/[\u2580\u2584\u2588]/)
    const bySlug = await runJv(["pending", "openai-new"], env)
    expect(bySlug.stdout).toContain(`  open:    ${vault.url}/w/mock-space/i/int_3kQ9`)
    expect(bySlug.stdout).toContain("  check:   the page says it was asked by test-box, session pi-1")
  })

  test("--json lists { pending: Ask[] } and one ask as { ask, next }, with notices only when there are any", async () => {
    await vault.enrolSoftware(dir.path)
    await seedLedger()
    confirmLedger()
    const list = json(await runJv(["pending", "--json"], env)) as { pending: { id: string; kind: string }[] }
    expect(list.pending.map((a) => a.id)).toEqual(["int_3kQ9", "apr_7Hq2"])
    expect(Object.keys(list.pending[0] ?? {}).sort()).toEqual(["account", "check", "context", "expiresAt", "id", "kind", "requestedBy", "title", "url", "wait", "what"])
    // Every ask carries the context of the slot it belongs to.
    expect((list.pending[0] as { context?: unknown }).context).toEqual({ origin: vault.url, workspace: MOCK_WORKSPACE, device: vault.lastDevice })
    const one = json(await runJv(["pending", "apr_7Hq2", "--json"], env)) as { ask: { id: string }; next: { url: string; command: string; say: string } }
    expect(one.ask.id).toBe("apr_7Hq2")
    expect(one).not.toHaveProperty("notices")
    expect(one.next).toMatchObject({ url: `${vault.url}/w/mock-space/a/apr_7Hq2`, command: "mehen wait apr_7Hq2 --timeout 60 --json" })
    expect(one.next.say).toContain("the page should show code K7Q2MX")
  })

  test("before enrolment the ledger alone answers, so a pending enrolment can be re-shown", async () => {
    // An enrolment entry carries its intent; its link is under that slug,
    // and it lives in that slug's pending slot.
    await addLedgerEntry(pendingSlotPath(dir.path, vault.url, "mock-space"), scope(), {
      ask: enrolAsk({ id: "enr_9m2kQ", url: link("/e/ABCD2345"), name: "test-mac", backend: "software", fingerprint: "ZLSQ 8ZY0 FNHK WLS5", expiresAt: inAnHour(), requestedBy: by }),
      enrol: { code: "ABCD2345", name: "test-mac", backend: "software", jwk: { kty: "EC", crv: "P-256", x: "x".repeat(43), y: "y".repeat(43) }, workspace: "mock-space", team: null },
    })
    const before = vault.seen.length
    const result = await runJv(["pending", "enr_9m2kQ"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(result.stdout).toContain("Human needed: approve this machine")
    // The fingerprint is the one of the key the pending slot holds, never the recorded text.
    const computed = fingerprintOf(await jwkThumbprint({ kty: "EC", crv: "P-256", x: "x".repeat(43), y: "y".repeat(43) }))
    expect(result.stdout).toContain(`  check:   the page shows fingerprint  ${computed}`)
    expect(vault.seen.length).toBe(before)
  })

  // The server's entries carry the V-7 shape: `title` (one sentence), `item`
  // (the slug the ask concerns) and `requestedBy` as recorded when the ask
  // was made.
  test("uses GET /v1/pending when the server has it, merging the ledger's richer ask and adding what only the server knows", async () => {
    await vault.enrolSoftware(dir.path)
    await seedLedger()
    const asked = { device: "dev_other", deviceName: "sam-mac-mini", session: "pi-4f2a" }
    vault.pending = [
      { kind: "approval", id: "apr_7Hq2", url: `${vault.url}/w/mock-space/a/apr_7Hq2`, title: "Send an email to sam@example.com", expiresAt: "2026-10-24T17:12:00.000Z", requestedBy: asked, item: "gmail-alex", bindingCode: "K7Q2MX" },
      { kind: "approval", id: "apr_other", url: `${vault.url}/w/mock-space/a/apr_other`, title: "Delete a message", expiresAt: "2026-10-24T17:30:00.000Z", requestedBy: asked, item: "gmail-alex", bindingCode: "P8RT2W" },
      { kind: "approval", id: "apr_run", url: `${vault.url}/w/mock-space/a/apr_run`, title: "Run my-project in production", expiresAt: "2026-10-24T17:40:00.000Z", requestedBy: asked, item: null, bindingCode: "R4NN3R" },
      { kind: "connect", id: "con_srv", url: `${vault.url}/w/mock-space/c/con_srv`, title: "Connect gmail-work to Gmail as work@example.com", expiresAt: null, requestedBy: { ...asked, session: null }, item: "gmail-work", provider: "google-gmail", account: "work@example.com" },
      { kind: "intake", id: "int_srv", url: `${vault.url}/w/mock-space/i/int_srv`, title: "Paste the OpenAI API key for openai-work", expiresAt: null, requestedBy: null, item: "openai-work", provider: "openai", kindRequested: "api-key" },
    ]
    const list = json(await runJv(["pending", "--json"], env)) as { pending: { id: string; kind: string; what: string; check: unknown; expiresAt: string | null; requestedBy: unknown }[] }
    expect(list.pending.map((a) => a.id)).toEqual(["apr_7Hq2", "apr_other", "apr_run", "con_srv", "int_srv", "int_3kQ9"])
    // The ledger's ask wins on what and check; the server's expiry is taken.
    expect(list.pending[0]).toMatchObject({ what: "Send an email to sam@example.com, from gmail-alex", expiresAt: "2026-10-24T17:12:00.000Z", requestedBy: by })
    expect(list.pending[1]).toMatchObject({ kind: "approval", what: "Delete a message, from gmail-alex", check: { label: "code", value: "P8RT2W" }, requestedBy: { device: "sam-mac-mini", session: "pi-4f2a" } })
    expect(list.pending[2]).toMatchObject({ kind: "approval", what: "Run my-project in production", check: { label: "code", value: "R4NN3R" } })
    expect(list.pending[3]).toMatchObject({ kind: "connect", what: "Connect gmail-work to Gmail as work@example.com", check: { label: "account", value: "work@example.com" }, expiresAt: null, requestedBy: { device: "sam-mac-mini", session: null } })
    // No requestedBy from the server: this machine's own name stands in.
    expect(list.pending[4]).toMatchObject({ kind: "intake", what: "Add openai-work (OpenAI API key, goes to api.openai.com)", requestedBy: { session: null } })
    expect((list.pending[4]?.requestedBy as { device: string }).device).not.toBe("")
    const bySlug = await runJv(["pending", "gmail-work"], env)
    expect(bySlug.stdout).toContain(`  open:    ${vault.url}/w/mock-space/c/con_srv`)
    const byItem = await runJv(["pending", "openai-work"], env)
    expect(byItem.stdout).toContain(`  open:    ${vault.url}/w/mock-space/i/int_srv`)
    // A hostile title or session label from the server is spelled out, never obeyed.
    vault.pending = [{ kind: "approval", id: "apr_bad", url: `${vault.url}/w/mock-space/a/apr_bad`, title: "Send\u001b[2K\u001b[32m allowed\u202e", expiresAt: null, requestedBy: { device: "d", deviceName: "box\u001b[A", session: "s\u200b" }, item: null, bindingCode: "K7Q2MX" }]
    const human = await runJv(["pending", "apr_bad"], env)
    expect(human.stdout).not.toContain("\u001b")
    expect(human.stdout).not.toContain("\u202e")
    expect(human.stdout).toContain("  what:    Send\\u001B[2K\\u001B[32m allowed[RLO U+202E]")
  })

  test("a server entry whose link is not on the vault is rebuilt from its id with a warning; the foreign link is never shown", async () => {
    await vault.enrolSoftware(dir.path)
    const foreign = [
      "https://evil.example/a/apr_f1",
      `${vault.url.replace("127.0.0.1", "127.0.0.1.evil.example")}/a/apr_f2`,
      `${vault.url.replace("http://", "http://vault@")}/a/apr_f3`,
      `${vault.url.replace(/:\d+$/, ":1")}/a/apr_f4`,
      `${vault.url.replace("http://", "https://")}/a/apr_f5`,
      `${vault.url}/w/mock-space/a/apr_f6\u200b`,
    ]
    vault.pending = foreign.map((url, i) => ({ kind: "approval" as const, id: `apr_f${i + 1}`, url, expiresAt: null, bindingCode: "K7Q2MX", title: "Send" }))
    const list = await runJv(["pending", "--json"], env)
    expect(list.code).toBe(EXIT.ok)
    expect(list.stdout).not.toContain("evil.example")
    expect(list.stdout).not.toContain("\u200b")
    expect(list.stdout).not.toContain("vault@")
    expect(list.stdout).not.toContain("https://")
    const asks = (json(list) as { pending: { id: string; url: string }[] }).pending
    expect(asks.map((a) => a.url)).toEqual(foreign.map((_, i) => `${vault.url}/w/mock-space/a/apr_f${i + 1}`))
    expect(list.stderr).toContain("warning: 6 pending entries came with a link not on the vault")
    const human = await runJv(["pending"], env)
    expect(human.stdout).not.toContain("evil.example")
    expect(human.stderr).toContain("warning:")
    const one = await runJv(["pending", "apr_f1"], env)
    expect(one.stdout).toContain(`  open:    ${vault.url}/w/mock-space/a/apr_f1`)
    expect(one.stdout).not.toContain("evil.example")
  })

  test("a hostile ledger file cannot put a foreign link or a terminal escape in front of a human", async () => {
    const device = await vault.enrolSoftware(dir.path)
    const identity = { origin: vault.url, workspace: MOCK_TENANT, device }
    const good = approvalAsk({ id: "apr_ok", url: link("/a/apr_ok"), summary: "Send\u001b[2K\u001b[32m allowed\u202e", bindingCode: "K7\u200bQ2", expiresAt: inAnHour(), requestedBy: by })
    const entries = [
      { ask: { ...good, id: "apr_evil", url: "https://evil.example/a/apr_evil", title: "Approve\u001b[2J a request" }, createdAt: new Date().toISOString(), ...identity, slug: null, command: null },
      { ask: { ...good, title: "Approve\u001b[31m a request\u200b\uFFFE[31m", wait: "mehen wait apr_ok\u001b[A" }, createdAt: new Date().toISOString(), ...identity, slug: null, command: null },
      // An entry another context wrote (another workspace) never reaches this one's human.
      { ask: { ...good, id: "apr_other", title: "Approve another workspace's request" }, createdAt: new Date().toISOString(), ...identity, workspace: "tn_other000000001", slug: null, command: null },
    ]
    await Bun.write(`${vault.slotDir(dir.path)}/ledger.json`, JSON.stringify({ entries }))
    const human = await runJv(["pending"], env)
    expect(human.code).toBe(EXIT.ok)
    expect(human.stdout).not.toContain("evil.example")
    expect(human.stdout).not.toContain("\u001b")
    expect(human.stdout).not.toContain("\u202e")
    expect(human.stdout).toContain("mehen wait apr_ok\\u001B[A")
    expect(human.stdout).not.toContain("apr_other")
    expect(human.stdout).toContain("send\\u001B[2K\\u001B[32m allowed[RLO U+202E]")
    const block = await runJv(["pending", "apr_ok"], env)
    expect(block.stdout).not.toContain("\u001b")
    // Only the vault could confirm it, and it has no list: it is stale.
    expect(block.stdout.split("\n").slice(0, 2)).toEqual(["(stale: may be settled)", "Human needed: approve\\u001B[31m a request[ZWSP U+200B][NONCHAR U+FFFE][31m"])
    expect(block.stdout).not.toContain("\uFFFE")
    expect(block.stdout).toContain("the page shows code K7[ZWSP U+200B]Q2")
    expect(block.stdout).toContain("then:    mehen wait apr_ok\\u001B[A")
    expect((await runJv(["pending", "apr_evil"], env)).code).toBe(EXIT.error)
  })

  test("a server entry whose id is not one mehen knows is left out and counted; a link whose route is another id is rebuilt", async () => {
    await vault.enrolSoftware(dir.path)
    vault.pending = [
      { kind: "approval", id: "apr_1/../x", url: `${vault.url}/w/mock-space/a/apr_1`, expiresAt: null, bindingCode: "K7Q2MX", title: "Send" },
      { kind: "approval", id: "int_1", url: `${vault.url}/w/mock-space/a/int_1`, expiresAt: null, bindingCode: "K7Q2MX", title: "Send" },
      { kind: "approval", id: "apr_ok", url: `${vault.url}/w/mock-space/a/apr_other`, expiresAt: null, bindingCode: "K7Q2MX", title: "Send" },
    ]
    const list = await runJv(["pending", "--json"], env)
    const asks = (json(list) as { pending: { id: string; url: string }[] }).pending
    expect(asks).toEqual([expect.objectContaining({ id: "apr_ok", url: `${vault.url}/w/mock-space/a/apr_ok` })])
    expect(list.stdout).not.toContain("../")
    expect(list.stderr).toContain("warning: 3 pending entries came with a link not on the vault or an id mehen does not know")
    // A ledger entry whose id does not fit its kind is dropped on read.
    await Bun.write(`${vault.slotDir(dir.path)}/ledger.json`, JSON.stringify({ entries: [{ ask: { ...approvalAsk({ id: "apr_1", url: link("/a/apr_1"), summary: "s", bindingCode: null, expiresAt: inAnHour(), requestedBy: by }), id: "apr_1\u001b[A" }, createdAt: new Date().toISOString(), slug: null, command: null }] }))
    expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])
  })

  test("a server entry without a binding code gets no check: nothing is invented", async () => {
    await vault.enrolSoftware(dir.path)
    vault.pending = [{ kind: "approval", id: "apr_bare", url: `${vault.url}/w/mock-space/a/apr_bare`, expiresAt: null }]
    const list = json(await runJv(["pending", "--json"], env)) as { pending: { check: unknown; expiresAt: unknown }[] }
    expect(list.pending[0]).toMatchObject({ check: null, expiresAt: null })
  })

  test("an unknown id exits 1 and points at mehen pending", async () => {
    await vault.enrolSoftware(dir.path)
    const result = await runJv(["pending", "apr_nothing", "--json"], env)
    expect(result.code).toBe(EXIT.error)
    expect(json(result)).toMatchObject({ error: "not_found", next: { command: "mehen pending" } })
  })

  test("expired ledger entries are pruned and never listed", async () => {
    await vault.enrolSoftware(dir.path)
    await addLedgerEntry(vault.slotDir(dir.path), scope(), {
      ask: approvalAsk({ id: "apr_old", url: link("/a/apr_old"), summary: "Old", bindingCode: "A1B2C3", expiresAt: new Date(Date.now() - 1000).toISOString(), requestedBy: by }),
    })
    await seedLedger()
    expect((await readLedger(vault.slotDir(dir.path), scope())).map((e) => e.ask.id)).toEqual(["int_3kQ9", "apr_7Hq2"])
    expect((await runJv(["pending"], env)).stdout).not.toContain("apr_old")
  })
})

describe("mehen pending review groups", () => {
  const asked = { device: "dev_mock1", deviceName: "sam-mac-mini", session: null }
  const approvals = (ids: string[]) => ids.map((id) => ({ kind: "approval" as const, id, url: `${vault.url}/w/mock-space/a/${id}`, title: `Create ${id}`, expiresAt: null, requestedBy: asked, item: "cloudflare", bindingCode: "K7Q2MX" }))

  test("--json carries each ask's group and the top-level groups; rows keep their shape and human output adds one line per group", async () => {
    await vault.enrolSoftware(dir.path)
    vault.pending = approvals(["apr_g1", "apr_g2", "apr_g3", "apr_solo"])
    const groupUrl = `${vault.url}/w/mock-space/g/grp_Q2mX9`
    vault.groups = [{ id: "grp_Q2mX9", url: groupUrl, approvals: ["apr_g1", "apr_g2", "apr_g3"], bundle: false }]
    const list = json(await runJv(["pending", "--json"], env)) as { pending: Record<string, unknown>[]; groups: unknown[] }
    expect(list.groups).toEqual([{ id: "grp_Q2mX9", url: groupUrl, approvals: ["apr_g1", "apr_g2", "apr_g3"], bundle: false }])
    expect(list.pending.slice(0, 3).map((a) => a.group)).toEqual(Array(3).fill({ id: "grp_Q2mX9", url: groupUrl, open: 3 }))
    expect(list.pending[3]).not.toHaveProperty("group")
    const { group: _group, ...row } = list.pending[0] as { group: unknown }
    vault.groups = undefined
    const ungrouped = json(await runJv(["pending", "--json"], env)) as { pending: Record<string, unknown>[] }
    expect(ungrouped).not.toHaveProperty("groups")
    expect(ungrouped.pending[0]).toEqual(row)
    vault.groups = [{ id: "grp_Q2mX9", url: groupUrl, approvals: ["apr_g1", "apr_g2", "apr_g3"], bundle: false }]
    const human = await runJv(["pending"], env)
    const lines = human.stdout.trimEnd().split("\n")
    expect(lines.filter((l) => l.startsWith("approval"))).toHaveLength(4)
    expect(lines.at(-1)).toBe(`3 asks from sam-mac-mini: review together at ${groupUrl}`)
    expect(json(await runJv(["pending", "apr_g2", "--json"], env)).ask).toMatchObject({ id: "apr_g2", group: { id: "grp_Q2mX9", url: groupUrl, open: 3 } })
  })

  test("a group whose link is off this vault or not its own /g/ page is left out and counted, a malformed one is left out, and neither is shown", async () => {
    await vault.enrolSoftware(dir.path)
    vault.pending = approvals(["apr_g1", "apr_g2"])
    const ids = ["apr_g1", "apr_g2"]
    vault.groups = [
      { id: "grp_a", url: "https://evil.example/w/mock-space/g/grp_a", approvals: ids, bundle: false },
      { id: "grp_b", url: `${vault.url}/w/mock-space/g/grp_other`, approvals: ids, bundle: false },
      { id: "grp_c", url: `${vault.url}/w/mock-space/g/grp_c`, approvals: ["apr_g1", "int_x"], bundle: false },
      "grp_d",
    ]
    const result = await runJv(["pending", "--json"], env)
    const list = json(result) as { pending: Record<string, unknown>[] }
    expect(list).not.toHaveProperty("groups")
    for (const ask of list.pending) expect(ask).not.toHaveProperty("group")
    expect(result.stdout).not.toContain("evil.example")
    expect(result.stderr).toContain("2 pending entries came with a link not on the vault")
    const human = await runJv(["pending"], env)
    expect(human.stdout).not.toContain("review together")
    expect(human.stdout).not.toContain("evil.example")
  })
})


function securityNotice(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    notice: "ntc_test", kind: "recovery", member: "mem_alex", memberName: "Alex",
    at: "2026-10-25T14:02:00.000Z", client: "Safari on Mac", place: "Amsterdam, NL",
    restrictedUntil: "2026-10-26T14:02:00.000Z", url: `${vault.url}/settings#security`, ...extra,
  }
}

describe("mehen pending security notices", () => {
  test("notices come before asks, in JSON and text, including when re-showing one ask", async () => {
    await vault.enrolSoftware(dir.path)
    await seedLedger()
    vault.pending = []
    vault.notices = [securityNotice(), securityNotice({ notice: "ntc_reset", kind: "reset" }), securityNotice({ notice: "ntc_break", kind: "break-glass" })]
    const result = await runJv(["pending"], env)
    expect(result.code).toBe(0)
    expect(result.stdout.split("\n")[0]).toBe(`Security: Alex's sign-in was recovered with a recovery code at 14:02 UTC on 2026-10-25 using Safari on Mac from Amsterdam, NL. Wider actions stay restricted until 14:02 UTC on 2026-10-26. Not expected? Open ${vault.url}/settings#security with an older passkey.`)
    expect(result.stdout.indexOf("Security:")).toBeLessThan(result.stdout.indexOf("KIND"))
    expect(result.stdout).toContain("with a reset link")
    expect(result.stdout).toContain("with a break-glass reset link")
    const list = json(await runJv(["pending", "--json"], env))
    expect(list.notices).toEqual(vault.notices)
    const one = await runJv(["pending", "apr_7Hq2"], env)
    expect(one.stdout.indexOf("Security:")).toBeLessThan(one.stdout.indexOf("Human needed:"))
    expect(json(await runJv(["pending", "apr_7Hq2", "--json"], env)).notices).toEqual(vault.notices)
  })

  test("a pending restriction (the PENDING_RESTRICTION_UNTIL sentinel) reads as until recovery completes, never as a date, in text and through MCP", async () => {
    await vault.enrolSoftware(dir.path)
    vault.pending = []
    for (const sentinel of [PENDING_RESTRICTION_UNTIL, String(PENDING_RESTRICTION_UNTIL)]) {
      vault.notices = [securityNotice({ restrictedUntil: sentinel })]
      const result = await runJv(["pending"], env)
      expect(result.code).toBe(0)
      expect(result.stdout.split("\n")[0]).toContain(" Wider actions stay restricted until recovery completes. Not expected?")
      expect(result.stdout).not.toContain(String(PENDING_RESTRICTION_UNTIL))
      expect(result.stdout).not.toMatch(/\d{4}-\d{2}-\d{2}T/)
      // JSON keeps the sentinel as the vault sent it: not a date either.
      expect((json(await runJv(["pending", "--json"], env)).notices as { restrictedUntil: unknown }[])[0]?.restrictedUntil).toBe(sentinel)
    }
    expect(PENDING_RESTRICTION_UNTIL).toBe(Number.MAX_SAFE_INTEGER)
    expect(restrictionText(null)).toBeNull()
    expect(restrictionText("2026-10-26T14:02:00.000Z")).toBe("until 14:02 UTC on 2026-10-26")
    // Any other number is not a time the notice can state: the notice is left out.
    vault.notices = [securityNotice({ restrictedUntil: 1_700_000_000_000 })]
    expect(json(await runJv(["pending", "--json"], env))).toEqual({ pending: [] })
  })

  test("notices alone are shown instead of an empty pending message; old vaults still work", async () => {
    await vault.enrolSoftware(dir.path)
    vault.pending = []
    vault.notices = [securityNotice({ client: null, place: null, restrictedUntil: null })]
    const result = await runJv(["pending"], env)
    expect(result.stdout).toStartWith("Security:")
    expect(result.stdout).not.toContain("Nothing is waiting")
    expect(result.stdout).not.toContain("null")
    vault.notices = undefined
    expect(json(await runJv(["pending", "--json"], env))).toEqual({ pending: [] })
  })

  test("joins, unknown notices and resolution powers never reach device output", async () => {
    await vault.enrolSoftware(dir.path)
    vault.pending = []
    vault.notices = [securityNotice({ canResolve: true, codes: ["DO-NOT-LEAK"] }), securityNotice({ notice: "ntc_join", kind: "join", memberName: "Hidden join" }), securityNotice({ kind: "unknown" }), securityNotice({ at: "not a date" }), null]
    const result = await runJv(["pending", "--json"], env)
    expect(json(result).notices).toEqual([securityNotice()])
    expect(result.stdout).not.toMatch(/canResolve|Hidden join|DO-NOT-LEAK|ntc_join/)
    const human = await runJv(["pending"], env)
    expect(human.stdout).not.toMatch(/canResolve|Hidden join|DO-NOT-LEAK|ntc_join/)
  })

  test("hostile names, clients and places cannot inject terminal controls or extra lines, and are capped", async () => {
    await vault.enrolSoftware(dir.path)
    vault.pending = []
    vault.notices = [securityNotice({ memberName: "Alex\n\u001b[2Jmehen: forged\u202e", client: "browser\r\nmehen: fake", place: "Amsterdam\n\u001b[31mNL\u200b" + "x".repeat(1000) })]
    const human = await runJv(["pending"], env)
    expect(human.stdout.trimEnd().split("\n")).toHaveLength(1)
    expect(human.stdout).not.toMatch(/[\u001b\u202e\u200b\r]/)
    expect(human.stdout).toContain("Alex\\u000A\\u001B[2Jmehen: forged[RLO U+202E]")
    expect(human.stdout).toContain("Amsterdam\\u000A\\u001B[31mNL[ZWSP U+200B]")
    const list = json(await runJv(["pending", "--json"], env)) as { notices: { place: string }[] }
    expect(list.notices[0]?.place.length).toBe(64)
  })

  test("a refused notice link is rebuilt and warned about, never passed through", async () => {
    await vault.enrolSoftware(dir.path)
    vault.pending = []
    const refused = ["https://evil.example/settings#security", `${vault.url}/settings#other`, `${vault.url}/settings?x=1#security`, `${vault.url}/settingsx#security`, `${vault.url}/w/mock-space/a/apr_test#security`, `${vault.url}/settings#security\u200b`]
    vault.notices = refused.map((url, i) => securityNotice({ notice: `ntc_${i}`, url }))
    for (const args of [["pending"], ["pending", "--json"]]) {
      const result = await runJv(args, env)
      expect(result.code).toBe(0)
      expect(result.stdout).not.toMatch(/evil.example|#other|\?x=1|settingsx|apr_test|\u200b/)
      expect(result.stderr).toContain("warning: 6 pending entries")
      expect(result.stdout).toContain(`${vault.url}/settings#security`)
    }
  })
})

test("a URL-shaped name or place stays metadata, never the notice's link", async () => {
  await vault.enrolSoftware(dir.path)
  vault.pending = []
  vault.notices = [securityNotice({ memberName: "https://evil.example", place: "https://else.example" })]
  const human = await runJv(["pending"], env)
  expect(human.stdout.trimEnd().split("\n")).toHaveLength(1)
  expect(human.stdout).toStartWith("Security: https://evil.example's sign-in was recovered")
  expect(human.stdout).toContain(` from https://else.example. Wider actions stay restricted until 14:02 UTC on 2026-10-26. Not expected? Open ${vault.url}/settings#security with an older passkey.`)
  const result = json(await runJv(["pending", "--json"], env)) as { notices: { url: string }[] }
  expect(result.notices[0]?.url).toBe(`${vault.url}/settings#security`)
})

test("policy asks use the recorded requester, code, summary, expiry and checked /p/ link", async () => {
  await vault.enrolSoftware(dir.path)
  const expiresAt = inAnHour()
  vault.overrides.set("GET /v1/pending", () => Response.json({ pending: [{ kind: "policy", id: "pol_test", url: `${vault.url}/w/mock-space/p/pol_test`, item: "example-key", title: "Relax project issues", bindingCode: "CODE42", expiresAt, requestedBy: { device: "dev_old", deviceName: "old-machine", session: "old-session" } }] }))
  try {
    const result = await runJv(["pending", "pol_test", "--json"], env)
    expect(result.code).toBe(0)
    expect(json(result)).toMatchObject({ ask: { kind: "policy", id: "pol_test", url: `${vault.url}/w/mock-space/p/pol_test`, what: "Relax project issues", expiresAt, check: { label: "code", value: "CODE42" }, requestedBy: { device: "old-machine", session: "old-session" }, wait: "mehen wait pol_test --timeout 60 --json" } })
  } finally { vault.overrides.clear() }
})

test("an adoption batch is listed with its count and checked /b/ link", async () => {
  await vault.enrolSoftware(dir.path)
  const expiresAt = inAnHour()
  vault.overrides.set("GET /v1/pending", () => Response.json({ pending: [{ kind: "adoption", id: "adp_test", url: `${vault.url}/w/mock-space/b/adp_test`, item: null, title: "Adopt 212 credentials", items: 212, expiresAt, requestedBy: { device: "dev_old", deviceName: "sam-mac-mini", session: null } }, { kind: "adoption", id: "adp_bad", url: `${vault.url}/w/mock-space/i/adp_bad` }] }))
  try {
    const result = await runJv(["pending", "adp_test", "--json"], env)
    expect(result.code).toBe(0)
    expect(json(result)).toMatchObject({ ask: { kind: "adoption", id: "adp_test", url: `${vault.url}/w/mock-space/b/adp_test`, what: "Review and approve 212 credentials adopted from sam-mac-mini; they go into the vault, never to the agent", expiresAt, wait: "mehen wait adp_test --timeout 60 --json" } })
    const listed = json(await runJv(["pending", "--json"], env)) as { pending: { id: string; url: string }[] }
    expect(listed.pending.map((p) => [p.id, p.url])).toEqual([["adp_test", `${vault.url}/w/mock-space/b/adp_test`], ["adp_bad", `${vault.url}/w/mock-space/b/adp_bad`]])
  } finally { vault.overrides.clear() }
})

test("refusal/device pending excludes member-only policy-review and malformed policy links", async () => {
  await vault.enrolSoftware(dir.path)
  vault.overrides.set("GET /v1/pending", () => Response.json({ pending: [{ kind: "policy-review", id: "pov_test", url: `${vault.url}/policy/overrides/pov_test` }, { kind: "policy", id: "pol_bad/next", url: `${vault.url}/w/mock-space/p/pol_bad/next` }, { kind: "policy", id: "pol_test", url: "https://evil.example/p/pol_test", title: "Review", bindingCode: "CODE42", expiresAt: inAnHour() }] }))
  try {
    const result = await runJv(["pending", "--json"], env)
    const pending = json(result).pending as { id: string; url: string }[]
    expect(pending.map((a) => a.id)).toEqual(["pol_test"])
    expect(pending[0]?.url).toBe(`${vault.url}/w/mock-space/p/pol_test`)
    expect(result.stderr).toContain("warning")
    expect(result.stdout).not.toContain("evil.example")
  } finally { vault.overrides.clear() }
})

test("workspace pending normalisation stays wired into listPending", async () => {
  const source = await Bun.file(new URL("./pending.ts", import.meta.url)).text()
  expect(source).toContain("normaliseWorkspacePending(listed, context)")
})

test("mehen pending displays only the own workspace ask and own machine notice, skipping foreign, stop and unknown projections", async () => {
  await vault.enrolSoftware(dir.path)
  const fixture = pendingWorkspaceFixtures(vault.url, MOCK_WORKSPACE, vault.lastDevice!, MOCK_OWNER)
  const notices = [fixture.machine, { ...fixture.machine, payload: { ...fixture.machine.payload, device: "dev_foreign" } }, { ...fixture.machine, payload: { ...fixture.machine.payload, workspace: { ...MOCK_WORKSPACE, id: "tn_foreign0000001" } } }, { ...fixture.machine, payload: { kind: "account_security" } }, { ...fixture.machine, payload: { ...fixture.machine.payload, kind: "unknown" } }]
  vault.overrides.set("GET /v1/pending", () => Response.json({ pending: fixture.pending, notices }))
  try {
    const expected = withContext(intakeAsk({ id: "int_workspace", url: link("/i/int_workspace"), name: "workspace-key", kind: "api-key", provider: "openai", reason: null, expiresAt: "2030-01-01T00:00:00.000Z", requestedBy: { device: "workspace-machine", session: null } }), { origin: vault.url, workspace: MOCK_WORKSPACE, device: vault.lastDevice! })
    const result = await runJv(["pending", "--json"], env)
    expect(result.code).toBe(0)
    expect(json(result)).toEqual({ pending: [expected], notices: [fixture.machine] })
    const human = await runJv(["pending"], env)
    expect(human.code).toBe(0)
    expect(human.stdout.split("\n")[0]).toBe(`Machine added on 2026-10-27: this machine, workspace-machine (${vault.lastDevice}), in Mock Space (mock-space) at ${vault.url}. Open ${fixture.machine.url} to review it.`)
    expect(human.stdout).not.toMatch(/foreign|int_stopped|unknown|int_other|dev_other/)
  } finally { vault.overrides.clear() }
})

test("workspace pending and machine notices reject extra fields and untrusted links never reach output", async () => {
  await vault.enrolSoftware(dir.path)
  const fixture = pendingWorkspaceFixtures(vault.url, MOCK_WORKSPACE, vault.lastDevice!, MOCK_OWNER)
  vault.overrides.set("GET /v1/pending", () => Response.json({ pending: [{ ...fixture.own, secret: "DO-NOT-LEAK" }, { ...fixture.own, detail: { ...fixture.own.detail, secret: "DO-NOT-LEAK" } }], notices: [{ ...fixture.machine, secret: "DO-NOT-LEAK" }, { ...fixture.machine, url: "https://evil.example/machine" }] }))
  try {
    const result = await runJv(["pending", "--json"], env)
    expect(json(result)).toEqual({ pending: [], notices: [fixture.machine] })
    expect(result.stdout).not.toMatch(/DO-NOT-LEAK|evil.example/)
    expect(result.stderr).toContain("warning")
  } finally { vault.overrides.clear() }
})

// Pending spans the allowed set, every ask with its context.
describe("mehen pending across workspaces", () => {
  const SECOND = { id: "tn_second00000001", slug: "second-space", name: "Second Space" }

  test("every active slot's asks, then every pending slot's enrol ask with its intent; a ceiling leaves the rest out", async () => {
    const a = await vault.enrolSoftware(dir.path)
    await seedLedger()
    const b = await vault.enrolSoftware(dir.path, { config: { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name } })
    const secondScope = { vaultUrl: vault.url, workspace: SECOND.id, device: b, workspaceSlug: SECOND.slug }
    const secondLink = (askUrl(`${vault.url}/w/${SECOND.slug}/a/apr_second1`, { vaultUrl: vault.url, workspaceSlug: SECOND.slug }) as { url: AskUrl }).url
    await addLedgerEntry(vault.slotDir(dir.path, SECOND.id), secondScope, { ask: approvalAsk({ id: "apr_second1", url: secondLink, summary: "Deploy", bindingCode: "Q2MXK7", expiresAt: inAnHour(), requestedBy: by }) })
    const enrol = await runJv(["enrol", "--workspace", "personal", "--json"], env)
    const enrolment = (json(enrol) as { enrolment: string }).enrolment
    const list = json(await runJv(["pending", "--json"], env)) as { pending: { id: string; context?: { workspace: { id: string } | null; device: string | null }; intent?: unknown }[] }
    expect(list.pending.map((p) => [p.id, p.context?.workspace?.id ?? null, p.context?.device ?? null])).toEqual([
      ["int_3kQ9", MOCK_TENANT, a],
      ["apr_7Hq2", MOCK_TENANT, a],
      ["apr_second1", SECOND.id, b],
      [enrolment, null, null],
    ])
    expect(list.pending.at(-1)?.intent).toEqual({ workspace: "personal", team: null })
    const narrowed = json(await runJv(["pending", "--json"], { ...env, MEHEN_WORKSPACES: SECOND.slug })) as { pending: { id: string }[] }
    expect(narrowed.pending.map((p) => p.id)).toEqual(["apr_second1"])
  })

  // A refusing vault never hides another workspace's enrolment.
  test("a revoked active workspace and a pending one: the pending enrolment is returned with its context and intent, and the refused workspace is named", async () => {
    const a = await vault.enrolSoftware(dir.path)
    const enrol = await runJv(["enrol", "--workspace", "personal", "--json"], env)
    const enrolment = (json(enrol) as { enrolment: string }).enrolment
    const record = vault.devices.get(a)
    if (record) record.revoked = true
    const result = await runJv(["pending", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const list = json(result) as { pending: { id: string; intent?: unknown; context?: unknown }[] }
    expect(list.pending.map((p) => p.id)).toEqual([enrolment])
    expect(list.pending[0]).toMatchObject({ intent: { workspace: "personal", team: null }, context: { origin: vault.url, workspace: null, device: null } })
    expect(result.stderr).toContain(`the vault for ${vault.slotDir(dir.path)} could not be asked (device_revoked`)
  })

  test("offline, the asks this machine recorded are listed marked stale with a warning, not refused", async () => {
    const shared = vault
    vault = new MockVault()
    try {
      const offline = { ...env, MEHEN_VAULT_URL: vault.url }
      await vault.enrolSoftware(dir.path)
      await seedLedger()
      vault.stop()
      const result = await runJv(["pending", "--json"], offline)
      expect(result.code).toBe(EXIT.ok)
      const listed = (json(result) as { pending: { id: string; stale?: boolean }[] }).pending
      expect(listed.map((p) => [p.id, p.stale])).toEqual([["int_3kQ9", true], ["apr_7Hq2", true]])
      expect(result.stderr).toContain("could not be asked (network")
      const human = await runJv(["pending"], offline)
      expect(human.stdout.split("\n").filter((line) => line.includes("(stale)")).map((line) => line.split(/\s+/)[1])).toEqual(["int_3kQ9", "apr_7Hq2"])
      expect(json(await runJv(["pending", "apr_7Hq2", "--json"], offline))).toMatchObject({ ask: { id: "apr_7Hq2", stale: true } })
    } finally {
      vault = shared
    }
  })

  test("offline, mehen pending <id> hands a stale ask over as a check-first step, never as a live link", async () => {
    const shared = vault
    vault = new MockVault()
    try {
      const offline = { ...env, MEHEN_VAULT_URL: vault.url }
      await vault.enrolSoftware(dir.path)
      await seedLedger()
      vault.stop()
      const result = await runJv(["pending", "apr_7Hq2", "--json"], offline)
      expect((json(result) as { next: unknown }).next).toEqual({ say: "The vault did not confirm this ask is open; it may already be settled. Do not hand the link over as live: run mehen pending again once the vault answers." })
      expect(result.stderr).toContain("the vault may have settled them")
      const human = await runJv(["pending", "apr_7Hq2"], offline)
      expect(human.stdout.split("\n")[0]).toBe("(stale: may be settled)")
    } finally {
      vault = shared
    }
  })

  test("a workspace whose vault refuses is listed from its ledger with a warning; when every vault refuses, the refusal is the answer", async () => {
    const a = await vault.enrolSoftware(dir.path)
    await seedLedger()
    const b = await vault.enrolSoftware(dir.path, { config: { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name } })
    const secondScope = { vaultUrl: vault.url, workspace: SECOND.id, device: b, workspaceSlug: SECOND.slug }
    const secondLink = (askUrl(`${vault.url}/w/${SECOND.slug}/a/apr_second1`, { vaultUrl: vault.url, workspaceSlug: SECOND.slug }) as { url: AskUrl }).url
    await addLedgerEntry(vault.slotDir(dir.path, SECOND.id), secondScope, { ask: approvalAsk({ id: "apr_second1", url: secondLink, summary: "Deploy", bindingCode: "Q2MXK7", expiresAt: inAnHour(), requestedBy: by }) })
    // The first vault answers and lists one of its two; the second refuses.
    confirmLedger()
    vault.pending = vault.pending!.filter((p) => p.id === "int_3kQ9")
    const record = vault.devices.get(b)
    if (record) record.revoked = true
    const partly = await runJv(["pending", "--json"], env)
    expect(partly.code).toBe(EXIT.ok)
    // Only what a vault confirmed is current; the rest may be settled.
    expect((json(partly) as { pending: { id: string; stale?: true }[] }).pending.map((p) => [p.id, p.stale])).toEqual([["int_3kQ9", undefined], ["apr_7Hq2", true], ["apr_second1", true]])
    for (const id of ["apr_7Hq2", "apr_second1"]) expect(json(await runJv(["pending", id, "--json"], env))).toMatchObject({ ask: { stale: true }, next: { say: expect.stringContaining("Do not hand the link over as live") } })
    expect(partly.stderr).toContain(`the vault for ${vault.slotDir(dir.path, SECOND.id)} could not be asked (device_revoked`)
    const other = vault.devices.get(a)
    if (other) other.revoked = true
    const none = await runJv(["pending", "--json"], env)
    expect(none.code).toBe(EXIT.identity)
    expect(json(none)).toMatchObject({ error: "device_revoked" })
  })
})

test("pending lists an open rule proposal as a policy ask titled Allow from now on, in JSON and in the table", async () => {
  await vault.enrolSoftware(dir.path)
  // As the vault's ruleProposalsPending answers a device: the workspace projection, no createdAt.
  const entry = { kind: "policy", id: "pol_rule", title: "Allow from now on: example-key", url: `${vault.url}/w/mock-space/p/pol_rule`, expiresAt: inAnHour(), requestedBy: { device: vault.lastDevice!, deviceName: "test-machine", session: null }, item: "example-key", bindingCode: "CODE42" }
  vault.overrides.set("GET /v1/pending", () => Response.json({ pending: [{ view: "detail", workspace: MOCK_WORKSPACE, owner: MOCK_OWNER, detail: entry }] }))
  try {
    const listed = json(await runJv(["pending", "--json"], env)) as { pending: Record<string, unknown>[] }
    expect(listed.pending).toHaveLength(1)
    expect(listed.pending[0]).toMatchObject({ kind: "policy", id: "pol_rule", title: "Allow from now on", url: entry.url, what: "Allow from now on: example-key", check: { label: "code", value: "CODE42" }, wait: "mehen wait pol_rule --timeout 60 --json" })
    const human = await runJv(["pending"], env)
    expect(human.code).toBe(0)
    expect(human.stdout).toMatch(/^policy +pol_rule +allow from now on: example-key +in \d+ min/m)
  } finally { vault.overrides.clear() }
})
