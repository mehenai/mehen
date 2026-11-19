import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { EXIT, EXIT_FOR_ERROR } from "@mehen/protocol/api"
import { readLedger } from "../ledger.ts"
import { MANDATES_OFF_BODY, mandateCreated, mandateOpenProposal, mandateReceipt, mandateView } from "../testing/mandate-fixtures.ts"
import { MockVault, vaultError } from "../testing/mock-vault.ts"
import { type JvResult, runJv, tempDir } from "../testing/run-mehen.ts"

let vault: MockVault
let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>
beforeAll(() => { vault = new MockVault() })
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url, TZ: "Etc/UTC" }
  await vault.enrolSoftware(dir.path)
  vault.seen.length = 0
  vault.overrides.clear()
})
afterEach(async () => dir.remove())

const json = (result: JvResult) => JSON.parse(result.stdout) as Record<string, unknown>
const mandateCalls = () => vault.seen.filter((s) => s.path.startsWith("/v1/mandates"))
const proposalsSent = () => vault.seen.filter((s) => s.path === "/v1/mandates/proposals").map((s) => JSON.parse(s.body) as Record<string, unknown>)
const propose = (...extra: string[]) => runJv(["mandate", "propose", "--note", "Nightly triage", ...extra], env)
const created = () => vault.overrides.set("POST /v1/mandates/proposals", () => Response.json(mandateCreated(vault.url), { status: 201 }))

test("propose with only a note asks for the protocol's defaults, hands over the sign page and exits 0; nothing goes in the ask ledger", async () => {
  created()
  const result = await propose("--json")
  expect(result.code).toBe(EXIT.ok)
  expect(proposalsSent()).toEqual([{ terms: { items: "all", classes: ["change", "delete", "read", "send"], caps: { read: 5000, change: 2000, send: 50, delete: 20 }, ttlDays: 90, schedule: null, note: "Nightly triage" }, reason: "Nightly triage" }])
  const url = `${vault.url}/w/mock-space/sign-mandate?proposal=mdp_new`
  expect(json(result)).toMatchObject({ proposal: "mdp_new", url, warning: null, ask: { kind: "mandate", id: "mdp_new", url, title: "Trust this machine", wait: null }, next: { url, command: "mehen mandate ls" } })
  expect((json(result).ask as { what: string }).what).toBe("Let test-machine read, change, send and delete with every credential it can use without asking you, for 90 days, at most 5000 reads, 2000 changes, 50 sends and 20 deletes a day: Nightly triage")
  expect(await readLedger(vault.slotDir(dir.path), vault.ledgerScope())).toEqual([])
  const human = await propose()
  expect(human.code).toBe(EXIT.ok)
  expect(human.stdout).toContain(`open:    ${url}`)
  expect(human.stdout).toContain("then:    mehen mandate ls shows it again while it is open, and the mandate once it is signed")
  expect(human.stdout).not.toContain("already waiting")
})

test("propose with the same terms as an open proposal hands back that link with existing, says so and exits 0", async () => {
  vault.overrides.set("POST /v1/mandates/proposals", () => Response.json({ ...mandateCreated(vault.url), existing: true }, { status: 201 }))
  const result = await propose("--json")
  expect(result.code).toBe(EXIT.ok)
  const url = `${vault.url}/w/mock-space/sign-mandate?proposal=mdp_new`
  expect(json(result)).toMatchObject({ proposal: "mdp_new", url, existing: true, next: { url, command: "mehen mandate ls", say: expect.stringContaining("These terms are already waiting for the person to sign.") } })
  const human = await propose()
  expect(human.code).toBe(EXIT.ok)
  expect(human.stdout.split("\n")[0]).toBe("These terms are already waiting for the person to sign; this is the same link.")
  expect(human.stdout).toContain(`open:    ${url}`)
  created()
  expect(json(await propose("--json"))).not.toHaveProperty("existing")
  vault.overrides.set("POST /v1/mandates/proposals", () => Response.json({ ...mandateCreated(vault.url), existing: false }, { status: 201 }))
  const fresh = await propose("--json")
  expect(fresh.code).toBe(EXIT.ok)
  expect(json(fresh)).toMatchObject({ proposal: "mdp_new", url })
  expect(json(fresh)).not.toHaveProperty("existing")
  expect((json(fresh).next as { say: string }).say).not.toContain("already waiting")
})

test("refusal/the open-proposals limit prints the newest waiting link and says mehen mandate ls lists every open one", async () => {
  const newest = `${vault.url}/w/mock-space/sign-mandate?proposal=mdp_newest`
  vault.overrides.set("POST /v1/mandates/proposals", () => vaultError("conflict", "This machine already has 3 mandates waiting for a person; mehen mandate ls lists them.", { next: { url: newest, say: "x" } }))
  const result = await propose("--json")
  expect(result.code).toBe(EXIT_FOR_ERROR.conflict)
  expect(json(result)).toMatchObject({ error: "conflict", next: { url: newest, command: "mehen mandate ls", say: expect.stringContaining("`mehen mandate ls` lists every open one, and the newest is at") } })
  const human = await propose()
  expect(human.stderr).toContain(`open: ${newest}`)
  expect(human.stderr).toContain("run:  mehen mandate ls")
  vault.overrides.set("POST /v1/mandates/proposals", () => vaultError("conflict", "This machine already has 3 mandates waiting for a person.", { next: { url: "https://evil.example/w/mock-space/sign-mandate?proposal=mdp_newest", say: "x" } }))
  const foreign = json(await propose("--json"))
  expect(foreign.next).toEqual({ command: "mehen mandate ls", say: expect.stringContaining("lists every open one.") })
  expect((foreign.next as { say: string }).say).toContain(`The vault returned a link that is not on ${vault.url}, so mehen did not show it.`)
  const foreignHuman = await propose()
  expect(foreignHuman.stderr).toContain(`The vault returned a link that is not on ${vault.url}, so mehen did not show it.`)
  expect(foreignHuman.stderr).not.toContain("evil.example")
  vault.overrides.set("POST /v1/mandates/proposals", () => vaultError("conflict", "This machine already has 3 mandates waiting for a person.", { next: { say: "x" } }))
  expect((json(await propose("--json")).next as { say: string }).say).not.toContain("The vault returned a link")
})

test("propose reads /v1/me before it creates anything, so a failed read leaves no proposal; the ask carries MEHEN_SESSION", async () => {
  created()
  vault.overrides.set("GET /v1/me", () => vaultError("internal", "The vault could not answer."))
  const failed = await propose("--json")
  expect(failed.code).not.toBe(EXIT.ok)
  expect(proposalsSent()).toEqual([])
  vault.overrides.delete("GET /v1/me")
  const labelled = await runJv(["mandate", "propose", "--note", "Nightly triage", "--json"], { ...env, MEHEN_SESSION: "triage-1" })
  expect(labelled.code).toBe(EXIT.ok)
  expect(json(labelled).ask).toMatchObject({ requestedBy: { device: "test-machine", session: "triage-1" } })
  expect(vault.seen.map((s) => s.path).filter((p) => p === "/v1/me" || p === "/v1/mandates/proposals").slice(-2)).toEqual(["/v1/me", "/v1/mandates/proposals"])
})

test("propose sends sorted slugs, read with the classes named, their caps, the days and the schedule as the protocol's windows", async () => {
  created()
  const result = await propose("--items", "linear-work,github-work,linear-work", "--classes", "send", "--caps", "send=20", "--days", "7", "--schedule", "Europe/Paris mon-fri 08:00-19:00; sat,sun 22:00-02:00", "--reason", "Tickets keep coming", "--json")
  expect(result.code).toBe(EXIT.ok)
  expect(proposalsSent()[0]).toEqual({
    terms: { items: ["github-work", "linear-work"], classes: ["read", "send"], caps: { read: 5000, change: 0, send: 20, delete: 0 }, ttlDays: 7, schedule: { tz: "Europe/Paris", windows: [{ days: [1, 2, 3, 4, 5], from: "08:00", to: "19:00" }, { days: [0, 6], from: "22:00", to: "02:00" }] }, note: "Nightly triage" },
    reason: "Tickets keep coming",
  })
  expect((json(result).ask as { what: string }).what).toBe("Let test-machine read and send with github-work and linear-work without asking you, for 7 days, at most 5000 reads and 20 sends a day, only Europe/Paris mon-fri 08:00-19:00; sat,sun 22:00-02:00: Nightly triage")
})

describe("refusal/propose terms the protocol would refuse, and a machine signing, resuming or stopping, never reach the vault", () => {
  for (const args of [
    ["mandate", "propose"],
    ["mandate", "propose", "--note", "  "],
    ["mandate", "propose", "--note", "x", "--classes", "read,publish"],
    ["mandate", "propose", "--note", "x", "--classes", "read", "--caps", "send=5"],
    ["mandate", "propose", "--note", "x", "--caps", "send=501"],
    ["mandate", "propose", "--note", "x", "--caps", "send=5,send=6"],
    ["mandate", "propose", "--note", "x", "--caps", "send"],
    ["mandate", "propose", "--note", "x", "--days", "2"],
    ["mandate", "propose", "--note", "x", "--items", "Not A Slug"],
    ["mandate", "propose", "--note", "x", "--items", "all,github-work"],
    ["mandate", "propose", "--note", "x", "--schedule", "mon-fri 08:00-19:00"],
    ["mandate", "propose", "--note", "x", "--schedule", "Mars/Olympus mon-fri 08:00-19:00"],
    ["mandate", "propose", "--note", "x", "--schedule", "Europe/Paris fri-mon 08:00-19:00"],
    ["mandate", "propose", "--note", "x", "--schedule", "Europe/Paris daily 08:00-08:00"],
    ["mandate", "propose", "--note", "x", "--schedule", "Europe/Paris daily 24:00-08:00"],
    ["mandate", "propose", "--note", "x", "--since", "1h"],
    ["mandate", "propose", "mdt_live", "--note", "x"],
    ["mandate", "ls", "mdt_live"],
    ["mandate", "show"],
    ["mandate", "show", "pol_live"],
    ["mandate", "pause", "mdt_live", "--note", "x"],
    ["mandate", "pause", "pol_live"],
    ["mandate", "uses", "mdt_live", "--since", "yesterday"],
    ["mandate", "resume", "mdt_live"],
    ["mandate", "stop", "mdt_live"],
    ["mandate", "sign", "mdp_new"],
    ["mandate", "widen", "mdt_live"],
  ]) test(args.join(" "), async () => {
    const result = await runJv([...args, "--json"], env)
    expect(result.code).toBe(EXIT.usage)
    expect(json(result).error).toBe("usage")
    expect(mandateCalls()).toEqual([])
  }, 20_000)

  test("resume names the person who signed it", async () => {
    const resume = json(await runJv(["mandate", "resume", "mdt_live", "--json"], env))
    expect(resume.message).toBe("A machine never resumes a mandate: the person who signed it resumes it from the mandate page.")
  }, 20_000)
})

test("a sign page link that is not this vault's for that proposal is replaced with the one built from its id, with a warning", async () => {
  vault.overrides.set("POST /v1/mandates/proposals", () => Response.json({ ...mandateCreated(vault.url), url: `https://evil.example/w/mock-space/sign-mandate?proposal=mdp_new` }, { status: 201 }))
  const foreign = json(await propose("--json"))
  expect(foreign).toMatchObject({ url: `${vault.url}/w/mock-space/sign-mandate?proposal=mdp_new`, warning: expect.any(String) })
  for (const url of [`${vault.url}/w/mock-space/sign-mandate?proposal=mdp_other`, `${vault.url}/w/mock-space/sign-mandate?proposal=mdp_new&next=x`, `${vault.url}/w/mock-space/a/apr_1`]) {
    vault.overrides.set("POST /v1/mandates/proposals", () => Response.json({ ...mandateCreated(vault.url), url }, { status: 201 }))
    expect(json(await propose("--json")), url).toMatchObject({ url: `${vault.url}/w/mock-space/sign-mandate?proposal=mdp_new`, warning: expect.any(String) })
  }
})

test("with mandates off, every action says so in one line and not to propose again", async () => {
  for (const route of ["POST /v1/mandates/proposals", "GET /v1/mandates", "GET /v1/mandates/mdt_live"]) vault.overrides.set(route, () => vaultError(MANDATES_OFF_BODY.error, MANDATES_OFF_BODY.message))
  for (const args of [["propose", "--note", "x"], ["ls"], ["show", "mdt_live"], ["pause", "mdt_live"], ["pause"]]) {
    const human = await runJv(["mandate", ...args], env)
    expect(human.code).toBe(EXIT_FOR_ERROR.not_found)
    expect(human.stderr.split("\n")[0]).toBe("mehen: This workspace has no mandates: they are not switched on here, or this vault is older than them.")
    expect(human.stderr).toContain("do not propose a mandate again")
  }
  vault.overrides.set("GET /v1/mandates/mdt_gone", () => vaultError("not_found", "No such mandate."))
  expect(json(await runJv(["mandate", "show", "mdt_gone", "--json"], env))).toMatchObject({ error: "not_found", message: "No such mandate." })
})

test("ls and show print the machine's own view and nothing more: no signerCurrent, today's counts against the caps", async () => {
  const leaked = { ...mandateView(), signerCurrent: false }
  vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [leaked] }))
  vault.overrides.set("GET /v1/mandates/mdt_live", () => Response.json(leaked))
  const ls = await runJv(["mandate", "ls", "--json"], env)
  expect(ls.code).toBe(EXIT.ok)
  expect(ls.stdout).not.toContain("signerCurrent")
  expect(json(ls)).toEqual({ mandates: [mandateView({ createdAt: leaked.createdAt, expiresAt: leaked.expiresAt })], proposals: [] })
  const table = (await runJv(["mandate", "ls"], env)).stdout
  expect(table).toContain("TODAY (UTC)")
  expect(table).toContain("read 12 of 5000, change 4 of 2000, send 3 of 50")
  const show = await runJv(["mandate", "show", "mdt_live"], env)
  expect(show.stdout).toContain("mdt_live: for test-machine, signed by Alex\nActive: covers what it names while the person who signed it still stands behind it.\nFor: Nightly triage of the support inbox\nMay read, change and send without asking, with github-work and linear-work.\nToday (UTC): read 12 of 5000, change 4 of 2000, send 3 of 50\nHours: at any time\n")
  expect(json(await runJv(["mandate", "show", "mdt_live", "--json"], env))).not.toHaveProperty("signerCurrent")
  expect(json(await runJv(["mandate", "show", "mdt_live", "--json"], env))).not.toHaveProperty("proposal")
  vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [] }))
  expect((await runJv(["mandate", "ls"], env)).stdout).toBe("No mandates for this machine. mehen mandate propose asks a person for one.\n")
  vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [{ ...leaked, state: "bored" }] }))
  expect(json(await runJv(["mandate", "ls", "--json"], env))).toMatchObject({ error: "internal" })
})

test("show names the proposal a mandate was signed from only when the vault sends a proposal id", async () => {
  vault.overrides.set("GET /v1/mandates/mdt_live", () => Response.json({ ...mandateView(), proposal: "mdp_from" }))
  expect(json(await runJv(["mandate", "show", "mdt_live", "--json"], env))).toMatchObject({ proposal: "mdp_from" })
  expect((await runJv(["mandate", "show", "mdt_live"], env)).stdout).toStartWith("mdt_live: for test-machine, signed by Alex\nSigned from proposal mdp_from\nActive:")
  vault.overrides.set("GET /v1/mandates/mdt_live", () => Response.json({ ...mandateView(), proposal: null }))
  expect((await runJv(["mandate", "show", "mdt_live"], env)).stdout).not.toContain("Signed from proposal")
})

for (const proposal of ["not-an-id", 7, { id: "mdp_from" }]) {
  test(`a proposal of ${JSON.stringify(proposal)} is left out of show, ls and status`, async () => {
    vault.overrides.set("GET /v1/mandates/mdt_live", () => Response.json({ ...mandateView(), proposal }))
    vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [{ ...mandateView(), proposal }], proposals: [] }))
    const shown = await runJv(["mandate", "show", "mdt_live", "--json"], env)
    expect(shown.code).toBe(EXIT.ok)
    expect(json(shown)).not.toHaveProperty("proposal")
    expect((await runJv(["mandate", "show", "mdt_live"], env)).stdout).not.toContain("Signed from proposal")
    const listed = await runJv(["mandate", "ls", "--json"], env)
    expect(listed.code).toBe(EXIT.ok)
    expect((json(listed).mandates as object[])[0]).not.toHaveProperty("proposal")
    expect(json(await runJv(["status", "--json", "--workspace", "mock-space"], env))).toMatchObject({ mandate: { id: "mdt_live" } })
  })
}

test("ls lists open proposals first, each waiting for its signer with its link, dates and reason; a foreign link is rebuilt from its id", async () => {
  const open = mandateOpenProposal(vault.url)
  vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [mandateView()], proposals: [open] }))
  const ls = await runJv(["mandate", "ls", "--json"], env)
  expect(json(ls)).toMatchObject({ proposals: [open], mandates: [{ id: "mdt_live" }] })
  const human = (await runJv(["mandate", "ls"], env)).stdout.split("\n")
  expect(human[0]).toBe(`Waiting for its signer: ${open.url}, proposed 2 Jan 09:00, expires 9 Jan 09:00: Tickets keep coming`)
  expect(human[1]).toBe("")
  expect(human[2]).toStartWith("ID")
  vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [], proposals: [{ ...open, url: "https://evil.example/w/mock-space/sign-mandate?proposal=mdp_open" }] }))
  const rebuilt = await runJv(["mandate", "ls"], env)
  expect(rebuilt.stdout).toBe(`Waiting for its signer: ${open.url}, proposed 2 Jan 09:00, expires 9 Jan 09:00: Tickets keep coming\n`)
  expect(rebuilt.stderr).toContain("mehen: warning:")
})

test("with no workspace slug to check a link against, ls and pause with no id drop an open proposal, with the refused-link warning, and go on", async () => {
  await dir.remove()
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url, TZ: "Etc/UTC" }
  await vault.enrolSoftware(dir.path, { config: { workspaceSlug: undefined } })
  vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [mandateView({ rev: 4 })], proposals: [mandateOpenProposal(vault.url)] }))
  const ls = await runJv(["mandate", "ls", "--json"], env)
  expect(ls.code).toBe(EXIT.ok)
  expect(json(ls)).toMatchObject({ proposals: [], mandates: [{ id: "mdt_live" }] })
  expect(ls.stderr).toContain("mehen: warning: The vault returned a link")
  const human = await runJv(["mandate", "ls"], env)
  expect(human.code).toBe(EXIT.ok)
  expect(human.stdout).not.toContain("Waiting for its signer")
  expect(human.stderr).toContain("mehen: warning: The vault returned a link")
  vault.overrides.set("GET /v1/mandates/mdt_live", () => Response.json(mandateView({ rev: 4 })))
  vault.overrides.set("POST /v1/mandates/mdt_live/pause", () => Response.json({ mandate: mandateView({ rev: 5, state: "paused" }) }))
  const paused = await runJv(["mandate", "pause", "--json"], env)
  expect(paused.code).toBe(EXIT.ok)
  expect(json(paused)).toMatchObject({ mandate: { id: "mdt_live", state: "paused" } })
})

test("a paused or tripped mandate says who can resume it, at its page, and never a command; credentials it cannot see are counted", async () => {
  const schedule = { tz: "Europe/Paris", windows: [{ days: [1, 2, 3, 4, 5], from: "08:00", to: "19:00" }] }
  const page = `${vault.url}/w/mock-space/mandates/mdt_live`
  for (const [state, words] of [["paused", `Paused: nothing goes through on trust; the person who signed it can resume it at ${page}.`], ["tripped", `Tripped: more than 120 requests beyond reading in a minute, so nothing goes through on trust; the person who signed it can resume it at ${page}, with their passkey.`]] as const) {
    vault.overrides.set("GET /v1/mandates/mdt_live", () => Response.json(mandateView({ state, hiddenItems: 2, schedule })))
    const show = await runJv(["mandate", "show", "mdt_live"], env)
    expect(show.stdout).toContain(`${words}\n`)
    expect(show.stdout).toContain("with github-work, linear-work and 2 credentials you cannot see.")
    expect(show.stdout).toContain("Hours: Europe/Paris mon-fri 08:00-19:00\n")
    expect(show.stdout).not.toContain("mehen mandate resume")
    expect(json(await runJv(["mandate", "show", "mdt_live", "--json"], env))).toMatchObject({ id: "mdt_live", state, next: { url: page, say: expect.stringContaining(`pass ${page} to the person who signed it`) } })
  }
  vault.overrides.set("GET /v1/mandates/mdt_live", () => Response.json(mandateView()))
  expect(json(await runJv(["mandate", "show", "mdt_live", "--json"], env))).not.toHaveProperty("next")
})

test("an ended mandate links its page to sign it again; ls points at the live one that covers nothing, or the newest ended one", async () => {
  const page = (id: string) => `${vault.url}/w/mock-space/mandates/${id}`
  vault.overrides.set("GET /v1/mandates/mdt_live", () => Response.json(mandateView({ state: "stopped", endedReason: "stopped" })))
  const show = await runJv(["mandate", "show", "mdt_live"], env)
  expect(show.stdout).toContain(`Stopped by a person: it covers nothing. Its signer can sign it again at ${page("mdt_live")}, or this machine can propose a new one.\n`)
  expect(json(await runJv(["mandate", "show", "mdt_live", "--json"], env))).toMatchObject({ next: { url: page("mdt_live") } })
  vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [mandateView({ id: "mdt_new", state: "paused" }), mandateView({ id: "mdt_old", state: "stopped", endedReason: "replaced" })], proposals: [] }))
  const ls = await runJv(["mandate", "ls"], env)
  expect(ls.stdout).toEndWith(`mdt_new: Paused: nothing goes through on trust; the person who signed it can resume it at ${page("mdt_new")}.\n`)
  expect(json(await runJv(["mandate", "ls", "--json"], env))).toMatchObject({ next: { url: page("mdt_new") } })
  vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [mandateView({ id: "mdt_old", state: "expired" })], proposals: [] }))
  expect(json(await runJv(["mandate", "ls", "--json"], env))).toMatchObject({ next: { url: page("mdt_old"), say: expect.stringContaining("to sign it again") } })
  vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [mandateView()], proposals: [] }))
  const active = await runJv(["mandate", "ls", "--json"], env)
  expect(json(active)).not.toHaveProperty("next")
})

test("uses follows the cursor to the end, or stops at the first receipt older than --since", async () => {
  const now = Date.now()
  const at = (minutesAgo: number) => new Date(now - minutesAgo * 60_000).toISOString()
  const pages: Record<string, { receipts: ReturnType<typeof mandateReceipt>[]; next: string | null }> = {
    "": { receipts: [mandateReceipt({ id: "mdu_1", at: at(1) }), mandateReceipt({ id: "mdu_2", at: at(20), credential: null })], next: "2.mdu_2" },
    "?before=2.mdu_2": { receipts: [mandateReceipt({ id: "mdu_3", at: at(90) })], next: null },
  }
  vault.overrides.set("GET /v1/mandates/mdt_live/uses", (_request, seen) => Response.json(pages[seen.search]))
  const all = await runJv(["mandate", "uses", "mdt_live", "--json"], env)
  expect(all.code).toBe(EXIT.ok)
  expect((json(all).receipts as { id: string }[]).map((r) => r.id)).toEqual(["mdu_1", "mdu_2", "mdu_3"])
  expect(mandateCalls().map((s) => s.search)).toEqual(["", "?before=2.mdu_2"])
  vault.seen.length = 0
  const recent = await runJv(["mandate", "uses", "mdt_live", "--since", "1h", "--json"], env)
  expect((json(recent).receipts as { id: string }[]).map((r) => r.id)).toEqual(["mdu_1", "mdu_2"])
  expect(json(recent).since).toEqual(expect.any(String))
  expect(mandateCalls().length).toBe(2)
  const table = (await runJv(["mandate", "uses", "mdt_live", "--since", "1h"], env)).stdout
  expect(table).toContain("github-work")
  expect(table).toContain("a credential you cannot see")
  expect(table).toContain("read and send")
  vault.overrides.set("GET /v1/mandates/mdt_live/uses", () => Response.json({ receipts: [], next: null }))
  expect((await runJv(["mandate", "uses", "mdt_live"], env)).stdout).toBe("Nothing has gone through on trust under mdt_live.\n")
})

test("uses keeps following pages past the 500 receipts vault_mandate stops at", async () => {
  const now = Date.now()
  const receipts = Array.from({ length: 640 }, (_, i) => mandateReceipt({ id: `mdu_${i}`, at: new Date(now - i * 1000).toISOString() }))
  vault.overrides.set("GET /v1/mandates/mdt_live/uses", (_request, seen) => {
    const from = seen.search === "" ? 0 : Number(seen.search.slice("?before=".length))
    return Response.json({ receipts: receipts.slice(from, from + 100), next: from + 100 < receipts.length ? String(from + 100) : null })
  })
  const all = await runJv(["mandate", "uses", "mdt_live", "--json"], env)
  expect(all.code).toBe(EXIT.ok)
  expect(json(all).receipts).toHaveLength(640)
  expect(json(all)).not.toHaveProperty("truncated")
  expect(mandateCalls().length).toBe(7)
})

test("pause sends the revision it read and says the signer may resume it; one already paused is left alone; an ended one is a conflict", async () => {
  vault.overrides.set("GET /v1/mandates/mdt_live", () => Response.json(mandateView({ rev: 4 })))
  vault.overrides.set("POST /v1/mandates/mdt_live/pause", () => Response.json({ mandate: mandateView({ rev: 5, state: "paused" }) }))
  const paused = await runJv(["mandate", "pause", "mdt_live"], env)
  expect(paused.code).toBe(EXIT.ok)
  expect(vault.seen.filter((s) => s.path === "/v1/mandates/mdt_live/pause").map((s) => JSON.parse(s.body))).toEqual([{ rev: 4 }])
  const page = `${vault.url}/w/mock-space/mandates/mdt_live`
  expect(paused.stdout).toBe(`Paused mandate mdt_live: nothing goes through on trust now. The person who signed it can resume it at ${page}; as this machine paused it, they need no passkey unless their own access has changed since they signed.\n`)
  expect(json(await runJv(["mandate", "pause", "mdt_live", "--json"], env))).toMatchObject({ mandate: { id: "mdt_live", state: "paused", rev: 5 }, next: { url: page } })
  vault.seen.length = 0
  vault.overrides.set("GET /v1/mandates/mdt_live", () => Response.json(mandateView({ state: "tripped" })))
  const again = await runJv(["mandate", "pause", "mdt_live"], env)
  expect(again.code).toBe(EXIT.ok)
  expect(again.stdout).toContain("Mandate mdt_live was already tripped; nothing changed.")
  expect(vault.seen.filter((s) => s.path.endsWith("/pause"))).toEqual([])
  vault.overrides.set("GET /v1/mandates/mdt_live", () => Response.json(mandateView({ state: "stopped", endedReason: "stopped" })))
  const ended = await runJv(["mandate", "pause", "mdt_live", "--json"], env)
  expect(ended.code).toBe(EXIT_FOR_ERROR.conflict)
  expect(json(ended)).toMatchObject({ error: "conflict", message: "Mandate mdt_live has ended (stopped); there is nothing to pause.", next: { url: page, command: "mehen mandate show mdt_live" } })
  expect((await runJv(["mandate", "pause", "mdt_live"], env)).stderr).toContain(`open: ${page}`)
  vault.overrides.set("GET /v1/mandates/mdt_live", () => Response.json(mandateView({ rev: 4 })))
  vault.overrides.set("POST /v1/mandates/mdt_live/pause", () => vaultError("conflict", "This mandate changed; review and try again."))
  expect(json(await runJv(["mandate", "pause", "mdt_live", "--json"], env))).toMatchObject({ error: "conflict", next: { command: "mehen mandate pause mdt_live" } })
})

test("pause with no id pauses this machine's live mandate here; none live, or several, is refused and nothing is sent", async () => {
  vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [mandateView({ id: "mdt_live", rev: 4 }), mandateView({ id: "mdt_old", state: "expired" })], proposals: [] }))
  vault.overrides.set("GET /v1/mandates/mdt_live", () => Response.json(mandateView({ rev: 4 })))
  vault.overrides.set("POST /v1/mandates/mdt_live/pause", () => Response.json({ mandate: mandateView({ rev: 5, state: "paused" }) }))
  const paused = await runJv(["mandate", "pause", "--json"], env)
  expect(paused.code).toBe(EXIT.ok)
  expect(json(paused)).toMatchObject({ mandate: { id: "mdt_live", state: "paused" }, next: { url: `${vault.url}/w/mock-space/mandates/mdt_live` } })
  expect(vault.seen.filter((s) => s.path.endsWith("/pause")).map((s) => [s.path, JSON.parse(s.body)])).toEqual([["/v1/mandates/mdt_live/pause", { rev: 4 }]])
  vault.seen.length = 0
  vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [mandateView({ id: "mdt_old", state: "stopped", endedReason: "stopped" })], proposals: [] }))
  const none = await runJv(["mandate", "pause", "--json"], env)
  expect(none.code).toBe(EXIT_FOR_ERROR.not_found)
  expect(json(none)).toMatchObject({ error: "not_found", message: "This machine has no live mandate in this workspace; there is nothing to pause.", next: { command: "mehen mandate ls" } })
  vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [mandateView({ id: "mdt_a" }), mandateView({ id: "mdt_b", state: "paused" })], proposals: [] }))
  const several = await runJv(["mandate", "pause", "--json"], env)
  expect(several.code).toBe(EXIT_FOR_ERROR.conflict)
  expect(json(several).message).toBe("This machine has 2 live mandates in this workspace (mdt_a, mdt_b); name the one to pause.")
  expect(vault.seen.filter((s) => s.path.endsWith("/pause"))).toEqual([])
})
