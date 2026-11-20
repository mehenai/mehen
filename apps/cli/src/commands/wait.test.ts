import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { LEASE_ONLY_HOST } from "@mehen/protocol/binding"
import { fingerprintOf } from "@mehen/protocol/fingerprint"
import { jwkThumbprint } from "@mehen/protocol/proof"
import { type AskUrl, approvalAsk, askUrl, clockText, policyAsk, connectAsk, enrolAsk, intakeAsk } from "../ask.ts"
import { ruleStatus } from "../testing/policy-rules-fixtures.ts"
import { readConfig } from "../config.ts"
import { activeSlotPath, pendingSlotPath } from "../home.ts"
import { type EnrolmentRecord, readEnrolmentRecord, writeEnrolmentRecord } from "../enrolment-record.ts"
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs"
import { stat } from "node:fs/promises"
import { SOFTWARE_KEY_FILE, createDeviceKey, readKeyScope } from "../device-key.ts"
import { addLedgerEntry, readLedger } from "../ledger.ts"
import { MOCK_OWNER, MOCK_TENANT, MOCK_WORKSPACE, MockVault, WORKSPACE_SCOPE, deviceFor, item, vaultError } from "../testing/mock-vault.ts"
import type { LedgerScope } from "../ledger.ts"
import { type JvResult, jsonLines, runJv, tempDir } from "../testing/run-mehen.ts"
import { plainStyler, plainText, styler, terminalText } from "../tty.ts"
import { countdownLine, outcomeLines, waitOutput } from "./intake.ts"

let vault: MockVault
let dir: { path: string; remove(): Promise<void> }
let env: Record<string, string>

const by = { device: "test-box", session: "pi-1" }
const inMinutes = (minutes: number) => new Date(Date.now() + minutes * 60_000).toISOString()
const link = (path: string): AskUrl => (askUrl(`${vault.url}/w/mock-space${path}`, vault.askVault()) as { url: AskUrl }).url

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url }
  vault.overrides.clear()
  vault.sequences.clear()
  vault.statusExpiresAt = null
  vault.enrolOutcome = { pendingPolls: 2, result: "active" }
  vault.enrolMode = "current"
  vault.activeAnswer = null
})
afterEach(async () => dir.remove())

function json(result: JvResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>
}

let device = ""
async function enrolled(): Promise<string> {
  device = await vault.enrolSoftware(dir.path)
  return device
}

// The ledger identity of the enrolled context, and the one while enrolling.
function scope(): LedgerScope {
  return { vaultUrl: vault.url, workspace: MOCK_TENANT, device, workspaceSlug: "mock-space" }
}
function enrolScope(): LedgerScope {
  return { vaultUrl: vault.url, workspace: null, device: null }
}
// Where a pending enrolment for mock-space lives under the root, and the
// active slot its finish step renames it to.
function pendingSlot(): string {
  return pendingSlotPath(dir.path, vault.url, "mock-space")
}
function activeSlot(): string {
  return activeSlotPath(dir.path, vault.url, MOCK_TENANT)
}

const GMAIL_ITEM = item("gmail-alex", { kind: "oauth-connection", provider: "google-gmail", account: "alex@example.com", accountVerified: true, hosts: ["gmail.googleapis.com"] })
const APPROVED = { approval: "apr_ok", status: "approved", bindingCode: "K7Q2MX", summary: "Send an email to sam@example.com", grant: { id: "gnt_1", uses: 1, expiresAt: "2026-10-24T16:12:00.000Z", kind: "exact" as const, scope: { selector: { device: "dev_test", session: null }, route: null }, parent: null } }

describe("mehen wait: polling", () => {
  test("checks at once, then long-polls an intake until it completes, and passes the item through pickSummary", async () => {
    await enrolled()
    const done = { intake: "int_abc", status: "completed", item: { ...item("openai-new"), secretValue: "sk-live", internal: { note: "x" } } }
    vault.sequences.set("intake:int_abc", [{ intake: "int_abc", status: "open" }, { intake: "int_abc", status: "open" }, done])
    const before = vault.seen.length
    const result = await runJv(["wait", "int_abc", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const out = json(result) as { item: Record<string, unknown> }
    expect(out).toMatchObject({ id: "int_abc", kind: "intake", status: "completed", item: { slug: "openai-new", kind: "api-key", provider: "openai", hosts: ["api.openai.com"] } })
    expect(out.item.secretValue).toBeUndefined()
    expect(out.item.internal).toBeUndefined()
    expect(out.item.secretFields).toBeUndefined()
    const polls = vault.seen.slice(before).map((p) => `${p.path}${p.search}`)
    expect(polls).toEqual(["/v1/intakes/int_abc", "/v1/intakes/int_abc?wait=1", "/v1/intakes/int_abc?wait=1"])
    expect(result.stderr).toBe("")
  })

  // A server or proxy that drops a held poll: Bun's fetch would resend the
  // same request, proof and all, on a reused connection; every poll is sent
  // once and the next one signed afresh.
  test("a long poll whose connection drops is polled again with a fresh proof, and the wait carries on to the answer", async () => {
    await enrolled()
    const done = { intake: "int_drop", status: "completed", item: item("openai-new") }
    vault.sequences.set("intake:int_drop", [{ intake: "int_drop", status: "open" }, done])
    vault.drops.set("GET /v1/intakes/int_drop?wait=1", 1)
    const before = vault.seen.length
    const result = await runJv(["wait", "int_drop", "--json"], env)
    expect(vault.replays).toEqual([])
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toMatchObject({ id: "int_drop", kind: "intake", status: "completed" })
    const polls = vault.seen.slice(before)
    expect(polls.map((p) => `${p.path}${p.search}`)).toEqual(["/v1/intakes/int_drop", "/v1/intakes/int_drop?wait=1", "/v1/intakes/int_drop?wait=1"])
    expect(new Set(polls.map((p) => p.claims.jti)).size).toBe(3)
  })

  test("durations: 10m, 2h and 0 are accepted; soon is a usage error", async () => {
    await enrolled()
    vault.sequences.set("approval:apr_ok", [APPROVED])
    for (const timeout of ["10m", "2h", "90", "30s"]) expect((await runJv(["wait", "apr_ok", "--timeout", timeout], env)).code).toBe(EXIT.ok)
    vault.statusExpiresAt = inMinutes(120)
    const once = await runJv(["wait", "apr_slow", "--timeout", "0", "--json"], env)
    expect(once.code).toBe(EXIT.human)
    expect(json(once)).toMatchObject({ error: "timeout", message: "Approval apr_slow is still waiting for a human; the link expires in 2 h.", next: { command: "mehen wait apr_slow" } })
    const soon = await runJv(["wait", "int_1", "--timeout", "soon"], env)
    expect(soon.code).toBe(EXIT.usage)
    expect(soon.stderr).toContain("--timeout takes a number of seconds, or a duration such as 30s, 10m or 2h, up to 24 h; 0 checks once.")
    expect((await runJv(["wait", "int_1", "--timeout", "25h"], env)).code).toBe(EXIT.usage)
    expect((await runJv(["wait", "xyz_1"], env)).code).toBe(EXIT.usage)
  })

  test("off a TTY nothing goes to stderr while waiting, and the timeout names the wait and the link's remaining life", async () => {
    await enrolled()
    vault.sequences.set("intake:int_two", [{ intake: "int_two", status: "open" }, { intake: "int_two", status: "open" }, { intake: "int_two", status: "completed", item: item("openai-new") }])
    const quiet = await runJv(["wait", "int_two", "--timeout", "10s"], env)
    expect(quiet.code).toBe(EXIT.ok)
    expect(quiet.stderr).toBe("")
    vault.statusExpiresAt = inMinutes(48)
    const timed = await runJv(["wait", "int_slow", "--timeout", "1"], env)
    expect(timed.code).toBe(EXIT.human)
    expect(timed.stderr).toStartWith("mehen: Intake int_slow is still waiting for a human after 1 s; the link expires in 48 min.\n")
    expect(timed.stderr).toContain("  run:  mehen wait int_slow")
  })

  test("the countdown line: the link's remaining life when known, this wait's otherwise, and the enrol wording", () => {
    const s = plainStyler()
    const now = Date.parse("2026-10-24T16:00:00.000Z")
    const deadline = now + 9 * 60_000 + 12_000
    expect(plainText(countdownLine({ kind: "approval", id: "apr_7Hq2", expiresAt: "2026-10-24T16:57:40.000Z", deadline, now }, s))).toBe("Waiting...  57:40 until the link expires  (Ctrl-C stops waiting; the link stays valid)")
    expect(plainText(countdownLine({ kind: "intake", id: "int_1", expiresAt: "2026-10-25T15:59:40.000Z", deadline, now }, s))).toBe("Waiting...  23:59:40 until the link expires  (Ctrl-C stops waiting; the link stays valid)")
    expect(plainText(countdownLine({ kind: "approval", id: "apr_7Hq2", expiresAt: null, deadline, now }, s))).toBe("Waiting...  9:12 left of this wait  (Ctrl-C stops waiting; mehen wait apr_7Hq2 resumes)")
    expect(plainText(countdownLine({ kind: "approval", id: "apr_7Hq2", expiresAt: "2026-10-24T15:00:00.000Z", deadline, now }, s))).toBe("Waiting...  the link has expired  (waiting for the vault to say so)")
    expect(plainText(countdownLine({ kind: "enrol", id: "enr_1", expiresAt: "2026-10-24T16:14:58.000Z", deadline, now }, s))).toStartWith("Waiting for the owner...  14:58 until the link expires")
    const coloured = terminalText(countdownLine({ kind: "approval", id: "apr_7Hq2", expiresAt: "2026-10-24T16:57:40.000Z", deadline, now }, styler(true)))
    expect(coloured).toContain("\u001b[1m57:40\u001b[0m")
  })
})

describe("mehen wait --events", () => {
  test("emits waiting (with the ledger's ask and the link's remaining seconds) and then settled, one JSON object per line", async () => {
    await enrolled()
    const ask = approvalAsk({ id: "apr_ev", url: link("/a/apr_ev"), summary: "Send an email to sam@example.com", bindingCode: "K7Q2MX", expiresAt: inMinutes(58), requestedBy: by })
    await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask })
    vault.sequences.set("approval:apr_ev", [{ approval: "apr_ev", status: "pending", bindingCode: "K7Q2MX", summary: "Send an email to sam@example.com" }, { ...APPROVED, approval: "apr_ev" }])
    const result = await runJv(["wait", "apr_ev", "--json", "--events"], env)
    expect(result.code).toBe(EXIT.ok)
    const events = jsonLines(result.stdout) as Record<string, unknown>[]
    expect(events.map((e) => e.event)).toEqual(["waiting", "settled"])
    expect(events[0]).toMatchObject({ event: "waiting", id: "apr_ev", kind: "approval", ask: { id: "apr_ev", check: { label: "code", value: "K7Q2MX" } } })
    const remaining = events[0]?.remainingSeconds as number
    expect(remaining).toBeGreaterThan(57 * 60)
    expect(remaining).toBeLessThanOrEqual(58 * 60)
    expect(events[1]).toEqual({ event: "settled", id: "apr_ev", kind: "approval", ...APPROVED, approval: "apr_ev" })
    expect(result.stderr).toBe("")
    expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])
  })

  test("without a ledger entry the first waiting line has no ask; the vault's status then supplies one built on this vault's link", async () => {
    await enrolled()
    vault.sequences.set("approval:apr_far", [{ approval: "apr_far", status: "pending", bindingCode: "ABCDEF", summary: "Delete a thread", expiresAt: inMinutes(30) }, { ...APPROVED, approval: "apr_far" }])
    const events = jsonLines((await runJv(["wait", "apr_far", "--json", "--events"], env)).stdout) as Record<string, unknown>[]
    expect(events.map((e) => e.event)).toEqual(["waiting", "waiting", "settled"])
    expect(events[0]).toEqual({ event: "waiting", id: "apr_far", kind: "approval", remainingSeconds: null })
    expect(events[1]).toMatchObject({ event: "waiting", ask: { kind: "approval", id: "apr_far", url: `${vault.url}/w/mock-space/a/apr_far`, what: "Delete a thread", check: { label: "code", value: "ABCDEF" } } })
    expect(events[1]?.remainingSeconds).toBeGreaterThan(29 * 60)
  })

  test("a failure ends the stream with an error event and the usual exit code; --events needs --json", async () => {
    await enrolled()
    vault.sequences.set("approval:apr_no", [{ approval: "apr_no", status: "denied", bindingCode: "K7Q2", summary: "Send" }])
    const denied = await runJv(["wait", "apr_no", "--json", "--events"], env)
    expect(denied.code).toBe(EXIT.refused)
    const events = jsonLines(denied.stdout) as Record<string, unknown>[]
    expect(events.map((e) => e.event)).toEqual(["waiting", "error"])
    expect(events[1]).toMatchObject({ event: "error", error: "denied", message: "The human denied approval apr_no: Send." })
    const timeout = await runJv(["wait", "apr_slow", "--timeout", "0", "--json", "--events"], env)
    expect(timeout.code).toBe(EXIT.human)
    expect((jsonLines(timeout.stdout).at(-1) as Record<string, unknown>).error).toBe("timeout")
    const plain = await runJv(["wait", "apr_no", "--events"], env)
    expect(plain.code).toBe(EXIT.usage)
    expect(plain.stderr).toContain("--events prints one JSON object per line, so it needs --json.")
  })
})

describe("mehen wait enr_", () => {
  const ID = "enr_ledger1"

  // A pending attempt as mehen enrol leaves it: the key and the record in
  // the pending slot, and the attempt at the mock vault.
  async function pendingEnrolment(options: { expiresAt?: string; hardExpiresAt?: string | null; legacy?: boolean; slot?: string; backend?: "software" | "secure-enclave"; env?: Record<string, string> } = {}): Promise<{ id: string; jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }; slot: string }> {
    const slot = options.slot ?? pendingSlot()
    const backend = options.backend ?? "software"
    const { jwk } = await createDeviceKey(slot, backend, options.env ?? {}, { vault: vault.url, tenant: null })
    const expiresAt = options.expiresAt ?? inMinutes(14)
    const hardExpiresAt = options.hardExpiresAt === undefined ? inMinutes(24 * 60) : options.hardExpiresAt
    vault.enrolments.set(ID, { id: ID, jwk, name: "test-mac", backend, polls: 0, workspace: "mock-space", owner: { kind: "self" }, expiresAt: Date.parse(expiresAt), ...(hardExpiresAt ? { hardExpiresAt: Date.parse(hardExpiresAt) } : {}), renewedAt: null, renewals: 0 })
    const record: EnrolmentRecord = { v: 1, state: "pending", id: ID, code: "ABCD2345", url: `${vault.url}/w/mock-space/e/ABCD2345`, origin: vault.url, intent: { workspace: "mock-space", team: null }, name: "test-mac", backend, jwk, session: null, startedAt: new Date().toISOString(), expiresAt, hardExpiresAt, renewals: 0, legacy: options.legacy ?? false, claimed: false }
    await writeEnrolmentRecord(slot, record)
    return { id: ID, jwk, slot }
  }

  async function record(slot = pendingSlot()): Promise<EnrolmentRecord | null> {
    const read = await readEnrolmentRecord(slot)
    return read && "record" in read ? read.record : null
  }

  function renewCalls(from: number): string[] {
    return vault.seen.slice(from).filter((c) => c.path.endsWith("/renew")).map((c) => c.path)
  }

  test("polls the attempt signed by its own key, activates it and renames the slot into workspaces/ with the fingerprint", async () => {
    const { id, jwk } = await pendingEnrolment()
    const before = vault.seen.length
    const result = await runJv(["wait", id, "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toMatchObject({ id, kind: "enrol", status: "active", tenant: MOCK_TENANT, device: deviceFor(id), workspace: MOCK_WORKSPACE, owner: MOCK_OWNER })
    const polls = vault.seen.slice(before)
    expect(polls).toHaveLength(3)
    for (const poll of polls) {
      expect(poll).toMatchObject({ method: "GET", path: `/v1/enrol/${id}`, search: "" })
      expect(poll.claims).toMatchObject({ ten: "enrol", dev: id })
    }
    expect(await readConfig(activeSlot())).toEqual({ vault: vault.url, tenant: MOCK_TENANT, device: deviceFor(id), backend: "software", fingerprint: fingerprintOf(await jwkThumbprint(jwk)), name: "test-mac", workspaceSlug: MOCK_WORKSPACE.slug, workspaceName: MOCK_WORKSPACE.name, owner: MOCK_OWNER })
    expect(await readKeyScope(activeSlot(), "software")).toEqual({ vault: vault.url, tenant: MOCK_TENANT })
    expect(existsSync(pendingSlot())).toBe(false)
    const status = await runJv(["status", "--json", "--workspace", MOCK_WORKSPACE.slug], env)
    expect(json(status)).toMatchObject({ device: deviceFor(id), fingerprint: fingerprintOf(await jwkThumbprint(jwk)) })
  })

  test("the human output is the Enrolled sentence; a rejected or expired attempt is the matching error, writes no config and removes the record", async () => {
    const { id } = await pendingEnrolment()
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    const human = await runJv(["wait", id], env)
    expect(human.code).toBe(EXIT.ok)
    expect(human.stdout).toBe(`Enrolled as ${deviceFor(id)} in Mock Space (mock-space).\n  then:    mehen status, then mehen guide\n`)
    expect(human.stderr).toBe("")

    for (const outcome of ["rejected", "expired"] as const) {
      const fresh = await tempDir()
      dir = fresh
      env = { ...env, MEHEN_CONFIG_DIR: fresh.path }
      const pending = await pendingEnrolment()
      vault.enrolOutcome = { pendingPolls: 0, result: outcome }
      // A terminal expiry is not renewed: the vault said so.
      const enrolment = vault.enrolments.get(pending.id)
      if (enrolment && outcome === "expired") enrolment.settled = "hard_cap"
      const result = await runJv(["wait", pending.id, "--json"], env)
      expect(result.code).toBe(outcome === "rejected" ? EXIT.refused : EXIT.error)
      expect(json(result)).toMatchObject(
        outcome === "rejected"
          ? { error: "rejected", message: `The enrolment ${pending.id} was rejected in the vault.` }
          : { error: "expired", message: `The enrolment link for ${pending.id} expired before anyone accepted it (it reached its hard limit).`, next: { command: "mehen enrol --workspace mock-space", say: "the link ran out for good; enrol again; the key is kept, so the fingerprint stays the same" } },
      )
      expect(await readConfig(pendingSlot())).toBeNull()
      expect(existsSync(activeSlot())).toBe(false)
      expect(await record()).toBeNull()
      // The key is kept: enrolling again keeps the fingerprint.
      expect(existsSync(join(pendingSlot(), SOFTWARE_KEY_FILE))).toBe(true)
    }
  })

  test("an enrolment this machine does not hold cannot be waited on, and nothing is signed", async () => {
    const result = await runJv(["wait", "enr_unknown", "--json"], env)
    expect(result.code).toBe(EXIT.error)
    expect(json(result)).toMatchObject({ error: "not_found", message: `No open enrolment enr_unknown is recorded on this machine for ${vault.url}.`, next: { command: "mehen enrol --workspace <slug>" } })
    expect(vault.seen.every((call) => call.path !== "/v1/enrol/enr_unknown")).toBe(true)
  })

  // The no-local-hit fallback signs one poll with the one active
  // slot's key, and only after the key-scope guard every session runs.
  test("no local hit, one active slot whose key scope names another vault or another workspace: workspace_mismatch, exit 2, nothing signed, the slot unchanged", async () => {
    await enrolled()
    const slot = vault.slotDir(dir.path)
    for (const scope of [{ vault: "https://other.example", tenant: MOCK_TENANT }, { vault: vault.url, tenant: "tn_other000000001" }]) {
      writeFileSync(join(slot, "device-key.scope.json"), `${JSON.stringify(scope)}\n`, { mode: 0o600 })
      const snapshot = async () => (await Bun.$`find ${slot} -type f -exec shasum {} +`.text()).trim()
      const before = await snapshot()
      const seen = vault.seen.length
      const result = await runJv(["wait", "enr_noLocalHit0001", "--json"], env)
      expect(result.code).toBe(EXIT.usage)
      expect(json(result)).toMatchObject({ error: "workspace_mismatch" })
      expect(vault.seen.length).toBe(seen)
      expect(await snapshot()).toBe(before)
    }
  })

  test("no local hit with the one active slot outside MEHEN_WORKSPACES: not_found and nothing signed", async () => {
    await enrolled()
    const seen = vault.seen.length
    const result = await runJv(["wait", "enr_noLocalHit0002", "--json"], { ...env, MEHEN_WORKSPACES: "other-space" })
    expect(result.code).toBe(EXIT.error)
    expect(json(result)).toMatchObject({ error: "not_found" })
    expect(vault.seen.length).toBe(seen)
  })

  test("the record is never pruned by its expiry: after a local lapse the terminal state is polled first, and an approval that landed in time is finished", async () => {
    const { id } = await pendingEnrolment({ expiresAt: new Date(Date.now() - 60_000).toISOString() })
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    const before = vault.seen.length
    const result = await runJv(["wait", id, "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toMatchObject({ status: "active", device: deviceFor(id) })
    expect(vault.seen.slice(before).map((c) => c.path)).toEqual([`/v1/enrol/${id}`])
    expect(await readConfig(activeSlot())).toMatchObject({ device: deviceFor(id) })
  })

  test("renews in place before the lease runs out, the same id, and --events says renewed", async () => {
    vault.enrolLeaseMs = 600
    vault.renewIntervalMs = 0
    const { id } = await pendingEnrolment({ expiresAt: new Date(Date.now() + 600).toISOString() })
    vault.enrolOutcome = { pendingPolls: 12, result: "active" }
    const before = vault.seen.length
    try {
      const result = await runJv(["wait", id, "--json", "--events"], { ...env, MEHEN_POLL_INTERVAL_MS: "100" })
      expect(result.code).toBe(EXIT.ok)
      const events = jsonLines(result.stdout) as Record<string, unknown>[]
      const renewed = events.filter((e) => e.event === "renewed")
      expect(renewed.length).toBeGreaterThan(0)
      expect(renewed[0]).toMatchObject({ event: "renewed", id, expiresAt: expect.any(String), hardExpiresAt: expect.any(String) })
      expect(events.at(-1)).toMatchObject({ event: "settled", id, status: "active" })
      for (const call of vault.seen.slice(before)) expect(call.claims).toMatchObject({ ten: "enrol", dev: id })
      expect(new Set(renewCalls(before))).toEqual(new Set([`/v1/enrol/${id}/renew`]))
    } finally {
      vault.enrolLeaseMs = 60_000
      vault.renewIntervalMs = 60_000
    }
  })

  test("a server expired while the record is renewable triggers one renewal; the terminal refusal ends it: exit 1 with mehen enrol as the next step", async () => {
    const { id } = await pendingEnrolment()
    vault.enrolOutcome = { pendingPolls: 0, result: "expired" }
    const before = vault.seen.length
    const result = await runJv(["wait", id, "--json"], env)
    expect(result.code).toBe(EXIT.error)
    expect(json(result)).toMatchObject({ error: "expired", next: { command: "mehen enrol --workspace mock-space" } })
    expect(renewCalls(before)).toEqual([`/v1/enrol/${id}/renew`])
    expect(await record()).toBeNull()
  })

  test("the wait's own timeout is exit 4 with the live ask, and the record stays", async () => {
    const { id } = await pendingEnrolment()
    vault.enrolOutcome = { pendingPolls: 1_000, result: "active" }
    const result = await runJv(["wait", id, "--timeout", "0", "--json"], env)
    expect(result.code).toBe(EXIT.human)
    expect(json(result)).toMatchObject({ error: "timeout", next: { command: `mehen wait ${id}` }, ask: { kind: "enrol", id, intent: { workspace: "mock-space", team: null }, claimed: false } })
    expect(await record()).toMatchObject({ id })
  })

  test("a still-valid legacy record is kept and polled, never renewed; once its own expiry passes without approval it ends", async () => {
    const { id } = await pendingEnrolment({ legacy: true, hardExpiresAt: null, expiresAt: inMinutes(1) })
    vault.enrolOutcome = { pendingPolls: 1_000, result: "active" }
    const before = vault.seen.length
    const kept = await runJv(["wait", id, "--timeout", "1", "--json"], env)
    expect(kept.code).toBe(EXIT.human)
    expect(await record()).toMatchObject({ id, legacy: true })
    expect(renewCalls(before)).toEqual([])
    const enrolment = vault.enrolments.get(id)
    if (enrolment) enrolment.expiresAt = Date.now() - 1_000
    await writeEnrolmentRecord(pendingSlot(), { ...((await record()) as EnrolmentRecord), expiresAt: new Date(Date.now() - 1_000).toISOString() })
    const ended = await runJv(["wait", id, "--json"], env)
    expect(ended.code).toBe(EXIT.error)
    expect(json(ended)).toMatchObject({ error: "expired", next: { command: "mehen enrol --workspace mock-space" } })
    expect(renewCalls(before)).toEqual([])
    expect(await record()).toBeNull()
  })

  test("against a vault from before 0008: no hardExpiresAt is never renewed, and expired without a reason is terminal", async () => {
    vault.enrolMode = "pre0008"
    try {
      const { id } = await pendingEnrolment({ hardExpiresAt: null })
      vault.enrolOutcome = { pendingPolls: 0, result: "expired" }
      const before = vault.seen.length
      const result = await runJv(["wait", id, "--json"], env)
      expect(result.code).toBe(EXIT.error)
      expect(json(result)).toMatchObject({ error: "expired" })
      expect(renewCalls(before)).toEqual([])
      expect(await record()).toBeNull()
    } finally {
      vault.enrolMode = "current"
    }
  })

  test("a legacy enrol entry an older mehen left in a pending slot's ledger is adopted as the record and finished", async () => {
    const slot = pendingSlot()
    const { jwk } = await createDeviceKey(slot, "software", {}, { vault: vault.url, tenant: null })
    vault.enrolments.set(ID, { id: ID, jwk, name: "test-mac", backend: "software", polls: 0, workspace: "mock-space", owner: { kind: "self" } })
    const ask = enrolAsk({ id: ID, url: link("/e/ABCD2345"), name: "test-mac", backend: "software", fingerprint: fingerprintOf(await jwkThumbprint(jwk)), expiresAt: inMinutes(14), requestedBy: by })
    await addLedgerEntry(slot, enrolScope(), { ask, command: "mehen enrol --workspace mock-space --name test-mac --backend software", enrol: { code: "ABCD2345", name: "test-mac", backend: "software", jwk, workspace: "mock-space", team: null } })
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    const result = await runJv(["wait", ID, "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toMatchObject({ status: "active", device: deviceFor(ID) })
    expect(await readConfig(activeSlot())).toMatchObject({ device: deviceFor(ID) })
  })

  // Activation is all or nothing. A failed scope or config write
  // self-revokes the new device, deletes the key and leaves no active config.
  test("a failed key-scope write during activation self-revokes, deletes the key and leaves no config; the record goes with it", async () => {
    const { id } = await pendingEnrolment()
    // A directory where the scope file must land: the atomic rename fails after the vault said active.
    rmSync(join(pendingSlot(), "device-key.scope.json"))
    mkdirSync(join(pendingSlot(), "device-key.scope.json"))
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    const revokedBefore = vault.revoked.length
    const result = await runJv(["wait", id, "--json"], env)
    expect(result.code).toBe(EXIT.error)
    expect(json(result)).toMatchObject({ error: "failed", message: expect.stringContaining("this machine could not record it") })
    expect(result.stdout).not.toContain('"status":"active"')
    expect(vault.revoked.slice(revokedBefore)).toEqual([deviceFor(id)])
    expect(existsSync(join(pendingSlot(), "device-key.json"))).toBe(false)
    expect(await readConfig(pendingSlot())).toBeNull()
    expect(existsSync(activeSlot())).toBe(false)
    expect(await record()).toBeNull()
  })

  test("a failed config write (the commit) self-revokes and leaves no active config or key, for both key backends", async () => {
    const { finishAttempt, openAttempt } = await import("./activate.ts")
    const { fakeHelper } = await import("../testing/fake-mehen-se.ts")
    for (const backend of ["software", "secure-enclave"] as const) {
      const fresh = await tempDir()
      try {
        const helper = backend === "secure-enclave" ? await fakeHelper(fresh.path) : null
        const keyEnv: Record<string, string> = helper ? { MEHEN_SE_PATH: helper, MEHEN_HOME: fresh.path } : { MEHEN_HOME: fresh.path }
        const slot = pendingSlotPath(fresh.path, vault.url, "mock-space")
        await pendingEnrolment({ slot, backend, env: keyEnv })
        const attempt = await openAttempt(keyEnv, fresh.path, slot, ID, null)
        const device = "dev_committed0001"
        vault.devices.set(device, { jwk: attempt.record.jwk, revoked: false })
        mkdirSync(join(slot, "config.json"))
        const revokedBefore = vault.revoked.length
        await expect(finishAttempt(attempt, { status: "active", tenant: MOCK_TENANT, workspace: MOCK_WORKSPACE, device, scope: WORKSPACE_SCOPE, owner: MOCK_OWNER })).rejects.toMatchObject({ code: "failed" })
        expect(vault.revoked.slice(revokedBefore)).toEqual([device])
        expect(existsSync(join(slot, backend === "software" ? "device-key.json" : "device-key.se"))).toBe(false)
        expect(await readKeyScope(slot, backend)).toBeNull()
        expect(existsSync(activeSlotPath(fresh.path, vault.url, MOCK_TENANT))).toBe(false)
        rmSync(join(slot, "config.json"), { recursive: true, force: true })
        expect(await readConfig(slot)).toBeNull()
      } finally {
        await fresh.remove()
      }
    }
  })

  // Once another enrolment (B) holds the workspace's slot, every
  // refusal branch of A's finish preserves B's config, key and scope byte
  // for byte, revokes A with A's returned identity, and prints no success;
  // only A's own pending slot is cleaned. A matching answer for A with B
  // there is already_enrolled: nothing revoked, nothing deleted.
  test("a mismatched, wrong-owner or incomplete A answer after B landed revokes A and leaves B's config, key and scope byte for byte, whether or not the vault accepts the revocation", async () => {
    const { finishAttempt, openAttempt } = await import("./activate.ts")
    const { readFile } = await import("node:fs/promises")
    const a = { tenant: MOCK_TENANT, workspace: MOCK_WORKSPACE, scope: WORKSPACE_SCOPE, owner: MOCK_OWNER }
    const answers: [string, Record<string, unknown>][] = [
      ["mismatched slug", { status: "active", ...a, workspace: { ...MOCK_WORKSPACE, slug: "other-space" } }],
      ["wrong owner kind", { status: "active", ...a, owner: { kind: "team", team: "tm_x", name: "Ops" } }],
      ["missing required tick", { status: "active", ...a, scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay"] } }],
    ]
    for (const revocation of ["accepted", "refused"] as const) {
      for (const [label, answer] of answers) {
        const fresh = await tempDir()
        try {
          // A's attempt, then B lands in the workspace's active slot.
          const slot = pendingSlotPath(fresh.path, vault.url, "mock-space")
          await pendingEnrolment({ slot })
          const attempt = await openAttempt({ MEHEN_HOME: fresh.path }, fresh.path, slot, ID, null)
          const aDevice = `dev_attemptA${revocation === "accepted" ? "1" : "2"}`
          vault.devices.set(aDevice, { jwk: attempt.record.jwk, revoked: false })
          const bDevice = await vault.enrolSoftware(fresh.path)
          const active = vault.slotDir(fresh.path)
          const files = ["config.json", SOFTWARE_KEY_FILE, "device-key.scope.json"]
          const before = Object.fromEntries(await Promise.all(files.map(async (f) => [f, await readFile(join(active, f), "utf8")])))
          expect(JSON.parse(before["config.json"]!).device).toBe(bDevice)
          if (revocation === "refused") vault.overrides.set("POST /v1/devices/self/revoke", () => Response.json({ error: "internal", message: "down" }, { status: 500, headers: { "Mehen-Error": "1" } }))
          const revokedBefore = vault.revoked.length
          const seen = vault.seen.length
          let thrown: unknown
          try {
            await finishAttempt(attempt, { ...answer, device: aDevice })
          } catch (error) {
            thrown = error
          }
          vault.overrides.clear()
          expect(thrown, label).toMatchObject({ code: "workspace_mismatch" })
          const message = (thrown as { message: string }).message
          // A's revocation was attempted with A's identity.
          const revoke = vault.seen.slice(seen).find((c) => c.path === "/v1/devices/self/revoke")
          expect(revoke?.claims, label).toMatchObject({ ten: MOCK_TENANT, dev: aDevice })
          if (revocation === "accepted") expect(vault.revoked.slice(revokedBefore), label).toEqual([aDevice])
          else expect(message, label).toContain(`did not accept the revocation of device ${aDevice}`)
          // B is untouched; A's own provisional key is gone.
          for (const f of files) expect(await readFile(join(active, f), "utf8"), `${label}: ${f}`).toBe(before[f]!)
          expect((await readConfig(active))?.device).toBe(bDevice)
          expect(existsSync(join(slot, SOFTWARE_KEY_FILE)), label).toBe(false)
        } finally {
          await fresh.remove()
        }
      }
    }
    // A matching A answer while B holds the slot: already_enrolled, revoke nothing, delete nothing.
    const fresh = await tempDir()
    try {
      const slot = pendingSlotPath(fresh.path, vault.url, "mock-space")
      await pendingEnrolment({ slot })
      const attempt = await openAttempt({ MEHEN_HOME: fresh.path }, fresh.path, slot, ID, null)
      const bDevice = await vault.enrolSoftware(fresh.path)
      const seen = vault.seen.length
      await expect(finishAttempt(attempt, { status: "active", ...a, device: "dev_attemptA3" })).rejects.toMatchObject({ code: "already_enrolled", message: expect.stringContaining(`This machine already holds device ${bDevice}`) })
      expect(vault.seen.slice(seen).filter((c) => c.path === "/v1/devices/self/revoke")).toEqual([])
      expect(existsSync(join(slot, SOFTWARE_KEY_FILE))).toBe(true)
      expect(await record(slot)).toMatchObject({ id: ID })
      expect((await readConfig(vault.slotDir(fresh.path)))?.device).toBe(bDevice)
    } finally {
      await fresh.remove()
    }
  })

  test("a persistence failure the vault will not undo still deletes the key and names the device to revoke", async () => {
    const { id } = await pendingEnrolment()
    rmSync(join(pendingSlot(), "device-key.scope.json"))
    mkdirSync(join(pendingSlot(), "device-key.scope.json"))
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    vault.overrides.set("POST /v1/devices/self/revoke", () => Response.json({ error: "internal", message: "down" }, { status: 500, headers: { "Mehen-Error": "1" } }))
    const result = await runJv(["wait", id, "--json"], env)
    expect(result.code).toBe(EXIT.error)
    expect((json(result) as { message: string }).message).toContain(`the vault did not accept the revocation of device ${deviceFor(id)}: an owner must revoke it on the Machines page`)
    expect(existsSync(join(pendingSlot(), "device-key.json"))).toBe(false)
    expect(await readConfig(pendingSlot())).toBeNull()
  })

  // Outside a bound checkout, wait selects the one context whose
  // ledger records the id before falling back to the default.
  test("mehen wait selects the context whose ledger alone records the id, refuses two hits, and polls under that context's identity", async () => {
    const home = await tempDir()
    try {
      const homeEnv = { HOME: home.path, MEHEN_CONFIG_DIR: "", MEHEN_VAULT_URL: vault.url }
      const a = await vault.enrolSoftware(join(home.path, ".config", "mehen"))
      const second = vault.slotDir(join(home.path, ".config", "mehen"), "tn_second00000001")
      const b = await vault.enrolSoftware(join(home.path, ".config", "mehen"), { config: { tenant: "tn_second00000001", workspaceSlug: "second-space", workspaceName: "Second" } })
      const bScope = { vaultUrl: vault.url, workspace: "tn_second00000001", device: b, workspaceSlug: "second-space" }
      const bLink = (askUrl(`${vault.url}/w/second-space/a/apr_inB`, { vaultUrl: vault.url, workspaceSlug: "second-space" }) as { url: AskUrl }).url
      await addLedgerEntry(second, bScope, { ask: approvalAsk({ id: "apr_inB", url: bLink, summary: "Send", bindingCode: "K7Q2MX", expiresAt: inMinutes(50), requestedBy: by }) })
      vault.sequences.set("approval:apr_inB", [{ ...APPROVED, approval: "apr_inB" }])
      const before = vault.seen.length
      const result = await runJv(["wait", "apr_inB", "--timeout", "0", "--json"], homeEnv)
      expect(result.code).toBe(EXIT.ok)
      const polls = vault.seen.slice(before)
      expect(polls.length).toBeGreaterThan(0)
      for (const poll of polls) expect(poll.claims).toMatchObject({ ten: "tn_second00000001", dev: b })
      // The same id in both ledgers (the settled B entry put back): ambiguous, and nothing is polled.
      await addLedgerEntry(second, bScope, { ask: approvalAsk({ id: "apr_inB", url: bLink, summary: "Send", bindingCode: "K7Q2MX", expiresAt: inMinutes(50), requestedBy: by }) })
      const aScope = { vaultUrl: vault.url, workspace: MOCK_TENANT, device: a, workspaceSlug: "mock-space" }
      await addLedgerEntry(vault.slotDir(join(home.path, ".config", "mehen")), aScope, { ask: approvalAsk({ id: "apr_inB", url: link("/a/apr_inB"), summary: "Send", bindingCode: "K7Q2MX", expiresAt: inMinutes(50), requestedBy: by }) })
      const seen = vault.seen.length
      const ambiguous = await runJv(["wait", "apr_inB", "--timeout", "0", "--json"], homeEnv)
      expect(ambiguous.code).toBe(EXIT.usage)
      expect(json(ambiguous)).toMatchObject({ error: "context_ambiguous" })
      expect(vault.seen.length).toBe(seen)
      // An explicit selector overrides the ledger stage.
      const explicit = await runJv(["wait", "apr_inB", "--timeout", "0", "--json", "--workspace", "mock-space"], homeEnv)
      expect(vault.seen.slice(seen).every((c) => c.claims.dev === a)).toBe(true)
      expect(explicit.code).toBe(EXIT.ok)
    } finally {
      await home.remove()
    }
  })

  test("an active answer for another workspace self-revokes, deletes the provisional key and writes no config (threat T11)", async () => {
    const { id } = await pendingEnrolment()
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    vault.activeAnswer = (_enrolment, activated) => ({ status: "active", tenant: MOCK_TENANT, workspace: { id: MOCK_TENANT, slug: "other-space", name: "Other" }, device: activated, scope: WORKSPACE_SCOPE, owner: MOCK_OWNER })
    try {
      const result = await runJv(["wait", id, "--json"], env)
      expect(result.code).toBe(EXIT.usage)
      expect(json(result)).toMatchObject({ error: "workspace_mismatch", message: expect.stringContaining("it is for workspace other-space, not mock-space") })
      expect(await readConfig(pendingSlot())).toBeNull()
      expect(await readKeyScope(pendingSlot(), "software")).toBeNull()
      await expect(stat(join(pendingSlot(), SOFTWARE_KEY_FILE))).rejects.toMatchObject({ code: "ENOENT" })
      expect(vault.revoked).toContain(deviceFor(id))
      expect(existsSync(activeSlot())).toBe(false)
    } finally {
      vault.activeAnswer = null
    }
  })
})
describe("mehen wait: outcome sentences", () => {
  test("completed: added, approved, approved and used, connected", async () => {
    await enrolled()
    vault.sequences.set("intake:int_done", [{ intake: "int_done", status: "completed", item: item("openai-new") }])
    expect((await runJv(["wait", "int_done"], env)).stdout).toBe("Added openai-new (OpenAI API key, goes to api.openai.com).\n  then:    mehen fetch openai-new GET https://api.openai.com/...\n")
    vault.sequences.set("intake:int_client", [{ intake: "int_client", status: "completed", item: item("google-oauth-client", { kind: "oauth-client", provider: "google-oauth-client", hosts: ["oauth2.googleapis.com"] }) }])
    expect((await runJv(["wait", "int_client"], env)).stdout).toBe('Added google-oauth-client (Google OAuth client, goes to oauth2.googleapis.com).\n  then:    mehen connect google-gmail --client google-oauth-client --name <slug> --reason "<why>"\n')
    vault.sequences.set("intake:int_bare", [{ intake: "int_bare", status: "completed" }])
    expect((await runJv(["wait", "int_bare"], env)).stdout).toBe("Completed: intake int_bare is done.\n")

    vault.sequences.set("approval:apr_ok", [APPROVED])
    const approved = await runJv(["wait", "apr_ok"], env)
    expect(approved.code).toBe(EXIT.ok)
    expect(approved.stdout).toMatch(/^Approved: Send an email to sam@example.com\.  Grant gnt_1: 1 use, until (\d\d:\d\d|\d+ \w+ \d\d:\d\d)\.\n  then:    repeat the same mehen fetch or mehen run \(you may add --approval apr_ok\)\n$/)
    vault.sequences.set("approval:apr_used", [{ ...APPROVED, approval: "apr_used", status: "used", grant: { id: "gnt_2", uses: null, expiresAt: "2026-10-24T16:12:00.000Z" } }])
    const used = await runJv(["wait", "apr_used"], env)
    expect(used.code).toBe(EXIT.ok)
    expect(used.stdout).toMatch(/^Approved and used: Send an email to sam@example.com\.  Grant gnt_2: unlimited uses, until /)

    vault.sequences.set("connect:con_ok", [{ connect: "con_ok", status: "completed", item: GMAIL_ITEM, account: "alex@example.com", grantedScopes: ["https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/gmail.labels"] }])
    expect((await runJv(["wait", "con_ok"], env)).stdout).toBe("Connected gmail-alex as alex@example.com (Gmail; scopes gmail.modify, gmail.labels).\n  then:    mehen fetch gmail-alex GET https://gmail.googleapis.com/gmail/v1/...\n")
    vault.sequences.set("connect:con_min", [{ connect: "con_min", status: "completed" }])
    expect((await runJv(["wait", "con_min"], env)).stdout).toBe("Connected con_min.\n")
  })

  test("status words are coloured only through the styler", () => {
    const lines = outcomeLines({ kind: "approval", status: { ...APPROVED, status: "approved", expiresAt: "2026-10-24T16:12:00.000Z" } }, styler(true))
    expect(terminalText(lines[0] ?? [])).toStartWith("\u001b[32mApproved\u001b[0m: Send an email")
    expect(plainText(lines[1] ?? [])).toBe("  then:    repeat the same mehen fetch or mehen run (you may add --approval apr_ok)")
    const hostile = outcomeLines({ kind: "intake", status: { intake: "int_h", status: "completed", expiresAt: "x", item: { ...item("evil-key"), hosts: ["api.evil.test\u001b[31m"] } } }, plainStyler())
    expect(terminalText(hostile[0] ?? [])).toBe("Added evil-key (OpenAI API key, goes to api.evil.test\\u001B[31m).")
  })

  test("a credential with no host is added with what its ceiling allows, never the reserved host or a mehen fetch", () => {
    const added = (extra: Partial<ReturnType<typeof item>>) => outcomeLines({ kind: "intake", status: { intake: "int_l", status: "completed", expiresAt: "x", item: { ...item("session-secret", { provider: null, hosts: [LEASE_ONLY_HOST], ...extra }) } } }, plainStyler()).map(plainText)
    expect(added({ kind: "generic", ceiling: "lease" })).toEqual(["Added session-secret (generic, no host: only delivered into a process with mehen run).", "  then:    mehen env set <NAME> --env <env> --item session-secret, then mehen run -- <command>"])
    expect(added({ kind: "hmac-key", ceiling: "sign" })).toEqual(["Added session-secret (hmac-key, no host: stored only; a human can allow mehen run by setting its ceiling to lease).", "  then:    mehen show session-secret"])
    expect(added({ kind: "ssh-key", ceiling: "sign" })).toEqual(["Added session-secret (ssh-key, no host: stored only).", "  then:    mehen show session-secret"])
  })

  test("denied, expired (with the full re-request from the ledger), cancelled and superseded", async () => {
    await enrolled()
    vault.sequences.set("approval:apr_no", [{ approval: "apr_no", status: "denied", bindingCode: "K7Q2", summary: "Send an email" }])
    const denied = await runJv(["wait", "apr_no"], env)
    expect(denied.code).toBe(EXIT.refused)
    expect(denied.stderr).toBe("mehen: The human denied approval apr_no: Send an email.\nnext: The request was denied; do not retry it without asking the human.\n")

    vault.sequences.set("approval:apr_late", [{ approval: "apr_late", status: "expired", bindingCode: "K7Q2", summary: "Send an email" }])
    const lateApproval = await runJv(["wait", "apr_late", "--json"], env)
    expect(lateApproval.code).toBe(EXIT.error)
    expect(json(lateApproval)).toMatchObject({ error: "expired", message: "Approval apr_late expired before a decision: Send an email.", next: { say: "Repeat the original request to get a fresh approval link, and share it sooner." } })

    const command = "mehen request api-key --name openai-new --provider openai --reason 'summarise the support inbox'"
    await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask: intakeAsk({ id: "int_exp", url: link("/i/int_exp"), name: "openai-new", kind: "api-key", provider: "openai", reason: "summarise the support inbox", expiresAt: inMinutes(5), requestedBy: by }), slug: "openai-new", command })
    vault.sequences.set("intake:int_exp", [{ intake: "int_exp", status: "expired" }])
    const expired = await runJv(["wait", "int_exp", "--json"], env)
    expect(expired.code).toBe(EXIT.error)
    expect(json(expired)).toMatchObject({ error: "expired", message: "The link for intake int_exp expired before a human added the credential.", next: { command } })
    expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])
    vault.sequences.set("intake:int_other", [{ intake: "int_other", status: "expired" }])
    expect(json(await runJv(["wait", "int_other", "--json"], env))).toMatchObject({ next: { command: "mehen request <kind> --name <slug> --reason <why>" } })

    vault.sequences.set("intake:int_can", [{ intake: "int_can", status: "cancelled" }])
    const cancelled = await runJv(["wait", "int_can", "--json"], env)
    expect(cancelled.code).toBe(EXIT.error)
    expect(json(cancelled)).toMatchObject({ error: "cancelled", message: "The human cancelled intake int_can without adding the credential." })

    await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask: intakeAsk({ id: "int_old", url: link("/i/int_old"), name: "openai-new", kind: "api-key", provider: "openai", reason: "r", expiresAt: inMinutes(5), requestedBy: by }), slug: "openai-new", command })
    await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask: intakeAsk({ id: "int_new", url: link("/i/int_new"), name: "openai-new", kind: "api-key", provider: "openai", reason: "r", expiresAt: inMinutes(5), requestedBy: by }), slug: "openai-new", command })
    vault.sequences.set("intake:int_old", [{ intake: "int_old", status: "cancelled", superseded: true }])
    const superseded = await runJv(["wait", "int_old", "--json"], env)
    expect(superseded.code).toBe(EXIT.error)
    expect(json(superseded)).toMatchObject({ error: "cancelled", message: "Intake int_old was replaced by a newer link from this machine (mehen request --new): int_new.", next: { command: "mehen wait int_new" } })
    expect((await readLedger(vault.slotDir(dir.path), scope())).map((e) => e.ask.id)).toEqual(["int_new"])
    vault.sequences.set("intake:int_lone", [{ intake: "int_lone", status: "cancelled", superseded: true }])
    expect(json(await runJv(["wait", "int_lone", "--json"], env))).toMatchObject({ message: "Intake int_lone was replaced by a newer link from this machine (mehen request --new).", next: { command: "mehen pending" } })
  })

  test("mismatch (exit 4, link still live so the ask goes out again), failed and expired connections", async () => {
    await enrolled()
    const command = "mehen connect google-gmail --client google-oauth-client --name gmail-alex --expect alex@example.com --reason triage"
    const ask = connectAsk({ id: "con_x", url: link("/c/con_x"), name: "gmail-alex", provider: "google-gmail", account: "alex@example.com", reason: "triage", expiresAt: inMinutes(10), requestedBy: by })
    await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask, slug: "gmail-alex", command })
    vault.sequences.set("connect:con_x", [{ connect: "con_x", status: "mismatch", account: "bob@example.com", message: "You signed in as bob@example.com, not alex@example.com." }])
    const mismatch = await runJv(["wait", "con_x", "--json"], env)
    expect(mismatch.code).toBe(EXIT.human)
    expect(json(mismatch)).toMatchObject({ error: "mismatch", message: "You signed in as bob@example.com, not alex@example.com.", next: { command: "mehen wait con_x" }, ask: { id: "con_x", account: "alex@example.com" } })
    expect(await readLedger(vault.slotDir(dir.path), scope())).toHaveLength(1)
    const human = await runJv(["wait", "con_x"], env)
    expect(human.stderr).toContain("mehen: You signed in as bob@example.com, not alex@example.com.")
    expect(human.stderr).toContain("  check:   the page shows account alex@example.com; sign in as that account")

    vault.sequences.set("connect:con_x", [{ connect: "con_x", status: "failed", message: "The provider refused the token exchange" }])
    const failed = await runJv(["wait", "con_x", "--json"], env)
    expect(failed.code).toBe(EXIT.error)
    expect(json(failed)).toMatchObject({ error: "failed", message: "Connection con_x failed: The provider refused the token exchange.", next: { command } })
    expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])

    vault.sequences.set("connect:con_gone", [{ connect: "con_gone", status: "expired" }])
    const expired = await runJv(["wait", "con_gone", "--json"], env)
    expect(expired.code).toBe(EXIT.error)
    expect(json(expired)).toMatchObject({ error: "expired", message: "The link for connection con_gone expired before the human finished signing in.", next: { command: "mehen connect <provider> --name <slug> --reason <why>" } })
    vault.sequences.set("connect:con_silent", [{ connect: "con_silent", status: "failed" }])
    expect(json(await runJv(["wait", "con_silent", "--json"], env)).message).toBe("Connection con_silent failed: the vault did not say why.")
  })

  test("a timeout keeps the ledger entry and hands the ask back with the error", async () => {
    await enrolled()
    const ask = approvalAsk({ id: "apr_slow", url: link("/a/apr_slow"), summary: "Send an email", bindingCode: "K7Q2MX", expiresAt: inMinutes(50), requestedBy: by })
    await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask })
    const result = await runJv(["wait", "apr_slow", "--timeout", "0", "--json"], env)
    expect(result.code).toBe(EXIT.human)
    expect(json(result)).toMatchObject({ error: "timeout", next: { command: "mehen wait apr_slow" }, ask: { id: "apr_slow", check: { label: "code", value: "K7Q2MX" } } })
    expect(await readLedger(vault.slotDir(dir.path), scope())).toHaveLength(1)
    const human = await runJv(["wait", "apr_slow", "--timeout", "0"], env)
    expect(human.stderr).toContain("  check:   the page shows code K7Q2MX")
  })

  test("waitOutput keeps the id and kind and filters the item", () => {
    const out = waitOutput("con_1", { kind: "connect", status: { connect: "con_1", status: "completed", expiresAt: "x", account: "a@b", item: { ...GMAIL_ITEM, extra: 1 } as typeof GMAIL_ITEM } })
    expect(out).toMatchObject({ id: "con_1", kind: "connect", status: "completed", account: "a@b", item: { slug: "gmail-alex" } })
    expect((out.item as Record<string, unknown>).extra).toBeUndefined()
    expect((out.item as Record<string, unknown>).secretFields).toBeUndefined()
  })
})

describe("mehen wait: the ask on a terminal", () => {
  test("the ledger's ask is not printed off a TTY, and the countdown never reaches a pipe", async () => {
    await enrolled()
    const ask = approvalAsk({ id: "apr_q", url: link("/a/apr_q"), summary: "Send an email", bindingCode: "K7Q2MX", expiresAt: inMinutes(50), requestedBy: by })
    await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask })
    vault.sequences.set("approval:apr_q", [{ approval: "apr_q", status: "pending", bindingCode: "K7Q2MX", summary: "Send an email" }, { ...APPROVED, approval: "apr_q" }])
    const result = await runJv(["wait", "apr_q"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(result.stderr).toBe("")
    expect(result.stdout).not.toContain("Waiting")
    expect(result.stdout).not.toContain("Human needed")
    expect(join(vault.slotDir(dir.path), "ledger.json")).toBeDefined()
  })
})

describe("mehen wait policy and guarded approvals", () => {
  const proposal = { proposal: "pol_x", item: "example-key", status: "pending", bindingCode: "CODE", summary: "Relax the route", expiresAt: inMinutes(60), outcome: null }
  const grant = { id: "gnt_x", uses: null, expiresAt: inMinutes(30), kind: "route", scope: { selector: { device: "dev_x", session: null }, route: null }, parent: "pov_x" }

  async function recordPolicy(): Promise<void> {
    const ask = policyAsk({ id: "pol_x", url: link("/p/pol_x"), summary: proposal.summary, bindingCode: "CODE", expiresAt: inMinutes(60), requestedBy: by })
    await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask })
  }

  test("pending policy times out at exit 4 and retains its ask and ledger entry", async () => {
    await enrolled()
    await recordPolicy()
    vault.overrides.set("GET /v1/policy/proposals/pol_x", () => Response.json(proposal))
    const result = await runJv(["wait", "pol_x", "--json", "--timeout", "0"], env)
    expect(result.code).toBe(4)
    expect(json(result)).toMatchObject({ error: "timeout", ask: { kind: "policy", id: "pol_x", wait: "mehen wait pol_x --timeout 60 --json" } })
    expect((await readLedger(vault.slotDir(dir.path), scope())).map((e) => e.ask.id)).toEqual(["pol_x"])
  })

  test("policy waiting and settled events preserve the actual narrowed, already ended outcome", async () => {
    await enrolled()
    let polls = 0
    const outcome = { change: { kind: "mode", policyMode: "relaxed", ttlSeconds: 60 }, override: "pov_narrowed", grant: null, effectiveUntil: inMinutes(1), active: false, endedReason: "revoked" }
    vault.overrides.set("GET /v1/policy/proposals/pol_x", () => Response.json(++polls === 1 ? proposal : { ...proposal, status: "approved", outcome }))
    const result = await runJv(["wait", "pol_x", "--json", "--events"], env)
    expect(result.code).toBe(0)
    const events = jsonLines(result.stdout)
    expect(events).toContainEqual(expect.objectContaining({ event: "waiting", kind: "policy", ask: expect.objectContaining({ kind: "policy", url: `${vault.url}/w/mock-space/p/pol_x` }) }))
    expect(events.at(-1)).toMatchObject({ event: "settled", id: "pol_x", kind: "policy", status: "approved", outcome })
  })

  test("an approved rule proposal says which rule allows it from now on and until when; its JSON carries the rule", async () => {
    await enrolled()
    const endsAt = inMinutes(7 * 24 * 60)
    vault.overrides.set("GET /v1/policy/proposals/pol_rule", () => Response.json(ruleStatus({ status: "approved", rule: { id: "rul_live", endsAt } })))
    const result = await runJv(["wait", "pol_rule", "--json"], env)
    expect(result.code).toBe(0)
    expect(json(result)).toMatchObject({ id: "pol_rule", kind: "policy", status: "approved", rule: { id: "rul_live", endsAt } })
    const lines = outcomeLines({ kind: "policy", status: ruleStatus({ status: "approved", rule: { id: "rul_live", endsAt } }) }, plainStyler()).map(plainText)
    expect(lines).toEqual([`Approved: rule rul_live allows this from now on, until ${clockText(endsAt)}.`, "  then:    mehen policy ls --item example-key"])
  })

  test("an expired rule proposal says so in standing-rule words, not a window's", async () => {
    await enrolled()
    vault.overrides.set("GET /v1/policy/proposals/pol_rule", () => Response.json(ruleStatus({ status: "expired" })))
    const result = await runJv(["wait", "pol_rule", "--json"], env)
    expect(result.code).toBe(1)
    expect(json(result)).toMatchObject({ error: "expired", next: { command: "mehen policy show example-key", say: "This standing rule proposal expired before anyone approved it. Check the item's rules with mehen policy show, and propose it again only if the agent still needs it." } })
    expect(result.stdout).not.toContain("window")
  })

  test("an approval remembered as a standing rule says which rule allows it from now on; its JSON carries rule", async () => {
    await enrolled()
    const endsAt = inMinutes(7 * 24 * 60)
    vault.sequences.set("approval:apr_rule", [{ ...APPROVED, approval: "apr_rule", rule: { id: "rul_live", endsAt } }])
    const human = await runJv(["wait", "apr_rule"], { ...env, TZ: "Etc/UTC" })
    expect(human.code).toBe(EXIT.ok)
    expect(human.stdout).toContain(`\n  Allowed from now on by rule rul_live until ${clockText(endsAt, { timeZone: "Etc/UTC" })}.\n  then:    repeat the same mehen fetch`)
    vault.sequences.set("approval:apr_rule", [{ ...APPROVED, approval: "apr_rule", rule: { id: "rul_live", endsAt } }])
    expect(json(await runJv(["wait", "apr_rule", "--json"], env))).toMatchObject({ id: "apr_rule", kind: "approval", status: "approved", rule: { id: "rul_live", endsAt } })
  })

  test("an approval whose rule waits for a co-signer shows that proposal's link and code; its JSON carries ruleProposal", async () => {
    await enrolled()
    const ruleProposal = { id: "pol_cosign", url: `${vault.url}/w/mock-space/p/pol_cosign`, bindingCode: "COSIGN", expiresAt: inMinutes(60) }
    vault.sequences.set("approval:apr_rule", [{ ...APPROVED, approval: "apr_rule", item: "example-key", ruleProposal }])
    const human = await runJv(["wait", "apr_rule"], env)
    expect(human.code).toBe(EXIT.ok)
    expect(human.stdout).toContain(`\n  A manager must co-sign the standing rule; open ${ruleProposal.url}, code COSIGN. Once co-signed, the rule appears in mehen policy ls --item example-key and in mehen wait apr_rule.\n`)
    expect(human.stdout).not.toContain("mehen wait pol_cosign")
    vault.sequences.set("approval:apr_rule", [{ ...APPROVED, approval: "apr_rule", ruleProposal }])
    expect((await runJv(["wait", "apr_rule"], env)).stdout).toContain("code COSIGN. Once co-signed, the rule appears in mehen policy ls and in mehen wait apr_rule.\n")
    vault.sequences.set("approval:apr_rule", [{ ...APPROVED, approval: "apr_rule", ruleProposal }])
    expect(json(await runJv(["wait", "apr_rule", "--json"], env))).toMatchObject({ id: "apr_rule", kind: "approval", ruleProposal })
  })

  test("refusal/a remembered rule's fields that do not check out are dropped, never printed or passed on", async () => {
    await enrolled()
    for (const extra of [{ rule: { id: "rul_a b", endsAt: inMinutes(60) } }, { rule: { id: "rul_live", endsAt: "soon" } }, { ruleProposal: { id: "pol_cosign", url: "https://evil.example/w/mock-space/p/pol_cosign", bindingCode: "COSIGN", expiresAt: inMinutes(60) } }, { ruleProposal: { id: "pol_cosign", url: `${vault.url}/w/mock-space/p/pol_other`, bindingCode: "COSIGN", expiresAt: inMinutes(60) } }]) {
      vault.sequences.set("approval:apr_rule", [{ ...APPROVED, approval: "apr_rule", ...extra }])
      const human = await runJv(["wait", "apr_rule"], env)
      expect(human.stdout).not.toMatch(/evil|rul_a|co-sign|Allowed from now on/)
      vault.sequences.set("approval:apr_rule", [{ ...APPROVED, approval: "apr_rule", ...extra }])
      const out = json(await runJv(["wait", "apr_rule", "--json"], env))
      expect(out).not.toHaveProperty("rule")
      expect(out).not.toHaveProperty("ruleProposal")
    }
  })

  test("terminal policy refusals remove only their ledger entry and retain status in error events", async () => {
    await enrolled()
    const other = approvalAsk({ id: "apr_other", url: link("/a/apr_other"), summary: "Other request", bindingCode: null, expiresAt: inMinutes(60), requestedBy: by })
    await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask: other })
    for (const [status, exit] of [["stale", 5], ["denied", 5], ["expired", 1], ["cancelled", 1]] as const) {
      await recordPolicy()
      vault.overrides.set("GET /v1/policy/proposals/pol_x", () => Response.json({ ...proposal, status }))
      const result = await runJv(["wait", "pol_x", "--json", "--events"], env)
      expect(result.code).toBe(exit)
      expect(jsonLines(result.stdout).at(-1)).toMatchObject({ event: "error", id: "pol_x", kind: "policy", status, error: status })
      expect((await readLedger(vault.slotDir(dir.path), scope())).map((e) => e.ask.id)).toEqual(["apr_other"])
    }
  })

  test("revoked and stale approvals settle once, retaining grant metadata and stopped wording", async () => {
    await enrolled()
    for (const status of ["revoked", "stale"] as const) {
      const ask = approvalAsk({ id: "apr_guarded", url: link("/a/apr_guarded"), summary: "Read", bindingCode: null, expiresAt: inMinutes(60), requestedBy: by })
      await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask })
      vault.overrides.set("GET /v1/approvals/apr_guarded", () => Response.json({ approval: "apr_guarded", item: "example-key", status, grant, summary: "Read", expiresAt: inMinutes(60) }))
      const before = vault.seen.length
      const result = await runJv(["wait", "apr_guarded", "--json", "--events"], env)
      expect(result.code).toBe(5)
      const event = jsonLines(result.stdout).at(-1) as Record<string, unknown> | undefined
      expect(event).toMatchObject({ event: "error", kind: "approval", status, error: status === "revoked" ? "denied" : "stale", grant })
      if (status === "revoked") {
        expect(JSON.stringify(event?.next)).toContain("stopped")
        expect(JSON.stringify(event?.next)).not.toContain("denied")
      }
      expect(vault.seen.slice(before).map((r) => r.path)).toEqual(["/v1/approvals/apr_guarded"])
      expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])
    }
  })

  test("an approval that was given and expired unused says so, not that it expired before a decision", async () => {
    await enrolled()
    for (const approvedAt of [inMinutes(-50), undefined]) {
      const ask = approvalAsk({ id: "apr_unused", url: link("/a/apr_unused"), summary: "Create", bindingCode: null, expiresAt: inMinutes(60), requestedBy: by })
      await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask })
      vault.overrides.set("GET /v1/approvals/apr_unused", () => Response.json({ approval: "apr_unused", item: "example-key", status: "expired", bindingCode: "Q7", summary: "Create", expiresAt: inMinutes(-1), ...(approvedAt ? { approvedAt } : {}) }))
      const result = await runJv(["wait", "apr_unused", "--json", "--timeout", "0"], env)
      expect(result.code).toBe(1)
      const body = json(result)
      expect(body).toMatchObject({ error: "expired" })
      if (approvedAt) {
        expect(String(body.message)).toContain("was approved but expired before the request used it")
        expect(JSON.stringify(body.next)).toContain("--approval")
      } else expect(String(body.message)).toContain("expired before a decision")
    }
  })

  test("a superseded approval ends at once: exit 5, the newer ask's wait command and the design's sentence, and its ledger entry goes", async () => {
    await enrolled()
    const ask = approvalAsk({ id: "apr_old", url: link("/a/apr_old"), summary: "Create", bindingCode: null, expiresAt: inMinutes(60), requestedBy: by })
    await addLedgerEntry(vault.slotDir(dir.path), scope(), { ask })
    vault.overrides.set("GET /v1/approvals/apr_old", () => Response.json({ approval: "apr_old", item: "example-key", status: "superseded", replacedBy: "apr_new", bindingCode: "Q7", summary: "Create", expiresAt: inMinutes(60) }))
    const before = vault.seen.length
    const result = await runJv(["wait", "apr_old", "--json", "--timeout", "10m"], env)
    expect(result.code).toBe(EXIT.refused)
    expect(json(result)).toMatchObject({
      error: "superseded",
      message: "A newer request to the same place replaced apr_old.",
      next: { command: "mehen wait apr_new", say: "Wait on apr_new; if you meant both, send them together with mehen plan submit." },
      replacedBy: "apr_new",
    })
    expect(vault.seen.slice(before).map((r) => r.path)).toEqual(["/v1/approvals/apr_old"])
    expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])
    const human = await runJv(["wait", "apr_old"], env)
    expect(human.code).toBe(EXIT.refused)
    expect(human.stderr).toContain("A newer request to the same place replaced apr_old.")
    expect(human.stderr).toContain("mehen wait apr_new")
  })

  test("a superseded approval without a usable replacedBy points at mehen pending, never at an id mehen does not know", async () => {
    await enrolled()
    for (const replacedBy of [undefined, "apr_new; rm -rf ~", "int_x"]) {
      vault.overrides.set("GET /v1/approvals/apr_old", () => Response.json({ approval: "apr_old", status: "superseded", ...(replacedBy === undefined ? {} : { replacedBy }), bindingCode: "Q7", summary: "Create" }))
      const result = await runJv(["wait", "apr_old", "--json"], env)
      expect(result.code).toBe(EXIT.refused)
      const body = json(result)
      expect(body).toMatchObject({ error: "superseded", message: "A newer request to the same place replaced apr_old.", next: { command: "mehen pending" } })
      expect(JSON.stringify(body)).not.toContain("rm -rf")
      expect(String((body.next as { say: string }).say)).toContain("mehen plan submit")
    }
  })
})

describe("mehen wait bnd_", () => {
  const bundle = (approvals: [string, string][]) => ({ bundle: "bnd_b1", approvals: approvals.map(([id, status]) => ({ id, status })) })

  test("waits while any request is pending, then exits 0 when every one was approved", async () => {
    await enrolled()
    vault.sequences.set("bundle:bnd_b1", [bundle([["apr_a", "approved"], ["apr_b", "pending"]]), bundle([["apr_a", "approved"], ["apr_b", "used"]])])
    const result = await runJv(["wait", "bnd_b1", "--json", "--timeout", "10m"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toEqual({ id: "bnd_b1", kind: "bundle", bundle: "bnd_b1", approvals: [{ id: "apr_a", status: "approved" }, { id: "apr_b", status: "used" }] })
    expect(vault.seen.filter((r) => r.path === "/v1/approvals/bundles/bnd_b1").map((r) => r.search)).toEqual(["", "?wait=1"])
    vault.sequences.set("bundle:bnd_b1", [bundle([["apr_a", "approved"]])])
    const human = await runJv(["wait", "bnd_b1"], env)
    expect(human.stdout).toContain("Approved: all 1 request in bnd_b1.")
  })

  test("any denied, stopped or replaced request exits 5, and next.say names the approved ones as usable", async () => {
    await enrolled()
    for (const status of ["denied", "revoked", "superseded"]) {
      vault.sequences.set("bundle:bnd_b1", [bundle([["apr_a", "approved"], ["apr_b", status], ["apr_c", "approved"]])])
      const result = await runJv(["wait", "bnd_b1", "--json"], env)
      expect(result.code).toBe(EXIT.refused)
      const body = json(result)
      expect(body).toMatchObject({ error: "denied", bundle: "bnd_b1", approvals: [{ id: "apr_a" }, { id: "apr_b", status }, { id: "apr_c" }] })
      expect(String(body.message)).toBe(`2 of 3 requests in bnd_b1 were approved; 1 ${status === "revoked" ? "stopped" : status}.`)
      expect(String((body.next as { say: string }).say)).toStartWith("The approved ones stay usable: repeat each with its --approval (apr_a, apr_c).")
    }
    vault.sequences.set("bundle:bnd_b1", [bundle([["apr_a", "expired"], ["apr_b", "approved"]])])
    const expired = await runJv(["wait", "bnd_b1", "--json"], env)
    expect(expired.code).toBe(EXIT.error)
    expect(json(expired)).toMatchObject({ error: "expired", message: "1 of 2 requests in bnd_b1 was approved; 1 expired." })
  })

  test("a human who has not acted by the timeout is exit 4; an unreadable status is an error, not a wait", async () => {
    await enrolled()
    vault.sequences.set("bundle:bnd_b1", [bundle([["apr_a", "pending"]])])
    const result = await runJv(["wait", "bnd_b1", "--json", "--timeout", "0"], env)
    expect(result.code).toBe(EXIT.human)
    expect(json(result)).toMatchObject({ error: "timeout", message: "Bundle bnd_b1 is still waiting for a human.", next: { command: "mehen wait bnd_b1" } })
    vault.sequences.set("bundle:bnd_b1", [{ bundle: "bnd_b1", approvals: [{ id: "apr_a", status: "maybe" }] }])
    expect(json(await runJv(["wait", "bnd_b1", "--json"], env))).toMatchObject({ error: "internal" })
    expect((await runJv(["wait", "bnd_", "--json"], env)).code).toBe(EXIT.usage)
  })
})

describe("mehen wait mdp_", () => {
  const status = (state: string, mandate: string | null) => ({ proposal: "mdp_p1", state, mandate, expiresAt: "2026-11-15T09:00:00.000Z" })
  const answering = (...answers: unknown[]) => {
    const queue = [...answers]
    vault.overrides.set("GET /v1/mandates/proposals/mdp_p1", () => Response.json(queue.length > 1 ? queue.shift() : queue[0]))
  }

  test("waits while the proposal is open, then exits 0 with the mandate a person signed from it", async () => {
    await enrolled()
    answering(status("open", null), status("signed", "mdt_m1"))
    const result = await runJv(["wait", "mdp_p1", "--json", "--timeout", "10m"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toEqual({ id: "mdp_p1", kind: "mandate", proposal: "mdp_p1", state: "signed", mandate: "mdt_m1", expiresAt: "2026-11-15T09:00:00.000Z" })
    expect(vault.seen.filter((r) => r.path === "/v1/mandates/proposals/mdp_p1").map((r) => r.search)).toEqual(["", "?wait=1"])
    answering(status("signed", "mdt_m1"))
    const signed = await runJv(["wait", "mdp_p1"], env)
    // A decision, not live authority: the vault checks each request.
    expect(signed.stdout).toContain("Signed: a person signed mandate mdt_m1 for this machine. The vault checks each request against it when it is sent.")
    expect(signed.stdout).not.toContain("lets this machine make requests like these without asking")
    expect(signed.stdout).toContain("mehen mandate show mdt_m1")
    answering(status("expired", "mdt_m2"))
    const human = await runJv(["wait", "mdp_p1"], env)
    expect(human.code).toBe(EXIT.ok)
    expect(human.stdout).toContain("Settled: a person signed mandate mdt_m2 for this machine instead, which closed this proposal. The vault checks each request against it when it is sent.")
    expect(human.stdout).toContain("mehen mandate show mdt_m2")
  })

  test("an unsigned expiry exits 1 and says nothing changed; a timeout is exit 4", async () => {
    await enrolled()
    answering(status("expired", null))
    const expired = await runJv(["wait", "mdp_p1", "--json"], env)
    expect(expired.code).toBe(EXIT.error)
    expect(json(expired)).toMatchObject({ error: "expired", message: "Mandate proposal mdp_p1 expired before anyone signed it; nothing changed." })
    answering(status("open", null))
    const waiting = await runJv(["wait", "mdp_p1", "--json", "--timeout", "0"], env)
    expect(waiting.code).toBe(EXIT.human)
    expect(json(waiting)).toMatchObject({ error: "timeout", next: { command: "mehen wait mdp_p1" } })
    expect(String(json(waiting).message)).toStartWith("Mandate proposal mdp_p1 is still waiting for a human")
  })

  test("a vault without mandates says so; an unreadable status is an error, not a wait", async () => {
    await enrolled()
    vault.overrides.set("GET /v1/mandates/proposals/mdp_p1", () => vaultError("not_found", "No such route."))
    expect(json(await runJv(["wait", "mdp_p1", "--json"], env))).toMatchObject({ error: "not_found", message: "This workspace has no mandates: they are not switched on here, or this vault is older than them." })
    answering({ proposal: "mdp_other", state: "signed", mandate: "mdt_m1", expiresAt: "2026-11-15T09:00:00.000Z" })
    expect(json(await runJv(["wait", "mdp_p1", "--json"], env))).toMatchObject({ error: "internal" })
  })
})

describe("mehen wait: an id the vault does not know", () => {
  test("is not_found naming the kind and pointing at mehen pending, never at credentials", async () => {
    await enrolled()
    for (const [id, path, words] of [["apr_gone1", "/v1/approvals/apr_gone1", "approval"], ["con_gone1", "/v1/connect/con_gone1", "connection"], ["bnd_gone1", "/v1/approvals/bundles/bnd_gone1", "bundle"]] as const) {
      vault.overrides.set(`GET ${path}`, () => vaultError("not_found", "No such object."))
      const result = await runJv(["wait", id, "--json"], env)
      expect(result.code).toBe(EXIT.error)
      expect(json(result)).toMatchObject({ error: "not_found", message: `No such ${words} ${id} in this workspace.`, next: { command: "mehen pending" } })
    }
  })

  test("a mandate proposal is not_found pointing at mehen mandate ls, which lists proposals, not at mehen pending", async () => {
    await enrolled()
    vault.overrides.set("GET /v1/mandates/proposals/mdp_gone1", () => vaultError("not_found", "No such proposal."))
    const result = await runJv(["wait", "mdp_gone1", "--json"], env)
    expect(result.code).toBe(EXIT.error)
    expect(json(result)).toMatchObject({ error: "not_found", message: "No such mandate proposal mdp_gone1 in this workspace.", next: { command: "mehen mandate ls", say: expect.stringContaining("mehen mandate ls") } })
    expect(JSON.stringify(json(result).next)).not.toContain("mehen pending")
  })
})

// An approval that asked for a push (ApprovalStatus.push): approving spends
// it at once, then the vault sends; the wait ends when the push's state is
// done, failed, unknown or not_sent (design push-providers 3.2 point 5).
describe("mehen wait: a push approval", () => {
  const SUMMARY = "Put openai-prod into GitHub acme/app, Actions secret OPENAI_API_KEY, using github-pat-ci"
  const pushStatus = (id: string, status: string, push: Record<string, unknown>) => ({ approval: id, status, bindingCode: "K7Q2MX", summary: SUMMARY, push: { destination: "github:acme/app/OPENAI_API_KEY", field: "key", version: 3, ...push } })
  const fast = () => ({ ...env, MEHEN_POLL_INTERVAL_MS: "0" })

  test("waits past approved and queued and sending until the push is done, then says where it went", async () => {
    await enrolled()
    vault.sequences.set("approval:apr_push", [pushStatus("apr_push", "pending", { state: "pending" }), pushStatus("apr_push", "used", { state: "queued" }), pushStatus("apr_push", "used", { state: "sending" }), pushStatus("apr_push", "used", { state: "done", outcome: "replaced" })])
    const before = vault.seen.length
    const human = await runJv(["wait", "apr_push"], fast())
    expect(human.code).toBe(EXIT.ok)
    expect(vault.seen.length - before).toBe(4)
    expect(human.stdout).toBe(`Pushed: ${SUMMARY}: replaced (version 3).\n`)
    vault.sequences.set("approval:apr_push", [pushStatus("apr_push", "used", { state: "sending" }), pushStatus("apr_push", "used", { state: "done", outcome: "created" })])
    const asJson = await runJv(["wait", "apr_push", "--json"], fast())
    expect(asJson.code).toBe(EXIT.ok)
    expect(json(asJson)).toMatchObject({ id: "apr_push", kind: "approval", status: "used", push: { destination: "github:acme/app/OPENAI_API_KEY", state: "done", outcome: "created" } })
  })

  // A wait that starts once the human has approved: the approval is spent
  // and the vault is sending, so nothing asks a human to act.
  test("a wait on an approved push being sent prints one line on a terminal, and no Human needed block", async () => {
    await enrolled()
    vault.sequences.set("approval:apr_go", [pushStatus("apr_go", "used", { state: "queued" }), pushStatus("apr_go", "used", { state: "sending" }), pushStatus("apr_go", "used", { state: "done", outcome: "replaced" })])
    const result = await runJv(["wait", "apr_go"], { ...fast(), MEHEN_TEST_STDERR_TTY: "1", NO_COLOR: "1" })
    expect(result.code).toBe(EXIT.ok)
    const line = "Approved; the push to GitHub acme/app, Actions secret OPENAI_API_KEY is being sent.\n"
    expect(result.stderr.split(line)).toHaveLength(2)
    expect(result.stderr).not.toContain("Human needed")
    expect(result.stderr).not.toContain("K7Q2MX")
    expect(result.stdout).toBe(`Pushed: ${SUMMARY}: replaced (version 3).\n`)
  })

  test("--events on an approved push being sent emits waiting events with no ask, then settled", async () => {
    await enrolled()
    vault.sequences.set("approval:apr_go", [pushStatus("apr_go", "used", { state: "queued" }), pushStatus("apr_go", "used", { state: "done", outcome: "created" })])
    const result = await runJv(["wait", "apr_go", "--json", "--events"], fast())
    expect(result.code).toBe(EXIT.ok)
    const events = jsonLines(result.stdout) as Record<string, unknown>[]
    expect(events.map((e) => e.event)).toEqual(["waiting", "settled"])
    for (const event of events) expect(event).not.toHaveProperty("ask")
    expect(result.stderr).toBe("")
  })

  test("a wait that times out on an approved push being sent says so and never to push again", async () => {
    await enrolled()
    vault.sequences.set("approval:apr_go", [pushStatus("apr_go", "used", { state: "sending" })])
    const result = await runJv(["wait", "apr_go", "--json", "--timeout", "0"], fast())
    expect(result.code).toBe(EXIT.human)
    const body = json(result) as { error: string; message: string; next: { command?: string; say: string } }
    expect(body).toMatchObject({ error: "timeout", message: "The push was approved and is still being sent. Wait again with mehen wait apr_go; do not push again.", next: { command: "mehen wait apr_go" } })
    expect(body.next.say).toContain("do not push again without asking the human")
    expect(body).not.toHaveProperty("ask")
    const human = await runJv(["wait", "apr_go", "--timeout", "0"], fast())
    expect(human.stderr).toStartWith("mehen: The push was approved and is still being sent. Wait again with mehen wait apr_go; do not push again.\n")
    expect(human.stderr).not.toContain("A human has not acted yet")
  })

  test("a push the provider refused is provider_refused, exit 5, with its providerStatus and no retry", async () => {
    await enrolled()
    vault.sequences.set("approval:apr_ref", [pushStatus("apr_ref", "used", { state: "failed", providerStatus: 403 })])
    const result = await runJv(["wait", "apr_ref", "--json"], fast())
    expect(result.code).toBe(EXIT.refused)
    const body = json(result) as { error: string; message: string; providerStatus: number; next: { say: string } }
    expect(body).toMatchObject({ error: "provider_refused", message: `GitHub refused the push (403): ${SUMMARY}.`, providerStatus: 403, push: { state: "failed" } })
    expect(body.next.say).toContain("do not push again without asking them")
    const human = await runJv(["wait", "apr_ref"], fast())
    expect(human.code).toBe(EXIT.refused)
    expect(human.stderr).toStartWith(`mehen: GitHub refused the push (403): ${SUMMARY}.\nnext: `)
  })

  // The vault records failed without providerStatus only for a provider's
  // rate limit: apps/vault/src/routes/push.ts:62-63 (sendPush) records any
  // VaultError but upstream_failed as failed with error.extra.providerStatus,
  // and apps/vault/src/push/common.ts:148 (answerError) is the only such
  // error without one, rate_limited. Each adapter makes one write request,
  // so a rate-limited answer means the provider wrote nothing.
  test("a failed push with no providerStatus (only rate_limited: vault routes/push.ts:62-63, push/common.ts:148) says nothing is known to have been written, exit 1", async () => {
    await enrolled()
    vault.sequences.set("approval:apr_lim", [pushStatus("apr_lim", "used", { state: "failed" })])
    const result = await runJv(["wait", "apr_lim", "--json"], fast())
    expect(result.code).toBe(EXIT.error)
    const body = json(result) as { error: string; message: string; next: { say: string; command?: string } }
    expect(body).toMatchObject({ error: "failed", message: `The push failed and nothing is known to have been written: ${SUMMARY}.` })
    expect(body).not.toHaveProperty("providerStatus")
    expect(body.next.say).toContain("do not push again without asking them")
    expect(body.next.command).toBeUndefined()
  })

  test("a push the vault did not send, or could not confirm, is failed, exit 1; unconfirmed says to check the provider first; neither suggests pushing again", async () => {
    await enrolled()
    vault.sequences.set("approval:apr_ns", [pushStatus("apr_ns", "used", { state: "not_sent" })])
    const notSent = await runJv(["wait", "apr_ns", "--json"], fast())
    expect(notSent.code).toBe(EXIT.error)
    expect(json(notSent)).toMatchObject({ error: "failed", message: `Mehen did not send the push; nothing was written: ${SUMMARY}.`, next: { say: "The approval is spent. Tell the human; do not push again without asking them." } })
    vault.sequences.set("approval:apr_unk", [pushStatus("apr_unk", "used", { state: "unknown" })])
    const unknown = await runJv(["wait", "apr_unk", "--json"], fast())
    expect(unknown.code).toBe(EXIT.error)
    expect(json(unknown)).toMatchObject({ error: "failed", message: `Mehen could not confirm the push: ${SUMMARY}.`, next: { say: "Check GitHub for OPENAI_API_KEY first, then tell the human; do not push again without asking them." } })
    for (const result of [notSent, unknown]) expect(JSON.stringify(json(result).next)).not.toContain("mehen push")
  })

  test("a push state this mehen does not know ends the wait as an older mehen would", async () => {
    await enrolled()
    vault.sequences.set("approval:apr_new", [pushStatus("apr_new", "used", { state: "recalled" })])
    const result = await runJv(["wait", "apr_new", "--json"], fast())
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toMatchObject({ id: "apr_new", status: "used", push: { state: "recalled" } })
  })

  test("an ended push that is not done prints its state and mehen show, never to repeat a fetch or run", async () => {
    await enrolled()
    vault.sequences.set("approval:apr_new", [pushStatus("apr_new", "used", { state: "recalled" })])
    const human = await runJv(["wait", "apr_new"], fast())
    expect(human.code).toBe(EXIT.ok)
    expect(human.stdout).toBe(`Approved and used: ${SUMMARY}. The push to GitHub acme/app, Actions secret OPENAI_API_KEY is recalled.\n  then:    mehen show <item>\n`)
    const named = outcomeLines({ kind: "approval", status: { ...pushStatus("apr_new", "used", { state: "recalled" }), item: "openai-prod", expiresAt: inMinutes(5) } as never }, plainStyler()).map(plainText)
    expect(named).toEqual([`Approved and used: ${SUMMARY}. The push to GitHub acme/app, Actions secret OPENAI_API_KEY is recalled.`, "  then:    mehen show openai-prod"])
    expect(named.join("\n")).not.toContain("repeat the same")
  })
})
