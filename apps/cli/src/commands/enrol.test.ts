import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { existsSync } from "node:fs"
import { chmod, lstat, mkdir, readFile, readdir, realpath, rm, stat, symlink, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { type EnrolRequestedScope, WorkspaceEnrolStartSchema } from "@mehen/protocol/workspace"
import { fingerprintGroups, fingerprintOf } from "@mehen/protocol/fingerprint"
import { type DeviceJwk, jwkThumbprint } from "@mehen/protocol/proof"
import { ensureConfigDir, readConfig } from "../config.ts"
import { activeSlotPath, pendingSlotPath } from "../home.ts"
import { ENCLAVE_KEY_FILE, ENCLAVE_PUBLIC_KEY_FILE, SOFTWARE_KEY_FILE, SOFTWARE_KEY_SCOPE_FILE, createDeviceKey, readKeyScope } from "../device-key.ts"
import { type EnrolmentRecord, readEnrolmentRecord } from "../enrolment-record.ts"
import { fakeHelper } from "../testing/fake-mehen-se.ts"
import { MOCK_OWNER, MOCK_TENANT, MOCK_WORKSPACE, MockVault, WORKSPACE_SCOPE, deviceFor, vaultError } from "../testing/mock-vault.ts"
import { type JvResult, jsonLines, runJv, tempDir } from "../testing/run-mehen.ts"
import { plainText } from "../tty.ts"
import { fingerprintLines, keyFingerprint } from "./enrol.ts"

let vault: MockVault
let dir: { path: string; remove(): Promise<void> }
let env: Record<string, string>

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_HOME: dir.path, MEHEN_VAULT_URL: vault.url }
  vault.overrides.clear()
  vault.sequences.clear()
  vault.enrolOutcome = { pendingPolls: 2, result: "active" }
  vault.enrolMode = "current"
  vault.renew409 = false
  vault.enrolLeaseMs = 60_000
  vault.renewIntervalMs = 60_000
  vault.activeAnswer = null
  vault.workspace = { ...MOCK_WORKSPACE }
  vault.owner = { ...MOCK_OWNER }
})
afterEach(async () => dir.remove())

function json(result: JvResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>
}

function lines(result: JvResult): Record<string, unknown>[] {
  return jsonLines(result.stdout) as Record<string, unknown>[]
}

// The pending slot an enrolment in mock-space lives in under the root, and
// the active slot the finish step renames it to.
function pendingSlot(origin = vault.url): string {
  return pendingSlotPath(dir.path, origin, "mock-space")
}
function activeSlot(origin = vault.url, tenant = MOCK_TENANT): string {
  return activeSlotPath(dir.path, origin, tenant)
}

async function record(slot = pendingSlot()): Promise<EnrolmentRecord | null> {
  const read = await readEnrolmentRecord(slot)
  return read && "record" in read ? read.record : null
}

// Edits the pending record on disk, as time passing or an older mehen would.
async function editRecord(change: (r: EnrolmentRecord) => EnrolmentRecord, slot = pendingSlot()): Promise<void> {
  const current = await record(slot)
  if (!current) throw new Error("no record")
  await writeFile(join(slot, "enrolment.json"), `${JSON.stringify(change(current), null, 2)}\n`, { mode: 0o600 })
}

const ENROLLED_DISPLAY = { workspaceSlug: MOCK_WORKSPACE.slug, workspaceName: MOCK_WORKSPACE.name, owner: MOCK_OWNER }
const ENROL = ["enrol", "--workspace", "mock-space", "--name", "test-mac", "--backend", "software"]

// The JWK each POST /v1/enrol carried, in order, since `from`.
function postedJwks(from = 0): DeviceJwk[] {
  return vault.seen
    .slice(from)
    .filter((call) => call.method === "POST" && call.path === "/v1/enrol")
    .map((call) => WorkspaceEnrolStartSchema.parse(JSON.parse(call.body)).jwk)
}

function renewals(from = 0): string[] {
  return vault.seen.slice(from).filter((call) => call.path.endsWith("/renew")).map((call) => call.path)
}

async function softwareJwk(slot = pendingSlot()): Promise<DeviceJwk> {
  const key = JSON.parse(await readFile(join(slot, SOFTWARE_KEY_FILE), "utf8")) as { x: string; y: string }
  return { kty: "EC", crv: "P-256", x: key.x, y: key.y }
}

function past(ms = 1_000): string {
  return new Date(Date.now() - ms).toISOString()
}

// The attempt's lease runs out, locally and at the mock vault alike.
async function lapse(slot = pendingSlot(), change: (r: EnrolmentRecord) => EnrolmentRecord = (r) => r): Promise<void> {
  const id = (await record(slot))?.id
  const enrolment = id ? vault.enrolments.get(id) : undefined
  if (enrolment) enrolment.expiresAt = Date.now() - 1_000
  await editRecord((r) => change({ ...r, expiresAt: past() }), slot)
}

describe("mehen enrol prints the ask and exits 0", () => {
  // The unresumable-record fallback cannot be reached through a fixture: the
  // validated reader drops a record whose link fails askUrl. Its next step
  // must still name the workspace, so the source literal is pinned.
  test("the unresumable-record fallback's next step names --workspace", async () => {
    const source = await readFile(new URL("./enrol.ts", import.meta.url), "utf8")
    expect(source).toContain('--fresh-key`, say: "The recorded enrolment cannot be resumed; start again with a fresh key." }')
    expect(source).not.toContain('command: "mehen enrol --fresh-key"')
  })

  test("creates a key, starts the attempt signed as ten=enrol dev=new, writes the record, prints the pending shape, and polls nothing", async () => {
    const before = vault.seen.length
    const result = await runJv([...ENROL, "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const pending = json(result)
    const fingerprint = await keyFingerprint(await softwareJwk())
    expect(pending).toMatchObject({ status: "pending", code: "ABCD2345", backend: "software", fingerprint, renewals: 0, claimed: false, slot: pendingSlot() })
    expect(pending.url).toBe(`${vault.url}/w/mock-space/e/ABCD2345`)
    expect(typeof pending.hardExpiresAt).toBe("string")
    expect(pending.ask).toMatchObject({ kind: "enrol", id: pending.enrolment, url: pending.url, check: { label: "fingerprint", value: fingerprint }, expiresAt: pending.expiresAt, wait: `mehen wait ${pending.enrolment} --timeout 60 --json`, intent: { workspace: "mock-space", team: null }, claimed: false, context: { origin: vault.url, workspace: null, device: null } })
    const calls = vault.seen.slice(before)
    expect(calls).toHaveLength(1)
    expect(calls[0]).toMatchObject({ method: "POST", path: "/v1/enrol", claims: { ten: "enrol", dev: "new" } })
    expect(JSON.parse(calls[0]?.body ?? "{}")).toMatchObject({ workspace: "mock-space", owner: { kind: "self" }, name: "test-mac", backend: "software" })
    expect(await record()).toMatchObject({ v: 1, state: "pending", id: pending.enrolment, code: "ABCD2345", url: pending.url, origin: vault.url, intent: { workspace: "mock-space", team: null }, name: "test-mac", backend: "software", renewals: 0, legacy: false, claimed: false, hardExpiresAt: pending.hardExpiresAt })
    expect((await stat(join(pendingSlot(), "enrolment.json"))).mode & 0o777).toBe(0o600)
    expect((await stat(join(pendingSlot(), SOFTWARE_KEY_FILE))).mode & 0o777).toBe(0o600)
    expect(await readConfig(pendingSlot())).toBeNull()
  })

  test("mehen wait then finishes it from another process: polls signed by the attempt, the slot renamed into workspaces/, the record gone", async () => {
    const started = json(await runJv([...ENROL, "--json"], env))
    const id = started.enrolment as string
    const jwk = await softwareJwk()
    const before = vault.seen.length
    const waited = await runJv(["wait", id, "--json"], env)
    expect(waited.code).toBe(EXIT.ok)
    expect(json(waited)).toMatchObject({ id, kind: "enrol", status: "active", tenant: MOCK_TENANT, device: deviceFor(id), workspace: MOCK_WORKSPACE, owner: MOCK_OWNER })
    for (const poll of vault.seen.slice(before)) expect(poll).toMatchObject({ method: "GET", path: `/v1/enrol/${id}`, claims: { ten: "enrol", dev: id } })
    const fingerprint = await keyFingerprint(jwk)
    expect(await readConfig(activeSlot())).toEqual({ vault: vault.url, tenant: MOCK_TENANT, device: deviceFor(id), backend: "software", fingerprint, name: "test-mac", ...ENROLLED_DISPLAY })
    expect(await softwareJwk(activeSlot())).toEqual(jwk)
    expect(await readKeyScope(activeSlot(), "software")).toEqual({ vault: vault.url, tenant: MOCK_TENANT })
    expect(existsSync(pendingSlot())).toBe(false)
    expect(existsSync(join(activeSlot(), "enrolment.json"))).toBe(false)
    const status = await runJv(["status", "--json", "--workspace", MOCK_TENANT], env)
    expect(status.code).toBe(EXIT.ok)
    expect(json(status)).toMatchObject({ tenant: MOCK_TENANT, device: deviceFor(id), slot: activeSlot(), fingerprint })
  })

  test("--wait follows the attempt in the same process and prints the active shape with its slot", async () => {
    const result = await runJv([...ENROL, "--wait", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const [pending, active] = lines(result)
    expect(pending).toMatchObject({ status: "pending" })
    expect(active).toEqual({ status: "active", tenant: MOCK_TENANT, workspace: MOCK_WORKSPACE, owner: MOCK_OWNER, device: deviceFor(pending?.enrolment as string), backend: "software", scope: WORKSPACE_SCOPE, slot: activeSlot() })
  })

  test("prints the ask block for a human with mehen wait as the next step, the four words and the hidden group, and nothing else", async () => {
    const result = await runJv(ENROL, env)
    expect(result.code).toBe(EXIT.ok)
    const fingerprint = await keyFingerprint(await softwareJwk())
    const out = result.stdout.split("\n")
    expect(out[0]).toBe("Human needed: approve this machine")
    expect(out[1]).toBe(`  open:    ${vault.url}/w/mock-space/e/ABCD2345`)
    expect(out[2]).toBe("  what:    Approve test-mac (software key) and choose what it may use")
    expect(out[3]).toBe(`  check:   the page shows fingerprint  ${fingerprint}`)
    expect(out[4]).toMatch(/^ {2}expires: in (under a minute|1 min) \((tomorrow )?\d\d:\d\d\); mehen wait enr_mock\d+ keeps it alive$/)
    expect(out[5]).toMatch(/^ {2}then: {4}mehen wait enr_mock\d+$/)
    expect(out[6]).toMatch(/^ {2}words: {3}[a-z]+ \([a-z]+\) {2}[a-z]+ \([a-z]+\) {2}[a-z]+ \([a-z]+\) {2}[a-z]+ \([a-z]+\)$/)
    // ABCD2345 hides the third group (the protocol's known answer).
    expect(out[7]).toBe(`  hidden:  the page hides the third group, ${fingerprintGroups(fingerprint)[2]}: type it on the page`)
    expect(out.slice(8).join("")).toBe("")
    expect(result.stderr).toBe("")
  })

  test("--wait for a human says mehen keeps waiting, then the Enrolled sentence", async () => {
    const result = await runJv([...ENROL, "--wait"], env)
    expect(result.code).toBe(EXIT.ok)
    const out = result.stdout.split("\n")
    expect(out[4]).toContain("; mehen keeps it alive while it waits")
    expect(out[5]).toMatch(/^ {2}then: {4}mehen keeps waiting \(Ctrl-C is safe: mehen wait enr_mock\d+ resumes\)$/)
    expect(out[8]).toContain("Enrolled as dev_for")
    expect(out[8]).toContain(`in Mock Space (mock-space) at ${vault.url}, owned by Test Owner.`)
  })

  test("a link off the vault from the enrol start is never printed: the link is rebuilt from the code with a warning, in human and --json output", async () => {
    vault.linkOrigin = "https://evil.example"
    try {
      const human = await runJv(ENROL, env)
      expect(human.code).toBe(EXIT.ok)
      expect(human.stdout).not.toContain("evil.example")
      expect(human.stdout).toContain(`  open:    ${vault.url}/w/mock-space/e/ABCD2345`)
      expect(human.stderr).toContain(`mehen: warning: The vault returned a link that is not on ${vault.url}`)
      expect(human.stderr).not.toContain("evil.example")
      const dir2 = await tempDir()
      try {
        const asJson = await runJv([...ENROL, "--json"], { ...env, MEHEN_HOME: dir2.path })
        expect(asJson.code).toBe(EXIT.ok)
        expect(asJson.stdout).not.toContain("evil.example")
        const pending = json(asJson)
        expect(pending.url).toBe(`${vault.url}/w/mock-space/e/ABCD2345`)
        expect((pending.ask as { url: string }).url).toBe(`${vault.url}/w/mock-space/e/ABCD2345`)
        expect(String(pending.warning)).toContain("not on")
      } finally {
        await dir2.remove()
      }
    } finally {
      vault.linkOrigin = null
    }
  })

  test("a rejected enrolment (--wait) exits 5, writes no config and removes the record", async () => {
    vault.enrolOutcome = { pendingPolls: 1, result: "rejected" }
    const before = vault.seen.length
    const result = await runJv([...ENROL, "--wait", "--json"], env)
    expect(result.code).toBe(EXIT.refused)
    expect(lines(result).at(-1)).toMatchObject({ error: "rejected" })
    expect(await readConfig(pendingSlot())).toBeNull()
    expect(existsSync(activeSlot())).toBe(false)
    expect(await record()).toBeNull()
    expect(postedJwks(before)).toHaveLength(1)
  })

  test("--wait --timeout shorter than the enrolment's life exits 4 with the live ask and mehen wait as the next step, which then finishes it", async () => {
    vault.enrolOutcome = { pendingPolls: 1_000_000, result: "active" }
    const timed = await runJv([...ENROL, "--wait", "--timeout", "1", "--json"], { ...env, MEHEN_POLL_INTERVAL_MS: "50" })
    expect(timed.code).toBe(EXIT.human)
    const [pending, timeout] = lines(timed)
    const id = pending?.enrolment as string
    expect(timeout).toMatchObject({ error: "timeout", message: `Enrolment ${id} is still waiting for a human after 1 s.`, next: { command: `mehen wait ${id} --timeout 60 --json` }, ask: { kind: "enrol", id, url: pending?.url } })
    expect(await record()).toMatchObject({ state: "pending", id })
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    const waited = await runJv(["wait", id, "--timeout", "60", "--json"], env)
    expect(waited.code).toBe(EXIT.ok)
    expect(json(waited)).toMatchObject({ id, kind: "enrol", status: "active" })
  }, 20_000)

  test("--timeout takes what mehen wait --timeout takes, and only with --wait; both refusals come before any key or request", async () => {
    const before = vault.seen.length
    const alone = await runJv([...ENROL, "--timeout", "60", "--json"], env)
    expect(alone.code).toBe(EXIT.usage)
    expect(json(alone)).toMatchObject({ error: "usage", message: "--timeout goes with --wait: it is how long mehen enrol waits here for a human.", next: { command: "mehen enrol --help" } })
    const bad = await runJv([...ENROL, "--wait", "--timeout", "soon", "--json"], env)
    expect(bad.code).toBe(EXIT.usage)
    const waitBad = await runJv(["wait", "enr_x", "--timeout", "soon", "--json"], env)
    expect(json(bad).message).toBe(json(waitBad).message as string)
    expect(json(bad).message).toBe("--timeout takes a number of seconds, or a duration such as 30s, 10m or 2h, up to 24 h; 0 checks once.")
    expect(vault.seen.length).toBe(before)
    expect(existsSync(pendingSlot())).toBe(false)
  })

  test("enrolling an enrolled workspace again is idempotent success: alreadyEnrolled from the signed check, nothing written, nothing started", async () => {
    const device = await vault.enrolSoftware(dir.path)
    const configBefore = await readFile(join(activeSlot(), "config.json"), "utf8")
    const before = vault.seen.length
    const result = await runJv(["enrol", "--workspace", "mock-space", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toEqual({ status: "active", alreadyEnrolled: true, tenant: MOCK_TENANT, workspace: MOCK_WORKSPACE, owner: MOCK_OWNER, device, backend: "software", scope: WORKSPACE_SCOPE, slot: activeSlot() })
    expect(vault.seen.slice(before).map((c) => `${c.method} ${c.path}`)).toEqual(["GET /v1/me"])
    expect(vault.seen.at(-1)?.claims).toMatchObject({ ten: MOCK_TENANT, dev: device })
    expect(await readFile(join(activeSlot(), "config.json"), "utf8")).toBe(configBefore)
    expect(existsSync(pendingSlot())).toBe(false)
    const human = await runJv(["enrol", "--workspace", "mock-space"], env)
    expect(human.stdout).toBe(`This machine is already enrolled as ${device} in Mock Space (mock-space) at ${vault.url}; nothing to do. Try \`mehen status\`.\n`)
    // By workspace id too, for an active slot.
    expect(json(await runJv(["enrol", "--workspace", MOCK_TENANT, "--json"], env))).toMatchObject({ alreadyEnrolled: true, device })
  })

  // A 0.3.18 machine may be given fill (ladder F1): the signed check reads a
  // scope holding it as complete, never as one to repair.
  test("enrolling again on a machine given fill is alreadyEnrolled with fill among its modes, nothing revoked", async () => {
    const device = await vault.enrolSoftware(dir.path)
    const modes = ["relay", "sign", "mint", "placeholder", "fill", "lease"]
    vault.overrides.set("GET /v1/me", (_request, seen) => Response.json({ tenant: MOCK_TENANT, device: seen.claims.dev, name: "test-machine", scope: { ...WORKSPACE_SCOPE, modes }, frozen: false, workspace: MOCK_WORKSPACE, owner: MOCK_OWNER }))
    const result = await runJv(["enrol", "--workspace", "mock-space", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toMatchObject({ status: "active", alreadyEnrolled: true, device, scope: { modes } })
    expect(vault.seen.filter((c) => c.path === "/v1/devices/self/revoke")).toEqual([])
  })

  test("a tn_ id names only an active slot: with none it is a usage error and nothing is sent or made", async () => {
    const before = vault.seen.length
    const result = await runJv(["enrol", "--workspace", MOCK_TENANT, "--json"], env)
    expect(result.code).toBe(EXIT.usage)
    expect(json(result).message).toContain("a tn_ id names only a workspace this machine is already in")
    expect(vault.seen.length).toBe(before)
    expect(existsSync(join(dir.path, "pending"))).toBe(false)
  })

  test("an unknown backend is a usage error", async () => {
    const result = await runJv(["enrol", "--workspace", "mock-space", "--backend", "tpm"], env)
    expect(result.code).toBe(EXIT.usage)
  })

  test("a workspace outside MEHEN_WORKSPACES refuses workspace_not_allowed before any key or request", async () => {
    const before = vault.seen.length
    const result = await runJv([...ENROL, "--json"], { ...env, MEHEN_WORKSPACES: "other-space" })
    expect(result.code).toBe(EXIT.usage)
    expect(json(result)).toMatchObject({ error: "workspace_not_allowed" })
    expect(vault.seen.length).toBe(before)
    expect(existsSync(pendingSlot())).toBe(false)
  })

  test("an origin-qualified ceiling admits the slug only at its own vault: elsewhere it refuses before any key or request", async () => {
    const before = vault.seen.length
    const result = await runJv([...ENROL, "--json"], { ...env, MEHEN_WORKSPACES: "vault.example/mock-space" })
    expect(result.code).toBe(EXIT.usage)
    expect(json(result)).toMatchObject({ error: "workspace_not_allowed" })
    expect(vault.seen.length).toBe(before)
    expect(existsSync(join(dir.path, "pending"))).toBe(false)
  })

  test("a failed record write after the start prints no ask and exits 1 with the explanation", async () => {
    vault.overrides.set("POST /v1/enrol", async (_request, seen) => {
      const start = WorkspaceEnrolStartSchema.parse(JSON.parse(seen.body))
      vault.enrolments.set("enr_unrecorded", { id: "enr_unrecorded", jwk: start.jwk, name: start.name, backend: start.backend, polls: 0, workspace: start.workspace, owner: start.owner })
      await chmod(pendingSlot(), 0o500)
      return Response.json({ enrolment: "enr_unrecorded", code: "ABCD2345", url: `${vault.url}/w/mock-space/e/ABCD2345`, fingerprint: "x", expiresAt: new Date(Date.now() + 60_000).toISOString(), hardExpiresAt: new Date(Date.now() + 3_600_000).toISOString() })
    })
    try {
      const result = await runJv([...ENROL, "--json"], env)
      expect(result.code).toBe(EXIT.error)
      const failure = json(result)
      expect(failure).toMatchObject({ error: "failed", next: { command: "mehen enrol --workspace mock-space" } })
      expect(String(failure.message)).toContain("no ask is printed")
      expect(String((failure.next as { say: string }).say)).toContain("issues a new link and expires the old one at the vault")
      expect(result.stdout).not.toContain('"status":"pending"')
      expect(result.stdout).not.toContain("/e/ABCD2345")
    } finally {
      await chmod(pendingSlot(), 0o700)
    }
    // The record says issuing; the next run removes it and issues anew.
    expect(await record()).toMatchObject({ state: "issuing" })
    vault.overrides.clear()
    const again = await runJv([...ENROL, "--json"], env)
    expect(again.code).toBe(EXIT.ok)
    expect(json(again)).toMatchObject({ status: "pending" })
  })
})

describe("mehen enrol repairs or replaces an active slot only on a definitive answer", () => {
  test("a definitive device_revoked from the signed check repairs: the slot is cleared and a new attempt starts; --wait reports repaired", async () => {
    const device = await vault.enrolSoftware(dir.path)
    const revoked = vault.devices.get(device)
    if (revoked) revoked.revoked = true
    const oldJwk = await softwareJwk(activeSlot())
    const result = await runJv([...ENROL, "--wait", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(result.stderr).toContain(`device ${device} was revoked in the vault; its slot was cleared`)
    const [pending, active] = lines(result)
    expect(pending).toMatchObject({ status: "pending" })
    expect(active).toMatchObject({ status: "active", repaired: { device, reason: "device_revoked" }, device: deviceFor(pending?.enrolment as string), slot: activeSlot() })
    expect(await softwareJwk(activeSlot())).not.toEqual(oldJwk)
  })

  // Every other answer is the error itself: one test per refusal, each
  // leaving this slot and the other workspace's slot byte for byte.
  const refusals: [string, () => void | Promise<void>, number, string][] = [
    ["unauthenticated", () => {
      vault.overrides.set("GET /v1/me", () => vaultError("unauthenticated", "Unknown device."))
    }, EXIT.identity, "unauthenticated"],
    ["proof_invalid", () => {
      vault.overrides.set("GET /v1/me", () => vaultError("proof_invalid", "Bad proof."))
    }, EXIT.identity, "proof_invalid"],
    ["a 5xx", () => {
      vault.overrides.set("GET /v1/me", () => Response.json({ error: "internal", message: "down" }, { status: 500, headers: { "Mehen-Error": "1" } }))
    }, EXIT.error, "internal"],
    ["a missing key file", () => rm(join(activeSlot(), SOFTWARE_KEY_FILE)), EXIT.identity, "unauthenticated"],
    ["an insecure key file", () => chmod(join(activeSlot(), SOFTWARE_KEY_FILE), 0o644), EXIT.identity, "key_insecure"],
  ]
  for (const [name, arrange, exit, code] of refusals) {
    test(`${name} from the signed check leaves the slot and every other slot untouched, and names forget --slot`, async () => {
      await vault.enrolSoftware(dir.path)
      await vault.enrolSoftware(dir.path, { config: { tenant: "tn_second00000001", workspaceSlug: "second-space", workspaceName: "Second" } })
      const snapshot = async () => Promise.all([activeSlot(), activeSlot(vault.url, "tn_second00000001")].map(async (slot) => (await Bun.$`find ${slot} -type f -exec shasum {} +`.text()).trim()))
      await arrange()
      const before = await snapshot()
      const posts = postedJwks().length
      const result = await runJv([...ENROL, "--json"], env)
      expect(result.code).toBe(exit)
      expect(json(result)).toMatchObject({ error: code })
      expect(String((json(result).next as { say: string }).say)).toContain(`mehen workspace forget --slot ${activeSlot()}`)
      expect(await snapshot()).toEqual(before)
      expect(postedJwks().length).toBe(posts)
      expect(existsSync(pendingSlot())).toBe(false)
    })
  }

  test("a device the vault does not know: the next step is forget --slot, never the enrol that refused, and following it reaches a new attempt (G1 N-1)", async () => {
    await vault.enrolSoftware(dir.path)
    vault.overrides.set("GET /v1/me", () =>
      vaultError("unauthenticated", "This machine is not enrolled in this vault.", {
        next: { command: "mehen enrol --workspace mock-space", say: "This machine is not enrolled with the vault; run `mehen enrol --workspace mock-space` and approve it in the browser." },
      }),
    )
    const refused = await runJv([...ENROL, "--json"], env)
    expect(refused.code).toBe(EXIT.identity)
    const next = json(refused).next as { command: string; say: string }
    expect(json(refused)).toMatchObject({ error: "unauthenticated", message: "This machine is not enrolled in this vault." })
    expect(next.command).toBe(`mehen workspace forget --slot ${activeSlot()}`)
    expect(next.say).toContain("then run `mehen enrol --workspace mock-space`")
    expect(existsSync(activeSlot())).toBe(true)
    // Following next.command, then the enrol it names, makes progress.
    const forgot = await runJv([...next.command.split(" ").slice(1), "--json"], env)
    expect(forgot.code).toBe(EXIT.ok)
    expect(existsSync(activeSlot())).toBe(false)
    const again = await runJv([...ENROL, "--json"], env)
    expect(again.code).toBe(EXIT.ok)
    expect(json(again)).toMatchObject({ status: "pending" })
  })

  test("a network failure from the signed check leaves the slot (exit 7)", async () => {
    await vault.enrolSoftware(dir.path)
    const config = await readFile(join(activeSlot(), "config.json"), "utf8")
    const unreachable = "http://127.0.0.1:1"
    // The slot is enrolled at an origin nothing listens on.
    const other = activeSlotPath(dir.path, unreachable, MOCK_TENANT)
    await ensureConfigDir(other)
    await Bun.$`cp ${join(activeSlot(), SOFTWARE_KEY_FILE)} ${other}/`
    await writeFile(join(other, "config.json"), config.replace(vault.url, unreachable), { mode: 0o600 })
    await writeFile(join(other, SOFTWARE_KEY_SCOPE_FILE), JSON.stringify({ vault: unreachable, tenant: MOCK_TENANT }), { mode: 0o600 })
    const result = await runJv([...ENROL, "--json"], { ...env, MEHEN_VAULT_URL: unreachable })
    expect(result.code).toBe(EXIT.transient)
    expect(String((json(result).next as { say: string }).say)).toContain(`mehen workspace forget --slot ${other}`)
    expect(await readConfig(other)).toMatchObject({ vault: unreachable })
    expect(existsSync(pendingSlotPath(dir.path, unreachable, "mock-space"))).toBe(false)
  })

  test("--fresh-key on an active slot replaces it (not idempotent success): revoked with its own key, the slot cleared, a new key; --wait reports replaced", async () => {
    const device = await vault.enrolSoftware(dir.path)
    const oldJwk = await softwareJwk(activeSlot())
    const before = vault.seen.length
    const result = await runJv([...ENROL, "--fresh-key", "--wait", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const calls = vault.seen.slice(before)
    expect(calls[0]).toMatchObject({ path: "/v1/devices/self/revoke", claims: { ten: MOCK_TENANT, dev: device } })
    expect(vault.revoked).toContain(device)
    const [pending, active] = lines(result)
    expect(pending?.alreadyEnrolled).toBeUndefined()
    expect(active).toMatchObject({ status: "active", replaced: { device }, slot: activeSlot() })
    const newJwk = await softwareJwk(activeSlot())
    expect(newJwk).not.toEqual(oldJwk)
    expect(postedJwks(before)).toEqual([newJwk])
  })

  test("--fresh-key whose revocation the vault refuses leaves the slot and starts nothing", async () => {
    await vault.enrolSoftware(dir.path)
    vault.overrides.set("POST /v1/devices/self/revoke", () => Response.json({ error: "internal", message: "down" }, { status: 500, headers: { "Mehen-Error": "1" } }))
    const config = await readFile(join(activeSlot(), "config.json"), "utf8")
    const posts = postedJwks().length
    const result = await runJv([...ENROL, "--fresh-key", "--json"], env)
    expect(result.code).toBe(EXIT.error)
    expect(await readFile(join(activeSlot(), "config.json"), "utf8")).toBe(config)
    expect(postedJwks().length).toBe(posts)
  })
})

// On a managed host enrol only confirms the pinned slot (rule 0 selects it
// and refuses every other workspace, unchanged): it never replaces the pin
// or repairs it. A CLI-level managed fixture needs an https pin origin, so
// step 2 is driven directly with the managed flag the command passes.
describe("mehen enrol on a managed host (step 2)", () => {
  test("--fresh-key and a revoked pin are refused before anything is sent or removed; the pin itself is confirmed", async () => {
    const { activeStep } = await import("./enrol.ts")
    const device = await vault.enrolSoftware(dir.path)
    const config = await readConfig(activeSlot())
    if (!config) throw new Error("no config")
    const found = { state: "active" as const, dir: activeSlot(), config }
    const snapshot = async () => (await Bun.$`find ${activeSlot()} -type f -exec shasum {} +`.text()).trim()
    const before = await snapshot()
    const seen = vault.seen.length
    expect(await activeStep(env, found, false, "mock-space", true)).toMatchObject({ done: { alreadyEnrolled: true, device } })
    await expect(activeStep(env, found, true, "mock-space", true)).rejects.toMatchObject({ code: "workspace_mismatch", message: expect.stringContaining("--fresh-key would replace the owner's pinned enrolment") })
    const revoked = vault.devices.get(device)
    if (revoked) revoked.revoked = true
    await expect(activeStep(env, found, false, "mock-space", true)).rejects.toMatchObject({ code: "workspace_mismatch", message: expect.stringContaining(`the pinned device ${device} was revoked`) })
    expect(await snapshot()).toBe(before)
    expect(vault.seen.slice(seen).filter((c) => c.path !== "/v1/me")).toEqual([])
  })
})

describe("mehen enrol keeps its key and its attempt", () => {
  test("a second mehen enrol resumes the same attempt: same id, code and link, no new start", async () => {
    const before = vault.seen.length
    const first = json(await runJv([...ENROL, "--json"], env))
    const jwk = await softwareJwk()
    const resumed = await runJv([...ENROL, "--json"], env)
    expect(resumed.code).toBe(EXIT.ok)
    expect(json(resumed)).toMatchObject({ status: "pending", enrolment: first.enrolment, code: first.code, url: first.url, fingerprint: first.fingerprint, renewals: 0 })
    expect(postedJwks(before)).toEqual([jwk])
    expect(await softwareJwk()).toEqual(jwk)
    const human = await runJv(ENROL, env)
    const out = human.stdout.split("\n")
    expect(out[0]).toBe("Resuming the enrolment this machine started a moment ago: same key, same link.")
    expect(out[2]).toBe(`  open:    ${first.url}`)
    expect(out[4]).toBe(`  check:   the page shows fingerprint  ${first.fingerprint}`)
  })

  test("a resumed attempt the vault already approved is finished at once (one active line)", async () => {
    const first = json(await runJv([...ENROL, "--json"], env))
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    const resumed = await runJv([...ENROL, "--json"], env)
    expect(resumed.code).toBe(EXIT.ok)
    expect(lines(resumed)).toEqual([expect.objectContaining({ status: "active", device: deviceFor(first.enrolment as string), slot: activeSlot() })])
  })

  test("a resumed attempt whose lease lapsed locally is polled first: approved after its expiry, it is finished", async () => {
    const first = json(await runJv([...ENROL, "--json"], env))
    await editRecord((r) => ({ ...r, expiresAt: past(60_000) }))
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    const before = vault.seen.length
    const resumed = await runJv([...ENROL, "--json"], env)
    expect(resumed.code).toBe(EXIT.ok)
    expect(json(resumed)).toMatchObject({ status: "active", device: deviceFor(first.enrolment as string) })
    expect(renewals(before)).toEqual([])
  })

  test("a lapsed renewable attempt is renewed in place: the same id, code and URL with a later expiry", async () => {
    const first = json(await runJv([...ENROL, "--json"], env))
    const id = first.enrolment as string
    const enrolment = vault.enrolments.get(id)
    if (enrolment) enrolment.expiresAt = Date.now() - 1_000
    await editRecord((r) => ({ ...r, expiresAt: past() }))
    vault.enrolOutcome = { pendingPolls: 1_000, result: "active" }
    const before = vault.seen.length
    const resumed = json(await runJv([...ENROL, "--json"], env))
    expect(renewals(before)).toEqual([`/v1/enrol/${id}/renew`])
    expect(vault.seen.slice(before).find((c) => c.path.endsWith("/renew"))?.claims).toMatchObject({ ten: "enrol", dev: id })
    expect(resumed).toMatchObject({ status: "pending", enrolment: id, code: first.code, url: first.url, renewals: 1 })
    expect(Date.parse(resumed.expiresAt as string)).toBeGreaterThan(Date.now())
    expect(await record()).toMatchObject({ id, code: first.code, url: first.url, renewals: 1, expiresAt: resumed.expiresAt })
    expect(postedJwks(before)).toEqual([])
  })

  test("a terminal renew refusal drops the record and issues a new attempt with the same key", async () => {
    const first = json(await runJv([...ENROL, "--json"], env))
    const jwk = await softwareJwk()
    await lapse()
    // The vault still says pending (lapsed) to the poll; the renewal finds it settled.
    vault.enrolOutcome = { pendingPolls: 1_000, result: "active" }
    vault.overrides.set(`POST /v1/enrol/${first.enrolment}/renew`, () => Response.json({ error: "conflict", message: "This enrolment can no longer be renewed.", enrolment: { status: "expired", reason: "hard_cap" } }, { status: 409, headers: { "Mehen-Error": "1" } }))
    const before = vault.seen.length
    const again = json(await runJv([...ENROL, "--json"], env))
    expect(renewals(before)).toEqual([`/v1/enrol/${first.enrolment}/renew`])
    expect(again).toMatchObject({ status: "pending", fingerprint: first.fingerprint })
    expect(again.enrolment).not.toBe(first.enrolment)
    expect(postedJwks(before)).toEqual([jwk])
  })

  test("a resumed attempt the vault no longer knows (its poll answers 404) gives way to a new attempt with the same key", async () => {
    const first = json(await runJv([...ENROL, "--json"], env))
    const jwk = await softwareJwk()
    vault.overrides.set(`GET /v1/enrol/${first.enrolment}`, () => Response.json({ error: "not_found", message: "No such enrolment." }, { status: 404, headers: { "Mehen-Error": "1" } }))
    const before = vault.seen.length
    const again = await runJv([...ENROL, "--json"], env)
    expect(again.code).toBe(EXIT.ok)
    expect(json(again)).toMatchObject({ status: "pending", fingerprint: first.fingerprint })
    expect(json(again).enrolment).not.toBe(first.enrolment)
    expect(renewals(before)).toEqual([])
    expect(postedJwks(before)).toEqual([jwk])
    expect(await record()).toMatchObject({ id: json(again).enrolment })
  })

  test("a legacy record is never renewed: a live one is printed as it is, a lapsed one gives way to a new attempt with the same key", async () => {
    const first = json(await runJv([...ENROL, "--json"], env))
    await editRecord((r) => ({ ...r, legacy: true, hardExpiresAt: null }))
    const before = vault.seen.length
    const live = json(await runJv([...ENROL, "--json"], env))
    expect(live).toMatchObject({ enrolment: first.enrolment, hardExpiresAt: null })
    await lapse()
    const lapsed = json(await runJv([...ENROL, "--json"], env))
    expect(lapsed.enrolment).not.toBe(first.enrolment)
    expect(lapsed.fingerprint).toBe(first.fingerprint)
    expect(renewals(before)).toEqual([])
  })

  test("--wait keeps a short lease alive by renewing it in place; --no-renew lets it lapse and exits 1 with mehen enrol as the next step", async () => {
    vault.enrolLeaseMs = 600
    vault.renewIntervalMs = 0
    vault.enrolOutcome = { pendingPolls: 40, result: "active" }
    const kept = await runJv([...ENROL, "--wait", "--json"], { ...env, MEHEN_POLL_INTERVAL_MS: "50" })
    expect(kept.code).toBe(EXIT.ok)
    const [pending, active] = lines(kept)
    expect(active).toMatchObject({ status: "active", device: deviceFor(pending?.enrolment as string) })
    expect(vault.renewed.filter((id) => id === pending?.enrolment).length).toBeGreaterThan(0)
    const fresh = await tempDir()
    try {
      vault.enrolOutcome = { pendingPolls: 1_000_000, result: "active" }
      const before = vault.seen.length
      const lapsed = await runJv([...ENROL, "--wait", "--no-renew", "--json"], { ...env, MEHEN_HOME: fresh.path, MEHEN_POLL_INTERVAL_MS: "50" })
      expect(lapsed.code).toBe(EXIT.error)
      expect(lines(lapsed).at(-1)).toMatchObject({ error: "expired", next: { command: "mehen enrol --workspace mock-space" } })
      expect(renewals(before)).toEqual([])
      expect(await record(pendingSlotPath(fresh.path, vault.url, "mock-space"))).toBeNull()
      // The key stays for the next attempt.
      expect(existsSync(join(pendingSlotPath(fresh.path, vault.url, "mock-space"), SOFTWARE_KEY_FILE))).toBe(true)
    } finally {
      await fresh.remove()
    }
  }, 20_000)

  test("a pending attempt under another name is not resumed: a new attempt for the same key", async () => {
    const before = vault.seen.length
    const first = json(await runJv([...ENROL, "--json"], env))
    const other = json(await runJv(["enrol", "--workspace", "mock-space", "--name", "other-name", "--backend", "software", "--json"], env))
    expect(other.enrolment).not.toBe(first.enrolment)
    expect(other.fingerprint).toBe(first.fingerprint)
    const posted = postedJwks(before)
    expect(posted).toHaveLength(2)
    expect(posted[1]).toEqual(posted[0] as DeviceJwk)
    expect(await record()).toMatchObject({ id: other.enrolment, name: "other-name" })
  })

  test("--fresh-key on a pending attempt makes a new key and a new attempt, and the old record goes", async () => {
    const before = vault.seen.length
    const first = json(await runJv([...ENROL, "--json"], env))
    const oldJwk = await softwareJwk()
    const fresh = json(await runJv([...ENROL, "--fresh-key", "--json"], env))
    expect(fresh.enrolment).not.toBe(first.enrolment)
    expect(fresh.fingerprint).not.toBe(first.fingerprint)
    const newJwk = await softwareJwk()
    expect(newJwk).not.toEqual(oldJwk)
    expect(postedJwks(before)).toEqual([oldJwk, newJwk])
    expect(await record()).toMatchObject({ id: fresh.enrolment, jwk: newJwk })
  })

  test("two enrols for the same slug at once serialise on the pending lock: one start, the second resumes it", async () => {
    const before = vault.seen.length
    const [a, b] = await Promise.all([runJv([...ENROL, "--json"], env), runJv([...ENROL, "--json"], env)])
    expect(a.code).toBe(EXIT.ok)
    expect(b.code).toBe(EXIT.ok)
    expect(json(a).enrolment).toBe(json(b).enrolment)
    expect(postedJwks(before)).toHaveLength(1)
  })

  test("the record holds the public JWK only: no private scalar anywhere in it", async () => {
    await runJv([...ENROL, "--json"], env)
    const key = JSON.parse(await readFile(join(pendingSlot(), SOFTWARE_KEY_FILE), "utf8")) as { x: string; y: string; d: string }
    const text = await readFile(join(pendingSlot(), "enrolment.json"), "utf8")
    expect(text).toContain(key.x)
    expect(text).toContain(key.y)
    expect(text).not.toContain(key.d)
    expect(Object.keys((JSON.parse(text) as { jwk: object }).jwk).sort()).toEqual(["crv", "kty", "x", "y"])
  })

  test("after mehen revoke the key file is gone, so the next mehen enrol makes a new key with a new fingerprint", async () => {
    const first = lines(await runJv([...ENROL, "--wait", "--json"], env))
    const oldJwk = await softwareJwk(activeSlot())
    expect((await runJv(["revoke", "--json"], env)).code).toBe(EXIT.ok)
    await expect(stat(join(activeSlot(), SOFTWARE_KEY_FILE))).rejects.toMatchObject({ code: "ENOENT" })
    expect(await readConfig(activeSlot())).toBeNull()
    const second = lines(await runJv([...ENROL, "--wait", "--json"], env))
    expect(await softwareJwk(activeSlot())).not.toEqual(oldJwk)
    expect(second[0]?.fingerprint).not.toBe(first[0]?.fingerprint)
  })

  test("a resumed attempt's ask is rebuilt from the key and the record's checked fields: anything else planted in the record is never printed", async () => {
    const first = json(await runJv([...ENROL, "--json"], env))
    const forged = "ZZZZ ZZZZ ZZZZ ZZZZ"
    const text = JSON.parse(await readFile(join(pendingSlot(), "enrolment.json"), "utf8")) as Record<string, unknown>
    await writeFile(join(pendingSlot(), "enrolment.json"), JSON.stringify({ ...text, check: { label: "fingerprint", value: forged }, what: "Approve evil-mac" }), { mode: 0o600 })
    const asJson = await runJv([...ENROL, "--json"], env)
    expect(json(asJson)).toMatchObject({ enrolment: first.enrolment, fingerprint: first.fingerprint, ask: { check: { value: first.fingerprint }, what: "Approve test-mac (software key) and choose what it may use" } })
    expect(asJson.stdout).not.toContain(forged)
    expect(asJson.stdout).not.toContain("evil-mac")
    const human = await runJv(ENROL, env)
    expect(human.stdout).toContain(`  check:   the page shows fingerprint  ${first.fingerprint}`)
    expect(human.stdout).not.toContain(forged)
  })

  test("a symbolic link planted as the key file is not followed: a fresh key, and the link's target is untouched", async () => {
    const elsewhere = await tempDir()
    try {
      const planted = await createDeviceKey(elsewhere.path, "software", {})
      const target = join(elsewhere.path, SOFTWARE_KEY_FILE)
      const before = await readFile(target, "utf8")
      await ensureConfigDir(pendingSlot())
      await symlink(target, join(pendingSlot(), SOFTWARE_KEY_FILE))
      const result = await runJv([...ENROL, "--json"], env)
      expect(result.code).toBe(EXIT.ok)
      expect(json(result).fingerprint).not.toBe(await keyFingerprint(planted.jwk))
      expect(await softwareJwk()).not.toEqual(planted.jwk)
      expect(await readFile(target, "utf8")).toBe(before)
    } finally {
      await elsewhere.remove()
    }
  })

  test("two workspaces never share a slot: each its own pending slot and then its own active slot", async () => {
    const first = lines(await runJv([...ENROL, "--wait", "--json"], env))
    expect(first.at(-1)).toMatchObject({ slot: activeSlot() })
    vault.workspace = { id: "tn_second00000001", slug: "second-space", name: "Second" }
    const second = lines(await runJv(["enrol", "--workspace", "second-space", "--name", "test-mac", "--backend", "software", "--wait", "--json"], env))
    expect(second[0]).toMatchObject({ slot: pendingSlotPath(dir.path, vault.url, "second-space") })
    expect(second.at(-1)).toMatchObject({ slot: activeSlot(vault.url, "tn_second00000001"), tenant: "tn_second00000001" })
    expect(await readConfig(activeSlot())).toMatchObject({ workspaceSlug: "mock-space", tenant: MOCK_TENANT })
    expect(await softwareJwk(activeSlot())).not.toEqual(await softwareJwk(activeSlot(vault.url, "tn_second00000001")))
  })
})

// G0 F-2: after an attempt ends for good, `mehen wait` removes the record
// and keeps the key. The directory is an ended attempt, never corrupt, and
// its next step is enrolling the slug again, never `workspace forget`.
describe("an attempt that ended for good keeps its key (G0 F-2)", () => {
  test("status, workspace list and doctor report it ended with the key kept and mehen enrol --workspace as the next step; that enrol reuses the key", async () => {
    const first = json(await runJv([...ENROL, "--json"], env))
    vault.enrolOutcome = { pendingPolls: 0, result: "expired" }
    const waited = await runJv(["wait", first.enrolment as string, "--json"], env)
    expect(waited.code).toBe(EXIT.error)
    expect(await record()).toBeNull()
    expect(existsSync(join(pendingSlot(), SOFTWARE_KEY_FILE))).toBe(true)
    const next = { command: "mehen enrol --workspace mock-space", say: expect.stringContaining("the key is kept") }

    const status = await runJv(["status", "--json"], env)
    expect(status.code).toBe(EXIT.ok)
    const body = json(status) as { workspaces: Record<string, unknown>[]; next: unknown }
    expect(body.workspaces).toEqual([{ state: "ended", slot: pendingSlot(), slug: "mock-space", detail: expect.stringContaining("ended without being accepted"), next }])
    expect(body.next).toEqual(next)
    expect(status.stdout).not.toContain("corrupt")
    expect(status.stdout).not.toContain("workspace forget")
    const human = await runJv(["status"], env)
    expect(plainText(human.stdout)).toContain("mock-space: the enrolment attempt ended; the key is kept")
    expect(human.stdout).not.toContain("workspace forget")

    const list = await runJv(["workspace", "list", "--json"], env)
    expect((json(list) as { workspaces: unknown[] }).workspaces).toEqual([expect.objectContaining({ state: "ended", slug: "mock-space", next })])
    expect(list.stdout).not.toContain("workspace forget")

    const doctor = await runJv(["doctor", "--json"], env)
    const report = json(doctor) as { workspaces: { state: string; checks: { check: string; status: string; next?: unknown }[] }[]; next: unknown }
    expect(report.workspaces).toEqual([expect.objectContaining({ state: "ended", checks: [expect.objectContaining({ check: "enrolled", status: "warn", next })] })])
    expect(report.next).toEqual(next)
    expect(doctor.stdout).not.toContain("workspace forget")

    vault.enrolOutcome = { pendingPolls: 2, result: "active" }
    const again = json(await runJv([...ENROL, "--json"], env))
    expect(again).toMatchObject({ status: "pending", fingerprint: first.fingerprint, slot: pendingSlot() })
    expect(again.enrolment).not.toBe(first.enrolment)
  })

  test("a pending directory with neither a record nor a key is still not a slot, with workspace forget as its next step", async () => {
    await mkdir(pendingSlot(), { recursive: true, mode: 0o700 })
    await chmod(join(dir.path, "pending"), 0o700)
    const status = json(await runJv(["status", "--json"], env)) as { workspaces: Record<string, unknown>[] }
    expect(status.workspaces).toEqual([expect.objectContaining({ state: "corrupt", reason: "not_a_slot", next: expect.objectContaining({ command: `mehen workspace forget --slot ${pendingSlot()}` }) })])
  })
})

// G0 F-1: a new colleague's machine. No MEHEN_HOME, so the root is the
// default ~/.config/mehen, which does not exist yet.
describe("mehen enrol on a fresh HOME (G0 F-1)", () => {
  async function freshHome(config: "none" | "empty"): Promise<string> {
    const user = await realpath(dir.path)
    if (config === "empty") await mkdir(join(user, ".config"), { mode: 0o755 })
    return user
  }

  for (const config of ["none", "empty"] as const) {
    test(`a HOME with ${config === "none" ? "nothing" : "an empty .config"}: status, workspace list and doctor create nothing and say no workspace yet; enrol creates the root 0700 and leaves a pending slot`, async () => {
      const user = await freshHome(config)
      const root = join(user, ".config", "mehen")
      const fresh = { HOME: user, MEHEN_VAULT_URL: vault.url }
      const status = await runJv(["status", "--json"], fresh)
      expect(status.code).toBe(EXIT.ok)
      expect(json(status)).toMatchObject({ home: root, workspaces: [], selected: null, next: { command: "mehen enrol --workspace <slug> --json" } })
      const list = await runJv(["workspace", "list", "--json"], fresh)
      expect(list.code).toBe(EXIT.ok)
      expect(json(list)).toMatchObject({ home: root, workspaces: [] })
      const doctor = await runJv(["doctor", "--json"], fresh)
      const report = json(doctor) as { machine: { check: string; status: string; detail: string }[]; next: { command?: string } }
      expect(report.machine.find((c) => c.check === "migration")).toMatchObject({ status: "ok", detail: `${root} does not exist yet; the first \`mehen enrol\` creates it.` })
      expect(report.machine.find((c) => c.check === "enrolled")?.detail).toContain("not enrolled")
      expect(report.next.command).toBe("mehen enrol --workspace <slug> --json")
      // Bun keeps its own cache under ~/Library; nothing of mehen's is made.
      if (config === "none") expect(existsSync(join(user, ".config"))).toBe(false)
      else expect(await readdir(join(user, ".config"))).toEqual([])

      const enrolled = await runJv([...ENROL, "--json"], fresh)
      expect(enrolled.code).toBe(EXIT.ok)
      const slot = pendingSlotPath(root, vault.url, "mock-space")
      expect(json(enrolled)).toMatchObject({ status: "pending", slot })
      for (const path of [...(config === "none" ? [join(user, ".config")] : []), root, join(root, "locks"), join(root, "pending"), slot]) {
        const info = await lstat(path)
        expect(info.isDirectory()).toBe(true)
        expect(info.mode & 0o777).toBe(0o700)
      }
      if (config === "empty") expect((await lstat(join(user, ".config"))).mode & 0o777).toBe(0o755)
      expect(await record(slot)).toMatchObject({ state: "pending", intent: { workspace: "mock-space" } })
      const after = await runJv(["status", "--json"], fresh)
      expect(after.code).toBe(EXIT.ok)
      expect(json(after)).toMatchObject({ home: root, workspaces: [{ state: "pending", slot }] })
    })
  }

  test("an unsafe ~/.config (group-writable, or a symbolic link) is refused key_insecure naming it: nothing is created and nothing is sent", async () => {
    const user = await realpath(dir.path)
    const config = join(user, ".config")
    const fresh = { HOME: user, MEHEN_VAULT_URL: vault.url }
    await mkdir(config, { mode: 0o700 })
    await chmod(config, 0o775)
    const before = vault.seen.length
    try {
      const refused = await runJv([...ENROL, "--json"], fresh)
      expect(refused.code).toBe(EXIT.identity)
      expect(json(refused)).toMatchObject({ error: "key_insecure" })
      expect(String(json(refused).message)).toContain(config)
      expect(await readdir(config)).toEqual([])
    } finally {
      await chmod(config, 0o700)
    }
    await rm(config, { recursive: true })
    await mkdir(join(user, "dotfiles"), { mode: 0o700 })
    await symlink(join(user, "dotfiles"), config)
    const linked = await runJv([...ENROL, "--json"], fresh)
    expect(linked.code).toBe(EXIT.identity)
    expect(json(linked)).toMatchObject({ error: "key_insecure" })
    expect(String(json(linked).message)).toContain(config)
    expect(await readdir(join(user, "dotfiles"))).toEqual([])
    expect(vault.seen.length).toBe(before)
  })
})

describe("mehen enrol against a vault from before 0008", () => {
  test("no hardExpiresAt is null and never renewed; expired without a reason ends the attempt", async () => {
    vault.enrolMode = "pre0008"
    const first = json(await runJv([...ENROL, "--json"], env))
    expect(first).toMatchObject({ status: "pending", hardExpiresAt: null })
    expect(await record()).toMatchObject({ hardExpiresAt: null, legacy: false })
    // A lapsed attempt is never renewed: the next enrol starts anew with the same key.
    await lapse()
    const before = vault.seen.length
    const again = json(await runJv([...ENROL, "--json"], env))
    expect(renewals(before)).toEqual([])
    expect(again.enrolment).not.toBe(first.enrolment)
    // expired without a reason (an old vault) from mehen wait is terminal.
    vault.enrolOutcome = { pendingPolls: 0, result: "expired" }
    const waited = await runJv(["wait", again.enrolment as string, "--json"], env)
    expect(waited.code).toBe(EXIT.error)
    expect(json(waited)).toMatchObject({ error: "expired", next: { command: "mehen enrol --workspace mock-space" } })
    expect(await record()).toBeNull()
  })

  test("a renewable record against an old vault: a renew 404 is terminal, and a 409 with neither retryAfter nor the enrolment is polled once and settled", async () => {
    for (const renew409 of [false, true]) {
      const home = await tempDir()
      try {
        const here = { ...env, MEHEN_HOME: home.path }
        const slot = pendingSlotPath(home.path, vault.url, "mock-space")
        vault.enrolMode = "current"
        const first = json(await runJv([...ENROL, "--json"], here))
        vault.enrolMode = "pre0008"
        vault.renew409 = renew409
        await lapse(slot)
        vault.enrolOutcome = { pendingPolls: 1_000, result: "active" }
        const before = vault.seen.length
        const again = json(await runJv([...ENROL, "--json"], here))
        expect(renewals(before)).toEqual([`/v1/enrol/${first.enrolment}/renew`])
        expect(again.enrolment).not.toBe(first.enrolment)
      } finally {
        await home.remove()
      }
    }
  })
})

describe("mehen enrol --connect (the immutable claim)", () => {
  test("the code goes in the start body only; a resumed unclaimed attempt with --connect starts a new one with the same key and says which it superseded; a claimed one is resumed without sending it", async () => {
    const before = vault.seen.length
    const unclaimed = json(await runJv([...ENROL, "--json"], env))
    const claimed = await runJv([...ENROL, "--connect", "CONN2345", "--json"], env)
    expect(claimed.code).toBe(EXIT.ok)
    const out = json(claimed)
    expect(out).toMatchObject({ status: "pending", claimed: true, superseded: unclaimed.enrolment, fingerprint: unclaimed.fingerprint, ask: { claimed: true } })
    expect(out.enrolment).not.toBe(unclaimed.enrolment)
    const starts = vault.seen.slice(before).filter((c) => c.path === "/v1/enrol")
    expect(JSON.parse(starts[0]?.body ?? "{}").connect).toBeUndefined()
    expect(JSON.parse(starts[1]?.body ?? "{}").connect).toBe("CONN2345")
    const text = await readFile(join(pendingSlot(), "enrolment.json"), "utf8")
    expect(text).not.toContain("CONN2345")
    expect(JSON.parse(text)).toMatchObject({ id: out.enrolment, claimed: true })
    const again = await runJv([...ENROL, "--connect", "OTHER234", "--json"], env)
    expect(json(again)).toMatchObject({ enrolment: out.enrolment, claimed: true })
    expect(json(again).superseded).toBeUndefined()
    expect(again.stderr).toContain("already claimed; the connect code was not sent again")
    expect(vault.seen.slice(before).filter((c) => c.path === "/v1/enrol")).toHaveLength(2)
    expect(again.stdout).not.toContain("OTHER234")
  })

  test("a refused connect code is the vault's forbidden with the Connect an agent advice, and no record is left", async () => {
    vault.overrides.set("POST /v1/enrol", () => vaultError("forbidden", "The connect code is not valid for this workspace."))
    const result = await runJv([...ENROL, "--connect", "BADC0DE2", "--json"], env)
    // forbidden is exit 5 in the protocol's EXIT_FOR_ERROR, whose map is frozen.
    expect(result.code).toBe(EXIT.refused)
    expect(json(result)).toMatchObject({ error: "forbidden", message: "The connect code is not valid for this workspace.", next: { say: "The connect code was refused; open Connect an agent for a fresh one." } })
    expect(await record()).toBeNull()
    // G1 N-4: the slot and key this run made never reached the vault, so they
    // are discarded and status reports no ended attempt.
    expect(existsSync(pendingSlot())).toBe(false)
    const status = json(await runJv(["status", "--json"], env)) as { workspaces: unknown[] }
    expect(status.workspaces).toEqual([])
  })

  test("a refused start keeps a key the vault has already seen, and a new key whose start failed with a 5xx (G1 N-4)", async () => {
    const first = json(await runJv([...ENROL, "--json"], env))
    vault.enrolOutcome = { pendingPolls: 0, result: "expired" }
    expect((await runJv(["wait", first.enrolment as string, "--json"], env)).code).toBe(EXIT.error)
    vault.overrides.set("POST /v1/enrol", () => vaultError("forbidden", "The connect code is not valid for this workspace."))
    expect((await runJv([...ENROL, "--connect", "BADC0DE2", "--json"], env)).code).toBe(EXIT.refused)
    expect(existsSync(join(pendingSlot(), SOFTWARE_KEY_FILE))).toBe(true)
    expect(await keyFingerprint(await softwareJwk())).toBe(first.fingerprint as string)

    const other = pendingSlotPath(dir.path, vault.url, "other-space")
    vault.overrides.set("POST /v1/enrol", () => Response.json({ error: "internal", message: "down" }, { status: 500, headers: { "Mehen-Error": "1" } }))
    expect((await runJv(["enrol", "--workspace", "other-space", "--name", "test-mac", "--backend", "software", "--json"], env)).code).toBe(EXIT.error)
    expect(existsSync(join(other, SOFTWARE_KEY_FILE))).toBe(true)
  })
})

describe("mehen enrol scopes the key to its vault", () => {
  test("the scope file records the vault at creation and the tenant on active", async () => {
    await runJv([...ENROL, "--json"], env)
    expect(await readKeyScope(pendingSlot(), "software")).toEqual({ vault: vault.url, tenant: null })
    expect((await stat(join(pendingSlot(), SOFTWARE_KEY_SCOPE_FILE))).mode & 0o777).toBe(0o600)
    const id = (await record())?.id as string
    expect((await runJv(["wait", id, "--json"], env)).code).toBe(EXIT.ok)
    expect(await readKeyScope(activeSlot(), "software")).toEqual({ vault: vault.url, tenant: MOCK_TENANT })
  })

  test("a key made for another vault is refused with key_scope before anything is sent, and the key is untouched", async () => {
    const other = "http://127.0.0.1:1"
    const otherSlot = pendingSlot(other)
    const { jwk } = await createDeviceKey(otherSlot, "software", {}, { vault: vault.url, tenant: null })
    const before = vault.seen.length
    const result = await runJv([...ENROL, "--json"], { ...env, MEHEN_VAULT_URL: other })
    expect(result.code).toBe(EXIT.identity)
    expect(json(result)).toMatchObject({
      error: "key_scope",
      message: `The software device key in ${otherSlot} was made for ${vault.url}, not ${other}.`,
      next: { command: "mehen enrol --workspace <slug> --fresh-key" },
    })
    expect(String((json(result).next as { say: string }).say)).toContain(`set MEHEN_VAULT_URL back to ${vault.url}`)
    expect(vault.seen.length).toBe(before)
    expect(await softwareJwk(otherSlot)).toEqual(jwk)
    expect(await readKeyScope(otherSlot, "software")).toEqual({ vault: vault.url, tenant: null })
    expect(await record(otherSlot)).toBeNull()
    const human = await runJv(ENROL, { ...env, MEHEN_VAULT_URL: other })
    expect(human.code).toBe(EXIT.identity)
    expect(human.stderr).toContain(`was made for ${vault.url}, not ${other}.`)
  })

  test("--fresh-key after the refusal makes a new key for the new vault, with a new fingerprint", async () => {
    const other = new MockVault()
    try {
      other.enrolOutcome = { pendingPolls: 1, result: "active" }
      const otherSlot = pendingSlot(other.url)
      const { jwk: oldJwk } = await createDeviceKey(otherSlot, "software", {}, { vault: vault.url, tenant: null })
      const otherEnv = { ...env, MEHEN_VAULT_URL: other.url }
      expect((await runJv([...ENROL, "--json"], otherEnv)).code).toBe(EXIT.identity)
      const fresh = await runJv([...ENROL, "--fresh-key", "--wait", "--json"], otherEnv)
      expect(fresh.code).toBe(EXIT.ok)
      const active = activeSlot(other.url)
      const newJwk = await softwareJwk(active)
      expect(newJwk).not.toEqual(oldJwk)
      expect(lines(fresh)[0]?.fingerprint).toBe(await keyFingerprint(newJwk))
      expect(await readKeyScope(active, "software")).toEqual({ vault: other.url, tenant: MOCK_TENANT })
      expect(await readConfig(active)).toMatchObject({ vault: other.url })
      expect(WorkspaceEnrolStartSchema.parse(JSON.parse(other.seen[0]?.body ?? "{}")).jwk).toEqual(newJwk)
    } finally {
      other.stop()
    }
  })

  test("a key with no scope file (made before scopes were recorded) is adopted for this vault", async () => {
    const { jwk } = await createDeviceKey(pendingSlot(), "software", {})
    expect(await readKeyScope(pendingSlot(), "software")).toBeNull()
    const result = await runJv([...ENROL, "--wait", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(lines(result)[0]?.fingerprint).toBe(await keyFingerprint(jwk))
    expect(await softwareJwk(activeSlot())).toEqual(jwk)
    expect(await readKeyScope(activeSlot(), "software")).toEqual({ vault: vault.url, tenant: MOCK_TENANT })
  })
})

describe("mehen enrol names its workspace and owner (design 9.2, threat T11)", () => {
  test("without --workspace nothing is sent: a usage error whose next names the Connect an agent page", async () => {
    const before = vault.seen.length
    const result = await runJv(["enrol", "--name", "test-mac", "--backend", "software", "--json"], env)
    expect(result.code).toBe(EXIT.usage)
    expect(json(result)).toMatchObject({ error: "usage", next: { command: "mehen enrol --workspace <slug>", say: "Run `mehen enrol --workspace <slug>`; the slug is on the workspace's Connect an agent page." } })
    expect(vault.seen.length).toBe(before)
    await expect(stat(join(pendingSlot(), SOFTWARE_KEY_FILE))).rejects.toMatchObject({ code: "ENOENT" })
    expect((await runJv(["enrol", "--workspace", "Not A Slug", "--json"], env)).code).toBe(EXIT.usage)
    expect(vault.seen.length).toBe(before)
  })

  test("--team sends a team owner intent, waits through pending_admission and records the team owner", async () => {
    const before = vault.seen.length
    const result = await runJv(["enrol", "--workspace", "mock-space", "--name", "ci-runner", "--team", "ci", "--backend", "software", "--wait", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(JSON.parse(vault.seen[before]?.body ?? "{}")).toMatchObject({ workspace: "mock-space", owner: { kind: "team", team: "ci" } })
    expect(lines(result)[0]).toMatchObject({ ask: { intent: { workspace: "mock-space", team: "ci" } } })
    expect(lines(result).at(-1)).toMatchObject({ status: "active", owner: { kind: "team", team: "team_ci", name: "ci" } })
    expect(await readConfig(activeSlot())).toMatchObject({ owner: { kind: "team", team: "team_ci", name: "ci" } })
  })

  // Every active answer that does not match the intent: nothing is written,
  // the new device is revoked with the identity the vault returned, and the
  // provisional key and record are deleted.
  const mismatches: [string, (device: string) => unknown, string][] = [
    ["another workspace slug (a rename alias is not verified here)", (device) => ({ status: "active", tenant: MOCK_TENANT, workspace: { id: MOCK_TENANT, slug: "other-space", name: "Other" }, device, scope: WORKSPACE_SCOPE, owner: MOCK_OWNER }), "it is for workspace other-space, not mock-space"],
    ["a workspace id that is not the proof tenant", (device) => ({ status: "active", tenant: MOCK_TENANT, workspace: { id: "tn_other000000001", slug: "mock-space", name: "Mock Space" }, device, scope: WORKSPACE_SCOPE, owner: MOCK_OWNER }), "its workspace id tn_other000000001 is not its tenant"],
    ["a team owner for a machine that was to be your own", (device) => ({ status: "active", tenant: MOCK_TENANT, workspace: MOCK_WORKSPACE, device, scope: WORKSPACE_SCOPE, owner: { kind: "team", team: "team_ci", name: "ci" } }), "its owner is team ci, but this machine was to be your own"],
    ["a scope without privateCredentials", (device) => ({ status: "active", tenant: MOCK_TENANT, workspace: MOCK_WORKSPACE, device, scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay"] }, owner: MOCK_OWNER }), "its scope has no privateCredentials"],
    ["a legacy active answer with no workspace or owner", (device) => ({ status: "active", tenant: MOCK_TENANT, device, scope: WORKSPACE_SCOPE }), "it names no workspace or owner"],
  ]
  for (const [name, answer, why] of mismatches) {
    test(`an active answer with ${name} self-revokes, deletes the key and the record and writes no config`, async () => {
      vault.activeAnswer = (_enrolment, device) => answer(device)
      vault.enrolOutcome = { pendingPolls: 1, result: "active" }
      const revokedBefore = vault.revoked.length
      const result = await runJv([...ENROL, "--wait", "--json"], env)
      expect(result.code).toBe(EXIT.usage)
      const failure = lines(result).at(-1) as { error: string; message: string; next: { command: string } }
      expect(failure.error).toBe("workspace_mismatch")
      expect(failure.message).toContain(why)
      expect(failure.next.command).toBe("mehen enrol --workspace mock-space --fresh-key")
      expect(await readConfig(pendingSlot())).toBeNull()
      expect(existsSync(join(dir.path, "workspaces"))).toBe(false)
      await expect(stat(join(pendingSlot(), SOFTWARE_KEY_FILE))).rejects.toMatchObject({ code: "ENOENT" })
      await expect(stat(join(pendingSlot(), SOFTWARE_KEY_SCOPE_FILE))).rejects.toMatchObject({ code: "ENOENT" })
      expect(await record()).toBeNull()
      expect(vault.revoked.slice(revokedBefore)).toHaveLength(1)
      expect(failure.message).toContain(`The device ${vault.revoked.at(-1)} was revoked and this machine's key deleted.`)
    })
  }

  test("an active answer whose tenant is not a workspace id never names a path: nothing is written under workspaces/ or outside the root, and the key is deleted", async () => {
    vault.activeAnswer = (_enrolment, device) => ({ status: "active", tenant: "tn_../../escape", workspace: { id: "tn_../../escape", slug: "mock-space", name: "Mock Space" }, device, scope: WORKSPACE_SCOPE, owner: MOCK_OWNER })
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    const result = await runJv([...ENROL, "--wait", "--json"], env)
    expect(result.code).toBe(EXIT.usage)
    expect(lines(result).at(-1)).toMatchObject({ error: "workspace_mismatch", message: expect.stringContaining("its tenant tn_../../escape is not a workspace id") })
    expect(existsSync(join(dir.path, "workspaces"))).toBe(false)
    expect(existsSync(join(dir.path, "escape"))).toBe(false)
    expect(existsSync(join(dir.path, "locks", "escape.lock"))).toBe(false)
    await expect(stat(join(pendingSlot(), SOFTWARE_KEY_FILE))).rejects.toMatchObject({ code: "ENOENT" })
  })

  // A persistence failure after the vault said active undoes the
  // enrolment like a mismatch, and no success line is printed.
  test("a persistence failure after activation self-revokes with the activated identity, writes no config and prints no success", async () => {
    const pending = json(await runJv([...ENROL, "--json"], env))
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    await chmod(pendingSlot(), 0o500)
    const revokedBefore = vault.revoked.length
    try {
      const result = await runJv(["wait", pending.enrolment as string, "--json"], env)
      expect(result.code).toBe(EXIT.error)
      expect(result.stdout).not.toContain('"status":"active"')
      const failure = json(result) as { error: string; message: string; next: { command: string } }
      expect(failure).toMatchObject({ error: "failed", next: { command: "mehen enrol --workspace mock-space --fresh-key" } })
      expect(failure.message).toContain("this machine could not record it")
      expect(vault.revoked.slice(revokedBefore)).toEqual([deviceFor(pending.enrolment as string)])
    } finally {
      await chmod(pendingSlot(), 0o700)
    }
    expect(await readConfig(pendingSlot())).toBeNull()
    expect(existsSync(activeSlot())).toBe(false)
  })

  test("when the vault refuses the self-revocation the error names the device for an owner to revoke, and the key is still deleted", async () => {
    vault.activeAnswer = (_enrolment, device) => ({ status: "active", tenant: MOCK_TENANT, workspace: { id: MOCK_TENANT, slug: "other-space", name: "Other" }, device, scope: WORKSPACE_SCOPE, owner: MOCK_OWNER })
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    vault.overrides.set("POST /v1/devices/self/revoke", () => Response.json({ error: "internal", message: "down" }, { status: 500, headers: { "Mehen-Error": "1" } }))
    const result = await runJv([...ENROL, "--wait", "--json"], env)
    expect(result.code).toBe(EXIT.usage)
    expect((lines(result).at(-1) as { message: string }).message).toMatch(/the vault did not accept the revocation of device dev_for[A-Za-z0-9]+: an owner must revoke it on the Machines page/)
    expect(await readConfig(pendingSlot())).toBeNull()
    await expect(stat(join(pendingSlot(), SOFTWARE_KEY_FILE))).rejects.toMatchObject({ code: "ENOENT" })
  })

  test("a workspace name is echoed as data: hidden characters are spelled out, and the slug and id are what select", async () => {
    vault.workspace = { id: MOCK_TENANT, slug: "mock-space", name: "Mock\u001b[31m $(rm -rf) \"quoted\"" }
    const result = await runJv([...ENROL, "--wait"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(result.stdout).not.toContain("\u001b")
    expect(result.stdout).toContain("in Mock\\u001B[31m $(rm -rf) \"quoted\" (mock-space)")
    expect(await readConfig(activeSlot())).toMatchObject({ workspaceSlug: "mock-space", workspaceName: "Mock\u001b[31m $(rm -rf) \"quoted\"" })
  })
})

describe("mehen enrol with a Secure Enclave key (fake mehen-se)", () => {
  let helper = ""
  beforeEach(async () => {
    helper = await fakeHelper(dir.path)
    env = { ...env, MEHEN_SE_PATH: helper }
  })
  const SE = ["enrol", "--workspace", "mock-space", "--name", "test-mac", "--backend", "secure-enclave"]

  async function sidecarJwk(slot = pendingSlot()): Promise<DeviceJwk> {
    return JSON.parse(await readFile(join(slot, ENCLAVE_PUBLIC_KEY_FILE), "utf8")) as DeviceJwk
  }

  test("enrols with the enclave key and stores its public JWK beside the blob, 0600; the blob moves with the commit and still signs", async () => {
    const before = vault.seen.length
    const result = await runJv([...SE, "--wait", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const [pending, active] = lines(result)
    expect(pending).toMatchObject({ backend: "secure-enclave" })
    const posted = postedJwks(before)
    expect(posted).toHaveLength(1)
    expect(await sidecarJwk(activeSlot())).toEqual(posted[0] as DeviceJwk)
    expect(Object.keys(await sidecarJwk(activeSlot())).sort()).toEqual(["crv", "kty", "x", "y"])
    expect((await stat(join(activeSlot(), ENCLAVE_PUBLIC_KEY_FILE))).mode & 0o777).toBe(0o600)
    expect((await stat(join(activeSlot(), ENCLAVE_KEY_FILE))).mode & 0o777).toBe(0o600)
    expect(pending?.fingerprint).toBe(await keyFingerprint(posted[0] as DeviceJwk))
    expect(active).toMatchObject({ backend: "secure-enclave", slot: activeSlot() })
    expect(await readConfig(activeSlot())).toMatchObject({ backend: "secure-enclave", fingerprint: pending?.fingerprint as string })
    expect((await runJv(["status", "--json"], env)).code).toBe(EXIT.ok)
  })

  test("the enclave key is reused when its attempt ended: the sidecar JWK is posted again once the blob has signed for it", async () => {
    const first = json(await runJv([...SE, "--json"], env))
    await lapse(pendingSlot(), (r) => ({ ...r, legacy: true }))
    const before = vault.seen.length
    const second = json(await runJv([...SE, "--json"], env))
    expect(second.enrolment).not.toBe(first.enrolment)
    expect(second.fingerprint).toBe(first.fingerprint)
    expect(postedJwks(before)).toEqual([await sidecarJwk()])
  })

  test("a sidecar JWK the blob cannot sign for is never posted: a fresh key is made and the sidecar replaced", async () => {
    await runJv([...SE, "--json"], env)
    const original = await sidecarJwk()
    const other = await crypto.subtle.exportKey("jwk", (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])).publicKey)
    const tampered: DeviceJwk = { kty: "EC", crv: "P-256", x: other.x as string, y: other.y as string }
    await Bun.write(join(pendingSlot(), ENCLAVE_PUBLIC_KEY_FILE), `${JSON.stringify(tampered)}\n`)
    const before = vault.seen.length
    const second = json(await runJv([...SE, "--json"], env))
    const posted = postedJwks(before)
    expect(posted).toHaveLength(1)
    expect(posted[0]).not.toEqual(tampered)
    expect(posted[0]).not.toEqual(original)
    expect(await sidecarJwk()).toEqual(posted[0] as DeviceJwk)
    expect(second.fingerprint).toBe(await keyFingerprint(posted[0] as DeviceJwk))
  })

  test("a missing or malformed sidecar means a fresh key", async () => {
    await runJv([...SE, "--json"], env)
    const first = await sidecarJwk()
    await rm(join(pendingSlot(), ENCLAVE_PUBLIC_KEY_FILE))
    await runJv([...SE, "--json"], env)
    const second = await sidecarJwk()
    expect(second).not.toEqual(first)
    await Bun.write(join(pendingSlot(), ENCLAVE_PUBLIC_KEY_FILE), "{not json")
    await runJv([...SE, "--json"], env)
    expect(await sidecarJwk()).not.toEqual(second)
  })

  test("--fresh-key and mehen revoke remove the blob and the sidecar together", async () => {
    await runJv([...SE, "--json"], env)
    const original = await sidecarJwk()
    const fresh = await runJv([...SE, "--fresh-key", "--wait", "--json"], env)
    expect(fresh.code).toBe(EXIT.ok)
    expect(await sidecarJwk(activeSlot())).not.toEqual(original)
    expect((await runJv(["revoke", "--json"], env)).code).toBe(EXIT.ok)
    await expect(stat(join(activeSlot(), ENCLAVE_KEY_FILE))).rejects.toMatchObject({ code: "ENOENT" })
    await expect(stat(join(activeSlot(), ENCLAVE_PUBLIC_KEY_FILE))).rejects.toMatchObject({ code: "ENOENT" })
    expect(await readConfig(activeSlot())).toBeNull()
  })
})

describe("fingerprintLines", () => {
  // The protocol's known-answer key (fingerprint.test.ts).
  const KNOWN_JWK: DeviceJwk = { kty: "EC", crv: "P-256", x: "6tuE4IjbL0XotYW14I4zOUjfvFBmDiXXIaU6JjRAtnQ", y: "HWA3LrV2W6kgB-T2UebdLmCTHsRpX9K_gYlyjIyTCtM" }

  test("names the group the page hides for the protocol's known-answer codes, and shows every word with its colour as text", async () => {
    const thumbprint = await jwkThumbprint(KNOWN_JWK)
    expect(thumbprint).toBe("LX-22Me3dAaszq-tcpK6ZOk5DS3wezKfqayZDEim7H4")
    const fp = fingerprintOf(thumbprint)
    expect(fp).toBe("5NZV DP67 PXT0 DB6E")
    const groups = fingerprintGroups(fp)
    const [words] = (await fingerprintLines({ thumbprint, code: "ABCD2345" })).map(plainText)
    expect(words).toBe("  words:   puppy (violet)  potato (indigo)  juice (mint)  oven (olive)")
    const expectations: [string, number, string][] = [
      ["ABCD2345", 2, "third"],
      ["K7Q2MX4D", 3, "fourth"],
      ["ZZZZ9999", 2, "third"],
    ]
    for (const [code, index, word] of expectations) {
      const [words, hidden] = (await fingerprintLines({ thumbprint, code })).map(plainText)
      expect(hidden).toBe(`  hidden:  the page hides the ${word} group, ${groups[index as 0 | 1 | 2 | 3]}: type it on the page`)
      expect(words).toMatch(/^ {2}words: {3}([a-z]+ \([a-z]+\) {2}){3}[a-z]+ \([a-z]+\)$/)
    }
  })

  test("the hidden group is the one at fingerprintGroupIndex, never read from anywhere but the key", async () => {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
    const exported = await crypto.subtle.exportKey("jwk", pair.publicKey)
    const jwk: DeviceJwk = { kty: "EC", crv: "P-256", x: exported.x as string, y: exported.y as string }
    const thumbprint = await jwkThumbprint(jwk)
    const groups = fingerprintGroups(fingerprintOf(thumbprint))
    const [, hidden] = (await fingerprintLines({ thumbprint, code: "abcd-2345" })).map(plainText)
    expect(hidden).toContain(`the third group, ${groups[2]}:`)
  })
})

describe("mehen enrol asks for a narrower scope (scoped enrolment)", () => {
  // The scope field of each POST /v1/enrol since `from`, undefined when absent.
  function postedScopes(from = 0): unknown[] {
    return vault.seen
      .slice(from)
      .filter((call) => call.method === "POST" && call.path === "/v1/enrol")
      .map((call) => (JSON.parse(call.body) as { scope?: unknown }).scope)
  }

  test("every flag lands in the start body's scope, in --json and in the record", async () => {
    const before = vault.seen.length
    const result = await runJv([...ENROL, "--tag", "agents", "--tag", "ci:build", "--project", "prj_one", "--project", "prj_two", "--mode", "relay", "--mode", "placeholder", "--no-private", "--workloads-only", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const scope: EnrolRequestedScope = { tags: ["agents", "ci:build"], projects: ["prj_one", "prj_two"], modes: ["relay", "placeholder"], privateCredentials: false, workloads: "required" }
    expect(postedScopes(before)).toEqual([scope])
    expect(json(result).requestedScope).toEqual(scope)
    expect((await record())?.scope).toEqual(scope)
  })

  test("each flag alone sends only its own field", async () => {
    const cases: [string[], Record<string, unknown>][] = [
      [["--tag", "agents"], { tags: ["agents"] }],
      [["--project", "prj_one"], { projects: ["prj_one"] }],
      [["--mode", "sign"], { modes: ["sign"] }],
      [["--no-private"], { privateCredentials: false }],
      [["--workloads-only"], { workloads: "required" }],
    ]
    for (const [flags, scope] of cases) {
      const before = vault.seen.length
      const result = await runJv([...ENROL, ...flags, "--json"], env)
      expect(result.code).toBe(EXIT.ok)
      expect(postedScopes(before)).toEqual([scope])
    }
  })

  test("without a scope flag nothing is sent: no scope in the body, the --json output or the record", async () => {
    const before = vault.seen.length
    const result = await runJv([...ENROL, "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const [call] = vault.seen.slice(before).filter((c) => c.path === "/v1/enrol")
    expect(Object.keys(JSON.parse(call?.body ?? "{}") as object)).not.toContain("scope")
    expect(Object.keys(json(result))).not.toContain("requestedScope")
    expect(Object.keys((await record()) ?? {})).not.toContain("scope")
  })

  test("a bad value is a usage error naming its flag, before a key is made or anything is signed", async () => {
    const cases: [string[], string][] = [
      [["--tag", "Agents"], "--tag"],
      [["--tag", "-x"], "--tag"],
      [["--tag", "a".repeat(41)], "--tag"],
      [Array.from({ length: 33 }, (_, i) => ["--tag", `t${i}`]).flat(), "--tag"],
      [["--project", ""], "--project"],
      [["--project", "p".repeat(65)], "--project"],
      [["--mode", "lease"], "--mode"],
      [["--mode", "reveal"], "--mode"],
      [["--mode", "relay", "--mode", "relay"], "--mode"],
    ]
    const before = vault.seen.length
    for (const [flags, flag] of cases) {
      const result = await runJv([...ENROL, ...flags, "--json"], env)
      expect(result.code).toBe(EXIT.usage)
      const body = json(result) as { error: string; message: string }
      expect(body.error).toBe("usage")
      expect(body.message).toContain(flag)
    }
    expect(vault.seen.slice(before)).toHaveLength(0)
    expect(existsSync(pendingSlot())).toBe(false)
  })

  test("the same requested scope resumes the attempt; a different one starts a new attempt with the same key", async () => {
    const before = vault.seen.length
    const first = json(await runJv([...ENROL, "--tag", "agents", "--json"], env))
    const again = json(await runJv([...ENROL, "--tag", "agents", "--json"], env))
    expect(again.enrolment).toBe(first.enrolment)
    expect(postedScopes(before)).toHaveLength(1)
    const narrower = json(await runJv([...ENROL, "--tag", "agents", "--no-private", "--json"], env))
    expect(narrower.enrolment).not.toBe(first.enrolment)
    expect(narrower.requestedScope).toEqual({ tags: ["agents"], privateCredentials: false })
    const unscoped = json(await runJv([...ENROL, "--json"], env))
    expect(unscoped.enrolment).not.toBe(narrower.enrolment)
    expect(postedScopes(before)).toEqual([{ tags: ["agents"] }, { tags: ["agents"], privateCredentials: false }, undefined])
    const keys = postedJwks(before)
    expect(keys.every((k) => k.x === keys[0]?.x && k.y === keys[0]?.y)).toBe(true)
  })

  test("a person reading along sees what the machine asked for under the ask", async () => {
    const result = await runJv([...ENROL, "--tag", "agents", "--mode", "relay", "--no-private", "--workloads-only"], env)
    expect(result.code).toBe(EXIT.ok)
    const out = result.stdout.split("\n")
    expect(out[8]).toBe("  scope:   asks for less than usual: items tagged agents; modes relay; no private credentials; acts only through workloads")
    expect(out.slice(9).join("")).toBe("")
  })

  test("an enrolled machine sends nothing and says the requested scope was not applied", async () => {
    await vault.enrolSoftware(dir.path)
    const before = vault.seen.length
    const result = await runJv(["enrol", "--workspace", "mock-space", "--tag", "agents", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toMatchObject({ status: "active", alreadyEnrolled: true })
    expect(vault.seen.slice(before).map((c) => `${c.method} ${c.path}`)).toEqual(["GET /v1/me"])
    expect(result.stderr).toContain("the requested scope (items tagged agents) was not sent")
  })
})
