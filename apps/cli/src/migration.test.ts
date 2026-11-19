// The migration to layout 2 on one machine
// fixture: the result, the kill matrix (after the journal write, every
// move, the marker write and the journal deletion), a stuck step refused
// by status while doctor prints it, the managed-host entry,
// and the legacy-adapter gate: today's enrol, wait and status on the
// migrated fixture against the mock vault.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, readlinkSync, realpathSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs"
import { join, relative } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { readConfig, writeConfig } from "./config.ts"
import { CliError } from "./errors.ts"
import { activeSlotPath, pendingSlotPath } from "./home.ts"
import { readLedger } from "./ledger.ts"
import { type MigrationJournal, assertSafeRoot, enterRoot, migrationJournalPath, migrationState, readMigrationJournal } from "./migration.ts"
import { selectSlot } from "./slots.ts"
import { fakeHelper } from "./testing/fake-mehen-se.ts"
import { MACHINE_ENCLAVE_JWK, MACHINE_INTAKE, MACHINE_NORTHWIND, MACHINE_OWNER, MACHINE_PERSONAL, MACHINE_PERSONAL_JWK, MACHINE_STRAY, buildMachineFixture } from "./testing/fixtures/machine-contexts-v1/index.ts"
import { MockVault, deviceFor } from "./testing/mock-vault.ts"
import { runJv, tempDir } from "./testing/run-mehen.ts"

const ORIGIN = "https://app.mehen.dev"

let dir: { path: string; remove(): Promise<void> }
let root: string

beforeEach(async () => {
  dir = await tempDir()
  root = join(dir.path, "mehen")
})
afterEach(() => dir.remove())

class Killed extends Error {}

// Every file under the root, by relative path, with its content; the
// marker's timestamp and the (released) lock directory left out.
function snapshot(at: string): Record<string, string> {
  const out: Record<string, string> = {}
  const walk = (path: string) => {
    for (const name of readdirSync(path).sort()) {
      const full = join(path, name)
      const info = lstatSync(full)
      const rel = relative(at, full)
      if (rel === "locks" || rel.startsWith("locks/")) continue
      if (info.isSymbolicLink()) out[rel] = `link ${readlinkSync(full)}`
      else if (info.isDirectory()) {
        out[`${rel}/`] = (info.mode & 0o777).toString(8)
        walk(full)
      } else if (rel === "mehen.json") {
        const { migratedAt: _at, ...marker } = JSON.parse(readFileSync(full, "utf8")) as { migratedAt: string }
        out[rel] = JSON.stringify(marker)
      } else out[rel] = `${(info.mode & 0o777).toString(8)} ${readFileSync(full, "utf8")}`
    }
  }
  walk(at)
  return out
}

async function migrate(hooks?: { at?: (point: string) => void }) {
  return enterRoot({ HOME: dir.path, MEHEN_HOME: root }, hooks ? { hooks } : {})
}

describe("the machine fixture", () => {
  test("migrates to one active slot and one legacy pending slot; strays and setup state are left; the caches and default-context go; a rerun is a no-op", async () => {
    await buildMachineFixture(root, ORIGIN)
    const setupState = readFileSync(join(root, "setup-state.json"), "utf8")
    const { migrated } = await migrate()
    expect(migrated?.steps.map((s) => [s.kind, relative(root, s.source)])).toEqual([
      ["slot", ""],
      ["pending", `contexts/${MACHINE_PERSONAL.slug}`],
      ["delete", "default-context"],
      ["delete", "update-check.json"],
      ["delete", `contexts/${MACHINE_PERSONAL.slug}/update-check.json`],
      ["delete", `contexts/${MACHINE_PERSONAL.slug}`],
      ["delete", "contexts"],
      ["leave", MACHINE_STRAY],
    ])
    const active = activeSlotPath(root, ORIGIN, MACHINE_NORTHWIND.tenant)
    const pending = pendingSlotPath(root, ORIGIN, MACHINE_PERSONAL.slug)
    expect(readdirSync(root).sort()).toEqual(["locks", "mehen.json", "pending", MACHINE_STRAY, "setup-state.json", "workspaces"].sort())
    expect(readdirSync(active).sort()).toEqual(["config.json", "device-key.se", "device-key.se.pub.json", "device-key.se.scope.json", "ledger.json"])
    expect(readdirSync(pending).sort()).toEqual(["device-key.json", "device-key.scope.json", "enrolment.json"])
    expect(readdirSync(join(root, MACHINE_STRAY)).sort()).toEqual(["config.json", "update-check.json"])
    expect(readFileSync(join(root, "setup-state.json"), "utf8")).toBe(setupState)
    expect(JSON.parse(readFileSync(join(root, "mehen.json"), "utf8"))).toMatchObject({ layout: 2, from: "contexts-v1" })
    expect(existsSync(migrationJournalPath(root))).toBe(false)
    // The pending slot's record is the legacy one: never renewed, never claimed.
    expect(JSON.parse(readFileSync(join(pending, "enrolment.json"), "utf8"))).toEqual({ v: 1, state: "pending", id: MACHINE_PERSONAL.enrolment, code: MACHINE_PERSONAL.code, url: `${ORIGIN}/w/${MACHINE_PERSONAL.slug}/e/${MACHINE_PERSONAL.code}`, origin: ORIGIN, intent: { workspace: MACHINE_PERSONAL.slug, team: null }, name: "sam-mac-mini", backend: "software", jwk: MACHINE_PERSONAL_JWK, session: "pi-office", startedAt: "2026-10-28T12:00:00.000Z", expiresAt: "2026-10-28T12:15:00.000Z", hardExpiresAt: null, renewals: 0, legacy: true, claimed: false })
    // Every file the migration made or moved is private.
    for (const [path, value] of Object.entries(snapshot(root))) {
      if (path.endsWith("/")) expect(value, path).toBe("700")
      else if (path !== "mehen.json") expect(value.slice(0, 3), path).toBe("600")
    }
    const after = snapshot(root)
    expect((await migrate()).migrated).toBeNull()
    expect(snapshot(root)).toEqual(after)
    // The open intake is still this slot's, and the selection finds the only active slot.
    expect((await readLedger(active, { vaultUrl: ORIGIN, workspace: MACHINE_NORTHWIND.tenant, device: MACHINE_NORTHWIND.device, workspaceSlug: MACHINE_NORTHWIND.slug })).map((e) => e.ask.id)).toEqual([MACHINE_INTAKE])
    expect(await selectSlot({ HOME: dir.path, MEHEN_HOME: root })).toMatchObject({ dir: active, reason: "only" })
  })

  // One fixture build and two migrations per kill point: a loaded runner needs more than the 5 s default.
  test("a kill after the journal write, after every move, after the marker write and after the journal deletion resumes to the identical result", async () => {
    await buildMachineFixture(root, ORIGIN)
    const points: string[] = []
    await migrate({ at: (point) => points.push(point) })
    const expected = snapshot(root)
    expect(points[0]).toBe("journal written")
    expect(points.at(-2)).toBe("marker written")
    expect(points.at(-1)).toBe("journal deleted")
    expect(points.filter((p) => p.includes("moved") || p.includes("renamed")).length).toBeGreaterThanOrEqual(7)
    for (let kill = 0; kill < points.length; kill++) {
      await dir.remove()
      mkdirSync(dir.path, { recursive: true, mode: 0o700 })
      await buildMachineFixture(root, ORIGIN)
      let seen = 0
      await expect(migrate({ at: () => { if (seen++ === kill) throw new Killed(points[kill]) } })).rejects.toBeInstanceOf(Killed)
      await migrate()
      expect(snapshot(root), `killed after "${points[kill]}"`).toEqual(expected)
    }
  }, 30_000)

  test("a lock left by a dead migrating process is reaped; two migrations at once serialise to one result", async () => {
    await buildMachineFixture(root, ORIGIN)
    const child = Bun.spawn([process.execPath, "--eval", ""], { stdout: "ignore", stderr: "ignore" })
    await child.exited
    mkdirSync(join(root, "locks"), { mode: 0o700 })
    writeFileSync(join(root, "locks", "root.lock"), JSON.stringify({ pid: child.pid, at: "2026-10-28T12:00:00.000Z" }), { mode: 0o600 })
    const old = new Date(Date.now() - 11_000)
    utimesSync(join(root, "locks", "root.lock"), old, old)
    const [a, b] = await Promise.all([migrate(), migrate()])
    expect([a.migrated === null, b.migrated === null].sort()).toEqual([false, true])
    expect(existsSync(activeSlotPath(root, ORIGIN, MACHINE_NORTHWIND.tenant))).toBe(true)
  })
})

describe("inventory rules", () => {
  test("a single default context migrates by files; two devices in one workspace become a duplicate slot; a missing key is reported, never deleted", async () => {
    mkdirSync(root, { mode: 0o700 })
    const config = { vault: ORIGIN, tenant: "tn_linuxbox0000000001", device: "dev_linuxbox000000001", backend: "software" as const }
    await writeConfig(root, config)
    await writeConfig(join(root, "contexts", "twin"), { ...config, device: "dev_twin0000000001" })
    await migrate()
    const slot = activeSlotPath(root, ORIGIN, config.tenant)
    expect(await readConfig(slot)).toEqual(config)
    const twin = `${slot}.duplicate-dev_twin0000000001`
    expect(await readConfig(twin)).toMatchObject({ device: "dev_twin0000000001" })
    // Neither had a key: both are there, both are reported, nothing was deleted.
    const found = (await import("./slots.ts")).listSlots
    const views = await Promise.all((await found(root)).map((f) => import("./slots.ts").then((m) => m.slotView(f, "office"))))
    expect(views.map((v) => [v.state, v.state === "corrupt" ? v.reason : null])).toEqual([["corrupt", "key_missing"], ["corrupt", "duplicate_device"]])
  })

  test("an older enrol entry for the same key is left as superseded; an entry with no key on disk is left; the newest moves", async () => {
    await buildMachineFixture(root, ORIGIN)
    const ledgerPath = join(root, "contexts", MACHINE_PERSONAL.slug, "ledger.json")
    const ledger = JSON.parse(readFileSync(ledgerPath, "utf8")) as { entries: { ask: { id: string; wait: string }; createdAt: string }[] }
    const older = { ...ledger.entries[0]!, createdAt: "2026-10-28T11:00:00.000Z", ask: { ...ledger.entries[0]!.ask, id: "enr_olderAttempt01", wait: "mehen wait enr_olderAttempt01" } }
    writeFileSync(ledgerPath, JSON.stringify({ entries: [older, ledger.entries[0]] }), { mode: 0o600 })
    const keyless = join(root, "contexts", "keyless")
    mkdirSync(keyless, { mode: 0o700 })
    writeFileSync(join(keyless, "ledger.json"), JSON.stringify({ entries: [{ ...ledger.entries[0], ask: { ...ledger.entries[0]!.ask, id: "enr_keylessAttempt", wait: "mehen wait enr_keylessAttempt" } }] }), { mode: 0o600 })
    const { migrated } = await migrate()
    const leaves = (migrated as MigrationJournal).steps.filter((s) => s.kind === "leave").map((s) => (s.kind === "leave" ? s.detail : ""))
    expect(leaves).toContain(`enrolment enr_olderAttempt01 is superseded by ${MACHINE_PERSONAL.enrolment}; the vault has already expired it`)
    expect(leaves).toContain("enrolment enr_keylessAttempt has no key on disk")
    expect(JSON.parse(readFileSync(join(pendingSlotPath(root, ORIGIN, MACHINE_PERSONAL.slug), "enrolment.json"), "utf8"))).toMatchObject({ id: MACHINE_PERSONAL.enrolment })
    expect(existsSync(join(keyless, "ledger.json"))).toBe(true)
  })

  test("a file the journal would move that is not private aborts before any write; so does a root below a link another user controls or a world-writable directory", async () => {
    await buildMachineFixture(root, ORIGIN)
    const before = snapshot(root)
    chmodSync(join(root, "device-key.se"), 0o644)
    await expect(migrate()).rejects.toMatchObject({ code: "failed" })
    chmodSync(join(root, "device-key.se"), 0o600)
    expect(snapshot(root)).toEqual(before)
    expect(existsSync(migrationJournalPath(root))).toBe(false)
    // An ancestor others can write, and a link in the path that is not root's.
    const shared = join(realpathSync(dir.path), "shared")
    mkdirSync(shared, { mode: 0o700 })
    chmodSync(shared, 0o777)
    try {
      expect(() => assertSafeRoot(join(shared, "mehen"))).toThrow(expect.objectContaining({ code: "key_insecure" }))
    } finally {
      chmodSync(shared, 0o700)
    }
    symlinkSync(root, join(dir.path, "linked"))
    expect(() => assertSafeRoot(join(dir.path, "linked", "x"))).toThrow(CliError)
    await expect(enterRoot({ HOME: dir.path, MEHEN_HOME: join(dir.path, "linked") })).rejects.toMatchObject({ code: "key_insecure" })
    expect(snapshot(root)).toEqual(before)
  })
})

describe("a stuck or corrupt journal", () => {
  test("status refuses failed with next mehen doctor --json; doctor prints the journal without migrating; nothing is deleted", async () => {
    await buildMachineFixture(root, ORIGIN)
    await expect(migrate({ at: (point) => { if (point === "journal written") throw new Killed(point) } })).rejects.toBeInstanceOf(Killed)
    // Both ends of the whole-directory rename now exist: the step cannot continue.
    const target = pendingSlotPath(root, ORIGIN, MACHINE_PERSONAL.slug)
    mkdirSync(target, { recursive: true, mode: 0o700 })
    writeFileSync(join(target, "device-key.json"), "{}", { mode: 0o600 })
    const env = { HOME: dir.path, MEHEN_HOME: root }
    const contents = (at: Record<string, string>) => Object.entries(at).filter(([path]) => !path.endsWith("/") && path !== "migration.json").map(([, value]) => value).sort()
    const before = snapshot(root)
    const status = await runJv(["status", "--json"], env)
    expect(status.code).toBe(EXIT.error)
    expect(JSON.parse(status.stdout)).toMatchObject({ error: "failed", next: { command: "mehen doctor --json" } })
    expect(JSON.parse(status.stdout).message).toContain("is stuck")
    // The steps before the stuck one ran; nothing was deleted, and both ends of the stuck step are kept.
    const stuck = snapshot(root)
    for (const value of contents(before)) expect(contents(stuck)).toContain(value)
    expect(existsSync(join(root, "contexts", MACHINE_PERSONAL.slug, "ledger.json"))).toBe(true)
    expect(existsSync(join(target, "device-key.json"))).toBe(true)
    const doctor = await runJv(["doctor", "--json"], env)
    expect(doctor.code).toBe(EXIT.error)
    // `migration` is the unfinished journal itself; the migration row names the stuck step.
    const report = JSON.parse(doctor.stdout) as { migration: { v: number; from: string; steps: unknown[] }; machine: { check: string; status: string; detail: string }[]; workspaces: unknown[]; origins: unknown[] }
    expect(report.migration).toMatchObject({ v: 1, from: "contexts-v1" })
    expect(report.migration.steps.length).toBeGreaterThan(0)
    expect(report.machine.find((c) => c.check === "migration")).toMatchObject({ status: "fail", detail: expect.stringContaining("cannot continue") })
    // The slots are not read and nothing is probed on a stuck root.
    expect(report.workspaces).toEqual([])
    expect(report.origins).toEqual([])
    // doctor never migrates.
    expect(snapshot(root)).toEqual(stuck)
    // A corrupt journal: the same refusal, and doctor says corrupt.
    writeFileSync(migrationJournalPath(root), "{ not json", { mode: 0o600 })
    expect(JSON.parse((await runJv(["status", "--json"], env)).stdout)).toMatchObject({ error: "failed", next: { command: "mehen doctor --json" } })
    const corrupt = JSON.parse((await runJv(["doctor", "--json"], env)).stdout) as { migration: unknown; machine: { check: string; status: string; detail: string }[] }
    expect(corrupt.migration).toBeNull()
    expect(corrupt.machine.find((c) => c.check === "migration")).toMatchObject({ status: "fail", detail: expect.stringContaining("cannot be read") })
    expect(await readMigrationJournal(root)).toMatchObject({ corrupt: expect.any(String) })
  })

  test("doctor on a legacy root warns that the next command migrates it, and on a resumable journal that the next command resumes it", async () => {
    await buildMachineFixture(root, ORIGIN)
    const env = { HOME: dir.path, MEHEN_HOME: root, MEHEN_VAULT_URL: "http://127.0.0.1:1" }
    const legacy = JSON.parse((await runJv(["doctor", "--json"], env)).stdout) as { migration: unknown; machine: { check: string; status: string; detail: string }[] }
    expect(legacy.migration).toBeNull()
    expect(legacy.machine.find((c) => c.check === "migration")).toMatchObject({ status: "warn", detail: `${root} is not migrated yet; the next command migrates it.` })
    expect(existsSync(join(root, "mehen.json"))).toBe(false)
    await expect(migrate({ at: (point) => { if (point.includes("moved")) throw new Killed(point) } })).rejects.toBeInstanceOf(Killed)
    expect((await migrationState(root)).state).toBe("journal")
    const resumable = JSON.parse((await runJv(["doctor", "--json"], env)).stdout) as { migration: { v: number } | null; machine: { check: string; status: string }[] }
    expect(resumable.machine.find((c) => c.check === "migration")).toMatchObject({ status: "warn" })
    expect(resumable.migration).toMatchObject({ v: 1 })
  })
})

// An owner-provisioned layout-2 root runs under unchanged rule
// 0; automatic migration never runs on a managed host.
describe("managed hosts", () => {
  function provision() {
    const owner = realpathSync(dir.path)
    chmodSync(owner, 0o700)
    mkdirSync(join(owner, ".config", "mehen"), { recursive: true, mode: 0o700 })
    chmodSync(join(owner, ".config"), 0o755)
    writeFileSync(join(owner, ".config", "mehen", "managed-agents"), "", { mode: 0o600 })
    return { owner, files: { ownerRoot: owner } }
  }

  test("a provisioned layout-2 root passes the entry and rule 0 selects the pin; nothing is migrated", async () => {
    const { owner, files } = provision()
    const agentRoot = join(owner, "agent-root")
    const pinned = activeSlotPath(agentRoot, ORIGIN, MACHINE_NORTHWIND.tenant)
    mkdirSync(pinned, { recursive: true, mode: 0o700 })
    for (let at = pinned; at !== owner; at = join(at, "..")) chmodSync(at, 0o700)
    const config = { vault: ORIGIN, tenant: MACHINE_NORTHWIND.tenant, device: MACHINE_NORTHWIND.device, backend: "software" as const, workspaceSlug: MACHINE_NORTHWIND.slug, workspaceName: MACHINE_NORTHWIND.name }
    await writeConfig(pinned, config)
    const pin = { agentDir: join(owner, "agent"), configDir: pinned, origin: ORIGIN, tenant: config.tenant, device: config.device, scope: { tags: ["work"], projects: [], maxEnvironment: "unprotected", modes: ["relay"], privateCredentials: false } }
    mkdirSync(pin.agentDir, { mode: 0o700 })
    writeFileSync(join(pinned, "contexts.json"), JSON.stringify({ version: 3, contexts: { work: pin } }), { mode: 0o600 })
    writeFileSync(join(agentRoot, "mehen.json"), JSON.stringify({ layout: 2, migratedAt: "2026-10-28T12:00:00.000Z", from: null }), { mode: 0o600 })
    const env = { HOME: owner, MEHEN_CONFIG_DIR: pinned, MEHEN_MANAGED_CONTEXT: "work" }
    expect(await enterRoot(env, { files })).toEqual({ root: agentRoot, migrated: null })
    expect(await selectSlot(env, { files })).toMatchObject({ dir: pinned, reason: "managed" })
  })

  test("a legacy layout on a managed host refuses workspace_mismatch before touching the root", async () => {
    const { owner, files } = provision()
    const legacy = join(owner, "mehen-work")
    mkdirSync(legacy, { mode: 0o700 })
    await writeConfig(legacy, { vault: ORIGIN, tenant: MACHINE_NORTHWIND.tenant, device: MACHINE_NORTHWIND.device, backend: "software" })
    const before = readdirSync(legacy).sort()
    const env = { HOME: owner, MEHEN_CONFIG_DIR: legacy, MEHEN_MANAGED_CONTEXT: "work" }
    await expect(enterRoot(env, { files })).rejects.toMatchObject({ code: "workspace_mismatch", message: expect.stringContaining("never migrates a managed host") })
    expect(readdirSync(legacy).sort()).toEqual(before)
  })
})

// The merge gate: today's status, enrol and wait on a
// migrated fixture against the mock vault, including the migrated
// pending record whose server answer is active after its local expiry.
describe("today's commands on the migrated machine fixture", () => {
  let vault: MockVault
  beforeAll(() => {
    vault = new MockVault()
  })
  afterAll(() => vault.stop())

  async function office(): Promise<Record<string, string>> {
    await buildMachineFixture(root, vault.url)
    vault.devices.set(MACHINE_NORTHWIND.device, { jwk: MACHINE_ENCLAVE_JWK, revoked: false, tenant: MACHINE_NORTHWIND.tenant })
    vault.workspaces.set(MACHINE_NORTHWIND.tenant, { id: MACHINE_NORTHWIND.tenant, slug: MACHINE_NORTHWIND.slug, name: MACHINE_NORTHWIND.name })
    vault.owner = MACHINE_OWNER
    return { MEHEN_CONFIG_DIR: root, MEHEN_VAULT_URL: vault.url, MEHEN_SE_PATH: await fakeHelper(dir.path) }
  }

  test("the migrated line is one JSON object on stderr with --json", async () => {
    const env = await office()
    const status = await runJv(["workspace", "list", "--json"], env)
    expect(status.code).toBe(EXIT.ok)
    expect(JSON.parse(status.stderr)).toEqual({ migrated: { root, slots: 1, pending: 1, deleted: 5, left: [join(root, MACHINE_STRAY)] } })
  })

  // status only observes: before the first other command it
  // refuses with the command that migrates, and changes nothing.
  test("status refuses the unmigrated root and changes nothing; workspace list migrates on first use; status then answers for the Northwind slot with its enclave key; pending still lists its intake", async () => {
    const env = await office()
    const untouched = snapshot(root)
    const refused = await runJv(["status", "--json"], env)
    expect(refused.code).toBe(EXIT.error)
    expect(JSON.parse(refused.stdout)).toMatchObject({ error: "failed", next: { command: "mehen workspace list" } })
    expect(snapshot(root)).toEqual(untouched)
    const list = await runJv(["workspace", "list"], env)
    expect(list.code).toBe(EXIT.ok)
    expect(list.stderr).toBe(`mehen: migrated ${root} to the workspaces layout: 1 workspace, 1 pending enrolment; 1 item left in place (mehen doctor names them).\n`)
    const human = await runJv(["status"], env)
    expect(human.code).toBe(EXIT.ok)
    expect(human.stdout).toContain(`in Northwind (northwind) at ${vault.url}`)
    const status = await runJv(["status", "--json"], env)
    expect(status.code).toBe(EXIT.ok)
    expect(JSON.parse(status.stdout)).toMatchObject({ workspaces: [{ state: "active", check: { ok: true, status: { tenant: MACHINE_NORTHWIND.tenant, device: MACHINE_NORTHWIND.device, slot: activeSlotPath(root, vault.url, MACHINE_NORTHWIND.tenant), pending: 1 } } }, { state: "pending", enrolment: MACHINE_PERSONAL.enrolment }] })
    const again = await runJv(["status", "--json"], env)
    expect(again.stderr).toBe("")
    const pending = await runJv(["pending", "--json"], env)
    expect((JSON.parse(pending.stdout) as { pending: { id: string }[] }).pending.map((a) => a.id)).toContain(MACHINE_INTAKE)
  })

  test("wait finishes the migrated Personal enrolment that the vault answers active after its local expiry", async () => {
    const env = await office()
    vault.enrolments.set(MACHINE_PERSONAL.enrolment, { id: MACHINE_PERSONAL.enrolment, jwk: MACHINE_PERSONAL_JWK, name: "sam-mac-mini", backend: "software", polls: 0, workspace: MACHINE_PERSONAL.slug, owner: { kind: "self" } })
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    vault.workspace = { id: MACHINE_PERSONAL.tenant, slug: MACHINE_PERSONAL.slug, name: MACHINE_PERSONAL.name }
    try {
      expect((await runJv(["workspace", "list", "--json"], env)).code).toBe(EXIT.ok)
      const pendingSlot = pendingSlotPath(root, vault.url, MACHINE_PERSONAL.slug)
      expect(existsSync(join(pendingSlot, "enrolment.json"))).toBe(true)
      const result = await runJv(["wait", MACHINE_PERSONAL.enrolment, "--json"], env)
      expect(result.code).toBe(EXIT.ok)
      expect(JSON.parse(result.stdout)).toMatchObject({ id: MACHINE_PERSONAL.enrolment, kind: "enrol", status: "active", tenant: MACHINE_PERSONAL.tenant, device: deviceFor(MACHINE_PERSONAL.enrolment) })
      // The finish step renames the pending slot into workspaces/; the record is gone.
      expect(await readConfig(activeSlotPath(root, vault.url, MACHINE_PERSONAL.tenant))).toMatchObject({ tenant: MACHINE_PERSONAL.tenant, workspaceSlug: MACHINE_PERSONAL.slug })
      expect(existsSync(pendingSlot)).toBe(false)
      expect(existsSync(join(activeSlotPath(root, vault.url, MACHINE_PERSONAL.tenant), "enrolment.json"))).toBe(false)
      // Two workspaces now: status lists both, nothing is selected without a
      // name, and each answers (the mock records the activated device under
      // its own workspace).
      const activated = vault.devices.get(deviceFor(MACHINE_PERSONAL.enrolment))
      if (activated) activated.tenant = MACHINE_PERSONAL.tenant
      const both = JSON.parse((await runJv(["status", "--json"], env)).stdout) as { selected: unknown; workspaces: { state: string; workspace: { id: string }; check: { ok: boolean } }[] }
      expect(both.selected).toBeNull()
      expect(both.workspaces.map((w) => [w.state, w.workspace.id, w.check.ok]).sort()).toEqual([["active", MACHINE_NORTHWIND.tenant, true], ["active", MACHINE_PERSONAL.tenant, true]].sort())
      expect(JSON.parse((await runJv(["status", "--json", "--workspace", MACHINE_PERSONAL.slug], env)).stdout)).toMatchObject({ tenant: MACHINE_PERSONAL.tenant })
      expect(JSON.parse((await runJv(["status", "--json", "--workspace", MACHINE_NORTHWIND.slug], env)).stdout)).toMatchObject({ tenant: MACHINE_NORTHWIND.tenant })
    } finally {
      vault.workspace = { id: "tn_mock0000000001", slug: "mock-space", name: "Mock Space" }
      vault.enrolOutcome = { pendingPolls: 2, result: "active" }
    }
  })

  test("enrol resumes the migrated record for the same key and finishes it; enrolling Northwind again is idempotent success", async () => {
    const env = await office()
    vault.enrolments.set(MACHINE_PERSONAL.enrolment, { id: MACHINE_PERSONAL.enrolment, jwk: MACHINE_PERSONAL_JWK, name: "sam-mac-mini", backend: "software", polls: 0, workspace: MACHINE_PERSONAL.slug, owner: { kind: "self" } })
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    vault.workspace = { id: MACHINE_PERSONAL.tenant, slug: MACHINE_PERSONAL.slug, name: MACHINE_PERSONAL.name }
    const posts = vault.seen.filter((c) => c.path === "/v1/enrol").length
    try {
      const result = await runJv(["enrol", "--workspace", MACHINE_PERSONAL.slug, "--name", "sam-mac-mini", "--backend", "software", "--json"], env)
      expect(result.code).toBe(EXIT.ok)
      // The resumed attempt is polled once and the vault says active: finished at once.
      const lines = result.stdout.trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>)
      expect(lines).toHaveLength(1)
      expect(lines[0]).toMatchObject({ status: "active", tenant: MACHINE_PERSONAL.tenant, device: deviceFor(MACHINE_PERSONAL.enrolment), slot: activeSlotPath(root, vault.url, MACHINE_PERSONAL.tenant) })
      // The same key and the same attempt: nothing new was started.
      expect(vault.seen.filter((c) => c.path === "/v1/enrol").length).toBe(posts)
      const again = await runJv(["enrol", "--workspace", MACHINE_NORTHWIND.slug, "--json"], env)
      expect(again.code).toBe(EXIT.ok)
      expect(JSON.parse(again.stdout)).toMatchObject({ status: "active", alreadyEnrolled: true, device: MACHINE_NORTHWIND.device, slot: activeSlotPath(root, vault.url, MACHINE_NORTHWIND.tenant) })
    } finally {
      vault.workspace = { id: "tn_mock0000000001", slug: "mock-space", name: "Mock Space" }
      vault.enrolOutcome = { pendingPolls: 2, result: "active" }
    }
  })
})

// The root is private, and every directory a migration writes
// into or locks in below it is a private directory of this user, checked
// before the journal is committed and before a resumed journal moves
// anything. Each refusal leaves every source and target unchanged.
describe("unsafe roots and destinations", () => {
  async function outsideDir(): Promise<string> {
    const outside = join(dir.path, "outside")
    mkdirSync(outside, { mode: 0o700 })
    return outside
  }

  test("a root other users can open, write or that this user cannot search is refused", async () => {
    await buildMachineFixture(root, ORIGIN)
    const before = snapshot(root)
    for (const mode of [0o777, 0o755, 0o750, 0o500]) {
      chmodSync(root, mode)
      expect(() => assertSafeRoot(root)).toThrow(expect.objectContaining({ code: "key_insecure" }))
      await expect(migrate()).rejects.toMatchObject({ code: "key_insecure" })
      chmodSync(root, 0o700)
      expect(snapshot(root)).toEqual(before)
    }
  })

  for (const linked of ["workspaces", "pending", "locks"]) {
    test(`a linked ${linked}/ is refused before the journal: the keys stay at the root and nothing lands outside it`, async () => {
      await buildMachineFixture(root, ORIGIN)
      const outside = await outsideDir()
      symlinkSync(outside, join(root, linked))
      const before = snapshot(root)
      await expect(migrate()).rejects.toMatchObject({ code: "key_insecure", message: expect.stringContaining(join(root, linked)) })
      expect(snapshot(root)).toEqual(before)
      expect(readdirSync(outside)).toEqual([])
      expect(existsSync(migrationJournalPath(root))).toBe(false)
    })
  }

  test("a linked origin directory, and a loose workspaces/ directory, are refused the same way", async () => {
    await buildMachineFixture(root, ORIGIN)
    const outside = await outsideDir()
    mkdirSync(join(root, "workspaces"), { mode: 0o700 })
    symlinkSync(outside, join(root, "workspaces", "app.mehen.dev"))
    const before = snapshot(root)
    await expect(migrate()).rejects.toMatchObject({ code: "key_insecure" })
    expect(snapshot(root)).toEqual(before)
    expect(readdirSync(outside)).toEqual([])
    rmSync(join(root, "workspaces"), { recursive: true })
    mkdirSync(join(root, "workspaces"), { mode: 0o700 })
    chmodSync(join(root, "workspaces"), 0o777)
    await expect(migrate()).rejects.toMatchObject({ code: "key_insecure" })
    expect(existsSync(join(root, "device-key.se"))).toBe(true)
  })

  test("a destination made unsafe after the journal was written stops the resumed migration before anything moves", async () => {
    await buildMachineFixture(root, ORIGIN)
    await expect(migrate({ at: (point) => { if (point === "journal written") throw new Killed(point) } })).rejects.toBeInstanceOf(Killed)
    const outside = await outsideDir()
    symlinkSync(outside, join(root, "workspaces"))
    await expect(migrate()).rejects.toMatchObject({ code: "key_insecure" })
    expect(readdirSync(outside)).toEqual([])
    expect(existsSync(join(root, "device-key.se"))).toBe(true)
    expect(existsSync(join(root, "config.json"))).toBe(true)
  })
})

// A journal is read only as a private regular file of this user,
// and each of its steps must be a step this root's inventory could have
// written; anything else is refused before anything moves or goes.
describe("untrusted journals", () => {
  function journal(steps: unknown[]): string {
    return JSON.stringify({ v: 1, from: "contexts-v1", startedAt: "2026-10-28T12:00:00.000Z", pid: 1, steps })
  }

  test("a loose, linked or escaping journal is corrupt: status refuses failed, doctor says corrupt, the outside file and the stray stay", async () => {
    await buildMachineFixture(root, ORIGIN)
    const outside = join(dir.path, "outside")
    mkdirSync(outside, { mode: 0o700 })
    const sentinel = join(outside, "sentinel.txt")
    writeFileSync(sentinel, "not to be deleted", { mode: 0o600 })
    const env = { HOME: dir.path, MEHEN_HOME: root }
    const before = snapshot(root)
    const elsewhereTarget = { kind: "slot", source: root, move: "files", files: ["config.json"], identity: { origin: ORIGIN, tenant: MACHINE_NORTHWIND.tenant, device: MACHINE_NORTHWIND.device, backend: "secure-enclave" }, target: join(outside, "slot"), state: "planned" }
    const cases: [string, () => void][] = [
      ["a loose journal", () => { writeFileSync(migrationJournalPath(root), journal([{ id: 0, kind: "delete", source: join(root, "default-context"), state: "planned" }]), { mode: 0o600 }); chmodSync(migrationJournalPath(root), 0o666) }],
      ["a linked journal", () => { const real = join(outside, "journal.json"); writeFileSync(real, journal([{ id: 0, kind: "delete", source: join(root, "default-context"), state: "planned" }]), { mode: 0o600 }); symlinkSync(real, migrationJournalPath(root)) }],
      ["a delete outside the root", () => writeFileSync(migrationJournalPath(root), journal([{ id: 0, kind: "delete", source: sentinel, state: "planned" }]), { mode: 0o600 })],
      ["a delete of a stray", () => writeFileSync(migrationJournalPath(root), journal([{ id: 0, kind: "delete", source: join(root, MACHINE_STRAY), state: "planned" }]), { mode: 0o600 })],
      ["a slot moved outside the root", () => writeFileSync(migrationJournalPath(root), journal([{ id: 0, ...elsewhereTarget }]), { mode: 0o600 })],
      ["a file name that is not a slot's", () => writeFileSync(migrationJournalPath(root), journal([{ id: 0, ...elsewhereTarget, target: activeSlotPath(root, ORIGIN, MACHINE_NORTHWIND.tenant), files: ["../../outside/sentinel.txt"] }]), { mode: 0o600 })],
      ["a source path that climbs out", () => writeFileSync(migrationJournalPath(root), journal([{ id: 0, kind: "delete", source: `${root}/contexts/../../outside/sentinel.txt`, state: "planned" }]), { mode: 0o600 })],
    ]
    for (const [name, plant] of cases) {
      plant()
      const status = await runJv(["status", "--json"], env)
      expect(status.code, name).toBe(EXIT.error)
      expect(JSON.parse(status.stdout), name).toMatchObject({ error: "failed", next: { command: "mehen doctor --json" } })
      const doctor = JSON.parse((await runJv(["doctor", "--json"], env)).stdout) as { migration: unknown; machine: { check: string; status: string; detail: string }[] }
      expect(doctor.migration, name).toBeNull()
      expect(doctor.machine.find((c) => c.check === "migration"), name).toMatchObject({ status: "fail", detail: expect.stringContaining("cannot be read") })
      expect(existsSync(sentinel), name).toBe(true)
      expect(existsSync(join(root, MACHINE_STRAY, "config.json")), name).toBe(true)
      expect(existsSync(join(root, "mehen.json")), name).toBe(false)
      rmSync(migrationJournalPath(root))
      expect(snapshot(root), name).toEqual(before)
    }
  })

  test("a legacy config whose workspace or device cannot name a directory is left where it is, never placed by its identity", async () => {
    mkdirSync(root, { mode: 0o700 })
    await writeConfig(join(root, "contexts", "odd"), { vault: ORIGIN, tenant: "../../escape", device: "dev_odd000000001", backend: "software" })
    const { migrated } = await migrate()
    expect(migrated?.steps).toMatchObject([{ kind: "leave", source: join(root, "contexts", "odd") }])
    expect(existsSync(join(root, "contexts", "odd", "config.json"))).toBe(true)
    expect(existsSync(join(dir.path, "escape"))).toBe(false)
  })
})
