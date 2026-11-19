import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { basename, dirname, join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { type DoctorCheck, type DoctorReport, doctorAll as doctor, guardRows } from "./doctor.ts"
import { MOCK_TENANT, MockVault } from "../testing/mock-vault.ts"
import { runJv, tempDir } from "../testing/run-mehen.ts"

let vault: MockVault
let dir: { path: string; remove(): Promise<void> }
let home: { path: string; remove(): Promise<void> }
let env: Record<string, string>

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  home = await tempDir()
  // HOME and PATH name no agent, so the skill rows read no real machine.
  env = { MEHEN_DL_BASE: "http://127.0.0.1:1/dl", MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url, MEHEN_SESSION: "pi-4f2a", HOME: home.path, PATH: "/usr/bin:/bin" }
  vault.overrides.clear()
  vault.frozen = false
  vault.healthz = () => Response.json({ ok: true }, { headers: { date: new Date().toUTCString() } })
})
afterEach(async () => {
  await dir.remove()
  await home.remove()
})

// Every check in report order: the machine, the session, each origin, each slot.
function checksOf(report: DoctorReport): DoctorCheck[] {
  return [...report.machine, report.session, ...report.origins.flatMap((o) => o.checks), ...report.workspaces.flatMap((w) => w.checks)]
}

function find(report: DoctorReport, name: string): DoctorCheck | undefined {
  return checksOf(report).find((c) => c.check === name)
}

function statusOf(report: DoctorReport): Record<string, string> {
  return Object.fromEntries(checksOf(report).map((c) => [c.check, c.status]))
}

describe("mehen doctor", () => {
  test("an enrolled machine with a sane clock and a session label passes every check and exits 0", async () => {
    const device = await vault.enrolSoftware(dir.path)
    const result = await runJv(["doctor", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const report = JSON.parse(result.stdout) as DoctorReport
    expect(report).toMatchObject({ ok: true, next: null, exitCode: 0, strays: [], migration: null, origins: [{ origin: vault.url }], workspaces: [{ slot: vault.slotDir(dir.path), state: "active", workspace: { id: MOCK_TENANT, slug: "mock-space", name: "Mock Space" } }] })
    expect(statusOf(report)).toEqual({ home: "ok", migration: "ok", vault_url: "ok", on_path: "skipped", update: "skipped", skill: "ok", guard: "skipped", enrolled: "ok", key: "ok", session: "ok", reachable: "ok", clock: "ok", identity: "ok", frozen: "ok", pending: "ok" })
    expect(report.cli).toMatchObject({ installed: null, previous: null, highestSeen: null, holdBelow: null, pending: null, check: null, vault: {}, lastUpdate: null })
    // What a server started now would decide; a source run is a development build.
    expect(report.cli.mcpHandover).toEqual({ handover: "off", reason: "a development build" })
    expect(Object.hasOwn(report.cli, "mcp")).toBe(false)
    expect(find(report, "identity")?.detail).toContain(device)
    const human = await runJv(["doctor"], env)
    expect(human.code).toBe(EXIT.ok)
    expect(human.stdout).toStartWith("mehen doctor: this machine can use the vault\n")
    expect(human.stdout).toContain("  ok    identity   The vault accepts this machine as test-machine")
  })

  test("before enrolment: fails enrolled with mehen enrol as next, still checks the vault and the clock, and signs nothing", async () => {
    const before = vault.seen.length
    const result = await runJv(["doctor", "--json"], env)
    expect(result.code).toBe(EXIT.identity)
    const report = JSON.parse(result.stdout) as DoctorReport
    expect(report.ok).toBe(false)
    expect(statusOf(report)).toMatchObject({ enrolled: "fail", reachable: "ok", clock: "ok" })
    expect(report.origins.map((o) => o.origin)).toEqual([vault.url])
    expect(report.workspaces).toEqual([])
    expect(report.next).toEqual({ command: "mehen enrol --workspace <slug> --json", say: "Run `mehen enrol --workspace <slug> --json` on this machine (the slug is on the workspace's Connect an agent page) and accept it in the browser with your passkey. If you cannot run commands, ask the human to run this in a terminal and open the link it prints." })
    expect(vault.seen.length).toBe(before)
  })

  test("a clock more than 60 s off fails with proof_invalid and says to fix the clock; 30 s off is a warning", async () => {
    await vault.enrolSoftware(dir.path)
    vault.healthz = () => Response.json({ ok: true }, { headers: { date: new Date(Date.now() - 5 * 60_000).toUTCString() } })
    const far = await doctor(env)
    const clock = find(far, "clock")
    expect(clock).toMatchObject({ status: "fail", error: "proof_invalid" })
    expect(clock?.detail).toMatch(/clock is 30\d s ahead of the vault/)
    expect(far.exitCode).toBe(EXIT.identity)
    expect(far.next?.say).toContain("Set this machine's clock")

    vault.healthz = () => Response.json({ ok: true }, { headers: { date: new Date(Date.now() + 45_000).toUTCString() } })
    const near = await doctor(env)
    expect(find(near, "clock")).toMatchObject({ status: "warn" })
    expect(near.ok).toBe(true)
    expect(near.exitCode).toBe(EXIT.ok)
  })

  test("an unreachable vault fails reachable with exit 7 and skips what needs it", async () => {
    await vault.enrolSoftware(dir.path, { config: { vault: "http://127.0.0.1:1" } })
    const result = await runJv(["doctor", "--json"], { ...env, MEHEN_VAULT_URL: "http://127.0.0.1:1" })
    expect(result.code).toBe(EXIT.transient)
    const report = JSON.parse(result.stdout) as DoctorReport
    expect(statusOf(report)).toMatchObject({ vault_url: "ok", reachable: "fail", clock: "skipped", identity: "skipped" })
    expect(report.next?.say).toContain("Check the network connection")
  })

  // A local origin or key-scope disagreement refuses before any
  // signature or request, to any host; the local checks are still reported.
  test("a MEHEN_VAULT_URL that is not the enrolment's origin refuses as workspace_mismatch: no probe, no signature, nothing sent anywhere", async () => {
    await vault.enrolSoftware(dir.path)
    const before = vault.seen.length
    let probes = 0
    const probe = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => { probes += 1; return Response.json({ ok: true }) } })
    try {
      const result = await runJv(["doctor", "--json"], { ...env, MEHEN_VAULT_URL: `http://127.0.0.1:${probe.port}` })
      expect(result.code).toBe(EXIT.usage)
      const report = JSON.parse(result.stdout) as DoctorReport
      expect(statusOf(report)).toMatchObject({ enrolled: "fail", key: "skipped", identity: "skipped", frozen: "skipped" })
      // No origin is probed: the slot refused locally and no new enrolment is in question.
      expect(report.origins).toEqual([])
      expect(find(report, "enrolled")).toMatchObject({ error: "workspace_mismatch" })
      expect(report.next?.say).toContain("Unset MEHEN_VAULT_URL")
      expect(vault.seen.length).toBe(before)
      expect(probes).toBe(0)
    } finally {
      probe.stop(true)
    }
  })

  test("a key scope naming another workspace or origin refuses before the key is read: key fails, nothing is signed or sent", async () => {
    await vault.enrolSoftware(dir.path)
    for (const scope of [{ vault: vault.url, tenant: "tn_other000000001" }, { vault: "https://other.example", tenant: MOCK_TENANT }]) {
      await Bun.write(join(vault.slotDir(dir.path), "device-key.scope.json"), `${JSON.stringify(scope)}\n`)
      const before = vault.seen.length
      const result = await runJv(["doctor", "--json"], env)
      expect(result.code).toBe(EXIT.usage)
      const report = JSON.parse(result.stdout) as DoctorReport
      expect(statusOf(report)).toMatchObject({ enrolled: "ok", key: "fail", identity: "skipped", frozen: "skipped" })
      expect(report.origins).toEqual([])
      expect(find(report, "key")).toMatchObject({ error: "workspace_mismatch" })
      expect(vault.seen.length).toBe(before)
    }
  })

  test("a refused context selection (an unbound manifest under two contexts) probes nothing", async () => {
    const home = await tempDir()
    const repo = await tempDir()
    try {
      await vault.enrolSoftware(join(home.path, ".config", "mehen"))
      await vault.enrolSoftware(join(home.path, ".config", "mehen"), { config: { tenant: "tn_second00000001", workspaceSlug: "second", workspaceName: "Second" } })
      await Bun.write(join(repo.path, "mehen.toml"), 'project = "prj_1"\n')
      const before = vault.seen.length
      const result = await runJv(["doctor", "--json"], { HOME: home.path, MEHEN_CONFIG_DIR: "" }, undefined, repo.path)
      expect(result.code).toBe(EXIT.usage)
      const report = JSON.parse(result.stdout) as DoctorReport
      expect(report.machine.find((c) => c.check === "enrolled")).toMatchObject({ status: "fail", error: "workspace_unbound" })
      expect(report.origins).toEqual([])
      expect(report.workspaces.map((w) => w.checks.find((c) => c.check === "identity")?.status)).toEqual(["skipped", "skipped"])
      expect(vault.seen.length).toBe(before)
    } finally {
      await home.remove()
      await repo.remove()
    }
  })

  test("a revoked device fails identity with exit 6 and the vault's own next step", async () => {
    const device = await vault.enrolSoftware(dir.path)
    const record = vault.devices.get(device)
    if (record) record.revoked = true
    const result = await runJv(["doctor", "--json"], env)
    expect(result.code).toBe(EXIT.identity)
    const report = JSON.parse(result.stdout) as DoctorReport
    expect(find(report, "identity")).toMatchObject({ status: "fail", error: "device_revoked" })
    expect(report.next).toEqual({ command: "mehen enrol", say: "Enrol again." })
  })

  test("a key other users can read fails the key check with its chmod fix and never signs with it", async () => {
    await vault.enrolSoftware(dir.path)
    await Bun.$`chmod 644 ${join(vault.slotDir(dir.path), "device-key.json")}`
    const before = vault.seen.length
    const report = await doctor(env)
    expect(find(report, "key")).toMatchObject({ status: "fail", error: "key_insecure" })
    expect(find(report, "identity")?.status).toBe("skipped")
    expect(report.next?.command).toStartWith("chmod 600 ")
    expect(report.exitCode).toBe(EXIT.identity)
    expect(vault.seen.length).toBe(before)
  })

  test("no MEHEN_SESSION is a warning that says to set it; an invalid one fails as usage", async () => {
    await vault.enrolSoftware(dir.path)
    const { MEHEN_SESSION: _, ...without } = env
    const unset = await doctor(without)
    expect(unset.ok).toBe(true)
    expect(find(unset, "session")?.status).toBe("warn")
    expect(unset.next?.say).toContain("Set MEHEN_SESSION")
    const bad = await doctor({ ...env, MEHEN_SESSION: "has spaces" })
    expect(find(bad, "session")).toMatchObject({ status: "fail", error: "usage" })
    expect(bad.exitCode).toBe(EXIT.usage)
  })

  // Codex's macOS sandbox: the enrolled enclave key is fine, this process cannot reach it.
  test("an enclave key the helper cannot reach fails identity saying to run outside the sandbox or use the MCP tools, not to enrol again", async () => {
    const { mkdir } = await import("node:fs/promises")
    const { fakeHelper } = await import("../testing/fake-mehen-se.ts")
    const { createDeviceKey } = await import("../device-key.ts")
    await vault.enrolSoftware(dir.path, { config: { backend: "secure-enclave" } })
    await mkdir(join(home.path, "ok"))
    await createDeviceKey(vault.slotDir(dir.path), "secure-enclave", { MEHEN_SE_PATH: await fakeHelper(join(home.path, "ok")) }, { vault: vault.url, tenant: MOCK_TENANT })
    const report = await doctor({ ...env, MEHEN_SE_PATH: await fakeHelper(home.path, { unreachable: true }) })
    expect(find(report, "key")?.status).toBe("ok")
    const identity = find(report, "identity")
    expect([identity?.status, identity?.error]).toEqual(["fail", "helper_failed"])
    expect(identity?.next?.say).toContain("do not enrol again")
    expect(report.next).toEqual(identity?.next ?? null)
    expect(report.next?.command).toBeUndefined()
  })

  test("a frozen tenant fails with exit 4 and says to tell the human", async () => {
    await vault.enrolSoftware(dir.path)
    vault.frozen = true
    const report = await doctor(env)
    expect(find(report, "frozen")).toMatchObject({ status: "fail", error: "frozen" })
    expect(report.exitCode).toBe(EXIT.human)
  })

  test("is listed in mehen --help and takes no arguments", async () => {
    expect((await runJv(["--help"], env)).stdout).toMatch(/^ {2}doctor\s+check in one go/m)
    expect((await runJv(["doctor", "extra"], env)).code).toBe(EXIT.usage)
  })
})

// The advisory release lookup and its update-check.json cache are gone:
// doctor asks no release service and writes nothing;
// the updater's update row arrives through install-state.ts.
test("doctor asks no release service, carries no update field and writes nothing", async () => {
  let asked = 0
  const releases = Bun.serve({ port: 0, fetch: () => { asked += 1; return Response.json({}) } })
  try {
    await vault.enrolSoftware(dir.path)
    const { readdirSync } = await import("node:fs")
    const before = readdirSync(dir.path).sort()
    const result = await runJv(["doctor", "--json"], { ...env, MEHEN_DL_BASE: `http://127.0.0.1:${releases.port}/dl` })
    expect(result.code).toBe(EXIT.ok)
    const report = JSON.parse(result.stdout) as Record<string, unknown>
    expect(Object.keys(report).sort()).toEqual(["cli", "exitCode", "machine", "migration", "next", "ok", "origins", "session", "strays", "workspaces"])
    expect(asked).toBe(0)
    expect(readdirSync(dir.path).sort()).toEqual(before)
  } finally { releases.stop(true) }
})

// One skill row per folder: mehen's copy current or stale, a symlinked or
// foreign copy against this build's text, none where an installed agent
// reads the folder.
test("the skill rows: current, stale, external same or different, and missing only where an installed agent reads the folder", async () => {
  const { mkdir, symlink, writeFile } = await import("node:fs/promises")
  const { stampedSkill } = await import("../setup/skills.ts")
  const { VERSION } = await import("../version.ts")
  const { default: published } = await import("../../../../skills/mehen/SKILL.md", { with: { type: "text" } })
  const claude = join(home.path, ".claude/skills/mehen/SKILL.md"), shared = join(home.path, ".agents/skills/mehen/SKILL.md")
  const rows = async () => (await doctor(env)).machine.filter((c) => c.check === "skill")
  expect(await rows()).toEqual([
    { check: "skill", status: "ok", detail: `${claude}: none, and no agent found here reads this folder.` },
    { check: "skill", status: "ok", detail: `${shared}: none, and no agent found here reads this folder.` },
  ])
  await mkdir(join(home.path, ".codex"))
  expect((await rows())[1]).toEqual({ check: "skill", status: "warn", detail: `${shared}: none, but codex reads this folder.`, next: { command: "mehen setup --json", say: "Run `mehen setup --json` to add mehen's skill for codex." } })
  await mkdir(dirname(shared), { recursive: true })
  await writeFile(shared, stampedSkill("0.0.1"))
  await vault.enrolSoftware(dir.path)
  const stale = await doctor(env)
  expect(stale.machine.filter((c) => c.check === "skill")[1]).toMatchObject({ status: "warn", detail: `${shared}: mehen's skill from 0.0.1; this CLI is ${VERSION}.`, next: { command: "mehen setup --json" } })
  expect(stale).toMatchObject({ ok: true, next: { command: "mehen setup --json", say: expect.stringContaining(shared) } })
  await writeFile(shared, stampedSkill())
  expect((await rows())[1]).toEqual({ check: "skill", status: "ok", detail: `${shared}: mehen ${VERSION}'s skill.` })
  await writeFile(shared, published)
  expect((await rows())[1]?.status).toBe("ok")
  await writeFile(shared, "a hand-made skill")
  expect((await rows())[1]).toMatchObject({ status: "warn", next: { say: `The skill at ${shared} is not managed by mehen and differs from mehen ${VERSION}'s skill; its owner should refresh it.` } })
  // The Office's ~/.claude/skills/mehen is a deliberate symlink into a skills repo.
  const kept = join(home.path, "skills-repo/mehen")
  await mkdir(kept, { recursive: true })
  await writeFile(join(kept, "SKILL.md"), published)
  await mkdir(dirname(dirname(claude)), { recursive: true })
  await symlink(kept, dirname(claude))
  expect((await rows())[0]).toEqual({ check: "skill", status: "ok", detail: `${claude}: a symlink to ${kept}, the same text as mehen ${VERSION}'s skill.` })
  await writeFile(join(kept, "SKILL.md"), stampedSkill("0.0.1"))
  expect((await rows())[0]).toMatchObject({ status: "warn", next: { say: `The skill at ${claude} (a symlink to ${kept}) is not managed by mehen and differs from mehen ${VERSION}'s skill; its owner should refresh ${kept}.` } })
})

// The installation rows: on_path and update come from
// the state next to the binary, read without the lock, and doctor writes
// nothing there either.
test("an installed mehen: on_path names the absolute binary off PATH; update warns on an unfinished journal and on skills that failed", async () => {
  const { mkdtemp, mkdir, readdir, writeFile } = await import("node:fs/promises")
  const { realpathSync } = await import("node:fs")
  const { tmpdir } = await import("node:os")
  const bin = realpathSync(await mkdtemp(join(tmpdir(), "mehen-doctor-bin-")))
  const binary = join(bin, "mehen")
  await writeFile(binary, "#!/bin/sh\n", { mode: 0o755 })
  const { freshInstallState, installation, writeInstallState } = await import("../install-state.ts")
  const state = freshInstallState()
  state.pending = { target: { version: "9.0.0", commit: "abc", sha256: "a".repeat(64), size: 1, at: "2026-10-28T00:00:00Z", by: "auto", keyId: "rk", manifestSha256: null, manifest: null }, previousSha256: "b".repeat(64), steps: ["record"], since: "2026-10-28T00:00:00Z" }
  await writeInstallState(installation(binary), state)
  // Automatic updating off, so no background child writes the log here.
  const installed = { ...env, MEHEN_SELF_EXECUTABLE: binary, PATH: "/usr/bin:/bin", MEHEN_NO_AUTO_UPDATE: "1" }
  let report = JSON.parse((await runJv(["doctor", "--json"], installed)).stdout) as DoctorReport
  expect(find(report, "on_path")).toMatchObject({ status: "warn", detail: expect.stringContaining(binary) })
  expect(find(report, "update")).toMatchObject({ status: "warn", detail: expect.stringContaining("An update to 9.0.0 is unfinished") })
  expect(report.cli.pending?.target.version).toBe("9.0.0")
  expect(report.cli.mcpHandover).toEqual({ handover: "off", reason: "MEHEN_NO_AUTO_UPDATE is set" })
  state.pending = null
  state.lastUpdate = { at: "2026-10-28T00:00:00Z", from: "0.3.0", to: "0.3.1", result: "ok_skills_failed", reason: "1 skill could not be refreshed", skills: [{ path: "/s/SKILL.md", status: "failed", reason: "EACCES" }] }
  await writeInstallState(installation(binary), state)
  report = JSON.parse((await runJv(["doctor", "--json"], { ...installed, PATH: `/usr/bin:${bin}` })).stdout) as DoctorReport
  expect(find(report, "on_path")).toMatchObject({ status: "ok" })
  expect(find(report, "update")).toMatchObject({ status: "warn", detail: expect.stringContaining("/s/SKILL.md (EACCES)"), next: { command: "mehen setup --json" } })
  await mkdir(join(bin, ".mehen.update.lock"))
  await writeFile(join(bin, ".mehen.update.lock/owner.json"), JSON.stringify({ pid: process.pid, boot: "", at: "2026-01-01T00:00:00Z", by: "auto" }))
  report = JSON.parse((await runJv(["doctor", "--json"], installed)).stdout) as DoctorReport
  expect(find(report, "update")).toMatchObject({ status: "warn", detail: `An update has been running since 2026-01-01T00:00:00Z (pid ${process.pid}).` })
  // Reported, never taken: the lock and the state are as they were.
  expect((await readdir(bin)).sort()).toEqual([".mehen.update.json", ".mehen.update.lock", "mehen"])
})

// A malformed journal and an ownerless lock read as
// healthy. Doctor reports each, and an invalid lock path, naming what a human
// must inspect; it takes, repairs and deletes nothing. An ownerless lock is
// mehen's to take over after the grace period, so doctor says so, and past
// it reports no lock at all.
test("doctor names a malformed journal, a lock with no readable owner, an unfinished reclamation and a lock path that is not a directory", async () => {
  const { mkdtemp, mkdir, readdir, readFile, rm, utimes, writeFile } = await import("node:fs/promises")
  const { realpathSync } = await import("node:fs")
  const { tmpdir } = await import("node:os")
  const bin = realpathSync(await mkdtemp(join(tmpdir(), "mehen-doctor-bin-")))
  const binary = join(bin, "mehen")
  await writeFile(binary, "#!/bin/sh\n", { mode: 0o755 })
  const installed = { ...env, MEHEN_SELF_EXECUTABLE: binary, MEHEN_NO_AUTO_UPDATE: "1" }
  const row = async () => find(JSON.parse((await runJv(["doctor", "--json"], installed)).stdout) as DoctorReport, "update")
  try {
    const malformed = JSON.stringify({ v: 1, installed: null, previous: null, highestSeen: null, holdBelow: null, pending: { target: "nonsense" }, check: null, vault: {}, lastUpdate: null })
    await writeFile(join(bin, ".mehen.update.json"), malformed)
    expect(await row()).toMatchObject({ status: "warn", detail: expect.stringContaining(`The installation state ${join(bin, ".mehen.update.json")} cannot be read`), next: { say: expect.stringContaining("an agent must not rerun the installer") } })
    expect(await readFile(join(bin, ".mehen.update.json"), "utf8")).toBe(malformed)
    await rm(join(bin, ".mehen.update.json"))
    const lock = join(bin, ".mehen.update.lock")
    await mkdir(lock)
    expect(await row()).toEqual({ check: "update", status: "warn", detail: `The installation lock ${lock} has no readable owner; mehen takes it over once it has stayed so for 10 minutes.`, next: { say: `Leave ${lock} alone; mehen takes it over itself once it has had no readable owner for 10 minutes.` } })
    const past = new Date(Date.now() - 11 * 60_000)
    await utimes(lock, past, past)
    expect(await row()).toMatchObject({ status: "ok" })
    expect(await readdir(lock)).toEqual([])
    await mkdir(join(lock, "reap"))
    await utimes(join(lock, "reap"), past, past)
    await utimes(lock, past, past)
    expect(await row()).toEqual({ check: "update", status: "warn", detail: `A reclamation of the installation lock ${lock} did not finish; the lock is held until a human inspects it.`, next: { say: `Ask the human to inspect ${lock}; mehen does not take it over or remove it.` } })
    await writeFile(join(lock, "owner.json"), JSON.stringify({ pid: 999_999, boot: "", at: "2026-10-28T00:00:00Z", by: "auto" }))
    expect(await row()).toMatchObject({ status: "warn", detail: expect.stringContaining("did not finish") })
    expect((await readdir(lock)).sort()).toEqual(["owner.json", "reap"])
    await rm(lock, { recursive: true })
    await writeFile(lock, "not a directory")
    expect(await row()).toMatchObject({ status: "warn", detail: expect.stringContaining("is not a lock directory"), next: { say: `Ask the human to inspect ${lock}; mehen does not take it over or remove it.` } })
    expect(await readFile(lock, "utf8")).toBe("not a directory")
  } finally {
    await rm(bin, { recursive: true, force: true })
  }
})

// Every file and directory under `root`, for "nothing was written or deleted".
async function tree(root: string): Promise<string[]> {
  const { readdir } = await import("node:fs/promises")
  return (await readdir(root, { recursive: true })).map(String).sort()
}

describe("mehen doctor across the allowed set", () => {
  const SECOND = { id: "tn_second00000001", slug: "second-space", name: "Second Space" }

  test("every slot is checked, each origin probed once, a pending and a corrupt slot reported, strays named; nothing is written or deleted", async () => {
    const { mkdirSync } = await import("node:fs")
    const first = await vault.enrolSoftware(dir.path)
    const second = await vault.enrolSoftware(dir.path, { config: { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name } })
    const enrol = await runJv(["enrol", "--workspace", "personal", "--json"], env)
    const enrolment = (JSON.parse(enrol.stdout) as { enrolment: string }).enrolment
    const corrupt = vault.slotDir(dir.path, "tn_broken0000001")
    mkdirSync(corrupt, { recursive: true, mode: 0o700 })
    // A migrated root (the marker written) with a hand-made directory beside the slots.
    const { writeFileSync } = await import("node:fs")
    writeFileSync(join(dir.path, "mehen.json"), JSON.stringify({ layout: 2, migratedAt: "2026-10-28T12:00:00.000Z", from: null }), { mode: 0o600 })
    const revokedByHand = join(dir.path, "revoked-dev_hrNjawWDCq8M7BKe1-20261028")
    mkdirSync(revokedByHand, { mode: 0o700 })
    const loose = vault.slotDir(dir.path, "tn_loose00000001")
    mkdirSync(loose, { mode: 0o755 })
    const record = vault.devices.get(second)
    if (record) record.revoked = true
    let probes = 0
    const before = await tree(dir.path)
    const report = await doctor(env, { fetch: (request) => { probes += 1; return fetch(request) } })
    // One origin, probed once (plus one GET /v1/me per active slot).
    expect(report.origins.map((o) => [o.origin, o.checks.map((c) => [c.check, c.status])])).toEqual([[vault.url, [["reachable", "ok"], ["clock", "ok"]]]])
    expect(probes).toBe(3)
    expect(report.workspaces.map((w) => [w.state, w.slot])).toEqual([["active", vault.slotDir(dir.path)], ["active", vault.slotDir(dir.path, SECOND.id)], ["pending", join(dir.path, "pending", basename(dirname(corrupt)), "personal")], ["corrupt", corrupt]])
    const [a, b, waiting, broken] = report.workspaces
    expect(a?.checks.find((c) => c.check === "identity")).toMatchObject({ status: "ok", detail: expect.stringContaining(first) })
    expect(b?.checks.find((c) => c.check === "identity")).toMatchObject({ status: "fail", error: "device_revoked" })
    expect(broken?.checks).toEqual([{ check: "enrolled", status: "warn", detail: expect.stringContaining("not_a_slot"), next: { command: `mehen workspace forget --slot ${corrupt}`, say: expect.any(String) } }])
    expect(waiting?.checks[0]).toMatchObject({ check: "enrolled", status: "warn", next: { command: `mehen wait ${enrolment}` } })
    expect(report.strays).toEqual([
      { path: revokedByHand, detail: "not a slot; mehen does not read or delete it; remove it yourself if you know what it is" },
      { path: loose, detail: expect.stringContaining("not a directory private to this user") },
    ])
    // The revoked device is the first failure: exit 6 with the vault's own next step.
    expect(report).toMatchObject({ ok: false, exitCode: EXIT.identity, next: { command: "mehen enrol", say: "Enrol again." }, migration: null })
    expect(await tree(dir.path)).toEqual(before)
    const human = await runJv(["doctor"], env)
    expect(human.stdout).toContain(`stray: ${revokedByHand}: not a slot; mehen does not read or delete it; remove it yourself if you know what it is`)
    expect(human.stdout).toContain(`Second Space (second-space): ${vault.slotDir(dir.path, SECOND.id)}`)
  })

  test("a pending slot alone fails enrolled with the wait step, not the enrol step", async () => {
    const enrol = await runJv(["enrol", "--workspace", "personal", "--json"], env)
    const enrolment = (JSON.parse(enrol.stdout) as { enrolment: string }).enrolment
    const result = await runJv(["doctor", "--json"], env)
    expect(result.code).toBe(EXIT.identity)
    const report = JSON.parse(result.stdout) as DoctorReport
    expect(report.machine.find((c) => c.check === "enrolled")).toMatchObject({ status: "fail", error: "unauthenticated", next: { command: `mehen wait ${enrolment}` } })
    expect(report.origins.map((o) => o.origin)).toEqual([vault.url])
  })

  test("a legacy root and a stuck journal are reported without migrating: no slot read, nothing probed, nothing moved", async () => {
    const { writeConfig } = await import("../config.ts")
    await writeConfig(dir.path, { vault: vault.url, tenant: "tn_legacy00000001", device: "dev_legacy0000001", backend: "software" })
    const before = await tree(dir.path)
    let probes = 0
    const legacy = await doctor(env, { fetch: (request) => { probes += 1; return fetch(request) } })
    expect(legacy.machine.find((c) => c.check === "migration")).toMatchObject({ status: "warn", detail: `${dir.path} is not migrated yet; the next command migrates it.` })
    expect(legacy).toMatchObject({ migration: null, workspaces: [], origins: [], strays: [] })
    expect(probes).toBe(0)
    expect(await tree(dir.path)).toEqual(before)
    // A journal whose rename has neither end on disk cannot continue: stuck.
    const { writeFileSync } = await import("node:fs")
    const identity = { origin: vault.url, tenant: "tn_stuck000000001", device: "dev_stuck00000001", backend: "software" }
    const journal = { v: 1, from: "contexts-v1", startedAt: "2026-10-28T12:00:00.000Z", pid: 1, steps: [{ id: 0, kind: "slot", source: join(dir.path, "contexts", "gone"), move: "rename", files: [], identity, target: vault.slotDir(dir.path, identity.tenant), state: "moving" }] }
    writeFileSync(join(dir.path, "migration.json"), JSON.stringify(journal), { mode: 0o600 })
    const stuckBefore = await tree(dir.path)
    const result = await runJv(["doctor", "--json"], env)
    expect(result.code).toBe(EXIT.error)
    const stuck = JSON.parse(result.stdout) as DoctorReport
    expect(stuck.migration).toEqual({ ...journal, omitted: 0 } as unknown as DoctorReport["migration"])
    expect(stuck.machine.find((c) => c.check === "migration")).toMatchObject({ status: "fail", error: "failed", detail: expect.stringContaining("step 0 cannot continue") })
    expect(stuck).toMatchObject({ workspaces: [], origins: [], next: { say: expect.stringContaining("journal") } })
    expect(await tree(dir.path)).toEqual(stuckBefore)
    expect((await runJv(["doctor"], env)).stdout).toContain("migration: an unfinished journal from 2026-10-28T12:00:00.000Z (pid 1) with 1 step;")
  })
})

// Doctor publishes an allowlisted projection of the journal, never
// the object read from disk: no enrolment code, link or key, and nothing the
// journal carries beyond the published fields; the journal stays as it was.
describe("doctor's migration journal projection", () => {
  test("a pending step's code, link and key and every unknown field stay out of JSON and text; recovery facts stay; the journal bytes are unchanged", async () => {
    const { writeFileSync, readFileSync, mkdirSync } = await import("node:fs")
    const jwk = { kty: "EC", crv: "P-256", x: "Xq3vZ9jLmN2pR7sT4uW6yA8bC1dE5fG0hI2kJ4lM6nO", y: "Yr4wA0kMnO3qS8tU5vX7zB9cD2eF6gH1iJ3lK5mN7pQ" }
    const record = { v: 1, state: "pending", id: "enr_journalled01", code: "ABCD2345", url: `${vault.url}/w/personal/e/ABCD2345`, origin: vault.url, intent: { workspace: "personal", team: null }, name: "n", backend: "software", jwk: { ...jwk, unknownInKey: "SENTINEL-KEY" }, session: null, startedAt: "2026-10-28T12:00:00.000Z", expiresAt: "2026-10-28T12:15:00.000Z", hardExpiresAt: null, renewals: 0, legacy: true, claimed: false, unknownInRecord: "SENTINEL-RECORD" }
    const step = { id: 0, kind: "pending", source: dir.path, files: ["device-key.json"], record, target: join(dir.path, "pending", basename(dirname(vault.slotDir(dir.path))), "personal"), state: "moving", unknownInStep: { nested: "SENTINEL-STEP" } }
    const journal = { v: 1, from: "contexts-v1", startedAt: "2026-10-28T12:00:00.000Z", pid: 1, steps: [step], unknownAtTop: "SENTINEL-TOP" }
    mkdirSync(dir.path, { recursive: true, mode: 0o700 })
    writeFileSync(join(dir.path, "migration.json"), JSON.stringify(journal), { mode: 0o600 })
    const bytes = readFileSync(join(dir.path, "migration.json"))
    const result = await runJv(["doctor", "--json"], { ...env, MEHEN_WORKSPACES: "" })
    const human = await runJv(["doctor"], { ...env, MEHEN_WORKSPACES: "" })
    const report = JSON.parse(result.stdout) as DoctorReport
    expect(report.migration).toEqual({ v: 1, from: "contexts-v1", startedAt: "2026-10-28T12:00:00.000Z", pid: 1, omitted: 0, steps: [{ id: 0, kind: "pending", source: dir.path, files: ["device-key.json"], enrolment: { id: "enr_journalled01", origin: vault.url, intent: { workspace: "personal", team: null } }, target: step.target, state: "moving" }] })
    for (const text of [result.stdout, result.stderr, human.stdout, human.stderr]) {
      for (const leak of ["ABCD2345", jwk.x, jwk.y, "SENTINEL"]) expect(text).not.toContain(leak)
    }
    expect(readFileSync(join(dir.path, "migration.json")).equals(bytes)).toBe(true)
  })

  test("nothing is read through a root the safety check refuses: the journal there is not projected", async () => {
    const { writeFileSync, mkdirSync, chmodSync } = await import("node:fs")
    const open = join(dir.path, "group-writable")
    mkdirSync(open, { mode: 0o700 })
    chmodSync(open, 0o770)
    const root = join(open, "mehen")
    mkdirSync(root, { mode: 0o700 })
    writeFileSync(join(root, "migration.json"), JSON.stringify({ v: 1, from: "contexts-v1", startedAt: "2026-10-28T12:00:00.000Z", pid: 1, steps: [] }), { mode: 0o600 })
    const report = await doctor({ MEHEN_HOME: root, MEHEN_VAULT_URL: vault.url })
    expect(report.machine.find((c) => c.check === "migration")).toMatchObject({ status: "fail", error: "key_insecure" })
    expect(report.migration).toBeNull()
  })
})

// The guard rows: one per agent set up here that runs the hooks, from a dry
// run of mehen guard install, so doctor writes nothing.
test("an installed mehen: a guard row for each of Claude Code, pi, Cursor and Codex set up here, missing, on, then off", async () => {
  const { mkdir, readdir } = await import("node:fs/promises")
  const binary = "/opt/mehen/bin/mehen"
  for (const agent of [".claude", ".pi", ".cursor", ".codex"]) await mkdir(join(home.path, agent))
  const installed = { ...env, MEHEN_SELF_EXECUTABLE: binary, MEHEN_NO_AUTO_UPDATE: "1" }
  const rows = async (extra: Record<string, string> = {}) => (JSON.parse((await runJv(["doctor", "--json"], { ...installed, ...extra })).stdout) as DoctorReport).machine.filter((c) => c.check === "guard")
  const before = await rows()
  expect(before.map((r) => [r.status, r.detail.split(":")[0]])).toEqual([["warn", "Claude Code"], ["warn", "pi"], ["warn", "Cursor"], ["warn", "Codex"]])
  expect(before[2]).toMatchObject({ detail: expect.stringContaining("no guard hooks"), next: { command: "mehen guard install --json" } })
  expect(await readdir(join(home.path, ".cursor"))).toEqual([])
  expect((await runJv(["guard", "install", "--json"], installed)).code).toBe(0)
  const on = await rows()
  expect(on.map((r) => r.status)).toEqual(["ok", "ok", "ok", "ok"])
  expect(on[2]?.detail).toBe(`Cursor: guard on (block) in ${join(home.path, ".cursor", "hooks.json")}.`)
  expect(on[3]?.detail).toContain("once they are trusted in /hooks")
  const off = await rows({ MEHEN_GUARD: "off" })
  expect(off.map((r) => r.status)).toEqual(["warn", "warn", "warn", "warn"])
  expect(off[0]?.next).toMatchObject({ command: "mehen guard block" })
})

test("guard rows: no agent set up is one ok row; a file the guard could not read is a warning with its reason", () => {
  expect(guardRows([{ agent: "cursor", status: "skipped", file: "/h/.cursor/hooks.json", absent: true, reason: "no ~/.cursor folder" }], "block")).toEqual([{ check: "guard", status: "ok", detail: expect.stringContaining("No agent that runs the guard hooks") }])
  expect(guardRows([{ agent: "codex", status: "skipped", file: "/h/.codex/hooks.json", reason: "Malformed agent settings." }], "block")).toEqual([{ check: "guard", status: "warn", detail: "Codex: Malformed agent settings." }])
  expect(guardRows([{ agent: "codex", status: "updated", file: "/h/.codex/hooks.json" }], "warn")[0]?.next?.say).toContain("/hooks")
})
