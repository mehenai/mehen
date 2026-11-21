import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { realpathSync } from "node:fs"
import { mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, utimes, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { FRESH_INSTALL_STATE, HUMAN_REPAIR, OWNERLESS_GRACE_MS, RECLAIM_GUARD, updateDoctorCheck, autoUpdateMode, bootId, cliState, selfInstallKind, selfLaunchPath, freshInstallState, installation, mcpHandoverDecision, lockHolder, observeLock, onPathCheck, reclaimStale, readInstallState, readSettings, recordVaultAdvice, withInstallLock, writeInstallState } from "./install-state.ts"
import { brewPrefix } from "./testing/brew-prefix.ts"
import { BUILD_COMMIT, BUILD_KIND, VERSION } from "./version.ts"

let root: string
beforeEach(async () => {
  root = realpathSync(await mkdtemp(join(tmpdir(), "mehen-install-state-")))
})
afterEach(async () => rm(root, { recursive: true, force: true }))
const home = () => ({ HOME: root, MEHEN_HOME: join(root, "config") })

describe("cliState, the fresh state", () => {
  test("fills version, commit, build, path and autoUpdate, and every InstallState field from FRESH_INSTALL_STATE", async () => {
    const state = await cliState(home())
    expect(state).toEqual({
      version: VERSION,
      commit: BUILD_COMMIT,
      build: BUILD_KIND,
      path: realpathSync(process.execPath),
      install: "source",
      autoUpdate: BUILD_KIND === "release" ? "on" : "dev",
      mcpHandover: BUILD_KIND === "release" ? { handover: "on" } : { handover: "off", reason: "a development build" },
      installed: null,
      previous: null,
      highestSeen: null,
      holdBelow: null,
      pending: null,
      check: null,
      vault: {},
      lastUpdate: null,
    })
    // No `v`, no `mcp` outside a server, and `vault` is an object, never null.
    expect(Object.hasOwn(state, "v")).toBe(false)
    expect(Object.hasOwn(state, "mcp")).toBe(false)
  })

  test("FRESH_INSTALL_STATE is exactly the contract's fresh shape, and a caller cannot change it through cliState", async () => {
    expect(FRESH_INSTALL_STATE).toEqual({ installed: null, previous: null, highestSeen: null, holdBelow: null, pending: null, check: null, vault: {}, lastUpdate: null })
    const state = await cliState(home())
    state.vault["https://app.mehen.dev"] = { minimum: "0.3.0", recommended: null, seenAt: "2026-10-28T12:00:00.000Z" }
    expect(FRESH_INSTALL_STATE.vault).toEqual({})
    expect((await cliState(home())).vault).toEqual({})
  })

  test("auto-update reads off with MEHEN_NO_AUTO_UPDATE=1 and ci on a runner, before the build kind", async () => {
    expect((await cliState({ ...home(), MEHEN_NO_AUTO_UPDATE: "1", CI: "true" })).autoUpdate).toBe("off")
    expect((await cliState({ ...home(), CI: "true" })).autoUpdate).toBe("ci")
    expect((await cliState({ ...home(), CI: "" })).autoUpdate).toBe(BUILD_KIND === "release" ? "on" : "dev")
  })

  test("with an installation, cliState embeds its state file and the binary's realpath", async () => {
    const binary = join(root, "mehen")
    await writeFile(binary, "#!/bin/sh\n", { mode: 0o755 })
    const state = freshInstallState()
    state.highestSeen = "0.3.0"
    state.vault["https://app.mehen.dev"] = { minimum: "0.2.0", recommended: "0.3.0", seenAt: "2026-10-28T12:00:00.000Z" }
    await writeInstallState(installation(binary), state)
    const link = join(root, "link")
    await symlink(binary, link)
    const embedded = await cliState({ ...home(), MEHEN_SELF_EXECUTABLE: link, CI: "" })
    expect(embedded).toMatchObject({ path: binary, highestSeen: "0.3.0", vault: state.vault, autoUpdate: "on" })
    expect(Object.hasOwn(embedded, "v")).toBe(false)
  })
})

describe("auto-update mode and settings", () => {
  test("off for MEHEN_NO_AUTO_UPDATE=1 or settings, ci on a runner, dev for any non-release build, read-only for an unwritable directory", () => {
    const on = { autoUpdate: true }
    expect(autoUpdateMode({}, true, on, "release")).toBe("on")
    expect(autoUpdateMode({ MEHEN_NO_AUTO_UPDATE: "1" }, true, on, "release")).toBe("off")
    expect(autoUpdateMode({}, true, { autoUpdate: false }, "release")).toBe("off")
    expect(autoUpdateMode({ CI: "1" }, true, on, "release")).toBe("ci")
    expect(autoUpdateMode({}, true, on, "dev")).toBe("dev")
    expect(autoUpdateMode({}, true, on, null)).toBe("dev")
    expect(autoUpdateMode({}, false, on, "release")).toBe("read-only")
  })

  test("settings.json under the root: only an explicit false switches updating off, and only an explicit false switches the MCP handover off", async () => {
    expect(await readSettings(home())).toEqual({ autoUpdate: true, mcpHandover: true })
    await mkdir(join(root, "config"), { mode: 0o700 })
    await writeFile(join(root, "config/settings.json"), '{"autoUpdate": false}')
    expect(await readSettings(home())).toEqual({ autoUpdate: false, mcpHandover: true })
    await writeFile(join(root, "config/settings.json"), '{"autoUpdate": "no", "mcpHandover": "yes"}')
    expect(await readSettings(home())).toEqual({ autoUpdate: true, mcpHandover: true })
    await writeFile(join(root, "config/settings.json"), '{"mcpHandover": false}')
    expect(await readSettings(home())).toEqual({ autoUpdate: true, mcpHandover: false })
    await writeFile(join(root, "config/settings.json"), '{"mcpHandover": true}')
    expect(await readSettings(home())).toEqual({ autoUpdate: true, mcpHandover: true })
    await writeFile(join(root, "config/settings.json"), "[false]")
    expect(await readSettings(home())).toEqual({ autoUpdate: true, mcpHandover: true })
  })

  test("the MCP handover is on by default with automatic updates on and a runtime that can switch in place; off, each reason names a setting or variable and no path or value", () => {
    const defaults = { autoUpdate: true, mcpHandover: true }
    expect(mcpHandoverDecision({}, "on", defaults)).toEqual({ handover: "on" })
    const offs = [
      mcpHandoverDecision({}, "on", { autoUpdate: true, mcpHandover: false }),
      mcpHandoverDecision({ MEHEN_NO_AUTO_UPDATE: "1" }, "off", defaults),
      mcpHandoverDecision({}, "off", { autoUpdate: false, mcpHandover: true }),
      mcpHandoverDecision({ CI: "1" }, "ci", defaults),
      mcpHandoverDecision({}, "dev", defaults),
      mcpHandoverDecision({}, "read-only", defaults),
      mcpHandoverDecision({}, "on", defaults, false),
    ]
    expect(offs).toEqual([
      { handover: "off", reason: "mcpHandover is false in settings.json" },
      { handover: "off", reason: "MEHEN_NO_AUTO_UPDATE is set" },
      { handover: "off", reason: "autoUpdate is false in settings.json" },
      { handover: "off", reason: "CI is set" },
      { handover: "off", reason: "a development build" },
      { handover: "off", reason: "the install directory is not writable" },
      { handover: "off", reason: "this runtime cannot switch in place" },
    ])
    for (const off of offs) expect(off.handover === "off" && off.reason).not.toMatch(/\/|\d+\.\d+/)
  })

  test("cliState carries what a server started now would decide, from this shell's settings and variables", async () => {
    const binary = join(root, "mehen")
    await writeFile(binary, "#!/bin/sh\n", { mode: 0o755 })
    const shell = { ...home(), MEHEN_SELF_EXECUTABLE: binary, CI: "" }
    expect((await cliState(shell)).mcpHandover).toEqual({ handover: "on" })
    await mkdir(join(root, "config"), { mode: 0o700 })
    await writeFile(join(root, "config/settings.json"), '{"mcpHandover": false}')
    expect((await cliState(shell)).mcpHandover).toEqual({ handover: "off", reason: "mcpHandover is false in settings.json" })
    await writeFile(join(root, "config/settings.json"), '{"mcpHandover": true}')
    expect((await cliState(shell)).mcpHandover).toEqual({ handover: "on" })
    expect((await cliState({ ...shell, MEHEN_NO_AUTO_UPDATE: "1" })).mcpHandover).toEqual({ handover: "off", reason: "MEHEN_NO_AUTO_UPDATE is set" })
    expect(Object.hasOwn(await cliState(shell), "mcp")).toBe(false)
  })
})

describe("the state file", () => {
  test("is written 0600 by rename; a symlinked state file is never followed; a malformed journal refuses", async () => {
    const install = installation(join(root, "mehen"))
    expect(await readInstallState(install)).toBeNull()
    await writeInstallState(install, freshInstallState())
    expect(await readInstallState(install)).toEqual(freshInstallState())
    await rm(install.files.state)
    await writeFile(join(root, "elsewhere.json"), JSON.stringify({ ...freshInstallState(), highestSeen: "9.9.9" }))
    await symlink(join(root, "elsewhere.json"), install.files.state)
    expect(await readInstallState(install)).toBeNull()
    await rm(install.files.state)
    await writeFile(install.files.state, JSON.stringify({ ...freshInstallState(), pending: { target: "nonsense" } }))
    await expect(readInstallState(install)).rejects.toThrow("journal is malformed")
    // Human-only repair advice.
    await expect(readInstallState(install)).rejects.toMatchObject({ next: { say: expect.stringContaining("an agent must not rerun the installer") } })
  })

  test("a check's highestAnswered reads only as a release version; anything else reads as none", async () => {
    const install = installation(join(root, "mehen"))
    const answered = async (highestAnswered: unknown) => {
      await writeFile(install.files.state, JSON.stringify({ ...freshInstallState(), check: { at: "2026-11-03T12:00:00.000Z", nextAt: "2026-11-03T13:00:00.000Z", base: "x", latest: "0.3.9", error: null, highestAnswered } }))
      return (await readInstallState(install))?.check?.highestAnswered
    }
    expect(await answered("0.3.10")).toBe("0.3.10")
    expect(await answered("1.0.0-rc.1")).toBe("1.0.0-rc.1")
    for (const bad of ["garbage", "", "1.2", "v1.2.3", 3]) expect(await answered(bad)).toBeNull()
  })
})

// Sets a path's mtime `ms` in the past (the future when negative), as a lock
// left that long ago would have it.
async function age(path: string, ms = OWNERLESS_GRACE_MS + 60_000): Promise<void> {
  const when = new Date(Date.now() - ms)
  await utimes(path, when, when)
}

describe("the installation lock", () => {
  test("a lock with no readable owner is held for the grace period: not taken, and left as it is", async () => {
    const install = installation(join(root, "mehen"))
    await mkdir(install.files.lock, { mode: 0o700 })
    await age(install.files.lock, OWNERLESS_GRACE_MS - 60_000)
    expect(await lockHolder(install)).toMatchObject({ live: true, pid: 0 })
    const held = await withInstallLock(install, "manual", async () => "ran", { wait: false })
    expect(held).toMatchObject({ ok: false, holder: { pid: 0, live: true } })
    expect(await readdir(install.files.lock)).toEqual([])
  })

  test("an empty lock older than the grace period is not live, and is taken over: one owner, and one line in the update log", async () => {
    const install = installation(join(root, "mehen"))
    await mkdir(install.files.lock, { mode: 0o700 })
    await age(install.files.lock)
    expect(await lockHolder(install)).toMatchObject({ pid: 0, live: false })
    const got = await withInstallLock(install, "manual", async () => ({ entries: await readdir(install.files.lock), owner: JSON.parse(await readFile(join(install.files.lock, "owner.json"), "utf8")), log: await readFile(install.files.log, "utf8") }), { wait: false })
    expect(got.ok).toBe(true)
    if (!got.ok) return
    expect(got.value.entries).toEqual(["owner.json"])
    expect(got.value.owner).toMatchObject({ pid: process.pid, by: "manual" })
    const lines = got.value.log.trim().split("\n").map((line) => JSON.parse(line))
    expect(lines).toEqual([{ at: expect.any(String), pid: process.pid, event: "lock", result: "reclaimed", reason: "ownerless" }])
    expect(await lockHolder(install)).toBeNull()
  })

  test("an owner file that does not parse is taken over once both it and the lock are older than the grace period", async () => {
    const install = installation(join(root, "mehen"))
    await mkdir(install.files.lock, { mode: 0o700 })
    const owner = join(install.files.lock, "owner.json")
    await writeFile(owner, '{"pid":12')
    await age(install.files.lock)
    // The younger of the two counts: a recent owner write keeps it held.
    expect((await withInstallLock(install, "manual", async () => "ran", { wait: false })).ok).toBe(false)
    expect(await readFile(owner, "utf8")).toBe('{"pid":12')
    await age(owner)
    await age(install.files.lock)
    expect(await withInstallLock(install, "manual", async () => "ran", { wait: false })).toEqual({ ok: true, value: "ran" })
    expect(await lockHolder(install)).toBeNull()
  })

  test("an ownerless lock with a reclamation guard is held at any age", async () => {
    const install = installation(join(root, "mehen"))
    await mkdir(join(install.files.lock, RECLAIM_GUARD), { recursive: true, mode: 0o700 })
    await age(join(install.files.lock, RECLAIM_GUARD), 30 * 86_400_000)
    await age(install.files.lock, 30 * 86_400_000)
    expect(await lockHolder(install)).toMatchObject({ pid: 0, live: true })
    expect((await withInstallLock(install, "manual", async () => "ran", { wait: false })).ok).toBe(false)
    expect(await readdir(install.files.lock)).toEqual([RECLAIM_GUARD])
  })

  test("an old owner file with a live pid is held: age never steals a live holder", async () => {
    const install = installation(join(root, "mehen"))
    await mkdir(install.files.lock, { mode: 0o700 })
    const owner = join(install.files.lock, "owner.json")
    const text = JSON.stringify({ pid: process.pid, boot: bootId(), at: "2000-01-01T00:00:00Z", by: "auto" })
    await writeFile(owner, text)
    await age(owner, 30 * 86_400_000)
    await age(install.files.lock, 30 * 86_400_000)
    expect(await lockHolder(install)).toMatchObject({ pid: process.pid, live: true })
    expect((await withInstallLock(install, "manual", async () => "ran", { wait: false })).ok).toBe(false)
    expect(await readFile(owner, "utf8")).toBe(text)
  })

  test("an ownerless lock whose directory or owner file has an mtime in the future is held", async () => {
    const install = installation(join(root, "mehen"))
    await mkdir(install.files.lock, { mode: 0o700 })
    await age(install.files.lock, -3_600_000)
    expect(await lockHolder(install)).toMatchObject({ pid: 0, live: true })
    expect((await withInstallLock(install, "manual", async () => "ran", { wait: false })).ok).toBe(false)
    const owner = join(install.files.lock, "owner.json")
    await writeFile(owner, "")
    await age(owner, -3_600_000)
    await age(install.files.lock)
    expect(await lockHolder(install)).toMatchObject({ pid: 0, live: true })
    expect((await withInstallLock(install, "manual", async () => "ran", { wait: false })).ok).toBe(false)
    expect(await readdir(install.files.lock)).toEqual(["owner.json"])
  })

  test("two contenders on one old ownerless lock: the one that reclaims holds it, and the other's old observation cannot displace it", async () => {
    const install = installation(join(root, "mehen"))
    await mkdir(install.files.lock, { mode: 0o700 })
    await age(install.files.lock)
    const observed = await observeLock(install)
    expect(observed?.text).toBeNull()
    let release!: () => void
    const held = new Promise<void>((resolve) => { release = resolve })
    let entered!: () => void
    const inside = new Promise<void>((resolve) => { entered = resolve })
    const b = withInstallLock(install, "manual", async () => {
      entered()
      await held
    })
    await inside
    const ownerB = await readFile(join(install.files.lock, "owner.json"), "utf8")
    expect(await reclaimStale(install, observed!, "auto", "nonce-a")).toBe(false)
    expect(await readFile(join(install.files.lock, "owner.json"), "utf8")).toBe(ownerB)
    expect(await readdir(install.files.lock)).toEqual(["owner.json"])
    expect((await withInstallLock(install, "auto", async () => "c", { wait: false })).ok).toBe(false)
    release()
    expect((await b).ok).toBe(true)
    expect((await readFile(install.files.log, "utf8")).trim().split("\n")).toHaveLength(1)
    expect(await lockHolder(install)).toBeNull()
  })

  test("an old ownerless lock removed and made again between observation and guard is held, and the new holder's owner is untouched", async () => {
    const install = installation(join(root, "mehen"))
    await mkdir(install.files.lock, { mode: 0o700 })
    await age(install.files.lock)
    const observed = await observeLock(install)
    // A new holder's mkdir, made beside the old lock first so it cannot reuse its inode.
    const fresh = `${install.files.lock}.fresh`
    await mkdir(fresh, { mode: 0o700 })
    await rm(install.files.lock, { recursive: true })
    await rename(fresh, install.files.lock)
    await age(install.files.lock)
    expect(await reclaimStale(install, observed!, "auto", "nonce-a")).toBe(false)
    expect(await readdir(install.files.lock)).toEqual([])
    const owner = JSON.stringify({ pid: process.pid, boot: bootId(), at: new Date().toISOString(), by: "manual", nonce: "new-holder" })
    await writeFile(join(install.files.lock, "owner.json"), owner, { flag: "wx" })
    expect(await readFile(join(install.files.lock, "owner.json"), "utf8")).toBe(owner)
  })

  test("the vault's zero-wait advice takes over an old ownerless lock and records the advice", async () => {
    const install = installation(join(root, "mehen"))
    await mkdir(install.files.lock, { mode: 0o700 })
    await age(install.files.lock)
    await recordVaultAdvice(install, "https://app.mehen.dev", { minimum: "0.3.0", recommended: "0.3.18" })
    expect((await readInstallState(install))?.vault["https://app.mehen.dev"]).toMatchObject({ minimum: "0.3.0", recommended: "0.3.18" })
    expect(await lockHolder(install)).toBeNull()
  })

  test("a holder from another boot is stale even when its pid is alive now; one from this boot with a live pid is not", async () => {
    const install = installation(join(root, "mehen"))
    await mkdir(install.files.lock, { mode: 0o700 })
    await writeFile(join(install.files.lock, "owner.json"), JSON.stringify({ pid: process.pid, boot: "linux:another-boot", at: "2026-10-28T00:00:00Z", by: "auto" }))
    if (bootId() !== "") {
      expect((await lockHolder(install))?.live).toBe(false)
      expect(await withInstallLock(install, "manual", async () => "ran", { wait: false })).toEqual({ ok: true, value: "ran" })
    }
    await mkdir(install.files.lock, { mode: 0o700 })
    await writeFile(join(install.files.lock, "owner.json"), JSON.stringify({ pid: process.pid, boot: bootId(), at: "2000-01-01T00:00:00Z", by: "auto" }))
    expect((await lockHolder(install))?.live).toBe(true)
    expect((await withInstallLock(install, "manual", async () => "ran", { wait: false })).ok).toBe(false)
  })

  // Stale reclamation admits exactly one writer. The probe: A
  // reads a dead owner; B reclaims and holds; A, acting on its old
  // observation, must not move B's lock; C must then find it held.
  test("three contenders on a stale lock: the old observation cannot displace the reclaimer, and a third finds it held", async () => {
    const install = installation(join(root, "mehen"))
    const gone = Bun.spawn(["true"])
    await gone.exited
    await mkdir(install.files.lock, { mode: 0o700 })
    await writeFile(join(install.files.lock, "owner.json"), JSON.stringify({ pid: gone.pid, boot: "", at: "2026-10-28T00:00:00Z", by: "auto" }))
    const observed = await observeLock(install)
    let active = 0
    let overlapped = false
    let release!: () => void
    const held = new Promise<void>((resolve) => { release = resolve })
    let entered!: () => void
    const inside = new Promise<void>((resolve) => { entered = resolve })
    const b = withInstallLock(install, "manual", async () => {
      active += 1
      entered()
      await held
      active -= 1
    })
    await inside
    const ownerB = await readFile(join(install.files.lock, "owner.json"), "utf8")
    expect(await reclaimStale(install, observed!, "auto", "nonce-a")).toBe(false)
    expect(await readFile(join(install.files.lock, "owner.json"), "utf8")).toBe(ownerB)
    const c = await withInstallLock(install, "auto", async () => {
      if (active > 0) overlapped = true
      return "c"
    }, { wait: false })
    expect(c.ok).toBe(false)
    release()
    expect((await b).ok).toBe(true)
    expect(overlapped).toBe(false)
    expect(await lockHolder(install)).toBeNull()
  })

  test("many contenders reclaiming one stale lock at once: exactly one enters, and no two critical sections overlap", async () => {
    const install = installation(join(root, "mehen"))
    const gone = Bun.spawn(["true"])
    await gone.exited
    await mkdir(install.files.lock, { mode: 0o700 })
    await writeFile(join(install.files.lock, "owner.json"), JSON.stringify({ pid: gone.pid, boot: "", at: "2026-10-28T00:00:00Z", by: "auto" }))
    let active = 0
    let max = 0
    const results = await Promise.all(Array.from({ length: 12 }, () => withInstallLock(install, "auto", async () => {
      active += 1
      max = Math.max(max, active)
      await Bun.sleep(20)
      active -= 1
    }, { wait: false })))
    expect(results.filter((r) => r.ok)).toHaveLength(1)
    expect(max).toBe(1)
  })

  test("a reclamation guard left behind (a reclaimer that died mid-way) is held, never removed by age", async () => {
    const install = installation(join(root, "mehen"))
    const gone = Bun.spawn(["true"])
    await gone.exited
    await mkdir(join(install.files.lock, RECLAIM_GUARD), { recursive: true, mode: 0o700 })
    await writeFile(join(install.files.lock, "owner.json"), JSON.stringify({ pid: gone.pid, boot: "", at: "2000-01-01T00:00:00Z", by: "auto" }))
    const got = await withInstallLock(install, "manual", async () => "ran", { wait: false })
    expect(got).toMatchObject({ ok: false, holder: { pid: gone.pid, live: true } })
    expect((await lockHolder(install))?.live).toBe(true)
    expect(await readFile(join(install.files.lock, "owner.json"), "utf8")).toContain(String(gone.pid))
  })

  test("a lock path that is not a directory refuses", async () => {
    const install = installation(join(root, "mehen"))
    await writeFile(install.files.lock, "x")
    await expect(withInstallLock(install, "manual", async () => "ran")).rejects.toThrow("not a lock directory")
  })

  test("the holder's lock is released when its work throws", async () => {
    const install = installation(join(root, "mehen"))
    await expect(withInstallLock(install, "manual", async () => { throw new Error("boom") })).rejects.toThrow("boom")
    expect(await lockHolder(install)).toBeNull()
  })

  test("advice is skipped while the lock is held and rewrites only `vault` under it", async () => {
    const install = installation(join(root, "mehen"))
    const state = freshInstallState()
    state.pending = { target: { version: "0.3.0", commit: "abc", sha256: "a".repeat(64), size: 1, at: "2026-10-28T00:00:00Z", by: "auto", keyId: "rk", manifestSha256: null, manifest: null }, previousSha256: "b".repeat(64), steps: ["record"], since: "2026-10-28T00:00:00Z" }
    await writeInstallState(install, state)
    await withInstallLock(install, "auto", async () => {
      await recordVaultAdvice(install, "https://app.mehen.dev", { minimum: "0.3.0", recommended: null })
      expect((await readInstallState(install))?.vault).toEqual({})
    })
    await recordVaultAdvice(install, "https://app.mehen.dev", { minimum: "0.3.0", recommended: null })
    const after = await readInstallState(install)
    expect(after?.vault["https://app.mehen.dev"]).toMatchObject({ minimum: "0.3.0", recommended: null })
    expect(after?.pending).toEqual(state.pending)
    // The same advice again writes nothing.
    const text = await readFile(install.files.state, "utf8")
    await recordVaultAdvice(install, "https://app.mehen.dev", { minimum: "0.3.0", recommended: null })
    expect(await readFile(install.files.state, "utf8")).toBe(text)
  })
})

describe("the update row's repair advice", () => {
  test("a refused journal tells the agent to stop and ask the human, with no command and no installer", async () => {
    const cli = await cliState(home())
    cli.pending = { target: { version: "9.0.0", commit: "abc", sha256: "a".repeat(64), size: 1, at: "2026-10-28T00:00:00Z", by: "auto", keyId: "rk", manifestSha256: null, manifest: null }, previousSha256: "b".repeat(64), steps: ["record"], since: "2026-10-28T00:00:00Z" }
    cli.lastUpdate = { at: "2026-10-28T00:00:00Z", from: "0.3.0", to: "9.0.0", result: "failed", reason: "the binary on disk is neither the previous nor the pending release", skills: [] }
    const row = updateDoctorCheck(cli, null, join(root, ".mehen.update.lock"))
    expect(row).toMatchObject({ status: "warn", next: { say: HUMAN_REPAIR } })
    expect(row.next?.command).toBeUndefined()
    expect(JSON.stringify(row)).not.toMatch(/reinstall/i)
  })
})

// Update rollout design gaps 4 and 5: a failed update and the vault's
// advice both reach the update row.
describe("the update row: a failed update and the vault's advice", () => {
  test("a failed update warns with mehen update as the next step", async () => {
    const cli = await cliState(home())
    cli.lastUpdate = { at: "2026-10-28T00:00:00Z", from: VERSION, to: "9.0.0", result: "failed", reason: "smoke_failed", skills: [] }
    expect(updateDoctorCheck(cli, null, join(root, ".mehen.update.lock"))).toEqual({ check: "update", status: "warn", detail: "The last update to 9.0.0 failed: smoke_failed.", next: { command: "mehen update --json", say: "Run mehen update --json to try again and see why." } })
  })

  test("below a vault's recommended version warns that an update is available; below its minimum fails as cli_outdated", async () => {
    const cli = await cliState(home())
    const lock = join(root, ".mehen.update.lock")
    cli.vault = { "https://app.mehen.dev": { minimum: "0.0.1", recommended: VERSION, seenAt: "2026-10-28T00:00:00Z" } }
    expect(updateDoctorCheck(cli, null, lock).status).toBe("ok")
    cli.vault["https://app.mehen.dev"]!.recommended = "99.0.0"
    cli.vault["https://other.example"] = { minimum: "0.0.1", recommended: "98.0.0", seenAt: "2026-10-28T00:00:00Z" }
    expect(updateDoctorCheck(cli, null, lock)).toEqual({ check: "update", status: "warn", detail: `Update available: https://app.mehen.dev recommends mehen 99.0.0 or later; this is ${VERSION}.`, next: { command: "mehen update --json", say: "Run mehen update --json to install the latest release." } })
    cli.vault["https://other.example"]!.minimum = "97.0.0"
    expect(updateDoctorCheck(cli, null, lock)).toEqual({ check: "update", status: "fail", detail: `https://other.example refuses mehen ${VERSION}: its minimum is 97.0.0.`, error: "cli_outdated", next: { command: "mehen update --json", say: "Run mehen update --json to install the latest release; https://other.example refuses mehen below 97.0.0." } })
  })
})

describe("the on_path row", () => {
  test("ok when the install directory is on PATH, else a warning naming the absolute binary", () => {
    const install = installation(join(root, "mehen"))
    expect(onPathCheck(install, { PATH: `/usr/bin:${root}` })).toMatchObject({ check: "on_path", status: "ok" })
    const off = onPathCheck(install, { PATH: "/usr/bin" })
    expect(off).toMatchObject({ check: "on_path", status: "warn" })
    expect(off.detail).toContain(install.binary)
  })
})

describe("a mehen Homebrew installed", () => {
  test("is told from where the binary really is: its kind, the link to record, and its auto-update mode", async () => {
    const brew = await brewPrefix(root)
    const env = { ...home(), MEHEN_SELF_EXECUTABLE: brew.bin }
    expect(selfInstallKind(env)).toBe("homebrew")
    expect(selfLaunchPath(env)).toBe(brew.opt)
    expect(selfInstallKind(home())).toBe("source")
    expect(selfLaunchPath(home())).toBeNull()
    const plain = join(root, "plain", "mehen")
    await mkdir(join(root, "plain"))
    await writeFile(plain, "#!/bin/sh\n", { mode: 0o755 })
    expect(selfInstallKind({ ...home(), MEHEN_SELF_EXECUTABLE: plain, HOMEBREW_PREFIX: brew.prefix })).toBe("standalone")
    expect(selfLaunchPath({ ...home(), MEHEN_SELF_EXECUTABLE: plain })).toBe(plain)
    const cli = await cliState(env)
    expect(cli).toMatchObject({ path: brew.keg, install: "homebrew", autoUpdate: "homebrew", mcpHandover: { handover: "off", reason: "Homebrew installed mehen; brew upgrade mehen updates it" } })
  })

  test("auto-update is homebrew before every other reason, and the MCP handover is off", () => {
    for (const env of [{}, { MEHEN_NO_AUTO_UPDATE: "1" }, { CI: "1" }]) expect(autoUpdateMode(env, true, { autoUpdate: true }, "release", true)).toBe("homebrew")
    expect(autoUpdateMode({}, false, { autoUpdate: false }, "dev", true)).toBe("homebrew")
    expect(mcpHandoverDecision({}, "homebrew", { autoUpdate: true, mcpHandover: true }, true)).toEqual({ handover: "off", reason: "Homebrew installed mehen; brew upgrade mehen updates it" })
  })

  test("the update row sends every update to brew upgrade mehen, below a vault's minimum too", async () => {
    const brew = await brewPrefix(root)
    const cli = await cliState({ ...home(), MEHEN_SELF_EXECUTABLE: brew.bin })
    const lock = join(root, ".mehen.update.lock")
    const next = { command: "brew upgrade mehen", say: "Run brew upgrade mehen: Homebrew installed this mehen and updates it." }
    expect(updateDoctorCheck(cli, null, lock)).toEqual({ check: "update", status: "ok", detail: `mehen ${VERSION}, installed by Homebrew; brew upgrade mehen updates it.` })
    cli.vault = { "https://app.mehen.dev": { minimum: "0.0.1", recommended: "99.0.0", seenAt: "2026-10-28T00:00:00Z" } }
    expect(updateDoctorCheck(cli, null, lock)).toEqual({ check: "update", status: "warn", detail: `Update available: https://app.mehen.dev recommends mehen 99.0.0 or later; this is ${VERSION}, installed by Homebrew.`, next })
    cli.vault["https://app.mehen.dev"]!.minimum = "98.0.0"
    expect(updateDoctorCheck(cli, null, lock)).toEqual({ check: "update", status: "fail", detail: `https://app.mehen.dev refuses mehen ${VERSION}: its minimum is 98.0.0. Homebrew installed this mehen.`, error: "cli_outdated", next })
  })

  test("the on_path row is ok with brew's bin on PATH, and names the link, not the keg, when it is not", async () => {
    const brew = await brewPrefix(root)
    const install = installation(brew.bin)
    expect(install.binary).toBe(brew.keg)
    expect(onPathCheck(install, { PATH: `/usr/bin:${join(brew.prefix, "bin")}` }, brew.opt)).toMatchObject({ status: "ok", detail: `${join(brew.prefix, "bin")} is on PATH.` })
    const off = onPathCheck(install, { PATH: "/usr/bin" }, brew.opt)
    expect(off).toMatchObject({ status: "warn" })
    expect(off.detail).toContain(brew.opt)
    expect(off.detail).not.toContain("Cellar")
  })
})
