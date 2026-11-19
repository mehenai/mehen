// The finish step, the compare-and-mutate helpers and the superseded
// observer: every pairing
// of observers finishing the same approval is one success and no revoke; a
// late answer about an older attempt or device never touches the newer
// one; an observer that can no longer sign as the device the vault
// activated says so instead of claiming a cleanup.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { existsSync } from "node:fs"
import { chmod, mkdir, open, readFile, rename, rm, symlink, unlink } from "node:fs/promises"
import { join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { type Config, readConfig, writeConfig } from "../config.ts"
import { SOFTWARE_KEY_FILE, readKeyScope, writeKeyScope } from "../device-key.ts"
import { type EnrolmentRecord, readEnrolmentRecord } from "../enrolment-record.ts"
import { activeSlotPath, pendingSlotPath } from "../home.ts"
import { mcpDeps } from "../mcp.ts"
import { vaultWait } from "../mcp/vault-wait.ts"
import { pendingLockPath } from "../slot-lock.ts"
import { fakeHelper } from "../testing/fake-mehen-se.ts"
import { MOCK_OWNER, MOCK_TENANT, MOCK_WORKSPACE, MockVault, WORKSPACE_SCOPE, deviceFor, vaultError } from "../testing/mock-vault.ts"
import { type JvResult, jsonLines, runJv, tempDir } from "../testing/run-mehen.ts"
import { type Attempt, attemptState, finishAttempt, followAttempt, mutateSlot, openAttempt, publicKeyOnDisk, sameKeyOnDisk } from "./activate.ts"

let vault: MockVault
let dir: { path: string; remove(): Promise<void> }
let env: Record<string, string>

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_HOME: dir.path, MEHEN_VAULT_URL: vault.url, MEHEN_POLL_INTERVAL_MS: "20" }
  vault.overrides.clear()
  vault.enrolOutcome = { pendingPolls: 1_000_000, result: "active" }
  vault.enrolMode = "current"
  vault.activeAnswer = null
  vault.workspace = { ...MOCK_WORKSPACE }
  vault.owner = { ...MOCK_OWNER }
  vault.renewIntervalMs = 60_000
})
afterEach(async () => dir.remove())

const ENROL = ["enrol", "--workspace", "mock-space", "--name", "test-mac", "--backend", "software"]

function json(result: JvResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>
}
function lines(result: JvResult): Record<string, unknown>[] {
  return jsonLines(result.stdout) as Record<string, unknown>[]
}
function pendingSlot(slug = "mock-space"): string {
  return pendingSlotPath(dir.path, vault.url, slug)
}
function activeSlot(tenant = MOCK_TENANT): string {
  return activeSlotPath(dir.path, vault.url, tenant)
}
async function record(slot = pendingSlot()): Promise<EnrolmentRecord | null> {
  const read = await readEnrolmentRecord(slot)
  return read && "record" in read ? read.record : null
}

// An attempt as mehen enrol leaves it, and the vault's active answer for it.
async function started(extra: string[] = [], envOverride: Record<string, string> = {}): Promise<{ id: string; slot: string }> {
  const result = await runJv([...ENROL, ...extra, "--json"], { ...env, ...envOverride })
  expect(result.code).toBe(EXIT.ok)
  return { id: json(result).enrolment as string, slot: json(result).slot as string }
}

function activeAnswer(id: string, workspace = vault.workspace): Record<string, unknown> {
  return { status: "active", tenant: workspace.id, workspace, device: deviceFor(id), scope: WORKSPACE_SCOPE, owner: MOCK_OWNER }
}

// The mock activates an enrolment's device the first time it answers active.
function activateAt(id: string): void {
  const enrolment = vault.enrolments.get(id)
  if (enrolment) vault.devices.set(deviceFor(id), { jwk: enrolment.jwk, revoked: false })
}

function revokesSince(from: number): string[] {
  return vault.seen.slice(from).filter((c) => c.path === "/v1/devices/self/revoke").map((c) => c.claims.dev)
}

// Answers the poll of `id` pending until `observers` polls have arrived,
// then active to every poll: the observers all learn of the approval
// together and race to finish it.
function approveOnceAllPolled(id: string, observers: number): void {
  let polls = 0
  vault.overrides.set(`GET /v1/enrol/${id}`, () => {
    polls += 1
    if (polls <= observers) return Response.json({ status: "pending_owner_acceptance", expiresAt: new Date(Date.now() + 600_000).toISOString(), hardExpiresAt: new Date(Date.now() + 86_400_000).toISOString() })
    activateAt(id)
    return Response.json(activeAnswer(id))
  })
}

// A 0.3.18 machine may be given fill (ladder F1): an activation whose scope
// holds it finishes like any other, and nothing is revoked.
test("an active answer whose modes include fill finishes the enrolment; nothing is revoked", async () => {
  const { id } = await started()
  const modes = ["relay", "sign", "mint", "placeholder", "fill", "lease"]
  vault.overrides.set(`GET /v1/enrol/${id}`, () => {
    activateAt(id)
    return Response.json({ ...activeAnswer(id), scope: { ...WORKSPACE_SCOPE, modes } })
  })
  const seen = vault.seen.length
  const waited = await runJv(["wait", id, "--json"], env)
  expect(waited.code).toBe(EXIT.ok)
  expect(json(waited)).toMatchObject({ status: "active", device: deviceFor(id) })
  expect(revokesSince(seen)).toEqual([])
  expect(await readConfig(activeSlot())).toMatchObject({ device: deviceFor(id) })
})

describe("the same approval finished twice is one success and no revoke", () => {
  test("enrol --wait and mehen wait at once: both report the same device, one slot, nothing revoked", async () => {
    const { id } = await started()
    approveOnceAllPolled(id, 2)
    const seen = vault.seen.length
    const [enrolled, waited] = await Promise.all([runJv([...ENROL, "--wait", "--json"], env), runJv(["wait", id, "--json"], env)])
    expect(enrolled.code).toBe(EXIT.ok)
    expect(waited.code).toBe(EXIT.ok)
    expect(lines(enrolled).at(-1)).toMatchObject({ status: "active", device: deviceFor(id), slot: activeSlot() })
    expect(json(waited)).toMatchObject({ status: "active", device: deviceFor(id) })
    expect(revokesSince(seen)).toEqual([])
    expect(await readConfig(activeSlot())).toMatchObject({ device: deviceFor(id) })
    expect(existsSync(pendingSlot())).toBe(false)
  })

  test("an observer that reads its record just before another commits, and looks for its key just after, finds the attempt moved, not replaced", async () => {
    const { id, slot } = await started()
    const a = await openAttempt(env, dir.path, slot, id, null)
    const state = await attemptState(a, async (path, backend, jwk) => {
      await rename(slot, `${slot}.committed`)
      return sameKeyOnDisk(path, backend, jwk)
    })
    expect(state).toEqual({ state: "moved" })
  })

  test("two mehen waits at once: both succeed, nothing revoked", async () => {
    const { id } = await started()
    approveOnceAllPolled(id, 2)
    const seen = vault.seen.length
    const results = await Promise.all([runJv(["wait", id, "--json"], env), runJv(["wait", id, "--json"], env)])
    for (const result of results) expect(json(result)).toMatchObject({ status: "active", device: deviceFor(id) })
    expect(revokesSince(seen)).toEqual([])
    expect(await readConfig(activeSlot())).toMatchObject({ device: deviceFor(id) })
  })

  test("vault_wait in a server and enrol --wait in a terminal at once: both succeed, the server latches the device, nothing revoked", async () => {
    const { id } = await started()
    approveOnceAllPolled(id, 2)
    const { bindMcpContext } = await import("../mcp.ts")
    const bound = await bindMcpContext(env, dir.path)
    expect(bound.slots.size).toBe(0)
    const deps = mcpDeps(env, bound, () => undefined)
    const seen = vault.seen.length
    const [served, enrolled] = await Promise.all([vaultWait.call({ id, timeoutSeconds: 10 }, deps, { signal: new AbortController().signal, progressToken: null }), runJv([...ENROL, "--wait", "--json"], env)])
    expect(served.structured).toMatchObject({ status: "active", device: deviceFor(id) })
    expect(lines(enrolled).at(-1)).toMatchObject({ status: "active", device: deviceFor(id) })
    expect([...bound.slots.values()]).toEqual([{ latched: { vault: vault.url, tenant: MOCK_TENANT, device: deviceFor(id) } }])
    expect(revokesSince(seen)).toEqual([])
  })

  test("a mehen wait started after another observer committed the attempt reports the same success, with nothing written or revoked", async () => {
    const { id } = await started()
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    expect((await runJv(["wait", id, "--json"], env)).code).toBe(EXIT.ok)
    const config = await readFile(join(activeSlot(), "config.json"), "utf8")
    const seen = vault.seen.length
    const late = await runJv(["wait", id, "--json"], env)
    expect(late.code).toBe(EXIT.ok)
    expect(json(late)).toMatchObject({ id, kind: "enrol", status: "active", device: deviceFor(id), tenant: MOCK_TENANT })
    // One poll, signed by the committed slot's key as the attempt.
    expect(vault.seen.slice(seen).map((c) => [c.path, c.claims.ten, c.claims.dev])).toEqual([[`/v1/enrol/${id}`, "enrol", id]])
    expect(revokesSince(seen)).toEqual([])
    expect(await readFile(join(activeSlot(), "config.json"), "utf8")).toBe(config)
    // An id this slot's key never started is not found, and nothing changes.
    const unknown = await runJv(["wait", "enr_neverStarted01", "--json"], env)
    expect(unknown.code).toBe(EXIT.error)
    expect(json(unknown)).toMatchObject({ error: "not_found" })
    expect(await readFile(join(activeSlot(), "config.json"), "utf8")).toBe(config)
  })

  test("a mehen enrol that waited for the pending lock while the finish step committed is idempotent success: no second key, no new attempt", async () => {
    const { id, slot } = await started()
    const lock = pendingLockPath(dir.path, vault.url, "mock-space")
    const held = await open(lock, "wx", 0o600)
    await held.writeFile(JSON.stringify({ pid: process.pid, at: new Date().toISOString() }))
    await held.close()
    const posts = vault.seen.filter((c) => c.path === "/v1/enrol").length
    const enrolling = runJv(ENROL.concat("--json"), env)
    await Bun.sleep(400)
    // The other observer's commit, while it holds the pending lock.
    activateAt(id)
    await writeKeyScope(slot, "software", { vault: vault.url, tenant: MOCK_TENANT })
    await writeConfig(slot, { vault: vault.url, tenant: MOCK_TENANT, device: deviceFor(id), backend: "software", workspaceSlug: "mock-space", workspaceName: "Mock Space", owner: MOCK_OWNER })
    await mkdir(join(dir.path, "workspaces", activeSlot().split("/").at(-2) as string), { recursive: true, mode: 0o700 })
    await rename(slot, activeSlot())
    await rm(join(activeSlot(), "enrolment.json"))
    await unlink(lock)
    const result = await enrolling
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toMatchObject({ status: "active", alreadyEnrolled: true, device: deviceFor(id), slot: activeSlot() })
    expect(vault.seen.filter((c) => c.path === "/v1/enrol").length).toBe(posts)
    expect(existsSync(slot)).toBe(false)
  })

  test("two finish steps released together from behind the pending lock: one commits, the other finds the slot already holding its device", async () => {
    const { id, slot } = await started()
    const a = await openAttempt(env, dir.path, slot, id, null)
    const b = await openAttempt(env, dir.path, slot, id, null)
    activateAt(id)
    // Hold the pending lock as another process would, so both finishers queue.
    const lock = pendingLockPath(dir.path, vault.url, "mock-space")
    const held = await open(lock, "wx", 0o600)
    await held.writeFile(JSON.stringify({ pid: process.pid, at: new Date().toISOString() }))
    await held.close()
    const seen = vault.seen.length
    const racing = Promise.all([finishAttempt(a, activeAnswer(id)), finishAttempt(b, activeAnswer(id))])
    await Bun.sleep(100)
    await unlink(lock)
    const [first, second] = await racing
    expect([first.already, second.already].sort()).toEqual([false, true])
    expect(first.config.device).toBe(deviceFor(id))
    expect(second.config.device).toBe(deviceFor(id))
    expect(first.slot).toBe(activeSlot())
    expect(revokesSince(seen)).toEqual([])
  })

  test("finish after the pending directory vanished: success when the active slot holds this device and key; otherwise failed, nothing written or revoked", async () => {
    const { id, slot } = await started()
    const a = await openAttempt(env, dir.path, slot, id, null)
    activateAt(id)
    // Another observer committed this very approval (the rename already done).
    await finishAttempt(await openAttempt(env, dir.path, slot, id, null), activeAnswer(id))
    const seen = vault.seen.length
    const again = await finishAttempt(a, activeAnswer(id))
    expect(again).toMatchObject({ already: true, slot: activeSlot(), config: { device: deviceFor(id) } })
    // Gone with nothing of this attempt anywhere: failed, and the device is named.
    await rm(activeSlot(), { recursive: true })
    await expect(finishAttempt(a, activeAnswer(id))).rejects.toMatchObject({ code: "failed", message: expect.stringContaining(`The local record of enrolment ${id} is gone; device ${deviceFor(id)} is active in the vault`) })
    expect(revokesSince(seen)).toEqual([])
    expect(existsSync(activeSlot())).toBe(false)
  })

  test("a crash between the scope write and the rename leaves a resumable pending slot that mehen wait finishes", async () => {
    const { id, slot } = await started()
    // What the finish step wrote before the crash: the scope and config.json in the pending slot.
    await writeKeyScope(slot, "software", { vault: vault.url, tenant: MOCK_TENANT })
    await writeConfig(slot, { vault: vault.url, tenant: MOCK_TENANT, device: deviceFor(id), backend: "software" })
    const listed = await runJv(["workspace", "list", "--json"], env)
    expect((json(listed).workspaces as { state: string; slot: string }[]).find((w) => w.slot === slot)).toMatchObject({ state: "pending" })
    const resumed = await runJv([...ENROL, "--json"], env)
    expect(json(resumed)).toMatchObject({ status: "pending", enrolment: id })
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    const waited = await runJv(["wait", id, "--json"], env)
    expect(waited.code).toBe(EXIT.ok)
    expect(await readConfig(activeSlot())).toMatchObject({ device: deviceFor(id), workspaceSlug: "mock-space" })
    expect(existsSync(slot)).toBe(false)
  })
})

describe("a finish step never overwrites another device", () => {
  test("another device already in the workspace's slot: already_enrolled naming both, nothing revoked or deleted", async () => {
    const { id, slot } = await started()
    const a = await openAttempt(env, dir.path, slot, id, null)
    const other = await vault.enrolSoftware(dir.path)
    const before = await readFile(join(activeSlot(), "config.json"), "utf8")
    const seen = vault.seen.length
    const failure = (await finishAttempt(a, activeAnswer(id)).catch((e: unknown) => e)) as { code: string; message: string; next: { command: string; say: string } }
    expect(failure.code).toBe("already_enrolled")
    expect(failure.message).toContain(`This machine already holds device ${other} in Mock Space (mock-space); the vault now also has device ${deviceFor(id)} active there`)
    expect(failure.next.command).toBe("mehen revoke --workspace mock-space")
    expect(failure.next.say).toContain(`or revoke ${deviceFor(id)} on the Machines page`)
    expect(revokesSince(seen)).toEqual([])
    expect(await readFile(join(activeSlot(), "config.json"), "utf8")).toBe(before)
    expect(await record(slot)).toMatchObject({ id })
    expect(existsSync(join(slot, SOFTWARE_KEY_FILE))).toBe(true)
  })

  test("two pending slugs that the vault resolves to one workspace serialise on the active lock: one commits, the other is already_enrolled", async () => {
    const first = await started()
    const second = await started([], {})
    expect(second.id).toBe(first.id)
    const renamed = await runJv(["enrol", "--workspace", "mock-renamed", "--name", "test-mac", "--backend", "software", "--json"], env)
    const other = { id: json(renamed).enrolment as string, slot: json(renamed).slot as string }
    const a = await openAttempt(env, dir.path, first.slot, first.id, null)
    const b = await openAttempt(env, dir.path, other.slot, other.id, null)
    activateAt(first.id)
    activateAt(other.id)
    const seen = vault.seen.length
    // The vault answers each with the slug its intent named (a rename between them), one tenant.
    const results = await Promise.allSettled([finishAttempt(a, activeAnswer(first.id)), finishAttempt(b, activeAnswer(other.id, { ...MOCK_WORKSPACE, slug: "mock-renamed" }))])
    const done = results.filter((r) => r.status === "fulfilled")
    const refused = results.filter((r): r is PromiseRejectedResult => r.status === "rejected")
    expect(done).toHaveLength(1)
    expect(refused).toHaveLength(1)
    expect(refused[0]?.reason).toMatchObject({ code: "already_enrolled" })
    expect(revokesSince(seen)).toEqual([])
    expect(await readConfig(activeSlot())).toMatchObject({ tenant: MOCK_TENANT })
  })
})

// A newer attempt (B) replaced the one this observer holds (A) while A was
// out at the vault. Whatever A's late answer says, B is never touched.
describe("a superseded observer", () => {
  async function replaceWithFreshKey(): Promise<string> {
    const fresh = await runJv([...ENROL, "--fresh-key", "--json"], env)
    expect(fresh.code).toBe(EXIT.ok)
    return json(fresh).enrolment as string
  }

  test("key replacement during a poll: the active answer for A finds B; A's software key still signs, so A's device is revoked; B is intact", async () => {
    const { id, slot } = await started()
    const a = await openAttempt(env, dir.path, slot, id, null)
    const newer = await replaceWithFreshKey()
    const bRecord = await readFile(join(slot, "enrolment.json"), "utf8")
    const bKey = await readFile(join(slot, SOFTWARE_KEY_FILE), "utf8")
    activateAt(id)
    const seen = vault.seen.length
    const failure = (await finishAttempt(a, activeAnswer(id)).catch((e: unknown) => e)) as { code: string; message: string; next: { command: string } }
    expect(failure.code).toBe("failed")
    expect(failure.message).toContain(`Enrolment ${id} was replaced on this machine by a newer attempt (${newer})`)
    expect(failure.message).toContain(`The device ${deviceFor(id)} the vault activated for it was revoked.`)
    expect(failure.next.command).toBe(`mehen wait ${newer}`)
    expect(revokesSince(seen)).toEqual([deviceFor(id)])
    expect(vault.seen.slice(seen).find((c) => c.path === "/v1/devices/self/revoke")?.claims).toMatchObject({ ten: MOCK_TENANT, dev: deviceFor(id) })
    expect(await readFile(join(slot, "enrolment.json"), "utf8")).toBe(bRecord)
    expect(await readFile(join(slot, SOFTWARE_KEY_FILE), "utf8")).toBe(bKey)
    expect(existsSync(activeSlot())).toBe(false)
  })

  test("a superseded observer whose revoke the vault refuses says to revoke the device on the Machines page", async () => {
    const { id, slot } = await started()
    const a = await openAttempt(env, dir.path, slot, id, null)
    await replaceWithFreshKey()
    activateAt(id)
    vault.overrides.set("POST /v1/devices/self/revoke", () => Response.json({ error: "internal", message: "down" }, { status: 500, headers: { "Mehen-Error": "1" } }))
    await expect(finishAttempt(a, activeAnswer(id))).rejects.toMatchObject({ code: "failed", message: expect.stringContaining(`The vault activated device ${deviceFor(id)} for it, which this machine cannot use: revoke it on the Machines page.`) })
  })

  test("a waiting observer that finds its attempt replaced stops before signing anything more", async () => {
    const { id, slot } = await started()
    const a = await openAttempt(env, dir.path, slot, id, null)
    const newer = await replaceWithFreshKey()
    const seen = vault.seen.length
    await expect(followAttempt(a, { deadline: Date.now() + 2_000, intervalMs: 20, renew: true })).rejects.toMatchObject({ code: "failed", message: expect.stringContaining(`replaced on this machine by a newer attempt (${newer})`) })
    expect(vault.seen.slice(seen).filter((c) => c.claims.dev === id)).toEqual([])
  })

  test("late rejection after replacement: the rejection of A removes nothing, and B's record is intact", async () => {
    const { id, slot } = await started()
    const a = await openAttempt(env, dir.path, slot, id, null)
    let newer = ""
    vault.overrides.set(`GET /v1/enrol/${id}`, async () => {
      newer = await replaceWithFreshKey()
      return Response.json({ status: "rejected" })
    })
    await expect(followAttempt(a, { deadline: Date.now() + 2_000, intervalMs: 20, renew: true })).rejects.toMatchObject({ code: "failed" })
    expect(await record(slot)).toMatchObject({ id: newer, state: "pending" })
  })

  test("late renewal answer after replacement: the renewed lease of A is never written over B's record", async () => {
    vault.enrolLeaseMs = 60_000
    vault.renewIntervalMs = 0
    const { id, slot } = await started()
    const a = await openAttempt(env, dir.path, slot, id, null)
    // Under five minutes left: the observer renews.
    a.record = { ...a.record, expiresAt: new Date(Date.now() + 30_000).toISOString(), renewals: 1 }
    let newer = ""
    vault.overrides.set(`POST /v1/enrol/${id}/renew`, async () => {
      newer = await replaceWithFreshKey()
      return Response.json({ enrolment: id, expiresAt: new Date(Date.now() + 3_600_000).toISOString(), hardExpiresAt: new Date(Date.now() + 86_400_000).toISOString() })
    })
    const bBefore = async () => readFile(join(slot, "enrolment.json"), "utf8")
    await expect(followAttempt(a, { deadline: Date.now() + 2_000, intervalMs: 20, renew: true })).rejects.toMatchObject({ code: "failed" })
    const b = await record(slot)
    expect(b).toMatchObject({ id: newer, renewals: 0 })
    expect(await bBefore()).toContain(newer)
  })
})

describe("stale answers about an active slot (mutateSlot)", () => {
  // B replaces A in the workspace's slot while A's answer is in flight.
  async function landB(): Promise<{ device: string; files: Record<string, string> }> {
    const scratch = await tempDir()
    try {
      const device = await vault.enrolSoftware(scratch.path)
      const from = vault.slotDir(scratch.path)
      for (const file of ["config.json", SOFTWARE_KEY_FILE, "device-key.scope.json"]) await rename(join(from, file), join(activeSlot(), file))
      const files = Object.fromEntries(await Promise.all(["config.json", SOFTWARE_KEY_FILE, "device-key.scope.json"].map(async (f) => [f, await readFile(join(activeSlot(), f), "utf8")])))
      return { device, files }
    } finally {
      await scratch.remove()
    }
  }

  test("a stale device_revoked for A with B active clears nothing: enrol fails naming the change, B is byte for byte intact, nothing is started", async () => {
    const a = await vault.enrolSoftware(dir.path)
    let b: Awaited<ReturnType<typeof landB>> | null = null
    vault.overrides.set("GET /v1/me", async () => {
      b = await landB()
      return vaultError("device_revoked", "This device was revoked.")
    })
    const posts = vault.seen.filter((c) => c.path === "/v1/enrol").length
    const result = await runJv([...ENROL, "--json"], env)
    expect(result.code).toBe(EXIT.error)
    expect(json(result)).toMatchObject({ error: "failed", message: expect.stringContaining(`no longer holds device ${a}`) })
    const landed = b as unknown as { device: string; files: Record<string, string> }
    for (const [file, text] of Object.entries(landed.files)) expect(await readFile(join(activeSlot(), file), "utf8")).toBe(text)
    expect(vault.seen.filter((c) => c.path === "/v1/enrol").length).toBe(posts)
  })

  test("a stale display refresh for A never rewrites B's config", async () => {
    await vault.enrolSoftware(dir.path)
    let b: Awaited<ReturnType<typeof landB>> | null = null
    vault.overrides.set("GET /v1/me", async (_request, seen) => {
      b = await landB()
      // A's answer carries a rename that would be recorded over B.
      return Response.json({ tenant: MOCK_TENANT, device: seen.claims.dev, name: "m", scope: WORKSPACE_SCOPE, frozen: false, workspace: { ...MOCK_WORKSPACE, name: "Renamed while in flight" }, owner: MOCK_OWNER, displayRev: 2 })
    })
    const result = await runJv(["status", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const landed = b as unknown as { device: string; files: Record<string, string> }
    expect(await readFile(join(activeSlot(), "config.json"), "utf8")).toBe(landed.files["config.json"] as string)
    expect(await readConfig(activeSlot())).toMatchObject({ device: landed.device, workspaceName: "Mock Space" })
  })

  test("mutateSlot applies only to the device and key it was given", async () => {
    const a = await vault.enrolSoftware(dir.path)
    const jwk = await publicKeyOnDisk(activeSlot(), "software")
    expect(await mutateSlot(activeSlot(), { device: "dev_someoneElse01", jwk }, () => null)).toBe("superseded")
    expect(await mutateSlot(activeSlot(), { device: a, jwk: { x: "x".repeat(43), y: "y".repeat(43) } }, () => null)).toBe("superseded")
    expect(await readConfig(activeSlot())).toMatchObject({ device: a })
    const renamed = await mutateSlot(activeSlot(), { device: a, jwk }, (config: Config) => ({ ...config, workspaceName: "Renamed" }))
    expect(renamed).toBe("applied")
    expect(await readConfig(activeSlot())).toMatchObject({ workspaceName: "Renamed" })
    expect(await mutateSlot(activeSlot(), { device: a, jwk }, () => null)).toBe("applied")
    expect(existsSync(activeSlot())).toBe(false)
    expect(await mutateSlot(activeSlot(), { device: a, jwk }, () => null)).toBe("gone")
  })
})

describe("an enclave observer (fake mehen-se)", () => {
  let helperEnv: Record<string, string> = {}
  beforeEach(async () => {
    helperEnv = { ...env, MEHEN_SE_PATH: await fakeHelper(dir.path) }
  })
  const SE = ["--backend", "secure-enclave"]

  async function enclaveAttempt(): Promise<{ id: string; slot: string; attempt: Attempt }> {
    const result = await runJv(["enrol", "--workspace", "mock-space", "--name", "test-mac", ...SE, "--json"], helperEnv)
    expect(result.code).toBe(EXIT.ok)
    const id = json(result).enrolment as string
    const slot = json(result).slot as string
    return { id, slot, attempt: await openAttempt(helperEnv, dir.path, slot, id, null) }
  }

  test("the blob replaced (--fresh-key): the active answer for A is reported failed with manual-revoke advice; no revoke is attempted, no cleanup claimed, B is intact", async () => {
    const { id, slot, attempt } = await enclaveAttempt()
    const fresh = await runJv(["enrol", "--workspace", "mock-space", "--name", "test-mac", ...SE, "--fresh-key", "--json"], helperEnv)
    const newer = json(fresh).enrolment as string
    const bBlob = await readFile(join(slot, "device-key.se"), "utf8")
    activateAt(id)
    const seen = vault.seen.length
    const failure = (await finishAttempt(attempt, activeAnswer(id)).catch((e: unknown) => e)) as { code: string; message: string; next: { say: string } }
    expect(failure.code).toBe("failed")
    expect(failure.message).toContain(`The vault activated device ${deviceFor(id)} for it, which this machine cannot use: revoke it on the Machines page.`)
    expect(failure.message).not.toContain("was revoked")
    expect(failure.next.say).toContain(`Device ${deviceFor(id)} is active in the vault`)
    expect(revokesSince(seen)).toEqual([])
    expect(vault.seen.slice(seen)).toEqual([])
    expect(await readFile(join(slot, "device-key.se"), "utf8")).toBe(bBlob)
    expect(await record(slot)).toMatchObject({ id: newer })
  })

  // A pending --fresh-key removes the old blob before the old
  // sidecar. Stopped between the two, the old record and sidecar survive
  // without the key. The finish step must not take the sidecar for the key.
  test("an interrupted replacement that left the sidecar without its blob (or a linked or insecure blob) is never committed: failed, nothing revoked, nothing rewritten", async () => {
    const blobStates: [string, (blob: string, elsewhere: string) => Promise<void>][] = [
      ["blob removed", async (blob) => rm(blob)],
      ["blob a link to a copy", async (blob, elsewhere) => {
        await rename(blob, join(elsewhere, "device-key.se"))
        await symlink(join(elsewhere, "device-key.se"), blob)
      }],
      ["blob readable by others", async (blob) => chmod(blob, 0o644)],
    ]
    for (const [label, damage] of blobStates) {
      await rm(join(dir.path, "pending"), { recursive: true, force: true })
      const { id, slot, attempt } = await enclaveAttempt()
      const elsewhere = await tempDir()
      try {
        await damage(join(slot, "device-key.se"), elsewhere.path)
        const recordBefore = await readFile(join(slot, "enrolment.json"), "utf8")
        const sidecarBefore = await readFile(join(slot, "device-key.se.pub.json"), "utf8")
        activateAt(id)
        const seen = vault.seen.length
        const failure = (await finishAttempt(attempt, activeAnswer(id)).catch((e: unknown) => e)) as { code: string; message: string }
        expect(failure.code, label).toBe("failed")
        expect(failure.message, label).toContain(`The vault activated device ${deviceFor(id)} for it, which this machine cannot use: revoke it on the Machines page.`)
        expect(existsSync(activeSlot()), label).toBe(false)
        expect(vault.seen.slice(seen), label).toEqual([])
        expect(await readFile(join(slot, "enrolment.json"), "utf8"), label).toBe(recordBefore)
        expect(await readFile(join(slot, "device-key.se.pub.json"), "utf8"), label).toBe(sidecarBefore)
        // A waiter in the same state signs nothing either.
        await expect(followAttempt(attempt, { deadline: Date.now() + 1_000, intervalMs: 20, renew: true }), label).rejects.toMatchObject({ code: "failed" })
        expect(vault.seen.slice(seen), label).toEqual([])
      } finally {
        await elsewhere.remove()
      }
    }
  })

  test("the blob renamed by another observer's commit: the waiter never signs through the old path, follows the key to its active slot and finishes as success", async () => {
    const { id, slot, attempt } = await enclaveAttempt()
    vault.enrolOutcome = { pendingPolls: 0, result: "active" }
    const committed = await runJv(["wait", id, "--json"], helperEnv)
    expect(committed.code).toBe(EXIT.ok)
    expect(existsSync(slot)).toBe(false)
    const seen = vault.seen.length
    const followed = await followAttempt(attempt, { deadline: Date.now() + 2_000, intervalMs: 20, renew: true })
    expect(followed).toMatchObject({ kind: "finished", finished: { already: true, slot: activeSlot(), config: { device: deviceFor(id), backend: "secure-enclave" } } })
    expect(revokesSince(seen)).toEqual([])
    // The one poll it made verified against the key: signed by the moved blob.
    expect(vault.seen.slice(seen).map((c) => c.path)).toEqual([`/v1/enrol/${id}`])
    expect(await readKeyScope(activeSlot(), "secure-enclave")).toEqual({ vault: vault.url, tenant: MOCK_TENANT })
  })

  test("a pending slot whose blob is gone with nothing committed anywhere: failed, nothing signed", async () => {
    const { id, slot, attempt } = await enclaveAttempt()
    await rm(slot, { recursive: true })
    await mkdir(join(dir.path, "workspaces"), { recursive: true, mode: 0o700 })
    const seen = vault.seen.length
    await expect(followAttempt(attempt, { deadline: Date.now() + 1_000, intervalMs: 20, renew: true })).rejects.toMatchObject({ code: "failed", message: expect.stringContaining(`The local record of enrolment ${id} is gone`) })
    expect(vault.seen.length).toBe(seen)
  })
})
