import { afterEach, beforeEach, expect, test } from "bun:test"
import { chmod, mkdir, readFile, readdir, stat, symlink, unlink, utimes, writeFile } from "node:fs/promises"
import { join } from "node:path"
import type { RelayRequestInput } from "@mehen/protocol/api"
import { base64UrlEncode, utf8 } from "@mehen/protocol/bytes"
import { CliError } from "./errors.ts"
import { MAX_REPLAY_BODY_BYTES, REPLAY_TTL_SECONDS, SWEEP_BUDGET, claimSavedRequest, neverSent, readSavedRequest, saveHeldRequest, savedRequestPath, withApprovalLock } from "./replay-cache.ts"
import { RelayOutcomeUnknownError, VaultApiError, VaultNetworkError } from "./vault-api.ts"
import { tempDir } from "./testing/run-mehen.ts"

let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_HOME: join(dir.path, "home") }
})
afterEach(() => dir.remove())

const owner = { vault: "https://vault.example", workspace: "tn_work00000001", device: "dev_one" }
const now = new Date("2026-11-20T10:00:00.000Z")
const request: RelayRequestInput = { item: "gmail-support", method: "POST", url: "https://gmail.googleapis.com/send", headers: [["Content-Type", "application/json"]], body: base64UrlEncode(utf8('{"to":"sam@example.com"}')), session: "agent-1", context: { project: "prj_3kQ9vXyZ7", environment: "prod" } }

async function refusal(promise: Promise<unknown>): Promise<CliError> {
  try {
    await promise
  } catch (error) {
    if (error instanceof CliError) return error
    throw error
  }
  throw new Error("expected a refusal")
}

test("a held request is saved 0600 in a 0700 folder, as the agent sent it, without its approval or replaces", async () => {
  const note = await saveHeldRequest(env, owner, "apr_1", { ...request, approval: "apr_old", replaces: "apr_older" }, now)
  expect(note).toEqual({ saved: true, expiresAt: "2026-11-20T11:00:00.000Z" })
  const path = savedRequestPath(env, "apr_1")
  expect(path).toBe(join(env.MEHEN_HOME as string, "pending-requests", "apr_1.json"))
  expect((await stat(path)).mode & 0o777).toBe(0o600)
  expect((await stat(join(env.MEHEN_HOME as string, "pending-requests"))).mode & 0o777).toBe(0o700)
  const saved = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>
  expect(saved).toEqual({ version: 1, approval: "apr_1", createdAt: now.toISOString(), ...owner, request })
})

test("a body over the approval body limit is not saved, and the note says why", async () => {
  expect(MAX_REPLAY_BODY_BYTES).toBe(64 * 1024)
  const big = { ...request, body: base64UrlEncode(new Uint8Array(MAX_REPLAY_BODY_BYTES + 1)) }
  const note = await saveHeldRequest(env, owner, "apr_big", big, now)
  expect(note).toMatchObject({ saved: false })
  expect(note.saved === false && note.reason).toContain("64 KiB")
  await expect(stat(savedRequestPath(env, "apr_big"))).rejects.toMatchObject({ code: "ENOENT" })
  expect((await saveHeldRequest(env, owner, "apr_edge", { ...request, body: base64UrlEncode(new Uint8Array(MAX_REPLAY_BODY_BYTES)) }, now)).saved).toBe(true)
})

test("an id that is not an approval id is never a file name", async () => {
  for (const id of ["../apr_1", "apr_1/x", "int_1", "apr_"]) {
    expect((await saveHeldRequest(env, owner, id, request, now)).saved).toBe(false)
    expect((await refusal(readSavedRequest(env, id, now))).code).toBe("usage")
  }
})

test("a saved request is claimed once: the claim removes it, and a second is replay_missing", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const saved = await readSavedRequest(env, "apr_1", now)
  const claimed = await claimSavedRequest(env, saved, owner)
  expect(claimed.request).toEqual({ ...request, approval: "apr_1" })
  await expect(stat(savedRequestPath(env, "apr_1"))).rejects.toMatchObject({ code: "ENOENT" })
  await claimed.spent()
  const again = await refusal(readSavedRequest(env, "apr_1", now))
  expect(again.code).toBe("replay_missing")
  expect(again.next?.say).toContain("byte for byte")
  expect((await refusal(claimSavedRequest(env, saved, owner))).code).toBe("replay_missing")
})

// A claim that never reached the network (a local failure, a connection
// refused for a write) puts the request back; one that may have is spent.
test("a claim that was never sent is put back, and only it", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const claimed = await claimSavedRequest(env, await readSavedRequest(env, "apr_1", now), owner)
  await claimed.unsent()
  const again = await claimSavedRequest(env, await readSavedRequest(env, "apr_1", now), owner)
  expect(again.request.approval).toBe("apr_1")
  await again.spent()
  // The marker stays for the hour, so the approval is not saved again.
  expect((await readdir(join(env.MEHEN_HOME as string, "pending-requests"))).filter((name) => name !== ".swept")).toEqual(["apr_1.spent"])
  const write = { method: "POST" }, read = { method: "GET" }
  const aborted = AbortSignal.abort()
  const live = new AbortController().signal
  expect(neverSent(new Error("signing failed"), write, live)).toBe(true)
  expect(neverSent(new VaultNetworkError("refused"), write, live)).toBe(true)
  expect(neverSent(new VaultNetworkError("refused"), read, live)).toBe(false)
  expect(neverSent(new RelayOutcomeUnknownError("maybe"), write, live)).toBe(false)
  expect(neverSent(new VaultApiError(403, { error: "forbidden", message: "no" }), write, live)).toBe(false)
  expect(neverSent(new Error("aborted"), write, aborted)).toBe(false)
})

test("an entry past its hour is removed when read and is replay_missing", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const later = new Date(now.getTime() + REPLAY_TTL_SECONDS * 1000 + 1)
  const expired = await refusal(readSavedRequest(env, "apr_1", later))
  expect(expired.code).toBe("replay_missing")
  expect(expired.message).toContain("expired")
  await expect(stat(savedRequestPath(env, "apr_1"))).rejects.toMatchObject({ code: "ENOENT" })
})

test("a request saved by another machine or workspace is refused and kept", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const saved = await readSavedRequest(env, "apr_1", now)
  for (const other of [{ ...owner, device: "dev_two" }, { ...owner, workspace: "tn_other0000001" }, { ...owner, vault: "https://other.example" }]) {
    const refused = await refusal(claimSavedRequest(env, saved, other))
    expect(refused.code).toBe("replay_missing")
    expect(refused.message).toContain("another")
  }
  expect((await stat(savedRequestPath(env, "apr_1"))).isFile()).toBe(true)
})

test("a file other users can read, a link or a file that is not a saved request is refused before it is used", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const path = savedRequestPath(env, "apr_1")
  await chmod(path, 0o640)
  const open = await refusal(readSavedRequest(env, "apr_1", now))
  expect(open.code).toBe("failed")
  expect(open.message).toContain("other users")
  await chmod(path, 0o600)
  await writeFile(join(dir.path, "elsewhere.json"), await readFile(path, "utf8"))
  const linked = savedRequestPath(env, "apr_2")
  await symlink(join(dir.path, "elsewhere.json"), linked)
  expect((await refusal(readSavedRequest(env, "apr_2", now))).message).toContain("symbolic link")
  await writeFile(savedRequestPath(env, "apr_3"), "{}", { mode: 0o600 })
  expect((await refusal(readSavedRequest(env, "apr_3", now))).code).toBe("replay_missing")
})

test("saving sweeps entries past their hour, and leaves newer ones", async () => {
  await saveHeldRequest(env, owner, "apr_old", request, now)
  await saveHeldRequest(env, owner, "apr_new", request, now)
  const old = new Date(now.getTime() - 2 * REPLAY_TTL_SECONDS * 1000)
  await utimes(savedRequestPath(env, "apr_old"), old, old)
  // A minute on, the next save sweeps again.
  await saveHeldRequest(env, owner, "apr_third", request, new Date(now.getTime() + 61_000))
  expect((await readdir(join(env.MEHEN_HOME as string, "pending-requests"))).filter((name) => name !== ".swept").sort()).toEqual(["apr_new.json", "apr_third.json"])
})

// The vault reuses one pending approval for identical asks, so a duplicate
// request's save can land after the first was claimed and sent. Save, claim
// and restore share per-approval state: a lock, and a marker kept for the
// entry's hour once the approval is claimed.
test("a save delayed across a claim and its send does not publish the approval again", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  let release: () => void = () => undefined
  const barrier = new Promise<void>((resolve) => (release = resolve))
  let reached: () => void = () => undefined
  const paused = new Promise<void>((resolve) => (reached = resolve))
  const late = saveHeldRequest(env, owner, "apr_1", request, now, { beforeLock: async () => { reached(); await barrier } })
  await paused
  const claimed = await claimSavedRequest(env, await readSavedRequest(env, "apr_1", now), owner)
  await claimed.spent()
  release()
  const note = await late
  expect(note).toMatchObject({ saved: false })
  expect(note.saved === false && note.reason).toContain("already sent again")
  await expect(stat(savedRequestPath(env, "apr_1"))).rejects.toMatchObject({ code: "ENOENT" })
  expect((await refusal(readSavedRequest(env, "apr_1", now))).code).toBe("replay_missing")
  // An in-flight claim refuses a save the same way.
  await saveHeldRequest(env, owner, "apr_2", request, now)
  const flying = await claimSavedRequest(env, await readSavedRequest(env, "apr_2", now), owner)
  expect((await saveHeldRequest(env, owner, "apr_2", request, now)).saved).toBe(false)
  await flying.spent()
})

test("a restore puts back only its own claim, and never once a newer claim of the approval exists", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const a = await claimSavedRequest(env, await readSavedRequest(env, "apr_1", now), owner)
  // Nobody else can claim or save it while a has it.
  expect((await saveHeldRequest(env, owner, "apr_1", request, now)).saved).toBe(false)
  await a.unsent()
  const b = await claimSavedRequest(env, await readSavedRequest(env, "apr_1", now), owner)
  await b.spent()
  // a's second restore (a stale one) finds a newer claim and puts nothing back.
  await a.unsent()
  await expect(stat(savedRequestPath(env, "apr_1"))).rejects.toMatchObject({ code: "ENOENT" })
  expect((await refusal(readSavedRequest(env, "apr_1", now))).code).toBe("replay_missing")
  expect((await saveHeldRequest(env, owner, "apr_1", request, now)).saved).toBe(false)
})

// A lock is never broken by age: its holders only rename and write small
// files, so a contender waits about two seconds and then fails closed.
test("two contenders for one approval's lock are never both in", async () => {
  await mkdir(join(env.MEHEN_HOME as string, "pending-requests"), { recursive: true, mode: 0o700 })
  const events: string[] = []
  let release: () => void = () => undefined
  const barrier = new Promise<void>((resolve) => (release = resolve))
  let entered: () => void = () => undefined
  const inside = new Promise<void>((resolve) => (entered = resolve))
  const a = withApprovalLock(env, "apr_1", async () => {
    events.push("a in")
    entered()
    await barrier
    events.push("a out")
  })
  await inside
  const b = withApprovalLock(env, "apr_1", async () => {
    events.push("b in")
  })
  await Bun.sleep(100)
  expect(events).toEqual(["a in"])
  release()
  await Promise.all([a, b])
  expect(events).toEqual(["a in", "a out", "b in"])
})

test("a lock a crashed holder left, however old, is replay_locked naming its path, pid and host, and a save is not saved: locked", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const lock = join(env.MEHEN_HOME as string, "pending-requests", "apr_1.lock")
  await writeFile(lock, `${JSON.stringify({ token: "crashed", pid: 4242, host: "old-box" })}\n`, { mode: 0o600 })
  const old = new Date(Date.now() - 2 * REPLAY_TTL_SECONDS * 1000)
  await utimes(lock, old, old)
  const started = Date.now()
  const locked = await refusal(claimSavedRequest(env, await readSavedRequest(env, "apr_1", now), owner))
  expect(Date.now() - started).toBeGreaterThanOrEqual(1500)
  expect(locked.code).toBe("replay_locked")
  for (const part of [lock, "4242", "old-box"]) expect(locked.message).toContain(part)
  expect(locked.next?.say).toContain(`delete ${lock}`)
  expect(await saveHeldRequest(env, owner, "apr_1", request, now)).toEqual({ saved: false, reason: "locked" })
  // Nothing broke the lock, the sweep included, and the saved request is as it was.
  expect((await stat(lock)).isFile()).toBe(true)
  expect((await stat(savedRequestPath(env, "apr_1"))).isFile()).toBe(true)
})

test("a holder releases only its own lock", async () => {
  await mkdir(join(env.MEHEN_HOME as string, "pending-requests"), { recursive: true, mode: 0o700 })
  const lock = join(env.MEHEN_HOME as string, "pending-requests", "apr_1.lock")
  await withApprovalLock(env, "apr_1", async () => {
    // Someone replaced the lock under this holder (by hand, say).
    await unlink(lock)
    await writeFile(lock, `${JSON.stringify({ token: "someone-else", pid: 1, host: "h" })}\n`, { mode: 0o600 })
  })
  expect(JSON.parse(await readFile(lock, "utf8"))).toMatchObject({ token: "someone-else" })
  await unlink(lock)
  await withApprovalLock(env, "apr_1", async () => undefined)
  await expect(stat(lock)).rejects.toMatchObject({ code: "ENOENT" })
})

// A marker or lock is read as any other file mehen keeps there: a regular
// file this user owns, nobody else can open, small, with a token mehen wrote.
test("a marker that is a link, not a regular file, open to others, oversized or not mehen's refuses the claim and the save", async () => {
  const folder = join(env.MEHEN_HOME as string, "pending-requests")
  const marker = join(folder, "apr_1.spent")
  const cases: [string, () => Promise<void>][] = [
    ["link", () => symlink(join(dir.path, "elsewhere"), marker)],
    ["fifo", async () => { expect(Bun.spawnSync(["mkfifo", "-m", "600", marker]).exitCode).toBe(0) }],
    ["open", () => writeFile(marker, "1.1.abc", { mode: 0o644 }).then(() => chmod(marker, 0o644))],
    ["large", () => writeFile(marker, "x".repeat(4096), { mode: 0o600 })],
    ["foreign", () => writeFile(marker, "not a token\n", { mode: 0o600 })],
  ]
  for (const [name, make] of cases) {
    await saveHeldRequest(env, owner, "apr_1", request, now)
    await make()
    const claim = await refusal(claimSavedRequest(env, await readSavedRequest(env, "apr_1", now), owner))
    expect(claim.code, name).toBe("failed")
    expect(claim.message, name).toContain(marker)
    const note = await saveHeldRequest(env, owner, "apr_1", request, now)
    expect(note.saved, name).toBe(false)
    expect((await stat(savedRequestPath(env, "apr_1"))).isFile(), name).toBe(true)
    await unlink(marker)
  }
})

// The sweep is throttled to once a minute and examines a bounded number of
// entries, so one save never walks a folder of any size.
test("one save examines at most the sweep's budget, sweeps at most once a minute, and never removes a lock", async () => {
  const folder = join(env.MEHEN_HOME as string, "pending-requests")
  await mkdir(folder, { recursive: true, mode: 0o700 })
  const old = new Date(now.getTime() - 2 * REPLAY_TTL_SECONDS * 1000)
  const count = SWEEP_BUDGET + 100
  for (let i = 0; i < count; i++) {
    const path = join(folder, `apr_old${i}.json`)
    await writeFile(path, "{}", { mode: 0o600 })
    await utimes(path, old, old)
  }
  await writeFile(join(folder, "apr_held.lock"), "{}", { mode: 0o600 })
  await utimes(join(folder, "apr_held.lock"), old, old)
  const left = async () => (await readdir(folder)).filter((name) => name.startsWith("apr_old")).length
  await saveHeldRequest(env, owner, "apr_new", request, now)
  const afterFirst = await left()
  expect(afterFirst).toBeGreaterThanOrEqual(count - SWEEP_BUDGET)
  expect(afterFirst).toBeLessThan(count)
  await saveHeldRequest(env, owner, "apr_newer", request, new Date(now.getTime() + 30_000))
  expect(await left()).toBe(afterFirst)
  await saveHeldRequest(env, owner, "apr_newest", request, new Date(now.getTime() + 61_000))
  expect(await left()).toBeLessThan(afterFirst)
  expect((await stat(join(folder, "apr_held.lock"))).isFile()).toBe(true)
})
