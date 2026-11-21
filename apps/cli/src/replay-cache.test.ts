import { afterEach, beforeEach, expect, test } from "bun:test"
import { chmod, mkdir, readFile, readdir, stat, symlink, utimes, writeFile } from "node:fs/promises"
import { join } from "node:path"
import type { RelayRequestInput } from "@mehen/protocol/api"
import { base64UrlEncode, utf8 } from "@mehen/protocol/bytes"
import { CliError } from "./errors.ts"
import { MAX_REPLAY_BODY_BYTES, REPLAY_TTL_SECONDS, SWEEP_BUDGET, claimSavedRequest, neverSent, readSavedRequest, replayFs, saveHeldRequest, savedRequestPath } from "./replay-cache.ts"
import { tempDir } from "./testing/run-mehen.ts"
import { RelayOutcomeUnknownError, VaultApiError, VaultNetworkError } from "./vault-api.ts"

let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>
const realFs = { ...replayFs }
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_HOME: join(dir.path, "home") }
})
afterEach(async () => {
  Object.assign(replayFs, realFs)
  await dir.remove()
})

const owner = { vault: "https://vault.example", workspace: "tn_work00000001", device: "dev_one" }
const now = new Date("2026-11-20T10:00:00.000Z")
const request: RelayRequestInput = { item: "gmail-support", method: "POST", url: "https://gmail.googleapis.com/send", headers: [["Content-Type", "application/json"]], body: base64UrlEncode(utf8('{"to":"sam@example.com"}')), session: "agent-1", context: { project: "prj_3kQ9vXyZ7", environment: "prod" } }

const folder = () => join(env.MEHEN_HOME as string, "pending-requests")
const markerFile = (approval: string) => join(folder(), `${approval}.spent`)
const listed = async () => (await readdir(folder())).filter((name) => name !== ".swept").sort()
const claim = async (approval = "apr_1") => claimSavedRequest(env, await readSavedRequest(env, approval, now), owner, now)
// Fault injection: an operation that fails as a full disk or a failing
// device would; afterEach puts the real ones back.
const failing = (code: string) => async () => {
  throw Object.assign(new Error(`${code}: injected`), { code })
}

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
  expect((await stat(folder())).mode & 0o777).toBe(0o700)
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

// The marker, created exclusively, is the single-use gate: the request
// file never moves, and only the sweep deletes anything.
test("a claim marks the approval spent and leaves the request where it is; a second claim is replay_missing", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const claimed = await claim()
  expect(claimed.request).toEqual({ ...request, approval: "apr_1" })
  await claimed.spent()
  expect(await listed()).toEqual(["apr_1.json", "apr_1.spent"])
  expect((await stat(markerFile("apr_1"))).mode & 0o777).toBe(0o600)
  const again = await refusal(claim())
  expect(again.code).toBe("replay_missing")
  expect(again.next?.say).toContain("byte for byte")
})

test("concurrent claims of one approval: exactly one wins", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const saved = await readSavedRequest(env, "apr_1", now)
  const results = await Promise.allSettled(Array.from({ length: 8 }, () => claimSavedRequest(env, saved, owner, now)))
  expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1)
  for (const result of results) if (result.status === "rejected") expect((result.reason as CliError).code).toBe("replay_missing")
})

test("a save after a spend does nothing and says spent", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  await (await claim()).spent()
  const before = await readFile(savedRequestPath(env, "apr_1"), "utf8")
  expect(await saveHeldRequest(env, owner, "apr_1", { ...request, url: "https://other.example/" }, now)).toEqual({ saved: false, reason: "spent" })
  expect(await readFile(savedRequestPath(env, "apr_1"), "utf8")).toBe(before)
})

test("a never-sent failure frees the replay, and the corrected claim gets it once", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  await (await claim()).unsent()
  expect(await listed()).toEqual(["apr_1.json"])
  const again = await claim()
  await again.spent()
  expect((await refusal(claim())).code).toBe("replay_missing")
})

// What neverSent says decides between spent and unsent: an outcome that may
// have reached the vault keeps the approval spent.
test("only a failure that certainly never left frees the replay", () => {
  const write = { method: "POST" }, read = { method: "GET" }
  const live = new AbortController().signal
  expect(neverSent(new Error("signing failed"), write, live)).toBe(true)
  expect(neverSent(new VaultNetworkError("refused"), write, live)).toBe(true)
  expect(neverSent(new VaultNetworkError("refused"), read, live)).toBe(false)
  expect(neverSent(new RelayOutcomeUnknownError("maybe"), write, live)).toBe(false)
  expect(neverSent(new VaultApiError(403, { error: "forbidden", message: "no" }), write, live)).toBe(false)
  expect(neverSent(new Error("aborted"), write, AbortSignal.abort())).toBe(false)
})

test("an unsent claim removes only its own marker", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const claimed = await claim()
  await writeFile(markerFile("apr_1"), "1.1.someoneelse", { mode: 0o600 })
  await claimed.unsent()
  expect(await readFile(markerFile("apr_1"), "utf8")).toBe("1.1.someoneelse")
})

test("marker creation that fails sends nothing and leaves the request intact", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const before = await readFile(savedRequestPath(env, "apr_1"), "utf8")
  replayFs.createMarker = failing("ENOSPC")
  const refused = await refusal(claim())
  expect(refused.code).toBe("failed")
  expect(refused.message).toContain("ENOSPC")
  expect(await listed()).toEqual(["apr_1.json"])
  expect(await readFile(savedRequestPath(env, "apr_1"), "utf8")).toBe(before)
})

test("a read that fails after the marker removes the marker, or names it when it cannot", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const saved = await readSavedRequest(env, "apr_1", now)
  replayFs.readRequest = failing("EIO")
  const refused = await refusal(claimSavedRequest(env, saved, owner, now))
  expect(refused.message).toContain("EIO")
  expect(await listed()).toEqual(["apr_1.json"])
  replayFs.unlink = failing("EROFS")
  const stuck = await refusal(claimSavedRequest(env, saved, owner, now))
  expect(stuck.message).toContain(markerFile("apr_1"))
  expect(stuck.next?.say).toContain(`delete ${markerFile("apr_1")}`)
  expect(await listed()).toEqual(["apr_1.json", "apr_1.spent"])
})

test("a marker that cannot be removed after a never-sent failure is named, with how to free the replay", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const claimed = await claim()
  replayFs.unlink = failing("EROFS")
  const refused = await refusal(claimed.unsent())
  expect(refused.message).toContain(markerFile("apr_1"))
  expect(refused.next?.say).toContain(`Deleting ${markerFile("apr_1")} lets the request be sent again`)
})

test("a request expired by the time it is read or claimed is replay_missing, and nothing is deleted", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const later = new Date(now.getTime() + REPLAY_TTL_SECONDS * 1000 + 1)
  const expired = await refusal(readSavedRequest(env, "apr_1", later))
  expect(expired.code).toBe("replay_missing")
  expect(expired.message).toContain("expired")
  const saved = await readSavedRequest(env, "apr_1", now)
  expect((await refusal(claimSavedRequest(env, saved, owner, later))).code).toBe("replay_missing")
  expect(await listed()).toEqual(["apr_1.json"])
})

test("a request saved by another machine or workspace is refused, and nothing is marked", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const saved = await readSavedRequest(env, "apr_1", now)
  for (const other of [{ ...owner, device: "dev_two" }, { ...owner, workspace: "tn_other0000001" }, { ...owner, vault: "https://other.example" }]) {
    const refused = await refusal(claimSavedRequest(env, saved, other, now))
    expect(refused.code).toBe("replay_missing")
    expect(refused.message).toContain("another")
  }
  expect(await listed()).toEqual(["apr_1.json"])
})

test("a request file other users can read, a link or a file that is not a saved request is refused before it is used", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, now)
  const path = savedRequestPath(env, "apr_1")
  await chmod(path, 0o640)
  const open = await refusal(readSavedRequest(env, "apr_1", now))
  expect(open.code).toBe("failed")
  expect(open.message).toContain("other users")
  await chmod(path, 0o600)
  await writeFile(join(dir.path, "elsewhere.json"), await readFile(path, "utf8"))
  await symlink(join(dir.path, "elsewhere.json"), savedRequestPath(env, "apr_2"))
  expect((await refusal(readSavedRequest(env, "apr_2", now))).message).toContain("symbolic link")
  expect(Bun.spawnSync(["mkfifo", "-m", "600", savedRequestPath(env, "apr_4")]).exitCode).toBe(0)
  expect((await refusal(readSavedRequest(env, "apr_4", now))).message).toContain("not a regular file")
  await writeFile(savedRequestPath(env, "apr_3"), "{}", { mode: 0o600 })
  expect((await refusal(readSavedRequest(env, "apr_3", now))).code).toBe("replay_missing")
})

// Whatever is at the marker's path, the gate holds: a claim cannot create
// it, a save will not write, and an unsent claim removes only what it can
// read as its own token.
test("a marker that is a link, a FIFO, open to others or not mehen's keeps the approval spent and is never followed", async () => {
  const cases: [string, () => Promise<void>][] = [
    ["link", () => symlink(join(dir.path, "elsewhere"), markerFile("apr_1"))],
    ["fifo", async () => { expect(Bun.spawnSync(["mkfifo", "-m", "600", markerFile("apr_1")]).exitCode).toBe(0) }],
    ["open", () => writeFile(markerFile("apr_1"), "1.1.abc", { mode: 0o644 }).then(() => chmod(markerFile("apr_1"), 0o644))],
    ["foreign", () => writeFile(markerFile("apr_1"), "x".repeat(4096), { mode: 0o600 })],
  ]
  for (const [name, make] of cases) {
    await saveHeldRequest(env, owner, "apr_1", request, now)
    await make()
    expect((await refusal(claim())).code, name).toBe("replay_missing")
    expect(await saveHeldRequest(env, owner, "apr_1", request, now), name).toEqual({ saved: false, reason: "spent" })
    await Bun.$`rm -f ${markerFile("apr_1")}`
  }
  await expect(stat(join(dir.path, "elsewhere"))).rejects.toMatchObject({ code: "ENOENT" })
})

// The sweep is best effort: throttled to about once a minute by the mtime
// of .swept, and bounded, so one save never walks a folder of any size.
test("one save examines at most the sweep's budget, sweeps about once a minute, and two sweeps at once are harmless", async () => {
  await mkdir(folder(), { recursive: true, mode: 0o700 })
  const old = new Date(now.getTime() - 2 * REPLAY_TTL_SECONDS * 1000)
  const count = SWEEP_BUDGET + 100
  for (let i = 0; i < count; i++) {
    const path = join(folder(), `apr_old${i}.json`)
    await writeFile(path, "{}", { mode: 0o600 })
    await utimes(path, old, old)
  }
  const left = async () => (await readdir(folder())).filter((name) => name.startsWith("apr_old")).length
  await saveHeldRequest(env, owner, "apr_new", request, now)
  const afterFirst = await left()
  expect(afterFirst).toBeGreaterThanOrEqual(count - SWEEP_BUDGET)
  expect(afterFirst).toBeLessThan(count)
  await saveHeldRequest(env, owner, "apr_newer", request, new Date(now.getTime() + 30_000))
  expect(await left()).toBe(afterFirst)
  const later = new Date(now.getTime() + 61_000)
  const notes = await Promise.all([saveHeldRequest(env, owner, "apr_a", request, later), saveHeldRequest(env, owner, "apr_b", request, later)])
  expect(notes.every((note) => note.saved)).toBe(true)
  expect(await left()).toBeLessThan(afterFirst)
  expect((await listed()).filter((name) => !name.startsWith("apr_old"))).toEqual(["apr_a.json", "apr_b.json", "apr_new.json", "apr_newer.json"])
})

test("the sweep removes requests, markers and temp files past the hour, and nothing newer", async () => {
  await saveHeldRequest(env, owner, "apr_keep", request, now)
  const old = new Date(now.getTime() - 2 * REPLAY_TTL_SECONDS * 1000)
  for (const name of ["apr_1.json", "apr_1.spent", "apr_2.json.1.1.tmp"]) {
    await writeFile(join(folder(), name), "", { mode: 0o600 })
    await utimes(join(folder(), name), old, old)
  }
  await saveHeldRequest(env, owner, "apr_new", request, new Date(now.getTime() + 61_000))
  expect(await listed()).toEqual(["apr_keep.json", "apr_new.json"])
})
