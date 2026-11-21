import { afterEach, beforeEach, expect, test } from "bun:test"
import { chmod, mkdir, readFile, readdir, stat, symlink, utimes, writeFile } from "node:fs/promises"
import { join } from "node:path"
import type { RelayRequestInput } from "@mehen/protocol/api"
import { base64UrlEncode, utf8 } from "@mehen/protocol/bytes"
import { CliError } from "./errors.ts"
import { APPROVAL_TTL_MS } from "@mehen/protocol/approval-ttl"
import { MAX_REPLAY_BODY_BYTES, PENDING_APPROVAL_SECONDS, REPLAY_TTL_SECONDS, SKEW_SECONDS, SWEEP_AGE_SECONDS, SWEEP_BUDGET, claimSavedRequest, neverSent, readSavedRequest, replayFs, replaySeams, replayClock, saveHeldRequest, savedRequestPath } from "./replay-cache.ts"
import { sendFetch } from "./commands/fetch.ts"
import type { VaultSession } from "./session.ts"
import type { VaultApi } from "./vault-api.ts"
import { tempDir } from "./testing/run-mehen.ts"
import { RelayOutcomeUnknownError, VaultApiError, VaultNetworkError } from "./vault-api.ts"

let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>
const realFs = { ...replayFs }
const realSeams = { ...replaySeams }
const realClock = { ...replayClock }
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_HOME: join(dir.path, "home") }
})
afterEach(async () => {
  Object.assign(replayFs, realFs)
  for (const key of Object.keys(replaySeams)) delete replaySeams[key as keyof typeof replaySeams]
  Object.assign(replaySeams, realSeams)
  Object.assign(replayClock, realClock)
  await dir.remove()
})

const owner = { vault: "https://vault.example", workspace: "tn_work00000001", device: "dev_one" }
const now = new Date("2026-11-20T10:00:00.000Z")
// A clock fixed at one moment; a test that moves time mid-call uses its own.
const at = (date: Date) => () => date.getTime()
const request: RelayRequestInput = { item: "gmail-support", method: "POST", url: "https://gmail.googleapis.com/send", headers: [["Content-Type", "application/json"]], body: base64UrlEncode(utf8('{"to":"sam@example.com"}')), session: "agent-1", context: { project: "prj_3kQ9vXyZ7", environment: "prod" } }

const folder = () => join(env.MEHEN_HOME as string, "pending-requests")
const markerFile = (approval: string) => join(folder(), `${approval}.spent`)
const listed = async () => (await readdir(folder())).filter((name) => name !== ".swept").sort()
const claim = async (approval = "apr_1") => claimSavedRequest(env, await readSavedRequest(env, approval, at(now)), owner, at(now))
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
  const note = await saveHeldRequest(env, owner, "apr_1", { ...request, approval: "apr_old", replaces: "apr_older" }, { clock: at(now) })
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
  const note = await saveHeldRequest(env, owner, "apr_big", big, { clock: at(now) })
  expect(note).toMatchObject({ saved: false })
  expect(note.saved === false && note.reason).toContain("64 KiB")
  await expect(stat(savedRequestPath(env, "apr_big"))).rejects.toMatchObject({ code: "ENOENT" })
  expect((await saveHeldRequest(env, owner, "apr_edge", { ...request, body: base64UrlEncode(new Uint8Array(MAX_REPLAY_BODY_BYTES)) }, { clock: at(now) })).saved).toBe(true)
})

test("an id that is not an approval id is never a file name", async () => {
  for (const id of ["../apr_1", "apr_1/x", "int_1", "apr_"]) {
    expect((await saveHeldRequest(env, owner, id, request, { clock: at(now) })).saved).toBe(false)
    expect((await refusal(readSavedRequest(env, id, at(now)))).code).toBe("usage")
  }
})

// The marker, created exclusively, is the single-use gate: the request
// file never moves, and only the sweep deletes anything.
test("a claim marks the approval spent and leaves the request where it is; a second claim is replay_missing", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
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
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
  const saved = await readSavedRequest(env, "apr_1", at(now))
  const results = await Promise.allSettled(Array.from({ length: 8 }, () => claimSavedRequest(env, saved, owner, at(now))))
  expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1)
  for (const result of results) if (result.status === "rejected") expect((result.reason as CliError).code).toBe("replay_missing")
})

test("a save after a spend does nothing and says spent", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
  await (await claim()).spent()
  const before = await readFile(savedRequestPath(env, "apr_1"), "utf8")
  expect(await saveHeldRequest(env, owner, "apr_1", { ...request, url: "https://other.example/" }, { clock: at(now) })).toEqual({ saved: false, reason: "spent" })
  expect(await readFile(savedRequestPath(env, "apr_1"), "utf8")).toBe(before)
})

test("a never-sent failure frees the replay, and the corrected claim gets it once", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
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

test("an unsent claim removes only its own marker: another claim's is kept and named", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
  const claimed = await claim()
  await writeFile(markerFile("apr_1"), "1.1.someoneelse", { mode: 0o600 })
  const refused = await refusal(claimed.unsent())
  expect(refused.message).toContain(markerFile("apr_1"))
  expect(await readFile(markerFile("apr_1"), "utf8")).toBe("1.1.someoneelse")
})

test("marker creation that fails sends nothing and leaves the request intact", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
  const before = await readFile(savedRequestPath(env, "apr_1"), "utf8")
  replayFs.createMarker = failing("ENOSPC")
  const refused = await refusal(claim())
  expect(refused.code).toBe("failed")
  expect(refused.message).toContain("ENOSPC")
  expect(await listed()).toEqual(["apr_1.json"])
  expect(await readFile(savedRequestPath(env, "apr_1"), "utf8")).toBe(before)
})

test("a read that fails after the marker removes the marker, or names it when it cannot", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
  const saved = await readSavedRequest(env, "apr_1", at(now))
  replayFs.readRequest = failing("EIO")
  const refused = await refusal(claimSavedRequest(env, saved, owner, at(now)))
  expect(refused.message).toContain("EIO")
  expect(await listed()).toEqual(["apr_1.json"])
  replayFs.unlink = failing("EROFS")
  const stuck = await refusal(claimSavedRequest(env, saved, owner, at(now)))
  expect(stuck.message).toContain(markerFile("apr_1"))
  expect(stuck.next?.say).toContain(`delete ${markerFile("apr_1")}`)
  expect(await listed()).toEqual(["apr_1.json", "apr_1.spent"])
})

test("a marker that cannot be removed after a never-sent failure is named, with how to free the replay", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
  const claimed = await claim()
  replayFs.unlink = failing("EROFS")
  const refused = await refusal(claimed.unsent())
  expect(refused.message).toContain(markerFile("apr_1"))
  expect(refused.next?.say).toContain(`Deleting ${markerFile("apr_1")} lets the request be sent again`)
})

test("a request expired by the time it is read or claimed is replay_missing, and nothing is deleted", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
  const later = new Date(now.getTime() + REPLAY_TTL_SECONDS * 1000 + 1)
  const expired = await refusal(readSavedRequest(env, "apr_1", at(later)))
  expect(expired.code).toBe("replay_missing")
  expect(expired.message).toContain("expired")
  const saved = await readSavedRequest(env, "apr_1", at(now))
  expect((await refusal(claimSavedRequest(env, saved, owner, at(later)))).code).toBe("replay_missing")
  expect(await listed()).toEqual(["apr_1.json"])
})

test("a request saved by another machine or workspace is refused, and nothing is marked", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
  const saved = await readSavedRequest(env, "apr_1", at(now))
  for (const other of [{ ...owner, device: "dev_two" }, { ...owner, workspace: "tn_other0000001" }, { ...owner, vault: "https://other.example" }]) {
    const refused = await refusal(claimSavedRequest(env, saved, other, at(now)))
    expect(refused.code).toBe("replay_missing")
    expect(refused.message).toContain("another")
  }
  expect(await listed()).toEqual(["apr_1.json"])
})

test("a request file other users can read, a link or a file that is not a saved request is refused before it is used", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
  const path = savedRequestPath(env, "apr_1")
  await chmod(path, 0o640)
  const open = await refusal(readSavedRequest(env, "apr_1", at(now)))
  expect(open.code).toBe("failed")
  expect(open.message).toContain("other users")
  await chmod(path, 0o600)
  await writeFile(join(dir.path, "elsewhere.json"), await readFile(path, "utf8"))
  await symlink(join(dir.path, "elsewhere.json"), savedRequestPath(env, "apr_2"))
  expect((await refusal(readSavedRequest(env, "apr_2", at(now)))).message).toContain("symbolic link")
  expect(Bun.spawnSync(["mkfifo", "-m", "600", savedRequestPath(env, "apr_4")]).exitCode).toBe(0)
  expect((await refusal(readSavedRequest(env, "apr_4", at(now)))).message).toContain("not a regular file")
  await writeFile(savedRequestPath(env, "apr_3"), "{}", { mode: 0o600 })
  expect((await refusal(readSavedRequest(env, "apr_3", at(now)))).code).toBe("replay_missing")
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
    await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
    await make()
    expect((await refusal(claim())).code, name).toBe("replay_missing")
    expect(await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) }), name).toEqual({ saved: false, reason: "spent" })
    await Bun.$`rm -f ${markerFile("apr_1")}`
  }
  await expect(stat(join(dir.path, "elsewhere"))).rejects.toMatchObject({ code: "ENOENT" })
})

// The sweep is best effort: throttled to about once a minute by the mtime
// of .swept, and bounded, so one save never walks a folder of any size.
test("one save examines at most the sweep's budget, sweeps about once a minute, and two sweeps at once are harmless", async () => {
  await mkdir(folder(), { recursive: true, mode: 0o700 })
  const old = new Date(now.getTime() - (SWEEP_AGE_SECONDS + 60) * 1000)
  const count = SWEEP_BUDGET + 100
  for (let i = 0; i < count; i++) {
    const path = join(folder(), `apr_old${i}.json`)
    await writeFile(path, "{}", { mode: 0o600 })
    await utimes(path, old, old)
  }
  const left = async () => (await readdir(folder())).filter((name) => name.startsWith("apr_old")).length
  await saveHeldRequest(env, owner, "apr_new", request, { clock: at(now) })
  const afterFirst = await left()
  expect(afterFirst).toBeGreaterThanOrEqual(count - SWEEP_BUDGET)
  expect(afterFirst).toBeLessThan(count)
  await saveHeldRequest(env, owner, "apr_newer", request, { clock: at(new Date(now.getTime() + 30_000)) })
  expect(await left()).toBe(afterFirst)
  const later = new Date(now.getTime() + 61_000)
  const notes = await Promise.all([saveHeldRequest(env, owner, "apr_a", request, { clock: at(later) }), saveHeldRequest(env, owner, "apr_b", request, { clock: at(later) })])
  expect(notes.every((note) => note.saved)).toBe(true)
  expect(await left()).toBeLessThan(afterFirst)
  expect((await listed()).filter((name) => !name.startsWith("apr_old"))).toEqual(["apr_a.json", "apr_b.json", "apr_new.json", "apr_newer.json"])
})

test("the sweep removes requests, markers and temp files older than its age, and nothing newer", async () => {
  await saveHeldRequest(env, owner, "apr_keep", request, { clock: at(now) })
  const old = new Date(now.getTime() - (SWEEP_AGE_SECONDS + 60) * 1000)
  for (const name of ["apr_1.json", "apr_1.spent", "apr_2.json.1.1.tmp"]) {
    await writeFile(join(folder(), name), "", { mode: 0o600 })
    await utimes(join(folder(), name), old, old)
  }
  await saveHeldRequest(env, owner, "apr_new", request, { clock: at(new Date(now.getTime() + 61_000)) })
  expect(await listed()).toEqual(["apr_keep.json", "apr_new.json"])
})

// Fault injection at each step after the marker's exclusive create: the
// file this call made is its own, so it removes it again.
for (const step of ["markerWrite", "markerSync", "markerClose"] as const) {
  test(`a marker that fails at ${step} is removed again, and the retry claims the request`, async () => {
    await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
    replayFs[step] = failing("ENOSPC")
    const refused = await refusal(claim())
    expect(refused.code).toBe("failed")
    expect(refused.message).toContain("ENOSPC")
    expect(await listed()).toEqual(["apr_1.json"])
    Object.assign(replayFs, realFs)
    expect((await claim()).request.approval).toBe("apr_1")
  })
}

test("a marker that fails at write and cannot be removed is named, with how to free the replay", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
  replayFs.markerWrite = failing("ENOSPC")
  replayFs.unlink = failing("EROFS")
  const refused = await refusal(claim())
  expect(refused.message).toContain(markerFile("apr_1"))
  expect(refused.next?.say).toContain(`Deleting ${markerFile("apr_1")} lets the request be sent again`)
})

// Only ENOENT is absence: any other failure to read the marker, before
// removing it, is the caller's marker-naming error.
test("a marker that cannot be read when an unsent claim releases it is named, and kept", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
  const claimed = await claim()
  replayFs.readMarker = failing("EIO")
  const refused = await refusal(claimed.unsent())
  expect(refused.message).toContain(markerFile("apr_1"))
  expect(refused.message).toContain("EIO")
  expect(await listed()).toEqual(["apr_1.json", "apr_1.spent"])
})

test("a marker that cannot be read after a failed request read is named, and kept", async () => {
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now) })
  const saved = await readSavedRequest(env, "apr_1", at(now))
  replayFs.readRequest = failing("EIO")
  replayFs.readMarker = failing("EACCES")
  const refused = await refusal(claimSavedRequest(env, saved, owner, at(now)))
  expect(refused.message).toContain(markerFile("apr_1"))
  expect(await listed()).toEqual(["apr_1.json", "apr_1.spent"])
})

// The invariant that lets the sweep and a stale release work without any
// coordination: a request records when it was sent; a save never reports a
// request it cannot replay, and nothing claims one past its hour; and the
// sweep removes a file only once every request of its approval is past its
// hour.
test("a held request is saved as of when it was sent, and one past its hour is not saved", async () => {
  const sentAt = new Date(now.getTime() - 30_000)
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now), sentAt: sentAt.getTime() })
  expect((JSON.parse(await readFile(savedRequestPath(env, "apr_1"), "utf8")) as { createdAt: string }).createdAt).toBe(sentAt.toISOString())
  const late = new Date(now.getTime() - REPLAY_TTL_SECONDS * 1000 - 1)
  expect(await saveHeldRequest(env, owner, "apr_2", request, { clock: at(now), sentAt: (late).getTime() })).toEqual({ saved: false, reason: "expired" })
  await expect(stat(savedRequestPath(env, "apr_2"))).rejects.toMatchObject({ code: "ENOENT" })
})

// The proof beside SWEEP_AGE_SECONDS needs three skews: one for when a
// request was sent, one for when a file was written, one for a clock
// stepped back between a sweep and a later check.
test("the sweep's age covers the hour, the vault's pending approval and three clock skews", () => {
  expect(SKEW_SECONDS).toBe(15 * 60)
  expect(SWEEP_AGE_SECONDS).toBeGreaterThanOrEqual(REPLAY_TTL_SECONDS + PENDING_APPROVAL_SECONDS + 3 * SKEW_SECONDS)
  expect(SWEEP_AGE_SECONDS).toBe(REPLAY_TTL_SECONDS + PENDING_APPROVAL_SECONDS + 3 * SKEW_SECONDS)
  // PENDING is the vault's own constant, from the module both import.
  expect(PENDING_APPROVAL_SECONDS * 1000).toBe(APPROVAL_TTL_MS)
})

test("old stat, then a fresh save of the same approval, then the unlink: the fresh save is refused as expired", async () => {
  await mkdir(folder(), { recursive: true, mode: 0o700 })
  const written = new Date(now.getTime() - (SWEEP_AGE_SECONDS + 1) * 1000)
  await writeFile(savedRequestPath(env, "apr_1"), "{}", { mode: 0o600 })
  await utimes(savedRequestPath(env, "apr_1"), written, written)
  let late: unknown = null
  replaySeams.afterSweepStat = async (path) => {
    // The latest a request for this approval can have been sent: its creation
    // (no later than the old file) plus the vault's pending lifetime and the skew.
    if (path === savedRequestPath(env, "apr_1")) late = await saveHeldRequest(env, owner, "apr_1", request, { clock: at(now), sentAt: (new Date(written.getTime() + (PENDING_APPROVAL_SECONDS + SKEW_SECONDS) * 1000)).getTime() })
  }
  await saveHeldRequest(env, owner, "apr_other", request, { clock: at(now) })
  expect(late).toEqual({ saved: false, reason: "expired" })
  expect(await listed()).toEqual(["apr_other.json"])
})

// Both sweeps are held at their look at the old marker: the first removes
// it, a fresh claim runs, then the second removes whatever is there.
test("two sweeps against one old marker, then a fresh claim between them: the claim fails as expired, and nothing is sent", async () => {
  await mkdir(folder(), { recursive: true, mode: 0o700 })
  const written = new Date(now.getTime() - (SWEEP_AGE_SECONDS + 1) * 1000)
  const latest = new Date(written.getTime() + (PENDING_APPROVAL_SECONDS + SKEW_SECONDS) * 1000)
  await writeFile(savedRequestPath(env, "apr_1"), `${JSON.stringify({ version: 1, approval: "apr_1", createdAt: latest.toISOString(), ...owner, request })}\n`, { mode: 0o600 })
  await writeFile(markerFile("apr_1"), "1.1.abc", { mode: 0o600 })
  await utimes(markerFile("apr_1"), written, written)
  const gates: (() => void)[] = []
  const looked = [Promise.withResolvers<void>(), Promise.withResolvers<void>()]
  replaySeams.afterSweepStat = async (path) => {
    if (path !== markerFile("apr_1")) return
    const gate = Promise.withResolvers<void>()
    looked[gates.length]?.resolve()
    gates.push(gate.resolve)
    await gate.promise
  }
  // B sweeps a minute later than A, so A's stamp on .swept does not hold it back.
  const later = new Date(now.getTime() + 61_000)
  const sweepA = saveHeldRequest(env, owner, "apr_a", request, { clock: at(now) })
  await looked[0]?.promise
  const sweepB = saveHeldRequest(env, owner, "apr_b", request, { clock: at(later) })
  await looked[1]?.promise
  gates[0]?.()
  await sweepA
  const saved = JSON.parse(await readFile(savedRequestPath(env, "apr_1"), "utf8")) as Parameters<typeof claimSavedRequest>[1]
  const refused = await refusal(claimSavedRequest(env, saved, owner, at(later)))
  expect(refused.code).toBe("replay_missing")
  expect(refused.message).toContain("expired")
  gates[1]?.()
  await Promise.all([sweepA, sweepB])
  expect(await listed()).toEqual(["apr_1.json", "apr_a.json", "apr_b.json"])
})

test("a stale release, then the sweep, then a new claim, then the unlink: the new claim sends nothing", async () => {
  const claimedAt = new Date(now.getTime() - (SWEEP_AGE_SECONDS + 1) * 1000)
  await saveHeldRequest(env, owner, "apr_1", request, { clock: at(claimedAt) })
  const first = await claimSavedRequest(env, await readSavedRequest(env, "apr_1", at(claimedAt)), owner, at(claimedAt))
  await utimes(markerFile("apr_1"), claimedAt, claimedAt)
  await utimes(savedRequestPath(env, "apr_1"), now, now)
  let second: Promise<unknown> | null = null
  replaySeams.afterMarkerCheck = async () => {
    replaySeams.afterMarkerCheck = undefined
    await Bun.$`rm -f ${join(folder(), ".swept")}`
    await saveHeldRequest(env, owner, "apr_other", request, { clock: at(now) })
    await expect(stat(markerFile("apr_1"))).rejects.toMatchObject({ code: "ENOENT" })
    const saved = JSON.parse(await readFile(savedRequestPath(env, "apr_1"), "utf8")) as Parameters<typeof claimSavedRequest>[1]
    second = claimSavedRequest(env, saved, owner, at(now))
    await (second as Promise<unknown>).catch(() => undefined)
  }
  await first.unsent().catch(() => undefined)
  const refused = await refusal(second as unknown as Promise<unknown>)
  expect(refused.code).toBe("replay_missing")
  expect(refused.message).toContain("expired")
})

// The clock is read again at each point that accepts: in a save just before
// the rename, in a claim once its marker exists and the request was read.
test("a save whose sweep runs past the hour is refused as expired, and writes nothing", async () => {
  let t = now.getTime()
  await mkdir(folder(), { recursive: true, mode: 0o700 })
  const old = new Date(now.getTime() - (SWEEP_AGE_SECONDS + 60) * 1000)
  await writeFile(join(folder(), "apr_old.json"), "{}", { mode: 0o600 })
  await utimes(join(folder(), "apr_old.json"), old, old)
  replaySeams.afterSweepStat = async () => {
    t += (REPLAY_TTL_SECONDS + 1) * 1000
  }
  expect(await saveHeldRequest(env, owner, "apr_1", request, { clock: () => t, sentAt: now.getTime() })).toEqual({ saved: false, reason: "expired" })
  expect((await readdir(folder())).filter((name) => name.startsWith("apr_1"))).toEqual([])
})

for (const [where, step] of [["the marker's create", "markerWrite"], ["the request's read", "readRequest"]] as const) {
  test(`a claim whose clock passes the hour during ${where} is refused as expired, and frees its marker`, async () => {
    let t = now.getTime()
    await saveHeldRequest(env, owner, "apr_1", request, { clock: () => t })
    const saved = await readSavedRequest(env, "apr_1", () => t)
    const real = realFs[step] as (...args: never[]) => Promise<unknown>
    ;(replayFs as Record<string, unknown>)[step] = async (...args: never[]) => {
      t += (REPLAY_TTL_SECONDS + 1) * 1000
      return real(...args)
    }
    const refused = await refusal(claimSavedRequest(env, saved, owner, () => t))
    expect(refused.code).toBe("replay_missing")
    expect(refused.message).toContain("expired")
    expect(await listed()).toEqual(["apr_1.json"])
  })
}

// createdAt is when the request was sent, taken before the relay call: an
// answer that arrives late (a suspended machine, a slow proxy) cannot
// stretch the hour.
test("a held answer that arrives after the hour has passed since sending is not saved, and nothing can be sent", async () => {
  let t = now.getTime()
  replayClock.now = () => t
  const env2 = { ...env, MEHEN_HOME: env.MEHEN_HOME as string }
  const api = {
    relay: async () => {
      t += (REPLAY_TTL_SECONDS + 1) * 1000
      throw new VaultApiError(403, { error: "approval_required", message: "Held.", approval: "apr_late", bindingCode: "K7Q2" } as never)
    },
    request: async () => {
      throw new Error("unexpected request")
    },
  } as unknown as VaultApi
  const config = { vault: owner.vault, tenant: owner.workspace, device: owner.device, backend: "software" as const }
  const session = { api, config, vaultUrl: owner.vault, configDir: dir.path, selection: { dir: dir.path, config, reason: "workspace" }, ledger: { vaultUrl: owner.vault, workspace: owner.workspace, device: owner.device, workspaceSlug: null }, context: { origin: owner.vault, workspace: null, device: owner.device } } as unknown as VaultSession
  const output = { json: true, output: null, select: null, selectText: null, include: false, fail: false, maxTime: null }
  const held = await refusal(sendFetch(env2, session, request, output))
  expect(held.code).toBe("approval_required")
  expect(held.extras.replay).toEqual({ saved: false, reason: "expired" })
  await expect(stat(savedRequestPath(env, "apr_late"))).rejects.toMatchObject({ code: "ENOENT" })
  expect((await refusal(readSavedRequest(env, "apr_late", () => t))).code).toBe("replay_missing")
})

// A rename delayed past the hour lands a file nobody can replay: the save
// says expired rather than saved, and leaves the file to the sweep.
test("a save whose rename lands after the hour reports expired, and a claim of what it wrote is replay_missing", async () => {
  let t = now.getTime()
  replayFs.rename = async (from, to) => {
    t += (REPLAY_TTL_SECONDS + 1) * 1000
    return realFs.rename(from, to)
  }
  expect(await saveHeldRequest(env, owner, "apr_1", request, { clock: () => t, sentAt: now.getTime() })).toEqual({ saved: false, reason: "expired" })
  expect(await listed()).toEqual(["apr_1.json"])
  Object.assign(replayFs, realFs)
  const saved = JSON.parse(await readFile(savedRequestPath(env, "apr_1"), "utf8")) as Parameters<typeof claimSavedRequest>[1]
  const refused = await refusal(claimSavedRequest(env, saved, owner, () => t))
  expect(refused.code).toBe("replay_missing")
  expect(refused.message).toContain("expired")
  expect(await listed()).toEqual(["apr_1.json"])
})
