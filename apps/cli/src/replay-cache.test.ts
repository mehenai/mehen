import { afterEach, beforeEach, expect, test } from "bun:test"
import { chmod, readFile, readdir, stat, symlink, utimes, writeFile } from "node:fs/promises"
import { join } from "node:path"
import type { RelayRequestInput } from "@mehen/protocol/api"
import { base64UrlEncode, utf8 } from "@mehen/protocol/bytes"
import { CliError } from "./errors.ts"
import { MAX_REPLAY_BODY_BYTES, REPLAY_TTL_SECONDS, claimSavedRequest, readSavedRequest, saveHeldRequest, savedRequestPath } from "./replay-cache.ts"
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
  expect(await claimSavedRequest(env, saved, owner)).toEqual({ ...request, approval: "apr_1" })
  await expect(stat(savedRequestPath(env, "apr_1"))).rejects.toMatchObject({ code: "ENOENT" })
  const again = await refusal(readSavedRequest(env, "apr_1", now))
  expect(again.code).toBe("replay_missing")
  expect(again.next?.say).toContain("byte for byte")
  expect((await refusal(claimSavedRequest(env, saved, owner))).code).toBe("replay_missing")
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
  await saveHeldRequest(env, owner, "apr_third", request, now)
  expect((await readdir(join(env.MEHEN_HOME as string, "pending-requests"))).sort()).toEqual(["apr_new.json", "apr_third.json"])
})
