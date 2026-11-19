// Slot locks: O_EXCL files under <root>/locks,
// taken in path order, reaped only when stale and dead, never stolen from
// a live holder, `failed` naming the holder when the wait runs out.

import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, renameSync, utimesSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { CliError, exitCodeFor } from "./errors.ts"
import { activeLockPath, pendingLockPath, rootLockPath, withSlotLocks } from "./slot-lock.ts"
import { tempDir } from "./testing/run-mehen.ts"

let dir: { path: string; remove(): Promise<void> }
const ORIGIN = "https://app.mehen.dev"

beforeEach(async () => {
  dir = await tempDir()
})
afterEach(() => dir.remove())

function plant(path: string, pid: number, ageMs: number): void {
  mkdirSync(join(path, ".."), { recursive: true, mode: 0o700 })
  writeFileSync(path, JSON.stringify({ pid, at: new Date(Date.now() - ageMs).toISOString() }), { mode: 0o600 })
  const at = new Date(Date.now() - ageMs)
  utimesSync(path, at, at)
}

async function deadPid(): Promise<number> {
  const child = Bun.spawn([process.execPath, "--eval", ""], { stdout: "ignore", stderr: "ignore" })
  await child.exited
  return child.pid
}

describe("slot locks", () => {
  test("live under <root>/locks/<originKey>, never inside a slot, and survive the slot directory's rename", async () => {
    expect(rootLockPath("/r")).toBe("/r/locks/root.lock")
    expect(pendingLockPath("/r", ORIGIN, "acme")).toBe("/r/locks/app.mehen.dev/pending-acme.lock")
    expect(activeLockPath("/r", ORIGIN, "tn_x")).toBe("/r/locks/app.mehen.dev/active-tn_x.lock")
    const pending = join(dir.path, "pending", "app.mehen.dev", "acme")
    mkdirSync(pending, { recursive: true, mode: 0o700 })
    const lock = pendingLockPath(dir.path, ORIGIN, "acme")
    await withSlotLocks([lock], async () => {
      expect(existsSync(lock)).toBe(true)
      renameSync(pending, join(dir.path, "moved"))
      expect(existsSync(lock)).toBe(true)
    })
    expect(existsSync(lock)).toBe(false)
  })

  test("several locks are taken in path order and released in reverse: two writers asking in opposite orders both finish", async () => {
    const a = activeLockPath(dir.path, ORIGIN, "tn_a")
    const b = pendingLockPath(dir.path, ORIGIN, "acme")
    const order: string[] = []
    await Promise.all([
      withSlotLocks([b, a], async () => {
        order.push("first")
        await Bun.sleep(50)
      }),
      withSlotLocks([a, b], async () => {
        order.push("second")
      }),
    ])
    expect(order.sort()).toEqual(["first", "second"])
    expect(existsSync(a) || existsSync(b)).toBe(false)
  })

  test("a stale lock of a dead process is reaped; a live holder is never stolen and the wait fails naming its pid", async () => {
    const lock = rootLockPath(dir.path)
    plant(lock, await deadPid(), 11_000)
    expect(await withSlotLocks([lock], async () => "ran")).toBe("ran")
    plant(lock, process.pid, 11_000)
    let thrown: unknown
    try {
      await withSlotLocks([lock], async () => "never", { waitMs: 200 })
    } catch (error) {
      thrown = error
    }
    expect(thrown).toBeInstanceOf(CliError)
    expect((thrown as CliError).code).toBe("failed")
    expect(exitCodeFor((thrown as CliError).code)).toBe(EXIT.error)
    expect((thrown as CliError).message).toContain(`pid ${process.pid}`)
    expect(existsSync(lock)).toBe(true)
    // A fresh lock of a dead process is not reaped before it is 10 s old.
    plant(lock, await deadPid(), 1_000)
    await expect(withSlotLocks([lock], async () => "never", { waitMs: 200 })).rejects.toMatchObject({ code: "failed" })
  })
})
