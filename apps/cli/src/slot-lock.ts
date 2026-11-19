// Lock files, extracted from the ledger's lock so
// both share one reap rule. A lock is an O_EXCL file holding
// { pid, at, attempt? }; it is reaped only when it is older than 10 s and
// its pid is gone (or it is an interrupted, empty creation), under a reap
// guard so two reapers never unlink a replacement. A live holder is never
// stolen, however old its lock.
//
// Slot locks live under <root>/locks/, never in a directory that moves:
//
//   locks/root.lock                          the migration
//   locks/<originKey>/pending-<slug>.lock    a pending slot
//   locks/<originKey>/active-<tn_id>.lock    an active slot
//
// Several are taken in lexicographic order of their paths and released in
// reverse; a lock not acquired in 30 s is `failed`, naming the holder's pid.

import { lstat, open, readFile, unlink } from "node:fs/promises"
import { dirname, join, sep } from "node:path"
import { CliError } from "./errors.ts"
import { LOCKS_DIR, ensureSafeRoot, mkdirPrivate, originKey, rootAboveSlot } from "./home.ts"

export const LOCK_STALE_MS = 10_000
export const SLOT_LOCK_WAIT_MS = 30_000
const LOCK_RETRY_MS = 25

export type LockContent = { pid: number; at: string; attempt?: string }
export type HeldLock = { path: string; handle: Awaited<ReturnType<typeof open>> }

function errorCode(error: unknown): string | undefined {
  return (error as { code?: string }).code
}

export function rootLockPath(root: string): string {
  return join(root, LOCKS_DIR, "root.lock")
}

export function pendingLockPath(root: string, origin: string, slug: string): string {
  return join(root, LOCKS_DIR, originKey(origin), `pending-${slug}.lock`)
}

export function activeLockPath(root: string, origin: string, tenant: string): string {
  return join(root, LOCKS_DIR, originKey(origin), `active-${tenant}.lock`)
}

// The lock of a slot directory, <root>/workspaces/<originKey>/<tn_id> or
// <root>/pending/<originKey>/<slug>: its active or pending lock. Null for a
// directory that is not a slot (a managed host's legacy pinned context).
export function slotLockPath(slot: string): string | null {
  const above = rootAboveSlot(slot)
  if (!above || above.kind === "contexts") return null
  const [origin, name] = above.parts as [string, string]
  return join(above.root, LOCKS_DIR, origin, `${above.kind === "workspaces" ? "active" : "pending"}-${name}.lock`)
}

// A live reaper holds its guard for one stale check, milliseconds. A guard
// older than a stale lock was left by a reaper that crashed mid-check, so it
// is cleared, and the next attempt reaps; otherwise one crash would stop
// every later writer from recovering a dead holder's lock.
async function clearAbandonedGuard(guardPath: string): Promise<void> {
  try {
    const info = await lstat(guardPath)
    if (info.isFile() && Date.now() - info.mtimeMs > LOCK_STALE_MS) await unlink(guardPath)
  } catch {
    // Gone already: another reaper finished or cleared it.
  }
}

function pidOf(text: string): number | null {
  try {
    const parsed: unknown = JSON.parse(text)
    const pid = typeof parsed === "object" && parsed !== null ? (parsed as { pid?: unknown }).pid : undefined
    return typeof pid === "number" && Number.isSafeInteger(pid) && pid > 0 ? pid : null
  } catch {
    // An interrupted lock creation can leave an empty file.
    return null
  }
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return errorCode(error) !== "ESRCH"
  }
}

export async function reapLock(path: string): Promise<void> {
  // Serialise stale checks: two reapers must not unlink a replacement lock.
  const guard = await open(`${path}.reap`, "wx", 0o600).catch(() => null)
  if (!guard) {
    await clearAbandonedGuard(`${path}.reap`)
    return
  }
  try {
    const info = await lstat(path)
    if (!info.isFile() || Date.now() - info.mtimeMs <= LOCK_STALE_MS) return
    const pid = pidOf(await readFile(path, "utf8"))
    if (pid !== null && alive(pid)) return
    await unlink(path)
  } catch {
    // Another writer may have released the lock before the stale check.
  } finally {
    await guard.close()
    await unlink(`${path}.reap`).catch(() => undefined)
  }
}

// The lock at `path`, or null when it was not acquired within `waitMs` or
// cannot be taken at all (a link or a missing directory in its place). The
// caller decides whether that is a warning or a failure.
export async function acquireLockFile(path: string, options: { waitMs: number; attempt?: string }): Promise<HeldLock | null> {
  const deadline = performance.now() + options.waitMs
  let handle: HeldLock["handle"] | undefined
  while (performance.now() < deadline) {
    try {
      handle = await open(path, "wx", 0o600)
      break
    } catch (error) {
      if (errorCode(error) !== "EEXIST") break
      await reapLock(path)
      await Bun.sleep(Math.min(LOCK_RETRY_MS, Math.max(0, deadline - performance.now())))
    }
  }
  if (!handle) return null
  const content: LockContent = { pid: process.pid, at: new Date().toISOString(), ...(options.attempt ? { attempt: options.attempt } : {}) }
  try {
    await handle.writeFile(JSON.stringify(content))
  } catch {
    await handle.close()
    await unlink(path).catch(() => undefined)
    return null
  }
  return { path, handle }
}

export async function releaseLockFile(held: HeldLock): Promise<void> {
  try {
    await held.handle.close()
  } finally {
    await unlink(held.path).catch(() => undefined)
  }
}

// Who holds a lock, for the refusal: its pid, or null when unreadable.
export async function lockHolder(path: string): Promise<number | null> {
  try {
    return pidOf(await readFile(path, "utf8"))
  } catch {
    return null
  }
}

// A slot lock's directory, <root>/locks[/<originKey>], made private one
// component at a time; a linked, foreign or loose one is refused. The first
// lock on a new machine creates the root itself (and a missing ~/.config)
// through the root walk, so an unsafe ancestor is refused by name first.
function lockDirectory(path: string): void {
  const at = path.lastIndexOf(`${sep}${LOCKS_DIR}${sep}`)
  if (at <= 0) throw new CliError("internal", `${path} is not a lock under a config root.`)
  const root = path.slice(0, at)
  ensureSafeRoot(root)
  mkdirPrivate(root, dirname(path))
}

// Runs `fn` holding every lock in `paths`, taken in lexicographic order and
// released in reverse. A lock not acquired in time is `failed` naming the
// holder's pid; nothing is ever taken from a live holder.
export async function withSlotLocks<T>(paths: string[], fn: () => Promise<T>, options: { waitMs?: number; attempt?: string } = {}): Promise<T> {
  const ordered = [...new Set(paths)].sort()
  const held: HeldLock[] = []
  try {
    for (const path of ordered) {
      lockDirectory(path)
      const lock = await acquireLockFile(path, { waitMs: options.waitMs ?? SLOT_LOCK_WAIT_MS, ...(options.attempt ? { attempt: options.attempt } : {}) })
      if (!lock) {
        const pid = await lockHolder(path)
        throw new CliError("failed", `Another mehen process${pid ? ` (pid ${pid})` : ""} holds ${path}, and it was not released within ${Math.round((options.waitMs ?? SLOT_LOCK_WAIT_MS) / 1000)} s.`, {
          say: pid ? `Wait for process ${pid} to finish, then run the command again; if it is stuck, stop it first.` : "Wait for the other mehen process to finish, then run the command again.",
        })
      }
      held.push(lock)
    }
    return await fn()
  } finally {
    for (const lock of held.reverse()) await releaseLockFile(lock)
  }
}
