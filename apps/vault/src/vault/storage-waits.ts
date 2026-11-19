// Long polls wait here for the next write to their object's storage instead
// of re-reading on a timer. Keyed on the DurableObjectStorage, which every
// call on one object shares; each call has its own VaultContext, so a
// context-keyed map would never meet the writer.

// A long poll re-checks at least this often, for an expiry, which writes
// nothing.
export const LONG_POLL_RECHECK_MS = 5_000

// A woken long poll re-checks no sooner than this after it started waiting,
// so one wait re-checks at most four times a second however often its
// object is written: every machine call writes a nonce, and every write
// drops the memoised access state each check rebuilds.
export const LONG_POLL_MIN_GAP_MS = 250

const waiting = new WeakMap<DurableObjectStorage, Set<() => void>>()

// Called for every write countWrites counts (tenant-vault.ts). It takes the
// waiters registered so far, so a waiter that registers after this write,
// such as one whose own check wrote, is not woken by it, and later writes
// in the same run find nothing to take. The wake is a queued microtask:
// microtasks run only once the running JavaScript has returned, so the
// write, the rest of the synchronous transactionSync around it and its
// commit all finish first, and each woken wait then resumes, at once or
// once its minimum gap has passed, reading the committed rows.
export function wakeStorageWaiters(storage: DurableObjectStorage): void {
  const woken = waiting.get(storage)
  if (!woken) return
  waiting.delete(storage)
  queueMicrotask(() => { for (const wake of woken) wake() })
}

// Resolves on the next write to this storage, but no sooner than
// LONG_POLL_MIN_GAP_MS after it was called, or after
// min(remainingMs, LONG_POLL_RECHECK_MS), whichever comes first, and
// unregisters itself either way. A wake may be for an unrelated write, so
// every caller loops and re-checks.
export function waitForStorageWrite(storage: DurableObjectStorage, remainingMs: number): Promise<void> {
  let waiters = waiting.get(storage)
  if (!waiters) {
    waiters = new Set()
    waiting.set(storage, waiters)
  }
  const registered = waiters
  const registeredAt = Date.now()
  const timeoutMs = Math.max(0, Math.min(remainingMs, LONG_POLL_RECHECK_MS))
  return new Promise((resolve) => {
    const done = () => {
      clearTimeout(timer)
      registered.delete(wake)
      if (registered.size === 0 && waiting.get(storage) === registered) waiting.delete(storage)
      resolve()
    }
    const wake = () => {
      const elapsed = Date.now() - registeredAt
      if (elapsed >= LONG_POLL_MIN_GAP_MS) return done()
      clearTimeout(timer)
      timer = setTimeout(done, Math.max(0, Math.min(LONG_POLL_MIN_GAP_MS, timeoutMs) - elapsed))
    }
    let timer = setTimeout(done, timeoutMs)
    registered.add(wake)
  })
}

export function storageWaiterCount(storage: DurableObjectStorage): number {
  return waiting.get(storage)?.size ?? 0
}
