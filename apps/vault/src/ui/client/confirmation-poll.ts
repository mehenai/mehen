// Waiting for an owner or admin to confirm a joined membership, shared by
// /signup and the workspace picker: GET /api/account every ten seconds until
// the membership in `slug` is active, then where the vault names
// (GET /api/account/onboarding/:id: Connect an agent, or the home while an
// identity check is due), only if that is on this vault. A failed check is said once
// ("retrying") and retried with the backoff below, after the vault's
// retryAfter when it gives one; a 401 (signed out here or elsewhere, every
// session ended, a security change) stops the wait and links to sign in.
// A membership the vault listed and then no longer does was removed by an
// owner or admin: the wait stops and says so.
// One timer at a time.

import type { AccountSession } from "@mehen/protocol/workspace"
import { VaultFailure, api } from "./api.ts"
import { find } from "./dom.ts"

export const CONFIRMATION_POLL_MS = 10_000

// The backoff after a failed status read, shared with the recovery wait: it
// doubles from fifteen seconds up to four minutes, and never asks sooner
// than the vault's retryAfter (capped at sixteen minutes).
export const RECOVERY_POLL_MS = 15_000
export const RECOVERY_BACKOFF_MAX_MS = 240_000

export function nextRecoveryPoll(failures: number, retryAfterSeconds: number | undefined): number {
  const backoff = Math.min(RECOVERY_BACKOFF_MAX_MS, RECOVERY_POLL_MS * 2 ** failures)
  const asked = retryAfterSeconds !== undefined && Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0 ? retryAfterSeconds * 1000 : 0
  return Math.max(backoff, Math.min(asked, RECOVERY_BACKOFF_MAX_MS * 4))
}

// A server-supplied place to go, only when it is on this vault: parsed
// against this page, its origin compared with this page's, and the parsed
// absolute address returned (never a path cut out of it, which a leading
// "//" would turn into another host). Anything else, or anything that does
// not parse, is null.
export function sameOriginHref(raw: string): string | null {
  let target: URL
  try {
    target = new URL(raw, location.origin)
  } catch {
    return null
  }
  return target.origin === location.origin ? target.href : null
}

// `root` holds the waiting card's two lines (confirm-retrying and
// confirm-ended, from confirmationWaiting in ui/pages/account-setup.ts).
// `confirmed` runs once, just before the page moves on. Returns a stop.
export function waitForConfirmation(slug: string, root: ParentNode, confirmed: () => void = () => undefined): () => void {
  const retrying = find('[data-region="confirm-retrying"]', root)
  const ended = find('[data-region="confirm-ended"]', root)
  const removed = find('[data-region="confirm-removed"]', root)
  let listed = false
  let timer: ReturnType<typeof setTimeout> | undefined
  let failures = 0
  let stopped = false
  const stop = () => {
    stopped = true
    clearTimeout(timer)
  }
  const schedule = (ms: number) => {
    clearTimeout(timer)
    if (!stopped) timer = setTimeout(() => void poll(), ms)
  }
  const poll = async (): Promise<void> => {
    timer = undefined
    try {
      const session = await api<AccountSession>("/api/account")
      const joined = session.memberships.find((m) => m.workspace.slug === slug)
      if (joined !== undefined && joined.status === "active") {
        const { next } = await api<{ next: string }>(`/api/account/onboarding/${encodeURIComponent(joined.workspace.id)}`)
        // Checked before anything stops or is cleared: a refused place is a
        // failed check, retried later like any other.
        const target = sameOriginHref(next)
        if (target === null) throw new Error("The vault named a place outside this vault.")
        if (stopped) return
        stop()
        confirmed()
        location.assign(target)
        return
      }
      if (retrying) retrying.hidden = true
      if (joined === undefined && listed) {
        stop()
        if (removed) removed.hidden = false
        return
      }
      listed = listed || joined !== undefined
      failures = 0
      schedule(CONFIRMATION_POLL_MS)
    } catch (failure) {
      if (stopped) return
      if (failure instanceof VaultFailure && failure.status === 401) {
        stop()
        if (retrying) retrying.hidden = true
        if (ended) ended.hidden = false
        return
      }
      if (retrying) retrying.hidden = false
      schedule(nextRecoveryPoll(failures, failure instanceof VaultFailure ? failure.body.retryAfter : undefined))
      failures += 1
    }
  }
  schedule(CONFIRMATION_POLL_MS)
  return stop
}
