// Pure enrolment code and fingerprint helpers shared by the workspace flow.
import { fingerprintGroupCheck,fingerprintGroupIndex,fingerprintGroups,fingerprintOf,fingerprintWords } from "@mehen/protocol"
import type { EnrolmentFingerprint } from "@mehen/protocol/api"
import type { VaultError } from "../http.ts"

export const ENROL_TENANT = "enrol"
export const NEW_DEVICE = "new"
// The lease: while it is ahead the link is live and can be accepted; the
// key that started the attempt renews it in place, at most once a minute,
// never past the attempt's hard cap. Five wrong typed groups reject the
// attempt however often it is renewed.
export const ENROLMENT_TTL_MS = 3_600_000
export const ENROLMENT_MAX_LIFE_MS = 86_400_000
export const ENROLMENT_RENEW_INTERVAL_MS = 60_000
// How long an expired or rejected attempt stays readable past its hard cap
// before maintenance deletes it: a public start leaves no row for ever. An
// attempt that never reached a workspace (directory/workspace-maintenance.ts)
// has nobody to read it and goes at its hard cap.
export const ENROLMENT_SETTLED_KEEP_MS = 30 * 86_400_000
// An attempt that never reached a workspace, over `enrolments e`: superseded
// or run out, claimed and accepted by no account, no tenant and no device.
// The prune deletes it at its hard cap and the source reconcile skips it.
// Never NULL, so NOT of it keeps a row with no expired_reason.
export const UNREACHED_ENROLMENT = `e.status='expired' AND COALESCE(e.expired_reason,'') IN ('hard_cap','superseded') AND e.tenant IS NULL AND e.device IS NULL
  AND e.claimed_account IS NULL AND e.accepted_by_account IS NULL AND e.discard_pending=0 AND e.mirror_acknowledged=0`
// Each prune step of a maintenance run deletes oldest first, in batches of
// ENROLMENT_PRUNE_LIMIT, at most ENROLMENT_PRUNE_BATCHES of them, stopping
// at the first short batch: at most 5,000 rows a step a run, 480,000 a day
// at one run every 15 minutes, above the 172,800 starts one address may make
// a day within RATE_LIMITER.
export const ENROLMENT_PRUNE_LIMIT = 500
export const ENROLMENT_PRUNE_BATCHES = 10
export const GROUP_ATTEMPTS_ALLOWED = 5

const CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
const CODE_LENGTH = 8
const CODE_PATTERN = /^[2-9A-HJKMNP-Z]{8}$/

export type EnrolmentRow = {
  id: string
  jwk: string
  thumbprint: string
  name: string
  backend: "secure-enclave" | "software"
  host: string | null
  status: "pending" | "active" | "rejected" | "expired"
  tenant: string | null
  device: string | null
  scope: string | null
  expires_at: number
  group_attempts: number
}

export type EnrolmentLease = "live" | "lapsed" | "terminal"
// The one classifier every reader uses. A row past its hard cap reads as
// terminal whether or not the cron has flipped its status yet. A NULL hard
// cap is a row from before the lease, whose expiry is its hard cap.
export function enrolmentLease(row: { status: EnrolmentRow["status"]; discard_pending: number; expires_at: number; hard_expires_at: number | null }, now: number): EnrolmentLease {
  if (row.status !== "pending" || row.discard_pending !== 0 || (row.hard_expires_at ?? row.expires_at) <= now) return "terminal"
  return row.expires_at > now ? "live" : "lapsed"
}

export function enrolmentCode(): string {
  let code = ""
  while (code.length < CODE_LENGTH) {
    for (const b of crypto.getRandomValues(new Uint8Array(16))) {
      // 248 is the largest multiple of 31 under 256: no bias.
      if (b < 248 && code.length < CODE_LENGTH) code += CODE_ALPHABET[b % CODE_ALPHABET.length]
    }
  }
  return code
}

// Accepts what a human might type: lower case, spaces, a dash in the middle.
export function normaliseCode(input: string): string | null {
  const code = input.toUpperCase().replaceAll(/[\s-]/g, "")
  return CODE_PATTERN.test(code) ? code : null
}

// The page's fingerprint. The hidden group is the one persisted at start
// (hidden), else, for a row from before 0008, the code's; the browser's
// pre-check is keyed by the page's ref, the code or the id.
export async function enrolmentFingerprint(ref: string, thumbprint: string, hidden?: 0 | 1 | 2 | 3): Promise<EnrolmentFingerprint> {
  const index = hidden ?? await fingerprintGroupIndex(ref)
  const groups = fingerprintGroups(fingerprintOf(thumbprint)),group = groups[index]
  return {
    groups: groups.filter((_, i) => i !== index) as [string, string, string],
    hidden: index,
    check: await fingerprintGroupCheck(ref, group),
    words: fingerprintWords(thumbprint),
  }
}

export type TypedGroup = { ok: true } | { ok: false; refusal: VaultError }
