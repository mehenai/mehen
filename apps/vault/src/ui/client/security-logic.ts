// Pure wording for the sign-in and recovery pages, shared by the server's
// pages and the browser code so both say the same thing: dates, the
// recovery code status line, the saved sheet of codes, and when a rate
// limit lifts.

import type { RecoveryStatus } from "@mehen/protocol/api"

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

// "12 Oct 2026" (UTC, like every time on the pages).
export function dateWords(value: string): string {
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`
}

// "8 of 10 left, made 12 Oct 2026".
export function recoveryStatusWords(active: NonNullable<RecoveryStatus["active"]>): string {
  return `${active.left} of ${active.total} left, made ${dateWords(active.generatedAt)}`
}

// The sheet Copy all and Download give: which vault and whose codes, the
// codes numbered as the page shows them, and how to use one.
export function recoveryCodesText(codes: readonly string[], vaultHost: string, made: string): string {
  return [
    `Mehen recovery codes for ${vaultHost}`,
    `Made ${dateWords(made)}. Each code works once.`,
    "",
    ...codes.map((code, i) => `${String(i + 1).padStart(2, " ")}. ${code}`),
    "",
    `Lost every passkey? Open https://${vaultHost}/recover and type one code.`,
    "Never paste a code into a chat or give one to an agent.",
    "",
  ].join("\n")
}

// "Try again after 19:00 UTC." from a refusal's retryAfter, in seconds.
export function retryWords(retryAfter: number | undefined, now: number): string {
  if (retryAfter === undefined || !Number.isFinite(retryAfter) || retryAfter <= 0) return "Try again later."
  const at = new Date(now + retryAfter * 1000)
  const pad = (n: number) => String(n).padStart(2, "0")
  return `Try again after ${pad(at.getUTCHours())}:${pad(at.getUTCMinutes())} UTC.`
}

// "has 15 minutes left to be confirmed", for a new set of codes.
export function confirmWindowWords(expiresAt: string, now: number): string {
  const ms = Date.parse(expiresAt) - now
  if (Number.isNaN(ms) || ms <= 0) return "has run out of time to be confirmed"
  const minutes = Math.max(1, Math.round(ms / 60_000))
  return `has ${minutes} minute${minutes === 1 ? "" : "s"} left to be confirmed`
}
