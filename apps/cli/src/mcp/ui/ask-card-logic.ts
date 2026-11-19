// What the ask card draws, from a tool result and from vault_ask_state.
// Pure and DOM-free; every field of a result is untrusted and read as data.
// The wording follows ask.ts (checkSentence, askedBy, relativeExpiry), which
// this browser code cannot import: ask-card-logic.test.ts holds them equal.

import type { AskCheckLabel } from "../../ask.ts"
import type { AskState } from "../vault-ask-state.ts"
import type { CallToolResult } from "./bridge.ts"

export type { AskState }

export const ASK_STATES: readonly AskState[] = ["waiting", "done", "declined", "expired", "cancelled", "stale", "failed", "mismatch"]

export const STATE_LABELS: Record<AskState, string> = {
  waiting: "Waiting for you",
  done: "Done",
  declined: "Declined",
  expired: "Expired",
  cancelled: "Cancelled",
  stale: "Changed",
  failed: "Failed",
  mismatch: "Account mismatch",
}

export type StateTone = "waiting" | "ok" | "warn" | "danger" | "quiet"

export const STATE_TONES: Record<AskState, StateTone> = {
  waiting: "waiting",
  done: "ok",
  declined: "danger",
  expired: "quiet",
  cancelled: "quiet",
  stale: "warn",
  failed: "danger",
  mismatch: "warn",
}

// The ids vault_ask_state follows; enr_ and an id-less ask are drawn without live state.
const LIVE_ID = /^(?:int|apr|con|pol|adp)_[A-Za-z0-9_-]{1,60}$/

export function isLiveId(id: string): boolean {
  return LIVE_ID.test(id)
}

// checkSentence's words with the value apart, so the card can set it in bold.
export type CheckLine = { lead: string; value: string; tail: string }

export function checkLine(check: { label: AskCheckLabel; value: string }): CheckLine {
  if (check.label === "fingerprint") return { lead: "the page shows fingerprint  ", value: check.value, tail: "" }
  if (check.label === "code") return { lead: "the page shows code ", value: check.value, tail: "" }
  if (check.label === "account") return { lead: "the page shows account ", value: check.value, tail: "; sign in as that account" }
  if (check.label === "codes") return { lead: "the page shows codes ", value: check.value, tail: "" }
  return { lead: "the page says it was asked by ", value: check.value, tail: "" }
}

export function askedByText(by: { device: string; session: string | null }): string {
  return by.session ? `${by.device}, session ${by.session}` : by.device
}

const MINUTE = 60_000
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR

// "in 58 min", "in 24 h", "in 3 days", "in under a minute", or "expired".
export function relativeExpiry(expiresAt: string, now: Date): string | null {
  const at = Date.parse(expiresAt)
  if (!Number.isFinite(at)) return null
  const left = at - now.getTime()
  if (left <= 0) return "expired"
  if (left < MINUTE) return "in under a minute"
  if (left < HOUR) return `in ${Math.ceil(left / MINUTE)} min`
  if (left < 2 * DAY) return `in ${Math.round(left / HOUR)} h`
  return `in ${Math.round(left / DAY)} days`
}

export function isExpired(expiresAt: string | null, now: Date): boolean {
  return expiresAt !== null && relativeExpiry(expiresAt, now) === "expired"
}

// A link the card may hand to the host: https, or http on this machine for a dev vault.
export function openableUrl(url: string): boolean {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return false
  }
  if (parsed.username !== "" || parsed.password !== "") return false
  if (parsed.protocol === "https:") return true
  return parsed.protocol === "http:" && (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1")
}

export type AskView = {
  id: string
  // vault_ask_state can follow it.
  live: boolean
  workspace: string | null
  title: string
  what: string
  check: CheckLine | null
  account: string | null
  askedBy: string | null
  expiresAt: string | null
  url: string
  // The url may go to ui/open-link.
  openable: boolean
}

export type AskCardView = { kind: "none" } | { kind: "single"; ask: AskView; note: string | null } | { kind: "list"; asks: AskView[]; more: number }

export const LIST_LIMIT = 8

const CHECK_LABELS: readonly string[] = ["fingerprint", "code", "account", "asked by", "codes"]

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null
}

function text(value: unknown): string | null {
  return typeof value === "string" ? value : null
}

// One ask from a result, or null when it is not shaped like one.
export function askView(value: unknown): AskView | null {
  const ask = record(value)
  if (!ask) return null
  const id = text(ask.id)
  const url = text(ask.url)
  const title = text(ask.title)
  const what = text(ask.what)
  if (id === null || url === null || url === "" || title === null || what === null) return null
  const rawCheck = record(ask.check)
  const checkLabel = text(rawCheck?.label)
  const checkValue = text(rawCheck?.value)
  const check = checkLabel !== null && checkValue !== null && CHECK_LABELS.includes(checkLabel) ? checkLine({ label: checkLabel as AskCheckLabel, value: checkValue }) : null
  const by = record(ask.requestedBy)
  const device = text(by?.device)
  const asked = device ? askedByText({ device, session: text(by?.session) }) : null
  const account = text(ask.account)
  return {
    id,
    live: isLiveId(id),
    workspace: text(record(record(ask.context)?.workspace)?.slug),
    title,
    what,
    check,
    // Each is drawn once: an account or requester the check already names is not repeated.
    account: account && !(checkLabel === "account" && checkValue === account) ? account : null,
    askedBy: asked && !(checkLabel === "asked by" && checkValue === asked) ? asked : null,
    expiresAt: text(ask.expiresAt),
    url,
    openable: openableUrl(url),
  }
}

// The card for a vault_request, vault_connect, vault_policy or vault_pending
// result, or for an error that hands over an ask. Anything else draws nothing.
export function askCardView(result: CallToolResult): AskCardView {
  const structured = record(result.structuredContent)
  if (!structured) return { kind: "none" }
  if (Array.isArray(structured.pending)) {
    const asks = structured.pending.map(askView).filter((a): a is AskView => a !== null)
    if (asks.length === 0) return { kind: "none" }
    if (asks.length === 1) return { kind: "single", ask: asks[0] as AskView, note: null }
    return { kind: "list", asks: asks.slice(0, LIST_LIMIT), more: Math.max(asks.length - LIST_LIMIT, 0) }
  }
  const ask = askView(structured.ask)
  if (!ask) return { kind: "none" }
  const note = structured.step === "client" ? "Step 1 of 2: the OAuth client. The agent asks for the connection once it is saved." : null
  return { kind: "single", ask, note }
}

export type AskStateRead = { state: AskState; expiresAt: string | null; message: string | null }

// vault_ask_state's answer, or null for an error or anything unexpected.
export function askStateFrom(result: CallToolResult, id: string): AskStateRead | null {
  if (result.isError === true) return null
  const structured = record(result.structuredContent)
  if (!structured || structured.id !== id) return null
  const state = text(structured.state)
  if (state === null || !(ASK_STATES as readonly string[]).includes(state)) return null
  return { state: state as AskState, expiresAt: text(structured.expiresAt), message: text(structured.message) }
}

export const FOLLOW_WAIT_SECONDS = 20
export const ERROR_BACKOFF_MS = 30_000
export const MAX_ERRORS = 5
// A host or vault that answers "waiting" at once is asked again no sooner than this.
export const MIN_SPACING_MS = 5_000

export type FollowEnd = { end: "settled"; state: AskState } | { end: "expired" } | { end: "errors" } | { end: "stopped" }

export type FollowOptions = {
  id: string
  workspace: string | null
  call: (args: Record<string, unknown>) => Promise<CallToolResult>
  sleep: (ms: number) => Promise<void>
  now: () => number
  expired: () => boolean
  stopped: () => boolean
  onRead: (read: AskStateRead) => void
}

// Follows one ask through vault_ask_state until it is no longer waiting,
// its link expires, the card is torn down, or five calls in a row fail
// (each failure waits 30 s before the next call).
export async function followAsk(options: FollowOptions): Promise<FollowEnd> {
  let errors = 0
  for (;;) {
    if (options.stopped()) return { end: "stopped" }
    if (options.expired()) return { end: "expired" }
    const started = options.now()
    let read: AskStateRead | null = null
    try {
      read = askStateFrom(await options.call({ id: options.id, ...(options.workspace ? { workspace: options.workspace } : {}), waitSeconds: FOLLOW_WAIT_SECONDS }), options.id)
    } catch {
      read = null
    }
    if (options.stopped()) return { end: "stopped" }
    if (read === null) {
      errors++
      if (errors >= MAX_ERRORS) return { end: "errors" }
      await options.sleep(ERROR_BACKOFF_MS)
      continue
    }
    errors = 0
    options.onRead(read)
    if (read.state !== "waiting") return { end: "settled", state: read.state }
    const spacing = MIN_SPACING_MS - (options.now() - started)
    if (spacing > 0) await options.sleep(spacing)
  }
}

// What the agent learns on its next turn once asks have settled: one ask as
// { ask, state }, several as { asks: [{ ask, state }] } (each update replaces the last).
export function modelContext(settled: { id: string; state: AskState }[]): Record<string, unknown> | null {
  if (settled.length === 0) return null
  if (settled.length === 1) return { ask: settled[0]?.id, state: settled[0]?.state }
  return { asks: settled.map((s) => ({ ask: s.id, state: s.state })) }
}
