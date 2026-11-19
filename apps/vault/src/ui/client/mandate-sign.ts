// Signing, pausing, stopping and resuming a mandate from its pages
// (pages/mandates.ts), with no DOM so the tests drive this exact code. The
// sign page builds the terms from the form, refuses what the vault would
// refuse in plain words, and signs one passkey over mandate.sign only once
// the vault's action carries the digest this page computed itself
// (mandateDigest) over the terms, the workspace and the person signing. A
// resume asks the vault whether it needs a passkey and never decides that
// itself; pause and stop need none. Each names the revision shown.

import type { MandateChanged, MandateClass, MandateSchedule, MandateTerms, WorkspaceStepUpAction } from "@mehen/protocol"
import { MANDATE_CLASSES, MandateTermsSchema, isMandateTimeZone, mandateCapsFit } from "@mehen/protocol/mandate-terms"
import { mandateDigest } from "@mehen/protocol/mandates"
import { MANDATE_BAD_CAPS, MANDATE_BAD_SCHEDULE, MANDATE_NO_NOTE, MANDATE_NOTHING_TICKED } from "../wording.ts"
import { VaultFailure, workspaceApi } from "./api.ts"
import type { ShellState } from "./shell-logic.ts"
import { CHANGED_SINCE_SHOWN, sameAction } from "./workspace-logic.ts"
import { type Passkey, browserPasskey, signAction, signed } from "./workspace-sign.ts"

// What the form holds now: the classes ticked (read always), a cap per
// class as typed, the credentials ticked by id or all, the length, the
// windows when Only at certain times is ticked, and the note.
export type MandateFormChoice = {
  classes: readonly MandateClass[]
  caps: Readonly<Record<MandateClass, number>>
  items: "all" | readonly string[]
  ttlDays: number
  schedule: { tz: string; windows: readonly { days: readonly number[]; from: string; to: string }[] } | null
  note: string
}

const sorted = <T extends string | number>(values: readonly T[]): T[] => [...new Set(values)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))

function schedule(choice: MandateFormChoice["schedule"]): MandateSchedule | null | "bad" {
  if (choice === null) return null
  const tz = choice.tz.trim()
  const windows = choice.windows.map((w) => ({ days: sorted(w.days), from: w.from, to: w.to }))
  if (!isMandateTimeZone(tz) || windows.length === 0 || windows.some((w) => w.days.length === 0 || w.from === "" || w.to === "" || w.from === w.to)) return "bad"
  return { tz, windows }
}

// The terms for this machine, or why not, in the page's words; the vault
// checks them all again.
export function mandateTermsOf(device: string, choice: MandateFormChoice): { terms: MandateTerms } | { refusal: string } {
  const classes = sorted<MandateClass>(["read", ...choice.classes])
  const caps = Object.fromEntries(MANDATE_CLASSES.map((c) => [c, classes.includes(c) ? choice.caps[c] : 0])) as Record<MandateClass, number>
  if (!MANDATE_CLASSES.every((c) => Number.isInteger(caps[c])) || !mandateCapsFit(classes, caps)) return { refusal: MANDATE_BAD_CAPS }
  const items = choice.items === "all" ? "all" as const : sorted(choice.items)
  if (items !== "all" && items.length === 0) return { refusal: MANDATE_NOTHING_TICKED }
  const note = choice.note.trim()
  if (note === "") return { refusal: MANDATE_NO_NOTE }
  const when = schedule(choice.schedule)
  if (when === "bad") return { refusal: MANDATE_BAD_SCHEDULE }
  const parsed = MandateTermsSchema.safeParse({ device, items, classes, caps, ttlDays: choice.ttlDays, schedule: when, note })
  return parsed.success ? { terms: parsed.data } : { refusal: parsed.error.issues[0]?.message ?? MANDATE_BAD_CAPS }
}

// The mandate.sign action the vault should build for these terms.
export async function mandateSignAction(workspace: string, signer: string, terms: MandateTerms): Promise<Extract<WorkspaceStepUpAction, { type: "mandate.sign" }>> {
  return { type: "mandate.sign", device: terms.device, digest: await mandateDigest({ terms, workspace, signer }) }
}

// A vault action other than the one expected is refused as changed since
// shown, before any passkey.
export async function signMandate(shell: ShellState, shown: { signer: string; proposal: string | null }, terms: MandateTerms, passkey: Passkey = browserPasskey): Promise<MandateChanged> {
  const expected = await mandateSignAction(shell.identity.workspace.id, shown.signer, terms)
  const body = { terms, ...(shown.proposal !== null ? { proposal: shown.proposal } : {}) }
  return signed<MandateChanged>(shell, { prepare: { path: "/mandates/action", body: { op: "sign", ...body } }, matches: (a) => sameAction(expected, a), mutation: { path: "/mandates", body } }, passkey)
}

// Whether Resume would run a passkey now: false only when the vault plans
// none for this mandate and revision; true when it plans one or the plan
// fails, so the page never says no passkey wrongly.
export async function resumeNeedsPasskey(shell: ShellState, id: string, rev: number): Promise<boolean> {
  const answer = await workspaceApi<WorkspaceStepUpAction | { stepUp: null }>(shell, "/mandates/action", { op: "resume", id, rev }).catch(() => null)
  return !(answer !== null && "stepUp" in answer && answer.stepUp === null)
}

// Resume: { stepUp: null } resumes straight away; a mandate.resume action
// for this mandate and revision runs the passkey first; anything else
// sends nothing.
export async function resumeMandate(shell: ShellState, id: string, rev: number, passkey: Passkey = browserPasskey): Promise<MandateChanged> {
  const path = `/mandates/${encodeURIComponent(id)}/resume`
  const answer = await workspaceApi<WorkspaceStepUpAction | { stepUp: null }>(shell, "/mandates/action", { op: "resume", id, rev })
  if ("stepUp" in answer && answer.stepUp === null) return workspaceApi<MandateChanged>(shell, path, { rev })
  const action = answer as WorkspaceStepUpAction
  if (action.type !== "mandate.resume" || action.mandate !== id || action.rev !== rev) throw new VaultFailure(409, CHANGED_SINCE_SHOWN)
  return signAction<MandateChanged>(shell, action, { path, body: { rev } }, undefined, passkey)
}

// Pause and stop: the revision shown, no passkey.
export function changeMandate(shell: ShellState, id: string, rev: number, change: "pause" | "stop"): Promise<MandateChanged> {
  return workspaceApi<MandateChanged>(shell, `/mandates/${encodeURIComponent(id)}/${change}`, { rev })
}

// Pause all: each "id:rev" the list shows, one request each, in turn; a
// refusal is counted and the rest still paused.
export async function pauseMandates(shell: ShellState, shown: string): Promise<{ total: number; refused: number }> {
  const entries = shown.split(" ").filter(Boolean)
  let refused = 0
  for (const entry of entries) {
    const [id, rev] = entry.split(":")
    await changeMandate(shell, id ?? "", Number(rev), "pause").catch(() => { refused++ })
  }
  return { total: entries.length, refused }
}
