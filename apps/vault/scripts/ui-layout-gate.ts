// The gallery layout gate's rules, apart from Chrome so they can be tested:
// a probe answer is accepted only when it is the gallery page that was asked
// for and a well-formed list of findings; a navigation that failed is
// refused; the run counts only accepted measurements and must reach exactly
// one per state, width and scheme; and the findings are compared with the
// checked-in baseline (scripts/ui-layout-baseline.json). Every refusal
// throws, so the gate fails closed: a probe that did not run can never pass
// as a page with nothing wrong. scripts/ui-gallery.ts drives it.

export type LayoutKind = "page" | "viewport" | "spill" | "text" | "clipped" | "scrolls" | "squeezed" | "crushed"
export type LayoutScheme = "light" | "dark"

// `selector` is the element's tag and classes, what the baseline matches
// on; `element` adds the start of its text, for a person reading the report.
export type LayoutIssue = { kind: LayoutKind; px: number; selector: string; element: string }

// What the probe returns: the gallery entry the page says it is, and what it found.
export type ProbeAnswer = { entry: string | null; issues: LayoutIssue[] }

// The parts of a CDP Runtime.evaluate reply the gate reads.
export type EvaluateReply = { result?: { value?: unknown }; exceptionDetails?: { text?: string; exception?: { description?: string } } }

// The parts of a CDP Page.navigate reply the gate reads.
export type NavigateReply = { errorText?: string }

// The <meta> every gallery page carries, naming its entry.
export const GALLERY_ENTRY_META = "mehen-gallery-entry"

//   SH shell and home, AK ask pages, PM people and machines,
//   CP credentials, projects and activity, F1 account and first run.
export type Lane = "SH" | "AK" | "PM" | "CP" | "F1"

export type LayoutBaselineEntry = { id: string; width: number; scheme: LayoutScheme; kind: LayoutKind; selector: string; lane: Lane; cause: string }

export type LayoutFinding = LayoutIssue & { id: string; width: number; scheme: LayoutScheme; shot: string }

const KINDS: readonly string[] = ["page", "viewport", "spill", "text", "clipped", "scrolls", "squeezed", "crushed"]

function isIssue(value: unknown): value is LayoutIssue {
  if (typeof value !== "object" || value === null) return false
  const v = value as Record<string, unknown>
  return typeof v.kind === "string" && KINDS.includes(v.kind) && typeof v.px === "number" && Number.isFinite(v.px) && typeof v.selector === "string" && v.selector !== "" && typeof v.element === "string"
}

// Refuses a navigation Chrome reports as failed, such as a missing file.
export function checkNavigation(where: string, reply: NavigateReply): void {
  if (reply.errorText !== undefined && reply.errorText !== "") throw new Error(`layout: ${where} did not load: ${reply.errorText}`)
}

// The findings from one probe, or a refusal naming the state: the probe
// threw, answered nothing or something malformed, or the page is not the
// gallery entry that was asked for (a browser error page, another file).
export function acceptProbe(where: string, expectedEntry: string, reply: EvaluateReply): LayoutIssue[] {
  if (reply.exceptionDetails !== undefined) throw new Error(`layout: the probe threw on ${where}: ${reply.exceptionDetails.exception?.description ?? reply.exceptionDetails.text ?? "no message"}`)
  const value = reply.result?.value
  if (typeof value !== "object" || value === null) throw new Error(`layout: the probe gave no answer on ${where}`)
  const answer = value as Record<string, unknown>
  if (answer.entry !== expectedEntry) throw new Error(`layout: ${where} is not the gallery page ${expectedEntry} (it says ${String(answer.entry)})`)
  if (!Array.isArray(answer.issues) || !answer.issues.every(isIssue)) throw new Error(`layout: the probe's findings on ${where} are malformed`)
  return answer.issues
}

// The run must have measured every state at every width in every scheme,
// and at least one: an empty gallery cannot pass an empty baseline.
export function checkMeasured(measured: number, states: number, widths: number, schemes: number): void {
  const expected = states * widths * schemes
  if (expected === 0) throw new Error("layout: nothing to measure (no gallery states, widths or schemes)")
  if (measured !== expected) throw new Error(`layout: measured ${measured} of ${expected} states (${states} pages x ${widths} widths x ${schemes} schemes)`)
}

export function baselineKey(f: { id: string; width: number; scheme: string; kind: string; selector: string }): string {
  return `${f.id} ${f.width} ${f.scheme} ${f.kind} ${f.selector}`
}

// Findings the baseline does not list, and baseline entries that no longer
// occur (fixed: the lane that fixed them deletes them). Either fails the run.
export function compareBaseline(findings: readonly LayoutFinding[], baseline: readonly LayoutBaselineEntry[]): { fresh: LayoutFinding[]; gone: LayoutBaselineEntry[] } {
  const known = new Set(baseline.map(baselineKey))
  const seen = new Set(findings.map(baselineKey))
  return { fresh: findings.filter((f) => !known.has(baselineKey(f))), gone: baseline.filter((b) => !seen.has(baselineKey(b))) }
}
