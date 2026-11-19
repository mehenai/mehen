// The browser's pure logic: what gets sealed and what gets signed. No DOM
// here, so it runs under bun test and inside workerd, where the tests
// compare it with the server's digests.

import type { BindingInput, IntakeSubmitBody } from "@mehen/protocol/api"
import { isLeaseOnly } from "@mehen/protocol/binding"
import { canonicalJson } from "@mehen/protocol/canonical-json"
import { sha256B64 } from "@mehen/protocol/bytes"
import { fillOrigin, signinOrigins } from "@mehen/protocol/fill"
import { fingerprintGroupCheck, normaliseFingerprintGroup } from "@mehen/protocol/fingerprint"

export function digestOf(value: unknown): Promise<string> {
  return sha256B64(canonicalJson(value))
}

// Splits a comma or newline separated list, trimmed, without empties or repeats.
export function parseList(text: string): string[] {
  const out: string[] = []
  for (const part of text.split(/[\n,]/)) {
    const value = part.trim()
    if (value && !out.includes(value)) out.push(value)
  }
  return out
}

// ---------------------------------------------------------------- intake

export type IntakeFieldBoot = { name: string; label: string; secret: boolean; required: boolean; multiline: boolean }
// `customPolicy`: the page offers the reads tick (IntakeView.customPolicy).
// `fillChoice`: the page offers "How may agents use it?" (pages/intake.ts).
export type IntakeBoot = { intake: string; slug: string; binding: BindingInput; verified: boolean; rotates: boolean; tags: string[]; fields: IntakeFieldBoot[]; customPolicy?: boolean; fillChoice?: true }
export type IntakeSubmission = Omit<IntakeSubmitBody, "stepUp">
export type Sealer = (value: string, context: string) => Promise<unknown>
export type Built<T> = { ok: true; value: T } | { ok: false; problems: string[] }

export function intakeSealContext(intake: string, field: string): string {
  return `intake/${intake}/${field}`
}

// Pasted single-line values lose stray surrounding whitespace; multi-line
// values (keys, files) keep everything but trailing whitespace.
function cleanValue(field: IntakeFieldBoot, raw: string): string {
  return field.multiline ? raw.replace(/\s+$/, "") : raw.trim()
}

export function intakeNeedsAcceptance(boot: Pick<IntakeBoot, "verified" | "rotates" | "binding">): boolean {
  return !boot.verified && !boot.rotates && !isLeaseOnly(boot.binding)
}

export async function buildIntakeSubmission(
  boot: IntakeBoot,
  values: Record<string, string>,
  acceptedDestination: boolean,
  sealer: Sealer,
  allowReads = false,
  typeIntoSignIn = false,
): Promise<Built<{ submission: IntakeSubmission; digest: string }>> {
  const problems: string[] = []
  if (intakeNeedsAcceptance(boot) && !acceptedDestination) {
    problems.push("Tick the box to accept the destination the agent proposed, after checking every host.")
  }
  for (const field of boot.fields) {
    if (field.required && cleanValue(field, values[field.name] ?? "") === "") problems.push(`Fill in ${field.label}.`)
  }
  if (problems.length) return { ok: false, problems }
  const publicFields: Record<string, string> = {}
  const sealed: Record<string, unknown> = {}
  for (const field of boot.fields) {
    const value = cleanValue(field, values[field.name] ?? "")
    if (value === "") continue
    if (field.secret) sealed[field.name] = await sealer(value, intakeSealContext(boot.intake, field.name))
    else publicFields[field.name] = value
  }
  const submission: IntakeSubmission = {
    slug: boot.slug,
    binding: boot.binding,
    publicFields,
    sealed,
    tags: boot.tags,
    ...(boot.customPolicy === true && allowReads ? { allowReads: true } : {}),
    ...(boot.fillChoice === true && typeIntoSignIn ? { ceiling: "fill" as const } : {}),
  }
  return { ok: true, value: { submission, digest: await intakeDigest(submission) } }
}

export type SetupStepState = "done" | "current" | "todo"

// The guided setup's done, current and to-do states from which fields are
// filled in: a step that names a filled field is done, and so is every step
// before it; the next one is current. A hint for the eye, not a gate.
export function setupStepStates(stepFields: readonly (string | null)[], filled: ReadonlySet<string>): SetupStepState[] {
  let lastDone = -1
  stepFields.forEach((field, i) => {
    if (field !== null && filled.has(field)) lastDone = i
  })
  return stepFields.map((_, i) => (i <= lastDone ? "done" : i === lastDone + 1 ? "current" : "todo"))
}

// The start or end a template's hint names for a field's value.
export type FieldShape = { at: "start" | "end"; literals: readonly string[] }

// Whether a value plainly lacks that shape, for a warning that never blocks
// saving. Until `settled` (the field is left), a value that could still be
// typed into one of the starts is not a miss, and an end is not judged.
export function missesFieldShape(shape: FieldShape, raw: string, settled: boolean): boolean {
  const value = raw.trim()
  if (value === "") return false
  if (shape.at === "end") return settled && !shape.literals.some((l) => value.endsWith(l))
  return !shape.literals.some((l) => value.startsWith(l) || (!settled && l.startsWith(value)))
}

export function intakeDigest(submission: IntakeSubmission): Promise<string> {
  return digestOf({
    slug: submission.slug,
    binding: submission.binding,
    publicFields: submission.publicFields,
    sealed: submission.sealed,
    tags: [...submission.tags].sort(),
    ...(submission.allowReads === true ? { allowReads: true } : {}),
    ...(submission.ceiling !== undefined ? { ceiling: submission.ceiling } : {}),
  })
}

// The pages a new login would be typed into, from the sign-in address typed
// so far and the hosts asked for, as the vault derives them (signinOrigins),
// and whether the address typed is one fill can never use.
export function intakeSigninPages(url: string, binding: BindingInput): { words: string | null; httpsOnly: boolean } {
  const typed = url.trim()
  const pages = signinOrigins({ publicFields: typed === "" ? {} : { url: typed }, binding })
  return { words: pages.length === 0 ? null : `${pages.length === 1 ? "Sign-in page" : "Sign-in pages"}: ${pages.join(", ")}`, httpsOnly: typed !== "" && fillOrigin(typed) === null }
}

// ---------------------------------------------------------------- enrolment

// The typed hidden group, read as the protocol reads it (case folded, I and
// L as 1, O as 0, spaces and hyphens dropped) and compared with the boot's
// check hash. `no-u` is called out on its own because a U is the one letter
// a person may read off a terminal that the alphabet never prints.
export type TypedGroupState = "empty" | "partial" | "no-u" | "invalid" | "matches" | "wrong"

// Keyed by the ref the page was opened with, the code or the enrolment id,
// as the vault keys the check it sent.
export async function typedGroupState(ref: string, check: string, typed: string): Promise<{ state: TypedGroupState; group: string }> {
  const stripped = typed.trim().replaceAll(/[\s-]/g, "").toUpperCase()
  if (stripped === "") return { state: "empty", group: "" }
  if (stripped.includes("U")) return { state: "no-u", group: stripped }
  const group = normaliseFingerprintGroup(stripped)
  if (group === undefined) return { state: /^[0-9A-Z]{1,3}$/.test(stripped) ? "partial" : "invalid", group: stripped }
  const matches = check !== "" && (await fingerprintGroupCheck(ref, group)) === check
  return { state: matches ? "matches" : "wrong", group }
}

// ---------------------------------------------------------------- change lines

export type ChangeLine = { text: string; widens: boolean }

// ---------------------------------------------------------------- projects

export type EnvironmentChange = { project: string; env: string; protected: boolean; fences: string[] }

// Step-up digest for POST /api/projects/:id/environments/:name, signed as
// item.update with item = the project id.
export function environmentChangeDigest(change: EnvironmentChange): Promise<string> {
  return digestOf({ change: "environment.update", project: change.project, env: change.env, protected: change.protected, fences: change.fences })
}

export function parseFences(text: string): string[] {
  return parseList(text.toLowerCase())
}
