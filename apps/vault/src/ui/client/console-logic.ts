// The consoles' form checks, before any passkey is asked for: each turns
// what was typed into a command's terms under the protocol's own schemas
// (platform-console.ts in the protocol package), or into the plain
// sentences that say what to fix. The vault checks every one again.

import { AccountIdSchema, PLATFORM_KEY_MAX_OVERLAP_HOURS, PLATFORM_RETIRE_MAX_DAYS, type PlatformLimitsChange, REMOVED_PLATFORM_SLUG_PREFIX } from "@mehen/protocol/platform-console"
import type { z } from "zod"
import { type PlatformDefaults, PlatformDefaultsSchema, type PlatformLimits, PlatformLimitsSchema, PlatformNameSchema, PlatformSlugSchema, PlatformSubjectSchema } from "@mehen/protocol/platform"

export type Checked<T> = { ok: true; value: T } | { ok: false; problems: string[] }

function refused<T>(...problems: string[]): Checked<T> {
  return { ok: false, problems }
}

// A whole number typed into a field, from 0 to `max`.
function wholeNumber(text: string, max: number, what: string): Checked<number> {
  const trimmed = text.trim()
  if (!/^\d{1,9}$/.test(trimmed) || Number(trimmed) > max) return refused(`${what} must be a whole number from 0 to ${max}.`)
  return { ok: true, value: Number(trimmed) }
}

export function overlapHoursOf(text: string): Checked<number> {
  return wholeNumber(text, PLATFORM_KEY_MAX_OVERLAP_HOURS, "The hours the other keys keep working")
}

export function afterDaysOf(text: string): Checked<number> {
  return wholeNumber(text, PLATFORM_RETIRE_MAX_DAYS, "The days until it retires")
}

// A reason, as the vault records it: trimmed, one line, at most 200.
export function reasonOf(text: string): Checked<string> {
  const trimmed = text.trim()
  if (trimmed === "") return refused("Say why, in a few words. It is kept in the platform's record.")
  if (trimmed.length > 200 || /[\u0000-\u001f\u007f]/.test(trimmed)) return refused("Keep the reason to one line of at most 200 characters.")
  return { ok: true, value: trimmed }
}

// The slug typed back, exactly.
export function confirmOf(text: string, slug: string): Checked<string> {
  const trimmed = text.trim()
  if (trimmed !== slug) return refused(`Type the platform's slug, ${slug}, exactly, to confirm.`)
  return { ok: true, value: trimmed }
}

export function registerNameOf(text: string): Checked<string> {
  const trimmed = text.trim()
  if (!PlatformNameSchema.safeParse(trimmed).success || /[\u0000-\u001f\u007f]/.test(trimmed)) return refused("Give the platform a name of 1 to 64 characters.")
  return { ok: true, value: trimmed }
}

// The slugs platforms hold when the register page was drawn: a registered
// platform's for good, one being removed until the cron frees it.
export type HeldSlugs = Readonly<Record<string, "registered" | "removing">>

export function registerSlugOf(text: string, held: HeldSlugs = {}): Checked<string> {
  const slug = text.trim()
  if (slug.startsWith(REMOVED_PLATFORM_SLUG_PREFIX)) return refused(`A slug may not start with ${REMOVED_PLATFORM_SLUG_PREFIX}: removed platforms keep those.`)
  if (!PlatformSlugSchema.safeParse(slug).success) return refused("The slug is 3 to 40 lower-case letters, digits and single hyphens, starting with a letter.")
  const holder = Object.hasOwn(held, slug) ? held[slug] : undefined
  if (holder === "removing") return refused(`${slug} is still held by the platform being removed. It is free once the cron has purged that platform's subjects, within 30 minutes for 50 or fewer; reload this page then.`)
  if (holder === "registered") return refused(`A platform with the slug ${slug} exists. Choose another.`)
  return { ok: true, value: slug }
}

export function accountIdOf(text: string): Checked<string> {
  const account = text.trim()
  if (!AccountIdSchema.safeParse(account).success) return refused("That is not a Mehen account id. It starts acc_ and is on the person's Your account page.")
  return { ok: true, value: account }
}

export function subjectOf(text: string): Checked<string> {
  const subject = text.trim()
  if (!PlatformSubjectSchema.safeParse(subject).success) return refused("A subject is 8 to 128 letters, digits, hyphens and underscores, exactly as the platform knows it.")
  return { ok: true, value: subject }
}

// The limits that changed, from every limit's field: each a whole number,
// and the whole set as PlatformLimitsSchema allows it. Nothing changed is
// a problem too, so no passkey is asked for to change nothing.
export function limitsChangeOf(before: PlatformLimits, typed: Readonly<Record<string, string>>): Checked<PlatformLimitsChange> {
  const change: Record<string, number> = {}
  const problems: string[] = []
  for (const key of Object.keys(before) as (keyof PlatformLimits)[]) {
    const text = (typed[key] ?? String(before[key])).trim()
    if (!/^\d{1,9}$/.test(text)) {
      problems.push(`${key} must be a whole number.`)
      continue
    }
    if (Number(text) !== before[key]) change[key] = Number(text)
  }
  if (problems.length > 0) return { ok: false, problems }
  if (Object.keys(change).length === 0) return refused("No limit changed.")
  const after = PlatformLimitsSchema.safeParse({ ...before, ...change })
  if (!after.success) return { ok: false, problems: after.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`) }
  return { ok: true, value: change }
}

const DEFAULTS_FIELDS = "templates, providers, scopes, tags, customReads and rules"

// What the person typed at an issue's path, to tell a missing field from a
// wrong one.
function typedAt(raw: unknown, path: readonly PropertyKey[]): unknown {
  let at = raw
  for (const key of path) {
    if (typeof at !== "object" || at === null) return undefined
    at = (at as Record<PropertyKey, unknown>)[key]
  }
  return at
}

const EXPECTED_WORDS: Readonly<Record<string, string>> = { object: "an object", record: "an object", array: "a list", string: "text in quotes" }

// One schema issue as a sentence: the catalogue's and the rules' own words
// as they are, the shape's in plain words.
function defaultsProblem(raw: unknown, issue: z.core.$ZodIssue): string {
  const where = issue.path.map(String).join(".")
  switch (issue.code) {
    case "unrecognized_keys":
      return where === "" ? `The defaults take only ${DEFAULTS_FIELDS}; remove ${issue.keys.map((k) => `"${k}"`).join(", ")}.` : `${where} has no field ${issue.keys.map((k) => `"${k}"`).join(", ")}.`
    case "invalid_type":
      if (where === "") return `The defaults are one JSON object with ${DEFAULTS_FIELDS}.`
      if (typedAt(raw, issue.path) === undefined) return `${where} is missing.`
      return `${where} must be ${EXPECTED_WORDS[issue.expected] ?? issue.expected}.`
    case "invalid_value":
      if (typedAt(raw, issue.path) === undefined) return `${where} is missing.`
      return `${where} must be ${issue.values.map((v) => `"${String(v)}"`).join(" or ")}.`
    case "invalid_format":
      return where.startsWith("tags.") ? `${where}: a tag is up to 40 lower-case letters, digits, colons, underscores and hyphens, starting with a letter or digit.` : `${where} is not in the form it needs.`
    default:
      return `${where === "" ? "" : `${where}: `}${issue.message}`
  }
}

// The defaults editor's JSON, under the same schema as defaults.put.
export function defaultsOf(text: string): Checked<PlatformDefaults> {
  let raw: unknown
  try {
    raw = JSON.parse(text)
  } catch {
    return refused("The defaults are not JSON. Check the brackets, commas and quotes.")
  }
  const parsed = PlatformDefaultsSchema.safeParse(raw)
  if (!parsed.success) return { ok: false, problems: parsed.error.issues.map((issue) => defaultsProblem(raw, issue)) }
  return { ok: true, value: parsed.data }
}
