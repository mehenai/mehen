// The consoles' form checks: what was typed becomes a command's terms
// under the protocol's schemas, or the sentences that say what to fix,
// before any passkey is asked for.
import { describe, expect, it } from "vitest"
import { DEFAULT_PLATFORM_LIMITS, INITIAL_PLATFORM_DEFAULTS } from "@mehen/protocol/platform"
import { accountIdOf, afterDaysOf, confirmOf, defaultsOf, limitsChangeOf, overlapHoursOf, reasonOf, registerNameOf, registerSlugOf, subjectOf } from "./console-logic.ts"

describe("the consoles' form checks", () => {
  it("takes the slug typed back only exactly", () => {
    expect(confirmOf(" globex ", "globex")).toEqual({ ok: true, value: "globex" })
    for (const typed of ["Globex", "ery", "globex-2", ""]) expect(confirmOf(typed, "globex").ok, typed).toBe(false)
  })

  it("takes whole hours to 168 and whole days to 365", () => {
    expect(overlapHoursOf("0")).toEqual({ ok: true, value: 0 })
    expect(overlapHoursOf(" 168 ")).toEqual({ ok: true, value: 168 })
    for (const typed of ["169", "-1", "1.5", "", "24h"]) expect(overlapHoursOf(typed).ok, typed).toBe(false)
    expect(afterDaysOf("365")).toEqual({ ok: true, value: 365 })
    expect(afterDaysOf("366").ok).toBe(false)
  })

  it("takes a reason as one trimmed line", () => {
    expect(reasonOf("  key leaked  ")).toEqual({ ok: true, value: "key leaked" })
    for (const typed of ["", "   ", "a\nb", "x".repeat(201)]) expect(reasonOf(typed).ok).toBe(false)
  })

  it("refuses a new slug a removed platform's could clash with, and any slug the schema refuses", () => {
    expect(registerSlugOf("globex")).toEqual({ ok: true, value: "globex" })
    for (const typed of ["removed-globex", "Globex", "er", "a--b", "1abc", "-abc"]) expect(registerSlugOf(typed).ok, typed).toBe(false)
    expect(registerNameOf(" Globex ")).toEqual({ ok: true, value: "Globex" })
    expect(registerNameOf("").ok).toBe(false)
    expect(registerNameOf("x".repeat(65)).ok).toBe(false)
  })

  it("refuses a slug a listed platform holds before any passkey, saying when a removed one's is free", () => {
    const held = { globex: "removing", acme: "registered" } as const
    const removing = registerSlugOf(" globex ", held)
    expect(removing.ok).toBe(false)
    if (!removing.ok) expect(removing.problems).toEqual(["globex is still held by the platform being removed. It is free once the cron has purged that platform's subjects, within 30 minutes for 50 or fewer; reload this page then."])
    expect(registerSlugOf("acme", held)).toEqual({ ok: false, problems: ["A platform with the slug acme exists. Choose another."] })
    expect(registerSlugOf("globex-two", held)).toEqual({ ok: true, value: "globex-two" })
    expect(registerSlugOf("constructor", held)).toEqual({ ok: true, value: "constructor" })
  })

  it("takes an account id and a subject as their schemas do", () => {
    expect(accountIdOf("acc_4Hq9Tz2Lm7Vb1Nc8").ok).toBe(true)
    expect(accountIdOf("mem_alex0001").ok).toBe(false)
    expect(subjectOf("user_7f3c9a21").ok).toBe(true)
    expect(subjectOf("short").ok).toBe(false)
    expect(subjectOf("has space in it").ok).toBe(false)
  })

  it("sends only the limits that changed, and only a set the schema allows", () => {
    const typed = Object.fromEntries(Object.entries(DEFAULT_PLATFORM_LIMITS).map(([k, v]) => [k, String(v)]))
    expect(limitsChangeOf(DEFAULT_PLATFORM_LIMITS, typed)).toEqual({ ok: false, problems: ["No limit changed."] })
    expect(limitsChangeOf(DEFAULT_PLATFORM_LIMITS, { ...typed, subjects: " 2000 ", callsPerMinute: "900" })).toEqual({ ok: true, value: { subjects: 2000, callsPerMinute: 900 } })
    expect(limitsChangeOf(DEFAULT_PLATFORM_LIMITS, { ...typed, decisionTtlSeconds: "30" }).ok).toBe(false)
    expect(limitsChangeOf(DEFAULT_PLATFORM_LIMITS, { ...typed, subjects: "lots" }).ok).toBe(false)
  })

  it("checks the defaults with defaults.put's own schema: no allow rule, nothing outside the catalogue", () => {
    expect(defaultsOf(JSON.stringify(INITIAL_PLATFORM_DEFAULTS))).toEqual({ ok: true, value: INITIAL_PLATFORM_DEFAULTS })
    const allow = defaultsOf(JSON.stringify({ ...INITIAL_PLATFORM_DEFAULTS, rules: { openai: [{ action: "allow" }] } }))
    expect(allow.ok).toBe(false)
    if (!allow.ok) expect(allow.problems.join(" ")).toContain("may only hold (approve) or refuse (deny)")
    expect(defaultsOf(JSON.stringify({ ...INITIAL_PLATFORM_DEFAULTS, templates: ["made-up"] })).ok).toBe(false)
    expect(defaultsOf("{not json").ok).toBe(false)
  })

  it("says what is wrong with the defaults' shape in plain words, never the schema's own", () => {
    const problems = (text: string) => {
      const read = defaultsOf(text)
      return read.ok ? [] : read.problems
    }
    // The defaults Alex sets for Globex are taken as they are.
    expect(defaultsOf('{ "providers": ["google-gmail", "google-calendar", "google-drive", "github-oauth", "microsoft-graph"], "scopes": {}, "tags": [], "customReads": "allow", "rules": {} }').ok).toBe(true)
    expect(problems(JSON.stringify({ ...INITIAL_PLATFORM_DEFAULTS, extra: 1 }))).toEqual(['The defaults take only templates, providers, scopes, tags, customReads and rules; remove "extra".'])
    expect(problems('{ "providers": [] }')).toEqual(["scopes is missing.", "tags is missing.", "customReads is missing.", "rules is missing."])
    expect(problems("[]")).toEqual(["The defaults are one JSON object with templates, providers, scopes, tags, customReads and rules."])
    expect(problems(JSON.stringify({ ...INITIAL_PLATFORM_DEFAULTS, customReads: "maybe", tags: "globex" }))).toEqual(["tags must be a list.", 'customReads must be "allow" or "approve".'])
    expect(problems(JSON.stringify({ ...INITIAL_PLATFORM_DEFAULTS, tags: ["Bad Tag"] }))).toEqual(["tags.0: a tag is up to 40 lower-case letters, digits, colons, underscores and hyphens, starting with a letter or digit."])
    expect(problems(JSON.stringify({ ...INITIAL_PLATFORM_DEFAULTS, providers: ["nope"] }))).toEqual(['providers.0: The catalogue has no OAuth provider "nope".'])
    for (const text of ['{ "providers": [] }', "[]", JSON.stringify({ ...INITIAL_PLATFORM_DEFAULTS, extra: 1 })]) expect(problems(text).join(" ")).not.toMatch(/Invalid input|Unrecognized|expected .* received/)
  })
})
