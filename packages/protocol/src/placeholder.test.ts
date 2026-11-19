import { describe, expect, test } from "bun:test"
import {
  type PlaceholderLookup,
  containsPlaceholder,
  findPlaceholders,
  newPlaceholder,
  placeholderCore,
  replacePlaceholders,
  secretPrefix,
} from "./placeholder.ts"

const CORE_SHAPE = /^jvph[0-9A-Za-z]{24}$/

type Entry = { placeholder: string; value: string }

function lookupOf(entries: Entry[]): PlaceholderLookup {
  const byCore = new Map<string, Entry>()
  for (const entry of entries) {
    const core = placeholderCore(entry.placeholder)
    if (core === null) throw new Error(`not a placeholder: ${entry.placeholder}`)
    byCore.set(core, entry)
  }
  return (core) => byCore.get(core) ?? null
}

function coreOf(placeholder: string): string {
  const core = placeholderCore(placeholder)
  if (core === null) throw new Error(`not a placeholder: ${placeholder}`)
  return core
}

describe("secretPrefix", () => {
  test("recognises known prefixes, longest first", () => {
    expect(secretPrefix("sk-proj-abc123")).toBe("sk-proj-")
    expect(secretPrefix("sk-ant-api03-abc")).toBe("sk-ant-api03-")
    expect(secretPrefix("sk-ant-abc")).toBe("sk-ant-")
    expect(secretPrefix("sk-abc")).toBe("sk-")
    expect(secretPrefix("ghp_abc")).toBe("ghp_")
    expect(secretPrefix("github_pat_abc")).toBe("github_pat_")
    expect(secretPrefix("xoxb-123-456")).toBe("xoxb-")
    expect(secretPrefix("AKIAIOSFODNN7EXAMPLE")).toBe("AKIA")
  })

  test("returns nothing for unknown values", () => {
    expect(secretPrefix("")).toBe("")
    expect(secretPrefix("correct-horse-battery")).toBe("")
    expect(secretPrefix("SK-PROJ-abc")).toBe("")
    expect(secretPrefix("xsk-proj-abc")).toBe("")
  })
})

describe("newPlaceholder", () => {
  test("keeps the sk-proj- prefix", () => {
    const p = newPlaceholder("sk-proj-REALVALUE")
    expect(p.startsWith("sk-proj-jvph")).toBe(true)
    expect(p.length).toBe("sk-proj-".length + 28)
    expect(coreOf(p)).toMatch(CORE_SHAPE)
  })

  test("keeps the ghp_ prefix", () => {
    const p = newPlaceholder("ghp_REALVALUE")
    expect(p.startsWith("ghp_jvph")).toBe(true)
    expect(p.length).toBe(4 + 28)
  })

  test("keeps the xoxb- prefix", () => {
    const p = newPlaceholder("xoxb-1234-5678-abcd")
    expect(p.startsWith("xoxb-jvph")).toBe(true)
    expect(p.length).toBe(5 + 28)
  })

  test("an unknown value or no hint gives a bare core", () => {
    expect(newPlaceholder("correct-horse-battery")).toMatch(CORE_SHAPE)
    expect(newPlaceholder()).toMatch(CORE_SHAPE)
  })

  test("never contains the real value", () => {
    expect(newPlaceholder("sk-proj-REALVALUE")).not.toContain("REALVALUE")
  })

  test("10k placeholders are unique and well formed", () => {
    const seen = new Set<string>()
    for (let i = 0; i < 10_000; i++) {
      const p = newPlaceholder("sk-proj-x")
      expect(p.startsWith("sk-proj-")).toBe(true)
      seen.add(coreOf(p))
    }
    expect(seen.size).toBe(10_000)
  })

  test("uses the whole base62 alphabet", () => {
    const chars = new Set<string>()
    for (let i = 0; i < 2_000; i++) for (const c of newPlaceholder().slice(4)) chars.add(c)
    expect(chars.size).toBe(62)
  })
})

describe("placeholderCore, findPlaceholders and containsPlaceholder", () => {
  test("placeholderCore takes the core from the end", () => {
    const p = newPlaceholder("sk-proj-x")
    expect(placeholderCore(p)).toBe(p.slice("sk-proj-".length))
    expect(placeholderCore("sk-proj-not-a-placeholder")).toBeNull()
    expect(placeholderCore(`${p}x`)).toBeNull()
    expect(placeholderCore("jvph" + "a".repeat(23))).toBeNull()
  })

  test("findPlaceholders returns each core once", () => {
    const a = newPlaceholder("ghp_x")
    const b = newPlaceholder()
    const found = findPlaceholders(`token=${a} other=${b} again=${a}`)
    expect(found.sort()).toEqual([coreOf(a), coreOf(b)].sort())
    expect(findPlaceholders("nothing here")).toEqual([])
  })

  test("containsPlaceholder is stable across repeated calls", () => {
    const text = `key ${newPlaceholder()}`
    for (let i = 0; i < 5; i++) expect(containsPlaceholder(text)).toBe(true)
    expect(containsPlaceholder("jvph-short")).toBe(false)
    expect(containsPlaceholder(text)).toBe(true)
  })
})

describe("replacePlaceholders", () => {
  test("a placeholder with its prefix kept becomes the real value", () => {
    const placeholder = newPlaceholder("sk-proj-REAL")
    const lookup = lookupOf([{ placeholder, value: "sk-proj-REAL" }])
    const result = replacePlaceholders(`Authorization: Bearer ${placeholder}`, lookup)
    expect(result).toEqual({ text: "Authorization: Bearer sk-proj-REAL", unknown: [], used: [coreOf(placeholder)] })
  })

  test("a bare core whose prefix was stripped becomes the real value", () => {
    const placeholder = newPlaceholder("sk-proj-REAL")
    const lookup = lookupOf([{ placeholder, value: "sk-proj-REAL" }])
    const result = replacePlaceholders(`key=${coreOf(placeholder)}&x=1`, lookup)
    expect(result.text).toBe("key=sk-proj-REAL&x=1")
    expect(result.used).toEqual([coreOf(placeholder)])
  })

  test("a partial prefix in front of the core is left as text", () => {
    const placeholder = newPlaceholder("sk-proj-REAL")
    const lookup = lookupOf([{ placeholder, value: "sk-proj-REAL" }])
    expect(replacePlaceholders(`proj-${coreOf(placeholder)}`, lookup).text).toBe("proj-sk-proj-REAL")
  })

  test("replaces several placeholders and repeats", () => {
    const a = newPlaceholder("sk-proj-A")
    const b = newPlaceholder("ghp_B")
    const c = newPlaceholder("plainvalue")
    const lookup = lookupOf([
      { placeholder: a, value: "sk-proj-AAAA" },
      { placeholder: b, value: "ghp_BBBB" },
      { placeholder: c, value: "plainvalue" },
    ])
    const result = replacePlaceholders(`${a} ${b},${c};${a}${b}`, lookup)
    expect(result.text).toBe("sk-proj-AAAA ghp_BBBB,plainvalue;sk-proj-AAAAghp_BBBB")
    expect(result.used.sort()).toEqual([coreOf(a), coreOf(b), coreOf(c)].sort())
    expect(result.unknown).toEqual([])
  })

  test("reports unknown cores once and leaves them in place", () => {
    const known = newPlaceholder("ghp_K")
    const stranger = newPlaceholder("sk-proj-S")
    const lookup = lookupOf([{ placeholder: known, value: "ghp_KNOWN" }])
    const input = `a=${stranger} b=${known} c=${stranger}`
    const result = replacePlaceholders(input, lookup)
    expect(result.text).toBe(`a=${stranger} b=ghp_KNOWN c=${stranger}`)
    expect(result.unknown).toEqual([coreOf(stranger)])
    expect(result.used).toEqual([coreOf(known)])
  })

  test("leaves adjacent text untouched", () => {
    const placeholder = newPlaceholder("xoxb-R")
    const lookup = lookupOf([{ placeholder, value: "xoxb-REAL" }])
    expect(replacePlaceholders(`"${placeholder}"`, lookup).text).toBe('"xoxb-REAL"')
    expect(replacePlaceholders(`pre${placeholder}post`, lookup).text).toBe("prexoxb-REALpost")
    expect(replacePlaceholders(`${placeholder}9`, lookup).text).toBe("xoxb-REAL9")
    expect(replacePlaceholders(`xoxb-${placeholder}`, lookup).text).toBe("xoxb-xoxb-REAL")
    expect(replacePlaceholders(`{"k":"${placeholder}"}\n`, lookup).text).toBe('{"k":"xoxb-REAL"}\n')
  })

  test("text without placeholders is returned unchanged", () => {
    const result = replacePlaceholders("nothing to see, jvph too short", () => null)
    expect(result).toEqual({ text: "nothing to see, jvph too short", unknown: [], used: [] })
  })

  test("a value with regex replacement tokens is inserted literally", () => {
    const placeholder = newPlaceholder()
    const lookup = lookupOf([{ placeholder, value: "$&$1$$" }])
    expect(replacePlaceholders(`v=${placeholder}`, lookup).text).toBe("v=$&$1$$")
  })
})
