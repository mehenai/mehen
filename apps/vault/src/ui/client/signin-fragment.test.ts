// A deep link's #fragment through sign-in: kept by /signin for the page its
// ?next= names, and put back on that page's address once signed in.

import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { SIGNIN_FRAGMENT_KEY, carriedFragment, rememberSigninFragment, signinDestination, takeSigninFragment } from "./signin-fragment.ts"

const PEOPLE = "/w/northwind/people"
const saved = (next: string, hash: string) => JSON.stringify({ next, hash })

describe("signinDestination", () => {
  it("puts the fragment saved for exactly this page back on it", () => {
    expect(signinDestination(PEOPLE, saved(PEOPLE, "#confirm-mem_tom01"), "")).toBe("/w/northwind/people#confirm-mem_tom01")
    expect(signinDestination("/w/northwind/people?tab=1", saved("/w/northwind/people?tab=1", "#confirm-mem_tom01"), "")).toBe("/w/northwind/people?tab=1#confirm-mem_tom01")
  })

  it("falls back to the fragment in /signin's own address", () => {
    expect(signinDestination(PEOPLE, null, "#confirm-mem_tom01")).toBe("/w/northwind/people#confirm-mem_tom01")
    expect(signinDestination(PEOPLE, saved("/w/other/people", "#confirm-mem_x"), "#confirm-mem_tom01")).toBe("/w/northwind/people#confirm-mem_tom01")
  })

  it("ignores a fragment saved for another page, a malformed save and an unusable fragment", () => {
    expect(signinDestination(PEOPLE, saved("/w/other/people", "#confirm-mem_x"), "")).toBe(PEOPLE)
    expect(signinDestination(PEOPLE, "{not json", "")).toBe(PEOPLE)
    expect(signinDestination(PEOPLE, JSON.stringify({ next: PEOPLE, hash: 42 }), "")).toBe(PEOPLE)
    for (const hash of ["", "#", "#a b", "#a\nb", `#${"x".repeat(513)}`, "confirm"]) expect(signinDestination(PEOPLE, null, hash), JSON.stringify(hash)).toBe(PEOPLE)
  })

  it("never adds a second fragment to a next that has one", () => {
    expect(signinDestination("/w/northwind/people#mine", saved("/w/northwind/people#mine", "#confirm-mem_tom01"), "#confirm-mem_tom01")).toBe("/w/northwind/people#mine")
  })

  it("carries only a fragment", () => {
    expect(carriedFragment("#confirm-mem_tom01")).toBe("#confirm-mem_tom01")
    expect(carriedFragment("/w/x")).toBeNull()
  })
})

describe("the tab's sessionStorage", () => {
  const g = globalThis as unknown as Record<string, unknown>
  let original: unknown
  let store: Map<string, string>
  beforeEach(() => {
    original = g.sessionStorage
    store = new Map()
    g.sessionStorage = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v), removeItem: (k: string) => void store.delete(k) }
  })
  afterEach(() => {
    g.sessionStorage = original
  })

  it("keeps the fragment from /signin and hands it back once, for the same page", () => {
    rememberSigninFragment(PEOPLE, "#confirm-mem_tom01")
    expect(store.get(SIGNIN_FRAGMENT_KEY)).toBe(saved(PEOPLE, "#confirm-mem_tom01"))
    expect(takeSigninFragment(PEOPLE, "")).toBe("/w/northwind/people#confirm-mem_tom01")
    expect(store.has(SIGNIN_FRAGMENT_KEY)).toBe(false)
    expect(takeSigninFragment(PEOPLE, "")).toBe(PEOPLE)
  })

  it("saves nothing without a fragment, and works when storage is refused", () => {
    rememberSigninFragment(PEOPLE, "")
    expect(store.size).toBe(0)
    g.sessionStorage = { getItem: () => { throw new Error("denied") }, setItem: () => { throw new Error("denied") }, removeItem: () => { throw new Error("denied") } }
    expect(() => rememberSigninFragment(PEOPLE, "#confirm-mem_tom01")).not.toThrow()
    expect(takeSigninFragment(PEOPLE, "#confirm-mem_tom01")).toBe("/w/northwind/people#confirm-mem_tom01")
  })
})
