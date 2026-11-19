// The boot names written in the server's page and route sources against the
// client's PAGES table in client/main.ts, read as source text: every name in
// the source has an init or is a static page, every init has a name in the
// source, and no name is both. It keeps the two in step; it does not prove a
// route serves a page (a name a caller always replaces still counts).

import { describe, expect, it } from "vitest"

const SERVER = import.meta.glob<string>(["./pages/*.ts", "./layout.ts", "../routes/*.ts", "!./pages/*.test.ts", "!../routes/*.test.ts"], { query: "?raw", import: "default", eager: true })
const MAIN = Object.values(import.meta.glob<string>("./client/main.ts", { query: "?raw", import: "default", eager: true }))[0] ?? ""

// Pages the client draws nothing on beyond the shared wiring.
const STATIC_PAGES: ReadonlySet<string> = new Set([
  "connect-closed",
  "error",
  "intake-closed",
  "machines",
  "operator",
  "operator-accounts",
  "operator-audit",
  "operator-workspaces",
  "people-guest",
  "platforms",
  "ws-adopt-inventory",
  "ws-adoption-closed",
  "ws-audit",
])

function emitted(): Set<string> {
  const names = new Set<string>()
  for (const text of Object.values(SERVER)) for (const m of text.matchAll(/\bpage: "([a-z][a-z-]*)"/g)) names.add(m[1]!)
  return names
}

function pagesKeys(): Set<string> {
  const start = MAIN.indexOf("const PAGES")
  const end = MAIN.indexOf("\n}\n", start)
  if (start < 0 || end < 0) throw new Error("client/main.ts has no PAGES table")
  const table = MAIN.slice(start, end)
  return new Set(Array.from(table.matchAll(/^ {2}(?:"([a-z-]+)"|([a-z]+)):/gm), (m) => (m[1] ?? m[2])!))
}

describe("boot names", () => {
  it("reads the server pages and the PAGES table", () => {
    expect(Object.keys(SERVER).length).toBeGreaterThan(20)
    expect(emitted().size).toBeGreaterThan(40)
    expect(pagesKeys().size).toBeGreaterThan(30)
  })

  it("has an init or a static entry for every name a page emits", () => {
    const pages = pagesKeys()
    expect([...emitted()].filter((name) => !pages.has(name) && !STATIC_PAGES.has(name))).toEqual([])
  })

  it("has a page emitting every init's and every static entry's name", () => {
    const names = emitted()
    expect([...pagesKeys()].filter((name) => !names.has(name))).toEqual([])
    expect([...STATIC_PAGES].filter((name) => !names.has(name))).toEqual([])
  })

  it("keeps the static pages out of PAGES", () => {
    const pages = pagesKeys()
    expect([...STATIC_PAGES].filter((name) => pages.has(name))).toEqual([])
  })
})
