import { expect, test } from "bun:test"
import { renderSearch } from "./search-page.ts"
import { type SearchEntry, search, snippetOf, tokenise } from "./search.ts"

test("a query is at most eight lower-case tokens of two characters or more, from 120 characters", () => {
  expect(tokenise("Approval_Required a, b2 !!")).toEqual(["approval", "required", "b2"])
  expect(tokenise("one two three four five six seven eight nine ten")).toHaveLength(8)
  expect(tokenise(`${"x".repeat(119)} late`)).toEqual(["x".repeat(119)])
})

const entries: SearchEntry[] = [
  { u: "/a#one", t: "Machines", h: "Reach", x: "A machine reaches what its owner can." },
  { u: "/b#two", t: "Placeholders", h: "How a run works", x: "Each variable is a placeholder in the child." },
  { u: "/c#three", t: "Runs", h: "Placeholders", x: "A placeholder has the real key's shape." },
]

test("a heading hit outranks a title hit, which outranks a text hit; ties keep the index order", () => {
  expect(search(entries, "placeholder", 20).map((h) => h.u)).toEqual(["/c#three", "/b#two"])
  expect(search(entries, "machine", 20).map((h) => h.u)).toEqual(["/a#one"])
  expect(search(entries, "", 20)).toEqual([])
  expect(search(entries, "placeholder", 1)).toHaveLength(1)
})

test("the snippet is the text around the first hit", () => {
  const text = `${"word ".repeat(60)}needle ${"tail ".repeat(60)}`
  const snippet = snippetOf(text, ["needle"])
  expect(snippet).toContain("needle")
  expect(snippet.startsWith("… ")).toBe(true)
  expect(snippet.endsWith(" …")).toBe(true)
})

test("the search page escapes the query and the results", () => {
  const shell = '<input value="{{query}}"><main><!--search-results--></main>'
  const out = renderSearch(shell, '"><img src=x>', search([{ u: "/x", t: "<b>", h: "h", x: "\"><img src=x> here" }], '"><img src=x>', 20))
  expect(out).not.toContain("<img")
  expect(out).toContain('value="&quot;&gt;&lt;img src=x&gt;"')
})
