// Edits a JSONC file in place, so a person's comments, spacing and key order
// survive: only the members and elements the caller names change. Offsets
// always refer to the text as it is, never to a comment-stripped copy, and
// every edit scans the text afresh, since the files are small.

import { usageError } from "../errors.ts"

type Token = { start: number; end: number; value: string }
type Item = { start: number; end: number; key?: string; value: number }

// A scalar (a number, true, false, null) ends where a comment starts, so
// `1/* x */` is the number 1 and a comment.
const PATTERN = /\s+|\/\/[^\r\n]*|\/\*[\s\S]*?\*\/|"(?:\\[\s\S]|[^"\\])*"|[{}[\]:,]|(?:[^\s{}[\]:,/]|\/(?![/*]))+/g
const COMMENTS = /"(?:\\[\s\S]|[^"\\])*"|\/\/[^\r\n]*(?:\r?\n|$)|\/\*[\s\S]*?\*\//g

function scan(text: string): Token[] {
  const tokens: Token[] = []
  for (const match of text.matchAll(PATTERN)) {
    const value = match[0]
    if (/^\s/.test(value) || value.startsWith("//") || value.startsWith("/*")) continue
    tokens.push({ start: match.index, end: match.index + value.length, value })
  }
  return tokens
}

export function hasComments(text: string): boolean {
  return [...text.matchAll(PATTERN)].some((match) => match[0].startsWith("//") || match[0].startsWith("/*"))
}

function token(ts: Token[], i: number): Token {
  const found = ts[i]
  if (!found) throw usageError("Malformed agent settings: the file ends early.")
  return found
}

// The index just past the value that starts at token i.
function skip(ts: Token[], i: number): number {
  if (token(ts, i).value !== "{" && token(ts, i).value !== "[") return i + 1
  let depth = 0
  do {
    const value = token(ts, i).value
    if (value === "{" || value === "[") depth++
    if (value === "}" || value === "]") depth--
    i++
  } while (depth > 0)
  return i
}

function items(ts: Token[], open: number): { items: Item[]; close: number } {
  const isObject = token(ts, open).value === "{"
  const found: Item[] = []
  let i = open + 1
  while (token(ts, i).value !== "}" && token(ts, i).value !== "]") {
    const first = token(ts, i)
    const value = isObject ? i + 2 : i
    const after = skip(ts, value)
    found.push({ start: first.start, end: token(ts, after - 1).end, value, ...(isObject ? { key: JSON.parse(first.value) as string } : {}) })
    i = after
    if (token(ts, i).value === ",") i++
  }
  return { items: found, close: i }
}

function pick(list: Item[], which: string | number, where: string): Item | undefined {
  if (typeof which === "number") return list[which]
  const named = list.filter((item) => item.key === which)
  if (named.length > 1) throw usageError(`The file names ${JSON.stringify(which)} more than once${where}, so mehen cannot tell which one the agent reads; nothing was changed.`)
  return named[0]
}

// The token where the value at `path` starts.
function locate(ts: Token[], path: (string | number)[]): number {
  let at = 0
  for (const [depth, step] of path.entries()) {
    const value = token(ts, at).value
    if (value !== "{" && value !== "[") throw usageError(`Malformed agent settings: ${path.slice(0, depth).join(".") || "the file"} is not an object or a list.`)
    const item = pick(items(ts, at).items, step, depth ? ` in ${path.slice(0, depth).join(".")}` : "")
    if (!item) throw usageError(`Malformed agent settings: no ${path.slice(0, depth + 1).join(".")}.`)
    at = item.value
  }
  return at
}

// Refuses a duplicate name along the path, which JSON.parse would read as
// the last one and an edit would change as the first.
export function checkUnique(text: string, path: string[]): void {
  const ts = scan(text)
  let at = 0
  for (const [depth, step] of path.entries()) {
    if (token(ts, at).value !== "{") return
    const item = pick(items(ts, at).items, step, depth ? ` in ${path.slice(0, depth).join(".")}` : "")
    if (!item) return
    at = item.value
  }
}

function lineIndent(text: string, at: number): string {
  const lineStart = text.lastIndexOf("\n", at - 1) + 1
  return /^[ \t]*/.exec(text.slice(lineStart))?.[0] ?? ""
}

function unit(text: string): string {
  return /\n([ \t]+)\S/.exec(text)?.[1] ?? "  "
}

function newline(text: string): string {
  return text.includes("\r\n") ? "\r\n" : "\n"
}

function render(text: string, value: unknown, indent: string): string {
  return JSON.stringify(value, null, unit(text)).replaceAll("\n", newline(text) + indent)
}

// Adds a member (with `key`) or an element at the end of the object or
// list at `path`.
export function insertItem(text: string, path: (string | number)[], key: string | undefined, value: unknown): string {
  const ts = scan(text)
  const open = locate(ts, path)
  const { items: list, close } = items(ts, open)
  const outer = lineIndent(text, token(ts, open).start)
  const inner = outer + unit(text)
  const body = `${key === undefined ? "" : `${JSON.stringify(key)}: `}${render(text, value, inner)}`
  const last = list.at(-1)
  if (last) return `${text.slice(0, last.end)},${newline(text)}${inner}${body}${text.slice(last.end)}`
  const openEnd = token(ts, open).end
  const closeStart = token(ts, close).start
  const middle = text.slice(openEnd, closeStart)
  const rest = middle.includes("\n") ? middle : `${middle.trim() ? ` ${middle.trim()}` : ""}${newline(text)}${outer}`
  return `${text.slice(0, openEnd)}${newline(text)}${inner}${body}${rest}${text.slice(closeStart)}`
}

// Replaces the value of a member or element, keeping what is around it.
export function replaceItem(text: string, path: (string | number)[], which: string | number, value: unknown): string {
  const ts = scan(text)
  const open = locate(ts, path)
  const item = pick(items(ts, open).items, which, "")
  if (!item) return text
  const start = token(ts, item.value).start
  const end = token(ts, skip(ts, item.value) - 1).end
  return `${text.slice(0, start)}${render(text, value, lineIndent(text, item.start))}${text.slice(end)}`
}

// Removes a member or element and its separating comma, keeping any
// comment that sat in the span taken out.
export function removeItem(text: string, path: (string | number)[], which: string | number): string {
  const ts = scan(text)
  const open = locate(ts, path)
  const { items: list } = items(ts, open)
  const item = pick(list, which, "")
  if (!item) return text
  const index = list.indexOf(item)
  const previous = list[index - 1]
  const next = list[index + 1]
  const start = previous ? previous.end : item.start
  const end = previous ? item.end : (next?.start ?? item.end)
  const comments = text.slice(start, end).match(COMMENTS)?.filter((t) => t.startsWith("/")).join("") ?? ""
  let tail = text.slice(end)
  if (!previous && !next) tail = tail.replace(/^(\s*),/, "$1")
  return `${text.slice(0, start)}${comments}${tail}`
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

// Changes only what differs between `current` (the value at `path`, as
// parsed) and `wanted`, member by member and element by element, so a
// comment inside the value stays, as does a member the person added.
export function patchItem(text: string, path: (string | number)[], current: unknown, wanted: unknown): string {
  if (JSON.stringify(current) === JSON.stringify(wanted)) return text
  if (isObject(current) && isObject(wanted)) {
    return Object.entries(wanted).reduce((next, [key, value]) => (key in current ? patchItem(next, [...path, key], current[key], value) : insertItem(next, path, key, value)), text)
  }
  if (Array.isArray(current) && Array.isArray(wanted) && current.length === wanted.length) {
    return wanted.reduce((next: string, value: unknown, i: number) => patchItem(next, [...path, i], current[i], value), text)
  }
  return replaceItem(text, path.slice(0, -1), path.at(-1) as string | number, wanted)
}
