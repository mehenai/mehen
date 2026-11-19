import { usageError } from "../errors.ts"

export type JsonObject = Record<string, unknown>
export function object(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

// Agent settings may use JSONC. Only remove comments and trailing commas
// outside strings. Invalid input is still refused by JSON.parse.
export function parseJson(text: string): JsonObject {
  let clean = "", string = false, escaped = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!, n = text[i + 1]
    if (string) {
      clean += c
      if (escaped) escaped = false
      else if (c === "\\") escaped = true
      else if (c === '"') string = false
    } else if (c === '"') { string = true; clean += c }
    else if (c === "/" && n === "/") { while (i + 1 < text.length && text[i + 1] !== "\n") i++; clean += " " }
    else if (c === "/" && n === "*") {
      const end = text.indexOf("*/", i + 2)
      if (end === -1) throw usageError("Malformed agent settings: unterminated comment.")
      i = end + 1; clean += " "
    } else clean += c
  }
  let normalised = ""
  string = false; escaped = false
  for (let i = 0; i < clean.length; i++) {
    const c = clean[i]!
    if (string) {
      normalised += c
      if (escaped) escaped = false
      else if (c === "\\") escaped = true
      else if (c === '\"') string = false
    } else if (c === '\"') { string = true; normalised += c }
    else if (c !== "," || !/^\s*[}\]]/.test(clean.slice(i + 1))) normalised += c
  }
  try { const value: unknown = JSON.parse(normalised); if (object(value)) return value } catch { /* refuse below */ }
  throw usageError("Malformed agent settings. Move or fix the file, then run setup again; it was not overwritten.")
}

export type ConfigEdit = { text: string; entry: unknown }
// The one server setup registers; the retired per-workspace
// `mehen-<slug>` entries are only ever removed.
export const DEFAULT_SERVER = "mehen"
export function jsonEntry(text: string, section: string, server = DEFAULT_SERVER): unknown {
  const data = parseJson(text)
  refuseDuplicatePath(text, section, server)
  if (data[section] !== undefined && !object(data[section])) throw usageError(`Malformed agent settings: ${section} must be an object.`)
  return (data[section] as JsonObject | undefined)?.[server]
}
type Token = { start: number; end: number; value: string }
type Member = { key: string; start: number; valueStart: number; end: number }
// Offsets refer to the original JSONC, never to the comment-stripped copy.
function tokens(text: string): Token[] {
  const result: Token[] = []
  const pattern = /\s+|\/\/[^\r\n]*|\/\*[\s\S]*?\*\/|"(?:\\[\s\S]|[^"\\])*"|[{}\[\]:,]|[^\s{}\[\]:,]+/g
  for (const match of text.matchAll(pattern)) {
    const value = match[0]
    if (/^\s|^\/\//.test(value) || value.startsWith("/*")) continue
    result.push({ start: match.index!, end: match.index! + value.length, value })
  }
  return result
}
function members(ts: Token[], open: number): { members: Member[]; close: number } {
  const result: Member[] = []
  let i = open + 1
  while (ts[i]?.value !== "}") {
    const key = ts[i]!
    const value = i + 2
    i = value
    if (["{", "["].includes(ts[i]!.value)) {
      let depth = 0
      do {
        if (["{", "["].includes(ts[i]!.value)) depth++
        if (["}", "]"].includes(ts[i]!.value)) depth--
        i++
      } while (depth)
    } else i++
    result.push({ key: JSON.parse(key.value) as string, start: key.start, valueStart: ts[value]!.start, end: ts[i - 1]!.end })
    if (ts[i]?.value === ",") i++
  }
  return { members: result, close: ts[i]!.start }
}
// JSON.parse keeps the last of two members with one name and the editor
// changes the first, and an agent may read either: a duplicate section or
// server name is refused rather than guessed at. The `mehen` server is
// checked with every other, so a retired `mehen-<slug>` pass, which runs
// first, refuses before it writes.
function refuseDuplicatePath(text: string, section: string, server: string): void {
  const ts = tokens(text)
  const sections = members(ts, 0).members.filter(m => m.key === section)
  const refuse = (named: string) => usageError(`The agent settings name ${named}, so setup cannot tell which one the agent reads; nothing was written. Remove the duplicate, then run mehen setup --json again.`)
  if (sections.length > 1) throw refuse(`${JSON.stringify(section)} more than once`)
  const open = sections[0] === undefined ? -1 : ts.findIndex(t => t.start === sections[0]!.valueStart)
  if (ts[open]?.value !== "{") return
  const servers = members(ts, open).members
  for (const name of new Set([DEFAULT_SERVER, server])) {
    if (servers.filter(m => m.key === name).length > 1) throw refuse(`${JSON.stringify(name)} more than once in ${JSON.stringify(section)}`)
  }
}
function spliceMember(text: string, ts: Token[], open: number, key: string, value: string | undefined, indent: string): string {
  const node = members(ts, open)
  const index = node.members.findIndex(m => m.key === key)
  const member = node.members[index]
  if (member) {
    if (value !== undefined) return text.slice(0, member.valueStart) + value + text.slice(member.end)
    const previous = node.members[index - 1], next = node.members[index + 1]
    const start = previous?.end ?? ts[open]!.end
    const end = previous ? member.end : next?.start ?? member.end
    // Keep comments even if the separating comma or whitespace was ours.
    const comments = text.slice(start, end).match(/"(?:\\[\s\S]|[^"\\])*"|\/\/[^\r\n]*(?:\r?\n|$)|\/\*[\s\S]*?\*\//g)?.filter(t => t.startsWith("/")).join("") ?? ""
    let tail = text.slice(end)
    if (!next && !previous) tail = tail.replace(/^(\s*),/, "$1")
    return text.slice(0, start) + comments + tail
  }
  if (value === undefined) return text
  const last = node.members.at(-1)
  const newline = text.includes("\r\n") ? "\r\n" : "\n"
  const at = last?.end ?? ts[open]!.end
  const addition = `${last ? "," : ""}${newline}${indent}${JSON.stringify(key)}: ${value}`
  return text.slice(0, at) + addition + text.slice(at)
}
export function editJson(text: string, section: string, entry: unknown, keepSection = false, server = DEFAULT_SERVER): ConfigEdit {
  return { text: editJsonText(text, section, entry === undefined ? undefined : JSON.stringify(entry), keepSection, server), entry }
}

// The server's entry exactly as the file spells it (comments and spacing
// kept), for restoring an original byte for byte; undefined when absent.
export function jsonEntryText(text: string, section: string, server = DEFAULT_SERVER): string | undefined {
  jsonEntry(text, section, server)
  const ts = tokens(text)
  const sectionMember = members(ts, 0).members.find(m => m.key === section)
  if (!sectionMember) return undefined
  const open = ts.findIndex(t => t.start === sectionMember.valueStart)
  const member = members(ts, open).members.find(m => m.key === server)
  return member ? text.slice(member.valueStart, member.end) : undefined
}

// Sets (raw JSON text), or with undefined removes, the server's entry.
export function editJsonText(text: string, section: string, value: string | undefined, keepSection = false, server = DEFAULT_SERVER): string {
  jsonEntry(text, section, server)
  const ts = tokens(text)
  const root = members(ts, 0)
  const sectionMember = root.members.find(m => m.key === section)
  const indent = text.match(/\n([ \t]+)"/)?.[1] ?? "  "
  if (!sectionMember) return spliceMember(text, ts, 0, section, value === undefined ? undefined : `{${JSON.stringify(server)}:${value}}`, indent)
  const open = ts.findIndex(t => t.start === sectionMember.valueStart)
  const node = members(ts, open)
  if (!keepSection && value === undefined && node.members.length === 1 && node.members[0]!.key === server) return spliceMember(text, ts, 0, section, undefined, indent)
  return spliceMember(text, ts, open, server, value, indent + indent)
}

function tomlData(text: string): JsonObject {
  try { return Bun.TOML.parse(text) as JsonObject } catch { throw usageError("Malformed TOML agent settings. The file was not overwritten.") }
}
export function tomlEntry(text: string, server = DEFAULT_SERVER): unknown {
  const data = tomlData(text)
  if (data.mcp_servers !== undefined && !object(data.mcp_servers)) throw usageError("mcp_servers must be a TOML table.")
  return (data.mcp_servers as JsonObject | undefined)?.[server]
}

// Keep every byte outside the dedicated table. Refuse alternate TOML spellings
// rather than accidentally leaving two definitions of the same server.
export function tomlRange(text: string, server = DEFAULT_SERVER): { start: number; end: number } | null {
  const headings = [...text.matchAll(/^[ \t]*\[([^\r\n]+)\][ \t]*(?:#[^\r\n]*)?(?:\r?\n|$)/gm)]
  const heading = headings.find(h => h[1] === `mcp_servers.${server}`)
  if (!heading) {
    if (tomlEntry(text, server) !== undefined) throw usageError(`The existing ${server} TOML entry is not a dedicated [mcp_servers.${server}] table. Move it to that table before setup.`)
    return null
  }
  const start = heading.index!
  const index = headings.indexOf(heading)
  const next = headings[index + 1]
  if (headings.some(h => h[1]?.startsWith(`mcp_servers.${server}.`))) throw usageError(`Nested ${server} TOML tables are not supported by setup.`)
  const limit = next?.index ?? text.length
  // Only trailing blank and comment lines are outside the owned table.
  const lines = text.slice(start, limit).match(/[^\n]*\n|[^\n]+$/g) ?? []
  while (lines.length > 1 && /^[ \t]*(?:#[^\r\n]*)?\r?\n?$/.test(lines.at(-1)!)) lines.pop()
  return { start, end: start + lines.join("").length }
}
export function editToml(text: string, table: string | null, server = DEFAULT_SERVER): string {
  tomlData(text)
  const range = tomlRange(text, server)
  if (range) return text.slice(0, range.start) + (table ?? "") + text.slice(range.end)
  return table === null ? text : text + (text ? text.endsWith("\n\n") ? "" : text.endsWith("\n") ? "\n" : "\n\n" : "") + table
}
export function tomlTable(text: string, server = DEFAULT_SERVER): string | null {
  const range = tomlRange(text, server)
  return range ? text.slice(range.start, range.end) : null
}
