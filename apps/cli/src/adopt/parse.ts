// Parsers for the files `mehen adopt` reads. Each returns names with their
// values in memory; a value never leaves this module except to the caller.
// A line that does not parse is reported by number and reason, never by
// content.

import { base64UrlDecode } from "@mehen/protocol/bytes"
import type { SourceType } from "./sources.ts"

// `variable` is the name a program reads (dotenv, envrc, plist, systemd, a
// JSON key that is a variable name); `pointer` locates a value in a
// structured file, "" for the whole file. `value` is null for a dynamic
// line, which is reported and never read.
export type ParsedEntry = { variable: string | null; pointer: string | null; line: number; value: string | null }
export type ParseError = { line: number; why: string }
// `envFiles`: the files a systemd unit's EnvironmentFile= names.
export type ParsedSource = { entries: ParsedEntry[]; errors: ParseError[]; envFiles: string[] }

export const VARIABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/

function lineAt(text: string, index: number): number {
  let line = 1
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++
  return line
}

function unescapeDouble(text: string): string {
  return text.replace(/\\([nrt"\\$`])/g, (_, ch: string) => (ch === "n" ? "\n" : ch === "r" ? "\r" : ch === "t" ? "\t" : ch))
}

// A quoted value from `start` (the opening quote) to its closing quote,
// possibly across lines. Null when it never closes.
function quoted(text: string, start: number): { value: string; end: number } | null {
  const quote = text[start] as string
  for (let i = start + 1; i < text.length; i++) {
    const ch = text[i]
    if (quote === '"' && ch === "\\") {
      i++
      continue
    }
    if (ch === quote) {
      const raw = text.slice(start + 1, i)
      return { value: quote === '"' ? unescapeDouble(raw) : raw, end: i + 1 }
    }
  }
  return null
}

const DYNAMIC = /\$\(|`|\$\{|\$[A-Za-z_]/

// .env, .dev.vars and NAME=value files: `export`, comments, quotes and
// multi-line quoted values, as dotenv reads them.
export function parseDotenv(text: string, options: { envrc?: boolean } = {}): ParsedSource {
  const entries: ParsedEntry[] = []
  const errors: ParseError[] = []
  let at = 0
  while (at < text.length) {
    const lineEnd = text.indexOf("\n", at) === -1 ? text.length : text.indexOf("\n", at)
    const line = lineAt(text, at)
    const raw = text.slice(at, lineEnd)
    const trimmed = raw.trim()
    let next = lineEnd + 1
    if (trimmed === "" || trimmed.startsWith("#")) {
      at = next
      continue
    }
    const exported = /^export\s+/.test(trimmed)
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*/.exec(trimmed)
    if (options.envrc && !exported) {
      // direnv commands (dotenv, use, layout, source_env) are not values.
      at = next
      continue
    }
    if (!match) {
      errors.push({ line, why: options.envrc ? "not a literal export NAME=value" : "not NAME=value" })
      at = next
      continue
    }
    const name = match[1] as string
    const valueStart = at + raw.indexOf(trimmed) + match[0].length
    const first = text[valueStart]
    let value: string
    let rest: string
    if (first === '"' || first === "'" || first === "`") {
      const q = quoted(text, valueStart)
      if (!q) {
        errors.push({ line, why: "a quote that never closes" })
        at = text.length
        continue
      }
      const end = text.indexOf("\n", q.end) === -1 ? text.length : text.indexOf("\n", q.end)
      rest = text.slice(q.end, end).trim()
      next = end + 1
      value = q.value
      if (options.envrc && (first === "`" || (first === '"' && DYNAMIC.test(text.slice(valueStart, q.end))))) {
        entries.push({ variable: name, pointer: null, line, value: null })
        at = next
        continue
      }
    } else {
      const body = text.slice(valueStart, lineEnd)
      const comment = body.search(/\s#/)
      value = (comment === -1 ? body : body.slice(0, comment)).trim()
      rest = ""
      if (options.envrc && DYNAMIC.test(value)) {
        entries.push({ variable: name, pointer: null, line, value: null })
        at = next
        continue
      }
    }
    if (rest !== "" && !rest.startsWith("#")) errors.push({ line, why: "text after the closing quote" })
    entries.push({ variable: name, pointer: null, line, value })
    at = next
  }
  return { entries, errors, envFiles: [] }
}

function pointerPart(key: string): string {
  return key.replaceAll("~", "~0").replaceAll("/", "~1")
}

// A JSON key whose name or value could be a credential: an env-style name,
// a secret-sounding key, or any string under an "env" object.
const SECRET_KEY = /token|secret|password|passwd|api[_-]?key|apikey|auth|credential|private[_-]?key/i
const ENV_STYLE = /^[A-Z][A-Z0-9_]*$/

// Settings JSON: string leaves at any depth, reported as JSON pointers. A
// Google service account key file is one value, the whole document.
export function parseJson(text: string, isCandidate: (key: string, value: string) => boolean = (key) => ENV_STYLE.test(key) || SECRET_KEY.test(key)): ParsedSource {
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch {
    return { entries: [], errors: [{ line: 0, why: "not valid JSON" }], envFiles: [] }
  }
  if (typeof data === "object" && data !== null && !Array.isArray(data) && (data as Record<string, unknown>).type === "service_account") {
    return { entries: [{ variable: null, pointer: "", line: 1, value: text }], errors: [], envFiles: [] }
  }
  const entries: ParsedEntry[] = []
  const walk = (value: unknown, pointer: string, key: string): void => {
    if (typeof value === "string") {
      if (key !== "" && isCandidate(key, value)) entries.push({ variable: VARIABLE_NAME.test(key) && ENV_STYLE.test(key) ? key : null, pointer, line: 0, value })
      return
    }
    if (Array.isArray(value)) value.forEach((v, i) => walk(v, `${pointer}/${i}`, key))
    else if (typeof value === "object" && value !== null) for (const [k, v] of Object.entries(value)) walk(v, `${pointer}/${pointerPart(k)}`, k)
  }
  walk(data, "", "")
  return { entries, errors: [], envFiles: [] }
}

const XML_ENTITIES: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" }

function decodeXml(text: string): string {
  return text.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (whole, name: string) => {
    if (name.startsWith("#x") || name.startsWith("#X")) return String.fromCodePoint(Number.parseInt(name.slice(2), 16))
    if (name.startsWith("#")) return String.fromCodePoint(Number.parseInt(name.slice(1), 10))
    return XML_ENTITIES[name.toLowerCase()] ?? whole
  })
}

// A launchd plist's EnvironmentVariables dictionary (XML plists only).
export function parsePlist(text: string): ParsedSource {
  const entries: ParsedEntry[] = []
  const errors: ParseError[] = []
  const block = /<key>\s*EnvironmentVariables\s*<\/key>\s*<dict>([\s\S]*?)<\/dict>/.exec(text)
  if (!block) return { entries, errors, envFiles: [] }
  const offset = block.index + block[0].indexOf("<dict>") + "<dict>".length
  const pair = /<key>([\s\S]*?)<\/key>\s*(?:<string>([\s\S]*?)<\/string>|<string\s*\/>|<(integer|real|true|false)\b)/g
  for (const m of (block[1] as string).matchAll(pair)) {
    const name = decodeXml((m[1] as string).trim())
    const line = lineAt(text, offset + (m.index ?? 0))
    if (!VARIABLE_NAME.test(name)) {
      errors.push({ line, why: "a key that is not a variable name" })
      continue
    }
    entries.push({ variable: name, pointer: null, line, value: m[3] ? null : decodeXml(m[2] ?? "") })
  }
  return { entries, errors, envFiles: [] }
}

// systemd's word splitting for Environment=: double or single quotes group,
// a backslash escapes.
function systemdWords(text: string): string[] | null {
  const words: string[] = []
  let current = ""
  let quote: string | null = null
  let started = false
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string
    if (quote) {
      if (ch === "\\" && i + 1 < text.length) current += text[++i]
      else if (ch === quote) quote = null
      else current += ch
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      started = true
    } else if (/\s/.test(ch)) {
      if (started) words.push(current)
      current = ""
      started = false
    } else if (ch === "\\" && i + 1 < text.length) {
      current += text[++i]
      started = true
    } else {
      current += ch
      started = true
    }
  }
  if (quote) return null
  if (started) words.push(current)
  return words
}

// A systemd unit's Environment= assignments and EnvironmentFile= paths.
// `home` expands %h; a path with another specifier is not followed.
export function parseSystemd(text: string, home: string): ParsedSource {
  const entries: ParsedEntry[] = []
  const errors: ParseError[] = []
  const envFiles: string[] = []
  const lines = text.split("\n")
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] as string).trim()
    const env = /^Environment\s*=\s*(.*)$/.exec(line)
    if (env) {
      const words = systemdWords(env[1] as string)
      if (!words) {
        errors.push({ line: i + 1, why: "a quote that never closes" })
        continue
      }
      for (const word of words) {
        const eq = word.indexOf("=")
        const name = eq === -1 ? "" : word.slice(0, eq)
        if (!VARIABLE_NAME.test(name)) errors.push({ line: i + 1, why: "not NAME=value" })
        else entries.push({ variable: name, pointer: null, line: i + 1, value: word.slice(eq + 1) })
      }
      continue
    }
    const file = /^EnvironmentFile\s*=\s*-?(.*)$/.exec(line)
    if (file) {
      const path = (file[1] as string).trim().replaceAll("%h", home)
      if (path.startsWith("/") && !path.includes("%")) envFiles.push(path)
    }
  }
  return { entries, errors, envFiles }
}

// A mapping-only YAML reader, enough for gh's hosts.yml: every scalar leaf
// with its key path. Lists, anchors and block scalars are not needed there.
function yamlLeaves(text: string): { pointer: string; key: string; value: string; line: number }[] {
  const leaves: { pointer: string; key: string; value: string; line: number }[] = []
  const stack: { indent: number; key: string }[] = []
  const lines = text.split("\n")
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] as string
    const m = /^(\s*)([^\s#:][^:]*):(?:\s+(.*))?\s*$/.exec(raw)
    if (!m) continue
    const indent = (m[1] as string).length
    while (stack.length && (stack.at(-1) as { indent: number }).indent >= indent) stack.pop()
    const key = (m[2] as string).trim()
    const value = (m[3] ?? "").replace(/\s+#.*$/, "").trim()
    if (value === "") {
      stack.push({ indent, key })
      continue
    }
    const unquoted = /^(["'])(.*)\1$/.exec(value)?.[2] ?? value
    leaves.push({ pointer: [...stack.map((s) => s.key), key].map((k) => `/${pointerPart(k)}`).join(""), key, value: unquoted, line: i + 1 })
  }
  return leaves
}

export function parseGhHosts(text: string): ParsedSource {
  const entries = yamlLeaves(text)
    .filter((leaf) => leaf.key === "oauth_token")
    .map((leaf) => ({ variable: null, pointer: leaf.pointer, line: leaf.line, value: leaf.value }))
  return { entries, errors: [], envFiles: [] }
}

// wrangler's OAuth login (TOML): reported so the plan can skip it by name.
export function parseWrangler(text: string): ParsedSource {
  const entries: ParsedEntry[] = []
  const lines = text.split("\n")
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*(oauth_token|refresh_token|api_token)\s*=\s*"(.*)"\s*$/.exec(lines[i] as string)
    if (m) entries.push({ variable: null, pointer: `/${m[1]}`, line: i + 1, value: m[2] as string })
  }
  return { entries, errors: [], envFiles: [] }
}

// Docker's auths: each registry's base64 user:password as two values.
export function parseDocker(text: string): ParsedSource {
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch {
    return { entries: [], errors: [{ line: 0, why: "not valid JSON" }], envFiles: [] }
  }
  const auths = (data as { auths?: unknown }).auths
  const entries: ParsedEntry[] = []
  const errors: ParseError[] = []
  if (typeof auths !== "object" || auths === null) return { entries, errors, envFiles: [] }
  for (const [registry, value] of Object.entries(auths)) {
    const auth = (value as { auth?: unknown } | null)?.auth
    if (typeof auth !== "string" || auth === "") continue
    let decoded: string
    try {
      decoded = new TextDecoder("utf-8", { fatal: true }).decode(base64UrlDecode(auth.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "")))
    } catch {
      errors.push({ line: 0, why: `the auth for a registry is not base64` })
      continue
    }
    const colon = decoded.indexOf(":")
    if (colon <= 0) continue
    const base = `/auths/${pointerPart(registry)}/auth`
    entries.push({ variable: null, pointer: `${base}/username`, line: 0, value: decoded.slice(0, colon) })
    entries.push({ variable: null, pointer: `${base}/password`, line: 0, value: decoded.slice(colon + 1) })
  }
  return { entries, errors, envFiles: [] }
}

// A whole file as one value: kubeconfig, talosconfig, gcloud ADC.
export function parseWhole(text: string): ParsedSource {
  return { entries: [{ variable: null, pointer: "", line: 1, value: text }], errors: [], envFiles: [] }
}

const PEM_BLOCK = /^-----BEGIN [A-Z0-9 ]+-----\r?\n[\s\S]+\r?\n-----END [A-Z0-9 ]+-----$/

// A file kept in .local-secrets: NAME=value lines as a .env, or else one
// key on its own read whole (a PEM block, a service account, a token on
// one line). Anything else is one error for the file, not one per line.
export function parseSecretsFile(text: string): ParsedSource {
  const lines = parseDotenv(text)
  if (lines.entries.length) return lines
  const trimmed = text.trim()
  if (trimmed === "") return lines
  const whole = (value: string): ParsedSource => ({ entries: [{ variable: null, pointer: "", line: 1, value }], errors: [], envFiles: [] })
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    const json = parseJson(text, () => false)
    if (json.entries.length) return json
    return { entries: [], errors: [{ line: 1, why: "a JSON file that is not settings: move what it holds by hand" }], envFiles: [] }
  }
  if (PEM_BLOCK.test(trimmed)) return whole(text)
  if (/^\S{16,}$/.test(trimmed)) return whole(trimmed)
  return { entries: [], errors: [{ line: 1, why: "not NAME=value lines, one key or one token: move what it holds by hand" }], envFiles: [] }
}

export function parseSource(type: SourceType, text: string, home: string): ParsedSource {
  switch (type) {
    case "dotenv": return parseDotenv(text)
    case "secrets-file": return parseSecretsFile(text)
    case "envrc": return parseDotenv(text, { envrc: true })
    case "json": return parseJson(text)
    case "plist": return parsePlist(text)
    case "systemd": return parseSystemd(text, home)
    case "gh-hosts": return parseGhHosts(text)
    case "wrangler": return parseWrangler(text)
    case "docker": return parseDocker(text)
    case "kubeconfig":
    case "talosconfig":
    case "gcloud-adc": return parseWhole(text)
  }
}

// The registry host a docker pointer names.
export function dockerRegistry(pointer: string): string | null {
  const m = /^\/auths\/([^/]+)\/auth\/(?:username|password)$/.exec(pointer)
  if (!m) return null
  const raw = (m[1] as string).replaceAll("~1", "/").replaceAll("~0", "~")
  try {
    return new URL(raw.includes("://") ? raw : `https://${raw}`).hostname
  } catch {
    return null
  }
}
