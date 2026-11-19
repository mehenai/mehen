// mehen templates new: writes a provider template with the safe defaults
// (reads allowed, every other method held for approval, ceiling
// placeholder, exact hosts), its test, and its line in the index, inside a
// checkout of this repository. A contributor then narrows it from the
// provider's documentation; a reviewer checks it against the rules in
// docs/INTEGRATING.md.

import { existsSync, readFileSync, writeFileSync } from "node:fs"
import path from "node:path"
import { validHostPattern } from "@mehen/protocol/binding"
import { isReservedHeader } from "@mehen/protocol/headers"
import { CUSTOM_OAUTH_PROVIDER_ID, OAUTH_PROVIDERS, TEMPLATES, TEMPLATE_CATEGORIES, type TemplateCategory } from "@mehen/protocol/templates"
import type { ParsedArgs } from "../args.ts"
import { CliError, usageError } from "../errors.ts"

export const NEW_USAGE =
  'new <id> --host <host> [--host <host>]... [--path <prefix>]... [--header <name>] [--format "Bearer {key}"] [--docs <https url>] [--name "Display name"] --category <category> [--prefix <prefix>]...'
export const NEW_FLAGS = ["host", "path", "header", "format", "docs", "name", "category", "prefix"] as const

const HELP = "mehen templates --help"
const ID = /^[a-z][a-z0-9-]{1,40}$/
// The folder's helpers, the subcommand itself and the id a custom OAuth
// provider's connections are recorded under.
const RESERVED_IDS = new Set(["shared", "new", CUSTOM_OAUTH_PROVIDER_ID])
const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
const HOST = new RegExp(`^(?:${LABEL}\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
const SPECIAL_USE = ["test", "example", "invalid", "localhost", "local", "internal", "onion"]
const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/
const PREFIX = /^[A-Za-z0-9][A-Za-z0-9_.-]{1,23}$/
const PATH = /^\/[A-Za-z0-9._~!$&'()+,;=:@*/-]*$/
const UNPRINTABLE = /[^\x20-\x7e]/
const MAX_HOSTS = 8
const MAX_PATHS = 16

export const PROTOCOL_SRC = path.join("packages", "protocol", "src")
const INDEX_FILE = path.join(PROTOCOL_SRC, "templates.ts")
const PLACEHOLDER_FILE = path.join(PROTOCOL_SRC, "placeholder.ts")
const TEMPLATES_DIR = path.join(PROTOCOL_SRC, "templates")
export const NEXT_TEST = "bun test packages/protocol"

export type NewTemplateInput = {
  id: string
  hosts: string[]
  paths: string[]
  header: string
  format: string
  docsUrl: string | null
  displayName: string
  category: TemplateCategory
  prefixes: string[]
}

export type NewTemplateResult = {
  id: string
  template: string
  test: string
  index: string
  placeholder: string | null
  next: string
}

function refuse(message: string): CliError {
  return usageError(message, HELP)
}

// Words that cannot name a binding in a strict-mode module, in JavaScript
// or TypeScript, and the TypeScript type keywords a reader would trip on.
const RESERVED_WORDS = new Set([
  "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else", "enum", "export", "extends", "false",
  "finally", "for", "function", "if", "import", "in", "instanceof", "new", "null", "return", "super", "switch", "this", "throw", "true", "try",
  "typeof", "var", "void", "while", "with", "yield", "let", "static", "implements", "interface", "package", "private", "protected", "public",
  "await", "arguments", "eval", "undefined", "as", "any", "asserts", "async", "boolean", "constructor", "declare", "get", "infer", "is", "keyof",
  "module", "namespace", "never", "number", "object", "of", "readonly", "require", "satisfies", "set", "string", "symbol", "type", "unique", "unknown",
])

export function isReservedWord(name: string): boolean {
  return RESERVED_WORDS.has(name)
}

// The camel-cased id, with a Template suffix where that is a reserved word:
// class becomes classTemplate.
export function exportName(id: string): string {
  const name = id.replace(/-([a-z0-9])/g, (_, c: string) => c.toUpperCase())
  return isReservedWord(name) ? `${name}Template` : name
}

function words(id: string): string {
  return id
    .split("-")
    .map((w) => (w ? (w[0] as string).toUpperCase() + w.slice(1) : w))
    .join(" ")
}

function plain(flag: string, value: string, max: number): string {
  if (value.length === 0 || value.length > max || UNPRINTABLE.test(value)) throw refuse(`--${flag} takes 1 to ${max} printable ASCII characters.`)
  return value
}

function checkId(id: string): string {
  if (!ID.test(id)) throw refuse(`The id ${JSON.stringify(id)} must match ${ID.source}: lower case letters, digits and hyphens, starting with a letter.`)
  if (id.includes("--") || id.endsWith("-")) throw refuse(`The id ${JSON.stringify(id)} may not end with a hyphen or hold two in a row.`)
  if (RESERVED_IDS.has(id)) throw refuse(`The id ${JSON.stringify(id)} is reserved; choose another.`)
  if (Object.hasOwn(TEMPLATES, id) || Object.hasOwn(OAUTH_PROVIDERS, id)) throw new CliError("conflict", `A template or OAuth provider called ${JSON.stringify(id)} exists already.`, { command: `mehen templates ${id}`, say: "Change the existing template instead, or choose another id." })
  return id
}

function checkHost(host: string): string {
  const special = host.split(".").at(-1) ?? ""
  if (host.length > 253 || !HOST.test(host) || !validHostPattern(host) || SPECIAL_USE.includes(special)) {
    throw refuse(`--host ${JSON.stringify(host)} is not a plain lower-case DNS name of a public service, such as api.example.com: no scheme, port, path, wildcard, IP address or upper case.`)
  }
  return host
}

function checkPath(prefix: string): string {
  const segments = prefix.split("/").slice(1)
  const bad =
    prefix.length > 256 ||
    !PATH.test(prefix) ||
    prefix === "/" ||
    prefix === "/**" ||
    segments.some((s, i) => s === "" || s === "." || s === ".." || (s.includes("*") && s !== "*" && s !== "**") || (s === "**" && i !== segments.length - 1))
  if (bad) throw refuse(`--path ${JSON.stringify(prefix)} must be a path pattern such as /v1/** or /graphql: it starts with /, has no empty, . or .. segment, and uses * or ** only as a whole segment (** only last).`)
  return prefix
}

function checkDocs(url: string): string {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    throw refuse(`--docs ${JSON.stringify(url)} is not a URL.`)
  }
  const special = parsed.hostname.split(".").at(-1) ?? ""
  if (parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "" || parsed.port !== "" || UNPRINTABLE.test(url) || !HOST.test(parsed.hostname) || SPECIAL_USE.includes(special)) {
    throw refuse("--docs must be an https URL on the provider's own public host, with no user name, password or port: the page where a person makes the credential.")
  }
  return url
}

function checkInjection(header: string, format: string): void {
  if (!HEADER_NAME.test(header)) throw refuse(`--header ${JSON.stringify(header)} is not an HTTP header name.`)
  if (isReservedHeader(header)) throw refuse(`--header ${JSON.stringify(header)} is a header the vault sets or refuses itself; name the header the provider reads the key from.`)
  plain("format", format, 200)
  const markers = [...format.matchAll(/\{([^}]*)\}/g)].map((m) => m[1])
  if (markers.length !== 1 || markers[0] !== "key") throw refuse(`--format must hold {key} exactly once and no other {marker}, for example "Bearer {key}", "token {key}" or "{key}".`)
}

function checkCategory(category: string | null): TemplateCategory {
  const allowed = TEMPLATE_CATEGORIES.filter((c) => c.id !== "clients").map((c) => c.id)
  const found = allowed.find((c) => c === category)
  if (found === undefined) throw refuse(`${category === null ? "--category is required" : `--category ${JSON.stringify(category)} is not one`}: use one of ${allowed.join(", ")}.`)
  return found
}

function unique(flag: string, values: string[], max: number): string[] {
  if (values.length > max) throw refuse(`--${flag} may be given at most ${max} times.`)
  if (new Set(values).size !== values.length) throw refuse(`--${flag} names the same value twice.`)
  return values
}

// The flags of `mehen templates new`, checked; nothing is read from disk.
export function newTemplateInput(id: string | undefined, args: ParsedArgs): NewTemplateInput {
  if (id === undefined) throw refuse(`Usage: mehen templates ${NEW_USAGE}`)
  const hosts = unique("host", args.list("host"), MAX_HOSTS).map(checkHost)
  if (hosts.length === 0) throw refuse("Name the provider's API host with --host, for example --host api.example.com.")
  const header = args.string("header") ?? "Authorization"
  const format = args.string("format") ?? "Bearer {key}"
  checkInjection(header, format)
  const docs = args.string("docs")
  const name = args.string("name")
  return {
    id: checkId(id),
    hosts,
    paths: unique("path", args.list("path"), MAX_PATHS).map(checkPath),
    header,
    format,
    docsUrl: docs === null ? null : checkDocs(docs),
    displayName: name === null ? `${words(id)} API key` : plain("name", name, 80),
    category: checkCategory(args.string("category")),
    prefixes: unique("prefix", args.list("prefix"), 8).map((p) => {
      if (!PREFIX.test(p)) throw refuse(`--prefix ${JSON.stringify(p)} must be 2 to 24 letters, digits, _, . or -, starting with a letter or digit: the provider's public, documented prefix, such as sk_live_.`)
      return p
    }),
  }
}

// The nearest folder at or above `start` that is a checkout of this
// repository: its package.json is called mehen and it has the protocol's
// template index.
export function findRepoRoot(start: string): string | null {
  let dir = path.resolve(start)
  for (;;) {
    const manifest = path.join(dir, "package.json")
    if (existsSync(manifest) && existsSync(path.join(dir, INDEX_FILE))) {
      try {
        if ((JSON.parse(readFileSync(manifest, "utf8")) as { name?: unknown }).name === "mehen") return dir
      } catch {
        // An unreadable package.json is not the root; keep walking up.
      }
    }
    const parent = path.dirname(dir)
    if (parent === dir) return null
    dir = parent
  }
}

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
const q = (s: string) => JSON.stringify(s)
const list = (values: string[]) => `[${values.map(q).join(", ")}]`

function keyPattern(prefixes: string[]): string | null {
  if (prefixes.length === 0) return null
  if (prefixes.length === 1) return `^${escapeRegExp(prefixes[0] as string)}`
  return `^(${prefixes.map(escapeRegExp).join("|")})`
}

export function templateSource(input: NewTemplateInput): string {
  const bearer = input.header === "Authorization" && input.format === "Bearer {key}"
  const injection = bearer ? "BEARER()" : `{ in: "header", name: ${q(input.header)}, format: ${q(input.format)} }`
  const pattern = keyPattern(input.prefixes)
  const binding = input.paths.length ? `{ hosts: ${list(input.hosts)}, paths: ${list(input.paths)} }` : `{ hosts: ${list(input.hosts)} }`
  const lines = [
    'import type { Template } from "../templates.ts"',
    `import { ${bearer ? "ALLOW_READS, BEARER" : "ALLOW_READS"} } from "./shared.ts"`,
    "",
    "// Without a human: reads. Every other method needs an approval.",
    ...(input.docsUrl ? [`// ${input.docsUrl}`] : []),
    `export const ${exportName(input.id)}: Template = {`,
    `  id: ${q(input.id)},`,
    `  displayName: ${q(input.displayName)},`,
    '  kind: "api-key",',
    `  category: ${q(input.category)},`,
    `  docsUrl: ${input.docsUrl === null ? "null" : q(input.docsUrl)},`,
    `  binding: ${binding},`,
    `  injection: ${injection},`,
    '  policy: { default: "approve", rules: [ALLOW_READS] },',
    '  ceiling: "placeholder",',
    `  fields: { key: { label: "API key"${pattern === null ? "" : `, pattern: ${q(pattern)}`} } },`,
    ...(input.prefixes.length ? [`  prefixes: ${list(input.prefixes)},`] : []),
    "}",
    "",
  ]
  return lines.join("\n")
}

// A concrete path inside the binding: every * and ** becomes one segment.
function samplePath(paths: string[]): string {
  const first = paths[0]
  if (first === undefined) return "/mehen-sample"
  return first
    .split("/")
    .map((s) => (s === "*" || s === "**" ? "mehen-sample" : s))
    .join("/")
}

export function templateTestSource(input: NewTemplateInput): string {
  const name = exportName(input.id)
  const sample = samplePath(input.paths)
  const reaches = input.hosts.flatMap((host) => [
    `    expect(reaches("GET", ${q(`https://${host}${sample}`)})).toBe(true)`,
    `    expect(reaches("GET", ${q(`https://${host}.evil.test${sample}`)})).toBe(false)`,
    `    expect(reaches("GET", ${q(`http://${host}${sample}`)})).toBe(false)`,
    ...(input.paths.length ? [`    expect(reaches("GET", ${q(`https://${host}/mehen-other/route`)})).toBe(false)`] : []),
  ])
  const host = input.hosts[0] as string
  const lines = [
    'import { describe, expect, it } from "bun:test"',
    'import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"',
    `import { ${name} } from "./${input.id}.ts"`,
    "",
    "function reaches(method: string, url: string): boolean {",
    "  const parsed = parseDestination(method, url)",
    `  return parsed.ok && checkBinding(${name}.binding, parsed.destination).ok`,
    "}",
    "",
    "function decide(method: string, url: string): string {",
    "  const parsed = parseDestination(method, url)",
    "  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)",
    `  return evaluatePolicy(${name}.policy, parsed.destination).action`,
    "}",
    "",
    `describe(${q(input.id)}, () => {`,
    `  it(${q(`reaches ${input.paths.length ? "its paths on " : ""}its own host${input.hosts.length > 1 ? "s" : ""} over https, and nothing that looks like ${input.hosts.length > 1 ? "them" : "it"}`)}, () => {`,
    ...reaches,
    "  })",
    "",
    '  it("lets a read through without a human", () => {',
    `    expect(decide("GET", ${q(`https://${host}${sample}`)})).toBe("allow")`,
    `    expect(decide("HEAD", ${q(`https://${host}${sample}`)})).toBe("allow")`,
    "  })",
    "",
    '  it("holds a write nobody listed for approval", () => {',
    `    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) expect({ method, action: decide(method, ${q(`https://${host}${sample}/mehen-unlisted`)}) }).toEqual({ method, action: "approve" })`,
    "  })",
    "})",
    "",
  ]
  return lines.join("\n")
}

const IMPORT_LINE = /^import \{ (\w+) \} from "\.\/templates\/([a-z0-9-]+)\.ts"$/
const TEMPLATES_OPEN = "export const TEMPLATES: Record<string, Template> = {"

function layoutError(file: string, what: string): CliError {
  return new CliError("not_available", `${file} does not have the layout mehen templates new expects (${what}).`, { say: "Update the checkout to the latest main, or add the template by hand as docs/INTEGRATING.md describes." })
}

// The index with the new template's import, in id order, and its entry at
// the end of TEMPLATES, so `mehen templates` lists it last in its category.
export function registerTemplate(index: string, id: string): string {
  const name = exportName(id)
  const code = index
    .split("\n")
    .filter((l) => !l.trim().startsWith("//"))
    .join("\n")
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
  if (new RegExp(`\\b${name}\\b`).test(code)) throw refuse(`The id ${JSON.stringify(id)} would export ${name}, a name the template index already uses; choose another id.`)
  const lines = index.split("\n")
  const imports = lines.flatMap((l, i) => {
    const m = IMPORT_LINE.exec(l)
    return m ? [{ at: i, id: m[2] as string }] : []
  })
  const last = imports.at(-1)
  if (last === undefined) throw layoutError(INDEX_FILE, "no template imports")
  const open = lines.indexOf(TEMPLATES_OPEN)
  const close = open === -1 ? -1 : lines.indexOf("}", open)
  if (close === -1) throw layoutError(INDEX_FILE, "no TEMPLATES record")
  const entry = id === name ? `  ${id},` : /^[a-z][a-z0-9]*$/.test(id) ? `  ${id}: ${name},` : `  ${q(id)}: ${name},`
  lines.splice(close, 0, entry)
  const before = imports.find((x) => x.id > id)
  lines.splice(before ? before.at : last.at + 1, 0, `import { ${name} } from "./templates/${id}.ts"`)
  return lines.join("\n")
}

// placeholder.ts with the prefixes it lacks, so a placeholder made for the
// new template keeps the shape SDKs check for; null when it has them all.
export function addKnownPrefixes(placeholder: string, prefixes: string[]): string | null {
  const lines = placeholder.split("\n")
  const open = lines.findIndex((l) => l.startsWith("const KNOWN_PREFIXES = ["))
  const close = open === -1 ? -1 : lines.findIndex((l, i) => i > open && l.startsWith("].sort("))
  if (close === -1) throw layoutError(PLACEHOLDER_FILE, "no KNOWN_PREFIXES list")
  const known = new Set([...lines.slice(open + 1, close).join("\n").matchAll(/"([^"]*)"/g)].map((m) => m[1]))
  const missing = prefixes.filter((p) => !known.has(p))
  if (missing.length === 0) return null
  lines.splice(close, 0, `  ${missing.map(q).join(", ")},`)
  return lines.join("\n")
}

// Writes the template, its test, the index and, when a prefix is new, the
// placeholder list under `root`, a checkout of this repository. Every file
// is read and every change made before the first write.
export function writeNewTemplate(root: string, input: NewTemplateInput): NewTemplateResult {
  const template = path.join(TEMPLATES_DIR, `${input.id}.ts`)
  const test = path.join(TEMPLATES_DIR, `${input.id}.test.ts`)
  for (const file of [template, test]) {
    if (existsSync(path.join(root, file))) throw new CliError("conflict", `${file} exists already.`, { say: "Change that template instead, or choose another id." })
  }
  const indexText = readFileSync(path.join(root, INDEX_FILE), "utf8")
  if (new RegExp(`"\\./templates/${input.id}\\.ts"`).test(indexText)) throw new CliError("conflict", `The template index registers ${JSON.stringify(input.id)} already.`, { say: "Choose another id." })
  const index = registerTemplate(indexText, input.id)
  const placeholder = input.prefixes.length ? addKnownPrefixes(readFileSync(path.join(root, PLACEHOLDER_FILE), "utf8"), input.prefixes) : null
  writeFileSync(path.join(root, template), templateSource(input), { flag: "wx" })
  writeFileSync(path.join(root, test), templateTestSource(input), { flag: "wx" })
  writeFileSync(path.join(root, INDEX_FILE), index)
  if (placeholder !== null) writeFileSync(path.join(root, PLACEHOLDER_FILE), placeholder)
  return { id: input.id, template, test, index: INDEX_FILE, placeholder: placeholder === null ? null : PLACEHOLDER_FILE, next: NEXT_TEST }
}

export function notInCheckout(start: string): CliError {
  return new CliError("not_available", `mehen templates new works only inside a checkout of the Mehen repository, and ${start} is not in one.`, {
    say: "Clone the Mehen repository, run the command from inside it, and open a pull request with the files it writes. To use a service without a template, add it as a custom destination in the vault instead.",
  })
}

export function newTemplateLines(result: NewTemplateResult, input: NewTemplateInput): string[] {
  return [
    `wrote ${result.template}`,
    `wrote ${result.test}`,
    `registered ${result.id} in ${result.index}`,
    ...(result.placeholder ? [`added ${input.prefixes.join(", ")} to the placeholder prefixes in ${result.placeholder}`] : []),
    ...(input.paths.length ? [] : [`the binding reaches every path on ${input.hosts.join(", ")}; give --path when the API lives under one prefix`]),
    "",
    "Next: narrow the template from the provider's own documentation (the rules are in docs/INTEGRATING.md),",
    `add the cases its test should prove, then run ${result.next}`,
  ]
}
