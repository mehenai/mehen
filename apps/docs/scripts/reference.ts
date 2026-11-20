// The five generated reference pages, as markdown: the facts from the JSON
// generate.ts wrote (the CLI's own command table, the protocol's error and
// exit tables, the MCP fixture, the template catalogue and the platform
// API's route table), joined with the hand-written prose of
// reference/*.md. A page's hand source is an intro, then one `### <key>`
// entry per code, tool, exit code, platform route or platform limit; the
// entries are placed beside the facts they explain.

import { type PolicySummaryLines, goesTo, injectionText, policySummaryLines, shortScope, templateSummary } from "../../cli/src/commands/templates.ts"
import { EXIT } from "@mehen/protocol/api"
import type { OAuthProviderTemplate, Template } from "@mehen/protocol/templates"
import { headingSlug, plainText } from "../src/markdown.ts"

export type CliFlag = { name: string; short: string | null; type: "string" | "boolean" | "list" | null }
export type CliCommand = { name: string; summary: string; usage: string; flags: CliFlag[]; examples: string[]; notes: string[]; help: string }
export type CliReference = { version: string; globalFlags: string[]; commands: CliCommand[] }

export type ErrorOrigin = "vault" | "mehen"
export type ErrorNext = { command?: string; say: string }
export type ErrorEntry = { code: string; origin: ErrorOrigin; http: number | null; exit: number; next: ErrorNext | null; means: string; do: string }

export type JsonSchema = {
  type?: string
  enum?: readonly string[]
  const?: string
  items?: JsonSchema
  oneOf?: readonly JsonSchema[]
  anyOf?: readonly JsonSchema[]
  minimum?: number
  maximum?: number
  description?: string
  properties?: Record<string, JsonSchema>
  required?: readonly string[]
}
export type McpTool = { name: string; description: string; inputSchema: JsonSchema }
export type McpReference = { tools: McpTool[] }

export type ProvidersReference = {
  categories: readonly { id: string; title: string }[]
  templates: Template[]
  oauthProviders: (OAuthProviderTemplate & { policy: Template["policy"] })[]
  redirectUri: string
}

// One member of a platform route's path, query, body or answer.
export type PlatformField = { field: string; type: string; required: "yes" | "no" | "in its shape" }
export type PlatformRouteEntry = {
  number: number
  name: string
  method: string
  path: string
  params: PlatformField[]
  query: PlatformField[] | null
  body: PlatformField[] | null
  answer: PlatformField[]
  status: number[]
  refusals: string[]
  prose: string
}
export type PlatformLimitEntry = { name: string; default: number; min: number | null; max: number | null }
export type PlatformReference = { header: string; pathPrefix: string; commonRefusals: string[]; limits: PlatformLimitEntry[]; routes: PlatformRouteEntry[] }

// The exit codes in order, with their protocol names.
export type ExitCode = { exit: number; name: string }
export const EXIT_CODES: readonly ExitCode[] = Object.entries(EXIT).map(([name, exit]) => ({ exit, name }))

// ---------------------------------------------------------------- hand prose

export type Entry = { key: string; body: string; line: number }
export type HandSource = { intro: string; entries: Entry[] }

const FENCE = /^ {0,3}(`{3,}|~{3,})/

// The intro and the `### ` entries of a hand source (front matter already
// removed). Nothing but entries may follow the first entry.
export function splitEntries(markdown: string, file: string): HandSource {
  const lines = markdown.split("\n")
  const intro: string[] = []
  const entries: Entry[] = []
  let fence: string | null = null
  let current: { key: string; line: number; lines: string[] } | null = null
  const close = () => {
    if (current) entries.push({ key: current.key, line: current.line, body: current.lines.join("\n").trim() })
  }
  lines.forEach((line, n) => {
    const marker = FENCE.exec(line)?.[1]
    if (marker !== undefined) {
      if (fence === null) fence = marker
      else if (marker[0] === fence[0] && marker.length >= fence.length && line.trim() === marker) fence = null
    }
    if (fence === null && /^### /.test(line)) {
      close()
      current = { key: plainText(line.slice(4).trim()), line: n + 1, lines: [] }
      return
    }
    if (fence === null && current && /^#{1,2} /.test(line)) throw new Error(`${file}:${n + 1}: only ### entries may follow the first entry`)
    if (current) current.lines.push(line)
    else intro.push(line)
  })
  close()
  const seen = new Set<string>()
  for (const entry of entries) {
    if (seen.has(entry.key)) throw new Error(`${file}:${entry.line}: ${entry.key} has two entries`)
    seen.add(entry.key)
  }
  return { intro: intro.join("\n").trim(), entries }
}

// The text of the paragraph that starts `**<label>.**`, without the label,
// on one line.
export function labelled(body: string, label: string): string | null {
  for (const paragraph of body.split(/\n\s*\n/)) {
    const text = paragraph.trim().replace(/\s*\n\s*/g, " ")
    const prefix = `**${label}.**`
    if (text.startsWith(prefix)) return text.slice(prefix.length).trim()
  }
  return null
}

// Text for one table cell: one line, pipes escaped.
function cell(text: string): string {
  return text.replace(/\s*\n\s*/g, " ").replace(/\|/g, "\\|")
}

// The first sentence: up to the first full stop followed by a space, outside
// code spans.
export function firstSentence(text: string): string {
  let inCode = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (c === "`") inCode = !inCode
    else if (!inCode && c === "." && (text[i + 1] === " " || text[i + 1] === undefined)) return text.slice(0, i + 1)
  }
  return text
}

function table(head: string[], rows: string[][]): string {
  return [`| ${head.join(" | ")} |`, `| ${head.map(() => "---").join(" | ")} |`, ...rows.map((r) => `| ${r.map(cell).join(" | ")} |`)].join("\n")
}

function joinBlocks(blocks: (string | null | false)[]): string {
  return `${blocks.filter((b): b is string => typeof b === "string" && b.trim() !== "").map((b) => b.trim()).join("\n\n")}\n`
}

// ---------------------------------------------------------------- errors

export type ExitProse = { exit: number; meaning: string; what: string }

// The `### Exit <n>` entries of the errors page: what each exit code means
// and what to do. Every protocol exit code needs one, and nothing else.
export function exitProse(source: HandSource, exits: readonly ExitCode[], file: string): ExitProse[] {
  const out: ExitProse[] = []
  for (const { exit } of exits) {
    const entry = source.entries.find((e) => e.key === `Exit ${exit}`)
    if (!entry) throw new Error(`${file}: exit code ${exit} has no "### Exit ${exit}" entry`)
    const meaning = labelled(entry.body, "Meaning")
    const what = labelled(entry.body, "What you do")
    if (!meaning || !what) throw new Error(`${file}:${entry.line}: Exit ${exit} needs a **Meaning.** and a **What you do.** paragraph`)
    out.push({ exit, meaning, what })
  }
  for (const entry of source.entries) {
    const m = /^Exit (\d+)$/.exec(entry.key)
    if (m && !exits.some((e) => e.exit === Number(m[1]))) throw new Error(`${file}:${entry.line}: exit code ${m[1]} does not exist`)
  }
  return out
}

function factsLine(entry: ErrorEntry): string {
  const facts = [entry.http === null ? null : `HTTP ${entry.http}`, `exit ${entry.exit}`, entry.origin === "vault" ? "from the vault" : "from mehen itself"]
  const next = entry.next?.command ? ` · default next: \`${entry.next.command}\`` : ""
  return `${facts.filter((f) => f !== null).join(" · ")}${next}`
}

function errorSection(entry: ErrorEntry): string {
  return joinBlocks([`### \`${entry.code}\``, factsLine(entry), `**What it means.** ${entry.means}`, `**What you do.** ${entry.do}`])
}

export function errorsMarkdown(source: HandSource, errors: readonly ErrorEntry[], exits: readonly ExitProse[]): string {
  const vault = errors.filter((e) => e.origin === "vault")
  const local = errors.filter((e) => e.origin === "mehen")
  return joinBlocks([
    source.intro,
    "## Exit codes",
    "One table for every `mehen` command and anything else that wraps the vault.",
    table(["Exit", "Meaning", "What you do"], exits.map((e) => [`\`${e.exit}\``, e.meaning, e.what])),
    "## Errors from the vault",
    "Every code the vault sends, with its HTTP status, the exit code `mehen` gives it, and the step `mehen` fills in when the vault sent no `next` of its own.",
    table(["`error`", "HTTP", "Exit", "Default next"], vault.map((e) => [`[\`${e.code}\`](#${e.code})`, String(e.http), String(e.exit), e.next?.say ?? ""])),
    ...vault.map(errorSection),
    "## Errors from mehen itself",
    "Failures that start on this machine. They use the same shape and the same exit codes, and the vault never sends them.",
    table(["`error`", "Exit", "What it means"], local.map((e) => [`[\`${e.code}\`](#${e.code})`, String(e.exit), firstSentence(e.means)])),
    ...local.map(errorSection),
  ])
}

// ---------------------------------------------------------------- CLI

const FLAG_TAKES: Record<NonNullable<CliFlag["type"]>, string> = { string: "a value", boolean: "nothing (a switch)", list: "a value; repeatable" }

// The commands with their own parsers (apps/cli/src/cli.ts dispatches them
// before the standard one); they refuse some of the global flags.
const SPECIAL_PARSERS = new Set(["run", "env", "init", "mcp"])

function commandSection(command: CliCommand): string {
  const special = SPECIAL_PARSERS.has(command.name)
  const flags = command.flags.length
    ? table(["Flag", "Short", "Takes"], command.flags.map((f) => [`\`--${f.name}\``, f.short ? `\`-${f.short}\`` : "", f.type ? FLAG_TAKES[f.type] : "see the usage"]))
    : special ? "No flags of its own; see the global-flag exceptions above." : "No flags of its own; the global flags apply."
  return joinBlocks([
    `## \`${command.name}\``,
    `${command.summary.charAt(0).toUpperCase()}${command.summary.slice(1)}.`,
    `\`\`\`\n${command.usage}\n\`\`\``,
    flags,
    special && command.flags.length ? "Global flags: see the exceptions above; the usage lists what this command accepts." : null,
    command.examples.length ? `Examples:\n\n\`\`\`sh\n${command.examples.join("\n")}\n\`\`\`` : null,
    command.notes.length ? command.notes.map((n) => `- ${n}`).join("\n") : null,
  ])
}

export function cliMarkdown(source: HandSource, cli: CliReference, exits: readonly ExitProse[]): string {
  return joinBlocks([
    source.intro,
    "## Exit codes",
    "These are Mehen's own exit codes. `mehen run` returns the child's exit code after a successful start; it is not limited to this table. [Errors and exit codes](errors.md#exit-codes) says what to do with each, and names every error code.",
    table(["Exit", "Meaning"], exits.map((e) => [`\`${e.exit}\``, e.meaning])),
    "## Commands",
    `In the order \`mehen --help\` lists them. Standard commands accept the global flags ${cli.globalFlags.map((f) => `\`${f}\``).join(", ")}. \`run\`, \`env\`, \`init\` and \`mcp\` have the command-specific exceptions described under [Output and \`--json\`](#output-and---json) and in their usage.`,
    table(["Command", "What it does"], cli.commands.map((c) => [`[\`${c.name}\`](#${c.name})`, c.summary])),
    ...cli.commands.map(commandSection),
  ])
}

// ---------------------------------------------------------------- MCP

export function schemaType(schema: JsonSchema): string {
  if (schema.const !== undefined) return `\`${schema.const}\``
  if (schema.enum) return `one of ${schema.enum.map((v) => `\`${v}\``).join(", ")}`
  const choices = schema.oneOf ?? schema.anyOf
  if (choices) {
    const types = [...new Set(choices.map((c) => (c.type === "object" ? "object" : schemaType(c))))]
    return types.length === 1 && choices.length > 1 && types[0] === "object" ? `object, one of ${choices.length} shapes` : types.join(" or ")
  }
  if (schema.type === "array") return `array of ${schema.items ? schemaType(schema.items) : "values"}`
  if (schema.type === "integer" && schema.minimum !== undefined && schema.maximum !== undefined) return `integer, ${schema.minimum} to ${schema.maximum}`
  return schema.type ?? "any value"
}

function toolSection(tool: McpTool, prose: Entry | undefined): string {
  const properties = Object.entries(tool.inputSchema.properties ?? {})
  const required = new Set(tool.inputSchema.required ?? [])
  const inputs = properties.length
    ? table(["Input", "Type", "Required", "What it is"], properties.map(([name, schema]) => [`\`${name}\``, schemaType(schema), required.has(name) ? "yes" : "no", schema.description ?? ""]))
    : "No inputs."
  return joinBlocks([`## \`${tool.name}\``, tool.description, inputs, prose?.body ?? null])
}

// Every hand entry must name a tool the fixture has; a tool without prose
// is allowed.
export function mcpMarkdown(source: HandSource, mcp: McpReference, file: string): string {
  for (const entry of source.entries) {
    if (!mcp.tools.some((t) => t.name === entry.key)) throw new Error(`${file}:${entry.line}: ${entry.key} is not an MCP tool`)
  }
  return joinBlocks([
    source.intro,
    "## Tools",
    table(["Tool", "What it is for"], mcp.tools.map((t) => [`[\`${t.name}\`](#${t.name})`, firstSentence(t.description)])),
    ...mcp.tools.map((t) => toolSection(t, source.entries.find((e) => e.key === t.name))),
  ])
}

// ---------------------------------------------------------------- the platform API

const errorLink = (code: string) => `[\`${code}\`](errors.md#${code})`

function fieldTable(fields: readonly PlatformField[], first: string): string {
  return table([first, "Type", "Required"], fields.map((f) => [`\`${f.field}\``, f.type, f.required]))
}

function platformRouteSection(route: PlatformRouteEntry, extra: Entry | undefined, commonRefusals: readonly string[]): string {
  const answers = route.status.join(" or ")
  const empty = (fields: readonly PlatformField[] | null) => fields !== null && fields.length === 0
  return joinBlocks([
    `### \`${route.name}\``,
    `\`\`\`http\n${route.method} ${route.path}\n\`\`\``,
    route.prose,
    route.params.length ? `**Path.**\n\n${fieldTable(route.params, "Parameter")}` : null,
    route.query?.length ? `**Query.** Every value is a string on the wire.\n\n${fieldTable(route.query, "Parameter")}` : null,
    route.body === null ? null : empty(route.body) ? "**Body.** `{}`" : `**Body.**\n\n${fieldTable(route.body, "Field")}`,
    empty(route.answer) ? `**Answer (${answers}).** \`{}\`` : `**Answer (${answers}).**\n\n${fieldTable(route.answer, "Field")}`,
    route.refusals.length
      ? `**Its own refusals**, beyond the [common ones](#common-refusals): ${route.refusals.filter((code) => !commonRefusals.includes(code)).map(errorLink).join(", ")}.`
      : "**Its own refusals:** none beyond the [common ones](#common-refusals).",
    extra?.body ?? null,
  ])
}

// Every hand entry names a route or a limit; every limit needs one, its
// meaning in a single paragraph. A route's entry is optional: its prose
// comes from the route table, and a route without prose fails generate.ts.
export function platformMarkdown(source: HandSource, platform: PlatformReference, file: string): string {
  const routeNames = new Set(platform.routes.map((r) => r.name))
  const limitNames = new Set(platform.limits.map((l) => l.name))
  for (const entry of source.entries) {
    if (!routeNames.has(entry.key) && !limitNames.has(entry.key)) throw new Error(`${file}:${entry.line}: ${entry.key} is not a platform route or limit`)
  }
  const meaning = (name: string) => {
    const entry = source.entries.find((e) => e.key === name)
    if (!entry || entry.body === "" || /\n\s*\n/.test(entry.body)) throw new Error(`${file}: the limit ${name} needs a "### ${name}" entry of one paragraph saying what it limits`)
    return entry.body
  }
  const n = (value: number) => value.toLocaleString("en-GB")
  const span = (l: PlatformLimitEntry) => (l.min === null || l.max === null ? "" : `${n(l.min)} to ${n(l.max)}`)
  const ofPlatform = platform.routes.filter((r) => !r.path.includes("/:subject"))
  const ofSubject = platform.routes.filter((r) => r.path.includes("/:subject"))
  const summary = (routes: readonly PlatformRouteEntry[]) =>
    table(["Route", "Method and path", "What it does"], routes.map((r) => [`[\`${r.name}\`](#${headingSlug(`\`${r.name}\``)})`, `\`${r.method} ${r.path}\``, firstSentence(r.prose)]))
  const sections = (routes: readonly PlatformRouteEntry[]) => routes.map((r) => platformRouteSection(r, source.entries.find((e) => e.key === r.name), platform.commonRefusals))
  return joinBlocks([
    source.intro,
    "## Routes",
    `Every route is under \`${platform.pathPrefix}\` and carries \`${platform.header}\`. In the tables below, a nested member such as \`a.b\` is required within its parent, \`a[].b\` is a member of each item of the array \`a\`, and \`a.<name>.b\` a member of each value of the map \`a\`. The platform's own routes:`,
    summary(ofPlatform),
    "One subject's routes, each under `/v1/platform/subjects/:subject`:",
    summary(ofSubject),
    "## Common refusals",
    "Any route may answer these, beyond its own. Every refusal is an error object with the header `Mehen-Error: 1`.",
    table(["`error`", "When"], platform.commonRefusals.map((code) => [errorLink(code), commonRefusalWhen(code)])),
    "## Limits",
    "Mehen's operator sets each platform's limits when it registers the platform, and may change them later. Every managed workspace reads them live; past one, a route answers `quota_exceeded` or `rate_limited`. The defaults:",
    table(["Limit", "Default", "Range", "What it limits"], platform.limits.map((l) => [`\`${l.name}\``, n(l.default), span(l), meaning(l.name)])),
    "## The platform",
    ...sections(ofPlatform),
    "## A subject",
    "Every route here names one subject in its path, and its proof's `sub` claim must be that same subject. A subject the platform does not have is `not_found`, exactly as one that never existed.",
    ...sections(ofSubject),
  ])
}

// What each common refusal means on a platform route.
const COMMON_REFUSAL_WHEN: Record<string, string> = {
  unauthenticated: "No proof, or its key is unknown, revoked, past its rotation date or not this platform's.",
  proof_invalid: "The proof's signature, time, method, URL, body hash or subject does not match the request, or its nonce was used before.",
  platform_suspended: "Mehen's operator suspended or retired the platform.",
  rate_limited: "Too many calls or decisions for the platform or the subject; wait `retryAfter` seconds.",
  bad_request: "The path, query or body does not have the shape this page gives.",
  not_found: "The subject, or the object the path names, is not this platform's, exactly as if it did not exist.",
}

function commonRefusalWhen(code: string): string {
  const when = COMMON_REFUSAL_WHEN[code]
  if (when === undefined) throw new Error(`the common refusal ${code} has no sentence saying when a platform route answers it`)
  return when
}

// ---------------------------------------------------------------- providers

function policyLines(lines: PolicySummaryLines): string[] {
  return [`- Without a human: ${lines.allowed}`, `- Needs approval: ${lines.approve}`, `- Refused: ${lines.deny}`]
}

function docsLink(url: string | null): string | null {
  if (!url) return null
  return `- Where the human gets it: [${new URL(url).hostname}](${url})`
}

function templateSection(template: Template): string {
  const lines = [
    `- Kind: \`${template.kind}\`; ceiling \`${template.ceiling}\``,
    `- Goes to: ${goesTo(template)}`,
    template.injection ? `- Sent as: \`${injectionText(template.injection)}\`` : null,
    template.defaultEnvVar ? `- Environment variable its SDK or CLI reads: \`${template.defaultEnvVar}\`` : null,
    ...policyLines(policySummaryLines(templateSummary(template.policy))),
    docsLink(template.docsUrl),
    `- Ask for it: \`mehen request ${template.kind} --name <slug> --provider ${template.id} --reason "<why>"\``,
  ]
  return joinBlocks([`### \`${template.id}\``, `**${template.displayName}**`, lines.filter((l) => l !== null).join("\n")])
}

function providerSection(provider: ProvidersReference["oauthProviders"][number]): string {
  const { binding } = provider.upstream
  const paths = binding.paths?.length ? ` ${binding.paths.join(", ")}` : ""
  const lines = [
    `- Client template: [\`${provider.clientTemplate}\`](#${provider.clientTemplate})`,
    `- Default scopes: ${provider.auth.scopes.defaults.map((s) => `\`${shortScope(provider, s)}\``).join(", ")}`,
    `- Allowed scopes: ${provider.auth.scopes.allowed.map((s) => `\`${shortScope(provider, s)}\``).join(", ")}`,
    `- Goes to: ${binding.hosts.join(", ")}${paths}`,
    ...policyLines(policySummaryLines(templateSummary(provider.policy))),
    docsLink(provider.docsUrl),
    `- Connect it: \`mehen connect ${provider.id} --name <slug> --reason "<why>"\``,
  ]
  return joinBlocks([`### \`${provider.id}\``, `**${provider.displayName}**`, lines.filter((l) => l !== null).join("\n")])
}

export function providersMarkdown(source: HandSource, providers: ProvidersReference, file: string): string {
  if (source.entries.length > 0) throw new Error(`${file}:${source.entries[0]?.line}: the providers page takes no ### entries`)
  return joinBlocks([
    source.intro,
    ...providers.categories.flatMap((category) => {
      const templates = providers.templates.filter((t) => t.category === category.id)
      return templates.length ? [`## ${category.title}`, ...templates.map(templateSection)] : []
    }),
    "## OAuth providers",
    `What \`mehen connect\` may name. Each needs an OAuth client in the workspace, made from its client template; the client must list the redirect URI \`${providers.redirectUri}\`. In a platform's managed workspace the client is the user's own app, made with the template's set-up steps, and lists the platform's own callback instead ([Build on Mehen](../guides/build-on-mehen.md#connecting-an-account)).`,
    ...providers.oauthProviders.map(providerSection),
  ])
}
