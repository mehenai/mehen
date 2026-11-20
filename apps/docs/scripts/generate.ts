// Writes the facts the reference pages are generated from, as JSON under
// generated/: the CLI's command table and help text (cli.json), every error
// code with its HTTP status, exit code, default next step and the prose of
// reference/errors.md (errors.json), the MCP tool list the server answers
// with under --toolsets all, each tool with its toolset (mcp.json) and the template catalogue `mehen templates --json` prints
// (providers.json), and the platform API's route table with every route's
// path, query, body and answer fields, refusals and prose, and the
// platform's limits (platform.json). Everything is imported; nothing runs
// the CLI, so no machine's Mehen state or environment can change the
// output. No dates, so the same commit always writes the same bytes.
//
//   bun scripts/generate.ts

import { mkdir, readFile, writeFile } from "node:fs/promises"
import path from "node:path"
import { ERROR_CODES, EXIT_FOR_ERROR, HTTP_STATUS_FOR_ERROR, type ErrorCode } from "@mehen/protocol/api"
import { DEFAULT_PLATFORM_LIMITS, PLATFORM_COMMON_REFUSALS, PLATFORM_PATH_PREFIX, PLATFORM_PROOF_HEADER, PLATFORM_ROUTES, PlatformLimitsSchema, type PlatformRoute } from "@mehen/protocol/platform"
import { GLOBAL_FLAGS } from "../../cli/src/args.ts"
import { COMMANDS, LANE_COMMANDS, commandHelp, shellWord } from "../../cli/src/cli.ts"
import type { Command } from "../../cli/src/command.ts"
import { MCP_HELP } from "../../cli/src/commands/info.ts"
import { toolsetOf } from "../../cli/src/mcp/registry.ts"
import { templatesJson } from "../../cli/src/commands/templates.ts"
import { WORKSPACE_HELP } from "../../cli/src/commands/workspace.ts"
import { DEFAULT_NEXT, LOCAL_EXIT } from "../../cli/src/errors.ts"
import { ENV_USAGE, INIT_USAGE, RUN_USAGE } from "../../cli/src/run/index.ts"
import { VERSION } from "../../cli/src/version.ts"
import { frontMatter } from "./pages.ts"
import { type CliCommand, type CliFlag, type CliReference, type ErrorEntry, type McpReference, type PlatformField, type PlatformReference, type PlatformRouteEntry, labelled, splitEntries } from "./reference.ts"

export const DOCS_ROOT = path.resolve(import.meta.dir, "..")
export const REPO_ROOT = path.resolve(DOCS_ROOT, "../..")
export const GENERATED_DIR = path.join(DOCS_ROOT, "generated")
export const ERRORS_SOURCE = "docs/site/reference/errors.md"
// The tool list mehen mcp --toolsets all answers tools/list with, held byte
// for byte against the server by the CLI's own test.
export const TOOLS_FIXTURE = "apps/cli/src/mcp/fixtures/tools-list-all.json"

// The redirect URI an OAuth client lists, for the default vault: what
// `mehen templates --json` prints with no MEHEN_VAULT_URL and no enrolment.
export const DEFAULT_REDIRECT_URI = "https://app.mehen.dev/oauth/callback"

function regularCommand(name: string, command: Command): CliCommand {
  const flags: CliFlag[] = Object.entries(command.spec.flags).map(([flag, spec]) => ({ name: flag, short: spec.short ?? null, type: spec.type }))
  return {
    name,
    summary: command.summary,
    usage: command.spec.usage,
    flags,
    examples: command.examples.map((args) => `mehen ${args.map(shellWord).join(" ")}`),
    notes: command.notes ?? [],
    help: commandHelp(command),
  }
}

// Every `--name` in a usage string, in order, once: the flags of a command
// whose parser is its own (run, env, init, workspace, mcp).
export function usageFlags(usage: string): CliFlag[] {
  const names = [...new Set([...usage.matchAll(/--([a-z][a-z0-9-]*)/g)].map((m) => m[1] as string))]
  return names.map((name) => ({ name, short: null, type: null }))
}

// A command that carries its help as one string: the usage on the first
// line, the summary on the second, then examples and notes.
function helpCommand(name: string, help: string): CliCommand {
  const lines = help.split("\n")
  const usage = (lines[0] ?? "").replace(/^usage: /, "")
  const summary = (lines[1] ?? "").trim()
  const examples: string[] = []
  const notes: string[] = []
  let inExamples = false
  for (const line of lines.slice(2)) {
    if (line === "examples:") {
      inExamples = true
      continue
    }
    if (line.trim() === "") {
      inExamples = false
      continue
    }
    if (inExamples) examples.push(line.trim())
    else notes.push(line.trim())
  }
  return { name, summary, usage, flags: usageFlags(usage), examples, notes, help }
}

// run, env and init print their usage and summary as their help.
function laneCommand(name: "run" | "env" | "init", usage: string): CliCommand {
  const summary = (LANE_COMMANDS[name] as { summary: string }).summary
  return { name, summary, usage, flags: usageFlags(usage), examples: [], notes: [], help: `usage: ${usage}\n  ${summary}` }
}

export function cliReference(): CliReference {
  return {
    version: VERSION,
    globalFlags: Object.keys(GLOBAL_FLAGS).map((f) => `--${f}`),
    commands: [
      ...Object.entries(COMMANDS).map(([name, command]) => regularCommand(name, command)),
      laneCommand("run", RUN_USAGE),
      laneCommand("env", ENV_USAGE),
      laneCommand("init", INIT_USAGE),
      helpCommand("workspace", WORKSPACE_HELP),
      helpCommand("mcp", MCP_HELP),
    ],
  }
}

// Every code in source, joined with its prose: vault codes in ERROR_CODES
// order, then mehen's own in the order of LOCAL_EXIT. A code without a
// `### ` entry, or an entry naming no code, fails.
export function errorEntries(errorsSource: string): ErrorEntry[] {
  const hand = splitEntries(frontMatter(errorsSource, ERRORS_SOURCE).body, ERRORS_SOURCE)
  const codes: Omit<ErrorEntry, "means" | "do">[] = [
    ...ERROR_CODES.map((code: ErrorCode) => ({ code, origin: "vault" as const, http: HTTP_STATUS_FOR_ERROR[code], exit: EXIT_FOR_ERROR[code], next: DEFAULT_NEXT[code] ?? null })),
    ...Object.entries(LOCAL_EXIT).map(([code, exit]) => ({ code, origin: "mehen" as const, http: null, exit, next: null })),
  ]
  const known = new Set(codes.map((c) => c.code))
  for (const entry of hand.entries) {
    if (!known.has(entry.key) && !/^Exit \d+$/.test(entry.key)) throw new Error(`${ERRORS_SOURCE}:${entry.line}: ${entry.key} is not an error code`)
  }
  return codes.map((c) => {
    const entry = hand.entries.find((e) => e.key === c.code)
    if (!entry) throw new Error(`${ERRORS_SOURCE}: ${c.code} has no "### \`${c.code}\`" entry`)
    const means = labelled(entry.body, "What it means")
    const what = labelled(entry.body, "What you do")
    if (!means || !what) throw new Error(`${ERRORS_SOURCE}:${entry.line}: ${c.code} needs a **What it means.** and a **What you do.** paragraph`)
    const next = c.next ? { ...(c.next.command ? { command: c.next.command } : {}), say: c.next.say ?? "" } : null
    return { ...c, next, means, do: what }
  })
}

// ---------------------------------------------------------------- the platform API

// The JSON Schema members a protocol schema produces that the reference
// reads. Our own schemas, so nothing here is a trust boundary.
export type FieldSchema = {
  type?: string | readonly string[]
  const?: unknown
  enum?: readonly unknown[]
  format?: string
  pattern?: string
  minLength?: number
  maxLength?: number
  minimum?: number
  maximum?: number
  exclusiveMinimum?: number
  minItems?: number
  maxItems?: number
  items?: FieldSchema
  properties?: Record<string, FieldSchema>
  required?: readonly string[]
  additionalProperties?: FieldSchema | boolean
  propertyNames?: FieldSchema
  anyOf?: readonly FieldSchema[]
  oneOf?: readonly FieldSchema[]
}

type Described = { toJSONSchema(params: { io: "input" | "output"; unrepresentable: "any" }): unknown }

export function fieldSchema(schema: Described, io: "input" | "output"): FieldSchema {
  return schema.toJSONSchema({ io, unrepresentable: "any" }) as FieldSchema
}

// Deeper than this, a member is named with its type and not opened up.
const FIELD_DEPTH = 4
const SAFE_MAX = Number.MAX_SAFE_INTEGER

const choicesOf = (schema: FieldSchema): readonly FieldSchema[] | null => schema.anyOf ?? schema.oneOf ?? null
const isNull = (schema: FieldSchema) => schema.type === "null"
const isObject = (schema: FieldSchema) => schema.type === "object"
const isRecord = (schema: FieldSchema) => isObject(schema) && schema.properties === undefined && typeof schema.additionalProperties === "object"

// 10000000 as 10,000,000.
function count(n: number): string {
  return n.toLocaleString("en-GB")
}

function range(min: number | undefined, max: number | undefined, unit: string): string | null {
  const top = max === undefined || max >= SAFE_MAX ? undefined : max
  const tail = unit === "" ? "" : ` ${unit}`
  if (min !== undefined && top !== undefined) return min === top ? `${count(min)}${tail}` : `${count(min)} to ${count(top)}${tail}`
  if (top !== undefined) return `at most ${count(top)}${tail}`
  if (min !== undefined && min > 0) return `at least ${count(min)}${tail}`
  return null
}

function stringType(schema: FieldSchema): string {
  if (schema.format === "date-time") return "time (ISO 8601)"
  if (schema.format === "uri") return schema.maxLength === undefined ? "URL" : `URL, at most ${schema.maxLength} characters`
  if (schema.pattern !== undefined) return `string matching \`${schema.pattern}\``
  const length = range(schema.minLength, schema.maxLength, "characters")
  return length === null ? "string" : `string, ${length}`
}

function numberType(schema: FieldSchema, name: string): string {
  const min = schema.minimum ?? (schema.exclusiveMinimum === undefined ? undefined : schema.exclusiveMinimum + 1)
  const span = range(min, schema.maximum, "")
  return span === null ? name : `${name}, ${span}`
}

// A field's type in words, from its JSON Schema.
export function fieldType(schema: FieldSchema): string {
  if (schema.const !== undefined) return `\`${typeof schema.const === "string" ? schema.const : JSON.stringify(schema.const)}\``
  if (schema.enum !== undefined) return `one of ${schema.enum.map((v) => `\`${/\s/.test(String(v)) ? JSON.stringify(v) : String(v)}\``).join(", ")}`
  const choices = choicesOf(schema)
  if (choices !== null) {
    const present = choices.filter((c) => !isNull(c))
    const nullable = present.length < choices.length ? ", or null" : ""
    if (present.length > 1 && present.every(isObject)) return `object, one of ${present.length} shapes${nullable}`
    return `${[...new Set(present.map(fieldType))].join(" or ")}${nullable}`
  }
  if (Array.isArray(schema.type)) {
    const types = (schema.type as readonly string[]).filter((t) => t !== "null")
    const nullable = types.length < (schema.type as readonly string[]).length ? ", or null" : ""
    return `${types.map((t) => fieldType({ ...schema, type: t })).join(" or ")}${nullable}`
  }
  if (schema.type === "string") return stringType(schema)
  if (schema.type === "integer") return numberType(schema, "integer")
  if (schema.type === "number") return numberType(schema, "number")
  if (schema.type === "boolean") return "boolean"
  if (schema.type === "array") {
    const count = range(schema.minItems, schema.maxItems, "items")
    return `array of ${schema.items === undefined ? "values" : fieldType(schema.items)}${count === null ? "" : `, ${count}`}`
  }
  if (isRecord(schema)) {
    const names = schema.propertyNames === undefined ? "names" : fieldType(schema.propertyNames)
    return `map of keys (${names}) to values (${fieldType(schema.additionalProperties as FieldSchema)})`
  }
  if (isObject(schema)) return "object"
  return "any value"
}

type Requirement = PlatformField["required"]

// One row per member, nested members as `a.b`, array items as `a[].b`,
// a map's values as `a.<name>.b`. Where a value is one of several object
// shapes, every shape's members are listed, and a member some shapes
// require is required "in its shape".
function fieldsOf(schema: FieldSchema, prefix: string, depth: number, out: Map<string, PlatformField>): void {
  if (depth > FIELD_DEPTH) return
  const add = (field: string, member: FieldSchema, required: Requirement) => {
    const row = { field, type: fieldType(member), required }
    const seen = out.get(field)
    if (seen === undefined) out.set(field, row)
    else {
      const types = seen.type === row.type ? seen.type : `${seen.type} or ${row.type}`
      out.set(field, { field, type: types, required: seen.required === required ? required : "in its shape" })
    }
    fieldsOf(member, field, depth + 1, out)
  }
  const choices = choicesOf(schema)
  if (choices !== null) {
    const shapes = choices.filter((c) => !isNull(c) && isObject(c) && c.properties !== undefined)
    if (shapes.length === 0) {
      for (const choice of choices) fieldsOf(choice, prefix, depth, out)
      return
    }
    const names = [...new Set(shapes.flatMap((s) => Object.keys(s.properties ?? {})))]
    for (const name of names) {
      const holding = shapes.filter((s) => s.properties?.[name] !== undefined)
      const requiredIn = holding.filter((s) => s.required?.includes(name)).length
      const required: Requirement = shapes.length === 1 ? (requiredIn === 1 ? "yes" : "no") : requiredIn === shapes.length ? "yes" : requiredIn === 0 ? "no" : "in its shape"
      for (const shape of holding) add(join(prefix, name), shape.properties?.[name] as FieldSchema, required)
    }
    return
  }
  if (schema.type === "array" && schema.items !== undefined) {
    fieldsOf(schema.items, `${prefix}[]`, depth, out)
    return
  }
  if (isRecord(schema)) {
    fieldsOf(schema.additionalProperties as FieldSchema, join(prefix, "<name>"), depth, out)
    return
  }
  for (const [name, member] of Object.entries(schema.properties ?? {})) add(join(prefix, name), member, schema.required?.includes(name) ? "yes" : "no")
}

function join(prefix: string, name: string): string {
  return prefix === "" ? name : `${prefix}.${name}`
}

// The members of a body, query or answer, top level first, each followed
// by its own members.
export function schemaFields(schema: FieldSchema): PlatformField[] {
  const out = new Map<string, PlatformField>()
  fieldsOf(schema, "", 1, out)
  return [...out.values()]
}

// A route's prose is what the reference says it does: a route without a
// whole sentence of it fails the generation.
export function platformRouteEntry(route: PlatformRoute): PlatformRouteEntry {
  const prose = route.prose.trim()
  if (prose === "" || !/[.!?]$/.test(prose)) throw new Error(`platform route ${route.name} (${route.method} ${route.path}) has no prose: give it a whole sentence saying what it does`)
  return {
    number: route.number,
    name: route.name,
    method: route.method,
    path: route.path,
    params: Object.entries(route.params).map(([name, schema]) => ({ field: name, type: fieldType(fieldSchema(schema, "input")), required: "yes" as const })),
    query: route.query === null ? null : schemaFields(fieldSchema(route.query, "input")),
    body: route.body === null ? null : schemaFields(fieldSchema(route.body, "input")),
    answer: schemaFields(fieldSchema(route.answer, "output")),
    status: [...route.status],
    refusals: [...route.refusals],
    prose,
  }
}

export function platformReference(routes: readonly PlatformRoute[] = PLATFORM_ROUTES): PlatformReference {
  const bounds = fieldSchema(PlatformLimitsSchema, "input").properties ?? {}
  return {
    header: PLATFORM_PROOF_HEADER,
    pathPrefix: PLATFORM_PATH_PREFIX,
    commonRefusals: [...PLATFORM_COMMON_REFUSALS],
    limits: Object.entries(DEFAULT_PLATFORM_LIMITS).map(([name, value]) => ({ name, default: value, min: bounds[name]?.minimum ?? null, max: bounds[name]?.maximum ?? null })),
    routes: routes.map(platformRouteEntry),
  }
}

// Each tool with the toolset that serves it; one in no toolset fails.
export function mcpReference(list: McpReference): McpReference {
  return {
    tools: list.tools.map((tool) => {
      const toolset = toolsetOf(tool.name)
      if (toolset === null) throw new Error(`${tool.name} is in no toolset`)
      return { ...tool, toolset }
    }),
  }
}

export type Generated = { cli: CliReference; errors: ErrorEntry[]; mcp: McpReference; providers: Record<string, unknown>; platform: PlatformReference }

export async function generate(errorsSource: string): Promise<Generated> {
  return {
    cli: cliReference(),
    errors: errorEntries(errorsSource),
    mcp: mcpReference(JSON.parse(await readFile(path.join(REPO_ROOT, TOOLS_FIXTURE), "utf8")) as McpReference),
    providers: templatesJson(DEFAULT_REDIRECT_URI, undefined),
    platform: platformReference(),
  }
}

export async function writeGenerated(outDir: string, generated: Generated): Promise<void> {
  await mkdir(outDir, { recursive: true })
  for (const [name, value] of Object.entries(generated)) await writeFile(path.join(outDir, `${name}.json`), `${JSON.stringify(value, null, 2)}\n`)
}

if (import.meta.main) {
  const generated = await generate(await readFile(path.join(REPO_ROOT, ERRORS_SOURCE), "utf8"))
  await writeGenerated(GENERATED_DIR, generated)
  console.log(`generated: ${generated.cli.commands.length} commands, ${generated.errors.length} error codes, ${generated.mcp.tools.length} MCP tools, ${(generated.providers.templates as unknown[]).length} templates, ${generated.platform.routes.length} platform routes`)
}
