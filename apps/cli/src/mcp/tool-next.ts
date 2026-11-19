import type { NextStep } from "@mehen/protocol/api"
import { z } from "zod"
import { CliError, DEFAULT_NEXT, toolCallText } from "../errors.ts"
import { APP_TOOLS, TOOLS } from "./registry.ts"

export const TOOL_SCHEMA_NEXT = { say: "Fix the arguments to match the tool's input schema." }
const TEMPLATES_NEXT = { say: "List the templates and providers with vault_templates and use an id from there.", tool: "vault_templates" }
const CLI_HELP = /^mehen(?: [a-z-]+)* --help$/

// The tool that does each mehen command's work, by the command's words.
const TOOL_FOR: Record<string, string> = {
  ls: "vault_list",
  show: "vault_show",
  check: "vault_check",
  request: "vault_request",
  connect: "vault_connect",
  fetch: "vault_fetch",
  plan: "vault_plan",
  fill: "vault_fill",
  push: "vault_push",
  wait: "vault_wait",
  pending: "vault_pending",
  status: "vault_status",
  whoami: "vault_status",
  doctor: "vault_doctor",
  templates: "vault_templates",
  policy: "vault_policy",
  "policy show": "vault_policy",
  mandate: "vault_mandate",
  "mandate ls": "vault_mandate",
  "mandate show": "vault_mandate",
  "mandate pause": "vault_mandate",
  "env ls": "vault_env",
  "env check": "vault_env",
  "adopt scan": "vault_adopt_scan",
  "adopt status": "vault_adopt_status",
  "workspace list": "vault_status",
  "workspace show": "vault_status",
}

// The tool's arguments for a command that takes nothing, or one value.
const FIXED_ARGUMENTS: Record<string, Record<string, string>> = { "mandate ls": { action: "list" } }
const VALUE_ARGUMENTS: Record<string, (value: string) => Record<string, string>> = {
  show: (item) => ({ item }),
  wait: (id) => ({ id }),
  templates: (id) => ({ id }),
  "mandate show": (id) => ({ action: "show", id }),
  "mandate pause": (id) => ({ action: "pause", id }),
  "policy show": (item) => ({ action: "show", item }),
  "adopt status": (adoption) => ({ adoption }),
}

const VALUE = /^[A-Za-z0-9][A-Za-z0-9_.:@-]*$/
const PLACEHOLDER = /^<[^>]*>$/
// Flags that change only how mehen prints.
const OUTPUT_FLAGS = new Set(["--json", "--no-qr"])

// A tool call as next carries it: the arguments only where they carry over.
export type ToolStep = { tool: string; arguments?: Record<string, string> }

function call(tool: string, args: Record<string, string> | null): ToolStep {
  return args === null ? { tool } : { tool, arguments: args }
}

// The tool call that does what a mehen command does: with its arguments
// where they carry over (`vault_wait { "id": "apr_1" }`), else the tool's
// name alone; null when no tool does it. `loose` takes a command with
// flags the tool spells another way (a request's --name) as the tool by
// name; without it such a command maps to nothing.
export function toolStep(command: string, loose: boolean): ToolStep | null {
  const words = command.trim().split(/\s+/)
  if (words[0] !== "mehen") return null
  const rest = words.slice(1).filter((w) => !OUTPUT_FLAGS.has(w))
  // The longer name first: `mandate show` before `mandate`.
  for (const length of [2, 1]) {
    const name = rest.slice(0, length).join(" ")
    const tool = rest.length >= length ? TOOL_FOR[name] : undefined
    if (tool === undefined) continue
    const after = rest.slice(length)
    if (after.length === 0) return call(tool, FIXED_ARGUMENTS[name] ?? null)
    const [value = "", ...extra] = after
    const timeout = name === "wait" && extra.length === 2 && extra[0] === "--timeout"
    const toArguments = VALUE_ARGUMENTS[name]
    // A placeholder stays in the arguments, so the action it goes with is kept.
    if (toArguments && (VALUE.test(value) || PLACEHOLDER.test(value)) && (extra.length === 0 || timeout)) return call(tool, toArguments(value))
    if (after.every((w) => PLACEHOLDER.test(w)) || loose) return call(tool, null)
    return null
  }
  return null
}

// toolStep as text, as a say names it.
export function toolCall(command: string, loose: boolean): string | null {
  const step = toolStep(command, loose)
  return step === null ? null : toolCallText(step.tool, step.arguments)
}

// A say written for the command line names the tools instead: each
// `mehen ...` in it that a tool does is that tool's call. A command with
// flags of its own (`mehen fetch -o <file>`) stays, since no tool takes them.
export function toolSay(say: string): string {
  return say.replace(/`(mehen [^`]+)`/g, (whole, command: string) => {
    const tool = toolCall(command, false)
    return tool === null ? whole : `\`${tool}\``
  })
}

// A command-line flag a tool spells another way than its words in camel case.
const FLAG_RENAMES: Record<string, string[]> = {
  "--max-time": ["timeoutSeconds"],
  "--timeout": ["timeoutSeconds"],
  "--tag": ["tags"],
  "--host": ["hosts"],
  "--path": ["path", "paths"],
  "--client-tag": ["clientTags"],
}

let toolArguments: Map<string, Set<string>> | null = null

function argumentsOf(tool: string): Set<string> {
  toolArguments ??= new Map(
    [...TOOLS, ...APP_TOOLS].map((t) => {
      const schema = z.toJSONSchema(t.input, { io: "input" }) as { properties?: Record<string, unknown> }
      return [t.name, new Set(Object.keys(schema.properties ?? {}))]
    }),
  )
  return toolArguments.get(tool) ?? new Set()
}

function flagArgument(flag: string, tool: string): string | null {
  const names = argumentsOf(tool)
  const camel = flag.slice(2).replace(/-([a-z])/g, (_, letter: string) => letter.toUpperCase())
  const candidates = [camel, ...(FLAG_RENAMES[flag] ?? [])]
  return candidates.find((name) => names.has(name)) ?? null
}

// A flag after `mehen ...` or `mcp ...` in the same clause belongs to that command.
const PROSE_FLAG = /(?<![\w-])(?<!\b(?:mehen|mcp)(?: [a-z-]+)* )--[a-z][a-z-]*/g

// A flag a say names outside a command (`with --client`) is the tool's
// argument (`with \`client\``); a flag the tool has no argument for, or
// one a command written in the say takes (`mcp --workspace`), stays.
export function toolFlags(say: string, tool: string): string {
  const named = (flag: string) => {
    const name = flagArgument(flag, tool)
    return name === null ? flag : `\`${name}\``
  }
  // The odd parts are inside backticks: a command, left as it is.
  return say
    .split("`")
    .map((part, i) => (i % 2 === 1 ? part : part.replace(PROSE_FLAG, named)))
    .join("`")
}

// The shared operations word their next steps for the command line; through
// a tool, a step another tool does is that tool's call, in next.tool and
// next.arguments, and loses its command. next.say stays a sentence for the
// human, its `mehen ...` and flags named as the tools have them. A usage
// error's --help (or the bare tool name resolveHome is given) is the tool's
// input schema: usageError's generic say becomes the schema's, while a say
// written for the case stays. A step only the command line takes keeps its
// command and names no tool.
export function toolNext(error: CliError, tool: string): CliError {
  const next = error.next
  if (next === null) return error
  const replaced = (step: NextStep) => new CliError(error.code, error.message, step, error.extras)
  if (error.code === "bad_request" && next.say === DEFAULT_NEXT.bad_request.say && next.command === undefined) return replaced(TOOL_SCHEMA_NEXT)
  const command = next.command
  const say = toolFlags(toolSay(next.say), tool)
  const link = next.url === undefined ? {} : { url: next.url }
  if (command === undefined) return say === next.say ? error : replaced({ ...link, say })
  if (command === "mehen templates") return replaced(TEMPLATES_NEXT)
  if (error.code === "usage" && (CLI_HELP.test(command) || command === tool)) {
    const generic = next.say === `Check the usage with \`${command}\`.`
    return replaced(generic ? TOOL_SCHEMA_NEXT : { say })
  }
  const step = toolStep(command, true)
  if (step !== null) return replaced({ ...link, say, ...step })
  const workspace = /^mehen --workspace (\S+)$/.exec(command)?.[1]
  if (workspace !== undefined) return replaced({ ...link, say, tool, arguments: { workspace } })
  return replaced({ ...next, say })
}
