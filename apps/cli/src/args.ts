// A small, strict argument parser: unknown flags and wrong positional counts
// are usage errors (exit 2), never guesses.

import { usageError } from "./errors.ts"

export type FlagSpec = { type: "string" | "boolean" | "list"; short?: string }

export type CommandSpec = {
  usage: string // "mehen show <item>"
  flags: Record<string, FlagSpec>
  positionals: { min: number; max: number }
}

export const GLOBAL_FLAGS: Record<string, FlagSpec> = {
  json: { type: "boolean" },
  help: { type: "boolean", short: "h" },
  "no-qr": { type: "boolean" },
  // Selects a local context by workspace slug or id (design 15.6); cli.ts
  // folds it into MEHEN_WORKSPACE before the command runs.
  workspace: { type: "string" },
}

export class ParsedArgs {
  readonly positionals: string[] = []
  private readonly values = new Map<string, string | string[] | true>()

  set(name: string, spec: FlagSpec, value: string | true): void {
    if (spec.type === "list") {
      const current = this.values.get(name)
      this.values.set(name, [...(Array.isArray(current) ? current : []), value as string])
    } else {
      this.values.set(name, value)
    }
  }

  string(name: string): string | null {
    const value = this.values.get(name)
    return typeof value === "string" ? value : null
  }

  list(name: string): string[] {
    const value = this.values.get(name)
    return Array.isArray(value) ? value : []
  }

  bool(name: string): boolean {
    return this.values.get(name) === true
  }
}

export function parseArgs(argv: string[], spec: CommandSpec): ParsedArgs {
  const flags = { ...GLOBAL_FLAGS, ...spec.flags }
  const shorts = new Map(Object.entries(flags).flatMap(([name, f]) => (f.short ? [[f.short, name] as const] : [])))
  const parsed = new ParsedArgs()
  const help = `${spec.usage.split(" ").slice(0, 2).join(" ")} --help`
  let rest = false
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string
    if (rest || arg === "-" || !arg.startsWith("-")) {
      parsed.positionals.push(arg)
      continue
    }
    if (arg === "--") {
      rest = true
      continue
    }
    let name: string | undefined
    let inline: string | null = null
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=")
      name = eq === -1 ? arg.slice(2) : arg.slice(2, eq)
      if (eq !== -1) inline = arg.slice(eq + 1)
    } else {
      name = shorts.get(arg.slice(1, 2))
      if (name && arg.length > 2) inline = arg.slice(2)
    }
    const flag = name ? flags[name] : undefined
    if (!name || !flag) throw usageError(`Unknown option ${arg} for \`${spec.usage}\`.`, help)
    if (flag.type === "boolean") {
      if (inline !== null) throw usageError(`${arg} takes no value.`, help)
      parsed.set(name, flag, true)
      continue
    }
    const value = inline ?? argv[++i]
    if (value === undefined) throw usageError(`${arg} needs a value. Usage: ${spec.usage}`, help)
    if (inline === null && value.startsWith("--")) throw usageError(`${arg} needs a value, but the next argument is the option ${value}. A value that starts with -- is given as --${name}=<value>. Usage: ${spec.usage}`, help)
    parsed.set(name, flag, value)
  }
  if (!parsed.bool("help")) {
    const n = parsed.positionals.length
    if (n < spec.positionals.min || n > spec.positionals.max) throw usageError(`Usage: ${spec.usage}`, help)
  }
  return parsed
}
