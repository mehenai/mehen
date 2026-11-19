import type { ParsedArgs, CommandSpec } from "./args.ts"
import type { Env } from "./config.ts"

export type CommandContext = {
  args: ParsedArgs
  json: boolean
  env: Env
}

export type Command = {
  summary: string
  spec: CommandSpec
  // Argument lists `mehen <command> --help` prints as examples; cli.test.ts
  // parses every one against `spec`, so none can drift from the flags.
  examples: string[][]
  // Short lines printed under the examples: what the output is, exit codes.
  notes?: string[]
  // Resolves with the exit code; throws CliError (or anything) to fail.
  run(ctx: CommandContext): Promise<number>
}
