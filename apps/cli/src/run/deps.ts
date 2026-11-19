// What the run, env and init commands are given, and how they report a
// failure: one line saying what went wrong, then the next step. A vault
// refusal is rendered by the same code as every other mehen command
// (output.ts writeError), so a link the vault hands back is checked against
// the configured vault and every line crosses the terminal boundary.
//
// Every other line these commands write for a human leaves through writeLine
// here, which applies terminalText: a name the vault or mehen.toml supplied is
// spelled out, and only the styler's segments carry colour.

import { EXIT, type ExitCode, type NextStep } from "@mehen/protocol/api"
import { type AskVault, askUrl, refusedLinkWarning } from "../ask.ts"
import { CliError, exitCodeFor, toCliError } from "../errors.ts"
import { writeError } from "../output.ts"
import { type Segment, type Styler, type Text, type TtyStream, colourEnabled, segments, styler, terminalText } from "../tty.ts"
import { VaultApiError, VaultNetworkError, type VaultApi } from "../vault-api.ts"

// A process stream, or a test's capture: colour is decided from isTTY.
export type Writer = TtyStream & { write(chunk: string | Uint8Array): unknown }

export type Deps = {
  api: VaultApi
  // The context's origin, workspace id, device and recorded slug (which
  // alone admits a workspace-prefixed link from the vault).
  config: { vault: string; tenant: string; device: string; workspaceSlug?: string; workspaceName?: string }
  stdout: Writer
  stderr: Writer
  // Where the command runs; process.cwd() when absent.
  cwd?: string
  // The parent environment; process.env when absent.
  env?: Record<string, string | undefined>
  // Where mehen run appends a line per finished run (run-log.ts); no log
  // when absent.
  runLog?: string
}

// The vault links are checked against: the origin with the context's slug.
export function askVault(deps: Pick<Deps, "config">): AskVault {
  return { vaultUrl: deps.config.vault, workspaceSlug: deps.config.workspaceSlug ?? null }
}

// A failure this CLI found itself, with its exit code and next step.
export class CommandError extends Error {
  readonly code: ExitCode
  readonly next: NextStep | undefined

  constructor(code: ExitCode, message: string, next?: NextStep) {
    super(message)
    this.code = code
    this.next = next
  }
}

export function cwdOf(deps: Deps): string {
  return deps.cwd ?? process.cwd()
}

export function envOf(deps: Deps): Record<string, string | undefined> {
  return deps.env ?? process.env
}

// True when --help or -h is one of this command's own options: not a flag's
// value, not after `--`, and, with stopAtPositional, not after the first
// positional (in `mehen run cmd --help` it belongs to cmd).
export function wantsHelp(argv: string[], valueFlags: readonly string[], stopAtPositional: boolean): boolean {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? ""
    if (arg === "--") return false
    if (arg === "--help" || arg === "-h") return true
    if (valueFlags.includes(arg)) i++
    else if (stopAtPositional && !arg.startsWith("-")) return false
  }
  return false
}

// The terminal boundary for run, env and init: one line for a human, spelled out.
export function writeLine(out: Writer, text: Text): void {
  out.write(`${terminalText(text)}\n`)
}

// The styler for lines going to `stream`: colour only when it is a TTY and
// the environment allows it (tty.ts colourEnabled).
export function stylerFor(deps: Deps, stream: Writer): Styler {
  return styler(colourEnabled(stream, envOf(deps)))
}

// `mehen: <message>`, the prefix dim on a TTY (UX-MEHEN-TOOLS 2.7).
export function mehenLine(s: Styler, message: string): Segment[] {
  return segments(s.dim("mehen:"), ` ${message}`)
}

// `mehen: warning: <message>`, as output.ts errorLines prints a warning.
export function warningLine(s: Styler, message: string): Segment[] {
  return segments(s.dim("mehen:"), " ", s.danger("warning:"), ` ${message}`)
}

// The next step for a human, laid out as every mehen error prints it: next:,
// then open:, then one run: per command (labels dim on a TTY). A link is
// printed only when askUrl accepts it against the vault this machine uses;
// without a vault URL to check against, or with a link that fails, a warning
// stands in for the open: line. `commands` replaces next.command when a step
// has several, as mehen env check has.
export function nextLines(next: NextStep, vaultUrl: AskVault | undefined, s: Styler, commands: readonly string[] = next.command === undefined ? [] : [next.command]): Segment[][] {
  const lines: Segment[][] = [segments("  ", s.dim("next:"), ` ${next.say}`)]
  if (next.url !== undefined) {
    const link = askUrl(next.url, vaultUrl)
    lines.push(link ? segments("  ", s.dim("open:"), ` ${link.url}`) : segments("  ", warningLine(s, refusedLinkWarning(vaultUrl ?? null))))
  }
  for (const command of commands) lines.push(segments("  ", s.dim("run:"), `  ${command}`))
  return lines
}

export function writeNext(out: Writer, next: NextStep | undefined, vaultUrl: AskVault | undefined, s: Styler): void {
  if (next === undefined) return
  for (const line of nextLines(next, vaultUrl, s)) writeLine(out, line)
}

// A failure as these commands' own error, or as the CliError every other command
// reports. Anything that is neither a vault refusal nor this CLI's own error
// means the vault could not be reached.
function asCliError(deps: Deps, error: unknown): CliError {
  if (error instanceof CliError || error instanceof VaultApiError || error instanceof VaultNetworkError) return toCliError(error)
  const message = `could not reach the vault at ${deps.config.vault}: ${error instanceof Error ? error.message : String(error)}`
  return new CliError("network", message, { say: "Check the network and try again." })
}

// Prints any failure and returns its exit code. A usage error is the
// usageError every other command throws (errors.ts), so it renders the same.
export function reportFailure(deps: Deps, error: unknown, json = false): ExitCode {
  const s = stylerFor(deps, deps.stderr)
  if (error instanceof CommandError) {
    if (json) deps.stdout.write(`${JSON.stringify({ error: error.code === EXIT.usage ? "usage" : "failed", message: error.message, next: error.next ?? null })}\n`)
    else {
      writeLine(deps.stderr, mehenLine(s, error.message))
      writeNext(deps.stderr, error.next, askVault(deps), s)
    }
    return error.code
  }
  const failure = asCliError(deps, error)
  writeError(failure, json, deps.stdout, deps.stderr, { env: envOf(deps), vaultUrl: askVault(deps) })
  return exitCodeFor(failure.code)
}
