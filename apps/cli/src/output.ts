// stdout carries results (one JSON object per line with --json); stderr
// carries everything meant for a person reading along. Decoration (colour,
// QR codes) appears only when the stream it goes to is a TTY.
//
// Every line for a human leaves through printLine, note, printBlock,
// noteBlock, printAsk or writeError, and each of those passes it through
// terminalText: every
// segment's text is spelled out (controls, hidden characters, noncharacters)
// and only a segment's trusted `style` becomes an escape sequence. A new
// field cannot skip it, and no text can style itself.

import type { Bytes } from "@mehen/protocol/bytes"
import type { NextStep } from "@mehen/protocol/api"
import { type Ask, type AskTextOptions, type AskVault, askForError, askLines, askUrl, refusedLinkWarning } from "./ask.ts"
import type { Env } from "./config.ts"
import { type CliError, describeNext, errorBody, toolCallText } from "./errors.ts"
import { type MandateCover, checkedMandateCover, mandateCoverText } from "./mandate-cover.ts"
import type { MandateSurface } from "./mandate-operations.ts"
import { type Segment, type Text, type TtyStream, colourEnabled, qrChoice, segments, styler, terminalText, visibleWidth } from "./tty.ts"

// --json results and errors: raw JSON, which escapes controls on its own.
export function printJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value)}\n`)
}

// A line is one line, string or segments: a line feed inside it, such as
// one in a name the vault sent, is a character of a field and is spelled out.
export function printLine(text: Text = ""): void {
  process.stdout.write(`${terminalText(text)}\n`)
}

export function note(text: Text): void {
  process.stderr.write(`${terminalText(text)}\n`)
}

// Text the CLI wrote itself with deliberate line breaks (help, a rendered
// config): each line crosses the boundary on its own. Never for text that
// holds anything from the vault or an upstream.
function blockText(text: string): string {
  return text.split("\n").map(terminalText).join("\n")
}

export function printBlock(text: string): void {
  process.stdout.write(`${blockText(text)}\n`)
}

export function noteBlock(text: string): void {
  process.stderr.write(`${blockText(text)}\n`)
}

export async function writeStdout(bytes: Bytes): Promise<void> {
  if (bytes.length === 0) return
  if (!process.stdout.write(bytes)) await new Promise<void>((resolve) => process.stdout.once("drain", () => resolve()))
}

export type OutputStream = "stdout" | "stderr"

// Something lines can be written to: a process stream, or a test's writer.
export type HumanWriter = TtyStream & { write(chunk: string | Uint8Array): unknown }

export type PrintAskOptions = Pick<AskTextOptions, "then" | "expiresNote" | "now"> & {
  stream?: OutputStream
  env?: Env
  noQr?: boolean
}

const ASK_INDENT = 2

function askBlock(ask: Ask, stream: HumanWriter, env: Env, noQr: boolean, options: Pick<AskTextOptions, "then" | "expiresNote" | "now"> = {}): Segment[][] {
  return askLines(ask, {
    style: styler(colourEnabled(stream, env)),
    qr: qrChoice(stream, env, ask.url, { noQr, indent: ASK_INDENT }),
    indent: ASK_INDENT,
    ...(options.then !== undefined ? { then: options.then } : {}),
    ...(options.expiresNote !== undefined ? { expiresNote: options.expiresNote } : {}),
    ...(options.now !== undefined ? { now: options.now } : {}),
  })
}

// The ask block for a human, with colour and a QR code when the stream is a
// TTY. Results (enrol, request, connect, pending) go to stdout; an ask that
// accompanies a refusal goes to stderr with the error.
export function printAsk(ask: Ask, options: PrintAskOptions = {}): void {
  const stream = (options.stream ?? "stdout") === "stdout" ? process.stdout : process.stderr
  const lines = askBlock(ask, stream, options.env ?? {}, options.noQr ?? false, options)
  stream.write(`${lines.map(terminalText).join("\n")}\n`)
}

// `then` replaces the ask block's then: line for a given ask (MCP names its
// own tool there instead of `mehen wait`); null drops the line.
// `surface` words a mandateCover line for the command line (the default) or MCP.
export type ErrorOutputOptions = { env?: Env; noQr?: boolean; vaultUrl?: AskVault | null; then?: (ask: Ask) => string | null; surface?: MandateSurface }

// The error's ask and next, with every link checked: the ask's through
// askForError, and next.url (whatever the error code) through askUrl. A
// link that fails is dropped, next becomes the warning, and `refused` says
// so. A link that passes is the canonical string askUrl returned.
// mandateCover's link is checked against the failing call's own vault, as
// a synthesised ask's is.
function checkedError(error: CliError, options: ErrorOutputOptions): { ask: Ask | null; next: NextStep | null; refused: boolean; cover: MandateCover | null } {
  const vaultUrl = options.vaultUrl ?? null
  const { ask, refusedLink } = askForError(error, options.env ?? {}, vaultUrl)
  const call = error.extras.context ?? null
  const cover = error.extras.mandateCover ? checkedMandateCover(error.extras.mandateCover, call ? { vaultUrl: call.origin, workspaceSlug: call.workspace?.slug ?? null } : vaultUrl) : null
  const given = error.next?.url
  const link = given === undefined ? null : askUrl(given, vaultUrl)
  const refused = refusedLink || (given !== undefined && link === null)
  if (refused) return { ask, next: { say: refusedLinkWarning(vaultUrl) }, refused, cover }
  if (!error.next) return { ask, next: null, refused, cover }
  return { ask, next: link ? { ...error.next, url: link.url } : error.next, refused, cover }
}

// The --json body for an error: `ask` where the refusal hands over a link,
// and never a link that failed askUrl (next becomes the warning).
export function errorJson(error: CliError, options: ErrorOutputOptions = {}): Record<string, unknown> {
  const { ask, next, cover } = checkedError(error, options)
  return { ...errorBody(error), next, ...(ask ? { ask } : {}), ...(cover ? { mandateCover: cover } : {}) }
}

// The human lines for an error: mehen: <message>, then next: <say>, then the
// ask block when the refusal hands over a link (its open: and then: lines
// replace next's open: and run:). A link that failed askUrl is never
// printed: a warning says so instead, and the exit code stays the error's.
export function errorLines(error: CliError, stream: HumanWriter, options: ErrorOutputOptions = {}): Segment[][] {
  const env = options.env ?? {}
  const { ask, next, refused, cover } = checkedError(error, options)
  const s = styler(colourEnabled(stream, env))
  const lines: Segment[][] = [segments(s.dim("mehen:"), ` ${error.message}`)]
  if (cover) lines.push(segments(s.dim("mandate:"), ` ${mandateCoverText(cover, options.surface ?? "cli")}`))
  if (refused) lines.push(segments(s.dim("mehen:"), " ", s.danger("warning:"), ` ${refusedLinkWarning(options.vaultUrl ?? null)}`))
  if (ask) {
    const then = options.then ? options.then(ask) : undefined
    if (next && !refused) lines.push(segments(s.dim("next:"), ` ${next.say}`))
    // An MCP step the ask's then: line does not already name.
    const call = next?.tool && !refused ? toolCallText(next.tool, next.arguments) : null
    if (call !== null && call !== then) lines.push(segments(`  call: ${call}`))
    lines.push(...askBlock(ask, stream, env, options.noQr ?? false, then !== undefined ? { then } : {}))
    return lines
  }
  if (!refused) for (const line of describeNext(next)) lines.push(segments(line))
  return lines
}

// One renderer for every failure: the CLI's own commands (cli.ts) and the
// run, env and init commands (run/deps.ts) both call this with their streams.
export function writeError(error: CliError, json: boolean, stdout: HumanWriter, stderr: HumanWriter, options: ErrorOutputOptions = {}): void {
  if (json) {
    stdout.write(`${JSON.stringify(errorJson(error, options))}\n`)
    return
  }
  stderr.write(`${errorLines(error, stderr, options).map(terminalText).join("\n")}\n`)
}

export function reportError(error: CliError, json: boolean, options: ErrorOutputOptions = {}): void {
  writeError(error, json, process.stdout, process.stderr, options)
}

// Aligned columns for human tables, as lines of segments. Every cell stays
// on its row and may carry colour: widths are measured on the visible text.
// Width is not clamped; wrapping is the terminal's job.
export function table(rows: readonly (readonly Text[])[]): Segment[][] {
  const widths: number[] = []
  for (const row of rows) row.forEach((cell, i) => (widths[i] = Math.max(widths[i] ?? 0, visibleWidth(cell))))
  return rows.map((row) => {
    const line: Segment[] = []
    row.forEach((cell, i) => {
      line.push(...segments(cell))
      if (i < row.length - 1) line.push({ text: `${" ".repeat((widths[i] ?? 0) - visibleWidth(cell))}  ` })
    })
    return trimLine(line)
  })
}

function trimLine(line: Segment[]): Segment[] {
  const out = [...line]
  while (out.length > 0) {
    const last = out[out.length - 1] as Segment
    const trimmed = last.text.trimEnd()
    if (trimmed === last.text) break
    if (trimmed === "") out.pop()
    else {
      out[out.length - 1] = { ...last, text: trimmed }
      break
    }
  }
  return out
}
