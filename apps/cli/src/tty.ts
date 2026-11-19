// What a human at a terminal gets and an agent reading a pipe never does:
// colour, a QR code, emphasis. Everything here keys off the stream being a
// TTY, so --json output and MCP results never carry an escape code.
//
// Colour never carries meaning on its own: every word it decorates is the
// same word without it.

import type { Env } from "./config.ts"
import { QR_QUIET_ZONE, type QrScheme, qrMatrix } from "./qr.ts"

export type TtyStream = { isTTY?: boolean; columns?: number }

export function isTty(stream: TtyStream): boolean {
  return stream.isTTY === true
}

// True only when the stream is a TTY, NO_COLOR is unset or empty and TERM is
// not "dumb". FORCE_COLOR (set and not "0") forces it on, TTY or not.
export function colourEnabled(stream: TtyStream, env: Env): boolean {
  const force = env.FORCE_COLOR
  if (force !== undefined && force !== "" && force !== "0") return true
  if (!isTty(stream)) return false
  if (env.NO_COLOR !== undefined && env.NO_COLOR !== "") return false
  if (env.TERM === "dumb") return false
  return true
}

// The named styles a line may carry, and nothing else: a closed set, so a
// segment can only ever ask for one of these and never for an escape code
// of its own. The SGR each one maps to lives here; the vault's accent is one
// entry to retune.
export type StyleName = "bold" | "dim" | "accent" | "ok" | "warn" | "danger"

const SGR_FOR: Record<StyleName, string> = { bold: "1", dim: "2", accent: "36", ok: "32", warn: "33", danger: "31" }
const SGR_RESET = "0"

// Styling is structure, never text. A line for a human is a list of
// segments; the `style` of a segment is a StyleName set only by this
// module's styler and is the only thing the terminal boundary turns into an
// escape sequence. The `text` of a segment, whatever it came from, is
// spelled out by visibleText at that boundary and can never become an
// escape code, a marker or a colour (BUILD-COMMON, constraints from
// security reviews).
export type Segment = { text: string; style?: StyleName }

// Anything a human line can be made of: plain text, one segment, or a list.
export type Text = string | Segment | readonly Segment[]

export function segments(...parts: readonly Text[]): Segment[] {
  const out: Segment[] = []
  for (const part of parts) {
    if (typeof part === "string") out.push({ text: part })
    else if (Array.isArray(part)) out.push(...(part as readonly Segment[]))
    else out.push(part as Segment)
  }
  return out
}

export function style(text: string, name: StyleName): Segment {
  return text === "" ? { text } : { text, style: name }
}

// The words alone, styles dropped: for tests, MCP text and width measuring.
export function plainText(parts: Text): string {
  return segments(parts)
    .map((s) => s.text)
    .join("")
}

const SGR_SEQUENCE = /\u001b\[[0-9;]*m/g

export function stripStyle(text: string): string {
  return text.replace(SGR_SEQUENCE, "")
}

// The terminal boundary: one line as it may be written to a TTY or a pipe
// for a human. Each segment's text is spelled out by visibleText, then
// wrapped in the SGR of its named style; a style that is not one of the
// names is ignored. Applied exactly once, by output.ts (and run/deps.ts),
// as the line is written.
export function terminalText(parts: Text): string {
  return segments(parts)
    .map((s) => {
      const text = visibleText(s.text)
      const sgr = s.style !== undefined && Object.hasOwn(SGR_FOR, s.style) ? SGR_FOR[s.style] : null
      return sgr !== null && text !== "" ? `\u001b[${sgr}m${text}\u001b[${SGR_RESET}m` : text
    })
    .join("")
}

// Columns the text takes once it reaches the terminal: styles aside, hidden
// and control characters counted as their spelled-out form.
export function visibleWidth(parts: Text): number {
  return visibleText(plainText(parts)).length
}

// One object a command asks for once, then applies everywhere: every method
// returns an unstyled segment when colour is off.
export type Styler = {
  enabled: boolean
  bold(text: string): Segment
  dim(text: string): Segment
  accent(text: string): Segment
  ok(text: string): Segment
  warn(text: string): Segment
  danger(text: string): Segment
  status(text: string): Segment
}

export function styler(enabled: boolean): Styler {
  const apply = (name: StyleName) => (text: string) => (enabled ? style(text, name) : { text })
  const ok = apply("ok")
  const warn = apply("warn")
  const danger = apply("danger")
  return {
    enabled,
    bold: apply("bold"),
    dim: apply("dim"),
    accent: apply("accent"),
    ok,
    warn,
    danger,
    status(text) {
      const tone = statusTone(text)
      return tone === "good" ? ok(text) : tone === "wait" ? warn(text) : tone === "bad" ? danger(text) : { text }
    },
  }
}

export function plainStyler(): Styler {
  return styler(false)
}

export type StatusTone = "good" | "wait" | "bad"

const GOOD_WORDS = new Set(["active", "allowed", "approved", "completed", "used", "verified", "connected", "ok"])
const WAIT_WORDS = new Set(["needs reauth", "needs_reauth", "refresh retrying", "refresh_retrying", "needs approval", "pending", "open", "waiting"])
const BAD_WORDS = new Set(["disabled", "denied", "refused", "expired", "(unverified)", "unverified", "needs review", "rejected", "cancelled", "failed", "mismatch", "frozen"])

// The tone a status word carries (UX-MEHEN-TOOLS 2.7), or null for a word that
// is not a status.
export function statusTone(word: string): StatusTone | null {
  const key = word.trim().toLowerCase()
  if (GOOD_WORDS.has(key)) return "good"
  if (WAIT_WORDS.has(key)) return "wait"
  if (BAD_WORDS.has(key)) return "bad"
  return null
}

// ---------------------------------------------------------------- text a terminal can be trusted to show

// Characters a terminal would obey or hide: C0 controls (tab, newline and
// carriage return included, since a line here is a row), DEL, C1 controls,
// and the format characters that reorder or hide text (bidi overrides and
// isolates, zero-width joiners and spaces, soft hyphen, BOM, tags). Arabic
// number signs and the syriac abbreviation mark are format characters that
// carry meaning in their scripts and are left alone, as the server does.
const CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F]/gu
// Format characters, the line and paragraph separators, every other default
// ignorable code point (variation selectors, Hangul fillers, Mongolian
// selectors, the combining grapheme joiner), which a terminal draws as
// nothing, and every Unicode noncharacter (U+FDD0 to U+FDEF, U+FFFE, U+FFFF
// and the last two code points of every plane): a terminal may drop, join or
// mis-draw them, and nothing a human reads has a reason to carry one. The
// vault's cards mark the same set (apps/vault/src/relay/spelling.ts).
const HIDDEN_CHARS = /(?![\u0600-\u0605\u06DD\u070F\u0890\u0891\u08E2\u{110BD}\u{110CD}])\p{Cf}|[\u2028\u2029\u{E0000}]|\p{Default_Ignorable_Code_Point}|\p{Noncharacter_Code_Point}/gu

const HIDDEN_NAMES: Record<number, string> = {
  0x00ad: "SHY",
  0x061c: "ALM",
  0x180e: "MVS",
  0x200b: "ZWSP",
  0x200c: "ZWNJ",
  0x200d: "ZWJ",
  0x200e: "LRM",
  0x200f: "RLM",
  0x2028: "LS",
  0x2029: "PS",
  0x202a: "LRE",
  0x202b: "RLE",
  0x202c: "PDF",
  0x202d: "LRO",
  0x202e: "RLO",
  0x2060: "WJ",
  0x2061: "FA",
  0x2062: "IT",
  0x2063: "IS",
  0x2064: "IP",
  0x2066: "LRI",
  0x2067: "RLI",
  0x2068: "FSI",
  0x2069: "PDI",
  0x206a: "ISS",
  0x206b: "ASS",
  0x206c: "IAFS",
  0x206d: "AAFS",
  0x206e: "NADS",
  0x206f: "NODS",
  0xfeff: "BOM",
  0xfff9: "IAA",
  0xfffa: "IAS",
  0xfffb: "IAT",
  0xe0001: "LANGTAG",
  0xe007f: "CANCELTAG",
}

function hiddenName(code: number): string {
  if (code >= 0xe0020 && code <= 0xe007e) return "TAG"
  if ((code >= 0xfdd0 && code <= 0xfdef) || (code & 0xfffe) === 0xfffe) return "NONCHAR"
  if ((code >= 0xfe00 && code <= 0xfe0f) || (code >= 0xe0100 && code <= 0xe01ef)) return "VS"
  if (code === 0x115f || code === 0x1160 || code === 0x3164 || code === 0xffa0) return "HF"
  if ((code >= 0x180b && code <= 0x180d) || code === 0x180f) return "FVS"
  if (code === 0x034f) return "CGJ"
  return HIDDEN_NAMES[code] ?? "FORMAT"
}

// One text or emoji presentation selector straight after a pictograph
// ("\u2764\uFE0F"), or after a digit, "#" or "*" that a keycap follows
// ("1\uFE0F\u20E3"), only picks how that emoji is drawn, so it is left
// alone, as on the vault's cards. Any other variation selector draws as
// nothing.
function emojiPresentation(text: string, at: number): boolean {
  const unit = text.charCodeAt(at)
  if (unit !== 0xfe0e && unit !== 0xfe0f) return false
  const before = text.slice(Math.max(0, at - 2), at)
  return /\p{Extended_Pictographic}$/u.test(before) || (/[0-9#*]$/.test(before) && text.charCodeAt(at + 1) === 0x20e3)
}

// Text that may have been written by an agent or an upstream (a rule path, a
// note, a summary, a message), made safe to print: every control character
// becomes \u00XX and every hidden or reordering character a [NAME U+XXXX]
// marker, the same spelling the approval card uses, so nothing in it can move
// the cursor, recolour the line or hide part of itself.
export function visibleText(text: string): string {
  return text
    .replace(HIDDEN_CHARS, (c, at: number) => {
      if (emojiPresentation(text, at)) return c
      const code = c.codePointAt(0) as number
      return `[${hiddenName(code)} U+${code.toString(16).toUpperCase().padStart(4, "0")}]`
    })
    .replace(CONTROL_CHARS, (c) => `\\u${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}`)
}

export function terminalColumns(stream: TtyStream): number | null {
  return isTty(stream) && typeof stream.columns === "number" && stream.columns > 0 ? stream.columns : null
}

// ---------------------------------------------------------------- QR codes

export type QrChoice = { scheme: QrScheme } | null

// Dark unless the terminal says otherwise. MEHEN_QR=light or MEHEN_QR=dark wins;
// then COLORFGBG ("fg;bg", set by some terminals), whose background 7 or 9
// and above is a light theme; otherwise dark.
export function qrScheme(env: Env): QrScheme {
  const override = env.MEHEN_QR?.trim().toLowerCase()
  if (override === "light" || override === "dark") return override
  const fgbg = env.COLORFGBG
  if (fgbg) {
    const bg = Number(fgbg.split(";").at(-1))
    if (Number.isInteger(bg) && (bg === 7 || bg >= 9)) return "light"
  }
  return "dark"
}

// The columns a rendered code takes: the modules plus the quiet zone on both
// sides, as renderQr draws it.
export function qrWidth(text: string): number {
  return qrMatrix(text).length + 2 * QR_QUIET_ZONE
}

export type QrOptions = { noQr?: boolean; indent?: number }

// Whether a QR code for `text` should be drawn on `stream`: a TTY, wide
// enough, MEHEN_QR not "0", and no --no-qr. Returns the scheme to draw with.
export function qrChoice(stream: TtyStream, env: Env, text: string, options: QrOptions = {}): QrChoice {
  if (options.noQr || !isTty(stream)) return null
  if (env.MEHEN_QR?.trim() === "0") return null
  const columns = terminalColumns(stream)
  if (columns === null) return null
  let width: number
  try {
    width = qrWidth(text)
  } catch {
    return null
  }
  if (columns < width + (options.indent ?? 0)) return null
  return { scheme: qrScheme(env) }
}
