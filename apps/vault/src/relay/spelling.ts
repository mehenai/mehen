// Spelling hidden characters out for a human: every deceptive (format,
// bidirectional, invisible) character as a [RLO U+202E] marker and every
// control character as \u00XX. Pure text in, text or segments out, with no
// other import, so the browser bundle (the command palette) spells with
// byte-identical rules to the server's cards. presentation.ts re-exports
// everything here; h7-deceptive pins the behaviour.

// Characters that make text render in a different order from how it is
// sent (bidirectional overrides and isolates) or render as nothing at all:
// every Unicode format character (general category Cf) except the Arabic,
// Syriac and Kaithi signs that render as a visible mark over the text
// after them, plus the line and paragraph separators, which a browser
// shows as a line break or as nothing, U+E0000, the unassigned first
// slot of the tag block, which \p{Cf} leaves out, and every other default
// ignorable code point (variation selectors, Hangul fillers, the combining
// grapheme joiner), which a browser draws as nothing. The card shows each one
// as a marker naming it, [RLO U+202E], where it sits.
const DECEPTIVES = /(?![\u0600-\u0605\u06DD\u070F\u0890\u0891\u08E2\u{110BD}\u{110CD}])\p{Cf}|[\u2028\u2029\u{E0000}]|\p{Default_Ignorable_Code_Point}/gu
export const DECEPTIVE_WARNING =
  "This request contains hidden text-direction or invisible characters, each marked where it sits (for example [RLO U+202E]). What you read may not be what is sent. Deny it unless you know why they are there."

// The Unicode abbreviations for the markers; anything else in the class is FORMAT.
const DECEPTIVE_NAMES: Record<number, string> = {
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

function deceptiveName(code: number): string {
  if (code >= 0xe0020 && code <= 0xe007e) return "TAG"
  if ((code >= 0xfe00 && code <= 0xfe0f) || (code >= 0xe0100 && code <= 0xe01ef)) return "VS"
  if (code === 0x115f || code === 0x1160 || code === 0x3164 || code === 0xffa0) return "HF"
  if ((code >= 0x180b && code <= 0x180d) || code === 0x180f) return "FVS"
  if (code === 0x034f) return "CGJ"
  return DECEPTIVE_NAMES[code] ?? "FORMAT"
}

// One text or emoji presentation selector straight after a pictograph
// ("\u2764\uFE0F"), or after a digit, "#" or "*" that a keycap follows
// ("1\uFE0F\u20E3"), only picks how that emoji is drawn, so it is left
// alone. Any other variation selector, a second one or one after a bare
// digit included, draws as nothing.
function emojiPresentation(text: string, at: number): boolean {
  const unit = text.charCodeAt(at)
  if (unit !== 0xfe0e && unit !== 0xfe0f) return false
  const before = text.slice(Math.max(0, at - 2), at)
  return /\p{Extended_Pictographic}$/u.test(before) || (/[0-9#*]$/.test(before) && text.charCodeAt(at + 1) === 0x20e3)
}

function hasDeceptive(text: string): boolean {
  for (const match of text.matchAll(DECEPTIVES)) if (!emojiPresentation(text, match.index)) return true
  return false
}

// What a marker looks like, so a page can style it. A marker is plain text
// and is escaped like any other text, never markup.
export const DECEPTIVE_MARKER = /\[[A-Z]+ U\+[0-9A-F]{4,6}\]/

// Each deceptive character replaced by its marker: "pay\u202Eexe.fdp" is
// shown as "pay[RLO U+202E]exe.fdp". A zero-width joiner inside an emoji
// sequence (a family, a profession) is marked too: the card cannot tell a
// joiner that builds an emoji from one placed between two pictographs to
// carry text past a reader without emoji data that differs by renderer,
// and an exemption would be the one invisible character an attacker may
// place freely. The marker between two emoji still reads as those emoji,
// and "unless you know why they are there" covers it.
export function spellDeceptive(text: string): string {
  return text.replace(DECEPTIVES, (c, at: number) => {
    if (emojiPresentation(text, at)) return c
    const code = c.codePointAt(0) as number
    return `[${deceptiveName(code)} U+${code.toString(16).toUpperCase().padStart(4, "0")}]`
  })
}

// JSON for an HTML attribute with every deceptive character as a \uXXXX
// escape (two for a character outside the BMP), so the page source reads
// in the order it is written. The parsed value is unchanged.
export function escapeDeceptiveJson(json: string): string {
  return json.replace(DECEPTIVES, (c, at: number) => (emojiPresentation(json, at) ? c : c.split("").map(escapeUnit).join("")))
}

function escapeUnit(unit: string): string {
  return `\\u${unit.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}`
}

// C0 control characters other than tab and line feed, DEL, the C1 control
// characters, and a carriage return that does not end a line: browsers drop
// or reflow them, so the card spells each one out as \u00XX. The digest
// still covers the bytes.
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]|\r(?!\n)/
const CONTROLS = new RegExp(CONTROL.source, "g")
export const CONTROL_WARNING =
  "This request contains control characters, which the card shows as \\u00XX (for example \\u0000 or \\u000D). Deny it unless you know why they are there."

export function spellControls(text: string): string {
  return text.replace(CONTROLS, escapeUnit)
}

// One line for an operator's terminal (the scripts under scripts/), as the
// CLI's visibleText spells one: deceptive characters marked, and every C0
// and C1 control character, tab and line feed included, spelled as
// \u00XX, so text in it cannot move the cursor, recolour, hide or end the
// line.
const TERMINAL_CONTROLS = /[\u0000-\u001F\u007F-\u009F]/g

export function spellTerminalLine(text: string): string {
  return spellDeceptive(text).replace(TERMINAL_CONTROLS, escapeUnit)
}

// Every string a human reads on a card goes through this: controls spelled
// as \u00XX, deceptive characters as [RLO U+202E] markers. Display only;
// every digest is over the request as sent. What to mark is decided on the
// text as sent, as textWarnings decides, so a spelled control ("\u0001"
// ends in a digit) cannot change it.
export function spellCardText(text: string): string {
  return spellCardSegments(text)
    .map((segment) => segment.text)
    .join("")
}

// The same spelling as spellCardText, returned as segments so a page can
// style the markers the vault generated without ever matching marker-shaped
// text in the input: a "[RLO U+202E]" an attacker typed is in a `text`
// segment and stays plain. Controls are spelled into the text segments;
// only deceptive characters become `marker` segments. Given a range, only
// text[start, end) is spelled, with what to mark still decided on the whole
// text, so a slice cut between a keycap digit and its selector marks nothing
// the whole text leaves alone.
export type CardTextSegment = { kind: "text" | "marker"; text: string }

export function spellCardSegments(text: string, start = 0, end = text.length): CardTextSegment[] {
  const out: CardTextSegment[] = []
  let from = start
  const push = (kind: CardTextSegment["kind"], value: string) => {
    if (value === "") return
    const last = out[out.length - 1]
    if (last && last.kind === kind && kind === "text") last.text += value
    else out.push({ kind, text: value })
  }
  for (const match of text.matchAll(DECEPTIVES)) {
    if (match.index < start || match.index >= end || emojiPresentation(text, match.index)) continue
    push("text", spellControls(text.slice(from, match.index)))
    push("marker", spellDeceptive(match[0]))
    from = match.index + match[0].length
  }
  push("text", spellControls(text.slice(from, end)))
  return out
}

// The warnings a set of card strings earns. The approval page also runs the
// fields it renders outside the presentation (who asked, the account, the
// request line) through this, so no rendered text escapes the check.
export function textWarnings(texts: readonly string[]): string[] {
  const out: string[] = []
  if (texts.some(hasDeceptive)) out.push(DECEPTIVE_WARNING)
  if (texts.some((t) => CONTROL.test(t))) out.push(CONTROL_WARNING)
  return out
}
