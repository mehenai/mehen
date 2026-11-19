// Output redaction for anything a secret might be echoed into: a leased
// subprocess's stdout and stderr, an upstream response relayed back to an
// agent. Streaming and chunk-boundary safe.
//
// Honest limits, stated wherever this is used: redaction catches a value
// printed as is or in the common encodings below. It cannot catch a value
// that a program transforms (reversed, split, hashed, encrypted, sent one
// character per line). That is why lease mode is opt-in and placeholder or
// relay mode, where the value never reaches the machine, is the default.

export type RedactionSecret = { label: string; value: string }

// pattern is global; shortest and longest are the fewest and most
// characters one match can span; partialAt says whether the text from a
// position to its end is the start of a match cut short, which more text
// could complete.
type Needle = { pattern: RegExp; shortest: number; longest: number; replacement: string; partialAt: (text: string, at: number) => boolean }

// A shorter value is never scrubbed: it would match ordinary text.
export const MIN_SECRET_LENGTH = 6

function base64(text: string, url: boolean): string {
  const bytes = new TextEncoder().encode(text)
  let binary = ""
  for (const b of bytes) binary += String.fromCharCode(b)
  const b64 = btoa(binary)
  return url ? b64.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "") : b64.replace(/=+$/, "")
}

function hex4(unit: string): string {
  return unit.charCodeAt(0).toString(16).padStart(4, "0")
}

// Text as a regular expression matching it exactly, one UTF-16 unit at a
// time (the patterns carry no u flag).
function literalPattern(text: string): string {
  return text
    .split("")
    .map((unit) => `\\u${hex4(unit)}`)
    .join("")
}

const JSON_SHORT_ESCAPES: Record<string, string> = { '"': '\\"', "\\": "\\\\", "/": "\\/", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t" }

// The value inside a JSON string however an encoder chose to write it: each
// UTF-16 unit as itself, as a \u escape in either hex case, or as its short
// escape (\" \\ \/ \n and the rest). Encoders differ in which characters
// they escape (Gson "=", .NET "+" in upper case, PHP "/", Go "<"), so no
// list of spellings reaches them all. A " or \ or control character is never
// left bare inside a JSON string, so those units have no bare alternative,
// and then every alternative of a unit starts differently (the unit, or "\"
// and a different second character): a match never backtracks. Trying one
// start costs at most the length of the partial match there, so the worst
// case is text × secret, for a secret that repeats itself ("aaaa...") in
// text that does too. One match spans at most 6 characters per unit.
function jsonPattern(value: string): string {
  return value
    .split("")
    .map((unit) => {
      const hex = [...hex4(unit)].map((d) => (/[a-f]/.test(d) ? `[${d}${d.toUpperCase()}]` : d)).join("")
      const alternatives = [`\\\\u${hex}`]
      const short = JSON_SHORT_ESCAPES[unit]
      if (short !== undefined) alternatives.push(literalPattern(short))
      if (unit.charCodeAt(0) >= 0x20 && unit !== '"' && unit !== "\\") alternatives.push(literalPattern(unit))
      return `(?:${alternatives.join("|")})`
    })
    .join("")
}

function literalPartialAt(literal: string): Needle["partialAt"] {
  return (text, at) => {
    if (text.length - at >= literal.length) return false
    for (let i = 0; at + i < text.length; i++) if (text.charCodeAt(at + i) !== literal.charCodeAt(i)) return false
    return true
  }
}

// One character of the value as a percent-encoder may write it: bare, or as
// the %XX escape of each of its UTF-8 bytes (kept in upper case here; RFC
// 3986 makes %2f and %2F the same octet, so either case matches each hex
// digit), and a space also as "+". Encoders differ in which characters
// they escape (of !'()*~, encodeURIComponent escapes none, URLSearchParams
// all but *, PHP's rawurlencode all but ~; some escape every byte), so no
// list of spellings reaches them all. A lone surrogate has no UTF-8 bytes,
// so it is bare only.
type PercentChar = { bare: string; escape: string | null }

function percentChars(value: string): PercentChar[] {
  const encoder = new TextEncoder()
  return [...value].map((bare) => {
    const code = bare.charCodeAt(0)
    if (bare.length === 1 && code >= 0xd800 && code <= 0xdfff) return { bare, escape: null }
    const escape = [...encoder.encode(bare)].map((b) => `%${b.toString(16).toUpperCase().padStart(2, "0")}`).join("")
    return { bare, escape }
  })
}

// The value in any percent-encoding, each character bare or escaped
// independently. Every alternative of a character starts differently (the
// character, "%", or "+" for a space) but for a % in the value, whose escape
// %25 and bare form both start with "%". The rule there: text that reads
// %25 is the escape, and a bare % matches only where the text after it
// shows it is not %25, that is anything but "25" and not the end of the
// text or a "2" there, where more text could still complete %25. So a
// match never backtracks or grows when more text arrives, and the stream
// gives what the whole text does; a value with "%25" in it is matched with
// its own % escaped once anything else in it is, and a % that ends the value
// at the very end of the text is left to the raw needle. Trying one start
// costs at most the length of the partial match there. One match spans at
// most 3 characters per UTF-8 byte.
function percentPattern(chars: PercentChar[]): string {
  return chars
    .map(({ bare, escape }) => {
      if (escape === null) return literalPattern(bare)
      if (bare === "%") return "%(?:25|(?!25|2?$))"
      const hex = escape
        .split("")
        .map((d) => (d >= "A" && d <= "F" ? `[${d}${d.toLowerCase()}]` : d))
        .join("")
      const alternatives = [hex, literalPattern(bare)]
      if (bare === " ") alternatives.push("\\+")
      return `(?:${alternatives.join("|")})`
    })
    .join("")
}

// The percentPattern match as a forward walk, one character at a time: the
// text picks the alternative ("%" an escape, "+" a space, else the bare
// character; for a % in the value, "%25" or a bare %), so it never
// backtracks.
function percentPartialAt(chars: PercentChar[]): Needle["partialAt"] {
  return (text, at) => {
    let j = at
    for (const { bare, escape } of chars) {
      if (j >= text.length) return true
      if (bare === "%") {
        if (text[j] !== "%") return false
        const after = text.slice(j + 1, j + 3)
        if (after === "25") j += 3
        else if ("2".startsWith(after)) return true
        else j += 1
        continue
      }
      const spelling = text[j] === "%" && escape !== null ? escape : bare === " " && text[j] === "+" ? "+" : bare
      for (let k = 0; k < spelling.length; k++) {
        if (j + k >= text.length) return true
        const c = text.charCodeAt(j + k)
        const want = spelling.charCodeAt(k)
        if (c !== want && !(spelling === escape && want >= 0x41 && want <= 0x46 && c === want + 0x20)) return false
      }
      j += spelling.length
    }
    return false
  }
}

// The jsonPattern match as a forward walk, one unit at a time: at most one
// alternative of a unit can begin at a position (the unit itself, or "\"
// and the character that picks the escape), so it never backtracks.
function jsonPartialAt(value: string): Needle["partialAt"] {
  return (text, at) => {
    let j = at
    for (let i = 0; i < value.length; i++) {
      if (j >= text.length) return true
      const unit = value.charCodeAt(i)
      if (text.charCodeAt(j) !== 0x5c) {
        if (text.charCodeAt(j) !== unit || unit < 0x20 || unit === 0x22) return false
        j += 1
      } else if (text[j + 1] === "u") {
        const hex = hex4(value[i] as string)
        for (let k = 0; k < 4 && j + 2 + k < text.length; k++) {
          const c = text.charCodeAt(j + 2 + k)
          const want = hex.charCodeAt(k)
          if (c !== want && !(want >= 0x61 && c === want - 0x20)) return false
        }
        j += 6
      } else {
        if (j + 1 < text.length && JSON_SHORT_ESCAPES[value[i] as string] !== `\\${text[j + 1]}`) return false
        j += 2
      }
    }
    return j > text.length
  }
}

// The value as is and each base64 spelling of it.
function variants(value: string): string[] {
  const out = new Set([value])
  // Base64 of the value at each of the three alignments it can appear in
  // inside a longer encoded string (for example "user:pass" in Basic auth),
  // trimmed to the characters that do not depend on the neighbours.
  for (const pad of ["", "a", "aa"]) {
    for (const url of [false, true]) {
      const encoded = base64(pad + value, url)
      const skip = pad.length === 0 ? 0 : pad.length + 1
      const trimmed = encoded.slice(skip, encoded.length - 3)
      if (trimmed.length >= 8) out.add(trimmed)
    }
  }
  return [...out].filter((v) => v.length >= MIN_SECRET_LENGTH)
}

export function buildNeedles(secrets: RedactionSecret[]): Needle[] {
  const needles: Needle[] = []
  for (const secret of secrets) {
    if (secret.value.length < MIN_SECRET_LENGTH) continue
    const replacement = `[redacted:${secret.label}]`
    // The percent needle goes first among those of equal shortest: it may
    // match on past where the others stop (a value ending in % as %25).
    const chars = percentChars(secret.value)
    const percentLongest = chars.reduce((n, { bare, escape }) => n + (escape ?? bare).length, 0)
    needles.push({ pattern: new RegExp(percentPattern(chars), "g"), shortest: secret.value.length, longest: percentLongest, replacement, partialAt: percentPartialAt(chars) })
    needles.push({ pattern: new RegExp(jsonPattern(secret.value), "g"), shortest: secret.value.length, longest: 6 * secret.value.length, replacement, partialAt: jsonPartialAt(secret.value) })
    for (const text of variants(secret.value)) needles.push({ pattern: new RegExp(literalPattern(text), "g"), shortest: text.length, longest: text.length, replacement, partialAt: literalPartialAt(text) })
  }
  // A secret inside another (a password inside a connection URL) must not be
  // replaced first and break up the other's encoded form, so needles run
  // longest first by the fewest characters a match can be.
  return needles.sort((a, b) => b.shortest - a.shortest)
}

export function redactText(text: string, needles: Needle[]): string {
  let out = text
  for (const needle of needles) out = out.replace(needle.pattern, () => needle.replacement)
  return out
}

// Where each boundary of a partly redacted text falls in the text before
// any redaction (-1 inside a replaced stretch), from one boundary up to
// another; null origin means the text is still unredacted.
function boundaries(origin: Int32Array | null, from: number, to: number): Int32Array {
  if (origin !== null) return origin.subarray(from, to)
  const out = new Int32Array(to - from)
  for (let i = 0; i < out.length; i++) out[i] = from + i
  return out
}

// A redactor for a text stream. It keeps the unredacted end of the stream
// until more arrives, so a secret split across two writes is still caught,
// and releases exactly what redacting the whole stream would show up to
// some point. Each needle in turn, in redactText's order, settles its
// replacements on the part of the text the needles before it settled, up
// to the earliest position where a match of it could start and is cut short
// by the end of that part: so text that cannot start a secret (a log line
// ending in a newline) is not held, and a secret inside another is not
// replaced while the other could still be completed around it. The cut
// never falls inside a replacement or a surrogate pair. Call end() to
// flush. The hold is at most the sum, over the needles whose partial
// matches chain at the end, of each one's longest match less one: 9 per
// UTF-16 unit of a secret for its percent-encoded form (a character outside
// ASCII), 6 for its JSON form. A secret's own needles can chain, so even one
// secret can hold back more than its longest needle. Like the
// redaction itself, each position tried costs at most the length of the
// partial match there.
export class StreamRedactor {
  private carry = ""

  constructor(private readonly needles: Needle[]) {}

  push(chunk: string): string {
    if (this.needles.length === 0) return chunk
    const raw = this.carry + chunk
    let text = raw
    let origin = null as Int32Array | null
    for (const needle of this.needles) {
      const matches = [...text.matchAll(needle.pattern)].map((m) => ({ start: m.index, end: m.index + m[0].length }))
      let cut = text.length
      let next = 0
      for (let at = Math.max(0, text.length - needle.longest + 1); at < text.length; at++) {
        while (next < matches.length && (matches[next]?.end ?? 0) <= at) next++
        const match = matches[next]
        if (match !== undefined && match.start <= at) at = match.end - 1
        else if (needle.partialAt(text, at)) {
          cut = at
          break
        }
      }
      for (;;) {
        const inside = matches.find((m) => m.start < cut && cut < m.end)
        if (inside !== undefined) cut = inside.start
        else if (origin !== null && origin[cut] === -1) cut -= 1
        else break
      }
      const kept = matches.filter((m) => m.start < cut)
      if (kept.length === 0) {
        text = text.slice(0, cut)
        origin = origin?.subarray(0, cut + 1) ?? null
        continue
      }
      const marker = needle.replacement.length
      const settled = new Int32Array(kept.reduce((n, m) => n + marker - (m.end - m.start), cut) + 1)
      let out = ""
      let from = 0
      for (const m of kept) {
        settled.set(boundaries(origin, from, m.start + 1), out.length)
        out += text.slice(from, m.start)
        settled.fill(-1, out.length + 1, out.length + marker)
        out += needle.replacement
        from = m.end
      }
      settled.set(boundaries(origin, from, cut + 1), out.length)
      text = out + text.slice(from, cut)
      origin = settled
    }
    let cut = text.length
    const code = text.charCodeAt(cut - 1)
    if (code >= 0xd800 && code <= 0xdbff) cut -= 1
    while (origin !== null && origin[cut] === -1) cut -= 1
    this.carry = raw.slice(origin === null ? cut : origin[cut])
    return text.slice(0, cut)
  }

  end(): string {
    const rest = redactText(this.carry, this.needles)
    this.carry = ""
    return rest
  }
}
