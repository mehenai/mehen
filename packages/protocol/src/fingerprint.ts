// The fingerprint a human compares when approving a machine (// UX-VAULT-WEB 2.3a). One derivation here, used by the CLI, the server and
// the enrol page, so they can never disagree.
//
// Input is the key's RFC 7638 thumbprint (jwkThumbprint in proof.ts):
// base64url of SHA-256, 43 characters for 32 bytes. The glyphs encode its
// first 10 bytes (80 bits) in Crockford base32, an alphabet without I, L, O
// or U, so nothing on the page or in a terminal font can be misread as a
// different character. The words (fingerprintWords) encode bytes 10 to 15,
// so a word never repeats information a glyph group already shows.
//
// Enrolment hides one of the four groups on the page and asks the human to
// type it from the terminal. fingerprintGroupIndex says which group, from
// the enrolment code; fingerprintGroupCheck is the hash the page compares the
// typed group against so it can enable Approve, keyed by the ref the page was
// opened with (the code, or the enrolment id). Both are conveniences for
// the page: the server checks the typed group against the stored thumbprint
// when it approves.

import { type Bytes, base64UrlDecode, base64UrlEncode, sha256B64 } from "./bytes.ts"
import { FINGERPRINT_COLOURS, FINGERPRINT_WORDS, type FingerprintColour } from "./fingerprint-words.ts"

export const FINGERPRINT_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
export const FINGERPRINT_GROUPS = 4
export const FINGERPRINT_GROUP_LENGTH = 4

const THUMBPRINT_BYTES = 32
const GLYPH_BYTES = 10
const WORD_BYTES_FROM = GLYPH_BYTES
const GROUP_PATTERN = /^[0-9A-HJKMNP-TV-Z]{4}$/
const FINGERPRINT_PATTERN = /^[0-9A-HJKMNP-TV-Z]{4}( [0-9A-HJKMNP-TV-Z]{4}){3}$/

export type FingerprintGroupIndex = 0 | 1 | 2 | 3
export type FingerprintGroups = [string, string, string, string]
export type FingerprintWord = { word: string; colour: FingerprintColour }

function thumbprintBytes(thumbprint: string): Bytes {
  let bytes: Bytes
  try {
    bytes = base64UrlDecode(thumbprint)
  } catch {
    throw new Error("A key thumbprint is base64url text (RFC 7638); this value is not.")
  }
  if (bytes.length !== THUMBPRINT_BYTES) {
    throw new Error(`A key thumbprint is SHA-256, ${THUMBPRINT_BYTES} bytes; this value decodes to ${bytes.length}.`)
  }
  // Padding characters and non-zero pad bits decode to the same bytes as the
  // canonical form; a thumbprint is the one string jwkThumbprint produces.
  if (base64UrlEncode(bytes) !== thumbprint) {
    throw new Error("A key thumbprint is canonical base64url without padding; this value is not.")
  }
  return bytes
}

function crockford(bytes: Uint8Array): string {
  let out = ""
  let buffer = 0
  let bits = 0
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += FINGERPRINT_ALPHABET[(buffer >> bits) & 31]
    }
    buffer &= (1 << bits) - 1
  }
  return out
}

// "K7Q2 MX4D 9RTV 3HNB": the first 80 bits of the thumbprint, four groups.
export function fingerprintOf(thumbprint: string): string {
  const glyphs = crockford(thumbprintBytes(thumbprint).subarray(0, GLYPH_BYTES))
  return (glyphs.match(/.{4}/g) ?? []).join(" ")
}

export function isFingerprint(value: string): boolean {
  return FINGERPRINT_PATTERN.test(value)
}

export function fingerprintGroups(fp: string): FingerprintGroups {
  if (!FINGERPRINT_PATTERN.test(fp)) {
    throw new Error("A fingerprint is four groups of four characters from the Crockford alphabet, separated by single spaces.")
  }
  return fp.split(" ") as FingerprintGroups
}

// What a human typed, as the group it names, or undefined when it cannot be
// one. Crockford decoding rules: I and L read as 1, O as 0, case is ignored,
// spaces and hyphens are dropped. U is not in the alphabet and is refused
// rather than guessed at.
export function normaliseFingerprintGroup(input: string): string | undefined {
  const group = input.trim().replaceAll(/[\s-]/g, "").toUpperCase().replaceAll(/[IL]/g, "1").replaceAll("O", "0")
  return GROUP_PATTERN.test(group) ? group : undefined
}

function canonicalEnrolmentCode(enrolmentCode: string): string {
  const code = enrolmentCode.trim().replaceAll(/[\s-]/g, "").toUpperCase()
  if (code.length === 0) throw new Error("An enrolment code is needed to pick the hidden fingerprint group.")
  return code
}

// Which group the enrol page hides. Stable for a link, uniform over the four
// values, and not a function of anything the page shows.
export async function fingerprintGroupIndex(enrolmentCode: string): Promise<FingerprintGroupIndex> {
  const digest = base64UrlDecode(await sha256B64(`mehen-fp-group-index\u0000${canonicalEnrolmentCode(enrolmentCode)}`))
  return ((digest[0] ?? 0) & 3) as FingerprintGroupIndex
}

// base64url SHA-256 over "mehen-fp-group", the page's ref (the code or the
// enrolment id) and the normalised group, NUL-separated. The boot payload
// carries the value for the hidden group; the browser compares what was
// typed against it before the passkey prompt.
export async function fingerprintGroupCheck(ref: string, group: string): Promise<string> {
  const normalised = normaliseFingerprintGroup(group)
  if (normalised === undefined) {
    throw new Error("A fingerprint group is four characters from the Crockford alphabet (no U).")
  }
  return sha256B64(`mehen-fp-group\u0000${canonicalEnrolmentCode(ref)}\u0000${normalised}`)
}

// Four words and colours from bytes 10 to 15 of the thumbprint: a byte per
// word, a nibble per colour. An aid to a quick look; the glyphs are the check.
export function fingerprintWords(thumbprint: string): FingerprintWord[] {
  const bytes = thumbprintBytes(thumbprint)
  const words: FingerprintWord[] = []
  for (let i = 0; i < FINGERPRINT_GROUPS; i++) {
    const wordByte = bytes[WORD_BYTES_FROM + i] ?? 0
    const colourByte = bytes[WORD_BYTES_FROM + FINGERPRINT_GROUPS + (i >> 1)] ?? 0
    const nibble = i % 2 === 0 ? colourByte >> 4 : colourByte & 15
    words.push({ word: FINGERPRINT_WORDS[wordByte] as string, colour: FINGERPRINT_COLOURS[nibble] as FingerprintColour })
  }
  return words
}
