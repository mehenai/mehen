// Recovery codes: 15 random symbols from the Crockford
// alphabet the fingerprints use (no I, L, O or U), 75 bits, plus one Luhn
// mod 32 check symbol, shown as four groups of four: "7KQ2-M9XD-4TRW-HN3P".
// The vault stores only SHA-256 over recoveryCodeHashInput, so at 75 bits a
// leaked hash cannot be searched back to its code.
//
// The check symbol catches every single-symbol mistake and every adjacent
// swap except 0 with Z, the one pair Luhn mod 32 cannot tell apart. A failed
// check is a typo, never a guess, so the vault does not count it as one.

import { FINGERPRINT_ALPHABET } from "./fingerprint.ts"

export const RECOVERY_CODE_COUNT = 10
export const RECOVERY_CODE_SYMBOLS = 16 // 15 random, 1 check

const RANDOM_SYMBOLS = RECOVERY_CODE_SYMBOLS - 1
const BASE = FINGERPRINT_ALPHABET.length
const GROUP = 4
const MAX_INPUT = 64
const CODE_PATTERN = /^[0-9A-HJKMNP-TV-Z]{16}$/

function valueOf(symbol: string): number {
  return FINGERPRINT_ALPHABET.indexOf(symbol)
}

// Luhn mod 32 over the data symbols: from the rightmost, every second value
// starting with that one is doubled and folded back into one symbol's range.
function checkValue(data: string): number {
  let sum = 0
  let double = true
  for (let i = data.length - 1; i >= 0; i--) {
    let v = valueOf(data[i] as string)
    if (double) {
      v *= 2
      v = Math.floor(v / BASE) + (v % BASE)
    }
    sum += v
    double = !double
  }
  return (BASE - (sum % BASE)) % BASE
}

export function formatRecoveryCode(code: string): string {
  if (!CODE_PATTERN.test(code)) throw new Error("A recovery code is 16 symbols from the Crockford alphabet.")
  return (code.match(/.{4}/g) ?? []).join("-")
}

// 32 symbols is exactly 5 bits, so masking each random byte to 5 bits keeps
// every symbol equally likely.
export function generateRecoveryCode(): string {
  const random = crypto.getRandomValues(new Uint8Array(RANDOM_SYMBOLS))
  let data = ""
  for (const byte of random) data += FINGERPRINT_ALPHABET[byte & (BASE - 1)]
  return formatRecoveryCode(data + FINGERPRINT_ALPHABET[checkValue(data)])
}

// The 16 symbols, or why not: "typo" when the check symbol fails, "shape"
// otherwise. Case, spaces and hyphens do not matter; I and L read as 1 and O
// as 0, as Crockford base32 intends; U and anything else are refused.
export function normaliseRecoveryCode(input: string): { ok: true; code: string } | { ok: false; reason: "shape" | "typo" } {
  if (input.length > MAX_INPUT) return { ok: false, reason: "shape" }
  const code = input
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/[IL]/g, "1")
    .replace(/O/g, "0")
  if (!CODE_PATTERN.test(code)) return { ok: false, reason: "shape" }
  const data = code.slice(0, RANDOM_SYMBOLS)
  if (FINGERPRINT_ALPHABET[checkValue(data)] !== code[RANDOM_SYMBOLS]) return { ok: false, reason: "typo" }
  return { ok: true, code }
}

// What the vault hashes: the normalised symbols under a domain prefix, so a
// recovery code hash can never collide with any other hash the vault keeps.
export function recoveryCodeHashInput(code: string): string {
  if (!CODE_PATTERN.test(code)) throw new Error("Normalise a recovery code before hashing it.")
  return `mehen-recovery/v1\n${code}`
}
