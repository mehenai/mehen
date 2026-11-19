import { describe, expect, spyOn, test } from "bun:test"
import { FINGERPRINT_ALPHABET } from "./fingerprint.ts"
import {
  RECOVERY_CODE_COUNT,
  RECOVERY_CODE_SYMBOLS,
  formatRecoveryCode,
  generateRecoveryCode,
  normaliseRecoveryCode,
  recoveryCodeHashInput,
} from "./recovery-code.ts"

const FORMATTED = /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$/

function bare(code: string): string {
  return code.replaceAll("-", "")
}

function valid(code: string): boolean {
  return normaliseRecoveryCode(code).ok
}

describe("recovery codes", () => {
  test("generates 16 symbols in four groups", () => {
    expect(RECOVERY_CODE_COUNT).toBe(10)
    expect(RECOVERY_CODE_SYMBOLS).toBe(16)
    const seen = new Set<string>()
    for (let i = 0; i < 200; i++) {
      const code = generateRecoveryCode()
      expect(code).toMatch(FORMATTED)
      expect(bare(code)).toHaveLength(16)
      expect(normaliseRecoveryCode(code)).toEqual({ ok: true, code: bare(code) })
      seen.add(code)
    }
    expect(seen.size).toBe(200)
  })

  test("draws 15 symbols from crypto.getRandomValues and nothing else", () => {
    const spy = spyOn(crypto, "getRandomValues")
    try {
      const random = spyOn(Math, "random")
      generateRecoveryCode()
      expect(random).not.toHaveBeenCalled()
      random.mockRestore()
      expect(spy).toHaveBeenCalledTimes(1)
      expect((spy.mock.calls[0]?.[0] as Uint8Array).length).toBe(15)
    } finally {
      spy.mockRestore()
    }
  })

  test("every symbol value is used, so 5 bits per symbol reach the code", () => {
    const counts = new Map<string, number>()
    for (let i = 0; i < 400; i++) for (const s of bare(generateRecoveryCode()).slice(0, 15)) counts.set(s, (counts.get(s) ?? 0) + 1)
    expect([...counts.keys()].sort().join("")).toBe([...FINGERPRINT_ALPHABET].sort().join(""))
  })

  test("every single-symbol error is caught", () => {
    for (let n = 0; n < 20; n++) {
      const code = bare(generateRecoveryCode())
      for (let i = 0; i < code.length; i++) {
        for (const s of FINGERPRINT_ALPHABET) {
          if (s === code[i]) continue
          const wrong = code.slice(0, i) + s + code.slice(i + 1)
          expect(normaliseRecoveryCode(wrong)).toEqual({ ok: false, reason: "typo" })
        }
      }
    }
  })

  test("adjacent swaps are caught, apart from 0 with Z", () => {
    for (let n = 0; n < 40; n++) {
      const code = bare(generateRecoveryCode())
      for (let i = 0; i + 1 < code.length; i++) {
        const a = code[i] as string
        const b = code[i + 1] as string
        if (a === b) continue
        const swapped = code.slice(0, i) + b + a + code.slice(i + 2)
        if ([a, b].sort().join("") === "0Z") continue
        expect(valid(swapped)).toBe(false)
      }
    }
    // A fixed code with the blind pair in it, so the exception is pinned.
    const data = "0Z0000000000000"
    const withCheck = [...FINGERPRINT_ALPHABET].map((c) => data + c).find((c) => valid(c)) as string
    expect(valid(`Z0${withCheck.slice(2)}`)).toBe(true)
  })

  test("I, L and O are read as 1, 1 and 0; U is refused", () => {
    const data = "1010K7Q2M9XD4TR"
    const code = [...FINGERPRINT_ALPHABET].map((c) => data + c).find((c) => valid(c)) as string
    const withOnes = code.replaceAll("1", "I")
    const withLs = code.replaceAll("1", "l")
    const withOs = code.replaceAll("0", "o")
    expect(normaliseRecoveryCode(withOnes)).toEqual({ ok: true, code })
    expect(normaliseRecoveryCode(withLs)).toEqual({ ok: true, code })
    expect(normaliseRecoveryCode(withOs)).toEqual({ ok: true, code })
    expect(normaliseRecoveryCode(`U${code.slice(1)}`)).toEqual({ ok: false, reason: "shape" })
  })

  test("case, spaces and hyphens do not matter; length and stray characters are a shape error", () => {
    const code = generateRecoveryCode()
    expect(normaliseRecoveryCode(code.toLowerCase())).toEqual({ ok: true, code: bare(code) })
    expect(normaliseRecoveryCode(` ${code.replaceAll("-", " ")} `)).toEqual({ ok: true, code: bare(code) })
    expect(normaliseRecoveryCode(bare(code))).toEqual({ ok: true, code: bare(code) })
    expect(normaliseRecoveryCode(bare(code).slice(0, 15))).toEqual({ ok: false, reason: "shape" })
    expect(normaliseRecoveryCode(`${bare(code)}0`)).toEqual({ ok: false, reason: "shape" })
    expect(normaliseRecoveryCode(`${code.slice(0, 4)}*${code.slice(5)}`)).toEqual({ ok: false, reason: "shape" })
    expect(normaliseRecoveryCode("")).toEqual({ ok: false, reason: "shape" })
    expect(normaliseRecoveryCode(`${code}${" ".repeat(100)}`)).toEqual({ ok: false, reason: "shape" })
  })

  test("formats and hashes only normalised codes", () => {
    const code = bare(generateRecoveryCode())
    expect(bare(formatRecoveryCode(code))).toBe(code)
    expect(recoveryCodeHashInput(code)).toBe(`mehen-recovery/v1\n${code}`)
    expect(() => recoveryCodeHashInput(formatRecoveryCode(code))).toThrow()
    expect(() => formatRecoveryCode("short")).toThrow()
  })
})
