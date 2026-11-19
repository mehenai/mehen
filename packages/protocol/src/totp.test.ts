import { describe, expect, test } from "bun:test"
import { fromUtf8 } from "./bytes.ts"
import { base32Decode, parseTotp, totpCode, type Totp } from "./totp.ts"

const SEED_SHA1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
const SEED_SHA256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA===="
const SEED_SHA512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA="

function parsed(seed: string): Totp {
  const result = parseTotp(seed)
  if (!result.ok) throw new Error(result.reason)
  return result.totp
}

describe("base32 (RFC 4648 section 10)", () => {
  test("the standard vectors decode", () => {
    for (const [encoded, plain] of [["", ""], ["MY======", "f"], ["MZXQ====", "fo"], ["MZXW6===", "foo"], ["MZXW6YQ=", "foob"], ["MZXW6YTB", "fooba"], ["MZXW6YTBOI======", "foobar"]] as const) {
      const bytes = base32Decode(encoded)
      expect({ encoded, plain: bytes && fromUtf8(bytes) }).toEqual({ encoded, plain })
    }
  })

  test("lower case, spaces and missing padding read as authenticator apps write them", () => {
    expect(fromUtf8(base32Decode("mzxw 6ytb oi")!)).toBe("foobar")
  })

  test("characters outside the alphabet, padding in the middle and impossible lengths are refused", () => {
    for (const encoded of ["MZXW1YTB", "MZXW6YT8", "MZ=XW6YTB", "MZXW6YTBO", "M", "MZX"]) expect({ encoded, bytes: base32Decode(encoded) }).toEqual({ encoded, bytes: null })
  })
})

describe("parseTotp", () => {
  test("a bare secret is SHA-1, 6 digits, every 30 seconds", () => {
    expect(parsed("JBSWY3DPEHPK3PXP")).toMatchObject({ algorithm: "SHA-1", digits: 6, period: 30 })
  })

  test("an otpauth link names its algorithm, digits and period", () => {
    expect(parsed(`otpauth://totp/Example:alex@example.com?secret=${SEED_SHA512.replace(/=/g, "")}&issuer=Example&algorithm=SHA512&digits=8&period=60`)).toMatchObject({ algorithm: "SHA-512", digits: 8, period: 60 })
    expect(parsed("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP")).toMatchObject({ algorithm: "SHA-1", digits: 6, period: 30 })
    expect(parsed("OTPAUTH://TOTP/Example?secret=JBSWY3DPEHPK3PXP&algorithm=sha256")).toMatchObject({ algorithm: "SHA-256" })
  })

  test("refuses counters, Steam codes, short secrets and anything out of range", () => {
    for (const [seed, reason] of [
      ["otpauth://hotp/Example?secret=JBSWY3DPEHPK3PXP&counter=0", "counter"],
      ["otpauth://totp/Steam?secret=JBSWY3DPEHPK3PXP&encoder=steam", "Steam"],
      ["JBSWY3DP", "80 bits"],
      ["otpauth://totp/Example?secret=JBSWY3DP", "80 bits"],
      ["otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", "algorithm"],
      ["otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=5", "digits"],
      ["otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=9", "digits"],
      ["otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=6.5", "digits"],
      ["otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&period=14", "period"],
      ["otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&period=121", "period"],
      ["otpauth://totp/Example?issuer=Example", "secret"],
      ["otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&secret=GEZDGNBVGY3TQOJQ", "twice"],
      ["otpauth://totp/Example?secret=not-base32!", "base32"],
      ["https://example.com/?secret=JBSWY3DPEHPK3PXP", "base32"],
      ["", "base32"],
      ["A".repeat(2000), "long"],
    ] as const) {
      const result = parseTotp(seed)
      expect({ seed: seed.slice(0, 60), ok: result.ok }).toEqual({ seed: seed.slice(0, 60), ok: false })
      if (!result.ok) expect(result.reason).toContain(reason)
    }
  })
})

describe("totpCode (RFC 6238 Appendix B)", () => {
  const vectors: [number, string, string, string][] = [
    [59, "94287082", "46119246", "90693936"],
    [1111111109, "07081804", "68084774", "25091201"],
    [1111111111, "14050471", "67062674", "99943326"],
    [1234567890, "89005924", "91819424", "93441116"],
    [2000000000, "69279037", "90698825", "38618901"],
    [20000000000, "65353130", "77737706", "47863826"],
  ]
  test("SHA-1, SHA-256 and SHA-512, 8 digits", async () => {
    const totps = [["SHA1", SEED_SHA1], ["SHA256", SEED_SHA256], ["SHA512", SEED_SHA512]].map(([algorithm, seed]) => parsed(`otpauth://totp/RFC?secret=${seed!.replace(/=/g, "")}&algorithm=${algorithm}&digits=8`))
    for (const [seconds, ...codes] of vectors)
      for (const [n, totp] of totps.entries()) expect({ seconds, algorithm: totp.algorithm, code: (await totpCode(totp, seconds * 1000)).code }).toEqual({ seconds, algorithm: totp.algorithm, code: codes[n]! })
  })

  test("the step and when its code stops being valid come from the given clock", async () => {
    expect(await totpCode(parsed(SEED_SHA1), 59_000)).toEqual({ code: "287082", step: 1, validUntilMs: 60_000 })
    expect(await totpCode(parsed(SEED_SHA1), 60_000)).toMatchObject({ step: 2, validUntilMs: 90_000 })
    expect((await totpCode(parsed(`otpauth://totp/x?secret=${SEED_SHA1}&period=60`), 59_999)).validUntilMs).toBe(60_000)
  })
})
