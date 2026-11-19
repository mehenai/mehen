import { describe, expect, test } from "bun:test"
import { base64UrlDecode, base64UrlEncode, randomBytes, sha256B64 } from "./bytes.ts"
import {
  FINGERPRINT_ALPHABET,
  type FingerprintGroupIndex,
  fingerprintGroupCheck,
  fingerprintGroupIndex,
  fingerprintGroups,
  fingerprintOf,
  fingerprintWords,
  normaliseFingerprintGroup,
} from "./fingerprint.ts"
import { FINGERPRINT_COLOURS, FINGERPRINT_WORDS } from "./fingerprint-words.ts"
import { type DeviceJwk, jwkThumbprint } from "./proof.ts"

// A fixed P-256 public key. Its thumbprint, fingerprint and words are pinned
// so a change to any derivation shows up here before it reaches a page.
const KNOWN_JWK: DeviceJwk = {
  kty: "EC",
  crv: "P-256",
  x: "6tuE4IjbL0XotYW14I4zOUjfvFBmDiXXIaU6JjRAtnQ",
  y: "HWA3LrV2W6kgB-T2UebdLmCTHsRpX9K_gYlyjIyTCtM",
}
const KNOWN_THUMBPRINT = "LX-22Me3dAaszq-tcpK6ZOk5DS3wezKfqayZDEim7H4"
const KNOWN_FINGERPRINT = "5NZV DP67 PXT0 DB6E"

// Bytes 0x00 to 0x1f: the Crockford groups can be checked by hand.
const RAMP_THUMBPRINT = base64UrlEncode(Uint8Array.from({ length: 32 }, (_, i) => i))
const ONES_THUMBPRINT = base64UrlEncode(new Uint8Array(32).fill(0xff))

const CODE = "ABCD2345"
const FORBIDDEN = /[ILOU]/

// Colour names, and the materials, foods, plants and places used as colour
// names, so a word never reads as a colour next to the dot beside it.
const COLOUR_WORDS = new Set(
  `red orange yellow green blue indigo violet purple pink brown black white grey gray cyan magenta teal navy
   maroon beige cream tan khaki olive lime lemon peach plum cherry coral salmon rose ruby jade amber gold silver
   copper bronze ivory ebony pearl mint sky azure cobalt crimson scarlet lilac mauve fuchsia aqua emerald sapphire
   topaz bone sand slate charcoal mustard ochre rust sienna umber apricot honey caramel chestnut hazel mahogany
   walnut wheat straw buff taupe fawn saffron burgundy wine claret orchid lavender blush rouge garnet mulberry moss
   sage avocado steel pewter platinum brass nickel lead ink midnight coal snow milk chalk vanilla linen mocha coffee
   cocoa espresso tobacco bark mud clay brick tomato pumpkin denim grape berry raspberry cranberry strawberry
   blueberry amethyst flamingo lobster ginger cinnamon nutmeg forest pine turquoise periwinkle tangerine mango
   chocolate biscuit oatmeal carrot aubergine eggplant`.split(/\s+/),
)

function randomThumbprint(): string {
  return base64UrlEncode(randomBytes(32))
}

describe("fingerprintOf", () => {
  test("known answer: a fixed JWK gives a fixed thumbprint and fingerprint", async () => {
    expect(await jwkThumbprint(KNOWN_JWK)).toBe(KNOWN_THUMBPRINT)
    expect(fingerprintOf(KNOWN_THUMBPRINT)).toBe(KNOWN_FINGERPRINT)
  })

  test("encodes the first 80 bits as Crockford base32 in four groups of four", () => {
    expect(fingerprintOf(RAMP_THUMBPRINT)).toBe("000G 40R4 0M30 E209")
    expect(fingerprintOf(ONES_THUMBPRINT)).toBe("ZZZZ ZZZZ ZZZZ ZZZZ")
  })

  test("depends only on the first ten bytes", () => {
    const a = Uint8Array.from({ length: 32 }, (_, i) => i)
    const b = Uint8Array.from(a)
    b[10] = 0xff
    b[31] = 0xff
    expect(fingerprintOf(base64UrlEncode(b))).toBe(fingerprintOf(base64UrlEncode(a)))
    const c = Uint8Array.from(a)
    c[9] = 0x08
    expect(fingerprintOf(base64UrlEncode(c))).not.toBe(fingerprintOf(base64UrlEncode(a)))
  })

  test("never contains I, L, O or U, and is always upper case in the right shape", () => {
    expect(FINGERPRINT_ALPHABET).toHaveLength(32)
    expect(FINGERPRINT_ALPHABET).not.toMatch(FORBIDDEN)
    for (let i = 0; i < 2000; i++) {
      const fp = fingerprintOf(randomThumbprint())
      expect(fp).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}( [0-9A-HJKMNP-TV-Z]{4}){3}$/)
      expect(fp).not.toMatch(FORBIDDEN)
      expect(fp).toBe(fp.toUpperCase())
    }
  })

  test("refuses anything that is not a 32-byte base64url thumbprint", () => {
    expect(() => fingerprintOf("")).toThrow(/32 bytes/)
    expect(() => fingerprintOf("not base64url!")).toThrow(/base64url/)
    expect(() => fingerprintOf(KNOWN_THUMBPRINT.slice(0, 20))).toThrow(/32 bytes/)
    expect(() => fingerprintOf(`${KNOWN_THUMBPRINT}AAAA`)).toThrow(/32 bytes/)
    expect(() => fingerprintOf(`${KNOWN_THUMBPRINT}=`)).toThrow(/base64url/)
    expect(() => fingerprintOf(`${KNOWN_THUMBPRINT}==`)).toThrow(/base64url/)
    expect(() => fingerprintOf(`${KNOWN_THUMBPRINT.slice(0, -1)}4=`)).toThrow(/base64url/)
  })

  test("refuses a thumbprint whose base64url is not canonical, even when it decodes to the same bytes", () => {
    // 43 characters carry 258 bits for 256; the last character's two pad bits
    // must be zero. "4" is 111000; "5", "6" and "7" differ only in pad bits.
    for (const last of ["5", "6", "7"]) {
      const variant = `${KNOWN_THUMBPRINT.slice(0, -1)}${last}`
      expect(base64UrlEncode(base64UrlDecode(variant))).toBe(KNOWN_THUMBPRINT)
      expect(() => fingerprintOf(variant)).toThrow(/canonical/)
      expect(() => fingerprintWords(variant)).toThrow(/canonical/)
    }
    const ones = `${ONES_THUMBPRINT.slice(0, -1)}_`
    expect(base64UrlEncode(base64UrlDecode(ones))).toBe(ONES_THUMBPRINT)
    expect(() => fingerprintOf(ones)).toThrow(/canonical/)
  })

  test("accepts every canonical thumbprint", () => {
    for (let i = 0; i < 500; i++) {
      const thumbprint = randomThumbprint()
      expect(base64UrlEncode(base64UrlDecode(thumbprint))).toBe(thumbprint)
      expect(() => fingerprintOf(thumbprint)).not.toThrow()
    }
  })
})

describe("fingerprintGroups", () => {
  test("splits a fingerprint into its four groups", () => {
    expect(fingerprintGroups(KNOWN_FINGERPRINT)).toEqual(["5NZV", "DP67", "PXT0", "DB6E"])
  })

  test("refuses anything that is not a fingerprint", () => {
    expect(() => fingerprintGroups("5NZV DP67 PXT0")).toThrow(/four groups/)
    expect(() => fingerprintGroups("5nzv dp67 pxt0 db6e")).toThrow(/four groups/)
    expect(() => fingerprintGroups("5NZV  DP67 PXT0 DB6E")).toThrow(/four groups/)
    expect(() => fingerprintGroups("5NZV DP67 PXT0 DB6U")).toThrow(/four groups/)
  })
})

describe("normaliseFingerprintGroup", () => {
  test("accepts what a human types for a group", () => {
    expect(normaliseFingerprintGroup("5NZV")).toBe("5NZV")
    expect(normaliseFingerprintGroup("5nzv")).toBe("5NZV")
    expect(normaliseFingerprintGroup("  5nzv ")).toBe("5NZV")
    expect(normaliseFingerprintGroup("5n zv")).toBe("5NZV")
    expect(normaliseFingerprintGroup("5n-zv")).toBe("5NZV")
    expect(normaliseFingerprintGroup("5N\tZV")).toBe("5NZV")
  })

  test("reads I and L as 1 and O as 0", () => {
    expect(normaliseFingerprintGroup("lI1o")).toBe("1110")
    expect(normaliseFingerprintGroup("LIlO")).toBe("1110")
    expect(normaliseFingerprintGroup("O0oI")).toBe("0001")
  })

  test("refuses U, other characters and the wrong length", () => {
    expect(normaliseFingerprintGroup("5NZU")).toBeUndefined()
    expect(normaliseFingerprintGroup("5nzu")).toBeUndefined()
    expect(normaliseFingerprintGroup("5NZ")).toBeUndefined()
    expect(normaliseFingerprintGroup("5NZVD")).toBeUndefined()
    expect(normaliseFingerprintGroup("")).toBeUndefined()
    expect(normaliseFingerprintGroup("   ")).toBeUndefined()
    expect(normaliseFingerprintGroup("5NZ*")).toBeUndefined()
    expect(normaliseFingerprintGroup("5NZ.")).toBeUndefined()
    expect(normaliseFingerprintGroup("5NZ_")).toBeUndefined()
    expect(normaliseFingerprintGroup("5NZé")).toBeUndefined()
    expect(normaliseFingerprintGroup("5NZV DP67")).toBeUndefined()
  })

  test("every group of every fingerprint normalises to itself", () => {
    for (let i = 0; i < 500; i++) {
      for (const group of fingerprintGroups(fingerprintOf(randomThumbprint()))) {
        expect(normaliseFingerprintGroup(group)).toBe(group)
        expect(normaliseFingerprintGroup(group.toLowerCase())).toBe(group)
      }
    }
  })
})

describe("fingerprintGroupIndex", () => {
  test("is stable for a code and ignores how it was typed", async () => {
    const index = await fingerprintGroupIndex(CODE)
    expect(await fingerprintGroupIndex(CODE)).toBe(index)
    expect(await fingerprintGroupIndex("abcd2345")).toBe(index)
    expect(await fingerprintGroupIndex(" abcd-2345 ")).toBe(index)
  })

  test("known answers", async () => {
    expect(await fingerprintGroupIndex("ABCD2345")).toBe(2)
    expect(await fingerprintGroupIndex("K7Q2MX4D")).toBe(3)
    expect(await fingerprintGroupIndex("ZZZZ9999")).toBe(2)
  })

  test("is the first byte of a domain-separated SHA-256, mod 4", async () => {
    const digest = atob(
      (await sha256B64(`mehen-fp-group-index\u0000${CODE}`)).replaceAll("-", "+").replaceAll("_", "/") + "=",
    )
    expect(await fingerprintGroupIndex(CODE)).toBe((digest.charCodeAt(0) & 3) as FingerprintGroupIndex)
  })

  test("spreads across all four values", async () => {
    const counts: [number, number, number, number] = [0, 0, 0, 0]
    for (let i = 0; i < 400; i++) {
      counts[await fingerprintGroupIndex(`CODE${i}`)] += 1
    }
    for (const count of counts) {
      expect(count).toBeGreaterThan(50)
      expect(count).toBeLessThan(150)
    }
  })

  test("refuses an empty code", async () => {
    await expect(fingerprintGroupIndex("")).rejects.toThrow(/enrolment code/)
    await expect(fingerprintGroupIndex("  - ")).rejects.toThrow(/enrolment code/)
  })
})

describe("fingerprintGroupCheck", () => {
  test("is base64url SHA-256 over the domain, the code and the normalised group", async () => {
    expect(await fingerprintGroupCheck(CODE, "5NZV")).toBe(await sha256B64(`mehen-fp-group\u0000${CODE}\u00005NZV`))
    expect(await fingerprintGroupCheck(CODE, "5NZV")).toBe("UgbicL0GJ2NKs_S8RGlepXQ54y_GTD9ln4yIAulXJWI")
  })

  test("is equal for every way of typing the same group", async () => {
    const check = await fingerprintGroupCheck(CODE, "5NZV")
    expect(await fingerprintGroupCheck(CODE, "5nzv")).toBe(check)
    expect(await fingerprintGroupCheck(CODE, " 5n-zv ")).toBe(check)
    expect(await fingerprintGroupCheck("abcd-2345", "5NZV")).toBe(check)
    const ones = await fingerprintGroupCheck(CODE, "1110")
    expect(await fingerprintGroupCheck(CODE, "lIlo")).toBe(ones)
  })

  test("differs for a wrong group, a different code or a different domain", async () => {
    const check = await fingerprintGroupCheck(CODE, "5NZV")
    expect(await fingerprintGroupCheck(CODE, "5NZW")).not.toBe(check)
    expect(await fingerprintGroupCheck(CODE, "DP67")).not.toBe(check)
    expect(await fingerprintGroupCheck("ABCD2346", "5NZV")).not.toBe(check)
    expect(await sha256B64(`mehen-fp-group-index\u0000${CODE}\u00005NZV`)).not.toBe(check)
    expect(await sha256B64(`${CODE}\u00005NZV`)).not.toBe(check)
  })

  test("is keyed by the page's ref: an enrolment id gives its own check, never the code's", async () => {
    const ref = "enr_7Kz9t7m2ujMLyIOwa7Skw"
    const check = await fingerprintGroupCheck(ref, "5NZV")
    expect(check).toBe(await sha256B64(`mehen-fp-group\u0000${ref.toUpperCase()}\u00005NZV`))
    expect(await fingerprintGroupCheck(ref, " 5n-zv ")).toBe(check)
    expect(check).not.toBe(await fingerprintGroupCheck(CODE, "5NZV"))
    expect(check).not.toBe(await fingerprintGroupCheck("enr_other", "5NZV"))
  })

  test("refuses a group that does not normalise", async () => {
    await expect(fingerprintGroupCheck(CODE, "5NZU")).rejects.toThrow(/four characters/)
    await expect(fingerprintGroupCheck(CODE, "5NZ")).rejects.toThrow(/four characters/)
    await expect(fingerprintGroupCheck(CODE, "")).rejects.toThrow(/four characters/)
    await expect(fingerprintGroupCheck("", "5NZV")).rejects.toThrow(/enrolment code/)
  })

  test("the page's gate: the hidden group matches, every other group does not", async () => {
    for (let i = 0; i < 50; i++) {
      const code = `CODE${i}`
      const groups = fingerprintGroups(fingerprintOf(randomThumbprint()))
      const hidden = await fingerprintGroupIndex(code)
      const expected = await fingerprintGroupCheck(code, groups[hidden])
      for (let g = 0; g < 4; g++) {
        const typed = await fingerprintGroupCheck(code, groups[g as FingerprintGroupIndex].toLowerCase())
        if (g === hidden) expect(typed).toBe(expected)
        else if (groups[g as FingerprintGroupIndex] !== groups[hidden]) expect(typed).not.toBe(expected)
      }
    }
  })
})

describe("fingerprintWords", () => {
  test("known answer: a fixed thumbprint gives fixed words and colours", () => {
    expect(fingerprintWords(KNOWN_THUMBPRINT).map((w) => [w.word, w.colour.name])).toEqual([
      ["puppy", "violet"],
      ["potato", "indigo"],
      ["juice", "mint"],
      ["oven", "olive"],
    ])
  })

  test("a word per byte from byte 10, a colour per nibble from byte 14", () => {
    expect(fingerprintWords(RAMP_THUMBPRINT).map((w) => [FINGERPRINT_WORDS.indexOf(w.word), FINGERPRINT_COLOURS.indexOf(w.colour)])).toEqual([
      [10, 0],
      [11, 14],
      [12, 0],
      [13, 15],
    ])
    expect(fingerprintWords(ONES_THUMBPRINT).map((w) => [w.word, w.colour.name])).toEqual([
      ["zebra", "grey"],
      ["zebra", "grey"],
      ["zebra", "grey"],
      ["zebra", "grey"],
    ])
  })

  test("uses bytes the glyphs do not, and only those", () => {
    const a = Uint8Array.from({ length: 32 }, (_, i) => i)
    const glyphsOnly = Uint8Array.from(a)
    for (let i = 0; i < 10; i++) glyphsOnly[i] = 0xff
    const tailOnly = Uint8Array.from(a)
    for (let i = 16; i < 32; i++) tailOnly[i] = 0xff
    expect(fingerprintWords(base64UrlEncode(glyphsOnly))).toEqual(fingerprintWords(base64UrlEncode(a)))
    expect(fingerprintWords(base64UrlEncode(tailOnly))).toEqual(fingerprintWords(base64UrlEncode(a)))
    const wordByte = Uint8Array.from(a)
    wordByte[12] = 0x0d
    expect(fingerprintWords(base64UrlEncode(wordByte))).not.toEqual(fingerprintWords(base64UrlEncode(a)))
  })

  test("refuses a malformed thumbprint", () => {
    expect(() => fingerprintWords("")).toThrow(/32 bytes/)
    expect(() => fingerprintWords("nope!")).toThrow(/base64url/)
  })
})

describe("fingerprint word list", () => {
  test("has exactly 256 unique words of 4 to 6 lower-case letters", () => {
    expect(FINGERPRINT_WORDS).toHaveLength(256)
    expect(new Set(FINGERPRINT_WORDS).size).toBe(256)
    for (const word of FINGERPRINT_WORDS) {
      expect(word).toMatch(/^[a-z]{4,6}$/)
    }
  })

  test("is sorted, so a duplicate or a stray edit is visible in the file", () => {
    expect([...FINGERPRINT_WORDS].sort()).toEqual([...FINGERPRINT_WORDS])
  })

  test("no two words are within one edit of each other", () => {
    const distance = (a: string, b: string): number => {
      const row: number[] = Array.from({ length: b.length + 1 }, (_, j) => j)
      for (let i = 1; i <= a.length; i++) {
        let diagonal = row[0] ?? 0
        row[0] = i
        for (let j = 1; j <= b.length; j++) {
          const above = row[j] ?? 0
          row[j] = Math.min(above + 1, (row[j - 1] ?? 0) + 1, diagonal + (a[i - 1] === b[j - 1] ? 0 : 1))
          diagonal = above
        }
      }
      return row[b.length] ?? 0
    }
    const close: string[] = []
    for (let i = 0; i < FINGERPRINT_WORDS.length; i++) {
      for (let j = i + 1; j < FINGERPRINT_WORDS.length; j++) {
        if (distance(FINGERPRINT_WORDS[i] as string, FINGERPRINT_WORDS[j] as string) < 2) {
          close.push(`${FINGERPRINT_WORDS[i]} ${FINGERPRINT_WORDS[j]}`)
        }
      }
    }
    expect(close).toEqual([])
  })

  test("no word is a colour name, nor a material or food used as one", () => {
    for (const name of FINGERPRINT_COLOURS.map((c) => c.name)) expect(COLOUR_WORDS.has(name)).toBe(true)
    expect(FINGERPRINT_WORDS.filter((w) => COLOUR_WORDS.has(w))).toEqual([])
  })

  test("has exactly 16 colours with unique names and hex values for both surfaces", () => {
    expect(FINGERPRINT_COLOURS).toHaveLength(16)
    expect(new Set(FINGERPRINT_COLOURS.map((c) => c.name)).size).toBe(16)
    for (const colour of FINGERPRINT_COLOURS) {
      expect(colour.name).toMatch(/^[a-z]{3,7}$/)
      expect(colour.light).toMatch(/^#[0-9a-f]{6}$/)
      expect(colour.dark).toMatch(/^#[0-9a-f]{6}$/)
      expect(colour.light).not.toBe(colour.dark)
    }
  })
})
