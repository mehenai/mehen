import { describe, expect, test } from "bun:test"
import { StreamRedactor, buildNeedles, redactText } from "./redact.ts"

const SECRET = "s3cr3t/Value+with=chars"
const LABEL = "stripe"
const MARKER = `[redacted:${LABEL}]`
const needles = buildNeedles([{ label: LABEL, value: SECRET }])

function b64(bytes: Uint8Array, url: boolean): string {
  let binary = ""
  for (const b of bytes) binary += String.fromCharCode(b)
  const encoded = btoa(binary)
  return url ? encoded.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "") : encoded
}

function textB64(text: string, url: boolean): string {
  return b64(new TextEncoder().encode(text), url)
}

// Runs a stream through the redactor in the given chunks, returning every
// emitted piece so tests can inspect each write as well as the whole.
function stream(redactor: StreamRedactor, chunks: string[]): string[] {
  const out = chunks.map((chunk) => redactor.push(chunk))
  out.push(redactor.end())
  return out
}

function splitEvery(text: string, size: number): string[] {
  const out: string[] = []
  for (let i = 0; i < text.length; i += size) out.push(text.slice(i, i + size))
  return out
}

// A small deterministic generator so chunking tests are repeatable.
function lcg(seed: number): () => number {
  let state = seed
  return () => {
    state = (state * 1_103_515_245 + 12_345) % 2_147_483_648
    return state / 2_147_483_648
  }
}

describe("buildNeedles and redactText", () => {
  test("redacts the plain value", () => {
    expect(redactText(`key=${SECRET}; again ${SECRET}.`, needles)).toBe(`key=${MARKER}; again ${MARKER}.`)
  })

  test("redacts the URL-encoded value", () => {
    const encoded = encodeURIComponent(SECRET)
    expect(encoded).not.toBe(SECRET)
    expect(redactText(`https://h.example/?token=${encoded}&x=1`, needles)).toBe(`https://h.example/?token=${MARKER}&x=1`)
  })

  test("redacts the value as a query string or form carries it", () => {
    const value = "Summer 2024!(x)~'*"
    const own = buildNeedles([{ label: "q", value }])
    const url = new URL("https://h.example/echo")
    url.searchParams.set("key", value)
    expect(url.search).not.toContain(encodeURIComponent(value))
    expect(redactText(url.href, own)).toBe("https://h.example/echo?key=[redacted:q]")
  })

  test("redacts the URL-encoded value with its percent escapes in either hex case, and only the escapes", () => {
    const value = "Ab+Cd/Ef12 \u00fc!(x)"
    const own = buildNeedles([{ label: "u", value }])
    const lower = (encoded: string) => encoded.replace(/%[0-9A-F]{2}/g, (escape) => escape.toLowerCase())
    const mixed = (encoded: string) => encoded.replace(/%[0-9A-F]{2}/g, (escape, at: number) => (at % 2 === 0 ? escape.toLowerCase() : escape))
    const query = new URLSearchParams([["", value]]).toString().slice(1)
    const spellings = [lower(encodeURIComponent(value)), mixed(encodeURIComponent(value)), lower(query), mixed(query)]
    for (const spelling of spellings) {
      expect(spelling).toMatch(/%[0-9a-f]*[a-f]/)
      const text = `x-echo: ?k=${spelling}&x=1`
      const whole = redactText(text, own)
      expect(whole, spelling).toBe("x-echo: ?k=[redacted:u]&x=1")
      for (let i = 1; i < text.length; i++) expect(stream(new StreamRedactor(own), [text.slice(0, i), text.slice(i)]).join(""), `${spelling} at ${i}`).toBe(whole)
    }
    const otherCase = lower(encodeURIComponent("aB+Cd/Ef12 \u00fc!(x)"))
    expect(redactText(otherCase, own)).toBe(otherCase)
  })

  test("redacts the value in any percent-encoding, whichever characters the encoder escapes, and wherever a write splits it", () => {
    const value = "Ab9!'()*~ +%/:\u00e9z"
    const own = buildNeedles([{ label: "pct", value }])
    const spellings = {
      // PHP's rawurlencode: everything outside A-Za-z0-9-_.~ escaped, a space as %20.
      rawurlencode: "Ab9%21%27%28%29%2A~%20%2B%25%2F%3A%C3%A9z",
      everyByte: "%41%62%39%21%27%28%29%2A%7E%20%2B%25%2F%3A%C3%A9%7A",
      mixedHexCase: "Ab9%21%27%28%29%2a~%20%2B%25%2f%3A%c3%A9z",
      plusForSpace: "Ab9%21%27%28%29%2A~+%2B%25%2F%3A%C3%A9z",
      someBare: "Ab9!'()*%7E %2B%/:\u00e9%7a",
    }
    for (const [name, spelling] of Object.entries(spellings)) {
      const text = `x-echo: ?k=${spelling}&x=1`
      const whole = redactText(text, own)
      expect(whole, name).toBe("x-echo: ?k=[redacted:pct]&x=1")
      for (let i = 1; i < text.length; i++) expect(stream(new StreamRedactor(own), [text.slice(0, i), text.slice(i)]).join(""), `${name} at ${i}`).toBe(whole)
    }
    const nearMiss = spellings.rawurlencode.replace("%3A", "%3B")
    expect(redactText(nearMiss, own)).toBe(nearMiss)
    expect(stream(new StreamRedactor(own), [nearMiss.slice(0, 20), nearMiss.slice(20)]).join("")).toBe(nearMiss)
  })

  test("a + in the value is %2B or itself and never a space, and a space is %20, + or itself", () => {
    const own = buildNeedles([{ label: "p", value: "ab+cd ef" }])
    for (const spelling of ["ab%2Bcd%20ef", "ab%2bcd+ef", "ab+cd+ef", "%61b+cd ef"]) expect(redactText(`[${spelling}]`, own), spelling).toBe("[[redacted:p]]")
    for (const spelling of ["ab cd+ef", "ab%20cd%20ef", "ab%2Bcd%2Bef"]) expect(redactText(`[${spelling}]`, own), spelling).toBe(`[${spelling}]`)
  })

  test("a % in the value is %25, or a bare % that the text shows is not the start of %25", () => {
    const own = buildNeedles([{ label: "p", value: "ab%cd-12" }])
    for (const spelling of ["ab%25cd-12", "%61b%cd-12", "%61b%25cd%2D12"]) expect(redactText(`[${spelling}]`, own), spelling).toBe("[[redacted:p]]")
    // Text that reads %25 is always the escape, so a value holding "%25"
    // needs its own % escaped once anything else in it is.
    const literal = buildNeedles([{ label: "q", value: "ab%25-12" }])
    for (const spelling of ["ab%25-12", "%61b%2525-12"]) expect(redactText(`[${spelling}]`, literal), spelling).toBe("[[redacted:q]]")
    expect(redactText("[%61b%25-12]", literal)).toBe("[%61b%25-12]")
    // A % that ends the value is held while more text could still make it
    // %25, so the stream gives what the whole text does.
    const last = buildNeedles([{ label: "r", value: "abcdef%" }])
    for (const text of ["x abcdef%25 y", "x %61bcdef% y", "x abcdef%2 y", "x abcdef%"]) {
      const whole = redactText(text, last)
      expect(whole, text).toContain("[redacted:r]")
      for (let i = 0; i <= text.length; i++) expect(stream(new StreamRedactor(last), [text.slice(0, i), text.slice(i)]).join(""), `${text} at ${i}`).toBe(whole)
    }
    expect(redactText("x abcdef%25 y", last)).toBe("x [redacted:r] y")
  })

  test("a long run of near misses of a percent spelling is left as it is", () => {
    const value = "Ab9!'()*~ +%/:\u00e9z"
    const own = buildNeedles([{ label: "pct", value }])
    const nearMiss = "Ab9%21%27%28%29%2A~%20%2B%25%2F%3A%C3%A8z".repeat(20_000)
    expect(redactText(nearMiss, own)).toBe(nearMiss)
    expect(stream(new StreamRedactor(own), splitEvery(nearMiss, 4096)).join("")).toBe(nearMiss)
    const repetitive = buildNeedles([{ label: "a", value: "a".repeat(64) }])
    const almost = `${"%61".repeat(63)}%62`.repeat(2_000)
    expect(redactText(almost, repetitive)).toBe(almost)
  })

  test("redacts the JSON-escaped value", () => {
    const tricky = 'p"ss\\word\n12'
    const own = buildNeedles([{ label: "db", value: tricky }])
    const json = JSON.stringify({ password: tricky })
    expect(json).not.toContain(tricky)
    expect(redactText(json, own)).toBe('{"password":"[redacted:db]"}')
  })

  test("redacts the JSON spellings other encoders write: an escaped slash, non-ASCII and <, > and & as \\u escapes", () => {
    expect(redactText('{"error":"invalid key s3cr3t\\/Value+with=chars"}', needles)).toBe(`{"error":"invalid key ${MARKER}"}`)
    const value = "s3cr3t/V\u00e4lue<&>\u2028\u{1F511}"
    const own = buildNeedles([{ label: "api", value }])
    const spellings = [
      "s3cr3t\\/V\u00e4lue<&>\u2028\u{1F511}",
      "s3cr3t/V\\u00e4lue<&>\\u2028\\ud83d\\udd11",
      "s3cr3t\\/V\\u00e4lue<&>\\u2028\\ud83d\\udd11",
      "s3cr3t/V\u00e4lue\\u003c\\u0026\\u003e\\u2028\u{1F511}",
      "s3cr3t\\/V\\u00e4lue\\u003c\\u0026\\u003e\\u2028\\ud83d\\udd11",
    ]
    for (const spelling of spellings) expect(redactText(`{"error":"invalid key ${spelling}"}`, own), spelling).toBe('{"error":"invalid key [redacted:api]"}')
  })

  test("redacts the value whichever characters a JSON encoder escapes as \\u, in either hex case", () => {
    const spellings = [
      // Gson's HTML-safe default escapes = and '.
      "s3cr3t/Value+with\\u003dchars",
      // System.Text.Json's default escapes + with upper-case hex.
      "s3cr3t/Value\\u002Bwith=chars",
      "s3cr3t\\/Value\\u002bwith\\u003Dchars",
      "\\u0073\\u0033cr3t\\u002FValue+with=chars",
    ]
    for (const spelling of spellings) expect(redactText(`{"error":"invalid key ${spelling}"}`, needles), spelling).toBe(`{"error":"invalid key ${MARKER}"}`)
    const tricky = 'p"ss\\word\n12'
    const own = buildNeedles([{ label: "db", value: tricky }])
    for (const spelling of ['p\\u0022ss\\\\word\\u000a12', 'p\\"ss\\u005Cword\\n12']) expect(redactText(`[${spelling}]`, own), spelling).toBe("[[redacted:db]]")
    expect(redactText("s3cr3t/Value+with\\u003chars", needles)).toBe("s3cr3t/Value+with\\u003chars")
  })

  test("a 4 KiB secret is redacted in every spelling and near miss, and the stream holds back at most six characters per character of it", () => {
    const random = lcg(7)
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    const value = Array.from({ length: 4096 }, () => alphabet[Math.floor(random() * alphabet.length)]).join("")
    const own = buildNeedles([{ label: "big", value }])
    const escaped = value.replace(/[+=]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0").toUpperCase()}`).replaceAll("/", "\\/")
    const nearMiss = value.slice(0, 2048)
    const text = `${"x".repeat(64 * 1024)} ${escaped} ${nearMiss} `.repeat(4)
    const out = redactText(text, own)
    expect(out.split("[redacted:big]").length - 1).toBe(4)
    expect(out).toContain(` ${nearMiss} `)
    const redactor = new StreamRedactor(own)
    const filler = "y".repeat(256 * 1024)
    expect(redactor.push(filler).length).toBeGreaterThanOrEqual(filler.length - 6 * value.length)
  })

  test("redacts base64 and base64url at every alignment and with any neighbours", () => {
    const filler = "Zq9!x~"
    for (let before = 0; before <= 5; before++) {
      for (let after = 0; after <= 4; after++) {
        for (const url of [false, true]) {
          const encoded = textB64(`${filler.slice(0, before)}${SECRET}${filler.slice(0, after)}`, url)
          const redacted = redactText(`<${encoded}>`, needles)
          expect({ before, after, url, found: redacted.includes(MARKER) }).toEqual({ before, after, url, found: true })
          // Only the characters that also depend on the neighbours may remain.
          const left = redacted.replace(MARKER, "").length - 2
          expect(left).toBeLessThanOrEqual(Math.ceil((before * 4) / 3) + 1 + 4 + Math.ceil((after * 4) / 3) + 1)
        }
      }
    }
  })

  test("redacts a secret inside a Basic auth header", () => {
    const password = "hunter2-correct-horse"
    const own = buildNeedles([{ label: "basic", value: password }])
    for (const user of ["u", "us", "usr", "user", "admin@example.com"]) {
      const header = `Authorization: Basic ${textB64(`${user}:${password}`, false)}`
      expect(redactText(header, own)).toContain("[redacted:basic]")
    }
  })

  test("redacts base64url of raw bytes that need the URL alphabet", () => {
    const value = "\u00fb\u00ff\u00bf-secret-tail"
    const own = buildNeedles([{ label: "bin", value }])
    const std = textB64(value, false)
    const url = textB64(value, true)
    expect(std).not.toBe(url)
    expect(redactText(std, own)).toContain("[redacted:bin]")
    expect(redactText(url, own)).toContain("[redacted:bin]")
  })

  test("ignores secrets shorter than six characters", () => {
    expect(buildNeedles([{ label: "short", value: "abcde" }])).toEqual([])
    expect(redactText("abcde", buildNeedles([{ label: "short", value: "abcde" }]))).toBe("abcde")
    expect(buildNeedles([{ label: "six", value: "abcdef" }]).length).toBeGreaterThan(0)
    expect(redactText("xabcdefx", buildNeedles([{ label: "six", value: "abcdef" }]))).toBe("x[redacted:six]x")
  })

  test("needles are sorted by their shortest match, longest first, and labelled", () => {
    const list = buildNeedles([
      { label: "a", value: "short-one" },
      { label: "b", value: "a-much-longer-secret-value" },
    ])
    for (let i = 1; i < list.length; i++) {
      expect((list[i - 1]?.shortest ?? 0) >= (list[i]?.shortest ?? 0)).toBe(true)
    }
    expect(list[0]?.replacement).toBe("[redacted:b]")
  })

  test("a secret inside another never breaks up the other's encoded form", () => {
    const inner = "Tr0ub4dor3x"
    const outer = `postgres://app:${inner}@db/x`
    const list = buildNeedles([
      { label: "password", value: inner },
      { label: "url", value: outer },
    ])
    for (const spelling of [outer, encodeURIComponent(outer), JSON.stringify(outer).slice(1, -1).replaceAll("/", "\\/")]) {
      expect(redactText(`dsn=${spelling};`, list), spelling).toBe("dsn=[redacted:url];")
    }
  })

  test("text without secrets is unchanged", () => {
    expect(redactText("nothing to hide here", needles)).toBe("nothing to hide here")
    expect(redactText("", needles)).toBe("")
  })

  test("redacts several secrets with their own labels", () => {
    const list = buildNeedles([
      { label: "one", value: "first-secret-1" },
      { label: "two", value: "second-secret-2" },
    ])
    expect(redactText("a first-secret-1 b second-secret-2 c", list)).toBe("a [redacted:one] b [redacted:two] c")
  })
})

describe("StreamRedactor", () => {
  test("passes text through unchanged with no needles", () => {
    const redactor = new StreamRedactor([])
    expect(redactor.push("hello")).toBe("hello")
    expect(redactor.end()).toBe("")
  })

  test("catches a secret split across two chunks", () => {
    const text = `before ${SECRET} after`
    for (let cut = 1; cut < text.length; cut++) {
      const out = stream(new StreamRedactor(needles), [text.slice(0, cut), text.slice(cut)])
      expect(out.join("")).toBe(`before ${MARKER} after`)
    }
  })

  test("catches a secret sent one character at a time and never emits part of it", () => {
    const text = `log line ${SECRET} and more ${SECRET}!`
    const out = stream(new StreamRedactor(needles), [...text])
    expect(out.join("")).toBe(`log line ${MARKER} and more ${MARKER}!`)
    for (const piece of out) expect(piece).not.toContain("s3c")
  })

  test("catches encoded variants split across many chunks", () => {
    const encoded = encodeURIComponent(SECRET)
    const basic = textB64(`user:${SECRET}`, false)
    const text = `q=${encoded} auth=Basic ${basic} end`
    const whole = redactText(text, needles)
    expect(whole).not.toContain(encoded)
    for (const size of [1, 2, 3, 7]) {
      expect(stream(new StreamRedactor(needles), splitEvery(text, size)).join("")).toBe(whole)
    }
  })

  test("random chunkings give the same result as redacting the whole text", () => {
    const text = `${SECRET}|${encodeURIComponent(SECRET)}|${textB64(SECRET, true)}|x ${SECRET}`
    const whole = redactText(text, needles)
    const random = lcg(42)
    for (let run = 0; run < 200; run++) {
      const chunks: string[] = []
      let i = 0
      while (i < text.length) {
        const size = 1 + Math.floor(random() * 12)
        chunks.push(text.slice(i, i + size))
        i += size
      }
      const out = stream(new StreamRedactor(needles), chunks)
      expect(out.join("")).toBe(whole)
      for (const piece of out) expect(piece.includes("s3cr3t")).toBe(false)
    }
  })

  test("holds back a possible secret prefix until it is resolved", () => {
    const redactor = new StreamRedactor(needles)
    const first = redactor.push(`ok ${SECRET.slice(0, 10)}`)
    expect(first).not.toContain(SECRET.slice(0, 3))
    const second = redactor.push(SECRET.slice(10))
    expect(second).not.toContain(SECRET.slice(10))
    expect(first + second + redactor.end()).toBe(`ok ${MARKER}`)
  })

  test("never releases the start of any spelling of a secret, wherever a write ends inside it", () => {
    const value = 'p"ss/w\\ord+x=\u00e9 ~!'
    const own = buildNeedles([{ label: "db", value }])
    const hexAll = (upper: boolean) => [...value].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`).map((e) => (upper ? e.toUpperCase().replace("\\U", "\\u") : e)).join("")
    const forms = [
      value,
      encodeURIComponent(value),
      new URLSearchParams([["", value]]).toString().slice(1),
      textB64(value, false).replace(/=+$/, "").slice(0, -3),
      textB64(value, true).slice(0, -3),
      JSON.stringify(value).slice(1, -1),
      JSON.stringify(value).slice(1, -1).replaceAll("/", "\\/").replace("\u00e9", "\\u00e9"),
      hexAll(false),
      hexAll(true),
    ]
    for (const form of forms) {
      expect(redactText(form, own), form).toBe("[redacted:db]")
      for (let k = 1; k < form.length; k++) {
        const redactor = new StreamRedactor(own)
        const first = redactor.push(`log: ${form.slice(0, k)}`)
        expect({ form, k, released: "log: ".startsWith(first) }).toEqual({ form, k, released: true })
        expect(first + redactor.push(`${form.slice(k)} ok`) + redactor.end()).toBe("log: [redacted:db] ok")
      }
    }
  })

  test("a line that cannot start a secret is emitted at once, however long the secret", () => {
    const redactor = new StreamRedactor(buildNeedles([{ label: "key", value: "sk-test-4f9c2a7e1b8d3c6f0a5e9b2d7c4f1a8e" }]))
    expect(redactor.push("ready on http://localhost:3000\n")).toBe("ready on http://localhost:3000\n")
    const event = 'event: delta\ndata: {"choices":[{"delta":{"content":"Hello"}}]}'
    expect(redactor.push(event)).toBe(event)
    expect(redactor.push("token sk-te")).toBe("token ")
    expect(redactor.end()).toBe("sk-te")
  })

  test("a secret inside another, written in two parts, is redacted as the outer one", () => {
    const list = buildNeedles([
      { label: "password", value: "Tr0ub4dor3x" },
      { label: "url", value: "postgres://app:Tr0ub4dor3x@db/x" },
    ])
    expect(stream(new StreamRedactor(list), ["dsn=postgres://app:Tr0ub4dor3x", "@db/x;"]).join("")).toBe("dsn=[redacted:url];")
  })

  test("nested and overlapping secrets in every spelling give the whole text's redaction wherever the writes split", () => {
    const inner = "Tr0ub4dor3x"
    const outer = `postgres://app:${inner}@db/x`
    const list = buildNeedles([
      { label: "password", value: inner },
      { label: "url", value: outer },
      { label: "a", value: "alpha-overlap-77" },
      { label: "b", value: "overlap-77-omega" },
      { label: "k", value: "Zx9Qw7Lm" },
      // Matches across the marker [redacted:k] leaves before it.
      { label: "t", value: "d:k]-ta" },
    ])
    const json = (value: string) => JSON.stringify(value).slice(1, -1).replaceAll("/", "\\/").replace("@", "\\u0040")
    const query = (value: string) => new URLSearchParams([["", value]]).toString().slice(1)
    const short = [`dsn=${outer};`, `"${json(outer)}"`, `p=${encodeURIComponent(outer)}`, "x alpha-overlap-77-omega y", "Zx9Qw7Lm-ta!"]
    const long = [
      `dsn=${outer}; pw=${inner}; e=${encodeURIComponent(outer)}; q=${query(outer)}; j="${json(outer)}"; b=${textB64(`u:${outer}`, false)}; i=${textB64(inner, true)}; o=alpha-overlap-77-omega; ${inner}@db/x Zx9Qw7Lm-ta.`,
    ]
    for (const text of [...short, ...long]) {
      const whole = redactText(text, list)
      for (let i = 0; i <= text.length; i++) {
        expect({ text, i, out: stream(new StreamRedactor(list), [text.slice(0, i), text.slice(i)]).join("") }).toEqual({ text, i, out: whole })
      }
    }
    for (const text of short) {
      const whole = redactText(text, list)
      for (let i = 0; i <= text.length; i++) {
        for (let j = i; j <= text.length; j++) {
          expect({ text, i, j, out: stream(new StreamRedactor(list), [text.slice(0, i), text.slice(i, j), text.slice(j)]).join("") }).toEqual({ text, i, j, out: whole })
        }
      }
    }
  })

  test("never splits a replacement marker across writes", () => {
    const text = `${SECRET}${"x".repeat(5)}`
    const out = stream(new StreamRedactor(needles), [...text])
    for (const piece of out) {
      const opens = piece.split("[redacted:").length - 1
      const closes = piece.split("]").length - 1
      expect(opens).toBe(closes)
    }
    expect(out.join("")).toBe(`${MARKER}xxxxx`)
  })

  test("flushes held text on end", () => {
    const redactor = new StreamRedactor(needles)
    expect(redactor.push(`tail ${SECRET.slice(0, 4)}`)).toBe("tail ")
    expect(redactor.end()).toBe(SECRET.slice(0, 4))
    expect(redactor.end()).toBe("")
  })

  test("flushes a held partial secret prefix as plain text on end", () => {
    const redactor = new StreamRedactor(needles)
    const partial = SECRET.slice(0, 8)
    expect(redactor.push(partial)).toBe("")
    expect(redactor.end()).toBe(partial)
  })

  test("long text is emitted progressively, never with a secret prefix", () => {
    const redactor = new StreamRedactor(needles)
    const text = `${"a".repeat(1000)} ${SECRET} ${"b".repeat(1000)}`
    let shown = ""
    for (const chunk of splitEvery(text, 7)) {
      shown += redactor.push(chunk)
      for (let k = 1; k < SECRET.length; k++) expect(shown.endsWith(SECRET.slice(0, k))).toBe(false)
    }
    expect(shown.length).toBeGreaterThan(1000)
    expect(shown + redactor.end()).toBe(redactText(text, needles))
  })

  test("handles multibyte text without splitting surrogate pairs", () => {
    const text = `héllo 🔐 wörld ${SECRET} 日本語 🎉🎉 end`
    const whole = redactText(text, needles)
    expect(whole).toBe(`héllo 🔐 wörld ${MARKER} 日本語 🎉🎉 end`)
    for (const size of [1, 2, 3, 5]) {
      const out = stream(new StreamRedactor(needles), splitEvery(text, size))
      expect(out.join("")).toBe(whole)
      for (const piece of out) {
        if (piece === "") continue
        const last = piece.charCodeAt(piece.length - 1)
        expect(last >= 0xd800 && last <= 0xdbff).toBe(false)
      }
    }
  })

  test("redacts a multibyte secret in plain and base64 form", () => {
    const value = "pässwörd-🔐-geheim"
    const own = buildNeedles([{ label: "mb", value }])
    const text = `x ${value} y ${textB64(`user:${value}`, false)} z`
    const out = stream(new StreamRedactor(own), [...text]).join("")
    expect(out).toBe(redactText(text, own))
    expect(out).not.toContain(value)
    expect(out.split("[redacted:mb]").length - 1).toBe(2)
  })
})
