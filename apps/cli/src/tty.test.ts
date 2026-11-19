import { describe, expect, test } from "bun:test"
import { colourEnabled, isTty, plainText, qrChoice, qrScheme, qrWidth, segments, statusTone, stripStyle, style, styler, terminalColumns, terminalText, visibleText, visibleWidth } from "./tty.ts"

const tty = { isTTY: true, columns: 120 }
const pipe = { isTTY: false }

describe("colourEnabled", () => {
  test("on for a TTY with a plain environment", () => {
    expect(colourEnabled(tty, {})).toBe(true)
  })

  test("off when the stream is not a TTY", () => {
    expect(isTty(pipe)).toBe(false)
    expect(colourEnabled(pipe, {})).toBe(false)
    expect(colourEnabled({}, {})).toBe(false)
  })

  test("NO_COLOR set to anything non-empty turns it off; empty does not", () => {
    expect(colourEnabled(tty, { NO_COLOR: "1" })).toBe(false)
    expect(colourEnabled(tty, { NO_COLOR: "yes" })).toBe(false)
    expect(colourEnabled(tty, { NO_COLOR: "" })).toBe(true)
  })

  test("TERM=dumb turns it off", () => {
    expect(colourEnabled(tty, { TERM: "dumb" })).toBe(false)
    expect(colourEnabled(tty, { TERM: "xterm-256color" })).toBe(true)
  })

  test("FORCE_COLOR forces it on, even without a TTY or with NO_COLOR", () => {
    expect(colourEnabled(pipe, { FORCE_COLOR: "1" })).toBe(true)
    expect(colourEnabled(tty, { FORCE_COLOR: "1", NO_COLOR: "1" })).toBe(true)
    expect(colourEnabled(pipe, { FORCE_COLOR: "0" })).toBe(false)
    expect(colourEnabled(pipe, { FORCE_COLOR: "" })).toBe(false)
  })
})

describe("style and styler", () => {
  test("style is a segment with a named style that only terminalText turns into an escape; empty text stays plain", () => {
    expect(style("x", "bold")).toEqual({ text: "x", style: "bold" })
    expect(terminalText(style("x", "bold"))).toBe("\u001b[1mx\u001b[0m")
    expect(terminalText(style("x", "danger"))).toBe("\u001b[31mx\u001b[0m")
    expect(terminalText(style("x", "ok"))).toBe("\u001b[32mx\u001b[0m")
    expect(terminalText(style("x", "warn"))).toBe("\u001b[33mx\u001b[0m")
    expect(terminalText(style("x", "accent"))).toBe("\u001b[36mx\u001b[0m")
    expect(style("", "bold")).toEqual({ text: "" })
    expect(terminalText(segments("a ", style("b", "dim"), " c"))).toBe("a \u001b[2mb\u001b[0m c")
    expect(plainText(segments("a ", style("b", "dim"), " c"))).toBe("a b c")
  })

  test("the style set is closed: a style that is not one of the names is ignored, never emitted", () => {
    // A value that slipped past the type (a ledger file, a cast) cannot pick an SGR code.
    const forged = [{ text: "a", style: "31" }, { text: "b", style: "\u001b[2K" }, { text: "c", style: "bold;31" }] as unknown as Parameters<typeof terminalText>[0]
    expect(terminalText(forged)).toBe("abc")
    expect(terminalText([{ text: "a", style: "constructor" }] as unknown as Parameters<typeof terminalText>[0])).toBe("a")
  })

  test("a disabled styler returns unstyled segments", () => {
    const s = styler(false)
    expect(s.bold("fp")).toEqual({ text: "fp" })
    expect(s.dim("open:")).toEqual({ text: "open:" })
    expect(s.status("active")).toEqual({ text: "active" })
    expect(s.accent("Human needed")).toEqual({ text: "Human needed" })
    expect(terminalText(s.bold("fp"))).toBe("fp")
  })

  test("an enabled styler colours statuses by tone and nothing else", () => {
    const s = styler(true)
    expect(terminalText(s.status("active"))).toBe("\u001b[32mactive\u001b[0m")
    expect(terminalText(s.status("needs reauth"))).toBe("\u001b[33mneeds reauth\u001b[0m")
    expect(terminalText(s.status("denied"))).toBe("\u001b[31mdenied\u001b[0m")
    expect(terminalText(s.status("(unverified)"))).toBe("\u001b[31m(unverified)\u001b[0m")
    expect(s.status("api-key")).toEqual({ text: "api-key" })
  })

  test("statusTone follows the 2.7 table", () => {
    expect(statusTone("approved")).toBe("good")
    expect(statusTone("completed")).toBe("good")
    expect(statusTone("pending")).toBe("wait")
    expect(statusTone("needs approval")).toBe("wait")
    expect(statusTone("refresh_retrying")).toBe("wait")
    expect(statusTone("expired")).toBe("bad")
    expect(statusTone("refused")).toBe("bad")
    expect(statusTone("needs review")).toBe("bad")
    expect(statusTone("disabled")).toBe("bad")
    expect(statusTone("oauth-connection")).toBeNull()
  })

  test("stripStyle and visibleWidth see through the codes and count spelled-out characters", () => {
    const text = style("K7Q2MX", "bold")
    expect(plainText(text)).toBe("K7Q2MX")
    expect(stripStyle(terminalText(text))).toBe("K7Q2MX")
    expect(visibleWidth(text)).toBe(6)
    expect(visibleWidth("a\u200bb")).toBe("a[ZWSP U+200B]b".length)
  })
})

describe("terminalText: the one boundary", () => {
  test("a styled string with a hidden character and an ESC sequence inside comes out with only mehen's own escapes", () => {
    const hostile = "re\u200bads\u001b[2K\u001b[31mred"
    const out = terminalText(styler(true).ok(hostile))
    expect(out).toBe("\u001b[32mre[ZWSP U+200B]ads\\u001B[2K\\u001B[31mred\u001b[0m")
    const escapes = out.match(/\u001b\[[0-9;]*m/g) ?? []
    expect(escapes).toEqual(["\u001b[32m", "\u001b[0m"])
  })

  test("nothing in a text field can become an escape: attacker text shaped like an old-style marker, an ESC sequence or a noncharacter stays plain", () => {
    const attacker = "\uFFFE[31mred \u001b[31mred \u001b[2K\u001b]0;title\u0007 \uFFFF \uFDD0 \u{1FFFE}"
    const out = terminalText(attacker)
    expect(out).not.toContain("\u001b")
    expect(out).toBe("[NONCHAR U+FFFE][31mred \\u001B[31mred \\u001B[2K\\u001B]0;title\\u0007 [NONCHAR U+FFFF] [NONCHAR U+FDD0] [NONCHAR U+1FFFE]")
    // Only a trusted segment is styled, and its text is spelled too.
    const line = segments(styler(true).ok("ok\uFFFE[31m"), " ", attacker)
    const styled = terminalText(line)
    expect(styled.match(/\u001b\[[0-9;]*m/g)).toEqual(["\u001b[32m", "\u001b[0m"])
    expect(styled).toStartWith("\u001b[32mok[NONCHAR U+FFFE][31m\u001b[0m ")
  })

  test("a style field is never read from text: a segment literal carrying codes in its text is plain", () => {
    expect(terminalText({ text: "\u001b[31mx" })).toBe("\\u001B[31mx")
    expect(terminalText([{ text: "a" }, { text: "b", style: "danger" }])).toBe("a\u001b[31mb\u001b[0m")
  })

  test("plain text is untouched", () => {
    for (const text of ["mehen: 200 OK", "  open:    https://vault.example/a/apr_1", "caf\u00e9 \u{1F512}", ""]) expect(terminalText(text)).toBe(text)
  })
})

describe("visibleText", () => {
  test("plain text, accents and emoji pass through unchanged", () => {
    for (const text of ["reads", "sends email as you", "/gmail/v1/users/*/messages/send", "caf\u00e9", "\u{1F512} locked", ""]) expect(visibleText(text)).toBe(text)
  })

  test("C0 and C1 controls, DEL, tab and newline are spelled as \\u00XX", () => {
    expect(visibleText("a\u001b[31mred\u001b[0m")).toBe("a\\u001B[31mred\\u001B[0m")
    expect(visibleText("line\nnext\r\tx\u0000\u007f\u0085\u009b")).toBe("line\\u000Anext\\u000D\\u0009x\\u0000\\u007F\\u0085\\u009B")
  })

  test("bidi overrides, zero-width and other hidden characters become named markers", () => {
    expect(visibleText("pay\u202eexe.fdp")).toBe("pay[RLO U+202E]exe.fdp")
    expect(visibleText("re\u200bads")).toBe("re[ZWSP U+200B]ads")
    expect(visibleText("\ufeffx\u2066y\u2069")).toBe("[BOM U+FEFF]x[LRI U+2066]y[PDI U+2069]")
    expect(visibleText("a\u00adb")).toBe("a[SHY U+00AD]b")
    expect(visibleText("\u2028")).toBe("[LS U+2028]")
    expect(visibleText("\u{E0041}")).toBe("[TAG U+E0041]")
    expect(visibleText("\u{E0001}")).toBe("[LANGTAG U+E0001]")
  })

  test("every other default ignorable character is a named marker, as on the vault's cards", () => {
    expect(visibleText("attached.A\u{E0100}\u{E011F}\uFE00")).toBe("attached.A[VS U+E0100][VS U+E011F][VS U+FE00]")
    expect(visibleText("A\uFE0E")).toBe("A[VS U+FE0E]")
    expect(visibleText("\u115F\u1160\u3164\uFFA0")).toBe("[HF U+115F][HF U+1160][HF U+3164][HF U+FFA0]")
    expect(visibleText("a\u180Bb\u180Fc")).toBe("a[FVS U+180B]b[FVS U+180F]c")
    expect(visibleText("a\u034Fb")).toBe("a[CGJ U+034F]b")
    expect(visibleText("a\u17B4b\u{1D173}")).toBe("a[FORMAT U+17B4]b[FORMAT U+1D173]")
  })

  test("one presentation selector after a pictograph, or after a digit, # or * a keycap follows, is left alone", () => {
    for (const text of ["\u2764\uFE0F", "\u263A\uFE0E", "1\uFE0F\u20E3", "#\uFE0F\u20E3", "\u{1F441}\uFE0F"]) expect(visibleText(text)).toBe(text)
    expect(visibleText("\u2764\uFE0F\uFE0F")).toBe("\u2764\uFE0F[VS U+FE0F]")
    expect(visibleText("Invoice 4\uFE0F2\uFE0E")).toBe("Invoice 4[VS U+FE0F]2[VS U+FE0E]")
    expect(visibleText("\u0001\uFE0F\u20E3")).toBe("\\u0001[VS U+FE0F]\u20E3")
  })

  test("format characters that carry meaning in their scripts are left alone", () => {
    expect(visibleText("\u0600\u06dd\u070f")).toBe("\u0600\u06dd\u070f")
  })

  test("a marker written in the text is not itself a hidden character and stays as written", () => {
    expect(visibleText("[RLO U+202E]")).toBe("[RLO U+202E]")
  })

  test("every Unicode noncharacter is spelled out", () => {
    expect(visibleText("\uFFFE")).toBe("[NONCHAR U+FFFE]")
    expect(visibleText("\uFFFF")).toBe("[NONCHAR U+FFFF]")
    expect(visibleText("\uFDD0\uFDEF")).toBe("[NONCHAR U+FDD0][NONCHAR U+FDEF]")
    expect(visibleText("\u{1FFFE}\u{1FFFF}\u{10FFFE}\u{10FFFF}")).toBe("[NONCHAR U+1FFFE][NONCHAR U+1FFFF][NONCHAR U+10FFFE][NONCHAR U+10FFFF]")
    expect(visibleText("\uFDCF\uFDF0")).toBe("\uFDCF\uFDF0")
  })
})

describe("terminal size and QR", () => {
  const link = "https://app.mehen.dev/e/K7Q2MXAB"

  test("terminalColumns is null off a TTY", () => {
    expect(terminalColumns(tty)).toBe(120)
    expect(terminalColumns(pipe)).toBeNull()
    expect(terminalColumns({ isTTY: true })).toBeNull()
  })

  test("a version 3 link with the quiet zone is 37 columns wide", () => {
    expect(qrWidth(link)).toBe(37)
  })

  test("the scheme comes from MEHEN_QR, then COLORFGBG, then defaults to dark", () => {
    expect(qrScheme({})).toBe("dark")
    expect(qrScheme({ COLORFGBG: "15;0" })).toBe("dark")
    expect(qrScheme({ COLORFGBG: "0;15" })).toBe("light")
    expect(qrScheme({ COLORFGBG: "0;7" })).toBe("light")
    expect(qrScheme({ COLORFGBG: "default;default;0" })).toBe("dark")
    expect(qrScheme({ COLORFGBG: "0;15", MEHEN_QR: "dark" })).toBe("dark")
    expect(qrScheme({ MEHEN_QR: "light" })).toBe("light")
  })

  test("a QR is drawn only on a TTY that is wide enough, unless MEHEN_QR=0 or --no-qr", () => {
    expect(qrChoice(tty, {}, link)).toEqual({ scheme: "dark" })
    expect(qrChoice(tty, { COLORFGBG: "0;15" }, link)).toEqual({ scheme: "light" })
    expect(qrChoice(pipe, {}, link)).toBeNull()
    expect(qrChoice(tty, { MEHEN_QR: "0" }, link)).toBeNull()
    expect(qrChoice(tty, {}, link, { noQr: true })).toBeNull()
    expect(qrChoice({ isTTY: true, columns: 36 }, {}, link)).toBeNull()
    expect(qrChoice({ isTTY: true, columns: 37 }, {}, link)).toEqual({ scheme: "dark" })
    expect(qrChoice({ isTTY: true, columns: 37 }, {}, link, { indent: 2 })).toBeNull()
    expect(qrChoice({ isTTY: true, columns: 39 }, {}, link, { indent: 2 })).toEqual({ scheme: "dark" })
  })

  test("a link too long for any code mehen draws gets no QR rather than an error", () => {
    expect(qrChoice(tty, {}, `https://vault.example/a/${"x".repeat(300)}`)).toBeNull()
  })
})
