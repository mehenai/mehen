// Approval cards make text that renders differently from what is sent
// visible: every format character that hides or reorders text is shown as
// a marker naming it, where it sits, in every string a human reads, and
// the card warns once. Display only: the digests are over the request as
// sent (test/h10-review4.test.ts proves that through the relay).

import { describe, expect, it } from "vitest"
import { OAUTH_PROVIDERS, base64UrlEncode, connectionPolicy, parseDestination, utf8 } from "@mehen/protocol"
import { CONTROL_WARNING, DECEPTIVE_MARKER, DECEPTIVE_WARNING, escapeDeceptiveJson, presentRequest, spellCardText, spellDeceptive, textWarnings } from "../src/relay/presentation.ts"
import { titlePieces, titleRanges } from "../src/ui/client/palette-logic.ts"
import type { ItemRecord } from "../src/vault/services.ts"

const item = {
  id: "itm_x",
  slug: "slack-bot",
  kind: "api-key",
  provider: "slack-bot",
  account: null,
  accountVerified: false,
  tags: [],
  ceiling: "placeholder",
  binding: { hosts: ["slack.com"] },
  policy: { default: "approve", rules: [] },
  injection: null,
  publicFields: {},
  status: "active",
  version: 1,
  description: null,
  createdAt: 0,
  updatedAt: 0,
} as unknown as ItemRecord

const GMAIL = OAUTH_PROVIDERS["google-gmail"]
if (!GMAIL) throw new Error("google-gmail")

const gmailItem = {
  ...item,
  id: "itm_g",
  slug: "gmail-alex",
  kind: "oauth-connection",
  provider: "google-gmail",
  account: "alex@example.com",
  accountVerified: true,
  binding: GMAIL.upstream.binding,
  policy: connectionPolicy(GMAIL),
  injection: GMAIL.upstream.injection,
} as unknown as ItemRecord

async function card(text: string, headers: [string, string][] = [], contentType = "application/json") {
  const url = new URL("https://slack.com/api/chat.postMessage")
  const parsed = parseDestination("POST", url.href)
  if (!parsed.ok) throw new Error("bad destination")
  return presentRequest(item, parsed.destination, url, utf8(text), contentType, headers)
}

async function gmailCard(message: string) {
  const url = new URL("https://gmail.googleapis.com/gmail/v1/users/me/messages/send")
  const parsed = parseDestination("POST", url.href)
  if (!parsed.ok) throw new Error("bad destination")
  const body = utf8(JSON.stringify({ raw: base64UrlEncode(utf8(message)) }))
  return presentRequest(gmailItem, parsed.destination, url, body, "application/json", [["content-type", "application/json"]])
}

// Every character the card must mark, with the marker it gets.
const MARKED: [string, string][] = [
  ["\u00AD", "[SHY U+00AD]"],
  ["\u061C", "[ALM U+061C]"],
  ["\u180E", "[MVS U+180E]"],
  ["\u200B", "[ZWSP U+200B]"],
  ["\u200C", "[ZWNJ U+200C]"],
  ["\u200D", "[ZWJ U+200D]"],
  ["\u200E", "[LRM U+200E]"],
  ["\u200F", "[RLM U+200F]"],
  ["\u2028", "[LS U+2028]"],
  ["\u2029", "[PS U+2029]"],
  ["\u202A", "[LRE U+202A]"],
  ["\u202B", "[RLE U+202B]"],
  ["\u202C", "[PDF U+202C]"],
  ["\u202D", "[LRO U+202D]"],
  ["\u202E", "[RLO U+202E]"],
  ["\u2060", "[WJ U+2060]"],
  ["\u2061", "[FA U+2061]"],
  ["\u2062", "[IT U+2062]"],
  ["\u2063", "[IS U+2063]"],
  ["\u2064", "[IP U+2064]"],
  ["\u2066", "[LRI U+2066]"],
  ["\u2067", "[RLI U+2067]"],
  ["\u2068", "[FSI U+2068]"],
  ["\u2069", "[PDI U+2069]"],
  ["\u206A", "[ISS U+206A]"],
  ["\u206F", "[NODS U+206F]"],
  ["\uFEFF", "[BOM U+FEFF]"],
  ["\uFFF9", "[IAA U+FFF9]"],
  ["\uFFFB", "[IAT U+FFFB]"],
  ["\u{E0001}", "[LANGTAG U+E0001]"],
  ["\u{E0067}", "[TAG U+E0067]"],
  ["\u{E007F}", "[CANCELTAG U+E007F]"],
  ["\u{1D173}", "[FORMAT U+1D173]"],
  ["\u{1BCA0}", "[FORMAT U+1BCA0]"],
  ["\uFE00", "[VS U+FE00]"],
  ["\uFE0F", "[VS U+FE0F]"],
  ["\u{E0100}", "[VS U+E0100]"],
  ["\u{E01EF}", "[VS U+E01EF]"],
  ["\u034F", "[CGJ U+034F]"],
  ["\u115F", "[HF U+115F]"],
  ["\u3164", "[HF U+3164]"],
  ["\uFFA0", "[HF U+FFA0]"],
  ["\u180B", "[FVS U+180B]"],
  ["\u17B4", "[FORMAT U+17B4]"],
]

// The format characters (Cf) the card leaves alone, every one: they render
// as a visible mark over the digits or text after them, so they hide
// nothing. Each is listed so the exclusion is explicit.
const VISIBLE_FORMAT = ["\u0600", "\u0601", "\u0602", "\u0603", "\u0604", "\u0605", "\u06DD", "\u070F", "\u0890", "\u0891", "\u08E2", "\u{110BD}", "\u{110CD}"]

// Text that must stay as it is: the visible format marks, emoji built
// without a joiner, combining and variation marks, and a literal marker
// typed as text.
const UNMARKED = [...VISIBLE_FORMAT.map((c) => `${c}1`), "👍🏽", "🇬🇧", "❤\uFE0F", "\u263A\uFE0E", "1\uFE0F\u20E3", "👁\uFE0F", "e\u0301", "[RLO U+202E]", "hello world, café"]

const MIXED = "Pay the \u202Efdp.exe\u202C invoice\u200B now\u2028please"

describe("spellDeceptive marks every character that hides or reorders text", () => {
  it("marks each character where it sits and keeps the text around it", () => {
    for (const [c, marker] of MARKED) {
      expect(spellDeceptive(`ab${c}cd`)).toBe(`ab${marker}cd`)
      expect(marker).toMatch(DECEPTIVE_MARKER)
    }
  })

  it("leaves ordinary text, visible format marks, emoji without a joiner and a literal marker alone", () => {
    for (const text of UNMARKED) expect(spellDeceptive(text)).toBe(text)
  })

  it("excludes exactly the visible format marks, and every one of them is a format character", () => {
    for (const c of VISIBLE_FORMAT) {
      expect(/^\p{Cf}$/u.test(c)).toBe(true)
      expect(spellDeceptive(c)).toBe(c)
    }
    expect(spellDeceptive("\u{E0000}")).toBe("[FORMAT U+E0000]")
  })

  it("keeps the visible text of a mixed string intact around the markers", () => {
    expect(spellDeceptive(MIXED)).toBe("Pay the [RLO U+202E]fdp.exe[PDF U+202C] invoice[ZWSP U+200B] now[LS U+2028]please")
  })

  it("is idempotent: spelling spelled text changes nothing, so a stored card can be spelled again at render", () => {
    for (const text of [MIXED, "a\u0000b\u202Ec", ...MARKED.map(([c]) => `x${c}y`)]) {
      const once = spellCardText(text)
      expect(spellCardText(once)).toBe(once)
      expect(once).not.toMatch(/[^\x20-\x7E]/u)
    }
  })

  it("marks the joiners inside an emoji sequence, so a family emoji reads as its parts", () => {
    expect(spellDeceptive("👨\u200D👩\u200D👧 at home")).toBe("👨[ZWJ U+200D]👩[ZWJ U+200D]👧 at home")
    expect(spellDeceptive("🏴\u{E0067}\u{E0062}\u{E007F}")).toBe("🏴[TAG U+E0067][TAG U+E0062][CANCELTAG U+E007F]")
  })

  it("marks a run of variation selectors, even after an emoji, where only one presentation selector picks how the emoji is drawn", () => {
    expect(spellDeceptive("❤\uFE0F\uFE0F")).toBe("❤\uFE0F[VS U+FE0F]")
    expect(spellDeceptive("A\uFE0E")).toBe("A[VS U+FE0E]")
    expect(spellDeceptive("attached.A\u{E0100}\u{E0101}")).toBe("attached.A[VS U+E0100][VS U+E0101]")
  })

  it("leaves a presentation selector alone only after a pictograph, or after a digit, # or * that a keycap follows", () => {
    expect(spellDeceptive("1\uFE0F")).toBe("1[VS U+FE0F]")
    expect(spellDeceptive("1\uFE0F\u20E3")).toBe("1\uFE0F\u20E3")
    expect(spellDeceptive("\u2764\uFE0F")).toBe("\u2764\uFE0F")
    expect(spellDeceptive("Invoice 4\uFE0F2\uFE0E")).toBe("Invoice 4[VS U+FE0F]2[VS U+FE0E]")
    expect(textWarnings(["Invoice 4\uFE0F2\uFE0E"])).toEqual([DECEPTIVE_WARNING])
  })

  it("spellCardText decides what to mark on the text as sent, so a warning never comes without a marker", () => {
    expect(spellCardText("\u0001\uFE0F")).toBe("\\u0001[VS U+FE0F]")
    expect(spellCardText("\u0001\uFE0F\u20E3")).toBe("\\u0001[VS U+FE0F]\u20E3")
    expect(textWarnings(["\u0001\uFE0F\u20E3"])).toEqual([DECEPTIVE_WARNING, CONTROL_WARNING])
  })

  it("the palette decides what to mark on the whole title, so a highlight never marks a selector the title leaves alone", () => {
    for (const [title, query] of [["Key 1\uFE0F\u20E3", "1"], ["Key \u2764\uFE0F set", "\u2764"], ["Key 1\uFE0F\u20E3", "key"]] as const) {
      const pieces = titlePieces(title, titleRanges(title, query))
      expect(pieces.map((p) => p.text).join(""), query).toBe(title)
      expect(pieces.filter((p) => p.kind === "marker"), query).toEqual([])
    }
    expect(titlePieces("Key 1\uFE0F", titleRanges("Key 1\uFE0F", "1"))).toEqual([{ kind: "text", text: "Key " }, { kind: "match", text: "1" }, { kind: "marker", text: "[VS U+FE0F]" }])
  })

  it("spellCardText spells controls and marks deceptive characters together", () => {
    expect(spellCardText("a\u0000b\u202Ec")).toBe("a\\u0000b[RLO U+202E]c")
  })
})

describe("approval cards show hidden characters and warn once", () => {
  it("marks the character in a generic body and warns", async () => {
    for (const [c, marker] of MARKED) {
      const shown = await card(JSON.stringify({ channel: "C1", text: `hello${c}world` }))
      expect(shown.body).toContain(`hello${marker}world`)
      expect(shown.body).not.toContain(c)
      expect(shown.warnings).toEqual([DECEPTIVE_WARNING])
    }
  })

  it("adds nothing for ordinary text, including emoji without a joiner", async () => {
    for (const text of UNMARKED) {
      const shown = await card(JSON.stringify({ channel: "C1", text }))
      expect(shown.warnings ?? []).toEqual([])
      expect(shown.body).toBe(JSON.stringify({ channel: "C1", text }, null, 2))
    }
  })

  it("marks and warns about variation selectors hidden in a plain-text body", async () => {
    const selectors = ["\u{E0100}", "\u{E011F}", "\uFE00", "\uFE0F"]
    const shown = await card(`Quarterly figures attached.A${selectors.join("")}`, [], "text/plain")
    expect(shown.warnings).toEqual([DECEPTIVE_WARNING])
    expect(shown.body).toBe("Quarterly figures attached.A[VS U+E0100][VS U+E011F][VS U+FE00][VS U+FE0F]")
  })

  it("a family emoji in the body is marked and warned about, deliberately", async () => {
    const shown = await card(JSON.stringify({ channel: "C1", text: "👨\u200D👩\u200D👧" }))
    expect(shown.body).toContain("👨[ZWJ U+200D]👩[ZWJ U+200D]👧")
    expect(shown.warnings).toEqual([DECEPTIVE_WARNING])
  })

  it("control characters alone earn only the control warning, and both together earn both", async () => {
    const controls = await card("a\u0001b", [], "text/plain")
    expect(controls.warnings).toEqual([CONTROL_WARNING])
    const both = await card("a\u0001b\u200Bc", [], "text/plain")
    expect(both.warnings).toEqual([DECEPTIVE_WARNING, CONTROL_WARNING])
    expect(both.body).toBe("a\\u0001b[ZWSP U+200B]c")
  })

  it("spells C1 control characters in a JSON string value as \\u00XX and warns, as it does C0 ones", async () => {
    const shown = await card(JSON.stringify({ channel: "C1", text: "a\u0085b\u009Bc\u0001d" }))
    expect(shown.body).toContain("a\\u0085b\\u009Bc\\u0001d")
    for (const c of ["\u0085", "\u009B", "\u0001"]) expect(shown.body).not.toContain(c)
    expect(shown.warnings).toEqual([CONTROL_WARNING])
    expect(spellCardText("\u0080\u009F")).toBe("\\u0080\\u009F")
    expect(textWarnings(["x\u0085"])).toEqual([CONTROL_WARNING])
    expect(spellCardText("caf\u00E9\u00A0\u00FF ok")).toBe("caf\u00E9\u00A0\u00FF ok")
    expect(textWarnings(["caf\u00E9\u00A0\u00FF ok"])).toEqual([])
  })

  it("marks the subject, a recipient, a header value, a body excerpt and the whole message of an email", async () => {
    const message = ["From: alex@example.com", "To: bo\u200Bb@example.com", "Subject: Invoice \u202Efdp.exe", "X-Note: st\uFEFFart", "", "Pay\u2066 now"].join("\r\n")
    const shown = await gmailCard(message)
    expect(shown.warnings).toEqual([DECEPTIVE_WARNING])
    expect(shown.email?.recipients).toEqual([{ header: "To", address: "bo[ZWSP U+200B]b@example.com", external: false }])
    expect(shown.email?.headers.find((h) => h.name === "Subject")?.value).toBe("Invoice [RLO U+202E]fdp.exe")
    expect(shown.email?.headers.find((h) => h.name === "X-Note")?.value).toBe("st[BOM U+FEFF]art")
    expect(shown.email?.sections[0]?.text).toBe("Pay[LRI U+2066] now")
    expect(shown.body).toContain("Subject: Invoice [RLO U+202E]fdp.exe")
    expect(shown.body).toContain("Pay[LRI U+2066] now")
    for (const c of ["\u200B", "\u202E", "\uFEFF", "\u2066"]) expect(JSON.stringify(shown)).not.toContain(c)
  })

  it("keeps the forwarded headers as sent for the digest, and marks every other string", async () => {
    const headers: [string, string][] = [["x-note", "a\u200Bb"]]
    const shown = await card(JSON.stringify({ text: "ok" }), headers)
    expect(shown.headers).toEqual(headers)
    expect(shown.warnings).toEqual([DECEPTIVE_WARNING])
    expect(spellCardText(shown.headers?.[0]?.[1] ?? "")).toBe("a[ZWSP U+200B]b")
  })
})

// ---------------------------------------------------------------- the page, for cards presentRequest did not build

// A marker the page generated, as the approval page styles it (cardText).

describe("escapeDeceptiveJson", () => {
  it("escapes each deceptive character as \\uXXXX, surrogate pairs included, and parses back unchanged", () => {
    const value = { text: "a\u202Eb\u{E0067}c", headers: [["x", "\u200B"]] }
    const escaped = escapeDeceptiveJson(JSON.stringify(value))
    expect(escaped).toBe('{"text":"a\\u202Eb\\uDB40\\uDC67c","headers":[["x","\\u200B"]]}')
    expect(JSON.parse(escaped)).toEqual(value)
  })
})
