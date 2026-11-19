import { describe, expect, test } from "bun:test"
import { LEASE_ONLY_HOST } from "./binding.ts"
import { FillRequestSchema, FillResponseSchema, ItemBrowserSchema, fillOrigin, fillSealContext, signinOriginSources, signinOrigins, typeIntoOrigins } from "./fill.ts"
import { generateSealKeyPair, importSealPublicKey, open, seal } from "./seal.ts"
import { fromUtf8 } from "./bytes.ts"
import { ERROR_CODES, EXIT, EXIT_FOR_ERROR, HTTP_STATUS_FOR_ERROR } from "./api.ts"
import { PrivateEventSchema } from "./workspace.ts"

describe("fillOrigin", () => {
  test("an https address becomes its origin: lower case, no path, no default port", () => {
    expect(fillOrigin("https://github.com/login?return_to=%2F#x")).toBe("https://github.com")
    expect(fillOrigin("https://GitHub.COM/")).toBe("https://github.com")
    expect(fillOrigin("HTTPS://github.com")).toBe("https://github.com")
    expect(fillOrigin("https://github.com:443/login")).toBe("https://github.com")
    expect(fillOrigin("https://intranet.example.com:8443/sign-in")).toBe("https://intranet.example.com:8443")
  })

  test("only https", () => {
    for (const url of ["http://github.com", "wss://github.com", "ftp://github.com", "javascript:alert(1)", "data:text/html,x", "github.com", "//github.com", "https:github.com", "https:/github.com"]) expect({ url, origin: fillOrigin(url) }).toEqual({ url, origin: null })
  })

  test("no userinfo, not even an empty one", () => {
    for (const url of ["https://alex@github.com", "https://alex:pw@github.com", "https://@github.com", "https://:@github.com", "https://github.com@evil.example"]) expect({ url, origin: fillOrigin(url) }).toEqual({ url, origin: null })
  })

  test("IP literals are refused in every spelling", () => {
    for (const url of ["https://127.0.0.1", "https://127.1", "https://0x7f.0.0.1", "https://2130706433", "https://[::1]", "https://[::ffff:127.0.0.1]:8443", "https://192.168.1.10:8443/login"]) expect({ url, origin: fillOrigin(url) }).toEqual({ url, origin: null })
  })

  test("international names become punycode, and an escaped host reads as what it spells", () => {
    expect(fillOrigin("https://Bücher.example/anmelden")).toBe("https://xn--bcher-kva.example")
    expect(fillOrigin("https://xn--bcher-kva.example")).toBe("https://xn--bcher-kva.example")
    expect(fillOrigin("https://ex%41mple.com")).toBe("https://example.com")
  })

  test("ports: any explicit one but 443 is kept, port 0 is refused", () => {
    expect(fillOrigin("https://example.com:1")).toBe("https://example.com:1")
    expect(fillOrigin("https://example.com:65535")).toBe("https://example.com:65535")
    expect(fillOrigin("https://example.com:0")).toBeNull()
    expect(fillOrigin("https://example.com:65536")).toBeNull()
  })

  test("wildcards, single labels, trailing dots and odd characters are refused", () => {
    for (const url of ["https://*.example.com", "https://example.com.", "https://a_b.example.com", "https://-a.example.com", "https://a-.example.com", "https://exa mple.com", "https://", "not a url", ""]) expect({ url, origin: fillOrigin(url) }).toEqual({ url, origin: null })
    expect(fillOrigin(`https://${Array.from({ length: 5 }, () => "a".repeat(60)).join(".")}`)).toBeNull()
    expect(fillOrigin("https://intranet/sign-in")).toBe("https://intranet")
  })
})

describe("sign-in and other pages", () => {
  const item = (overrides: Partial<Parameters<typeof signinOrigins>[0]> = {}) => ({ publicFields: { url: "https://github.com/login" }, binding: { hosts: ["github.com", "api.github.com"] }, browser: null, ...overrides })

  test("sign-in pages: the sign-in address, then exact binding hosts, then the ones a human added, each once", () => {
    expect(signinOrigins(item({ browser: { signinOrigins: ["https://github.com", "https://gist.github.com"], typeInto: [] } }))).toEqual(["https://github.com", "https://api.github.com", "https://gist.github.com"])
    expect(signinOriginSources(item({ browser: { signinOrigins: ["https://github.com", "https://gist.github.com"], typeInto: [] } }))).toEqual([{ origin: "https://github.com", source: "address" }, { origin: "https://api.github.com", source: "hosts" }, { origin: "https://gist.github.com", source: "added" }])
    expect(signinOriginSources(item({ publicFields: { url: "http://github.com" }, browser: { signinOrigins: ["https://github.com"], typeInto: [] } }))).toEqual([{ origin: "https://github.com", source: "hosts" }, { origin: "https://api.github.com", source: "hosts" }])
  })

  test("wildcard hosts, the lease-only host and IP hosts are never sign-in pages", () => {
    expect(signinOrigins(item({ publicFields: {}, binding: { hosts: ["*.github.com", LEASE_ONLY_HOST, "10.0.0.1", "[::1]", "github.com"] } }))).toEqual(["https://github.com"])
    expect(signinOrigins(item({ publicFields: {}, binding: { hosts: [LEASE_ONLY_HOST] } }))).toEqual([])
  })

  test("a sign-in address that is not https gives no sign-in page", () => {
    expect(signinOrigins(item({ publicFields: { url: "http://github.com/login" }, binding: { hosts: [LEASE_ONLY_HOST] } }))).toEqual([])
  })

  test("other services' pages are only the ones a human listed", () => {
    expect(typeIntoOrigins(item())).toEqual([])
    expect(typeIntoOrigins(item({ browser: { signinOrigins: [], typeInto: ["https://dash.cloudflare.com"] } }))).toEqual(["https://dash.cloudflare.com"])
    expect(signinOrigins(item({ binding: { hosts: [LEASE_ONLY_HOST] }, publicFields: {}, browser: { signinOrigins: [], typeInto: ["https://dash.cloudflare.com"] } }))).toEqual([])
  })

  test("an item's pages are canonical origins, at most 8 of each, each once", () => {
    expect(ItemBrowserSchema.parse({ signinOrigins: ["https://github.com"], typeInto: ["https://dash.cloudflare.com:8443"] })).toEqual({ signinOrigins: ["https://github.com"], typeInto: ["https://dash.cloudflare.com:8443"] })
    for (const origin of ["https://GitHub.com", "https://github.com/", "https://github.com:443", "http://github.com", "https://*.github.com", "https://127.0.0.1", "https://alex@github.com"]) expect({ origin, ok: ItemBrowserSchema.safeParse({ signinOrigins: [origin], typeInto: [] }).success }).toEqual({ origin, ok: false })
    const nine = Array.from({ length: 9 }, (_, n) => `https://s${n}.example.com`)
    expect(ItemBrowserSchema.safeParse({ signinOrigins: nine, typeInto: [] }).success).toBe(false)
    expect(ItemBrowserSchema.safeParse({ signinOrigins: [], typeInto: nine }).success).toBe(false)
    expect(ItemBrowserSchema.safeParse({ signinOrigins: ["https://github.com", "https://github.com"], typeInto: [] }).success).toBe(false)
    expect(ItemBrowserSchema.safeParse({ signinOrigins: [], typeInto: [], extra: true }).success).toBe(false)
  })
})

describe("fill's refusals", () => {
  test("a page outside the item's lists is refused, and an unreadable one-time code secret needs a person", () => {
    expect(ERROR_CODES).toContain("origin_mismatch")
    expect(ERROR_CODES).toContain("totp_unreadable")
    expect([EXIT_FOR_ERROR.origin_mismatch, HTTP_STATUS_FOR_ERROR.origin_mismatch]).toEqual([EXIT.refused, 403])
    expect([EXIT_FOR_ERROR.totp_unreadable, HTTP_STATUS_FOR_ERROR.totp_unreadable]).toEqual([EXIT.human, 400])
  })
})

describe("a private credential's fill in its owner's audit", () => {
  const event = { action: "item.fill", at: 1, actor: { kind: "device" as const, device: "dev_one", owner: { kind: "member" as const, member: "mem_one" } }, session: null, item: "itm_one", slug: "github-login", outcome: "typed", run: null }
  test("carries the origin and the field, and nothing else of the page", () => {
    expect(PrivateEventSchema.parse(event)).toEqual(event)
    expect(PrivateEventSchema.parse({ ...event, browser: { origin: "https://github.com", field: "password" } }).browser).toEqual({ origin: "https://github.com", field: "password" })
    for (const browser of [{ origin: "https://github.com", field: "password", page: "/login" }, { origin: "https://github.com", field: "Password" }, { origin: "https://github.com" }])
      expect(PrivateEventSchema.safeParse({ ...event, browser }).success).toBe(false)
  })
})

describe("fill requests and answers", () => {
  const recipient = { kty: "EC", crv: "P-256", x: "a".repeat(43), y: "b".repeat(43) }
  const request = { item: "github-alex", field: "password", origin: "https://github.com", page: "/login", recipient }

  test("a request names the page by path only, with no query", () => {
    expect(FillRequestSchema.parse({ ...request, context: { project: "prj_a", environment: "dev" }, approval: "apr_abc" })).toMatchObject({ page: "/login", approval: "apr_abc" })
    for (const page of ["/login?next=/", "/login#x", "login", "", "/a b", `/${"a".repeat(512)}`, "/\\evil"]) expect({ page, ok: FillRequestSchema.safeParse({ ...request, page }).success }).toEqual({ page, ok: false })
  })

  test("a page path is RFC 3986 path characters only, so nothing a card or the audit shows can hide or spoof a host", () => {
    for (const page of ["/", "/login", "/session/new", "/a-b_c.d~e", "/u/alex@example.com", "/x;y=z,w+v!$&'()*:", "/caf%C3%A9", `/${"a".repeat(511)}`]) expect({ page, ok: FillRequestSchema.safeParse({ ...request, page }).success }).toEqual({ page, ok: true })
    for (const page of ["//evil.example/login", "///login", "/log\u0000in", "/log\u0007in", "/log\u007fin", "/log\u0085in", "/log\u202ein", "/log\u2066in", "/log\u200bin", "/caf\u00e9", "/a\tb", "/a\nb", "/a<b>", "/a\"b", "/a`b", "/a{b}", "/a|b", "/a^b", "/a[b]"]) expect({ page, ok: FillRequestSchema.safeParse({ ...request, page }).success }).toEqual({ page, ok: false })
    expect(FillRequestSchema.safeParse({ ...request, origin: "https://github.com/login" }).success).toBe(false)
    expect(FillRequestSchema.safeParse({ ...request, approval: "rul_abc" }).success).toBe(false)
    expect(FillRequestSchema.safeParse({ ...request, extra: 1 }).success).toBe(false)
    const { recipient: _r, ...missing } = request
    expect(FillRequestSchema.safeParse(missing).success).toBe(false)
  })

  test("an answer carries a sealed box, says what it is, and how it was allowed", async () => {
    const keys = await generateSealKeyPair()
    const context = fillSealContext({ workspace: "tn_abc", item: "itm_1", field: "password", origin: "https://github.com", jti: "jti-1" })
    expect(context).toBe("fill/v1/tn_abc/itm_1/password/https://github.com/jti-1")
    const box = await seal(await importSealPublicKey(await crypto.subtle.exportKey("jwk", keys.publicKey)), "hunter2", context)
    const answer = FillResponseSchema.parse({ box, item: "itm_1", field: "password", input: "password", label: "the password for alex@example.com", origin: "https://github.com", by: { approval: "apr_abc" } })
    expect(fromUtf8(await open(keys.privateKey, answer.box, context))).toBe("hunter2")
    await expect(open(keys.privateKey, answer.box, fillSealContext({ workspace: "tn_abc", item: "itm_1", field: "password", origin: "https://evil.example", jti: "jti-1" }))).rejects.toThrow()
    await expect(open(keys.privateKey, answer.box, fillSealContext({ workspace: "tn_abc", item: "itm_1", field: "password", origin: "https://github.com", jti: "jti-2" }))).rejects.toThrow()
    for (const by of [{ rule: "rul_x" }, { free: true }]) expect(FillResponseSchema.safeParse({ ...answer, by }).success).toBe(true)
    expect(FillResponseSchema.safeParse({ ...answer, input: "one-time-code", validUntil: "2026-11-05T10:00:30.000Z" }).success).toBe(true)
    for (const by of [{ free: false }, { approval: "rul_x" }, {}]) expect(FillResponseSchema.safeParse({ ...answer, by }).success).toBe(false)
    expect(FillResponseSchema.safeParse({ ...answer, input: "email" }).success).toBe(false)
  })

  test("an answer names the item's id, which the machine needs to open the box", () => {
    const box = { v: 1, epk: { kty: "EC", crv: "P-256", x: "a".repeat(43), y: "b".repeat(43) }, iv: "a".repeat(16), ct: "b".repeat(24) }
    const answer = { box, item: "itm_Abc-123_x", field: "password", input: "password", label: "the password for alex@example.com", origin: "https://github.com", by: { free: true } }
    expect(FillResponseSchema.parse(answer).item).toBe("itm_Abc-123_x")
    const { item: _item, ...missing } = answer
    expect(FillResponseSchema.safeParse(missing).success).toBe(false)
    for (const item of ["github-alex", "itm_", "itm_a/b", "dev_abc", `itm_${"a".repeat(61)}`]) expect({ item, ok: FillResponseSchema.safeParse({ ...answer, item }).success }).toEqual({ item, ok: false })
  })
})
