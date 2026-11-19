import { describe, expect, test } from "bun:test"
import { canonicalJson } from "./api.ts"
import { KINDS, MODES, deviceModeAllowed, formatReference, isItemKind, isSlug, modeAllowed, parseReference } from "./kinds.ts"

describe("kinds", () => {
  test("every kind's default ceiling sits at or below its maximum", () => {
    for (const spec of Object.values(KINDS)) {
      expect({ kind: spec.kind, ok: modeAllowed(spec.maxCeiling, spec.defaultCeiling) }).toEqual({ kind: spec.kind, ok: true })
    }
  })

  test("primary fields exist and are secret", () => {
    for (const spec of Object.values(KINDS)) {
      if (spec.primary === null) continue
      const field = spec.fields.find((f) => f.name === spec.primary)
      expect({ kind: spec.kind, secret: field?.secret }).toEqual({ kind: spec.kind, secret: true })
    }
  })

  test("the ladder is ordered and ceilings compare by rank", () => {
    expect(MODES).toEqual(["relay", "sign", "mint", "placeholder", "fill", "lease", "reveal"])
    expect(modeAllowed("placeholder", "relay")).toBe(true)
    expect(modeAllowed("placeholder", "lease")).toBe(false)
    expect(modeAllowed("relay", "reveal")).toBe(false)
    expect(modeAllowed("placeholder", "fill")).toBe(false)
    expect(modeAllowed("fill", "placeholder")).toBe(true)
    expect(modeAllowed("fill", "lease")).toBe(false)
    expect(modeAllowed("lease", "fill")).toBe(true)
  })

  test("a device fills only under a ceiling of exactly fill or lease, so reveal gives it nothing new", () => {
    expect(MODES.filter((ceiling) => deviceModeAllowed(ceiling, "fill"))).toEqual(["fill", "lease"])
    expect(deviceModeAllowed("reveal", "fill")).toBe(false)
    expect(MODES.filter((wanted) => deviceModeAllowed("reveal", wanted))).toEqual(["relay", "sign", "mint", "placeholder"])
    expect(MODES.filter((wanted) => deviceModeAllowed("fill", wanted))).toEqual(["relay", "sign", "mint", "placeholder", "fill"])
    expect(MODES.filter((wanted) => deviceModeAllowed("lease", wanted))).toEqual(["relay", "sign", "mint", "placeholder", "fill", "lease"])
  })

  test("fill fields: sign-in fields on the two sign-in kinds, the primary value on three, nothing elsewhere", () => {
    const fills = Object.fromEntries(Object.values(KINDS).filter((spec) => spec.fill.length > 0).map((spec) => [spec.kind, spec.fill]))
    expect(fills).toEqual({
      "api-key": [{ name: "key", source: "key", input: "secret", signIn: false }],
      "bearer-token": [{ name: "token", source: "token", input: "secret", signIn: false }],
      generic: [{ name: "value", source: "value", input: "secret", signIn: false }],
      "password-login": [
        { name: "username", source: "username", input: "username", signIn: true },
        { name: "password", source: "password", input: "password", signIn: true },
        { name: "totp", source: "totp_seed", input: "one-time-code", signIn: true },
      ],
      totp: [{ name: "code", source: "seed", input: "one-time-code", signIn: true }],
    })
    for (const spec of Object.values(KINDS)) {
      for (const field of spec.fill) expect({ kind: spec.kind, source: field.source, stored: spec.fields.some((f) => f.name === field.source) }).toEqual({ kind: spec.kind, source: field.source, stored: true })
    }
  })

  test("defaults and maxima are unchanged by the fill rung", () => {
    expect(Object.fromEntries(Object.values(KINDS).map((spec) => [spec.kind, [spec.defaultCeiling, spec.maxCeiling]]))).toEqual({
      "api-key": ["placeholder", "lease"],
      "bearer-token": ["placeholder", "lease"],
      "basic-auth": ["relay", "lease"],
      "custom-headers": ["relay", "relay"],
      "oauth-client": ["relay", "relay"],
      "oauth-connection": ["relay", "mint"],
      "google-service-account": ["mint", "mint"],
      "github-app": ["mint", "mint"],
      "hmac-key": ["sign", "lease"],
      "ssh-key": ["sign", "sign"],
      "password-login": ["relay", "reveal"],
      totp: ["relay", "reveal"],
      "database-url": ["lease", "lease"],
      "smtp-imap": ["lease", "lease"],
      "cloud-access-key": ["lease", "lease"],
      file: ["lease", "lease"],
      note: ["reveal", "reveal"],
      generic: ["lease", "lease"],
    })
  })

  test("reveal is human-only: a reveal ceiling never lets a device lease, and a device never reveals", () => {
    expect(modeAllowed("reveal", "lease")).toBe(true)
    expect(deviceModeAllowed("reveal", "lease")).toBe(false)
    expect(deviceModeAllowed("lease", "lease")).toBe(true)
    for (const ceiling of MODES) expect({ ceiling, ok: deviceModeAllowed(ceiling, "reveal") }).toEqual({ ceiling, ok: false })
    expect(deviceModeAllowed("fill", "lease")).toBe(false)
    for (const wanted of ["relay", "sign", "mint", "placeholder"] as const) {
      for (const ceiling of MODES) expect({ ceiling, wanted, ok: deviceModeAllowed(ceiling, wanted) }).toEqual({ ceiling, wanted, ok: modeAllowed(ceiling, wanted) })
    }
    expect(deviceModeAllowed("placeholder", "lease")).toBe(false)
  })

  test("isItemKind refuses prototype keys", () => {
    expect(isItemKind("api-key")).toBe(true)
    expect(isItemKind("toString")).toBe(false)
    expect(isItemKind("__proto__")).toBe(false)
  })
})

describe("slugs and references", () => {
  test("slugs", () => {
    for (const s of ["gmail-alex", "openai-personal", "a1"]) expect(isSlug(s)).toBe(true)
    for (const s of ["", "a", "1abc", "Gmail", "a--b", "a-", "a_b", "a".repeat(65)]) expect(isSlug(s)).toBe(false)
  })

  test("references round trip and refuse anything loose", () => {
    expect(parseReference("mehen://openai-personal#key")).toEqual({ item: "openai-personal", field: "key" })
    expect(parseReference("mehen://gmail-alex")).toEqual({ item: "gmail-alex", field: null })
    for (const r of ["mehen://Gmail", "mehen://a--b", "mehen:/x", "mehen://gmail-alex#", "mehen://gmail-alex#Key", "mehen://x/../y", " mehen://gmail-alex"]) {
      expect({ r, parsed: parseReference(r) }).toEqual({ r, parsed: null })
    }
    expect(formatReference({ item: "a1", field: "key" })).toBe("mehen://a1#key")
  })
})

describe("canonicalJson", () => {
  test("sorts keys at every depth, drops undefined, keeps array order", () => {
    expect(canonicalJson({ b: 1, a: { d: [3, 1], c: undefined, b: null } })).toBe('{"a":{"b":null,"d":[3,1]},"b":1}')
    expect(canonicalJson("x")).toBe('"x"')
  })
})
