import { describe, expect, test } from "bun:test"
import {
  type Binding,
  type BindingCheck,
  type Destination,
  type Policy,
  type PolicyRule,
  checkBinding,
  customItemPolicy,
  evaluatePolicy,
  LEASE_ONLY_HOST,
  hostMatches,
  isLeaseOnly,
  isReadMethod,
  leaseOnlyBinding,
  parseDestination,
  pathMatches,
  pathMatchWork,
  pathPatternsOverlap,
  restrictivePathMayMeet,
  validHostPattern,
} from "./binding.ts"
import { BindingSchema, PolicySchema } from "./api.ts"
import { OAUTH_PROVIDERS, type OAuthProviderTemplate, TEMPLATES, connectionPolicy, getTemplate } from "./templates.ts"

function dest(url: string, method = "GET"): Destination {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`expected ${url} to parse, got ${parsed.error}`)
  return parsed.destination
}

function errorOf(url: string): string | null {
  const parsed = parseDestination("GET", url)
  return parsed.ok ? null : parsed.error
}

function bindingCheck(binding: Binding, url: string, method = "GET"): BindingCheck {
  return checkBinding(binding, dest(url, method))
}

const STRIPE: Binding = { hosts: ["api.stripe.com"] }

describe("parseDestination", () => {
  test("parses scheme, host, default port, path, method and query string", () => {
    expect(dest("https://api.stripe.com/v1/charges?limit=3#x", "post")).toEqual({
      scheme: "https",
      host: "api.stripe.com",
      port: 443,
      path: "/v1/charges",
      method: "POST",
      search: "?limit=3",
    })
    expect(dest("https://api.stripe.com/v1/charges#x").search).toBe("")
    expect(dest("http://example.com").port).toBe(80)
    expect(dest("wss://example.com/socket").port).toBe(443)
    expect(dest("ws://example.com/socket").port).toBe(80)
    expect(dest("https://example.com").path).toBe("/")
  })

  test("an explicit default port is the default port", () => {
    expect(dest("https://example.com:443/").port).toBe(443)
    expect(dest("https://example.com:8443/").port).toBe(8443)
  })

  test("normalises host case and a trailing dot", () => {
    expect(dest("https://API.Stripe.COM/v1").host).toBe("api.stripe.com")
    expect(dest("https://api.stripe.com./v1").host).toBe("api.stripe.com")
    expect(dest("https://API.STRIPE.COM./v1").host).toBe("api.stripe.com")
  })

  test("converts an IDN host to punycode", () => {
    expect(dest("https://bücher.example/").host).toBe("xn--bcher-kva.example")
    expect(dest("https://BÜCHER.example/").host).toBe("xn--bcher-kva.example")
  })

  test("rejects userinfo in any form", () => {
    expect(errorOf("https://user:pass@api.stripe.com/")).toBe("userinfo")
    expect(errorOf("https://user@api.stripe.com/")).toBe("userinfo")
    expect(errorOf("https://:pass@api.stripe.com/")).toBe("userinfo")
    expect(errorOf("https://api.stripe.com@evil.example/")).toBe("userinfo")
  })

  test("rejects unparseable URLs and unsupported schemes", () => {
    expect(errorOf("not a url")).toBe("invalid-url")
    expect(errorOf("/v1/charges")).toBe("invalid-url")
    expect(errorOf("https://exa mple.com/")).toBe("invalid-url")
    expect(errorOf("ftp://example.com/")).toBe("unsupported-scheme")
    expect(errorOf("file:///etc/passwd")).toBe("unsupported-scheme")
    expect(errorOf("javascript:alert(1)")).toBe("unsupported-scheme")
    expect(errorOf("data:text/plain,hi")).toBe("unsupported-scheme")
  })

  test("rejects encoded slashes, backslashes, dots and NULs in the path as ambiguous", () => {
    for (const url of [
      "https://api.stripe.com/v1/a%2fb",
      "https://api.stripe.com/v1/a%2Fb",
      "https://api.stripe.com/v1/a%5cb",
      "https://api.stripe.com/v1/a%5Cb",
      "https://api.stripe.com/v1/%2efoo",
      "https://api.stripe.com/v1/%00",
      "https://api.stripe.com/v1/%2e%2e/admin",
      "https://api.stripe.com/v1/%2E%2E/admin",
      "https://api.stripe.com/v1/.%2e/admin",
      "https://api.stripe.com/v1/%2e./admin",
      "https://api.stripe.com/admin/%2e%2e/v1/charges",
      "https://api.stripe.com/v1/%2e/charges",
      "https://api.stripe.com/v1\\..\\admin",
      "https://api.stripe.com/admin\\..\\v1/charges",
      "https://api.stripe.com/v1\\charges",
      "https://api.stripe.com\\v1/charges",
      "https://api.stripe.com/v1/%2\te%2e/admin",
      "https://api.stripe.com/v1/%2\ne%2e/admin",
    ]) {
      expect({ url, error: errorOf(url) }).toEqual({ url, error: "ambiguous-path" })
    }
  })

  test("encoded characters in the query are not path ambiguity", () => {
    expect(dest("https://api.stripe.com/v1/charges?next=%2e%2e%2fadmin").path).toBe("/v1/charges")
    expect(dest("https://api.stripe.com/v1/charges#%2e%2e").path).toBe("/v1/charges")
  })

  test("refuses literal dot segments and empty segments rather than resolving them", () => {
    for (const url of [
      "https://api.stripe.com/v1/../admin",
      "https://api.stripe.com/v1/./charges",
      "https://api.stripe.com/../../etc",
      "https://api.stripe.com/v1/..",
      "https://api.stripe.com/v1/.",
      "https://api.stripe.com/v1//charges",
      "https://api.stripe.com//v1/charges",
      "https://api.stripe.com/v1/charges//",
    ]) {
      expect({ url, error: errorOf(url) }).toEqual({ url, error: "ambiguous-path" })
    }
  })

  test("a single trailing slash and dots inside a segment are fine", () => {
    expect(dest("https://api.stripe.com/v1/charges/").path).toBe("/v1/charges/")
    expect(dest("https://api.stripe.com/v1/file.json").path).toBe("/v1/file.json")
    expect(dest("https://api.stripe.com/v1/..hidden").path).toBe("/v1/..hidden")
  })
})

describe("parseDestination canonicalises the path (RFC 3986 6.2.2)", () => {
  test("decodes escaped unreserved characters and upper-cases the hex of every other escape", () => {
    expect(dest("https://h.example/gmail/v1/users/me/messages/%73end").path).toBe("/gmail/v1/users/me/messages/send")
    expect(dest("https://h.example/%41%5a%61%7a%30%39%2D%5F%7E").path).toBe("/AZaz09-_~")
    expect(dest("https://h.example/%41%5A%61%7A%7e").path).toBe("/AZaz~")
    expect(dest("https://h.example/a%3ab/%c3%a9/%20x").path).toBe("/a%3Ab/%C3%A9/%20x")
    expect(dest("https://h.example/caf\u00e9/{x}").path).toBe("/caf%C3%A9/%7Bx%7D")
    expect(dest("https://h.example/a:b@c/!$&'()*+,;=").path).toBe("/a:b@c/!$&'()*+,;=")
  })

  test("a literal percent sign not followed by an escape is kept", () => {
    expect(dest("https://h.example/v1/100%25").path).toBe("/v1/100%25")
    expect(dest("https://h.example/v1/a%25zz").path).toBe("/v1/a%25zz")
  })

  test("refuses control characters, encoded or not", () => {
    for (const url of [
      "https://h.example/v1/%01",
      "https://h.example/v1/a%1fb",
      "https://h.example/v1/a%1Fb",
      "https://h.example/v1/a%7fb",
      "https://h.example/v1/a%7Fb",
      "https://h.example/v1/a%0db",
      "https://h.example/v1/a\u007fb",
      "https://h.example/v1/a\u0001b",
    ]) {
      expect({ url, error: errorOf(url) }).toEqual({ url, error: "ambiguous-path" })
    }
  })

  test("refuses malformed escapes", () => {
    for (const url of ["https://h.example/v1/%", "https://h.example/v1/a%", "https://h.example/v1/%4", "https://h.example/v1/%zz", "https://h.example/v1/%g1/x", "https://h.example/v1/%%41"]) {
      expect({ url, error: errorOf(url) }).toEqual({ url, error: "ambiguous-path" })
    }
  })

  test("refuses double encoding outright, so an upstream that decodes twice cannot read a different path", () => {
    for (const url of [
      "https://h.example/gmail/v1/users/me/messages/%2573end",
      "https://h.example/v1/%2541",
      "https://h.example/v1/a%252fb",
      "https://h.example/v1/a%252Fb",
      "https://h.example/v1/%252e%252e/admin",
      "https://h.example/v1/a%255cb",
      "https://h.example/v1/a%2500",
      "https://h.example/v1/a%252573",
      "https://h.example/v1/a%2525",
    ]) {
      expect({ url, error: errorOf(url) }).toEqual({ url, error: "ambiguous-path" })
    }
  })

  test("the canonical path is equivalent to the path as sent and stable when parsed again", () => {
    for (const url of ["https://h.example/repos/o/r/%6beys", "https://h.example/a%3ab/%c3%a9/%7e", "https://h.example/v1/Payouts/"]) {
      const path = dest(url).path
      expect(dest(`https://h.example${path}`).path).toBe(path)
    }
  })
})

describe("validHostPattern", () => {
  test("accepts exact names, wildcards with two labels below and IP literals", () => {
    for (const p of ["api.stripe.com", "localhost", "*.stripe.com", "*.a.b.example", "API.Stripe.com", "10.0.0.1", "[::1]", "[2001:db8::1]"]) {
      expect({ p, valid: validHostPattern(p) }).toEqual({ p, valid: true })
    }
  })

  test("refuses wildcards that would bind a TLD and other malformed patterns", () => {
    for (const p of ["*.com", "*", "*.", "**.stripe.com", "api.*.com", "*stripe.com", "api.stripe.com.", "", "api_stripe.com", "https://api.stripe.com", "api.stripe.com/v1", "user@api.stripe.com", "bücher.example", "[::1", `${"a".repeat(250)}.com`]) {
      expect({ p, valid: validHostPattern(p) }).toEqual({ p, valid: false })
    }
  })
})

describe("hostMatches", () => {
  test("exact names match exactly, ignoring case", () => {
    expect(hostMatches("api.stripe.com", "api.stripe.com")).toBe(true)
    expect(hostMatches("API.stripe.com", "api.STRIPE.com")).toBe(true)
    expect(hostMatches("api.stripe.com", "stripe.com")).toBe(false)
    expect(hostMatches("api.stripe.com", "x.api.stripe.com")).toBe(false)
    expect(hostMatches("api.stripe.com", "api.stripe.com.evil.example")).toBe(false)
    expect(hostMatches("stripe.com", "evilstripe.com")).toBe(false)
  })

  test("wildcards match any depth below but never the apex", () => {
    expect(hostMatches("*.stripe.com", "api.stripe.com")).toBe(true)
    expect(hostMatches("*.stripe.com", "a.b.c.stripe.com")).toBe(true)
    expect(hostMatches("*.stripe.com", "stripe.com")).toBe(false)
    expect(hostMatches("*.stripe.com", ".stripe.com")).toBe(false)
    expect(hostMatches("*.stripe.com", "evilstripe.com")).toBe(false)
    expect(hostMatches("*.stripe.com", "stripe.com.evil.example")).toBe(false)
  })
})

describe("pathPatternsOverlap", () => {
  test("two globs overlap when some path matches both, with * and ** on either side", () => {
    expect(pathPatternsOverlap("/drive/v3/files/*/permissions", "/drive/v3/**")).toBe(true)
    expect(pathPatternsOverlap("/drive/v3/**/watch", "/drive/v3/**")).toBe(true)
    expect(pathPatternsOverlap("/calendar/v3/**/watch", "/drive/v3/**")).toBe(false)
    expect(pathPatternsOverlap("/calendar/v3/calendars/*", "/upload/drive/v3/**")).toBe(false)
    expect(pathPatternsOverlap("/v1/*/x", "/v1/a/*")).toBe(true)
    expect(pathPatternsOverlap("/v1/*", "/v1/a/b")).toBe(false)
    expect(pathPatternsOverlap("/v1/**", "/v1")).toBe(true)
    expect(pathPatternsOverlap("/**/a", "/b/**")).toBe(true)
    // Without case, as a floor matches: it may show one it need not, never hide one.
    expect(pathPatternsOverlap("/Drive/v3/files", "/drive/**")).toBe(true)
  })
})

describe("restrictivePathMayMeet", () => {
  test("a restrictive pattern meets a binding path through a suffix, matrix parameters, an escape or case, as the relay reads it", () => {
    for (const bound of ["/drive/v3/files/123/watch.json", "/drive/v3/files/123/watch;alt=json", "/drive/v3/files/123/%57atch", "/Drive/V3/files/123/WATCH"]) expect(restrictivePathMayMeet("/drive/v3/**/watch", bound), bound).toBe(true)
    expect(restrictivePathMayMeet("/drive/v3/**/watch", "/drive/v3/files/123")).toBe(false)
    expect(restrictivePathMayMeet("/calendar/v3/**/watch", "/drive/v3/files/123/watch.json")).toBe(false)
    // A * admits one segment, which loose reading may split into several.
    expect(restrictivePathMayMeet("/drive/v3/files/*/permissions", "/drive/v3/files/*")).toBe(true)
    expect(restrictivePathMayMeet("/drive/v3/files/*/permissions", "/drive/v3/about/*")).toBe(false)
    // A glob still meets what it could cover.
    expect(restrictivePathMayMeet("/drive/v3/files/*/permissions", "/drive/v3/**")).toBe(true)
  })
})

describe("pathMatches", () => {
  test("literal patterns match exactly", () => {
    expect(pathMatches("/v1/charges", "/v1/charges")).toBe(true)
    expect(pathMatches("/v1/charges", "/v1/charges/ch_1")).toBe(false)
    expect(pathMatches("/v1/charges", "/v1/refunds")).toBe(false)
    expect(pathMatches("/v1/charges", "/v1/Charges")).toBe(false)
  })

  test("* matches exactly one segment", () => {
    expect(pathMatches("/v1/charges/*", "/v1/charges/ch_1")).toBe(true)
    expect(pathMatches("/v1/charges/*", "/v1/charges")).toBe(false)
    expect(pathMatches("/v1/charges/*", "/v1/charges/ch_1/capture")).toBe(false)
    expect(pathMatches("/v1/*/capture", "/v1/charges/capture")).toBe(true)
    expect(pathMatches("/v1/*/capture", "/v1/capture")).toBe(false)
  })

  test("** matches any number of segments including none", () => {
    expect(pathMatches("/v1/**", "/v1")).toBe(true)
    expect(pathMatches("/v1/**", "/v1/charges")).toBe(true)
    expect(pathMatches("/v1/**", "/v1/charges/ch_1/capture")).toBe(true)
    expect(pathMatches("/v1/**", "/v2/charges")).toBe(false)
    expect(pathMatches("/v1/**", "/v10")).toBe(false)
    expect(pathMatches("/**", "/")).toBe(true)
    expect(pathMatches("/**", "/anything/at/all")).toBe(true)
    expect(pathMatches("/v1/**/capture", "/v1/capture")).toBe(true)
    expect(pathMatches("/v1/**/capture", "/v1/a/b/capture")).toBe(true)
    expect(pathMatches("/v1/**/capture", "/v1/a/b/refund")).toBe(false)
  })

  test("a trailing slash or doubled slash does not add a segment", () => {
    expect(pathMatches("/v1/charges", "/v1/charges/")).toBe(true)
    expect(pathMatches("/v1/charges", "/v1//charges")).toBe(true)
  })

  test.each([
    ["/v1/charges", "/v1/charges", true],
    ["/v1/charges", "/v1/charges/ch_1", false],
    ["/v1/charges/*", "/v1/charges/ch_1", true],
    ["/v1/charges/*", "/v1/charges", false],
    ["/*", "/", false],
    ["/**", "/", true],
    ["/**/*", "/", false],
    ["/**/**", "/", true],
    ["/a/**", "/a/", true],
    ["/a//b", "/a/b", true],
    ["/**/b", "/a/b/", true],
    ["/**/x/*", "/x/y", true],
    ["/**/x/*", "/x", false],
    ["/v1/*/**/z", "/v1/a/z", true],
    ["/v1/*/**/z", "/v1/z", false],
    ["/v1/**/capture", "/v1/a/b/capture", true],
    ["/v1/**/capture", "/v1/a/b/refund", false],
    ["/**/a/**/b/**/c/**", "/a/b/c", true],
    ["/**/a/**/b/**/c/**", "/x/a/y/b/z/c/w", true],
    ["/**/a/**/b/**/c/**", "/c/b/a", false],
    ["/**/a/**/b/**/c/**", "/a/b/a/b", false],
    ["/**/**/**/**/z", "/z", true],
    ["/**/**/**/**/z", "/a/b/z", true],
    ["/**/**/**/**/z", "/z/a", false],
    ["/v1.0/**/messageRules/**", "/v1.0/me/mailFolders/inbox/messageRules", true],
    ["/v1.0/**/messageRules/**", "/v1.0/me/mailFolders/inbox/messagerules", false],
  ])("%s against %s is %p", (pattern, path, matched) => {
    expect(pathMatches(pattern, path)).toBe(matched)
  })

  // A device picks the path, up to the longest URL a relay request may
  // carry, so a pattern's "**" must not multiply the work.
  test.each([
    ["/**/**/**/**/z", "/a"],
    ["/**/a/**/b/**/c/**", "/a/b"],
  ])("%s against a long path that fails late is decided in pattern segments times path segments", (pattern, segment) => {
    for (const repeats of [4, 32, Math.floor(4084 / (segment.length / 2))]) {
      const path = segment.repeat(repeats)
      const work = pathMatchWork(pattern, path)
      expect(work.matched).toBe(false)
      expect(work.steps).toBeLessThanOrEqual((pattern.split("/").length + 1) * (path.split("/").length + 1))
    }
  })
})

describe("checkBinding", () => {
  test("allows an exact host over https on the default port", () => {
    expect(bindingCheck(STRIPE, "https://api.stripe.com/v1/charges")).toEqual({ ok: true })
    expect(bindingCheck(STRIPE, "https://API.STRIPE.COM./v1/charges")).toEqual({ ok: true })
  })

  test("refuses another host, including the apex and look-alikes", () => {
    for (const url of ["https://stripe.com/", "https://evil.example/", "https://api.stripe.com.evil.example/", "https://xapi.stripe.com/"]) {
      expect(bindingCheck(STRIPE, url)).toEqual({ ok: false, reason: "host" })
    }
  })

  test("wildcard bindings cover subdomains at any depth but not the apex", () => {
    const binding: Binding = { hosts: ["*.stripe.com"] }
    expect(bindingCheck(binding, "https://api.stripe.com/")).toEqual({ ok: true })
    expect(bindingCheck(binding, "https://a.b.stripe.com/")).toEqual({ ok: true })
    expect(bindingCheck(binding, "https://stripe.com/")).toEqual({ ok: false, reason: "host" })
  })

  test("an IDN binding written in punycode matches the Unicode URL", () => {
    expect(bindingCheck({ hosts: ["xn--bcher-kva.example"] }, "https://bücher.example/")).toEqual({ ok: true })
  })

  test("refuses http by default and allows it only when listed", () => {
    expect(bindingCheck(STRIPE, "http://api.stripe.com/v1")).toEqual({ ok: false, reason: "scheme" })
    expect(bindingCheck(STRIPE, "ws://api.stripe.com/v1")).toEqual({ ok: false, reason: "scheme" })
    expect(bindingCheck(STRIPE, "wss://api.stripe.com/v1")).toEqual({ ok: true })
    const plain: Binding = { hosts: ["api.stripe.com"], schemes: ["http"] }
    expect(bindingCheck(plain, "http://api.stripe.com/v1")).toEqual({ ok: true })
    expect(bindingCheck(plain, "https://api.stripe.com/v1")).toEqual({ ok: false, reason: "scheme" })
  })

  test("refuses a non-default port unless listed", () => {
    expect(bindingCheck(STRIPE, "https://api.stripe.com:8443/v1")).toEqual({ ok: false, reason: "port" })
    expect(bindingCheck(STRIPE, "https://api.stripe.com:80/v1")).toEqual({ ok: false, reason: "port" })
    const listed: Binding = { hosts: ["api.stripe.com"], ports: [8443] }
    expect(bindingCheck(listed, "https://api.stripe.com:8443/v1")).toEqual({ ok: true })
    expect(bindingCheck(listed, "https://api.stripe.com/v1")).toEqual({ ok: false, reason: "port" })
  })

  test("a listed http scheme uses port 80 by default", () => {
    const binding: Binding = { hosts: ["localhost"], schemes: ["http"] }
    expect(bindingCheck(binding, "http://localhost/")).toEqual({ ok: true })
    expect(bindingCheck(binding, "http://localhost:8080/")).toEqual({ ok: false, reason: "port" })
  })

  test("IP literals bind only when listed exactly", () => {
    expect(bindingCheck({ hosts: ["10.0.0.1"] }, "https://10.0.0.1/")).toEqual({ ok: true })
    expect(bindingCheck({ hosts: ["10.0.0.1"] }, "https://10.0.0.2/")).toEqual({ ok: false, reason: "host" })
    expect(bindingCheck({ hosts: ["[::1]"] }, "https://[::1]/")).toEqual({ ok: true })
    expect(bindingCheck(STRIPE, "https://10.0.0.1/")).toEqual({ ok: false, reason: "host" })
  })

  test("path globs restrict the binding", () => {
    const binding: Binding = { hosts: ["api.stripe.com"], paths: ["/v1/charges/*", "/v1/customers/**"] }
    expect(bindingCheck(binding, "https://api.stripe.com/v1/charges/ch_1")).toEqual({ ok: true })
    expect(bindingCheck(binding, "https://api.stripe.com/v1/customers")).toEqual({ ok: true })
    expect(bindingCheck(binding, "https://api.stripe.com/v1/customers/cus_1/sources")).toEqual({ ok: true })
    expect(bindingCheck(binding, "https://api.stripe.com/v1/charges")).toEqual({ ok: false, reason: "path" })
    expect(bindingCheck(binding, "https://api.stripe.com/v1/admin")).toEqual({ ok: false, reason: "path" })
  })

  test("dot-segment traversal never reaches the binding check", () => {
    for (const url of ["https://api.stripe.com/v1/../admin", "https://api.stripe.com/admin/../v1/charges"]) {
      expect({ url, error: errorOf(url) }).toEqual({ url, error: "ambiguous-path" })
    }
  })

  test("an empty path list allows any path", () => {
    expect(bindingCheck({ hosts: ["api.stripe.com"], paths: [] }, "https://api.stripe.com/anything")).toEqual({ ok: true })
  })

  test("methods restrict the binding, case insensitively, with * for any", () => {
    const binding: Binding = { hosts: ["api.stripe.com"], methods: ["get", "HEAD"] }
    expect(bindingCheck(binding, "https://api.stripe.com/v1", "GET")).toEqual({ ok: true })
    expect(bindingCheck(binding, "https://api.stripe.com/v1", "head")).toEqual({ ok: true })
    expect(bindingCheck(binding, "https://api.stripe.com/v1", "POST")).toEqual({ ok: false, reason: "method" })
    expect(bindingCheck({ hosts: ["api.stripe.com"], methods: ["*"] }, "https://api.stripe.com/v1", "DELETE")).toEqual({ ok: true })
    expect(bindingCheck({ hosts: ["api.stripe.com"], methods: [] }, "https://api.stripe.com/v1", "DELETE")).toEqual({ ok: true })
  })

  test("several hosts are each allowed", () => {
    const binding: Binding = { hosts: ["api.stripe.com", "*.stripe.network"] }
    expect(bindingCheck(binding, "https://m.stripe.network/")).toEqual({ ok: true })
    expect(bindingCheck(binding, "https://api.stripe.com/")).toEqual({ ok: true })
    expect(bindingCheck(binding, "https://stripe.network/")).toEqual({ ok: false, reason: "host" })
  })

  test("a binding with no hosts allows nothing", () => {
    expect(bindingCheck({ hosts: [] }, "https://api.stripe.com/")).toEqual({ ok: false, reason: "host" })
  })
})

describe("evaluatePolicy", () => {
  const allowReads: PolicyRule = { action: "allow", methods: ["GET"] }
  const approveWrites: PolicyRule = { action: "approve", methods: ["POST", "DELETE"] }
  const denyAdmin: PolicyRule = { action: "deny", paths: ["/admin/**"] }
  const policy: Policy = { default: "deny", rules: [allowReads, approveWrites, denyAdmin] }

  test("allow applies when only allow rules match", () => {
    expect(evaluatePolicy(policy, dest("https://h.example/v1/items"))).toEqual({ action: "allow", matched: [allowReads] })
  })

  test("approve beats allow", () => {
    const both: Policy = { default: "deny", rules: [{ action: "allow" }, approveWrites] }
    const decision = evaluatePolicy(both, dest("https://h.example/v1/items", "POST"))
    expect(decision).toEqual({ action: "approve", matched: [approveWrites] })
  })

  test("deny beats approve and allow regardless of rule order", () => {
    const allowAll: PolicyRule = { action: "allow" }
    for (const rules of [
      [allowAll, approveWrites, denyAdmin],
      [denyAdmin, approveWrites, allowAll],
      [approveWrites, denyAdmin, allowAll],
    ]) {
      expect(evaluatePolicy({ default: "allow", rules }, dest("https://h.example/admin/users", "POST"))).toEqual({
        action: "deny",
        matched: [denyAdmin],
      })
      expect(evaluatePolicy({ default: "allow", rules }, dest("https://h.example/admin", "GET")).action).toBe("deny")
    }
  })

  test("the default applies when nothing matches", () => {
    expect(evaluatePolicy(policy, dest("https://h.example/v1/items", "PATCH"))).toEqual({ action: "deny", matched: [] })
    expect(evaluatePolicy({ ...policy, default: "approve" }, dest("https://h.example/v1/items", "PATCH"))).toEqual({
      action: "approve",
      matched: [],
    })
    expect(evaluatePolicy({ default: "allow", rules: [] }, dest("https://h.example/"))).toEqual({ action: "allow", matched: [] })
  })

  test("a rule needs both its methods and paths to match", () => {
    const rule: PolicyRule = { action: "deny", methods: ["DELETE"], paths: ["/v1/**"] }
    const p: Policy = { default: "allow", rules: [rule] }
    expect(evaluatePolicy(p, dest("https://h.example/v1/items", "DELETE")).action).toBe("deny")
    expect(evaluatePolicy(p, dest("https://h.example/v1/items", "GET")).action).toBe("allow")
    expect(evaluatePolicy(p, dest("https://h.example/v2/items", "DELETE")).action).toBe("allow")
  })

  test("matched lists every rule of the winning action", () => {
    const a: PolicyRule = { action: "approve", note: "a" }
    const b: PolicyRule = { action: "approve", methods: ["POST"], note: "b" }
    const decision = evaluatePolicy({ default: "deny", rules: [{ action: "allow" }, a, b] }, dest("https://h.example/", "POST"))
    expect(decision).toEqual({ action: "approve", matched: [a, b] })
  })
})

describe("isReadMethod", () => {
  test("GET, HEAD and OPTIONS are reads, in any case", () => {
    expect(isReadMethod("GET")).toBe(true)
    expect(isReadMethod("head")).toBe(true)
    expect(isReadMethod("Options")).toBe(true)
    expect(isReadMethod("POST")).toBe(false)
    expect(isReadMethod("DELETE")).toBe(false)
  })
})

// Every attacker URL against the real templates, in
// every spelling an upstream might read as the same path.
describe("policy rules cannot be dodged by encoding or case", () => {
  function provider(id: string): OAuthProviderTemplate {
    const p = OAUTH_PROVIDERS[id]
    if (!p) throw new Error(`no provider ${id}`)
    return p
  }
  function templatePolicy(id: string): Policy {
    const t = getTemplate(id)
    if (!t) throw new Error(`no template ${id}`)
    return t.policy
  }

  const hex = (c: string) => c.charCodeAt(0).toString(16)
  // Each variant rewrites the sensitive segment the way an attacker would.
  const variants: [string, (word: string) => string][] = [
    ["first character encoded", (w) => `%${hex(w.charAt(0))}${w.slice(1)}`],
    ["every character encoded, lower-case hex", (w) => [...w].map((c) => `%${hex(c)}`).join("")],
    ["every character encoded, upper-case hex", (w) => [...w].map((c) => `%${hex(c).toUpperCase()}`).join("")],
    ["mixed case", (w) => [...w].map((c, i) => (i % 2 === 0 ? c.toUpperCase() : c.toLowerCase())).join("")],
    ["all upper case", (w) => w.toUpperCase()],
    ["mixed case and encoding", (w) => [...w].map((c, i) => (i % 2 === 0 ? `%${hex(c.toUpperCase()).toUpperCase()}` : c.toLowerCase())).join("")],
  ]

  const cases: { name: string; policy: Policy; method: string; base: string; word: string; rest?: string; expected: "approve" | "deny" }[] = [
    { name: "google-gmail send", policy: connectionPolicy(provider("google-gmail")), method: "POST", base: "https://gmail.googleapis.com/gmail/v1/users/me/messages/", word: "send", expected: "approve" },
    { name: "google-gmail upload send", policy: connectionPolicy(provider("google-gmail")), method: "POST", base: "https://gmail.googleapis.com/upload/gmail/v1/users/me/messages/", word: "send", expected: "approve" },
    { name: "google-gmail forwarding", policy: connectionPolicy(provider("google-gmail")), method: "POST", base: "https://gmail.googleapis.com/gmail/v1/users/me/settings/", word: "forwardingAddresses", expected: "deny" },
    { name: "github-pat deploy keys", policy: templatePolicy("github-pat"), method: "POST", base: "https://api.github.com/repos/o/r/", word: "keys", expected: "deny" },
    { name: "github-oauth deploy keys", policy: connectionPolicy(provider("github-oauth")), method: "POST", base: "https://api.github.com/repos/o/r/", word: "keys", expected: "deny" },
    { name: "stripe payouts", policy: templatePolicy("stripe"), method: "POST", base: "https://api.stripe.com/v1/", word: "payouts", expected: "approve" },
    { name: "stripe payout by id", policy: templatePolicy("stripe"), method: "POST", base: "https://api.stripe.com/v1/", word: "payouts", rest: "/po_1/cancel", expected: "approve" },
    { name: "microsoft-graph message rules", policy: connectionPolicy(provider("microsoft-graph")), method: "POST", base: "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/", word: "messageRules", expected: "deny" },
    { name: "microsoft-graph message rules on beta", policy: connectionPolicy(provider("microsoft-graph")), method: "PATCH", base: "https://graph.microsoft.com/beta/me/mailFolders/inbox/", word: "messageRules", rest: "/r1", expected: "deny" },
  ]

  for (const c of cases) {
    test(`${c.name}: ${c.expected} however the path is spelt`, () => {
      const plain = `${c.base}${c.word}${c.rest ?? ""}`
      expect(evaluatePolicy(c.policy, dest(plain, c.method)).action).toBe(c.expected)
      for (const [label, spell] of variants) {
        const url = `${c.base}${spell(c.word)}${c.rest ?? ""}`
        expect({ label, url, action: evaluatePolicy(c.policy, dest(url, c.method)).action }).toEqual({ label, url, action: c.expected })
      }
      // The method is upper-cased before any rule sees it.
      expect(evaluatePolicy(c.policy, dest(`${c.base}${variants[0]?.[1](c.word)}${c.rest ?? ""}`, c.method.toLowerCase())).action).toBe(c.expected)
    })

    test(`${c.name}: double encoding, traversal and backslashes are refused before any rule`, () => {
      const parent = c.base.replace(/^https:\/\/[^/]+/, "").replace(/\/$/, "")
      const host = c.base.match(/^https:\/\/[^/]+/)?.[0] ?? ""
      for (const url of [
        `${c.base}%25${hex(c.word.charAt(0))}${c.word.slice(1)}`,
        `${c.base}%25${hex(c.word.charAt(0)).toUpperCase()}${c.word.slice(1)}`,
        `${c.base}x/../${c.word}`,
        `${c.base}x/%2e%2e/${c.word}`,
        `${c.base}x\\..\\${c.word}`,
        `${c.base}%2e/${c.word}`,
        `${c.base}/${c.word}`,
        `${host}/other/..${parent}/${c.word}`,
      ]) {
        expect({ url, error: errorOf(url) }).toEqual({ url, error: "ambiguous-path" })
      }
    })
  }

  test("the canonical form still passes the templates' bindings, so the relay forwards what it checked", () => {
    const gmail = provider("google-gmail").upstream.binding
    expect(checkBinding(gmail, dest("https://gmail.googleapis.com/gmail/v1/users/me/messages/%73end", "POST"))).toEqual({ ok: true })
    expect(dest("https://gmail.googleapis.com/gmail/v1/users/me/messages/%73end", "POST").path).toBe("/gmail/v1/users/me/messages/send")
    expect(dest("https://api.github.com/repos/o/r/%6Beys", "POST").path).toBe("/repos/o/r/keys")
    expect(dest("https://api.stripe.com/v1/%70ayouts", "POST").path).toBe("/v1/payouts")
  })

  test("requests the rules do not cover are unaffected", () => {
    const gmail = connectionPolicy(provider("google-gmail"))
    expect(evaluatePolicy(gmail, dest("https://gmail.googleapis.com/gmail/v1/users/me/messages/%6Dsg1", "GET")).action).toBe("allow")
    expect(evaluatePolicy(gmail, dest("https://gmail.googleapis.com/gmail/v1/users/me/settings/forwardingAddresses", "GET")).action).toBe("allow")
    expect(evaluatePolicy(templatePolicy("stripe"), dest("https://api.stripe.com/v1/%70roducts", "POST")).action).toBe("allow")
  })
})

describe("matching is asymmetric so mistakes fail closed", () => {
  test("binding paths match the canonical path exactly and case-sensitively", () => {
    const binding: Binding = { hosts: ["api.stripe.com"], paths: ["/v1/charges/**"] }
    expect(bindingCheck(binding, "https://api.stripe.com/v1/%63harges/ch_1")).toEqual({ ok: true })
    expect(bindingCheck(binding, "https://api.stripe.com/v1/Charges/ch_1")).toEqual({ ok: false, reason: "path" })
    expect(bindingCheck(binding, "https://api.stripe.com/V1/charges")).toEqual({ ok: false, reason: "path" })
    expect(bindingCheck({ hosts: ["h.example"], paths: ["/a/%7euser"] }, "https://h.example/a/%7euser")).toEqual({ ok: false, reason: "path" })
    expect(bindingCheck({ hosts: ["h.example"], paths: ["/a/~user"] }, "https://h.example/a/%7euser")).toEqual({ ok: true })
  })

  test("allow rules match the canonical path exactly and case-sensitively", () => {
    const policy: Policy = { default: "deny", rules: [{ action: "allow", paths: ["/v1/charges/**"] }] }
    expect(evaluatePolicy(policy, dest("https://h.example/v1/%63harges")).action).toBe("allow")
    expect(evaluatePolicy(policy, dest("https://h.example/v1/Charges")).action).toBe("deny")
    expect(evaluatePolicy(policy, dest("https://h.example/V1/charges")).action).toBe("deny")
    expect(evaluatePolicy({ default: "deny", rules: [{ action: "allow", paths: ["/v1/a:b"] }] }, dest("https://h.example/v1/a%3Ab")).action).toBe("deny")
  })

  test("deny and approve rules match a decoded, lower-cased path against a decoded, lower-cased pattern", () => {
    const deny = (paths: string[], url: string) => evaluatePolicy({ default: "allow", rules: [{ action: "deny", paths }] }, dest(url)).action
    const approve = (paths: string[], url: string) => evaluatePolicy({ default: "allow", rules: [{ action: "approve", paths }] }, dest(url)).action
    expect(deny(["/v1/payouts"], "https://h.example/V1/PAYOUTS")).toBe("deny")
    expect(deny(["/V1/Payouts"], "https://h.example/v1/payouts")).toBe("deny")
    expect(deny(["/v1/a:b"], "https://h.example/v1/a%3Ab")).toBe("deny")
    expect(deny(["/v1/a%3ab"], "https://h.example/v1/a:b")).toBe("deny")
    expect(deny(["/v1/caf\u00e9"], "https://h.example/v1/CAF%C3%A9")).toBe("deny")
    expect(deny(["/v1/*/keys"], "https://h.example/v1/%41/%4Beys")).toBe("deny")
    expect(approve(["/v1/**/send"], "https://h.example/v1/a/b/SEND")).toBe("approve")
    expect(deny(["/v1/payouts"], "https://h.example/v1/payouts2")).toBe("allow")
  })

  // Decoding unreserved escapes must not build a new one.
  test("an escaped percent that decoding turns into a double escape is refused", () => {
    for (const url of ["https://h.example/messages/%25%37%33end", "https://h.example/messages/%25%33%37end", "https://h.example/a/%25%34%31"]) {
      expect({ url, error: errorOf(url) }).toEqual({ url, error: "ambiguous-path" })
    }
    expect(dest("https://h.example/a/%25zz").path).toBe("/a/%25zz")
  })

  // Restrictive rules match every form a router may read.
  test("deny and approve rules also match matrix parameters, format suffixes, Unicode case folds and qualified action names", () => {
    const deny = (paths: string[], url: string, method = "GET") => evaluatePolicy({ default: "allow", rules: [{ action: "deny", paths }] }, dest(url, method)).action
    for (const url of [
      "https://h.example/repos/o/r/keys;x=1",
      "https://h.example/repos/o/r/keys%3Bx=1",
      "https://h.example/repos/o/r;x=1/keys",
      "https://h.example/repos/o/r/keys.json",
      "https://h.example/repos/o/r/keys.json/",
      "https://h.example/repos/o/r/%E2%84%AAeys",
      "https://h.example/repos/o/r/\u212Aeys",
    ]) {
      expect({ url, action: deny(["/repos/*/*/keys"], url) }).toEqual({ url, action: "deny" })
    }
    expect(deny(["/me/messages/*/send"], "https://h.example/me/messages/m/%C5%BFend")).toBe("deny")
    for (const action of ["graph.send", "microsoft.graph.send", "Microsoft.Graph.SEND", "x.y.send;z"]) {
      expect({ action, result: deny(["/**/send"], `https://h.example/me/messages/m/${action}`) }).toEqual({ action, result: "deny" })
    }
    expect(deny(["/repos/*/*/keys"], "https://h.example/repos/o/r/keystore")).toBe("allow")
    expect(deny(["/repos/*/*/keys"], "https://h.example/repos/o/r/contents/keys.md")).toBe("allow")
  })

  test("an allow rule's body matcher must prove the body harmless; a restrictive rule's applies when in doubt", () => {
    const query = new TextEncoder().encode(JSON.stringify({ query: "{ viewer { login } }" }))
    const mutation = new TextEncoder().encode(JSON.stringify({ query: "mutation { x }" }))
    const allowQuery: Policy = { default: "approve", rules: [{ action: "allow", paths: ["/graphql"], body: "graphql-query" }] }
    expect(evaluatePolicy(allowQuery, dest("https://h.example/graphql", "POST"), query).action).toBe("allow")
    expect(evaluatePolicy(allowQuery, dest("https://h.example/graphql", "POST"), mutation).action).toBe("approve")
    expect(evaluatePolicy(allowQuery, dest("https://h.example/graphql", "POST"), null).action).toBe("approve")
    expect(evaluatePolicy(allowQuery, dest("https://h.example/graphql?query=mutation%7Bx%7D", "POST"), query).action).toBe("approve")
    expect(evaluatePolicy(allowQuery, dest("https://h.example/GraphQL", "POST"), query).action).toBe("approve")
    // Not valid by the schema, but evaluatePolicy must still fail closed.
    const allowMutation: Policy = { default: "approve", rules: [{ action: "allow", paths: ["/graphql"], body: "graphql-mutation" }] }
    expect(evaluatePolicy(allowMutation, dest("https://h.example/graphql", "POST"), mutation).action).toBe("approve")
    const denyQuery: Policy = { default: "allow", rules: [{ action: "deny", paths: ["/graphql"], body: "graphql-query" }] }
    expect(evaluatePolicy(denyQuery, dest("https://h.example/graphql", "POST"), mutation).action).toBe("deny")
  })

  test("an encoded ? or # in the path is kept, and a rule also meets the path cut there, as an upstream that decodes and splits again reads it", () => {
    expect(dest("https://h.example/repos/o/r/git/refs/heads/fix%23123").path).toBe("/repos/o/r/git/refs/heads/fix%23123")
    const deny = (url: string) => evaluatePolicy({ default: "allow", rules: [{ action: "deny", paths: ["/v1/keys/**"] }] }, dest(url)).action
    for (const url of ["https://h.example/v1/keys%3Fx", "https://h.example/v1/keys%3fx", "https://h.example/v1/keys%23x", "https://h.example/v1/keys%3F/x", "https://h.example/v1/keys%3Bx%3Fy"]) {
      expect({ url, action: deny(url) }).toEqual({ url, action: "deny" })
    }
    expect(evaluatePolicy({ default: "allow", rules: [{ action: "approve", paths: ["/v1/keys"] }] }, dest("https://h.example/v1/keys%23x")).action).toBe("approve")
    expect(deny("https://h.example/v1/keystore%3Fx")).toBe("allow")
    const send: Policy = { default: "approve", rules: [{ action: "allow", methods: ["POST"], paths: ["/v1/*/send"] }] }
    expect(evaluatePolicy(send, dest("https://h.example/v1/x/send", "POST")).action).toBe("allow")
    for (const url of ["https://h.example/v1/delete%3F/send", "https://h.example/v1/delete%3f/send", "https://h.example/v1/delete%23/send"]) {
      expect({ url, action: evaluatePolicy(send, dest(url, "POST")).action }).toEqual({ url, action: "approve" })
    }
    const refs: Policy = { default: "deny", rules: [{ action: "allow", paths: ["/repos/*/*/git/refs/**"] }] }
    expect(evaluatePolicy(refs, dest("https://h.example/repos/o/r/git/refs/heads/fix%23123")).action).toBe("allow")
    expect(evaluatePolicy({ default: "allow", rules: [{ action: "deny", paths: ["/v1/keys/**"] }] }, dest("https://h.example/storage/kv/values/user%231")).action).toBe("allow")
    expect(evaluatePolicy({ default: "approve", rules: [] }, dest("https://h.example/storage/kv/values/user%231")).action).toBe("approve")
    expect(bindingCheck({ hosts: ["h.example"], paths: ["/v1/public/*/x"] }, "https://h.example/v1/public/secret%3F/x")).toEqual({ ok: false, reason: "path", cutAt: "?" })
  })

  test("a binding refusal names the encoded ? or # when only the path cut there falls outside", () => {
    const gitlab = { hosts: ["gitlab.example"], paths: ["/api/v4/projects/*/repository/files/*/raw"] }
    expect(bindingCheck(gitlab, "https://gitlab.example/api/v4/projects/1/repository/files/what%3F.md/raw")).toEqual({ ok: false, reason: "path", cutAt: "?" })
    expect(bindingCheck(gitlab, "https://gitlab.example/api/v4/projects/1/repository/files/what%23.md/raw")).toEqual({ ok: false, reason: "path", cutAt: "#" })
    expect(bindingCheck(gitlab, "https://gitlab.example/api/v4/projects/1/repository/files/what.md/raw")).toEqual({ ok: true })
    expect(bindingCheck(gitlab, "https://gitlab.example/api/v4/projects/1/issues%3Fx")).toEqual({ ok: false, reason: "path" })
  })

  test("allow rules do not widen to those forms", () => {
    const policy: Policy = { default: "deny", rules: [{ action: "allow", paths: ["/v1/items"] }] }
    expect(evaluatePolicy(policy, dest("https://h.example/v1/items")).action).toBe("allow")
    for (const url of ["https://h.example/v1/items;x=1", "https://h.example/v1/items.json", "https://h.example/v1/x.items", "https://h.example/v1/%C5%BFtems"]) {
      expect({ url, action: evaluatePolicy(policy, dest(url)).action }).toEqual({ url, action: "deny" })
    }
  })

  test("a lower-case method meets the same rules as its upper-case form", () => {
    const policy: Policy = { default: "allow", rules: [{ action: "deny", methods: ["post"], paths: ["/v1/x"] }] }
    expect(evaluatePolicy(policy, dest("https://h.example/v1/X", "post")).action).toBe("deny")
    expect(evaluatePolicy(policy, dest("https://h.example/v1/X", "Post")).action).toBe("deny")
    expect(dest("https://h.example/", "pAtCh").method).toBe("PATCH")
  })
})

// Members write these, so they are bounded.
describe("PolicySchema and BindingSchema limits", () => {
  const rule = (paths: string[]) => ({ action: "deny" as const, paths })
  const policyOk = (value: unknown) => PolicySchema.safeParse(value).success
  const bindingOk = (value: unknown) => BindingSchema.safeParse(value).success

  test("a policy holds at most 64 rules", () => {
    expect(policyOk({ default: "allow", rules: Array.from({ length: 64 }, () => rule(["/x"])) })).toBe(true)
    expect(policyOk({ default: "allow", rules: Array.from({ length: 65 }, () => rule(["/x"])) })).toBe(false)
  })

  test("a rule holds at most 32 paths of at most 256 characters", () => {
    expect(policyOk({ default: "allow", rules: [rule(Array.from({ length: 32 }, (_, i) => `/p${i}`))] })).toBe(true)
    expect(policyOk({ default: "allow", rules: [rule(Array.from({ length: 33 }, (_, i) => `/p${i}`))] })).toBe(false)
    expect(policyOk({ default: "allow", rules: [rule([`/${"a".repeat(255)}`])] })).toBe(true)
    expect(policyOk({ default: "allow", rules: [rule([`/${"a".repeat(256)}`])] })).toBe(false)
  })

  test('a path pattern holds at most four "**"', () => {
    expect(policyOk({ default: "allow", rules: [rule(["/**/a/**/b/**/c/**"])] })).toBe(true)
    expect(policyOk({ default: "allow", rules: [rule(["/**/a/**/b/**/c/**/d/**"])] })).toBe(false)
    expect(bindingOk({ hosts: ["h.example"], paths: ["/**/a/**/b/**/c/**"] })).toBe(true)
    expect(bindingOk({ hosts: ["h.example"], paths: ["/**/**/**/**/**"] })).toBe(false)
  })

  test("a rule or binding lists at most 16 methods", () => {
    const methods = (n: number) => Array.from({ length: n }, () => "GET")
    expect(policyOk({ default: "allow", rules: [{ action: "deny", methods: methods(16) }] })).toBe(true)
    expect(policyOk({ default: "allow", rules: [{ action: "deny", methods: methods(17) }] })).toBe(false)
    expect(policyOk({ default: "allow", rules: [{ action: "deny", methods: ["X".repeat(17)] }] })).toBe(false)
    expect(bindingOk({ hosts: ["h.example"], methods: methods(17) })).toBe(false)
  })

  test("a binding holds at most 32 hosts and 64 paths", () => {
    expect(bindingOk({ hosts: Array.from({ length: 32 }, (_, i) => `h${i}.example`) })).toBe(true)
    expect(bindingOk({ hosts: Array.from({ length: 33 }, (_, i) => `h${i}.example`) })).toBe(false)
    expect(bindingOk({ hosts: ["h.example"], paths: Array.from({ length: 64 }, (_, i) => `/p${i}`) })).toBe(true)
    expect(bindingOk({ hosts: ["h.example"], paths: Array.from({ length: 65 }, (_, i) => `/p${i}`) })).toBe(false)
  })

  test("every shipped template and connection policy fits", () => {
    for (const p of Object.values(OAUTH_PROVIDERS)) {
      expect({ id: p.id, ok: policyOk(connectionPolicy(p)) && bindingOk(p.upstream.binding) }).toEqual({ id: p.id, ok: true })
    }
    for (const t of Object.values(TEMPLATES)) {
      expect({ id: t.id, ok: policyOk(t.policy) && bindingOk(t.binding) }).toEqual({ id: t.id, ok: true })
    }
  })
})

describe("customItemPolicy: a credential without a template fails closed", () => {
  test("without the reads tick every method waits for approval", () => {
    const policy = customItemPolicy(false)
    expect(PolicySchema.safeParse(policy).success).toBe(true)
    for (const method of ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]) {
      expect(evaluatePolicy(policy, dest("https://api.acme.test/v1/apps", method)).action).toBe("approve")
    }
  })

  test("with it reads go through and every other method still waits", () => {
    const policy = customItemPolicy(true)
    expect(PolicySchema.safeParse(policy).success).toBe(true)
    for (const method of ["GET", "HEAD", "OPTIONS"]) expect(evaluatePolicy(policy, dest("https://api.acme.test/v1/apps", method)).action).toBe("allow")
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "PROPFIND"]) expect(evaluatePolicy(policy, dest("https://api.acme.test/v1/apps", method)).action).toBe("approve")
  })
})

describe("a lease-only binding names nowhere", () => {
  test("checkBinding refuses every destination as a host mismatch, the reserved host included", () => {
    for (const url of [`https://${LEASE_ONLY_HOST}/`, `http://${LEASE_ONLY_HOST}/x`, "https://api.stripe.com/v1/charges", "https://x.mehen.invalid/"]) {
      expect({ url, check: bindingCheck({ ...leaseOnlyBinding(), schemes: ["https", "http"] }, url) }).toEqual({ url, check: { ok: false, reason: "host" } })
    }
    expect(isLeaseOnly(leaseOnlyBinding())).toBe(true)
    expect(isLeaseOnly(STRIPE)).toBe(false)
  })

  test("BindingSchema takes the reserved host on its own and refuses it beside another host, as a wildcard or as another name", () => {
    const ok = (hosts: string[]) => BindingSchema.safeParse({ hosts }).success
    expect(ok([LEASE_ONLY_HOST])).toBe(true)
    expect(ok([LEASE_ONLY_HOST, "api.stripe.com"])).toBe(false)
    expect(ok(["api.stripe.com", LEASE_ONLY_HOST])).toBe(false)
    expect(ok(["*.mehen.invalid"])).toBe(false)
    expect(ok(["other.mehen.invalid"])).toBe(false)
    expect(ok(["LEASE-ONLY.mehen.invalid"])).toBe(false)
    expect(ok(["mehen.invalid"])).toBe(false)
    expect(ok(["api.stripe.com"])).toBe(true)
  })
})
