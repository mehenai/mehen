// One predicate for the headers a credential may never
// be put into.

import { describe, expect, it } from "bun:test"
import { isReservedHeader } from "./headers.ts"

describe("isReservedHeader", () => {
  it("covers framing, hop-by-hop, cookie, routing and method-override headers, in any case", () => {
    for (const name of [
      "Host",
      "content-length",
      "Content-Type",
      "content-encoding",
      "Transfer-Encoding",
      "connection",
      "Keep-Alive",
      "te",
      "trailer",
      "upgrade",
      "Expect",
      "Cookie",
      "Set-Cookie",
      "Forwarded",
      "X-Real-IP",
      "True-Client-IP",
      "X-Original-URL",
      "x-rewrite-url",
      "X-HTTP-Method",
      "X-HTTP-Method-Override",
      "x-method-override",
    ]) {
      expect(isReservedHeader(name), name).toBe(true)
    }
  })

  it("covers whole families by prefix", () => {
    for (const name of ["X-Forwarded-Host", "x-forwarded-for", "X-Forwarded-Proto", "Proxy-Authorization", "proxy-connection", "Proxy-Anything", "CF-Connecting-IP", "cf-worker", "Mehen-Item", "mehen-anything"]) {
      expect(isReservedHeader(name), name).toBe(true)
    }
  })

  it("reads _ as - and ignores surrounding spaces, as CGI and FastCGI read a header name", () => {
    for (const name of ["X_Original_URL", "X_HTTP_Method_Override", "x_forwarded_for", "proxy_authorization", "Proxy_Anything", " x_rewrite-url ", "content_length", "cf_connecting_ip", "mehen_item"]) {
      expect(isReservedHeader(name), name).toBe(true)
    }
    for (const name of ["X_Api_Key", "private_token", "x_forwarded", "proxyish_key"]) {
      expect(isReservedHeader(name), name).toBe(false)
    }
  })

  it("leaves the headers credentials normally go in alone", () => {
    for (const name of ["Authorization", "X-Api-Key", "api-key", "X-Auth-Token", "PRIVATE-TOKEN", "x-forwarded", "proxyish", "cfg-token", "jvx"]) {
      expect(isReservedHeader(name), name).toBe(false)
    }
  })
})
