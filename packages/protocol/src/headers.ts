// Headers that frame, route or hop a request, carry cookies or proxy state,
// override its method, or belong to Cloudflare or the vault itself. A
// credential is never put into one of them, whoever asks: an agent's
// proposed injection, a template, or a stored header map.

const RESERVED_HEADERS = new Set([
  "host",
  "content-length",
  "content-type",
  "content-encoding",
  "transfer-encoding",
  "connection",
  "keep-alive",
  "te",
  "trailer",
  "upgrade",
  "expect",
  "cookie",
  "set-cookie",
  "forwarded",
  "x-real-ip",
  "true-client-ip",
  "x-original-url",
  "x-rewrite-url",
  "x-http-method",
  "x-http-method-override",
  "x-method-override",
])

const RESERVED_HEADER_PREFIXES = ["x-forwarded-", "proxy-", "cf-", "mehen-"]

// CGI and FastCGI read "_" in a header name as "-", so X_Original_URL is
// X-Original-URL to them.
export function isReservedHeader(name: string): boolean {
  const lower = name.trim().toLowerCase().replaceAll("_", "-")
  return RESERVED_HEADERS.has(lower) || RESERVED_HEADER_PREFIXES.some((prefix) => lower.startsWith(prefix))
}
