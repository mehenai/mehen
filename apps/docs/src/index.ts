// The Worker in front of the static docs at docs.mehen.dev. It sees every
// request (run_worker_first): it refuses anything but GET and HEAD, answers
// /search from the prebuilt index, serves a page's markdown twin to a client
// that sends `Accept: text/markdown`, sets explicit types on the markdown,
// text and JSON files, and puts the security and cache headers on every
// answer. Query strings are never logged (invocation logs are off).

import { renderSearch, SEARCH_LIMIT } from "./search-page.ts"
import { type SearchEntry, search } from "./search.ts"

export type Env = { ASSETS: Fetcher }

const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  // The search box fetches /search-index.json.
  "connect-src 'self'",
  "base-uri 'none'",
  // The search form submits to /search.
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ")

const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": CONTENT_SECURITY_POLICY,
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
  "X-Frame-Options": "DENY",
}

// RFC 9116 security.txt, served from code so no asset rule can drop the dot
// directory. Expires about a year out: renew it before then (the test fails
// once it has passed).
export function securityTxt(origin: string): string {
  return [
    "Contact: mailto:security@mehen.dev",
    "Expires: 2027-10-29T00:00:00.000Z",
    "Policy: https://docs.mehen.dev/security/disclosure",
    "Preferred-Languages: en",
    `Canonical: ${origin}/.well-known/security.txt`,
    "",
  ].join("\n")
}

const DAY = 86400
const FIVE_MINUTES = 300

// Fonts and images change rarely and are not fingerprinted: a day. Pages,
// CSS, scripts and the text and JSON files change together with a deploy:
// five minutes.
function cacheControl(pathname: string): string {
  const longLived = pathname.startsWith("/fonts/") || /\.(woff2|webp|png|jpg|svg|ico)$/.test(pathname)
  return `public, max-age=${longLived ? DAY : FIVE_MINUTES}`
}

const TEXT_FILES = new Set(["/llms.txt", "/llms-full.txt", "/robots.txt"])

function contentType(pathname: string): string | null {
  if (pathname.endsWith(".md")) return "text/markdown; charset=utf-8"
  if (TEXT_FILES.has(pathname)) return "text/plain; charset=utf-8"
  if (pathname.endsWith(".json")) return "application/json"
  return null
}

// A page's markdown twin: /reference/cli.md, and /index.md for the home page.
export function twinPath(pathname: string): string {
  return pathname === "/" ? "/index.md" : `${pathname}.md`
}

// Whether the client asked for markdown: `text/markdown` in Accept, with a
// quality above zero.
export function wantsMarkdown(accept: string | null): boolean {
  if (!accept) return false
  return accept.split(",").some((part) => {
    const [type, ...params] = part.trim().toLowerCase().split(";")
    if (type?.trim() !== "text/markdown") return false
    const q = params.map((p) => p.trim()).find((p) => p.startsWith("q="))
    return q === undefined || Number(q.slice(2)) > 0
  })
}

// The page list and the search index, read once per isolate from the
// assets the build wrote; a failed read is tried again on the next request.
let pages: Promise<Set<string>> | null = null
let entries: Promise<SearchEntry[]> | null = null

async function assetJson<T>(env: Env, origin: URL, pathname: string): Promise<T> {
  const response = await env.ASSETS.fetch(new Request(new URL(pathname, origin)))
  if (!response.ok) throw new Error(`${pathname}: ${response.status}`)
  return (await response.json()) as T
}

function pageList(env: Env, origin: URL): Promise<Set<string>> {
  pages ??= assetJson<{ pages: { url: string }[] }>(env, origin, "/index.json").then(
    (index) => new Set(index.pages.map((p) => p.url)),
    (error: unknown) => {
      pages = null
      throw error
    },
  )
  return pages
}

function searchIndex(env: Env, origin: URL): Promise<SearchEntry[]> {
  entries ??= assetJson<SearchEntry[]>(env, origin, "/search-index.json").catch((error: unknown) => {
    entries = null
    throw error
  })
  return entries
}

function withHeaders(response: Response, pathname: string, extra: Record<string, string> = {}): Response {
  const headers = new Headers(response.headers)
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value)
  headers.set("Cache-Control", response.status === 404 ? "no-store" : cacheControl(pathname))
  const type = response.status === 404 ? null : contentType(pathname)
  if (type) headers.set("Content-Type", type)
  for (const [name, value] of Object.entries(extra)) headers.set(name, value)
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers })
}

async function searchPage(request: Request, env: Env, url: URL): Promise<Response> {
  const query = url.searchParams.get("q") ?? ""
  const [shell, index] = await Promise.all([env.ASSETS.fetch(new Request(new URL("/search", url))).then((r) => r.text()), searchIndex(env, url)])
  const body = renderSearch(shell, query, search(index, query, SEARCH_LIMIT))
  const headers = new Headers({ ...SECURITY_HEADERS, "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" })
  return new Response(request.method === "HEAD" ? null : body, { headers })
}

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url)
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method not allowed\n", { status: 405, headers: { ...SECURITY_HEADERS, Allow: "GET, HEAD", "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } })
    }
    const pathname = url.pathname
    if (pathname === "/.well-known/security.txt") {
      const headers = { ...SECURITY_HEADERS, "Content-Type": "text/plain; charset=utf-8", "Cache-Control": `public, max-age=${FIVE_MINUTES}` }
      return new Response(request.method === "HEAD" ? null : securityTxt("https://docs.mehen.dev"), { headers })
    }
    if (pathname === "/search") return await searchPage(request, env, url)
    const isPage = (await pageList(env, url)).has(pathname)
    const negotiated = isPage && wantsMarkdown(request.headers.get("Accept"))
    const assetPath = negotiated ? twinPath(pathname) : pathname
    const asset = await env.ASSETS.fetch(new Request(new URL(`${assetPath}${url.search}`, url), request))
    const extra: Record<string, string> = isPage ? { Vary: "Accept" } : {}
    if (negotiated) extra["Content-Location"] = assetPath
    return withHeaders(asset, assetPath, extra)
  },
} satisfies ExportedHandler<Env>
