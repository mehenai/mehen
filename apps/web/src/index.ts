// The Worker in front of the static lander at mehen.dev: sends www to the
// apex, sends the old guide addresses to the docs site, streams the release
// channel, then serves the asset with the security and cache headers set
// (at /, the markdown page to an agent that asks for markdown). It
// runs before the asset layer (run_worker_first) because the www redirect
// has to catch requests the asset layer would otherwise answer on its own.

export type Env = { ASSETS: Fetcher; RELEASES: R2Bucket }

const APEX = "mehen.dev"

const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
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

// The guides moved to the docs site. Each old address answers a 301 with a
// one-line plain-text body naming the new URL, so an agent whose fetch tool
// reads a redirect without following it still lands. /setup.md keeps
// redirecting indefinitely: 0.3.0 binaries in the wild print it.
export const DOCS_ORIGIN = "https://docs.mehen.dev"
const MOVED: Readonly<Record<string, string>> = {
  "/setup.md": "/setup.md",
  "/setup": "/setup",
  "/setup/": "/setup",
  "/skill.md": "/skill.md",
  "/SKILL.md": "/skill.md",
  "/llms.txt": "/llms.txt",
}

// The new address for an old one, or null: the guides above, and /docs and
// anything under it (a guessed address) to the docs home.
export function movedTo(pathname: string): string | null {
  if (Object.hasOwn(MOVED, pathname)) return `${DOCS_ORIGIN}${MOVED[pathname]}`
  if (pathname === "/docs" || pathname.startsWith("/docs/")) return `${DOCS_ORIGIN}/`
  return null
}

// RFC 9116 security.txt, served from code so no asset rule can drop the dot
// directory. Expires about a year out: renew it before then (the test fails
// once it has passed).
const SECURITY_TXT = "/.well-known/security.txt"

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

// An agent that asks for markdown at / gets public/index.md, the short
// page for agents, instead of the HTML. Markdown wins only when the Accept
// header names text/markdown with a quality at least that of HTML (an
// explicit text/html, or else text/* or */* standing in for it).
export function prefersMarkdown(accept: string | null): boolean {
  const qualities = new Map<string, number>()
  for (const part of (accept ?? "").split(",")) {
    const [range = "", ...params] = part.split(";").map((p) => p.trim().toLowerCase())
    const q = params.find((p) => p.startsWith("q="))
    const quality = q === undefined ? 1 : Number(q.slice(2))
    if (Number.isFinite(quality)) qualities.set(range, Math.max(qualities.get(range) ?? 0, quality))
  }
  const markdown = qualities.get("text/markdown") ?? 0
  const html = qualities.get("text/html") ?? qualities.get("text/*") ?? qualities.get("*/*") ?? 0
  return markdown > 0 && markdown >= html
}

// The asset layer serves the not-found page at its own address with 200; it
// is a 404 wherever it is shown.
const NOT_FOUND_PAGE = new Set(["/404", "/404.html"])

const DAY = 86400
const FIVE_MINUTES = 300

// Fonts, art, marks and icons change rarely and are not fingerprinted: a day.
// HTML, CSS and JS ship together and change together: five minutes.
function cacheControl(pathname: string): string {
  const longLived = /^\/(fonts|art|marks)\//.test(pathname) || /\.(woff2|webp|png|jpg|svg|ico)$/.test(pathname)
  return `public, max-age=${longLived ? DAY : FIVE_MINUTES}`
}

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url)
    if (url.hostname === `www.${APEX}`) {
      return Response.redirect(`https://${APEX}${url.pathname}${url.search}`, 301)
    }

    const path = url.pathname
    const moved = movedTo(path)
    if ((path.startsWith("/dl/") || path === "/install" || path === SECURITY_TXT || moved !== null) && request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, HEAD" } })
    }
    if (moved !== null) {
      return new Response(request.method === "HEAD" ? null : `Moved: ${moved}\n`, { status: 301, headers: {
        ...SECURITY_HEADERS,
        Location: moved,
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": `public, max-age=${FIVE_MINUTES}`,
      } })
    }
    if (path === SECURITY_TXT) {
      return new Response(request.method === "HEAD" ? null : securityTxt(`https://${APEX}`), { headers: {
        ...SECURITY_HEADERS,
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": `public, max-age=${FIVE_MINUTES}`,
      } })
    }
    if (path.startsWith("/dl/")) {
      const notFound = () => new Response("Not found", { status: 404, headers: { ...SECURITY_HEADERS, "Cache-Control": "no-store" } })
      const key = path.slice(4)
      if (!/^(latest\.json|v\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?\/(?:manifest\.json|mehen-(?:(?:darwin|linux)-(?:arm64|x64)|se)\.gz))$/.test(key)) return notFound()
      const object: (R2Object & { body?: ReadableStream }) | null = request.method === "HEAD" ? await env.RELEASES.head(key) : await env.RELEASES.get(key)
      if (!object) return notFound()
      return new Response(object.body ?? null, { headers: {
        ...SECURITY_HEADERS,
        "Content-Type": key.endsWith(".json") ? "application/json" : "application/gzip",
        "Content-Length": String(object.size),
        "Cache-Control": key === "latest.json" ? "public, max-age=60" : "public, max-age=31536000, immutable",
        ETag: object.httpEtag,
      } })
    }
    const markdown = path === "/" && prefersMarkdown(request.headers.get("Accept"))
    const asset = await env.ASSETS.fetch(new Request(new URL(markdown ? "/index.md" : path, url), request))
    const headers = new Headers(asset.headers)
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value)
    headers.set("Cache-Control", path === "/install" ? "no-cache" : cacheControl(path))
    if (path === "/install") headers.set("Content-Type", "text/plain; charset=utf-8")
    if (path === "/") headers.set("Vary", "Accept")
    if (asset.status === 200 && (markdown || path === "/index.md")) headers.set("Content-Type", "text/markdown; charset=utf-8")
    if (asset.status === 200 && NOT_FOUND_PAGE.has(path)) return new Response(asset.body, { status: 404, headers })
    return new Response(asset.body, { status: asset.status, statusText: asset.statusText, headers })
  },
} satisfies ExportedHandler<Env>
