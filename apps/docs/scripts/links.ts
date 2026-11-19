// Links as the sources write them, and where they go: a relative `.md` file
// under docs/site/ is that page, a `/path` is a page or a file the site
// serves, `#id` is on the same page, and an https URL or a mailto: link to
// an address at mehen.dev is left as it is.
// Anything else does not resolve, and the build fails on it.

import path from "node:path"

export type LinkTarget =
  | { kind: "anchor"; hash: string }
  | { kind: "page"; url: string; hash: string }
  | { kind: "file"; url: string }
  | { kind: "external"; href: string }

export type LinkContext = {
  // The page's source, from the repository root: docs/site/reference/cli.md.
  file: string
  // The source directory, from the repository root: docs/site.
  sourceRoot: string
  pages: ReadonlySet<string>
  files: ReadonlySet<string>
}

function splitHash(href: string): [string, string] {
  const at = href.indexOf("#")
  return at < 0 ? [href, ""] : [href.slice(0, at), href.slice(at)]
}

export function resolveLink(href: string, ctx: LinkContext): LinkTarget | null {
  if (href.startsWith("#")) return href.length > 1 ? { kind: "anchor", hash: href } : null
  if (/^https?:\/\//i.test(href)) return { kind: "external", href }
  // A mail link only to an address at mehen.dev (the security contact).
  if (/^mailto:[a-z0-9.+-]+@mehen\.dev$/.test(href)) return { kind: "external", href }
  if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith("//")) return null
  const [target, hash] = splitHash(href)
  if (target.startsWith("/")) {
    if (ctx.pages.has(target)) return { kind: "page", url: target, hash }
    if (ctx.files.has(target) && hash === "") return { kind: "file", url: target }
    return null
  }
  if (!target.endsWith(".md")) return null
  const joined = path.posix.normalize(path.posix.join(path.posix.dirname(ctx.file), target))
  if (!joined.startsWith(`${ctx.sourceRoot}/`)) return null
  const bare = joined.slice(ctx.sourceRoot.length + 1).replace(/\.md$/, "")
  const url = bare === "index" ? "/" : `/${bare}`
  return ctx.pages.has(url) ? { kind: "page", url, hash } : null
}

// The href a page's HTML uses.
export function htmlHref(target: LinkTarget): string {
  if (target.kind === "anchor") return target.hash
  if (target.kind === "external") return target.href
  if (target.kind === "file") return target.url
  return `${target.url}${target.hash}`
}

// The href a page's markdown twin uses: absolute, and the twin of a page,
// so an agent that follows it gets markdown. Anchors on the page stay.
export function twinHref(target: LinkTarget, origin: string): string {
  if (target.kind === "anchor") return target.hash
  if (target.kind === "external") return target.href
  if (target.kind === "file") return `${origin}${target.url}`
  return `${origin}${target.url === "/" ? "/index" : target.url}.md${target.hash}`
}

const FENCE = /^ {0,3}(`{3,}|~{3,})/

// Every inline link `[text](href)` outside code, its href replaced by
// `rewrite`. Code spans and fenced blocks are left as they are.
export function rewriteLinks(markdown: string, rewrite: (href: string, line: number) => string): string {
  let fence: string | null = null
  return markdown
    .split("\n")
    .map((line, n) => {
      const marker = FENCE.exec(line)?.[1]
      if (marker !== undefined) {
        if (fence === null) fence = marker
        else if (marker[0] === fence[0] && marker.length >= fence.length && line.trim() === marker) fence = null
        return line
      }
      if (fence !== null) return line
      return line
        .split(/(`+[^`]*`+)/)
        .map((part) => (part.startsWith("`") ? part : part.replace(/\]\(\s*<?([^()\s<>]+)>?(\s+"[^"]*")?\s*\)/g, (_, href: string, title: string | undefined) => `](${rewrite(href, n + 1)}${title ?? ""})`)))
        .join("")
    })
    .join("\n")
}
