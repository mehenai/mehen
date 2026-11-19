// Builds docs.mehen.dev into public/: every page under docs/site/ as HTML
// with the template and as its markdown twin, the generated reference pages
// from generated/*.json (scripts/generate.ts runs first), llms.txt,
// llms-full.txt, index.json, the search index, the sitemap, robots.txt, the
// 404 page and the /search shell, the browser scripts, and the brand's
// fonts, favicon, touch icon and social card. No dates: the same commit builds the same
// bytes. A link that does not resolve fails the build.
//
//   bun scripts/build.ts

import { cp, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises"
import path from "node:path"
import { Html, html } from "../src/html.ts"
import { type DocHeading, renderMarkdown } from "../src/markdown.ts"
import { SEARCH_QUERY_MARK, SEARCH_RESULTS_MARK } from "../src/search-page.ts"
import type { SearchEntry } from "../src/search.ts"
import type { Generated } from "./generate.ts"
import { type LinkContext, htmlHref, resolveLink, rewriteLinks, twinHref } from "./links.ts"
import { COVERS_LABEL, type Covers, type SourcePage, loadPages } from "./pages.ts"
import { type CliReference, EXIT_CODES, type ErrorEntry, type McpReference, type ProvidersReference, cliMarkdown, errorsMarkdown, exitProse, mcpMarkdown, platformMarkdown, providersMarkdown, splitEntries } from "./reference.ts"
import { type NavPage, type SiteConfig, navOrder, renderPage, twinPath, withQuestion } from "./template.ts"

const DOCS_ROOT = path.resolve(import.meta.dir, "..")
const REPO_ROOT = path.resolve(DOCS_ROOT, "../..")

export type SiteIndexPage = { url: string; md: string; title: string; question: string; section: string; covers: Covers | null; agentOnly: boolean; headings: DocHeading[] }
export type SiteIndex = { site: string; cli: string; commit: string; pages: SiteIndexPage[] }

export type BuiltPage = { source: SourcePage; nav: NavPage; markdown: string; twin: string; html: string; headings: DocHeading[] }

export type BuildOptions = {
  repoRoot: string
  // docs/site, absolute.
  sourceDir: string
  outDir: string
  // The JSON generate.ts wrote; null for a site without generated pages.
  generated: Generated | null
  version: string
  commit: string
  // Copy the brand files and build the browser scripts (not for test sites).
  assets: boolean
}

export type BuildResult = { site: SiteConfig; pages: BuiltPage[]; index: SiteIndex; search: SearchEntry[]; files: string[] }

// The files a page may link to that are not pages.
function servedFiles(pages: readonly SourcePage[], generated: boolean): Set<string> {
  const files = ["/llms.txt", "/llms-full.txt", "/index.json", "/search-index.json", "/sitemap.xml", "/robots.txt", "/search"]
  if (generated) files.push("/reference/cli.json", "/reference/errors.json", "/reference/mcp.json", "/reference/providers.json", "/reference/platform.json")
  return new Set([...files, ...pages.map((p) => twinPath(p.url))])
}

// The order of the navigation: sections in the site's order, then each
// page's `order`, then its URL.
function sortPages(site: SiteConfig, pages: SourcePage[]): SourcePage[] {
  const rank = (id: string) => {
    const at = site.sections.findIndex((s) => s.id === id)
    return at < 0 ? site.sections.length : at
  }
  return [...pages].sort((a, b) => rank(a.meta.section) - rank(b.meta.section) || a.meta.order - b.meta.order || a.url.localeCompare(b.url))
}

function navPage(page: SourcePage): NavPage {
  return { url: page.url, title: page.meta.title, question: page.meta.question, section: page.meta.section, agentOnly: page.meta.agentOnly }
}

// The markdown a page serves: its source, with the generated reference
// joined in, or the exact bytes of the file it names.
async function composed(page: SourcePage, all: readonly SourcePage[], options: BuildOptions): Promise<string> {
  if (page.meta.bytes !== null) return await readFile(path.join(options.repoRoot, page.meta.bytes), "utf8")
  if (page.meta.include !== null) return `${page.body.trimEnd()}\n\n${demoteHeadings(await readFile(path.join(options.repoRoot, page.meta.include), "utf8"))}`
  const kind = page.meta.generate
  if (kind === null) return page.body
  const generated = options.generated
  if (generated === null) throw new Error(`${page.file}: generate: ${kind} needs scripts/generate.ts to have run`)
  const hand = splitEntries(page.body, page.file)
  const errorsPage = all.find((p) => p.meta.generate === "errors")
  const exits = () => {
    if (!errorsPage) throw new Error(`${page.file}: the exit codes come from the errors page, and there is none`)
    return exitProse(splitEntries(errorsPage.body, errorsPage.file), EXIT_CODES, errorsPage.file)
  }
  if (kind === "cli") return cliMarkdown(hand, generated.cli as CliReference, exits())
  if (kind === "errors") return errorsMarkdown(hand, generated.errors as ErrorEntry[], exits())
  if (kind === "mcp") return mcpMarkdown(hand, generated.mcp as McpReference, page.file)
  if (kind === "platform") return platformMarkdown(hand, generated.platform, page.file)
  return providersMarkdown(hand, generated.providers as unknown as ProvidersReference, page.file)
}

// The twin says which side the page covers on the line under its title, as
// the HTML does.
export function withCovers(markdown: string, covers: string | null): string {
  if (covers === null) return markdown
  const h1 = /^# .*$/m.exec(markdown)
  if (!h1) return `Covers: ${covers}\n\n${markdown}`
  const end = h1.index + h1[0].length
  return `${markdown.slice(0, end)}\n\nCovers: ${covers}${markdown.slice(end)}`
}

// Every heading outside code one level down, so an included document's
// title sits under the page's own.
export function demoteHeadings(markdown: string): string {
  let fence: string | null = null
  return markdown
    .split("\n")
    .map((line) => {
      const marker = /^ {0,3}(`{3,}|~{3,})/.exec(line)?.[1]
      if (marker !== undefined) {
        if (fence === null) fence = marker
        else if (marker[0] === fence[0] && marker.length >= fence.length && line.trim() === marker) fence = null
        return line
      }
      return fence === null && /^#{1,5} /.test(line) ? `#${line}` : line
    })
    .join("\n")
}

// The home page: the category line under the title, the two ways to start
// side by side, the three steps as cards and the sections as tiles. Built
// from the renderer's own output, split at its h2s, so the markdown twin
// stays plain markdown.
export function homeBody(body: Html, category: string, covers: string | null = null): Html {
  const value = body.value
  const starts = [...value.matchAll(/<h2 id="([^"]+)">/g)].map((m) => ({ at: m.index as number, id: m[1] as string }))
  const intro = value.slice(0, starts[0]?.at ?? value.length)
  const part = (id: string) => {
    const n = starts.findIndex((s) => s.id === id)
    return n < 0 ? "" : value.slice((starts[n] as { at: number }).at, starts[n + 1]?.at ?? value.length)
  }
  const used = new Set(["run-it-on-your-machine", "paste-this-to-your-agent", "how-it-works", "where-to-go"])
  const sub = html`<p class="sub">${category}</p>${covers ? html`<p class="covers">Covers: ${covers}</p>` : ""}`.value
  const how = part("how-it-works")
  const howCards = how.split(/(?=<h3 id=)/)
  const where = part("where-to-go").replace("<ul>", '<ul class="tiles">').replaceAll("</a>: ", "</a>")
  const rest = starts.filter((s) => !used.has(s.id)).map((s) => part(s.id)).join("")
  return new Html(
    `<div class="home-head">${intro.replace("</h1>", `</h1>${sub}`)}</div>` +
      `<div class="paths"><section class="card">${part("run-it-on-your-machine")}</section><section class="card">${part("paste-this-to-your-agent")}</section></div>` +
      (how ? `<section class="home-how">${howCards[0]}<div class="steps">${howCards.slice(1).map((c) => `<div class="card">${c}</div>`).join("")}</div></section>` : "") +
      (where ? `<section class="home-where">${where}</section>` : "") +
      rest,
  )
}

const ENTITIES: Record<string, string> = { "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#39;": "'", "&#96;": "`" }

function textOf(fragment: string): string {
  return fragment
    .replace(/<button[^>]*>[\s\S]*?<\/button>/g, " ")
    .replace(/<a class="doc-anchor"[^>]*>#<\/a>/g, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&(?:amp|lt|gt|quot|#39|#96);/g, (e) => ENTITIES[e] as string)
    .replace(/\s+/g, " ")
    .trim()
}

const SEARCH_TEXT_CHARS = 320

// One entry per h2 and h3: the text from the heading to the next h2 or h3.
export function searchEntries(url: string, title: string, body: string, headings: readonly DocHeading[]): SearchEntry[] {
  const out: SearchEntry[] = []
  const starts = [...body.matchAll(/<h([23]) id="([^"]+)">/g)].map((m) => ({ at: m.index as number, id: m[2] as string }))
  starts.forEach((start, n) => {
    const end = starts[n + 1]?.at ?? body.length
    const section = body.slice(start.at, end)
    const close = section.search(/<\/h[23]>/)
    const heading = headings.find((h) => h.id === start.id)
    out.push({ u: `${url === "/" ? "/" : url}#${start.id}`, t: title, h: heading?.text ?? start.id, x: textOf(section.slice(close)).slice(0, SEARCH_TEXT_CHARS) })
  })
  return out
}

function llmsTxt(site: SiteConfig, built: readonly BuiltPage[], generated: boolean): string {
  const line = (p: NavPage) => `- [${p.title}](${site.siteOrigin}${twinPath(p.url)}): ${p.question}`
  const out = [`# ${site.name}`, "", `> ${site.category} ${site.promise}`, "", `Every page is also markdown: add \`.md\` to its address (the home page is \`/index.md\`), or send \`Accept: text/markdown\`.`, ""]
  for (const section of site.sections) {
    const pages = built.filter((b) => b.nav.section === section.id && !b.nav.agentOnly)
    if (pages.length === 0) continue
    out.push(`## ${section.title}`, "", ...pages.map((b) => line(b.nav)), "")
  }
  const agents = built.filter((b) => b.nav.agentOnly || b.nav.url === "/setup").map((b) => line(b.nav))
  out.push("## For agents", "", ...agents)
  out.push(`- [Every page in one file](${site.siteOrigin}/llms-full.txt): the markdown of every page above, in this order`)
  out.push(`- [The page index](${site.siteOrigin}/index.json): every page with its question and headings, as JSON`)
  if (generated) out.push(`- [Every error code](${site.siteOrigin}/reference/errors.json): code, HTTP status, exit code, default next step, what it means and what to do, as JSON`)
  return `${out.join("\n")}\n`
}

function llmsFullTxt(site: SiteConfig, built: readonly BuiltPage[]): string {
  return built.map((b) => `# ${b.nav.title}\n\nURL: ${site.siteOrigin}${b.nav.url === "/" ? "/" : b.nav.url}\n\n${b.twin.trimEnd()}\n`).join("\n\n")
}

function sitemap(site: SiteConfig, built: readonly BuiltPage[]): string {
  const urls = built.map((b) => `  <url><loc>${site.siteOrigin}${b.nav.url === "/" ? "/" : b.nav.url}</loc></url>`)
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join("\n")}\n</urlset>\n`
}

function notFoundBody(site: SiteConfig, nav: readonly NavPage[]): Html {
  const indexes = site.sections.map((s) => nav.find((p) => p.url === s.index) ?? nav.find((p) => p.section === s.id)).filter((p): p is NavPage => p !== undefined)
  return html`<h1 id="page-not-found">Page not found</h1><p class="question">There is no page at this address.</p><p>Search the docs with the box at the top, or start from one of these:</p><ul>${indexes.map((p) => html`<li><a href="${p.url}">${p.title}</a>: ${p.question}</li>`)}</ul>`
}

async function writeOut(outDir: string, file: string, content: string | Uint8Array): Promise<void> {
  const target = path.join(outDir, file)
  await mkdir(path.dirname(target), { recursive: true })
  await writeFile(target, content)
}

// The faces docs.css names and their licences, from packages/brand.
const FONTS = ["Inter-normal-100-900.woff2", "JetBrainsMono-normal-100-800.woff2", "Fraunces-normal-100-900.woff2", "OFL-inter.txt", "OFL-jetbrains-mono.txt", "OFL-fraunces.txt"]

async function copyAssets(repoRoot: string, outDir: string): Promise<void> {
  const brand = path.join(repoRoot, "packages/brand")
  await rm(path.join(outDir, "fonts"), { recursive: true, force: true })
  await mkdir(path.join(outDir, "fonts"), { recursive: true })
  for (const font of FONTS) await cp(path.join(brand, "fonts", font), path.join(outDir, "fonts", font))
  await cp(path.join(brand, "marks/favicon.svg"), path.join(outDir, "favicon.svg"))
  await cp(path.join(repoRoot, "apps/web/public/og.jpg"), path.join(outDir, "og.jpg"))
  await cp(path.join(repoRoot, "apps/web/public/apple-touch-icon.png"), path.join(outDir, "apple-touch-icon.png"))
  // Plain scripts, not modules: theme.js runs blocking in <head>, docs.js deferred.
  const result = await Bun.build({
    entrypoints: [path.join(repoRoot, "apps/docs/src/client/docs.ts"), path.join(repoRoot, "apps/docs/src/client/theme.ts")],
    outdir: outDir,
    target: "browser",
    format: "iife",
    minify: true,
    sourcemap: "none",
    naming: { entry: "[name].[ext]" },
  })
  if (!result.success) throw new AggregateError(result.logs, "the browser scripts did not build")
}

export async function buildSite(options: BuildOptions): Promise<BuildResult> {
  const site = JSON.parse(await readFile(path.join(options.sourceDir, "site.json"), "utf8")) as SiteConfig
  const sourceRoot = path.relative(options.repoRoot, options.sourceDir)
  const pages = sortPages(site, await loadPages(options.sourceDir, options.repoRoot))
  for (const page of pages) if (!site.sections.some((s) => s.id === page.meta.section)) throw new Error(`${page.file}: section ${page.meta.section} is not in site.json`)
  const pageUrls = new Set(pages.map((p) => p.url))
  const files = servedFiles(pages, options.generated !== null)
  const nav = navOrder(site, pages.map(navPage))
  const byUrl = new Map(pages.map((p) => [p.url, p]))
  const sprite = new Html((await readFile(path.join(options.repoRoot, "packages/brand/marks/sprite.svg"), "utf8")).trim())
  const problems: string[] = []
  const built: BuiltPage[] = []

  for (const navEntry of nav) {
    const source = byUrl.get(navEntry.url) as SourcePage
    const covers = source.meta.covers === null ? null : COVERS_LABEL[source.meta.covers]
    const own = await composed(source, pages, options)
    const markdown = withCovers(own, covers)
    const ctx: LinkContext = { file: source.file, sourceRoot, pages: pageUrls, files }
    const resolve = (href: string) => {
      const target = resolveLink(href, ctx)
      if (target === null) problems.push(`${source.file}: the link ${href} is not a page, a file the site serves or an https URL`)
      return target
    }
    const rendered = renderMarkdown(own, { href: (href) => { const t = resolve(href); return t === null ? null : htmlHref(t) }, path: () => null })
    const body = source.url === "/" ? homeBody(rendered.body, site.category, covers) : withQuestion(rendered.body, source.meta.question, rendered.headings, covers)
    const twin = source.meta.bytes !== null ? markdown : rewriteLinks(markdown, (href) => { const t = resolveLink(href, ctx); return t === null ? href : twinHref(t, site.siteOrigin) })
    const page = renderPage({ site, nav, page: navEntry, title: source.meta.title, description: source.meta.question, body, headings: rendered.headings, version: options.version, sprite, query: "", home: source.url === "/" })
    built.push({ source, nav: navEntry, markdown, twin, html: page, headings: rendered.headings })
  }
  if (problems.length) throw new Error(problems.join("\n"))

  const search = built.flatMap((b) => searchEntries(b.nav.url, b.nav.title, b.html.slice(b.html.indexOf('<main id="content"'), b.html.indexOf("</main>")), b.headings))
  const index: SiteIndex = {
    site: site.siteOrigin,
    cli: options.version,
    commit: options.commit,
    pages: built.map((b) => ({ url: b.nav.url, md: twinPath(b.nav.url), title: b.nav.title, question: b.nav.question, section: b.nav.section, covers: b.source.meta.covers, agentOnly: b.nav.agentOnly, headings: b.headings })),
  }

  await mkdir(options.outDir, { recursive: true })
  const written: string[] = []
  const write = async (file: string, content: string) => {
    await writeOut(options.outDir, file, content)
    written.push(file)
  }
  for (const b of built) {
    await write(b.nav.url === "/" ? "index.html" : `${b.nav.url.slice(1)}.html`, b.html)
    await write(twinPath(b.nav.url).slice(1), b.twin)
  }
  const shell = { site, nav, page: null, headings: [], version: options.version, sprite, home: false }
  await write("404.html", renderPage({ ...shell, title: "Page not found", description: "There is no page at this address.", body: notFoundBody(site, nav), query: "" }))
  await write("search.html", renderPage({ ...shell, title: "Search", description: "Search the Mehen docs.", body: new Html(SEARCH_RESULTS_MARK), query: SEARCH_QUERY_MARK }))
  await write("llms.txt", llmsTxt(site, built, options.generated !== null))
  await write("llms-full.txt", llmsFullTxt(site, built))
  await write("index.json", `${JSON.stringify(index, null, 2)}\n`)
  await write("search-index.json", `${JSON.stringify(search)}\n`)
  await write("sitemap.xml", sitemap(site, built))
  await write("robots.txt", `User-agent: *\nAllow: /\nSitemap: ${site.siteOrigin}/sitemap.xml\n`)
  if (options.generated) {
    for (const [name, value] of Object.entries(options.generated)) await write(`reference/${name}.json`, `${JSON.stringify(value, null, 2)}\n`)
  }
  if (options.assets) await copyAssets(options.repoRoot, options.outDir)
  return { site, pages: built, index, search, files: written }
}

async function commitOf(repoRoot: string): Promise<string> {
  const proc = Bun.spawn(["git", "rev-parse", "--short", "HEAD"], { cwd: repoRoot, stdout: "pipe", stderr: "ignore" })
  const out = (await new Response(proc.stdout).text()).trim()
  return (await proc.exited) === 0 && out ? out : "unknown"
}

// The generated JSON from generated/, as generate.ts wrote it.
export async function readGenerated(dir: string): Promise<Generated> {
  const read = async (name: string) => JSON.parse(await readFile(path.join(dir, `${name}.json`), "utf8")) as unknown
  return {
    cli: (await read("cli")) as Generated["cli"],
    errors: (await read("errors")) as Generated["errors"],
    mcp: (await read("mcp")) as Generated["mcp"],
    providers: (await read("providers")) as Generated["providers"],
    platform: (await read("platform")) as Generated["platform"],
  }
}

// Build output from an earlier build that this one does not write again.
async function clean(outDir: string): Promise<void> {
  const keep = new Set(["docs.css"])
  for (const entry of await readdir(outDir)) if (!keep.has(entry)) await rm(path.join(outDir, entry), { recursive: true, force: true })
}

if (import.meta.main) {
  const outDir = path.join(DOCS_ROOT, "public")
  await clean(outDir)
  const cliPackage = JSON.parse(await readFile(path.join(REPO_ROOT, "apps/cli/package.json"), "utf8")) as { version: string }
  const result = await buildSite({
    repoRoot: REPO_ROOT,
    sourceDir: path.join(REPO_ROOT, "docs/site"),
    outDir,
    generated: await readGenerated(path.join(DOCS_ROOT, "generated")),
    version: cliPackage.version,
    commit: await commitOf(REPO_ROOT),
    assets: true,
  })
  console.log(`built ${result.pages.length} pages, ${result.search.length} search entries and ${result.files.length} files into ${path.relative(DOCS_ROOT, outDir)}/`)
}
