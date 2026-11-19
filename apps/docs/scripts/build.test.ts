import { afterAll, beforeAll, expect, test } from "bun:test"
import { cp, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { headingSlug } from "../src/markdown.ts"
import { type BuildResult, buildSite } from "./build.ts"

const DOCS = path.resolve(import.meta.dir, "..")
const REPO = path.resolve(DOCS, "../..")
const FIXTURE = path.join(import.meta.dir, "fixtures/site")

let scratch: string
let first: BuildResult

const build = (outDir: string, sourceDir = FIXTURE) => buildSite({ repoRoot: REPO, sourceDir, outDir, generated: null, version: "9.9.9", commit: "abc1234", assets: false })

async function files(dir: string): Promise<Map<string, string>> {
  const out = new Map<string, string>()
  const walk = async (d: string) => {
    for (const entry of await readdir(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name)
      if (entry.isDirectory()) await walk(full)
      else out.set(path.relative(dir, full), await readFile(full, "utf8"))
    }
  }
  await walk(dir)
  return out
}

beforeAll(async () => {
  scratch = await mkdtemp(path.join(tmpdir(), "mehen-docs-build-"))
  first = await build(path.join(scratch, "one"))
})
afterAll(async () => {
  await rm(scratch, { recursive: true, force: true })
})

const out = (file: string) => readFile(path.join(scratch, "one", file), "utf8")

test("every page has its HTML and its markdown twin, front matter removed", async () => {
  expect(first.pages.map((p) => p.nav.url)).toEqual(["/", "/guides/first"])
  for (const file of ["index.html", "index.md", "guides/first.html", "guides/first.md", "404.html", "search.html", "llms.txt", "llms-full.txt", "index.json", "search-index.json", "sitemap.xml", "robots.txt"]) expect(await out(file)).not.toBe("")
  const twin = await out("index.md")
  expect(twin).toStartWith("# Fixture home\n")
  expect(twin).not.toContain("question:")
})

test("relative links are absolute in the twin and site paths in the HTML", async () => {
  const twin = await out("index.md")
  expect(twin).toContain("[link to the guide](https://docs.mehen.dev/guides/first.md#the-same-heading)")
  expect(twin).toContain("[to an anchor here](#a-heading-with-code-and-punctuation)")
  expect(await out("guides/first.md")).toContain("[the home page](https://docs.mehen.dev/index.md) and [its code](https://docs.mehen.dev/index.md#a-heading-with-code-and-punctuation)")
  const html = await out("index.html")
  expect(html).toContain('<a href="/guides/first#the-same-heading">link to the guide</a>')
})

test("heading ids follow GitHub's algorithm, duplicates suffixed", async () => {
  const home = first.pages[0]
  expect(home?.headings.map((h) => h.id)).toEqual(["fixture-home", "a-heading-with-code-and-punctuation", "the-same-heading", "the-same-heading-1"])
  for (const h of home?.headings ?? []) expect(h.id.replace(/-1$/, "")).toBe(headingSlug(h.text))
  expect(await out("index.html")).toContain('<h2 id="a-heading-with-code-and-punctuation">A heading with <code>code</code>, and punctuation!<a class="doc-anchor" href="#a-heading-with-code-and-punctuation"')
})

test("the copy button sits beside the code it copies, and the code is the fence's text", async () => {
  const html = await out("index.html")
  const block = /<div class="doc-code"><pre><code data-lang="sh">([\s\S]*?)<\/code><\/pre><button type="button" class="btn secondary sm" data-copy aria-label="Copy">/.exec(html)
  const text = (block?.[1] ?? "").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&amp;/g, "&")
  expect(text).toBe('mehen status --json\necho "<not markup>"')
})

test("raw HTML in a source shows as text, and a cell keeps an escaped pipe", async () => {
  const html = await out("guides/first.html")
  expect(html).toContain("&lt;b&gt;raw HTML shows as text&lt;/b&gt;")
  expect(html).toContain("<td><code>a|b</code></td>")
})

test("the page carries its question, its twin link and the navigation", async () => {
  const html = await out("guides/first.html")
  expect(html).toContain('<p class="question">Does a second page link back?</p>')
  expect(html).toContain('<link rel="alternate" type="text/markdown" href="/guides/first.md">')
  expect(html).toContain('<a href="/guides/first" aria-current="page">The first guide</a>')
  expect(html).toContain('<a rel="prev" href="/"><small>Previous</small>Fixture home</a>')
  expect(html).toContain("mehen 9.9.9")
})

test("the line under the title says which side the page covers, in the HTML, the twin and index.json", async () => {
  expect(await out("guides/first.html")).toContain('</h1><p class="covers">Covers: Local only</p><p class="question">')
  expect(await out("index.html")).toContain('<p class="covers">Covers: Local and Cloud</p>')
  expect(await out("guides/first.md")).toStartWith("# The first guide\n\nCovers: Local only\n\n")
  const index = JSON.parse(await out("index.json")) as { pages: { covers: string | null }[] }
  expect(index.pages.map((p) => p.covers)).toEqual(["both", "local"])
})

test("a page that does not say which side it covers fails the build", async () => {
  const site = path.join(scratch, "no-covers")
  await cp(FIXTURE, site, { recursive: true })
  await writeFile(path.join(site, "guides/first.md"), (await readFile(path.join(FIXTURE, "guides/first.md"), "utf8")).replace("covers: local\n", ""))
  await expect(build(path.join(scratch, "no-covers-out"), site)).rejects.toThrow("front matter needs covers (both, local, cloud)")
  await writeFile(path.join(site, "guides/first.md"), (await readFile(path.join(FIXTURE, "guides/first.md"), "utf8")).replace("covers: local", "covers: everywhere"))
  await expect(build(path.join(scratch, "no-covers-out"), site)).rejects.toThrow("covers is one of both, local, cloud")
})

test("index.json lists both pages with their headings, and no date", async () => {
  const index = JSON.parse(await out("index.json")) as { site: string; cli: string; commit: string; pages: { url: string; md: string; headings: { id: string }[] }[] }
  expect(index.site).toBe("https://docs.mehen.dev")
  expect(index.cli).toBe("9.9.9")
  expect(index.commit).toBe("abc1234")
  expect(index.pages.map((p) => [p.url, p.md])).toEqual([["/", "/index.md"], ["/guides/first", "/guides/first.md"]])
  expect(index.pages[1]?.headings.map((h) => h.id)).toEqual(["the-first-guide", "the-same-heading"])
})

test("the search index has one entry per h2 and h3", async () => {
  const search = JSON.parse(await out("search-index.json")) as { u: string; t: string; h: string; x: string }[]
  expect(search.map((e) => e.u)).toEqual(["/#a-heading-with-code-and-punctuation", "/#the-same-heading", "/#the-same-heading-1", "/guides/first#the-same-heading"])
  expect(search[1]).toEqual({ u: "/#the-same-heading", t: "Fixture home", h: "The same heading", x: "Text under the first one." })
  expect(search[0]?.x).toBe('mehen status --json echo "<not markup>"')
})

test("llms.txt lists every page with its question; llms-full.txt carries every twin", async () => {
  const llms = await out("llms.txt")
  expect(llms).toContain("> Access for agents. Use credentials without reading them.")
  expect(llms).toContain("- [Fixture home](https://docs.mehen.dev/index.md): What does the build make of a page?")
  expect(llms).toContain("## Guides\n\n- [The first guide](https://docs.mehen.dev/guides/first.md): Does a second page link back?")
  const full = await out("llms-full.txt")
  for (const page of first.pages) expect(full).toContain(page.twin.trimEnd())
  expect(full).toContain("URL: https://docs.mehen.dev/guides/first")
})

test("two builds of the same sources are byte-identical", async () => {
  await build(path.join(scratch, "two"))
  expect(await files(path.join(scratch, "two"))).toEqual(await files(path.join(scratch, "one")))
})

test("a link to something that is not a page fails the build", async () => {
  const site = path.join(scratch, "bad-site")
  await cp(FIXTURE, site, { recursive: true })
  await writeFile(path.join(site, "guides/first.md"), (await readFile(path.join(FIXTURE, "guides/first.md"), "utf8")).replace("../index.md", "../nowhere.md"))
  expect(build(path.join(scratch, "bad"), site)).rejects.toThrow("the link ../nowhere.md is not a page")
})

// The role tokens in docs.css are the app's (apps/vault/src/ui/client/app.css,
// its :root block, one light-dark() pair each); until they move into
// packages/brand, the two copies must not drift. The docs differ in one
// deliberate place: color-scheme follows the system, where the app defaults
// to light because a member chooses. docs.css is served as is, so its own
// comments name nothing internal.
test("docs.css carries the app's role tokens", async () => {
  const declarations = (css: string, from: number) => {
    const start = css.indexOf(":root {", from)
    const end = css.indexOf("\n}\n", start)
    return [...css.slice(start, end).matchAll(/^\s*(--[\w-]+):\s*([^;]+);/gm)].map((m) => [m[1], m[2]?.replace(/\s+/g, " ")])
  }
  const docs = await readFile(path.join(DOCS, "public/docs.css"), "utf8")
  const app = await readFile(path.join(REPO, "apps/vault/src/ui/client/app.css"), "utf8")
  const fromDocs = declarations(docs, docs.indexOf("/* role tokens: start */"))
  expect(fromDocs.length).toBeGreaterThan(70)
  expect(fromDocs).toEqual(declarations(app, 0))
})
