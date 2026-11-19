import { expect, test } from "bun:test"
import { type DocLinks, headingSlug, renderMarkdown } from "./markdown.ts"

const links: DocLinks = {
  href: (href) => (href.startsWith("#") || href.startsWith("https://") ? href : href === "page.md" ? "/page" : null),
  path: () => null,
}

const render = (source: string) => renderMarkdown(source, links)

test("headings get GitHub's ids, duplicates suffixed, and an anchor link", () => {
  const out = render("# Title\n\n## Find what exists\n\n## `approval_required`: what to say\n\n## Find what exists\n")
  expect(out.title).toBe("Title")
  expect(out.headings.map((h) => [h.level, h.id, h.text])).toEqual([
    [1, "title", "Title"],
    [2, "find-what-exists", "Find what exists"],
    [2, "approval_required-what-to-say", "approval_required: what to say"],
    [2, "find-what-exists-1", "Find what exists"],
  ])
  expect(out.body.value).toContain('<h2 id="find-what-exists">Find what exists<a class="doc-anchor" href="#find-what-exists" aria-label="Link to this section">#</a></h2>')
  expect(headingSlug("Workspaces, homes and who decides")).toBe("workspaces-homes-and-who-decides")
})

test("a fenced block is escaped code with the app's copy button", () => {
  const out = render("```sh\nmehen fetch x GET 'https://a.example/?q=<b>'\n```\n")
  expect(out.body.value).toBe('<div class="doc-code"><pre><code data-lang="sh">mehen fetch x GET &#39;https://a.example/?q=&lt;b&gt;&#39;</code></pre><button type="button" class="btn secondary sm" data-copy aria-label="Copy"><svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/></svg><span>Copy</span></button></div>')
})

test("a table keeps alignment and escaped pipes inside code", () => {
  const out = render("| A | B |\n| :-- | --: |\n| `x\\|y` | 2 |\n")
  expect(out.body.value).toBe('<div class="doc-table"><table><thead><tr><th class="al-l">A</th><th class="al-r">B</th></tr></thead><tbody><tr><td class="al-l"><code>x|y</code></td><td class="al-r">2</td></tr></tbody></table></div>')
})

test("lists, tight and loose, ordered with a start", () => {
  expect(render("- one\n- two\n").body.value).toBe("<ul><li>one</li><li>two</li></ul>")
  expect(render("3. three\n4. four\n").body.value).toBe('<ol start="3"><li>three</li><li>four</li></ol>')
  expect(render("- one\n\n- two\n").body.value).toBe("<ul><li><p>one</p></li><li><p>two</p></li></ul>")
})

test("links go through the resolver; an unresolved one is plain text", () => {
  const out = render("[a](page.md) [b](#here) [c](https://mehen.dev/) [d](nowhere.md) [e](javascript:alert)\n")
  expect(out.body.value).toBe('<p><a href="/page">a</a> <a href="#here">b</a> <a href="https://mehen.dev/" rel="noreferrer">c</a> d e</p>')
})

test("raw HTML in the source is shown as text", () => {
  expect(render('<script>alert("x")</script>\n').body.value).toBe("<p>&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;</p>")
})

test("front matter is not part of the page", () => {
  const out = render("---\nname: mehen\n---\n# Skill\n")
  expect(out.title).toBe("Skill")
  expect(out.body.value).not.toContain("name: mehen")
})
