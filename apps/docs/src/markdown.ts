// Markdown for the docs pages: the subset the documents use (headings,
// paragraphs, fenced code, GFM tables, lists, block quotes, rules, code
// spans, strong, emphasis and links). Moved from the vault's /docs pages so
// heading anchors and copy buttons stay the same. Nothing in a source
// becomes markup except through these rules and the escaping `html`
// template: raw HTML in the source shows as text.

import { Html, type HtmlValue, html, safeHref } from "./html.ts"

// The app's copy icon (the vault's icons.ts), inlined: the only icon here.
const COPY_ICON = new Html('<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/></svg>')

export type DocHeading = { level: number; id: string; text: string }

// Where a link in the source goes: a path on the site, an anchor, an
// http(s) URL, or null to show the text unlinked.
export type LinkResolver = (href: string) => string | null

// `href` resolves a link as written in the document; `path` resolves a code
// span that is exactly a `.md` file name (the docs site links none).
export type DocLinks = { href: LinkResolver; path: LinkResolver }

export type RenderedMarkdown = { body: Html; title: string | null; headings: DocHeading[] }

type Align = "left" | "center" | "right" | null

type Block =
  | { type: "heading"; level: number; text: string }
  | { type: "paragraph"; lines: string[] }
  | { type: "code"; lang: string; text: string }
  | { type: "rule" }
  | { type: "quote"; blocks: Block[] }
  | { type: "list"; ordered: boolean; start: number; loose: boolean; items: Block[][] }
  | { type: "table"; align: Align[]; head: string[]; rows: string[][] }

const FENCE = /^( {0,3})(`{3,}|~{3,})\s*([^`]*)$/
const HEADING = /^ {0,3}(#{1,6})(?:\s+(.*?))?\s*$/
const RULE = /^ {0,3}([-*_])(?:\s*\1){2,}\s*$/
const LIST = /^( *)([-*+]|\d{1,9}[.)])( +|$)(.*)$/
const QUOTE = /^ {0,3}> ?(.*)$/
const TABLE_SEP = /^ {0,3}\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/
const PUNCTUATION = /[!-/:-@[-`{-~]/

const isBlank = (line: string): boolean => line.trim() === ""
const indentOf = (line: string): number => line.length - line.trimStart().length

function stripIndent(line: string, n: number): string {
  return line.slice(Math.min(n, indentOf(line)))
}

function startsBlock(line: string): boolean {
  return FENCE.test(line) || HEADING.test(line) || RULE.test(line) || QUOTE.test(line) || LIST.test(line)
}

function isTableStart(lines: string[], i: number): boolean {
  const next = lines[i + 1]
  return (lines[i] as string).includes("|") && next !== undefined && next.includes("-") && TABLE_SEP.test(next)
}

// A row's cells, with `\|` as a literal pipe (inside code spans too, as GFM has it).
function cells(row: string): string[] {
  let s = row.trim()
  if (s.startsWith("|")) s = s.slice(1)
  if (s.endsWith("|") && !s.endsWith("\\|")) s = s.slice(0, -1)
  const out: string[] = []
  let cur = ""
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "\\" && s[i + 1] === "|") {
      cur += "|"
      i++
    } else if (s[i] === "|") {
      out.push(cur.trim())
      cur = ""
    } else cur += s[i]
  }
  out.push(cur.trim())
  return out
}

function alignOf(cell: string): Align {
  const left = cell.startsWith(":")
  const right = cell.endsWith(":")
  if (left && right) return "center"
  if (right) return "right"
  if (left) return "left"
  return null
}

function parseList(lines: string[], from: number): { block: Block; next: number } {
  const first = LIST.exec(lines[from] as string) as RegExpExecArray
  const base = (first[1] as string).length
  const ordered = /\d/.test(first[2] as string)
  const start = ordered ? Number.parseInt(first[2] as string, 10) : 1
  const items: string[][] = []
  let current: string[] = []
  let contentIndent = 0
  let loose = false
  let blankBefore = false
  let i = from
  while (i < lines.length) {
    const line = lines[i] as string
    if (isBlank(line)) {
      blankBefore = true
      current.push("")
      i++
      continue
    }
    const ind = indentOf(line)
    const m = LIST.exec(line)
    if (m && (items.length === 0 || ind < contentIndent)) {
      const markerIndent = (m[1] as string).length
      if (markerIndent < base || markerIndent > base + 3 || /\d/.test(m[2] as string) !== ordered) break
      if (items.length > 0 && blankBefore) loose = true
      blankBefore = false
      const spaces = (m[3] as string).length
      contentIndent = markerIndent + (m[2] as string).length + (m[4] === "" || spaces > 4 ? 1 : spaces)
      current = [m[4] as string]
      items.push(current)
      i++
      continue
    }
    if (ind >= contentIndent) {
      if (blankBefore) loose = true
      blankBefore = false
      current.push(line.slice(contentIndent))
      i++
      continue
    }
    // A lazy continuation of the item's paragraph.
    if (!blankBefore && !startsBlock(line) && !line.trimStart().startsWith("|")) {
      current.push(line.trim())
      i++
      continue
    }
    break
  }
  const parsed = items.map((item) => {
    while (item.length > 0 && isBlank(item[item.length - 1] as string)) item.pop()
    return parseBlocks(item)
  })
  return { block: { type: "list", ordered, start, loose, items: parsed }, next: i }
}

function parseBlocks(lines: string[]): Block[] {
  const blocks: Block[] = []
  let i = 0
  while (i < lines.length) {
    const line = lines[i] as string
    if (isBlank(line)) {
      i++
      continue
    }
    const fence = FENCE.exec(line)
    if (fence) {
      const indent = (fence[1] as string).length
      const marker = fence[2] as string
      const close = new RegExp(`^ {0,3}${marker[0] === "`" ? "`" : "~"}{${marker.length},}\\s*$`)
      const body: string[] = []
      i++
      while (i < lines.length && !close.test(lines[i] as string)) {
        body.push(stripIndent(lines[i] as string, indent))
        i++
      }
      i++
      blocks.push({ type: "code", lang: (fence[3] as string).trim().split(/\s+/)[0] ?? "", text: body.join("\n") })
      continue
    }
    const heading = HEADING.exec(line)
    if (heading) {
      blocks.push({ type: "heading", level: (heading[1] as string).length, text: (heading[2] ?? "").replace(/\s+#+$/, "") })
      i++
      continue
    }
    if (RULE.test(line)) {
      blocks.push({ type: "rule" })
      i++
      continue
    }
    if (isTableStart(lines, i)) {
      const head = cells(line)
      const align = cells(lines[i + 1] as string).map(alignOf)
      const rows: string[][] = []
      i += 2
      while (i < lines.length && !isBlank(lines[i] as string) && (lines[i] as string).includes("|")) {
        const row = cells(lines[i] as string)
        rows.push(head.map((_, n) => row[n] ?? ""))
        i++
      }
      blocks.push({ type: "table", align: head.map((_, n) => align[n] ?? null), head, rows })
      continue
    }
    if (QUOTE.test(line)) {
      const inner: string[] = []
      while (i < lines.length) {
        const q = QUOTE.exec(lines[i] as string)
        if (!q) break
        inner.push(q[1] as string)
        i++
      }
      blocks.push({ type: "quote", blocks: parseBlocks(inner) })
      continue
    }
    if (LIST.test(line)) {
      const { block, next } = parseList(lines, i)
      blocks.push(block)
      i = next
      continue
    }
    const para: string[] = []
    while (i < lines.length) {
      const l = lines[i] as string
      if (isBlank(l) || (para.length > 0 && (startsBlock(l) || isTableStart(lines, i)))) break
      para.push(l.trim())
      i++
    }
    blocks.push({ type: "paragraph", lines: para })
  }
  return blocks
}

// GitHub's anchor for a heading: lower case, punctuation dropped, each space
// a hyphen, so links written for GitHub land on the same heading here.
export function headingSlug(text: string): string {
  return plainText(text)
    .toLowerCase()
    .replace(/[^\p{L}\p{N} _-]/gu, "")
    .replace(/ /g, "-")
}

// The text of an inline run without its markup.
export function plainText(text: string): string {
  return text
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/`+([^`]*)`+/g, "$1")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\\([!-/:-@[-`{-~])/g, "$1")
}

type Context = {
  links: DocLinks
  // Line breaks inside a paragraph are kept (a quoted chat message).
  breaks: boolean
  // A tight list item: its paragraphs render without <p>.
  tight: boolean
  headings: DocHeading[]
  ids: Map<string, number>
}

// The end of a backtick run of exactly `n`, from `from`, or -1.
function codeEnd(src: string, n: number, from: number): number {
  let j = from
  while (j < src.length) {
    const k = src.indexOf("`", j)
    if (k < 0) return -1
    let run = 0
    while (src[k + run] === "`") run++
    if (run === n) return k
    j = k + run
  }
  return -1
}

// The next `delim` at or after `from` that is not inside a code span.
function findOutsideCode(src: string, delim: string, from: number): number {
  let j = from
  while (j < src.length) {
    if (src[j] === "\\") {
      j += 2
      continue
    }
    if (src[j] === "`") {
      let n = 0
      while (src[j + n] === "`") n++
      const end = codeEnd(src, n, j + n)
      j = end < 0 ? j + n : end + n
      continue
    }
    if (src.startsWith(delim, j)) return j
    j++
  }
  return -1
}

// The `]` that closes the `[` at `open`, counting nested brackets.
function closingBracket(src: string, open: number): number {
  let depth = 0
  for (let j = open; j < src.length; j++) {
    const c = src[j]
    if (c === "\\") j++
    else if (c === "`") {
      let n = 0
      while (src[j + n] === "`") n++
      const end = codeEnd(src, n, j + n)
      j = (end < 0 ? j + n : end + n) - 1
    } else if (c === "[") depth++
    else if (c === "]" && --depth === 0) return j
  }
  return -1
}

function link(target: string | null, content: Html): Html {
  if (target === null) return content
  if (/^#[^\s"'<>]+$/.test(target)) return html`<a href="${target}">${content}</a>`
  const href = safeHref(target)
  if (href === "#") return content
  const external = /^https?:/i.test(href)
  return external ? html`<a href="${href}" rel="noreferrer">${content}</a>` : html`<a href="${href}">${content}</a>`
}

const isWordChar = (c: string | undefined): boolean => c !== undefined && /[\p{L}\p{N}]/u.test(c)

export function inline(src: string, ctx: Pick<Context, "links">): Html {
  const out: HtmlValue[] = []
  let text = ""
  const flush = (): void => {
    if (text !== "") out.push(text)
    text = ""
  }
  let i = 0
  while (i < src.length) {
    const c = src[i] as string
    if (c === "\\" && i + 1 < src.length && PUNCTUATION.test(src[i + 1] as string)) {
      text += src[i + 1]
      i += 2
      continue
    }
    if (c === "`") {
      let n = 0
      while (src[i + n] === "`") n++
      const end = codeEnd(src, n, i + n)
      if (end < 0) {
        text += "`".repeat(n)
        i += n
        continue
      }
      flush()
      let code = src.slice(i + n, end).replace(/\n/g, " ")
      if (code.length > 2 && code.startsWith(" ") && code.endsWith(" ")) code = code.slice(1, -1)
      // A code span that is exactly the path of another document links to it.
      const target = /^[\w./-]+\.md(#[\w-]+)?$/.test(code) ? ctx.links.path(code) : null
      out.push(link(target, html`<code>${code}</code>`))
      i = end + n
      continue
    }
    if (c === "*" && src[i + 1] === "*" && src[i + 2] !== " ") {
      const end = findOutsideCode(src, "**", i + 2)
      if (end > i + 2 && src[end - 1] !== " ") {
        flush()
        out.push(html`<strong>${inline(src.slice(i + 2, end), ctx)}</strong>`)
        i = end + 2
        continue
      }
    }
    if (c === "*" && src[i + 1] !== "*" && src[i + 1] !== " " && src[i + 1] !== undefined && !isWordChar(src[i - 1])) {
      let end = findOutsideCode(src, "*", i + 1)
      while (end > 0 && src[end + 1] === "*") end = findOutsideCode(src, "*", end + 2)
      if (end > i + 1 && src[end - 1] !== " " && !isWordChar(src[end + 1])) {
        flush()
        out.push(html`<em>${inline(src.slice(i + 1, end), ctx)}</em>`)
        i = end + 1
        continue
      }
    }
    if (c === "[") {
      const close = closingBracket(src, i)
      if (close > 0 && src[close + 1] === "(") {
        const end = src.indexOf(")", close + 2)
        if (end > 0) {
          const href = (src.slice(close + 2, end).trim().split(/\s+/)[0] ?? "").replace(/^<|>$/g, "")
          flush()
          out.push(link(ctx.links.href(href), inline(src.slice(i + 1, close), ctx)))
          i = end + 1
          continue
        }
      }
    }
    text += c
    i++
  }
  flush()
  return html`${out}`
}

function headingId(text: string, ctx: Context): string {
  const base = headingSlug(text) || "section"
  const seen = ctx.ids.get(base) ?? 0
  ctx.ids.set(base, seen + 1)
  return seen === 0 ? base : `${base}-${seen}`
}

function paragraphText(lines: string[], ctx: Context): Html {
  if (!ctx.breaks) return inline(lines.join("\n"), ctx)
  return html`${lines.map((l, n) => html`${n > 0 ? html`<br>` : ""}${inline(l, ctx)}`)}`
}

const ALIGN_CLASS: Record<Exclude<Align, null>, string> = { left: "al-l", center: "al-c", right: "al-r" }

function cell(tag: "th" | "td", content: string, align: Align, ctx: Context): Html {
  const body = inline(content, ctx)
  if (align === null) return tag === "th" ? html`<th>${body}</th>` : html`<td>${body}</td>`
  const cls = ALIGN_CLASS[align]
  return tag === "th" ? html`<th class="${cls}">${body}</th>` : html`<td class="${cls}">${body}</td>`
}

function renderBlock(block: Block, ctx: Context): Html {
  switch (block.type) {
    case "heading": {
      const level = Math.min(Math.max(block.level, 1), 4)
      const id = headingId(block.text, ctx)
      ctx.headings.push({ level: block.level, id, text: plainText(block.text) })
      const content = html`${inline(block.text, ctx)}<a class="doc-anchor" href="#${id}" aria-label="Link to this section">#</a>`
      if (level === 1) return html`<h1 id="${id}">${content}</h1>`
      if (level === 2) return html`<h2 id="${id}">${content}</h2>`
      if (level === 3) return html`<h3 id="${id}">${content}</h3>`
      return html`<h4 id="${id}">${content}</h4>`
    }
    case "paragraph":
      return ctx.tight ? paragraphText(block.lines, ctx) : html`<p>${paragraphText(block.lines, ctx)}</p>`
    case "code":
      return html`<div class="doc-code"><pre><code${block.lang ? html` data-lang="${block.lang}"` : ""}>${block.text}</code></pre><button type="button" class="btn secondary sm" data-copy aria-label="Copy">${COPY_ICON}<span>Copy</span></button></div>`
    case "rule":
      return html`<hr>`
    case "quote":
      return html`<blockquote>${renderBlocks(block.blocks, { ...ctx, breaks: true, tight: false })}</blockquote>`
    case "list": {
      const items = block.items.map((item) => html`<li>${renderBlocks(item, { ...ctx, tight: !block.loose })}</li>`)
      if (!block.ordered) return html`<ul>${items}</ul>`
      return block.start === 1 ? html`<ol>${items}</ol>` : html`<ol start="${block.start}">${items}</ol>`
    }
    case "table":
      return html`<div class="doc-table"><table><thead><tr>${block.head.map((h, n) => cell("th", h, block.align[n] ?? null, ctx))}</tr></thead><tbody>${block.rows.map((row) => html`<tr>${row.map((c, n) => cell("td", c, block.align[n] ?? null, ctx))}</tr>`)}</tbody></table></div>`
  }
}

function renderBlocks(blocks: Block[], ctx: Context): Html {
  return html`${blocks.map((b, n) => html`${n > 0 && ctx.tight ? "\n" : ""}${renderBlock(b, ctx)}`)}`
}

// Front matter (a skill's name and description) is not part of the page.
function withoutFrontMatter(source: string): string {
  if (!source.startsWith("---\n")) return source
  const end = source.indexOf("\n---\n", 4)
  return end < 0 ? source : source.slice(end + 5)
}

export function renderMarkdown(source: string, links: DocLinks): RenderedMarkdown {
  const lines = withoutFrontMatter(source.replace(/\r\n?/g, "\n")).replace(/\t/g, "    ").split("\n")
  const ctx: Context = { links, breaks: false, tight: false, headings: [], ids: new Map() }
  const body = renderBlocks(parseBlocks(lines), ctx)
  const title = ctx.headings.find((h) => h.level === 1)?.text ?? null
  return { body, title, headings: ctx.headings }
}
