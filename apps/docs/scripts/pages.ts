// The docs sources: every `.md` under docs/site/ is one page, its URL its
// path without `.md` (`index.md` is `/`), its front matter `key: value`
// lines saying what it is.

import { readdir, readFile } from "node:fs/promises"
import path from "node:path"

export type GenerateKind = "cli" | "errors" | "mcp" | "providers" | "platform"

// Which way of running Mehen a page is about: a vault on your own machine,
// Mehen Cloud, or both.
export type Covers = "both" | "local" | "cloud"

export const COVERS_LABEL: Record<Covers, string> = { both: "Local and Cloud", local: "Local only", cloud: "Cloud only" }

export type PageMeta = {
  title: string
  question: string
  section: string
  order: number
  generate: GenerateKind | null
  // Every page says which side it covers, except one serving another file's
  // exact bytes, which has nowhere to say it.
  covers: Covers | null
  agentOnly: boolean
  // A repository path whose exact bytes are served as the page's markdown.
  bytes: string | null
  // A repository path appended to the page's own markdown, its headings one
  // level down (the changelog's CLI release notes).
  include: string | null
}

export type SourcePage = {
  // From the repository root: docs/site/reference/cli.md.
  file: string
  url: string
  meta: PageMeta
  // The source without its front matter.
  body: string
}

const GENERATE_KINDS: readonly GenerateKind[] = ["cli", "errors", "mcp", "providers", "platform"]
const COVERS: readonly Covers[] = ["both", "local", "cloud"]
const KEYS = new Set(["title", "question", "section", "order", "generate", "covers", "agentOnly", "bytes", "include"])

// The front matter of a source, as `key: value` pairs, and the rest.
export function frontMatter(source: string, file: string): { fields: Map<string, string>; body: string } {
  const text = source.replace(/\r\n?/g, "\n")
  if (!text.startsWith("---\n")) return { fields: new Map(), body: text }
  const end = text.indexOf("\n---\n", 4)
  if (end < 0) throw new Error(`${file}:1: front matter is not closed`)
  const fields = new Map<string, string>()
  text
    .slice(4, end)
    .split("\n")
    .forEach((line, n) => {
      if (line.trim() === "") return
      const m = /^([A-Za-z]+):\s*(.*?)\s*$/.exec(line)
      if (!m) throw new Error(`${file}:${n + 2}: front matter lines are key: value`)
      fields.set(m[1] as string, m[2] as string)
    })
  return { fields, body: text.slice(end + 5).replace(/^\n+/, "") }
}

export function pageMeta(fields: Map<string, string>, file: string): PageMeta {
  for (const key of fields.keys()) if (!KEYS.has(key)) throw new Error(`${file}: unknown front matter key ${key}`)
  const need = (key: string): string => {
    const value = fields.get(key)
    if (!value) throw new Error(`${file}: front matter needs ${key}`)
    return value
  }
  const generate = fields.get("generate") ?? null
  if (generate !== null && !GENERATE_KINDS.includes(generate as GenerateKind)) throw new Error(`${file}: generate is one of ${GENERATE_KINDS.join(", ")}`)
  const covers = fields.get("covers") ?? null
  const bytes = fields.get("bytes") ?? null
  if (covers !== null && !COVERS.includes(covers as Covers)) throw new Error(`${file}: covers is one of ${COVERS.join(", ")}`)
  if (covers === null && bytes === null) throw new Error(`${file}: front matter needs covers (${COVERS.join(", ")})`)
  if (covers !== null && bytes !== null) throw new Error(`${file}: a page that serves another file's bytes cannot say covers`)
  const order = Number(fields.get("order") ?? "0")
  if (!Number.isInteger(order)) throw new Error(`${file}: order is a whole number`)
  return {
    title: need("title"),
    question: need("question"),
    section: need("section"),
    order,
    generate: generate as GenerateKind | null,
    covers: covers as Covers | null,
    agentOnly: fields.get("agentOnly") === "true",
    bytes,
    include: fields.get("include") ?? null,
  }
}

export function urlOf(relative: string): string {
  const bare = relative.replace(/\.md$/, "")
  return bare === "index" ? "/" : `/${bare}`
}

async function walk(dir: string): Promise<string[]> {
  const out: string[] = []
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) out.push(...(await walk(full)))
    else if (entry.name.endsWith(".md")) out.push(full)
  }
  return out.sort()
}

// Every page under `sourceDir`, `file` given from `repoRoot`.
export async function loadPages(sourceDir: string, repoRoot: string): Promise<SourcePage[]> {
  const pages: SourcePage[] = []
  for (const full of await walk(sourceDir)) {
    const file = path.relative(repoRoot, full)
    const { fields, body } = frontMatter(await readFile(full, "utf8"), file)
    pages.push({ file, url: urlOf(path.relative(sourceDir, full)), meta: pageMeta(fields, file), body })
  }
  return pages
}
