// Static checks on the lander: every link in the pages resolves (anchors
// exist, local files exist, external links are https and on the allowed
// list, mail links are to mehen.dev), and no file in apps/web or
// packages/brand carries a dash from the em or en family.
//
//   bun scripts/check.ts

import { readdir, readFile, stat } from "node:fs/promises"
import path from "node:path"

const root = path.resolve(import.meta.dir, "..")
const publicDir = path.join(root, "public")
const brand = path.resolve(root, "../../packages/brand")
const ALLOWED_HOSTS = new Set(["mehen.dev", "app.mehen.dev", "docs.mehen.dev", "github.com"])
// The one kind of mail link the pages carry: an address at mehen.dev.
const MAIL = /^mailto:[a-z0-9.+-]+@mehen\.dev$/
const PAGES = ["index.html", "404.html"]
const DASHES = /[\u2013\u2014\u2015\u2E3A]/
const TEXT_FILES = /\.(html|css|js|ts|json|jsonc|md|txt|svg|xml)$/

const problems: string[] = []

async function walk(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true })
  const files: string[] = []
  for (const entry of entries) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === ".wrangler") continue
      files.push(...(await walk(full)))
    } else files.push(full)
  }
  return files
}

async function exists(file: string): Promise<boolean> {
  return stat(file).then(() => true, () => false)
}

for (const page of PAGES) {
  const file = path.join(publicDir, page)
  const html = await readFile(file, "utf8")
  const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]))
  for (const match of html.matchAll(/\s(?:href|src)="([^"]+)"/g)) {
    const target = match[1] as string
    if (target.startsWith("#")) {
      if (target === "#") problems.push(`${page}: placeholder link "#"`)
      else if (!ids.has(target.slice(1))) problems.push(`${page}: anchor ${target} has no element`)
      continue
    }
    if (target.startsWith("mailto:")) {
      if (!MAIL.test(target)) problems.push(`${page}: ${target} is not an address at mehen.dev`)
      continue
    }
    if (/^[a-z]+:/i.test(target)) {
      const url = new URL(target)
      if (url.protocol !== "https:") problems.push(`${page}: ${target} is not https`)
      else if (!ALLOWED_HOSTS.has(url.hostname)) problems.push(`${page}: ${url.hostname} is not an allowed host`)
      continue
    }
    const local = target === "/" ? "index.html" : target.replace(/^\//, "")
    if (!(await exists(path.join(publicDir, local)))) problems.push(`${page}: ${target} is not in public/`)
  }
}

for (const dir of [root, brand]) {
  for (const file of await walk(dir)) {
    if (!TEXT_FILES.test(file)) continue
    const text = await readFile(file, "utf8")
    const line = text.split("\n").findIndex((l) => DASHES.test(l))
    if (line >= 0) problems.push(`${path.relative(root, file)}:${line + 1}: dash from the em or en family`)
  }
}

if (problems.length) {
  for (const problem of problems) console.error(problem)
  process.exit(1)
}
console.log(`links and dashes: ok (${PAGES.join(", ")})`)
