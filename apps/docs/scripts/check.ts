// The docs lint, over what the site serves: every page's markdown twin,
// llms.txt and the HTML pages. It fails with `path:line: reason` when a page
// names a command, a flag, an error code, an MCP tool or a MEHEN_ variable
// that does not exist; links to a page, an anchor or a host that is not
// there or not allowed; says anything that is internal to how Mehen is built
// and run; carries a dash from the em or en family; or breaks the site's
// shape (one title, every page reachable from its section and in llms.txt).
//
//   bun scripts/check.ts        (after bun run build)

import { readdir, readFile, stat } from "node:fs/promises"
import path from "node:path"
import type { SiteIndex } from "./build.ts"
import type { CliReference, ErrorEntry, McpReference } from "./reference.ts"
import type { SiteConfig } from "./template.ts"

export type Problem = { line: number; reason: string }

export type LintContext = {
  origin: string
  // Command name to its long flags (without --) and short letters.
  commands: Map<string, { flags: Set<string>; shorts: Set<string> }>
  globalFlags: Set<string>
  errorCodes: Set<string>
  tools: Set<string>
  envVars: Set<string>
  hosts: Set<string>
  // Page URL to its heading ids.
  pages: Map<string, Set<string>>
  // Served files that are not pages: /llms.txt, /reference/cli.json.
  files: Set<string>
}

const DOCS_ROOT = path.resolve(import.meta.dir, "..")
const REPO_ROOT = path.resolve(DOCS_ROOT, "../..")
const PUBLIC = path.join(DOCS_ROOT, "public")

// Words `mehen` may be followed by that are not commands.
const MEHEN_WORDS = new Set(["help", "--help", "-h", "--version", "--json", "--no-qr", "--workspace"])
const GLOBAL_SHORTS = new Set(["h"])

// Global flags the commands with their own parsers refuse (apps/cli/src/cli.ts
// and the run module): `--json` on run, mcp and env set; `--no-qr` on run,
// env, init and mcp. `--workspace` is accepted by every command.
function refusedGlobals(command: string, subcommand: string | undefined): Set<string> {
  if (command === "run" || command === "mcp") return new Set(["json", "no-qr"])
  if (command === "init") return new Set(["no-qr"])
  if (command === "env") return new Set(subcommand === "set" ? ["json", "no-qr"] : ["no-qr"])
  return new Set()
}

// Pages where the retired MEHEN_CONFIG_DIR may be named.
const CONFIG_DIR_PAGES = new Set(["/changelog", "/reference/errors"])

const CODE_SUFFIXES = ["_refused", "_required", "_denied", "_pending", "_revoked", "_invalid", "_missing", "_mismatch", "_unknown", "_unbound", "_ambiguous", "_outdated", "_retired", "_failed", "_inactive", "_unshared", "_enrolled", "_retrying", "_limited", "_insecure", "_scope", "_allowed", "_status"]
const CODE_WORDS = new Set(["bad_request", "not_found", "too_large"])

// What a public page never says: how the platform is built and deployed
// and the programme it was built in.
const INTERNAL: [RegExp, string][] = [
  // A repository path, not the same word inside a URL's path.
  [/(?<![\w/.-])apps\//, "apps/"],
  [/(?<![\w/.-])packages\//, "packages/"],
  [/(?<![\w/.-])src\//, "src/"],
  [/\b[\w-]+\.ts\b/, "a .ts file name"],
  [/wrangler/, "wrangler"],
  [/Durable Object/, "Durable Object"],
  [/D1 database/, "D1 database"],
  [/R2 bucket/, "R2 bucket"],
  [/\/Users\/(?!sam\/)/, "a /Users/ path other than /Users/sam/"],
  [/ROOT_KEYS/, "ROOT_KEYS"],
  [/SEAL_PRIVATE_JWK/, "SEAL_PRIVATE_JWK"],
  [/BOOTSTRAP_CODE/, "BOOTSTRAP_CODE"],
  [/account_id/, "account_id"],
  [/OPERATIONS\.md/, "OPERATIONS.md"],
  [/phase 2/, "phase 2"],
  [/phase 3/, "phase 3"],
  [/TODO/, "TODO"],
  [/WS-/, "WS-"],
  [/\blane\b/, "lane"],
]

const DASHES = /[\u2013\u2014\u2015\u2E3A]/

// ---------------------------------------------------------------- markdown

// `block` is a line of a fenced block; a code span has `code` alone.
type Segment = { text: string; line: number; code: boolean; block: boolean }

const FENCE = /^ {0,3}(`{3,}|~{3,})/

// The text of a page, split into code (fenced lines and code spans) and
// prose, each piece with its line number.
export function segments(markdown: string): Segment[] {
  const out: Segment[] = []
  let fence: string | null = null
  markdown.split("\n").forEach((line, n) => {
    const marker = FENCE.exec(line)?.[1]
    if (marker !== undefined) {
      if (fence === null) fence = marker
      else if (marker[0] === fence[0] && marker.length >= fence.length && line.trim() === marker) fence = null
      return
    }
    if (fence !== null) {
      out.push({ text: line, line: n + 1, code: true, block: true })
      return
    }
    for (const part of line.split(/(`+[^`]*`+)/)) {
      if (part === "") continue
      const span = /^(`+)([^`]*)\1$/.exec(part)
      if (span) out.push({ text: (span[2] as string).trim(), line: n + 1, code: true, block: false })
      else out.push({ text: part, line: n + 1, code: false, block: false })
    }
  })
  return out
}

// Shell words, with quoted strings kept as one word.
function words(text: string): string[] {
  return [...text.matchAll(/'[^']*'|"(?:[^"\\]|\\.)*"|[^\s]+/g)].map((m) => m[0])
}

const SEPARATORS = new Set(["|", "||", "&&", ";", ">", ">>", "2>", "2>&1", "&", "#"])

function cleanWord(word: string): string {
  return word.replace(/^[[(`]+/, "").replace(/[\]),.:;`]+$/, "")
}

// `mehen` where a shell would run it: at the start, after a pipe, `&&`, `;`,
// `(`, a backtick or a `$ ` prompt, after a label such as `then:` in an ask
// block, or after `NAME=value` assignments. Prose that quotes a message
// ("so mehen did not show it") is not a command.
const COMMAND_POSITION = /(?:^\s*|[|;&(`]\s*|\$\s+|\b[a-z]+:\s+)(?:[A-Z_][A-Z0-9_]*=\S+\s+)*mehen(?=\s)/g

// Every `mehen <command> [--flag]...` in a piece of code.
function lintCommands(segment: Segment, ctx: LintContext, problems: Problem[]): void {
  for (const m of segment.text.matchAll(COMMAND_POSITION)) {
    const rest = segment.text.slice((m.index as number) + m[0].length)
    const tokens = words(rest)
    let i = 0
    // Global flags may come before the command.
    const leading: string[] = []
    while (i < tokens.length) {
      const t = cleanWord(tokens[i] as string)
      if (t === "--json" || t === "--no-qr") leading.push(t.slice(2))
      if (t === "--json" || t === "--no-qr" || t.startsWith("--workspace=")) i++
      else if (t === "--workspace") i += 2
      else break
    }
    const first = tokens[i]
    if (first === undefined) continue
    const word = cleanWord(first)
    if (word === "" || word.startsWith("<") || /^\d/.test(word) || /^[^\w-]/.test(word)) continue
    if (MEHEN_WORDS.has(word)) continue
    const command = ctx.commands.get(word)
    if (!command) {
      problems.push({ line: segment.line, reason: `mehen ${word} is not a command` })
      continue
    }
    const subcommand = tokens[i + 1] === undefined ? undefined : cleanWord(tokens[i + 1] as string)
    const refused = refusedGlobals(word, subcommand)
    const named = word === "env" && subcommand === "set" ? "env set" : word
    for (const flag of leading) if (refused.has(flag)) problems.push({ line: segment.line, reason: `mehen ${named} does not take --${flag}` })
    for (const raw of tokens.slice(i + 1)) {
      if (SEPARATORS.has(raw) || raw.startsWith("#") || raw.startsWith("(") || raw === "--") break
      const token = cleanWord(raw)
      if (token.startsWith("<") || token.startsWith("'") || token.startsWith('"')) continue
      const long = /^--([a-z][a-z0-9-]*)(=.*)?$/.exec(token)
      if (long) {
        const name = long[1] as string
        if (refused.has(name)) problems.push({ line: segment.line, reason: `mehen ${named} does not take --${name}` })
        else if (!command.flags.has(name) && !ctx.globalFlags.has(name)) problems.push({ line: segment.line, reason: `mehen ${word} has no flag --${name}` })
        continue
      }
      const short = /^-([A-Za-z])$/.exec(token)
      if (short && !command.shorts.has(short[1] as string) && !GLOBAL_SHORTS.has(short[1] as string)) problems.push({ line: segment.line, reason: `mehen ${word} has no flag -${short[1]}` })
    }
  }
}

function isCodeLike(token: string): boolean {
  return CODE_WORDS.has(token) || CODE_SUFFIXES.some((s) => token.endsWith(s))
}

function lintCodes(markdown: string, ctx: LintContext, problems: Problem[]): void {
  // Tables whose header names `error` or Exit: every snake_case code span is a code.
  let inErrorTable = false
  const lines = markdown.split("\n")
  lines.forEach((line, n) => {
    if (!line.trimStart().startsWith("|")) {
      inErrorTable = false
      return
    }
    const next = lines[n + 1] ?? ""
    if (/^\s*\|?\s*:?-+/.test(next) && !/^\s*\|?\s*:?-+/.test(line)) inErrorTable = /`error`|\bExit\b/.test(line)
    if (!inErrorTable) return
    for (const span of line.matchAll(/`([a-z]+(?:_[a-z]+)+)`/g)) {
      const token = span[1] as string
      if (token.startsWith("vault_")) continue
      if (!ctx.errorCodes.has(token)) problems.push({ line: n + 1, reason: `${token} is not an error code` })
    }
  })
  for (const segment of segments(markdown)) {
    if (!segment.code || !/^[a-z]+(?:_[a-z]+)+$/.test(segment.text) || segment.text.startsWith("vault_")) continue
    if (isCodeLike(segment.text) && !ctx.errorCodes.has(segment.text)) problems.push({ line: segment.line, reason: `${segment.text} is not an error code` })
  }
}

function lintTools(markdown: string, ctx: LintContext, problems: Problem[]): void {
  for (const segment of segments(markdown)) {
    if (!segment.code || segment.block) continue
    for (const m of segment.text.matchAll(/\bvault_[a-z_]+/g)) if (!ctx.tools.has(m[0])) problems.push({ line: segment.line, reason: `${m[0]} is not an MCP tool` })
  }
}

function lintEnv(markdown: string, url: string, ctx: LintContext, problems: Problem[]): void {
  markdown.split("\n").forEach((line, n) => {
    for (const m of line.matchAll(/MEHEN_[A-Z_]*[A-Z]/g)) {
      const name = m[0]
      if (name === "MEHEN_CONFIG_DIR" && !CONFIG_DIR_PAGES.has(url)) problems.push({ line: n + 1, reason: "MEHEN_CONFIG_DIR is retired; name it only on /changelog and /reference/errors" })
      else if (!ctx.envVars.has(name)) problems.push({ line: n + 1, reason: `${name} is not a variable mehen reads` })
    }
  })
}

// One href, from a page at `url` whose own ids are `ids`.
export function checkHref(href: string, url: string, ids: ReadonlySet<string>, ctx: LintContext): string | null {
  if (href.startsWith("#")) return ids.has(decodeURIComponent(href.slice(1))) ? null : `${href} is not a heading on this page`
  let target: URL
  try {
    target = new URL(href, `${ctx.origin}${url}`)
  } catch {
    return `${href} is not a link`
  }
  // The one mail link the site carries: an address at mehen.dev.
  if (target.protocol === "mailto:") return /^[a-z0-9.+-]+@mehen\.dev$/.test(target.pathname) ? null : `${href} is not an address at mehen.dev`
  if (target.protocol !== "https:") return `${href} is not https`
  if (target.origin !== ctx.origin) {
    if (!ctx.hosts.has(target.hostname)) return `${target.hostname} is not an allowed host`
    if (target.hostname === "app.mehen.dev" && /^\/docs(\/|$)/.test(target.pathname)) return `${href}: the docs are on ${ctx.origin}, not app.mehen.dev/docs`
    return null
  }
  const pathname = target.pathname
  const page = pathname.endsWith(".md") ? (pathname === "/index.md" ? "/" : pathname.slice(0, -3)) : pathname
  const headings = ctx.pages.get(page)
  if (headings === undefined) {
    if (target.hash === "" && ctx.files.has(pathname)) return null
    return `${href} is not a page or a file the site serves`
  }
  if (target.hash !== "" && !headings.has(decodeURIComponent(target.hash.slice(1)))) return `${href}: ${page} has no heading ${target.hash}`
  return null
}

function lintLinks(markdown: string, url: string, ctx: LintContext, problems: Problem[]): void {
  const ids = ctx.pages.get(url) ?? new Set<string>()
  let fence: string | null = null
  markdown.split("\n").forEach((line, n) => {
    const marker = FENCE.exec(line)?.[1]
    if (marker !== undefined) {
      if (fence === null) fence = marker
      else if (marker[0] === fence[0] && marker.length >= fence.length && line.trim() === marker) fence = null
      return
    }
    if (fence !== null) return
    for (const part of line.split(/(`+[^`]*`+)/)) {
      if (part.startsWith("`")) continue
      for (const m of part.matchAll(/\]\(\s*<?([^()\s<>]+)>?(?:\s+"[^"]*")?\s*\)/g)) {
        const problem = checkHref(m[1] as string, url, ids, ctx)
        if (problem) problems.push({ line: n + 1, reason: problem })
      }
    }
  })
}

function lintWords(text: string, problems: Problem[]): void {
  text.split("\n").forEach((line, n) => {
    for (const [pattern, word] of INTERNAL) if (pattern.test(line)) problems.push({ line: n + 1, reason: `says ${word}, which is internal` })
    if (DASHES.test(line)) problems.push({ line: n + 1, reason: "a dash from the em or en family" })
  })
}

// Every check that reads one page's markdown on its own.
export function lintMarkdown(markdown: string, url: string, ctx: LintContext): Problem[] {
  const problems: Problem[] = []
  for (const segment of segments(markdown)) if (segment.code) lintCommands(segment, ctx, problems)
  lintCodes(markdown, ctx, problems)
  lintTools(markdown, ctx, problems)
  lintEnv(markdown, url, ctx, problems)
  lintLinks(markdown, url, ctx, problems)
  lintWords(markdown, problems)
  return problems.sort((a, b) => a.line - b.line)
}

// Every href in a built HTML page.
export function lintHtml(htmlText: string, url: string, ctx: LintContext): Problem[] {
  const problems: Problem[] = []
  const ids = new Set([...htmlText.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1] as string))
  htmlText.split("\n").forEach((line, n) => {
    for (const m of line.matchAll(/\shref="([^"]+)"/g)) {
      const href = (m[1] as string).replace(/&amp;/g, "&")
      if (href === "/favicon.svg" || href === "/apple-touch-icon.png" || href === "/docs.css" || href.startsWith("/fonts/")) continue
      const problem = checkHref(href, url, ids, ctx)
      if (problem) problems.push({ line: n + 1, reason: problem })
    }
    if (DASHES.test(line)) problems.push({ line: n + 1, reason: "a dash from the em or en family" })
  })
  return problems
}

// ---------------------------------------------------------------- the site

async function walk(dir: string, filter: (file: string) => boolean): Promise<string[]> {
  const out: string[] = []
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) out.push(...(await walk(full, filter)))
    else if (filter(full)) out.push(full)
  }
  return out.sort()
}

// Every MEHEN_ name the CLI's sources use, outside tests, and the local
// vault's, which the CLI carries for `mehen serve`.
async function cliVariables(repoRoot: string): Promise<Set<string>> {
  const names = new Set<string>()
  for (const dir of ["apps/cli/src", "apps/local/src"]) {
    for (const file of await walk(path.join(repoRoot, dir), (f) => f.endsWith(".ts") && !f.endsWith(".test.ts"))) {
      for (const m of (await readFile(file, "utf8")).matchAll(/MEHEN_[A-Z_]*[A-Z]/g)) names.add(m[0])
    }
  }
  return names
}

export async function lintContext(publicDir: string, repoRoot: string): Promise<{ ctx: LintContext; index: SiteIndex; site: SiteConfig }> {
  const json = async <T>(file: string) => JSON.parse(await readFile(path.join(publicDir, file), "utf8")) as T
  const index = await json<SiteIndex>("index.json")
  const site = JSON.parse(await readFile(path.join(repoRoot, "docs/site/site.json"), "utf8")) as SiteConfig
  const cli = await json<CliReference>("reference/cli.json")
  const errors = await json<ErrorEntry[]>("reference/errors.json")
  const mcp = await json<McpReference>("reference/mcp.json")
  const providers = await json<{ templates: { docsUrl: string | null }[]; oauthProviders: { docsUrl: string | null }[] }>("reference/providers.json")
  const hosts = new Set(site.allowedHosts)
  for (const entry of [...providers.templates, ...providers.oauthProviders]) if (entry.docsUrl) hosts.add(new URL(entry.docsUrl).hostname)
  const files = new Set<string>()
  for (const file of await walk(publicDir, (f) => !f.endsWith(".html"))) files.add(`/${path.relative(publicDir, file)}`)
  files.add("/search")
  return {
    index,
    site,
    ctx: {
      origin: site.siteOrigin,
      commands: new Map(cli.commands.map((c) => [c.name, { flags: new Set(c.flags.map((f) => f.name)), shorts: new Set(c.flags.flatMap((f) => (f.short ? [f.short] : []))) }])),
      globalFlags: new Set(cli.globalFlags.map((f) => f.replace(/^--/, ""))),
      errorCodes: new Set(errors.map((e) => e.code)),
      tools: new Set(mcp.tools.map((t) => t.name)),
      envVars: await cliVariables(repoRoot),
      hosts,
      pages: new Map(index.pages.map((p) => [p.url, new Set(p.headings.map((h) => h.id))])),
      files,
    },
  }
}

const exists = (file: string) => stat(file).then(() => true, () => false)

// The checks across pages: titles, reachability, llms.txt, twins and the
// errors page's coverage.
export async function lintSite(publicDir: string, index: SiteIndex, site: SiteConfig, ctx: LintContext): Promise<string[]> {
  const out: string[] = []
  const twins = new Map<string, string>()
  for (const page of index.pages) {
    const twinFile = path.join(publicDir, page.md.slice(1))
    if (!(await exists(twinFile))) {
      out.push(`${page.md}: the markdown twin of ${page.url} is missing`)
      continue
    }
    twins.set(page.url, await readFile(twinFile, "utf8"))
    // An agent-only page serves another file's exact bytes, under its own title.
    const h1s = page.headings.filter((h) => h.level === 1)
    if (!page.agentOnly && (h1s.length !== 1 || h1s[0]?.text !== page.title)) out.push(`${page.md}: needs exactly one # heading, and it must be the title "${page.title}"`)
    if (!page.title || !page.question || !page.section) out.push(`${page.md}: needs a title, a question and a section`)
  }
  const linked = (from: string, to: string) => {
    const twin = twins.get(from) ?? ""
    const md = to === "/" ? "/index.md" : `${to}.md`
    return twin.includes(`](${ctx.origin}${md})`) || twin.includes(`](${ctx.origin}${md}#`)
  }
  for (const page of index.pages) {
    const section = site.sections.find((s) => s.id === page.section)
    if (page.url === "/" || section === undefined || section.index === page.url) continue
    if (!index.pages.some((p) => p.url === section.index)) out.push(`${page.md}: its section ${section.id} has no index page at ${section.index}`)
    else if (!linked(section.index, page.url)) out.push(`${page.md}: the section index ${section.index} does not link to it`)
  }
  const llms = await readFile(path.join(publicDir, "llms.txt"), "utf8")
  const agentsAt = llms.indexOf("\n## For agents\n")
  for (const page of index.pages) {
    const at = llms.indexOf(`](${ctx.origin}${page.md})`)
    if (at < 0) out.push(`llms.txt: does not list ${page.md}`)
    else if (page.agentOnly && (agentsAt < 0 || at < agentsAt)) out.push(`llms.txt: ${page.md} is agent-only and belongs under For agents`)
  }
  const errorsTwin = twins.get("/reference/errors")
  if (errorsTwin !== undefined) for (const code of ctx.errorCodes) if (!errorsTwin.includes(`### \`${code}\``)) out.push(`/reference/errors.md: ${code} has no section`)
  return out
}

export async function checkSite(publicDir: string, repoRoot: string): Promise<string[]> {
  const { ctx, index, site } = await lintContext(publicDir, repoRoot)
  const out: string[] = []
  const report = (file: string, problems: Problem[]) => {
    for (const p of problems) out.push(`${file}:${p.line}: ${p.reason}`)
  }
  for (const page of index.pages) {
    const twinFile = path.join(publicDir, page.md.slice(1))
    if (await exists(twinFile)) report(`public${page.md}`, lintMarkdown(await readFile(twinFile, "utf8"), page.url, ctx))
    const htmlFile = page.url === "/" ? "index.html" : `${page.url.slice(1)}.html`
    report(`public/${htmlFile}`, lintHtml(await readFile(path.join(publicDir, htmlFile), "utf8"), page.url, ctx))
  }
  for (const extra of ["404.html", "search.html"]) report(`public/${extra}`, lintHtml(await readFile(path.join(publicDir, extra), "utf8"), "/", ctx))
  report("public/llms.txt", lintMarkdown(await readFile(path.join(publicDir, "llms.txt"), "utf8"), "/llms.txt", ctx))
  out.push(...(await lintSite(publicDir, index, site, ctx)))
  return out
}

if (import.meta.main) {
  const problems = await checkSite(PUBLIC, REPO_ROOT)
  if (problems.length) {
    for (const problem of problems) console.error(problem)
    console.error(`docs check: ${problems.length} problem${problems.length === 1 ? "" : "s"}`)
    process.exit(1)
  }
  console.log("docs check: ok")
}
