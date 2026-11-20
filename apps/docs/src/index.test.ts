import { expect, test } from "bun:test"
import { resolve } from "node:path"
import worker, { type Env, wantsMarkdown } from "./index.ts"

const PUBLIC = resolve(import.meta.dir, "../public")

// The asset layer as wrangler.jsonc sets it up: html_handling
// auto-trailing-slash (/x serves x.html) and not_found_handling 404-page.
const env = {
  ASSETS: {
    async fetch(request: Request) {
      const path = new URL(request.url).pathname
      const candidates = path === "/" ? ["index.html"] : [`${path.slice(1)}.html`, path.slice(1)]
      for (const candidate of candidates) {
        const file = Bun.file(resolve(PUBLIC, candidate))
        if (await file.exists()) return new Response(request.method === "HEAD" ? null : file, { headers: { "Content-Type": candidate.endsWith(".html") ? "text/html; charset=utf-8" : "application/octet-stream" } })
      }
      return new Response(Bun.file(resolve(PUBLIC, "404.html")), { status: 404, headers: { "Content-Type": "text/html; charset=utf-8" } })
    },
  },
} as unknown as Env

type IncomingRequest = Parameters<NonNullable<typeof worker.fetch>>[0]
const request = (path: string, init: RequestInit = {}) => worker.fetch!(new Request(`https://docs.mehen.dev${path}`, init) as IncomingRequest, env)
const publicText = (file: string) => Bun.file(resolve(PUBLIC, file)).text()
const index = async () => JSON.parse(await publicText("index.json")) as { pages: { url: string; md: string; title: string }[] }

function expectSecurityHeaders(response: Response): void {
  expect(response.headers.get("content-security-policy")).toBe("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
  expect(response.headers.get("strict-transport-security")).toBe("max-age=31536000; includeSubDomains")
  expect(response.headers.get("x-content-type-options")).toBe("nosniff")
  expect(response.headers.get("x-frame-options")).toBe("DENY")
}

test("a page is HTML with the security headers and a five-minute cache; its twin is the built markdown", async () => {
  const page = await request("/reference/errors")
  expect(page.status).toBe(200)
  expect(page.headers.get("content-type")).toContain("text/html")
  expect(page.headers.get("cache-control")).toBe("public, max-age=300")
  expect(page.headers.get("vary")).toBe("Accept")
  expectSecurityHeaders(page)
  const twin = await request("/reference/errors.md")
  expect(twin.headers.get("content-type")).toBe("text/markdown; charset=utf-8")
  expectSecurityHeaders(twin)
  expect(await twin.text()).toBe(await publicText("reference/errors.md"))
})

test("Accept: text/markdown gets the twin, with Vary and Content-Location", async () => {
  for (const [path, twin] of [["/reference/cli", "/reference/cli.md"], ["/", "/index.md"]] as const) {
    const response = await request(path, { headers: { Accept: "text/markdown, text/html;q=0.5" } })
    expect(response.headers.get("content-type")).toBe("text/markdown; charset=utf-8")
    expect(response.headers.get("vary")).toBe("Accept")
    expect(response.headers.get("content-location")).toBe(twin)
    expect(await response.text()).toBe(await publicText(twin.slice(1)))
  }
  const md = await request("/reference/cli.md", { headers: { Accept: "text/markdown" } })
  expect(md.headers.get("content-type")).toBe("text/markdown; charset=utf-8")
  const html = await request("/reference/cli", { headers: { Accept: "text/html" } })
  expect(html.headers.get("content-type")).toContain("text/html")
  const nope = await request("/nope", { headers: { Accept: "text/markdown" } })
  expect(nope.status).toBe(404)
  expect(nope.headers.get("cache-control")).toBe("no-store")
})

test("only a positive quality asks for markdown", () => {
  expect(wantsMarkdown("text/markdown")).toBe(true)
  expect(wantsMarkdown("text/html, text/markdown;q=0.1")).toBe(true)
  expect(wantsMarkdown("text/markdown;q=0")).toBe(false)
  expect(wantsMarkdown("text/html")).toBe(false)
  expect(wantsMarkdown(null)).toBe(false)
})

test("llms.txt lists every page in index.json; llms-full.txt carries every twin", async () => {
  const llms = await request("/llms.txt")
  expect(llms.headers.get("content-type")).toBe("text/plain; charset=utf-8")
  const text = await llms.text()
  const listed = new Set([...text.matchAll(/\]\(https:\/\/docs\.mehen\.dev(\/[^)]*\.md)\)/g)].map((m) => m[1]))
  const pages = (await index()).pages
  expect(listed).toEqual(new Set(pages.map((p) => p.md)))
  const full = await (await request("/llms-full.txt")).text()
  for (const page of pages) expect(full).toContain((await publicText(page.md.slice(1))).trimEnd())
})

test("/search answers without JavaScript, best match first, never cached", async () => {
  const response = await request("/search?q=approval_required")
  expect(response.status).toBe(200)
  expect(response.headers.get("content-type")).toBe("text/html; charset=utf-8")
  expect(response.headers.get("cache-control")).toBe("no-store")
  expectSecurityHeaders(response)
  const html = await response.text()
  const first = /<ol class="results"><li><a href="([^"]+)"/.exec(html)
  expect(first?.[1]).toBe("/reference/errors#approval_required")
  expect(html).toContain('value="approval_required"')
  expect(html).toContain('<nav class="side" aria-label="Pages">')
  const placeholder = await (await request("/search?q=placeholder")).text()
  expect(/<ol class="results"><li><a href="([^"]+)"/.exec(placeholder)?.[1]).toBe("/concepts/projects#placeholders")
})

test("/search escapes the query it echoes", async () => {
  const html = await (await request(`/search?q=${encodeURIComponent('<zqxj>"x"')}`)).text()
  expect(html).not.toContain('<zqxj>"x"')
  expect(html).toContain('value="&lt;zqxj&gt;&quot;x&quot;"')
  expect(html).toContain("No results for “&lt;zqxj&gt;&quot;x&quot;”.")
})

test("/search with an empty or a very long query still answers", async () => {
  for (const q of ["", "a".repeat(200), "approval ".repeat(40)]) {
    const response = await request(`/search?q=${encodeURIComponent(q)}`)
    expect(response.status).toBe(200)
    expect(await response.text()).toContain('<h1 id="search">Search</h1>')
  }
  expect(await (await request("/search")).text()).toContain("Type a word or a code")
})

test("only GET and HEAD; the JSON files are application/json", async () => {
  for (const path of ["/", "/reference/cli", "/search", "/llms.txt"]) {
    const response = await request(path, { method: "POST" })
    expect(response.status).toBe(405)
    expect(response.headers.get("allow")).toBe("GET, HEAD")
  }
  const head = await request("/reference/cli", { method: "HEAD" })
  expect(head.status).toBe(200)
  expect(await head.text()).toBe("")
  for (const path of ["/index.json", "/reference/errors.json", "/reference/cli.json", "/search-index.json"]) {
    expect((await request(path)).headers.get("content-type")).toBe("application/json")
  }
})

test("the 404 page carries the navigation, the search box and no-store", async () => {
  const response = await request("/no/such/page")
  expect(response.status).toBe(404)
  expect(response.headers.get("cache-control")).toBe("no-store")
  expectSecurityHeaders(response)
  const html = await response.text()
  expect(html).toContain("Page not found")
  expect(html).toContain('<nav class="side" aria-label="Pages">')
  expect(html).toContain('<form class="search" action="/search" method="get" role="search">')
})

test("fonts are cached for a day", async () => {
  expect((await request("/fonts/Inter-normal-100-900.woff2")).headers.get("cache-control")).toBe("public, max-age=86400")
})

// The 0.3.0 instruction contract the lander's tests held before the guides
// moved here: the exact setup procedure and skill an agent fetches.
test("the setup page names who accepts the machine and the workspace enrolment", async () => {
  const guide = await (await request("/setup.md")).text()
  expect(guide).toContain("The human accepts their own machine with a passkey")
  // G1 N-2: ask.what already starts with "Approve" (apps/cli/src/ask.ts enrolAsk), so the relay uses it verbatim.
  expect(guide).toContain("**Needs you in the vault:** <ask.what>\n")
  expect(guide).not.toContain("approve <ask.what>")
  expect(guide).toContain("mehen enrol --workspace <slug> --json")
  expect(guide).not.toContain("mehen enrol --json")
  expect(guide).not.toContain("WS-DOCS")
  expect(guide).not.toContain("/tmp/")
  expect(guide).toContain("Unless your harness already sets `MEHEN_SESSION`")
  expect(guide).toContain("If the `vault_*` tools are missing")
  expect(guide).not.toContain("export MEHEN_SESSION")
  const skill = await (await request("/skill.md")).text()
  expect(skill).toBe(await Bun.file(resolve(import.meta.dir, "../../../skills/mehen/SKILL.md")).text())
  expect(skill).not.toContain("MEHEN_SESSION=setup-agent")
  expect(skill).toContain("If `MEHEN_SESSION` is already set in your environment, leave it")
})

test("the setup page updates an installed mehen and never reinstalls it", async () => {
  const guide = await (await request("/setup.md")).text()
  // G1 N-5: with Mehen absent the check prints nothing at all, stderr included.
  expect(guide).toContain('command -v mehen || ls "$HOME/.local/bin/mehen" 2>/dev/null\n')
  expect(guide).toContain("**Nothing is printed: Mehen is not installed.**")
  expect(guide.indexOf("mehen update --json")).toBeGreaterThan(-1)
  expect(guide.indexOf("mehen update --json")).toBeLessThan(guide.indexOf("curl "))
  expect(guide).toContain("Never run the installer on a machine that already has Mehen")
  // An already-active enrolment still registers the agent;
  // the final check is the signed one-workspace status, never a local flag;
  // switching an existing entry's identity is a human-agreed --reset-env.
  expect(guide).toContain("still do step 4 if this agent has not been registered")
  const confirm = guide.slice(guide.indexOf("### 6. Confirm and report"), guide.indexOf("## Several workspaces"))
  expect(confirm).toContain("mehen status --workspace <slug> --json")
  expect(confirm).toContain("`vault` equal to the vault you were given")
  expect(confirm).toContain("A refusal is not a successful setup")
  expect(guide).toContain("mehen setup --agent <name> --reset-env --json")
  expect(guide).not.toContain("Two homes never see each other's workspaces or keys")
  expect(guide).toContain("It returns a refusal with `next.command`; run it again.")
  expect(guide).toContain("report to the human every entry whose `status` is not `added`, `updated` or `unchanged`")
  expect(guide).toContain("mehen wait <enr_id>")
  for (const stale of ["the same command updates in place", "background with its output captured", "not the PID", "15 minutes", "MEHEN_CONFIG_DIR", "setup --workspace ", "mehen-<slug>", "workspace default", "https://mehen.dev/setup.md"]) {
    expect(guide, stale).not.toContain(stale)
  }
  const skill = await (await request("/skill.md")).text()
  expect(skill).toContain("Never reinstall over an installed `mehen`")
  expect(await (await request("/guide.md")).text()).toContain("In `agents`, inspect `mcp`, `reason`, `skill`, `skillReason` and `restart`")
  // No hand-written MCP registration offered as a fallback.
  expect(skill).not.toContain("mcp add")
  for (const stale of ["background with its output captured", "(15 minutes)", "MEHEN_CONFIG_DIR", "setup --workspace ", "mehen-<slug>", "up to 3 times", "https://mehen.dev/setup.md"]) {
    expect(skill, stale).not.toContain(stale)
  }
})

// The local path: a prompt naming no workspace runs mehen up and relays its
// asks; one naming a slug enrols; both add the guard hooks.
test("the setup page has a local branch with mehen up, and a workspace branch that enrols", async () => {
  const guide = await (await request("/setup.md")).text()
  const local = guide.slice(guide.indexOf("## A vault on this machine"), guide.indexOf("## Join a workspace"))
  expect(local).toContain("mehen up --json")
  expect(local).toContain('`ask.kind: "signup"`')
  expect(local).toContain("with the full fingerprint from `ask.check.value`")
  expect(local).toContain("mehen adopt scan")
  const join = guide.slice(guide.indexOf("## Join a workspace"), guide.indexOf("## Several workspaces"))
  expect(join).toContain("mehen enrol --workspace <slug> --json")
  expect(join).toContain("mehen guard install --json")
})

// Corrections the docs carried before they moved here.
test("the published text keeps the restart notice and the rename refusal as built", async () => {
  const keys = await (await request("/security/keys-and-signing.md")).text()
  expect(keys).toContain("Switching automatic updates off stops automatic installation, not this notice")
  expect(keys).not.toContain("only `cli.mcp` says so")
  const machines = await (await request("/concepts/machines.md")).text()
  expect(machines).toContain("`mehen workspace list --check` refuses an answer for another workspace or origin")
  expect(machines).toContain("`vault_status` keeps the recorded names when the answer names another workspace")
})

// The disclosure contact (RFC 9116), served by the Worker itself.
test("/.well-known/security.txt names the contact, the policy and this host, as plain text", async () => {
  const response = await request("/.well-known/security.txt")
  expect(response.status).toBe(200)
  expect(response.headers.get("content-type")).toBe("text/plain; charset=utf-8")
  expectSecurityHeaders(response)
  const text = await response.text()
  expect(text).toContain("Contact: mailto:security@mehen.dev\n")
  expect(text).toContain("Policy: https://docs.mehen.dev/security/disclosure\n")
  expect(text).toContain("Preferred-Languages: en\n")
  expect(text).toContain("Canonical: https://docs.mehen.dev/.well-known/security.txt\n")
  // RFC 9116 needs an Expires in the future: renew it when this fails.
  const expires = Date.parse(/^Expires: (.+)$/m.exec(text)?.[1] ?? "")
  expect(expires).toBeGreaterThan(Date.now())
  expect((await request("/.well-known/security.txt", { method: "HEAD" })).status).toBe(200)
  expect((await request("/.well-known/security.txt", { method: "POST" })).status).toBe(405)
  const policy = await request("/security/disclosure")
  expect(policy.status).toBe(200)
})

test("the disclosure page names the contact and promises no response time, bounty or safe harbour", async () => {
  const page = await (await request("/security/disclosure.md")).text()
  expect(page).toContain("[security@mehen.dev](mailto:security@mehen.dev)")
  expect(page).toContain("We cannot promise a response time. There is no bug bounty, and we offer no legal safe harbour.")
  const html = await (await request("/security/disclosure")).text()
  expect(html).toContain('<a href="mailto:security@mehen.dev">security@mehen.dev</a>')
  const home = await (await request("/")).text()
  expect(home).toContain('<a href="/security/disclosure">Report a security problem</a>')
  expect(home).toContain('<a href="/security/disclosure">Security</a>')
  expect(await (await request("/llms.txt")).text()).toContain("[Reporting a vulnerability](https://docs.mehen.dev/security/disclosure.md)")
})
