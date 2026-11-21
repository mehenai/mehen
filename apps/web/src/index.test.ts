import { expect, test } from "bun:test"
import { resolve } from "node:path"
import worker, { type Env, prefersMarkdown } from "./index.ts"

const keys: string[] = []
const heads: string[] = []
const env = {
  ASSETS: { async fetch(request: Request) {
    const path = new URL(request.url).pathname
    const file = Bun.file(resolve(import.meta.dir, "../public", path === "/setup/" ? "setup/index.html" : path === "/" ? "index.html" : path.slice(1)))
    if (await file.exists()) return new Response(file, { headers: { "Content-Type": path.endsWith("/") ? "text/html" : "text/plain" } })
    // html_handling serves /name from name.html with 200, as the asset layer does.
    const page = Bun.file(resolve(import.meta.dir, "../public", `${path.slice(1)}.html`))
    return await page.exists() ? new Response(page, { headers: { "Content-Type": "text/html" } }) : new Response("Not found", { status: 404 })
  } },
  RELEASES: { async head(key: string) {
    heads.push(key)
    if (key.includes("9.9.9")) return null
    return { size: 19, httpEtag: '"fixture"' }
  }, async get(key: string) {
    keys.push(key)
    if (key.includes("9.9.9")) return null
    const text = key.endsWith(".json") ? '{"version":"1.2.3"}' : "gzip fixture"
    return { body: new Response(text).body, size: text.length, httpEtag: '"fixture"' }
  } },
} as unknown as Env
const request = (path: string, method = "GET", headers: Record<string, string> = {}) => worker.fetch!(new Request(`https://mehen.dev${path}`, { method, headers }), env)
const PROMPT = "Follow https://docs.mehen.dev/setup.md to connect this machine to Mehen workspace <your-slug> at https://app.mehen.dev. I will approve it in my browser; never ask me for a key, password or secret."

test("the installer is served as plain text from its exact source bytes, never cached", async () => {
  const response = await request("/install")
  expect(response.status).toBe(200)
  expect(response.headers.get("content-type")).toBe("text/plain; charset=utf-8")
  expect(response.headers.get("cache-control")).toBe("no-cache")
  expect(await response.text()).toBe(await Bun.file(resolve(import.meta.dir, "../../..", "tools/release/install.sh")).text())
})
test("the old guide addresses redirect to the docs site with a plain-text body naming the target", async () => {
  for (const [path, target] of [
    ["/setup.md", "https://docs.mehen.dev/setup.md"],
    ["/skill.md", "https://docs.mehen.dev/skill.md"],
    ["/SKILL.md", "https://docs.mehen.dev/skill.md"],
    ["/llms.txt", "https://docs.mehen.dev/llms.txt"],
    ["/setup", "https://docs.mehen.dev/setup"],
    ["/setup/", "https://docs.mehen.dev/setup"],
    ["/docs", "https://docs.mehen.dev/"],
    ["/docs/x", "https://docs.mehen.dev/"],
    ["/docs/agent-guide", "https://docs.mehen.dev/"],
  ] as const) {
    const response = await request(path)
    expect(response.status, path).toBe(301)
    expect(response.headers.get("location"), path).toBe(target)
    expect(response.headers.get("content-type"), path).toBe("text/plain; charset=utf-8")
    expect(response.headers.get("cache-control"), path).toBe("public, max-age=300")
    expect(response.headers.get("x-content-type-options"), path).toBe("nosniff")
    expect(await response.text(), path).toBe(`Moved: ${target}\n`)
    const head = await request(path, "HEAD")
    expect(head.status, path).toBe(301)
    expect(await head.text(), path).toBe("")
  }
  // Only the exact old addresses move: a path that merely starts like one is the lander's 404.
  for (const path of ["/setup.mdx", "/docsx", "/skill"]) expect((await request(path)).status, path).toBe(404)
})
test("the lander gives the workspace prompt, its links go to the docs site, and no build writes the old guides", async () => {
  const response = await request("/")
  expect(response.headers.get("content-type")).toContain("text/html")
  const text = await response.text()
  expect(text).toContain("Follow https://docs.mehen.dev/setup.md to connect this machine to Mehen workspace &lt;your-slug&gt; at https://app.mehen.dev.")
  expect(text).toContain('data-copy="Follow https://docs.mehen.dev/setup.md')
  expect(text).toContain("/style.css")
  expect(text).not.toContain("https://mehen.dev/setup.md")
  expect(text).not.toContain("app.mehen.dev/docs")
  expect(text).toContain('href="https://docs.mehen.dev/"')
  for (const file of ["setup.md", "skill.md", "llms.txt", "setup/index.html"]) expect(await Bun.file(resolve(import.meta.dir, "../public", file)).exists(), file).toBe(false)
})

// An agent pointed at mehen.dev finds the setup guide and
// llms.txt, can ask for markdown, and meets the prompt before the installer.
test("the lander names setup.md and llms.txt as markdown alternates", async () => {
  const text = await (await request("/")).text()
  const head = text.slice(0, text.indexOf("</head>"))
  expect(head).toContain('<link rel="alternate" type="text/markdown" href="https://docs.mehen.dev/setup.md"')
  expect(head).toContain('<link rel="alternate" type="text/markdown" href="https://docs.mehen.dev/llms.txt"')
})
// The hero leads with the one-line local install, and gives the agent its
// prompt naming setup.md beside it; agents asking for markdown meet the
// prompt first (below).
test("the hero gives the one-line local install and the agent prompt that names setup.md", async () => {
  const text = await (await request("/")).text()
  const hero = text.slice(text.indexOf('<section class="hero"'), text.indexOf("</section>"))
  const install = hero.indexOf('data-copy="curl -fsSL https://mehen.dev/install | sh &amp;&amp; mehen up"')
  const prompt = hero.indexOf('data-copy="Follow https://docs.mehen.dev/setup.md to set up Mehen on this machine.')
  expect(install).toBeGreaterThan(0)
  expect(prompt).toBeGreaterThan(install)
  expect(hero).toContain('href="https://github.com/mehenai/mehen"')
})
test("/ answers Accept: text/markdown with the short page for agents, and HTML otherwise", async () => {
  const markdown = await request("/", "GET", { Accept: "text/markdown, text/html;q=0.9, */*;q=0.8" })
  expect(markdown.status).toBe(200)
  expect(markdown.headers.get("content-type")).toBe("text/markdown; charset=utf-8")
  expect(markdown.headers.get("vary")).toBe("Accept")
  expect(markdown.headers.get("x-content-type-options")).toBe("nosniff")
  const body = await markdown.text()
  expect(body.startsWith("# Mehen: use credentials without reading them\n")).toBe(true)
  for (const line of [PROMPT, "https://docs.mehen.dev/setup.md", "https://docs.mehen.dev/llms.txt", "curl -fsSL https://mehen.dev/install | sh"]) expect(body).toContain(line)
  expect(body.indexOf(PROMPT)).toBeLessThan(body.indexOf("curl -fsSL"))
  const browser = await request("/", "GET", { Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" })
  expect(browser.headers.get("content-type")).toContain("text/html")
  expect(browser.headers.get("vary")).toBe("Accept")
  expect(await browser.text()).toContain("<!doctype html>")
  expect((await request("/index.md")).headers.get("content-type")).toBe("text/markdown; charset=utf-8")
})
test("markdown wins only when Accept rates it at least as high as HTML", () => {
  for (const accept of ["text/markdown", "text/markdown, text/html, */*", "text/html;q=0.5, text/markdown", "TEXT/MARKDOWN; charset=utf-8", "*/*;q=0.1, text/markdown;q=0.2"]) expect(prefersMarkdown(accept), accept).toBe(true)
  for (const accept of [null, "", "*/*", "text/html", "text/html, text/markdown;q=0.9", "text/markdown;q=0", "text/*, text/markdown;q=0.5", "text/plain"]) expect(prefersMarkdown(accept), String(accept)).toBe(false)
})

// G1 N-3: a merge brought the retired guides back into the tree; the docs site owns them.
test("the retired agent guides are not tracked under public/", () => {
  const listed = Bun.spawnSync(["git", "ls-files", "--", "public/setup.md", "public/skill.md", "public/llms.txt", "public/setup"], { cwd: resolve(import.meta.dir, "..") })
  expect(listed.exitCode).toBe(0)
  expect(listed.stdout.toString()).toBe("")
})
test("R2 routes stream only allowed release keys with length and caching", async () => {
  for (const path of ["/dl/latest.json", "/dl/v1.2.3/manifest.json", "/dl/v1.2.3/mehen-darwin-arm64.gz", "/dl/v1.2.3/mehen-linux-x64.gz", "/dl/v1.2.3/mehen-linux-x64-musl.gz", "/dl/v1.2.3/mehen-linux-arm64-musl.gz", "/dl/v1.2.3/mehen-se.gz"]) {
    const response = await request(path)
    expect(response.status).toBe(200)
    expect(response.headers.get("content-type")).toBe(path.endsWith("json") ? "application/json" : "application/gzip")
    expect(response.headers.get("cache-control")).toBe(path.includes("latest") ? "public, max-age=60" : "public, max-age=31536000, immutable")
    expect(Number(response.headers.get("content-length"))).toBe((await response.text()).length)
  }
  const before = keys.length
  const head = await request("/dl/latest.json", "HEAD")
  expect(await head.text()).toBe("")
  expect(heads).toContain("latest.json")
  expect(keys.length).toBe(before)
})
test("404s never list or fetch arbitrary R2 objects; mutation is refused", async () => {
  for (const path of ["/dl/", "/dl/v1.2.3/", "/dl/secret.txt", "/dl/v1.2.3/other.gz", "/dl/v1.2.3/mehen-windows-x64.gz", "/dl/v1.2.3/mehen-darwin-arm64-musl.gz", "/dl/v1.2.3/mehen-linux-x64-glibc.gz", "/dl/v1.2.3/manifest.json/extra", "/dl/v9.9.9/manifest.json", "/unknown", "/dl/../secret.txt", "/dl/%2e%2e/secret.txt", "/dl/v1.2.3%2Fmanifest.json", "/dl/%252e%252e/secret", "/DL/latest.json"]) expect((await request(path)).status).toBe(404)
  expect(keys).not.toContain("secret.txt")
  for (const path of ["/install", "/setup", "/skill.md", "/setup.md", "/llms.txt", "/dl/latest.json"]) expect((await request(path, "POST")).status).toBe(405)
})
test("/404 is the not-found page with status 404, not 200", async () => {
  const notFound = await Bun.file(resolve(import.meta.dir, "../public/404.html")).text()
  for (const path of ["/404", "/404.html"]) {
    const response = await request(path)
    expect(response.status, path).toBe(404)
    expect(await response.text(), path).toBe(notFound)
  }
  expect((await request("/")).status).toBe(200)
})
test("www redirects before touching assets", async () => {
  const response = await worker.fetch!(new Request("https://www.mehen.dev/setup.md?q=1"), env)
  expect(response.status).toBe(301)
  expect(response.headers.get("location")).toBe("https://mehen.dev/setup.md?q=1")
})

test("download 404s carry security headers and never cache", async () => {
  for (const path of ["/dl/secret.txt", "/dl/v9.9.9/manifest.json"]) for (const method of ["GET", "HEAD"]) {
    const response = await request(path, method)
    expect(response.status).toBe(404)
    expect(response.headers.get("cache-control")).toBe("no-store")
    expect(response.headers.get("x-content-type-options")).toBe("nosniff")
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'")
  }
})
test("the lander says who accepts the machine", async () => {
  const text = await (await request("/")).text()
  expect(text).toContain("You accept your own machine with your passkey.")
  expect(text).toContain("a team's machine is admitted by a workspace owner or admin")
  expect(text).not.toContain("You, or a workspace owner, approve the machine")
})

test("URL-normalised traversal to the lander never asks R2 for an object", async () => {
  for (const path of ["/dl/..", "/dl/%2e%2e"]) {
    const before = keys.length
    expect((await request(path)).status).toBe(200)
    expect(keys.length).toBe(before)
  }
})

// The first explanation of relay states the scrubbing limits; later
// tiles say scrubbing has limits and link to them.
test("the lander qualifies every scrubbing claim", async () => {
  const text = await (await request("/")).text()
  expect(text).toContain("The vault scrubs credential echoes in raw, URL-encoded, JSON-escaped and supported base64 forms. It cannot catch arbitrary transformations, and values shorter than six characters are not redacted.")
  expect(text.match(/scrubs supported credential echoes; <a href="https:\/\/docs\.mehen\.dev\/security#limits-stated-plainly">scrubbing has limits<\/a>/g)?.length).toBe(2)
  expect(text).not.toContain("with echoes of the key scrubbed")
})

// Generic examples never name the owner's own account.
test("no lander file names gmail-alex", async () => {
  for (const file of ["index.html", "404.html", "app.js"]) expect(await Bun.file(resolve(import.meta.dir, "../public", file)).text(), file).not.toContain("gmail-alex")
})

// No fixed setup time; the connect code is conditional.
test("the lander promises no setup time and only a connect code when available", async () => {
  const text = await (await request("/")).text()
  expect(text.toLowerCase()).not.toContain("three minutes")
  expect(text).toContain("fills in the slug and, when available, a connect code")
})

// Alex's decision of 29 October: the category line and the promise.
test("the lander carries the category line and the promise, not the old slogan", async () => {
  const text = await (await request("/")).text()
  expect(text).toContain("<title>Mehen: use credentials without reading them</title>")
  expect(text).toContain('<meta property="og:title" content="Mehen: use credentials without reading them">')
  expect(text).toContain('<meta name="twitter:title" content="Mehen: use credentials without reading them">')
  expect(text).toContain('<p class="sub">Access for agents.')
  for (const file of ["index.html", "404.html", "app.js"]) {
    const body = await Bun.file(resolve(import.meta.dir, "../public", file)).text()
    for (const old of ["never secrets", "credential vault and proxy"]) expect(body, `${file}: ${old}`).not.toContain(old)
  }
})

// The social card is rendered from scripts/og-card.html by
// scripts/og-card.ts; the words live in that source.
test("the social card source carries the qualified headline, and og.jpg is a 1200 by 630 JPEG", async () => {
  const card = await Bun.file(resolve(import.meta.dir, "../scripts/og-card.html")).text()
  expect(card).toContain("<h1>Use credentials without reading them.</h1>")
  expect(card).toContain("Relay and placeholder modes keep values off the agent's machine. Explicitly allowed leases deliver values to the child process.")
  expect(card).not.toContain("never leaves")
  const jpeg = new Uint8Array(await Bun.file(resolve(import.meta.dir, "../public/og.jpg")).arrayBuffer())
  expect([jpeg[0], jpeg[1]]).toEqual([0xff, 0xd8])
  // The first start-of-frame segment holds the height and width.
  let at = 2
  while (at < jpeg.length && !(jpeg[at] === 0xff && (jpeg[at + 1] === 0xc0 || jpeg[at + 1] === 0xc2))) at += 2 + ((jpeg[at + 2] as number) << 8 | (jpeg[at + 3] as number))
  const height = (jpeg[at + 5] as number) << 8 | (jpeg[at + 6] as number)
  const width = (jpeg[at + 7] as number) << 8 | (jpeg[at + 8] as number)
  expect([width, height]).toEqual([1200, 630])
})

// The disclosure contact (RFC 9116), served by the Worker itself.
test("/.well-known/security.txt names the contact, the policy and this host, as plain text", async () => {
  const response = await request("/.well-known/security.txt")
  expect(response.status).toBe(200)
  expect(response.headers.get("content-type")).toBe("text/plain; charset=utf-8")
  expect(response.headers.get("strict-transport-security")).toBe("max-age=31536000; includeSubDomains")
  const text = await response.text()
  expect(text).toContain("Contact: mailto:security@mehen.dev\n")
  expect(text).toContain("Policy: https://docs.mehen.dev/security/disclosure\n")
  expect(text).toContain("Preferred-Languages: en\n")
  expect(text).toContain("Canonical: https://mehen.dev/.well-known/security.txt\n")
  // RFC 9116 needs an Expires in the future: renew it when this fails.
  expect(Date.parse(/^Expires: (.+)$/m.exec(text)?.[1] ?? "")).toBeGreaterThan(Date.now())
  expect(await (await request("/.well-known/security.txt", "HEAD")).text()).toBe("")
  expect((await request("/.well-known/security.txt", "POST")).status).toBe(405)
  for (const file of ["index.html", "404.html"]) expect(await Bun.file(resolve(import.meta.dir, "../public", file)).text(), file).toContain('<a href="https://docs.mehen.dev/security/disclosure">Security</a>')
})

// A grid track of plain `fr` is at least its content's min-content width, and
// the install line does not wrap, so on a phone the hero column grew past the
// screen (411 px at 390) and clipped the text and the Copy button. The hero
// grid sizes its tracks from zero.
test("the hero grid's tracks start at zero, so the install line cannot widen the page on a phone", async () => {
  const css = await Bun.file(resolve(import.meta.dir, "../public/style.css")).text()
  const heroRules = [...css.matchAll(/\.hero-in \{[^}]*grid-template-columns: ([^;]+);/g)].map((m) => m[1] as string)
  expect(heroRules.length).toBeGreaterThan(0)
  for (const columns of heroRules) for (const track of columns.split(/\s+(?![^(]*\))/)) expect(track, columns).toMatch(/^minmax\(0, /)
})
