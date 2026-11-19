// The one page template every docs page, the 404 and the /search shell are
// built with: the header with the search box and the section links, the side
// navigation, the page, the on-this-page column and the footer. Only the
// `html` template makes markup, so a title or a heading from a source can
// never become a tag.

import { Html, html } from "../src/html.ts"
import type { DocHeading } from "../src/markdown.ts"

export type SiteSection = { id: string; title: string; index: string }

export type SiteConfig = {
  name: string
  category: string
  promise: string
  sections: SiteSection[]
  allowedHosts: string[]
  appOrigin: string
  siteOrigin: string
}

// A page as the navigation knows it.
export type NavPage = { url: string; title: string; question: string; section: string; agentOnly: boolean }

export type TemplateInput = {
  site: SiteConfig
  nav: readonly NavPage[]
  // The page shown, or null for the 404 and the search shell.
  page: NavPage | null
  // The document title and description when there is no page.
  title: string
  description: string
  body: Html
  headings: readonly DocHeading[]
  version: string
  sprite: Html
  // The search box's value: the query on /search, empty elsewhere.
  query: string
  // The home page's first block goes wide.
  home: boolean
}

// The path of a page's markdown twin: /reference/cli.md, and /index.md for
// the home page.
export function twinPath(url: string): string {
  return url === "/" ? "/index.md" : `${url}.md`
}

function sectionOf(site: SiteConfig, id: string): SiteSection | null {
  return site.sections.find((s) => s.id === id) ?? null
}

// Sections that have at least one page, in the site's order.
function liveSections(site: SiteConfig, nav: readonly NavPage[]): SiteSection[] {
  return site.sections.filter((s) => nav.some((p) => p.section === s.id))
}

function current(on: boolean): Html {
  return on ? html` aria-current="page"` : html``
}

function sectionLinks(site: SiteConfig, nav: readonly NavPage[], page: NavPage | null): Html {
  return html`${liveSections(site, nav).map((s) => {
    const href = nav.some((p) => p.url === s.index) ? s.index : (nav.find((p) => p.section === s.id) as NavPage).url
    return html`<a href="${href}"${page?.section === s.id ? html` aria-current="true"` : ""}>${s.title}</a>`
  })}`
}

// Every page under its section's eyebrow; agent-only pages last, under
// "For agents".
function sideLinks(site: SiteConfig, nav: readonly NavPage[], page: NavPage | null): Html {
  const groups = liveSections(site, nav).map((s) => ({ title: s.title, pages: nav.filter((p) => p.section === s.id && !p.agentOnly) }))
  const agents = nav.filter((p) => p.agentOnly)
  if (agents.length > 0) groups.push({ title: "For agents", pages: agents })
  return html`${groups.filter((g) => g.pages.length > 0).map((g) => html`<p class="eyebrow">${g.title}</p>${g.pages.map((p) => html`<a href="${p.url}"${current(p.url === page?.url)}>${p.title}</a>`)}`)}`
}

function onThisPage(headings: readonly DocHeading[]): Html {
  return html`${headings.filter((h) => h.level === 2).map((h) => html`<a href="#${h.id}">${h.text}</a>`)}`
}

// Previous and next follow the navigation: sections in order, agent-only
// pages last.
export function navOrder(site: SiteConfig, nav: readonly NavPage[]): NavPage[] {
  const order = site.sections.map((s) => s.id)
  const rank = (p: NavPage) => (p.agentOnly ? order.length : order.indexOf(p.section))
  return nav.map((p, n) => ({ p, n })).sort((a, b) => rank(a.p) - rank(b.p) || a.n - b.n).map(({ p }) => p)
}

function prevNext(site: SiteConfig, nav: readonly NavPage[], page: NavPage): Html {
  const order = navOrder(site, nav)
  const at = order.findIndex((p) => p.url === page.url)
  const prev = at > 0 ? order[at - 1] : undefined
  const next = at >= 0 ? order[at + 1] : undefined
  if (!prev && !next) return html``
  return html`<nav class="prev-next" aria-label="Previous and next">${prev ? html`<a rel="prev" href="${prev.url}"><small>Previous</small>${prev.title}</a>` : html`<span></span>`}${next ? html`<a rel="next" href="${next.url}"><small>Next</small>${next.title}</a>` : ""}</nav>`
}

function crumbs(site: SiteConfig, nav: readonly NavPage[], page: NavPage): Html {
  const section = sectionOf(site, page.section)
  if (page.url === "/" || !section) return html``
  const index = nav.some((p) => p.url === section.index) ? section.index : null
  if (index === page.url) return html``
  return html`<p class="crumbs">${index ? html`<a href="${index}">${section.title}</a>` : html`<span>${section.title}</span>`}<span aria-hidden="true">›</span><span>${page.title}</span></p>`
}

// Under the h1, the side the page covers ("Local only"), the question and,
// with two or more h2s, the folded contents; inserted after the renderer's h1
// so the body stays the renderer's output.
export function withQuestion(body: Html, question: string, headings: readonly DocHeading[], covers: string | null = null): Html {
  const h2s = headings.filter((h) => h.level === 2)
  const after = html`${covers ? html`<p class="covers">Covers: ${covers}</p>` : ""}<p class="question">${question}</p>${h2s.length >= 2 ? html`<details class="toc-inline"><summary>On this page</summary><nav aria-label="On this page, in the document">${onThisPage(headings)}</nav></details>` : ""}`
  const end = body.value.indexOf("</h1>")
  if (end < 0) return html`${after}${body}`
  const cut = end + "</h1>".length
  // A slice of the renderer's Html is still Html made by the template.
  return html`${new Html(body.value.slice(0, cut))}${after}${new Html(body.value.slice(cut))}`
}

const DISCLOSURE = "/security/disclosure"

export function renderPage(input: TemplateInput): string {
  const { site, nav, page } = input
  const url = page?.url ?? null
  const docTitle = page ? (page.url === "/" ? `${site.name} docs` : `${page.title} · ${site.name} docs`) : `${input.title} · ${site.name} docs`
  const description = page?.question ?? input.description
  // The home page's previews carry the promise; every other page its own title.
  const shareTitle = url === "/" ? `${site.name}: ${site.promise.charAt(0).toLowerCase()}${site.promise.slice(1).replace(/\.$/, "")}` : (page?.title ?? input.title)
  const live = liveSections(site, nav)
  const footSections = live.filter((s) => s.id === "changelog" && nav.some((p) => p.url === s.index))
  // The design's two security links, once the disclosure page exists.
  const disclosure = nav.some((p) => p.url === DISCLOSURE)
  const h2s = input.headings.filter((h) => h.level === 2)
  const out = html`<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${docTitle}</title>
<meta name="description" content="${description}">
${url !== null ? html`<link rel="canonical" href="${site.siteOrigin}${url === "/" ? "/" : url}">
<link rel="alternate" type="text/markdown" href="${twinPath(url)}">
` : html`<meta name="robots" content="noindex">
`}<meta property="og:type" content="article"><meta property="og:site_name" content="${site.name} docs"><meta property="og:title" content="${shareTitle}"><meta property="og:description" content="${description}"><meta property="og:image" content="${site.siteOrigin}/og.jpg">
<meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="${shareTitle}"><meta name="twitter:description" content="${description}"><meta name="twitter:image" content="${site.siteOrigin}/og.jpg">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#f3ead8" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0f1626" media="(prefers-color-scheme: dark)">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="preload" href="/fonts/Inter-normal-100-900.woff2" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="/fonts/JetBrainsMono-normal-100-800.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="/docs.css">
<script src="/theme.js"></script>
</head>
<body${input.home ? html` class="home"` : ""}>
<a class="skip" href="#content">Skip to content</a>
${input.sprite}
<header class="top">
<div class="wrap top-in">
<a class="lockup" href="/" aria-label="${site.name} docs home"><svg class="mark" viewBox="0 0 64 64" aria-hidden="true"><use href="#m-coil-s"/></svg><span class="wordmark">mehen</span><span class="wordmark-docs">docs</span></a>
<form class="search" action="/search" method="get" role="search">
<label class="sr-only" for="q">Search the docs</label>
<input id="q" type="search" name="q" placeholder="Search" autocomplete="off" value="${input.query}">
<ul class="search-results" hidden></ul>
</form>
<nav class="top-links" aria-label="Sections">${sectionLinks(site, nav, page)}</nav>
<div class="top-cta">
<a class="btn quiet" href="https://mehen.dev/">mehen.dev</a>
<a class="btn primary" href="${site.appOrigin}/">Sign in</a>
<button class="theme" type="button" aria-label="Switch colour scheme" data-theme-toggle hidden><span>Theme</span></button>
</div>
<details class="menu"><summary>Menu</summary><div class="menu-panel"><nav class="menu-sections" aria-label="Sections, in the menu">${sectionLinks(site, nav, page)}</nav><nav class="menu-pages" aria-label="Pages, in the menu">${sideLinks(site, nav, page)}</nav><p class="menu-cta"><a class="btn quiet" href="https://mehen.dev/">mehen.dev</a><a class="btn primary" href="${site.appOrigin}/">Sign in</a><button class="theme" type="button" aria-label="Switch colour scheme" data-theme-toggle hidden><span>Theme</span></button></p></div></details>
</div>
</header>
<div class="wrap docs">
<nav class="side" aria-label="Pages">${sideLinks(site, nav, page)}</nav>
<main id="content" class="doc">
${page ? crumbs(site, nav, page) : ""}${input.body}
<footer class="doc-foot">
${page ? prevNext(site, nav, page) : ""}<p class="small muted">${url !== null ? html`<a href="${twinPath(url)}">This page as markdown</a> · ` : ""}<a href="/llms.txt">llms.txt</a> · mehen ${input.version}${disclosure ? html` · <a href="${DISCLOSURE}">Report a security problem</a>` : ""}</p>
</footer>
</main>
${h2s.length > 0 && !input.home ? html`<nav class="toc" aria-label="On this page"><p class="eyebrow">On this page</p>${onThisPage(input.headings)}</nav>` : ""}
</div>
<footer class="foot"><div class="wrap foot-in"><span class="muted small">${site.name}</span><nav aria-label="Footer"><a href="https://mehen.dev/">mehen.dev</a><a href="${site.appOrigin}/">Sign in</a>${footSections.map((s) => html`<a href="${s.index}">${s.title}</a>`)}${disclosure ? html`<a href="${DISCLOSURE}">Security</a>` : ""}</nav></div></footer>
<script src="/docs.js" defer></script>
</body>
</html>
`
  return out.value
}
