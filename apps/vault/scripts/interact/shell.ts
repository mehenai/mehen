// The shell's interaction scenarios: the
// phone's More sheet, the workspace switcher, the command palette and the
// folds, by keyboard and by pointer. scripts/ui-interact.ts runs them at
// 360 and 390 px.
//
// The pages are the shell and people galleries' own fixtures. Their origin
// is not the local server's, so they run without a workspace tab state;
// the More sheet, the switcher, the palette and the folds need none.

import type { InboxResponse } from "@mehen/protocol/inbox"
import { type PageInput, renderDocument } from "../../src/ui/layout.ts"
import { needsYouPage } from "../../src/ui/pages/needs-you.ts"
import { inboxItemKey } from "../../src/ui/client/pages/needs-you-logic.ts"
import { peopleGallery } from "../../src/ui/people-gallery.ts"
import { GALLERY_ACCOUNT_SHELL, GALLERY_NOW, INBOX_THREE, shellGallery } from "../../src/ui/shell-gallery.ts"
import type { InteractPage, InteractScenario } from "../ui-interact.ts"

function galleryPage(entries: () => readonly { id: string; page: PageInput }[], id: string): () => PageInput {
  return () => {
    const found = entries().find((e) => e.id === id)
    if (found === undefined) throw new Error(`interact: no gallery entry ${id}`)
    return found.page
  }
}

function check(ok: boolean, message: string): void {
  if (!ok) throw new Error(message)
}

const SHEET = 'details[data-region="more-sheet"]'

async function sheetOpen(page: InteractPage): Promise<boolean> {
  return page.evaluate<boolean>(`document.querySelector('${SHEET}').open`)
}

// What has focus, as a short label: a link's or button's text, else its tag.
async function active(page: InteractPage): Promise<string> {
  return page.evaluate<string>(`(() => { const a = document.activeElement; return a ? (a.textContent ?? "").trim() || a.tagName : "" })()`)
}

async function noSidewaysScroll(page: InteractPage): Promise<void> {
  const widths = await page.evaluate<{ scroll: number; inner: number }>(`({ scroll: document.scrollingElement.scrollWidth, inner: innerWidth })`)
  check(widths.scroll <= widths.inner + 0.5, `the page scrolls sideways (${widths.scroll} of ${widths.inner})`)
}

// Every link and button in the open sheet is inside the viewport.
async function linksInView(page: InteractPage): Promise<string[]> {
  const boxes = await page.evaluate<{ label: string; left: number; right: number; top: number; bottom: number }[]>(`Array.from(document.querySelectorAll('${SHEET} .more-list a, ${SHEET} .more-list button')).map((el) => { const r = el.getBoundingClientRect(); return { label: el.textContent.trim(), left: r.left, right: r.right, top: r.top, bottom: r.bottom } })`)
  const size = await page.evaluate<{ w: number; h: number }>("({ w: innerWidth, h: innerHeight })")
  check(boxes.length > 0, "the More sheet lists nothing")
  for (const b of boxes) check(b.left >= 0 && b.right <= size.w + 0.5 && b.top >= 0 && b.bottom <= size.h + 0.5, `${b.label} is outside the viewport`)
  return boxes.map((b) => b.label)
}

async function focusBefore(page: InteractPage, selector: string): Promise<void> {
  await page.evaluate(`(() => { document.activeElement?.blur?.(); document.querySelector(${JSON.stringify(selector)}).focus(); return true })()`)
}

const HOME = galleryPage(shellGallery, "workspace-home")

const moreByPointer: InteractScenario = {
  name: "More sheet by pointer",
  page: HOME,
  run: async (page) => {
    check(!(await sheetOpen(page)), "the More sheet starts open")
    await page.click(`${SHEET} > summary`)
    check(await sheetOpen(page), "a tap on More did not open its sheet")
    const labels = await linksInView(page)
    for (const want of ["Machines", "People", "Teams", "Activity", "Connect an agent", "Settings", "All workspaces", "Your account", "Docs", "Sign out"]) check(labels.includes(want), `the More sheet has no ${want}`)
    await noSidewaysScroll(page)
    // A tap outside, on the page's heading.
    const head = await page.evaluate<{ x: number; y: number }>(`(() => { window.scrollTo(0, 0); const r = document.querySelector("h1").getBoundingClientRect(); return { x: r.left + 4, y: r.top + r.height / 2 } })()`)
    await page.clickAt(head.x, head.y)
    check(!(await sheetOpen(page)), "a tap outside did not close the More sheet")
  },
}

const moreByKeyboard: InteractScenario = {
  name: "More sheet by keyboard",
  page: HOME,
  run: async (page) => {
    // Tab from the tab before it to the More tab, then Enter.
    await focusBefore(page, '.tabs > a[href$="/projects"]')
    await page.press("Tab")
    check((await active(page)) === "More", `Tab reached ${await active(page)}, not the More tab`)
    await page.press("Enter")
    check(await sheetOpen(page), "Enter on the More tab did not open its sheet")
    const labels = await linksInView(page)
    // Tab visits every link in order.
    for (const label of labels) {
      await page.press("Tab")
      check((await active(page)) === label, `Tab reached ${await active(page)}, not ${label}`)
    }
    // Past the last one the sheet closes and focus moves on.
    await page.press("Tab")
    await page.evaluate("new Promise((resolve) => setTimeout(() => resolve(true), 50))")
    check(!(await sheetOpen(page)), `Tab past the last link left the More sheet open, focus on ${await active(page)}`)
    // Escape from inside closes it and puts focus back on the tab.
    await focusBefore(page, '.tabs > a[href$="/projects"]')
    await page.press("Tab")
    await page.press("Enter")
    await page.press("Tab")
    await page.press("Escape")
    check(!(await sheetOpen(page)), "Escape did not close the More sheet")
    check((await active(page)) === "More", `Escape left focus on ${await active(page)}, not the More tab`)
    await noSidewaysScroll(page)
  },
}

const switcherByKeyboard: InteractScenario = {
  name: "Workspace switcher by keyboard",
  page: galleryPage(shellGallery, "workspace-home"),
  run: async (page) => {
    await focusBefore(page, ".top > .brand")
    await page.press("Tab")
    const summary = await page.evaluate<boolean>(`document.activeElement === document.querySelector(".top .switcher > summary")`)
    check(summary, "Tab from the brand did not reach the switcher")
    await page.press("Enter")
    check(await page.evaluate<boolean>(`document.querySelector(".top .switcher").open`), "Enter did not open the switcher")
    const rows = await page.evaluate<{ name: string; slug: string }[]>(`Array.from(document.querySelectorAll(".top .switcher-list .switcher-row")).map((r) => ({ name: r.querySelector(".switcher-name").textContent, slug: r.querySelector(".switcher-slug").textContent }))`)
    for (const slug of ["northwind", "alex", "northwind-labs", "acme-rebuild", "old-side-project", "hostile-name", "montgomery-fitzwilliam-office-consultant"]) check(rows.some((r) => r.slug === slug && r.name !== ""), `the switcher does not list ${slug} by name and slug`)
    const menu = await page.evaluate<{ left: number; right: number; w: number }>(`(() => { const r = document.querySelector(".top .switcher-menu").getBoundingClientRect(); return { left: r.left, right: r.right, w: innerWidth } })()`)
    check(menu.left >= 0 && menu.right <= menu.w + 0.5, "the switcher's menu runs outside the viewport")
    // Where the top bar carries the pages there is no More sheet and no
    // rail foot: the menu holds this workspace's other pages.
    if (page.width >= 900) {
      const brand = await page.evaluate<{ brand: number; bar: number }>(`({ brand: document.querySelector(".top > .brand").getBoundingClientRect().height, bar: document.querySelector(".top").getBoundingClientRect().height })`)
      check(brand.brand <= brand.bar, `the top bar's brand wraps (${brand.brand} px in a ${brand.bar} px bar)`)
      const links = await page.evaluate<string[]>(`Array.from(document.querySelectorAll(".top .switcher-menu .switcher-page")).filter((a) => a.getBoundingClientRect().width > 0).map((a) => a.textContent)`)
      check(links.includes("Connect an agent") && links.includes("Settings"), `the switcher's menu does not offer Connect an agent and Settings (${links.join(", ")})`)
    }
  },
  widths: [360, 390, 900],
}

const paletteByKeyboard: InteractScenario = {
  name: "Command palette by keyboard",
  page: HOME,
  run: async (page) => {
    await page.evaluate("(() => { document.activeElement?.blur?.(); return true })()")
    await page.press("k", { ctrl: true })
    check(await page.evaluate<boolean>(`!document.querySelector('[data-region="palette"]').hidden`), "the shortcut did not open the palette")
    check(await page.evaluate<boolean>(`document.querySelector("#palette-list").getAttribute("role") === "listbox"`), "the palette's list is not a listbox")
    // The lists load (here: refused) and the fixed actions remain.
    await page.evaluate(`new Promise((resolve) => { const wait = () => document.querySelectorAll('#palette-list [role="option"]').length > 1 ? resolve(true) : setTimeout(wait, 50); wait() })`)
    const state = async () => page.evaluate<{ active: string | null; selected: string | null }>(`({ active: document.querySelector('[role="combobox"]').getAttribute("aria-activedescendant"), selected: document.querySelector('#palette-list [aria-selected="true"]')?.id ?? null })`)
    const first = await state()
    check(first.active !== null && first.active === first.selected, "aria-activedescendant does not name the selected option")
    await page.press("ArrowDown")
    const second = await state()
    check(second.active !== first.active && second.active === second.selected, "ArrowDown did not move aria-activedescendant to the next option")
    await page.press("ArrowUp")
    check((await state()).active === first.active, "ArrowUp did not move back")
    await page.press("Escape")
    check(await page.evaluate<boolean>(`document.querySelector('[data-region="palette"]').hidden`), "Escape did not close the palette")
  },
}

const PEOPLE = galleryPage(peopleGallery, "people-owner")

const foldsAndRoleSelect: InteractScenario = {
  name: "Folds and the role select",
  page: PEOPLE,
  run: async (page) => {
    // The first person's Manage fold that holds a role select.
    const marked = await page.evaluate<boolean>(`(() => { const d = Array.from(document.querySelectorAll('details[data-region="manage"]')).find((d) => d.querySelector('select[data-input="member-role"]')); if (!d) return false; d.dataset.interact = "fold"; return true })()`)
    check(marked, "the people page has no Manage fold with a role select")
    const fold = '[data-interact="fold"] > summary'
    const isOpen = () => page.evaluate<boolean>(`document.querySelector(${JSON.stringify(fold)}).parentElement.open`)
    await page.evaluate(`(() => { document.querySelector(${JSON.stringify(fold)}).focus(); return true })()`)
    await page.press("Enter")
    check(await isOpen(), "Enter did not open the fold")
    await page.press("Enter")
    check(!(await isOpen()), "Enter did not close the fold")
    await page.press(" ")
    check(await isOpen(), "Space did not open the fold")
    // In the open fold: Enter on the role select changes and sends nothing.
    await page.evaluate(`(() => { window.__calls = []; const f = window.fetch.bind(window); window.fetch = (i, o) => { window.__calls.push(String(i)); return f(i, o) }; return true })()`)
    const before = await page.evaluate<string>("location.href")
    const select = await page.evaluate<boolean>(`(() => { const s = document.querySelector(${JSON.stringify(fold)}).parentElement.querySelector('select[data-input="member-role"]'); if (!s) return false; s.focus(); return true })()`)
    check(select, "the open fold has no role select")
    await page.press("Enter")
    const after = await page.evaluate<{ href: string; value: string; calls: string[] }>(`({ href: location.href, value: document.activeElement.value, calls: window.__calls })`)
    check(after.href === before, "Enter on the role select navigated")
    check(after.value === "", `Enter on the role select chose ${after.value}`)
    check(after.calls.length === 0, `Enter on the role select sent ${after.calls.join(", ")}`)
  },
}


// ---------------------------------------------------------------- the Needs you refresh

// The inbox page with every network call answered from queues the scenario
// fills: GET /api/needs-you from __api, the page's own redraw read from
// __html. Every call is logged with its If-None-Match and whether the tab
// was visible when it started. visibilityState is the scenario's to set.
const SHIM = `(() => {
  window.__api = []; window.__html = []; window.__log = []; window.__vis = "visible";
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => window.__vis });
  window.fetch = async (input, init) => {
    const url = new URL(String(input), location.href);
    const headers = new Headers(init && init.headers);
    window.__log.push({ path: url.pathname, inm: headers.get("if-none-match"), vis: window.__vis });
    const queue = url.pathname === "/api/needs-you" ? window.__api : window.__html;
    const next = queue.shift();
    if (next === undefined) return new Response("{}", { status: 503 });
    if (next.hold) await new Promise((resolve) => { window.__release = resolve; });
    return new Response(next.status === 304 ? null : next.body, { status: next.status, headers: { "content-type": next.type, ...(next.etag ? { etag: next.etag } : {}) } });
  };
  return true;
})()`

type Queued = { status: number; body?: string; etag?: string; type?: string; hold?: boolean }

function apiAnswer(inbox: InboxResponse, etag: string, hold = false): Queued {
  return { status: 200, body: JSON.stringify(inbox), etag, type: "application/json", hold }
}

function pageAnswer(inbox: InboxResponse, etag: string): Queued {
  return { status: 200, body: renderDocument(needsYouPage(GALLERY_ACCOUNT_SHELL, { ok: true, inbox, etag }, GALLERY_NOW)).value, type: "text/html; charset=utf-8" }
}

async function queue(page: InteractPage, api: readonly Queued[], htmlAnswers: readonly Queued[] = []): Promise<void> {
  await page.evaluate(`(() => { window.__api.push(...${JSON.stringify(api)}); window.__html.push(...${JSON.stringify(htmlAnswers)}); return true })()`)
}

// Asks now, as a returning tab does, and waits for the refresh to settle.
async function refresh(page: InteractPage): Promise<void> {
  await page.evaluate(`(() => { window.dispatchEvent(new Event("focus")); return new Promise((resolve) => setTimeout(() => resolve(true), 250)) })()`)
}

async function rows(page: InteractPage, workspace: string): Promise<number> {
  return page.evaluate<number>(`document.querySelectorAll('[data-region="needs-list"] li.inbox-row[data-workspace="${workspace}"]').length`)
}

async function apiCalls(page: InteractPage): Promise<{ path: string; inm: string | null; vis: string }[]> {
  return page.evaluate("window.__log")
}

const WORK_ID = INBOX_THREE.workspaces[1]?.workspace.id ?? ""
const NEEDS = galleryPage(shellGallery, "needs-you-three")

// Northwind gated: its rows gone from the answer, the rest kept.
function gated(): InboxResponse {
  const workspaces = INBOX_THREE.workspaces.map((w) => (w.workspace.id === WORK_ID ? { ...w, state: "gated" as const, count: null } : w))
  const items = INBOX_THREE.items.filter((i) => i.workspace.id !== WORK_ID)
  return { workspaces, items, notices: [], count: items.length, complete: false }
}

const refreshWithdraws: InteractScenario = {
  name: "Needs you refresh drops gated rows at once, and a 304 never vouches for an undrawn list",
  page: NEEDS,
  run: async (page) => {
    await page.evaluate(SHIM)
    check((await rows(page, WORK_ID)) > 0, "the fixture has no Northwind rows")
    const others = await page.evaluate<number>(`document.querySelectorAll('[data-region="needs-list"] li.inbox-row').length`) - (await rows(page, WORK_ID))
    // The workspace is gated now and the redraw read fails.
    await queue(page, [apiAnswer(gated(), 'W/"gated"')], [{ status: 500, body: "", type: "text/html" }])
    await refresh(page)
    check((await rows(page, WORK_ID)) === 0, "a gated workspace's rows stayed on screen")
    check((await rows(page, WORK_ID)) === 0 && (await page.evaluate<number>(`document.querySelectorAll('[data-region="needs-list"] li.inbox-row').length`)) === others, "rows of the workspaces that still answer were removed")
    check(!(await page.evaluate<boolean>(`document.querySelector('[data-region="needs-retrying"]').hidden`)), "a failed redraw did not say it is retrying")
    check((await page.evaluate<string>("document.title")).startsWith("(3+) Needs you"), `the title says ${await page.evaluate<string>("document.title")}`)
    // The next poll still asks about the list on screen, so it gets the change again.
    await queue(page, [apiAnswer(gated(), 'W/"gated"')], [pageAnswer(gated(), 'W/"gated"')])
    await refresh(page)
    const calls = (await apiCalls(page)).filter((c) => c.path === "/api/needs-you")
    check(calls[1]?.inm !== 'W/"gated"', "the poll revalidated a list it never drew")
    check(await page.evaluate<boolean>(`document.querySelector('[data-region="needs-retrying"]').hidden`), "the retry line stayed after the redraw")
    check(await page.evaluate<boolean>(`document.body.textContent.includes("Verify your identity to see what needs you in Northwind")`), "the redrawn list does not say Northwind is gated")
    // Now drawn: a 304 keeps it, and names it.
    await queue(page, [{ status: 304, etag: 'W/"gated"', type: "application/json" }])
    await refresh(page)
    const last = (await apiCalls(page)).filter((c) => c.path === "/api/needs-you").at(-1)
    check(last?.inm === 'W/"gated"', `the poll after the redraw sent ${last?.inm ?? "nothing"}`)
    check((await rows(page, WORK_ID)) === 0, "a 304 brought rows back")
  },
}

// The answer without one request.
function without(key: string): InboxResponse {
  const items = INBOX_THREE.items.filter((i) => inboxItemKey(i) !== key)
  return { ...INBOX_THREE, items, count: items.length }
}

async function focusedRow(page: InteractPage): Promise<{ key: string | null; tag: string; inList: boolean }> {
  return page.evaluate(`(() => { const a = document.activeElement; const list = document.querySelector('[data-region="needs-list"]'); return { key: a?.closest("li.inbox-row")?.dataset.key ?? null, tag: a?.tagName ?? "", inList: list.contains(a) } })()`)
}

const refreshKeepsFocus: InteractScenario = {
  name: "Needs you refresh keeps keyboard focus",
  page: NEEDS,
  run: async (page) => {
    await page.evaluate(SHIM)
    // Focus on Personal's credential request; another workspace's request goes.
    await page.evaluate(`(() => { document.querySelector('li[data-key="int_4hz8rq2nk1"] a.btn').focus(); return true })()`)
    await queue(page, [apiAnswer(without("apr_6t3vb9nx2w"), 'W/"one"')], [pageAnswer(without("apr_6t3vb9nx2w"), 'W/"one"')])
    await refresh(page)
    const kept = await focusedRow(page)
    check(kept.key === "int_4hz8rq2nk1" && kept.tag === "A", `focus moved to ${kept.key ?? kept.tag} when another request changed`)
    check(await page.evaluate<boolean>(`document.querySelector('[data-region="needs-announce"]').textContent === "6 waiting"`), "the count change was not announced once, politely")
    // The focused request itself goes: focus lands on its workspace's next one, never the body.
    await page.evaluate(`(() => { document.querySelector('li[data-key="enr_4h8s2kd9pq"] a.btn').focus(); return true })()`)
    const gone = { ...without("apr_6t3vb9nx2w"), items: without("apr_6t3vb9nx2w").items.filter((i) => inboxItemKey(i) !== "enr_4h8s2kd9pq") }
    await queue(page, [apiAnswer({ ...gone, count: gone.items.length }, 'W/"two"')], [pageAnswer({ ...gone, count: gone.items.length }, 'W/"two"')])
    await refresh(page)
    const fallback = await focusedRow(page)
    check(fallback.inList && fallback.key !== null && fallback.key !== "enr_4h8s2kd9pq", `focus fell to ${fallback.tag} when its request went`)
    // Focus outside the list stays where it is.
    await page.evaluate(`(() => { document.querySelector('.account-nav a').focus(); return true })()`)
    await queue(page, [apiAnswer(INBOX_THREE, 'W/"three"')], [pageAnswer(INBOX_THREE, 'W/"three"')])
    await refresh(page)
    check(await page.evaluate<boolean>(`document.activeElement === document.querySelector('.account-nav a')`), "a refresh took focus from the account bar")
  },
}

const refreshWhileHidden: InteractScenario = {
  name: "Needs you refresh starts no page read while the tab is hidden",
  page: NEEDS,
  run: async (page) => {
    await page.evaluate(SHIM)
    await queue(page, [apiAnswer(without("apr_6t3vb9nx2w"), 'W/"one"', true)], [pageAnswer(without("apr_6t3vb9nx2w"), 'W/"one"')])
    await page.evaluate(`(() => { window.dispatchEvent(new Event("focus")); return true })()`)
    await page.evaluate("new Promise((resolve) => setTimeout(() => resolve(true), 50))")
    // Hidden while the inbox read is out; then it answers with a change.
    await page.evaluate(`(() => { window.__vis = "hidden"; document.dispatchEvent(new Event("visibilitychange")); window.__release(); return new Promise((resolve) => setTimeout(() => resolve(true), 250)) })()`)
    check(!(await apiCalls(page)).some((c) => c.path !== "/api/needs-you"), "a page read started while the tab was hidden")
    check(!(await page.evaluate<boolean>(`!!document.querySelector('li[data-key="apr_6t3vb9nx2w"]')`)), "the withdrawn request stayed while hidden")
    // Visible again: the change is asked for again with the old validator and drawn.
    await queue(page, [apiAnswer(without("apr_6t3vb9nx2w"), 'W/"one"')])
    await page.evaluate(`(() => { window.__vis = "visible"; document.dispatchEvent(new Event("visibilitychange")); return new Promise((resolve) => setTimeout(() => resolve(true), 250)) })()`)
    const log = await apiCalls(page)
    const read = log.find((c) => c.path !== "/api/needs-you")
    check(read !== undefined && read.vis === "visible", "the redraw did not run once visible")
    check(log.filter((c) => c.path === "/api/needs-you").every((c) => c.inm !== 'W/"one"'), "a validator was adopted before its list was drawn")
  },
}

export const SHELL_SCENARIOS: readonly InteractScenario[] = [moreByPointer, moreByKeyboard, switcherByKeyboard, paletteByKeyboard, foldsAndRoleSelect, refreshWithdraws, refreshKeepsFocus, refreshWhileHidden]
