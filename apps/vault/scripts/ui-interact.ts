// The interaction gate: what screenshots cannot prove, such
// as the phone's More sheet and the decision bar, driven in headless Chrome
// by keyboard and pointer at 360 and 390 px in portrait. Each scenario names
// a page built from the gallery's fixtures (src/ui/*-gallery.ts) and the
// steps and checks to run on it; the shell's scenarios are in
// interact/shell.ts, the decision bar's in interact/bar.ts and the
// consoles' in interact/console.ts.
//
//   cd apps/vault && bun run build:ui
//   bun scripts/ui-interact.ts [--chrome <path>]
//
// The pages load with the client bundle, from a local server that serves
// the built assets and answers every other address, /api/* included, with
// a 404 in JSON, so the shell's poller sees nothing to report and no page
// waits on the network. A scenario fails when a check throws, when it runs
// longer than SCENARIO_TIMEOUT_MS, or when the page itself throws. One line
// is printed per scenario and width; the run exits 1 on any failure, and 2
// when there are scenarios but no Chrome or no built bundle: never a skip.
// With no scenarios it says so and exits 0.

import { readFile } from "node:fs/promises"
import { type Server, createServer } from "node:http"
import type { AddressInfo } from "node:net"
import path from "node:path"
// First, before any page: vault/areas/devices.ts and workspace-devices.ts
// import each other, and only loading devices.ts first works. The Worker
// and the gallery reach it first by their own imports; a scenario file
// that builds a machine or enrolment page would reach workspace-devices.ts
// first.
import "../src/vault/areas/devices.ts"
import { type PageInput, renderDocument } from "../src/ui/layout.ts"
import { CHROME_CANDIDATES, type Cdp, findChrome, launchChrome } from "./chrome.ts"
import { BAR_SCENARIOS } from "./interact/bar.ts"
import { CONSOLE_SCENARIOS } from "./interact/console.ts"
import { SHELL_SCENARIOS } from "./interact/shell.ts"

export type InteractWidth = 360 | 390 | 900

// The widths a scenario may run at, with a window's height for each: two
// phones, and the narrowest window whose top bar carries the pages, the
// tightest that bar gets.
export const INTERACT_VIEWPORTS: Readonly<Record<InteractWidth, number>> = { 360: 780, 390: 844, 900: 768 }

// The widths every scenario runs at unless it names its own.
export const PHONE_WIDTHS: readonly InteractWidth[] = [360, 390]

export type KeyModifiers = { alt?: boolean; ctrl?: boolean; meta?: boolean; shift?: boolean }

// What a scenario may do to the page it runs on.
export type InteractPage = {
  width: InteractWidth
  // Runs an expression in the page, awaiting a promise, and returns its
  // value as JSON. Throws when the expression throws.
  evaluate: <T>(expression: string) => Promise<T>
  // Presses and releases one key on whatever has focus: "Tab", "Enter",
  // "Escape", " ", an arrow ("ArrowDown"), or one printable character.
  press: (key: string, modifiers?: KeyModifiers) => Promise<void>
  // A pointer click at the centre of the first element the selector
  // matches that has a box, scrolled into view first. Throws when none has.
  click: (selector: string) => Promise<void>
  // A pointer click at a point in CSS pixels from the viewport's top left.
  clickAt: (x: number, y: number) => Promise<void>
}

export type InteractScenario = {
  name: string
  // The page, rendered as the Worker renders it.
  page: () => PageInput
  // Throws on the first check that fails.
  run: (page: InteractPage) => Promise<void>
  // The widths it runs at; the phones' when left out.
  widths?: readonly InteractWidth[]
}

export const SCENARIO_TIMEOUT_MS = 20_000

// Keys Chrome needs a code and a virtual key code for, so they do what the
// key does (move focus, activate, close).
const NAMED_KEYS: Readonly<Record<string, { code: string; keyCode: number; text?: string }>> = {
  Tab: { code: "Tab", keyCode: 9 },
  Enter: { code: "Enter", keyCode: 13, text: "\r" },
  Escape: { code: "Escape", keyCode: 27 },
  " ": { code: "Space", keyCode: 32, text: " " },
  ArrowLeft: { code: "ArrowLeft", keyCode: 37 },
  ArrowUp: { code: "ArrowUp", keyCode: 38 },
  ArrowRight: { code: "ArrowRight", keyCode: 39 },
  ArrowDown: { code: "ArrowDown", keyCode: 40 },
  Home: { code: "Home", keyCode: 36 },
  End: { code: "End", keyCode: 35 },
}

function keyEvent(key: string): { key: string; code: string; windowsVirtualKeyCode: number; text?: string } {
  const named = NAMED_KEYS[key]
  if (named !== undefined) return { key, code: named.code, windowsVirtualKeyCode: named.keyCode, ...(named.text !== undefined ? { text: named.text } : {}) }
  if ([...key].length !== 1) throw new Error(`interact: no key named ${JSON.stringify(key)}`)
  const upper = key.toUpperCase()
  const letter = /^[A-Z]$/.test(upper)
  const digit = /^[0-9]$/.test(key)
  return { key, code: letter ? `Key${upper}` : digit ? `Digit${key}` : "", windowsVirtualKeyCode: letter || digit ? upper.charCodeAt(0) : 0, text: key }
}

function modifierBits(m: KeyModifiers = {}): number {
  return (m.alt ? 1 : 0) | (m.ctrl ? 2 : 0) | (m.meta ? 4 : 0) | (m.shift ? 8 : 0)
}

type EvaluateResult = { result?: { value?: unknown }; exceptionDetails?: { text?: string; exception?: { description?: string } } }

function interactPage(cdp: Cdp, sessionId: string, width: InteractWidth): InteractPage {
  const evaluate = async <T>(expression: string): Promise<T> => {
    const reply = (await cdp.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true }, sessionId)) as EvaluateResult
    if (reply.exceptionDetails !== undefined) throw new Error(reply.exceptionDetails.exception?.description ?? reply.exceptionDetails.text ?? "the expression threw")
    return reply.result?.value as T
  }
  const clickAt = async (x: number, y: number): Promise<void> => {
    for (const type of ["mouseMoved", "mousePressed", "mouseReleased"] as const) {
      await cdp.send("Input.dispatchMouseEvent", { type, x, y, button: type === "mouseMoved" ? "none" : "left", clickCount: type === "mouseMoved" ? 0 : 1 }, sessionId)
    }
  }
  return {
    width,
    evaluate,
    press: async (key, modifiers) => {
      const event = { ...keyEvent(key), modifiers: modifierBits(modifiers) }
      await cdp.send("Input.dispatchKeyEvent", { type: event.text !== undefined ? "keyDown" : "rawKeyDown", ...event }, sessionId)
      await cdp.send("Input.dispatchKeyEvent", { type: "keyUp", ...event, text: undefined }, sessionId)
    },
    click: async (selector) => {
      const box = await evaluate<{ x: number; y: number } | null>(`(() => {
        const shown = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 || r.height > 0; };
        const el = Array.from(document.querySelectorAll(${JSON.stringify(selector)})).find(shown);
        if (!el) return null;
        el.scrollIntoView({ block: "center", inline: "center" });
        const r = el.getBoundingClientRect();
        return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
      })()`)
      if (box === null) throw new Error(`nothing to click at ${selector}`)
      await clickAt(box.x, box.y)
    },
    clickAt,
  }
}

// Runs before the page's own scripts: keeps whatever the page throws, so a
// scenario on a page that broke fails even when its checks would pass.
const CATCH_PAGE_ERRORS = `window.__interactErrors = [];
addEventListener("error", (e) => window.__interactErrors.push(String(e.message || e.error)));
addEventListener("unhandledrejection", (e) => window.__interactErrors.push(String(e.reason)));`

// The local server: the built assets under /assets/, each scenario's page
// at /interact/<n>, and a 404 in JSON for every other address.
async function serve(assets: string, pages: readonly string[]): Promise<{ origin: string; close: () => Promise<void> }> {
  const types: Record<string, string> = { ".js": "text/javascript", ".css": "text/css", ".woff2": "font/woff2", ".svg": "image/svg+xml", ".png": "image/png", ".txt": "text/plain" }
  const server: Server = createServer((request, response) => {
    void (async () => {
      const url = new URL(request.url ?? "/", "http://localhost")
      const page = /^\/interact\/(\d+)$/.exec(url.pathname)
      const html = page !== null ? pages[Number(page[1])] : undefined
      if (html !== undefined) {
        response.writeHead(200, { "content-type": "text/html; charset=utf-8" })
        response.end(html)
        return
      }
      if (url.pathname.startsWith("/assets/") && !url.pathname.includes("..")) {
        try {
          const body = await readFile(path.join(assets, url.pathname.slice("/assets/".length)))
          response.writeHead(200, { "content-type": types[path.extname(url.pathname)] ?? "application/octet-stream" })
          response.end(body)
          return
        } catch {
          // Not built: the 404 below.
        }
      }
      response.writeHead(404, { "content-type": "application/json" })
      response.end(JSON.stringify({ error: "not_found", message: "No such route." }))
    })()
  })
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  const { port } = server.address() as AddressInfo
  return { origin: `http://127.0.0.1:${port}`, close: () => new Promise<void>((resolve) => server.close(() => resolve())) }
}

function withTimeout<T>(work: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} did not finish within ${ms} ms`)), ms)
  })
  return Promise.race([work, late]).finally(() => clearTimeout(timer))
}

async function runScenario(cdp: Cdp, sessionId: string, url: string, scenario: InteractScenario, width: InteractWidth): Promise<void> {
  await cdp.send("Emulation.setDeviceMetricsOverride", { width, height: INTERACT_VIEWPORTS[width], deviceScaleFactor: 1, mobile: width < 600, screenOrientation: { type: "portraitPrimary", angle: 0 } }, sessionId)
  const loaded = cdp.once("Page.loadEventFired", sessionId)
  const navigated = (await cdp.send("Page.navigate", { url }, sessionId)) as { errorText?: string }
  if (navigated.errorText) {
    loaded.catch(() => undefined)
    throw new Error(`the page did not load: ${navigated.errorText}`)
  }
  await loaded
  const page = interactPage(cdp, sessionId, width)
  await page.evaluate("document.fonts.ready.then(() => true)")
  await scenario.run(page)
  const thrown = await page.evaluate<string[]>("window.__interactErrors")
  if (thrown.length > 0) throw new Error(`the page threw: ${thrown.join("; ")}`)
}

async function main(argv: string[]): Promise<number> {
  const scenarios: readonly InteractScenario[] = [...SHELL_SCENARIOS, ...BAR_SCENARIOS, ...CONSOLE_SCENARIOS]
  if (scenarios.length === 0) {
    console.log("interact: no scenarios")
    return 0
  }
  const chromeFlag = argv.indexOf("--chrome")
  const chromePath = (chromeFlag >= 0 ? argv[chromeFlag + 1] : findChrome()) ?? ""
  if (chromePath === "") {
    console.error(`interact: no Chrome or Chromium found (looked for ${CHROME_CANDIDATES.join(", ")}): pass --chrome <path>`)
    return 2
  }
  const assets = path.resolve(import.meta.dirname, "../dist/assets")
  try {
    await readFile(path.join(assets, "app.js"))
  } catch {
    console.error(`interact: ${path.join(assets, "app.js")} is missing: run \`bun run build:ui\` in apps/vault first`)
    return 2
  }

  const pages = scenarios.map((s) => renderDocument(s.page()).value)
  const server = await serve(assets, pages)
  let failed = 0
  try {
    let chrome: Awaited<ReturnType<typeof launchChrome>>
    try {
      chrome = await launchChrome(chromePath)
    } catch (error) {
      console.error(`interact: Chrome did not start from ${chromePath}: ${error instanceof Error ? error.message : String(error)}`)
      return 2
    }
    const { cdp, close } = chrome
    try {
      const { targetId } = (await cdp.send("Target.createTarget", { url: "about:blank" })) as { targetId: string }
      const { sessionId } = (await cdp.send("Target.attachToTarget", { targetId, flatten: true })) as { sessionId: string }
      await cdp.send("Page.enable", {}, sessionId)
      await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: CATCH_PAGE_ERRORS }, sessionId)
      await cdp.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] }, sessionId)
      for (const [index, scenario] of scenarios.entries()) {
        for (const width of scenario.widths ?? PHONE_WIDTHS) {
          const where = `${scenario.name} at ${width} px`
          try {
            await withTimeout(runScenario(cdp, sessionId, `${server.origin}/interact/${index}`, scenario, width), SCENARIO_TIMEOUT_MS, where)
            console.log(`ok    ${where}`)
          } catch (error) {
            failed++
            console.log(`FAIL  ${where}: ${error instanceof Error ? error.message : String(error)}`)
          }
        }
      }
    } finally {
      await close()
    }
  } finally {
    await server.close()
  }
  console.log(failed === 0 ? `interact: ${scenarios.length} scenarios passed at every width` : `interact: ${failed} failed`)
  return failed === 0 ? 0 : 1
}

process.exit(await main(process.argv.slice(2)))
