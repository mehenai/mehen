// mehen fill against a real Chrome, headless, on https pages served with
// leaves of a run CA (relay/ca.ts) on two sites, login.test and other.test,
// so a frame of the other site is out of process. Skipped where no Chrome
// is installed (CHROME_PATH names one elsewhere).

import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { createHash, X509Certificate } from "node:crypto"
import { existsSync } from "node:fs"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { Server, Subprocess } from "bun"
import { type FillRequest, fillSealContext } from "@mehen/protocol/fill"
import { importSealPublicKey, seal } from "@mehen/protocol/seal"
import { CliError } from "../errors.ts"
import { createRunCa } from "../relay/ca.ts"
import type { VaultApi } from "../vault-api.ts"
import { CHROME_START_MS, startChrome } from "../testing/chrome.ts"
import { CdpConnection } from "./cdp.ts"
import { type FillOptions, fill } from "./fill.ts"
import { checkField, locateField, pageFrames } from "./page-check.ts"

const CHROME = [process.env.CHROME_PATH, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/usr/bin/google-chrome", "/usr/bin/chromium"].find((path): path is string => typeof path === "string" && existsSync(path))

const VALUE = "s3ntinel-Value-7Q"
const WORKSPACE = "tn_ChromeTest1234"
const ITEM = "itm_chrometest"

type Site = { server: Server<undefined>; origin: string }
let login: Site
let other: Site
let profile: string
let chrome: Subprocess
let control: CdpConnection
let session: string
let pageTarget: string
const asked: FillRequest[] = []
// Runs while the vault "decides", to change the page under the fill.
let duringAsk: (() => Promise<void>) | null = null

const html = (body: string) => new Response(`<!doctype html><html><body style="margin:0">${body}</body></html>`, { headers: { "content-type": "text/html" } })
const password = '<input id="pw" type="password" autocomplete="current-password">'

function loginPages(path: string): Response {
  switch (path) {
    case "/plain":
      return html(`<form action="/done"><input id="user" type="email" autocomplete="username">${password}<input id="otp" inputmode="numeric" autocomplete="one-time-code"></form>`)
    case "/kinds":
      return html('<input id="text" type="text"><input id="new" type="password" autocomplete="new-password"><textarea id="area"></textarea><input id="check" type="checkbox">')
    case "/hidden":
      return html(`<input id="none" type="password" style="display:none"><input id="clear" type="password" style="opacity:0"><input id="off" type="password" disabled><input id="ro" type="password" readonly>`)
    case "/overlay":
      return html(`${password}<div style="position:fixed;inset:0;background:white"></div>`)
    case "/shadow":
      return html(`<div id="open"></div><div id="closed"></div><script>
        document.getElementById("open").attachShadow({ mode: "open" }).innerHTML = '${password}'
        document.getElementById("closed").attachShadow({ mode: "closed" }).innerHTML = '${password}'
      </script>`)
    case "/twice":
      return html(`${password}<iframe src="/inner"></iframe>`)
    case "/nested":
      return html('<iframe src="/inner" style="width:400px;height:200px"></iframe>')
    case "/inner":
      return html(password)
    case "/submits":
      return html(`<form action="/done">${password}</form>`)
    case "/submits-beside":
      return html(`<form action="/done">${password}</form><iframe src="${other.origin}/ad" style="width:200px;height:100px"></iframe>`)
    case "/clobbered":
      return html(`<img name="querySelectorAll"><img name="elementFromPoint"><img name="execCommand"><form name="activeElement"></form>${password}`)
    case "/turns":
      return html(`<input id="to-text" type="password" autocomplete="current-password" onfocus="this.type = 'text'"><input id="to-ro" type="password" autocomplete="current-password" onfocus="this.readOnly = true">`)
    case "/stays":
      return html(`<form onsubmit="event.preventDefault()">${password}</form>`)
    case "/done":
      return html("<p>signed in</p>")
    default:
      return new Response("not found", { status: 404 })
  }
}

function otherPages(path: string): Response {
  if (path === "/embeds-login") return html(`<iframe src="${login.origin}/inner" style="width:400px;height:200px"></iframe>`)
  if (path === "/inner") return html(password)
  if (path === "/ad") return html("<p>an advert</p>")
  return new Response("not found", { status: 404 })
}

async function site(host: string, ca: Awaited<ReturnType<typeof createRunCa>>, pages: (path: string) => Response): Promise<Site> {
  const leaf = await ca.issueLeaf(host)
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, tls: { cert: leaf.certPem, key: leaf.keyPem }, fetch: (request) => pages(new URL(request.url).pathname) })
  return { server, origin: `https://${host}:${server.port}` }
}

async function evaluate(expression: string): Promise<unknown> {
  const answer = await control.send<{ result: { value?: unknown } }>("Runtime.evaluate", { expression, returnByValue: true }, { sessionId: session })
  return answer.result.value
}

async function loaded(url: string): Promise<void> {
  for (let i = 0; i < 100; i++) {
    await Bun.sleep(50)
    if ((await evaluate("location.href").catch(() => null)) === url && (await evaluate("document.readyState").catch(() => null)) === "complete") {
      await Bun.sleep(200)
      return
    }
  }
  throw new Error(`${url} did not load`)
}

async function open(url: string): Promise<void> {
  await control.send("Page.navigate", { url }, { sessionId: session })
  await loaded(url)
}

// The vault's side, in process: it seals the value to the request's key
// under the context the CLI must build, with the jti of the proof.
const vault: VaultApi = {
  async request<T>(_method: string, _path: string, body?: unknown, options?: { onProof?: (jti: string) => void }): Promise<T> {
    const request = body as FillRequest
    asked.push(request)
    await duringAsk?.()
    const jti = `jti_${asked.length}`
    options?.onProof?.(jti)
    const box = await seal(await importSealPublicKey(request.recipient), VALUE, fillSealContext({ workspace: WORKSPACE, item: ITEM, field: request.field, origin: request.origin, jti }))
    const input = request.field === "username" ? "username" : request.field === "totp" ? "one-time-code" : "password"
    return { box, item: ITEM, field: request.field, input, label: `the ${input} for alex@example.com`, origin: request.origin, by: { free: true } } as T
  },
  relay: async () => new Response(),
}

function options(selector: string, extra: Partial<FillOptions> = {}): FillOptions {
  return { item: "github-alex", field: "password", selector, submit: false, source: { userDataDir: profile }, target: pageTarget, context: null, approval: null, help: "mehen fill --help", ...extra }
}

async function refusal(promise: Promise<unknown>): Promise<CliError> {
  const error = await promise.then(() => null, (e: unknown) => e)
  if (!(error instanceof CliError)) throw new Error(`expected a refusal, got ${error instanceof Error ? error.stack : JSON.stringify(error)}`)
  expect(JSON.stringify({ message: error.message, next: error.next, extras: error.extras })).not.toContain(VALUE)
  return error
}

const fieldValue = (selector: string) => evaluate(`document.querySelector(${JSON.stringify(selector)}).value`)
const deps = { vault: async () => ({ api: vault, workspace: WORKSPACE }), submitWaitMs: 2000 }

describe.skipIf(CHROME === undefined)("mehen fill in a real Chrome", () => {
  beforeAll(async () => {
    const ca = await createRunCa(["login.test", "other.test"])
    login = await site("login.test", ca, loginPages)
    other = await site("other.test", ca, otherPages)
    const spki = createHash("sha256").update(new X509Certificate((await ca.issueLeaf("login.test")).certPem).publicKey.export({ type: "spki", format: "der" })).digest("base64")
    profile = await mkdtemp(join(tmpdir(), "mehen-fill-chrome-"))
    const started = await startChrome(CHROME as string, profile, ["--site-per-process", "--host-resolver-rules=MAP *.test 127.0.0.1", `--ignore-certificate-errors-spki-list=${spki}`])
    chrome = started.process
    control = await CdpConnection.open(started.endpoint)
    const { targetInfos } = await control.send<{ targetInfos: { targetId: string; type: string }[] }>("Target.getTargets")
    pageTarget = (targetInfos.find((info) => info.type === "page") as { targetId: string }).targetId
    session = (await control.send<{ sessionId: string }>("Target.attachToTarget", { targetId: pageTarget, flatten: true })).sessionId
    await control.send("Page.enable", {}, { sessionId: session })
    // A headless page has no focus, so it fires no focus events; the agent's
    // browser does, and the page's focus handlers run inside the typing call.
    await control.send("Emulation.setFocusEmulationEnabled", { enabled: true }, { sessionId: session })
  }, CHROME_START_MS + 15_000)

  afterAll(async () => {
    control?.close()
    chrome?.kill()
    await chrome?.exited
    login?.server.stop(true)
    other?.server.stop(true)
    if (profile) await rm(profile, { recursive: true, force: true })
  })

  test("types each field into the field that is for it, checked in one task, and returns no value", async () => {
    await open(`${login.origin}/plain`)
    asked.length = 0
    const result = await fill(options("#pw"), deps)
    expect(result).toEqual({ typed: true, label: "the password for alex@example.com", origin: login.origin, page: "/plain", submitted: false, navigatedTo: null, cleared: false })
    expect(JSON.stringify(result)).not.toContain(VALUE)
    expect(await fieldValue("#pw")).toBe(VALUE)
    expect(asked).toMatchObject([{ item: "github-alex", field: "password", origin: login.origin, page: "/plain" }])
    await fill(options("#user", { field: "username" }), deps)
    expect(await fieldValue("#user")).toBe(VALUE)
    await fill(options("#otp", { field: "totp" }), deps)
    expect(await fieldValue("#otp")).toBe(VALUE)
    await fill(options("#pw"), deps)
    expect(await fieldValue("#pw")).toBe(VALUE)
  }, 30_000)

  test("refuses a field of another kind before asking the vault", async () => {
    await open(`${login.origin}/kinds`)
    asked.length = 0
    for (const selector of ["#text", "#new", "#area", "#check"]) expect({ selector, code: (await refusal(fill(options(selector), deps))).code }).toEqual({ selector, code: "field_kind_mismatch" })
    expect((await refusal(fill(options("#check", { field: "key" }), deps))).code).toBe("field_kind_mismatch")
    expect(asked).toEqual([])
  }, 30_000)

  test("refuses a hidden, transparent, disabled, read-only or covered field before asking the vault", async () => {
    await open(`${login.origin}/hidden`)
    asked.length = 0
    for (const selector of ["#none", "#clear", "#off", "#ro"]) expect({ selector, code: (await refusal(fill(options(selector), deps))).code }).toEqual({ selector, code: "field_hidden" })
    await open(`${login.origin}/overlay`)
    expect((await refusal(fill(options("#pw"), deps))).code).toBe("field_hidden")
    expect(asked).toEqual([])
  }, 30_000)

  test("steps into an open shadow root, never a closed one", async () => {
    await open(`${login.origin}/shadow`)
    asked.length = 0
    await fill(options("#open >>> #pw"), deps)
    expect(await evaluate('document.getElementById("open").shadowRoot.getElementById("pw").value')).toBe(VALUE)
    expect((await refusal(fill(options("#closed >>> #pw"), deps))).code).toBe("field_not_found")
    expect((await refusal(fill(options("#missing"), deps))).code).toBe("field_not_found")
    expect((await refusal(fill(options("#open >>> "), deps))).code).toBe("usage")
    expect(asked).toHaveLength(1)
  }, 30_000)

  test("a selector that matches in two frames is ambiguous", async () => {
    await open(`${login.origin}/twice`)
    expect((await refusal(fill(options("#pw"), deps))).code).toBe("field_ambiguous")
  }, 30_000)

  test("types into a frame nested in a page of its own origin", async () => {
    await open(`${login.origin}/nested`)
    const result = await fill(options("#pw"), deps)
    expect(result).toMatchObject({ origin: login.origin, page: "/inner" })
    expect(await evaluate('document.querySelector("iframe").contentDocument.getElementById("pw").value')).toBe(VALUE)
  }, 30_000)

  test("refuses a frame inside a page of another origin, out of process, before asking the vault", async () => {
    await open(`${other.origin}/embeds-login`)
    asked.length = 0
    const error = await refusal(fill(options("#pw"), deps))
    expect(error.code).toBe("frame_origin_mismatch")
    expect(asked).toEqual([])
  }, 30_000)

  // Chrome 156 reports a no-referrer parent's real origin in
  // location.ancestorOrigins, so a "null" from the page is driven here by
  // giving the check the browser's side of a disagreement.
  test("the check refuses when the browser and the frame disagree about its ancestors, a null among them", async () => {
    await open(`${login.origin}/nested`)
    const frames = await pageFrames(control, session)
    const located = await locateField(control, frames, "#pw")
    if (!("field" in located)) throw new Error("the nested field was not found")
    const check = { selector: "#pw", origin: login.origin, input: "password" as const }
    expect(await checkField(control, located.field, { ...check, ancestors: [login.origin] }, null)).toEqual({ code: "ok" })
    for (const ancestors of [[], ["null"], [login.origin, login.origin], [other.origin]]) {
      expect({ ancestors, verdict: (await checkField(control, located.field, { ...check, ancestors }, VALUE)).code }).toEqual({ ancestors, verdict: "frame_origin_mismatch" })
    }
    expect(await checkField(control, located.field, { ...check, origin: other.origin, ancestors: [other.origin] }, VALUE)).toMatchObject({ code: "frame_origin_mismatch" })
    expect(await evaluate('document.querySelector("iframe").contentDocument.getElementById("pw").value')).toBe("")
  }, 30_000)

  test("the field going away, or the page navigating, while the vault answers is page_changed with nothing typed", async () => {
    try {
      await open(`${login.origin}/plain`)
      duringAsk = async () => void (await evaluate('document.getElementById("pw").remove()'))
      expect((await refusal(fill(options("#pw"), deps))).code).toBe("page_changed")
      await open(`${login.origin}/plain`)
      duringAsk = async () => void (await evaluate('document.getElementById("pw").replaceWith(Object.assign(document.createElement("input"), { id: "pw", type: "password" }))'))
      expect((await refusal(fill(options("#pw"), deps))).code).toBe("page_changed")
      expect(await fieldValue("#pw")).toBe("")
      await open(`${login.origin}/plain`)
      duringAsk = async () => open(`${login.origin}/kinds`)
      expect((await refusal(fill(options("#pw"), deps))).code).toBe("page_changed")
    } finally {
      duringAsk = null
    }
  }, 30_000)

  test("named elements that shadow the document's methods in the page's own world do not stop the check, the typing or the clearing", async () => {
    await open(`${login.origin}/clobbered`)
    expect(await evaluate("typeof document.querySelectorAll + ' ' + typeof document.activeElement")).toBe("object object")
    expect(await fill(options("#pw"), deps)).toMatchObject({ typed: true, origin: login.origin, page: "/clobbered" })
    expect(await fieldValue("#pw")).toBe(VALUE)
    const error = await refusal(fill(options("#pw", { submit: true }), deps))
    expect({ code: error.code, cleared: error.extras.cleared }).toEqual({ code: "not_submitted", cleared: true })
    expect(await fieldValue("#pw")).toBe("")
  }, 30_000)

  test("a field its focus handler turns into another kind, or read-only, is refused and nothing is typed", async () => {
    await open(`${login.origin}/turns`)
    const turned = await refusal(fill(options("#to-text"), deps))
    expect({ code: turned.code, message: turned.message }).toEqual({ code: "field_kind_mismatch", message: expect.stringContaining("when it took the focus") })
    expect(await fieldValue("#to-text")).toBe("")
    await open(`${login.origin}/turns`)
    const frozen = await refusal(fill(options("#to-ro"), deps))
    expect({ code: frozen.code, message: frozen.message }).toEqual({ code: "field_hidden", message: expect.stringContaining("when it took the focus") })
    expect(await fieldValue("#to-ro")).toBe("")
  }, 30_000)

  test("--submit presses a trusted Enter and reports where the page went", async () => {
    await open(`${login.origin}/submits`)
    const result = await fill(options("#pw", { submit: true }), deps)
    expect(result).toMatchObject({ typed: true, submitted: true, navigatedTo: `${login.origin}/done`, cleared: false })
    await loaded(`${login.origin}/done?`)
  }, 30_000)

  test("--submit reads the frame tree again before the Enter, beside a frame of another site, and submits", async () => {
    await open(`${login.origin}/submits-beside`)
    const result = await fill(options("#pw", { submit: true }), deps)
    expect(result).toMatchObject({ typed: true, submitted: true, navigatedTo: `${login.origin}/done`, cleared: false })
    await loaded(`${login.origin}/done?`)
  }, 30_000)

  test("--submit on a page that does not go anywhere empties the field and says not_submitted", async () => {
    await open(`${login.origin}/stays`)
    const error = await refusal(fill(options("#pw", { submit: true }), deps))
    expect(error.code).toBe("not_submitted")
    expect(error.extras.cleared).toBe(true)
    expect(await fieldValue("#pw")).toBe("")
  }, 30_000)
})
