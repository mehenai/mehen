// The credentials page's add sheet in the browser path: the page the server
// renders, run in test/mini-dom.ts with the production
// initWorkspaceCredentials wiring it. The page head's button opens the
// sheet; its close button, a click on the scrim and Escape close it; a
// click inside the panel leaves it open. Its checks and the vault's
// refusals show inside the open sheet, never in the page's notice behind
// the scrim, and the typed name stays for correcting. Then the credential
// page's How careful card, wired by initWorkspaceCredential the same way.
// One credential's page signs its push allowance under item.update and
// pushes a rotated value to the places ticked under item.push, refusing
// before the passkey unless the vault's action is the one the page rebuilt.
// Then the credential page's In web pages card, at the end.
import { afterEach, describe, expect, it, vi } from "vitest"
import type { WorkspaceStepUpAction } from "@mehen/protocol/workspace"
import { renderDocument } from "../src/ui/layout.ts"
import { type HumanItemDescription, NAME_NOT_AVAILABLE_WORDS, workspaceCredentialPage, workspaceCredentialsPage } from "../src/ui/pages/workspace-credentials.ts"
import { GALLERY_ITEMS, GALLERY_LOGIN, GALLERY_PUSHES, GALLERY_WORKSPACE, VIEWERS, description, galleryShell } from "../src/ui/workspace-projects-gallery.ts"
import type { Viewer } from "../src/ui/workspace-rights.ts"
import { initWorkspaceCredential, initWorkspaceCredentials } from "../src/ui/client/pages/workspace.ts"
import { digestOf } from "../src/ui/client/logic.ts"
import { PUSH_AGAIN_CHANGED_WORDS, PUSH_AGAIN_CHOOSE_WORDS, PUSH_AGAIN_VIA_UNSEEN_WORDS } from "../src/ui/push-wording.ts"
import { stepUpDigest } from "../src/vault/areas/items.ts"
import type { PageInput } from "../src/ui/layout.ts"
import { POSTURE_TOKEN, POSTURE_TRUST_NAMED, postureGallery, posturePage } from "../src/ui/posture-gallery.ts"
import { ShellState } from "../src/ui/client/shell-logic.ts"
import type { Boot } from "../src/ui/client/dom.ts"
import { type MiniBrowser, type MiniElement, MiniEvent, installPage, settle } from "./mini-dom.ts"

// The In web pages card's Save: the passkey prompt, stubbed.
const passkeys = vi.hoisted(() => ({ count: 0 }))
vi.mock("@simplewebauthn/browser", () => ({
  startAuthentication: async () => {
    passkeys.count++
    return { id: "test-assertion" }
  },
  startRegistration: async () => ({ id: "test-registration" }),
}))

let browser: MiniBrowser | null = null
afterEach(() => {
  browser?.restore()
  browser = null
  passkeys.count = 0
})

function open(respond: MiniBrowser["respond"] = () => ({ status: 404, body: { error: "not_found", message: "No such route." } })): MiniBrowser {
  const markup = renderDocument(workspaceCredentialsPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, items: GALLERY_ITEMS.filter((i) => i.home.kind !== "member"), projects: [] })).value
  browser = installPage(markup, respond)
  const boot = JSON.parse(browser.document.querySelector("#app")?.getAttribute("data-boot") ?? "{}") as Boot
  initWorkspaceCredentials(boot, new ShellState({ origin: "https://vault.test", account: "acc_4Hq9Tz2Lm7Vb1Nc8", workspace: GALLERY_WORKSPACE, pages: [], reads: [] }))
  return browser
}

it("opens the add sheet from the page head's button and closes it by its button, the scrim and Escape", () => {
  const b = open()
  const sheet = b.document.querySelector('[data-region="add-credential"]')!
  const opener = b.document.querySelector('[data-action="open-add"]')!
  expect(sheet.hidden).toBe(true)
  opener.click()
  expect(sheet.hidden).toBe(false)
  b.document.querySelector('[data-action="close-sheet"]')!.click()
  expect(sheet.hidden).toBe(true)
  opener.click()
  sheet.click()
  expect(sheet.hidden).toBe(true)
  opener.click()
  b.document.querySelector('[data-input="slug"]')!.click()
  expect(sheet.hidden).toBe(false)
  b.document.dispatchEvent(Object.assign(new MiniEvent("keydown"), { key: "Escape" }))
  expect(sheet.hidden).toBe(true)
})

// Opens the sheet, types a name and presses Continue; returns the sheet.
async function pressContinue(b: MiniBrowser, name: string): Promise<MiniElement> {
  const sheet = b.document.querySelector('[data-region="add-credential"]')!
  b.document.querySelector('[data-action="open-add"]')!.click()
  b.document.querySelector('[data-input="slug"]')!.value = name
  b.document.querySelector('[data-action="add-credential"]')!.click()
  await settle()
  return sheet
}

// The message is in the open sheet, and the page's own notice is untouched.
function expectInSheet(b: MiniBrowser, sheet: MiniElement, words: string): void {
  expect(sheet.hidden).toBe(false)
  const inside = sheet.querySelector('[data-region="sheet-notice"]')!
  expect(inside.hidden).toBe(false)
  expect(inside.className).toBe("notice error")
  expect(inside.getAttribute("role")).toBe("alert")
  expect(inside.textContent).toContain(words)
  const page = b.document.querySelector("#notice")!
  expect(page.hidden).toBe(true)
  expect(page.textContent).toBe("")
}

it("shows an empty name's check inside the open sheet and sends nothing", async () => {
  const b = open()
  const sheet = await pressContinue(b, "")
  expectInSheet(b, sheet, "Name the credential and choose where it belongs.")
  expect(b.calls).toEqual([])
})

it("shows the vault's name refusal inside the open sheet, the name kept for correcting", async () => {
  const b = open(() => ({ status: 409, body: { error: "conflict", message: "name not available" } }))
  const sheet = await pressContinue(b, "openai-dev")
  expectInSheet(b, sheet, NAME_NOT_AVAILABLE_WORDS)
  expect(b.calls.map((c) => c.path)).toEqual([`/api/w/${GALLERY_WORKSPACE.slug}/intakes`])
  expect(b.document.querySelector('[data-input="slug"]')!.value).toBe("openai-dev")
  expect(b.assigned).toEqual([])
})

it("shows any other failure inside the open sheet in the vault's words, and a reopened sheet starts clear", async () => {
  const b = open(() => ({ status: 503, body: { error: "unavailable", message: "The vault is busy; try again in a minute." } }))
  const sheet = await pressContinue(b, "openai-dev")
  expectInSheet(b, sheet, "The vault is busy; try again in a minute.")
  b.document.querySelector('[data-action="close-sheet"]')!.click()
  b.document.querySelector('[data-action="open-add"]')!.click()
  expect(sheet.querySelector('[data-region="sheet-notice"]')!.hidden).toBe(true)
})

// ---------------------------------------------------------------- How careful

// A credential's page from the How careful gallery (posture-gallery.ts),
// wired by the production initWorkspaceCredential.
function credential(page: PageInput, respond: MiniBrowser["respond"] = () => ({ status: 404, body: { error: "not_found", message: "No such route." } })): MiniBrowser {
  browser = installPage(renderDocument(page).value, respond)
  const boot = JSON.parse(browser.document.querySelector("#app")?.getAttribute("data-boot") ?? "{}") as Boot
  initWorkspaceCredential(boot, new ShellState({ origin: "https://vault.test", account: "acc_4Hq9Tz2Lm7Vb1Nc8", workspace: GALLERY_WORKSPACE, pages: [], reads: [] }))
  return browser
}
const postureEntry = (id: string) => postureGallery().find((e) => e.id === id)!.page
const level = (b: MiniBrowser, value: string) => b.document.querySelector(`[data-input="posture-level"][value="${value}"]`)!

it("draws no How careful card, and no Save for it, when the description carries no posture", () => {
  const b = credential(workspaceCredentialPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, item: description(GALLERY_ITEMS[0]!), projects: [] }))
  expect(b.document.querySelector('[data-region="posture"]')).toBeNull()
  expect(b.document.querySelector('[data-action="posture-save"]')).toBeNull()
})

it("keeps Save with passkey disabled, saying Nothing to save, until a choice changes something", () => {
  const b = credential(postureEntry("ws-posture-ask"))
  const save = b.document.querySelector('[data-action="posture-save"]')!
  const nothing = b.document.querySelector('[data-region="posture-nothing"]')!
  expect(save.disabled).toBe(true)
  expect(nothing.hidden).toBe(false)
  expect(nothing.textContent).toBe("Nothing to save.")
  level(b, "routine").click()
  expect(save.disabled).toBe(false)
  expect(nothing.hidden).toBe(true)
  expect(b.document.querySelector('[data-region="posture-machines"]')!.hidden).toBe(false)
  b.document.querySelector('[data-input="posture-machines"][value="named"]')!.click()
  expect(save.disabled).toBe(true)
  expect(nothing.textContent).toBe("Tick at least one machine.")
  b.document.querySelector('[data-input="posture-machine"][value="dev_tomlaptop01"]')!.click()
  expect(save.disabled).toBe(false)
  // Custom stores ask, as stored: nothing to save, and nothing is sent.
  level(b, "custom").click()
  expect(save.disabled).toBe(true)
  expect(nothing.textContent).toBe("Nothing to save.")
  expect(b.document.querySelector('[data-region="posture-custom"]')!.hidden).toBe(false)
  expect(b.document.querySelector('[data-region="posture-machines"]')!.hidden).toBe(true)
  save.click()
  expect(b.calls).toEqual([])
})

it("draws On these machines from the vault's eligible machines for the level chosen, keeps a named one no longer covered with a note, and sends only the ticks drawn", async () => {
  const named = { ...POSTURE_TRUST_NAMED, machines: [{ id: "dev_alexmbp0001", name: "alex-mbp" }, { id: "dev_oldci00001", name: "old-ci" }] }
  const b = credential(posturePage(POSTURE_TOKEN, named), () => ({ status: 200, body: { type: "item.posture", item: "itm_cloudflareprod", digest: "not-this-page's", level: "routine" } }))
  const row = (device: string) => b.document.querySelector(`[data-input="posture-machine"][value="${device}"]`)!.closest('[data-region="posture-machine-row"]')!
  const note = (device: string) => row(device).querySelector('[data-region="posture-machine-uncovered"]')!
  // Trust reaches only Alex's machine; Tom's is not drawn, and old-ci,
  // which the posture names, is drawn ticked with a note.
  expect([row("dev_alexmbp0001").hidden, row("dev_tomlaptop01").hidden, row("dev_oldci00001").hidden]).toEqual([false, true, false])
  expect([note("dev_alexmbp0001").hidden, note("dev_oldci00001").hidden]).toEqual([true, false])
  expect(note("dev_oldci00001").textContent).toBe("Not covered now.")
  // Routine reaches Tom's machine too.
  level(b, "routine").click()
  expect([row("dev_alexmbp0001").hidden, row("dev_tomlaptop01").hidden, row("dev_oldci00001").hidden]).toEqual([false, false, false])
  b.document.querySelector('[data-input="posture-machine"][value="dev_tomlaptop01"]')!.click()
  level(b, "trust").click()
  expect(row("dev_tomlaptop01").hidden).toBe(true)
  // Tom's tick is not drawn under Trust, so it is not sent.
  b.document.querySelector('[data-input="posture-machine"][value="dev_oldci00001"]')!.click()
  b.document.querySelector('[data-action="posture-save"]')!.click()
  await settle()
  expect(b.calls).toEqual([{ path: `/api/w/${GALLERY_WORKSPACE.slug}/items/cloudflare-prod/action`, body: { action: "posture", posture: { level: "trust", machines: ["dev_alexmbp0001"] }, rev: 2 } }])
})

it("Trust to Custom asks the vault for item.posture at level ask, and signs nothing when its action differs", async () => {
  const b = credential(postureEntry("ws-posture-trust-named"), () => ({ status: 200, body: { type: "item.posture", item: "itm_cloudflareprod", digest: "not-this-page's", level: "ask" } }))
  level(b, "custom").click()
  const save = b.document.querySelector('[data-action="posture-save"]')!
  expect(save.disabled).toBe(false)
  save.click()
  await settle()
  expect(b.calls).toEqual([{ path: `/api/w/${GALLERY_WORKSPACE.slug}/items/cloudflare-prod/action`, body: { action: "posture", posture: { level: "ask", machines: null }, rev: 2 } }])
  expect(b.document.querySelector("#notice")!.textContent).toContain("changed")
  expect(b.reloaded).toBe(0)
})

// ---------------------------------------------------------------- pushes

const API = `/api/w/${GALLERY_WORKSPACE.slug}`
const ITEM_API = `${API}/items/openai-ci`
const ASSERTION = { nonce: "n", assertion: { id: "test-assertion" } }
const PUSHED: HumanItemDescription = { ...description({ ...GALLERY_ITEMS[0]!, slug: "openai-ci" }), version: 4, pushable: true, pushes: GALLERY_PUSHES }
const SHOWN = { id: PUSHED.id, version: PUSHED.version, configRevision: PUSHED.configRevision, dependencyRevision: PUSHED.dependencyRevision }

// The calls every signed change makes once its action is checked, and the
// routes a test names; anything else is not found.
function signing(routes: Record<string, unknown>): MiniBrowser["respond"] {
  return (path) => {
    if (path === API) return { status: 200, body: GALLERY_WORKSPACE }
    if (path === ITEM_API) return { status: 200, body: SHOWN }
    if (path === `${API}/stepup/start`) return { status: 200, body: { nonce: "n", options: { challenge: "c" } } }
    if (path in routes) return { status: 200, body: routes[path] }
    return { status: 404, body: { error: "not_found", message: `No route ${path}.` } }
  }
}

function openPushedCredential(item: HumanItemDescription, respond: MiniBrowser["respond"]): MiniBrowser {
  const page = workspaceCredentialPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, item, projects: [], pushes: true })
  browser = installPage(renderDocument(page).value, respond)
  initWorkspaceCredential(page.boot, new ShellState({ origin: "https://vault.test", account: "acc_4Hq9Tz2Lm7Vb1Nc8", workspace: GALLERY_WORKSPACE, pages: [], reads: [] }))
  return browser
}

const $ = (selector: string): MiniElement => {
  const found = browser!.document.querySelector(selector)
  if (!found) throw new Error(`no ${selector}`)
  return found
}
const call = (path: string) => browser!.calls.find((c) => c.path === path)

describe("the push allowance", () => {
  it("saves the tick with a passkey over item.update for the version and configuration shown, once it changed", async () => {
    const item = { ...PUSHED, pushable: false }
    const change = { pushable: true }
    const expected: WorkspaceStepUpAction = { type: "item.update", item: SHOWN.id, digest: await digestOf({ change, version: SHOWN.version, configRevision: SHOWN.configRevision }) }
    const b = openPushedCredential(item, signing({ [`${ITEM_API}/action`]: expected, [`${ITEM_API}/update`]: {} }))
    const save = $('[data-action="save-pushable"]')
    expect(save.disabled).toBe(true)
    const box = $('[data-input="pushable"]')
    box.checked = true
    box.dispatchEvent(new MiniEvent("change", { bubbles: true }))
    expect(save.disabled).toBe(false)
    save.click()
    await settle()
    expect(call(`${ITEM_API}/action`)?.body).toEqual({ action: "update", change })
    expect(call(`${API}/stepup/start`)?.body).toEqual({ action: expected })
    expect(call(`${ITEM_API}/update`)?.body).toEqual({ ...change, stepUp: ASSERTION })
    expect(b.reloaded).toBe(1)
  })

  it("refuses before the passkey when the vault's action is not the change the page rebuilt", async () => {
    const item = { ...PUSHED, pushable: false }
    const other: WorkspaceStepUpAction = { type: "item.update", item: SHOWN.id, digest: await digestOf({ change: { pushable: false }, version: SHOWN.version, configRevision: SHOWN.configRevision }) }
    const b = openPushedCredential(item, signing({ [`${ITEM_API}/action`]: other }))
    const box = $('[data-input="pushable"]')
    box.checked = true
    box.dispatchEvent(new MiniEvent("change", { bubbles: true }))
    $('[data-action="save-pushable"]').click()
    await settle()
    expect(b.calls.map((c) => c.path)).not.toContain(`${API}/stepup/start`)
    expect(b.calls.map((c) => c.path)).not.toContain(`${ITEM_API}/update`)
    expect(b.reloaded).toBe(0)
  })
})

describe("pushing the new value to the same places", () => {
  const ticked = (...records: string[]) => {
    for (const record of records) $(`[data-input="push-record"][value="${record}"]`).click()
  }
  const action = (destinations: string[]): WorkspaceStepUpAction => ({ type: "item.push", item: SHOWN.id, field: "key", version: SHOWN.version, pushes: destinations.map((destination) => ({ destination, via: "itm_githubci", viaVersion: 2 })) })
  // The credential the ticked rows show carrying them, as this viewer reads it.
  const VIA_API = `${API}/items/github-ci`
  const VIA = { id: "itm_githubci", version: 2 }
  const notSigned = (b: MiniBrowser) => {
    expect(b.calls.map((c) => c.path)).not.toContain(`${API}/stepup/start`)
    expect(b.calls.map((c) => c.path)).not.toContain(`${ITEM_API}/push`)
    expect(b.reloaded).toBe(0)
  }

  it("offers every place on an older value unticked, and signs item.push for exactly the places ticked, with the credential each row showed", async () => {
    const expected = action(["github:northwind/platform/OPENAI_API_KEY"])
    const b = openPushedCredential(PUSHED, signing({ [VIA_API]: VIA, [`${ITEM_API}/push/action`]: expected, [`${ITEM_API}/push`]: { pushes: [] } }))
    const boxes = b.document.querySelectorAll('[data-input="push-record"]')
    expect(boxes.map((x) => x.getAttribute("value"))).toEqual(["psh_gh000001", "psh_gh000002"])
    expect(boxes.every((x) => !x.checked)).toBe(true)
    ticked("psh_gh000001")
    $('[data-action="push-again"]').click()
    await settle()
    const paths = b.calls.map((c) => c.path)
    expect(paths.indexOf(VIA_API)).toBeLessThan(paths.indexOf(`${ITEM_API}/push/action`))
    expect(call(`${ITEM_API}/push/action`)?.body).toEqual({ records: ["psh_gh000001"] })
    expect(call(`${API}/stepup/start`)?.body).toEqual({ action: expected })
    expect(call(`${ITEM_API}/push`)?.body).toEqual({ records: ["psh_gh000001"], stepUp: ASSERTION })
    expect(b.reloaded).toBe(1)
  })

  it("refuses before the passkey when the vault's plan names another place, version or credential", async () => {
    for (const planned of [action(["github:northwind/platform/OPENAI_API_KEY", "github:northwind/website/env/production/OPENAI_API_KEY"]), { ...action(["github:northwind/platform/OPENAI_API_KEY"]), version: SHOWN.version + 1 }, { ...action(["github:northwind/platform/OPENAI_API_KEY"]), item: "itm_another" }]) {
      const b = openPushedCredential(PUSHED, signing({ [VIA_API]: VIA, [`${ITEM_API}/push/action`]: planned }))
      ticked("psh_gh000001")
      $('[data-action="push-again"]').click()
      await settle()
      notSigned(b)
      browser!.restore()
    }
    browser = null
  })

  it("refuses before the passkey when the plan carries a push with another credential, or another version of it, than the row showed", async () => {
    const shown = action(["github:northwind/platform/OPENAI_API_KEY"])
    const entry = shown.type === "item.push" ? shown.pushes[0]! : null
    for (const planned of [{ ...shown, pushes: [{ ...entry!, via: "itm_cloudflaredeploy" }] }, { ...shown, pushes: [{ ...entry!, viaVersion: 3 }] }]) {
      const b = openPushedCredential(PUSHED, signing({ [VIA_API]: VIA, [`${ITEM_API}/push/action`]: planned }))
      ticked("psh_gh000001")
      $('[data-action="push-again"]').click()
      await settle()
      expect(call(`${ITEM_API}/push/action`)).toBeDefined()
      notSigned(b)
      expect($("#notice").textContent).toContain(PUSH_AGAIN_CHANGED_WORDS)
      browser!.restore()
    }
    browser = null
  })

  it("refuses before the plan and the passkey when the viewer cannot read the credential a ticked row showed", async () => {
    const b = openPushedCredential(PUSHED, signing({ [`${ITEM_API}/push/action`]: action(["github:northwind/platform/OPENAI_API_KEY"]) }))
    ticked("psh_gh000001")
    $('[data-action="push-again"]').click()
    await settle()
    expect(call(VIA_API)).toBeDefined()
    expect(call(`${ITEM_API}/push/action`)).toBeUndefined()
    notSigned(b)
    expect($("#notice").textContent).toContain(PUSH_AGAIN_VIA_UNSEEN_WORDS)
  })

  it("never offers a place whose carrying credential the viewer cannot see as one to tick", () => {
    const b = openPushedCredential(PUSHED, signing({}))
    const unseen = $('[data-region="push-again-unseen"] input')
    expect(unseen.disabled).toBe(true)
    expect(unseen.getAttribute("data-input")).toBeNull()
    expect(b.document.querySelectorAll('[data-input="push-record"]').map((x) => x.getAttribute("value"))).not.toContain("psh_gh000003")
  })

  it("asks for a place first and sends nothing when none is ticked", async () => {
    const b = openPushedCredential(PUSHED, signing({}))
    $('[data-action="push-again"]').click()
    await settle()
    expect($("#notice").textContent).toContain(PUSH_AGAIN_CHOOSE_WORDS)
    expect(b.calls.filter((c) => c.path.startsWith(ITEM_API))).toEqual([])
  })
})

// ---------------------------------------------------------------- In web pages

// The credential page's "In web pages" card where
// BROWSER_FILL is on: how agents may use it, the sign-in pages marked as
// the vault's signinOriginSources marks them, the pages of other services
// it may also be typed into, and Save with passkey through item.update.
// Rendered by the server and run in test/mini-dom.ts with the production
// initWorkspaceCredential, the vault answered by the test and the passkey
// prompt stubbed. Switch off, or a kind fill never types, the page is as
// it was.
const WORKSPACE = { id: "tn_8kQw2Lm4Zp7Rt5Vx", slug: "northwind", name: "Northwind" }
const ITEM = `${API}/items/github-login`
type Answer = { status: number; body: unknown }
const ok = (body: unknown): Answer => ({ status: 200, body })

const pageOf = (item: HumanItemDescription, fill: boolean, viewer: Viewer = VIEWERS.owner) => workspaceCredentialPage(galleryShell(viewer), { viewer, item, projects: [], ...(fill ? { fill } : {}) })
const { browser: _pages, ...LOGIN_WITHOUT_PAGES } = GALLERY_LOGIN

function openCredential(item: HumanItemDescription, respond: (path: string, body: unknown) => Answer = () => ({ status: 404, body: { error: "not_found", message: "No route." } })): MiniBrowser {
  const page = pageOf(item, true)
  browser = installPage(renderDocument(page).value, respond, "https://app.mehen.dev/w/northwind/items/github-login")
  initWorkspaceCredential(page.boot, new ShellState({ origin: "https://app.mehen.dev", account: "acc_4Hq9Tz2Lm7Vb1Nc8", workspace: WORKSPACE, pages: [], reads: [] }))
  return browser
}

const origins = (region: string) => browser!.document.querySelectorAll(`[data-region="${region}"] li[data-origin]`).map((li) => `${li.getAttribute("data-origin")} ${li.querySelector(".row-sub")?.textContent ?? ""}`.trim())
function typeIn(selector: string, value: string): void {
  const el = $(selector)
  el.value = value
  el.dispatchEvent(new MiniEvent("input", { bubbles: true }))
}

describe("the In web pages card on the page", () => {
  it("marks each sign-in page where the vault found it, lists the pages it may also be typed into, and offers the choice and Save to someone who may change it", () => {
    const page = pageOf(GALLERY_LOGIN, true)
    const body = page.body.value
    expect(body).toContain('<section class="card" aria-label="In web pages" data-region="in-web-pages"><div class="card-head"><h2>In web pages</h2></div>')
    expect(body).toContain('<legend class="label">How agents may use it</legend>')
    expect(body).toContain('<input type="radio" name="web-ceiling" data-input="web-ceiling" value="fill" checked><span><strong>Type it into the sign-in page</strong>')
    expect(body).toContain('<input type="radio" name="web-ceiling" data-input="web-ceiling" value="relay"><span><strong>Not at all</strong> Only you can use it.</span>')
    expect(body).not.toContain("Sign in for them")
    browser = installPage(renderDocument(page).value, () => ({ status: 404, body: {} }))
    expect(origins("signin-pages")).toEqual(["https://github.com from its sign-in address", "https://api.github.com from its hosts", "https://gist.github.com added"])
    expect(browser.document.querySelectorAll('[data-region="signin-pages"] [data-action="remove-signin-page"]').map((b) => b.getAttribute("data-origin"))).toEqual(["https://gist.github.com"])
    expect(origins("type-into")).toEqual(["https://dash.cloudflare.com"])
    expect($('[data-region="type-into-none"]').hidden).toBe(true)
    expect($('[data-action="add-signin-page"]').textContent).toBe("Add a sign-in page")
    expect($('[data-action="save-web-pages"]').disabled).toBe(true)
    expect(page.boot).toMatchObject({ web: { ceiling: "fill", signinOrigins: ["https://gist.github.com"], typeInto: ["https://dash.cloudflare.com"] } })
  })

  it("shows the lists to read, with no choice, no Add and no Save, to someone who may not change it", () => {
    const page = pageOf(GALLERY_LOGIN, true, VIEWERS.guest)
    const body = page.body.value
    expect(body).toContain('data-region="in-web-pages"')
    expect(body).toContain('<p data-region="web-ceiling-shown"><strong>Type it into the sign-in page</strong></p>')
    for (const control of ['data-input="web-ceiling"', 'data-action="add-signin-page"', 'data-action="add-type-into"', 'data-action="remove-', 'data-action="save-web-pages"']) expect(body).not.toContain(control)
    expect(page.boot).not.toHaveProperty("web")
  })

  it("offers no choice where the ceiling is neither relay nor fill, since a save changes only those", () => {
    const body = pageOf({ ...LOGIN_WITHOUT_PAGES, ceiling: "lease" }, true).body.value
    expect(body).toContain('<p class="small muted" data-region="web-ceiling-fixed">Its ceiling, lease, already decides this.</p>')
    expect(body).not.toContain('data-input="web-ceiling"')
    expect(body).toContain('data-action="add-signin-page"')
  })

  it("for a key: no choice and no sign-in pages, None to start, and a line while its ceiling does not allow typing", () => {
    const body = pageOf(description(GALLERY_ITEMS[0]!), true).body.value
    expect(body).toContain('data-region="in-web-pages"')
    expect(body).not.toContain('data-region="signin-pages"')
    expect(body).not.toContain('data-input="web-ceiling"')
    expect(body).toContain('<p class="small muted" data-region="web-not-allowed">Agents cannot type it anywhere until its ceiling allows typing into web pages.</p>')
    expect(body).toMatch(/<p class="muted small" data-region="type-into-none">None<\/p>/)
  })

  it("leaves the page exactly as it was with the switch off, and for a kind fill never types", () => {
    const off = renderDocument(pageOf(GALLERY_LOGIN, false)).value
    expect(off).not.toContain('data-region="in-web-pages"')
    const client: HumanItemDescription = { ...description(GALLERY_ITEMS[0]!), kind: "oauth-client" }
    expect(renderDocument(pageOf(client, true)).value).toBe(renderDocument(pageOf(client, false)).value)
  })
})

describe("the In web pages card in the browser", () => {
  it("adds a sign-in page as its origin, and refuses one that is not https", async () => {
    openCredential(GALLERY_LOGIN)
    typeIn('[data-input="signin-page"]', "http://login.example.com")
    $('[data-action="add-signin-page"]').click()
    await settle()
    expect($("#notice").textContent).toContain("Only https sign-in pages can be filled.")
    expect(origins("signin-pages")).toHaveLength(3)
    expect($('[data-action="save-web-pages"]').disabled).toBe(true)
    typeIn('[data-input="signin-page"]', "https://Login.Example.com/session?next=/")
    $('[data-action="add-signin-page"]').click()
    await settle()
    expect(origins("signin-pages")).toEqual(["https://github.com from its sign-in address", "https://api.github.com from its hosts", "https://gist.github.com added", "https://login.example.com added"])
    expect($('[data-input="signin-page"]').value).toBe("")
    expect($('[data-action="save-web-pages"]').disabled).toBe(false)
    typeIn('[data-input="signin-page"]', "https://github.com/")
    $('[data-action="add-signin-page"]').click()
    await settle()
    expect(origins("signin-pages")).toHaveLength(4)
  })

  it("warns as soon as another service's page is added, and refuses one that is not https", async () => {
    openCredential(LOGIN_WITHOUT_PAGES)
    expect($('[data-region="type-into-none"]').hidden).toBe(false)
    expect($('[data-region="type-into-warning"]').hidden).toBe(true)
    typeIn('[data-input="type-into"]', "https://10.0.0.1")
    $('[data-action="add-type-into"]').click()
    await settle()
    expect($("#notice").textContent).toContain("Only https pages can be typed into.")
    typeIn('[data-input="type-into"]', "https://dash.example.net/keys")
    $('[data-action="add-type-into"]').click()
    await settle()
    expect(origins("type-into")).toEqual(["https://dash.example.net"])
    expect($('[data-region="type-into-none"]').hidden).toBe(true)
    expect($('[data-region="type-into-warning"]').textContent).toBe("This puts the credential into another service. Every time asks you first.")
    expect($('[data-region="type-into-warning"]').hidden).toBe(false)
  })

  it("refuses a page past the most the vault keeps in one list, before it is listed", async () => {
    openCredential(LOGIN_WITHOUT_PAGES)
    for (let n = 1; n <= 8; n++) {
      typeIn('[data-input="type-into"]', `https://page${n}.example.net`)
      $('[data-action="add-type-into"]').click()
    }
    await settle()
    expect(origins("type-into")).toHaveLength(8)
    typeIn('[data-input="type-into"]', "https://page9.example.net")
    $('[data-action="add-type-into"]').click()
    await settle()
    expect($("#notice").textContent).toContain("A credential can list at most 8 pages here.")
    expect(origins("type-into")).toHaveLength(8)
  })

  it("saves only what changed through item.update, the last pages removed as null, signing the digest the vault rebuilds", async () => {
    const change = { ceiling: "relay", browser: null }
    const expected = { type: "item.update", item: GALLERY_LOGIN.id, digest: await stepUpDigest({ change, version: GALLERY_LOGIN.version, configRevision: GALLERY_LOGIN.configRevision }) }
    const shown = { id: GALLERY_LOGIN.id, version: GALLERY_LOGIN.version, configRevision: GALLERY_LOGIN.configRevision, dependencyRevision: GALLERY_LOGIN.dependencyRevision }
    openCredential(GALLERY_LOGIN, (path) => {
      if (path === `${ITEM}/action`) return ok(expected)
      if (path === API) return ok(WORKSPACE)
      if (path === ITEM) return ok(shown)
      if (path === `${API}/stepup/start`) return ok({ nonce: "n", options: { challenge: "c" } })
      if (path === `${ITEM}/update`) return ok({ ...GALLERY_LOGIN, ceiling: "relay" })
      return { status: 404, body: { error: "not_found", message: `No route ${path}.` } }
    })
    $('[data-input="web-ceiling"][value="relay"]').click()
    $('[data-action="remove-signin-page"][data-origin="https://gist.github.com"]').click()
    $('[data-action="remove-type-into"][data-origin="https://dash.cloudflare.com"]').click()
    expect(origins("signin-pages")).toEqual(["https://github.com from its sign-in address", "https://api.github.com from its hosts"])
    expect($('[data-region="type-into-none"]').hidden).toBe(false)
    $('[data-action="save-web-pages"]').click()
    await settle(60)
    const call = (path: string) => browser!.calls.find((c) => c.path === path)
    expect(call(`${ITEM}/action`)?.body).toEqual({ action: "update", change })
    expect(call(`${API}/stepup/start`)?.body).toEqual({ action: expected })
    const { stepUp, ...sent } = call(`${ITEM}/update`)?.body as { stepUp: unknown } & Record<string, unknown>
    expect(sent).toEqual(change)
    expect(stepUp).toBeDefined()
    expect(passkeys.count).toBe(1)
  })

  it("sends nothing when the vault's action is not the one the page rebuilt", async () => {
    openCredential(GALLERY_LOGIN, (path) => (path === `${ITEM}/action` ? ok({ type: "item.update", item: GALLERY_LOGIN.id, digest: "something-else" }) : { status: 404, body: { error: "not_found", message: "No route." } }))
    $('[data-input="web-ceiling"][value="relay"]').click()
    $('[data-action="save-web-pages"]').click()
    await settle(60)
    expect(browser!.calls.map((c) => c.path)).toEqual([`${ITEM}/action`])
    expect(passkeys.count).toBe(0)
  })
})
