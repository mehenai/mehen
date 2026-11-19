// The adoption review page's keep-open control (ui/client/pages/
// workspace-adopt.ts), run against the gallery's server-rendered conflict
// batch (test/mini-dom.ts) with the vault answered here: it sends the
// expiry shown, then shows the one the vault answers in the time's text and
// its title, says how much the next click adds, and is gone at the longest
// the batch may stay open.
import { afterEach, expect, it } from "vitest"
import type { AdoptionKeptOpen } from "@mehen/protocol/adopt"
import { renderDocument } from "../src/ui/layout.ts"
import { GALLERY_CONFLICT_ADOPTION, workspaceAsksGallery } from "../src/ui/workspace-asks-gallery.ts"
import { GALLERY_WORKSPACE } from "../src/ui/workspace-projects-gallery.ts"
import { ShellState } from "../src/ui/client/shell-logic.ts"
import { initWorkspaceAdoption } from "../src/ui/client/pages/workspace-adopt.ts"
import { formatTime } from "../src/ui/wording.ts"
import { type MiniBrowser, type MiniElement, installPage, settle } from "./mini-dom.ts"

let browser: MiniBrowser | null = null
afterEach(() => {
  browser?.restore()
  browser = null
})

const DAY_MS = 86_400_000
const { adoption, expiresAt } = GALLERY_CONFLICT_ADOPTION
const KEEP_OPEN = `/api/w/${GALLERY_WORKSPACE.slug}/adoptions/${adoption}/keep-open`
const $ = (selector: string) => browser!.document.querySelector(selector) as MiniElement

function openPage(answers: AdoptionKeptOpen[]): void {
  const page = workspaceAsksGallery().find((e) => e.id === "ws-adoption-conflict")!.page
  browser = installPage(renderDocument(page).value, (path) => (path === KEEP_OPEN ? { status: 200, body: answers.shift() } : { status: 404, body: { error: "not_found", message: "No such route." } }), `https://app.mehen.dev/w/${GALLERY_WORKSPACE.slug}/b/${adoption}`)
  initWorkspaceAdoption(page.boot, new ShellState({ origin: "https://app.mehen.dev", account: "acc_4Hq9Tz2Lm7Vb1Nc8", workspace: GALLERY_WORKSPACE, pages: [], reads: [] }))
}

it("keep-open sends the expiry shown, shows the new one in the time and its title, says what the next click adds, and is gone at the longest", async () => {
  const first = new Date(Date.parse(expiresAt) + 3 * DAY_MS).toISOString()
  const second = new Date(Date.parse(first) + 2 * DAY_MS).toISOString()
  openPage([{ adoption, expiresAt: first, maxExpiresAt: new Date(Date.parse(first) + 2 * DAY_MS).toISOString() }, { adoption, expiresAt: second, maxExpiresAt: second }])
  const keep = $('[data-action="keep-open"]')
  const time = () => $('[data-region="expires"] time')
  expect([keep.textContent, time().getAttribute("title")]).toEqual(["Keep open 3 more days", formatTime(expiresAt)])
  keep.click()
  await settle()
  expect(browser!.calls.filter((c) => c.path === KEEP_OPEN).map((c) => c.body)).toEqual([{ expiresAt }])
  expect([time().getAttribute("title"), keep.textContent, keep.hidden]).toEqual([formatTime(first), "Keep open 2 more days", false])
  keep.click()
  await settle()
  expect(browser!.calls.filter((c) => c.path === KEEP_OPEN).map((c) => c.body)).toEqual([{ expiresAt }, { expiresAt: first }])
  expect([time().getAttribute("title"), keep.hidden]).toEqual([formatTime(second), true])
})
